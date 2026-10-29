//! Every way to reach friends (desktop/api/NETWORK_PARITY.md): `network.*`,
//! `contacts.routes` / `contacts.set_routes`, `security.status`, `lock.*`
//! and `updates.status`.
//!
//! The settings are the CLI's own commands (crates/ash, through the engine
//! bridge), on the same node_policy.json the CLI reads; the states are the
//! gates of raven-core, read in this process, and what the profile's
//! raven-node reports in its Status. A held way is `preview` and is never
//! turned on here (NOT_AVAILABLE_YET); a debug build's lab switch shows as
//! `lab`, and the raven-node this engine starts inherits the switch.

use std::path::Path;

use ash_engine::engine as bridge;
use raven_core::ipc::{IpcRequest, IpcResponse, P2pStatusInfo};
use raven_core::node_policy::NodePolicy;
use raven_core::outbox::QueueReach;
use raven_core::security_gate::{self, SecGate};
use serde_json::{json, Value};

use crate::engine::{build_kind, Inner};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::node::PROBE_TIMEOUT;

/// The lab unlock most gates need besides their own switch.
const TEST_A: &str = "RAVEN_LAB_TEST_A";

/// One way's gate: its production constant (by name), whether it is open in
/// this process, and the debug lab switches that open it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gate {
    pub production: bool,
    pub live: bool,
    pub constant: &'static str,
    pub switches: &'static [&'static str],
}

impl Gate {
    /// Open only through a debug build's lab switch.
    pub(crate) fn lab(&self) -> bool {
        self.live && !self.production
    }
}

/// The ways (carriers), in the order the apps list them.
pub(crate) const CARRIERS: [&str; 14] = [
    "lan",
    "lan_beacon",
    "internet",
    "port_mapping",
    "p2p",
    "friend_relay",
    "websocket",
    "proxy",
    "custody",
    "letters",
    "handoff",
    "route_hints",
    "nearby",
    "tor",
];

/// The protections and other gated parts the network view lists.
pub(crate) const PROTECTIONS: [&str; 6] = [
    "random_port",
    "link_knock",
    "link_padding",
    "lock_v2",
    "security_events",
    "updates_from_friends",
];

fn sec(g: SecGate, switches: &'static [&'static str]) -> Gate {
    Gate {
        production: g.production(),
        live: security_gate::live(g),
        constant: g.const_name(),
        switches,
    }
}

/// The gate of way `id` (a carrier or a protection), read now.
pub(crate) fn gate(id: &str) -> Gate {
    use raven_core::{custody_gate, horizon, lan_beacon, route_hints, wss_gate};
    match id {
        "lan" => Gate {
            production: raven_core::LAN_DIRECT_PRODUCTION_ENABLED,
            live: raven_core::lan_direct_live_enabled(),
            constant: "LAN_DIRECT_PRODUCTION_ENABLED",
            switches: &[],
        },
        "lan_beacon" => Gate {
            production: lan_beacon::LAN_BEACON_PRODUCTION_ENABLED,
            live: lan_beacon::lan_beacon_live(),
            constant: "LAN_BEACON_PRODUCTION_ENABLED",
            switches: &["RAVEN_LAB_LAN_BEACON"],
        },
        "internet" => Gate {
            production: raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED,
            live: raven_core::internet_direct_live_enabled(),
            constant: "INTERNET_DIRECT_PRODUCTION_ENABLED",
            switches: &[TEST_A],
        },
        // Router port opening rides on p2p (UPnP since Phase 1); NAT-PMP and
        // PCP also need PORT_MAP (network.status `port_mapping.nat_pmp_pcp`).
        "port_mapping" => Gate {
            production: raven_core::P2P_PRODUCTION_ENABLED,
            live: raven_core::p2p_live_enabled(),
            constant: "P2P_PRODUCTION_ENABLED",
            switches: &[TEST_A],
        },
        "p2p" => Gate {
            production: raven_core::P2P_PRODUCTION_ENABLED,
            live: raven_core::p2p_live_enabled(),
            constant: "P2P_PRODUCTION_ENABLED",
            switches: &[TEST_A],
        },
        "friend_relay" => Gate {
            production: raven_core::p2p_gate::FRIEND_RELAY_PRODUCTION_ENABLED,
            live: raven_core::p2p_gate::friend_relay_live_enabled(),
            constant: "FRIEND_RELAY_PRODUCTION_ENABLED",
            switches: &[TEST_A, "RAVEN_LAB_FRIEND_RELAY"],
        },
        "websocket" => Gate {
            production: wss_gate::WSS_PRODUCTION_ENABLED,
            live: wss_gate::wss_live_enabled(),
            constant: "WSS_PRODUCTION_ENABLED",
            switches: &[TEST_A, "RAVEN_LAB_WSS"],
        },
        "proxy" => Gate {
            production: wss_gate::WSS_PROXY_PRODUCTION_ENABLED,
            live: wss_gate::wss_proxy_live_enabled(),
            constant: "WSS_PROXY_PRODUCTION_ENABLED",
            switches: &[TEST_A, "RAVEN_LAB_WSS", "RAVEN_LAB_WSS_PROXY"],
        },
        "custody" => Gate {
            production: custody_gate::FRIEND_CUSTODY_PRODUCTION_ENABLED,
            live: custody_gate::CustodyGates::current().live,
            constant: "FRIEND_CUSTODY_PRODUCTION_ENABLED",
            switches: &[TEST_A],
        },
        "letters" => Gate {
            production: horizon::ASYNC_LETTER_PRODUCTION_ENABLED,
            live: horizon::letter_live_enabled(),
            constant: "ASYNC_LETTER_PRODUCTION_ENABLED",
            switches: &[TEST_A, "RAVEN_LAB_HORIZON", "RAVEN_LAB_LETTER"],
        },
        "handoff" => Gate {
            production: custody_gate::CUSTODY_HANDOFF_PRODUCTION_ENABLED,
            live: custody_gate::handoff_live(),
            constant: "CUSTODY_HANDOFF_PRODUCTION_ENABLED",
            switches: &[TEST_A, "RAVEN_LAB_CUSTODY_HANDOFF"],
        },
        "route_hints" => Gate {
            production: route_hints::ROUTE_HINTS_PRODUCTION_ENABLED,
            live: route_hints::route_hints_live(),
            constant: "ROUTE_HINTS_PRODUCTION_ENABLED",
            switches: &["RAVEN_LAB_ROUTE_HINTS"],
        },
        "nearby" => Gate {
            production: raven_core::NEARBY_PRODUCTION_ENABLED,
            live: raven_core::nearby_live_enabled(),
            constant: "NEARBY_PRODUCTION_ENABLED",
            switches: &[TEST_A, "RAVEN_LAB_NEARBY"],
        },
        "tor" => Gate {
            production: raven_core::ONION_PRODUCTION_ENABLED,
            live: raven_core::onion_live_enabled(),
            constant: "ONION_PRODUCTION_ENABLED",
            switches: &[TEST_A, raven_core::onion_gate::LAB_TOR],
        },
        "random_port" => sec(SecGate::RandomPort, &[TEST_A, "RAVEN_LAB_RANDOM_PORT"]),
        "link_knock" => sec(SecGate::LinkKnock, &[TEST_A, "RAVEN_LAB_LINK_KNOCK"]),
        "link_padding" => sec(SecGate::LinkPadding, &[TEST_A, "RAVEN_LAB_LINK_PADDING"]),
        "lock_v2" => sec(
            SecGate::LocalProtection,
            &[TEST_A, "RAVEN_LAB_LOCAL_PROTECTION"],
        ),
        "security_events" => sec(SecGate::Events, &[TEST_A, "RAVEN_LAB_SECURITY_EVENTS"]),
        "updates_from_friends" => sec(
            SecGate::MeshUpdate,
            &[
                TEST_A,
                "RAVEN_LAB_ADVISORY",
                "RAVEN_LAB_RELEASE_BUNDLE",
                "RAVEN_LAB_MESH_UPDATE",
            ],
        ),
        _ => Gate {
            production: false,
            live: false,
            constant: "",
            switches: &[],
        },
    }
}

/// The ways a developer build's lab switch turned on in this process
/// (never in a release build: it reads no switch).
pub(crate) fn lab_ways() -> Vec<&'static str> {
    CARRIERS
        .iter()
        .chain(PROTECTIONS.iter())
        .copied()
        .filter(|id| gate(id).lab())
        .collect()
}

/// The `RAVEN_LAB_*` variables set in this process's environment, by name
/// (never a value). A release build reads none, so it lists none.
pub(crate) fn lab_switches_seen() -> Vec<String> {
    if !cfg!(debug_assertions) {
        return Vec::new();
    }
    let mut seen: Vec<String> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let k = k.into_string().ok()?;
            (k.starts_with("RAVEN_LAB_") && !v.is_empty()).then_some(k)
        })
        .collect();
    seen.sort();
    seen
}

/// Bluetooth nearby has a radio backend for this operating system
/// (raven-node: BlueZ on glibc Linux, WinRT on Windows, CoreBluetooth
/// through the RavenNearby helper on macOS).
const NEARBY_ON_THIS_OS: bool = cfg!(any(
    target_os = "macos",
    windows,
    all(target_os = "linux", target_env = "gnu")
));

/// The debug lab switch that lets raven-node's radio go on the air from the
/// adapter's fixed public address (raven-node `nearby/mod.rs`
/// `allow_public_address`; inert in a release build).
const NEARBY_ALLOW_PUBLIC_ADDR: &str = "RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR";

/// Whether raven-node runs Bluetooth nearby now, decided as raven-node
/// decides it (`nearby/engine.rs` `address_private`, owner decision O5-12,
/// review nearby-1): the radio advertises, connects and scans only while it
/// is switched on and powered, and its address is not the adapter's fixed
/// public one, unless a debug lab run allows that (`allow_public`, the
/// switch [`NEARBY_ALLOW_PUBLIC_ADDR`] the node it starts inherits). On
/// Windows the node treats the address as public until row N7w settles it,
/// so nearby stays inactive there even with the radio on.
fn nearby_running(info: Option<&raven_core::ipc::NearbyStatusInfo>, allow_public: bool) -> bool {
    info.is_some_and(|i| {
        i.enabled && i.radio == "powered_on" && (i.address_privacy != "public" || allow_public)
    })
}

/// What a way is called in the apps.
fn name_of(id: &str) -> &'static str {
    match id {
        "lan" => "Same network (Wi-Fi, cable or hotspot)",
        "lan_beacon" => "Finding friends on a new network",
        "internet" => "Internet direct",
        "port_mapping" => "Router port opening (UPnP, NAT-PMP, PCP)",
        "p2p" => "Peer-to-peer and relays",
        "friend_relay" => "Relay for friends",
        "websocket" => "Relays over WebSocket (port 443)",
        "proxy" => "Web proxy for relays",
        "custody" => "Friends carry your messages",
        "letters" => "Sealed letters with friends",
        "handoff" => "Passing messages on between friends",
        "route_hints" => "Routes friends tell each other",
        "nearby" => "Bluetooth nearby",
        "tor" => "Tor",
        "random_port" => "A port of its own for this profile",
        "link_knock" => "Silent to strangers (link knock)",
        "link_padding" => "Padding that hides message sizes",
        "lock_v2" => "Lock while running",
        "security_events" => "Security notices",
        "updates_from_friends" => "Updates passed on by friends",
        _ => "",
    }
}

/// The plain sentence for a way held in this build.
const PREVIEW_REASON: &str = "Not in this version of Raven yet.";
/// Bluetooth nearby on Windows and Linux: release builds have it on macOS
/// only (2026-10).
const NEARBY_MACOS_ONLY_REASON: &str =
    "Not in this version of Raven on this computer: Bluetooth nearby is on macOS only so far.";
/// The plain sentence for a way on only through a lab switch.
const LAB_REASON: &str = "On for testing only: a developer build's lab switch turned it on.";
/// The plain sentence for a way the running raven-node uses while the saved
/// setting is off.
const RUNNING_NOT_SAVED_REASON: &str = "Running now: Raven's background program was started with \
     this way on. The saved setting is off, so it stops when the program starts again with the \
     saved settings.";

/// What the profile's settings and the running raven-node say, read once
/// for one view.
pub(crate) struct NetFacts {
    pub status: Result<IpcResponse, String>,
    pub policy: Option<NodePolicy>,
    pub lan: bridge::LanView,
    pub nearby: bridge::NearbyView,
    pub carry: bridge::CarryView,
}

impl NetFacts {
    pub(crate) fn read(dir: &Path) -> NetFacts {
        let status = bridge::ipc_request_timeout(dir, &IpcRequest::status(), PROBE_TIMEOUT);
        NetFacts {
            policy: raven_core::node_policy::try_load_policy(dir).ok(),
            lan: bridge::lan_view(dir, &status),
            nearby: bridge::nearby_view(dir, &status),
            carry: bridge::carry_view(dir),
            status,
        }
    }

    fn caps(&self) -> &[String] {
        match &self.status {
            Ok(IpcResponse::Status { capabilities, .. }) => capabilities,
            _ => &[],
        }
    }

    fn has_cap(&self, cap: &str) -> bool {
        self.caps().iter().any(|c| c == cap)
    }

    fn p2p(&self) -> Option<&P2pStatusInfo> {
        match &self.status {
            Ok(IpcResponse::Status { p2p, .. }) => p2p.as_deref(),
            _ => None,
        }
    }

    fn answered(&self) -> bool {
        matches!(self.status, Ok(IpcResponse::Status { .. }))
    }

    /// raven-node's Tor line (`Status.tor`, lab): absent while its gate is
    /// closed, from an older raven-node, and while none answers.
    fn tor(&self) -> Option<TorView> {
        match &self.status {
            Ok(IpcResponse::Status {
                tor: Some(line), ..
            }) => Some(TorView::parse(line)),
            _ => None,
        }
    }

    fn policy(&self) -> NodePolicy {
        self.policy.clone().unwrap_or_default()
    }
}

/// One way: `{id, name, state, reason, lab, gate, lab_switches, can_set,
/// setting?, running?, detail?}` (API.md `Carrier`).
fn way(id: &'static str, facts: &NetFacts) -> Value {
    let g = gate(id);
    let p = facts.policy();
    // The person's setting (None: automatic, nothing to switch).
    let setting: Option<bool> = match id {
        "lan" => Some(facts.lan.setting == "on"),
        "internet" => Some(!p.internet_listen.trim().is_empty()),
        "port_mapping" => Some(p.upnp == Some(true)),
        "p2p" => Some(!p.p2p_listen.trim().is_empty()),
        "friend_relay" => Some(p.relay_offer == Some(true)),
        // Friend mailboxes on, or friends listed by hand for a contact
        // (used whatever the mailbox choice says).
        "custody" => Some(p.custody_use == Some(true) || facts.carry.listed > 0),
        "handoff" => Some(p.custody_handoff),
        "nearby" => Some(p.nearby == Some(true)),
        _ => None,
    };
    // What the running raven-node says it uses now (None: it doesn't say).
    let p2p = facts.p2p();
    let running: Option<bool> = if !facts.answered() {
        None
    } else {
        match id {
            "lan" => Some(facts.has_cap("lan_direct")),
            "lan_beacon" => Some(match &facts.status {
                Ok(IpcResponse::Status { lan: Some(lan), .. }) => {
                    lan.beacon.as_ref().is_some_and(|b| b.state == "on")
                }
                _ => false,
            }),
            "internet" => Some(facts.has_cap("internet_direct")),
            "port_mapping" => Some(p2p.is_some_and(|i| {
                i.upnp.starts_with("mapped")
                    || i.port_map
                        .as_ref()
                        .is_some_and(|m| matches!(m.v4.as_str(), "pcp" | "nat-pmp" | "upnp"))
            })),
            "p2p" => Some(p2p.is_some_and(|i| i.up)),
            "friend_relay" => Some(
                p2p.and_then(|i| i.friend_relay.as_ref())
                    .is_some_and(|f| f.offering),
            ),
            "websocket" => {
                Some(p2p.is_some_and(|i| i.relay_paths.iter().any(|t| t.starts_with("wss"))))
            }
            "proxy" => Some(p2p.is_some_and(|i| i.relay_paths.iter().any(|t| t == "wss-proxy"))),
            "route_hints" => Some(match &facts.status {
                Ok(IpcResponse::Status {
                    route_hints: Some(h),
                    ..
                }) => h.live,
                _ => false,
            }),
            "nearby" => Some(nearby_running(
                facts.nearby.info.as_ref(),
                raven_core::pair_init::lab_switch(NEARBY_ALLOW_PUBLIC_ADDR),
            )),
            // Tor: ready (its client bootstrapped) as raven-node's line says;
            // nothing said without that line.
            "tor" => facts.tor().map(|t| t.running()),
            _ => None,
        }
    };
    let tor = (id == "tor").then(|| facts.tor()).flatten();
    let radio = facts.nearby.info.as_ref().map(|i| i.radio.as_str());
    let not_here = id == "nearby" && (!NEARBY_ON_THIS_OS || radio == Some("unsupported"));
    // The running raven-node uses it although the saved setting is off (it
    // was started with settings of its own): the state is what runs, and
    // the reason says the saved setting differs.
    let runs_unsaved = setting == Some(false) && running == Some(true);
    let (state, reason) = if not_here {
        (
            "not_on_this_os",
            "This computer can't use Bluetooth nearby (no Bluetooth LE support for it).",
        )
    } else if !g.live && id == "nearby" && !raven_core::NEARBY_PRODUCTION_ENABLED {
        ("preview", NEARBY_MACOS_ONLY_REASON)
    } else if !g.live {
        ("preview", PREVIEW_REASON)
    } else if runs_unsaved {
        (if g.lab() { "lab" } else { "on" }, RUNNING_NOT_SAVED_REASON)
    } else if setting == Some(false) || (id == "lan_beacon" && facts.lan.setting != "on") {
        ("off", off_reason(id))
    } else if let Some(t) = &tor {
        // Tor's own state, as raven-node reports it (states only).
        (if g.lab() { "lab" } else { "on" }, t.reason())
    } else if g.lab() {
        ("lab", LAB_REASON)
    } else {
        ("on", on_reason(id))
    };
    let mut v = json!({
        "id": id,
        "name": name_of(id),
        "state": state,
        "reason": reason,
        "lab": g.lab(),
        "gate": g.constant,
        "lab_switches": g.switches,
        "can_set": can_set(id),
    });
    if let Some(on) = setting {
        v["setting"] = on.into();
    }
    if let Some(on) = running {
        v["running"] = on.into();
    }
    if let Some(detail) = detail_of(id, facts) {
        v["detail"] = detail.into();
    } else if let Some(t) = &tor {
        v["detail"] = t.words.clone().into();
    }
    v
}

/// The Tor onion carrier as raven-node's Status line says it (`Tor: ready`,
/// `Tor: starting (45 %)`, `Tor: blocked on this network (why; retrying in
/// 2 min)`, `Tor: ready, onion service unreachable for 5 min (why; onion
/// service outages since start: 2, ...)`; raven-node `onion::status_line`).
/// States only: the line never holds an address, and nothing here adds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TorView {
    /// `ready`, `publishing` (ready, the onion service not confirmed yet),
    /// `unreachable` (ready, the onion service can't be reached), `starting`,
    /// `restarting`, `blocked`, `could_not_start`, `not_built`, `off`, or
    /// `unknown` for words this engine doesn't know.
    pub phase: &'static str,
    /// The line after `Tor: `.
    pub words: String,
    /// How far Tor's start is (`starting`).
    pub percent: Option<u8>,
    /// Why (blocked, could not start, restarting, unreachable).
    pub why: Option<String>,
    /// When raven-node tries again (`retrying in 2 min`).
    pub retry: Option<String>,
    /// The onion service's outage history since raven-node started.
    pub outages: Option<String>,
}

impl TorView {
    pub(crate) fn parse(line: &str) -> TorView {
        let words = raven_core::sanitize::sanitize_terminal_line(line.trim()).to_string();
        let words = words
            .strip_prefix("Tor:")
            .map_or(words.as_str(), str::trim)
            .to_owned();
        // `head (part; part)`: the head says the state, the parts why,
        // when it retries and the outage history.
        let (head, parts) = match words.split_once(" (") {
            Some((head, rest)) => (
                head.to_owned(),
                rest.strip_suffix(')')
                    .unwrap_or(rest)
                    .split("; ")
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            ),
            None => (words.clone(), Vec::new()),
        };
        let phase = if head.starts_with("ready, onion service unreachable") {
            "unreachable"
        } else if head == "ready"
            && parts
                .first()
                .is_some_and(|p| p == "onion service publishing")
        {
            "publishing"
        } else if head.starts_with("ready") {
            "ready"
        } else if head.starts_with("starting") {
            "starting"
        } else if head.starts_with("restarting") {
            "restarting"
        } else if head.starts_with("blocked") {
            "blocked"
        } else if head.starts_with("could not start") {
            "could_not_start"
        } else if head.starts_with("not built") {
            "not_built"
        } else if head == "off" {
            "off"
        } else {
            "unknown"
        };
        let mut why = Vec::new();
        let (mut retry, mut outages, mut percent) = (None, None, None);
        for part in parts {
            if part.starts_with("onion service outages since start") {
                outages = Some(part);
            } else if part.starts_with("retrying in") {
                retry = Some(part);
            } else if phase == "starting" {
                // `45 %` or `45 %, Tor says: ...`.
                let (pct, rest) = part.split_once(", ").unwrap_or((part.as_str(), ""));
                percent = pct.trim_end_matches('%').trim().parse::<u8>().ok();
                if !rest.is_empty() {
                    why.push(rest.to_owned());
                }
            } else if part != "onion service publishing" {
                why.push(part);
            }
        }
        TorView {
            phase,
            words,
            percent,
            why: (!why.is_empty()).then(|| why.join("; ")),
            retry,
            outages,
        }
    }

    /// Ready to carry messages: its client bootstrapped.
    fn running(&self) -> bool {
        matches!(self.phase, "ready" | "publishing" | "unreachable")
    }

    /// The way's plain sentence for this state.
    fn reason(&self) -> &'static str {
        match self.phase {
            "ready" => "Ready: friends can reach you over Tor, and you them.",
            "publishing" => "Ready: your onion service is being published, so friends may not reach you over Tor yet.",
            "unreachable" => "Ready, but your onion service can't be reached right now: you still reach friends over Tor.",
            "starting" => "Starting: Tor is connecting to its network.",
            "restarting" => "Restarting.",
            "blocked" => "Blocked on this network: Tor can't connect from here.",
            "could_not_start" => "Could not start on this computer.",
            "not_built" => "Not built into this Raven (its Tor helper is missing).",
            "off" => "Off.",
            _ => "As Raven's background program reports it.",
        }
    }

    /// API.md `NetworkStatus.tor`.
    fn json(&self) -> Value {
        let mut v = json!({"phase": self.phase, "words": self.words});
        if let Some(p) = self.percent {
            v["percent"] = p.into();
        }
        if let Some(w) = &self.why {
            v["why"] = w.clone().into();
        }
        if let Some(r) = &self.retry {
            v["retry"] = r.clone().into();
        }
        if let Some(o) = &self.outages {
            v["outages"] = o.clone().into();
        }
        v
    }
}

/// A way `network.set` changes.
fn can_set(id: &str) -> bool {
    matches!(
        id,
        "lan"
            | "internet"
            | "port_mapping"
            | "p2p"
            | "friend_relay"
            | "proxy"
            | "custody"
            | "handoff"
            | "nearby"
    )
}

fn off_reason(id: &str) -> &'static str {
    match id {
        "lan" => {
            "Turned off on this computer: Raven doesn't send or receive on this network until it \
             is turned on again."
        }
        "lan_beacon" => "Off while sending on this network is off.",
        "custody" => "Raven doesn't leave your messages with friends or collect mail from them.",
        _ => "Turned off.",
    }
}

fn on_reason(id: &str) -> &'static str {
    match id {
        "lan" => "On. Works without the internet.",
        "lan_beacon" => "On: Raven finds your friends when you join a new network.",
        "letters" | "route_hints" | "websocket" => "On: Raven uses it by itself when it helps.",
        _ => "On.",
    }
}

/// The CLI's own row for a way, where it has one.
fn detail_of(id: &str, facts: &NetFacts) -> Option<String> {
    match id {
        "lan" => Some(facts.lan.row.clone()),
        "lan_beacon" => facts.lan.beacon_row.clone(),
        "internet" => Some(bridge::internet_row(
            &facts.status,
            &facts.policy().internet_listen,
        )),
        "nearby" => facts
            .nearby
            .rows
            .iter()
            .map(|(label, value)| format!("{label}: {value}"))
            .reduce(|a, b| format!("{a}; {b}")),
        _ => None,
    }
}

/// `{label, value}` rows.
fn rows_json<L: AsRef<str>>(rows: &[(L, String)]) -> Value {
    Value::Array(
        rows.iter()
            .map(|(label, value)| json!({"label": label.as_ref(), "value": value}))
            .collect(),
    )
}

/// The LAN port this profile's raven-node listens on (the one it picked, else
/// Raven's default).
fn profile_port(dir: &Path) -> u16 {
    raven_core::node_policy::profile_lan_port(dir).unwrap_or(raven_core::paths::DEFAULT_LAN_PORT)
}

/// What the honest effect of each help-friends flag is (API.md).
pub(crate) fn flag_effect(flag: &str) -> &'static str {
    match flag {
        "bridge" => {
            "Raven's background program passes on sealed envelopes other devices hand it on its \
             bridge listeners (the older mesh envelope path; a program started by Raven listens \
             for these on this computer only). Messages to your friends don't use it."
        }
        "store" => {
            "Lets Raven's background program keep sealed envelopes until their next hop is ready. \
             In this version it always has a next hop, so this changes nothing yet."
        }
        "relay" => {
            "Reserved for relaying between Raven's own links. This version of Raven's background \
             program doesn't use it, so this changes nothing yet. To lend friends a relay, use \
             Relay for friends."
        }
        _ => "",
    }
}

impl Inner {
    /// `network.status`.
    pub(crate) fn network_status(&self) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        let facts = NetFacts::read(&dir);
        Ok(network_view(&dir, &facts))
    }
}

/// API.md's `NetworkStatus` of the profile in `dir`.
pub(crate) fn network_view(dir: &Path, facts: &NetFacts) -> Value {
    let p = facts.policy();
    let p2p = facts.p2p();
    let mut listening: Vec<String> = match &facts.status {
        Ok(IpcResponse::Status {
            lan: Some(lan),
            lan_listen,
            ..
        }) if !lan.listen.is_empty() || lan_listen.is_none() => lan.listen.clone(),
        Ok(IpcResponse::Status {
            lan_listen: Some(at),
            ..
        }) => vec![at.clone()],
        _ => Vec::new(),
    };
    // The port the running raven-node really listens on (its LAN listener),
    // else the one this profile's raven-node would use.
    let port = listening
        .first()
        .and_then(|at| at.rsplit_once(':'))
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or_else(|| profile_port(dir));
    if facts.has_cap("internet_direct") && !p.internet_listen.is_empty() {
        listening.push(p.internet_listen.clone());
    }
    let relays: Vec<Value> = p2p.map_or_else(Vec::new, |i| {
        i.relay_health
            .iter()
            .map(|h| {
                let mut r = json!({"relay": h.relay, "state": h.state, "source": h.source});
                if !h.operator_pub_hex.is_empty() {
                    r["friend_address"] = crate::contacts::address_of_hex(&h.operator_pub_hex)
                        .map_or(Value::Null, Value::from);
                }
                r
            })
            .collect()
    });
    let port_map = p2p.and_then(|i| i.port_map.as_ref());
    let pmp = raven_core::portmap_gate::PORT_MAP_PRODUCTION_ENABLED;
    let pmp_live = raven_core::portmap_gate::port_map_live_enabled();
    let mut port_mapping = json!({
        "setting": match p.upnp {
            Some(true) => "on",
            Some(false) => "off",
            None => "unset",
        },
        "router": p2p.map_or("", |i| i.upnp.as_str()),
        // NAT-PMP and PCP besides UPnP (Phase 4): their own gate.
        "nat_pmp_pcp": if !pmp_live { "preview" } else if pmp { "on" } else { "lab" },
    });
    if let Some(m) = port_map {
        port_mapping["v4"] = m.v4.clone().into();
        port_mapping["v4_port"] = m.v4_port.into();
        port_mapping["v6"] = m.v6.clone().into();
    }
    let proxy = json!({
        "setting": if p.p2p_proxy.is_empty() { "auto".to_owned() } else { p.p2p_proxy.clone() },
        "in_use": p2p.map_or("", |i| i.proxy.as_str()),
        "lines": bridge::proxy_lines(dir, &facts.status),
    });
    let n = &facts.nearby;
    let mut nearby = json!({
        "state": n.state,
        "saved": n.saved,
        "on_this_os": NEARBY_ON_THIS_OS,
        "rows": rows_json(&n.rows),
    });
    if let Some(info) = &n.info {
        nearby["enabled"] = info.enabled.into();
        nearby["radio"] = info.radio.clone().into();
        nearby["address_privacy"] = info.address_privacy.clone().into();
        nearby["in_range"] = info.in_range.into();
        nearby["connected"] = info.pipes.into();
    }
    let c = &facts.carry;
    let carry = json!({
        "friends_carry_mine": {
            "setting": match c.friends_carry_mine {
                Some(true) => "on",
                Some(false) => "off",
                None => "not_decided",
            },
            "mail_friends": c.mail_friends,
            "chosen_by_hand": c.mail_friends_by_hand,
            "offering": c.offering,
            "offering_over_internet": c.offering_internet,
            "offering_reachable": c.offering_reachable,
            "listed_by_hand": c.listed,
        },
        "carry_for_friends": {
            "on": c.carry_for_friends,
            "held_messages": c.held_messages,
            "held_bytes": c.held_bytes,
            "handoff": c.handoff,
            "handoff_lines": c.handoff_lines,
        },
        "letters_left": c.letters_left,
        "relay_for_friends": {
            "setting": p.relay_offer == Some(true),
            "offering": p2p.and_then(|i| i.friend_relay.as_ref()).is_some_and(|f| f.offering),
            "offered_to": p2p.and_then(|i| i.friend_relay.as_ref()).map_or(0, |f| f.offered_to),
        },
    });
    let help = json!({
        "bridge": p.bridge,
        "store": p.store,
        "relay": p.relay,
        "automatic": p.auto_policy,
        "effects": {
            "bridge": flag_effect("bridge"),
            "store": flag_effect("store"),
            "relay": flag_effect("relay"),
        },
    });
    let mut v = json!({
        "build": build_kind(),
        "node": if facts.answered() { "running" } else { "not_running" },
        "carriers": CARRIERS.iter().map(|id| way(id, facts)).collect::<Vec<_>>(),
        "protections": PROTECTIONS.iter().map(|id| way(id, facts)).collect::<Vec<_>>(),
        "listening": listening,
        "port": port,
        "port_mapping": port_mapping,
        "relays": relays,
        "proxy": proxy,
        "nearby": nearby,
        "carry": carry,
        "help": help,
        "hide_ip": p.hide_ip,
        "lab_switches": lab_switches_seen(),
        "texts": {
            "carry_for_friends": bridge::CARRY_FOR_FRIENDS_CONSENT,
            "friends_carry_mine": bridge::FRIENDS_CARRY_MINE_CONSENT,
            "handoff": bridge::HANDOFF_CONSENT,
        },
    });
    if !p.internet_listen.is_empty() {
        v["internet_listen"] = p.internet_listen.clone().into();
    }
    if !p.p2p_listen.is_empty() {
        v["p2p_listen"] = p.p2p_listen.clone().into();
    }
    if let Some(i) = p2p {
        v["p2p_addresses"] = json!(i.listen_addrs);
    }
    if let Some(m) = facts.lan.meeting_until_ms {
        v["lan_until_ms"] = m.into();
    }
    if facts.policy.is_none() {
        v["policy_unreadable"] = true.into();
    }
    if let Some(t) = facts.tor() {
        v["tor"] = t.json();
    }
    v
}

// ── network.set ────────────────────────────────────────────────────────────

/// When a change takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applies {
    /// The running raven-node follows it now (or reads it at its next start).
    Now,
    /// When raven-node starts again.
    Restart,
}

/// One change `network.set` makes.
struct Change {
    setting: &'static str,
    value: Value,
    effect: String,
    applies: Applies,
    lines: Vec<String>,
}

/// The settings `network.set` takes, in the order it applies them.
const SETTINGS: [&str; 17] = [
    "lan",
    "internet",
    "p2p",
    "port_mapping",
    "proxy",
    "nearby",
    "carry_for_friends",
    "friends_carry_mine",
    "handoff",
    "relay_for_friends",
    "bridge",
    "store",
    "relay",
    "hide_ip",
    // Taken with their setting: `lan_for` with `lan`, `internet_listen`
    // with `internet`, `p2p_listen` and `relays` with `p2p`.
    "lan_for",
    "internet_listen",
    "p2p_listen",
];

/// The gated way a setting turns on (None: no gate).
fn gate_for_setting(setting: &str) -> Option<&'static str> {
    match setting {
        "internet" => Some("internet"),
        "p2p" | "port_mapping" => Some("p2p"),
        "proxy" => Some("proxy"),
        "nearby" => Some("nearby"),
        "carry_for_friends" | "friends_carry_mine" => Some("custody"),
        "handoff" => Some("handoff"),
        "relay_for_friends" => Some("friend_relay"),
        _ => None,
    }
}

/// The CLI command each setting runs, for the refusal's words.
fn cli_of(setting: &str) -> &'static str {
    match setting {
        "internet" => "raven node internet on",
        "p2p" => "raven node p2p on",
        "port_mapping" => "raven node upnp on",
        "proxy" => "raven node proxy",
        "nearby" => "raven nearby enable",
        "carry_for_friends" => "raven node custody on",
        "friends_carry_mine" => "raven custody use on",
        "handoff" => "raven node custody handoff on",
        "relay_for_friends" => "raven relay offer on",
        _ => "",
    }
}

/// The refusal for turning on a way this build holds.
fn held(setting: &str) -> ApiError {
    let way = gate_for_setting(setting).unwrap_or("");
    let g = gate(way);
    let mut detail = format!(
        "{setting}: {} is false in this build",
        if g.constant.is_empty() {
            "its gate"
        } else {
            g.constant
        }
    );
    if cfg!(debug_assertions) && !g.switches.is_empty() {
        detail.push_str(&format!(
            "; a developer build opens it with {}=1",
            g.switches.join("=1 ")
        ));
    }
    let cli = cli_of(setting);
    if !cli.is_empty() {
        detail.push_str(&format!(
            " (the CLI's `{cli}` is refused or kept off the same way)"
        ));
    }
    ApiError::new(
        code::NOT_AVAILABLE_YET,
        format!(
            "{} isn't in this version of Raven yet. Nothing was changed.",
            name_of(way)
        ),
        detail,
    )
}

/// A setting that turns something on needs the person's yes to what it
/// means first.
fn needs_consent(setting: &str) -> bool {
    matches!(
        setting,
        "carry_for_friends" | "friends_carry_mine" | "handoff"
    )
}

/// Lines the CLI said, terminal colours removed.
fn plain_lines(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|l| raven_core::sanitize::strip_ansi(&l).trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The settings of a `network.set` request, in the order they are
/// applied, checked before anything changes: the types, the gate of every
/// way turned on (a held one is NOT_AVAILABLE_YET, in a release build
/// always), and the person's yes (`agreed`) where a setting needs it
/// (CONSENT_NEEDED). The companions (`lan_for`, `internet_listen`,
/// `p2p_listen`, `relays`) are read with their setting.
pub(crate) fn checked_settings(args: &Args) -> Result<Vec<(&'static str, Value)>, ApiError> {
    let main: Vec<(&'static str, Value)> = SETTINGS
        .iter()
        .filter(|s| !matches!(**s, "lan_for" | "internet_listen" | "p2p_listen"))
        .filter_map(|s| {
            args.get(s)
                .filter(|v| !v.is_null())
                .map(|v| (*s, v.clone()))
        })
        .collect();
    if main.is_empty() {
        return Err(ApiError::bad_request(
            "network.set needs at least one setting (API.md lists them)",
        ));
    }
    let agreed = args.opt_bool("agreed")?.unwrap_or(false);
    for (setting, value) in &main {
        let on = match *setting {
            "proxy" => {
                let text = value.as_str().ok_or_else(|| {
                    ApiError::bad_request("\"proxy\" must be auto, off or http://host:port")
                })?;
                !text.trim().eq_ignore_ascii_case("off")
            }
            _ => value.as_bool().ok_or_else(|| {
                ApiError::bad_request(format!("\"{setting}\" must be true or false"))
            })?,
        };
        if !on {
            continue;
        }
        if let Some(way) = gate_for_setting(setting) {
            if !gate(way).live {
                return Err(held(setting));
            }
        }
        if needs_consent(setting) && !agreed {
            return Err(ApiError::new(
                code::CONSENT_NEEDED,
                crate::envelope::default_message(code::CONSENT_NEEDED),
                format!(
                    "{setting}: show network.status texts.{setting} and pass \"agreed\": true \
                     with the person's yes"
                ),
            ));
        }
    }
    Ok(main)
}

impl Inner {
    /// `network.set`: every setting checked first (types, gates, consent),
    /// then applied in [`SETTINGS`] order with the CLI's own commands.
    pub(crate) fn network_set(&self, args: &Args) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        // Everything is checked before anything is changed.
        let main = checked_settings(args)?;
        // Then the identity: the CLI's commands work on a set-up profile.
        self.identity()?;
        let opt_str = |key: &str| -> Result<Option<String>, ApiError> {
            Ok(args.opt_str(key)?.map(str::to_owned))
        };
        let lan_for = opt_str("lan_for")?;
        let internet_listen = opt_str("internet_listen")?;
        let p2p_listen = opt_str("p2p_listen")?;
        let relays: Vec<String> = match args.get("relays") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| ApiError::bad_request("\"relays\" must be a list of texts"))
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(ApiError::bad_request("\"relays\" must be a list of texts")),
        };
        let mut done: Vec<Change> = Vec::new();
        for (setting, value) in &main {
            let change = self
                .apply_setting(
                    &dir,
                    setting,
                    value,
                    &lan_for,
                    &internet_listen,
                    &p2p_listen,
                    &relays,
                )
                .map_err(|e| {
                    let before: Vec<&str> = done.iter().map(|c| c.setting).collect();
                    let detail = if before.is_empty() {
                        e.detail.clone()
                    } else {
                        format!("{} (already changed: {})", e.detail, before.join(", "))
                    };
                    ApiError::new(e.code, e.message.clone(), detail)
                })?;
            done.push(change);
        }
        let facts = NetFacts::read(&dir);
        let restart = done.iter().any(|c| c.applies == Applies::Restart) && facts.answered();
        let changes: Vec<Value> = done
            .into_iter()
            .map(|c| {
                json!({
                    "setting": c.setting,
                    "value": c.value,
                    "effect": c.effect,
                    "applies": match c.applies {
                        Applies::Now => "now",
                        Applies::Restart => "restart",
                    },
                    "detail": plain_lines(c.lines),
                })
            })
            .collect();
        Ok(json!({
            "changes": changes,
            "restart_needed": restart,
            "status": network_view(&dir, &facts),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_setting(
        &self,
        dir: &Path,
        setting: &'static str,
        value: &Value,
        lan_for: &Option<String>,
        internet_listen: &Option<String>,
        p2p_listen: &Option<String>,
        relays: &[String],
    ) -> Result<Change, ApiError> {
        let failed = |why: String| {
            ApiError::new(
                code::BAD_REQUEST,
                "Raven couldn't change that setting. Open Details to see why; nothing else was \
                 changed.",
                why,
            )
        };
        let on = value.as_bool().unwrap_or(false);
        let mut change = Change {
            setting,
            value: value.clone(),
            effect: String::new(),
            applies: Applies::Now,
            lines: Vec::new(),
        };
        match setting {
            "lan" => {
                change.lines =
                    bridge::lan_set(dir, on, lan_for.as_deref().filter(|_| on)).map_err(failed)?;
                change.effect = match (on, lan_for) {
                    (true, Some(t)) => format!(
                        "Raven sends and receives on this network for {t}, then turns it off by \
                         itself."
                    ),
                    (true, None) => "Raven sends and receives on this network again.".into(),
                    (false, _) => "Raven stops sending and receiving on this network. Friends \
                                   here can't reach you until you turn it on again."
                        .into(),
                };
                if let Some(t) = lan_for.as_deref().filter(|_| on) {
                    change.value = json!({"on": true, "for": t});
                }
            }
            "internet" => {
                let listen = if on {
                    Some(
                        internet_listen
                            .clone()
                            .filter(|l| !l.trim().is_empty())
                            .or_else(|| {
                                raven_core::node_policy::try_load_policy(dir)
                                    .ok()
                                    .map(|p| p.internet_listen)
                                    .filter(|l| !l.is_empty())
                            })
                            .unwrap_or_else(|| {
                                format!("0.0.0.0:{}", raven_core::paths::DEFAULT_INTERNET_PORT)
                            }),
                    )
                } else {
                    None
                };
                bridge::internet_set(dir, listen.as_deref()).map_err(failed)?;
                change.applies = Applies::Restart;
                change.effect = match &listen {
                    Some(at) => format!(
                        "Raven listens for friends over the internet on {at} once its background \
                         program restarts. Only your verified friends get an answer, but anyone \
                         who scans that port can see that something listens there; your router \
                         or firewall may also need to let it in."
                    ),
                    None => "Raven closes its internet port when its background program restarts."
                        .into(),
                };
                if let Some(at) = listen {
                    change.value = json!({"on": true, "listen": at});
                }
            }
            "p2p" => {
                let args = on.then(|| {
                    let listen = p2p_listen
                        .clone()
                        .filter(|l| !l.trim().is_empty())
                        .or_else(|| {
                            raven_core::node_policy::try_load_policy(dir)
                                .ok()
                                .map(|p| p.p2p_listen)
                                .filter(|l| !l.is_empty())
                        })
                        .unwrap_or_else(|| raven_core::paths::DEFAULT_P2P_PORT.to_string());
                    (listen, relays.to_vec(), None)
                });
                bridge::p2p_set(dir, args).map_err(failed)?;
                change.applies = Applies::Restart;
                change.effect = if on {
                    "Raven reaches friends across networks, directly or through relays, once its \
                     background program restarts. The relays you use learn your network ID, your \
                     IP address and when you talk."
                        .into()
                } else {
                    "Raven stops using peer-to-peer and relays when its background program \
                     restarts."
                        .into()
                };
            }
            "port_mapping" => {
                bridge::port_mapping_set(dir, on).map_err(failed)?;
                change.applies = Applies::Restart;
                change.effect = if on {
                    "Raven asks your router to open its peer-to-peer port (UPnP, NAT-PMP or PCP) \
                     when its background program restarts. Your router may not support it."
                        .into()
                } else {
                    "Raven won't ask your router to open a port.".into()
                };
            }
            "proxy" => {
                let text = value.as_str().unwrap_or("").trim().to_owned();
                change.lines = bridge::proxy_set(dir, &text).map_err(failed)?;
                change.applies = Applies::Restart;
                change.effect = if text.eq_ignore_ascii_case("off") {
                    "Raven dials relays directly, never through a web proxy.".into()
                } else if text.eq_ignore_ascii_case("auto") || text.is_empty() {
                    "Raven uses this computer's HTTPS proxy setting when a network lets only web \
                     traffic out (applies when its background program restarts)."
                        .into()
                } else {
                    "Raven dials relays through this web proxy when a network lets only web \
                     traffic out (applies when its background program restarts). A user name \
                     and password are never saved here."
                        .into()
                };
            }
            "nearby" => {
                change.lines = bridge::nearby_set(dir, on).map_err(failed)?;
                change.effect = if on {
                    "Raven may use Bluetooth to reach your verified friends when they are in \
                     range. It advertises only while it has something to send, under a random \
                     name only they can recognise."
                        .into()
                } else {
                    "Raven stops using Bluetooth.".into()
                };
            }
            "carry_for_friends" => {
                change.lines = bridge::carry_for_friends_set(dir, on).map_err(failed)?;
                change.effect = if on {
                    "This computer holds sealed messages for your verified friends while they are \
                     offline. It can't read them, but it sees who wrote to whom, and when."
                        .into()
                } else {
                    "This computer stops taking messages for friends. What it holds stays until \
                     it is collected or expires."
                        .into()
                };
            }
            "friends_carry_mine" => {
                change.lines = bridge::friends_carry_mine_set(dir, on).map_err(failed)?;
                change.effect = if on {
                    "When a friend can't be reached, Raven may leave a sealed copy with a friend \
                     you both verified, and collect mail friends hold for you."
                        .into()
                } else {
                    "Raven doesn't leave your messages with friends or collect mail from them."
                        .into()
                };
            }
            "handoff" => {
                change.lines = bridge::handoff_set(dir, on).map_err(failed)?;
                change.effect = if on {
                    "This computer may pass sealed messages on between your verified friends, \
                     and hold ones a friend passes on. It can't read them."
                        .into()
                } else {
                    "New handoffs are refused; what this computer already took on is still passed \
                     on or kept until it expires."
                        .into()
                };
            }
            "relay_for_friends" => {
                change.lines = bridge::relay_offer_set(dir, on).map_err(failed)?;
                change.effect = if on {
                    "This computer lends a relay to your verified friends, so friends behind \
                     other routers can reach each other through it. It must be reachable from \
                     the internet, and it shows its IP address to those friends."
                        .into()
                } else {
                    "This computer stops relaying for friends.".into()
                };
            }
            "bridge" | "store" | "relay" => {
                // `raven node bridge|store|relay on|off` (cli.rs
                // `set_node_flag`): AUTO off, the one flag set, every other
                // setting kept. raven-node reads it again within a second.
                raven_core::node_policy::update_policy(dir, |p| {
                    p.auto_policy = false;
                    match setting {
                        "bridge" => p.bridge = on,
                        "store" => p.store = on,
                        _ => p.relay = on,
                    }
                })
                .map_err(|e| failed(format!("save policy failed: {e}")))?;
                change.effect = flag_effect(setting).into();
            }
            "hide_ip" => {
                bridge::hide_ip_set(dir, on).map_err(failed)?;
                change.effect = if on {
                    "Your contacts no longer learn this computer's IP address from Raven; they \
                     reach you through relays or friends instead."
                        .into()
                } else {
                    "Your contacts may reach you directly again.".into()
                };
            }
            other => return Err(ApiError::bad_request(format!("unknown setting {other:?}"))),
        }
        Ok(change)
    }
}

// ── network.check ──────────────────────────────────────────────────────────

/// A doctor line as `{key, value}`: `key: value` or `key=value …`.
fn split_line(line: &str) -> (String, String) {
    let line = line.trim();
    let colon = line.find(": ");
    let eq = line.find('=');
    let at = match (colon, eq) {
        (Some(c), Some(e)) if e < c => Some((e, 1)),
        (Some(c), _) => Some((c, 2)),
        (None, Some(e)) => Some((e, 1)),
        (None, None) => None,
    };
    match at {
        Some((i, skip)) if i > 0 && !line[..i].contains(' ') => {
            (line[..i].to_owned(), line[i + skip..].trim().to_owned())
        }
        _ => (String::new(), line.to_owned()),
    }
}

/// A plain sentence for the doctor rows Raven has one for.
fn plain_of(key: &str, value: &str) -> Option<String> {
    let first = value.split_whitespace().next().unwrap_or("");
    let s = match (key, first) {
        ("receiving", "yes") => "Raven receives messages on this network.",
        ("receiving", "local_only") => {
            "Raven listens on this computer only: friends on your network can't reach it."
        }
        ("receiving", "not_running") => "Raven's background program isn't running.",
        ("receiving", "not_answering") => "Raven's background program doesn't answer.",
        ("receiving", "no") => "Raven isn't receiving messages on this network now.",
        ("reach_class", "off") => "Peer-to-peer isn't running, so only direct ways are used.",
        ("reach_class", "unknown") => {
            "Raven hasn't found out yet how friends on the internet can reach this computer."
        }
        ("internet_route", "none") => "This computer has no route to the internet right now.",
        ("router_pcp", "yes") => "Your router can open ports when asked (PCP).",
        ("router_pcp", "no") => "Your router didn't answer PCP.",
        ("router_natpmp", "yes") => "Your router can open ports when asked (NAT-PMP).",
        ("router_natpmp", "no") => "Your router didn't answer NAT-PMP.",
        ("router_upnp_igd", "none") => "No UPnP router answered.",
        ("router_upnp_igd", _) => "Your router speaks UPnP.",
        ("router_external_v4", "global") => "Your router has a public internet address.",
        ("router_external_v4", "behind_another_nat") => {
            "Another router sits between yours and the internet (carrier-grade NAT): friends \
             can't reach you directly from outside."
        }
        ("router_external_v4", _) => "Your router didn't say its internet address.",
        ("router_gateway_v4", "none") => "This computer has no IPv4 router.",
        ("router_gateway_v4", "public") => {
            "This computer is directly on the internet: there is no router to ask."
        }
        ("router_gateway_v6", "found") => "This computer has an IPv6 router.",
        ("router_ipv6_firewall_control", "yes") => {
            "Your router can open its IPv6 firewall for this computer."
        }
        ("router_local_network", "refused") => {
            "macOS didn't let Raven ask the router: allow Local Network for Raven in System \
             Settings, then check again."
        }
        _ => return None,
    };
    Some(s.to_owned())
}

/// A text that tells the person to type something: a command, a key to
/// press in a terminal or an environment switch.
fn has_command(text: &str) -> bool {
    text.contains('`')
        || text.contains("Ctrl-")
        || text.contains("RAVEN_")
        || text.contains("--")
        || ["ash ", "raven ", "run:"].iter().any(|w| {
            text.match_indices(w)
                .any(|(i, _)| i == 0 || !text[..i].ends_with(|c: char| c.is_alphanumeric()))
        })
}

/// `text` without what names a command: a part in brackets that holds one
/// goes, then every sentence that still holds one.
fn without_commands(text: &str) -> String {
    let mut out = String::new();
    let mut group = String::new();
    let mut depth = 0usize;
    for ch in text.chars() {
        if ch == '(' {
            depth += 1;
        }
        if depth > 0 {
            group.push(ch);
            if ch == ')' {
                depth -= 1;
                if depth == 0 {
                    if !has_command(&group) {
                        out.push_str(&group);
                    }
                    group.clear();
                }
            }
        } else {
            out.push(ch);
        }
    }
    if !has_command(&group) {
        out.push_str(&group);
    }
    let kept: Vec<&str> = out
        .split_inclusive(". ")
        .flat_map(|s| s.split_inclusive("; "))
        .filter(|s| !has_command(s))
        .collect();
    let joined = kept
        .join("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    joined
        .replace(" ,", ",")
        .replace(" .", ".")
        .trim_end_matches([' ', ',', ':', ';'])
        .to_owned()
}

/// The doctor's next step in the app's words: what to do in the app, never
/// a command (the CLI's own words stay under Technical details).
fn app_step(next: &str) -> String {
    let t = next.trim();
    let lower = t.to_ascii_lowercase();
    let known = if lower.starts_with("all set") {
        Some("All set: Raven can send and receive messages on this computer.")
    } else if lower.starts_with("run `ash init`") {
        Some("Set up Raven on this computer first.")
    } else if lower.starts_with("add your first friend") {
        Some("Add your first friend: share your card with them and add theirs.")
    } else if lower.starts_with("to receive messages run") {
        Some("Raven's background program isn't running. Start it on the Network page.")
    } else if lower.starts_with("lan is off") {
        Some("Raven is turned off on this network. Turn Local network on on the Network page.")
    } else {
        None
    };
    let plain = match known {
        Some(s) => s.to_owned(),
        None => without_commands(t).replace("raven-node", "Raven's background program"),
    };
    let plain = plain.trim();
    if plain.is_empty() {
        return "Raven has a suggestion for this computer: see Technical details.".to_owned();
    }
    let mut chars = plain.chars();
    let first = chars.next().map(|c| c.to_uppercase().collect::<String>());
    let mut out = first.unwrap_or_default() + chars.as_str();
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

/// `{key, value, plain?}` rows of doctor lines; a line indented under the
/// one before it keeps that one's key.
fn check_rows(lines: &[String]) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut last_key = String::new();
    for raw in lines {
        let indented = raw.starts_with("  ");
        let (key, value) = if indented {
            (last_key.clone(), raw.trim().to_owned())
        } else {
            split_line(raw)
        };
        if !indented {
            last_key = key.clone();
        }
        let mut row = json!({"key": key, "value": value});
        if let Some(plain) = plain_of(&key, &value) {
            row["plain"] = plain.into();
        }
        rows.push(row);
    }
    rows
}

impl Inner {
    /// `network.check {router?}`: `raven doctor`'s summary and network lines
    /// (and with `router: true`, `raven doctor --router`'s read-only router
    /// probe, up to about 4 s).
    pub(crate) fn network_check(&self, args: &Args) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        let router = args.opt_bool("router")?.unwrap_or(false);
        let probe = router.then(|| std::thread::spawn(bridge::router_lines));
        let (summary, next) = bridge::doctor_summary(&dir);
        let status = bridge::ipc_request_timeout(&dir, &IpcRequest::status(), PROBE_TIMEOUT);
        let mut lines = vec![format!("receiving: {}", bridge::doctor_receiving(&status))];
        lines.extend(bridge::doctor_network_lines(&dir, &status));
        if let Ok(p) = raven_core::node_policy::try_load_policy(&dir) {
            lines.push(format!(
                "policy: bridge={} store={} relay={}",
                p.bridge, p.store, p.relay
            ));
        }
        // The CLI's own words, for Technical details.
        let mut technical: Vec<String> = summary
            .iter()
            .map(|(label, value)| format!("{label}: {value}"))
            .collect();
        if !technical.iter().any(|l| l.starts_with("next step:")) {
            technical.push(format!("next step: {next}"));
        }
        // Plain words: the next step once (not again as a summary row), and
        // no command in either (E1: "ash send --contact NAME ...").
        let summary: Vec<Value> = summary
            .into_iter()
            .map(|(label, value)| {
                let key = label.replace([' ', '-'], "_").to_ascii_lowercase();
                (key, label, value)
            })
            .filter(|(key, _, _)| key != "next_step")
            .map(|(key, label, value)| {
                json!({"key": key, "label": label, "value": without_commands(&value)})
            })
            .collect();
        let mut v = json!({
            "summary": summary,
            "next_step": app_step(&next),
            "rows": check_rows(&lines),
            "technical": technical,
        });
        if let Some(probe) = probe {
            let router_lines = probe
                .join()
                .unwrap_or_else(|_| vec!["router_probe=failed".to_owned()]);
            v["router"] = check_rows(&router_lines).into();
        }
        Ok(v)
    }
}

// ── contacts.routes / contacts.set_routes ──────────────────────────────────

/// `carriers.away` for [`bridge::away_reach`]'s answer: until when a message
/// written now could wait, or that none can (`meet_first`). `first_message`
/// says why for a friend Raven hasn't connected with yet: a first message
/// needs you both online, the terminal app's words (E1: the apps said "meet
/// first" there too, which is for a secure connection that ended).
/// `meet_first` stays set with it, so an app that knows only that field
/// keeps its line.
fn away_json(reach: QueueReach) -> Value {
    match reach {
        QueueReach::CanWait { until_ms } => json!({"until_ms": until_ms}),
        QueueReach::Ended { .. } => json!({"meet_first": true}),
        QueueReach::NeverPaired => json!({"meet_first": true, "first_message": true}),
    }
}

impl Inner {
    /// `contacts.routes {address}`: the friend's saved routes, what it told
    /// this node (route hints), whether this computer's IP is hidden from it,
    /// and who carries its mail. Never its security words or old code.
    pub(crate) fn contacts_routes(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        self.routes_of(address)
    }

    pub(crate) fn routes_of(&self, address: &str) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        let contact = self.contact(address)?;
        let routes = bridge::contact_routes(&dir, &contact.pub_hex)
            .map_err(|e| ApiError::of(code::NOT_A_CONTACT, e))?;
        // One source for every screen (E1: Routes said "Lab only" where the
        // Network page said "Off"): a route's state is its way's state in
        // `network.status`, read from the running raven-node. An Internet
        // route is dialled out, which needs no listener of this computer's
        // own: it follows the way's gate only.
        let facts = NetFacts::read(&dir);
        let status = &facts.status;
        let state = |id: &'static str| -> String {
            if id == "internet" {
                let g = gate(id);
                return if !g.live {
                    "preview"
                } else if g.lab() {
                    "lab"
                } else {
                    "on"
                }
                .to_owned();
            }
            way(id, &facts)["state"]
                .as_str()
                .unwrap_or("preview")
                .to_owned()
        };
        let mut list = Vec::new();
        if !contact.lan_dial.trim().is_empty() {
            list.push(json!({"kind": "lan", "label": name_of("lan"),
                             "value": contact.lan_dial.trim(), "state": state("lan")}));
        }
        if !contact.internet_dial.trim().is_empty() {
            list.push(json!({"kind": "internet", "label": name_of("internet"),
                             "value": contact.internet_dial.trim(), "state": state("internet")}));
        }
        if !contact.p2p.trim().is_empty() {
            let mut r = json!({"kind": "p2p", "label": name_of("p2p"),
                               "value": contact.p2p.trim(), "via": routes.p2p_via,
                               "state": state("p2p")});
            if !routes.p2p_next.is_empty() {
                r["next"] = routes.p2p_next.clone().into();
            }
            list.push(r);
        }
        if contact.pinned {
            list.push(json!({"kind": "nearby", "label": name_of("nearby"),
                             "value": "", "state": state("nearby")}));
        }
        let learned = hex::decode(contact.pub_hex.trim())
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
            .and_then(|peer| {
                raven_core::learned_routes::learned(&dir, &peer, crate::engine::now_ms())
            })
            .map(|l| {
                let mut v = json!({
                    "relays": l.relays.len(),
                    "direct": l.direct.len(),
                    "mail_friends": l.custodians.len(),
                    "peer_id_proven": l.peer_id_proven,
                    "expires_at_ms": l.expires_at_ms,
                });
                if let Some(id) = l.peer_id {
                    v["peer_id"] = id.into();
                }
                if let Some(lan) = l.lan {
                    if let Some(port) = lan.port {
                        v["lan_port"] = port.into();
                    }
                }
                v
            });
        let carriers =
            bridge::contact_carriers(&dir, &contact.pub_hex, status).map_err(ApiError::internal)?;
        let friend = |hex: &str| -> Value {
            let address = crate::contacts::address_of_hex(hex);
            let name = self.contacts().ok().and_then(|list| {
                list.iter()
                    .find(|c| c.pub_hex.eq_ignore_ascii_case(hex))
                    .map(|c| crate::safety::line(&c.label))
            });
            json!({"address": address, "name": name})
        };
        let mut carry = json!({
            "hints": state("route_hints"),
            "told": carriers.told.iter().map(|(k, inbox)| {
                let mut f = friend(k);
                f["takes_handoffs"] = (*inbox).into();
                f
            }).collect::<Vec<_>>(),
            "told_unknown": carriers.told_unknown,
            "listed": carriers.listed.iter().map(|(k, usable)| {
                let mut f = friend(k);
                f["usable"] = (*usable).into();
                f
            }).collect::<Vec<_>>(),
            "receipts_stranded": carriers.receipts_stranded,
        });
        if let Some((kind, name, until)) = carriers.coverage {
            carry["coverage"] = json!({"kind": kind, "name": name, "until": until});
        }
        // How long a message written now could wait for the friend, by the
        // rule `raven contact list` and the terminal app use (E1: "until
        // tomorrow" there, "up to 7 days" here).
        let now = crate::engine::now_ms();
        if !contact.blocked {
            if let Some(reach) = bridge::away_reach(&dir, &contact.pub_hex, now) {
                carry["away"] = away_json(reach);
            }
        }
        let mut v = json!({
            "address": contact.address,
            "verified": contact.pinned,
            "routes": list,
            "hide_ip": routes.hide_ip,
            "carriers": carry,
        });
        if let Some(l) = learned {
            v["learned"] = l;
        }
        // Where Raven reaches the friend on the local network now (E1:
        // Routes showed only the saved address, an old one, while every
        // message went to the new one): this run's last delivery there, or
        // where the friend last reached this computer from, whichever came
        // later. `saved_stale`: the saved LAN address is another one.
        let used = crate::engine::lock(&self.book)
            .lan_used
            .get(&contact.pub_hex.to_ascii_lowercase())
            .cloned();
        let seen = bridge::lan_seen_dial(
            &dir,
            &contact.pub_hex,
            &contact.lan_dial,
            contact.pinned,
            now,
        );
        if let Some((addr, at)) = [used, seen].into_iter().flatten().max_by_key(|(_, at)| *at) {
            let saved = contact.lan_dial.trim();
            v["lan_now"] = json!({
                "addr": crate::safety::line(&addr),
                "at_ms": at,
                "saved_stale": !saved.is_empty() && !saved.eq_ignore_ascii_case(addr.trim()),
            });
        }
        Ok(v)
    }

    /// `contacts.set_routes {address, internet?, p2p?, via?, clear?,
    /// custodians?, hide_ip?}`: `raven contact set-addr` and `raven contact
    /// hide-ip` for one friend.
    pub(crate) fn contacts_set_routes(&self, args: &Args) -> OpResult {
        let address = args.str("address")?.trim().to_owned();
        let dir = self.data_dir()?.to_path_buf();
        let contact = self.contact(&address)?;
        let list = |key: &str| -> Result<Option<Vec<String>>, ApiError> {
            match args.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|v| {
                        v.as_str().map(|s| s.trim().to_owned()).ok_or_else(|| {
                            ApiError::bad_request(format!("\"{key}\" must be a list of texts"))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Some),
                Some(_) => Err(ApiError::bad_request(format!(
                    "\"{key}\" must be a list of texts"
                ))),
            }
        };
        let internet = args
            .opt_str("internet")?
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let p2p = args
            .opt_str("p2p")?
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let via = list("via")?.unwrap_or_default();
        let clear = list("clear")?.unwrap_or_default();
        let custodians = list("custodians")?;
        let hide_ip = args.opt_bool("hide_ip")?;
        if internet.is_none()
            && p2p.is_none()
            && via.is_empty()
            && clear.is_empty()
            && custodians.is_none()
            && hide_ip.is_none()
        {
            return Err(ApiError::bad_request(
                "contacts.set_routes needs internet, p2p, via, clear, custodians or hide_ip",
            ));
        }
        let invalid = |e: String| {
            ApiError::new(
                code::BAD_REQUEST,
                "That route isn't one Raven can use. Check it and try again; nothing was changed.",
                e,
            )
        };
        let _guard = crate::engine::lock(&self.contacts_lock);
        if internet.is_some() || p2p.is_some() || !via.is_empty() || !clear.is_empty() {
            bridge::set_contact_routes(&dir, &contact.address, internet, p2p, &via, &clear)
                .map_err(invalid)?;
        }
        if let Some(custodians) = &custodians {
            // Friends named by address; the CLI resolves names and tags too.
            bridge::set_contact_custodians(&dir, &contact.address, custodians).map_err(invalid)?;
        }
        if let Some(on) = hide_ip {
            bridge::contact_hide_ip_set(&dir, &contact.address, on).map_err(invalid)?;
        }
        drop(_guard);
        self.invalidate_contacts();
        let c = self.contact(&contact.address)?;
        let unread = self
            .refresh(std::time::Duration::from_millis(1500))
            .ok()
            .and_then(|s| s.unread.get(&c.pub_hex.to_ascii_lowercase()).copied());
        let refreshed = self.contact_json(&c, None, unread);
        let routes = self.routes_of(&contact.address)?;
        Ok(json!({"contact": refreshed, "routes": routes}))
    }
}

// ── security.status ────────────────────────────────────────────────────────

impl Inner {
    /// `security.status`: `raven security` as the terminal app's SEC screen
    /// reads it (no write: the ledger is never created by a read).
    pub(crate) fn security_status(&self) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        let g = gate("security_events");
        let view = bridge::security_view(&dir).map_err(|e| {
            ApiError::new(
                code::PROFILE_UNREADABLE,
                "Raven can't read its security notices right now. Open Details to see why.",
                e,
            )
        })?;
        let notices: Vec<Value> = view
            .notices
            .iter()
            .map(|n| {
                let mut v = json!({
                    "id": n.id,
                    "level": if n.alert { "alert" } else { "warning" },
                    "name": n.name,
                    "headline": n.headline,
                    "what_raven_did": n.did,
                    "what_to_do": n.todo,
                    "when": n.when,
                    "details": rows_json(&n.details),
                });
                if let Some(peer) = &n.peer {
                    v["address"] = crate::contacts::address_of_hex(peer).into();
                }
                v
            })
            .collect();
        let mut v = json!({
            "available": g.live,
            "lab": g.lab(),
            "kept": view.kept,
            "notices": notices,
            "counted": view.counted,
        });
        if let Ok(IpcResponse::Status {
            security: Some(s), ..
        }) = bridge::ipc_request_timeout(&dir, &IpcRequest::status(), PROBE_TIMEOUT)
        {
            v["node"] = json!({
                "strangers_refused_1h": s.strangers_refused_1h,
                "failed_handshakes_1h": s.preauth_failures_1h,
                "bans_active": s.bans_active,
                "link_tag_failures_24h": s.link_tag_failures_24h,
                "alerts_open": s.alerts_open,
            });
        }
        Ok(v)
    }
}

// ── lock.* (Lock v2) ───────────────────────────────────────────────────────

/// The CLI command Lock now is without Lock v2.
const LOCK_CLI: &str = "raven lock";

impl Inner {
    /// `lock.state`.
    pub(crate) fn lock_state(&self) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        let g = gate("lock_v2");
        let node = if g.live {
            bridge::lock_v2_state(&dir)
        } else {
            None
        };
        let mut v = json!({
            "available": g.live,
            "lab": g.lab(),
            "supported": node.is_some(),
            "locked": node.unwrap_or(false),
        });
        if let Some(has) = bridge::has_passphrase(&dir) {
            v["has_passphrase"] = has.into();
        }
        Ok(v)
    }

    /// `lock.now`: Lock v2 (raven-node keeps running and forgets its keys).
    pub(crate) fn lock_now(&self) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        if !gate("lock_v2").live {
            return Err(crate::engine::not_in_the_app("lock.now", LOCK_CLI));
        }
        if bridge::lock_v2_state(&dir).is_none() {
            return Err(ApiError::new(
                code::NOT_AVAILABLE_YET,
                "Lock while running needs Raven's background program running, in a version that \
                 can lock. Nothing was changed.",
                "raven-node does not serve Lock v2 (no node, an older one, or its gate shut); \
                 `raven lock` stops it instead",
            ));
        }
        match bridge::lock_now(&dir) {
            Ok(true) => self.lock_state(),
            Ok(false) => Err(crate::engine::not_in_the_app("lock.now", LOCK_CLI)),
            Err(e) => Err(ApiError::new(
                code::NODE_NOT_RUNNING,
                "Raven's background program didn't lock. Try again.",
                e,
            )),
        }
    }

    /// `lock.unlock {passphrase?}`: Lock v2's unlock (the passphrase only
    /// goes to raven-node, in a field that is never logged).
    pub(crate) fn lock_unlock(&self, args: &Args) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        if !gate("lock_v2").live {
            return Err(crate::engine::not_in_the_app("lock.unlock", "raven unlock"));
        }
        let pass = args.opt_str("passphrase")?.map(|p| p.as_bytes().to_vec());
        match bridge::unlock(&dir, pass.as_deref()) {
            bridge::Unlocked::Opened(lines) => {
                let mut v = self.lock_state()?;
                v["note"] = plain_lines(lines).join(" ").into();
                Ok(v)
            }
            bridge::Unlocked::Wrong(m) => Err(ApiError::of(code::PASSPHRASE_WRONG, m)),
            bridge::Unlocked::Wait(m) => Err(ApiError::of(code::UNLOCK_WAIT, m)),
            bridge::Unlocked::NeedsPassphrase(m) => Err(ApiError::of(code::PASSPHRASE_NEEDED, m)),
            bridge::Unlocked::Failed(m) => Err(ApiError::new(
                code::NODE_NOT_RUNNING,
                "Raven's background program didn't unlock. Try again.",
                m,
            )),
        }
    }
}

// ── updates.status ─────────────────────────────────────────────────────────

impl Inner {
    /// `updates.status`: `raven update status`, read-only. Installing stays
    /// the CLI's (`raven update install`).
    pub(crate) fn updates_status(&self) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        let view = bridge::updates_view(&dir);
        let advisory = security_gate::live(SecGate::Advisory);
        let from_friends = gate("updates_from_friends");
        let mut v = json!({
            "available": advisory,
            "bundles": view.live,
            "from_friends": from_friends.live,
            "lab": gate("updates_from_friends").lab() || (advisory && !SecGate::Advisory.production()),
            "lines": plain_lines(view.lines),
            "install": "cli_only",
            "install_text": "Install updates with `raven update install` in a terminal. The app \
                             shows what is ready; it doesn't install yet.",
        });
        if let Some(row) = view.net_row {
            v["summary"] = row.into();
        }
        if let Some(offer) = view.offer {
            v["offer"] = plain_lines(offer).into();
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E1 (three-machine test): Routes said "meet first" for a friend Raven
    /// had never connected with, where the terminal app says a first message
    /// needs you both online. `first_message` tells the two apart; an ended
    /// connection is meet first alone.
    #[test]
    fn away_tells_a_first_message_from_an_ended_connection() {
        assert_eq!(
            away_json(QueueReach::CanWait { until_ms: 42 }),
            json!({"until_ms": 42})
        );
        assert_eq!(
            away_json(QueueReach::NeverPaired),
            json!({"meet_first": true, "first_message": true})
        );
        assert_eq!(
            away_json(QueueReach::Ended { at_ms: 7 }),
            json!({"meet_first": true})
        );
    }

    #[test]
    fn every_way_has_a_name_and_a_gate() {
        for id in CARRIERS.iter().chain(PROTECTIONS.iter()) {
            assert!(!name_of(id).is_empty(), "{id}");
            let g = gate(id);
            assert!(g.constant.ends_with("_PRODUCTION_ENABLED"), "{id}");
            // Every way but LAN direct has a debug switch: a held one's
            // opens it, a switched-on one's (2026-10) closes it with "0".
            assert_eq!(g.switches.is_empty(), *id == "lan", "{id}");
        }
        assert!(gate("lan").production, "LAN direct is the released way");
    }

    /// The released ways (2026-10): LAN direct and the field-tested set,
    /// Bluetooth nearby on macOS only; every other way and every protection
    /// stays held (the owner's gate rule).
    #[test]
    fn only_the_field_tested_ways_are_released() {
        let released = [
            "lan",
            "internet",
            "port_mapping",
            "p2p",
            "friend_relay",
            "custody",
            "route_hints",
            "tor",
        ];
        for id in CARRIERS.iter().chain(PROTECTIONS.iter()) {
            let want = released.contains(id) || (*id == "nearby" && cfg!(target_os = "macos"));
            assert_eq!(gate(id).production, want, "{id}");
        }
    }

    #[test]
    fn the_app_says_no_command() {
        assert_eq!(
            app_step(
                "all set. Send a test message: ash send --contact NAME   (type the message, then \
                 Ctrl-Z, then Enter)"
            ),
            "All set: Raven can send and receive messages on this computer."
        );
        assert_eq!(without_commands("MISSING (run: ash init)"), "MISSING");
        assert_eq!(
            without_commands("running, but LAN is off (`raven lan on` turns it back on)"),
            "running, but LAN is off"
        );
        assert_eq!(
            without_commands("NOT running (it starts when you send; to receive run: ash listen)"),
            "NOT running"
        );
        let step = app_step(
            "friends cannot reach you: raven-node listens on this computer only (127.0.0.1:1). \
             Run `ash listen` to listen on your networks.",
        );
        assert!(!has_command(&step), "{step}");
        assert!(step.starts_with("Friends cannot reach you"), "{step}");
        assert!(!app_step("`raven node p2p on`").is_empty());
        // Words that only look like a command stay.
        assert!(!has_command("Raven's background program isn't running."));
        assert!(!has_command("a dash-separated word"));
    }

    #[test]
    fn doctor_lines_split_into_keys_and_values() {
        assert_eq!(
            split_line("reach_class: off (p2p host not running)"),
            ("reach_class".into(), "off (p2p host not running)".into())
        );
        assert_eq!(
            split_line("router_pcp=yes"),
            ("router_pcp".into(), "yes".into())
        );
        assert_eq!(
            split_line("route_hints=on learned_contacts=2 hide_ip=off"),
            (
                "route_hints".into(),
                "on learned_contacts=2 hide_ip=off".into()
            )
        );
        assert_eq!(
            split_line("offline_delivery: verified_contacts=1 direct=1"),
            (
                "offline_delivery".into(),
                "verified_contacts=1 direct=1".into()
            )
        );
        let rows = check_rows(&[
            "offline_delivery: verified_contacts=1".to_owned(),
            "  when you meet (1 contact): up to a day".to_owned(),
            "receiving: yes".to_owned(),
        ]);
        assert_eq!(rows[1]["key"], "offline_delivery");
        assert_eq!(rows[2]["plain"], "Raven receives messages on this network.");
    }

    #[test]
    fn held_ways_are_refused_with_the_cli_words() {
        let e = held("p2p");
        assert_eq!(e.code, code::NOT_AVAILABLE_YET);
        assert!(e.message.contains("Peer-to-peer"), "{e:?}");
        assert!(e.detail.contains("P2P_PRODUCTION_ENABLED"), "{e:?}");
        assert!(e.detail.contains("raven node p2p on"), "{e:?}");
    }

    #[test]
    fn the_help_flags_say_what_they_really_do() {
        assert!(flag_effect("store").contains("changes nothing yet"));
        assert!(flag_effect("relay").contains("changes nothing yet"));
        assert!(flag_effect("bridge").contains("don't use it"));
    }

    fn nearby_info(radio: &str, privacy: &str) -> raven_core::ipc::NearbyStatusInfo {
        raven_core::ipc::NearbyStatusInfo {
            enabled: true,
            gate_live: true,
            radio: radio.into(),
            address_privacy: privacy.into(),
            ..Default::default()
        }
    }

    /// Row N7w: raven-node keeps a radio with the fixed public address off
    /// the air (Windows reports `public`), so the engine must not say nearby
    /// runs there just because the radio is on.
    #[test]
    fn nearby_runs_only_where_the_node_goes_on_the_air() {
        let public = nearby_info("powered_on", "public");
        assert!(!nearby_running(Some(&public), false), "public address");
        assert!(nearby_running(Some(&public), true), "lab allows public");
        for privacy in ["random", "unknown"] {
            let info = nearby_info("powered_on", privacy);
            assert!(nearby_running(Some(&info), false), "{privacy}");
        }
        for radio in ["off", "unauthorized", "unsupported", "helper_unavailable"] {
            let info = nearby_info(radio, "random");
            assert!(!nearby_running(Some(&info), true), "{radio}");
        }
        let disabled = raven_core::ipc::NearbyStatusInfo {
            enabled: false,
            ..nearby_info("powered_on", "random")
        };
        assert!(!nearby_running(Some(&disabled), false), "switched off");
        assert!(!nearby_running(None, true), "no report");
    }

    /// raven-node's Tor line, every state it says (onion::status_line),
    /// read into the Tor way's state: states only, never an address.
    #[test]
    fn the_tor_line_reads_into_its_state() {
        let t = TorView::parse("Tor: starting (45 %)");
        assert_eq!(
            (t.phase, t.percent, t.why.as_deref()),
            ("starting", Some(45), None)
        );
        assert_eq!(t.words, "starting (45 %)");
        assert!(!t.running());
        let t = TorView::parse("Tor: starting (80 %, Tor says: loading descriptors)");
        assert_eq!(t.percent, Some(80));
        assert_eq!(t.why.as_deref(), Some("Tor says: loading descriptors"));
        let t = TorView::parse("Tor: ready");
        assert_eq!(
            (t.phase, t.running(), t.outages.as_deref()),
            ("ready", true, None)
        );
        let t = TorView::parse(
            "Tor: ready (onion service outages since start: 2, the last lasted 3 min and ended 10 min ago)",
        );
        assert_eq!(t.phase, "ready");
        assert_eq!(
            t.outages.as_deref(),
            Some(
                "onion service outages since start: 2, the last lasted 3 min and ended 10 min ago"
            )
        );
        assert_eq!(t.why, None);
        let t = TorView::parse("Tor: ready (onion service publishing)");
        assert_eq!((t.phase, t.why.as_deref()), ("publishing", None));
        let t = TorView::parse(
            "Tor: ready (onion service publishing; onion service outages since start: 1)",
        );
        assert_eq!(t.phase, "publishing");
        assert_eq!(
            t.outages.as_deref(),
            Some("onion service outages since start: 1")
        );
        let t = TorView::parse(
            "Tor: ready, onion service unreachable for 5 min (self-check failed; onion service outages since start: 1)",
        );
        assert_eq!((t.phase, t.running()), ("unreachable", true));
        assert_eq!(t.why.as_deref(), Some("self-check failed"));
        assert_eq!(
            t.outages.as_deref(),
            Some("onion service outages since start: 1")
        );
        let t = TorView::parse("Tor: blocked on this network (bridges needed; retrying in 2 min)");
        assert_eq!(t.phase, "blocked");
        assert_eq!(t.why.as_deref(), Some("bridges needed"));
        assert_eq!(t.retry.as_deref(), Some("retrying in 2 min"));
        let t = TorView::parse("Tor: could not start on this computer (helper exited)");
        assert_eq!(
            (t.phase, t.why.as_deref()),
            ("could_not_start", Some("helper exited"))
        );
        assert_eq!(TorView::parse("Tor: restarting").phase, "restarting");
        assert_eq!(
            TorView::parse("Tor: not built in this raven").phase,
            "not_built"
        );
        assert_eq!(TorView::parse("Tor: off").phase, "off");
        assert_eq!(TorView::parse("Tor: something new").phase, "unknown");
        // Control characters from the line never reach the apps.
        assert!(!TorView::parse("Tor: ready\u{1b}[31m")
            .words
            .contains('\u{1b}'));
    }

    /// The Tor way and `NetworkStatus.tor` follow raven-node's line; with
    /// none (a closed gate, an older raven-node) nothing is said of Tor's
    /// state.
    #[test]
    fn the_tor_way_follows_raven_nodes_line() {
        let status = |tor: Option<&str>| IpcResponse::Status {
            v: raven_core::ipc::IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: Vec::new(),
            p2p: None,
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            learning: None,
            locked: None,
            updates: None,
            tor: tor.map(str::to_owned),
        };
        let facts = |tor: Option<&str>| NetFacts {
            status: Ok(status(tor)),
            policy: Some(NodePolicy::default()),
            lan: bridge::LanView {
                setting: "on",
                meeting_until_ms: None,
                verified_only: false,
                row: String::new(),
                beacon_row: None,
            },
            nearby: bridge::NearbyView {
                state: "held",
                saved: None,
                info: None,
                rows: Vec::new(),
            },
            carry: bridge::CarryView::default(),
        };
        let g = gate("tor");
        assert_eq!(g.constant, "ONION_PRODUCTION_ENABLED");
        assert!(g.production, "Tor is on in release builds since 2026-10");
        let dir = std::env::temp_dir().join("raven-client-tor-view-test-missing");
        let blocked = facts(Some(
            "Tor: blocked on this network (bridges needed; retrying in 2 min)",
        ));
        let w = way("tor", &blocked);
        assert_eq!(w["name"], "Tor");
        assert_eq!(w["can_set"], false);
        assert!(w.get("setting").is_none());
        assert_eq!(w["running"], false);
        assert_eq!(
            w["detail"],
            "blocked on this network (bridges needed; retrying in 2 min)"
        );
        let want_reason = if !g.live {
            PREVIEW_REASON
        } else {
            "Blocked on this network: Tor can't connect from here."
        };
        assert_eq!(w["reason"], want_reason);
        let view = network_view(&dir, &blocked);
        assert_eq!(
            view["carriers"].as_array().map(Vec::len),
            Some(CARRIERS.len())
        );
        assert_eq!(view["carriers"][13]["id"], "tor");
        assert_eq!(
            view["tor"],
            json!({"phase": "blocked", "words": "blocked on this network (bridges needed; retrying in 2 min)",
                   "why": "bridges needed", "retry": "retrying in 2 min"})
        );
        let ready = facts(Some("Tor: ready"));
        assert_eq!(way("tor", &ready)["running"], true);
        assert_eq!(network_view(&dir, &ready)["tor"]["phase"], "ready");
        // No line: no state, no running, no `tor`.
        let none = facts(None);
        let w = way("tor", &none);
        assert!(
            w.get("running").is_none() && w.get("detail").is_none(),
            "{w}"
        );
        assert!(network_view(&dir, &none).get("tor").is_none());
    }

    /// The whole view: a node that answers with a powered radio on a public
    /// address reads `running: false` for nearby.
    #[test]
    fn a_public_address_node_does_not_run_nearby_in_the_view() {
        let status = IpcResponse::Status {
            v: raven_core::ipc::IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: Vec::new(),
            p2p: None,
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            learning: None,
            locked: None,
            updates: None,
            tor: None,
        };
        let facts = |privacy: &str| NetFacts {
            status: Ok(status.clone()),
            policy: Some(NodePolicy {
                nearby: Some(true),
                ..Default::default()
            }),
            lan: bridge::LanView {
                setting: "on",
                meeting_until_ms: None,
                verified_only: false,
                row: String::new(),
                beacon_row: None,
            },
            nearby: bridge::NearbyView {
                state: "live",
                saved: Some(true),
                info: Some(nearby_info("powered_on", privacy)),
                rows: Vec::new(),
            },
            carry: bridge::CarryView::default(),
        };
        let allow = raven_core::pair_init::lab_switch(NEARBY_ALLOW_PUBLIC_ADDR);
        assert_eq!(way("nearby", &facts("public"))["running"], allow);
        assert_eq!(way("nearby", &facts("random"))["running"], true);
    }

    /// E1 (three machines): a raven-node started with settings of its own
    /// (a kit's LAN port, Internet direct and p2p on) while node_policy.json
    /// saves none of them. The view shows the port it really listens on and
    /// says the ways run, not "Turned off".
    #[test]
    fn the_view_reads_the_running_node_not_only_the_saved_settings() {
        let status = IpcResponse::Status {
            v: raven_core::ipc::IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["lan_direct".into(), "internet_direct".into()],
            p2p: Some(Box::new(P2pStatusInfo {
                up: true,
                ..Default::default()
            })),
            pid: None,
            lan_listen: Some("0.0.0.0:17420".into()),
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby: None,
            learning: None,
            locked: None,
            updates: None,
            tor: None,
        };
        let facts = |lan: &'static str| NetFacts {
            status: Ok(status.clone()),
            policy: Some(NodePolicy::default()),
            lan: bridge::LanView {
                setting: lan,
                meeting_until_ms: None,
                verified_only: false,
                row: String::new(),
                beacon_row: None,
            },
            nearby: bridge::NearbyView {
                state: "held",
                saved: None,
                info: None,
                rows: Vec::new(),
            },
            carry: bridge::CarryView::default(),
        };
        let dir = std::env::temp_dir().join("raven-client-e1-no-such-profile");
        let view = network_view(&dir, &facts("on"));
        assert_eq!(view["port"], 17420, "the port it listens on, not 7420");
        assert_eq!(view["listening"][0], "0.0.0.0:17420");
        for id in ["internet", "p2p"] {
            let v = way(id, &facts("on"));
            assert_eq!(v["setting"], false, "{v}");
            assert_eq!(v["running"], true, "{v}");
            if gate(id).live {
                assert_ne!(v["state"], "off", "{v}");
                assert_eq!(v["reason"], RUNNING_NOT_SAVED_REASON, "{v}");
            } else {
                assert_eq!(v["state"], "preview", "{v}");
            }
        }
        // LAN direct is released: saved off, yet the node listens.
        let lan = way("lan", &facts("off"));
        assert_eq!(lan["state"], "on", "{lan}");
        assert_eq!(lan["setting"], false, "{lan}");
        assert_eq!(lan["reason"], RUNNING_NOT_SAVED_REASON, "{lan}");
        // Saved off and not running: still "off".
        let mut quiet = facts("off");
        quiet.status = Err("not running".into());
        assert_eq!(way("lan", &quiet)["state"], "off");
        assert_eq!(
            network_view(&dir, &quiet)["port"],
            7420,
            "the profile's port"
        );
    }

    /// (f) A release build holds every way but LAN direct whatever lab
    /// switch is set: `preview` in `network.status`, NOT_AVAILABLE_YET from
    /// `network.set`, no switch listed. CI's release step and the local
    /// release run set every switch (desktop/README.md); a debug run checks
    /// the same rules against its own environment (its gates follow the
    /// switches it has).
    #[test]
    fn every_lab_switch_is_inert_in_a_release_build() {
        let release = !cfg!(debug_assertions);
        for id in CARRIERS.iter().chain(PROTECTIONS.iter()) {
            let g = gate(id);
            if release {
                assert_eq!(g.live, g.production, "{id} opened in a release build");
            }
        }
        if release {
            assert!(lab_ways().is_empty());
            assert!(lab_switches_seen().is_empty());
        }
        for (setting, value) in [
            ("internet", json!(true)),
            ("p2p", json!(true)),
            ("port_mapping", json!(true)),
            ("proxy", json!("auto")),
            ("nearby", json!(true)),
            ("carry_for_friends", json!(true)),
            ("friends_carry_mine", json!(true)),
            ("handoff", json!(true)),
            ("relay_for_friends", json!(true)),
        ] {
            let mut m = serde_json::Map::new();
            m.insert(setting.into(), value);
            m.insert("agreed".into(), true.into());
            let live = gate(gate_for_setting(setting).unwrap()).live;
            match checked_settings(&Args(&m)) {
                Ok(_) => assert!(live, "{setting} passed while held"),
                Err(e) => {
                    assert!(!live, "{setting}: {e:?}");
                    assert_eq!(e.code, code::NOT_AVAILABLE_YET, "{setting}");
                }
            }
            if release {
                assert!(!live, "{setting} is open in a release build");
            }
            // Turning it off is always allowed.
            let mut off = serde_json::Map::new();
            off.insert(
                setting.into(),
                if setting == "proxy" {
                    json!("off")
                } else {
                    json!(false)
                },
            );
            assert!(checked_settings(&Args(&off)).is_ok(), "{setting} off");
        }
        // Every way switched on in the settings, no node: a held way reads
        // preview, a lab one lab, a released one on.
        let policy = NodePolicy {
            internet_listen: "127.0.0.1:9".into(),
            p2p_listen: "7000".into(),
            upnp: Some(true),
            relay_offer: Some(true),
            custody_use: Some(true),
            custody_handoff: true,
            nearby: Some(true),
            ..Default::default()
        };
        let facts = NetFacts {
            status: Err("not running".into()),
            policy: Some(policy),
            lan: bridge::LanView {
                setting: "on",
                meeting_until_ms: None,
                verified_only: false,
                row: String::new(),
                beacon_row: None,
            },
            nearby: bridge::NearbyView {
                state: "held",
                saved: Some(true),
                info: None,
                rows: Vec::new(),
            },
            carry: bridge::CarryView::default(),
        };
        for id in CARRIERS.iter().chain(PROTECTIONS.iter()) {
            let v = way(id, &facts);
            let g = gate(id);
            let want = if *id == "nearby" && !NEARBY_ON_THIS_OS {
                "not_on_this_os"
            } else if !g.live {
                "preview"
            } else if g.lab() {
                "lab"
            } else {
                "on"
            };
            assert_eq!(v["state"], want, "{v}");
            assert_eq!(v["lab"], g.lab(), "{v}");
            if release && *id != "lan" {
                assert!(
                    matches!(v["state"].as_str(), Some("preview" | "not_on_this_os")),
                    "{v}"
                );
            }
        }
    }
}
