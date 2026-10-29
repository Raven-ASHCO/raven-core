//! `raven node p2p|upnp|proxy` and `raven relay …` (transports design
//! 2026-10 P3; the proxy and `raven relay card --wss`: Phase 4, RWS1), and
//! the p2p rows of `raven status`.
//!
//! Everything here edits local files only (node_policy.json,
//! relay_allow.json) or reads what the running raven-node reports over IPC
//! (and learned_routes.json, for the relays contacts offer). raven-node
//! applies the p2p settings when it (re)starts; the relay allow-list, the
//! friend relay's consent (`raven relay offer`) and automatic relay choice
//! (`raven relay auto`) are applied live. Nothing here opens a port, maps
//! one on the router or dials anybody.

use std::collections::HashMap;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use raven_core::clock::now_ms;
use raven_core::ipc::{
    AutoReachStatus, ContactPath, ContactWhy, FriendRelayInfo, IpcRequest, IpcResponse,
    NatMappingStatus, P2pGateStatus, P2pPathCounts, P2pStatusInfo, PathCounts, PortMapStatus,
    RelayCounts, RelayHealth, RotationStatus,
};
use raven_core::learned_routes;
use raven_core::net_proxy::{self, ProxySetting};
use raven_core::node_policy::{
    peers_readable, save_policy, try_load_policy, NodePolicy, MAX_RELAY_EXTERNAL, POLICY_FILE,
};
use raven_core::p2p_route::{self, P2pListen, DEFAULT_P2P_PORT, FRIEND_RELAY_PORT, MAX_VIA};
use raven_core::peer_rotation;
use raven_core::reach::{reach_class, NatVerdict, ReachClass, ReachFacts};
use raven_core::reach_diag::{
    self, Diag, Fix, MailPath, Why, HOLD_MAIL_CMD, KIT_REF, LAN_ON_CMD, MAILBOX_CMD, OFFER_CMD,
};
use raven_core::relay_allow::{self, RelayAllowList, FRIEND_RELAY_DIR, RELAY_ALLOW_FILE};
use raven_core::sanitize::sanitize_terminal_line;

use super::{
    c, ipc_client, kv, load_contacts, no_contact_message, read_line_opt, resolve_contact_arg,
    service_restart_hint, stdin_is_tty, try_load_identity, Contact, C_DIM, C_GREEN, C_PURPLE,
    C_RESET,
};

/// The p2p settings of `raven node p2p on`.
#[derive(Debug, Clone, Default)]
pub(super) struct P2pOnArgs {
    pub listen: String,
    pub relay: Vec<String>,
    /// `--upnp` / `--no-upnp` (they skip the question).
    pub upnp: Option<bool>,
}

/// Inbound firewall rule for the libp2p port (TCP and UDP), as text to run
/// yourself: RAVEN never changes firewall settings.
pub(super) fn p2p_firewall_hint(port: u16) -> String {
    if cfg!(windows) {
        format!(
            "New-NetFirewallRule -DisplayName \"Raven node p2p\" -Direction Inbound -Program \
             <path to raven-node.exe> -Protocol TCP -LocalPort {port} -Profile Private, and the \
             same with -Protocol UDP (elevated PowerShell; never the Public profile)"
        )
    } else if cfg!(target_os = "macos") {
        "if the macOS firewall is on: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add \
         <path to raven-node> && sudo /usr/libexec/ApplicationFirewall/socketfilterfw \
         --unblockapp <path to raven-node>"
            .to_string()
    } else {
        format!(
            "e.g. sudo ufw allow {port}/tcp && sudo ufw allow {port}/udp (or your firewalld / \
             nftables / cloud rule)"
        )
    }
}

/// The one UPnP question (owner decision Q8, "ask once at setup"). It maps
/// the p2p endpoint's port only: relaying for contacts has a consent and a
/// port of its own (`raven relay offer`).
pub(super) fn upnp_question(port: u16) -> String {
    upnp_question_for(port, raven_core::port_map_live_enabled())
}

/// [`upnp_question`] with the PORT_MAP gate given: Phase 1's text while it
/// is closed (the installers and guides quote it); with it open the same
/// consent also covers NAT-PMP and PCP (owner decision O4-11).
pub(super) fn upnp_question_for(port: u16, port_map_live: bool) -> String {
    if port_map_live {
        format!(
            "Let raven ask your router to open TCP/UDP {port} automatically (UPnP, NAT-PMP or \
             PCP) so friends can reach this node? [y/N] "
        )
    } else {
        format!(
            "Open TCP/UDP {port} on your router automatically (UPnP) so friends can reach this \
             node? [y/N] "
        )
    }
}

/// The IPv6 pinhole question (owner decision O4-11: its own consent, never
/// implied by the UPnP answer). Asked only where the V6_PINHOLE gate is
/// open, after a yes to [`upnp_question`] ([`v6_pinhole_decision`]).
pub(super) fn v6_pinhole_question(port: u16) -> String {
    format!("Also open {port} in your router's IPv6 firewall for this computer (PCP)? [y/N] ")
}

/// What `raven node p2p on` saves for the IPv6 pinhole, and whether it
/// asked: the ask-once rules of [`upnp_decision`], asked only while the
/// V6_PINHOLE gate is open (`live`) and router port mapping is on
/// (`upnp`). An answer saved before is kept; off a terminal nothing is
/// asked and it stays unset (behaves as off).
pub(super) fn v6_pinhole_decision(
    saved: Option<bool>,
    upnp: Option<bool>,
    port: Option<u16>,
    tty: bool,
    live: bool,
    ask: impl FnOnce(u16) -> Option<String>,
) -> (Option<bool>, bool) {
    match port {
        Some(port) if live && upnp == Some(true) && saved.is_none() && tty => {
            (Some(said_yes(ask(port))), true)
        }
        _ => (saved, false),
    }
}

/// What `raven node p2p on` saves for UPnP, and whether it asked. A flag
/// (`--upnp` / `--no-upnp`) decides without asking; an answer saved before is
/// kept and never asked again; a run that is not on a terminal (scripts, CI,
/// installers) asks nothing and leaves it unset (behaves as off); otherwise
/// the question is asked exactly once: `y`/`yes` is on, Enter, EOF or anything
/// else is off. No port to open (the retired `--listen relay`, kept only under
/// the debug test switch): nothing is asked either.
pub(super) fn upnp_decision(
    saved: Option<bool>,
    flag: Option<bool>,
    port: Option<u16>,
    tty: bool,
    ask: impl FnOnce(u16) -> Option<String>,
) -> (Option<bool>, bool) {
    if flag.is_some() {
        return (flag, false);
    }
    if saved.is_some() {
        return (saved, false);
    }
    let Some(port) = port else {
        return (None, false);
    };
    if !tty {
        return (None, false);
    }
    (Some(said_yes(ask(port))), true)
}

/// `y` / `yes` (any case) is yes; Enter, EOF or anything else is no.
fn said_yes(answer: Option<String>) -> bool {
    answer.is_some_and(|a| {
        let a = a.trim();
        a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes")
    })
}

/// Ask `question` on the terminal; the answer line, or `None` at EOF.
fn ask_line(question: &str) -> Option<String> {
    print!("{question}");
    let _ = io::stdout().flush();
    read_line_opt()
}

fn ask_on_terminal(port: u16) -> Option<String> {
    ask_line(&upnp_question(port))
}

fn ask_v6_on_terminal(port: u16) -> Option<String> {
    ask_line(&v6_pinhole_question(port))
}

/// The direct libp2p address in `contact`'s card (a `via=` naming the
/// contact's own PeerId): what `--relay @friend` used before friend relays
/// had a key of their own (now only under the debug
/// `RAVEN_LAB_P2P_PROFILE_RELAY=1`), and how REACHABILITY tells a contact
/// that can be reached from the internet.
fn contact_direct_address(contact: &Contact) -> Result<String, String> {
    let label = contact.primary_label();
    let peer = p2p_route::normalize_peer_id(&contact.p2p).map_err(|_| {
        format!(
            "{label} has no p2p PeerId saved yet (Raven learns it from them once you are \
             connected): ask them for `raven relay card`"
        )
    })?;
    contact
        .p2p_via
        .iter()
        .filter_map(|v| p2p_route::parse_via(v).ok())
        .find(|v| v.peer_id == peer)
        .map(|v| v.text)
        .ok_or_else(|| {
            format!(
                "{label}'s card has no direct address of their own (a via= that ends in their own \
                 PeerId): ask them to run `raven relay card --host <their public address>` and \
                 give you that line"
            )
        })
}

/// The relay `contact` offers this node (their friend relay, learned from
/// their route hints: [`learned_routes::offers`], an unexpired snapshot
/// only), as `via=` texts in card order: the first address and, when `max`
/// leaves room, its fallback on another TCP port (443). Without an offer,
/// under the debug `RAVEN_LAB_P2P_PROFILE_RELAY=1` only, the contact's own
/// direct address (the retired relay under their profile PeerId).
fn contact_relay(data_dir: &Path, contact: &Contact, max: usize) -> Result<Vec<String>, String> {
    let now = now_ms();
    let key = contact.pub_hex.trim();
    let offered =
        learned_routes::offers(data_dir, now)
            .into_iter()
            .find(|(operator, _, _, expires_at)| {
                operator.eq_ignore_ascii_case(key) && *expires_at > now
            });
    if let Some((_, _, offer, _)) = offered {
        let lines: Vec<String> = offer
            .addrs
            .iter()
            .filter_map(|a| p2p_route::parse_via(&format!("{a}/p2p/{}", offer.relay_peer_id)).ok())
            .map(|v| v.text)
            .collect();
        let ordered = order_card_lines(lines);
        let pick: Vec<String> = if max >= 2 {
            relay_use_pair(&ordered)
        } else {
            ordered.into_iter().take(1).collect()
        };
        if !pick.is_empty() {
            return Ok(pick);
        }
    }
    if raven_core::p2p_profile_relay_test_enabled() {
        return contact_direct_address(contact).map(|a| vec![a]);
    }
    Err(format!(
        "{} has not offered you a relay: ask them to run `{OFFER_CMD}` (their computer must be \
         reachable from the internet)",
        contact.primary_label()
    ))
}

/// `--relay` values: multiaddrs (a pasted `raven relay card` line keeps its
/// `via=`), or `@contact` / a contact name (the relay they offer you,
/// [`contact_relay`]: two addresses of it when it is the only relay given).
fn resolve_relays(data_dir: &Path, relays: &[String]) -> Result<Vec<String>, String> {
    if relays.len() > MAX_VIA {
        return Err(format!("at most {MAX_VIA} relays (got {})", relays.len()));
    }
    let per_contact = MAX_VIA / relays.len().max(1);
    let mut out = Vec::new();
    for r in relays {
        let addr = r.trim();
        let addr = addr.strip_prefix("via=").unwrap_or(addr);
        let texts = if addr.starts_with('/') {
            vec![
                p2p_route::parse_via(addr)
                    .map_err(|e| format!("--relay: {e}"))?
                    .text,
            ]
        } else {
            let contacts = load_contacts(data_dir)?;
            let hits = resolve_contact_arg(&contacts, r);
            match hits.as_slice() {
                [] => return Err(no_contact_message(&contacts, r)),
                [one] => contact_relay(data_dir, one, per_contact)?,
                many => {
                    return Err(format!(
                        "contact {} is ambiguous ({} matches): use the @tag",
                        sanitize_terminal_line(r),
                        many.len()
                    ))
                }
            }
        };
        for text in texts {
            if !out.contains(&text) {
                out.push(text);
            }
        }
    }
    Ok(out)
}

/// The policy, or a refusal that names the problem: saving over an
/// unreadable file would silently turn the user's other flags off.
fn policy_for_edit(data_dir: &Path) -> Result<NodePolicy, String> {
    try_load_policy(data_dir).map_err(|e| {
        format!(
            "node_policy.json is unreadable ({}); fix or move it aside first (nothing changed)",
            sanitize_terminal_line(&e.to_string())
        )
    })
}

fn listen_port(listen: &P2pListen) -> Option<u16> {
    match listen {
        P2pListen::All(p) => Some(*p),
        P2pListen::One(a) => Some(a.port()),
        // Only under the debug test switch (`P2pListen::effective`).
        P2pListen::RelayOnly => None,
    }
}

/// The p2p port this node listens on, as the running raven-node reports
/// it: the port of its listen setting (whatever its source: a test
/// profile's `--p2p-listen 17423`), else the TCP port of its first listen
/// address that is no circuit (a setting of port 0); the release default
/// only when neither names one. The advice that says which port to forward
/// names this one (field test E2 r7: it said 7423 on a profile listening on
/// 17423).
pub(super) fn p2p_port(info: &P2pStatusInfo) -> u16 {
    let tcp_port = |addr: &str| {
        let parts: Vec<&str> = addr.split('/').skip(1).collect();
        if parts.contains(&"p2p-circuit") {
            return None;
        }
        match (parts.get(2), parts.get(3)) {
            (Some(&"tcp"), Some(port)) => port.parse::<u16>().ok(),
            _ => None,
        }
    };
    p2p_route::normalize_p2p_listen(&info.listen_setting)
        .ok()
        .flatten()
        .and_then(|l| listen_port(&l))
        .filter(|p| *p != 0)
        .or_else(|| {
            info.listen_addrs
                .iter()
                .filter_map(|a| tcp_port(a))
                .find(|p| *p != 0)
        })
        .unwrap_or(DEFAULT_P2P_PORT)
}

/// What `raven node p2p on --listen relay` prints: the setting is retired
/// and 7423 was saved instead.
pub(super) fn relay_listen_retired_note() -> String {
    format!(
        "{C_PURPLE}note{C_RESET}: --listen relay is retired: it opened no port, so hole punching \
         could never work. Saved {DEFAULT_P2P_PORT} (TCP and UDP, every interface) instead."
    )
}

/// `raven node p2p on …` (`Some`) / `off` (`None`).
pub(super) fn cmd_node_p2p(data_dir: &Path, on: Option<P2pOnArgs>) -> Result<(), String> {
    cmd_node_p2p_asking(
        data_dir,
        on,
        stdin_is_tty(),
        ask_on_terminal,
        raven_core::v6_pinhole_live_enabled().then_some(ask_v6_on_terminal),
    )
}

/// [`cmd_node_p2p`] with the UPnP question's answer given (`ask`); the IPv6
/// pinhole question is not asked.
pub(super) fn cmd_node_p2p_with(
    data_dir: &Path,
    on: Option<P2pOnArgs>,
    tty: bool,
    ask: impl FnOnce(u16) -> Option<String>,
) -> Result<(), String> {
    cmd_node_p2p_asking(data_dir, on, tty, ask, None::<fn(u16) -> Option<String>>)
}

/// [`cmd_node_p2p`] with both answers given: `ask_v6` is `Some` while the
/// V6_PINHOLE gate is open ([`v6_pinhole_decision`]).
pub(super) fn cmd_node_p2p_asking(
    data_dir: &Path,
    on: Option<P2pOnArgs>,
    tty: bool,
    ask: impl FnOnce(u16) -> Option<String>,
    ask_v6: Option<impl FnOnce(u16) -> Option<String>>,
) -> Result<(), String> {
    let mut policy = policy_for_edit(data_dir)?;
    let path = data_dir.join("node_policy.json");
    let Some(args) = on else {
        policy.p2p_listen.clear();
        save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
        println!(
            "{C_GREEN}ok{C_RESET} p2p=off saved in {} (relays and UPnP choice kept)",
            path.display()
        );
        println!(
            "{C_DIM}a running raven-node stops its libp2p host when it restarts: {}{C_RESET}",
            service_restart_hint()
        );
        return Ok(());
    };
    let listen = p2p_route::normalize_p2p_listen(&args.listen)
        .map_err(|e| format!("--listen: {e}"))?
        .ok_or("--listen needs a port or IP:PORT (or use `raven node p2p off`)")?;
    // The retired `relay` (no listener: it could never hole-punch) saves
    // 7423, said before the UPnP question that then follows for it.
    let (listen, retired) = listen.effective(raven_core::p2p_relay_only_test_enabled());
    if retired {
        println!("{}", relay_listen_retired_note());
    }
    let relays = if args.relay.is_empty() {
        policy.p2p_relays.clone()
    } else {
        resolve_relays(data_dir, &args.relay)?
    };
    let port = listen_port(&listen);
    let (upnp, asked) = upnp_decision(policy.upnp, args.upnp, port, tty, ask);
    let v6_live = ask_v6.is_some();
    let (v6_pinhole, v6_asked) = match ask_v6 {
        Some(ask_v6) => v6_pinhole_decision(policy.v6_pinhole, upnp, port, tty, true, ask_v6),
        None => (policy.v6_pinhole, false),
    };
    policy.p2p_listen = listen.policy_text();
    policy.p2p_relays = relays;
    policy.upnp = upnp;
    policy.v6_pinhole = v6_pinhole;
    save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
    println!(
        "{C_GREEN}ok{C_RESET} p2p listen={} relays={} upnp={}{} saved in {}",
        policy.p2p_listen,
        policy.p2p_relays.len(),
        upnp_policy_word(policy.upnp),
        if v6_live {
            format!(" ipv6_pinhole={}", upnp_policy_word(policy.v6_pinhole))
        } else {
            String::new()
        },
        path.display()
    );
    if asked {
        println!("{C_DIM}(asked once; change it any time with `raven node upnp on|off`){C_RESET}");
    }
    if v6_asked {
        println!(
            "{C_DIM}(asked once; change it any time with `raven node ipv6-pinhole on|off`){C_RESET}"
        );
    }
    println!(
        "{C_DIM}raven-node starts its libp2p host when it (re)starts: {}{C_RESET}",
        service_restart_hint()
    );
    if let Some(port) = port {
        println!(
            "{C_DIM}only your verified contacts get a Raven link, but anyone who scans the port can \
             see that a libp2p node listens there. Allow inbound TCP and UDP {port}: {}{C_RESET}",
            p2p_firewall_hint(port)
        );
    }
    if policy.p2p_relays.is_empty() {
        println!(
            "{C_DIM}no relay: friends behind other NATs reach you only directly. Add one with \
             --relay MULTIADDR (a friend's `raven relay card` line) or --relay NAME (a friend's \
             name or tag).{C_RESET}"
        );
    }
    if super::card_routes_live() {
        println!(
            "{C_DIM}your card now carries p2p=<your PeerId> and a via= per relay: `raven whoami \
             --card`{C_RESET}"
        );
    } else {
        println!(
            "{C_DIM}your verified friends learn your PeerId and relays inside your encrypted \
             links once you are connected; a card carries neither{C_RESET}"
        );
    }
    if !raven_core::p2p_live_enabled() {
        println!(
            "{C_PURPLE}note{C_RESET}: the p2p carrier is not enabled in this build \
             (P2P_HOLD): raven-node keeps it off until it is."
        );
    }
    Ok(())
}

fn upnp_policy_word(upnp: Option<bool>) -> &'static str {
    match upnp {
        None => "unset",
        Some(true) => "on",
        Some(false) => "off",
    }
}

/// `raven node upnp on|off`: change the saved UPnP choice.
pub(super) fn cmd_node_upnp(data_dir: &Path, on: bool) -> Result<(), String> {
    let mut policy = policy_for_edit(data_dir)?;
    policy.upnp = Some(on);
    save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
    println!(
        "{C_GREEN}ok{C_RESET} upnp={} saved in {}",
        upnp_policy_word(policy.upnp),
        data_dir.join("node_policy.json").display()
    );
    println!(
        "{C_DIM}raven-node applies it when it (re)starts: {}{C_RESET}",
        service_restart_hint()
    );
    if on {
        println!(
            "{C_DIM}when p2p is on, raven-node asks your router to forward its p2p port; it logs \
             only the mapped port and whether it worked. Your router may not support it.{C_RESET}"
        );
    }
    Ok(())
}

/// `raven node ipv6-pinhole on|off`: change the saved IPv6 pinhole choice
/// (owner decision O4-11: its own consent). Its lines, for the caller to
/// print.
pub(super) fn node_ipv6_pinhole_with(
    data_dir: &Path,
    on: bool,
    live: bool,
) -> Result<Vec<String>, String> {
    let mut policy = policy_for_edit(data_dir)?;
    policy.v6_pinhole = Some(on);
    save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
    let mut lines = vec![
        format!(
            "{C_GREEN}ok{C_RESET} ipv6_pinhole={} saved in {}",
            upnp_policy_word(policy.v6_pinhole),
            data_dir.join("node_policy.json").display()
        ),
        format!(
            "{C_DIM}raven-node applies it when it (re)starts: {}{C_RESET}",
            service_restart_hint()
        ),
    ];
    if on {
        lines.push(format!(
            "{C_DIM}when p2p and router port mapping are on, raven-node asks your router (PCP) to \
             let friends reach its p2p port over IPv6 on this computer only; it logs only whether \
             it worked. Your router may not support it.{C_RESET}"
        ));
        if policy.upnp != Some(true) {
            lines.push(format!(
                "{C_PURPLE}note{C_RESET}: it applies only with router port mapping on (`raven \
                 node upnp on`)."
            ));
        }
        if !live {
            lines.push(format!(
                "{C_PURPLE}note{C_RESET}: {}: raven-node does not ask the router until it is \
                 enabled.",
                raven_core::V6_PINHOLE_HOLD
            ));
        }
    }
    Ok(lines)
}

/// `raven node ipv6-pinhole on|off`.
pub(super) fn cmd_node_ipv6_pinhole(data_dir: &Path, on: bool) -> Result<(), String> {
    let lines = node_ipv6_pinhole_with(data_dir, on, raven_core::v6_pinhole_live_enabled())?;
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

// ── raven node stun: auto-reach STUN discovery ──────────────────────────────

/// The `auto_reach` row of `raven status` (and `raven node stun`): whether
/// STUN servers are asked, what they agreed on (never the address), the NAT
/// class and which ports a contact reached from outside.
pub(super) fn auto_reach_row(ar: &AutoReachStatus) -> String {
    let setting = match ar.state.as_str() {
        "off" => return "off (`raven node stun on` to ask STUN servers again)".into(),
        "hidden" => {
            return "off while you hide your IP from every contact (`raven node hide-ip off`)"
                .into()
        }
        _ => "on",
    };
    let found = match ar.public.as_str() {
        "found" => format!(
            "public address found{}; NAT {}",
            if ar.anchored {
                " (the p2p port's own)"
            } else {
                ""
            },
            nat_class_text(&ar.class)
        ),
        "waiting" => "not asked yet on this network".into(),
        _ if ar.answered == 0 && ar.asked > 0 => {
            "no STUN server answered (UDP blocked or offline); retrying".into()
        }
        _ => "the servers did not agree on one public address".into(),
    };
    let age = ar
        .age_s
        .map(|s| format!(", {} answered {} ago", ar.answered, age_words(s)))
        .unwrap_or_default();
    let reached = if ar.reached.is_empty() {
        "no contact has reached it from outside yet".to_string()
    } else {
        format!(
            "reached from outside: {}",
            ar.reached
                .iter()
                .map(|r| match r.as_str() {
                    "tcp" => "p2p TCP",
                    "quic" => "p2p QUIC",
                    "inet" => "Internet direct",
                    _ => "another port",
                })
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut row = format!("{setting}: {found}{age}");
    if ar.public == "found" {
        row.push_str(&format!("; {reached}"));
    }
    if let Some(p) = &ar.punch {
        row.push_str(&format!(
            "; serverless punches: {} target{}, {} tried, {} connected",
            p.targets,
            if p.targets == 1 { "" } else { "s" },
            p.tried,
            p.connected
        ));
    }
    sanitize_terminal_line(&row)
}

/// Seconds as `12 s`, `3 min` or `2 h`.
fn age_words(s: u64) -> String {
    match s {
        0..=89 => format!("{s} s"),
        90..=5399 => format!("{} min", s / 60),
        _ => format!("{} h", s / 3600),
    }
}

/// `raven node stun [on|off]`: change the saved STUN setting (`Some`), or
/// show it (`None`), with what the running raven-node found (`status`).
/// `live`: the STUN discovery gate. Its lines, for the caller to print.
pub(super) fn node_stun_with(
    data_dir: &Path,
    on: Option<bool>,
    live: bool,
    status: &Result<IpcResponse, String>,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let policy = match on {
        Some(on) => {
            let mut policy = policy_for_edit(data_dir)?;
            policy.stun = Some(on);
            save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
            lines.push(format!(
                "{C_GREEN}ok{C_RESET} stun={} saved in {}",
                if on { "on" } else { "off" },
                data_dir.join(POLICY_FILE).display()
            ));
            lines.push(format!(
                "{C_DIM}a running raven-node follows it within a few seconds{C_RESET}"
            ));
            policy
        }
        None => try_load_policy(data_dir).unwrap_or_else(|_| NodePolicy::fail_closed()),
    };
    let word = match (policy.stun, policy.hide_ip) {
        (_, true) => "off (you hide your IP from every contact)",
        (Some(false), _) => "off",
        (Some(true), _) => "on",
        (None, _) => "on (the default)",
    };
    if on.is_none() {
        lines.push(format!("stun: {word}"));
    }
    lines.push(format!(
        "{C_DIM}{}{C_RESET}",
        raven_core::stun::CONSENT_TEXT
    ));
    if !live {
        lines.push(format!(
            "{C_PURPLE}note{C_RESET}: {}: nothing is asked until it is enabled.",
            raven_core::STUN_DISCOVERY_HOLD
        ));
    } else if on.is_none() {
        match p2p_info(status).and_then(|i| i.auto_reach.as_ref()) {
            Some(ar) => lines.push(format!("now: {}", auto_reach_row(ar))),
            None => lines.push(format!(
                "{C_DIM}now: no p2p host runs (`raven node p2p on`, then start raven-node){C_RESET}"
            )),
        }
    }
    Ok(lines)
}

/// `raven node stun [on|off]`.
pub(super) fn cmd_node_stun(data_dir: &Path, on: Option<bool>) -> Result<(), String> {
    let status = daemon_status(data_dir);
    let lines = node_stun_with(
        data_dir,
        on,
        raven_core::stun_discovery_live_enabled(),
        &status,
    )?;
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

// ── raven node p2p rotate: PeerId rotation (Phase 4 P4.28) ──────────────────

/// What `raven node p2p rotate on` explains (owner decision O4-13: an
/// opt-in privacy setting with its trade-off said).
pub(super) const ROTATE_TRADE_OFF: &str = "your network ID (PeerId) then changes every epoch \
    (28 days), so someone who learned it (from an old card, or by scanning your port) cannot \
    recognise you after that. Your contacts follow it through route hints; it starts only once \
    every verified contact with a p2p route runs a raven that can follow. The trade-off: a relay \
    that is not your contact refuses your new ID unless it has your schedule (run `raven relay \
    schedule` and give its line to the relay's operator, again within about 6 months; until \
    then raven-node keeps the previous ID), and cards you gave out stop working after about two \
    epochs.";

/// `raven node p2p rotate on|off`: change the saved PeerId rotation setting.
/// Its lines, for the caller to print; `live`: the rotation gate.
pub(super) fn node_p2p_rotate_with(
    data_dir: &Path,
    on: bool,
    live: bool,
) -> Result<Vec<String>, String> {
    let mut policy = policy_for_edit(data_dir)?;
    policy.peer_rotation = Some(on);
    save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
    let mut lines = vec![
        format!(
            "{C_GREEN}ok{C_RESET} peer_rotation={} saved in {}",
            upnp_policy_word(policy.peer_rotation),
            data_dir.join("node_policy.json").display()
        ),
        format!("{C_DIM}a running raven-node follows it within a few seconds{C_RESET}"),
    ];
    if on {
        lines.push(format!("{C_DIM}{ROTATE_TRADE_OFF}{C_RESET}"));
        if !live {
            lines.push(format!(
                "{C_PURPLE}note{C_RESET}: {}: your network ID stays fixed until it is enabled.",
                raven_core::portmap_gate::PEER_ROTATION_HOLD
            ));
        }
    } else {
        lines.push(format!(
            "{C_DIM}raven-node goes back to your fixed network ID: the one your older cards \
             name{C_RESET}"
        ));
    }
    Ok(lines)
}

/// `raven node p2p rotate on|off`.
pub(super) fn cmd_node_p2p_rotate(data_dir: &Path, on: bool) -> Result<(), String> {
    let lines = node_p2p_rotate_with(
        data_dir,
        on,
        raven_core::portmap_gate::peer_rotation_live_enabled(),
    )?;
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

/// A wait in words: `N d`, `N h`, `N min` or `N s` (the largest unit).
fn wait_words(secs: u64) -> String {
    match secs {
        0..=119 => format!("{secs} s"),
        120..=7_199 => format!("{} min", secs / 60),
        7_200..=172_799 => format!("{} h", secs / 3600),
        _ => format!("{} d", secs / 86_400),
    }
}

/// The `p2p_rotation` row (Phase 4, the PEER_ROTATION gate open): which
/// network ID the running raven-node uses and why. Words and counts.
fn rotation_row(r: &RotationStatus) -> String {
    let next = r.next_change_s.map(wait_words).unwrap_or_default();
    match r.state.as_str() {
        "off" => "off (fixed network ID; `raven node p2p rotate on` changes it every epoch)".into(),
        "waiting" if r.waiting_on == u32::MAX => {
            "waiting: the contact book cannot be read (fixed network ID)".into()
        }
        "waiting" => format!(
            "waiting: {} contact{} cannot follow a rotating network ID yet (fixed network ID)",
            r.waiting_on,
            if r.waiting_on == 1 { "" } else { "s" }
        ),
        "starting" => format!(
            "starting: contacts are told your coming network IDs; the first change in {next}"
        ),
        "on" => format!("on: a new network ID every epoch; next change in {next}"),
        "postponed" => format!(
            "postponed: a relay refused the new network ID (`raven relay schedule` for its \
             operator); trying again in {next}"
        ),
        other => sanitize_terminal_line(other),
    }
}

/// The PeerId rotation line of `raven doctor` (key=value; words and
/// counts, never a PeerId): the saved setting and what the running
/// raven-node does. `None` while the gate is closed and nothing is saved,
/// so a release doctor is unchanged.
pub(super) fn doctor_peer_rotation_line(
    status: &Result<IpcResponse, String>,
    policy: &NodePolicy,
    live: bool,
) -> Option<String> {
    if !live && policy.peer_rotation.is_none() {
        return None;
    }
    let running = p2p_info(status).and_then(|i| i.rotation.as_ref());
    Some(format!(
        "peer_rotation={} setting={} waiting_on={} gate={}",
        running.map_or("-", |r| doctor_word_of(&r.state)),
        upnp_policy_word(policy.peer_rotation),
        running.map_or(0, |r| r.waiting_on),
        if live { "open" } else { "held" }
    ))
}

/// A fixed word from IPC, or `other`.
fn doctor_word_of(word: &str) -> &'static str {
    match word {
        "off" => "off",
        "waiting" => "waiting",
        "starting" => "starting",
        "on" => "on",
        "postponed" => "postponed",
        _ => "other",
    }
}

// ── raven node proxy: the HTTPS proxy of relay dials (Phase 4, RWS1 §8) ─────

/// `raven node proxy` refuses a setting with a user name or password (any
/// `@`): node_policy.json holds no secrets. The text is never repeated.
pub(super) const NODE_PROXY_NO_SECRETS: &str = "a user name or password is not saved: set them \
    in the service's RAVEN_P2P_PROXY; node_policy.json holds no secrets (nothing changed)";

/// A proxy setting as `raven node proxy` shows it: `auto` (explained),
/// `off` or `http://host:port`; a credential in it (a hand-edited
/// node_policy.json) shows as `<redacted>@`, and a text Raven cannot use
/// only as its kind. Never the text itself.
fn proxy_setting_text(text: &str) -> String {
    match net_proxy::parse_setting(text) {
        Ok(ProxySetting::Auto) => "auto (HTTPS_PROXY, then the system settings)".into(),
        Ok(setting) => setting.to_string(),
        Err(e) => format!("unusable ({})", e.kind()),
    }
}

/// `raven node proxy [auto|off|http://host:port]`: with a setting, save it
/// ([`node_proxy_set`]); without one, show it ([`node_proxy_show`]).
pub(super) fn cmd_node_proxy(data_dir: &Path, setting: Option<&str>) -> Result<(), String> {
    let daemon = daemon_status(data_dir);
    match setting {
        Some(text) => print_said(&node_proxy_set(data_dir, text, &daemon)?),
        None => {
            for line in node_proxy_show(data_dir, &daemon) {
                println!("{line}");
            }
        }
    }
    Ok(())
}

/// [`cmd_node_proxy`] with a setting: refuse a user name or password
/// ([`NODE_PROXY_NO_SECRETS`]) and anything [`net_proxy::parse_setting`]
/// refuses (its fixed texts never repeat the input), save the canonical
/// setting (`auto` as none), and say when raven-node applies it, whether
/// the running one takes its proxy from a flag or variable that comes
/// first, and whether this build dials through a proxy at all.
pub(super) fn node_proxy_set(
    data_dir: &Path,
    text: &str,
    daemon: &Result<IpcResponse, String>,
) -> Result<Vec<String>, String> {
    if net_proxy::has_credentials(text) {
        return Err(NODE_PROXY_NO_SECRETS.into());
    }
    let setting = net_proxy::parse_setting(text).map_err(|e| format!("{e} (nothing changed)"))?;
    let mut policy = policy_for_edit(data_dir)?;
    policy.p2p_proxy = match &setting {
        ProxySetting::Auto => String::new(),
        other => other.to_string(),
    };
    save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
    let mut lines = vec![
        format!(
            "ok proxy={setting} saved in {}",
            data_dir.join(POLICY_FILE).display()
        ),
        format!(
            "raven-node applies it when it (re)starts: {}",
            service_restart_hint()
        ),
    ];
    if let Some(source) = service_p2p(daemon)
        .map(|i| sanitize_terminal_line(&i.proxy_source))
        .filter(|s| !s.is_empty() && s != POLICY_FILE)
    {
        lines.push(format!(
            "note: the running raven-node takes its proxy setting from {source}, which comes \
             before node_policy.json"
        ));
    }
    if setting != ProxySetting::Off && !raven_core::wss_proxy_live_enabled() {
        lines.push(
            "note: dialling relays through an HTTPS proxy is not enabled in this build \
             (WSS_PROXY_PRODUCTION_ENABLED=false): raven-node keeps it off until it is."
                .into(),
        );
    }
    Ok(lines)
}

/// [`cmd_node_proxy`] without a setting: the one node_policy.json holds
/// (sealed with the relays in a sealed profile: unknown while that cannot
/// be read) and what the running raven-node uses ([`node_proxy_daemon`]).
/// ash cannot read the system proxy itself: raven-node's readers do.
pub(super) fn node_proxy_show(
    data_dir: &Path,
    daemon: &Result<IpcResponse, String>,
) -> Vec<String> {
    let saved = if !peers_readable(data_dir) {
        "unknown now (it is sealed with your relays: unlock this profile first)".to_string()
    } else {
        match try_load_policy(data_dir) {
            Ok(policy) => proxy_setting_text(&policy.p2p_proxy),
            Err(_) => "unknown (node_policy.json is unreadable)".into(),
        }
    };
    let mut lines = vec![
        format!("saved       {saved}"),
        format!("raven-node  {}", node_proxy_daemon(daemon)),
    ];
    if let Some(hint) = p2p_info(daemon).and_then(proxy_auth_hint) {
        lines.push(format!("note: {hint}"));
    }
    lines.push(
        "change it: raven node proxy auto|off|http://host:port (a user name and password go \
         only in the service's RAVEN_P2P_PROXY)"
            .into(),
    );
    lines
}

/// What the running raven-node says about its proxy: where its setting
/// came from (`--p2p-proxy`, `RAVEN_P2P_PROXY` or node_policy.json) and
/// its `proxy` word ([`proxy_word_text`]). Never a proxy host: the status
/// carries none.
fn node_proxy_daemon(daemon: &Result<IpcResponse, String>) -> String {
    let info = match daemon {
        Err(e) if ipc_client::error_means_not_running(e) => {
            return "not running (it applies the saved setting when it starts)".into()
        }
        Err(_) => return "does not answer; run `ash doctor`".into(),
        Ok(_) => service_p2p(daemon),
    };
    let Some(info) = info else {
        return "p2p is off, so it dials no relay".into();
    };
    if !info.config_error.is_empty() {
        return format!(
            "the p2p settings could not be used ({})",
            sanitize_terminal_line(&info.config_error)
        );
    }
    if info.listen_setting.is_empty() {
        return "p2p is off, so it dials no relay".into();
    }
    if info.proxy_source.is_empty() {
        return "an older raven-node: it does not say which proxy it uses".into();
    }
    let source = sanitize_terminal_line(&info.proxy_source);
    let now = if info.held {
        "the p2p carrier is not enabled in this build (P2P_HOLD)".to_string()
    } else if !info.up {
        "the libp2p host is not up, so it dials no relay now".to_string()
    } else {
        proxy_word_text(&info.proxy)
    };
    format!("uses the setting from {source}; {now}")
}

/// The running host's `proxy` word in words.
fn proxy_word_text(word: &str) -> String {
    match word {
        "" => "no proxy: relay dials over WebSocket/TLS go direct".into(),
        "setting" => "relay dials over WebSocket/TLS go through the proxy set".into(),
        "env" => "relay dials over WebSocket/TLS go through the proxy in its environment \
                  (HTTPS_PROXY or ALL_PROXY)"
            .into(),
        "system" => "relay dials over WebSocket/TLS go through this computer's system proxy".into(),
        "held" => "a proxy is named, but dialling relays through an HTTPS proxy is lab-only in \
                   this build (WSS_PROXY_PRODUCTION_ENABLED=false): relay dials go direct"
            .into(),
        other => match other.strip_prefix("unsupported: ") {
            Some(kind) => unsupported_proxy_hint(kind),
            None => sanitize_terminal_line(other),
        },
    }
}

// ── raven relay offer|auto: the friend relay ────────────────────────────────

/// The friend relay's port as saved (`relay_port`, else 7427).
fn offer_port(policy: &NodePolicy) -> u16 {
    policy.relay_port.unwrap_or(FRIEND_RELAY_PORT)
}

/// The friend relay's port as the relay offer texts name it: the one the
/// running raven-node reports when it is not `saved` (the port
/// node_policy.json held before this command), since its start setting
/// wins there (the test profiles' 17427 through the debug
/// `RAVEN_LAB_FRIEND_RELAY_LISTEN`; field test E2 r7 was told 7427); else
/// `now`, the port saved now (a `--port` given is used once raven-node
/// reloads).
fn friend_relay_port(daemon: &Result<IpcResponse, String>, saved: u16, now: u16) -> u16 {
    friend_relay_of(daemon)
        .map(|f| f.port)
        .filter(|p| *p != 0 && *p != saved)
        .unwrap_or(now)
}

/// The one relay-offer question (owner decision 7: asked once, on a
/// terminal, while two independent checks confirm this computer is public).
pub(super) fn relay_offer_question(port: u16) -> String {
    format!(
        "This computer can be reached from the internet. Let your verified contacts relay \
         through it, so they can reach each other when they are behind NAT? It uses its own \
         relay key (not your Raven identity) and port {port}; your contacts, and the contacts \
         of anyone who uses this relay, learn this computer's IP address. [y/N] "
    )
}

/// What to save for the friend relay's consent, and whether it asked. An
/// answer saved before is kept and never asked again; nothing is asked while
/// relaying is `held` (the running raven-node cannot relay, or hide my IP
/// rules it out), off a terminal, or unless the running node is confirmed
/// `public` (a `mapped` node gets the suggestion row only). Asked: `y` /
/// `yes` is yes; Enter, EOF or anything else is no.
pub(super) fn relay_offer_decision(
    saved: Option<bool>,
    reach: ReachClass,
    tty: bool,
    held: bool,
    ask: impl FnOnce() -> Option<String>,
) -> (Option<bool>, bool) {
    if saved.is_some() || held || !tty || reach != ReachClass::Public {
        return (saved, false);
    }
    (Some(said_yes(ask())), true)
}

/// `raven relay offer on` refuses while this node hides its IP from every
/// contact (`raven node hide-ip on`): their relay would show it to them.
pub(super) const RELAY_OFFER_HIDE_IP: &str = "you hide your IP from your contacts; a relay would \
    show it to them. Turn that off first, or run a dedicated relay elsewhere (`raven-node relay`).";

/// `raven relay offer off`.
const RELAY_OFFER_OFF: &str = "ok relay offer=off saved: raven-node stops the relay within a few \
    seconds; contacts that reserved on it switch to another relay if they have one.";

/// After the question was answered no.
fn relay_offer_no_text() -> String {
    format!("ok: not relaying (change it any time with `{OFFER_CMD}`)")
}

/// `raven relay auto on|off`.
fn relay_auto_text(on: bool) -> &'static str {
    if on {
        "ok relay auto=on: raven-node picks up to 2 of the relays your verified contacts offer, \
         keeps them while they work, and switches only after one has not answered for 10 minutes."
    } else {
        "ok relay auto=off: only the relays you set (`raven node p2p on --relay …`) are used."
    }
}

/// While the friend relay gate is closed in this build (as the P2P note of
/// `raven node p2p on`).
fn friend_relay_held_note(what: &str) -> String {
    format!(
        "note: {what} is not enabled in this build (FRIEND_RELAY_HOLD): \
         raven-node keeps it off until it is."
    )
}

/// What `raven relay offer on` (or a yes to the question) says: what was
/// saved, what the relay does and costs, the firewall rule, and the notes
/// for a node not confirmed public (`class`; `None`: no libp2p host runs)
/// and for a build that holds the friend relay. With no route to the
/// internet (`no_route`, W0) the note says only that: no address, UPnP or
/// port forward could help then.
pub(super) fn relay_offer_on_lines(
    path: &Path,
    port: u16,
    also_443: bool,
    class: Option<ReachClass>,
    declared: bool,
    held: bool,
    no_route: bool,
) -> Vec<String> {
    let mut lines = vec![
        format!("ok relay offer=on saved in {}", path.display()),
        format!(
            "your verified contacts may now reserve on this computer's own relay (its own key, \
             port {port} TCP and UDP{}) and reach each other through it.",
            if also_443 && port != 443 {
                " and TCP 443"
            } else {
                ""
            }
        ),
        "It carries only encrypted bytes, within fixed limits (at most 64 circuits, each 2 MiB \
         and 5 minutes). The relay sees the IP addresses of the contacts who use it and when they \
         talk, never their messages."
            .to_string(),
        format!(
            "Allow inbound TCP and UDP {port}: {}",
            p2p_firewall_hint(port)
        ),
        "raven-node starts the relay within a few seconds (no restart needed).".to_string(),
    ];
    if no_route {
        lines.push(format!("note: {NO_ROUTE_RELAY}."));
    } else if class != Some(ReachClass::Public) {
        lines.push(format!(
            "note: this computer is not confirmed reachable from the internet (reachability: \
             {}); the relay helps only if contacts can reach port {port}: a public IP, UPnP \
             (`raven node upnp on`) or a port forward of TCP and UDP {port}.",
            class.unwrap_or(ReachClass::Unknown).as_str()
        ));
    }
    if !no_route && !declared && !matches!(class, Some(ReachClass::Public | ReachClass::Mapped)) {
        // Nothing confirms an address: the relay is not offered until a
        // contact reaches it, which needs its address (RRH1 §11.4).
        lines.push(format!(
            "note: until something confirms an address of this computer, the relay is offered to \
             your contacts only at an address you name: {} (a /dns4/ name works too); a friend \
             you give `raven relay card` can use it either way.",
            external_hint(port)
        ));
    }
    if held {
        lines.push(friend_relay_held_note("relaying for your contacts"));
    }
    lines
}

/// Print what a relay command says: its first line plain (`ok` in green),
/// `note:` lines in purple, the rest dim.
fn print_said(lines: &[String]) {
    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            match line.strip_prefix("ok") {
                Some(rest) => println!("{C_GREEN}ok{C_RESET}{rest}"),
                None => println!("{line}"),
            }
        } else if let Some(rest) = line.strip_prefix("note:") {
            println!("{C_PURPLE}note{C_RESET}:{rest}");
        } else {
            println!("{C_DIM}{line}{C_RESET}");
        }
    }
}

/// The settings of `raven relay offer on`: each one given replaces the
/// saved one, the others are kept.
#[derive(Debug, Clone, Default)]
pub(super) struct RelayOfferOn {
    pub port: Option<u16>,
    /// `--also-443` (`Some(true)`) / `--no-443` (`Some(false)`).
    pub also_443: Option<bool>,
    /// `--external`: the addresses contacts reach the relay at (host and
    /// transport), at most [`MAX_RELAY_EXTERNAL`].
    pub external: Vec<String>,
}

/// `raven relay offer` (`Ask`: no argument), `… on`, `… off`.
#[derive(Debug, Clone)]
pub(super) enum RelayOfferArg {
    Ask,
    On(RelayOfferOn),
    Off,
}

/// A dedicated relay folder (and a profile's `friend_relay/`) relays
/// already: the friend relay's settings belong to a profile.
fn refuse_relay_folder(data_dir: &Path, what: &str) -> Result<(), String> {
    if relay_allow::is_relay_dir(data_dir) {
        return Err(format!(
            "this folder is a dedicated relay (raven-node relay): `raven relay {what}` is for a \
             profile; run it without --data-dir (nothing changed)"
        ));
    }
    Ok(())
}

/// The friend relay's port may not be one Raven itself listens on.
fn check_offer_port(port: u16, policy: &NodePolicy) -> Result<(), String> {
    let lan = raven_core::DEFAULT_LAN_LISTEN
        .parse::<std::net::SocketAddr>()
        .map(|a| a.port())
        .ok();
    let p2p = p2p_route::normalize_p2p_listen(&policy.p2p_listen)
        .ok()
        .flatten()
        .and_then(|l| listen_port(&l));
    let own = Some(port) == lan
        || Some(port) == p2p
        || (raven_core::paths::RESERVED_RAVEN_PORTS.contains(&port) && port != FRIEND_RELAY_PORT);
    if port == 0 || own {
        return Err(format!(
            "--port {port}: the relay needs a port of its own, not one Raven already uses (LAN, \
             Internet or p2p): e.g. {FRIEND_RELAY_PORT} (nothing changed)"
        ));
    }
    Ok(())
}

/// Apply `on` to `policy`, refusing a bad value before anything is saved.
fn apply_offer_settings(policy: &mut NodePolicy, on: &RelayOfferOn) -> Result<(), String> {
    if let Some(port) = on.port {
        check_offer_port(port, policy)?;
        policy.relay_port = Some(port);
    }
    if let Some(also) = on.also_443 {
        policy.relay_also_443 = also;
    }
    if !on.external.is_empty() {
        let mut external: Vec<String> = Vec::new();
        for text in &on.external {
            let addr =
                p2p_route::parse_host_transport(text).map_err(|e| format!("--external: {e}"))?;
            if !external.contains(&addr) {
                external.push(addr);
            }
        }
        if external.len() > MAX_RELAY_EXTERNAL {
            return Err(format!(
                "--external: at most {MAX_RELAY_EXTERNAL} addresses (got {}; nothing changed)",
                external.len()
            ));
        }
        policy.relay_external = external;
    }
    Ok(())
}

/// The friend relay the running raven-node reports (`None`: none answers,
/// an older raven-node, or its gate is closed and consent is not given).
fn friend_relay_of(status: &Result<IpcResponse, String>) -> Option<&FriendRelayInfo> {
    service_p2p(status).and_then(|i| i.friend_relay.as_ref())
}

/// Ask the relay-offer question when [`relay_offer_decision`] says so, and
/// save the answer. `held` is a running raven-node that cannot relay now
/// (it reports no friend relay, or one that is not `off`: consent given by
/// its start flag, or held), or hide my IP. `Some(lines)` when it asked.
/// After a yes, while friend custody is off (and live), the custody
/// follow-up question (Phase 3 item 3).
fn prompt_relay_offer(
    data_dir: &Path,
    policy: &mut NodePolicy,
    daemon: &Result<IpcResponse, String>,
    tty: bool,
    mut ask: impl FnMut(&str) -> Option<String>,
) -> Result<Option<Vec<String>>, String> {
    let class = p2p_info(daemon).map_or(ReachClass::Unknown, class_of);
    // Only a raven-node whose friend relay gate is open reports it `off`
    // (consent not given yet); a release build never does.
    let can_relay = friend_relay_of(daemon).is_some_and(|f| f.state == "off");
    // With no route to the internet (W0) nobody outside this network could
    // use it: not asked.
    let held = !can_relay || policy.hide_ip || no_route(daemon);
    let port = friend_relay_port(daemon, offer_port(policy), offer_port(policy));
    let (choice, asked) = relay_offer_decision(policy.relay_offer, class, tty, held, || {
        ask(&relay_offer_question(port))
    });
    if !asked {
        return Ok(None);
    }
    // The policy as it is now, not the copy read before the question (a
    // `raven lan off` made meanwhile stays; review D-6).
    *policy = super::custody_cli::update(data_dir, |p| p.relay_offer = choice)?;
    if choice != Some(true) {
        return Ok(Some(vec![relay_offer_no_text()]));
    }
    let mut lines = relay_offer_on_lines(
        &raven_core::policy_path(data_dir),
        port,
        policy.relay_also_443,
        Some(class),
        !policy.relay_external.is_empty(),
        false,
        no_route(daemon),
    );
    if let Some(more) = super::custody_cli::relay_custody_follow_up(data_dir, policy, &mut ask)? {
        lines.extend(more);
    }
    Ok(Some(lines))
}

/// `raven relay offer` without an argument, when nothing is asked: the
/// saved choice and how to change it. `port`: the friend relay's
/// ([`friend_relay_port`]).
fn relay_offer_state_lines(policy: &NodePolicy, port: u16) -> Vec<String> {
    let mut lines = match policy.relay_offer {
        None => vec![
            "relay offer=unset: this computer relays for nobody.".to_string(),
            format!(
                "`{OFFER_CMD}` lets your verified contacts relay through it (its own relay key, \
                 port {port}); `raven relay offer off` stops the question."
            ),
        ],
        Some(true) => vec![
            "relay offer=on: your verified contacts may relay through this computer.".to_string(),
            "`raven relay status` shows what it does; `raven relay offer off` stops it."
                .to_string(),
        ],
        Some(false) => vec![
            "relay offer=off: this computer relays for nobody.".to_string(),
            format!("`{OFFER_CMD}` to change it."),
        ],
    };
    if policy.hide_ip && policy.relay_offer != Some(false) {
        lines.push(
            "note: you hide your IP from your contacts, so this computer does not relay for \
             them (`raven node hide-ip off` first)."
                .to_string(),
        );
    }
    lines
}

/// [`cmd_relay_offer`] with the daemon's status, the terminal check and the
/// question passed in; returns what to print.
pub(super) fn relay_offer_with(
    data_dir: &Path,
    arg: RelayOfferArg,
    daemon: &Result<IpcResponse, String>,
    tty: bool,
    ask: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<String>, String> {
    refuse_relay_folder(data_dir, "offer")?;
    let mut policy = policy_for_edit(data_dir)?;
    let path = raven_core::policy_path(data_dir);
    match arg {
        RelayOfferArg::Off => {
            policy.relay_offer = Some(false);
            save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
            Ok(vec![RELAY_OFFER_OFF.to_string()])
        }
        RelayOfferArg::On(on) => {
            if policy.hide_ip {
                return Err(RELAY_OFFER_HIDE_IP.into());
            }
            let saved = offer_port(&policy);
            apply_offer_settings(&mut policy, &on)?;
            policy.relay_offer = Some(true);
            save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
            Ok(relay_offer_on_lines(
                &path,
                friend_relay_port(daemon, saved, offer_port(&policy)),
                policy.relay_also_443,
                p2p_info(daemon).map(class_of),
                !policy.relay_external.is_empty(),
                !raven_core::friend_relay_live_enabled(),
                no_route(daemon),
            ))
        }
        RelayOfferArg::Ask => Ok(
            match prompt_relay_offer(data_dir, &mut policy, daemon, tty, ask)? {
                Some(lines) => lines,
                None => relay_offer_state_lines(
                    &policy,
                    friend_relay_port(daemon, offer_port(&policy), offer_port(&policy)),
                ),
            },
        ),
    }
}

/// What the friend relay rows say with no route to the internet (W0), in
/// place of any address, UPnP or port forward advice: none could help.
const NO_ROUTE_RELAY: &str = "this computer has no route to the internet right now: only \
                              contacts on this network can use its relay";

/// The running raven-node read no default route (`Status.egress`).
pub(super) fn no_route(status: &Result<IpcResponse, String>) -> bool {
    matches!(
        status,
        Ok(IpcResponse::Status {
            egress: Some(false),
            ..
        })
    )
}

/// The running raven-node read no default route ([`no_route`]; one
/// `Status`, 2 s at most): `false` when none answers.
pub(super) fn daemon_has_no_route(data_dir: &Path) -> bool {
    no_route(&daemon_status(data_dir))
}

/// The running raven-node's `Status` (2 s at most).
fn daemon_status(data_dir: &Path) -> Result<IpcResponse, String> {
    ipc_client::ipc_request_timeout(data_dir, &IpcRequest::status(), Duration::from_secs(2))
}

/// Both stdin and stdout are a terminal: someone sees the question (the
/// harness captures the output, so it is never asked there).
fn terminal_both() -> bool {
    stdin_is_tty() && io::stdout().is_terminal() && !cfg!(test)
}

/// The relay-offer question on the terminal (a trust decision: lines of an
/// earlier paste never answer it).
fn ask_offer_on_terminal(question: &str) -> Option<String> {
    super::discard_pending_tty_input();
    ask_line(question)
}

/// `raven relay offer [on|off]`.
pub(super) fn cmd_relay_offer(data_dir: &Path, arg: RelayOfferArg) -> Result<(), String> {
    let daemon = daemon_status(data_dir);
    let lines = relay_offer_with(
        data_dir,
        arg,
        &daemon,
        terminal_both(),
        ask_offer_on_terminal,
    )?;
    print_said(&lines);
    Ok(())
}

/// The end of `raven status`: at most one ask-once question per run (Phase
/// 3, custody consent (d)), in this order: Phase 1's UPnP question, then the
/// relay offer ([`relay_offer_decision`]), then friend mailboxes
/// ([`super::custody_cli::mailbox_prompt`]). The UPnP question belongs to
/// `raven node p2p on` and is never asked here, so the relay offer comes
/// first. Quiet otherwise (and on any error: the status is printed already).
pub(super) fn offer_after_status(data_dir: &Path) {
    if !terminal_both() || relay_allow::is_relay_dir(data_dir) {
        return;
    }
    match after_status_with(
        data_dir,
        || daemon_status(data_dir),
        |q| {
            println!();
            ask_offer_on_terminal(q)
        },
    ) {
        Ok(lines) => print_said(&lines),
        Err(e) => eprintln!("{}", sanitize_terminal_line(&e)),
    }
}

/// [`offer_after_status`] on a terminal, with the daemon's status (read
/// only when the relay offer may be asked) and the question passed in;
/// returns what to print (nothing when nothing was asked).
pub(super) fn after_status_with(
    data_dir: &Path,
    daemon: impl FnOnce() -> Result<IpcResponse, String>,
    mut ask: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<String>, String> {
    let Ok(mut policy) = try_load_policy(data_dir) else {
        return Ok(Vec::new());
    };
    if policy.relay_offer.is_none() && !policy.hide_ip {
        let daemon = daemon();
        if let Some(lines) = prompt_relay_offer(data_dir, &mut policy, &daemon, true, &mut ask)? {
            return Ok(lines);
        }
    }
    Ok(
        super::custody_cli::mailbox_prompt(data_dir, &mut policy, true, &mut ask)?
            .unwrap_or_default(),
    )
}

/// [`cmd_relay_auto`]; returns what to print.
pub(super) fn relay_auto_with(data_dir: &Path, on: bool) -> Result<Vec<String>, String> {
    refuse_relay_folder(data_dir, "auto")?;
    let mut policy = policy_for_edit(data_dir)?;
    policy.relay_auto = Some(on);
    save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
    let mut lines = vec![relay_auto_text(on).to_string()];
    if on && !raven_core::friend_relay_live_enabled() {
        lines.push(friend_relay_held_note("automatic relay choice"));
    }
    Ok(lines)
}

/// `raven relay auto on|off`: automatic choice among the relays contacts
/// offer (on by default; the relays set by hand always come first).
pub(super) fn cmd_relay_auto(data_dir: &Path, on: bool) -> Result<(), String> {
    print_said(&relay_auto_with(data_dir, on)?);
    Ok(())
}

// ── raven status rows ────────────────────────────────────────────────────────

/// The running service's libp2p host, while it is up.
pub(super) fn p2p_info(status: &Result<IpcResponse, String>) -> Option<&P2pStatusInfo> {
    service_p2p(status).filter(|i| i.up)
}

/// What the running service reports about p2p, up or not: its effective
/// setting and where it came from (a flag or env var beats node_policy.json).
/// `None`: no service answers, or an older one that does not say.
pub(super) fn service_p2p(status: &Result<IpcResponse, String>) -> Option<&P2pStatusInfo> {
    match status {
        Ok(IpcResponse::Status { p2p, .. }) => p2p.as_deref(),
        _ => None,
    }
}

/// The `p2p` row: YES only while the running service reports its host up.
/// While a service answers, its own effective setting is shown (an installer
/// flag included); otherwise what node_policy.json (`configured`) asks.
pub(super) fn p2p_reach_row(
    status: &Result<IpcResponse, String>,
    configured: &str,
    p2p_live: bool,
) -> String {
    if let Some(info) = p2p_info(status) {
        let retrying = if info.listen_retrying > 0 {
            format!(
                "; {} listen address(es) not open yet (a busy port, or an address not on this \
                 computer): see raven-node-service.log",
                info.listen_retrying
            )
        } else {
            String::new()
        };
        return format!(
            "YES \u{2014} the libp2p host is up (reachability: {}; reservations {}/{}{retrying}{}{})",
            class_of(info).as_str(),
            info.reservations.len(),
            relay_slots(info),
            retired_note(info, true),
            wss_notes(info, raven_core::wss_live_enabled())
        );
    }
    if let Some(info) = service_p2p(status) {
        let setting = sanitize_terminal_line(&info.listen_setting);
        let source = sanitize_terminal_line(&info.source);
        return if !info.config_error.is_empty() {
            format!(
                "NO \u{2014} the p2p settings could not be used ({}); see \
                 raven-node-service.log in your Raven folder",
                sanitize_terminal_line(&info.config_error)
            )
        } else if setting.is_empty() {
            if source.is_empty() || source == "node_policy.json" {
                format!("off (opt-in: raven node p2p on --listen {DEFAULT_P2P_PORT})")
            } else {
                format!("off ({source} turns it off for the running raven-node)")
            }
        } else if info.held {
            format!(
                "NO \u{2014} configured ({setting}, from {source}{}) but the p2p carrier is not \
                 enabled in this build (P2P_HOLD)",
                retired_note(info, false)
            )
        } else {
            format!(
                "NO \u{2014} configured ({setting}, from {source}{}) but the libp2p host is not \
                 up yet (starting, or failing: see raven-node-service.log in your Raven folder)",
                retired_note(info, false)
            )
        };
    }
    let configured = sanitize_terminal_line(configured);
    match status {
        Ok(IpcResponse::Status { .. }) if configured.is_empty() => {
            format!("off (opt-in: raven node p2p on --listen {DEFAULT_P2P_PORT})")
        }
        Ok(IpcResponse::Status { .. }) if !p2p_live => format!(
            "NO \u{2014} configured ({configured}) but the p2p carrier is not enabled in this \
             build (P2P_HOLD)"
        ),
        Ok(IpcResponse::Status { .. }) => format!(
            "NO \u{2014} configured ({configured}) but the libp2p host is not up (busy port, or \
             raven-node started before it was configured: restart it); see \
             raven-node-service.log in your Raven folder"
        ),
        Err(e) if ipc_client::error_means_not_running(e) && configured.is_empty() => {
            "off (raven-node is not running)".into()
        }
        Err(e) if ipc_client::error_means_not_running(e) => {
            format!("off \u{2014} configured ({configured}), raven-node is not running")
        }
        _ => "unknown \u{2014} raven-node does not answer; run `ash doctor`".into(),
    }
}

/// Phase 4 (RWS1) notes of the `p2p` row while the host is up: how the
/// relays travel (`; relay over WSS[ through the HTTPS proxy]`), the
/// restricted network (`; restricted network (relay only)`), then the hint
/// of [`restrictive_hint`], if any. An older raven-node reports none of
/// it: nothing is added.
fn wss_notes(info: &P2pStatusInfo, wss_live: bool) -> String {
    let mut out = String::new();
    if info.relay_paths.iter().any(|p| p == "wss-proxy") {
        out.push_str("; relay over WSS through the HTTPS proxy");
    } else if info.relay_paths.iter().any(|p| p == "wss") {
        out.push_str("; relay over WSS");
    }
    if info.restricted {
        out.push_str("; restricted network (relay only)");
    }
    if let Some(hint) = restrictive_hint(info, wss_live) {
        out.push_str("; ");
        out.push_str(&hint);
    }
    out
}

/// The running host's proxy refused its dials with a 407 (`proxy_auth`):
/// what that means for the user. A refused password is named where it came
/// from: the environment's proxy (`proxy` word `env`: HTTPS_PROXY or
/// ALL_PROXY), `--p2p-proxy`, else RAVEN_P2P_PROXY.
fn proxy_auth_hint(info: &P2pStatusInfo) -> Option<String> {
    Some(match info.proxy_auth.as_str() {
        "unsupported" => {
            "the HTTPS proxy needs Windows sign-in (NTLM/Kerberos), not supported".into()
        }
        "other" => "the HTTPS proxy wants a sign-in Raven cannot do (only a user name and \
                    password, Basic, is supported)"
            .into(),
        "basic" => "the HTTPS proxy wants a user name and password: give them in the service's \
                    RAVEN_P2P_PROXY (http://user:pass@host:port)"
            .into(),
        "refused" => {
            let place = if info.proxy == "env" {
                "the service's HTTPS_PROXY or ALL_PROXY"
            } else if info.proxy_source == "--p2p-proxy" {
                "the service's --p2p-proxy"
            } else {
                "the service's RAVEN_P2P_PROXY"
            };
            format!("the HTTPS proxy refused the user name and password in {place}")
        }
        _ => return None,
    })
}

/// A proxy raven-node found but cannot use (`unsupported: <kind>`): PAC
/// (or WPAD) gets the design's own words.
fn unsupported_proxy_hint(kind: &str) -> String {
    if kind == "pac" {
        "your system uses a proxy script (PAC), which Raven cannot read: `raven node proxy \
         http://host:port`"
            .into()
    } else {
        format!(
            "the proxy raven-node found is one Raven cannot use ({}): `raven node proxy \
             http://host:port`, or `raven node proxy off`",
            sanitize_terminal_line(kind)
        )
    }
}

/// Said while the WSS gate holds and every relay slot's raw or QUIC
/// attempt fails.
pub(super) const WEB_ONLY_HINT: &str =
    "this network may allow only web traffic; WSS relays are lab-only in this build";

/// What keeps relays out of reach on a restrictive network, from the
/// running host's status (the `p2p` row; the doctor's next step takes its
/// two parts apart): [`proxy_hint`], else [`web_only_hint`]. `None`
/// otherwise, and from an older raven-node.
pub(super) fn restrictive_hint(info: &P2pStatusInfo, wss_live: bool) -> Option<String> {
    proxy_hint(info).or_else(|| web_only_hint(info, wss_live))
}

/// The proxy is in the way: a 407 ([`proxy_auth_hint`]: NTLM or
/// Negotiate, a missing or refused password), or a proxy Raven cannot use
/// (`unsupported: pac` and the like). Only while the host holds no relay
/// reservation (review B-2): a node that holds one is reachable, whatever
/// an earlier 407 or a proxy setting it cannot use says.
pub(super) fn proxy_hint(info: &P2pStatusInfo) -> Option<String> {
    if !info.reservations.is_empty() {
        return None;
    }
    proxy_auth_hint(info).or_else(|| {
        info.proxy
            .strip_prefix("unsupported: ")
            .map(unsupported_proxy_hint)
    })
}

/// [`WEB_ONLY_HINT`] while WSS is held in this build (`wss_live` false)
/// and every relay slot is retrying (its raw or QUIC attempts failed) with
/// none reserved.
pub(super) fn web_only_hint(info: &P2pStatusInfo, wss_live: bool) -> Option<String> {
    let all_failing = !info.relay_health.is_empty()
        && info.reservations.is_empty()
        && info.relay_health.iter().all(|h| h.state == "retrying");
    (!wss_live && all_failing).then(|| WEB_ONLY_HINT.to_string())
}

/// The relays the running host keeps (or tries to keep) a reservation on:
/// its slots, the ones set by hand and the ones picked from contacts'
/// offers (`relays_configured` counts only the former; an older raven-node
/// reports no slots).
pub(super) fn relay_slots(info: &P2pStatusInfo) -> usize {
    (info.relays_configured as usize).max(info.relay_health.len())
}

/// The running host's reachability class. An older raven-node reports no
/// class: it is worked out from what that one does report, with its
/// `public` (a single AutoNAT server said so) read as `unconfirmed`.
pub(super) fn class_of(info: &P2pStatusInfo) -> ReachClass {
    if !info.reach.is_empty() {
        return ReachClass::parse(&info.reach);
    }
    reach_class(ReachFacts {
        verdict: verdict_of(info),
        upnp_mapped: info.upnp.starts_with("mapped"),
        reservations: info.reservations.len(),
        listening: listening(info),
        reached_outside: false,
    })
}

/// The AutoNAT verdict the class rests on: an older raven-node (no class)
/// says `public` after one server, read as `unconfirmed`.
pub(super) fn verdict_of(info: &P2pStatusInfo) -> NatVerdict {
    match NatVerdict::parse(&info.nat) {
        NatVerdict::Public if info.reach.is_empty() => NatVerdict::Unconfirmed,
        other => other,
    }
}

/// The host has a listen address of its own (a circuit through a relay is
/// none).
pub(super) fn listening(info: &P2pStatusInfo) -> bool {
    info.listen_addrs
        .iter()
        .any(|a| !a.split('/').any(|p| p == "p2p-circuit"))
}

/// `; listen "relay" is retired: listening on 7423` (`up`; else `…: it uses
/// 7423`) when the service was given the retired setting (an older
/// raven-node never says).
fn retired_note(info: &P2pStatusInfo, up: bool) -> String {
    if info.retired_listen.is_empty() {
        return String::new();
    }
    let what = if up { "listening on" } else { "it uses" };
    format!(
        "; listen \"{}\" is retired: {what} {DEFAULT_P2P_PORT}",
        sanitize_terminal_line(&info.retired_listen)
    )
}

fn upnp_row(status: &Result<IpcResponse, String>, policy: Option<bool>) -> String {
    let live = p2p_info(status).map(|i| i.upnp.as_str());
    match (policy, live) {
        (None, _) => "unset (never asked: no router mapping; raven node upnp on|off)".into(),
        (Some(false), _) => "off".into(),
        (Some(true), Some(state)) if state.starts_with("mapped") => format!(
            "on \u{2014} the router forwards port {}",
            sanitize_terminal_line(state.trim_start_matches("mapped").trim())
        ),
        // No route to the internet (W0): no router to map, and nothing to
        // advise.
        (Some(true), Some("failed")) if no_route(status) => {
            "on \u{2014} no router mapping (this computer has no route to the internet right now)"
                .into()
        }
        (Some(true), Some("failed")) => {
            "on \u{2014} the router mapping failed (no UPnP router, or it refused; NAT-PMP / PCP \
             routers are not supported: forward the port by hand); friends then reach you through \
             a relay"
                .into()
        }
        (Some(true), Some(_)) => "on \u{2014} asking the router".into(),
        (Some(true), None) => "on (applied while the libp2p host runs)".into(),
    }
}

/// The router mapping rows of `raven status`: `router mapping` and `IPv6
/// pinhole` from a raven-node that reports `port_map` (the PORT_MAP gate
/// open), else Phase 1's `upnp` row ([`upnp_row`]; an older raven-node
/// too).
fn router_mapping_rows(
    status: &Result<IpcResponse, String>,
    policy: Option<bool>,
) -> Vec<(&'static str, String)> {
    match p2p_info(status).and_then(|i| i.port_map.as_ref()) {
        Some(map) => vec![
            ("router mapping", router_mapping_row(map, no_route(status))),
            ("IPv6 pinhole", v6_pinhole_row(map)),
        ],
        None => vec![("upnp", upnp_row(status, policy))],
    }
}

/// The name of the protocol a router answered in ([`PortMapStatus::v4`]).
fn mapping_protocol(word: &str) -> Option<&'static str> {
    match word {
        "pcp" => Some("PCP"),
        "nat-pmp" => Some("NAT-PMP"),
        "upnp" => Some("UPnP"),
        _ => None,
    }
}

/// The `router mapping` row in plain words.
fn router_mapping_row(map: &PortMapStatus, no_route: bool) -> String {
    if let Some(via) = mapping_protocol(&map.v4) {
        return format!("{via}, port {} open (TCP+UDP)", map.v4_port);
    }
    match map.v4.as_str() {
        "off" => "off (raven node upnp on)".into(),
        _ if no_route => {
            "no router mapping (this computer has no route to the internet right now)".into()
        }
        "asking" => "asking the router (PCP, NAT-PMP, UPnP)".into(),
        "none" => "none found (UPnP, NAT-PMP, PCP)".into(),
        "behind_another_nat" => "router is behind another NAT".into(),
        "double_nat" => "router is behind another router (double NAT)".into(),
        "off_path" => "not asked: internet traffic bypasses this router (a VPN?)".into(),
        "refused" => "the router refused (forward TCP and UDP by hand)".into(),
        other => sanitize_terminal_line(other),
    }
}

/// The `IPv6 pinhole` row in plain words.
fn v6_pinhole_row(map: &PortMapStatus) -> String {
    match map.v6.as_str() {
        "open" => "open (PCP)".into(),
        "not_asked" | "" => "not asked".into(),
        "none" => "none".into(),
        "asking" => "asking the router (PCP)".into(),
        "refused" => "the router refused".into(),
        other => sanitize_terminal_line(other),
    }
}

/// The retired relay role under this node's own PeerId (debug
/// `RAVEN_LAB_P2P_PROFILE_RELAY=1` only); the friend relay is [`relaying_row`].
fn relay_row(counts: &RelayCounts) -> String {
    let who = if counts.open {
        "anyone (open)".to_string()
    } else if counts.allow_list_unreadable {
        format!("nobody: {RELAY_ALLOW_FILE} is unreadable")
    } else {
        format!("{} allow-listed peer(s)", counts.allowed_peers)
    };
    format!(
        "YES \u{2014} relaying for {who}; reservations={} circuits={} refused={} (its PeerId is \
         YOUR PeerId: everyone who uses it learns it)",
        counts.reservations,
        counts.circuits,
        counts.reservations_refused + counts.circuits_refused + counts.connections_refused
    )
}

/// The `p2p_gate` row: who the running host admits, and how many others it
/// refused (counts only; they start over with each endpoint).
fn gate_row(gate: &P2pGateStatus) -> String {
    let who = if gate.unreadable {
        "NOBODY: contacts.json or blocked_pubs.json cannot be read; only your relays are admitted"
            .to_string()
    } else if gate.contacts == 0 {
        "no verified contact has a p2p PeerId yet (each is learned from the friend once you \
         are connected)"
            .to_string()
    } else {
        format!(
            "verified contacts {}, relays {}",
            gate.contacts, gate.relays
        )
    };
    let punched = if gate.refused_hole_punch > 0 {
        format!(
            " and {} hole-punch dial(s) to a private address",
            gate.refused_hole_punch
        )
    } else {
        String::new()
    };
    format!(
        "{who}; refused {} connection(s) from others{punched} (since the last start or network \
         change)",
        gate.refused
    )
}

/// `n verified contact` / `n verified contacts`.
fn verified_contacts(n: u32) -> String {
    format!("{n} verified contact{}", if n == 1 { "" } else { "s" })
}

/// `n circuit` / `n circuits`.
fn circuits_word(n: u32) -> String {
    format!("{n} circuit{}", if n == 1 { "" } else { "s" })
}

/// How to name the address contacts reach the friend relay at (its
/// `port`): what makes a relay nothing has confirmed yet worth offering.
fn external_hint(port: u16) -> String {
    format!("`{OFFER_CMD} --external /ip4/<public IP>/tcp/{port}`")
}

/// What the `relaying` row and `raven relay status` say of a friend relay
/// that is up but not offered (`offering` false) or has no address to
/// offer: name its address ([`external_hint`]).
fn not_offered_text(fr: &FriendRelayInfo) -> String {
    let port = fr.port;
    match fr.reachable.as_str() {
        "no_address" => format!(
            "this computer has no public address to offer: contacts outside this network cannot \
             use it. If they can reach it (a public IP, or a forward of TCP and UDP {port}), name \
             the address: {} (or give a friend `raven relay card`)",
            external_hint(port)
        ),
        _ => format!(
            "not offered to your contacts yet: nothing has confirmed the address it would name. \
             Name the address they reach it at: {} (or give a friend `raven relay card`); behind \
             a router, forward TCP and UDP {port} or turn on UPnP (`raven node upnp on`)",
            external_hint(port)
        ),
    }
}

/// The `relaying` row: the friend relay (its own key) as the running
/// raven-node reports it. `None` (no row) from an older raven-node, while
/// its gate is closed and consent is not given, and while consent is not
/// given and this node is not reachable from the internet (nothing to
/// suggest). A node reachable through its router's mapping (`mapped`) gets
/// the suggestion too; only `public` is asked (`raven status`). With no
/// route to the internet (`no_route`, W0) nothing is suggested or advised:
/// an unconfirmed relay is said to serve this network only.
pub(super) fn relaying_row(info: &P2pStatusInfo, no_route: bool) -> Option<String> {
    let fr = info.friend_relay.as_ref()?;
    let port = fr.port;
    let m = verified_contacts(fr.members);
    Some(match fr.state.as_str() {
        "up" if no_route && fr.reachable != "confirmed" => {
            format!("YES \u{2014} for {m}, but {NO_ROUTE_RELAY}")
        }
        "up" => match fr.reachable.as_str() {
            "confirmed" => format!(
                "YES \u{2014} for {m} ({} reserved, {}); own relay key, port {port}",
                fr.counts.reservations,
                circuits_word(fr.counts.circuits)
            ),
            "no_address" => format!("YES \u{2014} but {}", not_offered_text(fr)),
            _ if !fr.offering => format!("YES \u{2014} for {m}, but {}", not_offered_text(fr)),
            _ => format!(
                "YES \u{2014} for {m}, but no contact has reached it from the internet yet: \
                 forward TCP and UDP {port} on your router, or turn on UPnP (`raven node upnp on`)"
            ),
        },
        "hidden" => "no \u{2014} stopped while you hide your IP from every contact (`raven node \
                     hide-ip off` to relay again)"
            .to_string(),
        "starting" => format!("starting \u{2014} own relay key, port {port}"),
        "failed" => format!(
            "NOT running \u{2014} port {port} could not be opened (another program?); retrying"
        ),
        "held" => "held: relaying is off in this build".to_string(),
        "off" => match fr.consent.as_str() {
            "no" => format!("no (you said no; `{OFFER_CMD}` to change)"),
            "unset"
                if info.up
                    && !no_route
                    && matches!(class_of(info), ReachClass::Public | ReachClass::Mapped) =>
            {
                format!(
                    "not yet \u{2014} this computer can be reached from the internet: \
                     `{OFFER_CMD}` lets your contacts relay through it"
                )
            }
            _ => return None,
        },
        other => sanitize_terminal_line(other),
    })
}

/// The `p2p_paths` row: how Raven links travelled since raven-node started
/// (links this node started that delivered, links a peer started that it
/// served) and DCUtR's verdicts. Counts only.
fn p2p_paths_row(paths: &P2pPathCounts) -> String {
    let side = |c: &PathCounts| {
        format!(
            "direct {} · reversed {} · relayed {} · hole-punched {}",
            c.direct, c.reversed, c.relayed, c.hole_punched
        )
    };
    format!(
        "sent: {}; received: {}; hole punching {} ok, {} failed (since raven-node started)",
        side(&paths.sent),
        side(&paths.received),
        paths.upgrades,
        paths.upgrade_failures
    )
}

/// The `p2p_listen` row of a running host: its listen and circuit addresses.
fn p2p_listen_row(info: &P2pStatusInfo) -> String {
    let listen: Vec<String> = info
        .listen_addrs
        .iter()
        .map(|a| sanitize_terminal_line(a))
        .collect();
    if listen.is_empty() && info.listen_retrying > 0 {
        "(none open yet: its port is busy, or its address is not on this computer)".to_string()
    } else if listen.is_empty() {
        "(none: reachable through relays only)".to_string()
    } else {
        listen.join(", ")
    }
}

/// A NAT mapping class ([`NatMappingStatus`]) in plain words.
fn nat_class_text(word: &str) -> String {
    match word {
        "unknown" => "unknown".into(),
        "no_nat" => "no NAT".into(),
        "stable_kept" => "stable (port kept)".into(),
        "stable_shifted" => "stable (port changed)".into(),
        "varies" => "varies by destination".into(),
        other => sanitize_terminal_line(other),
    }
}

/// The `p2p_nat` row (Phase 4, the NAT_CLASS gate open): this network's NAT
/// mapping classes and what the hole-punch policy did. Words and counts.
fn nat_row(nat: &NatMappingStatus) -> String {
    format!(
        "tcp {}, quic {}, seen from {} network{}; hole punches skipped {}, failed {}",
        nat_class_text(&nat.tcp),
        nat_class_text(&nat.quic),
        nat.observers,
        if nat.observers == 1 { "" } else { "s" },
        nat.punch_skipped,
        nat.punch_failed
    )
}

/// The p2p rows of `raven status` (after the `internet` row).
pub(super) fn print_status_rows(status: &Result<IpcResponse, String>, policy: &NodePolicy) {
    kv(
        "p2p",
        &p2p_reach_row(status, &policy.p2p_listen, raven_core::p2p_live_enabled()),
    );
    if let Some(info) = p2p_info(status) {
        kv("p2p_peer", &sanitize_terminal_line(&info.peer_id));
        kv("p2p_listen", &p2p_listen_row(info));
        if let Some(paths) = &info.paths {
            kv("p2p_paths", &p2p_paths_row(paths));
        }
        if let Some(gate) = &info.gate {
            kv("p2p_gate", &gate_row(gate));
        }
        if let Some(nat) = &info.nat_mapping {
            kv("p2p_nat", &nat_row(nat));
        }
        if let Some(rotation) = &info.rotation {
            kv("p2p_rotation", &rotation_row(rotation));
        }
        if let Some(ar) = &info.auto_reach {
            kv("auto_reach", &auto_reach_row(ar));
        }
    }
    let service_on = service_p2p(status).is_some_and(|i| !i.listen_setting.is_empty());
    if !policy.p2p_listen.is_empty() || policy.upnp.is_some() || service_on {
        for (label, row) in router_mapping_rows(status, policy.upnp) {
            kv(label, &row);
        }
    }
    if let Some(counts) = p2p_info(status).and_then(|i| i.relay.as_ref()) {
        kv("p2p_relay", &relay_row(counts));
    }
    if let Some(row) = service_p2p(status).and_then(|i| relaying_row(i, no_route(status))) {
        kv("relaying", &row);
    }
}

/// The friend relay line of `raven doctor` (key=value; states and counts,
/// never a PeerId or an address): the saved consent (`relay_offer`), the
/// friend relay as the running raven-node reports it, automatic relay
/// choice, spare relays, and where each relay slot came from. `None` while
/// none of it applies (nothing saved, and an older raven-node or one that
/// cannot relay), so a release doctor is unchanged.
pub(super) fn doctor_relay_offer_line(
    status: &Result<IpcResponse, String>,
    policy: &NodePolicy,
) -> Option<String> {
    let info = service_p2p(status);
    let fr = info.and_then(|i| i.friend_relay.as_ref());
    let auto = info.is_some_and(|i| i.relay_auto);
    if policy.relay_offer.is_none() && fr.is_none() && !auto {
        return None;
    }
    let mut line = format!(
        "relay_offer={} friend_relay={} friend_relay_members={} friend_relay_reserved={} \
         relay_auto={} relay_standby={}",
        match policy.relay_offer {
            None => "unset",
            Some(false) => "no",
            Some(true) => "yes",
        },
        fr.map_or_else(|| "off".to_string(), |f| super::doctor_word(&f.state)),
        fr.map_or(0, |f| f.members),
        fr.map_or(0, |f| f.counts.reservations),
        if auto { "on" } else { "off" },
        info.map_or(0, |i| i.relay_standby)
    );
    let slots = p2p_info(status).map_or(&[][..], |i| i.relay_health.as_slice());
    for (i, h) in slots.iter().enumerate() {
        line.push_str(&format!(
            " relay_{}_source={}",
            i + 1,
            if h.source == "offer" {
                "offer"
            } else {
                "manual"
            }
        ));
    }
    Some(line)
}

// ── raven status: route hints and hide my IP ────────────────────────────────

/// `n contact` / `n contacts`.
fn contacts_word(n: u32) -> String {
    format!("{n} contact{}", if n == 1 { "" } else { "s" })
}

/// The `route hints` row: what the running raven-node reports (RRH1, counts
/// only). `None` while it does not say: route hints are off there, it is an
/// older raven-node, or none answers.
pub(super) fn route_hints_row(status: &Result<IpcResponse, String>) -> Option<String> {
    let Ok(IpcResponse::Status {
        route_hints: Some(hints),
        ..
    }) = status
    else {
        return None;
    };
    if !hints.live {
        return None;
    }
    Some(format!(
        "on{} \u{b7} told {} \u{b7} learned from {}",
        if raven_core::route_hints::ROUTE_HINTS_PRODUCTION_ENABLED {
            ""
        } else {
            " (lab)"
        },
        contacts_word(hints.told),
        hints.learned
    ))
}

/// The `hide my IP` row (D4), from node_policy.json (`hide_all`) and the
/// contact book: `on (every contact)`, `off (1 contact hidden)`, `off`.
/// `None` (no row) when nothing is hidden and route hints are off in this
/// build (`hints_live`), so a release status is unchanged.
pub(super) fn hide_ip_row(
    hide_all: bool,
    contacts: &[Contact],
    hints_live: bool,
) -> Option<String> {
    let mut hidden: Vec<String> = contacts
        .iter()
        .filter(|c| c.hide_ip)
        .map(|c| c.pub_hex.trim().to_ascii_lowercase())
        .collect();
    hidden.sort();
    hidden.dedup();
    let hidden = u32::try_from(hidden.len()).unwrap_or(u32::MAX);
    if hide_all {
        return Some("on (every contact)".into());
    }
    match hidden {
        0 if hints_live => Some("off".into()),
        0 => None,
        n => Some(format!("off ({} hidden)", contacts_word(n))),
    }
}

/// The route hints rows of `raven status` (after the p2p rows).
pub(super) fn print_route_hint_rows(
    status: &Result<IpcResponse, String>,
    policy: &NodePolicy,
    contacts: &[Contact],
) {
    if let Some(row) = route_hints_row(status) {
        kv("route hints", &row);
    }
    let live = raven_core::route_hints::route_hints_live();
    if let Some(row) = hide_ip_row(policy.hide_ip, contacts, live) {
        kv("hide my IP", &row);
    }
}

// ── raven status: REACHABILITY ───────────────────────────────────────────────

/// `12 s`, `3 min`, `2 h`, `1 d` (rounded down).
pub(super) fn age_text(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s} s"),
        s if s < 3_600 => format!("{} min", s / 60),
        s if s < 86_400 => format!("{} h", s / 3_600),
        s => format!("{} d", s / 86_400),
    }
}

/// The router port of a `mapped <port>` UPnP state.
fn mapped_port(info: &P2pStatusInfo) -> Option<String> {
    info.upnp
        .strip_prefix("mapped")
        .map(|p| sanitize_terminal_line(p.trim()))
}

/// The REACHABILITY `internet` row: the class in plain words, and what the
/// AutoNAT verdict adds to it.
pub(super) fn internet_row(info: &P2pStatusInfo) -> String {
    let verdict = verdict_of(info);
    let port = mapped_port(info).unwrap_or_default();
    let relays = info.reservations.len();
    let mut row = match class_of(info) {
        ReachClass::Public => {
            "reachable directly from the internet (2 independent checks agree)".to_string()
        }
        ReachClass::Mapped => format!(
            "reachable through your router's port mapping ({}, port {port}); waiting for 2 \
             independent checks to confirm it",
            info.port_map
                .as_ref()
                .and_then(|m| mapping_protocol(&m.v4))
                .unwrap_or("UPnP")
        ),
        ReachClass::Relayed => format!(
            "behind NAT: contacts reach you through {relays} relay{}",
            if relays == 1 { "" } else { "s" }
        ),
        ReachClass::Unreachable => {
            "NOT reachable from the internet: behind NAT and no working relay".to_string()
        }
        // One check counted, so "nobody has checked yet" would be wrong.
        ReachClass::Unknown if verdict == NatVerdict::Unconfirmed => {
            return "not confirmed yet: one independent check reached you directly, a second is \
                    needed; you have no working relay"
                .to_string();
        }
        ReachClass::Unknown => {
            "not known: nobody has checked yet, and you have no working relay".to_string()
        }
    };
    if verdict == NatVerdict::Unconfirmed {
        row.push_str("; one check says you may also be reachable directly");
    }
    if verdict == NatVerdict::Private && mapped_port(info).is_some() {
        row.push_str(&format!(
            "; your router mapped port {port}, but the check could not reach it (a firewall, or \
             carrier NAT in front of your router?)"
        ));
    }
    row
}

/// The REACHABILITY `checks` row: the independent AutoNAT checks (counts).
/// `None` from an older raven-node, which reports no counts.
pub(super) fn checks_row(info: &P2pStatusInfo) -> Option<String> {
    if info.reach.is_empty() {
        return None;
    }
    let c = &info.nat_checks;
    let mut row = if c.reached == 0 && c.failed == 0 {
        "none yet (only relays started with `raven-node relay --autonat-server` can check)"
            .to_string()
    } else {
        format!(
            "{} of the 2 needed independent checks reached you directly; {} could not",
            c.reached, c.failed
        )
    };
    if c.not_counted > 0 {
        row.push_str(&format!(
            "; {} did not count (your own network, or reached through a relay)",
            c.not_counted
        ));
    }
    Some(row)
}

/// The host and port of a relay's configured address (`/ip4|ip6|dns*/…/tcp|
/// udp/<port>/…`), up to its PeerId, which is never shown.
fn relay_host_port(text: &str) -> (Option<String>, Option<String>) {
    let parts: Vec<&str> = text.split('/').collect();
    let (mut host, mut port) = (None, None);
    let mut i = 0;
    while i + 1 < parts.len() {
        match parts[i] {
            "p2p" | "p2p-circuit" => break,
            "ip4" | "dns" | "dns4" | "dns6" if host.is_none() => {
                host = Some(sanitize_terminal_line(parts[i + 1]));
                i += 1;
            }
            "ip6" if host.is_none() => {
                host = Some(format!("[{}]", sanitize_terminal_line(parts[i + 1])));
                i += 1;
            }
            "tcp" | "udp" if port.is_none() => {
                port = Some(sanitize_terminal_line(parts[i + 1]));
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    (host, port)
}

/// `host:port` of a relay's configured address; never its PeerId.
pub(super) fn relay_label(text: &str) -> String {
    match relay_host_port(text) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host,
        (None, _) => "(no address)".to_string(),
    }
}

/// The name of the contact whose device key is `pub_hex` (an offered
/// relay's operator), as the contact book shows it; "a contact" when the
/// book no longer holds them. Never a key or a PeerId.
fn operator_name(contacts: &[Contact], pub_hex: &str) -> String {
    let key = pub_hex.trim();
    contacts
        .iter()
        .find(|c| !key.is_empty() && c.pub_hex.trim().eq_ignore_ascii_case(key))
        .map_or_else(|| "a contact".to_string(), |c| c.primary_label())
}

/// One `relay N` row: its state in words, how long, its last ping. A relay
/// a contact offered is `{name}'s relay (host:port)` (`owner`).
fn relay_health_row(h: &RelayHealth, owner: Option<&str>) -> String {
    let at = match owner {
        Some(name) => format!("{name}'s relay ({})", relay_label(&h.relay)),
        None => relay_label(&h.relay),
    };
    match h.state.as_str() {
        "reserved" => {
            let mut row = format!("OK \u{2014} {at}");
            if let Some(s) = h.for_s {
                row.push_str(&format!(", reserved for {}", age_text(s)));
            }
            if let (Some(ms), Some(age)) = (h.ping_ms, h.ping_age_s) {
                row.push_str(&format!(", ping {ms} ms {} ago", age_text(age)));
            }
            row
        }
        "asking" => format!("asking {at} for a reservation"),
        "resolving" => {
            let host = relay_host_port(&h.relay)
                .0
                .unwrap_or_else(|| "(no address)".to_string());
            match owner {
                Some(name) => format!("looking up {name}'s relay ({host})"),
                None => format!("looking up {host}"),
            }
        }
        "retrying" => {
            let next = h
                .retry_in_s
                .map(|s| format!("; next try in {s} s"))
                .unwrap_or_default();
            match h.for_s {
                Some(s) => format!(
                    "NOT reserved \u{2014} {at}, lost {} ago{next} ({} failed)",
                    age_text(s),
                    h.tries
                ),
                None => format!("NOT reserved yet \u{2014} {at}{next} ({} failed)", h.tries),
            }
        }
        "waiting" => format!("not tried yet \u{2014} {at}"),
        other => format!("{} \u{2014} {at}", sanitize_terminal_line(other)),
    }
}

/// The `relay 1` / `relay 2` … rows, one per slot (none from an older
/// raven-node): a relay set by hand by its host and port, one picked from a
/// contact's offer as that contact's relay (`contacts` names them).
pub(super) fn relay_rows(info: &P2pStatusInfo, contacts: &[Contact]) -> Vec<(String, String)> {
    info.relay_health
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let owner = (h.source == "offer").then(|| operator_name(contacts, &h.operator_pub_hex));
            (
                format!("relay {}", i + 1),
                relay_health_row(h, owner.as_deref()),
            )
        })
        .collect()
}

/// The `spare relays` row: offered relays automatic choice could take
/// beside the ones it holds. `None` while there are none.
pub(super) fn spare_relays_row(info: &P2pStatusInfo) -> Option<String> {
    (info.relay_standby > 0).then(|| {
        format!(
            "{} more offered by your contacts (used when one stops answering)",
            info.relay_standby
        )
    })
}

/// The user's circle as `raven status` and `raven doctor` name it: who
/// offers this node relaying and who can be reached directly from the
/// internet ([`reach_diag::circle_facts`]), by label, never by key, and the
/// friend to ask first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CircleNames {
    /// Contacts who offer this node relaying, in book order.
    pub offers: Vec<String>,
    /// Contacts who can be reached directly from the internet.
    pub reachable: Vec<String>,
    /// The friend to ask first (one who offers relaying, else one who can
    /// be reached), and how `raven node p2p on --relay` names them, as one
    /// shell word of the shell this runs in ([`relay_arg_for`]).
    pub friend: Option<(String, String)>,
}

/// Characters no shell treats specially inside a word: neither a POSIX shell,
/// nor PowerShell or cmd.exe (Windows adds `@` and `,`, below).
pub(super) fn plain_word(arg: &str, windows: bool) -> bool {
    !arg.is_empty()
        && arg.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '-' | '+' | ':' | '/')
                || (!windows && matches!(c, '@' | ','))
        })
}

/// A PowerShell single-quoted string: verbatim (`$`, a backtick, `%`, `"`,
/// `@` and `,` are literal), a quote inside it doubled. PowerShell also ends
/// such a string at the typographic single quotes, so they are doubled too.
pub(super) fn powershell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// The `--relay` argument naming a reachable friend, as one word the user
/// can paste: `label` (the @tag, else the petname) when no shell treats any
/// of it specially. Otherwise, on Unix, `label` in POSIX single quotes. On
/// Windows, the friend's own direct address (`direct`, a multiaddr ending in
/// its PeerId, which `--relay` takes as well): it is plain, so it pastes
/// unchanged into PowerShell (the default shell, where a bare `@tag` is a
/// splat and `$` expands inside double quotes) and into cmd.exe (where `%`
/// expands and single quotes are not quotes). Only an address that is not
/// plain itself falls back to the label in PowerShell quotes.
fn relay_arg_for(label: &str, direct: &str, windows: bool) -> String {
    if plain_word(label, windows) {
        label.to_string()
    } else if !windows {
        super::ext::shell_quote(label)
    } else if plain_word(direct, true) {
        direct.to_string()
    } else {
        powershell_quote(label)
    }
}

/// Labels for `facts` from the contact book (a key the book no longer holds
/// is left out).
pub(super) fn circle_names(facts: &reach_diag::CircleFacts, contacts: &[Contact]) -> CircleNames {
    let find = |key: &[u8; 32]| {
        let hex = hex::encode(key);
        contacts
            .iter()
            .find(|c| c.pub_hex.trim().eq_ignore_ascii_case(&hex))
    };
    let offers: Vec<&Contact> = facts.offers.iter().filter_map(find).collect();
    let reachable: Vec<&Contact> = facts.reachable.iter().filter_map(find).collect();
    let friend = offers.first().or(reachable.first()).map(|c| {
        (
            c.primary_label(),
            relay_arg_for(
                &c.tag_subtitle().unwrap_or_else(|| c.primary_label()),
                &contact_direct_address(c).unwrap_or_default(),
                cfg!(windows),
            ),
        )
    });
    CircleNames {
        offers: offers.iter().map(|c| c.primary_label()).collect(),
        reachable: reachable.iter().map(|c| c.primary_label()).collect(),
        friend,
    }
}

/// What the REACHABILITY advice and the NOT REACHABLE NOW section need
/// besides the host's own report: the circle, the default route reading
/// (`Status.egress`), the contacts raven-node could not reach
/// (`Status.unreachable`) and the contact book, for names.
#[derive(Debug, Clone, Default)]
pub(super) struct ReachCtx<'a> {
    /// raven-node's Tor is ready and its onion service reachable (lab,
    /// `Status.tor`, [`raven_core::onion::status_line_says_reachable`]).
    pub tor_reachable: bool,
    /// Contacts (lowercase key hex) raven-node delivered to in the last 10
    /// minutes (`Status.last_paths`): their computers answer.
    pub reached_lately: Vec<String>,
    pub circle: reach_diag::CircleFacts,
    pub names: CircleNames,
    pub egress: Option<bool>,
    pub unreachable: &'a [ContactWhy],
    pub contacts: &'a [Contact],
    /// Per contact whose reason says it is offline (lowercase key hex):
    /// whether a friend could hold its mail (Phase 3 custody,
    /// [`reach_diag::mail_path`]); a contact not listed has no mailbox fix.
    pub mail: Vec<(String, MailPath)>,
}

/// A delivery at most this old (seconds) shows a contact's computer
/// answers ([`ReachCtx::reached_lately`]).
const REACHED_LATELY_S: u64 = 600;

impl<'a> ReachCtx<'a> {
    /// From the profile's files and the running raven-node's `Status`. A
    /// circle that cannot be read is an empty one (`known: false`).
    pub(super) fn read(
        data_dir: &Path,
        status: &'a Result<IpcResponse, String>,
        contacts: &'a [Contact],
    ) -> Self {
        let circle = reach_diag::circle_facts(data_dir, now_ms()).unwrap_or_default();
        let (egress, unreachable, tor_reachable, reached_lately) = match status {
            Ok(IpcResponse::Status {
                egress,
                unreachable,
                tor,
                last_paths,
                ..
            }) => (
                *egress,
                unreachable.as_slice(),
                tor.as_deref()
                    .is_some_and(raven_core::onion::status_line_says_reachable),
                last_paths
                    .iter()
                    .filter(|p| p.age_s <= REACHED_LATELY_S)
                    .map(|p| p.peer_pub_hex.trim().to_ascii_lowercase())
                    .collect(),
            ),
            _ => (None, &[][..], false, Vec::new()),
        };
        let offline: Vec<&str> = unreachable
            .iter()
            .filter(|r| Diag::find(&r.reason).is_some_and(|d| super::ext::offline_reason(d.why)))
            .map(|r| r.peer_pub_hex.as_str())
            .collect();
        let mail = super::ext::contact_mail_paths(data_dir, &offline);
        Self {
            tor_reachable,
            reached_lately,
            names: circle_names(&circle, contacts),
            circle,
            egress,
            unreachable,
            contacts,
            mail,
        }
    }

    /// The circle as a fix for the contact `pub_hex` reads it: with its
    /// mailbox fact ([`ReachCtx::mail`]).
    fn circle_for(&self, pub_hex: &str) -> reach_diag::CircleFacts {
        let key = pub_hex.trim().to_ascii_lowercase();
        reach_diag::CircleFacts {
            mail: self
                .mail
                .iter()
                .find(|(k, _)| *k == key)
                .map_or(MailPath::NoFix, |(_, m)| *m),
            ..self.circle.clone()
        }
    }

    /// raven-node read no default route: nothing outside this network can
    /// be reached, and nothing on this computer changes that.
    pub(super) fn no_route(&self) -> bool {
        self.egress == Some(false)
    }

    /// The contact whose key is `pub_hex`.
    fn contact(&self, pub_hex: &str) -> Option<&'a Contact> {
        let key = pub_hex.trim();
        self.contacts
            .iter()
            .find(|c| !key.is_empty() && c.pub_hex.trim().eq_ignore_ascii_case(key))
    }

    /// The rows of contacts this book holds, each with its reason (`None`:
    /// a reason this ash does not know).
    fn known_rows(&self) -> Vec<(&'a ContactWhy, &'a Contact, Option<Diag>)> {
        self.unreachable
            .iter()
            .filter_map(|r| Some((r, self.contact(&r.peer_pub_hex)?, Diag::find(&r.reason))))
            .collect()
    }
}

/// The `circle` row of REACHABILITY: who offers relaying, who can be
/// reached from the internet (labels only, at most 3 each then `+N`).
/// `None` when the contact book cannot be read.
pub(super) fn circle_row(facts: &reach_diag::CircleFacts, names: &CircleNames) -> Option<String> {
    if !facts.known {
        return None;
    }
    let mut parts = Vec::new();
    if !names.offers.is_empty() {
        parts.push(format!(
            "relaying offered by {} ({} in use)",
            name_list(&names.offers),
            facts.offers_in_use
        ));
    }
    if !names.reachable.is_empty() {
        parts.push(format!(
            "reachable directly from the internet: {}",
            name_list(&names.reachable)
        ));
    }
    Some(if parts.is_empty() {
        "nobody in your circle can be reached from the internet yet (no relay offers, no \
         contact with a public address)"
            .into()
    } else {
        parts.join("; ")
    })
}

/// `A, B, C +2`.
fn name_list(names: &[String]) -> String {
    let shown = names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    match names.len().saturating_sub(3) {
        0 => shown,
        more => format!("{shown} +{more}"),
    }
}

/// The REACHABILITY decision (first match wins).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReachAdvice {
    /// W0: this computer has no route to the internet.
    NoRoute,
    Public,
    /// W5: public, relaying for nobody, and this many contacts cannot be
    /// reached from the internet (both behind NAT, or with no relay).
    PublicCouldRelay(usize),
    /// The router forwards this port.
    Mapped(String),
    /// Relays configured, none reserved yet, and each is still on its first
    /// try (raven-node just started).
    FirstTry,
    /// W1: relays configured and none reserved. `owner`: the contact whose
    /// offered relay every slot is; `switch`: what automatic choice does
    /// when one stays away (empty without a spare offer).
    RelayDown {
        owner: Option<String>,
        switch: String,
    },
    /// W1, while the relay's owner is a contact raven-node delivered to in
    /// the last 10 minutes (E2 r38: "asleep or switched off?" beside LAST
    /// DELIVERY "same network (LAN), 52 s ago"): its computer answers, so
    /// its relay may be turned off.
    RelayOffOwnerAwake {
        owner: String,
        switch: String,
    },
    /// W1c: every slot is a relay contacts offered (more than one contact),
    /// none reserved. `spare`: another offered relay could take a slot
    /// (`relay_standby`), so automatic choice can switch.
    OffersDown {
        spare: bool,
    },
    /// W1b: some reserved, not all.
    OneRelayDown,
    /// Every relay reserved.
    Relayed,
    /// Relayed through the one relay a contact offers (named), and no other
    /// is offered.
    RelayedOneOffer(String),
    /// Not known, and no relay configured: nothing has checked whether
    /// contacts outside this network reach this node (a port forward or a
    /// public IP may already let them), so it is not a problem to fix.
    /// `friend`: a contact to ask (label, `--relay` arg).
    NotChecked {
        friend: Option<(String, String)>,
    },
    /// W2: not reachable, and a contact offers relaying or can be reached
    /// from the internet.
    AskFriend {
        name: String,
    },
    /// W3: nobody in the circle can be reached from the internet.
    NobodyReachable,
    /// The advice inside, while this computer's onion service is reachable
    /// over Tor (lab, E2 r38): friends outside this network reach it that
    /// way, whatever the relay says.
    OverTor(Box<ReachAdvice>),
}

/// A relay on its first attempt, not reserved yet: no failure so far.
fn first_try(h: &RelayHealth) -> bool {
    h.tries == 0 && matches!(h.state.as_str(), "asking" | "resolving" | "waiting")
}

/// This node relays for its verified contacts now (its friend relay runs).
pub(super) fn relaying_for_contacts(info: &P2pStatusInfo) -> bool {
    info.friend_relay
        .as_ref()
        .is_some_and(|f| matches!(f.state.as_str(), "up" | "starting"))
}

/// Contacts raven-node found behind NAT with no relay, or with no relay
/// (each contact once).
fn cannot_be_reached(ctx: &ReachCtx) -> usize {
    ctx.unreachable
        .iter()
        .filter(|r| {
            Diag::find(&r.reason).is_some_and(|d| matches!(d.why, Why::BothNat | Why::NoRelay))
        })
        .map(|r| r.peer_pub_hex.trim().to_ascii_lowercase())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

/// The contact (device key, lowercase hex) who offered every relay slot;
/// `None` with a relay set by hand, or no slot.
fn offered_slot_owners(info: &P2pStatusInfo) -> Option<Vec<String>> {
    let all_offered = info.relays_configured == 0
        && !info.relay_health.is_empty()
        && info.relay_health.iter().all(|h| h.source == "offer");
    all_offered.then(|| {
        let mut owners: Vec<String> = info
            .relay_health
            .iter()
            .map(|h| h.operator_pub_hex.trim().to_ascii_lowercase())
            .collect();
        owners.sort_unstable();
        owners.dedup();
        owners
    })
}

/// W1's last clause: automatic choice moves to a spare offered relay when
/// one is there (`relay_standby`), named by its owner when the circle knows
/// another contact who offers.
fn switch_clause(info: &P2pStatusInfo, ctx: &ReachCtx, owner: Option<&str>) -> String {
    if info.relay_standby == 0 {
        return String::new();
    }
    match ctx.names.offers.iter().find(|n| Some(n.as_str()) != owner) {
        Some(other) => format!(", and moves to {other}'s relay if it stays away"),
        None => ", and moves to another offered relay if it stays away".into(),
    }
}

/// [`reach_advice_direct`], with Tor (E2 r38): while this computer's onion
/// service is reachable, advice that says friends outside this network
/// cannot reach it (no relay, a relay down, nothing checked) says they
/// reach it over Tor.
fn reach_advice(info: &P2pStatusInfo, ctx: &ReachCtx) -> ReachAdvice {
    let advice = reach_advice_direct(info, ctx);
    let over_tor = ctx.tor_reachable
        && matches!(
            advice,
            ReachAdvice::RelayDown { .. }
                | ReachAdvice::RelayOffOwnerAwake { .. }
                | ReachAdvice::OffersDown { .. }
                | ReachAdvice::RelayedOneOffer(_)
                | ReachAdvice::NotChecked { .. }
                | ReachAdvice::AskFriend { .. }
                | ReachAdvice::NobodyReachable
        );
    if over_tor {
        ReachAdvice::OverTor(Box::new(advice))
    } else {
        advice
    }
}

fn reach_advice_direct(info: &P2pStatusInfo, ctx: &ReachCtx) -> ReachAdvice {
    if ctx.no_route() {
        return ReachAdvice::NoRoute;
    }
    let class = class_of(info);
    match class {
        ReachClass::Public => {
            let n = cannot_be_reached(ctx);
            return if n > 0 && !relaying_for_contacts(info) {
                ReachAdvice::PublicCouldRelay(n)
            } else {
                ReachAdvice::Public
            };
        }
        ReachClass::Mapped => return ReachAdvice::Mapped(mapped_port(info).unwrap_or_default()),
        _ => {}
    }
    let reserved = info.reservations.len();
    let configured = relay_slots(info);
    let mut unreserved = info
        .relay_health
        .iter()
        .filter(|h| h.state != "reserved")
        .peekable();
    let starting = unreserved.peek().is_some() && unreserved.all(first_try);
    let owners = offered_slot_owners(info);
    if configured > 0 && reserved == 0 {
        if starting {
            return ReachAdvice::FirstTry;
        }
        let owner = match owners.as_deref() {
            Some([one]) => Some(operator_name(ctx.contacts, one)),
            Some(_) => {
                return ReachAdvice::OffersDown {
                    spare: info.relay_standby > 0,
                }
            }
            None => None,
        };
        let switch = switch_clause(info, ctx, owner.as_deref());
        let awake = owners
            .as_deref()
            .and_then(|o| o.first())
            .is_some_and(|key| ctx.reached_lately.iter().any(|r| r == key));
        return match owner {
            Some(owner) if awake => ReachAdvice::RelayOffOwnerAwake { owner, switch },
            owner => ReachAdvice::RelayDown { owner, switch },
        };
    }
    if reserved > 0 && reserved < configured && !starting {
        return ReachAdvice::OneRelayDown;
    }
    if reserved > 0 {
        if info.relay_health.len() == 1 && info.relay_standby == 0 {
            if let Some([one]) = owners.as_deref() {
                return ReachAdvice::RelayedOneOffer(operator_name(ctx.contacts, one));
            }
        }
        return ReachAdvice::Relayed;
    }
    let friend = ctx.names.friend.clone();
    // W2 and W3 say this node cannot be reached: only a check says so.
    if class == ReachClass::Unknown {
        return ReachAdvice::NotChecked { friend };
    }
    match friend {
        Some((name, _)) => ReachAdvice::AskFriend { name },
        None => ReachAdvice::NobodyReachable,
    }
}

/// W0: this computer has no default route. Nothing here names an
/// internet-side fix: none of them could help.
const NO_ROUTE_TEXT: &str = "this computer has no route to the internet right now: contacts \
     outside this network cannot reach you, and nothing on this computer can change that. \
     People on this network (Wi-Fi, hotspot or cable) still can.";

/// W1: our relay (offered by `owner`, or set by hand) does not answer.
fn w1_text(owner: Option<&str>, switch: &str) -> String {
    match owner {
        Some(owner) => format!(
            "{owner}'s relay is not answering (asleep or switched off?), so contacts outside \
             this network cannot reach you. Ask {owner} to wake that computer (`raven relay \
             status` on it shows whether the relay runs); raven-node keeps trying{switch}."
        ),
        None => format!(
            "your relay is not answering, so contacts outside this network cannot reach you. \
             Check that it runs and lets you in (on the relay's computer: `raven relay \
             status`); raven-node keeps trying{switch}."
        ),
    }
}

/// [`ReachAdvice::OverTor`]'s words: friends outside this network reach
/// this computer over Tor, so nothing is to do; a relay that is down is
/// named, never with "cannot reach you" or a step (E2 r38).
fn over_tor_text(inner: &ReachAdvice) -> String {
    const OVER_TOR: &str = "nothing to do: friends outside this network reach you over Tor \
         (your onion service is reachable)";
    match inner {
        ReachAdvice::RelayDown {
            owner: Some(owner), ..
        }
        | ReachAdvice::RelayOffOwnerAwake { owner, .. } => {
            format!("{OVER_TOR}. {owner}'s relay is not answering; raven-node keeps trying it.")
        }
        ReachAdvice::RelayDown { owner: None, .. } => {
            format!("{OVER_TOR}. Your relay is not answering; raven-node keeps trying it.")
        }
        ReachAdvice::OffersDown { .. } => format!(
            "{OVER_TOR}. The relays your contacts offered are not answering; raven-node keeps \
             trying them."
        ),
        ReachAdvice::RelayedOneOffer(name) => format!(
            "nothing to do: contacts reach you through {name}'s relay, and over Tor (your onion \
             service is reachable)."
        ),
        _ => format!("{OVER_TOR}. A relay or a forwarded port would be faster."),
    }
}

/// W1c: every relay contacts offered is lost. The switch is promised only
/// when another offered relay could take a slot (`spare`: status
/// `relay_standby`); with none, automatic choice keeps the ones it has.
fn w1c_text(spare: bool) -> String {
    format!(
        "the relays your contacts offered are not answering (a laptop relay may be asleep); \
         raven-node keeps trying{}.",
        if spare {
            " and switches to another offered relay after 10 minutes"
        } else {
            ""
        }
    )
}

/// W3, and the NOT REACHABLE NOW section's NobodyReachable row. `port`:
/// this node's p2p port ([`p2p_port`]).
fn w3_text(port: u16) -> String {
    format!(
        "nobody in your circle can be reached from the internet, so nobody outside this \
         network can reach you. Any one of these fixes it: ask a friend whose computer has a \
         public IP or a forwarded port to offer relaying (`{OFFER_CMD}` on their computer); run \
         {KIT_REF} on a Raspberry Pi with a forwarded port, or on a small VPS; or forward port \
         {port} (TCP and UDP) on your router to this computer (`raven node upnp on` does it if \
         your router supports UPnP)."
    )
}

impl ReachAdvice {
    /// The advice in words; `port` is this node's p2p port ([`p2p_port`]),
    /// the one a port forward must name.
    fn text(&self, port: u16) -> String {
        match self {
            Self::NoRoute => NO_ROUTE_TEXT.into(),
            Self::Public => "nothing to do: contacts can reach you directly.".into(),
            Self::PublicCouldRelay(n) => format!(
                "nothing to do: contacts can reach you directly. {n} of your contacts cannot be \
                 reached from the internet: this computer could relay for them (`{OFFER_CMD}`)."
            ),
            Self::Mapped(port) => format!(
                "nothing to do: your router forwards port {port}; a second independent check \
                 will confirm it."
            ),
            Self::FirstTry => {
                "wait a moment: raven-node is asking your relay for its first reservation.".into()
            }
            Self::RelayDown { owner, switch } => w1_text(owner.as_deref(), switch),
            Self::RelayOffOwnerAwake { owner, switch } => format!(
                "{owner}'s relay is not answering, though {owner}'s computer answered lately: \
                 its relay may be turned off, so contacts outside this network cannot reach \
                 you through it. Ask {owner} to check it (`raven relay status` on that \
                 computer); raven-node keeps trying{switch}."
            ),
            Self::OffersDown { spare } => w1c_text(*spare),
            Self::OneRelayDown => "one of your two relays is not answering; the other still \
                 works. Check it on the relay's computer with `raven relay status`."
                .into(),
            Self::Relayed => {
                "nothing to do: contacts reach you through your relay. Keep it running.".into()
            }
            Self::RelayedOneOffer(name) => format!(
                "nothing to do: contacts reach you through {name}'s relay. Only one relay is \
                 offered to you: if it stops or moves, contacts outside this network cannot \
                 reach you until it is back."
            ),
            Self::NotChecked { friend } => {
                let otherwise = match friend {
                    Some((name, arg)) => format!(
                        "{name} can be reached from the internet: ask {name} to relay for you \
                         (`raven node p2p on --relay {arg}`), run your own relay (`raven-node \
                         relay` on a Pi or a VPS), or turn on UPnP (`raven node upnp on`)"
                    ),
                    None => "ask a friend with a public IP or a port forward to run a relay, or \
                             run one yourself on a Pi or a VPS (`raven-node relay`, then `raven \
                             node p2p on --relay <its address>`), or turn on UPnP (`raven node \
                             upnp on`)"
                        .to_string(),
                };
                format!(
                    "nothing has checked yet whether contacts outside this network can reach \
                     you. If you forwarded port {port} (TCP and UDP) or have a public IP, \
                     contacts that have your direct address can; if not, {otherwise}."
                )
            }
            Self::AskFriend { name } => format!(
                "contacts outside this network cannot reach you: you are behind NAT and no relay \
                 is in use. {name} can be reached from the internet: ask {name} to offer \
                 relaying (`{OFFER_CMD}` on {name}'s computer), and RAVEN uses it by itself. Or \
                 run {KIT_REF} on a Raspberry Pi or a small VPS, or forward port {port} (TCP and \
                 UDP) on your router to this computer."
            ),
            Self::NobodyReachable => w3_text(port),
            Self::OverTor(inner) => over_tor_text(inner),
        }
    }

    /// Something for the user to do (not "nothing to do" or "wait"). Over
    /// Tor nothing is: friends outside this network reach this computer.
    fn is_problem(&self) -> bool {
        match self {
            Self::OverTor(_) => false,
            _ => matches!(
                self,
                Self::RelayDown { .. }
                    | Self::RelayOffOwnerAwake { .. }
                    | Self::OffersDown { .. }
                    | Self::OneRelayDown
                    | Self::AskFriend { .. }
                    | Self::NobodyReachable
            ),
        }
    }
}

/// The REACHABILITY `what to do` row.
pub(super) fn internet_what_to_do(info: &P2pStatusInfo, ctx: &ReachCtx) -> String {
    let text = reach_advice(info, ctx).text(p2p_port(info));
    match router_mapping_advice(info, ctx) {
        Some(more) => format!("{text} {more}"),
        None => text,
    }
}

/// What the router mapping adds to [`internet_what_to_do`] (Phase 4, only
/// from a raven-node that reports `port_map`): carrier NAT needs a relay, a
/// double NAT is fixed on the outer router, and a relayed node could turn
/// on router port mapping.
fn router_mapping_advice(info: &P2pStatusInfo, ctx: &ReachCtx) -> Option<&'static str> {
    let map = info.port_map.as_ref()?;
    if ctx.no_route() {
        return None;
    }
    match (class_of(info), map.v4.as_str()) {
        (_, "behind_another_nat") => Some("Your provider uses carrier NAT; a relay is required."),
        (_, "double_nat") => Some(
            "Your router sits behind another router: put the outer one in bridge mode or \
             forward the port there; until then a relay is needed.",
        ),
        (ReachClass::Relayed, "off") => Some("Turn on router port mapping: raven node upnp on."),
        _ => None,
    }
}

/// Contacts outside this network reach this node now: a relay holds a
/// reservation for it, or its own address answers (public, or mapped by
/// UPnP).
pub(super) fn reached_from_outside(info: &P2pStatusInfo) -> bool {
    matches!(
        class_of(info),
        ReachClass::Public | ReachClass::Mapped | ReachClass::Relayed
    ) || !info.reservations.is_empty()
}

/// The same advice as `raven doctor`'s next step, only when there is
/// something to do (W1, W1b, W1c, W2, W3).
pub(super) fn internet_next_step(info: &P2pStatusInfo, ctx: &ReachCtx) -> Option<String> {
    let advice = reach_advice(info, ctx);
    advice.is_problem().then(|| advice.text(p2p_port(info)))
}

// ── raven status: NOT REACHABLE NOW ─────────────────────────────────────────

/// Rows of the NOT REACHABLE NOW section shown at most.
const NOT_REACHABLE_ROWS: usize = 8;

/// How each of our relay slots is named: `{owner}'s relay` when a contact
/// offered it, else `your relay at host:port`. Never a PeerId.
pub(super) fn slot_names(info: &P2pStatusInfo, contacts: &[Contact]) -> Vec<String> {
    info.relay_health
        .iter()
        .map(|h| {
            if h.source == "offer" {
                format!("{}'s relay", operator_name(contacts, &h.operator_pub_hex))
            } else {
                format!("your relay at {}", relay_label(&h.relay))
            }
        })
        .collect()
}

/// One contact's reason in a few words (`name`: its label; `relays`: our
/// slots' names, [`slot_names`]; `reversed`: the last delivery to it went
/// over a connection it opened).
fn short_reason(d: &Diag, name: &str, relays: &[String], reversed: bool) -> String {
    match d.why {
        Why::ContactOffline => format!(
            "offline \u{2014} {name}'s computer is not connected to its relay{}",
            d.heard_s
                .map(|s| format!("; last heard {} ago", age_text(s)))
                .unwrap_or_default()
        ),
        Why::RelayAsleep => match d
            .relay
            .and_then(|slot| relays.get(usize::from(slot.saturating_sub(1))))
        {
            Some(relay) => format!("no path \u{2014} {relay} is not answering (you both use it)"),
            None if d.relay.is_some() => {
                "no path \u{2014} your relay is not answering (you both use it)".into()
            }
            None => format!(
                "no path \u{2014} {name}'s relay is not answering (asleep or switched off?)"
            ),
        },
        Why::RelayRefused => format!(
            "turned away \u{2014} {name}'s relay carries messages only for its owner's verified \
             contacts"
        ),
        Why::RelayOff => format!("no path \u{2014} {name}'s relay stopped relaying"),
        Why::RelayBusy => format!(
            "turned away \u{2014} {name}'s relay is full, or does not relay for you; retrying"
        ),
        Why::NotAdmitted => {
            format!("turned away \u{2014} {name}'s RAVEN does not have your current card")
        }
        Why::BothNat => {
            format!("no path \u{2014} you and {name} are both behind NAT, and {name} uses no relay")
        }
        Why::NoRelay => format!(
            "no path \u{2014} {name} uses no relay; it goes out when {name} next sends you a \
             message{}",
            if reversed { " (as last time)" } else { "" }
        ),
        Why::DirectFailed => {
            format!("no answer \u{2014} {name}'s computer did not answer at its internet address")
        }
        Why::NoRoute => "no route \u{2014} this computer has no route to the internet".into(),
        Why::LanOff => format!(
            "local network off \u{2014} you turned it off, so RAVEN does not look for {name} \
             here (`{LAN_ON_CMD}`)"
        ),
        Why::LanNoAnswer => format!(
            "no answer \u{2014} {}{}",
            super::ext::LAN_NO_ANSWER_SHORT,
            d.heard_s
                .map(|s| format!("; last heard {} ago", age_text(s)))
                .unwrap_or_default()
        ),
    }
}

/// `rows` with the reason `raven send` gives (E1: status said a contact's
/// computer "did not answer at its internet address" where the send had
/// said it was there): a contact whose p2p reason only says its direct
/// addresses did not answer, or that this computer has no route to the
/// internet, and whose waiting messages last failed on the LAN
/// (`lan_failed`, by lowercase key) gets the LAN's words ([`lan_reason`]).
/// Such a row names no fix on the internet side.
pub(super) fn with_lan_reasons(
    rows: &[ContactWhy],
    lan_failed: &HashMap<String, &'static str>,
) -> Vec<ContactWhy> {
    rows.iter()
        .map(|r| {
            let lan = lan_failed.get(&r.peer_pub_hex.trim().to_ascii_lowercase());
            match (Diag::find(&r.reason), lan) {
                (Some(d), Some(code)) if matches!(d.why, Why::DirectFailed | Why::NoRoute) => {
                    ContactWhy {
                        reason: format!("{LAN_REASON_TAG}{code}"),
                        ..r.clone()
                    }
                }
                _ => r.clone(),
            }
        })
        .collect()
}

/// `lan_failed` ([`with_lan_reasons`]'s) plus every contact whose last
/// delivery went over the LAN (`paths`, LAST DELIVERY's rows) as one that
/// did not answer on this network (E2 r9 #9: NOT REACHABLE said "did not
/// answer at its internet address" while LAST DELIVERY said "same network
/// (LAN)" for the same friend, who had no internet address at all). A LAN
/// failure the outbox saw keeps its own code.
pub(super) fn with_last_lan_deliveries(
    lan_failed: &HashMap<String, &'static str>,
    paths: &[ContactPath],
) -> HashMap<String, &'static str> {
    let mut out = lan_failed.clone();
    for p in paths.iter().filter(|p| p.carrier == "lan_dial") {
        out.entry(p.peer_pub_hex.trim().to_ascii_lowercase())
            .or_insert("NOT_REACHABLE");
    }
    out
}

/// A row's reason that [`with_lan_reasons`] took from the LAN: this tag,
/// then the outbox code. Never a reason block, so no fix reads it.
const LAN_REASON_TAG: &str = "lan: ";

/// The words of a LAN reason ([`with_lan_reasons`]), as `short_reason`'s.
fn lan_reason(code: &str, name: &str) -> Option<String> {
    Some(match code {
        "NOT_LISTENING" => format!(
            "not receiving \u{2014} {name}'s computer is there, but Raven isn't receiving right \
             now (it may be locked or closed)"
        ),
        "NOT_REACHABLE" => {
            format!("no answer \u{2014} {name}'s computer did not answer on this network")
        }
        "CLOSED_EARLY" => format!(
            "hung up \u{2014} something answered at {name}'s address on this network but hung up"
        ),
        _ => return None,
    })
}

/// `n message(s) waiting`.
fn messages_waiting(n: usize) -> String {
    format!("{n} message{} waiting", if n == 1 { "" } else { "s" })
}

/// The NOT REACHABLE NOW rows: each contact raven-node could not reach
/// (newest first), its label (cut to the key column) and why, how many
/// messages wait for it (`waiting`, by lowercase key) and how long ago.
/// Keys this book does not hold are skipped; at most
/// [`NOT_REACHABLE_ROWS`], then `(+N more)`. When every row says this
/// computer has no route, one row says so for all of them. A reason this
/// ash does not know is shown as it came, made safe for the terminal.
pub(super) fn not_reachable_rows(
    rows: &[ContactWhy],
    contacts: &[Contact],
    paths: &[ContactPath],
    waiting: &HashMap<String, usize>,
    relays: &[String],
) -> Vec<(String, String)> {
    let ctx = ReachCtx {
        unreachable: rows,
        contacts,
        ..ReachCtx::default()
    };
    let known = ctx.known_rows();
    let waits = |r: &ContactWhy| {
        waiting
            .get(&r.peer_pub_hex.trim().to_ascii_lowercase())
            .copied()
            .unwrap_or(0)
    };
    if !known.is_empty()
        && known
            .iter()
            .all(|(_, _, d)| d.as_ref().is_some_and(|d| d.why == Why::NoRoute))
    {
        let n: usize = known.iter().map(|(r, _, _)| waits(r)).sum();
        return vec![(
            "contacts".into(),
            format!(
                "this computer has no route to the internet: only contacts on this network can \
                 be reached ({})",
                messages_waiting(n)
            ),
        )];
    }
    let more = known.len().saturating_sub(NOT_REACHABLE_ROWS);
    let mut out: Vec<(String, String)> = known
        .iter()
        .take(NOT_REACHABLE_ROWS)
        .map(|(r, c, d)| {
            let name = c.primary_label();
            let reversed = paths.iter().any(|p| {
                p.peer_pub_hex
                    .trim()
                    .eq_ignore_ascii_case(r.peer_pub_hex.trim())
                    && p.carrier == "p2p_dial"
                    && p.path == "reversed"
            });
            let short = match d {
                Some(d) => short_reason(d, &name, relays, reversed),
                None => r
                    .reason
                    .strip_prefix(LAN_REASON_TAG)
                    .and_then(|code| lan_reason(code, &name))
                    .unwrap_or_else(|| sanitize_terminal_line(&r.reason)),
            };
            let wait = match waits(r) {
                0 => String::new(),
                n => format!("; {}", messages_waiting(n)),
            };
            (
                super::key_label(&name),
                format!("{short}{wait}, {} ago", age_text(r.age_s)),
            )
        })
        .collect();
    if more > 0 {
        out.push((String::new(), format!("(+{more} more)")));
    }
    out
}

/// The NOT REACHABLE NOW `what to do` row: the fix with the highest
/// [`Fix::priority`] over the rows, worded for the contact of the first row
/// that needs it. With no route to the internet nothing here can help, and
/// it says so. `None` when no row says anything (reasons this ash does not
/// know, or a circle it cannot read).
pub(super) fn section_what_to_do(info: &P2pStatusInfo, ctx: &ReachCtx) -> Option<String> {
    let rows = ctx.known_rows();
    if rows.is_empty() {
        return None;
    }
    // `raven lan off` first: with no route to the internet it is the one
    // way left.
    if rows
        .iter()
        .any(|(_, _, d)| d.as_ref().is_some_and(|d| d.why == Why::LanOff))
    {
        return Some(lan_on_row());
    }
    if ctx.no_route() {
        return Some(local_only_row());
    }
    let me_public = class_of(info) == ReachClass::Public;
    let relaying = relaying_for_contacts(info);
    let (fix, d, contact) = rows
        .iter()
        .filter_map(|(r, c, d)| {
            let d = d.as_ref()?;
            let circle = ctx.circle_for(&r.peer_pub_hex);
            let fix = reach_diag::pick_fix(d, me_public, relaying, &circle);
            (fix != Fix::Generic).then_some((fix, d, *c))
        })
        .min_by_key(|(fix, _, _)| std::cmp::Reverse(fix.priority()))?;
    let who = contact.primary_label();
    Some(match fix {
        Fix::LocalOnly => local_only_row(),
        Fix::LanOn => lan_on_row(),
        Fix::UseMailbox => mailbox_row(&who),
        Fix::AskFriendToHoldMail => hold_mail_row(&who),
        Fix::NobodyReachable => w3_text(p2p_port(info)).replace(
            "so nobody outside this network can reach you",
            "so nothing can carry messages between two computers behind NAT",
        ),
        Fix::AskFriend(key) => {
            let name = ctx
                .contact(&hex::encode(key))
                .map_or_else(|| "a contact".to_string(), Contact::primary_label);
            format!(
                "{name} can be reached from the internet: ask {name} to offer relaying \
                 (`{OFFER_CMD}` on {name}'s computer); RAVEN then uses it by itself for every \
                 contact who is also {name}'s verified contact."
            )
        }
        Fix::OfferRelaying => format!(
            "this computer can be reached from the internet: offer relaying to your verified \
             contacts (`{OFFER_CMD}`) and RAVEN reaches them through it."
        ),
        Fix::AskRelayOwner => format!(
            "ask {who} whose relay it is and become that person's verified contact (`raven \
             whoami --card` on both computers)."
        ),
        Fix::WakeRelay => match d.relay {
            Some(slot) => {
                let owner = info
                    .relay_health
                    .get(usize::from(slot.saturating_sub(1)))
                    .filter(|h| h.source == "offer")
                    .map(|h| operator_name(ctx.contacts, &h.operator_pub_hex));
                w1_text(
                    owner.as_deref(),
                    &switch_clause(info, ctx, owner.as_deref()),
                )
            }
            None => format!(
                "ask {who} to check {who}'s relay: the computer it runs on must be on and awake; \
                 raven-node keeps trying."
            ),
        },
        Fix::ResendCard => format!(
            "make sure {who} verified you (`raven contact verify` on both computers); {who}'s \
             node learns this computer's network ID once you are connected over Tor or the local \
             network."
        ),
        Fix::TheyNeedNewRelay => format!(
            "{who} needs a new relay (a friend of {who}'s who offers relaying); raven-node keeps \
             trying."
        ),
        Fix::TheyWriteFirst => {
            format!("nothing to do: it goes out when {who} next sends you a message.")
        }
        Fix::RetryLater => "nothing to do: raven-node tries again by itself.".into(),
        Fix::WaitUntilOnline => "nothing to do on your side: waiting messages go out when the \
             contacts are back online."
            .into(),
        Fix::Generic => return None,
    })
}

/// The LocalOnly fix in row style: nothing on this computer can help.
fn local_only_row() -> String {
    "nothing to fix from here: messages to people on this network still go; the rest wait.".into()
}

/// The LanOn fix in row style (Phase 3, P3.C6's words): `raven lan off`
/// keeps every contact on this network away, and nothing is lost.
fn lan_on_row() -> String {
    super::ext::LAN_OFF_TEXT.into()
}

/// The UseMailbox fix in row style (Phase 3 custody), for `who`.
fn mailbox_row(who: &str) -> String {
    format!(
        "turn on friend mailboxes (`{MAILBOX_CMD}`): a friend you both verified can then hold \
         messages for {who} while {who} is offline."
    )
}

/// The AskFriendToHoldMail fix in row style (Phase 3 custody), for `who`.
fn hold_mail_row(who: &str) -> String {
    format!(
        "no friend holds mail for {who} yet: ask a friend you both verified, whose computer is \
         always on, to run `{HOLD_MAIL_CMD}`."
    )
}

/// The local network's next step (Phase 3 diagnosis, P3.C6's words),
/// whether or not a p2p host runs: `raven lan on` when raven-node noted
/// `lan_off` for a contact of this book, else, for `lan_no_answer`, what the
/// beacon found and what to try (a hotspot), then a friend's mailbox when
/// none can hold that contact's mail. `None` when no row says either.
pub(super) fn lan_what_to_do(ctx: &ReachCtx) -> Option<String> {
    let rows = ctx.known_rows();
    let has = |why: Why| {
        rows.iter()
            .find(|(_, _, d)| d.as_ref().is_some_and(|d| d.why == why))
    };
    if has(Why::LanOff).is_some() {
        return Some(lan_on_row());
    }
    let (r, c, _) = has(Why::LanNoAnswer)?;
    let who = c.primary_label();
    let then = match ctx.circle_for(&r.peer_pub_hex).mail {
        MailPath::MailboxOff => format!(" Or {}", mailbox_row(&who)),
        MailPath::NoFriend => format!(" Or: {}", hold_mail_row(&who)),
        MailPath::NoFix => String::new(),
    };
    Some(format!("{}{then}", super::ext::LAN_NO_ANSWER_TEXT))
}

/// A fix the user can act on (the doctor's next step); "nothing to do"
/// rows and no route to the internet are not, but for `raven lan on`
/// (Phase 3: the local network is the one way left).
pub(super) fn section_next_step(info: &P2pStatusInfo, ctx: &ReachCtx) -> Option<String> {
    let step = section_what_to_do(info, ctx)?;
    if ctx.no_route() && step != lan_on_row() {
        return None;
    }
    let idle = ["nothing to do", "nothing to fix from here"];
    (!idle.iter().any(|w| step.starts_with(w))).then_some(step)
}

/// The NOT REACHABLE NOW section, after REACHABILITY: while the host runs
/// and raven-node could not reach a contact of this book since it started
/// (in memory only).
fn print_not_reachable_section(
    data_dir: &Path,
    status: &Result<IpcResponse, String>,
    info: &P2pStatusInfo,
    ctx: &ReachCtx,
) {
    if ctx.unreachable.is_empty() {
        return;
    }
    let paths = match status {
        Ok(IpcResponse::Status { last_paths, .. }) => last_paths.as_slice(),
        _ => &[],
    };
    let live = super::ext::live_outbox_counts(data_dir);
    // The reason `raven send` gives (E1): the LAN's where it failed there,
    // and for a contact last reached on the LAN (E2 r9 #9).
    let lan_failed = with_last_lan_deliveries(&live.lan_failed, paths);
    let lan_rows = with_lan_reasons(ctx.unreachable, &lan_failed);
    let ctx = &ReachCtx {
        unreachable: &lan_rows,
        ..ctx.clone()
    };
    let rows = not_reachable_rows(
        ctx.unreachable,
        ctx.contacts,
        paths,
        &live.counts,
        &slot_names(info, ctx.contacts),
    );
    if rows.is_empty() {
        return;
    }
    let col = c();
    println!();
    println!(
        "{}NOT REACHABLE NOW \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}",
        col.bold, col.reset
    );
    println!(
        "  {}(why the last try failed; since raven-node started){}",
        col.dim, col.reset
    );
    for (label, value) in rows {
        kv(&label, &value);
    }
    if let Some(step) = section_what_to_do(info, ctx) {
        kv("what to do", &step);
    }
}

/// The REACHABILITY section of `raven status`, while the libp2p host runs,
/// then NOT REACHABLE NOW.
pub(super) fn print_reach_section(
    data_dir: &Path,
    status: &Result<IpcResponse, String>,
    contacts: &[Contact],
) {
    let Some(info) = p2p_info(status) else {
        return;
    };
    let ctx = ReachCtx::read(data_dir, status, contacts);
    let col = c();
    println!();
    println!(
        "{}REACHABILITY \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}",
        col.bold, col.reset
    );
    kv("internet", &internet_row(info));
    if let Some(row) = checks_row(info) {
        kv("checks", &row);
    }
    for (label, row) in relay_rows(info, contacts) {
        kv(&label, &row);
    }
    if let Some(row) = spare_relays_row(info) {
        kv("spare relays", &row);
    }
    if let Some(row) = circle_row(&ctx.circle, &ctx.names) {
        kv("circle", &row);
    }
    kv("what to do", &internet_what_to_do(info, &ctx));
    print_not_reachable_section(data_dir, status, info, &ctx);
}

// ── raven relay … ────────────────────────────────────────────────────────────

/// `raven relay use`: a relay a friend runs, from the `via=` lines of their
/// `raven relay card` (pasted with or without `via=`, on one line or
/// several, at most [`MAX_VIA`] addresses). Saved like `raven node p2p on
/// --relay …`: a listen setting already saved is kept, and p2p is turned on
/// (port 7423) when it was off.
pub(super) fn cmd_relay_use(data_dir: &Path, words: &[String]) -> Result<(), String> {
    cmd_relay_use_with(data_dir, words, stdin_is_tty(), ask_on_terminal)
}

pub(super) fn cmd_relay_use_with(
    data_dir: &Path,
    words: &[String],
    tty: bool,
    ask: impl FnOnce(u16) -> Option<String>,
) -> Result<(), String> {
    if relay_allow::is_relay_dir(data_dir) {
        return Err(
            "this folder is a dedicated relay (raven-node relay): `raven relay use` saves a \
             friend's relay in your own profile; run it without --data-dir (nothing changed)"
                .into(),
        );
    }
    let vias = p2p_route::split_relay_tokens(&words.join(" "))?;
    let policy = policy_for_edit(data_dir)?;
    let listen = if policy.p2p_listen.trim().is_empty() {
        "on".to_string()
    } else {
        policy.p2p_listen.clone()
    };
    let on = P2pOnArgs {
        listen,
        relay: vias.iter().map(|v| v.text.clone()).collect(),
        upnp: None,
    };
    cmd_node_p2p_with(data_dir, Some(on), tty, ask)?;
    println!("{C_DIM}{}{C_RESET}", relay_use_saved(&vias));
    if super::card_routes_live() {
        println!(
            "next: 1) restart raven-node: {}\n      2) give the relay's operator your card \
             (raven whoami --card): they allow it (raven-relay allow --card …) and compare your \
             fingerprint\n      3) send the same card to your contacts, so they reach you \
             through this relay",
            service_restart_hint()
        );
    } else {
        println!(
            "next: 1) restart raven-node: {}\n      2) give the relay's operator your network \
             ID (raven whoami --peer-id): they allow it (raven-relay allow <PeerId>)\n      3) \
             your verified contacts learn this relay inside your encrypted links once you are \
             connected",
            service_restart_hint()
        );
    }
    Ok(())
}

/// What `raven relay use` saved: relays, not addresses (two addresses of
/// one relay are one relay with a fallback).
fn relay_use_saved(vias: &[p2p_route::ViaAddr]) -> String {
    let relays = p2p_route::distinct_relays(vias);
    let addrs = vias.len();
    let fallback = if relays < addrs {
        ": the second address of the same relay is its fallback, e.g. TCP 443"
    } else {
        ""
    };
    format!(
        "{relays} relay{} saved ({addrs} address{}{fallback})",
        if relays == 1 { "" } else { "s" },
        if addrs == 1 { "" } else { "es" },
    )
}

/// `raven relay allow|deny` target: a PeerId, or a contact (its p2p PeerId).
/// Returns the PeerId, the contact's name and its device key (both empty
/// for a PeerId).
fn resolve_peer_id(data_dir: &Path, who: &str) -> Result<(String, String, String), String> {
    if let Ok(peer) = p2p_route::normalize_peer_id(who) {
        return Ok((peer, String::new(), String::new()));
    }
    let contacts = load_contacts(data_dir)?;
    let hits = resolve_contact_arg(&contacts, who);
    let contact = match hits.as_slice() {
        [] => {
            return Err(format!(
                "{} is neither a PeerId (12D3KooW…) nor one of your contacts{}",
                sanitize_terminal_line(who),
                if contacts.is_empty() {
                    " (this folder has no contacts: pass the PeerId or --card)".to_string()
                } else {
                    format!(": {}", no_contact_message(&contacts, who))
                }
            ))
        }
        [one] => *one,
        many => {
            return Err(format!(
                "contact {} is ambiguous ({} matches): use the @tag",
                sanitize_terminal_line(who),
                many.len()
            ))
        }
    };
    let peer = p2p_route::normalize_peer_id(&contact.p2p)
        .ok()
        .or_else(|| proven_learned_peer(data_dir, contact))
        .ok_or_else(|| {
            format!(
                "{} has no p2p PeerId yet (Raven learns it from them once you are connected): \
                 pass the PeerId they read out (`raven whoami --peer-id`)",
                contact.primary_label()
            )
        })?;
    Ok((peer, contact.primary_label(), contact.pub_hex.clone()))
}

/// The PeerId `contact`'s route hints named, once a p2p link proved it
/// (the friend relay admits such a contact too).
fn proven_learned_peer(data_dir: &Path, contact: &Contact) -> Option<String> {
    let key = contact.pub_hex.trim();
    learned_routes::learned_peer_ids(data_dir, now_ms())
        .into_iter()
        .find(|(pub_hex, _, proven)| *proven && pub_hex.eq_ignore_ascii_case(key))
        .map(|(_, peer, _)| peer)
}

/// The contact whose PeerId (in the book, or learned and proven) is
/// `peer`: their name and device key. The friend relay admits them by
/// itself.
fn contact_with_peer(data_dir: &Path, peer: &str) -> Option<(String, String)> {
    let contacts = load_contacts(data_dir).ok()?;
    contacts
        .iter()
        .find(|c| {
            p2p_route::normalize_peer_id(&c.p2p).ok().as_deref() == Some(peer)
                || proven_learned_peer(data_dir, c).as_deref() == Some(peer)
        })
        .map(|c| (c.primary_label(), c.pub_hex.clone()))
}

/// The p2p PeerId of a card `raven relay allow` takes.
fn card_peer_id(card: super::ContactCard) -> Result<(String, String), String> {
    let route = card.p2p.ok_or(if super::card_routes_live() {
        "that card has no p2p= PeerId (a raven-card/2): ask for `raven whoami --card` after \
         `raven node p2p on`"
    } else {
        "that card names no PeerId (a card carries no network ID in this raven): ask your \
         friend for the line `raven whoami --peer-id` prints and allow that PeerId"
    })?;
    Ok((route.peer_id, card.fingerprint))
}

/// Printed for every card `raven relay allow` reads: the card's own
/// fingerprint, to compare with the friend before allowing them.
fn allow_card_fingerprint(fingerprint: &str) -> String {
    format!(
        "fingerprint={fingerprint}  {C_DIM}(compare it with your friend in person or by \
         voice){C_RESET}"
    )
}

/// The one question `raven relay allow --card` asks on a terminal.
fn allow_question(who: &str) -> String {
    format!("Allow {who} to use this relay? [y/N] ")
}

const ALLOW_PRIVACY_NOTE: &str =
    "a running relay picks this up within seconds. They learn this relay's PeerId and address; \
     it learns their PeerId, IP, timing and byte counts, never their messages.";

/// `raven relay allow`: who (a PeerId or a contact) or `--card`. A card's
/// fingerprint is printed, and on a terminal the card is confirmed once.
pub(super) fn cmd_relay_allow(
    data_dir: &Path,
    who: Option<&str>,
    card: Option<&str>,
    label: &str,
) -> Result<(), String> {
    // Asked only when someone sees the question: stdin and stdout are both
    // a terminal (the harness and the netns script capture the output, so
    // they behave as before even when started from a terminal). Unit tests
    // drive the question through `cmd_relay_allow_with`.
    let tty = stdin_is_tty() && io::stdout().is_terminal() && !cfg!(test);
    cmd_relay_allow_with(data_dir, who, card, label, tty, |question| {
        // A trust decision: lines of an earlier paste never answer it.
        super::discard_pending_tty_input();
        ask_line(question)
    })
}

/// [`cmd_relay_allow`] with the terminal check and the question passed in.
/// Without a terminal (scripts, the harness) nothing is asked, as before.
pub(super) fn cmd_relay_allow_with(
    data_dir: &Path,
    who: Option<&str>,
    card: Option<&str>,
    label: &str,
    tty: bool,
    ask: impl FnOnce(&str) -> Option<String>,
) -> Result<(), String> {
    let (peer, name, fingerprint, key) = match (who, card) {
        (Some(_), Some(_)) => return Err("give a contact / PeerId or --card, not both".into()),
        (None, None) => {
            return Err(
                "who may reserve? give a contact (@tag), a PeerId, --card CARD or --cards FILE"
                    .into(),
            )
        }
        (Some(w), None) => {
            let (peer, name, key) = resolve_peer_id(data_dir, w)?;
            (peer, name, None, key)
        }
        (None, Some(text)) => {
            let (peer, fingerprint) = card_peer_id(super::read_card_arg(text)?)?;
            (peer, String::new(), Some(fingerprint), String::new())
        }
    };
    // A profile's friend relay: the contact this PeerId belongs to, so a
    // block of that contact turns the entry away even once its PeerId is
    // forgotten (a learned one goes with the block).
    let key = if relay_allow::is_relay_dir(data_dir) {
        String::new()
    } else if key.is_empty() {
        contact_with_peer(data_dir, &peer).map_or_else(String::new, |(_, key)| key)
    } else {
        key
    };
    let label = if label.trim().is_empty() {
        name
    } else {
        label.to_string()
    };
    if let Some(fingerprint) = &fingerprint {
        println!("{}", allow_card_fingerprint(fingerprint));
        let who = if label.is_empty() {
            peer.clone()
        } else {
            sanitize_terminal_line(&label)
        };
        if tty && !said_yes(ask(&allow_question(&who))) {
            println!("{C_DIM}not allowed (nothing changed){C_RESET}");
            return Ok(());
        }
    }
    let added = relay_allow::relay_allow_contact(data_dir, &peer, &label, &key)?;
    println!(
        "{C_GREEN}{}{C_RESET} {peer}{} may reserve on this relay ({})",
        if added { "allowed" } else { "already allowed" },
        if label.is_empty() {
            String::new()
        } else {
            format!(" ({})", sanitize_terminal_line(&label))
        },
        relay_allow::relay_allow_path(data_dir).display()
    );
    println!("{C_DIM}{ALLOW_PRIVACY_NOTE}{C_RESET}");
    Ok(())
}

/// Largest `raven relay allow --cards` file: a card line per friend, up to
/// [`relay_allow::MAX_ALLOW_ENTRIES`] of them, with room for comments.
const CARDS_FILE_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// The cards of a `--cards` file: one card per line, `#` lines and blank
/// lines skipped, at most [`relay_allow::MAX_ALLOW_ENTRIES`]. Any bad line
/// refuses the whole file. Returns each card's PeerId and fingerprint.
fn parse_cards_text(raw: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if out.len() == relay_allow::MAX_ALLOW_ENTRIES {
            return Err(format!(
                "--cards: more than {} cards (nobody was allowed)",
                relay_allow::MAX_ALLOW_ENTRIES
            ));
        }
        let card = super::parse_card_or_invite(line)
            .and_then(card_peer_id)
            .map_err(|e| format!("--cards line {}: {e} (nobody was allowed)", i + 1))?;
        out.push(card);
    }
    if out.is_empty() {
        return Err("--cards: the file holds no card (one card line per friend)".into());
    }
    Ok(out)
}

/// `raven relay allow --cards FILE`: several friends at once, all or
/// nothing. Every line is checked first, and nothing is written when one is
/// bad or the allow-list has no room for all of them. Nothing is asked (the
/// file is the operator's own list); each card's fingerprint is printed, to
/// compare.
pub(super) fn cmd_relay_allow_cards(
    data_dir: &Path,
    file: &Path,
    label: &str,
) -> Result<(), String> {
    let shown = sanitize_terminal_line(&file.display().to_string());
    let meta = std::fs::metadata(file).map_err(|e| format!("--cards: {shown}: {e}"))?;
    if !meta.is_file() || meta.len() > CARDS_FILE_MAX_BYTES {
        return Err(format!(
            "--cards: {shown} is not a cards file (a regular file of at most \
             {CARDS_FILE_MAX_BYTES} bytes, one card per line)"
        ));
    }
    let raw = std::fs::read_to_string(file).map_err(|e| format!("--cards: {shown}: {e}"))?;
    let cards = parse_cards_text(&raw)?;
    let entries: Vec<(String, String)> = cards
        .iter()
        .map(|(peer, _)| (peer.clone(), label.to_string()))
        .collect();
    let added = relay_allow::relay_allow_all(data_dir, &entries)?;
    for ((peer, fingerprint), new) in cards.iter().zip(&added) {
        println!(
            "{C_GREEN}{}{C_RESET} {peer} fingerprint={fingerprint}",
            if *new { "allowed" } else { "already allowed" }
        );
    }
    let new = added.iter().filter(|a| **a).count();
    println!(
        "{} card(s): {new} allowed, {} already allowed ({})",
        cards.len(),
        cards.len() - new,
        relay_allow::relay_allow_path(data_dir).display()
    );
    println!(
        "{C_DIM}compare each fingerprint with its friend in person or by voice; deny a wrong one \
         with `raven relay deny <PeerId>`{C_RESET}"
    );
    println!("{C_DIM}{ALLOW_PRIVACY_NOTE}{C_RESET}");
    Ok(())
}

/// How many epochs `raven relay schedule` names by default: the active one
/// and [`peer_rotation::AHEAD`] more (about 6 months of 28-day epochs).
pub(super) const RELAY_SCHEDULE_DEFAULT_EPOCHS: u8 = peer_rotation::AHEAD as u8 + 1;

/// Largest `raven relay allow --schedule` input: one schedule line
/// ([`peer_rotation::RELAY_SCHEDULE_MAX_LEN`]) with room for white space.
const SCHEDULE_INPUT_MAX_BYTES: u64 = 4096;

/// [`cmd_relay_schedule`]'s line: this profile's PeerIds (its `identity`,
/// read last) of `epochs` epochs from the one in use at `now_ms`, or from
/// `postponed` (the earlier epoch a running raven-node kept after a relay
/// refused the next ID) (`raven-relay-schedule/1 …`). Refused, with the
/// reason, while PeerId rotation is off: its gate (`live`) or this
/// profile's setting (node_policy.json `peer_rotation`): the profile's
/// PeerId is then fixed, and a relay allows it once.
pub(super) fn relay_schedule_text(
    data_dir: &Path,
    epochs: u8,
    live: bool,
    now_ms: u64,
    postponed: Option<u64>,
    identity: impl FnOnce() -> Result<Option<raven_core::Identity>, String>,
) -> Result<String, String> {
    if !live {
        return Err(format!(
            "your network ID (PeerId) does not rotate, so a relay needs no schedule: the relay \
             allows your PeerId once (raven-relay allow --card …, with your `raven whoami \
             --card`). {}",
            raven_core::portmap_gate::PEER_ROTATION_HOLD
        ));
    }
    if relay_allow::is_relay_dir(data_dir) {
        return Err(
            "this is a relay folder: run `raven relay schedule` in your own profile, then give \
             its line to this relay (raven-relay allow --schedule -)"
                .into(),
        );
    }
    if raven_core::node_policy::load_policy(data_dir).peer_rotation != Some(true) {
        return Err(
            "your network ID (PeerId) rotation is off, so a relay needs no schedule: the relay \
             allows your PeerId once (raven-relay allow --card …, with your `raven whoami \
             --card`). `raven node p2p rotate on` turns it on."
                .into(),
        );
    }
    let id =
        identity()?.ok_or("no identity here: run `raven relay schedule` in your own profile")?;
    let len = peer_rotation::epoch_len_s();
    let clock = peer_rotation::epoch_at(&id, now_ms / 1000, len);
    let active = postponed.map_or(clock, |e| e.min(clock));
    Ok(peer_rotation::format_relay_schedule(
        &id,
        active,
        usize::from(epochs),
    ))
}

/// `raven relay schedule [--epochs N]`: print the line a dedicated relay's
/// operator gives `raven relay allow --schedule`, so the relay keeps
/// admitting this profile while its PeerId rotates. Only the line goes to
/// stdout (it can be piped); the advice goes to stderr.
pub(super) fn cmd_relay_schedule(data_dir: &Path, epochs: u8) -> Result<(), String> {
    // A running raven-node that postponed a rotation keeps an earlier
    // epoch's key: the line starts there.
    let live = raven_core::portmap_gate::peer_rotation_live_enabled();
    let postponed = live
        .then(|| {
            let status = ipc_client::ipc_request_timeout(
                data_dir,
                &IpcRequest::status(),
                Duration::from_millis(1500),
            );
            p2p_info(&status)
                .and_then(|i| i.rotation.as_ref())
                .filter(|r| r.state == "postponed")
                .and_then(|r| r.epoch)
        })
        .flatten();
    let text = relay_schedule_text(data_dir, epochs, live, now_ms(), postponed, || {
        try_load_identity(data_dir)
    })?;
    println!("{text}");
    let days = u64::from(epochs).saturating_mul(peer_rotation::epoch_len_s()) / 86_400;
    eprintln!(
        "{C_DIM}give this line to the operator of each relay you use that is not your contact \
         (raven-relay allow --schedule -). It names your network IDs for the next {epochs} \
         epoch(s), about {days} day(s): run it again before then. Contacts follow your network \
         ID by themselves.{C_RESET}"
    );
    Ok(())
}

/// The schedule text of `--schedule`: `-` reads stdin, a line starting with
/// `raven-relay-schedule/` is the text itself, anything else is a file. At
/// most [`SCHEDULE_INPUT_MAX_BYTES`] are read.
fn read_schedule_arg(source: &str) -> Result<String, String> {
    let t = source.trim();
    if t.starts_with("raven-relay-schedule/") {
        return Ok(t.to_string());
    }
    let mut raw = String::new();
    if t == "-" {
        io::Read::read_to_string(
            &mut io::Read::take(io::stdin().lock(), SCHEDULE_INPUT_MAX_BYTES + 1),
            &mut raw,
        )
        .map_err(|e| format!("--schedule: stdin: {e}"))?;
    } else {
        let shown = sanitize_terminal_line(t);
        let meta = std::fs::metadata(t).map_err(|e| {
            format!(
                "--schedule: \"{shown}\" is neither a schedule line (raven-relay-schedule/1 …), \
                 - (stdin) nor a readable file ({e})"
            )
        })?;
        if !meta.is_file() || meta.len() > SCHEDULE_INPUT_MAX_BYTES {
            return Err(format!(
                "--schedule: {shown} is not a schedule file (a regular file of at most \
                 {SCHEDULE_INPUT_MAX_BYTES} bytes holding the line `raven relay schedule` prints)"
            ));
        }
        raw = std::fs::read_to_string(t).map_err(|e| format!("--schedule: {shown}: {e}"))?;
    }
    if raw.len() as u64 > SCHEDULE_INPUT_MAX_BYTES {
        return Err(format!(
            "--schedule: more than {SCHEDULE_INPUT_MAX_BYTES} bytes: give the one line `raven \
             relay schedule` prints"
        ));
    }
    Ok(raw)
}

/// When an allow-list entry stops admitting, as `raven relay allow
/// --schedule` and `raven relay status` say it.
fn expiry_text(expires_ms: Option<u64>, now_ms: u64) -> String {
    match expires_ms {
        None => String::new(),
        Some(at) if at < now_ms => "expired".into(),
        Some(at) => {
            let left = at - now_ms;
            if left >= 86_400_000 {
                format!("for {} more day(s)", left / 86_400_000)
            } else {
                format!("for {} more hour(s)", left.div_ceil(3_600_000))
            }
        }
    }
}

/// [`cmd_relay_allow_schedule`] after reading the text: returns what to
/// print. Each entry expires 7 days after the latest end its epoch can have
/// ([`peer_rotation::latest_epoch_end_ms`]: a relay knows no friend's
/// phase).
pub(super) fn relay_allow_schedule_with(
    data_dir: &Path,
    text: &str,
    label: &str,
) -> Result<Vec<String>, String> {
    let entries =
        peer_rotation::parse_relay_schedule(text).map_err(|e| format!("--schedule: {e}"))?;
    let len = peer_rotation::epoch_len_s();
    let out = relay_allow::relay_allow_schedule(data_dir, label, &entries, |e| {
        peer_rotation::latest_epoch_end_ms(e, len)
    })?;
    let list = relay_allow::load_relay_allow(data_dir)?.unwrap_or_default();
    let now = now_ms();
    let mut lines: Vec<String> = entries
        .iter()
        .map(|(epoch, peer)| {
            let until =
                list.peers
                    .iter()
                    .find(|e| e.peer_id == *peer)
                    .map_or("expired".to_string(), |e| match e.expires_ms {
                        None => "allowed without expiry".to_string(),
                        at => expiry_text(at, now),
                    });
            format!("epoch {epoch}: {peer} {until}")
        })
        .collect();
    lines.push(format!(
        "{} PeerId(s) of a rotating friend: {} allowed, {} already allowed, {} expired already \
         ({})",
        entries.len(),
        out.added,
        out.already,
        out.past,
        relay_allow::relay_allow_path(data_dir).display()
    ));
    Ok(lines)
}

/// `raven relay allow --schedule <FILE|->`: allow a rotating friend's
/// PeerIds of the coming epochs (the line their `raven relay schedule`
/// prints), each until a week after its epoch, all or nothing.
pub(super) fn cmd_relay_allow_schedule(
    data_dir: &Path,
    source: &str,
    label: &str,
) -> Result<(), String> {
    let text = read_schedule_arg(source)?;
    for line in relay_allow_schedule_with(data_dir, &text, label)? {
        println!("{line}");
    }
    println!(
        "{C_DIM}ask your friend for a fresh `raven relay schedule` before the last one expires. \
         {ALLOW_PRIVACY_NOTE}{C_RESET}"
    );
    Ok(())
}

/// [`cmd_relay_deny`]; returns what to print. In a profile, a contact (by
/// name, or by the PeerId of one) also goes on the deny list: the friend
/// relay admits verified contacts by itself, so leaving the allow-list
/// alone would not turn them away. The deny entry names the contact, so
/// the friend relay turns away every PeerId it is known by (a rotating
/// contact's card `p2pn=` and scheduled epochs too, the coming ones
/// included: peer rotation spec §9). A dedicated relay folder only has the
/// allow-list.
pub(super) fn relay_deny_with(data_dir: &Path, who: &str) -> Result<String, String> {
    let (peer, name, pub_hex) = resolve_peer_id(data_dir, who)?;
    let contact = if relay_allow::is_relay_dir(data_dir) {
        None
    } else if !name.is_empty() {
        Some((name, pub_hex))
    } else {
        contact_with_peer(data_dir, &peer)
    };
    let outcome = match &contact {
        Some((_, key)) => relay_allow::relay_deny_contact(data_dir, &peer, key)?,
        None => relay_allow::relay_deny(data_dir, &peer, false)?,
    };
    let contact = contact.map(|(name, _)| name);
    Ok(match contact {
        Some(name) if outcome.denied || outcome.removed => format!(
            "denied {peer}: {name} is your contact, so they stay on the deny list; the relay \
             drops them within seconds"
        ),
        Some(name) => format!("{peer} ({name}) is denied already (nothing changed)"),
        None if outcome.removed => {
            format!("denied {peer}: a running relay ends its reservation within seconds")
        }
        None => format!("{peer} was not on the allow-list (nothing changed)"),
    })
}

pub(super) fn cmd_relay_deny(data_dir: &Path, who: &str) -> Result<(), String> {
    let said = relay_deny_with(data_dir, who)?;
    match said.strip_prefix("denied") {
        Some(rest) => println!("{C_GREEN}denied{C_RESET}{rest}"),
        None => println!("{C_DIM}{said}{C_RESET}"),
    }
    Ok(())
}

fn status_age(updated_at_ms: u64) -> String {
    let secs = now_ms().saturating_sub(updated_at_ms) / 1000;
    format!("{secs}s ago")
}

/// Whether a dedicated relay runs: it holds its folder's lock for its whole
/// life, and rewrites its status at least every 10 s (a heartbeat).
pub(super) fn relay_state_line(running: bool, updated_at_ms: u64, now: u64) -> String {
    let age = now.saturating_sub(updated_at_ms) / 1000;
    match (
        running,
        now.saturating_sub(updated_at_ms) > relay_allow::RELAY_STATUS_STALE_MS,
    ) {
        (false, _) => format!(
            "not running (last status {age}s ago; start it: raven-node relay --data-dir <this \
             folder>)"
        ),
        (true, false) => "running".into(),
        (true, true) => {
            format!("running but its status is {age}s old (stuck?): check its log, or restart it")
        }
    }
}

fn counts_line(c: &RelayCounts) -> String {
    format!(
        "reservations={} circuits={} refused_reservations={} refused_circuits={} \
         refused_connections={}",
        c.reservations,
        c.circuits,
        c.reservations_refused,
        c.circuits_refused,
        c.connections_refused
    )
}

/// A section header of `raven relay status`.
fn relay_section(title: &str) {
    let col = c();
    println!();
    println!(
        "{}{title} \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}",
        col.bold, col.reset
    );
}

/// A profile's friend relay folder (`<profile>/friend_relay/`): the
/// profile it belongs to.
fn friend_relay_profile(data_dir: &Path) -> Option<&Path> {
    if data_dir.file_name()? == FRIEND_RELAY_DIR && relay_allow::is_relay_dir(data_dir) {
        data_dir.parent()
    } else {
        None
    }
}

/// One allow or deny list entry: its PeerId and the operator's note.
fn allow_entry_row(e: &relay_allow::RelayAllowEntry) -> String {
    format!(
        "{}{}{}",
        e.peer_id,
        if e.label.is_empty() {
            String::new()
        } else {
            format!("  ({})", sanitize_terminal_line(&e.label))
        },
        match e.expires_ms {
            None => String::new(),
            at => format!("  [{}]", expiry_text(at, now_ms())),
        }
    )
}

/// The `allow_list` rows (each PeerId on a row of its own) and, for a
/// profile's friend relay (`friend`), the `deny_list` rows: who the friend
/// relay never admits, although they are contacts.
///
/// The list kept by hand is the only way into a dedicated relay
/// (`raven-node relay`): empty, nobody may reserve. The friend relay admits
/// the verified contacts by themselves (`members` in FRIEND RELAY), and the
/// list kept by hand only adds to them: empty, it says so and nothing more
/// (field test E2 r7: "nobody may reserve" beside one verified member).
pub(super) fn allow_list_rows(
    allow: &Result<Option<RelayAllowList>, String>,
    friend: bool,
) -> Vec<(String, String)> {
    let empty = if friend {
        "none added by hand (your verified contacts are members)"
    } else {
        "none yet: nobody may reserve (raven relay allow …)"
    };
    let mut rows = Vec::new();
    match allow {
        Ok(None) => {
            rows.push(("allow_list".to_string(), empty.to_string()));
            if friend {
                rows.push(("deny_list".to_string(), "none".to_string()));
            }
        }
        Ok(Some(list)) => {
            rows.push((
                "allow_list".to_string(),
                match list.peers.len() {
                    0 => empty.to_string(),
                    n if friend => format!("{n} peer(s) added by hand"),
                    n => format!("{n} peer(s)"),
                },
            ));
            rows.extend(
                list.peers
                    .iter()
                    .map(|e| (String::new(), allow_entry_row(e))),
            );
            if friend {
                rows.push((
                    "deny_list".to_string(),
                    if list.deny.is_empty() {
                        "none".to_string()
                    } else {
                        format!("{} peer(s)", list.deny.len())
                    },
                ));
                rows.extend(
                    list.deny
                        .iter()
                        .map(|e| (String::new(), allow_entry_row(e))),
                );
            }
        }
        Err(e) => rows.push((
            "allow_list".to_string(),
            format!(
                "UNREADABLE: nobody may reserve until it is fixed ({})",
                sanitize_terminal_line(e)
            ),
        )),
    }
    rows
}

/// The friend relay's `state` in words.
fn friend_state_text(fr: &FriendRelayInfo) -> String {
    match fr.state.as_str() {
        "up" => "running".to_string(),
        "starting" => "starting".to_string(),
        "failed" => format!(
            "NOT running \u{2014} port {} could not be opened (another program?); retrying",
            fr.port
        ),
        "held" => "held: relaying is off in this build (FRIEND_RELAY_HOLD)".to_string(),
        "hidden" => "stopped: you hide your IP from every contact, and the relay would show it \
                     to them (`raven node hide-ip off` to relay again)"
            .to_string(),
        other => sanitize_terminal_line(other),
    }
}

/// Whether contacts outside this network have reached the friend relay;
/// with no route to the internet (`no_route`, W0) no advice.
fn friend_reachable_text(fr: &FriendRelayInfo, no_route: bool) -> String {
    match fr.reachable.as_str() {
        "unconfirmed" | "no_address" if no_route => format!("not now: {NO_ROUTE_RELAY}"),
        "confirmed" => match fr.confirmed_age_s {
            Some(age) => format!(
                "yes: a contact reached it from the internet {} ago",
                age_text(age)
            ),
            None => "yes: your router forwards its port (UPnP)".to_string(),
        },
        "unconfirmed" if fr.offering => format!(
            "not yet: no contact has reached it from the internet (forward TCP and UDP {} on \
             your router, or turn on UPnP: `raven node upnp on`)",
            fr.port
        ),
        "unconfirmed" | "no_address" => not_offered_text(fr),
        other => sanitize_terminal_line(other),
    }
}

/// The friend relay's ports: TCP 443 as the running relay reported it
/// (`port_443_open`), so a 443 it was asked for but may not open is not
/// shown as open; an older raven-node reports nothing, and then only what
/// was asked for is shown.
fn friend_port_text(fr: &FriendRelayInfo) -> String {
    let extra = match (fr.also_443 && fr.port != 443, fr.port_443_open) {
        (false, _) => "",
        (true, Some(false)) => {
            "; TCP 443 was asked for but is not open: this user may not open it (Linux: \
             CAP_NET_BIND_SERVICE, or net.ipv4.ip_unprivileged_port_start=443)"
        }
        (true, _) => ", and TCP 443",
    };
    format!("{} TCP and UDP{extra}", fr.port)
}

/// The FRIEND RELAY rows of `raven relay status` on a profile: the relay
/// with its own key, as the running raven-node reports it, else the saved
/// consent (`offer`). `verified`: the verified contacts it admits by itself
/// (from the contact book; `None` when it cannot be read).
pub(super) fn friend_relay_rows(
    daemon: &Result<IpcResponse, String>,
    offer: Option<bool>,
    verified: Option<u32>,
) -> Vec<(String, String)> {
    let row = |k: &str, v: String| (k.to_string(), v);
    let Some(fr) = friend_relay_of(daemon).filter(|f| f.state != "off") else {
        let answers = matches!(daemon, Ok(IpcResponse::Status { .. }));
        let state = match offer {
            None => format!(
                "off (`{OFFER_CMD}` lets your verified contacts relay through this computer)"
            ),
            Some(false) => format!("off (you said no; `{OFFER_CMD}` to change)"),
            Some(true) if answers => "on in node_policy.json, but the running raven-node does not \
                                      relay for your contacts (an older raven-node?)"
                .to_string(),
            Some(true) => "on in node_policy.json; raven-node is not running".to_string(),
        };
        return vec![row("state", state)];
    };
    let mut rows = vec![row("state", friend_state_text(fr))];
    if matches!(fr.state.as_str(), "held" | "hidden") {
        return rows;
    }
    rows.push(row(
        "relay key",
        "its own (not your Raven identity)".to_string(),
    ));
    rows.push(row("port", friend_port_text(fr)));
    if fr.state != "up" {
        return rows;
    }
    let contacts = match verified {
        Some(n) => format!("{} + ", verified_contacts(n)),
        None => "contacts unreadable + ".to_string(),
    };
    rows.push(row(
        "members",
        format!(
            "{} ({contacts}{} by hand \u{2212} {} denied)",
            fr.members, fr.manual, fr.denied
        ),
    ));
    rows.push(row("counts", counts_line(&fr.counts)));
    rows.push(row(
        "reachable",
        friend_reachable_text(fr, no_route(daemon)),
    ));
    rows.push(row("offered to", contacts_word(fr.offered_to)));
    rows
}

/// The RELAYS YOU USE rows of `raven relay status` on a profile: one per
/// relay slot of the running host ([`relay_rows`]: a contact's relay by
/// their name), automatic relay choice, and the spare relays.
pub(super) fn relays_you_use_rows(
    daemon: &Result<IpcResponse, String>,
    contacts: &[Contact],
) -> Vec<(String, String)> {
    let row = |k: &str, v: String| (k.to_string(), v);
    let Some(info) = p2p_info(daemon) else {
        let why = if matches!(daemon, Ok(IpcResponse::Status { .. })) {
            "none: the libp2p host is not running (`raven status` says why)"
        } else {
            "none: raven-node is not running"
        };
        return vec![row("relays", why.to_string())];
    };
    let mut rows = relay_rows(info, contacts);
    if rows.is_empty() {
        rows.push(row(
            "relays",
            "none (`raven relay use …` for one a friend runs)".to_string(),
        ));
    }
    if info.relay_auto || info.friend_relay.is_some() {
        rows.push(row(
            "auto",
            if info.relay_auto {
                "on: relays your verified contacts offer are used by themselves (`raven relay \
                 auto off` to stop)"
            } else {
                "off: only the relays you set are used (`raven relay auto on`)"
            }
            .to_string(),
        ));
    }
    if let Some(spare) = spare_relays_row(info) {
        rows.push(row("spare", spare));
    }
    rows
}

/// The verified contacts the friend relay admits by itself (book PeerIds
/// and proven learned ones); `None` when the contact book or the block list
/// cannot be read.
fn verified_member_count(data_dir: &Path) -> Option<u32> {
    raven_core::outbox::p2p_gate_peers(data_dir)
        .ok()
        .map(|peers| u32::try_from(peers.iter().filter(|p| p.proven).count()).unwrap_or(u32::MAX))
}

/// `raven relay status`: on a profile, its friend relay (its own key), the
/// relays it uses and its allow and deny lists; in a dedicated relay folder,
/// who may reserve and what the relay does (counts).
pub(super) fn cmd_relay_status(data_dir: &Path) -> Result<(), String> {
    if let Some(profile) = friend_relay_profile(data_dir) {
        println!(
            "this is the relay of the profile in {}: run `raven relay status` there",
            profile.display()
        );
        return Ok(());
    }
    if !relay_allow::is_relay_dir(data_dir) {
        return profile_relay_status(data_dir);
    }
    relay_section("RELAY");
    kv(
        "folder",
        &format!("{} (dedicated relay: raven-node relay)", data_dir.display()),
    );
    for (k, v) in allow_list_rows(&relay_allow::load_relay_allow(data_dir), false) {
        kv(&k, &v);
    }
    let running = relay_allow::relay_is_running(data_dir);
    match relay_allow::load_relay_status(data_dir)? {
        Some(st) => {
            kv(
                "state",
                &relay_state_line(running, st.updated_at_ms, now_ms()),
            );
            kv("peer_id", &sanitize_terminal_line(&st.peer_id));
            kv(
                "listen",
                &st.listen_addrs
                    .iter()
                    .map(|a| sanitize_terminal_line(a))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            kv(
                "counts",
                &format!(
                    "{} (updated {})",
                    counts_line(&st.counts),
                    status_age(st.updated_at_ms)
                ),
            );
        }
        None => kv(
            "state",
            "the relay has not run here yet: raven-node relay --data-dir <this folder>",
        ),
    }
    Ok(())
}

/// `raven relay status` on a profile: FRIEND RELAY, RELAYS YOU USE, and the
/// allow and deny lists.
fn profile_relay_status(data_dir: &Path) -> Result<(), String> {
    let daemon = daemon_status(data_dir);
    let offer = try_load_policy(data_dir).ok().and_then(|p| p.relay_offer);
    relay_section("FRIEND RELAY");
    kv(
        "folder",
        &format!(
            "{} (profile: its friend relay keeps its own key in {FRIEND_RELAY_DIR}/)",
            data_dir.display()
        ),
    );
    for (k, v) in friend_relay_rows(&daemon, offer, verified_member_count(data_dir)) {
        kv(&k, &v);
    }
    if let Some(counts) = p2p_info(&daemon).and_then(|i| i.relay.as_ref()) {
        kv("profile relay", &relay_row(counts));
    }
    relay_section("RELAYS YOU USE");
    let contacts = load_contacts(data_dir).unwrap_or_default();
    for (k, v) in relays_you_use_rows(&daemon, &contacts) {
        kv(&k, &v);
    }
    relay_section("ALLOW AND DENY");
    for (k, v) in allow_list_rows(&relay_allow::load_relay_allow(data_dir), true) {
        kv(&k, &v);
    }
    Ok(())
}

/// What `raven relay card` reads: the relay's PeerId, the addresses it
/// names for itself (`relay_status.json` `advertised`) and its listen
/// addresses. On a profile that is its friend relay's (`friend_relay/`,
/// its own key), never the profile's PeerId.
#[derive(Clone)]
struct CardSource {
    peer_id: String,
    advertised: Vec<String>,
    listen: Vec<String>,
    /// The ports a router or firewall maps from another public port
    /// (`--also-tcp LOCAL:PUBLIC`, the kit's 7443:443).
    extra_tcp: Vec<p2p_route::ExtraTcp>,
    /// A profile's friend relay (not a dedicated relay folder).
    friend: bool,
}

impl CardSource {
    fn read(data_dir: &Path) -> Result<Self, String> {
        if relay_allow::is_relay_dir(data_dir) {
            let st = relay_allow::load_relay_status(data_dir)?.ok_or(
                "start the relay once first (raven-node relay --data-dir <this folder>): its \
                 PeerId is in relay_status.json",
            )?;
            return Ok(Self {
                peer_id: st.peer_id,
                advertised: st.advertised,
                listen: st.listen_addrs,
                extra_tcp: st.extra_tcp,
                friend: false,
            });
        }
        // A profile: only that it is one is checked; its own PeerId is
        // never a relay's.
        try_load_identity(data_dir)?
            .ok_or("no identity here: this is neither a relay folder nor a profile")?;
        let offer = try_load_policy(data_dir).ok().and_then(|p| p.relay_offer);
        Self::friend_relay(data_dir, &daemon_status(data_dir), offer)
    }

    /// A profile's card: its friend relay's, from `friend_relay/`'s
    /// `relay_status.json`, while relaying is on (the running raven-node
    /// reports it; with none answering, the saved consent `offer`).
    fn friend_relay(
        data_dir: &Path,
        daemon: &Result<IpcResponse, String>,
        offer: Option<bool>,
    ) -> Result<Self, String> {
        let fr = friend_relay_of(daemon);
        if fr.is_some_and(|f| f.state == "held") {
            return Err("relaying is off in this build (FRIEND_RELAY_HOLD): \
                 there is no relay to give out"
                .into());
        }
        if fr.is_some_and(|f| f.state == "hidden") {
            return Err(
                "you hide your IP from every contact, so the relay is stopped: there is no \
                 relay to give out (`raven node hide-ip off` first)"
                    .into(),
            );
        }
        let on = fr.map_or(offer == Some(true), |f| f.state != "off");
        if !on {
            return Err(format!("relaying is off: `{OFFER_CMD}` first"));
        }
        let st = relay_allow::load_relay_status(&relay_allow::friend_relay_dir(data_dir))?.ok_or(
            "the friend relay has not started yet: raven-node starts it within a few seconds \
                 (`raven relay status` shows it)",
        )?;
        Ok(Self {
            peer_id: st.peer_id,
            advertised: st.advertised,
            listen: st.listen_addrs,
            extra_tcp: st.extra_tcp,
            friend: true,
        })
    }

    /// The port a card names when the relay names none.
    fn default_port(&self) -> u16 {
        if self.friend {
            FRIEND_RELAY_PORT
        } else {
            DEFAULT_P2P_PORT
        }
    }

    /// A transport as friends reach it at a public host: a TCP port a
    /// router or firewall maps from another port names that public port.
    fn public_transport(&self, (quic, port): (bool, u16)) -> (bool, u16) {
        let mapped = self
            .extra_tcp
            .iter()
            .find(|e| !quic && e.local == port)
            .map_or(port, |e| e.public);
        (quic, mapped)
    }

    /// The addresses the card is made from: the advertised ones, else the
    /// listen addresses.
    fn named(&self) -> &[String] {
        if self.advertised.is_empty() {
            &self.listen
        } else {
            &self.advertised
        }
    }

    /// A named address as friends reach it: one of this box's own listen
    /// addresses at a globally routable IP (a VPS's interface holds its
    /// public IP), on a TCP port a router or firewall maps from another
    /// public port, names that public port, as `--host` and `--public-host`
    /// do ([`Self::public_transport`]: the kit's 7443 mode, where friends
    /// reach 443). Any other address is kept as it is: a LAN friend reaches
    /// the local port itself, and an address the relay was told to name
    /// (`--public-host`, UPnP) is already the public one.
    fn reached_at(&self, addr: &str) -> String {
        let addr = addr.trim();
        let Some((false, port)) = card_transport(addr) else {
            return addr.to_string();
        };
        let own_global = self.listen.iter().any(|l| l.trim() == addr)
            && card_ip(addr).is_some_and(p2p_route::is_global_ip);
        let (_, public) = self.public_transport((false, port));
        if !own_global || public == port {
            return addr.to_string();
        }
        let rest: Vec<&str> = addr.split('/').skip(5).collect();
        let mut out = format!("{}/tcp/{public}", card_host(addr));
        for part in rest {
            out.push('/');
            out.push_str(part);
        }
        out
    }
}

/// A relay listen address of its `--wss` listener (`…/tcp/P/tls/ws`, RWS1
/// §6): the WSS form; its raw sibling is listed beside it.
fn is_wss_listen(addr: &str) -> bool {
    addr.trim()
        .split('/')
        .any(|p| matches!(p, "tls" | "ws" | "wss" | "sni"))
}

/// `raven relay card --wss`'s `via=` lines (canonical, without `via=`; RWS1
/// §2). With `host`: `{host}/tcp/{port}/tls/ws/p2p/R`, a name as
/// `/dns/<name>`, which is also the name TLS asks for (RWS1 §4); the port is
/// `wss_port`, else the relay's own WSS port as friends reach it
/// ([`CardSource::public_transport`]), else 443. Without `host`: the
/// relay's `/tls/ws` listen addresses as friends reach them
/// ([`CardSource::reached_at`], on `wss_port` when given); the raw sibling
/// of a WSS port is not repeated, and a wildcard is never one. Every line
/// passes the via grammar.
fn relay_card_wss_lines(
    src: &CardSource,
    host: Option<&str>,
    wss_port: Option<u16>,
) -> Result<Vec<String>, String> {
    let peer_id = &src.peer_id;
    // The raw sibling of each WSS listen address: host and TCP port.
    let wss_listen: Vec<(String, u16)> = src
        .listen
        .iter()
        .filter_map(|a| {
            let raw = a.trim().strip_suffix("/tls/ws")?;
            match card_transport(raw) {
                Some((false, port)) if !names_a_peer(raw) => Some((raw.to_string(), port)),
                _ => None,
            }
        })
        .collect();
    let mut lines: Vec<String> = Vec::new();
    match host {
        Some(h) => {
            let base = p2p_route::host_prefix(h)?;
            let port = wss_port
                .or_else(|| {
                    wss_listen
                        .first()
                        .map(|(_, p)| src.public_transport((false, *p)).1)
                })
                .unwrap_or(443);
            lines.push(format!("{base}/tcp/{port}/tls/ws/p2p/{peer_id}"));
        }
        None => {
            for (raw, _) in &wss_listen {
                if raw.starts_with("/ip4/0.0.0.0/") || raw.starts_with("/ip6/::/") {
                    continue;
                }
                let reached = match wss_port {
                    Some(p) => format!("{}/tcp/{p}", card_host(raw)),
                    None => src.reached_at(raw),
                };
                lines.push(format!("{reached}/tls/ws/p2p/{peer_id}"));
            }
        }
    }
    let mut valid = Vec::new();
    for l in lines {
        if let Ok(v) = p2p_route::parse_via(&l) {
            if v.is_wss() && !valid.contains(&v.text) {
                valid.push(v.text);
            }
        }
    }
    Ok(valid)
}

/// `raven relay card --wss` for a friend relay: it has no WSS listener.
const RELAY_CARD_WSS_FRIEND: &str = "a friend relay does not listen on WebSocket/TLS: only a \
    dedicated relay does (`raven-node relay --wss 443`); `raven relay card` prints this relay's \
    lines";

/// `raven relay card --wss [--host H] [--wss-port P]`: the WebSocket/TLS
/// line(s) friends on a network that lets only web traffic out need
/// (stdout, as `via=` lines; [`relay_card_wss_lines`]), and on stderr the
/// `raven relay use …` line to give each friend. Refused with WSS_HOLD
/// while WSS is lab-only in this build, and for a friend relay.
pub(super) fn cmd_relay_card_wss(
    data_dir: &Path,
    host: Option<&str>,
    wss_port: Option<u16>,
) -> Result<(), String> {
    if !raven_core::wss_live_enabled() {
        return Err(raven_core::WSS_HOLD.into());
    }
    let src = CardSource::read(data_dir)?;
    if src.friend {
        return Err(RELAY_CARD_WSS_FRIEND.into());
    }
    let valid = relay_card_wss_lines(&src, host, wss_port)?;
    if valid.is_empty() {
        return Err(
            "no WebSocket/TLS address to give out yet: start the relay with --wss (e.g. \
             `raven-node relay --wss 443 …`), or pass the address friends reach it at, e.g. \
             `raven relay card --wss --host relay.example.org`"
                .into(),
        );
    }
    for v in &valid {
        println!("via={v}");
    }
    let pair: Vec<String> = relay_use_lines(&valid, host.is_some())
        .iter()
        .map(|v| format!("via={v}"))
        .collect();
    if pair.is_empty() {
        eprintln!(
            "No `raven relay use` line to give out: every address above is on this computer or \
             its local network, which friends elsewhere cannot reach. Run `raven relay card \
             --wss --host <the public IP or DNS name friends reach this relay at>`."
        );
        return Ok(());
    }
    eprintln!(
        "Give each friend whose network lets only web traffic out this line (they run it once):"
    );
    eprintln!("  raven relay use {}", pair.join(" "));
    eprintln!(
        "{C_DIM}The same port also takes plain libp2p, so their Raven can try both. A DNS name \
         (--host relay.example.org) is also the name TLS asks for; Raven checks the relay's \
         PeerId, not its certificate. Allow every such friend on the relay as before (raven \
         relay allow --card …).{C_RESET}"
    );
    Ok(())
}

/// The IP of a route text whose host is an IP literal (`/ip4/…`, `/ip6/…`).
fn card_ip(addr: &str) -> Option<std::net::IpAddr> {
    let parts: Vec<&str> = addr.trim().split('/').collect();
    match parts.get(1) {
        Some(&"ip4") | Some(&"ip6") => parts.get(2)?.parse().ok(),
        _ => None,
    }
}

/// A card line a friend elsewhere can reach: a DNS name, or a globally
/// routable IP (never loopback or a local network's).
fn reachable_elsewhere(line: &str) -> bool {
    card_ip(line).is_none_or(p2p_route::is_global_ip)
}

/// The transport of a route text (`/<kind>/<host>/tcp/PORT…` or
/// `/<kind>/<host>/udp/PORT/quic-v1…`): whether it is QUIC, and its port.
fn card_transport(addr: &str) -> Option<(bool, u16)> {
    let parts: Vec<&str> = addr.trim().split('/').collect();
    let port = parts.get(4)?.parse::<u16>().ok().filter(|p| *p != 0)?;
    match (parts.get(3), parts.get(5)) {
        (Some(&"tcp"), _) => Some((false, port)),
        (Some(&"udp"), Some(&"quic-v1")) => Some((true, port)),
        _ => None,
    }
}

/// A circuit, or an address that already names a PeerId: not a relay's
/// own address.
fn names_a_peer(addr: &str) -> bool {
    addr.split('/').any(|p| p == "p2p" || p == "p2p-circuit")
}

/// The host part of a route text (`/ip4/203.0.113.7`).
fn card_host(addr: &str) -> String {
    addr.trim().split('/').take(3).collect::<Vec<_>>().join("/")
}

/// `raven relay card`'s order: TCP on the main port (the one QUIC listens
/// on too, else the first TCP port), then TCP on the relay's other ports
/// (its 443 fallback), then QUIC; each kind in the order it was named.
fn order_card_lines(lines: Vec<String>) -> Vec<String> {
    let transports: Vec<(bool, u16)> = lines.iter().filter_map(|l| card_transport(l)).collect();
    let tcp = || transports.iter().filter(|(q, _)| !q).map(|(_, p)| *p);
    let main = tcp()
        .find(|p| transports.contains(&(true, *p)))
        .or_else(|| tcp().next());
    let mut ranked: Vec<(u8, String)> = lines
        .into_iter()
        .map(|l| {
            let rank = match card_transport(&l) {
                Some((false, p)) if Some(p) == main => 0,
                Some((false, _)) => 1,
                _ => 2,
            };
            (rank, l)
        })
        .collect();
    ranked.sort_by_key(|(rank, _)| *rank);
    ranked.into_iter().map(|(_, l)| l).collect()
}

/// The lines a friend gives `raven relay use`: the first of the card (TCP
/// on the main port) and, when the relay has one, TCP on another port (its
/// 443 fallback), on the same host when there is one.
fn relay_use_pair(ordered: &[String]) -> Vec<String> {
    let Some(first) = ordered.first() else {
        return Vec::new();
    };
    let main = card_transport(first);
    let other_tcp = |l: &&String| matches!((card_transport(l), main), (Some((false, p)), Some((false, m))) if p != m);
    let host = card_host(first);
    let fallback = ordered
        .iter()
        .filter(other_tcp)
        .find(|l| card_host(l) == host)
        .or_else(|| ordered.iter().find(other_tcp));
    std::iter::once(first).chain(fallback).cloned().collect()
}

/// `raven relay card`'s `via=` lines (canonical, without `via=`).
///
/// An explicit `port` keeps the output from before the relay kit exactly
/// (`wan_two_network_test.sh vps-relay`): TCP on `port` at `host` (and QUIC
/// with `quic`), or without `host` the TCP listen addresses (and QUIC ones
/// with `quic`). Otherwise the card is made from the relay's advertised
/// addresses, else its listen addresses, QUIC included whenever they name
/// it; `host` replaces their host and keeps each transport and port (TCP
/// 7423, and QUIC with `quic`, when they name none), except that a TCP
/// port a router or firewall maps from a public port
/// ([`CardSource::public_transport`]: the kit's 7443:443) names the public
/// one. Without `host` the same holds for the box's own global listen
/// addresses ([`CardSource::reached_at`]). Those lines are in
/// [`order_card_lines`] order. A `--wss` listener's `/tls/ws` listen forms
/// are never among them: `raven relay card --wss` prints those
/// ([`relay_card_wss_lines`]).
fn relay_card_lines(
    src: &CardSource,
    host: Option<&str>,
    port: Option<u16>,
    quic: bool,
) -> Result<Vec<String>, String> {
    let peer_id = &src.peer_id;
    let mut lines: Vec<String> = Vec::new();
    match (host, port) {
        (Some(h), Some(port)) => {
            let base = p2p_route::host_prefix(h)?;
            lines.push(format!("{base}/tcp/{port}/p2p/{peer_id}"));
            if quic {
                lines.push(format!("{base}/udp/{port}/quic-v1/p2p/{peer_id}"));
            }
        }
        (None, Some(_)) => {
            // A `--wss` listener's `/tls/ws` form is `--wss`'s line
            // ([`relay_card_wss_lines`]): its raw sibling is listed too.
            for a in src.listen.iter().filter(|a| !is_wss_listen(a)) {
                let a = a.trim();
                let tcp = a.contains("/tcp/") && !a.contains("/p2p-circuit");
                let q = quic && a.contains("/quic-v1") && !a.contains("/p2p-circuit");
                if (tcp || q)
                    && !a.starts_with("/ip4/0.0.0.0")
                    && !a.starts_with("/ip6/::/")
                    && !a.contains("/p2p/")
                {
                    lines.push(format!("{a}/p2p/{peer_id}"));
                }
            }
        }
        (Some(h), None) => {
            let base = p2p_route::host_prefix(h)?;
            let mut transports: Vec<(bool, u16)> = Vec::new();
            for a in src.named() {
                if let Some(t) = card_transport(a).filter(|_| !names_a_peer(a)) {
                    let t = src.public_transport(t);
                    if !transports.contains(&t) {
                        transports.push(t);
                    }
                }
            }
            if transports.is_empty() {
                transports.push((false, src.default_port()));
                if quic {
                    transports.push((true, src.default_port()));
                }
            }
            for (q, p) in transports {
                lines.push(if q {
                    format!("{base}/udp/{p}/quic-v1/p2p/{peer_id}")
                } else {
                    format!("{base}/tcp/{p}/p2p/{peer_id}")
                });
            }
        }
        (None, None) => {
            for a in src.named() {
                let a = a.trim();
                if card_transport(a).is_some() && !names_a_peer(a) && !is_wss_listen(a) {
                    lines.push(format!("{}/p2p/{peer_id}", src.reached_at(a)));
                }
            }
        }
    }
    let mut valid = Vec::new();
    for l in lines {
        if let Ok(v) = p2p_route::parse_via(&l) {
            if !valid.contains(&v.text) {
                valid.push(v.text);
            }
        }
    }
    Ok(if port.is_some() {
        valid
    } else {
        order_card_lines(valid)
    })
}

/// The lines of the `raven relay use …` command to give friends
/// ([`relay_use_pair`]). Without `--host` (`named_host` false) only lines a
/// friend elsewhere can reach count ([`reachable_elsewhere`]): a loopback
/// or LAN address is never the line to give, and with no other one there
/// is none (empty). An address named with `--host` is the operator's.
fn relay_use_lines(card: &[String], named_host: bool) -> Vec<String> {
    let reachable: Vec<String> = card
        .iter()
        .filter(|l| named_host || reachable_elsewhere(l))
        .cloned()
        .collect();
    relay_use_pair(&reachable)
}

/// Said instead of a `raven relay use …` line when every address of the
/// card is on this computer or its local network.
fn no_use_line_text(port: u16) -> String {
    format!(
        "No `raven relay use` line to give out: every address above is on this computer or \
         its local network, which friends elsewhere cannot reach. Run `raven relay card --host \
         <the public IP or DNS name friends reach this relay at>` (with the relay kit: `sudo \
         raven-relay card --host …`; behind a router: its public IP, with port {port} \
         forwarded)."
    )
}

/// `raven relay card`: the `via=` line(s) friends need to use this relay
/// (stdout), and on stderr the one `raven relay use …` command to give
/// each friend ([`relay_use_lines`]: never a loopback or LAN address
/// without `--host`).
pub(super) fn cmd_relay_card(
    data_dir: &Path,
    host: Option<&str>,
    port: Option<u16>,
    quic: bool,
) -> Result<(), String> {
    let src = CardSource::read(data_dir)?;
    let valid = relay_card_lines(&src, host, port, quic)?;
    if valid.is_empty() {
        let port = port.unwrap_or(src.default_port());
        let name_it = if src.friend {
            format!("or name it with `{OFFER_CMD} --external /ip4/203.0.113.7/tcp/{port}`")
        } else {
            "or start the relay with --public-host".to_string()
        };
        return Err(format!(
            "no address to give out yet: pass the address friends reach this relay at, e.g. \
             `raven relay card --host 203.0.113.7` (your public IP, a DNS name, or a forwarded \
             port's address; port {port}), {name_it}"
        ));
    }
    for v in &valid {
        println!("via={v}");
    }
    let pair: Vec<String> = relay_use_lines(&valid, host.is_some())
        .iter()
        .map(|v| format!("via={v}"))
        .collect();
    if pair.is_empty() {
        if src.friend {
            eprintln!(
                "Your verified contacts get this relay by themselves (route hints) at the \
                 addresses it offers."
            );
        }
        eprintln!("{}", no_use_line_text(port.unwrap_or(src.default_port())));
        return Ok(());
    }
    if src.friend {
        eprintln!(
            "Your verified contacts get this relay by themselves (route hints). A contact whose \
             Raven does not pick relays by itself runs once:"
        );
        eprintln!("  raven relay use {}", pair.join(" "));
        eprintln!(
            "{C_DIM}This relay has its own key (not your Raven identity) and serves only your \
             verified contacts and the peers you allowed (raven relay allow …). A loopback or LAN \
             address works only for friends on this computer or network.{C_RESET}"
        );
        return Ok(());
    }
    eprintln!("Give each friend this line (they run it once):");
    eprintln!("  raven relay use {}", pair.join(" "));
    eprintln!(
        "{C_DIM}The relay serves circuits only between people you allowed: allow EVERY friend \
         who should be reachable through it or send through it (raven relay allow --card …; with \
         the relay kit: raven-relay allow --card …). A loopback or LAN address works only for \
         friends on this computer or network.{C_RESET}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::ipc::IPC_VERSION;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Owner decision Q8: asked once, only on a terminal; Enter or EOF is off;
    /// the flags skip the question; an answer saved before is never asked
    /// again; non-interactive runs stay unset.
    #[test]
    fn upnp_is_asked_once_only_on_a_terminal() {
        let never = |_: u16| -> Option<String> { panic!("must not ask") };
        // Flags decide without asking, on a terminal or not.
        assert_eq!(
            upnp_decision(None, Some(true), Some(7423), true, never),
            (Some(true), false)
        );
        assert_eq!(
            upnp_decision(None, Some(false), Some(7423), true, never),
            (Some(false), false)
        );
        assert_eq!(
            upnp_decision(Some(false), Some(true), Some(7423), false, never),
            (Some(true), false)
        );
        // Saved answers are kept: never asked again.
        assert_eq!(
            upnp_decision(Some(true), None, Some(7423), true, never),
            (Some(true), false)
        );
        assert_eq!(
            upnp_decision(Some(false), None, Some(7423), true, never),
            (Some(false), false)
        );
        // Not a terminal: no prompt, stays unset.
        assert_eq!(
            upnp_decision(None, None, Some(7423), false, never),
            (None, false)
        );
        // No port to open: nothing to ask.
        assert_eq!(upnp_decision(None, None, None, true, never), (None, false));
        // On a terminal: y / yes is on; Enter, EOF and anything else are off.
        for (answer, want) in [
            (Some("y"), true),
            (Some(" YES "), true),
            (Some(""), false),
            (None, false),
            (Some("n"), false),
            (Some("maybe"), false),
        ] {
            let mut asked_port = 0;
            let got = upnp_decision(None, None, Some(7999), true, |p| {
                asked_port = p;
                answer.map(String::from)
            });
            assert_eq!(got, (Some(want), true), "{answer:?}");
            assert_eq!(asked_port, 7999);
        }
        // Phase 1's text while PORT_MAP is closed; the caller's lab switches
        // (RAVEN_LAB_TEST_A=1 RAVEN_LAB_PORT_MAP=1) pick the other one.
        assert_eq!(
            upnp_question(7423),
            upnp_question_for(7423, raven_core::port_map_live_enabled())
        );
        assert!(upnp_question_for(7423, false)
            .starts_with("Open TCP/UDP 7423 on your router automatically"));
        assert!(upnp_question(7423).ends_with("[y/N] "));
    }

    /// The installers ask the same one-time question as `raven node p2p on`
    /// and the install guides quote it: each copy is `upnp_question` with the
    /// port filled in. libp2p-upnp speaks UPnP-IGD only, so the question and
    /// the installers never name NAT-PMP (the guides say it is not supported).
    /// UPnP maps the p2p endpoint's port only: relaying for contacts has its
    /// own consent and port (owner decision 11), so no copy says it relays.
    #[test]
    fn the_upnp_question_is_the_same_everywhere_and_names_no_nat_pmp() {
        let question = upnp_question_for(7423, false);
        assert!(!question.contains("NAT-PMP"), "{question}");
        assert_eq!(
            question,
            "Open TCP/UDP 7423 on your router automatically (UPnP) so friends can reach this \
             node? [y/N] "
        );
        let want = question.trim_end();
        let node = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        // Each file and how it writes the port.
        for (file, port) in [
            ("scripts/install/macos_launchd.sh", "${P2P_PORT}"),
            ("scripts/install/linux_systemd_user.sh", "${P2P_PORT}"),
            ("scripts/install/windows_service.ps1", "$p2pPort"),
            ("../docs/INSTALL_macOS.md", "7423"),
            ("../docs/INSTALL_Linux.md", "7423"),
            ("../docs/INSTALL_Windows.md", "7423"),
        ] {
            let text =
                std::fs::read_to_string(node.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
            let asks: Vec<&str> = text
                .lines()
                .filter(|l| l.contains("on your router automatically"))
                .collect();
            assert_eq!(asks.len(), 1, "{file}: {asks:?}");
            assert!(
                asks[0].replace(port, "7423").contains(want),
                "{file}: {}",
                asks[0]
            );
            assert!(!asks[0].contains("relay for them"), "{file}: {}", asks[0]);
            if file.starts_with("scripts/") {
                assert!(!text.contains("NAT-PMP"), "{file}");
            }
        }
    }

    #[test]
    fn node_p2p_on_asks_once_saves_the_answer_and_round_trips() {
        let dir = tmp();
        let asked = std::cell::Cell::new(0);
        let ask = |_: u16| {
            asked.set(asked.get() + 1);
            None // EOF
        };
        let on = || P2pOnArgs {
            listen: "7423".into(),
            ..P2pOnArgs::default()
        };
        cmd_node_p2p_with(dir.path(), Some(on()), true, ask).unwrap();
        assert_eq!(asked.get(), 1);
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!(p.p2p_listen, "7423");
        assert_eq!(p.upnp, Some(false), "EOF saves off");
        // Never asked again.
        cmd_node_p2p_with(dir.path(), Some(on()), true, |_| -> Option<String> {
            panic!("asked twice")
        })
        .unwrap();
        // `raven node upnp on` changes it at any time; off keeps it.
        cmd_node_upnp(dir.path(), true).unwrap();
        cmd_node_p2p_with(dir.path(), None, true, |_| -> Option<String> {
            panic!("no")
        })
        .unwrap();
        let p = try_load_policy(dir.path()).unwrap();
        assert!(p.p2p_listen.is_empty());
        assert_eq!(p.upnp, Some(true));
        // A non-interactive first run leaves it unset (no prompt at all).
        let fresh = tmp();
        cmd_node_p2p_with(fresh.path(), Some(on()), false, |_| -> Option<String> {
            panic!("no prompt off a terminal")
        })
        .unwrap();
        assert_eq!(try_load_policy(fresh.path()).unwrap().upnp, None);
        // --no-upnp / --upnp skip the question.
        let flagged = tmp();
        cmd_node_p2p_with(
            flagged.path(),
            Some(P2pOnArgs {
                upnp: Some(true),
                ..on()
            }),
            true,
            |_| -> Option<String> { panic!("the flag skips the question") },
        )
        .unwrap();
        assert_eq!(try_load_policy(flagged.path()).unwrap().upnp, Some(true));
    }

    /// Phase 4 (P4.20): the UPnP question keeps Phase 1's text (which the
    /// installers and guides quote) while the PORT_MAP gate is closed; with
    /// it open the same consent names NAT-PMP and PCP too.
    #[test]
    fn upnp_question_keeps_phase1_text_while_port_map_gate_closed() {
        assert_eq!(
            upnp_question_for(7423, false),
            "Open TCP/UDP 7423 on your router automatically (UPnP) so friends can reach this \
             node? [y/N] "
        );
        if !raven_core::port_map_live_enabled() {
            assert_eq!(upnp_question(7423), upnp_question_for(7423, false));
        }
        assert_eq!(
            upnp_question_for(7999, true),
            "Let raven ask your router to open TCP/UDP 7999 automatically (UPnP, NAT-PMP or \
             PCP) so friends can reach this node? [y/N] "
        );
        assert_eq!(
            v6_pinhole_question(7423),
            "Also open 7423 in your router's IPv6 firewall for this computer (PCP)? [y/N] "
        );
    }

    /// Phase 4 (P4.20, O4-11): the IPv6 pinhole has its own ask-once
    /// question, asked only where its gate is open, after a yes to router
    /// port mapping, and only on a terminal; `raven node ipv6-pinhole
    /// on|off` changes it.
    #[test]
    fn v6_pinhole_is_asked_once_only_after_upnp_yes_and_only_on_a_terminal() {
        let never = |_: u16| -> Option<String> { panic!("asked") };
        let yes = |_: u16| Some("y".to_string());
        // The rules of the decision alone.
        assert_eq!(
            v6_pinhole_decision(None, Some(true), Some(7423), true, true, yes),
            (Some(true), true)
        );
        assert_eq!(
            v6_pinhole_decision(None, Some(true), Some(7423), true, true, |_| None),
            (Some(false), true)
        );
        for (saved, upnp, port, tty, live) in [
            (None, Some(true), Some(7423), true, false),
            (None, Some(false), Some(7423), true, true),
            (None, None, Some(7423), true, true),
            (None, Some(true), Some(7423), false, true),
            (None, Some(true), None, true, true),
            (Some(false), Some(true), Some(7423), true, true),
            (Some(true), Some(true), Some(7423), true, true),
        ] {
            assert_eq!(
                v6_pinhole_decision(saved, upnp, port, tty, live, never),
                (saved, false),
                "{saved:?} {upnp:?} {port:?} {tty} {live}"
            );
        }
        let on = || P2pOnArgs {
            listen: "7423".into(),
            ..P2pOnArgs::default()
        };
        // A UPnP no: the pinhole is not asked.
        let dir = tmp();
        cmd_node_p2p_asking(dir.path(), Some(on()), true, |_| None, Some(never)).unwrap();
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!((p.upnp, p.v6_pinhole), (Some(false), None));
        // A UPnP yes: asked once, after it, and saved.
        let dir = tmp();
        let order = std::cell::RefCell::new(Vec::new());
        cmd_node_p2p_asking(
            dir.path(),
            Some(on()),
            true,
            |port| {
                order.borrow_mut().push(("upnp", port));
                Some("yes".into())
            },
            Some(|port| {
                order.borrow_mut().push(("v6", port));
                Some("y".into())
            }),
        )
        .unwrap();
        assert_eq!(*order.borrow(), [("upnp", 7423), ("v6", 7423)]);
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!((p.upnp, p.v6_pinhole), (Some(true), Some(true)));
        // Never asked again; the gate closed (`None`) asks nothing either.
        cmd_node_p2p_asking(dir.path(), Some(on()), true, never, Some(never)).unwrap();
        cmd_node_p2p_with(dir.path(), Some(on()), true, never).unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap().v6_pinhole, Some(true));
        // Off a terminal: nothing is asked, and it stays unset.
        let fresh = tmp();
        cmd_node_p2p_asking(
            fresh.path(),
            Some(P2pOnArgs {
                upnp: Some(true),
                ..on()
            }),
            false,
            never,
            Some(never),
        )
        .unwrap();
        let p = try_load_policy(fresh.path()).unwrap();
        assert_eq!((p.upnp, p.v6_pinhole), (Some(true), None));
        // `raven node ipv6-pinhole on|off`, with the notes it needs.
        let lines = node_ipv6_pinhole_with(fresh.path(), true, false).unwrap();
        assert_eq!(
            try_load_policy(fresh.path()).unwrap().v6_pinhole,
            Some(true)
        );
        assert!(lines[0].contains("ipv6_pinhole=on"), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("V6_PINHOLE_HOLD:")),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("raven node upnp on")),
            "{lines:?}"
        );
        let lines = node_ipv6_pinhole_with(dir.path(), false, true).unwrap();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(try_load_policy(dir.path()).unwrap().v6_pinhole, Some(false));
        let no_upnp = tmp();
        let lines = node_ipv6_pinhole_with(no_upnp.path(), true, true).unwrap();
        assert!(
            lines.iter().any(|l| l.contains("(`raven node upnp on`)")),
            "{lines:?}"
        );
        assert_eq!(try_load_policy(no_upnp.path()).unwrap().upnp, None);
    }

    #[test]
    fn node_p2p_on_validates_relays_and_refuses_an_unreadable_policy() {
        let dir = tmp();
        let relay = p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[4; 32]));
        let good = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}");
        cmd_node_p2p_with(
            dir.path(),
            Some(P2pOnArgs {
                listen: "7423".into(),
                relay: vec![good.clone()],
                upnp: None,
            }),
            false,
            |_| -> Option<String> { panic!("no prompt off a terminal") },
        )
        .unwrap();
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!(p.p2p_listen, "7423");
        assert_eq!(p.p2p_relays, vec![good.clone()]);
        assert_eq!(p.upnp, None);
        for bad in [
            vec!["/ip4/198.51.100.7/tcp/7423".to_string()],
            vec![good.clone(), good.clone(), good.clone()],
        ] {
            assert!(cmd_node_p2p_with(
                dir.path(),
                Some(P2pOnArgs {
                    listen: "7423".into(),
                    relay: bad,
                    upnp: Some(false),
                }),
                false,
                |_| None,
            )
            .is_err());
        }
        std::fs::write(dir.path().join("node_policy.json"), b"{broken").unwrap();
        let err = cmd_node_upnp(dir.path(), true).unwrap_err();
        assert!(err.contains("nothing changed"), "{err}");
        assert_eq!(
            std::fs::read(dir.path().join("node_policy.json")).unwrap(),
            b"{broken"
        );
    }

    /// Privacy pack PP.6: in a sealed profile `raven node p2p on --relay`
    /// writes the relay addresses only to the sealed sidecar
    /// (node_policy_peers.rms, RMS1 kind 19); node_policy.json keeps the
    /// listen setting and names no relay, and every reader still sees them.
    #[test]
    fn node_p2p_on_relay_writes_to_the_sealed_sidecar() {
        let lab = ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(windows) || (cfg!(debug_assertions) && lab)) {
            eprintln!("skipped: needs a debug build and RAVEN_CHAT_HISTORY_BACKEND=locked-file");
            return;
        }
        let dir = tmp();
        let dd = dir.path();
        std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        let report = raven_core::privacy::migrate_all(
            dd,
            now_ms(),
            raven_core::at_rest::MigratePolicy::Allow,
        )
        .unwrap();
        assert_eq!(report.outcome, raven_core::privacy::MigrateOutcome::Sealed);
        let relay = p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[4; 32]));
        let good = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}");
        cmd_node_p2p_with(
            dd,
            Some(P2pOnArgs {
                listen: "7423".into(),
                relay: vec![good.clone()],
                upnp: Some(false),
            }),
            false,
            |_| -> Option<String> { panic!("no prompt off a terminal") },
        )
        .unwrap();
        let plain = std::fs::read_to_string(dd.join("node_policy.json")).unwrap();
        assert!(plain.contains(r#""p2p_listen": "7423""#), "{plain}");
        assert!(
            !plain.contains("p2p_relays") && !plain.contains(&relay),
            "{plain}"
        );
        let sidecar = std::fs::read(raven_core::node_policy::policy_peers_path(dd)).unwrap();
        assert!(raven_core::at_rest::is_sealed(&sidecar) && sidecar[5] == 19);
        let p = try_load_policy(dd).unwrap();
        assert_eq!((p.p2p_listen, p.p2p_relays), ("7423".into(), vec![good]));
        // `p2p off` keeps the relays, still only in the sidecar.
        cmd_node_p2p_with(dd, None, false, |_| None).unwrap();
        let p = try_load_policy(dd).unwrap();
        assert!(p.p2p_listen.is_empty() && p.p2p_relays.len() == 1);
        let plain = std::fs::read_to_string(dd.join("node_policy.json")).unwrap();
        assert!(!plain.contains("p2p_relays"), "{plain}");
    }

    /// Phase 1 item 2: `--listen relay` (no port: it could never
    /// hole-punch) is retired. It saves 7423 like `on`, says why, and the
    /// UPnP question then follows for 7423 on a terminal.
    #[test]
    fn node_p2p_on_listen_relay_saves_7423_and_says_why() {
        let note = relay_listen_retired_note();
        assert!(
            note.contains(
                "--listen relay is retired: it opened no port, so hole punching could \
                 never work. Saved 7423 (TCP and UDP, every interface) instead."
            ),
            "{note}"
        );
        if raven_core::p2p_relay_only_test_enabled() {
            // The debug test switch keeps the old no-listener mode.
            return;
        }
        let dir = tmp();
        cmd_node_p2p_with(
            dir.path(),
            Some(P2pOnArgs {
                listen: "relay".into(),
                ..P2pOnArgs::default()
            }),
            false,
            |_| -> Option<String> { panic!("no prompt off a terminal") },
        )
        .unwrap();
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!(p.p2p_listen, DEFAULT_P2P_PORT.to_string());
        assert_eq!(p.upnp, None);
        let asked = tmp();
        let mut port = None;
        cmd_node_p2p_with(
            asked.path(),
            Some(P2pOnArgs {
                listen: " RELAY ".into(),
                ..P2pOnArgs::default()
            }),
            true,
            |p| {
                port = Some(p);
                Some("n".into())
            },
        )
        .unwrap();
        assert_eq!(port, Some(DEFAULT_P2P_PORT));
        let p = try_load_policy(asked.path()).unwrap();
        assert_eq!((p.p2p_listen.as_str(), p.upnp), ("7423", Some(false)));
    }

    /// Phase 1 item 2: the reach row says when the service was given the
    /// retired `relay` (it listens on 7423 instead), and only then.
    #[test]
    fn status_says_relay_listen_is_retired() {
        let up = P2pStatusInfo {
            up: true,
            nat: "unknown".into(),
            listen_setting: "7423".into(),
            retired_listen: "relay".into(),
            source: "node_policy.json".into(),
            ..P2pStatusInfo::default()
        };
        let row = p2p_reach_row(&status(Some(up.clone())), "relay", true);
        assert!(
            row.starts_with("YES")
                && row.ends_with("; listen \"relay\" is retired: listening on 7423)"),
            "{row}"
        );
        let held = P2pStatusInfo {
            up: false,
            held: true,
            ..up.clone()
        };
        let row = p2p_reach_row(&status(Some(held)), "relay", true);
        assert!(
            row.contains(
                "configured (7423, from node_policy.json; listen \"relay\" is retired: it uses \
                 7423) but the p2p carrier is not enabled"
            ),
            "{row}"
        );
        let plain = P2pStatusInfo {
            retired_listen: String::new(),
            ..up
        };
        let row = p2p_reach_row(&status(Some(plain)), "7423", true);
        assert!(row.starts_with("YES") && !row.contains("retired"), "{row}");
    }

    fn status(p2p: Option<P2pStatusInfo>) -> Result<IpcResponse, String> {
        Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: true,
            store: true,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: p2p.map(Box::new),
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
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        })
    }

    #[test]
    fn status_p2p_row_says_yes_only_while_the_host_is_up() {
        let up = P2pStatusInfo {
            up: true,
            nat: "private".into(),
            reservations: vec!["x".into()],
            relays_configured: 2,
            upnp: "mapped 7423".into(),
            ..P2pStatusInfo::default()
        };
        assert!(p2p_reach_row(&status(Some(up.clone())), "7423", true).starts_with("YES"));
        assert!(p2p_reach_row(&status(Some(up.clone())), "7423", true).contains("reservations 1/2"));
        let down = P2pStatusInfo {
            up: false,
            listen_setting: "7423".into(),
            source: "node_policy.json".into(),
            ..up.clone()
        };
        assert!(p2p_reach_row(&status(Some(down)), "7423", true).starts_with("NO"));
        assert!(p2p_reach_row(&status(None), "", true).starts_with("off"));
        assert!(p2p_reach_row(&status(None), "7423", false).contains("P2P_HOLD"));
        assert!(p2p_reach_row(&status(None), "7423", true).contains("not up"));
        assert_eq!(
            upnp_row(&status(Some(up.clone())), Some(true)),
            "on \u{2014} the router forwards port 7423"
        );
        assert!(upnp_row(&status(None), None).starts_with("unset"));
        assert_eq!(upnp_row(&status(None), Some(false)), "off");
        let failed = P2pStatusInfo {
            upnp: "failed".into(),
            ..up
        };
        assert!(upnp_row(&status(Some(failed)), Some(true)).contains("failed"));
        let row = relay_row(&RelayCounts {
            allowed_peers: 2,
            reservations: 1,
            ..RelayCounts::default()
        });
        assert!(
            row.contains("2 allow-listed") && row.contains("YOUR PeerId"),
            "{row}"
        );
        // Every refusal counts, the peer gate's too.
        let row = relay_row(&RelayCounts {
            reservations_refused: 1,
            circuits_refused: 2,
            connections_refused: 4,
            ..RelayCounts::default()
        });
        assert!(row.contains("refused=7"), "{row}");
        let line = counts_line(&RelayCounts {
            connections_refused: 4,
            ..RelayCounts::default()
        });
        assert!(line.ends_with("refused_connections=4"), "{line}");
    }

    /// Phase 4 (P4.20): a raven-node that reports `port_map` (the PORT_MAP
    /// gate open) gets the `router mapping` and `IPv6 pinhole` rows in plain
    /// words; an older one (or the gate closed) keeps Phase 1's `upnp` row,
    /// which reads `mapped <port>` for PCP and NAT-PMP too.
    #[test]
    fn router_mapping_rows_in_plain_words_and_older_daemon_fallback() {
        let with = |v4: &str, port: u16, v6: &str| P2pStatusInfo {
            up: true,
            upnp: if port == 0 {
                "failed".into()
            } else {
                format!("mapped {port}")
            },
            port_map: Some(PortMapStatus {
                v4: v4.into(),
                v4_port: port,
                v6: v6.into(),
                ..PortMapStatus::default()
            }),
            ..P2pStatusInfo::default()
        };
        for (v4, port, v6, row, v6_row) in [
            (
                "pcp",
                7423,
                "open",
                "PCP, port 7423 open (TCP+UDP)",
                "open (PCP)",
            ),
            (
                "nat-pmp",
                41000,
                "not_asked",
                "NAT-PMP, port 41000 open (TCP+UDP)",
                "not asked",
            ),
            (
                "upnp",
                7423,
                "none",
                "UPnP, port 7423 open (TCP+UDP)",
                "none",
            ),
            ("none", 0, "none", "none found (UPnP, NAT-PMP, PCP)", "none"),
            (
                "behind_another_nat",
                0,
                "not_asked",
                "router is behind another NAT",
                "not asked",
            ),
            (
                "double_nat",
                0,
                "not_asked",
                "router is behind another router (double NAT)",
                "not asked",
            ),
            (
                "off_path",
                0,
                "not_asked",
                "not asked: internet traffic bypasses this router (a VPN?)",
                "not asked",
            ),
            (
                "off",
                0,
                "not_asked",
                "off (raven node upnp on)",
                "not asked",
            ),
            (
                "asking",
                0,
                "asking",
                "asking the router (PCP, NAT-PMP, UPnP)",
                "asking the router (PCP)",
            ),
            (
                "refused",
                0,
                "refused",
                "the router refused (forward TCP and UDP by hand)",
                "the router refused",
            ),
        ] {
            let rows = router_mapping_rows(&status(Some(with(v4, port, v6))), Some(true));
            assert_eq!(
                rows,
                [
                    ("router mapping", row.to_string()),
                    ("IPv6 pinhole", v6_row.to_string())
                ],
                "{v4}"
            );
        }
        // A word from a newer raven-node is shown as it is, made safe.
        let rows = router_mapping_rows(&status(Some(with("later\x1b[2J", 0, "x"))), Some(true));
        assert!(!rows[0].1.contains('\u{1b}'), "{rows:?}");
        // An older raven-node: Phase 1's row, PCP's mapping included.
        let old = P2pStatusInfo {
            up: true,
            upnp: "mapped 7423".into(),
            ..P2pStatusInfo::default()
        };
        assert_eq!(
            router_mapping_rows(&status(Some(old.clone())), Some(true)),
            [(
                "upnp",
                "on \u{2014} the router forwards port 7423".to_string()
            )]
        );
        assert_eq!(
            router_mapping_rows(&status(None), Some(false)),
            [("upnp", "off".to_string())]
        );
        // REACHABILITY names the protocol that mapped the port.
        let mapped = |port_map| P2pStatusInfo {
            reach: "mapped".into(),
            port_map,
            ..old.clone()
        };
        assert!(internet_row(&mapped(None)).contains("(UPnP, port 7423)"));
        let pcp = mapped(with("pcp", 7423, "open").port_map);
        assert!(
            internet_row(&pcp).contains("(PCP, port 7423)"),
            "{}",
            internet_row(&pcp)
        );
    }

    /// Phase 1 item 5: the `p2p` row shows the running host's reachability
    /// class. An older raven-node reports no class: it is worked out from
    /// its AutoNAT word, reservations, UPnP state and listeners, its
    /// single-server `public` read as `unconfirmed`.
    #[test]
    fn an_older_daemon_without_reach_gets_a_class_from_nat() {
        let up = P2pStatusInfo {
            up: true,
            nat: "unconfirmed".into(),
            reach: "relayed".into(),
            reservations: vec!["r".into()],
            relays_configured: 2,
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/7423".into()],
            ..P2pStatusInfo::default()
        };
        let row = p2p_reach_row(&status(Some(up.clone())), "7423", true);
        assert!(
            row.starts_with(
                "YES \u{2014} the libp2p host is up (reachability: relayed; \
                 reservations 1/2)"
            ),
            "{row}"
        );
        // A class word this ash does not know reads unknown, never raw.
        let newer = P2pStatusInfo {
            reach: "\u{1b}[2Jmesh".into(),
            ..up.clone()
        };
        assert!(class_of(&newer) == ReachClass::Unknown);
        let old = |nat: &str, upnp: &str, reservations: usize, listen: &[&str]| {
            class_of(&P2pStatusInfo {
                up: true,
                nat: nat.into(),
                upnp: upnp.into(),
                reservations: vec!["r".into(); reservations],
                listen_addrs: listen.iter().map(|a| a.to_string()).collect(),
                ..P2pStatusInfo::default()
            })
        };
        let tcp = "/ip4/0.0.0.0/tcp/7423";
        let circuit = "/ip4/203.0.113.7/tcp/7423/p2p/x/p2p-circuit/p2p/y";
        // One server's `public` is not enough for `public`.
        assert_eq!(old("public", "on", 0, &[tcp]), ReachClass::Unknown);
        assert_eq!(old("public", "mapped 7423", 0, &[tcp]), ReachClass::Mapped);
        assert_eq!(old("public", "on", 1, &[tcp, circuit]), ReachClass::Relayed);
        assert_eq!(
            old("private", "mapped 7423", 0, &[tcp]),
            ReachClass::Unreachable
        );
        // A circuit address is no listener.
        assert_eq!(
            old("unknown", "off", 0, &[circuit]),
            ReachClass::Unreachable
        );
        assert_eq!(old("unknown", "off", 0, &[tcp]), ReachClass::Unknown);
        let row = p2p_reach_row(
            &status(Some(P2pStatusInfo {
                reach: String::new(),
                nat: "public".into(),
                reservations: Vec::new(),
                ..up.clone()
            })),
            "7423",
            true,
        );
        assert!(
            row.contains("(reachability: unknown; reservations 0/2)"),
            "{row}"
        );
        // Its REACHABILITY rows: one server's `public` is one check, and it
        // reports no check counts or relay rows.
        let older = P2pStatusInfo {
            reach: String::new(),
            nat: "public".into(),
            reservations: Vec::new(),
            ..up.clone()
        };
        assert_eq!(verdict_of(&older), NatVerdict::Unconfirmed);
        assert!(
            internet_row(&older).starts_with("not confirmed yet: one independent check"),
            "{}",
            internet_row(&older)
        );
        assert_eq!(checks_row(&older), None);
        assert!(relay_rows(&older, &[]).is_empty());
        // A current raven-node's `public` is its own verdict.
        let current = P2pStatusInfo {
            reach: "public".into(),
            nat: "public".into(),
            ..older
        };
        assert_eq!(verdict_of(&current), NatVerdict::Public);
        assert!(internet_row(&current).starts_with("reachable directly"));
    }

    use raven_core::ipc::NatChecks;

    fn up_with(f: impl FnOnce(&mut P2pStatusInfo)) -> P2pStatusInfo {
        let mut info = P2pStatusInfo {
            up: true,
            nat: "unknown".into(),
            reach: "unknown".into(),
            upnp: "unset".into(),
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/7423".into()],
            ..P2pStatusInfo::default()
        };
        f(&mut info);
        info
    }

    /// The REACHABILITY `internet` and `checks` rows, in plain words for each
    /// class, with what the verdict adds (unconfirmed; a mapping the check
    /// could not reach).
    #[test]
    fn reach_rows_in_plain_words() {
        let row = |f: fn(&mut P2pStatusInfo)| internet_row(&up_with(f));
        assert_eq!(
            row(|i| {
                i.reach = "public".into();
                i.nat = "public".into();
            }),
            "reachable directly from the internet (2 independent checks agree)"
        );
        assert_eq!(
            row(|i| {
                i.reach = "mapped".into();
                i.upnp = "mapped 7423".into();
            }),
            "reachable through your router's port mapping (UPnP, port 7423); waiting for 2 \
             independent checks to confirm it"
        );
        assert_eq!(
            row(|i| {
                i.reach = "relayed".into();
                i.reservations = vec!["r".into()];
            }),
            "behind NAT: contacts reach you through 1 relay"
        );
        assert_eq!(
            row(|i| {
                i.reach = "relayed".into();
                i.nat = "unconfirmed".into();
                i.reservations = vec!["r".into(), "s".into()];
            }),
            "behind NAT: contacts reach you through 2 relays; one check says you may also be \
             reachable directly"
        );
        assert_eq!(
            row(|i| {
                i.reach = "unreachable".into();
                i.nat = "private".into();
                i.upnp = "mapped 7423".into();
            }),
            "NOT reachable from the internet: behind NAT and no working relay; your router \
             mapped port 7423, but the check could not reach it (a firewall, or carrier NAT in \
             front of your router?)"
        );
        assert_eq!(
            row(|_| {}),
            "not known: nobody has checked yet, and you have no working relay"
        );
        assert_eq!(
            row(|i| i.nat = "unconfirmed".into()),
            "not confirmed yet: one independent check reached you directly, a second is needed; \
             you have no working relay"
        );
        // checks: none yet, then the counts; an older raven-node reports none.
        assert_eq!(
            checks_row(&up_with(|_| {})).as_deref(),
            Some(
                "none yet (only relays started with `raven-node relay --autonat-server` can check)"
            )
        );
        assert_eq!(
            checks_row(&up_with(|i| {
                i.nat_checks = NatChecks {
                    reached: 1,
                    failed: 1,
                    not_counted: 2,
                }
            }))
            .as_deref(),
            Some(
                "1 of the 2 needed independent checks reached you directly; 1 could not; 2 did \
                 not count (your own network, or reached through a relay)"
            )
        );
        assert_eq!(
            checks_row(&up_with(|i| i.nat_checks.not_counted = 1)).as_deref(),
            Some(
                "none yet (only relays started with `raven-node relay --autonat-server` can \
                 check); 1 did not count (your own network, or reached through a relay)"
            )
        );
        assert_eq!(checks_row(&up_with(|i| i.reach.clear())), None);
        assert_eq!(age_text(59), "59 s");
        assert_eq!(age_text(60), "1 min");
        assert_eq!(age_text(7_199), "1 h");
        assert_eq!(age_text(86_400 * 3), "3 d");
    }

    /// The `relay N` rows: state, how long, the last ping, the next try; the
    /// relay's host and port only, never its PeerId; a word from a newer
    /// raven-node is shown safely.
    #[test]
    fn relay_rows_name_state_ping_and_retry_never_a_peer_id() {
        let peer = p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[4; 32]));
        let health = |relay: &str, state: &str| RelayHealth {
            relay: format!("{relay}/p2p/{peer}"),
            state: state.into(),
            ..RelayHealth::default()
        };
        let info = up_with(|i| {
            i.relay_health = vec![
                RelayHealth {
                    for_s: Some(125),
                    ping_ms: Some(31),
                    ping_age_s: Some(4),
                    ..health("/ip4/127.0.0.1/tcp/40001", "reserved")
                },
                RelayHealth {
                    for_s: Some(90),
                    retry_in_s: Some(12),
                    tries: 3,
                    ..health("/ip6/2001:db8::7/udp/7423/quic-v1", "retrying")
                },
                RelayHealth {
                    retry_in_s: Some(5),
                    tries: 1,
                    ..health("/dns4/relay.example.org/tcp/7423", "retrying")
                },
                health("/ip4/198.51.100.7/tcp/7423", "asking"),
                health("/dns/relay.example.org/tcp/7423", "resolving"),
                health("/ip4/198.51.100.7/tcp/7423", "waiting"),
                health("/ip4/198.51.100.7/tcp/7423", "half\u{1b}[2J open"),
                RelayHealth {
                    for_s: Some(3),
                    ..health("/ip4/127.0.0.1/tcp/40001", "reserved")
                },
            ];
        });
        let rows = relay_rows(&info, &[]);
        let want = [
            "OK \u{2014} 127.0.0.1:40001, reserved for 2 min, ping 31 ms 4 s ago",
            "NOT reserved \u{2014} [2001:db8::7]:7423, lost 1 min ago; next try in 12 s (3 failed)",
            "NOT reserved yet \u{2014} relay.example.org:7423; next try in 5 s (1 failed)",
            "asking 198.51.100.7:7423 for a reservation",
            "looking up relay.example.org",
            "not tried yet \u{2014} 198.51.100.7:7423",
        ];
        for (i, want) in want.iter().enumerate() {
            assert_eq!(rows[i], (format!("relay {}", i + 1), want.to_string()));
        }
        assert!(
            rows[6].1.ends_with("\u{2014} 198.51.100.7:7423"),
            "{:?}",
            rows[6]
        );
        assert!(!rows[6].1.contains('\u{1b}'), "{:?}", rows[6]);
        // Held, no ping yet.
        assert_eq!(rows[7].1, "OK \u{2014} 127.0.0.1:40001, reserved for 3 s");
        for (_, row) in &rows {
            assert!(!row.contains("12D3KooW") && !row.contains("/p2p"), "{row}");
        }
        assert_eq!(relay_label("/p2p/x"), "(no address)");
        // An older raven-node reports no rows.
        assert!(relay_rows(&up_with(|_| {}), &[]).is_empty());
    }

    fn contact(petname: &str, tag: &str, pinned: bool, direct: bool) -> Contact {
        let id = raven_core::Identity::from_seed(&[petname.len() as u8 + 40; 32]);
        let peer = p2p_route::local_peer_id(&id);
        let relay = p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[7; 32]));
        let via = if direct {
            format!("/ip4/203.0.113.9/tcp/7423/p2p/{peer}")
        } else {
            format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}")
        };
        Contact {
            petname: petname.into(),
            public_tag: tag.into(),
            alias: String::new(),
            address: id.address(),
            pub_hex: hex::encode(id.public_key_bytes()),
            pinned,
            lan_dial: String::new(),
            internet_dial: String::new(),
            p2p: peer,
            p2p_via: vec![via],
            p2p_next: String::new(),
            custodians: Vec::new(),
            hide_ip: false,
            onion: String::new(),
            lan_dial_trusted: false,
        }
    }

    /// How the advice names `c` after `--relay` ([`relay_arg_for`]): its
    /// @tag, or on Windows, where PowerShell reads a bare `@tag` as a splat,
    /// its own direct address.
    fn relay_word(c: &Contact) -> String {
        if cfg!(windows) {
            contact_direct_address(c).unwrap()
        } else {
            c.tag_subtitle().unwrap()
        }
    }

    /// A contact's device key.
    fn key_of(c: &Contact) -> [u8; 32] {
        hex::decode(&c.pub_hex).unwrap().try_into().unwrap()
    }

    /// The circle the advice reads: `offers` and `reachable` (contacts in
    /// that order), nothing in use.
    fn circle_of(offers: &[&Contact], reachable: &[&Contact]) -> reach_diag::CircleFacts {
        reach_diag::CircleFacts {
            known: true,
            offers: offers.iter().map(|c| key_of(c)).collect(),
            reachable: reachable.iter().map(|c| key_of(c)).collect(),
            ..reach_diag::CircleFacts::default()
        }
    }

    fn ctx_of<'a>(
        circle: reach_diag::CircleFacts,
        book: &'a [Contact],
        unreachable: &'a [ContactWhy],
        egress: Option<bool>,
    ) -> ReachCtx<'a> {
        ReachCtx {
            tor_reachable: false,
            reached_lately: Vec::new(),
            names: circle_names(&circle, book),
            circle,
            egress,
            unreachable,
            contacts: book,
            mail: Vec::new(),
        }
    }

    /// A contact named `petname` with its own key (`seed`) and a card whose
    /// p2p route goes through a relay.
    fn person(petname: &str, seed: u8) -> Contact {
        let id = raven_core::Identity::from_seed(&[seed; 32]);
        Contact {
            petname: petname.into(),
            address: id.address(),
            pub_hex: hex::encode(id.public_key_bytes()),
            pinned: true,
            ..contact(petname, "", true, false)
        }
    }

    /// One `Status.unreachable` row: `who`'s key, a reason block, an age.
    fn why_row(who: &Contact, reason: &str, age_s: u64) -> ContactWhy {
        ContactWhy {
            peer_pub_hex: who.pub_hex.clone(),
            reason: reason.into(),
            age_s,
        }
    }

    /// An offered relay slot of `owner`.
    fn offered_slot(owner: &Contact, state: &str, tries: u32) -> RelayHealth {
        RelayHealth {
            relay: "/ip4/198.51.100.7/tcp/7427".into(),
            state: state.into(),
            tries,
            source: "offer".into(),
            operator_pub_hex: owner.pub_hex.clone(),
            ..RelayHealth::default()
        }
    }

    /// Phase 4 (P4.20): with `port_map` reported, carrier NAT says a relay
    /// is required, and a relayed node with router mapping off is told how
    /// to turn it on; an older raven-node's advice is unchanged.
    #[test]
    fn what_to_do_names_router_mapping_from_a_port_map_daemon() {
        let book = [contact("Dana", "dana", true, true)];
        let ctx = ctx_of(circle_of(&[], &[]), &book, &[], None);
        let relayed = |v4: Option<&str>| {
            up_with(|i: &mut P2pStatusInfo| {
                i.reach = "relayed".into();
                i.reservations = vec!["/ip4/198.51.100.7/tcp/7423/p2p/r".into()];
                i.relays_configured = 1;
                i.port_map = v4.map(|v4| PortMapStatus {
                    v4: v4.into(),
                    ..PortMapStatus::default()
                });
            })
        };
        let plain = internet_what_to_do(&relayed(None), &ctx);
        assert_eq!(
            internet_what_to_do(&relayed(Some("off")), &ctx),
            format!("{plain} Turn on router port mapping: raven node upnp on.")
        );
        assert_eq!(
            internet_what_to_do(&relayed(Some("behind_another_nat")), &ctx),
            format!("{plain} Your provider uses carrier NAT; a relay is required.")
        );
        // Review C-2: a private external address is a double NAT at the
        // site, not the provider's carrier NAT.
        let double = internet_what_to_do(&relayed(Some("double_nat")), &ctx);
        assert_eq!(
            double,
            format!(
                "{plain} Your router sits behind another router: put the outer one in bridge \
                 mode or forward the port there; until then a relay is needed."
            )
        );
        assert!(!double.contains("carrier"));
        assert_eq!(internet_what_to_do(&relayed(Some("off_path")), &ctx), plain);
        assert_eq!(internet_what_to_do(&relayed(Some("pcp")), &ctx), plain);
        let offline = ctx_of(circle_of(&[], &[]), &book, &[], Some(false));
        assert!(!internet_what_to_do(&relayed(Some("off")), &offline).contains("upnp on"));
    }

    /// The `what to do` row, first match wins: no route (W0), public (W5
    /// when contacts cannot be reached), mapped, W1 (no relay answers;
    /// named by its owner when a contact offered it, with the spare offer
    /// automatic choice moves to), W1c (several contacts' offered relays
    /// all lost), W1b (one of two), relayed fine (one offer only: said),
    /// not checked (unknown, no relay), W2 (unreachable, a contact offers
    /// relaying or can be reached from the internet), W3 (nobody can). Only
    /// W1, W1b, W1c, W2 and W3 are a next step for `raven doctor`; a relay
    /// still on its first try, or a node nothing has checked, is not.
    #[test]
    fn what_to_do_decision_table() {
        let book = [
            contact("Unpinned", "un", false, true),
            contact("Relayed", "rel", true, false),
            contact("Dana", "dana", true, true),
        ];
        let friend = ctx_of(circle_of(&[], &[&book[2]]), &book, &[], None);
        assert_eq!(
            friend.names,
            CircleNames {
                offers: vec![],
                reachable: vec!["Dana".into()],
                friend: Some(("Dana".into(), relay_word(&book[2]))),
            }
        );
        let nobody = ctx_of(circle_of(&[], &[]), &book, &[], None);
        let held = |state: &str, tries: u32| RelayHealth {
            relay: "/ip4/198.51.100.7/tcp/7423".into(),
            state: state.into(),
            tries,
            ..RelayHealth::default()
        };
        let case = |f: &dyn Fn(&mut P2pStatusInfo), ctx: &ReachCtx| {
            let info = up_with(f);
            (
                internet_what_to_do(&info, ctx),
                internet_next_step(&info, ctx),
            )
        };
        let (text, step) = case(&|i| i.reach = "public".into(), &friend);
        assert_eq!(text, "nothing to do: contacts can reach you directly.");
        assert_eq!(step, None);
        let (text, step) = case(
            &|i| {
                i.reach = "mapped".into();
                i.upnp = "mapped 7423".into();
            },
            &nobody,
        );
        assert_eq!(
            text,
            "nothing to do: your router forwards port 7423; a second independent check will \
             confirm it."
        );
        assert_eq!(step, None);
        let w1 = "your relay is not answering, so contacts outside this network cannot reach \
                  you. Check that it runs and lets you in (on the relay's computer: `raven relay \
                  status`); raven-node keeps trying.";
        for rows in [vec![held("retrying", 2)], vec![held("asking", 1)], vec![]] {
            let (text, step) = case(
                &|i| {
                    i.reach = "unreachable".into();
                    i.relays_configured = 1;
                    i.relay_health = rows.clone();
                },
                &friend,
            );
            assert_eq!(text, w1, "{rows:?}");
            assert_eq!(step.as_deref(), Some(w1));
        }
        // Just started: the relay is on its first try, nothing failed yet.
        let (text, step) = case(
            &|i| {
                i.reach = "unknown".into();
                i.relays_configured = 1;
                i.relay_health = vec![held("asking", 0)];
            },
            &friend,
        );
        assert_eq!(
            text,
            "wait a moment: raven-node is asking your relay for its first reservation."
        );
        assert_eq!(step, None);
        let w1b = "one of your two relays is not answering; the other still works. Check it on \
                   the relay's computer with `raven relay status`.";
        let (text, step) = case(
            &|i| {
                i.reach = "relayed".into();
                i.relays_configured = 2;
                i.reservations = vec!["r".into()];
                i.relay_health = vec![held("reserved", 0), held("retrying", 4)];
            },
            &nobody,
        );
        assert_eq!((text.as_str(), step.as_deref()), (w1b, Some(w1b)));
        let fine = "nothing to do: contacts reach you through your relay. Keep it running.";
        for rows in [
            vec![held("reserved", 0), held("reserved", 0)],
            vec![held("reserved", 0), held("resolving", 0)],
        ] {
            let (text, step) = case(
                &|i| {
                    i.reach = "relayed".into();
                    i.relays_configured = 2;
                    i.reservations =
                        vec!["r".into(); if rows[1].state == "reserved" { 2 } else { 1 }];
                    i.relay_health = rows.clone();
                },
                &nobody,
            );
            assert_eq!((text.as_str(), step.as_deref()), (fine, None), "{rows:?}");
        }
        let w2 = "contacts outside this network cannot reach you: you are behind NAT and no \
                  relay is in use. Dana can be reached from the internet: ask Dana to offer \
                  relaying (`raven relay offer on` on Dana's computer), and RAVEN uses it by \
                  itself. Or run the relay kit (docs/RELAY_KIT.md) on a Raspberry Pi or a small \
                  VPS, or forward port 7423 (TCP and UDP) on your router to this computer.";
        let (text, step) = case(&|i| i.reach = "unreachable".into(), &friend);
        assert_eq!((text.as_str(), step.as_deref()), (w2, Some(w2)));
        let w3 = "nobody in your circle can be reached from the internet, so nobody outside this \
                  network can reach you. Any one of these fixes it: ask a friend whose computer \
                  has a public IP or a forwarded port to offer relaying (`raven relay offer on` \
                  on their computer); run the relay kit (docs/RELAY_KIT.md) on a Raspberry Pi \
                  with a forwarded port, or on a small VPS; or forward port 7423 (TCP and UDP) \
                  on your router to this computer (`raven node upnp on` does it if your router \
                  supports UPnP).";
        let (text, step) = case(&|i| i.reach = "unreachable".into(), &nobody);
        assert_eq!((text.as_str(), step.as_deref()), (w3, Some(w3)));
        // A friend with no tag is named by petname.
        let erin = [contact("Erin", "", true, true)];
        let untagged = circle_names(&circle_of(&[], &[&erin[0]]), &erin);
        assert_eq!(untagged.friend.unwrap().1, "Erin");

        // A contact who offers relaying is the friend to ask, before one who
        // can be reached.
        let offering = ctx_of(circle_of(&[&book[1]], &[&book[2]]), &book, &[], None);
        let (text, _) = case(&|i| i.reach = "unreachable".into(), &offering);
        assert!(
            text.contains(
                "Relayed can be reached from the internet: ask Relayed to offer relaying"
            ),
            "{text}"
        );

        // W1 for a relay a contact offered names its owner; W1c for several
        // contacts' relays; one offered relay held and nothing else offered
        // says so; W5 for a public node with contacts it could relay for.
        let carol = person("Carol", 61);
        let erin = person("Erin Ng", 62);
        let book = [carol.clone(), erin.clone(), book[2].clone()];
        let ctx = ctx_of(circle_of(&[&carol], &[]), &book, &[], None);
        let (text, step) = case(
            &|i| {
                i.reach = "unreachable".into();
                i.relay_health = vec![offered_slot(&carol, "retrying", 3)];
            },
            &ctx,
        );
        assert!(text.starts_with("Carol's relay is not answering"), "{text}");
        assert_eq!(step.as_deref(), Some(text.as_str()));
        let (text, step) = case(
            &|i| {
                i.reach = "unreachable".into();
                i.relay_health = vec![
                    offered_slot(&carol, "retrying", 3),
                    offered_slot(&erin, "retrying", 1),
                ];
            },
            &ctx,
        );
        // No other relay is offered: no switch is promised.
        assert_eq!(text, w1c_text(false));
        assert!(!text.contains("switches"), "{text}");
        assert_eq!(step.as_deref(), Some(text.as_str()));
        let (text, _) = case(
            &|i| {
                i.reach = "unreachable".into();
                i.relay_health = vec![
                    offered_slot(&carol, "retrying", 3),
                    offered_slot(&erin, "retrying", 1),
                ];
                i.relay_standby = 1;
            },
            &ctx,
        );
        assert_eq!(text, w1c_text(true), "a spare offer: the switch");
        let (text, step) = case(
            &|i| {
                i.reach = "relayed".into();
                i.reservations = vec!["r".into()];
                i.relay_health = vec![offered_slot(&carol, "reserved", 0)];
            },
            &ctx,
        );
        assert_eq!(
            text,
            "nothing to do: contacts reach you through Carol's relay. Only one relay is offered \
             to you: if it stops or moves, contacts outside this network cannot reach you until \
             it is back."
        );
        assert_eq!(step, None);
        let (text, _) = case(
            &|i| {
                i.reach = "relayed".into();
                i.reservations = vec!["r".into()];
                i.relay_health = vec![offered_slot(&carol, "reserved", 0)];
                i.relay_standby = 1;
            },
            &ctx,
        );
        assert_eq!(text, fine, "a spare offer: not the only one");
        let rows = [why_row(&erin, "reach: why=both_nat me=public", 5)];
        let w5 = ctx_of(circle_of(&[], &[]), &book, &rows, None);
        let (text, step) = case(&|i| i.reach = "public".into(), &w5);
        assert_eq!(
            text,
            "nothing to do: contacts can reach you directly. 1 of your contacts cannot be \
             reached from the internet: this computer could relay for them (`raven relay offer \
             on`)."
        );
        assert_eq!(step, None);
        // ... unless it relays for them already.
        let (text, _) = case(
            &|i| {
                i.reach = "public".into();
                i.friend_relay = Some(FriendRelayInfo {
                    state: "up".into(),
                    ..FriendRelayInfo::default()
                });
            },
            &w5,
        );
        assert_eq!(text, "nothing to do: contacts can reach you directly.");

        // Phase 3 diagnosis (P3.23), merged into the same table: the NOT
        // REACHABLE NOW row and the local network step for the new reasons
        // and fixes. `raven lan off` beats everything, no route included;
        // an offline contact with no friend to hold mail gets a mailbox fix.
        let info = up_with(|i| i.reach = "unreachable".into());
        // P3.C6's words.
        let lan_on = "You turned the local network off (`raven lan on` turns it on). Your \
                      messages wait here.";
        let rows = [
            why_row(&carol, "reach: why=both_nat me=unreachable", 5),
            why_row(&erin, "reach: why=lan_off", 9),
        ];
        for egress in [None, Some(false)] {
            let ctx = ctx_of(circle_of(&[], &[]), &book, &rows, egress);
            assert_eq!(section_what_to_do(&info, &ctx).as_deref(), Some(lan_on));
            assert_eq!(section_next_step(&info, &ctx).as_deref(), Some(lan_on));
            assert_eq!(lan_what_to_do(&ctx).as_deref(), Some(lan_on));
        }
        let silent = [why_row(&erin, "reach: why=lan_no_answer heard=5m", 9)];
        let mut ctx = ctx_of(circle_of(&[], &[]), &book, &silent, None);
        let hotspot = "None of your friends answered on this network. If you are on the same \
                       Wi-Fi, it may keep devices apart (common in hotels and guest Wi-Fi): make \
                       a hotspot instead (docs/OFFLINE_GUIDE.md §3).";
        assert_eq!(lan_what_to_do(&ctx).as_deref(), Some(hotspot));
        assert_eq!(
            section_what_to_do(&info, &ctx).as_deref(),
            Some(
                "nothing to do on your side: waiting messages go out when the contacts are back \
                 online."
            )
        );
        let mailbox = "turn on friend mailboxes (`raven custody use on`): a friend you both \
                       verified can then hold messages for Erin Ng while Erin Ng is offline.";
        let hold = "no friend holds mail for Erin Ng yet: ask a friend you both verified, whose \
                    computer is always on, to run `raven node custody on`.";
        for (mail, row) in [(MailPath::MailboxOff, mailbox), (MailPath::NoFriend, hold)] {
            ctx.mail = vec![(erin.pub_hex.to_ascii_lowercase(), mail)];
            assert_eq!(section_what_to_do(&info, &ctx).as_deref(), Some(row));
            assert_eq!(section_next_step(&info, &ctx).as_deref(), Some(row));
            let step = lan_what_to_do(&ctx).unwrap();
            assert!(step.starts_with(hotspot) && step.contains(row), "{step}");
        }
        // The same for a p2p offline contact; another contact's mailbox
        // fact is not this one's.
        let offline = [why_row(&carol, "reach: why=contact_offline", 9)];
        let mut ctx = ctx_of(circle_of(&[], &[]), &book, &offline, None);
        ctx.mail = vec![(erin.pub_hex.to_ascii_lowercase(), MailPath::NoFriend)];
        assert!(section_what_to_do(&info, &ctx)
            .unwrap()
            .starts_with("nothing to do on your side"));
        ctx.mail = vec![(carol.pub_hex.to_ascii_lowercase(), MailPath::NoFriend)];
        assert_eq!(
            section_what_to_do(&info, &ctx).as_deref(),
            Some(hold.replace("Erin Ng", "Carol").as_str())
        );
        assert_eq!(lan_what_to_do(&ctx), None, "no local network reason");
        // The short rows.
        let out = not_reachable_rows(
            &[
                why_row(&erin, "reach: why=lan_no_answer heard=5m", 9),
                why_row(&carol, "reach: why=lan_off", 9),
            ],
            &book,
            &[],
            &HashMap::new(),
            &[],
        );
        assert_eq!(
            out[0].1,
            "no answer \u{2014} none of your friends answered on this network; last heard 5 min \
             ago, 9 s ago"
        );
        assert_eq!(
            out[1].1,
            "local network off \u{2014} you turned it off, so RAVEN does not look for Carol here \
             (`raven lan on`), 9 s ago"
        );
    }

    /// Unknown with no relay (nothing can check: a node with a port forward or
    /// a public IP stays here) is not called behind NAT or unreachable, and is
    /// no next step for `raven doctor`. An older raven-node's one-server
    /// `public` (read `unconfirmed`, no class) lands here too.
    #[test]
    fn what_to_do_for_a_node_nothing_has_checked() {
        let dana = [contact("Dana", "dana", true, true)];
        let friend = ctx_of(circle_of(&[], &[&dana[0]]), &dana, &[], None);
        let nobody = ctx_of(circle_of(&[], &[]), &dana, &[], None);
        let checked = "nothing has checked yet whether contacts outside this network can reach \
                       you. If you forwarded port 7423 (TCP and UDP) or have a public IP, \
                       contacts that have your direct address can; if not, ";
        let with_friend = format!(
            "{checked}Dana can be reached from the internet: ask Dana to relay for you (`raven \
             node p2p on --relay {}`), run your own relay (`raven-node relay` on a Pi or a \
             VPS), or turn on UPnP (`raven node upnp on`).",
            relay_word(&dana[0])
        );
        let alone = format!(
            "{checked}ask a friend with a public IP or a port forward to run a relay, or run one \
             yourself on a Pi or a VPS (`raven-node relay`, then `raven node p2p on --relay <its \
             address>`), or turn on UPnP (`raven node upnp on`)."
        );
        let unknown = up_with(|i| i.reach = "unknown".into());
        let old_public = up_with(|i| {
            i.reach = String::new();
            i.nat = "public".into();
        });
        for info in [&unknown, &old_public] {
            for (ctx, want) in [(&friend, &with_friend), (&nobody, &alone)] {
                let text = internet_what_to_do(info, ctx);
                assert_eq!(&text, want);
                assert!(!text.contains("behind NAT"), "{text}");
                assert!(!text.contains("cannot reach you"), "{text}");
                assert_eq!(internet_next_step(info, ctx), None, "{text}");
            }
        }
        // The internet row says the same: nobody has checked.
        assert!(
            internet_row(&unknown).starts_with("not known: nobody has checked yet"),
            "{}",
            internet_row(&unknown)
        );
    }

    /// The advice names the port this node listens on (field test E2 r7: a
    /// profile started with `--p2p-listen 17423` was told to forward 7423):
    /// its listen setting, else a TCP listen address (no circuit), else the
    /// release default.
    #[test]
    fn reach_advice_names_the_port_this_node_listens_on() {
        let dana = [contact("Dana", "dana", true, true)];
        let friend = ctx_of(circle_of(&[], &[&dana[0]]), &dana, &[], None);
        let nobody = ctx_of(circle_of(&[], &[]), &dana, &[], None);
        let profile = |reach: &str| {
            up_with(|i| {
                i.reach = reach.into();
                i.listen_setting = "17423".into();
                i.listen_addrs = vec![
                    "/ip4/192.168.1.5/tcp/17423".into(),
                    "/ip4/192.168.1.5/udp/17423/quic-v1".into(),
                ];
            })
        };
        let (unknown, unreachable) = (profile("unknown"), profile("unreachable"));
        let texts = [
            internet_what_to_do(&unknown, &friend),
            internet_what_to_do(&unknown, &nobody),
            internet_what_to_do(&unreachable, &friend),
            internet_what_to_do(&unreachable, &nobody),
            internet_next_step(&unreachable, &nobody).unwrap(),
        ];
        for text in &texts {
            assert!(text.contains("port 17423 (TCP and UDP)"), "{text}");
            assert!(!text.contains("port 7423"), "{text}");
        }
        // Every form of the setting, and none.
        for (setting, addrs, want) in [
            ("0.0.0.0:17424", vec![], 17424),
            ("[::]:17425", vec![], 17425),
            ("on", vec![], DEFAULT_P2P_PORT),
            (
                "127.0.0.1:0",
                vec![
                    "/ip4/1.2.3.4/tcp/7427/p2p/12D3KooWx/p2p-circuit",
                    "/ip4/127.0.0.1/tcp/50123",
                ],
                50123,
            ),
            (
                "",
                vec!["/ip4/127.0.0.1/udp/50124/quic-v1"],
                DEFAULT_P2P_PORT,
            ),
            ("", vec![], DEFAULT_P2P_PORT),
        ] {
            let info = up_with(|i| {
                i.listen_setting = setting.into();
                i.listen_addrs = addrs.iter().map(|a| a.to_string()).collect();
            });
            assert_eq!(p2p_port(&info), want, "{setting:?} {addrs:?}");
        }
    }

    /// The `circle` row: who offers relaying (and how many of their relays
    /// are in use), who can be reached, both, or nobody; at most three
    /// names, then `+N`; nothing when the book cannot be read.
    #[test]
    fn circle_row_texts() {
        let people: Vec<Contact> = ["Ann", "Bo", "Cy", "Dee"]
            .iter()
            .enumerate()
            .map(|(i, n)| person(n, 70 + i as u8))
            .collect();
        let row = |offers: &[&Contact], reachable: &[&Contact], in_use: u8| {
            let mut circle = circle_of(offers, reachable);
            circle.offers_in_use = in_use;
            circle_row(&circle, &circle_names(&circle, &people))
        };
        assert_eq!(
            row(&[&people[0], &people[1]], &[], 1).as_deref(),
            Some("relaying offered by Ann, Bo (1 in use)")
        );
        assert_eq!(
            row(&[], &[&people[2]], 0).as_deref(),
            Some("reachable directly from the internet: Cy")
        );
        assert_eq!(
            row(&[&people[0]], &[&people[2], &people[3]], 0).as_deref(),
            Some(
                "relaying offered by Ann (0 in use); reachable directly from the internet: Cy, Dee"
            )
        );
        assert_eq!(
            row(&[], &[], 0).as_deref(),
            Some(
                "nobody in your circle can be reached from the internet yet (no relay offers, \
                 no contact with a public address)"
            )
        );
        let all: Vec<&Contact> = people.iter().collect();
        assert_eq!(
            row(&[], &all, 0).as_deref(),
            Some("reachable directly from the internet: Ann, Bo, Cy +1")
        );
        assert_eq!(
            circle_row(&reach_diag::CircleFacts::default(), &CircleNames::default()),
            None
        );
        // Names only: never a key.
        let text = row(&all, &all, 2).unwrap();
        assert!(!text.contains(&people[0].pub_hex), "{text}");
    }

    /// W1 names the owner of the offered relay that stopped answering, and
    /// the contact whose spare offer automatic choice moves to; without a
    /// name for the spare it says "another offered relay"; a relay set by
    /// hand keeps Phase 1's words with the same clause.
    #[test]
    fn w1_names_the_relay_owner_and_the_spare_offer() {
        let carol = person("Carol", 61);
        let dave = person("Dave", 63);
        let book = [carol.clone(), dave.clone()];
        let down = |standby: u32, manual: bool| {
            up_with(|i| {
                i.reach = "unreachable".into();
                i.relay_standby = standby;
                i.relay_health = vec![if manual {
                    RelayHealth {
                        relay: "/ip4/198.51.100.7/tcp/7423".into(),
                        state: "retrying".into(),
                        tries: 2,
                        source: "manual".into(),
                        ..RelayHealth::default()
                    }
                } else {
                    offered_slot(&carol, "retrying", 2)
                }];
                i.relays_configured = u32::from(manual);
            })
        };
        let both = ctx_of(circle_of(&[&carol, &dave], &[]), &book, &[], None);
        assert_eq!(
            internet_what_to_do(&down(1, false), &both),
            "Carol's relay is not answering (asleep or switched off?), so contacts outside this \
             network cannot reach you. Ask Carol to wake that computer (`raven relay status` on \
             it shows whether the relay runs); raven-node keeps trying, and moves to Dave's \
             relay if it stays away."
        );
        assert!(internet_what_to_do(&down(0, false), &both).ends_with("raven-node keeps trying."));
        let alone = ctx_of(circle_of(&[&carol], &[]), &book, &[], None);
        assert!(internet_what_to_do(&down(2, false), &alone).ends_with(
            "raven-node keeps trying, and moves to another offered relay if it stays away."
        ));
        let manual = internet_what_to_do(&down(1, true), &both);
        assert!(
            manual.starts_with("your relay is not answering"),
            "{manual}"
        );
        assert!(
            manual
                .ends_with("raven-node keeps trying, and moves to Carol's relay if it stays away."),
            "{manual}"
        );
    }

    /// W1c (every offered relay lost) and the note for the one offered
    /// relay in use; without a route W1c promises no switch.
    #[test]
    fn w1c_and_single_offer_texts() {
        assert_eq!(
            w1c_text(true),
            "the relays your contacts offered are not answering (a laptop relay may be asleep); \
             raven-node keeps trying and switches to another offered relay after 10 minutes."
        );
        assert_eq!(
            ReachAdvice::RelayedOneOffer("Carol".into()).text(DEFAULT_P2P_PORT),
            "nothing to do: contacts reach you through Carol's relay. Only one relay is offered \
             to you: if it stops or moves, contacts outside this network cannot reach you until \
             it is back."
        );
        assert!(ReachAdvice::OffersDown { spare: true }.is_problem());
        assert!(ReachAdvice::OffersDown { spare: false }.is_problem());
        assert!(!ReachAdvice::RelayedOneOffer("Carol".into()).is_problem());
    }

    #[test]
    fn w1c_has_no_switch_clause_without_a_spare_relay() {
        let text = w1c_text(false);
        assert_eq!(
            text,
            "the relays your contacts offered are not answering (a laptop relay may be asleep); \
             raven-node keeps trying."
        );
        assert!(!text.contains("switch"), "{text}");
    }

    /// W2 and W3 name the friend relay command and the relay kit; W5 counts
    /// the contacts a public node could relay for.
    /// E2 r38: with this computer's onion service reachable over Tor, the
    /// advice never says friends outside this network cannot reach it: they
    /// reach it over Tor; a relay that is down is still named, with its one
    /// step, and stays a problem; the rest is nothing to do.
    #[test]
    fn with_tor_reachable_the_advice_says_friends_reach_you_over_tor() {
        let book = [contact("Dana", "dana", true, true)];
        let mut nobody = ctx_of(circle_of(&[], &[]), &book, &[], None);
        let unreachable = up_with(|i| i.reach = "unreachable".into());
        let before = internet_what_to_do(&unreachable, &nobody);
        assert!(
            before.contains("nobody outside this network can reach you"),
            "{before}"
        );
        nobody.tor_reachable = true;
        let text = internet_what_to_do(&unreachable, &nobody);
        assert_eq!(
            text,
            "nothing to do: friends outside this network reach you over Tor (your onion service \
             is reachable). A relay or a forwarded port would be faster."
        );
        assert_eq!(internet_next_step(&unreachable, &nobody), None);
        let down = ReachAdvice::OverTor(Box::new(ReachAdvice::RelayDown {
            owner: Some("Dana".into()),
            switch: String::new(),
        }));
        let words = down.text(DEFAULT_P2P_PORT);
        assert_eq!(
            words,
            "nothing to do: friends outside this network reach you over Tor (your onion service \
             is reachable). Dana's relay is not answering; raven-node keeps trying it."
        );
        assert!(!down.is_problem());
        // E2 r38 (mac-b): the relay's owner was reached on the LAN 52 s ago:
        // never "asleep or switched off?".
        let held = RelayHealth {
            relay: "/ip4/198.51.100.7/tcp/7423".into(),
            state: "failed".into(),
            tries: 3,
            source: "offer".into(),
            operator_pub_hex: book[0].pub_hex.clone(),
            ..RelayHealth::default()
        };
        let relay_down = up_with(|i| {
            i.reach = "unreachable".into();
            i.relay_health = vec![held.clone()];
        });
        let mut awake = ctx_of(circle_of(&[], &[]), &book, &[], None);
        awake.reached_lately = vec![book[0].pub_hex.to_ascii_lowercase()];
        let text = internet_what_to_do(&relay_down, &awake);
        assert!(
            text.starts_with("Dana's relay is not answering, though Dana's computer"),
            "{text}"
        );
        assert!(!text.contains("asleep"), "{text}");
        awake.tor_reachable = true;
        let text = internet_what_to_do(&relay_down, &awake);
        assert!(text.starts_with("nothing to do: friends outside"), "{text}");
        let one = ReachAdvice::OverTor(Box::new(ReachAdvice::RelayedOneOffer("Dana".into())));
        assert!(!one.text(DEFAULT_P2P_PORT).contains("cannot reach you"));
        assert!(!one.is_problem());
    }

    #[test]
    fn w2_w3_w5_texts() {
        let w2 = ReachAdvice::AskFriend {
            name: "Dana".into(),
        }
        .text(DEFAULT_P2P_PORT);
        for words in [
            "you are behind NAT and no relay is in use",
            "ask Dana to offer relaying (`raven relay offer on` on Dana's computer)",
            "the relay kit (docs/RELAY_KIT.md)",
            "forward port 7423 (TCP and UDP)",
        ] {
            assert!(w2.contains(words), "{words:?} missing: {w2}");
        }
        assert!(!w2.contains("--relay"), "{w2}");
        let w3 = ReachAdvice::NobodyReachable.text(DEFAULT_P2P_PORT);
        for words in [
            "nobody in your circle can be reached from the internet",
            "`raven relay offer on` on their computer",
            "the relay kit (docs/RELAY_KIT.md) on a Raspberry Pi with a forwarded port",
            "`raven node upnp on` does it if your router supports UPnP",
        ] {
            assert!(w3.contains(words), "{words:?} missing: {w3}");
        }
        assert_eq!(
            ReachAdvice::PublicCouldRelay(2).text(DEFAULT_P2P_PORT),
            "nothing to do: contacts can reach you directly. 2 of your contacts cannot be \
             reached from the internet: this computer could relay for them (`raven relay offer \
             on`)."
        );
        // Each contact counts once, and only for both_nat / no_relay.
        let (ann, bo) = (person("Ann", 70), person("Bo", 71));
        let book = [ann.clone(), bo.clone()];
        let rows = [
            why_row(&ann, "reach: why=both_nat", 5),
            why_row(&ann, "reach: why=no_relay", 9),
            why_row(&bo, "reach: why=contact_offline", 5),
        ];
        assert_eq!(
            cannot_be_reached(&ctx_of(circle_of(&[], &[]), &book, &rows, None)),
            1
        );
    }

    /// Without a route to the internet W0 replaces every other advice (W1
    /// to W3 included), names no internet-side fix (no UPnP, no relay kit,
    /// no relay offer), is no doctor next step, and the relay-offer question
    /// is not asked.
    #[test]
    fn w0_replaces_w1_to_w3_and_suppresses_the_upnp_and_relay_prompts() {
        let dana = [contact("Dana", "dana", true, true)];
        let w0 = "this computer has no route to the internet right now: contacts outside this \
                  network cannot reach you, and nothing on this computer can change that. People \
                  on this network (Wi-Fi, hotspot or cable) still can.";
        let infos = [
            up_with(|i| {
                i.reach = "unreachable".into();
                i.relays_configured = 1;
                i.relay_health = vec![RelayHealth {
                    state: "retrying".into(),
                    tries: 3,
                    ..RelayHealth::default()
                }];
            }),
            up_with(|i| i.reach = "unreachable".into()),
            up_with(|i| i.reach = "unknown".into()),
            up_with(|i| i.reach = "public".into()),
            up_with(|i| i.reach = "mapped".into()),
        ];
        for circle in [circle_of(&[], &[&dana[0]]), circle_of(&[], &[])] {
            let ctx = ctx_of(circle, &dana, &[], Some(false));
            for info in &infos {
                let text = internet_what_to_do(info, &ctx);
                assert_eq!(text, w0);
                assert_eq!(internet_next_step(info, &ctx), None);
                assert_no_internet_side_fix(&text);
            }
        }
        // The relay-offer question: asked on a public node with a route,
        // never without one.
        let dir = tmp();
        let status = |egress: Option<bool>| {
            Ok(IpcResponse::Status {
                v: IPC_VERSION,
                bridge: false,
                store: false,
                relay: false,
                forward_pending: 0,
                capabilities: Vec::new(),
                p2p: Some(Box::new(up_with(|i| {
                    i.reach = "public".into();
                    i.friend_relay = Some(friend("off", "unset"));
                }))),
                pid: None,
                lan_listen: None,
                last_paths: Vec::new(),
                route_hints: None,
                unreachable: Vec::new(),
                egress,
                lan_listen_wanted: None,
                lan_bind_error: None,
                clock_skew: Vec::new(),
                unanswered: Vec::new(),
                at_rest: None,
                lan: None,
                security: None,
                nearby: None,
                tor: None,
                learning: None,
                locked: None,
                updates: None,
            })
        };
        let asked = |egress: Option<bool>| {
            let mut policy = NodePolicy::default();
            let mut asked = false;
            let _ = prompt_relay_offer(dir.path(), &mut policy, &status(egress), true, |_| {
                asked = true;
                Some("n".into())
            });
            asked
        };
        assert!(asked(Some(true)));
        assert!(!asked(Some(false)));
    }

    /// F9: with no route to the internet (`Status.egress` false) no UPnP or
    /// `relaying` row of `raven status`, no `raven relay status` row and no
    /// `raven relay offer on` note advises a port forward, UPnP, an address
    /// to name or offering relaying: none could help. The same states with a
    /// route still advise them.
    #[test]
    fn no_route_relay_and_upnp_rows_advise_nothing_on_the_internet_side() {
        let with_egress = |info: P2pStatusInfo, egress: Option<bool>| {
            Ok(IpcResponse::Status {
                v: IPC_VERSION,
                bridge: false,
                store: false,
                relay: false,
                forward_pending: 0,
                capabilities: Vec::new(),
                p2p: Some(Box::new(info)),
                pid: None,
                lan_listen: None,
                last_paths: Vec::new(),
                route_hints: None,
                unreachable: Vec::new(),
                egress,
                lan_listen_wanted: None,
                lan_bind_error: None,
                clock_skew: Vec::new(),
                unanswered: Vec::new(),
                at_rest: None,
                lan: None,
                security: None,
                nearby: None,
                tor: None,
                learning: None,
                locked: None,
                updates: None,
            })
        };
        // UPnP on and its mapping failed (no router to map without a route).
        let failed = up_with(|i| i.upnp = "failed".into());
        let offline = upnp_row(&with_egress(failed.clone(), Some(false)), Some(true));
        assert_no_internet_side_fix(&offline);
        assert!(offline.contains("no route to the internet"), "{offline}");
        let online = upnp_row(&with_egress(failed, Some(true)), Some(true));
        assert!(online.contains("forward the port by hand"), "{online}");
        // The friend relay: up and not confirmed (offered, not offered, no
        // address), and off with consent unset on a reachable node.
        let up = |reachable: &str, offering: bool| FriendRelayInfo {
            reachable: reachable.into(),
            offering,
            members: 2,
            ..friend("up", "yes")
        };
        for (fr, class) in [
            (up("unconfirmed", true), "unknown"),
            (up("unconfirmed", false), "unknown"),
            (up("no_address", true), "unknown"),
            (friend("off", "unset"), "public"),
            (friend("off", "unset"), "mapped"),
        ] {
            let info = up_with(|i| {
                i.reach = class.into();
                i.friend_relay = Some(fr.clone());
            });
            let advice = relaying_row(&info, false).unwrap();
            assert!(
                advice.contains("forward") || advice.contains(OFFER_CMD),
                "{advice}"
            );
            if let Some(row) = relaying_row(&info, true) {
                assert_no_internet_side_fix(&row);
                assert!(row.contains("no route to the internet"), "{row}");
            }
            for (key, value) in
                friend_relay_rows(&with_egress(info, Some(false)), Some(true), Some(2))
            {
                assert_no_internet_side_fix(&value);
                if key == "reachable" {
                    assert!(value.contains("no route to the internet"), "{value}");
                }
            }
        }
        // `raven relay offer on` on a node not confirmed public.
        let off = up_with(|i| i.friend_relay = Some(friend("off", "unset")));
        let offer = |egress: Option<bool>| {
            let dir = tmp();
            relay_offer_with(
                dir.path(),
                RelayOfferArg::On(RelayOfferOn::default()),
                &with_egress(off.clone(), egress),
                false,
                |_| None,
            )
            .unwrap()
        };
        let lines = offer(Some(false));
        for line in &lines[1..] {
            assert_no_internet_side_fix(line);
        }
        assert!(
            lines.iter().any(|l| l.contains("no route to the internet")),
            "{lines:?}"
        );
        let lines = offer(Some(true)).join("\n");
        assert!(
            lines.contains("UPnP") && lines.contains("--external"),
            "{lines}"
        );
    }

    /// No text for a computer without a route names a fix on the internet
    /// side: none of them could help.
    fn assert_no_internet_side_fix(text: &str) {
        let lower = text.to_ascii_lowercase();
        for word in [
            "relay kit",
            "relay_kit",
            "vps",
            "raspberry pi",
            OFFER_CMD,
            "upnp",
            "forward",
            "--external",
            "public ip",
            "wake",
            "--relay",
        ] {
            assert!(!lower.contains(word), "{word:?} in: {text}");
        }
    }

    /// The NOT REACHABLE NOW rows: labels (petnames, cut to the key
    /// column), never keys or PeerIds; unknown keys skipped; waiting counts
    /// and ages; eight rows at most, then `(+N more)`.
    #[test]
    fn not_reachable_rows_use_petnames_never_keys_and_skip_unknown() {
        let bob = person("Bob", 80);
        let long = person("Maximilian von Berlin", 81);
        let stranger = person("Stranger", 82);
        let carol = person("Carol", 61);
        let book = [bob.clone(), long.clone(), carol.clone()];
        let rows = [
            why_row(&bob, "reach: why=both_nat me=unreachable", 180),
            why_row(&stranger, "reach: why=both_nat", 5),
            why_row(&long, "reach: why=contact_offline me=relayed heard=3h", 30),
            why_row(&carol, "reach: why=relay_asleep me=relayed relay=mine1", 7),
        ];
        let waiting = HashMap::from([(bob.pub_hex.to_ascii_lowercase(), 2usize)]);
        let relays = ["Dave's relay".to_string()];
        let out = not_reachable_rows(&rows, &book, &[], &waiting, &relays);
        assert_eq!(
            out,
            vec![
                (
                    "Bob".to_string(),
                    "no path \u{2014} you and Bob are both behind NAT, and Bob uses no relay; 2 \
                     messages waiting, 3 min ago"
                        .to_string()
                ),
                (
                    "Maximilian v\u{2026}".to_string(),
                    "offline \u{2014} Maximilian von Berlin's computer is not connected to its \
                     relay; last heard 3 h ago, 30 s ago"
                        .to_string()
                ),
                (
                    "Carol".to_string(),
                    "no path \u{2014} Dave's relay is not answering (you both use it), 7 s ago"
                        .to_string()
                ),
            ]
        );
        for (label, value) in &out {
            for key in [&bob.pub_hex, &stranger.pub_hex, &long.pub_hex] {
                assert!(!label.contains(key.as_str()) && !value.contains(key.as_str()));
            }
            assert!(!value.contains("12D3KooW"), "{value}");
            assert!(!value.contains("Stranger"), "{value}");
        }
        // Every short text, one line each.
        for why in Why::ALL {
            let d = Diag::find(&format!("reach: why={}", why.token())).unwrap();
            let text = short_reason(&d, "Bob", &relays, false);
            assert!(!text.contains('\n') && text.len() < 120, "{text}");
        }
        // Eight rows, then the rest counted.
        let many: Vec<Contact> = (0..11).map(|i| person(&format!("P{i}"), 90 + i)).collect();
        let rows: Vec<ContactWhy> = many
            .iter()
            .map(|c| why_row(c, "reach: why=relay_busy", 60))
            .collect();
        let out = not_reachable_rows(&rows, &many, &[], &HashMap::new(), &[]);
        assert_eq!(out.len(), 9);
        assert_eq!(out[8], (String::new(), "(+3 more)".to_string()));
        assert_eq!(
            out[0].1,
            "turned away \u{2014} P0's relay is full, or does not relay for you; retrying, 1 min \
             ago"
        );
    }

    /// E1: `raven status` gives a contact the reason `raven send` gave: a
    /// p2p reason that only says its direct addresses did not answer (or
    /// that this computer has no route) gives way to its waiting messages'
    /// LAN failure, in the LAN's words, with no internet fix for it; any
    /// other p2p reason, or no LAN failure, stays.
    #[test]
    fn a_lan_failure_is_the_status_reason_over_a_direct_failed_p2p_one() {
        let bob = person("Bob", 80);
        let carol = person("Carol", 61);
        let dave = person("Dave", 62);
        let book = [bob.clone(), carol.clone(), dave.clone()];
        let rows = [
            why_row(&bob, "reach: why=direct_failed me=unreachable", 20),
            why_row(&carol, "reach: why=both_nat", 20),
            why_row(&dave, "reach: why=direct_failed", 20),
        ];
        let lan_failed = HashMap::from([
            (bob.pub_hex.to_ascii_lowercase(), "NOT_LISTENING"),
            (carol.pub_hex.to_ascii_lowercase(), "NOT_REACHABLE"),
        ]);
        let mixed = with_lan_reasons(&rows, &lan_failed);
        let waiting = HashMap::from([(bob.pub_hex.to_ascii_lowercase(), 2usize)]);
        let out = not_reachable_rows(&mixed, &book, &[], &waiting, &[]);
        assert_eq!(
            out[0],
            (
                "Bob".to_string(),
                "not receiving \u{2014} Bob's computer is there, but Raven isn't receiving right \
                 now (it may be locked or closed); 2 messages waiting, 20 s ago"
                    .to_string()
            )
        );
        assert!(
            out[1].1.starts_with("no path \u{2014} you and Carol"),
            "{out:?}"
        );
        assert!(
            out[2]
                .1
                .starts_with("no answer \u{2014} Dave's computer did not answer at its internet"),
            "{out:?}"
        );
        // E2 r9 #9: Dave's last delivery went over the LAN (and Bob's, whose
        // own LAN failure stays): Dave's row says so in the LAN's words, as
        // LAST DELIVERY does, not "its internet address"; Carol's NAT reason
        // stays.
        let lan_path = |who: &Contact| ContactPath {
            peer_pub_hex: who.pub_hex.clone(),
            carrier: "lan_dial".into(),
            age_s: 1_980,
            ..ContactPath::default()
        };
        let paths = [lan_path(&dave), lan_path(&bob)];
        let both = with_last_lan_deliveries(&lan_failed, &paths);
        assert_eq!(both[&bob.pub_hex.to_ascii_lowercase()], "NOT_LISTENING");
        let agreed = not_reachable_rows(
            &with_lan_reasons(&rows, &both),
            &book,
            &paths,
            &waiting,
            &[],
        );
        assert_eq!(
            agreed[2].1,
            "no answer \u{2014} Dave's computer did not answer on this network, 20 s ago"
        );
        assert!(agreed[1].1.starts_with("no path \u{2014} you and Carol"));
        // Bob's row reads no reason block: no fix on the internet side is
        // picked for him.
        assert!(Diag::find(&mixed[0].reason).is_none());
        let unreachable = HashMap::from([(bob.pub_hex.to_ascii_lowercase(), "NOT_REACHABLE")]);
        let lan = with_lan_reasons(&rows[..1], &unreachable);
        assert_eq!(
            not_reachable_rows(&lan, &book, &[], &HashMap::new(), &[])[0].1,
            "no answer \u{2014} Bob's computer did not answer on this network, 20 s ago"
        );
    }

    /// `no_relay`: it goes out when the contact next writes, and "as last
    /// time" when the last delivery went over a connection it opened.
    #[test]
    fn no_relay_row_says_as_last_time_after_a_reversed_delivery() {
        let bob = person("Bob", 80);
        let rows = [why_row(&bob, "reach: why=no_relay me=relayed", 60)];
        let path = |p: &str| ContactPath {
            peer_pub_hex: bob.pub_hex.clone(),
            carrier: "p2p_dial".into(),
            path: p.into(),
            age_s: 100,
        };
        let row = |paths: &[ContactPath]| {
            not_reachable_rows(
                &rows,
                std::slice::from_ref(&bob),
                paths,
                &HashMap::new(),
                &[],
            )[0]
            .1
            .clone()
        };
        assert_eq!(
            row(&[path("reversed")]),
            "no path \u{2014} Bob uses no relay; it goes out when Bob next sends you a message \
             (as last time), 1 min ago"
        );
        assert_eq!(
            row(&[path("relayed")]),
            "no path \u{2014} Bob uses no relay; it goes out when Bob next sends you a message, 1 \
             min ago"
        );
        assert_eq!(row(&[]), row(&[path("direct")]));
    }

    /// The section's `what to do` is the fix of highest priority over its
    /// rows, worded for the contact of the first row that needs it.
    #[test]
    fn section_what_to_do_takes_the_highest_priority_fix() {
        let (bob, ann, dana) = (person("Bob", 80), person("Ann", 70), person("Dana", 64));
        let book = [bob.clone(), ann.clone(), dana.clone()];
        let info = up_with(|i| i.reach = "relayed".into());
        let what = |rows: &[ContactWhy], circle: reach_diag::CircleFacts| {
            section_what_to_do(&info, &ctx_of(circle, &book, rows, None))
        };
        let offline = why_row(&bob, "reach: why=contact_offline", 5);
        let busy = why_row(&ann, "reach: why=relay_busy", 5);
        let refused = why_row(&ann, "reach: why=relay_refused", 5);
        let nat = why_row(&bob, "reach: why=both_nat", 5);
        assert_eq!(
            what(std::slice::from_ref(&offline), circle_of(&[], &[])).as_deref(),
            Some(
                "nothing to do on your side: waiting messages go out when the contacts are back \
                 online."
            )
        );
        assert_eq!(
            what(&[offline.clone(), busy.clone()], circle_of(&[], &[])).as_deref(),
            Some("nothing to do: raven-node tries again by itself.")
        );
        assert_eq!(
            what(
                &[busy.clone(), refused.clone(), offline.clone()],
                circle_of(&[], &[])
            )
            .as_deref(),
            Some(
                "ask Ann whose relay it is and become that person's verified contact (`raven \
                 whoami --card` on both computers)."
            )
        );
        assert_eq!(
            what(&[refused.clone(), nat.clone()], circle_of(&[], &[&dana])).as_deref(),
            Some(
                "Dana can be reached from the internet: ask Dana to offer relaying (`raven relay \
                 offer on` on Dana's computer); RAVEN then uses it by itself for every contact \
                 who is also Dana's verified contact."
            )
        );
        let nobody = what(&[refused, nat.clone()], circle_of(&[], &[])).unwrap();
        assert!(
            nobody.starts_with(
                "nobody in your circle can be reached from the internet, so nothing can carry \
                 messages between two computers behind NAT. Any one of these fixes it:"
            ),
            "{nobody}"
        );
        // A circle that cannot be read says nothing for both_nat.
        assert_eq!(
            what(
                std::slice::from_ref(&nat),
                reach_diag::CircleFacts::default()
            ),
            None
        );
        // No route to the internet wins over everything, with nothing to fix.
        let ctx = ctx_of(
            circle_of(&[], &[]),
            &book,
            std::slice::from_ref(&nat),
            Some(false),
        );
        assert_eq!(
            section_what_to_do(&info, &ctx).as_deref(),
            Some("nothing to fix from here: messages to people on this network still go; the rest wait.")
        );
        assert_eq!(section_next_step(&info, &ctx), None);
        let local = why_row(&bob, "reach: why=no_route", 5);
        let rows = [nat, local];
        let ctx = ctx_of(circle_of(&[], &[&dana]), &book, &rows, None);
        assert_eq!(
            section_what_to_do(&info, &ctx).as_deref(),
            Some("nothing to fix from here: messages to people on this network still go; the rest wait.")
        );
        // Only something to act on is a doctor next step.
        let rows = [busy];
        let ctx = ctx_of(circle_of(&[], &[]), &book, &rows, None);
        assert_eq!(section_next_step(&info, &ctx), None);
    }

    /// A reason this ash does not know is shown as it came, made safe.
    #[test]
    fn an_unparsable_reason_is_shown_sanitized() {
        let bob = person("Bob", 80);
        let rows = [why_row(&bob, "reach: why=moon_phase\u{1b}[2J x", 4)];
        let out = not_reachable_rows(&rows, std::slice::from_ref(&bob), &[], &HashMap::new(), &[]);
        assert_eq!(out.len(), 1);
        assert!(!out[0].1.contains('\u{1b}'), "{:?}", out[0]);
        assert!(
            out[0].1.starts_with("reach: why=moon_phase"),
            "{:?}",
            out[0]
        );
        assert!(out[0].1.ends_with(", 4 s ago"), "{:?}", out[0]);
        let info = up_with(|_| {});
        assert_eq!(
            section_what_to_do(&info, &ctx_of(circle_of(&[], &[]), &[bob], &rows, None)),
            None
        );
    }

    /// When every row says this computer has no route, one row says it for
    /// all of them (with how many messages wait), and the advice names no
    /// internet-side fix.
    #[test]
    fn not_reachable_now_collapses_no_route_rows() {
        let (bob, ann) = (person("Bob", 80), person("Ann", 70));
        let book = [bob.clone(), ann.clone()];
        let rows = [
            why_row(&bob, "reach: why=no_route me=unknown", 5),
            why_row(&ann, "reach: why=no_route heard=1h", 9),
        ];
        let waiting = HashMap::from([
            (bob.pub_hex.to_ascii_lowercase(), 2usize),
            (ann.pub_hex.to_ascii_lowercase(), 1usize),
        ]);
        let out = not_reachable_rows(&rows, &book, &[], &waiting, &[]);
        assert_eq!(
            out,
            vec![(
                "contacts".to_string(),
                "this computer has no route to the internet: only contacts on this network can \
                 be reached (3 messages waiting)"
                    .to_string()
            )]
        );
        let info = up_with(|i| i.reach = "unreachable".into());
        let ctx = ctx_of(circle_of(&[], &[]), &book, &rows, Some(false));
        let step = section_what_to_do(&info, &ctx).unwrap();
        assert_no_internet_side_fix(&step);
        assert_no_internet_side_fix(&out[0].1);
        // One that is not no_route: one row per contact.
        let mixed = [rows[0].clone(), why_row(&ann, "reach: why=both_nat", 9)];
        assert_eq!(
            not_reachable_rows(&mixed, &book, &[], &waiting, &[]).len(),
            2
        );
    }

    /// The `--relay` argument in the advice is one shell word: a petname with a
    /// space, parentheses or a quote is quoted, an @tag stays as it is.
    #[test]
    fn the_relay_argument_in_the_advice_is_one_shell_word() {
        let arg = |petname: &str, tag: &str| {
            let book = [contact(petname, tag, true, true)];
            circle_names(&circle_of(&[], &[&book[0]]), &book)
                .friend
                .unwrap()
                .1
        };
        let names = [
            "Robin (Office)",
            "Bob Smith",
            "O'Neil",
            "a;b",
            "$HOME",
            "50%off",
            "\u{0639}\u{0644}\u{06cc}",
        ];
        if cfg!(windows) {
            // The friend's own direct address instead (`relay_arg_for`).
            let direct =
                |name: &str| contact_direct_address(&contact(name, "", true, true)).unwrap();
            assert_eq!(arg("Robin (Office)", "robin"), direct("Robin (Office)"));
            for name in names {
                assert_eq!(arg(name, ""), direct(name));
            }
        } else {
            assert_eq!(arg("Robin (Office)", "robin"), "@robin");
            for name in names {
                let quoted = arg(name, "");
                assert!(
                    quoted.starts_with('\'') && quoted.ends_with('\''),
                    "{quoted}"
                );
            }
        }
        assert_eq!(arg("Erin", ""), "Erin");
        if cfg!(unix) {
            assert_eq!(arg("Robin (Office)", ""), "'Robin (Office)'");
            assert_eq!(arg("O'Neil", ""), "'O'\\''Neil'");
            // What a POSIX shell makes of it: exactly the petname, one argument.
            for name in names {
                let out = std::process::Command::new("/bin/sh")
                    .arg("-c")
                    .arg(format!("printf '%s|' {}", arg(name, "")))
                    .output()
                    .unwrap();
                assert!(out.status.success(), "{name}: {out:?}");
                assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{name}|"));
            }
            // And the advice carries the quoted form (a node nothing has
            // checked; W2 names the friend relay command instead).
            let book = [contact("Robin (Office)", "", true, true)];
            let ctx = ctx_of(circle_of(&[], &[&book[0]]), &book, &[], None);
            let text = internet_what_to_do(&up_with(|i| i.reach = "unknown".into()), &ctx);
            assert!(
                text.contains("`raven node p2p on --relay 'Robin (Office)'`"),
                "{text}"
            );
            assert!(text.contains("ask Robin (Office) to relay"), "{text}");
        }
    }

    /// On Windows (PowerShell by default, or cmd.exe) the advice never puts a
    /// name in the command that the shell would change: a bare `@tag` is a
    /// PowerShell splat (it passes nothing), `$name` expands inside double
    /// quotes, `,` makes an array, and cmd.exe expands `%VAR%` and takes no
    /// single quotes. The friend's direct address goes there instead, and
    /// only an address that is not plain itself falls back to PowerShell's
    /// verbatim single quotes.
    #[test]
    fn the_windows_relay_argument_is_safe_in_powershell_and_cmd() {
        let peer = p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[44; 32]));
        let direct = format!("/ip4/203.0.113.9/tcp/7423/p2p/{peer}");
        for label in [
            "@robin",
            "a,b",
            "Robin (Office)",
            "$name",
            "%USERPROFILE%",
            "O'Neil",
            "`whoami`",
        ] {
            assert_eq!(relay_arg_for(label, &direct, true), direct, "{label}");
            // The same label on Unix: POSIX quoting (or bare when plain).
            let unix = relay_arg_for(label, &direct, false);
            assert!(unix == label || unix.starts_with('\''), "{unix}");
        }
        assert_eq!(relay_arg_for("Erin", &direct, true), "Erin");
        assert_eq!(relay_arg_for("@robin", &direct, false), "@robin");
        // A direct address that is not plain (a name with a `$`): the label
        // in PowerShell quotes, every quote doubled, the typographic ones too.
        let odd = "/dns4/a$b.example/tcp/7423";
        assert_eq!(relay_arg_for("$name", odd, true), "'$name'");
        assert_eq!(relay_arg_for("O'Neil", odd, true), "'O''Neil'");
        assert_eq!(
            relay_arg_for("Bob\u{2019}s 50%", odd, true),
            "'Bob\u{2019}\u{2019}s 50%'"
        );
        assert_eq!(powershell_quote("@robin"), "'@robin'");
    }

    /// Auto-reach: the `auto_reach` row says the setting, what the servers
    /// agreed on and which ports a contact reached, never an address.
    #[test]
    fn auto_reach_row_in_plain_words() {
        let found = AutoReachStatus {
            state: "on".into(),
            public: "found".into(),
            class: "stable_kept".into(),
            anchored: true,
            asked: 3,
            answered: 3,
            age_s: Some(130),
            reached: vec!["quic".into(), "tcp".into()],
            punch: None,
        };
        let row = auto_reach_row(&found);
        assert_eq!(
            row,
            "on: public address found (the p2p port's own); NAT stable (port kept), 3 answered \
             2 min ago; reached from outside: p2p QUIC, p2p TCP"
        );
        let fresh = AutoReachStatus {
            reached: Vec::new(),
            anchored: false,
            ..found.clone()
        };
        assert!(auto_reach_row(&fresh).ends_with("no contact has reached it from outside yet"));
        let silent = AutoReachStatus {
            public: "none".into(),
            answered: 0,
            age_s: None,
            ..found.clone()
        };
        assert_eq!(
            auto_reach_row(&silent),
            "on: no STUN server answered (UDP blocked or offline); retrying"
        );
        let off = AutoReachStatus {
            state: "off".into(),
            ..found.clone()
        };
        assert!(auto_reach_row(&off).starts_with("off (`raven node stun on`"));
        let hidden = AutoReachStatus {
            state: "hidden".into(),
            ..found.clone()
        };
        assert!(auto_reach_row(&hidden).contains("hide-ip off"));
        let punching = AutoReachStatus {
            punch: Some(raven_core::ipc::PunchStatus {
                targets: 1,
                tried: 4,
                connected: 1,
                ..Default::default()
            }),
            ..found
        };
        assert!(auto_reach_row(&punching)
            .ends_with("; serverless punches: 1 target, 4 tried, 1 connected"));
    }

    /// `raven node stun on|off` saves the setting; without one it shows it
    /// with the consent text, and the hold while the gate is shut.
    #[test]
    fn node_stun_saves_and_shows_the_setting() {
        let dir = tmp();
        let none: Result<IpcResponse, String> = Err("no service".into());
        let lines = node_stun_with(dir.path(), Some(false), true, &none).unwrap();
        assert!(lines[0].contains("stun=off"), "{lines:?}");
        assert_eq!(try_load_policy(dir.path()).unwrap().stun, Some(false));
        let lines = node_stun_with(dir.path(), None, true, &none).unwrap();
        assert_eq!(lines[0], "stun: off", "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("(Cloudflare and Google)")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("no p2p host runs")),
            "{lines:?}"
        );
        node_stun_with(dir.path(), Some(true), true, &none).unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap().stun, Some(true));
        let lines = node_stun_with(dir.path(), None, false, &none).unwrap();
        assert_eq!(lines[0], "stun: on");
        assert!(
            lines.iter().any(|l| l.contains("STUN_DISCOVERY_HOLD:")),
            "{lines:?}"
        );
        let fresh = tmp();
        let lines = node_stun_with(fresh.path(), None, true, &none).unwrap();
        assert_eq!(lines[0], "stun: on (the default)");
    }

    /// Phase 4 (P4.24): the `p2p_nat` row in plain words, one count each;
    /// an unknown word from a newer raven-node is shown safely.
    #[test]
    fn nat_row_in_plain_words() {
        let row = nat_row(&NatMappingStatus {
            tcp: "varies".into(),
            quic: "stable_kept".into(),
            observers: 2,
            punch_skipped: 1,
            punch_failed: 0,
        });
        assert_eq!(
            row,
            "tcp varies by destination, quic stable (port kept), seen from 2 networks; hole \
             punches skipped 1, failed 0"
        );
        let row = nat_row(&NatMappingStatus {
            tcp: "later\u{1b}[2J".into(),
            quic: "no_nat".into(),
            observers: 1,
            ..NatMappingStatus::default()
        });
        assert!(!row.contains('\u{1b}'), "{row}");
        assert!(row.contains("quic no NAT, seen from 1 network;"), "{row}");
    }

    /// Phase 4 (P4.28): `raven node p2p rotate on|off` saves the setting,
    /// says the trade-off (and the hold while the gate is closed) and
    /// parses; the `p2p_rotation` row and the doctor line say the state in
    /// words and counts, never a PeerId.
    #[test]
    fn rotate_command_status_row_and_doctor_line() {
        let dir = tempfile::tempdir().unwrap();
        let lines = node_p2p_rotate_with(dir.path(), true, false).unwrap();
        assert!(lines[0].contains("peer_rotation=on"), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("raven relay schedule")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("trade-off")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("PEER_ROTATION_HOLD")),
            "{lines:?}"
        );
        assert_eq!(
            raven_core::node_policy::load_policy(dir.path()).peer_rotation,
            Some(true)
        );
        let lines = node_p2p_rotate_with(dir.path(), true, true).unwrap();
        assert!(
            !lines.iter().any(|l| l.contains("PEER_ROTATION_HOLD")),
            "{lines:?}"
        );
        let lines = node_p2p_rotate_with(dir.path(), false, true).unwrap();
        assert!(lines[0].contains("peer_rotation=off"), "{lines:?}");
        assert_eq!(
            raven_core::node_policy::load_policy(dir.path()).peer_rotation,
            Some(false)
        );

        use super::super::{Commands, NodeCommands, OnOff, P2pState};
        use clap::Parser;
        let parse = |args: &[&str]| {
            super::super::Cli::try_parse_from(std::iter::once("raven").chain(args.iter().copied()))
                .map(|c| c.cmd)
        };
        for (word, on) in [("on", true), ("off", false)] {
            match parse(&["node", "p2p", "rotate", word]) {
                Ok(Some(Commands::Node {
                    cmd:
                        NodeCommands::P2p {
                            state: P2pState::Rotate { state },
                        },
                })) => assert_eq!(matches!(state, OnOff::On), on),
                other => panic!("{other:?}"),
            }
        }
        assert!(parse(&["node", "p2p", "rotate"]).is_err());

        let row = |state: &str, waiting_on: u32, next: Option<u64>| {
            rotation_row(&RotationStatus {
                state: state.into(),
                waiting_on,
                epoch: Some(9),
                epoch_len_s: 30,
                next_change_s: next,
            })
        };
        assert!(row("waiting", 1, None).starts_with("waiting: 1 contact cannot"));
        assert!(row("waiting", 2, None).starts_with("waiting: 2 contacts cannot"));
        assert!(row("waiting", u32::MAX, None).contains("cannot be read"));
        assert_eq!(
            row("on", 0, Some(20)),
            "on: a new network ID every epoch; next change in 20 s"
        );
        assert!(row("on", 0, Some(3 * 86_400)).ends_with("in 3 d"));
        assert!(row("postponed", 0, Some(7200)).contains("trying again in 2 h"));
        assert!(row("off", 0, None).starts_with("off"));
        assert!(row("starting", 0, Some(25)).ends_with("first change in 25 s"));
        assert!(!row("x\u{1b}[2J", 0, None).contains('\u{1b}'));
        for state in ["off", "waiting", "starting", "on", "postponed"] {
            assert!(!row(state, 1, Some(5)).contains("12D3"), "{state}");
        }

        // Doctor: nothing while held and unset; the setting and the state.
        let none: Result<IpcResponse, String> = Err("not running".into());
        let unset = NodePolicy::default();
        assert_eq!(doctor_peer_rotation_line(&none, &unset, false), None);
        assert_eq!(
            doctor_peer_rotation_line(&none, &unset, true).as_deref(),
            Some("peer_rotation=- setting=unset waiting_on=0 gate=open")
        );
        let on = NodePolicy {
            peer_rotation: Some(true),
            ..NodePolicy::default()
        };
        let running = status(Some(P2pStatusInfo {
            up: true,
            rotation: Some(RotationStatus {
                state: "waiting".into(),
                waiting_on: 1,
                ..RotationStatus::default()
            }),
            ..P2pStatusInfo::default()
        }));
        assert_eq!(
            doctor_peer_rotation_line(&running, &on, true).as_deref(),
            Some("peer_rotation=waiting setting=on waiting_on=1 gate=open")
        );
        assert_eq!(super::super::card_rotation_epoch(&running), None);
        let rotating = status(Some(P2pStatusInfo {
            up: true,
            rotation: Some(RotationStatus {
                state: "on".into(),
                epoch: Some(41),
                ..RotationStatus::default()
            }),
            ..P2pStatusInfo::default()
        }));
        assert_eq!(super::super::card_rotation_epoch(&rotating), Some(41));
    }

    /// The `p2p_paths` row: both sides' counts per path and the hole-punch
    /// verdicts, counts only.
    #[test]
    fn p2p_paths_row_formats_counts() {
        let row = p2p_paths_row(&P2pPathCounts {
            sent: PathCounts {
                direct: 1,
                reversed: 2,
                relayed: 3,
                hole_punched: 0,
            },
            received: PathCounts {
                direct: 4,
                reversed: 0,
                relayed: 5,
                hole_punched: 6,
            },
            upgrades: 1,
            upgrade_failures: 2,
        });
        assert_eq!(
            row,
            "sent: direct 1 · reversed 2 · relayed 3 · hole-punched 0; received: direct 4 · \
             reversed 0 · relayed 5 · hole-punched 6; hole punching 1 ok, 2 failed (since \
             raven-node started)"
        );
        assert!(p2p_paths_row(&P2pPathCounts::default()).contains("hole punching 0 ok, 0 failed"));
    }

    /// The `p2p_gate` row: who is admitted (counts only), an unreadable
    /// contact book or block list, and no verified contact yet.
    #[test]
    fn p2p_gate_row_says_who_is_admitted() {
        let normal = gate_row(&P2pGateStatus {
            contacts: 2,
            relays: 1,
            refused: 3,
            ..P2pGateStatus::default()
        });
        assert_eq!(
            normal,
            "verified contacts 2, relays 1; refused 3 connection(s) from others (since the last \
             start or network change)"
        );
        let unreadable = gate_row(&P2pGateStatus {
            contacts: 0,
            relays: 1,
            unreadable: true,
            ..P2pGateStatus::default()
        });
        assert!(
            unreadable.starts_with(
                "NOBODY: contacts.json or blocked_pubs.json cannot be read; only your relays \
                 are admitted; refused 0"
            ),
            "{unreadable}"
        );
        let empty = gate_row(&P2pGateStatus {
            relays: 1,
            refused_hole_punch: 2,
            ..P2pGateStatus::default()
        });
        assert!(
            empty.starts_with(
                "no verified contact has a p2p PeerId yet (each is learned from the friend once \
                 you are connected); refused 0 connection(s) from others and 2 hole-punch \
                 dial(s)"
            ),
            "{empty}"
        );
        for row in [normal, unreadable, empty] {
            assert!(!row.contains("12D3KooW"), "{row}");
        }
    }

    /// Review item 8: while a service answers, its own effective setting (an
    /// installer flag included) decides the row, not node_policy.json.
    #[test]
    fn status_p2p_row_follows_the_running_service_not_the_policy_file() {
        let service = |f: fn(&mut P2pStatusInfo)| {
            let mut info = P2pStatusInfo::default();
            f(&mut info);
            status(Some(info))
        };
        // A flag turned it on although node_policy.json says nothing.
        let held = service(|i| {
            i.listen_setting = "7423".into();
            i.source = "--p2p-listen".into();
            i.held = true;
        });
        let row = p2p_reach_row(&held, "", true);
        assert!(
            row.starts_with("NO") && row.contains("from --p2p-listen") && row.contains("P2P_HOLD"),
            "{row}"
        );
        let starting = service(|i| {
            i.listen_setting = "relay".into();
            i.source = "RAVEN_P2P_LISTEN".into();
        });
        let row = p2p_reach_row(&starting, "", true);
        assert!(
            row.contains("(relay, from RAVEN_P2P_LISTEN)") && row.contains("not up"),
            "{row}"
        );
        // An env var turned it off although node_policy.json turns it on.
        let off = service(|i| i.source = "RAVEN_P2P_LISTEN".into());
        let row = p2p_reach_row(&off, "7423", true);
        assert_eq!(
            row,
            "off (RAVEN_P2P_LISTEN turns it off for the running raven-node)"
        );
        let plain_off = service(|i| i.source = "node_policy.json".into());
        assert!(p2p_reach_row(&plain_off, "", true).starts_with("off (opt-in"));
        let broken = service(|i| {
            i.listen_setting = "7423".into();
            i.config_error = "bad relay".into();
        });
        let row = p2p_reach_row(&broken, "7423", true);
        assert!(row.starts_with("NO") && row.contains("bad relay"), "{row}");
        // Up, but no listen address open (a busy port, or an address on no
        // interface): said so in both rows.
        let busy = P2pStatusInfo {
            up: true,
            nat: "unknown".into(),
            listen_setting: "7423".into(),
            listen_retrying: 2,
            ..P2pStatusInfo::default()
        };
        let row = p2p_reach_row(&status(Some(busy.clone())), "7423", true);
        assert!(
            row.starts_with("YES") && row.contains("2 listen address(es) not open yet"),
            "{row}"
        );
        assert_eq!(
            p2p_listen_row(&busy),
            "(none open yet: its port is busy, or its address is not on this computer)"
        );
        let relayed = P2pStatusInfo {
            listen_retrying: 0,
            ..busy.clone()
        };
        assert_eq!(
            p2p_listen_row(&relayed),
            "(none: reachable through relays only)"
        );
        let open = P2pStatusInfo {
            listen_addrs: vec![
                "/ip4/127.0.0.1/tcp/7423".into(),
                "/ip4/127.0.0.1/udp/7423/quic-v1".into(),
            ],
            ..relayed
        };
        assert_eq!(
            p2p_listen_row(&open),
            "/ip4/127.0.0.1/tcp/7423, /ip4/127.0.0.1/udp/7423/quic-v1"
        );
    }

    /// Review item 13: a stopped relay is told apart by its lock, a stuck one
    /// by its heartbeat.
    #[test]
    fn relay_status_says_not_running_running_or_stuck() {
        let now = 1_000_000_000;
        assert!(relay_state_line(false, now - 5_000, now)
            .starts_with("not running (last status 5s ago"));
        assert_eq!(relay_state_line(true, now - 5_000, now), "running");
        let stuck = relay_state_line(true, now - relay_allow::RELAY_STATUS_STALE_MS - 1_000, now);
        assert!(
            stuck.starts_with("running but its status is 36s old"),
            "{stuck}"
        );
        // A relay that never wrote a status (0) and is not running.
        assert!(relay_state_line(false, 0, now).starts_with("not running"));
    }

    #[test]
    fn relay_allow_reads_peer_ids_cards_and_contacts() {
        // A lab card's routes (cards carry none outside the lab: card_routes_live).
        let _card_routes = super::super::CardRoutesForTest::set(true);
        let dir = tmp();
        let friend = raven_core::Identity::from_seed(&[9; 32]);
        let peer = p2p_route::local_peer_id(&friend);
        cmd_relay_allow(dir.path(), Some(&peer), None, "").unwrap();
        assert!(relay_allow::load_relay_allow(dir.path())
            .unwrap()
            .unwrap()
            .contains(&peer));
        let card = super::super::format_card_with(
            &friend,
            "",
            "",
            Some(&super::super::P2pRoute {
                peer_id: peer.clone(),
                via: Vec::new(),
                next: None,
            }),
        );
        cmd_relay_allow(dir.path(), None, Some(&card), "bob").unwrap();
        let v1 = super::super::format_card_with(&friend, "", "", None);
        assert!(cmd_relay_allow(dir.path(), None, Some(&v1), "").is_err());
        assert!(cmd_relay_allow(dir.path(), None, None, "").is_err());
        assert!(cmd_relay_allow(dir.path(), Some("nobody"), None, "").is_err());
        cmd_relay_deny(dir.path(), &peer).unwrap();
        assert!(!relay_allow::load_relay_allow(dir.path())
            .unwrap()
            .unwrap()
            .contains(&peer));
    }

    #[test]
    fn relay_card_host_parts_cover_v4_v6_and_names() {
        let host_part = p2p_route::host_prefix;
        assert_eq!(host_part("203.0.113.7").unwrap(), "/ip4/203.0.113.7");
        assert_eq!(host_part("[2001:db8::7]").unwrap(), "/ip6/2001:db8::7");
        assert_eq!(
            host_part("Relay.Example.com").unwrap(),
            "/dns/relay.example.com"
        );
    }

    fn peer_of(seed: u8) -> String {
        p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[seed; 32]))
    }

    /// A raven-card/2 of `seed`'s identity (its p2p= PeerId, no via=).
    fn p2p_card(seed: u8) -> String {
        let id = raven_core::Identity::from_seed(&[seed; 32]);
        super::super::format_card_with(
            &id,
            "",
            "",
            Some(&super::super::P2pRoute {
                peer_id: p2p_route::local_peer_id(&id),
                via: Vec::new(),
                next: None,
            }),
        )
    }

    fn words(w: &[&str]) -> Vec<String> {
        w.iter().map(|s| s.to_string()).collect()
    }

    /// Relay kit: a friend pastes the lines of `raven relay card` (with or
    /// without `via=`, on one line or several); they are saved like `raven
    /// node p2p on --relay …`, and anything else changes nothing.
    #[test]
    fn relay_use_accepts_pasted_card_lines() {
        let relay = peer_of(0x51);
        let main = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}");
        let fallback = format!("/ip4/198.51.100.7/tcp/443/p2p/{relay}");
        let never = |_: u16| -> Option<String> { panic!("no prompt off a terminal") };

        // p2p was off: turned on (7423), both addresses saved in card order.
        let dir = tmp();
        cmd_relay_use_with(
            dir.path(),
            &words(&[&format!("via={main}"), &format!("via={fallback}")]),
            false,
            never,
        )
        .unwrap();
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!(p.p2p_listen, DEFAULT_P2P_PORT.to_string());
        assert_eq!(p.p2p_relays, vec![main.clone(), fallback.clone()]);
        assert_eq!(p.upnp, None);

        // One pasted block: newlines and commas, with and without via=, a
        // duplicate dropped. A listen setting saved before is kept.
        let kept = tmp();
        cmd_node_p2p_with(
            kept.path(),
            Some(P2pOnArgs {
                listen: "127.0.0.1:7500".into(),
                ..P2pOnArgs::default()
            }),
            false,
            never,
        )
        .unwrap();
        cmd_relay_use_with(
            kept.path(),
            &[format!("via={main}\nvia={main},{fallback}\n")],
            false,
            never,
        )
        .unwrap();
        let p = try_load_policy(kept.path()).unwrap();
        assert_eq!(p.p2p_listen, "127.0.0.1:7500");
        assert_eq!(p.p2p_relays, vec![main.clone(), fallback.clone()]);

        // Refused, and nothing changed: a third address, junk, nothing, a
        // circuit.
        let before = std::fs::read(kept.path().join("node_policy.json")).unwrap();
        let third = format!("/ip4/203.0.113.9/tcp/7423/p2p/{}", peer_of(0x52));
        for bad in [
            vec![main.clone(), fallback.clone(), third],
            words(&["via=/ip4/198.51.100.7/tcp/7423"]),
            words(&["hello"]),
            words(&[" "]),
            vec![format!("{main}/p2p-circuit/p2p/{}", peer_of(0x53))],
        ] {
            assert!(
                cmd_relay_use_with(kept.path(), &bad, false, never).is_err(),
                "{bad:?}"
            );
            assert_eq!(
                std::fs::read(kept.path().join("node_policy.json")).unwrap(),
                before,
                "{bad:?}"
            );
        }
        let e = cmd_relay_use_with(
            kept.path(),
            &words(&[
                &main,
                &fallback,
                &format!("/ip4/203.0.113.9/tcp/1/p2p/{relay}"),
            ]),
            false,
            never,
        )
        .unwrap_err();
        assert!(e.contains("at most 2 relay addresses"), "{e}");

        // On a terminal, the UPnP question of `raven node p2p on` is asked
        // once, for 7423.
        let asked = tmp();
        let mut port = None;
        cmd_relay_use_with(asked.path(), &words(&[&main]), true, |p| {
            port = Some(p);
            Some("n".into())
        })
        .unwrap();
        assert_eq!(port, Some(DEFAULT_P2P_PORT));
        assert_eq!(try_load_policy(asked.path()).unwrap().upnp, Some(false));

        // What it says it saved: relays, not addresses.
        let vias = p2p_route::split_relay_tokens(&format!("{main} {fallback}")).unwrap();
        assert_eq!(
            relay_use_saved(&vias),
            "1 relay saved (2 addresses: the second address of the same relay is its fallback, \
             e.g. TCP 443)"
        );
        let two = format!("{main} /ip4/203.0.113.9/tcp/7423/p2p/{}", peer_of(0x52));
        assert_eq!(
            relay_use_saved(&p2p_route::split_relay_tokens(&two).unwrap()),
            "2 relays saved (2 addresses)"
        );
        assert_eq!(
            relay_use_saved(&p2p_route::split_relay_tokens(&main).unwrap()),
            "1 relay saved (1 address)"
        );

        // A dedicated relay folder is not a profile: refused, nothing saved.
        let relay_dir = tmp();
        std::fs::write(
            relay_dir.path().join(relay_allow::RELAY_KEY_FILE),
            [0u8; 32],
        )
        .unwrap();
        let e = cmd_relay_use_with(relay_dir.path(), &words(&[&main]), false, never).unwrap_err();
        assert!(e.contains("dedicated relay"), "{e}");
        assert!(!relay_dir.path().join("node_policy.json").exists());
    }

    /// `raven node p2p on --relay` takes a pasted card line as it is.
    #[test]
    fn resolve_relays_accepts_a_via_prefix() {
        let dir = tmp();
        let addr = format!("/ip4/198.51.100.7/tcp/7423/p2p/{}", peer_of(0x54));
        assert_eq!(
            resolve_relays(dir.path(), &[format!("via={addr}")]).unwrap(),
            vec![addr.clone()]
        );
        // Trimmed, and the same relay given twice is saved once.
        assert_eq!(
            resolve_relays(dir.path(), &[format!("  via={addr} "), addr.clone()]).unwrap(),
            vec![addr.clone()]
        );
        // A via= that is no relay address is refused as an address.
        let e = resolve_relays(dir.path(), &["via=/ip4/198.51.100.7/tcp/7423".into()]).unwrap_err();
        assert!(e.starts_with("--relay: "), "{e}");
    }

    /// A relay folder with a status (`raven-node relay` wrote it).
    fn relay_dir_with(advertised: &[&str], listen: &[&str]) -> (tempfile::TempDir, String) {
        let dir = tmp();
        std::fs::write(dir.path().join(relay_allow::RELAY_KEY_FILE), [0u8; 32]).unwrap();
        let peer = peer_of(0x55);
        relay_allow::write_relay_status(
            dir.path(),
            &relay_allow::RelayStatusFile {
                version: 1,
                peer_id: peer.clone(),
                listen_addrs: words(listen),
                advertised: words(advertised),
                ..Default::default()
            },
        )
        .unwrap();
        (dir, peer)
    }

    /// Relay kit: the card is made from the addresses the relay names for
    /// itself (`--public-host`, `--external`), else its listen addresses, in
    /// one order: TCP on the main port, TCP 443, QUIC. The `raven relay
    /// use` line takes the first two TCP lines.
    #[test]
    fn relay_card_prefers_advertised_and_orders_tcp_then_443_then_quic() {
        let listen = [
            "/ip4/192.168.1.5/udp/7423/quic-v1",
            "/ip4/192.168.1.5/tcp/7423",
            "/ip4/192.168.1.5/tcp/443",
        ];
        // The advertiser's set comes sorted, not in card order.
        let (dir, peer) = relay_dir_with(
            &[
                "/dns/relay.example.org/udp/7423/quic-v1",
                "/dns/relay.example.org/tcp/443",
                "/dns/relay.example.org/tcp/7423",
            ],
            &listen,
        );
        let src = CardSource::read(dir.path()).unwrap();
        let lines = relay_card_lines(&src, None, None, false).unwrap();
        assert_eq!(
            lines,
            [
                format!("/dns/relay.example.org/tcp/7423/p2p/{peer}"),
                format!("/dns/relay.example.org/tcp/443/p2p/{peer}"),
                format!("/dns/relay.example.org/udp/7423/quic-v1/p2p/{peer}"),
            ],
            "advertised only (no LAN address), QUIC without --quic"
        );
        assert_eq!(relay_use_pair(&lines), lines[..2]);

        // Nothing advertised: the listen addresses, in the same order;
        // unspecified addresses and circuits are never a card line.
        let (dir, peer) = relay_dir_with(
            &[],
            &[
                "/ip4/0.0.0.0/tcp/7423",
                "/ip6/::1/udp/7423/quic-v1",
                listen[0],
                listen[1],
                "/ip6/::1/tcp/443",
                listen[2],
                "/ip6/::1/tcp/7423",
                "/ip4/198.51.100.7/tcp/7423/p2p/12D3KooWInvalid/p2p-circuit",
            ],
        );
        let lines =
            relay_card_lines(&CardSource::read(dir.path()).unwrap(), None, None, false).unwrap();
        assert_eq!(
            lines,
            [
                format!("/ip4/192.168.1.5/tcp/7423/p2p/{peer}"),
                format!("/ip6/::1/tcp/7423/p2p/{peer}"),
                format!("/ip6/::1/tcp/443/p2p/{peer}"),
                format!("/ip4/192.168.1.5/tcp/443/p2p/{peer}"),
                format!("/ip6/::1/udp/7423/quic-v1/p2p/{peer}"),
                format!("/ip4/192.168.1.5/udp/7423/quic-v1/p2p/{peer}"),
            ]
        );
        // The fallback on the main line's host.
        assert_eq!(relay_use_pair(&lines), [lines[0].clone(), lines[3].clone()]);

        // No 443: one line to give, the main TCP one.
        let (dir, peer) = relay_dir_with(
            &[
                "/ip4/203.0.113.7/udp/7423/quic-v1",
                "/ip4/203.0.113.7/tcp/7423",
            ],
            &[],
        );
        let lines =
            relay_card_lines(&CardSource::read(dir.path()).unwrap(), None, None, false).unwrap();
        assert_eq!(
            relay_use_pair(&lines),
            [format!("/ip4/203.0.113.7/tcp/7423/p2p/{peer}")]
        );

        // Neither: nothing to give (cmd_relay_card then asks for --host).
        let (dir, _) = relay_dir_with(&[], &[]);
        let src = CardSource::read(dir.path()).unwrap();
        assert!(relay_card_lines(&src, None, None, true).unwrap().is_empty());
        assert!(relay_use_pair(&[]).is_empty());
        assert!(cmd_relay_card(dir.path(), None, None, false)
            .unwrap_err()
            .contains("--host"));
        // A folder whose relay never ran.
        let fresh = tmp();
        std::fs::write(fresh.path().join(relay_allow::RELAY_KEY_FILE), [0u8; 32]).unwrap();
        assert!(cmd_relay_card(fresh.path(), None, None, false)
            .unwrap_err()
            .contains("start the relay once first"));
    }

    /// `--host` keeps the relay's own transports and ports and replaces only
    /// the host (behind a router, the relay knows only its LAN address).
    #[test]
    fn relay_card_host_takes_ports_from_status() {
        let (dir, peer) = relay_dir_with(
            &[],
            &[
                "/ip4/192.168.1.5/tcp/7424",
                "/ip4/192.168.1.5/udp/7424/quic-v1",
                "/ip6/fd00::5/tcp/7424",
                "/ip4/192.168.1.5/tcp/443",
                "/ip4/192.168.1.5/tcp/7424/p2p-circuit",
            ],
        );
        let src = CardSource::read(dir.path()).unwrap();
        assert_eq!(
            relay_card_lines(&src, Some("203.0.113.9"), None, false).unwrap(),
            [
                format!("/ip4/203.0.113.9/tcp/7424/p2p/{peer}"),
                format!("/ip4/203.0.113.9/tcp/443/p2p/{peer}"),
                format!("/ip4/203.0.113.9/udp/7424/quic-v1/p2p/{peer}"),
            ]
        );
        assert_eq!(
            relay_card_lines(&src, Some("[2001:DB8::9]"), None, false).unwrap()[0],
            format!("/ip6/2001:db8::9/tcp/7424/p2p/{peer}")
        );
        // The host is checked like any route's: no unspecified address, no
        // junk.
        for bad in ["0.0.0.0", "[::]", "relay example", "/ip4/1.2.3.4"] {
            assert!(
                relay_card_lines(&src, Some(bad), None, false).is_err(),
                "{bad}"
            );
        }
        // A relay that names no port yet: 7423 (and QUIC with --quic).
        let none = CardSource {
            peer_id: peer.clone(),
            advertised: Vec::new(),
            listen: Vec::new(),
            extra_tcp: Vec::new(),
            friend: false,
        };
        assert_eq!(
            relay_card_lines(&none, Some("relay.example.org"), None, false).unwrap(),
            [format!("/dns/relay.example.org/tcp/7423/p2p/{peer}")]
        );
        assert_eq!(
            relay_card_lines(&none, Some("relay.example.org"), None, true).unwrap(),
            [
                format!("/dns/relay.example.org/tcp/7423/p2p/{peer}"),
                format!("/dns/relay.example.org/udp/7423/quic-v1/p2p/{peer}"),
            ]
        );
    }

    /// The kit's `RAVEN_RELAY_TCP443=7443` (`--also-tcp 7443:443`) behind
    /// a router, installed without RAVEN_RELAY_HOST: the relay knows only
    /// its LAN listeners, and `card --host` names the public port friends
    /// reach (443, which the router maps to 7443), never the local 7443.
    #[test]
    fn relay_card_host_names_the_public_port_of_a_mapped_port() {
        let dir = tmp();
        std::fs::write(dir.path().join(relay_allow::RELAY_KEY_FILE), [0u8; 32]).unwrap();
        let peer = peer_of(0x57);
        relay_allow::write_relay_status(
            dir.path(),
            &relay_allow::RelayStatusFile {
                version: 1,
                peer_id: peer.clone(),
                listen_addrs: words(&[
                    "/ip4/192.168.1.5/tcp/7423",
                    "/ip4/192.168.1.5/udp/7423/quic-v1",
                    "/ip4/192.168.1.5/tcp/7443",
                ]),
                extra_tcp: vec![p2p_route::ExtraTcp {
                    local: 7443,
                    public: 443,
                }],
                ..Default::default()
            },
        )
        .unwrap();
        let src = CardSource::read(dir.path()).unwrap();
        let lines = relay_card_lines(&src, Some("203.0.113.7"), None, false).unwrap();
        assert_eq!(
            lines,
            [
                format!("/ip4/203.0.113.7/tcp/7423/p2p/{peer}"),
                format!("/ip4/203.0.113.7/tcp/443/p2p/{peer}"),
                format!("/ip4/203.0.113.7/udp/7423/quic-v1/p2p/{peer}"),
            ]
        );
        assert_eq!(relay_use_pair(&lines), lines[..2]);
        // Without --host the LAN listeners stay as they are: a friend on
        // this network reaches 7443 itself.
        let lan = relay_card_lines(&src, None, None, false).unwrap();
        assert!(
            lan.contains(&format!("/ip4/192.168.1.5/tcp/7443/p2p/{peer}")),
            "{lan:?}"
        );
        // With --public-host the relay advertises 443 already: unchanged.
        let advertised = CardSource {
            advertised: words(&["/ip4/203.0.113.7/tcp/7423", "/ip4/203.0.113.7/tcp/443"]),
            ..CardSource::read(dir.path()).unwrap()
        };
        assert_eq!(
            relay_card_lines(&advertised, Some("relay.example.org"), None, false).unwrap(),
            [
                format!("/dns/relay.example.org/tcp/7423/p2p/{peer}"),
                format!("/dns/relay.example.org/tcp/443/p2p/{peer}"),
            ]
        );
    }

    /// The kit's 7443 mode on a VPS (its interface holds the public IP)
    /// installed without RAVEN_RELAY_HOST: the relay names its own global
    /// listen addresses, and the card without `--host` names the public 443
    /// for the mapped 7443 (the provider's firewall opens 443, never 7443),
    /// in the line for friends too; a LAN or loopback listener keeps its
    /// port. A card whose addresses are all loopback or LAN gives no `raven
    /// relay use` line without `--host`, and says to run it with `--host`.
    #[test]
    fn relay_card_without_host_names_the_public_port_and_never_a_local_use_line() {
        let peer = peer_of(0x58);
        let vps = CardSource {
            peer_id: peer.clone(),
            advertised: words(&[
                "/ip4/11.0.7.7/tcp/7423",
                "/ip4/11.0.7.7/tcp/7443",
                "/ip4/11.0.7.7/udp/7423/quic-v1",
            ]),
            listen: words(&[
                "/ip4/127.0.0.1/tcp/7423",
                "/ip4/127.0.0.1/tcp/7443",
                "/ip4/11.0.7.7/tcp/7423",
                "/ip4/11.0.7.7/tcp/7443",
                "/ip4/11.0.7.7/udp/7423/quic-v1",
            ]),
            extra_tcp: vec![p2p_route::ExtraTcp {
                local: 7443,
                public: 443,
            }],
            friend: false,
        };
        let lines = relay_card_lines(&vps, None, None, false).unwrap();
        assert_eq!(
            lines,
            [
                format!("/ip4/11.0.7.7/tcp/7423/p2p/{peer}"),
                format!("/ip4/11.0.7.7/tcp/443/p2p/{peer}"),
                format!("/ip4/11.0.7.7/udp/7423/quic-v1/p2p/{peer}"),
            ]
        );
        assert_eq!(relay_use_lines(&lines, false), lines[..2]);
        // An address the relay was told to name (`--public-host`, UPnP)
        // keeps its port: it is not one of this box's listen addresses.
        let told = CardSource {
            advertised: words(&["/ip4/198.51.100.20/tcp/7443"]),
            ..vps.clone()
        };
        assert_eq!(
            relay_card_lines(&told, None, None, false).unwrap(),
            [format!("/ip4/198.51.100.20/tcp/7443/p2p/{peer}")]
        );
        // Behind a router (LAN listeners only): the LAN port, and no line
        // to give friends without --host; with it, the operator's address.
        let lan = CardSource {
            advertised: Vec::new(),
            listen: words(&[
                "/ip4/192.168.1.5/tcp/7423",
                "/ip4/192.168.1.5/tcp/7443",
                "/ip4/127.0.0.1/tcp/7423",
            ]),
            ..vps.clone()
        };
        let lines = relay_card_lines(&lan, None, None, false).unwrap();
        assert!(
            lines.contains(&format!("/ip4/192.168.1.5/tcp/7443/p2p/{peer}")),
            "{lines:?}"
        );
        assert!(relay_use_lines(&lines, false).is_empty(), "{lines:?}");
        assert_eq!(relay_use_lines(&lines, true), relay_use_pair(&lines));
        let host = relay_card_lines(&lan, Some("203.0.113.7"), None, false).unwrap();
        assert_eq!(
            relay_use_lines(&host, true),
            [
                format!("/ip4/203.0.113.7/tcp/7423/p2p/{peer}"),
                format!("/ip4/203.0.113.7/tcp/443/p2p/{peer}"),
            ]
        );
        // A DNS name is a friend's to reach; a LAN line before a global
        // one never becomes the line to give.
        let mixed = [
            format!("/ip4/192.168.1.5/tcp/7423/p2p/{peer}"),
            format!("/dns/relay.example.org/tcp/7423/p2p/{peer}"),
        ];
        assert_eq!(relay_use_lines(&mixed, false), mixed[1..]);
        let text = no_use_line_text(7423);
        assert!(
            text.contains("raven relay card --host") && text.contains("port 7423"),
            "{text}"
        );
    }

    /// `wan_two_network_test.sh vps-relay` runs `raven relay card --host H
    /// --port P --quic`: an explicit --port prints exactly what it did
    /// before the relay kit.
    #[test]
    fn relay_card_explicit_port_keeps_the_old_output() {
        let peer = peer_of(0x56);
        let src = CardSource {
            peer_id: peer.clone(),
            advertised: words(&[
                "/dns/relay.example.org/tcp/443",
                "/dns/relay.example.org/tcp/7423",
            ]),
            listen: words(&[
                "/ip4/192.168.1.5/udp/7423/quic-v1",
                "/ip4/0.0.0.0/tcp/7423",
                "/ip4/192.168.1.5/tcp/7423",
                "/ip4/192.168.1.5/tcp/443",
            ]),
            extra_tcp: Vec::new(),
            friend: false,
        };
        assert_eq!(
            relay_card_lines(&src, Some("203.0.113.7"), Some(7423), true).unwrap(),
            [
                format!("/ip4/203.0.113.7/tcp/7423/p2p/{peer}"),
                format!("/ip4/203.0.113.7/udp/7423/quic-v1/p2p/{peer}"),
            ]
        );
        assert_eq!(
            relay_card_lines(&src, Some("203.0.113.7"), Some(4001), false).unwrap(),
            [format!("/ip4/203.0.113.7/tcp/4001/p2p/{peer}")]
        );
        // Without --host: the listen addresses as they come (QUIC only with
        // --quic), whatever is advertised.
        assert_eq!(
            relay_card_lines(&src, None, Some(7423), false).unwrap(),
            [
                format!("/ip4/192.168.1.5/tcp/7423/p2p/{peer}"),
                format!("/ip4/192.168.1.5/tcp/443/p2p/{peer}"),
            ]
        );
        assert_eq!(
            relay_card_lines(&src, None, Some(7423), true).unwrap(),
            [
                format!("/ip4/192.168.1.5/udp/7423/quic-v1/p2p/{peer}"),
                format!("/ip4/192.168.1.5/tcp/7423/p2p/{peer}"),
                format!("/ip4/192.168.1.5/tcp/443/p2p/{peer}"),
            ]
        );
    }

    /// Phase 4 (P4.16): `raven relay card --wss` prints `/tls/ws` lines that
    /// pass the via grammar: with `--host`, a name as `/dns/<name>` (also
    /// the name TLS asks for) on `--wss-port`, else the relay's own WSS
    /// port as friends reach it, else 443; without it, the relay's WSS
    /// listen addresses and never their raw siblings or a wildcard. The
    /// plain card never prints a `/tls/ws` listen form (P4.13).
    #[test]
    fn relay_card_wss_lines_parse_and_use_dns_for_names() {
        let peer = peer_of(0x5a);
        let src = CardSource {
            peer_id: peer.clone(),
            advertised: Vec::new(),
            listen: words(&[
                "/ip4/127.0.0.1/tcp/7423",
                "/ip4/127.0.0.1/udp/7423/quic-v1",
                "/ip4/0.0.0.0/tcp/443/tls/ws",
                "/ip4/11.0.7.7/tcp/7423",
                "/ip4/11.0.7.7/tcp/443",
                "/ip4/11.0.7.7/tcp/443/tls/ws",
                "/ip6/2001:db8::7/tcp/443",
                "/ip6/2001:db8::7/tcp/443/tls/ws",
            ]),
            extra_tcp: Vec::new(),
            friend: false,
        };
        let wss =
            |host: Option<&str>, port: Option<u16>| relay_card_wss_lines(&src, host, port).unwrap();
        assert_eq!(
            wss(Some("Relay.Example.org"), None),
            [format!("/dns/relay.example.org/tcp/443/tls/ws/p2p/{peer}")]
        );
        assert_eq!(
            wss(Some("relay.example.org"), Some(8443)),
            [format!("/dns/relay.example.org/tcp/8443/tls/ws/p2p/{peer}")]
        );
        assert_eq!(
            wss(Some("203.0.113.7"), None),
            [format!("/ip4/203.0.113.7/tcp/443/tls/ws/p2p/{peer}")]
        );
        assert_eq!(
            wss(Some("[2001:DB8::9]"), None),
            [format!("/ip6/2001:db8::9/tcp/443/tls/ws/p2p/{peer}")]
        );
        assert_eq!(
            wss(None, None),
            [
                format!("/ip4/11.0.7.7/tcp/443/tls/ws/p2p/{peer}"),
                format!("/ip6/2001:db8::7/tcp/443/tls/ws/p2p/{peer}"),
            ]
        );
        assert_eq!(
            wss(None, Some(8443))[0],
            format!("/ip4/11.0.7.7/tcp/8443/tls/ws/p2p/{peer}")
        );
        for lines in [
            wss(Some("relay.example.org"), None),
            wss(None, None),
            wss(Some("203.0.113.7"), Some(1)),
        ] {
            for line in &lines {
                let v = p2p_route::parse_via(line).unwrap();
                assert!(v.is_wss() && v.peer_id == peer && v.text == *line, "{line}");
            }
        }
        for bad in ["0.0.0.0", "relay example", "/ip4/1.2.3.4"] {
            assert!(
                relay_card_wss_lines(&src, Some(bad), None).is_err(),
                "{bad}"
            );
        }
        // The WSS listener of a mapped port names the public one; a relay
        // with no WSS listener yet: 443 with --host, nothing without.
        let mapped = CardSource {
            listen: words(&[
                "/ip4/192.168.1.5/tcp/7443",
                "/ip4/192.168.1.5/tcp/7443/tls/ws",
            ]),
            extra_tcp: vec![p2p_route::ExtraTcp {
                local: 7443,
                public: 443,
            }],
            ..src.clone()
        };
        assert_eq!(
            relay_card_wss_lines(&mapped, Some("relay.example.org"), None).unwrap(),
            [format!("/dns/relay.example.org/tcp/443/tls/ws/p2p/{peer}")]
        );
        let plain = CardSource {
            listen: words(&["/ip4/11.0.7.7/tcp/7423"]),
            ..src.clone()
        };
        assert!(relay_card_wss_lines(&plain, None, None).unwrap().is_empty());
        assert_eq!(
            relay_card_wss_lines(&plain, Some("relay.example.org"), None).unwrap(),
            [format!("/dns/relay.example.org/tcp/443/tls/ws/p2p/{peer}")]
        );
        // The plain card: never a `/tls/ws` listen form, in either mode
        // that reads the listen addresses.
        for lines in [
            relay_card_lines(&src, None, None, false).unwrap(),
            relay_card_lines(&src, None, Some(443), true).unwrap(),
        ] {
            assert!(lines.iter().all(|l| !l.contains("/tls")), "{lines:?}");
            assert!(
                lines.contains(&format!("/ip4/11.0.7.7/tcp/443/p2p/{peer}")),
                "{lines:?}"
            );
        }
        // A friend relay has no WSS listener; the gate's refusal is WSS_HOLD.
        assert!(RELAY_CARD_WSS_FRIEND.contains("raven-node relay --wss"));
        if !raven_core::wss_live_enabled() {
            let dir = tmp();
            let err = cmd_relay_card_wss(dir.path(), None, None).unwrap_err();
            assert_eq!(err, raven_core::WSS_HOLD);
        }
    }

    /// Phase 4 (P4.16): `raven node proxy` saves auto, off or
    /// http://host:port in canonical form, and refuses a user name or
    /// password (saving nothing) without repeating the text; so does every
    /// other refusal. Without a setting it shows the saved one and what the
    /// running raven-node uses (where its setting came from, its proxy
    /// word, a 407), never a credential: not even one a hand-edited
    /// node_policy.json holds.
    #[test]
    fn node_proxy_refuses_userinfo_and_shows_no_secrets() {
        let dir = tmp();
        let down: Result<IpcResponse, String> = Err("raven-node is not running".into());
        let secret = "s3cretPW";
        for text in [
            format!("http://alice:{secret}@proxy.example:3128"),
            format!("alice:{secret}@proxy.example"),
            format!("http://{secret}@proxy.example:3128"),
            format!("auto@{secret}"),
        ] {
            let err = node_proxy_set(dir.path(), &text, &down).unwrap_err();
            assert_eq!(err, NODE_PROXY_NO_SECRETS);
        }
        assert!(NODE_PROXY_NO_SECRETS.contains(
            "set them in the service's RAVEN_P2P_PROXY; node_policy.json holds no secrets"
        ));
        assert!(!NODE_PROXY_NO_SECRETS.contains(secret));
        assert!(!dir.path().join(POLICY_FILE).exists(), "nothing saved");
        for (text, says) in [
            (
                "https://proxy.example:3128",
                "https:// proxies are not supported",
            ),
            (
                "socks5://proxy.example:1080",
                "SOCKS proxies are not supported",
            ),
            (
                "http://proxy.example/wpad.dat",
                "(PAC, WPAD) is not supported",
            ),
            ("http://proxy.example:99999", "not a proxy setting (port)"),
            ("ftp://proxy.example", "not a proxy setting (scheme)"),
        ] {
            let err = node_proxy_set(dir.path(), text, &down).unwrap_err();
            assert!(err.contains(says), "{text}: {err}");
            assert!(err.ends_with("(nothing changed)"), "{err}");
            assert!(!err.contains("proxy.example"), "{err}");
        }
        assert!(!dir.path().join(POLICY_FILE).exists(), "nothing saved");

        let saved = |dir: &Path| try_load_policy(dir).unwrap().p2p_proxy;
        let lines = node_proxy_set(dir.path(), "  HTTP://Proxy.Example:3128/ ", &down).unwrap();
        assert!(
            lines[0].starts_with("ok proxy=http://proxy.example:3128 saved in "),
            "{lines:?}"
        );
        assert!(lines[1].starts_with("raven-node applies it when it (re)starts: "));
        assert_eq!(saved(dir.path()), "http://proxy.example:3128");
        assert_eq!(
            lines
                .iter()
                .any(|l| l.contains("WSS_PROXY_PRODUCTION_ENABLED=false")),
            !raven_core::wss_proxy_live_enabled()
        );
        let off = node_proxy_set(dir.path(), "OFF", &down).unwrap();
        assert_eq!(saved(dir.path()), "off");
        assert!(!off.iter().any(|l| l.contains("WSS_PROXY_PRODUCTION")));
        node_proxy_set(dir.path(), "auto", &down).unwrap();
        assert_eq!(saved(dir.path()), "");
        let raw = std::fs::read_to_string(dir.path().join(POLICY_FILE)).unwrap();
        assert!(!raw.contains("p2p_proxy"), "auto is none: {raw}");

        // Shown.
        let shown = node_proxy_show(dir.path(), &down);
        assert_eq!(
            shown[0],
            "saved       auto (HTTPS_PROXY, then the system settings)"
        );
        assert_eq!(
            shown[1],
            "raven-node  not running (it applies the saved setting when it starts)"
        );
        assert!(shown
            .last()
            .unwrap()
            .starts_with("change it: raven node proxy auto|off"));
        node_proxy_set(dir.path(), "[2001:DB8::3]:8080", &down).unwrap();
        assert_eq!(
            node_proxy_show(dir.path(), &down)[0],
            "saved       http://[2001:db8::3]:8080"
        );
        // A credential in a hand-edited node_policy.json: redacted.
        std::fs::write(
            dir.path().join(POLICY_FILE),
            format!(r#"{{"p2p_proxy":"http://alice:{secret}@proxy.example:3128"}}"#),
        )
        .unwrap();
        let shown = node_proxy_show(dir.path(), &down).join("\n");
        assert!(
            shown.contains("saved       http://<redacted>@proxy.example:3128"),
            "{shown}"
        );
        assert!(
            !shown.contains(secret) && !shown.contains("alice"),
            "{shown}"
        );
        std::fs::write(
            dir.path().join(POLICY_FILE),
            r#"{"p2p_proxy":"socks5://x:1"}"#,
        )
        .unwrap();
        assert_eq!(
            node_proxy_show(dir.path(), &down)[0],
            "saved       unusable (socks)"
        );

        // The running raven-node: where its setting came from and its word.
        let node = |source: &str, f: &dyn Fn(&mut P2pStatusInfo)| {
            status(Some(up_with(|i| {
                i.listen_setting = "7423".into();
                i.proxy_source = source.into();
                f(i);
            })))
        };
        let said = |daemon: &Result<IpcResponse, String>| node_proxy_show(dir.path(), daemon);
        for (word, says) in [
            ("", "no proxy: relay dials over WebSocket/TLS go direct"),
            ("setting", "go through the proxy set"),
            (
                "env",
                "go through the proxy in its environment (HTTPS_PROXY or ALL_PROXY)",
            ),
            ("system", "go through this computer's system proxy"),
            (
                "held",
                "lab-only in this build (WSS_PROXY_PRODUCTION_ENABLED=false)",
            ),
            (
                "unsupported: pac",
                "your system uses a proxy script (PAC), which Raven cannot read",
            ),
            ("unsupported: https", "one Raven cannot use (https)"),
        ] {
            let text = proxy_word_text(word);
            assert!(text.contains(says), "{word}: {text}");
            let lines = said(&node("node_policy.json", &|i| i.proxy = word.into()));
            assert_eq!(
                lines[1],
                format!("raven-node  uses the setting from node_policy.json; {text}")
            );
        }
        let ntlm = said(&node("RAVEN_P2P_PROXY", &|i| {
            i.proxy = "setting".into();
            i.proxy_auth = "unsupported".into();
        }));
        assert!(ntlm[1].starts_with("raven-node  uses the setting from RAVEN_P2P_PROXY;"));
        assert_eq!(
            ntlm[2],
            "note: the HTTPS proxy needs Windows sign-in (NTLM/Kerberos), not supported"
        );
        let flag = node("--p2p-proxy", &|i| i.proxy = "setting".into());
        let set = node_proxy_set(dir.path(), "off", &flag).unwrap();
        assert!(
            set.contains(
                &"note: the running raven-node takes its proxy setting from --p2p-proxy, which \
                  comes before node_policy.json"
                    .to_string()
            ),
            "{set:?}"
        );
        let from_policy = node("node_policy.json", &|_| {});
        assert!(!node_proxy_set(dir.path(), "off", &from_policy)
            .unwrap()
            .iter()
            .any(|l| l.contains("comes before")));
        for (daemon, says) in [
            (
                node("", &|_| {}),
                "an older raven-node: it does not say which proxy it uses",
            ),
            (
                node("node_policy.json", &|i| i.listen_setting.clear()),
                "p2p is off, so it dials no relay",
            ),
            (
                node("node_policy.json", &|i| i.up = false),
                "the libp2p host is not up",
            ),
            (
                node("node_policy.json", &|i| {
                    i.up = false;
                    i.held = true;
                }),
                "P2P_HOLD",
            ),
            (status(None), "p2p is off, so it dials no relay"),
            (Err("garbled".into()), "does not answer"),
        ] {
            let line = &said(&daemon)[1];
            assert!(line.contains(says), "{says}: {line}");
        }
        // A hostile word is shown terminal-safe.
        let odd = said(&node("node_policy.json", &|i| {
            i.proxy = "unsupported: \u{1b}[2Jx".into()
        }));
        assert!(!odd[1].contains('\u{1b}'), "{odd:?}");

        // The clap side: the setting is optional.
        use clap::Parser;
        let proxy = |args: &[&str]| match super::super::Cli::try_parse_from(
            ["raven", "node", "proxy"].iter().chain(args).copied(),
        )
        .map(|c| c.cmd)
        {
            Ok(Some(super::super::Commands::Node {
                cmd: super::super::NodeCommands::Proxy { setting },
            })) => setting,
            other => panic!("{other:?}"),
        };
        assert_eq!(proxy(&[]), None);
        assert_eq!(proxy(&["off"]).as_deref(), Some("off"));
        assert_eq!(
            proxy(&["http://proxy.example:3128"]).as_deref(),
            Some("http://proxy.example:3128")
        );
    }

    /// Phase 4 (P4.16): the `p2p` row says how the relays travel (over WSS,
    /// through the HTTPS proxy) and whether the network is restricted, and
    /// what keeps relays out of reach: a proxy script (PAC), a 407 Raven
    /// cannot answer (NTLM or Negotiate), a missing or refused password, a
    /// proxy Raven cannot use, or, while WSS is held, a network that may let
    /// only web traffic out. The doctor gets the proxy and the web-only
    /// parts apart. An older raven-node reports none of it: the row is the
    /// one it gave before.
    #[test]
    fn p2p_reach_row_names_wss_proxy_restricted_and_pac_hints() {
        let reserved = |f: &dyn Fn(&mut P2pStatusInfo)| {
            up_with(|i| {
                i.reach = "relayed".into();
                i.reservations = vec!["/ip4/198.51.100.7/tcp/443/p2p/R".into()];
                i.relay_health = vec![RelayHealth {
                    state: "reserved".into(),
                    ..RelayHealth::default()
                }];
                f(i);
            })
        };
        let row = |info: P2pStatusInfo| p2p_reach_row(&status(Some(info)), "7423", true);
        let before = "YES \u{2014} the libp2p host is up (reachability: relayed; reservations 1/1";
        // An older raven-node: as before.
        assert_eq!(row(reserved(&|_| {})), format!("{before})"));
        assert_eq!(
            row(reserved(&|i| {
                i.relay_paths = vec!["wss-proxy".into()];
                i.restricted = true;
                i.proxy = "env".into();
            })),
            format!(
                "{before}; relay over WSS through the HTTPS proxy; restricted network (relay only))"
            )
        );
        assert_eq!(
            row(reserved(
                &|i| i.relay_paths = vec!["tcp".into(), "wss".into()]
            )),
            format!("{before}; relay over WSS)")
        );
        assert_eq!(
            row(reserved(
                &|i| i.relay_paths = vec!["tcp".into(), String::new()]
            )),
            format!("{before})")
        );

        // Every relay failing.
        let failing = |f: &dyn Fn(&mut P2pStatusInfo)| {
            up_with(|i| {
                i.reach = "unreachable".into();
                i.relay_health = vec![
                    RelayHealth {
                        state: "retrying".into(),
                        tries: 3,
                        ..RelayHealth::default()
                    };
                    2
                ];
                f(i);
            })
        };
        let pac = failing(&|i| i.proxy = "unsupported: pac".into());
        let pac_text = "your system uses a proxy script (PAC), which Raven cannot read: `raven \
                        node proxy http://host:port`";
        assert!(
            row(pac.clone()).ends_with(&format!("; {pac_text})")),
            "{}",
            row(pac.clone())
        );
        assert_eq!(proxy_hint(&pac).as_deref(), Some(pac_text));
        for (auth, says) in [
            (
                "unsupported",
                "the HTTPS proxy needs Windows sign-in (NTLM/Kerberos), not supported",
            ),
            (
                "basic",
                "wants a user name and password: give them in the service's RAVEN_P2P_PROXY",
            ),
            (
                "refused",
                "refused the user name and password in the service's RAVEN_P2P_PROXY",
            ),
            (
                "other",
                "the HTTPS proxy wants a sign-in Raven cannot do (only a user name and password, \
                 Basic, is supported)",
            ),
        ] {
            let info = failing(&|i| {
                i.proxy = "setting".into();
                i.proxy_auth = auth.into();
            });
            let hint = proxy_hint(&info).unwrap();
            assert!(hint.contains(says), "{auth}: {hint}");
            assert_eq!(
                restrictive_hint(&info, false),
                Some(hint.clone()),
                "before web-only"
            );
            assert!(row(info).contains(&hint));
            // Review B-2: a node that holds a reservation is reachable; an
            // earlier 407 is no next step.
            let held = reserved(&|i| {
                i.proxy = "setting".into();
                i.proxy_auth = auth.into();
            });
            assert_eq!(proxy_hint(&held), None, "{auth}");
            assert_eq!(restrictive_hint(&held, false), None, "{auth}");
            assert!(!row(held).contains(&hint), "{auth}");
        }
        // Review B-6: a refused password is named where it came from.
        for (proxy, source, place) in [
            ("env", "", "HTTPS_PROXY or ALL_PROXY"),
            ("setting", "--p2p-proxy", "--p2p-proxy"),
            ("setting", "RAVEN_P2P_PROXY", "RAVEN_P2P_PROXY"),
        ] {
            let info = failing(&|i| {
                i.proxy = proxy.into();
                i.proxy_source = source.into();
                i.proxy_auth = "refused".into();
            });
            assert_eq!(
                proxy_hint(&info).unwrap(),
                format!(
                    "the HTTPS proxy refused the user name and password in the service's {place}"
                )
            );
        }
        let pac_held = reserved(&|i| i.proxy = "unsupported: pac".into());
        assert_eq!(proxy_hint(&pac_held), None, "dials go direct and work");
        let socks = failing(&|i| i.proxy = "unsupported: socks".into());
        assert!(proxy_hint(&socks)
            .unwrap()
            .starts_with("the proxy raven-node found is one Raven cannot use (socks)"));
        let hostile = failing(&|i| i.proxy = "unsupported: \u{1b}[2J".into());
        assert!(!row(hostile).contains('\u{1b}'));

        // A network that may let only web traffic out: only while WSS is
        // held, every slot retrying and none reserved.
        let blocked = failing(&|_| {});
        assert_eq!(proxy_hint(&blocked), None);
        assert_eq!(
            web_only_hint(&blocked, false).as_deref(),
            Some(WEB_ONLY_HINT)
        );
        assert_eq!(web_only_hint(&blocked, true), None, "WSS live");
        assert_eq!(
            restrictive_hint(&blocked, false).as_deref(),
            Some(WEB_ONLY_HINT)
        );
        assert_eq!(
            row(blocked.clone()).ends_with(&format!("; {WEB_ONLY_HINT})")),
            !raven_core::wss_live_enabled()
        );
        let waiting = failing(&|i| i.relay_health[1].state = "waiting".into());
        assert_eq!(web_only_hint(&waiting, false), None);
        assert_eq!(web_only_hint(&reserved(&|_| {}), false), None);
        assert_eq!(web_only_hint(&up_with(|_| {}), false), None, "no relay");
        assert_eq!(
            WEB_ONLY_HINT,
            "this network may allow only web traffic; WSS relays are lab-only in this build"
        );
    }

    /// Cards on the allow-list are checked like contact cards: the card's
    /// fingerprint is always printed, and on a terminal the operator
    /// confirms once (Enter is no). Off a terminal nothing is asked, as
    /// before (the harness and the netns script).
    #[test]
    fn relay_allow_prints_the_fingerprint_and_asks_only_on_a_tty() {
        // A lab card's routes (cards carry none outside the lab: card_routes_live).
        let _card_routes = super::super::CardRoutesForTest::set(true);
        let friend = raven_core::Identity::from_seed(&[0x61; 32]);
        let peer = p2p_route::local_peer_id(&friend);
        let card = p2p_card(0x61);
        let fp = raven_core::fingerprint::device_fingerprint_v1(&friend.public_key_bytes());
        let line = allow_card_fingerprint(&fp);
        assert!(line.starts_with(&format!("fingerprint={fp} ")), "{line}");
        assert!(line.contains("in person or by voice"), "{line}");
        assert_eq!(
            card_peer_id(super::super::read_card_arg(&card).unwrap()).unwrap(),
            (peer.clone(), fp.clone())
        );
        let allowed = |dir: &Path| {
            relay_allow::load_relay_allow(dir)
                .unwrap()
                .is_some_and(|l| l.contains(&peer))
        };

        // Not a terminal: never asked.
        let dir = tmp();
        cmd_relay_allow_with(dir.path(), None, Some(&card), "", false, |_: &str| {
            panic!("no prompt off a terminal")
        })
        .unwrap();
        assert!(allowed(dir.path()));

        // On a terminal: Enter, EOF or anything but yes allows nobody.
        let dir = tmp();
        for answer in [Some(""), None, Some("n"), Some("maybe")] {
            let mut asked = String::new();
            cmd_relay_allow_with(dir.path(), None, Some(&card), "bob", true, |q: &str| {
                asked = q.to_string();
                answer.map(String::from)
            })
            .unwrap();
            assert_eq!(asked, "Allow bob to use this relay? [y/N] ");
            assert_eq!(relay_allow::load_relay_allow(dir.path()).unwrap(), None);
        }
        // Yes: allowed. Without a label the question names the PeerId.
        cmd_relay_allow_with(dir.path(), None, Some(&card), "", true, |q: &str| {
            assert_eq!(q, allow_question(&peer));
            Some(" Yes ".into())
        })
        .unwrap();
        assert!(allowed(dir.path()));

        // A PeerId (or a contact) is not a card: never asked.
        let other = peer_of(0x62);
        cmd_relay_allow_with(dir.path(), Some(&other), None, "", true, |_: &str| {
            panic!("a PeerId is not asked about")
        })
        .unwrap();
        assert!(relay_allow::load_relay_allow(dir.path())
            .unwrap()
            .unwrap()
            .contains(&other));
    }

    /// `--cards FILE`: every line is checked before anything is written;
    /// one bad line allows nobody.
    #[test]
    fn relay_allow_cards_file_is_all_or_nothing() {
        // A lab card's routes (cards carry none outside the lab: card_routes_live).
        let _card_routes = super::super::CardRoutesForTest::set(true);
        let dir = tmp();
        let files = tmp();
        let good = format!(
            "# my circle\n\n{}\n   {}   \r\n{}\n",
            p2p_card(0x71),
            p2p_card(0x72),
            p2p_card(0x71)
        );
        let v1 = super::super::format_card_with(
            &raven_core::Identity::from_seed(&[0x73; 32]),
            "",
            "",
            None,
        );
        for bad in [
            "raven-card/2 nonsense".to_string(),
            v1,
            "hello".to_string(),
            "/ip4/198.51.100.7/tcp/7423".to_string(),
        ] {
            let path = files.path().join("bad.cards");
            std::fs::write(&path, format!("{good}{bad}\n")).unwrap();
            let e = cmd_relay_allow_cards(dir.path(), &path, "").unwrap_err();
            assert!(e.starts_with("--cards line 6: "), "{e}");
            assert!(e.contains("nobody was allowed"), "{e}");
            assert_eq!(
                relay_allow::load_relay_allow(dir.path()).unwrap(),
                None,
                "{bad}"
            );
        }
        // Comments only, a missing file, a folder: refused.
        let empty = files.path().join("empty.cards");
        std::fs::write(&empty, "# nobody yet\n\n").unwrap();
        for path in [
            empty,
            files.path().join("missing.cards"),
            files.path().to_path_buf(),
        ] {
            assert!(cmd_relay_allow_cards(dir.path(), &path, "").is_err());
        }
        // More cards than an allow-list holds: refused before any is read
        // further.
        let many = format!("{}\n", p2p_card(0x71)).repeat(relay_allow::MAX_ALLOW_ENTRIES + 1);
        assert!(parse_cards_text(&many)
            .unwrap_err()
            .contains("more than 1024 cards"));
        assert_eq!(relay_allow::load_relay_allow(dir.path()).unwrap(), None);

        // A good file: everyone on it, once, with the label.
        let path = files.path().join("circle.cards");
        std::fs::write(&path, &good).unwrap();
        cmd_relay_allow_cards(dir.path(), &path, "circle").unwrap();
        let list = relay_allow::load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.peers.len(), 2);
        assert!(list.contains(&peer_of(0x71)) && list.contains(&peer_of(0x72)));
        assert!(list.peers.iter().all(|e| e.label == "circle"));
        // Again: nothing new, still fine.
        cmd_relay_allow_cards(dir.path(), &path, "").unwrap();
        assert_eq!(
            relay_allow::load_relay_allow(dir.path())
                .unwrap()
                .unwrap()
                .peers
                .len(),
            2
        );
    }

    /// An installed relay's folder belongs to its own account: `raven relay
    /// allow|deny` there as anyone else is refused, and the refusal names
    /// the `raven-relay` wrapper. Skipped as root (or as the owner of `/`).
    #[cfg(unix)]
    #[test]
    fn a_foreign_owned_relay_folder_is_refused() {
        // A lab card's routes (cards carry none outside the lab: card_routes_live).
        let _card_routes = super::super::CardRoutesForTest::set(true);
        use std::os::unix::fs::MetadataExt;
        let foreign = Path::new("/");
        let euid = std::fs::metadata(tmp().path()).unwrap().uid();
        if euid == 0 || std::fs::metadata(foreign).unwrap().uid() == euid {
            eprintln!("running as the owner of /: skipped");
            return;
        }
        let peer = peer_of(0x81);
        let files = tmp();
        let cards = files.path().join("one.cards");
        std::fs::write(&cards, p2p_card(0x81)).unwrap();
        for e in [
            cmd_relay_allow(foreign, Some(&peer), None, "").unwrap_err(),
            cmd_relay_allow_with(
                foreign,
                None,
                Some(&p2p_card(0x81)),
                "",
                false,
                |_: &str| None,
            )
            .unwrap_err(),
            cmd_relay_allow_cards(foreign, &cards, "").unwrap_err(),
            cmd_relay_deny(foreign, &peer).unwrap_err(),
        ] {
            assert!(e.contains("belongs to another account"), "{e}");
            assert!(e.contains("raven-relay"), "{e}");
        }
    }

    /// `raven relay schedule` and `raven relay allow --schedule`: refused
    /// while rotation is off or outside a profile; the line names this
    /// profile's PeerIds from the epoch in use; a relay folder allows each
    /// until a week after its epoch's latest end, all or nothing, again
    /// without change; and the clap side (epochs 1 to 13, --schedule alone).
    #[test]
    fn relay_schedule_and_allow_schedule_commands() {
        use raven_core::peer_rotation as pr;
        let profile = tempfile::tempdir().unwrap();
        let relay = tempfile::tempdir().unwrap();
        std::fs::write(relay.path().join(relay_allow::RELAY_KEY_FILE), [1u8; 32]).unwrap();
        let id = raven_core::Identity::from_seed(&[0x5c; 32]);
        let now = now_ms();
        let unused = || -> Result<Option<raven_core::Identity>, String> {
            panic!("identity read although refused")
        };
        // Rotation off: refused with the reason, nothing read.
        let e = relay_schedule_text(profile.path(), 7, false, now, None, unused).unwrap_err();
        assert!(e.contains("does not rotate"), "{e}");
        assert!(e.contains("PEER_ROTATION_HOLD"), "{e}");
        let e = relay_schedule_text(relay.path(), 7, true, now, None, unused).unwrap_err();
        assert!(e.contains("relay folder"), "{e}");
        // The profile's own setting is off (P4.28): refused too.
        let e = relay_schedule_text(profile.path(), 7, true, now, None, unused).unwrap_err();
        assert!(e.contains("rotation is off"), "{e}");
        assert!(e.contains("raven node p2p rotate on"), "{e}");
        node_p2p_rotate_with(profile.path(), true, true).unwrap();
        let e = relay_schedule_text(profile.path(), 7, true, now, None, || Ok(None)).unwrap_err();
        assert!(e.contains("no identity"), "{e}");
        // The line: 7 epochs (the default) from the one in use now.
        let len = pr::epoch_len_s();
        let active = pr::epoch_at(&id, now / 1000, len);
        let me = || Ok(Some(raven_core::Identity::from_seed(&[0x5c; 32])));
        let text = relay_schedule_text(
            profile.path(),
            RELAY_SCHEDULE_DEFAULT_EPOCHS,
            true,
            now,
            None,
            me,
        )
        .unwrap();
        let entries = pr::parse_relay_schedule(&text).unwrap();
        assert_eq!(entries.len(), 7);
        for (i, (e, peer)) in entries.iter().enumerate() {
            assert_eq!(*e, active + i as u64);
            assert_eq!(*peer, pr::epoch_peer_id(&id, *e));
        }
        let long = relay_schedule_text(profile.path(), 13, true, now, None, me);
        assert_eq!(pr::parse_relay_schedule(&long.unwrap()).unwrap().len(), 13);
        // A postponed raven-node keeps an earlier epoch: the line starts
        // there (never later than the clock's).
        let back = relay_schedule_text(profile.path(), 2, true, now, Some(active - 1), me);
        let back = pr::parse_relay_schedule(&back.unwrap()).unwrap();
        assert_eq!(back[0].0, active - 1);
        let ahead = relay_schedule_text(profile.path(), 2, true, now, Some(active + 5), me);
        assert_eq!(
            pr::parse_relay_schedule(&ahead.unwrap()).unwrap()[0].0,
            active
        );

        // The relay side: every PeerId allowed until a week after its
        // epoch's latest end.
        let lines = relay_allow_schedule_with(relay.path(), &format!("{text}\n"), "dana").unwrap();
        assert_eq!(lines.len(), 8, "{lines:?}");
        assert!(
            lines[7].contains("7 allowed, 0 already allowed, 0 expired"),
            "{lines:?}"
        );
        assert!(
            lines[0].starts_with(&format!("epoch {active}: 12D3KooW")),
            "{lines:?}"
        );
        assert!(lines[0].contains("more day(s)"), "{lines:?}");
        let list = relay_allow::load_relay_allow(relay.path())
            .unwrap()
            .unwrap();
        assert_eq!(list.peers.len(), 7);
        for (entry, (e, peer)) in list.peers.iter().zip(&entries) {
            assert_eq!(entry.peer_id, *peer);
            assert_eq!(entry.label, "dana");
            assert_eq!(
                entry.expires_ms,
                Some(pr::latest_epoch_end_ms(*e, len) + relay_allow::SCHEDULE_GRACE_MS)
            );
        }
        let rows = allow_list_rows(&Ok(Some(list.clone())), false);
        assert!(rows[1].1.contains("[for "), "{rows:?}");
        // Again: no change.
        let lines = relay_allow_schedule_with(relay.path(), &text, "").unwrap();
        assert!(
            lines[7].contains("0 allowed, 7 already allowed"),
            "{lines:?}"
        );
        assert_eq!(
            relay_allow::load_relay_allow(relay.path())
                .unwrap()
                .unwrap(),
            list
        );
        // A bad line writes nothing.
        let before = std::fs::read(relay_allow::relay_allow_path(relay.path())).unwrap();
        for bad in [
            "",
            "raven-relay-schedule/2 1:x",
            &text.replace(' ', "  ").replace(":12D3", ":12d3"),
        ] {
            let e = relay_allow_schedule_with(relay.path(), bad, "").unwrap_err();
            assert!(e.starts_with("--schedule: "), "{e}");
        }
        assert_eq!(
            std::fs::read(relay_allow::relay_allow_path(relay.path())).unwrap(),
            before
        );

        // --schedule's argument: the line itself or a file (stdin is `-`).
        assert_eq!(read_schedule_arg(&format!(" {text} ")).unwrap(), text);
        let file = profile.path().join("friend.schedule");
        std::fs::write(&file, format!("{text}\n")).unwrap();
        assert_eq!(
            read_schedule_arg(file.to_str().unwrap()).unwrap().trim(),
            text
        );
        std::fs::write(&file, vec![b' '; SCHEDULE_INPUT_MAX_BYTES as usize + 1]).unwrap();
        let e = read_schedule_arg(file.to_str().unwrap()).unwrap_err();
        assert!(e.contains("not a schedule file"), "{e}");
        let e = read_schedule_arg("no-such-file").unwrap_err();
        assert!(e.contains("neither a schedule line"), "{e}");

        // The clap side.
        use clap::Parser;
        let parse = |args: &[&str]| {
            super::super::Cli::try_parse_from(std::iter::once("raven").chain(args.iter().copied()))
                .map(|c| c.cmd)
        };
        use super::super::{Commands, RelayCommands as R};
        match parse(&["relay", "schedule"]) {
            Ok(Some(Commands::Relay {
                cmd: R::Schedule { epochs: 7 },
            })) => {}
            other => panic!("{other:?}"),
        }
        match parse(&["relay", "schedule", "--epochs", "13"]) {
            Ok(Some(Commands::Relay {
                cmd: R::Schedule { epochs: 13 },
            })) => {}
            other => panic!("{other:?}"),
        }
        assert!(parse(&["relay", "schedule", "--epochs", "14"]).is_err());
        assert!(parse(&["relay", "schedule", "--epochs", "0"]).is_err());
        match parse(&["relay", "allow", "--schedule", "-", "--label", "dana"]) {
            Ok(Some(Commands::Relay {
                cmd:
                    R::Allow {
                        who: None,
                        card: None,
                        cards: None,
                        schedule: Some(source),
                        label,
                    },
            })) => assert_eq!((source.as_str(), label.as_str()), ("-", "dana")),
            other => panic!("{other:?}"),
        }
        assert!(parse(&["relay", "allow", "@bob", "--schedule", "-"]).is_err());
        assert!(parse(&["relay", "allow", "--cards", "f", "--schedule", "-"]).is_err());
        assert!(parse(&["relay", "allow", "--card", "c", "--schedule", "-"]).is_err());
    }

    /// The clap side of the relay kit's commands.
    #[test]
    fn relay_commands_parse_use_cards_and_an_optional_port() {
        use clap::Parser;
        let parse = |args: &[&str]| {
            super::super::Cli::try_parse_from(std::iter::once("raven").chain(args.iter().copied()))
        };
        let relay = |args: &[&str]| match parse(args).map(|c| c.cmd) {
            Ok(Some(super::super::Commands::Relay { cmd })) => Ok(cmd),
            Ok(other) => panic!("{other:?}"),
            Err(e) => Err(e.kind()),
        };
        use super::super::RelayCommands as R;
        match relay(&["relay", "use", "via=/a", "via=/b"]) {
            Ok(R::Use { addrs }) => assert_eq!(addrs, ["via=/a", "via=/b"]),
            other => panic!("{other:?}"),
        }
        assert!(relay(&["relay", "use"]).is_err(), "use needs an address");
        match relay(&["relay", "allow", "--cards", "circle.cards"]) {
            Ok(R::Allow {
                who: None,
                card: None,
                cards: Some(f),
                ..
            }) => assert_eq!(f, Path::new("circle.cards")),
            other => panic!("{other:?}"),
        }
        assert!(relay(&["relay", "allow", "@bob", "--cards", "f"]).is_err());
        assert!(relay(&["relay", "allow", "--card", "c", "--cards", "f"]).is_err());
        match relay(&["relay", "card"]) {
            Ok(R::Card { port: None, .. }) => {}
            other => panic!("{other:?}"),
        }
        match relay(&["relay", "card", "--host", "h", "--port", "7423", "--quic"]) {
            Ok(R::Card {
                port: Some(7423),
                quic: true,
                wss: false,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        // Phase 4 (P4.16): --wss, with its own port; not with --port or
        // --quic, and --wss-port only with --wss.
        match relay(&[
            "relay",
            "card",
            "--wss",
            "--host",
            "h",
            "--wss-port",
            "8443",
        ]) {
            Ok(R::Card {
                wss: true,
                wss_port: Some(8443),
                port: None,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        for bad in [
            &["relay", "card", "--wss-port", "443"][..],
            &["relay", "card", "--wss", "--port", "443"],
            &["relay", "card", "--wss", "--quic"],
        ] {
            assert!(relay(bad).is_err(), "{bad:?}");
        }
    }

    // ── Phase 2: the friend relay in ash (P2.22) ────────────────────────────

    use raven_core::ipc::FriendRelayInfo;

    fn never_asked(_: &str) -> Option<String> {
        panic!("must not ask")
    }

    /// A running node of reach class `class` whose friend relay is `fr`.
    fn node_with(class: &str, fr: Option<FriendRelayInfo>) -> Result<IpcResponse, String> {
        status(Some(up_with(|i| {
            i.reach = class.into();
            i.nat = if class == "public" {
                "public"
            } else {
                "unknown"
            }
            .into();
            i.friend_relay = fr;
        })))
    }

    /// The friend relay as a raven-node with its gate open reports it.
    fn friend(state: &str, consent: &str) -> FriendRelayInfo {
        FriendRelayInfo {
            state: state.into(),
            consent: consent.into(),
            port: FRIEND_RELAY_PORT,
            ..FriendRelayInfo::default()
        }
    }

    /// Owner decision 7: asked once, only on a terminal, only while the
    /// running node is confirmed public, never while relaying is held (the
    /// build, the running raven-node or hide my IP); a saved answer is kept.
    #[test]
    fn relay_offer_is_asked_once_only_on_a_public_node_and_a_terminal() {
        let never = || -> Option<String> { panic!("must not ask") };
        use ReachClass::{Mapped, Public, Relayed, Unknown, Unreachable};
        // (saved, class, tty, held): nothing asked, the saved answer kept.
        for (saved, class, tty, held) in [
            (Some(true), Public, true, false),
            (Some(false), Public, true, false),
            (None, Mapped, true, false),
            (None, Relayed, true, false),
            (None, Unreachable, true, false),
            (None, Unknown, true, false),
            (None, Public, false, false),
            (None, Public, true, true),
            (Some(false), Public, false, true),
        ] {
            assert_eq!(
                relay_offer_decision(saved, class, tty, held, never),
                (saved, false),
                "{saved:?} {class:?} tty={tty} held={held}"
            );
        }
        // Asked: y / yes is yes; Enter, EOF and anything else are no.
        for (answer, want) in [
            (Some("y"), true),
            (Some(" Yes "), true),
            (Some(""), false),
            (None, false),
            (Some("no"), false),
            (Some("sure"), false),
        ] {
            let mut asked = 0;
            let got = relay_offer_decision(None, Public, true, false, || {
                asked += 1;
                answer.map(String::from)
            });
            assert_eq!(got, (Some(want), true), "{answer:?}");
            assert_eq!(asked, 1);
        }

        // Bare `raven relay offer` (and the end of `raven status`): only a
        // raven-node that reports its friend relay `off` (its gate open,
        // consent not given) can be asked.
        let dir = tmp();
        let saved = || try_load_policy(dir.path()).unwrap().relay_offer;
        for cannot in [
            node_with("public", None),
            node_with("public", Some(friend("held", "flag"))),
            node_with("public", Some(friend("up", "flag"))),
            node_with("mapped", Some(friend("off", "unset"))),
            Err("not running".into()),
        ] {
            let lines =
                relay_offer_with(dir.path(), RelayOfferArg::Ask, &cannot, true, never_asked)
                    .unwrap();
            assert!(lines[0].starts_with("relay offer=unset: "), "{lines:?}");
            assert_eq!(saved(), None);
        }
        let public = node_with("public", Some(friend("off", "unset")));
        // Not a terminal: never asked.
        relay_offer_with(dir.path(), RelayOfferArg::Ask, &public, false, never_asked).unwrap();
        assert_eq!(saved(), None);
        // Asked once; no is saved and never asked again.
        let mut question = String::new();
        let lines = relay_offer_with(dir.path(), RelayOfferArg::Ask, &public, true, |q| {
            question = q.to_string();
            Some("n".into())
        })
        .unwrap();
        assert_eq!(question, relay_offer_question(FRIEND_RELAY_PORT));
        assert_eq!(
            lines,
            ["ok: not relaying (change it any time with `raven relay offer on`)"]
        );
        assert_eq!(saved(), Some(false));
        let lines =
            relay_offer_with(dir.path(), RelayOfferArg::Ask, &public, true, never_asked).unwrap();
        assert!(lines[0].starts_with("relay offer=off: "), "{lines:?}");
        // Yes is saved, with what it means; a public node gets no
        // reachability note, and nothing held is said.
        let dir = tmp();
        let lines = relay_offer_with(dir.path(), RelayOfferArg::Ask, &public, true, |_| {
            Some("yes".into())
        })
        .unwrap();
        assert_eq!(try_load_policy(dir.path()).unwrap().relay_offer, Some(true));
        assert!(
            lines[0].starts_with("ok relay offer=on saved in "),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.starts_with("note:")), "{lines:?}");
        // Hide my IP from everyone: never asked (the offer would be refused).
        let dir = tmp();
        save_policy(
            dir.path(),
            &NodePolicy {
                hide_ip: true,
                ..NodePolicy::default()
            },
        )
        .unwrap();
        let lines =
            relay_offer_with(dir.path(), RelayOfferArg::Ask, &public, true, never_asked).unwrap();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("you hide your IP from your contacts")),
            "{lines:?}"
        );
        assert_eq!(try_load_policy(dir.path()).unwrap().relay_offer, None);
    }

    /// Phase 3 item 3: after a yes to the relay offer, the custody follow-up
    /// is asked only while friend custody is off (and its gate is live); a
    /// no leaves custody off; a no to the relay offer asks nothing more.
    #[test]
    fn relay_offer_follow_up_asks_custody_only_when_off() {
        use super::super::custody_cli::relay_custody_follow_up_question;
        use raven_core::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
        let gates = |live| {
            set_custody_gates_for_this_thread(Some(CustodyGates { live, wan: false }));
        };
        let public = node_with("public", Some(friend("off", "unset")));
        let run = |dir: &Path, answers: &[&str]| {
            let mut asked: Vec<String> = Vec::new();
            let lines = relay_offer_with(dir, RelayOfferArg::Ask, &public, true, |q| {
                asked.push(q.to_string());
                answers.get(asked.len() - 1).map(|a| a.to_string())
            })
            .unwrap();
            (asked, lines)
        };
        let both = [
            relay_offer_question(FRIEND_RELAY_PORT),
            relay_custody_follow_up_question(),
        ];
        gates(true);
        // Custody off: asked; yes turns it on.
        let dir = tmp();
        let (asked, lines) = run(dir.path(), &["y", "y"]);
        assert_eq!(asked, both);
        assert!(
            lines.last().unwrap().starts_with("friend custody on: "),
            "{lines:?}"
        );
        let policy = try_load_policy(dir.path()).unwrap();
        assert_eq!((policy.relay_offer, policy.custody), (Some(true), true));
        // A no keeps it off.
        let dir = tmp();
        let (asked, _) = run(dir.path(), &["y", ""]);
        assert_eq!(asked, both);
        assert!(!try_load_policy(dir.path()).unwrap().custody);
        // No to the relay: nothing more.
        let dir = tmp();
        let (asked, _) = run(dir.path(), &["n"]);
        assert_eq!(asked, both[..1]);
        // Custody on already: not asked.
        let dir = tmp();
        save_policy(
            dir.path(),
            &NodePolicy {
                custody: true,
                ..NodePolicy::default()
            },
        )
        .unwrap();
        let (asked, _) = run(dir.path(), &["y"]);
        assert_eq!(asked, both[..1]);
        // Custody held in this build: not asked.
        gates(false);
        let dir = tmp();
        let (asked, _) = run(dir.path(), &["y"]);
        assert_eq!(asked, both[..1]);
        assert!(!try_load_policy(dir.path()).unwrap().custody);
        set_custody_gates_for_this_thread(None);
    }

    /// Phase 3 custody consent (d): the end of `raven status` asks at most
    /// one ask-once question per run, the relay offer before the mailbox
    /// question (Phase 1's UPnP question is asked by `raven node p2p on`
    /// only); once both are answered nothing is asked and the daemon is not
    /// even read.
    #[test]
    fn status_shows_at_most_one_ask_once_prompt_in_priority_order() {
        use super::super::custody_cli::MAILBOX_QUESTION;
        use raven_core::custody_gate::{
            set_custody_gates_for_this_thread, set_custody_hints_for_this_thread, CustodyGates,
        };
        // Mailboxes due (live, a verified friend offers); the relay
        // follow-up held so each run asks one question.
        set_custody_hints_for_this_thread(Some(true));
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: false,
            wan: false,
        }));
        let dir = tmp();
        let carol = contact("Carol", "carol", true, false);
        super::super::save_contacts(dir.path(), std::slice::from_ref(&carol)).unwrap();
        let now = now_ms();
        std::fs::write(
            dir.path().join(learned_routes::LEARNED_ROUTES_FILE),
            serde_json::json!([{
                "pub_hex": carol.pub_hex,
                "generation": 1,
                "received_at_ms": now,
                "expires_at_ms": now + 3_600_000,
                "via": "lan",
                "custody_offer": 2,
            }])
            .to_string(),
        )
        .unwrap();
        let run = |daemon_read: bool| {
            let mut asked: Vec<String> = Vec::new();
            let lines = after_status_with(
                dir.path(),
                || {
                    assert!(daemon_read, "the daemon is not read");
                    node_with("public", Some(friend("off", "unset")))
                },
                |q| {
                    asked.push(q.to_string());
                    Some("n".into())
                },
            )
            .unwrap();
            (asked, lines)
        };
        let (asked, lines) = run(true);
        assert_eq!(asked, [relay_offer_question(FRIEND_RELAY_PORT)]);
        assert_eq!(lines.len(), 1, "{lines:?}");
        let (asked, lines) = run(false);
        assert_eq!(asked, [MAILBOX_QUESTION]);
        assert!(
            lines[0].starts_with("ok: friend mailboxes stay off"),
            "{lines:?}"
        );
        let (asked, lines) = run(false);
        assert!(asked.is_empty() && lines.is_empty(), "{asked:?} {lines:?}");
        // A node that cannot be asked the relay offer gets the mailbox
        // question in the same run.
        let dir2 = tmp();
        super::super::save_contacts(dir2.path(), std::slice::from_ref(&carol)).unwrap();
        std::fs::copy(
            dir.path().join(learned_routes::LEARNED_ROUTES_FILE),
            dir2.path().join(learned_routes::LEARNED_ROUTES_FILE),
        )
        .unwrap();
        let mut asked: Vec<String> = Vec::new();
        after_status_with(
            dir2.path(),
            || node_with("mapped", Some(friend("off", "unset"))),
            |q| {
                asked.push(q.to_string());
                None
            },
        )
        .unwrap();
        assert_eq!(asked, [MAILBOX_QUESTION]);
        set_custody_hints_for_this_thread(None);
        set_custody_gates_for_this_thread(None);
    }

    #[test]
    fn relay_offer_question_text_is_exact() {
        assert_eq!(
            relay_offer_question(7427),
            "This computer can be reached from the internet. Let your verified contacts relay \
             through it, so they can reach each other when they are behind NAT? It uses its own \
             relay key (not your Raven identity) and port 7427; your contacts, and the contacts \
             of anyone who uses this relay, learn this computer's IP address. [y/N] "
        );
        assert!(relay_offer_question(7500).contains(" port 7500; "));
    }

    /// `raven relay offer on|off` (not on a terminal): what is saved, and
    /// the exact explanation, with the note for a node not confirmed public
    /// and the one for a build that holds the friend relay. Bad values
    /// change nothing.
    #[test]
    fn relay_offer_on_off_saves_and_explains() {
        let dir = tmp();
        let not_running: Result<IpcResponse, String> = Err("not running".into());
        let on = |o: RelayOfferOn| RelayOfferArg::On(o);
        let lines = relay_offer_with(
            dir.path(),
            on(RelayOfferOn {
                port: Some(7428),
                also_443: Some(true),
                external: words(&[
                    "/dns4/home.example.net/tcp/7428",
                    " /dns4/home.example.net/tcp/7428 ",
                ]),
            }),
            &not_running,
            false,
            never_asked,
        )
        .unwrap();
        let mut want =
            vec![
            format!(
                "ok relay offer=on saved in {}",
                raven_core::policy_path(dir.path()).display()
            ),
            "your verified contacts may now reserve on this computer's own relay (its own key, \
             port 7428 TCP and UDP and TCP 443) and reach each other through it."
                .to_string(),
            "It carries only encrypted bytes, within fixed limits (at most 64 circuits, each 2 \
             MiB and 5 minutes). The relay sees the IP addresses of the contacts who use it and \
             when they talk, never their messages."
                .to_string(),
            format!("Allow inbound TCP and UDP 7428: {}", p2p_firewall_hint(7428)),
            "raven-node starts the relay within a few seconds (no restart needed).".to_string(),
            "note: this computer is not confirmed reachable from the internet (reachability: \
             unknown); the relay helps only if contacts can reach port 7428: a public IP, UPnP \
             (`raven node upnp on`) or a port forward of TCP and UDP 7428."
                .to_string(),
        ];
        if !raven_core::friend_relay_live_enabled() {
            want.push(
                "note: relaying for your contacts is not enabled in this build \
                 (FRIEND_RELAY_HOLD): raven-node keeps it off until it is."
                    .to_string(),
            );
        }
        assert_eq!(lines, want);
        let policy = || try_load_policy(dir.path()).unwrap();
        let p = policy();
        assert_eq!(
            (p.relay_offer, p.relay_port, p.relay_also_443),
            (Some(true), Some(7428), true)
        );
        assert_eq!(p.relay_external, ["/dns4/home.example.net/tcp/7428"]);
        // On a node confirmed public: no reachability note. What is not
        // given is kept; --no-443 turns 443 off.
        let public = node_with("public", None);
        let lines = relay_offer_with(
            dir.path(),
            on(RelayOfferOn {
                also_443: Some(false),
                ..RelayOfferOn::default()
            }),
            &public,
            false,
            never_asked,
        )
        .unwrap();
        assert!(
            lines[1].contains("(its own key, port 7428 TCP and UDP) and reach"),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("not confirmed")),
            "{lines:?}"
        );
        let p = policy();
        assert_eq!(
            (p.relay_port, p.relay_also_443, p.relay_external.len()),
            (Some(7428), false, 1)
        );
        // A mapped node is not confirmed: the note names its class.
        let mapped = node_with("mapped", None);
        let lines = relay_offer_with(
            dir.path(),
            on(RelayOfferOn::default()),
            &mapped,
            false,
            never_asked,
        )
        .unwrap();
        assert!(
            lines.iter().any(|l| l.contains("(reachability: mapped)")),
            "{lines:?}"
        );
        let external_note = "note: until something confirms an address of this computer, the \
             relay is offered to your contacts only at an address you name: `raven relay offer on \
             --external /ip4/<public IP>/tcp/7427` (a /dns4/ name works too); a friend you give \
             `raven relay card` can use it either way.";
        // Declared addresses, a public or a mapped node: no note to name one.
        assert!(!lines.iter().any(|l| l.contains("--external")), "{lines:?}");
        // Nothing confirms an address and none is named (the first public
        // computer of a circle): how to name it.
        let fresh = tmp();
        let lines = relay_offer_with(
            fresh.path(),
            on(RelayOfferOn::default()),
            &not_running,
            false,
            never_asked,
        )
        .unwrap();
        assert!(lines.iter().any(|l| l == external_note), "{lines:?}");
        let lines = relay_offer_with(
            fresh.path(),
            on(RelayOfferOn::default()),
            &mapped,
            false,
            never_asked,
        )
        .unwrap();
        assert!(!lines.iter().any(|l| l.contains("--external")), "{lines:?}");
        // Bad values: refused, nothing changed.
        save_policy(
            dir.path(),
            &NodePolicy {
                p2p_listen: "7500".into(),
                ..policy()
            },
        )
        .unwrap();
        let before = std::fs::read(raven_core::policy_path(dir.path())).unwrap();
        let five: Vec<String> = (1..=5)
            .map(|i| format!("/ip4/203.0.113.{i}/tcp/7427"))
            .collect();
        for (bad, why) in [
            (Some(0), Vec::new()),
            (Some(7420), Vec::new()),
            (Some(7423), Vec::new()),
            (Some(7500), Vec::new()),
            (None, words(&["/ip4/203.0.113.7/tcp/7427/p2p/x"])),
            (None, words(&["203.0.113.7"])),
            (None, five),
        ] {
            let e = relay_offer_with(
                dir.path(),
                on(RelayOfferOn {
                    port: bad,
                    external: why.clone(),
                    ..RelayOfferOn::default()
                }),
                &not_running,
                false,
                never_asked,
            )
            .err()
            .unwrap_or_else(|| panic!("{bad:?} {why:?} must be refused"));
            assert!(
                e.starts_with("--port") || e.starts_with("--external"),
                "{e}"
            );
            assert_eq!(
                std::fs::read(raven_core::policy_path(dir.path())).unwrap(),
                before
            );
        }
        // Off: saved, the settings kept for the next `on`.
        let lines = relay_offer_with(
            dir.path(),
            RelayOfferArg::Off,
            &not_running,
            false,
            never_asked,
        )
        .unwrap();
        assert_eq!(
            lines,
            [
                "ok relay offer=off saved: raven-node stops the relay within a few seconds; \
              contacts that reserved on it switch to another relay if they have one."
            ]
        );
        let p = policy();
        assert_eq!((p.relay_offer, p.relay_port), (Some(false), Some(7428)));
        // A dedicated relay folder relays already: refused.
        let (relay_dir, _) = relay_dir_with(&[], &[]);
        for arg in [RelayOfferArg::Off, on(RelayOfferOn::default())] {
            let e = relay_offer_with(relay_dir.path(), arg, &not_running, false, never_asked)
                .err()
                .unwrap();
            assert!(e.contains("dedicated relay"), "{e}");
        }
        assert!(!relay_dir.path().join("node_policy.json").exists());
    }

    /// The relay offer texts name the port the running friend relay uses
    /// when its start setting is not the saved one (field test E2 r7: a
    /// test profile's relay listens on 17427 through the debug
    /// `RAVEN_LAB_FRIEND_RELAY_LISTEN`, and the note said 7427); a `--port`
    /// given is named when the relay follows the saved port.
    #[test]
    fn relay_offer_texts_name_the_port_the_relay_uses() {
        let reporting = |port: u16| {
            node_with(
                "unknown",
                Some(FriendRelayInfo {
                    port,
                    ..friend("off", "no")
                }),
            )
        };
        let lab = reporting(17427);
        let on = |port: Option<u16>| {
            RelayOfferArg::On(RelayOfferOn {
                port,
                ..RelayOfferOn::default()
            })
        };
        for port in [None, Some(7500)] {
            let dir = tmp();
            let lines = relay_offer_with(dir.path(), on(port), &lab, false, never_asked).unwrap();
            let text = lines.join("\n");
            for want in [
                "port 17427 TCP and UDP",
                "Allow inbound TCP and UDP 17427",
                "the relay helps only if contacts can reach port 17427",
                "a port forward of TCP and UDP 17427.",
                "--external /ip4/<public IP>/tcp/17427`",
            ] {
                assert!(text.contains(want), "{want:?} missing: {text}");
            }
            assert!(!text.contains(" 7427") && !text.contains("/7427"), "{text}");
        }
        // The relay follows the saved port: a new `--port` is the one named.
        let dir = tmp();
        let lines = relay_offer_with(
            dir.path(),
            on(Some(7500)),
            &reporting(FRIEND_RELAY_PORT),
            false,
            never_asked,
        )
        .unwrap();
        let text = lines.join("\n");
        assert!(text.contains("can reach port 7500:"), "{text}");
        assert!(!text.contains("7427"), "{text}");
        // A bare `raven relay offer` names it too; with none reported (port
        // 0: the OS picks one) the saved port.
        let dir = tmp();
        let lines =
            relay_offer_with(dir.path(), RelayOfferArg::Ask, &lab, false, never_asked).unwrap();
        assert!(lines[1].contains("port 17427)"), "{lines:?}");
        let lines = relay_offer_with(
            dir.path(),
            RelayOfferArg::Ask,
            &reporting(0),
            false,
            never_asked,
        )
        .unwrap();
        assert!(lines[1].contains("port 7427)"), "{lines:?}");
    }

    /// A bare `raven relay offer` while hide my IP is on for everyone and the
    /// relay has consent: it says the computer does not relay for them, which
    /// holds (raven-node stops the relay while hide my IP is on).
    #[test]
    fn relay_offer_state_under_global_hide_ip_says_it_does_not_relay() {
        let policy = NodePolicy {
            hide_ip: true,
            relay_offer: Some(true),
            ..NodePolicy::default()
        };
        let lines = relay_offer_state_lines(&policy, offer_port(&policy));
        assert_eq!(
            lines.last().map(String::as_str),
            Some(
                "note: you hide your IP from your contacts, so this computer does not relay for \
                 them (`raven node hide-ip off` first)."
            )
        );
    }

    /// D4: a node that hides its IP from every contact cannot offer them a
    /// relay, which would show it.
    #[test]
    fn relay_offer_refuses_under_global_hide_ip() {
        let dir = tmp();
        save_policy(
            dir.path(),
            &NodePolicy {
                hide_ip: true,
                ..NodePolicy::default()
            },
        )
        .unwrap();
        let e = relay_offer_with(
            dir.path(),
            RelayOfferArg::On(RelayOfferOn::default()),
            &node_with("public", None),
            false,
            never_asked,
        )
        .err()
        .unwrap();
        assert_eq!(
            e,
            "you hide your IP from your contacts; a relay would show it to them. Turn that off \
             first, or run a dedicated relay elsewhere (`raven-node relay`)."
        );
        assert_eq!(e, RELAY_OFFER_HIDE_IP);
        assert_eq!(try_load_policy(dir.path()).unwrap().relay_offer, None);
        // Saying no stays possible.
        relay_offer_with(
            dir.path(),
            RelayOfferArg::Off,
            &Err(String::new()),
            false,
            never_asked,
        )
        .unwrap();
        assert_eq!(
            try_load_policy(dir.path()).unwrap().relay_offer,
            Some(false)
        );
    }

    #[test]
    fn relay_auto_on_off_texts() {
        let dir = tmp();
        assert_eq!(
            relay_auto_with(dir.path(), false).unwrap(),
            ["ok relay auto=off: only the relays you set (`raven node p2p on --relay …`) are used."]
        );
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!(p.relay_auto, Some(false));
        assert!(!p.relay_auto_on());
        let lines = relay_auto_with(dir.path(), true).unwrap();
        assert_eq!(
            lines[0],
            "ok relay auto=on: raven-node picks up to 2 of the relays your verified contacts \
             offer, keeps them while they work, and switches only after one has not answered \
             for 10 minutes."
        );
        let held = !raven_core::friend_relay_live_enabled();
        assert_eq!(lines.len(), if held { 2 } else { 1 }, "{lines:?}");
        if held {
            assert_eq!(
                lines[1],
                "note: automatic relay choice is not enabled in this build \
                 (FRIEND_RELAY_HOLD): raven-node keeps it off until it is."
            );
        }
        assert_eq!(try_load_policy(dir.path()).unwrap().relay_auto, Some(true));
        let (relay_dir, _) = relay_dir_with(&[], &[]);
        assert!(relay_auto_with(relay_dir.path(), true).is_err());
    }

    /// In a profile, a contact denied (by name, or by their PeerId) goes on
    /// the deny list as well: the friend relay admits verified contacts by
    /// itself. Anyone else only leaves the allow-list, and a dedicated relay
    /// folder has no deny list at all.
    #[test]
    fn relay_deny_of_a_contact_keeps_it_denied() {
        let dir = tmp();
        let dana = contact("Dana", "dana", true, true);
        let bob = contact("Bob", "bob", true, true);
        super::super::save_contacts(dir.path(), &[dana.clone(), bob.clone()]).unwrap();
        let list = || relay_allow::load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(
            relay_deny_with(dir.path(), "@dana").unwrap(),
            format!(
                "denied {}: Dana is your contact, so they stay on the deny list; the relay drops \
                 them within seconds",
                dana.p2p
            )
        );
        assert!(list().is_denied(&dana.p2p) && !list().contains(&dana.p2p));
        // Review D-5: the entry names the contact, so the friend relay
        // turns away every PeerId they are known by (their coming epochs
        // too), not only this one.
        assert_eq!(
            list().denied_contacts(),
            [dana.pub_hex.to_ascii_lowercase()]
        );
        assert_eq!(
            relay_deny_with(dir.path(), "dana").unwrap(),
            format!("{} (Dana) is denied already (nothing changed)", dana.p2p)
        );
        // By PeerId: still a contact. One allowed by hand leaves that list.
        relay_allow::relay_allow(dir.path(), &bob.p2p, "bob").unwrap();
        assert!(relay_deny_with(dir.path(), &bob.p2p)
            .unwrap()
            .starts_with(&format!("denied {}: Bob is your contact", bob.p2p)));
        assert!(list().is_denied(&bob.p2p) && !list().contains(&bob.p2p));
        assert!(list()
            .denied_contacts()
            .contains(&bob.pub_hex.to_ascii_lowercase()));
        // Somebody else: the allow-list only, as before.
        let stranger = peer_of(0x61);
        relay_allow::relay_allow(dir.path(), &stranger, "").unwrap();
        assert_eq!(
            relay_deny_with(dir.path(), &stranger).unwrap(),
            format!("denied {stranger}: a running relay ends its reservation within seconds")
        );
        assert!(!list().is_denied(&stranger));
        // Allowing a denied contact again takes them off the deny list.
        cmd_relay_allow(dir.path(), Some("@dana"), None, "").unwrap();
        assert!(list().contains(&dana.p2p) && !list().is_denied(&dana.p2p));
        // A contact whose PeerId only their route hints named (proven by a
        // p2p link) is found and denied too.
        let carol = Contact {
            p2p: String::new(),
            p2p_via: Vec::new(),
            ..contact("Carol", "carol", true, false)
        };
        super::super::save_contacts(dir.path(), &[dana.clone(), bob.clone(), carol.clone()])
            .unwrap();
        let learned_peer = peer_of(0x62);
        let now = now_ms();
        std::fs::write(
            dir.path().join(learned_routes::LEARNED_ROUTES_FILE),
            serde_json::json!([{
                "pub_hex": carol.pub_hex,
                "generation": 1,
                "received_at_ms": now,
                "expires_at_ms": now + 3_600_000,
                "via": "p2p",
                "peer_id": learned_peer,
                "peer_id_proven": true,
            }])
            .to_string(),
        )
        .unwrap();
        assert!(relay_deny_with(dir.path(), "@carol")
            .unwrap()
            .starts_with(&format!("denied {learned_peer}: Carol is your contact")));
        assert!(list().is_denied(&learned_peer));
        // A dedicated relay folder: off the allow-list, never on a deny list.
        let (relay_dir, _) = relay_dir_with(&[], &[]);
        relay_allow::relay_allow(relay_dir.path(), &dana.p2p, "").unwrap();
        assert!(relay_deny_with(relay_dir.path(), &dana.p2p)
            .unwrap()
            .ends_with("a running relay ends its reservation within seconds"));
        let dedicated = relay_allow::load_relay_allow(relay_dir.path())
            .unwrap()
            .unwrap();
        assert!(dedicated.deny.is_empty() && !dedicated.contains(&dana.p2p));
    }

    /// `raven relay allow` of a contact (by name, or by the PeerId of one)
    /// names the contact on the friend relay's allow-list, a PeerId only its
    /// route hints named included; a stranger's entry names none. An entry
    /// made before (no contact named) is told its contact when that
    /// contact's routes are forgotten, as a block does: the learned PeerId
    /// goes with them, and the friend relay must still turn the entry away
    /// while the contact is blocked.
    #[test]
    fn relay_allow_names_the_contact_and_forgetting_its_routes_keeps_it_named() {
        let dir = tmp();
        let dana = contact("Dana", "dana", true, true);
        let learned_only = |name: &str, tag: &str| Contact {
            p2p: String::new(),
            p2p_via: Vec::new(),
            ..contact(name, tag, true, false)
        };
        let (carol, hannah) = (
            learned_only("Carol", "carol"),
            learned_only("Hannah", "hannah"),
        );
        super::super::save_contacts(dir.path(), &[dana.clone(), carol.clone(), hannah.clone()])
            .unwrap();
        let (carol_peer, hannah_peer, stranger) = (peer_of(0x62), peer_of(0x63), peer_of(0x61));
        let now = now_ms();
        let learned = |c: &Contact, peer: &str| {
            serde_json::json!({
                "pub_hex": c.pub_hex,
                "generation": 1,
                "received_at_ms": now,
                "expires_at_ms": now + 3_600_000,
                "via": "p2p",
                "peer_id": peer,
                "peer_id_proven": true,
            })
        };
        std::fs::write(
            dir.path().join(learned_routes::LEARNED_ROUTES_FILE),
            serde_json::json!([learned(&carol, &carol_peer), learned(&hannah, &hannah_peer)])
                .to_string(),
        )
        .unwrap();
        cmd_relay_allow(dir.path(), Some("@carol"), None, "").unwrap();
        cmd_relay_allow(dir.path(), Some(&dana.p2p), None, "").unwrap();
        cmd_relay_allow(dir.path(), Some(&stranger), None, "").unwrap();
        // Hannah's entry from an older build: no contact named.
        relay_allow::relay_allow(dir.path(), &hannah_peer, "hannah").unwrap();
        let named = || -> Vec<(String, String)> {
            let list = relay_allow::load_relay_allow(dir.path()).unwrap().unwrap();
            list.peers
                .iter()
                .map(|e| (e.peer_id.clone(), e.contact.clone()))
                .collect()
        };
        assert_eq!(
            named(),
            [
                (carol_peer, carol.pub_hex.clone()),
                (dana.p2p.clone(), dana.pub_hex.clone()),
                (stranger, String::new()),
                (hannah_peer.clone(), String::new()),
            ]
        );
        // Hannah's routes are forgotten (a block): her entry names her first.
        super::super::forget_outbox_routes(dir.path(), &hannah.pub_hex);
        assert!(learned_routes::learned_peer_ids(dir.path(), now_ms())
            .iter()
            .all(|(key, _, _)| !key.eq_ignore_ascii_case(&hannah.pub_hex)));
        assert_eq!(named()[3], (hannah_peer, hannah.pub_hex.clone()));
        // The relay folder of a dedicated relay never names a contact.
        let (relay_dir, _) = relay_dir_with(&[], &[]);
        super::super::save_contacts(relay_dir.path(), std::slice::from_ref(&dana)).ok();
        cmd_relay_allow(relay_dir.path(), Some(&dana.p2p), None, "").unwrap();
        let dedicated = relay_allow::load_relay_allow(relay_dir.path())
            .unwrap()
            .unwrap();
        assert!(dedicated.peers.iter().all(|e| e.contact.is_empty()));
    }

    /// A profile's `friend_relay/` with its own key and status.
    fn friend_relay_folder(profile: &Path, peer: &str, advertised: &[&str], listen: &[&str]) {
        let dir = relay_allow::friend_relay_dir(profile);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(relay_allow::RELAY_KEY_FILE), [0u8; 32]).unwrap();
        relay_allow::write_relay_status(
            &dir,
            &relay_allow::RelayStatusFile {
                version: 1,
                peer_id: peer.to_string(),
                listen_addrs: words(listen),
                advertised: words(advertised),
                ..Default::default()
            },
        )
        .unwrap();
    }

    /// `raven relay card` on a profile gives out its friend relay (its own
    /// key, port 7427), never the profile's PeerId; with relaying off it
    /// says how to turn it on.
    #[test]
    fn relay_card_on_a_profile_prints_the_friend_relay_never_the_profile_peer() {
        let dir = tmp();
        let profile_peer = peer_of(0x70);
        let relay_peer = peer_of(0x71);
        friend_relay_folder(
            dir.path(),
            &relay_peer,
            &[
                "/ip4/203.0.113.7/udp/7427/quic-v1",
                "/ip4/203.0.113.7/tcp/7427",
                "/ip4/203.0.113.7/tcp/443",
            ],
            &["/ip4/192.168.1.5/tcp/7427"],
        );
        // The running node: the profile's own PeerId and listen addresses.
        let node = |state: &str| {
            status(Some(P2pStatusInfo {
                up: true,
                peer_id: profile_peer.clone(),
                listen_addrs: words(&["/ip4/203.0.113.7/tcp/7423"]),
                friend_relay: Some(friend(state, "yes")),
                ..P2pStatusInfo::default()
            }))
        };
        let card = |daemon: &Result<IpcResponse, String>, offer: Option<bool>| {
            CardSource::friend_relay(dir.path(), daemon, offer)
                .and_then(|src| relay_card_lines(&src, None, None, false))
        };
        let want = [
            format!("/ip4/203.0.113.7/tcp/7427/p2p/{relay_peer}"),
            format!("/ip4/203.0.113.7/tcp/443/p2p/{relay_peer}"),
            format!("/ip4/203.0.113.7/udp/7427/quic-v1/p2p/{relay_peer}"),
        ];
        for daemon in [node("up"), node("starting"), node("failed")] {
            let lines = card(&daemon, None).unwrap();
            assert_eq!(lines, want);
            assert!(
                lines.iter().all(|l| !l.contains(&profile_peer)),
                "{lines:?}"
            );
        }
        // No service answering: the saved consent decides.
        assert_eq!(card(&Err("not running".into()), Some(true)).unwrap(), want);
        // --host on a relay that names no port: the friend relay's 7427.
        let src = CardSource::friend_relay(dir.path(), &node("up"), None)
            .ok()
            .unwrap();
        let bare = CardSource {
            advertised: Vec::new(),
            listen: Vec::new(),
            ..src
        };
        assert_eq!(
            relay_card_lines(&bare, Some("relay.example.org"), None, false).unwrap(),
            [format!("/dns/relay.example.org/tcp/7427/p2p/{relay_peer}")]
        );
        // Off: say how to turn it on, whatever the folder holds.
        let off = "relaying is off: `raven relay offer on` first".to_string();
        assert_eq!(card(&node("off"), Some(true)).err(), Some(off.clone()));
        assert_eq!(card(&status(None), None).err(), Some(off.clone()));
        assert_eq!(
            card(&Err("not running".into()), Some(false)).err(),
            Some(off)
        );
        // Held in this build; stopped while hide my IP is on; on, but it
        // never ran.
        assert!(card(&node("held"), Some(true))
            .err()
            .unwrap()
            .contains("relaying is off in this build"));
        assert!(card(&node("hidden"), Some(true))
            .err()
            .unwrap()
            .contains("`raven node hide-ip off` first"));
        let fresh = tmp();
        let e = CardSource::friend_relay(fresh.path(), &node("starting"), Some(true))
            .err()
            .unwrap();
        assert!(e.contains("has not started yet"), "{e}");
        // `raven relay status` run in that folder points at the profile.
        assert_eq!(
            friend_relay_profile(&relay_allow::friend_relay_dir(dir.path())),
            Some(dir.path())
        );
        assert_eq!(friend_relay_profile(dir.path()), None);
        let (relay_dir, _) = relay_dir_with(&[], &[]);
        assert_eq!(friend_relay_profile(relay_dir.path()), None);
    }

    /// The learned_routes.json of a node that `operator` offered `relay` at
    /// `addrs`, expiring at `expires_at_ms`.
    fn offered(dir: &Path, operator: &Contact, relay: &str, addrs: &[&str], expires_at_ms: u64) {
        let now = now_ms();
        std::fs::write(
            dir.join(learned_routes::LEARNED_ROUTES_FILE),
            serde_json::json!([{
                "pub_hex": operator.pub_hex,
                "generation": 1,
                "received_at_ms": now.min(expires_at_ms.saturating_sub(1_000)),
                "expires_at_ms": expires_at_ms,
                "via": "p2p",
                "offers": [{"relay_peer_id": relay, "addrs": addrs, "flags": 0}],
            }])
            .to_string(),
        )
        .unwrap();
    }

    /// `--relay @friend` saves the relay that friend offers (their route
    /// hints): its first address and its 443 fallback, one address when two
    /// relays are given. Without an offer it says how to get one (the old
    /// direct address only under the profile-relay lab switch).
    #[test]
    fn at_friend_uses_their_offered_relay_or_says_how_to_get_one() {
        let dir = tmp();
        let dana = contact("Dana", "dana", true, true);
        super::super::save_contacts(dir.path(), std::slice::from_ref(&dana)).unwrap();
        let how =
            "Dana has not offered you a relay: ask them to run `raven relay offer on` (their \
                   computer must be reachable from the internet)";
        let lab = raven_core::p2p_profile_relay_test_enabled();
        let no_offer = resolve_relays(dir.path(), &words(&["@dana"]));
        if lab {
            assert_eq!(no_offer.unwrap(), [dana.p2p_via[0].clone()]);
        } else {
            assert_eq!(no_offer.unwrap_err(), how);
        }
        let relay = peer_of(0x72);
        let hour = now_ms() + 3_600_000;
        offered(
            dir.path(),
            &dana,
            &relay,
            &[
                "/ip4/203.0.113.7/udp/7427/quic-v1",
                "/ip4/203.0.113.7/tcp/7427",
                "/ip4/203.0.113.7/tcp/443",
            ],
            hour,
        );
        let tcp = format!("/ip4/203.0.113.7/tcp/7427/p2p/{relay}");
        let fallback = format!("/ip4/203.0.113.7/tcp/443/p2p/{relay}");
        assert_eq!(
            resolve_relays(dir.path(), &words(&["@dana"])).unwrap(),
            [tcp.clone(), fallback]
        );
        // With a second relay: one address of each.
        let other = format!("/ip4/198.51.100.9/tcp/7423/p2p/{}", peer_of(0x73));
        assert_eq!(
            resolve_relays(dir.path(), &[String::from("Dana"), other.clone()]).unwrap(),
            [tcp, other]
        );
        // An offer whose snapshot expired (a tombstone's) is not given out.
        offered(
            dir.path(),
            &dana,
            &relay,
            &["/ip4/203.0.113.7/tcp/7427"],
            now_ms() - 60_000,
        );
        let expired = resolve_relays(dir.path(), &words(&["@dana"]));
        if lab {
            assert_eq!(expired.unwrap(), [dana.p2p_via[0].clone()]);
        } else {
            assert_eq!(expired.unwrap_err(), how);
        }
    }

    /// The `relaying` row in every state: the friend relay (its own key) as
    /// the running raven-node reports it. No PeerId, no address.
    #[test]
    fn relaying_row_texts() {
        let fr = |state: &str, consent: &str, reachable: &str, members: u32| FriendRelayInfo {
            members,
            reachable: reachable.into(),
            counts: RelayCounts {
                reservations: 2,
                circuits: 1,
                ..RelayCounts::default()
            },
            ..friend(state, consent)
        };
        let row = |f: FriendRelayInfo, class: &str| {
            relaying_row(
                &up_with(|i| {
                    i.reach = class.into();
                    i.friend_relay = Some(f);
                }),
                false,
            )
        };
        let some = |s: &str| Some(s.to_string());
        assert_eq!(
            row(fr("up", "yes", "confirmed", 3), "public"),
            some("YES \u{2014} for 3 verified contacts (2 reserved, 1 circuit); own relay key, port 7427")
        );
        assert_eq!(
            row(fr("up", "flag", "confirmed", 1), "relayed"),
            some("YES \u{2014} for 1 verified contact (2 reserved, 1 circuit); own relay key, port 7427")
        );
        let offered = |f: FriendRelayInfo| FriendRelayInfo {
            offering: true,
            ..f
        };
        assert_eq!(
            row(offered(fr("up", "yes", "unconfirmed", 3)), "public"),
            some(
                "YES \u{2014} for 3 verified contacts, but no contact has reached it from the \
                 internet yet: forward TCP and UDP 7427 on your router, or turn on UPnP (`raven \
                 node upnp on`)"
            )
        );
        // Not offered (nothing confirms or names its address: the first
        // public computer of a circle): how to name it, not a forward.
        assert_eq!(
            row(fr("up", "yes", "unconfirmed", 3), "unknown"),
            some(
                "YES \u{2014} for 3 verified contacts, but not offered to your contacts yet: \
                 nothing has confirmed the address it would name. Name the address they reach it \
                 at: `raven relay offer on --external /ip4/<public IP>/tcp/7427` (or give a friend \
                 `raven relay card`); behind a router, forward TCP and UDP 7427 or turn on UPnP \
                 (`raven node upnp on`)"
            )
        );
        assert_eq!(
            row(fr("up", "yes", "no_address", 3), "unknown"),
            some(
                "YES \u{2014} but this computer has no public address to offer: contacts outside \
                 this network cannot use it. If they can reach it (a public IP, or a forward of TCP \
                 and UDP 7427), name the address: `raven relay offer on --external /ip4/<public \
                 IP>/tcp/7427` (or give a friend `raven relay card`)"
            )
        );
        // Stopped while hide my IP is on for everyone.
        assert_eq!(
            row(fr("hidden", "yes", "", 0), "public"),
            some(
                "no \u{2014} stopped while you hide your IP from every contact (`raven node \
                 hide-ip off` to relay again)"
            )
        );
        assert_eq!(
            row(fr("failed", "yes", "", 0), "public"),
            some("NOT running \u{2014} port 7427 could not be opened (another program?); retrying")
        );
        assert_eq!(
            row(fr("held", "yes", "", 0), "public"),
            some("held: relaying is off in this build")
        );
        assert_eq!(
            row(fr("starting", "yes", "", 0), "public"),
            some("starting \u{2014} own relay key, port 7427")
        );
        for class in ["public", "mapped", "unknown"] {
            assert_eq!(
                row(fr("off", "no", "", 0), class),
                some("no (you said no; `raven relay offer on` to change)")
            );
        }
        let not_yet = some(
            "not yet \u{2014} this computer can be reached from the internet: `raven relay offer \
             on` lets your contacts relay through it",
        );
        assert_eq!(row(fr("off", "unset", "", 0), "public"), not_yet);
        assert_eq!(row(fr("off", "unset", "", 0), "mapped"), not_yet);
        for class in ["relayed", "unreachable", "unknown"] {
            assert_eq!(row(fr("off", "unset", "", 0), class), None, "{class}");
        }
        // The host is not up: nothing tells whether it is reachable.
        let down = P2pStatusInfo {
            up: false,
            reach: "public".into(),
            friend_relay: Some(fr("off", "unset", "", 0)),
            ..P2pStatusInfo::default()
        };
        assert_eq!(relaying_row(&down, false), None);
        // A newer raven-node's state word is shown safely.
        let odd = row(fr("half\u{1b}[2J open", "yes", "", 0), "public").unwrap();
        assert!(!odd.contains('\u{1b}'), "{odd}");
    }

    /// Relay rows name a relay picked from a contact's offer as that
    /// contact's relay (their name from the contact book; "a contact" when
    /// the book no longer has them), never by a PeerId or key; the p2p row
    /// counts every slot, and spare relays get a row of their own.
    #[test]
    fn relay_rows_name_the_operators_petname_never_a_peer_id() {
        let dana = contact("Dana", "dana", true, true);
        let odd = contact("Ev\u{1b}[2Je", "", true, true);
        let relay = peer_of(0x74);
        let health = |addr: &str, state: &str, source: &str, operator: &str| RelayHealth {
            relay: format!("{addr}/p2p/{relay}"),
            state: state.into(),
            source: source.into(),
            operator_pub_hex: operator.into(),
            ..RelayHealth::default()
        };
        let stranger = hex::encode([0x5a; 32]);
        let info = up_with(|i| {
            i.relays_configured = 1;
            i.reservations = words(&["a", "b"]);
            i.relay_standby = 2;
            i.friend_relay = Some(friend("off", "unset"));
            i.relay_health = vec![
                RelayHealth {
                    for_s: Some(60),
                    ..health("/ip4/198.51.100.7/tcp/7423", "reserved", "manual", "")
                },
                RelayHealth {
                    for_s: Some(125),
                    ..health(
                        "/ip4/203.0.113.7/tcp/7427",
                        "reserved",
                        "offer",
                        &dana.pub_hex.to_uppercase(),
                    )
                },
                health(
                    "/dns4/relay.example.org/tcp/7427",
                    "resolving",
                    "offer",
                    &stranger,
                ),
                RelayHealth {
                    tries: 2,
                    retry_in_s: Some(9),
                    ..health(
                        "/ip4/203.0.113.9/tcp/7427",
                        "retrying",
                        "offer",
                        &odd.pub_hex,
                    )
                },
            ];
        });
        let rows = relay_rows(&info, &[dana.clone(), odd.clone()]);
        let values: Vec<&str> = rows.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(
            values,
            [
                "OK \u{2014} 198.51.100.7:7423, reserved for 1 min",
                "OK \u{2014} Dana's relay (203.0.113.7:7427), reserved for 2 min",
                "looking up a contact's relay (relay.example.org)",
                "NOT reserved yet \u{2014} Eve's relay (203.0.113.9:7427); next try in 9 s (2 \
                 failed)",
            ]
        );
        for (_, row) in &rows {
            assert!(
                !row.contains("12D3KooW")
                    && !row.contains("/p2p")
                    && !row.contains(&stranger)
                    && !row.contains('\u{1b}'),
                "{row}"
            );
        }
        assert_eq!(
            spare_relays_row(&info).as_deref(),
            Some("2 more offered by your contacts (used when one stops answering)")
        );
        assert_eq!(spare_relays_row(&up_with(|_| {})), None);
        // The p2p row counts every slot, not only the relays set by hand.
        assert!(
            p2p_reach_row(&status(Some(info.clone())), "7423", true).contains("reservations 2/4"),
            "{}",
            p2p_reach_row(&status(Some(info.clone())), "7423", true)
        );
        assert_eq!(relay_slots(&info), 4);
        // `raven relay status`: the same rows, then automatic choice and the
        // spare relays.
        let you_use = relays_you_use_rows(&status(Some(info)), &[dana]);
        assert_eq!(you_use[1].1, values[1]);
        assert_eq!(you_use[4].0, "auto");
        assert!(you_use[4].1.starts_with("off: "), "{you_use:?}");
        assert_eq!(you_use[5].0, "spare");
        assert_eq!(
            relays_you_use_rows(&Err("not running".into()), &[]),
            [(
                "relays".to_string(),
                "none: raven-node is not running".to_string()
            )]
        );
    }

    /// `raven relay status` on a profile: the friend relay's rows (its own
    /// key, members in parts, counts, whether contacts reached it) and the
    /// allow and deny lists.
    #[test]
    fn relay_status_on_a_profile_shows_the_friend_relay_and_its_lists() {
        let up = FriendRelayInfo {
            also_443: true,
            members: 3,
            manual: 1,
            denied: 1,
            reachable: "confirmed".into(),
            confirmed_age_s: Some(7_200),
            offered_to: 2,
            ..friend("up", "yes")
        };
        let rows = friend_relay_rows(&node_with("public", Some(up)), Some(true), Some(3));
        let get = |k: &str| {
            rows.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("{k}: {rows:?}"))
        };
        assert_eq!(get("state"), "running");
        assert_eq!(get("relay key"), "its own (not your Raven identity)");
        assert_eq!(get("port"), "7427 TCP and UDP, and TCP 443");
        // The relay reported its listeners: 443 as it is.
        let port_row = |open: Option<bool>| {
            friend_port_text(&FriendRelayInfo {
                also_443: true,
                port_443_open: open,
                ..friend("up", "yes")
            })
        };
        assert_eq!(port_row(Some(true)), "7427 TCP and UDP, and TCP 443");
        let skipped = port_row(Some(false));
        assert!(
            skipped.starts_with("7427 TCP and UDP; TCP 443 was asked for but is not open")
                && skipped.contains("CAP_NET_BIND_SERVICE")
                && !skipped.contains(", and TCP 443"),
            "{skipped}"
        );
        let skipped_up = FriendRelayInfo {
            also_443: true,
            port_443_open: Some(false),
            ..friend("up", "yes")
        };
        let rows = friend_relay_rows(&node_with("public", Some(skipped_up)), Some(true), Some(3));
        assert_eq!(rows[2], ("port".to_string(), skipped));
        assert_eq!(
            friend_port_text(&friend("up", "yes")),
            "7427 TCP and UDP",
            "443 not asked for"
        );
        assert_eq!(
            get("members"),
            "3 (3 verified contacts + 1 by hand \u{2212} 1 denied)"
        );
        assert!(get("counts").starts_with("reservations=0 circuits=0"));
        assert_eq!(
            get("reachable"),
            "yes: a contact reached it from the internet 2 h ago"
        );
        assert_eq!(get("offered to"), "2 contacts");
        // Not running: the saved choice in words.
        let state = |daemon: Result<IpcResponse, String>, offer: Option<bool>| {
            friend_relay_rows(&daemon, offer, None)[0].1.clone()
        };
        assert!(state(Err("x".into()), None).starts_with("off (`raven relay offer on` lets"));
        assert_eq!(
            state(node_with("public", Some(friend("off", "no"))), Some(false)),
            "off (you said no; `raven relay offer on` to change)"
        );
        assert!(state(status(None), Some(true)).contains("an older raven-node?"));
        assert_eq!(
            friend_relay_rows(
                &node_with("public", Some(friend("held", "yes"))),
                None,
                None
            ),
            [(
                "state".to_string(),
                "held: relaying is off in this build (FRIEND_RELAY_HOLD)".to_string()
            )]
        );
        // The allow and deny lists, PeerId by PeerId.
        let dir = tmp();
        let (a, b) = (peer_of(0x75), peer_of(0x76));
        relay_allow::relay_allow(dir.path(), &a, "box").unwrap();
        relay_allow::relay_allow(dir.path(), &b, "").unwrap();
        relay_allow::relay_deny(dir.path(), &b, true).unwrap();
        let rows = allow_list_rows(&relay_allow::load_relay_allow(dir.path()), true);
        assert_eq!(
            rows,
            [
                (
                    "allow_list".to_string(),
                    "1 peer(s) added by hand".to_string()
                ),
                (String::new(), format!("{a}  (box)")),
                ("deny_list".to_string(), "1 peer(s)".to_string()),
                (String::new(), b.clone()),
            ]
        );
        // A dedicated relay folder shows no deny list.
        assert_eq!(
            allow_list_rows(&relay_allow::load_relay_allow(dir.path()), false)[..1],
            [("allow_list".to_string(), "1 peer(s)".to_string())]
        );
        assert_eq!(
            allow_list_rows(&relay_allow::load_relay_allow(dir.path()), false).len(),
            2
        );
        // An empty list kept by hand (none yet, or every entry taken off):
        // the friend relay still admits the verified contacts, so only a
        // dedicated relay says nobody may reserve (field test E2 r7).
        let none = tmp();
        relay_allow::relay_allow(none.path(), &a, "").unwrap();
        relay_allow::relay_deny(none.path(), &a, false).unwrap();
        assert!(matches!(
            relay_allow::load_relay_allow(none.path()),
            Ok(Some(l)) if l.peers.is_empty()
        ));
        for allow in [Ok(None), relay_allow::load_relay_allow(none.path())] {
            let friend = allow_list_rows(&allow, true);
            assert_eq!(
                friend[0],
                (
                    "allow_list".to_string(),
                    "none added by hand (your verified contacts are members)".to_string()
                ),
                "{allow:?}"
            );
            assert!(
                friend.iter().all(|(_, v)| !v.contains("nobody")),
                "{friend:?}"
            );
            let operator = allow_list_rows(&allow, false);
            assert_eq!(operator.len(), 1, "{operator:?}");
            assert!(
                operator[0].1.starts_with("none yet: nobody may reserve"),
                "{operator:?}"
            );
        }
    }

    /// The doctor line is key=value words only: the saved consent, the
    /// friend relay's state and counts, automatic choice, spare relays and
    /// each slot's source.
    #[test]
    fn doctor_relay_offer_lines_are_key_value() {
        let policy = |offer: Option<bool>| NodePolicy {
            relay_offer: offer,
            ..NodePolicy::default()
        };
        let info = up_with(|i| {
            i.friend_relay = Some(FriendRelayInfo {
                members: 3,
                counts: RelayCounts {
                    reservations: 2,
                    ..RelayCounts::default()
                },
                ..friend("up", "yes")
            });
            i.relay_auto = true;
            i.relay_standby = 1;
            i.relay_health = vec![
                RelayHealth {
                    source: "manual".into(),
                    ..RelayHealth::default()
                },
                RelayHealth {
                    source: "offer".into(),
                    ..RelayHealth::default()
                },
                RelayHealth::default(),
            ];
        });
        let line = doctor_relay_offer_line(&status(Some(info)), &policy(Some(true))).unwrap();
        assert_eq!(
            line,
            "relay_offer=yes friend_relay=up friend_relay_members=3 friend_relay_reserved=2 \
             relay_auto=on relay_standby=1 relay_1_source=manual relay_2_source=offer \
             relay_3_source=manual"
        );
        let saved_no =
            doctor_relay_offer_line(&Err("not running".into()), &policy(Some(false))).unwrap();
        assert_eq!(
            saved_no,
            "relay_offer=no friend_relay=off friend_relay_members=0 friend_relay_reserved=0 \
             relay_auto=off relay_standby=0"
        );
        let odd = up_with(|i| i.friend_relay = Some(friend("held up\u{1b}[2J", "flag")));
        let odd = doctor_relay_offer_line(&status(Some(odd)), &policy(None)).unwrap();
        assert!(
            odd.starts_with("relay_offer=unset friend_relay=held:up"),
            "{odd}"
        );
        for line in [line, saved_no, odd] {
            for word in line.split(' ') {
                let (k, v) = word.split_once('=').unwrap_or_else(|| panic!("{word}"));
                assert!(!k.is_empty() && !v.is_empty() && !v.contains('='), "{word}");
                assert!(!word.contains('\u{1b}'), "{word}");
            }
        }
        // Nothing saved, nothing reported: no line.
        assert_eq!(
            doctor_relay_offer_line(&Err(String::new()), &policy(None)),
            None
        );
    }

    /// An older raven-node (no friend relay, relay_auto, relay_standby in its
    /// JSON), like a build whose friend relay gate is closed and that has no
    /// consent: no `relaying` row, no doctor line, no question.
    #[test]
    fn an_older_daemon_without_friend_relay_shows_no_row() {
        let older: P2pStatusInfo = serde_json::from_str(
            r#"{"up":true,"peer_id":"12D3KooWx","listen_addrs":["/ip4/203.0.113.7/tcp/7423"],
                "nat":"public","reservations":[],"relays_configured":0,"upnp":"unset",
                "reach":"public"}"#,
        )
        .unwrap();
        assert_eq!(older.friend_relay, None);
        assert_eq!(relaying_row(&older, false), None);
        assert_eq!(spare_relays_row(&older), None);
        let daemon = status(Some(older.clone()));
        assert_eq!(
            doctor_relay_offer_line(&daemon, &NodePolicy::default()),
            None
        );
        let dir = tmp();
        let lines =
            relay_offer_with(dir.path(), RelayOfferArg::Ask, &daemon, true, never_asked).unwrap();
        assert!(lines[0].starts_with("relay offer=unset"), "{lines:?}");
        assert!(relays_you_use_rows(&daemon, &[])
            .iter()
            .all(|(k, _)| k != "auto"));
        // What a newer raven-node says with its gate open: an `off` row
        // to suggest from.
        let newer = P2pStatusInfo {
            friend_relay: Some(friend("off", "unset")),
            ..older
        };
        assert!(relaying_row(&newer, false).is_some());
    }

    #[test]
    fn relay_offer_and_auto_parse() {
        use super::super::{OfferState as O, OnOff, RelayCommands as R};
        use clap::Parser;
        let relay = |args: &[&str]| match super::super::Cli::try_parse_from(
            std::iter::once("raven").chain(args.iter().copied()),
        )
        .map(|c| c.cmd)
        {
            Ok(Some(super::super::Commands::Relay { cmd })) => Ok(cmd),
            Ok(other) => panic!("{other:?}"),
            Err(e) => Err(e.kind()),
        };
        assert!(matches!(
            relay(&["relay", "offer"]),
            Ok(R::Offer { state: None })
        ));
        assert!(matches!(
            relay(&["relay", "offer", "off"]),
            Ok(R::Offer {
                state: Some(O::Off)
            })
        ));
        match relay(&[
            "relay",
            "offer",
            "on",
            "--port",
            "7428",
            "--also-443",
            "--external",
            "/dns4/a.example/tcp/7428",
            "--external",
            "/ip4/203.0.113.7/tcp/443",
        ]) {
            Ok(R::Offer {
                state:
                    Some(O::On {
                        port: Some(7428),
                        also_443: true,
                        no_443: false,
                        external,
                    }),
            }) => assert_eq!(external.len(), 2),
            other => panic!("{other:?}"),
        }
        assert!(relay(&["relay", "offer", "on", "--also-443", "--no-443"]).is_err());
        assert!(matches!(
            relay(&["relay", "auto", "off"]),
            Ok(R::Auto { state: OnOff::Off })
        ));
        assert!(relay(&["relay", "auto"]).is_err());
    }
}
