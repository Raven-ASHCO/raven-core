//! The Bluetooth nearby carrier in the CLI (Phase 5, Nearby design step
//! 5.7; `protocol/RAVEN_NEARBY_LINK_V1.md`): `raven nearby
//! enable|disable|on|off|status`, the consent shown once, the BLUETOOTH
//! NEARBY rows of `raven status` and the `bluetooth_nearby:` line of `raven
//! doctor`, menu 7, and the best-effort `foreground` a send or a chat gives
//! the running raven-node.
//! Owner decision OD-C8 (2026-10-28): `raven nearby background-mail
//! on|off|status`, background mail's own consent (default off), asked like
//! the custody consents (`raven node custody on`, `raven custody use on`).
//!
//! Held by [`raven_core::nearby_live_enabled`] (`NEARBY_PRODUCTION_ENABLED`
//! is false; a debug build opens it with `RAVEN_LAB_TEST_A=1` and
//! `RAVEN_LAB_NEARBY=1`): held, every command but `status` refuses with the
//! hold and changes nothing, a send asks nothing, and `raven status` shows
//! nothing unless a choice was saved. The running raven-node does the work
//! (IPC `NearbyControl`); with none running, `enable` and `disable` save the
//! choice in node_policy.json for its next start. Rows hold counts and
//! states only: never a contact key, token, Bluetooth address or name (the
//! consent names this computer's own Bluetooth name, to its own user).

use std::path::Path;
use std::time::Duration;

use raven_core::ipc::{IpcRequest, IpcResponse, NearbyStatusInfo, IPC_VERSION};
use raven_core::node_policy::{try_load_policy, NodePolicy};
use raven_core::sanitize::sanitize_terminal_line;

use super::custody_cli::{said_yes, Refusal};
use super::{
    ipc_client, load_contacts, no_contact_message, require_identity_before_state,
    resolve_contact_arg, Contact, C_BOLD, C_DIM, C_GREEN, C_PURPLE, C_RESET,
};

/// What `raven nearby` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NearbyArg {
    /// Turn nearby on (the consent, once).
    Enable,
    /// Turn it off.
    Disable,
    /// Advertise for one verified contact now, for `ttl` (`30m`, `2h`, as
    /// `raven lan on --for`; `None`: until `off`).
    On {
        contact: String,
        ttl: Option<String>,
    },
    /// Stop advertising for one contact, or for all of them.
    Off { contact: Option<String> },
    /// The nearby carrier now.
    Status,
}

/// What `raven nearby background-mail` was asked (owner decision OD-C8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackgroundArg {
    /// Turn background mail on (its consent first; `yes`: without the
    /// question, for scripts).
    On { yes: bool },
    /// Turn it off.
    Off,
    /// Whether it is on.
    Status,
}

/// How long `NearbyControl` may take (the node answers at once; a busy one
/// is not waited for).
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// A send's foreground is best effort: never hold the send up.
const FOREGROUND_TIMEOUT: Duration = Duration::from_millis(800);

/// What an older raven-node (which answers `IPC_FRAME` to a nearby request)
/// means for the user.
pub(super) const TOO_OLD: &str = "raven-node is too old for nearby: update it";
/// With no raven-node running, `on` and `off` have nothing to tell.
const NOT_RUNNING: &str = "raven-node is not running: nearby needs it (it starts when you \
     send, or run `raven listen`)";

/// The ask-once consent of `raven nearby enable` (owner decision O5-12):
/// what nearby devices can see, what a device that connects can read (this
/// computer's Bluetooth name `name` and model), what someone who recorded a
/// contact's Bluetooth ID can learn (review nearby-4), and who may use it.
pub(super) fn consent_text(name: &str) -> String {
    format!(
        "Nearby (Bluetooth) lets your verified contacts in radio range get your messages with \
         no network at all:\n\
         \x20 - nearby devices can see a random Bluetooth ID, which changes every 15 minutes, \
         only while you have something to send to a contact (or after `raven nearby on`);\n\
         \x20 - this computer connects, from a random Bluetooth address, to a contact whose ID \
         it sees; someone who recorded that contact's ID in the last 30 minutes can play it \
         back to learn that this computer is in range (at most twice per recorded ID);\n\
         \x20 - a device that connects to this computer can read its Bluetooth name '{}' and \
         its model;\n\
         \x20 - only your verified contacts can use it, and messages stay end-to-end \
         encrypted.\n\
         This is shown once. Turn nearby off any time: raven nearby disable",
        sanitize_terminal_line(name)
    )
}

/// What `raven nearby background-mail on` asks (owner decision OD-C8; offline
/// mesh carry research, Phase 0): what a radio neighbour then sees without
/// any send of the user's (an advert while mail waits, so that this
/// computer keeps or waits with mail for someone, and for how long), who
/// can use it, the replay a recorded ID allows (as `raven nearby enable`
/// says, review nearby-4), the battery, and that it needs nearby itself.
/// Off by default, and asked like the custody consents: on a terminal only
/// `y` / `yes` turns it on; off a terminal it needs `--yes`.
pub(super) const BACKGROUND_MAIL_CONSENT: &str = "\
Advertise over Bluetooth while mail waits (background mail)?
While this computer keeps sealed mail for a verified contact (as their mail
friend), or has a message or a receipt waiting for them, nearby also advertises
for that contact on its own, not only while you send:
- nearby devices can see a random Bluetooth ID, which changes every 15 minutes,
  for as long as such mail waits (at most 2 contacts at a time). They cannot
  tell whom it is for, but they can see that this computer advertises, and so
  that it keeps or waits with mail for someone, and for how long.
- Only that contact's computer recognises the ID; it connects and collects the
  mail. Only your verified contacts can, and the mail stays end-to-end
  encrypted: this computer cannot read what it keeps for friends.
- Someone who recorded that contact's ID in the last 30 minutes can play it back
  to learn that this computer is in range (at most twice per recorded ID).
- Bluetooth keeps scanning while background mail is on (more battery on a
  laptop).
It works only while nearby itself is on (raven nearby enable). Turn it off any
time: raven nearby background-mail off";

/// Off a terminal without `--yes`: nothing is asked and nothing changes.
pub(super) const BACKGROUND_NEEDS_YES: &str = "background mail needs your consent and stdin is \
    not a terminal: add --yes to turn it on without the question (nothing changed)";

/// This computer's Bluetooth name, as a device that connects can read it
/// (its GAP device name): the computer name on macOS (`scutil --get
/// ComputerName`) and Windows (`COMPUTERNAME`), BlueZ's default on Linux
/// (the pretty host name of /etc/machine-info, else the host name). "this
/// computer's name" when it cannot be read. Read-only.
pub(super) fn bluetooth_name() -> String {
    let name = if cfg!(target_os = "macos") {
        std::process::Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else if cfg!(windows) {
        std::env::var("COMPUTERNAME").ok()
    } else {
        std::fs::read_to_string("/etc/machine-info")
            .ok()
            .and_then(|t| pretty_hostname(&t))
            .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
    };
    let name: String = name
        .map(|n| sanitize_terminal_line(n.trim()))
        .unwrap_or_default()
        .chars()
        .take(64)
        .collect();
    if name.is_empty() {
        "this computer's name".into()
    } else {
        name
    }
}

/// `PRETTY_HOSTNAME` of an /etc/machine-info text (quotes removed).
fn pretty_hostname(machine_info: &str) -> Option<String> {
    machine_info.lines().find_map(|l| {
        let v = l.trim().strip_prefix("PRETTY_HOSTNAME=")?.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(v);
        (!v.trim().is_empty()).then(|| v.trim().to_string())
    })
}

/// `--for`: as `raven lan on --for` reads it (30m, 1h, 3h: minutes or
/// hours, up to 24h), in seconds.
pub(super) fn parse_for(s: &str) -> Result<u32, String> {
    let minutes = super::parse_meeting_minutes(s)?;
    u32::try_from(minutes * 60).map_err(|_| "--for is too long".to_string())
}

/// What the nearby carrier is, as `raven status`, `raven doctor` and
/// `raven nearby status` show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NearbyView {
    /// This build holds nearby (a release build): the saved choice, if any.
    Held { saved: Option<bool> },
    /// The running raven-node does not run nearby: its own gate is closed,
    /// or it is older than nearby.
    NodeHeld { saved: Option<bool> },
    /// No raven-node answers: the saved choice.
    NotRunning { saved: Option<bool> },
    /// What the running raven-node reports.
    Live(Box<NearbyStatusInfo>),
}

/// The saved choice (node_policy `nearby`); `None` when never asked or
/// unreadable.
fn saved(data_dir: &Path) -> Option<bool> {
    try_load_policy(data_dir).ok().and_then(|p| p.nearby)
}

/// [`NearbyView`] from `raven status`'s IPC answer (no extra request).
pub(super) fn view(data_dir: &Path, daemon: &Result<IpcResponse, String>) -> NearbyView {
    view_with(raven_core::nearby_live_enabled(), saved(data_dir), daemon)
}

/// [`view`] from its inputs: this build's gate, the saved choice and the
/// node's answer.
pub(super) fn view_with(
    gate: bool,
    saved: Option<bool>,
    daemon: &Result<IpcResponse, String>,
) -> NearbyView {
    if !gate {
        return NearbyView::Held { saved };
    }
    match daemon {
        Ok(IpcResponse::Status {
            nearby: Some(info), ..
        }) => NearbyView::Live(info.clone()),
        Ok(IpcResponse::Status { .. }) => NearbyView::NodeHeld { saved },
        _ => NearbyView::NotRunning { saved },
    }
}

/// The radio state in words, with what to do about it.
fn radio_text(info: &NearbyStatusInfo) -> String {
    match info.radio.as_str() {
        "powered_on" if info.roles.iter().any(|r| r == "peripheral") => "on".into(),
        "powered_on" => {
            "on, central only: this computer can only connect to contacts that advertise".into()
        }
        "off" => "off: turn Bluetooth on in this computer's settings".into(),
        // On macOS the permission belongs to the RavenNearby helper app, not
        // raven-node (docs/NEARBY.md).
        "unauthorized" => "not allowed: allow Bluetooth for Raven in this computer's privacy \
                           settings (on macOS: RavenNearby), then restart raven-node"
            .into(),
        "unsupported" => "no Bluetooth LE on this computer".into(),
        "no_backend" => "no Bluetooth support in this build of raven-node".into(),
        // Review nearby-3: what raven-node could not start, not the
        // computer's Bluetooth (docs/NEARBY.md section 8).
        "helper_unavailable" => "the RavenNearby helper is missing, outdated or did not run: \
                                 install it (RAVEN_INSTALL_NEARBY_HELPER=1 bash \
                                 scripts/install/macos_launchd.sh), then restart raven-node"
            .into(),
        "service_down" => "the Bluetooth service is not running: start it (sudo systemctl \
                           enable --now bluetooth); raven-node tries again by itself"
            .into(),
        "local_state" => "Raven's own state is not ready (identity, sessions or disk space): \
                          see the other lines of raven doctor; raven-node tries again by itself"
            .into(),
        other => sanitize_terminal_line(other),
    }
}

/// The address the radio would use on the air, while it is on. A fixed
/// public address keeps nearby inactive: no advert and no connect (owner
/// decision O5-12, review nearby-1: a connect shows the address as an advert
/// does); Windows does not say which address it uses.
fn address_text(info: &NearbyStatusInfo) -> Option<&'static str> {
    if info.radio != "powered_on" {
        return None;
    }
    match info.address_privacy.as_str() {
        "random" if info.roles.iter().any(|r| r == "peripheral") => {
            Some("random, changing (nothing fixed is advertised)")
        }
        "public" if cfg!(windows) => Some(
            "nearby inactive: Windows may use this PC's fixed Bluetooth address, so it neither \
             advertises nor connects until that is ruled out (row N7w)",
        ),
        "public" => Some(
            "nearby inactive: the adapter would use its fixed public address, so this computer \
             neither advertises nor connects; set Privacy = device in /etc/bluetooth/main.conf \
             (admin)",
        ),
        _ => None,
    }
}

/// The off row: how to turn it on.
const OFF_ROW: &str = "off (turn on: raven nearby enable; verified contacts only)";

/// The first row of the BLUETOOTH NEARBY section: whether it is on.
const STATE_LABEL: &str = "state";

/// The BLUETOOTH NEARBY section's `background` row while background mail
/// is on (OD-C8).
const BACKGROUND_ON_ROW: &str = "mail on: also advertises for contacts this computer keeps or \
    has mail for (raven nearby background-mail off)";

/// The rows of the BLUETOOTH NEARBY section of `raven status` and `raven
/// nearby status` (label, value). Held with nothing saved: none (a release build's
/// status is as before).
pub(super) fn status_rows(view: &NearbyView) -> Vec<(&'static str, String)> {
    match view {
        NearbyView::Held { saved: None } => Vec::new(),
        NearbyView::Held { saved: Some(_) } => vec![(
            STATE_LABEL,
            format!("held in this build: {HELD_WHY} (your choice is kept)"),
        )],
        NearbyView::NodeHeld { .. } => vec![(
            STATE_LABEL,
            "raven-node does not run nearby (held there, or too old: update it)".into(),
        )],
        NearbyView::NotRunning { saved } => vec![(
            STATE_LABEL,
            match saved {
                Some(true) => format!("on; {NOT_RUNNING}"),
                _ => OFF_ROW.into(),
            },
        )],
        NearbyView::Live(info) if !info.enabled => vec![(STATE_LABEL, OFF_ROW.into())],
        NearbyView::Live(info) => {
            let mut rows = vec![
                (STATE_LABEL, "on (verified contacts only)".to_string()),
                ("radio", radio_text(info)),
            ];
            if let Some(addr) = address_text(info) {
                rows.push(("address", addr.into()));
            }
            if info.radio == "powered_on" {
                let mut range = format!(
                    "{} contact{} in range now, {} connected",
                    info.in_range,
                    if info.in_range == 1 { "" } else { "s" },
                    info.pipes
                );
                if info.advertising > 0 {
                    range.push_str(&format!(
                        "; advertising for {} (only while you have something to send{})",
                        info.rotating,
                        if info.background_mail {
                            " or mail waits"
                        } else {
                            ""
                        }
                    ));
                }
                rows.push(("in range", range));
            }
            if info.background_mail {
                rows.push(("background", BACKGROUND_ON_ROW.into()));
            }
            rows
        }
    }
}

/// `raven doctor`'s Bluetooth nearby lines: `bluetooth_nearby: …` (keys and
/// counts), and `bluetooth_nearby_fix: …` when the radio needs the user.
/// Named apart from the LAN search row (the LAN beacon), which is another
/// feature.
pub(super) fn doctor_lines(view: &NearbyView) -> Vec<String> {
    let saved_word = |s: &Option<bool>| match s {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unset",
    };
    match view {
        NearbyView::Held { .. } => vec![format!("bluetooth_nearby: held ({HELD_DOCTOR})")],
        NearbyView::NodeHeld { saved } => vec![format!(
            "bluetooth_nearby: node=held_or_old enabled={}",
            saved_word(saved)
        )],
        NearbyView::NotRunning { saved } => vec![format!(
            "bluetooth_nearby: node=not_running enabled={}",
            saved_word(saved)
        )],
        NearbyView::Live(info) => {
            let mut lines = vec![format!(
                "bluetooth_nearby: enabled={} radio={} roles={} address={} advertising={} rotating={} \
                 in_range={} pipes={} knock_silenced={} background_mail={}",
                if info.enabled { "yes" } else { "no" },
                sanitize_terminal_line(&info.radio),
                sanitize_terminal_line(&info.roles.join(",")),
                sanitize_terminal_line(&info.address_privacy),
                info.advertising,
                info.rotating,
                info.in_range,
                info.pipes,
                info.knock_silenced,
                if info.background_mail { "yes" } else { "no" }
            )];
            if info.enabled {
                let radio = radio_text(info);
                if info.radio == "powered_on" && info.address_privacy == "public" {
                    lines.push(format!(
                        "bluetooth_nearby_fix: {}",
                        address_text(info).unwrap_or_default()
                    ));
                } else if info.radio != "powered_on"
                    || !info.roles.iter().any(|r| r == "peripheral")
                {
                    lines.push(format!("bluetooth_nearby_fix: {radio}"));
                }
            }
            lines
        }
    }
}

/// A raven-node's answer to `NearbyControl`.
enum Control {
    Done(Box<NearbyStatusInfo>),
    /// IPC `IPC_FRAME`: older than nearby.
    TooOld,
    /// No raven-node answers.
    NotRunning,
    /// A refusal: its code and why.
    Refused(String, String),
}

fn control(
    data_dir: &Path,
    action: &str,
    peer_pub_hex: Option<&str>,
    ttl_secs: Option<u32>,
    timeout: Duration,
) -> Control {
    let req = IpcRequest::NearbyControl {
        v: IPC_VERSION,
        action: action.into(),
        peer_pub_hex: peer_pub_hex.map(str::to_string),
        ttl_secs,
    };
    control_answer(ipc_client::ipc_request_timeout(data_dir, &req, timeout))
}

/// [`control`]'s answer in words.
fn control_answer(answer: Result<IpcResponse, String>) -> Control {
    match answer {
        Ok(IpcResponse::NearbyControlResult { status, .. }) => Control::Done(status),
        Ok(IpcResponse::Error { code, .. }) if code == "IPC_FRAME" => Control::TooOld,
        Ok(IpcResponse::Error { code, message, .. }) => Control::Refused(code, message),
        Ok(other) => Control::Refused("IPC".into(), format!("unexpected answer: {other:?}")),
        Err(e) if ipc_client::error_means_not_running(&e) => Control::NotRunning,
        Err(e) => Control::Refused("IPC".into(), e),
    }
}

/// A refusal of the running node in words (its stable code kept for
/// scripts).
fn refused_text(code: &str, message: &str) -> String {
    match code {
        "NEARBY_HOLD" => format!(
            "raven-node holds nearby in its build: {}",
            sanitize_terminal_line(message)
        ),
        "NEARBY_NOT_RUNNING" => format!(
            "nearby is not running in raven-node: turn it on with `raven nearby enable` (it \
             also needs Bluetooth support in raven-node's build) ({code})"
        ),
        _ => format!(
            "nearby: {} ({})",
            sanitize_terminal_line(message),
            sanitize_terminal_line(code)
        ),
    }
}

/// The verified contact `arg` names, as `(label, key hex)`.
fn verified_contact(data_dir: &Path, arg: &str) -> Result<(String, String), String> {
    let contacts = load_contacts(data_dir)?;
    let hits: Vec<&Contact> = resolve_contact_arg(&contacts, arg);
    let c = match hits.as_slice() {
        [] => return Err(no_contact_message(&contacts, arg)),
        [c] => *c,
        _ => {
            return Err(format!(
                "contact {} is ambiguous ({} matches): use the @tag, or see `ash contact list`",
                sanitize_terminal_line(arg),
                hits.len()
            ))
        }
    };
    if !c.pinned {
        return Err(format!(
            "{} is not verified: nearby is for verified contacts only (compare the security \
             words with them, then pin: raven contact verify)",
            c.primary_label()
        ));
    }
    Ok((c.primary_label(), c.pub_hex.trim().to_ascii_lowercase()))
}

/// `raven nearby …`: the lines to print, or why not.
pub(super) fn cmd_nearby(data_dir: &Path, arg: NearbyArg) -> Result<Vec<String>, String> {
    if arg == NearbyArg::Status {
        return Ok(nearby_status(data_dir));
    }
    if !raven_core::nearby_live_enabled() {
        return Err(format!(
            "nearby is not available in this build (nothing changed): {}",
            raven_core::NEARBY_HOLD
        ));
    }
    require_identity_before_state(data_dir, "nearby")?;
    match arg {
        NearbyArg::Enable | NearbyArg::Disable => enable(data_dir, arg == NearbyArg::Enable),
        NearbyArg::On { contact, ttl } => {
            let secs = ttl.as_deref().map(parse_for).transpose()?;
            let (who, key) = verified_contact(data_dir, &contact)?;
            let status = expect_done(control(data_dir, "on", Some(&key), secs, CONTROL_TIMEOUT))?;
            let until = match secs {
                Some(s) if s % 3600 == 0 => format!("for {} h", s / 3600),
                Some(s) if s % 60 == 0 => format!("for {} min", s / 60),
                Some(s) => format!("for {s} s"),
                None => "until `raven nearby off` (or raven-node restarts)".into(),
            };
            let mut lines = vec![format!(
                "ok nearby on for {who} {until}: this computer advertises a random Bluetooth \
                 ID only {who} can recognise"
            )];
            lines.extend(rows_text(&NearbyView::Live(status)));
            Ok(lines)
        }
        NearbyArg::Off { contact } => {
            let targets = match contact {
                Some(arg) => vec![verified_contact(data_dir, &arg)?],
                None => load_contacts(data_dir)?
                    .iter()
                    .filter(|c| c.pinned)
                    .map(|c| (c.primary_label(), c.pub_hex.trim().to_ascii_lowercase()))
                    .collect(),
            };
            let mut status = None;
            for (_, key) in &targets {
                status = Some(expect_done(control(
                    data_dir,
                    "off",
                    Some(key),
                    None,
                    CONTROL_TIMEOUT,
                ))?);
            }
            let who = match targets.as_slice() {
                [(who, _)] => who.clone(),
                _ => "every contact".into(),
            };
            let mut lines = vec![format!(
                "ok nearby off for {who}: this computer stops advertising for them (it still \
                 sees contacts who advertise for it)"
            )];
            if let Some(status) = status {
                lines.extend(rows_text(&NearbyView::Live(status)));
            }
            Ok(lines)
        }
        NearbyArg::Status => unreachable!("answered above"),
    }
}

/// A `Done` answer's status, or why not.
fn expect_done(c: Control) -> Result<Box<NearbyStatusInfo>, String> {
    match c {
        Control::Done(status) => Ok(status),
        Control::TooOld => Err(TOO_OLD.into()),
        Control::NotRunning => Err(NOT_RUNNING.into()),
        Control::Refused(code, message) => Err(refused_text(&code, &message)),
    }
}

/// `raven nearby enable|disable`: the running raven-node saves the choice
/// and applies it at once; with none running it is saved for its next
/// start. The consent comes before the first `enable` only (nothing saved
/// yet: never asked).
fn enable(data_dir: &Path, on: bool) -> Result<Vec<String>, String> {
    let policy = try_load_policy(data_dir).map_err(|e| {
        format!(
            "node_policy.json is unreadable ({}); fix or move it aside first (nothing changed)",
            sanitize_terminal_line(&e.to_string())
        )
    })?;
    let mut lines = Vec::new();
    if on && policy.nearby.is_none() {
        lines.extend(consent_text(&bluetooth_name()).lines().map(str::to_string));
    }
    let action = if on { "enable" } else { "disable" };
    let applied = match control(data_dir, action, None, None, CONTROL_TIMEOUT) {
        Control::Done(status) => Some(status),
        Control::NotRunning => {
            raven_core::node_policy::update_settings(data_dir, |p| p.nearby = Some(on))
                .map_err(|e| format!("save policy failed: {e}"))?;
            None
        }
        other => return Err(expect_done(other).err().unwrap_or_default()),
    };
    lines.push(match (on, applied.is_some()) {
        (true, true) => "ok nearby=on: raven-node looks for your verified contacts nearby now \
                         and advertises only while you have something to send"
            .into(),
        (true, false) => "ok nearby=on saved: raven-node turns it on when it starts".into(),
        (false, true) => "ok nearby=off: raven-node stopped its Bluetooth radio work".into(),
        (false, false) => "ok nearby=off saved".into(),
    });
    if let Some(status) = applied {
        lines.extend(rows_text(&NearbyView::Live(status)));
    }
    Ok(lines)
}

/// The background-mail choice node_policy.json holds (`None`: never
/// answered, which is off; unreadable: `None` too).
fn saved_background(data_dir: &Path) -> Option<bool> {
    try_load_policy(data_dir)
        .ok()
        .and_then(|p| p.nearby_background_mail)
}

/// `raven nearby background-mail …` (owner decision OD-C8) with the
/// terminal check and the question passed in; the lines to print, or the
/// refusal and its exit code (2: it needs `--yes`). The running raven-node
/// saves the choice and applies it at once (`NearbyControl
/// background_on|off`); with none running, or one older than this action
/// (it reads the file within [`POLICY_POLL_TEXT`]), it is saved here. It
/// never turns nearby itself on.
pub(super) fn background_mail_with(
    data_dir: &Path,
    arg: BackgroundArg,
    tty: bool,
    ask: impl FnOnce(&str) -> Option<String>,
) -> Result<Vec<String>, Refusal> {
    if arg == BackgroundArg::Status {
        return Ok(background_status(data_dir));
    }
    if !raven_core::nearby_live_enabled() {
        return Err(format!(
            "nearby is not available in this build (nothing changed): {}",
            raven_core::NEARBY_HOLD
        )
        .into());
    }
    require_identity_before_state(data_dir, "nearby")?;
    background_set(data_dir, arg, tty, ask)
}

/// [`background_mail_with`] past the gate and the identity check: `on` or
/// `off` asked, saved and applied.
fn background_set(
    data_dir: &Path,
    arg: BackgroundArg,
    tty: bool,
    ask: impl FnOnce(&str) -> Option<String>,
) -> Result<Vec<String>, Refusal> {
    if arg == BackgroundArg::Status {
        return Ok(background_status(data_dir));
    }
    let policy = try_load_policy(data_dir).map_err(|e| {
        format!(
            "node_policy.json is unreadable ({}); fix or move it aside first (nothing changed)",
            sanitize_terminal_line(&e.to_string())
        )
    })?;
    let on = matches!(arg, BackgroundArg::On { .. });
    let mut lines = Vec::new();
    if let BackgroundArg::On { yes } = arg {
        if policy.nearby_background_mail == Some(true) && !yes {
            return Ok(vec![
                "background mail is on already (raven nearby background-mail off stops it)".into(),
            ]);
        }
        if !yes && !tty {
            return Err(Refusal {
                code: 2,
                text: BACKGROUND_NEEDS_YES.into(),
            });
        }
        if !yes && !said_yes(ask(&format!("{BACKGROUND_MAIL_CONSENT}\nTurn on? [y/N] "))) {
            return Ok(vec![format!(
                "nothing changed: background mail stays {}",
                if policy.nearby_background_mail == Some(true) {
                    "on"
                } else {
                    "off"
                }
            )]);
        }
    }
    let action = if on {
        "background_on"
    } else {
        "background_off"
    };
    let save_here = || {
        raven_core::node_policy::update_settings(data_dir, |p| {
            p.nearby_background_mail = Some(on);
        })
        .map_err(|e| format!("save policy failed: {e}"))
    };
    let applied = match control(data_dir, action, None, None, CONTROL_TIMEOUT) {
        Control::Done(status) => Some(status),
        Control::NotRunning => {
            save_here()?;
            None
        }
        // A raven-node older than this action: saved here, and its nearby
        // service reads the file within its poll.
        Control::Refused(code, _) if code == "NEARBY_BAD_REQUEST" => {
            save_here()?;
            lines.push(background_first_line(on, Applied::Polled));
            return Ok(with_consent(lines, arg, &policy));
        }
        other => return Err(expect_done(other).err().unwrap_or_default().into()),
    };
    lines.push(background_first_line(
        on,
        if applied.is_some() {
            Applied::Now
        } else {
            Applied::AtStart
        },
    ));
    let mut lines = with_consent(lines, arg, &policy);
    if let Some(status) = applied {
        lines.extend(rows_text(&NearbyView::Live(status)));
    }
    Ok(lines)
}

/// When raven-node applies a background-mail choice.
#[derive(Clone, Copy)]
enum Applied {
    Now,
    AtStart,
    /// An older raven-node: from the file, within its poll.
    Polled,
}

/// How often an older raven-node reads the nearby settings.
const POLICY_POLL_TEXT: &str = "30 s";

/// The `ok` line of `raven nearby background-mail on|off`.
fn background_first_line(on: bool, applied: Applied) -> String {
    match (on, applied) {
        (true, Applied::Now) => "ok background mail on: nearby also advertises for the contacts \
                                 this computer keeps or has mail for (at most 2 at a time)"
            .into(),
        (true, Applied::AtStart) => {
            "ok background mail on saved: raven-node applies it when it starts".into()
        }
        (false, Applied::Now) => "ok background mail off: nearby advertises only while you send \
                                  (or after raven nearby on)"
            .into(),
        (false, Applied::AtStart) => "ok background mail off saved".into(),
        (on, Applied::Polled) => format!(
            "ok background mail {} saved: this raven-node reads it within {POLICY_POLL_TEXT}",
            if on { "on" } else { "off" }
        ),
    }
}

/// After the `ok` line: with `--yes`, the consent as what was agreed to
/// (scripts keep it in their log, as `raven node custody on --yes` does);
/// turned on while nearby itself is off, a note that it waits for it.
fn with_consent(mut lines: Vec<String>, arg: BackgroundArg, policy: &NodePolicy) -> Vec<String> {
    if let BackgroundArg::On { yes } = arg {
        if yes {
            lines.extend(BACKGROUND_MAIL_CONSENT.lines().skip(1).map(str::to_string));
        }
        if policy.nearby != Some(true) {
            lines.push(
                "note: nearby itself is off: background mail starts once you turn it on \
                 (raven nearby enable)"
                    .into(),
            );
        }
    }
    lines
}

/// `raven nearby background-mail status`: the saved choice in words (and,
/// in a build that holds nearby, that it is held).
fn background_status(data_dir: &Path) -> Vec<String> {
    let on = saved_background(data_dir) == Some(true);
    let mut lines = vec![format!(
        "background mail: {}",
        if on {
            "on: nearby also advertises for the contacts this computer keeps or has mail for \
             (raven nearby background-mail off)"
        } else {
            "off: nearby advertises only while you send (raven nearby background-mail on)"
        }
    )];
    if !raven_core::nearby_live_enabled() {
        lines.push(format!(
            "held in this build: {HELD_WHY} (your choice is kept)"
        ));
    }
    lines
}

/// Why Bluetooth nearby is held here (2026-10): release builds have it on
/// macOS only; on macOS only a debug build closes it (`RAVEN_LAB_NEARBY=0`).
pub(super) const HELD_WHY: &str = if raven_core::NEARBY_PRODUCTION_ENABLED {
    "Bluetooth nearby is closed in this process (RAVEN_LAB_NEARBY=0)"
} else {
    "Bluetooth nearby is in release builds on macOS only"
};

/// [`HELD_WHY`] as `raven doctor` names it.
pub(super) const HELD_DOCTOR: &str = if raven_core::NEARBY_PRODUCTION_ENABLED {
    "RAVEN_LAB_NEARBY=0"
} else {
    "NEARBY_PRODUCTION_ENABLED=false: macOS only"
};

/// `raven nearby background-mail …`: print, or exit with the refusal's code.
pub(super) fn cmd_background_mail(data_dir: &Path, arg: BackgroundArg) {
    // Someone sees the question (as the custody consents ask it).
    let tty = super::stdin_is_tty()
        && std::io::IsTerminal::is_terminal(&std::io::stdout())
        && !cfg!(test);
    match background_mail_with(data_dir, arg, tty, super::custody_cli::ask_on_terminal) {
        Ok(lines) => print_lines(&lines),
        Err(r) => {
            eprintln!("{}", sanitize_terminal_line(&r.text));
            std::process::exit(r.code);
        }
    }
}

/// `raven nearby status` (and menu 7): the carrier now, asked of the
/// running raven-node (`NearbyControl status`).
fn nearby_status(data_dir: &Path) -> Vec<String> {
    let saved = saved(data_dir);
    let view = if !raven_core::nearby_live_enabled() {
        NearbyView::Held { saved }
    } else {
        match control(data_dir, "status", None, None, CONTROL_TIMEOUT) {
            Control::Done(status) => NearbyView::Live(status),
            Control::NotRunning => NearbyView::NotRunning { saved },
            Control::TooOld => return vec![format!("Nearby (Bluetooth): {TOO_OLD}")],
            Control::Refused(code, message) => {
                return vec![format!(
                    "Nearby (Bluetooth): {}",
                    refused_text(&code, &message)
                )]
            }
        }
    };
    let mut lines = vec!["Nearby (Bluetooth): your verified contacts in radio range".to_string()];
    // The field test's Bluetooth-only node (debug lab switch): said here
    // too, so a look at the carrier shows nothing else could carry.
    if raven_core::nearby_only() {
        lines.push(format!(
            "  {:<w$}{}",
            "only",
            raven_core::NEARBY_ONLY_NOTE,
            w = super::W_KEY
        ));
    }
    match &view {
        NearbyView::Held { .. } => lines.push(format!(
            "held in this build: {HELD_WHY}. To add a friend use `raven contact add`."
        )),
        _ => lines.extend(rows_text(&view)),
    }
    lines
}

/// [`status_rows`] as `  label   value` lines.
fn rows_text(view: &NearbyView) -> Vec<String> {
    status_rows(view)
        .into_iter()
        .map(|(k, v)| format!("  {k:<w$}{v}", w = super::W_KEY))
        .collect()
}

/// Print `raven nearby`'s lines: the first `ok` in green, the rest as
/// they are (rows dim).
pub(super) fn print_lines(lines: &[String]) {
    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            if let Some(rest) = line.strip_prefix("ok") {
                println!("{C_GREEN}ok{C_RESET}{rest}");
                continue;
            }
            if line.starts_with("Nearby (Bluetooth)") {
                println!("{C_BOLD}{line}{C_RESET}");
                continue;
            }
        }
        if line.starts_with("  ") {
            println!("{C_DIM}{line}{C_RESET}");
        } else if let Some(rest) = line.strip_prefix("Nearby (Bluetooth)") {
            println!("{C_PURPLE}Nearby (Bluetooth){C_RESET}{rest}");
        } else {
            println!("{line}");
        }
    }
}

/// A send or an open chat to `peer_pub_hex`: tell the running raven-node
/// the user works with this contact (`NearbyControl foreground`), so it
/// may advertise for them while something waits (RNL1 §3). Best effort and
/// silent: nothing in a build that holds nearby, and no word when the node
/// is old, not running or busy.
pub(super) fn foreground(data_dir: &Path, peer_pub_hex: &str) {
    if !raven_core::nearby_live_enabled() || peer_pub_hex.trim().len() != 64 {
        return;
    }
    let _ = control(
        data_dir,
        "foreground",
        Some(&peer_pub_hex.trim().to_ascii_lowercase()),
        None,
        FOREGROUND_TIMEOUT,
    );
}

#[cfg(test)]
mod tests;
