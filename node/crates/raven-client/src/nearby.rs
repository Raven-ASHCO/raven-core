//! Bluetooth nearby in the engine API (Task 2 design §4): `nearby.status`,
//! `nearby.contact`, `nearby.stop_all` and `nearby.permission`, next to the
//! existing `network.set {nearby}` (`raven nearby enable|disable`) and
//! `network.set {nearby_background_mail}` (`raven nearby background-mail`).
//!
//! The CLI's own view and the running raven-node's `NearbyControl` (`raven
//! nearby status|on|off`): counts and states only, as raven-node reports
//! them. What raven-node never reports per contact stays local to this app
//! (Task 2 Q4): `advertising_for` lists only the friends this app asked
//! `nearby.contact` to advertise for (by your names for them), still within
//! their time; raven-node forgets them when it restarts.
//!
//! Held while the nearby gate is closed in this process (a release build on
//! iOS, Windows or Linux): `nearby.status` says `held`, the others answer
//! `NOT_AVAILABLE_YET` and change nothing.

use std::path::Path;
use std::time::Duration;

use ash_engine::engine as bridge;
use raven_core::ipc::{IpcRequest, IpcResponse, NearbyStatusInfo, IPC_VERSION};
use serde_json::{json, Value};

use crate::engine::{lock, now_ms, Inner};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::network::NetFacts;
use crate::safety;

/// How long `NearbyControl` may take (the CLI's: the node answers at once).
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// `nearby.contact`'s `for_min`: as `raven nearby on --for` (30 min to
/// 24 h).
const FOR_MIN: std::ops::RangeInclusive<u64> = 30..=1440;

/// iOS drafts for the owner (Task 2 design §5.3, question Q7): the consent
/// before `network.set {nearby: true}`.
const CONSENT_IOS: &str = "Nearby (Bluetooth) lets your verified friends in radio range get your \
     messages with no network at all. On iPhone it works while Raven is open. Nearby devices can \
     see a random Bluetooth ID, which changes every 15 minutes, only while you have something to \
     send. A device that connects can read this iPhone's name (Settings > General > About > \
     Name) and its model. Only verified friends can use it, and messages stay end-to-end \
     encrypted.";
/// iOS draft (§5.3): the status row while nearby stops in the background.
const FOREGROUND_ONLY_IOS: &str = "Bluetooth nearby pauses while Raven is in the background. Open \
     Raven near your friend to exchange messages.";
/// iOS draft (§5.3): the status row while nearby keeps running in the
/// background (`node.pause {nearby: "keep"}`).
const BACKGROUND_IOS: &str = "In the background, iPhone lets Raven find friends only slowly, and \
     a friend's Mac cannot find this iPhone. Open Raven for a quick exchange.";
/// iOS draft (§5.3): after the person swiped Raven away.
const AFTER_SWIPE_IOS: &str = "Bluetooth stays off until you open Raven again.";
/// iOS draft (§5.3): the battery line of background mail with background
/// Bluetooth.
const BATTERY_IOS: &str = "Raven keeps Bluetooth listening while mail waits. This uses some \
     battery.";

/// What a NearbyControl refusal of raven-node is in the API.
fn node_refusal(code: &str, message: String) -> ApiError {
    let (code, plain) = match code {
        "NEARBY_HOLD" => (
            code::NOT_AVAILABLE_YET,
            "Raven's background program doesn't have Bluetooth nearby in this version. Nothing \
             was changed.",
        ),
        "NEARBY_NOT_RUNNING" => (
            code::NEARBY_NOT_RUNNING,
            "Bluetooth nearby isn't running. Turn it on in Network first.",
        ),
        "NEARBY_POLICY" => (
            code::NEARBY_POLICY,
            "Raven couldn't save the Bluetooth nearby setting. Open Details to see why.",
        ),
        _ => (
            code::NEARBY_BAD_REQUEST,
            "Raven's background program didn't take that Bluetooth nearby request. Open Details.",
        ),
    };
    ApiError::new(code, plain, message)
}

/// The nearby gate closed in this process: nothing is asked of raven-node.
fn held(op: &str) -> ApiError {
    ApiError::new(
        code::NOT_AVAILABLE_YET,
        "Bluetooth nearby isn't in this version of Raven on this device yet. Nothing was changed.",
        format!("{op}: {}", raven_core::NEARBY_HOLD),
    )
}

/// IPC `NearbyControl` to the running raven-node: its nearby status after
/// `action`, or why not.
fn control(
    dir: &Path,
    action: &str,
    peer_pub_hex: Option<&str>,
    ttl_secs: Option<u32>,
) -> Result<NearbyStatusInfo, ApiError> {
    let req = IpcRequest::NearbyControl {
        v: IPC_VERSION,
        action: action.into(),
        peer_pub_hex: peer_pub_hex.map(str::to_string),
        ttl_secs,
    };
    match bridge::ipc_request_timeout(dir, &req, CONTROL_TIMEOUT) {
        Ok(IpcResponse::NearbyControlResult { status, .. }) => Ok(*status),
        Ok(IpcResponse::Error { code, message, .. }) if code == "IPC_FRAME" => Err(ApiError::new(
            code::NOT_AVAILABLE_YET,
            "Raven's background program is too old for Bluetooth nearby. Update Raven.",
            message,
        )),
        Ok(IpcResponse::Error { code, message, .. }) => Err(node_refusal(&code, message)),
        Ok(other) => Err(ApiError::internal(format!(
            "unexpected answer to NearbyControl: {other:?}"
        ))),
        Err(e) if bridge::error_means_not_running(&e) => Err(ApiError::of(
            code::NODE_NOT_RUNNING,
            format!("nearby {action}: {e}"),
        )),
        Err(e) => Err(ApiError::internal(e)),
    }
}

/// `background`: whether nearby keeps working while the app is in the
/// background. The desktop's raven-node runs on its own; an embedded node
/// (iOS) keeps it only after `node.pause {nearby: "keep"}`.
fn background_word() -> &'static str {
    #[cfg(feature = "embedded-node")]
    if crate::embedded::mode_on() && !crate::embedded::kept_nearby() {
        return "foreground_only";
    }
    "background"
}

/// The app's Bluetooth permission (iOS only).
fn permission() -> Option<&'static str> {
    #[cfg(feature = "embedded-node")]
    if let Some(p) = crate::embedded::nearby_permission() {
        return Some(p);
    }
    None
}

impl Inner {
    /// `NearbyStatus`: the CLI's view of the carrier with what the running
    /// raven-node reports, this app's own `advertising_for`, and the texts
    /// the app shows (see the module doc).
    pub(crate) fn nearby_status(&self) -> OpResult {
        let dir = self.data_dir()?.to_path_buf();
        let facts = NetFacts::read(&dir);
        Ok(self.status_json(&dir, &facts.nearby, now_ms()))
    }

    fn status_json(&self, dir: &Path, view: &bridge::NearbyView, now: u64) -> Value {
        let policy = raven_core::node_policy::try_load_policy(dir).ok();
        let saved_background = policy
            .as_ref()
            .and_then(|p| p.nearby_background_mail)
            .unwrap_or(false);
        let info = view.info.clone().unwrap_or_default();
        let live = view.info.is_some();
        let rows: Vec<Value> = view
            .rows
            .iter()
            .map(|(label, value)| json!({"label": label, "value": safety::line(value)}))
            .collect();
        let background = background_word();
        let ios = cfg!(target_os = "ios");
        let mut texts = json!({
            "nearby": if ios { CONSENT_IOS.to_owned() } else { bridge::nearby_consent() },
            "nearby_background_mail": if ios {
                format!("{}\n{BATTERY_IOS}", bridge::NEARBY_BACKGROUND_MAIL_CONSENT)
            } else {
                bridge::NEARBY_BACKGROUND_MAIL_CONSENT.to_owned()
            },
        });
        if ios {
            texts["background"] = if background == "background" {
                BACKGROUND_IOS
            } else {
                FOREGROUND_ONLY_IOS
            }
            .into();
            texts["after_swipe"] = AFTER_SWIPE_IOS.into();
        }
        let mut v = json!({
            "state": view.state,
            "enabled": if live { info.enabled } else { view.saved == Some(true) },
            "background_mail": if live { info.background_mail } else { saved_background },
            "radio": if live { info.radio.clone() } else { "off".to_owned() },
            "roles": info.roles,
            "address_privacy": if live { info.address_privacy.clone() } else { "unknown".to_owned() },
            "advertising": info.advertising > 0,
            "rotating": info.rotating,
            "in_range": info.in_range,
            "connected": info.pipes,
            "frames_tx": info.frames_tx,
            "frames_rx": info.frames_rx,
            "bytes_tx": info.bytes_tx,
            "bytes_rx": info.bytes_rx,
            "knock_silenced": info.knock_silenced,
            "background": background,
            "advertising_for": self.advertising_for(live, now),
            "rows": rows,
            "texts": texts,
        });
        if let Some(p) = permission() {
            v["permission"] = p.into();
        }
        v
    }

    /// The friends this app asked raven-node to advertise for, still within
    /// their time (none while nearby does not run), by your names for them.
    fn advertising_for(&self, live: bool, now: u64) -> Vec<Value> {
        let mut on = lock(&self.nearby_on);
        on.retain(|_, until| until.is_none_or(|u| u > now));
        if !live {
            return Vec::new();
        }
        let contacts = self.contacts().ok();
        let mut list: Vec<Value> = on
            .iter()
            .filter_map(|(key, until)| {
                let c = contacts
                    .as_ref()?
                    .iter()
                    .find(|c| c.pub_hex.trim().eq_ignore_ascii_case(key))?;
                let mut e = json!({"address": c.address, "name": safety::line(&c.label)});
                if let Some(u) = until {
                    e["until_ms"] = (*u).into();
                }
                Some(e)
            })
            .collect();
        list.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        list
    }

    /// `nearby.contact {address, advertise, for_min?}`: `raven nearby on
    /// <friend> [--for]` or `raven nearby off <friend>`. Verified friends
    /// only; `for_min` (30 to 1440) only with `advertise: true` (without
    /// it: until asked to stop, or raven-node restarts).
    pub(crate) fn nearby_contact(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let advertise = args.opt_bool("advertise")?.ok_or_else(|| {
            ApiError::bad_request("nearby.contact needs \"advertise\": true or false")
        })?;
        let for_min = args.opt_u64("for_min")?;
        if let Some(m) = for_min {
            if !advertise || !FOR_MIN.contains(&m) {
                return Err(ApiError::bad_request(
                    "\"for_min\" is 30 to 1440 minutes, with \"advertise\": true only",
                ));
            }
        }
        if !raven_core::nearby_live_enabled() {
            return Err(held("nearby.contact"));
        }
        let dir = self.data_dir()?.to_path_buf();
        let contact = self.contact(address)?;
        if !contact.pinned {
            return Err(ApiError::new(
                code::NEARBY_BAD_REQUEST,
                "Bluetooth nearby is for verified friends only. Compare your security words with \
                 them first.",
                "nearby.contact: the friend is not verified",
            ));
        }
        let key = contact.pub_hex.trim().to_ascii_lowercase();
        let secs = for_min.map(|m| (m * 60) as u32);
        let action = if advertise { "on" } else { "off" };
        control(&dir, action, Some(&key), secs)?;
        let until = for_min.map(|m| now_ms() + m * 60_000);
        {
            let mut on = lock(&self.nearby_on);
            if advertise {
                on.insert(key, until);
            } else {
                on.remove(&key);
            }
        }
        let facts = NetFacts::read(&dir);
        let mut v = json!({
            "address": contact.address,
            "advertising": advertise,
            "status": self.status_json(&dir, &facts.nearby, now_ms()),
        });
        if let Some(u) = until {
            v["until_ms"] = u.into();
        }
        Ok(v)
    }

    /// `nearby.stop_all`: `raven nearby off` with no friend (every verified
    /// friend's advertising stops; contacts that advertise for this device
    /// are still seen).
    pub(crate) fn nearby_stop_all(&self) -> OpResult {
        if !raven_core::nearby_live_enabled() {
            return Err(held("nearby.stop_all"));
        }
        let dir = self.data_dir()?.to_path_buf();
        let keys: Vec<String> = self
            .contacts()?
            .iter()
            .filter(|c| c.pinned)
            .map(|c| c.pub_hex.trim().to_ascii_lowercase())
            .collect();
        for key in &keys {
            control(&dir, "off", Some(key), None)?;
        }
        lock(&self.nearby_on).clear();
        let facts = NetFacts::read(&dir);
        Ok(json!({"status": self.status_json(&dir, &facts.nearby, now_ms())}))
    }

    /// `nearby.permission` (iOS): the app's Bluetooth permission, read
    /// without a prompt, so the app can explain before iOS asks. Elsewhere
    /// the permission is not this app's (macOS: RavenNearby's).
    pub(crate) fn nearby_permission(&self) -> OpResult {
        match permission() {
            Some(p) => Ok(json!({"permission": p})),
            None => Err(ApiError::of(
                code::NOT_ON_THIS_SYSTEM,
                "nearby.permission: iPhone and iPad only (on macOS Bluetooth is RavenNearby's \
                 permission, in System Settings)",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// raven-node's refusals keep their nearby codes (the closed gate is
    /// NOT_AVAILABLE_YET), with the node's words under Details.
    #[test]
    fn node_refusals_keep_their_codes() {
        for (node, api) in [
            ("NEARBY_HOLD", code::NOT_AVAILABLE_YET),
            ("NEARBY_NOT_RUNNING", code::NEARBY_NOT_RUNNING),
            ("NEARBY_POLICY", code::NEARBY_POLICY),
            ("NEARBY_BAD_REQUEST", code::NEARBY_BAD_REQUEST),
            ("ANYTHING_ELSE", code::NEARBY_BAD_REQUEST),
        ] {
            let e = node_refusal(node, "why".into());
            assert_eq!(e.code, api, "{node}");
            assert_eq!(e.detail, "why");
            assert!(!e.message.is_empty());
        }
    }

    /// The iOS drafts are plain sentences that name no command.
    #[test]
    fn the_ios_drafts_name_no_command() {
        for t in [
            CONSENT_IOS,
            FOREGROUND_ONLY_IOS,
            BACKGROUND_IOS,
            AFTER_SWIPE_IOS,
            BATTERY_IOS,
        ] {
            assert!(!t.contains("raven "), "{t}");
            assert!(t.ends_with('.'), "{t}");
        }
        assert_eq!(background_word(), {
            #[cfg(feature = "embedded-node")]
            let w = if crate::embedded::mode_on() {
                "foreground_only"
            } else {
                "background"
            };
            #[cfg(not(feature = "embedded-node"))]
            let w = "background";
            w
        });
    }
}
