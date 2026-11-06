//! `contacts.warm` (speed design M3; the warm gate
//! `raven_core::onion_gate::onion_warm_live`, false in release builds): the
//! app says a chat with a friend opened (`why: "open"`) or that the user
//! types in it (`why: "typing"`), and the engine asks the profile's
//! raven-node to warm its Tor path to that friend ahead of the send (IPC
//! `OnionWarm`). A chat open probes the friend's rendezvous circuit, which
//! the friend's Tor answers and its raven-node never sees; typing opens an
//! onion link with no frame, which the send then rides. Nothing is sent
//! early (owner decision 8): the message goes when the user sends it.
//!
//! Nothing is asked for a friend not verified or blocked, while Lock v2
//! holds the profile (the op table's refusal), while the app's node is
//! paused or only a mail check's small node runs, or, for typing, on mobile
//! data unless the setting `typing_warm_on_mobile_data` allows it (owner
//! decision 7: on for the desktop, off for the iPhone). raven-node keeps the
//! rate limits (a chat open once per 6 minutes, typing once per 20 s per
//! friend), Tor on Wi-Fi only, and never waits for Tor or starts it.

use std::time::Duration;

use ash_engine::engine as bridge;
use raven_core::ipc::{
    IpcRequest, IpcResponse, WarmLevel, IPC_VERSION, LOCKED, ONION_WARM_SKIPPED, WARM_SKIP_WORDS,
};
use raven_core::net_path::{self, PathKind};
use serde_json::{json, Value};

use crate::engine::Inner;
use crate::envelope::{ApiError, Args, OpResult};

/// How long the engine waits for raven-node's answer: it answers at once,
/// and the warm-up goes on after it.
const WARM_ASK_TIMEOUT: Duration = Duration::from_millis(1500);

/// What the engine itself refuses before it asks raven-node, in the order
/// it looks: the friend `blocked` or not `verified`, the app's node
/// `paused`, and a typing warm-up `on_mobile_data` unless the setting
/// allows it (`mobile_data_ok`).
fn engine_refusal(
    blocked: bool,
    verified: bool,
    paused: bool,
    level: WarmLevel,
    on_mobile_data: bool,
    mobile_data_ok: bool,
) -> Option<&'static str> {
    if blocked {
        Some("blocked")
    } else if !verified {
        Some("not_verified")
    } else if paused {
        Some("paused")
    } else if level == WarmLevel::Link && on_mobile_data && !mobile_data_ok {
        Some("mobile_data")
    } else {
        None
    }
}

/// The answer when nothing warms, and why.
fn skipped(why: &'static str) -> Value {
    json!({"warming": false, "why": why})
}

/// raven-node's answer to `OnionWarm`, as the op says it.
fn answered(reply: Result<IpcResponse, String>) -> Value {
    match reply {
        Ok(IpcResponse::Accepted { .. }) => json!({"warming": true}),
        Ok(IpcResponse::Error { code, message, .. }) if code == ONION_WARM_SKIPPED => skipped(
            WARM_SKIP_WORDS
                .iter()
                .copied()
                .find(|w| *w == message)
                .unwrap_or("other"),
        ),
        // A raven-node older than the op does not know it.
        Ok(IpcResponse::Error { code, .. }) if code == "IPC_FRAME" => skipped("old_node"),
        Ok(IpcResponse::Error { code, .. }) if code == LOCKED => skipped("locked"),
        Ok(_) => skipped("other"),
        Err(_) => skipped("node_off"),
    }
}

impl Inner {
    /// `contacts.warm {address, why}` (module docs): `{warming: true}` once
    /// raven-node started the warm-up, else `{warming: false, why}`.
    pub(crate) fn contacts_warm(&self, args: &Args) -> OpResult {
        let address = args.str("address")?;
        let level = match args.str("why")? {
            "open" => WarmLevel::Circuit,
            "typing" => WarmLevel::Link,
            _ => return Err(ApiError::bad_request("\"why\" must be open or typing")),
        };
        let contact = self.contact(address)?;
        let refused = engine_refusal(
            contact.blocked,
            contact.pinned,
            crate::node::paused_here(self),
            level,
            net_path::current() == PathKind::Cellular,
            self.settings_view().typing_warm_on_mobile_data(),
        );
        if let Some(why) = refused {
            return Ok(skipped(why));
        }
        if !raven_core::onion_gate::onion_warm_live() {
            return Ok(skipped("off"));
        }
        // On the iPhone, a mail check's small node has no Tor.
        if crate::node::embedded_mode() && !self.full_node_runs_here() {
            return Ok(skipped("node_off"));
        }
        let dir = self.data_dir()?;
        let mut key = [0u8; 32];
        if hex::decode_to_slice(contact.pub_hex.trim(), &mut key).is_err() {
            return Ok(skipped("other"));
        }
        let onion = raven_core::outbox::contact_routes(dir, &key)
            .ok()
            .flatten()
            .filter(|routes| routes.pinned)
            .and_then(|routes| routes.onion);
        let Some(binding) = onion else {
            return Ok(skipped("no_tor_route"));
        };
        let req = IpcRequest::OnionWarm {
            v: IPC_VERSION,
            onion_dial: raven_core::onion::dial_for(&binding.hs_id),
            expected_pub_hex: contact.pub_hex.clone(),
            level,
        };
        Ok(answered(bridge::ipc_request_timeout(
            dir,
            &req,
            WARM_ASK_TIMEOUT,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Owner decision 7: a typing warm-up on mobile data only where the
    /// setting allows it; a chat open's probe follows Tor on Wi-Fi only in
    /// raven-node instead. A blocked or unverified friend, and a paused
    /// node, warm nothing whatever the network.
    #[test]
    fn the_engine_refuses_a_friend_not_verified_or_blocked_a_pause_and_typing_on_mobile_data() {
        use WarmLevel::{Circuit, Link};
        let ok = |blocked, verified, paused, level, cellular, allowed| {
            engine_refusal(blocked, verified, paused, level, cellular, allowed)
        };
        assert_eq!(ok(false, true, false, Link, false, false), None, "Wi-Fi");
        assert_eq!(ok(false, true, false, Link, true, true), None, "allowed");
        assert_eq!(
            ok(false, true, false, Link, true, false),
            Some("mobile_data")
        );
        assert_eq!(
            ok(false, true, false, Circuit, true, false),
            None,
            "a probe"
        );
        for level in [Circuit, Link] {
            assert_eq!(ok(true, true, false, level, false, true), Some("blocked"));
            assert_eq!(ok(true, false, false, level, false, true), Some("blocked"));
            assert_eq!(
                ok(false, false, false, level, false, true),
                Some("not_verified")
            );
            assert_eq!(ok(false, true, true, level, false, true), Some("paused"));
        }
    }

    /// raven-node's answers as the op says them: only its own words pass
    /// through; an older node, a locked one and none at all have the
    /// engine's.
    #[test]
    fn the_nodes_answer_is_one_word() {
        let error = |code: &str, message: &str| {
            Ok(IpcResponse::Error {
                v: IPC_VERSION,
                code: code.into(),
                message: message.into(),
            })
        };
        assert_eq!(
            answered(Ok(IpcResponse::Accepted { v: IPC_VERSION })),
            json!({"warming": true})
        );
        for word in WARM_SKIP_WORDS {
            assert_eq!(answered(error(ONION_WARM_SKIPPED, word)), skipped(word));
        }
        let cases = [
            (error(ONION_WARM_SKIPPED, "an onion address"), "other"),
            (error("IPC_FRAME", "unknown op"), "old_node"),
            (error(LOCKED, "locked"), "locked"),
            (error("ONION_UNREACHABLE", "x"), "other"),
            (Err("connection refused".into()), "node_off"),
        ];
        for (reply, want) in cases {
            assert_eq!(answered(reply)["why"], want);
        }
        // The engine's own words, besides raven-node's (API.md).
        let engine = [
            "paused",
            "no_tor_route",
            "node_off",
            "old_node",
            "locked",
            "other",
        ];
        assert!(WARM_SKIP_WORDS
            .iter()
            .chain(engine.iter())
            .all(|w| w.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
    }

    /// Lock v2 holds the profile: `contacts.warm` is refused as every
    /// profile op is, before any contact is read or raven-node asked.
    #[test]
    fn contacts_warm_is_refused_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let inner = Inner::new(Ok(dir.path().to_path_buf()));
        inner.hold_locked_for_test();
        let answer = inner
            .handle(r#"{"v":1,"op":"contacts.warm","args":{"address":"rvn1x","why":"typing"}}"#);
        assert_eq!(answer["ok"], false, "{answer}");
        assert_eq!(answer["error"]["code"], "PROFILE_LOCKED", "{answer}");
    }
}
