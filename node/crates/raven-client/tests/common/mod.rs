//! Shared by the integration tests: a lab environment that keeps every test
//! off the OS keychain and the real profile, throwaway profiles, and calls.
//!
//! Every process this test binary starts (raven-node) inherits the same
//! environment: the file-backed (`locked-file`) secret stores, loopback-only
//! listening on a free port, no address from `RAVEN_PEER`, and none of the
//! privacy pack's lab switches.
#![allow(dead_code)]

pub mod flow;
pub mod net;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;
use std::time::{Duration, Instant};

use raven_client::Client;
use serde_json::{json, Value};

/// Sets the lab environment once, before any engine runs in this process.
pub fn lab_env() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        for key in [
            "RAVEN_IDENTITY_BACKEND",
            "RAVEN_SESSION_BACKEND",
            "RAVEN_PREKEY_BACKEND",
            "RAVEN_CHAT_HISTORY_BACKEND",
        ] {
            std::env::set_var(key, "locked-file");
        }
        std::env::set_var("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1");
        // Never the default port 7420: loopback, any free port.
        std::env::set_var("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0");
        for key in [
            "RAVEN_PEER",
            "ASH_LAN_DIAL",
            "RAVEN_VERBOSE",
            "ASH_VERBOSE",
            "RAVEN_LAB_TEST_A",
            "RAVEN_LAB_NET_TAG",
            "RAVEN_LAB_ROUTE_HINTS",
            "RAVEN_LAB_SESSION_RESET",
            "RAVEN_INTERNET_LISTEN",
            "RAVEN_P2P_LISTEN",
            "RAVEN_P2P_RELAYS",
            "RAVEN_P2P_RELAY",
            "RAVEN_TRACE_LOG",
        ] {
            std::env::remove_var(key);
        }
        // Plain profiles, whatever privacy switches the suite runs with (as
        // ash's harnesses): a test that wants a sealed profile, an erase
        // root or a key fault sets its switch itself (tests/sealed.rs).
        for switch in raven_core::lan_gate::PRIVACY_LAB_SWITCHES {
            std::env::remove_var(switch);
        }
        // No lab switch from the shell either: a network test sets the
        // ones it needs after this (tests/net_*.rs, one process each).
        let lab: Vec<_> = std::env::vars_os()
            .filter(|(k, _)| k.to_string_lossy().starts_with("RAVEN_LAB_"))
            .map(|(k, _)| k)
            .collect();
        for key in lab {
            std::env::remove_var(key);
        }
        // Never this Mac's own proxy settings for a relay dial.
        std::env::set_var("RAVEN_P2P_PROXY", "off");
        match raven_node() {
            Some(node) => std::env::set_var(raven_client::NODE_PROGRAM_ENV, node),
            None => std::env::remove_var(raven_client::NODE_PROGRAM_ENV),
        }
    });
}

/// The raven-node `cargo build` put in this target directory, if any.
pub fn raven_node() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = if cfg!(windows) {
        "raven-node.exe"
    } else {
        "raven-node"
    };
    // target/<profile>/deps/<test> → target/<profile>/raven-node
    let node = exe.parent()?.parent()?.join(name);
    node.is_file().then_some(node)
}

/// A throwaway profile folder whose IPC socket path fits `sun_path`.
pub fn short_dir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new().prefix("rc").tempdir().unwrap();
    if dir.path().as_os_str().len() <= 60 {
        return dir;
    }
    tempfile::Builder::new()
        .prefix("rc")
        .tempdir_in("/tmp")
        .unwrap()
}

/// The whole response envelope of one call.
pub fn raw(client: &Client, op: &str, args: Value) -> Value {
    let request = json!({"v": 1, "op": op, "args": args}).to_string();
    let response = client.call(&request);
    serde_json::from_str(&response).unwrap_or_else(|e| panic!("{op}: not JSON ({e}): {response}"))
}

/// The result of a call that must succeed.
pub fn ok(client: &Client, op: &str, args: Value) -> Value {
    let r = raw(client, op, args);
    assert_eq!(r["v"], 1, "{op}: {r}");
    assert_eq!(r["ok"], true, "{op} failed: {r}");
    r["result"].clone()
}

/// The error code of a call that must fail.
pub fn err(client: &Client, op: &str, args: Value) -> String {
    let r = raw(client, op, args);
    assert_eq!(r["ok"], false, "{op} should have failed: {r}");
    let e = &r["error"];
    assert!(e["message"].as_str().is_some_and(|m| !m.is_empty()), "{r}");
    assert!(e["detail"].is_string(), "{r}");
    e["code"].as_str().unwrap().to_owned()
}

/// Polls `events.poll` from `*after` until `done` says so or `limit` runs
/// out; returns every event seen (and moves `after`).
pub fn events_until(
    client: &Client,
    after: &mut u64,
    limit: Duration,
    mut done: impl FnMut(&[Value]) -> bool,
) -> Vec<Value> {
    let deadline = Instant::now() + limit;
    let mut seen = Vec::new();
    loop {
        let batch = ok(client, "events.poll", json!({"after_seq": *after}));
        *after = batch["seq"].as_u64().unwrap();
        seen.extend(batch["events"].as_array().unwrap().iter().cloned());
        if done(&seen) || Instant::now() >= deadline {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Stops this profile's raven-node when dropped (and, should a bug leave one
/// behind, the one whose command line names this profile, and only it).
pub struct NodeGuard {
    pub client: Client,
    pub dir: PathBuf,
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.client.call(r#"{"v":1,"op":"node.stop"}"#);
        if cfg!(unix) {
            let _ = Command::new("pkill")
                .args([
                    "-f",
                    &format!("raven-node service --data-dir {}( |$)", self.dir.display()),
                ])
                .status();
        }
    }
}

/// Every string in `v`, joined: to look for text that must never be there.
pub fn all_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(all_text).collect::<Vec<_>>().join(" "),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k} {}", all_text(v)))
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}

pub fn path_text(p: &Path) -> String {
    p.display().to_string()
}
