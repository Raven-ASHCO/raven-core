//! Shared by the network tests (tests/net_*.rs): throwaway profiles on
//! their own engines, friends verified by their security words, raven-node
//! processes on 127.0.0.1 with free ports, and the CLI (`raven`) on the
//! same profile folder. Every lab switch a test needs is set by that test's
//! own binary (one process per file): the environment is the process's.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use raven_client::Client;
use serde_json::{json, Value};

use super::{err, ok, short_dir, NodeGuard};

/// The ports a test never binds: the owner's live raven-node and Raven's
/// defaults.
pub const NEVER: [u16; 4] = [7420, 7422, 7423, 7427];

/// A free TCP port on 127.0.0.1 (never one of [`NEVER`]).
pub fn free_port() -> u16 {
    loop {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        if !NEVER.contains(&port) {
            return port;
        }
    }
}

/// One throwaway profile and its engine; its raven-node is stopped when it
/// is dropped.
pub struct Peer {
    pub name: String,
    pub path: PathBuf,
    pub client: Client,
    pub me: Value,
    _guard: NodeGuard,
    _dir: tempfile::TempDir,
}

impl Peer {
    /// A new profile named `name`, receiving off (a node the engine starts
    /// listens on 127.0.0.1, any free port).
    pub fn new(name: &str) -> Peer {
        super::lab_env();
        let dir = short_dir();
        let path = dir.path().join("p");
        let client = Client::with_data_dir(&path);
        ok(&client, "settings.set", json!({"receive": false}));
        ok(&client, "identity.create", json!({"display_name": name}));
        let me = ok(&client, "identity.me", json!({}));
        Peer {
            name: name.to_owned(),
            _guard: NodeGuard {
                client: client.clone(),
                dir: path.clone(),
            },
            path,
            client,
            me,
            _dir: dir,
        }
    }

    pub fn address(&self) -> String {
        self.me["address"].as_str().unwrap().to_owned()
    }

    pub fn ok(&self, op: &str, args: Value) -> Value {
        ok(&self.client, op, args)
    }

    pub fn err(&self, op: &str, args: Value) -> String {
        err(&self.client, op, args)
    }

    /// Adds `other` from its invite (or `text`, a card) and verifies it by
    /// its security words, as a person who compared them would.
    pub fn befriend(&self, other: &Peer, text: Option<&str>) {
        let paste = text.map_or_else(|| other.me["invite"].clone(), Value::from);
        self.ok(
            "contacts.add",
            json!({"text": paste, "name": format!("Friend {}", other.name)}),
        );
        let checked = self.ok(
            "verify.check_words",
            json!({"address": other.address(), "words": other.me["words"]}),
        );
        assert_eq!(checked["result"], "match", "{checked}");
    }

    /// Starts this profile's raven-node through the engine; where it
    /// listens.
    pub fn start(&self) -> String {
        let st = self.ok("node.start", json!({}));
        assert_eq!(st["running"], true, "{}: {st}", self.name);
        st["listening"].as_str().unwrap_or_default().to_owned()
    }

    pub fn stop(&self) {
        let st = self.ok("node.stop", json!({}));
        assert!(
            matches!(st["stop"].as_str(), Some("stopped" | "not_running")),
            "{}: {st}",
            self.name
        );
    }

    /// Saves `friend`'s LAN address `lan`.
    pub fn set_lan(&self, friend: &Peer, lan: &str) {
        self.ok(
            "contacts.set_address",
            json!({"address": friend.address(), "lan": lan}),
        );
    }

    /// Sends `text` to `friend` and waits (up to `limit`) for its state to
    /// be one of `ends`; the message as `messages.history` has it then.
    pub fn send_until(&self, friend: &Peer, text: &str, ends: &[&str], limit: Duration) -> Value {
        let sent = self.ok(
            "messages.send",
            json!({"address": friend.address(), "text": text}),
        );
        let id = sent["message"]["id"].as_str().unwrap().to_owned();
        let deadline = Instant::now() + limit;
        let mut after = 0;
        loop {
            // Polling keeps the engine's watcher running.
            let batch = self.ok("events.poll", json!({"after_seq": after}));
            after = batch["seq"].as_u64().unwrap();
            let history = self.ok(
                "messages.history",
                json!({"address": friend.address(), "limit": 50}),
            );
            if let Some(m) = history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["id"] == id.as_str())
            {
                if ends.contains(&m["state"].as_str().unwrap_or("")) {
                    return m.clone();
                }
                if Instant::now() >= deadline {
                    panic!("{}: {text} stayed {m} ({})", self.name, self.service_log());
                }
            }
            assert!(
                Instant::now() < deadline,
                "{}: {text} never showed",
                self.name
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Waits (up to `limit`) for a message from `friend` with `text`.
    pub fn wait_incoming(&self, friend: &Peer, text: &str, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            let history = self.ok(
                "messages.history",
                json!({"address": friend.address(), "limit": 50}),
            );
            if history["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["direction"] == "in" && m["text"] == text)
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(400));
        }
    }

    /// raven-node's own log for this profile (the CLI keeps it there).
    pub fn service_log(&self) -> String {
        std::fs::read_to_string(self.path.join("raven-node-service.log")).unwrap_or_default()
    }

    /// Waits (up to `limit`) until the service log has `needle`.
    pub fn wait_log(&self, needle: &str, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if self.service_log().contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        false
    }

    /// The CLI on this profile folder (the `raven` next to raven-node).
    pub fn cli(&self, args: &[&str]) -> Output {
        cli(&self.path, args)
    }

    /// One carrier of `network.status`.
    pub fn carrier(&self, id: &str) -> Value {
        carrier_of(&self.ok("network.status", json!({})), id)
    }
}

/// The carrier (or protection) `id` of a `network.status` result.
pub fn carrier_of(status: &Value, id: &str) -> Value {
    status["carriers"]
        .as_array()
        .unwrap()
        .iter()
        .chain(status["protections"].as_array().unwrap().iter())
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no {id} in {status}"))
        .clone()
}

/// The `raven` CLI built next to raven-node.
pub fn raven_cli() -> PathBuf {
    let node = super::raven_node().expect("raven-node is built");
    node.with_file_name(if cfg!(windows) { "raven.exe" } else { "raven" })
}

/// `raven --data-dir <dir> <args>` with this process's environment.
pub fn cli(dir: &Path, args: &[&str]) -> Output {
    Command::new(raven_cli())
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run raven")
}

/// The CLI and raven-node are built (`cargo build` in node/); without them
/// a test says so and passes.
pub fn binaries_ready() -> bool {
    let ready = super::raven_node().is_some() && raven_cli().is_file();
    if !ready {
        eprintln!("skipped: raven-node or raven is not built (run `cargo build` in node/)");
    }
    ready
}
