//! (c) p2p relayed through a local relay, through the engine API, the way
//! the carrier matrix's C6 does it (node/crates/raven-node/tests/
//! carrier_matrix.rs): a dedicated `raven-node relay` on 127.0.0.1, both
//! profiles reserve on it with no listener of their own (`p2p_listen:
//! "relay"`, kept by the matrix's test switch), the relay allows their
//! cards, and a message rides the relay circuit. Lab switches for this test
//! binary only: `RAVEN_LAB_TEST_A=1` (the p2p gate) and
//! `RAVEN_LAB_P2P_RELAY_ONLY=1`.
//!
//! Needs the raven-node and raven that `cargo build` puts next to the test
//! binaries' folder; without them the test says so and passes.

mod common;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::net::{binaries_ready, carrier_of, cli, Peer};
use serde_json::{json, Value};

/// One `raven-node relay`, stopped (by its pid) when dropped.
struct Relay {
    child: Child,
    dir: PathBuf,
    log: Arc<Mutex<String>>,
    via: String,
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Relay {
    fn start(root: &Path) -> Relay {
        let dir = root.join("relay");
        std::fs::create_dir_all(&dir).unwrap();
        let node = common::raven_node().unwrap();
        // The relay holds no Raven identity: none of a profile's settings.
        let mut child = Command::new(node)
            .args(["relay", "--data-dir"])
            .arg(&dir)
            .args(["--listen", "127.0.0.1:0"])
            .env_remove("RAVEN_DATA_DIR")
            .env_remove("ASH_DATA_DIR")
            .env_remove("RAVEN_LAB_P2P_RELAY_ONLY")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn raven-node relay");
        let log = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&log);
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut l = sink.lock().unwrap();
                l.push_str(&line);
                l.push('\n');
            }
        });
        let mut relay = Relay {
            child,
            dir,
            log,
            via: String::new(),
        };
        relay.wait(|_| true, "raven-node relay: up");
        let status = relay.wait_status(|s| tcp_listen(s).is_some());
        relay.via = format!(
            "{}/p2p/{}",
            tcp_listen(&status).unwrap(),
            status["peer_id"].as_str().unwrap()
        );
        relay
    }

    fn wait(&self, _: impl Fn(&str) -> bool, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.log.lock().unwrap().contains(needle) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("relay: no {needle:?}:\n{}", self.log.lock().unwrap());
    }

    /// relay_status.json once `pred` holds (rewritten every 2 s).
    fn wait_status(&self, pred: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let raw =
                std::fs::read_to_string(self.dir.join("relay_status.json")).unwrap_or_default();
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                if pred(&v) {
                    return v;
                }
            }
            assert!(
                Instant::now() < deadline,
                "relay status never matched:\n{raw}\n{}",
                self.log.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// `raven --data-dir <relay folder> relay allow --card <card>`.
    fn allow(&self, card: &str) {
        let out = cli(&self.dir, &["relay", "allow", "--card", card]);
        assert!(
            out.status.success(),
            "relay allow: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The relay's plain TCP listen address.
fn tcp_listen(status: &Value) -> Option<String> {
    status["listen_addrs"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find(|a| a.contains("/tcp/") && !a.ends_with("/ws"))
        .map(str::to_owned)
}

#[test]
fn p2p_through_a_local_relay() {
    if !binaries_ready() {
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch (tests/net_gates.rs)");
        return;
    }
    common::lab_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var("RAVEN_LAB_P2P_RELAY_ONLY", "1");
    let root = common::short_dir();
    let relay = Relay::start(root.path());
    let a = Peer::new("P2p A");
    let b = Peer::new("P2p B");

    // p2p on, through the relay only, as `raven node p2p on --relay`.
    for p in [&a, &b] {
        let p2p = p.carrier("p2p");
        assert_eq!(
            (p2p["state"].as_str(), p2p["lab"].as_bool()),
            (Some("off"), Some(true))
        );
        let set = p.ok(
            "network.set",
            json!({"p2p": true, "p2p_listen": "relay", "relays": [relay.via]}),
        );
        assert_eq!(set["changes"][0]["applies"], "restart", "{set}");
        let policy = raven_core::node_policy::try_load_policy(&p.path).unwrap();
        assert_eq!(policy.p2p_listen, "relay");
        assert_eq!(policy.p2p_relays, vec![relay.via.clone()]);
    }
    // Each card now carries its PeerId and the relay (raven-card/2).
    let card = |p: &Peer| -> String {
        let card = p.ok("identity.me", json!({}))["card"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            card.starts_with("raven-card/2 ") && card.contains(" p2p=") && card.contains(" via=/"),
            "{card}"
        );
        card
    };
    let (a_card, b_card) = (card(&a), card(&b));
    relay.allow(&a_card);
    relay.allow(&b_card);
    relay.wait_status(|s| s["counts"]["allowed_peers"].as_u64() == Some(2));
    a.start();
    b.start();
    relay.wait_status(|s| s["counts"]["reservations"].as_u64() == Some(2));

    // Each adds the other from the card (p2p only: no LAN or Internet
    // route) and verifies the words.
    a.befriend(&b, Some(&b_card));
    b.befriend(&a, Some(&a_card));
    for p in [&a, &b] {
        assert!(
            p.wait_log(
                "raven-node p2p: peer gate reloaded (verified contacts 1,",
                Duration::from_secs(60)
            ),
            "{}: the peer gate never admitted the friend:\n{}",
            p.name,
            p.service_log()
        );
    }
    let routes = a.ok("contacts.routes", json!({"address": b.address()}));
    let p2p_route = &routes["routes"][0];
    assert_eq!(p2p_route["kind"], "p2p", "{routes}");
    assert_eq!(p2p_route["via"][0], relay.via.as_str(), "{routes}");
    assert_eq!(p2p_route["state"], "lab", "{routes}");

    let m = a.send_until(
        &b,
        "over the relay",
        &["delivered", "failed", "not_sent_meet_first"],
        Duration::from_secs(120),
    );
    assert_eq!(m["state"], "delivered", "{m}\n{}", a.service_log());
    assert_eq!(m["path_kind"], "p2p_relayed", "{m}");
    assert_eq!(m["path"], "p2p \u{00B7} relayed", "{m}");
    assert!(b.wait_incoming(&a, "over the relay", Duration::from_secs(20)));

    // A's view: p2p on for testing and up, the relay in use.
    let net = a.ok("network.status", json!({}));
    let p2p = carrier_of(&net, "p2p");
    assert_eq!(p2p["state"], "lab", "{p2p}");
    assert_eq!(p2p["running"], true, "{p2p}");
    let relays = net["relays"].as_array().unwrap();
    assert_eq!(relays.len(), 1, "{net}");
    assert_eq!(relays[0]["source"], "manual", "{net}");
    assert!(
        net["p2p_addresses"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a.as_str().unwrap().contains("/p2p-circuit")),
        "{net}"
    );
    // WebSocket relays stay held: their own switch is not set.
    assert_eq!(carrier_of(&net, "websocket")["state"], "preview");
    // The doctor's reachability lines, as rows.
    let check = a.ok("network.check", json!({}));
    let reach = check["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "reach_class")
        .unwrap_or_else(|| panic!("{check}"));
    assert!(
        reach["value"].as_str().unwrap().starts_with("relayed"),
        "{reach}"
    );
}
