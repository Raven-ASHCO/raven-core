//! Bluetooth nearby through the engine API, on the fake radio the carrier
//! matrix uses (C50): no Bluetooth is touched. A `raven-node nearby-ether`
//! hub on 127.0.0.1 stands in for the air; both raven-nodes the engines
//! start take their radio from it (`RAVEN_LAB_NEARBY_ETHER`, debug builds
//! only). The friends meet once on the LAN, their LAN addresses then go
//! dead, `network.set {nearby: true}` turns nearby on (`raven nearby
//! enable`), and the next message goes over the ether. Lab switches for this
//! test binary only: `RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_NEARBY=1` and the hub.
//!
//! Real Bluetooth (CoreBluetooth through the RavenNearby helper on macOS,
//! BlueZ, WinRT) is not tested here.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::net::{binaries_ready, carrier_of, free_port, Peer};
use serde_json::json;

/// The fake ether, stopped (by its pid) when dropped.
struct Ether {
    child: Child,
    addr: String,
}

impl Drop for Ether {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Ether {
    fn start() -> Ether {
        let mut child = Command::new(common::raven_node().unwrap())
            .args(["nearby-ether", "--listen", "127.0.0.1:0", "--print-port"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn raven-node nearby-ether");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port: u16 = line
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("no port: {line:?}"));
        Ether {
            child,
            addr: format!("127.0.0.1:{port}"),
        }
    }
}

#[test]
fn nearby_over_the_fake_ether() {
    if !binaries_ready() {
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch (tests/net_gates.rs)");
        return;
    }
    common::lab_env();
    std::env::set_var("RAVEN_LAB_TEST_A", "1");
    std::env::set_var("RAVEN_LAB_NEARBY", "1");
    // Route hints (on in release builds since 2026-10) would teach each node
    // the other's live LAN address again: closed here, so once the saved LAN
    // addresses go dead only the ether is left.
    std::env::set_var("RAVEN_LAB_ROUTE_HINTS", "0");
    let ether = Ether::start();
    std::env::set_var("RAVEN_LAB_NEARBY_ETHER", &ether.addr);
    let a = Peer::new("Near A");
    let b = Peer::new("Near B");
    a.befriend(&b, None);
    b.befriend(&a, None);
    let (la, lb) = (a.start(), b.start());
    a.set_lan(&b, &lb);
    b.set_lan(&a, &la);
    // They meet once on the LAN: a session each way.
    for (x, y) in [(&a, &b), (&b, &a)] {
        let m = x.send_until(y, "meet", &["delivered", "failed"], Duration::from_secs(90));
        assert_eq!(m["path_kind"], "lan", "{m}");
    }
    // Their LAN addresses go dead: only the ether is left.
    for (x, y) in [(&a, &b), (&b, &a)] {
        x.set_lan(y, &format!("127.0.0.1:{}", free_port()));
    }
    // A lab way where release builds hold it (Windows and Linux); on
    // macOS release builds have it since 2026-10.
    let lab = !raven_core::NEARBY_PRODUCTION_ENABLED;
    let off = a.carrier("nearby");
    assert_eq!(off["lab"], lab, "{off}");
    assert_eq!(off["setting"], false, "{off}");
    for p in [&a, &b] {
        let set = p.ok("network.set", json!({"nearby": true}));
        assert_eq!(set["changes"][0]["setting"], "nearby", "{set}");
        assert!(
            raven_core::node_policy::try_load_policy(&p.path)
                .unwrap()
                .nearby
                == Some(true)
        );
    }
    for p in [&a, &b] {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut net = serde_json::Value::Null;
        while Instant::now() < deadline {
            net = p.ok("network.status", json!({}));
            if net["nearby"]["radio"] == "powered_on" {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        assert_eq!(net["nearby"]["radio"], "powered_on", "{}: {net}", p.name);
        assert_eq!(net["nearby"]["state"], "live", "{net}");
        let nearby = carrier_of(&net, "nearby");
        assert_eq!(nearby["state"], if lab { "lab" } else { "on" }, "{nearby}");
        assert_eq!(nearby["running"], true, "{nearby}");
    }
    let m = a.send_until(
        &b,
        "over the air",
        &["delivered", "failed", "not_sent_meet_first"],
        Duration::from_secs(120),
    );
    assert_eq!(m["state"], "delivered", "{m}\n{}", a.service_log());
    assert_eq!(
        m["path_kind"],
        "nearby",
        "{m}\n{}",
        String::from_utf8_lossy(&a.cli(&["status"]).stdout)
    );
    assert_eq!(m["path"], "Bluetooth nearby", "{m}");
    assert!(b.wait_incoming(&a, "over the air", Duration::from_secs(20)));
    // Off again, as `raven nearby disable`.
    a.ok("network.set", json!({"nearby": false}));
    assert_eq!(
        raven_core::node_policy::try_load_policy(&a.path)
            .unwrap()
            .nearby,
        Some(false)
    );
}
