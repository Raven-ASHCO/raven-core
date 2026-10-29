//! What the desktop apps needed after round 4 of the three-machine test's E1
//! feedback: "Use the new address" (`contacts.set_address`) changed the
//! friend's saved LAN address and also forgot what the friend had told this
//! computer (its route hints, its peer-to-peer ID), so a friend whose card
//! had no `p2p=` left the p2p peer gate until it told its routes again. Now
//! only the saved address changes.
//!
//! Lab switch for this test binary only: `RAVEN_LAB_ROUTE_HINTS=1` (the peer
//! gate admits a PeerId a friend's route hints named only while route hints
//! are on).

mod common;

use std::path::Path;

use common::net::Peer;
use serde_json::{json, Value};

fn key_hex(dir: &Path, address: &str) -> String {
    ash_engine::engine::contact_views(dir)
        .expect("contacts")
        .into_iter()
        .find(|c| c.address == address)
        .expect("a saved friend")
        .pub_hex
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The verified friends the p2p peer gate admits from `dir`'s files
/// (raven-node's `gate_files`): each one's PeerId, whether its route hints
/// named it and whether a p2p link proved it.
fn gate(dir: &Path) -> Vec<(String, bool, bool)> {
    raven_core::outbox::p2p_gate_peers(dir)
        .expect("the book and the block list read")
        .into_iter()
        .map(|p| (p.peer_id, p.learned, p.proven))
        .collect()
}

fn lan_route(routes: &Value) -> Value {
    routes["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "lan")
        .cloned()
        .unwrap_or_else(|| panic!("no LAN route: {routes}"))
}

/// E1 round 4: "Use the new address" keeps what the friend told this
/// computer (Relays, direct addresses, mail friends, kept until, its
/// Peer-to-peer ID), its verification and its place in the peer gate.
#[test]
fn a_new_lan_address_keeps_what_the_friend_told() {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: a release engine reads no lab switch");
        return;
    }
    common::lab_env();
    std::env::set_var("RAVEN_LAB_ROUTE_HINTS", "1");
    let a = Peer::new("a");
    let b = Peer::new("b");
    a.befriend(&b, None);
    a.set_lan(&b, "192.168.1.146:17420");
    let quiet = a.ok("contacts.routes", json!({"address": b.address()}));
    assert!(
        quiet["routes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["kind"] != "p2p"),
        "no p2p= saved: the gate admits the friend by its route hints alone: {quiet}"
    );
    assert!(quiet.get("learned").is_none(), "{quiet}");
    assert!(gate(&a.path).is_empty());

    // The friend told this computer its routes (raven-node keeps them).
    let key = key_hex(&a.path, &b.address());
    let peer_id = "12D3KooWMvUn92XzaN9xbg4ZT7SwngnBcjdqEApginEoTG4FKANF";
    let now = now_ms();
    std::fs::write(
        a.path.join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
        json!([{
            "pub_hex": key, "generation": now, "received_at_ms": now,
            "expires_at_ms": now + 3_600_000, "via": "lan",
            "peer_id": peer_id, "peer_id_proven": true,
            "lan": {"generation": now, "received_at_ms": now,
                    "expires_at_ms": now + 3_600_000, "lan_port": 17420,
                    "lan_ip": "192.168.0.24"},
        }])
        .to_string(),
    )
    .unwrap();
    let told = a.ok("contacts.routes", json!({"address": b.address()}));
    assert_eq!(told["learned"]["peer_id"], peer_id, "{told}");
    assert_eq!(told["learned"]["peer_id_proven"], true, "{told}");
    let admitted = gate(&a.path);
    assert_eq!(admitted, [(peer_id.to_owned(), true, true)]);

    // "Use the new address".
    a.set_lan(&b, "192.168.0.24:17420");
    let after = a.ok("contacts.routes", json!({"address": b.address()}));
    assert_eq!(lan_route(&after)["value"], "192.168.0.24:17420", "{after}");
    assert_eq!(
        after["learned"], told["learned"],
        "what b told stays: {after}"
    );
    assert_eq!(after["verified"], true, "{after}");
    assert_eq!(gate(&a.path), admitted, "b keeps its place in the gate");
}
