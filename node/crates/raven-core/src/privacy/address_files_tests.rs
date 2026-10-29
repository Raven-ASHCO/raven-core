//! PP.6 tests of the address and activity files: each one migrated, read by
//! its readers and written sealed; the advisory-file rule (a file a writer
//! could not read is never written over, `edit_route_file` included); the
//! policy's relay addresses in their sealed sidecar (round trip, a
//! crash-safe move, an older build's file, the key not loaded yet); the
//! keyed send-lock names beside an older build's; the byte scan. Profiles are
//! temp folders with an identity marker; keys come from the test build's lab
//! K_hist (never a keychain item).

use super::*;
use crate::at_rest::{self, Advisory};
use crate::contact_book::tests::{profile, seal};
use crate::identity::Identity;
use crate::node_policy::{
    peers_readable, policy_path, policy_peers_path, save_policy, try_load_policy, update_settings,
    NodePolicy, POLICY_FILE, POLICY_PEERS_FILE,
};
use crate::outbox::{CarrierChoice, OutboxCarrier, OutboxRoute, PeerSendLock, OUTBOX_ROUTES_FILE};
use crate::paths::DataDirLock;
use crate::relay_allow::{self, RelayStatusFile};
use crate::relay_select::{self, RelayMemory};
use crate::route_hints::{HintLink, ValidHints, RRH1_DEFAULT_TTL_S};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

const NOW: u64 = 20_000 * DAY_MS;
const BOB_IP: &str = "192.168.1.44";
const BOB_LAN: &str = "192.168.1.44:7531";
const BOB_NET: &str = "203.0.113.9:7422";
const EXTERNAL: &str = "/dns4/home.example.net/tcp/7427";
const NET_TAG: &str = "n1";

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn key(seed: u8) -> [u8; 32] {
    id(seed).public_key_bytes()
}

fn peer_id(seed: u8) -> String {
    crate::p2p_route::local_peer_id(&id(seed))
}

fn relay_addr(seed: u8) -> String {
    format!("/ip4/198.51.100.{seed}/tcp/7423/p2p/{}", peer_id(seed))
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn route(carrier: OutboxCarrier, dial: &str) -> OutboxRoute {
    OutboxRoute {
        carrier,
        dial: dial.into(),
    }
}

/// `sender` told this node over a LAN link from `from` that it listens on
/// `lan_port` (stored as raven-node stores it; the gate is the test's).
fn told(dd: &Path, sender: &[u8; 32], from: &str, lan_port: u16) -> crate::learned_routes::Applied {
    let hints = ValidHints {
        generation: crate::clock::now_ms(),
        ttl_s: RRH1_DEFAULT_TTL_S,
        lan_port: Some(lan_port),
        ..Default::default()
    };
    let link = HintLink {
        carrier: OutboxCarrier::Lan,
        peer_ip: Some(ip(from)),
        peer_zone: None,
        link_peer_id: None,
        book_peer_id: None,
        pinned: true,
        sender: *sender,
        local: [0x52; 32],
        local_p2p: [0x53; 32],
        local_relay: None,
        lab_local: false,
        lab_loopback: false,
    };
    crate::learned_routes::apply_ungated(dd, sender, &hints, &link, None, crate::clock::now_ms())
        .unwrap()
}

/// `peer`'s Internet route reached it after its LAN route failed: the route
/// memory remembers the Internet one on [`NET_TAG`].
fn remember(dd: &Path, peer: &[u8; 32]) -> Result<(), String> {
    let now = crate::clock::now_ms();
    let lan = route(OutboxCarrier::Lan, BOB_LAN);
    let inet = route(OutboxCarrier::Internet, BOB_NET);
    crate::route_memory::learn(
        dd,
        peer,
        &[lan.clone(), inet.clone()],
        None,
        &[(lan, false), (inet, true)],
        Some(NET_TAG),
        now,
        now,
    )
}

/// A queued message to `peer` (its routes and the "not sent yet" mark).
fn queued(dd: &Path, peer: &[u8; 32], mid: u8) -> Result<(), String> {
    let now = crate::clock::now_ms();
    crate::outbox::record_object_routes(
        dd,
        &[mid; 16],
        peer,
        CarrierChoice::Auto,
        &[
            route(OutboxCarrier::Lan, BOB_LAN),
            route(OutboxCarrier::Internet, BOB_NET),
        ],
        now + 3_600_000,
        now,
    )?;
    crate::outbox::set_object_unsent(dd, &[mid; 16], true, now)
}

fn memory_with(peer: &str) -> RelayMemory {
    let mut mem = RelayMemory::default();
    relay_select::note_ok(&mut mem, peer, crate::clock::now_ms());
    mem
}

fn status_of(peer: &str) -> RelayStatusFile {
    RelayStatusFile {
        version: 1,
        peer_id: peer.into(),
        listen_addrs: vec!["/ip4/0.0.0.0/tcp/7427".into()],
        advertised: vec!["/ip4/203.0.113.77/tcp/7427".into()],
        updated_at_ms: crate::clock::now_ms(),
        ..Default::default()
    }
}

/// The CLI-only files (their reader and writer live in ash): as an older
/// build or a plain profile holds them.
fn write_cli_files(dd: &Path, bob: &[u8; 32]) {
    let bob_hex = hex::encode(bob);
    std::fs::write(
        dd.join(crate::chat_history::CHAT_INBOX_CURSORS_FILE),
        json!({ bob_hex.clone(): {"received_at_ms": 7, "message_id_hex": "ab".repeat(16)} })
            .to_string(),
    )
    .unwrap();
    std::fs::write(
        dd.join(crate::alias_record::ALIAS_CLAIMS_FILE),
        json!([{
            "alias": "bob", "identity_address": crate::encode_address(bob), "sequence": 1,
            "expires_at": NOW, "signature_hex": "00".repeat(64), "ed25519_pub_hex": bob_hex,
        }])
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        dd.join(crate::nearby::NEARBY_REGISTRY_FILE),
        json!([{"token": "11".repeat(16)}]).to_string(),
    )
    .unwrap();
    let inbox = dd.join(crate::contact_request::CONTACT_INBOX_DIR);
    std::fs::create_dir_all(&inbox).unwrap();
    let mut wire = crate::contact_request::CONTACT_REQ_WIRE.to_vec();
    wire.extend_from_slice(bob);
    std::fs::write(inbox.join(format!("{}.wire", "cd".repeat(16))), wire).unwrap();
    let relay_dir = relay_allow::friend_relay_dir(dd);
    std::fs::create_dir_all(&relay_dir).unwrap();
    std::fs::write(relay_dir.join(relay_allow::RELAY_KEY_FILE), [0x5a; 32]).unwrap();
}

/// Every PP.6 file of a profile, written by its own writer where raven-core
/// has one (today's bytes in a plain profile): Bob's sighting, his route
/// hint, a route memory grant, a queued message's routes, the relay memory,
/// the friend relay's status, the policy's relays and this computer's public
/// name; the CLI's files as they are on disk.
fn write_address_files(dd: &Path) {
    let bob = key(0x61);
    crate::contact_book::write_rows(
        dd,
        json!([{
            "petname": "Bob", "address": crate::encode_address(&bob),
            "pub_hex": hex::encode(bob), "pinned": true, "lan_dial": BOB_LAN,
        }])
        .as_array()
        .unwrap(),
    )
    .unwrap();
    crate::lan_seen::record_contact_seen(dd, &bob, ip(BOB_IP), None, crate::clock::now_ms())
        .unwrap();
    told(dd, &bob, BOB_IP, 7531);
    remember(dd, &bob).unwrap();
    queued(dd, &bob, 0x71).unwrap();
    relay_select::save_memory(dd, &memory_with(&peer_id(0x62))).unwrap();
    write_cli_files(dd, &bob);
    relay_allow::write_relay_status(
        &relay_allow::friend_relay_dir(dd),
        &status_of(&peer_id(0x63)),
    )
    .unwrap();
    save_policy(
        dd,
        &NodePolicy {
            p2p_listen: "7423".into(),
            p2p_relays: vec![relay_addr(0x64)],
            relay_external: vec![EXTERNAL.into()],
            ..NodePolicy::default()
        },
    )
    .unwrap();
}

/// What every reader of the PP.6 files answers, as text.
fn address_readers(dd: &Path) -> Vec<String> {
    let now = crate::clock::now_ms();
    let bob = key(0x61);
    let file = |name: &str, kind: Kind| {
        format!(
            "{name} {:?}",
            at_rest::load_json::<Value>(dd, &dd.join(name), kind)
        )
    };
    let records = crate::outbox::object_route_records(dd, now).map(|r| {
        r.values()
            .map(|r| (r.routes.clone(), r.unsent))
            .collect::<Vec<_>>()
    });
    vec![
        format!(
            "seen {:?} {:?}",
            crate::lan_seen::seen_ip(dd, &bob, now),
            crate::lan_seen::learned_lan_dial(dd, &bob, "192.168.1.20:7531", true, now)
        ),
        format!(
            "learned {:?}",
            crate::learned_routes::learned(dd, &bob, now).map(|v| v.lan)
        ),
        format!(
            "memory {:?}",
            crate::route_memory::preferred_route(dd, &bob, Some(NET_TAG), now)
        ),
        format!("routes {records:?}"),
        format!(
            "evidence {:?}",
            crate::outbox::object_route_evidence(dd, now).map(|e| e.len())
        ),
        format!(
            "relay memory {:?}",
            relay_select::load_memory(dd)
                .relays
                .keys()
                .collect::<Vec<_>>()
        ),
        format!(
            "relay status {:?}",
            relay_allow::load_relay_status(&relay_allow::friend_relay_dir(dd))
                .map(|s| s.map(|s| (s.peer_id, s.advertised)))
        ),
        format!(
            "relay key {:?}",
            at_rest::load_bytes(
                dd,
                &relay_allow::friend_relay_dir(dd).join(relay_allow::RELAY_KEY_FILE),
                Kind::FriendRelayKey
            )
            .map(|k| k.map(|k| k.to_vec()))
        ),
        format!(
            "policy {:?}",
            try_load_policy(dd).map(|p| (p.p2p_listen, p.p2p_relays, p.relay_external))
        ),
        file(
            crate::chat_history::CHAT_INBOX_CURSORS_FILE,
            Kind::ChatInboxCursors,
        ),
        file(crate::alias_record::ALIAS_CLAIMS_FILE, Kind::AliasClaims),
        file(crate::nearby::NEARBY_REGISTRY_FILE, Kind::NearbyRegistry),
        format!(
            "inbox {:?}",
            contact_inbox_files(dd)
                .iter()
                .map(|path| at_rest::load_bytes(dd, path, Kind::ContactInbox)
                    .map(|b| b.map(|b| b.to_vec())))
                .collect::<Vec<_>>()
        ),
    ]
}

/// The PP.6 files a sealed profile holds sealed, with their kinds.
fn sealed_files(dd: &Path) -> Vec<(PathBuf, Kind)> {
    let relay_dir = relay_allow::friend_relay_dir(dd);
    let mut files = vec![
        (dd.join(crate::lan_seen::LAN_SEEN_FILE), Kind::LanSeen),
        (
            dd.join(crate::learned_routes::LEARNED_ROUTES_FILE),
            Kind::LearnedRoutes,
        ),
        (dd.join(OUTBOX_ROUTES_FILE), Kind::OutboxRoutes),
        (
            dd.join(crate::route_memory::ROUTE_MEMORY_FILE),
            Kind::RouteMemory,
        ),
        (
            dd.join(crate::chat_history::CHAT_INBOX_CURSORS_FILE),
            Kind::ChatInboxCursors,
        ),
        (
            dd.join(crate::alias_record::ALIAS_CLAIMS_FILE),
            Kind::AliasClaims,
        ),
        (
            dd.join(crate::nearby::NEARBY_REGISTRY_FILE),
            Kind::NearbyRegistry,
        ),
        (dd.join(relay_select::RELAY_MEMORY_FILE), Kind::RelayMemory),
        (
            relay_dir.join(relay_allow::RELAY_STATUS_FILE),
            Kind::FriendRelayStatus,
        ),
        (
            relay_dir.join(relay_allow::RELAY_KEY_FILE),
            Kind::FriendRelayKey,
        ),
        (policy_peers_path(dd), Kind::NodePolicyPeers),
    ];
    files.extend(
        contact_inbox_files(dd)
            .into_iter()
            .map(|path| (path, Kind::ContactInbox)),
    );
    files
}

/// RMS1 of `kind` (the kind byte of its header).
fn sealed_as(path: &Path, kind: Kind) -> bool {
    std::fs::read(path).is_ok_and(|raw| at_rest::is_sealed(&raw) && raw[5] == kind.code())
}

fn assert_all_sealed(dd: &Path, when: &str) {
    let files = sealed_files(dd);
    assert_eq!(files.len(), 12, "{when}: the fixture's files");
    for (path, kind) in files {
        assert!(
            sealed_as(&path, kind),
            "{when}: {} is not RMS1",
            path.display()
        );
    }
    // node_policy.json keeps the rest of the settings, in plain, and names
    // no other machine.
    let policy = std::fs::read_to_string(policy_path(dd)).unwrap();
    assert!(
        policy.contains(r#""p2p_listen": "7423""#),
        "{when}: {policy}"
    );
    for name in [
        "p2p_relays",
        "relay_external",
        "198.51.100",
        "home.example.net",
    ] {
        assert!(!policy.contains(name), "{when}: {name} in {policy}");
    }
}

/// Per kind: migrated, read by every reader (the same answers sealed as
/// plain), and written sealed by every writer.
#[test]
fn address_files_migrate_read_and_write_sealed() {
    let dir = profile();
    let dd = dir.path();
    write_address_files(dd);
    for (path, kind) in sealed_files(dd) {
        if kind == Kind::NodePolicyPeers {
            assert!(!path.exists(), "a plain profile has no sidecar");
            continue;
        }
        assert!(path.exists(), "the fixture has no {}", path.display());
        assert!(
            !sealed_as(&path, kind),
            "{} sealed in plain",
            path.display()
        );
    }
    let plain_policy = std::fs::read_to_string(policy_path(dd)).unwrap();
    assert!(plain_policy.contains("p2p_relays") && plain_policy.contains("relay_external"));
    let before = address_readers(dd);
    assert!(
        before.iter().all(|line| !line.contains("Err")),
        "{before:#?}"
    );
    assert!(before[0].starts_with("seen Some(") && before[1].starts_with("learned Some(Some("));
    assert!(before[2].starts_with("memory Some("), "{before:#?}");

    seal(dd);
    assert_all_sealed(dd, "after the migration");
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(report.sealed, 0, "idempotent");
    assert_eq!(address_readers(dd), before, "every reader, sealed");
    assert!(recorded_kinds(dd).contains(&Kind::NodePolicyPeers.name().to_owned()));
    assert!(recorded_kinds(dd).contains(&Kind::ContactInbox.name().to_owned()));

    // Every writer writes sealed.
    let carol = key(0x65);
    assert!(crate::lan_seen::record_contact_seen(
        dd,
        &carol,
        ip("192.168.1.45"),
        None,
        crate::clock::now_ms()
    )
    .unwrap());
    assert!(matches!(
        told(dd, &carol, "192.168.1.45", 7532),
        crate::learned_routes::Applied::Changed { .. }
    ));
    remember(dd, &carol).unwrap();
    queued(dd, &carol, 0x72).unwrap();
    relay_select::save_memory(dd, &memory_with(&peer_id(0x66))).unwrap();
    relay_allow::write_relay_status(
        &relay_allow::friend_relay_dir(dd),
        &status_of(&peer_id(0x67)),
    )
    .unwrap();
    let mut policy = try_load_policy(dd).unwrap();
    policy.p2p_relays.push(relay_addr(0x68));
    policy.upnp = Some(true);
    save_policy(dd, &policy).unwrap();
    assert_all_sealed(dd, "after the writers");
    let now = crate::clock::now_ms();
    assert_eq!(
        crate::lan_seen::seen_ip(dd, &carol, now),
        Some(ip("192.168.1.45"))
    );
    assert!(crate::learned_routes::learned(dd, &carol, now).is_some());
    assert!(crate::route_memory::preferred_route(dd, &carol, Some(NET_TAG), now).is_some());
    assert_eq!(
        crate::outbox::object_route_records(dd, now).unwrap().len(),
        2
    );
    assert!(relay_select::load_memory(dd)
        .relays
        .contains_key(&peer_id(0x66)));
    assert_eq!(
        relay_allow::load_relay_status(&relay_allow::friend_relay_dir(dd))
            .unwrap()
            .unwrap()
            .peer_id,
        peer_id(0x67)
    );
    assert_eq!(try_load_policy(dd).unwrap(), policy);
    // The forgetting writers too (a contact removed).
    crate::lan_seen::forget(dd, &carol).unwrap();
    crate::learned_routes::forget(dd, &carol).unwrap();
    crate::route_memory::forget(dd, &carol).unwrap();
    crate::outbox::clear_peer_routes(dd, &carol).unwrap();
    assert_eq!(crate::lan_seen::seen_ip(dd, &carol, now), None);
    assert!(crate::learned_routes::learned(dd, &carol, now).is_none());
    assert_eq!(
        crate::route_memory::preferred_route(dd, &carol, Some(NET_TAG), now),
        None
    );
    assert_all_sealed(dd, "after forgetting");
}

fn recorded_kinds(dd: &Path) -> Vec<String> {
    read_file(dd).unwrap().unwrap_or_default().kinds
}

/// The PP.6 advisory files, by name.
const ADVISORY: [&str; 5] = [
    "lan_seen.json",
    "learned_routes.json",
    "route_memory.json",
    "outbox_routes.json",
    "relay_memory.json",
];

fn snapshot(dd: &Path) -> Vec<Vec<u8>> {
    ADVISORY
        .iter()
        .map(|name| std::fs::read(dd.join(name)).unwrap())
        .collect()
}

/// Every advisory writer, with a new contact or message (each would write).
fn write_everything(dd: &Path, who: &[u8; 32], mid: u8) -> Vec<String> {
    let now = crate::clock::now_ms();
    vec![
        format!(
            "seen {:?}",
            crate::lan_seen::record_contact_seen(dd, who, ip("192.168.1.46"), None, now)
        ),
        format!(
            "forget seen {:?}",
            crate::lan_seen::forget(dd, &key(0x61)).is_err()
        ),
        format!("told {:?}", told(dd, who, "192.168.1.46", 7533)),
        format!(
            "forget learned {:?}",
            crate::learned_routes::forget(dd, &key(0x61)).is_err()
        ),
        format!("memory {:?}", remember(dd, who).is_err()),
        format!(
            "forget memory {:?}",
            crate::route_memory::forget(dd, &key(0x61)).is_err()
        ),
        format!("queued {:?}", queued(dd, who, mid).is_err()),
        format!(
            "cleared {:?}",
            crate::outbox::clear_object_routes(dd, &[[0x71; 16]]).is_err()
        ),
        format!(
            "peer routes {:?}",
            crate::outbox::clear_peer_routes(dd, &key(0x61)).is_err()
        ),
        format!(
            "relay memory {:?}",
            relay_select::save_memory(dd, &memory_with(&peer_id(0x69))).is_err()
        ),
    ]
}

/// The advisory-file rule: a reader that treats an unreadable file as empty
/// never writes after it could not read the file: while the key is not
/// loaded (not counted: only late) and when a byte changed (counted), for
/// every PP.6 advisory writer, `edit_route_file` included.
#[test]
fn an_unreadable_advisory_file_is_never_written_over() {
    let dir = profile();
    let dd = dir.path();
    write_address_files(dd);
    seal(dd);
    let sealed = snapshot(dd);
    assert!(sealed.iter().all(|raw| at_rest::is_sealed(raw)));
    let counted = at_rest::skipped_writes(dd);

    // The key not loaded (raven-node before its key thread finished).
    at_rest::forget_cached_keys(dd);
    let answers = write_everything(dd, &key(0x6a), 0x73);
    assert_eq!(
        answers,
        [
            "seen Ok(false)",
            "forget seen true",
            "told Ignored",
            "forget learned true",
            "memory true",
            "forget memory true",
            "queued true",
            "cleared true",
            "peer routes true",
            "relay memory true",
        ]
    );
    assert_eq!(snapshot(dd), sealed, "nothing written over");
    assert_eq!(
        at_rest::skipped_writes(dd),
        counted,
        "only late: not counted"
    );
    // Readers read nothing meanwhile (and do not fail).
    let now = crate::clock::now_ms();
    assert_eq!(crate::lan_seen::seen_ip(dd, &key(0x61), now), None);
    assert!(crate::outbox::object_route_records(dd, now).is_err());

    // A changed byte, the key loaded: skipped, and counted.
    at_rest::keys_load_with(dd, MigratePolicy::Allow).unwrap();
    for name in ADVISORY {
        let path = dd.join(name);
        let mut raw = std::fs::read(&path).unwrap();
        *raw.last_mut().unwrap() ^= 0x01;
        std::fs::write(&path, raw).unwrap();
    }
    let tampered = snapshot(dd);
    assert_eq!(write_everything(dd, &key(0x6a), 0x73), answers);
    assert_eq!(snapshot(dd), tampered, "nothing written over");
    assert!(at_rest::skipped_writes(dd) > counted, "counted");
    assert!(status(dd)
        .to_ipc("sealed")
        .notes
        .contains(&NOTE_UNREADABLE_FILE_KEPT.to_owned()));
    // Plain bytes that do not parse are replaced, as always.
    for name in ADVISORY {
        std::fs::write(dd.join(name), b"{not json").unwrap();
    }
    let answers = write_everything(dd, &key(0x6a), 0x74);
    assert_eq!(answers[0], "seen Ok(true)");
    for name in ADVISORY {
        let raw = std::fs::read(dd.join(name)).unwrap();
        assert!(at_rest::is_sealed(&raw), "{name} was not replaced");
    }
    assert!(matches!(
        at_rest::load_json_advisory::<Value>(
            dd,
            &dd.join(crate::lan_seen::LAN_SEEN_FILE),
            Kind::LanSeen
        ),
        Advisory::Loaded(_)
    ));
}

/// The policy's relay addresses live only in the sealed sidecar: a save
/// writes them there (and none to node_policy.json), a load merges them, a
/// policy without relays removes the sidecar; an older build's reader still
/// parses node_policy.json, and an older build's file without relays leaves
/// the sidecar alone.
#[test]
fn policy_relays_round_trip_through_the_sealed_sidecar() {
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    let policy = NodePolicy {
        p2p_listen: "7423".into(),
        p2p_relays: vec![relay_addr(0x64), relay_addr(0x65)],
        relay_external: vec![EXTERNAL.into()],
        relay_offer: Some(true),
        ..NodePolicy::default()
    };
    save_policy(dd, &policy).unwrap();
    assert!(sealed_as(&policy_peers_path(dd), Kind::NodePolicyPeers));
    let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
    assert!(
        !raw.contains("p2p_relays") && !raw.contains("relay_external"),
        "{raw}"
    );
    assert_eq!(try_load_policy(dd).unwrap(), policy);
    assert!(peers_readable(dd));
    // An older build's reader (the fields it knows) still parses the file.
    #[derive(Deserialize)]
    struct OlderReader {
        bridge: bool,
        p2p_listen: String,
        #[serde(default)]
        p2p_relays: Vec<String>,
    }
    let older: OlderReader = serde_json::from_str(&raw).unwrap();
    assert!(older.bridge && older.p2p_listen == "7423" && older.p2p_relays.is_empty());
    // An older build saves the policy for another reason: it writes no
    // relays, and the sidecar is untouched.
    let sidecar = std::fs::read(policy_peers_path(dd)).unwrap();
    std::fs::write(
        policy_path(dd),
        r#"{"bridge":false,"store":true,"relay":false,"endpoint":true,"auto_policy":false,"p2p_listen":"7423"}"#,
    )
    .unwrap();
    let loaded = try_load_policy(dd).unwrap();
    assert!(!loaded.bridge);
    assert_eq!(
        (loaded.p2p_relays, loaded.relay_external),
        (policy.p2p_relays.clone(), policy.relay_external.clone())
    );
    assert_eq!(
        migrate_all(dd, NOW, MigratePolicy::Allow).unwrap().sealed,
        0
    );
    assert_eq!(std::fs::read(policy_peers_path(dd)).unwrap(), sidecar);
    // Cleared: no sidecar left.
    let cleared = NodePolicy {
        p2p_relays: Vec::new(),
        relay_external: Vec::new(),
        ..try_load_policy(dd).unwrap()
    };
    save_policy(dd, &cleared).unwrap();
    assert!(!policy_peers_path(dd).exists());
    assert_eq!(try_load_policy(dd).unwrap(), cleared);
    // A plain profile keeps today's bytes and no sidecar.
    let plain = profile();
    save_policy(plain.path(), &policy).unwrap();
    assert!(!policy_peers_path(plain.path()).exists());
    assert_eq!(
        std::fs::read_to_string(policy_path(plain.path())).unwrap(),
        serde_json::to_string_pretty(&policy).unwrap()
    );
}

/// The migration moves node_policy.json's relays to the sidecar, the
/// sidecar first: a crash between the two leaves both (readers see the
/// relays once; the kind is not recorded) and the next pass finishes
/// without an older-build note. An older build that saves relays later (it
/// cannot see the sidecar) wins, and its plain copy is moved and noted.
#[test]
fn policy_relays_move_to_the_sidecar_crash_safe() {
    let dir = profile();
    let dd = dir.path();
    let policy = NodePolicy {
        p2p_listen: "7423".into(),
        p2p_relays: vec![relay_addr(0x64)],
        relay_external: vec![EXTERNAL.into()],
        ..NodePolicy::default()
    };
    save_policy(dd, &policy).unwrap();
    crate::at_rest::tests::expect_key_file(dd);
    super::tests::arm(super::tests::Crash::PolicySidecarWritten);
    let first = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(first.outcome, MigrateOutcome::Sealed);
    assert!(sealed_as(&policy_peers_path(dd), Kind::NodePolicyPeers));
    assert!(std::fs::read_to_string(policy_path(dd))
        .unwrap()
        .contains("p2p_relays"));
    assert!(!recorded_kinds(dd).contains(&Kind::NodePolicyPeers.name().to_owned()));
    assert_eq!(try_load_policy(dd).unwrap(), policy);
    assert!(
        status(dd).plain_files > 0,
        "node_policy.json still names relays"
    );
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    assert_eq!(
        (report.sealed, report.leftovers),
        (1, 0),
        "this build's own crash is no downgrade"
    );
    assert!(!recorded(dd).notices.older_build_wrote_plain);
    assert!(recorded_kinds(dd).contains(&Kind::NodePolicyPeers.name().to_owned()));
    assert!(!std::fs::read_to_string(policy_path(dd))
        .unwrap()
        .contains("p2p_relays"));
    assert_eq!(try_load_policy(dd).unwrap(), policy);
    assert_eq!(status(dd).plain_files, 0);

    // An older build saves new relays into node_policy.json: they are the
    // newer, so they win now and replace the sidecar's at the next pass
    // (this computer's public name, which it did not write, stays).
    let mut older: Value =
        serde_json::from_str(&std::fs::read_to_string(policy_path(dd)).unwrap()).unwrap();
    older["p2p_relays"] = json!([relay_addr(0x6b)]);
    std::fs::write(policy_path(dd), older.to_string()).unwrap();
    let merged = try_load_policy(dd).unwrap();
    assert_eq!(merged.p2p_relays, [relay_addr(0x6b)]);
    assert_eq!(merged.relay_external, [EXTERNAL]);
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!((report.sealed, report.leftovers), (1, 1));
    assert!(recorded(dd).notices.older_build_wrote_plain);
    assert!(!std::fs::read_to_string(policy_path(dd))
        .unwrap()
        .contains("p2p_relays"));
    assert_eq!(try_load_policy(dd).unwrap(), merged);
}

fn recorded(dd: &Path) -> PrivacyFile {
    read_file(dd).unwrap().unwrap_or_default()
}

/// raven-node before its key thread loaded the key: the sidecar does not
/// open, so relays are refused (retryably) and nothing is written over, while
/// a save without relays and IPC SetPolicy's settings still work.
#[test]
fn relay_addresses_wait_for_the_key_and_the_other_settings_do_not() {
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    let policy = NodePolicy {
        p2p_listen: "7423".into(),
        p2p_relays: vec![relay_addr(0x64)],
        ..NodePolicy::default()
    };
    save_policy(dd, &policy).unwrap();
    let sidecar = std::fs::read(policy_peers_path(dd)).unwrap();
    at_rest::forget_cached_keys(dd);
    assert!(!peers_readable(dd));
    let early = try_load_policy(dd).unwrap();
    assert!(early.p2p_relays.is_empty(), "the sidecar adds nothing yet");
    assert_eq!(early.p2p_listen, "7423");
    let err = save_policy(dd, &policy).unwrap_err().to_string();
    assert!(
        err.contains(POLICY_PEERS_FILE) && err.contains("try again"),
        "{err}"
    );
    // A save that names no relay (the user's other settings) goes through
    // and keeps the sidecar; so does SetPolicy's.
    save_policy(
        dd,
        &NodePolicy {
            upnp: Some(true),
            ..early
        },
    )
    .unwrap();
    update_settings(dd, |p| {
        p.bridge = false;
        p.auto_policy = false;
    })
    .unwrap();
    assert_eq!(std::fs::read(policy_peers_path(dd)).unwrap(), sidecar);
    // The key arrives: everything is there.
    at_rest::keys_load_with(dd, MigratePolicy::Allow).unwrap();
    let loaded = try_load_policy(dd).unwrap();
    assert_eq!(
        (loaded.p2p_relays, loaded.upnp, loaded.bridge),
        (policy.p2p_relays, Some(true), false)
    );
    let raw = std::fs::read_to_string(policy_path(dd)).unwrap();
    assert!(!raw.contains("p2p_relays"), "{raw}");
    assert_eq!(
        std::fs::read_to_string(dd.join(POLICY_FILE)).unwrap(),
        raw,
        "one policy file"
    );
}

/// The per-friend send lock in a sealed profile: a keyed name (never the
/// key in hex); an older build's lock file is taken too while it exists, so
/// a thread holding it (an older ash) excludes a new sender and the other
/// way round; it is deleted once both are let go and never made again;
/// removing the contact's lock files leaves none.
#[test]
fn keyed_send_locks_and_an_older_builds_lock() {
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    let bob = key(0x61);
    let legacy = PeerSendLock::legacy_file_name(&bob);
    let keyed = PeerSendLock::file_name(dd, &bob).unwrap();
    assert_ne!(keyed, legacy);
    assert!(!keyed.contains(&hex::encode(bob)), "{keyed}");
    assert_eq!(
        keyed,
        at_rest::lock_name(&at_rest::keys_cached(dd).unwrap(), &bob)
    );
    let names = |dd: &Path| -> Vec<String> {
        std::fs::read_dir(dd)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".send_"))
            .collect()
    };
    drop(PeerSendLock::acquire_within(dd, &bob, Duration::ZERO).unwrap());
    assert_eq!(
        names(dd),
        std::slice::from_ref(&keyed),
        "only the keyed name is made"
    );

    // An older ash (another thread) holds its lock: a new sender waits.
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let older = {
        let dd = dd.to_path_buf();
        let legacy = legacy.clone();
        std::thread::spawn(move || {
            let lock = DataDirLock::acquire_within(&dd, &legacy, Duration::ZERO).unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(lock);
        })
    };
    held_rx.recv().unwrap();
    let err = PeerSendLock::acquire_within(dd, &bob, Duration::from_millis(50))
        .err()
        .expect("the older build's holder excludes a new sender");
    assert!(crate::outbox::send_lock_busy(&err), "{err}");
    release_tx.send(()).unwrap();
    older.join().unwrap();

    // The other way round: while a new sender holds both, the older one
    // waits.
    let held = PeerSendLock::acquire_within(dd, &bob, Duration::ZERO).unwrap();
    let blocked = {
        let dd = dd.to_path_buf();
        let legacy = legacy.clone();
        std::thread::spawn(move || {
            DataDirLock::acquire_within(&dd, &legacy, Duration::from_millis(50)).err()
        })
    };
    let err = blocked
        .join()
        .unwrap()
        .expect("the new sender excludes an older one");
    assert!(crate::outbox::send_lock_busy(&err), "{err}");
    drop(held);
    assert_eq!(
        names(dd),
        std::slice::from_ref(&keyed),
        "the older name goes when both are free"
    );
    drop(PeerSendLock::acquire_within(dd, &bob, Duration::ZERO).unwrap());
    assert_eq!(
        names(dd),
        std::slice::from_ref(&keyed),
        "and is never made again"
    );

    // Removing the contact's lock files (keyed, and an older build's).
    drop(DataDirLock::acquire_within(dd, &legacy, Duration::ZERO).unwrap());
    PeerSendLock::remove_files(dd, &bob).unwrap();
    assert!(names(dd).is_empty(), "{:?}", names(dd));
    // A rotation never renames it: the stable index key.
    assert_eq!(PeerSendLock::file_name(dd, &bob).unwrap(), keyed);
    // A plain profile keeps the hex name, as every older build.
    let plain = profile();
    assert_eq!(PeerSendLock::file_name(plain.path(), &bob).unwrap(), legacy);
}

/// Review B-sealed-stores-4: an older build's per-friend send locks (each
/// named by the friend's key) in a profile that is then sealed. The sealing
/// pass deletes every one it can take (and a stray journal beside none) and
/// leaves the one a send still holds, which status counts as plain (by the
/// registry's pattern, never by its name); the next prune pass deletes it.
/// No file name names a friend then, though nothing was sent since (only a
/// send to that friend deleted one before).
#[test]
fn an_older_builds_send_locks_go_when_the_profile_is_sealed() {
    let dir = profile();
    let dd = dir.path();
    let (bob, carol, dave) = (key(0x71), key(0x72), key(0x73));
    // A plain profile: each send left its lock file, named by the key.
    for peer in [&bob, &carol] {
        drop(PeerSendLock::acquire_within(dd, peer, Duration::ZERO).unwrap());
    }
    let journal = format!("{}-journal", PeerSendLock::legacy_file_name(&dave));
    std::fs::write(dd.join(&journal), b"").unwrap();
    let names = |dd: &Path| -> Vec<String> {
        std::fs::read_dir(dd)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    };
    let naming = |dd: &Path, peer: &[u8; 32]| {
        names(dd)
            .into_iter()
            .filter(|n| n.contains(&hex::encode(peer)))
            .collect::<Vec<_>>()
    };
    assert_eq!(naming(dd, &bob).len(), 1, "the control");
    // A send to Carol is under way (an older ash holds her lock).
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let older = {
        let dd = dd.to_path_buf();
        let legacy = PeerSendLock::legacy_file_name(&carol);
        std::thread::spawn(move || {
            let lock = DataDirLock::acquire_within(&dd, &legacy, Duration::ZERO).unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(lock);
        })
    };
    held_rx.recv().unwrap();
    seal(dd);
    assert!(naming(dd, &bob).is_empty(), "{:?}", names(dd));
    assert!(naming(dd, &dave).is_empty(), "{:?}", names(dd));
    // The held lock stays, with the journal its holder keeps beside it.
    let held = naming(dd, &carol);
    assert!(
        held.contains(&PeerSendLock::legacy_file_name(&carol)),
        "{held:?}"
    );
    assert_eq!(status(dd).plain_files as usize, held.len());
    let report = report(dd, NOW);
    let mut patterns: Vec<String> = held
        .iter()
        .map(|name| {
            if name.ends_with("-journal") {
                ".send_*.lock.sqlite-journal".to_owned()
            } else {
                ".send_*.lock.sqlite".to_owned()
            }
        })
        .collect();
    patterns.sort();
    assert_eq!(report.plain_files, patterns);
    assert!(!report.to_json().to_string().contains(&hex::encode(carol)));
    // Another sealing pass while it is held: still left.
    seal(dd);
    assert_eq!(naming(dd, &carol).len(), held.len());
    release_tx.send(()).unwrap();
    older.join().unwrap();
    let _ = upkeep_stores(dd);
    for peer in [&bob, &carol, &dave] {
        assert!(naming(dd, peer).is_empty(), "{:?}", names(dd));
    }
    assert_eq!(status(dd).plain_files, 0);
    // A send to Carol now: the keyed name only.
    drop(PeerSendLock::acquire_within(dd, &carol, Duration::ZERO).unwrap());
    assert!(naming(dd, &carol).is_empty(), "{:?}", names(dd));
}

/// Review E-harness-docs-ci-1: whatever way a profile ends up sealed, no
/// file name is left that holds a friend's key, a friend removed from the
/// book before the upgrade included (no send to her and no `raven contact
/// remove` of her will ever come again). (1) The first sealing of a plain
/// profile whose book holds Bob, with an older lock for Bob and one for the
/// removed friend. (2) A profile sealed already that holds such a lock (an
/// older build's send after the sealing, say): the next pass (raven-node's
/// start, the top of every ash command) deletes it and status counts it as
/// plain until then. (3) `raven privacy unseal`, a send in the unsealed
/// profile (the key-hex name again, as in every plain profile), then `raven
/// privacy seal-now`.
#[test]
fn older_send_locks_go_whichever_way_the_profile_is_sealed() {
    let dir = profile();
    let dd = dir.path();
    crate::contact_book::tests::fixture(dd);
    let bob = [1u8; 32];
    let removed = key(0x74);
    let book = std::fs::read_to_string(dd.join(crate::contact_book::CONTACTS_FILE)).unwrap();
    assert!(book.contains(&hex::encode(bob)) && !book.contains(&hex::encode(removed)));
    let naming = |dd: &Path| -> Vec<String> {
        std::fs::read_dir(dd)
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
            })
            .filter(|n| n.contains(&hex::encode(bob)) || n.contains(&hex::encode(removed)))
            .collect()
    };
    // (1) The plain profile's locks (each send left its own), then the
    // first sealing.
    for peer in [&bob, &removed] {
        drop(PeerSendLock::acquire_within(dd, peer, Duration::ZERO).unwrap());
    }
    assert_eq!(naming(dd).len(), 2, "the control");
    seal(dd);
    assert!(naming(dd).is_empty(), "first sealing: {:?}", naming(dd));
    assert_eq!(status(dd).plain_files, 0);

    // (2) A sealed profile that holds one: counted as plain, and the next
    // pass deletes it.
    drop(
        DataDirLock::acquire_within(
            dd,
            &PeerSendLock::legacy_file_name(&removed),
            Duration::ZERO,
        )
        .unwrap(),
    );
    assert_eq!(naming(dd).len(), 1);
    assert_eq!(status(dd).plain_files, 1);
    let report = migrate_all(dd, NOW, MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    assert!(naming(dd).is_empty(), "sealed pass: {:?}", naming(dd));
    assert_eq!(status(dd).plain_files, 0);

    // (3) Unsealed by the user, a send there, then sealed again.
    unseal_all(dd, &|| true).unwrap();
    assert_eq!(mode(dd), Mode::UnsealedByUser);
    drop(PeerSendLock::acquire_within(dd, &bob, Duration::ZERO).unwrap());
    assert_eq!(
        naming(dd),
        [PeerSendLock::legacy_file_name(&bob)],
        "an unsealed profile names its lock by the key"
    );
    let report = seal_now(dd, NOW, MigratePolicy::Allow, None).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
    assert!(naming(dd).is_empty(), "seal-now: {:?}", naming(dd));
    assert_eq!(status(dd).plain_files, 0);
}

/// Review B-sealed-stores-4 follow-up (privacy re-verify): the sealing pass
/// that deletes an older lock creates no keyed lock file for a friend no
/// longer in the book (nothing would ever delete it: `raven contact remove`
/// needs the book entry), and still takes a book friend's keyed lock first.
/// `raven privacy rotate-meta` deletes every keyed lock file no friend in
/// the book has (one an earlier build of the pack left that way, a journal
/// beside none) unless a send holds it; such a file used to stay keyed
/// under the old `k_index` for good.
#[test]
fn no_keyed_send_lock_stays_for_a_contact_removed_before_the_upgrade() {
    let dir = profile();
    let dd = dir.path();
    crate::contact_book::tests::fixture(dd);
    let bob = [1u8; 32];
    let (removed, earlier, held) = (key(0x76), key(0x77), key(0x78));
    for peer in [&bob, &removed] {
        drop(PeerSendLock::acquire_within(dd, peer, Duration::ZERO).unwrap());
    }
    seal(dd);
    let old = at_rest::keys_cached(dd).unwrap();
    assert!(crate::outbox::legacy_send_lock_files(dd).is_empty());
    assert!(
        dd.join(at_rest::lock_name(&old, &bob)).exists(),
        "as before"
    );
    assert!(
        !dd.join(at_rest::lock_name(&old, &removed)).exists(),
        "no keyed lock for a name the book does not hold"
    );
    let databases = |dd: &Path| -> Vec<String> {
        let mut found: Vec<String> = std::fs::read_dir(dd)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".send_") && n.ends_with(".lock.sqlite"))
            .collect();
        found.sort();
        found
    };
    assert_eq!(databases(dd), [at_rest::lock_name(&old, &bob)]);

    // Keyed names no friend in the book has: one an earlier build of the
    // pack left, a journal beside none, and one a send holds now.
    drop(DataDirLock::acquire(dd, &at_rest::lock_name(&old, &earlier)).unwrap());
    let journal = format!("{}-journal", at_rest::lock_name(&old, &removed));
    std::fs::write(dd.join(&journal), b"").unwrap();
    let held_name = at_rest::lock_name(&old, &held);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let sender = {
        let dd = dd.to_path_buf();
        let name = held_name.clone();
        std::thread::spawn(move || {
            let lock = DataDirLock::acquire_within(&dd, &name, Duration::ZERO).unwrap();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(lock);
        })
    };
    held_rx.recv().unwrap();
    let rotated = rotate_meta(dd, NOW, &|| true).unwrap();
    assert_eq!(rotated.lock_files, 1, "Bob's, renamed");
    let new = at_rest::keys_cached(dd).unwrap();
    let mut left = vec![at_rest::lock_name(&new, &bob), held_name];
    left.sort();
    assert_eq!(databases(dd), left);
    assert!(!dd.join(&journal).exists());
    release_tx.send(()).unwrap();
    sender.join().unwrap();
}

/// A sealed profile after every PP.6 writer ran (and locks were taken for a
/// friend): no file holds a friend's key (hex, either case), address, IP,
/// relay PeerId or this computer's public name, and no file name names a
/// friend key, outside what the registry keeps plain on purpose.
#[test]
fn byte_scan_finds_no_friend_address_in_the_address_files() {
    let dir = profile();
    let dd = dir.path();
    write_address_files(dd);
    seal(dd);
    let bob = key(0x61);
    drop(PeerSendLock::acquire_within(dd, &bob, Duration::ZERO).unwrap());
    write_everything(dd, &key(0x65), 0x75);
    let needles: Vec<String> = vec![
        hex::encode(bob),
        hex::encode(bob).to_uppercase(),
        crate::encode_address(&bob),
        BOB_IP.into(),
        "203.0.113".into(),
        "198.51.100".into(),
        peer_id(0x62),
        peer_id(0x63),
        peer_id(0x64),
        "home.example.net".into(),
        "cd".repeat(16),
    ];
    let mut checked = 0;
    let mut stack = vec![dd.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path
                .strip_prefix(dd)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            // A contact request is named by its random request id; nothing
            // else names a friend.
            for needle in needles.iter().filter(|n| **n != "cd".repeat(16)) {
                assert!(!name.contains(needle.as_str()), "{name} names {needle}");
            }
            if name == "contacts.json" || name.ends_with(".sqlite") {
                // The book (PP.4) is sealed and checked by its own scan;
                // SQLite stores are PP.12-PP.14's.
                continue;
            }
            let raw = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
            for needle in &needles {
                assert!(!raw.contains(needle.as_str()), "{name} holds {needle}");
            }
            checked += 1;
        }
    }
    assert!(checked >= 14, "only {checked} files scanned");
}
