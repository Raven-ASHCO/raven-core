//! PP.7 tests: friends' addresses forgotten after 30 days without contact
//! ([`forget_stale_addresses`]). What a pass removes is what no dial reads
//! any more (every planner answers the same before and after, over a table
//! of route fixtures); a forgotten tombstone keeps no IP and a day; routes of
//! messages the outbox no longer holds go; a fresh sighting stays; a pass
//! that removed something marks a data-key rotation due; a second pass
//! changes nothing; the log line is counts only; raven-node's durable prune
//! runs it. Profiles are temp folders; the sealed ones take their keys from
//! the test build's lab K_hist (never a keychain item).

use super::*;
use crate::contact_book::tests::{profile, seal};
use crate::identity::Identity;
use crate::outbox::{
    CarrierChoice, CarrierGates, ContactRoutes, OutboxCarrier, OutboxRoute, OUTBOX_ROUTES_FILE,
};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::IpAddr;

const HOUR: u64 = 60 * 60 * 1000;
const DAY: u64 = 24 * HOUR;
const NET: &str = "n1";

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn key(seed: u8) -> [u8; 32] {
    id(seed).public_key_bytes()
}

fn peer_id(seed: u8) -> String {
    crate::p2p_route::local_peer_id(&id(seed))
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

fn mid(n: u8) -> [u8; 16] {
    [n; 16]
}

fn write_json(dd: &Path, name: &str, value: &Value) {
    std::fs::write(dd.join(name), serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

/// The file as JSON, sealed or plain (`Null` when it is missing).
fn read_json(dd: &Path, name: &str, kind: Kind) -> Value {
    at_rest::load_json::<Value>(dd, &dd.join(name), kind)
        .unwrap()
        .unwrap_or(Value::Null)
}

/// One learned_routes.json row as raven-node stores it: a global part
/// (PeerId, a relay, a custodian, a relay offer) and, with `lan`, a LAN part
/// `(port, peer IP, expiry)`.
fn learned_row(seed: u8, received: u64, expires: u64, lan: Option<(u16, &str, u64)>) -> Value {
    let relay = peer_id(seed.wrapping_add(0x40));
    let mut row = json!({
        "pub_hex": hex::encode(key(seed)), "generation": received, "received_at_ms": received,
        "expires_at_ms": expires, "via": "lan", "peer_id": peer_id(seed),
        "relays": [format!("/ip4/198.51.100.{seed}/tcp/7423/p2p/{relay}")],
        "custodians": [hex::encode(key(0x7f))],
        "offers": [{
            "relay_peer_id": peer_id(seed.wrapping_add(0x50)),
            "addrs": [format!("/ip4/198.51.100.{seed}/tcp/7427")], "flags": 0,
        }],
    });
    if let Some((port, lan_ip, lan_expires)) = lan {
        row["lan"] = json!({
            "generation": received, "received_at_ms": received, "expires_at_ms": lan_expires,
            "lan_port": port, "lan_ip": lan_ip,
        });
    }
    row
}

/// `row` as an expired snapshot is stored: the key, the generation, the
/// times, the carrier and the relays it offered.
fn tombstone(row: Value) -> Value {
    let keep = [
        "pub_hex",
        "generation",
        "received_at_ms",
        "expires_at_ms",
        "via",
        "offers",
    ];
    Value::Object(
        row.as_object()
            .unwrap()
            .iter()
            .filter(|(k, _)| keep.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

fn sighting(seed: u8, at: &str, when: u64) -> Value {
    json!({"pub_hex": hex::encode(key(seed)), "ip": at, "seen_at_ms": when})
}

fn remembered(seed: u8, carrier: &str, dial: &str, at: u64) -> Value {
    json!({
        "pub_hex": hex::encode(key(seed)), "route": {"carrier": carrier, "dial": dial},
        "at_ms": at, "net": NET,
    })
}

fn object(seed: u8, routes: &[(&str, &str)], expires: u64) -> Value {
    json!({
        "peer_pub_hex": hex::encode(key(seed)), "choice": "auto",
        "routes": routes.iter().map(|(c, d)| json!({"carrier": c, "dial": d})).collect::<Vec<_>>(),
        "expires_at_ms": expires, "unsent": true,
    })
}

/// The contacts of the route fixture table, each with its saved routes:
/// - Alice (0x71): heard an hour ago on the LAN and by RRH1 (a live snapshot
///   with a LAN part, and an older duplicate row), a fresh route-memory grant,
///   a waiting message;
/// - Bob (0x72): unheard for 31 days: a 31-day-old sighting, an expired
///   snapshot with its LAN part and offers, a 31-day-old grant, records of
///   messages the outbox no longer holds (one live, one expired);
/// - Carol (0x73): linked two days ago, her last RRH1 35 days old (a
///   tombstone with an offer, kept whole), a grant past its lease, a waiting
///   message live and one expired whose evidence is still needed;
/// - Dave (0x74): unverified, no saved LAN route (an invite), a noise pin
///   and a 3-day-old sighting (the cutoff F7 default-port guess), a live
///   snapshot whose LAN part expired (since Phase 3 P3.C1 its port is kept
///   and planned, in place of F7's guess);
/// - Erin (0x75): a snapshot stamped in the future (the clock went back).
const CONTACTS: [u8; 5] = [0x71, 0x72, 0x73, 0x74, 0x75];
/// The messages the store still holds.
const IN_OUTBOX: [u8; 3] = [1, 4, 5];

fn plant(dd: &Path, now: u64) {
    let row = |seed: u8, name: &str, pinned: bool, lan: &str, inet: &str| {
        json!({
            "petname": name, "address": crate::encode_address(&key(seed)),
            "pub_hex": hex::encode(key(seed)), "pinned": pinned, "lan_dial": lan,
            "internet_dial": inet,
        })
    };
    crate::contact_book::write_rows(
        dd,
        &[
            row(0x71, "Alice", true, "192.168.1.20:7420", "203.0.113.9:7422"),
            row(0x72, "Bob", true, "192.168.1.21:7420", ""),
            row(0x73, "Carol", true, "192.168.1.22:7420", ""),
            row(0x74, "Dave", false, "", ""),
            row(0x75, "Erin", true, "192.168.1.25:7420", ""),
        ],
    )
    .unwrap();
    write_json(
        dd,
        crate::lan_seen::LAN_SEEN_FILE,
        &json!([
            sighting(0x71, "192.168.1.37", now - HOUR),
            sighting(0x72, "192.168.1.38", now - 31 * DAY),
            sighting(0x73, "192.168.1.39", now - 2 * DAY),
            sighting(0x74, "10.77.0.40", now - 3 * DAY),
        ]),
    );
    write_json(
        dd,
        crate::learned_routes::LEARNED_ROUTES_FILE,
        &json!([
            learned_row(
                0x71,
                now - HOUR,
                now + 6 * DAY,
                Some((7531, "192.168.1.37", now + 6 * DAY))
            ),
            learned_row(0x71, now - 2 * HOUR, now + 5 * DAY, None),
            learned_row(
                0x72,
                now - 31 * DAY,
                now - 24 * DAY,
                Some((7532, "192.168.1.38", now - 24 * DAY))
            ),
            tombstone(learned_row(0x73, now - 35 * DAY, now - 28 * DAY, None)),
            learned_row(
                0x74,
                now - 3 * DAY,
                now + 2 * DAY,
                Some((7534, "10.77.0.40", now - HOUR))
            ),
            learned_row(0x75, now + 2 * DAY, now + 3 * DAY, None),
        ]),
    );
    write_json(
        dd,
        crate::route_memory::ROUTE_MEMORY_FILE,
        &json!([
            remembered(0x71, "internet", "203.0.113.9:7422", now - 5 * 60 * 1000),
            remembered(0x72, "lan", "192.168.1.21:7420", now - 31 * DAY),
            remembered(0x73, "lan", "192.168.1.22:7420", now - 40 * 60 * 1000),
        ]),
    );
    let lan = |d: &'static str| ("lan", d);
    write_json(
        dd,
        OUTBOX_ROUTES_FILE,
        &json!({
            "objects": {
                hex::encode(mid(1)): object(0x71, &[lan("192.168.1.20:7420"),
                    ("internet", "203.0.113.9:7422")], now + DAY),
                hex::encode(mid(2)): object(0x72, &[lan("192.168.1.21:7420")], now + HOUR),
                hex::encode(mid(4)): object(0x73, &[lan("192.168.1.22:7420")], now + DAY),
            },
            "ended": {
                hex::encode(mid(3)): {"expires_at_ms": now - DAY, "unsent": true},
                hex::encode(mid(5)): {"expires_at_ms": now - HOUR, "written": true},
            },
        }),
    );
    crate::lan_noise_pin::record(
        dd,
        &crate::lan_noise_pin::test_key(),
        &key(0x74),
        &[0x51; 32],
    )
    .unwrap();
}

/// Everything a planner reads from the four files, as text: per contact its
/// routes with what it told us (route hints and the F7 guess on), its
/// remembered route and the plan of each waiting message; then the p2p
/// peer gate's lists, the announce targets, the relays named and the live
/// relay offers.
fn plans(dd: &Path, now: u64) -> Vec<String> {
    let gates = crate::outbox::LearnedGates {
        hints: true,
        default_port: true,
        inet: false,
    };
    let carriers = CarrierGates {
        lan: true,
        internet: true,
        p2p: true,
        nearby: false,
        onion: false,
    };
    let records = crate::outbox::object_route_records(dd, now).unwrap();
    let mut out = Vec::new();
    for seed in CONTACTS {
        let peer = key(seed);
        let book = crate::outbox::contact_routes(dd, &peer).unwrap().unwrap();
        let contact: ContactRoutes =
            crate::outbox::with_learned_routes_gated(dd, &peer, book, |_| true, gates);
        let preferred = crate::route_memory::preferred_route(dd, &peer, Some(NET), now);
        let objects: Vec<_> = IN_OUTBOX
            .iter()
            .map(|n| {
                let record = records
                    .get(&mid(*n))
                    .filter(|r| r.peer_pub_hex == hex::encode(peer));
                crate::outbox::plan_object_routes_preferring(
                    record,
                    &contact,
                    carriers,
                    preferred.as_ref(),
                )
            })
            .collect();
        out.push(format!("{seed:#x} {contact:?} {preferred:?} {objects:?}"));
    }
    let live_offers: Vec<_> = crate::learned_routes::offers(dd, now)
        .into_iter()
        .filter(|(.., expires)| *expires > now)
        .collect();
    out.push(format!(
        "{:?} {:?} {:?} {:?} {live_offers:?}",
        crate::learned_routes::learned_peer_ids(dd, now),
        crate::learned_routes::learned_p2p(dd, now),
        crate::learned_routes::live_contacts(dd, now),
        crate::learned_routes::relays_named_at(dd, now),
    ));
    let evidence = crate::outbox::object_route_evidence(dd, now).unwrap();
    out.push(format!(
        "evidence {:?}",
        IN_OUTBOX.map(|n| evidence.get(&mid(n)).copied())
    ));
    out
}

fn in_outbox() -> Result<HashSet<[u8; 16]>, String> {
    Ok(IN_OUTBOX.iter().map(|n| mid(*n)).collect())
}

/// Every planner answers the same before and after a pass, over the table
/// of fixtures: what went is what no dial reads.
#[test]
fn prune_removes_only_entries_no_dial_uses() {
    let dir = profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    plant(dd, now);
    let before = plans(dd, now);
    let report = forget_stale_addresses_with(dd, now, in_outbox);
    assert_eq!(plans(dd, now), before);
    assert_eq!(
        report,
        ForgetReport {
            sightings: 1,
            // Bob's snapshot cut, Erin's future snapshot, Alice's older
            // row (Dave's expired LAN part is kept: Phase 3 P3.C1).
            learned_routes: 3,
            remembered_routes: 2,
            message_routes: 2,
            peer_schedules: 0,
            kept: 0,
        }
    );
    // Something was there to forget: the fixtures are not trivially equal.
    // Alice: the port she told on her saved host, and where she was seen
    // (since E2 the told port goes on the saved host first).
    assert!(before.iter().any(|p| p.contains("192.168.1.20:7531")));
    assert!(before.iter().any(|p| p.contains("192.168.1.37:7420")));
    assert!(before.iter().any(|p| p.contains("10.77.0.40:")));
    // On disk: nothing of Bob's sighting, LAN part or offer; Carol's offer
    // (heard on the LAN two days ago) stays.
    let disk = |name: &str, kind: Kind| read_json(dd, name, kind).to_string();
    let seen = disk(crate::lan_seen::LAN_SEEN_FILE, Kind::LanSeen);
    let learned = disk(
        crate::learned_routes::LEARNED_ROUTES_FILE,
        Kind::LearnedRoutes,
    );
    assert!(!seen.contains("192.168.1.38") && seen.contains("192.168.1.37"));
    assert!(!learned.contains("192.168.1.38") && !learned.contains("198.51.100.114"));
    assert!(learned.contains("198.51.100.115"), "{learned}");
    assert!(
        learned.contains("10.77.0.40"),
        "Dave's kept LAN part (P3.C1)"
    );
    let routes = disk(OUTBOX_ROUTES_FILE, Kind::OutboxRoutes);
    for gone in [mid(2), mid(3)] {
        assert!(!routes.contains(&hex::encode(gone)), "{routes}");
    }
    for kept in IN_OUTBOX {
        assert!(routes.contains(&hex::encode(mid(kept))), "{routes}");
    }
    let memory = disk(crate::route_memory::ROUTE_MEMORY_FILE, Kind::RouteMemory);
    assert!(!memory.contains("192.168.1.2") && memory.contains("203.0.113.9:7422"));
}

/// A contact unheard for 30 days keeps a tombstone with its generation and
/// times to the day (the generation is a time too): no IP, port, relay,
/// offer or custodian. It still goes [`crate::learned_routes::TOMBSTONE_MS`]
/// past its expiry (to the day).
#[test]
fn tombstones_keep_no_ip_and_day_granular_time() {
    let dir = profile();
    let dd = dir.path();
    let now = 20_000 * DAY + 13 * HOUR + 7;
    let heard = now - 31 * DAY - 5 * HOUR;
    let expires = heard + 7 * DAY;
    write_json(
        dd,
        crate::learned_routes::LEARNED_ROUTES_FILE,
        &json!([learned_row(
            0x72,
            heard,
            expires,
            Some((7532, "192.168.1.38", expires))
        )]),
    );
    let report = forget_stale_addresses_with(dd, now, in_outbox);
    assert_eq!(report.learned_routes, 1);
    let rows = read_json(
        dd,
        crate::learned_routes::LEARNED_ROUTES_FILE,
        Kind::LearnedRoutes,
    );
    let row = rows[0].as_object().unwrap();
    let mut fields: Vec<&str> = row.keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "expires_at_ms",
            "generation",
            "pub_hex",
            "received_at_ms",
            "via"
        ]
    );
    assert_eq!(row["generation"], json!(heard - heard % DAY));
    assert_eq!(row["received_at_ms"], json!(heard - heard % DAY));
    assert_eq!(row["expires_at_ms"], json!(expires - expires % DAY));
    let text = rows.to_string();
    for absent in ["192.168.1.38", "7532", "198.51.100", &peer_id(0x72)] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
    // The diagnosis still knows the contact was heard, about when.
    assert_eq!(
        crate::learned_routes::last_heard(dd, &key(0x72), now),
        Some((heard - heard % DAY, true))
    );
    // Linked recently (a sighting): not cut.
    let carol = learned_row(0x73, heard, expires, None);
    write_json(
        dd,
        crate::learned_routes::LEARNED_ROUTES_FILE,
        &json!([carol]),
    );
    write_json(
        dd,
        crate::lan_seen::LAN_SEEN_FILE,
        &json!([sighting(0x73, "192.168.1.39", now - 29 * DAY)]),
    );
    forget_stale_addresses_with(dd, now, in_outbox);
    let text = read_json(
        dd,
        crate::learned_routes::LEARNED_ROUTES_FILE,
        Kind::LearnedRoutes,
    )
    .to_string();
    assert!(text.contains("198.51.100.115"), "the offer stays: {text}");
    // The bare tombstone goes when its time is up, as before.
    write_json(
        dd,
        crate::learned_routes::LEARNED_ROUTES_FILE,
        &json!([learned_row(0x72, heard, expires, None)]),
    );
    forget_stale_addresses_with(dd, now, in_outbox);
    let gone = (expires - expires % DAY) + crate::learned_routes::TOMBSTONE_MS;
    forget_stale_addresses_with(dd, gone - 1, in_outbox);
    assert_eq!(
        read_json(
            dd,
            crate::learned_routes::LEARNED_ROUTES_FILE,
            Kind::LearnedRoutes
        )
        .as_array()
        .map(Vec::len),
        Some(1)
    );
    forget_stale_addresses_with(dd, gone, in_outbox);
    assert_eq!(
        read_json(
            dd,
            crate::learned_routes::LEARNED_ROUTES_FILE,
            Kind::LearnedRoutes
        ),
        json!([])
    );
}

/// The routes of a message the outbox no longer holds go, live or expired;
/// those of a waiting message stay, and so does what an expired one that
/// is still waiting keeps. A record written while the store was read is
/// never a candidate; a store that cannot be read removes nothing.
#[test]
fn finished_objects_lose_their_routes() {
    let dir = profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    let bob = key(0x72);
    let lan = [route(OutboxCarrier::Lan, "192.168.1.21:7420")];
    let record = |n: u8, expires: u64, at: u64| {
        crate::outbox::record_object_routes(
            dd,
            &mid(n),
            &bob,
            CarrierChoice::Auto,
            &lan,
            expires,
            at,
        )
        .unwrap();
        crate::outbox::set_object_unsent(dd, &mid(n), true, at).unwrap();
    };
    record(1, now + DAY, now);
    record(2, now + DAY, now);
    // Expired: only its evidence is kept.
    record(3, now - HOUR, now - 2 * HOUR);
    record(4, now - HOUR, now - 2 * HOUR);
    let unreadable = forget_stale_addresses_with(dd, now, || Err("store busy".into()));
    assert_eq!((unreadable.message_routes, unreadable.kept), (0, 1));
    assert_eq!(
        crate::outbox::object_route_evidence(dd, now).unwrap().len(),
        4
    );
    let report = forget_stale_addresses_with(dd, now, || {
        // Recorded while the store is read: not a candidate.
        record(9, now + DAY, now);
        Ok([mid(1), mid(3)].into())
    });
    assert_eq!(report.message_routes, 2);
    let live = crate::outbox::object_route_records(dd, now).unwrap();
    assert_eq!(
        live.keys().copied().collect::<Vec<_>>(),
        vec![mid(1), mid(9)]
    );
    let evidence = crate::outbox::object_route_evidence(dd, now).unwrap();
    assert_eq!(
        evidence.keys().copied().collect::<Vec<_>>(),
        vec![mid(1), mid(3), mid(9)]
    );
    assert!(evidence[&mid(3)].unsent, "a waiting message's evidence");
    // A profile without a store holds no outbox: none is created.
    let report = forget_stale_addresses(dd, now);
    assert_eq!(report.message_routes, 3);
    assert!(!dd
        .join(crate::indexed_session_store::INDEXED_SESSION_METADATA_FILE)
        .exists());
}

/// P5.9 (the long message horizon, Phase 5a): a parked message still waits
/// for its deadline, so while the horizon is live it counts as held and its
/// route record (with its never-sent flag) stays through the pass; with the
/// gate closed nothing new is read and the record goes, as before.
#[test]
fn parked_messages_keep_their_routes_while_the_horizon_is_live() {
    let dir = profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    let bob = key(0x72);
    let lan = [route(OutboxCarrier::Lan, "192.168.1.21:7420")];
    crate::outbox::record_object_routes(
        dd,
        &mid(1),
        &bob,
        CarrierChoice::Auto,
        &lan,
        now + crate::horizon::MESSAGE_HORIZON_MS,
        now,
    )
    .unwrap();
    crate::outbox::set_object_unsent(dd, &mid(1), true, now).unwrap();
    let mut store = crate::indexed_session_store::IndexedSessionStore::open(dd).unwrap();
    assert!(store
        .park_outbound(
            &bob,
            &mid(1),
            None,
            now,
            now + crate::horizon::MESSAGE_HORIZON_MS,
            now
        )
        .unwrap());
    drop(store);
    crate::horizon::set_lab_horizon_for_this_thread(Some(false));
    assert!(outbox_message_ids(dd).unwrap().is_empty(), "gate closed");
    crate::horizon::set_lab_horizon_for_this_thread(Some(true));
    assert_eq!(outbox_message_ids(dd).unwrap(), HashSet::from([mid(1)]));
    let report = forget_stale_addresses(dd, now);
    assert_eq!(report.message_routes, 0);
    let evidence = crate::outbox::object_route_evidence(dd, now).unwrap();
    assert!(
        evidence[&mid(1)].unsent,
        "the parked message's record stays"
    );
    crate::horizon::set_lab_horizon_for_this_thread(Some(false));
    let report = forget_stale_addresses(dd, now);
    assert_eq!(report.message_routes, 1, "gate closed: as before");
    crate::horizon::set_lab_horizon_for_this_thread(None);
}

/// A sighting within 30 days stays (a dial may use it); an older one goes.
#[test]
fn a_fresh_sighting_is_kept() {
    let dir = profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    let (bob, carol) = (key(0x72), key(0x73));
    crate::lan_seen::record_contact_seen(dd, &bob, ip("192.168.1.38"), None, now - 29 * DAY)
        .unwrap();
    crate::lan_seen::record_contact_seen(dd, &carol, ip("192.168.1.39"), None, now - 31 * DAY)
        .unwrap();
    let report = forget_stale_addresses_with(dd, now, in_outbox);
    assert_eq!(report.sightings, 1);
    assert_eq!(
        crate::lan_seen::seen_ip(dd, &bob, now),
        Some(ip("192.168.1.38"))
    );
    assert_eq!(
        crate::lan_seen::sighting_times(dd)
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec![&hex::encode(bob)]
    );
    // A pass that finds nothing old writes nothing and takes no lock.
    let raw = std::fs::read(dd.join(crate::lan_seen::LAN_SEEN_FILE)).unwrap();
    std::fs::remove_file(dd.join(crate::lan_seen::LAN_SEEN_LOCK)).unwrap();
    assert_eq!(
        forget_stale_addresses_with(dd, now, in_outbox),
        ForgetReport::default()
    );
    assert_eq!(
        std::fs::read(dd.join(crate::lan_seen::LAN_SEEN_FILE)).unwrap(),
        raw
    );
    assert!(!dd.join(crate::lan_seen::LAN_SEEN_LOCK).exists());
}

/// In a sealed profile the files stay sealed, a pass that removed something
/// marks a data-key rotation due (older sealed copies in freed blocks still
/// hold what went), and one that removed nothing does not. A file whose key
/// this process has not loaded is kept as it is.
#[test]
fn a_prune_that_removed_something_sets_rotation_due() {
    let dir = profile();
    let dd = dir.path();
    seal(dd);
    let now = crate::clock::now_ms();
    crate::lan_seen::record_contact_seen(dd, &key(0x72), ip("192.168.1.38"), None, now - 29 * DAY)
        .unwrap();
    assert_eq!(
        forget_stale_addresses_with(dd, now, in_outbox),
        ForgetReport::default()
    );
    assert!(!rotation_due(dd));
    let path = dd.join(crate::lan_seen::LAN_SEEN_FILE);
    at_rest::forget_cached_keys(dd);
    let sealed = std::fs::read(&path).unwrap();
    assert!(at_rest::is_sealed(&sealed));
    let later = now + 2 * DAY;
    let blind = forget_stale_addresses_with(dd, later, in_outbox);
    assert_eq!((blind.removed(), blind.kept), (0, 1));
    assert_eq!(std::fs::read(&path).unwrap(), sealed);
    assert!(!rotation_due(dd));
    at_rest::keys_load_with(dd, MigratePolicy::Allow).unwrap();
    assert_eq!(
        forget_stale_addresses_with(dd, later, in_outbox).sightings,
        1
    );
    assert!(rotation_due(dd));
    assert!(at_rest::is_sealed(&std::fs::read(&path).unwrap()));
    assert_eq!(
        read_json(dd, crate::lan_seen::LAN_SEEN_FILE, Kind::LanSeen),
        json!([])
    );
}

/// A second pass at the same time removes nothing and writes nothing.
#[test]
fn a_second_pass_changes_nothing() {
    let dir = profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    plant(dd, now);
    assert!(forget_stale_addresses_with(dd, now, in_outbox).removed() > 0);
    let files = [
        crate::lan_seen::LAN_SEEN_FILE,
        crate::learned_routes::LEARNED_ROUTES_FILE,
        crate::route_memory::ROUTE_MEMORY_FILE,
        OUTBOX_ROUTES_FILE,
    ];
    let bytes = || files.map(|name| std::fs::read(dd.join(name)).unwrap());
    let first = bytes();
    assert_eq!(
        forget_stale_addresses_with(dd, now, in_outbox),
        ForgetReport::default()
    );
    assert_eq!(bytes(), first);
}

/// What a pass logs is fixed words and counts: no key, address or time.
#[test]
fn the_report_is_counts_only() {
    let dir = profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    plant(dd, now);
    let line = forget_stale_addresses_with(dd, now, in_outbox).to_string();
    let names: Vec<&str> = line
        .split(' ')
        .map(|field| {
            let (name, count) = field.split_once('=').unwrap();
            assert!(count.parse::<usize>().is_ok(), "{line}");
            name
        })
        .collect();
    assert_eq!(
        names,
        [
            "sightings",
            "learned_routes",
            "route_memory",
            "outbox_routes",
            "peer_schedules",
            "kept"
        ]
    );
    // Dave's expired LAN part is kept (Phase 3 P3.C1): 3 learned routes.
    assert_eq!(
        line,
        "sightings=1 learned_routes=3 route_memory=2 outbox_routes=2 peer_schedules=0 kept=0"
    );
}

/// Phase 4: the pass takes a contact's PeerId schedule entries behind its
/// clock off the disk (the capability stays), and counts them.
#[test]
fn the_forget_pass_prunes_peer_schedules() {
    use crate::peer_rotation::{self as pr, ContactSchedule};
    let dir = profile();
    let dd = dir.path();
    let id = Identity::from_seed(&[0x5a; 32]);
    let received_ms = 1_800_000_000_000u64;
    let announced = pr::announced_schedule(&id, Some((10, false)), 600);
    let s = ContactSchedule::from_announced(&announced, received_ms);
    pr::save_schedule(dd, &hex::encode(key(0x5a)), &s).unwrap();
    // Four epochs later: 9 (previous) .. 12 are behind the clock (14 or 15).
    let later = received_ms + 4 * 600 * 1000;
    let report = forget_stale_addresses_with(dd, later, in_outbox);
    assert_eq!(report.peer_schedules, 4, "{report}");
    let left = pr::load_schedules(dd).unwrap();
    let kept = &left[&hex::encode(key(0x5a))];
    assert!(kept.capable);
    assert_eq!(
        kept.entries.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
        [13, 14, 15, 16]
    );
    assert_eq!(
        forget_stale_addresses_with(dd, later, in_outbox).peer_schedules,
        0
    );
}

/// raven-node's periodic durable prune forgets too, whatever its own pass
/// did (here: a profile with nothing else in it).
#[test]
fn the_durable_prune_forgets_old_sightings() {
    let dir = profile();
    let dd = dir.path();
    let now = crate::clock::now_ms();
    crate::lan_seen::record_contact_seen(dd, &key(0x72), ip("192.168.1.38"), None, now - 31 * DAY)
        .unwrap();
    let _ = crate::lan_dispatch::prune_expired_lan_durable_state(dd);
    assert_eq!(
        crate::lan_seen::sighting_times(dd).map(|t| t.len()),
        Some(0)
    );
}
