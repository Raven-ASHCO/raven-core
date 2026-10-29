use super::*;
use crate::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
use crate::envelope::Envelope;
use crate::friend_custody::{handle_frame, rfc1_rso1, InboundLink};
use crate::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointDeliveryState, IndexedSessionRecordKey,
};
use crate::lan_dispatch::{
    cache_peer_bundle, create_initiator_pair_init, dispatch_frame, local_bundle, wrap_pair_init,
};
use crate::outbox::OutboxCarrier;
use crate::owed_acks::OwedAcks;
use crate::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};

/// Raven's clock, as the code under test reads it (the suite may run on a
/// lab clock).
fn now() -> u64 {
    crate::clock::now_ms()
}

fn contacts(dir: &Path, entries: &[(&Identity, &str)]) {
    let rows: Vec<String> = entries
        .iter()
        .map(|(id, name)| {
            format!(
                r#"{{"petname":"{name}","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.9:7420","internet_dial":""}}"#,
                hex::encode(id.public_key_bytes())
            )
        })
        .collect();
    std::fs::write(dir.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
}

struct World {
    alice: Identity,
    bob: Identity,
    carol: Identity,
    a: tempfile::TempDir,
    b: tempfile::TempDir,
    c: tempfile::TempDir,
    key: IndexedSessionRecordKey,
}

fn world(seed: u8) -> World {
    crate::identity_store::test_enable_locked_file_identity_backend();
    let id = |n: u8| Identity::from_seed(&[seed.wrapping_add(n); 32]);
    let (alice, bob, carol) = (id(0), id(1), id(2));
    let (a, b, c) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let a_bundle = local_bundle(a.path(), &alice).unwrap();
    let b_bundle = local_bundle(b.path(), &bob).unwrap();
    contacts(a.path(), &[(&bob, "Bob"), (&carol, "Carol")]);
    contacts(b.path(), &[(&alice, "Alice"), (&carol, "Carol")]);
    contacts(c.path(), &[(&alice, "Alice"), (&bob, "Bob")]);
    crate::node_policy::save_policy(
        c.path(),
        &crate::node_policy::NodePolicy {
            custody: true,
            ..Default::default()
        },
    )
    .unwrap();
    cache_peer_bundle(a.path(), &b_bundle).unwrap();
    cache_peer_bundle(b.path(), &a_bundle).unwrap();
    let (init, key) = create_initiator_pair_init(a.path(), &alice, &b_bundle).unwrap();
    let replies = dispatch_frame(
        b.path(),
        &bob,
        &a_bundle,
        &alice.public_key_bytes(),
        &wrap_pair_init(&alice, &init).unwrap(),
    )
    .unwrap();
    let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
        panic!()
    };
    IndexedSessionStore::open(a.path())
        .unwrap()
        .confirm_verified_pair_response(
            &key,
            &init,
            &crate::pair_init::decode_response(&wire).unwrap(),
            now(),
        )
        .unwrap();
    World {
        alice,
        bob,
        carol,
        a,
        b,
        c,
        key,
    }
}

impl World {
    /// A dial to Carol from `who` over a local LAN link: every frame goes to
    /// Carol's real handler.
    fn carol_dial<'a>(
        &'a self,
        who: &'a Identity,
    ) -> impl FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + 'a {
        move |frames: &[Vec<u8>]| {
            let link = InboundLink {
                carrier: OutboxCarrier::Lan,
                source: Some("192.168.1.30".parse().unwrap()),
            };
            let mut out = vec![b"RLB1-offer".to_vec()];
            // Carol's LAN carrier gate is the build's: no test turns `raven
            // lan off` on while her handler reads it.
            let _untouched = crate::lan_gate::lan_user_switch_untouched();
            for f in frames {
                out.extend(handle_frame(
                    self.c.path(),
                    &self.carol,
                    &who.public_key_bytes(),
                    &link,
                    f,
                    now(),
                )?);
            }
            Ok(out)
        }
    }

    fn seal(&self, text: &str) -> Vec<u8> {
        let mut store = IndexedSessionStore::open(self.a.path()).unwrap();
        let (cert, reg) = crate::device_cert::ensure_local_device_certificate(
            self.a.path(),
            &self.alice,
            crate::paths::PRIMARY_DEVICE_ID,
        )
        .unwrap();
        let device = AuthorizedEndpointDevice::authorize(&cert, &self.alice, &reg, now()).unwrap();
        let t = now();
        let end = store.session_expires_at(&self.key).unwrap();
        let expires = crate::outbox::envelope_expires_at(t, end).unwrap();
        let mut out = None;
        store
            .send_message_envelope(
                &self.key,
                text,
                &device,
                t,
                expires,
                t,
                &mut rand::rngs::OsRng,
                &mut |d, bytes| {
                    out = Some(bytes.to_vec());
                    Ok(*d)
                },
            )
            .unwrap();
        out.unwrap()
    }
}

#[test]
fn a_message_and_its_ack_travel_via_a_friend() {
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: true,
        wan: false,
    }));
    let w = world(0x81);
    // Alice leaves two messages with Carol for Bob.
    let packed = [w.seal("via carol 1"), w.seal("via carol 2")];
    let items: Vec<DepositItem> = packed
        .iter()
        .map(|p| {
            let tag = IndexedSessionStore::open(w.a.path())
                .unwrap()
                .outbound_store_tag_for_object(&w.key, p, now())
                .unwrap();
            DepositItem {
                recipient: w.bob.public_key_bytes(),
                rso1: rfc1_rso1(tag, p).unwrap(),
            }
        })
        .collect();
    let answers = deposit_batch(&items, &mut w.carol_dial(&w.alice)).unwrap();
    assert_eq!(answers, vec![Some(CustodyCode::Ok), Some(CustodyCode::Ok)]);
    let again = deposit_batch(&items, &mut w.carol_dial(&w.alice)).unwrap();
    assert_eq!(
        again,
        vec![Some(CustodyCode::Duplicate), Some(CustodyCode::Duplicate)]
    );

    // Bob fetches with his inbound tags for Alice, ingests, then releases.
    let tags = inbound_tags(w.b.path(), &w.bob, &[w.alice.public_key_bytes()], now()).unwrap();
    assert!(!tags.is_empty());
    let mut state = FetchState::default();
    let report = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut w.carol_dial(&w.bob),
    );
    assert_eq!(report.accepted_messages, 2, "{report:?}");
    assert_eq!(report.released, 2, "the trailing release-only dial");
    assert!(state.pending_release.is_empty());
    let inbox = IndexedSessionStore::open(w.b.path())
        .unwrap()
        .list_endpoint_inbox()
        .unwrap();
    assert_eq!(inbox.len(), 2);
    // Released: a later round sees nothing.
    let quiet = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut w.carol_dial(&w.bob),
    );
    assert_eq!(quiet.items, 0);

    // Bob owes two ACKs; he leaves them with Carol for Alice.
    let (mut owed, _) = OwedAcks::open(w.b.path()).unwrap();
    let acks = owed.list(now()).unwrap();
    assert_eq!(acks.len(), 2);
    let ack_items: Vec<DepositItem> = acks
        .iter()
        .map(|a| {
            let tag = IndexedSessionStore::open(w.b.path())
                .unwrap()
                .outbound_store_tag_for_object(&w.key, &a.bytes, now())
                .unwrap();
            DepositItem {
                recipient: w.alice.public_key_bytes(),
                rso1: rfc1_rso1(tag, &a.bytes).unwrap(),
            }
        })
        .collect();
    let stored = deposit_batch(&ack_items, &mut w.carol_dial(&w.bob)).unwrap();
    assert!(
        stored.iter().all(|c| c.is_some_and(CustodyCode::held)),
        "{stored:?}"
    );

    // Alice fetches them: both messages delivered.
    let a_tags = inbound_tags(w.a.path(), &w.alice, &[w.bob.public_key_bytes()], now()).unwrap();
    let mut a_state = FetchState::default();
    let back = fetch_round(
        w.a.path(),
        &w.alice,
        &a_tags,
        &mut a_state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut w.carol_dial(&w.alice),
    );
    assert_eq!(back.accepted_acks, 2, "{back:?}");
    let store = IndexedSessionStore::open(w.a.path()).unwrap();
    let sid = {
        let mut s = IndexedSessionStore::open(w.a.path()).unwrap();
        s.session_id_for_record_key(&w.key).unwrap()
    };
    for p in &packed {
        let mid = Envelope::unpack(p).unwrap().message_id;
        assert_eq!(
            store
                .outstanding_delivery_state(&sid, &mid, &w.bob.public_key_bytes())
                .unwrap(),
            Some(EndpointDeliveryState::Delivered)
        );
    }
    set_custody_gates_for_this_thread(None);
}

#[test]
fn a_co_custodian_or_stranger_cannot_fetch_or_release() {
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: true,
        wan: false,
    }));
    let w = world(0x91);
    let p = w.seal("for bob only");
    let tag = IndexedSessionStore::open(w.a.path())
        .unwrap()
        .outbound_store_tag_for_object(&w.key, &p, now())
        .unwrap();
    let item = DepositItem {
        recipient: w.bob.public_key_bytes(),
        rso1: rfc1_rso1(tag, &p).unwrap(),
    };
    assert_eq!(
        deposit_batch(&[item], &mut w.carol_dial(&w.alice)).unwrap(),
        vec![Some(CustodyCode::Ok)]
    );
    // Alice (a pinned contact of Carol, not the recipient) presents Bob's tag.
    let tags = inbound_tags(w.b.path(), &w.bob, &[w.alice.public_key_bytes()], now()).unwrap();
    let mut state = FetchState::default();
    let report = fetch_round(
        w.a.path(),
        &w.alice,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut w.carol_dial(&w.alice),
    );
    assert_eq!(report.items, 0);
    // Bob still gets it.
    let mut bob_state = FetchState::default();
    let got = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut bob_state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut w.carol_dial(&w.bob),
    );
    assert_eq!(got.accepted_messages, 1);
    set_custody_gates_for_this_thread(None);
}

#[test]
fn custodian_lists_are_validated_and_targets_need_both_pins() {
    crate::identity_store::test_enable_locked_file_identity_backend();
    let dir = tempfile::tempdir().unwrap();
    let id = |n: u8| Identity::from_seed(&[n; 32]);
    let (me, bob, carol, dan, eve) = (id(1), id(2), id(3), id(4), id(5));
    let hexk = |i: &Identity| hex::encode(i.public_key_bytes());
    let rows = format!(
        r#"[{{"pub_hex":"{b}","pinned":true,"custodians":["{c}","{c}","{b}","{m}","zz","{d}","{e}"]}},
            {{"pub_hex":"{c}","pinned":true}},
            {{"pub_hex":"{d}","pinned":false}},
            {{"pub_hex":"{e}","pinned":true}}]"#,
        b = hexk(&bob),
        c = hexk(&carol),
        m = hexk(&me),
        d = hexk(&dan),
        e = hexk(&eve)
    );
    std::fs::write(dir.path().join("contacts.json"), rows).unwrap();
    let local = me.public_key_bytes();
    let listed = listed_custodians(dir.path(), &bob.public_key_bytes(), &local).unwrap();
    // Deduped, never the peer or me, garbage skipped, at most two.
    assert_eq!(
        listed,
        vec![carol.public_key_bytes(), dan.public_key_bytes()]
    );
    // Dan is not pinned: not usable, so only Carol is a fetch target.
    let targets = fetch_targets(dir.path(), &local, now()).unwrap();
    assert_eq!(
        targets,
        vec![(carol.public_key_bytes(), vec![bob.public_key_bytes()])]
    );
}

/// A WAN custody fetch plans no Internet direct route to a custodian this
/// node hides its IP from, by its row or by the node policy (every contact),
/// as every other planner (D4); its LAN route stays.
#[test]
fn a_custodian_hidden_from_gets_no_internet_route() {
    use crate::outbox::{CarrierGates, OutboxCarrier};
    let dir = tempfile::tempdir().unwrap();
    let carol = Identity::from_seed(&[0x33; 32]).public_key_bytes();
    let book = |hide_ip: bool| {
        std::fs::write(
            dir.path().join("contacts.json"),
            format!(
                r#"[{{"pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.9:7420","internet_dial":"203.0.113.7:7422","hide_ip":{hide_ip}}}]"#,
                hex::encode(carol)
            ),
        )
        .unwrap();
    };
    let everyone = |hide_ip: bool| {
        crate::node_policy::save_policy(
            dir.path(),
            &crate::node_policy::NodePolicy {
                hide_ip,
                ..crate::node_policy::NodePolicy::default()
            },
        )
        .unwrap();
    };
    let open = CarrierGates {
        lan: true,
        internet: true,
        p2p: false,
        nearby: false,
        onion: false,
    };
    let wan = CustodyGates {
        live: true,
        wan: true,
    };
    let carriers = || -> Vec<OutboxCarrier> {
        custodian_routes_with(
            dir.path(),
            &carol,
            None,
            &[],
            open,
            wan,
            crate::outbox::LearnedGates::now(),
            |_| true,
            false,
        )
        .into_iter()
        .map(|(planned, _)| planned.carrier)
        .collect()
    };
    book(false);
    everyone(false);
    assert_eq!(carriers(), [OutboxCarrier::Lan, OutboxCarrier::Internet]);
    book(true);
    assert_eq!(carriers(), [OutboxCarrier::Lan], "hidden by its row");
    book(false);
    everyone(true);
    assert_eq!(carriers(), [OutboxCarrier::Lan], "hidden from everyone");
}

/// A custodian is planned as the delivery planners plan a contact: a
/// learned local-network address (where it last reached us from) that the
/// caller's on-link filter refuses is not dialled, so a deposit or a fetch
/// after a network change never sends the signed bind to whoever holds that
/// address now. The saved route stays; a kept address is dialled after it.
#[test]
fn a_custodian_s_learned_address_off_this_network_is_not_dialled() {
    use crate::outbox::{CarrierGates, OutboxRoute};
    let dir = tempfile::tempdir().unwrap();
    let carol = Identity::from_seed(&[0x35; 32]).public_key_bytes();
    std::fs::write(
        dir.path().join("contacts.json"),
        format!(
            r#"[{{"pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.9:7420"}}]"#,
            hex::encode(carol)
        ),
    )
    .unwrap();
    let seen: std::net::IpAddr = "192.168.1.20".parse().unwrap();
    crate::lan_seen::record_contact_seen(dir.path(), &carol, seen, None, now()).unwrap();
    let lan_only = CarrierGates {
        lan: true,
        internet: false,
        p2p: false,
        nearby: false,
        onion: false,
    };
    let custody = CustodyGates {
        live: true,
        wan: false,
    };
    let dials = |keep: fn(std::net::IpAddr) -> bool| -> Vec<String> {
        custodian_routes_with(
            dir.path(),
            &carol,
            None,
            &[],
            lan_only,
            custody,
            crate::outbox::LearnedGates::now(),
            keep,
            false,
        )
        .into_iter()
        .map(|(_, dialled): (OutboxRoute, OutboxRoute)| dialled.dial)
        .collect()
    };
    assert_eq!(dials(|_| true), ["192.168.1.9:7420", "192.168.1.20:7420"]);
    assert_eq!(
        dials(|ip| ip != "192.168.1.20".parse::<std::net::IpAddr>().unwrap()),
        ["192.168.1.9:7420"]
    );
    assert_eq!(
        dials(|_| false),
        ["192.168.1.9:7420"],
        "the saved route stays"
    );
}

/// Cutoff F8: a custodian that came back on another port and told us so
/// (RRH1 LAN_PORT on a LAN link from its address) is fetched from there,
/// after its saved route, while route hints are live; with them off only
/// the saved route is dialled.
#[test]
fn custodian_routes_include_the_rrh1_learned_lan_route() {
    use crate::outbox::{CarrierGates, LearnedGates, OutboxRoute};
    let dir = tempfile::tempdir().unwrap();
    let carol = Identity::from_seed(&[0x36; 32]).public_key_bytes();
    std::fs::write(
        dir.path().join("contacts.json"),
        format!(
            r#"[{{"pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.9:7420"}}]"#,
            hex::encode(carol)
        ),
    )
    .unwrap();
    let told = crate::route_hints::ValidHints {
        generation: 7,
        ttl_s: crate::route_hints::RRH1_DEFAULT_TTL_S,
        lan_port: Some(7533),
        ..Default::default()
    };
    let link = crate::route_hints::HintLink {
        carrier: OutboxCarrier::Lan,
        peer_ip: Some("192.168.1.9".parse().unwrap()),
        peer_zone: None,
        link_peer_id: None,
        book_peer_id: None,
        pinned: true,
        sender: carol,
        local: [0x52; 32],
        local_p2p: [0x53; 32],
        local_relay: None,
        lab_local: false,
        lab_loopback: false,
    };
    let applied =
        crate::learned_routes::apply_ungated(dir.path(), &carol, &told, &link, None, now())
            .unwrap();
    assert!(
        matches!(applied, crate::learned_routes::Applied::Changed { .. }),
        "{applied:?}"
    );
    let lan_only = CarrierGates {
        lan: true,
        internet: false,
        p2p: false,
        nearby: false,
        onion: false,
    };
    let custody = CustodyGates {
        live: true,
        wan: false,
    };
    let dials = |hints: bool, keep: fn(std::net::IpAddr) -> bool| -> Vec<String> {
        let learned = LearnedGates {
            hints,
            default_port: false,
            inet: false,
        };
        custodian_routes_with(
            dir.path(),
            &carol,
            None,
            &[],
            lan_only,
            custody,
            learned,
            keep,
            false,
        )
        .into_iter()
        .map(|(_, dialled): (OutboxRoute, OutboxRoute)| dialled.dial)
        .collect()
    };
    assert_eq!(
        dials(true, |_| true),
        ["192.168.1.9:7420", "192.168.1.9:7533"],
        "the announced port, after the saved route"
    );
    assert_eq!(dials(false, |_| true), ["192.168.1.9:7420"], "hints off");
    assert_eq!(
        dials(true, |_| false),
        ["192.168.1.9:7420"],
        "an address off this network is not dialled"
    );
}

/// A FETCH page comes in page-token order: Bob takes its messages in the
/// order Alice wrote them, each at its own receive time, so his inbox
/// (receive time, then message id) lists them in that order (s97).
#[test]
fn fetched_messages_are_taken_in_the_order_they_were_written() {
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: true,
        wan: false,
    }));
    let w = world(0x91);
    let texts = ["first", "second", "third", "fourth", "fifth"];
    let packed: Vec<Vec<u8>> = texts
        .iter()
        .map(|t| {
            // Distinct creation times, as messages written one by one.
            std::thread::sleep(std::time::Duration::from_millis(3));
            w.seal(t)
        })
        .collect();
    let items: Vec<DepositItem> = packed
        .iter()
        .map(|p| {
            let tag = IndexedSessionStore::open(w.a.path())
                .unwrap()
                .outbound_store_tag_for_object(&w.key, p, now())
                .unwrap();
            DepositItem {
                recipient: w.bob.public_key_bytes(),
                rso1: rfc1_rso1(tag, p).unwrap(),
            }
        })
        .collect();
    let answers = deposit_batch(&items, &mut w.carol_dial(&w.alice)).unwrap();
    assert!(
        answers.iter().all(|a| *a == Some(CustodyCode::Ok)),
        "{answers:?}"
    );
    let tags = inbound_tags(w.b.path(), &w.bob, &[w.alice.public_key_bytes()], now()).unwrap();
    let mut state = FetchState::default();
    let report = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut w.carol_dial(&w.bob),
    );
    assert_eq!(report.accepted_messages, texts.len(), "{report:?}");
    let inbox = IndexedSessionStore::open(w.b.path())
        .unwrap()
        .list_endpoint_inbox()
        .unwrap();
    let read: Vec<String> = inbox
        .iter()
        .map(|r| String::from_utf8_lossy(&r.plaintext).into_owned())
        .collect();
    assert_eq!(read, texts, "the order Alice wrote them");
    let times: Vec<u64> = inbox.iter().map(|r| r.received_at_ms).collect();
    assert!(times.windows(2).all(|t| t[0] < t[1]), "{times:?}");
    set_custody_gates_for_this_thread(None);
}

/// Receive times follow the clock, never repeat, and a caller's time ahead
/// of the clock still moves on by one.
#[test]
fn taken_at_is_strictly_increasing() {
    let mut last = 0;
    let first = taken_at(0, &mut last);
    let second = taken_at(0, &mut last);
    assert!(second > first);
    let ahead = crate::clock::now_ms() + 3_600_000;
    let a = taken_at(ahead, &mut last);
    let b = taken_at(ahead, &mut last);
    assert_eq!((a, b), (ahead, ahead + 1));
}

// ── Phase 3 P3.19: announced tags, deposit set, home targets, routes,
// budgets, rotation, tag cache ────────────────────────────────────────────

/// A test key (not a real identity: these tests never sign).
fn k(n: u8) -> [u8; 32] {
    [n; 32]
}

/// `dir`'s contact book: (key, verified, the custodians this node listed
/// for it), in this order, with a LAN route each.
/// A contact row: its key, verified, the custodians listed for it.
type BookRow<'a> = ([u8; 32], bool, &'a [[u8; 32]]);

fn book(dir: &Path, rows: &[BookRow<'_>]) {
    let rows: Vec<serde_json::Value> = rows
        .iter()
        .map(|(key, pinned, custodians)| {
            serde_json::json!({
                "pub_hex": hex::encode(key),
                "pinned": pinned,
                "lan_dial": "192.168.1.9:7420",
                "custodians": custodians.iter().map(hex::encode).collect::<Vec<_>>(),
            })
        })
        .collect();
    std::fs::write(
        dir.join("contacts.json"),
        serde_json::Value::Array(rows).to_string(),
    )
    .unwrap();
}

/// The node policy with `custody_use` and the manual home list.
fn uses_friends(dir: &Path, custody_use: Option<bool>, home: &[[u8; 32]]) {
    crate::node_policy::save_policy(
        dir,
        &crate::node_policy::NodePolicy {
            custody_use,
            custody_home: home.iter().map(hex::encode).collect(),
            ..Default::default()
        },
    )
    .unwrap();
}

/// `sender` (a verified contact) told this node `v` over `carrier` (a LAN
/// link from a local address, or a p2p link whose PeerId is `link_peer_id`).
fn told(
    dir: &Path,
    sender: &[u8; 32],
    carrier: OutboxCarrier,
    link_peer_id: Option<&str>,
    v: &crate::route_hints::ValidHints,
) {
    let link = crate::route_hints::HintLink {
        carrier,
        peer_ip: (carrier == OutboxCarrier::Lan).then(|| "192.168.1.9".parse().unwrap()),
        peer_zone: None,
        link_peer_id,
        book_peer_id: None,
        pinned: true,
        sender: *sender,
        local: [0x52; 32],
        local_p2p: [0x53; 32],
        local_relay: None,
        lab_local: false,
        lab_loopback: false,
    };
    let applied = crate::learned_routes::apply_ungated(dir, sender, v, &link, None, now()).unwrap();
    assert!(
        matches!(applied, crate::learned_routes::Applied::Changed { .. }),
        "{applied:?}"
    );
}

fn hints(generation: u64) -> crate::route_hints::ValidHints {
    crate::route_hints::ValidHints {
        generation,
        ttl_s: crate::route_hints::RRH1_DEFAULT_TTL_S,
        ..Default::default()
    }
}

/// `sender` announced the custodian tags `tags` (flags 0).
fn told_tags(dir: &Path, sender: &[u8; 32], tags: &[[u8; 32]]) {
    let mut v = hints(1);
    v.custodian_tags = tags.to_vec();
    v.custodian_tag_flags = vec![0; tags.len()];
    told(dir, sender, OutboxCarrier::Lan, None, &v);
}

/// `custodian` offers custody with `flags`.
fn told_offer(dir: &Path, custodian: &[u8; 32], flags: u8) {
    let mut v = hints(1);
    v.custody_offer = Some(flags);
    told(dir, custodian, OutboxCarrier::Lan, None, &v);
}

#[test]
fn announced_tags_union_home_and_static_cap_two_never_peer_or_self() {
    use crate::route_hints::custodian_tag;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (me, bob, carol, dan, eve) = (k(0x01), k(0xB0), k(0xC0), k(0xD0), k(0xE0));
    let tags = |cs: &[[u8; 32]]| -> Vec<[u8; 32]> {
        cs.iter().map(|c| custodian_tag(&me, &bob, c)).collect()
    };
    // Bob's row lists Dan (and Bob and me, never announced).
    book(
        d,
        &[
            (bob, true, &[bob, me, dan]),
            (carol, true, &[]),
            (dan, true, &[]),
            (eve, true, &[]),
        ],
    );
    // No consent: the static list only.
    uses_friends(d, None, &[carol]);
    assert_eq!(announced_custodian_tags(d, &me, &bob, now()), tags(&[dan]));
    // Consent: home first, then the static list; Bob himself never.
    uses_friends(d, Some(true), &[bob, carol]);
    assert_eq!(
        announced_custodian_tags(d, &me, &bob, now()),
        tags(&[carol, dan])
    );
    // At most two: the home list fills them.
    uses_friends(d, Some(true), &[carol, eve]);
    assert_eq!(
        announced_custodian_tags(d, &me, &bob, now()),
        tags(&[carol, eve])
    );
    // A home custodian also listed statically counts once.
    uses_friends(d, Some(true), &[dan]);
    assert_eq!(announced_custodian_tags(d, &me, &bob, now()), tags(&[dan]));
    // Tags are per pair: what Carol would see differs.
    assert_ne!(
        custodian_tag(&me, &bob, &dan),
        custodian_tag(&me, &carol, &dan)
    );
    // A listed custodian that is no longer a verified contact is never
    // named (the hints snapshot's rule).
    book(
        d,
        &[(bob, true, &[dan]), (carol, true, &[]), (dan, false, &[])],
    );
    uses_friends(d, None, &[]);
    assert!(announced_custodian_tags(d, &me, &bob, now()).is_empty());
}

#[test]
fn deposit_custodians_table() {
    use crate::custody_gate::{OFFER_REACHABLE, OFFER_WAN};
    use crate::route_hints::custodian_tag;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (me, bob, carol, dan, eve, fay, gus, hal, ivy) = (
        k(0x01),
        k(0xB0),
        k(0xC0),
        k(0xD0),
        k(0xE0),
        k(0xF0),
        k(0x60),
        k(0x70),
        k(0x80),
    );
    // Bob: I listed Eve (not verified) and Dan for him. Gus, Hal and Ivy
    // list nobody. Fay is blocked.
    book(
        d,
        &[
            (bob, true, &[eve, dan]),
            (carol, true, &[]),
            (dan, true, &[]),
            (eve, false, &[]),
            (fay, true, &[]),
            (gus, true, &[]),
            (hal, true, &[]),
            (ivy, true, &[]),
        ],
    );
    let mut blocks = crate::chat_history::BlockList::default();
    blocks.block(&hex::encode(fay));
    blocks.save(d).unwrap();
    // Bob names Dan (no offer) and Carol (offers); Ivy names Fay (offers,
    // blocked) and Carol.
    told_tags(
        d,
        &bob,
        &[
            custodian_tag(&bob, &me, &dan),
            custodian_tag(&bob, &me, &carol),
        ],
    );
    told_tags(
        d,
        &ivy,
        &[
            custodian_tag(&ivy, &me, &fay),
            custodian_tag(&ivy, &me, &carol),
        ],
    );
    told_offer(d, &carol, OFFER_WAN | OFFER_REACHABLE);
    told_offer(d, &fay, OFFER_WAN);
    // Gus names nobody I know (and a tag for another receiver).
    told_tags(
        d,
        &gus,
        &[
            custodian_tag(&gus, &me, &k(0x99)),
            custodian_tag(&gus, &bob, &carol),
        ],
    );
    // Hal uses Phase 2's plain keys (0x05).
    let mut legacy = hints(1);
    legacy.custodians = vec![carol];
    told(d, &hal, OutboxCarrier::Lan, None, &legacy);

    let offered = Some(OFFER_WAN | OFFER_REACHABLE);
    let set = |peer: &[u8; 32], live: bool| deposit_custodians_with(d, &me, peer, now(), live);

    // Consent on, hints live: the learned match with an offer first, then
    // the static list (Eve not usable: Dan, with no offer needed).
    uses_friends(d, Some(true), &[]);
    let before = crate::learned_routes::loads_on_this_thread();
    assert_eq!(set(&bob, true), [(carol, offered), (dan, None)]);
    assert_eq!(
        crate::learned_routes::loads_on_this_thread() - before,
        1,
        "one learned_routes read for every contact"
    );
    // No match: nothing.
    assert_eq!(set(&gus, true), []);
    // 0x05 legacy match.
    assert_eq!(set(&hal, true), [(carol, offered)]);
    // A blocked custodian is never used, offer or not.
    assert_eq!(set(&ivy, true), [(carol, offered)]);
    // Review nearby-7: one read of everything for many contacts answers as
    // one lookup per contact does, with one learned_routes read in all.
    for live in [true, false] {
        let before = crate::learned_routes::loads_on_this_thread();
        let book = DepositBook::read(d, now(), live);
        let batch: Vec<_> = [bob, gus, hal, ivy, carol, dan, me]
            .iter()
            .map(|p| (*p, book.custodians(d, &me, p)))
            .collect();
        assert_eq!(
            crate::learned_routes::loads_on_this_thread() - before,
            usize::from(live)
        );
        for (p, got) in batch {
            assert_eq!(got, set(&p, live), "{} live={live}", hex::encode(p));
        }
    }
    // Hints off, or consent unset or off: the static list only.
    assert_eq!(set(&bob, false), [(dan, None)]);
    uses_friends(d, None, &[]);
    assert_eq!(set(&bob, true), [(dan, None)]);
    assert_eq!(set(&hal, true), []);
    uses_friends(d, Some(false), &[]);
    assert_eq!(set(&bob, true), [(dan, None)]);
    // Carol withdraws her offer: a match without an offer is skipped.
    uses_friends(d, Some(true), &[]);
    let mut gone = hints(2);
    gone.custody_offer = None;
    told(d, &carol, OutboxCarrier::Lan, None, &gone);
    assert_eq!(set(&bob, true), [(dan, None)]);
    assert_eq!(set(&ivy, true), []);
    // Unblocking Fay makes her usable.
    std::fs::remove_file(crate::chat_history::blocked_path(d)).unwrap();
    assert_eq!(set(&ivy, true), [(fay, Some(OFFER_WAN))]);
    // The public reader agrees with the gated one while learned custody
    // is closed in this build.
    if !crate::custody_gate::custody_hints_live() {
        assert_eq!(deposit_custodians(d, &me, &bob, now()), [(dan, None)]);
    }
}

/// [`deposit_custodians_with`] as it was before Phase 6a split it (P6.16):
/// the reference the split must equal byte for byte.
fn deposit_custodians_before_p6_16(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
    hints_live: bool,
) -> Vec<([u8; 32], Option<u8>)> {
    let mut out: Vec<([u8; 32], Option<u8>)> = Vec::new();
    if hints_live && consent(data_dir) {
        let learned = crate::learned_routes::learned_custody_all(data_dir, now_ms);
        if let Some(told) = learned.get(peer) {
            for c in crate::outbox::pinned_unblocked_contacts(data_dir).unwrap_or_default() {
                if out.len() == MAX_CUSTODIANS_PER_CONTACT {
                    break;
                }
                if c == *peer || c == *local {
                    continue;
                }
                let named = told
                    .tags
                    .contains(&crate::route_hints::custodian_tag(peer, local, &c))
                    || told.plain.contains(&c);
                let offer = learned.get(&c).and_then(|o| o.offer);
                if named && offer.is_some() {
                    out.push((c, offer));
                }
            }
        }
    }
    for c in listed_custodians(data_dir, peer, local).unwrap_or_default() {
        if out.len() < MAX_CUSTODIANS_PER_CONTACT
            && !out.iter().any(|(k, _)| *k == c)
            && custodian_usable(data_dir, &c, peer, local)
        {
            out.push((c, None));
        }
    }
    out
}

/// A book for the candidate tests: me; Bob, whose announcement names
/// 0x20 and 0x23 by tag and 0x24 and 0x21 by Phase 2's plain keys (RRH1
/// carries at most two of each), of the friends 0x20..0x29 in the book
/// (all offer custody except 0x23; 0x24 is blocked, 0x25 unverified), and
/// for whom I listed 0x27 and 0x30 (0x30 unverified); Carol, who announced
/// 0x21 only and for whom I listed 0x22 and 0x21; Dan, who announced
/// nothing and for whom I listed 0x31 and 0x32. Learned custody is read
/// through the gate argument.
fn candidate_book(d: &Path) -> ([u8; 32], [[u8; 32]; 3]) {
    use crate::custody_gate::OFFER_WAN;
    use crate::route_hints::custodian_tag;
    let (me, bob, carol, dan) = (k(0x01), k(0xB0), k(0xC0), k(0xD0));
    let friends: Vec<[u8; 32]> = (0x20..0x2A).map(k).collect();
    let bob_listed = [k(0x27), k(0x30)];
    let carol_listed = [k(0x22), k(0x21)];
    let dan_listed = [k(0x31), k(0x32)];
    let mut rows: Vec<BookRow<'_>> = vec![
        (bob, true, &bob_listed[..]),
        (carol, true, &carol_listed[..]),
        (dan, true, &dan_listed[..]),
        (k(0x30), false, &[][..]),
        (k(0x31), true, &[][..]),
        (k(0x32), true, &[][..]),
    ];
    for f in &friends {
        rows.push((*f, *f != k(0x25), &[][..]));
    }
    book(d, &rows);
    let mut blocks = crate::chat_history::BlockList::default();
    blocks.block(&hex::encode(k(0x24)));
    blocks.save(d).unwrap();
    let mut v = hints(1);
    v.custodian_tags = vec![
        custodian_tag(&bob, &me, &k(0x20)),
        custodian_tag(&bob, &me, &k(0x23)),
    ];
    v.custodian_tag_flags = vec![0, 0];
    v.custodians = vec![k(0x24), k(0x21)];
    told(d, &bob, OutboxCarrier::Lan, None, &v);
    told_tags(d, &carol, &[custodian_tag(&carol, &me, &k(0x21))]);
    for f in friends.iter().filter(|f| **f != k(0x23)) {
        told_offer(d, f, OFFER_WAN);
    }
    (me, [bob, carol, dan])
}

/// P6.16: the first [`MAX_CUSTODIANS_PER_CONTACT`] candidates are exactly
/// the deposit set of before the split, for every contact, with learned
/// custody live or not and the consent on, unset or off; the candidates
/// extend it (at most [`MAX_CUSTODIAN_CANDIDATES`]).
#[test]
fn candidates_then_cap_equals_todays_deposit_custodians() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (me, peers) = candidate_book(d);
    let mut seen_more = false;
    for consent in [Some(true), None, Some(false)] {
        uses_friends(d, consent, &[]);
        for live in [true, false] {
            for peer in &peers {
                let before = deposit_custodians_before_p6_16(d, &me, peer, now(), live);
                let cands = custodian_candidates_with(d, &me, peer, now(), live);
                assert_eq!(deposit_custodians_with(d, &me, peer, now(), live), before);
                assert!(cands.len() <= MAX_CUSTODIAN_CANDIDATES, "{cands:?}");
                assert_eq!(cands[..before.len()], before[..]);
                if before.len() < MAX_CUSTODIANS_PER_CONTACT {
                    assert_eq!(cands.len(), before.len(), "nothing more to find");
                }
                seen_more |= cands.len() > before.len();
            }
        }
    }
    assert!(seen_more, "Bob's friends give more candidates than two");
    // Bob, consent on, live: the two announced friends that are usable and
    // offer (0x23 offers nothing, 0x24 is blocked) in book order, then the
    // listed 0x27 (0x30 is unverified).
    uses_friends(d, Some(true), &[]);
    let bob = custodian_candidates_with(d, &me, &peers[0], now(), true);
    let keys: Vec<[u8; 32]> = bob.iter().map(|(c, _)| *c).collect();
    assert_eq!(keys, [k(0x20), k(0x21), k(0x27)]);
    // The public readers are the gated ones.
    let live = crate::custody_gate::custody_hints_live();
    for peer in &peers {
        assert_eq!(
            custodian_candidates(d, &me, peer, now()),
            custodian_candidates_with(d, &me, peer, now(), live)
        );
        assert_eq!(
            deposit_custodians(d, &me, peer, now()),
            deposit_custodians_with(d, &me, peer, now(), live)
        );
    }
    // The batch reader (a nearby encounter, carry choice live) answers as
    // the one-contact one does.
    let each: Vec<_> = peers
        .iter()
        .map(|p| custodian_candidates(d, &me, p, now()))
        .collect();
    assert_eq!(custodian_candidates_for(d, &me, &peers, now()), each);
}

/// P6.16: every candidate is usable ([`custodian_usable`]: a verified,
/// unblocked contact, never the peer or this node), named once; an
/// announced one carries its offer and a listed one none; the most RRH1
/// and the book can name stays within [`MAX_CUSTODIAN_CANDIDATES`].
#[test]
fn candidates_are_usable_only() {
    use crate::custody_gate::OFFER_WAN;
    use crate::route_hints::custodian_tag;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (me, peers) = candidate_book(d);
    for consent in [Some(true), None] {
        uses_friends(d, consent, &[]);
        for live in [true, false] {
            for peer in &peers {
                let cands = custodian_candidates_with(d, &me, peer, now(), live);
                for (i, (c, offer)) in cands.iter().enumerate() {
                    assert!(custodian_usable(d, c, peer, &me), "{i}");
                    assert!(c != peer && *c != me);
                    assert!(!cands[..i].iter().any(|(k, _)| k == c), "named once");
                    let listed = listed_custodians(d, peer, &me).unwrap();
                    assert!(offer.is_some() || listed.contains(c), "{i}");
                }
                for bad in [k(0x23), k(0x24), k(0x25), k(0x30)] {
                    assert!(!cands.iter().any(|(c, _)| *c == bad));
                }
            }
        }
    }
    // Everything RRH1 can name (two tags, two plain keys) and two listed,
    // all usable and distinct: six candidates, within the bound.
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (bob, many): ([u8; 32], Vec<[u8; 32]>) = (k(0xB0), (0x40..0x46).map(k).collect());
    let listed = [many[4], many[5]];
    let mut rows: Vec<BookRow<'_>> = vec![(bob, true, &listed[..])];
    rows.extend(many.iter().map(|f| (*f, true, &[][..])));
    book(d, &rows);
    let mut v = hints(1);
    v.custodian_tags = vec![
        custodian_tag(&bob, &me, &many[0]),
        custodian_tag(&bob, &me, &many[1]),
    ];
    v.custodian_tag_flags = vec![0, 0];
    v.custodians = vec![many[2], many[3]];
    told(d, &bob, OutboxCarrier::Lan, None, &v);
    for f in &many[..4] {
        told_offer(d, f, OFFER_WAN);
    }
    uses_friends(d, Some(true), &[]);
    let cands = custodian_candidates_with(d, &me, &bob, now(), true);
    let keys: Vec<[u8; 32]> = cands.iter().map(|(c, _)| *c).collect();
    assert_eq!(keys, many, "announced in book order, then listed");
    assert!(cands[..4].iter().all(|(_, o)| *o == Some(OFFER_WAN)));
    assert!(cands[4..].iter().all(|(_, o)| o.is_none()));
    assert!(cands.len() <= MAX_CUSTODIAN_CANDIDATES);
    assert_eq!(
        deposit_custodians_with(d, &me, &bob, now(), true),
        cands[..MAX_CUSTODIANS_PER_CONTACT]
    );
}

#[test]
fn fetch_targets_home_custodians_get_every_pinned_contact_and_static_map_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (me, bob, carol, dan, eve) = (k(0x01), k(0xB0), k(0xC0), k(0xD0), k(0xE0));
    book(
        d,
        &[
            (bob, true, &[dan]),
            (carol, true, &[]),
            (dan, true, &[]),
            (eve, false, &[]),
        ],
    );
    let targets = |live: bool| fetch_targets_with(d, &me, now(), live).unwrap();
    let static_map = vec![(dan, vec![bob])];
    uses_friends(d, Some(true), &[carol]);
    // Carol (home) is asked for every verified contact but herself; Eve is
    // not verified. Dan's static entry is as before.
    assert_eq!(targets(true), [(carol, vec![bob, dan]), (dan, vec![bob])]);
    // Learned custody closed: the static map, unchanged.
    assert_eq!(targets(false), static_map);
    // A home custodian that is also a static one keeps its static peers
    // first.
    uses_friends(d, Some(true), &[dan]);
    assert_eq!(targets(true), [(dan, vec![bob, carol])]);
    // No consent and nothing draining: the static map.
    uses_friends(d, None, &[carol]);
    assert_eq!(targets(true), static_map);
    // An unreadable book: an error, as before.
    uses_friends(d, Some(true), &[carol]);
    std::fs::write(d.join("contacts.json"), b"[{").unwrap();
    assert!(fetch_targets_with(d, &me, now(), true).is_err());
    assert!(fetch_targets_with(d, &me, now(), false).is_err());
}

/// P5.14: a custodian a pinned contact announced to this node (where that
/// contact leaves mail for it: its tags, or Phase 2's plain keys) is a
/// fetch target for that contact while learned custody is live, though
/// this node listed nobody for it and holds no session with it; only a
/// verified, unblocked contact here, never the contact itself or this node.
#[test]
fn fetch_targets_include_custodians_a_contact_announced_without_a_session() {
    use crate::route_hints::custodian_tag;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (me, bob, carol, dan, eve, hal) = (k(0x01), k(0xB0), k(0xC0), k(0xD0), k(0xE0), k(0x70));
    book(
        d,
        &[
            (bob, true, &[]),
            (carol, true, &[]),
            (dan, true, &[]),
            (eve, false, &[]),
            (hal, true, &[]),
        ],
    );
    // Bob names Carol, Eve (not verified here), himself and me; Hal names
    // Dan with a plain key.
    told_tags(
        d,
        &bob,
        &[
            custodian_tag(&bob, &me, &carol),
            custodian_tag(&bob, &me, &eve),
            custodian_tag(&bob, &me, &bob),
            custodian_tag(&bob, &me, &me),
        ],
    );
    let mut legacy = hints(1);
    legacy.custodians = vec![dan];
    told(d, &hal, OutboxCarrier::Lan, None, &legacy);
    // Carol and Dan hold mail for this node too (review handoff-5: a
    // custodian a contact names is fetched from only then).
    told_offer(d, &carol, 0);
    told_offer(d, &dan, 0);
    let targets = |live: bool| fetch_targets_with(d, &me, now(), live).unwrap();
    assert_eq!(targets(true), [(carol, vec![bob]), (dan, vec![hal])]);
    assert!(IndexedSessionStore::open(d)
        .unwrap()
        .list_record_keys()
        .unwrap()
        .is_empty());
    // No consent needed (it is where others leave mail for this node), but
    // learned custody must be live.
    uses_friends(d, Some(false), &[]);
    assert_eq!(targets(true), [(carol, vec![bob]), (dan, vec![hal])]);
    assert!(targets(false).is_empty());
    // Carol blocked: no longer a target.
    let mut blocks = crate::chat_history::BlockList::default();
    blocks.block(&hex::encode(carol));
    blocks.save(d).unwrap();
    assert_eq!(targets(true), [(dan, vec![hal])]);
}

/// Review handoff-5: a custodian a contact named (its mail friend, say,
/// which this node pins only to name it as a custody handoff's next hop)
/// that offers this node no custody of its own is no fetch target: it does
/// not take this node, and every dial would show it this node's identity.
/// It is one once it offers custody to this node (its own snapshot), or
/// while this node lists it for that contact itself.
#[test]
fn fetch_targets_skip_a_named_custodian_that_offers_this_node_nothing() {
    use crate::route_hints::custodian_tag;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let (me, bob, carol, gina) = (k(0x01), k(0xB0), k(0xC0), k(0xF6));
    book(
        d,
        &[(bob, true, &[]), (carol, true, &[]), (gina, true, &[])],
    );
    told_tags(
        d,
        &bob,
        &[
            custodian_tag(&bob, &me, &carol),
            custodian_tag(&bob, &me, &gina),
        ],
    );
    told_offer(d, &carol, 0);
    let targets = || fetch_targets_with(d, &me, now(), true).unwrap();
    assert_eq!(targets(), [(carol, vec![bob])]);
    // Listed for Bob by this node: a target as before.
    book(
        d,
        &[(bob, true, &[gina]), (carol, true, &[]), (gina, true, &[])],
    );
    assert_eq!(targets(), [(carol, vec![bob]), (gina, vec![bob])]);
    // Not listed, but Gina offers this node custody now.
    book(
        d,
        &[(bob, true, &[]), (carol, true, &[]), (gina, true, &[])],
    );
    told_offer(d, &gina, 0);
    assert_eq!(targets(), [(carol, vec![bob]), (gina, vec![bob])]);
}

fn pid(seed: u8) -> String {
    crate::p2p_route::local_peer_id(&Identity::from_seed(&[seed; 32]))
}

const ALL_CARRIERS: crate::outbox::CarrierGates = crate::outbox::CarrierGates {
    lan: true,
    internet: true,
    p2p: true,
    nearby: false,
    onion: false,
};

const HINTS_LIVE: crate::outbox::LearnedGates = crate::outbox::LearnedGates {
    hints: true,
    default_port: false,
    inet: false,
};

fn custody(wan: bool) -> CustodyGates {
    CustodyGates { live: true, wan }
}

/// The carriers of [`custodian_routes_with`]' plan.
fn carriers(
    d: &Path,
    custodian: &[u8; 32],
    offer: Option<u8>,
    gates: crate::outbox::CarrierGates,
    wan: bool,
) -> Vec<OutboxCarrier> {
    custodian_routes_with(
        d,
        custodian,
        offer,
        &[],
        gates,
        custody(wan),
        HINTS_LIVE,
        |_| true,
        false,
    )
    .into_iter()
    .map(|(planned, _)| planned.carrier)
    .collect()
}

/// A custodian known only by its route hints (no PeerId in the book) gets
/// the p2p route they name, dialled only while WAN custody is live.
#[test]
fn custodian_routes_uses_learned_p2p_route() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let carol = k(0xC0);
    book(d, &[(carol, true, &[])]);
    let peer_id = pid(0x51);
    let mut v = hints(3);
    v.peer_id = Some(peer_id.clone());
    v.relays =
        vec![
            crate::p2p_route::parse_via(&format!("/ip4/11.0.2.1/tcp/7423/p2p/{}", pid(0x61)))
                .unwrap(),
        ];
    told(d, &carol, OutboxCarrier::P2p, Some(&peer_id), &v);
    let routes = custodian_routes_with(
        d,
        &carol,
        None,
        &[],
        ALL_CARRIERS,
        custody(true),
        HINTS_LIVE,
        |_| true,
        false,
    );
    assert!(
        routes
            .iter()
            .any(|(planned, _)| planned.carrier == OutboxCarrier::P2p
                && planned.dial == crate::p2p_route::peer_route(&peer_id)),
        "{routes:?}"
    );
    assert_eq!(
        carriers(d, &carol, None, ALL_CARRIERS, false),
        [OutboxCarrier::Lan],
        "WAN custody off: no p2p route"
    );
    let p2p_off = crate::outbox::CarrierGates {
        p2p: false,
        ..ALL_CARRIERS
    };
    assert_eq!(
        carriers(d, &carol, None, p2p_off, true),
        [OutboxCarrier::Lan],
        "the p2p carrier gate off: no p2p route"
    );
}

/// A custodian whose offer has no WAN bit serves custody on LAN links only:
/// its Internet and p2p routes are dropped. No offer known: nothing dropped.
#[test]
fn offer_without_wan_bit_drops_wan_routes() {
    use crate::custody_gate::{OFFER_REACHABLE, OFFER_WAN};
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let carol = k(0xC0);
    let peer_id = pid(0x52);
    std::fs::write(
        d.join("contacts.json"),
        format!(
            r#"[{{"pub_hex":"{}","pinned":true,"lan_dial":"192.168.1.9:7420","internet_dial":"203.0.113.7:7422","p2p":"{peer_id}"}}]"#,
            hex::encode(carol)
        ),
    )
    .unwrap();
    let all = [
        OutboxCarrier::Lan,
        OutboxCarrier::Internet,
        OutboxCarrier::P2p,
    ];
    assert_eq!(carriers(d, &carol, None, ALL_CARRIERS, true), all);
    assert_eq!(
        carriers(d, &carol, Some(OFFER_WAN), ALL_CARRIERS, true),
        all
    );
    assert_eq!(
        carriers(
            d,
            &carol,
            Some(OFFER_WAN | OFFER_REACHABLE),
            ALL_CARRIERS,
            true
        ),
        all
    );
    for lan_only in [0, OFFER_REACHABLE] {
        assert_eq!(
            carriers(d, &carol, Some(lan_only), ALL_CARRIERS, true),
            [OutboxCarrier::Lan],
            "offer {lan_only:#04x}"
        );
    }
}

/// The LAN beacon's finds lead the LAN routes (the learned LAN routes are
/// then left out, as for a contact); with the LAN carrier closed (`raven
/// lan off`) no LAN route is planned at all, finds included.
#[test]
fn extra_lan_candidates_go_first_and_lan_off_drops_them() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let carol = k(0xC0);
    book(d, &[(carol, true, &[])]);
    crate::lan_seen::record_contact_seen(d, &carol, "192.168.1.20".parse().unwrap(), None, now())
        .unwrap();
    let dials = |extra: &[&str], gates: crate::outbox::CarrierGates| -> Vec<String> {
        let extra: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
        custodian_routes_with(
            d,
            &carol,
            None,
            &extra,
            gates,
            custody(false),
            HINTS_LIVE,
            |_| true,
            false,
        )
        .into_iter()
        .map(|(_, dialled)| dialled.dial)
        .collect()
    };
    assert_eq!(
        dials(&[], ALL_CARRIERS),
        ["192.168.1.9:7420", "192.168.1.20:7420"],
        "no finds: saved, then learned"
    );
    assert_eq!(
        dials(
            &["192.168.1.40:7533", "203.0.113.9:7420", "name:1"],
            ALL_CARRIERS
        ),
        ["192.168.1.40:7533", "192.168.1.9:7420"],
        "a local find first, the learned one left out, a public one or a name never"
    );
    let lan_off = crate::outbox::CarrierGates {
        lan: false,
        ..ALL_CARRIERS
    };
    assert!(dials(&["192.168.1.40:7533"], lan_off).is_empty());
    assert!(dials(&[], lan_off).is_empty());
}

#[test]
fn deposit_chunks_respect_16_frames_and_512_kib() {
    const KIB: usize = 1024;
    assert!(deposit_chunks(&[]).is_empty());
    assert_eq!(deposit_chunks(&[60 * KIB; 12]), [0..8, 8..12]);
    let lone = deposit_chunks(&[600 * KIB]);
    assert_eq!((lone.len(), lone[0].clone()), (1, 0..1));
    assert_eq!(
        deposit_chunks(&[10 * KIB, 600 * KIB, 10 * KIB]),
        [0..1, 1..2, 2..3],
        "a lone larger object gets a dial of its own"
    );
    assert_eq!(deposit_chunks(&[KIB; 20]), [0..16, 16..20]);
    assert_eq!(
        deposit_chunks(&[256 * KIB, 256 * KIB, 1]),
        [0..2, 2..3],
        "exactly 512 KiB fits"
    );
    // Every object once, in order, within both budgets.
    let sizes: Vec<usize> = (0..100).map(|i| (i * 7919 % 97) * KIB).collect();
    let chunks = deposit_chunks(&sizes);
    assert_eq!(chunks.first().unwrap().start, 0);
    assert_eq!(chunks.last().unwrap().end, sizes.len());
    for pair in chunks.windows(2) {
        assert_eq!(pair[0].end, pair[1].start);
    }
    for c in &chunks {
        assert!(c.len() <= MAX_DEPOSITS_PER_DIAL);
        let bytes: usize = sizes[c.clone()].iter().sum();
        assert!(c.len() == 1 || bytes <= MAX_DEPOSIT_BYTES_PER_DIAL);
    }
}

/// `n` distinct tags, sorted, each with a placeholder hint (a fake custodian
/// never returns an item, so nothing is ingested).
fn fake_tags(n: usize) -> BTreeMap<[u8; 16], RelayHint> {
    (0..n)
        .map(|i| {
            let mut tag = [0u8; 16];
            tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let hint = RelayHint {
                record_key: IndexedSessionRecordKey {
                    profile_id: Vec::new(),
                    initiator_address: String::new(),
                    responder_address: String::new(),
                    initiator_device_ed25519: [0; 32],
                    responder_device_ed25519: [0; 32],
                    init_id: [0; 16],
                },
                peer_device: [0; 32],
                store_tag: tag,
            };
            (tag, hint)
        })
        .collect()
}

/// A custodian that answers every FETCH with no item, ending the chunk
/// (`more: false`) or not (`more: true`), and records each chunk's first tag.
fn empty_custodian(
    seen: &mut Vec<[u8; 16]>,
    more: bool,
) -> impl FnMut(&[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> + '_ {
    use crate::friend_custody::{decode_request, encode_reply, RequestDecode};
    move |frames: &[Vec<u8>]| {
        let mut out = Vec::new();
        for f in frames {
            let Ok(RequestDecode::Request(id, request)) = decode_request(f) else {
                return Err("bad frame".into());
            };
            let reply = match request {
                Rfc1Request::Fetch { tags, .. } => {
                    seen.push(tags[0]);
                    Rfc1Reply::FetchEnd {
                        code: CustodyCode::Ok,
                        returned: 0,
                        next: more.then_some([0x5A; 32]),
                    }
                }
                Rfc1Request::Release { .. } => Rfc1Reply::ReleaseResult {
                    code: CustodyCode::Ok,
                    released: 0,
                },
                _ => return Err("not a fetch".into()),
            };
            out.push(encode_reply(&id, &reply));
        }
        Ok(out)
    }
}

/// More than eight chunks: the next trigger starts where the last one
/// stopped, so 10 chunks (320 tags) are all asked for in two triggers (the
/// old walk always restarted at chunk 0 and never reached chunks 8 and 9).
#[test]
fn fetch_round_rotation_visits_all_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let me = Identity::from_seed(&[0x44; 32]);
    let tags = fake_tags(320);
    let firsts: Vec<[u8; 16]> = tags.keys().step_by(MAX_FETCH_TAGS).copied().collect();
    assert_eq!(firsts.len(), 10);
    let mut state = FetchState::default();
    let mut seen = Vec::new();
    let first = fetch_round(
        dir.path(),
        &me,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut empty_custodian(&mut seen, false),
    );
    assert_eq!(first.dials, MAX_PAGES_PER_TRIGGER);
    assert_eq!(seen, firsts[..8]);
    assert_eq!(state.next_chunk, 8);
    seen.clear();
    let second = fetch_round(
        dir.path(),
        &me,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut empty_custodian(&mut seen, false),
    );
    assert_eq!(second.dials, MAX_PAGES_PER_TRIGGER);
    let want: Vec<[u8; 16]> = [8, 9, 0, 1, 2, 3, 4, 5]
        .iter()
        .map(|&i| firsts[i])
        .collect();
    assert_eq!(seen, want, "8, 9, then from the start");
    assert_eq!(state.next_chunk, 6);
    // Fewer chunks than the budget: all of them, and the next trigger starts
    // where this one did.
    let few = fake_tags(70);
    let mut small = FetchState {
        next_chunk: 2,
        ..FetchState::default()
    };
    seen.clear();
    let report = fetch_round(
        dir.path(),
        &me,
        &few,
        &mut small,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut empty_custodian(&mut seen, false),
    );
    assert_eq!(report.dials, 3);
    let few_firsts: Vec<[u8; 16]> = few.keys().step_by(MAX_FETCH_TAGS).copied().collect();
    assert_eq!(seen, [few_firsts[2], few_firsts[0], few_firsts[1]]);
    assert_eq!(small.next_chunk, 2);
}

/// A relayed custodian gets at most four pages a trigger; a chunk that
/// still has more stays first for the next trigger.
#[test]
fn relayed_budget_caps_pages_at_four() {
    let dir = tempfile::tempdir().unwrap();
    let me = Identity::from_seed(&[0x45; 32]);
    let tags = fake_tags(320);
    let mut seen = Vec::new();
    let mut state = FetchState::default();
    let relayed = fetch_round(
        dir.path(),
        &me,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER_RELAYED,
        &mut empty_custodian(&mut seen, true),
    );
    assert_eq!(relayed.dials, 4);
    assert_eq!(seen.len(), 4);
    assert_eq!(state.next_chunk, 0, "chunk 0 has more pages");
    assert_eq!(state.cursors.len(), 1);
    let mut direct = FetchState::default();
    let report = fetch_round(
        dir.path(),
        &me,
        &tags,
        &mut direct,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut empty_custodian(&mut seen, true),
    );
    assert_eq!(report.dials, 8);
}

/// A dial that dies after the custodian took its frames (the reply lost):
/// the digests to release stay pending, the cursor stays where it was, and
/// the next trigger takes the lost page again; every message arrives once
/// and the custodian ends up holding nothing.
#[test]
fn a_dial_that_dies_mid_fetch_loses_nothing() {
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: true,
        wan: false,
    }));
    let w = world(0xA1);
    let packed: Vec<Vec<u8>> = (0..20).map(|i| w.seal(&format!("note {i}"))).collect();
    let items: Vec<DepositItem> = packed
        .iter()
        .map(|p| {
            let tag = IndexedSessionStore::open(w.a.path())
                .unwrap()
                .outbound_store_tag_for_object(&w.key, p, now())
                .unwrap();
            DepositItem {
                recipient: w.bob.public_key_bytes(),
                rso1: rfc1_rso1(tag, p).unwrap(),
            }
        })
        .collect();
    for range in deposit_chunks(&vec![1; items.len()]) {
        let answers = deposit_batch(&items[range], &mut w.carol_dial(&w.alice)).unwrap();
        assert!(answers.iter().all(|a| *a == Some(CustodyCode::Ok)));
    }
    let tags = inbound_tags(w.b.path(), &w.bob, &[w.alice.public_key_bytes()], now()).unwrap();
    let mut state = FetchState::default();
    // The first dial goes through; the second reaches Carol, and its reply
    // is lost.
    let mut calls = 0;
    let mut carol = w.carol_dial(&w.bob);
    let mut dying = |frames: &[Vec<u8>]| {
        calls += 1;
        let replies = carol(frames)?;
        if calls == 1 {
            Ok(replies)
        } else {
            Err("connection reset".to_string())
        }
    };
    let first = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut dying,
    );
    assert_eq!(first.accepted_messages, 16, "{first:?}");
    assert_eq!(first.dials, 2);
    assert_eq!(state.pending_release.len(), 16, "kept for the next dial");
    assert_eq!(state.cursors.len(), 1, "the page after the first");
    let second = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut w.carol_dial(&w.bob),
    );
    assert_eq!(second.accepted_messages, 4, "{second:?}");
    assert!(state.pending_release.is_empty());
    assert!(state.cursors.is_empty());
    let inbox = IndexedSessionStore::open(w.b.path())
        .unwrap()
        .list_endpoint_inbox()
        .unwrap();
    assert_eq!(inbox.len(), 20);
    let quiet = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut state,
        now(),
        MAX_PAGES_PER_TRIGGER,
        &mut w.carol_dial(&w.bob),
    );
    assert_eq!(quiet.items, 0, "Carol holds nothing more");
    set_custody_gates_for_this_thread(None);
}

/// Tags already derived come from the cache: a second round needs no
/// protected session load, and gives the same tags; a session no longer
/// live leaves the cache.
#[test]
fn tag_cache_hit_needs_no_protected_load() {
    let w = world(0xB1);
    let alice = [w.alice.public_key_bytes()];
    let mut cache = TagCache::default();
    let first = inbound_tags_cached(w.b.path(), &w.bob, &alice, now(), &mut cache).unwrap();
    assert!(!first.is_empty());
    assert_eq!(cache.protected_loads(), 1);
    assert_eq!(cache.len(), first.len());
    let second = inbound_tags_cached(w.b.path(), &w.bob, &alice, now(), &mut cache).unwrap();
    assert_eq!(second, first);
    assert_eq!(cache.protected_loads(), 1, "a hit: no protected load");
    assert_eq!(
        inbound_tags(w.b.path(), &w.bob, &alice, now()).unwrap(),
        first,
        "the uncached reader agrees"
    );
    // Asked for nobody: no tags, and the live session's stay cached.
    assert!(
        inbound_tags_cached(w.b.path(), &w.bob, &[], now(), &mut cache)
            .unwrap()
            .is_empty()
    );
    assert_eq!(cache.len(), first.len());
    // Once the session has expired it is gone from the cache.
    let end = IndexedSessionStore::open(w.b.path())
        .unwrap()
        .session_expires_at(&w.key)
        .unwrap();
    let later = inbound_tags_cached(w.b.path(), &w.bob, &alice, end + 1, &mut cache).unwrap();
    assert!(later.is_empty());
    assert!(cache.is_empty());
    assert_eq!(cache.protected_loads(), 1);
}

/// Phase 6b P6.25 (S18): what a custodian does wrong lands in
/// [`FetchReport::misbehaviour`] (an item that does not decode, an object
/// under a tag this round did not ask for, an object served again after its
/// RELEASE was answered OK), and the refusal of an object Alice signed in
/// [`FetchReport::sender_events`] about her. What is taken is taken as
/// before.
#[test]
fn a_custodians_misbehaviour_and_a_senders_bad_object_are_reported() {
    use crate::friend_custody::{decode_request, encode_reply, RequestDecode};
    let w = world(0x8C);
    let tag_of = |packed: &[u8]| {
        IndexedSessionStore::open(w.a.path())
            .unwrap()
            .outbound_store_tag_for_object(&w.key, packed, now())
            .unwrap()
    };
    // Sealed in the order the second page serves them (a page is taken in
    // the order its objects were written).
    let unasked = w.seal("under another tag");
    let first = w.seal("served twice");
    let tag = tag_of(&first);
    let mut other_tag = tag;
    other_tag[0] ^= 0xFF;
    let mut env = Envelope::unpack(&w.seal("changed")).unwrap();
    *env.message_ciphertext.last_mut().unwrap() ^= 1;
    env.sign_with(&w.alice);
    let tampered = env.pack();
    let tags = BTreeMap::from([(
        tag,
        RelayHint {
            record_key: w.key.clone(),
            peer_device: w.alice.public_key_bytes(),
            store_tag: tag,
        },
    )]);
    // Each FETCH answers the next page; a RELEASE is answered OK.
    let mut pages = vec![
        vec![rfc1_rso1(tag, &first).unwrap()],
        vec![
            b"not an RSO1".to_vec(),
            rfc1_rso1(other_tag, &unasked).unwrap(),
            rfc1_rso1(tag, &first).unwrap(),
            rfc1_rso1(tag, &tampered).unwrap(),
        ],
    ]
    .into_iter();
    let mut custodian = |frames: &[Vec<u8>]| -> Result<Vec<Vec<u8>>, String> {
        let mut out = Vec::new();
        for f in frames {
            let Ok(RequestDecode::Request(id, request)) = decode_request(f) else {
                return Err("bad frame".into());
            };
            match request {
                Rfc1Request::Fetch { .. } => {
                    let page = pages.next().unwrap_or_default();
                    let returned = page.len() as u8;
                    for rso1 in page {
                        out.push(encode_reply(&id, &Rfc1Reply::FetchItem { rso1 }));
                    }
                    out.push(encode_reply(
                        &id,
                        &Rfc1Reply::FetchEnd {
                            code: CustodyCode::Ok,
                            returned,
                            next: None,
                        },
                    ));
                }
                Rfc1Request::Release { digests } => out.push(encode_reply(
                    &id,
                    &Rfc1Reply::ReleaseResult {
                        code: CustodyCode::Ok,
                        released: digests.len() as u8,
                    },
                )),
                _ => return Err("not a fetch".into()),
            }
        }
        Ok(out)
    };
    let mut state = FetchState::default();
    let one = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut state,
        now(),
        1,
        &mut custodian,
    );
    assert_eq!(one.accepted_messages, 1);
    assert!(one.misbehaviour.is_empty() && one.sender_events.is_empty());
    assert_eq!(state.pending_release, vec![custody_digest(&first)]);
    // The next round releases it (answered OK), then gets it again with the
    // rest of the page.
    let two = fetch_round(
        w.b.path(),
        &w.bob,
        &tags,
        &mut state,
        now(),
        1,
        &mut custodian,
    );
    assert_eq!(state.released, vec![custody_digest(&first)]);
    assert_eq!(
        two.misbehaviour,
        vec![
            SecKind::CustodianBadObject,
            SecKind::CustodianUnrequested,
            SecKind::CustodianReplay,
        ]
    );
    assert_eq!(
        two.sender_events,
        vec![(w.alice.public_key_bytes(), SecKind::ObjectAuthFail)]
    );
    // Taken as before: the duplicate answered, the bad object refused.
    assert_eq!((two.accepted_messages, two.refused), (1, 1));
}

/// Phase 6b: the released digests a fetch state keeps are bounded.
#[test]
fn released_digests_are_bounded() {
    let mut released = Vec::new();
    for n in 0..(MAX_PENDING_RELEASES + 10) {
        let mut d = [0u8; 32];
        d[..8].copy_from_slice(&(n as u64).to_be_bytes());
        note_released(&mut released, &[d, d]);
    }
    assert_eq!(released.len(), MAX_PENDING_RELEASES);
    assert_eq!(released[0][..8], 10u64.to_be_bytes());
}

/// Custody over Tor (lab): a verified custodian's signed onion route comes
/// last while the Tor helper is ready and WAN custody is live; never under
/// a LAN-only custody offer, without WAN custody, with the onion carrier
/// closed or the helper not ready.
#[test]
fn custodian_routes_add_the_onion_route_last_for_wan_custody() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let carol = crate::identity::Identity::from_seed(&[0xC1; 32]);
    let carol_pub = carol.public_key_bytes();
    book(d, &[(carol_pub, true, &[])]);
    // Any Ed25519 public key is a usable onion key.
    let hs_id = crate::identity::Identity::from_seed(&[0x0e; 32]).public_key_bytes();
    let binding = crate::onion::OnionBinding::sign(&carol, hs_id, crate::onion::now_s());
    assert!(crate::onion::store_contact_binding(d, &carol_pub, &binding).unwrap());
    let tor = crate::outbox::CarrierGates {
        onion: true,
        ..ALL_CARRIERS
    };
    let plan = |offer: Option<u8>, gates, wan: bool, ready: bool| {
        custodian_routes_with(
            d,
            &carol_pub,
            offer,
            &[],
            gates,
            custody(wan),
            HINTS_LIVE,
            |_| true,
            ready,
        )
        .into_iter()
        .map(|(planned, _)| planned)
        .collect::<Vec<_>>()
    };
    let routes = plan(None, tor, true, true);
    let last = routes.last().expect("routes");
    assert_eq!(last.carrier, OutboxCarrier::Onion, "{routes:?}");
    assert_eq!(last.dial, crate::onion::dial_for(&hs_id));
    assert_eq!(routes[0].carrier, OutboxCarrier::Lan, "{routes:?}");
    let no_onion = |routes: Vec<crate::outbox::OutboxRoute>| {
        routes.iter().all(|r| r.carrier != OutboxCarrier::Onion)
    };
    assert!(no_onion(plan(None, tor, true, false)), "helper not ready");
    assert!(
        no_onion(plan(None, ALL_CARRIERS, true, true)),
        "carrier closed"
    );
    assert!(no_onion(plan(None, tor, false, true)), "no WAN custody");
    assert!(no_onion(plan(Some(0), tor, true, true)), "LAN-only offer");
}
