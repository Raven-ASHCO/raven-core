use super::*;
use crate::p2p_route::{active_peer_id, libp2p_ed25519_public, local_peer_id, parse_peer_id};

const L: u64 = DEFAULT_EPOCH_S;
const DAY_MS: u64 = 86_400_000;

fn id(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn vector(name: &str) -> serde_json::Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../shared-vectors/rvn1/p2p")
        .join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap()
}

fn seed_of(v: &serde_json::Value) -> Identity {
    let seed: [u8; 32] = hex::decode(v.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    Identity::from_seed(&seed)
}

fn u(v: &serde_json::Value) -> u64 {
    v.as_u64().unwrap()
}

/// `shared-vectors/rvn1/p2p/epoch_peer_id_001.json`, written by the
/// independent Python reference (`generate_peer_rotation.py`): the epoch
/// seeds, keys and PeerIds, the legacy PeerId and the announced schedule.
#[test]
fn epoch_peer_id_matches_shared_vectors() {
    let v = vector("epoch_peer_id_001.json");
    let me = seed_of(&v["inputs"]["raven_seed_hex"]);
    let x = &v["expected"];
    assert_eq!(local_peer_id(&me), x["legacy_peer_id"]);
    assert_eq!(
        hex::encode(*crate::p2p_route::libp2p_ed25519_seed(&me)),
        x["legacy_seed_hex"]
    );
    let cases = x["epochs"].as_array().unwrap();
    assert!(cases.iter().any(|c| u(&c["epoch"]) == 1 << 40));
    for case in cases {
        let e = u(&case["epoch"]);
        assert_eq!(hex::encode(*epoch_seed(&me, e)), case["epoch_seed_hex"]);
        assert_eq!(
            hex::encode(epoch_public(&me, e)),
            case["ed25519_public_hex"]
        );
        assert_eq!(epoch_peer_id(&me, e), case["peer_id"]);
        assert_eq!(active_peer_id(&me, Some(e)), case["peer_id"]);
        assert_eq!(
            parse_peer_id(case["peer_id"].as_str().unwrap()).unwrap(),
            epoch_public(&me, e)
        );
    }
    let active = u(&v["inputs"]["schedule_active"]);
    let want: Vec<(u64, String)> = x["own_schedule"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                u(&c["epoch"]),
                c["ed25519_public_hex"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let got: Vec<(u64, String)> = own_schedule(&me, active)
        .into_iter()
        .map(|(e, key)| (e, hex::encode(key)))
        .collect();
    assert_eq!(got, want);
    let at_0: Vec<u64> = serde_json::from_value(x["own_schedule_at_0"].clone()).unwrap();
    assert_eq!(
        own_schedule(&me, 0)
            .iter()
            .map(|(e, _)| *e)
            .collect::<Vec<_>>(),
        at_0
    );
}

/// `epoch_phase_001.json`: the phase, the epoch and the next boundary of two
/// seeds at three lengths, and the rules around a boundary.
#[test]
fn epoch_phase_and_boundary_kat() {
    let v = vector("epoch_phase_001.json");
    assert_eq!(u(&v["inputs"]["default_epoch_s"]), DEFAULT_EPOCH_S);
    assert_eq!(DEFAULT_EPOCH_S, 2_419_200);
    let cases = v["expected"]["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let me = seed_of(&case["raven_seed_hex"]);
        let len = u(&case["epoch_len_s"]);
        assert_eq!(phase_s(&me, len), u(&case["phase_s"]));
        assert!(phase_s(&me, len) < len);
        for t in case["times"].as_array().unwrap() {
            let at = u(&t["unix_s"]);
            let e = epoch_at(&me, at, len);
            assert_eq!(e, u(&t["epoch"]), "{at}");
            let next = next_boundary_unix(&me, at, len);
            assert_eq!(next, u(&t["next_boundary_unix"]), "{at}");
            assert!(next > at && next - at <= len);
            assert_eq!(epoch_at(&me, next, len), e + 1);
            assert_eq!(epoch_at(&me, next - 1, len), e);
            // A relay's bound on the end of `e` (no phase known) is never
            // early, and late by less than one epoch.
            let bound = latest_epoch_end_ms(e, len);
            assert!(next * 1000 <= bound && bound - next * 1000 < len * 1000);
        }
    }
    // Two profiles do not rotate at the same moment, and a zero length
    // cannot divide by zero.
    assert_ne!(phase_s(&id(0x51), L), phase_s(&id(0x52), L));
    assert_eq!(phase_s(&id(0x51), 0), 0);
    assert_eq!(epoch_at(&id(0x51), 7, 0), 7);
    assert_eq!(epoch_at(&id(0x51), u64::MAX, L), u64::MAX / L);
    assert_eq!(latest_epoch_end_ms(u64::MAX, L), u64::MAX);
    assert_eq!(latest_epoch_end_ms(4, 0), 5_000);
    // The lab length is read only in a debug build with the lab unlock.
    if std::env::var_os("RAVEN_LAB_PEER_EPOCH_S").is_none() {
        assert_eq!(epoch_len_s(), DEFAULT_EPOCH_S);
    }
}

/// With rotation off the PeerId is the one every earlier raven derived, and
/// no epoch key equals it.
#[test]
fn legacy_key_is_unchanged_when_rotation_is_off() {
    for seed in [0x01, 0x51, 0xfe] {
        let me = id(seed);
        assert_eq!(local_peer_id(&me), active_peer_id(&me, None));
        assert_eq!(
            parse_peer_id(&active_peer_id(&me, None)).unwrap(),
            libp2p_ed25519_public(&me)
        );
        for e in [0, 1, 741, u64::MAX] {
            assert_ne!(active_peer_id(&me, Some(e)), local_peer_id(&me));
            assert_ne!(epoch_public(&me, e), libp2p_ed25519_public(&me));
        }
    }
    // The pinned legacy PeerId of seed 0x51 (route hint and card vectors).
    assert_eq!(
        active_peer_id(&id(0x51), None),
        vector("card_p2pn_001.json")["expected"]["legacy_peer_id"]
    );
}

#[test]
fn own_schedule_window_is_prev_plus_six() {
    let me = id(0x51);
    let s = own_schedule(&me, 741);
    assert_eq!(s.len(), MAX_SCHEDULE);
    assert_eq!(
        s.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
        (740..=747).collect::<Vec<_>>()
    );
    assert!(s.iter().all(|(e, key)| *key == epoch_public(&me, *e)));
    assert!(s.iter().all(|(_, key)| schedule_key_ok(key)));
    // At epoch 0 there is no previous one; at the end of time no 6 ahead.
    assert_eq!(own_schedule(&me, 0).len(), 7);
    assert_eq!(own_schedule(&me, u64::MAX).len(), 2);
    // A schedule it announces passes its own checks.
    let announced = ContactSchedule {
        capable: true,
        rotating: true,
        postponed: false,
        len_s: L as u32,
        active: 741,
        entries: s,
        received_ms: 0,
    };
    assert_eq!(announced.check(), Ok(()));
}

/// A contact (seed 0x61) rotating since epoch `active`, its schedule heard
/// at `received_s`.
fn contact_schedule(active: u64, received_s: u64) -> ContactSchedule {
    ContactSchedule {
        capable: true,
        rotating: true,
        postponed: false,
        len_s: L as u32,
        active,
        entries: own_schedule(&id(0x61), active),
        received_ms: received_s * 1000,
    }
}

fn bob(e: u64) -> String {
    epoch_peer_id(&id(0x61), e)
}

#[test]
fn admitted_peer_ids_and_dial_order_tables() {
    let card = local_peer_id(&id(0x61));
    let next = bob(11);
    let t0 = 1_000 * L;
    let fresh = contact_schedule(10, t0);
    let postponed = ContactSchedule {
        postponed: true,
        ..fresh.clone()
    };
    let not_rotating = ContactSchedule {
        rotating: false,
        entries: Vec::new(),
        ..fresh.clone()
    };
    // P4.28: about to rotate (the entries before the first switch).
    let starting = ContactSchedule {
        rotating: false,
        ..fresh.clone()
    };
    let p = |v: &[u64]| v.iter().map(|e| bob(*e)).collect::<Vec<_>>();
    let with_card = |rest: Vec<String>| [vec![card.clone()], rest].concat();
    // (why, schedule, now, admitted after the card's p2p=, dial order)
    type Row<'a> = (
        &'a str,
        Option<&'a ContactSchedule>,
        u64,
        Vec<String>,
        Vec<String>,
    );
    let rows: Vec<Row> = vec![
        (
            "no schedule: the card",
            None,
            t0,
            vec![],
            vec![card.clone()],
        ),
        (
            "capable, not rotating: the card",
            Some(&not_rotating),
            t0,
            vec![],
            vec![card.clone()],
        ),
        (
            "just heard: active, then the next epoch",
            Some(&fresh),
            t0,
            p(&[9, 10, 11, 12]),
            p(&[10, 11]),
        ),
        (
            "half an epoch later: the next epoch is likelier",
            Some(&fresh),
            t0 + L / 2,
            p(&[9, 10, 11, 12]),
            p(&[11, 10]),
        ),
        (
            "a boundary straddle 2.3 epochs later: 12 or 13",
            Some(&fresh),
            t0 + 2 * L + 3 * L / 10,
            p(&[10, 11, 12, 13, 14]),
            p(&[12, 13]),
        ),
        (
            "postponed: the likelier clock epoch, then the active one",
            Some(&postponed),
            t0 + 2 * L + 7 * L / 10,
            p(&[10, 11, 12, 13, 14]),
            p(&[13, 10]),
        ),
        (
            "near the end of the schedule: the last entry",
            Some(&fresh),
            t0 + 6 * L + 6 * L / 10,
            p(&[10, 15, 16]),
            p(&[16]),
        ),
        (
            "long past the schedule: the card",
            Some(&fresh),
            t0 + 9 * L,
            p(&[10]),
            vec![card.clone()],
        ),
        (
            "a clock behind the hint counts as just heard",
            Some(&fresh),
            t0 - L,
            p(&[9, 10, 11, 12]),
            p(&[10, 11]),
        ),
        (
            "about to rotate: admitted, but the card first, then the switch",
            Some(&starting),
            t0,
            p(&[9, 10, 11, 12]),
            with_card(p(&[11])),
        ),
        (
            "about to rotate, two epochs on: the card, then the clock epoch",
            Some(&starting),
            t0 + 2 * L + 7 * L / 10,
            p(&[10, 11, 12, 13, 14]),
            with_card(p(&[13])),
        ),
    ];
    for (why, s, now, admitted, dial) in rows {
        assert_eq!(
            admitted_peer_ids(Some(&card), None, s, now),
            with_card(admitted),
            "{why}"
        );
        assert_eq!(dial_peer_ids(&card, None, s, now), dial, "{why}");
    }
    // The card's p2pn= is admitted and dialled second; values that are no
    // PeerId are left out; nothing is repeated.
    assert_eq!(
        admitted_peer_ids(Some(&card), Some(&next), None, t0),
        [card.clone(), next.clone()]
    );
    assert_eq!(
        dial_peer_ids(&card, Some(&next), None, t0),
        [card.clone(), next.clone()]
    );
    assert_eq!(
        dial_peer_ids(&card, Some("not-a-peer-id"), None, t0),
        std::slice::from_ref(&card)
    );
    assert_eq!(
        admitted_peer_ids(Some("junk"), Some(&next), Some(&fresh), t0),
        [&next, &bob(9), &bob(10), &bob(12)].map(String::clone)
    );
    assert!(admitted_peer_ids(None, None, None, t0).is_empty());
    assert!(dial_peer_ids("junk", None, None, t0).is_empty());
    // At most 2 dialled; the schedule's keys win over the card.
    assert_eq!(dial_peer_ids(&card, Some(&next), Some(&fresh), t0).len(), 2);
    // An entry missing from the schedule is skipped, not invented.
    let gap = ContactSchedule {
        entries: fresh
            .entries
            .iter()
            .filter(|(e, _)| *e != 11)
            .cloned()
            .collect(),
        ..fresh.clone()
    };
    assert_eq!(dial_peer_ids(&card, None, Some(&gap), t0), p(&[10]));
    // Postponed and just heard: the active epoch is the likelier one, so
    // the next epoch comes second.
    assert_eq!(
        dial_peer_ids(&card, None, Some(&postponed), t0),
        p(&[10, 11])
    );
}

/// P4.28: this profile's own rotation progress round-trips, is written only
/// when it changes, holds no PeerId, and reads as not ready when missing.
#[test]
fn own_rotation_state_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    assert_eq!(load_own_rotation(dd).unwrap(), OwnRotation::default());
    let ready = OwnRotation {
        ready_ms: Some(1_800_000_000_000),
    };
    save_own_rotation(dd, ready).unwrap();
    assert_eq!(load_own_rotation(dd).unwrap(), ready);
    let raw = std::fs::read_to_string(dd.join(ROTATION_STATE_FILE)).unwrap();
    assert!(
        raw.contains("ready_ms") && raw.contains("1800000000000"),
        "{raw}"
    );
    assert!(!raw.contains("12D3"), "{raw}");
    let stamp = std::fs::metadata(dd.join(ROTATION_STATE_FILE))
        .unwrap()
        .modified()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    save_own_rotation(dd, ready).unwrap();
    assert_eq!(
        std::fs::metadata(dd.join(ROTATION_STATE_FILE))
            .unwrap()
            .modified()
            .unwrap(),
        stamp,
        "unchanged: not written"
    );
    save_own_rotation(dd, OwnRotation::default()).unwrap();
    assert_eq!(load_own_rotation(dd).unwrap(), OwnRotation::default());
    std::fs::write(dd.join(ROTATION_STATE_FILE), b"not json").unwrap();
    assert_eq!(load_own_rotation(dd).unwrap(), OwnRotation::default());
}

#[test]
fn peer_schedules_store_is_owner_only_bounded_and_prunes() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let key = |n: u32| format!("{:064x}", u64::from(n) | 0xab00_0000_0000);
    let t0 = 1_000 * L;
    assert!(load_schedules(dd).unwrap().is_empty());
    // A read and a forget take no lock and make no file.
    forget_schedule(dd, &key(1)).unwrap();
    assert_eq!(prune_schedules(dd, t0 * 1000).unwrap(), 0);
    assert_eq!(std::fs::read_dir(dd).unwrap().count(), 0);

    let s = contact_schedule(10, t0);
    save_schedule(dd, &key(1).to_uppercase(), &s).unwrap();
    assert!(dd.join(PEER_SCHEDULES_LOCK).exists());
    assert_eq!(
        crate::at_rest::rule_for(PEER_SCHEDULES_FILE).and_then(|r| r.lock),
        Some(PEER_SCHEDULES_LOCK)
    );
    let all = load_schedules(dd).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[&key(1)], s, "keyed by the lower-case contact key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dd.join(PEER_SCHEDULES_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "owner only");
    }
    // No PeerId and no secret on disk: epochs and public keys only.
    let raw = std::fs::read_to_string(dd.join(PEER_SCHEDULES_FILE)).unwrap();
    assert!(!raw.contains("12D3KooW"), "{raw}");
    assert!(raw.contains(&hex::encode(epoch_public(&id(0x61), 10))));

    // Refused: what no hint could carry.
    let bad = |f: &dyn Fn(&mut ContactSchedule)| {
        let mut b = s.clone();
        f(&mut b);
        save_schedule(dd, &key(2), &b).unwrap_err()
    };
    assert!(bad(&|b| b.capable = false).contains("capable"));
    assert!(bad(&|b| b.len_s = 0).contains("length"));
    assert!(bad(&|b| b.entries.push((17, epoch_public(&id(0x61), 17)))).contains("8"));
    assert!(bad(&|b| b.active = 20).contains("outside"));
    assert!(bad(&|b| b.entries.swap(0, 1)).contains("increasing"));
    assert!(bad(&|b| b.entries[2].1 = [0; 32]).contains("usable"));
    assert!(bad(&|b| b.entries[2].1 = [0xff; 32]).contains("usable"));
    assert!(save_schedule(dd, "abc", &s).is_err());
    assert_eq!(load_schedules(dd).unwrap().len(), 1);

    // The same schedule again within the hour is not rewritten; later it is.
    let stored_at_t0 = || {
        std::fs::read_to_string(dd.join(PEER_SCHEDULES_FILE))
            .unwrap()
            .matches(&(t0 * 1000).to_string())
            .count()
    };
    let again = ContactSchedule {
        received_ms: s.received_ms + 60_000,
        ..s.clone()
    };
    save_schedule(dd, &key(1), &again).unwrap();
    assert_eq!(
        load_schedules(dd).unwrap()[&key(1)].received_ms,
        s.received_ms
    );
    assert_eq!(stored_at_t0(), 1);
    let later = ContactSchedule {
        received_ms: s.received_ms + DAY_MS,
        ..s.clone()
    };
    save_schedule(dd, &key(1), &later).unwrap();
    assert_eq!(
        load_schedules(dd).unwrap()[&key(1)].received_ms,
        later.received_ms
    );

    // Entries behind a contact's clock go when anything is written, and by
    // the prune pass; the capability stays.
    let old = contact_schedule(10, t0);
    save_schedule(dd, &key(3), &old).unwrap();
    let new_one = contact_schedule(40, t0 + 4 * L);
    save_schedule(dd, &key(4), &new_one).unwrap();
    let all = load_schedules(dd).unwrap();
    let epochs = |s: &ContactSchedule| s.entries.iter().map(|(e, _)| *e).collect::<Vec<_>>();
    assert_eq!(epochs(&all[&key(3)]), (13..=16).collect::<Vec<_>>());
    assert_eq!(epochs(&all[&key(4)]), (39..=46).collect::<Vec<_>>());
    // key 3: 13..=16 go; key 1 (heard a day later): 12..=16; key 4: 39..=43.
    assert_eq!(prune_schedules(dd, (t0 + 9 * L) * 1000).unwrap(), 4 + 5 + 5);
    let all = load_schedules(dd).unwrap();
    assert!(all[&key(3)].entries.is_empty() && all[&key(3)].capable);
    assert_eq!(epochs(&all[&key(4)]), (44..=46).collect::<Vec<_>>());
    assert_eq!(prune_schedules(dd, (t0 + 9 * L) * 1000).unwrap(), 0);

    // A removed contact is forgotten.
    forget_schedule(dd, &key(3)).unwrap();
    assert!(!load_schedules(dd).unwrap().contains_key(&key(3)));

    // Bounded: the least recently heard contacts go first.
    let mut cap = contact_schedule(10, t0);
    cap.entries.clear();
    let mut big = Schedules::new();
    for n in 0..MAX_SCHEDULE_CONTACTS as u32 {
        cap.received_ms = u64::from(n);
        big.insert(key(1000 + n), cap.clone());
    }
    crate::at_rest::store_json(dd, &dd.join(PEER_SCHEDULES_FILE), Kind::PeerSchedules, &big)
        .unwrap();
    save_schedule(dd, &key(1), &later).unwrap();
    let all = load_schedules(dd).unwrap();
    assert_eq!(all.len(), MAX_SCHEDULE_CONTACTS);
    assert!(all.contains_key(&key(1)) && !all.contains_key(&key(1000)));

    // A plain file that does not parse reads as none and may be replaced;
    // a hand-edited schedule that fails the checks is left out.
    std::fs::write(dd.join(PEER_SCHEDULES_FILE), b"{not json").unwrap();
    assert!(load_schedules(dd).unwrap().is_empty());
    save_schedule(dd, &key(1), &later).unwrap();
    let mut edited: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dd.join(PEER_SCHEDULES_FILE)).unwrap())
            .unwrap();
    edited[key(1)]["len_s"] = 0.into();
    edited[key(5)] = edited[key(1)].clone();
    edited[key(5)]["len_s"] = (L as u32).into();
    std::fs::write(
        dd.join(PEER_SCHEDULES_FILE),
        serde_json::to_vec(&edited).unwrap(),
    )
    .unwrap();
    let all = load_schedules(dd).unwrap();
    assert_eq!(all.keys().collect::<Vec<_>>(), [&key(5)]);
}

/// `relay_schedule_text_001.json`: the formatted texts, the accepted ones
/// with their entries and the refused ones (each rule of the parse), then
/// round trips of this raven's own texts.
#[test]
fn relay_schedule_text_round_trip_and_strict_rejections() {
    let v = vector("relay_schedule_text_001.json");
    let me = seed_of(&v["inputs"]["raven_seed_hex"]);
    assert_eq!(u(&v["inputs"]["max_entries"]), MAX_RELAY_SCHEDULE as u64);
    assert_eq!(u(&v["inputs"]["max_len"]), RELAY_SCHEDULE_MAX_LEN as u64);
    for f in v["inputs"]["format"].as_array().unwrap() {
        let n = usize::try_from(u(&f["n"])).unwrap();
        assert_eq!(format_relay_schedule(&me, u(&f["from"]), n), f["text"]);
    }
    let accept = v["expected"]["accept"].as_array().unwrap();
    for case in accept {
        let input = case["input"].as_str().unwrap();
        let got = parse_relay_schedule(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        let want: Vec<(u64, String)> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (u(&c["epoch"]), c["peer_id"].as_str().unwrap().to_string()))
            .collect();
        assert_eq!(got, want, "{input}");
    }
    let reject = v["expected"]["reject"].as_array().unwrap();
    assert!(reject.len() >= 20);
    for case in reject {
        let input = case["input"].as_str().unwrap();
        let err = parse_relay_schedule(input).expect_err(input);
        let want = match case["error"].as_str().unwrap() {
            "not_one_line" => "one line",
            "version" => "update raven",
            "prefix" => "must start with",
            "entry" => "<epoch>:<PeerId>",
            "epoch" => "decimal",
            "peer_id" => "canonical PeerId",
            "order" => "strictly increasing",
            "duplicate" => "twice",
            "empty" => "at least one",
            "too_many" => "at most 13",
            other => panic!("unknown error code {other}"),
        };
        assert!(err.contains(want), "{input:?}: {err}");
    }
    for (from, n, want) in [(0, 1, 1), (741, 7, 7), (u64::MAX - 2, 13, 3)] {
        let text = format_relay_schedule(&id(0x52), from, n);
        assert!(text.len() <= RELAY_SCHEDULE_MAX_LEN);
        let got = parse_relay_schedule(&text).unwrap();
        assert_eq!(got.len(), want);
        for (e, peer) in got {
            assert_eq!(peer, epoch_peer_id(&id(0x52), e));
        }
    }
}

/// `card_p2pn_001.json`: the card's `p2p=` is the epoch at the vector's
/// time and `p2pn=` the next one.
#[test]
fn card_p2pn_vector_names_this_and_the_next_epoch() {
    let v = vector("card_p2pn_001.json");
    let (i, x) = (&v["inputs"], &v["expected"]);
    let me = seed_of(&i["raven_seed_hex"]);
    let len = u(&i["epoch_len_s"]);
    let e = epoch_at(&me, u(&i["now_unix"]), len);
    assert_eq!(e, u(&x["epoch"]));
    assert_eq!(phase_s(&me, len), u(&x["phase_s"]));
    assert_eq!(active_peer_id(&me, Some(e)), x["p2p"]);
    assert_eq!(active_peer_id(&me, Some(e + 1)), x["p2pn"]);
    let card = x["card"].as_str().unwrap();
    assert!(card.contains(&format!(
        " p2p={} p2pn={} ",
        x["p2p"].as_str().unwrap(),
        x["p2pn"].as_str().unwrap()
    )));
}
