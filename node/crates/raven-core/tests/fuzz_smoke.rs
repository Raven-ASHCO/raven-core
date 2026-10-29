//! Parser fuzz smoke + ANSI/bidi sanitization + opt-in scale hook.
//!
//! `fuzz_targets` is the cargo-fuzz target library (`node/fuzz/src/lib.rs`),
//! compiled here as a module so every libFuzzer target body type-checks against
//! the current decoder APIs and runs on stable in CI over seeded pseudo-random
//! inputs (`fuzz_smoke_all_targets_random`). Long campaigns: see node/fuzz/.

#[path = "../../../fuzz/src/lib.rs"]
mod fuzz_targets;

use raven_core::envelope::Envelope;
use raven_core::internet::{deframe_prefix, frame, unpack_verify_hello, HelloBinding, HelloRole};
use raven_core::sanitize::{had_dangerous_controls, sanitize_terminal_text};
use raven_core::store_object::StoreObject;
use std::path::{Path, PathBuf};

/// A well-formed app frame of an unregistered type (`a2a-request/2` is one
/// bit flip away from a seed) must not panic the target.
#[test]
fn fuzz_app_frame_accepts_unregistered_types() {
    let id = "00".repeat(16);
    for ct in ["a2a-request/2", "foo/1", "a2a-response/9"] {
        fuzz_targets::app_frame(format!("RVNAPP/1 {ct} {id}\n{{}}").as_bytes());
    }
    fuzz_targets::app_frame(format!("RVNAPP/1 a2a-request/1 {id}\n{{}}").as_bytes());
}

/// Relay kit inputs at their edges reach every branch of `relay_inputs`
/// without tripping its invariants: a public host whose card line would be
/// too long (a 253-character DNS name), bracketed and bare IPv6, port 0,
/// a paste with a duplicate and one with too many addresses, and JSON with
/// unknown or missing fields.
#[test]
fn fuzz_relay_inputs_edges() {
    let peer = raven_core::p2p_route::peer_id_from_ed25519_public(&[9; 32]);
    let via = format!("/ip6/2001:db8::7/udp/7423/quic-v1/p2p/{peer}");
    let long_name = format!("{}.example", "a".repeat(244));
    assert_eq!(long_name.len(), 252);
    let cases: Vec<(u8, String)> = vec![
        (0, via.clone()),
        (0, format!("  {via}  ")),
        (0, format!("{via}/p2p-circuit/p2p/{peer}")),
        (1, format!("via={via} {via},via={via}")),
        (
            1,
            format!(
                "{via} /ip4/203.0.113.7/tcp/7423/p2p/{peer} /ip4/203.0.113.8/tcp/443/p2p/{peer}"
            ),
        ),
        (2, "0".into()),
        (2, "443,7443:443 1:2".into()),
        (2, "7423".into()),
        (3, long_name),
        (3, "[2001:db8::1]".into()),
        (3, "2001:db8::1".into()),
        (3, "[203.0.113.7]".into()),
        (3, "0.0.0.0".into()),
        (4, r#"{"version":7,"peers":[],"extra":true}"#.into()),
        (4, r#"{"version":1}"#.into()),
        (4, r#"{"peer_id":"x"}"#.into()),
    ];
    for (parser, text) in cases {
        for p in [parser, parser + 5, parser + 250] {
            fuzz_targets::relay_inputs(&[&[p], text.as_bytes()].concat());
        }
    }
    // WebSocket over TLS (RWS1 §2): /wss grows by 3 characters as /tls/ws,
    // at the 300-character bound and one step past it; SNI after an IP;
    // refused forms. The target's invariants (canonical re-parse, at most
    // 300 plain characters) hold for each.
    let wss = |host: &str, suffix: &str| format!("{host}/tcp/443{suffix}/p2p/{peer}");
    let wss_cases = [
        wss("/ip4/203.0.113.7", "/wss"),
        wss("/ip4/203.0.113.7", "/tls/sni/Relay.Example.org/ws"),
        wss(&format!("/dns/{}", "a".repeat(223)), "/wss"),
        wss(&format!("/dns/{}", "a".repeat(226)), "/wss"),
        wss("/dns4/relay.example.org", "/tls/sni/relay.example.org/ws"),
        wss("/ip4/203.0.113.7", "/ws"),
        format!("/ip4/203.0.113.7/udp/443/quic-v1/tls/ws/p2p/{peer}"),
    ];
    for text in &wss_cases {
        fuzz_targets::relay_inputs(&[&[0], text.as_bytes()].concat());
        fuzz_targets::relay_inputs(&[&[1], format!("via={text}").as_bytes()].concat());
    }
    fuzz_targets::relay_inputs(&[]);
    fuzz_targets::relay_inputs(&[3]);
}

/// Reason blocks at their edges: the widest block, ages at the unit edges
/// and past u64, a cut inside a multi-byte character, unknown reasons and
/// keys, and a block with no end.
#[test]
fn fuzz_reach_tokens_edges() {
    let max = u64::MAX;
    let cases = [
        format!("reach: why=contact_offline me=unreachable relay=mine2 heard={max}s stale=1 src=card asof={max}s"),
        "reach: why=relay_busy heard=119s asof=120s".to_string(),
        "reach: why=relay_off heard=7199s asof=172799s".to_string(),
        "reach: why=no_relay heard=99999999999999999999d asof=213503982334602d".to_string(),
        format!("reach: why=both_nat src=card {}", "é".repeat(60)),
        "reach: why=gremlins me=public".to_string(),
        "reach: why=both_nat; reach: why=".to_string(),
        "reach: why=no_route me=unknown future=1 x".to_string(),
        format!("reach: why=lan_no_answer me=unreachable relay=mine2 heard={max}s stale=1 src=card asof={max}s"),
        "reach: why=lan_off heard=3h asof=30s".to_string(),
        "reach: why=LAN_OFF".to_string(),
        "reach: why=direct_failed me=\u{1F600} heard=3ｈ".to_string(),
    ];
    for c in &cases {
        fuzz_targets::reach_tokens(c.as_bytes());
        fuzz_targets::reach_tokens(&c.as_bytes()[..c.len() / 2]);
    }
    fuzz_targets::reach_tokens(&[]);
    fuzz_targets::reach_tokens(&[0xff, 0xfe, b';']);
}

/// RELAY_OFFER records at their edges reach every arm of `rrh1_frame`'s
/// record check (accepted, with unknown flag bits too; another version;
/// malformed), and frames whose records are kept, dropped or over the limit.
#[test]
fn fuzz_rrh1_relay_offer_edges() {
    use raven_core::identity::Identity;
    use raven_core::route_hints::{encode, encode_offer, RelayOfferRecord, RouteHints};
    let offer = |seed: u8| RelayOfferRecord {
        flags: 3,
        relay_pub: Identity::from_seed(&[seed; 32]).public_key_bytes(),
        addrs: vec![
            format!("/ip4/11.0.2.{seed}/tcp/7427"),
            "/dns4/relay.example.org/tcp/443".into(),
        ],
    };
    let record = encode_offer(&offer(7));
    let mut unknown_bits = record.clone();
    unknown_bits[1] = 0xff;
    let mut later = record.clone();
    later[0] = 2;
    let mut trailing = record.clone();
    trailing.push(0);
    for r in [&record, &unknown_bits, &later, &trailing] {
        fuzz_targets::rrh1_frame(r);
        fuzz_targets::rrh1_frame(&r[..r.len() - 1]);
    }
    fuzz_targets::rrh1_frame(&[]);
    fuzz_targets::rrh1_frame(&[1]);
    let snapshot = |offers: Vec<RelayOfferRecord>| {
        encode(&RouteHints {
            generation: 7,
            ttl_s: 3600,
            offers,
            ..RouteHints::default()
        })
    };
    let two = snapshot(vec![offer(7), offer(8)]);
    fuzz_targets::rrh1_frame(&two);
    // Three good records, a malformed one and one of a later version: decode
    // keeps two, counts the third and the malformed one (a count the round
    // trip must not expect back) and ignores the later one.
    let entry = |r: &[u8]| {
        let mut e = vec![0x20];
        e.extend_from_slice(&u16::try_from(r.len()).unwrap().to_be_bytes());
        e.extend_from_slice(r);
        e
    };
    let crowded = [
        two.as_slice(),
        &entry(&encode_offer(&offer(9))),
        &entry(&trailing),
        &entry(&later),
    ]
    .concat();
    let h = raven_core::route_hints::decode(&crowded).expect("relay records never cost the frame");
    assert_eq!((h.offers.len(), h.dropped_offers), (2, 2));
    fuzz_targets::rrh1_frame(&crowded);
}

/// RRH1 custody entries (§12) at their edges reach every arm of
/// `rrh1_frame`: an offer and tags of every flags value, every length around
/// the right one, too many of each, an all-zero and a repeated tag, and
/// custody entries next to Phase 2's 0x05 and the reserved types.
#[test]
fn fuzz_rrh1_custody_edges() {
    use raven_core::route_hints::{custodian_tag, decode, encode, RouteHints};
    let tag = custodian_tag(&[1; 32], &[2; 32], &[3; 32]);
    let header = encode(&RouteHints {
        generation: 7,
        ttl_s: 3600,
        ..RouteHints::default()
    });
    let entry = |kind: u8, value: &[u8]| {
        let mut e = vec![kind];
        e.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        e.extend_from_slice(value);
        e
    };
    let frame = |es: &[Vec<u8>]| [header.clone(), es.concat()].concat();
    let tag_value = |flags: u8| [tag.as_slice(), &[flags]].concat();
    for flags in 0..=u8::MAX {
        let f = frame(&[entry(0x06, &[flags]), entry(0x07, &tag_value(flags))]);
        assert!(decode(&f).is_some());
        fuzz_targets::rrh1_frame(&f);
    }
    for len in [0, 1, 2, 31, 32, 33, 34, 64] {
        fuzz_targets::rrh1_frame(&frame(&[entry(0x06, &vec![3; len])]));
        fuzz_targets::rrh1_frame(&frame(&[entry(0x07, &vec![0x7c; len])]));
    }
    let crowded = [
        frame(&[entry(0x06, &[1]), entry(0x06, &[2])]),
        frame(&[
            entry(0x07, &tag_value(0)),
            entry(0x07, &tag_value(1)),
            entry(0x07, &tag_value(2)),
        ]),
    ];
    for f in &crowded {
        assert!(decode(f).is_none());
        fuzz_targets::rrh1_frame(f);
    }
    let mixed = frame(&[
        entry(0x22, &[0xee; 9]),
        entry(0x07, &[0; 33]),
        entry(0x05, &[0x77; 32]),
        entry(0x07, &tag_value(0xff)),
        entry(0x07, &tag_value(0xff)),
        entry(0x06, &[0xff]),
        entry(0x31, &[]),
        entry(0x04, &[0x1d, 0x6b]),
    ]);
    assert!(decode(&mixed).is_none(), "three CUSTODIAN_TAGs");
    let mixed = frame(&[
        entry(0x22, &[0xee; 9]),
        entry(0x07, &[0; 33]),
        entry(0x05, &[0x77; 32]),
        entry(0x07, &tag_value(0xff)),
        entry(0x06, &[0xff]),
        entry(0x31, &[]),
        entry(0x04, &[0x1d, 0x6b]),
    ]);
    let h = decode(&mixed).expect("custody entries next to 0x05 and reserved types");
    assert_eq!((h.custody_offer, h.custodian_tags.len()), (Some(0xff), 2));
    fuzz_targets::rrh1_frame(&mixed);
    let dup = frame(&[entry(0x07, &tag_value(1)), entry(0x07, &tag_value(2))]);
    fuzz_targets::rrh1_frame(&dup);
}

/// The Phase 6b PAIR_SEED entry (§14) at its edges reaches every arm of
/// `rrh1_frame`: every length around 40, generation 0, an all-zero seed and
/// two entries are dropped alone (the frame and its other entries kept), and
/// a kept one re-encodes byte for byte.
#[test]
fn fuzz_rrh1_pair_seed_edges() {
    use raven_core::pair_seed::SeedEntry;
    use raven_core::route_hints::{decode, encode, RouteHints};
    let header = encode(&RouteHints {
        generation: 7,
        ttl_s: 3600,
        lan_port: Some(7531),
        ..RouteHints::default()
    });
    let entry = |value: &[u8]| {
        let mut e = vec![0x08];
        e.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        e.extend_from_slice(value);
        e
    };
    let good = SeedEntry::new(3, [0x38; 32], 2).to_bytes();
    for len in [0, 1, 4, 36, 39, 40, 41, 80] {
        let value: Vec<u8> = good.iter().copied().cycle().take(len).collect();
        let f = [header.clone(), entry(&value)].concat();
        let h = decode(&f).expect("a PAIR_SEED never costs the frame");
        assert_eq!(h.lan_port, Some(7531));
        assert_eq!(
            (h.pair_seed.is_some(), h.dropped_pair_seed),
            (len == 40, u32::from(len != 40))
        );
        fuzz_targets::rrh1_frame(&f);
    }
    let mut zero_gen = good;
    zero_gen[..4].fill(0);
    let mut zero_seed = good;
    zero_seed[4..36].fill(0);
    for bad in [zero_gen, zero_seed] {
        let f = [header.clone(), entry(&bad)].concat();
        assert_eq!(decode(&f).unwrap().dropped_pair_seed, 1);
        fuzz_targets::rrh1_frame(&f);
    }
    let two = [header.clone(), entry(&good), entry(&zero_gen)].concat();
    let h = decode(&two).unwrap();
    assert_eq!(
        (h.pair_seed.unwrap().generation, h.dropped_pair_seed),
        (3, 1)
    );
    fuzz_targets::rrh1_frame(&two);
}

/// Phase 4 RRH1 entries at their edges reach every arm of `rrh1_phase4_tlvs`:
/// a good NAT_CLASS, short and long ones, two of them, out-of-range codes and
/// flags, other Phase 4 types, a value cut by the end of the input, and a
/// frame filled to its bound; the PEER_SCHEDULE vectors' values (good, a
/// capability alone and the negatives), one cut short and two of them.
#[test]
fn fuzz_rrh1_phase4_tlv_edges() {
    // `0x22 = 0x21 + 1`: the type byte 1 (or 16) is NAT_CLASS.
    let good = [1u8, 5, 4, 3, 2, 0, 1];
    for input in [
        &[][..],
        &good[..],
        &[1, 4, 4, 4, 0, 0],
        &[16, 6, 4, 4, 0, 0, 0, 0],
        &[1, 5, 9, 0xff, 4, 1, 0xfe],
        &[0, 3, 1, 2, 3, 2, 5, 1, 1, 1, 1, 1],
        &[1, 9, 4, 4],
        &[14, 0],
    ] {
        fuzz_targets::rrh1_phase4_tlvs(input);
    }
    let twice = [good.as_slice(), &good].concat();
    fuzz_targets::rrh1_phase4_tlvs(&twice);
    let mut full = Vec::new();
    for _ in 0..40 {
        full.extend_from_slice(&[2, 200]);
        full.extend_from_slice(&[0xab; 200]);
    }
    full.extend_from_slice(&good);
    fuzz_targets::rrh1_phase4_tlvs(&full);

    // PEER_SCHEDULE: `0x23 = 0x21 + 2` (type byte 2 or 17), length byte
    // half the value's.
    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../shared-vectors/rvn1/route_hints");
    let mut values: Vec<Vec<u8>> = Vec::new();
    for file in [
        "rrh1_peer_schedule_001.json",
        "rrh1_peer_schedule_capability_only_001.json",
    ] {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(file)).unwrap()).unwrap();
        let hex_value = v["expected"]["decoded"]["peer_schedule"]["value_hex"]
            .as_str()
            .unwrap();
        values.push(hex::decode(hex_value).unwrap());
    }
    for file in [
        "negative/rrh1_peer_schedule_nonmonotonic_001.json",
        "negative/rrh1_peer_schedule_too_many_001.json",
        "negative/rrh1_peer_schedule_bad_key_001.json",
    ] {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(file)).unwrap()).unwrap();
        let frame = hex::decode(v["inputs"]["frame_hex"].as_str().unwrap()).unwrap();
        // Its entries after the 17-byte header: type, u16 length, value.
        let mut rest = &frame[17..];
        while let [kind, a, b, tail @ ..] = rest {
            let len = usize::from(u16::from_be_bytes([*a, *b]));
            if *kind == 0x23 {
                values.push(tail[..len].to_vec());
            }
            rest = &tail[len..];
        }
    }
    assert!(values.len() >= 4, "{}", values.len());
    let entry = |value: &[u8]| {
        let mut e = vec![2u8, u8::try_from(value.len() / 2).unwrap_or(u8::MAX)];
        e.extend_from_slice(value);
        e
    };
    for value in &values {
        fuzz_targets::rrh1_phase4_tlvs(&entry(value));
        fuzz_targets::rrh1_phase4_tlvs(&entry(value)[..value.len() / 2]);
    }
    let two = [entry(&values[1]), entry(&values[0]), good.to_vec()].concat();
    fuzz_targets::rrh1_phase4_tlvs(&two);
}

/// Relay schedule texts at their edges reach every arm of
/// `relay_schedule_text`: the vector's accepted and refused texts, each cut
/// at every byte, and the bounds of the epoch and of the entry count.
#[test]
fn fuzz_relay_schedule_text_edges() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../shared-vectors/rvn1/p2p/relay_schedule_text_001.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut texts: Vec<String> = Vec::new();
    for side in ["accept", "reject"] {
        for case in v["expected"][side].as_array().unwrap() {
            texts.push(case["input"].as_str().unwrap().to_string());
        }
    }
    assert!(texts.len() > 25);
    for text in &texts {
        fuzz_targets::relay_schedule_text(text.as_bytes());
        for cut in (0..text.len()).step_by(7) {
            fuzz_targets::relay_schedule_text(&text.as_bytes()[..cut]);
        }
    }
    for input in [
        &[][..],
        &[0xff; 9][..],
        b"raven-relay-schedule/1 18446744073709551615:x",
        &[0x51, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe],
    ] {
        fuzz_targets::relay_schedule_text(input);
    }
}

/// Port mapping replies at their edges reach every arm of `portmap_reply`:
/// the vectors' replies cut, padded and with flipped R bits, options at the
/// length bounds, the largest and one-too-large PCP message, header-only
/// errors, and the "unsupported version" answers of a NAT-PMP-only router.
#[test]
fn fuzz_portmap_reply_edges() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../shared-vectors/rvn1/portmap");
    let mut replies = Vec::new();
    collect_vector_seeds(&dir, &mut replies);
    assert!(replies.len() > 20);
    let mut head = vec![2u8, 0x80, 0, 0];
    head.extend_from_slice(&[0; 20]);
    let mut cases: Vec<Vec<u8>> = vec![
        head.clone(),
        [head.as_slice(), &[0x80, 0, 0, 0]].concat(),
        [head.as_slice(), &[0x80, 0, 0xff, 0xff]].concat(),
        [head.as_slice(), &[0x7f, 0, 0, 4, 1, 2, 3, 4]].concat(),
        [head.as_slice(), &[0x80, 0, 0x04, 0x30], &[0; 1072]].concat(),
        [head.as_slice(), &[0x80, 0, 0x04, 0x34], &[0; 1076]].concat(),
        vec![
            2, 0x81, 0, 8, 0, 0, 0, 30, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        vec![0, 0x81, 0, 1, 0, 0, 0, 9],
        vec![0, 0x80, 0, 1, 0, 0, 0, 9],
        vec![0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 0],
        vec![0, 0x82, 0, 1, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0],
    ];
    for r in &replies {
        cases.push(r.clone());
        if !r.is_empty() {
            cases.push(r[..r.len() - 1].to_vec());
            let mut flipped = r.clone();
            if flipped.len() > 1 {
                flipped[1] ^= 0x80;
            }
            cases.push(flipped);
        }
        cases.push([r.as_slice(), &[0; 4]].concat());
    }
    for c in &cases {
        fuzz_targets::portmap_reply(c);
    }
    fuzz_targets::portmap_reply(&[]);
    fuzz_targets::portmap_reply(&[0]);
    fuzz_targets::portmap_reply(&[2]);
}

/// `MapperCore::on_datagram` from a mapped state at its edges (the second
/// half of `portmap_reply`): answers that match the fuzz cores' mappings with
/// every result code of the profile, a moved or non-global external address,
/// lifetime 0, port 0 and a restarted epoch, for PCP and NAT-PMP.
#[test]
fn fuzz_portmap_mapper_edges() {
    use raven_core::identity::Identity;
    use raven_core::portmap::{nonce_key, pcp_nonce, Proto};
    use std::net::{IpAddr, Ipv4Addr};
    let key = nonce_key(&Identity::from_seed(&fuzz_targets::PORTMAP_FUZZ_SEED));
    let client = IpAddr::V4(fuzz_targets::PORTMAP_FUZZ_CLIENT);
    let gateway = IpAddr::V4(fuzz_targets::PORTMAP_FUZZ_GATEWAY);
    let port = fuzz_targets::PORTMAP_FUZZ_PORT;
    let pcp =
        |proto: Proto, result: u8, lifetime: u32, epoch: u32, ext: Ipv4Addr, ext_port: u16| {
            let mut b = vec![2, 0x81, 0, result];
            b.extend_from_slice(&lifetime.to_be_bytes());
            b.extend_from_slice(&epoch.to_be_bytes());
            b.extend_from_slice(&[0; 12]);
            b.extend_from_slice(&pcp_nonce(&key, gateway, client, proto, port));
            b.extend_from_slice(&[proto as u8, 0, 0, 0]);
            b.extend_from_slice(&port.to_be_bytes());
            b.extend_from_slice(&ext_port.to_be_bytes());
            b.extend_from_slice(&ext.to_ipv6_mapped().octets());
            b
        };
    let natpmp = |op: u8, result: u16, lifetime: u32, epoch: u32, ext_port: u16| {
        let mut b = vec![0, 0x80 | op];
        b.extend_from_slice(&result.to_be_bytes());
        b.extend_from_slice(&epoch.to_be_bytes());
        b.extend_from_slice(&port.to_be_bytes());
        b.extend_from_slice(&ext_port.to_be_bytes());
        b.extend_from_slice(&lifetime.to_be_bytes());
        b
    };
    let natpmp_ext = |result: u16, epoch: u32, ext: Ipv4Addr| {
        let mut b = vec![0, 0x80];
        b.extend_from_slice(&result.to_be_bytes());
        b.extend_from_slice(&epoch.to_be_bytes());
        b.extend_from_slice(&ext.octets());
        b
    };
    let e = fuzz_targets::PORTMAP_FUZZ_EPOCH + 1;
    let same = Ipv4Addr::new(11, 0, 2, 9);
    let moved = Ipv4Addr::new(11, 0, 3, 7);
    let cgn = Ipv4Addr::new(100, 64, 0, 9);
    let mut cases = Vec::new();
    for proto in [Proto::Tcp, Proto::Udp] {
        for result in [0u8, 1, 2, 3, 7, 8, 9, 10, 11, 12, 13, 200] {
            cases.push(pcp(proto, result, 7200, e, same, port));
            cases.push(pcp(proto, result, 30, e, same, port));
        }
        cases.push(pcp(proto, 0, 7200, e, moved, port));
        cases.push(pcp(proto, 0, 7200, e, same, port + 1));
        cases.push(pcp(proto, 0, 7200, e, cgn, port));
        cases.push(pcp(proto, 0, 7200, e, Ipv4Addr::LOCALHOST, port));
        cases.push(pcp(proto, 0, 0, e, same, port));
        cases.push(pcp(proto, 0, 7200, e, same, 0));
        cases.push(pcp(proto, 0, 7200, 0, same, port));
        cases.push(pcp(proto, 0, 7200, 5000, moved, port));
        let op = proto.natpmp_op();
        for result in 0u16..=6 {
            cases.push(natpmp(op, result, 7200, e, port));
        }
        cases.push(natpmp(op, 0, 7200, e, port + 1));
        cases.push(natpmp(op, 0, 0, e, port));
        cases.push(natpmp(op, 0, 7200, e, 0));
        cases.push(natpmp(op, 0, 7200, 0, port));
    }
    for ext in [same, moved, cgn] {
        for result in [0u16, 3] {
            cases.push(natpmp_ext(result, e, ext));
            cases.push(natpmp_ext(result, 0, ext));
        }
    }
    for c in &cases {
        fuzz_targets::portmap_reply(c);
    }
}

/// Proxy settings and bypass lists at their edges: every input of
/// shared-vectors/rvn1/wss (settings, Windows strings, lists and hosts),
/// texts at the 1024-byte bound and with multi-byte characters, and their
/// first 64 byte cuts reach `proxy_setting` without tripping its invariants.
#[test]
fn fuzz_proxy_setting_edges() {
    let dir = rvn1_vectors_root().join("wss");
    let mut texts: Vec<String> = Vec::new();
    for name in ["rws1_proxy_url_001.json", "rws1_no_proxy_001.json"] {
        let raw = std::fs::read(dir.join(name)).expect("proxy vectors");
        let v: serde_json::Value = serde_json::from_slice(&raw).expect("vector json");
        let e = &v["expected"];
        for key in ["settings", "windows"] {
            for case in e[key].as_array().into_iter().flatten() {
                texts.push(case["input"].as_str().unwrap().to_owned());
            }
        }
        for case in e["lists"].as_array().into_iter().flatten() {
            texts.push(case["list"].as_str().unwrap().to_owned());
            for check in case["checks"].as_array().unwrap() {
                texts.push(check["host"].as_str().unwrap().to_owned());
            }
        }
    }
    assert!(texts.len() > 150, "{}", texts.len());
    let at_bound = format!("http://{}.example", "a".repeat(1009));
    assert_eq!(at_bound.len(), 1024);
    texts.extend([
        format!("{at_bound}a"),
        at_bound,
        "http://user:pass@[2001:db8::1]:3128".into(),
        "http://\u{e9}@proxy.example".into(),
        "\u{e9}.example,*\u{e9}*,[\u{e9}]:443,\u{e9}/8".into(),
        "https=\u{e9};\u{e9}".into(),
    ]);
    texts.extend(["%", "@", "[", "[]", "*", ":", "/", "=", ";"].map(String::from));
    for text in &texts {
        let bytes = text.as_bytes();
        fuzz_targets::proxy_setting(bytes);
        for cut in 0..bytes.len().min(64) {
            fuzz_targets::proxy_setting(&bytes[..cut]);
        }
    }
}

/// WebSocket frames at their edges: every frame and head of
/// shared-vectors/rvn1/wss/rws1_ws_frames_001.json, the frames of its
/// sequences in a row, the largest frame both ways, a message at the
/// 262144-byte limit in fragments around a ping and one byte past it, and
/// the handshake keys, each whole, cut and with flipped bits, reach
/// `ws_frame` without tripping its invariants.
#[test]
fn fuzz_ws_frame_edges() {
    use raven_core::ws_frame::{
        apply_mask, encode, encode_head, OP_BINARY, OP_CONTINUATION, OP_PING, WS_MAX_MESSAGE,
    };
    let dir = rvn1_vectors_root().join("wss");
    let read = |name: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(dir.join(name)).expect("ws vectors")).expect("json")
    };
    let hex_of = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let frames = read("rws1_ws_frames_001.json");
    let e = &frames["expected"];
    let mask: [u8; 4] = hex_of(&frames["inputs"]["mask_hex"]).try_into().unwrap();
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for key in ["data", "control"] {
        for case in e[key].as_array().unwrap() {
            for side in ["client", "server"] {
                for part in ["frame_hex", "head_hex"] {
                    if let Some(h) = case.get(format!("{side}_{part}")) {
                        cases.push(hex_of(h));
                    }
                }
            }
        }
    }
    for key in ["heads", "incomplete", "reject"] {
        for case in e[key].as_array().unwrap() {
            cases.push(hex_of(&case["head_hex"]));
        }
    }
    for case in e["sequences"].as_array().unwrap() {
        let key = case["expect_masked"].as_bool().unwrap().then_some(mask);
        let mut wire = Vec::new();
        for f in case["frames"].as_array().unwrap() {
            let payload = match f.get("payload_hex") {
                Some(h) => hex_of(h),
                None => (0..f["payload_len"].as_u64().unwrap())
                    .map(|i| (i % 251) as u8)
                    .collect(),
            };
            let op = f["op"].as_u64().unwrap() as u8;
            let fin = f["fin"].as_bool().unwrap();
            encode_head(fin, op, payload.len() as u64, key, &mut wire);
            let at = wire.len();
            wire.extend_from_slice(&payload);
            if let Some(k) = key {
                apply_mask(&mut wire[at..], k, 0);
            }
        }
        cases.push(wire);
    }
    let big: Vec<u8> = (0..WS_MAX_MESSAGE).map(|i| (i % 251) as u8).collect();
    for key in [Some(mask), None] {
        let mut f = Vec::new();
        encode(OP_BINARY, &big, key, &mut f);
        cases.push(f);
        let half = WS_MAX_MESSAGE / 2;
        let mut parts = Vec::new();
        encode_head(false, OP_BINARY, half as u64, key, &mut parts);
        parts.extend_from_slice(&big[..half]);
        encode(OP_PING, b"p", key, &mut parts);
        encode_head(true, OP_CONTINUATION, half as u64, key, &mut parts);
        parts.extend_from_slice(&big[half..]);
        cases.push(parts);
        let mut over = Vec::new();
        encode_head(false, OP_BINARY, big.len() as u64, key, &mut over);
        over.extend_from_slice(&big);
        encode(OP_CONTINUATION, b"!", key, &mut over);
        cases.push(over);
    }
    let handshake = read("rws1_ws_handshake_001.json");
    cases.push(
        handshake["inputs"]["key"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
    );
    cases.extend(
        ["AQIDBAUGBwgJCgsMDQ4PEA==", "dGhlIHNhbXBsZSBub25jZR==", "=="]
            .map(|k| k.as_bytes().to_vec()),
    );
    assert!(cases.len() > 60, "{}", cases.len());
    for c in &cases {
        fuzz_targets::ws_frame(c);
        for cut in 0..c.len().min(16) {
            fuzz_targets::ws_frame(&c[..cut]);
        }
        if let Some(last) = c.len().checked_sub(1) {
            fuzz_targets::ws_frame(&c[..last]);
        }
        // Flip each bit of the head (of the first two bytes for the large
        // frames, whose payload every accepted flip would copy again).
        let head_bytes = if c.len() > 4096 { 2 } else { c.len().min(14) };
        for bit in 0..head_bytes * 8 {
            let mut flipped = c.clone();
            flipped[bit / 8] ^= 1 << (bit % 8);
            fuzz_targets::ws_frame(&flipped);
        }
    }
}

/// LAN beacon datagrams at their edges reach every branch of
/// `lan_beacon_datagram`: the committed query and answer
/// (shared-vectors/rvn1/lan_beacon) bare, with their longest tails (Phase 6b
/// W-B3) and one byte over them, the padded vectors' datagrams, all zeros,
/// one byte short of or over each length range, the negative vector's
/// datagrams (port 0 among them), and queries the fixture finds from its
/// link-local source and at both ends of u64, which the target re-encodes.
#[test]
fn fuzz_lan_beacon_datagram_edges() {
    use raven_core::lan_beacon::{build_query_with, match_query, open_answer};
    let fx = fuzz_targets::lan_beacon_fixture();
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("lan_beacon").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    let query = bytes(&vector("lbcn_query_001.json")["expected"]["query_hex"]);
    let answer = bytes(&vector("lbcn_answer_001.json")["expected"]["answer_hex"]);
    // The committed datagrams reach the accepted branches.
    assert_eq!(
        match_query(&query, fx.sources[0], fx.epoch, &fx.book),
        [(0, 7420), (1, 7420)]
    );
    let (src, dst) = (fx.answer_src, fx.answer_dst);
    assert_eq!(
        open_answer(&answer, &fx.book[2], &fx.q_nonce, src, dst),
        Some(7420)
    );
    let mut inputs = vec![query.clone(), answer.clone()];
    for (d, most) in [(&query, 31), (&answer, 15)] {
        inputs.push(d[..d.len() - 1].to_vec());
        inputs.push([d.as_slice(), &[0]].concat());
        inputs.push([d.as_slice(), &vec![0xa5; most]].concat());
        inputs.push([d.as_slice(), &vec![0; most + 1]].concat());
    }
    // A tail changes nothing: the longest ones name and open as the bare
    // datagrams do.
    assert_eq!(
        match_query(&inputs[4], fx.sources[0], fx.epoch, &fx.book),
        [(0, 7420), (1, 7420)]
    );
    assert_eq!(
        open_answer(&inputs[8], &fx.book[2], &fx.q_nonce, src, dst),
        Some(7420)
    );
    for len in [0, 47, 48, 49, 63, 64, 159, 160, 161, 191, 192] {
        inputs.push(vec![0; len]);
    }
    for file in [
        "lbcn_negative_001.json",
        "lbcn_query_padded_001.json",
        "lbcn_answer_padded_001.json",
    ] {
        let rows = &vector(file)["expected"];
        let rows = rows["datagrams"].as_array().or(rows["padded"].as_array());
        for row in rows.unwrap() {
            inputs.push(bytes(&row["datagram_hex"]));
        }
    }
    let pad = [[0x5a; 18]; 7];
    for (src, epoch) in [
        (fx.sources[2], fx.epoch),
        (fx.sources[0], 0),
        (fx.sources[1], u64::MAX),
    ] {
        let q = build_query_with([9; 16], &[6], &pad, epoch, src, 51_000, &[&fx.mirror[0]]);
        assert_eq!(match_query(&q, src, epoch, &fx.book), [(0, 51_000)]);
        inputs.push(q.to_vec());
    }
    for d in &inputs {
        fuzz_targets::lan_beacon_datagram(d);
    }
}

/// Nearby frames at their edges reach every branch of `rnp1_frame`: the
/// committed HELLO (answered by the fixture, then silent), CHALLENGE, PROOF
/// and RNP1 frames of shared-vectors/rvn1/nearby at each frame size and
/// role, the negative vectors' frame sequences (length-prefixed) for both
/// roles with and without local sends, and frames one byte over each size.
#[test]
fn fuzz_rnp1_frame_edges() {
    use raven_core::nearby_link::{decode, KnockReplay, PeripheralKnock};
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("nearby").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    let knock = vector("rnk1_knock_001.json");
    let hello = bytes(&knock["expected"]["hello_hex"]);
    // The committed HELLO reaches the answered branch.
    let fx = fuzz_targets::nearby_fixture();
    assert!(PeripheralKnock::answer(
        &fx.peripheral,
        fx.token,
        &decode(&hello, 64).unwrap(),
        [1; 16],
        &mut KnockReplay::new()
    )
    .is_some());
    let mut frames = vec![
        hello,
        bytes(&knock["expected"]["challenge_hex"]),
        bytes(&knock["expected"]["proof_hex"]),
    ];
    for row in vector("rnp1_frames_001.json")["expected"]["frames"]
        .as_array()
        .unwrap()
    {
        frames.push(bytes(&row["frame_hex"]));
    }
    let mut sequences = Vec::new();
    for file in [
        "bad_kind",
        "short_data",
        "credit_overflow",
        "data_without_credit",
        "seq_gap",
        "chan_owner",
        "data_too_long",
        "knock_after_up",
    ] {
        let v = vector(&format!("negative/rnp1_{file}_001.json"));
        let mut seq = Vec::new();
        for f in v["inputs"]["frames_hex"].as_array().unwrap() {
            let f = bytes(f);
            seq.push(f.len() as u8);
            seq.extend(f);
        }
        sequences.push(seq);
    }
    let mut inputs = Vec::new();
    for sel in [0u8, 1, 2, 0x80, 0x81, 0x82, 0x40, 0xc2] {
        for f in &frames {
            inputs.push([&[sel][..], f].concat());
        }
        for s in &sequences {
            inputs.push([&[sel][..], s].concat());
        }
        for over in [65usize, 186, 513] {
            let mut long = vec![0x11, 0, 0, 0];
            long.resize(over, 0x5a);
            inputs.push([&[sel][..], &long].concat());
        }
        inputs.push(vec![sel]);
    }
    for d in &inputs {
        fuzz_targets::rnp1_frame(d);
    }
}

/// PAD1 frames at their edges reach every branch of `pad1_frame`: the
/// committed frames and negatives of shared-vectors/rvn1/link, one byte
/// short and one byte over, a frame in a larger bucket than needed, and
/// frame sequences (bare, padded, malformed, bare after padded) to each side.
#[test]
fn fuzz_pad1_frame_edges() {
    use raven_core::link_padding::{unwrap, wrap, PAD1_MAX_INNER};
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("link").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    let mut frames = Vec::new();
    for file in ["pad1_ack_512_001.json", "pad1_pairinit_4096_001.json"] {
        let v = vector(file);
        let frame = bytes(&v["expected"]["frame_hex"]);
        assert!(unwrap(&frame).is_ok());
        frames.push(frame[..frame.len() - 1].to_vec());
        frames.push([&frame[..], &[0]].concat());
        frames.push(bytes(&v["inputs"]["inner_hex"]));
        frames.push(frame);
    }
    for file in [
        "nonzero_padding",
        "bad_bucket",
        "nested",
        "len_overflow",
        "zero_len",
        "bad_version",
        "reserved",
    ] {
        let frame =
            bytes(&vector(&format!("negative/pad1_{file}_001.json"))["inputs"]["frame_hex"]);
        assert!(unwrap(&frame).is_err(), "{file}");
        frames.push(frame);
    }
    let mut roomy = wrap(b"RVN1").unwrap();
    roomy.resize(4_096, 0);
    assert!(unwrap(&roomy).is_ok());
    frames.push(roomy);
    frames.push(vec![0x5a; PAD1_MAX_INNER]);
    frames.push(vec![0x5a; PAD1_MAX_INNER + 1]);
    frames.push(b"RPD1".to_vec());
    frames.push(Vec::new());
    // Sequences: a length byte (odd: the peer pads), then half as many bytes.
    let chunk =
        |padded: bool, b: &[u8]| [&[((b.len() as u8) << 1) | u8::from(padded)][..], b].concat();
    let sequences = [
        [
            chunk(false, b"RVN1 bare"),
            chunk(true, b"RVN1 padded"),
            chunk(false, b"RVN1 bare"),
        ]
        .concat(),
        [
            chunk(true, b"RRH1"),
            chunk(true, b"RLB1"),
            chunk(true, b"RPD1 nested"),
        ]
        .concat(),
        [
            chunk(false, b""),
            chunk(true, b""),
            chunk(false, b"RPD1"),
            chunk(true, b"x"),
        ]
        .concat(),
        [chunk(true, b"a"), chunk(false, b"b")].concat(),
    ];
    let mut inputs = Vec::new();
    for sel in [0u8, 1, 2] {
        for f in frames.iter().chain(&sequences) {
            inputs.push([&[sel][..], f].concat());
        }
    }
    inputs.extend(frames);
    for d in &inputs {
        fuzz_targets::pad1_frame(d);
    }
}

/// RLK1 inputs at their edges reach every branch of `rlk1_m1`: the
/// committed knock of shared-vectors/rvn1/link (it matches at the vectors'
/// day), the negatives' messages 1 (another day, another pair), one byte
/// short and over the lengths that can match, the committed message 2
/// payloads (bob's proof, then random bytes) and padded RLX1 payloads.
#[test]
fn fuzz_rlk1_m1_edges() {
    use raven_core::link_knock::{check_m2, match_m1};
    let fx = fuzz_targets::knock_fixture();
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("link").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    let tags = vector("rlk1_tags_001.json");
    let m1 = bytes(&tags["expected"]["raw_m1_hex"]);
    assert_eq!(
        match_m1(&fx.book, &m1, fx.day).map(|m| (m.index, m.peer)),
        Some((1, fx.alice))
    );
    let proof = bytes(&tags["expected"]["m2_payload_hex"]);
    assert!(check_m2(&fx.alice_to_bob, &fx.nonce, &fx.e, &fx.s, &proof));
    let unmatched =
        bytes(&vector("negative/rlk1_unmatched_m2_random_001.json")["inputs"]["m2_payload_hex"]);
    assert!(!check_m2(
        &fx.alice_to_bob,
        &fx.nonce,
        &fx.e,
        &fx.s,
        &unmatched
    ));
    let mut inputs = vec![m1.clone(), proof.clone(), unmatched];
    inputs.push(m1[..m1.len() - 1].to_vec());
    inputs.push([&m1[..], &[0]].concat());
    inputs.push(m1[..64].to_vec());
    inputs.push([&m1[..64], &[7; 31][..]].concat());
    inputs.push([&m1[..64], &[7; 32][..]].concat());
    inputs.push(m1[..63].to_vec());
    inputs.push(proof[..16].to_vec());
    inputs.push([&proof[..16], &[1; 31][..]].concat());
    inputs.push([&proof[..16], &[1; 32][..]].concat());
    for case in vector("negative/rlk1_wrong_pair_001.json")["inputs"]["cases"]
        .as_array()
        .unwrap()
    {
        inputs.push(bytes(&case["raw_m1_hex"]));
    }
    for case in tags["expected"]["m3_payloads"].as_array().unwrap() {
        inputs.push(bytes(&case["payload_hex"]));
    }
    for len in [0, 1, 7, 13, 32, 64, 65, 255] {
        inputs.push(vec![len as u8; len]);
    }
    for d in &inputs {
        fuzz_targets::rlk1_m1(d);
    }
}

/// RAD1 advisories, key sets and signature blocks at their edges reach every
/// branch of `rad1_decode`: the committed advisories and the test key set of
/// shared-vectors/rvn1/update (each verified under its key set), each one
/// byte short and one byte over, its signature block alone, one padded to
/// the size limit, and every case of the decode-rule and key set negatives.
#[test]
fn fuzz_rad1_decode_edges() {
    use raven_core::advisory::{Advisory, MAX_RAD1_LEN};
    use raven_core::release_keys::{KeySet, SigBlock};
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("update").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    let sets = fuzz_targets::release_key_fixture();
    let mut inputs = Vec::new();
    for (file, part, set) in [
        ("rad1_two_of_three_001.json", "advisory", 0),
        ("rad1_three_of_three_001.json", "advisory", 0),
        ("rad1_key_rotation_001.json", "rotation", 0),
        ("rad1_key_rotation_001.json", "after", 1),
    ] {
        let data = bytes(&vector(file)["expected"][part]["advisory_hex"]);
        let a = Advisory::decode(&data).expect("a committed advisory decodes");
        assert_eq!(a.verify(&sets[set]), Ok(()), "{file} {part}");
        let block = &data[a.signed_len()..];
        assert!(SigBlock::decode(block).is_ok());
        let mut padded = data.clone();
        padded.resize(MAX_RAD1_LEN, 0);
        inputs.extend([
            data[..data.len() - 1].to_vec(),
            [&data[..], &[0]].concat(),
            block.to_vec(),
            padded,
            data,
        ]);
    }
    let keys = bytes(&vector("keyset_001.json")["expected"]["key_set_hex"]);
    assert_eq!(KeySet::decode(&keys).as_ref(), Ok(&sets[0]));
    inputs.push(keys);
    for (file, field) in [
        ("negative/rad1_decode_rules_001.json", "advisory_hex"),
        ("negative/keyset_rules_001.json", "key_set_hex"),
    ] {
        for case in vector(file)["inputs"]["cases"].as_array().unwrap() {
            inputs.push(bytes(&case[field]));
        }
    }
    for d in &inputs {
        fuzz_targets::rad1_decode(d);
    }
}

/// RTL1 tree heads and snapshots at their edges reach every branch of
/// `rtl1_snapshot`: the committed snapshots of shared-vectors/rvn1/update
/// (both sides of the split view, the bad root and every check-rule case
/// among them) and their tree heads, each one byte short and one byte
/// over, one padded to the size limit, and every case of the decode-rule
/// negative.
#[test]
fn fuzz_rtl1_snapshot_edges() {
    use raven_core::tlog::{LogCheckError, Snapshot, Sth, MAX_SNAPSHOT_LEN};
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("update").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    let test_set = &fuzz_targets::release_key_fixture()[0];
    let mut snapshots = Vec::new();
    for (file, path) in [
        ("rtl1_snapshot_5_001.json", &["expected", "snapshot"][..]),
        ("rtl1_consistency_001.json", &["expected", "five"]),
        ("rtl1_consistency_001.json", &["expected", "eight"]),
        ("negative/rtl1_split_view_pair_001.json", &["expected", "a"]),
        ("negative/rtl1_split_view_pair_001.json", &["expected", "b"]),
    ] {
        let v = path.iter().fold(vector(file), |v, k| v[*k].clone());
        let data = bytes(&v["snapshot_hex"]);
        let snap = Snapshot::decode(&data).expect("a committed snapshot decodes");
        assert!(snap.check(test_set).is_ok(), "{file} {path:?}");
        snapshots.push(data);
    }
    let bad_root = bytes(&vector("negative/rtl1_bad_root_001.json")["inputs"]["snapshot_hex"]);
    let bad = Snapshot::decode(&bad_root).expect("the bad root decodes");
    assert_eq!(bad.check(test_set).err(), Some(LogCheckError::BadRoot));
    snapshots.push(bad_root);
    for case in vector("negative/rtl1_check_rules_001.json")["inputs"]["cases"]
        .as_array()
        .unwrap()
    {
        snapshots.push(bytes(&case["snapshot_hex"]));
    }
    let mut inputs = Vec::new();
    for data in snapshots {
        let snap = Snapshot::decode(&data).expect("a committed snapshot decodes");
        let sth = snap.sth().bytes().to_vec();
        assert!(Sth::decode(&sth).is_ok());
        let mut padded = data.clone();
        padded.resize(MAX_SNAPSHOT_LEN, 0);
        inputs.extend([
            data[..data.len() - 1].to_vec(),
            [&data[..], &[0]].concat(),
            sth[..sth.len() - 1].to_vec(),
            [&sth[..], &[0]].concat(),
            sth,
            padded,
            data,
        ]);
    }
    for case in vector("negative/rtl1_decode_rules_001.json")["inputs"]["cases"]
        .as_array()
        .unwrap()
    {
        let mut data = bytes(&case["hex"]);
        if let Some(n) = case["zero_pad_to"].as_u64() {
            data.resize(usize::try_from(n).unwrap(), 0);
        }
        inputs.push(data);
    }
    for d in &inputs {
        fuzz_targets::rtl1_snapshot(d);
    }
}

/// RRB1 manifests at their edges reach every branch of `rrb1_manifest`: the
/// committed manifests of shared-vectors/rvn1/update (the test release, and
/// every manifest of the verification rules, each one byte short and one
/// byte over, one padded to the size limit) and every case of the decode,
/// path-traversal and overlap negatives.
#[test]
fn fuzz_rrb1_manifest_edges() {
    use raven_core::release_bundle::{Manifest, MAX_MANIFEST_LEN};
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("update").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    let test_set = &fuzz_targets::release_key_fixture()[0];
    let good = bytes(&vector("rrb1_manifest_001.json")["expected"]["manifest"]["manifest_hex"]);
    let m = Manifest::decode(&good).expect("the committed manifest decodes");
    assert_eq!(m.verify(test_set), Ok(()));
    let mut manifests = vec![good];
    for case in vector("negative/rrbc_verify_rules_001.json")["inputs"]["cases"]
        .as_array()
        .unwrap()
    {
        manifests.push(bytes(&case["parts"]["manifest_hex"]));
    }
    let mut inputs = Vec::new();
    for data in manifests {
        assert!(Manifest::decode(&data).is_ok());
        let mut padded = data.clone();
        padded.resize(MAX_MANIFEST_LEN, 0);
        inputs.extend([
            data[..data.len() - 1].to_vec(),
            [&data[..], &[0]].concat(),
            padded,
            data,
        ]);
    }
    for (file, field) in [
        ("negative/rrb1_decode_rules_001.json", "hex"),
        ("negative/rrb1_path_traversal_001.json", "manifest_hex"),
        ("negative/rrb1_overlap_001.json", "manifest_hex"),
    ] {
        for case in vector(file)["inputs"]["cases"].as_array().unwrap() {
            let mut data = bytes(&case[field]);
            if let Some(n) = case["zero_pad_to"].as_u64() {
                data.resize(usize::try_from(n).unwrap(), 0);
            }
            assert!(Manifest::decode(&data).is_err(), "{file}");
            inputs.push(data);
        }
    }
    // Chunk trees: `C`, the chunk size byte, then the payload.
    for (size, len) in [
        (0u8, 1usize),
        (0, 2),
        (6, 7),
        (6, 8),
        (6, 9),
        (63, 64),
        (63, 4_096),
        (17, 1_000),
    ] {
        inputs.push(
            [
                &[b'C', size][..],
                &(0..len).map(|j| (j % 251) as u8).collect::<Vec<_>>(),
            ]
            .concat(),
        );
    }
    for d in &inputs {
        fuzz_targets::rrb1_manifest(d);
    }
}

/// RRBC containers at their edges reach every branch of `rrbc_container`:
/// the test release's container (it verifies), the unlogged and tampered
/// ones, a container of each verification case's parts, each one byte short
/// and one byte over, and every case of the container decode negative.
#[test]
fn fuzz_rrbc_container_edges() {
    use raven_core::advisory::Advisory;
    use raven_core::release_bundle::{verify_bundle, Container, Manifest, Parts, VerifyCtx};
    use raven_core::tlog::Snapshot;
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("update").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    let test_set = &fuzz_targets::release_key_fixture()[0];
    let good = bytes(&vector("rrbc_small_001.json")["expected"]["container_hex"]);
    let parts = Container::open(&good[..]).expect("the committed container opens");
    let ctx = VerifyCtx {
        key_set: Some(test_set),
        stored_log: &[],
        installed_serial: 0,
        target: &parts.manifest.target,
        release_floor: 0,
        allow_downgrade: false,
    };
    assert!(verify_bundle(&parts, &ctx).is_ok());
    let mut containers = vec![good];
    for file in [
        "negative/rrb1_unlogged_001.json",
        "negative/rrbc_chunk_tamper_001.json",
    ] {
        containers.push(bytes(&vector(file)["inputs"]["container_hex"]));
    }
    let verify = vector("negative/rrbc_verify_rules_001.json");
    let good_payload = bytes(&verify["inputs"]["good_payload_hex"]);
    for case in verify["inputs"]["cases"].as_array().unwrap() {
        let p = &case["parts"];
        let parts = Parts {
            manifest: Manifest::decode(&bytes(&p["manifest_hex"])).unwrap(),
            snapshot: Snapshot::decode(&bytes(&p["snapshot_hex"])).unwrap(),
            advisory: p["advisory_hex"]
                .as_str()
                .map(|h| Advisory::decode(&hex::decode(h).unwrap()).unwrap()),
            payload: p["payload_hex"]
                .as_str()
                .map_or(good_payload.clone(), |h| hex::decode(h).unwrap()),
        };
        containers.push(parts.encode());
    }
    let mut inputs = Vec::new();
    for data in containers {
        inputs.extend([
            data[..data.len() - 1].to_vec(),
            [&data[..], &[0]].concat(),
            data,
        ]);
    }
    for case in vector("negative/rrbc_decode_rules_001.json")["inputs"]["cases"]
        .as_array()
        .unwrap()
    {
        let data = bytes(&case["hex"]);
        assert!(Container::open(&data[..]).is_err());
        inputs.push(data);
    }
    for d in &inputs {
        fuzz_targets::rrbc_container(d);
    }
}

/// RUP1 frames at their edges reach every branch of `rup1_frame`: every
/// committed frame and HAVE of shared-vectors/rvn1/update/rup1_*, every
/// CHUNK of the chunk-path vector (the large ones rebuilt from their head,
/// fill and tail), every refusal and forged chunk of the negatives, each
/// one byte short and one byte over, and every body behind each op.
#[test]
fn fuzz_rup1_frame_edges() {
    use raven_core::update_exchange::{decode, decode_for_listener, ListenerDecode};
    let vector = |file: &str| -> serde_json::Value {
        let path = rvn1_vectors_root().join("update").join(file);
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_slice(&raw).expect("vector json")
    };
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().expect("a hex string")).unwrap();
    // A case's frame: whole, or head | fill (byte j = (start + j) mod 251) |
    // tail with one byte flipped at `xor_at`.
    let frame_of = |case: &serde_json::Value| -> Vec<u8> {
        if let Some(h) = case.get("frame_hex") {
            return bytes(h);
        }
        let spec = &case["frame"];
        let start = spec["fill_start"].as_u64().unwrap() as usize;
        let fill =
            (0..spec["fill_len"].as_u64().unwrap() as usize).map(|j| ((start + j) % 251) as u8);
        let mut f: Vec<u8> = bytes(&spec["head_hex"]);
        f.extend(fill);
        f.extend(bytes(&spec["tail_hex"]));
        if let Some(at) = spec["xor_at"].as_u64() {
            f[at as usize] ^= 1;
        }
        assert_eq!(f.len() as u64, spec["len"].as_u64().unwrap());
        f
    };
    let mut frames = Vec::new();
    for (file, key) in [
        ("rup1_frames_001.json", "frames"),
        ("rup1_have_001.json", "haves"),
    ] {
        for e in vector(file)["expected"][key].as_array().unwrap() {
            let f = bytes(&e["frame_hex"]);
            assert!(decode(&f).is_ok(), "{file} {}", e["name"]);
            frames.push(f);
        }
    }
    let chunks = vector("rup1_chunk_path_001.json");
    for part in ["small", "max"] {
        for e in chunks["expected"][part]["chunks"].as_array().unwrap() {
            let f = frame_of(e);
            assert!(decode(&f).is_ok(), "{part} chunk {}", e["index"]);
            frames.push(f);
        }
    }
    frames.push(bytes(&chunks["expected"]["small"]["last_frame_hex"]));
    for (file, key) in [
        ("negative/rup1_decode_rules_001.json", "cases"),
        ("negative/rup1_oversize_chunk_001.json", "refused"),
        ("negative/rup1_oversize_chunk_001.json", "forged"),
    ] {
        for case in vector(file)["expected"][key].as_array().unwrap() {
            let f = frame_of(case);
            let ok = case["result"] == "OK";
            assert_eq!(decode(&f).is_ok(), ok, "{file} {}", case["name"]);
            let listener = match decode_for_listener(&f) {
                ListenerDecode::Request(..) => "REQUEST".to_string(),
                ListenerDecode::Have(_) => "HAVE".into(),
                ListenerDecode::Refuse(_, c) => format!("ERROR {}", c.name()),
                ListenerDecode::Drop => "DROP".into(),
            };
            assert_eq!(case["listener"].as_str().unwrap_or("DROP"), listener);
            frames.push(f);
        }
    }
    let mut inputs = Vec::new();
    for f in frames {
        inputs.extend([
            f[..f.len() - 1].to_vec(),
            [&f[..], &[0]].concat(),
            // The body behind each op (the target's second reading).
            [
                &[f.get(5).copied().unwrap_or(0)][..],
                f.get(10..).unwrap_or(&[]),
            ]
            .concat(),
            f,
        ]);
    }
    for d in &inputs {
        fuzz_targets::rup1_frame(d);
    }
}

/// Deterministic byte mutations — CI-safe fuzz smoke (not a long campaign).
#[test]
fn fuzz_smoke_envelope_and_frames() {
    let seeds: &[&[u8]] = &[
        &[],
        b"RVN1",
        b"RVN1\x01",
        b"RSO1",
        b"RIH1",
        b"RRH1",
        b"RRH1\x01",
        b"RLX1\x01",
        &[0xff; 8],
        &[0x00; 200],
        b"\x1b[31mRVN1",
    ];
    let mut corpus = Vec::new();
    for s in seeds {
        corpus.push(s.to_vec());
        // Mutations
        let mut m = s.to_vec();
        if !m.is_empty() {
            m[0] ^= 0x5a;
            corpus.push(m.clone());
            m.push(0xaa);
            corpus.push(m);
        }
        let mut big = s.to_vec();
        big.extend(std::iter::repeat_n(0x41, 4096));
        corpus.push(big);
    }
    // Also mutate a well-formed framed payload.
    if let Ok(f) = frame(b"RVN1demo") {
        corpus.push(f.clone());
        let mut t = f;
        if t.len() > 5 {
            t[5] ^= 0xff;
        }
        corpus.push(t);
    }

    let hello_binding = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: [0u8; 32],
        noise_static_pub: [0u8; 32],
    };
    for c in &corpus {
        let _ = Envelope::unpack(c);
        let _ = StoreObject::unpack(c);
        let _ = unpack_verify_hello(c, &hello_binding);
        let _ = deframe_prefix(c);
        fuzz_targets::rrh1_frame(c);
    }
}

/// Deterministic xorshift64* — reproducible "random" inputs without a
/// dev-dependency. Override with RAVEN_FUZZ_SMOKE_SEED / RAVEN_FUZZ_SMOKE_ROUNDS.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn rvn1_vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../shared-vectors/rvn1")
}

/// Collect structured seeds from the committed vectors: every hex string
/// (decoded) and every JSON object (re-serialised), so mutations start from
/// well-formed envelopes, PairInit, RLB1 offers, revocations, certs, bundles.
fn collect_vector_seeds(dir: &Path, out: &mut Vec<Vec<u8>>) {
    fn walk(v: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
        match v {
            serde_json::Value::String(s) => {
                if s.len() >= 8 && s.len() % 2 == 0 {
                    if let Ok(b) = hex::decode(s) {
                        out.push(b);
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(m) => {
                out.push(serde_json::to_vec(v).expect("re-serialise"));
                m.values().for_each(|x| walk(x, out));
            }
            _ => {}
        }
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_vector_seeds(&p, out);
        } else if p.extension().is_some_and(|x| x == "json") {
            let raw = std::fs::read(&p).expect("read vector");
            let v: serde_json::Value = serde_json::from_slice(&raw).expect("vector json");
            walk(&v, out);
        }
    }
}

fn mutate(rng: &mut XorShift, seed: &[u8]) -> Vec<u8> {
    let mut m = seed.to_vec();
    match rng.below(7) {
        0 if !m.is_empty() => {
            let i = rng.below(m.len());
            m[i] ^= 1 << rng.below(8);
        }
        1 if !m.is_empty() => {
            let i = rng.below(m.len());
            m[i] = rng.next() as u8;
        }
        2 => m.truncate(rng.below(m.len() + 1)),
        3 => {
            let at = rng.below(m.len() + 1);
            let n = 1 + rng.below(16);
            let extra = rng.bytes(n);
            m.splice(at..at, extra);
        }
        4 if m.len() >= 4 => {
            // Hit length fields with boundary values.
            let at = rng.below(m.len() - 3);
            let vals = [0u32, 1, 0x7fff_ffff, u32::MAX, m.len() as u32];
            let v = vals[rng.below(vals.len())];
            m[at..at + 4].copy_from_slice(&v.to_be_bytes());
        }
        5 => m.push(rng.next() as u8),
        _ => {
            let n = 1 + rng.below(4);
            for _ in 0..n {
                if m.is_empty() {
                    break;
                }
                let i = rng.below(m.len());
                m[i] = rng.next() as u8;
            }
        }
    }
    m
}

#[test]
fn fuzz_smoke_all_targets_random() {
    use raven_core::ipc::{encode_request, IpcRequest, IPC_VERSION};

    let mut seeds = Vec::new();
    collect_vector_seeds(&rvn1_vectors_root(), &mut seeds);
    for req in [
        IpcRequest::Ping { v: IPC_VERSION },
        IpcRequest::status(),
        IpcRequest::SetPolicy {
            v: IPC_VERSION,
            bridge: Some(true),
            store: None,
            relay: Some(false),
        },
    ] {
        seeds.push(encode_request(&req).expect("encode ipc"));
    }
    // Route hints: bare headers; the RRH1 frames, RELAY_OFFER records and
    // RLX1 payloads come from shared-vectors/rvn1/route_hints (with its
    // negative/ folder) and lan/noise_xx_handshake_002.
    seeds.extend([b"RRH1".to_vec(), b"RRH1\x01".to_vec(), b"RLX1\x01".to_vec()]);
    let framed: Vec<Vec<u8>> = seeds.iter().filter_map(|s| frame(s).ok()).collect();
    seeds.extend(framed);
    // Relay kit inputs (`relay_inputs`): the first byte picks the parser.
    let relay_peer = raven_core::p2p_route::peer_id_from_ed25519_public(&[7; 32]);
    let via_tcp = format!("/ip4/203.0.113.7/tcp/7423/p2p/{relay_peer}");
    let via_443 = format!("/dns4/relay.example.org/tcp/443/p2p/{relay_peer}");
    for (parser, text) in [
        (0u8, via_tcp.clone()),
        (1, format!("via={via_tcp}\nvia={via_443}")),
        (2, "443".to_string()),
        (2, "7443:443".to_string()),
        (3, "relay.example.org".to_string()),
        (3, "[2001:db8::1]".to_string()),
        (
            4,
            format!(r#"{{"version":1,"peers":[{{"peer_id":"{relay_peer}","label":"bob"}}]}}"#),
        ),
        (
            4,
            format!(
                r#"{{"version":1,"peer_id":"{relay_peer}","listen_addrs":["/ip4/0.0.0.0/tcp/7423"],"counts":{{"open":false,"allowed_peers":1,"reservations":1,"circuits":0,"reservations_refused":0,"circuits_refused":0}},"updated_at_ms":1,"advertised":["/ip4/203.0.113.7/tcp/443"]}}"#
            ),
        ),
    ] {
        seeds.push([&[parser], text.as_bytes()].concat());
    }
    // Diagnosis reason blocks (`reach_tokens`): each reason, a joined
    // multi-route text, one inside "(technical: …)", an F9 `no_route` and
    // the Phase 3 local network reasons.
    for why in raven_core::reach_diag::Why::ALL {
        seeds.push(
            format!(
                "P2P_UNREACHABLE: unreachable; reach: why={} me=unreachable relay=mine1 heard=3h stale=1 src=card asof=30s",
                why.token()
            )
            .into_bytes(),
        );
    }
    seeds.extend([
        b"; reach: why=no_route me=unknown".to_vec(),
        b"; reach: why=lan_off".to_vec(),
        b"; reach: why=lan_no_answer heard=5m asof=30s".to_vec(),
        b"lan_dial NOT_REACHABLE: x; reach: why=contact_offline heard=2d; p2p_dial P2P_UNREACHABLE: y; reach: why=both_nat me=unreachable src=card".to_vec(),
        b"(technical: ipc P2P_DIAL: P2P_UNREACHABLE: z; reach: why=relay_asleep relay=mine2)".to_vec(),
    ]);
    // Proxy settings and bypass lists (`proxy_setting`): the vectors give
    // them only inside JSON objects.
    seeds.extend(
        [
            "http://user:pass@proxy.example:3128",
            "[2001:db8::1]:8080",
            "socks5h://127.0.0.1:1080",
            "example.com, .example.net;10.0.0.0/8 <local> 169.254/16 [2001:db8::7]:443",
            "http=a.example:1;https=b.example:2",
        ]
        .map(|s| s.as_bytes().to_vec()),
    );
    // Relay schedule texts (`relay_schedule_text`): the vectors give them
    // only inside JSON objects.
    let schedule = raven_core::peer_rotation::format_relay_schedule(
        &raven_core::identity::Identity::from_seed(&[0x51; 32]),
        741,
        3,
    );
    seeds.extend([schedule.into_bytes(), b"raven-relay-schedule/1".to_vec()]);
    // LAN beacon datagrams (`lan_beacon_datagram`): the committed query and
    // answer come from shared-vectors/rvn1/lan_beacon; all zeros at both
    // ends of each length range (Phase 6b W-B3) and one byte outside each.
    for len in [47, 48, 49, 63, 64, 159, 160, 161, 191, 192] {
        seeds.push(vec![0; len]);
    }
    assert!(seeds.len() > 100, "vector seed corpus unexpectedly small");

    // The round-trip assertions inside the targets only fire on accepted
    // inputs; make sure the seed corpus actually reaches them.
    let accepted = |f: &dyn Fn(&[u8]) -> bool| seeds.iter().filter(|s| f(s)).count();
    assert!(
        accepted(&|s| Envelope::unpack(s).is_some()) > 0,
        "no valid RVN1 seed"
    );
    assert!(
        accepted(&|s| raven_core::pair_init::decode_init(s).is_ok()) > 0,
        "no PairInit seed"
    );
    // RAL1 letters and both inner kinds: shared-vectors/rvn1/letter.
    {
        use raven_core::async_letter::{decode, decode_inner, Ral1Kind};
        assert!(accepted(&|s| decode(s).is_ok()) > 0, "no RAL1 letter seed");
        for kind in [Ral1Kind::Letter, Ral1Kind::Reply] {
            assert!(
                accepted(&|s| decode_inner(kind, s).is_ok()) > 0,
                "no RAL1 {kind:?} inner seed"
            );
        }
    }
    // RHW1 records, HANDOFF requests and TAGS: shared-vectors/rvn1/custody.
    {
        use raven_core::friend_custody::{decode_request, RequestDecode, Rfc1Request};
        assert!(
            accepted(&|s| raven_core::custody_handoff::Rhw1::decode(s).is_ok()) > 0,
            "no RHW1 record seed"
        );
        assert!(
            accepted(&|s| matches!(
                decode_request(s),
                Ok(RequestDecode::Request(_, Rfc1Request::Handoff { .. }))
            )) > 0,
            "no HANDOFF request seed"
        );
        assert!(
            accepted(&|s| matches!(
                decode_request(s),
                Ok(RequestDecode::Request(_, Rfc1Request::Tags { .. }))
            )) > 0,
            "no TAGS request seed"
        );
    }
    assert!(
        accepted(&|s| raven_core::lan_rlb1::decode_offer(s).is_ok()) > 0,
        "no RLB1 seed"
    );
    // RAD1 advisories and release key sets: shared-vectors/rvn1/update.
    assert!(
        accepted(&|s| raven_core::advisory::Advisory::decode(s).is_ok()) > 0,
        "no RAD1 seed"
    );
    assert!(
        accepted(&|s| raven_core::release_keys::KeySet::decode(s).is_ok()) > 0,
        "no release key set seed"
    );
    // RTL1 tree heads and snapshots: shared-vectors/rvn1/update.
    assert!(
        accepted(&|s| raven_core::tlog::Sth::decode(s).is_ok()) > 0,
        "no RTL1 tree head seed"
    );
    // RUP1 frames of every role: shared-vectors/rvn1/update/rup1_*.
    {
        use raven_core::update_exchange::{decode, Role};
        for role in [Role::OneWay, Role::Request, Role::Reply { terminal: true }] {
            assert!(
                accepted(&|s| decode(s).is_ok_and(|(_, m)| m.role() == role)) > 0,
                "no RUP1 {role:?} seed"
            );
        }
    }
    assert!(
        accepted(&|s| raven_core::tlog::Snapshot::decode(s).is_ok()) > 0,
        "no RTL1 snapshot seed"
    );
    assert!(
        accepted(&|s| raven_core::device_revocation::DeviceRevocationV1::decode(s).is_ok()) > 0,
        "no device revocation seed"
    );
    assert!(
        accepted(&|s| raven_core::ipc::decode_request(s).is_ok()) > 0,
        "no IPC seed"
    );
    assert!(
        accepted(&|s| deframe_prefix(s).is_some()) > 0,
        "no framed seed"
    );
    assert!(
        accepted(&|s| raven_core::route_hints::decode(s).is_some()) > 0,
        "no RRH1 seed"
    );
    assert!(
        accepted(&|s| raven_core::route_hints::rlx1_caps(s) != 0) > 0,
        "no RLX1 seed"
    );
    assert!(
        accepted(&|s| raven_core::route_hints::decode_offer(s).is_ok()) > 0,
        "no RELAY_OFFER seed"
    );
    assert!(
        accepted(&|s| raven_core::route_hints::decode(s).is_some_and(|h| !h.offers.is_empty())) > 0,
        "no RRH1 seed with a relay offer"
    );
    // Port mapping replies (`portmap_reply`): shared-vectors/rvn1/portmap.
    {
        use raven_core::portmap::{decode_reply, NatPmpResp, Reply};
        assert!(
            accepted(&|s| matches!(
                decode_reply(s, Some(1), None),
                Ok(Reply::Pcp(p)) if p.map.is_some()
            )) > 0,
            "no PCP MAP reply seed"
        );
        assert!(
            accepted(&|s| matches!(decode_reply(s, Some(0), None), Ok(Reply::Pcp(_)))) > 0,
            "no PCP ANNOUNCE reply seed"
        );
        assert!(
            accepted(&|s| matches!(
                decode_reply(s, None, Some(2)),
                Ok(Reply::NatPmp(NatPmpResp::Map { .. }))
            )) > 0,
            "no NAT-PMP mapping reply seed"
        );
        assert!(
            accepted(&|s| matches!(
                decode_reply(s, None, Some(0)),
                Ok(Reply::NatPmp(NatPmpResp::ExternalAddr { .. }))
            )) > 0,
            "no NAT-PMP address reply seed"
        );
        assert!(
            accepted(&|s| decode_reply(s, Some(1), None) == Ok(Reply::NatPmpOnly)) > 0,
            "no NAT-PMP-only answer seed"
        );
    }
    assert!(
        accepted(&|s| matches!(
            raven_core::net_proxy::parse_setting(&String::from_utf8_lossy(s)),
            Ok(raven_core::net_proxy::ProxySetting::Url(u)) if u.has_credentials()
        )) > 0,
        "no proxy URL seed with credentials"
    );
    assert!(
        accepted(&|s| {
            raven_core::peer_rotation::parse_relay_schedule(&String::from_utf8_lossy(s))
                .is_ok_and(|e| e.len() == 3)
        }) > 0,
        "no relay schedule seed"
    );
    // WebSocket frames (`ws_frame`): shared-vectors/rvn1/wss/rws1_ws_frames_001.json.
    assert!(
        accepted(&|s| matches!(
            raven_core::ws_frame::parse_head(s, true),
            Ok(Some(h)) if h.op == raven_core::ws_frame::OP_BINARY && s.len() == h.frame_len()
        )) > 0,
        "no whole masked binary WebSocket frame seed"
    );
    assert!(
        accepted(&|s| {
            raven_core::route_hints::decode(s)
                .is_some_and(|h| h.custody_offer.is_some() && !h.custodian_tags.is_empty())
        }) > 0,
        "no RRH1 seed with custody entries"
    );
    assert!(
        accepted(&|s| {
            raven_core::reach_diag::Diag::find(&String::from_utf8_lossy(s))
                .is_some_and(|d| d.why == raven_core::reach_diag::Why::NoRoute)
        }) > 0,
        "no reason block seed with no_route"
    );
    let beacon = fuzz_targets::lan_beacon_fixture();
    assert!(
        accepted(&|s| {
            !raven_core::lan_beacon::match_query(s, beacon.sources[0], beacon.epoch, &beacon.book)
                .is_empty()
        }) > 0,
        "no LAN beacon query seed"
    );
    assert!(
        accepted(&|s| {
            beacon.book.iter().any(|k| {
                let (src, dst) = (beacon.answer_src, beacon.answer_dst);
                raven_core::lan_beacon::open_answer(s, k, &beacon.q_nonce, src, dst).is_some()
            })
        }) > 0,
        "no LAN beacon answer seed"
    );
    // Each relay_inputs parser accepts a seed tagged for it.
    {
        use raven_core::p2p_route::{
            parse_extra_tcp, parse_via, relay_public_addrs, split_relay_tokens,
        };
        use raven_core::relay_allow::{RelayAllowList, RelayStatusFile};
        let tagged = |parser: u8, s: &[u8]| match s.split_first() {
            Some((&p, rest)) if p == parser => Some(String::from_utf8_lossy(rest).into_owned()),
            _ => None,
        };
        let json = |s: &[u8]| {
            s.split_first()
                .filter(|(p, _)| **p == 4)
                .map(|(_, r)| r.to_vec())
        };
        for (what, hits) in [
            (
                "via",
                accepted(&|s| tagged(0, s).is_some_and(|t| parse_via(&t).is_ok())),
            ),
            (
                "pasted via= block",
                accepted(&|s| {
                    tagged(1, s).is_some_and(|t| split_relay_tokens(&t).is_ok_and(|v| v.len() == 2))
                }),
            ),
            (
                "--also-tcp LOCAL:PUBLIC",
                accepted(&|s| {
                    tagged(2, s)
                        .is_some_and(|t| parse_extra_tcp(&t).is_ok_and(|e| e.local != e.public))
                }),
            ),
            (
                "--public-host",
                accepted(&|s| {
                    tagged(3, s).is_some_and(|t| {
                        let e = parse_extra_tcp("443").unwrap();
                        relay_public_addrs(&t, 7423, &[e]).is_ok()
                    })
                }),
            ),
            (
                "relay_allow.json",
                accepted(&|s| {
                    json(s).is_some_and(|j| {
                        serde_json::from_slice::<RelayAllowList>(&j)
                            .is_ok_and(|l| l.peers.len() == 1)
                    })
                }),
            ),
            (
                "relay_status.json",
                accepted(&|s| {
                    json(s).is_some_and(|j| {
                        serde_json::from_slice::<RelayStatusFile>(&j)
                            .is_ok_and(|st| st.advertised.len() == 1)
                    })
                }),
            ),
        ] {
            assert!(hits > 0, "no relay_inputs seed reaches the {what} parser");
        }
    }

    let mut rng = XorShift(env_u64("RAVEN_FUZZ_SMOKE_SEED", 0x5241_5645_4e5f_4655) | 1);
    let rounds = env_u64("RAVEN_FUZZ_SMOKE_ROUNDS", 6) as usize;
    let mut inputs = 0usize;
    for seed in &seeds {
        for (_, target) in fuzz_targets::ALL_TARGETS {
            target(seed);
        }
        inputs += 1;
        for _ in 0..rounds {
            let m = mutate(&mut rng, seed);
            for (_, target) in fuzz_targets::ALL_TARGETS {
                target(&m);
            }
            inputs += 1;
        }
    }
    // Unstructured noise of assorted lengths.
    for _ in 0..(rounds * 200) {
        let len = rng.below(2048);
        let noise = rng.bytes(len);
        for (_, target) in fuzz_targets::ALL_TARGETS {
            target(&noise);
        }
        inputs += 1;
    }
    assert!(inputs > seeds.len() * rounds);
}

#[test]
fn ansi_and_bidi_sanitization() {
    let nasty = "\u{1b}[32malice\u{202E}bob\u{1b}[0m";
    assert!(had_dangerous_controls(nasty));
    let clean = sanitize_terminal_text(nasty);
    assert_eq!(clean, "alicebob");
    assert!(!clean.contains('\u{1b}'));
    assert!(!clean.contains('\u{202E}'));
}

#[test]
fn scale_1k_queue_enqueue_dedup_ack() {
    // Strengthened 1k subset of the 10k reliability script — always runs in CI.
    use raven_core::queue::{DeliveryState, OutgoingQueue, QueueItem};
    let dir = tempfile::tempdir().unwrap();
    let q = OutgoingQueue::open(&dir.path().join("q.sqlite")).unwrap();
    const N: u32 = 1_000;
    for i in 0..N {
        let mut mid = [0u8; 16];
        mid[..4].copy_from_slice(&i.to_be_bytes());
        q.enqueue(&QueueItem {
            message_id: mid,
            packed_envelope: {
                let mut v = vec![0x52, 0x56, 0x4E, 0x31, 1];
                v.extend_from_slice(&i.to_be_bytes());
                v
            },
            peer_addr: format!("peer-{}", i % 17),
            state: DeliveryState::Queued,
            created_at_ms: i as u64,
        })
        .unwrap();
        if i % 2 == 0 {
            q.mark_state(&mid, DeliveryState::Sent).unwrap();
        }
        assert!(!q.dedup_check_and_insert(&mid, i as u64).unwrap());
        assert!(q.dedup_check_and_insert(&mid, i as u64 + 1).unwrap());
    }
    assert_eq!(q.pending().unwrap().len(), N as usize);
    for i in 0..N {
        let mut mid = [0u8; 16];
        mid[..4].copy_from_slice(&i.to_be_bytes());
        q.mark_state(&mid, DeliveryState::Delivered).unwrap();
    }
    assert!(q.pending().unwrap().is_empty());
}
