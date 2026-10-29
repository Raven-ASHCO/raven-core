//! RELAY_OFFER, RRH1 entry type 0x20 (`protocol/RAVEN_ROUTE_HINTS_V1.md`
//! §11): a contact offers this receiver a relay it runs for its contacts.
//!
//! The friend relay (any-network plan C6) is a stock Circuit Relay v2 server
//! under its own relay key, never the operator's profile PeerId, and it
//! admits the operator's relay members only. The operator tells each member
//! about it in the RRH1 it sends that member, one record per relay. A record
//! has no TTL and no signature of its own: it lives exactly as long as the
//! RRH1 snapshot that carried it, and the link authenticates it with the rest
//! of the frame.
//!
//! This module is the record codec ([`encode_offer`], [`decode_offer`]) and
//! the address rule receivers apply ([`RelayOfferRecord::usable_addrs`]).
//! [`super::decode`] runs [`decode_offer`] on every 0x20 entry: a record of
//! another version is ignored and a malformed one dropped, never the frame.

use crate::p2p_route::{is_global_ip, parse_host_transport, peer_id_from_ed25519_public};

/// The record version this build reads; any other is
/// [`OfferDecode::Unsupported`].
pub const RELAY_OFFER_VERSION: u8 = 1;
/// Flag bit 0: a member reserved on the relay from a globally routable IP
/// within the last 24 hours, or UPnP mapped the relay's port.
pub const FLAG_CONFIRMED: u8 = 1;
/// Flag bit 1: the relay answers AutoNAT v2.
pub const FLAG_AUTONAT: u8 = 2;
/// Flag bit 2: one of the addresses is `/tcp/443`.
pub const FLAG_PORT_443: u8 = 4;
/// The flag bits a writer may set; readers ignore the others.
pub const OFFER_FLAGS_KNOWN: u8 = FLAG_CONFIRMED | FLAG_AUTONAT | FLAG_PORT_443;
/// Addresses one record names: 1 to 4.
pub const MAX_OFFER_ADDRS: usize = 4;
/// Shortest address text a record may carry ...
pub const OFFER_ADDR_MIN_LEN: usize = 8;
/// ... and the longest.
pub const OFFER_ADDR_MAX_LEN: usize = 120;
/// Version, flags, relay_pub and n_addrs.
const OFFER_HEADER_LEN: usize = 35;
/// Longest version-1 record: 519 bytes.
pub const RELAY_OFFER_MAX_LEN: usize =
    OFFER_HEADER_LEN + MAX_OFFER_ADDRS * (1 + OFFER_ADDR_MAX_LEN);

/// One RELAY_OFFER record (§11.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayOfferRecord {
    /// [`FLAG_CONFIRMED`], [`FLAG_AUTONAT`], [`FLAG_PORT_443`], kept as
    /// received: readers test the bits they know and ignore the rest;
    /// writers set only [`OFFER_FLAGS_KNOWN`].
    pub flags: u8,
    /// The Ed25519 public key of the relay's libp2p key (a valid point). Its
    /// PeerId is [`Self::relay_peer_id`]; receivers refuse the sender's own
    /// p2p key and their own keys here (§11.3).
    pub relay_pub: [u8; 32],
    /// 1 to [`MAX_OFFER_ADDRS`] distinct addresses, each the canonical host
    /// and transport text [`parse_host_transport`] returns:
    /// `/ip4|ip6|dns|dns4|dns6/<host>/(tcp/P | udp/P/quic-v1)`, no `/p2p`,
    /// never a circuit.
    pub addrs: Vec<String>,
}

impl RelayOfferRecord {
    /// The relay's PeerId (`12D3KooW…`): it is dialled at
    /// `<addr>/p2p/<PeerId>`.
    pub fn relay_peer_id(&self) -> String {
        peer_id_from_ed25519_public(&self.relay_pub)
    }

    /// The addresses a receiver may dial (§11.3), in record order: DNS names
    /// and globally routable IP literals ([`is_global_ip`]). `lab_local`
    /// (debug `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1`,
    /// [`crate::p2p_local_candidates_enabled`]; inert in release builds)
    /// admits loopback and private addresses too. A receiver drops an offer
    /// left with none.
    pub fn usable_addrs(&self, lab_local: bool) -> Vec<&str> {
        self.addrs
            .iter()
            .map(String::as_str)
            .filter(|a| lab_local || super::host_ip(a).is_none_or(is_global_ip))
            .collect()
    }
}

/// Why [`decode_offer`] refused a record. Either way the frame is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferDecode {
    /// Another record version (a later format): ignored, without a log.
    Unsupported,
    /// A version-1 rule is broken: the record is dropped (`RRH1_MALFORMED`,
    /// counts-only debug log).
    Malformed,
}

/// A record's bytes (§11.1). Every field is written as given, so only a
/// record [`decode_offer`] accepts round-trips; a count or a length that
/// does not fit a byte is written as 0, which [`decode_offer`] refuses.
pub fn encode_offer(r: &RelayOfferRecord) -> Vec<u8> {
    let byte = |n: usize| u8::try_from(n).unwrap_or(0);
    let mut out =
        Vec::with_capacity(OFFER_HEADER_LEN + r.addrs.iter().map(|a| 1 + a.len()).sum::<usize>());
    out.push(RELAY_OFFER_VERSION);
    out.push(r.flags);
    out.extend_from_slice(&r.relay_pub);
    out.push(byte(r.addrs.len()));
    for addr in &r.addrs {
        out.push(byte(addr.len()));
        out.extend_from_slice(addr.as_bytes());
    }
    out
}

/// Decode one record (§11.2). [`OfferDecode::Unsupported`] when the first
/// byte is not [`RELAY_OFFER_VERSION`]; otherwise [`OfferDecode::Malformed`]
/// on any of:
/// - no version byte, or a record cut short;
/// - a relay key that is not a valid Ed25519 point;
/// - no address, or more than [`MAX_OFFER_ADDRS`];
/// - an address whose length is outside
///   [`OFFER_ADDR_MIN_LEN`]..=[`OFFER_ADDR_MAX_LEN`], that is not exactly the
///   canonical host and transport text, or that repeats an earlier one;
/// - bytes after the last address.
pub fn decode_offer(body: &[u8]) -> Result<RelayOfferRecord, OfferDecode> {
    use OfferDecode::{Malformed, Unsupported};
    match body.first() {
        None => return Err(Malformed),
        Some(&version) if version != RELAY_OFFER_VERSION => return Err(Unsupported),
        Some(_) => {}
    }
    if !(OFFER_HEADER_LEN..=RELAY_OFFER_MAX_LEN).contains(&body.len()) {
        return Err(Malformed);
    }
    let flags = body[1];
    let relay_pub: [u8; 32] = body[2..34].try_into().map_err(|_| Malformed)?;
    if ed25519_dalek::VerifyingKey::from_bytes(&relay_pub).is_err() {
        return Err(Malformed);
    }
    let n = usize::from(body[34]);
    if !(1..=MAX_OFFER_ADDRS).contains(&n) {
        return Err(Malformed);
    }
    let mut addrs: Vec<String> = Vec::with_capacity(n);
    let mut rest = &body[OFFER_HEADER_LEN..];
    for _ in 0..n {
        let (&len, r) = rest.split_first().ok_or(Malformed)?;
        let len = usize::from(len);
        if !(OFFER_ADDR_MIN_LEN..=OFFER_ADDR_MAX_LEN).contains(&len) {
            return Err(Malformed);
        }
        let text = std::str::from_utf8(r.get(..len).ok_or(Malformed)?).map_err(|_| Malformed)?;
        // Canonical only: parsing gives back exactly the same text (no
        // `/p2p`, no circuit, nothing after the transport).
        if parse_host_transport(text).ok().as_deref() != Some(text)
            || addrs.iter().any(|a| a == text)
        {
            return Err(Malformed);
        }
        addrs.push(text.to_owned());
        rest = &r[len..];
    }
    if !rest.is_empty() {
        return Err(Malformed);
    }
    Ok(RelayOfferRecord {
        flags,
        relay_pub,
        addrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_route::{parse_via, peer_id_bytes};
    use crate::route_hints::tests::{assert_vector, entries, full, pid, raw, vector, G, SENDER};
    use crate::route_hints::{
        decode, encode, RouteHints, DIRECT_MAX_LEN, MAX_DIRECT, MAX_RELAY_ENTRIES,
        MAX_RELAY_OFFERS, RELAY_MAX_LEN, RRH1_DEFAULT_TTL_S, RRH1_MAX_LEN, T_P2P_ID, T_RELAY_OFFER,
    };
    use rand::{Rng, RngCore};
    use serde_json::json;

    /// Not an Ed25519 point: no curve point has y = 2.
    const BAD_POINT: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 2;
        b
    };

    /// The public key of a relay's own Ed25519 key from `seed` (like the
    /// friend relay's `relay_key.ed25519`, not a profile-derived key).
    fn relay_pub(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn offer(seed: u8, flags: u8, addrs: &[&str]) -> RelayOfferRecord {
        RelayOfferRecord {
            flags,
            relay_pub: relay_pub(seed),
            addrs: addrs.iter().map(|a| a.to_string()).collect(),
        }
    }

    /// The record of `rrh1_relay_offer_001.json`.
    fn ip4_offer() -> RelayOfferRecord {
        offer(
            0x63,
            FLAG_CONFIRMED | FLAG_AUTONAT,
            &["/ip4/11.0.2.7/tcp/7427", "/ip4/11.0.2.7/udp/7427/quic-v1"],
        )
    }

    /// The record of `rrh1_relay_offer_dns_002.json`.
    fn dns_offer() -> RelayOfferRecord {
        offer(
            0x64,
            FLAG_AUTONAT | FLAG_PORT_443,
            &[
                "/dns4/relay.example.org/tcp/7427",
                "/dns4/relay.example.org/udp/7427/quic-v1",
                "/dns4/relay.example.org/tcp/443",
            ],
        )
    }

    /// A record from raw parts (any version, any count).
    fn body(version: u8, flags: u8, key: [u8; 32], addrs: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![version, flags];
        out.extend_from_slice(&key);
        out.push(u8::try_from(addrs.len()).unwrap());
        for addr in addrs {
            out.push(u8::try_from(addr.len()).unwrap());
            out.extend_from_slice(addr);
        }
        out
    }

    /// An RRH1 frame from the vector sender: its P2P_ID, then each of
    /// `records` as a RELAY_OFFER entry.
    fn frame_with(records: &[Vec<u8>]) -> Vec<u8> {
        let mut e = vec![(T_P2P_ID, peer_id_bytes(&pid(SENDER)).unwrap().to_vec())];
        e.extend(records.iter().map(|r| (T_RELAY_OFFER, r.clone())));
        raw(G, RRH1_DEFAULT_TTL_S, &e)
    }

    /// What a receiver built before §11 (the first draft's decoder) reads
    /// from `frame`: 0x20 was an unregistered type then, skipped like any
    /// other. The current decoder reads the frame with its 0x20 entries
    /// retyped to another unregistered type (0x7f) exactly that way.
    fn decode_before_relay_records(frame: &[u8]) -> Option<RouteHints> {
        let retyped: Vec<(u8, Vec<u8>)> = entries(frame)
            .into_iter()
            .map(|(kind, value)| (if kind == T_RELAY_OFFER { 0x7f } else { kind }, value))
            .collect();
        let generation = u64::from_be_bytes(frame[5..13].try_into().unwrap());
        let ttl_s = u32::from_be_bytes(frame[13..17].try_into().unwrap());
        decode(&raw(generation, ttl_s, &retyped))
    }

    /// A 120-character address (the longest a record carries), its labels
    /// at most 63 characters (RWS1 §2.1).
    fn longest_addr(n: u8) -> String {
        let a = format!(
            "/dns4/{}.{}{n}.example.org/tcp/7427",
            "r".repeat(46),
            "r".repeat(45)
        );
        assert_eq!(a.len(), OFFER_ADDR_MAX_LEN);
        a
    }

    /// The largest record: four 120-character addresses.
    fn largest(seed: u8) -> RelayOfferRecord {
        let addrs: Vec<String> = (1..=4).map(longest_addr).collect();
        RelayOfferRecord {
            flags: OFFER_FLAGS_KNOWN,
            relay_pub: relay_pub(seed),
            addrs,
        }
    }

    /// What a decoded record is, as the vectors record it.
    fn offer_json(r: &RelayOfferRecord) -> serde_json::Value {
        let peer = r.relay_peer_id();
        json!({
            "version": RELAY_OFFER_VERSION,
            "flags": r.flags,
            "confirmed": r.flags & FLAG_CONFIRMED != 0,
            "autonat": r.flags & FLAG_AUTONAT != 0,
            "port_443": r.flags & FLAG_PORT_443 != 0,
            "relay_pub_hex": hex::encode(r.relay_pub),
            "relay_peer_id": peer,
            "addrs": r.addrs,
            "dial": r
                .addrs
                .iter()
                .map(|a| parse_via(&format!("{a}/p2p/{peer}")).unwrap().text)
                .collect::<Vec<_>>(),
        })
    }

    /// The negative vectors (§11.2): file stem, name, record and the rule it
    /// breaks. Each breaks exactly one rule.
    fn negatives() -> Vec<(&'static str, &'static str, Vec<u8>, &'static str)> {
        let key = relay_pub(0x63);
        let addr = |n: u8| format!("/ip4/11.0.2.{n}/tcp/7427").into_bytes();
        let p2p_suffix = format!(
            "/ip4/11.0.2.7/tcp/7427/p2p/{}",
            peer_id_from_ed25519_public(&key)
        );
        vec![
            (
                "no_addr",
                "RELAY_OFFER without an address",
                body(1, 0, key, &[]),
                "n_addrs is 0 (1..=4)",
            ),
            (
                "five_addrs",
                "RELAY_OFFER with five addresses",
                body(
                    1,
                    0,
                    key,
                    &[&addr(1), &addr(2), &addr(3), &addr(4), &addr(5)],
                ),
                "n_addrs is 5 (1..=4)",
            ),
            (
                "circuit",
                "RELAY_OFFER address that is a circuit",
                body(1, 0, key, &[b"/ip4/11.0.2.7/tcp/7427/p2p-circuit"]),
                "an address goes on past its transport (/p2p-circuit): host and transport only",
            ),
            (
                "p2p_suffix",
                "RELAY_OFFER address with a /p2p suffix",
                body(1, 0, key, &[p2p_suffix.as_bytes()]),
                "an address goes on past its transport (/p2p/<PeerId>): host and transport only",
            ),
            (
                "trailing",
                "RELAY_OFFER with a byte after its last address",
                [encode_offer(&ip4_offer()).as_slice(), &[0]].concat(),
                "bytes after the last address",
            ),
            (
                "noncanonical",
                "RELAY_OFFER address not in canonical form",
                body(1, 0, key, &[b"/dns4/Relay.example.org/tcp/7427"]),
                "an address is not its canonical text (DNS names are lowercase)",
            ),
            (
                "bad_point",
                "RELAY_OFFER relay key that is not an Ed25519 point",
                body(1, 0, BAD_POINT, &[&addr(7)]),
                "relay_pub is not a valid Ed25519 point",
            ),
        ]
    }

    #[test]
    fn offer_constants_hold_the_layout() {
        assert_eq!(RELAY_OFFER_MAX_LEN, 519);
        assert_eq!(OFFER_FLAGS_KNOWN, 0b111);
        assert_eq!(MAX_RELAY_OFFERS, 2);
        assert_eq!(encode_offer(&largest(0x63)).len(), RELAY_OFFER_MAX_LEN);
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&BAD_POINT).is_err());
    }

    /// KATs (spec §11, §10). Regenerate with `RAVEN_REGEN_RRH1_VECTORS=1`
    /// only when the wire format changes on purpose.
    #[test]
    fn offer_record_known_answer_vectors() {
        const LAYOUT: &str = "RELAY_OFFER v1 record (RAVEN_ROUTE_HINTS_V1 §11.1): version 0x01 | \
                              flags u8 (bit0 CONFIRMED, bit1 AUTONAT, bit2 PORT_443) | relay_pub \
                              [32] | n_addrs u8 (1..=4) | n x (len u8 (8..=120) | canonical ASCII \
                              host+transport multiaddr). It rides RRH1 as entry type 0x20 (type \
                              u8 | len u16 BE | record)";
        const KEY: &str = "The relay key is the Ed25519 public key of the relay seed (the \
                           relay's own key, never a profile key); its PeerId is the libp2p \
                           Ed25519 PeerId of relay_pub, dialled at <addr>/p2p/<PeerId>";
        let ip4 = ip4_offer();
        let dns = dns_offer();
        let ip4_record = encode_offer(&ip4);
        let dns_record = encode_offer(&dns);
        // The layout, byte by byte.
        let first = b"/ip4/11.0.2.7/tcp/7427";
        assert_eq!(ip4_record[..2], [RELAY_OFFER_VERSION, 3]);
        assert_eq!(ip4_record[2..34], ip4.relay_pub);
        assert_eq!(ip4_record[34], 2);
        assert_eq!(usize::from(ip4_record[35]), first.len());
        assert_eq!(&ip4_record[36..36 + first.len()], first);
        assert_eq!(ip4_record.len(), 35 + (1 + 22) + (1 + 30));
        for (r, record) in [(&ip4, &ip4_record), (&dns, &dns_record)] {
            assert_eq!(decode_offer(record).as_ref(), Ok(r));
        }

        // The frames: one offer, then two (the most a frame carries), after
        // the sender's P2P_ID, in ascending type order.
        let one = RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            p2p_id: Some(peer_id_bytes(&pid(SENDER)).unwrap()),
            offers: vec![ip4.clone()],
            ..Default::default()
        };
        let one_frame = encode(&one);
        assert_eq!(one_frame, frame_with(std::slice::from_ref(&ip4_record)));
        assert_eq!(decode(&one_frame), Some(one.clone()));
        let two = RouteHints {
            offers: vec![ip4.clone(), dns.clone()],
            ..one.clone()
        };
        let two_frame = encode(&two);
        assert_eq!(
            two_frame,
            frame_with(&[ip4_record.clone(), dns_record.clone()])
        );
        assert_eq!(decode(&two_frame), Some(two));

        let inputs = |r: &RelayOfferRecord, seed: u8| {
            json!({
                "relay_seed_hex": hex::encode([seed; 32]),
                "relay_pub_hex": hex::encode(r.relay_pub),
                "relay_peer_id": r.relay_peer_id(),
                "flags": r.flags,
                "addrs": r.addrs,
                "sender_seed_hex": hex::encode([SENDER; 32]),
                "sender_peer_id": pid(SENDER),
                "generation": G,
                "ttl_s": RRH1_DEFAULT_TTL_S,
            })
        };
        let expected = |record: &[u8], frame: &[u8], r: &RelayOfferRecord| {
            json!({
                "record_hex": hex::encode(record),
                "record_len": record.len(),
                "frame_hex": hex::encode(frame),
                "frame_len": frame.len(),
                "decoded": offer_json(r),
            })
        };
        assert_vector(
            "rrh1_relay_offer_001.json",
            &vector(
                "RELAY_OFFER: an IPv4 relay on TCP and QUIC, flags CONFIRMED | AUTONAT",
                &format!(
                    "{LAYOUT}. {KEY}. The frame is an RRH1 snapshot from the sender seed: its \
                     P2P_ID, then this record"
                ),
                inputs(&ip4, 0x63),
                expected(&ip4_record, &one_frame, &ip4),
            ),
        );
        assert_vector(
            "rrh1_relay_offer_dns_002.json",
            &vector(
                "RELAY_OFFER: a DNS-named relay with TCP 443, flags AUTONAT | PORT_443",
                &format!(
                    "{LAYOUT}. {KEY}. The frame is an RRH1 snapshot from the sender seed with \
                     two records, the most a frame carries: its P2P_ID, the record of \
                     rrh1_relay_offer_001.json, then this one"
                ),
                inputs(&dns, 0x64),
                expected(&dns_record, &two_frame, &dns),
            ),
        );
    }

    #[test]
    fn offer_decoder_rejects_every_negative_vector() {
        let rows = negatives();
        assert_eq!(rows.len(), 7);
        for (stem, name, record, reason) in &rows {
            assert_eq!(decode_offer(record), Err(OfferDecode::Malformed), "{stem}");
            // In a frame: the record is dropped and counted, the frame kept.
            let frame = frame_with(std::slice::from_ref(record));
            let h = decode(&frame).unwrap_or_else(|| panic!("{stem}: the frame was ignored"));
            assert!(h.p2p_id.is_some() && h.offers.is_empty(), "{stem}");
            assert_eq!(h.dropped_offers, 1, "{stem}");
            assert_vector(
                &format!("negative/rrh1_relay_offer_{stem}.json"),
                &vector(
                    name,
                    "A version-1 RELAY_OFFER record that breaks one rule of \
                     RAVEN_ROUTE_HINTS_V1 §11.2: decode_offer refuses it as malformed. In an RRH1 \
                     frame (frame_hex: the sender seed's P2P_ID, then this record as entry type \
                     0x20) the record is dropped with an RRH1_MALFORMED debug log and the frame \
                     is kept",
                    json!({
                        "record_hex": hex::encode(record),
                        "frame_hex": hex::encode(&frame),
                    }),
                    json!({
                        "record": "malformed",
                        "reason": reason,
                        "frame_kept": true,
                        "offers_kept": 0,
                    }),
                ),
            );
        }

        // Every other rule, and the edges just inside.
        let key = relay_pub(0x63);
        let a = |n: u8| format!("/ip4/11.0.2.{n}/tcp/7427").into_bytes();
        let good = encode_offer(&ip4_offer());
        let over = format!(
            "/dns4/{}.{}.example.org/tcp/7427",
            "r".repeat(47),
            "r".repeat(46)
        );
        assert_eq!(over.len(), OFFER_ADDR_MAX_LEN + 1);
        let mut n_short = body(1, 0, key, &[&a(1), &a(2)]);
        n_short[34] = 3;
        let malformed: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("version only", vec![RELAY_OFFER_VERSION]),
            ("cut in the key", good[..20].to_vec()),
            ("no n_addrs", good[..34].to_vec()),
            ("cut in an address", good[..good.len() - 1].to_vec()),
            ("n_addrs 3, two addresses", n_short),
            ("a duplicate address", body(1, 0, key, &[&a(1), &a(1)])),
            ("address len 0", body(1, 0, key, &[b""])),
            ("address len 7", body(1, 0, key, &[b"/dns/ab"])),
            ("address len 121", body(1, 0, key, &[over.as_bytes()])),
            (
                "a non-UTF-8 address",
                body(1, 0, key, &[b"/dns4/r\xffy.org/tcp/1"]),
            ),
        ];
        for (name, record) in &malformed {
            assert_eq!(decode_offer(record), Err(OfferDecode::Malformed), "{name}");
        }
        let longest = longest_addr(1);
        let accepted: Vec<(&str, Vec<u8>)> = vec![
            ("one address", body(1, 0, key, &[&a(1)])),
            (
                "four addresses",
                body(1, 0, key, &[&a(1), &a(2), &a(3), &a(4)]),
            ),
            (
                "a 120-character address",
                body(1, 0, key, &[longest.as_bytes()]),
            ),
            ("the largest record", encode_offer(&largest(0x63))),
        ];
        for (name, record) in &accepted {
            let r = decode_offer(record).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(&encode_offer(&r), record, "{name}");
        }
    }

    #[test]
    fn offer_addresses_must_be_canonical_global_and_circuit_free() {
        let key = relay_pub(0x63);
        let peer = peer_id_from_ed25519_public(&key);
        let with_p2p = format!("/ip4/11.0.2.7/tcp/7427/p2p/{peer}");
        let circuit_to = format!("/ip4/11.0.2.7/tcp/7427/p2p/{peer}/p2p-circuit");
        let rows: Vec<(&str, bool)> = vec![
            ("/ip4/11.0.2.7/tcp/7427", true),
            ("/ip4/11.0.2.7/udp/7427/quic-v1", true),
            ("/ip6/2c0f:fff0:a::5/tcp/443", true),
            ("/dns/relay.example.org/tcp/443", true),
            ("/dns6/relay.example.org/udp/443/quic-v1", true),
            // Never a circuit, never a peer.
            ("/ip4/11.0.2.7/tcp/7427/p2p-circuit", false),
            (with_p2p.as_str(), false),
            (circuit_to.as_str(), false),
            // Host and transport grammar.
            ("/ip4/11.0.2.7/udp/7427", false),
            ("/ip4/11.0.2.7/udp/7427/quic", false),
            ("/ip4/11.0.2.7/tcp/7427/", false),
            ("/ip4/0.0.0.0/tcp/7427", false),
            ("/ip4/11.0.2.7/tcp/0", false),
            ("/onion3/relay/tcp/7427", false),
            // Canonical text only.
            ("/ip4/11.0.2.7/tcp/07427", false),
            ("/ip6/2C0F:FFF0:A::5/tcp/443", false),
            ("/ip6/2c0f:fff0:000a::5/tcp/443", false),
            ("/dns4/Relay.example.org/tcp/443", false),
            (" /ip4/11.0.2.7/tcp/7427", false),
            ("/ip4/11.0.2.7/tcp/7427 ", false),
        ];
        for (addr, ok) in &rows {
            let record = body(1, 0, key, &[addr.as_bytes()]);
            assert_eq!(decode_offer(&record).is_ok(), *ok, "{addr}");
        }

        // Global addresses only: loopback, private, link-local and a NAT64 /
        // 6to4 address around a private IPv4 are not dialled; names are.
        let local = offer(
            0x63,
            0,
            &[
                "/ip4/127.0.0.1/tcp/7427",
                "/ip4/192.168.1.5/udp/7427/quic-v1",
                "/ip6/fe80::1/tcp/7427",
                "/ip6/64:ff9b::a00:1/tcp/7427",
            ],
        );
        let public = offer(
            0x64,
            0,
            &[
                "/ip4/11.0.2.7/tcp/7427",
                "/ip6/2002:b00:207::1/udp/7427/quic-v1",
                "/ip6/::1/tcp/7427",
                "/dns4/relay.example.org/tcp/443",
            ],
        );
        for r in [&local, &public] {
            assert_eq!(
                decode_offer(&encode_offer(r)).as_ref(),
                Ok(r),
                "valid records"
            );
        }
        // A release build never reads the lab switch, so it refuses them.
        let release = crate::p2p_gate::lab_flag(false, || Some("1".to_owned()));
        assert!(!release);
        assert!(local.usable_addrs(release).is_empty());
        assert_eq!(
            public.usable_addrs(release),
            [
                "/ip4/11.0.2.7/tcp/7427",
                "/ip6/2002:b00:207::1/udp/7427/quic-v1",
                "/dns4/relay.example.org/tcp/443",
            ]
        );
        // The debug lab switch admits loopback and private addresses.
        let lab = crate::p2p_gate::lab_flag(true, || Some("1".to_owned()));
        assert_eq!(local.usable_addrs(lab), local.addrs);
        assert_eq!(public.usable_addrs(lab), public.addrs);
        // The receiver's switch is the debug-only RAVEN_LAB_P2P_LOCAL_CANDIDATES.
        if !cfg!(debug_assertions) {
            assert!(!crate::p2p_local_candidates_enabled());
        }
    }

    /// §11.3 in `validate`: a pinned sender's offers only, each with the
    /// addresses the receiver may dial (one left with none is dropped and
    /// counted), at most two, one per relay, and only records `decode_offer`
    /// would accept, even past what `decode` lets through.
    #[test]
    fn validate_keeps_a_pinned_senders_offers_with_addresses_it_may_dial() {
        use crate::outbox::OutboxCarrier;
        use crate::route_hints::{validate, HintLink};
        let public = offer(
            0x66,
            FLAG_AUTONAT,
            &[
                "/ip4/127.0.0.1/tcp/7427",
                "/ip4/11.0.2.7/tcp/7427",
                "/dns4/relay.example.org/tcp/443",
            ],
        );
        let private = offer(0x67, 0, &["/ip4/192.168.1.5/tcp/7427"]);
        let h = RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            p2p_id: Some(peer_id_bytes(&pid(SENDER)).unwrap()),
            offers: vec![public.clone(), private.clone()],
            ..Default::default()
        };
        let inet = HintLink::fixture(OutboxCarrier::Internet, true);
        let v = validate(&h, &inet);
        let dialable = RelayOfferRecord {
            addrs: vec![
                "/ip4/11.0.2.7/tcp/7427".into(),
                "/dns4/relay.example.org/tcp/443".into(),
            ],
            ..public.clone()
        };
        assert_eq!(v.offers, std::slice::from_ref(&dialable));
        assert_eq!(v.dropped, 1, "the offer left without an address");
        // The debug lab switch keeps loopback and private ones.
        let lab = HintLink {
            lab_local: true,
            ..inet
        };
        assert_eq!(validate(&h, &lab).offers, [public.clone(), private.clone()]);
        // An unpinned sender's offers are never kept, on any link.
        for carrier in [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
        ] {
            let v = validate(&h, &HintLink::fixture(carrier, false));
            assert!(v.offers.is_empty(), "{carrier:?}");
        }
        // Past what decode lets through: a repeated relay, a record decode
        // refuses (no address) and a third offer are dropped.
        let no_addr = offer(0x68, 0, &[]);
        let many = RouteHints {
            offers: vec![
                public.clone(),
                public.clone(),
                no_addr,
                ip4_offer(),
                dns_offer(),
            ],
            ..h.clone()
        };
        let v = validate(&many, &inet);
        assert_eq!(v.offers, [dialable, ip4_offer()]);
        assert_eq!(v.dropped, 3);
    }

    #[test]
    fn readers_ignore_unknown_flag_bits() {
        let mut record = encode_offer(&ip4_offer());
        record[1] = 0xf8 | FLAG_PORT_443;
        let r = decode_offer(&record).expect("unknown bits never refuse a record");
        assert_eq!(r.flags & OFFER_FLAGS_KNOWN, FLAG_PORT_443);
        // Kept as received, so the record round-trips.
        assert_eq!(encode_offer(&r), record);
    }

    #[test]
    fn an_unsupported_offer_version_keeps_the_frame() {
        let good = encode_offer(&ip4_offer());
        let snapshot = entries(&encode(&full()));
        for version in [0u8, 2, 0xff] {
            let mut later = good.clone();
            later[0] = version;
            // A later format may be shorter or longer than a v1 record.
            for record in [
                later.clone(),
                vec![version],
                [later.as_slice(), &[0xee; 600]].concat(),
            ] {
                assert_eq!(decode_offer(&record), Err(OfferDecode::Unsupported));
                let mut e = snapshot.clone();
                e.insert(2, (T_RELAY_OFFER, record));
                // Ignored and not counted; the rest of the frame is used.
                assert_eq!(
                    decode(&raw(G, RRH1_DEFAULT_TTL_S, &e)),
                    Some(full()),
                    "{version}"
                );
            }
        }
        // It takes none of the two places: the v1 records after it are kept.
        let mut later = encode_offer(&dns_offer());
        later[0] = 2;
        let h = decode(&frame_with(&[
            later.clone(),
            later,
            good,
            encode_offer(&dns_offer()),
        ]))
        .unwrap();
        assert_eq!(h.offers, vec![ip4_offer(), dns_offer()]);
        assert_eq!(h.dropped_offers, 0);
        // A record without a version byte is malformed, still not the frame.
        let h = decode(&frame_with(&[Vec::new()])).unwrap();
        assert_eq!((h.offers.len(), h.dropped_offers), (0, 1));
    }

    /// A frame with two offers on top of a full snapshot, each record of the
    /// largest size: a receiver that predates §11 skips both and reads the
    /// same hints as from the frame without them (spec §4's skip rule).
    #[test]
    fn an_rrh1_frame_with_two_offers_decodes_on_a_step_1_decoder_without_change() {
        let h = RouteHints {
            offers: vec![largest(0x63), largest(0x64)],
            ..full()
        };
        let frame = encode(&h);
        assert_eq!(
            entries(&frame)
                .iter()
                .filter(|(kind, value)| *kind == T_RELAY_OFFER
                    && value.len() == RELAY_OFFER_MAX_LEN)
                .count(),
            2
        );
        assert_eq!(decode(&frame), Some(h));
        assert_eq!(decode_before_relay_records(&frame), Some(full()));
        assert_eq!(
            decode_before_relay_records(&frame),
            decode(&encode(&full()))
        );

        // Every first-draft entry at its limits plus two of the largest
        // records stays within the frame bound, which old receivers enforce.
        let max = RouteHints {
            relays: vec!["r".repeat(RELAY_MAX_LEN); MAX_RELAY_ENTRIES],
            direct: vec!["d".repeat(DIRECT_MAX_LEN); MAX_DIRECT],
            custodians: vec![[0x77; 32], [0x78; 32]],
            offers: vec![largest(0x63), largest(0x64)],
            ..full()
        };
        let f = encode(&max);
        assert!(f.len() <= RRH1_MAX_LEN, "{}", f.len());
        assert_eq!(decode(&f), Some(max.clone()));
        assert_eq!(
            decode_before_relay_records(&f),
            Some(RouteHints {
                offers: Vec::new(),
                ..max
            })
        );
    }

    #[test]
    fn decode_keeps_the_first_two_offers_one_per_relay() {
        let a = encode_offer(&ip4_offer());
        let b = encode_offer(&dns_offer());
        let same_relay = encode_offer(&offer(0x63, 0, &["/ip4/11.0.2.8/tcp/7427"]));
        let third = encode_offer(&offer(0x65, 0, &["/ip4/11.0.2.9/tcp/7427"]));
        let bad = negatives()[0].2.clone();
        let h = decode(&frame_with(&[
            bad.clone(),
            a.clone(),
            same_relay.clone(),
            b.clone(),
            third.clone(),
        ]))
        .expect("relay records never cost the frame");
        assert_eq!(h.offers, vec![ip4_offer(), dns_offer()]);
        assert_eq!(h.dropped_offers, 3);
        assert!(h.p2p_id.is_some());
        // Records may come anywhere in the frame.
        let mut e = entries(&encode(&full()));
        e.insert(0, (T_RELAY_OFFER, b));
        e.insert(3, (T_RELAY_OFFER, a));
        let h = decode(&raw(G, RRH1_DEFAULT_TTL_S, &e)).unwrap();
        assert_eq!(
            h,
            RouteHints {
                offers: vec![dns_offer(), ip4_offer()],
                ..full()
            }
        );
    }

    #[test]
    fn encode_writes_only_offers_decode_keeps() {
        let five: Vec<String> = (1..=5)
            .map(|n| format!("/ip4/11.0.2.{n}/tcp/7427"))
            .collect();
        let five: Vec<&str> = five.iter().map(String::as_str).collect();
        let h = RouteHints {
            offers: vec![
                offer(0x65, 0, &["/ip4/11.0.2.9/tcp/7427/p2p-circuit"]),
                offer(0x66, 0, &[]),
                offer(0x67, 0, &five),
                RelayOfferRecord {
                    relay_pub: BAD_POINT,
                    ..ip4_offer()
                },
                RelayOfferRecord {
                    // A count that does not fit a byte is written as 0.
                    addrs: (0..256)
                        .map(|n| format!("/ip4/11.0.{n}.7/tcp/7427"))
                        .collect(),
                    ..offer(0x68, 0, &[])
                },
                ip4_offer(),
                offer(0x63, 0, &["/ip4/11.0.2.8/tcp/7427"]),
                dns_offer(),
                offer(0x69, 0, &["/ip4/11.0.2.10/tcp/7427"]),
            ],
            ..full()
        };
        let got = decode(&encode(&h)).expect("never a frame a receiver ignores");
        assert_eq!(got.offers, vec![ip4_offer(), dns_offer()]);
        assert_eq!(got.dropped_offers, 0, "nothing a receiver drops is written");
        // A length that does not fit a byte is written as 0 too.
        let long = RelayOfferRecord {
            addrs: vec![format!("/dns4/{}.org/tcp/7427", "r".repeat(300))],
            ..ip4_offer()
        };
        assert_eq!(encode_offer(&long)[35], 0);
        assert_eq!(
            decode_offer(&encode_offer(&long)),
            Err(OfferDecode::Malformed)
        );
    }

    #[test]
    fn decode_offer_never_panics_and_accepted_records_round_trip() {
        let mut rng = rand::thread_rng();
        let seeds = [
            encode_offer(&ip4_offer()),
            encode_offer(&dns_offer()),
            encode_offer(&largest(0x63)),
        ];
        let mut accepted = 0;
        for i in 0..20_000 {
            let mut record = if i % 2 == 0 {
                let len = rng.gen_range(0..=RELAY_OFFER_MAX_LEN + 8);
                let mut r = vec![0u8; len];
                rng.fill_bytes(&mut r);
                if let Some(v) = r.first_mut() {
                    *v = RELAY_OFFER_VERSION;
                }
                r
            } else {
                seeds[i % seeds.len()].clone()
            };
            // Flip or set one byte, sometimes cut the record.
            if !record.is_empty() {
                let at = rng.gen_range(0..record.len());
                match i % 3 {
                    0 => record[at] ^= 1 << rng.gen_range(0..8),
                    1 => record[at] = rng.gen(),
                    _ => record.truncate(at),
                }
            }
            if let Ok(r) = decode_offer(&record) {
                accepted += 1;
                assert_eq!(encode_offer(&r), record, "{record:02x?}");
            }
        }
        assert!(accepted > 0, "some mutated records still decode");
    }
}
