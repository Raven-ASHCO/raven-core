//! Fuzz target bodies for Raven's attacker-facing decoders.
//!
//! Every function takes arbitrary bytes, must never panic, and checks cheap
//! invariants (canonical re-encoding, bounded consumption) on inputs a decoder
//! accepts. The same file is compiled twice:
//!
//! * as the library of the `raven-fuzz` cargo-fuzz crate (`node/fuzz`, outside
//!   the workspace; `fuzz_targets/*.rs` are one-line libFuzzer wrappers), and
//! * as a module of `raven-core`'s `tests/fuzz_smoke.rs`, which runs every
//!   target over seeded pseudo-random inputs on stable Rust in CI — so these
//!   bodies always type-check against the current decoder APIs.
//!
//! Only `raven_core` and `serde_json` may be used here (both crates have them).

use raven_core::ble_adapter::{ble_frame_decode, validate_opaque_rvn1};
use raven_core::bridge::{decide, BridgeRole};
use raven_core::device_cert::DeviceCertificate;
use raven_core::device_revocation::{claim_digest, DeviceRevocationV1};
use raven_core::envelope::Envelope;
use raven_core::internet::{deframe_prefix, frame, unpack_verify_hello, HelloBinding, HelloRole};
use raven_core::ipc::{decode_request, decode_response, encode_request, encode_response};
use raven_core::lan_rlb1::{decode_offer, encode_offer};
use raven_core::pair_init::{
    decode_init, decode_response as decode_pair_response, encode_init,
    encode_response as encode_pair_response,
};
use raven_core::prekey_bundle::{PrekeyBundle, PrekeyBundleJson};
use raven_core::store_object::StoreObject;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::sync::OnceLock;

/// Fixed validation clock so runs are reproducible (2023-11-14T22:13:20Z).
const NOW_MS: u64 = 1_700_000_000_000;

/// RVN1 envelope — the outer wire every carrier and bridge ingests.
pub fn envelope(data: &[u8]) {
    if let Some(env) = Envelope::unpack(data) {
        // The strict decoder is exact-length, so decoding is canonical: an
        // accepted input must re-encode to the identical bytes.
        assert_eq!(env.pack(), data, "RVN1 envelope re-encode mismatch");
        let _ = env.signing_bytes();
    }
    for role in [BridgeRole::Endpoint, BridgeRole::Relay] {
        let _ = decide(data, role, NOW_MS, false);
        let _ = decide(data, role, NOW_MS, true);
    }
    let _ = validate_opaque_rvn1(data);
}

/// RSO1 store object (store-and-forward custody wrapper).
pub fn store_object(data: &[u8]) {
    if let Ok(obj) = StoreObject::unpack(data) {
        let packed = obj.pack().expect("accepted store object must re-encode");
        let again = StoreObject::unpack(&packed).expect("re-encoded store object must decode");
        assert_eq!(
            again.pack().expect("second re-encode"),
            packed,
            "RSO1 re-encode is not stable"
        );
    }
}

/// RLB1 LAN bundle offer (device cert + prekey bundle, sent in the LAN Noise
/// handshake by an unauthenticated peer).
pub fn rlb1_offer(data: &[u8]) {
    if let Ok(bundle) = decode_offer(data) {
        let wire = encode_offer(&bundle).expect("accepted RLB1 offer must re-encode");
        let again = decode_offer(&wire).expect("re-encoded RLB1 offer must decode");
        assert_eq!(again, bundle, "RLB1 offer round trip changed the bundle");
        let _ = bundle.verify_bound(NOW_MS);
    }
}

/// Length-prefixed carrier frames: Internet/LAN TCP frames, the mock-BLE /
/// bridge frame, and the RIH1 Internet hello.
pub fn carrier_frames(data: &[u8]) {
    if let Some((payload, used)) = deframe_prefix(data) {
        assert!(used <= data.len(), "deframe consumed past the buffer");
        assert_eq!(used, payload.len() + 4, "deframe length accounting");
        let reframed = frame(&payload).expect("accepted frame must re-frame");
        assert_eq!(reframed, &data[..used], "frame re-encode mismatch");
    }
    if let Ok(Some((payload, used))) = ble_frame_decode(data) {
        assert!(used <= data.len(), "BLE frame consumed past the buffer");
        assert_eq!(used, payload.len() + 4, "BLE frame length accounting");
        assert!(
            validate_opaque_rvn1(&payload),
            "BLE frame passed a non-RVN1 payload"
        );
    }
    // The hello signature is channel-bound; a fixed binding still exercises
    // the full decode + verify path on arbitrary bytes.
    let binding = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: [0u8; 32],
        noise_static_pub: [0u8; 32],
    };
    let _ = unpack_verify_hello(data, &binding);
}

/// PairInit / PairResponse (fixed-length, signed first-contact messages).
pub fn pair_init(data: &[u8]) {
    if let Ok(init) = decode_init(data) {
        let wire = encode_init(&init).expect("accepted PairInit must re-encode");
        assert_eq!(wire, data, "PairInit re-encode mismatch");
    }
    if let Ok(resp) = decode_pair_response(data) {
        let wire = encode_pair_response(&resp).expect("accepted PairResponse must re-encode");
        assert_eq!(wire, data, "PairResponse re-encode mismatch");
    }
}

/// Device certificate and prekey bundle JSON (peer cert cache, RLB1 bodies).
pub fn device_cert(data: &[u8]) {
    if let Ok(cert) = serde_json::from_slice::<DeviceCertificate>(data) {
        let _ = cert.verify(NOW_MS);
        let _ = raven_core::pair_init::device_certificate_hash(&cert);
    }
    if let Ok(json) = serde_json::from_slice::<PrekeyBundleJson>(data) {
        if let Ok(bundle) = PrekeyBundle::from_json(&json) {
            let _ = bundle.verify(NOW_MS);
        }
    }
}

/// Device revocation claim (`RAVEN_DEVICE_REVOCATION_V1`).
pub fn device_revocation(data: &[u8]) {
    let _ = claim_digest(data);
    if let Ok(rev) = DeviceRevocationV1::decode(data) {
        let wire = rev.encode().expect("accepted revocation must re-encode");
        assert_eq!(wire, data, "device revocation re-encode mismatch");
    }
}

/// Local IPC frames (`ash` ⇄ `raven-node`; reachable by any local process
/// that can open the socket / named pipe).
pub fn ipc_frame(data: &[u8]) {
    if let Ok(req) = decode_request(data) {
        let wire = encode_request(&req).expect("accepted IPC request must re-encode");
        // The re-encode may legitimately be refused (e.g. a JSON escape that
        // spells a forbidden field name once normalised); if it decodes, it
        // must be the same request.
        if let Ok(again) = decode_request(&wire) {
            assert_eq!(again, req, "IPC request round trip changed the request");
        }
    }
    if let Ok(resp) = decode_response(data) {
        let _ = encode_response(&resp);
    }
}

/// ATSAM indexed-session wire pieces and discovery / contact records.
pub fn session_and_records(data: &[u8]) {
    let _ = raven_core::atsam_indexed_session::parse_indexed_message_header(data);
    let _ = raven_core::atsam_indexed_session::decode_signed_ack(data);
    let _ = raven_core::seal::parse_rvna1_header(data);
    let _ = raven_core::alias_record::AliasRecord::decode(data);
    let _ = raven_core::discovery::PeerRecord::decode(data);
    let _ = raven_core::contact_request::RavenContactRequestV1::decode_wire(data);
    let _ = raven_core::contact_request::ContactAcceptV1::decode_wire(data);
}

/// RSR1 session-reset frames (raw Noise plaintext on authenticated links).
pub fn rsr1_frame(data: &[u8]) {
    use raven_core::session_reset::{
        decode, frame_expects_reply, frame_is_terminal_reply, Rsr1Decode,
    };
    let _ = frame_expects_reply(data);
    let _ = frame_is_terminal_reply(data);
    if let Ok(Rsr1Decode::Frame(frame)) = decode(data) {
        // A decoded frame names both devices and carries a full signature.
        assert_eq!(frame.signature.len(), 64);
        let _ = raven_core::session_reset::verify(
            data,
            &frame,
            &frame.signer_device,
            &frame.subject_device,
        );
    }
}

/// RAL1 async letters (`async_letter::decode` and `decode_inner`): what a
/// custodian reads from a depositor and a recipient from a custodian, and
/// the inner a recipient reads after the AEAD.
pub fn ral1_decode(data: &[u8]) {
    use raven_core::async_letter::{
        decode, decode_header, decode_inner, encode_letter_inner, encode_reply_inner, Ral1Inner,
        Ral1Kind, MAX_RAL1_INNER, MAX_RAL1_LEN, MIN_RAL1_LEN, PAD_BLOCK, TAG_LEN,
    };
    match decode(data) {
        Ok(letter) => {
            // Strict: the bytes are exactly the encoding, within the caps.
            assert_eq!(letter.encode(), data);
            assert!((MIN_RAL1_LEN..=MAX_RAL1_LEN).contains(&data.len()));
            let inner_len = letter.header.ct_len as usize - TAG_LEN;
            assert!(inner_len.is_multiple_of(PAD_BLOCK) && inner_len <= MAX_RAL1_INNER);
            assert_eq!(decode_header(data), Ok(letter.header));
        }
        Err(_) => assert!(decode_header(data).is_err()),
    }
    for kind in [Ral1Kind::Letter, Ral1Kind::Reply] {
        match decode_inner(kind, data) {
            Ok(Ral1Inner::Letter(value)) => {
                assert_eq!(kind, Ral1Kind::Letter);
                assert_eq!(encode_letter_inner(&value).as_deref(), Ok(data));
            }
            Ok(Ral1Inner::Reply(value)) => {
                assert_eq!(kind, Ral1Kind::Reply);
                assert_eq!(encode_reply_inner(&value).as_deref(), Ok(data));
            }
            Err(_) => {}
        }
    }
}

/// RFC1 friend-custody frames, both directions.
pub fn rfc1_frame(data: &[u8]) {
    use raven_core::friend_custody::{
        decode_reply, decode_request, encode_reply, encode_request, RequestDecode, Rfc1Request,
    };
    let _ = raven_core::friend_custody::frame_expects_reply(data);
    let _ = raven_core::friend_custody::frame_is_terminal_reply(data);
    if let Ok(RequestDecode::Request(req_id, request)) = decode_request(data) {
        // Decoding dedups repeated tags/digests, so compare after one round.
        let again = encode_request(&req_id, &request);
        assert_eq!(
            decode_request(&again),
            Ok(RequestDecode::Request(req_id, request)),
            "RFC1 request round trip changed the request"
        );
    }
    if let Ok((req_id, reply)) = decode_reply(data) {
        // The dial classifier agrees with the reply: LETTER_ITEM and
        // FETCH_ITEM never end a request (§10).
        assert_eq!(
            raven_core::friend_custody::frame_is_terminal_reply(data),
            reply.is_terminal()
        );
        let again = encode_reply(&req_id, &reply);
        assert_eq!(decode_reply(&again), Ok((req_id, reply)));
    }
    let _ = raven_core::friend_custody::check_rfc1_rso1(data);
    // RHW1 records (custody handoff, op 0x07): an accepted record re-encodes
    // byte for byte, raw or inside a HANDOFF request; a HANDOFF request is
    // exactly what `is_handoff_request` says.
    {
        use raven_core::custody_handoff::{check_rhw1_rso1, Rhw1};
        if let Ok(record) = Rhw1::decode(data) {
            assert_eq!(record.encode(), data, "RHW1 re-encode mismatch");
            let _ = check_rhw1_rso1(&record.rso1);
        }
        let _ = check_rhw1_rso1(data);
        if let Ok(RequestDecode::Request(_, Rfc1Request::Handoff { record })) = decode_request(data)
        {
            assert!(raven_core::friend_custody::is_handoff_request(data));
            assert_eq!(record.encode(), data[14..], "HANDOFF record mismatch");
        }
    }
    // Letter custody admission reads the header only (§10).
    const NOW: u64 = 1_700_200_000_000;
    let letter = match decode_request(data) {
        Ok(RequestDecode::Request(_, Rfc1Request::DepositLetter { letter, .. })) => letter,
        _ => data.to_vec(),
    };
    if let Ok(header) = raven_core::carrier_admission::admit_letter(&letter, NOW) {
        assert_eq!(raven_core::async_letter::decode_header(&letter), Ok(header));
    }
}

/// RVNAPP/1 app frames inside the ATSAM plaintext.
pub fn app_frame(data: &[u8]) {
    use raven_core::app_channel::{
        classify, content_type_registered, encode_frame, AppFrameError, PayloadClass,
    };
    if let PayloadClass::App(frame) = classify(data) {
        let again = encode_frame(&frame.content_type, &frame.app_id, &frame.body, true);
        if content_type_registered(&frame.content_type, true) {
            let again = again.expect("an accepted registered frame re-encodes");
            assert_eq!(again.as_bytes(), data, "RVNAPP/1 re-encode mismatch");
        } else {
            // Well formed but unregistered: a receiver defers it and a sender
            // never builds one.
            assert_eq!(again, Err(AppFrameError::BadContentType));
        }
    }
}

/// RRH1 route hints (raw Noise plaintext after RLB1), the RLX1 LAN
/// message-3 payload, and the RELAY_OFFER record (RRH1 entry 0x20) on the
/// same bytes. The custody entries (0x06 CUSTODY_OFFER, 0x07 CUSTODIAN_TAG,
/// §12) re-encode byte for byte.
pub fn rrh1_frame(data: &[u8]) {
    use raven_core::outbox::OutboxCarrier;
    use raven_core::route_hints::{
        decode, decode_offer as decode_relay_offer, encode, encode_offer as encode_relay_offer,
        relay_host_usable, rlx1_caps, validate, HintLink, OfferDecode, RouteHints,
        CUSTODIAN_TAG_KNOWN_FLAGS, CUSTODIAN_TAG_LEN, CUSTODY_OFFER_KNOWN, MAX_ADDRS_PER_RELAY,
        MAX_CUSTODIANS, MAX_DIRECT, MAX_OFFER_ADDRS, MAX_RELAYS, MAX_RELAY_ENTRIES,
        MAX_RELAY_OFFERS, RELAY_OFFER_MAX_LEN, RELAY_OFFER_VERSION, RRH1_HEADER_LEN, RRH1_MAX_LEN,
    };
    /// The (type, value) entries of `kinds` in a frame `decode` accepted, in
    /// frame order.
    fn entries_of<'a>(frame: &'a [u8], kinds: &[u8]) -> Vec<(u8, &'a [u8])> {
        let mut out = Vec::new();
        let mut rest = &frame[RRH1_HEADER_LEN..];
        while let Some((&kind, r)) = rest.split_first() {
            let len = usize::from(u16::from_be_bytes([r[0], r[1]]));
            if kinds.contains(&kind) {
                out.push((kind, &r[2..2 + len]));
            }
            rest = &r[2 + len..];
        }
        out
    }
    let _ = rlx1_caps(data);
    match decode_relay_offer(data) {
        Ok(offer) => {
            // Strict and canonical: an accepted record re-encodes exactly.
            assert_eq!(
                encode_relay_offer(&offer),
                data,
                "RELAY_OFFER re-encode mismatch"
            );
            assert!(data.len() <= RELAY_OFFER_MAX_LEN);
            assert!((1..=MAX_OFFER_ADDRS).contains(&offer.addrs.len()));
        }
        Err(OfferDecode::Unsupported) => {
            assert!(data.first().is_some_and(|v| *v != RELAY_OFFER_VERSION));
        }
        Err(OfferDecode::Malformed) => {}
    }
    if let Some(h) = decode(data) {
        let again = encode(&h);
        assert!(again.len() <= RRH1_MAX_LEN);
        // What decode dropped is a count for the receiver's log, not on the
        // wire.
        let canonical = RouteHints {
            dropped_offers: 0,
            dropped_phase4: 0,
            dropped_pair_seed: 0,
            ..h.clone()
        };
        assert_eq!(
            decode(&again).as_ref(),
            Some(&canonical),
            "RRH1 canonical round trip"
        );
        // The canonical frame is a fixed point: encode(decode(x)) == x.
        assert_eq!(
            decode(&again).map(|h| encode(&h)).as_deref(),
            Some(again.as_slice()),
            "RRH1 canonical fixed point"
        );
        // Custody entries (§12) come back exactly, flags included, in frame
        // order within their type: the canonical frame differs from an
        // accepted one only by the order across types and by skipped or
        // dropped entries of other types.
        for kind in [0x06, 0x07] {
            assert_eq!(
                entries_of(&again, &[kind]),
                entries_of(data, &[kind]),
                "RRH1 custody entries re-encode"
            );
        }
        assert!(h.custodian_tags.len() <= MAX_CUSTODIANS);
        assert!(entries_of(data, &[0x07])
            .iter()
            .all(|(_, v)| v.len() == CUSTODIAN_TAG_LEN));
        assert!(h.offers.len() <= MAX_RELAY_OFFERS);
        for (i, offer) in h.offers.iter().enumerate() {
            assert_eq!(
                decode_relay_offer(&encode_relay_offer(offer)).as_ref(),
                Ok(offer)
            );
            assert!(
                h.offers[..i].iter().all(|o| o.relay_pub != offer.relay_pub),
                "one record per relay"
            );
        }
        for carrier in [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
        ] {
            for pinned in [false, true] {
                let v = validate(&h, &HintLink::fixture(carrier, pinned));
                assert!(v.relays.len() <= MAX_RELAY_ENTRIES);
                // A kept RELAY is a DNS name or a global address (§5.2).
                assert!(v.relays.iter().all(|r| relay_host_usable(r, false, false)));
                let mut relays: Vec<&str> = v.relays.iter().map(|r| r.peer_id.as_str()).collect();
                relays.sort_unstable();
                for id in &relays {
                    let addrs = relays.iter().filter(|r| *r == id).count();
                    assert!(addrs <= MAX_ADDRS_PER_RELAY, "addresses of one relay");
                }
                relays.dedup();
                assert!(relays.len() <= MAX_RELAYS, "distinct relays");
                assert!(v.direct.len() + v.local_direct.len() <= MAX_DIRECT);
                if carrier != OutboxCarrier::Lan {
                    assert!(v.lan_port.is_none() && v.local_direct.is_empty());
                }
                if !pinned {
                    assert!(
                        v.peer_id.is_none()
                            && v.relays.is_empty()
                            && v.direct.is_empty()
                            && v.local_direct.is_empty()
                            && v.custodians.is_empty()
                            && v.custody_offer.is_none()
                            && v.custodian_tags.is_empty()
                            && v.offers.is_empty()
                            && v.nat_class.is_none()
                    );
                }
                // Kept custody entries (§5.2, §12): known bits only, bounded,
                // never all-zero, one per tag, a flags byte for each.
                assert_eq!(v.custody_offer.unwrap_or(0) & !CUSTODY_OFFER_KNOWN, 0);
                assert!(v.custodian_tags.len() <= MAX_CUSTODIANS);
                assert_eq!(v.custodian_tags.len(), v.custodian_tag_flags.len());
                assert!(v
                    .custodian_tag_flags
                    .iter()
                    .all(|f| f & !CUSTODIAN_TAG_KNOWN_FLAGS == 0));
                for (i, tag) in v.custodian_tags.iter().enumerate() {
                    assert_ne!(*tag, [0; 32], "an all-zero tag");
                    assert!(!v.custodian_tags[..i].contains(tag), "one entry per tag");
                }
                if pinned {
                    assert_eq!(v.custody_offer.is_some(), h.custody_offer.is_some());
                }
                // A NAT_CLASS only with the PeerId it describes (§13.1).
                assert!(v.nat_class.is_none() || v.peer_id.is_some());
                // Kept offers (§11.3): bounded, one per relay, never the
                // receiver's own key, each with an address it may dial.
                let link = HintLink::fixture(carrier, pinned);
                assert!(v.offers.len() <= MAX_RELAY_OFFERS);
                for (i, offer) in v.offers.iter().enumerate() {
                    assert!(v.offers[..i].iter().all(|o| o.relay_pub != offer.relay_pub));
                    assert_ne!(offer.relay_pub, link.local_p2p, "the receiver's own key");
                    assert!(!offer.addrs.is_empty() && offer.addrs.len() <= MAX_OFFER_ADDRS);
                    assert_eq!(offer.usable_addrs(link.lab_local).len(), offer.addrs.len());
                }
            }
        }
    }
}

/// RRH1 Phase 4 entries (RAVEN_ROUTE_HINTS_V1 §13): `data` is read as
/// entries in the Phase 4 range (type `0x21 + byte % 15`, a length byte,
/// the value; a PEER_SCHEDULE's length is twice the byte, so every
/// `14 + 40 n` is reachable) appended to a valid frame that names a PeerId
/// and a relay. None ever costs the frame or another entry: the PeerId and
/// the relay are always kept, the first 5-byte NAT_CLASS and the first
/// PEER_SCHEDULE that follows §13.2 are kept (normalized), the first two
/// distinct INET_DIRECT entries that follow §13.3 are kept (flags masked),
/// and every other one is counted as dropped, the rest skipped; the frame
/// round trips canonically.
pub fn rrh1_phase4_tlvs(data: &[u8]) {
    use raven_core::identity::Identity;
    use raven_core::p2p_route::{local_peer_id, peer_id_bytes};
    use raven_core::peer_rotation::{schedule_key_ok, AHEAD, MAX_SCHEDULE};
    use raven_core::route_hints::RRH1_MAX_LEN;
    use raven_core::route_hints::{
        decode, encode, InetDirect, NatClass, PeerSchedule, RouteHints, INET_FLAGS_KNOWN,
        MAX_INET_DIRECT, NAT_CLASS_LEN, NAT_CLASS_MAX_CODE, NAT_FLAGS_KNOWN, SCHEDULE_FLAGS_KNOWN,
        SCHEDULE_FLAG_CAPABLE,
    };
    let peer = local_peer_id(&Identity::from_seed(&[0x51; 32]));
    let relay = local_peer_id(&Identity::from_seed(&[0x61; 32]));
    let base = RouteHints {
        generation: 7,
        ttl_s: 3600,
        p2p_id: Some(peer_id_bytes(&peer).expect("a PeerId")),
        relays: vec![format!("/ip4/11.0.2.1/tcp/7423/p2p/{relay}")],
        ..RouteHints::default()
    };
    let mut frame = encode(&base);
    let (mut kept, mut schedule, mut dropped) = (None, None, 0u32);
    let mut inet: Vec<InetDirect> = Vec::new();
    let mut rest = data;
    while let [kind, len, tail @ ..] = rest {
        let kind = 0x21 + kind % 15;
        let len = if kind == 0x23 {
            usize::from(*len) * 2
        } else {
            usize::from(*len)
        };
        let len = len.min(tail.len());
        if frame.len() + 3 + len > RRH1_MAX_LEN {
            break;
        }
        let value = &tail[..len];
        frame.push(kind);
        frame.extend_from_slice(&u16::try_from(len).expect("a byte").to_be_bytes());
        frame.extend_from_slice(value);
        if kind == 0x22 {
            match NatClass::from_bytes(value) {
                Some(c) if kept.is_none() => kept = Some(c),
                _ => dropped += 1,
            }
        }
        if kind == 0x23 {
            match PeerSchedule::from_bytes(value) {
                Some(s) if schedule.is_none() => schedule = Some(s),
                _ => dropped += 1,
            }
        }
        if kind == 0x24 {
            match InetDirect::from_bytes(value) {
                Some(e)
                    if inet.len() < MAX_INET_DIRECT && inet.iter().all(|o| o.addr != e.addr) =>
                {
                    inet.push(e)
                }
                _ => dropped += 1,
            }
        }
        rest = &tail[len..];
    }
    let h = decode(&frame).expect("a Phase 4 entry never costs the frame");
    assert_eq!(h.p2p_id, base.p2p_id);
    assert_eq!(h.relays, base.relays);
    assert_eq!((h.nat_class, h.dropped_phase4), (kept, dropped));
    assert_eq!(h.peer_schedule, schedule);
    assert_eq!(h.inet, inet);
    assert!(h.inet.iter().all(|e| e.flags & !INET_FLAGS_KNOWN == 0
        && InetDirect::from_bytes(&e.to_bytes()).as_ref() == Some(e)));
    if let Some(s) = &h.peer_schedule {
        assert!(s.flags & SCHEDULE_FLAG_CAPABLE != 0);
        assert_eq!(s.flags & !SCHEDULE_FLAGS_KNOWN, 0);
        assert!(s.epoch_len_s > 0 && s.entries.len() <= MAX_SCHEDULE);
        assert!(s.entries.windows(2).all(|w| w[0].0 < w[1].0));
        let (lo, hi) = (
            s.active_epoch.saturating_sub(1),
            s.active_epoch.saturating_add(AHEAD),
        );
        assert!(s
            .entries
            .iter()
            .all(|(e, key)| (lo..=hi).contains(e) && schedule_key_ok(key)));
        assert_eq!(
            PeerSchedule::from_bytes(&s.to_bytes().unwrap()).as_ref(),
            Some(s)
        );
    }
    if let Some(c) = h.nat_class {
        for code in [c.v4_tcp, c.v4_quic, c.v6_tcp, c.v6_quic] {
            assert!(code <= NAT_CLASS_MAX_CODE);
        }
        assert_eq!(c.flags & !NAT_FLAGS_KNOWN, 0);
        assert_eq!(c.to_bytes().len(), NAT_CLASS_LEN);
    }
    let canonical = RouteHints {
        dropped_phase4: 0,
        ..h.clone()
    };
    assert_eq!(decode(&encode(&h)), Some(canonical));
}

/// What a person pastes or a relay folder holds for the relay kit: `via=`
/// lines (`raven relay use`, `relay-probe`), `--also-tcp` and
/// `--public-host` (`raven-node relay`), `relay_allow.json` and
/// `relay_status.json`. The first byte picks the parser; the rest is read as
/// (lossy) UTF-8, as the CLI and the files are.
pub fn relay_inputs(data: &[u8]) {
    use raven_core::p2p_route::{
        host_prefix, parse_extra_tcp, parse_host_transport, parse_via, peer_id_from_ed25519_public,
        relay_listen_multiaddrs, relay_public_addrs, split_relay_tokens, P2pListen, MAX_EXTRA_TCP,
        MAX_MULTIADDR_CHARS, MAX_VIA,
    };
    use raven_core::relay_allow::{RelayAllowList, RelayStatusFile};
    let Some((&parser, rest)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(rest);
    match parser % 5 {
        0 => {
            if let Ok(via) = parse_via(&text) {
                assert_eq!(parse_via(&via.text).as_ref(), Ok(&via), "via re-parse");
                assert!(
                    via.text.len() <= MAX_MULTIADDR_CHARS
                        && via.text.bytes().all(|b| b.is_ascii_graphic()),
                    "a via's canonical text is plain and short"
                );
            }
        }
        1 => {
            if let Ok(vias) = split_relay_tokens(&text) {
                assert!((1..=MAX_VIA).contains(&vias.len()), "relay paste size");
                for (i, via) in vias.iter().enumerate() {
                    assert_eq!(
                        parse_via(&via.text).as_ref(),
                        Ok(via),
                        "pasted via re-parse"
                    );
                    assert!(!vias[..i].contains(via), "a pasted via kept twice");
                }
            }
        }
        2 => {
            // Each `--also-tcp` value (separated like repeated flags), then
            // the listeners of a relay on every interface.
            let extra: Vec<_> = text
                .split([' ', ','])
                .filter_map(|t| parse_extra_tcp(t).ok())
                .collect();
            for e in &extra {
                let again = parse_extra_tcp(&format!("{}:{}", e.local, e.public));
                assert_eq!(again.as_ref(), Ok(e), "--also-tcp re-parse");
            }
            let listen = P2pListen::All(7423);
            if let Ok(addrs) = relay_listen_multiaddrs(&listen, &extra) {
                assert!(extra.len() <= MAX_EXTRA_TCP);
                assert!(addrs.len() <= listen.multiaddrs().len() + 2 * MAX_EXTRA_TCP);
            }
        }
        3 => {
            let _ = host_prefix(&text);
            if let Ok(addrs) = relay_public_addrs(&text, 7423, &[parse_extra_tcp("443").unwrap()]) {
                assert_eq!(addrs.len(), 3, "{addrs:?}");
                let peer = peer_id_from_ed25519_public(&[7; 32]);
                for a in &addrs {
                    assert_eq!(
                        parse_host_transport(a).as_ref(),
                        Ok(a),
                        "named address re-parse"
                    );
                    // A card line: the address with the relay's PeerId, unless
                    // the name is too long for one (a 253-character DNS name).
                    let line = format!("{a}/p2p/{peer}");
                    assert_eq!(
                        parse_via(&line).is_ok(),
                        line.len() <= MAX_MULTIADDR_CHARS,
                        "{line}"
                    );
                }
            }
        }
        _ => {
            // The relay re-reads both files; a round trip keeps them.
            if let Ok(list) = serde_json::from_slice::<RelayAllowList>(rest) {
                let again = serde_json::to_vec(&list).expect("an allow-list serialises");
                let back: RelayAllowList = serde_json::from_slice(&again).expect("re-parse");
                assert_eq!(back, list, "relay_allow.json round trip");
            }
            if let Ok(status) = serde_json::from_slice::<RelayStatusFile>(rest) {
                let again = serde_json::to_vec(&status).expect("a status serialises");
                let back: RelayStatusFile = serde_json::from_slice(&again).expect("re-parse");
                assert_eq!(back, status, "relay_status.json round trip");
            }
        }
    }
}

/// The diagnosis reason block (`; reach: why=…`, local IPC:
/// RAVEN_ERROR_CODES_V1.md §2.1) that ash reads out of a dial error. A block
/// it finds renders within `MAX_RENDERED` bytes, with no '/' or ':' after its
/// tag, and reads back the same; a cut at any char boundary of the first 64
/// bytes never panics.
pub fn reach_tokens(data: &[u8]) {
    use raven_core::reach_diag::{Diag, MAX_RENDERED, REACH_TAG};
    let s = String::from_utf8_lossy(data);
    if let Some(d) = Diag::find(&s) {
        let r = d.render();
        assert!(r.len() <= MAX_RENDERED, "reason block too long: {r}");
        assert!(
            !r[REACH_TAG.len()..].contains(['/', ':']),
            "reason block names an address: {r}"
        );
        assert_eq!(Diag::find(&r), Some(d), "reason block round trip");
    }
    for (i, _) in s.char_indices().take_while(|(i, _)| *i < 64) {
        let _ = Diag::find(&s[i..]);
        let _ = Diag::find(&s[..i]);
    }
}

/// NAT-PMP and PCP replies from the default router
/// (`portmap::decode_reply`, RAVEN_PORT_MAPPING_V1.md) under every
/// combination of requests the client can have outstanding, opcodes it never
/// sends included. An accepted reply keeps the profile's version, opcode and
/// length rules, and nothing is accepted with nothing outstanding. Then the
/// same bytes reach `MapperCore::on_datagram` from a mapped state
/// ([`portmap_mapper`]).
pub fn portmap_reply(data: &[u8]) {
    use raven_core::portmap::{decode_reply, NatPmpResp, Reply, MAX_PCP, NATPMP_UNSUPP_VERSION};
    assert!(decode_reply(data, None, None).is_err());
    for pcp in [None, Some(0u8), Some(1), Some(2)] {
        for natpmp in [None, Some(0u8), Some(1), Some(2), Some(3)] {
            match decode_reply(data, pcp, natpmp) {
                Ok(Reply::Pcp(p)) => {
                    assert_eq!(Some(p.opcode), pcp, "PCP reply to another opcode");
                    assert!(p.opcode <= 1);
                    assert!((24..=MAX_PCP).contains(&data.len()) && data.len().is_multiple_of(4));
                    assert_eq!((data[0], data[1], data[3]), (2, 0x80 | p.opcode, p.result));
                    match p.map {
                        Some(m) => {
                            assert!(p.opcode == 1 && data.len() >= 60);
                            assert_eq!(m.nonce, data[24..36]);
                        }
                        None => assert!(p.opcode == 0 || p.result != 0),
                    }
                }
                Ok(Reply::NatPmp(n)) => {
                    let op = natpmp.expect("a NAT-PMP reply answers a NAT-PMP request");
                    assert_eq!((data[0], data[1]), (0, 0x80 | op));
                    let len = match n {
                        NatPmpResp::ExternalAddr { .. } => 12,
                        NatPmpResp::Map { .. } => 16,
                    };
                    assert_eq!(data.len(), len);
                    assert_eq!(n.result(), u16::from_be_bytes([data[2], data[3]]));
                }
                Ok(Reply::NatPmpOnly) => {
                    assert!(pcp.is_some(), "a version answer needs a PCP request");
                    assert_eq!(data[0], 0);
                    assert_eq!(
                        u16::from_be_bytes([data[2], data[3]]),
                        NATPMP_UNSUPP_VERSION
                    );
                    assert!(matches!(data.len(), 8 | 12 | 16));
                }
                Err(_) => {}
            }
        }
    }
    portmap_mapper(data);
}

/// Seed of the profile whose nonces the `portmap_reply` mapper cores use.
pub const PORTMAP_FUZZ_SEED: [u8; 32] = [0x5a; 32];
/// Client address and internal port of the `portmap_reply` mapper cores.
pub const PORTMAP_FUZZ_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
/// The router the `portmap_reply` mapper cores ask (part of every nonce).
pub const PORTMAP_FUZZ_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub const PORTMAP_FUZZ_PORT: u16 = 7423;
/// Epoch every scripted answer of the `portmap_reply` mapper cores carries.
pub const PORTMAP_FUZZ_EPOCH: u32 = 100;

/// What a mapper core reported: mapped endpoints and their external
/// addresses. Every `Mapped` is new or follows the endpoint's `Expired`,
/// every `Expired` names what is mapped, every mapped address is global, and
/// every datagram is a request of the profile.
#[derive(Default)]
struct MapperLedger {
    mapped: Vec<(raven_core::portmap::Proto, u16, std::net::SocketAddr)>,
}

impl MapperLedger {
    fn feed(&mut self, out: Vec<raven_core::portmap::Out>) -> Vec<Vec<u8>> {
        use raven_core::portmap::Out;
        let mut sent = Vec::new();
        for o in out {
            match o {
                Out::Send(b) => {
                    match b.first() {
                        Some(2) => assert!(b.len() == 24 || b.len() == 60, "PCP request size"),
                        Some(0) => assert!(b.len() == 2 || b.len() == 12, "NAT-PMP request size"),
                        _ => panic!("not a request of the profile"),
                    }
                    sent.push(b);
                }
                Out::Mapped {
                    proto,
                    internal_port,
                    external,
                    ..
                } => {
                    assert!(raven_core::p2p_route::is_global_ip(external.ip()));
                    assert_ne!(external.port(), 0);
                    assert!(
                        !self
                            .mapped
                            .iter()
                            .any(|m| (m.0, m.1) == (proto, internal_port)),
                        "mapped twice without an expiry"
                    );
                    self.mapped.push((proto, internal_port, external));
                }
                Out::Expired {
                    proto,
                    internal_port,
                    external,
                    ..
                } => {
                    let at = self
                        .mapped
                        .iter()
                        .position(|m| *m == (proto, internal_port, external));
                    self.mapped.remove(at.expect("expired what is not mapped"));
                }
                Out::NoServer
                | Out::Refused { .. }
                | Out::NonRoutable { .. }
                | Out::ServerRestarted { .. } => {}
            }
        }
        sent
    }
}

/// The router's success answer to a request the mapper core sent, in the
/// protocol the core chose (`None` for anything but a mapping request).
fn portmap_fuzz_grant(req: &[u8]) -> Option<Vec<u8>> {
    let epoch = PORTMAP_FUZZ_EPOCH.to_be_bytes();
    match (req.first(), req.len()) {
        (Some(2), 60) => {
            let mut b = vec![2, 0x81, 0, 0, 0, 0, 0x1c, 0x20];
            b.extend_from_slice(&epoch);
            b.extend_from_slice(&[0; 12]);
            b.extend_from_slice(&req[24..44]);
            b.extend_from_slice(&Ipv4Addr::new(11, 0, 2, 9).to_ipv6_mapped().octets());
            b[42..44].copy_from_slice(&req[40..42]);
            Some(b)
        }
        (Some(0), 12) => {
            let mut b = vec![0, 0x80 | req[1], 0, 0];
            b.extend_from_slice(&epoch);
            b.extend_from_slice(&req[4..6]);
            b.extend_from_slice(&req[4..6]);
            b.extend_from_slice(&[0, 0, 0x1c, 0x20]);
            Some(b)
        }
        _ => None,
    }
}

/// `portmap::MapperCore::on_datagram` from a mapped state: one core that
/// chose PCP and one that chose NAT-PMP, each holding a TCP and a UDP
/// mapping, get `data` twice, then a tick and a shutdown; the ledger's
/// invariants hold throughout and nothing stays mapped after the shutdown.
fn portmap_mapper(data: &[u8]) {
    use raven_core::identity::Identity;
    use raven_core::portmap::{nonce_key, MapperConfig, MapperCore, Proto, Via};
    use std::time::{Duration, Instant};
    let t0 = Instant::now();
    let epoch = PORTMAP_FUZZ_EPOCH.to_be_bytes();
    let client = IpAddr::V4(PORTMAP_FUZZ_CLIENT);
    let pcp_announce = [&[2u8, 0x80, 0, 0, 0, 0, 0, 0][..], &epoch, &[0; 12]].concat();
    let natpmp_only = [&[0u8, 0x80, 0, 1][..], &epoch].concat();
    let natpmp_ext = [&[0u8, 0x80, 0, 0][..], &epoch, &[11, 0, 2, 9]].concat();
    let scripts: [(Via, Vec<Vec<u8>>); 2] = [
        (Via::Pcp, vec![pcp_announce]),
        (Via::NatPmp, vec![natpmp_only, natpmp_ext]),
    ];
    for (via, probe_answers) in scripts {
        let gateway = IpAddr::V4(PORTMAP_FUZZ_GATEWAY);
        let cfg = MapperConfig::new(nonce_key(&Identity::from_seed(&PORTMAP_FUZZ_SEED)), gateway);
        let (mut core, out) = MapperCore::new(client, cfg, t0);
        let mut ledger = MapperLedger::default();
        ledger.feed(out);
        let mut sent = Vec::new();
        for proto in [Proto::Tcp, Proto::Udp] {
            sent.extend(ledger.feed(core.want(proto, PORTMAP_FUZZ_PORT, t0)));
        }
        for answer in &probe_answers {
            sent.extend(ledger.feed(core.on_datagram(answer, t0)));
        }
        assert_eq!(core.via(), Some(via));
        for req in &sent {
            if let Some(grant) = portmap_fuzz_grant(req) {
                ledger.feed(core.on_datagram(&grant, t0));
            }
        }
        assert_eq!(
            ledger.mapped.len(),
            2,
            "the scripted state maps TCP and UDP"
        );
        let now = t0 + Duration::from_secs(1);
        ledger.feed(core.on_datagram(data, now));
        ledger.feed(core.on_datagram(data, now));
        if let Some(wake) = core.next_wake() {
            ledger.feed(core.on_tick(wake.max(now)));
        }
        ledger.feed(core.shutdown());
        assert!(
            ledger.mapped.is_empty(),
            "every mapping expires at shutdown"
        );
        assert!(core.is_halted() && core.next_wake().is_none());
    }
}

/// Proxy settings and bypass lists (`net_proxy`, RAVEN_WSS_TRANSPORT_V1.md
/// §8): local settings, but read from the environment and the OS. An
/// accepted URL keeps a port and is shown, and debug-printed, with its
/// credential redacted; without one its text reads back the same. A refusal
/// shows no credential. Any bypass list leaves loopback and link-local hosts
/// direct; a Windows entry is one item of the string.
pub fn proxy_setting(data: &[u8]) {
    use raven_core::net_proxy::{
        effective, has_credentials, parse_proxy_url, parse_setting, parse_windows_proxy, Bypass,
        ProxySetting, SystemProxy,
    };
    let text = String::from_utf8_lossy(data);
    match parse_setting(&text) {
        Ok(ProxySetting::Url(url)) => {
            assert_ne!(url.port(), 0);
            let (host, port) = (url.host(), url.port());
            let at = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let shown = url.to_string();
            let debug = format!("{url:?}");
            if url.basic().is_some() {
                assert!(has_credentials(&text), "credentials without an @");
                assert_eq!(shown, format!("http://<redacted>@{at}"));
                assert_eq!(
                    debug,
                    format!(
                        "ProxyUrl {{ host: {host:?}, port: {port}, basic: Some(\"<redacted>\") }}"
                    )
                );
            } else {
                assert_eq!(shown, format!("http://{at}"));
                assert_eq!(parse_proxy_url(&shown).as_ref(), Ok(&url), "{shown}");
            }
        }
        Ok(_) => {}
        Err(e) => {
            assert!(
                !e.to_string().contains('@'),
                "a refusal shows the user part"
            );
            assert!(matches!(e.kind(), "https" | "socks" | "pac" | "invalid"));
        }
    }
    let port = data.first().map_or(443, |&b| u16::from(b) * 257);
    let bypass = Bypass::parse(&text);
    for host in ["127.0.0.1", "::1", "[fe80::1]", "169.254.9.9", "localhost"] {
        assert!(bypass.bypasses(host, port), "{host} must go direct");
    }
    for host in [
        "relay.example.org",
        "203.0.113.7",
        "[2001:db8::7]",
        "intranet",
    ] {
        let _ = bypass.bypasses(host, port);
    }
    let fixed = Bypass::parse("example.com,10.0.0.0/8,*.local,<local>,[2001:db8::/32]:443");
    let _ = fixed.bypasses(&text, port);
    if let Some(entry) = parse_windows_proxy(&text) {
        assert!(!entry.is_empty() && text.contains(entry.as_str()));
        assert!(!entry.contains([';', ' ', '\t', '\r', '\n']), "{entry:?}");
    }
    let sys = SystemProxy {
        https_enabled: true,
        host: text.to_string(),
        port: 0,
        exceptions: vec![text.to_string()],
        ..SystemProxy::default()
    };
    let e = effective(&ProxySetting::Auto, |_| None, || sys);
    assert!(e.proxy.is_none() || e.unsupported.is_none());
}

/// The relay schedule text (`peer_rotation::parse_relay_schedule`,
/// RAVEN_P2P_PEER_ROTATION_V1.md §6): what a dedicated relay's operator
/// pastes from anyone. An accepted text holds 1 to 13 entries with strictly
/// increasing epochs and canonical, distinct PeerIds, and its canonical form
/// is within the bound and reads back the same; a text this raven formats
/// from the input's first bytes always reads back.
pub fn relay_schedule_text(data: &[u8]) {
    use raven_core::identity::Identity;
    use raven_core::p2p_route::normalize_peer_id;
    use raven_core::peer_rotation::{
        epoch_peer_id, format_relay_schedule, parse_relay_schedule, MAX_RELAY_SCHEDULE,
        RELAY_SCHEDULE_MAX_LEN, RELAY_SCHEDULE_PREFIX,
    };
    let text = String::from_utf8_lossy(data);
    if let Ok(entries) = parse_relay_schedule(&text) {
        assert!((1..=MAX_RELAY_SCHEDULE).contains(&entries.len()));
        assert!(entries.windows(2).all(|w| w[0].0 < w[1].0));
        for (i, (_, peer)) in entries.iter().enumerate() {
            assert_eq!(normalize_peer_id(peer).as_deref(), Ok(peer.as_str()));
            assert!(entries[..i].iter().all(|(_, other)| other != peer));
        }
        let canonical: String = std::iter::once(RELAY_SCHEDULE_PREFIX.to_string())
            .chain(entries.iter().map(|(e, peer)| format!("{e}:{peer}")))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(canonical.len() <= RELAY_SCHEDULE_MAX_LEN);
        assert_eq!(parse_relay_schedule(&canonical).as_ref(), Ok(&entries));
    }
    // Two keys at most: each one is an Ed25519 derivation.
    let id = Identity::from_seed(&[data.first().copied().unwrap_or(0); 32]);
    let mut from = [0u8; 8];
    for (to, b) in from.iter_mut().zip(data.iter().skip(1)) {
        *to = *b;
    }
    let from = u64::from_be_bytes(from);
    let n = 1 + data.len() % 2;
    let back = parse_relay_schedule(&format_relay_schedule(&id, from, n)).expect("own text");
    assert_eq!(
        back.len(),
        n.min(usize::try_from(u64::MAX - from).map_or(n, |left| left.saturating_add(1)))
    );
    for (e, peer) in back {
        assert_eq!(peer, epoch_peer_id(&id, e));
    }
}

/// WebSocket frames (`ws_frame`, RAVEN_WSS_TRANSPORT_V1.md §5): what a
/// relay's WSS listener reads from any client before Noise, and a client
/// from the relay. Frames are read in a row both ways (masked and
/// unmasked) through the message reassembly, as `wss::ws` reads them. An
/// accepted head keeps the subset's bounds, re-encodes byte-identically and
/// every shorter prefix of it asks for more bytes; a head is decided once
/// 14 bytes are there; every refusal is a close code the subset names; no
/// message is over WS_MAX_MESSAGE; masking in two pieces at an offset is
/// masking the whole.
pub fn ws_frame(data: &[u8]) {
    use raven_core::ws_frame::{
        accept_token, apply_mask, close_code, encode_head, parse_head, valid_key, Reassembly,
        WsClose, OP_CLOSE, OP_PING, OP_PONG, WS_MAX_CONTROL, WS_MAX_MESSAGE,
    };
    for expect_masked in [true, false] {
        let mut rest = data;
        let mut msg = Reassembly::new();
        loop {
            let head = match parse_head(rest, expect_masked) {
                Ok(Some(h)) => h,
                Ok(None) => {
                    assert!(rest.len() < 14, "an undecided head of {} bytes", rest.len());
                    break;
                }
                Err(c) => {
                    assert!(c == WsClose::PROTOCOL || c == WsClose::TOO_BIG, "{c:?}");
                    break;
                }
            };
            assert_eq!(head.mask.is_some(), expect_masked);
            assert!(head.len <= WS_MAX_MESSAGE as u64);
            if head.op >= 8 {
                assert!(head.fin && head.len <= WS_MAX_CONTROL as u64);
            }
            let mut again = Vec::new();
            encode_head(head.fin, head.op, head.len, head.mask, &mut again);
            assert_eq!(again, rest[..head.hdr_len], "head re-encoding");
            for cut in [0, 1, head.hdr_len / 2, head.hdr_len - 1] {
                assert_eq!(parse_head(&rest[..cut], expect_masked), Ok(None));
            }
            let Some(wire) = rest.get(head.hdr_len..head.frame_len()) else {
                break;
            };
            let mut payload = wire.to_vec();
            if let Some(key) = head.mask {
                apply_mask(&mut payload, key, 0);
                let mut pieces = wire.to_vec();
                let (a, b) = pieces.split_at_mut(wire.len() / 3);
                apply_mask(a, key, 0);
                apply_mask(b, key, wire.len() / 3);
                assert_eq!(pieces, payload, "masking in pieces");
            }
            rest = &rest[head.frame_len()..];
            match head.op {
                OP_CLOSE => {
                    match close_code(&payload) {
                        Ok(code) => assert_eq!(code.is_some(), payload.len() >= 2),
                        Err(c) => assert!(c == WsClose::PROTOCOL && payload.len() == 1),
                    }
                    break;
                }
                OP_PING | OP_PONG => {}
                op => match msg.push(head.fin, op, &payload) {
                    Ok(Some(m)) => assert!(m.len() <= WS_MAX_MESSAGE && !msg.is_open()),
                    Ok(None) => assert!(msg.is_open()),
                    Err(c) => {
                        assert!(matches!(c.code(), 1002 | 1003 | 1009), "{c:?}");
                        break;
                    }
                },
            }
        }
    }
    // Upgrade keys come from the other side too.
    let text = String::from_utf8_lossy(data);
    if valid_key(&text) {
        assert!(text.len() == 24 && text.ends_with("=="), "{text:?}");
    }
    let token = accept_token(|input| [input.len() as u8; 20], &text);
    assert_eq!(token.len(), 28);
}

/// What [`lan_beacon_datagram`] tries: the people of
/// shared-vectors/rvn1/lan_beacon (RFC 8032 section 7.1 tests 1-3 as alice,
/// bob and carol), so the committed query and answer reach the accepted
/// branches.
pub struct BeaconFixture {
    /// The 3 contacts' keys tried: bob's and carol's for alice (the committed
    /// query names both) and alice's for bob (they open the committed answer).
    pub book: [raven_core::lan_beacon::PairKeys; 3],
    /// The other side of each book entry: the querier's keys.
    pub mirror: [raven_core::lan_beacon::PairKeys; 3],
    /// The vectors' epoch.
    pub epoch: u64,
    /// Alice's query source, its IPv4-mapped form and a link-local address.
    pub sources: [IpAddr; 3],
    /// The committed answer's query nonce, source (bob) and destination
    /// (alice).
    pub q_nonce: [u8; 16],
    pub answer_src: IpAddr,
    pub answer_dst: IpAddr,
}

/// The [`BeaconFixture`], built once.
pub fn lan_beacon_fixture() -> &'static BeaconFixture {
    use raven_core::identity::Identity;
    use raven_core::lan_beacon::pair_keys;
    static FIXTURE: OnceLock<BeaconFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let person = |seed_hex: &str| {
            let seed: [u8; 32] = std::array::from_fn(|i| {
                u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).expect("a hex seed")
            });
            Identity::from_seed(&seed)
        };
        let alice = person("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let bob = person("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let carol = person("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let keys = |own: &Identity, peer: &Identity| {
            pair_keys(own, &peer.public_key_bytes()).expect("the fixture's keys are usable")
        };
        let alice_ip = Ipv4Addr::new(192, 168, 1, 20);
        BeaconFixture {
            book: [keys(&bob, &alice), keys(&carol, &alice), keys(&alice, &bob)],
            mirror: [keys(&alice, &bob), keys(&alice, &carol), keys(&bob, &alice)],
            epoch: 2_833_333,
            sources: [
                IpAddr::V4(alice_ip),
                IpAddr::V6(alice_ip.to_ipv6_mapped()),
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x20)),
            ],
            q_nonce: std::array::from_fn(|i| i as u8),
            answer_src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)),
            answer_dst: IpAddr::V4(alice_ip),
        }
    })
}

/// RAVEN_LAN_BEACON_V1 datagrams (UDP 7420): `match_query` from every source
/// of the [`lan_beacon_fixture`] at its epoch and at both ends of u64, and
/// `open_answer` with every book entry. Only the two length ranges are read
/// (a query is 160..=191 bytes, an answer 48..=63; Phase 6b W-B3), and only
/// their first 160 or 48 bytes count. A match names each contact once, in
/// book order, and its query's first 160 bytes re-encode byte for byte from
/// the querier's keys; an opened answer carries a port other than 0, opens
/// in one direction only and opens the same without its tail.
pub fn lan_beacon_datagram(data: &[u8]) {
    use raven_core::lan_beacon::{
        kind_of, match_query, open_answer, DatagramKind, ANSWER_LEN, QUERY_LEN,
    };
    let fx = lan_beacon_fixture();
    let kind = kind_of(data.len());
    for src in fx.sources {
        for now in [fx.epoch, 0, u64::MAX] {
            let found = match_query(data, src, now, &fx.book);
            if kind != Some(DatagramKind::Query) {
                assert!(
                    found.is_empty(),
                    "a datagram of another length named a contact"
                );
            } else {
                assert_eq!(
                    found,
                    match_query(&data[..QUERY_LEN], src, now, &fx.book),
                    "a query's tail changed what it names"
                );
            }
            assert!(
                found.windows(2).all(|w| w[0].0 < w[1].0),
                "each contact once, in book order"
            );
            for &(i, port) in &found {
                let epochs = now.saturating_sub(1)..=now.saturating_add(1);
                assert!(
                    beacon_query_rebuilds(&data[..QUERY_LEN], &fx.mirror[i], src, port, epochs),
                    "a matched query does not re-encode"
                );
            }
        }
    }
    for k in &fx.book {
        if let Some(port) = open_answer(data, k, &fx.q_nonce, fx.answer_src, fx.answer_dst) {
            assert_eq!(
                kind,
                Some(DatagramKind::Answer),
                "an answer of another length opened"
            );
            assert_ne!(port, 0, "an answer with port 0 opened");
            assert_eq!(
                open_answer(
                    &data[..ANSWER_LEN],
                    k,
                    &fx.q_nonce,
                    fx.answer_src,
                    fx.answer_dst
                ),
                Some(port),
                "an answer's tail changed what it opens to"
            );
            assert_eq!(
                open_answer(data, k, &fx.q_nonce, fx.answer_dst, fx.answer_src),
                None,
                "an answer opened in both directions"
            );
        }
    }
}

/// Whether the 160-byte query `data` is, byte for byte, the query that
/// `querier`'s keys build from `src` naming one contact with `port` in one of
/// its slots at one of `epochs`, the other slots as they are.
fn beacon_query_rebuilds(
    data: &[u8],
    querier: &raven_core::lan_beacon::PairKeys,
    src: IpAddr,
    port: u16,
    epochs: RangeInclusive<u64>,
) -> bool {
    use raven_core::lan_beacon::{build_query_with, SLOTS};
    let nonce: [u8; 16] = data[..16]
        .try_into()
        .expect("a query starts with its nonce");
    let slot = |p: usize| -> [u8; 18] {
        let at = 16 + 18 * p;
        data[at..at + 18]
            .try_into()
            .expect("a query has 8 slots of 18 bytes")
    };
    (0..SLOTS).any(|pos| {
        let padding: Vec<[u8; 18]> = (0..SLOTS).filter(|&p| p != pos).map(slot).collect();
        epochs.clone().any(|e| {
            let again = build_query_with(nonce, &[pos], &padding, e, src, port, &[querier]);
            again[..] == *data
        })
    })
}

/// What [`rnp1_frame`] knocks with: bob's keys for alice (the vectors'
/// people), so the committed HELLO of shared-vectors/rvn1/nearby is answered.
pub struct NearbyFixture {
    /// Bob's RNB1 keys for alice.
    pub peripheral: raven_core::nearby_link::PairKeys,
    /// T(e0, bob): the service the committed HELLO knocks on.
    pub token: [u8; 16],
}

/// The [`NearbyFixture`], built once.
pub fn nearby_fixture() -> &'static NearbyFixture {
    use raven_core::identity::Identity;
    use raven_core::nearby_link::pair_keys;
    static FIXTURE: OnceLock<NearbyFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let person = |seed_hex: &str| {
            let seed: [u8; 32] = std::array::from_fn(|i| {
                u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).expect("a hex seed")
            });
            Identity::from_seed(&seed)
        };
        let alice = person("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let bob = person("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let peripheral =
            pair_keys(&bob, &alice.public_key_bytes()).expect("the fixture's keys are usable");
        let token = peripheral.token_out(1_888_888);
        NearbyFixture { peripheral, token }
    })
}

/// RAVEN_NEARBY_LINK_V1 frames (RNK1 knock and RNP1 pipe, one per ATT PDU).
/// The first byte picks the receiver's frame size (64, 185 or 512), its role
/// (bit 7) and whether it also sends (bit 6). The rest is decoded as one
/// frame: an accepted frame fits the size and re-encodes byte for byte, and
/// a HELLO the [`nearby_fixture`]'s peripheral answers gets one CHALLENGE
/// and then silence for the same nonce. Then the rest is read as
/// length-prefixed frames fed to a pipe that just came UP: delivered bytes
/// fit one DATA payload, credit stays at most 64 each way, a grant is 1 to
/// 64, and after an error or a RESET the pipe is dead.
pub fn rnp1_frame(data: &[u8]) {
    use raven_core::nearby_link::{
        decode, encode, Frame, KnockReplay, PeripheralKnock, PipeState, Role, RxAction,
        DATA_HEADER, W_MAX,
    };
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let max_rx = [64usize, 185, 512][usize::from(sel % 3)];
    let role = if sel & 0x80 == 0 {
        Role::Central
    } else {
        Role::Peripheral
    };
    if let Ok(f) = decode(rest, max_rx) {
        assert!(rest.len() <= max_rx, "an accepted frame is over max_rx");
        let mut again = Vec::new();
        encode(&f, &mut again);
        assert_eq!(again, rest, "an accepted RNP1 frame does not re-encode");
        let fx = nearby_fixture();
        let mut replay = KnockReplay::new();
        if let Some((_, challenge)) =
            PeripheralKnock::answer(&fx.peripheral, fx.token, &f, [0x5a; 16], &mut replay)
        {
            assert!(matches!(
                decode(&challenge, 64),
                Ok(Frame::Challenge { version: 1, nonce, .. }) if nonce == [0x5a; 16]
            ));
            assert!(
                PeripheralKnock::answer(&fx.peripheral, fx.token, &f, [0x5b; 16], &mut replay)
                    .is_none(),
                "a replayed HELLO was answered"
            );
        }
    }
    let mut pipe = PipeState::new(role, max_rx, max_rx).expect("every size is at least 64");
    let own = role.own_chan();
    let mut chunks = rest;
    while let Some((&len, tail)) = chunks.split_first() {
        let (frame, next) = tail.split_at(usize::from(len).min(tail.len()));
        chunks = next;
        match pipe.on_rx_bytes(frame) {
            Ok(RxAction::Deliver { chan, bytes }) => {
                assert!(!bytes.is_empty() && bytes.len() <= max_rx - DATA_HEADER);
                if let Some(Frame::Credit { add, .. }) = pipe.consumed(chan, 1) {
                    assert!((1..=W_MAX).contains(&add), "a grant out of range");
                }
            }
            Ok(RxAction::Reset(_)) | Err(_) => {
                assert!(pipe.is_dead(), "the pipe outlived an error or RESET");
                assert!(pipe.open().is_none() && !pipe.can_send(own));
                break;
            }
            Ok(_) => {}
        }
        assert!(pipe.tx_credit(0) <= W_MAX && pipe.tx_credit(1) <= W_MAX);
        if sel & 0x40 != 0 {
            let _ = pipe.open();
            if pipe.can_send(own) {
                assert!(pipe.on_tx_data(own).is_some());
            }
        }
    }
}

/// PAD1 link padding (`link_padding`, RAVEN_LINK_PADDING_V1): what a peer's
/// link frame decrypts to. `data` is unwrapped as one frame: an accepted
/// frame is a bucket, its inner frame fits, is not RPD1, the rest is zeros,
/// and it wraps back to the same bytes when its bucket is the smallest. It is
/// wrapped as one inner frame: the frame is the smallest bucket and unwraps
/// to it, and only what cannot be padded (empty, longer than 65,511 bytes,
/// starting with RPD1) is refused. Then the first byte picks a side (off,
/// agreed, LAN dialer) and the rest is read as frames (a length byte, then
/// half that many bytes, padded by the peer when the length byte is odd)
/// fed to its `on_recv`: an off side passes everything untouched, a bare
/// frame is read only until the peer's first RPD1 frame, an error ends the
/// link, and what the side sends is padded exactly when it wraps.
pub fn pad1_frame(data: &[u8]) {
    use raven_core::link_padding::{
        bucket_for, unwrap, wrap, Pad1Error, PadState, PAD1_BUCKETS, PAD1_HEADER_LEN, PAD1_MAGIC,
        PAD1_MAX_INNER,
    };
    if let Ok(inner) = unwrap(data) {
        assert!(
            PAD1_BUCKETS.contains(&data.len()),
            "an accepted frame is not a bucket"
        );
        assert!(!inner.is_empty() && inner.len() <= data.len() - PAD1_HEADER_LEN);
        assert!(
            !inner.starts_with(PAD1_MAGIC),
            "an accepted frame is nested"
        );
        assert!(data[PAD1_HEADER_LEN + inner.len()..]
            .iter()
            .all(|&b| b == 0));
        let again = wrap(inner).expect("an accepted inner frame wraps");
        assert!(
            again.len() <= data.len(),
            "a smaller bucket than the smallest"
        );
        if again.len() == data.len() {
            assert_eq!(again, data, "an accepted PAD1 frame does not re-encode");
        }
    }
    match wrap(data) {
        Ok(frame) => {
            assert_eq!(Some(frame.len()), bucket_for(data.len()));
            assert_eq!(unwrap(&frame), Ok(data), "a padded frame does not unwrap");
        }
        Err(e) => assert!(
            (e == Pad1Error::Nested && data.starts_with(PAD1_MAGIC))
                || (e == Pad1Error::BadLength && (data.is_empty() || data.len() > PAD1_MAX_INNER)),
            "a frame that can be padded was refused: {e}"
        ),
    }
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let side = match sel % 3 {
        0 => PadState::OFF,
        1 => PadState::agreed(true),
        _ => PadState::lan_dialer(true),
    };
    let mut state = side;
    let mut chunks = rest;
    while let Some((&len, tail)) = chunks.split_first() {
        let (bytes, next) = tail.split_at(usize::from(len >> 1).min(tail.len()));
        chunks = next;
        let padded;
        let frame = match wrap(bytes) {
            Ok(f) if len & 1 == 1 => {
                padded = f;
                &padded[..]
            }
            _ => bytes,
        };
        let before = state;
        match state.on_recv(frame) {
            Ok(inner) if side == PadState::OFF => assert_eq!(inner, frame),
            Ok(inner) if frame.starts_with(PAD1_MAGIC) => {
                assert_eq!(unwrap(frame), Ok(inner));
                assert!(state.peer_started() && state.negotiated());
            }
            Ok(inner) => {
                assert!(!before.peer_started(), "a bare frame after the peer padded");
                assert_eq!((inner, state), (frame, before));
            }
            Err(e) => {
                assert_ne!(side, PadState::OFF, "an off side refused a frame");
                if frame.starts_with(PAD1_MAGIC) {
                    assert_eq!(unwrap(frame), Err(e));
                } else {
                    assert!(e == Pad1Error::Unpadded && before.peer_started());
                }
                break;
            }
        }
        match state.on_send(bytes) {
            Ok(out) if state.negotiated() => assert_eq!(unwrap(&out), Ok(bytes)),
            Ok(out) => assert_eq!(&out[..], bytes),
            Err(_) => assert!(state.negotiated(), "a side that does not wrap refused"),
        }
    }
}

/// What [`rlk1_m1`] tries: the people and the knock of
/// shared-vectors/rvn1/link/rlk1_tags_001.json (RFC 8032 section 7.1 tests
/// 1-3 as alice, bob and carol): bob's book (carol, then alice), alice's
/// keys for bob, and the knock's day, nonce, ephemeral and bob's static.
pub struct KnockFixture {
    pub book: [raven_core::link_knock::KnockKeys; 2],
    pub alice_to_bob: raven_core::link_knock::KnockKeys,
    pub alice: [u8; 32],
    pub day: u32,
    pub nonce: [u8; 16],
    pub e: [u8; 32],
    pub s: [u8; 32],
}

/// The [`KnockFixture`], built once.
pub fn knock_fixture() -> &'static KnockFixture {
    use raven_core::identity::Identity;
    use raven_core::link_knock::{day_of, knock_keys};
    static FIXTURE: OnceLock<KnockFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let person = |seed_hex: &str| {
            let seed: [u8; 32] = std::array::from_fn(|i| {
                u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).expect("a hex seed")
            });
            Identity::from_seed(&seed)
        };
        let alice = person("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let bob = person("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let carol = person("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let keys = |own: &Identity, peer: &Identity| {
            knock_keys(own, &peer.public_key_bytes()).expect("the fixture's keys are usable")
        };
        let x_pub = |scalar: u8| raven_core::lan_noise::noise_static_public(&[scalar; 32]);
        KnockFixture {
            book: [keys(&bob, &carol), keys(&bob, &alice)],
            alice_to_bob: keys(&alice, &bob),
            alice: alice.public_key_bytes(),
            day: day_of(1_792_756_800_000),
            nonce: std::array::from_fn(|i| 0x10 + i as u8),
            e: x_pub(0x11),
            s: x_pub(0x33),
        }
    })
}

/// RLK1 (`link_knock`, RAVEN_LINK_KNOCK_V1): `data` as the raw Noise XX
/// message 1 a listener reads before it builds its responder (`e ||
/// payload`), matched against the [`knock_fixture`]'s book at its day and at
/// both ends of u32. Only 64..=95 bytes can match; a match names alice (the
/// book's second contact), carries `data`'s ephemeral and nonce, its tag is
/// alice's for bob at one of the three days, and it is a replay the second
/// time. Then `data` as a message 2 payload for the fixture's knock: a proof
/// verifies only at 16..=47 bytes and only when its first 16 bytes are bob's
/// proof. And as a message 3 payload: its RLX1 caps read without a panic, and
/// a padded RLX1 of any caps and length keeps its caps.
pub fn rlk1_m1(data: &[u8]) {
    use raven_core::link_knock::{check_m2, match_m1, ReplayCache, E_LEN, M1_PAYLOAD_MIN};
    use raven_core::route_hints::{rlx1_caps, rlx1_payload_padded, RLX1_MAX_LEN};
    let fx = knock_fixture();
    for day in [fx.day, 0, u32::MAX] {
        let Some(m) = match_m1(&fx.book, data, day) else {
            continue;
        };
        assert!((64..=95).contains(&data.len()), "a match of another length");
        assert_eq!((m.index, m.peer), (1, fx.alice), "not the knocking contact");
        assert_eq!(&data[..E_LEN], &m.e[..]);
        assert_eq!(&data[E_LEN..E_LEN + 16], &m.nonce[..]);
        let tag = &data[E_LEN + 16..E_LEN + M1_PAYLOAD_MIN];
        let days = [day.saturating_sub(1), day, day.saturating_add(1)];
        assert!(
            days.iter()
                .any(|d| fx.alice_to_bob.tag_out(*d, &m.nonce, &m.e)[..] == *tag),
            "a match whose tag is not alice's"
        );
        let mut cache = ReplayCache::new();
        assert!(!cache.replayed(&m.nonce, 0));
        assert!(cache.replayed(&m.nonce, 1), "a matched nonce twice");
    }
    if check_m2(&fx.alice_to_bob, &fx.nonce, &fx.e, &fx.s, data) {
        assert!((16..=47).contains(&data.len()), "a proof of another length");
        assert_eq!(
            fx.alice_to_bob.proof_in(&fx.nonce, &fx.e, &fx.s)[..],
            data[..16]
        );
    }
    let _ = rlx1_caps(data);
    if let Some(&b) = data.first() {
        let caps = u32::from_be_bytes([b, b ^ 0x5a, b.rotate_left(3), b]);
        let p = rlx1_payload_padded(caps, usize::from(b));
        assert!(p.len() <= RLX1_MAX_LEN);
        assert_eq!(rlx1_caps(&p), caps, "a padded RLX1 lost its caps");
    }
}

/// The release key sets `rad1_decode` checks advisories against: the
/// published test set (seeds `0x11`, `0x22`, `0x33` x 32, 2 of 3) and the
/// set the rotation vector names (`0x22`, `0x33`, `0x44`), built once.
pub fn release_key_fixture() -> &'static [raven_core::release_keys::KeySet; 2] {
    use raven_core::identity::Identity;
    use raven_core::release_keys::KeySet;
    static FIXTURE: OnceLock<[KeySet; 2]> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let set = |seeds: [u8; 3]| {
            let keys = seeds.map(|b| Identity::from_seed(&[b; 32]).public_key_bytes());
            KeySet::new(2, keys.to_vec()).expect("the test keys form a key set")
        };
        [set([0x11, 0x22, 0x33]), set([0x22, 0x33, 0x44])]
    })
}

/// RAD1 security advisories, release key sets and signature blocks
/// (`advisory`, `release_keys`, RAVEN_SECURITY_ADVISORY_V1): what a friend or
/// a file hands the update state. `data` is decoded as an advisory: an
/// accepted one keeps every bound and kind rule, re-encodes byte for byte,
/// and its signatures are checked against the fixture's key sets without a
/// panic. It is decoded as a key set (an accepted one re-encodes, its keys
/// are distinct and its threshold fits) and as one signature block (it
/// re-encodes, and checking it against the test set never panics).
pub fn rad1_decode(data: &[u8]) {
    use raven_core::advisory::{
        target_well_formed, Advisory, EntryKind, Severity, MAX_ARG_LEN, MAX_ENTRIES, MAX_RAD1_LEN,
        SIGNING_DOMAIN,
    };
    use raven_core::release_keys::{KeySet, SigBlock, KEYSET_MAX_KEYS};
    let sets = release_key_fixture();
    if let Ok(a) = Advisory::decode(data) {
        assert!(
            data.len() <= MAX_RAD1_LEN,
            "an accepted advisory is too long"
        );
        assert!(a.entries.len() <= MAX_ENTRIES);
        assert_eq!(
            a.serial == 1,
            a.prev_digest == [0; 32],
            "serial and prev_digest disagree"
        );
        for (i, e) in a.entries.iter().enumerate() {
            assert!(target_well_formed(&e.target) && e.arg.len() <= MAX_ARG_LEN);
            assert!(
                e.severity != Severity::Broken
                    || matches!(
                        e.kind,
                        EntryKind::SuiteStatus | EntryKind::FeatureHold | EntryKind::Other(_)
                    ),
                "BROKEN on a kind that cannot carry it"
            );
            match e.kind {
                EntryKind::ReleaseFloor => assert!(e.release_floor().is_some_and(|f| f >= 1)),
                EntryKind::Notice => assert!(e.notice_text().is_some_and(|t| !t.is_empty())),
                EntryKind::KeySet => assert!(e.key_set().is_some()),
                _ => {}
            }
            assert!(
                !a.entries[..i]
                    .iter()
                    .any(|p| p.kind == e.kind && p.target == e.target),
                "a duplicate entry was accepted"
            );
        }
        let again = a
            .draft()
            .assemble(a.sigs())
            .expect("an accepted advisory assembles again");
        assert_eq!(again.bytes(), data, "an accepted RAD1 does not re-encode");
        assert_eq!(
            a.signing_input(),
            [SIGNING_DOMAIN, &data[..a.signed_len()]].concat()
        );
        for set in sets {
            if a.verify(set).is_ok() {
                assert_eq!(a.key_set_digest, set.digest());
                assert!(a.sigs().sigs().len() >= usize::from(set.threshold()));
            }
        }
    }
    if let Ok(set) = KeySet::decode(data) {
        assert_eq!(set.encode(), data, "an accepted key set does not re-encode");
        let keys = set.keys();
        assert!(!keys.is_empty() && keys.len() <= KEYSET_MAX_KEYS);
        assert!((1..=keys.len()).contains(&usize::from(set.threshold())));
        for (i, k) in keys.iter().enumerate() {
            assert!(!keys[..i].contains(k), "a key set lists a key twice");
        }
    }
    if let Ok(block) = SigBlock::decode(data) {
        assert_eq!(block.encode(), data, "a signature block does not re-encode");
        let _ = sets[0].verify_sigs(b"rvn1/fuzz/v1\0", &block);
    }
}

/// RTL1 transparency log snapshots and signed tree heads (`tlog`,
/// RAVEN_TRANSPARENCY_LOG_V1): what travels with every advisory and release
/// bundle. `data` is decoded as a tree head (an accepted one keeps its
/// bounds and re-encodes byte for byte; one that verifies names that key
/// set) and as a snapshot (an accepted one keeps the entry cap, its head's
/// size is its entry count, and it re-encodes byte for byte). A snapshot is
/// checked against the fixture's key sets: a checked log lists each of its
/// entries, is SAME as itself and EXTENDS each of its prefixes, and a
/// BAD_ROOT is a real mismatch. Prefix consistency against a small fixed
/// log is symmetric.
pub fn rtl1_snapshot(data: &[u8]) {
    use raven_core::tlog::{
        consistency, mth, Consistency, EntryType, LogCheckError, LogEntry, Snapshot, Sth,
        MAX_LOG_ENTRIES, MAX_SNAPSHOT_LEN, MAX_STH_LEN, STH_SIGNED_LEN, STH_SIGNING_DOMAIN,
    };
    let sets = release_key_fixture();
    if let Ok(sth) = Sth::decode(data) {
        assert!(
            data.len() <= MAX_STH_LEN,
            "an accepted tree head is too long"
        );
        assert!(sth.tree_size >= 1);
        let again = sth
            .draft()
            .assemble(sth.sigs())
            .expect("an accepted tree head assembles again");
        assert_eq!(again.bytes(), data, "an accepted STH does not re-encode");
        assert_eq!(
            sth.signing_input(),
            [STH_SIGNING_DOMAIN, &data[..STH_SIGNED_LEN]].concat()
        );
        for set in sets {
            if sth.verify(set).is_ok() {
                assert_eq!(sth.key_set_digest, set.digest());
                assert!(sth.sigs().sigs().len() >= usize::from(set.threshold()));
            }
        }
    }
    let Ok(snap) = Snapshot::decode(data) else {
        return;
    };
    assert!(
        data.len() <= MAX_SNAPSHOT_LEN,
        "an accepted snapshot is too long"
    );
    let entries = snap.entries();
    assert!(!entries.is_empty() && entries.len() <= MAX_LOG_ENTRIES);
    assert_eq!(snap.sth().tree_size, entries.len() as u64);
    assert!(entries.iter().all(|e| e.kind.byte() != 0));
    assert_eq!(
        snap.encode(),
        data,
        "an accepted snapshot does not re-encode"
    );
    for set in sets {
        match snap.check(set) {
            Ok(checked) => {
                assert_eq!(mth(entries), snap.sth().root_hash);
                assert_eq!(checked.consistency(entries), Consistency::Same);
                for e in entries {
                    assert!(checked.contains(e.kind, &e.digest));
                }
                let half = &entries[..entries.len() / 2];
                assert_eq!(consistency(half, entries), Consistency::Extends);
                assert_eq!(consistency(entries, half), Consistency::Older);
            }
            Err(LogCheckError::BadRoot) => assert_ne!(mth(entries), snap.sth().root_hash),
            Err(LogCheckError::Sig(_)) => {}
        }
    }
    let fixed: Vec<LogEntry> = (1..=3u8)
        .map(|i| LogEntry {
            kind: EntryType::Advisory,
            digest: [i; 32],
            logged_at_ms: u64::from(i),
        })
        .collect();
    let there = consistency(&fixed, entries);
    let back = consistency(entries, &fixed);
    assert_eq!(
        (there, back),
        match there {
            Consistency::Extends => (there, Consistency::Older),
            Consistency::Older => (there, Consistency::Extends),
            Consistency::Same | Consistency::Split => (there, there),
        },
        "prefix consistency is not symmetric"
    );
}

/// Is `path` safe to join under a staging directory, by `std::path` alone
/// (the traversal property `rrb1_manifest` checks every accepted path
/// against): 2 or 3 normal components under `bin` or `docs`, nothing a
/// Windows or Unix file system reads as a separator, a drive or a stream,
/// and the join stays inside the directory.
fn path_is_contained(path: &str) -> bool {
    use std::path::{Component, Path};
    let comps: Vec<Component> = Path::new(path).components().collect();
    let base = Path::new("staged");
    (2..=3).contains(&comps.len())
        && comps.iter().all(|c| matches!(c, Component::Normal(_)))
        && matches!(comps[0], Component::Normal(n) if n == "bin" || n == "docs")
        && !path.contains(['\\', ':', '\0', ' '])
        && path.split('/').count() == comps.len()
        && base.join(path).starts_with(base)
}

/// RRB1 release manifests and chunk trees (`release_bundle`,
/// RAVEN_RELEASE_BUNDLE_V1): what a `.rrb` file or a friend hands the update
/// state before anything is staged. `data` is decoded as a manifest: an
/// accepted one keeps every bound and re-encodes byte for byte; every path
/// is safe by `std::path` alone (the path-traversal property) and no two
/// collide ignoring case or as file and directory; the files tile the
/// payload in order, without gap or overlap (the overlap property); its
/// signatures are checked against the fixture's key sets without a panic.
/// Data that starts with `C` and is at most 4 KiB is also cut into chunks of
/// `1 + data[1] % 64` bytes (hashing is the expensive part, so other inputs
/// skip it): each chunk's audit path proves it, and proves no changed chunk.
pub fn rrb1_manifest(data: &[u8]) {
    use raven_core::release_bundle::{
        chunk_root, verify_chunk_path, ChunkTree, Manifest, CHUNK_SIZE, MAX_FILES,
        MAX_MANIFEST_LEN, MAX_PAYLOAD_LEN, SIGNING_DOMAIN,
    };
    let sets = release_key_fixture();
    if let Ok(m) = Manifest::decode(data) {
        assert!(
            data.len() <= MAX_MANIFEST_LEN,
            "an accepted manifest is too long"
        );
        assert!((1..=MAX_FILES).contains(&m.files.len()));
        assert_eq!(m.chunk_size, CHUNK_SIZE);
        assert!((1..=MAX_PAYLOAD_LEN).contains(&m.payload_len));
        let mut end = 0;
        for (i, f) in m.files.iter().enumerate() {
            assert!(path_is_contained(&f.path), "{:?} escapes", f.path);
            let lower = f.path.to_ascii_lowercase();
            assert!(
                !m.files[..i].iter().any(|g| {
                    let other = g.path.to_ascii_lowercase();
                    other == lower
                        || lower.starts_with(&format!("{other}/"))
                        || other.starts_with(&format!("{lower}/"))
                }),
                "two paths name one file"
            );
            assert_eq!(f.offset, end, "the files do not tile the payload");
            end = f.offset + f.size;
        }
        assert_eq!(end, m.payload_len, "the files do not cover the payload");
        let again = m
            .draft()
            .assemble(m.sigs())
            .expect("an accepted manifest assembles again");
        assert_eq!(again.bytes(), data, "an accepted RRB1 does not re-encode");
        assert_eq!(
            m.signing_input(),
            [SIGNING_DOMAIN, &data[..m.signed_len()]].concat()
        );
        for set in sets {
            if m.verify(set).is_ok() {
                assert_eq!(m.key_set_digest, set.digest());
                assert!(m.sigs().sigs().len() >= usize::from(set.threshold()));
            }
        }
        let _ = m.check_chunk(0, data, &[]);
    }
    let [b'C', first, rest @ ..] = data else {
        return;
    };
    if rest.len() > 4_096 {
        return;
    }
    let size = 1 + u32::from(first % 64);
    let tree = ChunkTree::new(rest, size);
    let root = tree.root();
    assert_eq!(root, chunk_root(rest, size));
    let n = tree.len() as u64;
    for i in 0..tree.len().min(64) {
        let path = tree.chunk_path(i).expect("a chunk in the tree");
        let leaf = tree.leaf(i).expect("a chunk in the tree");
        assert!(
            verify_chunk_path(&root, n, i as u64, &leaf, &path),
            "a true path fails"
        );
        let mut other = leaf;
        other[0] ^= 1;
        assert!(
            !verify_chunk_path(&root, n, i as u64, &other, &path),
            "a changed chunk passes"
        );
    }
}

/// Reads at most `step` bytes at a time.
struct Trickle<'a> {
    data: &'a [u8],
    step: usize,
}

impl std::io::Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step).min(self.data.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        Ok(n)
    }
}

/// RRBC containers (`release_bundle::Container`, `verify_bundle`,
/// RAVEN_RELEASE_BUNDLE_V1): a `.rrb` file from a USB stick or a download.
/// `data` is opened whole and through a reader that hands out a few bytes
/// at a time (the same result either way); an opened container re-encodes
/// byte for byte and its payload is the manifest's length. It is verified
/// against the test key set as a fresh build of its own target, as a build
/// newer than any bundle, and without release keys: a verified bundle is
/// listed in its log, for that target, newer than the installed build, not
/// under its floor, and its files tile the payload, whose chunk root is the
/// manifest's.
pub fn rrbc_container(data: &[u8]) {
    use raven_core::release_bundle::{chunk_root, verify_bundle, Container, VerifyCtx};
    use raven_core::tlog::EntryType;
    let whole = Container::open(data);
    let step = 1 + data.len() % 7;
    assert_eq!(
        Container::open(Trickle { data, step }),
        whole,
        "a container opens differently in pieces"
    );
    let Ok(parts) = whole else {
        return;
    };
    assert_eq!(
        parts.encode(),
        data,
        "an opened container does not re-encode"
    );
    assert_eq!(parts.payload.len() as u64, parts.manifest.payload_len);
    let set = &release_key_fixture()[0];
    let target = parts.manifest.target.as_str();
    let ctxs = [
        VerifyCtx {
            key_set: Some(set),
            stored_log: &[],
            installed_serial: 0,
            target,
            release_floor: 0,
            allow_downgrade: false,
        },
        VerifyCtx {
            key_set: Some(set),
            stored_log: &[],
            installed_serial: u64::MAX,
            target,
            release_floor: 0,
            allow_downgrade: false,
        },
        VerifyCtx {
            key_set: None,
            stored_log: &[],
            installed_serial: 0,
            target,
            release_floor: 0,
            allow_downgrade: false,
        },
    ];
    for ctx in &ctxs {
        match verify_bundle(&parts, ctx) {
            Ok(v) => {
                let m = v.manifest();
                assert!(ctx.key_set.is_some());
                assert!(v.log().contains(EntryType::Manifest, &m.digest()));
                assert_eq!(m.target, ctx.target);
                assert!(m.build_serial > ctx.installed_serial || ctx.allow_downgrade);
                assert!(m.build_serial >= v.release_floor());
                let tiled: Vec<u8> = v.files().flat_map(|(_, b)| b.iter().copied()).collect();
                assert_eq!(tiled, v.payload());
                assert_eq!(chunk_root(v.payload(), m.chunk_size), m.payload_chunk_root);
            }
            Err(e) => {
                let _ = (e.code(), e.inner_code(), e.sec_kind());
            }
        }
    }
}

/// RUP1 update exchange frames (`update_exchange::decode`,
/// `decode_for_listener`, the dial classifier, RAVEN_UPDATE_EXCHANGE_V1.md):
/// what friends pass advisories, logs and bundles with. `data` is read as a
/// frame, and its tail behind a valid version 1 header whose op is its first
/// byte (and, for HAVE, a zero request id). An accepted frame is at most
/// 65,511 bytes, keeps the offer, chunk and path caps and re-encodes byte
/// for byte; the classifier agrees with the op's role; a listener serves
/// exactly the accepted requests, takes exactly the accepted HAVEs, answers
/// anything else only with UNSUPPORTED or MALFORMED echoing the request id,
/// and never answers a reply (its own ERROR included).
pub fn rup1_frame(data: &[u8]) {
    use raven_core::update_exchange::{
        decode, decode_for_listener, encode, frame_expects_reply, frame_is_terminal_reply, is_rup1,
        ErrorCode, ListenerDecode, Role, Rup1Msg, HEADER_LEN, MAX_CHUNKS_PER_REQUEST,
        MAX_FRAME_LEN, MAX_OFFERS, NO_REQ_ID, RUP1_MAGIC, RUP1_VERSION,
    };
    fn check(frame: &[u8]) {
        let (expects, terminal) = (frame_expects_reply(frame), frame_is_terminal_reply(frame));
        assert!(
            !(expects && terminal),
            "a RUP1 frame is a request and a reply"
        );
        let listener = decode_for_listener(frame);
        match decode(frame) {
            Ok((req_id, msg)) => {
                assert!((HEADER_LEN..=MAX_FRAME_LEN).contains(&frame.len()));
                assert!(is_rup1(frame) && frame[4] == RUP1_VERSION && frame[5] == msg.op());
                assert_eq!(
                    encode(&req_id, &msg).as_deref(),
                    Ok(frame),
                    "an accepted RUP1 frame does not re-encode"
                );
                assert_eq!(expects, msg.role() == Role::Request);
                assert_eq!(terminal, msg.is_terminal());
                match &msg {
                    Rup1Msg::Have(h) => {
                        assert_eq!(req_id, NO_REQ_ID);
                        assert!(h.offers.len() <= MAX_OFFERS);
                    }
                    Rup1Msg::GetChunks { count, .. } => {
                        assert!((1..=MAX_CHUNKS_PER_REQUEST).contains(count));
                    }
                    Rup1Msg::Chunk(c) => {
                        assert!(!c.bytes.is_empty() && c.bytes.len() <= 61_440);
                        assert!(c.path.len() <= 11);
                    }
                    Rup1Msg::Error(code) => assert_ne!(code.byte(), 0),
                    _ => {}
                }
                match msg.role() {
                    Role::Request => {
                        assert_eq!(listener, ListenerDecode::Request(req_id, msg.clone()));
                        assert!(msg.answered_by(&Rup1Msg::Error(ErrorCode::Busy)));
                    }
                    Role::OneWay => assert!(matches!(listener, ListenerDecode::Have(_))),
                    Role::Reply { .. } => assert_eq!(listener, ListenerDecode::Drop),
                }
            }
            Err(e) => {
                let _ = e.code();
                assert!(
                    !matches!(
                        listener,
                        ListenerDecode::Request(..) | ListenerDecode::Have(_)
                    ),
                    "a listener took a refused frame"
                );
            }
        }
        if let ListenerDecode::Refuse(id, code) = listener {
            assert!(matches!(
                code,
                ErrorCode::Unsupported | ErrorCode::Malformed
            ));
            assert_eq!(id[..], frame[6..HEADER_LEN]);
            let reply = encode(&id, &Rup1Msg::Error(code)).expect("an ERROR encodes");
            assert!(frame_is_terminal_reply(&reply));
            assert_eq!(decode_for_listener(&reply), ListenerDecode::Drop);
        }
    }
    check(data);
    if let Some((&op, rest)) = data.split_first() {
        let req_id = if op == 0x01 {
            NO_REQ_ID
        } else {
            *b"RU\x00\x01"
        };
        let framed = [&RUP1_MAGIC[..], &[RUP1_VERSION, op], &req_id, rest].concat();
        check(&framed);
    }
}

/// A fuzz target body.
pub type Target = fn(&[u8]);

/// Every target, for smoke drivers that feed one input to all decoders.
pub const ALL_TARGETS: &[(&str, Target)] = &[
    ("envelope", envelope),
    ("store_object", store_object),
    ("rlb1_offer", rlb1_offer),
    ("carrier_frames", carrier_frames),
    ("pair_init", pair_init),
    ("device_cert", device_cert),
    ("device_revocation", device_revocation),
    ("ipc_frame", ipc_frame),
    ("session_and_records", session_and_records),
    ("rsr1_frame", rsr1_frame),
    ("rfc1_frame", rfc1_frame),
    ("ral1_decode", ral1_decode),
    ("app_frame", app_frame),
    ("rrh1_frame", rrh1_frame),
    ("rrh1_phase4_tlvs", rrh1_phase4_tlvs),
    ("relay_inputs", relay_inputs),
    ("reach_tokens", reach_tokens),
    ("portmap_reply", portmap_reply),
    ("proxy_setting", proxy_setting),
    ("relay_schedule_text", relay_schedule_text),
    ("ws_frame", ws_frame),
    ("lan_beacon_datagram", lan_beacon_datagram),
    ("rnp1_frame", rnp1_frame),
    ("pad1_frame", pad1_frame),
    ("rlk1_m1", rlk1_m1),
    ("rad1_decode", rad1_decode),
    ("rtl1_snapshot", rtl1_snapshot),
    ("rrb1_manifest", rrb1_manifest),
    ("rrbc_container", rrbc_container),
    ("rup1_frame", rup1_frame),
];
