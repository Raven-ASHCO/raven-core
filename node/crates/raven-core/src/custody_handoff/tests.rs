//! The RHW1 codec (P5.18). The record's RSO1 is only bounded by the codec,
//! so these tests use opaque bytes; the RSO1 rules and the vectors are in
//! `friend_custody` tests (`tests/handoff.rs`), next to the RFC1 frames.

use super::*;

fn rso1(len: usize) -> Vec<u8> {
    vec![0x5A; len]
}

#[test]
fn constants_are_the_spec_numbers() {
    assert_eq!(RHW1_FIXED_LEN, 44);
    assert_eq!(MAX_RHW1_RSO1, 65_461);
    assert_eq!(MAX_RHW1_ENVELOPE, 65_402);
    assert_eq!(MIN_RFC1_RSO1, 145);
    // A HANDOFF frame of the largest record is exactly one transport
    // plaintext.
    assert_eq!(
        RFC1_HEADER_LEN + RHW1_FIXED_LEN + MAX_RHW1_RSO1,
        crate::lan_noise::MAX_TRANSPORT_PLAINTEXT
    );
    // The largest LAN send fits (49,344 bytes).
    assert_eq!(
        crate::lan_noise::MAX_LAN_ENDPOINT_TEXT + 26 + 16 + 86 + 64,
        49_344
    );
}

#[test]
fn records_round_trip_at_both_bounds() {
    for len in [MIN_RFC1_RSO1, 1_000, MAX_RHW1_RSO1] {
        for record in [
            Rhw1::forward([0xF2; 32], rso1(len)),
            Rhw1::deliver(rso1(len)),
        ] {
            let bytes = record.encode();
            assert_eq!(bytes.len(), RHW1_FIXED_LEN + len);
            assert_eq!(&bytes[..4], b"RHW1");
            assert_eq!(bytes[4], 1);
            assert_eq!(bytes[5], record.kind as u8);
            assert_eq!(&bytes[6..8], &[0, 0]);
            assert_eq!(Rhw1::decode(&bytes), Ok(record));
        }
    }
}

/// Every rule the spec lists (§1): short input, magic, version 2, kind 0
/// or 3, flags, reserved, FORWARD with a zero hop, DELIVER with a hop, the
/// RSO1 length out of range, and a length mismatch either way.
#[test]
fn decode_rejects_every_broken_rule() {
    let good = Rhw1::forward([0xF2; 32], rso1(MIN_RFC1_RSO1)).encode();
    let deliver = Rhw1::deliver(rso1(MIN_RFC1_RSO1)).encode();
    let edit = |base: &[u8], at: usize, value: u8| {
        let mut b = base.to_vec();
        b[at] = value;
        b
    };
    let with_len = |base: &[u8], n: usize, body: usize| {
        let mut b = base[..RHW1_FIXED_LEN].to_vec();
        b[40..44].copy_from_slice(&(n as u32).to_be_bytes());
        b.extend(std::iter::repeat_n(0x5A, body));
        b
    };
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("empty", vec![], "RHW1_MALFORMED_HEADER"),
        ("short", good[..43].to_vec(), "RHW1_MALFORMED_HEADER"),
        ("magic", edit(&good, 3, b'2'), "RHW1_MALFORMED_HEADER"),
        ("version 0", edit(&good, 4, 0), "RHW1_VERSION"),
        ("version 2", edit(&good, 4, 2), "RHW1_VERSION"),
        ("kind 0", edit(&good, 5, 0), "RHW1_KIND"),
        ("kind 3", edit(&good, 5, 3), "RHW1_KIND"),
        ("flags", edit(&good, 6, 1), "RHW1_FLAGS"),
        ("reserved", edit(&good, 7, 0x80), "RHW1_FLAGS"),
        (
            "forward zero hop",
            edit(&deliver, 5, Rhw1Kind::Forward as u8),
            "RHW1_FORWARD_NO_HOP",
        ),
        (
            "deliver with a hop",
            edit(&good, 5, Rhw1Kind::Deliver as u8),
            "RHW1_DELIVER_HOP",
        ),
        (
            "deliver with one hop byte",
            edit(&deliver, 39, 1),
            "RHW1_DELIVER_HOP",
        ),
        (
            "rso1 below the minimum",
            with_len(&good, MIN_RFC1_RSO1 - 1, MIN_RFC1_RSO1 - 1),
            "RHW1_RSO1_LEN",
        ),
        (
            "rso1 above the maximum",
            with_len(&good, MAX_RHW1_RSO1 + 1, MAX_RHW1_RSO1 + 1),
            "RHW1_RSO1_LEN",
        ),
        ("rso1 zero", with_len(&good, 0, 0), "RHW1_RSO1_LEN"),
        (
            "trailing byte",
            [good.clone(), vec![0]].concat(),
            "RHW1_LENGTH",
        ),
        (
            "one byte short",
            good[..good.len() - 1].to_vec(),
            "RHW1_LENGTH",
        ),
        (
            "length says more",
            with_len(&good, MIN_RFC1_RSO1 + 1, MIN_RFC1_RSO1),
            "RHW1_LENGTH",
        ),
    ];
    for (what, bytes, want) in cases {
        assert_eq!(Rhw1::decode(&bytes), Err(want), "{what}");
    }
}

#[test]
fn tags_actions() {
    assert_eq!(TagsAction::from_u8(1), Some(TagsAction::Register));
    assert_eq!(TagsAction::from_u8(2), Some(TagsAction::Withdraw));
    for v in [0u8, 3, 0x81, 0xFF] {
        assert_eq!(TagsAction::from_u8(v), None);
    }
    assert_eq!(MAX_TAG_ENTRIES, 32);
}

mod store;
