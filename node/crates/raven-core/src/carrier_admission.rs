//! Custody admission allow-list (design 2026-10 transports §4.1, finding F3).
//!
//! Every path that takes **custody** of an object for someone else (bridge
//! store-and-forward, IPC `EnqueueSealed`, `message_router` relay, mailbox PUT)
//! calls [`admit_relayable`] before it stores or forwards anything. Only the
//! two objects a relay may ever hold pass:
//!
//! - a strict `RavenEnvelopeV1` **message** (`env_type = 1`) whose body is a
//!   sealed RVNA1 indexed-session frame (`RVNA1\0\0\0 || 0x03 || 0x01 || ...`,
//!   at least header + tag long), and
//! - a strict **ACK** (`env_type = 2`) whose body is exactly one sealed indexed
//!   ACK (same header, [`ACK_SEALED_WIRE_LEN`] bytes),
//!
//! both with `flags = 0`, an empty ratchet header, a packed size that fits one
//! Noise transport frame, `created_at` no more than the normative clock skew in
//! the future, and `expires_at` in the future but at most 24 h (+ skew) away.
//!
//! Everything else is refused before custody: PairInit / PairResponse wrapped
//! as a message (addresses and trust material in clear, PairInit §7), the
//! `0x7F` interim demo cipher, RVNA1 v1/v2 frames, plaintext ACK records, alias
//! gossip and capability records. Classification reads the fixed header bytes
//! only, never the ciphertext (umbrella §7.2): an admitted object stays opaque.
//!
//! RAL1 letters (`RAVEN_ASYNC_LETTER_V1.md`) are never RVN1, so
//! [`admit_relayable`] refuses them. Friend custody's letter ops
//! (`RAVEN_FRIEND_CUSTODY_V1.md` §10) admit them with [`admit_letter`]
//! instead: the strict header and its time window, never the ciphertext.
//!
//! Lab exception: builds with the `unsafe-demo-crypto` feature (debug only,
//! see `seal.rs`) also admit the interim demo message cipher and demo ACK
//! bodies so the mock-BLE A-B-C demo keeps working. PairInit stays refused
//! there too.

use crate::async_letter::{decode_header, Ral1Header, MAX_LETTER_LIFETIME_MS};
use crate::atsam_indexed_session::{
    ACK_SEALED_WIRE_LEN, INDEXED_SEALED_HEADER_LEN, INDEXED_SEALED_MIN_WIRE_LEN, RVNA1_PROTO,
    RVNA1_SUITE,
};
use crate::envelope::{EnvType, Envelope};
use crate::pair_init_lan_oob::{classify_message_ciphertext, PairInitOobClassify};
use crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS;
use crate::seal::SEAL_MAGIC_RVNA1;

/// Largest object a custody path holds: one Noise transport frame, so every
/// admitted object can still be delivered over any authenticated Raven link.
pub const MAX_CUSTODY_OBJECT_BYTES: usize = crate::lan_noise::MAX_TRANSPORT_PLAINTEXT;

/// `created_at` may be at most this far in the future (the normative
/// `MAX_PEER_CLOCK_SKEW_MS`, PairInit §1).
pub const MAX_CUSTODY_FUTURE_SKEW_MS: u64 = MAX_PREKEY_FUTURE_SKEW_MS;

/// Longest validity a custody path accepts, measured from its own clock: the
/// session lifetime (24 h) plus the clock skew a sender may be ahead by.
pub const MAX_CUSTODY_VALIDITY_MS: u64 = 24 * 60 * 60 * 1000 + MAX_CUSTODY_FUTURE_SKEW_MS;

/// Longest validity custody accepts for an RAL1 letter, measured from its
/// own clock: a letter's lifetime (7 d, owner decision O5-4) plus the clock
/// skew a sender may be ahead by.
pub const MAX_LETTER_CUSTODY_VALIDITY_MS: u64 = MAX_LETTER_LIFETIME_MS + MAX_CUSTODY_FUTURE_SKEW_MS;
// A whole DEPOSIT_LETTER frame (header, recipient, length, letter) fits one
// transport message, and so does the LETTER_ITEM that serves it.
const _: () =
    assert!(50 + crate::async_letter::MAX_RAL1_LEN <= crate::lan_noise::MAX_TRANSPORT_PLAINTEXT);

/// Required `flags` (the indexed-session `OUTBOUND_FLAGS`).
const CUSTODY_FLAGS: u16 = 0;

/// Why an object was refused custody. Local diagnostics only: callers map it
/// to their existing wire codes, so no new byte reaches a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyRefusal {
    /// Over [`MAX_CUSTODY_OBJECT_BYTES`].
    TooLarge,
    /// Not a strict `RavenEnvelopeV1`.
    Malformed,
    /// Neither a message nor an ACK (alias gossip, capabilities, ...).
    UnsupportedType,
    /// Non-zero `flags`.
    Flags,
    /// Non-empty ratchet header (the indexed profile sends none).
    RatchetHeader,
    /// A wrapped PairInit / PairResponse: never relay- or store-readable.
    PairingMaterial,
    /// The body is not a sealed indexed-session frame (demo cipher, RVNA1
    /// v1/v2, plaintext ACK record, anything else).
    NotSealedIndexed,
    /// `created_at` too far in the future.
    FromTheFuture,
    /// Already expired.
    Expired,
    /// Valid for longer than [`MAX_CUSTODY_VALIDITY_MS`].
    ValidityTooLong,
}

/// What custody may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayableKind {
    Message,
    Ack,
}

/// An admitted object: the decoded envelope (for the caller's bookkeeping)
/// plus its kind. The packed bytes the caller holds are what it stores.
#[derive(Debug, Clone)]
pub struct RelayableObject {
    pub kind: RelayableKind,
    pub envelope: Envelope,
}

fn sealed_indexed_header(body: &[u8]) -> bool {
    body.len() >= INDEXED_SEALED_HEADER_LEN
        && body[..8] == SEAL_MAGIC_RVNA1
        && body[8] == RVNA1_PROTO
        && body[9] == RVNA1_SUITE
}

/// Lab-only (`unsafe-demo-crypto`) bodies the mock-BLE demo relays.
#[cfg(feature = "unsafe-demo-crypto")]
fn lab_demo_body(kind: RelayableKind, body: &[u8]) -> bool {
    match kind {
        RelayableKind::Message => matches!(
            crate::seal::classify_sealed_body(body),
            crate::seal::SealClass::InterimStub
        ),
        RelayableKind::Ack => !body.is_empty(),
    }
}

#[cfg(not(feature = "unsafe-demo-crypto"))]
fn lab_demo_body(_kind: RelayableKind, _body: &[u8]) -> bool {
    false
}

/// The custody allow-list. See the module docs for the rule.
pub fn admit_relayable(packed: &[u8], now_ms: u64) -> Result<RelayableObject, CustodyRefusal> {
    if packed.len() > MAX_CUSTODY_OBJECT_BYTES {
        return Err(CustodyRefusal::TooLarge);
    }
    let envelope = Envelope::unpack(packed).ok_or(CustodyRefusal::Malformed)?;
    let kind = match EnvType::from_u8(envelope.env_type) {
        Some(EnvType::Message) => RelayableKind::Message,
        Some(EnvType::Ack) => RelayableKind::Ack,
        _ => return Err(CustodyRefusal::UnsupportedType),
    };
    if envelope.flags != CUSTODY_FLAGS {
        return Err(CustodyRefusal::Flags);
    }
    if !envelope.ratchet_header_ciphertext.is_empty() {
        return Err(CustodyRefusal::RatchetHeader);
    }
    // Before the body-shape rule, so a pairing frame is always reported (and
    // refused) as what it is, in lab builds too.
    if !matches!(
        classify_message_ciphertext(&envelope.message_ciphertext),
        PairInitOobClassify::NotPairInitOob
    ) {
        return Err(CustodyRefusal::PairingMaterial);
    }
    let body = &envelope.message_ciphertext;
    let sealed = sealed_indexed_header(body)
        && match kind {
            RelayableKind::Message => body.len() >= INDEXED_SEALED_MIN_WIRE_LEN,
            RelayableKind::Ack => body.len() == ACK_SEALED_WIRE_LEN,
        };
    if !sealed && !lab_demo_body(kind, body) {
        return Err(CustodyRefusal::NotSealedIndexed);
    }
    if envelope.created_at > now_ms.saturating_add(MAX_CUSTODY_FUTURE_SKEW_MS) {
        return Err(CustodyRefusal::FromTheFuture);
    }
    if envelope.expires_at <= now_ms {
        return Err(CustodyRefusal::Expired);
    }
    if envelope.expires_at > now_ms.saturating_add(MAX_CUSTODY_VALIDITY_MS) {
        return Err(CustodyRefusal::ValidityTooLong);
    }
    Ok(RelayableObject { kind, envelope })
}

/// Custody admission of an RAL1 letter (friend custody's DEPOSIT_LETTER,
/// `RAVEN_FRIEND_CUSTODY_V1.md` §10). Reads the header only: the strict
/// header decode ([`decode_header`]: magic, version, kind 1 or 2, flags, the
/// field rules and the exact length), then the time window: `created_at` at
/// most the clock skew ahead, `expires_at` in the future but at most
/// [`MAX_LETTER_CUSTODY_VALIDITY_MS`] away, and a lifetime of at most 7 d
/// (what every recipient refuses past, RAL1 §6 step 3). Never the
/// ciphertext, never a key; the signature is the caller's (it knows the
/// depositor).
pub fn admit_letter(bytes: &[u8], now_ms: u64) -> Result<Ral1Header, CustodyRefusal> {
    if bytes.len() > MAX_CUSTODY_OBJECT_BYTES {
        return Err(CustodyRefusal::TooLarge);
    }
    let header = decode_header(bytes).map_err(|_| CustodyRefusal::Malformed)?;
    if header.created_at_ms > now_ms.saturating_add(MAX_CUSTODY_FUTURE_SKEW_MS) {
        return Err(CustodyRefusal::FromTheFuture);
    }
    if header.expires_at_ms <= now_ms {
        return Err(CustodyRefusal::Expired);
    }
    if header.expires_at_ms > now_ms.saturating_add(MAX_LETTER_CUSTODY_VALIDITY_MS)
        || header.expires_at_ms - header.created_at_ms > MAX_LETTER_LIFETIME_MS
    {
        return Err(CustodyRefusal::ValidityTooLong);
    }
    Ok(header)
}

/// A strictly shaped RAL1 letter from `sender` to `recipient`, signed, whose
/// ciphertext is `inner_len + 16` bytes of `fill` (`inner_len` a multiple of
/// 512): the *shape* custody admits, not a letter anyone can open. For tests
/// and harnesses of custody paths in other crates.
#[doc(hidden)]
pub fn opaque_letter_for_tests(
    sender: &crate::identity::Identity,
    recipient: &[u8; 32],
    created_at_ms: u64,
    expires_at_ms: u64,
    inner_len: usize,
    fill: u8,
) -> Vec<u8> {
    use crate::async_letter::{signing_bytes, Ral1Kind, TAG_LEN};
    let secret = x25519_dalek::StaticSecret::from([fill | 0x40; 32]);
    let header = Ral1Header {
        kind: Ral1Kind::Letter,
        letter_id: [fill | 0x01; 16],
        sender_device: sender.public_key_bytes(),
        recipient_device: *recipient,
        created_at_ms,
        expires_at_ms,
        wrap_bundle_hash: [0x5B; 32],
        wrap_ephemeral: x25519_dalek::PublicKey::from(&secret).to_bytes(),
        wrap_nonce: [fill; 12],
        ct_len: (inner_len + TAG_LEN) as u32,
    };
    let mut out = header.to_bytes().to_vec();
    out.resize(out.len() + inner_len + TAG_LEN, fill);
    let signature = sender.sign(&signing_bytes(&out));
    out.extend_from_slice(&signature);
    out
}

/// A body with the fixed sealed indexed-session header and `len` bytes in
/// total (filled with `fill`). For tests and harnesses of custody paths in
/// other crates: it has the *shape* custody admits, not a decryptable frame.
#[doc(hidden)]
pub fn opaque_indexed_body_for_tests(kind: RelayableKind, fill: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(ACK_SEALED_WIRE_LEN);
    body.extend_from_slice(&SEAL_MAGIC_RVNA1);
    body.push(RVNA1_PROTO);
    body.push(RVNA1_SUITE);
    let target = match kind {
        RelayableKind::Message => INDEXED_SEALED_MIN_WIRE_LEN.max(10 + fill.len() + 16),
        RelayableKind::Ack => ACK_SEALED_WIRE_LEN,
    };
    let mut i = 0usize;
    while body.len() < target {
        body.push(if fill.is_empty() {
            0x5a
        } else {
            fill[i % fill.len()]
        });
        i += 1;
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::pair_init::{INIT_MAGIC, INIT_WIRE_LEN, RESPONSE_MAGIC, RESPONSE_WIRE_LEN};

    const NOW: u64 = 1_800_000_000_000;

    fn env(env_type: EnvType, body: Vec<u8>) -> Envelope {
        let mut e = Envelope {
            env_type: env_type as u8,
            flags: 0,
            message_id: [0x11; 16],
            routing_tag: [0x22; 16],
            dest_device_hint: 0,
            created_at: NOW,
            expires_at: NOW + 60 * 60 * 1000,
            hop_limit: 8,
            replication_budget: 2,
            anti_replay_nonce: [0x33; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: body,
            sender_authentication: vec![],
        };
        e.sign_with(&Identity::from_seed(&[0x44; 32]));
        e
    }

    fn msg() -> Envelope {
        env(
            EnvType::Message,
            opaque_indexed_body_for_tests(RelayableKind::Message, b"ct"),
        )
    }

    fn ack() -> Envelope {
        env(
            EnvType::Ack,
            opaque_indexed_body_for_tests(RelayableKind::Ack, b"ack"),
        )
    }

    fn refusal(e: &Envelope) -> CustodyRefusal {
        admit_relayable(&e.pack(), NOW).unwrap_err()
    }

    #[test]
    fn sealed_indexed_message_and_ack_are_admitted() {
        let m = admit_relayable(&msg().pack(), NOW).unwrap();
        assert_eq!(m.kind, RelayableKind::Message);
        let a = admit_relayable(&ack().pack(), NOW).unwrap();
        assert_eq!(a.kind, RelayableKind::Ack);
        // Legacy-hint senders are not refused (a hop rewrites nothing).
        let mut legacy = msg();
        legacy.dest_device_hint = 0x0123_4567_89ab_cdef;
        assert!(admit_relayable(&legacy.pack(), NOW).is_ok());
    }

    #[test]
    fn pairing_material_is_never_admitted() {
        let mut init = INIT_MAGIC.to_vec();
        init.resize(INIT_WIRE_LEN, 0x01);
        let mut resp = RESPONSE_MAGIC.to_vec();
        resp.resize(RESPONSE_WIRE_LEN, 0x02);
        for body in [init, resp] {
            assert_eq!(
                refusal(&env(EnvType::Message, body.clone())),
                CustodyRefusal::PairingMaterial
            );
            assert_eq!(
                refusal(&env(EnvType::Ack, body)),
                CustodyRefusal::PairingMaterial
            );
        }
        // The real wrapper (hop 0 / budget 0, short TTL) is refused as well.
        let wrapped = crate::pair_init_lan_oob::wrap_oob_wire(
            &{
                let mut w = INIT_MAGIC.to_vec();
                w.resize(INIT_WIRE_LEN, 0x07);
                w
            },
            crate::pair_init_lan_oob::PairInitOobKind::PairInit,
            &Identity::from_seed(&[0x45; 32]),
            [0; 16],
            NOW,
            &mut rand::thread_rng(),
        )
        .unwrap();
        assert_eq!(
            admit_relayable(&wrapped, NOW).unwrap_err(),
            CustodyRefusal::PairingMaterial
        );
    }

    /// RSR1 frames (session reset) ride only authenticated direct links and
    /// are never custody objects.
    #[test]
    fn rsr1_is_refused_custody() {
        let a = Identity::from_seed(&[0x61; 32]);
        let b = Identity::from_seed(&[0x62; 32]);
        let query = crate::session_reset::session_query_frame(
            &a,
            &b.public_key_bytes(),
            &msg().pack(),
            NOW,
        )
        .unwrap();
        assert_eq!(
            admit_relayable(&query, NOW).unwrap_err(),
            CustodyRefusal::Malformed
        );
    }

    #[test]
    fn other_bodies_types_and_shapes_are_refused() {
        // Plaintext / demo / other RVNA1 protocols.
        let mut demo = SEAL_MAGIC_RVNA1.to_vec();
        demo.extend_from_slice(&[crate::seal::STUB_PROTO, 0x01]);
        demo.resize(64, 0);
        let mut v2 = SEAL_MAGIC_RVNA1.to_vec();
        v2.extend_from_slice(&[0x02, 0x01]);
        v2.resize(64, 0);
        for body in [b"hello plaintext".to_vec(), v2, vec![]] {
            assert_eq!(
                refusal(&env(EnvType::Message, body)),
                CustodyRefusal::NotSealedIndexed
            );
        }
        if !cfg!(feature = "unsafe-demo-crypto") {
            assert_eq!(
                refusal(&env(EnvType::Message, demo)),
                CustodyRefusal::NotSealedIndexed
            );
            // A plaintext 101-byte ACK record is not a sealed ACK.
            assert_eq!(
                refusal(&env(EnvType::Ack, vec![0x01; 101])),
                CustodyRefusal::NotSealedIndexed
            );
        }
        // A sealed ACK must be exactly one ACK frame.
        let mut long_ack = opaque_indexed_body_for_tests(RelayableKind::Ack, b"x");
        long_ack.push(0);
        if !cfg!(feature = "unsafe-demo-crypto") {
            assert_eq!(
                refusal(&env(EnvType::Ack, long_ack)),
                CustodyRefusal::NotSealedIndexed
            );
        }
        // Truncated message frame (header without tag).
        let short = opaque_indexed_body_for_tests(RelayableKind::Message, b"")
            [..INDEXED_SEALED_HEADER_LEN]
            .to_vec();
        assert_eq!(
            refusal(&env(EnvType::Message, short)),
            CustodyRefusal::NotSealedIndexed
        );
        for t in [EnvType::AliasGossip, EnvType::Capabilities] {
            let body = opaque_indexed_body_for_tests(RelayableKind::Message, b"c");
            assert_eq!(refusal(&env(t, body)), CustodyRefusal::UnsupportedType);
        }
        let mut flagged = msg();
        flagged.flags = 1;
        flagged.sign_with(&Identity::from_seed(&[0x44; 32]));
        assert_eq!(refusal(&flagged), CustodyRefusal::Flags);
        let mut header = msg();
        header.ratchet_header_ciphertext = vec![1, 2, 3];
        header.sign_with(&Identity::from_seed(&[0x44; 32]));
        assert_eq!(refusal(&header), CustodyRefusal::RatchetHeader);
        assert_eq!(
            admit_relayable(b"RVN1 not an envelope", NOW).unwrap_err(),
            CustodyRefusal::Malformed
        );
        let mut big = msg();
        big.message_ciphertext
            .resize(MAX_CUSTODY_OBJECT_BYTES, 0x00);
        big.sign_with(&Identity::from_seed(&[0x44; 32]));
        assert_eq!(refusal(&big), CustodyRefusal::TooLarge);
    }

    #[test]
    fn time_window_is_bounded() {
        let mut future = msg();
        future.created_at = NOW + MAX_CUSTODY_FUTURE_SKEW_MS + 1;
        future.expires_at = future.created_at + 1000;
        assert_eq!(refusal(&future), CustodyRefusal::FromTheFuture);
        let mut skewed = msg();
        skewed.created_at = NOW + MAX_CUSTODY_FUTURE_SKEW_MS;
        skewed.expires_at = skewed.created_at + 1000;
        assert!(admit_relayable(&skewed.pack(), NOW).is_ok());
        let mut expired = msg();
        expired.created_at = NOW - 10;
        expired.expires_at = NOW;
        assert_eq!(refusal(&expired), CustodyRefusal::Expired);
        let mut long = msg();
        long.expires_at = NOW + MAX_CUSTODY_VALIDITY_MS + 1;
        assert_eq!(refusal(&long), CustodyRefusal::ValidityTooLong);
        let mut day = msg();
        day.expires_at = NOW + 24 * 60 * 60 * 1000;
        assert!(admit_relayable(&day.pack(), NOW).is_ok());
    }

    /// Admission is opaque: it never needs, or touches, a key.
    #[test]
    fn admission_reads_only_the_fixed_header() {
        let mut a = msg();
        let mut b = msg();
        let n = a.message_ciphertext.len();
        a.message_ciphertext[n - 1] = 0x00;
        b.message_ciphertext[n - 1] = 0xff;
        assert!(admit_relayable(&a.pack(), NOW).is_ok());
        assert!(admit_relayable(&b.pack(), NOW).is_ok());
    }

    // ── RAL1 letters (friend custody §10, Phase 5 P5.13) ──────────────────

    const DAY: u64 = 24 * 60 * 60 * 1000;

    fn letter(created: u64, expires: u64, fill: u8) -> Vec<u8> {
        let alice = Identity::from_seed(&[0xA0; 32]);
        opaque_letter_for_tests(&alice, &[0xB0; 32], created, expires, 512, fill)
    }

    /// A letter is not RVN1: the RVN1 allow-list refuses it on every path,
    /// as it did before the letter ops existed.
    #[test]
    fn admit_relayable_still_refuses_ral1() {
        let letter = letter(NOW, NOW + DAY, 1);
        assert!(admit_letter(&letter, NOW).is_ok());
        assert_eq!(
            admit_relayable(&letter, NOW).unwrap_err(),
            CustodyRefusal::Malformed
        );
        // And an RVN1 envelope is never a letter.
        assert_eq!(
            admit_letter(&msg().pack(), NOW).unwrap_err(),
            CustodyRefusal::Malformed
        );
    }

    /// Letter admission is opaque: the ciphertext and the signature are never
    /// read (any bytes there pass); the header is strict, and its times are
    /// bounded by 7 d plus the skew.
    #[test]
    fn admit_letter_reads_header_only() {
        let good = letter(NOW, NOW + 7 * DAY, 2);
        let header = admit_letter(&good, NOW).unwrap();
        assert_eq!(header.recipient_device, [0xB0; 32]);
        // Another ciphertext and a broken signature: still admitted (the
        // custodian checks the signature against the depositor itself).
        let mut other = good.clone();
        other[crate::async_letter::HEADER_LEN] ^= 0xFF;
        let last = other.len() - 1;
        other[last] ^= 0xFF;
        assert_eq!(admit_letter(&other, NOW).unwrap(), header);
        // The header is strict: kind 3, flags, a short or long frame.
        for (at, value) in [(5usize, 3u8), (7, 1), (4, 2), (0, b'X')] {
            let mut bad = good.clone();
            bad[at] = value;
            assert_eq!(
                admit_letter(&bad, NOW).unwrap_err(),
                CustodyRefusal::Malformed,
                "byte {at}"
            );
        }
        let mut long = good.clone();
        long.push(0);
        assert_eq!(
            admit_letter(&long, NOW).unwrap_err(),
            CustodyRefusal::Malformed
        );
        assert_eq!(
            admit_letter(&good[..good.len() - 1], NOW).unwrap_err(),
            CustodyRefusal::Malformed
        );
        assert_eq!(
            admit_letter(&vec![0u8; MAX_CUSTODY_OBJECT_BYTES + 1], NOW).unwrap_err(),
            CustodyRefusal::TooLarge
        );
        // The time window.
        let skew = MAX_CUSTODY_FUTURE_SKEW_MS;
        assert!(admit_letter(&letter(NOW + skew, NOW + skew + DAY, 3), NOW).is_ok());
        assert_eq!(
            admit_letter(&letter(NOW + skew + 1, NOW + 2 * DAY, 3), NOW).unwrap_err(),
            CustodyRefusal::FromTheFuture
        );
        assert_eq!(
            admit_letter(&letter(NOW - DAY, NOW, 3), NOW).unwrap_err(),
            CustodyRefusal::Expired
        );
        // 7 d + skew from now (created at the skew, a 7 d lifetime):
        // admitted; one millisecond more is refused.
        let edge = NOW + MAX_LETTER_CUSTODY_VALIDITY_MS;
        assert!(admit_letter(&letter(edge - 7 * DAY, edge, 4), NOW).is_ok());
        assert_eq!(
            admit_letter(&letter(edge - 7 * DAY, edge + 1, 4), NOW).unwrap_err(),
            CustodyRefusal::ValidityTooLong
        );
        assert_eq!(
            admit_letter(&letter(NOW - 1, NOW + 7 * DAY, 4), NOW).unwrap_err(),
            CustodyRefusal::ValidityTooLong,
            "a lifetime over 7 d"
        );
    }
}
