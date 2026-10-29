//! How far a contact's clock runs ahead of ours, from what it sent us
//! (cutoff pack CP.7, F10 / M11).
//!
//! In a long cutoff there is no network time, and a laptop's clock may be set
//! by hand. Raven refuses a PairInit, a PairResponse, an envelope or a prekey
//! bundle dated more than five minutes in its future
//! ([`crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS`],
//! [`crate::indexed_session_store::MAX_ENDPOINT_FUTURE_SKEW_MS`]), and nothing
//! said "clock". Each side can see only the half where the **other** side is
//! ahead: an object from the future. The refusals stay exactly as they are
//! (error kinds, texts and codes); their callers take the skew as a side value
//! from here and explain it. Raven never corrects the clock and never asks a
//! time server.
//!
//! The refusing checks, and what each one's side value is measured from:
//! - `prekey_lifecycle` `PairInitClockSkew` and `pair_init::verify_init`
//!   `NotCurrentlyValid`: the PairInit's `created_at_ms`;
//! - `pair_init::verify_response` `ConfirmationMismatch`: the PairResponse's
//!   `created_at_ms`;
//! - `indexed_session_store` `endpoint_time_window_valid` (a message or an
//!   ACK, `EndpointNotCurrentlyValid`): the envelope's `created_at`
//!   ([`frame_future_by_ms`]; PairInit and PairResponse travel in such an
//!   envelope too, stamped with the same clock);
//! - a dialer's check of the peer's RLB1 offer (`PREKEY_NOT_YET_VALID`): its
//!   prekey bundle's `created_at_ms` ([`bundle_future_by_ms`]).

use crate::envelope::Envelope;
use crate::indexed_session_store::MAX_ENDPOINT_FUTURE_SKEW_MS;
use crate::lan_rlb1::LanBundle;
use crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS;

/// How far in the future an object may be dated before it is refused: the
/// same five minutes for every check named above.
pub const FUTURE_SKEW_MS: u64 = MAX_ENDPOINT_FUTURE_SKEW_MS;
const _: () = assert!(MAX_ENDPOINT_FUTURE_SKEW_MS == MAX_PREKEY_FUTURE_SKEW_MS);

/// How far `created_at_ms` is ahead of `now_ms` when it is beyond the
/// [`FUTURE_SKEW_MS`] the checks tolerate (exactly when they refuse it as
/// "from the future"); None otherwise.
pub fn future_by_ms(created_at_ms: u64, now_ms: u64) -> Option<u64> {
    (created_at_ms > now_ms.saturating_add(FUTURE_SKEW_MS)).then(|| created_at_ms - now_ms)
}

/// [`future_by_ms`] of one frame from a contact: a RavenEnvelopeV1 (message,
/// ACK, or the envelope a PairInit or PairResponse travels in). None for
/// anything else (an RLB1 offer, route hints) and for a frame in time.
pub fn frame_future_by_ms(frame: &[u8], now_ms: u64) -> Option<u64> {
    future_by_ms(Envelope::unpack(frame)?.created_at, now_ms)
}

/// Whether `frame` is a RavenEnvelopeV1 dated within the window at `now_ms`
/// (not from the future): evidence that its sender's clock agrees with ours.
pub fn frame_in_time(frame: &[u8], now_ms: u64) -> bool {
    Envelope::unpack(frame).is_some_and(|env| future_by_ms(env.created_at, now_ms).is_none())
}

/// [`future_by_ms`] of a peer's RLB1 bundle: its prekey bundle's creation
/// time (`PREKEY_NOT_YET_VALID` past the window).
pub fn bundle_future_by_ms(bundle: &LanBundle, now_ms: u64) -> Option<u64> {
    future_by_ms(bundle.prekey.created_at_ms, now_ms)
}

/// What one object from a contact said about its clock, for the caller of a
/// refusing check (see the module notes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerClock {
    /// Refused as dated this many ms in our future.
    Ahead(u64),
    /// Accepted (a message, an ACK or a PairInit): the contact's clock is
    /// within the window of ours.
    Agrees,
}

/// `ahead_ms` in whole minutes, rounded to the nearest (what "about N min"
/// says); saturates at the ends of `i32`.
pub fn minutes(ahead_ms: i64) -> i32 {
    let rounded = if ahead_ms >= 0 {
        ahead_ms.saturating_add(30_000) / 60_000
    } else {
        ahead_ms.saturating_sub(30_000) / 60_000
    };
    i32::try_from(rounded).unwrap_or(if rounded < 0 { i32::MIN } else { i32::MAX })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvType;
    use crate::identity::Identity;
    use crate::indexed_session_store::IndexedSessionStoreError;
    use crate::pair_init::PairInitError;
    use crate::prekey_lifecycle::PrekeyLifecycleError;

    const NOW: u64 = 1_800_000_000_000;
    const MIN: u64 = 60_000;

    #[test]
    fn future_by_ms_is_some_exactly_past_the_window() {
        let cases: &[(u64, Option<u64>)] = &[
            (NOW - 10 * MIN, None),
            (NOW, None),
            (NOW + 4 * MIN, None),
            (NOW + 5 * MIN, None),
            (NOW + 5 * MIN + 1, Some(5 * MIN + 1)),
            (NOW + 10 * MIN, Some(10 * MIN)),
            (u64::MAX, Some(u64::MAX - NOW)),
        ];
        for &(created, want) in cases {
            assert_eq!(future_by_ms(created, NOW), want, "created={created}");
        }
        // A clock at the far end cannot overflow the window.
        assert_eq!(future_by_ms(u64::MAX, u64::MAX - 1), None);
        assert_eq!(future_by_ms(0, 0), None);
    }

    #[test]
    fn minutes_rounds_to_the_nearest_and_saturates() {
        let cases: &[(i64, i32)] = &[
            (0, 0),
            (29_999, 0),
            (30_000, 1),
            (599_000, 10),
            (600_000, 10),
            (629_999, 10),
            (-600_000, -10),
            (-630_000, -11),
            (i64::MAX, i32::MAX),
            (i64::MIN, i32::MIN),
        ];
        for &(ms, want) in cases {
            assert_eq!(minutes(ms), want, "ms={ms}");
        }
    }

    fn envelope(created_at: u64, env_type: EnvType) -> Vec<u8> {
        let id = Identity::from_seed(&[0x42; 32]);
        let mut env = Envelope {
            env_type: env_type as u8,
            flags: 0,
            message_id: [1; 16],
            routing_tag: [2; 16],
            dest_device_hint: 0,
            created_at,
            expires_at: created_at + 3_600_000,
            hop_limit: 0,
            replication_budget: 0,
            anti_replay_nonce: [3; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![4; 32],
            sender_authentication: vec![],
        };
        env.sign_with(&id);
        env.pack()
    }

    #[test]
    fn frames_are_measured_by_their_envelope_time() {
        let ahead = envelope(NOW + 10 * MIN, EnvType::Message);
        let ack = envelope(NOW + 6 * MIN, EnvType::Ack);
        let in_time = envelope(NOW + 4 * MIN, EnvType::Ack);
        assert_eq!(frame_future_by_ms(&ahead, NOW), Some(10 * MIN));
        assert_eq!(frame_future_by_ms(&ack, NOW), Some(6 * MIN));
        assert_eq!(frame_future_by_ms(&in_time, NOW), None);
        assert!(frame_in_time(&in_time, NOW));
        assert!(!frame_in_time(&ahead, NOW));
        // Not an envelope (an RLB1 offer, garbage): says nothing.
        assert_eq!(frame_future_by_ms(b"RLB1....", NOW), None);
        assert!(!frame_in_time(b"RLB1....", NOW));
    }

    /// Each check refuses past exactly the instant [`future_by_ms`] measures
    /// from: a prekey bundle (an RLB1 offer), a PairInit, a PairResponse.
    #[test]
    fn the_side_value_starts_where_each_refusal_does() {
        for created in [NOW + FUTURE_SKEW_MS, NOW + FUTURE_SKEW_MS + 1] {
            let bundle = crate::prekey_bundle::PrekeyBundle::from_hybrid_public(
                "ash-primary",
                [7; 32],
                vec![1; crate::prekey_bundle::MLKEM768_EK_LEN],
                1,
                created,
                created + 3_600_000,
            )
            .unwrap();
            let refused = bundle.verify(NOW).err();
            assert_eq!(
                future_by_ms(created, NOW).is_some(),
                refused.as_deref() == Some("PREKEY_NOT_YET_VALID"),
                "created={created} {refused:?}"
            );
        }
    }

    /// The refusals keep their kinds and texts byte for byte: CP.7 only adds
    /// the side value, so no frozen text, cause needle or registry code moves.
    #[test]
    fn refusal_texts_are_unchanged() {
        assert_eq!(
            PrekeyLifecycleError::PairInitClockSkew.to_string(),
            "PairInit creation time exceeds allowed clock skew"
        );
        assert_eq!(
            PairInitError::NotCurrentlyValid.to_string(),
            "PairInit is not currently valid"
        );
        assert_eq!(
            PairInitError::ConfirmationMismatch.to_string(),
            "PairResponse does not confirm the exact accepted PairInit"
        );
        assert_eq!(
            IndexedSessionStoreError::EndpointNotCurrentlyValid.redacted_display(),
            "endpoint envelope or bound session is not currently valid"
        );
    }
}
