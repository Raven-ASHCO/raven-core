//! Nearby BLE ephemeral discovery — no permanent Raven ID in advertisements.
//!
//! RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3 forbids a generic "Raven user nearby"
//! marker: the advertised bytes are only random-looking values (a fresh
//! token and a commitment to a fresh secret), with no domain prefix, no
//! cleartext timestamp and no constant TTL.

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The CLI's store of this device's live nearby advertisements (`raven
/// nearby`; privacy pack PP.6: RMS1 kind 27 in a sealed profile).
pub const NEARBY_REGISTRY_FILE: &str = "nearby_registry.json";

/// Exact length of [`NearbyAdvertisement::advertise_bytes`]:
/// `ephemeral_token(16) || session_commitment(32)`.
pub const ADVERT_LEN: usize = 48;

/// Ephemeral nearby advertisement (V1 mock / software substitute for GATT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearbyAdvertisement {
    /// Rotating ephemeral token — NOT a Raven ID.
    pub ephemeral_token: [u8; 16],
    pub session_commitment: [u8; 32],
    /// Local only: never part of the advertised bytes.
    pub issued_at_ms: u64,
    /// Local only: never part of the advertised bytes.
    pub ttl_ms: u64,
}

impl NearbyAdvertisement {
    /// Mint with a caller-chosen confirm secret (tests). A constant secret
    /// lets anyone recompute the commitment from the token and so recognise
    /// the advertisement; production callers use [`Self::mint_random`].
    pub fn mint(now_ms: u64, ttl_ms: u64, confirm_secret: &[u8]) -> Self {
        let mut ephemeral_token = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut ephemeral_token);
        let mut h = Sha256::new();
        h.update(b"raven/nearby/v1");
        h.update(ephemeral_token);
        h.update(confirm_secret);
        let session_commitment = h.finalize().into();
        Self {
            ephemeral_token,
            session_commitment,
            issued_at_ms: now_ms,
            ttl_ms,
        }
    }

    /// Mint with a fresh 32-byte confirm secret drawn from the OS RNG, so the
    /// commitment is not a public test for a Raven advertisement. Returns the
    /// secret for the caller to keep or drop. A draw whose bytes happen to
    /// contain a Raven address marker is redrawn (about 1 in 10^7), so the
    /// result always passes [`NearbyRegistry::publish_ephemeral`].
    pub fn mint_random(now_ms: u64, ttl_ms: u64) -> (Self, Zeroizing<[u8; 32]>) {
        loop {
            let mut secret = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(secret.as_mut());
            let adv = Self::mint(now_ms, ttl_ms, secret.as_ref());
            if !adv.contains_permanent_raven_id() {
                return (adv, secret);
            }
        }
    }

    pub fn is_live(&self, now_ms: u64) -> bool {
        now_ms <= self.issued_at_ms.saturating_add(self.ttl_ms)
    }

    /// Exactly `ephemeral_token || session_commitment` ([`ADVERT_LEN`]
    /// bytes): no prefix, no issued_at_ms, no ttl_ms (RAVEN_PRIVATE_RENDEZVOUS_V1
    /// §5.3: no generic Raven marker). MUST NOT embed a permanent address.
    pub fn advertise_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ADVERT_LEN);
        out.extend_from_slice(&self.ephemeral_token);
        out.extend_from_slice(&self.session_commitment);
        out
    }

    /// Scans every advertised byte (no skipped prefix) for the `rvn1`
    /// address marker in any ASCII case and for a whole bech32m Raven
    /// address.
    pub fn contains_permanent_raven_id(&self) -> bool {
        let bytes = self.advertise_bytes();
        if bytes.windows(4).any(|w| w.eq_ignore_ascii_case(b"rvn1")) {
            return true;
        }
        let addr_len = crate::address::HRP.len() + 1 + RAVEN_ADDRESS_DATA_CHARS;
        bytes.windows(addr_len).any(|w| {
            std::str::from_utf8(w)
                .is_ok_and(|s| crate::address::decode_address(&s.to_ascii_lowercase()).is_some())
        })
    }
}

/// Data-part length of a canonical RavenAddressV1: a 21-byte payload is 34
/// five-bit characters, plus the 6-character bech32m checksum.
const RAVEN_ADDRESS_DATA_CHARS: usize = 34 + 6;

/// After mutual confirm, bind ephemeral session → Raven ID locally (not in adv).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearbyConfirmBinding {
    pub ephemeral_token: [u8; 16],
    pub peer_raven_id: String,
    pub peer_pub: [u8; 32],
    pub confirmed_at_ms: u64,
}

#[derive(Default)]
pub struct NearbyRegistry {
    pub live_ads: Vec<NearbyAdvertisement>,
    pub confirmed: Vec<NearbyConfirmBinding>,
}

impl NearbyRegistry {
    pub fn publish_ephemeral(&mut self, adv: NearbyAdvertisement) -> Result<(), String> {
        if adv.contains_permanent_raven_id() {
            return Err("NEARBY_PERMANENT_ID_IN_ADV".into());
        }
        self.live_ads.push(adv);
        Ok(())
    }

    pub fn scan_live(&self, now_ms: u64) -> Vec<&NearbyAdvertisement> {
        self.live_ads.iter().filter(|a| a.is_live(now_ms)).collect()
    }

    pub fn confirm(
        &mut self,
        token: [u8; 16],
        peer_raven_id: String,
        peer_pub: [u8; 32],
        now_ms: u64,
    ) {
        self.confirmed.push(NearbyConfirmBinding {
            ephemeral_token: token,
            peer_raven_id,
            peer_pub,
            confirmed_at_ms: now_ms,
        });
    }

    /// Confirm-to-bind only when the user-entered safety phrase matches.
    pub fn confirm_with_phrase(
        &mut self,
        token: [u8; 16],
        peer_raven_id: String,
        peer_pub: [u8; 32],
        now_ms: u64,
        session_commitment: &[u8; 32],
        phrase: &str,
    ) -> Result<(), String> {
        let expect = nearby_safety_phrase(&token, session_commitment);
        if !constant_eq_ascii(&expect, phrase.trim()) {
            return Err("NEARBY_SAFETY_PHRASE_MISMATCH".into());
        }
        self.confirm(token, peer_raven_id, peer_pub, now_ms);
        Ok(())
    }
}

/// Short human-checkable phrase from ephemeral token + session commitment.
/// Shown OOB before pin — finding nearby ≠ verifying a person.
pub fn nearby_safety_phrase(token: &[u8; 16], commitment: &[u8; 32]) -> String {
    const WORDS: [&str; 32] = [
        "amber", "birch", "cedar", "delta", "ember", "flint", "grove", "harbor", "iris", "jade",
        "kite", "lotus", "maple", "nova", "olive", "pine", "quartz", "river", "sage", "tide",
        "umbra", "vale", "willow", "xenon", "yarrow", "zephyr", "coral", "dusk", "echo", "fern",
        "glen", "haze",
    ];
    let mut h = Sha256::new();
    h.update(b"raven/nearby/safety-phrase/v1");
    h.update(token);
    h.update(commitment);
    let dig: [u8; 32] = h.finalize().into();
    let a = WORDS[(dig[0] as usize) % WORDS.len()];
    let b = WORDS[(dig[1] as usize) % WORDS.len()];
    let c = WORDS[(dig[2] as usize) % WORDS.len()];
    format!("{a}-{b}-{c}")
}

fn constant_eq_ascii(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
