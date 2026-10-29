//! Ed25519 identity — never log or print private keys.

use crate::address::encode_address;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

pub struct Identity {
    verifying: VerifyingKey,
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self { verifying, signing }
    }

    /// Load from 32-byte RFC-8032 seed (test vectors / persistence).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let verifying = signing.verifying_key();
        Self { verifying, signing }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    pub fn address(&self) -> String {
        encode_address(&self.public_key_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        // No Raven object may ever look like an AgentSign delegation (every
        // test that signs a Raven format proves its bytes cannot).
        debug_assert!(
            !msg.starts_with(&crate::agent_sign::AGENT_DELEGATION_PREFIX),
            "Raven signing input carries the AgentSign delegation prefix"
        );
        self.signing.sign(msg).to_bytes()
    }

    /// The only path that signs AgentSign delegation bytes
    /// ([`crate::agent_sign::sign`]).
    pub(crate) fn sign_agent_delegation(
        &self,
        bytes: &crate::agent_sign::AgentDelegationBytes,
    ) -> [u8; 64] {
        self.signing.sign(bytes.as_bytes()).to_bytes()
    }

    /// Strict verification of an AgentSign delegation signature.
    pub(crate) fn verify_agent_delegation(
        pub_key: &[u8; 32],
        bytes: &crate::agent_sign::AgentDelegationBytes,
        sig: &[u8; 64],
    ) -> bool {
        Self::verify_strict_raw(pub_key, bytes.as_bytes(), sig)
    }

    /// Strict Ed25519 verification for every identity/device/record signature.
    ///
    /// Rejects small-order ("weak") public keys and small-order `R`, and
    /// requires canonical `s`. A weak key such as the identity point accepts
    /// `(R = identity, s = 0)` for *every* message, so non-strict
    /// verification would let a crafted key "sign" arbitrary PairInit, cert,
    /// revocation or record bytes without a private key. Honestly generated
    /// keys never hit these checks, so interop with other RFC 8032 signers is
    /// unchanged.
    ///
    /// An AgentSign delegation (bytes starting with
    /// [`crate::agent_sign::AGENT_DELEGATION_PREFIX`]) is never a Raven
    /// signature: refused here in every build.
    pub fn verify(pub_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        if msg.starts_with(&crate::agent_sign::AGENT_DELEGATION_PREFIX) {
            return false;
        }
        Self::verify_strict_raw(pub_key, msg, sig)
    }

    fn verify_strict_raw(pub_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pub_key) else {
            return false;
        };
        if vk.is_weak() {
            return false;
        }
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        vk.verify_strict(msg, &signature).is_ok()
    }

    /// Seed bytes for encrypted persistence only — callers MUST NOT print.
    ///
    /// Returns a plain `Copy` array; the caller owns wiping it. New code should
    /// prefer [`Identity::seed_zeroizing`], which wipes itself on drop.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Same bytes as [`Identity::seed_bytes`], wrapped so the copy is wiped on
    /// drop (and cannot be silently left behind in a plain local).
    pub fn seed_zeroizing(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// X25519 scalar of this identity key: SHA-512(seed)[0..32] (X25519 clamps it); its public
    /// key is the Montgomery form of public_key_bytes(). ONLY for the R2 pairwise root
    /// (RAVEN_LAN_BEACON_V1 §2): never a message, session, route, mailbox or ACK key.
    pub fn x25519_agreement_scalar(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_scalar_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// Compressed Edwards identity point (y = 1): order 1, i.e. a weak key.
    const IDENTITY_POINT: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    #[test]
    fn weak_key_universal_forgery_rejected() {
        // (R = identity, s = 0) satisfies the cofactorless equation for any
        // message under the identity public key.
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&IDENTITY_POINT);
        for msg in [&b"rvn1/devcert anything"[..], b"PairInit transcript"] {
            let vk = VerifyingKey::from_bytes(&IDENTITY_POINT).unwrap();
            assert!(
                vk.verify(msg, &Signature::from_bytes(&forged)).is_ok(),
                "non-strict verify accepts the forgery"
            );
            assert!(!Identity::verify(&IDENTITY_POINT, msg, &forged));
        }
    }

    #[test]
    fn seed_zeroizing_matches_seed_bytes_and_roundtrips() {
        let id = Identity::from_seed(&[9u8; 32]);
        let wrapped = id.seed_zeroizing();
        assert_eq!(*wrapped, id.seed_bytes());
        assert_eq!(*wrapped, [9u8; 32]);
        let back = Identity::from_seed(&wrapped);
        assert_eq!(back.public_key_bytes(), id.public_key_bytes());
    }

    /// The beacon's pairwise root (RAVEN_LAN_BEACON_V1 §2) relies on this:
    /// X25519 of the scalar with the base point is the Montgomery form of the
    /// Ed25519 public key, so both sides of a pair compute the same secret
    /// from the other's pinned identity key alone.
    #[test]
    fn x25519_agreement_scalar_matches_montgomery_public() {
        use sha2::{Digest, Sha512};
        // RFC 8032 section 7.1, tests 1-3 (the alice, bob and carol seeds).
        for seed in [
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        ] {
            let seed: [u8; 32] = hex::decode(seed).unwrap().try_into().unwrap();
            let id = Identity::from_seed(&seed);
            let scalar = id.x25519_agreement_scalar();
            assert_eq!(scalar[..], Sha512::digest(seed)[..32]);
            let public = VerifyingKey::from_bytes(&id.public_key_bytes()).unwrap();
            assert_eq!(
                x25519_dalek::x25519(*scalar, x25519_dalek::X25519_BASEPOINT_BYTES),
                public.to_montgomery().to_bytes()
            );
        }
    }

    #[test]
    fn honest_signatures_still_verify_strictly() {
        let id = Identity::from_seed(&[7u8; 32]);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&IDENTITY_POINT);
        assert!(!Identity::verify(&id.public_key_bytes(), b"m", &sig));
        let good = id.sign(b"m");
        assert!(Identity::verify(&id.public_key_bytes(), b"m", &good));
        assert!(!Identity::verify(&id.public_key_bytes(), b"n", &good));
    }
}
