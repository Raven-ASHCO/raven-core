//! AgentSign (`docs/design/2026-10-rdap-app-channel.md` §4.2): RDAP, bound to
//! this node, signs its A2A delegation statements with the node's identity
//! through one typed context. The node builds RDAP's exact canonical bytes
//! from the statement fields and never sees the task text (only its digest).
//!
//! Structural domain separation: every AgentSign signing input starts with
//! [`AGENT_DELEGATION_PREFIX`]. Only [`build`] can make an
//! [`AgentDelegationBytes`], only [`sign`] signs one, [`Identity::sign`]
//! asserts it is never handed such bytes, and [`Identity::verify`] refuses
//! them, so no Raven verifier can ever accept an AgentSign signature and no
//! AgentSign request can produce a Raven-format signature.

use serde::{Deserialize, Serialize};

use crate::identity::Identity;

/// The one context AgentSign signs (RDAP `raven_identity.SIGNING_CONTEXT`).
pub const AGENT_DELEGATION_CONTEXT: &str = "raven.a2a.delegation.v2";
const _: () = assert!(AGENT_DELEGATION_CONTEXT.len() == 0x17);

const fn delegation_prefix() -> [u8; 25] {
    let ctx = AGENT_DELEGATION_CONTEXT.as_bytes();
    let mut out = [0u8; 25];
    out[1] = ctx.len() as u8;
    let mut i = 0;
    while i < ctx.len() {
        out[2 + i] = ctx[i];
        i += 1;
    }
    out
}

/// `lp(context)`: a 2-byte big-endian length, then the context. Every
/// AgentSign signing input starts with these bytes.
pub const AGENT_DELEGATION_PREFIX: [u8; 25] = delegation_prefix();

/// Longest delegation lifetime (RDAP `MAX_DELEGATION_TTL_SECONDS`).
pub const MAX_LIFETIME_SECS: u64 = 86_400;
/// Allowed clock skew of `issued_at` against the node's clock.
pub const MAX_SKEW_SECS: u64 = 60;

/// One delegation statement (§4.2). `payload_sha256_hex` is the digest of the
/// task or answer text; the text itself never reaches the node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentDelegationStatement {
    pub context: String,
    pub sender: String,
    pub recipient: String,
    pub task_id: String,
    pub kind: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub payload_sha256_hex: String,
    pub nonce_hex: String,
}

/// Canonical delegation signing bytes; only [`build`] makes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDelegationBytes(Vec<u8>);

impl AgentDelegationBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Why a statement is refused (stable codes, §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSignError {
    Fields,
    Sender,
    RecipientNotContact,
    Time,
}

impl AgentSignError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Fields => "AGENT_SIGN_FIELDS",
            Self::Sender => "AGENT_SIGN_SENDER",
            Self::RecipientNotContact => "AGENT_SIGN_RECIPIENT_NOT_CONTACT",
            Self::Time => "AGENT_SIGN_TIME",
        }
    }
}

fn hex_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

fn task_id_ok(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn lp(out: &mut Vec<u8>, field: &[u8]) -> Result<(), AgentSignError> {
    let len = u16::try_from(field.len()).map_err(|_| AgentSignError::Fields)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// The field checks that need no clock and no contact book, then the bytes
/// (RDAP `delegation_signing_bytes`, byte for byte):
/// `lp(ctx) ‖ lp(sender) ‖ lp(recipient) ‖ lp(task_id) ‖ lp(kind) ‖
/// lp(dec(issued_at)) ‖ lp(dec(expires_at)) ‖ lp(digest32) ‖ lp(nonce16)`.
pub fn build(s: &AgentDelegationStatement) -> Result<AgentDelegationBytes, AgentSignError> {
    if s.context != AGENT_DELEGATION_CONTEXT
        || !task_id_ok(&s.task_id)
        || !matches!(s.kind.as_str(), "task" | "answer")
        || !crate::address::is_canonical_address(&s.sender)
        || !crate::address::is_canonical_address(&s.recipient)
    {
        return Err(AgentSignError::Fields);
    }
    let digest = hex_exact::<32>(&s.payload_sha256_hex).ok_or(AgentSignError::Fields)?;
    let nonce = hex_exact::<16>(&s.nonce_hex).ok_or(AgentSignError::Fields)?;
    let mut out = Vec::with_capacity(256);
    lp(&mut out, AGENT_DELEGATION_CONTEXT.as_bytes())?;
    lp(&mut out, s.sender.as_bytes())?;
    lp(&mut out, s.recipient.as_bytes())?;
    lp(&mut out, s.task_id.as_bytes())?;
    lp(&mut out, s.kind.as_bytes())?;
    lp(&mut out, s.issued_at.to_string().as_bytes())?;
    lp(&mut out, s.expires_at.to_string().as_bytes())?;
    lp(&mut out, &digest)?;
    lp(&mut out, &nonce)?;
    debug_assert!(out.starts_with(&AGENT_DELEGATION_PREFIX));
    Ok(AgentDelegationBytes(out))
}

/// The full validation (§4.2, cheapest first): fields, the sender is this
/// node, the recipient is a current unblocked contact (`is_contact`), the
/// time window. Then the bytes.
pub fn validate(
    s: &AgentDelegationStatement,
    own_address: &str,
    is_contact: &dyn Fn(&str) -> bool,
    now_secs: u64,
) -> Result<AgentDelegationBytes, AgentSignError> {
    let bytes = build(s)?;
    if s.sender != own_address {
        return Err(AgentSignError::Sender);
    }
    if !is_contact(&s.recipient) {
        return Err(AgentSignError::RecipientNotContact);
    }
    if s.issued_at.abs_diff(now_secs) > MAX_SKEW_SECS
        || s.expires_at <= s.issued_at
        || s.expires_at - s.issued_at > MAX_LIFETIME_SECS
    {
        return Err(AgentSignError::Time);
    }
    Ok(bytes)
}

/// Sign validated delegation bytes with the node identity: the only path
/// that signs prefixed bytes.
pub fn sign(identity: &Identity, bytes: &AgentDelegationBytes) -> [u8; 64] {
    identity.sign_agent_delegation(bytes)
}

/// Verify an AgentSign signature (RDAP verifies with its own builder; this is
/// for tests and diagnostics).
pub fn verify(public_key: &[u8; 32], bytes: &AgentDelegationBytes, sig: &[u8; 64]) -> bool {
    Identity::verify_agent_delegation(public_key, bytes, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(id: &Identity, recipient: &Identity) -> AgentDelegationStatement {
        AgentDelegationStatement {
            context: AGENT_DELEGATION_CONTEXT.into(),
            sender: id.address(),
            recipient: recipient.address(),
            task_id: "3f2a9c0d1e2b4f5a6b7c8d9e0f1a2b3c".into(),
            kind: "task".into(),
            issued_at: 1_760_500_000,
            expires_at: 1_760_514_400,
            payload_sha256_hex: "ab".repeat(32),
            nonce_hex: "cd".repeat(16),
        }
    }

    #[test]
    fn the_prefix_is_lp_of_the_context() {
        assert_eq!(&AGENT_DELEGATION_PREFIX[..2], &[0x00, 0x17]);
        assert_eq!(
            &AGENT_DELEGATION_PREFIX[2..],
            AGENT_DELEGATION_CONTEXT.as_bytes()
        );
    }

    #[test]
    fn a_signature_verifies_only_as_a_delegation() {
        let (alice, bob) = (Identity::from_seed(&[1; 32]), Identity::from_seed(&[2; 32]));
        let s = statement(&alice, &bob);
        let bytes = validate(&s, &alice.address(), &|r| r == bob.address(), s.issued_at).unwrap();
        let sig = sign(&alice, &bytes);
        assert!(verify(&alice.public_key_bytes(), &bytes, &sig));
        // A Raven verifier never accepts it, whatever the format.
        assert!(!Identity::verify(
            &alice.public_key_bytes(),
            bytes.as_bytes(),
            &sig
        ));
    }

    #[test]
    fn every_rule_refuses_with_its_code() {
        let (alice, bob) = (Identity::from_seed(&[1; 32]), Identity::from_seed(&[2; 32]));
        let base = statement(&alice, &bob);
        let contact = |r: &str| r == bob.address();
        let now = base.issued_at;
        let check = |s: AgentDelegationStatement| {
            validate(&s, &alice.address(), &contact, now)
                .map(|_| ())
                .unwrap_err()
        };
        let mut s = base.clone();
        s.context = "raven.a2a.delegation.v3".into();
        assert_eq!(check(s), AgentSignError::Fields);
        let mut s = base.clone();
        s.kind = "card".into();
        assert_eq!(check(s), AgentSignError::Fields);
        let mut s = base.clone();
        s.task_id = "bad id".into();
        assert_eq!(check(s), AgentSignError::Fields);
        let mut s = base.clone();
        s.payload_sha256_hex = "AB".repeat(32);
        assert_eq!(check(s), AgentSignError::Fields);
        let mut s = base.clone();
        s.nonce_hex = "cd".repeat(15);
        assert_eq!(check(s), AgentSignError::Fields);
        // Only the exact canonical spelling of an address is signed.
        for spelled in [
            format!(" {}", bob.address()),
            format!("{}\n", bob.address()),
            bob.address().to_uppercase(),
        ] {
            let mut s = base.clone();
            s.recipient = spelled;
            assert_eq!(check(s), AgentSignError::Fields);
        }
        let mut s = base.clone();
        s.sender = format!("{} ", alice.address());
        assert_eq!(check(s), AgentSignError::Fields);
        let mut s = base.clone();
        s.sender = bob.address();
        assert_eq!(check(s), AgentSignError::Sender);
        let mut s = base.clone();
        s.recipient = Identity::from_seed(&[3; 32]).address();
        assert_eq!(check(s), AgentSignError::RecipientNotContact);
        let mut s = base.clone();
        s.issued_at = now + 61;
        s.expires_at = s.issued_at + 100;
        assert_eq!(check(s), AgentSignError::Time);
        let mut s = base.clone();
        s.expires_at = s.issued_at + MAX_LIFETIME_SECS + 1;
        assert_eq!(check(s), AgentSignError::Time);
        let mut s = base;
        s.expires_at = s.issued_at;
        assert_eq!(check(s), AgentSignError::Time);
    }

    /// The bytes RDAP's `delegation_signing_bytes` produces for the same
    /// fields (shared vector, generated by RDAP).
    #[test]
    fn the_bytes_equal_rdaps_shared_vector() {
        let raw = include_str!("../../../../shared-vectors/rdap/agent_sign/delegation_v2_001.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let s: AgentDelegationStatement = serde_json::from_value(v["statement"].clone()).unwrap();
        let bytes = build(&s).unwrap();
        assert_eq!(
            hex::encode(bytes.as_bytes()),
            v["signing_bytes_hex"].as_str().unwrap()
        );
    }

    /// No Raven signing input in the shared vectors starts with the prefix,
    /// so no Raven signature can ever be replayed as a delegation.
    #[test]
    fn no_raven_signing_vector_starts_with_the_prefix() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../shared-vectors/rvn1");
        let prefix_hex = hex::encode(AGENT_DELEGATION_PREFIX);
        let mut seen = 0;
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "json") {
                    let text = std::fs::read_to_string(&path).unwrap().to_ascii_lowercase();
                    for (key, _) in text.match_indices("signing") {
                        let rest = &text[key..];
                        if let Some(q) = rest.find(":") {
                            let value = rest[q + 1..].trim_start().trim_start_matches('"');
                            assert!(
                                !value.starts_with(&prefix_hex),
                                "{} carries a delegation-prefixed signing input",
                                path.display()
                            );
                        }
                    }
                    seen += 1;
                }
            }
        }
        assert!(seen > 10, "shared vectors found: {seen}");
    }
}
