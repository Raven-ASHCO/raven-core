//! RAVEN Async Letter V1 (RAL1): the codec half
//! (`protocol/RAVEN_ASYNC_LETTER_V1.md`).
//!
//! A letter lets a friend (custodian) hold a sealed PairInit plus the first
//! messages of that session for up to 7 days, so a contact who is offline for
//! longer than a 24 h session can still receive them. Kind 1 (LETTER, from the
//! initiator) carries a PairInit V1 and 1 to 16 sealed RVNA1 `0x03` messages;
//! kind 2 (REPLY, from the responder) carries the PairResponse and up to 32
//! sealed ACKs. The inner bytes are wrapped to the recipient's signed X25519
//! prekey (ChaCha20-Poly1305 under an HKDF key schedule whose nonce is derived
//! from the plaintext) and the whole letter is signed by the sender device
//! under `rvn1/async-letter/v1\0`.
//!
//! This module is pure: the wire codec, the key schedule, seal and open, the
//! inner codecs with padding to multiples of 512 bytes, the stateless
//! bindings and the stable refusal codes. Intake (the contact book, the prekey
//! actor, accepting the PairInit and the envelopes) owns state and lives in
//! [`intake`] (P5.14); it runs [`open`] with its two lookups, which keeps the
//! spec's verification order (the signature is checked before any secret is
//! used).
//!
//! Production disabled: nothing sends or accepts a letter unless
//! [`crate::horizon::letter_live_enabled`]. `pair_kind` 3 is reserved for
//! PairInit V3 and refused like any other unknown value.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::atsam_indexed_session::{
    derive_route_tag, parse_indexed_message_header, Direction, ACK_SEALED_WIRE_LEN,
    INDEXED_SEALED_MIN_WIRE_LEN, RVNA1_PROTO, RVNA1_SUITE,
};
use crate::atsam_root::{x25519_public_is_contributory, x25519_shared_checked};
use crate::envelope::{EnvType, Envelope, PREFIX_LEN as ENVELOPE_PREFIX_LEN};
use crate::identity::Identity;
use crate::pair_init::{
    decode_init, decode_response, PairInit, PairResponse, INIT_WIRE_LEN, RESPONSE_WIRE_LEN,
};
use crate::prekey_lifecycle::{
    PrekeyLifecycleActor, PrekeyLifecycleError, MAX_PREKEY_FUTURE_SKEW_MS,
};
use crate::seal::SEAL_MAGIC_RVNA1;

pub const MAGIC: [u8; 4] = *b"RAL1";
pub const VERSION: u8 = 1;
/// The only `flags` value of version 1.
pub const FLAGS: u16 = 0;
/// `header[0..168]`: everything before `wrap_nonce`. It is the HKDF info
/// suffix, so the wrap keys are bound to every header field the nonce and
/// `ct_len` do not depend on.
pub const HEADER_PREFIX_LEN: usize = 168;
pub const HEADER_LEN: usize = 184;
pub const TAG_LEN: usize = 16;
pub const SIGNATURE_LEN: usize = 64;
/// The inner length is a multiple of this.
pub const PAD_BLOCK: usize = 512;
pub const MIN_RAL1_INNER: usize = PAD_BLOCK;
pub const MAX_RAL1_INNER: usize = 65_024;
/// A REPLY with no ACKs.
pub const MIN_RAL1_LEN: usize = HEADER_LEN + MIN_RAL1_INNER + TAG_LEN + SIGNATURE_LEN;
/// Fits one RFC1 frame.
pub const MAX_RAL1_LEN: usize = HEADER_LEN + MAX_RAL1_INNER + TAG_LEN + SIGNATURE_LEN;
const _: () = assert!(
    MIN_RAL1_LEN == 776 && MAX_RAL1_LEN == 65_288 && MAX_RAL1_INNER.is_multiple_of(PAD_BLOCK)
);

pub const SIGNING_DOMAIN: &[u8] = b"rvn1/async-letter/v1\0";
pub const SALT_LABEL: &[u8] = b"rvn1/async-letter/v1/salt";
pub const WRAP_LABEL: &[u8] = b"rvn1/async-letter/v1/wrap";
pub const NONCE_LABEL: &[u8] = b"rvn1/async-letter/v1/nonce";
/// `page_token = SHA-256(PAGE_TOKEN_DOMAIN || letter)`: the custodian's fetch
/// order (RFC1 letter ops).
pub const PAGE_TOKEN_DOMAIN: &[u8] = b"raven/custody-letter/page-token/v1";

pub const INNER_VERSION: u8 = 1;
pub const PAIR_KIND_INIT_V1: u8 = 1;
pub const PAIR_KIND_RESPONSE_V1: u8 = 2;
/// Reserved for PairInit V3; refused by this version.
pub const PAIR_KIND_INIT_V3_RESERVED: u8 = 3;
pub const MAX_LETTER_ENVELOPES: usize = 16;
pub const MAX_REPLY_ACKS: usize = 32;
/// A carried envelope is at least an RVN1 prefix long.
pub const MIN_ITEM_LEN: usize = ENVELOPE_PREFIX_LEN;
pub const MAX_ITEM_LEN: usize = MAX_RAL1_INNER;

/// `expires_at - created_at` of a letter, and the longest letter session.
pub const MAX_LETTER_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// `created_at` may be this far ahead of the recipient's clock.
pub const MAX_LETTER_FUTURE_SKEW_MS: u64 = MAX_PREKEY_FUTURE_SKEW_MS;
const _: () = assert!(MAX_LETTER_LIFETIME_MS == crate::horizon::LETTER_SESSION_LIFETIME_MS);

type HmacSha256 = Hmac<Sha256>;

/// Why a letter was refused. [`Self::code`] is the stable identifier
/// (RAVEN_ASYNC_LETTER_V1.md §6); the refusals carry no other data.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Ral1Error {
    /// Step 1: not a strict RAL1 letter.
    #[error("LETTER_MALFORMED")]
    Malformed,
    /// Step 2: addressed to another device.
    #[error("LETTER_WRONG_RECIPIENT")]
    WrongRecipient,
    /// Step 3: `now >= expires_at`.
    #[error("LETTER_EXPIRED")]
    Expired,
    /// Step 3: dated in the future, or valid for longer than 7 days.
    #[error("LETTER_TIME")]
    Time,
    /// Step 4: the sender device is not a pinned, unblocked contact.
    #[error("LETTER_NOT_CONTACT")]
    NotContact,
    /// Step 5: the Ed25519 signature does not verify.
    #[error("LETTER_BAD_SIGNATURE")]
    BadSignature,
    /// Step 6: `wrap_bundle_hash` names no retained local generation.
    #[error("LETTER_UNKNOWN_PREKEY")]
    UnknownPrekey,
    /// Step 7: the AEAD does not open.
    #[error("LETTER_UNWRAP")]
    Unwrap,
    /// Step 8: the inner bytes are not a strict LETTER / REPLY of this kind.
    #[error("LETTER_INNER")]
    Inner,
    /// Step 9: the inner PairInit, PairResponse or envelopes do not match the
    /// letter header.
    #[error("LETTER_BINDING")]
    Binding,
    /// Step 10: the PairInit was refused.
    #[error("LETTER_PAIR_REFUSED")]
    PairRefused,
    /// Step 10: the initiator holds the most letter claims allowed.
    #[error("LETTER_CLAIM_LIMIT")]
    ClaimLimit,
    /// Steps 10-11: a local store error.
    #[error("LETTER_STORE")]
    Store,
    /// The letter gate is closed on this node.
    #[error("LETTER_GATE")]
    Gate,
    /// Sender side: the inner is larger than [`MAX_RAL1_INNER`].
    #[error("LETTER_TOO_LARGE")]
    TooLarge,
    /// Sender side: the letter could not be sealed (header fields, the
    /// recipient prekey, or a lifetime over 7 days).
    #[error("LETTER_SEAL")]
    Seal,
}

impl Ral1Error {
    pub const ALL: [Self; 16] = [
        Self::Malformed,
        Self::WrongRecipient,
        Self::Expired,
        Self::Time,
        Self::NotContact,
        Self::BadSignature,
        Self::UnknownPrekey,
        Self::Unwrap,
        Self::Inner,
        Self::Binding,
        Self::PairRefused,
        Self::ClaimLimit,
        Self::Store,
        Self::Gate,
        Self::TooLarge,
        Self::Seal,
    ];

    /// The stable code.
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "LETTER_MALFORMED",
            Self::WrongRecipient => "LETTER_WRONG_RECIPIENT",
            Self::Expired => "LETTER_EXPIRED",
            Self::Time => "LETTER_TIME",
            Self::NotContact => "LETTER_NOT_CONTACT",
            Self::BadSignature => "LETTER_BAD_SIGNATURE",
            Self::UnknownPrekey => "LETTER_UNKNOWN_PREKEY",
            Self::Unwrap => "LETTER_UNWRAP",
            Self::Inner => "LETTER_INNER",
            Self::Binding => "LETTER_BINDING",
            Self::PairRefused => "LETTER_PAIR_REFUSED",
            Self::ClaimLimit => "LETTER_CLAIM_LIMIT",
            Self::Store => "LETTER_STORE",
            Self::Gate => "LETTER_GATE",
            Self::TooLarge => "LETTER_TOO_LARGE",
            Self::Seal => "LETTER_SEAL",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|error| error.code() == code)
    }

    /// Whether a recipient that refuses a fetched letter with this code
    /// releases it at the custodian. A letter that fails a check of its own
    /// bytes never gets better; a claim or store error may, so the letter
    /// stays held. Sender-side codes never reach a custodian.
    pub fn releases_letter(self) -> bool {
        !matches!(
            self,
            Self::ClaimLimit | Self::Store | Self::TooLarge | Self::Seal
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ral1Kind {
    /// Initiator to responder: PairInit V1 plus sealed messages.
    Letter = 1,
    /// Responder to initiator: PairResponse V1 plus sealed ACKs.
    Reply = 2,
}

impl Ral1Kind {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Letter),
            2 => Some(Self::Reply),
            _ => None,
        }
    }

    /// The only `pair_kind` the inner of this kind may carry.
    pub fn pair_kind(self) -> u8 {
        match self {
            Self::Letter => PAIR_KIND_INIT_V1,
            Self::Reply => PAIR_KIND_RESPONSE_V1,
        }
    }

    fn pair_len(self) -> usize {
        match self {
            Self::Letter => INIT_WIRE_LEN,
            Self::Reply => RESPONSE_WIRE_LEN,
        }
    }

    fn item_range(self) -> std::ops::RangeInclusive<usize> {
        match self {
            Self::Letter => 1..=MAX_LETTER_ENVELOPES,
            Self::Reply => 0..=MAX_REPLY_ACKS,
        }
    }

    /// The session direction the carried envelopes travel in.
    pub fn direction(self) -> Direction {
        match self {
            Self::Letter => Direction::InitiatorToResponder,
            Self::Reply => Direction::ResponderToInitiator,
        }
    }
}

/// The 184-byte header. Integers are big-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ral1Header {
    pub kind: Ral1Kind,
    /// Random, non-zero.
    pub letter_id: [u8; 16],
    /// Ed25519 device key that signs the letter.
    pub sender_device: [u8; 32],
    pub recipient_device: [u8; 32],
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    /// `prekey_bundle_hash` (domain `rvn1/pair-prekey`) of the recipient
    /// bundle whose signed prekey the letter is wrapped to.
    pub wrap_bundle_hash: [u8; 32],
    pub wrap_ephemeral: [u8; 32],
    pub wrap_nonce: [u8; 12],
    /// `inner_len + 16`.
    pub ct_len: u32,
}

impl Ral1Header {
    /// `header[0..168]`.
    pub fn prefix_bytes(&self) -> [u8; HEADER_PREFIX_LEN] {
        let mut out = [0u8; HEADER_PREFIX_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = self.kind as u8;
        out[6..8].copy_from_slice(&FLAGS.to_be_bytes());
        out[8..24].copy_from_slice(&self.letter_id);
        out[24..56].copy_from_slice(&self.sender_device);
        out[56..88].copy_from_slice(&self.recipient_device);
        out[88..96].copy_from_slice(&self.created_at_ms.to_be_bytes());
        out[96..104].copy_from_slice(&self.expires_at_ms.to_be_bytes());
        out[104..136].copy_from_slice(&self.wrap_bundle_hash);
        out[136..168].copy_from_slice(&self.wrap_ephemeral);
        out
    }

    /// `header[0..184]`: the AEAD associated data.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..HEADER_PREFIX_LEN].copy_from_slice(&self.prefix_bytes());
        out[168..180].copy_from_slice(&self.wrap_nonce);
        out[180..184].copy_from_slice(&self.ct_len.to_be_bytes());
        out
    }

    fn inner_len(&self) -> usize {
        (self.ct_len as usize).saturating_sub(TAG_LEN)
    }

    /// The field rules of step 1 that do not depend on the total length.
    fn check_fields(&self) -> Result<(), Ral1Error> {
        let zero = |value: &[u8]| value.iter().all(|byte| *byte == 0);
        let inner_len = self.inner_len();
        if zero(&self.letter_id)
            || zero(&self.sender_device)
            || zero(&self.recipient_device)
            || self.sender_device == self.recipient_device
            || zero(&self.wrap_bundle_hash)
            || self.expires_at_ms <= self.created_at_ms
            // All-zero and every other small-order point: the wrap DH would
            // be all-zero for every recipient key.
            || !x25519_public_is_contributory(&self.wrap_ephemeral)
            || (self.ct_len as usize) < TAG_LEN
            || !(MIN_RAL1_INNER..=MAX_RAL1_INNER).contains(&inner_len)
            || !inner_len.is_multiple_of(PAD_BLOCK)
        {
            return Err(Ral1Error::Malformed);
        }
        Ok(())
    }
}

/// A strictly decoded letter. Decoding checks the shape only: no signature,
/// no time, no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ral1Letter {
    pub header: Ral1Header,
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
}

impl Ral1Letter {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len() + SIGNATURE_LEN);
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.signature);
        out
    }
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("fixed header slice")
}

/// Step 1 for the header alone: magic, version, kind, flags, the field rules
/// and `ct_len` against the exact total length. Never reads the ciphertext;
/// a custodian's admission uses this.
pub fn decode_header(bytes: &[u8]) -> Result<Ral1Header, Ral1Error> {
    if !(MIN_RAL1_LEN..=MAX_RAL1_LEN).contains(&bytes.len())
        || bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || u16::from_be_bytes([bytes[6], bytes[7]]) != FLAGS
    {
        return Err(Ral1Error::Malformed);
    }
    let kind = Ral1Kind::from_u8(bytes[5]).ok_or(Ral1Error::Malformed)?;
    let header = Ral1Header {
        kind,
        letter_id: array(&bytes[8..24]),
        sender_device: array(&bytes[24..56]),
        recipient_device: array(&bytes[56..88]),
        created_at_ms: u64::from_be_bytes(array(&bytes[88..96])),
        expires_at_ms: u64::from_be_bytes(array(&bytes[96..104])),
        wrap_bundle_hash: array(&bytes[104..136]),
        wrap_ephemeral: array(&bytes[136..168]),
        wrap_nonce: array(&bytes[168..180]),
        ct_len: u32::from_be_bytes(array(&bytes[180..184])),
    };
    header.check_fields()?;
    if bytes.len() != HEADER_LEN + header.ct_len as usize + SIGNATURE_LEN {
        return Err(Ral1Error::Malformed);
    }
    Ok(header)
}

/// Step 1: strict decode, no trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<Ral1Letter, Ral1Error> {
    let header = decode_header(bytes)?;
    let split = bytes.len() - SIGNATURE_LEN;
    Ok(Ral1Letter {
        header,
        ciphertext: bytes[HEADER_LEN..split].to_vec(),
        signature: array(&bytes[split..]),
    })
}

/// `SHA-256(letter)`: custody dedup, RELEASE and WITHDRAW name a letter by it.
pub fn letter_digest(letter: &[u8]) -> [u8; 32] {
    Sha256::digest(letter).into()
}

/// `SHA-256("raven/custody-letter/page-token/v1" || letter)`.
pub fn page_token(letter: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PAGE_TOKEN_DOMAIN);
    hasher.update(letter);
    hasher.finalize().into()
}

/// `SIGNING_DOMAIN || bytes[0 .. 184 + ct_len]`.
pub fn signing_bytes(unsigned: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNING_DOMAIN.len() + unsigned.len());
    out.extend_from_slice(SIGNING_DOMAIN);
    out.extend_from_slice(unsigned);
    out
}

/// Step 5: strict Ed25519 under `sender_device`. `bytes` is the whole letter
/// and `header` its decoded header.
pub fn verify_signature(bytes: &[u8], header: &Ral1Header) -> Result<(), Ral1Error> {
    let split = bytes
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(Ral1Error::Malformed)?;
    let signature: [u8; 64] = array(&bytes[split..]);
    if !Identity::verify(
        &header.sender_device,
        &signing_bytes(&bytes[..split]),
        &signature,
    ) {
        return Err(Ral1Error::BadSignature);
    }
    Ok(())
}

/// Steps 2 and 3.
pub fn check_recipient_and_time(
    header: &Ral1Header,
    local_device: &[u8; 32],
    now_ms: u64,
) -> Result<(), Ral1Error> {
    if header.recipient_device != *local_device {
        return Err(Ral1Error::WrongRecipient);
    }
    if now_ms >= header.expires_at_ms {
        return Err(Ral1Error::Expired);
    }
    if header.created_at_ms > now_ms.saturating_add(MAX_LETTER_FUTURE_SKEW_MS)
        || header.expires_at_ms.saturating_sub(header.created_at_ms) > MAX_LETTER_LIFETIME_MS
    {
        return Err(Ral1Error::Time);
    }
    Ok(())
}

/// The two wrap keys of one letter.
pub struct WrapKeys {
    pub k_wrap: Zeroizing<[u8; 32]>,
    pub k_nonce: Zeroizing<[u8; 32]>,
}

/// `SHA-256("rvn1/async-letter/v1/salt" || wrap_bundle_hash)`.
pub fn wrap_salt(wrap_bundle_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SALT_LABEL);
    hasher.update(wrap_bundle_hash);
    hasher.finalize().into()
}

/// `"rvn1/async-letter/v1/wrap" || 0x00 || header[0..168]`.
pub fn wrap_info(header_prefix: &[u8; HEADER_PREFIX_LEN]) -> Vec<u8> {
    let mut info = Vec::with_capacity(WRAP_LABEL.len() + 1 + HEADER_PREFIX_LEN);
    info.extend_from_slice(WRAP_LABEL);
    info.push(0);
    info.extend_from_slice(header_prefix);
    info
}

/// `okm = HKDF-SHA256(IKM = dh, salt, info, L = 64)`; `K_wrap = okm[0..32]`,
/// `K_nonce = okm[32..64]`. The salt's bundle hash is read from the prefix.
pub fn wrap_keys(dh: &[u8; 32], header_prefix: &[u8; HEADER_PREFIX_LEN]) -> WrapKeys {
    let salt = wrap_salt(&array(&header_prefix[104..136]));
    let hk = Hkdf::<Sha256>::new(Some(&salt), dh);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(&wrap_info(header_prefix), &mut *okm)
        .expect("64-byte HKDF output");
    WrapKeys {
        k_wrap: Zeroizing::new(array(&okm[..32])),
        k_nonce: Zeroizing::new(array(&okm[32..])),
    }
}

/// `HMAC-SHA256(K_nonce, "rvn1/async-letter/v1/nonce" || 0x00 || inner)[0..12]`:
/// derived from the plaintext, so a replayed RNG (the same ephemeral and
/// header) never reuses a nonce with a different inner.
pub fn wrap_nonce(k_nonce: &[u8; 32], inner: &[u8]) -> [u8; 12] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k_nonce).expect("HMAC accepts 32-byte keys");
    mac.update(NONCE_LABEL);
    mac.update(&[0]);
    mac.update(inner);
    array(&mac.finalize().into_bytes()[..12])
}

/// What the sender seals; `sender_device` is the signing identity's key.
pub struct SealInput<'a> {
    pub kind: Ral1Kind,
    pub letter_id: [u8; 16],
    pub recipient_device: [u8; 32],
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub wrap_bundle_hash: [u8; 32],
    /// `x25519_pub` of the bundle named by `wrap_bundle_hash`.
    pub recipient_signed_prekey: [u8; 32],
    /// An encoded inner ([`encode_letter_inner`] / [`encode_reply_inner`]).
    pub inner: &'a [u8],
}

/// Seals and signs one letter with a fresh ephemeral secret `e_w`. Refuses a
/// lifetime over 7 days, an inner that is not a padded inner, and a recipient
/// prekey whose DH would be all-zero.
pub fn seal(
    sender: &Identity,
    ephemeral_secret: &[u8; 32],
    input: &SealInput<'_>,
) -> Result<Vec<u8>, Ral1Error> {
    if input.expires_at_ms.saturating_sub(input.created_at_ms) > MAX_LETTER_LIFETIME_MS {
        return Err(Ral1Error::Seal);
    }
    seal_unchecked_lifetime(sender, ephemeral_secret, input)
}

fn seal_unchecked_lifetime(
    sender: &Identity,
    ephemeral_secret: &[u8; 32],
    input: &SealInput<'_>,
) -> Result<Vec<u8>, Ral1Error> {
    let inner = input.inner;
    if inner.len() > MAX_RAL1_INNER {
        return Err(Ral1Error::TooLarge);
    }
    if inner.len() < MIN_RAL1_INNER || !inner.len().is_multiple_of(PAD_BLOCK) {
        return Err(Ral1Error::Inner);
    }
    let secret = StaticSecret::from(*ephemeral_secret);
    let mut header = Ral1Header {
        kind: input.kind,
        letter_id: input.letter_id,
        sender_device: sender.public_key_bytes(),
        recipient_device: input.recipient_device,
        created_at_ms: input.created_at_ms,
        expires_at_ms: input.expires_at_ms,
        wrap_bundle_hash: input.wrap_bundle_hash,
        wrap_ephemeral: PublicKey::from(&secret).to_bytes(),
        wrap_nonce: [0; 12],
        ct_len: (inner.len() + TAG_LEN) as u32,
    };
    header.check_fields().map_err(|_| Ral1Error::Seal)?;
    let dh = Zeroizing::new(
        x25519_shared_checked(ephemeral_secret, &input.recipient_signed_prekey)
            .map_err(|_| Ral1Error::Seal)?,
    );
    let keys = wrap_keys(&dh, &header.prefix_bytes());
    header.wrap_nonce = wrap_nonce(&keys.k_nonce, inner);
    let aad = header.to_bytes();
    let ciphertext = ChaCha20Poly1305::new((&*keys.k_wrap).into())
        .encrypt(
            Nonce::from_slice(&header.wrap_nonce),
            Payload {
                msg: inner,
                aad: &aad,
            },
        )
        .map_err(|_| Ral1Error::Seal)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len() + SIGNATURE_LEN);
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ciphertext);
    let signature = sender.sign(&signing_bytes(&out));
    out.extend_from_slice(&signature);
    debug_assert_eq!(decode_header(&out).map(|_| ()), Ok(()));
    Ok(out)
}

/// Step 7: AEAD open with the wrap DH of step 6.
pub fn unwrap_inner(letter: &Ral1Letter, dh: &[u8; 32]) -> Result<Vec<u8>, Ral1Error> {
    let keys = wrap_keys(dh, &letter.header.prefix_bytes());
    ChaCha20Poly1305::new((&*keys.k_wrap).into())
        .decrypt(
            Nonce::from_slice(&letter.header.wrap_nonce),
            Payload {
                msg: &letter.ciphertext,
                aad: &letter.header.to_bytes(),
            },
        )
        .map_err(|_| Ral1Error::Unwrap)
}

/// Kind 1 inner: the exact signed PairInit V1 bytes and 1 to 16 packed RVN1
/// messages of its session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LetterInner {
    pub pair_init: Vec<u8>,
    pub envelopes: Vec<Vec<u8>>,
}

/// Kind 2 inner: the PairResponse V1 bytes and 0 to 32 packed RVN1 ACKs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyInner {
    pub pair_response: Vec<u8>,
    pub acks: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ral1Inner {
    Letter(LetterInner),
    Reply(ReplyInner),
}

/// The shape a carried envelope must have: a strict RVN1 envelope with
/// `flags = 0` and no ratchet header whose body is a sealed RVNA1 `0x03`
/// message (kind 1) or exactly one sealed indexed ACK (kind 2).
fn check_item(kind: Ral1Kind, packed: &[u8]) -> Result<Envelope, Ral1Error> {
    let envelope = Envelope::unpack(packed).ok_or(Ral1Error::Inner)?;
    let body = &envelope.message_ciphertext;
    let sealed = body.len() >= INDEXED_SEALED_MIN_WIRE_LEN
        && body[..8] == SEAL_MAGIC_RVNA1
        && body[8] == RVNA1_PROTO
        && body[9] == RVNA1_SUITE;
    let shape = match kind {
        Ral1Kind::Letter => envelope.env_type == EnvType::Message as u8,
        Ral1Kind::Reply => {
            envelope.env_type == EnvType::Ack as u8 && body.len() == ACK_SEALED_WIRE_LEN
        }
    };
    if !sealed || !shape || envelope.flags != 0 || !envelope.ratchet_header_ciphertext.is_empty() {
        return Err(Ral1Error::Inner);
    }
    Ok(envelope)
}

fn encode_inner(kind: Ral1Kind, pair: &[u8], items: &[Vec<u8>]) -> Result<Vec<u8>, Ral1Error> {
    if pair.len() != kind.pair_len() || !kind.item_range().contains(&items.len()) {
        return Err(Ral1Error::Inner);
    }
    let pair_ok = match kind {
        Ral1Kind::Letter => decode_init(pair).is_ok(),
        Ral1Kind::Reply => decode_response(pair).is_ok(),
    };
    if !pair_ok {
        return Err(Ral1Error::Inner);
    }
    let mut unpadded = 4 + pair.len() + 1 + 2;
    for item in items {
        if item.len() > MAX_ITEM_LEN {
            return Err(Ral1Error::TooLarge);
        }
        check_item(kind, item)?;
        unpadded += 4 + item.len();
        if unpadded > MAX_RAL1_INNER {
            return Err(Ral1Error::TooLarge);
        }
    }
    let pad = (PAD_BLOCK - unpadded % PAD_BLOCK) % PAD_BLOCK;
    if unpadded + pad > MAX_RAL1_INNER {
        return Err(Ral1Error::TooLarge);
    }
    let mut out = Vec::with_capacity(unpadded + pad);
    out.push(INNER_VERSION);
    out.push(kind.pair_kind());
    out.extend_from_slice(&(pair.len() as u16).to_be_bytes());
    out.extend_from_slice(pair);
    out.push(items.len() as u8);
    for item in items {
        out.extend_from_slice(&(item.len() as u32).to_be_bytes());
        out.extend_from_slice(item);
    }
    out.extend_from_slice(&(pad as u16).to_be_bytes());
    out.resize(unpadded + pad, 0);
    Ok(out)
}

/// Encodes a kind 1 inner with the smallest padding that makes its length a
/// multiple of 512.
pub fn encode_letter_inner(value: &LetterInner) -> Result<Vec<u8>, Ral1Error> {
    encode_inner(Ral1Kind::Letter, &value.pair_init, &value.envelopes)
}

/// Encodes a kind 2 inner with the smallest padding that makes its length a
/// multiple of 512.
pub fn encode_reply_inner(value: &ReplyInner) -> Result<Vec<u8>, Ral1Error> {
    encode_inner(Ral1Kind::Reply, &value.pair_response, &value.acks)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Ral1Error> {
        let end = self.at.checked_add(n).ok_or(Ral1Error::Inner)?;
        let out = self.bytes.get(self.at..end).ok_or(Ral1Error::Inner)?;
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Ral1Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Ral1Error> {
        Ok(u16::from_be_bytes(array(self.take(2)?)))
    }

    fn u32(&mut self) -> Result<u32, Ral1Error> {
        Ok(u32::from_be_bytes(array(self.take(4)?)))
    }
}

/// Step 8: strict inner decode for the header's kind: `pair_kind` matches the
/// kind, the pair bytes decode, counts and item lengths are in range, every
/// item has the carried-envelope shape, and the padding is the smallest one,
/// all zero, with nothing after it.
pub fn decode_inner(kind: Ral1Kind, bytes: &[u8]) -> Result<Ral1Inner, Ral1Error> {
    if !(MIN_RAL1_INNER..=MAX_RAL1_INNER).contains(&bytes.len())
        || !bytes.len().is_multiple_of(PAD_BLOCK)
    {
        return Err(Ral1Error::Inner);
    }
    let mut reader = Reader { bytes, at: 0 };
    if reader.u8()? != INNER_VERSION
        || reader.u8()? != kind.pair_kind()
        || reader.u16()? as usize != kind.pair_len()
    {
        return Err(Ral1Error::Inner);
    }
    let pair = reader.take(kind.pair_len())?.to_vec();
    let pair_ok = match kind {
        Ral1Kind::Letter => decode_init(&pair).is_ok(),
        Ral1Kind::Reply => decode_response(&pair).is_ok(),
    };
    let count = reader.u8()? as usize;
    if !pair_ok || !kind.item_range().contains(&count) {
        return Err(Ral1Error::Inner);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let len = reader.u32()? as usize;
        if !(MIN_ITEM_LEN..=MAX_ITEM_LEN).contains(&len) {
            return Err(Ral1Error::Inner);
        }
        let item = reader.take(len)?;
        check_item(kind, item)?;
        items.push(item.to_vec());
    }
    let pad_len = reader.u16()? as usize;
    if pad_len >= PAD_BLOCK
        || reader.take(pad_len)?.iter().any(|byte| *byte != 0)
        || reader.at != bytes.len()
    {
        return Err(Ral1Error::Inner);
    }
    Ok(match kind {
        Ral1Kind::Letter => Ral1Inner::Letter(LetterInner {
            pair_init: pair,
            envelopes: items,
        }),
        Ral1Kind::Reply => Ral1Inner::Reply(ReplyInner {
            pair_response: pair,
            acks: items,
        }),
    })
}

/// One carried envelope: the exact packed bytes and their decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarriedEnvelope {
    pub packed: Vec<u8>,
    pub envelope: Envelope,
}

/// An opened kind 1 letter that passed steps 1-9 (all but the route tags,
/// which need the session root: [`check_route_tags`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedLetter {
    pub header: Ral1Header,
    pub letter_digest: [u8; 32],
    pub pair_init: PairInit,
    pub pair_init_wire: Vec<u8>,
    pub envelopes: Vec<CarriedEnvelope>,
}

/// An opened kind 2 letter that passed steps 1-9 (all but the session
/// lookup by `init_id`, which needs state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedReply {
    pub header: Ral1Header,
    pub letter_digest: [u8; 32],
    pub pair_response: PairResponse,
    pub pair_response_wire: Vec<u8>,
    pub acks: Vec<CarriedEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    Letter(Box<OpenedLetter>),
    Reply(Box<OpenedReply>),
}

fn carried(
    header: &Ral1Header,
    items: Vec<Vec<u8>>,
    check_expiry: bool,
) -> Result<Vec<CarriedEnvelope>, Ral1Error> {
    items
        .into_iter()
        .map(|packed| {
            let envelope = Envelope::unpack(&packed).ok_or(Ral1Error::Inner)?;
            if !envelope.verify(&header.sender_device)
                || (check_expiry && envelope.expires_at > header.expires_at_ms)
            {
                return Err(Ral1Error::Binding);
            }
            Ok(CarriedEnvelope { packed, envelope })
        })
        .collect()
}

/// Step 9 for kind 1, the stateless part: PairInit initiator = sender,
/// responder = recipient, its bundle hash = `wrap_bundle_hash`, no one-time
/// prekey, its validity contains the letter's, the wrap ephemeral is not the
/// PairInit ephemeral, and every envelope is signed by the sender and expires
/// no later than the letter.
pub fn check_letter_bindings(
    header: &Ral1Header,
    inner: LetterInner,
) -> Result<(PairInit, Vec<u8>, Vec<CarriedEnvelope>), Ral1Error> {
    if header.kind != Ral1Kind::Letter {
        return Err(Ral1Error::Inner);
    }
    let init = decode_init(&inner.pair_init).map_err(|_| Ral1Error::Inner)?;
    if init.initiator_device_ed_pub != header.sender_device
        || init.responder_device_ed_pub != header.recipient_device
        || init.responder_prekey_bundle_hash != header.wrap_bundle_hash
        || init.one_time_prekey_id != 0
        || init.created_at_ms > header.created_at_ms
        || header.expires_at_ms > init.expires_at_ms
        || header.wrap_ephemeral == init.initiator_ephemeral_x25519_pub
    {
        return Err(Ral1Error::Binding);
    }
    let envelopes = carried(header, inner.envelopes, true)?;
    Ok((init, inner.pair_init, envelopes))
}

/// Step 9 for kind 2, the stateless part: the PairResponse is the sender's
/// and every ACK is signed by the sender. That `init_id` names a provisional
/// letter session of ours with this peer is the caller's check.
pub fn check_reply_bindings(
    header: &Ral1Header,
    inner: ReplyInner,
) -> Result<(PairResponse, Vec<u8>, Vec<CarriedEnvelope>), Ral1Error> {
    if header.kind != Ral1Kind::Reply {
        return Err(Ral1Error::Inner);
    }
    let response = decode_response(&inner.pair_response).map_err(|_| Ral1Error::Inner)?;
    if response.responder_device_ed_pub != header.sender_device {
        return Err(Ral1Error::Binding);
    }
    let acks = carried(header, inner.acks, false)?;
    Ok((response, inner.pair_response, acks))
}

/// The rest of step 9 once the session root is known: each envelope's route
/// tag is the one of its index, type and `created_at` in the direction of
/// the letter's kind.
pub fn check_route_tags(
    root: &[u8; 32],
    kind: Ral1Kind,
    envelopes: &[CarriedEnvelope],
) -> Result<(), Ral1Error> {
    for carried in envelopes {
        let envelope = &carried.envelope;
        let index = parse_indexed_message_header(&envelope.message_ciphertext)
            .map_err(|_| Ral1Error::Binding)?;
        let tag = derive_route_tag(
            root,
            envelope.created_at,
            index,
            envelope.env_type,
            kind.direction(),
        )
        .map_err(|_| Ral1Error::Binding)?;
        if tag != envelope.routing_tag {
            return Err(Ral1Error::Binding);
        }
    }
    Ok(())
}

/// Steps 1-9 in the spec's order. `is_contact` answers step 4 for the sender
/// device; `wrap_dh` is step 6 (the recipient's signed-prekey DH with
/// `wrap_ephemeral` for the generation named by `wrap_bundle_hash`, or
/// [`Ral1Error::UnknownPrekey`]). It runs only after the signature verified.
pub fn open<C, D>(
    bytes: &[u8],
    local_device: &[u8; 32],
    now_ms: u64,
    is_contact: C,
    wrap_dh: D,
) -> Result<Opened, Ral1Error>
where
    C: FnOnce(&[u8; 32]) -> bool,
    D: FnOnce(&Ral1Header) -> Result<Zeroizing<[u8; 32]>, Ral1Error>,
{
    let letter = decode(bytes)?;
    check_recipient_and_time(&letter.header, local_device, now_ms)?;
    if !is_contact(&letter.header.sender_device) {
        return Err(Ral1Error::NotContact);
    }
    verify_signature(bytes, &letter.header)?;
    let dh = wrap_dh(&letter.header)?;
    let inner = unwrap_inner(&letter, &dh)?;
    let letter_digest = letter_digest(bytes);
    let header = letter.header;
    Ok(match decode_inner(header.kind, &inner)? {
        Ral1Inner::Letter(inner) => {
            let (pair_init, pair_init_wire, envelopes) = check_letter_bindings(&header, inner)?;
            Opened::Letter(Box::new(OpenedLetter {
                header,
                letter_digest,
                pair_init,
                pair_init_wire,
                envelopes,
            }))
        }
        Ral1Inner::Reply(inner) => {
            let (pair_response, pair_response_wire, acks) = check_reply_bindings(&header, inner)?;
            Opened::Reply(Box::new(OpenedReply {
                header,
                letter_digest,
                pair_response,
                pair_response_wire,
                acks,
            }))
        }
    })
}

/// The recipient's side of the wrap DH for a known signed-prekey secret:
/// `X25519(spk_R_secret, E_w)`, refusing an all-zero output.
pub fn wrap_dh_with_secret(
    signed_prekey_secret: &[u8; 32],
    wrap_ephemeral: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Ral1Error> {
    x25519_shared_checked(signed_prekey_secret, wrap_ephemeral)
        .map(Zeroizing::new)
        .map_err(|_| Ral1Error::Unwrap)
}

/// Step 6 with this device's prekey lifecycle actor, for [`open`]'s
/// `wrap_dh`: [`PrekeyLifecycleActor::letter_shared_secret`] for the header's
/// `wrap_bundle_hash` and `wrap_ephemeral`. An unknown or destroyed
/// generation is [`Ral1Error::UnknownPrekey`] (the letter is released); a
/// non-contributory key, which decode already refuses, is
/// [`Ral1Error::Unwrap`] like [`wrap_dh_with_secret`]; a local store error is
/// [`Ral1Error::Store`] (the letter stays held).
pub fn wrap_dh_with_actor(
    actor: &PrekeyLifecycleActor,
    header: &Ral1Header,
    now_ms: u64,
) -> Result<Zeroizing<[u8; 32]>, Ral1Error> {
    actor
        .letter_shared_secret(&header.wrap_bundle_hash, &header.wrap_ephemeral, now_ms)
        .map_err(|error| match error {
            PrekeyLifecycleError::UnknownPrekey => Ral1Error::UnknownPrekey,
            PrekeyLifecycleError::NonContributoryWrapKey => Ral1Error::Unwrap,
            _ => Ral1Error::Store,
        })
}

pub mod intake;

#[cfg(test)]
mod tests;
