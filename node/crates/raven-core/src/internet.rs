//! InternetTransport codec — Noise XX + channel-bound RIH1 hello + frames.
//!
//! Live sockets live in `raven-node` `internet_direct`. Wire (lab-only):
//! every message is `u32_be(len) || noise_msg`; first a Noise XX handshake
//! (prologue [`NOISE_PROLOGUE`]), then each side sends an encrypted RIH1
//! hello whose Ed25519 signature covers the final handshake hash, the
//! signer's role and its Noise static key. RLB1 offers, PairInit and
//! envelopes only ever travel as Noise transport ciphertext. This module is
//! pack/unpack only. Localhost indexed delivery is a software substitute; it
//! is **not** public-Internet / WAN Proven.
//!
//! ADR-0002 target: rust-libp2p QUIC/TCP + DHT. Signed discovery records live
//! in `crate::discovery`. Live Kademlia / DCUtR / multi-NAT CGNAT: see
//! `discovery::NAT_STATUS` (BLOCKED_HARDWARE).

use crate::identity::Identity;
use crate::lan_noise::{self, LanNoiseError};
use crate::transport::NodeCapability;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use snow::HandshakeState;

/// Protocol id for capability negotiation (ASCII, fixed).
pub const INTERNET_PROTO_ID: &[u8] = b"raven/internet/v1";

/// Noise prologue: domain-separates InternetTransport from LAN Noise (which
/// has no prologue), so neither transcript can complete against the other.
pub const NOISE_PROLOGUE: &[u8] = INTERNET_PROTO_ID;

/// Noise prologue of the Raven link inside a libp2p `/raven/link/1.0.0`
/// stream (P3, transports design §3.2). Same XX, RIH1 hello layout and frames
/// as Internet direct; the distinct prologue means neither a raw-TCP nor a
/// libp2p transcript can complete against the other.
pub const P2P_LINK_PROLOGUE: &[u8] = b"raven/p2p-link/v1";

/// Noise prologue of the Raven link on a Bluetooth LE nearby pipe channel
/// (RAVEN_NEARBY_LINK_V1 §7): same XX, RIH1 hello and frames; the distinct
/// prologue means no TCP, libp2p or nearby transcript can complete against
/// another.
pub use crate::nearby_link::NEARBY_LINK_PROLOGUE;

/// Noise prologue of the Raven link inside a Tor onion stream
/// (`RAVEN_ONION_CARRIER_V1.md` §5): same XX, RIH1 hello and frames as
/// Internet direct; the distinct prologue means no TCP, libp2p, nearby or
/// onion transcript can complete against another.
pub const ONION_LINK_PROLOGUE: &[u8] = b"raven/onion-link/v1";

/// Max `u32_be`-framed wire message: one Noise message (snow's limit).
pub const MAX_FRAME_BYTES: usize = lan_noise::MAX_NOISE_MSG;

/// Max application payload (RLB1 / PairInit / envelope) per Noise frame.
pub const MAX_PAYLOAD_BYTES: usize = lan_noise::MAX_TRANSPORT_PLAINTEXT;

/// Hello magic.
pub const HELLO_MAGIC: &[u8; 4] = b"RIH1";

/// Hello signature domain. Distinct from the retired cleartext RIH1 signing
/// bytes (`"RIH1" || proto || ...`) and from the LAN bind domain.
pub const HELLO_SIG_DOMAIN: &[u8] = b"rvn1/internet-hello/v1";

/// Capability bit flags (generic — never contact-identifying).
pub const CAP_BLE: u32 = 1 << 0;
pub const CAP_INTERNET: u32 = 1 << 1;
pub const CAP_RELAY: u32 = 1 << 2;
pub const CAP_STORE: u32 = 1 << 3;
pub const CAP_BRIDGE: u32 = 1 << 4;

/// Link features (bits 8..31; bits 0..7 are node capabilities). Every receiver ignores
/// bits it does not know (unchanged behaviour: only CAP_INTERNET is required).
/// Bit 8: this side accepts RRH1 route hints on this link (RAVEN_ROUTE_HINTS_V1 §3.1).
pub const CAP_LINK_RRH1: u32 = 1 << 8;
/// Bit 9: this side pads its link frames with PAD1 and reads padded ones
/// (RAVEN_LINK_PADDING_V1 §3, [`crate::link_padding`]).
pub const CAP_LINK_PAD1: u32 = 1 << 9;
/// Bit 10: this side passes advisories, logs and bundles along with RUP1 on
/// this link (RAVEN_UPDATE_EXCHANGE_V1 §2, [`crate::update_exchange`]). No
/// build sets it while the mesh update gate is shut; the capability floor
/// records it once one does.
pub const CAP_LINK_RUP1: u32 = 1 << 10;
/// Bit 11: this side holds no route hints of the peer's (none since its
/// start, or it forgot them: `raven contact forget-address`, a new card),
/// so the peer sends its RRH1 on this link even when it would not be due
/// (RAVEN_ROUTE_HINTS_V1 §3.1, §6.1). Set only with [`CAP_LINK_RRH1`]; a
/// per-link request, never a capability (the capability floor ignores it).
pub const CAP_LINK_RRH1_ASK: u32 = 1 << 11;

/// The link features one side offers on one link: caps bits 8 up, a set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct LinkFeatures(u32);

impl LinkFeatures {
    /// No link feature: the hello of every build before route hints.
    pub const NONE: Self = Self(0);
    /// RRH1 route hints ([`CAP_LINK_RRH1`]).
    pub const RRH1: Self = Self(CAP_LINK_RRH1);
    /// PAD1 link padding ([`CAP_LINK_PAD1`]).
    pub const PAD1: Self = Self(CAP_LINK_PAD1);
    /// RUP1 update exchange ([`CAP_LINK_RUP1`]).
    pub const RUP1: Self = Self(CAP_LINK_RUP1);
    /// The request for the peer's RRH1 on this link ([`CAP_LINK_RRH1_ASK`]).
    pub const RRH1_ASK: Self = Self(CAP_LINK_RRH1_ASK);

    /// This set, plus `feature` when `on`.
    #[must_use]
    pub const fn with(self, feature: Self, on: bool) -> Self {
        if on {
            Self(self.0 | feature.0)
        } else {
            self
        }
    }

    /// Does this set hold every feature of `feature`?
    pub const fn contains(self, feature: Self) -> bool {
        self.0 & feature.0 == feature.0
    }

    /// The caps bits of this set.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// The caps a Raven link hello carries: [`CAP_INTERNET`] plus the link
/// features this side offers on this link (RRH1 when the route-hints gate and
/// the carrier's own are live, `route_hints::route_hints_live_on`; PAD1 when
/// link padding is; RUP1 when the update exchange is). With
/// [`LinkFeatures::NONE`] the hello is exactly what
/// every build before route hints sends, with [`LinkFeatures::RRH1`] what
/// every build before PAD1 sends.
pub fn hello_caps(features: LinkFeatures) -> u32 {
    CAP_INTERNET | features.bits()
}

pub fn caps_to_bits(caps: &[NodeCapability]) -> u32 {
    let mut b = 0u32;
    for c in caps {
        b |= match c {
            NodeCapability::Ble => CAP_BLE,
            NodeCapability::Internet => CAP_INTERNET,
            NodeCapability::Relay => CAP_RELAY,
            NodeCapability::Store => CAP_STORE,
            NodeCapability::Bridge => CAP_BRIDGE,
        };
    }
    b
}

pub fn bits_to_caps(bits: u32) -> Vec<NodeCapability> {
    let mut out = Vec::new();
    if bits & CAP_BLE != 0 {
        out.push(NodeCapability::Ble);
    }
    if bits & CAP_INTERNET != 0 {
        out.push(NodeCapability::Internet);
    }
    if bits & CAP_RELAY != 0 {
        out.push(NodeCapability::Relay);
    }
    if bits & CAP_STORE != 0 {
        out.push(NodeCapability::Store);
    }
    if bits & CAP_BRIDGE != 0 {
        out.push(NodeCapability::Bridge);
    }
    out
}

/// Noise XX initiator for InternetTransport (LAN static key, internet prologue).
pub fn build_noise_initiator(static_priv: &[u8; 32]) -> Result<HandshakeState, LanNoiseError> {
    lan_noise::build_initiator_with_prologue(static_priv, NOISE_PROLOGUE)
}

/// Noise XX responder for InternetTransport (LAN static key, internet prologue).
pub fn build_noise_responder(static_priv: &[u8; 32]) -> Result<HandshakeState, LanNoiseError> {
    lan_noise::build_responder_with_prologue(static_priv, NOISE_PROLOGUE)
}

/// Which side of the Noise handshake signed a hello. Signed, so a hello can
/// never be reflected back to its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloRole {
    Initiator,
    Responder,
}

impl HelloRole {
    pub fn wire(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 2,
        }
    }
}

/// Channel binding a hello signature commits to. For [`pack_hello`] it
/// describes the signer (us); for [`unpack_verify_hello`] the expected peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloBinding {
    /// Role of the hello's signer.
    pub role: HelloRole,
    /// Final Noise XX handshake hash (identical on both sides, fresh per
    /// connection because it covers both ephemeral keys).
    pub handshake_hash: [u8; 32],
    /// Signer's Noise static X25519 public key, as authenticated by XX.
    pub noise_static_pub: [u8; 32],
}

/// Hello signing bytes:
/// `"rvn1/internet-hello/v1" || role_u8 || caps_be || hs_hash32 || noise_static32 || ed_pub32`
pub fn hello_signing_bytes(caps: u32, binding: &HelloBinding, pub_key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_SIG_DOMAIN.len() + 1 + 4 + 32 + 32 + 32);
    out.extend_from_slice(HELLO_SIG_DOMAIN);
    out.push(binding.role.wire());
    out.extend_from_slice(&caps.to_be_bytes());
    out.extend_from_slice(&binding.handshake_hash);
    out.extend_from_slice(&binding.noise_static_pub);
    out.extend_from_slice(pub_key);
    out
}

/// Packed hello wire length: magic(4) || caps_u32_be || pub(32) || sig(64).
pub const HELLO_WIRE_LEN: usize = 4 + 4 + 32 + 64;

/// Packed hello (sent only as Noise transport plaintext):
/// `magic(4) || caps_u32_be || pub(32) || sig(64)`. `binding` is the signer's.
pub fn pack_hello(id: &Identity, caps: u32, binding: &HelloBinding) -> Vec<u8> {
    let pk = id.public_key_bytes();
    let sb = hello_signing_bytes(caps, binding, &pk);
    let sig = id.sign(&sb);
    let mut out = Vec::with_capacity(HELLO_WIRE_LEN);
    out.extend_from_slice(HELLO_MAGIC);
    out.extend_from_slice(&caps.to_be_bytes());
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sig);
    out
}

/// Verify a peer hello against this connection's binding (peer role, shared
/// handshake hash, peer Noise static). A hello from any other connection,
/// direction or static key fails. Returns `(caps, ed25519_pub)`. Unknown caps
/// bits (link features such as [`CAP_LINK_RRH1`]) are returned, never refused.
pub fn unpack_verify_hello(raw: &[u8], binding: &HelloBinding) -> Result<(u32, [u8; 32]), String> {
    if raw.len() != HELLO_WIRE_LEN {
        return Err("hello length".into());
    }
    if &raw[0..4] != HELLO_MAGIC {
        return Err("hello magic".into());
    }
    let caps = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[8..40]);
    let mut sig_b = [0u8; 64];
    sig_b.copy_from_slice(&raw[40..104]);
    let sb = hello_signing_bytes(caps, binding, &pk);
    if sb.starts_with(&crate::agent_sign::AGENT_DELEGATION_PREFIX) {
        return Err("hello sig".into());
    }
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad pub")?;
    let sig = Signature::from_bytes(&sig_b);
    vk.verify_strict(&sb, &sig).map_err(|_| "hello sig")?;
    Ok((caps, pk))
}

/// Frame: u32 BE length || payload. On the live path the payload is one Noise
/// message (handshake or transport ciphertext), never an application object.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err("frame too large".into());
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Lenient prefix deframer: `None` means "no complete frame" for *both* an
/// incomplete buffer and a length that can never be valid, and a zero-length
/// frame is accepted. Not used on the live path (`read_raw` in raven-node
/// rejects both); a buffered stream reader must use [`deframe_prefix_checked`]
/// so it can tell "wait for more bytes" from "protocol violation, close".
pub fn deframe_prefix(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if n > MAX_FRAME_BYTES {
        return None;
    }
    if buf.len() < 4 + n {
        return None;
    }
    Some((buf[4..4 + n].to_vec(), 4 + n))
}

/// Strict prefix deframer with the live reader's rules: `Ok(None)` only when
/// the buffer holds an incomplete length prefix or body (read more bytes);
/// `Err` as soon as the prefix is a zero or over-[`MAX_FRAME_BYTES`] length,
/// which can never become a valid frame (fail fast instead of buffering).
pub fn deframe_prefix_checked(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if n == 0 || n > MAX_FRAME_BYTES {
        return Err("frame length out of range".into());
    }
    if buf.len() < 4 + n {
        return Ok(None);
    }
    Ok(Some((buf[4..4 + n].to_vec(), 4 + n)))
}

/// Opaque store index: SHA-256("raven/relay-tag/v1" || mailbox_tag)[:16].
/// The input is the separately derived rotating mailbox capability, never an
/// envelope routing tag or username.
pub fn opaque_store_tag(mailbox_tag: &[u8; 16]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"raven/relay-tag/v1");
    h.update(mailbox_tag);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::lan_noise::{
        derive_noise_static, get_remote_static, handshake_hash, handshake_read, handshake_write,
        into_transport, noise_static_public, transport_decrypt, transport_encrypt,
    };
    use snow::TransportState;

    /// One completed internet Noise XX session, as both endpoints see it.
    struct Session {
        init_t: TransportState,
        resp_t: TransportState,
        /// Binding the initiator signs (and the responder verifies against).
        init_binding: HelloBinding,
        /// Binding the responder signs (and the initiator verifies against).
        resp_binding: HelloBinding,
    }

    fn session(initiator: &Identity, responder: &Identity) -> Session {
        let ip = derive_noise_static(initiator).unwrap();
        let rp = derive_noise_static(responder).unwrap();
        let mut i = build_noise_initiator(&ip).unwrap();
        let mut r = build_noise_responder(&rp).unwrap();
        let m1 = handshake_write(&mut i, &[]).unwrap();
        handshake_read(&mut r, &m1).unwrap();
        let m2 = handshake_write(&mut r, &[]).unwrap();
        handshake_read(&mut i, &m2).unwrap();
        let m3 = handshake_write(&mut i, &[]).unwrap();
        handshake_read(&mut r, &m3).unwrap();
        let h = handshake_hash(&i);
        assert_eq!(h, handshake_hash(&r));
        // Each side's view of the peer static must equal what the peer signs.
        assert_eq!(get_remote_static(&r).unwrap(), noise_static_public(&ip));
        assert_eq!(get_remote_static(&i).unwrap(), noise_static_public(&rp));
        Session {
            init_binding: HelloBinding {
                role: HelloRole::Initiator,
                handshake_hash: h,
                noise_static_pub: noise_static_public(&ip),
            },
            resp_binding: HelloBinding {
                role: HelloRole::Responder,
                handshake_hash: h,
                noise_static_pub: noise_static_public(&rp),
            },
            init_t: into_transport(i).unwrap(),
            resp_t: into_transport(r).unwrap(),
        }
    }

    fn alice() -> Identity {
        Identity::from_seed(&[0x11; 32])
    }
    fn bob() -> Identity {
        Identity::from_seed(&[0x22; 32])
    }
    fn mallory() -> Identity {
        Identity::from_seed(&[0x33; 32])
    }

    #[test]
    fn hello_roundtrip() {
        let (a, b) = (alice(), bob());
        let s = session(&a, &b);
        let packed = pack_hello(&a, CAP_INTERNET | CAP_RELAY, &s.init_binding);
        assert_eq!(packed.len(), HELLO_WIRE_LEN);
        let (caps, pk) = unpack_verify_hello(&packed, &s.init_binding).unwrap();
        assert_eq!(caps, CAP_INTERNET | CAP_RELAY);
        assert_eq!(pk, a.public_key_bytes());
        let packed = pack_hello(&b, CAP_INTERNET, &s.resp_binding);
        let (_, pk) = unpack_verify_hello(&packed, &s.resp_binding).unwrap();
        assert_eq!(pk, b.public_key_bytes());
    }

    #[test]
    fn hello_caps_carry_the_rrh1_link_bit_only_when_asked() {
        let rrh1 = |on| hello_caps(LinkFeatures::NONE.with(LinkFeatures::RRH1, on));
        assert_eq!(rrh1(false), CAP_INTERNET);
        assert_eq!(rrh1(true), CAP_INTERNET | CAP_LINK_RRH1);
        assert_eq!(rrh1(true), 0x0000_0102);
        assert_eq!(CAP_LINK_RRH1, 1 << 8);
        // A link feature is not a node capability.
        assert_eq!(bits_to_caps(rrh1(true)), bits_to_caps(CAP_INTERNET));
        // A hello with the link bit verifies and returns it unchanged (old
        // builds check only CAP_INTERNET, so they ignore it).
        let a = alice();
        let s = session(&a, &bob());
        let packed = pack_hello(&a, 0x0000_0102, &s.init_binding);
        let (caps, pk) = unpack_verify_hello(&packed, &s.init_binding).unwrap();
        assert_eq!(caps, 0x0000_0102);
        assert_ne!(caps & CAP_INTERNET, 0);
        assert_eq!(pk, a.public_key_bytes());
        // Bits nobody knows yet are returned too, never refused.
        let packed = pack_hello(&a, u32::MAX, &s.init_binding);
        assert_eq!(
            unpack_verify_hello(&packed, &s.init_binding).unwrap().0,
            u32::MAX
        );
    }

    /// A `LinkFeatures` set: the caps of a set that holds only RRH1 are the
    /// ones `hello_caps(true)` gave before PAD1 (the rih1 vectors are
    /// unchanged); PAD1 adds bit 9 and nothing else.
    #[test]
    fn hello_caps_from_a_link_feature_set() {
        assert_eq!(CAP_LINK_PAD1, 0x0000_0200);
        assert_eq!(CAP_LINK_RUP1, 0x0000_0400);
        assert_eq!(CAP_LINK_RRH1_ASK, 0x0000_0800);
        assert_eq!(
            hello_caps(LinkFeatures::RRH1.with(LinkFeatures::RRH1_ASK, true)),
            0x0000_0902
        );
        assert_eq!(hello_caps(LinkFeatures::NONE), 0x0000_0002);
        assert_eq!(hello_caps(LinkFeatures::RRH1), 0x0000_0102);
        assert_eq!(hello_caps(LinkFeatures::PAD1), 0x0000_0202);
        let both = LinkFeatures::RRH1.with(LinkFeatures::PAD1, true);
        assert_eq!(hello_caps(both), 0x0000_0302);
        assert_eq!(
            LinkFeatures::RRH1.with(LinkFeatures::PAD1, false),
            LinkFeatures::RRH1
        );
        assert!(both.contains(LinkFeatures::RRH1) && both.contains(LinkFeatures::PAD1));
        assert!(!LinkFeatures::RRH1.contains(LinkFeatures::PAD1));
        assert!(LinkFeatures::PAD1.contains(LinkFeatures::NONE));
        assert_eq!(LinkFeatures::default(), LinkFeatures::NONE);
        // Link features are bits 8 up: never a node capability.
        assert_eq!(both.bits() & 0xFF, 0);
        assert_eq!(bits_to_caps(hello_caps(both)), bits_to_caps(CAP_INTERNET));
        // RUP1 adds bit 10 and nothing else (update/rup1_frames_001.json).
        assert_eq!(hello_caps(LinkFeatures::RUP1), 0x0000_0402);
        let all = both.with(LinkFeatures::RUP1, true);
        assert_eq!(hello_caps(all), 0x0000_0702);
        assert_eq!(both.with(LinkFeatures::RUP1, false), both);
        assert!(all.contains(both) && all.contains(LinkFeatures::RUP1));
        assert!(!both.contains(LinkFeatures::RUP1));
        assert_eq!(bits_to_caps(hello_caps(all)), bits_to_caps(CAP_INTERNET));
    }

    #[test]
    fn hello_tamper_rejected() {
        let a = alice();
        let s = session(&a, &bob());
        let good = pack_hello(&a, CAP_BRIDGE, &s.init_binding);
        for idx in [5usize, 10, 60] {
            let mut packed = good.clone();
            packed[idx] ^= 0xff;
            assert!(unpack_verify_hello(&packed, &s.init_binding).is_err());
        }
        assert!(unpack_verify_hello(&good[..HELLO_WIRE_LEN - 1], &s.init_binding).is_err());
    }

    #[test]
    fn captured_hello_cannot_be_replayed_on_another_connection() {
        // Old RIH1 signed only a self-chosen nonce, so a captured hello
        // authenticated anyone who replayed it. Now it is bound to the
        // handshake hash, which covers fresh ephemerals on every connection.
        let (a, b, m) = (alice(), bob(), mallory());
        let s1 = session(&a, &b);
        let captured = pack_hello(&a, CAP_INTERNET, &s1.init_binding);
        // Mallory dials Bob and replays Alice's hello.
        let s2 = session(&m, &b);
        assert_eq!(
            unpack_verify_hello(&captured, &s2.init_binding),
            Err("hello sig".into())
        );
        // Even a second Alice→Bob connection gets a different hash.
        let s3 = session(&a, &b);
        assert_ne!(
            s1.init_binding.handshake_hash,
            s3.init_binding.handshake_hash
        );
        assert!(unpack_verify_hello(&captured, &s3.init_binding).is_err());
    }

    #[test]
    fn hello_is_bound_to_role_and_noise_static() {
        let (a, b, m) = (alice(), bob(), mallory());
        let s = session(&a, &b);
        let hello = pack_hello(&a, CAP_INTERNET, &s.init_binding);
        // Reflection: the initiator's own hello must not pass as the responder's.
        let reflected = HelloBinding {
            role: HelloRole::Responder,
            ..s.init_binding
        };
        assert!(unpack_verify_hello(&hello, &reflected).is_err());
        // A different Noise static (e.g. an on-path relay's) must not verify.
        let wrong_static = HelloBinding {
            noise_static_pub: noise_static_public(&derive_noise_static(&m).unwrap()),
            ..s.init_binding
        };
        assert!(unpack_verify_hello(&hello, &wrong_static).is_err());
    }

    #[test]
    fn hello_and_offers_are_never_cleartext_on_the_wire() {
        let a = alice();
        let mut s = session(&a, &bob());
        let hello = pack_hello(&a, CAP_INTERNET, &s.init_binding);
        let ct = transport_encrypt(&mut s.init_t, &hello).unwrap();
        assert!(!ct.windows(4).any(|w| w == HELLO_MAGIC));
        assert!(!ct.windows(32).any(|w| w == a.public_key_bytes()));
        let pt = transport_decrypt(&mut s.resp_t, &ct).unwrap();
        unpack_verify_hello(&pt, &s.init_binding).unwrap();
        let offer = b"RLB1\x01\x02 cert json must stay inside Noise";
        let ct = transport_encrypt(&mut s.resp_t, offer).unwrap();
        assert!(!ct.windows(4).any(|w| w == b"RLB1"));
        assert!(frame(&ct).unwrap().len() <= 4 + MAX_FRAME_BYTES);
    }

    #[test]
    fn lan_transcript_does_not_complete_against_internet_responder() {
        let ip = derive_noise_static(&alice()).unwrap();
        let rp = derive_noise_static(&bob()).unwrap();
        let mut i = crate::lan_noise::build_initiator(&ip).unwrap();
        let mut r = build_noise_responder(&rp).unwrap();
        let m1 = handshake_write(&mut i, &[]).unwrap();
        handshake_read(&mut r, &m1).unwrap();
        let m2 = handshake_write(&mut r, &[]).unwrap();
        assert!(handshake_read(&mut i, &m2).is_err());
    }

    #[test]
    fn p2p_link_and_internet_transcripts_do_not_complete_against_each_other() {
        let ip = derive_noise_static(&alice()).unwrap();
        let rp = derive_noise_static(&bob()).unwrap();
        for (init, resp) in [
            (NOISE_PROLOGUE, P2P_LINK_PROLOGUE),
            (P2P_LINK_PROLOGUE, NOISE_PROLOGUE),
            (NOISE_PROLOGUE, ONION_LINK_PROLOGUE),
            (ONION_LINK_PROLOGUE, NOISE_PROLOGUE),
            (P2P_LINK_PROLOGUE, ONION_LINK_PROLOGUE),
            (ONION_LINK_PROLOGUE, NEARBY_LINK_PROLOGUE),
        ] {
            let mut i = crate::lan_noise::build_initiator_with_prologue(&ip, init).unwrap();
            let mut r = crate::lan_noise::build_responder_with_prologue(&rp, resp).unwrap();
            let m1 = handshake_write(&mut i, &[]).unwrap();
            handshake_read(&mut r, &m1).unwrap();
            let m2 = handshake_write(&mut r, &[]).unwrap();
            assert!(handshake_read(&mut i, &m2).is_err());
        }
        assert_ne!(P2P_LINK_PROLOGUE, NOISE_PROLOGUE);
    }

    #[test]
    fn frame_cap_is_one_noise_message() {
        assert_eq!(MAX_FRAME_BYTES, 65535);
        assert!(frame(&vec![0u8; MAX_FRAME_BYTES]).is_ok());
        assert!(frame(&vec![0u8; MAX_FRAME_BYTES + 1]).is_err());
        let mut oversized = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec();
        oversized.resize(4 + MAX_FRAME_BYTES + 1, 0);
        assert!(deframe_prefix(&oversized).is_none());
    }

    #[test]
    fn deframe_prefix_checked_separates_incomplete_from_invalid() {
        let payload = b"RVN1demo".to_vec();
        let f = frame(&payload).unwrap();
        assert_eq!(
            deframe_prefix_checked(&f).unwrap(),
            Some((payload, f.len()))
        );
        // Incomplete prefix / body: read more bytes.
        assert_eq!(deframe_prefix_checked(&f[..3]).unwrap(), None);
        assert_eq!(deframe_prefix_checked(&f[..f.len() - 1]).unwrap(), None);
        // A length that can never be valid fails at once, before any body
        // bytes have arrived.
        let oversized = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert!(deframe_prefix_checked(&oversized).is_err());
        assert!(deframe_prefix_checked(&u32::MAX.to_be_bytes()).is_err());
        // Zero-length frames are refused like the live reader does.
        assert!(deframe_prefix_checked(&0u32.to_be_bytes()).is_err());
        // The lenient variant keeps its documented behaviour.
        assert!(deframe_prefix(&oversized).is_none());
        assert_eq!(deframe_prefix(&0u32.to_be_bytes()), Some((Vec::new(), 4)));
    }

    #[test]
    fn frame_roundtrip() {
        let payload = b"RVN1demo".to_vec();
        let f = frame(&payload).unwrap();
        let (p, n) = deframe_prefix(&f).unwrap();
        assert_eq!(p, payload);
        assert_eq!(n, f.len());
    }

    #[test]
    fn store_tag_not_username() {
        let tag = [7u8; 16];
        let a = opaque_store_tag(&tag);
        let b = opaque_store_tag(&tag);
        assert_eq!(a, b);
        assert_ne!(a, tag);
    }
}
