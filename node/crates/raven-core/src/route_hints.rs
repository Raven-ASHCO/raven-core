//! Route hints (RRH1): a contact tells another contact how to reach it.
//!
//! Design: the any-network reachability plan (not published) (Phase 2 item 1,
//! C5). Normative wire format: `protocol/RAVEN_ROUTE_HINTS_V1.md`.
//!
//! RRH1 is a raw Noise-transport plaintext frame, like RLB1 and RSR1. It rides
//! only an endpoint-authenticated Raven link (LAN direct, Internet direct, the
//! p2p link), at most once each way, after both RLB1 offers, and only to a
//! peer that asked for it on that connection: RIH1 hello caps bit 8
//! ([`crate::CAP_LINK_RRH1`]), or on LAN the RLX1 payload of Noise XX
//! message 3 ([`rlx1_payload`]). A build that did not ask closes the link on
//! any non-RVN1 frame, so nothing is ever sent unasked. RRH1 is never wrapped
//! in RVN1, never a reply, never stored except by its receiver (to reach the
//! sender) and never forwarded. It has no signature: the link authenticates
//! it, so it stays deniable.
//!
//! This module is the pure part: the gate, the RLX1 and RRH1 codecs
//! ([`decode`] is the structural check, §5.1), the RELAY_OFFER record codec
//! ([`decode_offer`], §11), the custody entries' tag ([`custodian_tag`],
//! §12) and the receiver's semantic rules ([`validate`], §5.2 and §11.3).
//! Everything is behind [`route_hints_live`] (on in release builds since
//! 2026-10; `RAVEN_LAB_ROUTE_HINTS=0` closes it in a debug build) and the
//! carrier's own gate ([`route_hints_live_on`]); relay offers also need the
//! friend relay gate ([`crate::relay_offers_live`]).

use std::net::IpAddr;
use std::sync::OnceLock;

use crate::identity::Identity;
use crate::outbox::{is_local_network_ip, OutboxCarrier};
use crate::p2p_route::{
    is_global_ip, libp2p_ed25519_public, normalize_peer_id, parse_peer_id, parse_via,
    peer_id_from_bytes, ViaAddr, MAX_MULTIADDR_CHARS, PEER_ID_BYTES,
};

mod relay_offer;

pub use relay_offer::{
    decode_offer, encode_offer, OfferDecode, RelayOfferRecord, FLAG_AUTONAT, FLAG_CONFIRMED,
    FLAG_PORT_443, MAX_OFFER_ADDRS, OFFER_ADDR_MAX_LEN, OFFER_ADDR_MIN_LEN, OFFER_FLAGS_KNOWN,
    RELAY_OFFER_MAX_LEN, RELAY_OFFER_VERSION,
};

/// Production gate for route hints on every link (LAN, Internet, p2p, Tor,
/// nearby): one const. Switched on 2026-10 after the three-machine field
/// test; not independently reviewed. Addresses still travel only inside
/// these encrypted, authenticated links between verified friends.
pub const ROUTE_HINTS_PRODUCTION_ENABLED: bool = true;

/// The sender's generation state in the data dir (raven-node's
/// `hints::GEN_STATE_FILE`, its only writer): per-contact digests, the
/// shared digest and this node's own LAN listener address. RMS1 kind 17 in a
/// sealed profile (privacy pack PP.5); named here so the migration knows it.
pub const ROUTE_HINTS_STATE_FILE: &str = "route_hints_state.json";

/// Route hints on: the production gate (a debug build: `RAVEN_LAB_ROUTE_HINTS=1`
/// opens it, `=0` closes it, independent of `RAVEN_LAB_TEST_A`; release
/// builds never read it), unless a security notice holds them or marks
/// `rrh1/1` BROKEN (P6.45).
pub fn route_hints_live() -> bool {
    crate::lan_gate::gate_switch(
        cfg!(debug_assertions),
        ROUTE_HINTS_PRODUCTION_ENABLED,
        || std::env::var("RAVEN_LAB_ROUTE_HINTS").ok(),
    ) && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_ROUTE_HINTS)
}

/// Whether contact cards carry, and readers take, the route fields no key
/// signs (`inet=`, `p2p=`, `via=`, a `raven-card/3`'s `p2pn=` and `relay=`;
/// spec §9.1): only a debug build with the lab unlock (`RAVEN_LAB_TEST_A=1`),
/// for the lab harnesses; never a release build. A card is copied around in
/// plain text and comparing security words checks the key only, so an
/// unsigned address in a card must never steer a dial: the addresses a
/// verified friend needs travel in these hints, inside an encrypted,
/// authenticated link. `lan=` (kept to the local network) and the signed
/// `onion=` are not affected.
pub fn card_routes_live() -> bool {
    crate::pair_init::lab_test_a_enabled()
}

/// RRH1 on this carrier: the hints gate AND the carrier's own gate.
pub fn route_hints_live_on(carrier: OutboxCarrier) -> bool {
    route_hints_live()
        && match carrier {
            OutboxCarrier::Lan => crate::lan_direct_live_enabled(),
            OutboxCarrier::Internet => crate::internet_direct_live_enabled(),
            OutboxCarrier::P2p => crate::p2p_live_enabled(),
            OutboxCarrier::Nearby => crate::nearby_live_enabled(),
            OutboxCarrier::Onion => crate::onion_live_enabled(),
        }
}

// ── RLX1: the LAN Noise XX message-3 payload (spec §3.2) ────────────────────

pub const RLX1_MAGIC: &[u8; 4] = b"RLX1";
pub const RLX1_VERSION: u8 = 1;
/// Longest RLX1 payload a receiver reads (anything longer is ignored whole).
pub const RLX1_MAX_LEN: usize = 64;
/// `LINK_CAPS`: u32 BE, the RIH1 hello caps bit namespace (bit 8 = RRH1).
pub const EXT_LINK_CAPS: u8 = 0x01;
/// Magic and version.
const RLX1_HEADER_LEN: usize = 5;

/// The m3 payload a LAN dialer sends: empty for `caps == 0` (byte for byte
/// what every pre-RLX1 build and a gate-off build send), otherwise
/// `"RLX1" || 01 || 01 04 || caps_be` (11 bytes).
pub fn rlx1_payload(caps: u32) -> Vec<u8> {
    if caps == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(RLX1_HEADER_LEN + 2 + 4);
    out.extend_from_slice(RLX1_MAGIC);
    out.push(RLX1_VERSION);
    out.push(EXT_LINK_CAPS);
    out.push(4);
    out.extend_from_slice(&caps.to_be_bytes());
    out
}

/// `PAD` (RAVEN_LINK_KNOCK_V1 §6): its value is ignored. A knocking dialer
/// adds one so message 3 has no fixed length; every RLX1 parser skips it as
/// an unknown type.
pub const EXT_PAD: u8 = 0x7E;

/// The shortest RLX1 payload [`rlx1_payload_padded`] makes for `caps`: the
/// header, `LINK_CAPS` when `caps` is not 0, and an empty `PAD` entry.
pub fn rlx1_padded_min_len(caps: u32) -> usize {
    RLX1_HEADER_LEN + if caps == 0 { 0 } else { 2 + 4 } + 2
}

/// An RLX1 payload with `LINK_CAPS` `caps` (left out when 0) and a `PAD`
/// entry of zeros that brings it to `total` bytes, kept within
/// [`rlx1_padded_min_len`]`..=`[`RLX1_MAX_LEN`]. Its caps read as `caps`
/// ([`rlx1_caps`]).
pub fn rlx1_payload_padded(caps: u32, total: usize) -> Vec<u8> {
    let min = rlx1_padded_min_len(caps);
    let total = total.clamp(min, RLX1_MAX_LEN);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(RLX1_MAGIC);
    out.push(RLX1_VERSION);
    if caps != 0 {
        out.push(EXT_LINK_CAPS);
        out.push(4);
        out.extend_from_slice(&caps.to_be_bytes());
    }
    let pad = total - out.len() - 2;
    out.push(EXT_PAD);
    out.push(u8::try_from(pad).expect("an RLX1 entry is at most 57 bytes"));
    out.resize(total, 0);
    out
}

/// The LINK_CAPS a dialer's m3 payload carries; never an error. 0 for the
/// empty payload and for any malformed one (length below 5 or above
/// [`RLX1_MAX_LEN`], wrong magic or version, a truncated entry, a duplicate
/// type, or LINK_CAPS whose len is not 4). Unknown types are skipped.
pub fn rlx1_caps(payload: &[u8]) -> u32 {
    if payload.len() < RLX1_HEADER_LEN
        || payload.len() > RLX1_MAX_LEN
        || payload[..4] != *RLX1_MAGIC
        || payload[4] != RLX1_VERSION
    {
        return 0;
    }
    let mut seen = [false; 256];
    let mut caps = 0;
    let mut rest = &payload[RLX1_HEADER_LEN..];
    while !rest.is_empty() {
        let (Some(&kind), Some(&len)) = (rest.first(), rest.get(1)) else {
            return 0;
        };
        let end = 2 + usize::from(len);
        let Some(value) = rest.get(2..end) else {
            return 0;
        };
        rest = &rest[end..];
        if std::mem::replace(&mut seen[usize::from(kind)], true) {
            return 0;
        }
        if kind == EXT_LINK_CAPS {
            let Ok(be) = <[u8; 4]>::try_from(value) else {
                return 0;
            };
            caps = u32::from_be_bytes(be);
        }
    }
    caps
}

// ── RRH1: the frame (spec §4) ───────────────────────────────────────────────

pub const RRH1_MAGIC: &[u8; 4] = b"RRH1";
pub const RRH1_VERSION: u8 = 1;
/// Magic, version, generation u64, ttl_s u32.
pub const RRH1_HEADER_LEN: usize = 17;
/// Longest frame; it also bounds unregistered entries, which are skipped
/// whatever their length.
pub const RRH1_MAX_LEN: usize = 4096;
/// Receivers ignore a frame with a lower TTL ...
pub const RRH1_MIN_TTL_S: u32 = 60;
/// ... and clamp a higher one to 7 days.
pub const RRH1_MAX_TTL_S: u32 = 604_800;
/// What senders use: 72 hours.
pub const RRH1_DEFAULT_TTL_S: u32 = 259_200;
/// Distinct relays a receiver keeps.
pub const MAX_RELAYS: usize = 2;
/// Addresses of one relay a receiver keeps (e.g. TCP 7423 and TCP 443: two
/// addresses of one reservation, fallbacks for each other).
pub const MAX_ADDRS_PER_RELAY: usize = 2;
/// RELAY entries one frame may carry.
pub const MAX_RELAY_ENTRIES: usize = MAX_RELAYS * MAX_ADDRS_PER_RELAY;
/// DIRECT entries one frame may carry ...
pub const MAX_DIRECT: usize = 6;
/// ... of which a receiver keeps at most this many global ones ...
pub const MAX_GLOBAL_DIRECT: usize = 4;
/// ... and this many same-LAN ones (LAN links only).
pub const MAX_LOCAL_DIRECT: usize = 2;
/// CUSTODIAN entries one frame may carry, and CUSTODIAN_TAG entries too.
pub const MAX_CUSTODIANS: usize = 2;
/// Domain of [`custodian_tag`] (spec §4, §12).
pub const CUSTODIAN_TAG_DOMAIN: &[u8] = b"raven/rrh1/custodian-tag/v1";
/// A CUSTODIAN_TAG value: the tag (32 bytes) and a flags u8 (spec §4, the
/// custodian flags rule). Bit 0 is HANDOFF_INBOX (Phase 5,
/// [`CUSTODIAN_FLAG_HANDOFF_INBOX`]); bit 1 LETTER_INBOX stays reserved. A
/// receiver clears every bit it does not know ([`CUSTODIAN_TAG_KNOWN_FLAGS`];
/// a Phase 3 one clears them all).
pub const CUSTODIAN_TAG_LEN: usize = 33;
/// The CUSTODY_OFFER bits this revision defines (spec §4, §12): WAN and
/// REACHABLE ([`crate::custody_gate::OFFER_WAN`],
/// [`crate::custody_gate::OFFER_REACHABLE`]). [`validate`] clears the others.
pub const CUSTODY_OFFER_KNOWN: u8 =
    crate::custody_gate::OFFER_WAN | crate::custody_gate::OFFER_REACHABLE;
/// The CUSTODIAN_TAG flag bits this revision defines: HANDOFF_INBOX (Phase
/// 5; Phase 3 defined none). [`validate`] clears the others.
pub const CUSTODIAN_TAG_KNOWN_FLAGS: u8 = CUSTODIAN_FLAG_HANDOFF_INBOX;
/// CUSTODIAN_TAG flag bit 0, HANDOFF_INBOX (Phase 5,
/// `RAVEN_CUSTODY_HANDOFF_V1.md` §3.6): the sender takes custody handoffs at
/// that custodian (it registered its tags there and the custodian answered
/// OK within 24 h), so a peer may FORWARD to it. The requester reads it
/// ([`crate::custody_client::announced_custodians`]); raven-node's snapshot
/// builder sets it.
pub const CUSTODIAN_FLAG_HANDOFF_INBOX: u8 = 0x01;
/// RELAY_OFFER records a receiver keeps from one frame (§11.2): the first
/// ones it accepts, one per relay.
pub const MAX_RELAY_OFFERS: usize = 2;
/// Longest RELAY value (a full `via=` multiaddr).
pub const RELAY_MAX_LEN: usize = MAX_MULTIADDR_CHARS;
/// Longest DIRECT value (an IP literal and a transport, no `/p2p`).
pub const DIRECT_MAX_LEN: usize = 120;

// Registered entry types (spec §4). Every other type, including the
// reserved 0x21, the rest of the range reserved for Phase 4 (0x25-0x2F) and
// Phase 5's (0x30-0x3F), is skipped. A receiver built before §11 skips 0x20
// too, one built before §12 skips 0x06 and 0x07, one built before §13 skips
// 0x22 and 0x23 (and one built before §13.3 0x24), and one built before §14
// skips 0x08.
const T_P2P_ID: u8 = 0x01;
const T_RELAY: u8 = 0x02;
const T_DIRECT: u8 = 0x03;
const T_LAN_PORT: u8 = 0x04;
/// Phase 2's plain custodian key: receive-only since §12 (Phase 3 senders
/// write CUSTODIAN_TAG instead).
const T_CUSTODIAN: u8 = 0x05;
const T_CUSTODY_OFFER: u8 = 0x06;
const T_CUSTODIAN_TAG: u8 = 0x07;
/// Phase 6b (§14): the pair seed ([`crate::pair_seed`]), the next free type
/// of this document's own range.
const T_PAIR_SEED: u8 = 0x08;
const T_RELAY_OFFER: u8 = 0x20;
const T_NAT_CLASS: u8 = 0x22;
const T_PEER_SCHEDULE: u8 = 0x23;
/// Auto-reach (§13.3): the public address of the sender's Internet direct
/// listener.
const T_INET_DIRECT: u8 = 0x24;
/// The Tor onion carrier's binding (§15; `RAVEN_ONION_CARRIER_V1.md` §3).
const T_ONION: u8 = 0x40;
/// Type u8 and len u16.
const ENTRY_HEADER_LEN: usize = 3;

const _: () = assert!(MAX_GLOBAL_DIRECT + MAX_LOCAL_DIRECT == MAX_DIRECT);
// The custody entries (§12) are this document's types, outside the ranges
// reserved for Phase 4 (0x22-0x2F) and Phase 5 (0x30-0x3F).
const _: () = assert!(T_CUSTODY_OFFER < 0x20 && T_CUSTODIAN_TAG < 0x20 && T_PAIR_SEED < 0x20);
const _: () = assert!(CUSTODIAN_TAG_LEN == 32 + 1);
// A frame with every registered entry at its limits still fits, so
// [`encode`] never writes one a receiver ignores for its length.
const _: () = assert!(
    RRH1_HEADER_LEN
        + (ENTRY_HEADER_LEN + PEER_ID_BYTES)
        + MAX_RELAY_ENTRIES * (ENTRY_HEADER_LEN + RELAY_MAX_LEN)
        + MAX_DIRECT * (ENTRY_HEADER_LEN + DIRECT_MAX_LEN)
        + (ENTRY_HEADER_LEN + 2)
        + MAX_CUSTODIANS * (ENTRY_HEADER_LEN + 32)
        + (ENTRY_HEADER_LEN + 1)
        + MAX_CUSTODIANS * (ENTRY_HEADER_LEN + CUSTODIAN_TAG_LEN)
        + (ENTRY_HEADER_LEN + crate::pair_seed::ENTRY_LEN)
        + MAX_RELAY_OFFERS * (ENTRY_HEADER_LEN + RELAY_OFFER_MAX_LEN)
        + (ENTRY_HEADER_LEN + NAT_CLASS_LEN)
        + (ENTRY_HEADER_LEN + PEER_SCHEDULE_MAX_LEN)
        + MAX_INET_DIRECT * (ENTRY_HEADER_LEN + INET_DIRECT_MAX_LEN)
        <= RRH1_MAX_LEN
);

// ── Auto-reach (spec §13.3) ─────────────────────────────────────────────────

/// INET_DIRECT entries per frame.
pub const MAX_INET_DIRECT: usize = 2;
/// INET_DIRECT's shortest and longest value: a flags byte and `ip:port`
/// (`1.1.1.1:1` to a bracketed full IPv6 address with a 5-digit port).
pub const INET_DIRECT_MIN_LEN: usize = 1 + 9;
pub const INET_DIRECT_MAX_LEN: usize = 1 + 47;
/// INET_DIRECT flags bit 0: a contact reached that listener from outside
/// within the last 24 hours.
pub const INET_FLAG_CONFIRMED: u8 = 0x01;
/// The INET_DIRECT flags this revision defines; the others are cleared on
/// decode.
pub const INET_FLAGS_KNOWN: u8 = INET_FLAG_CONFIRMED;

/// The public address of the sender's Internet direct listener (RRH1
/// INET_DIRECT, type 0x24, spec §13.3), with its flags (only
/// [`INET_FLAGS_KNOWN`] bits once decoded). Sent only while STUN discovery
/// is live ([`crate::stun_discovery_live_enabled`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InetDirect {
    pub flags: u8,
    pub addr: std::net::SocketAddr,
}

impl InetDirect {
    /// The entry's value: flags, then `addr` as text (IPv4 dotted decimal,
    /// IPv6 in brackets in RFC 5952 form, the port).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.flags];
        out.extend_from_slice(self.addr.to_string().as_bytes());
        out
    }

    /// An INET_DIRECT value: [`INET_DIRECT_MIN_LEN`]..=[`INET_DIRECT_MAX_LEN`]
    /// bytes, canonical `ip:port` text (it reads back to itself) with a port,
    /// no unspecified, multicast, broadcast or IPv4-mapped address, no scope;
    /// unknown flag bits cleared. Anything else is `None`.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        if !(INET_DIRECT_MIN_LEN..=INET_DIRECT_MAX_LEN).contains(&value.len()) {
            return None;
        }
        let text = std::str::from_utf8(&value[1..]).ok()?;
        let addr: std::net::SocketAddr = text.parse().ok()?;
        let ok_ip = match addr {
            std::net::SocketAddr::V4(a) => {
                !a.ip().is_unspecified() && !a.ip().is_multicast() && !a.ip().is_broadcast()
            }
            std::net::SocketAddr::V6(a) => {
                !a.ip().is_unspecified()
                    && !a.ip().is_multicast()
                    && a.ip().to_ipv4_mapped().is_none()
                    && a.scope_id() == 0
                    && a.flowinfo() == 0
            }
        };
        (ok_ip && addr.port() != 0 && addr.to_string() == text).then_some(Self {
            flags: value[0] & INET_FLAGS_KNOWN,
            addr,
        })
    }

    /// CONFIRMED is set.
    pub fn confirmed(&self) -> bool {
        self.flags & INET_FLAG_CONFIRMED != 0
    }
}

// ── Phase 4 extensions (spec §13) ───────────────────────────────────────────

/// NAT_CLASS's length: four class bytes and a flags byte.
pub const NAT_CLASS_LEN: usize = 5;
/// The highest class code ([`NatClass`]); a higher one reads as 0, unknown.
pub const NAT_CLASS_MAX_CODE: u8 = 4;
/// NAT_CLASS flags bit 0: the sender has a globally routable IPv6 address.
pub const NAT_FLAG_V6_GLOBAL: u8 = 0x01;
/// NAT_CLASS flags bit 1: an IPv6 pinhole (or an open IPv6 firewall) is
/// confirmed for the sender.
pub const NAT_FLAG_V6_OPEN: u8 = 0x02;
/// The flags this revision defines; the others are cleared on decode.
pub const NAT_FLAGS_KNOWN: u8 = NAT_FLAG_V6_GLOBAL | NAT_FLAG_V6_OPEN;

/// The sender's NAT mapping classes (RRH1 NAT_CLASS, type 0x22, spec §13.1),
/// one code per transport and family: 0 unknown, 1 no_nat, 2 stable_kept,
/// 3 stable_shifted, 4 varies. Sent only while the NAT_CLASS gate is live
/// ([`crate::nat_class_live_enabled`]); it inherits the frame's expiry. As
/// decoded, every code is at most [`NAT_CLASS_MAX_CODE`] and only
/// [`NAT_FLAGS_KNOWN`] bits are set ([`Self::normalized`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NatClass {
    pub v4_tcp: u8,
    pub v4_quic: u8,
    pub v6_tcp: u8,
    pub v6_quic: u8,
    pub flags: u8,
}

impl NatClass {
    /// The value as a receiver reads it: a code above
    /// [`NAT_CLASS_MAX_CODE`] is unknown (0), unknown flag bits are clear.
    pub fn normalized(self) -> Self {
        let code = |c: u8| if c > NAT_CLASS_MAX_CODE { 0 } else { c };
        Self {
            v4_tcp: code(self.v4_tcp),
            v4_quic: code(self.v4_quic),
            v6_tcp: code(self.v6_tcp),
            v6_quic: code(self.v6_quic),
            flags: self.flags & NAT_FLAGS_KNOWN,
        }
    }

    /// The five value bytes ([`Self::normalized`] first).
    pub fn to_bytes(self) -> [u8; NAT_CLASS_LEN] {
        let n = self.normalized();
        [n.v4_tcp, n.v4_quic, n.v6_tcp, n.v6_quic, n.flags]
    }

    /// A NAT_CLASS value: exactly [`NAT_CLASS_LEN`] bytes, else `None`
    /// (the entry is dropped alone, never the frame).
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let [v4_tcp, v4_quic, v6_tcp, v6_quic, flags] =
            <[u8; NAT_CLASS_LEN]>::try_from(value).ok()?;
        Some(
            Self {
                v4_tcp,
                v4_quic,
                v6_tcp,
                v6_quic,
                flags,
            }
            .normalized(),
        )
    }

    /// The word of one class code (logs, status, vectors).
    pub fn word(code: u8) -> &'static str {
        match code {
            1 => "no_nat",
            2 => "stable_kept",
            3 => "stable_shifted",
            4 => "varies",
            _ => "unknown",
        }
    }
}

/// PEER_SCHEDULE's fixed part: flags u8, epoch_len_s u32, active_epoch u64
/// and n u8.
pub const PEER_SCHEDULE_HEADER_LEN: usize = 14;
/// One PEER_SCHEDULE entry: epoch u64 and an Ed25519 public key.
pub const PEER_SCHEDULE_ENTRY_LEN: usize = 40;
/// The longest PEER_SCHEDULE value: [`crate::peer_rotation::MAX_SCHEDULE`]
/// entries.
pub const PEER_SCHEDULE_MAX_LEN: usize =
    PEER_SCHEDULE_HEADER_LEN + crate::peer_rotation::MAX_SCHEDULE * PEER_SCHEDULE_ENTRY_LEN;
/// PEER_SCHEDULE flags bit 0: the sender can rotate (always set when sent).
pub const SCHEDULE_FLAG_CAPABLE: u8 = 0x01;
/// PEER_SCHEDULE flags bit 1: the sender's rotation is on.
pub const SCHEDULE_FLAG_ROTATING: u8 = 0x02;
/// PEER_SCHEDULE flags bit 2: the sender rolled back to an earlier epoch.
pub const SCHEDULE_FLAG_POSTPONED: u8 = 0x04;
/// The flags this revision defines; the others are cleared on decode.
pub const SCHEDULE_FLAGS_KNOWN: u8 =
    SCHEDULE_FLAG_CAPABLE | SCHEDULE_FLAG_ROTATING | SCHEDULE_FLAG_POSTPONED;

/// The sender's PeerId rotation schedule (RRH1 PEER_SCHEDULE, type 0x23,
/// spec §13.2; `RAVEN_P2P_PEER_ROTATION_V1.md` §4): whether it can rotate,
/// whether it does, its epoch length, the epoch it uses and the Ed25519
/// public keys of the epochs around it. Sent only while the PeerId rotation
/// gate is live ([`crate::peer_rotation_live_enabled`]); the entries only
/// while the sender's rotation is on (none is a capability announcement).
/// As decoded: the capable bit set, only [`SCHEDULE_FLAGS_KNOWN`] bits, a
/// length of at least 1 s, at most [`crate::peer_rotation::MAX_SCHEDULE`]
/// entries with epochs strictly increasing within `active_epoch - 1 ..=
/// active_epoch + 6`, and every key usable
/// ([`crate::peer_rotation::schedule_key_ok`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSchedule {
    pub flags: u8,
    pub epoch_len_s: u32,
    pub active_epoch: u64,
    pub entries: Vec<(u64, [u8; 32])>,
}

impl PeerSchedule {
    /// The announcement of a sender whose rotation is off: capable, its
    /// epoch length, no entries. The active epoch says nothing then and is
    /// 0 (a clock epoch would tell the secret phase's neighbourhood).
    pub fn capability_only(epoch_len_s: u32) -> Self {
        Self {
            flags: SCHEDULE_FLAG_CAPABLE,
            epoch_len_s,
            active_epoch: 0,
            entries: Vec::new(),
        }
    }

    pub fn capable(&self) -> bool {
        self.flags & SCHEDULE_FLAG_CAPABLE != 0
    }

    pub fn rotating(&self) -> bool {
        self.flags & SCHEDULE_FLAG_ROTATING != 0
    }

    pub fn postponed(&self) -> bool {
        self.flags & SCHEDULE_FLAG_POSTPONED != 0
    }

    /// Does the value follow §13.2 (as [`Self::from_bytes`] reads it)?
    fn valid(&self) -> bool {
        let (lo, hi) = (
            self.active_epoch.saturating_sub(1),
            self.active_epoch
                .saturating_add(crate::peer_rotation::AHEAD),
        );
        self.capable()
            && self.flags & !SCHEDULE_FLAGS_KNOWN == 0
            && self.epoch_len_s != 0
            && self.entries.len() <= crate::peer_rotation::MAX_SCHEDULE
            && self.entries.iter().all(|(e, _)| (lo..=hi).contains(e))
            && self.entries.windows(2).all(|w| w[0].0 < w[1].0)
            && self
                .entries
                .iter()
                .all(|(_, key)| crate::peer_rotation::schedule_key_ok(key))
    }

    /// The value bytes: `flags u8 | epoch_len_s u32 | active_epoch u64 | n
    /// u8 | n × (epoch u64 | key 32)`, all big-endian. `None` for a value
    /// [`Self::from_bytes`] would drop (the sender then writes none).
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let flags = self.flags & SCHEDULE_FLAGS_KNOWN;
        let s = Self {
            flags,
            ..self.clone()
        };
        if !s.valid() {
            return None;
        }
        let mut out = Vec::with_capacity(
            PEER_SCHEDULE_HEADER_LEN + s.entries.len() * PEER_SCHEDULE_ENTRY_LEN,
        );
        out.push(flags);
        out.extend_from_slice(&s.epoch_len_s.to_be_bytes());
        out.extend_from_slice(&s.active_epoch.to_be_bytes());
        // At most MAX_SCHEDULE (8), checked by `valid`.
        out.push(s.entries.len() as u8);
        for (e, key) in &s.entries {
            out.extend_from_slice(&e.to_be_bytes());
            out.extend_from_slice(key);
        }
        Some(out)
    }

    /// A PEER_SCHEDULE value, or `None` (the entry is dropped alone, never
    /// the frame): a length other than `14 + 40 n`, n above 8, the capable
    /// bit clear, an epoch length of 0, epochs not strictly increasing or
    /// outside `active - 1 ..= active + 6`, a key that is not a point, not
    /// canonical or of small order. Unknown flag bits are cleared.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let (head, body) = value.split_at_checked(PEER_SCHEDULE_HEADER_LEN)?;
        let n = usize::from(head[13]);
        if n > crate::peer_rotation::MAX_SCHEDULE || body.len() != n * PEER_SCHEDULE_ENTRY_LEN {
            return None;
        }
        let entries = body
            .as_chunks::<PEER_SCHEDULE_ENTRY_LEN>()
            .0
            .iter()
            .map(|c| {
                let (e, key) = c.split_at(8);
                (
                    u64::from_be_bytes(e.try_into().expect("8 bytes")),
                    key.try_into().expect("32 bytes"),
                )
            })
            .collect();
        let s = Self {
            flags: head[0] & SCHEDULE_FLAGS_KNOWN,
            epoch_len_s: u32::from_be_bytes(head[1..5].try_into().ok()?),
            active_epoch: u64::from_be_bytes(head[5..13].try_into().ok()?),
            entries,
        };
        s.valid().then_some(s)
    }
}

/// One RRH1 frame as it travels: structurally valid ([`decode`]), not yet
/// checked against the link it came on ([`validate`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteHints {
    /// Strictly increasing per sender identity; never 0.
    pub generation: u64,
    /// Seconds the receiver may keep the snapshot (clamped on decode).
    pub ttl_s: u32,
    /// The sender's libp2p PeerId, binary ([`crate::p2p_route::peer_id_bytes`]).
    pub p2p_id: Option<[u8; PEER_ID_BYTES]>,
    /// Relays the sender holds a live reservation on (`via=` multiaddrs).
    pub relays: Vec<String>,
    /// Confirmed addresses of the sender's libp2p host, without `/p2p`.
    pub direct: Vec<String>,
    /// The sender's LAN-direct listener port.
    pub lan_port: Option<u16>,
    /// Custodians the sender listed for this receiver (Ed25519 device keys):
    /// Phase 2's CUSTODIAN, receive-only since §12. Phase 3 senders leave it
    /// empty; [`encode`] still writes what it holds (legacy vectors, the
    /// round trip).
    pub custodians: Vec<[u8; 32]>,
    /// CUSTODY_OFFER (§12): the sender holds sealed mail for its verified
    /// contacts; the flags as sent ([`validate`] clears unknown bits).
    pub custody_offer: Option<u8>,
    /// CUSTODIAN_TAG entries (§12): [`custodian_tag`] values and their flags
    /// u8 as sent, in frame order.
    pub custodian_tags: Vec<([u8; 32], u8)>,
    /// Relays the sender offers this receiver (RELAY_OFFER, §11): at most
    /// [`MAX_RELAY_OFFERS`], one per relay key, in frame order.
    pub offers: Vec<RelayOfferRecord>,
    /// RELAY_OFFER records [`decode`] dropped (§11.2): malformed, naming the
    /// relay of an earlier record, or past [`MAX_RELAY_OFFERS`]. Not on the
    /// wire ([`encode`] ignores it): the receiver's counts-only
    /// `RRH1_MALFORMED` log. Records of another version are not counted.
    pub dropped_offers: u32,
    /// The sender's NAT mapping classes (NAT_CLASS, Phase 4, spec §13.1).
    pub nat_class: Option<NatClass>,
    /// The sender's PeerId rotation schedule (PEER_SCHEDULE, Phase 4, spec
    /// §13.2).
    pub peer_schedule: Option<PeerSchedule>,
    /// Auto-reach (spec §13.3): the public address of the sender's Internet
    /// direct listener, at most [`MAX_INET_DIRECT`], in frame order.
    pub inet: Vec<InetDirect>,
    /// Phase 4 entries [`decode`] dropped alone (spec §13): a NAT_CLASS,
    /// PEER_SCHEDULE or INET_DIRECT that breaks its rules, or one too many.
    /// Not on the wire; counts-only logs.
    pub dropped_phase4: u32,
    /// The sender's pair seed (PAIR_SEED, Phase 6b, spec §14): its seed
    /// offer and the generation it uses.
    pub pair_seed: Option<crate::pair_seed::SeedEntry>,
    /// PAIR_SEED entries [`decode`] dropped alone (spec §14): one that
    /// breaks its rules, or a second one. Not on the wire; counts-only logs.
    pub dropped_pair_seed: u32,
    /// The sender's onion binding (ONION, spec §15): structure only here;
    /// [`validate`] keeps it only from a pinned sender whose key signed it.
    pub onion: Option<crate::onion::OnionBinding>,
    /// ONION entries [`decode`] dropped alone (spec §15): not exactly 104
    /// bytes, or a second one. Not on the wire; counts-only logs.
    pub dropped_onion: u32,
}

/// Does `frame` claim to be RRH1 (its magic)? Whether it is valid is
/// [`decode`]'s question.
pub fn is_rrh1(frame: &[u8]) -> bool {
    frame.len() >= 4 && frame[..4] == *RRH1_MAGIC
}

/// A RELAY or DIRECT value: 1..=`max` bytes, each 0x21..=0x7e.
fn text_value_ok(value: &[u8], max: usize) -> bool {
    (1..=max).contains(&value.len()) && value.iter().all(u8::is_ascii_graphic)
}

/// Structural decode (spec §5.1). `None` means: ignore the WHOLE frame (no
/// state change, no close, no reply). Entries may come in any order;
/// unregistered types are skipped. A RELAY_OFFER record never costs the
/// frame: it is checked on its own ([`decode_offer`], §11.2), and one of
/// another version is ignored, a bad one dropped. So is a Phase 4 entry
/// (NAT_CLASS, PEER_SCHEDULE, §13) and a PAIR_SEED (§14): a bad one is
/// dropped alone.
pub fn decode(frame: &[u8]) -> Option<RouteHints> {
    if frame.len() < RRH1_HEADER_LEN
        || frame.len() > RRH1_MAX_LEN
        || !is_rrh1(frame)
        || frame[4] != RRH1_VERSION
    {
        return None;
    }
    let generation = u64::from_be_bytes(frame[5..13].try_into().ok()?);
    let ttl_s = u32::from_be_bytes(frame[13..17].try_into().ok()?);
    if generation == 0 || ttl_s < RRH1_MIN_TTL_S {
        return None;
    }
    let mut h = RouteHints {
        generation,
        ttl_s: ttl_s.min(RRH1_MAX_TTL_S),
        ..Default::default()
    };
    let mut rest = &frame[RRH1_HEADER_LEN..];
    while let Some((&kind, r)) = rest.split_first() {
        let len = usize::from(u16::from_be_bytes(r.get(..2)?.try_into().ok()?));
        let value = r.get(2..2 + len)?;
        rest = &r[2 + len..];
        match kind {
            T_P2P_ID => {
                if h.p2p_id.is_some() {
                    return None;
                }
                h.p2p_id = Some(value.try_into().ok()?);
            }
            T_RELAY => {
                if h.relays.len() == MAX_RELAY_ENTRIES || !text_value_ok(value, RELAY_MAX_LEN) {
                    return None;
                }
                h.relays.push(String::from_utf8(value.to_vec()).ok()?);
            }
            T_DIRECT => {
                if h.direct.len() == MAX_DIRECT || !text_value_ok(value, DIRECT_MAX_LEN) {
                    return None;
                }
                h.direct.push(String::from_utf8(value.to_vec()).ok()?);
            }
            T_LAN_PORT => {
                let port = u16::from_be_bytes(value.try_into().ok()?);
                if h.lan_port.is_some() || port == 0 {
                    return None;
                }
                h.lan_port = Some(port);
            }
            T_CUSTODIAN => {
                if h.custodians.len() == MAX_CUSTODIANS {
                    return None;
                }
                h.custodians.push(value.try_into().ok()?);
            }
            T_CUSTODY_OFFER => {
                let [flags] = <[u8; 1]>::try_from(value).ok()?;
                if h.custody_offer.is_some() {
                    return None;
                }
                h.custody_offer = Some(flags);
            }
            T_CUSTODIAN_TAG => {
                if h.custodian_tags.len() == MAX_CUSTODIANS || value.len() != CUSTODIAN_TAG_LEN {
                    return None;
                }
                let (tag, flags) = value.split_at(32);
                h.custodian_tags.push((tag.try_into().ok()?, flags[0]));
            }
            // Phase 6b (§14): checked on its own, a bad one dropped alone.
            T_PAIR_SEED => match crate::pair_seed::SeedEntry::from_bytes(value) {
                Some(entry) if h.pair_seed.is_none() => h.pair_seed = Some(entry),
                _ => h.dropped_pair_seed += 1,
            },
            T_RELAY_OFFER => match decode_offer(value) {
                // A later record format: ignored, the frame kept (§11.2).
                Err(OfferDecode::Unsupported) => {}
                Ok(offer)
                    if h.offers.len() < MAX_RELAY_OFFERS
                        && h.offers.iter().all(|o| o.relay_pub != offer.relay_pub) =>
                {
                    h.offers.push(offer);
                }
                _ => h.dropped_offers += 1,
            },
            // Phase 4 (§13): checked on its own, a bad one dropped alone.
            T_NAT_CLASS => match NatClass::from_bytes(value) {
                Some(class) if h.nat_class.is_none() => h.nat_class = Some(class),
                _ => h.dropped_phase4 += 1,
            },
            T_PEER_SCHEDULE => match PeerSchedule::from_bytes(value) {
                Some(s) if h.peer_schedule.is_none() => h.peer_schedule = Some(s),
                _ => h.dropped_phase4 += 1,
            },
            // Auto-reach (§13.3): checked one at a time, a bad one dropped
            // alone, at most two distinct addresses.
            T_INET_DIRECT => match InetDirect::from_bytes(value) {
                Some(e)
                    if h.inet.len() < MAX_INET_DIRECT
                        && h.inet.iter().all(|o| o.addr != e.addr) =>
                {
                    h.inet.push(e)
                }
                _ => h.dropped_phase4 += 1,
            },
            // The Tor onion carrier (§15): checked on its own, a bad one
            // dropped alone.
            T_ONION => match crate::onion::OnionBinding::from_bytes(value) {
                Some(b) if h.onion.is_none() => h.onion = Some(b),
                _ => h.dropped_onion += 1,
            },
            _ => {} // unregistered: skipped; RRH1_MAX_LEN bounds it (spec §4)
        }
    }
    Some(h)
}

/// The canonical frame: the header, then the entries in ascending type
/// order, values as given (frame order within a type). Only what [`decode`]
/// accepts is written (at most the per-type count, RELAY and DIRECT within
/// their length and byte rules, no LAN_PORT 0, RELAY_OFFER records that
/// decode back to themselves, one per relay, NAT_CLASS normalized, a
/// PEER_SCHEDULE only when it follows §13.2, a PAIR_SEED only when it
/// follows §14); the sender's snapshot keeps
/// within those limits anyway. The header is written as given: generation
/// and TTL are the sender's job. CUSTODY_OFFER and the CUSTODIAN_TAG flags
/// go out as given too (a sender writes 0 in the bits it does not define).
/// 0x05 CUSTODIAN is written only when `custodians` holds keys, which no
/// Phase 3 sender does (§12.3).
pub fn encode(h: &RouteHints) -> Vec<u8> {
    let mut out = Vec::with_capacity(RRH1_HEADER_LEN + 256);
    out.extend_from_slice(RRH1_MAGIC);
    out.push(RRH1_VERSION);
    out.extend_from_slice(&h.generation.to_be_bytes());
    out.extend_from_slice(&h.ttl_s.to_be_bytes());
    let mut put = |kind: u8, value: &[u8]| {
        out.push(kind);
        // Every value below is at most RELAY_MAX_LEN bytes.
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
    };
    if let Some(id) = &h.p2p_id {
        put(T_P2P_ID, id.as_slice());
    }
    for relay in text_values(&h.relays, RELAY_MAX_LEN, MAX_RELAY_ENTRIES) {
        put(T_RELAY, relay.as_bytes());
    }
    for direct in text_values(&h.direct, DIRECT_MAX_LEN, MAX_DIRECT) {
        put(T_DIRECT, direct.as_bytes());
    }
    if let Some(port) = h.lan_port.filter(|p| *p != 0) {
        put(T_LAN_PORT, port.to_be_bytes().as_slice());
    }
    for custodian in h.custodians.iter().take(MAX_CUSTODIANS) {
        put(T_CUSTODIAN, custodian.as_slice());
    }
    if let Some(flags) = h.custody_offer {
        put(T_CUSTODY_OFFER, &[flags]);
    }
    for (tag, flags) in h.custodian_tags.iter().take(MAX_CUSTODIANS) {
        put(T_CUSTODIAN_TAG, &[tag.as_slice(), &[*flags]].concat());
    }
    if let Some(entry) = h.pair_seed.as_ref().filter(|e| e.valid()) {
        put(T_PAIR_SEED, &entry.to_bytes());
    }
    let mut offered: Vec<&[u8; 32]> = Vec::with_capacity(MAX_RELAY_OFFERS);
    for offer in &h.offers {
        let body = encode_offer(offer);
        if offered.len() < MAX_RELAY_OFFERS
            && !offered.contains(&&offer.relay_pub)
            && decode_offer(&body).as_ref() == Ok(offer)
        {
            offered.push(&offer.relay_pub);
            put(T_RELAY_OFFER, &body);
        }
    }
    if let Some(class) = h.nat_class {
        put(T_NAT_CLASS, &class.to_bytes());
    }
    if let Some(value) = h.peer_schedule.as_ref().and_then(PeerSchedule::to_bytes) {
        put(T_PEER_SCHEDULE, &value);
    }
    let mut inet: Vec<std::net::SocketAddr> = Vec::new();
    for e in &h.inet {
        let value = e.to_bytes();
        if inet.len() < MAX_INET_DIRECT
            && !inet.contains(&e.addr)
            && InetDirect::from_bytes(&value).as_ref() == Some(e)
        {
            inet.push(e.addr);
            put(T_INET_DIRECT, &value);
        }
    }
    if let Some(binding) = &h.onion {
        put(T_ONION, &binding.to_bytes());
    }
    out
}

/// The first `max` of `values` that [`decode`] accepts as RELAY or DIRECT.
fn text_values(values: &[String], max_len: usize, max: usize) -> impl Iterator<Item = &String> {
    values
        .iter()
        .filter(move |v| text_value_ok(v.as_bytes(), max_len))
        .take(max)
}

/// The CUSTODIAN_TAG of `custodian` in a frame from `sender` to `receiver`
/// (spec §12): SHA-256(domain || sender || receiver || custodian), all three
/// contact-book Ed25519 device keys. Pair-blinded: only a receiver that
/// already knows `custodian` recognises it, and the same custodian gets an
/// unrelated tag in every other pair and direction.
pub fn custodian_tag(sender: &[u8; 32], receiver: &[u8; 32], custodian: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(CUSTODIAN_TAG_DOMAIN);
    h.update(sender);
    h.update(receiver);
    h.update(custodian);
    h.finalize().into()
}

// ── Receiver rules (spec §5.2) ──────────────────────────────────────────────

/// The link an RRH1 arrived on, as the receiver authenticated it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HintLink<'a> {
    pub carrier: OutboxCarrier,
    /// The peer's IP on this link (LAN and Internet direct; `None` on p2p).
    pub peer_ip: Option<IpAddr>,
    /// The zone of an IPv6 link-local `peer_ip` on a LAN link: the interface
    /// of this computer the link came in on (`en0`, or its number). The
    /// learned LAN part keeps it (Phase 3 P3.4, [`crate::lan_seen::ScopedIp`]).
    pub peer_zone: Option<&'a str>,
    /// p2p links: the libp2p PeerId of the connection.
    pub link_peer_id: Option<&'a str>,
    /// The PeerId the receiver's contact book holds for the sender, if any.
    pub book_peer_id: Option<&'a str>,
    /// The sender is a verified (pinned) contact.
    pub pinned: bool,
    /// The sender's Raven identity key (the link's peer).
    pub sender: [u8; 32],
    /// The receiver's own Raven identity key.
    pub local: [u8; 32],
    /// The receiver's own libp2p key (its profile PeerId's): never a relay
    /// it is offered (§11.3).
    pub local_p2p: [u8; 32],
    /// The key of the receiver's own friend relay, when it has one: never a
    /// relay it is offered either.
    pub local_relay: Option<[u8; 32]>,
    /// Debug lab `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1`
    /// ([`crate::p2p_local_candidates_enabled`]): loopback and private DIRECT,
    /// RELAY and offered relay addresses are kept as if global. Inert in
    /// release builds.
    pub lab_local: bool,
    /// Debug lab ([`lab_loopback_relays`]): route hints run under their
    /// debug switch, as in every one-machine harness, whose relays all
    /// listen on loopback: a loopback RELAY is kept. Inert in release builds.
    pub lab_loopback: bool,
}

/// Debug builds with route hints on through their debug switch
/// `RAVEN_LAB_ROUTE_HINTS=1` (one-machine harnesses: every relay listens on
/// loopback): a RELAY at a loopback address is kept
/// ([`HintLink::lab_loopback`]). Release builds never read the variable, so
/// there a RELAY must be globally routable (spec §5.2).
pub fn lab_loopback_relays() -> bool {
    crate::p2p_gate::lab_flag(cfg!(debug_assertions), || {
        std::env::var("RAVEN_LAB_ROUTE_HINTS").ok()
    })
}

impl HintLink<'static> {
    /// A fixed link for the fuzz target and the vectors (not test-only: the
    /// fuzz crate's library is compiled outside `cfg(test)`). The sender is
    /// seed 0x51, whose libp2p PeerId is the book's and, on p2p, the link's;
    /// the receiver is seed 0x52 (its libp2p key from that seed), with no
    /// friend relay. The peer IP is 192.168.7.20 on LAN, 11.0.3.9 on Internet
    /// and none on p2p, with no zone. `lab_local` and `lab_loopback` are off.
    #[doc(hidden)]
    pub fn fixture(carrier: OutboxCarrier, pinned: bool) -> Self {
        type Fixture = ([u8; 32], [u8; 32], [u8; 32], String);
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        let (sender, local, local_p2p, peer_id) = FIXTURE.get_or_init(|| {
            let sender = Identity::from_seed(&[0x51; 32]);
            let local = Identity::from_seed(&[0x52; 32]);
            (
                sender.public_key_bytes(),
                local.public_key_bytes(),
                libp2p_ed25519_public(&local),
                crate::p2p_route::local_peer_id(&sender),
            )
        });
        let peer_ip = match carrier {
            OutboxCarrier::Lan => Some(IpAddr::from([192, 168, 7, 20])),
            OutboxCarrier::Internet => Some(IpAddr::from([11, 0, 3, 9])),
            OutboxCarrier::P2p | OutboxCarrier::Nearby | OutboxCarrier::Onion => None,
        };
        Self {
            carrier,
            peer_ip,
            peer_zone: None,
            link_peer_id: (carrier == OutboxCarrier::P2p).then_some(peer_id.as_str()),
            book_peer_id: Some(peer_id.as_str()),
            pinned,
            sender: *sender,
            local: *local,
            local_p2p: *local_p2p,
            local_relay: None,
            lab_local: false,
            lab_loopback: false,
        }
    }
}

/// What a receiver may use from one RRH1 ([`validate`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidHints {
    pub generation: u64,
    /// Clamped to [`RRH1_MIN_TTL_S`]..=[`RRH1_MAX_TTL_S`].
    pub ttl_s: u32,
    /// The sender's PeerId (canonical text), when its P2P_ID passed.
    pub peer_id: Option<String>,
    /// Relay addresses: at most [`MAX_RELAYS`] distinct relays, at most
    /// [`MAX_ADDRS_PER_RELAY`] addresses each, in frame order.
    pub relays: Vec<ViaAddr>,
    /// Global DIRECT addresses, each ending in `/p2p/<peer_id>`.
    pub direct: Vec<ViaAddr>,
    /// Same-LAN DIRECT addresses (LAN links only), each ending in
    /// `/p2p/<peer_id>`.
    pub local_direct: Vec<ViaAddr>,
    pub lan_port: Option<u16>,
    /// Phase 2's plain custodian keys (0x05, receive-only; §12.3).
    pub custodians: Vec<[u8; 32]>,
    /// CUSTODY_OFFER with the unknown bits cleared ([`CUSTODY_OFFER_KNOWN`]):
    /// present means the sender holds sealed mail for its verified contacts
    /// (§12), even when no bit is left.
    pub custody_offer: Option<u8>,
    /// CUSTODIAN_TAG values (§12.1): never all-zero, no duplicates, at most
    /// [`MAX_CUSTODIANS`], in frame order.
    pub custodian_tags: Vec<[u8; 32]>,
    /// The flags of each of [`Self::custodian_tags`] (same index), masked to
    /// [`CUSTODIAN_TAG_KNOWN_FLAGS`] (bit 0 HANDOFF_INBOX; all 0 in Phase 3).
    pub custodian_tag_flags: Vec<u8>,
    /// Relays the sender offers this receiver (§11.3): at most
    /// [`MAX_RELAY_OFFERS`], one per relay, each with only the addresses the
    /// receiver may dial (at least one), in frame order.
    pub offers: Vec<RelayOfferRecord>,
    /// The sender's NAT mapping classes (§13.1): from a pinned sender whose
    /// P2P_ID passed only (they describe that libp2p host).
    pub nat_class: Option<NatClass>,
    /// The sender's PeerId rotation schedule (§13.2): from a pinned sender
    /// only, whatever its P2P_ID (it is kept under the link's authenticated
    /// key, never under a PeerId).
    pub peer_schedule: Option<PeerSchedule>,
    /// The sender's pair seed (§14): from a pinned sender only, on any link.
    pub pair_seed: Option<crate::pair_seed::SeedEntry>,
    /// The public address of the sender's Internet direct listener (§13.3):
    /// from a pinned sender only, a globally routable IP (any under
    /// `lab_local`), at most [`MAX_INET_DIRECT`].
    pub inet: Vec<InetDirect>,
    /// The sender's onion binding (§15): from a pinned sender only, on any
    /// link, and only when the sender's own key signed it
    /// ([`crate::onion::OnionBinding::verify`]).
    pub onion: Option<crate::onion::OnionBinding>,
    /// Entries the frame carried that were dropped (counts-only logs).
    pub dropped: u32,
}

/// Semantic validation (spec §5.2, and §11.3 for RELAY_OFFER), pure. Each
/// entry that fails is dropped and the rest is kept:
/// - an unpinned sender: only LAN_PORT, and only on a LAN link from a
///   local-network address (owner decision 1); LAN_PORT is a per-link field
///   and is kept on LAN links only, for every sender (so an unpinned
///   sender's CUSTODY_OFFER and CUSTODIAN_TAG are dropped);
/// - P2P_ID must be an Ed25519 PeerId, equal to the connection's PeerId on a
///   p2p link and to the book's when the book has one; otherwise P2P_ID and
///   every RELAY and DIRECT go;
/// - RELAY: the strict `via=` grammar (never a circuit), not naming the
///   sender's own PeerId, and an IP literal host only when it is globally
///   routable (or any, under `lab_local`; a loopback one under
///   `lab_loopback`): a contact never makes this node dial loopback or its
///   local networks; at most [`MAX_RELAYS`] relays of
///   [`MAX_ADDRS_PER_RELAY`] addresses each, in frame order;
/// - DIRECT: an IP literal that, with `/p2p/<peer_id>` appended, passes the
///   grammar. Global ones (or any, under `lab_local`) are kept, at most
///   [`MAX_GLOBAL_DIRECT`]; a non-global one only on a LAN link, when it is a
///   local-network address in the /24 (IPv4) or /64 (IPv6) of the link's peer
///   IP, at most [`MAX_LOCAL_DIRECT`];
/// - CUSTODIAN: never all-zero, the receiver's or the sender's own key;
/// - CUSTODY_OFFER (§12): its unknown bits cleared ([`CUSTODY_OFFER_KNOWN`]);
/// - CUSTODIAN_TAG (§12): never all-zero; its flags masked to
///   [`CUSTODIAN_TAG_KNOWN_FLAGS`]; a duplicate is merged into the first
///   (flags OR-ed);
/// - RELAY_OFFER: never naming the sender's own libp2p key, the receiver's
///   or the receiver's friend relay's; only the addresses
///   [`RelayOfferRecord::usable_addrs`] keeps, and an offer left with none
///   is dropped; at most [`MAX_RELAY_OFFERS`], one per relay;
/// - NAT_CLASS (§13.1): from a sender whose P2P_ID passed only;
/// - PEER_SCHEDULE (§13.2): from a pinned sender, whatever its P2P_ID;
/// - INET_DIRECT (§13.3): from a pinned sender, a globally routable IP only
///   (any under `lab_local`);
/// - PAIR_SEED (§14): from a pinned sender, on any link;
/// - ONION (§15): from a pinned sender, on any link, and only a binding the
///   sender's own key (the link's authenticated one) signed.
///
/// Duplicates are dropped too.
pub fn validate(h: &RouteHints, link: &HintLink) -> ValidHints {
    let mut v = ValidHints {
        generation: h.generation,
        ttl_s: h.ttl_s.clamp(RRH1_MIN_TTL_S, RRH1_MAX_TTL_S),
        ..Default::default()
    };
    let from_local_network = link.peer_ip.is_some_and(is_local_network_ip);
    if link.carrier == OutboxCarrier::Lan && (link.pinned || from_local_network) {
        v.lan_port = h.lan_port.filter(|p| *p != 0);
    }
    if link.pinned {
        if let Some(peer_id) = sender_peer_id(h, link) {
            keep_relays(&mut v, h, &peer_id, link);
            keep_direct(&mut v, h, &peer_id, link);
            v.nat_class = h.nat_class.map(NatClass::normalized);
            v.peer_id = Some(peer_id);
        }
        // A frame that did not come through decode is held to it here.
        v.peer_schedule = h.peer_schedule.clone().filter(PeerSchedule::valid);
        v.pair_seed = h
            .pair_seed
            .clone()
            .filter(crate::pair_seed::SeedEntry::valid);
        // Never an unsigned onion address, never one signed by anyone else.
        v.onion = h
            .onion
            .filter(|b| b.verify(&link.sender, crate::onion::now_s()));
        for key in &h.custodians {
            if v.custodians.len() < MAX_CUSTODIANS
                && *key != [0; 32]
                && *key != link.local
                && *key != link.sender
                && !v.custodians.contains(key)
            {
                v.custodians.push(*key);
            }
        }
        v.custody_offer = h.custody_offer.map(|flags| flags & CUSTODY_OFFER_KNOWN);
        for e in &h.inet {
            let e = InetDirect {
                flags: e.flags & INET_FLAGS_KNOWN,
                ..*e
            };
            if v.inet.len() < MAX_INET_DIRECT
                && (is_global_ip(e.addr.ip()) || link.lab_local)
                && v.inet.iter().all(|o| o.addr != e.addr)
            {
                v.inet.push(e);
            }
        }
        for (tag, flags) in &h.custodian_tags {
            let flags = flags & CUSTODIAN_TAG_KNOWN_FLAGS;
            if let Some(i) = v.custodian_tags.iter().position(|t| t == tag) {
                v.custodian_tag_flags[i] |= flags;
            } else if v.custodian_tags.len() < MAX_CUSTODIANS && *tag != [0; 32] {
                v.custodian_tags.push(*tag);
                v.custodian_tag_flags.push(flags);
            }
        }
        keep_offers(&mut v, h, link);
    }
    let carried = usize::from(h.p2p_id.is_some())
        + h.relays.len()
        + h.direct.len()
        + usize::from(h.lan_port.is_some())
        + h.custodians.len()
        + usize::from(h.custody_offer.is_some())
        + h.custodian_tags.len()
        + h.offers.len()
        + usize::from(h.nat_class.is_some())
        + usize::from(h.peer_schedule.is_some())
        + usize::from(h.pair_seed.is_some())
        + h.inet.len()
        + usize::from(h.onion.is_some());
    let kept = usize::from(v.peer_id.is_some())
        + v.relays.len()
        + v.direct.len()
        + v.local_direct.len()
        + usize::from(v.lan_port.is_some())
        + v.custodians.len()
        + usize::from(v.custody_offer.is_some())
        + v.custodian_tags.len()
        + v.offers.len()
        + usize::from(v.nat_class.is_some())
        + usize::from(v.peer_schedule.is_some())
        + usize::from(v.pair_seed.is_some())
        + v.inet.len()
        + usize::from(v.onion.is_some());
    v.dropped = u32::try_from(carried.saturating_sub(kept)).unwrap_or(u32::MAX);
    v
}

/// RELAY_OFFER from a pinned sender (§11.3). An offer is dropped when its
/// relay key is the sender's own libp2p key (the key of its P2P_ID, of the
/// PeerId the book holds for it or, on a p2p link, of the connection's
/// PeerId: a relay under the sender's profile PeerId), the receiver's own
/// ([`HintLink::local_p2p`]) or that of the receiver's friend relay
/// ([`HintLink::local_relay`]). Each kept record names only the addresses
/// [`RelayOfferRecord::usable_addrs`] admits; one left with none is
/// dropped. At most [`MAX_RELAY_OFFERS`], one per relay, in frame order.
fn keep_offers(v: &mut ValidHints, h: &RouteHints, link: &HintLink) {
    let sender_p2p = h.p2p_id.as_ref().and_then(|id| peer_id_from_bytes(id).ok());
    let refused: Vec<[u8; 32]> = sender_p2p
        .as_deref()
        .into_iter()
        .chain(link.book_peer_id)
        .chain(link.link_peer_id)
        .filter_map(|peer_id| parse_peer_id(peer_id).ok())
        .chain([link.local_p2p])
        .chain(link.local_relay)
        .collect();
    for offer in &h.offers {
        if v.offers.len() == MAX_RELAY_OFFERS {
            break;
        }
        if refused.contains(&offer.relay_pub)
            || v.offers.iter().any(|o| o.relay_pub == offer.relay_pub)
            // A record that did not come through decode is held to it here.
            || decode_offer(&encode_offer(offer)).as_ref() != Ok(offer)
        {
            continue;
        }
        let addrs: Vec<String> = offer
            .usable_addrs(link.lab_local)
            .into_iter()
            .map(str::to_owned)
            .collect();
        if !addrs.is_empty() {
            v.offers.push(RelayOfferRecord {
                addrs,
                ..offer.clone()
            });
        }
    }
}

/// The sender's PeerId, when P2P_ID is an Ed25519 PeerId that matches the
/// p2p connection (p2p links) and the contact book (when it has one). While
/// this node's PeerId rotation gate is live (Phase 4, §13.2), a P2P_ID the
/// book does not hold is kept when the same frame's PEER_SCHEDULE says the
/// sender uses epoch keys and names it: a rotating contact's P2P_ID is the
/// PeerId of its current epoch, not the one its card gave.
fn sender_peer_id(h: &RouteHints, link: &HintLink) -> Option<String> {
    sender_peer_id_with(h, link, crate::portmap_gate::peer_rotation_live_enabled())
}

/// [`sender_peer_id`] with the PeerId rotation gate as an argument.
fn sender_peer_id_with(h: &RouteHints, link: &HintLink, rotation_live: bool) -> Option<String> {
    let peer_id = peer_id_from_bytes(h.p2p_id.as_ref()?).ok()?;
    let names_it = |other: Option<&str>| {
        other
            .and_then(|o| normalize_peer_id(o).ok())
            .is_some_and(|o| o == peer_id)
    };
    if link.carrier == OutboxCarrier::P2p && !names_it(link.link_peer_id) {
        return None;
    }
    if link.book_peer_id.is_some()
        && !names_it(link.book_peer_id)
        && !(rotation_live && scheduled(h, &peer_id))
    {
        return None;
    }
    Some(peer_id)
}

/// `peer_id` is one of the epoch PeerIds of the frame's own valid
/// PEER_SCHEDULE, and that schedule says its sender uses epoch keys (its
/// rotation is on, or on and postponed).
fn scheduled(h: &RouteHints, peer_id: &str) -> bool {
    h.peer_schedule
        .as_ref()
        .filter(|s| s.valid() && (s.rotating() || s.postponed()))
        .is_some_and(|s| {
            s.entries
                .iter()
                .any(|(_, key)| crate::p2p_route::peer_id_from_ed25519_public(key) == peer_id)
        })
}

fn keep_relays(v: &mut ValidHints, h: &RouteHints, sender_peer_id: &str, link: &HintLink) {
    let mut relay_ids: Vec<String> = Vec::new();
    for text in &h.relays {
        // parse_via refuses every circuit.
        let Ok(via) = parse_via(text) else {
            continue;
        };
        if via.peer_id == sender_peer_id
            || v.relays.contains(&via)
            || !relay_host_usable(&via, link.lab_local, link.lab_loopback)
        {
            continue;
        }
        let addrs = v.relays.iter().filter(|r| r.peer_id == via.peer_id).count();
        if addrs == 0 {
            if relay_ids.len() == MAX_RELAYS {
                continue;
            }
            relay_ids.push(via.peer_id.clone());
        } else if addrs == MAX_ADDRS_PER_RELAY {
            continue;
        }
        v.relays.push(via);
    }
}

fn keep_direct(v: &mut ValidHints, h: &RouteHints, sender_peer_id: &str, link: &HintLink) {
    for text in &h.direct {
        // A DIRECT value with its own `/p2p` (or anything after the
        // transport) fails here.
        let Ok(via) = parse_via(&format!("{text}/p2p/{sender_peer_id}")) else {
            continue;
        };
        // §5.2: the plain transport only. Endpoints never listen on WSS
        // (RWS1 §2.3), and a WSS form would be dialled through the HTTPS
        // proxy with a name the sender chose (review A-2).
        if via.is_wss() {
            continue;
        }
        let Some(ip) = host_ip(&via.text) else {
            continue; // a DNS name: IP literals only
        };
        if v.direct.contains(&via) || v.local_direct.contains(&via) {
            continue;
        }
        if is_global_ip(ip) || link.lab_local {
            if v.direct.len() < MAX_GLOBAL_DIRECT {
                v.direct.push(via);
            }
        } else if link.carrier == OutboxCarrier::Lan
            && is_local_network_ip(ip)
            && link.peer_ip.is_some_and(|peer| same_subnet(ip, peer))
            && v.local_direct.len() < MAX_LOCAL_DIRECT
        {
            v.local_direct.push(via);
        }
    }
}

/// A RELAY this node may dial (§5.2): a DNS name, or an IP literal that is
/// globally routable unicast ([`is_global_ip`]: an IPv4-mapped, NAT64 or
/// 6to4 address by the IPv4 address inside). `lab_local` admits any IP,
/// `lab_loopback` a loopback one ([`HintLink`]). Also for snapshots stored
/// before this rule ([`crate::learned_routes`]).
pub fn relay_host_usable(via: &ViaAddr, lab_local: bool, lab_loopback: bool) -> bool {
    match host_ip(&via.text) {
        None => true,
        Some(ip) => {
            is_global_ip(ip) || lab_local || (lab_loopback && ip.to_canonical().is_loopback())
        }
    }
}

/// The IP literal of a parsed `/ip4/…` or `/ip6/…` address (`None` for a
/// DNS name).
fn host_ip(text: &str) -> Option<IpAddr> {
    let mut parts = text.split('/').skip(1);
    match (parts.next(), parts.next()) {
        (Some("ip4" | "ip6"), Some(host)) => host.parse().ok(),
        _ => None,
    }
}

/// The same /24 (IPv4) or /64 (IPv6); an IPv4-mapped address counts as its
/// IPv4 address.
fn same_subnet(a: IpAddr, b: IpAddr) -> bool {
    match (a.to_canonical(), b.to_canonical()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.segments()[..4] == b.segments()[..4],
        _ => false,
    }
}

// ── Sender side (spec §6) ───────────────────────────────────────────────────

/// SHA-256 (hex) of what a sender's snapshot is made from, each part length
/// prefixed. raven-node keeps one for the inputs every verified contact
/// shares and one per contact, and moves its generation exactly when one of
/// them changes ("same generation, same content").
pub fn inputs_digest(parts: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    hex::encode(h.finalize())
}

/// HKDF-SHA256 salt and info of [`NetworksKey`] (its own salt: never the
/// noise pin key's or the Noise static's).
const NETWORKS_KEY_SALT: &[u8] = b"rvn1/route-hints-networks-key/v1";
const NETWORKS_KEY_INFO: &[u8] = b"hmac-sha256-key";

/// The key of the digest raven-node keeps of this computer's own networks in
/// its route hints state (a wildcard listener's `lan` input): HKDF-SHA256 of
/// the identity seed, wiped on drop, never stored. A plain digest of one
/// IPv4 network (`192.168.1.30/24`) is brute-forced from a copy of the data
/// dir over the private ranges in seconds and names where this computer
/// was; keyed, it cannot be recomputed without the seed (review FU-2, like
/// the noise pins' [`crate::lan_noise_pin::PinKey`]).
pub struct NetworksKey(zeroize::Zeroizing<[u8; 32]>);

impl NetworksKey {
    /// From `identity`'s seed: the same profile gets the same key after a
    /// restart, so the same networks read back as no move.
    pub fn derive(identity: &Identity) -> Self {
        use zeroize::Zeroize;
        let mut seed = identity.seed_bytes();
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(NETWORKS_KEY_SALT), &seed);
        seed.zeroize();
        let mut okm = zeroize::Zeroizing::new([0u8; 32]);
        hk.expand(NETWORKS_KEY_INFO, okm.as_mut_slice())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self(okm)
    }
}

impl std::fmt::Debug for NetworksKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworksKey(..)")
    }
}

/// [`inputs_digest`] keyed with `key`: HMAC-SHA256 (hex) over the same
/// length-prefixed parts.
pub fn keyed_inputs_digest(key: &NetworksKey, parts: &[&[u8]]) -> String {
    use hmac::Mac;
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key.0.as_slice()).expect("hmac takes any key");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p_route::{libp2p_ed25519_public, local_peer_id, peer_id_bytes};
    use rand::{Rng, RngCore};
    use serde_json::json;

    pub(super) const G: u64 = 1_760_000_000_123;
    pub(super) const SENDER: u8 = 0x51;

    pub(super) fn pid(seed: u8) -> String {
        local_peer_id(&Identity::from_seed(&[seed; 32]))
    }

    fn key(seed: u8) -> [u8; 32] {
        Identity::from_seed(&[seed; 32]).public_key_bytes()
    }

    /// A frame with the given header and raw entries, in the given order.
    pub(super) fn raw(generation: u64, ttl_s: u32, entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = RRH1_MAGIC.to_vec();
        out.push(RRH1_VERSION);
        out.extend_from_slice(&generation.to_be_bytes());
        out.extend_from_slice(&ttl_s.to_be_bytes());
        for (kind, value) in entries {
            out.push(*kind);
            out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    /// The entries of a well-formed frame, in frame order.
    pub(super) fn entries(frame: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut rest = &frame[RRH1_HEADER_LEN..];
        while let Some((&kind, r)) = rest.split_first() {
            let len = usize::from(u16::from_be_bytes([r[0], r[1]]));
            out.push((kind, r[2..2 + len].to_vec()));
            rest = &r[2 + len..];
        }
        out
    }

    fn relay_addr(host: &str, seed: u8) -> String {
        format!("{host}/p2p/{}", pid(seed))
    }

    fn relay_entry(n: u8) -> (u8, Vec<u8>) {
        (
            T_RELAY,
            relay_addr(&format!("/ip4/11.0.2.{n}/tcp/7423"), 0x61).into_bytes(),
        )
    }

    fn direct_entry(n: u8) -> (u8, Vec<u8>) {
        (T_DIRECT, format!("/ip4/11.0.3.{n}/tcp/7423").into_bytes())
    }

    fn lan_entry(value: &[u8]) -> (u8, Vec<u8>) {
        (T_LAN_PORT, value.to_vec())
    }

    fn custodian_entry(len: usize) -> (u8, Vec<u8>) {
        (T_CUSTODIAN, vec![0x77; len])
    }

    fn offer_entry(value: &[u8]) -> (u8, Vec<u8>) {
        (T_CUSTODY_OFFER, value.to_vec())
    }

    fn tag_entry(len: usize) -> (u8, Vec<u8>) {
        (T_CUSTODIAN_TAG, vec![0x7c; len])
    }

    /// The custodian seeds of the custody vectors: friends C1 and C2.
    const CUSTODIANS: [u8; 2] = [0x71, 0x72];

    /// The tag of custodian `seed` in a frame from the vector sender to the
    /// vector receiver (seeds 0x51 and 0x52, [`HintLink::fixture`]).
    fn tag_of(seed: u8) -> [u8; 32] {
        custodian_tag(&key(SENDER), &key(0x52), &key(seed))
    }

    /// The custody frame (`rrh1_custody_001.json`, §12): LAN_PORT 7531,
    /// CUSTODY_OFFER WAN | REACHABLE and two CUSTODIAN_TAGs, the first with
    /// flags 0x00 and the second with 0x03 (Phase 5's bits, which a Phase 3
    /// receiver clears).
    fn custody() -> RouteHints {
        RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            lan_port: Some(7531),
            custody_offer: Some(0x03),
            custodian_tags: vec![(tag_of(CUSTODIANS[0]), 0x00), (tag_of(CUSTODIANS[1]), 0x03)],
            ..Default::default()
        }
    }

    /// The flag bits a Phase 3 receiver knew: none (§4).
    const PHASE3_CUSTODIAN_TAG_KNOWN_FLAGS: u8 = 0;

    /// The HANDOFF_INBOX frame (`rrh1_custody_handoff_inbox_001.json`): two
    /// CUSTODIAN_TAGs, the first with flags 0x01 (HANDOFF_INBOX), the second
    /// with 0xfe (every bit this revision does not define).
    fn handoff_inbox() -> RouteHints {
        RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            custodian_tags: vec![(tag_of(CUSTODIANS[0]), 0x01), (tag_of(CUSTODIANS[1]), 0xfe)],
            ..Default::default()
        }
    }

    /// An old reader ignores unknown flag bits (§4): a Phase 3 receiver
    /// (no bit defined) and this one keep every tag of a frame whose flags
    /// carry any bits, whatever they are, and drop nothing; this one keeps
    /// HANDOFF_INBOX only.
    #[test]
    fn an_old_reader_ignores_unknown_flag_bits() {
        let link = HintLink::fixture(OutboxCarrier::P2p, true);
        let h = decode(&encode(&handoff_inbox())).unwrap();
        let v = validate(&h, &link);
        assert_eq!(
            v.custodian_tags,
            [tag_of(CUSTODIANS[0]), tag_of(CUSTODIANS[1])]
        );
        assert_eq!(v.custodian_tag_flags, [CUSTODIAN_FLAG_HANDOFF_INBOX, 0]);
        assert_eq!(v.dropped, 0);
        // The frame is never ignored for its flags: every flags byte decodes
        // and both tags are kept, each with the bits its reader knows.
        for flags in 0..=u8::MAX {
            let mut one = handoff_inbox();
            one.custodian_tags[0].1 = flags;
            let back = decode(&encode(&one)).unwrap();
            assert_eq!(back.custodian_tags[0].1, flags);
            let v = validate(&back, &link);
            assert_eq!(v.custodian_tags.len(), 2, "{flags:#04x}");
            assert_eq!(v.custodian_tag_flags[0], flags & CUSTODIAN_TAG_KNOWN_FLAGS);
            assert_eq!(flags & PHASE3_CUSTODIAN_TAG_KNOWN_FLAGS, 0);
            assert_eq!(v.dropped, 0);
        }
    }

    /// Every entry type of the first draft (the rrh1_full vector): relay R1
    /// at two addresses of one reservation (TCP 7423 and TCP 443) and relay
    /// R2 at one, one global IPv6 QUIC and one global IPv4 TCP address, LAN
    /// port 7531, one custodian. No relay offer.
    pub(super) fn full() -> RouteHints {
        RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            p2p_id: Some(peer_id_bytes(&pid(SENDER)).unwrap()),
            relays: vec![
                relay_addr("/ip4/11.0.2.1/tcp/7423", 0x61),
                relay_addr("/ip4/11.0.2.1/tcp/443", 0x61),
                relay_addr("/dns4/relay.example.org/tcp/443", 0x62),
            ],
            direct: vec![
                "/ip6/2c0f:fff0:a::5/udp/7423/quic-v1".into(),
                "/ip4/11.0.3.5/tcp/7423".into(),
            ],
            lan_port: Some(7531),
            custodians: vec![[0x77; 32]],
            ..Default::default()
        }
    }

    /// The LAN-scope frame (an unverified LAN contact's): LAN_PORT only.
    fn lan_scope() -> RouteHints {
        RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            lan_port: Some(7531),
            ..Default::default()
        }
    }

    /// §5.1: frames a receiver ignores whole, each with the rule it breaks
    /// (the table of `rrh1_ignored_001.json`).
    fn ignored_frames() -> Vec<(&'static str, Vec<u8>, &'static str)> {
        const LENGTH: &str = "length out of bounds (17..=4096)";
        const TRUNCATED: &str = "a truncated entry";
        const ENTRY_LEN: &str = "a registered type with a length out of range";
        const COUNT: &str = "more entries of one type than its max";
        const BYTE: &str = "a RELAY or DIRECT byte outside 0x21..0x7e";
        let p2p = (T_P2P_ID, peer_id_bytes(&pid(SENDER)).unwrap().to_vec());
        let ttl = RRH1_DEFAULT_TTL_S;
        let good = raw(G, ttl, &[]);
        let with = |extra: &[u8]| [good.as_slice(), extra].concat();
        let mut truncated = raw(G, ttl, &[direct_entry(1)]);
        truncated.pop();
        vec![
            (
                "bad magic",
                [b"RRH2".as_slice(), &good[4..]].concat(),
                "bad magic",
            ),
            (
                "version 2",
                [&good[..4], &[2u8][..], &good[5..]].concat(),
                "version is not 1",
            ),
            ("len 16", good[..16].to_vec(), LENGTH),
            (
                "len 4097",
                raw(
                    G,
                    ttl,
                    &[(0x7f, vec![0; RRH1_MAX_LEN - RRH1_HEADER_LEN - 2])],
                ),
                LENGTH,
            ),
            ("generation 0", raw(0, ttl, &[]), "generation is 0"),
            ("ttl 59", raw(G, 59, &[]), "ttl_s below 60"),
            ("truncated entry", truncated, TRUNCATED),
            (
                "truncated entry length",
                with(&[T_DIRECT, 0x00][..]),
                TRUNCATED,
            ),
            ("an entry type alone", with(&[T_RELAY][..]), TRUNCATED),
            (
                "a second P2P_ID",
                raw(G, ttl, &[p2p.clone(), p2p.clone()]),
                COUNT,
            ),
            (
                "P2P_ID len 37",
                raw(G, ttl, &[(T_P2P_ID, p2p.1[..37].to_vec())]),
                ENTRY_LEN,
            ),
            (
                "5 RELAY",
                raw(G, ttl, &(1..=5).map(relay_entry).collect::<Vec<_>>()),
                COUNT,
            ),
            (
                "RELAY len 0",
                raw(G, ttl, &[(T_RELAY, Vec::new())]),
                ENTRY_LEN,
            ),
            (
                "RELAY len 301",
                raw(G, ttl, &[(T_RELAY, vec![b'r'; 301])]),
                ENTRY_LEN,
            ),
            (
                "7 DIRECT",
                raw(G, ttl, &(1..=7).map(direct_entry).collect::<Vec<_>>()),
                COUNT,
            ),
            (
                "DIRECT len 0",
                raw(G, ttl, &[(T_DIRECT, Vec::new())]),
                ENTRY_LEN,
            ),
            (
                "DIRECT len 121",
                raw(G, ttl, &[(T_DIRECT, vec![b'd'; 121])]),
                ENTRY_LEN,
            ),
            (
                "LAN_PORT len 3",
                raw(G, ttl, &[lan_entry(&[0x1d, 0x6b, 0])]),
                ENTRY_LEN,
            ),
            (
                "LAN_PORT len 1",
                raw(G, ttl, &[lan_entry(&[0x1d])]),
                ENTRY_LEN,
            ),
            (
                "LAN_PORT 0",
                raw(G, ttl, &[lan_entry(&[0, 0])]),
                "LAN_PORT = 0",
            ),
            (
                "a second LAN_PORT",
                raw(
                    G,
                    ttl,
                    &[lan_entry(&[0x1d, 0x6b]), lan_entry(&[0x1d, 0x6c])],
                ),
                COUNT,
            ),
            (
                "CUSTODIAN len 31",
                raw(G, ttl, &[custodian_entry(31)]),
                ENTRY_LEN,
            ),
            (
                "CUSTODIAN len 33",
                raw(G, ttl, &[custodian_entry(33)]),
                ENTRY_LEN,
            ),
            (
                "3 CUSTODIAN",
                raw(
                    G,
                    ttl,
                    &[
                        custodian_entry(32),
                        custodian_entry(32),
                        custodian_entry(32),
                    ],
                ),
                COUNT,
            ),
            (
                "a non-graphic byte in DIRECT",
                raw(G, ttl, &[(T_DIRECT, b"/ip4/11.0.3.5/tcp/7423 ".to_vec())]),
                BYTE,
            ),
            (
                "a DEL byte in RELAY",
                raw(G, ttl, &[(T_RELAY, b"/dns4/relay\x7f".to_vec())]),
                BYTE,
            ),
            (
                "a non-ASCII byte in RELAY",
                raw(G, ttl, &[(T_RELAY, "/dns4/rélay".as_bytes().to_vec())]),
                BYTE,
            ),
            (
                "CUSTODY_OFFER len 0",
                raw(G, ttl, &[offer_entry(&[])]),
                ENTRY_LEN,
            ),
            (
                "CUSTODY_OFFER len 2",
                raw(G, ttl, &[offer_entry(&[0x03, 0x00])]),
                ENTRY_LEN,
            ),
            (
                "a second CUSTODY_OFFER",
                raw(G, ttl, &[offer_entry(&[0x01]), offer_entry(&[0x02])]),
                COUNT,
            ),
            (
                "CUSTODIAN_TAG len 32",
                raw(G, ttl, &[tag_entry(32)]),
                ENTRY_LEN,
            ),
            (
                "CUSTODIAN_TAG len 34",
                raw(G, ttl, &[tag_entry(34)]),
                ENTRY_LEN,
            ),
            (
                "3 CUSTODIAN_TAG",
                raw(G, ttl, &[tag_entry(33), tag_entry(33), tag_entry(33)]),
                COUNT,
            ),
        ]
    }

    /// RLX1 payloads and the LINK_CAPS a responder reads from each; 0 means
    /// the whole payload is ignored (the table of `rlx1_caps_001.json`).
    fn rlx1_rows() -> Vec<(&'static str, Vec<u8>, u32)> {
        let caps = rlx1_payload(0x100);
        let with = |extra: &[u8]| [caps.as_slice(), extra].concat();
        let header = b"RLX1\x01".to_vec();
        let after_header = |entries: &[u8]| [header.as_slice(), entries].concat();
        // An unknown entry that fills the payload to `total` bytes.
        let filled = |total: usize| {
            let len = total - caps.len() - 2;
            let mut entry = vec![0x7f, u8::try_from(len).unwrap()];
            entry.resize(2 + len, 0);
            with(&entry)
        };
        vec![
            ("empty", Vec::new(), 0),
            ("LINK_CAPS", caps.clone(), 0x100),
            ("header only", header.clone(), 0),
            (
                "unknown entries are skipped",
                with(&[0x7f, 3, 1, 2, 3][..]),
                0x100,
            ),
            (
                "an unknown entry first",
                after_header(&[&[0x02, 0][..], &caps[5..]].concat()),
                0x100,
            ),
            ("64 bytes", filled(64), 0x100),
            ("65 bytes", filled(65), 0),
            ("4 bytes", b"RLX1".to_vec(), 0),
            ("wrong magic", [b"RLX2".as_slice(), &caps[4..]].concat(), 0),
            (
                "version 2",
                [&caps[..4], &[2u8][..], &caps[5..]].concat(),
                0,
            ),
            ("truncated entry", caps[..caps.len() - 1].to_vec(), 0),
            ("a type byte alone", with(&[0x7f][..]), 0),
            ("duplicate LINK_CAPS", with(&caps[5..]), 0),
            ("duplicate unknown type", with(&[0x7f, 0, 0x7f, 0][..]), 0),
            (
                "LINK_CAPS len 3",
                after_header(&[EXT_LINK_CAPS, 3, 0, 1, 0][..]),
                0,
            ),
            (
                "LINK_CAPS len 5",
                after_header(&[EXT_LINK_CAPS, 5, 0, 0, 1, 0, 0][..]),
                0,
            ),
        ]
    }

    fn vectors_dir() -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors/rvn1/route_hints")
    }

    /// A vector file's JSON, in the layout of the other rvn1 vectors.
    pub(super) fn vector(
        name: &str,
        description: &str,
        inputs: serde_json::Value,
        expected: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "name": name,
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": description,
            "inputs": inputs,
            "expected": expected,
        })
    }

    /// Assert that the committed vector `file` (relative to
    /// `shared-vectors/rvn1/route_hints`) equals `expected`. Regenerate with
    /// `RAVEN_REGEN_RRH1_VECTORS=1` only when the wire format changes on
    /// purpose.
    pub(super) fn assert_vector(file: &str, expected: &serde_json::Value) {
        let path = vectors_dir().join(file);
        if std::env::var("RAVEN_REGEN_RRH1_VECTORS").as_deref() == Ok("1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(expected).unwrap() + "\n",
            )
            .unwrap();
        }
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
        let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(&stored, expected, "{file}");
    }

    /// Does `h` carry a custody entry (§12)?
    fn has_custody(h: &RouteHints) -> bool {
        h.custody_offer.is_some() || !h.custodian_tags.is_empty()
    }

    /// What [`decode`] returns, as the vectors record it. The custody entries
    /// (§12) appear only when the frame carries one, so the vectors written
    /// before them are unchanged.
    fn decoded_json(h: &RouteHints) -> serde_json::Value {
        let mut out = json!({
            "generation": h.generation,
            "ttl_s": h.ttl_s,
            "p2p_id_hex": h.p2p_id.map(hex::encode),
            "peer_id": h.p2p_id.as_ref().map(|b| peer_id_from_bytes(b).unwrap()),
            "relays": h.relays,
            "direct": h.direct,
            "lan_port": h.lan_port,
            "custodians_hex": h.custodians.iter().map(hex::encode).collect::<Vec<_>>(),
        });
        if has_custody(h) {
            out["custody_offer"] = json!(h.custody_offer);
            out["custodian_tags"] = h
                .custodian_tags
                .iter()
                .map(|(tag, flags)| json!({ "tag_hex": hex::encode(tag), "flags": flags }))
                .collect();
        }
        out
    }

    /// What [`validate`] keeps, as the vectors record it; the custody part
    /// only for a frame that carried a custody entry (`custody`).
    fn kept_json(v: &ValidHints, custody: bool) -> serde_json::Value {
        let texts = |vs: &[ViaAddr]| vs.iter().map(|v| v.text.clone()).collect::<Vec<_>>();
        let mut out = json!({
            "generation": v.generation,
            "ttl_s": v.ttl_s,
            "peer_id": v.peer_id,
            "relays": texts(&v.relays),
            "direct": texts(&v.direct),
            "local_direct": texts(&v.local_direct),
            "lan_port": v.lan_port,
            "custodians_hex": v.custodians.iter().map(hex::encode).collect::<Vec<_>>(),
        });
        if custody {
            out["custody_offer"] = json!(v.custody_offer);
            out["custodian_tags_hex"] =
                json!(v.custodian_tags.iter().map(hex::encode).collect::<Vec<_>>());
            out["custodian_tag_flags"] = json!(v.custodian_tag_flags);
        }
        out
    }

    fn link_json(link: &HintLink) -> serde_json::Value {
        json!({
            "carrier": link.carrier,
            "peer_ip": link.peer_ip.map(|ip| ip.to_string()),
            "pinned": link.pinned,
            "book_peer_id": link.book_peer_id,
            "link_peer_id": link.link_peer_id,
            "lab_local": link.lab_local,
        })
    }

    /// A table row's frame: the canonical encoding of `h`, which decodes back
    /// to `h` (every row is something a sender can put on the wire).
    fn wire(h: &RouteHints) -> Vec<u8> {
        let frame = encode(h);
        assert_eq!(decode(&frame).as_ref(), Some(h), "not on the wire: {h:?}");
        frame
    }

    /// 2026-10: route hints are on in release builds; a debug build closes
    /// them with `RAVEN_LAB_ROUTE_HINTS=0`, and then no carrier carries them.
    /// Spec §9.1: a card's unsigned route fields are a lab matter only. A
    /// release build never writes or reads them, whatever the lab unlock
    /// says (CI sets every switch in its release run).
    #[test]
    fn card_routes_lab_switch_is_inert_in_release() {
        let unlock = std::env::var(crate::pair_init::LAB_TEST_A)
            .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"));
        assert_eq!(card_routes_live(), cfg!(debug_assertions) && unlock);
        if !cfg!(debug_assertions) {
            assert!(!card_routes_live(), "release");
        }
    }

    #[test]
    fn production_flag_is_on_and_a_closed_gate_closes_every_carrier() {
        const {
            assert!(ROUTE_HINTS_PRODUCTION_ENABLED);
        }
        let set = std::env::var("RAVEN_LAB_ROUTE_HINTS").ok();
        assert_eq!(
            route_hints_live(),
            crate::lan_gate::gate_switch(
                cfg!(debug_assertions),
                ROUTE_HINTS_PRODUCTION_ENABLED,
                || set.clone()
            )
        );
        if !route_hints_live() {
            for carrier in [
                OutboxCarrier::Lan,
                OutboxCarrier::Internet,
                OutboxCarrier::P2p,
            ] {
                assert!(!route_hints_live_on(carrier), "{carrier:?}");
            }
        }
    }

    #[test]
    fn rrh1_encode_decode_round_trip() {
        let h = full();
        let f = encode(&h);
        assert!(is_rrh1(&f));
        assert_eq!(&f[..5], b"RRH1\x01");
        assert_eq!(f[5..13], G.to_be_bytes());
        assert_eq!(f[13..17], RRH1_DEFAULT_TTL_S.to_be_bytes());
        // Canonical: ascending type order, frame order within a type.
        let kinds: Vec<u8> = entries(&f).iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, [1, 2, 2, 2, 3, 3, 4, 5]);
        assert_eq!(entries(&f)[1].1, h.relays[0].as_bytes());
        assert_eq!(decode(&f), Some(h.clone()));
        assert_eq!(encode(&decode(&f).unwrap()), f);

        // LAN scope (an unverified LAN contact's frame): 22 bytes.
        let lan = lan_scope();
        let f = encode(&lan);
        assert_eq!(f.len(), 22);
        assert_eq!(
            hex::encode(&f),
            format!("5252483101{G:016x}0003f4800400021d6b")
        );
        assert_eq!(decode(&f), Some(lan));

        // No entries at all: still a frame (the LAN capability answer, a
        // withdrawal).
        let empty = RouteHints {
            generation: 1,
            ttl_s: RRH1_MIN_TTL_S,
            ..Default::default()
        };
        assert_eq!(encode(&empty).len(), RRH1_HEADER_LEN);
        assert_eq!(decode(&encode(&empty)), Some(empty));

        // Every registered entry at its limits fits in one frame.
        let max = RouteHints {
            relays: vec!["r".repeat(RELAY_MAX_LEN); MAX_RELAY_ENTRIES],
            direct: vec!["d".repeat(DIRECT_MAX_LEN); MAX_DIRECT],
            custodians: vec![[0x77; 32], [0x78; 32]],
            ..full()
        };
        let f = encode(&max);
        assert!(f.len() <= RRH1_MAX_LEN, "{}", f.len());
        assert_eq!(decode(&f), Some(max));
    }

    #[test]
    fn encode_writes_only_what_decode_accepts() {
        let r = |n: u8| relay_addr(&format!("/ip4/11.0.2.{n}/tcp/7423"), 0x61);
        let h = RouteHints {
            relays: vec![r(1), "with space".into(), r(2), r(3), r(4), r(5)],
            direct: (1..=7)
                .map(|n| format!("/ip4/11.0.3.{n}/tcp/7423"))
                .chain(["x".repeat(DIRECT_MAX_LEN + 1), String::new()])
                .collect(),
            lan_port: Some(0),
            custodians: vec![[1; 32], [2; 32], [3; 32]],
            ..full()
        };
        let got = decode(&encode(&h)).expect("never a frame a receiver ignores");
        assert_eq!(got.relays, vec![r(1), r(2), r(3), r(4)]);
        assert_eq!(got.direct, h.direct[..MAX_DIRECT].to_vec());
        assert_eq!(got.lan_port, None);
        assert_eq!(got.custodians, vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn rrh1_structural_rejects_ignore_the_whole_frame() {
        let rows = ignored_frames();
        for (name, frame, _) in &rows {
            assert_eq!(decode(frame), None, "{name}");
        }
        assert_eq!(
            rows.iter()
                .find(|(n, ..)| *n == "len 4097")
                .unwrap()
                .1
                .len(),
            RRH1_MAX_LEN + 1
        );

        // The same limits, just inside: accepted.
        let ttl = RRH1_DEFAULT_TTL_S;
        let accepted: Vec<(&str, Vec<u8>)> = vec![
            ("header only", raw(G, ttl, &[])),
            ("ttl 60", raw(G, 60, &[])),
            ("generation 1", raw(1, ttl, &[])),
            (
                "4 RELAY",
                raw(G, ttl, &(1..=4).map(relay_entry).collect::<Vec<_>>()),
            ),
            ("RELAY len 300", raw(G, ttl, &[(T_RELAY, vec![b'r'; 300])])),
            (
                "6 DIRECT",
                raw(G, ttl, &(1..=6).map(direct_entry).collect::<Vec<_>>()),
            ),
            (
                "DIRECT len 120",
                raw(G, ttl, &[(T_DIRECT, vec![b'd'; 120])]),
            ),
            ("LAN_PORT 65535", raw(G, ttl, &[lan_entry(&[0xff, 0xff])])),
            (
                "2 CUSTODIAN",
                raw(G, ttl, &[custodian_entry(32), custodian_entry(32)]),
            ),
            (
                "printable ASCII edges",
                raw(G, ttl, &[(T_DIRECT, b"!~".to_vec())]),
            ),
        ];
        for (name, frame) in &accepted {
            assert!(decode(frame).is_some(), "{name}");
        }
    }

    /// Unregistered types are skipped whatever their length, and entries may
    /// come in any order. The 0x20 entry was unregistered when this was
    /// written; since §11 it is a RELAY_OFFER record whose first byte (0xab)
    /// is an unknown record version, which is ignored the same way.
    #[test]
    fn rrh1_unregistered_types_of_any_length_are_skipped() {
        let h = full();
        let mut mixed = entries(&encode(&h));
        // Descending type order; a stable sort keeps frame order within a type.
        mixed.sort_by_key(|(kind, _)| std::cmp::Reverse(*kind));
        mixed.insert(1, (0x20, vec![0xab; 523]));
        mixed.insert(4, (0x7f, vec![0xcd; 1000]));
        mixed.push((0x00, Vec::new()));
        let unpadded = raw(h.generation, h.ttl_s, &mixed).len();
        let pad = RRH1_MAX_LEN - unpadded - ENTRY_HEADER_LEN;
        mixed.insert(0, (0xff, vec![0; pad]));
        let frame = raw(h.generation, h.ttl_s, &mixed);
        assert_eq!(frame.len(), RRH1_MAX_LEN);
        assert_eq!(decode(&frame), Some(h.clone()));
        // Canonical again on re-encode: the unregistered entries are gone.
        assert_eq!(encode(&decode(&frame).unwrap()), encode(&h));
        // One byte more is over the frame bound.
        mixed[0].1.push(0);
        assert_eq!(decode(&raw(h.generation, h.ttl_s, &mixed)), None);
    }

    /// The reserved types (spec §4): Phase 2's 0x21, the rest of Phase 4's
    /// 0x25-0x2F and 0x30-0x3F for Phase 5 are skipped at any length, in any
    /// position and any number of times, so a later sender's frame gives this
    /// receiver the same hints. 0x22 NAT_CLASS and 0x23 PEER_SCHEDULE are
    /// registered since §13 (`malformed_phase4_tlv_is_dropped_alone`,
    /// `malformed_peer_schedule_is_dropped_alone`), 0x24 INET_DIRECT since
    /// §13.3 (`inet_direct_tlv_matches_vectors`).
    #[test]
    fn rrh1_reserved_phase4_and_phase5_types_are_skipped() {
        let h = full();
        let base = entries(&encode(&h));
        let reserved = || {
            (0x21..=0x3f_u8).filter(|k| ![T_NAT_CLASS, T_PEER_SCHEDULE, T_INET_DIRECT].contains(k))
        };
        for kind in reserved() {
            for len in [0, 1, 2, 33, 300, 1024] {
                for at in [0, base.len() / 2, base.len()] {
                    let mut e = base.clone();
                    e.insert(at, (kind, vec![kind; len]));
                    assert_eq!(
                        decode(&raw(h.generation, h.ttl_s, &e)),
                        Some(h.clone()),
                        "type {kind:#04x}, {len} bytes, entry {at}"
                    );
                }
            }
        }
        // All of them at once, three entries of each.
        let mut e = base;
        for kind in reserved() {
            for _ in 0..3 {
                e.push((kind, vec![0xff; 8]));
            }
        }
        let frame = raw(h.generation, h.ttl_s, &e);
        assert!(frame.len() <= RRH1_MAX_LEN, "{}", frame.len());
        assert_eq!(decode(&frame), Some(h.clone()));
        // Canonical again on re-encode: the reserved entries are gone.
        assert_eq!(encode(&decode(&frame).unwrap()), encode(&h));
    }

    #[test]
    fn rrh1_ttl_is_clamped_and_generation_zero_is_ignored() {
        for (ttl, want) in [
            (0, None),
            (59, None),
            (60, Some(60)),
            (RRH1_DEFAULT_TTL_S, Some(RRH1_DEFAULT_TTL_S)),
            (604_800, Some(604_800)),
            (604_801, Some(604_800)),
            (u32::MAX, Some(604_800)),
        ] {
            assert_eq!(decode(&raw(1, ttl, &[])).map(|h| h.ttl_s), want, "{ttl}");
        }
        for (generation, ok) in [(0, false), (1, true), (u64::MAX, true)] {
            assert_eq!(
                decode(&raw(generation, 60, &[])).map(|h| h.generation),
                ok.then_some(generation)
            );
        }
        // A clamped TTL re-encodes clamped: the round trip is canonical.
        let h = decode(&raw(7, u32::MAX, &[])).unwrap();
        assert_eq!(decode(&encode(&h)), Some(h));
        // validate clamps a TTL that did not come through decode as well.
        let link = HintLink::fixture(OutboxCarrier::Lan, true);
        for (ttl, want) in [(0, 60), (u32::MAX, RRH1_MAX_TTL_S)] {
            let h = RouteHints {
                generation: 1,
                ttl_s: ttl,
                ..Default::default()
            };
            assert_eq!(validate(&h, &link).ttl_s, want);
        }
    }

    /// §5.2, one row per rule. Every row is a frame a sender can write; the
    /// table is `rrh1_validated_001.json`.
    #[test]
    fn validate_table() {
        let me = pid(SENDER);
        let other = pid(0x99);
        let via = |t: &str| parse_via(t).unwrap();
        let d = |t: &str| via(&format!("{t}/p2p/{me}"));
        let r1a = relay_addr("/ip4/11.0.2.1/tcp/7423", 0x61);
        let r1b = relay_addr("/ip4/11.0.2.1/tcp/443", 0x61);
        let r1c = relay_addr("/dns4/r1.example.org/tcp/443", 0x61);
        let r2a = relay_addr("/ip4/11.0.2.2/tcp/7423", 0x62);
        let r2b = relay_addr("/dns4/relay.example.org/tcp/443", 0x62);
        let r3a = relay_addr("/ip4/11.0.2.3/tcp/7423", 0x63);
        let base = RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            p2p_id: Some(peer_id_bytes(&me).unwrap()),
            ..Default::default()
        };
        let with_direct = |direct: &[&str]| {
            wire(&RouteHints {
                direct: direct.iter().map(|s| s.to_string()).collect(),
                ..base.clone()
            })
        };
        let with_relays = |relays: &[&String]| {
            wire(&RouteHints {
                relays: relays.iter().map(|s| s.to_string()).collect(),
                ..base.clone()
            })
        };
        let with_custodians = |custodians: &[[u8; 32]]| {
            wire(&RouteHints {
                p2p_id: None,
                custodians: custodians.to_vec(),
                ..base.clone()
            })
        };
        let with_custody = |offer: Option<u8>, tags: &[([u8; 32], u8)]| {
            wire(&RouteHints {
                p2p_id: None,
                custody_offer: offer,
                custodian_tags: tags.to_vec(),
                ..base.clone()
            })
        };
        let (c1, c2) = (tag_of(CUSTODIANS[0]), tag_of(CUSTODIANS[1]));
        // full() with a 600-byte entry of type 0x20 between the RELAY and
        // DIRECT entries: reserved when the vector was written, a RELAY_OFFER
        // record of an unknown version (0xab) since §11, ignored either way.
        let full_with_unregistered = {
            let mut e = entries(&wire(&full()));
            e.insert(4, (0x20, vec![0xab; 600]));
            raw(G, RRH1_DEFAULT_TTL_S, &e)
        };
        let lan = HintLink::fixture(OutboxCarrier::Lan, true);
        let inet = HintLink::fixture(OutboxCarrier::Internet, true);
        let p2p = HintLink::fixture(OutboxCarrier::P2p, true);
        let at = |link: HintLink<'static>, ip: &str| HintLink {
            peer_ip: Some(ip.parse().unwrap()),
            ..link
        };
        let want = |dropped: u32| ValidHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            peer_id: Some(me.clone()),
            dropped,
            ..Default::default()
        };
        let nothing_p2p = |dropped: u32| ValidHints {
            peer_id: None,
            ..want(dropped)
        };
        let full_kept = |dropped: u32| ValidHints {
            relays: full().relays.iter().map(|r| via(r)).collect(),
            direct: full().direct.iter().map(|t| d(t)).collect(),
            custodians: vec![[0x77; 32]],
            ..want(dropped)
        };

        let rows: Vec<(&str, Vec<u8>, HintLink, ValidHints)> = vec![
            (
                "global-only DIRECT",
                with_direct(&[
                    "/ip4/11.0.3.5/tcp/7423",
                    "/ip6/2c0f:fff0:a::5/udp/7423/quic-v1",
                    "/ip4/192.168.1.30/tcp/7423",
                    "/ip4/127.0.0.1/tcp/7423",
                    "/ip4/203.0.113.9/tcp/7423",
                    "/ip6/fe80::1/tcp/7423",
                ]),
                inet,
                ValidHints {
                    direct: vec![
                        d("/ip4/11.0.3.5/tcp/7423"),
                        d("/ip6/2c0f:fff0:a::5/udp/7423/quic-v1"),
                    ],
                    ..want(4)
                },
            ),
            (
                "NAT64 and 6to4 DIRECT are global only when the IPv4 inside is",
                with_direct(&[
                    "/ip6/64:ff9b::a00:1/tcp/7423",
                    "/ip6/2002:a00:1::1/udp/7423/quic-v1",
                    "/ip6/64:ff9b::b00:305/tcp/7423",
                ]),
                inet,
                ValidHints {
                    direct: vec![d("/ip6/64:ff9b::b00:305/tcp/7423")],
                    ..want(2)
                },
            ),
            (
                "same-LAN /24 on a LAN link",
                wire(&RouteHints {
                    lan_port: Some(7531),
                    direct: [
                        "/ip4/192.168.7.30/tcp/7423",
                        "/ip4/192.168.8.30/tcp/7423",
                        "/ip4/10.0.0.5/tcp/7423",
                        "/ip4/11.0.3.5/tcp/7423",
                    ]
                    .map(String::from)
                    .to_vec(),
                    ..base.clone()
                }),
                lan,
                ValidHints {
                    direct: vec![d("/ip4/11.0.3.5/tcp/7423")],
                    local_direct: vec![d("/ip4/192.168.7.30/tcp/7423")],
                    lan_port: Some(7531),
                    ..want(2)
                },
            ),
            (
                "same-LAN /64 on a LAN link",
                with_direct(&[
                    "/ip6/fd00:7:7:7::30/udp/7423/quic-v1",
                    "/ip6/fd00:7:7:8::30/udp/7423/quic-v1",
                    "/ip4/192.168.7.30/tcp/7423",
                ]),
                at(lan, "fd00:7:7:7::20"),
                ValidHints {
                    local_direct: vec![d("/ip6/fd00:7:7:7::30/udp/7423/quic-v1")],
                    ..want(2)
                },
            ),
            (
                "the same-LAN rule is for LAN links only",
                wire(&RouteHints {
                    lan_port: Some(7531),
                    direct: ["/ip4/192.168.7.30/tcp/7423", "/ip4/11.0.3.5/tcp/7423"]
                        .map(String::from)
                        .to_vec(),
                    ..base.clone()
                }),
                at(inet, "192.168.7.20"),
                ValidHints {
                    direct: vec![d("/ip4/11.0.3.5/tcp/7423")],
                    ..want(2)
                },
            ),
            (
                "at most 4 global DIRECT",
                with_direct(&[
                    "/ip4/11.0.3.1/tcp/7423",
                    "/ip4/11.0.3.2/tcp/7423",
                    "/ip4/11.0.3.3/tcp/7423",
                    "/ip4/11.0.3.4/tcp/7423",
                    "/ip4/11.0.3.5/tcp/7423",
                    "/ip4/11.0.3.6/tcp/7423",
                ]),
                inet,
                ValidHints {
                    direct: (1..=4)
                        .map(|n| d(&format!("/ip4/11.0.3.{n}/tcp/7423")))
                        .collect(),
                    ..want(2)
                },
            ),
            (
                "at most 2 same-LAN DIRECT, duplicates dropped",
                with_direct(&[
                    "/ip4/192.168.7.30/tcp/7423",
                    "/ip4/192.168.7.30/tcp/7423",
                    "/ip4/192.168.7.31/tcp/7423",
                    "/ip4/192.168.7.32/tcp/7423",
                    "/ip4/11.0.3.5/tcp/7423",
                ]),
                lan,
                ValidHints {
                    direct: vec![d("/ip4/11.0.3.5/tcp/7423")],
                    local_direct: vec![
                        d("/ip4/192.168.7.30/tcp/7423"),
                        d("/ip4/192.168.7.31/tcp/7423"),
                    ],
                    ..want(2)
                },
            ),
            (
                "DIRECT with its own /p2p, a DNS name or a circuit",
                with_direct(&[
                    format!("/ip4/11.0.3.5/tcp/7423/p2p/{me}").as_str(),
                    "/dns4/me.example.org/tcp/7423",
                    "/ip4/11.0.3.5/tcp/7423/p2p-circuit",
                    "/ip4/11.0.3.5/udp/7423",
                    "/ip4/11.0.3.6/udp/7423/quic-v1",
                ]),
                inet,
                ValidHints {
                    direct: vec![d("/ip4/11.0.3.6/udp/7423/quic-v1")],
                    ..want(4)
                },
            ),
            (
                // Review A-2: endpoints never listen on WSS (RWS1 §2.3).
                "DIRECT in a WSS form",
                with_direct(&[
                    "/ip4/11.0.3.5/tcp/443/tls/ws",
                    "/ip4/11.0.3.5/tcp/443/tls/sni/x.example/ws",
                    "/ip4/11.0.3.5/tcp/443/wss",
                    "/ip4/11.0.3.6/tcp/443",
                ]),
                inet,
                ValidHints {
                    direct: vec![d("/ip4/11.0.3.6/tcp/443")],
                    ..want(3)
                },
            ),
            (
                "lab_local keeps loopback and private DIRECT",
                with_direct(&["/ip4/127.0.0.1/tcp/7423", "/ip4/10.1.2.3/tcp/7423"]),
                HintLink {
                    lab_local: true,
                    ..inet
                },
                ValidHints {
                    direct: vec![d("/ip4/127.0.0.1/tcp/7423"), d("/ip4/10.1.2.3/tcp/7423")],
                    ..want(0)
                },
            ),
            (
                "RELAY naming the sender, a circuit or junk",
                with_relays(&[
                    &r1a,
                    &format!("/ip4/11.0.3.5/tcp/7423/p2p/{me}"),
                    &format!("{r2a}/p2p-circuit"),
                    &format!("/ip4/11.0.2.2/tcp/7423/p2p-circuit/p2p/{}", pid(0x62)),
                ]),
                inet,
                ValidHints {
                    relays: vec![via(&r1a)],
                    ..want(3)
                },
            ),
            (
                "RELAY that is not a multiaddr",
                with_relays(&[&"junk".to_string(), &r2b]),
                inet,
                ValidHints {
                    relays: vec![via(&r2b)],
                    ..want(1)
                },
            ),
            (
                "4 RELAY of 2 relays kept",
                with_relays(&[&r1a, &r1b, &r2a, &r2b]),
                inet,
                ValidHints {
                    relays: vec![via(&r1a), via(&r1b), via(&r2a), via(&r2b)],
                    ..want(0)
                },
            ),
            (
                "3 distinct relays drop the third",
                with_relays(&[&r1a, &r2a, &r3a, &r1b]),
                inet,
                ValidHints {
                    relays: vec![via(&r1a), via(&r2a), via(&r1b)],
                    ..want(1)
                },
            ),
            (
                "a third address of one relay and a duplicate dropped",
                with_relays(&[&r1a, &r1a, &r1b, &r1c]),
                inet,
                ValidHints {
                    relays: vec![via(&r1a), via(&r1b)],
                    ..want(2)
                },
            ),
            (
                "P2P_ID matching the p2p link; LAN_PORT on a p2p link dropped",
                wire(&full()),
                p2p,
                full_kept(1),
            ),
            (
                "P2P_ID mismatch with the p2p link drops the p2p part",
                wire(&full()),
                HintLink {
                    link_peer_id: Some(&other),
                    ..p2p
                },
                ValidHints {
                    custodians: vec![[0x77; 32]],
                    ..nothing_p2p(7)
                },
            ),
            (
                "a p2p link without its PeerId drops the p2p part",
                wire(&full()),
                HintLink {
                    link_peer_id: None,
                    ..p2p
                },
                ValidHints {
                    custodians: vec![[0x77; 32]],
                    ..nothing_p2p(7)
                },
            ),
            (
                "P2P_ID mismatch with the book drops the p2p part",
                wire(&full()),
                HintLink {
                    book_peer_id: Some(&other),
                    ..inet
                },
                ValidHints {
                    custodians: vec![[0x77; 32]],
                    ..nothing_p2p(7)
                },
            ),
            (
                "no book PeerId: P2P_ID kept",
                wire(&full()),
                HintLink {
                    book_peer_id: None,
                    ..inet
                },
                full_kept(1),
            ),
            (
                "P2P_ID of another key type drops the p2p part",
                wire(&RouteHints {
                    p2p_id: base.p2p_id.map(|mut b| {
                        b[3] = 0x00;
                        b
                    }),
                    ..full()
                }),
                lan,
                ValidHints {
                    lan_port: Some(7531),
                    custodians: vec![[0x77; 32]],
                    ..nothing_p2p(6)
                },
            ),
            (
                "no P2P_ID: RELAY and DIRECT dropped",
                wire(&RouteHints {
                    p2p_id: None,
                    ..full()
                }),
                lan,
                ValidHints {
                    lan_port: Some(7531),
                    custodians: vec![[0x77; 32]],
                    ..nothing_p2p(5)
                },
            ),
            (
                "an unpinned sender keeps only LAN_PORT on a local LAN link",
                wire(&full()),
                HintLink::fixture(OutboxCarrier::Lan, false),
                ValidHints {
                    lan_port: Some(7531),
                    ..nothing_p2p(7)
                },
            ),
            (
                "an unpinned sender from a public address keeps nothing",
                wire(&full()),
                at(HintLink::fixture(OutboxCarrier::Lan, false), "11.0.3.9"),
                nothing_p2p(8),
            ),
            (
                "an unpinned sender on an Internet link keeps nothing",
                wire(&full()),
                HintLink::fixture(OutboxCarrier::Internet, false),
                nothing_p2p(8),
            ),
            (
                "an unpinned sender on a p2p link keeps nothing",
                wire(&full()),
                HintLink::fixture(OutboxCarrier::P2p, false),
                nothing_p2p(8),
            ),
            (
                "a pinned sender's LAN_PORT on a LAN link from any address",
                wire(&RouteHints {
                    lan_port: Some(7531),
                    ..base.clone()
                }),
                at(lan, "11.0.3.9"),
                ValidHints {
                    lan_port: Some(7531),
                    ..want(0)
                },
            ),
            (
                "zero and the receiver's own custodian dropped",
                with_custodians(&[[0; 32], lan.local]),
                lan,
                nothing_p2p(2),
            ),
            (
                "the sender's own custodian dropped",
                with_custodians(&[lan.sender, [0x77; 32]]),
                lan,
                ValidHints {
                    custodians: vec![[0x77; 32]],
                    ..nothing_p2p(1)
                },
            ),
            (
                "a duplicate custodian dropped",
                with_custodians(&[[0x77; 32], [0x77; 32]]),
                lan,
                ValidHints {
                    custodians: vec![[0x77; 32]],
                    ..nothing_p2p(1)
                },
            ),
            (
                "an unregistered type of len 600 is skipped",
                full_with_unregistered,
                inet,
                full_kept(1),
            ),
            (
                "an unpinned sender's custody entries dropped",
                wire(&custody()),
                HintLink::fixture(OutboxCarrier::Lan, false),
                ValidHints {
                    lan_port: Some(7531),
                    ..nothing_p2p(3)
                },
            ),
            (
                "CUSTODY_OFFER 0xff kept as 0x03",
                with_custody(Some(0xff), &[]),
                p2p,
                ValidHints {
                    custody_offer: Some(0x03),
                    ..nothing_p2p(0)
                },
            ),
            (
                "an all-zero CUSTODIAN_TAG dropped",
                with_custody(None, &[([0; 32], 0), (c1, 0)]),
                inet,
                ValidHints {
                    custodian_tags: vec![c1],
                    custodian_tag_flags: vec![0],
                    ..nothing_p2p(1)
                },
            ),
            (
                "CUSTODIAN_TAG unknown flag bits cleared, HANDOFF_INBOX kept",
                with_custody(Some(0x01), &[(c1, 0x03), (c2, 0xff)]),
                lan,
                ValidHints {
                    custody_offer: Some(0x01),
                    custodian_tags: vec![c1, c2],
                    custodian_tag_flags: vec![0x01, 0x01],
                    ..nothing_p2p(0)
                },
            ),
            (
                "a duplicate CUSTODIAN_TAG merged",
                with_custody(None, &[(c2, 0x02), (c2, 0x00)]),
                inet,
                ValidHints {
                    custodian_tags: vec![c2],
                    custodian_tag_flags: vec![0],
                    ..nothing_p2p(1)
                },
            ),
        ];
        let mut cases = Vec::new();
        for (name, frame, link, want) in &rows {
            let h = decode(frame).unwrap_or_else(|| panic!("{name}: not a frame"));
            assert_eq!(&validate(&h, link), want, "{name}");
            // Every row uses the fixture's identities (the vector's inputs).
            assert_eq!((link.sender, link.local), (key(SENDER), key(0x52)));
            cases.push(json!({
                "name": name,
                "frame_hex": hex::encode(frame),
                "link": link_json(link),
                "kept": kept_json(want, has_custody(&h)),
                "dropped": want.dropped,
            }));
        }
        assert_vector(
            "rrh1_validated_001.json",
            &vector(
                "RRH1 receiver rules (§5.2): what a receiver keeps from each frame",
                "Each case: a frame, the link it arrived on, what validate keeps and how many \
                 entries it drops. The sender is the sender seed (its Raven key and libp2p \
                 PeerId), the receiver the receiver seed. Kept DIRECT entries carry \
                 /p2p/<sender PeerId>; addresses are canonical text. A case whose frame \
                 carries custody entries (§12) also shows the kept custody_offer, \
                 custodian_tags_hex and custodian_tag_flags (the CUSTODIAN_TAG flags after \
                 validate, one per kept tag)",
                json!({
                    "sender_seed_hex": hex::encode([SENDER; 32]),
                    "sender_device_hex": hex::encode(key(SENDER)),
                    "sender_peer_id": me,
                    "receiver_seed_hex": hex::encode([0x52u8; 32]),
                    "receiver_device_hex": hex::encode(key(0x52)),
                }),
                json!({ "cases": cases }),
            ),
        );
    }

    /// §5.2 RELAY address rule, one row per case: an IP literal RELAY is
    /// kept only when it is globally routable (an IPv4-mapped, NAT64 or 6to4
    /// address by the IPv4 address inside), on any link, so a contact never
    /// makes this node dial loopback or its local networks. A DNS name is
    /// kept. The debug lab flags keep loopback and private ones. The table is
    /// `rrh1_validated_relay_002.json`.
    #[test]
    fn validate_relay_address_rule() {
        let me = pid(SENDER);
        let via = |t: &str| parse_via(t).unwrap();
        let r1 = |host: &str| relay_addr(host, 0x61);
        let r2 = |host: &str| relay_addr(host, 0x62);
        let base = RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            p2p_id: Some(peer_id_bytes(&me).unwrap()),
            ..Default::default()
        };
        let with_relays = |relays: &[String]| {
            wire(&RouteHints {
                relays: relays.to_vec(),
                ..base.clone()
            })
        };
        let want = |relays: &[&String], dropped: u32| ValidHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            peer_id: Some(me.clone()),
            relays: relays.iter().map(|r| via(r)).collect(),
            dropped,
            ..Default::default()
        };
        let lan = HintLink::fixture(OutboxCarrier::Lan, true);
        let inet = HintLink::fixture(OutboxCarrier::Internet, true);
        let p2p = HintLink::fixture(OutboxCarrier::P2p, true);
        let local = [
            r1("/ip4/127.0.0.1/tcp/22"),
            r1("/ip4/192.168.1.1/tcp/80"),
            r2("/ip6/::1/tcp/7423"),
            r2("/ip4/11.0.2.2/tcp/7423"),
        ];
        let rows: Vec<(&str, Vec<u8>, HintLink, ValidHints)> = vec![
            (
                "loopback and private RELAY dropped, a global one kept",
                with_relays(&local),
                inet,
                want(&[&local[3]], 3),
            ),
            (
                "unique-local, CGNAT and NAT64 of a private IPv4 dropped, a DNS name kept",
                with_relays(&[
                    r1("/ip6/fd00::1/tcp/7423"),
                    r1("/ip4/100.64.0.1/tcp/7423"),
                    r2("/ip6/64:ff9b::a00:1/tcp/7423"),
                    r2("/dns4/relay.example.org/tcp/443"),
                ]),
                p2p,
                want(&[&r2("/dns4/relay.example.org/tcp/443")], 3),
            ),
            (
                "on a LAN link too: same-LAN, 6to4 of a private IPv4 and documentation dropped",
                with_relays(&[
                    r1("/ip4/192.168.7.30/tcp/7423"),
                    r1("/ip4/10.0.0.1/tcp/7423"),
                    r2("/ip6/2002:a00:1::1/udp/7423/quic-v1"),
                    r2("/ip4/198.51.100.1/tcp/7423"),
                ]),
                lan,
                want(&[], 4),
            ),
            (
                "lab_local keeps loopback and private RELAY",
                with_relays(&local),
                HintLink {
                    lab_local: true,
                    ..inet
                },
                want(&local.iter().collect::<Vec<_>>(), 0),
            ),
            (
                "lab_loopback keeps loopback RELAY only",
                with_relays(&local),
                HintLink {
                    lab_loopback: true,
                    ..inet
                },
                want(&[&local[0], &local[2], &local[3]], 1),
            ),
        ];
        let mut cases = Vec::new();
        for (name, frame, link, want) in &rows {
            let h = decode(frame).unwrap_or_else(|| panic!("{name}: not a frame"));
            assert_eq!(&validate(&h, link), want, "{name}");
            assert_eq!((link.sender, link.local), (key(SENDER), key(0x52)));
            let mut link_json = link_json(link);
            link_json["lab_loopback"] = json!(link.lab_loopback);
            cases.push(json!({
                "name": name,
                "frame_hex": hex::encode(frame),
                "link": link_json,
                "kept": kept_json(want, has_custody(&h)),
                "dropped": want.dropped,
            }));
        }
        assert_vector(
            "rrh1_validated_relay_002.json",
            &vector(
                "RRH1 receiver rules (§5.2): the RELAY address rule",
                "Each case: a frame of RELAY entries, the link it arrived on, what validate \
                 keeps and how many entries it drops. An IP literal RELAY is kept only when it \
                 is globally routable; lab_local (debug) keeps any, lab_loopback (debug) a \
                 loopback one. The sender is the sender seed, the receiver the receiver seed; \
                 addresses are canonical text",
                json!({
                    "sender_seed_hex": hex::encode([SENDER; 32]),
                    "sender_device_hex": hex::encode(key(SENDER)),
                    "sender_peer_id": me,
                    "receiver_seed_hex": hex::encode([0x52u8; 32]),
                    "receiver_device_hex": hex::encode(key(0x52)),
                }),
                json!({ "cases": cases }),
            ),
        );
    }

    /// validate holds its own limits even past what decode lets through.
    #[test]
    fn validate_holds_its_limits_beyond_the_frame() {
        let me = pid(SENDER);
        let d = |t: &str| parse_via(&format!("{t}/p2p/{me}")).unwrap();
        let base = RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            p2p_id: Some(peer_id_bytes(&me).unwrap()),
            ..Default::default()
        };
        let lan = HintLink::fixture(OutboxCarrier::Lan, true);
        let direct = RouteHints {
            direct: [
                "/ip4/11.0.3.5/tcp/7423",
                "/ip6/2c0f:fff0:a::5/udp/7423/quic-v1",
                "/ip4/192.168.1.30/tcp/7423",
                "/ip4/127.0.0.1/tcp/7423",
                "/ip4/203.0.113.9/tcp/7423",
                "/ip6/fe80::1/tcp/7423",
                "/ip6/64:ff9b::a00:1/tcp/7423",
            ]
            .map(String::from)
            .to_vec(),
            ..base.clone()
        };
        let v = validate(&direct, &HintLink::fixture(OutboxCarrier::Internet, true));
        assert_eq!(
            v.direct,
            vec![
                d("/ip4/11.0.3.5/tcp/7423"),
                d("/ip6/2c0f:fff0:a::5/udp/7423/quic-v1")
            ]
        );
        assert_eq!(v.dropped, 5);
        let custodians = RouteHints {
            p2p_id: None,
            custodians: vec![
                [0; 32], lan.local, lan.sender, [0x77; 32], [0x77; 32], [0x78; 32], [0x79; 32],
            ],
            ..base
        };
        let v = validate(&custodians, &lan);
        assert_eq!(v.custodians, vec![[0x77; 32], [0x78; 32]]);
        assert_eq!(v.dropped, 5);
    }

    #[test]
    fn fixture_links_match_the_vector_sender() {
        let me = pid(SENDER);
        for carrier in [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
        ] {
            for pinned in [false, true] {
                let link = HintLink::fixture(carrier, pinned);
                assert_eq!(link.carrier, carrier);
                assert_eq!(link.pinned, pinned);
                assert_eq!(link.book_peer_id, Some(me.as_str()));
                assert_eq!(
                    link.link_peer_id,
                    (carrier == OutboxCarrier::P2p).then_some(me.as_str())
                );
                assert!(!link.lab_local);
                // The full frame keeps its whole p2p part on every pinned
                // fixture link, and nothing but LAN_PORT on an unpinned one.
                let v = validate(&full(), &link);
                assert_eq!(v.peer_id.is_some(), pinned, "{carrier:?}");
                assert_eq!(v.relays.len(), if pinned { 3 } else { 0 });
                if !pinned {
                    assert!(v.direct.is_empty() && v.custodians.is_empty());
                    assert_eq!(v.lan_port.is_some(), carrier == OutboxCarrier::Lan);
                }
            }
        }
    }

    /// §4 and §12: the custody entries round trip, canonical, after the
    /// Phase 2 entries; a CUSTODIAN_TAG is the tag then its flags byte.
    #[test]
    fn rrh1_custody_entries_round_trip() {
        let h = custody();
        let f = encode(&h);
        let e = entries(&f);
        let kinds: Vec<u8> = e.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            kinds,
            [
                T_LAN_PORT,
                T_CUSTODY_OFFER,
                T_CUSTODIAN_TAG,
                T_CUSTODIAN_TAG
            ]
        );
        assert_eq!(e[1].1, [0x03]);
        assert_eq!(e[2].1.len(), CUSTODIAN_TAG_LEN);
        assert_eq!(e[2].1[..32], tag_of(CUSTODIANS[0]));
        assert_eq!(e[2].1[32], 0x00);
        assert_eq!(e[3].1[..32], tag_of(CUSTODIANS[1]));
        assert_eq!(e[3].1[32], 0x03);
        assert_eq!(
            f.len(),
            RRH1_HEADER_LEN + 5 + 4 + 2 * (3 + CUSTODIAN_TAG_LEN)
        );
        assert_eq!(decode(&f), Some(h.clone()));
        assert_eq!(encode(&decode(&f).unwrap()), f);

        // With every Phase 2 entry: ascending type order, 0x05 before 0x06.
        let both = RouteHints {
            custody_offer: Some(0x01),
            custodian_tags: vec![(tag_of(CUSTODIANS[1]), 0x00)],
            ..full()
        };
        let f = encode(&both);
        let kinds: Vec<u8> = entries(&f).iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, [1, 2, 2, 2, 3, 3, 4, 5, 6, 7]);
        assert_eq!(decode(&f), Some(both));

        // Entries in any order decode to the same hints.
        let mut reversed = entries(&encode(&h));
        reversed.reverse();
        let back = decode(&raw(G, RRH1_DEFAULT_TTL_S, &reversed)).unwrap();
        assert_eq!(back.custody_offer, h.custody_offer);
        assert_eq!(
            back.custodian_tags,
            h.custodian_tags.iter().rev().copied().collect::<Vec<_>>()
        );

        // Every registered entry at its limits still fits in one frame, and
        // encode writes at most MAX_CUSTODIANS tags.
        let max = RouteHints {
            relays: vec!["r".repeat(RELAY_MAX_LEN); MAX_RELAY_ENTRIES],
            direct: vec!["d".repeat(DIRECT_MAX_LEN); MAX_DIRECT],
            custodians: vec![[0x77; 32], [0x78; 32]],
            custody_offer: Some(0xff),
            custodian_tags: vec![([1; 32], 0xff), ([2; 32], 0x80)],
            ..full()
        };
        let f = encode(&max);
        assert!(f.len() <= RRH1_MAX_LEN, "{}", f.len());
        assert_eq!(decode(&f), Some(max.clone()));
        let three = RouteHints {
            custodian_tags: vec![([1; 32], 0), ([2; 32], 0), ([3; 32], 0)],
            ..max
        };
        let got = decode(&encode(&three)).expect("never a frame a receiver ignores");
        assert_eq!(got.custodian_tags, three.custodian_tags[..MAX_CUSTODIANS]);
    }

    /// §5.1: a custody entry of the wrong length, or too many of them,
    /// ignores the whole frame, like every registered type; just inside the
    /// limits it is accepted.
    #[test]
    fn custody_entry_structural_rejects_ignore_the_whole_frame() {
        let ttl = RRH1_DEFAULT_TTL_S;
        let custody_rows: Vec<_> = ignored_frames()
            .into_iter()
            .filter(|(name, ..)| name.contains("CUSTODY_OFFER") || name.contains("CUSTODIAN_TAG"))
            .collect();
        assert_eq!(custody_rows.len(), 6);
        for (name, frame, _) in &custody_rows {
            assert_eq!(decode(frame), None, "{name}");
            // The same frame with the full snapshot around it: still ignored.
            let mut e = entries(&encode(&full()));
            e.extend(entries(frame));
            assert_eq!(decode(&raw(G, ttl, &e)), None, "{name} in a full frame");
        }
        for flags in 0..=u8::MAX {
            let h = decode(&raw(G, ttl, &[offer_entry(&[flags])])).unwrap();
            assert_eq!(h.custody_offer, Some(flags));
        }
        let accepted = [
            (
                "2 CUSTODIAN_TAG",
                raw(G, ttl, &[tag_entry(33), tag_entry(33)]),
            ),
            (
                "2 CUSTODIAN and 2 CUSTODIAN_TAG",
                raw(
                    G,
                    ttl,
                    &[
                        custodian_entry(32),
                        tag_entry(33),
                        custodian_entry(32),
                        tag_entry(33),
                    ],
                ),
            ),
            (
                "an all-zero CUSTODIAN_TAG (validate drops it)",
                raw(G, ttl, &[(T_CUSTODIAN_TAG, vec![0; 33])]),
            ),
        ];
        for (name, frame) in &accepted {
            assert!(decode(frame).is_some(), "{name}");
        }
    }

    /// §5.2: only a pinned sender's custody entries are kept, on every
    /// carrier; an unpinned one keeps at most LAN_PORT.
    #[test]
    fn unpinned_sender_drops_custody_entries() {
        let h = decode(&encode(&custody())).unwrap();
        for carrier in [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
        ] {
            let v = validate(&h, &HintLink::fixture(carrier, false));
            assert_eq!(v.custody_offer, None, "{carrier:?}");
            assert!(v.custodian_tags.is_empty() && v.custodian_tag_flags.is_empty());
            assert_eq!(v.lan_port.is_some(), carrier == OutboxCarrier::Lan);
            assert_eq!(v.dropped, if carrier == OutboxCarrier::Lan { 3 } else { 4 });

            let v = validate(&h, &HintLink::fixture(carrier, true));
            assert_eq!(v.custody_offer, Some(0x03), "{carrier:?}");
            assert_eq!(
                v.custodian_tags,
                [tag_of(CUSTODIANS[0]), tag_of(CUSTODIANS[1])]
            );
            // 0x03: HANDOFF_INBOX kept, the reserved LETTER_INBOX cleared.
            assert_eq!(v.custodian_tag_flags, [0, CUSTODIAN_FLAG_HANDOFF_INBOX]);
        }
    }

    /// §12: CUSTODY_OFFER keeps WAN and REACHABLE and clears every other bit;
    /// an offer left with no bit is still an offer.
    #[test]
    fn offer_unknown_bits_are_cleared() {
        use crate::custody_gate::{OFFER_REACHABLE, OFFER_WAN};
        assert_eq!(CUSTODY_OFFER_KNOWN, 0x03);
        assert_eq!(OFFER_WAN | OFFER_REACHABLE, CUSTODY_OFFER_KNOWN);
        let link = HintLink::fixture(OutboxCarrier::P2p, true);
        for flags in 0..=u8::MAX {
            let h = RouteHints {
                generation: G,
                ttl_s: RRH1_DEFAULT_TTL_S,
                custody_offer: Some(flags),
                ..Default::default()
            };
            let h = decode(&encode(&h)).unwrap();
            assert_eq!(h.custody_offer, Some(flags), "carried as sent");
            let v = validate(&h, &link);
            assert_eq!(v.custody_offer, Some(flags & 0x03), "{flags:#04x}");
            assert_eq!(v.dropped, 0);
        }
    }

    /// The custodian flags rule (§4): decode and encode carry a tag's flags
    /// byte as sent; validate keeps HANDOFF_INBOX (bit 0, Phase 5), clears
    /// the bits this revision does not define and never drops the tag or the
    /// frame for one.
    #[test]
    fn tag_flags_are_carried_and_cleared_by_validate() {
        assert_eq!(CUSTODIAN_TAG_KNOWN_FLAGS, 0x01);
        assert_eq!(CUSTODIAN_FLAG_HANDOFF_INBOX, 0x01);
        let link = HintLink::fixture(OutboxCarrier::Internet, true);
        let tag = tag_of(CUSTODIANS[0]);
        for flags in 0..=u8::MAX {
            let h = RouteHints {
                generation: G,
                ttl_s: RRH1_DEFAULT_TTL_S,
                custodian_tags: vec![(tag, flags)],
                ..Default::default()
            };
            let f = encode(&h);
            assert_eq!(*f.last().unwrap(), flags);
            assert_eq!(decode(&f), Some(h.clone()));
            let v = validate(&h, &link);
            assert_eq!(v.custodian_tags, [tag], "{flags:#04x}");
            assert_eq!(v.custodian_tag_flags, [flags & 0x01], "{flags:#04x}");
            assert_eq!(v.dropped, 0);
        }
    }

    /// §5.2: an all-zero tag is dropped; a repeated tag is kept once, its
    /// flags merged; the order is the frame's.
    #[test]
    fn all_zero_tag_dropped_and_duplicates_merged() {
        let link = HintLink::fixture(OutboxCarrier::Lan, true);
        let (c1, c2) = (tag_of(CUSTODIANS[0]), tag_of(CUSTODIANS[1]));
        let with = |tags: &[([u8; 32], u8)]| RouteHints {
            generation: G,
            ttl_s: RRH1_DEFAULT_TTL_S,
            custodian_tags: tags.to_vec(),
            ..Default::default()
        };
        for (tags, kept, flags, dropped) in [
            (vec![([0; 32], 0)], vec![], vec![], 1),
            (vec![([0; 32], 3), (c2, 0)], vec![c2], vec![0], 1),
            // The copies' flags are OR-ed: HANDOFF_INBOX from the second.
            (vec![(c1, 0), (c1, 3)], vec![c1], vec![1], 1),
            (vec![(c2, 1), (c1, 0)], vec![c2, c1], vec![1, 0], 0),
            (vec![(c1, 2), (c1, 2)], vec![c1], vec![0], 1),
            // validate holds its bound past what decode lets through.
            (
                vec![(c1, 0), (c2, 0), ([9; 32], 0)],
                vec![c1, c2],
                vec![0, 0],
                1,
            ),
            (vec![(c1, 0), (c1, 0), (c2, 0)], vec![c1, c2], vec![0, 0], 1),
        ] {
            let v = validate(&with(&tags), &link);
            assert_eq!(v.custodian_tags, kept, "{tags:?}");
            assert_eq!(v.custodian_tag_flags, flags, "{tags:?}");
            assert_eq!(v.dropped, dropped, "{tags:?}");
        }
    }

    /// §12.3: Phase 2's 0x05 CUSTODIAN still decodes and validates as
    /// before, alone or next to the custody entries, and keeps its 32 bytes
    /// without flags.
    #[test]
    fn legacy_0x05_still_decodes() {
        let key77 = [0x77; 32];
        let legacy = raw(G, RRH1_DEFAULT_TTL_S, &[(T_CUSTODIAN, key77.to_vec())]);
        let h = decode(&legacy).unwrap();
        assert_eq!(h.custodians, [key77]);
        assert!(!has_custody(&h));
        assert_eq!(encode(&h), legacy);
        let link = HintLink::fixture(OutboxCarrier::Lan, true);
        assert_eq!(validate(&h, &link).custodians, [key77]);

        let mixed = RouteHints {
            custodians: vec![key77],
            ..custody()
        };
        let h = decode(&encode(&mixed)).unwrap();
        assert_eq!(h, mixed);
        let v = validate(&h, &link);
        assert_eq!(v.custodians, [key77]);
        assert_eq!(v.custody_offer, Some(0x03));
        assert_eq!(v.custodian_tags.len(), 2);
        // The full vector's frame (0x05 among the Phase 2 entries) is
        // unchanged: no custody entry, the same custodian.
        let v = validate(&full(), &link);
        assert_eq!(v.custodians, [key77]);
        assert_eq!((v.custody_offer, v.custodian_tags.len()), (None, 0));
        // 0x05 keeps its own length rule: 33 bytes is still a reject.
        assert_eq!(
            decode(&raw(G, RRH1_DEFAULT_TTL_S, &[custodian_entry(33)])),
            None
        );
    }

    /// §12 tag, a known answer computed outside Rust (SHA-256 over the
    /// domain and three 32-byte keys), and the vector of three real key
    /// triples (`rrh1_custodian_tag_001.json`).
    #[test]
    fn custodian_tag_known_answer() {
        assert_eq!(
            hex::encode(custodian_tag(&[1; 32], &[2; 32], &[3; 32])),
            "6ee6500b2012797421f0d005b91b8285817a0140a9c3be000342a88163cde807"
        );
        assert_eq!(
            hex::encode(custodian_tag(&[2; 32], &[1; 32], &[3; 32])),
            "0bf2a76e3aef0a0c640dd3a0e9bb69252cd0157f986c7fcb0e0b9ea3b42e6719"
        );
        let rows: Vec<serde_json::Value> = [
            (SENDER, 0x52, CUSTODIANS[0]),
            (SENDER, 0x52, CUSTODIANS[1]),
            (0x52, SENDER, CUSTODIANS[0]),
        ]
        .into_iter()
        .map(|(s, r, c)| {
            let (s, r, c) = (key(s), key(r), key(c));
            json!({
                "sender_pub_hex": hex::encode(s),
                "receiver_pub_hex": hex::encode(r),
                "custodian_pub_hex": hex::encode(c),
                "tag_hex": hex::encode(custodian_tag(&s, &r, &c)),
            })
        })
        .collect();
        assert_vector(
            "rrh1_custodian_tag_001.json",
            &vector(
                "RRH1 CUSTODIAN_TAG (§12): the pair-blinded custodian id",
                "tag = SHA-256(domain || sender_pub || receiver_pub || custodian_pub), all \
                 contact-book Ed25519 device keys (32 bytes each); domain is the ASCII string \
                 below, with no length prefix or terminator. Rows 1 and 2: the vector sender \
                 to the vector receiver, custodians C1 and C2. Row 3: C1 in the other \
                 direction, an unrelated tag",
                json!({
                    "domain": std::str::from_utf8(CUSTODIAN_TAG_DOMAIN).unwrap(),
                    "seeds_hex": {
                        "sender": hex::encode([SENDER; 32]),
                        "receiver": hex::encode([0x52u8; 32]),
                        "c1": hex::encode([CUSTODIANS[0]; 32]),
                        "c2": hex::encode([CUSTODIANS[1]; 32]),
                    },
                }),
                json!({ "rows": rows }),
            ),
        );
    }

    /// §12.4: a tag binds the ordered pair and the custodian; nothing else
    /// derives it.
    #[test]
    fn custodian_tag_is_order_sensitive_and_pair_bound() {
        let (s, r, c, d) = (key(SENDER), key(0x52), key(0x71), key(0x72));
        let t = custodian_tag(&s, &r, &c);
        let others = [
            custodian_tag(&r, &s, &c),
            custodian_tag(&s, &d, &c),
            custodian_tag(&d, &r, &c),
            custodian_tag(&s, &r, &d),
            custodian_tag(&s, &c, &r),
            custodian_tag(&c, &r, &s),
        ];
        for (i, o) in others.iter().enumerate() {
            assert_ne!(*o, t, "{i}");
        }
        assert_eq!(custodian_tag(&s, &r, &c), t, "deterministic");
        // The domain is part of it: a bare SHA-256 of the keys differs.
        use sha2::{Digest, Sha256};
        let bare: [u8; 32] = Sha256::digest([s, r, c].concat()).into();
        assert_ne!(bare, t);
        // The tag never shows a key it hides.
        assert!(![s, r, c].contains(&t));
    }

    /// What a Phase 2 receiver decodes from `frame`: the same decoder with
    /// 0x06 and 0x07 unregistered, i.e. this decoder over the frame with
    /// those entries moved to an unregistered type (0x7f).
    fn phase2_decode(frame: &[u8]) -> Option<RouteHints> {
        let retyped: Vec<(u8, Vec<u8>)> = entries(frame)
            .into_iter()
            .map(|(kind, value)| match kind {
                T_CUSTODY_OFFER | T_CUSTODIAN_TAG => (0x7f, value),
                _ => (kind, value),
            })
            .collect();
        let generation = u64::from_be_bytes(frame[5..13].try_into().unwrap());
        let ttl_s = u32::from_be_bytes(frame[13..17].try_into().unwrap());
        decode(&raw(generation, ttl_s, &retyped))
    }

    /// §5.1 and §12, old peers: a Phase 2 receiver skips the custody entries
    /// (unregistered for it, at any length) and reads the same hints minus
    /// them (`rrh1_phase2_decoder_skips_custody_001.json`).
    #[test]
    fn a_phase2_decoder_skips_custody_entries() {
        let both = RouteHints {
            custody_offer: Some(0x03),
            custodian_tags: custody().custodian_tags,
            ..full()
        };
        let mut first = entries(&encode(&custody()));
        first.reverse();
        let rows = [
            (
                "the full frame with CUSTODY_OFFER and two CUSTODIAN_TAGs",
                encode(&both),
            ),
            (
                "the custody frame, entries in descending type order",
                raw(G, RRH1_DEFAULT_TTL_S, &first),
            ),
        ];
        let mut cases = Vec::new();
        for (name, frame) in &rows {
            let now = decode(frame).unwrap();
            assert!(has_custody(&now), "{name}");
            let then = phase2_decode(frame).unwrap_or_else(|| panic!("{name}: ignored"));
            assert_eq!(
                then,
                RouteHints {
                    custody_offer: None,
                    custodian_tags: Vec::new(),
                    ..now.clone()
                },
                "{name}"
            );
            cases.push(json!({
                "name": name,
                "frame_hex": hex::encode(frame),
                "phase2_decoded": decoded_json(&then),
                "phase3_decoded": decoded_json(&now),
            }));
        }
        assert_vector(
            "rrh1_phase2_decoder_skips_custody_001.json",
            &vector(
                "RRH1 custody entries and a Phase 2 receiver (§5.1, §12)",
                "A receiver built before §12 treats 0x06 CUSTODY_OFFER and 0x07 CUSTODIAN_TAG \
                 as unregistered types and skips them at any length: it decodes each frame to \
                 phase2_decoded, the hints of a Phase 3 receiver (phase3_decoded) without the \
                 custody entries",
                json!({}),
                json!({ "cases": cases }),
            ),
        );
    }

    /// KATs (spec §10): the full and LAN-scope frames, the ignored table and
    /// RLX1. Regenerate with `RAVEN_REGEN_RRH1_VECTORS=1` only when the wire
    /// format changes on purpose.
    #[test]
    fn rrh1_known_answer_vectors() {
        const LAYOUT: &str = "RRH1 v1 frame (RAVEN_ROUTE_HINTS_V1 §4): magic RRH1 | version 1 | \
                              generation u64 BE | ttl_s u32 BE | entries (type u8 | len u16 BE | \
                              value); a sender writes entries in ascending type order";
        let sender = Identity::from_seed(&[SENDER; 32]);
        let h = full();
        let frame = encode(&h);
        assert_eq!(decode(&frame), Some(h.clone()));
        assert_vector(
            "rrh1_full_001.json",
            &vector(
                "RRH1 full snapshot: every registered entry type",
                &format!(
                    "{LAYOUT}. Relay R1 is named at two addresses of one reservation \
                     (TCP 7423 and TCP 443), relay R2 at one. PeerIds are libp2p Ed25519 \
                     PeerIds of p2p_route::libp2p_ed25519_public(seed)"
                ),
                json!({
                    "sender_seed_hex": hex::encode([SENDER; 32]),
                    "sender_libp2p_public_hex": hex::encode(libp2p_ed25519_public(&sender)),
                    "sender_peer_id": pid(SENDER),
                    "relay_seeds_hex": [hex::encode([0x61u8; 32]), hex::encode([0x62u8; 32])],
                    "relay_peer_ids": [pid(0x61), pid(0x62)],
                    "hints": decoded_json(&h),
                }),
                json!({
                    "frame_hex": hex::encode(&frame),
                    "frame_len": frame.len(),
                    "decoded": decoded_json(&h),
                }),
            ),
        );

        let h = custody();
        let frame = encode(&h);
        assert_eq!(decode(&frame), Some(h.clone()));
        let kept = validate(&h, &HintLink::fixture(OutboxCarrier::Lan, true));
        assert_vector(
            "rrh1_custody_001.json",
            &vector(
                "RRH1 custody entries (§12): CUSTODY_OFFER and two CUSTODIAN_TAGs",
                &format!(
                    "{LAYOUT}. CUSTODY_OFFER (0x06, 1 byte) is 0x03, WAN | REACHABLE. Each \
                     CUSTODIAN_TAG (0x07, 33 bytes) is tag[32] || flags u8; the tags are \
                     rrh1_custodian_tag_001 rows 1 and 2. The second carries flags 0x03 \
                     (bits a Phase 3 sender never sets): decode keeps them as sent, \
                     validate keeps bit 0 HANDOFF_INBOX (Phase 5) and clears the reserved \
                     bit 1 (a Phase 3 receiver clears both): kept is what a receiver keeps \
                     from a pinned sender on a LAN link"
                ),
                json!({
                    "sender_device_hex": hex::encode(key(SENDER)),
                    "receiver_device_hex": hex::encode(key(0x52)),
                    "custodian_devices_hex": CUSTODIANS.map(|c| hex::encode(key(c))),
                    "hints": decoded_json(&h),
                }),
                json!({
                    "frame_hex": hex::encode(&frame),
                    "frame_len": frame.len(),
                    "decoded": decoded_json(&h),
                    "kept": kept_json(&kept, true),
                }),
            ),
        );

        // Phase 5 (custody handoff): HANDOFF_INBOX on the first tag, every
        // other bit on the second. This revision keeps bit 0 only; a Phase 3
        // receiver (it defined no bit) keeps both tags with every bit
        // cleared, and neither drops anything.
        let h = handoff_inbox();
        let frame = encode(&h);
        assert_eq!(decode(&frame), Some(h.clone()));
        let kept = validate(&h, &HintLink::fixture(OutboxCarrier::Internet, true));
        assert_eq!(kept.custodian_tag_flags, [CUSTODIAN_FLAG_HANDOFF_INBOX, 0]);
        assert_eq!(kept.dropped, 0);
        let phase3: Vec<u8> = h
            .custodian_tags
            .iter()
            .map(|(_, flags)| flags & PHASE3_CUSTODIAN_TAG_KNOWN_FLAGS)
            .collect();
        assert_vector(
            "rrh1_custody_handoff_inbox_001.json",
            &vector(
                "RRH1 CUSTODIAN_TAG flag bit 0 HANDOFF_INBOX (§4, §12; Phase 5)",
                &format!(
                    "{LAYOUT}. Two CUSTODIAN_TAGs (0x07, tag[32] || flags u8), the tags of \
                     rrh1_custodian_tag_001 rows 1 and 2: the first with flags 0x01 \
                     (HANDOFF_INBOX: the sender registered its store tags at that custodian, \
                     RAVEN_CUSTODY_HANDOFF_V1 §3.6), the second with 0xfe (every bit this \
                     revision does not define). decode keeps the flags as sent; kept is what \
                     this revision's receiver keeps from a pinned sender on an Internet link \
                     (bit 0 only); phase3_kept_flags is what a receiver built before it \
                     keeps (every bit cleared, both tags kept, nothing dropped)"
                ),
                json!({
                    "sender_device_hex": hex::encode(key(SENDER)),
                    "receiver_device_hex": hex::encode(key(0x52)),
                    "custodian_devices_hex": CUSTODIANS.map(|c| hex::encode(key(c))),
                    "hints": decoded_json(&h),
                }),
                json!({
                    "frame_hex": hex::encode(&frame),
                    "frame_len": frame.len(),
                    "decoded": decoded_json(&h),
                    "kept": kept_json(&kept, true),
                    "phase3_kept_flags": phase3,
                }),
            ),
        );

        let h = lan_scope();
        let frame = encode(&h);
        assert_eq!(frame.len(), 22);
        assert_eq!(decode(&frame), Some(h.clone()));
        assert_vector(
            "rrh1_lan_port_001.json",
            &vector(
                "RRH1 LAN scope: LAN_PORT only",
                &format!(
                    "{LAYOUT}. What an unverified contact admitted on the LAN gets, on a LAN \
                     link only (§6)"
                ),
                json!({ "hints": decoded_json(&h) }),
                json!({
                    "frame_hex": hex::encode(&frame),
                    "frame_len": frame.len(),
                    "decoded": decoded_json(&h),
                }),
            ),
        );

        let ignored = ignored_frames();
        for (name, frame, _) in &ignored {
            assert_eq!(decode(frame), None, "{name}");
        }
        assert_vector(
            "rrh1_ignored_001.json",
            &vector(
                "RRH1 frames a receiver ignores whole (§5.1)",
                "Each frame breaks one structural rule: the receiver changes no state, writes \
                 nothing and keeps the link (a counts-only log line). Unregistered entry types \
                 are skipped whatever their length, so none appears here",
                json!({}),
                json!({
                    "cases": ignored
                        .iter()
                        .map(|(name, frame, reason)| json!({
                            "name": name,
                            "frame_hex": hex::encode(frame),
                            "reason": reason,
                        }))
                        .collect::<Vec<_>>(),
                }),
            ),
        );

        let encodings: Vec<serde_json::Value> = [crate::CAP_LINK_RRH1, 0x1, 0]
            .into_iter()
            .map(|caps| {
                let payload = rlx1_payload(caps);
                assert_eq!(rlx1_caps(&payload), caps);
                json!({ "caps": caps, "payload_hex": hex::encode(&payload) })
            })
            .collect();
        let rows = rlx1_rows();
        for (name, payload, want) in &rows {
            assert_eq!(rlx1_caps(payload), *want, "{name}");
        }
        assert_vector(
            "rlx1_caps_001.json",
            &vector(
                "RLX1 LAN Noise XX message-3 payload (§3.2)",
                "payload = \"RLX1\" | version 0x01 | entries (type u8 | len u8 | value), at most \
                 64 bytes; LINK_CAPS (type 0x01, len 4) is u32 BE in the RIH1 caps namespace, \
                 bit 8 = RRH1. Caps 0 is the empty payload. In the cases, caps is the \
                 LINK_CAPS the responder reads: 0 when there is none, or when the payload is \
                 malformed and the responder ignores it whole",
                json!({}),
                json!({
                    "encodings": encodings,
                    "cases": rows
                        .iter()
                        .map(|(name, payload, caps)| json!({
                            "name": name,
                            "payload_hex": hex::encode(payload),
                            "caps": caps,
                        }))
                        .collect::<Vec<_>>(),
                }),
            ),
        );
    }

    /// The RIH1 hello of a link that accepts RRH1 (caps bit 8), §3.1.
    #[test]
    fn rih1_hello_caps_vector() {
        use crate::internet::{
            hello_caps, hello_signing_bytes, pack_hello, unpack_verify_hello, HelloBinding,
            HelloRole, LinkFeatures, HELLO_WIRE_LEN,
        };
        use crate::lan_noise::{derive_noise_static, noise_static_public};
        let id = Identity::from_seed(&[SENDER; 32]);
        let binding = HelloBinding {
            role: HelloRole::Initiator,
            handshake_hash: [0x48; 32],
            noise_static_pub: noise_static_public(&derive_noise_static(&id).unwrap()),
        };
        let caps = hello_caps(LinkFeatures::RRH1);
        assert_eq!(caps, 0x0000_0102);
        let hello = pack_hello(&id, caps, &binding);
        assert_eq!(hello.len(), HELLO_WIRE_LEN);
        let signing = hello_signing_bytes(caps, &binding, &id.public_key_bytes());
        assert_vector(
            "rih1_hello_rrh1_001.json",
            &vector(
                "RIH1 hello with link feature bit 8 (RRH1)",
                "hello = RIH1 | caps u32 BE | ed25519_pub32 | sig64; sig = Ed25519(signer, \
                 \"rvn1/internet-hello/v1\" | role u8 | caps u32 BE | handshake_hash32 | \
                 signer_noise_static32 | ed25519_pub32) (RAVEN_TRANSPORT_INTERFACE_V1 §3). \
                 Caps = CAP_INTERNET | CAP_LINK_RRH1 (RAVEN_ROUTE_HINTS_V1 §3.1)",
                json!({
                    "signer_seed_hex": hex::encode([SENDER; 32]),
                    "role": "initiator",
                    "role_u8": binding.role.wire(),
                    "caps": caps,
                    "handshake_hash_hex": hex::encode(binding.handshake_hash),
                    "noise_static_pub_hex": hex::encode(binding.noise_static_pub),
                    "ed25519_pub_hex": hex::encode(id.public_key_bytes()),
                }),
                json!({
                    "signing_bytes_hex": hex::encode(&signing),
                    "signature_hex": hex::encode(&hello[40..]),
                    "hello_hex": hex::encode(&hello),
                    "hello_len": hello.len(),
                }),
            ),
        );
        // It verifies and returns every bit; a build that knows only
        // CAP_INTERNET checks that bit alone and ignores bit 8.
        let (got, pk) = unpack_verify_hello(&hello, &binding).unwrap();
        assert_eq!((got, pk), (caps, id.public_key_bytes()));
        assert_ne!(got & crate::CAP_INTERNET, 0);
        assert_ne!(got & crate::CAP_LINK_RRH1, 0);
    }

    #[test]
    fn rlx1_payload_is_empty_without_caps() {
        assert!(rlx1_payload(0).is_empty());
        let p = rlx1_payload(crate::CAP_LINK_RRH1);
        assert_eq!(hex::encode(&p), "524c583101010400000100");
        assert_eq!(p.len(), 11);
        assert_eq!(rlx1_caps(&p), crate::CAP_LINK_RRH1);
        assert_eq!(rlx1_caps(&rlx1_payload(1)), 1);
        assert_eq!(rlx1_caps(&rlx1_payload(u32::MAX)), u32::MAX);
    }

    #[test]
    fn rlx1_caps_table() {
        let rows = rlx1_rows();
        for (name, payload, want) in &rows {
            assert_eq!(rlx1_caps(payload), *want, "{name}");
        }
        assert_eq!(
            rows.iter()
                .find(|(n, ..)| *n == "64 bytes")
                .unwrap()
                .1
                .len(),
            RLX1_MAX_LEN
        );
    }

    #[test]
    fn rlx1_caps_never_panics_on_random_payloads() {
        let mut rng = rand::thread_rng();
        for i in 0..20_000 {
            let len = rng.gen_range(0..=80);
            let mut payload = vec![0u8; len];
            rng.fill_bytes(&mut payload);
            if i % 2 == 0 && len >= RLX1_HEADER_LEN {
                payload[..RLX1_HEADER_LEN].copy_from_slice(b"RLX1\x01");
            }
            let caps = rlx1_caps(&payload);
            if !(RLX1_HEADER_LEN..=RLX1_MAX_LEN).contains(&len) {
                assert_eq!(caps, 0, "{payload:02x?}");
            }
            // RRH1 decode never panics on the same bytes either.
            let _ = decode(&payload);
        }
    }

    /// The sender's generation digest: parts are length prefixed (moving a
    /// byte across a boundary changes it), order matters, and it is SHA-256.
    #[test]
    fn inputs_digest_frames_each_part() {
        let ab_c = inputs_digest(&[b"ab", b"c"]);
        assert_ne!(ab_c, inputs_digest(&[b"a", b"bc"]));
        assert_ne!(ab_c, inputs_digest(&[b"c", b"ab"]));
        assert_eq!(ab_c, inputs_digest(&[b"ab", b"c"]));
        assert_ne!(inputs_digest(&[]), inputs_digest(&[b""]));
        // SHA-256 of the empty input.
        assert_eq!(
            inputs_digest(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Review FU-2: the keyed digest frames its parts the same way, is
    /// stable for one identity (a restart reads it back), differs for
    /// another, and is never the plain digest a reader of the file computes.
    #[test]
    fn keyed_inputs_digest_needs_the_identity() {
        let key = NetworksKey::derive(&Identity::from_seed(&[0x11; 32]));
        let again = NetworksKey::derive(&Identity::from_seed(&[0x11; 32]));
        let other = NetworksKey::derive(&Identity::from_seed(&[0x12; 32]));
        let net: &[&[u8]] = &[b"192.168.1.30/24"];
        let d = keyed_inputs_digest(&key, net);
        assert_eq!(d.len(), 64);
        assert_eq!(d, keyed_inputs_digest(&again, net));
        assert_ne!(d, keyed_inputs_digest(&other, net));
        assert_ne!(
            d,
            inputs_digest(net),
            "a reader of the file cannot test a guess"
        );
        assert_ne!(
            keyed_inputs_digest(&key, &[b"ab", b"c"]),
            keyed_inputs_digest(&key, &[b"a", b"bc"])
        );
        assert_eq!(format!("{key:?}"), "NetworksKey(..)");
    }

    // ── Phase 4 extensions (§13) ────────────────────────────────────────────

    /// The NAT_CLASS of `rrh1_nat_class_001.json`: IPv4 TCP varies, IPv4
    /// QUIC stable_shifted, IPv6 TCP stable_kept, IPv6 QUIC unknown, a
    /// global IPv6 address.
    fn nat_class() -> NatClass {
        NatClass {
            v4_tcp: 4,
            v4_quic: 3,
            v6_tcp: 2,
            v6_quic: 0,
            flags: NAT_FLAG_V6_GLOBAL,
        }
    }

    fn nat_json(c: Option<NatClass>) -> serde_json::Value {
        c.map_or(serde_json::Value::Null, |c| {
            json!({
                "v4_tcp": NatClass::word(c.v4_tcp),
                "v4_quic": NatClass::word(c.v4_quic),
                "v6_tcp": NatClass::word(c.v6_tcp),
                "v6_quic": NatClass::word(c.v6_quic),
                "v6_global": c.flags & NAT_FLAG_V6_GLOBAL != 0,
                "v6_open": c.flags & NAT_FLAG_V6_OPEN != 0,
                "value_hex": hex::encode(c.to_bytes()),
            })
        })
    }

    /// The sender seed's P2P_ID, then `extra` (raw entries).
    fn p2p_id_then(extra: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut e = vec![(T_P2P_ID, peer_id_bytes(&pid(SENDER)).unwrap().to_vec())];
        e.extend(extra.iter().cloned());
        raw(G, RRH1_DEFAULT_TTL_S, &e)
    }

    /// KAT (spec §13.1): the full snapshot with a NAT_CLASS entry, last in
    /// the frame (type 0x22 after every Phase 2 type), and its negative: a
    /// 4-byte NAT_CLASS is dropped alone, the frame kept. Regenerate with
    /// `RAVEN_REGEN_RRH1_VECTORS=1` only when the wire format changes on
    /// purpose.
    #[test]
    fn nat_class_tlv_matches_vectors() {
        let h = RouteHints {
            nat_class: Some(nat_class()),
            ..full()
        };
        let frame = encode(&h);
        let phase2 = encode(&full());
        assert_eq!(frame.len(), phase2.len() + ENTRY_HEADER_LEN + NAT_CLASS_LEN);
        assert_eq!(frame[..phase2.len()], phase2[..]);
        assert_eq!(frame[phase2.len()..], [0x22, 0x00, 0x05, 4, 3, 2, 0, 1]);
        assert_eq!(decode(&frame), Some(h.clone()));
        let link = HintLink::fixture(OutboxCarrier::P2p, true);
        let v = validate(&decode(&frame).unwrap(), &link);
        let without = validate(&full(), &link);
        assert_eq!(
            (v.nat_class, v.dropped),
            (Some(nat_class()), without.dropped)
        );
        let mut decoded = decoded_json(&h);
        decoded["nat_class"] = nat_json(h.nat_class);
        assert_vector(
            "rrh1_nat_class_001.json",
            &vector(
                "RRH1 with a NAT_CLASS entry (Phase 4)",
                "RRH1 v1 frame (RAVEN_ROUTE_HINTS_V1 §4) carrying the Phase 4 entry NAT_CLASS \
                 (§13.1: type 0x22, len 5: v4_tcp u8 | v4_quic u8 | v6_tcp u8 | v6_quic u8 | \
                 flags u8; codes 0 unknown, 1 no_nat, 2 stable_kept, 3 stable_shifted, 4 varies; \
                 flags bit 0 global IPv6, bit 1 IPv6 pinhole confirmed). The frame is \
                 rrh1_full_001.json's with this entry appended (ascending type order): a \
                 receiver built before §13 skips it and keeps the same hints",
                json!({
                    "sender_seed_hex": hex::encode([SENDER; 32]),
                    "sender_peer_id": pid(SENDER),
                    "hints": decoded.clone(),
                }),
                json!({
                    "frame_hex": hex::encode(&frame),
                    "frame_len": frame.len(),
                    "phase2_frame_hex": hex::encode(&phase2),
                    "decoded": decoded,
                }),
            ),
        );

        let short = p2p_id_then(&[(T_NAT_CLASS, vec![4, 4, 0, 0])]);
        let h = decode(&short).expect("a short NAT_CLASS never costs the frame");
        assert!(h.p2p_id.is_some() && h.nat_class.is_none());
        assert_eq!(h.dropped_phase4, 1);
        assert_vector(
            "negative/rrh1_nat_class_short_001.json",
            &vector(
                "NAT_CLASS of 4 bytes",
                "An RRH1 frame (the sender seed's P2P_ID, then a NAT_CLASS entry, type 0x22, of \
                 4 bytes instead of 5) that breaks RAVEN_ROUTE_HINTS_V1 §13.1: the entry is \
                 dropped alone with an RRH1_MALFORMED debug log, and the frame and its P2P_ID \
                 are kept",
                json!({ "frame_hex": hex::encode(&short) }),
                json!({
                    "frame_kept": true,
                    "nat_class": null,
                    "reason": "NAT_CLASS length 4 (exactly 5)",
                }),
            ),
        );
    }

    /// §13: a bad Phase 4 entry is dropped on its own, in any position, and
    /// never costs the frame or another entry: a length other than 5, a
    /// second NAT_CLASS (the first is kept). Codes above 4 read as unknown
    /// and unknown flag bits are cleared, never dropped.
    #[test]
    fn malformed_phase4_tlv_is_dropped_alone() {
        let h = full();
        let base = entries(&encode(&h));
        for len in [0, 1, 4, 6, 33, 1024] {
            for at in [0, base.len() / 2, base.len()] {
                let mut e = base.clone();
                e.insert(at, (T_NAT_CLASS, vec![4; len]));
                let got = decode(&raw(h.generation, h.ttl_s, &e))
                    .unwrap_or_else(|| panic!("{len} bytes at {at}: the frame was ignored"));
                assert_eq!(got.dropped_phase4, 1, "{len} bytes at {at}");
                assert_eq!(
                    RouteHints {
                        dropped_phase4: 0,
                        ..got
                    },
                    h,
                    "{len} bytes at {at}"
                );
            }
        }
        // Two: the first is kept, the second dropped.
        let mut e = base.clone();
        e.push((T_NAT_CLASS, vec![4, 4, 0, 0, 0]));
        e.insert(0, (T_NAT_CLASS, vec![2, 2, 0, 0, 1]));
        let got = decode(&raw(h.generation, h.ttl_s, &e)).unwrap();
        assert_eq!(got.nat_class.map(|c| c.to_bytes()), Some([2, 2, 0, 0, 1]));
        assert_eq!(got.dropped_phase4, 1);
        // Out-of-range codes and unknown flags: read as unknown and cleared.
        let mut e = base.clone();
        e.push((T_NAT_CLASS, vec![5, 0xff, 4, 1, 0xfe]));
        let got = decode(&raw(h.generation, h.ttl_s, &e)).unwrap();
        assert_eq!(
            got.nat_class,
            Some(NatClass {
                v4_tcp: 0,
                v4_quic: 0,
                v6_tcp: 4,
                v6_quic: 1,
                flags: NAT_FLAG_V6_OPEN,
            })
        );
        assert_eq!(got.dropped_phase4, 0);
        // A frame full to RRH1_MAX_LEN keeps a good NAT_CLASS too.
        let mut e = base;
        e.push((T_NAT_CLASS, nat_class().to_bytes().to_vec()));
        let used = raw(h.generation, h.ttl_s, &e).len();
        e.insert(0, (0x7f, vec![0; RRH1_MAX_LEN - used - ENTRY_HEADER_LEN]));
        let frame = raw(h.generation, h.ttl_s, &e);
        assert_eq!(frame.len(), RRH1_MAX_LEN);
        assert_eq!(decode(&frame).unwrap().nat_class, Some(nat_class()));
        // An unpinned sender's, or one without a valid P2P_ID, is not kept.
        let with = RouteHints {
            nat_class: Some(nat_class()),
            ..full()
        };
        let unpinned = validate(&with, &HintLink::fixture(OutboxCarrier::P2p, false));
        assert_eq!(unpinned.nat_class, None);
        let no_id = RouteHints {
            p2p_id: None,
            ..with
        };
        let v = validate(&no_id, &HintLink::fixture(OutboxCarrier::P2p, true));
        assert_eq!(v.nat_class, None);
        assert!(v.dropped >= 1);
    }

    /// With the NAT_CLASS and PeerId rotation gates closed the sender writes
    /// no NAT_CLASS and no PEER_SCHEDULE, and the frame is byte for byte the
    /// Phase 2 vector's.
    #[test]
    fn gates_closed_rrh1_bytes_equal_phase2_vectors() {
        let raw = std::fs::read_to_string(vectors_dir().join("rrh1_full_001.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let frame = encode(&full());
        assert_eq!(
            v["expected"]["frame_hex"].as_str(),
            Some(hex::encode(&frame).as_str())
        );
        assert!(!entries(&frame)
            .iter()
            .any(|(k, _)| [T_NAT_CLASS, T_PEER_SCHEDULE].contains(k)));
        let lan = std::fs::read_to_string(vectors_dir().join("rrh1_lan_port_001.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&lan).unwrap();
        assert_eq!(
            v["expected"]["frame_hex"].as_str(),
            Some(hex::encode(encode(&lan_scope())).as_str())
        );
    }

    /// A Phase 2 receiver (no §13) skips type 0x22 as an unregistered
    /// entry (§5.1): walking the frame with only the Phase 2 types
    /// registered leaves exactly the hints of the frame without it.
    #[test]
    fn a_phase2_decoder_skips_0x22() {
        let with = RouteHints {
            nat_class: Some(nat_class()),
            ..full()
        };
        let frame = encode(&with);
        // The Phase 2 walk: registered types 0x01-0x05 and 0x20, the rest
        // skipped by length; the frame is well formed and nothing is left.
        let phase2: Vec<(u8, Vec<u8>)> = entries(&frame)
            .into_iter()
            .filter(|(k, _)| matches!(k, 0x01..=0x05 | 0x20))
            .collect();
        let skipped: Vec<(u8, Vec<u8>)> = entries(&frame)
            .into_iter()
            .filter(|(k, _)| !matches!(k, 0x01..=0x05 | 0x20))
            .collect();
        assert_eq!(skipped, vec![(0x22, nat_class().to_bytes().to_vec())]);
        assert_eq!(raw(G, RRH1_DEFAULT_TTL_S, &phase2), encode(&full()));
        let got = decode(&frame).unwrap();
        assert_eq!(
            RouteHints {
                nat_class: None,
                ..got
            },
            full()
        );
        // The same 0x22 entry in a reserved slot of the old table: every
        // receiver before §13 treated 0x22 like 0x25-0x2F, which this build
        // still skips at any length.
        let mut e = entries(&encode(&full()));
        e.push((0x25, nat_class().to_bytes().to_vec()));
        assert_eq!(decode(&raw(G, RRH1_DEFAULT_TTL_S, &e)), Some(full()));
    }

    // ── INET_DIRECT (§13.3, auto-reach) ─────────────────────────────────────

    fn inet(flags: u8, addr: &str) -> InetDirect {
        InetDirect {
            flags,
            addr: addr.parse().unwrap(),
        }
    }

    fn inet_json(entries: &[InetDirect]) -> serde_json::Value {
        entries
            .iter()
            .map(|e| {
                json!({
                    "addr": e.addr.to_string(),
                    "confirmed": e.confirmed(),
                    "value_hex": hex::encode(e.to_bytes()),
                })
            })
            .collect()
    }

    /// KAT (spec §13.3): the full snapshot with two INET_DIRECT entries
    /// (a confirmed IPv4 address and an unconfirmed IPv6 one), last in the
    /// frame (type 0x24 after every other), and its negative: a value that is
    /// not canonical, one with port 0 and a third entry are dropped alone,
    /// the frame kept. Regenerate with `RAVEN_REGEN_RRH1_VECTORS=1` only
    /// when the wire format changes on purpose.
    #[test]
    fn inet_direct_tlv_matches_vectors() {
        let entries = vec![
            inet(INET_FLAG_CONFIRMED, "11.0.3.7:7422"),
            inet(0, "[2c0f:fff0:a::7]:17422"),
        ];
        let h = RouteHints {
            inet: entries.clone(),
            ..full()
        };
        let frame = encode(&h);
        let phase2 = encode(&full());
        assert_eq!(frame[..phase2.len()], phase2[..]);
        let tail = &frame[phase2.len()..];
        assert_eq!(tail[0], 0x24);
        assert_eq!(&tail[3..4], &[INET_FLAG_CONFIRMED]);
        assert_eq!(&tail[4..17], b"11.0.3.7:7422");
        assert_eq!(decode(&frame), Some(h.clone()));
        let link = HintLink::fixture(OutboxCarrier::P2p, true);
        let v = validate(&decode(&frame).unwrap(), &link);
        assert_eq!(v.inet, entries);
        assert_eq!(v.dropped, validate(&full(), &link).dropped);
        let mut decoded = decoded_json(&h);
        decoded["inet"] = inet_json(&h.inet);
        assert_vector(
            "rrh1_inet_direct_001.json",
            &vector(
                "RRH1 with INET_DIRECT entries (auto-reach)",
                "RRH1 v1 frame (RAVEN_ROUTE_HINTS_V1 §4) carrying two auto-reach entries \
                 INET_DIRECT (§13.3: type 0x24, len 10..=48: flags u8 | ASCII ip:port, \
                 canonical; flags bit 0 CONFIRMED). The frame is rrh1_full_001.json's with the \
                 entries appended (ascending type order): a receiver built before §13.3 skips \
                 them and keeps the same hints",
                json!({
                    "sender_seed_hex": hex::encode([SENDER; 32]),
                    "sender_peer_id": pid(SENDER),
                    "hints": decoded.clone(),
                }),
                json!({
                    "frame_hex": hex::encode(&frame),
                    "frame_len": frame.len(),
                    "phase2_frame_hex": hex::encode(&phase2),
                    "decoded": decoded,
                }),
            ),
        );

        let bad = p2p_id_then(&[
            (T_INET_DIRECT, [&[1u8][..], b"11.0.3.7:07422"].concat()),
            (T_INET_DIRECT, [&[0u8][..], b"11.0.3.7:0"].concat()),
            (T_INET_DIRECT, [&[0u8][..], b"11.0.3.7:7422"].concat()),
            (T_INET_DIRECT, [&[0xffu8][..], b"11.0.3.8:7422"].concat()),
            (T_INET_DIRECT, [&[0u8][..], b"11.0.3.9:7422"].concat()),
        ]);
        let h = decode(&bad).expect("a bad INET_DIRECT never costs the frame");
        assert!(h.p2p_id.is_some());
        assert_eq!(
            h.inet,
            vec![
                inet(0, "11.0.3.7:7422"),
                // Unknown flag bits cleared.
                inet(INET_FLAG_CONFIRMED, "11.0.3.8:7422"),
            ]
        );
        assert_eq!(h.dropped_phase4, 3);
        assert_vector(
            "negative/rrh1_inet_direct_bad_001.json",
            &vector(
                "INET_DIRECT entries that break §13.3",
                "An RRH1 frame (the sender seed's P2P_ID, then five INET_DIRECT entries, type \
                 0x24): a port with a leading zero (not canonical), port 0, two good ones (the \
                 second with every flag bit set) and a third good one past the limit of 2. \
                 Each bad or extra entry is dropped alone with an RRH1_MALFORMED debug log; \
                 the frame, its P2P_ID and the two good entries (unknown flag bits cleared) \
                 are kept",
                json!({ "frame_hex": hex::encode(&bad) }),
                json!({
                    "frame_kept": true,
                    "inet": inet_json(&h.inet),
                    "dropped": 3,
                }),
            ),
        );
    }

    /// §13.3: every INET_DIRECT value rule, and the receiver's: a pinned
    /// sender only, a globally routable IP only (any in a loopback lab).
    #[test]
    fn inet_direct_values_and_receiver_rules() {
        let ok = |t: &str| InetDirect::from_bytes(&[&[0u8][..], t.as_bytes()].concat());
        assert!(ok("1.1.1.1:1").is_some());
        assert!(ok("[2c0f:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535").is_some());
        for bad in [
            "",
            "1.1.1.1",
            "1.1.1.1:0",
            "1.1.1.1:65536",
            "01.1.1.1:7422",
            "0.0.0.0:7422",
            "224.0.0.1:7422",
            "255.255.255.255:7422",
            "[::]:7422",
            "[ff02::1]:7422",
            "[::ffff:1.1.1.1]:7422",
            "[2001:DB8::1]:7422",
            "[2001:db8:0:0:0:0:0:1]:7422",
            "[fe80::1%4]:7422",
            "host.example:7422",
            "1.1.1.1:7422 ",
        ] {
            assert_eq!(ok(bad), None, "{bad:?}");
        }
        assert_eq!(InetDirect::from_bytes(&[0]), None);
        let h = RouteHints {
            inet: vec![
                inet(0, "192.168.1.5:7422"),
                inet(0, "11.0.3.7:7422"),
                inet(0, "127.0.0.1:7422"),
            ],
            ..full()
        };
        let pinned = HintLink::fixture(OutboxCarrier::Lan, true);
        assert_eq!(validate(&h, &pinned).inet, vec![inet(0, "11.0.3.7:7422")]);
        let lab = HintLink {
            lab_local: true,
            ..HintLink::fixture(OutboxCarrier::Lan, true)
        };
        assert_eq!(validate(&h, &lab).inet.len(), MAX_INET_DIRECT);
        let stranger = HintLink::fixture(OutboxCarrier::Lan, false);
        assert!(validate(&h, &stranger).inet.is_empty());
    }

    // ── PEER_SCHEDULE (§13.2) ───────────────────────────────────────────────

    /// The sender seed's announcement with rotation on in epoch 23 (28-day
    /// epochs): epochs 22 ..= 29 and their keys, the schedule
    /// `epoch_peer_id_001.json` names.
    fn schedule() -> PeerSchedule {
        crate::peer_rotation::announced_schedule(
            &Identity::from_seed(&[SENDER; 32]),
            Some((23, false)),
            crate::peer_rotation::DEFAULT_EPOCH_S,
        )
    }

    fn schedule_json(s: Option<&PeerSchedule>) -> serde_json::Value {
        s.map_or(serde_json::Value::Null, |s| {
            json!({
                "flags": s.flags,
                "capable": s.capable(),
                "rotating": s.rotating(),
                "postponed": s.postponed(),
                "epoch_len_s": s.epoch_len_s,
                "active_epoch": s.active_epoch,
                "entries": s.entries.iter().map(|(e, key)| json!({
                    "epoch": e,
                    "key_hex": hex::encode(key),
                    "peer_id": crate::p2p_route::peer_id_from_ed25519_public(key),
                })).collect::<Vec<_>>(),
                "value_hex": s.to_bytes().map(hex::encode),
            })
        })
    }

    /// One raw PEER_SCHEDULE value: header fields and entries as given.
    fn schedule_value(flags: u8, len: u32, active: u64, entries: &[(u64, [u8; 32])]) -> Vec<u8> {
        let mut out = vec![flags];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&active.to_be_bytes());
        out.push(u8::try_from(entries.len()).unwrap());
        for (e, key) in entries {
            out.extend_from_slice(&e.to_be_bytes());
            out.extend_from_slice(key);
        }
        out
    }

    /// A small-order Ed25519 point (the identity, order 1): it decodes, so
    /// only the small-order rule refuses it.
    const SMALL_ORDER: [u8; 32] = {
        let mut k = [0u8; 32];
        k[0] = 1;
        k
    };

    /// KAT (spec §13.2): the full snapshot with a PEER_SCHEDULE of 8
    /// entries (rotation on) and one of none (a capability announcement),
    /// each last in the frame (type 0x23 after every other), and the
    /// negatives: epochs not strictly increasing, 9 entries, a small-order
    /// key; each is dropped alone and the frame kept. Regenerate with
    /// `RAVEN_REGEN_RRH1_VECTORS=1` only when the wire format changes on
    /// purpose.
    #[test]
    fn peer_schedule_tlvs_match_vectors() {
        let phase2 = encode(&full());
        let link = HintLink::fixture(OutboxCarrier::P2p, true);
        let without = validate(&full(), &link);
        let cases = [
            (
                "rrh1_peer_schedule_001.json",
                "RRH1 with a PEER_SCHEDULE entry (Phase 4)",
                "RRH1 v1 frame (RAVEN_ROUTE_HINTS_V1 §4) carrying the Phase 4 entry PEER_SCHEDULE \
                 (§13.2: type 0x23, len 14 + 40 n: flags u8 | epoch_len_s u32 | active_epoch \
                 u64 | n u8 | n x (epoch u64 | Ed25519 public key 32 B); flags bit 0 capable, \
                 bit 1 rotating, bit 2 postponed) of a sender whose rotation is on in epoch 23: \
                 the previous epoch and 6 ahead, 8 entries, the keys of RAVEN_P2P_PEER_ROTATION_V1 \
                 §2 for the sender seed. The frame is rrh1_full_001.json's with this entry \
                 appended (ascending type order): a receiver built before §13 skips it",
                schedule(),
            ),
            (
                "rrh1_peer_schedule_capability_only_001.json",
                "RRH1 with a capability-only PEER_SCHEDULE (Phase 4)",
                "RRH1 v1 frame carrying PEER_SCHEDULE (§13.2) with n = 0: the sender can rotate \
                 (flags 0x01) but its rotation is off; the epoch length is its own, the active \
                 epoch 0. The frame is rrh1_full_001.json's with this entry appended",
                PeerSchedule::capability_only(crate::peer_rotation::DEFAULT_EPOCH_S as u32),
            ),
        ];
        for (file, name, description, s) in cases {
            let h = RouteHints {
                peer_schedule: Some(s.clone()),
                ..full()
            };
            let frame = encode(&h);
            let value = s.to_bytes().unwrap();
            assert_eq!(
                value.len(),
                PEER_SCHEDULE_HEADER_LEN + s.entries.len() * PEER_SCHEDULE_ENTRY_LEN
            );
            assert_eq!(frame.len(), phase2.len() + ENTRY_HEADER_LEN + value.len());
            assert_eq!(frame[..phase2.len()], phase2[..]);
            assert_eq!(frame[phase2.len()], 0x23);
            assert_eq!(decode(&frame), Some(h.clone()));
            let v = validate(&decode(&frame).unwrap(), &link);
            assert_eq!(
                (v.peer_schedule, v.dropped),
                (Some(s.clone()), without.dropped)
            );
            let mut decoded = decoded_json(&h);
            decoded["peer_schedule"] = schedule_json(h.peer_schedule.as_ref());
            assert_vector(
                file,
                &vector(
                    name,
                    description,
                    json!({
                        "sender_seed_hex": hex::encode([SENDER; 32]),
                        "sender_peer_id": pid(SENDER),
                        "hints": decoded.clone(),
                    }),
                    json!({
                        "frame_hex": hex::encode(&frame),
                        "frame_len": frame.len(),
                        "phase2_frame_hex": hex::encode(&phase2),
                        "decoded": decoded,
                    }),
                ),
            );
        }
        // The 8 entries name the sender's epoch PeerIds.
        let id = Identity::from_seed(&[SENDER; 32]);
        for (e, key) in &schedule().entries {
            assert_eq!(
                crate::p2p_route::peer_id_from_ed25519_public(key),
                crate::peer_rotation::epoch_peer_id(&id, *e)
            );
        }

        let entries8 = schedule().entries;
        let mut swapped = entries8.clone();
        swapped.swap(2, 3);
        let mut nine = entries8.clone();
        nine.push((30, entries8[0].1));
        let mut bad_key = entries8.clone();
        bad_key[4].1 = SMALL_ORDER;
        let flags = SCHEDULE_FLAG_CAPABLE | SCHEDULE_FLAG_ROTATING;
        let negatives = [
            (
                "negative/rrh1_peer_schedule_nonmonotonic_001.json",
                "PEER_SCHEDULE epochs not strictly increasing",
                "epochs 22, 23, 25, 24, …: not strictly increasing",
                schedule_value(flags, 2_419_200, 23, &swapped),
                "epochs not strictly increasing",
            ),
            (
                "negative/rrh1_peer_schedule_too_many_001.json",
                "PEER_SCHEDULE with 9 entries",
                "n = 9 entries (14 + 40 x 9 bytes), more than the 8 a schedule holds",
                schedule_value(flags, 2_419_200, 23, &nine),
                "n 9 (at most 8)",
            ),
            (
                "negative/rrh1_peer_schedule_bad_key_001.json",
                "PEER_SCHEDULE with a small-order key",
                "the fifth key is the Ed25519 identity point (01 00 … 00): it decodes but is of \
                 small order",
                schedule_value(flags, 2_419_200, 23, &bad_key),
                "a key of small order",
            ),
        ];
        for (file, name, what, value, reason) in negatives {
            let frame = p2p_id_then(&[(T_PEER_SCHEDULE, value)]);
            let h = decode(&frame).expect("a bad PEER_SCHEDULE never costs the frame");
            assert!(h.p2p_id.is_some() && h.peer_schedule.is_none(), "{file}");
            assert_eq!(h.dropped_phase4, 1, "{file}");
            assert_vector(
                file,
                &vector(
                    name,
                    &format!(
                        "An RRH1 frame (the sender seed's P2P_ID, then a PEER_SCHEDULE entry, \
                         type 0x23) that breaks RAVEN_ROUTE_HINTS_V1 §13.2: {what}. The entry is \
                         dropped alone with an RRH1_MALFORMED debug log, and the frame and its \
                         P2P_ID are kept"
                    ),
                    json!({ "frame_hex": hex::encode(&frame) }),
                    json!({
                        "frame_kept": true,
                        "peer_schedule": null,
                        "reason": reason,
                    }),
                ),
            );
        }
    }

    /// §13.2 (P4.28): with this node's PeerId rotation live, a P2P_ID that
    /// the book does not hold is the sender's when the frame's own schedule
    /// says it uses epoch keys and names it (on a p2p link the connection
    /// must still be that PeerId); a capability-only schedule, a PeerId the
    /// schedule does not name, or the gate closed keep Phase 2's rule.
    #[test]
    fn a_scheduled_p2p_id_is_the_senders_only_while_rotation_is_live() {
        let sender = Identity::from_seed(&[SENDER; 32]);
        let s = schedule();
        let epoch_id = crate::p2p_route::peer_id_from_ed25519_public(&s.entries[1].1);
        assert_eq!(s.entries[1].0, 23);
        let with = |p2p_id: &str, schedule: Option<PeerSchedule>| RouteHints {
            p2p_id: Some(crate::p2p_route::peer_id_bytes(p2p_id).unwrap()),
            peer_schedule: schedule,
            ..full()
        };
        let lan = HintLink::fixture(OutboxCarrier::Lan, true);
        assert_eq!(
            lan.book_peer_id,
            Some(crate::p2p_route::local_peer_id(&sender).as_str())
        );
        let rotating = with(&epoch_id, Some(s.clone()));
        assert_eq!(sender_peer_id_with(&rotating, &lan, false), None);
        assert_eq!(
            sender_peer_id_with(&rotating, &lan, true),
            Some(epoch_id.clone())
        );
        // A PeerId the schedule does not name, a capability-only schedule.
        let stranger = crate::p2p_route::local_peer_id(&Identity::from_seed(&[0x77; 32]));
        assert_eq!(
            sender_peer_id_with(&with(&stranger, Some(s.clone())), &lan, true),
            None
        );
        let only = PeerSchedule::capability_only(600);
        assert_eq!(
            sender_peer_id_with(&with(&epoch_id, Some(only)), &lan, true),
            None
        );
        assert_eq!(
            sender_peer_id_with(&with(&epoch_id, None), &lan, true),
            None
        );
        // On p2p the connection decides first.
        let p2p = HintLink::fixture(OutboxCarrier::P2p, true);
        assert_eq!(sender_peer_id_with(&rotating, &p2p, true), None);
        let on_epoch = HintLink {
            link_peer_id: Some(epoch_id.as_str()),
            ..p2p
        };
        assert_eq!(
            sender_peer_id_with(&rotating, &on_epoch, true),
            Some(epoch_id.clone())
        );
        // The book's own PeerId stays the sender's either way.
        let fixed = crate::p2p_route::local_peer_id(&sender);
        assert_eq!(
            sender_peer_id_with(&with(&fixed, Some(s)), &lan, false),
            Some(fixed)
        );
    }

    /// §13.2: a bad PEER_SCHEDULE is dropped on its own, in any position:
    /// a length that is not 14 + 40 n, n above 8 or not matching, the
    /// capable bit clear, an epoch length of 0, an entry outside
    /// `active - 1 ..= active + 6`, a repeated epoch, a key that is no point
    /// or not canonical, a second PEER_SCHEDULE (the first is kept).
    /// Unknown flag bits are cleared, never dropped. Only a pinned sender's
    /// is kept, whatever its P2P_ID; the writer never writes a bad one.
    #[test]
    fn malformed_peer_schedule_is_dropped_alone() {
        let h = full();
        let base = entries(&encode(&h));
        let s = schedule();
        let good = s.to_bytes().unwrap();
        let flags = s.flags;
        let mut bad: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![1; 13],
            good[..good.len() - 1].to_vec(),
            [&good[..], &[0]].concat(),
            schedule_value(0, 600, 23, &[]),
            schedule_value(SCHEDULE_FLAG_ROTATING, 600, 23, &s.entries),
            schedule_value(flags, 0, 23, &s.entries),
            schedule_value(flags, 600, 24, &s.entries),
            schedule_value(flags, 600, 21, &s.entries),
            schedule_value(flags, 600, 23, &[s.entries[1], s.entries[1]]),
            schedule_value(flags, 600, 23, &[(23, [0xff; 32])]),
            schedule_value(flags, 600, 23, &[(23, [0; 32])]),
        ];
        // n says 2, one entry follows; n says 1, two follow.
        let mut short = schedule_value(flags, 600, 23, &s.entries[..1]);
        short[13] = 2;
        bad.push(short);
        let mut long = schedule_value(flags, 600, 23, &s.entries[..2]);
        long[13] = 1;
        bad.push(long);
        // A non-canonical encoding (y = p + 1).
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xee;
        non_canonical[31] = 0x7f;
        bad.push(schedule_value(flags, 600, 23, &[(23, non_canonical)]));
        for (i, value) in bad.into_iter().enumerate() {
            assert_eq!(PeerSchedule::from_bytes(&value), None, "case {i}");
            for at in [0, base.len() / 2, base.len()] {
                let mut e = base.clone();
                e.insert(at, (T_PEER_SCHEDULE, value.clone()));
                let got = decode(&raw(h.generation, h.ttl_s, &e))
                    .unwrap_or_else(|| panic!("case {i} at {at}: the frame was ignored"));
                assert_eq!(got.dropped_phase4, 1, "case {i} at {at}");
                assert_eq!(
                    RouteHints {
                        dropped_phase4: 0,
                        ..got
                    },
                    h,
                    "case {i} at {at}"
                );
            }
        }
        // Two: the first is kept, the second dropped.
        let only = PeerSchedule::capability_only(600);
        let mut e = base.clone();
        e.push((T_PEER_SCHEDULE, good.clone()));
        e.insert(0, (T_PEER_SCHEDULE, only.to_bytes().unwrap()));
        let got = decode(&raw(h.generation, h.ttl_s, &e)).unwrap();
        assert_eq!(got.peer_schedule, Some(only.clone()));
        assert_eq!(got.dropped_phase4, 1);
        // Unknown flags are cleared; the edges of the window are kept, and
        // epoch 0 has no previous one.
        let mut e = base.clone();
        let edges = [s.entries[0], s.entries[7]];
        e.push((
            T_PEER_SCHEDULE,
            schedule_value(flags | 0xf8, 600, 23, &edges),
        ));
        let got = decode(&raw(h.generation, h.ttl_s, &e)).unwrap();
        let kept = got.peer_schedule.unwrap();
        assert_eq!((kept.flags, kept.entries), (flags, edges.to_vec()));
        let zero = schedule_value(flags, 1, 0, &[(0, s.entries[0].1), (6, s.entries[1].1)]);
        assert!(PeerSchedule::from_bytes(&zero).is_some());
        // A frame full to RRH1_MAX_LEN keeps a good one too.
        let mut e = base;
        e.push((T_PEER_SCHEDULE, good.clone()));
        let used = raw(h.generation, h.ttl_s, &e).len();
        e.insert(0, (0x7f, vec![0; RRH1_MAX_LEN - used - ENTRY_HEADER_LEN]));
        let frame = raw(h.generation, h.ttl_s, &e);
        assert_eq!(frame.len(), RRH1_MAX_LEN);
        assert_eq!(decode(&frame).unwrap().peer_schedule, Some(s.clone()));
        // Kept from a pinned sender without a P2P_ID too; never from an
        // unpinned one.
        let with = RouteHints {
            peer_schedule: Some(s.clone()),
            ..full()
        };
        let pinned = HintLink::fixture(OutboxCarrier::P2p, true);
        let no_id = RouteHints {
            p2p_id: None,
            ..with.clone()
        };
        assert_eq!(validate(&no_id, &pinned).peer_schedule, Some(s.clone()));
        let unpinned = HintLink::fixture(OutboxCarrier::P2p, false);
        let v = validate(&with, &unpinned);
        assert_eq!(v.peer_schedule, None);
        assert!(v.dropped >= 1);
        // The writer writes no bad schedule (and validate keeps none that
        // did not come through decode).
        let broken = PeerSchedule {
            entries: vec![(23, SMALL_ORDER)],
            ..s.clone()
        };
        assert_eq!(broken.to_bytes(), None);
        let frame = encode(&RouteHints {
            peer_schedule: Some(broken.clone()),
            ..full()
        });
        assert_eq!(frame, encode(&full()));
        let forged = RouteHints {
            peer_schedule: Some(broken),
            ..full()
        };
        assert_eq!(validate(&forged, &pinned).peer_schedule, None);
    }

    /// A Phase 2 receiver (no §13) skips type 0x23 as an unregistered entry
    /// (§5.1): walking the frame with only the Phase 2 types registered
    /// leaves exactly the hints of the frame without it.
    #[test]
    fn a_phase2_decoder_skips_0x23() {
        let with = RouteHints {
            peer_schedule: Some(schedule()),
            nat_class: Some(nat_class()),
            ..full()
        };
        let frame = encode(&with);
        let phase2: Vec<(u8, Vec<u8>)> = entries(&frame)
            .into_iter()
            .filter(|(k, _)| matches!(k, 0x01..=0x05 | 0x20))
            .collect();
        let skipped: Vec<u8> = entries(&frame)
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| !matches!(k, 0x01..=0x05 | 0x20))
            .collect();
        assert_eq!(skipped, [0x22, 0x23]);
        assert_eq!(raw(G, RRH1_DEFAULT_TTL_S, &phase2), encode(&full()));
        let got = decode(&frame).unwrap();
        assert_eq!(
            RouteHints {
                nat_class: None,
                peer_schedule: None,
                ..got
            },
            full()
        );
        // A receiver of §13.1 only (P4.24) skips 0x23 the same way.
        let p4_24: Vec<(u8, Vec<u8>)> = entries(&frame)
            .into_iter()
            .filter(|(k, _)| *k != 0x23)
            .collect();
        assert_eq!(
            decode(&raw(G, RRH1_DEFAULT_TTL_S, &p4_24)).unwrap(),
            RouteHints {
                peer_schedule: None,
                ..with
            }
        );
    }

    // ── Phase 6b PAIR_SEED (§14) ────────────────────────────────────────────

    fn seed_entry(generation: u32, acked: u32) -> crate::pair_seed::SeedEntry {
        crate::pair_seed::SeedEntry {
            generation,
            seed: zeroize::Zeroizing::new(std::array::from_fn(|i| 0x30 + i as u8)),
            acked,
        }
    }

    /// KAT (spec §14): the full snapshot with a PAIR_SEED entry (type 0x08,
    /// after CUSTODIAN 0x05 and before RELAY_OFFER 0x20: ascending order),
    /// and its negatives: a 39-byte entry, generation 0 and a second entry
    /// are dropped alone, the frame kept. A receiver built before §14 skips
    /// it. Regenerate with `RAVEN_REGEN_RRH1_VECTORS=1` only when the wire
    /// format changes on purpose.
    #[test]
    fn pair_seed_tlv_matches_vectors() {
        let h = RouteHints {
            pair_seed: Some(seed_entry(3, 2)),
            ..full()
        };
        let frame = encode(&h);
        let phase2 = encode(&full());
        assert_eq!(
            frame.len(),
            phase2.len() + ENTRY_HEADER_LEN + crate::pair_seed::ENTRY_LEN
        );
        let kinds: Vec<u8> = entries(&frame).into_iter().map(|(k, _)| k).collect();
        let at = kinds.iter().position(|k| *k == T_PAIR_SEED).unwrap();
        assert!(kinds[..at].iter().all(|k| *k < T_PAIR_SEED));
        assert!(kinds[at + 1..].iter().all(|k| *k > T_PAIR_SEED));
        assert_eq!(decode(&frame), Some(h.clone()));
        // A Phase 2 receiver (no §14) skips 0x08 and keeps the same hints.
        let older: Vec<(u8, Vec<u8>)> = entries(&frame)
            .into_iter()
            .filter(|(k, _)| *k != T_PAIR_SEED)
            .collect();
        assert_eq!(raw(G, RRH1_DEFAULT_TTL_S, &older), phase2);
        let retyped: Vec<(u8, Vec<u8>)> = entries(&frame)
            .into_iter()
            .map(|(k, v)| (if k == T_PAIR_SEED { 0x7f } else { k }, v))
            .collect();
        assert_eq!(decode(&raw(G, RRH1_DEFAULT_TTL_S, &retyped)), Some(full()));
        // Kept from a pinned sender on any link; dropped from an unpinned one.
        for carrier in [
            OutboxCarrier::Lan,
            OutboxCarrier::Internet,
            OutboxCarrier::P2p,
        ] {
            let pinned = validate(&h, &HintLink::fixture(carrier, true));
            assert_eq!(pinned.pair_seed, Some(seed_entry(3, 2)), "{carrier:?}");
            let unpinned = validate(&h, &HintLink::fixture(carrier, false));
            assert_eq!(unpinned.pair_seed, None, "{carrier:?}");
        }
        let entry = seed_entry(3, 2).to_bytes();
        let mut decoded = decoded_json(&h);
        decoded["pair_seed"] = json!({
            "generation": 3,
            "seed_hex": hex::encode(*seed_entry(3, 2).seed),
            "acked_generation": 2,
            "value_hex": hex::encode(entry),
        });
        assert_vector(
            "rrh1_pair_seed_001.json",
            &vector(
                "RRH1 with a PAIR_SEED entry (Phase 6b)",
                "RRH1 v1 frame (RAVEN_ROUTE_HINTS_V1 §4, §14) carrying the Phase 6b entry \
                 PAIR_SEED (type 0x08, len 40: generation u32 | seed[32] | acked_generation \
                 u32, big-endian; generation >= 1, the seed not all zero). The frame is \
                 rrh1_full_001.json's with this entry in ascending type order: a receiver \
                 built before §14 skips it and keeps the same hints",
                json!({
                    "sender_seed_hex": hex::encode([SENDER; 32]),
                    "sender_peer_id": pid(SENDER),
                    "hints": decoded.clone(),
                }),
                json!({
                    "frame_hex": hex::encode(&frame),
                    "frame_len": frame.len(),
                    "phase2_frame_hex": hex::encode(&phase2),
                    "decoded": decoded,
                }),
            ),
        );

        let short = p2p_id_then(&[(T_PAIR_SEED, entry[..39].to_vec())]);
        let mut zero_gen = entry;
        zero_gen[..4].fill(0);
        let two = p2p_id_then(&[
            (T_PAIR_SEED, entry.to_vec()),
            (T_PAIR_SEED, seed_entry(4, 3).to_bytes().to_vec()),
        ]);
        for (frame, kept) in [
            (&short, None),
            (&p2p_id_then(&[(T_PAIR_SEED, zero_gen.to_vec())]), None),
            (&two, Some(seed_entry(3, 2))),
        ] {
            let h = decode(frame).expect("a bad PAIR_SEED never costs the frame");
            assert!(h.p2p_id.is_some());
            assert_eq!(h.pair_seed, kept);
            assert_eq!(h.dropped_pair_seed, 1);
        }
        assert_vector(
            "negative/rrh1_pair_seed_short_001.json",
            &vector(
                "PAIR_SEED of 39 bytes",
                "An RRH1 frame (the sender seed's P2P_ID, then a PAIR_SEED entry, type 0x08, of \
                 39 bytes instead of 40) that breaks RAVEN_ROUTE_HINTS_V1 §14: the entry is \
                 dropped alone with an RRH1_MALFORMED debug log, and the frame and its P2P_ID \
                 are kept",
                json!({ "frame_hex": hex::encode(&short) }),
                json!({
                    "frame_kept": true,
                    "pair_seed": null,
                    "reason": "PAIR_SEED length 39 (exactly 40)",
                }),
            ),
        );
        // The writer writes no bad entry.
        let bad = RouteHints {
            pair_seed: Some(crate::pair_seed::SeedEntry {
                generation: 0,
                ..seed_entry(1, 0)
            }),
            ..full()
        };
        assert_eq!(encode(&bad), encode(&full()));
        assert_eq!(
            validate(&bad, &HintLink::fixture(OutboxCarrier::Lan, true)).pair_seed,
            None
        );
    }

    /// §15: the ONION entry round-trips; a pinned sender's binding that its
    /// own key signed is kept, any other (unsigned, foreign, unpinned) is
    /// dropped alone; a bad entry never costs the frame.
    #[test]
    fn onion_entry_round_trips_and_is_kept_only_signed_by_a_pinned_sender() {
        use crate::onion::{now_s, OnionBinding};
        let link = HintLink::fixture(OutboxCarrier::Internet, true);
        // The fixture's sender is seed 0x51.
        let sender = Identity::from_seed(&[0x51; 32]);
        assert_eq!(sender.public_key_bytes(), link.sender);
        let hs_id = Identity::from_seed(&[0x61; 32]).public_key_bytes();
        let binding = OnionBinding::sign(&sender, hs_id, now_s());
        let h = RouteHints {
            generation: 7,
            ttl_s: RRH1_DEFAULT_TTL_S,
            onion: Some(binding),
            ..RouteHints::default()
        };
        let frame = encode(&h);
        let back = decode(&frame).expect("frame");
        assert_eq!(back.onion, Some(binding));
        assert_eq!(back.dropped_onion, 0);
        assert_eq!(validate(&back, &link).onion, Some(binding));
        // On every carrier, onion included.
        for carrier in [
            OutboxCarrier::Lan,
            OutboxCarrier::P2p,
            OutboxCarrier::Nearby,
            OutboxCarrier::Onion,
        ] {
            assert_eq!(
                validate(&back, &HintLink::fixture(carrier, true)).onion,
                Some(binding),
                "{carrier:?}"
            );
        }
        // An unpinned sender: dropped.
        let v = validate(&back, &HintLink::fixture(OutboxCarrier::Internet, false));
        assert_eq!(v.onion, None);
        assert_eq!(v.dropped, 1);
        // Signed by someone else, or not at all: dropped.
        let foreign = OnionBinding::sign(&Identity::from_seed(&[0x52; 32]), hs_id, now_s());
        for bad in [
            foreign,
            OnionBinding {
                sig: [0; 64],
                ..binding
            },
        ] {
            let h = RouteHints {
                onion: Some(bad),
                ..h.clone()
            };
            let v = validate(&decode(&encode(&h)).unwrap(), &link);
            assert_eq!(v.onion, None);
            assert_eq!(v.dropped, 1);
        }
        // A short entry and a second one: dropped alone, the frame kept.
        let mut short = encode(&RouteHints {
            onion: None,
            ..h.clone()
        });
        short.extend_from_slice(&[T_ONION, 0, 103]);
        short.extend_from_slice(&binding.to_bytes()[..103]);
        let got = decode(&short).expect("the frame is kept");
        assert_eq!((got.onion, got.dropped_onion), (None, 1));
        let mut twice = frame.clone();
        twice.extend_from_slice(&[T_ONION, 0, 104]);
        twice.extend_from_slice(&binding.to_bytes());
        let got = decode(&twice).expect("the frame is kept");
        assert_eq!((got.onion, got.dropped_onion), (Some(binding), 1));
        // A frame without it is byte-identical to before §15.
        let without = RouteHints {
            onion: None,
            ..h.clone()
        };
        assert_eq!(encode(&without).len(), RRH1_HEADER_LEN);
    }
}
