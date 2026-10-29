//! Raven Port Mapping Profile V1 (`protocol/RAVEN_PORT_MAPPING_V1.md`): the
//! codec and state machine of Raven's NAT-PMP (RFC 6886) and PCP (RFC 6887)
//! client. Pure: no IO, no libp2p. Raven talks to the OS default router only, on UDP
//! [`PCP_PORT`]; no Raven peer ever sees these bytes.
//!
//! - Requests: [`pcp_request`] (ANNOUNCE and MAP only, no options) and
//!   [`natpmp_request`] (the external address and MAP).
//! - Replies: [`decode_reply`], strict; anything it refuses the caller
//!   ignores, like a datagram that never came.
//! - [`EpochWatch`]: the server-epoch rule (RFC 6887 §8.5), also applied to
//!   NAT-PMP's seconds since start of epoch.
//! - [`nonce_key`] / [`pcp_nonce`]: the MAP nonce, derived per profile,
//!   router and internal endpoint, so a restarted node can renew or delete
//!   what it mapped before.
//! - [`MapperCore`]: the sans-IO client state machine of one address family
//!   (probe, mapping, renewal, result codes, external address, epoch); its
//!   driver owns the socket and the clock.
//!
//! Gates: [`crate::portmap_gate`]. Vectors: `shared-vectors/rvn1/portmap/`
//! (`protocol/reference/generate_portmap.py`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::identity::Identity;

/// UDP port of the router's NAT-PMP and PCP server (the two share it).
pub const PCP_PORT: u16 = 5351;
/// Largest PCP message (RFC 6887 §7); a longer reply is invalid.
pub const MAX_PCP: usize = 1100;
/// Version byte of PCP (RFC 6887).
pub const PCP_VERSION: u8 = 2;
/// Version byte of NAT-PMP (RFC 6886).
pub const NATPMP_VERSION: u8 = 0;
/// PCP ANNOUNCE: the probe (the 24-byte header, lifetime 0).
pub const PCP_OP_ANNOUNCE: u8 = 0;
/// PCP MAP.
pub const PCP_OP_MAP: u8 = 1;
/// NAT-PMP external address request: the probe sent with the ANNOUNCE.
pub const NATPMP_OP_EXTERNAL_ADDR: u8 = 0;
/// NAT-PMP UDP mapping.
pub const NATPMP_OP_MAP_UDP: u8 = 1;
/// NAT-PMP TCP mapping.
pub const NATPMP_OP_MAP_TCP: u8 = 2;
/// Lifetime every IPv4 mapping request asks for, in seconds.
pub const REQUESTED_LIFETIME_S: u32 = 7200;
/// Lifetime an IPv6 pinhole request asks for, in seconds (owner decision
/// O4-11): shorter than [`REQUESTED_LIFETIME_S`], so a pinhole a node can no
/// longer delete (a crash, sleep or another network) stops exposing the
/// listener sooner.
pub const PINHOLE_LIFETIME_S: u32 = 3600;
/// Domain of the MAP nonce key ([`nonce_key`]).
pub const NONCE_KEY_DOMAIN: &[u8] = b"raven/pcp-nonce-key/v1";

// PCP result codes (RFC 6887 §7.4).
pub const PCP_SUCCESS: u8 = 0;
pub const PCP_UNSUPP_VERSION: u8 = 1;
pub const PCP_NOT_AUTHORIZED: u8 = 2;
pub const PCP_MALFORMED_REQUEST: u8 = 3;
pub const PCP_UNSUPP_OPCODE: u8 = 4;
pub const PCP_UNSUPP_OPTION: u8 = 5;
pub const PCP_MALFORMED_OPTION: u8 = 6;
pub const PCP_NETWORK_FAILURE: u8 = 7;
pub const PCP_NO_RESOURCES: u8 = 8;
pub const PCP_UNSUPP_PROTOCOL: u8 = 9;
pub const PCP_USER_EX_QUOTA: u8 = 10;
pub const PCP_CANNOT_PROVIDE_EXTERNAL: u8 = 11;
pub const PCP_ADDRESS_MISMATCH: u8 = 12;
pub const PCP_EXCESSIVE_REMOTE_PEERS: u8 = 13;

// NAT-PMP result codes (RFC 6886 §3.5).
pub const NATPMP_SUCCESS: u16 = 0;
pub const NATPMP_UNSUPP_VERSION: u16 = 1;
pub const NATPMP_NOT_AUTHORIZED: u16 = 2;
pub const NATPMP_NETWORK_FAILURE: u16 = 3;
pub const NATPMP_OUT_OF_RESOURCES: u16 = 4;
pub const NATPMP_UNSUPP_OPCODE: u16 = 5;

/// PCP header, request and response alike.
const PCP_HEADER: usize = 24;
/// MAP opcode data, request and response alike.
const MAP_DATA: usize = 36;
/// The R bit of PCP and the top bit of a NAT-PMP opcode: set on a reply.
const RESPONSE_BIT: u8 = 0x80;

/// Transport protocol of a mapping, as its IANA number (what PCP carries).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Proto {
    Tcp = 6,
    Udp = 17,
}

impl Proto {
    /// The protocol of an IANA number; `None` for any other.
    pub fn from_iana(n: u8) -> Option<Self> {
        match n {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }

    /// The NAT-PMP opcode that maps this protocol.
    pub fn natpmp_op(self) -> u8 {
        match self {
            Self::Udp => NATPMP_OP_MAP_UDP,
            Self::Tcp => NATPMP_OP_MAP_TCP,
        }
    }
}

/// The MAP opcode data of a PCP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapReq {
    pub nonce: [u8; 12],
    pub proto: Proto,
    pub internal_port: u16,
    pub suggested_port: u16,
    /// [`unspecified_external`] of the client: Raven never asks for a
    /// particular external address.
    pub suggested_ip: Ipv6Addr,
}

/// The 16-byte address form PCP carries: IPv6 as is, IPv4 as
/// `::ffff:a.b.c.d`.
pub fn v6_form(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// The address a 16-byte PCP field names: an IPv4-mapped one as IPv4.
pub fn from_v6_form(ip: Ipv6Addr) -> IpAddr {
    match ip.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip),
    }
}

/// The suggested external address of a MAP request from `client`:
/// `::ffff:0.0.0.0` for IPv4, `::` for an IPv6 pinhole.
pub fn unspecified_external(client: IpAddr) -> Ipv6Addr {
    match client {
        IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(),
        IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED,
    }
}

/// A PCP request: version 2, R=0, `op` ([`PCP_OP_ANNOUNCE`] or
/// [`PCP_OP_MAP`]), `lifetime`, the client's own address (it must equal the
/// datagram's source address), then the 36 bytes of `map`. No options.
/// 24 bytes, or 60 with `map`.
pub fn pcp_request(op: u8, lifetime: u32, client: IpAddr, map: Option<&MapReq>) -> Vec<u8> {
    let mut b = Vec::with_capacity(PCP_HEADER + MAP_DATA);
    b.extend_from_slice(&[PCP_VERSION, op & 0x7f, 0, 0]);
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&v6_form(client).octets());
    if let Some(m) = map {
        b.extend_from_slice(&m.nonce);
        b.extend_from_slice(&[m.proto as u8, 0, 0, 0]);
        b.extend_from_slice(&m.internal_port.to_be_bytes());
        b.extend_from_slice(&m.suggested_port.to_be_bytes());
        b.extend_from_slice(&m.suggested_ip.octets());
    }
    b
}

/// A NAT-PMP request: the external address request for `op`
/// [`NATPMP_OP_EXTERNAL_ADDR`] (2 bytes, the other arguments unused), a
/// mapping request otherwise (12 bytes). A delete is `lifetime` 0 with
/// `suggested` 0.
pub fn natpmp_request(op: u8, internal_port: u16, suggested: u16, lifetime: u32) -> Vec<u8> {
    if op == NATPMP_OP_EXTERNAL_ADDR {
        return vec![NATPMP_VERSION, op];
    }
    let mut b = Vec::with_capacity(12);
    b.extend_from_slice(&[NATPMP_VERSION, op, 0, 0]);
    b.extend_from_slice(&internal_port.to_be_bytes());
    b.extend_from_slice(&suggested.to_be_bytes());
    b.extend_from_slice(&lifetime.to_be_bytes());
    b
}

/// A reply [`decode_reply`] accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Pcp(PcpResp),
    NatPmp(NatPmpResp),
    /// A NAT-PMP-only router answered a PCP request "unsupported version":
    /// use NAT-PMP with it.
    NatPmpOnly,
}

/// A PCP response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcpResp {
    pub opcode: u8,
    /// [`PCP_SUCCESS`] or another RFC 6887 §7.4 code.
    pub result: u8,
    /// The granted lifetime; for an error, how long the error should last.
    pub lifetime: u32,
    /// The server's epoch time ([`EpochWatch`]).
    pub epoch: u32,
    /// The MAP data of a MAP response. Only an error may come without it.
    pub map: Option<MapResp>,
}

/// The MAP opcode data of a PCP response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapResp {
    pub nonce: [u8; 12],
    /// IANA protocol number as the router sent it ([`Proto::from_iana`]).
    pub proto: u8,
    pub internal_port: u16,
    /// The assigned external port.
    pub external_port: u16,
    /// The assigned external address, in the 16-byte form.
    pub external_ip: Ipv6Addr,
}

impl MapResp {
    /// The assigned external address ([`from_v6_form`]).
    pub fn external_addr(&self) -> IpAddr {
        from_v6_form(self.external_ip)
    }
}

/// A NAT-PMP response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatPmpResp {
    ExternalAddr {
        result: u16,
        epoch: u32,
        external: Ipv4Addr,
    },
    Map {
        proto: Proto,
        result: u16,
        epoch: u32,
        internal_port: u16,
        external_port: u16,
        lifetime: u32,
    },
}

impl NatPmpResp {
    /// [`NATPMP_SUCCESS`] or another RFC 6886 §3.5 code.
    pub fn result(&self) -> u16 {
        match *self {
            Self::ExternalAddr { result, .. } | Self::Map { result, .. } => result,
        }
    }

    /// Seconds since the router's start of epoch ([`EpochWatch`]).
    pub fn epoch(&self) -> u32 {
        match *self {
            Self::ExternalAddr { epoch, .. } | Self::Map { epoch, .. } => epoch,
        }
    }
}

/// Why [`decode_reply`] refused a datagram. [`ReplyError::code`] is the
/// reason the shared vectors and the Python reference name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    #[error("no request of that protocol is outstanding")]
    Unexpected,
    #[error("bad length")]
    Length,
    #[error("unknown version")]
    Version,
    #[error("not a response (R bit clear)")]
    NotResponse,
    #[error("opcode does not answer the request")]
    Opcode,
    #[error("unknown mandatory option")]
    MandatoryOption,
    #[error("malformed option")]
    MalformedOption,
}

impl ReplyError {
    /// The reason's name in the vectors.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unexpected => "unexpected",
            Self::Length => "length",
            Self::Version => "version",
            Self::NotResponse => "not_response",
            Self::Opcode => "opcode",
            Self::MandatoryOption => "mandatory_option",
            Self::MalformedOption => "malformed_option",
        }
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Strict decode of a datagram from the gateway socket, given the opcodes
/// of the requests outstanding (`None`: nothing of that protocol sent).
///
/// - PCP (version 2): 24..=[`MAX_PCP`] bytes, a multiple of 4; R set; the
///   opcode sent; a MAP response carries its 36 bytes of data unless it is
///   an error; options: one of code 128 or more is skipped, one below 128
///   is unknown (Raven sends none) and refuses the reply, lengths must fit.
/// - NAT-PMP (version 0): opcode 128 + the opcode sent; exactly 12 bytes
///   (external address) or 16 (mapping).
/// - A version-0 reply with result 1 to a PCP request, 8, 12 or 16 bytes,
///   opcode 0 (the RFC 6886 §3.5 figure) or 128 + the PCP opcode (what
///   miniupnpd sends): [`Reply::NatPmpOnly`] (RFC 6887 §9).
///
/// Matching a MAP response to its mapping (nonce, protocol, internal port)
/// is the caller's.
pub fn decode_reply(
    b: &[u8],
    sent_pcp_op: Option<u8>,
    sent_natpmp_op: Option<u8>,
) -> Result<Reply, ReplyError> {
    match b.first() {
        None => Err(ReplyError::Length),
        Some(&PCP_VERSION) => {
            let op = sent_pcp_op.ok_or(ReplyError::Unexpected)?;
            decode_pcp(b, op).map(Reply::Pcp)
        }
        Some(&NATPMP_VERSION) => {
            if sent_pcp_op.is_some_and(|op| natpmp_only(b, op)) {
                return Ok(Reply::NatPmpOnly);
            }
            let op = sent_natpmp_op.ok_or(ReplyError::Unexpected)?;
            decode_natpmp(b, op).map(Reply::NatPmp)
        }
        Some(_) => Err(ReplyError::Version),
    }
}

fn natpmp_only(b: &[u8], sent_pcp_op: u8) -> bool {
    matches!(b.len(), 8 | 12 | 16)
        && (b[1] == 0 || b[1] == RESPONSE_BIT | sent_pcp_op)
        && be16(&b[2..4]) == NATPMP_UNSUPP_VERSION
}

fn decode_pcp(b: &[u8], sent_op: u8) -> Result<PcpResp, ReplyError> {
    if b.len() < PCP_HEADER || b.len() > MAX_PCP || !b.len().is_multiple_of(4) {
        return Err(ReplyError::Length);
    }
    if b[1] & RESPONSE_BIT == 0 {
        return Err(ReplyError::NotResponse);
    }
    let opcode = b[1] & 0x7f;
    if opcode != sent_op || opcode > PCP_OP_MAP {
        return Err(ReplyError::Opcode);
    }
    let result = b[3];
    let mut at = PCP_HEADER;
    let mut map = None;
    if opcode == PCP_OP_MAP {
        if b.len() >= PCP_HEADER + MAP_DATA {
            let d = &b[at..at + MAP_DATA];
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&d[..12]);
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&d[20..36]);
            map = Some(MapResp {
                nonce,
                proto: d[12],
                internal_port: be16(&d[16..18]),
                external_port: be16(&d[18..20]),
                external_ip: Ipv6Addr::from(ip),
            });
            at += MAP_DATA;
        } else if result == PCP_SUCCESS {
            return Err(ReplyError::Length);
        }
    }
    check_options(&b[at..])?;
    Ok(PcpResp {
        opcode,
        result,
        lifetime: be32(&b[4..8]),
        epoch: be32(&b[8..12]),
        map,
    })
}

/// Options: code u8, reserved u8, length u16, then the data padded to a
/// multiple of 4 bytes.
fn check_options(mut rest: &[u8]) -> Result<(), ReplyError> {
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(ReplyError::MalformedOption);
        }
        let padded = (usize::from(be16(&rest[2..4])) + 3) & !3;
        if 4 + padded > rest.len() {
            return Err(ReplyError::MalformedOption);
        }
        if rest[0] < 128 {
            return Err(ReplyError::MandatoryOption);
        }
        rest = &rest[4 + padded..];
    }
    Ok(())
}

fn decode_natpmp(b: &[u8], sent_op: u8) -> Result<NatPmpResp, ReplyError> {
    if b.len() < 2 {
        return Err(ReplyError::Length);
    }
    if b[1] & RESPONSE_BIT == 0 {
        return Err(ReplyError::NotResponse);
    }
    if sent_op > NATPMP_OP_MAP_TCP || b[1] != RESPONSE_BIT | sent_op {
        return Err(ReplyError::Opcode);
    }
    let want = if sent_op == NATPMP_OP_EXTERNAL_ADDR {
        12
    } else {
        16
    };
    if b.len() != want {
        return Err(ReplyError::Length);
    }
    let (result, epoch) = (be16(&b[2..4]), be32(&b[4..8]));
    if sent_op == NATPMP_OP_EXTERNAL_ADDR {
        return Ok(NatPmpResp::ExternalAddr {
            result,
            epoch,
            external: Ipv4Addr::new(b[8], b[9], b[10], b[11]),
        });
    }
    Ok(NatPmpResp::Map {
        proto: if sent_op == NATPMP_OP_MAP_UDP {
            Proto::Udp
        } else {
            Proto::Tcp
        },
        result,
        epoch,
        internal_port: be16(&b[8..10]),
        external_port: be16(&b[10..12]),
        lifetime: be32(&b[12..16]),
    })
}

/// The server-epoch check of RFC 6887 §8.5, also used for NAT-PMP's seconds
/// since start of epoch: one per gateway, fed every reply's epoch.
#[derive(Clone, Copy, Debug, Default)]
pub struct EpochWatch {
    last: Option<(u32, Instant)>,
}

impl EpochWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the epoch of a reply received at `now`; true when the server
    /// lost its state (every mapping must be requested again at once): the
    /// epoch went back more than one second (`curr + 1 < prev`), or it and
    /// the client's clock drifted apart by more than 1/16 plus 2 seconds
    /// (`c + 2 < s - s/16` or `s + 2 < c - c/16`, `c` the client's whole
    /// seconds since the previous reply, `s = curr - prev` or 0). The first
    /// reply is always valid.
    pub fn lost(&mut self, server: u32, now: Instant) -> bool {
        let lost = match self.last {
            None => false,
            Some((prev, at)) => {
                if u64::from(server) + 1 < u64::from(prev) {
                    true
                } else {
                    let c = now.saturating_duration_since(at).as_secs();
                    let s = u64::from(server.saturating_sub(prev));
                    c + 2 < s - s / 16 || s + 2 < c - c / 16
                }
            }
        };
        self.last = Some((server, now));
        lost
    }

    /// Forget the gateway (a new network or router).
    pub fn reset(&mut self) {
        self.last = None;
    }
}

/// The MAP nonce key of this profile: `SHA-256(NONCE_KEY_DOMAIN || raven
/// seed)`.
pub fn nonce_key(id: &Identity) -> Zeroizing<[u8; 32]> {
    let seed = id.seed_zeroizing();
    let mut h = Sha256::new();
    h.update(NONCE_KEY_DOMAIN);
    h.update(seed.as_slice());
    Zeroizing::new(h.finalize().into())
}

/// The MAP nonce of one internal endpoint behind one router: `SHA-256(key
/// || gateway IP (16 bytes, IPv4-mapped) || internal IP (16 bytes) ||
/// protocol || be16 port)[0..12]`. Stable across restarts on one network,
/// so a renewal or a delete matches the router's mapping; another router
/// address or another profile's key gives other nonces, so routers on other
/// networks do not see the same value (§12).
pub fn pcp_nonce(
    key: &[u8; 32],
    gateway: IpAddr,
    internal: IpAddr,
    proto: Proto,
    port: u16,
) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(key);
    h.update(v6_form(gateway).octets());
    h.update(v6_form(internal).octets());
    h.update([proto as u8]);
    h.update(port.to_be_bytes());
    let digest = h.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

// ---------------------------------------------------------------------------
// MapperCore: the client state machine of one address family (§6-§9).
// ---------------------------------------------------------------------------

/// When the probe goes out, in milliseconds from its start (§6; the short
/// schedule is the profile's written deviation from RFC 6887 §8.1.1).
pub const PROBE_AT_MS: [u64; 4] = [0, 250, 750, 1750];
/// The probe ends this long after its start: [`Out::NoServer`].
pub const PROBE_END_MS: u64 = 3750;
/// How long a NAT-PMP answer to the probe waits for a PCP answer, which wins.
pub const PCP_GRACE_MS: u64 = 250;
/// Initial retransmission time of a mapping request or renewal (RFC 6887
/// §8.1.1); it doubles after every try.
pub const MAP_IRT_S: u64 = 3;
/// Tries of one mapping request or renewal: sent at 0, 3 and 9 s, given up
/// at 21 s.
pub const MAP_TRIES: u32 = 3;
/// Floor of the wait after NO_RESOURCES or NETWORK_FAILURE.
pub const MIN_RETRY_S: u32 = 60;
/// Cap of every wait before asking again: after an error, and after a
/// request that got no answer.
pub const MAX_RETRY_S: u32 = 1800;

/// The protocol a family's router answered in (§6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Via {
    Pcp,
    NatPmp,
}

/// What a [`MapperCore`] asks its driver to send, or reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    /// Send this datagram to the gateway (on the driver's socket connected
    /// to it).
    Send(Vec<u8>),
    /// The router maps `internal_port` of `proto` at `external`, a routable
    /// address (§9).
    Mapped {
        via: Via,
        proto: Proto,
        internal_port: u16,
        external: SocketAddr,
    },
    /// A mapping [`Out::Mapped`] reported is gone: its lifetime ended, its
    /// external address or port changed, Raven deleted it, or the core
    /// stopped. Every `Mapped` is followed by one `Expired` at the latest
    /// at [`MapperCore::shutdown`].
    Expired {
        via: Via,
        proto: Proto,
        internal_port: u16,
        external: SocketAddr,
    },
    /// The probe got no answer, neither PCP nor NAT-PMP; the core stops
    /// (IPv4 falls back to UPnP-IGD).
    NoServer,
    /// The router refused, `code` its PCP or NAT-PMP result code (§8).
    /// NOT_AUTHORIZED and ADDRESS_MISMATCH stop the core (after deleting
    /// the mappings the router granted); another code stops that mapping
    /// only.
    Refused { via: Via, code: u16 },
    /// The router's external address is not routable (§9): its mappings
    /// were deleted and the core stops. `carrier`: the address is in the
    /// shared 100.64.0.0/10 of a provider's carrier-grade NAT; otherwise
    /// (RFC 1918 and the other non-global ranges) the router sits behind
    /// another router of the same site, a double NAT the user can fix.
    NonRoutable { carrier: bool },
    /// The router lost its state (§7): every wanted mapping not already in
    /// flight was asked again at once.
    ServerRestarted { via: Via },
}

/// [`Out::NonRoutable`] for the non-global external address `ip`: carrier
/// NAT for 100.64.0.0/10 (RFC 6598), a double NAT for any other.
pub fn non_routable(ip: IpAddr) -> Out {
    let carrier = match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64,
        IpAddr::V6(_) => false,
    };
    Out::NonRoutable { carrier }
}

/// Settings of a [`MapperCore`].
#[derive(Clone)]
pub struct MapperConfig {
    /// The lifetime every request asks for: [`REQUESTED_LIFETIME_S`], or
    /// the lab's (`portmap_gate::lab_portmap_lifetime`).
    pub lifetime: u32,
    /// [`nonce_key`] of the profile.
    pub nonce_key: Zeroizing<[u8; 32]>,
    /// The router this core asks (the address its driver's socket is
    /// connected to): part of every MAP nonce ([`pcp_nonce`]).
    pub gateway: IpAddr,
    /// Lab only: a loopback external address counts as routable (a fake
    /// gateway on the loopback). Any other non-global address stays
    /// [`Out::NonRoutable`].
    pub any_ip: bool,
}

impl MapperConfig {
    /// The production settings for the router at `gateway`:
    /// [`REQUESTED_LIFETIME_S`], global external addresses only.
    pub fn new(nonce_key: Zeroizing<[u8; 32]>, gateway: IpAddr) -> Self {
        Self {
            lifetime: REQUESTED_LIFETIME_S,
            nonce_key,
            gateway,
            any_ip: false,
        }
    }
}

impl std::fmt::Debug for MapperConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapperConfig")
            .field("lifetime", &self.lifetime)
            .field("nonce_key", &"<redacted>")
            .field("gateway", &"<redacted>")
            .field("any_ip", &self.any_ip)
            .finish()
    }
}

/// Retransmission of one request (RFC 6887 §8.1.1 timing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Retx {
    tries: u32,
    next: Instant,
}

impl Retx {
    fn first(now: Instant) -> Self {
        Self {
            tries: 1,
            next: now + Duration::from_secs(MAP_IRT_S),
        }
    }

    /// The next try once `next` has passed; `None` after [`MAP_TRIES`].
    fn again(self) -> Option<Self> {
        (self.tries < MAP_TRIES).then(|| Self {
            tries: self.tries + 1,
            next: self.next + Duration::from_secs(MAP_IRT_S << self.tries),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Waiting for the probe to choose the protocol.
    Idle,
    /// A request (new or renewal) is out.
    Asking(Retx),
    RenewAt(Instant),
    RetryAt(Instant),
    /// Not asked again: refused, or its protocol is not mapped.
    Stopped,
}

/// A mapping the core reported ([`Out::Mapped`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Lease {
    external: SocketAddr,
    expires: Instant,
}

/// One wanted mapping: an internal port of one protocol.
#[derive(Clone, Copy, Debug)]
struct Entry {
    proto: Proto,
    port: u16,
    nonce: [u8; 12],
    /// The external port to suggest: the internal port, then the one
    /// granted, 0 after CANNOT_PROVIDE_EXTERNAL.
    suggested: u16,
    /// A request went out, so the router may hold it (a delete is owed).
    asked: bool,
    lease: Option<Lease>,
    phase: Phase,
}

#[derive(Clone, Copy, Debug)]
struct Probe {
    start: Instant,
    /// Probe rounds sent ([`PROBE_AT_MS`]).
    rounds: usize,
    /// The router answered the PCP probe as a NAT-PMP-only router.
    pcp_off: bool,
    /// The first successful NAT-PMP answer: external address, epoch, when.
    natpmp: Option<(Ipv4Addr, u32, Instant)>,
}

#[derive(Clone, Copy, Debug)]
enum State {
    Probing(Probe),
    Active(Via),
    /// No server, refused, not routable or shut down: nothing more is sent.
    Halted,
}

/// What the profile does with a result code (§8).
enum Action {
    Success,
    CannotProvide,
    Retry,
    Stop,
    DropProto,
    Other,
}

fn action(via: Via, code: u16) -> Action {
    match via {
        Via::Pcp => match u8::try_from(code).unwrap_or(u8::MAX) {
            PCP_SUCCESS => Action::Success,
            PCP_CANNOT_PROVIDE_EXTERNAL => Action::CannotProvide,
            PCP_NETWORK_FAILURE | PCP_NO_RESOURCES => Action::Retry,
            PCP_NOT_AUTHORIZED | PCP_ADDRESS_MISMATCH => Action::Stop,
            PCP_UNSUPP_PROTOCOL => Action::DropProto,
            _ => Action::Other,
        },
        Via::NatPmp => match code {
            NATPMP_SUCCESS => Action::Success,
            NATPMP_NETWORK_FAILURE | NATPMP_OUT_OF_RESOURCES => Action::Retry,
            NATPMP_NOT_AUTHORIZED => Action::Stop,
            NATPMP_UNSUPP_OPCODE => Action::DropProto,
            _ => Action::Other,
        },
    }
}

/// The sans-IO port-mapping client of one address family and one gateway:
/// it says what to send ([`Out::Send`]) and what happened; its driver owns
/// the socket and the clock, calls [`MapperCore::on_datagram`] for every
/// datagram from the gateway and [`MapperCore::on_tick`] at
/// [`MapperCore::next_wake`]. A new network or gateway is a new core.
///
/// - [`MapperCore::new`] sends the probe: PCP ANNOUNCE and, for IPv4, a
///   NAT-PMP external address request, at [`PROBE_AT_MS`]; PCP wins, NAT-PMP
///   is chosen [`PCP_GRACE_MS`] after its answer (at once after a
///   NAT-PMP-only answer), and silence until [`PROBE_END_MS`] is
///   [`Out::NoServer`].
/// - Mappings ([`MapperCore::want`]) ask for [`MapperConfig::lifetime`],
///   suggest the internal port, carry the profile's nonce ([`pcp_nonce`]),
///   and are renewed at half the granted lifetime, however short, so a
///   lease never ends before its renewal (RFC 6887 §11.2.1).
/// - Requests and renewals are tried [`MAP_TRIES`] times; after that the
///   mapping stays until its lifetime ends and is asked again after
///   [`MAX_RETRY_S`] or at that end, whichever comes first.
/// - Result codes, external addresses and the epoch follow §7-§9.
pub struct MapperCore {
    client: IpAddr,
    cfg: MapperConfig,
    state: State,
    watch: EpochWatch,
    /// NAT-PMP: the router's external address.
    ext: Option<IpAddr>,
    /// NAT-PMP: an external address request is out (sent with renewals).
    ext_ask: Option<Retx>,
    /// Protocols the router does not map (UNSUPP_PROTOCOL).
    dropped: Vec<Proto>,
    entries: Vec<Entry>,
}

impl MapperCore {
    /// A core for the client address `client` (the egress address of the
    /// family, which every PCP request names), started at `now`; the
    /// returned [`Out::Send`]s are the probe's first round.
    pub fn new(client: IpAddr, mut cfg: MapperConfig, now: Instant) -> (Self, Vec<Out>) {
        cfg.lifetime = cfg.lifetime.max(1);
        let mut core = Self {
            client,
            cfg,
            state: State::Probing(Probe {
                start: now,
                rounds: 0,
                pcp_off: false,
                natpmp: None,
            }),
            watch: EpochWatch::new(),
            ext: None,
            ext_ask: None,
            dropped: Vec::new(),
            entries: Vec::new(),
        };
        let mut out = Vec::new();
        core.probe_tick(now, &mut out);
        (core, out)
    }

    /// The protocol chosen, once the probe has ended with an answer.
    pub fn via(&self) -> Option<Via> {
        match self.state {
            State::Active(via) => Some(via),
            _ => None,
        }
    }

    /// True once the core sends nothing more: no server, refused, not
    /// routable, or shut down.
    pub fn is_halted(&self) -> bool {
        matches!(self.state, State::Halted)
    }

    /// Map `port` of `proto` (a listen port of the client address); asked
    /// at once when the protocol is known, else when the probe ends.
    pub fn want(&mut self, proto: Proto, port: u16, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        if port == 0 || self.find(proto, port).is_some() {
            return out;
        }
        let phase = if self.dropped.contains(&proto) {
            Phase::Stopped
        } else {
            Phase::Idle
        };
        self.entries.push(Entry {
            proto,
            port,
            nonce: pcp_nonce(
                &self.cfg.nonce_key,
                self.cfg.gateway,
                self.client,
                proto,
                port,
            ),
            suggested: port,
            asked: false,
            lease: None,
            phase,
        });
        if phase == Phase::Idle && self.via().is_some() {
            self.ask(self.entries.len() - 1, now, &mut out);
        }
        out
    }

    /// Stop mapping `port` of `proto`: its [`Out::Expired`] if it was
    /// mapped, and a delete (lifetime 0) if it was ever asked.
    pub fn unwant(&mut self, proto: Proto, port: u16) -> Vec<Out> {
        let mut out = Vec::new();
        if let Some(i) = self.find(proto, port) {
            let e = self.entries.remove(i);
            if let Some(via) = self.via() {
                self.release(via, &e, true, &mut out);
            }
        }
        out
    }

    /// Delete every mapping (lifetime 0) and stop; the driver sends the
    /// deletes once, best effort.
    pub fn shutdown(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        self.halt(true, &mut out);
        self.entries.clear();
        out
    }

    /// When [`MapperCore::on_tick`] has something to do; `None` once halted
    /// or idle.
    pub fn next_wake(&self) -> Option<Instant> {
        match self.state {
            State::Halted => None,
            State::Probing(p) => {
                let mut at = p.start + Duration::from_millis(PROBE_END_MS);
                if let Some(ms) = PROBE_AT_MS.get(p.rounds) {
                    at = at.min(p.start + Duration::from_millis(*ms));
                }
                if let Some((_, _, t)) = p.natpmp {
                    at = at.min(t + Duration::from_millis(PCP_GRACE_MS));
                }
                Some(at)
            }
            State::Active(_) => {
                let entries = self.entries.iter().flat_map(|e| {
                    let phase = match e.phase {
                        Phase::Asking(r) => Some(r.next),
                        Phase::RenewAt(t) | Phase::RetryAt(t) => Some(t),
                        Phase::Idle | Phase::Stopped => None,
                    };
                    phase.into_iter().chain(e.lease.map(|l| l.expires))
                });
                entries.chain(self.ext_ask.map(|r| r.next)).min()
            }
        }
    }

    /// Timers due at `now`: probe rounds and its end, retransmissions,
    /// renewals, retries and lifetimes.
    pub fn on_tick(&mut self, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        match self.state {
            State::Probing(_) => self.probe_tick(now, &mut out),
            State::Active(via) => self.active_tick(via, now, &mut out),
            State::Halted => {}
        }
        out
    }

    /// A datagram from the gateway, received at `now`. Anything that is not
    /// a valid answer to something outstanding, or names a mapping this
    /// core does not hold, is ignored like a datagram that never came.
    pub fn on_datagram(&mut self, b: &[u8], now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        match self.state {
            State::Probing(_) => self.probe_datagram(b, now, &mut out),
            State::Active(via) => self.active_datagram(via, b, now, &mut out),
            State::Halted => {}
        }
        out
    }

    fn find(&self, proto: Proto, port: u16) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.proto == proto && e.port == port)
    }

    fn routable(&self, ip: IpAddr) -> bool {
        crate::p2p_route::is_global_ip(ip) || (self.cfg.any_ip && ip.is_loopback())
    }

    /// The request for `e` with `lifetime`; 0 is a delete (suggested port 0).
    fn request(&self, via: Via, e: &Entry, lifetime: u32) -> Vec<u8> {
        let suggested = if lifetime == 0 { 0 } else { e.suggested };
        match via {
            Via::Pcp => {
                let map = MapReq {
                    nonce: e.nonce,
                    proto: e.proto,
                    internal_port: e.port,
                    suggested_port: suggested,
                    suggested_ip: unspecified_external(self.client),
                };
                pcp_request(PCP_OP_MAP, lifetime, self.client, Some(&map))
            }
            Via::NatPmp => natpmp_request(e.proto.natpmp_op(), e.port, suggested, lifetime),
        }
    }

    /// Send the request of entry `i` now (a new mapping or a renewal); with
    /// NAT-PMP a renewal also asks for the external address again.
    fn ask(&mut self, i: usize, now: Instant, out: &mut Vec<Out>) {
        let Some(via) = self.via() else {
            return;
        };
        let e = &mut self.entries[i];
        e.asked = true;
        e.phase = Phase::Asking(Retx::first(now));
        let renewal = e.lease.is_some();
        let e = *e;
        out.push(Out::Send(self.request(via, &e, self.cfg.lifetime)));
        if via == Via::NatPmp && renewal && self.ext_ask.is_none() {
            self.ext_ask = Some(Retx::first(now));
            out.push(Out::Send(natpmp_request(NATPMP_OP_EXTERNAL_ADDR, 0, 0, 0)));
        }
    }

    /// Report `e` gone ([`Out::Expired`] if mapped) and, with `delete`,
    /// send its delete if it was ever asked.
    fn release(&self, via: Via, e: &Entry, delete: bool, out: &mut Vec<Out>) {
        if let Some(l) = e.lease {
            out.push(Out::Expired {
                via,
                proto: e.proto,
                internal_port: e.port,
                external: l.external,
            });
        }
        if delete && e.asked {
            out.push(Out::Send(self.request(via, e, 0)));
        }
    }

    /// Stop for good: every mapping expires, deleted with `delete`.
    fn halt(&mut self, delete: bool, out: &mut Vec<Out>) {
        if let Some(via) = self.via() {
            for e in &self.entries {
                self.release(via, e, delete, out);
            }
        }
        for e in &mut self.entries {
            e.lease = None;
            e.phase = Phase::Stopped;
        }
        self.ext_ask = None;
        self.state = State::Halted;
    }

    fn probe_tick(&mut self, now: Instant, out: &mut Vec<Out>) {
        let client = self.client;
        let State::Probing(p) = &mut self.state else {
            return;
        };
        if let Some((ext, epoch, at)) = p.natpmp {
            if p.pcp_off || now >= at + Duration::from_millis(PCP_GRACE_MS) {
                self.watch.lost(epoch, at);
                self.choose_natpmp(ext, now, out);
                return;
            }
        }
        let elapsed = now.saturating_duration_since(p.start);
        if elapsed >= Duration::from_millis(PROBE_END_MS) {
            self.state = State::Halted;
            out.push(Out::NoServer);
            return;
        }
        let due = PROBE_AT_MS
            .iter()
            .filter(|ms| elapsed >= Duration::from_millis(**ms))
            .count();
        if due > p.rounds {
            p.rounds = due;
            if !p.pcp_off {
                out.push(Out::Send(pcp_request(PCP_OP_ANNOUNCE, 0, client, None)));
            }
            if client.is_ipv4() && p.natpmp.is_none() {
                out.push(Out::Send(natpmp_request(NATPMP_OP_EXTERNAL_ADDR, 0, 0, 0)));
            }
        }
    }

    fn probe_datagram(&mut self, b: &[u8], now: Instant, out: &mut Vec<Out>) {
        let v4 = self.client.is_ipv4();
        let State::Probing(p) = &mut self.state else {
            return;
        };
        let pcp = (!p.pcp_off).then_some(PCP_OP_ANNOUNCE);
        let natpmp = v4.then_some(NATPMP_OP_EXTERNAL_ADDR);
        match decode_reply(b, pcp, natpmp) {
            Ok(Reply::Pcp(r)) => {
                self.state = State::Active(Via::Pcp);
                self.watch.lost(r.epoch, now);
                if let Action::Stop = action(Via::Pcp, u16::from(r.result)) {
                    out.push(Out::Refused {
                        via: Via::Pcp,
                        code: u16::from(r.result),
                    });
                    self.halt(false, out);
                    return;
                }
                self.ask_idle(now, out);
            }
            Ok(Reply::NatPmpOnly) => {
                p.pcp_off = true;
                if let Some((ext, epoch, at)) = p.natpmp {
                    self.watch.lost(epoch, at);
                    self.choose_natpmp(ext, now, out);
                }
            }
            Ok(Reply::NatPmp(NatPmpResp::ExternalAddr {
                result: NATPMP_SUCCESS,
                epoch,
                external,
            })) if p.natpmp.is_none() => {
                p.natpmp = Some((external, epoch, now));
                if p.pcp_off {
                    self.watch.lost(epoch, now);
                    self.choose_natpmp(external, now, out);
                }
            }
            _ => {}
        }
    }

    fn choose_natpmp(&mut self, ext: Ipv4Addr, now: Instant, out: &mut Vec<Out>) {
        self.state = State::Active(Via::NatPmp);
        let ext = IpAddr::V4(ext);
        self.ext = Some(ext);
        if !self.routable(ext) {
            out.push(non_routable(ext));
            self.halt(true, out);
            return;
        }
        self.ask_idle(now, out);
    }

    /// Ask every mapping wanted during the probe.
    fn ask_idle(&mut self, now: Instant, out: &mut Vec<Out>) {
        for i in 0..self.entries.len() {
            if self.entries[i].phase == Phase::Idle {
                self.ask(i, now, out);
            }
        }
    }

    fn active_tick(&mut self, via: Via, now: Instant, out: &mut Vec<Out>) {
        if let Some(r) = self.ext_ask.filter(|r| now >= r.next) {
            self.ext_ask = r.again();
            if self.ext_ask.is_some() {
                out.push(Out::Send(natpmp_request(NATPMP_OP_EXTERNAL_ADDR, 0, 0, 0)));
            }
        }
        for i in 0..self.entries.len() {
            let mut e = self.entries[i];
            if let Some(l) = e.lease.filter(|l| now >= l.expires) {
                out.push(Out::Expired {
                    via,
                    proto: e.proto,
                    internal_port: e.port,
                    external: l.external,
                });
                e.lease = None;
            }
            match e.phase {
                Phase::Asking(r) if now >= r.next => match r.again() {
                    Some(next) => {
                        e.phase = Phase::Asking(next);
                        out.push(Out::Send(self.request(via, &e, self.cfg.lifetime)));
                    }
                    None => {
                        let cap = now + Duration::from_secs(u64::from(MAX_RETRY_S));
                        e.phase = Phase::RetryAt(e.lease.map_or(cap, |l| l.expires.min(cap)));
                    }
                },
                Phase::RenewAt(t) | Phase::RetryAt(t) if now >= t => {
                    self.entries[i] = e;
                    self.ask(i, now, out);
                    continue;
                }
                _ => {}
            }
            self.entries[i] = e;
        }
    }

    fn active_datagram(&mut self, via: Via, b: &[u8], now: Instant, out: &mut Vec<Out>) {
        match via {
            Via::Pcp => {
                let Ok(Reply::Pcp(r)) = decode_reply(b, Some(PCP_OP_MAP), None) else {
                    return;
                };
                let Some(m) = r.map else {
                    return;
                };
                let Some(i) = self.entries.iter().position(|e| {
                    e.nonce == m.nonce && e.proto as u8 == m.proto && e.port == m.internal_port
                }) else {
                    return;
                };
                let granted = (m.external_addr(), m.external_port);
                let code = u16::from(r.result);
                self.answer(via, i, code, r.lifetime, r.epoch, Some(granted), now, out);
            }
            Via::NatPmp => {
                let reply = [
                    NATPMP_OP_EXTERNAL_ADDR,
                    NATPMP_OP_MAP_UDP,
                    NATPMP_OP_MAP_TCP,
                ]
                .into_iter()
                .find_map(|op| match decode_reply(b, None, Some(op)) {
                    Ok(Reply::NatPmp(n)) => Some(n),
                    _ => None,
                });
                match reply {
                    Some(NatPmpResp::ExternalAddr {
                        result,
                        epoch,
                        external,
                    }) if self.ext_ask.is_some() => {
                        self.ext_ask = None;
                        if result != NATPMP_SUCCESS {
                            return;
                        }
                        let lost = self.watch.lost(epoch, now);
                        if lost {
                            out.push(Out::ServerRestarted { via });
                        }
                        self.external_addr(via, IpAddr::V4(external), out);
                        if lost {
                            self.remap(None, now, out);
                        }
                    }
                    Some(NatPmpResp::Map {
                        proto,
                        result,
                        epoch,
                        internal_port,
                        external_port,
                        lifetime,
                    }) => {
                        let Some(i) = self.find(proto, internal_port) else {
                            return;
                        };
                        let granted = self.ext.map(|ip| (ip, external_port));
                        self.answer(via, i, result, lifetime, epoch, granted, now, out);
                    }
                    _ => {}
                }
            }
        }
    }

    /// The router's answer `code` for entry `i`: lifetime, epoch and the
    /// external address and port it granted.
    #[allow(clippy::too_many_arguments)]
    fn answer(
        &mut self,
        via: Via,
        i: usize,
        code: u16,
        lifetime: u32,
        epoch: u32,
        granted: Option<(IpAddr, u16)>,
        now: Instant,
        out: &mut Vec<Out>,
    ) {
        if self.entries[i].phase == Phase::Stopped {
            return;
        }
        let lost = self.watch.lost(epoch, now);
        if lost {
            out.push(Out::ServerRestarted { via });
        }
        let mut answered = None;
        match action(via, code) {
            Action::Success => {
                // Lifetime 0 answers a delete; port 0 maps nothing.
                if let Some((ip, port)) = granted.filter(|(_, p)| lifetime > 0 && *p != 0) {
                    if !self.routable(ip) {
                        out.push(non_routable(ip));
                        self.halt(true, out);
                        return;
                    }
                    self.granted(via, i, SocketAddr::new(ip, port), lifetime, now, out);
                    answered = Some(i);
                }
            }
            Action::CannotProvide if self.entries[i].suggested != 0 => {
                self.entries[i].suggested = 0;
                self.ask(i, now, out);
                answered = Some(i);
            }
            Action::CannotProvide | Action::Retry => {
                let wait = lifetime.clamp(MIN_RETRY_S, MAX_RETRY_S);
                self.entries[i].phase = Phase::RetryAt(now + Duration::from_secs(u64::from(wait)));
            }
            Action::Stop => {
                out.push(Out::Refused { via, code });
                // Stop asking, but delete what the router still forwards
                // (§6, §8): the driver ends with the core, so no later
                // shutdown could. The refused request holds nothing unless
                // it renewed a lease.
                if self.entries[i].lease.is_none() {
                    self.entries[i].asked = false;
                }
                self.halt(true, out);
                return;
            }
            Action::DropProto => {
                let proto = self.entries[i].proto;
                self.dropped.push(proto);
                for j in 0..self.entries.len() {
                    if self.entries[j].proto == proto {
                        self.stop_entry(via, j, out);
                    }
                }
            }
            Action::Other => {
                out.push(Out::Refused { via, code });
                self.stop_entry(via, i, out);
            }
        }
        if lost {
            self.remap(answered, now, out);
        }
    }

    fn stop_entry(&mut self, via: Via, i: usize, out: &mut Vec<Out>) {
        let e = self.entries[i];
        self.release(via, &e, false, out);
        self.entries[i].lease = None;
        self.entries[i].phase = Phase::Stopped;
    }

    /// The server lost its state: ask every mapping again at once, except
    /// `skip` (just answered) and those already in flight or stopped.
    fn remap(&mut self, skip: Option<usize>, now: Instant, out: &mut Vec<Out>) {
        for j in 0..self.entries.len() {
            let waiting = matches!(self.entries[j].phase, Phase::RenewAt(_) | Phase::RetryAt(_));
            if Some(j) != skip && waiting {
                self.ask(j, now, out);
            }
        }
    }

    /// A mapping was granted: report it if new or moved, renew at half the
    /// lifetime.
    fn granted(
        &mut self,
        via: Via,
        i: usize,
        external: SocketAddr,
        lifetime: u32,
        now: Instant,
        out: &mut Vec<Out>,
    ) {
        let e = self.entries[i];
        let old = e.lease.map(|l| l.external);
        if old != Some(external) {
            self.release(via, &e, false, out);
            out.push(Out::Mapped {
                via,
                proto: e.proto,
                internal_port: e.port,
                external,
            });
        }
        // Half the granted lifetime, in milliseconds: strictly before the
        // lease ends even when the router grants a minute or less (a floor
        // past the lease's end let the mapping lapse and come back every
        // round).
        let renew = Duration::from_millis(u64::from(lifetime) * 500);
        let e = &mut self.entries[i];
        e.lease = Some(Lease {
            external,
            expires: now + Duration::from_secs(u64::from(lifetime)),
        });
        e.suggested = external.port();
        e.phase = Phase::RenewAt(now + renew);
        // A new external address: renew the others now to learn theirs.
        if old.is_some_and(|o| o.ip() != external.ip()) {
            for j in 0..self.entries.len() {
                let e = self.entries[j];
                if j != i && e.lease.is_some() && matches!(e.phase, Phase::RenewAt(_)) {
                    self.ask(j, now, out);
                }
            }
        }
    }

    /// NAT-PMP: the router's external address; a change moves every
    /// mapping (Expired, then Mapped at the same port).
    fn external_addr(&mut self, via: Via, ip: IpAddr, out: &mut Vec<Out>) {
        if !self.routable(ip) {
            out.push(non_routable(ip));
            self.halt(true, out);
            return;
        }
        if self.ext == Some(ip) {
            return;
        }
        self.ext = Some(ip);
        for i in 0..self.entries.len() {
            let e = self.entries[i];
            let Some(l) = e.lease else {
                continue;
            };
            let external = SocketAddr::new(ip, l.external.port());
            self.release(via, &e, false, out);
            out.push(Out::Mapped {
                via,
                proto: e.proto,
                internal_port: e.port,
                external,
            });
            self.entries[i].lease = Some(Lease { external, ..l });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portmap_fake::{FakeGateway, Mode};
    use serde_json::{json, Value};
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    fn vectors_dir() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors/rvn1/portmap")
    }

    fn vector(name: &str) -> Value {
        let path = vectors_dir().join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(&text).unwrap()
    }

    fn names_in(dir: PathBuf) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        names
    }

    fn hex_of(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    fn op_of(v: &Value) -> Option<u8> {
        v.as_u64().map(|n| u8::try_from(n).unwrap())
    }

    fn u16_of(v: &Value) -> u16 {
        u16::try_from(v.as_u64().unwrap()).unwrap()
    }

    fn u32_of(v: &Value) -> u32 {
        u32::try_from(v.as_u64().unwrap()).unwrap()
    }

    fn ip_of(v: &Value) -> IpAddr {
        v.as_str().unwrap().parse().unwrap()
    }

    /// A decoded reply in the shape of the vectors' `expected`.
    fn reply_json(r: &Reply) -> Value {
        match r {
            Reply::NatPmpOnly => json!({ "kind": "natpmp_only" }),
            Reply::Pcp(p) => json!({
                "kind": "pcp",
                "opcode": p.opcode,
                "result": p.result,
                "lifetime": p.lifetime,
                "epoch": p.epoch,
                "map": p.map.map(|m| json!({
                    "nonce_hex": hex::encode(m.nonce),
                    "protocol": m.proto,
                    "internal_port": m.internal_port,
                    "external_port": m.external_port,
                    "external_ip": m.external_addr().to_string(),
                })),
            }),
            Reply::NatPmp(NatPmpResp::ExternalAddr {
                result,
                epoch,
                external,
            }) => json!({
                "kind": "natpmp_external_addr",
                "result": result,
                "epoch": epoch,
                "external_ip": external.to_string(),
            }),
            Reply::NatPmp(NatPmpResp::Map {
                proto,
                result,
                epoch,
                internal_port,
                external_port,
                lifetime,
            }) => json!({
                "kind": "natpmp_map",
                "protocol": *proto as u8,
                "result": result,
                "epoch": epoch,
                "internal_port": internal_port,
                "external_port": external_port,
                "lifetime": lifetime,
            }),
        }
    }

    fn decode_vector(v: &Value) -> Result<Reply, ReplyError> {
        let i = &v["inputs"];
        decode_reply(
            &hex_of(&i["reply_hex"]),
            op_of(&i["sent_pcp_op"]),
            op_of(&i["sent_natpmp_op"]),
        )
    }

    /// The MAP request of a `pcp_map_*` vector, rebuilt from its inputs.
    fn map_request_of(v: &Value) -> (Vec<u8>, [u8; 12]) {
        let i = &v["inputs"];
        let seed: [u8; 32] = hex_of(&i["seed_hex"]).try_into().unwrap();
        let client = ip_of(&i["client_ip"]);
        let gateway = ip_of(&i["gateway_ip"]);
        let proto = Proto::from_iana(op_of(&i["protocol"]).unwrap()).unwrap();
        let port = u16_of(&i["internal_port"]);
        let key = nonce_key(&Identity::from_seed(&seed));
        let nonce = pcp_nonce(&key, gateway, client, proto, port);
        let suggested_ip: Ipv6Addr = i["suggested_ip"].as_str().unwrap().parse().unwrap();
        assert_eq!(suggested_ip, unspecified_external(client));
        let req = MapReq {
            nonce,
            proto,
            internal_port: port,
            suggested_port: u16_of(&i["suggested_port"]),
            suggested_ip,
        };
        let bytes = pcp_request(PCP_OP_MAP, u32_of(&i["lifetime"]), client, Some(&req));
        (bytes, nonce)
    }

    #[test]
    fn pcp_and_natpmp_requests_match_shared_vectors() {
        let v = vector("natpmp_extaddr_req_001.json");
        assert_eq!(
            natpmp_request(NATPMP_OP_EXTERNAL_ADDR, 0, 0, 0),
            hex_of(&v["expected"]["request_hex"])
        );
        let v = vector("natpmp_map_tcp_req_001.json");
        let i = &v["inputs"];
        let req = natpmp_request(
            op_of(&i["op"]).unwrap(),
            u16_of(&i["internal_port"]),
            u16_of(&i["suggested_port"]),
            u32_of(&i["lifetime"]),
        );
        assert_eq!(req, hex_of(&v["expected"]["request_hex"]));
        assert_eq!(req.len(), 12);
        assert_eq!(Proto::Tcp.natpmp_op(), op_of(&i["op"]).unwrap());
        let v = vector("pcp_announce_req_001.json");
        let req = pcp_request(PCP_OP_ANNOUNCE, 0, ip_of(&v["inputs"]["client_ip"]), None);
        assert_eq!(req, hex_of(&v["expected"]["request_hex"]));
        assert_eq!(req.len(), 24);
        for name in [
            "pcp_map_v4_req_001.json",
            "pcp_map_v4_delete_001.json",
            "pcp_map_v6_req_001.json",
        ] {
            let v = vector(name);
            let (req, nonce) = map_request_of(&v);
            assert_eq!(hex::encode(nonce), v["inputs"]["nonce_hex"], "{name}");
            assert_eq!(req, hex_of(&v["expected"]["request_hex"]), "{name}");
            assert_eq!(req.len(), 60, "{name}");
        }
    }

    #[test]
    fn pcp_and_natpmp_replies_decode_like_the_shared_vectors() {
        let names: Vec<String> = names_in(vectors_dir())
            .into_iter()
            .filter(|n| vector(n)["inputs"].get("reply_hex").is_some())
            .collect();
        assert_eq!(names.len(), 7, "{names:?}");
        for name in &names {
            let v = vector(name);
            let r = decode_vector(&v).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(reply_json(&r), v["expected"], "{name}");
        }
        // The MAP response answers the MAP request: same nonce, protocol and
        // internal port; the external address reads as IPv4.
        let Reply::Pcp(resp) = decode_vector(&vector("pcp_map_v4_resp_001.json")).unwrap() else {
            panic!("a PCP reply");
        };
        let m = resp.map.unwrap();
        let (_, nonce) = map_request_of(&vector("pcp_map_v4_req_001.json"));
        assert_eq!(
            (m.nonce, Proto::from_iana(m.proto), m.internal_port),
            (nonce, Some(Proto::Tcp), 7423)
        );
        assert_eq!(m.external_addr(), IpAddr::V4(Ipv4Addr::new(11, 0, 2, 9)));
        // An optional option is skipped: the same reply.
        assert_eq!(
            decode_vector(&vector("pcp_map_v4_resp_002.json")),
            Ok(Reply::Pcp(resp))
        );
    }

    #[test]
    fn decode_rejects_bad_version_r_bit_opcode_length_and_mandatory_options() {
        let dir = vectors_dir().join("negative");
        let names = names_in(dir.clone());
        assert_eq!(names.len(), 7, "{names:?}");
        let mut codes = std::collections::BTreeSet::new();
        for name in &names {
            let v: Value =
                serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap();
            let err = decode_vector(&v).expect_err(name);
            assert_eq!(err.code(), v["expected"]["error"], "{name}");
            codes.insert(err.code());
        }
        for code in [
            "version",
            "not_response",
            "opcode",
            "length",
            "mandatory_option",
        ] {
            assert!(codes.contains(code), "no negative vector for {code}");
        }
        // Option and size bounds.
        let head = |op: u8, result: u8| {
            let mut b = vec![PCP_VERSION, RESPONSE_BIT | op, 0, result];
            b.extend_from_slice(&[0; 20]);
            b
        };
        let with = |extra: &[u8]| [head(PCP_OP_ANNOUNCE, 0).as_slice(), extra].concat();
        assert!(decode_reply(&with(&[0x80, 0, 0, 0]), Some(0), None).is_ok());
        for (options, err) in [
            (
                &[0x80, 0, 0, 5, 0, 0, 0, 0][..],
                ReplyError::MalformedOption,
            ),
            (&[0x80, 0, 0xff, 0xff][..], ReplyError::MalformedOption),
            (&[0x01, 0, 0, 0][..], ReplyError::MandatoryOption),
        ] {
            assert_eq!(decode_reply(&with(options), Some(0), None), Err(err));
        }
        let longest = with(&[&[0x80, 0, 0x04, 0x30][..], &[0; 1072]].concat());
        assert_eq!(longest.len(), MAX_PCP);
        assert!(decode_reply(&longest, Some(0), None).is_ok());
        let too_long = [longest.as_slice(), &[0; 4]].concat();
        assert_eq!(
            decode_reply(&too_long, Some(0), None),
            Err(ReplyError::Length)
        );
        // A MAP error may come without the MAP data; SUCCESS may not.
        let refused = decode_reply(&head(PCP_OP_MAP, PCP_NOT_AUTHORIZED), Some(1), None);
        assert!(matches!(
            refused,
            Ok(Reply::Pcp(PcpResp {
                map: None,
                result: PCP_NOT_AUTHORIZED,
                ..
            }))
        ));
        // Nothing outstanding, an opcode Raven never sends, an empty datagram.
        let announce = head(PCP_OP_ANNOUNCE, 0);
        assert_eq!(
            decode_reply(&announce, None, Some(0)),
            Err(ReplyError::Unexpected)
        );
        assert_eq!(
            decode_reply(&head(2, 0), Some(2), None),
            Err(ReplyError::Opcode)
        );
        assert_eq!(decode_reply(&[], Some(0), Some(0)), Err(ReplyError::Length));
        let ext = hex_of(&vector("natpmp_extaddr_resp_001.json")["inputs"]["reply_hex"]);
        assert_eq!(
            decode_reply(&ext, Some(0), None),
            Err(ReplyError::Unexpected)
        );
        assert_eq!(decode_reply(&ext, None, Some(1)), Err(ReplyError::Opcode));
        assert_eq!(decode_reply(&ext, None, Some(3)), Err(ReplyError::Opcode));
    }

    #[test]
    fn a_natpmp_only_router_answering_a_pcp_request_is_recognised() {
        for name in [
            "pcp_reply_natpmp_only_001.json",
            "pcp_reply_natpmp_only_002.json",
        ] {
            let v = vector(name);
            assert_eq!(decode_vector(&v), Ok(Reply::NatPmpOnly), "{name}");
            // Only as the answer to a PCP request.
            let reply = hex_of(&v["inputs"]["reply_hex"]);
            assert_eq!(reply.len(), 8);
            assert!(decode_reply(&reply, None, Some(NATPMP_OP_MAP_TCP)).is_err());
            assert_eq!(
                decode_reply(&reply, None, None),
                Err(ReplyError::Unexpected)
            );
        }
        let answer = |op_byte: u8, result: u8, len: usize| {
            let mut b = vec![0, op_byte, 0, result, 0, 0, 0, 9];
            b.resize(len, 0);
            b
        };
        for (op_byte, sent, len, ok) in [
            (0x81, PCP_OP_MAP, 8, true),
            (0x81, PCP_OP_MAP, 16, true),
            (0x80, PCP_OP_ANNOUNCE, 12, true),
            (0x00, PCP_OP_MAP, 8, true),
            (0x80, PCP_OP_MAP, 8, false),
            (0x82, PCP_OP_MAP, 8, false),
            (0x81, PCP_OP_MAP, 4, false),
            (0x81, PCP_OP_MAP, 10, false),
        ] {
            let got = decode_reply(&answer(op_byte, 1, len), Some(sent), None);
            assert_eq!(
                got == Ok(Reply::NatPmpOnly),
                ok,
                "{op_byte:#x} {sent} {len}"
            );
        }
        // Another result code is no version answer.
        assert!(decode_reply(&answer(0x81, 2, 8), Some(PCP_OP_MAP), None).is_err());
        // With the probe's NAT-PMP request outstanding too, its own answer
        // still decodes as NAT-PMP.
        let ext = hex_of(&vector("natpmp_extaddr_resp_001.json")["inputs"]["reply_hex"]);
        assert!(matches!(
            decode_reply(&ext, Some(PCP_OP_ANNOUNCE), Some(NATPMP_OP_EXTERNAL_ADDR)),
            Ok(Reply::NatPmp(NatPmpResp::ExternalAddr { .. }))
        ));
    }

    #[test]
    fn epoch_validity_follows_rfc6887_8_5() {
        let v = vector("pcp_epoch_validity_001.json");
        let t0 = Instant::now();
        let at = |c: &Value| {
            (
                u32_of(&c["server"]),
                t0 + Duration::from_secs(c["client_s"].as_u64().unwrap()),
            )
        };
        let mut got = Vec::new();
        for case in v["inputs"]["cases"].as_array().unwrap() {
            let mut w = EpochWatch::new();
            if !case["prev"].is_null() {
                let (server, now) = at(&case["prev"]);
                assert!(!w.lost(server, now), "the first reply is valid");
            }
            let (server, now) = at(&case["curr"]);
            got.push(Value::Bool(w.lost(server, now)));
        }
        assert_eq!(Value::Array(got), v["expected"]["lost"]);
        // Fractions of a second do not count; reset forgets the gateway.
        let mut w = EpochWatch::new();
        assert!(!w.lost(100, t0));
        assert!(!w.lost(200, t0 + Duration::from_millis(108_999)));
        let mut w = EpochWatch::new();
        assert!(!w.lost(3600, t0));
        w.reset();
        assert!(!w.lost(5, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn nonce_is_deterministic_per_router_and_internal_endpoint_and_differs_per_profile() {
        let v = vector("pcp_nonce_001.json");
        let seed: [u8; 32] = hex_of(&v["inputs"]["seed_hex"]).try_into().unwrap();
        let other: [u8; 32] = hex_of(&v["inputs"]["other_seed_hex"]).try_into().unwrap();
        assert_eq!(v["inputs"]["domain_ascii"], "raven/pcp-nonce-key/v1");
        let key = nonce_key(&Identity::from_seed(&seed));
        let other_key = nonce_key(&Identity::from_seed(&other));
        assert_eq!(hex::encode(*key), v["expected"]["key_hex"]);
        assert_eq!(hex::encode(*other_key), v["expected"]["other_key_hex"]);
        let mut seen = std::collections::BTreeSet::new();
        for case in v["expected"]["cases"].as_array().unwrap() {
            let gw = ip_of(&case["gateway_ip"]);
            let ip = ip_of(&case["internal_ip"]);
            let proto = Proto::from_iana(op_of(&case["protocol"]).unwrap()).unwrap();
            let port = u16_of(&case["port"]);
            let n = pcp_nonce(&key, gw, ip, proto, port);
            assert_eq!(hex::encode(n), case["nonce_hex"]);
            assert_eq!(n, pcp_nonce(&key, gw, ip, proto, port), "deterministic");
            let o = pcp_nonce(&other_key, gw, ip, proto, port);
            assert_eq!(hex::encode(o), case["other_profile_nonce_hex"]);
            assert_ne!(n, o);
            assert!(seen.insert(n), "one nonce per router and internal endpoint");
        }
        assert_eq!(seen.len(), 7);
        // An IPv4 endpoint and its IPv4-mapped form are the same endpoint.
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let v4: IpAddr = "192.168.1.20".parse().unwrap();
        assert_eq!(
            pcp_nonce(&key, gw, v4, Proto::Tcp, 7423),
            pcp_nonce(&key, gw, IpAddr::V6(v6_form(v4)), Proto::Tcp, 7423)
        );
        // The same internal endpoint behind another router (a venue whose
        // DHCP hands out the same address): another nonce, so the two
        // routers' operators cannot link the visits by it.
        let venue: IpAddr = "10.0.0.1".parse().unwrap();
        assert_ne!(
            pcp_nonce(&key, gw, v4, Proto::Tcp, 7423),
            pcp_nonce(&key, venue, v4, Proto::Tcp, 7423)
        );
    }

    /// The fake gateway, written from the RFC tables on its own, answers the
    /// request vectors with the reply vectors' exact bytes.
    #[test]
    fn fake_gateway_reproduces_the_reply_vectors() {
        let t0 = Instant::now();
        let mut checked = 0;
        for name in names_in(vectors_dir()) {
            let v = vector(&name);
            let Some(request_name) = v["inputs"]["answers"].as_str() else {
                continue;
            };
            let gw = &v["inputs"]["gateway"];
            assert_eq!(gw["external_ipv4"], "11.0.2.9");
            assert_eq!(gw["max_lifetime_s"], REQUESTED_LIFETIME_S);
            let request = vector(request_name);
            let req = hex_of(&request["expected"]["request_hex"]);
            let client = ip_of(&request["inputs"]["client_ip"]);
            let mut fake = FakeGateway::new(Mode::Pcp, t0);
            let now = t0 + Duration::from_secs(gw["epoch_s"].as_u64().unwrap());
            let reply = fake
                .reply(&req, SocketAddr::new(client, 40_000), now)
                .unwrap_or_else(|| panic!("{name}: no reply"));
            assert_eq!(hex::encode(reply), v["inputs"]["reply_hex"], "{name}");
            checked += 1;
        }
        assert_eq!(checked, 4);
    }
}

/// [`MapperCore`] against the fake gateway, with explicit clocks.
#[cfg(test)]
mod mapper_tests {
    use super::*;
    use crate::portmap_fake::{FakeGateway, Mode, SeenReq, FAKE_EXTERNAL_V4};
    use std::collections::VecDeque;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    const GW: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const PORT: u16 = 7423;
    const KEY: [u8; 32] = [7; 32];

    fn cfg() -> MapperConfig {
        MapperConfig::new(Zeroizing::new(KEY), GW)
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn ext(ip: Ipv4Addr, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), port)
    }

    fn mapped(via: Via, proto: Proto, external: SocketAddr) -> Out {
        Out::Mapped {
            via,
            proto,
            internal_port: PORT,
            external,
        }
    }

    fn expired(via: Via, proto: Proto, external: SocketAddr) -> Out {
        Out::Expired {
            via,
            proto,
            internal_port: PORT,
            external,
        }
    }

    /// Rewrites (or drops, with `None`) the gateway's reply to a request.
    type Rewrite = fn(&[u8], Vec<u8>) -> Option<Vec<u8>>;

    /// A core wired to a fake gateway: every datagram is answered at once.
    struct Lab {
        core: MapperCore,
        gw: FakeGateway,
        client: IpAddr,
        t0: Instant,
        now: Instant,
        /// When each request the gateway logged was sent (parallel to
        /// `gw.log`).
        sent_at: Vec<Duration>,
        events: Vec<Out>,
        rewrite: Option<Rewrite>,
    }

    impl Lab {
        fn new(mode: Mode) -> Self {
            Self::with(mode, CLIENT, cfg(), None)
        }

        fn with(mode: Mode, client: IpAddr, cfg: MapperConfig, rewrite: Option<Rewrite>) -> Self {
            let t0 = Instant::now();
            let (core, out) = MapperCore::new(client, cfg, t0);
            let mut lab = Self {
                core,
                gw: FakeGateway::new(mode, t0),
                client,
                t0,
                now: t0,
                sent_at: Vec::new(),
                events: Vec::new(),
                rewrite,
            };
            lab.pump(out);
            lab
        }

        /// Hand every datagram to the gateway (from CLIENT, whatever the
        /// core's client), every answer back to the core; keep the events.
        fn pump(&mut self, out: Vec<Out>) {
            let mut queue: VecDeque<Out> = out.into();
            while let Some(o) = queue.pop_front() {
                let Out::Send(req) = o else {
                    self.events.push(o);
                    continue;
                };
                self.sent_at.push(self.now - self.t0);
                let src = SocketAddr::new(CLIENT, 50_000);
                let mut reply = self.gw.reply(&req, src, self.now);
                if let Some(f) = self.rewrite {
                    reply = reply.and_then(|r| f(&req, r));
                }
                if let Some(r) = reply {
                    queue.extend(self.core.on_datagram(&r, self.now));
                }
            }
        }

        fn want(&mut self, proto: Proto) {
            let out = self.core.want(proto, PORT, self.now);
            self.pump(out);
        }

        /// Move the clock to `t0 + d`, running every wake on the way.
        fn run_to(&mut self, d: Duration) {
            let end = self.t0 + d;
            for _ in 0..10_000 {
                match self.core.next_wake() {
                    Some(w) if w <= end => {
                        self.now = w.max(self.now);
                        let out = self.core.on_tick(self.now);
                        self.pump(out);
                    }
                    _ => {
                        self.now = end;
                        return;
                    }
                }
            }
            panic!("the core keeps waking at the same time");
        }

        fn take(&mut self) -> Vec<Out> {
            std::mem::take(&mut self.events)
        }

        /// The MAP requests (PCP op 1, NAT-PMP op 1/2) the gateway saw, with
        /// when they were sent.
        fn maps(&self) -> Vec<(Duration, SeenReq)> {
            self.gw
                .log
                .iter()
                .zip(&self.sent_at)
                .filter(|(s, _)| s.proto.is_some())
                .map(|(s, t)| (*t, *s))
                .collect()
        }
    }

    #[test]
    fn probe_prefers_pcp_then_natpmp_then_reports_no_server_after_3750ms() {
        // Silence: four rounds of PCP ANNOUNCE plus NAT-PMP, then NoServer.
        let mut lab = Lab::new(Mode::Silent);
        lab.run_to(Duration::from_millis(3749));
        assert!(lab.take().is_empty());
        let times: Vec<u128> = lab.sent_at.iter().map(Duration::as_millis).collect();
        assert_eq!(times, [0, 0, 250, 250, 750, 750, 1750, 1750]);
        let kinds: Vec<(u8, u8)> = lab.gw.log.iter().map(|s| (s.version, s.op)).collect();
        assert_eq!(kinds, [(2, 0), (0, 0)].repeat(4));
        assert!(lab.gw.log.iter().all(|s| s.lifetime == 0));
        lab.run_to(Duration::from_millis(3750));
        assert_eq!(lab.take(), [Out::NoServer]);
        assert!(lab.core.is_halted() && lab.core.next_wake().is_none());
        lab.want(Proto::Tcp);
        assert_eq!(lab.gw.log.len(), 8, "nothing sent after NoServer");

        // An IPv6 client probes with PCP only.
        let v6: IpAddr = "2001:db8::20".parse().unwrap();
        let (_, out) = MapperCore::new(v6, cfg(), Instant::now());
        assert_eq!(out, [Out::Send(pcp_request(PCP_OP_ANNOUNCE, 0, v6, None))]);

        // Both answer: PCP wins even when NAT-PMP's answer comes first.
        let t0 = Instant::now();
        let mut gw = FakeGateway::new(Mode::Pcp, t0);
        let src = SocketAddr::new(CLIENT, 50_000);
        let (mut core, out) = MapperCore::new(CLIENT, cfg(), t0);
        let answers: Vec<Vec<u8>> = out
            .iter()
            .map(|o| match o {
                Out::Send(b) => gw.reply(b, src, t0).unwrap(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(answers.len(), 2);
        assert!(core.on_datagram(&answers[1], t0).is_empty());
        assert_eq!(core.via(), None);
        assert!(core
            .on_datagram(&answers[0], t0 + Duration::from_millis(100))
            .is_empty());
        assert_eq!(core.via(), Some(Via::Pcp));

        // Only NAT-PMP answers: chosen 250 ms after its answer.
        let (mut core, _) = MapperCore::new(CLIENT, cfg(), t0);
        assert!(core.on_datagram(&answers[1], t0).is_empty());
        assert_eq!(core.next_wake(), Some(t0 + Duration::from_millis(250)));
        assert!(core.on_tick(t0 + Duration::from_millis(249)).is_empty());
        assert_eq!(core.via(), None);
        let out = core.want(Proto::Tcp, PORT, t0 + Duration::from_millis(249));
        assert!(out.is_empty(), "nothing is mapped during the probe");
        let out = core.on_tick(t0 + Duration::from_millis(250));
        assert_eq!(core.via(), Some(Via::NatPmp));
        assert_eq!(
            out,
            [Out::Send(natpmp_request(
                NATPMP_OP_MAP_TCP,
                PORT,
                PORT,
                7200
            ))]
        );

        // A NAT-PMP-only router: NAT-PMP at once.
        let mut lab = Lab::new(Mode::NatPmpOnly);
        assert_eq!(lab.core.via(), Some(Via::NatPmp));
        lab.want(Proto::Tcp);
        let via = Via::NatPmp;
        assert_eq!(
            lab.take(),
            [mapped(via, Proto::Tcp, ext(FAKE_EXTERNAL_V4, PORT))]
        );
        let (_, m) = lab.maps()[0];
        assert_eq!((m.version, m.op, m.lifetime), (0, NATPMP_OP_MAP_TCP, 7200));
    }

    #[test]
    fn maps_tcp_and_udp_with_one_nonce_each_and_renews_at_half_lifetime() {
        let mut lab = Lab::new(Mode::Pcp);
        lab.gw.max_lifetime_s = 600;
        assert_eq!(lab.core.via(), Some(Via::Pcp));
        lab.want(Proto::Tcp);
        lab.want(Proto::Udp);
        lab.want(Proto::Udp);
        let at = ext(FAKE_EXTERNAL_V4, PORT);
        assert_eq!(
            lab.take(),
            [
                mapped(Via::Pcp, Proto::Tcp, at),
                mapped(Via::Pcp, Proto::Udp, at)
            ]
        );
        let tcp = pcp_nonce(&KEY, GW, CLIENT, Proto::Tcp, PORT);
        let udp = pcp_nonce(&KEY, GW, CLIENT, Proto::Udp, PORT);
        assert_ne!(tcp, udp);
        let maps = lab.maps();
        assert_eq!(maps.len(), 2);
        for ((t, m), (proto, nonce)) in maps.iter().zip([(6, tcp), (17, udp)]) {
            assert_eq!(*t, Duration::ZERO);
            assert_eq!(
                (m.proto, m.nonce, m.lifetime, m.suggested_port),
                (Some(proto), Some(nonce), 7200, PORT)
            );
            assert_eq!(m.client_ip, Some(CLIENT));
        }
        // Granted 600 s: renewed at 300 s with the same nonce and port.
        assert_eq!(lab.core.next_wake(), Some(lab.t0 + secs(300)));
        lab.run_to(secs(299));
        assert_eq!(lab.maps().len(), 2);
        lab.run_to(secs(300));
        let maps = lab.maps();
        assert_eq!(maps.len(), 4);
        for (t, m) in &maps[2..] {
            assert_eq!(*t, secs(300));
            assert_eq!((m.lifetime, m.suggested_port), (7200, PORT));
        }
        assert_eq!((maps[2].1.nonce, maps[3].1.nonce), (Some(tcp), Some(udp)));
        lab.run_to(secs(1000));
        assert!(lab.take().is_empty(), "renewals report nothing");
        assert_eq!(lab.maps().len(), 8);

        // Short leases renew at half too: a granted lifetime of 100 s after
        // 50 s; a lab lifetime of 8 s after 4 s.
        let mut lab = Lab::new(Mode::Pcp);
        lab.gw.max_lifetime_s = 100;
        lab.want(Proto::Tcp);
        assert_eq!(lab.core.next_wake(), Some(lab.t0 + secs(50)));
        let lab_cfg = MapperConfig {
            lifetime: 8,
            ..cfg()
        };
        let mut lab = Lab::with(Mode::Pcp, CLIENT, lab_cfg, None);
        lab.want(Proto::Udp);
        assert_eq!(lab.maps()[0].1.lifetime, 8);
        assert_eq!(lab.core.next_wake(), Some(lab.t0 + secs(4)));

        // NAT-PMP renews the same way, and asks for the external address
        // with each renewal.
        let mut lab = Lab::new(Mode::NatPmpOnly);
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Udp);
        assert_eq!(lab.take().len(), 1);
        let before = lab.gw.log.len();
        lab.run_to(secs(300));
        let renewal: Vec<(u8, u8)> = lab.gw.log[before..]
            .iter()
            .map(|s| (s.version, s.op))
            .collect();
        assert_eq!(
            renewal,
            [(0, NATPMP_OP_MAP_UDP), (0, NATPMP_OP_EXTERNAL_ADDR)]
        );
        assert!(lab.take().is_empty());
    }

    #[test]
    fn renewal_failures_keep_the_mapping_until_its_lifetime_then_expire() {
        let mut lab = Lab::new(Mode::Pcp);
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Tcp);
        let at = ext(FAKE_EXTERNAL_V4, PORT);
        assert_eq!(lab.take(), [mapped(Via::Pcp, Proto::Tcp, at)]);
        lab.gw.mode = Mode::DropRenewals;
        lab.run_to(secs(599));
        assert!(lab.take().is_empty(), "kept while its lifetime lasts");
        let times: Vec<Duration> = lab.maps().iter().map(|(t, _)| *t).collect();
        // Three tries (RFC 6887 timing), then a wait until the lifetime's
        // end (sooner than the 30 min cap).
        assert_eq!(times, [secs(0), secs(300), secs(303), secs(309)]);
        assert_eq!(lab.core.next_wake(), Some(lab.t0 + secs(600)));
        // At the end it expires; the gateway lost it too, so asking again
        // creates it anew.
        lab.run_to(secs(600));
        assert_eq!(
            lab.take(),
            [
                expired(Via::Pcp, Proto::Tcp, at),
                mapped(Via::Pcp, Proto::Tcp, at)
            ]
        );

        // A mapping request that never gets an answer: three tries, then
        // the 30 min cap.
        let mut lab = Lab::new(Mode::Pcp);
        lab.gw.mode = Mode::Silent;
        lab.want(Proto::Udp);
        lab.run_to(secs(1820));
        let times: Vec<Duration> = lab.maps().iter().map(|(t, _)| *t).collect();
        assert_eq!(times, [secs(0), secs(3), secs(9)]);
        lab.run_to(secs(21 + 1800));
        assert_eq!(lab.maps().len(), 4);
        assert!(lab.take().is_empty());
    }

    #[test]
    fn epoch_reset_remaps_at_once() {
        let mut lab = Lab::new(Mode::EpochResetAt(secs(250)));
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Tcp);
        lab.run_to(secs(100));
        lab.want(Proto::Udp);
        assert_eq!(lab.take().len(), 2);
        assert_eq!(lab.maps().len(), 2);
        // The TCP renewal at 300 s meets the restarted gateway (epoch 0):
        // UDP, due at 400 s, is asked at once.
        lab.run_to(secs(300));
        assert_eq!(lab.take(), [Out::ServerRestarted { via: Via::Pcp }]);
        let maps = lab.maps();
        assert_eq!(maps.len(), 4);
        assert_eq!((maps[2].0, maps[2].1.proto), (secs(300), Some(6)));
        assert_eq!((maps[3].0, maps[3].1.proto), (secs(300), Some(17)));
        assert_eq!(lab.gw.mappings.len(), 2, "both mapped again");
        // Next renewals follow the new grants.
        lab.run_to(secs(599));
        assert_eq!(lab.maps().len(), 4);
        lab.run_to(secs(600));
        assert_eq!(lab.maps().len(), 6);
        assert!(lab.take().is_empty());

        // NAT-PMP: a restart seen on the external address answer.
        let mut lab = Lab::new(Mode::NatPmpOnly);
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Tcp);
        lab.run_to(secs(100));
        lab.want(Proto::Udp);
        lab.take();
        lab.gw.mode = Mode::EpochResetAt(secs(250));
        lab.run_to(secs(300));
        assert_eq!(lab.take(), [Out::ServerRestarted { via: Via::NatPmp }]);
        let maps = lab.maps();
        assert_eq!(maps.len(), 4);
        assert_eq!((maps[3].0, maps[3].1.proto), (secs(300), Some(17)));
    }

    #[test]
    fn external_ip_change_expires_old_then_confirms_new() {
        let old = ext(FAKE_EXTERNAL_V4, PORT);
        let new_ip = Ipv4Addr::new(11, 0, 3, 7);
        let new = ext(new_ip, PORT);
        let mut lab = Lab::new(Mode::Pcp);
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Tcp);
        lab.run_to(secs(100));
        lab.want(Proto::Udp);
        assert_eq!(lab.take().len(), 2);
        lab.gw.mode = Mode::ExternalIp(IpAddr::V4(new_ip));
        // TCP's renewal shows the new address; UDP is renewed at once.
        lab.run_to(secs(300));
        assert_eq!(
            lab.take(),
            [
                expired(Via::Pcp, Proto::Tcp, old),
                mapped(Via::Pcp, Proto::Tcp, new),
                expired(Via::Pcp, Proto::Udp, old),
                mapped(Via::Pcp, Proto::Udp, new),
            ]
        );
        assert_eq!(lab.maps().last().unwrap().0, secs(300));

        // NAT-PMP: the external address answer sent with a renewal.
        let mut lab = Lab::new(Mode::NatPmpOnly);
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Tcp);
        lab.take();
        lab.gw.mode = Mode::ExternalIp(IpAddr::V4(new_ip));
        lab.run_to(secs(300));
        assert_eq!(
            lab.take(),
            [
                expired(Via::NatPmp, Proto::Tcp, old),
                mapped(Via::NatPmp, Proto::Tcp, new)
            ]
        );
    }

    #[test]
    fn cgn_external_ip_is_non_routable_and_deleted() {
        const CARRIER: Out = Out::NonRoutable { carrier: true };
        const DOUBLE_NAT: Out = Out::NonRoutable { carrier: false };
        let cgn = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9));
        let mut lab = Lab::new(Mode::ExternalIp(cgn));
        lab.want(Proto::Tcp);
        assert_eq!(lab.take(), [CARRIER]);
        // The mapping just made is deleted (lifetime 0, same nonce, port 0).
        let maps = lab.maps();
        assert_eq!(maps.len(), 2);
        let tcp = pcp_nonce(&KEY, GW, CLIENT, Proto::Tcp, PORT);
        assert_eq!(
            (
                maps[1].1.lifetime,
                maps[1].1.nonce,
                maps[1].1.suggested_port
            ),
            (0, Some(tcp), 0)
        );
        assert!(lab.gw.mappings.is_empty());
        assert!(lab.core.is_halted() && lab.core.next_wake().is_none());
        lab.want(Proto::Udp);
        assert_eq!(lab.maps().len(), 2, "nothing asked after NonRoutable");

        // Two mappings in flight: both deleted.
        let mut lab = Lab::new(Mode::Pcp);
        lab.gw.mode = Mode::ExternalIp(cgn);
        let mut out = lab.core.want(Proto::Tcp, PORT, lab.now);
        out.extend(lab.core.want(Proto::Udp, PORT, lab.now));
        lab.pump(out);
        assert_eq!(lab.take(), [CARRIER]);
        let deletes = lab.maps().iter().filter(|(_, m)| m.lifetime == 0).count();
        assert_eq!(deletes, 2);
        assert!(lab.gw.mappings.is_empty());

        // A NAT-PMP router that reports a private address stops at once:
        // it sits behind another router of the site (a double NAT, not the
        // provider's carrier NAT).
        let mut lab = Lab::new(Mode::NatPmpOnly);
        lab.gw.mode = Mode::ExternalIp(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)));
        lab.want(Proto::Tcp);
        lab.take();
        lab.run_to(secs(3600));
        assert_eq!(
            lab.take(),
            [
                DOUBLE_NAT,
                expired(Via::NatPmp, Proto::Tcp, ext(FAKE_EXTERNAL_V4, PORT))
            ]
        );
        assert!(lab.gw.mappings.is_empty(), "deleted");
        // The same through PCP, for each private range; the edges of
        // 100.64.0.0/10 are carrier NAT and nothing else is.
        for (ip, class) in [
            ([192, 168, 0, 2], DOUBLE_NAT),
            ([10, 0, 0, 2], DOUBLE_NAT),
            ([172, 16, 5, 1], DOUBLE_NAT),
            ([100, 64, 0, 0], CARRIER),
            ([100, 127, 255, 255], CARRIER),
            ([169, 254, 1, 1], DOUBLE_NAT),
        ] {
            let mut lab = Lab::new(Mode::ExternalIp(IpAddr::V4(Ipv4Addr::from(ip))));
            lab.want(Proto::Tcp);
            assert_eq!(lab.take(), [class], "{ip:?}");
        }
        // Just outside 100.64.0.0/10 (global, so never reported anyway).
        for ip in [[100, 63, 255, 255], [100, 128, 0, 1]] {
            assert_eq!(non_routable(Ipv4Addr::from(ip).into()), DOUBLE_NAT);
        }

        // The lab accepts loopback, never CGN.
        let lab_cfg = MapperConfig {
            any_ip: true,
            ..cfg()
        };
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut lab = Lab::with(Mode::ExternalIp(lo), CLIENT, lab_cfg.clone(), None);
        lab.want(Proto::Tcp);
        let at = SocketAddr::new(lo, PORT);
        assert_eq!(lab.take(), [mapped(Via::Pcp, Proto::Tcp, at)]);
        let mut lab = Lab::with(Mode::ExternalIp(lo), CLIENT, cfg(), None);
        lab.want(Proto::Tcp);
        assert_eq!(lab.take(), [DOUBLE_NAT]);
        let mut lab = Lab::with(Mode::ExternalIp(cgn), CLIENT, lab_cfg, None);
        lab.want(Proto::Tcp);
        assert_eq!(lab.take(), [CARRIER]);
    }

    #[test]
    fn not_authorized_and_address_mismatch_stop() {
        let mut lab = Lab::new(Mode::NotAuthorized);
        lab.want(Proto::Tcp);
        lab.want(Proto::Udp);
        assert_eq!(
            lab.take(),
            [Out::Refused {
                via: Via::Pcp,
                code: u16::from(PCP_NOT_AUTHORIZED)
            }]
        );
        assert!(lab.core.is_halted());
        lab.run_to(secs(7200));
        assert_eq!(lab.maps().len(), 1, "nothing asked after the refusal");

        // NAT-PMP's code 2 is the same.
        let mut lab = Lab::new(Mode::NatPmpOnly);
        lab.gw.mode = Mode::NotAuthorized;
        lab.want(Proto::Udp);
        assert_eq!(
            lab.take(),
            [Out::Refused {
                via: Via::NatPmp,
                code: NATPMP_NOT_AUTHORIZED
            }]
        );
        assert!(lab.core.is_halted());

        // The core names another client address than the datagrams' source:
        // the probe's own answer is ADDRESS_MISMATCH.
        let other = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21));
        let mut lab = Lab::with(Mode::Pcp, other, cfg(), None);
        assert_eq!(
            lab.take(),
            [Out::Refused {
                via: Via::Pcp,
                code: u16::from(PCP_ADDRESS_MISMATCH)
            }]
        );
        lab.want(Proto::Tcp);
        assert!(lab.maps().is_empty());
        assert_eq!(lab.client, other);

        // An existing mapping is reported gone when the router refuses later.
        fn refuse_renewals(req: &[u8], mut reply: Vec<u8>) -> Option<Vec<u8>> {
            if req[0] == 2 && req[1] == PCP_OP_MAP && reply[4..8] != [0, 0, 0, 0] {
                reply[3] = PCP_ADDRESS_MISMATCH;
            }
            Some(reply)
        }
        let mut lab = Lab::with(Mode::Pcp, CLIENT, cfg(), None);
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Tcp);
        lab.take();
        lab.rewrite = Some(refuse_renewals);
        lab.run_to(secs(300));
        assert_eq!(
            lab.take(),
            [
                Out::Refused {
                    via: Via::Pcp,
                    code: u16::from(PCP_ADDRESS_MISMATCH)
                },
                expired(Via::Pcp, Proto::Tcp, ext(FAKE_EXTERNAL_V4, PORT))
            ]
        );
    }

    #[test]
    fn cannot_provide_external_retries_with_port_zero() {
        let mut lab = Lab::new(Mode::CannotProvideExternal);
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Tcp);
        let suggested: Vec<u16> = lab.maps().iter().map(|(_, m)| m.suggested_port).collect();
        assert_eq!(suggested, [PORT, 0]);
        let at = ext(FAKE_EXTERNAL_V4, PORT);
        assert_eq!(lab.take(), [mapped(Via::Pcp, Proto::Tcp, at)]);
        // The renewal suggests the port granted.
        lab.run_to(secs(300));
        assert_eq!(lab.maps()[2].1.suggested_port, PORT);
        assert!(lab.take().is_empty());
    }

    #[test]
    fn no_resources_retries_after_the_hinted_lifetime_capped() {
        for (hint, wait) in [(5000, 1800), (120, 120), (5, 60)] {
            let mut lab = Lab::new(Mode::NoResources { retry_s: hint });
            lab.want(Proto::Tcp);
            assert!(lab.take().is_empty());
            lab.run_to(secs(wait - 1));
            assert_eq!(lab.maps().len(), 1, "hint {hint}");
            lab.run_to(secs(wait));
            assert_eq!(lab.maps().len(), 2, "hint {hint}");
            // The router has resources again.
            lab.gw.mode = Mode::Pcp;
            lab.run_to(secs(2 * wait));
            let at = ext(FAKE_EXTERNAL_V4, PORT);
            assert_eq!(
                lab.take(),
                [mapped(Via::Pcp, Proto::Tcp, at)],
                "hint {hint}"
            );
        }
        // NAT-PMP's code 4 carries no lifetime: the floor.
        let mut lab = Lab::new(Mode::NatPmpOnly);
        lab.gw.mode = Mode::NoResources { retry_s: 5000 };
        lab.want(Proto::Tcp);
        lab.run_to(secs(59));
        assert_eq!(lab.maps().len(), 1);
        lab.run_to(secs(60));
        assert_eq!(lab.maps().len(), 2);
    }

    #[test]
    fn unsupp_protocol_drops_only_that_protocol() {
        fn no_udp(req: &[u8], mut reply: Vec<u8>) -> Option<Vec<u8>> {
            if req[0] == 2 && req.len() == 60 && req[36] == 17 {
                reply[3] = PCP_UNSUPP_PROTOCOL;
            }
            Some(reply)
        }
        let mut lab = Lab::with(Mode::Pcp, CLIENT, cfg(), Some(no_udp));
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Udp);
        lab.want(Proto::Tcp);
        let at = ext(FAKE_EXTERNAL_V4, PORT);
        assert_eq!(lab.take(), [mapped(Via::Pcp, Proto::Tcp, at)]);
        let out = lab.core.want(Proto::Udp, PORT + 1, lab.now);
        assert!(out.is_empty(), "UDP is not asked again");
        lab.run_to(secs(1000));
        let protos: Vec<Option<u8>> = lab.maps().iter().map(|(_, m)| m.proto).collect();
        assert_eq!(protos, [Some(17), Some(6), Some(6), Some(6), Some(6)]);
        assert!(lab.take().is_empty());

        // Any other code refuses that mapping only.
        fn quota_udp(req: &[u8], mut reply: Vec<u8>) -> Option<Vec<u8>> {
            if req[0] == 2 && req.len() == 60 && req[36] == 17 {
                reply[3] = PCP_USER_EX_QUOTA;
            }
            Some(reply)
        }
        let mut lab = Lab::with(Mode::Pcp, CLIENT, cfg(), Some(quota_udp));
        lab.want(Proto::Udp);
        lab.want(Proto::Tcp);
        assert_eq!(
            lab.take(),
            [
                Out::Refused {
                    via: Via::Pcp,
                    code: u16::from(PCP_USER_EX_QUOTA)
                },
                mapped(Via::Pcp, Proto::Tcp, at)
            ]
        );
        assert!(!lab.core.is_halted());
    }

    #[test]
    fn unwant_and_shutdown_send_lifetime_zero() {
        let at = ext(FAKE_EXTERNAL_V4, PORT);
        let mut lab = Lab::new(Mode::Pcp);
        lab.want(Proto::Tcp);
        lab.want(Proto::Udp);
        lab.take();
        let out = lab.core.unwant(Proto::Tcp, PORT);
        lab.pump(out);
        assert_eq!(lab.take(), [expired(Via::Pcp, Proto::Tcp, at)]);
        let (_, del) = *lab.maps().last().unwrap();
        let tcp = pcp_nonce(&KEY, GW, CLIENT, Proto::Tcp, PORT);
        assert_eq!(
            (del.proto, del.lifetime, del.nonce, del.suggested_port),
            (Some(6), 0, Some(tcp), 0)
        );
        assert_eq!(lab.gw.mappings.len(), 1);
        assert!(lab.core.unwant(Proto::Tcp, PORT).is_empty());
        let out = lab.core.shutdown();
        lab.pump(out);
        assert_eq!(lab.take(), [expired(Via::Pcp, Proto::Udp, at)]);
        assert_eq!(lab.maps().last().unwrap().1.lifetime, 0);
        assert!(lab.gw.mappings.is_empty());
        assert!(lab.core.is_halted() && lab.core.next_wake().is_none());

        // NAT-PMP deletes: lifetime 0, suggested port 0.
        let mut lab = Lab::new(Mode::NatPmpOnly);
        lab.want(Proto::Udp);
        lab.take();
        let out = lab.core.shutdown();
        lab.pump(out);
        assert_eq!(lab.take(), [expired(Via::NatPmp, Proto::Udp, at)]);
        let (_, del) = *lab.maps().last().unwrap();
        assert_eq!(
            (del.version, del.op, del.lifetime, del.suggested_port),
            (0, NATPMP_OP_MAP_UDP, 0, 0)
        );
        assert!(lab.gw.mappings.is_empty());

        // Nothing was asked yet: nothing to delete.
        let (mut core, _) = MapperCore::new(CLIENT, cfg(), Instant::now());
        core.want(Proto::Tcp, PORT, Instant::now());
        assert!(core.shutdown().is_empty());
    }

    /// Review C-4: a router that grants a minute or less is renewed before
    /// each lease ends, so the mapping never lapses (no Expired, no second
    /// Mapped) and the router never goes without it.
    #[test]
    fn short_granted_lifetimes_are_renewed_before_they_end() {
        for granted in [60, 30, 1] {
            let mut lab = Lab::new(Mode::Pcp);
            lab.gw.max_lifetime_s = granted;
            lab.want(Proto::Tcp);
            lab.run_to(secs(400));
            let at = ext(FAKE_EXTERNAL_V4, PORT);
            assert_eq!(
                lab.take(),
                [mapped(Via::Pcp, Proto::Tcp, at)],
                "granted {granted}"
            );
            let renewals = lab.maps().len() - 1;
            let want = 400 * 2 / u64::from(granted);
            assert_eq!(renewals as u64, want, "granted {granted}");
            assert_eq!(lab.gw.mappings.len(), 1, "granted {granted}");
        }
    }

    /// Review C-3: a refusal after grants (a router policy change, or a
    /// spoofed answer) stops asking but deletes what the router still
    /// forwards, since the driver ends with the core; the refused request
    /// itself is not deleted.
    #[test]
    fn a_refusal_deletes_the_mappings_the_router_granted() {
        fn refuse_7500(req: &[u8], mut reply: Vec<u8>) -> Option<Vec<u8>> {
            let map = req[0] == 2 && req[1] == PCP_OP_MAP;
            if map && req[40..42] == 7500u16.to_be_bytes() && req[4..8] != [0; 4] {
                reply[3] = PCP_NOT_AUTHORIZED;
            }
            Some(reply)
        }
        let mut lab = Lab::with(Mode::Pcp, CLIENT, cfg(), Some(refuse_7500));
        lab.want(Proto::Tcp);
        lab.want(Proto::Udp);
        assert_eq!(lab.take().len(), 2);
        let asked = lab.maps().len();
        let out = lab.core.want(Proto::Tcp, 7500, lab.now);
        lab.pump(out);
        let at = ext(FAKE_EXTERNAL_V4, PORT);
        assert_eq!(
            lab.take(),
            [
                Out::Refused {
                    via: Via::Pcp,
                    code: u16::from(PCP_NOT_AUTHORIZED)
                },
                expired(Via::Pcp, Proto::Tcp, at),
                expired(Via::Pcp, Proto::Udp, at),
            ]
        );
        assert!(lab.core.is_halted());
        let deletes: Vec<(Option<u8>, u16, u32)> = lab.maps()[asked + 1..]
            .iter()
            .map(|(_, m)| (m.proto, m.internal_port, m.lifetime))
            .collect();
        assert_eq!(deletes, [(Some(6), PORT, 0), (Some(17), PORT, 0)]);
        assert!(lab.gw.mappings.iter().all(|m| m.internal_port != PORT));
        assert!(lab.core.shutdown().is_empty(), "nothing left to delete");

        // NAT-PMP's refusal of a renewal deletes the refused mapping too
        // (the router may still hold its lease).
        fn refuse_natpmp_renewals(req: &[u8], mut reply: Vec<u8>) -> Option<Vec<u8>> {
            if req[0] == 0 && req.len() == 12 && req[8..12] != [0; 4] {
                reply[3] = 2;
            }
            Some(reply)
        }
        let mut lab = Lab::new(Mode::NatPmpOnly);
        lab.gw.max_lifetime_s = 600;
        lab.want(Proto::Udp);
        assert_eq!(lab.take().len(), 1);
        lab.rewrite = Some(refuse_natpmp_renewals);
        lab.run_to(secs(300));
        let events = lab.take();
        assert_eq!(
            events[0],
            Out::Refused {
                via: Via::NatPmp,
                code: NATPMP_NOT_AUTHORIZED
            }
        );
        let last = lab.maps().last().unwrap().1;
        assert_eq!((last.proto, last.lifetime), (Some(17), 0));
        assert!(lab.gw.mappings.is_empty());
    }

    /// Review C-5: the core puts its router's address into every nonce, so
    /// the same profile and internal endpoint behind another router sends
    /// another one.
    #[test]
    fn the_nonce_names_the_router_asked() {
        let venue = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let other = MapperConfig::new(Zeroizing::new(KEY), venue);
        let mut home = Lab::new(Mode::Pcp);
        let mut away = Lab::with(Mode::Pcp, CLIENT, other, None);
        home.want(Proto::Tcp);
        away.want(Proto::Tcp);
        let (home_nonce, away_nonce) = (home.maps()[0].1.nonce, away.maps()[0].1.nonce);
        assert_eq!(
            home_nonce,
            Some(pcp_nonce(&KEY, GW, CLIENT, Proto::Tcp, PORT))
        );
        assert_eq!(
            away_nonce,
            Some(pcp_nonce(&KEY, venue, CLIENT, Proto::Tcp, PORT))
        );
        assert_ne!(home_nonce, away_nonce);
    }

    #[test]
    fn a_reply_with_a_foreign_nonce_or_port_is_ignored() {
        let mut lab = Lab::new(Mode::Pcp);
        lab.want(Proto::Tcp);
        lab.take();
        let wake = lab.core.next_wake();
        let tcp = pcp_nonce(&KEY, GW, CLIENT, Proto::Tcp, PORT);
        let reply = |nonce: [u8; 12], proto: u8, port: u16, ip: Ipv4Addr| {
            let mut b = vec![2, 0x80 | PCP_OP_MAP, 0, 0];
            b.extend_from_slice(&600u32.to_be_bytes());
            // The epoch the fake gateway would send a second later.
            b.extend_from_slice(&1u32.to_be_bytes());
            b.extend_from_slice(&[0; 12]);
            b.extend_from_slice(&nonce);
            b.extend_from_slice(&[proto, 0, 0, 0]);
            b.extend_from_slice(&port.to_be_bytes());
            b.extend_from_slice(&40_001u16.to_be_bytes());
            b.extend_from_slice(&ip.to_ipv6_mapped().octets());
            b
        };
        let cgn = Ipv4Addr::new(100, 64, 0, 9);
        let now = lab.now + secs(1);
        for b in [
            reply([1; 12], 6, PORT, cgn),
            reply(tcp, 6, PORT + 1, cgn),
            reply(tcp, 17, PORT, cgn),
            reply([1; 12], 6, PORT, FAKE_EXTERNAL_V4),
        ] {
            assert!(lab.core.on_datagram(&b, now).is_empty());
        }
        // NAT-PMP answers and ANNOUNCE answers are not PCP MAP answers.
        let mut nat = vec![0, 0x82, 0, 0, 0, 0, 0, 10];
        nat.extend_from_slice(&PORT.to_be_bytes());
        nat.extend_from_slice(&[0x9c, 0x41, 0, 0, 2, 0x58]);
        assert!(lab.core.on_datagram(&nat, now).is_empty());
        let announce = [&[2u8, 0x80, 0, 0][..], &[0; 20]].concat();
        assert!(lab.core.on_datagram(&announce, now).is_empty());
        assert_eq!(lab.core.next_wake(), wake);
        assert!(!lab.core.is_halted());
        // The real answer still moves it.
        let out = lab
            .core
            .on_datagram(&reply(tcp, 6, PORT, FAKE_EXTERNAL_V4), now);
        let at = ext(FAKE_EXTERNAL_V4, PORT);
        assert_eq!(
            out,
            [
                expired(Via::Pcp, Proto::Tcp, at),
                mapped(Via::Pcp, Proto::Tcp, ext(FAKE_EXTERNAL_V4, 40_001))
            ]
        );
    }
}
