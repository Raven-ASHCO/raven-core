//! STUN Binding for auto-reach (`docs/design/2026-10-auto-reach.md` §3): the
//! request a node sends a public STUN server to learn which public address
//! and port the server sees, the strict reading of the answer, and what a
//! set of answers says about this computer's NAT. Pure: no socket, no
//! clock, no DNS; raven-node sends and receives (`raven-node/src/autoreach.rs`).
//!
//! **What is sent.** A bare RFC 8489 Binding request ([`binding_request`]):
//! 20 bytes, the magic cookie and a random 96-bit transaction ID, no
//! attribute. No USERNAME, SOFTWARE, key, PeerId or Raven marker ever goes to
//! a STUN server.
//!
//! **What is accepted** ([`parse_binding_success`]): a Binding success
//! response (`0x0101`) with the magic cookie and the transaction ID asked
//! for, a length that matches the datagram, well-formed attributes, a right
//! FINGERPRINT when one is present (RFC 8489 §14.7), no comprehension-required
//! attribute this reader does not know (§6.3.3: such a response is
//! discarded; the RFC 3489 and RFC 5780 attributes servers still send are
//! known), and a mapped address: XOR-MAPPED-ADDRESS first, MAPPED-ADDRESS
//! (older servers) otherwise. An unspecified, multicast, broadcast or port-0
//! address is no answer. The sender's address is the caller's check.
//!
//! **Classes** ([`classify`]): the words and codes of the Phase 4 NAT class
//! (RRH1 NAT_CLASS, `RAVEN_ROUTE_HINTS_V1.md` §13.1), from the answers one
//! local socket got from at least two independent servers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

/// RFC 8489 §5: the fixed magic cookie.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// Binding request (method 0x001, class request).
pub const BINDING_REQUEST: u16 = 0x0001;
/// Binding success response.
pub const BINDING_SUCCESS: u16 = 0x0101;
/// The STUN header: type, length, cookie, transaction ID.
pub const HEADER_LEN: usize = 20;
/// The longest answer read: a Binding response is well under one Ethernet
/// payload; anything longer is no answer.
pub const MAX_MESSAGE_LEN: usize = 1280;
/// A transaction ID (RFC 8489 §5: 96 bits).
pub type TxId = [u8; 12];

/// MAPPED-ADDRESS (RFC 8489 §14.1).
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// XOR-MAPPED-ADDRESS (§14.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// FINGERPRINT (§14.7).
pub const ATTR_FINGERPRINT: u16 = 0x8028;
/// The FINGERPRINT XOR value (§14.7, "STUN").
pub const FINGERPRINT_XOR: u32 = 0x5354_554E;

/// Comprehension-required attributes (type below 0x8000) this reader knows,
/// whether or not it reads them: RFC 8489 §18.3 (MAPPED-ADDRESS, USERNAME,
/// MESSAGE-INTEGRITY, ERROR-CODE, UNKNOWN-ATTRIBUTES, REALM, NONCE,
/// MESSAGE-INTEGRITY-SHA256, PASSWORD-ALGORITHM, USERHASH,
/// XOR-MAPPED-ADDRESS), RFC 3489's RESPONSE-ADDRESS, CHANGE-REQUEST,
/// SOURCE-ADDRESS, CHANGED-ADDRESS and REFLECTED-FROM (old servers still send
/// some), RFC 5780's PADDING and RESPONSE-PORT, and RFC 8445's PRIORITY and
/// USE-CANDIDATE.
const KNOWN_REQUIRED: [u16; 21] = [
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0009, 0x000A, 0x000B, 0x0014, 0x0015,
    0x001C, 0x001D, 0x001E, 0x0020, 0x0024, 0x0025, 0x0026, 0x0027, 0x0007,
];

/// The Binding request for transaction `txid`: 20 bytes, no attribute.
pub fn binding_request(txid: &TxId) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Length 0: no attribute.
    out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out[8..20].copy_from_slice(txid);
    out
}

/// Why a datagram is no answer to a request in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Shorter than the header, longer than [`MAX_MESSAGE_LEN`], or the top
    /// two bits of the type are set: not STUN.
    NotStun,
    /// No magic cookie (RFC 3489 server or not STUN).
    NoCookie,
    /// Another transaction ID.
    OtherTransaction,
    /// Not a Binding success response (an error response, say).
    NotSuccess(u16),
    /// The length field does not match the datagram, is not a multiple of
    /// four, or an attribute runs past the end.
    Malformed,
    /// A FINGERPRINT that does not match, or one that is not last.
    BadFingerprint,
    /// A comprehension-required attribute this reader does not know.
    UnknownRequired(u16),
    /// No usable mapped address.
    NoMappedAddress,
}

/// CRC-32 (IEEE 802.3, reflected, as zlib computes it) of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Does `msg` end in a FINGERPRINT attribute that matches the message before
/// it (RFC 8489 §14.7: the CRC over the message up to the attribute, with the
/// header length already counting it, XOR 0x5354554E)?
pub fn fingerprint_ok(msg: &[u8]) -> bool {
    if msg.len() < HEADER_LEN + 8 {
        return false;
    }
    let at = msg.len() - 8;
    if u16::from_be_bytes([msg[at], msg[at + 1]]) != ATTR_FINGERPRINT
        || u16::from_be_bytes([msg[at + 2], msg[at + 3]]) != 4
    {
        return false;
    }
    let want = u32::from_be_bytes([msg[at + 4], msg[at + 5], msg[at + 6], msg[at + 7]]);
    crc32(&msg[..at]) ^ FINGERPRINT_XOR == want
}

/// The mapped address of a Binding success response to transaction `txid`
/// (module doc, "What is accepted").
pub fn parse_binding_success(msg: &[u8], txid: &TxId) -> Result<SocketAddr, ParseError> {
    if msg.len() < HEADER_LEN || msg.len() > MAX_MESSAGE_LEN || msg[0] & 0xC0 != 0 {
        return Err(ParseError::NotStun);
    }
    let kind = u16::from_be_bytes([msg[0], msg[1]]);
    let len = usize::from(u16::from_be_bytes([msg[2], msg[3]]));
    let cookie = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(ParseError::NoCookie);
    }
    if msg[8..20] != txid[..] {
        return Err(ParseError::OtherTransaction);
    }
    if kind != BINDING_SUCCESS {
        return Err(ParseError::NotSuccess(kind));
    }
    if len % 4 != 0 || HEADER_LEN + len != msg.len() {
        return Err(ParseError::Malformed);
    }
    let mut xor_mapped: Option<SocketAddr> = None;
    let mut mapped: Option<SocketAddr> = None;
    let mut pos = HEADER_LEN;
    while pos < msg.len() {
        if pos + 4 > msg.len() {
            return Err(ParseError::Malformed);
        }
        let attr = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let alen = usize::from(u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]));
        let start = pos + 4;
        let end = start + alen;
        let padded = start + alen.div_ceil(4) * 4;
        if padded > msg.len() {
            return Err(ParseError::Malformed);
        }
        let value = &msg[start..end];
        match attr {
            ATTR_FINGERPRINT => {
                // Last, four bytes, and right.
                if alen != 4 || padded != msg.len() || !fingerprint_ok(msg) {
                    return Err(ParseError::BadFingerprint);
                }
            }
            ATTR_XOR_MAPPED_ADDRESS if xor_mapped.is_none() => {
                xor_mapped = address_value(value, Some(txid));
            }
            ATTR_MAPPED_ADDRESS if mapped.is_none() => {
                mapped = address_value(value, None);
            }
            a if a < 0x8000 && !KNOWN_REQUIRED.contains(&a) => {
                return Err(ParseError::UnknownRequired(a));
            }
            _ => {}
        }
        pos = padded;
    }
    xor_mapped
        .or(mapped)
        .filter(|a| usable_mapped(*a))
        .ok_or(ParseError::NoMappedAddress)
}

/// An address attribute's value (family, port, address), XOR-ed with the
/// cookie (and, for IPv6, the transaction ID) when `xor` names the
/// transaction. `None` when malformed.
fn address_value(value: &[u8], xor: Option<&TxId>) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    if xor.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    match (family, value.len()) {
        (0x01, 8) => {
            let mut ip = [value[4], value[5], value[6], value[7]];
            if xor.is_some() {
                for (b, k) in ip.iter_mut().zip(cookie) {
                    *b ^= k;
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        (0x02, 20) => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[4..20]);
            if let Some(txid) = xor {
                let key: Vec<u8> = cookie.iter().chain(txid.iter()).copied().collect();
                for (b, k) in ip.iter_mut().zip(key) {
                    *b ^= k;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

/// A mapped address worth anything: a port, and a unicast IP that is not
/// unspecified, multicast or the IPv4 broadcast address.
fn usable_mapped(a: SocketAddr) -> bool {
    a.port() != 0
        && match a.ip() {
            IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
        }
}

/// What a NAT does to this host's outbound UDP mapping, in the Phase 4 NAT
/// class words and RRH1 codes (`raven_swarm::natclass::Mapping`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StunClass {
    /// Fewer than two independent answers.
    #[default]
    Unknown,
    /// The mapped address is this computer's own, on the local port.
    NoNat,
    /// Every server saw one address, on the local port (port preserved).
    StableKept,
    /// Every server saw one address, on another port.
    StableShifted,
    /// The servers saw different addresses or ports.
    Varies,
}

impl StunClass {
    /// The NAT class word (logs, status).
    pub fn word(self) -> &'static str {
        match self {
            StunClass::Unknown => "unknown",
            StunClass::NoNat => "no_nat",
            StunClass::StableKept => "stable_kept",
            StunClass::StableShifted => "stable_shifted",
            StunClass::Varies => "varies",
        }
    }

    /// The RRH1 NAT_CLASS code (route hints spec §13.1).
    pub fn code(self) -> u8 {
        match self {
            StunClass::Unknown => 0,
            StunClass::NoNat => 1,
            StunClass::StableKept => 2,
            StunClass::StableShifted => 3,
            StunClass::Varies => 4,
        }
    }

    /// Endpoint-independent (or no NAT at all): a friend that knows the
    /// mapped endpoint can punch to it.
    pub fn punchable(self) -> bool {
        matches!(
            self,
            StunClass::NoNat | StunClass::StableKept | StunClass::StableShifted
        )
    }

    /// How the class reads in one plain phrase (logs, status).
    pub fn phrase(self) -> &'static str {
        match self {
            StunClass::Unknown => "NAT class unknown",
            StunClass::NoNat => "no NAT",
            StunClass::StableKept => "NAT endpoint-independent, port kept",
            StunClass::StableShifted => "NAT endpoint-independent, port changed",
            StunClass::Varies => "NAT endpoint-dependent",
        }
    }
}

/// Does the RRH1 NAT_CLASS code `code` (no_nat, stable_kept or
/// stable_shifted) keep one mapping for every destination, so a friend that
/// knows the mapped endpoint can punch to it ([`StunClass::punchable`])?
pub fn class_punchable(code: u8) -> bool {
    matches!(code, 1..=3)
}

/// One server's answer to one local socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The server's address (where the request went and the answer came
    /// from).
    pub server: SocketAddr,
    /// The address and port it saw us at.
    pub mapped: SocketAddrV4,
}

/// What one probe's answers say ([`classify`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Discovery {
    /// The public IPv4 address, when two independent servers answered and
    /// every answer names the same one (one answer alone could be spoofed).
    pub public_ip: Option<Ipv4Addr>,
    /// The public endpoint of the local socket: the one every answer named,
    /// when two independent servers answered.
    pub mapped: Option<SocketAddrV4>,
    pub class: StunClass,
    /// Answers, and how many came from independent servers.
    pub answered: u32,
    pub independent: u32,
}

/// Classify the IPv4 `answers` one local socket bound at `local` got
/// (module doc). `own` holds this computer's interface addresses (for
/// `no_nat` when `local` is a wildcard). `by_port`: servers count as
/// independent by address and port (a harness's fake servers on one IP),
/// else by address only.
pub fn classify(
    local: SocketAddrV4,
    own: &[IpAddr],
    answers: &[Answer],
    by_port: bool,
) -> Discovery {
    let mut servers: Vec<SocketAddr> = Vec::new();
    for a in answers {
        let key = if by_port {
            a.server
        } else {
            SocketAddr::new(a.server.ip(), 0)
        };
        if !servers.contains(&key) {
            servers.push(key);
        }
    }
    let answered = u32::try_from(answers.len()).unwrap_or(u32::MAX);
    let independent = u32::try_from(servers.len()).unwrap_or(u32::MAX);
    let Some(first) = answers.first() else {
        return Discovery::default();
    };
    let same_ip = answers.iter().all(|a| a.mapped.ip() == first.mapped.ip());
    let same_endpoint = answers.iter().all(|a| a.mapped == first.mapped);
    // One unauthenticated STUN answer (a spoofed UDP reply) is no address to
    // advertise to friends: the address and the endpoint count only when two
    // independent servers (both operators) agree on them.
    let agreed = independent >= 2;
    let public_ip = (agreed && same_ip).then_some(*first.mapped.ip());
    let mapped = (agreed && same_endpoint).then_some(first.mapped);
    let class = if independent < 2 {
        StunClass::Unknown
    } else if !same_endpoint {
        StunClass::Varies
    } else {
        let ip = IpAddr::V4(*first.mapped.ip());
        let own_ip = (!local.ip().is_unspecified() && *local.ip() == *first.mapped.ip())
            || own.contains(&ip);
        if own_ip && first.mapped.port() == local.port() {
            StunClass::NoNat
        } else if first.mapped.port() == local.port() {
            StunClass::StableKept
        } else {
            StunClass::StableShifted
        }
    };
    Discovery {
        public_ip,
        mapped,
        class,
        answered,
        independent,
    }
}

/// The public STUN servers a node asks (design §3.2, owner decision AR-1):
/// Cloudflare and Google, IPv4 over UDP. Every probe asks both at once;
/// the address, the endpoint and the class need both to answer and agree
/// (one answer alone could be spoofed: [`classify`]). Never used by a
/// harness, which names its own
/// ([`crate::portmap_gate::lab_stun_servers`]).
pub const PUBLIC_SERVERS: [(&str, u16); 2] =
    [("stun.cloudflare.com", 3478), ("stun.l.google.com", 19302)];

/// The operators of [`PUBLIC_SERVERS`], in order (status and consent text).
pub const PUBLIC_OPERATORS: [&str; 2] = ["Cloudflare", "Google"];

/// The servers every probe asks: all of [`PUBLIC_SERVERS`].
pub fn servers_to_ask() -> Vec<(&'static str, u16)> {
    PUBLIC_SERVERS.to_vec()
}

/// The user-facing sentence about what STUN discovery does (status, doctor,
/// `raven node stun`).
pub const CONSENT_TEXT: &str = "Raven asks two public STUN servers (Cloudflare and Google) which \
    internet address they see for this computer. They see that address and when you ask; \
    nothing else is sent. Turn it off with `raven node stun off`.";

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 5769 §2: every sample's transaction ID.
    const RFC5769_TXID: TxId = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    /// RFC 5769 §2.1, Sample Request.
    fn rfc5769_request() -> Vec<u8> {
        hex("00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
             80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74
             00 24 00 04 6e 00 01 ff 80 29 00 08 93 2f f9 b1 51 26 3b 36
             00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20
             00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2
             80 28 00 04 e5 7a 3b cf")
    }

    /// RFC 5769 §2.2, Sample IPv4 Response (192.0.2.1:32853).
    fn rfc5769_v4() -> Vec<u8> {
        hex("01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
             80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
             00 20 00 08 00 01 a1 47 e1 12 a6 43
             00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7
             80 28 00 04 c0 7d 4c 96")
    }

    /// RFC 5769 §2.3, Sample IPv6 Response
    /// ([2001:db8:1234:5678:11:2233:4455:6677]:32853).
    fn rfc5769_v6() -> Vec<u8> {
        hex("01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
             80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
             00 20 00 14 00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9
             00 08 00 14 a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75 bf e3 ed 41
             80 28 00 04 c8 fb 0b 4c")
    }

    /// A Binding success response to `txid` with these attributes (each
    /// padded), and a FINGERPRINT when `fp`.
    fn response(txid: &TxId, attrs: &[(u16, Vec<u8>)], fp: bool) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let total = body.len() + if fp { 8 } else { 0 };
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(total as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(txid);
        msg.extend_from_slice(&body);
        if fp {
            // The header's length already counts the FINGERPRINT.
            let crc = crc32(&msg) ^ FINGERPRINT_XOR;
            msg.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
            msg.extend_from_slice(&4u16.to_be_bytes());
            msg.extend_from_slice(&crc.to_be_bytes());
        }
        msg
    }

    fn xor_v4(addr: SocketAddrV4) -> Vec<u8> {
        let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
        let ip = u32::from(*addr.ip()) ^ MAGIC_COOKIE;
        let mut v = vec![0, 1];
        v.extend_from_slice(&port.to_be_bytes());
        v.extend_from_slice(&ip.to_be_bytes());
        v
    }

    fn plain_v4(addr: SocketAddrV4) -> Vec<u8> {
        let mut v = vec![0, 1];
        v.extend_from_slice(&addr.port().to_be_bytes());
        v.extend_from_slice(&addr.ip().octets());
        v
    }

    const TX: TxId = [7; 12];

    fn v4(text: &str) -> SocketAddrV4 {
        text.parse().unwrap()
    }

    #[test]
    fn crc32_matches_the_check_value() {
        // The CRC-32 check value of "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn the_request_is_20_bytes_with_the_cookie_and_the_transaction() {
        let req = binding_request(&RFC5769_TXID);
        assert_eq!(req.len(), 20);
        assert_eq!(
            req[..8],
            [0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42],
            "type 0x0001, length 0, magic cookie"
        );
        assert_eq!(req[8..], RFC5769_TXID);
        // The RFC's sample request has the same header fields.
        let sample = rfc5769_request();
        assert_eq!(sample[..2], req[..2]);
        assert_eq!(sample[4..20], req[4..20]);
    }

    #[test]
    fn rfc5769_fingerprints_check() {
        assert!(fingerprint_ok(&rfc5769_request()));
        assert!(fingerprint_ok(&rfc5769_v4()));
        assert!(fingerprint_ok(&rfc5769_v6()));
        let mut bad = rfc5769_v4();
        let at = bad.len() - 1;
        bad[at] ^= 1;
        assert!(!fingerprint_ok(&bad));
    }

    #[test]
    fn rfc5769_ipv4_response() {
        assert_eq!(
            parse_binding_success(&rfc5769_v4(), &RFC5769_TXID),
            Ok("192.0.2.1:32853".parse().unwrap())
        );
    }

    #[test]
    fn rfc5769_ipv6_response() {
        assert_eq!(
            parse_binding_success(&rfc5769_v6(), &RFC5769_TXID),
            Ok("[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                .parse()
                .unwrap())
        );
    }

    #[test]
    fn the_request_itself_is_no_answer() {
        assert_eq!(
            parse_binding_success(&rfc5769_request(), &RFC5769_TXID),
            Err(ParseError::NotSuccess(BINDING_REQUEST))
        );
    }

    #[test]
    fn xor_mapped_wins_over_mapped_and_mapped_alone_is_read() {
        let a = v4("203.0.113.7:40000");
        let b = v4("198.51.100.9:1234");
        let both = response(
            &TX,
            &[
                (ATTR_MAPPED_ADDRESS, plain_v4(b)),
                (ATTR_XOR_MAPPED_ADDRESS, xor_v4(a)),
            ],
            true,
        );
        assert_eq!(parse_binding_success(&both, &TX), Ok(a.into()));
        let old = response(&TX, &[(ATTR_MAPPED_ADDRESS, plain_v4(b))], false);
        assert_eq!(parse_binding_success(&old, &TX), Ok(b.into()));
    }

    #[test]
    fn rejections() {
        let a = v4("203.0.113.7:40000");
        let good = response(&TX, &[(ATTR_XOR_MAPPED_ADDRESS, xor_v4(a))], true);
        assert!(parse_binding_success(&good, &TX).is_ok());
        // Another transaction.
        assert_eq!(
            parse_binding_success(&good, &[8; 12]),
            Err(ParseError::OtherTransaction)
        );
        // Short, too long, top bits set.
        assert_eq!(
            parse_binding_success(&good[..19], &TX),
            Err(ParseError::NotStun)
        );
        assert_eq!(
            parse_binding_success(&vec![0; MAX_MESSAGE_LEN + 4], &TX),
            Err(ParseError::NotStun)
        );
        let mut top = good.clone();
        top[0] |= 0x80;
        assert_eq!(parse_binding_success(&top, &TX), Err(ParseError::NotStun));
        // No cookie (RFC 3489).
        let mut old = good.clone();
        old[4] ^= 0xff;
        assert_eq!(parse_binding_success(&old, &TX), Err(ParseError::NoCookie));
        // An error response.
        let mut err = good.clone();
        err[0..2].copy_from_slice(&0x0111u16.to_be_bytes());
        assert_eq!(
            parse_binding_success(&err, &TX),
            Err(ParseError::NotSuccess(0x0111))
        );
        // A length that does not match the datagram.
        let mut long = good.clone();
        long.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            parse_binding_success(&long, &TX),
            Err(ParseError::Malformed)
        );
        // A broken FINGERPRINT.
        let mut fp = good.clone();
        let at = fp.len() - 1;
        fp[at] ^= 1;
        assert_eq!(
            parse_binding_success(&fp, &TX),
            Err(ParseError::BadFingerprint)
        );
        // An attribute running past the end.
        let mut cut = response(&TX, &[(ATTR_XOR_MAPPED_ADDRESS, xor_v4(a))], false);
        cut[23] = 0x40;
        assert_eq!(parse_binding_success(&cut, &TX), Err(ParseError::Malformed));
        // An unknown comprehension-required attribute.
        let unknown = response(
            &TX,
            &[
                (0x7777, vec![1, 2, 3, 4]),
                (ATTR_XOR_MAPPED_ADDRESS, xor_v4(a)),
            ],
            false,
        );
        assert_eq!(
            parse_binding_success(&unknown, &TX),
            Err(ParseError::UnknownRequired(0x7777))
        );
        // Unknown comprehension-optional attributes and known old ones pass.
        let optional = response(
            &TX,
            &[
                (0x8022, b"srv".to_vec()),
                (0x0004, plain_v4(v4("192.0.2.2:3478"))),
                (0x0005, plain_v4(v4("192.0.2.3:3479"))),
                (0x802b, plain_v4(v4("192.0.2.2:3478"))),
                (ATTR_XOR_MAPPED_ADDRESS, xor_v4(a)),
            ],
            true,
        );
        assert_eq!(parse_binding_success(&optional, &TX), Ok(a.into()));
        // No mapped address, or a useless one.
        let none = response(&TX, &[(0x8022, b"srv".to_vec())], true);
        assert_eq!(
            parse_binding_success(&none, &TX),
            Err(ParseError::NoMappedAddress)
        );
        for useless in [
            "0.0.0.0:4000",
            "224.0.0.1:4000",
            "255.255.255.255:4000",
            "203.0.113.7:0",
        ] {
            let r = response(
                &TX,
                &[(ATTR_XOR_MAPPED_ADDRESS, xor_v4(v4(useless)))],
                false,
            );
            assert_eq!(
                parse_binding_success(&r, &TX),
                Err(ParseError::NoMappedAddress),
                "{useless}"
            );
        }
        // A short address value is no address.
        let short = response(&TX, &[(ATTR_XOR_MAPPED_ADDRESS, vec![0, 1, 2])], false);
        assert_eq!(
            parse_binding_success(&short, &TX),
            Err(ParseError::NoMappedAddress)
        );
    }

    fn answer(server: &str, mapped: &str) -> Answer {
        Answer {
            server: server.parse().unwrap(),
            mapped: v4(mapped),
        }
    }

    #[test]
    fn classes() {
        let local = v4("0.0.0.0:17423");
        // The home router of the field test: one address and the local port.
        let kept = classify(
            local,
            &[],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:17423"),
                answer("198.51.100.20:19302", "203.0.113.7:17423"),
                answer("192.0.2.30:443", "203.0.113.7:17423"),
            ],
            false,
        );
        assert_eq!(kept.class, StunClass::StableKept);
        assert_eq!(kept.mapped, Some(v4("203.0.113.7:17423")));
        assert_eq!(kept.public_ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!((kept.answered, kept.independent), (3, 3));
        assert!(kept.class.punchable());
        // Another port, the same for both.
        let shifted = classify(
            local,
            &[],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:5000"),
                answer("198.51.100.20:19302", "203.0.113.7:5000"),
            ],
            false,
        );
        assert_eq!(shifted.class, StunClass::StableShifted);
        assert!(shifted.class.punchable());
        // Ports differ per server: endpoint-dependent; the IP is still known.
        let varies = classify(
            local,
            &[],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:5000"),
                answer("198.51.100.20:19302", "203.0.113.7:5001"),
            ],
            false,
        );
        assert_eq!(varies.class, StunClass::Varies);
        assert_eq!(varies.mapped, None);
        assert_eq!(varies.public_ip, Some("203.0.113.7".parse().unwrap()));
        assert!(!varies.class.punchable());
        // An address pool: no public IP.
        let pool = classify(
            local,
            &[],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:5000"),
                answer("198.51.100.20:19302", "203.0.113.8:5000"),
            ],
            false,
        );
        assert_eq!((pool.class, pool.public_ip), (StunClass::Varies, None));
        // One server, twice: not independent.
        let one = classify(
            local,
            &[],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:17423"),
                answer("192.0.2.10:3479", "203.0.113.7:17423"),
            ],
            false,
        );
        assert_eq!(one.class, StunClass::Unknown);
        assert_eq!(one.independent, 1);
        // One server alone (one answer could be spoofed) names no address
        // and no endpoint.
        assert_eq!((one.public_ip, one.mapped), (None, None));
        let agreed = classify(
            local,
            &[],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:17423"),
                answer("198.51.100.20:19302", "203.0.113.7:17423"),
            ],
            false,
        );
        assert_eq!(agreed.public_ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(agreed.mapped, Some(v4("203.0.113.7:17423")));
        // Two servers that disagree on the address: none.
        let spoofed = classify(
            local,
            &[],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:17423"),
                answer("198.51.100.20:19302", "198.18.0.66:17423"),
            ],
            false,
        );
        assert_eq!(spoofed.public_ip, None);
        // The same two count by port in a harness.
        let lab = classify(
            v4("127.0.0.1:17423"),
            &[],
            &[
                answer("127.0.0.1:3478", "127.0.0.1:20001"),
                answer("127.0.0.1:3479", "127.0.0.1:20001"),
            ],
            true,
        );
        assert_eq!(lab.class, StunClass::StableShifted);
        // Our own address on our port: no NAT (bound to the address, or a
        // wildcard and the address is an interface's).
        let own = classify(
            v4("203.0.113.7:17423"),
            &[],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:17423"),
                answer("198.51.100.20:19302", "203.0.113.7:17423"),
            ],
            false,
        );
        assert_eq!(own.class, StunClass::NoNat);
        let wild = classify(
            local,
            &["203.0.113.7".parse().unwrap()],
            &[
                answer("192.0.2.10:3478", "203.0.113.7:17423"),
                answer("198.51.100.20:19302", "203.0.113.7:17423"),
            ],
            false,
        );
        assert_eq!(wild.class, StunClass::NoNat);
        // Nothing at all.
        assert_eq!(classify(local, &[], &[], false), Discovery::default());
    }

    #[test]
    fn class_codes_are_the_nat_class_codes() {
        for (c, code, word) in [
            (StunClass::Unknown, 0, "unknown"),
            (StunClass::NoNat, 1, "no_nat"),
            (StunClass::StableKept, 2, "stable_kept"),
            (StunClass::StableShifted, 3, "stable_shifted"),
            (StunClass::Varies, 4, "varies"),
        ] {
            assert_eq!((c.code(), c.word()), (code, word));
        }
    }

    #[test]
    fn every_probe_asks_both_operators() {
        let s = servers_to_ask();
        assert_eq!(
            s,
            vec![("stun.cloudflare.com", 3478), ("stun.l.google.com", 19302)]
        );
        assert_eq!(PUBLIC_OPERATORS.len(), PUBLIC_SERVERS.len());
        for op in PUBLIC_OPERATORS {
            assert!(CONSENT_TEXT.contains(op), "{op}");
        }
        for gone in ["Nextcloud", "sipgate", "Twilio"] {
            assert!(!CONSENT_TEXT.contains(gone), "{gone}");
        }
    }
}
