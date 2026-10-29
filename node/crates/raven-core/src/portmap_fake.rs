//! A pure NAT-PMP (RFC 6886) and PCP (RFC 6887) gateway for tests: no
//! sockets, explicit clocks. Written from the RFCs' field tables on its own
//! (it parses requests and builds replies itself, sharing no code with the
//! client codec in [`crate::portmap`]) and checked against
//! `shared-vectors/rvn1/portmap`. Harnesses wrap it in a thread that owns a
//! UDP socket.
//!
//! Test code only: compiled for raven-core's own tests and with the
//! `test-helpers` feature, never into a release build.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The external IPv4 address the gateway reports unless
/// [`Mode::ExternalIp`] names another (a global address).
pub const FAKE_EXTERNAL_V4: Ipv4Addr = Ipv4Addr::new(11, 0, 2, 9);
/// The longest lifetime the gateway grants unless told otherwise
/// ([`FakeGateway::max_lifetime_s`]).
pub const FAKE_MAX_LIFETIME_S: u32 = 7200;
/// The first external port the gateway assigns when neither the suggested
/// nor the internal port is free.
const FIRST_FREE_PORT: u16 = 40_000;

const PCP_HEADER: usize = 24;
const MAP_DATA: usize = 36;
const MAX_PCP: usize = 1100;

// PCP result codes (RFC 6887 §7.4) and NAT-PMP result codes (RFC 6886 §3.5).
const PCP_SUCCESS: u8 = 0;
const PCP_UNSUPP_VERSION: u8 = 1;
const PCP_NOT_AUTHORIZED: u8 = 2;
const PCP_MALFORMED_REQUEST: u8 = 3;
const PCP_UNSUPP_OPCODE: u8 = 4;
const PCP_UNSUPP_OPTION: u8 = 5;
const PCP_MALFORMED_OPTION: u8 = 6;
const PCP_NO_RESOURCES: u8 = 8;
const PCP_UNSUPP_PROTOCOL: u8 = 9;
const PCP_CANNOT_PROVIDE_EXTERNAL: u8 = 11;
const PCP_ADDRESS_MISMATCH: u8 = 12;
const NATPMP_UNSUPP_VERSION: u8 = 1;
const NATPMP_NOT_AUTHORIZED: u8 = 2;
const NATPMP_OUT_OF_RESOURCES: u8 = 4;
const NATPMP_UNSUPP_OPCODE: u8 = 5;

/// How the gateway behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Speaks PCP and NAT-PMP (as miniupnpd does), maps what it is asked.
    Pcp,
    /// Speaks NAT-PMP only: a PCP request gets the 8-byte "unsupported
    /// version" answer (version 0, opcode 128 + the request's opcode).
    NatPmpOnly,
    /// Answers nothing.
    Silent,
    /// Refuses every mapping (PCP NOT_AUTHORIZED, NAT-PMP 2); the probes
    /// still succeed.
    NotAuthorized,
    /// Refuses every mapping for lack of resources (PCP NO_RESOURCES with
    /// `retry_s` as the error's lifetime, NAT-PMP 4).
    NoResources { retry_s: u32 },
    /// A PCP MAP that suggests an external port gets CANNOT_PROVIDE_EXTERNAL
    /// unless it renews a mapping; one that suggests port 0 is mapped.
    CannotProvideExternal,
    /// Maps every new mapping to this external port.
    AssignPort(u16),
    /// Reports this external IPv4 address (for example the CGN address
    /// 100.64.0.9) instead of [`FAKE_EXTERNAL_V4`].
    ExternalIp(IpAddr),
    /// Loses every mapping, and restarts its epoch at 0, once this long
    /// after [`FakeGateway::epoch_start`]; behaves as [`Mode::Pcp`] after.
    EpochResetAt(Duration),
    /// Answers the request that creates a mapping, drops every renewal.
    DropRenewals,
    /// Also serves IPv6 clients: a MAP opens a pinhole, the external
    /// address and port are the internal ones. In every other mode a
    /// request from an IPv6 source gets no answer.
    Ipv6Firewall,
}

/// A mapping the gateway holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub client: IpAddr,
    /// IANA protocol number (6 TCP, 17 UDP).
    pub proto: u8,
    pub internal_port: u16,
    pub external_port: u16,
    /// The PCP nonce that owns it (`None`: made by NAT-PMP).
    pub nonce: Option<[u8; 12]>,
    pub expires: Instant,
}

/// A request the gateway received, for assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeenReq {
    pub src: SocketAddr,
    /// 2 PCP, 0 NAT-PMP (another value: some other version).
    pub version: u8,
    /// The opcode, R bit cleared.
    pub op: u8,
    /// IANA protocol number of a mapping request.
    pub proto: Option<u8>,
    pub internal_port: u16,
    pub suggested_port: u16,
    pub lifetime: u32,
    pub nonce: Option<[u8; 12]>,
    /// The client address a PCP request names.
    pub client_ip: Option<IpAddr>,
}

/// The gateway. Every field is public, so a test can switch the mode, move
/// the epoch or drop mappings between requests.
#[derive(Clone, Debug)]
pub struct FakeGateway {
    pub mode: Mode,
    pub epoch_start: Instant,
    pub mappings: Vec<Mapping>,
    pub log: Vec<SeenReq>,
    pub max_lifetime_s: u32,
    /// The external IPv4 address reported in place of
    /// [`FAKE_EXTERNAL_V4`] ([`Mode::ExternalIp`] still wins): a harness on
    /// loopback names 127.0.0.1, where its forwarders listen, so that no
    /// test ever dials a real Internet address.
    pub reported_v4: Option<Ipv4Addr>,
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The address a 16-byte PCP field names: `::ffff:a.b.c.d` as IPv4.
fn field_ip(b: &[u8]) -> IpAddr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&b[..16]);
    let v6 = Ipv6Addr::from(o);
    v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
}

fn field_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// A datagram source as the gateway sees it: an IPv4-mapped IPv6 source is
/// the IPv4 address.
fn source_ip(src: SocketAddr) -> IpAddr {
    match src.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

impl FakeGateway {
    /// A gateway whose epoch starts at `now`.
    pub fn new(mode: Mode, now: Instant) -> Self {
        Self {
            mode,
            epoch_start: now,
            mappings: Vec::new(),
            log: Vec::new(),
            max_lifetime_s: FAKE_MAX_LIFETIME_S,
            reported_v4: None,
        }
    }

    /// Seconds since the start of the epoch at `now`.
    pub fn epoch(&self, now: Instant) -> u32 {
        u32::try_from(now.saturating_duration_since(self.epoch_start).as_secs()).unwrap_or(u32::MAX)
    }

    /// The external IPv4 address the gateway reports.
    pub fn external_v4(&self) -> Ipv4Addr {
        match self.mode {
            Mode::ExternalIp(IpAddr::V4(v4)) => v4,
            _ => self.reported_v4.unwrap_or(FAKE_EXTERNAL_V4),
        }
    }

    /// The answer to the datagram `req` from `src` at `now`, if any. Every
    /// request is logged first, even one that gets no answer.
    pub fn reply(&mut self, req: &[u8], src: SocketAddr, now: Instant) -> Option<Vec<u8>> {
        if req.len() < 2 {
            return None;
        }
        self.log.push(seen(req, src));
        if let Mode::EpochResetAt(after) = self.mode {
            if now >= self.epoch_start + after {
                self.mappings.clear();
                self.epoch_start = now;
                self.mode = Mode::Pcp;
            }
        }
        self.mappings.retain(|m| m.expires > now);
        if self.mode == Mode::Silent
            || req[1] & 0x80 != 0
            || (source_ip(src).is_ipv6() && self.mode != Mode::Ipv6Firewall)
        {
            return None;
        }
        let epoch = self.epoch(now);
        match req[0] {
            0 if source_ip(src).is_ipv4() => self.natpmp(req, src, now, epoch),
            0 => None,
            _ if self.mode == Mode::NatPmpOnly => {
                let mut b = vec![0, 0x80 | req[1], 0, NATPMP_UNSUPP_VERSION];
                b.extend_from_slice(&epoch.to_be_bytes());
                Some(b)
            }
            2 => self.pcp(req, src, now, epoch),
            _ => Some(pcp_header(req[1], PCP_UNSUPP_VERSION, 0, epoch)),
        }
    }

    fn natpmp(&mut self, req: &[u8], src: SocketAddr, now: Instant, epoch: u32) -> Option<Vec<u8>> {
        let op = req[1];
        let mut b = vec![0, 0x80 | op, 0, 0];
        b.extend_from_slice(&epoch.to_be_bytes());
        match op {
            0 if req.len() == 2 => {
                b.extend_from_slice(&self.external_v4().octets());
                Some(b)
            }
            1 | 2 if req.len() == 12 => {
                let proto = if op == 1 { 17 } else { 6 };
                let (internal, suggested, lifetime) =
                    (be16(&req[4..6]), be16(&req[6..8]), be32(&req[8..12]));
                let client = source_ip(src);
                let refused = match self.mode {
                    Mode::NotAuthorized => Some(NATPMP_NOT_AUTHORIZED),
                    Mode::NoResources { .. } => Some(NATPMP_OUT_OF_RESOURCES),
                    _ => None,
                };
                let (external, granted) = if let Some(code) = refused {
                    b[3] = code;
                    (0, 0)
                } else if lifetime == 0 {
                    self.mappings.retain(|m| {
                        !(m.client == client
                            && m.proto == proto
                            && (internal == 0 || m.internal_port == internal))
                    });
                    (0, 0)
                } else {
                    let existing = self.find(client, proto, internal).is_some();
                    if existing && self.mode == Mode::DropRenewals {
                        return None;
                    }
                    let granted = lifetime.min(self.max_lifetime_s);
                    let expires = now + Duration::from_secs(u64::from(granted));
                    let external = self.map(client, proto, internal, suggested, None, expires);
                    (external, granted)
                };
                b.extend_from_slice(&internal.to_be_bytes());
                b.extend_from_slice(&external.to_be_bytes());
                b.extend_from_slice(&granted.to_be_bytes());
                Some(b)
            }
            3..=127 => {
                b[3] = NATPMP_UNSUPP_OPCODE;
                Some(b)
            }
            _ => None,
        }
    }

    fn pcp(&mut self, req: &[u8], src: SocketAddr, now: Instant, epoch: u32) -> Option<Vec<u8>> {
        let op = req[1] & 0x7f;
        if req.len() < PCP_HEADER || req.len() > MAX_PCP || !req.len().is_multiple_of(4) {
            return Some(pcp_header(op, PCP_MALFORMED_REQUEST, 0, epoch));
        }
        // An error answer carries the request's opcode data and options.
        let error = |result: u8, lifetime: u32| {
            let mut b = pcp_header(op, result, lifetime, epoch);
            b.extend_from_slice(&req[PCP_HEADER..]);
            Some(b)
        };
        let client = field_ip(&req[8..24]);
        if client != source_ip(src) {
            return error(PCP_ADDRESS_MISMATCH, 0);
        }
        let data_len = match op {
            0 => 0,
            1 => MAP_DATA,
            _ => return error(PCP_UNSUPP_OPCODE, 0),
        };
        if req.len() < PCP_HEADER + data_len {
            return Some(pcp_header(op, PCP_MALFORMED_REQUEST, 0, epoch));
        }
        // Options: Raven's client sends none, and this gateway knows none.
        let mut rest = &req[PCP_HEADER + data_len..];
        while !rest.is_empty() {
            if rest.len() < 4 {
                return error(PCP_MALFORMED_OPTION, 0);
            }
            let padded = (usize::from(be16(&rest[2..4])) + 3) & !3;
            if 4 + padded > rest.len() {
                return error(PCP_MALFORMED_OPTION, 0);
            }
            if rest[0] < 128 {
                return error(PCP_UNSUPP_OPTION, 0);
            }
            rest = &rest[4 + padded..];
        }
        if op == 0 {
            return Some(pcp_header(op, PCP_SUCCESS, 0, epoch));
        }
        let d = &req[PCP_HEADER..PCP_HEADER + MAP_DATA];
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&d[..12]);
        let (proto, internal, suggested) = (d[12], be16(&d[16..18]), be16(&d[18..20]));
        let lifetime = be32(&req[4..8]);
        if proto != 6 && proto != 17 {
            return error(PCP_UNSUPP_PROTOCOL, 0);
        }
        if internal == 0 && lifetime != 0 {
            return error(PCP_MALFORMED_REQUEST, 0);
        }
        match self.mode {
            Mode::NotAuthorized => return error(PCP_NOT_AUTHORIZED, 0),
            Mode::NoResources { retry_s } => return error(PCP_NO_RESOURCES, retry_s),
            _ => {}
        }
        let existing = self.find(client, proto, internal);
        if existing.is_some_and(|m| m.nonce.is_some_and(|n| n != nonce)) {
            return error(PCP_NOT_AUTHORIZED, 0);
        }
        if lifetime == 0 {
            self.mappings.retain(|m| {
                !(m.client == client
                    && m.proto == proto
                    && (internal == 0 || m.internal_port == internal))
            });
            return error(PCP_SUCCESS, 0);
        }
        if existing.is_none() && suggested != 0 && self.mode == Mode::CannotProvideExternal {
            return error(PCP_CANNOT_PROVIDE_EXTERNAL, 0);
        }
        if existing.is_some() && self.mode == Mode::DropRenewals {
            return None;
        }
        let granted = lifetime.min(self.max_lifetime_s);
        let expires = now + Duration::from_secs(u64::from(granted));
        let external = self.map(client, proto, internal, suggested, Some(nonce), expires);
        let external_ip = if client.is_ipv6() {
            client
        } else {
            IpAddr::V4(self.external_v4())
        };
        let mut b = pcp_header(op, PCP_SUCCESS, granted, epoch);
        b.extend_from_slice(&nonce);
        b.extend_from_slice(&[proto, 0, 0, 0]);
        b.extend_from_slice(&internal.to_be_bytes());
        b.extend_from_slice(&external.to_be_bytes());
        b.extend_from_slice(&field_bytes(external_ip));
        Some(b)
    }

    fn find(&self, client: IpAddr, proto: u8, internal: u16) -> Option<Mapping> {
        self.mappings
            .iter()
            .copied()
            .find(|m| m.client == client && m.proto == proto && m.internal_port == internal)
    }

    /// Create or renew a mapping; returns its external port (an IPv6
    /// pinhole's is the internal port).
    fn map(
        &mut self,
        client: IpAddr,
        proto: u8,
        internal: u16,
        suggested: u16,
        nonce: Option<[u8; 12]>,
        expires: Instant,
    ) -> u16 {
        if let Some(m) = self
            .mappings
            .iter_mut()
            .find(|m| m.client == client && m.proto == proto && m.internal_port == internal)
        {
            m.expires = expires;
            m.nonce = m.nonce.or(nonce);
            return m.external_port;
        }
        let free = |p: u16, maps: &[Mapping]| {
            p != 0
                && !maps
                    .iter()
                    .any(|m| m.proto == proto && m.external_port == p)
        };
        let external = match self.mode {
            Mode::AssignPort(p) => p,
            _ if client.is_ipv6() => internal,
            _ if free(suggested, &self.mappings) => suggested,
            _ if free(internal, &self.mappings) => internal,
            _ => (FIRST_FREE_PORT..=u16::MAX)
                .find(|p| free(*p, &self.mappings))
                .unwrap_or(FIRST_FREE_PORT),
        };
        self.mappings.push(Mapping {
            client,
            proto,
            internal_port: internal,
            external_port: external,
            nonce,
            expires,
        });
        external
    }
}

/// A PCP response header: version 2, R=1, `op`, the result, the lifetime,
/// the epoch and 12 reserved bytes.
fn pcp_header(op: u8, result: u8, lifetime: u32, epoch: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(PCP_HEADER + MAP_DATA);
    b.extend_from_slice(&[2, 0x80 | (op & 0x7f), 0, result]);
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&epoch.to_be_bytes());
    b.extend_from_slice(&[0; 12]);
    b
}

/// What [`FakeGateway::log`] records of a request (at least 2 bytes long).
fn seen(req: &[u8], src: SocketAddr) -> SeenReq {
    let mut s = SeenReq {
        src,
        version: req[0],
        op: req[1] & 0x7f,
        proto: None,
        internal_port: 0,
        suggested_port: 0,
        lifetime: 0,
        nonce: None,
        client_ip: None,
    };
    match req[0] {
        0 if req.len() >= 12 && (s.op == 1 || s.op == 2) => {
            s.proto = Some(if s.op == 1 { 17 } else { 6 });
            s.internal_port = be16(&req[4..6]);
            s.suggested_port = be16(&req[6..8]);
            s.lifetime = be32(&req[8..12]);
        }
        2 if req.len() >= PCP_HEADER => {
            s.lifetime = be32(&req[4..8]);
            s.client_ip = Some(field_ip(&req[8..24]));
            if s.op == 1 && req.len() >= PCP_HEADER + MAP_DATA {
                let d = &req[PCP_HEADER..];
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&d[..12]);
                s.nonce = Some(nonce);
                s.proto = Some(d[12]);
                s.internal_port = be16(&d[16..18]);
                s.suggested_port = be16(&d[18..20]);
            }
        }
        _ => {}
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portmap::{
        decode_reply, natpmp_request, pcp_request, unspecified_external, MapReq, NatPmpResp,
        PcpResp, Proto, Reply, NATPMP_OP_EXTERNAL_ADDR, PCP_OP_ANNOUNCE, PCP_OP_MAP,
    };

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    const PORT: u16 = 7423;

    fn src(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 50_000)
    }

    fn map_req(client: IpAddr, nonce: u8, proto: Proto, suggested: u16, lifetime: u32) -> Vec<u8> {
        let m = MapReq {
            nonce: [nonce; 12],
            proto,
            internal_port: PORT,
            suggested_port: suggested,
            suggested_ip: unspecified_external(client),
        };
        pcp_request(PCP_OP_MAP, lifetime, client, Some(&m))
    }

    fn pcp(reply: Option<Vec<u8>>, op: u8) -> PcpResp {
        match decode_reply(&reply.expect("an answer"), Some(op), None) {
            Ok(Reply::Pcp(p)) => p,
            other => panic!("not a PCP reply: {other:?}"),
        }
    }

    fn natpmp(reply: Option<Vec<u8>>, op: u8) -> NatPmpResp {
        match decode_reply(&reply.expect("an answer"), None, Some(op)) {
            Ok(Reply::NatPmp(n)) => n,
            other => panic!("not a NAT-PMP reply: {other:?}"),
        }
    }

    #[test]
    fn pcp_mode_answers_both_protocols_maps_and_logs_every_request() {
        let t0 = Instant::now();
        let now = t0 + Duration::from_secs(30);
        let mut gw = FakeGateway::new(Mode::Pcp, t0);
        let a = pcp(
            gw.reply(
                &pcp_request(PCP_OP_ANNOUNCE, 0, CLIENT, None),
                src(CLIENT),
                now,
            ),
            0,
        );
        assert_eq!((a.result, a.epoch, a.map), (0, 30, None));
        let ext = natpmp(gw.reply(&natpmp_request(0, 0, 0, 0), src(CLIENT), now), 0);
        assert_eq!(
            ext,
            NatPmpResp::ExternalAddr {
                result: 0,
                epoch: 30,
                external: FAKE_EXTERNAL_V4
            }
        );
        let m = pcp(
            gw.reply(
                &map_req(CLIENT, 1, Proto::Tcp, PORT, 7200),
                src(CLIENT),
                now,
            ),
            1,
        );
        let data = m.map.unwrap();
        assert_eq!((m.result, m.lifetime), (0, 7200));
        assert_eq!(
            (data.nonce, data.proto, data.internal_port),
            ([1; 12], 6, PORT)
        );
        assert_eq!(data.external_port, PORT);
        assert_eq!(data.external_addr(), IpAddr::V4(FAKE_EXTERNAL_V4));
        let u = natpmp(
            gw.reply(&natpmp_request(1, PORT, PORT, 9000), src(CLIENT), now),
            1,
        );
        assert_eq!(
            u,
            NatPmpResp::Map {
                proto: Proto::Udp,
                result: 0,
                epoch: 30,
                internal_port: PORT,
                external_port: PORT,
                lifetime: 7200,
            }
        );
        assert_eq!(gw.mappings.len(), 2);
        assert_eq!(gw.log.len(), 4);
        let seen = gw.log[2];
        assert_eq!(
            (
                seen.version,
                seen.op,
                seen.proto,
                seen.internal_port,
                seen.lifetime
            ),
            (2, 1, Some(6), PORT, 7200)
        );
        assert_eq!((seen.nonce, seen.client_ip), (Some([1; 12]), Some(CLIENT)));
        assert_eq!(
            (gw.log[3].version, gw.log[3].proto, gw.log[3].lifetime),
            (0, Some(17), 9000)
        );
        // A taken external port moves the next client's mapping elsewhere.
        let other = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 21));
        let m = pcp(
            gw.reply(&map_req(other, 2, Proto::Tcp, PORT, 7200), src(other), now),
            1,
        );
        assert_eq!(m.map.unwrap().external_port, FIRST_FREE_PORT);
        // Responses and requests of another version are no requests.
        assert_eq!(gw.reply(&[0, 0x80], src(CLIENT), now), None);
        let v1 = gw.reply(&[1, 1, 0, 0], src(CLIENT), now).unwrap();
        assert_eq!((v1[0], v1[1], v1[3]), (2, 0x81, PCP_UNSUPP_VERSION));
    }

    #[test]
    fn natpmp_only_and_silent_gateways() {
        let t0 = Instant::now();
        let mut gw = FakeGateway::new(Mode::NatPmpOnly, t0);
        for (req, op) in [
            (
                pcp_request(PCP_OP_ANNOUNCE, 0, CLIENT, None),
                PCP_OP_ANNOUNCE,
            ),
            (map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), PCP_OP_MAP),
        ] {
            let answer = gw.reply(&req, src(CLIENT), t0).unwrap();
            assert_eq!(answer[..4], [0, 0x80 | op, 0, NATPMP_UNSUPP_VERSION]);
            assert_eq!(answer.len(), 8);
            assert_eq!(decode_reply(&answer, Some(op), None), Ok(Reply::NatPmpOnly));
        }
        assert!(gw.mappings.is_empty());
        let n = natpmp(
            gw.reply(&natpmp_request(2, PORT, 0, 7200), src(CLIENT), t0),
            2,
        );
        assert!(matches!(
            n,
            NatPmpResp::Map {
                result: 0,
                external_port: PORT,
                ..
            }
        ));
        let mut gw = FakeGateway::new(Mode::Silent, t0);
        assert_eq!(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), src(CLIENT), t0),
            None
        );
        assert_eq!(gw.reply(&natpmp_request(0, 0, 0, 0), src(CLIENT), t0), None);
        assert_eq!(gw.log.len(), 2, "a silent gateway still sees the requests");
        assert!(gw.mappings.is_empty());
    }

    #[test]
    fn refusing_gateways_answer_with_their_codes() {
        let t0 = Instant::now();
        let mut gw = FakeGateway::new(Mode::NotAuthorized, t0);
        let a = pcp(
            gw.reply(
                &pcp_request(PCP_OP_ANNOUNCE, 0, CLIENT, None),
                src(CLIENT),
                t0,
            ),
            0,
        );
        assert_eq!(a.result, PCP_SUCCESS, "the probe still finds the server");
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!(m.result, PCP_NOT_AUTHORIZED);
        assert_eq!(
            m.map.unwrap().nonce,
            [1; 12],
            "an error carries the request's data"
        );
        let n = natpmp(
            gw.reply(&natpmp_request(2, PORT, PORT, 7200), src(CLIENT), t0),
            2,
        );
        assert_eq!(n.result(), u16::from(NATPMP_NOT_AUTHORIZED));
        let mut gw = FakeGateway::new(Mode::NoResources { retry_s: 120 }, t0);
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!((m.result, m.lifetime), (PCP_NO_RESOURCES, 120));
        let n = natpmp(
            gw.reply(&natpmp_request(2, PORT, PORT, 7200), src(CLIENT), t0),
            2,
        );
        assert_eq!(n.result(), u16::from(NATPMP_OUT_OF_RESOURCES));
        let mut gw = FakeGateway::new(Mode::CannotProvideExternal, t0);
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!(m.result, PCP_CANNOT_PROVIDE_EXTERNAL);
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, 0, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!(
            (m.result, m.map.unwrap().external_port),
            (PCP_SUCCESS, PORT)
        );
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, 0, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!(m.result, PCP_SUCCESS, "a renewal is no new external port");
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!(m.result, PCP_SUCCESS);
    }

    #[test]
    fn external_ip_assigned_port_and_ipv6_pinholes() {
        let t0 = Instant::now();
        let cgn = Ipv4Addr::new(100, 64, 0, 9);
        let mut gw = FakeGateway::new(Mode::ExternalIp(IpAddr::V4(cgn)), t0);
        let ext = natpmp(gw.reply(&natpmp_request(0, 0, 0, 0), src(CLIENT), t0), 0);
        assert!(matches!(ext, NatPmpResp::ExternalAddr { external, .. } if external == cgn));
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Udp, PORT, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!(m.map.unwrap().external_addr(), IpAddr::V4(cgn));
        // A harness's reported address (loopback) in every answer; the CGN
        // mode still wins over it.
        gw.reported_v4 = Some(Ipv4Addr::LOCALHOST);
        assert_eq!(gw.external_v4(), cgn);
        let mut gw = FakeGateway::new(Mode::AssignPort(40_123), t0);
        gw.reported_v4 = Some(Ipv4Addr::LOCALHOST);
        let ext = natpmp(gw.reply(&natpmp_request(0, 0, 0, 0), src(CLIENT), t0), 0);
        assert!(
            matches!(ext, NatPmpResp::ExternalAddr { external, .. } if external == Ipv4Addr::LOCALHOST)
        );
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), src(CLIENT), t0),
            1,
        );
        let data = m.map.unwrap();
        assert_eq!(
            (data.external_addr(), data.external_port),
            (IpAddr::V4(Ipv4Addr::LOCALHOST), 40_123)
        );
        let n = natpmp(
            gw.reply(&natpmp_request(1, PORT, PORT, 7200), src(CLIENT), t0),
            1,
        );
        assert!(matches!(
            n,
            NatPmpResp::Map {
                external_port: 40_123,
                ..
            }
        ));
        let v6: IpAddr = "2001:db8::20".parse().unwrap();
        let mut gw = FakeGateway::new(Mode::Ipv6Firewall, t0);
        let m = pcp(
            gw.reply(&map_req(v6, 3, Proto::Udp, PORT, 7200), src(v6), t0),
            1,
        );
        let data = m.map.unwrap();
        assert_eq!((data.external_addr(), data.external_port), (v6, PORT));
        assert_eq!(
            gw.reply(&natpmp_request(0, 0, 0, 0), src(v6), t0),
            None,
            "NAT-PMP is IPv4 only"
        );
        let mut gw = FakeGateway::new(Mode::Pcp, t0);
        assert_eq!(
            gw.reply(&map_req(v6, 3, Proto::Udp, PORT, 7200), src(v6), t0),
            None,
            "no PCP server on IPv6 unless it is a firewall"
        );
    }

    #[test]
    fn epoch_reset_loses_every_mapping_and_restarts_the_epoch() {
        let t0 = Instant::now();
        let mut gw = FakeGateway::new(Mode::EpochResetAt(Duration::from_secs(100)), t0);
        let mut watch = crate::portmap::EpochWatch::new();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let m = pcp(
            gw.reply(
                &map_req(CLIENT, 1, Proto::Tcp, PORT, 7200),
                src(CLIENT),
                at(10),
            ),
            1,
        );
        assert_eq!(m.epoch, 10);
        assert!(!watch.lost(m.epoch, at(10)));
        let a = pcp(
            gw.reply(
                &pcp_request(PCP_OP_ANNOUNCE, 0, CLIENT, None),
                src(CLIENT),
                at(60),
            ),
            0,
        );
        assert!(!watch.lost(a.epoch, at(60)));
        assert_eq!(gw.mappings.len(), 1);
        let a = pcp(
            gw.reply(
                &pcp_request(PCP_OP_ANNOUNCE, 0, CLIENT, None),
                src(CLIENT),
                at(150),
            ),
            0,
        );
        assert_eq!(a.epoch, 0);
        assert!(watch.lost(a.epoch, at(150)), "the client sees the restart");
        assert!(gw.mappings.is_empty());
        assert_eq!(gw.mode, Mode::Pcp);
        let ext = natpmp(
            gw.reply(
                &natpmp_request(NATPMP_OP_EXTERNAL_ADDR, 0, 0, 0),
                src(CLIENT),
                at(170),
            ),
            0,
        );
        assert_eq!(ext.epoch(), 20);
    }

    #[test]
    fn nonce_and_client_address_are_enforced() {
        let t0 = Instant::now();
        let mut gw = FakeGateway::new(Mode::Pcp, t0);
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!(m.result, PCP_SUCCESS);
        for lifetime in [7200, 0] {
            let other = pcp(
                gw.reply(
                    &map_req(CLIENT, 2, Proto::Tcp, PORT, lifetime),
                    src(CLIENT),
                    t0,
                ),
                1,
            );
            assert_eq!(
                other.result, PCP_NOT_AUTHORIZED,
                "another nonce, lifetime {lifetime}"
            );
        }
        assert_eq!(gw.mappings.len(), 1);
        // The client address field must be the datagram's source.
        let elsewhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)), 50_000);
        let wrong = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), elsewhere, t0),
            1,
        );
        assert_eq!(wrong.result, PCP_ADDRESS_MISMATCH);
        let mapped_source = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(192, 168, 1, 20).to_ipv6_mapped()),
            1,
        );
        let ok = pcp(
            gw.reply(
                &map_req(CLIENT, 1, Proto::Tcp, PORT, 7200),
                mapped_source,
                t0,
            ),
            1,
        );
        assert_eq!(
            ok.result, PCP_SUCCESS,
            "an IPv4-mapped source is the IPv4 address"
        );
        // The owner's nonce deletes it.
        let del = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, 0, 0), src(CLIENT), t0),
            1,
        );
        assert_eq!((del.result, del.lifetime), (PCP_SUCCESS, 0));
        assert!(gw.mappings.is_empty());
        // Malformed and unknown requests.
        let mut short = map_req(CLIENT, 1, Proto::Tcp, PORT, 7200);
        short.truncate(40);
        assert_eq!(
            pcp(gw.reply(&short, src(CLIENT), t0), 1).result,
            PCP_MALFORMED_REQUEST
        );
        let mut sctp = map_req(CLIENT, 1, Proto::Tcp, PORT, 7200);
        sctp[36] = 132;
        assert_eq!(
            pcp(gw.reply(&sctp, src(CLIENT), t0), 1).result,
            PCP_UNSUPP_PROTOCOL
        );
        let mut option = map_req(CLIENT, 1, Proto::Tcp, PORT, 7200);
        option.extend_from_slice(&[1, 0, 0, 0]);
        // (The echoed option is one Raven's client would refuse to read.)
        let r = gw.reply(&option, src(CLIENT), t0).unwrap();
        assert_eq!((r.len(), r[3]), (64, PCP_UNSUPP_OPTION));
        let mut peer = pcp_request(PCP_OP_ANNOUNCE, 0, CLIENT, None);
        peer[1] = 2;
        let r = gw.reply(&peer, src(CLIENT), t0).unwrap();
        assert_eq!((r[1], r[3]), (0x82, PCP_UNSUPP_OPCODE));
        let r = gw.reply(&[0, 9], src(CLIENT), t0).unwrap();
        assert_eq!((r[1], r[3], r.len()), (0x89, NATPMP_UNSUPP_OPCODE, 8));
    }

    #[test]
    fn dropped_renewals_and_expiry() {
        let t0 = Instant::now();
        let mut gw = FakeGateway::new(Mode::DropRenewals, t0);
        gw.max_lifetime_s = 100;
        let m = pcp(
            gw.reply(&map_req(CLIENT, 1, Proto::Tcp, PORT, 7200), src(CLIENT), t0),
            1,
        );
        assert_eq!(
            m.lifetime, 100,
            "the gateway grants at most its own maximum"
        );
        let renew = map_req(CLIENT, 1, Proto::Tcp, PORT, 7200);
        assert_eq!(
            gw.reply(&renew, src(CLIENT), t0 + Duration::from_secs(50)),
            None
        );
        assert_eq!(
            gw.reply(&natpmp_request(2, PORT, PORT, 7200), src(CLIENT), t0),
            None
        );
        // Past its lifetime the mapping is gone, and the next request is a
        // new mapping again.
        let later = t0 + Duration::from_secs(101);
        let m = pcp(gw.reply(&renew, src(CLIENT), later), 1);
        assert_eq!(m.result, PCP_SUCCESS);
        assert_eq!(gw.mappings.len(), 1);
        assert_eq!(gw.mappings[0].expires, later + Duration::from_secs(100));
        let del = natpmp(gw.reply(&natpmp_request(2, 0, 0, 0), src(CLIENT), later), 2);
        assert!(matches!(
            del,
            NatPmpResp::Map {
                result: 0,
                lifetime: 0,
                ..
            }
        ));
        assert!(
            gw.mappings.is_empty(),
            "internal port 0, lifetime 0 deletes them all"
        );
    }
}
