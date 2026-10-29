//! `raven doctor --router` (Phase 4 P4.4, the evidence step for D11): asks
//! this computer's own router which port mapping it speaks, so real routers
//! can be recorded (rows R2b and R2c) before port mapping goes further. An
//! explicit, user-run, read-only probe, allowed in release builds (owner
//! decision O4-10): it maps nothing, stores nothing and runs only when the
//! user asks for it.
//!
//! - **Routers:** [`gateway::default_gateways`].
//! - **NAT-PMP and PCP:** a PCP ANNOUNCE and a NAT-PMP external address
//!   request ([`raven_core::portmap`]) to the IPv4 router's port 5351, from
//!   one blocking UDP socket connected to it, on the profile's probe schedule
//!   (`protocol/RAVEN_PORT_MAPPING_V1.md` §6: 0, 250, 750 and 1750 ms; it
//!   ends at 3750 ms, sooner once both have answered).
//! - **UPnP:** one SSDP search (an M-SEARCH per target, sent twice as UPnP
//!   asks) for an Internet Gateway Device, v1 or v2, and the IPv6 firewall
//!   control service, with a 3 s window that runs alongside. Only the
//!   router's own answers count, and a repeated answer counts once.
//! - Nothing is sent without an IPv4 router, or when that router has a
//!   global address (a public network: there is nothing to map).
//!
//! It prints words (`found`, `yes`, `v2`, `behind_another_nat`), never an
//! address. When macOS refuses the packets (the terminal app's Local Network
//! permission), one more line says so.
//!
//! **Lab:** a debug build with the lab unlock and `RAVEN_LAB_PORTMAP_GATEWAY`
//! sends all of it, the SSDP search included, to that gateway's IPv4 entry
//! (a fake on loopback), so a harness never reaches a real router.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use raven_core::gateway::{self, Gateways};
use raven_core::p2p_route;
use raven_core::portmap::{
    decode_reply, natpmp_request, pcp_request, NatPmpResp, Reply, MAX_PCP, NATPMP_OP_EXTERNAL_ADDR,
    NATPMP_SUCCESS, PCP_OP_ANNOUNCE, PCP_PORT,
};
use raven_core::portmap_gate::{lab_portmap_gateway, LabGateway};

/// When the NAT-PMP/PCP probe sends, in ms after it starts (the profile's
/// short probe schedule).
const PROBE_SENDS_MS: [u64; 4] = [0, 250, 750, 1750];
/// When the NAT-PMP/PCP probe gives up, in ms after it starts.
const PROBE_END_MS: u64 = 3750;
/// SSDP's IPv4 multicast group and port.
const SSDP_GROUP: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900));
/// When the SSDP search is sent, in ms after it starts: twice, since UDP may
/// lose one (UPnP Device Architecture 1.1 §1.3.2).
const SSDP_SENDS_MS: [u64; 2] = [0, 500];
/// How long the SSDP search waits for answers, in ms.
const SSDP_WINDOW_MS: u64 = 3000;
/// `MX`: the most seconds a device waits before it answers.
const SSDP_MX_S: u8 = 2;
/// The multicast TTL UPnP asks for.
const SSDP_TTL: u32 = 2;
/// Receive errors either probe outlives (an ICMP error comes back at most
/// once per send) before it stops.
const MAX_RECV_ERRORS: u32 = 16;

/// The search target of an Internet Gateway Device v1.
const ST_IGD_1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
/// The search target of an Internet Gateway Device v2.
const ST_IGD_2: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
/// The search target of UPnP's IPv6 firewall control (IGDv2 pinholes).
const ST_V6_FIREWALL: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

/// The doctor's SSDP search targets and what an answer to each means. A
/// device of a newer version also answers a search for the older one.
const SSDP_SEARCHES: [(&str, SsdpFound); 3] = [
    (ST_IGD_1, SsdpFound::Igd(Igd::V1)),
    (ST_IGD_2, SsdpFound::Igd(Igd::V2)),
    (ST_V6_FIREWALL, SsdpFound::V6Firewall),
];

/// The line `raven doctor --router` adds when macOS refused the packets.
const LOCAL_NETWORK_LINE: &str = "router_local_network=refused (your terminal app may need Local \
     Network permission: System Settings > Privacy & Security > Local Network; then run raven \
     doctor --router again)";

/// What the doctor learnt about this computer's routers: words only, no
/// address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RouterReport {
    gateway_v4: GatewayV4,
    /// An IPv6 default router was found.
    gateway_v6: bool,
    /// The IPv4 router answered PCP.
    pcp: bool,
    /// The IPv4 router answered NAT-PMP, or told PCP it speaks only NAT-PMP.
    natpmp: bool,
    upnp_igd: Igd,
    /// The router offers UPnP's IPv6 firewall control (IGDv2 pinholes).
    ipv6_firewall_control: bool,
    external_v4: ExternalV4,
    /// macOS refused to let the packets reach the router.
    local_network_refused: bool,
}

/// The IPv4 default router, in the doctor's words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum GatewayV4 {
    #[default]
    NotFound,
    Found,
    /// A global address: a public network, with nothing to map.
    PublicHost,
}

impl GatewayV4 {
    fn of(gw: Option<Ipv4Addr>) -> Self {
        match gw {
            None => Self::NotFound,
            Some(gw) if gateway::public_host(gw) => Self::PublicHost,
            Some(_) => Self::Found,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::NotFound => "none",
            Self::Found => "found",
            Self::PublicHost => "public_host",
        }
    }
}

/// The newest Internet Gateway Device version that answered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Igd {
    #[default]
    No,
    V1,
    V2,
}

impl Igd {
    fn word(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

/// The router's own external IPv4 address (NAT-PMP's answer), in words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ExternalV4 {
    #[default]
    Unknown,
    Global,
    /// Not a global address (carrier-grade NAT, a private range): another
    /// NAT sits between the router and the internet.
    BehindAnotherNat,
}

impl ExternalV4 {
    /// The word for NAT-PMP's external address answer: unknown unless it
    /// succeeded with an address.
    fn of(result: u16, external: Ipv4Addr) -> Self {
        if result != NATPMP_SUCCESS || external.is_unspecified() {
            Self::Unknown
        } else if p2p_route::is_global_ipv4(external) {
            Self::Global
        } else {
            Self::BehindAnotherNat
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Global => "global",
            Self::BehindAnotherNat => "behind_another_nat",
        }
    }
}

/// `raven doctor --router`'s lines, one `key=word` each (never an address),
/// then [`LOCAL_NETWORK_LINE`] when macOS refused the packets.
pub(super) fn doctor_router_lines(r: &RouterReport) -> Vec<String> {
    let yes = |b: bool| if b { "yes" } else { "no" };
    let mut lines = vec![
        format!("router_gateway_v4={}", r.gateway_v4.word()),
        format!(
            "router_gateway_v6={}",
            if r.gateway_v6 { "found" } else { "none" }
        ),
        format!("router_pcp={}", yes(r.pcp)),
        format!("router_natpmp={}", yes(r.natpmp)),
        format!("router_upnp_igd={}", r.upnp_igd.word()),
        format!(
            "router_ipv6_firewall_control={}",
            yes(r.ipv6_firewall_control)
        ),
        format!("router_external_v4={}", r.external_v4.word()),
    ];
    if r.local_network_refused {
        lines.push(LOCAL_NETWORK_LINE.to_string());
    }
    lines
}

/// Ask this computer's routers (the module doc says what is sent). Blocks
/// for up to [`PROBE_END_MS`]: the SSDP search runs alongside on a second
/// thread.
pub(super) fn probe() -> RouterReport {
    let gws = gateway::default_gateways();
    let mut report = RouterReport {
        gateway_v4: GatewayV4::of(gws.v4),
        gateway_v6: gws.v6.is_some(),
        ..RouterReport::default()
    };
    let Some(t) = targets(&gws, lab_portmap_gateway()) else {
        return report;
    };
    let (pcp, ssdp) = std::thread::scope(|s| {
        let ssdp = s.spawn(|| ssdp_probe(t.ssdp, t.router));
        (pcp_probe(t.server), ssdp.join().unwrap_or_default())
    });
    report.pcp = pcp.pcp;
    report.natpmp = pcp.natpmp;
    report.external_v4 = pcp.external_v4;
    report.upnp_igd = ssdp.igd;
    report.ipv6_firewall_control = ssdp.v6_firewall;
    report.local_network_refused = pcp.local_network_refused || ssdp.local_network_refused;
    report
}

/// Where the probes go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Targets {
    /// The IPv4 router's NAT-PMP/PCP server.
    server: SocketAddr,
    /// Where the SSDP search goes.
    ssdp: SocketAddr,
    /// The address whose SSDP answers count: the router's.
    router: IpAddr,
}

/// The probes' targets: the IPv4 router to map ([`Gateways::v4_to_map`]) on
/// port 5351, with the SSDP search to the multicast group; with a lab
/// gateway, its IPv4 entry for both (the same public-host rule applies).
/// `None` without an IPv4 router to ask (none, a global one, a lab gateway
/// with only an IPv6 entry).
fn targets(gws: &Gateways, lab: Option<LabGateway>) -> Option<Targets> {
    if let Some(lab) = lab {
        let gw = SocketAddr::V4(lab.v4.filter(|a| !gateway::public_host(*a.ip()))?);
        return Some(Targets {
            server: gw,
            ssdp: gw,
            router: gw.ip(),
        });
    }
    let gw = IpAddr::V4(gws.v4_to_map()?);
    Some(Targets {
        server: SocketAddr::new(gw, PCP_PORT),
        ssdp: SSDP_GROUP,
        router: gw,
    })
}

/// A probe's clock: when it sends (ms after its start) and when it ends.
struct Clock {
    start: Instant,
    sends: &'static [u64],
    next: usize,
    end: Instant,
}

impl Clock {
    fn start(sends: &'static [u64], end_ms: u64) -> Self {
        let start = Instant::now();
        Clock {
            start,
            sends,
            next: 0,
            end: start + Duration::from_millis(end_ms),
        }
    }

    fn at(&self, i: usize) -> Option<Instant> {
        self.sends
            .get(i)
            .map(|ms| self.start + Duration::from_millis(*ms))
    }

    /// Whether a send is due at `now` (sends that fell due together, after a
    /// stall, make one).
    fn send_due(&mut self, now: Instant) -> bool {
        let mut due = false;
        while self.at(self.next).is_some_and(|at| at <= now) {
            self.next += 1;
            due = true;
        }
        due
    }

    /// How long to wait for answers at `now`: until the next send or the end,
    /// at least 1 ms (a socket timeout cannot be zero); `None` once the probe
    /// has ended.
    fn wait(&self, now: Instant) -> Option<Duration> {
        if now >= self.end {
            return None;
        }
        let wake = self.at(self.next).map_or(self.end, |at| at.min(self.end));
        Some(
            wake.saturating_duration_since(now)
                .max(Duration::from_millis(1)),
        )
    }
}

/// A socket read timeout: `WouldBlock` on Unix, `TimedOut` on Windows.
fn timed_out(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// macOS 15 and later refuse a terminal app's packets to the local network
/// while its Local Network permission is off: the send fails with EPERM or
/// EHOSTUNREACH.
fn local_network_refused(e: &io::Error) -> bool {
    cfg!(target_os = "macos") && refused_kind(e.kind())
}

/// The error kinds of EPERM (and EACCES) and EHOSTUNREACH.
fn refused_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::PermissionDenied | io::ErrorKind::HostUnreachable
    )
}

/// What the NAT-PMP/PCP probe learnt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PcpProbe {
    pcp: bool,
    natpmp: bool,
    external_v4: ExternalV4,
    local_network_refused: bool,
}

/// A UDP socket on an ephemeral port, connected to `server`: the system
/// picks the source address (which a PCP request names), and only
/// `server`'s datagrams are read.
fn connect(server: SocketAddr) -> io::Result<UdpSocket> {
    let any: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(any)?;
    sock.connect(server)?;
    Ok(sock)
}

/// The NAT-PMP/PCP probe of `server`: a PCP ANNOUNCE (lifetime 0: nothing
/// is mapped) and a NAT-PMP external address request at each time of
/// [`PROBE_SENDS_MS`], each until it is answered. It ends at
/// [`PROBE_END_MS`], or once both are answered. A PCP answer means PCP; a
/// NAT-PMP-only router's "unsupported version" to the ANNOUNCE, or a NAT-PMP
/// answer, means NAT-PMP, and that answer's external address gives
/// [`ExternalV4`]. A datagram [`decode_reply`] refuses is ignored.
fn pcp_probe(server: SocketAddr) -> PcpProbe {
    let mut clock = Clock::start(&PROBE_SENDS_MS, PROBE_END_MS);
    let mut out = PcpProbe::default();
    let sock = match connect(server) {
        Ok(sock) => sock,
        Err(e) => {
            out.local_network_refused = local_network_refused(&e);
            return out;
        }
    };
    let Ok(client) = sock.local_addr().map(|a| a.ip()) else {
        return out;
    };
    let announce = pcp_request(PCP_OP_ANNOUNCE, 0, client, None);
    let address = natpmp_request(NATPMP_OP_EXTERNAL_ADDR, 0, 0, 0);
    let (mut pcp_done, mut natpmp_done) = (false, false);
    let mut buf = [0u8; MAX_PCP + 4];
    let mut errors = 0;
    loop {
        let now = Instant::now();
        if clock.send_due(now) {
            for (done, request) in [(pcp_done, &announce), (natpmp_done, &address)] {
                if done {
                    continue;
                }
                if let Err(e) = sock.send(request) {
                    out.local_network_refused |= local_network_refused(&e);
                    return out;
                }
            }
        }
        let Some(wait) = clock.wait(now) else {
            break;
        };
        if sock.set_read_timeout(Some(wait)).is_err() {
            break;
        }
        match sock.recv(&mut buf) {
            // Both requests stay outstanding: a late repeat of an answer is
            // still read as what it is.
            Ok(n) => match decode_reply(
                &buf[..n],
                Some(PCP_OP_ANNOUNCE),
                Some(NATPMP_OP_EXTERNAL_ADDR),
            ) {
                Ok(Reply::Pcp(_)) => {
                    out.pcp = true;
                    pcp_done = true;
                }
                Ok(Reply::NatPmpOnly) => {
                    out.natpmp = true;
                    pcp_done = true;
                }
                Ok(Reply::NatPmp(NatPmpResp::ExternalAddr {
                    result, external, ..
                })) if !natpmp_done => {
                    out.natpmp = true;
                    out.external_v4 = ExternalV4::of(result, external);
                    natpmp_done = true;
                }
                _ => {}
            },
            Err(e) if timed_out(&e) => {}
            Err(_) => {
                errors += 1;
                if errors > MAX_RECV_ERRORS {
                    break;
                }
            }
        }
        if pcp_done && natpmp_done {
            break;
        }
    }
    out
}

/// What an answer to one of [`SSDP_SEARCHES`] says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SsdpFound {
    Igd(Igd),
    V6Firewall,
}

/// What the SSDP search learnt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SsdpProbe {
    igd: Igd,
    v6_firewall: bool,
    local_network_refused: bool,
}

/// An SSDP M-SEARCH for `st` sent to `host` (the multicast group, or a lab
/// gateway). No USER-AGENT: it names no software.
fn m_search(host: SocketAddr, st: &str) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {host}\r\nMAN: \"ssdp:discover\"\r\nMX: {SSDP_MX_S}\r\n\
         ST: {st}\r\n\r\n"
    )
    .into_bytes()
}

/// What an SSDP datagram answers, when it answers one of [`SSDP_SEARCHES`]:
/// an `HTTP/1.x 200` response whose `ST` header (the name in any case) is
/// one of the targets (ASCII case ignored). A notification, a search,
/// another status or another target is `None`.
fn ssdp_answer(datagram: &[u8]) -> Option<SsdpFound> {
    let text = String::from_utf8_lossy(datagram);
    let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));
    let mut status = lines.next()?.split_ascii_whitespace();
    let version = status.next()?;
    if !(version.eq_ignore_ascii_case("HTTP/1.1") || version.eq_ignore_ascii_case("HTTP/1.0"))
        || status.next()? != "200"
    {
        return None;
    }
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("ST") {
            let value = value.trim();
            return SSDP_SEARCHES
                .iter()
                .find(|(st, _)| st.eq_ignore_ascii_case(value))
                .map(|(_, found)| *found);
        }
    }
    None
}

/// The SSDP search: an M-SEARCH for each of [`SSDP_SEARCHES`] to `target` at
/// each time of [`SSDP_SENDS_MS`], then answers for [`SSDP_WINDOW_MS`]
/// (sooner once an IGDv2 and the IPv6 firewall service have answered:
/// nothing more can be learnt). Only answers from `router` count.
fn ssdp_probe(target: SocketAddr, router: IpAddr) -> SsdpProbe {
    let mut clock = Clock::start(&SSDP_SENDS_MS, SSDP_WINDOW_MS);
    let mut out = SsdpProbe::default();
    let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
        return out;
    };
    // The local link only, as UPnP asks (a lab gateway's search is unicast).
    let _ = sock.set_multicast_ttl_v4(SSDP_TTL);
    let searches: Vec<Vec<u8>> = SSDP_SEARCHES
        .iter()
        .map(|(st, _)| m_search(target, st))
        .collect();
    let mut buf = [0u8; 4096];
    let mut errors = 0;
    loop {
        let now = Instant::now();
        if clock.send_due(now) {
            for search in &searches {
                if let Err(e) = sock.send_to(search, target) {
                    out.local_network_refused |= local_network_refused(&e);
                    return out;
                }
            }
        }
        let Some(wait) = clock.wait(now) else {
            break;
        };
        if sock.set_read_timeout(Some(wait)).is_err() {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from.ip() == router => match ssdp_answer(&buf[..n]) {
                Some(SsdpFound::Igd(v)) => out.igd = out.igd.max(v),
                Some(SsdpFound::V6Firewall) => out.v6_firewall = true,
                None => {}
            },
            Ok(_) => {}
            Err(e) if timed_out(&e) => {}
            Err(_) => {
                errors += 1;
                if errors > MAX_RECV_ERRORS {
                    break;
                }
            }
        }
        if out.igd == Igd::V2 && out.v6_firewall {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::portmap::PCP_VERSION;
    use raven_core::portmap_fake::{FakeGateway, Mode};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    /// A [`FakeGateway`] behind a UDP socket on 127.0.0.1:0, in a thread. It
    /// also answers an SSDP search for a target in `serves` the way a router
    /// does: one 200 response per search, which names the target.
    struct FakeRouter {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        searches: Arc<AtomicUsize>,
        thread: Option<JoinHandle<FakeGateway>>,
    }

    /// What [`FakeRouter::halt`] sends the fake to end its loop.
    const FAKE_STOP: &[u8] = b"fake router: stop";

    impl FakeRouter {
        fn start(mode: Mode, serves: &'static [&'static str]) -> Self {
            let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            // No short read timeout: on Windows under full-suite load a UDP read
            // that timed out lost the datagram arriving at that moment (a PCP
            // request or an M-SEARCH went missing from the count). The fake
            // blocks until a datagram comes and ends on FAKE_STOP; the long
            // timeout only stops a lost FAKE_STOP from hanging the test.
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let addr = sock.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let searches = Arc::new(AtomicUsize::new(0));
            let (stop_t, searches_t) = (stop.clone(), searches.clone());
            let thread = std::thread::spawn(move || {
                let mut gw = FakeGateway::new(mode, Instant::now());
                let mut buf = [0u8; 2048];
                let handle = |gw: &mut FakeGateway, req: &[u8], src: SocketAddr| {
                    let reply = if req.starts_with(b"M-SEARCH") {
                        searches_t.fetch_add(1, Ordering::SeqCst);
                        ssdp_reply(req, serves)
                    } else {
                        gw.reply(req, src, Instant::now())
                    };
                    if let Some(reply) = reply {
                        let _ = sock.send_to(&reply, src);
                    }
                };
                loop {
                    match sock.recv_from(&mut buf) {
                        Ok((n, _)) if &buf[..n] == FAKE_STOP => break,
                        Ok((n, src)) => handle(&mut gw, &buf[..n], src),
                        Err(_) if stop_t.load(Ordering::SeqCst) => break,
                        Err(_) => {}
                    }
                }
                // The probe's sends all returned before FAKE_STOP was sent, so they
                // are queued ahead of it; whatever is still queued is read without
                // waiting (a non-blocking read never times out).
                if sock.set_nonblocking(true).is_ok() {
                    while let Ok((n, src)) = sock.recv_from(&mut buf) {
                        if &buf[..n] != FAKE_STOP {
                            handle(&mut gw, &buf[..n], src);
                        }
                    }
                }
                gw
            });
            FakeRouter {
                addr,
                stop,
                searches,
                thread: Some(thread),
            }
        }

        /// End the fake's loop and wait for it: the gateway, once.
        fn halt(&mut self) -> Option<FakeGateway> {
            let thread = self.thread.take()?;
            self.stop.store(true, Ordering::SeqCst);
            if let Ok(s) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) {
                let _ = s.send_to(FAKE_STOP, self.addr);
            }
            thread.join().ok()
        }

        /// Stop it; the gateway (what it saw and holds) and how many SSDP
        /// searches came.
        fn stop(mut self) -> (FakeGateway, usize) {
            let gw = self.halt().unwrap();
            (gw, self.searches.load(Ordering::SeqCst))
        }
    }

    impl Drop for FakeRouter {
        fn drop(&mut self) {
            let _ = self.halt();
        }
    }

    /// A router's answer to `search` when it serves the target.
    fn ssdp_reply(search: &[u8], serves: &[&str]) -> Option<Vec<u8>> {
        let text = std::str::from_utf8(search).ok()?;
        let st = text.lines().find_map(|l| l.strip_prefix("ST: "))?.trim();
        serves.contains(&st).then(|| {
            format!(
                "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\nLOCATION: \
                 http://192.0.2.1:5000/rootDesc.xml\r\nSERVER: test/1 UPnP/1.1 fake/1\r\n\
                 ST: {st}\r\nUSN: uuid:00000000-0000-0000-0000-000000000001::{st}\r\n\r\n"
            )
            .into_bytes()
        })
    }

    /// The doctor only asked: ANNOUNCEs with lifetime 0 and NAT-PMP external
    /// address requests, and the gateway holds no mapping.
    fn assert_read_only(gw: &FakeGateway) {
        assert!(!gw.log.is_empty());
        for seen in &gw.log {
            assert!(
                (seen.version == PCP_VERSION || seen.version == 0)
                    && seen.op == 0
                    && seen.lifetime == 0
                    && seen.proto.is_none(),
                "{seen:?}"
            );
        }
        assert!(gw.mappings.is_empty(), "{:?}", gw.mappings);
    }

    /// The probe against an in-process fake gateway: a PCP router (which
    /// also speaks NAT-PMP, as miniupnpd does) gives `router_pcp=yes`; a
    /// NAT-PMP-only one `router_natpmp=yes router_pcp=no`; one behind
    /// carrier-grade NAT `behind_another_nat`; a silent one both `no`,
    /// within the 3.75 s budget, having sent each request 4 times. It maps
    /// nothing.
    #[test]
    fn doctor_router_against_an_in_process_fake_gateway() {
        let probe = |mode| {
            let fake = FakeRouter::start(mode, &[]);
            let t0 = Instant::now();
            let got = pcp_probe(fake.addr);
            let took = t0.elapsed();
            (got, took, fake.stop().0)
        };
        let budget = Duration::from_millis(PROBE_END_MS);

        let (got, took, gw) = probe(Mode::Pcp);
        let pcp_router = PcpProbe {
            pcp: true,
            natpmp: true,
            external_v4: ExternalV4::Global,
            local_network_refused: false,
        };
        assert_eq!(got, pcp_router);
        // Both answered: it did not wait out the budget.
        assert!(took < budget, "{took:?}");
        assert_read_only(&gw);

        let (got, took, gw) = probe(Mode::NatPmpOnly);
        let natpmp_only = PcpProbe {
            pcp: false,
            ..pcp_router
        };
        assert_eq!(got, natpmp_only);
        assert!(took < budget, "{took:?}");
        assert_read_only(&gw);

        let cgn = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9));
        let (got, _, gw) = probe(Mode::ExternalIp(cgn));
        assert_eq!(
            got,
            PcpProbe {
                external_v4: ExternalV4::BehindAnotherNat,
                ..pcp_router
            }
        );
        assert_read_only(&gw);

        let (got, took, gw) = probe(Mode::Silent);
        assert_eq!(got, PcpProbe::default());
        assert!(took >= budget, "{took:?}");
        assert!(took < budget + Duration::from_millis(1500), "{took:?}");
        assert_read_only(&gw);
        let sent = |version| gw.log.iter().filter(|s| s.version == version).count();
        assert_eq!(
            (sent(PCP_VERSION), sent(0)),
            (PROBE_SENDS_MS.len(), PROBE_SENDS_MS.len())
        );
    }

    /// `raven doctor --router`'s lines: one `key=word` each, the words from
    /// their own short lists, never an address; the Local Network line only
    /// when macOS refused the packets.
    #[test]
    fn doctor_router_lines_are_key_value_without_addresses() {
        assert_eq!(
            doctor_router_lines(&RouterReport::default()),
            [
                "router_gateway_v4=none",
                "router_gateway_v6=none",
                "router_pcp=no",
                "router_natpmp=no",
                "router_upnp_igd=no",
                "router_ipv6_firewall_control=no",
                "router_external_v4=unknown",
            ]
        );
        let home = RouterReport {
            gateway_v4: GatewayV4::Found,
            gateway_v6: true,
            pcp: true,
            natpmp: true,
            upnp_igd: Igd::V2,
            ipv6_firewall_control: true,
            external_v4: ExternalV4::BehindAnotherNat,
            local_network_refused: true,
        };
        assert_eq!(
            doctor_router_lines(&home),
            [
                "router_gateway_v4=found",
                "router_gateway_v6=found",
                "router_pcp=yes",
                "router_natpmp=yes",
                "router_upnp_igd=v2",
                "router_ipv6_firewall_control=yes",
                "router_external_v4=behind_another_nat",
                LOCAL_NETWORK_LINE,
            ]
        );
        assert!(LOCAL_NETWORK_LINE.contains("Local Network permission"));

        let words = [
            "found",
            "none",
            "public_host",
            "yes",
            "no",
            "v1",
            "v2",
            "global",
            "behind_another_nat",
            "unknown",
        ];
        for gateway_v4 in [GatewayV4::NotFound, GatewayV4::Found, GatewayV4::PublicHost] {
            for upnp_igd in [Igd::No, Igd::V1, Igd::V2] {
                for external_v4 in [
                    ExternalV4::Unknown,
                    ExternalV4::Global,
                    ExternalV4::BehindAnotherNat,
                ] {
                    for flags in [false, true] {
                        let r = RouterReport {
                            gateway_v4,
                            gateway_v6: flags,
                            pcp: !flags,
                            natpmp: flags,
                            upnp_igd,
                            ipv6_firewall_control: !flags,
                            external_v4,
                            local_network_refused: flags,
                        };
                        let lines = doctor_router_lines(&r);
                        assert_eq!(lines.len(), 7 + usize::from(flags));
                        for line in &lines[..7] {
                            let (key, word) = line.split_once('=').unwrap();
                            assert!(
                                key.starts_with("router_")
                                    && key.bytes().all(|b| b.is_ascii_lowercase()
                                        || b.is_ascii_digit()
                                        || b == b'_'),
                                "{line}"
                            );
                            assert!(words.contains(&word), "{line}");
                        }
                        for line in &lines {
                            assert!(!line.contains('.') && !line.contains("::"), "{line}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn gateway_and_external_address_words() {
        assert_eq!(GatewayV4::of(None), GatewayV4::NotFound);
        assert_eq!(
            GatewayV4::of(Some(Ipv4Addr::new(192, 168, 1, 1))),
            GatewayV4::Found
        );
        // A carrier-grade NAT router is still a router to ask.
        assert_eq!(
            GatewayV4::of(Some(Ipv4Addr::new(100, 64, 0, 1))),
            GatewayV4::Found
        );
        assert_eq!(
            GatewayV4::of(Some(Ipv4Addr::new(11, 0, 2, 1))),
            GatewayV4::PublicHost
        );

        let global = Ipv4Addr::new(11, 0, 2, 9);
        assert_eq!(ExternalV4::of(NATPMP_SUCCESS, global), ExternalV4::Global);
        for behind in [
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::new(192, 168, 0, 2),
            Ipv4Addr::new(10, 1, 2, 3),
        ] {
            assert_eq!(
                ExternalV4::of(NATPMP_SUCCESS, behind),
                ExternalV4::BehindAnotherNat
            );
        }
        // No address yet, or an error (3: the router has no address).
        assert_eq!(
            ExternalV4::of(NATPMP_SUCCESS, Ipv4Addr::UNSPECIFIED),
            ExternalV4::Unknown
        );
        assert_eq!(ExternalV4::of(3, global), ExternalV4::Unknown);
    }

    /// Only an IPv4 router with something to map is asked, on port 5351, with
    /// the SSDP search to the multicast group; a lab gateway's IPv4 entry
    /// takes all of it, under the same public-host rule.
    #[test]
    fn targets_are_the_ipv4_router_or_the_lab_gateway() {
        let router = Ipv4Addr::new(192, 168, 1, 1);
        let v6 = Some(("fe80::1".parse().unwrap(), 4));
        let home = Gateways {
            v4: Some(router),
            v6,
        };
        assert_eq!(
            targets(&home, None),
            Some(Targets {
                server: SocketAddr::new(router.into(), PCP_PORT),
                ssdp: SSDP_GROUP,
                router: router.into(),
            })
        );
        let public = Gateways {
            v4: Some(Ipv4Addr::new(11, 0, 2, 1)),
            v6,
        };
        assert_eq!(targets(&public, None), None);
        assert_eq!(targets(&Gateways { v4: None, v6 }, None), None);

        let fake: SocketAddrV4 = "127.0.0.1:40123".parse().unwrap();
        let lab = LabGateway {
            v4: Some(fake),
            v6: None,
        };
        assert_eq!(
            targets(&lab.into(), Some(lab)),
            Some(Targets {
                server: fake.into(),
                ssdp: fake.into(),
                router: (*fake.ip()).into(),
            })
        );
        let lab_v6 = LabGateway {
            v4: None,
            v6: Some("[::1]:40123".parse().unwrap()),
        };
        assert_eq!(targets(&lab_v6.into(), Some(lab_v6)), None);
        let lab_public = LabGateway {
            v4: Some("11.0.2.1:40123".parse().unwrap()),
            v6: None,
        };
        assert_eq!(targets(&lab_public.into(), Some(lab_public)), None);
    }

    #[test]
    fn m_search_is_the_upnp_search_and_names_no_software() {
        assert_eq!(
            String::from_utf8(m_search(SSDP_GROUP, ST_IGD_2)).unwrap(),
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\
             MX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n"
        );
    }

    #[test]
    fn ssdp_answers_are_200_responses_naming_a_searched_target() {
        let ok = |st: &str| format!("HTTP/1.1 200 OK\r\nEXT:\r\nST: {st}\r\nUSN: x::{st}\r\n\r\n");
        assert_eq!(
            ssdp_answer(ok(ST_IGD_1).as_bytes()),
            Some(SsdpFound::Igd(Igd::V1))
        );
        assert_eq!(
            ssdp_answer(ok(ST_IGD_2).as_bytes()),
            Some(SsdpFound::Igd(Igd::V2))
        );
        assert_eq!(
            ssdp_answer(ok(ST_V6_FIREWALL).as_bytes()),
            Some(SsdpFound::V6Firewall)
        );
        // Any case, HTTP/1.0, bare line feeds, spaces around the value.
        assert_eq!(
            ssdp_answer(
                b"http/1.0 200 OK\nst:  URN:schemas-upnp-org:device:InternetGatewayDevice:2 \n\n"
            ),
            Some(SsdpFound::Igd(Igd::V2))
        );
        for not_an_answer in [
            ok("urn:schemas-upnp-org:device:MediaServer:1"),
            ok("upnp:rootdevice"),
            format!("HTTP/1.1 404 Not Found\r\nST: {ST_IGD_2}\r\n\r\n"),
            format!("NOTIFY * HTTP/1.1\r\nNT: {ST_IGD_2}\r\nNTS: ssdp:alive\r\n\r\n"),
            String::from_utf8(m_search(SSDP_GROUP, ST_IGD_2)).unwrap(),
            "HTTP/1.1 200 OK\r\nUSN: x\r\n\r\n".to_string(),
            format!("HTTP/1.1 200 OK\r\n\r\nST: {ST_IGD_2}\r\n"),
            format!("HTTP/2 200\r\nST: {ST_IGD_2}\r\n\r\n"),
            format!("HTTP/1.1 2000 OK\r\nST: {ST_IGD_2}\r\n\r\n"),
            String::new(),
        ] {
            assert_eq!(
                ssdp_answer(not_an_answer.as_bytes()),
                None,
                "{not_an_answer:?}"
            );
        }
        // Bytes that are not text never panic.
        assert_eq!(ssdp_answer(&[0xff, 0xfe, b'\n', 0xc3, b':', 0x80]), None);
        assert_eq!(ssdp_answer("HTTP/1é 200\r\n".as_bytes()), None);
    }

    /// An IGDv2 router with the IPv6 firewall service answers both, and the
    /// search ends as soon as nothing more can be learnt.
    #[test]
    fn ssdp_search_finds_igd_v2_and_the_ipv6_firewall_and_ends_early() {
        let fake = FakeRouter::start(Mode::Silent, &[ST_IGD_1, ST_IGD_2, ST_V6_FIREWALL]);
        let t0 = Instant::now();
        let got = ssdp_probe(fake.addr, fake.addr.ip());
        assert!(t0.elapsed() < Duration::from_millis(SSDP_WINDOW_MS));
        assert_eq!(
            got,
            SsdpProbe {
                igd: Igd::V2,
                v6_firewall: true,
                local_network_refused: false,
            }
        );
        let (gw, searches) = fake.stop();
        // SSDP only: nothing reached the NAT-PMP/PCP side.
        assert!(gw.log.is_empty(), "{:?}", gw.log);
        assert!(searches >= SSDP_SEARCHES.len(), "{searches}");
    }

    /// An IGDv1 alone might still be followed by a v2 answer: the search
    /// waits out its window, having sent every search twice.
    #[test]
    fn ssdp_search_with_igd_v1_alone_waits_out_the_window() {
        let fake = FakeRouter::start(Mode::Silent, &[ST_IGD_1]);
        let t0 = Instant::now();
        let got = ssdp_probe(fake.addr, fake.addr.ip());
        assert!(t0.elapsed() >= Duration::from_millis(SSDP_WINDOW_MS));
        assert_eq!(
            got,
            SsdpProbe {
                igd: Igd::V1,
                ..SsdpProbe::default()
            }
        );
        let (_, searches) = fake.stop();
        assert_eq!(searches, SSDP_SEARCHES.len() * SSDP_SENDS_MS.len());
    }

    /// Answers from any address but the router's (a printer, a TV, a second
    /// router) do not count.
    #[test]
    fn ssdp_answers_from_another_address_do_not_count() {
        let fake = FakeRouter::start(Mode::Silent, &[ST_IGD_1, ST_IGD_2, ST_V6_FIREWALL]);
        let elsewhere = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(ssdp_probe(fake.addr, elsewhere), SsdpProbe::default());
    }

    #[test]
    fn only_eperm_and_ehostunreach_on_macos_mean_local_network_refused() {
        assert!(refused_kind(io::ErrorKind::PermissionDenied));
        assert!(refused_kind(io::ErrorKind::HostUnreachable));
        for other in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Other,
        ] {
            assert!(!refused_kind(other), "{other:?}");
        }
        assert_eq!(
            local_network_refused(&io::ErrorKind::HostUnreachable.into()),
            cfg!(target_os = "macos")
        );
        // EPERM and EHOSTUNREACH as macOS numbers them.
        #[cfg(target_os = "macos")]
        for errno in [1, 65] {
            assert!(local_network_refused(&io::Error::from_raw_os_error(errno)));
        }
    }

    /// A probe's clock sends at each offset once (sends that fell due
    /// together make one), waits at least 1 ms, and stops at its end.
    #[test]
    fn clock_sends_on_schedule_and_ends() {
        let mut clock = Clock::start(&PROBE_SENDS_MS, PROBE_END_MS);
        let t0 = clock.start;
        let ms = |n: u64| t0 + Duration::from_millis(n);
        assert!(clock.send_due(t0));
        assert!(!clock.send_due(t0));
        assert_eq!(clock.wait(t0), Some(Duration::from_millis(250)));
        assert_eq!(clock.wait(ms(250)), Some(Duration::from_millis(1)));
        // A stall past two sends: one send.
        assert!(clock.send_due(ms(800)));
        assert_eq!(clock.next, 3);
        assert_eq!(clock.wait(ms(800)), Some(Duration::from_millis(950)));
        assert!(clock.send_due(ms(1750)));
        assert_eq!(clock.wait(ms(1750)), Some(Duration::from_millis(2000)));
        assert!(!clock.send_due(ms(3000)));
        assert_eq!(clock.wait(ms(PROBE_END_MS)), None);
    }
}
