//! This computer's default gateways: the routers port mapping asks
//! (NAT-PMP, RFC 6886, and PCP, RFC 6887; the codec is [`crate::portmap`]).
//! Read from the system itself, with no new crate; nothing is sent.
//!
//! - **Linux:** the gateway of the default route with the lowest metric in
//!   `/proc/net/route` and `/proc/net/ipv6_route` ([`parse_proc_route`],
//!   [`parse_proc_ipv6_route`]); none when that route has no gateway (a
//!   tunnel or PPP link).
//! - **macOS:** the default route among the routing table's gateway routes
//!   (`sysctl` `NET_RT_FLAGS`, [`parse_rt_dump`]). macOS also keeps a
//!   default route bound to each interface (VPN tunnels included): those
//!   do not count.
//! - **Windows:** the next hop of `GetBestRoute2` toward the documentation
//!   addresses the egress probe uses (192.0.2.1 and 2001:db8::1, as
//!   [`crate::route_memory::egress_addrs`]; [`windows_route_gateway`]).
//! - Any other system: none.
//!
//! An IPv6 router comes with its scope: for a link-local router (the usual
//! one) the interface it is reached through, else 0. A global IPv4 gateway
//! means this computer is on a public network with nothing to map
//! ([`public_host`], [`Gateways::v4_to_map`]). The address a mapping is
//! asked for (the egress source) comes from
//! [`crate::route_memory::egress_addrs`], not from here.
//!
//! The parsers are pure and tested on every system. No gate: reading the
//! table changes nothing, and what acts on it is gated
//! ([`crate::portmap_gate`]). Callers print words about these routers
//! (`found`, `none`, `public_host`), never their addresses.
//!
//! **Lab:** a debug build with the lab unlock takes both routers from
//! `RAVEN_LAB_PORTMAP_GATEWAY` instead (a fake gateway on loopback; its
//! ports stay with [`crate::portmap_gate::lab_portmap_gateway`]), so a
//! harness never reaches a real router. A release build never reads it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::portmap_gate::LabGateway;

/// This computer's default routers, one per family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gateways {
    /// The IPv4 default router.
    pub v4: Option<Ipv4Addr>,
    /// The IPv6 default router and its scope id: the interface index for a
    /// link-local router, 0 for any other.
    pub v6: Option<(Ipv6Addr, u32)>,
}

impl Gateways {
    /// The IPv4 router a port mapping asks: [`Gateways::v4`], unless it is a
    /// global address ([`public_host`]).
    pub fn v4_to_map(&self) -> Option<Ipv4Addr> {
        self.v4.filter(|gw| !public_host(*gw))
    }
}

/// The routers a harness names, without their ports (which stay with
/// [`crate::portmap_gate::lab_portmap_gateway`]); an IPv6 router keeps the
/// scope written with it.
impl From<LabGateway> for Gateways {
    fn from(lab: LabGateway) -> Self {
        Gateways {
            v4: lab.v4.map(|a| *a.ip()),
            v6: lab.v6.map(|a| (*a.ip(), a.scope_id())),
        }
    }
}

/// This computer's default routers: the harness's
/// ([`crate::portmap_gate::lab_portmap_gateway`]: a debug build with the lab
/// unlock, both families from it), else the system's. Synchronous and cheap
/// (two small files, a few `sysctl` calls or two `GetBestRoute2` calls):
/// port mapping reads it again on every network change.
pub fn default_gateways() -> Gateways {
    if let Some(lab) = crate::portmap_gate::lab_portmap_gateway() {
        return lab.into();
    }
    os_query()
}

/// A global IPv4 default gateway ([`crate::p2p_route::is_global_ipv4`]):
/// this computer sits on a public network with no NAT in front of it, so
/// there is nothing to map. A private or carrier-grade NAT (100.64/10)
/// gateway is a router to ask.
pub fn public_host(gw: Ipv4Addr) -> bool {
    crate::p2p_route::is_global_ipv4(gw)
}

// Route flags. Up and via a gateway are numbered alike by Linux
// (`linux/route.h`, also in `/proc/net/ipv6_route`) and the BSDs
// (`net/route.h`); the others differ.
const RTF_UP: u32 = 0x1;
const RTF_GATEWAY: u32 = 0x2;
/// Linux: an unreachable or prohibited route.
const LINUX_RTF_REJECT: u32 = 0x200;
/// BSD: a route to one host.
const BSD_RTF_HOST: u32 = 0x4;
/// BSD: an unreachable route.
const BSD_RTF_REJECT: u32 = 0x8;
/// BSD: a route that discards.
const BSD_RTF_BLACKHOLE: u32 = 0x1000;
/// macOS: a route bound to one interface (scoped routing).
const BSD_RTF_IFSCOPE: u32 = 0x100_0000;
/// The routing message version macOS writes (`rtm_version`).
const BSD_RTM_VERSION: u8 = 5;
/// The sockaddrs that follow a routing message's header, in this order,
/// each present when its bit is set in `rtm_addrs`: destination, gateway,
/// netmask (and five more [`parse_rt_dump`] never needs).
const BSD_RTA_COUNT: usize = 3;
/// macOS's address family numbers (`sa_family`).
const MACOS_AF_INET: u8 = 2;
const MACOS_AF_INET6: u8 = 30;

#[cfg(target_os = "linux")]
const _: () = assert!(
    RTF_UP == libc::RTF_UP as u32
        && RTF_GATEWAY == libc::RTF_GATEWAY as u32
        && LINUX_RTF_REJECT == libc::RTF_REJECT as u32
);

#[cfg(target_os = "macos")]
const _: () = assert!(
    RTF_UP == libc::RTF_UP as u32
        && RTF_GATEWAY == libc::RTF_GATEWAY as u32
        && BSD_RTF_HOST == libc::RTF_HOST as u32
        && BSD_RTF_REJECT == libc::RTF_REJECT as u32
        && BSD_RTF_BLACKHOLE == libc::RTF_BLACKHOLE as u32
        && BSD_RTF_IFSCOPE == libc::RTF_IFSCOPE as u32
        && BSD_RTM_VERSION as libc::c_int == libc::RTM_VERSION
        && libc::RTA_DST == 1
        && libc::RTA_GATEWAY == 2
        && libc::RTA_NETMASK == 4
        && MACOS_AF_INET as libc::c_int == libc::AF_INET
        && MACOS_AF_INET6 as libc::c_int == libc::AF_INET6
);

/// The IPv4 default router in the text of Linux's `/proc/net/route`: of the
/// lines up with destination and mask `00000000` (reject routes aside), the
/// one with the lowest `Metric` (the first on a tie) is the default route
/// the kernel uses, and its gateway is the router; a default route without
/// a gateway (a tunnel or PPP link) has none. The kernel prints each address
/// as the 32-bit word its network-order bytes make on the host
/// (little-endian on every host Raven ships for: `0101A8C0` is
/// 192.168.1.1). Lines that do not parse are skipped.
pub fn parse_proc_route(text: &str) -> Option<Ipv4Addr> {
    // The best default route: its metric, flags and gateway word.
    let mut best: Option<(u32, u32, u32)> = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let (Some(dst), Some(gw), Some(flags), Some(metric), Some(mask)) = (
            hex_u32(fields[1]),
            hex_u32(fields[2]),
            hex_u32(fields[3]),
            decimal_metric(fields[6]),
            hex_u32(fields[7]),
        ) else {
            continue;
        };
        if dst != 0 || mask != 0 || !live_route(flags, LINUX_RTF_REJECT) {
            continue;
        }
        if best.is_none_or(|(m, ..)| metric < m) {
            best = Some((metric, flags, gw));
        }
    }
    let (_, flags, gw) = best?;
    if flags & RTF_GATEWAY == 0 {
        return None;
    }
    v4_router(Ipv4Addr::from(gw.to_ne_bytes()))
}

/// The IPv6 default router in the text of Linux's `/proc/net/ipv6_route`
/// and the interface it is reached through: of the lines up to `::/0` from
/// any source (a default route for one source prefix does not count; reject
/// routes aside), the one with the lowest metric (the first on a tie) is the
/// default route the kernel uses, and its next hop is the router; a default
/// route without a gateway has none. Lines that do not parse are skipped.
pub fn parse_proc_ipv6_route(text: &str) -> Option<(Ipv6Addr, String)> {
    // The best default route: its metric, flags, next hop and interface.
    let mut best: Option<(u32, u32, Ipv6Addr, &str)> = None;
    for line in text.lines() {
        // Destination, its prefix length, source, its prefix length, next
        // hop, metric, reference count, use count, flags, interface.
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 10 {
            continue;
        }
        let (Some(dst), Some(dst_len), Some(src_len), Some(next_hop), Some(metric), Some(flags)) = (
            hex_v6(fields[0]),
            hex_u32(fields[1]),
            hex_u32(fields[3]),
            hex_v6(fields[4]),
            hex_u32(fields[5]),
            hex_u32(fields[8]),
        ) else {
            continue;
        };
        if !dst.is_unspecified()
            || dst_len != 0
            || src_len != 0
            || !live_route(flags, LINUX_RTF_REJECT)
        {
            continue;
        }
        if best.is_none_or(|(m, ..)| metric < m) {
            best = Some((metric, flags, next_hop, fields[9]));
        }
    }
    let (_, flags, next_hop, ifname) = best?;
    (flags & RTF_GATEWAY != 0 && !next_hop.is_unspecified()).then(|| (next_hop, ifname.to_string()))
}

/// The default router in a macOS routing table dump (`sysctl` `{CTL_NET,
/// PF_ROUTE, 0, family, NET_RT_FLAGS, RTF_GATEWAY}`): routing messages of
/// `rtm_msglen` bytes, each a header of `hdr_len` bytes
/// (`size_of::<libc::rt_msghdr>()`, 92) and then its sockaddrs, each padded
/// to 4 bytes. `family` is the sockaddr family asked for (2 IPv4, 30 IPv6).
///
/// The first route that is up, via a gateway of that family, to everything
/// (destination all zero, mask absent or all zero: so not a VPN's
/// 0.0.0.0/1), not a host, reject or blackhole route, and not bound to one
/// interface gives the router. An IPv6 link-local router's scope is the
/// gateway's scope id, else the one a KAME kernel writes into address bytes
/// 2-3 (cleared from the address), else the route's interface. A message
/// that does not fit is skipped; a length that runs past the buffer ends
/// the walk.
pub fn parse_rt_dump(buf: &[u8], hdr_len: usize, family: u8) -> Option<(IpAddr, u32)> {
    // The header fields read here end at byte 16.
    let hdr_len = hdr_len.max(16);
    let mut rest = buf;
    while rest.len() >= 2 {
        let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        if len < hdr_len || len > rest.len() {
            return None;
        }
        let (msg, next) = rest.split_at(len);
        rest = next;
        if let Some(found) = rt_default_router(msg, hdr_len, family) {
            return Some(found);
        }
    }
    None
}

/// [`parse_rt_dump`] on one routing message of at least `hdr_len` (16 or
/// more) bytes.
fn rt_default_router(msg: &[u8], hdr_len: usize, family: u8) -> Option<(IpAddr, u32)> {
    let word = |at: usize| u32::from_ne_bytes([msg[at], msg[at + 1], msg[at + 2], msg[at + 3]]);
    let (version, index, flags, addrs) = (
        msg[2],
        u16::from_ne_bytes([msg[4], msg[5]]),
        word(8),
        word(12),
    );
    if version != BSD_RTM_VERSION
        || flags & RTF_GATEWAY == 0
        || !live_route(
            flags,
            BSD_RTF_HOST | BSD_RTF_REJECT | BSD_RTF_BLACKHOLE | BSD_RTF_IFSCOPE,
        )
    {
        return None;
    }
    // Where the address sits in a sockaddr of this family, and its length.
    let (addr_at, addr_len) = match family {
        MACOS_AF_INET => (4, 4),
        MACOS_AF_INET6 => (8, 16),
        _ => return None,
    };
    let mut sockaddrs: [Option<&[u8]>; BSD_RTA_COUNT] = [None; BSD_RTA_COUNT];
    let mut at = hdr_len;
    for (bit, slot) in sockaddrs.iter_mut().enumerate() {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let len = usize::from(*msg.get(at)?);
        *slot = Some(msg.get(at..at + len)?);
        at += rt_roundup(len);
    }
    // A sockaddr's address bytes; a short one (a mask) is zero past its end.
    let addr = |sa: &[u8]| -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().take(addr_len).enumerate() {
            *b = sa.get(addr_at + i).copied().unwrap_or(0);
        }
        out
    };
    let [dst, gateway, mask] = sockaddrs;
    let (dst, gateway) = (dst?, gateway?);
    if dst.get(1) != Some(&family)
        || addr(dst) != [0; 16]
        || mask.is_some_and(|m| addr(m) != [0; 16])
        || gateway.get(1) != Some(&family)
    {
        return None;
    }
    let bytes = addr(gateway);
    if family == MACOS_AF_INET {
        let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        return v4_router(ip).map(|ip| (IpAddr::V4(ip), 0));
    }
    let scope_id = gateway
        .get(24..28)
        .map_or(0, |s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]));
    let (ip, scope_id) = kame_unembed(bytes, scope_id);
    v6_router(ip, scope_id, u32::from(index)).map(|(ip, scope)| (IpAddr::V6(ip), scope))
}

/// The bytes a sockaddr of `len` bytes takes in a macOS routing message:
/// rounded up to 4, and 4 for an empty one (xnu's `ROUNDUP32`).
fn rt_roundup(len: usize) -> usize {
    if len == 0 {
        4
    } else {
        (len + 3) & !3
    }
}

/// A KAME kernel (macOS, the BSDs) writes a link-local address's interface
/// index into its bytes 2-3: the plain address and its scope (the scope id
/// given, else that index).
fn kame_unembed(mut bytes: [u8; 16], scope_id: u32) -> (Ipv6Addr, u32) {
    let link_local = bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80;
    let embedded = u32::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if link_local && embedded != 0 {
        bytes[2] = 0;
        bytes[3] = 0;
        let scope_id = if scope_id == 0 { embedded } else { scope_id };
        return (Ipv6Addr::from(bytes), scope_id);
    }
    (Ipv6Addr::from(bytes), scope_id)
}

/// One answer of Windows' `GetBestRoute2` (`MIB_IPFORWARD_ROW2`), as
/// [`windows_route_gateway`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsBestRoute {
    /// `NextHop`: unspecified when the destination is on the link (no
    /// router).
    pub next_hop: IpAddr,
    /// `NextHop`'s IPv6 scope id (0 for IPv4).
    pub next_hop_scope_id: u32,
    /// `InterfaceIndex`: the interface the route leaves by.
    pub interface_index: u32,
}

/// The router of a Windows best route (pure: it compiles and is tested on
/// every system): its next hop, if it has one; an IPv6 link-local next hop
/// is reached through its scope id, else the route's interface.
pub fn windows_route_gateway(route: &WindowsBestRoute) -> Option<(IpAddr, u32)> {
    match route.next_hop {
        IpAddr::V4(ip) => v4_router(ip).map(|ip| (IpAddr::V4(ip), 0)),
        IpAddr::V6(ip) => v6_router(ip, route.next_hop_scope_id, route.interface_index)
            .map(|(ip, scope)| (IpAddr::V6(ip), scope)),
    }
}

/// Up, and none of the `bad` flags.
fn live_route(flags: u32, bad: u32) -> bool {
    flags & RTF_UP != 0 && flags & bad == 0
}

/// A router address of a route: not unspecified, loopback, multicast or
/// broadcast.
fn v4_router(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    (!(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()))
        .then_some(ip)
}

/// A router address of a route (not unspecified, loopback, multicast or
/// IPv4-mapped) and its scope: for a link-local router the scope id the
/// system gave, else `if_index` (the interface its route leaves by), and
/// with neither it cannot be reached; 0 for any other router.
fn v6_router(ip: Ipv6Addr, scope_id: u32, if_index: u32) -> Option<(Ipv6Addr, u32)> {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.to_ipv4_mapped().is_some()
    {
        return None;
    }
    if ip.segments()[0] & 0xffc0 != 0xfe80 {
        return Some((ip, 0));
    }
    let scope = if scope_id != 0 { scope_id } else { if_index };
    (scope != 0).then_some((ip, scope))
}

/// 1 to 8 hex digits.
fn hex_u32(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 8 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// 32 hex digits: an IPv6 address in network order.
fn hex_v6(s: &str) -> Option<Ipv6Addr> {
    let mut bytes = [0u8; 16];
    hex::decode_to_slice(s, &mut bytes).ok()?;
    Some(Ipv6Addr::from(bytes))
}

/// `/proc/net/route`'s `Metric`: the kernel prints the unsigned priority
/// with `%d`, so one above `i32::MAX` reads negative.
fn decimal_metric(s: &str) -> Option<u32> {
    s.parse::<i32>()
        .map(|m| m as u32)
        .ok()
        .or_else(|| s.parse::<u32>().ok())
}

/// Linux: `/proc/net/route` and `/proc/net/ipv6_route`.
#[cfg(target_os = "linux")]
fn os_query() -> Gateways {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    let v4 = read("/proc/net/route").and_then(|t| parse_proc_route(&t));
    let v6 = read("/proc/net/ipv6_route")
        .and_then(|t| parse_proc_ipv6_route(&t))
        .and_then(|(ip, ifname)| v6_router(ip, 0, if_index(&ifname)));
    Gateways { v4, v6 }
}

/// The index of the interface `ifname`; 0 when there is none.
#[cfg(target_os = "linux")]
fn if_index(ifname: &str) -> u32 {
    let Ok(name) = std::ffi::CString::new(ifname) else {
        return 0;
    };
    // SAFETY: `name` is NUL-terminated and outlives the call.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// macOS: the routing table's gateway routes of each family.
#[cfg(target_os = "macos")]
fn os_query() -> Gateways {
    let hdr_len = std::mem::size_of::<libc::rt_msghdr>();
    let find = |family: u8| parse_rt_dump(&rt_dump(family)?, hdr_len, family);
    routers(find(MACOS_AF_INET), find(MACOS_AF_INET6))
}

/// The largest routing table dump [`rt_dump`] reads (a computer, not a
/// backbone router).
#[cfg(target_os = "macos")]
const MAX_RT_DUMP: usize = 8 << 20;

/// The table may grow between the size query and the read: give up after
/// this many tries.
#[cfg(target_os = "macos")]
const RT_DUMP_TRIES: usize = 4;

/// The routing table's gateway routes of `family` (`sysctl` `{CTL_NET,
/// PF_ROUTE, 0, family, NET_RT_FLAGS, RTF_GATEWAY}`); `None` when the
/// system refuses or the table is larger than [`MAX_RT_DUMP`].
#[cfg(target_os = "macos")]
fn rt_dump(family: u8) -> Option<Vec<u8>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::c_int::from(family),
        libc::NET_RT_FLAGS,
        libc::RTF_GATEWAY,
    ];
    let names = mib.len() as libc::c_uint;
    for _ in 0..RT_DUMP_TRIES {
        let mut size: libc::size_t = 0;
        // SAFETY: `mib` holds `names` names; a null buffer asks only for the
        // size, written to `size`; nothing is set.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                names,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || size > MAX_RT_DUMP {
            return None;
        }
        // Room for routes added since the size query.
        let mut buf = vec![0u8; size + size / 8 + 1024];
        let mut len: libc::size_t = buf.len();
        // SAFETY: `buf` is writable for `len` bytes; the kernel writes at most
        // that many and sets `len` to what it wrote; nothing is set.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                names,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(len);
            return Some(buf);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

/// Windows: `GetBestRoute2`.
#[cfg(windows)]
fn os_query() -> Gateways {
    windows::os_query()
}

/// No reader on this system: no gateway.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn os_query() -> Gateways {
    Gateways::default()
}

/// The routers found for each family as [`Gateways`] (an answer of the
/// other family is dropped).
#[cfg(any(target_os = "macos", windows))]
fn routers(v4: Option<(IpAddr, u32)>, v6: Option<(IpAddr, u32)>) -> Gateways {
    Gateways {
        v4: match v4 {
            Some((IpAddr::V4(ip), _)) => Some(ip),
            _ => None,
        },
        v6: match v6 {
            Some((IpAddr::V6(ip), scope)) => Some((ip, scope)),
            _ => None,
        },
    }
}

#[cfg(windows)]
mod windows {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_IN6_0, SOCKADDR_INET,
    };

    use super::{routers, windows_route_gateway, Gateways, WindowsBestRoute};

    /// The egress probe's destinations ([`crate::route_memory::egress_addrs`]):
    /// documentation addresses, so their best route is the default route.
    const TO_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const TO_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    pub(super) fn os_query() -> Gateways {
        // SAFETY: a zeroed SOCKADDR_INET is valid (integers and bytes in
        // every view); the field assignments below write whole views.
        let mut to_v4: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        to_v4.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(TO_V4.octets()),
                },
            },
            sin_zero: [0; 8],
        };
        // SAFETY: as above.
        let mut to_v6: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        to_v6.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: TO_V6.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        };
        let find = |to: &SOCKADDR_INET| best_route(to).and_then(|r| windows_route_gateway(&r));
        routers(find(&to_v4), find(&to_v6))
    }

    /// The best route toward `to`, as [`WindowsBestRoute`]; `None` when the
    /// system has none (no network of that family).
    fn best_route(to: &SOCKADDR_INET) -> Option<WindowsBestRoute> {
        // SAFETY: zeroed out-parameters are valid (integers, bytes and unions
        // of them).
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let mut source: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        // SAFETY: `to` is a valid destination; `row` and `source` are
        // writable; a null interface LUID, interface 0 and a null source let
        // the system choose.
        let rc = unsafe {
            GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                to,
                0,
                &mut row,
                &mut source,
            )
        };
        if rc != NO_ERROR {
            return None;
        }
        // SAFETY: every view of the union starts with the family.
        let (next_hop, next_hop_scope_id) = match unsafe { row.NextHop.si_family } {
            AF_INET => {
                // SAFETY: an AF_INET next hop; every view of IN_ADDR is plain
                // bytes.
                let raw = unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_addr };
                (IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))), 0)
            }
            AF_INET6 => {
                // SAFETY: an AF_INET6 next hop; both unions are plain bytes in
                // every view.
                let (bytes, scope_id) = unsafe {
                    (
                        row.NextHop.Ipv6.sin6_addr.u.Byte,
                        row.NextHop.Ipv6.Anonymous.sin6_scope_id,
                    )
                };
                (IpAddr::V6(Ipv6Addr::from(bytes)), scope_id)
            }
            _ => return None,
        };
        Some(WindowsBestRoute {
            next_hop,
            next_hop_scope_id,
            interface_index: row.InterfaceIndex,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddrV4, SocketAddrV6};

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn proc_net_route_picks_the_lowest_metric_default_and_decodes_little_endian() {
        // The kernel prints an address as the word its network-order bytes
        // make on this host; Raven's hosts are little-endian.
        let word = |ip: &str| format!("{:08X}", u32::from_ne_bytes(v4(ip).octets()));
        if cfg!(target_endian = "little") {
            assert_eq!(word("192.168.1.1"), "0101A8C0");
            assert_eq!(word("128.0.0.0"), "00000080");
        }
        let (wifi, cable, vpn) = (word("10.0.0.1"), word("192.168.1.1"), word("10.8.0.1"));
        let half = word("128.0.0.0");
        let table = format!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
             wlan0\t00000000\t{wifi}\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             eth0\t00000000\t{cable}\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
             tun0\t00000000\t{vpn}\t0003\t0\t0\t50\t{half}\t0\t0\t0\n\
             tun1\t00000000\t{vpn}\t0203\t0\t0\t1\t00000000\t0\t0\t0\n\
             eth1\t00000000\t{vpn}\t0002\t0\t0\t2\t00000000\t0\t0\t0\n"
        );
        // The VPN's 0.0.0.0/1, the reject route and the one not up do not
        // count; the cable's metric 100 beats the Wi-Fi's 600.
        assert_eq!(parse_proc_route(&table), Some(v4("192.168.1.1")));

        // The default route in use has no gateway (a tunnel, a PPP link) or
        // none that can be a router: no router, whatever routes come after.
        let cable_line = format!("eth0\t00000000\t{cable}\t0003\t0\t0\t100\t00000000\t0\t0\t0\n");
        for first in [
            "ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n",
            "eth2\t00000000\t00000000\t0003\t0\t0\t3\t00000000\t0\t0\t0\n",
        ] {
            assert_eq!(
                parse_proc_route(&format!("{first}{cable_line}")),
                None,
                "{first:?}"
            );
        }

        // On a tie the first line wins; a metric printed negative (above
        // i32::MAX) is the largest.
        let tie = format!(
            "eth0\t00000000\t{wifi}\t0003\t0\t0\t-5\t00000000\t0\t0\t0\n\
             eth1\t00000000\t{cable}\t0003\t0\t0\t7\t00000000\t0\t0\t0\n\
             eth2\t00000000\t{vpn}\t0003\t0\t0\t7\t00000000\t0\t0\t0\n"
        );
        assert_eq!(parse_proc_route(&tie), Some(v4("192.168.1.1")));
        assert_eq!(decimal_metric("-1"), Some(u32::MAX));
        assert_eq!(decimal_metric("4294967295"), Some(u32::MAX));

        for none in [
            "",
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\n",
            "eth0\t00000000\tZZ01A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
            "eth0\t00000000\t+101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
            "eth0\t00000000\t0101A8C0\t0003\t0\t0\tlow\t00000000\t0\t0\t0\n",
            "eth0\t00000000\t0101A8C0A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
            "lo\t00000000\t0100007F\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        ] {
            if none.starts_with("lo") && !cfg!(target_endian = "little") {
                continue;
            }
            assert_eq!(parse_proc_route(none), None, "{none:?}");
        }
    }

    #[test]
    fn proc_net_ipv6_route_gives_router_and_iface() {
        let table = "\
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000002 00000000 00450003     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000258 00000001 00000000 00450003    wlan0
00000000000000000000000000000000 00 20010db8000000000000000000000000 40 fe800000000000000000000000000003 00000001 00000001 00000000 00000003     eth1
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000005 00000003 00000001 00000000 00000203     eth3
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 fe800000000000000000000000000006 00000001 00000001 00000000 00000003     eth4
";
        // The source-specific default, the reject routes and the /64 do not
        // count; Wi-Fi's metric 600 (0x258) beats the cable's 1024 (0x400).
        assert_eq!(
            parse_proc_ipv6_route(table),
            Some((v6("fe80::2"), "wlan0".to_string()))
        );
        // The default route in use has no gateway (a tunnel): no router.
        let tunnel = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000032 00000001 00000000 00000001      wg0\n";
        assert_eq!(parse_proc_ipv6_route(&format!("{tunnel}{table}")), None);

        let global = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n";
        assert_eq!(
            parse_proc_ipv6_route(global),
            Some((v6("2001:db8::1"), "eth0".to_string()))
        );
        for none in [
            "",
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003\n",
            "0000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n",
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000000000000000000g 00000400 00000001 00000000 00000003 eth0\n",
        ] {
            assert_eq!(parse_proc_ipv6_route(none), None, "{none:?}");
        }
    }

    // ── macOS routing table dumps, laid out as `sysctl` writes them ──────────

    const RT_HDR: usize = 92;
    const RTM_GET: u8 = 4;
    const UP_GW: u32 = RTF_UP | RTF_GATEWAY;
    /// The flags macOS gives a default route: up, gateway, static,
    /// cloning, global.
    const DEFAULT: u32 = UP_GW | 0x800 | 0x1_0000 | 0x4000_0000;

    /// One routing message: the 92-byte header and the sockaddrs (each
    /// with its `rtm_addrs` bit), each padded to 4 bytes after the length
    /// its first byte says.
    fn rt_msg(index: u16, flags: u32, sockaddrs: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut addrs = 0u32;
        for (bit, sa) in sockaddrs {
            addrs |= bit;
            let start = body.len();
            body.extend_from_slice(sa);
            body.resize(start + rt_roundup(usize::from(sa[0])), 0);
        }
        let mut msg = vec![0u8; RT_HDR];
        let len = u16::try_from(RT_HDR + body.len()).unwrap();
        msg[0..2].copy_from_slice(&len.to_ne_bytes());
        msg[2] = BSD_RTM_VERSION;
        msg[3] = RTM_GET;
        msg[4..6].copy_from_slice(&index.to_ne_bytes());
        msg[8..12].copy_from_slice(&flags.to_ne_bytes());
        msg[12..16].copy_from_slice(&addrs.to_ne_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    /// A `sockaddr_in`; macOS writes a scoped route's interface into
    /// `sin_zero[0]` of its gateway.
    fn sin(ip: &str, zero0: u8) -> Vec<u8> {
        let mut sa = vec![16, MACOS_AF_INET, 0, 0];
        sa.extend_from_slice(&v4(ip).octets());
        sa.extend_from_slice(&[zero0, 0, 0, 0, 0, 0, 0, 0]);
        sa
    }

    /// A `sockaddr_in6`; a nonzero `embedded` is written into its address
    /// bytes 2-3 (KAME).
    fn sin6(ip: &str, embedded: u16, scope_id: u32) -> Vec<u8> {
        let mut bytes = v6(ip).octets();
        if embedded != 0 {
            bytes[2..4].copy_from_slice(&embedded.to_be_bytes());
        }
        let mut sa = vec![28, MACOS_AF_INET6, 0, 0, 0, 0, 0, 0];
        sa.extend_from_slice(&bytes);
        sa.extend_from_slice(&scope_id.to_ne_bytes());
        sa
    }

    /// The mask of a default route: an empty sockaddr.
    fn mask0() -> Vec<u8> {
        vec![0]
    }

    const DST: u32 = 0x1;
    const GW: u32 = 0x2;
    const MASK: u32 = 0x4;
    const IFA: u32 = 0x20;

    /// A dump shaped like a laptop's: scoped defaults (one per interface,
    /// VPN tunnels included) before and after the real one, a VPN's
    /// 0.0.0.0/1 and cloned host routes.
    fn v4_dump() -> Vec<u8> {
        let mut dump = Vec::new();
        // The scoped default of a second interface.
        dump.extend(rt_msg(
            11,
            DEFAULT | BSD_RTF_IFSCOPE,
            &[
                (DST, sin("0.0.0.0", 0)),
                (GW, sin("10.0.0.1", 11)),
                (MASK, mask0()),
                (IFA, sin("10.0.0.20", 0)),
            ],
        ));
        // A VPN's 0.0.0.0/1: its mask is 128.0.0.0, cut to 5 bytes.
        dump.extend(rt_msg(
            12,
            UP_GW | 0x800,
            &[
                (DST, sin("0.0.0.0", 0)),
                (GW, sin("10.8.0.1", 0)),
                (MASK, vec![5, 0, 0, 0, 0x80]),
            ],
        ));
        // A cloned host route through the router.
        dump.extend(rt_msg(
            4,
            UP_GW | BSD_RTF_HOST | 0x2_0000,
            &[
                (DST, sin("192.0.2.80", 0)),
                (GW, sin("192.168.1.1", 4)),
                (IFA, sin("192.168.1.20", 0)),
            ],
        ));
        // A blackhole default.
        dump.extend(rt_msg(
            1,
            DEFAULT | BSD_RTF_BLACKHOLE,
            &[
                (DST, sin("0.0.0.0", 0)),
                (GW, sin("127.0.0.2", 0)),
                (MASK, mask0()),
            ],
        ));
        // The default route.
        dump.extend(rt_msg(
            4,
            DEFAULT,
            &[
                (DST, sin("0.0.0.0", 0)),
                (GW, sin("192.168.1.1", 4)),
                (MASK, mask0()),
                (IFA, sin("192.168.1.20", 0)),
            ],
        ));
        // The scoped default of the same interface.
        dump.extend(rt_msg(
            4,
            DEFAULT | BSD_RTF_IFSCOPE,
            &[
                (DST, sin("0.0.0.0", 0)),
                (GW, sin("192.168.1.254", 4)),
                (MASK, mask0()),
            ],
        ));
        dump
    }

    /// Scoped defaults on two VPN tunnels (gateway fe80::%utunN, its scope
    /// both embedded and in the scope id), then the default route through
    /// fe80::1 on interface 4 (scope embedded only).
    fn v6_dump() -> Vec<u8> {
        let mut dump = Vec::new();
        for utun in [28u16, 29] {
            dump.extend(rt_msg(
                utun,
                UP_GW | 0x1_0000 | 0x4000_0000 | BSD_RTF_IFSCOPE,
                &[
                    (DST, sin6("::", 0, 0)),
                    (GW, sin6("fe80::", utun, u32::from(utun))),
                    (MASK, mask0()),
                    (IFA, sin6("fe80::1234", utun, u32::from(utun))),
                ],
            ));
        }
        dump.extend(rt_msg(
            4,
            UP_GW | 0x1_0000 | 0x4000_0000,
            &[
                (DST, sin6("::", 0, 0)),
                (GW, sin6("fe80::1", 4, 0)),
                (MASK, mask0()),
                (IFA, sin6("fe80::20", 4, 0)),
            ],
        ));
        dump
    }

    #[test]
    fn bsd_route_dump_parses_v4_and_v6_and_moves_the_kame_scope() {
        #[cfg(target_os = "macos")]
        assert_eq!(std::mem::size_of::<libc::rt_msghdr>(), RT_HDR);

        let v4_dump = v4_dump();
        let v6_dump = v6_dump();
        assert_eq!(
            parse_rt_dump(&v4_dump, RT_HDR, MACOS_AF_INET),
            Some((IpAddr::V4(v4("192.168.1.1")), 0))
        );
        // The embedded scope moves out of the address.
        assert_eq!(
            parse_rt_dump(&v6_dump, RT_HDR, MACOS_AF_INET6),
            Some((IpAddr::V6(v6("fe80::1")), 4))
        );
        // A family the dump does not hold, or one macOS does not number so.
        assert_eq!(parse_rt_dump(&v4_dump, RT_HDR, MACOS_AF_INET6), None);
        assert_eq!(parse_rt_dump(&v6_dump, RT_HDR, MACOS_AF_INET), None);
        assert_eq!(parse_rt_dump(&v4_dump, RT_HDR, 28), None);

        let one = |gw: Vec<u8>, index: u16| {
            let dump = rt_msg(
                index,
                DEFAULT,
                &[(DST, sin6("::", 0, 0)), (GW, gw), (MASK, mask0())],
            );
            parse_rt_dump(&dump, RT_HDR, MACOS_AF_INET6)
        };
        let ll = |scope| Some((IpAddr::V6(v6("fe80::1")), scope));
        // The scope id wins over the embedded index; then the embedded one;
        // then the route's interface; with none the router is unusable.
        assert_eq!(one(sin6("fe80::1", 4, 9), 6), ll(9));
        assert_eq!(one(sin6("fe80::1", 0, 9), 6), ll(9));
        assert_eq!(one(sin6("fe80::1", 4, 0), 6), ll(4));
        assert_eq!(one(sin6("fe80::1", 0, 0), 6), ll(6));
        assert_eq!(one(sin6("fe80::1", 0, 0), 0), None);
        // A global router has no scope; an unspecified one is none.
        assert_eq!(
            one(sin6("2001:db8::1", 0, 0), 6),
            Some((IpAddr::V6(v6("2001:db8::1")), 0))
        );
        assert_eq!(one(sin6("::", 0, 0), 6), None);
        // A route without a destination or without a gateway gives none.
        let no_dst = rt_msg(4, DEFAULT, &[(GW, sin("192.168.1.1", 0)), (MASK, mask0())]);
        assert_eq!(parse_rt_dump(&no_dst, RT_HDR, MACOS_AF_INET), None);
        let no_gw = rt_msg(4, DEFAULT, &[(DST, sin("0.0.0.0", 0)), (MASK, mask0())]);
        assert_eq!(parse_rt_dump(&no_gw, RT_HDR, MACOS_AF_INET), None);
        // A default route with no mask at all still counts.
        let no_mask = rt_msg(
            4,
            DEFAULT,
            &[(DST, sin("0.0.0.0", 0)), (GW, sin("10.1.1.1", 0))],
        );
        assert_eq!(
            parse_rt_dump(&no_mask, RT_HDR, MACOS_AF_INET),
            Some((IpAddr::V4(v4("10.1.1.1")), 0))
        );
        // Another routing message version is skipped.
        let mut old = no_mask.clone();
        old[2] = 4;
        assert_eq!(parse_rt_dump(&old, RT_HDR, MACOS_AF_INET), None);
    }

    /// No cut, length or byte in a dump panics or loops; a broken length
    /// ends the walk.
    #[test]
    fn bsd_route_dump_survives_broken_input() {
        let mut dump = v4_dump();
        dump.extend(v6_dump());
        for cut in 0..dump.len() {
            let _ = parse_rt_dump(&dump[..cut], RT_HDR, MACOS_AF_INET);
            let _ = parse_rt_dump(&dump[..cut], RT_HDR, MACOS_AF_INET6);
        }
        // A first message of length 0, or longer than the dump: nothing
        // after it is read.
        let mut zero_len = v4_dump();
        zero_len[0..2].copy_from_slice(&0u16.to_ne_bytes());
        assert_eq!(parse_rt_dump(&zero_len, RT_HDR, MACOS_AF_INET), None);
        let mut too_long = v4_dump();
        too_long[0..2].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert_eq!(parse_rt_dump(&too_long, RT_HDR, MACOS_AF_INET), None);
        // A sockaddr running past its message skips that message only.
        let mut bad_sa = rt_msg(
            4,
            DEFAULT,
            &[(DST, sin("0.0.0.0", 0)), (GW, sin("10.1.1.1", 0))],
        );
        bad_sa[RT_HDR + 16] = 200;
        bad_sa.extend(rt_msg(
            5,
            DEFAULT,
            &[(DST, sin("0.0.0.0", 0)), (GW, sin("10.2.2.2", 0))],
        ));
        assert_eq!(
            parse_rt_dump(&bad_sa, RT_HDR, MACOS_AF_INET),
            Some((IpAddr::V4(v4("10.2.2.2")), 0))
        );
        // A header length below the fields read is raised to them.
        for hdr_len in [0, 2, 15] {
            let _ = parse_rt_dump(&dump, hdr_len, MACOS_AF_INET);
        }
        let mut noise = 0x9e37_79b9u32;
        for _ in 0..2000 {
            let bytes: Vec<u8> = (0..64)
                .map(|_| {
                    noise ^= noise << 13;
                    noise ^= noise >> 17;
                    noise ^= noise << 5;
                    noise as u8
                })
                .collect();
            let _ = parse_rt_dump(&bytes, RT_HDR, MACOS_AF_INET6);
            let _ = parse_rt_dump(&bytes, 16, MACOS_AF_INET);
        }
    }

    #[test]
    fn windows_best_route_rows_map_next_hop_and_scope() {
        let route = |next_hop: &str, next_hop_scope_id: u32, interface_index: u32| {
            windows_route_gateway(&WindowsBestRoute {
                next_hop: next_hop.parse().unwrap(),
                next_hop_scope_id,
                interface_index,
            })
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(route("192.168.1.1", 0, 7), Some((ip("192.168.1.1"), 0)));
        // On the link: no router.
        assert_eq!(route("0.0.0.0", 0, 7), None);
        assert_eq!(route("::", 0, 7), None);
        assert_eq!(route("255.255.255.255", 0, 7), None);
        assert_eq!(route("127.0.0.1", 0, 1), None);
        // A link-local next hop: its scope id, else the route's interface.
        assert_eq!(route("fe80::1", 12, 7), Some((ip("fe80::1"), 12)));
        assert_eq!(route("fe80::1", 0, 7), Some((ip("fe80::1"), 7)));
        assert_eq!(route("fe80::1", 0, 0), None);
        // Any other next hop has no scope.
        assert_eq!(route("2001:db8::1", 0, 7), Some((ip("2001:db8::1"), 0)));
        assert_eq!(route("2001:db8::1", 3, 7), Some((ip("2001:db8::1"), 0)));
        assert_eq!(route("::ffff:192.168.1.1", 0, 7), None);
        assert_eq!(route("ff02::1", 0, 7), None);
    }

    #[test]
    fn public_ipv4_gateway_means_no_mapping_needed() {
        let gw = |s: &str| Gateways {
            v4: Some(v4(s)),
            v6: None,
        };
        // A global gateway: this computer is public (100.128/9 is past
        // carrier-grade NAT's 100.64/10).
        for public in ["11.0.2.1", "100.128.0.1"] {
            assert!(public_host(v4(public)), "{public}");
            assert_eq!(gw(public).v4_to_map(), None, "{public}");
        }
        // A home router, a carrier-grade NAT, a link-local gateway: a router
        // to ask.
        for router in [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.1.1",
        ] {
            assert!(!public_host(v4(router)), "{router}");
            assert_eq!(gw(router).v4_to_map(), Some(v4(router)), "{router}");
        }
        assert_eq!(Gateways::default().v4_to_map(), None);
    }

    /// Runs in both builds: the release test jobs set the lab unlock and a
    /// lab gateway, and the system's routers come back (never loopback); a
    /// debug build follows exactly its environment and changes none of it.
    #[test]
    fn lab_gateway_override_is_inert_in_release() {
        let lab = LabGateway {
            v4: Some("127.0.0.1:5351".parse::<SocketAddrV4>().unwrap()),
            v6: Some("[fe80::1%4]:5351".parse::<SocketAddrV6>().unwrap()),
        };
        assert_eq!(
            Gateways::from(lab),
            Gateways {
                v4: Some(Ipv4Addr::LOCALHOST),
                v6: Some((v6("fe80::1"), 4)),
            }
        );
        let only_v6 = LabGateway {
            v4: None,
            v6: Some("[::1]:40001".parse::<SocketAddrV6>().unwrap()),
        };
        assert_eq!(
            Gateways::from(only_v6),
            Gateways {
                v4: None,
                v6: Some((Ipv6Addr::LOCALHOST, 0)),
            }
        );
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No release test needs them unset.
            std::env::set_var("RAVEN_LAB_TEST_A", "1");
            std::env::set_var("RAVEN_LAB_PORTMAP_GATEWAY", "127.0.0.1:5351");
            assert_eq!(crate::portmap_gate::lab_portmap_gateway(), None);
            let gw = default_gateways();
            assert_ne!(gw.v4, Some(Ipv4Addr::LOCALHOST));
            return;
        }
        match crate::portmap_gate::lab_portmap_gateway() {
            Some(lab) => assert_eq!(default_gateways(), Gateways::from(lab)),
            None => {
                let gw = default_gateways();
                assert_ne!(gw.v4, Some(Ipv4Addr::LOCALHOST));
            }
        }
    }

    /// The system's answer: whatever it is, it is a usable router. The CI
    /// jobs of the three systems (which have one) set
    /// `RAVEN_TEST_EXPECT_GATEWAY=1`, and then an IPv4 router must be found.
    /// No message prints an address of this host's network.
    #[test]
    fn default_gateways_on_this_host_does_not_panic() {
        let _ = default_gateways();
        let gw = os_query();
        if let Some(ip) = gw.v4 {
            assert!(v4_router(ip).is_some(), "the IPv4 router is not usable");
        }
        if let Some((ip, scope)) = gw.v6 {
            assert!(
                v6_router(ip, scope, 0) == Some((ip, scope)),
                "the IPv6 router or its scope is not usable"
            );
        }
        if std::env::var("RAVEN_TEST_EXPECT_GATEWAY").as_deref() == Ok("1") {
            assert!(
                gw.v4.is_some(),
                "no IPv4 default gateway found on this host"
            );
        }
    }
}
