//! This computer's network interfaces and their addresses (cutoff pack F3),
//! read from the system itself: `getifaddrs` on Unix, `GetAdaptersAddresses`
//! on Windows. Nothing is sent.
//!
//! - **Every address.** Link-local addresses stay in [`read`]: 169.254/16, and
//!   fe80::/10 with its scope id. A cable between two laptops has nothing
//!   else. (if-addrs drops them, which is why this reads the system directly.)
//! - **What a friend can dial.** [`lan_addresses_for_friends`] keeps the
//!   addresses of interfaces that are up and lead to a local network (no
//!   loopback, no point-to-point tunnel, no Apple peer-to-peer Wi-Fi), IPv4
//!   first and the hotspot this computer hosts at the top ([`hotspot_rank`]).
//!   The networks of virtual machines and containers on this computer
//!   ([`is_virtual`]) come last and never count as being on a network
//!   ([`on_a_network`]; [`on_a_network_seen`] also counts a link with only
//!   fe80:: where raven-node saw a friend lately). `ash listen` and the terminal app's MEET list those
//!   the listener takes ([`listener_takes`]: one on 0.0.0.0 takes no IPv6
//!   address).
//! - **Interfaces.** Each address carries its interface's index and whether
//!   it takes multicast and broadcast: raven-node's LAN interface list
//!   (`lan_ifaces`, Phase 3) groups [`read`] by interface with them.
//!
//! Display and local facts only: no gate, and no dial depends on it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// One address on one of this computer's interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAddr {
    /// The interface's name: `en0`, `bridge100`, `wlan0`; on Windows its
    /// friendly name (`Wi-Fi 2`), which the user may have typed: sanitize it
    /// before it is printed.
    pub ifname: String,
    pub ip: IpAddr,
    /// The length of the address's network prefix (0 when the system does not
    /// say).
    pub prefix: u8,
    /// The interface is up and running (Windows: its operational status is
    /// up).
    pub up: bool,
    pub loopback: bool,
    /// A point-to-point link: a VPN tunnel (`utun`, `tun0`, `wg0`; on
    /// Windows a WireGuard or Tailscale adapter) or PPP.
    pub point_to_point: bool,
    /// The system says the adapter is a virtual one that no friend dials
    /// (Windows, by its description and its lack of a gateway: an internal
    /// Hyper-V switch, a VPN's TAP adapter, a virtual machine's host-only
    /// adapter; [`windows_adapter_kind`]). [`is_virtual`] also reads the
    /// interface's name.
    pub virtual_net: bool,
    /// The IPv6 scope id (the interface's index) of a link-local address;
    /// 0 otherwise.
    pub scope_id: u32,
    /// The interface's index (`if_nametoindex`; Windows: the adapter's
    /// index, its IPv6 one when IPv4 is off there); 0 when the system gave
    /// none.
    pub index: u32,
    /// The interface takes multicast (Unix `IFF_MULTICAST`; Windows: the
    /// adapter is not marked no-multicast).
    pub multicast: bool,
    /// The interface takes broadcast (Unix `IFF_BROADCAST`; Windows: every
    /// adapter but loopback and tunnels).
    pub broadcast: bool,
}

/// The address a computer gives itself when it hosts a hotspot: macOS
/// Internet Sharing, Windows' Mobile hotspot, NetworkManager's shared mode
/// (`nmcli device wifi hotspot`).
pub const HOTSPOT_HOST_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(192, 168, 2, 1),
    Ipv4Addr::new(192, 168, 137, 1),
    Ipv4Addr::new(10, 42, 0, 1),
];

/// [`hotspot_rank`] of a virtual machine's or a container's network on this
/// computer ([`is_virtual`]): after every other address.
pub const VIRTUAL_RANK: u8 = 4;

/// Where `a` goes in the list a friend is told, lowest first:
///
/// - 0: this computer hosts a hotspot there: the address is one of
///   [`HOTSPOT_HOST_IPS`] (macOS Internet Sharing's bridge has the first), or
///   the interface is an access point, `ap<n>`;
/// - 1: another private IPv4 address on an interface that is up and not
///   point-to-point (a Wi-Fi or a cable to a router);
/// - 2: an IPv4 link-local address, 169.254/16 (a cable with no router);
/// - 3: the rest;
/// - [`VIRTUAL_RANK`]: a network of virtual machines or containers
///   ([`is_virtual`]), whatever its address: a friend can't dial it.
///
/// A laptop set by hand to 192.168.2.1 on a home router's 192.168.2.0/24
/// counts as a hotspot host too: that only moves it up the list.
pub fn hotspot_rank(a: &LocalAddr) -> u8 {
    let v4 = match a.ip {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    };
    if a.loopback {
        3
    } else if is_virtual(a) {
        VIRTUAL_RANK
    } else if access_point_ifname(&a.ifname) || v4.is_some_and(|ip| HOTSPOT_HOST_IPS.contains(&ip))
    {
        0
    } else if a.up && !a.point_to_point && v4.is_some_and(|ip| ip.is_private()) {
        1
    } else if v4.is_some_and(|ip| ip.is_link_local()) {
        2
    } else {
        3
    }
}

/// `ap<n>`: an access point interface.
fn access_point_ifname(name: &str) -> bool {
    name.strip_prefix("ap").is_some_and(all_digits)
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The names of the bridges and adapters that container and virtual machine
/// programs make on Linux and macOS: Docker (`docker0`, a compose network's
/// `br-<id>`), libvirt (`virbr0`), VMware (`vmnet8`), VirtualBox
/// (`vboxnet0`), LXC and LXD, Podman, Parallels (`vnic0`).
const VIRTUAL_IFNAME_PREFIXES: [&str; 9] = [
    "docker", "br-", "virbr", "vmnet", "vboxnet", "lxcbr", "lxdbr", "podman", "vnic",
];

/// Whether `a` is a network of virtual machines or containers on this
/// computer, which a friend on the same Wi-Fi or cable can't dial: the system
/// says so ([`LocalAddr::virtual_net`], Windows), its name is one of
/// [`VIRTUAL_IFNAME_PREFIXES`], or it is a macOS `bridge1xx` without a
/// hotspot host's address ([`HOTSPOT_HOST_IPS`]). Apple's vmnet (UTM, Lima,
/// Tart, Multipass, Parallels, Docker Desktop's VM) makes `bridge100` with
/// 192.168.64.1/24, which is no hotspot; Internet Sharing makes a
/// `bridge1xx` too, with 192.168.2.1.
pub fn is_virtual(a: &LocalAddr) -> bool {
    let bridge1xx = a
        .ifname
        .strip_prefix("bridge1")
        .is_some_and(|n| n.len() == 2 && all_digits(n));
    let hotspot_ip = matches!(a.ip, IpAddr::V4(ip) if HOTSPOT_HOST_IPS.contains(&ip));
    a.virtual_net
        || VIRTUAL_IFNAME_PREFIXES
            .iter()
            .any(|p| a.ifname.starts_with(p))
        || (bridge1xx && !hotspot_ip)
}

/// This computer's addresses a friend on the same network could dial, in the
/// order to offer them: IPv4 first, then by [`hotspot_rank`], else in the
/// order the system lists them. Empty when this computer is on no network, or
/// when the interfaces can't be read.
pub fn lan_addresses_for_friends() -> Vec<LocalAddr> {
    read().map(for_friends).unwrap_or_default()
}

/// The part of [`lan_addresses_for_friends`] that does not read the system:
/// of `all` (a [`read`]), the addresses on an interface that is up, not
/// loopback, not point-to-point (`utun`) and not Apple's peer-to-peer Wi-Fi
/// (`awdl*`, `llw*`), sorted. An IPv6 link-local address (fe80::/10) is left
/// out: every interface has one, and it names this computer's interface, so
/// a friend could not dial it as it is. Virtual machines' and containers'
/// networks stay, ranked last of their family ([`VIRTUAL_RANK`]).
pub fn for_friends(all: Vec<LocalAddr>) -> Vec<LocalAddr> {
    let mut friends: Vec<LocalAddr> = all
        .into_iter()
        .filter(|a| leads_to_a_local_network(a) && !is_v6_link_local(a.ip))
        .collect();
    // Stable: equal keys keep the system's order.
    friends.sort_by_key(|a| (a.ip.is_ipv6(), hotspot_rank(a)));
    friends
}

/// `a` is on an interface that is up, not loopback, not point-to-point
/// (`utun`) and not Apple's peer-to-peer Wi-Fi (`awdl*`, `llw*`), and is an
/// address of one host ([`for_friends`] also leaves out fe80::/10).
fn leads_to_a_local_network(a: &LocalAddr) -> bool {
    a.up && !a.loopback
        && !a.point_to_point
        && !a.ifname.starts_with("awdl")
        && !a.ifname.starts_with("llw")
        && !a.ip.is_loopback()
        && !a.ip.is_unspecified()
        && !a.ip.is_multicast()
}

/// Whether `all` (a [`read`]) puts this computer on a network a friend could
/// share: one of [`for_friends`] that is not a virtual machine's or a
/// container's network ([`is_virtual`]), which is up whether or not this
/// computer is on any Wi-Fi, cable or hotspot.
pub fn on_a_network(all: Vec<LocalAddr>) -> bool {
    for_friends(all).iter().any(|a| !is_virtual(a))
}

/// [`on_a_network`], or a link with only an IPv6 link-local address on which
/// the running raven-node saw a friend lately: `friends_here` is its count
/// (IPC `Status`'s `lan.friends_here_10m`: a beacon find on an interface it
/// runs on now, or an authenticated link to an address on one of this
/// computer's networks now), None without a running raven-node. A cable
/// between two laptops that nobody hands addresses on has fe80:: alone (an
/// IPv6-only link, or the minute before 169.254 is taken), and Raven works
/// there; but every Mac keeps fe80:: on ports and bridges that lead nowhere,
/// so fe80:: alone, with no friend seen, is still no network.
pub fn on_a_network_seen(all: Vec<LocalAddr>, friends_here: Option<u32>) -> bool {
    let link_local_link = all
        .iter()
        .any(|a| leads_to_a_local_network(a) && is_v6_link_local(a.ip) && !is_virtual(a));
    (link_local_link && friends_here.is_some_and(|n| n > 0)) || on_a_network(all)
}

/// Whether a listener bound to `listen` takes connections to `ip`: on its own
/// address only; on 0.0.0.0, on every IPv4 address; on [::], on every IPv6
/// address, and on IPv4 ones too where such a socket is dual-stack (Unix; on
/// Windows it is IPv6-only). A friend told an address the listener does not
/// take would dial nothing.
pub fn listener_takes(listen: IpAddr, ip: IpAddr) -> bool {
    match listen {
        IpAddr::V4(any) if any.is_unspecified() => ip.is_ipv4(),
        IpAddr::V6(any) if any.is_unspecified() => ip.is_ipv6() || !cfg!(windows),
        _ => listen == ip,
    }
}

/// Whether `ip` is one of this computer's own addresses (any loopback address
/// is). None when the interfaces can't be read.
pub fn is_on_this_computer(ip: IpAddr) -> Option<bool> {
    let all = read().ok()?;
    let ip = ip.to_canonical();
    Some(ip.is_loopback() || all.iter().any(|a| a.ip == ip))
}

/// Whether `ip` is on one of this computer's own networks: loopback, an
/// IPv6 link-local address (its zone names the interface), or an address
/// inside the network of one of this computer's addresses (by its prefix;
/// /24 or /64 when the system gave none). None when the interfaces can't be
/// read. A LAN address a contact was only seen at is dialled only when it
/// is (E2: a router's address in front of two friends).
pub fn on_our_networks(ip: IpAddr) -> Option<bool> {
    Some(on_networks_in(&read().ok()?, ip))
}

/// [`on_our_networks`] over the interface list `all` (pure).
pub fn on_networks_in(all: &[LocalAddr], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    if ip.is_loopback() || is_v6_link_local(ip) {
        return true;
    }
    all.iter().any(|a| match (a.ip.to_canonical(), ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let bits = if a.prefix == 0 { 24 } else { a.prefix.min(32) };
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) if !is_v6_link_local(IpAddr::V6(net)) => {
            let bits = if a.prefix == 0 { 64 } else { a.prefix.min(128) };
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    })
}

fn is_v6_link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
}

/// The index of the interface named `name` (`if_nametoindex`; on Windows
/// the adapter's system name, `ethernet_32769`); `None` when there is none.
#[cfg(unix)]
pub fn interface_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the whole call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}

/// The index of the interface named `name` (`if_nametoindex`; on Windows
/// the adapter's system name, `ethernet_32769`); `None` when there is none.
#[cfg(windows)]
pub fn interface_index(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the whole call.
    let idx = unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::if_nametoindex(c.as_ptr().cast())
    };
    (idx != 0).then_some(idx)
}

/// No interface names on this system.
#[cfg(not(any(unix, windows)))]
pub fn interface_index(_name: &str) -> Option<u32> {
    None
}

/// `[v6%zone]:port` (a `--lan-listen` such as `[fe80::1%en0]:7420`) as a
/// socket address whose scope id is the zone's interface index: std parses
/// only a numeric zone, and a bind of the text would ask the resolver and
/// fail. `None` when `addr` has no `%zone` in brackets; `Err` (why) when the
/// address or the interface is not there.
pub fn scoped_v6_socket(addr: &str) -> Option<Result<SocketAddr, String>> {
    let addr = addr.trim();
    let (host, port) = addr.strip_prefix('[')?.rsplit_once("]:")?;
    let (ip, zone) = host.split_once('%')?;
    let parsed = (|| {
        let port: u16 = port
            .parse()
            .map_err(|_| format!("{addr:?}: not a port after ]:"))?;
        let ip: Ipv6Addr = ip
            .parse()
            .map_err(|_| format!("{addr:?}: not an IPv6 address before %"))?;
        let scope = zone
            .parse::<u32>()
            .ok()
            .or_else(|| interface_index(zone))
            .ok_or_else(|| format!("{addr:?}: unknown network interface {zone:?}"))?;
        Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
    })();
    Some(parsed)
}

/// Every address on every interface, in the order the system lists them,
/// link-local addresses included. Err (the system's reason) when the list
/// can't be read.
#[cfg(unix)]
pub fn read() -> Result<Vec<LocalAddr>, String> {
    unix::read()
}

/// Every address on every interface, in the order the system lists them,
/// link-local addresses included. Err (the system's reason) when the list
/// can't be read.
#[cfg(windows)]
pub fn read() -> Result<Vec<LocalAddr>, String> {
    windows::read()
}

/// Every address on every interface. This system has no reader: always Err.
#[cfg(not(any(unix, windows)))]
pub fn read() -> Result<Vec<LocalAddr>, String> {
    Err("this system's network interfaces can't be read".into())
}

/// What a Windows adapter is, as [`read`] counts it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterKind {
    /// A Wi-Fi, a cable, a hotspot: what friends may dial.
    Physical,
    /// A tunnel: PPP, a tunnel adapter, or a VPN's own adapter type
    /// (WireGuard and Tailscale use Wintun's `IF_TYPE_PROP_VIRTUAL`).
    PointToPoint,
    /// A virtual switch or adapter on this computer with no gateway of its
    /// own: Hyper-V's `vEthernet` (WSL2, Windows Sandbox, Docker Desktop),
    /// OpenVPN's TAP adapter, or a virtual machine program's host-only
    /// adapter.
    Virtual,
}

/// The adapter types (`IfType`, ipifcons.h) [`windows_adapter_kind`] counts as
/// tunnels: PPP (23), Wintun and WireGuardNT (`IF_TYPE_PROP_VIRTUAL`, 53),
/// and tunnel adapters (131).
pub const WINDOWS_TUNNEL_IF_TYPES: [u32; 3] = [23, 53, 131];

/// Words in a Windows adapter's description that mark a virtual one
/// (lowercase). Never "virtual" alone: the Mobile hotspot's adapter is a
/// "Wi-Fi Direct Virtual Adapter".
const VIRTUAL_ADAPTER_WORDS: [&str; 4] = [
    "hyper-v virtual ethernet",
    "tap-windows",
    "virtualbox host-only",
    "vmware virtual ethernet",
];

/// What a Windows adapter is, from its `IfType`, its description, its
/// friendly name and whether it has a gateway (pure: it compiles and is
/// tested on every system). A Hyper-V switch with a gateway is an external
/// one: this computer's own network moved onto it, so it counts as one.
pub fn windows_adapter_kind(
    if_type: u32,
    description: &str,
    friendly_name: &str,
    has_gateway: bool,
) -> AdapterKind {
    if WINDOWS_TUNNEL_IF_TYPES.contains(&if_type) {
        return AdapterKind::PointToPoint;
    }
    let description = description.to_ascii_lowercase();
    let virtual_adapter = VIRTUAL_ADAPTER_WORDS
        .iter()
        .any(|w| description.contains(w))
        || friendly_name.starts_with("vEthernet (");
    if virtual_adapter && !has_gateway {
        AdapterKind::Virtual
    } else {
        AdapterKind::Physical
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::CStr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::LocalAddr;

    /// The list `getifaddrs` returned, freed once when dropped.
    struct IfAddrs(*mut libc::ifaddrs);

    impl Drop for IfAddrs {
        fn drop(&mut self) {
            // SAFETY: the pointer came from a successful `getifaddrs` and this
            // is the only place it is freed.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    pub(super) fn read() -> Result<Vec<LocalAddr>, String> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `head` is a valid out-pointer; on success the list is owned
        // by `IfAddrs` below, which frees it.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(format!(
                "getifaddrs failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let list = IfAddrs(head);
        let mut out = Vec::new();
        let mut at = list.0.cast_const();
        while !at.is_null() {
            // SAFETY: `at` is a node of the list `getifaddrs` returned, which
            // `list` keeps alive until the end of this function.
            let ifa = unsafe { &*at };
            at = ifa.ifa_next.cast_const();
            // SAFETY: as above; `entry` reads only this node's own fields.
            if let Some(addr) = unsafe { entry(ifa) } {
                out.push(addr);
            }
        }
        Ok(out)
    }

    /// One node as a [`LocalAddr`]; None for a node without an IPv4 or IPv6
    /// address (a link-layer entry, an interface without addresses).
    ///
    /// # Safety
    /// `ifa` is a node of a live `getifaddrs` list.
    unsafe fn entry(ifa: &libc::ifaddrs) -> Option<LocalAddr> {
        let addr = ifa.ifa_addr.cast_const();
        if addr.is_null() || ifa.ifa_name.is_null() {
            return None;
        }
        // SAFETY: a non-null `ifa_addr` points to a sockaddr of the list.
        let family = libc::c_int::from(unsafe { (*addr).sa_family });
        // SAFETY: `ifa_name` is the NUL-terminated name the list holds.
        let ifname = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let mask = ifa.ifa_netmask.cast_const();
        let flag = |f: libc::c_int| ifa.ifa_flags & (f as libc::c_uint) != 0;
        let (ip, prefix, mut scope_id) = match family {
            libc::AF_INET => {
                // SAFETY: an AF_INET address is a sockaddr_in.
                let sin: libc::sockaddr_in = unsafe { copy_sockaddr(addr) };
                let prefix = if mask.is_null() {
                    0
                } else {
                    // SAFETY: the mask of an AF_INET address, read as one
                    // (BSDs leave its family unset and may shorten it).
                    let m: libc::sockaddr_in = unsafe { copy_sockaddr(mask) };
                    m.sin_addr.s_addr.count_ones() as u8
                };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                (IpAddr::V4(ip), prefix, 0)
            }
            libc::AF_INET6 => {
                // SAFETY: an AF_INET6 address is a sockaddr_in6.
                let sin6: libc::sockaddr_in6 = unsafe { copy_sockaddr(addr) };
                let prefix = if mask.is_null() {
                    0
                } else {
                    // SAFETY: the mask of an AF_INET6 address, read as one.
                    let m: libc::sockaddr_in6 = unsafe { copy_sockaddr(mask) };
                    m.sin6_addr
                        .s6_addr
                        .iter()
                        .map(|b| b.count_ones())
                        .sum::<u32>() as u8
                };
                let (ip, scope_id) = unembed_scope(sin6.sin6_addr.s6_addr, sin6.sin6_scope_id);
                (IpAddr::V6(ip), prefix, scope_id)
            }
            _ => return None,
        };
        // SAFETY: `ifa_name` is NUL-terminated (above).
        let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
        if scope_id == 0 && super::is_v6_link_local(ip) {
            scope_id = index;
        }
        Some(LocalAddr {
            ifname,
            ip,
            prefix,
            up: flag(libc::IFF_UP) && flag(libc::IFF_RUNNING),
            loopback: flag(libc::IFF_LOOPBACK) || ip.is_loopback(),
            point_to_point: flag(libc::IFF_POINTOPOINT),
            // The name tells on these systems ([`super::is_virtual`]).
            virtual_net: false,
            scope_id,
            index,
            multicast: flag(libc::IFF_MULTICAST),
            broadcast: flag(libc::IFF_BROADCAST),
        })
    }

    /// The sockaddr at `sa` copied into a zeroed `T`. On the BSDs only the
    /// `sa_len` bytes it says it has are read: a netmask there may be shorter
    /// than its type.
    ///
    /// # Safety
    /// `sa` points to a sockaddr of a live `getifaddrs` list whose family's
    /// type is `T` (or, for a netmask, whose address's type is `T`).
    unsafe fn copy_sockaddr<T: Copy>(sa: *const libc::sockaddr) -> T {
        let mut out = std::mem::MaybeUninit::<T>::zeroed();
        // SAFETY: the caller's contract; `stored_len` never exceeds `T`'s size
        // nor (on the BSDs) the bytes the sockaddr says it has.
        unsafe {
            let len = stored_len::<T>(sa);
            std::ptr::copy_nonoverlapping(sa.cast::<u8>(), out.as_mut_ptr().cast::<u8>(), len);
            // A zeroed sockaddr is a valid one: every field is an integer.
            out.assume_init()
        }
    }

    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    unsafe fn stored_len<T>(sa: *const libc::sockaddr) -> usize {
        // SAFETY: `sa` points to a sockaddr (caller); `sa_len` is its first byte.
        usize::from(unsafe { (*sa).sa_len }).min(std::mem::size_of::<T>())
    }

    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    unsafe fn stored_len<T>(_sa: *const libc::sockaddr) -> usize {
        // Linux and the others store each sockaddr whole.
        std::mem::size_of::<T>()
    }

    /// A KAME-style kernel (the BSDs, macOS) may hand out a link-local
    /// address with its interface index written into its second 16 bits and
    /// no scope id: the plain address and its scope.
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    fn unembed_scope(mut bytes: [u8; 16], scope_id: u32) -> (Ipv6Addr, u32) {
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

    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    fn unembed_scope(bytes: [u8; 16], scope_id: u32) -> (Ipv6Addr, u32) {
        (Ipv6Addr::from(bytes), scope_id)
    }
}

#[cfg(windows)]
mod windows {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL,
        IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_NO_MULTICAST,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    use super::{AdapterKind, LocalAddr};

    // The pure classifier's numbers are the system's.
    const _: () = assert!(
        super::WINDOWS_TUNNEL_IF_TYPES[0] == IF_TYPE_PPP
            && super::WINDOWS_TUNNEL_IF_TYPES[1] == IF_TYPE_PROP_VIRTUAL
            && super::WINDOWS_TUNNEL_IF_TYPES[2] == IF_TYPE_TUNNEL
    );

    /// Microsoft's suggested first buffer (15 KB); the call says how much it
    /// needs when that is short.
    const FIRST_SIZE: u32 = 15 * 1024;
    /// The adapter list may grow between two calls: give up after this many.
    const TRIES: usize = 4;

    pub(super) fn read() -> Result<Vec<LocalAddr>, String> {
        // Gateways tell an external Hyper-V switch (this computer's network)
        // from an internal one ([`super::windows_adapter_kind`]).
        let flags = GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER
            | GAA_FLAG_INCLUDE_GATEWAYS;
        let mut size = FIRST_SIZE;
        for _ in 0..TRIES {
            // u64 cells: the adapter records need 8-byte alignment.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            size = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);
            // SAFETY: `buf` is writable for `size` bytes and 8-byte aligned;
            // `size` is a valid in/out parameter; `reserved` must be null.
            let rc = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                    &mut size,
                )
            };
            match rc {
                // SAFETY: on success `buf` holds the adapter list, and it
                // outlives the walk.
                ERROR_SUCCESS => return Ok(unsafe { walk(buf.as_ptr().cast()) }),
                ERROR_NO_DATA => return Ok(Vec::new()),
                ERROR_BUFFER_OVERFLOW => continue,
                other => return Err(format!("GetAdaptersAddresses failed (error {other})")),
            }
        }
        Err("GetAdaptersAddresses: the adapter list kept growing".into())
    }

    /// Every unicast address of every adapter in the list at `first`.
    ///
    /// # Safety
    /// `first` is null or the head of a list `GetAdaptersAddresses` wrote into
    /// a buffer that outlives this call.
    unsafe fn walk(first: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<LocalAddr> {
        let mut out = Vec::new();
        let mut adapter = first;
        while !adapter.is_null() {
            // SAFETY: a node of the list (caller's contract).
            let a = unsafe { &*adapter };
            adapter = a.Next.cast_const();
            // SAFETY: `FriendlyName` is null or a NUL-terminated string of the list.
            let ifname = unsafe { wide(a.FriendlyName) };
            // SAFETY: `Description` is null or a NUL-terminated string of the list.
            let description = unsafe { wide(a.Description) };
            let up = a.OperStatus == IfOperStatusUp;
            let loopback = a.IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            let has_gateway = !a.FirstGatewayAddress.is_null();
            let kind = super::windows_adapter_kind(a.IfType, &description, &ifname, has_gateway);
            let point_to_point = kind == AdapterKind::PointToPoint;
            let virtual_net = kind == AdapterKind::Virtual;
            // SAFETY: both unions are plain integers in every view.
            let (if_index, flags) = unsafe { (a.Anonymous1.Anonymous.IfIndex, a.Anonymous2.Flags) };
            // The IPv4 index is 0 where IPv4 is off on the adapter (older
            // Windows): its IPv6 index then.
            let index = if if_index != 0 {
                if_index
            } else {
                a.Ipv6IfIndex
            };
            let multicast = flags & IP_ADAPTER_NO_MULTICAST == 0;
            let mut unicast = a.FirstUnicastAddress.cast_const();
            while !unicast.is_null() {
                // SAFETY: a node of the adapter's unicast list.
                let u = unsafe { &*unicast };
                unicast = u.Next.cast_const();
                // SAFETY: `Address` describes a sockaddr of the list and its
                // length.
                let Some((ip, scope_id)) = (unsafe {
                    socket_ip(u.Address.lpSockaddr.cast_const(), u.Address.iSockaddrLength)
                }) else {
                    continue;
                };
                out.push(LocalAddr {
                    ifname: ifname.clone(),
                    ip,
                    prefix: u.OnLinkPrefixLength,
                    up,
                    loopback: loopback || ip.is_loopback(),
                    point_to_point,
                    virtual_net,
                    scope_id,
                    index,
                    multicast,
                    broadcast: !loopback && !point_to_point,
                });
            }
        }
        out
    }

    /// The IP (and IPv6 scope id) of the sockaddr at `sa`, `len` bytes long.
    ///
    /// # Safety
    /// `sa` is null or points to `len` readable bytes of a sockaddr.
    unsafe fn socket_ip(
        sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
        len: i32,
    ) -> Option<(IpAddr, u32)> {
        let len = usize::try_from(len).ok()?;
        if sa.is_null() || len < std::mem::size_of::<u16>() {
            return None;
        }
        // SAFETY: at least the family is readable (checked above).
        match unsafe { (*sa).sa_family } {
            AF_INET if len >= std::mem::size_of::<SOCKADDR_IN>() => {
                // SAFETY: an AF_INET sockaddr of full size; unaligned-safe read.
                let sin = unsafe { std::ptr::read_unaligned(sa.cast::<SOCKADDR_IN>()) };
                // SAFETY: every view of the IN_ADDR union is plain bytes.
                let raw = unsafe { sin.sin_addr.S_un.S_addr };
                Some((IpAddr::V4(Ipv4Addr::from(u32::from_be(raw))), 0))
            }
            AF_INET6 if len >= std::mem::size_of::<SOCKADDR_IN6>() => {
                // SAFETY: an AF_INET6 sockaddr of full size; unaligned-safe read.
                let sin6 = unsafe { std::ptr::read_unaligned(sa.cast::<SOCKADDR_IN6>()) };
                // SAFETY: both unions are plain bytes in every view.
                let (bytes, scope_id) =
                    unsafe { (sin6.sin6_addr.u.Byte, sin6.Anonymous.sin6_scope_id) };
                Some((IpAddr::V6(Ipv6Addr::from(bytes)), scope_id))
            }
            _ => None,
        }
    }

    /// A NUL-terminated UTF-16 string, lossily; empty for null.
    ///
    /// # Safety
    /// `p` is null or points to a NUL-terminated UTF-16 string.
    unsafe fn wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        // SAFETY: the string is NUL-terminated (caller's contract); 256
        // characters is far beyond any adapter name.
        while len < 256 && unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: the `len` units before the NUL (or the cap) are readable.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B-5: a named IPv6 zone becomes the interface's index (numeric ones
    /// stay); no zone is not ours; a bad address, port or interface says so.
    #[test]
    fn a_named_ipv6_zone_becomes_its_interface_index() {
        let lo = if cfg!(windows) {
            "loopback_0"
        } else if cfg!(target_os = "linux") {
            "lo"
        } else {
            "lo0"
        };
        if let Some(index) = interface_index(lo) {
            let got = scoped_v6_socket(&format!("[fe80::1%{lo}]:7420"))
                .unwrap()
                .unwrap();
            assert_eq!(
                got,
                SocketAddr::V6(SocketAddrV6::new(
                    "fe80::1".parse().unwrap(),
                    7420,
                    0,
                    index
                ))
            );
        }
        assert_eq!(
            scoped_v6_socket(" [fe80::1%7]:0 ").unwrap().unwrap(),
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 0, 0, 7))
        );
        for plain in ["0.0.0.0:7420", "[::1]:7420", "auto", "fe80::1%en0"] {
            assert!(scoped_v6_socket(plain).is_none(), "{plain}");
        }
        for bad in [
            "[fe80::1%no-such-if0]:7420",
            "[fe80::zz%1]:7420",
            "[fe80::1%1]:http",
        ] {
            assert!(scoped_v6_socket(bad).unwrap().is_err(), "{bad}");
        }
    }

    fn at(ifname: &str, ip: &str) -> LocalAddr {
        LocalAddr {
            ifname: ifname.into(),
            ip: ip.parse().unwrap(),
            prefix: 24,
            up: true,
            loopback: false,
            point_to_point: false,
            virtual_net: false,
            scope_id: 0,
            index: 0,
            multicast: true,
            broadcast: true,
        }
    }

    #[test]
    fn hotspot_rank_table() {
        let p2p = |ifname: &str, ip: &str| LocalAddr {
            point_to_point: true,
            ..at(ifname, ip)
        };
        let ranked = [
            // macOS Internet Sharing, any address on an access point,
            // Windows' Mobile hotspot, NetworkManager's shared mode.
            (at("bridge100", "192.168.2.1"), 0),
            (at("bridge101", "192.168.2.1"), 0),
            (at("ap1", "192.168.50.1"), 0),
            (at("Wi-Fi 2", "192.168.137.1"), 0),
            (at("wlan0", "10.42.0.1"), 0),
            // A Wi-Fi or a cable to a router.
            (at("en0", "192.168.1.20"), 1),
            (at("eth0", "172.16.4.9"), 1),
            (at("Ethernet", "10.1.2.3"), 1),
            // A cable with no router.
            (at("en5", "169.254.12.3"), 2),
            // The rest: a VPN, a public address, IPv6, a down interface.
            (p2p("utun3", "10.8.0.2"), 3),
            (at("en0", "203.0.113.7"), 3),
            (at("en0", "fd00::7"), 3),
            (
                LocalAddr {
                    up: false,
                    ..at("en0", "192.168.1.21")
                },
                3,
            ),
            // Only an ap<n> is a hotspot by name. A Mac's Thunderbolt
            // Bridge (bridge0) is a cable.
            (at("bridge0", "192.168.1.30"), 1),
            (at("bridge1000", "192.168.1.31"), 1),
            (at("apple0", "192.168.1.32"), 1),
            (at("br0", "192.168.1.33"), 1),
            // A virtual machine's or a container's network, never a
            // hotspot: Apple's vmnet (UTM, Lima, Tart, Parallels) on
            // bridge100, any other bridge1xx address, Docker, libvirt,
            // VMware, VirtualBox; on Windows, as the reader says.
            (at("bridge100", "192.168.64.1"), VIRTUAL_RANK),
            (at("bridge101", "192.168.3.1"), VIRTUAL_RANK),
            (at("bridge102", "10.211.55.2"), VIRTUAL_RANK),
            (at("docker0", "172.17.0.1"), VIRTUAL_RANK),
            (at("br-3f2a9c1d0e4b", "172.18.0.1"), VIRTUAL_RANK),
            (at("virbr0", "192.168.122.1"), VIRTUAL_RANK),
            (at("vmnet8", "172.16.81.1"), VIRTUAL_RANK),
            (at("vboxnet0", "192.168.56.1"), VIRTUAL_RANK),
            (
                LocalAddr {
                    virtual_net: true,
                    ..at("vEthernet (Default Switch)", "172.29.160.1")
                },
                VIRTUAL_RANK,
            ),
            (
                LocalAddr {
                    virtual_net: true,
                    ..at("vEthernet (Internal)", "192.168.137.1")
                },
                VIRTUAL_RANK,
            ),
        ];
        for (addr, rank) in &ranked {
            assert_eq!(hotspot_rank(addr), *rank, "{addr:?}");
        }
        // Loopback is never a hotspot, whatever its name.
        let lo = LocalAddr {
            loopback: true,
            ..at("ap0", "127.0.0.1")
        };
        assert_eq!(hotspot_rank(&lo), 3);

        // A friend is offered the hotspot first, then the Wi-Fi, then the
        // cable, IPv6 last; tunnels, Apple's peer-to-peer Wi-Fi, loopback,
        // down interfaces and fe80 never.
        let all = vec![
            at("en5", "169.254.12.3"),
            at("en0", "fe80::1c2b:3a4d:5e6f:7081"),
            at("en0", "192.168.1.20"),
            p2p("utun0", "10.8.0.2"),
            at("awdl0", "fe80::aa"),
            at("awdl0", "192.168.9.9"),
            at("llw0", "192.168.9.10"),
            at("en0", "fd00::7"),
            LocalAddr {
                loopback: true,
                ..at("lo0", "127.0.0.1")
            },
            LocalAddr {
                up: false,
                ..at("en1", "192.168.1.21")
            },
            at("Wi-Fi 2", "192.168.137.1"),
            at("bridge101", "10.42.0.1"),
        ];
        let offered: Vec<(String, String)> = for_friends(all)
            .into_iter()
            .map(|a| (a.ifname, a.ip.to_string()))
            .collect();
        let want = [
            ("Wi-Fi 2", "192.168.137.1"),
            ("bridge101", "10.42.0.1"),
            ("en0", "192.168.1.20"),
            ("en5", "169.254.12.3"),
            ("en0", "fd00::7"),
        ];
        let want: Vec<(String, String)> = want
            .iter()
            .map(|(i, a)| (i.to_string(), a.to_string()))
            .collect();
        assert_eq!(offered, want);
    }

    /// A virtual machine's bridge that the system lists before the Wi-Fi
    /// is offered after it, never as a hotspot, and does not put this
    /// computer on a network (D-interfaces-texts-1).
    #[test]
    fn a_vm_bridge_comes_after_the_wifi_and_is_no_network() {
        let vm = at("bridge100", "192.168.64.1");
        let wifi = at("en0", "192.168.0.16");
        let order: Vec<String> = for_friends(vec![vm.clone(), wifi.clone()])
            .into_iter()
            .map(|a| a.ifname)
            .collect();
        assert_eq!(order, ["en0", "bridge100"]);
        assert!(is_virtual(&vm) && !is_virtual(&wifi));
        // Internet Sharing turned on beside the VM: the hotspot first.
        let sharing = at("bridge101", "192.168.2.1");
        let order: Vec<String> = for_friends(vec![vm.clone(), wifi.clone(), sharing])
            .into_iter()
            .map(|a| a.ifname)
            .collect();
        assert_eq!(order, ["bridge101", "en0", "bridge100"]);
        // Wi-Fi off: only VM and container networks are up.
        let docker = at("docker0", "172.17.0.1");
        assert!(!on_a_network(vec![vm.clone(), docker.clone()]));
        assert!(on_a_network(vec![vm.clone(), docker, wifi]));
        assert!(on_a_network(vec![at("en5", "169.254.12.3")]));
        assert!(!on_a_network(Vec::new()));
        let hyper_v = LocalAddr {
            virtual_net: true,
            ..at("vEthernet (Default Switch)", "172.29.160.1")
        };
        assert!(!on_a_network(vec![hyper_v, vm]));
    }

    /// E-1 (Phase 3 review): a cable with fe80:: alone, where raven-node saw
    /// a friend lately, is a network; fe80:: on a Mac's ports, tunnels and
    /// peer-to-peer Wi-Fi with nobody seen is still none, and a friend seen
    /// over this computer's own loopback makes no network either.
    #[test]
    fn a_cable_with_only_fe80_is_a_network_once_a_friend_is_seen_there() {
        let cable = || vec![at("en5", "fe80::1")];
        assert!(!on_a_network(cable()));
        assert!(on_a_network_seen(cable(), Some(1)));
        assert!(!on_a_network_seen(cable(), Some(0)));
        assert!(!on_a_network_seen(cable(), None));
        // A Mac with Wi-Fi off: fe80:: on the Thunderbolt and anpi ports,
        // the tunnels and AWDL.
        let tunnel = LocalAddr {
            point_to_point: true,
            ..at("utun0", "fe80::2")
        };
        let mac = || {
            vec![
                at("anpi0", "fe80::3"),
                at("en1", "fe80::4"),
                tunnel.clone(),
                at("awdl0", "fe80::5"),
                at("llw0", "fe80::6"),
            ]
        };
        assert!(!on_a_network(mac()));
        assert!(!on_a_network_seen(mac(), None));
        assert!(!on_a_network_seen(mac(), Some(0)));
        // Only tunnels, peer-to-peer Wi-Fi, loopback and virtual networks
        // carry fe80::: a friend seen (over loopback) is no network.
        let lo = LocalAddr {
            loopback: true,
            ..at("lo0", "fe80::1")
        };
        let vm = at("bridge100", "fe80::7");
        let nowhere = vec![
            tunnel,
            at("awdl0", "fe80::5"),
            at("llw0", "fe80::6"),
            lo,
            vm,
        ];
        assert!(!on_a_network_seen(nowhere, Some(2)));
        // The count never takes a network away.
        assert!(on_a_network_seen(vec![at("en0", "192.168.0.16")], None));
        assert!(on_a_network_seen(vec![at("en5", "169.254.12.3")], Some(0)));
    }

    /// Windows adapters by their type, description and name
    /// (D-interfaces-texts-5): the pure part of the Windows reader.
    #[test]
    fn windows_adapters_by_type_description_and_name() {
        use AdapterKind::*;
        let table = [
            // Wintun: WireGuard and Tailscale.
            (53, "WireGuard Tunnel", "wg0", false, PointToPoint),
            (53, "Tailscale Tunnel", "Tailscale", true, PointToPoint),
            (23, "WAN Miniport (PPPOE)", "Broadband", true, PointToPoint),
            (
                131,
                "Microsoft Teredo Tunneling Adapter",
                "Teredo",
                false,
                PointToPoint,
            ),
            // Ethernet-typed virtual adapters with no gateway of their own.
            (
                6,
                "Hyper-V Virtual Ethernet Adapter",
                "vEthernet (Default Switch)",
                false,
                Virtual,
            ),
            (
                6,
                "Hyper-V Virtual Ethernet Adapter #2",
                "Renamed by me",
                false,
                Virtual,
            ),
            (6, "Some Ethernet", "vEthernet (WSL)", false, Virtual),
            (6, "TAP-Windows Adapter V9", "Ethernet 3", false, Virtual),
            (
                6,
                "VirtualBox Host-Only Ethernet Adapter",
                "Ethernet 4",
                false,
                Virtual,
            ),
            (
                6,
                "VMware Virtual Ethernet Adapter for VMnet8",
                "VMware Network Adapter VMnet8",
                false,
                Virtual,
            ),
            // An external Hyper-V switch carries this computer's own network.
            (
                6,
                "Hyper-V Virtual Ethernet Adapter",
                "vEthernet (External)",
                true,
                Physical,
            ),
            // Real adapters, the Mobile hotspot's among them.
            (71, "Intel(R) Wi-Fi 6 AX201 160MHz", "Wi-Fi", true, Physical),
            (
                71,
                "Microsoft Wi-Fi Direct Virtual Adapter #2",
                "Local Area Connection* 10",
                false,
                Physical,
            ),
            (
                6,
                "Realtek USB GbE Family Controller",
                "Ethernet",
                false,
                Physical,
            ),
        ];
        for (if_type, description, name, gateway, kind) in table {
            assert_eq!(
                windows_adapter_kind(if_type, description, name, gateway),
                kind,
                "{if_type} {description} {name} {gateway}"
            );
        }
    }

    #[test]
    fn a_listener_takes_its_family_on_every_address_and_else_its_own() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let (v4, v6) = (ip("192.168.1.20"), ip("fd00::7"));
        assert!(listener_takes(ip("0.0.0.0"), v4));
        assert!(!listener_takes(ip("0.0.0.0"), v6));
        assert!(listener_takes(ip("::"), v6));
        assert_eq!(listener_takes(ip("::"), v4), !cfg!(windows));
        assert!(listener_takes(v4, v4));
        assert!(!listener_takes(v4, ip("192.168.1.21")));
        assert!(!listener_takes(ip("127.0.0.1"), v4));
    }

    /// E2: mac-b (cable on 192.168.0.0/24, Wi-Fi on 192.168.1.0/24) is on
    /// both networks; a friend seen from 10.0.0.7 (a VPN's) is on neither.
    #[test]
    fn on_our_networks_by_prefix() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let at = |s: &str, prefix: u8| LocalAddr {
            ifname: "en0".into(),
            ip: ip(s),
            prefix,
            up: true,
            loopback: false,
            point_to_point: false,
            virtual_net: false,
            scope_id: 0,
            index: 4,
            multicast: true,
            broadcast: true,
        };
        let all = [
            at("192.168.0.16", 24),
            at("192.168.1.24", 0),
            at("172.16.4.2", 16),
            at("2a02:1:2:3::14", 64),
            at("fe80::14", 64),
        ];
        for (addr, on) in [
            ("192.168.0.50", true),
            ("192.168.1.30", true),
            ("172.16.200.1", true),
            ("::ffff:192.168.0.9", true),
            ("2a02:1:2:3::99", true),
            ("127.0.0.1", true),
            ("fe80::99", true),
            ("10.0.0.7", false),
            ("192.168.2.1", false),
            ("172.17.0.1", false),
            ("2a02:1:2:4::1", false),
        ] {
            assert_eq!(on_networks_in(&all, ip(addr)), on, "{addr}");
        }
        assert!(!on_networks_in(&[], ip("192.168.0.50")));
    }

    #[test]
    fn read_on_this_host_has_loopback_and_does_not_panic() {
        let all = read().expect("this host's interfaces");
        let lo = all
            .iter()
            .find(|a| a.ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || a.ip == Ipv6Addr::LOCALHOST)
            .unwrap_or_else(|| panic!("no loopback address in {all:?}"));
        assert!(lo.loopback, "{lo:?}");
        if lo.ip.is_ipv4() {
            assert_eq!(lo.prefix, 8, "{lo:?}");
        }
        // A link-local IPv6 address carries its interface, and no index is
        // left inside the address itself (macOS writes one there).
        for a in &all {
            if is_v6_link_local(a.ip) {
                let IpAddr::V6(v6) = a.ip else { unreachable!() };
                assert_eq!(v6.segments()[1], 0, "{a:?}");
                assert_ne!(a.scope_id, 0, "{a:?}");
                if cfg!(unix) {
                    assert_eq!(a.scope_id, a.index, "{a:?}");
                }
            }
            // Every address names its interface's index.
            assert_ne!(a.index, 0, "{a:?}");
        }
        // What friends are offered is part of what was read.
        for a in lan_addresses_for_friends() {
            assert!(a.up && !a.loopback && !a.point_to_point, "{a:?}");
        }
    }

    #[test]
    fn is_on_this_computer_for_loopback_and_testnet() {
        assert_eq!(
            is_on_this_computer("127.0.0.1".parse().unwrap()),
            Some(true)
        );
        assert_eq!(is_on_this_computer("::1".parse().unwrap()), Some(true));
        // TEST-NET-1 (RFC 5737) is never configured on a real interface.
        assert_eq!(
            is_on_this_computer("192.0.2.10".parse().unwrap()),
            Some(false)
        );
        // The IPv4-mapped form of an address is the address.
        assert_eq!(
            is_on_this_computer("::ffff:127.0.0.1".parse().unwrap()),
            Some(true)
        );
    }
}
