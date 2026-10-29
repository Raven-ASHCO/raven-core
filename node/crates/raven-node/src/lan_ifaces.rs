//! This computer's LAN interfaces (Phase 3 items 1-2): the ones the LAN
//! beacon runs on, and the networks the `auto` LAN listener counts as local
//! ([`on_link`]).
//!
//! - **Read:** raven-core's interface list ([`netifs::read`]: `getifaddrs`
//!   on Unix, `GetAdaptersAddresses` on Windows; 169.254/16 and fe80::/10
//!   are kept, with their zone), grouped by interface ([`group`]). No new
//!   crate: if-addrs drops link-local addresses, and libp2p's mDNS stays off
//!   (the hickory-proto advisory; it announces the PeerId in the clear).
//! - **Which ([`select`]):** interfaces that are up and take multicast,
//!   never loopback, a point-to-point tunnel (`utun`, WireGuard, PPP) or
//!   Apple's peer-to-peer Wi-Fi (`awdl*`, `llw*`: no Wi-Fi Direct); at most
//!   [`MAX_IFACES`]: a hotspot this computer hosts first, then those with an
//!   address a network gave them, then the rest, container and VM bridges
//!   after every physical one, each group in the order the system lists
//!   them (Phase 3 P3.C3, F11a). A cable with only link-local addresses
//!   counts (Windows' APIPA too), and so do container and VM bridges: a
//!   beacon there reaches only this computer's guests.
//! - **Cache:** [`refresh`] reads the system and keeps [`select`]'s list
//!   (the LAN beacon reads it at each poll and change, [`crate::lan_beacon`]);
//!   [`on_link`] asks the kept one (read on first use), and a miss reads
//!   again first, at most once per [`MISS_READ_GAP`].
//!
//! Local facts only: it opens no socket and sends nothing, so no gate holds
//! it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use raven_core::netifs::{self, LocalAddr};

use crate::netutil;

/// Interfaces the beacon runs on, at most.
pub(crate) const MAX_IFACES: usize = 8;

/// A miss in [`on_link`] reads the system again at most this often.
const MISS_READ_GAP: Duration = Duration::from_secs(1);

/// One interface as the system lists it, before [`select`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawIf {
    /// Its name: `en0`; on Windows the adapter's friendly name.
    pub(crate) name: String,
    /// Its index; 0 when the system gave none.
    pub(crate) index: u32,
    pub(crate) up: bool,
    pub(crate) multicast: bool,
    pub(crate) broadcast: bool,
    pub(crate) loopback: bool,
    pub(crate) point_to_point: bool,
    /// Its addresses, link-local ones included, in the system's order.
    pub(crate) addrs: Vec<LocalAddr>,
}

/// One interface the beacon runs on ([`select`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BeaconIf {
    /// Its index: multicast joins and sends, and the scope id of its
    /// link-local address.
    pub(crate) index: u32,
    /// How the zone of its link-local address is written in a dial string
    /// ([`netutil::zone_for`]).
    pub(crate) zone: String,
    /// Its primary IPv4 address (the first one that is not link-local, else
    /// the first), that address's prefix length, and its subnet's broadcast
    /// address: None on a /31 or /32, when the prefix is not known, or when
    /// the interface does not broadcast.
    pub(crate) v4: Option<(Ipv4Addr, u8, Option<Ipv4Addr>)>,
    /// Every IPv4 network on it, as (network, prefix length).
    pub(crate) v4_prefixes: Vec<(Ipv4Addr, u8)>,
    /// Its IPv6 link-local address (fe80::/10; its scope id is
    /// [`BeaconIf::index`]).
    pub(crate) v6_ll: Option<Ipv6Addr>,
    /// Its other IPv6 networks (ULA, global), as (network, prefix length).
    pub(crate) v6_prefixes: Vec<(Ipv6Addr, u8)>,
}

/// `all` ([`netifs::read`]) as one [`RawIf`] per interface (pure), in the
/// order the system first lists each. Addresses with the same index are one
/// interface (Linux lists an alias, `eth0:1`, under its own name); without
/// an index the name decides. The system gives every address of an
/// interface its flags; loopback and point-to-point count when any address
/// says so.
fn group(all: Vec<LocalAddr>) -> Vec<RawIf> {
    let mut out: Vec<RawIf> = Vec::new();
    for a in all {
        let same = |r: &RawIf| match a.index {
            0 => r.index == 0 && r.name == a.ifname,
            index => r.index == index,
        };
        match out.iter().position(same) {
            Some(at) => {
                let r = &mut out[at];
                r.loopback |= a.loopback;
                r.point_to_point |= a.point_to_point;
                r.addrs.push(a);
            }
            None => out.push(RawIf {
                name: a.ifname.clone(),
                index: a.index,
                up: a.up,
                multicast: a.multicast,
                broadcast: a.broadcast,
                loopback: a.loopback,
                point_to_point: a.point_to_point,
                addrs: vec![a],
            }),
        }
    }
    out
}

/// The interfaces the beacon runs on (pure): of `raw`, those that are up,
/// take multicast, have an index and an IPv4 or IPv6 link-local address;
/// never loopback, a point-to-point tunnel or Apple's peer-to-peer Wi-Fi
/// (`awdl*`, `llw*`); at most [`MAX_IFACES`], in [`select_rank`]'s order
/// (Phase 3 P3.C3, F11a: a hotspot this computer hosts is never the one the
/// cap leaves out), else in `raw`'s.
fn select(raw: Vec<RawIf>) -> Vec<BeaconIf> {
    let mut kept: Vec<(u8, RawIf)> = raw
        .into_iter()
        .filter(|r| {
            r.up && r.multicast
                && !r.loopback
                && !r.point_to_point
                && r.index != 0
                && !r.name.starts_with("awdl")
                && !r.name.starts_with("llw")
        })
        .map(|r| (select_rank(&r), r))
        .collect();
    // Stable: interfaces of one rank keep the system's order.
    kept.sort_by_key(|(rank, _)| *rank);
    kept.into_iter()
        .filter_map(|(_, r)| beacon_if(r))
        .take(MAX_IFACES)
        .collect()
}

/// Where an interface goes in [`select`]'s order, lowest first (Phase 3
/// P3.C3, F11a):
///
/// - 0: this computer hosts a hotspot there (one of its addresses has
///   [`netifs::hotspot_rank`] 0: Internet Sharing's bridge, an access point
///   `ap<n>`, 192.168.2.1, 192.168.137.1 or 10.42.0.1);
/// - 1: another interface with an address a network gave it (an IPv4
///   address that is not link-local, or a ULA or global IPv6 one);
/// - 2: the rest (link-local addresses only: a cable with no router, or an
///   interface nothing uses);
/// - 3 and 4: the same for the networks of virtual machines and containers
///   ([`netifs::is_virtual`]: `docker*`, `br-*`, `vmnet*`, `vboxnet*`,
///   `virbr*` and the like), after every physical one: a beacon there
///   reaches only this computer's guests.
fn select_rank(r: &RawIf) -> u8 {
    if r.addrs.iter().any(|a| netifs::hotspot_rank(a) == 0) {
        return 0;
    }
    let assigned = r.addrs.iter().any(|a| match a.ip {
        IpAddr::V4(ip) => !(ip.is_link_local() || ip.is_loopback() || ip.is_unspecified()),
        IpAddr::V6(ip) => {
            !(is_v6_link_local(ip) || ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
        }
    });
    let rank = if assigned { 1 } else { 2 };
    if r.addrs.iter().any(netifs::is_virtual) {
        rank + 2
    } else {
        rank
    }
}

/// What the beacon keeps of the interface `r` (pure); None when it has
/// neither an IPv4 nor an IPv6 link-local address.
fn beacon_if(r: RawIf) -> Option<BeaconIf> {
    let mut v4s: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut v6_ll = None;
    let mut v6_prefixes = Vec::new();
    for a in &r.addrs {
        match a.ip {
            IpAddr::V4(ip)
                if !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_broadcast()) =>
            {
                v4s.push((ip, a.prefix.min(32)));
            }
            IpAddr::V6(ip) if is_v6_link_local(ip) => {
                v6_ll.get_or_insert(ip);
            }
            IpAddr::V6(ip)
                if !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
                    && (1..=128).contains(&a.prefix) =>
            {
                let net = (Ipv6Addr::from(u128::from(ip) & v6_mask(a.prefix)), a.prefix);
                if !v6_prefixes.contains(&net) {
                    v6_prefixes.push(net);
                }
            }
            _ => {}
        }
    }
    let primary = v4s
        .iter()
        .find(|(ip, _)| !ip.is_link_local())
        .or_else(|| v4s.first())
        .copied();
    if primary.is_none() && v6_ll.is_none() {
        return None;
    }
    let v4 = primary.map(|(ip, len)| {
        let broadcast = (r.broadcast && (1..=30).contains(&len))
            .then(|| Ipv4Addr::from(u32::from(ip) | !v4_mask(len)));
        (ip, len, broadcast)
    });
    let mut v4_prefixes = Vec::new();
    // A prefix the system did not give (0) is no network.
    for &(ip, len) in v4s.iter().filter(|(_, len)| *len > 0) {
        let net = (Ipv4Addr::from(u32::from(ip) & v4_mask(len)), len);
        if !v4_prefixes.contains(&net) {
            v4_prefixes.push(net);
        }
    }
    Some(BeaconIf {
        index: r.index,
        zone: netutil::zone_for(r.index, Some(&r.name)),
        v4,
        v4_prefixes,
        v6_ll,
        v6_prefixes,
    })
}

fn is_v6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// The network mask of an IPv4 prefix of `len` bits.
fn v4_mask(len: u8) -> u32 {
    u32::MAX
        .checked_shl(32 - u32::from(len.min(32)))
        .unwrap_or(0)
}

/// The network mask of an IPv6 prefix of `len` bits.
fn v6_mask(len: u8) -> u128 {
    u128::MAX
        .checked_shl(128 - u32::from(len.min(128)))
        .unwrap_or(0)
}

/// Whether `ip` is on one of `ifaces`' networks (pure): inside one of their
/// IPv4 or IPv6 prefixes, or an IPv6 link-local address while one of them
/// has one. An IPv4-mapped IPv6 address is its IPv4 address. The LAN beacon
/// finds a datagram's interface with it.
pub(crate) fn on_link_in(ifaces: &[BeaconIf], ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ifaces
            .iter()
            .flat_map(|i| &i.v4_prefixes)
            .any(|&(net, len)| u32::from(ip) & v4_mask(len) == u32::from(net)),
        IpAddr::V6(ip) if is_v6_link_local(ip) => ifaces.iter().any(|i| i.v6_ll.is_some()),
        IpAddr::V6(ip) => ifaces
            .iter()
            .flat_map(|i| &i.v6_prefixes)
            .any(|&(net, len)| u128::from(ip) & v6_mask(len) == u128::from(net)),
    }
}

/// Reads the system's interfaces, grouped by interface.
type Read<'a> = &'a dyn Fn() -> Result<Vec<RawIf>, String>;

/// The list [`refresh`] last kept, and when the system was last read.
struct Cache {
    ifaces: Option<Arc<Vec<BeaconIf>>>,
    read_at: Option<Instant>,
}

impl Cache {
    const fn new() -> Self {
        Cache {
            ifaces: None,
            read_at: None,
        }
    }

    /// Read the system now and keep [`select`]'s list. A read that fails
    /// keeps the last list (empty before the first).
    fn refresh(&mut self, now: Instant, read: Read<'_>) -> Arc<Vec<BeaconIf>> {
        self.read_at = Some(now);
        if let Ok(raw) = read() {
            self.ifaces = Some(Arc::new(select(raw)));
        }
        Arc::clone(self.ifaces.get_or_insert_with(Default::default))
    }

    /// The kept list; the system is read the first time.
    fn current(&mut self, now: Instant, read: Read<'_>) -> Arc<Vec<BeaconIf>> {
        match &self.ifaces {
            Some(ifaces) => Arc::clone(ifaces),
            None => self.refresh(now, read),
        }
    }
}

static CACHE: Mutex<Cache> = Mutex::new(Cache::new());

fn lock(cache: &Mutex<Cache>) -> MutexGuard<'_, Cache> {
    cache.lock().unwrap_or_else(PoisonError::into_inner)
}

/// This computer's interfaces ([`netifs::read`]), grouped ([`group`]).
fn read_system() -> Result<Vec<RawIf>, String> {
    netifs::read().map(group)
}

/// Read this computer's interfaces now and keep the ones the beacon runs on
/// ([`select`]). A read that fails keeps the last list.
pub(crate) fn refresh() -> Arc<Vec<BeaconIf>> {
    lock(&CACHE).refresh(Instant::now(), &read_system)
}

/// The list [`refresh`] last kept; read now the first time (tests: the LAN
/// beacon reads the interfaces afresh, and [`on_link`] keeps its own rule).
#[cfg(test)]
pub(crate) fn current() -> Arc<Vec<BeaconIf>> {
    lock(&CACHE).current(Instant::now(), &read_system)
}

/// Is `ip` on one of this computer's LAN networks: inside a prefix of an
/// interface [`refresh`] kept (read the first time), or on a network
/// netwatch settled on ([`crate::netwatch::on_link`])? The list may be a
/// poll old when a connection from a network that just came up arrives, so
/// a miss reads the interfaces again and asks once more, at most once per
/// [`MISS_READ_GAP`]; not for an address that is local anyway (raven-core's
/// `is_local_network_ip`: loopback, private, link-local, ULA), which the
/// local-source rule takes without asking.
pub(crate) fn on_link(ip: IpAddr) -> bool {
    on_link_with(&CACHE, ip, Instant::now(), &read_system, |ip| {
        crate::netwatch::on_link(ip) == Some(true)
    })
}

/// [`on_link`] against `cache` at `now`, the system read by `read` and
/// netwatch's answer given by `netwatch`.
fn on_link_with(
    cache: &Mutex<Cache>,
    ip: IpAddr,
    now: Instant,
    read: Read<'_>,
    netwatch: impl FnOnce(IpAddr) -> bool,
) -> bool {
    let ifaces = lock(cache).current(now, read);
    if on_link_in(&ifaces, ip) || netwatch(ip) {
        return true;
    }
    if raven_core::outbox::is_local_network_ip(ip) {
        return false;
    }
    let mut cache = lock(cache);
    let due = cache
        .read_at
        .is_none_or(|at| now.saturating_duration_since(at) >= MISS_READ_GAP);
    let ifaces = if due {
        cache.refresh(now, read)
    } else {
        cache.current(now, read)
    };
    on_link_in(&ifaces, ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const UP: u8 = 1;
    const MULTICAST: u8 = 2;
    const BROADCAST: u8 = 4;
    const LOOPBACK: u8 = 8;
    const POINTOPOINT: u8 = 16;
    /// A Wi-Fi, a cable or a bridge.
    const LAN: u8 = UP | MULTICAST | BROADCAST;

    fn ip4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn ip6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// An address as [`netifs::read`] lists it: `ip/prefix` on the interface
    /// `name` (index `index`, `flags`).
    fn addr(name: &str, index: u32, flags: u8, ip_prefix: &str) -> LocalAddr {
        let has = |f: u8| flags & f != 0;
        let (ip, prefix) = ip_prefix.split_once('/').unwrap();
        let ip: IpAddr = ip.parse().unwrap();
        let link_local = matches!(ip, IpAddr::V6(v6) if is_v6_link_local(v6));
        LocalAddr {
            ifname: name.into(),
            ip,
            prefix: prefix.parse().unwrap(),
            up: has(UP),
            loopback: has(LOOPBACK) || ip.is_loopback(),
            point_to_point: has(POINTOPOINT),
            virtual_net: false,
            scope_id: if link_local { index } else { 0 },
            index,
            multicast: has(MULTICAST),
            broadcast: has(BROADCAST),
        }
    }

    /// One interface with `addrs`, grouped as the system's list is.
    fn iface(name: &str, index: u32, flags: u8, addrs: &[&str]) -> RawIf {
        let all = addrs.iter().map(|a| addr(name, index, flags, a)).collect();
        let mut raw = group(all);
        assert_eq!(raw.len(), 1, "{raw:?}");
        raw.remove(0)
    }

    #[test]
    fn select_keeps_lan_interfaces_and_link_local_cables() {
        let raw = vec![
            iface(
                "lo0",
                1,
                UP | MULTICAST | LOOPBACK,
                &["127.0.0.1/8", "::1/128", "fe80::1/64"],
            ),
            iface(
                "en0",
                4,
                LAN,
                &[
                    "fe80::1c2b:3a4d:5e6f:7081/64",
                    "192.168.1.20/24",
                    "2001:db8:1:2::20/64",
                    // A temporary address in the same prefix.
                    "2001:db8:1:2:a:b:c:d/64",
                    "fd00:1::20/64",
                ],
            ),
            iface(
                "utun3",
                15,
                UP | MULTICAST | POINTOPOINT,
                &["fe80::aaaa/64", "10.8.0.2/32"],
            ),
            iface("awdl0", 11, LAN, &["fe80::bb/64"]),
            iface("llw0", 12, LAN, &["fe80::cc/64"]),
            // Down.
            iface("en1", 5, MULTICAST | BROADCAST, &["192.168.1.21/24"]),
            // No multicast.
            iface("gif0", 6, UP | BROADCAST, &["192.168.7.1/24"]),
            // A cable between two laptops: link-local addresses only.
            iface("en5", 7, LAN, &["169.254.12.3/16", "fe80::5/64"]),
            // Windows' APIPA on a cable.
            iface("Ethernet 2", 9, LAN, &["fe80::9/64", "169.254.80.5/16"]),
        ];
        let kept = select(raw);
        let indexes: Vec<u32> = kept.iter().map(|i| i.index).collect();
        assert_eq!(indexes, [4, 7, 9], "{kept:?}");
        assert_eq!(
            kept[0],
            BeaconIf {
                index: 4,
                zone: if cfg!(windows) { "4" } else { "en0" }.into(),
                v4: Some((ip4("192.168.1.20"), 24, Some(ip4("192.168.1.255")))),
                v4_prefixes: vec![(ip4("192.168.1.0"), 24)],
                v6_ll: Some(ip6("fe80::1c2b:3a4d:5e6f:7081")),
                v6_prefixes: vec![(ip6("2001:db8:1:2::"), 64), (ip6("fd00:1::"), 64)],
            }
        );
        let cable = &kept[1];
        assert_eq!(
            cable.v4,
            Some((ip4("169.254.12.3"), 16, Some(ip4("169.254.255.255"))))
        );
        assert_eq!(cable.v6_ll, Some(ip6("fe80::5")));
        assert_eq!(cable.zone, if cfg!(windows) { "7" } else { "en5" });
        // A name with a space is written as the number everywhere.
        let apipa = &kept[2];
        assert_eq!(apipa.zone, "9");
        assert_eq!(
            apipa.v4,
            Some((ip4("169.254.80.5"), 16, Some(ip4("169.254.255.255"))))
        );
        assert_eq!(apipa.v6_ll, Some(ip6("fe80::9")));
    }

    #[test]
    fn primary_ipv4_broadcast_and_networks() {
        // A DHCP address beside a link-local one is the primary; both are
        // networks of the interface.
        let both = select(vec![iface(
            "en0",
            4,
            LAN,
            &["169.254.3.3/16", "192.168.4.4/24"],
        )]);
        assert_eq!(
            both[0].v4,
            Some((ip4("192.168.4.4"), 24, Some(ip4("192.168.4.255"))))
        );
        assert_eq!(
            both[0].v4_prefixes,
            [(ip4("169.254.0.0"), 16), (ip4("192.168.4.0"), 24)]
        );
        // No subnet broadcast on a /31 or a /32, without a known prefix, or
        // on an interface that does not broadcast.
        for (flags, a) in [
            (LAN, "10.0.0.1/31"),
            (LAN, "10.0.0.1/32"),
            (LAN, "10.0.0.1/0"),
            (UP | MULTICAST, "10.0.0.1/24"),
        ] {
            let kept = select(vec![iface("en0", 4, flags, &[a])]);
            assert_eq!(kept[0].v4.map(|v4| v4.2), Some(None), "{a} {flags}");
        }
        // A prefix the system did not give is no network.
        let unknown = select(vec![iface("en0", 4, LAN, &["10.0.0.1/0", "fe80::1/0"])]);
        assert!(unknown[0].v4_prefixes.is_empty() && unknown[0].v6_prefixes.is_empty());
        // No index (the interface just went), or neither an IPv4 nor a
        // link-local address: nothing to beacon from.
        assert!(select(vec![iface("en0", 0, LAN, &["192.168.1.20/24"])]).is_empty());
        assert!(select(vec![iface("en0", 4, LAN, &["2001:db8::1/64"])]).is_empty());
    }

    #[test]
    fn at_most_eight_in_the_systems_order() {
        let raw: Vec<RawIf> = (1..=12u32)
            .map(|n| {
                let a = format!("192.168.{n}.2/24");
                iface(&format!("en{n}"), n, LAN, &[a.as_str()])
            })
            .collect();
        let kept = select(raw);
        assert_eq!(kept.len(), MAX_IFACES);
        let indexes: Vec<u32> = kept.iter().map(|i| i.index).collect();
        assert_eq!(indexes, (1..=8).collect::<Vec<u32>>());
    }

    /// Phase 3 P3.C3 (F11a): the order before the cap. A hotspot this
    /// computer hosts first, then interfaces with an address a network gave
    /// them, then link-local-only ones; the networks of virtual machines and
    /// containers after every physical one; within a rank, the system's
    /// order. The exclusions are unchanged.
    #[test]
    fn select_order_table() {
        let table: [(&str, &[&str], u8); 16] = [
            // macOS Internet Sharing, Windows' Mobile hotspot,
            // NetworkManager's shared mode, an access point with fe80 only.
            ("bridge100", &["192.168.2.1/24", "fe80::1/64"], 0),
            ("Wi-Fi 2", &["192.168.137.1/24"], 0),
            ("wlan0", &["10.42.0.1/24", "fe80::42/64"], 0),
            ("ap1", &["fe80::a1/64"], 0),
            // A Wi-Fi or a cable to a router, a public LAN, an IPv6-only
            // network.
            ("en0", &["fe80::20/64", "192.168.1.20/24"], 1),
            ("en8", &["203.0.113.5/24"], 1),
            ("en7", &["fe80::7/64", "fd00:7::7/64"], 1),
            // A cable with no router, an interface nothing uses.
            ("en5", &["169.254.12.3/16", "fe80::5/64"], 2),
            ("anpi0", &["fe80::a0/64"], 2),
            // Virtual machines' and containers' networks: Apple's vmnet on
            // bridge101, Docker, a compose network, VMware, libvirt,
            // VirtualBox (link-local only).
            ("bridge101", &["192.168.64.1/24", "fe80::64/64"], 3),
            ("docker0", &["172.17.0.1/16"], 3),
            ("br-3f2a9c1d0e4b", &["172.18.0.1/16"], 3),
            ("vmnet8", &["172.16.81.1/24"], 3),
            ("virbr0", &["192.168.122.1/24"], 3),
            ("vboxnet0", &["fe80::56/64"], 4),
            ("vmnet1", &["169.254.9.9/16"], 4),
        ];
        let raw: Vec<RawIf> = table
            .iter()
            .zip(1u32..)
            .map(|((name, addrs, _), index)| iface(name, index, LAN, addrs))
            .collect();
        for (r, (name, _, rank)) in raw.iter().zip(&table) {
            assert_eq!(select_rank(r), *rank, "{name}");
        }
        // Listed last to first by the system: sorted by rank, the system's
        // order within one, at most eight.
        let mut reversed = raw.clone();
        reversed.reverse();
        let names = |kept: &[BeaconIf]| -> Vec<String> {
            kept.iter()
                .map(|i| {
                    let at = usize::try_from(i.index - 1).unwrap();
                    table[at].0.to_string()
                })
                .collect()
        };
        assert_eq!(
            names(&select(reversed)),
            [
                "ap1",
                "wlan0",
                "Wi-Fi 2",
                "bridge100",
                "en7",
                "en8",
                "en0",
                "anpi0"
            ]
        );
        assert_eq!(
            names(&select(raw.clone())),
            [
                "bridge100",
                "Wi-Fi 2",
                "wlan0",
                "ap1",
                "en0",
                "en8",
                "en7",
                "en5"
            ]
        );
        // Down, no multicast, loopback, a tunnel or Apple's peer-to-peer
        // Wi-Fi: never, whatever the address.
        let out = [
            iface("bridge102", 41, MULTICAST | BROADCAST, &["192.168.2.1/24"]),
            iface("ap2", 42, UP | BROADCAST, &["192.168.50.1/24"]),
            iface("lo0", 43, UP | MULTICAST | LOOPBACK, &["127.0.0.1/8"]),
            iface("utun4", 44, UP | MULTICAST | POINTOPOINT, &["10.42.0.1/32"]),
            iface("awdl0", 45, LAN, &["fe80::aa/64"]),
            iface("llw0", 46, LAN, &["fe80::bb/64"]),
        ];
        assert!(select(out.to_vec()).is_empty());
    }

    /// Phase 3 P3.C3 (F11a): a Mac with many interfaces that hosts a hotspot
    /// lists Internet Sharing's bridge last; the cap of eight still keeps it.
    #[test]
    fn twelve_interfaces_keep_the_hotspot_host_listed_last() {
        let mut raw: Vec<RawIf> = (1..=11u32)
            .map(|n| {
                let a = format!("192.168.{}.2/24", n + 10);
                iface(&format!("en{n}"), n, LAN, &[a.as_str(), "fe80::2/64"])
            })
            .collect();
        raw.push(iface(
            "bridge100",
            12,
            LAN,
            &["192.168.2.1/24", "fe80::1/64"],
        ));
        let kept = select(raw);
        assert_eq!(kept.len(), MAX_IFACES);
        let indexes: Vec<u32> = kept.iter().map(|i| i.index).collect();
        assert_eq!(indexes, [12, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            kept[0].v4,
            Some((ip4("192.168.2.1"), 24, Some(ip4("192.168.2.255"))))
        );
    }

    #[test]
    fn group_joins_an_interfaces_addresses_in_the_systems_order() {
        let all = vec![
            addr("eth0", 2, LAN, "192.168.1.20/24"),
            addr("lo", 1, UP | LOOPBACK, "127.0.0.1/8"),
            addr("eth0", 2, LAN, "fe80::1/64"),
            // A Linux alias is its interface.
            addr("eth0:1", 2, LAN, "10.0.0.5/24"),
            addr("wlan0", 3, LAN, "192.168.9.9/24"),
            addr("lo", 1, UP | LOOPBACK, "::1/128"),
        ];
        let raw = group(all);
        let names: Vec<(&str, usize)> = raw
            .iter()
            .map(|r| (r.name.as_str(), r.addrs.len()))
            .collect();
        assert_eq!(names, [("eth0", 3), ("lo", 2), ("wlan0", 1)]);
        assert!(raw[1].loopback && !raw[0].loopback);
        // Without an index the name decides.
        let raw = group(vec![
            addr("x", 0, LAN, "192.168.1.1/24"),
            addr("y", 0, LAN, "192.168.2.1/24"),
            addr("x", 0, LAN, "fe80::1/64"),
        ]);
        let names: Vec<(&str, usize)> = raw
            .iter()
            .map(|r| (r.name.as_str(), r.addrs.len()))
            .collect();
        assert_eq!(names, [("x", 2), ("y", 1)]);
        // One address of an interface saying point-to-point is enough.
        let raw = group(vec![
            addr("en0", 4, LAN, "192.168.1.20/24"),
            addr("en0", 4, LAN | POINTOPOINT, "10.9.0.1/32"),
        ]);
        assert!(raw[0].point_to_point);
        assert!(select(raw).is_empty());
    }

    #[test]
    fn on_link_table_and_at_most_one_read_a_second_on_a_miss() {
        let wifi = iface(
            "en0",
            4,
            LAN,
            &["192.168.1.20/24", "fe80::1/64", "2001:db8:1:2::20/64"],
        );
        let system = RefCell::new(vec![wifi]);
        let reads = Cell::new(0u32);
        let read = || -> Result<Vec<RawIf>, String> {
            reads.set(reads.get() + 1);
            Ok(system.borrow().clone())
        };
        let cache = Mutex::new(Cache::new());
        let t0 = Instant::now();
        let ask = |ip: &str, ms: u64| {
            let at = t0 + Duration::from_millis(ms);
            on_link_with(&cache, ip.parse().unwrap(), at, &read, |_| false)
        };
        // Inside and outside a /24 and a /64.
        for (ip, want) in [
            ("192.168.1.77", true),
            ("192.168.1.0", true),
            ("192.168.1.255", true),
            ("::ffff:192.168.1.9", true),
            ("192.168.2.1", false),
            ("192.168.0.255", false),
            ("2001:db8:1:2::99", true),
            ("2001:db8:1:2:ffff:ffff:ffff:ffff", true),
            ("2001:db8:1:3::20", false),
            ("2001:db8:1:1:ffff:ffff:ffff:ffff", false),
            ("fe80::42", true),
            ("100.64.0.1", false),
            ("203.0.113.9", false),
        ] {
            assert_eq!(ask(ip, 0), want, "{ip}");
        }
        // The first question read the system; misses within the second
        // after a read read nothing.
        assert_eq!(reads.get(), 1);
        for ms in (0..1000).step_by(10) {
            assert!(!ask("203.0.113.9", ms));
        }
        assert_eq!(reads.get(), 1);
        // A miss a second later reads again, once in that second.
        for ms in (1000..2000).step_by(10) {
            assert!(!ask("203.0.113.9", ms));
        }
        assert_eq!(reads.get(), 2);
        // A miss for an address that is local anyway never reads.
        assert!(!ask("10.20.30.40", 5000));
        assert!(!ask("fd00:9::1", 5000));
        assert_eq!(reads.get(), 2);
        // A network that just came up (a public LAN, 203.0.113.0/24) is
        // found on the next miss, then from the list.
        system
            .borrow_mut()
            .push(iface("en7", 8, LAN, &["203.0.113.5/24"]));
        assert!(ask("203.0.113.9", 5000));
        assert_eq!(reads.get(), 3);
        assert!(ask("203.0.113.10", 5001));
        assert_eq!(reads.get(), 3);
        // netwatch's view counts too, without a read.
        let t = t0 + Duration::from_millis(5002);
        assert!(on_link_with(
            &cache,
            "198.51.100.7".parse().unwrap(),
            t,
            &read,
            |_| true
        ));
        assert_eq!(reads.get(), 3);
        // A read that fails keeps the last list.
        let failing = || -> Result<Vec<RawIf>, String> { Err("no".into()) };
        let t = t0 + Duration::from_millis(9000);
        assert!(on_link_with(
            &cache,
            "192.168.1.5".parse().unwrap(),
            t,
            &failing,
            |_| false
        ));
        assert!(!on_link_with(
            &cache,
            "198.51.100.7".parse().unwrap(),
            t,
            &failing,
            |_| false
        ));
        assert_eq!(lock(&cache).current(t, &failing).len(), 2);
        // No interface with a link-local address: fe80 is on none.
        let v4_only = Mutex::new(Cache::new());
        let read_v4 = || -> Result<Vec<RawIf>, String> {
            Ok(vec![iface("en0", 4, LAN, &["192.168.1.20/24"])])
        };
        assert!(!on_link_with(
            &v4_only,
            "fe80::42".parse().unwrap(),
            t0,
            &read_v4,
            |_| false
        ));
    }

    /// This host's interfaces read without panicking, and loopback is never
    /// one of them.
    #[test]
    fn this_hosts_interfaces_read_without_panicking() {
        for ifaces in [current(), refresh()] {
            assert!(ifaces.len() <= MAX_IFACES, "{ifaces:?}");
            for i in ifaces.iter() {
                assert_ne!(i.index, 0, "{i:?}");
                assert!(!i.zone.is_empty(), "{i:?}");
                assert!(i.v4.is_some() || i.v6_ll.is_some(), "{i:?}");
                assert!(i.v4.is_none_or(|(ip, _, _)| !ip.is_loopback()), "{i:?}");
            }
        }
        assert!(!on_link("127.0.0.1".parse().unwrap()));
        assert!(!on_link("::1".parse().unwrap()));
    }
}
