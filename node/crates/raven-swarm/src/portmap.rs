//! Router port mapping for the endpoint host (Phase 4 part B, P4.6;
//! `protocol/RAVEN_PORT_MAPPING_V1.md`): the [`PortMap`] behaviour takes the
//! slot libp2p-upnp had in [`crate::host::EndpointBehaviour`].
//!
//! - **Gate closed** ([`PortMapConfig::pcp`] false, `PORT_MAP_PRODUCTION_ENABLED`):
//!   libp2p-upnp is created at once and sees every swarm event, and its
//!   output passes through unchanged ([`PortMapEvent::Upnp`]): today's
//!   UPnP-IGD behaviour, byte for byte. No socket is opened.
//! - **Gate open:** a driver per family runs `raven_core::portmap::MapperCore`
//!   (NAT-PMP and PCP) on a tokio task that owns a UDP socket connected to
//!   the default router ([`PortMapConfig::gw_v4`], [`PortMapConfig::gw_v6`]
//!   on [`PortMapConfig::gw_port`]). Only the egress address of each family
//!   is mapped: the IPv4 listen address equal to the IPv4 driver's source
//!   address toward the router, which must be [`PortMapConfig::egress_v4`]
//!   (else the Internet path bypasses that router, a full-tunnel VPN, and
//!   nothing is asked: [`PortMapEvent::OffEgress`]), and the IPv6 listen
//!   address equal to
//!   [`PortMapConfig::egress_v6`] (the pinhole, behind its own gate and
//!   consent, [`PortMapConfig::v6`]). VPN, container and every other
//!   listen address is never mapped. A mapping confirms its external
//!   address (`ExternalAddrConfirmed`, the IP and port of the listen
//!   address replaced, `/quic-v1` kept); its end expires it.
//! - **No PCP or NAT-PMP answer** on IPv4 ([`PortMapEvent::NoServer`]):
//!   libp2p-upnp is created then, and the remembered listen addresses are
//!   replayed to it, the egress IPv4 address only (§6: one protocol per
//!   family per network). Not while a harness names the router
//!   ([`PortMapConfig::upnp_fallback`] false): libp2p-upnp searches the
//!   real network, never the lab's fake router, so it is never created.
//! - **Leases:** IPv4 mappings ask [`PortMapConfig::lifetime`], IPv6
//!   pinholes at most `raven_core::portmap::PINHOLE_LIFETIME_S` (3600 s).
//! - **Drop:** each driver's command channel closes, and its task sends the
//!   lifetime-0 deletes once, best effort, on its own: the endpoint's
//!   shutdown (`close_everything` with `upnp_grace`) keeps the runtime up a
//!   moment for them.
//!
//! The behaviour opens no connection handler (both it and libp2p-upnp use
//! the dummy one), and nothing here logs: raven-node writes the lines,
//! counts and protocol names only, never an address (§12).

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::task::{Context, Poll};
use std::time::Instant;

use libp2p::core::transport::{ListenerId, PortUse};
use libp2p::core::Endpoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::{ExpiredListenAddr, NewListenAddr};
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{upnp, Multiaddr, PeerId};
use raven_core::portmap::{MapperConfig, MapperCore, Out, Proto, Via, PCP_PORT};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// The largest datagram a driver reads; a PCP message is at most
/// `raven_core::portmap::MAX_PCP` bytes, and a longer one is refused by the
/// codec.
const RECV_BUF: usize = 2048;

/// What the endpoint maps, built per endpoint generation (so the router is
/// looked up again on every network change).
#[derive(Clone)]
pub struct PortMapConfig {
    /// The IPv4 default router (`raven_core::gateway::Gateways::v4`); a
    /// global one means a public host with nothing to map.
    pub gw_v4: Option<Ipv4Addr>,
    /// The IPv6 default router and its scope id.
    pub gw_v6: Option<(Ipv6Addr, u32)>,
    /// The egress IPv4 address (`raven_core::route_memory::egress_addrs`):
    /// the source address toward the Internet. The IPv4 router is asked
    /// only when the source address toward it is this one; with a
    /// full-tunnel VPN they differ, and a mapping there would publish the
    /// address the VPN hides.
    pub egress_v4: Option<Ipv4Addr>,
    /// The egress IPv6 address (`raven_core::route_memory::egress_addrs`):
    /// the one IPv6 listen address a pinhole is asked for, and the IPv6
    /// driver's source address.
    pub egress_v6: Option<Ipv6Addr>,
    /// The PORT_MAP gate (`raven_core::port_map_live_enabled`): NAT-PMP and
    /// PCP before UPnP. False keeps today's UPnP-IGD exactly.
    pub pcp: bool,
    /// The V6_PINHOLE gate and its own consent; needs [`PortMapConfig::pcp`].
    pub v6: bool,
    /// The lease asked for (7200 s, or the lab's); an IPv6 pinhole asks at
    /// most `raven_core::portmap::PINHOLE_LIFETIME_S` (3600 s).
    pub lifetime: u32,
    /// `raven_core::portmap::nonce_key` of the profile.
    pub nonce_key: Zeroizing<[u8; 32]>,
    /// Lab only (`AddrRule::LabAnyIp`): a loopback client and external
    /// address count, for a fake gateway on the loopback.
    pub any_ip: bool,
    /// The routers' NAT-PMP/PCP port: [`PCP_PORT`], or the lab gateway's.
    pub gw_port: u16,
    /// libp2p-upnp may run: at once with [`PortMapConfig::pcp`] false, or
    /// after NAT-PMP and PCP stayed silent. False while a harness names the
    /// router (`RAVEN_LAB_PORTMAP_GATEWAY`): libp2p-upnp's SSDP search would
    /// reach the real network's router instead of the lab's.
    pub upnp_fallback: bool,
}

impl PortMapConfig {
    /// Today's behaviour: UPnP-IGD only, no NAT-PMP, PCP or pinhole.
    pub fn upnp_only() -> Self {
        Self {
            gw_v4: None,
            gw_v6: None,
            egress_v4: None,
            egress_v6: None,
            pcp: false,
            v6: false,
            lifetime: raven_core::portmap::REQUESTED_LIFETIME_S,
            nonce_key: Zeroizing::new([0; 32]),
            any_ip: false,
            gw_port: PCP_PORT,
            upnp_fallback: true,
        }
    }
}

/// Addresses and the key stay out of Debug output.
impl std::fmt::Debug for PortMapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let found = |set: bool| if set { "found" } else { "none" };
        f.debug_struct("PortMapConfig")
            .field("gw_v4", &found(self.gw_v4.is_some()))
            .field("gw_v6", &found(self.gw_v6.is_some()))
            .field("egress_v4", &found(self.egress_v4.is_some()))
            .field("egress_v6", &found(self.egress_v6.is_some()))
            .field("pcp", &self.pcp)
            .field("v6", &self.v6)
            .field("lifetime", &self.lifetime)
            .field("nonce_key", &"<redacted>")
            .field("any_ip", &self.any_ip)
            .field("gw_port", &self.gw_port)
            .field("upnp_fallback", &self.upnp_fallback)
            .finish()
    }
}

/// Why a mapping [`PortMapEvent::Mapped`] reported is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LostWhy {
    /// Its listen address went away, and Raven deleted it.
    Released,
    /// The router's side: the lease ended without a renewal, the external
    /// address or port changed, or the router refused or is not routable.
    Ended,
}

/// What the behaviour reports. No variant carries an address.
#[derive(Debug)]
pub enum PortMapEvent {
    /// libp2p-upnp's own event, unchanged.
    Upnp(upnp::Event),
    /// The router maps `port` (external) for the egress address of the
    /// family; one event per protocol.
    Mapped {
        via: Via,
        v6: bool,
        port: u16,
        tcp: bool,
        udp: bool,
    },
    /// A mapping reported [`PortMapEvent::Mapped`] is gone; `tcp` and
    /// `udp` as there.
    Lost {
        via: Via,
        v6: bool,
        why: LostWhy,
        tcp: bool,
        udp: bool,
    },
    /// Neither PCP nor NAT-PMP answered; `upnp`: IPv4 falls back to
    /// UPnP-IGD (false: [`PortMapConfig::upnp_fallback`] is off, nothing
    /// else is tried; always false for IPv6).
    NoServer { v6: bool, upnp: bool },
    /// The router refused, `code` its PCP or NAT-PMP result code.
    Refused { via: Via, v6: bool, code: u16 },
    /// The router's external address is not routable (another NAT in
    /// front of it): nothing is mapped. `carrier`: the provider's
    /// carrier-grade NAT (100.64.0.0/10); otherwise another router of the
    /// site (a double NAT).
    NonRoutable { carrier: bool },
    /// No router to ask for that family (none found, a public IPv4 host, no
    /// egress IPv6 address, or no socket toward it).
    NoGateway { v6: bool },
    /// The IPv4 router is not on the Internet path (the source address
    /// toward it is not the egress address: a full-tunnel VPN, or another
    /// default route): nothing is asked, not even UPnP.
    OffEgress,
    /// The router lost its mappings; they were asked again.
    ServerRestarted { via: Via },
}

/// A request to a driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmd {
    Want(Proto, u16),
    Unwant(Proto, u16),
}

/// One family's mapper, on its own tokio task: commands in, reports out.
/// Dropping it closes the command channel, and the task deletes what it
/// asked for and ends.
struct Driver {
    /// The source address toward the router: the egress address mapped.
    client: IpAddr,
    cmds: mpsc::UnboundedSender<Cmd>,
    outs: mpsc::UnboundedReceiver<Out>,
    /// The task ended (the core halted).
    done: bool,
}

impl Driver {
    /// A socket bound at `bind` and connected to the router at `gw` (nothing
    /// is sent), and the source address the system picked for it.
    fn connect(bind: SocketAddr, gw: SocketAddr) -> std::io::Result<(UdpSocket, IpAddr)> {
        let socket = UdpSocket::bind(bind)?;
        socket.connect(gw)?;
        socket.set_nonblocking(true)?;
        let client = socket.local_addr()?.ip();
        Ok((socket, client))
    }

    /// The task that runs the core on `socket`. Needs a tokio runtime, as
    /// libp2p-upnp does.
    fn spawn(socket: UdpSocket, client: IpAddr, cfg: MapperConfig) -> Self {
        let (cmds, cmd_rx) = mpsc::unbounded_channel();
        let (out_tx, outs) = mpsc::unbounded_channel();
        tokio::spawn(drive(socket, client, cfg, cmd_rx, out_tx));
        Self {
            client,
            cmds,
            outs,
            done: false,
        }
    }

    fn send(&self, cmd: Cmd) {
        // A halted core's task has ended: nothing more to ask.
        let _ = self.cmds.send(cmd);
    }
}

/// The driver task: the core's timers, the socket's datagrams and the
/// behaviour's commands, until the core halts or the behaviour is dropped
/// (then the deletes go out once).
async fn drive(
    socket: UdpSocket,
    client: IpAddr,
    cfg: MapperConfig,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    outs: mpsc::UnboundedSender<Out>,
) {
    let Ok(socket) = tokio::net::UdpSocket::from_std(socket) else {
        return;
    };
    let (mut core, mut todo) = MapperCore::new(client, cfg, Instant::now());
    let mut buf = vec![0u8; RECV_BUF];
    let mut readable = true;
    loop {
        for out in todo.drain(..) {
            match out {
                Out::Send(datagram) => {
                    let _ = socket.send(&datagram).await;
                }
                report => {
                    let _ = outs.send(report);
                }
            }
        }
        if core.is_halted() {
            return;
        }
        let wake = core.next_wake();
        let timer = async move {
            match wake {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            cmd = cmds.recv() => match cmd {
                Some(Cmd::Want(proto, port)) => todo = core.want(proto, port, Instant::now()),
                Some(Cmd::Unwant(proto, port)) => todo = core.unwant(proto, port),
                None => {
                    for out in core.shutdown() {
                        if let Out::Send(datagram) = out {
                            let _ = socket.send(&datagram).await;
                        }
                    }
                    return;
                }
            },
            got = socket.recv(&mut buf), if readable => match got {
                Ok(n) => todo = core.on_datagram(&buf[..n], Instant::now()),
                // An ICMP unreachable from the router: as if nothing came.
                Err(e) if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
                ) => {}
                // Any other error: read no more, keep the timers (the probe
                // then ends in NoServer).
                Err(_) => readable = false,
            },
            () = timer => todo = core.on_tick(Instant::now()),
        }
    }
}

/// A mapping as the behaviour tracks it: family, protocol, internal port.
type MapKey = (bool, Proto, u16);

/// The endpoint's router port mapping (see the module docs). `U` is the
/// UPnP-IGD behaviour: libp2p-upnp in every build; a test stub replaces it
/// so no test ever multicasts to a real router.
pub struct PortMap<U = upnp::tokio::Behaviour> {
    cfg: PortMapConfig,
    v4: Option<Driver>,
    v6: Option<Driver>,
    upnp: Option<U>,
    make_upnp: Box<dyn Fn() -> U + Send>,
    /// Every listen address the swarm reported, for the UPnP replay.
    listen: Vec<(ListenerId, Multiaddr)>,
    pending: VecDeque<ToSwarm<PortMapEvent, Infallible>>,
    /// Asked mappings and the listen address each was asked for.
    wanted: HashMap<MapKey, Multiaddr>,
    /// Confirmed external addresses, until their mapping ends.
    confirmed: HashMap<MapKey, Multiaddr>,
}

impl PortMap {
    /// The behaviour for `cfg`: with the PORT_MAP gate closed, libp2p-upnp at
    /// once (it starts its gateway search now, as before); with it open,
    /// the drivers (each starts its probe now).
    pub fn new(cfg: PortMapConfig) -> Self {
        Self::with_upnp(cfg, Box::new(upnp::tokio::Behaviour::default))
    }
}

impl<U> PortMap<U>
where
    U: NetworkBehaviour<ConnectionHandler = dummy::ConnectionHandler, ToSwarm = upnp::Event>,
{
    fn with_upnp(cfg: PortMapConfig, make_upnp: Box<dyn Fn() -> U + Send>) -> Self {
        let mut map = Self {
            cfg,
            v4: None,
            v6: None,
            upnp: None,
            make_upnp,
            listen: Vec::new(),
            pending: VecDeque::new(),
            wanted: HashMap::new(),
            confirmed: HashMap::new(),
        };
        if !map.cfg.pcp {
            if map.cfg.upnp_fallback {
                map.upnp = Some((map.make_upnp)());
            }
            return map;
        }
        // One per driver: the router's address is part of every nonce. An
        // IPv6 pinhole asks a shorter lease (owner decision O4-11).
        let (lifetime, nonce_key, any_ip) =
            (map.cfg.lifetime, map.cfg.nonce_key.clone(), map.cfg.any_ip);
        let mapper = move |gateway: IpAddr| MapperConfig {
            lifetime: if gateway.is_ipv6() {
                lifetime.min(raven_core::portmap::PINHOLE_LIFETIME_S)
            } else {
                lifetime
            },
            nonce_key: nonce_key.clone(),
            gateway,
            any_ip,
        };
        let port = map.cfg.gw_port;
        // A global IPv4 router: a public host, nothing to map (and no
        // UPnP either: the router to ask is the same one).
        let v4 = map
            .cfg
            .gw_v4
            .filter(|gw| !raven_core::gateway::public_host(*gw))
            .and_then(|gw| {
                let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
                let to = SocketAddr::V4(SocketAddrV4::new(gw, port));
                Driver::connect(bind, to).ok().map(|c| (gw, c))
            })
            .filter(|(_, (_, client))| map.v4_client_ok(*client));
        match v4 {
            // The router is on the Internet path: its source address is
            // the egress one.
            Some((gw, (socket, client))) if map.on_egress_v4(client) => {
                map.v4 = Some(Driver::spawn(socket, client, mapper(gw.into())));
            }
            Some(_) => map.report(PortMapEvent::OffEgress),
            None => map.report(PortMapEvent::NoGateway { v6: false }),
        }
        if map.cfg.v6 {
            let egress = map.cfg.egress_v6.filter(|ip| map.v6_ip_ok(*ip));
            map.v6 = match (map.cfg.gw_v6, egress) {
                (Some((gw, scope)), Some(egress)) => {
                    let bind = SocketAddr::V6(SocketAddrV6::new(egress, 0, 0, 0));
                    let to = SocketAddr::V6(SocketAddrV6::new(gw, port, 0, scope));
                    Driver::connect(bind, to)
                        .ok()
                        .map(|(socket, client)| Driver::spawn(socket, client, mapper(gw.into())))
                }
                _ => None,
            };
            if map.v6.is_none() {
                map.report(PortMapEvent::NoGateway { v6: true });
            }
        }
        map
    }

    fn report(&mut self, event: PortMapEvent) {
        self.pending.push_back(ToSwarm::GenerateEvent(event));
    }

    /// The IPv4 source address toward the router is an address behind a
    /// NAT (RFC 1918 or the shared 100.64/10), or loopback in the lab.
    fn v4_client_ok(&self, client: IpAddr) -> bool {
        match client {
            IpAddr::V4(ip) => {
                ip.is_private()
                    || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64)
                    || (self.cfg.any_ip && ip.is_loopback())
            }
            IpAddr::V6(_) => false,
        }
    }

    /// The source address toward the IPv4 router is the egress address
    /// ([`PortMapConfig::egress_v4`]); an unknown egress counts as not.
    fn on_egress_v4(&self, client: IpAddr) -> bool {
        self.cfg
            .egress_v4
            .is_some_and(|egress| client == IpAddr::V4(egress))
    }

    /// An IPv6 address a pinhole may be asked for: global, or loopback in
    /// the lab.
    fn v6_ip_ok(&self, ip: Ipv6Addr) -> bool {
        raven_core::p2p_route::is_global_ipv6(ip) || (self.cfg.any_ip && ip.is_loopback())
    }

    /// The egress IPv4 address: the only one UPnP is told about once it
    /// replaces NAT-PMP and PCP.
    fn is_egress_v4(&self, addr: &Multiaddr) -> bool {
        matches!(self.route(addr), Some((false, _, _)))
    }

    /// Which driver maps this listen address, and what: the egress address
    /// of the family only, as `/ip*/A/tcp/P` or `/ip*/A/udp/P/quic-v1`.
    fn route(&self, addr: &Multiaddr) -> Option<MapKey> {
        let parts: Vec<Protocol<'_>> = addr.iter().collect();
        let (proto, port) = match parts.as_slice() {
            [_, Protocol::Tcp(port)] => (Proto::Tcp, *port),
            [_, Protocol::Udp(port), Protocol::QuicV1] => (Proto::Udp, *port),
            _ => return None,
        };
        let v6 = match parts[0] {
            Protocol::Ip4(ip) => {
                let client = self.v4.as_ref()?.client;
                (IpAddr::V4(ip) == client).then_some(false)?
            }
            Protocol::Ip6(ip) => {
                self.v6.as_ref()?;
                (Some(ip) == self.cfg.egress_v6).then_some(true)?
            }
            _ => return None,
        };
        (port != 0).then_some((v6, proto, port))
    }

    fn driver(&self, v6: bool) -> Option<&Driver> {
        if v6 {
            self.v6.as_ref()
        } else {
            self.v4.as_ref()
        }
    }

    /// May libp2p-upnp see this swarm event? Every one with the gate
    /// closed; with it open, listen addresses of the egress IPv4 only.
    fn upnp_sees(&self, event: &FromSwarm) -> bool {
        if !self.cfg.pcp {
            return true;
        }
        match event {
            FromSwarm::NewListenAddr(NewListenAddr { addr, .. })
            | FromSwarm::ExpiredListenAddr(ExpiredListenAddr { addr, .. }) => {
                self.is_egress_v4(addr)
            }
            _ => true,
        }
    }

    /// libp2p-upnp after NAT-PMP and PCP stayed silent on IPv4: created
    /// now, and told the egress IPv4 listen addresses the swarm already
    /// reported (it maps on `NewListenAddr` only).
    fn start_upnp(&mut self) {
        if self.upnp.is_some() {
            return;
        }
        let mut upnp = (self.make_upnp)();
        for (listener_id, addr) in &self.listen {
            if self.is_egress_v4(addr) {
                upnp.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
                    listener_id: *listener_id,
                    addr,
                }));
            }
        }
        self.upnp = Some(upnp);
    }

    /// A driver's report, as swarm commands and events.
    fn on_out(&mut self, v6: bool, out: Out) {
        match out {
            Out::Send(_) => {}
            Out::Mapped {
                via,
                proto,
                internal_port,
                external,
            } => {
                let key = (v6, proto, internal_port);
                let Some(listen) = self.wanted.get(&key) else {
                    return;
                };
                let Some(ext) = external_multiaddr(listen, external) else {
                    return;
                };
                if let Some(old) = self.confirmed.insert(key, ext.clone()) {
                    if old != ext {
                        self.pending.push_back(ToSwarm::ExternalAddrExpired(old));
                    }
                }
                self.pending.push_back(ToSwarm::ExternalAddrConfirmed(ext));
                self.report(PortMapEvent::Mapped {
                    via,
                    v6,
                    port: external.port(),
                    tcp: proto == Proto::Tcp,
                    udp: proto == Proto::Udp,
                });
            }
            Out::Expired {
                via,
                proto,
                internal_port,
                ..
            } => {
                let key = (v6, proto, internal_port);
                if let Some(ext) = self.confirmed.remove(&key) {
                    self.pending.push_back(ToSwarm::ExternalAddrExpired(ext));
                    let why = if self.wanted.contains_key(&key) {
                        LostWhy::Ended
                    } else {
                        LostWhy::Released
                    };
                    self.report(PortMapEvent::Lost {
                        via,
                        v6,
                        why,
                        tcp: proto == Proto::Tcp,
                        udp: proto == Proto::Udp,
                    });
                }
            }
            Out::NoServer => {
                let upnp = !v6 && self.cfg.upnp_fallback;
                self.report(PortMapEvent::NoServer { v6, upnp });
                if upnp {
                    self.start_upnp();
                }
            }
            Out::Refused { via, code } => self.report(PortMapEvent::Refused { via, v6, code }),
            Out::NonRoutable { carrier } => self.report(PortMapEvent::NonRoutable { carrier }),
            Out::ServerRestarted { via } => self.report(PortMapEvent::ServerRestarted { via }),
        }
    }

    /// The next report of either driver, if one is ready.
    fn poll_drivers(&mut self, cx: &mut Context<'_>) -> Option<(bool, Out)> {
        for (v6, driver) in [(false, self.v4.as_mut()), (true, self.v6.as_mut())] {
            let Some(driver) = driver.filter(|d| !d.done) else {
                continue;
            };
            match driver.outs.poll_recv(cx) {
                Poll::Ready(Some(out)) => return Some((v6, out)),
                Poll::Ready(None) => driver.done = true,
                Poll::Pending => {}
            }
        }
        None
    }
}

/// `listen` with its IP and port replaced by the mapping's external ones
/// (`/quic-v1` kept); `None` if the family differs.
fn external_multiaddr(listen: &Multiaddr, external: SocketAddr) -> Option<Multiaddr> {
    let ip = match external.ip() {
        IpAddr::V4(ip) => Protocol::Ip4(ip),
        IpAddr::V6(ip) => Protocol::Ip6(ip),
    };
    let port = match listen.iter().nth(1)? {
        Protocol::Tcp(_) => Protocol::Tcp(external.port()),
        Protocol::Udp(_) => Protocol::Udp(external.port()),
        _ => return None,
    };
    let same_family = matches!(
        (listen.iter().next()?, &ip),
        (Protocol::Ip4(_), Protocol::Ip4(_)) | (Protocol::Ip6(_), Protocol::Ip6(_))
    );
    if !same_family {
        return None;
    }
    listen.replace(0, |_| Some(ip))?.replace(1, |_| Some(port))
}

impl<U> NetworkBehaviour for PortMap<U>
where
    U: NetworkBehaviour<ConnectionHandler = dummy::ConnectionHandler, ToSwarm = upnp::Event>,
{
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = PortMapEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if self.upnp.is_some() && self.upnp_sees(&event) {
            if let Some(upnp) = self.upnp.as_mut() {
                upnp.on_swarm_event(event);
            }
        }
        if !self.cfg.pcp {
            return;
        }
        match event {
            FromSwarm::NewListenAddr(NewListenAddr { listener_id, addr }) => {
                if !self.listen.iter().any(|(_, a)| a == addr) {
                    self.listen.push((listener_id, addr.clone()));
                }
                if let Some(key @ (v6, proto, port)) = self.route(addr) {
                    if let Entry::Vacant(slot) = self.wanted.entry(key) {
                        slot.insert(addr.clone());
                        if let Some(driver) = self.driver(v6) {
                            driver.send(Cmd::Want(proto, port));
                        }
                    }
                }
            }
            FromSwarm::ExpiredListenAddr(ExpiredListenAddr { addr, .. }) => {
                self.listen.retain(|(_, a)| a != addr);
                if let Some(key @ (v6, proto, port)) = self.route(addr) {
                    if self.wanted.get(&key) == Some(addr) {
                        self.wanted.remove(&key);
                        if let Some(driver) = self.driver(v6) {
                            driver.send(Cmd::Unwant(proto, port));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        libp2p::core::util::unreachable(event)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            if let Some(next) = self.pending.pop_front() {
                return Poll::Ready(next);
            }
            match self.poll_drivers(cx) {
                Some((v6, out)) => self.on_out(v6, out),
                None => break,
            }
        }
        if let Some(upnp) = self.upnp.as_mut() {
            if let Poll::Ready(next) = upnp.poll(cx) {
                return Poll::Ready(next.map_out(PortMapEvent::Upnp));
            }
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use futures::future::poll_fn;
    use raven_core::portmap_fake::{FakeGateway, Mode, SeenReq, FAKE_EXTERNAL_V4};

    use super::*;

    /// What the stub UPnP behaviour saw and what it will emit.
    #[derive(Default)]
    struct UpnpLog {
        made: AtomicUsize,
        seen: Mutex<Vec<String>>,
        script: Mutex<VecDeque<ToSwarm<upnp::Event, Infallible>>>,
    }

    /// libp2p-upnp's place in tests: records the swarm events it is given
    /// and emits a script; never searches for a gateway.
    struct StubUpnp(Arc<UpnpLog>);

    impl NetworkBehaviour for StubUpnp {
        type ConnectionHandler = dummy::ConnectionHandler;
        type ToSwarm = upnp::Event;

        fn handle_established_inbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: &Multiaddr,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn handle_established_outbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: Endpoint,
            _: PortUse,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn on_swarm_event(&mut self, event: FromSwarm) {
            let line = match event {
                FromSwarm::NewListenAddr(e) => format!("new {}", e.addr),
                FromSwarm::ExpiredListenAddr(e) => format!("expired {}", e.addr),
                _ => "other".into(),
            };
            self.0.seen.lock().unwrap().push(line);
        }

        fn on_connection_handler_event(
            &mut self,
            _: PeerId,
            _: ConnectionId,
            event: THandlerOutEvent<Self>,
        ) {
            libp2p::core::util::unreachable(event)
        }

        fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<upnp::Event, Infallible>> {
            match self.0.script.lock().unwrap().pop_front() {
                Some(next) => Poll::Ready(next),
                None => Poll::Pending,
            }
        }
    }

    fn stub_map(cfg: PortMapConfig) -> (PortMap<StubUpnp>, Arc<UpnpLog>) {
        let log = Arc::new(UpnpLog::default());
        let made = log.clone();
        let map = PortMap::with_upnp(
            cfg,
            Box::new(move || {
                made.made.fetch_add(1, Ordering::SeqCst);
                StubUpnp(made.clone())
            }),
        );
        (map, log)
    }

    /// A [`FakeGateway`] on a loopback UDP socket, served by a thread.
    struct Gw {
        port: u16,
        fake: Arc<Mutex<FakeGateway>>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Gw {
        /// `None` when the loopback of that family cannot be bound (an
        /// IPv6-less CI container).
        fn start(ip: IpAddr, mode: Mode) -> Option<Self> {
            let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).ok()?;
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let port = socket.local_addr().unwrap().port();
            let fake = Arc::new(Mutex::new(FakeGateway::new(mode, Instant::now())));
            let stop = Arc::new(AtomicBool::new(false));
            let (f, s) = (fake.clone(), stop.clone());
            let thread = std::thread::spawn(move || {
                let mut buf = [0u8; RECV_BUF];
                while !s.load(Ordering::SeqCst) {
                    if let Ok((n, src)) = socket.recv_from(&mut buf) {
                        let answer = f.lock().unwrap().reply(&buf[..n], src, Instant::now());
                        if let Some(answer) = answer {
                            let _ = socket.send_to(&answer, src);
                        }
                    }
                }
            });
            Some(Self {
                port,
                fake,
                stop,
                thread: Some(thread),
            })
        }

        fn log(&self) -> Vec<SeenReq> {
            self.fake.lock().unwrap().log.clone()
        }

        /// Lifetime-0 MAP requests (deletes) seen so far, as
        /// `(proto, internal port)`.
        fn deletes(&self) -> Vec<(u8, u16)> {
            self.log()
                .iter()
                .filter(|r| r.lifetime == 0 && r.proto.is_some())
                .map(|r| (r.proto.unwrap(), r.internal_port))
                .collect()
        }
    }

    impl Drop for Gw {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn lab_cfg(gw: &Gw) -> PortMapConfig {
        PortMapConfig {
            gw_v4: Some(Ipv4Addr::LOCALHOST),
            gw_v6: None,
            egress_v4: Some(Ipv4Addr::LOCALHOST),
            egress_v6: None,
            pcp: true,
            v6: false,
            lifetime: 7200,
            nonce_key: Zeroizing::new([7; 32]),
            any_ip: true,
            gw_port: gw.port,
            upnp_fallback: true,
        }
    }

    /// The leases the router was asked for (lifetime > 0 mapping requests).
    fn asked_lifetimes(gw: &Gw) -> Vec<u32> {
        gw.log()
            .iter()
            .filter(|r| r.proto.is_some() && r.lifetime > 0)
            .map(|r| r.lifetime)
            .collect()
    }

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn new_listen<U>(map: &mut PortMap<U>, id: ListenerId, addr: &Multiaddr)
    where
        U: NetworkBehaviour<ConnectionHandler = dummy::ConnectionHandler, ToSwarm = upnp::Event>,
    {
        map.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
            listener_id: id,
            addr,
        }));
    }

    fn expired_listen<U>(map: &mut PortMap<U>, id: ListenerId, addr: &Multiaddr)
    where
        U: NetworkBehaviour<ConnectionHandler = dummy::ConnectionHandler, ToSwarm = upnp::Event>,
    {
        map.on_swarm_event(FromSwarm::ExpiredListenAddr(ExpiredListenAddr {
            listener_id: id,
            addr,
        }));
    }

    /// One output of the behaviour, as text: what a test compares.
    fn show(next: &ToSwarm<PortMapEvent, Infallible>) -> String {
        match next {
            ToSwarm::ExternalAddrConfirmed(a) => format!("confirmed {a}"),
            ToSwarm::ExternalAddrExpired(a) => format!("expired {a}"),
            ToSwarm::GenerateEvent(e) => format!("{e:?}"),
            other => format!("other {other:?}"),
        }
    }

    /// Everything the behaviour emits until `until` matches an output or
    /// `secs` pass.
    async fn collect_until<U>(
        map: &mut PortMap<U>,
        secs: u64,
        until: impl Fn(&[String]) -> bool,
    ) -> Vec<String>
    where
        U: NetworkBehaviour<ConnectionHandler = dummy::ConnectionHandler, ToSwarm = upnp::Event>,
    {
        let mut got = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        loop {
            let next = tokio::time::timeout_at(deadline, poll_fn(|cx| map.poll(cx))).await;
            let Ok(next) = next else {
                return got;
            };
            got.push(show(&next));
            if until(&got) {
                return got;
            }
        }
    }

    /// The last output starts with `what`.
    fn ends(got: &[String], what: &str) -> bool {
        got.last().is_some_and(|l| l.starts_with(what))
    }

    async fn wait_for(secs: u64, what: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if what() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        what()
    }

    /// With the gate closed the stub UPnP behaviour exists from the start,
    /// sees every swarm event (VPN and Docker addresses too, as today), and
    /// what it emits comes out unchanged in the same order; no driver and no
    /// socket.
    #[tokio::test]
    async fn gate_closed_creates_upnp_at_once_and_starts_no_driver() {
        let (mut map, log) = stub_map(PortMapConfig::upnp_only());
        assert_eq!(log.made.load(Ordering::SeqCst), 1);
        assert!(map.v4.is_none() && map.v6.is_none());
        let id = ListenerId::next();
        let addrs = [
            "/ip4/192.168.1.20/tcp/7423",
            "/ip4/10.8.0.2/udp/7423/quic-v1",
            "/ip4/172.17.0.1/tcp/7423",
        ];
        for a in addrs {
            new_listen(&mut map, id, &ma(a));
        }
        expired_listen(&mut map, id, &ma(addrs[2]));
        assert_eq!(
            *log.seen.lock().unwrap(),
            [
                "new /ip4/192.168.1.20/tcp/7423",
                "new /ip4/10.8.0.2/udp/7423/quic-v1",
                "new /ip4/172.17.0.1/tcp/7423",
                "expired /ip4/172.17.0.1/tcp/7423",
            ]
        );
        let local = ma("/ip4/192.168.1.20/tcp/7423");
        let external = ma("/ip4/11.0.2.9/tcp/7423");
        log.script.lock().unwrap().extend([
            ToSwarm::ExternalAddrConfirmed(external.clone()),
            ToSwarm::GenerateEvent(upnp::Event::NewExternalAddr {
                local_addr: local.clone(),
                external_addr: external.clone(),
            }),
            ToSwarm::ExternalAddrExpired(external.clone()),
            ToSwarm::GenerateEvent(upnp::Event::ExpiredExternalAddr {
                local_addr: local,
                external_addr: external,
            }),
            ToSwarm::GenerateEvent(upnp::Event::GatewayNotFound),
            ToSwarm::GenerateEvent(upnp::Event::NonRoutableGateway),
        ]);
        let got = collect_until(&mut map, 1, |g| g.len() == 6).await;
        assert_eq!(
            got,
            [
                "confirmed /ip4/11.0.2.9/tcp/7423",
                "Upnp(NewExternalAddr { local_addr: /ip4/192.168.1.20/tcp/7423, \
                 external_addr: /ip4/11.0.2.9/tcp/7423 })",
                "expired /ip4/11.0.2.9/tcp/7423",
                "Upnp(ExpiredExternalAddr { local_addr: /ip4/192.168.1.20/tcp/7423, \
                 external_addr: /ip4/11.0.2.9/tcp/7423 })",
                "Upnp(GatewayNotFound)",
                "Upnp(NonRoutableGateway)",
            ]
        );
        assert!(map.pending.is_empty() && map.wanted.is_empty());
        assert_eq!(log.made.load(Ordering::SeqCst), 1);
    }

    /// A PCP router maps the egress TCP and QUIC ports: each is confirmed
    /// at the external address with its port, `/quic-v1` kept.
    #[tokio::test]
    async fn pcp_mapping_confirms_external_tcp_and_quic_multiaddrs() {
        let gw = Gw::start(Ipv4Addr::LOCALHOST.into(), Mode::AssignPort(41_000)).unwrap();
        let (mut map, log) = stub_map(lab_cfg(&gw));
        let id = ListenerId::next();
        new_listen(&mut map, id, &ma("/ip4/127.0.0.1/tcp/47001"));
        new_listen(&mut map, id, &ma("/ip4/127.0.0.1/udp/47001/quic-v1"));
        let got = collect_until(&mut map, 10, |g| g.len() == 4).await;
        let ext = FAKE_EXTERNAL_V4;
        for want in [
            format!("confirmed /ip4/{ext}/tcp/41000"),
            format!("confirmed /ip4/{ext}/udp/41000/quic-v1"),
            "Mapped { via: Pcp, v6: false, port: 41000, tcp: true, udp: false }".into(),
            "Mapped { via: Pcp, v6: false, port: 41000, tcp: false, udp: true }".into(),
        ] {
            assert!(got.contains(&want), "{want} in {got:?}");
        }
        assert!(collect_until(&mut map, 1, |_| false).await.is_empty());
        assert_eq!(log.made.load(Ordering::SeqCst), 0, "no UPnP");
        // Every PCP request names the egress client and nobody else.
        assert!(gw
            .log()
            .iter()
            .filter(|r| r.version == 2)
            .all(|r| r.client_ip == Some(Ipv4Addr::LOCALHOST.into())));
        // Review E-1: an IPv4 mapping asks the configured 7200 s lease.
        let leases = asked_lifetimes(&gw);
        assert!(
            !leases.is_empty() && leases.iter().all(|l| *l == 7200),
            "{leases:?}"
        );
    }

    /// A router that speaks NAT-PMP only is mapped through NAT-PMP.
    #[tokio::test]
    async fn nat_pmp_only_router_confirms_through_natpmp() {
        let gw = Gw::start(Ipv4Addr::LOCALHOST.into(), Mode::NatPmpOnly).unwrap();
        let (mut map, log) = stub_map(lab_cfg(&gw));
        new_listen(
            &mut map,
            ListenerId::next(),
            &ma("/ip4/127.0.0.1/tcp/47002"),
        );
        let got = collect_until(&mut map, 10, |g| ends(g, "Mapped")).await;
        assert_eq!(
            got,
            [
                format!("confirmed /ip4/{FAKE_EXTERNAL_V4}/tcp/47002"),
                "Mapped { via: NatPmp, v6: false, port: 47002, tcp: true, udp: false }".into(),
            ]
        );
        assert_eq!(log.made.load(Ordering::SeqCst), 0);
        assert!(gw
            .log()
            .iter()
            .any(|r| r.version == 0 && r.proto == Some(6)));
    }

    /// A silent router: after the probe, NoServer, then UPnP is created
    /// and told the egress IPv4 listen address only (not VPN, Docker or
    /// IPv6 ones, not a circuit), and from then on the egress one's changes.
    #[tokio::test]
    async fn silent_router_starts_upnp_and_replays_only_the_egress_listen_address() {
        let gw = Gw::start(Ipv4Addr::LOCALHOST.into(), Mode::Silent).unwrap();
        let (mut map, log) = stub_map(lab_cfg(&gw));
        let id = ListenerId::next();
        for a in [
            "/ip4/127.0.0.1/tcp/47003",
            "/ip4/10.8.0.2/tcp/47003",
            "/ip4/172.17.0.1/udp/47003/quic-v1",
            "/ip6/2001:db8::5/tcp/47003",
        ] {
            new_listen(&mut map, id, &ma(a));
        }
        let circuit = format!(
            "/ip4/127.0.0.1/tcp/47003/p2p/{}/p2p-circuit",
            PeerId::random()
        );
        new_listen(&mut map, id, &ma(&circuit));
        assert_eq!(
            log.made.load(Ordering::SeqCst),
            0,
            "not before the probe ends"
        );
        let got = collect_until(&mut map, 8, |g| ends(g, "NoServer")).await;
        assert_eq!(got, ["NoServer { v6: false, upnp: true }"]);
        assert_eq!(log.made.load(Ordering::SeqCst), 1);
        assert_eq!(*log.seen.lock().unwrap(), ["new /ip4/127.0.0.1/tcp/47003"]);
        new_listen(&mut map, id, &ma("/ip4/127.0.0.1/udp/47003/quic-v1"));
        new_listen(&mut map, id, &ma("/ip4/10.8.0.2/udp/47003/quic-v1"));
        expired_listen(&mut map, id, &ma("/ip4/127.0.0.1/tcp/47003"));
        expired_listen(&mut map, id, &ma("/ip4/10.8.0.2/tcp/47003"));
        assert_eq!(
            *log.seen.lock().unwrap(),
            [
                "new /ip4/127.0.0.1/tcp/47003",
                "new /ip4/127.0.0.1/udp/47003/quic-v1",
                "expired /ip4/127.0.0.1/tcp/47003",
            ]
        );
        // The probe asked; no mapping request ever went out.
        assert!(gw.log().iter().all(|r| r.proto.is_none()));
    }

    /// With the gate open only the egress IPv4 address is asked for; VPN
    /// and Docker addresses on the same ports never reach the router.
    #[tokio::test]
    async fn vpn_and_docker_listen_addresses_are_never_mapped_with_the_gate_open() {
        let gw = Gw::start(Ipv4Addr::LOCALHOST.into(), Mode::Pcp).unwrap();
        let (mut map, _log) = stub_map(lab_cfg(&gw));
        let id = ListenerId::next();
        for a in [
            "/ip4/10.8.0.2/tcp/47004",
            "/ip4/172.17.0.1/udp/47005/quic-v1",
            "/ip4/100.64.0.7/tcp/47006",
            "/ip4/127.0.0.1/tcp/47007",
        ] {
            new_listen(&mut map, id, &ma(a));
        }
        let got = collect_until(&mut map, 10, |g| ends(g, "Mapped")).await;
        assert_eq!(
            got,
            [
                format!("confirmed /ip4/{FAKE_EXTERNAL_V4}/tcp/47007"),
                "Mapped { via: Pcp, v6: false, port: 47007, tcp: true, udp: false }".into(),
            ]
        );
        let asked: Vec<u16> = gw
            .log()
            .iter()
            .filter(|r| r.proto.is_some())
            .map(|r| r.internal_port)
            .collect();
        assert!(
            !asked.is_empty() && asked.iter().all(|p| *p == 47007),
            "{asked:?}"
        );
        assert!(collect_until(&mut map, 1, |_| false).await.is_empty());
    }

    /// An expired listen address deletes its mapping: the external address
    /// expires, Lost(Released), and a lifetime-0 request reaches the router.
    #[tokio::test]
    async fn expired_listen_addr_deletes_its_mapping() {
        let gw = Gw::start(Ipv4Addr::LOCALHOST.into(), Mode::Pcp).unwrap();
        let (mut map, _log) = stub_map(lab_cfg(&gw));
        let id = ListenerId::next();
        let listen = ma("/ip4/127.0.0.1/udp/47008/quic-v1");
        new_listen(&mut map, id, &listen);
        let got = collect_until(&mut map, 10, |g| ends(g, "Mapped")).await;
        assert_eq!(got.len(), 2, "{got:?}");
        expired_listen(&mut map, id, &listen);
        let got = collect_until(&mut map, 5, |g| ends(g, "Lost")).await;
        assert_eq!(
            got,
            [
                format!("expired /ip4/{FAKE_EXTERNAL_V4}/udp/47008/quic-v1"),
                "Lost { via: Pcp, v6: false, why: Released, tcp: false, udp: true }".into(),
            ]
        );
        assert!(
            wait_for(5, || gw.deletes() == [(17, 47008)]).await,
            "{:?}",
            gw.deletes()
        );
        assert!(gw.fake.lock().unwrap().mappings.is_empty());
    }

    /// The pinhole: only the egress IPv6 address (loopback in this lab) is
    /// mapped, never a ULA, link-local or another global address, nor an
    /// IPv4 one through the IPv6 router; it follows listen-address events.
    #[tokio::test]
    async fn v6_pinhole_maps_only_the_egress_global_ipv6_and_follows_listen_events() {
        let Some(gw) = Gw::start(Ipv6Addr::LOCALHOST.into(), Mode::Ipv6Firewall) else {
            eprintln!("skipped: no IPv6 loopback");
            return;
        };
        let cfg = PortMapConfig {
            gw_v4: None,
            gw_v6: Some((Ipv6Addr::LOCALHOST, 0)),
            egress_v6: Some(Ipv6Addr::LOCALHOST),
            v6: true,
            ..lab_cfg(&gw)
        };
        let (mut map, log) = stub_map(cfg);
        let id = ListenerId::next();
        for a in [
            "/ip6/fd00::5/tcp/47009",
            "/ip6/fe80::1/udp/47009/quic-v1",
            "/ip6/2a00:1450::5/tcp/47009",
            "/ip4/127.0.0.1/tcp/47009",
            "/ip6/::1/tcp/47009",
        ] {
            new_listen(&mut map, id, &ma(a));
        }
        let got = collect_until(&mut map, 10, |g| ends(g, "Mapped")).await;
        assert_eq!(
            got,
            [
                "NoGateway { v6: false }",
                "confirmed /ip6/::1/tcp/47009",
                "Mapped { via: Pcp, v6: true, port: 47009, tcp: true, udp: false }",
            ]
        );
        // A later listen address of the egress IP is mapped too, and an
        // expired one is deleted.
        new_listen(&mut map, id, &ma("/ip6/::1/udp/47010/quic-v1"));
        let got = collect_until(&mut map, 10, |g| ends(g, "Mapped")).await;
        assert_eq!(got[0], "confirmed /ip6/::1/udp/47010/quic-v1");
        expired_listen(&mut map, id, &ma("/ip6/::1/tcp/47009"));
        let got = collect_until(&mut map, 5, |g| ends(g, "Lost")).await;
        assert_eq!(
            got,
            [
                "expired /ip6/::1/tcp/47009",
                "Lost { via: Pcp, v6: true, why: Released, tcp: true, udp: false }",
            ]
        );
        assert!(
            wait_for(5, || gw.deletes() == [(6, 47009)]).await,
            "{:?}",
            gw.deletes()
        );
        let asked: Vec<u16> = gw
            .log()
            .iter()
            .filter(|r| r.proto.is_some())
            .map(|r| r.internal_port)
            .collect();
        assert!(
            asked.iter().all(|p| *p == 47009 || *p == 47010),
            "{asked:?}"
        );
        assert!(gw
            .log()
            .iter()
            .all(|r| r.version == 2 && r.client_ip == Some(Ipv6Addr::LOCALHOST.into())));
        assert_eq!(log.made.load(Ordering::SeqCst), 0, "no UPnP for IPv6");
        // Review E-1 (owner decision O4-11): a pinhole asks 3600 s, not the
        // configured 7200 s of an IPv4 mapping.
        let leases = asked_lifetimes(&gw);
        assert!(
            !leases.is_empty()
                && leases
                    .iter()
                    .all(|l| *l == raven_core::portmap::PINHOLE_LIFETIME_S),
            "{leases:?}"
        );
        assert_eq!(raven_core::portmap::PINHOLE_LIFETIME_S, 3600);
    }

    /// Review E-1: a lab lease shorter than 3600 s is kept for a pinhole.
    #[tokio::test]
    async fn pinhole_lease_is_the_shorter_of_the_configured_and_3600_s() {
        let Some(gw) = Gw::start(Ipv6Addr::LOCALHOST.into(), Mode::Ipv6Firewall) else {
            eprintln!("skipped: no IPv6 loopback");
            return;
        };
        let cfg = PortMapConfig {
            gw_v4: None,
            gw_v6: Some((Ipv6Addr::LOCALHOST, 0)),
            egress_v6: Some(Ipv6Addr::LOCALHOST),
            v6: true,
            lifetime: 600,
            ..lab_cfg(&gw)
        };
        let (mut map, _log) = stub_map(cfg);
        new_listen(&mut map, ListenerId::next(), &ma("/ip6/::1/tcp/47011"));
        let got = collect_until(&mut map, 10, |g| ends(g, "Mapped")).await;
        assert!(ends(&got, "Mapped"), "{got:?}");
        let leases = asked_lifetimes(&gw);
        assert!(
            !leases.is_empty() && leases.iter().all(|l| *l == 600),
            "{leases:?}"
        );
    }

    /// Review E-2: while a harness names the router
    /// ([`PortMapConfig::upnp_fallback`] false) libp2p-upnp, whose SSDP
    /// search would reach the real network's router, is never created: not
    /// after a silent probe, and not with the gate closed.
    #[tokio::test]
    async fn a_named_lab_router_never_falls_back_to_upnp() {
        let gw = Gw::start(Ipv4Addr::LOCALHOST.into(), Mode::Silent).unwrap();
        let (mut map, log) = stub_map(PortMapConfig {
            upnp_fallback: false,
            ..lab_cfg(&gw)
        });
        let id = ListenerId::next();
        new_listen(&mut map, id, &ma("/ip4/127.0.0.1/tcp/47012"));
        let got = collect_until(&mut map, 8, |g| ends(g, "NoServer")).await;
        assert_eq!(got, ["NoServer { v6: false, upnp: false }"]);
        new_listen(&mut map, id, &ma("/ip4/127.0.0.1/udp/47012/quic-v1"));
        assert!(collect_until(&mut map, 1, |_| false).await.is_empty());
        assert_eq!(log.made.load(Ordering::SeqCst), 0, "UPnP after NoServer");
        assert!(map.upnp.is_none());
        assert!(gw.log().iter().all(|r| r.proto.is_none()));
        // The gate closed: no libp2p-upnp at once either, and nothing sent.
        let (mut closed, log) = stub_map(PortMapConfig {
            upnp_fallback: false,
            ..PortMapConfig::upnp_only()
        });
        new_listen(&mut closed, id, &ma("/ip4/192.168.1.20/tcp/47012"));
        assert!(collect_until(&mut closed, 1, |_| false).await.is_empty());
        assert_eq!(
            log.made.load(Ordering::SeqCst),
            0,
            "UPnP with the gate closed"
        );
        assert!(closed.upnp.is_none() && closed.v4.is_none() && closed.v6.is_none());
    }

    /// Dropping the behaviour (the endpoint goes away) deletes every
    /// mapping it holds, once, from the driver task.
    #[tokio::test]
    async fn drop_sends_deletes() {
        let gw = Gw::start(Ipv4Addr::LOCALHOST.into(), Mode::Pcp).unwrap();
        let (mut map, _log) = stub_map(lab_cfg(&gw));
        let id = ListenerId::next();
        new_listen(&mut map, id, &ma("/ip4/127.0.0.1/tcp/47011"));
        new_listen(&mut map, id, &ma("/ip4/127.0.0.1/udp/47011/quic-v1"));
        let got = collect_until(&mut map, 10, |g| g.len() == 4).await;
        assert_eq!(got.iter().filter(|l| l.starts_with("Mapped")).count(), 2);
        assert_eq!(gw.fake.lock().unwrap().mappings.len(), 2);
        assert!(gw.deletes().is_empty());
        drop(map);
        assert!(
            wait_for(5, || {
                let mut d = gw.deletes();
                d.sort();
                d == [(6, 47011), (17, 47011)]
            })
            .await,
            "{:?}",
            gw.deletes()
        );
        assert!(gw.fake.lock().unwrap().mappings.is_empty());
    }

    /// Review C-1: a full-tunnel VPN leaves the LAN router as the IPv4
    /// default router while the Internet egress is the tunnel. The source
    /// address toward the router (here 127.0.0.1) is then not the egress
    /// address (127.0.0.2, or unknown): no driver, no datagram to the
    /// router, no UPnP, and the egress-looking listen address is never
    /// mapped or confirmed.
    #[tokio::test]
    async fn a_router_off_the_internet_path_is_never_asked() {
        for egress_v4 in [Some(Ipv4Addr::new(127, 0, 0, 2)), None] {
            let gw = Gw::start(Ipv4Addr::LOCALHOST.into(), Mode::Pcp).unwrap();
            let cfg = PortMapConfig {
                egress_v4,
                ..lab_cfg(&gw)
            };
            let (mut map, log) = stub_map(cfg);
            assert!(map.v4.is_none(), "{egress_v4:?}");
            let id = ListenerId::next();
            new_listen(&mut map, id, &ma("/ip4/127.0.0.1/tcp/47012"));
            new_listen(&mut map, id, &ma("/ip4/127.0.0.1/udp/47012/quic-v1"));
            let got = collect_until(&mut map, 5, |_| false).await;
            assert_eq!(got, ["OffEgress"], "{egress_v4:?}");
            assert!(map.wanted.is_empty() && map.confirmed.is_empty());
            assert!(gw.log().is_empty(), "the router heard nothing");
            assert_eq!(log.made.load(Ordering::SeqCst), 0, "no UPnP");
            assert!(log.seen.lock().unwrap().is_empty());
        }
    }

    /// A public IPv4 router, or none: nothing to map and no UPnP.
    #[tokio::test]
    async fn no_or_public_router_reports_no_gateway() {
        for gw_v4 in [None, Some(Ipv4Addr::new(8, 8, 8, 8))] {
            let cfg = PortMapConfig {
                gw_v4,
                pcp: true,
                ..PortMapConfig::upnp_only()
            };
            let (mut map, log) = stub_map(cfg);
            let got = collect_until(&mut map, 1, |_| false).await;
            assert_eq!(got, ["NoGateway { v6: false }"]);
            assert_eq!(log.made.load(Ordering::SeqCst), 0);
        }
    }

    /// Debug output names no address and no key.
    #[test]
    fn config_debug_hides_addresses_and_key() {
        let cfg = PortMapConfig {
            gw_v4: Some(Ipv4Addr::new(192, 168, 1, 1)),
            egress_v6: Some("2a00:1450::5".parse().unwrap()),
            nonce_key: Zeroizing::new([0xAB; 32]),
            ..PortMapConfig::upnp_only()
        };
        let text = format!("{cfg:?}");
        assert!(!text.contains("192.168") && !text.contains("2a00") && !text.contains("171"));
        assert!(
            text.contains("<redacted>") && text.contains("found"),
            "{text}"
        );
    }

    #[test]
    fn external_multiaddr_keeps_quic_and_refuses_another_family() {
        let ext = SocketAddr::from((FAKE_EXTERNAL_V4, 40_001));
        assert_eq!(
            external_multiaddr(&ma("/ip4/10.0.0.2/udp/7423/quic-v1"), ext),
            Some(ma("/ip4/11.0.2.9/udp/40001/quic-v1"))
        );
        assert_eq!(external_multiaddr(&ma("/ip6/::1/tcp/7423"), ext), None);
    }
}
