//! Relays over WebSocket over TLS on TCP (RWS1,
//! `protocol/RAVEN_WSS_TRANSPORT_V1.md`), for networks that let only web
//! traffic out. A relay serves raw libp2p and WebSocket/TLS on the same port,
//! and a node behind such a network reaches it as
//! `/tcp/443/tls/ws/p2p/<relay>`, directly or through an HTTPS proxy (HTTP
//! CONNECT). The stack (RWS1 §3) is TCP, an optional CONNECT tunnel, TLS 1.3,
//! the WebSocket upgrade with binary messages, then libp2p's usual
//! multistream-select, Noise and Yamux: no new libp2p protocol and no Raven
//! frame change.
//!
//! [`tls`] is the TLS layer (§4) and [`ws`] the WebSocket subset (§5): the
//! upgrade and the byte stream over binary messages, on raven-core's frame
//! codec (`raven_core::ws_frame`). [`connect`] is the HTTP CONNECT client
//! (§7), and [`demux`] the first-byte check of the two-protocol listener
//! (§6).
//!
//! [`Transport`] is the libp2p transport over libp2p's own TCP transport:
//! - **Dial** (a [`ClientSide`] only, as the dialer only: no hole punching
//!   over WSS): `/ip4|ip6|dns*/<h>/tcp/<p>/tls[/sni/<n>]/ws[/p2p/<id>]`.
//!   Through the proxy [`ProxyLookup`] names for the host (an IP host with
//!   a `/sni/` name goes direct when either bypasses it), or straight to an
//!   IP host; a `/dns*` host with no proxy is not dialled, because
//!   raven-node resolves names first and behind a proxy the proxy resolves
//!   them (the name is never resolved here). SNI is the `/dns*` or `/sni/`
//!   name, none for an IP; the WebSocket Host is that name or the IP
//!   literal (IPv6 in brackets), with `:port` when the port is not 443.
//! - **Listen** (a [`ServerSide`] only): `/ip4|ip6/<h>/tcp/<p>/tls/ws`, with
//!   no `/sni/` and no `/p2p/`. The port is a two-protocol port (§6): each
//!   listen address is reported as `…/tls/ws` and then plain, and each new
//!   connection is split by its first byte, peeked within [`DEMUX_WAIT`]:
//!   TLS then the WebSocket upgrade, raw libp2p, or closed with no reply.
//!   An inbound connection is labelled `…/tls/ws` either way; the IP is
//!   what the per-IP limits read.
//! - [`client_transport`] and [`server_transport`] add multistream-select
//!   (V1Lazy), libp2p Noise and Yamux, as libp2p's TCP transport gets. The
//!   swarm's connection timeout (10 s) bounds the whole dial and the whole
//!   inbound upgrade: the CONNECT tunnel, TLS and the WebSocket upgrade have
//!   no timeout of their own.
//!
//! Compiled into raven-node only (feature `wss`), which uses it only while
//! `raven_core::wss_live_enabled()` holds: WSS_PRODUCTION_ENABLED is false,
//! so only a debug build with the lab unlock gets that far.

pub mod connect;
pub mod tls;
pub mod ws;

#[cfg(test)]
mod transport_tests;

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use futures::future::BoxFuture;
use futures::io::{AsyncRead, AsyncWrite};
use futures::{FutureExt as _, TryFutureExt as _};
use futures_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::{
    Boxed, DialOpts, ListenerId, PortUse, TransportError, TransportEvent,
};
use libp2p::core::upgrade::Version;
use libp2p::core::{Endpoint, Transport as _};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::tcp::tokio::TcpStream;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};

use connect::Tunnel;
pub use connect::{ProxyEndpoint, ProxyError};

/// What a relay's two-protocol listener (RWS1 §6) does with a new
/// connection, by the first byte the client sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Demux {
    /// 0x16, a TLS handshake record: TLS (§4), then the WebSocket upgrade
    /// (§5).
    Tls,
    /// 0x13, the varint 19 before `/multistream/1.0.0\n`: raw libp2p,
    /// untouched, as on a raw TCP listener.
    Raw,
    /// Anything else, or nothing (within the wait, or before the connection
    /// ended): closed with no reply.
    Refused,
}

/// [`Demux`] for the bytes peeked at the start of a connection; only the
/// first one counts.
pub fn demux(first: &[u8]) -> Demux {
    match first.first() {
        Some(0x16) => Demux::Tls,
        Some(0x13) => Demux::Raw,
        _ => Demux::Refused,
    }
}

/// How long the two-protocol listener waits for a new connection's first
/// byte (RWS1 §6) before it closes the connection.
pub const DEMUX_WAIT: Duration = Duration::from_secs(10);

/// Most links of an error chain [`proxy_error_in`] follows.
const ERROR_CHAIN_MAX: usize = 32;

/// The host of a WSS address: an IP address, or a `/dns*` name that only a
/// proxy resolves.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

/// Which proxy, if any, a WSS dial goes through (raven-node's proxy
/// settings and bypass list, RWS1 §8). It answers `None` while the proxy
/// gate (`raven_core::wss_proxy_live_enabled`) is closed; raw TCP and QUIC
/// never ask it.
pub trait ProxyLookup: Send + Sync + 'static {
    /// The proxy for a dial of `host` at `port`, or `None` to dial directly.
    fn proxy_for(&self, host: &Host, port: u16) -> Option<ProxyEndpoint>;
}

/// What a WSS dial needs: the TLS client config ([`tls::client_tls`]) and,
/// when a proxy may be in the way, the lookup that names it.
#[derive(Clone)]
pub struct ClientSide {
    pub tls: Arc<ClientConfig>,
    pub proxy: Option<Arc<dyn ProxyLookup>>,
}

impl fmt::Debug for ClientSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSide")
            .field("proxy", &self.proxy.is_some())
            .finish_non_exhaustive()
    }
}

/// What a relay's two-protocol listener needs: the TLS server config
/// ([`tls::ephemeral_server_tls`] or [`tls::operator_server_tls`]).
#[derive(Clone)]
pub struct ServerSide {
    pub tls: Arc<ServerConfig>,
}

impl fmt::Debug for ServerSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSide").finish_non_exhaustive()
    }
}

/// A connection the transport made or took: raw libp2p from a
/// two-protocol listener, or WebSocket messages over TLS (over a CONNECT
/// tunnel when proxied). libp2p's upgrades run on it either way.
pub enum WssStream {
    Raw(TcpStream),
    Ws(Box<ws::WsStream<TlsStream<Tunnel>>>),
}

impl fmt::Debug for WssStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WssStream::Raw(_) => "WssStream::Raw",
            WssStream::Ws(_) => "WssStream::Ws",
        })
    }
}

impl AsyncRead for WssStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            WssStream::Raw(s) => Pin::new(s).poll_read(cx, buf),
            WssStream::Ws(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WssStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            WssStream::Raw(s) => Pin::new(s).poll_write(cx, buf),
            WssStream::Ws(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WssStream::Raw(s) => Pin::new(s).poll_flush(cx),
            WssStream::Ws(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WssStream::Raw(s) => Pin::new(s).poll_close(cx),
            WssStream::Ws(s) => Pin::new(s).poll_close(cx),
        }
    }
}

/// A WSS dial address, taken apart (RWS1 §2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    host: Host,
    port: u16,
    /// The `/sni/` name after an IP host.
    sni: Option<String>,
}

impl Target {
    /// `/ip4|ip6|dns|dns4|dns6/<h>/tcp/<p>/tls[/sni/<n>]/ws[/p2p/<id>]`:
    /// port not 0, an IP host not unspecified, a `/dns*` or `/sni/` name a
    /// DNS name (not an IP literal), `/sni/` only after an IP host, `/ws`
    /// of `/` only. Anything else is not a WSS dial address.
    fn parse(addr: &Multiaddr) -> Option<Self> {
        let mut it = addr.iter();
        let host = match it.next()? {
            Protocol::Ip4(ip) => Host::Ip(ip.into()),
            Protocol::Ip6(ip) => Host::Ip(ip.into()),
            Protocol::Dns(n) | Protocol::Dns4(n) | Protocol::Dns6(n) if is_dns_name(&n) => {
                Host::Name(n.into_owned())
            }
            _ => return None,
        };
        let Protocol::Tcp(port) = it.next()? else {
            return None;
        };
        if port == 0 || matches!(host, Host::Ip(ip) if ip.is_unspecified()) {
            return None;
        }
        if it.next()? != Protocol::Tls {
            return None;
        }
        let mut sni = None;
        let mut next = it.next()?;
        if let Protocol::Sni(name) = &next {
            if !matches!(host, Host::Ip(_)) || !is_dns_name(name) {
                return None;
            }
            sni = Some(name.to_string());
            next = it.next()?;
        }
        if !is_ws_root(&next) {
            return None;
        }
        match (it.next(), it.next()) {
            (None, _) | (Some(Protocol::P2p(_)), None) => Some(Target { host, port, sni }),
            _ => None,
        }
    }

    /// The SNI name, or the IP itself (for which TLS sends no SNI).
    fn server_name(&self) -> Option<ServerName<'static>> {
        match (&self.sni, &self.host) {
            (Some(name), _) | (None, Host::Name(name)) => ServerName::try_from(name.clone()).ok(),
            (None, Host::Ip(ip)) => Some(ServerName::IpAddress((*ip).into())),
        }
    }

    /// The proxy this dial goes through ([`ProxyLookup::proxy_for`] of its
    /// host). An IP host with a `/sni/` name goes direct when either the
    /// IP or the name bypasses the proxy: raven-node resolves a `/dns*` WSS
    /// form into that shape only when its name bypasses the proxy, so a
    /// bypass entry for the name (`NO_PROXY=.corp.example`, `*.local`,
    /// `<local>`) still holds once the host is an IP.
    fn proxy(&self, lookup: &dyn ProxyLookup) -> Option<ProxyEndpoint> {
        let proxy = lookup.proxy_for(&self.host, self.port)?;
        match (&self.sni, &self.host) {
            (Some(name), Host::Ip(_)) => lookup
                .proxy_for(&Host::Name(name.clone()), self.port)
                .map(|_| proxy),
            _ => Some(proxy),
        }
    }

    /// The CONNECT target (RWS1 §7): `name:port`, `a.b.c.d:port` or
    /// `[v6]:port`.
    fn authority(&self) -> String {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
            Host::Ip(ip) => format!("{ip}:{}", self.port),
            Host::Name(name) => format!("{name}:{}", self.port),
        }
    }

    /// The WebSocket Host value (RWS1 §5.1): the SNI name or the IP literal
    /// (IPv6 in brackets), with `:port` when the port is not 443.
    fn host_header(&self) -> String {
        let name = match (&self.sni, &self.host) {
            (Some(name), _) | (None, Host::Name(name)) => name.clone(),
            (None, Host::Ip(IpAddr::V6(ip))) => format!("[{ip}]"),
            (None, Host::Ip(ip)) => ip.to_string(),
        };
        if self.port == 443 {
            name
        } else {
            format!("{name}:{}", self.port)
        }
    }
}

/// A DNS name as TLS sends it in SNI; an IP literal is not one.
fn is_dns_name(name: &str) -> bool {
    matches!(ServerName::try_from(name), Ok(ServerName::DnsName(_)))
}

fn is_ws_root(p: &Protocol<'_>) -> bool {
    matches!(p, Protocol::Ws(path) if path == "/")
}

/// The TCP address a WSS listen address names: `/ip4|ip6/<h>/tcp/<p>/tls/ws`
/// only, with no `/sni/` and no `/p2p/`.
fn listen_tcp_addr(addr: &Multiaddr) -> Option<Multiaddr> {
    let mut it = addr.iter();
    let ip = match it.next()? {
        p @ (Protocol::Ip4(_) | Protocol::Ip6(_)) => p,
        _ => return None,
    };
    let Protocol::Tcp(port) = it.next()? else {
        return None;
    };
    if it.next()? != Protocol::Tls || !is_ws_root(&it.next()?) || it.next().is_some() {
        return None;
    }
    Some(Multiaddr::empty().with(ip).with(Protocol::Tcp(port)))
}

/// `addr/tls/ws`.
fn with_tls_ws(addr: Multiaddr) -> Multiaddr {
    addr.with(Protocol::Tls).with(Protocol::Ws("/".into()))
}

/// A dial or an inbound connection on its way to a [`WssStream`].
type Upgrade = BoxFuture<'static, io::Result<WssStream>>;

/// The WSS transport (module docs): dials with a [`ClientSide`], listens
/// with a [`ServerSide`], over libp2p's TCP transport.
pub struct Transport {
    tcp: tcp::tokio::Transport,
    client: Option<ClientSide>,
    server: Option<ServerSide>,
    /// The plain form of a listen address just reported as `…/tls/ws`.
    pending: VecDeque<TransportEvent<Upgrade, io::Error>>,
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("client", &self.client)
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// An endpoint's transport: it dials and never listens.
    pub fn client(client: ClientSide) -> Self {
        Self::new(Some(client), None)
    }

    /// A relay's transport: it listens and never dials.
    pub fn server(server: ServerSide) -> Self {
        Self::new(None, Some(server))
    }

    fn new(client: Option<ClientSide>, server: Option<ServerSide>) -> Self {
        Transport {
            tcp: tcp::tokio::Transport::new(tcp::Config::default().nodelay(true)),
            client,
            server,
            pending: VecDeque::new(),
        }
    }
}

impl libp2p::core::Transport for Transport {
    type Output = WssStream;
    type Error = io::Error;
    type ListenerUpgrade = Upgrade;
    type Dial = Upgrade;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<io::Error>> {
        if self.server.is_none() {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        let Some(inner) = listen_tcp_addr(&addr) else {
            return Err(TransportError::MultiaddrNotSupported(addr));
        };
        self.tcp.listen_on(id, inner).map_err(|e| match e {
            TransportError::MultiaddrNotSupported(_) => TransportError::MultiaddrNotSupported(addr),
            other => other,
        })
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.tcp.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<io::Error>> {
        // Relays never dial over WSS, and nobody hole-punches over it.
        let Some(client) = &self.client else {
            return Err(TransportError::MultiaddrNotSupported(addr));
        };
        if opts.role != Endpoint::Dialer {
            return Err(TransportError::MultiaddrNotSupported(addr));
        }
        let Some((target, name)) =
            Target::parse(&addr).and_then(|t| t.server_name().map(|name| (t, name)))
        else {
            return Err(TransportError::MultiaddrNotSupported(addr));
        };
        let proxy = client.proxy.as_ref().and_then(|p| target.proxy(p.as_ref()));
        let tunnel: BoxFuture<'static, io::Result<Tunnel>> = match (proxy, &target.host) {
            // CONNECT name:port: the proxy resolves the name.
            (Some(proxy), _) => connect::tunnel(proxy, target.authority())
                .map_err(surface_proxy_error)
                .boxed(),
            (None, Host::Ip(ip)) => {
                let tcp_addr = Multiaddr::empty()
                    .with(Protocol::from(*ip))
                    .with(Protocol::Tcp(target.port));
                let opts = DialOpts {
                    role: Endpoint::Dialer,
                    port_use: PortUse::New,
                };
                match self.tcp.dial(tcp_addr, opts) {
                    Ok(dial) => dial.map_ok(Tunnel::direct).boxed(),
                    Err(TransportError::MultiaddrNotSupported(_)) => {
                        return Err(TransportError::MultiaddrNotSupported(addr))
                    }
                    Err(other) => return Err(other),
                }
            }
            // raven-node resolves names before it dials (no libp2p-dns).
            (None, Host::Name(_)) => return Err(TransportError::MultiaddrNotSupported(addr)),
        };
        let tls = TlsConnector::from(client.tls.clone());
        let host = target.host_header();
        Ok(async move {
            let stream = tls.connect(name, tunnel.await?).await?;
            let ws = ws::client(TlsStream::from(stream), &host).await?;
            Ok(WssStream::Ws(Box::new(ws)))
        }
        .boxed())
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, io::Error>> {
        let this = self.get_mut();
        if let Some(event) = this.pending.pop_front() {
            return Poll::Ready(event);
        }
        let event = match ready!(Pin::new(&mut this.tcp).poll(cx)) {
            // The port takes raw libp2p too (RWS1 §6): the plain address
            // comes right after the `…/tls/ws` one.
            TransportEvent::NewAddress {
                listener_id,
                listen_addr,
            } => {
                this.pending.push_back(TransportEvent::NewAddress {
                    listener_id,
                    listen_addr: listen_addr.clone(),
                });
                TransportEvent::NewAddress {
                    listener_id,
                    listen_addr: with_tls_ws(listen_addr),
                }
            }
            TransportEvent::AddressExpired {
                listener_id,
                listen_addr,
            } => {
                this.pending.push_back(TransportEvent::AddressExpired {
                    listener_id,
                    listen_addr: listen_addr.clone(),
                });
                TransportEvent::AddressExpired {
                    listener_id,
                    listen_addr: with_tls_ws(listen_addr),
                }
            }
            TransportEvent::Incoming {
                listener_id,
                upgrade,
                local_addr,
                send_back_addr,
            } => TransportEvent::Incoming {
                listener_id,
                upgrade: accept(upgrade, this.server.as_ref().map(|s| s.tls.clone())).boxed(),
                local_addr: with_tls_ws(local_addr),
                send_back_addr: with_tls_ws(send_back_addr),
            },
            TransportEvent::ListenerClosed {
                listener_id,
                reason,
            } => TransportEvent::ListenerClosed {
                listener_id,
                reason,
            },
            TransportEvent::ListenerError { listener_id, error } => {
                TransportEvent::ListenerError { listener_id, error }
            }
        };
        Poll::Ready(event)
    }
}

/// A new connection on a two-protocol listener (RWS1 §6): its first byte,
/// peeked within [`DEMUX_WAIT`] and left in place, picks TLS then the
/// WebSocket upgrade or raw libp2p; anything else, nothing, or the
/// connection ending first closes it with no reply.
async fn accept(
    upgrade: impl Future<Output = io::Result<TcpStream>>,
    tls: Option<Arc<ServerConfig>>,
) -> io::Result<WssStream> {
    let tcp = upgrade.await?;
    let tls = tls.ok_or_else(|| io::Error::other("wss: no server side"))?;
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(DEMUX_WAIT, tcp.0.peek(&mut first))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "wss: no first byte"))??;
    match demux(&first[..n]) {
        Demux::Tls => {
            let stream = TlsAcceptor::from(tls).accept(Tunnel::direct(tcp)).await?;
            let ws = ws::server(TlsStream::from(stream)).await?;
            Ok(WssStream::Ws(Box::new(ws)))
        }
        Demux::Raw => Ok(WssStream::Raw(tcp)),
        Demux::Refused => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wss: neither TLS nor libp2p",
        )),
    }
}

/// An endpoint's WSS transport with libp2p's upgrades: multistream-select
/// (V1Lazy), Noise with `key`, Yamux. Boxed, so that
/// `OptionalTransport<Boxed<…>>` names one type with or without it.
pub fn client_transport(
    key: &Keypair,
    client: ClientSide,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, noise::Error> {
    upgraded(Transport::client(client), key)
}

/// A relay's two-protocol listener with libp2p's upgrades, as
/// [`client_transport`].
pub fn server_transport(
    key: &Keypair,
    server: ServerSide,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, noise::Error> {
    upgraded(Transport::server(server), key)
}

fn upgraded(
    transport: Transport,
    key: &Keypair,
) -> Result<Boxed<(PeerId, StreamMuxerBox)>, noise::Error> {
    Ok(transport
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(key)?)
        .multiplex(yamux::Config::default())
        .map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
        .boxed())
}

/// A proxy's refusal as a dial error: the same kind and fixed text, with
/// the [`ProxyError`] as the source. libp2p's transport combinators wrap a
/// dial error in `Either`s whose `source()` is the inner error's own
/// source (it skips the inner error, and an `io::Error`'s `source()` skips
/// its payload too), so only a `source()` of the payload survives them.
#[derive(Debug)]
struct ProxyFailed(ProxyError);

impl fmt::Display for ProxyFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for ProxyFailed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

fn surface_proxy_error(e: io::Error) -> io::Error {
    match connect::proxy_error(&e) {
        Some(p) => io::Error::new(e.kind(), ProxyFailed(p.clone())),
        None => e,
    }
}

/// The [`ProxyError`] of a failed proxied dial, wherever the swarm's
/// transport layers put it in the error's chain (an `io::Error` is followed
/// into the error it wraps, anything else to its source).
pub fn proxy_error_in<'a>(e: &'a (dyn Error + 'static)) -> Option<&'a ProxyError> {
    let mut next = Some(e);
    for _ in 0..ERROR_CHAIN_MAX {
        let e = next?;
        if let Some(p) = e.downcast_ref::<ProxyError>() {
            return Some(p);
        }
        next = match e.downcast_ref::<io::Error>() {
            Some(io) => io.get_ref().map(|inner| inner as &(dyn Error + 'static)),
            None => e.source(),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `shared-vectors/rvn1/wss/rws1_demux_001.json`: 0x16 is TLS, 0x13 raw
    /// libp2p; plain HTTP, other TLS records, SOCKS, 0x00 and nothing are
    /// refused.
    #[test]
    fn demux_vectors_decode_as_tls_raw_or_refused() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/wss/rws1_demux_001.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let cases = v["expected"]["cases"].as_array().unwrap();
        let mut seen = std::collections::HashSet::new();
        for case in cases {
            let first = hex::decode(case["first_hex"].as_str().unwrap()).unwrap();
            let want = match case["outcome"].as_str().unwrap() {
                "tls" => Demux::Tls,
                "raw" => Demux::Raw,
                "refused" => Demux::Refused,
                other => panic!("unknown outcome {other}"),
            };
            assert_eq!(demux(&first), want, "{}", case["why"]);
            seen.insert((want, first.len()));
        }
        assert!(seen.contains(&(Demux::Tls, 1)) && seen.contains(&(Demux::Raw, 1)));
        assert!(seen.contains(&(Demux::Refused, 0)));
        assert_eq!(demux(&[0x16, 0x13]), Demux::Tls);
        assert_eq!(demux(b"\x13/multistream/1.0.0\n"), Demux::Raw);
        assert_eq!(demux(b"GET / HTTP/1.1\r\n"), Demux::Refused);
    }

    const PEER: &str = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";

    fn target(addr: &str) -> Option<Target> {
        Target::parse(&addr.parse().unwrap())
    }

    /// The WSS dial forms of RWS1 §2.1 and what each sends: SNI, the
    /// CONNECT target and the WebSocket Host value.
    #[test]
    fn wss_dial_addresses_name_sni_connect_target_and_host() {
        let cases = [
            (
                "/dns/relay.example.org/tcp/443/tls/ws",
                Some("relay.example.org"),
                "relay.example.org:443",
                "relay.example.org",
            ),
            (
                "/dns4/relay.example.org/tcp/8443/tls/ws/p2p/PEER",
                Some("relay.example.org"),
                "relay.example.org:8443",
                "relay.example.org:8443",
            ),
            (
                "/ip4/203.0.113.7/tcp/8443/tls/ws",
                None,
                "203.0.113.7:8443",
                "203.0.113.7:8443",
            ),
            (
                "/ip6/2001:db8::7/tcp/443/tls/ws/p2p/PEER",
                None,
                "[2001:db8::7]:443",
                "[2001:db8::7]",
            ),
            (
                "/ip4/203.0.113.7/tcp/443/tls/sni/relay.example.org/ws",
                Some("relay.example.org"),
                "203.0.113.7:443",
                "relay.example.org",
            ),
            (
                "/ip6/2001:db8::7/tcp/8443/tls/sni/relay.example.org/ws/p2p/PEER",
                Some("relay.example.org"),
                "[2001:db8::7]:8443",
                "relay.example.org:8443",
            ),
        ];
        for (addr, sni, authority, host) in cases {
            let addr = addr.replace("PEER", PEER);
            let t = target(&addr).unwrap_or_else(|| panic!("{addr} refused"));
            let name = t.server_name().unwrap();
            match sni {
                Some(sni) => assert_eq!(name, ServerName::try_from(sni).unwrap(), "{addr}"),
                None => assert!(matches!(name, ServerName::IpAddress(_)), "{addr}"),
            }
            assert_eq!(t.authority(), authority, "{addr}");
            assert_eq!(t.host_header(), host, "{addr}");
        }
    }

    /// The three Host values of `rws1_ws_handshake_001.json`, from the
    /// addresses they belong to.
    #[test]
    fn host_values_match_the_handshake_vector() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/wss/rws1_ws_handshake_001.json");
        let raw = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let hosts: Vec<&str> = v["expected"]["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["host"].as_str().unwrap())
            .collect();
        let from: Vec<String> = [
            "/dns/relay.example.org/tcp/443/tls/ws",
            "/ip4/203.0.113.7/tcp/8443/tls/ws",
            "/ip6/2001:db8::7/tcp/443/tls/ws",
        ]
        .iter()
        .map(|a| target(a).unwrap().host_header())
        .collect();
        assert_eq!(from, hosts);
    }

    /// Review A-5: every `/dns*` and `/sni/` name raven-core's via grammar
    /// takes is one TLS can send as SNI, so no stored WSS via is undialable;
    /// the names rustls refuses are refused there too.
    #[test]
    fn via_names_are_tls_server_names() {
        let long = format!("{}.example.org", "a".repeat(63));
        let too_long = format!("{}.example.org", "a".repeat(64));
        let names = [
            "relay.example.org",
            "relay.example.org.",
            "r-1.example.org",
            "1relay.2example.org",
            "localhost",
            long.as_str(),
            too_long.as_str(),
            "203.0.113.7",
            "relay-.example.org",
            "-relay.example.org",
            "relay.-x.org",
            "relay.123",
            "relay.123.",
            "relay..example.org",
            ".relay.example.org",
            ".",
            "relay_1.example.org",
        ];
        let mut accepted = 0;
        for name in names {
            let dns = raven_core::p2p_route::parse_via(&format!(
                "/dns4/{name}/tcp/443/tls/ws/p2p/{PEER}"
            ));
            let sni = raven_core::p2p_route::parse_via(&format!(
                "/ip4/203.0.113.7/tcp/443/tls/sni/{name}/ws/p2p/{PEER}"
            ));
            assert_eq!(dns.is_ok(), sni.is_ok(), "{name}");
            if let Ok(via) = dns {
                accepted += 1;
                assert!(is_dns_name(name), "{name}");
                let addr: Multiaddr = via.text.parse().unwrap();
                assert!(Target::parse(&addr).is_some(), "{name}");
            } else {
                assert!(name.contains('_') || !is_dns_name(name), "{name}");
            }
        }
        assert_eq!(accepted, 6);
    }

    #[test]
    fn only_wss_forms_are_wss_dial_addresses() {
        for addr in [
            "/ip4/203.0.113.7/tcp/443",
            "/ip4/203.0.113.7/tcp/443/ws",
            "/ip4/203.0.113.7/tcp/443/wss",
            "/ip4/203.0.113.7/tcp/443/tls",
            "/ip4/203.0.113.7/tcp/443/tls/x-parity-ws/%2Fx",
            "/ip4/203.0.113.7/tcp/0/tls/ws",
            "/ip4/0.0.0.0/tcp/443/tls/ws",
            "/ip6/::/tcp/443/tls/ws",
            "/ip4/203.0.113.7/udp/443/quic-v1",
            "/ip4/203.0.113.7/tcp/443/tls/ws/p2p/PEER/p2p-circuit",
            "/ip4/203.0.113.7/tcp/443/tls/ws/p2p/PEER/p2p/PEER",
            "/ip4/203.0.113.7/tcp/443/tls/ws/p2p-circuit",
            "/dns/relay.example.org/tcp/443/tls/sni/relay.example.org/ws",
            "/ip4/203.0.113.7/tcp/443/tls/sni/198.51.100.1/ws",
            "/dns/198.51.100.1/tcp/443/tls/ws",
            "/dns/relay..example/tcp/443/tls/ws",
            "/tcp/443/tls/ws",
            "/ip4/203.0.113.7/tls/ws",
        ] {
            let addr = addr.replace("PEER", PEER);
            assert_eq!(target(&addr), None, "{addr}");
        }
    }

    #[test]
    fn only_ip_tls_ws_forms_are_listen_addresses() {
        let listen = |a: &str| listen_tcp_addr(&a.parse().unwrap()).map(|m| m.to_string());
        assert_eq!(
            listen("/ip4/0.0.0.0/tcp/443/tls/ws").as_deref(),
            Some("/ip4/0.0.0.0/tcp/443")
        );
        assert_eq!(
            listen("/ip6/::1/tcp/0/tls/ws").as_deref(),
            Some("/ip6/::1/tcp/0")
        );
        for addr in [
            "/ip4/0.0.0.0/tcp/443",
            "/ip4/0.0.0.0/tcp/443/ws",
            "/ip4/0.0.0.0/tcp/443/tls/sni/relay.example.org/ws",
            "/ip4/0.0.0.0/tcp/443/tls/ws/p2p/PEER",
            "/dns/relay.example.org/tcp/443/tls/ws",
            "/ip4/0.0.0.0/udp/443/quic-v1",
        ] {
            let addr = addr.replace("PEER", PEER);
            assert_eq!(listen(&addr), None, "{addr}");
        }
    }

    /// The chain walk finds a ProxyError behind io::Error and source()
    /// links, and nothing in an unrelated error.
    #[test]
    fn proxy_error_is_found_through_wrapping_errors() {
        #[derive(Debug)]
        struct Outer(io::Error);
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("outer")
            }
        }
        impl Error for Outer {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(&self.0)
            }
        }
        let auth = ProxyError::Auth {
            schemes: vec!["Negotiate"],
            sent_basic: false,
        };
        let inner = io::Error::new(io::ErrorKind::PermissionDenied, auth.clone());
        let wrapped = io::Error::other(Outer(inner));
        assert_eq!(proxy_error_in(&wrapped), Some(&auth));
        assert!(proxy_error_in(&wrapped).is_some_and(ProxyError::unsupported_auth));

        // libp2p's `Either` is transparent: its source() is the inner
        // error's source(). Only the surfaced form survives it.
        #[derive(Debug)]
        struct Transparent(io::Error);
        impl fmt::Display for Transparent {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl Error for Transparent {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                self.0.source()
            }
        }
        let raw = || io::Error::new(io::ErrorKind::PermissionDenied, auth.clone());
        let surfaced = surface_proxy_error(raw());
        assert_eq!(surfaced.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(surfaced.to_string(), auth.to_string());
        assert_eq!(proxy_error_in(&surfaced), Some(&auth));
        let through = io::Error::other(Outer(io::Error::other(Transparent(surfaced))));
        assert_eq!(proxy_error_in(&through), Some(&auth));
        let lost = io::Error::other(Outer(io::Error::other(Transparent(raw()))));
        assert_eq!(proxy_error_in(&lost), None);
        // Anything else passes through as it is.
        assert_eq!(
            surface_proxy_error(io::Error::from(io::ErrorKind::TimedOut)).kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(proxy_error_in(&io::Error::other("plain")), None);
        assert_eq!(
            proxy_error_in(&io::Error::from(io::ErrorKind::TimedOut)),
            None
        );
    }
}
