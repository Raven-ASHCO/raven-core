//! The WSS transport on loopback (RWS1 §3, §6, §7). Small swarms are built
//! the way `host.rs` builds its hosts: TCP, QUIC, then the WSS transport as
//! the "other" transport inside an `OptionalTransport`, then the relay
//! client. A relay serves a two-protocol listener, an endpoint without WSS
//! stands in for an older peer, and an in-test HTTP CONNECT proxy records
//! what a proxy sees.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use futures::{AsyncReadExt as _, AsyncWriteExt as _, StreamExt as _};
use libp2p::core::transport::OptionalTransport;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::{DialError, NetworkBehaviour, SwarmEvent};
use libp2p::{relay, Swarm, SwarmBuilder};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::connect::connect_request;
use super::*;
use crate::host::RAVEN_LINK_PROTOCOL;

const RELAY_SEED: u8 = 0x51;
const A_SEED: u8 = 0xA1;
const B_SEED: u8 = 0xB1;
const C_SEED: u8 = 0xC1;

/// The connection timeout of every swarm here, as the product's hosts use.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a test may make no progress before it fails instead of
/// hanging: everything runs on loopback and normally takes well under a
/// second, so this bounds a regression, not a product timing.
const STALL: Duration = Duration::from_secs(60);

const DIALER: DialOpts = DialOpts {
    role: Endpoint::Dialer,
    port_use: PortUse::New,
};

/// Raven's own frame tags and libp2p's protocol names, as a Raven link
/// would carry them: a proxy must never see any of them in the clear.
const MARKERS: &[&[u8]] = &[
    b"RVPI1\0",
    b"RLB1\0",
    b"RIH1\0",
    b"/multistream",
    b"/noise",
    b"/yamux",
    b"/libp2p/circuit",
    b"/raven/link",
];

#[derive(NetworkBehaviour)]
struct RelayNode {
    relay: relay::Behaviour,
}

#[derive(NetworkBehaviour)]
struct Node {
    relay_client: relay::client::Behaviour,
    stream: libp2p_stream::Behaviour,
}

fn key(seed: u8) -> Keypair {
    Keypair::ed25519_from_bytes([seed; 32]).unwrap()
}

fn peer(seed: u8) -> PeerId {
    key(seed).public().to_peer_id()
}

fn server_side() -> ServerSide {
    ServerSide {
        tls: tls::ephemeral_server_tls(&[]).unwrap(),
    }
}

fn client_side(proxy: Option<Arc<dyn ProxyLookup>>) -> ClientSide {
    ClientSide {
        tls: tls::client_tls(),
        proxy,
    }
}

/// A relay with the WSS server transport when `wss` is given (P4.11 wires
/// the same into `build_relay_swarm`).
fn relay_node(wss: Option<ServerSide>) -> Swarm<RelayNode> {
    SwarmBuilder::with_existing_identity(key(RELAY_SEED))
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_quic()
        .with_other_transport(|key| -> Result<_, Box<dyn Error + Send + Sync>> {
            Ok(match wss {
                Some(s) => OptionalTransport::some(server_transport(key, s)?),
                None => OptionalTransport::none(),
            })
        })
        .unwrap()
        .with_behaviour(|key| RelayNode {
            relay: relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default()),
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .with_connection_timeout(CONNECTION_TIMEOUT)
        .build()
}

/// An endpoint with the WSS client transport when `wss` is given (P4.11
/// wires the same into `build_endpoint_swarm`); without it, an endpoint as
/// an older version builds it.
fn node_with(seed: u8, wss: Option<ClientSide>, timeout: Duration) -> Swarm<Node> {
    SwarmBuilder::with_existing_identity(key(seed))
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_quic()
        .with_other_transport(|key| -> Result<_, Box<dyn Error + Send + Sync>> {
            Ok(match wss {
                Some(c) => OptionalTransport::some(client_transport(key, c)?),
                None => OptionalTransport::none(),
            })
        })
        .unwrap()
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .unwrap()
        .with_behaviour(|_, relay_client| Node {
            relay_client,
            stream: libp2p_stream::Behaviour::new(),
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .with_connection_timeout(timeout)
        .build()
}

fn node(seed: u8, wss: Option<ClientSide>) -> Swarm<Node> {
    node_with(seed, wss, CONNECTION_TIMEOUT)
}

/// A relay on loopback and what it saw.
struct Lab {
    relay: Swarm<RelayNode>,
    port: u16,
    /// `/ip4/127.0.0.1/tcp/<port>/p2p/<relay>`.
    raw_addr: Multiaddr,
    /// `/ip4/127.0.0.1/tcp/<port>/tls/ws/p2p/<relay>`.
    wss_addr: Multiaddr,
    seen: Vec<SwarmEvent<RelayNodeEvent>>,
}

impl Lab {
    /// With `wss`, the relay listens on `/ip4/127.0.0.1/tcp/0/tls/ws`, which
    /// must report the `/tls/ws` address and then the plain one; without
    /// it, it is an older relay with a raw TCP listener only. Its external
    /// address is the raw one, as a relay's is (RWS1 §2.2).
    async fn new(wss: bool) -> Lab {
        let (mut relay, at, count) = if wss {
            (
                relay_node(Some(server_side())),
                "/ip4/127.0.0.1/tcp/0/tls/ws",
                2,
            )
        } else {
            (relay_node(None), "/ip4/127.0.0.1/tcp/0", 1)
        };
        relay.listen_on(at.parse().unwrap()).unwrap();
        let mut addrs = Vec::new();
        tokio::time::timeout(STALL, async {
            while addrs.len() < count {
                if let SwarmEvent::NewListenAddr { address, .. } = relay.select_next_some().await {
                    addrs.push(address);
                }
            }
        })
        .await
        .expect("the relay never listened");
        let raw = addrs.last().unwrap().clone();
        let Some(Protocol::Tcp(port)) = raw.iter().nth(1) else {
            panic!("not a TCP address: {raw}");
        };
        if wss {
            assert_eq!(
                addrs,
                [with_tls_ws(raw.clone()), raw.clone()],
                "the /tls/ws address first, then the plain one"
            );
        }
        relay.add_external_address(raw.clone());
        let id = Protocol::P2p(*relay.local_peer_id());
        Lab {
            relay,
            port,
            raw_addr: raw.clone().with(id.clone()),
            wss_addr: with_tls_ws(raw).with(id),
            seen: Vec::new(),
        }
    }

    /// The relay's inbound connections from `peer`: (local, send-back)
    /// addresses.
    fn inbound_from(&self, peer: PeerId) -> Vec<(Multiaddr, Multiaddr)> {
        self.seen
            .iter()
            .filter_map(|e| match e {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint:
                        ConnectedPoint::Listener {
                            local_addr,
                            send_back_addr,
                        },
                    ..
                } if *peer_id == peer => Some((local_addr.clone(), send_back_addr.clone())),
                _ => None,
            })
            .collect()
    }
}

/// Drives the relay (when there is one) and the nodes until `done` picks a
/// value: from a node event (`Some((index, event))`) or on a 50 ms tick
/// (`None`). Panics after [`STALL`] with what everyone reported.
async fn drive<T>(
    mut lab: Option<&mut Lab>,
    nodes: &mut [&mut Swarm<Node>],
    mut done: impl FnMut(Option<(usize, SwarmEvent<NodeEvent>)>) -> Option<T>,
) -> T {
    let mut seen: Vec<String> = Vec::new();
    let outcome = tokio::time::timeout(STALL, async {
        loop {
            let mut next = futures::future::select_all(
                nodes
                    .iter_mut()
                    .map(|s| Box::pin(s.select_next_some()))
                    .collect::<Vec<_>>(),
            );
            let relay_event = async {
                match lab.as_deref_mut() {
                    Some(lab) => lab.relay.select_next_some().await,
                    None => futures::future::pending().await,
                }
            };
            tokio::select! {
                event = relay_event => {
                    if let Some(lab) = lab.as_deref_mut() {
                        lab.seen.push(event);
                    }
                }
                (event, i, _) = &mut next => {
                    seen.push(format!("{i}: {event:?}"));
                    if let Some(v) = done(Some((i, event))) {
                        return v;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if let Some(v) = done(None) {
                        return v;
                    }
                }
            }
        }
    })
    .await;
    match outcome {
        Ok(v) => v,
        Err(_) => panic!(
            "no progress for {STALL:?}\nrelay events: {:#?}\nnode events: {seen:#?}",
            lab.map(|l| l.seen.iter().map(|e| format!("{e:?}")).collect::<Vec<_>>())
        ),
    }
}

/// The address of a node's established connection to `to`, if this event
/// is one.
fn dialed(event: &SwarmEvent<NodeEvent>, to: PeerId) -> Option<Multiaddr> {
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id,
            endpoint: ConnectedPoint::Dialer { address, .. },
            ..
        } if *peer_id == to => Some(address.clone()),
        _ => None,
    }
}

fn dial_error(event: SwarmEvent<NodeEvent>) -> Option<DialError> {
    match event {
        SwarmEvent::OutgoingConnectionError { error, .. } => Some(error),
        _ => None,
    }
}

fn is_wss(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| p == Protocol::Tls) && addr.iter().any(|p| is_ws_root(&p))
}

/// Reserves on `relay_addr` and returns the address the reservation's
/// connection was dialled at.
async fn reserve(lab: &mut Lab, a: &mut Swarm<Node>, relay_addr: &Multiaddr) -> Multiaddr {
    let relay = *lab.relay.local_peer_id();
    a.listen_on(relay_addr.clone().with(Protocol::P2pCircuit))
        .unwrap();
    let mut via = None;
    drive(Some(lab), &mut [a], |e| {
        let (_, e) = e?;
        if let Some(addr) = dialed(&e, relay) {
            via = Some(addr);
        }
        match e {
            SwarmEvent::Behaviour(NodeEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. },
            )) => Some(()),
            _ => None,
        }
    })
    .await;
    via.expect("a connection to the relay")
}

/// `b` dials `a` through the relay at `relay_addr`, then opens a stream to
/// it: (b's end, a's end).
async fn circuit_stream(
    lab: &mut Lab,
    a: &mut Swarm<Node>,
    b: &mut Swarm<Node>,
    relay_addr: &Multiaddr,
) -> (libp2p::Stream, libp2p::Stream) {
    let a_peer = *a.local_peer_id();
    let mut incoming = a
        .behaviour()
        .stream
        .new_control()
        .accept(RAVEN_LINK_PROTOCOL)
        .unwrap();
    let mut control = b.behaviour().stream.new_control();
    b.dial(
        relay_addr
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(a_peer)),
    )
    .unwrap();
    let opened = tokio::spawn(async move {
        control
            .open_stream(a_peer, RAVEN_LINK_PROTOCOL)
            .await
            .map_err(|e| e.to_string())
    });
    let accepted = tokio::spawn(async move { incoming.next().await.map(|(_, s)| s) });
    drive(Some(lab), &mut [a, b], |_| {
        (opened.is_finished() && accepted.is_finished()).then_some(())
    })
    .await;
    let out = opened.await.unwrap().expect("a stream over the circuit");
    let inn = accepted.await.unwrap().expect("the inbound stream");
    (out, inn)
}

/// `payload` from b to a and back over the circuit stream.
async fn round_trip(
    lab: &mut Lab,
    a: &mut Swarm<Node>,
    b: &mut Swarm<Node>,
    (mut out, mut inn): (libp2p::Stream, libp2p::Stream),
    payload: &'static [u8],
) {
    let pump = tokio::spawn(async move {
        out.write_all(payload).await.unwrap();
        out.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        inn.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        inn.write_all(&got).await.unwrap();
        inn.flush().await.unwrap();
        let mut back = vec![0u8; payload.len()];
        out.read_exact(&mut back).await.unwrap();
        assert_eq!(back, payload);
    });
    drive(Some(lab), &mut [a, b], |_| pump.is_finished().then_some(())).await;
    pump.await.unwrap();
}

/// What the in-test proxy saw: each request head, then the tunnel's bytes
/// each way.
#[derive(Default)]
struct ProxyLog {
    requests: Vec<Vec<u8>>,
    up: Vec<u8>,
    down: Vec<u8>,
}

/// An HTTP CONNECT proxy on loopback. It reads one request head per
/// connection and records it; with `reply` it sends that and closes,
/// otherwise it opens the tunnel to the address `routes` names for the
/// request's target (a 502 for any other target), answers 200 and relays
/// the bytes both ways, recording them. It resolves nothing.
async fn spawn_proxy(
    routes: HashMap<String, SocketAddr>,
    reply: Option<&'static [u8]>,
) -> (ProxyEndpoint, Arc<Mutex<ProxyLog>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(ProxyLog::default()));
    let shared = log.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            let (log, routes) = (shared.clone(), routes.clone());
            tokio::spawn(async move {
                // Byte by byte: nothing past the head is taken.
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    match c.read_u8().await {
                        Ok(b) => head.push(b),
                        Err(_) => return,
                    }
                }
                log.lock().unwrap().requests.push(head.clone());
                if let Some(reply) = reply {
                    let _ = c.write_all(reply).await;
                    return;
                }
                let line = String::from_utf8_lossy(&head).into_owned();
                let target = line.split(' ').nth(1).unwrap_or_default();
                let upstream = match routes.get(target) {
                    Some(to) => tokio::net::TcpStream::connect(to).await.ok(),
                    None => None,
                };
                let Some(upstream) = upstream else {
                    let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                if c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let (cr, cw) = c.into_split();
                let (ur, uw) = upstream.into_split();
                tokio::join!(pump(cr, uw, &log, true), pump(ur, cw, &log, false));
            });
        }
    });
    let endpoint = ProxyEndpoint {
        addr: format!("127.0.0.1:{port}"),
        basic: None,
    };
    (endpoint, log)
}

async fn pump(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, log: &Mutex<ProxyLog>, up: bool) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        {
            let mut log = log.lock().unwrap();
            let seen = if up { &mut log.up } else { &mut log.down };
            seen.extend_from_slice(&buf[..n]);
        }
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

/// A proxy setting that sends every dial to one proxy and records what it
/// was asked.
struct OneProxy {
    proxy: ProxyEndpoint,
    asked: Mutex<Vec<(Host, u16)>>,
}

impl OneProxy {
    fn new(proxy: ProxyEndpoint) -> Arc<Self> {
        Arc::new(OneProxy {
            proxy,
            asked: Mutex::new(Vec::new()),
        })
    }
}

impl ProxyLookup for OneProxy {
    fn proxy_for(&self, host: &Host, port: u16) -> Option<ProxyEndpoint> {
        self.asked.lock().unwrap().push((host.clone(), port));
        Some(self.proxy.clone())
    }
}

/// A proxy that maps `relay.invalid:<port>` to the lab relay, and the
/// relay's WSS address under that name (which no resolver knows).
async fn proxy_to(lab: &Lab) -> (Arc<OneProxy>, Arc<Mutex<ProxyLog>>, Multiaddr) {
    let port = lab.port;
    let routes = HashMap::from([(
        format!("relay.invalid:{port}"),
        SocketAddr::from(([127, 0, 0, 1], port)),
    )]);
    let (endpoint, log) = spawn_proxy(routes, None).await;
    let addr = format!(
        "/dns4/relay.invalid/tcp/{port}/tls/ws/p2p/{}",
        lab.relay.local_peer_id()
    )
    .parse()
    .unwrap();
    (OneProxy::new(endpoint), log, addr)
}

/// TLS records only: each a known content type (change_cipher_spec,
/// alert, handshake, application_data), version 3.x and a length within
/// TLS's bound. A record cut off at the end (still in flight) is allowed.
fn assert_tls_records(bytes: &[u8], which: &str) {
    let mut at = 0;
    let mut records = 0;
    while at + 5 <= bytes.len() {
        let (kind, major, len) = (
            bytes[at],
            bytes[at + 1],
            u16::from_be_bytes([bytes[at + 3], bytes[at + 4]]) as usize,
        );
        assert!(
            matches!(kind, 0x14..=0x17) && major == 0x03 && len <= (1 << 14) + 256,
            "{which}: not a TLS record at byte {at}: {:02x?}",
            &bytes[at..at + 5]
        );
        at += 5 + len;
        records += 1;
    }
    assert!(records > 2, "{which}: {records} records");
}

/// RWS1 §6 and §10: a relay's two-protocol listener takes a reservation over
/// `/tls/ws` and, on the same port, raw libp2p from an older endpoint; a
/// circuit between the two carries a stream both ways.
#[tokio::test]
async fn a_wss_reservation_on_a_two_protocol_listener_carries_a_circuit() {
    let mut lab = Lab::new(true).await;
    let mut a = node(A_SEED, Some(client_side(None)));
    let mut b = node(B_SEED, None);
    let wss_addr = lab.wss_addr.clone();
    let via = reserve(&mut lab, &mut a, &wss_addr).await;
    assert!(is_wss(&via), "the reservation rides {via}");

    let raw_addr = lab.raw_addr.clone();
    let streams = circuit_stream(&mut lab, &mut a, &mut b, &raw_addr).await;
    round_trip(&mut lab, &mut a, &mut b, streams, b"over the circuit").await;

    // Both arrived on the one listener, which labels its connections
    // `/tls/ws`.
    let (from_a, from_b) = (
        lab.inbound_from(peer(A_SEED)),
        lab.inbound_from(peer(B_SEED)),
    );
    let local = with_tls_ws(format!("/ip4/127.0.0.1/tcp/{}", lab.port).parse().unwrap());
    assert!(!from_a.is_empty() && !from_b.is_empty());
    for (l, back) in from_a.iter().chain(&from_b) {
        assert_eq!(*l, local);
        assert!(is_wss(back), "{back}");
    }
}

/// libp2p Noise authenticates the relay inside TLS and the WebSocket: a WSS
/// address naming another PeerId gets through TLS and the upgrade, then
/// fails on the PeerId.
#[tokio::test]
async fn a_wss_dial_to_the_wrong_peer_id_fails_after_noise() {
    let mut lab = Lab::new(true).await;
    let mut a = node(A_SEED, Some(client_side(None)));
    let wrong = peer(0xEE);
    let mut addr = lab.wss_addr.clone();
    addr.pop();
    a.dial(addr.with(Protocol::P2p(wrong))).unwrap();
    let error = drive(Some(&mut lab), &mut [&mut a], |e| dial_error(e?.1)).await;
    match error {
        DialError::WrongPeerId { obtained, .. } => assert_eq!(obtained, peer(RELAY_SEED)),
        other => panic!("not a PeerId mismatch: {other:?}"),
    }
}

/// RWS1 §10: against an older relay (raw libp2p only) the WSS form fails at
/// once, long before the connection timeout (the TLS ClientHello fails
/// multistream-select), and the raw form works.
#[tokio::test]
async fn a_wss_form_to_an_old_raw_relay_fails_fast_then_the_raw_form_works() {
    let mut lab = Lab::new(false).await;
    // A long connection timeout, so a failure within the product's 10 s
    // cannot be the timeout.
    let mut a = node_with(A_SEED, Some(client_side(None)), STALL);
    let started = Instant::now();
    a.dial(lab.wss_addr.clone()).unwrap();
    let error = drive(Some(&mut lab), &mut [&mut a], |e| dial_error(e?.1)).await;
    assert!(
        matches!(error, DialError::Transport(_)),
        "not a transport error: {error:?}"
    );
    assert!(
        started.elapsed() < CONNECTION_TIMEOUT,
        "failed only after {:?}",
        started.elapsed()
    );

    let relay = peer(RELAY_SEED);
    a.dial(lab.raw_addr.clone()).unwrap();
    let via = drive(Some(&mut lab), &mut [&mut a], |e| dialed(&e?.1, relay)).await;
    assert!(!is_wss(&via), "{via}");
}

/// RWS1 §7: a proxied dial of a `/dns4` relay sends the name to the proxy,
/// which resolves it (`relay.invalid` resolves nowhere else); without a
/// proxy the same address is not dialled at all.
#[tokio::test]
async fn a_proxied_wss_dial_carries_the_name_and_resolves_nothing() {
    let mut lab = Lab::new(true).await;
    let (proxy, log, addr) = proxy_to(&lab).await;
    let mut a = node(A_SEED, Some(client_side(Some(proxy.clone()))));
    let relay = peer(RELAY_SEED);
    a.dial(addr.clone()).unwrap();
    let via = drive(Some(&mut lab), &mut [&mut a], |e| dialed(&e?.1, relay)).await;
    assert_eq!(via, addr);
    let port = lab.port;
    assert_eq!(
        *proxy.asked.lock().unwrap(),
        [(Host::Name("relay.invalid".into()), port)]
    );
    assert_eq!(
        log.lock().unwrap().requests,
        [connect_request(&format!("relay.invalid:{port}"), None)]
    );

    // No proxy: the transport refuses the name ...
    let mut t = Transport::client(client_side(None));
    assert!(matches!(
        t.dial(addr.clone(), DIALER),
        Err(TransportError::MultiaddrNotSupported(_))
    ));
    // ... and so does every transport of a swarm.
    let mut c = node(C_SEED, Some(client_side(None)));
    c.dial(addr).unwrap();
    let error = drive(Some(&mut lab), &mut [&mut c], |e| dial_error(e?.1)).await;
    match error {
        DialError::Transport(errors) => {
            assert!(!errors.is_empty());
            for (_, e) in &errors {
                assert!(
                    matches!(e, TransportError::MultiaddrNotSupported(_)),
                    "{e:?}"
                );
            }
        }
        other => panic!("{other:?}"),
    }
}

/// A proxy setting with a name bypass (`NO_PROXY=.corp.example`): every
/// dial goes to one proxy except a name under the suffix.
struct BypassNames {
    proxy: ProxyEndpoint,
    suffix: &'static str,
}

impl ProxyLookup for BypassNames {
    fn proxy_for(&self, host: &Host, _port: u16) -> Option<ProxyEndpoint> {
        match host {
            Host::Name(name) if name.ends_with(self.suffix) => None,
            _ => Some(self.proxy.clone()),
        }
    }
}

/// RWS1 §8.3 (review B-1): raven-node resolves a WSS form whose name
/// bypasses the proxy into `/ip4/A/…/tls/sni/<name>/ws`; the bypass still
/// holds for that form, so the dial goes straight to the relay and the
/// proxy is never asked for a tunnel. An IP with no name still goes
/// through the proxy.
#[tokio::test]
async fn a_resolved_form_whose_name_bypasses_the_proxy_goes_direct() {
    let mut lab = Lab::new(true).await;
    let (endpoint, log) = spawn_proxy(HashMap::new(), None).await;
    let lookup = Arc::new(BypassNames {
        proxy: endpoint,
        suffix: ".corp.example",
    });
    let mut a = node(A_SEED, Some(client_side(Some(lookup.clone()))));
    let relay = peer(RELAY_SEED);
    let addr: Multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}/tls/sni/relay.corp.example/ws/p2p/{relay}",
        lab.port
    )
    .parse()
    .unwrap();
    a.dial(addr.clone()).unwrap();
    let via = drive(Some(&mut lab), &mut [&mut a], |e| dialed(&e?.1, relay)).await;
    assert_eq!(via, addr);
    assert!(
        log.lock().unwrap().requests.is_empty(),
        "the proxy was asked"
    );

    let target = |text: &str| Target::parse(&text.parse().unwrap()).unwrap();
    let ip = |text: &str| target(text).proxy(lookup.as_ref()).is_some();
    assert!(!ip("/ip4/10.1.2.3/tcp/443/tls/sni/relay.corp.example/ws"));
    assert!(ip("/ip4/10.1.2.3/tcp/443/tls/sni/relay.example.org/ws"));
    assert!(ip("/ip4/10.1.2.3/tcp/443/tls/ws"));
    assert!(!ip("/dns4/relay.corp.example/tcp/443/tls/ws"));
    assert!(ip("/dns4/relay.example.org/tcp/443/tls/ws"));
}

/// RWS1 §9: through the proxy only TLS records pass, the first a handshake
/// record (0x16) right after the 200; none of libp2p's protocol names nor a
/// Raven frame tag carried over the circuit is in the clear.
#[tokio::test]
async fn the_proxy_sees_only_tls_records() {
    let mut lab = Lab::new(true).await;
    let (proxy, log, addr) = proxy_to(&lab).await;
    let mut a = node(A_SEED, Some(client_side(Some(proxy))));
    let mut b = node(B_SEED, None);
    let via = reserve(&mut lab, &mut a, &addr).await;
    assert_eq!(via, addr);
    let raw_addr = lab.raw_addr.clone();
    let streams = circuit_stream(&mut lab, &mut a, &mut b, &raw_addr).await;
    let payload: &'static [u8] = b"RVPI1\0RLB1\0RIH1\0/multistream/1.0.0\n/noise\n/yamux/1.0.0\n";
    round_trip(&mut lab, &mut a, &mut b, streams, payload).await;

    let log = log.lock().unwrap();
    assert_eq!(log.requests.len(), 1);
    assert_eq!(log.up.first(), Some(&0x16), "the first byte after the 200");
    assert_eq!(log.down.first(), Some(&0x16));
    assert_tls_records(&log.up, "client to relay");
    assert_tls_records(&log.down, "relay to client");
    for marker in MARKERS {
        for (bytes, which) in [(&log.up, "up"), (&log.down, "down")] {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == *marker),
                "{which} carries {:?}",
                String::from_utf8_lossy(marker)
            );
        }
    }
}

/// RWS1 §7: a proxy that wants Negotiate (or anything but Basic) is
/// reported as such through the swarm's dial error, and the error names no
/// proxy address.
#[tokio::test]
async fn proxy_407_negotiate_is_reported_as_unsupported_auth() {
    let (endpoint, log) = spawn_proxy(
        HashMap::new(),
        Some(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n",
        ),
    )
    .await;
    let proxy_addr = endpoint.addr.clone();
    let mut a = node(A_SEED, Some(client_side(Some(OneProxy::new(endpoint)))));
    let addr: Multiaddr = format!(
        "/dns4/relay.invalid/tcp/443/tls/ws/p2p/{}",
        peer(RELAY_SEED)
    )
    .parse()
    .unwrap();
    a.dial(addr).unwrap();
    let error = drive(None, &mut [&mut a], |e| dial_error(e?.1)).await;
    let DialError::Transport(errors) = &error else {
        panic!("{error:?}");
    };
    let found: Vec<&ProxyError> = errors
        .iter()
        .filter_map(|(_, e)| match e {
            TransportError::Other(e) => proxy_error_in(e),
            TransportError::MultiaddrNotSupported(_) => None,
        })
        .collect();
    assert_eq!(
        found,
        [&ProxyError::Auth {
            schemes: vec!["Negotiate"],
            sent_basic: false,
        }]
    );
    assert!(found[0].unsupported_auth());
    assert!(!format!("{error}").contains(&proxy_addr));
    assert!(!format!("{error:?}").contains(&proxy_addr));
    assert_eq!(
        log.lock().unwrap().requests,
        [connect_request("relay.invalid:443", None)]
    );
}

async fn next_event(t: &mut Transport) -> TransportEvent<Upgrade, io::Error> {
    futures::future::poll_fn(|cx| Pin::new(&mut *t).poll(cx)).await
}

/// The listen addresses a WSS listener reports: `/tls/ws`, then plain.
async fn listen(t: &mut Transport) -> u16 {
    t.listen_on(
        ListenerId::next(),
        "/ip4/127.0.0.1/tcp/0/tls/ws".parse().unwrap(),
    )
    .unwrap();
    let mut addrs = Vec::new();
    while addrs.len() < 2 {
        match next_event(t).await {
            TransportEvent::NewAddress { listen_addr, .. } => addrs.push(listen_addr),
            other => panic!("{:?}", other.map_upgrade(|_| ())),
        }
    }
    assert_eq!(addrs[0], with_tls_ws(addrs[1].clone()));
    match addrs[1].iter().nth(1) {
        Some(Protocol::Tcp(port)) => port,
        other => panic!("{other:?}"),
    }
}

/// The next inbound connection's upgrade; both its addresses are labelled
/// `/tls/ws`.
async fn incoming(t: &mut Transport) -> Upgrade {
    match next_event(t).await {
        TransportEvent::Incoming {
            upgrade,
            local_addr,
            send_back_addr,
            ..
        } => {
            assert!(is_wss(&local_addr) && is_wss(&send_back_addr));
            upgrade
        }
        other => panic!("{:?}", other.map_upgrade(|_| ())),
    }
}

/// RWS1 §6: a connection that sends nothing is closed, with no reply, once
/// the demux wait is over, and not before.
#[tokio::test(start_paused = true)]
async fn a_silent_client_is_closed_after_the_demux_wait() {
    let mut t = Transport::server(server_side());
    let port = listen(&mut t).await;
    let mut silent = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let upgrade = incoming(&mut t).await;
    let started = tokio::time::Instant::now();
    let error = upgrade.await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= DEMUX_WAIT, "{:?}", started.elapsed());
    let mut buf = [0u8; 64];
    assert_eq!(silent.read(&mut buf).await.unwrap_or(0), 0, "a reply");
}

/// RWS1 §6: the first byte decides and stays in place: 0x13 gives the raw
/// stream with every byte, anything but 0x13 or 0x16 is closed at once
/// with no reply, and 0x16 goes to TLS.
#[tokio::test]
async fn the_first_byte_picks_raw_tls_or_a_close() {
    let mut t = Transport::server(server_side());
    let port = listen(&mut t).await;

    let mut raw = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    raw.write_all(b"\x13/multistream/1.0.0\n").await.unwrap();
    let up = incoming(&mut t).await;
    let WssStream::Raw(mut s) = tokio::time::timeout(STALL, up).await.unwrap().unwrap() else {
        panic!("not raw");
    };
    let mut got = [0u8; 20];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"\x13/multistream/1.0.0\n");

    let mut http = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    http.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let up = incoming(&mut t).await;
    let started = Instant::now();
    let error = tokio::time::timeout(STALL, up).await.unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(started.elapsed() < DEMUX_WAIT);
    let mut buf = [0u8; 64];
    assert_eq!(http.read(&mut buf).await.unwrap_or(0), 0, "a reply");

    // A TLS client whose upgrade the WebSocket server then refuses: the
    // listener took it to TLS.
    let tls = TlsConnector::from(tls::client_tls());
    let client = tokio::spawn(async move {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let mut s = tls
            .connect(name, Tunnel::direct(TcpStream(tcp)))
            .await
            .unwrap();
        s.write_all(b"GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        s.flush().await.unwrap();
        let mut reply = Vec::new();
        let _ = s.read_to_end(&mut reply).await;
        reply
    });
    let up = incoming(&mut t).await;
    assert!(tokio::time::timeout(STALL, up).await.unwrap().is_err());
    let reply = tokio::time::timeout(STALL, client).await.unwrap().unwrap();
    assert_eq!(reply, ws::NOT_FOUND);
}

fn wss_target() -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/4443/tls/ws/p2p/{}", peer(RELAY_SEED))
        .parse()
        .unwrap()
}

/// A relay builds no WSS client: its transport refuses every dial, so
/// neither its AutoNAT dial-backs nor anything else go out over WSS.
#[test]
fn a_relay_side_transport_never_dials() {
    let mut t = Transport::server(server_side());
    for addr in [
        wss_target(),
        "/ip4/127.0.0.1/tcp/4443".parse().unwrap(),
        "/dns4/relay.invalid/tcp/443/tls/ws".parse().unwrap(),
    ] {
        assert!(matches!(
            t.dial(addr, DIALER),
            Err(TransportError::MultiaddrNotSupported(_))
        ));
    }
    let mut upgraded = server_transport(&key(RELAY_SEED), server_side()).unwrap();
    assert!(matches!(
        upgraded.dial(wss_target(), DIALER),
        Err(TransportError::MultiaddrNotSupported(_))
    ));
}

/// No hole punching over WSS: a dial in the listener role (DCUtR's) is
/// refused, and an endpoint's transport never listens.
#[test]
fn listener_role_dials_are_refused() {
    let as_listener = DialOpts {
        role: Endpoint::Listener,
        port_use: PortUse::Reuse,
    };
    let mut t = Transport::client(client_side(None));
    assert!(matches!(
        t.dial(wss_target(), as_listener),
        Err(TransportError::MultiaddrNotSupported(_))
    ));
    assert!(matches!(
        t.listen_on(
            ListenerId::next(),
            "/ip4/127.0.0.1/tcp/0/tls/ws".parse().unwrap()
        ),
        Err(TransportError::MultiaddrNotSupported(_))
    ));
    let mut upgraded = client_transport(&key(A_SEED), client_side(None)).unwrap();
    assert!(matches!(
        upgraded.dial(wss_target(), as_listener),
        Err(TransportError::MultiaddrNotSupported(_))
    ));
}
