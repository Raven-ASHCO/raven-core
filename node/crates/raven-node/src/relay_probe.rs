//! `raven-node relay-probe <VIA>...` (relay kit): does each relay address
//! answer, from where this runs, as the relay its `/p2p/` PeerId names? It
//! checks a port forward, a firewall or a stale card from outside the
//! relay's own network (a phone hotspot, a friend's computer).
//!
//! It dials each address on its own, once, with a throwaway key: no Raven
//! identity, no keystore, no reservation, nothing written. A relay refuses
//! the stranger at its peer gate right after the Noise handshake, which has
//! already proven the relay's PeerId: that is the expected success. Results
//! name the transport and port only, never an IP or a PeerId (NAT spec §5).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::StreamExt;
use raven_core::p2p_route::{parse_via, ViaAddr};
use raven_swarm::gate::{GateHandle, PeerClass};
use raven_swarm::host::{build_endpoint_swarm, EndpointBehaviour, EndpointConfig, HostGate};
use raven_swarm::libp2p::identity::Keypair;
use raven_swarm::libp2p::multiaddr::Protocol;
use raven_swarm::libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use raven_swarm::libp2p::swarm::{DialError, SwarmEvent};
use raven_swarm::libp2p::{Multiaddr, PeerId, Swarm};

use crate::relay::RelayExit;

/// Addresses one run probes at most.
pub(crate) const MAX_PROBES: usize = 6;
/// How long one address may take to answer.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// What one relay address did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Probe {
    /// The Noise handshake proved the PeerId in the address.
    Reachable,
    /// Something answered with another key.
    OtherPeer,
    /// Its `/dns*` name resolves to nothing.
    Unresolved,
    /// Refused, unreachable, or the handshake failed.
    Refused,
    /// Nothing within [`ANSWER_WITHIN`].
    NoAnswer,
    /// A WSS address while the WSS gate is closed: not dialled.
    WssHeld,
}

impl Probe {
    pub(crate) fn text(self) -> &'static str {
        match self {
            Self::Reachable => "reachable (answers as the relay in the address)",
            Self::OtherPeer => {
                "answers as a DIFFERENT PeerId (stale card, or another program on that port)"
            }
            Self::Unresolved => "the name does not resolve",
            Self::Refused => "refused or unreachable",
            Self::NoAnswer => "no answer within 10 s",
            Self::WssHeld => {
                "not probed: WSS_HOLD (relays over WebSocket/TLS are lab-only in this build)"
            }
        }
    }
}

/// The relay addresses to probe: 1 to [`MAX_PROBES`], each a `via=` address
/// ([`parse_via`]), pasted with or without `via=`.
pub(crate) fn parse_args(args: &[String]) -> Result<Vec<ViaAddr>, String> {
    if args.is_empty() || args.len() > MAX_PROBES {
        return Err(format!(
            "give 1 to {MAX_PROBES} relay addresses (the via= lines of `raven relay card`)"
        ));
    }
    args.iter()
        .map(|a| {
            let t = a.trim();
            parse_via(t.strip_prefix("via=").unwrap_or(t))
        })
        .collect()
}

/// What a result line names: `tcp/<port>`, `wss/<port>` or `quic/<port>`.
pub(crate) fn transport_label(via: &ViaAddr) -> String {
    let Ok(addr) = via.text.parse::<Multiaddr>() else {
        return "?".into();
    };
    let mut port = 0;
    let mut quic = false;
    for p in addr.iter() {
        match p {
            Protocol::Tcp(n) | Protocol::Udp(n) => port = n,
            Protocol::QuicV1 => quic = true,
            _ => {}
        }
    }
    let kind = if quic {
        "quic"
    } else if via.is_wss() {
        "wss"
    } else {
        "tcp"
    };
    format!("{kind}/{port}")
}

/// Is `via` dialled? A WSS address only while the WSS gate is live
/// (review A-3: otherwise it would read as refused).
fn probed(via: &ViaAddr, wss_live: bool) -> bool {
    wss_live || !via.is_wss()
}

/// Probe every address in turn. Held while the P2P gate is closed (it
/// dials).
pub(crate) async fn probe_all(vias: &[ViaAddr]) -> Result<Vec<Probe>, RelayExit> {
    let host_gate = HostGate::open(raven_core::p2p_live_enabled()).map_err(|_| RelayExit::Held)?;
    let peers = vias
        .iter()
        .map(|v| {
            v.peer_id
                .parse::<PeerId>()
                .map_err(|e| RelayExit::Other(format!("relay-probe: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // The probed relays are this host's own relays, and nobody else is
    // admitted.
    let gate = GateHandle::default();
    let own: HashMap<PeerId, PeerClass> =
        peers.iter().map(|p| (*p, PeerClass::OWN_RELAY)).collect();
    gate.replace(own, false, Instant::now());
    let wss_live = raven_core::wss_live_enabled();
    let mut swarm = build_endpoint_swarm(
        &host_gate,
        Keypair::generate_ed25519(),
        EndpointConfig {
            gate,
            // WSS addresses (`/tls/ws`, review A-3) while the WSS gate is
            // live: always direct, never through this computer's proxy, so
            // the answer is the relay's own.
            wss: wss_live.then(|| raven_swarm::wss::ClientSide {
                tls: raven_swarm::wss::tls::client_tls(),
                proxy: None,
            }),
            ..EndpointConfig::default()
        },
    )
    .map_err(|e| RelayExit::Other(format!("relay-probe: {e}")))?;
    let mut out = Vec::new();
    for (via, peer) in vias.iter().zip(peers) {
        out.push(if probed(via, wss_live) {
            probe_one(&mut swarm, via, peer).await
        } else {
            Probe::WssHeld
        });
    }
    Ok(out)
}

async fn probe_one(swarm: &mut Swarm<EndpointBehaviour>, via: &ViaAddr, peer: PeerId) -> Probe {
    let Ok(mut addr) = via.text.parse::<Multiaddr>() else {
        return Probe::Refused;
    };
    // The dial names the PeerId; the address is the transport's alone.
    if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
        addr.pop();
    }
    let addrs = crate::p2p::resolve_all(vec![addr]).await;
    if addrs.is_empty() {
        return Probe::Unresolved;
    }
    let opts = DialOpts::peer_id(peer)
        .addresses(addrs)
        .condition(PeerCondition::Always)
        .build();
    let id = opts.connection_id();
    if let Err(e) = swarm.dial(opts) {
        return classify(&e);
    }
    let deadline = tokio::time::Instant::now() + ANSWER_WITHIN;
    let result = loop {
        match tokio::time::timeout_at(deadline, swarm.select_next_some()).await {
            Err(_) => break Probe::NoAnswer,
            Ok(SwarmEvent::ConnectionEstablished { connection_id, .. }) if connection_id == id => {
                break Probe::Reachable
            }
            Ok(SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                ..
            }) if connection_id == id => break classify(&error),
            Ok(_) => {}
        }
    };
    let _ = swarm.disconnect_peer_id(peer);
    result
}

fn classify(error: &DialError) -> Probe {
    match error {
        DialError::WrongPeerId { .. } => Probe::OtherPeer,
        _ => Probe::Refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_one_to_six_relay_addresses() {
        let peer = raven_core::p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[7; 32]));
        let tcp = format!("/ip4/203.0.113.7/tcp/7423/p2p/{peer}");
        let quic = format!("via=/dns4/relay.example.org/udp/7423/quic-v1/p2p/{peer}");
        let vias = parse_args(&[tcp.clone(), quic]).unwrap();
        assert_eq!(transport_label(&vias[0]), "tcp/7423");
        assert_eq!(transport_label(&vias[1]), "quic/7423");
        // Review A-3: a WSS line says wss, and is dialled only while the
        // WSS gate is live (with it closed it says WSS_HOLD, not refused).
        let wss = parse_args(&[
            format!("/ip4/203.0.113.7/tcp/443/tls/ws/p2p/{peer}"),
            format!("via=/dns4/relay.example.org/tcp/8443/wss/p2p/{peer}"),
            format!("/ip4/203.0.113.7/tcp/443/p2p/{peer}"),
        ])
        .unwrap();
        assert_eq!(transport_label(&wss[0]), "wss/443");
        assert_eq!(transport_label(&wss[1]), "wss/8443");
        assert_eq!(transport_label(&wss[2]), "tcp/443");
        assert!(probed(&wss[0], true) && !probed(&wss[0], false));
        assert!(probed(&wss[2], false) && probed(&vias[1], false));
        assert!(Probe::WssHeld.text().contains("WSS_HOLD"));
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&vec![tcp.clone(); MAX_PROBES]).is_ok());
        assert!(parse_args(&vec![tcp; MAX_PROBES + 1]).is_err());
        // A circuit or an address without the relay's PeerId is not a relay
        // address.
        assert!(parse_args(&[format!(
            "/ip4/203.0.113.7/tcp/7423/p2p/{peer}/p2p-circuit/p2p/{peer}"
        )])
        .is_err());
        assert!(parse_args(&["/ip4/203.0.113.7/tcp/7423".into()]).is_err());
    }

    #[tokio::test]
    async fn the_probe_is_held_while_the_gate_is_closed() {
        if raven_core::p2p_live_enabled() {
            return;
        }
        let peer = raven_core::p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[7; 32]));
        let vias = parse_args(&[format!("/ip4/127.0.0.1/tcp/1/p2p/{peer}")]).unwrap();
        assert_eq!(probe_all(&vias).await.unwrap_err(), RelayExit::Held);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_probe_classifies_reachable_other_peer_and_refused() {
        if !raven_core::p2p_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let cmd = crate::relay::tests::dedicated(dir.path(), "127.0.0.1:0");
        let (relay_peer, tcp, quic, stop, task) = crate::relay::tests::start(cmd).await;
        let stranger =
            raven_core::p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[9; 32]));
        // A port nobody listens on.
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let vias = parse_args(&[
            format!("{tcp}/p2p/{relay_peer}"),
            format!("{quic}/p2p/{relay_peer}"),
            format!("{tcp}/p2p/{stranger}"),
            format!("/ip4/127.0.0.1/tcp/{closed}/p2p/{relay_peer}"),
        ])
        .unwrap();
        let results = probe_all(&vias).await.unwrap();
        assert_eq!(
            results,
            [
                Probe::Reachable,
                Probe::Reachable,
                Probe::OtherPeer,
                Probe::Refused
            ]
        );
        // What main.rs prints: transport and port, never an IP or PeerId.
        for (via, result) in vias.iter().zip(&results) {
            let line = format!("{}: {}", transport_label(via), result.text());
            for leak in ["127.0.0.1", "/ip4", relay_peer.as_str(), stranger.as_str()] {
                assert!(!line.contains(leak), "{line}");
            }
        }
        // Nothing was reserved: the relay saw a stranger only.
        let status = raven_core::relay_allow::load_relay_status(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(status.counts.reservations, 0);
        stop.send(()).unwrap();
        assert_eq!(task.await.unwrap(), Ok(()));
    }
}
