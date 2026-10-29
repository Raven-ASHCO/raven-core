//! What a failed libp2p dial says about each address it tried
//! ([`dial_failures`]): for a circuit, what the relay answered
//! ([`CircuitOutcome`]); for a direct address, whether the host refused it
//! ([`AddrOutcome`]). Relay selection and the "nobody reachable" diagnosis
//! (raven-node) both read dial errors through this one classifier.
//!
//! **Where the answer is.** Checked against the locked libp2p 0.57 (swarm
//! 0.48, core 0.44, relay 0.22, either 1.17) and pinned against a real relay
//! by `host::tests::circuit_failures_say_what_the_relay_answered`:
//! - `DialError::Transport` lists `(Multiaddr, TransportError<io::Error>)`
//!   (swarm lib.rs:1532-1554);
//! - the swarm builder boxes the whole transport under its timeout (libp2p
//!   builder/phase/build.rs:28): that `io::Error` holds a
//!   `TransportTimeoutError`, whose source is the error it wraps (core
//!   transport/timeout.rs:208-214);
//! - that error is a stack of `either::Either`s: the relay-or-direct and
//!   TCP-or-QUIC choices (core transport/choice.rs:52) and the security and
//!   muxer upgrades, each an `AndThen` (core transport/and_then.rs:60). An
//!   `Either`'s source is the source of the error it holds (either
//!   lib.rs:1617-1635), so the whole stack is one link of the chain, and the
//!   next link is the source of the transport's own error;
//! - for a circuit, the transport's own error is
//!   `relay::client::transport::Error` (priv_client/transport.rs:416-439),
//!   and its source is the relay's answer, a `ConnectError`
//!   (protocol/outbound_hop.rs:39-54);
//! - for a direct TCP address it is the socket's `io::Error`, which has no
//!   source: no link of the chain is that error, but every layer above it
//!   prints it unchanged, and std prints an OS error as
//!   `<message> (os error <code>)`.
//!
//! So every link of the source chain is asked, starting with the boxed error
//! (`io::Error::source()` would skip it), and for a direct address the OS
//! error a link prints too. The walk is bounded (an error may even name
//! itself as its source), and whatever it does not recognise reads as no
//! answer, never as a refusal.
//!
//! **What an answer means** (libp2p-relay 0.22):
//! - every refusal of the relay's circuit limiter, its caps and rate and
//!   [`crate::host::RelayGuard`]'s membership check alike, is
//!   RESOURCE_LIMIT_EXCEEDED (behaviour.rs:693-716): `Busy`;
//! - PERMISSION_DENIED comes only from the destination's STOP answer
//!   (protocol/outbound_stop.rs:135): `Refused`;
//! - NO_RESERVATION, and CONNECTION_FAILED, which a STOP that could not be
//!   completed gives (behaviour/handler.rs:480-496, 733-747): `NotOnRelay`;
//! - a peer that does not speak the relay protocol: `NotARelay`;
//! - a request the relay client dropped unanswered, because its dial to the
//!   relay failed (priv_client.rs:279-282, 418-431) or the connection closed
//!   first (no `ConnectError`), a stream I/O failure or a protocol
//!   violation: `NoAnswer`.
//!
//! A relay whose peer gate refuses us does not answer at all: it closes our
//! connection right after Noise. raven-node tells that quick close apart
//! itself (`closed_at_once`).

use std::error::Error;
use std::io;

use libp2p::core::transport::TransportError;
use libp2p::multiaddr::Protocol;
use libp2p::relay;
use libp2p::swarm::DialError;
use libp2p::{Multiaddr, PeerId};
use raven_core::reach_diag::{AddrOutcome, CircuitOutcome};

/// One address of a failed dial, and what it said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed {
    /// A direct address.
    Direct(AddrOutcome),
    /// A circuit through `relay`.
    Circuit {
        relay: PeerId,
        outcome: CircuitOutcome,
    },
}

/// Links of one address's error the walk asks at most, the boxed error
/// first.
const MAX_CHAIN: usize = 8;
/// Addresses of one failed dial read at most.
const MAX_ADDRS: usize = 8;

/// The relay of `/…/p2p/<relay>/p2p-circuit/p2p/<dst>`: the last `/p2p`
/// before the first `/p2p-circuit`. `None` for a direct address and for a
/// circuit that names no relay.
pub fn circuit_relay(addr: &Multiaddr) -> Option<PeerId> {
    let mut last = None;
    for p in addr.iter() {
        match p {
            Protocol::P2p(id) => last = Some(id),
            Protocol::P2pCircuit => return last,
            _ => {}
        }
    }
    None
}

/// The error `e` boxes, then its sources: at most [`MAX_CHAIN`] links.
fn chain(e: &io::Error) -> impl Iterator<Item = &(dyn Error + 'static)> {
    std::iter::successors(e.get_ref().map(|r| r as &(dyn Error + 'static)), |&x| {
        x.source()
    })
    .take(MAX_CHAIN)
}

/// What the relay answered our circuit request, from that circuit's error.
fn relay_answer(e: &io::Error) -> CircuitOutcome {
    use relay::outbound::hop::ConnectError as C;
    chain(e)
        .find_map(|x| x.downcast_ref::<C>())
        .map_or(CircuitOutcome::NoAnswer, |c| match c {
            C::NoReservation | C::ConnectionFailed => CircuitOutcome::NotOnRelay,
            C::PermissionDenied => CircuitOutcome::Refused,
            C::ResourceLimitExceeded => CircuitOutcome::Busy,
            C::Unsupported => CircuitOutcome::NotARelay,
            C::Io(_) | C::Protocol(_) => CircuitOutcome::NoAnswer,
        })
}

/// The OS error a text ends with, as std prints one:
/// `<message> (os error <code>)`.
fn os_error_at_end(text: &str) -> Option<io::Error> {
    let (_, code) = text.strip_suffix(')')?.rsplit_once("(os error ")?;
    code.parse().ok().map(io::Error::from_raw_os_error)
}

/// Whether a direct address refused us, from its error: the error itself,
/// a link of its chain, or the OS error a link prints (the socket's own
/// error is no link: see the module doc).
fn addr_answer(e: &io::Error) -> AddrOutcome {
    let refused = |i: &io::Error| i.kind() == io::ErrorKind::ConnectionRefused;
    let says_refused = |x: &(dyn Error + 'static)| {
        x.downcast_ref::<io::Error>().is_some_and(refused)
            || os_error_at_end(&x.to_string()).is_some_and(|i| refused(&i))
    };
    if refused(e) || chain(e).any(says_refused) {
        AddrOutcome::Refused
    } else {
        AddrOutcome::NoAnswer
    }
}

/// What each address of a failed dial said, in the error's order (at most
/// [`MAX_ADDRS`]). Empty when no transport ran (a gate denied the dial, it
/// was aborted, had no address or reached the wrong peer): such a failure
/// says nothing about the network.
pub fn dial_failures(e: &DialError) -> Vec<Failed> {
    let DialError::Transport(list) = e else {
        return Vec::new();
    };
    list.iter()
        .take(MAX_ADDRS)
        .map(|(addr, failure)| {
            let io = match failure {
                TransportError::Other(io) => Some(io),
                TransportError::MultiaddrNotSupported(_) => None,
            };
            match circuit_relay(addr) {
                Some(relay) => Failed::Circuit {
                    relay,
                    outcome: io.map_or(CircuitOutcome::NoAnswer, relay_answer),
                },
                None => Failed::Direct(io.map_or(AddrOutcome::NoAnswer, addr_answer)),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use futures::channel::oneshot::Canceled;
    use libp2p::core::transport::timeout::TransportTimeoutError;
    use libp2p::relay::client::transport::Error as RelayClientError;
    use libp2p::relay::outbound::hop::{ConnectError, ProtocolViolation};
    use libp2p::swarm::derive_prelude::Either;
    use libp2p::swarm::ConnectionDenied;

    use super::*;

    /// A relay client error as the endpoint's transport stacks it (module
    /// doc): the timeout, the relay-or-direct `Either`, the muxer and
    /// security upgrades' `Either`s.
    fn via_relay(e: RelayClientError) -> io::Error {
        io::Error::other(TransportTimeoutError::Other(Either::<_, io::Error>::Left(
            Either::<_, io::Error>::Left(Either::<_, io::Error>::Left(e)),
        )))
    }

    /// A TCP socket error as the endpoint's transport stacks it: the
    /// timeout, the relay-or-direct and TCP-or-QUIC `Either`s, the upgrades'.
    fn via_tcp(e: io::Error) -> io::Error {
        io::Error::other(TransportTimeoutError::Other(Either::<io::Error, _>::Right(
            Either::<_, io::Error>::Left(Either::<_, io::Error>::Left(
                Either::<_, io::Error>::Left(e),
            )),
        )))
    }

    /// An OS error of `kind`, as a socket reports it (with this OS's code).
    fn os_error(kind: io::ErrorKind) -> io::Error {
        (1..=20_000)
            .map(io::Error::from_raw_os_error)
            .find(|e| e.kind() == kind)
            .expect("an OS error code of that kind")
    }

    fn failed_at(addr: &Multiaddr, e: io::Error) -> Vec<Failed> {
        dial_failures(&DialError::Transport(vec![(
            addr.clone(),
            TransportError::Other(e),
        )]))
    }

    fn circuit(relay: PeerId) -> Multiaddr {
        format!(
            "/ip4/127.0.0.1/tcp/4001/p2p/{relay}/p2p-circuit/p2p/{}",
            PeerId::random()
        )
        .parse()
        .unwrap()
    }

    fn direct() -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", PeerId::random())
            .parse()
            .unwrap()
    }

    /// An error that wraps another one (its source).
    #[derive(Debug)]
    struct Layer(Box<dyn Error + Send + Sync>);

    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("layer")
        }
    }

    impl Error for Layer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&*self.0)
        }
    }

    /// An error that names itself as its source.
    #[derive(Debug)]
    struct Loop;

    impl fmt::Display for Loop {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("loop")
        }
    }

    impl Error for Loop {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self)
        }
    }

    /// The whole mapping, through every layer the transport wraps a relay's
    /// answer in.
    #[test]
    fn every_relay_answer_maps_to_one_outcome() {
        use CircuitOutcome::*;
        let relay = PeerId::random();
        let at = circuit(relay);
        let answers = [
            (ConnectError::NoReservation, NotOnRelay),
            (ConnectError::ConnectionFailed, NotOnRelay),
            (ConnectError::PermissionDenied, Refused),
            (ConnectError::ResourceLimitExceeded, Busy),
            (ConnectError::Unsupported, NotARelay),
            (ConnectError::Io(io::ErrorKind::TimedOut.into()), NoAnswer),
            (
                ConnectError::Protocol(ProtocolViolation::MissingStatusField),
                NoAnswer,
            ),
        ];
        for (answer, outcome) in answers {
            let text = format!("{answer:?}");
            assert_eq!(
                failed_at(&at, via_relay(RelayClientError::Connect(answer))),
                [Failed::Circuit { relay, outcome }],
                "{text}"
            );
        }
        // The answer boxed on its own reads the same.
        assert_eq!(
            failed_at(&at, io::Error::other(ConnectError::ResourceLimitExceeded)),
            [Failed::Circuit {
                relay,
                outcome: Busy
            }]
        );
        // No answer: dropped unanswered, the transport's own timeout, an
        // unknown error, a refused socket (only a direct address has one).
        let unanswered = [
            via_relay(RelayClientError::ResponseFromBehaviourCanceled(Canceled)),
            io::Error::other(TransportTimeoutError::<io::Error>::Timeout),
            io::Error::other("something else"),
            via_tcp(os_error(io::ErrorKind::ConnectionRefused)),
        ];
        for e in unanswered {
            assert_eq!(
                failed_at(&at, e),
                [Failed::Circuit {
                    relay,
                    outcome: NoAnswer
                }]
            );
        }
        // An address the relay transport did not take.
        assert_eq!(
            dial_failures(&DialError::Transport(vec![(
                at.clone(),
                TransportError::MultiaddrNotSupported(at.clone()),
            )])),
            [Failed::Circuit {
                relay,
                outcome: NoAnswer
            }]
        );
    }

    #[test]
    fn a_direct_address_is_refused_only_when_its_host_said_so() {
        let at = direct();
        let refused = [Failed::Direct(AddrOutcome::Refused)];
        let os_refused = || os_error(io::ErrorKind::ConnectionRefused);
        // Under every layer (read from the text a link prints), boxed in
        // another error, or on its own.
        assert_eq!(failed_at(&at, via_tcp(os_refused())), refused);
        assert_eq!(failed_at(&at, io::Error::other(os_refused())), refused);
        assert_eq!(failed_at(&at, os_refused()), refused);
        assert_eq!(
            failed_at(&at, io::ErrorKind::ConnectionRefused.into()),
            refused
        );
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::AddrNotAvailable,
        ] {
            assert_eq!(
                failed_at(&at, via_tcp(os_error(kind))),
                [Failed::Direct(AddrOutcome::NoAnswer)],
                "{kind:?}"
            );
        }
        // Text that only looks like an OS error, or names it elsewhere.
        let code = os_refused().raw_os_error().unwrap();
        for text in [
            format!("(os error {code}) and then something"),
            format!("(os error x{code})"),
            "os error".to_owned(),
        ] {
            assert_eq!(
                failed_at(&at, io::Error::other(text.clone())),
                [Failed::Direct(AddrOutcome::NoAnswer)],
                "{text}"
            );
        }
        // A relay's answer means nothing on a direct address.
        assert_eq!(
            failed_at(
                &at,
                via_relay(RelayClientError::Connect(ConnectError::NoReservation))
            ),
            [Failed::Direct(AddrOutcome::NoAnswer)]
        );
    }

    /// The walk asks at most [`MAX_CHAIN`] links and ends even on an error
    /// that names itself as its source; a dial reads at most [`MAX_ADDRS`]
    /// addresses; a dial no transport ran says nothing.
    #[test]
    fn the_walk_is_bounded_and_only_transport_failures_count() {
        let relay = PeerId::random();
        let at = circuit(relay);
        let layered = |n: usize| {
            let mut e: Box<dyn Error + Send + Sync> = Box::new(ConnectError::ResourceLimitExceeded);
            for _ in 0..n {
                e = Box::new(Layer(e));
            }
            io::Error::other(e)
        };
        let outcome = |e| match failed_at(&at, e)[..] {
            [Failed::Circuit { outcome, .. }] => outcome,
            ref other => panic!("{other:?}"),
        };
        assert_eq!(outcome(layered(MAX_CHAIN - 1)), CircuitOutcome::Busy);
        assert_eq!(outcome(layered(MAX_CHAIN)), CircuitOutcome::NoAnswer);
        assert_eq!(outcome(io::Error::other(Loop)), CircuitOutcome::NoAnswer);
        assert_eq!(
            failed_at(&direct(), io::Error::other(Loop)),
            [Failed::Direct(AddrOutcome::NoAnswer)]
        );

        let many: Vec<_> = (0..MAX_ADDRS + 3)
            .map(|_| {
                (
                    direct(),
                    TransportError::Other(io::ErrorKind::ConnectionRefused.into()),
                )
            })
            .collect();
        assert_eq!(
            dial_failures(&DialError::Transport(many)),
            vec![Failed::Direct(AddrOutcome::Refused); MAX_ADDRS]
        );

        for e in [
            DialError::Aborted,
            DialError::NoAddresses,
            DialError::Denied {
                cause: ConnectionDenied::new(io::Error::other("not admitted")),
            },
            DialError::Transport(Vec::new()),
        ] {
            assert!(dial_failures(&e).is_empty(), "{e:?}");
        }
    }
}
