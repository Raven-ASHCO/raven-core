//! Reachability words shared by raven-node (which decides) and ash (which
//! explains them): the AutoNAT verdict and the reachability class of the p2p
//! host (any-network plan §3 Phase 1 items 5 and 7). Pure: no I/O, no
//! addresses.
//!
//! `public` needs two *independent* checks: two AutoNAT servers on different
//! networks (a /24 or a /48 other than each other's and the tested address's
//! own) that both reached the same IP of ours. In Phase 1 those servers are
//! the node's own relays started with `raven-node relay --autonat-server`,
//! each asked by a client of its own; with one such relay a node is at most
//! `unconfirmed`.

/// What the AutoNAT checks that count say about this node's addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatVerdict {
    /// Two independent servers reached one of our IPs.
    Public,
    /// One independent server reached us; a second has not (yet).
    Unconfirmed,
    /// Only failures counted.
    Private,
    /// Nothing counted yet.
    Unknown,
}

impl NatVerdict {
    pub const ALL: [Self; 4] = [
        Self::Public,
        Self::Unconfirmed,
        Self::Private,
        Self::Unknown,
    ];

    /// `public` | `unconfirmed` | `private` | `unknown`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Unconfirmed => "unconfirmed",
            Self::Private => "private",
            Self::Unknown => "unknown",
        }
    }

    /// The exact word; anything else (a newer daemon's word, another
    /// spelling, empty) reads `Unknown`.
    pub fn parse(s: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s)
            .unwrap_or(Self::Unknown)
    }
}

/// How contacts outside this network can reach the node ([`reach_class`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachClass {
    /// Directly: it listens and two independent checks reached it.
    Public,
    /// Through the router's UPnP port mapping, not refuted by the checks.
    Mapped,
    /// Through a relay that holds a reservation for it.
    Relayed,
    /// Not at all: no listener, or the checks failed, and no relay.
    Unreachable,
    /// Not known yet: nobody has checked, and no relay holds it.
    Unknown,
}

impl ReachClass {
    pub const ALL: [Self; 5] = [
        Self::Public,
        Self::Mapped,
        Self::Relayed,
        Self::Unreachable,
        Self::Unknown,
    ];

    /// `public` | `mapped` | `relayed` | `unreachable` | `unknown`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Mapped => "mapped",
            Self::Relayed => "relayed",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }

    /// The exact word; anything else reads `Unknown`.
    pub fn parse(s: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .unwrap_or(Self::Unknown)
    }
}

/// What the class is decided from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReachFacts {
    pub verdict: NatVerdict,
    /// The router mapped our port (UPnP).
    pub upnp_mapped: bool,
    /// Relays holding an active reservation for us.
    pub reservations: usize,
    /// At least one (non-circuit) listener is open.
    pub listening: bool,
    /// Auto-reach (`docs/design/2026-10-auto-reach.md` §4.4): an
    /// authenticated contact reached a listener directly from a globally
    /// routable IP that is not this node's own, within the last 24 h, and not
    /// right after this node dialled it (a punch). Stronger evidence than an
    /// AutoNAT server's, which may lie.
    pub reached_outside: bool,
}

/// `public` needs two independent checks, or a contact that reached a
/// listener from outside (auto-reach), AND an open listener; a UPnP mapping
/// is `mapped` unless the checks say private; any active reservation makes a
/// node `relayed`; no listener, or a private verdict, without a reservation
/// is `unreachable`; else `unknown`.
pub fn reach_class(f: ReachFacts) -> ReachClass {
    if f.listening && (f.verdict == NatVerdict::Public || f.reached_outside) {
        return ReachClass::Public;
    }
    if f.listening && f.upnp_mapped && f.verdict != NatVerdict::Private {
        return ReachClass::Mapped;
    }
    if f.reservations > 0 {
        return ReachClass::Relayed;
    }
    if !f.listening || f.verdict == NatVerdict::Private {
        return ReachClass::Unreachable;
    }
    ReachClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every listening x verdict x UPnP x reservations row.
    #[test]
    fn reach_class_table() {
        for listening in [false, true] {
            for verdict in NatVerdict::ALL {
                for upnp_mapped in [false, true] {
                    for reservations in [0, 1, 2] {
                        let f = ReachFacts {
                            verdict,
                            upnp_mapped,
                            reservations,
                            listening,
                            reached_outside: false,
                        };
                        let class = reach_class(f);
                        let row = format!("{f:?} -> {class:?}");
                        // Public needs both checks and a listener.
                        assert_eq!(
                            class == ReachClass::Public,
                            listening && verdict == NatVerdict::Public,
                            "{row}"
                        );
                        // A mapping the checks refuted is never `mapped`.
                        if verdict == NatVerdict::Private || !listening || !upnp_mapped {
                            assert_ne!(class, ReachClass::Mapped, "{row}");
                        }
                        if class != ReachClass::Public && class != ReachClass::Mapped {
                            let expected = if reservations > 0 {
                                ReachClass::Relayed
                            } else if !listening || verdict == NatVerdict::Private {
                                ReachClass::Unreachable
                            } else {
                                ReachClass::Unknown
                            };
                            assert_eq!(class, expected, "{row}");
                        }
                    }
                }
            }
        }
        let facts = |verdict, upnp_mapped, reservations, listening| ReachFacts {
            verdict,
            upnp_mapped,
            reservations,
            listening,
            reached_outside: false,
        };
        use NatVerdict as V;
        use ReachClass as C;
        for (f, class) in [
            (facts(V::Public, false, 0, true), C::Public),
            (facts(V::Public, true, 2, true), C::Public),
            // One check is not enough, however good the rest looks.
            (facts(V::Unconfirmed, false, 0, true), C::Unknown),
            (facts(V::Unconfirmed, false, 1, true), C::Relayed),
            (facts(V::Unconfirmed, true, 1, true), C::Mapped),
            (facts(V::Unknown, true, 0, true), C::Mapped),
            (facts(V::Private, true, 0, true), C::Unreachable),
            (facts(V::Private, true, 1, true), C::Relayed),
            // A verdict without a listener is about nothing that listens.
            (facts(V::Public, true, 0, false), C::Unreachable),
            (facts(V::Public, false, 1, false), C::Relayed),
            (facts(V::Unknown, false, 0, false), C::Unreachable),
            (facts(V::Unknown, false, 0, true), C::Unknown),
        ] {
            assert_eq!(reach_class(f), class, "{f:?}");
        }
        // Auto-reach: a contact that came in from outside makes a listening
        // node public, whatever the checks say; without a listener it is
        // about nothing that listens.
        let reached = |verdict, listening| ReachFacts {
            reached_outside: true,
            ..facts(verdict, false, 0, listening)
        };
        assert_eq!(reach_class(reached(V::Unknown, true)), C::Public);
        assert_eq!(reach_class(reached(V::Private, true)), C::Public);
        assert_eq!(reach_class(reached(V::Unknown, false)), C::Unreachable);
    }

    #[test]
    fn words_round_trip_and_unknown_words_read_unknown() {
        for v in NatVerdict::ALL {
            assert_eq!(NatVerdict::parse(v.as_str()), v);
        }
        for c in ReachClass::ALL {
            assert_eq!(ReachClass::parse(c.as_str()), c);
        }
        for odd in [
            "",
            "Public",
            "PUBLIC",
            " public",
            "reachable",
            "mapped 7423",
        ] {
            assert_eq!(NatVerdict::parse(odd), NatVerdict::Unknown, "{odd:?}");
            assert_eq!(ReachClass::parse(odd), ReachClass::Unknown, "{odd:?}");
        }
        assert_eq!(NatVerdict::parse("mapped"), NatVerdict::Unknown);
        assert_eq!(ReachClass::parse("unconfirmed"), ReachClass::Unknown);
    }
}
