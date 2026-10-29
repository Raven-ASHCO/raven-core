//! How each received message came to this node (field test E2 r9 #12, #15):
//! the carrier of the link it arrived on (LAN, Internet direct, p2p, Tor,
//! Bluetooth nearby) or a keeper (friend custody: fetched from a friend who
//! held a sealed copy). For `raven inbox`, the group view and one log line
//! per message.
//!
//! - **In memory only**, in the receiving process (raven-node), bounded
//!   ([`MAX_KEPT`]), like the last delivery paths: it starts over when
//!   raven-node restarts, and nothing is written for a chat message. The
//!   group store keeps a group message's path with the message itself
//!   ([`current`], read while the group store takes the frame).
//! - **Never an address**: a carrier word, the sender's key and the message
//!   id. The log line names the sender by raven-node's short tag only.

use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::outbox::OutboxCarrier;
use crate::security_events::Via;

/// How a received message came.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArrivedVia {
    Lan,
    /// Internet direct (the friend's own listener or ours, no relay).
    Internet,
    P2p,
    /// Through a p2p relay circuit (the Raven link still ends at the friend).
    Relayed,
    Tor,
    Nearby,
    /// From a keeper: a friend held a sealed copy (friend custody, letters,
    /// handoff).
    Keeper,
}

impl ArrivedVia {
    /// Every value, in token order.
    pub const ALL: [ArrivedVia; 7] = [
        ArrivedVia::Lan,
        ArrivedVia::Internet,
        ArrivedVia::P2p,
        ArrivedVia::Relayed,
        ArrivedVia::Tor,
        ArrivedVia::Nearby,
        ArrivedVia::Keeper,
    ];

    /// The stable token (IPC, the group store).
    pub fn token(self) -> &'static str {
        match self {
            ArrivedVia::Lan => "lan",
            ArrivedVia::Internet => "internet",
            ArrivedVia::P2p => "p2p",
            ArrivedVia::Relayed => "relayed",
            ArrivedVia::Tor => "tor",
            ArrivedVia::Nearby => "nearby",
            ArrivedVia::Keeper => "keeper",
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.token() == token.trim())
    }

    /// The words after "via" (or alone, for a keeper): `LAN`, `Tor`, ...
    pub fn words(self) -> &'static str {
        match self {
            ArrivedVia::Lan => "LAN",
            ArrivedVia::Internet => "direct",
            ArrivedVia::P2p => "p2p",
            ArrivedVia::Relayed => "a relay",
            ArrivedVia::Tor => "Tor",
            ArrivedVia::Nearby => "Bluetooth nearby",
            ArrivedVia::Keeper => "a keeper",
        }
    }

    /// "via Tor", "from a keeper".
    pub fn phrase(self) -> String {
        match self {
            ArrivedVia::Keeper => "from a keeper".into(),
            other => format!("via {}", other.words()),
        }
    }

    /// The carrier of an outbox route as an arrival.
    pub fn of_carrier(carrier: OutboxCarrier) -> Self {
        match carrier {
            OutboxCarrier::Lan => ArrivedVia::Lan,
            OutboxCarrier::Internet => ArrivedVia::Internet,
            OutboxCarrier::P2p => ArrivedVia::P2p,
            OutboxCarrier::Nearby => ArrivedVia::Nearby,
            OutboxCarrier::Onion => ArrivedVia::Tor,
        }
    }

    /// How the link or object a security check names came; `None` for this
    /// computer's own state.
    pub fn of_via(via: Via) -> Option<Self> {
        match via {
            Via::DirectLink(c) | Via::Dial(c) => Some(Self::of_carrier(c)),
            Via::Custodian(_) => Some(ArrivedVia::Keeper),
            Via::Relay => Some(ArrivedVia::Relayed),
            Via::Local => None,
        }
    }
}

/// One received message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrival {
    /// The sender's identity key (its user key when known, else its device
    /// key).
    pub sender: [u8; 32],
    /// The ATSAM message id of the copy that came (a group copy's own id,
    /// not the group message's).
    pub message_id: [u8; 16],
    pub via: ArrivedVia,
    pub at_ms: u64,
    /// The copy carried a group frame.
    pub group: bool,
}

/// Arrivals kept, newest last.
pub const MAX_KEPT: usize = 1024;

static KEPT: Mutex<VecDeque<Arrival>> = Mutex::new(VecDeque::new());
static HOOK: OnceLock<fn(&Arrival)> = OnceLock::new();

thread_local! {
    static CURRENT: Cell<Option<ArrivedVia>> = const { Cell::new(None) };
}

/// raven-node's log line for every arrival (set once at start; later calls
/// are ignored).
pub fn set_hook(hook: fn(&Arrival)) {
    let _ = HOOK.set(hook);
}

/// Keep `a` (dropping the oldest beyond [`MAX_KEPT`]) and tell the hook.
pub fn note(a: Arrival) {
    {
        let mut kept = KEPT.lock().unwrap_or_else(PoisonError::into_inner);
        if kept.len() >= MAX_KEPT {
            kept.pop_front();
        }
        kept.push_back(a);
    }
    if let Some(hook) = HOOK.get() {
        hook(&a);
    }
}

/// The arrivals kept, oldest first.
pub fn recent() -> Vec<Arrival> {
    KEPT.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .copied()
        .collect()
}

/// Run `f` with `via` as how the message being taken came ([`current`]),
/// on this thread only; the previous value comes back after.
pub fn during<T>(via: Option<ArrivedVia>, f: impl FnOnce() -> T) -> T {
    let before = CURRENT.with(|c| c.replace(via));
    let out = f();
    CURRENT.with(|c| c.set(before));
    out
}

/// How the message this thread is taking now came ([`during`]); `None`
/// outside one (a test, the expiry archive, a retry from the store).
pub fn current() -> Option<ArrivedVia> {
    CURRENT.with(Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_and_words_name_no_address() {
        for v in ArrivedVia::ALL {
            assert_eq!(ArrivedVia::parse(v.token()), Some(v));
            assert!(!v.words().is_empty());
        }
        assert_eq!(ArrivedVia::parse("carrier pigeon"), None);
        assert_eq!(ArrivedVia::Tor.phrase(), "via Tor");
        assert_eq!(ArrivedVia::Keeper.phrase(), "from a keeper");
        assert_eq!(
            ArrivedVia::of_via(Via::DirectLink(OutboxCarrier::Onion)),
            Some(ArrivedVia::Tor)
        );
        assert_eq!(
            ArrivedVia::of_via(Via::Custodian([1; 32])),
            Some(ArrivedVia::Keeper)
        );
        assert_eq!(ArrivedVia::of_via(Via::Local), None);
    }

    #[test]
    fn during_sets_current_on_this_thread_only_and_restores_it() {
        assert_eq!(current(), None);
        let inner = during(Some(ArrivedVia::Lan), || {
            let other = std::thread::spawn(current).join().unwrap();
            assert_eq!(other, None, "another thread sees nothing");
            during(Some(ArrivedVia::Keeper), current)
        });
        assert_eq!(inner, Some(ArrivedVia::Keeper));
        assert_eq!(current(), None);
    }

    #[test]
    fn kept_arrivals_are_bounded_newest_last() {
        let a = |n: u16| Arrival {
            sender: [9; 32],
            message_id: {
                let mut id = [0xA7; 16];
                id[..2].copy_from_slice(&n.to_be_bytes());
                id
            },
            via: ArrivedVia::Tor,
            at_ms: u64::from(n),
            group: false,
        };
        for n in 0..(MAX_KEPT as u16 + 5) {
            note(a(n));
        }
        let mine: Vec<Arrival> = recent()
            .into_iter()
            .filter(|r| r.message_id[2..] == [0xA7; 14])
            .collect();
        assert!(mine.len() <= MAX_KEPT);
        assert_eq!(mine.last().map(|r| r.at_ms), Some(MAX_KEPT as u64 + 4));
    }
}
