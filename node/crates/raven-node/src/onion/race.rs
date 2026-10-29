//! The outbox's race between the direct paths and Tor (design
//! `docs/design/2026-10-tor-fallback.md` §2, §3.4; "happy eyeballs").
//!
//! One outbox attempt with an onion route and any other route holds a
//! [`RaceGuard`]. Its dials carry a [`RaceTicket`] (in
//! [`crate::learning::DialMeta::race`]): the onion dial the onion side's,
//! every LAN, Internet direct and p2p dial the direct side's. The first dial
//! that completes the Raven handshake (the contact's RLB1 offer read and
//! verified: `netutil::ReplyCollector::begin`, right before the first frame)
//! [`claim`]s the attempt for its side and writes its frames; a dial of the
//! other side that gets there later writes nothing and ends with
//! [`RACE_LOST`], which is no route failure. A dial of the losing side still
//! in flight is cut at once ([`lost`]).
//!
//! The onion dial waits for its head start ([`RaceGuard::wait_head_start`])
//! unless every direct route already failed ([`RaceGuard::direct_exhausted`])
//! or the direct side already won.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// A dial that lost the race: it wrote no frame. Not a route failure.
pub(crate) const RACE_LOST: &str = "RACE_LOST: another path to this contact completed its \
    handshake first; nothing was written on this one";

/// Does `err` say the dial lost the race ([`RACE_LOST`])?
pub(crate) fn is_race_lost(err: &str) -> bool {
    err.starts_with("RACE_LOST")
}

/// The two sides of the race.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Side {
    /// LAN, Internet direct, p2p (direct, hole-punched or relayed).
    Direct,
    /// Tor.
    Onion,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Self::Direct => Self::Onion,
            Self::Onion => Self::Direct,
        }
    }
}

/// One dial's place in one race (a copy is cheap; a dial without one is in
/// no race).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RaceTicket {
    id: u64,
    side: Side,
}

#[derive(Default)]
struct State {
    winner: Option<Side>,
    direct_exhausted: bool,
}

struct Race {
    state: Mutex<State>,
    /// Wakes [`RaceGuard::wait_head_start`].
    changed: Condvar,
    /// The winner, for the async waiters ([`lost`]).
    decided: tokio::sync::watch::Sender<Option<Side>>,
}

impl Race {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn decide(&self, side: Side) -> bool {
        let mut state = self.lock();
        match state.winner {
            Some(w) => w == side,
            None => {
                state.winner = Some(side);
                drop(state);
                self.decided.send_replace(Some(side));
                self.changed.notify_all();
                true
            }
        }
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static RACES: Mutex<Option<HashMap<u64, Arc<Race>>>> = Mutex::new(None);

fn races() -> std::sync::MutexGuard<'static, Option<HashMap<u64, Arc<Race>>>> {
    RACES.lock().unwrap_or_else(PoisonError::into_inner)
}

fn find(id: u64) -> Option<Arc<Race>> {
    races().as_ref()?.get(&id).cloned()
}

/// One attempt's race. Dropping it ends the race: an undecided one goes to
/// the direct side (an onion dial still waiting or connecting ends with
/// [`RACE_LOST`]), and its tickets name no race any more.
pub(crate) struct RaceGuard {
    id: u64,
    race: Arc<Race>,
}

impl RaceGuard {
    pub(crate) fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let (decided, _) = tokio::sync::watch::channel(None);
        let race = Arc::new(Race {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            decided,
        });
        races()
            .get_or_insert_with(HashMap::new)
            .insert(id, race.clone());
        Self { id, race }
    }

    /// A ticket for a dial of `side`.
    pub(crate) fn ticket(&self, side: Side) -> RaceTicket {
        RaceTicket { id: self.id, side }
    }

    /// Who won so far.
    pub(crate) fn winner(&self) -> Option<Side> {
        self.race.lock().winner
    }

    /// Every direct route of the attempt was tried (none won): the onion
    /// dial needs no more head start.
    pub(crate) fn direct_exhausted(&self) {
        self.race.lock().direct_exhausted = true;
        self.race.changed.notify_all();
    }

    /// The onion dial's head start (blocking): back after `head_start`, at
    /// once when the direct routes are exhausted, `false` when the direct
    /// side already won (nothing to dial).
    pub(crate) fn wait_head_start(&self, head_start: Duration) -> bool {
        let until = Instant::now() + head_start;
        let mut state = self.race.lock();
        loop {
            if let Some(w) = state.winner {
                return w == Side::Onion;
            }
            if state.direct_exhausted {
                return true;
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            state = self
                .race
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

impl Drop for RaceGuard {
    fn drop(&mut self) {
        // Whatever still runs for the onion side stops.
        self.race.decide(Side::Direct);
        if let Some(map) = races().as_mut() {
            map.remove(&self.id);
        }
    }
}

/// Claim the race for `ticket`'s side: `true` when it is undecided (it is
/// now this side's) or already this side's; `false` when the other side won.
/// A ticket of a race that ended is refused too: its attempt is over.
pub(crate) fn claim(ticket: RaceTicket) -> bool {
    find(ticket.id).is_some_and(|race| race.decide(ticket.side))
}

/// Resolves once the other side has won `ticket`'s race (or the race ended
/// without this side); never while this side may still win or has won.
pub(crate) async fn lost(ticket: RaceTicket) {
    let Some(race) = find(ticket.id) else {
        return;
    };
    let mut rx = race.decided.subscribe();
    drop(race);
    let other = ticket.side.other();
    // `wait_for` checks the current value first; an Err means every sender
    // is gone (the race ended), which is a loss for whoever still waits.
    let _ = rx.wait_for(|w| *w == Some(other)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_claim_wins_and_the_other_side_loses() {
        let race = RaceGuard::new();
        let (direct, onion) = (race.ticket(Side::Direct), race.ticket(Side::Onion));
        assert_eq!(race.winner(), None);
        assert!(claim(onion));
        assert!(claim(onion), "the winner's later dials go on");
        assert!(!claim(direct));
        assert_eq!(race.winner(), Some(Side::Onion));
    }

    #[test]
    fn races_are_separate() {
        let a = RaceGuard::new();
        let b = RaceGuard::new();
        assert!(claim(a.ticket(Side::Direct)));
        assert!(claim(b.ticket(Side::Onion)));
        assert_eq!(a.winner(), Some(Side::Direct));
        assert_eq!(b.winner(), Some(Side::Onion));
    }

    #[test]
    fn an_ended_race_refuses_every_ticket_and_stops_the_onion_side() {
        let race = RaceGuard::new();
        let onion = race.ticket(Side::Onion);
        drop(race);
        assert!(!claim(onion));
    }

    #[test]
    fn the_head_start_ends_early_when_direct_routes_are_exhausted() {
        let race = Arc::new(RaceGuard::new());
        let r2 = race.clone();
        let t = Instant::now();
        let waiter = std::thread::spawn(move || r2.wait_head_start(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(50));
        race.direct_exhausted();
        assert!(waiter.join().unwrap());
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn the_head_start_ends_with_no_dial_when_the_direct_side_won() {
        let race = Arc::new(RaceGuard::new());
        let r2 = race.clone();
        let waiter = std::thread::spawn(move || r2.wait_head_start(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(50));
        assert!(claim(race.ticket(Side::Direct)));
        assert!(!waiter.join().unwrap());
    }

    #[test]
    fn the_head_start_runs_out_on_its_own() {
        let race = RaceGuard::new();
        let t = Instant::now();
        assert!(race.wait_head_start(Duration::from_millis(80)));
        assert!(t.elapsed() >= Duration::from_millis(80));
    }

    #[tokio::test]
    async fn lost_resolves_only_for_the_losing_side() {
        let race = RaceGuard::new();
        let (direct, onion) = (race.ticket(Side::Direct), race.ticket(Side::Onion));
        let pending = tokio::time::timeout(Duration::from_millis(50), lost(direct)).await;
        assert!(pending.is_err(), "undecided: nobody lost yet");
        assert!(claim(onion));
        tokio::time::timeout(Duration::from_secs(2), lost(direct))
            .await
            .expect("the direct side lost");
        let winner = tokio::time::timeout(Duration::from_millis(50), lost(onion)).await;
        assert!(winner.is_err(), "the winner never loses");
    }

    #[tokio::test]
    async fn an_ended_race_counts_as_lost_for_the_onion_side() {
        let race = RaceGuard::new();
        let onion = race.ticket(Side::Onion);
        let waiting = tokio::spawn(lost(onion));
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(race);
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .expect("resolved")
            .unwrap();
    }

    #[test]
    fn race_lost_is_recognised() {
        assert!(is_race_lost(RACE_LOST));
        assert!(!is_race_lost("INTERNET_DIAL_PEER_CLOSED"));
    }
}
