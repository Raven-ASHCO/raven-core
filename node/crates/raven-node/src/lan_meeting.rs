//! Meeting mode in raven-node (Phase 3 P3.C2, cutoff M1): `raven lan on --for
//! <time>` keeps the local network on until that time, then turns it off as
//! `raven lan off` does ([`crate::lan_direct::set_lan_on`]: the listener
//! closes its port and its connections, LAN dials and custody links over LAN
//! stop, and the LAN beacon follows `lan_on()`).
//!
//! raven-node never writes the setting: ash saves `lan_off` (node_policy.json)
//! and the meeting time ([`raven_core::lan_meeting`], sealed in a sealed
//! profile) and tells a running node with IPC `SetLan` ([`apply`]). At start
//! [`seed`] reads both: LAN is on while `raven lan off` is not in effect and
//! the meeting time, if any, has not come
//! ([`raven_core::lan_meeting::lan_on_at`]), so a restart after it stays off.
//! A meeting time this process cannot read yet (the at-rest key of a sealed
//! profile is still loading; nobody is admitted before then anyway) keeps LAN
//! off until it can ([`run`] reads it again every [`POLL`]); one that does
//! not open keeps LAN off until `raven lan on` replaces it (fail closed).
//!
//! [`run`] watches Raven's clock (the lab clock in a debug build): a laptop
//! that slept through the meeting time, or a clock set ahead, closes within
//! a [`POLL`]. It also watches the time that really passed since the meeting
//! time was set or read (a monotonic deadline, at most
//! [`raven_core::lan_meeting::MAX_MEETING_MS`] away), and closes at whichever
//! comes first, so a clock set back during a meeting does not keep LAN open
//! longer; a saved meeting time more than a day ahead counts as over
//! ([`raven_core::lan_meeting::lan_on_at`]). Log lines are fixed words: never
//! the time, which says when a meeting ended.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use raven_core::at_rest::AtRestError;
use tokio::sync::watch;

/// How often [`run`] looks at Raven's clock while a meeting time is ahead,
/// and at a meeting time it could not read yet.
pub(crate) const POLL: Duration = Duration::from_secs(1);

/// The service log's line when the meeting time comes.
const OVER_LINE: &str = "raven-node lan_direct: the meeting time is over: LAN off (`raven lan on \
                         --for 1h` opens it again)";

/// What this process holds about the meeting time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Meeting {
    /// None: LAN follows `raven lan on|off` alone.
    None,
    /// LAN turns off at this time (ms since the epoch on Raven's clock).
    Until(u64),
    /// A meeting time is saved that this process cannot read yet: LAN stays
    /// off, and the watch reads it again.
    Waiting,
    /// A saved meeting time that does not open or parse: LAN stays off until
    /// `raven lan on` replaces it.
    Unreadable,
}

/// One process's meeting time and the LAN switch it turns: production's
/// ([`crate::lan_direct::set_lan_on`], [`crate::lan_direct::lan_on`]), or a
/// test's own.
pub(crate) struct Meetings {
    state: watch::Sender<Meeting>,
    /// Start, `SetLan` and the watch change the switch and the state one at a
    /// time, so a `SetLan` is never undone by a decision taken before it.
    turn: Mutex<()>,
    set_lan: Box<dyn Fn(bool) + Send + Sync>,
    lan_on: Box<dyn Fn() -> bool + Send + Sync>,
    /// The meeting's end on the monotonic clock (`mono`): set with every
    /// [`Meeting::Until`], as far ahead as the meeting time was then, at
    /// most a day. LAN closes when it passes even if Raven's clock was set
    /// back meanwhile.
    deadline: Mutex<Option<Instant>>,
    /// The monotonic clock (`Instant::now`; a test's own).
    mono: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl Meetings {
    pub(crate) fn new(
        set_lan: impl Fn(bool) + Send + Sync + 'static,
        lan_on: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            state: watch::Sender::new(Meeting::None),
            turn: Mutex::new(()),
            set_lan: Box::new(set_lan),
            lan_on: Box::new(lan_on),
            deadline: Mutex::new(None),
            mono: Box::new(Instant::now),
        }
    }

    /// These meetings on a test's own monotonic clock.
    #[cfg(test)]
    fn with_mono(mut self, mono: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        self.mono = Box::new(mono);
        self
    }

    /// The meeting time as this process holds it now.
    pub(crate) fn meeting(&self) -> Meeting {
        *self.state.borrow()
    }

    /// A meeting time still ahead at `now_ms` and on the monotonic clock
    /// ([`meeting_on`]).
    pub(crate) fn meeting_on(&self, now_ms: u64) -> bool {
        matches!(self.meeting(), Meeting::Until(until)
            if raven_core::lan_meeting::lan_on_at(false, Some(until), now_ms)
                && !self.past_deadline())
    }

    /// The monotonic deadline of the meeting time held has passed.
    fn past_deadline(&self) -> bool {
        let deadline = *self.deadline.lock().unwrap_or_else(PoisonError::into_inner);
        deadline.is_some_and(|deadline| (self.mono)() >= deadline)
    }

    /// Hold `meeting`, seen at `now_ms` (with the turn held): a meeting time
    /// also gets its monotonic deadline, as far ahead as it is now (at most
    /// a day).
    fn hold(&self, meeting: Meeting, now_ms: u64) {
        let deadline = match meeting {
            Meeting::Until(until) => Some(
                (self.mono)()
                    + Duration::from_millis(
                        until
                            .saturating_sub(now_ms)
                            .min(raven_core::lan_meeting::MAX_MEETING_MS),
                    ),
            ),
            _ => None,
        };
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner) = deadline;
        self.state.send_replace(meeting);
    }

    fn turn(&self) -> std::sync::MutexGuard<'_, ()> {
        self.turn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// At start: LAN as node_policy.json's `lan_off` says (`Err`: the file
    /// cannot be read, so off: the owner's fail-closed rule) and the saved
    /// meeting time (`saved`, read only while LAN is on in the policy) at
    /// `now_ms`.
    pub(crate) fn start(
        &self,
        lan_off: Result<bool, String>,
        saved: impl FnOnce() -> Result<Option<u64>, AtRestError>,
        now_ms: u64,
    ) {
        let (on, meeting) = match lan_off {
            Err(e) => {
                eprintln!(
                    "raven-node lan_direct: node_policy.json unreadable ({e}): LAN stays off \
                     until `raven lan on`"
                );
                (false, Meeting::None)
            }
            Ok(true) => (false, Meeting::None),
            Ok(false) => match saved() {
                Ok(None) => (true, Meeting::None),
                Ok(Some(until)) => {
                    let on = raven_core::lan_meeting::lan_on_at(false, Some(until), now_ms);
                    if !on {
                        eprintln!("{OVER_LINE}");
                    }
                    (on, Meeting::Until(until))
                }
                Err(e) if e.is_unavailable() => {
                    eprintln!(
                        "raven-node lan_direct: LAN waits for the at-rest key: the meeting time \
                         is sealed"
                    );
                    (false, Meeting::Waiting)
                }
                Err(e) => {
                    note_unreadable(&e);
                    (false, Meeting::Unreadable)
                }
            },
        };
        let _turn = self.turn();
        (self.set_lan)(on);
        self.hold(meeting, now_ms);
    }

    /// IPC `SetLan` (ash has saved the setting): LAN `on` or off now, with
    /// the meeting time `until_ms` (none: no meeting time; an earlier one
    /// is dropped, and so is one sent with `off`).
    pub(crate) fn apply(&self, on: bool, until_ms: Option<u64>, now_ms: u64) {
        let until_ms = until_ms.filter(|_| on);
        let meeting = until_ms.map_or(Meeting::None, Meeting::Until);
        let lan = raven_core::lan_meeting::lan_on_at(!on, until_ms, now_ms);
        let _turn = self.turn();
        (self.set_lan)(lan);
        self.hold(meeting, now_ms);
    }

    /// For as long as the task lives: LAN off when the meeting time comes on
    /// `now`'s clock or its monotonic deadline passes (looked at every
    /// `poll`), and a meeting time that could not be read yet read again
    /// every `poll` until it can (`data_dir`).
    pub(crate) async fn watch(
        &self,
        data_dir: &Path,
        now: impl Fn() -> u64,
        poll: Duration,
    ) -> Infallible {
        let mut changed = self.state.subscribe();
        loop {
            let current = *changed.borrow_and_update();
            let look_again = match current {
                Meeting::Until(until)
                    if !raven_core::lan_meeting::lan_on_at(false, Some(until), now())
                        || self.past_deadline() =>
                {
                    self.close_at(until);
                    false
                }
                Meeting::Until(_) => true,
                Meeting::Waiting => {
                    let dd = data_dir.to_path_buf();
                    let saved = tokio::task::spawn_blocking(move || {
                        raven_core::lan_meeting::load_until(&dd)
                    })
                    .await
                    .unwrap_or_else(|e| Err(AtRestError::Io(e.to_string())));
                    match saved {
                        Err(e) if e.is_unavailable() => true,
                        saved => {
                            self.read_at_last(saved, now());
                            false
                        }
                    }
                }
                Meeting::None | Meeting::Unreadable => false,
            };
            if look_again {
                let _ = tokio::time::timeout(poll, changed.changed()).await;
            } else if changed.changed().await.is_err() {
                // The state lives as long as this watch: never.
                return std::future::pending().await;
            }
        }
    }

    /// The meeting time `until` came: LAN off, unless a `SetLan` changed it
    /// meanwhile or LAN is off already.
    fn close_at(&self, until: u64) {
        let _turn = self.turn();
        if self.meeting() == Meeting::Until(until) && (self.lan_on)() {
            (self.set_lan)(false);
            eprintln!("{OVER_LINE}");
        }
    }

    /// The meeting time could be read at last (`saved`, at `now_ms`): LAN as
    /// it says, unless a `SetLan` came meanwhile.
    fn read_at_last(&self, saved: Result<Option<u64>, AtRestError>, now_ms: u64) {
        let _turn = self.turn();
        if self.meeting() != Meeting::Waiting {
            return;
        }
        let (on, meeting) = match saved {
            Ok(None) => (true, Meeting::None),
            Ok(Some(until)) => (
                raven_core::lan_meeting::lan_on_at(false, Some(until), now_ms),
                Meeting::Until(until),
            ),
            Err(e) => {
                note_unreadable(&e);
                (false, Meeting::Unreadable)
            }
        };
        if !on && matches!(meeting, Meeting::Until(_)) {
            eprintln!("{OVER_LINE}");
        }
        (self.set_lan)(on);
        self.hold(meeting, now_ms);
    }
}

/// A saved meeting time that will not open: say so once (the error names a
/// kind or a parse failure, never the time).
fn note_unreadable(e: &AtRestError) {
    eprintln!(
        "raven-node lan_direct: the saved meeting time cannot be read ({e}): LAN stays off \
         until `raven lan on`"
    );
}

/// This process's meeting time, turning its LAN switch.
fn meetings() -> &'static Meetings {
    static MEETINGS: OnceLock<Meetings> = OnceLock::new();
    MEETINGS.get_or_init(|| Meetings::new(crate::lan_direct::set_lan_on, crate::lan_direct::lan_on))
}

/// Service start (and `raven-node ipc`): LAN on or off from node_policy.json
/// and the saved meeting time, before the LAN listener starts.
pub(crate) fn seed(data_dir: &Path) {
    meetings().start(
        raven_core::node_policy::try_load_policy(data_dir)
            .map(|policy| policy.lan_off)
            .map_err(|e| e.to_string()),
        || raven_core::lan_meeting::load_until(data_dir),
        raven_core::clock::now_ms(),
    );
}

/// IPC `SetLan`: LAN `on` or off now, with the meeting time `until_ms`.
pub(crate) fn apply(on: bool, until_ms: Option<u64>) {
    meetings().apply(on, until_ms, raven_core::clock::now_ms());
}

/// Meeting mode is on at `now_ms`: `raven lan on --for <time>` holds a
/// meeting time still ahead (the LAN beacon's join round goes while it does,
/// Phase 3 P3.C3, owner decision OD-C7).
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
pub(crate) fn meeting_on(now_ms: u64) -> bool {
    meetings().meeting_on(now_ms)
}

/// The service's meeting watch ([`Meetings::watch`] on Raven's clock).
pub(crate) async fn run(data_dir: PathBuf) -> Result<(), String> {
    match meetings()
        .watch(&data_dir, raven_core::clock::now_ms, POLL)
        .await {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    const T0: u64 = 1_800_000_000_000;
    const MIN: u64 = 60_000;

    /// A switch of the test's own and a clock it moves.
    fn rig() -> (Arc<Meetings>, watch::Receiver<bool>, Arc<AtomicU64>) {
        let (switch, on) = watch::channel(false);
        let switch = Arc::new(switch);
        let (set, get) = (Arc::clone(&switch), Arc::clone(&switch));
        let meetings = Meetings::new(
            move |on| {
                set.send_replace(on);
            },
            move || *get.borrow(),
        );
        (Arc::new(meetings), on, Arc::new(AtomicU64::new(T0)))
    }

    /// [`rig`] on a monotonic clock the test moves too (ms past its start).
    fn rig_mono() -> (
        Arc<Meetings>,
        watch::Receiver<bool>,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
    ) {
        let (switch, on) = watch::channel(false);
        let switch = Arc::new(switch);
        let (set, get) = (Arc::clone(&switch), Arc::clone(&switch));
        let (base, mono) = (Instant::now(), Arc::new(AtomicU64::new(0)));
        let m = Arc::clone(&mono);
        let meetings = Meetings::new(
            move |on| {
                set.send_replace(on);
            },
            move || *get.borrow(),
        )
        .with_mono(move || base + Duration::from_millis(m.load(Ordering::SeqCst)));
        (Arc::new(meetings), on, Arc::new(AtomicU64::new(T0)), mono)
    }

    /// B-1: a clock set back by two hours during a 30-minute meeting does
    /// not keep LAN open: it closes once 30 minutes really passed (the
    /// monotonic deadline), and meeting mode ends with it. (Set back by more
    /// than a day it closes at once: [`a_meeting_time_more_than_a_day_ahead_is_over`].)
    #[test]
    fn a_clock_set_back_does_not_keep_the_meeting_open() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (m, mut on, clock, mono) = rig_mono();
            let dir = tempfile::tempdir().unwrap();
            let (w, c, dd) = (Arc::clone(&m), Arc::clone(&clock), dir.path().to_path_buf());
            let task = tokio::spawn(async move {
                match w
                    .watch(
                        &dd,
                        move || c.load(Ordering::SeqCst),
                        Duration::from_millis(20),
                    )
                    .await {}
            });
            m.apply(true, Some(T0 + 30 * MIN), T0);
            assert!(*on.borrow_and_update());
            clock.store(T0 - 120 * MIN, Ordering::SeqCst);
            mono.store(10 * MIN, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(*on.borrow(), "10 of 30 minutes passed");
            assert!(m.meeting_on(clock.load(Ordering::SeqCst)));
            mono.store(30 * MIN, Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(5), on.wait_for(|on| !*on))
                .await
                .expect("off once 30 minutes really passed")
                .unwrap();
            assert_eq!(m.meeting(), Meeting::Until(T0 + 30 * MIN));
            assert!(!m.meeting_on(clock.load(Ordering::SeqCst)));
            task.abort();
        });
    }

    /// B-1: a saved or sent meeting time more than a day ahead (no meeting
    /// is that long: the clock was set back) is over: LAN off, no meeting
    /// mode; a day ahead exactly still opens.
    #[test]
    fn a_meeting_time_more_than_a_day_ahead_is_over() {
        let (m, on, _) = rig();
        let day = raven_core::lan_meeting::MAX_MEETING_MS;
        m.start(Ok(false), || Ok(Some(T0 + day + MIN)), T0);
        assert_eq!(
            (*on.borrow(), m.meeting()),
            (false, Meeting::Until(T0 + day + MIN))
        );
        assert!(!m.meeting_on(T0));
        m.apply(true, Some(T0 + day + MIN), T0);
        assert!(!*on.borrow());
        assert!(!m.meeting_on(T0));
        m.apply(true, Some(T0 + day), T0);
        assert!(*on.borrow());
        assert!(m.meeting_on(T0));
    }

    /// Start: off while `raven lan off` holds or the policy cannot be read
    /// (the meeting time is then not even read), on without a meeting time,
    /// on before it and off after it, off while it cannot be read yet or at
    /// all.
    #[test]
    fn start_table() {
        let (m, on, _) = rig();
        let unread = || -> Result<Option<u64>, AtRestError> { panic!("not read") };
        m.start(Ok(true), unread, T0);
        assert_eq!((*on.borrow(), m.meeting()), (false, Meeting::None));
        m.start(Err("bad json".into()), unread, T0);
        assert_eq!((*on.borrow(), m.meeting()), (false, Meeting::None));
        m.start(Ok(false), || Ok(None), T0);
        assert_eq!((*on.borrow(), m.meeting()), (true, Meeting::None));
        m.start(Ok(false), || Ok(Some(T0 + MIN)), T0);
        assert_eq!(
            (*on.borrow(), m.meeting()),
            (true, Meeting::Until(T0 + MIN))
        );
        m.start(Ok(false), || Ok(Some(T0)), T0);
        assert_eq!((*on.borrow(), m.meeting()), (false, Meeting::Until(T0)));
        m.start(
            Ok(false),
            || Err(AtRestError::KeyUnavailable("not loaded".into())),
            T0,
        );
        assert_eq!((*on.borrow(), m.meeting()), (false, Meeting::Waiting));
        m.start(Ok(false), || Err(AtRestError::Tampered { kind: 32 }), T0);
        assert_eq!((*on.borrow(), m.meeting()), (false, Meeting::Unreadable));
    }

    /// Phase 3 P3.C3 (OD-C7): meeting mode is on while a meeting time is
    /// ahead, not at it or after it, and not without one (none, or one
    /// that cannot be read).
    #[test]
    fn meeting_on_while_a_meeting_time_is_ahead() {
        let (m, _on, _) = rig();
        m.start(Ok(false), || Ok(Some(T0 + 30 * MIN)), T0);
        assert!(m.meeting_on(T0));
        assert!(m.meeting_on(T0 + 30 * MIN - 1));
        assert!(!m.meeting_on(T0 + 30 * MIN));
        m.start(Ok(false), || Ok(None), T0);
        assert!(!m.meeting_on(T0));
        m.start(
            Ok(false),
            || Err(AtRestError::KeyUnavailable("not loaded".into())),
            T0,
        );
        assert!(!m.meeting_on(T0));
    }

    /// `SetLan`: on with a meeting time, on without one (it is dropped), off
    /// (any time sent with it is dropped), and a time already past is off.
    #[test]
    fn apply_table() {
        let (m, on, _) = rig();
        m.apply(true, Some(T0 + 30 * MIN), T0);
        assert_eq!(
            (*on.borrow(), m.meeting()),
            (true, Meeting::Until(T0 + 30 * MIN))
        );
        m.apply(true, None, T0);
        assert_eq!((*on.borrow(), m.meeting()), (true, Meeting::None));
        m.apply(false, Some(T0 + MIN), T0);
        assert_eq!((*on.borrow(), m.meeting()), (false, Meeting::None));
        m.apply(true, Some(T0 - 1), T0);
        assert_eq!((*on.borrow(), m.meeting()), (false, Meeting::Until(T0 - 1)));
    }

    /// The watch: LAN goes off within a poll once the clock passes the
    /// meeting time (a jump, as a lab clock or a wake from sleep makes),
    /// stays off when the clock goes back, and a `SetLan` afterwards wins.
    #[test]
    fn the_watch_closes_at_the_meeting_time_and_setlan_wins() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (m, mut on, clock) = rig();
            let dir = tempfile::tempdir().unwrap();
            let (w, c, dd) = (Arc::clone(&m), Arc::clone(&clock), dir.path().to_path_buf());
            let task = tokio::spawn(async move {
                match w
                    .watch(
                        &dd,
                        move || c.load(Ordering::SeqCst),
                        Duration::from_millis(20),
                    )
                    .await {}
            });
            m.apply(true, Some(T0 + 30 * MIN), T0);
            assert!(*on.borrow_and_update());
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(*on.borrow(), "still before the meeting time");
            clock.store(T0 + 31 * MIN, Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(5), on.wait_for(|on| !*on))
                .await
                .expect("off within a poll")
                .unwrap();
            assert_eq!(
                m.meeting(),
                Meeting::Until(T0 + 30 * MIN),
                "kept for status"
            );
            clock.store(T0, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!*on.borrow(), "a clock moved back does not reopen it");
            m.apply(true, None, clock.load(Ordering::SeqCst));
            assert!(*on.borrow());
            clock.store(T0 + 90 * MIN, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(*on.borrow(), "no meeting time: nothing closes it");
            task.abort();
        });
    }
}
