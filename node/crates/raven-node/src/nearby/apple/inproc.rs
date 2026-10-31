//! The nearby radio inside the app's own process (iOS with feature
//! `nearby-radio`; Task 2 design §3). iOS lets an app start no helper
//! process, so the helper's machine and CoreBluetooth glue
//! ([`super::machine`], [`super::cb`]) run here, on the same kind of serial
//! queue, behind the same [`HelperRadio`]: its connection numbering, send
//! window and checks of what the radio says (`on_line`) are the macOS
//! radio's, and the RNL1 bytes on the air are the helper's.
//!
//! - **The channel** is typed values, with no line and no JSON (design §3.2
//!   A): a command is posted to the queue (`dispatch_async_f`, it never
//!   waits); what the machine says goes from the queue straight to
//!   `on_line`, into the engine's bounded queue ([`EventTx`]; RNL1 §8's
//!   overflow rule unchanged).
//! - **A life** is one pair of managers, one delegate, one machine and one
//!   event sender. Each [`open`] makes one; dropping its radio ends it on
//!   the queue before the drop returns (never on the queue itself: `cb`'s
//!   `run_sync` asserts it). A command or a tick of an earlier life finds
//!   another generation and is dropped; a callback of an earlier life's
//!   managers is dropped by its delegate (`cb`).
//! - **The tick** is a `dispatch_after` on the same queue, re-armed while
//!   its life lasts: no thread, and nothing ticks while the app is
//!   suspended.
//! - **Before any manager** [`open`] checks the back-off, the app's usage
//!   description (without it: [`cb::NO_USAGE`], no manager and no crash)
//!   and iOS's Bluetooth permission (denied or restricted:
//!   [`machine::NOT_ALLOWED`], no manager and no prompt). Only an undecided
//!   permission lets the managers ask, and that only after the user turned
//!   nearby on (the service makes no radio before).
//! - **A panic** on the queue ends the life, not the app: every connection
//!   gets its `Disconnected`, the radio says [`INTERNAL`] (classed
//!   `helper_unavailable`), and its event queue closes, so the engine ends
//!   and the service opens a new radio after the back-off, as when the
//!   macOS helper dies.
//!
//! The life machinery is generic over the machine's [`Os`] ([`Backend`]),
//! so the tests run it with a fake OS on a real dispatch queue on macOS: no
//! CoreBluetooth manager is ever made there.

// On macOS the library builds this only for its tests.
#![cfg_attr(not(target_os = "ios"), allow(dead_code))]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::cb::{self, Life, Sink, Slot};
use super::machine::{self, Machine, Os};
use super::proto::{FromHelper, ToHelper};
use super::{lock, next_generation, note, on_line, Backoff, HelperRadio, Link, Outlet, Table};
use crate::nearby::radio::{ConnId, EventTx, RadioEvent, RadioState};

/// How often the machine's deadlines are checked (the helper's tick).
pub(crate) const TICK: Duration = Duration::from_millis(500);
/// Why the radio stopped after an internal error on its queue (classed
/// `helper_unavailable`: the software Raven needs, not the device's
/// Bluetooth).
pub(crate) const INTERNAL: &str = "the nearby radio stopped (internal error)";
/// Why there is no radio when the queue or its life could not be made.
const NO_QUEUE: &str = "the nearby radio could not start (no dispatch queue)";
const NO_LIFE: &str = "the nearby radio could not start (internal error)";

/// A machine's OS that the life machinery runs: CoreBluetooth, or a test's
/// fake.
pub(super) trait Backend: Os + Sized + 'static {
    /// Its one life at a time.
    fn slot() -> &'static Slot<Self>;
}

impl Backend for cb::Cb {
    fn slot() -> &'static Slot<Self> {
        &cb::STATE
    }
}

/// The radio's way into its life: commands posted to the queue, and the
/// life's end.
pub(super) struct Inlet {
    life: u64,
    post: fn(u64, ToHelper),
    stop: fn(u64),
}

impl Inlet {
    pub(super) fn put(&self, m: ToHelper) {
        (self.post)(self.life, m);
    }

    /// The life ends on the queue; returns once it has.
    pub(super) fn stop(&self) {
        (self.stop)(self.life);
    }
}

/// A life's sink: what the machine says goes through the link's checks
/// into the engine's queue.
struct ToEngine {
    link: Arc<Link>,
    events: EventTx,
    backoff: Option<Arc<Mutex<Backoff>>>,
}

impl Sink for ToEngine {
    fn say(&self, lines: Vec<FromHelper>) {
        for m in lines {
            on_line(&self.link, &self.events, m, self.backoff.as_deref());
        }
        self.link
            .overflows
            .store(self.events.dropped(), Ordering::Relaxed);
    }

    /// Owed `Disconnected` events arrive on the tick too (RNL1 §8).
    fn ticked(&self) {
        self.events.flush();
        self.link
            .overflows
            .store(self.events.dropped(), Ordering::Relaxed);
    }

    /// As when the macOS helper ends on its own: every connection ends, the
    /// radio says why, the back-off grows, and the event sender goes with
    /// the life (the engine's queue closes). Nothing once the radio let go.
    fn panicked(&self) {
        if self.link.stopped.load(Ordering::SeqCst) {
            return;
        }
        lock(&self.link.out).take();
        let conns: Vec<ConnId> = lock(&self.link.table)
            .conns
            .drain()
            .map(|(c, _)| c)
            .collect();
        for conn in conns {
            let _ = self.events.emit(RadioEvent::Disconnected { conn });
        }
        let why = RadioState::Unsupported(INTERNAL.into());
        let _ = self.events.emit(RadioEvent::State(why.clone()));
        if let Some(b) = &self.backoff {
            note(&why);
            lock(b).failed(Instant::now(), why);
        }
    }
}

/// A panic past every other catch on the queue: said, never unwound.
fn log_panic() {
    eprintln!("raven-node nearby: internal error on the radio's queue");
}

/// `cmd` for life `life`, on the queue.
fn post_cmd<O: Backend>(life: u64, cmd: ToHelper) {
    cb::post(Box::new(move || {
        cb::deliver(O::slot(), move |l, now| {
            if l.id == life {
                l.m.command(cmd, now);
            }
        });
    }));
}

/// The next tick of life `life`.
fn arm_tick<O: Backend>(life: u64) {
    cb::post_after(TICK, Box::new(move || tick::<O>(life)));
}

/// Life `life`'s tick, armed again while the life lasts.
fn tick<O: Backend>(life: u64) {
    cb::deliver(O::slot(), move |l, now| {
        if l.id != life {
            return;
        }
        l.m.tick(now);
        l.sink.ticked();
        arm_tick::<O>(life);
    });
}

/// End life `life` and wait for it (never on the queue).
fn stop_life<O: Backend>(life: u64) {
    cb::run_sync(Box::new(move || end::<O>(life)));
}

/// On the queue: life `life` leaves its slot; its machine stops (the advert
/// and the scan off, every link cancelled, every service withdrawn), then
/// every object of it is let go of here.
fn end<O: Backend>(life: u64) {
    let ended = {
        let mut slot = lock(O::slot());
        if slot.as_ref().is_some_and(|l| l.id == life) {
            slot.take()
        } else {
            None
        }
    };
    if let Some(mut l) = ended {
        // A machine that panics while stopping still lets go of it all.
        let _ = catch_unwind(AssertUnwindSafe(|| l.m.stop()));
    }
}

/// The radio of this iOS device: CoreBluetooth in this process (see the
/// module doc). On the blocking pool, as `apple::open` is on macOS.
#[cfg(target_os = "ios")]
pub(crate) fn open(tx: mpsc::Sender<RadioEvent>) -> Result<HelperRadio, RadioState> {
    let options = cb::Options {
        power_alert: Some(false),
        filtered_scan: true,
    };
    open_with::<cb::Cb>(
        tx,
        super::backoff(),
        cb::has_usage_description,
        || cb::permission_word(cb::authorization_raw()),
        move |queue| cb::make(queue, options),
    )
}

/// [`open`] with what it reads given: the back-off, whether the app has
/// the usage description, iOS's permission word, and how the life's OS is
/// made on the queue. A failure is noted and counts for the back-off,
/// except a missing usage description or a refused permission, which make
/// nothing and cost nothing to read again.
pub(super) fn open_with<O: Backend>(
    tx: mpsc::Sender<RadioEvent>,
    backoff: Arc<Mutex<Backoff>>,
    usage: impl FnOnce() -> bool,
    permission: impl FnOnce() -> &'static str,
    make: impl FnOnce(cb::Queue) -> O + 'static,
) -> Result<HelperRadio, RadioState> {
    lock(&backoff).check(Instant::now())?;
    let refused = if !usage() {
        Some(RadioState::Unsupported(cb::NO_USAGE.into()))
    } else if matches!(permission(), "denied" | "restricted") {
        Some(RadioState::Unauthorized(machine::NOT_ALLOWED.into()))
    } else {
        None
    };
    if let Some(state) = refused {
        note(&state);
        return Err(state);
    }
    let opened = begin(tx, Some(Arc::clone(&backoff)), make);
    if let Err(state) = &opened {
        note(state);
        lock(&backoff).failed(Instant::now(), state.clone());
    }
    opened
}

/// A new life over the OS `make` makes on the queue, its first tick armed,
/// and its radio.
fn begin<O: Backend>(
    tx: mpsc::Sender<RadioEvent>,
    backoff: Option<Arc<Mutex<Backoff>>>,
    make: impl FnOnce(cb::Queue) -> O + 'static,
) -> Result<HelperRadio, RadioState> {
    let queue = cb::queue(log_panic).ok_or_else(|| RadioState::Unsupported(NO_QUEUE.into()))?;
    let id = next_generation();
    let link = Arc::new(Link {
        out: Mutex::new(Some(Outlet::Queue(Inlet {
            life: id,
            post: post_cmd::<O>,
            stop: stop_life::<O>,
        }))),
        table: Mutex::new(Table::default()),
        child: Mutex::new(None),
        stopped: AtomicBool::new(false),
        overflows: AtomicU64::new(0),
        generation: id,
    });
    let sink: Arc<dyn Sink> = Arc::new(ToEngine {
        link: Arc::clone(&link),
        events: EventTx::new(tx),
        backoff,
    });
    let started = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&started);
    cb::run_sync(Box::new(move || {
        if let Ok(os) = catch_unwind(AssertUnwindSafe(|| make(queue))) {
            *lock(O::slot()) = Some(Life {
                m: Machine::new(os),
                sink,
                id,
            });
            arm_tick::<O>(id);
            done.store(true, Ordering::SeqCst);
        }
    }));
    if !started.load(Ordering::SeqCst) {
        lock(&link.out).take();
        return Err(RadioState::Unsupported(NO_LIFE.into()));
    }
    Ok(HelperRadio { link })
}

#[cfg(test)]
mod tests {
    //! The in-process life over the machine tests' fake OS, on the real
    //! dispatch queue (macOS): no CoreBluetooth manager is made, no radio is
    //! touched, no permission is asked.

    use std::sync::Arc;

    use raven_core::nearby_link::{char_uuid, Role};

    use super::super::machine::CbState;
    use super::super::machine_tests::{Call, FakeOs};
    use super::super::proto;
    use super::*;
    use crate::nearby::radio::{Radio, RadioAddr, Sent, EVENT_QUEUE};

    /// The fake's one life at a time (one queue per process, as in the app).
    static FAKE: Slot<FakeOs> = Mutex::new(None);

    impl Backend for FakeOs {
        fn slot() -> &'static Slot<Self> {
            &FAKE
        }
    }

    /// The tests share the queue and the slot: one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    const T: [u8; 16] = [
        0x06, 0x2a, 0x8a, 0xc6, 0x9e, 0x02, 0x4a, 0xbb, 0xab, 0x83, 0xf9, 0xea, 0xbb, 0x5e, 0x8d,
        0x99,
    ];
    const DEV: &str = "00112233445566778899aabbccddeeff";

    /// Every call the fake was asked, kept outside the life (it is gone
    /// once the life ends).
    type Journal = Arc<Mutex<Vec<Call>>>;

    fn fake(journal: &Journal) -> impl FnOnce(cb::Queue) -> FakeOs + 'static {
        let journal = Arc::clone(journal);
        move |_| FakeOs {
            calls: Vec::new(),
            room: true,
            journal: Some(journal),
        }
    }

    fn opened(journal: &Journal) -> (HelperRadio, mpsc::Receiver<RadioEvent>) {
        let (tx, rx) = mpsc::channel(EVENT_QUEUE);
        let radio = open_with(tx, Arc::default(), || true, || "allowed", fake(journal)).unwrap();
        (radio, rx)
    }

    /// Everything posted so far has run (the queue is serial).
    fn settle() {
        cb::run_sync(Box::new(|| {}));
    }

    /// `f` with the fake's life on the queue, as a CoreBluetooth callback
    /// would reach it.
    fn callback(f: impl FnOnce(&mut Machine<FakeOs>, Instant) + 'static) {
        cb::post(Box::new(move || {
            cb::deliver(&FAKE, move |l, now| f(&mut l.m, now))
        }));
        settle();
    }

    fn take(journal: &Journal) -> Vec<Call> {
        std::mem::take(&mut *lock(journal))
    }

    fn events(rx: &mut mpsc::Receiver<RadioEvent>) -> Vec<RadioEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    fn powered(rx: &mut mpsc::Receiver<RadioEvent>) {
        callback(|m, now| {
            m.cm_state(CbState::PoweredOn, now);
            m.pm_state(CbState::PoweredOn, now);
        });
        assert_eq!(events(rx), vec![RadioEvent::State(RadioState::PoweredOn)]);
    }

    /// Open, commands, what the machine says, and the events: the radio's
    /// commands reach the machine as values on the queue, and its lines come
    /// back through `on_line` as the macOS radio's do; the scan filter goes
    /// to the radio in process.
    #[test]
    fn commands_reach_the_machine_and_its_lines_the_engine() {
        let _serial = lock(&SERIAL);
        let journal = Journal::default();
        let (mut radio, mut rx) = opened(&journal);
        powered(&mut rx);
        radio.set_services(&[T], Some(T)).unwrap();
        radio.set_scanning(true).unwrap();
        radio.set_scan_filter(&[T]).unwrap();
        settle();
        assert_eq!(
            take(&journal),
            vec![
                Call::Add(T, char_uuid(&T)),
                Call::Scan(true),
                Call::ScanFilter(vec![T])
            ]
        );
        callback(|m, now| m.added(T, true, now));
        assert_eq!(take(&journal), vec![Call::Advertise(Some(T))]);
        assert!(radio
            .set_scan_filter(&vec![T; proto::MAX_FILTER + 1])
            .is_err());
        // A central subscribes: a connection of the radio's own numbering.
        callback(|m, now| m.subscribed(T, "c1", 100, now));
        let ev = events(&mut rx);
        let [RadioEvent::Connected {
            conn,
            role: Role::Peripheral,
            service,
            max_tx: 100,
            max_rx: 100,
        }] = ev.as_slice()
        else {
            panic!("{ev:?}");
        };
        assert_eq!((*service, *conn & 0xffff_ffff), (T, 2));
        assert_eq!(*conn >> 32, radio.link.generation);
        callback(|m, _| m.written(T, "c1", &[0x10, 1]));
        assert_eq!(
            events(&mut rx),
            vec![RadioEvent::Frame {
                conn: *conn,
                bytes: vec![0x10, 1]
            }]
        );
        drop(radio);
    }

    /// The send window holds in process as on macOS: 16 frames on their way,
    /// the next one would block, and room gives one `Writable`.
    #[test]
    fn the_send_window_holds_in_process() {
        let _serial = lock(&SERIAL);
        let journal = Journal::default();
        let (mut radio, mut rx) = opened(&journal);
        powered(&mut rx);
        callback(|m, now| {
            m.discovered(DEV, &[T], Some(true), -50, now);
        });
        events(&mut rx);
        let conn = radio.connect(&RadioAddr(DEV.into()), T).unwrap();
        settle();
        callback(|m, _| {
            m.os.room = false;
            m.central_up(DEV, 100);
        });
        assert!(matches!(
            events(&mut rx).as_slice(),
            [RadioEvent::Connected {
                role: Role::Central,
                ..
            }]
        ));
        for _ in 0..super::super::SEND_WINDOW {
            assert_eq!(radio.send(conn, &[0x10, 0]), Ok(Sent::Queued));
        }
        assert_eq!(radio.send(conn, &[0x10, 0]), Ok(Sent::WouldBlock));
        settle();
        callback(|m, _| {
            m.os.room = true;
            m.central_ready(DEV);
        });
        assert_eq!(events(&mut rx), vec![RadioEvent::Writable { conn }]);
        drop(radio);
    }

    /// Dropping the radio ends its life once, before the drop returns: the
    /// advert and the scan off, the links and services gone, the slot empty,
    /// and nothing said after. The next open is a new generation, and what
    /// an earlier life still had queued (a command, a tick) is dropped.
    #[test]
    fn drop_ends_the_life_and_a_new_one_ignores_the_old() {
        let _serial = lock(&SERIAL);
        let journal = Journal::default();
        let (mut radio, mut rx) = opened(&journal);
        powered(&mut rx);
        radio.set_services(&[T], Some(T)).unwrap();
        radio.set_scanning(true).unwrap();
        settle();
        callback(|m, now| m.added(T, true, now));
        take(&journal);
        let old = radio.link.generation;
        drop(radio);
        assert!(lock(&FAKE).is_none(), "the life ended within the drop");
        assert_eq!(
            take(&journal),
            vec![Call::Advertise(None), Call::Scan(false), Call::Remove(T)]
        );
        assert!(events(&mut rx).is_empty());
        let (radio, mut rx) = opened(&journal);
        assert_ne!(radio.link.generation, old);
        post_cmd::<FakeOs>(old, ToHelper::Scan { on: true });
        cb::post(Box::new(move || tick::<FakeOs>(old)));
        settle();
        assert!(
            take(&journal).is_empty(),
            "the old life's command is dropped"
        );
        powered(&mut rx);
        drop(radio);
        assert!(lock(&FAKE).is_none());
    }

    /// A panic on the queue ends the life, not the process: every open
    /// connection gets its `Disconnected`, then the radio says it stopped,
    /// the back-off grows, and the event queue closes (the engine ends);
    /// the radio's commands fail from then on, and its drop is quiet.
    #[test]
    fn a_panic_ends_the_life_and_closes_the_queue() {
        let _serial = lock(&SERIAL);
        let journal = Journal::default();
        let (tx, mut rx) = mpsc::channel(EVENT_QUEUE);
        let backoff: Arc<Mutex<Backoff>> = Arc::default();
        let mut radio = open_with(
            tx,
            Arc::clone(&backoff),
            || true,
            || "not_determined",
            fake(&journal),
        )
        .unwrap();
        powered(&mut rx);
        callback(|m, now| m.subscribed(T, "c1", 100, now));
        // Not published: no connection. Publish, then subscribe.
        radio.set_services(&[T], None).unwrap();
        settle();
        callback(|m, now| m.added(T, true, now));
        callback(|m, now| m.subscribed(T, "c1", 100, now));
        let ev = events(&mut rx);
        let [RadioEvent::Connected { conn, .. }] = ev.as_slice() else {
            panic!("{ev:?}");
        };
        let conn = *conn;
        callback(|_, _| panic!("a test's panic on the radio's queue"));
        assert!(lock(&FAKE).is_none(), "the life ended");
        assert_eq!(
            events(&mut rx),
            vec![
                RadioEvent::Disconnected { conn },
                RadioEvent::State(RadioState::Unsupported(INTERNAL.into()))
            ]
        );
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ),
            "the event queue closed"
        );
        assert!(lock(&backoff).check(Instant::now()).is_err());
        assert!(radio.set_scanning(true).is_err());
        assert_eq!(
            crate::nearby::engine::state_name(&RadioState::Unsupported(INTERNAL.into())),
            "helper_unavailable"
        );
        drop(radio);
    }

    /// Before any manager: a test binary has no usage description, so the
    /// real check refuses with no life made (no manager, no prompt, no
    /// kill); a refused permission makes none either; a back-off wait
    /// answers its last failure.
    #[test]
    fn no_usage_description_or_permission_makes_no_life() {
        let _serial = lock(&SERIAL);
        let journal = Journal::default();
        let (tx, _rx) = mpsc::channel(EVENT_QUEUE);
        let asked = Arc::new(AtomicBool::new(false));
        let was = Arc::clone(&asked);
        let got = open_with(
            tx,
            Arc::default(),
            cb::has_usage_description,
            move || {
                was.store(true, Ordering::SeqCst);
                "allowed"
            },
            fake(&journal),
        );
        assert_eq!(
            got.err(),
            Some(RadioState::Unsupported(cb::NO_USAGE.into()))
        );
        assert!(!asked.load(Ordering::SeqCst), "the permission is not read");
        for word in ["denied", "restricted"] {
            let (tx, _rx) = mpsc::channel(EVENT_QUEUE);
            let got = open_with(tx, Arc::default(), || true, || word, fake(&journal));
            assert_eq!(
                got.err(),
                Some(RadioState::Unauthorized(machine::NOT_ALLOWED.into()))
            );
        }
        let backoff: Arc<Mutex<Backoff>> = Arc::default();
        let why = RadioState::Unsupported(INTERNAL.into());
        lock(&backoff).failed(Instant::now(), why.clone());
        let (tx, _rx) = mpsc::channel(EVENT_QUEUE);
        let got = open_with(tx, backoff, || true, || "allowed", fake(&journal));
        assert_eq!(got.err(), Some(why));
        assert!(lock(&FAKE).is_none());
        assert!(take(&journal).is_empty(), "no OS call at all");
    }

    /// The tick runs on the queue by itself while its life lasts: an event
    /// lost to a full queue (a `Disconnected`, owed, RNL1 §8) arrives on a
    /// tick with no other input. Work on the queue knows it is there (the
    /// drop's `run_sync` must not be).
    #[test]
    fn the_tick_runs_on_the_queue_while_the_life_lasts() {
        let _serial = lock(&SERIAL);
        let journal = Journal::default();
        let (tx, mut rx) = mpsc::channel(2);
        let mut radio =
            open_with(tx, Arc::default(), || true, || "allowed", fake(&journal)).unwrap();
        callback(|m, now| {
            m.cm_state(CbState::PoweredOn, now);
            m.pm_state(CbState::PoweredOn, now);
        });
        radio.set_services(&[T], None).unwrap();
        settle();
        callback(|m, now| m.added(T, true, now));
        callback(|m, now| m.subscribed(T, "c1", 100, now));
        // The queue (2) is full: the end of the connection is owed.
        callback(|m, now| m.unsubscribed(T, "c1", now));
        let ev = events(&mut rx);
        let [RadioEvent::State(RadioState::PoweredOn), RadioEvent::Connected { conn, .. }] =
            ev.as_slice()
        else {
            panic!("{ev:?}");
        };
        let conn = *conn;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut owed = Vec::new();
        while Instant::now() < deadline && owed.is_empty() {
            std::thread::sleep(TICK / 5);
            owed = events(&mut rx);
        }
        assert_eq!(owed, vec![RadioEvent::Disconnected { conn }]);
        assert!(!cb::on_queue());
        let seen = Arc::new(AtomicBool::new(false));
        let mark = Arc::clone(&seen);
        cb::run_sync(Box::new(move || {
            mark.store(cb::on_queue(), Ordering::SeqCst);
        }));
        assert!(seen.load(Ordering::SeqCst));
        drop(radio);
    }
}
