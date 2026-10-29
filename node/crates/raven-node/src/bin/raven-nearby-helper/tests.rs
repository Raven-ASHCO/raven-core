//! The helper's state machine over scripted inputs (no CoreBluetooth, no
//! radio): power, services and the one advert, scanning, both kinds of
//! connection, the send queues, silence and stopping.

use std::time::{Duration, Instant};

use crate::machine::*;
use crate::proto::{self, FromHelper, Gatt, Power, Side, ToHelper};

const A: [u8; 16] = [
    0x06, 0x2a, 0x8a, 0xc6, 0x9e, 0x02, 0x4a, 0xbb, 0xab, 0x83, 0xf9, 0xea, 0xbb, 0x5e, 0x8d, 0x99,
];
const CA: [u8; 16] = [0xca; 16];
const B: [u8; 16] = [0x22; 16];
const CB_: [u8; 16] = [0xcb; 16];
/// Battery Service, written long.
const SIG: [u8; 16] = [
    0x00, 0x00, 0x18, 0x0f, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];
/// Device and central handles (placeholders).
const DEV: &str = "00112233445566778899aabbccddeeff";
const DEV2: &str = "ffeeddccbbaa99887766554433221100";
const CEN: &str = "0123456789abcdef0123456789abcdef";

/// What the machine asked of CoreBluetooth, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Add([u8; 16], [u8; 16]),
    Remove([u8; 16]),
    Advertise(Option<[u8; 16]>),
    Scan(bool),
    Connect(String, [u8; 16], [u8; 16]),
    Cancel(String),
    Write(String, Vec<u8>),
    Notify([u8; 16], String, Vec<u8>),
    Forget(String),
    ForgetCentral(String),
    Reset,
}

struct FakeOs {
    calls: Vec<Call>,
    /// Whether a write or a notification is taken now.
    room: bool,
}

impl Os for FakeOs {
    fn add(&mut self, t: [u8; 16], c: [u8; 16]) {
        self.calls.push(Call::Add(t, c));
    }
    fn remove(&mut self, t: [u8; 16]) {
        self.calls.push(Call::Remove(t));
    }
    fn advertise(&mut self, t: Option<[u8; 16]>) {
        self.calls.push(Call::Advertise(t));
    }
    fn scan(&mut self, on: bool) {
        self.calls.push(Call::Scan(on));
    }
    fn connect(&mut self, dev: &str, t: [u8; 16], c: [u8; 16]) -> bool {
        self.calls.push(Call::Connect(dev.into(), t, c));
        true
    }
    fn cancel(&mut self, dev: &str) {
        self.calls.push(Call::Cancel(dev.into()));
    }
    fn write(&mut self, dev: &str, frame: &[u8]) -> bool {
        if self.room {
            self.calls.push(Call::Write(dev.into(), frame.to_vec()));
        }
        self.room
    }
    fn notify(&mut self, t: [u8; 16], central: &str, frame: &[u8]) -> bool {
        if self.room {
            self.calls
                .push(Call::Notify(t, central.into(), frame.to_vec()));
        }
        self.room
    }
    fn forget(&mut self, dev: &str) {
        self.calls.push(Call::Forget(dev.into()));
    }
    fn forget_central(&mut self, central: &str) {
        self.calls.push(Call::ForgetCentral(central.into()));
    }
    fn reset(&mut self) {
        self.calls.push(Call::Reset);
    }
}

fn machine() -> Machine<FakeOs> {
    Machine::new(FakeOs {
        calls: Vec::new(),
        room: true,
    })
}

fn calls(m: &mut Machine<FakeOs>) -> Vec<Call> {
    std::mem::take(&mut m.os.calls)
}

fn h(u: &[u8; 16]) -> String {
    proto::uuid_hex(u)
}

fn gatt(t: &[u8; 16], c: &[u8; 16]) -> Gatt {
    Gatt {
        service: h(t),
        characteristic: h(c),
    }
}

fn services(list: &[([u8; 16], [u8; 16])], advertise: Option<[u8; 16]>) -> ToHelper {
    ToHelper::Services {
        services: list.iter().map(|(t, c)| gatt(t, c)).collect(),
        advertise: advertise.as_ref().map(h),
    }
}

fn send(conn: u64, frame: &[u8]) -> ToHelper {
    ToHelper::Send {
        conn,
        b64: proto::b64_of(frame),
    }
}

fn frame(conn: u64, bytes: &[u8]) -> FromHelper {
    FromHelper::Frame {
        conn,
        b64: proto::b64_of(bytes),
    }
}

fn state(state: Power, detail: &str) -> FromHelper {
    FromHelper::State {
        state,
        detail: detail.into(),
    }
}

/// Both managers on: the radio is up.
fn powered(now: Instant) -> Machine<FakeOs> {
    let mut m = machine();
    m.cm_state(CbState::PoweredOn, now);
    m.pm_state(CbState::PoweredOn, now);
    assert_eq!(m.take_out(), vec![state(Power::On, "")]);
    m
}

/// Powered, with service A (and its characteristic) published.
fn serving(now: Instant) -> Machine<FakeOs> {
    let mut m = powered(now);
    m.command(services(&[(A, CA)], None), now);
    m.added(A, true, now);
    calls(&mut m);
    m
}

/// Powered, with a connected central link to DEV on A as connection 1.
fn linked(now: Instant) -> Machine<FakeOs> {
    let mut m = powered(now);
    assert!(m.discovered(DEV, &[A], Some(true), -50, now));
    m.take_out();
    m.command(
        ToHelper::Connect {
            conn: 1,
            dev: DEV.into(),
            service: h(&A),
            characteristic: h(&CA),
        },
        now,
    );
    m.central_up(DEV, 182);
    m.take_out();
    calls(&mut m);
    m
}

#[test]
fn cb_states_map_and_combine() {
    assert_eq!(CbState::from_raw(5), CbState::PoweredOn);
    assert_eq!(CbState::from_raw(4), CbState::PoweredOff);
    assert_eq!(CbState::from_raw(3), CbState::Unauthorized);
    assert_eq!(CbState::from_raw(2), CbState::Unsupported);
    assert_eq!(CbState::from_raw(1), CbState::Resetting);
    assert_eq!(CbState::from_raw(0), CbState::Unknown);
    assert_eq!(CbState::from_raw(99), CbState::Unknown);
    use CbState::*;
    assert_eq!(combine(PoweredOn, Unknown), None, "still asking");
    assert_eq!(combine(PoweredOn, PoweredOn), Some((Power::On, "")));
    assert_eq!(combine(PoweredOn, PoweredOff), Some((Power::Off, "")));
    assert_eq!(combine(Resetting, PoweredOn), Some((Power::Off, "")));
    assert_eq!(
        combine(Unauthorized, Unknown),
        Some((Power::Unauthorized, NOT_ALLOWED))
    );
    assert_eq!(
        combine(PoweredOn, Unsupported),
        Some((Power::Unsupported, NO_LE))
    );
    assert!(NOT_ALLOWED.contains("Privacy & Security > Bluetooth"));
}

/// Nothing reaches CoreBluetooth before both managers are on; then what
/// raven-node asked for is set up, and each state is said once.
#[test]
fn nothing_happens_until_both_managers_are_on() {
    let now = Instant::now();
    let mut m = machine();
    m.command(services(&[(A, CA)], Some(A)), now);
    m.command(ToHelper::Scan { on: true }, now);
    m.cm_state(CbState::PoweredOn, now);
    assert!(calls(&mut m).is_empty());
    assert!(
        m.take_out().is_empty(),
        "the peripheral manager is still unknown"
    );
    m.pm_state(CbState::PoweredOn, now);
    assert_eq!(m.take_out(), vec![state(Power::On, "")]);
    assert_eq!(calls(&mut m), vec![Call::Add(A, CA), Call::Scan(true)]);
    m.pm_state(CbState::PoweredOn, now);
    assert!(m.take_out().is_empty(), "said once");
}

/// RNL1 §3-§4: only an added service is advertised, as the advert's only
/// UUID; the token going off air goes first, so at most one is on air.
#[test]
fn one_token_on_air_and_only_once_its_service_is_up() {
    let now = Instant::now();
    let mut m = powered(now);
    m.command(services(&[(A, CA), (B, CB_)], Some(A)), now);
    assert_eq!(calls(&mut m), vec![Call::Add(A, CA), Call::Add(B, CB_)]);
    m.added(B, true, now);
    assert!(calls(&mut m).is_empty(), "A is not up yet");
    m.added(A, true, now);
    assert_eq!(calls(&mut m), vec![Call::Advertise(Some(A))]);
    // Switch the advert to B: A goes off air first.
    m.command(services(&[(A, CA), (B, CB_)], Some(B)), now);
    assert_eq!(
        calls(&mut m),
        vec![Call::Advertise(None), Call::Advertise(Some(B))]
    );
    // Withdraw B (on air): off air, then removed.
    m.command(services(&[(A, CA)], None), now);
    assert_eq!(calls(&mut m), vec![Call::Advertise(None), Call::Remove(B)]);
    assert_eq!(m.service_of_char(&CA), Some(A));
    assert_eq!(m.service_of_char(&CB_), None);
}

/// A refused service or advert is tried again after RETRY.
#[test]
fn refused_services_and_adverts_are_retried() {
    let now = Instant::now();
    let mut m = powered(now);
    m.command(services(&[(A, CA)], Some(A)), now);
    m.added(A, false, now);
    calls(&mut m);
    m.tick(now + RETRY - Duration::from_millis(1));
    assert!(calls(&mut m).is_empty());
    m.tick(now + RETRY);
    assert_eq!(calls(&mut m), vec![Call::Add(A, CA)]);
    let later = now + RETRY;
    m.added(A, true, later);
    assert_eq!(calls(&mut m), vec![Call::Advertise(Some(A))]);
    m.advertising(false, later);
    m.tick(later + Duration::from_secs(1));
    assert!(calls(&mut m).is_empty());
    m.tick(later + RETRY);
    assert_eq!(calls(&mut m), vec![Call::Advertise(Some(A))]);
    // A late answer for a service no longer wanted changes nothing.
    m.command(services(&[], None), later + RETRY);
    calls(&mut m);
    m.added(A, true, later + RETRY);
    assert!(calls(&mut m).is_empty());
}

/// Lines that make no sense are ignored.
#[test]
fn bad_service_lines_are_ignored() {
    let now = Instant::now();
    let mut m = powered(now);
    m.command(services(&[(A, CA)], Some(B)), now);
    m.command(
        ToHelper::Services {
            services: vec![Gatt {
                service: "not hex".into(),
                characteristic: h(&CA),
            }],
            advertise: None,
        },
        now,
    );
    let too_many = vec![(A, CA); proto::MAX_SERVICES + 1];
    m.command(services(&too_many, None), now);
    assert!(calls(&mut m).is_empty());
}

/// A central that subscribes is one peripheral connection (even numbers);
/// its writes are frames; it ends when the central unsubscribes.
#[test]
fn a_subscribed_central_is_one_connection() {
    let now = Instant::now();
    let mut m = serving(now);
    m.subscribed(B, CEN, 182, now);
    assert!(m.take_out().is_empty(), "B is not published");
    m.subscribed(A, CEN, 182, now);
    assert_eq!(
        m.take_out(),
        vec![FromHelper::Connected {
            conn: 2,
            role: Side::Peripheral,
            service: h(&A),
            max_tx: 182,
            max_rx: 182,
        }]
    );
    assert!(m.has_central(CEN));
    m.subscribed(A, CEN, 182, now);
    assert!(m.take_out().is_empty(), "already connected");
    m.written(A, CEN, &[0x01, 0x02]);
    m.written(A, "someone-else", &[0x01]);
    m.written(A, CEN, &[]);
    assert_eq!(m.take_out(), vec![frame(2, &[0x01, 0x02])]);
    m.unsubscribed(A, CEN, now);
    assert_eq!(m.take_out(), vec![FromHelper::Disconnected { conn: 2 }]);
    assert_eq!(calls(&mut m), vec![Call::ForgetCentral(CEN.into())]);
    assert!(!m.has_central(CEN));
    // A new subscription is a new connection.
    m.subscribed(A, CEN, 600, now);
    assert!(matches!(
        m.take_out()[..],
        [FromHelper::Connected {
            conn: 4,
            max_tx: proto::MAX_FRAME,
            ..
        }]
    ));
}

/// CoreBluetooth cannot drop a central: one this side ended is silenced
/// for SILENCE unless it unsubscribes first.
#[test]
fn a_central_this_side_ended_is_silenced() {
    let now = Instant::now();
    let mut m = serving(now);
    m.subscribed(A, CEN, 100, now);
    m.take_out();
    m.command(ToHelper::Disconnect { conn: 2 }, now);
    assert_eq!(m.take_out(), vec![FromHelper::Disconnected { conn: 2 }]);
    m.written(A, CEN, &[0x01]);
    m.subscribed(A, CEN, 100, now + Duration::from_secs(1));
    assert!(m.take_out().is_empty(), "silenced");
    m.subscribed(A, CEN, 100, now + SILENCE);
    assert!(matches!(
        m.take_out()[..],
        [FromHelper::Connected { conn: 4, .. }]
    ));
    // Unsubscribing lifts the silence at once.
    m.command(ToHelper::Disconnect { conn: 4 }, now + SILENCE);
    m.unsubscribed(A, CEN, now + SILENCE);
    m.take_out();
    m.subscribed(A, CEN, 100, now + SILENCE);
    assert!(matches!(
        m.take_out()[..],
        [FromHelper::Connected { conn: 6, .. }]
    ));
}

/// Notifications wait while CoreBluetooth's queue is full and go, in
/// order, when it is ready; each one that goes is one `sent`. A frame over
/// max_tx is dropped with its credit; a queue past QUEUE ends the link.
#[test]
fn notifications_wait_for_room_and_each_one_sent_is_a_credit() {
    let now = Instant::now();
    let mut m = serving(now);
    m.subscribed(A, CEN, 100, now);
    m.take_out();
    m.os.room = false;
    m.command(send(2, &[1]), now);
    m.command(send(2, &[2]), now);
    assert!(m.take_out().is_empty());
    m.os.room = true;
    m.peripheral_ready();
    assert_eq!(
        calls(&mut m),
        vec![
            Call::Notify(A, CEN.into(), vec![1]),
            Call::Notify(A, CEN.into(), vec![2])
        ]
    );
    assert_eq!(
        m.take_out(),
        vec![FromHelper::Sent { conn: 2 }, FromHelper::Sent { conn: 2 }]
    );
    m.command(send(2, &[0; 101]), now);
    assert_eq!(m.take_out(), vec![FromHelper::Sent { conn: 2 }]);
    assert!(calls(&mut m).is_empty(), "too big: dropped");
    m.command(send(9, &[1]), now);
    assert!(m.take_out().is_empty(), "no such connection");
    m.os.room = false;
    for _ in 0..QUEUE {
        m.command(send(2, &[3]), now);
    }
    assert!(m.take_out().is_empty());
    m.command(send(2, &[3]), now);
    assert_eq!(m.take_out(), vec![FromHelper::Disconnected { conn: 2 }]);
}

/// RNL1 §3: an advert is seen only with candidate tokens, at most once a
/// second per device unless its UUIDs change; a device is remembered only
/// then, and forgotten after DEVICE_TTL.
#[test]
fn adverts_with_tokens_are_seen_throttled_and_forgotten() {
    let now = Instant::now();
    let mut m = powered(now);
    assert!(!m.discovered(DEV, &[SIG], Some(true), -40, now));
    assert!(!m.discovered(DEV, &[A], Some(false), -40, now));
    assert!(m.take_out().is_empty());
    assert!(m.discovered(DEV, &[SIG, A, A], None, -40, now));
    assert_eq!(
        m.take_out(),
        vec![FromHelper::Seen {
            dev: DEV.into(),
            uuids: vec![h(&A)],
            rssi: -40,
        }]
    );
    assert!(m.discovered(DEV, &[A], None, -41, now + Duration::from_millis(500)));
    assert!(m.take_out().is_empty(), "throttled");
    assert!(m.discovered(DEV, &[B], None, -41, now + Duration::from_millis(600)));
    assert_eq!(m.take_out().len(), 1, "its UUIDs changed");
    assert!(m.discovered(DEV, &[B], None, -42, now + Duration::from_millis(1600)));
    assert_eq!(m.take_out().len(), 1, "a second later");
    m.tick(now + Duration::from_millis(1600) + DEVICE_TTL);
    assert_eq!(calls(&mut m), vec![Call::Forget(DEV.into())]);
    // Off: nothing is seen.
    m.pm_state(CbState::PoweredOff, now);
    m.take_out();
    assert!(!m.discovered(DEV2, &[A], None, -40, now));
    assert!(m.take_out().is_empty());
}

/// At most MAX_DEVICES are remembered: the one seen longest ago goes.
#[test]
fn the_device_memory_is_bounded() {
    let now = Instant::now();
    let mut m = powered(now);
    for i in 0..MAX_DEVICES {
        assert!(m.discovered(
            &format!("{i:032x}"),
            &[A],
            None,
            -40,
            now + Duration::from_millis(i as u64)
        ));
    }
    calls(&mut m);
    assert!(m.discovered(DEV2, &[A], None, -40, now + Duration::from_secs(5)));
    assert_eq!(calls(&mut m), vec![Call::Forget(format!("{:032x}", 0))]);
}

/// A connect: CoreBluetooth connects and subscribes; the connection is up
/// with the subscription, and notifications that came first follow its
/// `connected`. Frames go as Write Commands while there is room.
#[test]
fn a_connect_is_up_once_subscribed() {
    let now = Instant::now();
    let mut m = powered(now);
    assert!(m.discovered(DEV, &[A], Some(true), -50, now));
    m.take_out();
    m.command(
        ToHelper::Connect {
            conn: 1,
            dev: DEV.into(),
            service: h(&A),
            characteristic: h(&CA),
        },
        now,
    );
    assert_eq!(calls(&mut m), vec![Call::Connect(DEV.into(), A, CA)]);
    m.notified(DEV, vec![0x11, 0], now);
    m.command(send(1, &[1]), now);
    assert_eq!(
        m.take_out(),
        vec![FromHelper::Sent { conn: 1 }],
        "not up: dropped"
    );
    m.central_up(DEV, 244);
    assert_eq!(
        m.take_out(),
        vec![
            FromHelper::Connected {
                conn: 1,
                role: Side::Central,
                service: h(&A),
                max_tx: 244,
                max_rx: 244,
            },
            frame(1, &[0x11, 0]),
        ]
    );
    m.central_up(DEV, 244);
    assert!(m.take_out().is_empty(), "once");
    m.os.room = false;
    m.command(send(1, &[7]), now);
    assert!(m.take_out().is_empty());
    m.os.room = true;
    m.central_ready(DEV);
    assert_eq!(calls(&mut m), vec![Call::Write(DEV.into(), vec![7])]);
    assert_eq!(m.take_out(), vec![FromHelper::Sent { conn: 1 }]);
    m.notified(DEV, vec![0x12], now);
    assert_eq!(m.take_out(), vec![frame(1, &[0x12])]);
    m.central_down(DEV, now);
    assert_eq!(m.take_out(), vec![FromHelper::Disconnected { conn: 1 }]);
    assert!(calls(&mut m).is_empty(), "CoreBluetooth ended it");
}

/// A connect to a device never seen, a second link to one device, or one
/// with the radio off fails at once; a malformed one is ignored.
#[test]
fn connects_that_cannot_happen_fail_at_once() {
    let now = Instant::now();
    let mut m = linked(now);
    let connect = |conn, dev: &str| ToHelper::Connect {
        conn,
        dev: dev.into(),
        service: h(&A),
        characteristic: h(&CA),
    };
    m.command(connect(3, DEV2), now);
    m.command(connect(5, DEV), now);
    assert_eq!(
        m.take_out(),
        vec![
            FromHelper::Disconnected { conn: 3 },
            FromHelper::Disconnected { conn: 5 }
        ]
    );
    m.command(connect(4, DEV), now);
    m.command(connect(1, DEV), now);
    assert!(m.take_out().is_empty(), "even, or in use: ignored");
    assert!(calls(&mut m).is_empty());
}

/// A connect that does not come up within CONNECT_BUDGET is cancelled; one
/// raven-node ends is cancelled too.
#[test]
fn a_connect_that_does_not_come_up_is_cancelled() {
    let now = Instant::now();
    let mut m = powered(now);
    assert!(m.discovered(DEV, &[A], None, -50, now));
    m.take_out();
    m.command(
        ToHelper::Connect {
            conn: 1,
            dev: DEV.into(),
            service: h(&A),
            characteristic: h(&CA),
        },
        now,
    );
    calls(&mut m);
    m.tick(now + CONNECT_BUDGET - Duration::from_millis(1));
    assert!(m.take_out().is_empty());
    m.tick(now + CONNECT_BUDGET);
    assert_eq!(calls(&mut m), vec![Call::Cancel(DEV.into())]);
    assert_eq!(m.take_out(), vec![FromHelper::Disconnected { conn: 1 }]);
    let mut m = linked(now);
    m.command(ToHelper::Disconnect { conn: 1 }, now);
    assert_eq!(calls(&mut m), vec![Call::Cancel(DEV.into())]);
    assert_eq!(m.take_out(), vec![FromHelper::Disconnected { conn: 1 }]);
}

/// Too many notifications before the link is up end it.
#[test]
fn early_notifications_are_bounded() {
    let now = Instant::now();
    let mut m = powered(now);
    assert!(m.discovered(DEV, &[A], None, -50, now));
    m.command(
        ToHelper::Connect {
            conn: 1,
            dev: DEV.into(),
            service: h(&A),
            characteristic: h(&CA),
        },
        now,
    );
    m.take_out();
    calls(&mut m);
    for _ in 0..EARLY_FRAMES {
        m.notified(DEV, vec![1], now);
    }
    assert!(m.take_out().is_empty());
    m.notified(DEV, vec![1], now);
    assert_eq!(m.take_out(), vec![FromHelper::Disconnected { conn: 1 }]);
    assert_eq!(calls(&mut m), vec![Call::Cancel(DEV.into())]);
}

/// The radio going off ends every connection and forgets what
/// CoreBluetooth dropped; coming back sets up what raven-node still wants.
#[test]
fn power_off_ends_everything_and_power_on_restores_it() {
    let now = Instant::now();
    let mut m = linked(now);
    m.command(services(&[(A, CA)], Some(A)), now);
    m.command(ToHelper::Scan { on: true }, now);
    m.added(A, true, now);
    m.subscribed(A, CEN, 100, now);
    m.take_out();
    calls(&mut m);
    m.cm_state(CbState::PoweredOff, now);
    assert_eq!(
        m.take_out(),
        vec![
            FromHelper::Disconnected { conn: 1 },
            FromHelper::Disconnected { conn: 2 },
            state(Power::Off, ""),
        ]
    );
    assert_eq!(
        calls(&mut m),
        vec![Call::ForgetCentral(CEN.into()), Call::Reset]
    );
    m.cm_state(CbState::PoweredOn, now);
    assert_eq!(m.take_out(), vec![state(Power::On, "")]);
    assert_eq!(calls(&mut m), vec![Call::Add(A, CA), Call::Scan(true)]);
    m.added(A, true, now);
    assert_eq!(calls(&mut m), vec![Call::Advertise(Some(A))]);
}

/// A withdrawn service ends the connections on it.
#[test]
fn a_withdrawn_service_ends_its_connections() {
    let now = Instant::now();
    let mut m = serving(now);
    m.subscribed(A, CEN, 100, now);
    m.take_out();
    m.command(services(&[], None), now);
    assert_eq!(m.take_out(), vec![FromHelper::Disconnected { conn: 2 }]);
    assert_eq!(
        calls(&mut m),
        vec![Call::Remove(A), Call::ForgetCentral(CEN.into())]
    );
}

/// Unauthorized says where to allow Bluetooth; nothing is set up.
#[test]
fn unauthorized_is_said_with_where_to_allow_it() {
    let now = Instant::now();
    let mut m = machine();
    m.command(ToHelper::Scan { on: true }, now);
    m.cm_state(CbState::Unauthorized, now);
    assert_eq!(m.take_out(), vec![state(Power::Unauthorized, NOT_ALLOWED)]);
    m.pm_state(CbState::Unauthorized, now);
    assert!(m.take_out().is_empty());
    assert!(calls(&mut m).is_empty());
}

/// Stopping (raven-node let go) takes the token off air, stops the scan,
/// ends the links and withdraws the services; nothing more is said.
#[test]
fn stop_withdraws_everything() {
    let now = Instant::now();
    let mut m = linked(now);
    m.command(services(&[(A, CA)], Some(A)), now);
    m.command(ToHelper::Scan { on: true }, now);
    m.added(A, true, now);
    calls(&mut m);
    m.take_out();
    m.stop();
    assert_eq!(
        calls(&mut m),
        vec![
            Call::Advertise(None),
            Call::Scan(false),
            Call::Cancel(DEV.into()),
            Call::Remove(A)
        ]
    );
    m.command(ToHelper::Scan { on: true }, now);
    m.tick(now + Duration::from_secs(60));
    m.cm_state(CbState::PoweredOff, now);
    assert!(m.take_out().is_empty());
    assert!(calls(&mut m).is_empty());
}
