//! The radio seam of the nearby carrier (RNL1 §3-§4, §8; Nearby design step
//! 5.5): what every Bluetooth LE backend and the no-hardware
//! [`super::fake`] radio implement, and [`platform_radio`], the one place
//! that picks a backend.
//!
//! - **Never waits:** a [`Radio`] call returns at once. A connect completes
//!   later as [`RadioEvent::Connected`] or [`RadioEvent::Disconnected`] of
//!   the [`ConnId`] it returned; a send is [`Sent::Queued`], or
//!   [`Sent::WouldBlock`] and then one [`RadioEvent::Writable`].
//! - **One frame is one ATT PDU value:** an RNK1 or RNP1 frame, never split
//!   or joined. A side sends at most `max_tx` bytes per frame and receives at
//!   most `max_rx` (`min(ATT_MTU - 3, 512)` each way).
//! - **Events** reach the engine through one bounded queue of
//!   [`EVENT_QUEUE`] ([`EventTx`]). A full queue never blocks a backend's
//!   callback thread: the event is dropped and counted, and a connection
//!   that lost an event is disconnected (its `Disconnected` is owed and
//!   delivered once there is room), so the pipe on it fails instead of
//!   missing a frame.
//! - **Every connection that ends** gets one `Disconnected`, including one
//!   this side ended.
//! - A [`RadioAddr`] is the backend's opaque handle for a device it saw;
//!   `Debug` never prints it.

// A release build without a platform backend (anything but glibc Linux,
// Windows or macOS with `nearby-radio`; the fake radio and the ether hub are
// debug-only) constructs no radio's events.
#![cfg_attr(not(debug_assertions), allow(dead_code))]

use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use raven_core::nearby_link::Role;
use tokio::sync::mpsc::{self, error::TrySendError};

use super::lock;
use super::pipe::FrameSink;

/// A connection, as the backend numbers it (unique per radio).
pub(crate) type ConnId = u64;

/// The radio's event queue (RNL1 §8: overflow disconnects that connection).
pub(crate) const EVENT_QUEUE: usize = 256;

/// Connections whose owed `Disconnected` was delivered and whose stray
/// events are still dropped (the most recent ones).
const ENDED_MEMORY: usize = 64;

/// The adapter's state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RadioState {
    PoweredOn,
    PoweredOff,
    /// The OS refused Bluetooth to this process (macOS TCC, BlueZ policy).
    Unauthorized(String),
    /// No backend, no adapter, or the adapter lacks a role.
    Unsupported(String),
}

/// What the advertising address reveals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Privacy {
    /// A resolvable or non-resolvable private address.
    Random,
    /// The adapter's public address: never advertised from (owner decision
    /// O5-12) unless a debug lab run allows it.
    Public,
    /// Not known. A backend that cannot tell whether it would advertise
    /// from the adapter's public address reports `Public` instead (BlueZ
    /// does when the management socket cannot tell, P5.29; WinRT always,
    /// P5.30); none reports this.
    #[allow(dead_code)]
    Unknown,
}

/// What a backend can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RadioCaps {
    pub(crate) central: bool,
    /// GATT server and advertising. A central-only radio (Windows without a
    /// working GattServiceProvider) still dials and receives over pipes it
    /// opened.
    pub(crate) peripheral: bool,
    /// Reserved: RNK1 flag bit 0, 0 in V1.
    pub(crate) l2cap: bool,
    pub(crate) address_privacy: Privacy,
    /// Notifications reach only the central they are for.
    pub(crate) per_central_notify: bool,
}

/// A device the backend saw, in the backend's own terms (a BlueZ object
/// path, a WinRT address, a CoreBluetooth identifier, a fake radio's name).
/// Only ever handed back to the same backend's [`Radio::connect`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct RadioAddr(pub(crate) String);

impl fmt::Debug for RadioAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RadioAddr(..)")
    }
}

/// What [`Radio::send`] did with a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    /// It is on its way.
    Queued,
    /// It was not taken: send it again after the connection's next
    /// [`RadioEvent::Writable`].
    WouldBlock,
}

/// What the radio tells the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RadioEvent {
    State(RadioState),
    /// An advertisement: its 128-bit service UUIDs (RNB1 tokens are one).
    Seen {
        addr: RadioAddr,
        uuids: Vec<[u8; 16]>,
        rssi: i16,
    },
    /// A connection is ready for frames. `role` is this side's: the central
    /// connected and subscribed; the peripheral saw that subscription.
    Connected {
        conn: ConnId,
        role: Role,
        service: [u8; 16],
        max_tx: usize,
        max_rx: usize,
    },
    /// Exactly one ATT PDU value.
    Frame {
        conn: ConnId,
        bytes: Vec<u8>,
    },
    /// Room again after a [`Sent::WouldBlock`].
    Writable {
        conn: ConnId,
    },
    Disconnected {
        conn: ConnId,
    },
}

impl RadioEvent {
    /// The connection the event is about, if any.
    pub(crate) fn conn(&self) -> Option<ConnId> {
        match self {
            Self::State(_) | Self::Seen { .. } => None,
            Self::Connected { conn, .. }
            | Self::Frame { conn, .. }
            | Self::Writable { conn }
            | Self::Disconnected { conn } => Some(*conn),
        }
    }
}

/// A Bluetooth LE backend. Every call returns at once (see the module doc).
pub(crate) trait Radio: Send {
    fn caps(&self) -> RadioCaps;
    /// Publish one GATT service per entry of `services` (service UUID `t`,
    /// one characteristic `nearby_link::char_uuid(t)`, RNL1 §4) and
    /// advertise exactly `advertise`: nothing, or one of `services` as the
    /// advertisement's only content. A connection on a service no longer
    /// published ends.
    fn set_services(
        &mut self,
        services: &[[u8; 16]],
        advertise: Option<[u8; 16]>,
    ) -> Result<(), String>;
    /// Passive scanning where the OS allows (RNL1 §3).
    fn set_scanning(&mut self, on: bool) -> Result<(), String>;
    /// Connect to `addr` and subscribe to `service`'s characteristic. The
    /// connection completes as `Connected` or `Disconnected` of the id
    /// returned.
    fn connect(&mut self, addr: &RadioAddr, service: [u8; 16]) -> Result<ConnId, String>;
    /// One frame on `conn` (a Write Command as the central, a Notification
    /// to that central as the peripheral). A frame over `max_tx` is an error.
    fn send(&mut self, conn: ConnId, frame: &[u8]) -> Result<Sent, String>;
    /// End `conn` (where the OS lets a peripheral do so); unknown ids are
    /// ignored.
    fn disconnect(&mut self, conn: ConnId);
    /// Events dropped because the event queue was full.
    fn overflows(&self) -> u64;
}

/// The radio as the engine shares it with its pipes: each pipe sends on its
/// own connection only ([`ConnSink`]). A [`Radio`] call never waits, so the
/// lock is never held long.
pub(crate) type SharedRadio = Arc<Mutex<Box<dyn Radio>>>;

/// One connection of a [`SharedRadio`], as a pipe's [`FrameSink`].
pub(crate) struct ConnSink {
    radio: SharedRadio,
    conn: ConnId,
}

impl ConnSink {
    pub(crate) fn new(radio: SharedRadio, conn: ConnId) -> Self {
        Self { radio, conn }
    }
}

impl FrameSink for ConnSink {
    fn send(&mut self, frame: &[u8]) -> Result<Sent, String> {
        lock(&self.radio).send(self.conn, frame)
    }

    fn disconnect(&mut self) {
        lock(&self.radio).disconnect(self.conn);
    }
}

/// The sending side of a radio's event queue. Never waits: see
/// [`EventTx::emit`].
#[derive(Clone)]
pub(crate) struct EventTx {
    tx: mpsc::Sender<RadioEvent>,
    lost: Arc<Mutex<Lost>>,
}

#[derive(Default)]
struct Lost {
    /// Events dropped because the queue was full.
    dropped: u64,
    /// Connections that lost an event: their `Disconnected` is still owed,
    /// and their other events are moot.
    owed: BTreeSet<ConnId>,
    /// Connections whose owed `Disconnected` was delivered: later events of
    /// theirs are moot too (the last [`ENDED_MEMORY`]).
    ended: VecDeque<ConnId>,
}

impl EventTx {
    pub(crate) fn new(tx: mpsc::Sender<RadioEvent>) -> Self {
        Self {
            tx,
            lost: Arc::default(),
        }
    }

    /// Queue `ev` without waiting, after any owed `Disconnected` that fits
    /// now. `Err(Some(conn))`: the queue was full and `conn` lost an event:
    /// the backend disconnects it now, and its `Disconnected` is delivered
    /// once there is room (exactly once). `Err(None)`: full, and an event of
    /// no connection (a state, an advertisement) was dropped. Later events of
    /// a connection that lost one (its backend's own `Disconnected`
    /// included) are dropped quietly. With nobody listening any more
    /// everything is dropped quietly.
    pub(crate) fn emit(&self, ev: RadioEvent) -> Result<(), Option<ConnId>> {
        let mut lost = lock(&self.lost);
        self.pay(&mut lost);
        let conn = ev.conn();
        if let Some(c) = conn {
            if lost.owed.contains(&c) || lost.ended.contains(&c) {
                return Ok(());
            }
        }
        match self.tx.try_send(ev) {
            Ok(()) | Err(TrySendError::Closed(_)) => Ok(()),
            Err(TrySendError::Full(ev)) => {
                lost.dropped += 1;
                match conn {
                    Some(c) => {
                        lost.owed.insert(c);
                        if matches!(ev, RadioEvent::Disconnected { .. }) {
                            Ok(())
                        } else {
                            Err(Some(c))
                        }
                    }
                    None => Err(None),
                }
            }
        }
    }

    /// Deliver owed `Disconnected` events that fit now (a backend calls
    /// this on its own tick, so they arrive even when nothing else
    /// happens).
    pub(crate) fn flush(&self) {
        self.pay(&mut lock(&self.lost));
    }

    /// Events dropped so far.
    pub(crate) fn dropped(&self) -> u64 {
        lock(&self.lost).dropped
    }

    fn pay(&self, lost: &mut Lost) {
        while let Some(&conn) = lost.owed.first() {
            match self.tx.try_send(RadioEvent::Disconnected { conn }) {
                Ok(()) => {
                    lost.owed.remove(&conn);
                    lost.ended.push_back(conn);
                    if lost.ended.len() > ENDED_MEMORY {
                        lost.ended.pop_front();
                    }
                }
                Err(TrySendError::Full(_)) => return,
                Err(TrySendError::Closed(_)) => {
                    lost.owed.clear();
                    return;
                }
            }
        }
    }
}

/// What [`platform_radio`] answers in a build without a backend.
pub(crate) const NO_BACKEND: &str = "no backend in this build";

// `Unsupported` reasons that mean the Bluetooth software Raven needs on this
// computer is missing, outdated or not running, not that the computer has no
// Bluetooth LE ([`unsupported_kind`]; review nearby-3).

/// How every reason the macOS backend gives about its RavenNearby.app
/// helper starts: not installed, did not start or answer, ended, or speaks
/// another protocol version (`super::apple`).
pub(crate) const HELPER_REASON: &str = "the nearby helper";
/// BlueZ is not on the system bus: bluetoothd stopped or disabled
/// (`super::bluez`).
pub(crate) const BLUEZ_NOT_RUNNING: &str = "BlueZ is not running (no org.bluez on the system bus)";
/// BlueZ left the system bus while the radio ran (`super::bluez`).
pub(crate) const BLUEZ_STOPPED: &str = "BlueZ stopped";
/// No D-Bus system bus at all; the error follows in brackets
/// (`super::bluez`).
pub(crate) const NO_SYSTEM_BUS: &str = "no D-Bus system bus";

/// What an `Unsupported` radio `why` means for the user, as
/// [`raven_core::ipc::NEARBY_RADIO_STATES`] names it: `no_backend` (this
/// build has no Bluetooth backend), `helper_unavailable` (the macOS helper is
/// missing, outdated or did not run), `service_down` (BlueZ or the system
/// bus is not running), else `unsupported` (no adapter, no Bluetooth LE, a
/// role or an error of the operating system).
pub(crate) fn unsupported_kind(why: &str) -> &'static str {
    if why == NO_BACKEND {
        "no_backend"
    } else if why.starts_with(HELPER_REASON) {
        "helper_unavailable"
    } else if why == BLUEZ_NOT_RUNNING || why == BLUEZ_STOPPED || why.starts_with(NO_SYSTEM_BUS) {
        "service_down"
    } else {
        "unsupported"
    }
}

/// The backend [`platform_radio`] would use in this process, without
/// creating anything (`raven-node ble-status`, the service's log line):
/// `ether_hub` (a debug lab run with `RAVEN_LAB_NEARBY_ETHER`), else this
/// build's platform backend (`bluez`, `winrt`, `apple`), else `none`.
pub(crate) fn backend_name() -> &'static str {
    #[cfg(debug_assertions)]
    if matches!(super::ether_hub::lab_ether(), Ok(Some(_))) {
        return "ether_hub";
    }
    if cfg!(all(
        target_os = "linux",
        target_env = "gnu",
        feature = "nearby-radio"
    )) {
        return "bluez";
    }
    if cfg!(all(windows, feature = "nearby-radio")) {
        return "winrt";
    }
    if cfg!(all(target_os = "macos", feature = "nearby-radio")) {
        return "apple";
    }
    "none"
}

/// The radio this process uses, in this order:
/// 1. a debug build with the nearby lab switch on and
///    `RAVEN_LAB_NEARBY_ETHER=127.0.0.1:PORT`: a fake radio on that ether hub
///    ([`super::ether_hub`]);
/// 2. the platform backend of this build, with feature `nearby-radio`:
///    BlueZ on glibc Linux ([`super::bluez`]; its default adapter), WinRT on
///    Windows ([`super::winrt`]; the default adapter), CoreBluetooth on
///    macOS through the RavenNearby.app helper ([`super::apple`]); a musl
///    static build has none;
/// 3. otherwise `Unsupported("no backend in this build")`.
///
/// Called by the nearby engine only once the gate is open and the user
/// enabled nearby, so a closed gate creates no radio object (and no macOS
/// Bluetooth prompt). It may block briefly (a hub or D-Bus connect); call it
/// on the blocking pool, inside the runtime.
pub(crate) fn platform_radio(tx: mpsc::Sender<RadioEvent>) -> Result<Box<dyn Radio>, RadioState> {
    #[cfg(debug_assertions)]
    if let Some(hub) = super::ether_hub::lab_ether().map_err(RadioState::Unsupported)? {
        let name = format!("raven-node-{}", std::process::id());
        return super::ether_hub::HubRadio::connect(hub, &name, Default::default(), tx)
            .map(|r| Box::new(r) as Box<dyn Radio>)
            .map_err(RadioState::Unsupported);
    }
    platform_backend(tx)
}

/// BlueZ on its default adapter.
#[cfg(all(target_os = "linux", target_env = "gnu", feature = "nearby-radio"))]
fn platform_backend(tx: mpsc::Sender<RadioEvent>) -> Result<Box<dyn Radio>, RadioState> {
    super::bluez::dbus::open(None, tx).map(|r| Box::new(r) as Box<dyn Radio>)
}

/// WinRT on the default adapter.
#[cfg(all(windows, feature = "nearby-radio"))]
fn platform_backend(tx: mpsc::Sender<RadioEvent>) -> Result<Box<dyn Radio>, RadioState> {
    super::winrt::sys::open(tx).map(|r| Box::new(r) as Box<dyn Radio>)
}

/// CoreBluetooth in the RavenNearby.app helper.
#[cfg(all(target_os = "macos", feature = "nearby-radio"))]
fn platform_backend(tx: mpsc::Sender<RadioEvent>) -> Result<Box<dyn Radio>, RadioState> {
    super::apple::open(tx).map(|r| Box::new(r) as Box<dyn Radio>)
}

#[cfg(not(any(
    all(target_os = "linux", target_env = "gnu", feature = "nearby-radio"),
    all(windows, feature = "nearby-radio"),
    all(target_os = "macos", feature = "nearby-radio")
)))]
fn platform_backend(tx: mpsc::Sender<RadioEvent>) -> Result<Box<dyn Radio>, RadioState> {
    drop(tx);
    Err(RadioState::Unsupported(NO_BACKEND.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(conn: ConnId) -> RadioEvent {
        RadioEvent::Frame {
            conn,
            bytes: vec![0x10, 0],
        }
    }

    /// RNL1 §8: a full queue never waits; the connection that lost an event
    /// is disconnected, gets exactly one `Disconnected` once there is room,
    /// and its later events are dropped quietly.
    #[test]
    fn a_full_queue_disconnects_the_connection_and_owes_its_end() {
        let (tx, mut rx) = mpsc::channel(2);
        let events = EventTx::new(tx);
        assert_eq!(events.emit(frame(7)), Ok(()));
        assert_eq!(events.emit(frame(8)), Ok(()));
        assert_eq!(events.emit(frame(7)), Err(Some(7)));
        let seen = RadioEvent::Seen {
            addr: RadioAddr("x".into()),
            uuids: vec![[1; 16]],
            rssi: -40,
        };
        assert_eq!(events.emit(seen), Err(None));
        assert_eq!(events.dropped(), 2);
        // Room again: the owed end comes first, once; 7's other events and
        // its own Disconnected (the backend's, after it disconnected) are
        // quiet.
        assert_eq!(rx.try_recv().unwrap(), frame(7));
        assert_eq!(rx.try_recv().unwrap(), frame(8));
        assert_eq!(events.emit(frame(7)), Ok(()));
        assert_eq!(
            events.emit(RadioEvent::Disconnected { conn: 7 }),
            Ok(()),
            "already delivered as owed"
        );
        assert_eq!(rx.try_recv().unwrap(), RadioEvent::Disconnected { conn: 7 });
        assert!(rx.try_recv().is_err(), "nothing else of 7");
        assert_eq!(events.emit(frame(8)), Ok(()));
        assert_eq!(rx.try_recv().unwrap(), frame(8));
    }

    /// An owed end arrives on the backend's tick even when no other event
    /// comes; a lost `Disconnected` is owed and not a reason to disconnect.
    #[test]
    fn flush_pays_owed_ends_and_a_lost_disconnected_is_owed() {
        let (tx, mut rx) = mpsc::channel(1);
        let events = EventTx::new(tx);
        assert_eq!(events.emit(frame(1)), Ok(()));
        assert_eq!(events.emit(RadioEvent::Disconnected { conn: 2 }), Ok(()));
        assert_eq!(events.dropped(), 1);
        events.flush();
        assert_eq!(rx.try_recv().unwrap(), frame(1));
        assert!(rx.try_recv().is_err());
        events.flush();
        assert_eq!(rx.try_recv().unwrap(), RadioEvent::Disconnected { conn: 2 });
        events.flush();
        assert!(rx.try_recv().is_err(), "paid once");
        // Nobody listening: quiet, nothing owed.
        drop(rx);
        assert_eq!(events.emit(frame(3)), Ok(()));
    }

    /// A debug build without the ether switch has no backend unless it is a
    /// glibc Linux, Windows or macOS build with `nearby-radio` (BlueZ, WinRT
    /// or the CoreBluetooth helper, which this test never opens: no real
    /// radio); a backend address never shows in logs.
    #[tokio::test]
    async fn no_backend_without_the_ether_switch() {
        assert_eq!(
            format!("{:?}", RadioAddr("hci0/dev_AA_BB".into())),
            "RadioAddr(..)"
        );
        if std::env::var("RAVEN_LAB_NEARBY_ETHER").is_ok() {
            return;
        }
        if cfg!(all(
            target_os = "linux",
            target_env = "gnu",
            feature = "nearby-radio"
        )) {
            assert_eq!(backend_name(), "bluez");
            return;
        }
        if cfg!(all(windows, feature = "nearby-radio")) {
            assert_eq!(backend_name(), "winrt");
            return;
        }
        if cfg!(all(target_os = "macos", feature = "nearby-radio")) {
            assert_eq!(backend_name(), "apple");
            return;
        }
        assert_eq!(backend_name(), "none");
        let (tx, _rx) = mpsc::channel(1);
        match platform_radio(tx) {
            Err(RadioState::Unsupported(why)) => assert_eq!(why, NO_BACKEND),
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a radio without a backend"),
        }
    }
}
