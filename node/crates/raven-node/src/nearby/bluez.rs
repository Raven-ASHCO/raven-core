//! The Linux BlueZ backend of the nearby radio (RNL1 §3-§4, §8-§9; Nearby
//! design step 5.8). Built for glibc Linux with feature `nearby-radio` only:
//! a musl static build, like every build without a backend, reports `no
//! backend in this build`.
//!
//! This file is the backend's pure part, tested on every platform: the
//! objects this process serves to BlueZ, the state machine that drives
//! BlueZ ([`Core`]) and the radio's send table ([`Table`]). `dbus` (glibc
//! Linux only) is the thin part that speaks D-Bus through zbus 1.9.3 and
//! moves the acquired sockets.
//!
//! **One thread, one connection.** A thread named `raven-bluez` owns one
//! system-bus connection that both serves this process's objects and calls
//! BlueZ. BlueZ calls GetManagedObjects back before it answers
//! RegisterApplication, so the thread never blocks in a call: every call goes
//! out with `send_message` and its reply is matched by its reply serial
//! ([`Pending`]) while the thread keeps answering BlueZ. A radio call (from
//! the engine) or a connection's I/O task queues a [`Cmd`] and wakes the
//! thread. The thread polls the bus socket itself, together with a wake
//! socket: zbus 1.9.3's blocking read spins forever on a closed socket, and
//! the design's wake (a D-Bus method sent to this process's own name from a
//! second connection) would never arrive on a stock system bus, whose
//! default policy denies method calls that no policy file allows.
//!
//! **Objects.** One GATT application per published service, each under its
//! own hand-written ObjectManager (zbus 1.9.3 has none), so publishing or
//! withdrawing one service never moves another one's attribute handles under
//! a live pipe (the design re-registered one application holding every
//! service):
//! - `/org/raven/nearby/app<n>`: ObjectManager, whose GetManagedObjects
//!   answers the two objects below;
//! - `.../app<n>/svc0`: GattService1 {UUID = T, Primary};
//! - `.../app<n>/svc0/chr0`: GattCharacteristic1 {UUID = C(T), Service,
//!   Flags = write-without-response, write, notify}. No read.
//! - `/org/raven/nearby/adv<n>`: LEAdvertisement1 {Type = peripheral,
//!   ServiceUUIDs = [T]}, with no Includes and no LocalName; a new path for
//!   each registration.
//!
//! **Peripheral.** A connection is one central writing to one service. It
//! starts at that central's first write after the characteristic was
//! subscribed (WriteValue names the device and the MTU) and ends when the
//! subscriptions end, the device leaves, or the service is withdrawn.
//! LIMITATION (disclosed, RNL1 §9): BlueZ sends a notification to every
//! subscriber of the characteristic, so `per_central_notify` is false. A
//! stranger that subscribes to a pair's service sees that pipe's ciphertext
//! and sizes, never a plaintext byte, and gets no answer to its own writes.
//!
//! **Central.** Adapter1.SetDiscoveryFilter {Transport le, DuplicateData}
//! then StartDiscovery; a device's 128-bit service UUIDs and RSSI become
//! `Seen` (at most once a second per device). A connect is Device1.Connect,
//! ServicesResolved, the service and its characteristic found by UUID in
//! BlueZ's GetManagedObjects, then AcquireNotify and AcquireWrite: two
//! SOCK_SEQPACKET sockets with one ATT PDU value per read or write, moved by
//! tokio `AsyncFd` with the socket's own backpressure. BlueZ keeps every
//! service UUID a device ever advertised, so a sighting can name a token the
//! device no longer advertises; that connect fails (no such service) and the
//! engine's 10 s gap applies.
//!
//! **Capabilities.** Adapter1.Roles, where BlueZ has it, and the presence of
//! GattManager1 and LEAdvertisingManager1 decide the roles. Address privacy
//! comes from the management socket ([`super::bluez_mgmt`]); unknown counts
//! as public (owner decision O5-12: no advert from it).
//!
//! **Errors.** No system bus or no org.bluez: `Unsupported` with the reason.
//! D-Bus policy refusing BlueZ to this user: `Unauthorized`. A refused
//! registration or scan is tried again after [`RETRY`]. When BlueZ, the
//! adapter or the bus goes away, every connection ends and the thread stops;
//! the engine then ends and the nearby service makes a new radio later.

// Only the D-Bus side (glibc Linux, feature `nearby-radio`) uses all of this;
// the tests build it on every platform.
#![cfg_attr(
    not(all(target_os = "linux", target_env = "gnu", feature = "nearby-radio")),
    allow(dead_code)
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raven_core::nearby_link::{char_uuid, uuid_string, Role, MAX_FRAME};
use serde::Serialize;

use super::radio::{ConnId, EventTx, RadioAddr, RadioCaps, RadioEvent, RadioState, BLUEZ_STOPPED};

#[cfg(all(target_os = "linux", target_env = "gnu", feature = "nearby-radio"))]
pub(crate) mod dbus;
#[cfg(test)]
mod tests;

pub(crate) const BLUEZ: &str = "org.bluez";
pub(crate) const BUS_DAEMON: &str = "org.freedesktop.DBus";
pub(crate) const ADAPTER: &str = "org.bluez.Adapter1";
pub(crate) const DEVICE: &str = "org.bluez.Device1";
pub(crate) const GATT_MANAGER: &str = "org.bluez.GattManager1";
pub(crate) const ADV_MANAGER: &str = "org.bluez.LEAdvertisingManager1";
pub(crate) const GATT_SERVICE: &str = "org.bluez.GattService1";
pub(crate) const GATT_CHAR: &str = "org.bluez.GattCharacteristic1";
pub(crate) const ADVERTISEMENT: &str = "org.bluez.LEAdvertisement1";
pub(crate) const OBJECT_MANAGER: &str = "org.freedesktop.DBus.ObjectManager";
pub(crate) const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
/// Where this process's objects live.
pub(crate) const ROOT: &str = "/org/raven/nearby";
/// The characteristic's properties (RNL1 §4: WriteWithoutResponse | Write |
/// Notify, no Read).
const FLAGS: [&str; 3] = ["write-without-response", "write", "notify"];

pub(crate) const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
pub(crate) const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";
pub(crate) const UNKNOWN_INTERFACE: &str = "org.freedesktop.DBus.Error.UnknownInterface";
pub(crate) const UNKNOWN_PROPERTY: &str = "org.freedesktop.DBus.Error.UnknownProperty";
pub(crate) const UNKNOWN_METHOD: &str = "org.freedesktop.DBus.Error.UnknownMethod";
pub(crate) const NOT_SUPPORTED: &str = "org.bluez.Error.NotSupported";

/// ATT's MTU when nothing larger was negotiated (or BlueZ names none).
const ATT_DEFAULT_MTU: u16 = 23;
/// How long a call to BlueZ may go unanswered (BlueZ's own calls time out at
/// 25 s).
pub(crate) const CALL_DEADLINE: Duration = Duration::from_secs(30);
/// How long a connect may take to come up (the engine gives up sooner).
pub(crate) const CONNECT_BUDGET: Duration = Duration::from_secs(20);
/// A refused registration or scan is tried again after this.
pub(crate) const RETRY: Duration = Duration::from_secs(10);
/// A device that keeps advertising is `Seen` at most this often (a change
/// of its UUIDs at once).
pub(crate) const SEEN_EVERY: Duration = Duration::from_secs(1);
/// Writes from a central whose connection this side ended are ignored this
/// long, unless its link drops first.
pub(crate) const SILENCE: Duration = Duration::from_secs(10);
/// Remote devices remembered (BlueZ reports every device in range).
pub(crate) const MAX_DEVICES: usize = 1024;
/// Peripheral connections at once (the engine keeps at most 8 knocking and
/// 4 pipes).
pub(crate) const MAX_PERIPHERAL: usize = 16;
/// Silenced (device, service) pairs remembered.
const MAX_SILENCED: usize = 256;
/// Notifications a peripheral connection may have queued for the bus thread
/// before a send is [`super::radio::Sent::WouldBlock`].
pub(crate) const NOTIFY_WINDOW: usize = 16;

// ── UUIDs and paths ─────────────────────────────────────────────────────────

/// A UUID from BlueZ's text form (8-4-4-4-12 hex digits, either case).
pub(crate) fn uuid_parse(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
        return None;
    }
    let digits: String = s.chars().filter(|c| *c != '-').collect();
    let mut out = [0u8; 16];
    hex::decode_to_slice(digits, &mut out).ok()?;
    Some(out)
}

/// The Bluetooth base UUID's last 12 bytes (`xxxxxxxx-0000-1000-8000-
/// 00805f9b34fb`): a 16- or 32-bit UUID written long, never an RNB1 token
/// (whose byte 6 starts with the version nibble 4).
const SIG_BASE_TAIL: [u8; 12] = [
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// A Bluetooth SIG UUID, not a candidate token.
pub(crate) fn is_sig_uuid(u: &[u8; 16]) -> bool {
    u[4..] == SIG_BASE_TAIL
}

pub(crate) fn app_path(slot: u32) -> String {
    format!("{ROOT}/app{slot}")
}

pub(crate) fn service_path(slot: u32) -> String {
    format!("{ROOT}/app{slot}/svc0")
}

pub(crate) fn char_path(slot: u32) -> String {
    format!("{ROOT}/app{slot}/svc0/chr0")
}

pub(crate) fn adv_path(seq: u32) -> String {
    format!("{ROOT}/adv{seq}")
}

/// Which of this process's objects a path names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Obj {
    App(u32),
    Service(u32),
    Char(u32),
    Adv(u32),
}

/// The object `path` names, if it is one of this process's.
pub(crate) fn object_of(path: &str) -> Option<Obj> {
    let rest = path.strip_prefix(ROOT)?.strip_prefix('/')?;
    if let Some(n) = rest.strip_prefix("adv") {
        return number(n).map(Obj::Adv);
    }
    let rest = rest.strip_prefix("app")?;
    let (n, tail) = match rest.split_once('/') {
        Some((n, tail)) => (n, Some(tail)),
        None => (rest, None),
    };
    let n = number(n)?;
    match tail {
        None => Some(Obj::App(n)),
        Some("svc0") => Some(Obj::Service(n)),
        Some("svc0/chr0") => Some(Obj::Char(n)),
        Some(_) => None,
    }
}

/// A path component's number: decimal, no leading zero.
fn number(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// The largest frame each way on a link of ATT MTU `mtu` (RNL1 §4:
/// `min(ATT_MTU - 3, 512)`).
pub(crate) fn frame_limit(mtu: u16) -> usize {
    usize::from(mtu.max(ATT_DEFAULT_MTU) - 3).min(MAX_FRAME)
}

// ── The objects this process serves ─────────────────────────────────────────

/// A D-Bus property value as this process serves it, tagged with its D-Bus
/// signature (the golden map writes it that way).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Prop {
    #[serde(rename = "s")]
    Str(String),
    #[serde(rename = "b")]
    Bool(bool),
    #[serde(rename = "o")]
    Path(String),
    #[serde(rename = "as")]
    Strs(Vec<String>),
}

pub(crate) type Props = BTreeMap<&'static str, Prop>;
/// GetManagedObjects' answer: object path, interface, properties.
pub(crate) type Objects = BTreeMap<String, BTreeMap<&'static str, Props>>;

fn service_props(t: &[u8; 16]) -> Props {
    BTreeMap::from([
        ("UUID", Prop::Str(uuid_string(t))),
        ("Primary", Prop::Bool(true)),
    ])
}

fn char_props(slot: u32, t: &[u8; 16]) -> Props {
    BTreeMap::from([
        ("UUID", Prop::Str(uuid_string(&char_uuid(t)))),
        ("Service", Prop::Path(service_path(slot))),
        (
            "Flags",
            Prop::Strs(FLAGS.iter().map(|f| (*f).to_owned()).collect()),
        ),
    ])
}

fn adv_props(t: &[u8; 16]) -> Props {
    BTreeMap::from([
        ("Type", Prop::Str("peripheral".to_owned())),
        ("ServiceUUIDs", Prop::Strs(vec![uuid_string(t)])),
    ])
}

/// What application `slot` (serving `t`) answers to GetManagedObjects.
pub(crate) fn app_objects(slot: u32, t: &[u8; 16]) -> Objects {
    BTreeMap::from([
        (
            service_path(slot),
            BTreeMap::from([(GATT_SERVICE, service_props(t))]),
        ),
        (
            char_path(slot),
            BTreeMap::from([(GATT_CHAR, char_props(slot, t))]),
        ),
    ])
}

// ── What goes to and comes from BlueZ ───────────────────────────────────────

/// A call this process makes to BlueZ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Call {
    pub(crate) path: String,
    pub(crate) iface: &'static str,
    pub(crate) member: &'static str,
    pub(crate) args: Args,
}

/// A call's arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Args {
    None,
    /// An empty options dict (`a{sv}`: AcquireNotify, AcquireWrite).
    Options,
    /// One of this process's object paths and empty options (`oa{sv}`:
    /// RegisterApplication, RegisterAdvertisement).
    Register(String),
    /// One of this process's object paths (`o`: Unregister*).
    Unregister(String),
    /// SetDiscoveryFilter's `{Transport: "le", DuplicateData: true}`.
    LeFilter,
}

/// What a call in flight is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Register([u8; 16]),
    Unregister([u8; 16]),
    AdvRegister(u32),
    AdvUnregister(u32),
    Filter,
    StartScan,
    StopScan,
    Connect(ConnId),
    Find(ConnId),
    AcquireNotify(ConnId),
    AcquireWrite(ConnId),
    Disconnect,
}

/// What a reply's body holds, for the D-Bus side to decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    Nothing,
    /// BlueZ's GetManagedObjects: the remote GATT objects.
    Objects,
    /// AcquireNotify or AcquireWrite: a socket and the ATT MTU.
    Socket,
}

impl Op {
    fn expect(self) -> Expect {
        match self {
            Self::Find(_) => Expect::Objects,
            Self::AcquireNotify(_) | Self::AcquireWrite(_) => Expect::Socket,
            _ => Expect::Nothing,
        }
    }
}

/// A reply, decoded.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reply<F> {
    Done,
    Objects(Vec<Remote>),
    Socket {
        fd: F,
        mtu: u16,
    },
    /// The D-Bus error name (never its text, which may name a device).
    Failed(String),
}

/// A remote GATT object in BlueZ's GetManagedObjects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Remote {
    Service {
        path: String,
        uuid: [u8; 16],
        device: String,
    },
    Char {
        path: String,
        uuid: [u8; 16],
        service: String,
    },
}

/// Calls in flight, by serial: a reply carries its call's serial as its
/// reply serial. A reply nobody waits for (late, or a stranger's) matches
/// nothing.
pub(crate) struct Pending<T> {
    calls: HashMap<u32, (T, Instant)>,
}

impl<T: Copy> Pending<T> {
    pub(crate) fn new() -> Self {
        Self {
            calls: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, serial: u32, what: T, at: Instant) {
        self.calls.insert(serial, (what, at));
    }

    pub(crate) fn peek(&self, serial: u32) -> Option<T> {
        self.calls.get(&serial).map(|(what, _)| *what)
    }

    pub(crate) fn take(&mut self, serial: u32) -> Option<T> {
        self.calls.remove(&serial).map(|(what, _)| what)
    }

    /// The calls sent `deadline` or longer ago, removed (oldest first).
    pub(crate) fn expire(&mut self, now: Instant, deadline: Duration) -> Vec<T> {
        let mut late: Vec<(u32, Instant)> = self
            .calls
            .iter()
            .filter(|(_, (_, at))| now.saturating_duration_since(*at) >= deadline)
            .map(|(serial, (_, at))| (*serial, *at))
            .collect();
        late.sort_by_key(|(serial, at)| (*at, *serial));
        late.into_iter()
            .filter_map(|(serial, _)| self.take(serial))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.calls.len()
    }
}

/// A device's properties as a signal or GetManagedObjects names them (absent
/// ones did not change).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeviceProps {
    pub(crate) uuids: Option<Vec<[u8; 16]>>,
    pub(crate) rssi: Option<i16>,
    pub(crate) connected: Option<bool>,
    pub(crate) resolved: Option<bool>,
}

/// A signal from BlueZ (or the bus), decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Signal {
    /// Adapter1 added or changed: its `Powered`, when named.
    Adapter { path: String, powered: Option<bool> },
    /// Device1 added or changed.
    Device { path: String, props: DeviceProps },
    /// Interfaces removed from an object.
    Removed { path: String, ifaces: Vec<String> },
    /// org.bluez has a new owner (`None`: BlueZ stopped).
    Owner(Option<String>),
}

/// A method call BlueZ makes on this process's objects, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Incoming {
    ManagedObjects,
    GetAll(String),
    Get(String, String),
    Write {
        value: Vec<u8>,
        device: Option<String>,
        mtu: Option<u16>,
    },
    StartNotify,
    StopNotify,
    Read,
    Release,
    Other,
}

/// The answer to an [`Incoming`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    Objects(Objects),
    Props(Props),
    Prop(Prop),
    Unit,
    Error(&'static str),
}

/// What the radio handle and the I/O tasks ask of the bus thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Cmd {
    Services(Vec<[u8; 16]>, Option<[u8; 16]>),
    Scan(bool),
    Connect {
        conn: ConnId,
        device: String,
        service: [u8; 16],
    },
    /// A frame for a peripheral connection's central (a notification).
    Notify {
        conn: ConnId,
        frame: Vec<u8>,
    },
    Disconnect(ConnId),
    /// A central connection's sockets closed or failed (or its events were
    /// lost).
    Down(ConnId),
    Stop,
}

/// The bus side of [`Core`]: D-Bus in the backend, a recorder in the tests.
pub(crate) trait Bus {
    /// An acquired socket.
    type Fd;
    /// Send a call to BlueZ without waiting; its serial.
    fn call(&mut self, call: Call) -> Result<u32, String>;
    /// Notify `value` on the characteristic at `chr` for peripheral
    /// connection `conn`.
    fn notify(&mut self, conn: ConnId, chr: &str, value: &[u8]);
    /// Central connection `conn` is up: its sends go to `write` from now
    /// on, and its frames will come on `notify`.
    fn central_up(
        &mut self,
        conn: ConnId,
        notify: Self::Fd,
        write: Self::Fd,
        max_tx: usize,
        max_rx: usize,
    );
    /// Start reading central connection `conn`'s frames (after its
    /// `Connected`, so no frame comes before it).
    fn start_reading(&mut self, conn: ConnId);
    /// Peripheral connection `conn` is up: its sends become notifications.
    fn peripheral_up(&mut self, conn: ConnId, max_tx: usize);
    /// `conn` ended: stop its I/O and forget its send route.
    fn ended(&mut self, conn: ConnId);
}

// ── The state machine ───────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reg {
    Registering,
    Registered,
    Unregistering,
    Failed(Instant),
}

/// One published service's GATT application.
struct App {
    slot: u32,
    reg: Reg,
    /// A central subscribed to its characteristic (StartNotify).
    notifying: bool,
}

/// The advertisement registered (or on its way).
struct Adv {
    uuid: [u8; 16],
    seq: u32,
    reg: Reg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scan {
    Off,
    Starting,
    On,
    Stopping,
    Failed(Instant),
}

/// A remote device under the adapter.
struct Device {
    uuids: Vec<[u8; 16]>,
    rssi: Option<i16>,
    connected: bool,
    resolved: bool,
    /// The last `Seen` and how many tokens it named.
    seen: Option<(Instant, usize)>,
    touched: Instant,
}

enum Stage<F> {
    Connecting,
    Resolving,
    Finding,
    Acquiring {
        notify: Option<(F, u16)>,
        write: Option<(F, u16)>,
    },
    Up,
}

enum Conn<F> {
    Central {
        device: String,
        service: [u8; 16],
        stage: Stage<F>,
        deadline: Instant,
    },
    Peripheral {
        device: String,
        service: [u8; 16],
        slot: u32,
    },
}

impl<F> Conn<F> {
    fn device(&self) -> &str {
        match self {
            Self::Central { device, .. } | Self::Peripheral { device, .. } => device,
        }
    }
}

/// The adapter as [`Core`] starts from (the D-Bus side reads it at open).
pub(crate) struct Start {
    pub(crate) adapter: String,
    /// org.bluez's owner: only it may call this process's objects or send
    /// the signals [`Core`] acts on.
    pub(crate) bluez: String,
    pub(crate) caps: RadioCaps,
    pub(crate) powered: bool,
    /// The devices BlueZ knows under the adapter now.
    pub(crate) devices: Vec<(String, DeviceProps)>,
}

/// The backend's state machine: it publishes the services and the advert the
/// engine asks for, scans, connects and keeps every connection's state,
/// emitting the radio's events. Every input is a method; every output is a
/// [`Bus`] call or an event.
pub(crate) struct Core<B: Bus> {
    pub(crate) bus: B,
    events: EventTx,
    adapter: String,
    bluez: String,
    caps: RadioCaps,
    powered: bool,
    alive: bool,
    want_services: BTreeSet<[u8; 16]>,
    apps: BTreeMap<[u8; 16], App>,
    want_advert: Option<[u8; 16]>,
    adv: Option<Adv>,
    next_adv: u32,
    want_scan: bool,
    scan: Scan,
    devices: HashMap<String, Device>,
    conns: BTreeMap<ConnId, Conn<B::Fd>>,
    silenced: HashMap<(String, [u8; 16]), Instant>,
    next_peripheral: ConnId,
    pending: Pending<Op>,
    /// Connections whose events the queue lost: ended once the current
    /// input is handled.
    lost: Vec<ConnId>,
    /// The last BlueZ error logged (each distinct one once in a row).
    logged: Option<String>,
}

impl<B: Bus> Core<B> {
    pub(crate) fn new(bus: B, events: EventTx, start: Start, now: Instant) -> Self {
        let devices = start
            .devices
            .into_iter()
            .filter(|(path, _)| is_device_of(&start.adapter, path))
            .take(MAX_DEVICES)
            .map(|(path, p)| {
                let d = Device {
                    uuids: p.uuids.unwrap_or_default(),
                    rssi: None,
                    connected: p.connected.unwrap_or(false),
                    resolved: p.resolved.unwrap_or(false),
                    seen: None,
                    touched: now,
                };
                (path, d)
            })
            .collect();
        Self {
            bus,
            events,
            adapter: start.adapter,
            bluez: start.bluez,
            caps: start.caps,
            powered: start.powered,
            alive: true,
            want_services: BTreeSet::new(),
            apps: BTreeMap::new(),
            want_advert: None,
            adv: None,
            next_adv: 0,
            want_scan: false,
            scan: Scan::Off,
            devices,
            conns: BTreeMap::new(),
            silenced: HashMap::new(),
            // Peripheral connections are even; the radio handle numbers
            // central ones odd.
            next_peripheral: 2,
            pending: Pending::new(),
            lost: Vec::new(),
            logged: None,
        }
    }

    /// Tell the engine the adapter's state.
    pub(crate) fn start(&mut self) {
        let state = if self.powered {
            RadioState::PoweredOn
        } else {
            RadioState::PoweredOff
        };
        self.emit(RadioEvent::State(state));
    }

    /// False once BlueZ, the adapter or the bus went away, or the radio was
    /// dropped: the thread stops.
    pub(crate) fn alive(&self) -> bool {
        self.alive
    }

    /// Events the queue dropped so far.
    pub(crate) fn dropped(&self) -> u64 {
        self.events.dropped()
    }

    /// How to decode the reply with this serial; `None`: nobody waits for
    /// it.
    pub(crate) fn expects(&self, serial: u32) -> Option<Expect> {
        self.pending.peek(serial).map(Op::expect)
    }

    // ── Inputs ──────────────────────────────────────────────────────────

    pub(crate) fn command(&mut self, cmd: Cmd, now: Instant) {
        match cmd {
            Cmd::Services(services, advert) => {
                self.want_services = services.into_iter().collect();
                self.want_advert = advert.filter(|t| self.want_services.contains(t));
                // A connection on a service no longer published ends.
                let gone: Vec<ConnId> = self
                    .conns
                    .iter()
                    .filter(|(_, c)| {
                        matches!(c, Conn::Peripheral { service, .. }
                            if !self.want_services.contains(service))
                    })
                    .map(|(id, _)| *id)
                    .collect();
                for conn in gone {
                    self.end(conn, true, now);
                }
                self.reconcile(now);
            }
            Cmd::Scan(on) => {
                self.want_scan = on;
                self.reconcile_scan(now);
            }
            Cmd::Connect {
                conn,
                device,
                service,
            } => self.connect(conn, device, service, now),
            Cmd::Notify { conn, frame } => {
                if let Some(Conn::Peripheral { slot, .. }) = self.conns.get(&conn) {
                    let chr = char_path(*slot);
                    self.bus.notify(conn, &chr, &frame);
                }
            }
            Cmd::Disconnect(conn) | Cmd::Down(conn) => self.end(conn, true, now),
            Cmd::Stop => self.shutdown(None, true, now),
        }
        self.settle(now);
    }

    pub(crate) fn reply(&mut self, serial: u32, reply: Reply<B::Fd>, now: Instant) {
        // A reply nobody waits for is dropped (with any socket it brought).
        let Some(op) = self.pending.take(serial) else {
            return;
        };
        self.on_reply(op, reply, now);
        self.settle(now);
    }

    /// A signal from `sender`: BlueZ's own, or the bus daemon's
    /// NameOwnerChanged. Anything else (a unicast signal from another
    /// process) is ignored.
    pub(crate) fn signal(&mut self, sender: Option<&str>, sig: Signal, now: Instant) {
        let from = match &sig {
            Signal::Owner(_) => BUS_DAEMON,
            _ => self.bluez.as_str(),
        };
        if sender != Some(from) {
            return;
        }
        match sig {
            Signal::Adapter { path, powered } => {
                if let (true, Some(on)) = (path == self.adapter, powered) {
                    self.set_powered(on, now);
                }
            }
            Signal::Device { path, props } => {
                if self.is_device(&path) {
                    self.device(path, props, now);
                }
            }
            Signal::Removed { path, ifaces } => {
                if path == self.adapter && ifaces.iter().any(|i| i == ADAPTER) {
                    self.shutdown(Some("the Bluetooth adapter went away"), false, now);
                } else if ifaces.iter().any(|i| i == DEVICE) && self.devices.remove(&path).is_some()
                {
                    self.device_down(&path, now);
                }
            }
            Signal::Owner(owner) => {
                if owner.as_deref() != Some(self.bluez.as_str()) {
                    self.shutdown(Some(BLUEZ_STOPPED), false, now);
                }
            }
        }
        self.settle(now);
    }

    /// A method call on one of this process's objects. Only BlueZ may make
    /// one.
    pub(crate) fn call(
        &mut self,
        sender: Option<&str>,
        path: &str,
        call: Incoming,
        now: Instant,
    ) -> Answer {
        if sender != Some(self.bluez.as_str()) {
            return Answer::Error(ACCESS_DENIED);
        }
        let Some(obj) = object_of(path) else {
            return Answer::Error(UNKNOWN_OBJECT);
        };
        let answer = match (obj, call) {
            (Obj::App(slot), Incoming::ManagedObjects) => match self.app_at(slot) {
                Some(t) => Answer::Objects(app_objects(slot, &t)),
                None => Answer::Error(UNKNOWN_OBJECT),
            },
            (obj, Incoming::GetAll(iface)) => match self.props_of(obj) {
                Some((name, props)) if name == iface => Answer::Props(props),
                Some(_) => Answer::Error(UNKNOWN_INTERFACE),
                None => Answer::Error(UNKNOWN_OBJECT),
            },
            (obj, Incoming::Get(iface, prop)) => match self.props_of(obj) {
                Some((name, mut props)) if name == iface => match props.remove(prop.as_str()) {
                    Some(p) => Answer::Prop(p),
                    None => Answer::Error(UNKNOWN_PROPERTY),
                },
                Some(_) => Answer::Error(UNKNOWN_INTERFACE),
                None => Answer::Error(UNKNOWN_OBJECT),
            },
            (Obj::Char(slot), Incoming::Write { value, device, mtu }) => {
                self.write(slot, value, device, mtu, now);
                Answer::Unit
            }
            (Obj::Char(slot), Incoming::StartNotify) => {
                if let Some(app) = self.apps.values_mut().find(|a| a.slot == slot) {
                    app.notifying = true;
                }
                Answer::Unit
            }
            (Obj::Char(slot), Incoming::StopNotify) => {
                self.stop_notify(slot, now);
                Answer::Unit
            }
            (Obj::Char(_), Incoming::Read) => Answer::Error(NOT_SUPPORTED),
            (Obj::Adv(seq), Incoming::Release) => {
                // BlueZ dropped the advert (adapter off, or its own reasons):
                // register it again while it is still wanted.
                if self.adv.as_ref().is_some_and(|a| a.seq == seq) {
                    self.adv = None;
                    self.reconcile_adv(now);
                }
                Answer::Unit
            }
            _ => Answer::Error(UNKNOWN_METHOD),
        };
        self.settle(now);
        answer
    }

    /// Deadlines, retries and owed events.
    pub(crate) fn tick(&mut self, now: Instant) {
        for op in self.pending.expire(now, CALL_DEADLINE) {
            self.on_reply(op, Reply::Failed("timeout".to_owned()), now);
        }
        let late: Vec<ConnId> = self
            .conns
            .iter()
            .filter_map(|(id, c)| match c {
                Conn::Central {
                    stage, deadline, ..
                } if !matches!(stage, Stage::Up) && now >= *deadline => Some(*id),
                _ => None,
            })
            .collect();
        for conn in late {
            self.end(conn, true, now);
        }
        self.silenced.retain(|_, until| *until > now);
        self.reconcile(now);
        self.events.flush();
        self.settle(now);
    }

    // ── Commands ────────────────────────────────────────────────────────

    fn connect(&mut self, conn: ConnId, device: String, service: [u8; 16], now: Instant) {
        if !self.alive
            || !self.powered
            || !self.caps.central
            || !self.is_device(&device)
            || self.conns.contains_key(&conn)
        {
            self.emit(RadioEvent::Disconnected { conn });
            return;
        }
        let call = Call {
            path: device.clone(),
            iface: DEVICE,
            member: "Connect",
            args: Args::None,
        };
        self.conns.insert(
            conn,
            Conn::Central {
                device,
                service,
                stage: Stage::Connecting,
                deadline: now + CONNECT_BUDGET,
            },
        );
        if !self.send(call, Op::Connect(conn), now) {
            self.end(conn, false, now);
        }
    }

    /// End `conn` with one `Disconnected`. `local`: this side ended it, so
    /// the device's link is dropped too once no other connection uses it,
    /// and a central that wrote to us is silenced for [`SILENCE`].
    fn end(&mut self, conn: ConnId, local: bool, now: Instant) {
        let Some(c) = self.conns.remove(&conn) else {
            return;
        };
        self.bus.ended(conn);
        if let (
            true,
            Conn::Peripheral {
                device, service, ..
            },
        ) = (local, &c)
        {
            if self.silenced.len() >= MAX_SILENCED {
                self.silenced.retain(|_, until| *until > now);
            }
            if self.silenced.len() < MAX_SILENCED {
                self.silenced
                    .insert((device.clone(), *service), now + SILENCE);
            }
        }
        let device = c.device().to_owned();
        // An acquired socket (a central still acquiring) closes here.
        drop(c);
        self.emit(RadioEvent::Disconnected { conn });
        if local && self.alive && !self.conns.values().any(|c| c.device() == device) {
            let call = Call {
                path: device,
                iface: DEVICE,
                member: "Disconnect",
                args: Args::None,
            };
            self.send(call, Op::Disconnect, now);
        }
    }

    /// Every connection ends; the thread stops. `why`: tell the engine the
    /// radio is gone (BlueZ, the adapter or the bus went away).
    pub(crate) fn shutdown(&mut self, why: Option<&str>, local: bool, now: Instant) {
        if !self.alive {
            return;
        }
        let all: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in all {
            self.end(conn, local, now);
        }
        self.alive = false;
        if let Some(why) = why {
            self.note("stopped", why);
            self.emit(RadioEvent::State(RadioState::Unsupported(why.to_owned())));
        }
    }

    // ── Replies ─────────────────────────────────────────────────────────

    fn on_reply(&mut self, op: Op, reply: Reply<B::Fd>, now: Instant) {
        let error = match &reply {
            Reply::Failed(e) => Some(e.clone()),
            _ => None,
        };
        let failed_but = |also: &str| error.as_deref().is_some_and(|e| e != also);
        match op {
            Op::Register(t) => {
                // AlreadyExists: an earlier, timed-out registration did land.
                let ok = !failed_but("org.bluez.Error.AlreadyExists");
                if let Some(app) = self.apps.get_mut(&t) {
                    app.reg = if ok {
                        Reg::Registered
                    } else {
                        Reg::Failed(now)
                    };
                }
                if !ok {
                    self.note("RegisterApplication", error.as_deref().unwrap_or(""));
                }
                self.reconcile(now);
            }
            Op::Unregister(t) => {
                self.apps.remove(&t);
                self.reconcile(now);
            }
            Op::AdvRegister(seq) => {
                let ok = error.is_none();
                if let Some(adv) = self.adv.as_mut().filter(|a| a.seq == seq) {
                    adv.reg = if ok {
                        Reg::Registered
                    } else {
                        Reg::Failed(now)
                    };
                }
                if !ok {
                    self.note("RegisterAdvertisement", error.as_deref().unwrap_or(""));
                }
                self.reconcile_adv(now);
            }
            Op::AdvUnregister(seq) => {
                if self.adv.as_ref().is_some_and(|a| a.seq == seq) {
                    self.adv = None;
                }
                self.reconcile_adv(now);
            }
            Op::Filter => {
                // Whatever the answer (an older BlueZ may lack DuplicateData),
                // start: the filter only refines the scan.
                if self.want_scan && self.powered {
                    let call = self.adapter_call("StartDiscovery", Args::None);
                    if !self.send(call, Op::StartScan, now) {
                        self.scan = Scan::Failed(now);
                    }
                } else {
                    self.scan = Scan::Off;
                    self.reconcile_scan(now);
                }
            }
            Op::StartScan => {
                // InProgress: this client's discovery already runs.
                let ok = !failed_but("org.bluez.Error.InProgress");
                self.scan = if ok { Scan::On } else { Scan::Failed(now) };
                if !ok {
                    self.note("StartDiscovery", error.as_deref().unwrap_or(""));
                }
                self.reconcile_scan(now);
            }
            Op::StopScan => {
                self.scan = Scan::Off;
                self.reconcile_scan(now);
            }
            Op::Connect(conn) => {
                if failed_but("org.bluez.Error.AlreadyConnected") {
                    self.end(conn, false, now);
                } else if let Some(Conn::Central { device, stage, .. }) = self.conns.get_mut(&conn)
                {
                    if matches!(stage, Stage::Connecting) {
                        *stage = Stage::Resolving;
                        let resolved = self
                            .devices
                            .get(device.as_str())
                            .is_some_and(|d| d.resolved);
                        if resolved {
                            self.find(conn, now);
                        }
                    }
                }
            }
            Op::Find(conn) => match reply {
                Reply::Objects(objects) => self.found(conn, &objects, now),
                _ => self.end(conn, true, now),
            },
            Op::AcquireNotify(conn) | Op::AcquireWrite(conn) => match reply {
                Reply::Socket { fd, mtu } => {
                    self.acquired(conn, matches!(op, Op::AcquireNotify(_)), fd, mtu);
                }
                _ => self.end(conn, true, now),
            },
            Op::Disconnect => {}
        }
    }

    /// Look the connection's service up (BlueZ resolved the device's
    /// services).
    fn find(&mut self, conn: ConnId, now: Instant) {
        let Some(Conn::Central { stage, .. }) = self.conns.get_mut(&conn) else {
            return;
        };
        *stage = Stage::Finding;
        let call = Call {
            path: "/".to_owned(),
            iface: OBJECT_MANAGER,
            member: "GetManagedObjects",
            args: Args::None,
        };
        if !self.send(call, Op::Find(conn), now) {
            self.end(conn, true, now);
        }
    }

    /// The service `T` on the connection's device and its characteristic
    /// `C(T)`; then both sockets.
    fn found(&mut self, conn: ConnId, objects: &[Remote], now: Instant) {
        let Some(Conn::Central {
            device, service, ..
        }) = self.conns.get(&conn)
        else {
            return;
        };
        let (device, t) = (device.clone(), *service);
        let under = format!("{device}/");
        let svc = objects.iter().find_map(|o| match o {
            Remote::Service {
                path,
                uuid,
                device: d,
            } if *uuid == t && *d == device && path.starts_with(&under) => Some(path.clone()),
            _ => None,
        });
        let want = char_uuid(&t);
        let chr = svc.and_then(|svc| {
            let under = format!("{svc}/");
            objects.iter().find_map(|o| match o {
                Remote::Char {
                    path,
                    uuid,
                    service,
                } if *uuid == want && *service == svc && path.starts_with(&under) => {
                    Some(path.clone())
                }
                _ => None,
            })
        });
        let Some(chr) = chr else {
            self.end(conn, true, now);
            return;
        };
        if let Some(Conn::Central { stage, .. }) = self.conns.get_mut(&conn) {
            *stage = Stage::Acquiring {
                notify: None,
                write: None,
            };
        }
        // Subscribe first (AcquireNotify writes the CCCD), then the write
        // socket; the replies may come in either order.
        for (member, op) in [
            ("AcquireNotify", Op::AcquireNotify(conn)),
            ("AcquireWrite", Op::AcquireWrite(conn)),
        ] {
            let call = Call {
                path: chr.clone(),
                iface: GATT_CHAR,
                member,
                args: Args::Options,
            };
            if !self.send(call, op, now) {
                self.end(conn, true, now);
                return;
            }
        }
    }

    fn acquired(&mut self, conn: ConnId, notify: bool, fd: B::Fd, mtu: u16) {
        let Some(Conn::Central { service, stage, .. }) = self.conns.get_mut(&conn) else {
            return;
        };
        let Stage::Acquiring {
            notify: n,
            write: w,
        } = stage
        else {
            return;
        };
        if notify {
            *n = Some((fd, mtu));
        } else {
            *w = Some((fd, mtu));
        }
        if n.is_none() || w.is_none() {
            return;
        }
        let service = *service;
        let Stage::Acquiring {
            notify: Some((nfd, nmtu)),
            write: Some((wfd, wmtu)),
        } = std::mem::replace(stage, Stage::Up)
        else {
            return;
        };
        let (max_tx, max_rx) = (frame_limit(wmtu), frame_limit(nmtu));
        // The send route first (the engine sends HELLO on Connected), the
        // reading last (no frame before Connected).
        self.bus.central_up(conn, nfd, wfd, max_tx, max_rx);
        self.emit(RadioEvent::Connected {
            conn,
            role: Role::Central,
            service,
            max_tx,
            max_rx,
        });
        self.bus.start_reading(conn);
    }

    // ── Signals ─────────────────────────────────────────────────────────

    fn set_powered(&mut self, on: bool, now: Instant) {
        if on == self.powered {
            return;
        }
        self.powered = on;
        if on {
            self.emit(RadioEvent::State(RadioState::PoweredOn));
            // An advert BlueZ still holds may not be on air after the
            // power cycle: register it again.
            if let Some(adv) = self.adv.as_mut().filter(|a| a.reg == Reg::Registered) {
                adv.reg = Reg::Unregistering;
                let call = Call {
                    path: self.adapter.clone(),
                    iface: ADV_MANAGER,
                    member: "UnregisterAdvertisement",
                    args: Args::Unregister(adv_path(adv.seq)),
                };
                let op = Op::AdvUnregister(adv.seq);
                self.send(call, op, now);
            }
        } else {
            let all: Vec<ConnId> = self.conns.keys().copied().collect();
            for conn in all {
                self.end(conn, false, now);
            }
            // The adapter's discovery ended with the power.
            self.scan = Scan::Off;
            self.emit(RadioEvent::State(RadioState::PoweredOff));
        }
        self.reconcile(now);
    }

    fn device(&mut self, path: String, props: DeviceProps, now: Instant) {
        if !self.devices.contains_key(&path) && self.devices.len() >= MAX_DEVICES {
            self.evict_device();
        }
        let d = self.devices.entry(path.clone()).or_insert(Device {
            uuids: Vec::new(),
            rssi: None,
            connected: false,
            resolved: false,
            seen: None,
            touched: now,
        });
        d.touched = now;
        if let Some(uuids) = props.uuids {
            d.uuids = uuids;
        }
        if let Some(rssi) = props.rssi {
            d.rssi = Some(rssi);
        }
        if let Some(resolved) = props.resolved {
            d.resolved = resolved;
        }
        let was = d.connected;
        if let Some(connected) = props.connected {
            d.connected = connected;
        }
        if was && !d.connected {
            d.resolved = false;
            self.device_down(&path, now);
            return;
        }
        if props.resolved == Some(true) {
            let resolving: Vec<ConnId> = self
                .conns
                .iter()
                .filter(|(_, c)| {
                    matches!(c, Conn::Central { device, stage: Stage::Resolving, .. }
                        if *device == path)
                })
                .map(|(id, _)| *id)
                .collect();
            for conn in resolving {
                self.find(conn, now);
            }
        }
        if props.rssi.is_some() {
            self.seen(&path, now);
        }
    }

    /// Forget the device touched longest ago that no connection uses.
    fn evict_device(&mut self) {
        let oldest = self
            .devices
            .iter()
            .filter(|(path, _)| !self.conns.values().any(|c| c.device() == path.as_str()))
            .min_by_key(|(_, d)| d.touched)
            .map(|(path, _)| path.clone());
        if let Some(path) = oldest {
            self.devices.remove(&path);
        }
    }

    /// A device's advert, as `Seen`: its candidate tokens (no SIG UUIDs),
    /// at most once per [`SEEN_EVERY`] unless they changed.
    fn seen(&mut self, path: &str, now: Instant) {
        let Some(d) = self.devices.get_mut(path) else {
            return;
        };
        let Some(rssi) = d.rssi else {
            return;
        };
        let tokens: Vec<[u8; 16]> = d
            .uuids
            .iter()
            .filter(|u| !is_sig_uuid(u))
            .copied()
            .collect();
        if tokens.is_empty() {
            return;
        }
        let due = d.seen.is_none_or(|(at, count)| {
            count != tokens.len() || now.saturating_duration_since(at) >= SEEN_EVERY
        });
        if !due {
            return;
        }
        d.seen = Some((now, tokens.len()));
        self.emit(RadioEvent::Seen {
            addr: RadioAddr(path.to_owned()),
            uuids: tokens,
            rssi,
        });
    }

    /// The device's link is gone: its connections end, and its silence.
    fn device_down(&mut self, path: &str, now: Instant) {
        let gone: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| c.device() == path)
            .map(|(id, _)| *id)
            .collect();
        for conn in gone {
            self.end(conn, false, now);
        }
        self.silenced.retain(|(device, _), _| device != path);
    }

    // ── Calls from BlueZ ────────────────────────────────────────────────

    /// The service of the application in `slot`.
    fn app_at(&self, slot: u32) -> Option<[u8; 16]> {
        self.apps
            .iter()
            .find(|(_, a)| a.slot == slot)
            .map(|(t, _)| *t)
    }

    fn props_of(&self, obj: Obj) -> Option<(&'static str, Props)> {
        match obj {
            Obj::App(slot) => self.app_at(slot).map(|_| (OBJECT_MANAGER, Props::new())),
            Obj::Service(slot) => self.app_at(slot).map(|t| (GATT_SERVICE, service_props(&t))),
            Obj::Char(slot) => self.app_at(slot).map(|t| (GATT_CHAR, char_props(slot, &t))),
            Obj::Adv(seq) => self
                .adv
                .as_ref()
                .filter(|a| a.seq == seq)
                .map(|a| (ADVERTISEMENT, adv_props(&a.uuid))),
        }
    }

    /// A central's write on application `slot`'s characteristic: a frame of
    /// its connection, which starts here.
    fn write(
        &mut self,
        slot: u32,
        value: Vec<u8>,
        device: Option<String>,
        mtu: Option<u16>,
        now: Instant,
    ) {
        let Some((&t, app)) = self.apps.iter().find(|(_, a)| a.slot == slot) else {
            return;
        };
        if !app.notifying || !self.want_services.contains(&t) {
            return;
        }
        let Some(device) = device.filter(|d| self.is_device(d)) else {
            return;
        };
        if self
            .silenced
            .get(&(device.clone(), t))
            .is_some_and(|until| *until > now)
        {
            return;
        }
        let existing = self.conns.iter().find_map(|(id, c)| match c {
            Conn::Peripheral {
                device: d, service, ..
            } if *d == device && *service == t => Some(*id),
            _ => None,
        });
        let conn = match existing {
            Some(conn) => conn,
            None => {
                let peripherals = self
                    .conns
                    .values()
                    .filter(|c| matches!(c, Conn::Peripheral { .. }))
                    .count();
                if peripherals >= MAX_PERIPHERAL {
                    return;
                }
                let conn = self.next_peripheral;
                self.next_peripheral += 2;
                let max = frame_limit(mtu.unwrap_or(ATT_DEFAULT_MTU));
                self.conns.insert(
                    conn,
                    Conn::Peripheral {
                        device,
                        service: t,
                        slot,
                    },
                );
                self.bus.peripheral_up(conn, max);
                self.emit(RadioEvent::Connected {
                    conn,
                    role: Role::Peripheral,
                    service: t,
                    max_tx: max,
                    max_rx: max,
                });
                conn
            }
        };
        self.emit(RadioEvent::Frame { conn, bytes: value });
    }

    /// The last subscriber of application `slot`'s characteristic left:
    /// every connection on its service ends.
    fn stop_notify(&mut self, slot: u32, now: Instant) {
        let Some(t) = self.app_at(slot) else {
            return;
        };
        if let Some(app) = self.apps.get_mut(&t) {
            app.notifying = false;
        }
        let gone: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| matches!(c, Conn::Peripheral { service, .. } if *service == t))
            .map(|(id, _)| *id)
            .collect();
        for conn in gone {
            self.end(conn, false, now);
        }
    }

    // ── Publishing and scanning ─────────────────────────────────────────

    fn reconcile(&mut self, now: Instant) {
        self.reconcile_apps(now);
        self.reconcile_adv(now);
        self.reconcile_scan(now);
    }

    /// One application per wanted service: register what is missing,
    /// unregister what is no longer wanted, retry what BlueZ refused.
    fn reconcile_apps(&mut self, now: Instant) {
        if !self.alive {
            return;
        }
        let peripheral = self.caps.peripheral;
        let have: Vec<([u8; 16], u32, Reg)> =
            self.apps.iter().map(|(t, a)| (*t, a.slot, a.reg)).collect();
        for (t, slot, reg) in have {
            let wanted = peripheral && self.want_services.contains(&t);
            match (wanted, reg) {
                (false, Reg::Registered) => {
                    self.set_app(t, Reg::Unregistering);
                    let call = self
                        .manager_call("UnregisterApplication", Args::Unregister(app_path(slot)));
                    if !self.send(call, Op::Unregister(t), now) {
                        self.apps.remove(&t);
                    }
                }
                (false, Reg::Failed(_)) => {
                    self.apps.remove(&t);
                }
                (true, Reg::Failed(at)) if now.saturating_duration_since(at) >= RETRY => {
                    self.register_app(t, slot, now);
                }
                _ => {}
            }
        }
        if !peripheral {
            return;
        }
        let missing: Vec<[u8; 16]> = self
            .want_services
            .iter()
            .filter(|t| !self.apps.contains_key(*t))
            .copied()
            .collect();
        for t in missing {
            let slot = (0..)
                .find(|s| !self.apps.values().any(|a| a.slot == *s))
                .unwrap_or_default();
            self.apps.insert(
                t,
                App {
                    slot,
                    reg: Reg::Registering,
                    notifying: false,
                },
            );
            self.register_app(t, slot, now);
        }
    }

    fn register_app(&mut self, t: [u8; 16], slot: u32, now: Instant) {
        self.set_app(t, Reg::Registering);
        let call = self.manager_call("RegisterApplication", Args::Register(app_path(slot)));
        if !self.send(call, Op::Register(t), now) {
            self.set_app(t, Reg::Failed(now));
        }
    }

    fn set_app(&mut self, t: [u8; 16], reg: Reg) {
        if let Some(app) = self.apps.get_mut(&t) {
            app.reg = reg;
        }
    }

    /// The one advert: the wanted token once its application is registered
    /// and the adapter is on; one registration in flight at a time.
    fn reconcile_adv(&mut self, now: Instant) {
        if !self.alive {
            return;
        }
        let want = self.want_advert.filter(|t| {
            self.powered
                && self.caps.peripheral
                && self.apps.get(t).is_some_and(|a| a.reg == Reg::Registered)
        });
        // At most two rounds: drop a failed advert, then register anew.
        for _ in 0..2 {
            match self.adv.as_ref().map(|a| (a.uuid, a.seq, a.reg)) {
                None => {
                    let Some(t) = want else {
                        return;
                    };
                    let seq = self.next_adv;
                    self.next_adv = self.next_adv.wrapping_add(1);
                    self.adv = Some(Adv {
                        uuid: t,
                        seq,
                        reg: Reg::Registering,
                    });
                    let call = Call {
                        path: self.adapter.clone(),
                        iface: ADV_MANAGER,
                        member: "RegisterAdvertisement",
                        args: Args::Register(adv_path(seq)),
                    };
                    if !self.send(call, Op::AdvRegister(seq), now) {
                        self.adv = None;
                    }
                    return;
                }
                Some((uuid, seq, Reg::Registered)) if Some(uuid) != want => {
                    if let Some(adv) = self.adv.as_mut() {
                        adv.reg = Reg::Unregistering;
                    }
                    let call = Call {
                        path: self.adapter.clone(),
                        iface: ADV_MANAGER,
                        member: "UnregisterAdvertisement",
                        args: Args::Unregister(adv_path(seq)),
                    };
                    if !self.send(call, Op::AdvUnregister(seq), now) {
                        self.adv = None;
                    }
                    return;
                }
                Some((uuid, _, Reg::Failed(at)))
                    if Some(uuid) != want || now.saturating_duration_since(at) >= RETRY =>
                {
                    self.adv = None;
                }
                _ => return,
            }
        }
    }

    fn reconcile_scan(&mut self, now: Instant) {
        if !self.alive {
            return;
        }
        let want = self.want_scan && self.powered && self.caps.central;
        let start = match (want, self.scan) {
            (true, Scan::Off) => true,
            (true, Scan::Failed(at)) => now.saturating_duration_since(at) >= RETRY,
            (false, Scan::On) => {
                self.scan = Scan::Stopping;
                let call = self.adapter_call("StopDiscovery", Args::None);
                if !self.send(call, Op::StopScan, now) {
                    self.scan = Scan::Off;
                }
                false
            }
            (false, Scan::Failed(_)) => {
                self.scan = Scan::Off;
                false
            }
            _ => false,
        };
        if start {
            self.scan = Scan::Starting;
            let call = self.adapter_call("SetDiscoveryFilter", Args::LeFilter);
            if !self.send(call, Op::Filter, now) {
                self.scan = Scan::Failed(now);
            }
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    fn adapter_call(&self, member: &'static str, args: Args) -> Call {
        Call {
            path: self.adapter.clone(),
            iface: ADAPTER,
            member,
            args,
        }
    }

    fn manager_call(&self, member: &'static str, args: Args) -> Call {
        Call {
            path: self.adapter.clone(),
            iface: GATT_MANAGER,
            member,
            args,
        }
    }

    /// Send `call` for `op`. A call that cannot be sent means the bus
    /// connection broke: the thread stops.
    fn send(&mut self, call: Call, op: Op, now: Instant) -> bool {
        match self.bus.call(call) {
            Ok(serial) => {
                self.pending.insert(serial, op, now);
                true
            }
            Err(e) => {
                self.note("D-Bus", &e);
                self.alive = false;
                false
            }
        }
    }

    fn emit(&mut self, ev: RadioEvent) {
        if let Err(Some(conn)) = self.events.emit(ev) {
            self.lost.push(conn);
        }
    }

    /// End the connections whose events were lost.
    fn settle(&mut self, now: Instant) {
        while let Some(conn) = self.lost.pop() {
            self.end(conn, true, now);
        }
    }

    fn is_device(&self, path: &str) -> bool {
        is_device_of(&self.adapter, path)
    }

    /// Log a BlueZ error once in a row (an error name, never a device).
    fn note(&mut self, what: &str, error: &str) {
        let line = format!("{what}: {error}");
        if self.logged.as_ref() != Some(&line) {
            eprintln!("raven-node nearby: BlueZ {line}");
            self.logged = Some(line);
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_calls(&self) -> usize {
        self.pending.len()
    }
}

/// A device object directly under `adapter` (`<adapter>/dev_<address>`).
fn is_device_of(adapter: &str, path: &str) -> bool {
    path.strip_prefix(adapter)
        .and_then(|r| r.strip_prefix("/dev_"))
        .is_some_and(|r| !r.is_empty() && !r.contains('/'))
}

// ── The send table ──────────────────────────────────────────────────────────

/// How each live connection sends, shared by the radio handle (the engine's
/// sends) and the bus thread (which adds and removes connections). `W` is a
/// central connection's write socket.
pub(crate) struct Table<W> {
    slots: HashMap<ConnId, Slot<W>>,
}

enum Slot<W> {
    Central {
        writer: Arc<W>,
        max_tx: usize,
    },
    /// Notifications go through the bus thread, at most [`NOTIFY_WINDOW`]
    /// queued.
    Peripheral {
        queued: usize,
        want: bool,
        max_tx: usize,
    },
}

/// Where [`Table::route`] sends a frame.
pub(crate) enum Route<W> {
    /// Write it to this socket now.
    Write(Arc<W>),
    /// Queue it for the bus thread as a notification.
    Notify,
    /// The window is full: one `Writable` follows when it has room.
    Full,
}

impl<W> Default for Table<W> {
    fn default() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }
}

impl<W> Table<W> {
    pub(crate) fn central(&mut self, conn: ConnId, writer: Arc<W>, max_tx: usize) {
        self.slots.insert(conn, Slot::Central { writer, max_tx });
    }

    pub(crate) fn peripheral(&mut self, conn: ConnId, max_tx: usize) {
        self.slots.insert(
            conn,
            Slot::Peripheral {
                queued: 0,
                want: false,
                max_tx,
            },
        );
    }

    pub(crate) fn remove(&mut self, conn: ConnId) {
        self.slots.remove(&conn);
    }

    /// Where a frame of `len` bytes on `conn` goes; an error for an unknown
    /// connection or a frame that is empty or over `max_tx`.
    pub(crate) fn route(&mut self, conn: ConnId, len: usize) -> Result<Route<W>, String> {
        let slot = self.slots.get_mut(&conn).ok_or("not connected")?;
        let max_tx = match slot {
            Slot::Central { max_tx, .. } | Slot::Peripheral { max_tx, .. } => *max_tx,
        };
        if len == 0 || len > max_tx {
            return Err(format!(
                "a frame of {len} bytes on a link of max_tx {max_tx}"
            ));
        }
        Ok(match slot {
            Slot::Central { writer, .. } => Route::Write(Arc::clone(writer)),
            Slot::Peripheral { queued, want, .. } => {
                if *queued >= NOTIFY_WINDOW {
                    *want = true;
                    Route::Full
                } else {
                    *queued += 1;
                    Route::Notify
                }
            }
        })
    }

    /// The bus thread passed one of `conn`'s notifications on: true when a
    /// send waits for room (one `Writable` is owed now).
    pub(crate) fn notified(&mut self, conn: ConnId) -> bool {
        let Some(Slot::Peripheral { queued, want, .. }) = self.slots.get_mut(&conn) else {
            return false;
        };
        *queued = queued.saturating_sub(1);
        if *want && *queued < NOTIFY_WINDOW {
            *want = false;
            return true;
        }
        false
    }
}
