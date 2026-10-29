//! The Windows backend of the nearby radio (RNL1 §3-§4, §8-§9; Nearby
//! design step 5.9): Bluetooth LE through WinRT (`Windows.Devices.Bluetooth`)
//! on windows 0.62.2. Built for Windows with feature `nearby-radio` only;
//! the windows crate was already in Cargo.lock and gains features only (owner
//! decision O5-11).
//!
//! This file is the backend's pure part, tested on every platform: GUIDs and
//! addresses, the capabilities ([`caps`]), the state machine that drives
//! WinRT ([`Core`]) and the radio's send table ([`Table`]). `sys` (Windows
//! only) is the thin part that calls WinRT; its asynchronous operations are
//! awaited on tokio through windows-future's `IntoFuture`.
//!
//! **One driver task.** A tokio task owns [`Core`] and every WinRT object
//! the backend keeps. WinRT raises its events on its own thread pool, and
//! each handler only queues a message for the driver. Every asynchronous
//! WinRT call runs in a task of its own whose result comes back as a
//! message, so the driver never waits on the radio. A radio call from the
//! engine queues a [`Cmd`] the same way; a frame goes straight to its
//! connection's writer task through the [`Table`], one WinRT write at a time
//! and at most [`SEND_WINDOW`] queued.
//!
//! **Peripheral.** One `GattServiceProvider` per published service `T`,
//! with one characteristic `C(T)`: WriteWithoutResponse | Write | Notify, no
//! Read, no encryption (RNL1 §4).
//! - The advertised service advertises connectable and discoverable: `T` is
//!   the advert's only content (RNL1 §3). Every other published service is
//!   started connectable but not discoverable, so a central keeps its pipe on
//!   it while another token is on air.
//! - WinRT cannot change a started provider's parameters, so a change is a
//!   stop and a start. The change that takes a token off air goes first, so
//!   at most one token is ever on air.
//! - A connection is one central subscribed to one service
//!   (`SubscribedClientsChanged`). It ends when that subscription ends or the
//!   service is withdrawn. A write that arrives before its central's
//!   subscription is known waits up to [`EARLY_WAIT`].
//! - Notifications go to that central only
//!   (`NotifyValueForSubscribedClientAsync`): `per_central_notify` is true.
//! - A Windows peripheral cannot drop a central. A connection this side ends
//!   is silenced: that central's writes are ignored for [`SILENCE`], unless
//!   it unsubscribes first.
//!
//! **Central.** A passive `BluetoothLEAdvertisementWatcher`. A connectable
//! advert's 128-bit service UUIDs and RSSI become `Seen`, at most once a
//! second per address. A connect is:
//! 1. the BluetoothLEDevice for the address and its type;
//! 2. a GattSession kept open (`MaintainConnection`);
//! 3. the service and its characteristic found by UUID, uncached (no stale
//!    GATT cache);
//! 4. the ValueChanged handler, then the CCCD written for notifications.
//!
//! Frames go out as Write Commands (`WriteWithoutResponse`).
//!
//! **Capabilities.** The default adapter's IsLowEnergySupported,
//! IsCentralRoleSupported and IsPeripheralRoleSupported decide the roles.
//! WinRT's GATT server may be refused to an unpackaged process (raven-node
//! runs from a logon task), so `sys` creates one provider, never advertised,
//! when the radio opens: a refusal makes the radio central-only (owner
//! decision O5-11: no sparse package). WinRT does not say which address an
//! advert goes out from, so the address privacy counts as public (RNL1 §3,
//! owner decision O5-12). The engine then advertises nothing unless a debug
//! lab run allows it, until hardware shows that Windows advertises from a
//! random address. The radio's power comes from `Windows.Devices.Radios`.
//!
//! **Errors.** No adapter, or no LE: `Unsupported`. Windows refusing
//! Bluetooth to this process (`E_ACCESSDENIED`): `Unauthorized`. A refused
//! provider, advertisement or scan is tried again after [`RETRY`]. Errors are
//! logged by name or code only, never with a device's address or id.

// Only the WinRT side (Windows, feature `nearby-radio`) uses all of this;
// the tests build it on every platform.
#![cfg_attr(not(all(windows, feature = "nearby-radio")), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::time::{Duration, Instant};

use raven_core::nearby_link::{windows_guid_u128, Role, MAX_FRAME};
use tokio::sync::mpsc;

use super::radio::{ConnId, EventTx, Privacy, RadioAddr, RadioCaps, RadioEvent, RadioState, Sent};

#[cfg(all(windows, feature = "nearby-radio"))]
pub(crate) mod sys;
#[cfg(test)]
mod tests;

/// ATT's MTU when nothing larger was negotiated.
const ATT_DEFAULT_MTU: u16 = 23;
/// How long a connect may take to come up (the engine gives up sooner).
pub(crate) const CONNECT_BUDGET: Duration = Duration::from_secs(20);
/// A refused provider, advertisement or scan is tried again after this.
pub(crate) const RETRY: Duration = Duration::from_secs(10);
/// An address that keeps advertising is `Seen` at most this often (a change
/// of its UUIDs at once).
pub(crate) const SEEN_EVERY: Duration = Duration::from_secs(1);
/// Writes from a central whose connection this side ended are ignored this
/// long, unless it unsubscribes first.
pub(crate) const SILENCE: Duration = Duration::from_secs(10);
/// A write from a central whose subscription is not known yet waits this
/// long for it (WinRT reports the two on different threads).
pub(crate) const EARLY_WAIT: Duration = Duration::from_secs(2);
/// Frames held for one connection before it is up (a central's
/// notifications before its `Connected`, a peripheral's early writes).
pub(crate) const EARLY_FRAMES: usize = 8;
/// Addresses remembered for the `Seen` throttle (WinRT reports every advert
/// in range).
pub(crate) const MAX_DEVICES: usize = 1024;
/// Peripheral connections at once (the engine keeps at most 8 knocking and
/// 4 pipes).
pub(crate) const MAX_PERIPHERAL: usize = 16;
/// Service UUIDs read from one advert (a legacy advert holds at most one
/// 128-bit UUID; an extended one more).
pub(crate) const MAX_ADVERT_UUIDS: usize = 8;
/// Frames a connection may have queued for its writer task before a send is
/// [`Sent::WouldBlock`].
pub(crate) const SEND_WINDOW: usize = 16;

// ── GUIDs, addresses and sizes ──────────────────────────────────────────────

/// The value WinRT's GUID for UUID `u` is made from (`GUID::from_u128`, RNL1
/// §2).
pub(crate) fn guid_u128(u: &[u8; 16]) -> u128 {
    windows_guid_u128(u)
}

/// The UUID a WinRT GUID stands for (`GUID::to_u128`).
pub(crate) fn uuid_of(g: u128) -> [u8; 16] {
    g.to_be_bytes()
}

/// The Bluetooth base UUID's last 12 bytes (`xxxxxxxx-0000-1000-8000-
/// 00805f9b34fb`): a 16- or 32-bit UUID written long, never an RNB1 token
/// (whose byte 6 starts with the version nibble 4). As BlueZ's, whose module
/// is not built on Windows.
const SIG_BASE_TAIL: [u8; 12] = [
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// A Bluetooth SIG UUID, not a candidate token.
pub(crate) fn is_sig_uuid(u: &[u8; 16]) -> bool {
    u[4..] == SIG_BASE_TAIL
}

/// The candidate tokens among an advert's service UUIDs: the ones that are
/// not the SIG's, each once, in order, at most [`MAX_ADVERT_UUIDS`].
pub(crate) fn candidates(uuids: impl IntoIterator<Item = [u8; 16]>) -> Vec<[u8; 16]> {
    let mut out: Vec<[u8; 16]> = Vec::new();
    for u in uuids {
        if out.len() == MAX_ADVERT_UUIDS {
            break;
        }
        if !is_sig_uuid(&u) && !out.contains(&u) {
            out.push(u);
        }
    }
    out
}

/// The largest frame each way on a link of ATT MTU `mtu` (RNL1 §4:
/// `min(ATT_MTU - 3, 512)`).
pub(crate) fn frame_limit(mtu: u16) -> usize {
    usize::from(mtu.max(ATT_DEFAULT_MTU) - 3).min(MAX_FRAME)
}

/// A subscribed central's `max_tx` from WinRT's MaxNotificationSize (at
/// least ATT's default, at most [`MAX_FRAME`]).
pub(crate) fn notify_limit(max_notification: u16) -> usize {
    usize::from(max_notification).clamp(usize::from(ATT_DEFAULT_MTU - 3), MAX_FRAME)
}

/// A device address's type, as the watcher reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AddrKind {
    Public,
    Random,
    /// WinRT did not say: the connect names the address only.
    Unspecified,
}

/// A device address as WinRT reports it (48 bits) and its type. `Debug`
/// never prints the address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Addr {
    pub(crate) raw: u64,
    pub(crate) kind: AddrKind,
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Addr(..)")
    }
}

impl Addr {
    const MASK: u64 = 0xffff_ffff_ffff;

    pub(crate) fn new(raw: u64, kind: AddrKind) -> Self {
        Self {
            raw: raw & Self::MASK,
            kind,
        }
    }

    /// The engine's handle for this address: `<12 hex digits>/<p|r|u>`.
    pub(crate) fn radio_addr(self) -> RadioAddr {
        let kind = match self.kind {
            AddrKind::Public => 'p',
            AddrKind::Random => 'r',
            AddrKind::Unspecified => 'u',
        };
        RadioAddr(format!("{:012x}/{kind}", self.raw))
    }

    /// The address a [`Addr::radio_addr`] handle names.
    pub(crate) fn parse(a: &RadioAddr) -> Option<Self> {
        let (hex, kind) = a.0.split_once('/')?;
        if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let kind = match kind {
            "p" => AddrKind::Public,
            "r" => AddrKind::Random,
            "u" => AddrKind::Unspecified,
            _ => return None,
        };
        Some(Self::new(u64::from_str_radix(hex, 16).ok()?, kind))
    }
}

// ── Capabilities and errors ─────────────────────────────────────────────────

/// What the default adapter says it supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Adapter {
    pub(crate) low_energy: bool,
    pub(crate) central: bool,
    pub(crate) peripheral: bool,
}

/// What became of the GATT server probe at open (one provider, never
/// advertised).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Server {
    Works,
    /// WinRT refused it (a BluetoothError name or an HRESULT).
    Refused(String),
    /// Not tried: the adapter has no peripheral role.
    NotTried,
}

/// The radio's capabilities from the adapter and the GATT server probe. A
/// refused server makes the radio central-only (owner decision O5-11).
pub(crate) fn caps(adapter: Adapter, server: &Server) -> Result<RadioCaps, RadioState> {
    if !adapter.low_energy {
        return Err(RadioState::Unsupported(
            "the Bluetooth adapter has no Bluetooth LE".into(),
        ));
    }
    let peripheral = adapter.peripheral && *server == Server::Works;
    if !adapter.central && !peripheral {
        return Err(RadioState::Unsupported(match server {
            Server::Refused(why) if adapter.peripheral => format!(
                "the Bluetooth adapter has no central role, and Windows refused its GATT server \
                 to this process ({why})"
            ),
            _ => "the Bluetooth adapter has neither LE role".into(),
        }));
    }
    Ok(RadioCaps {
        central: adapter.central,
        peripheral,
        l2cap: false,
        // WinRT does not say which address adverts use: unknown counts as
        // public (RNL1 §3, O5-12; see the module doc).
        address_privacy: Privacy::Public,
        per_central_notify: true,
    })
}

/// WinRT's `BluetoothError` by name (Windows.Devices.Bluetooth).
pub(crate) fn bt_error_name(code: i32) -> &'static str {
    match code {
        0 => "Success",
        1 => "RadioNotAvailable",
        2 => "ResourceInUse",
        3 => "DeviceNotConnected",
        4 => "OtherError",
        5 => "DisabledByPolicy",
        6 => "NotSupported",
        7 => "DisabledByUser",
        8 => "ConsentRequired",
        9 => "TransportNotSupported",
        _ => "BluetoothError(unknown)",
    }
}

/// `E_ACCESSDENIED`.
pub(crate) const E_ACCESSDENIED: u32 = 0x8007_0005;

/// What a failed setup call (`what`, with its HRESULT) means for the radio.
/// HRESULT 0 is WinRT's empty answer: no adapter, or no radio.
pub(crate) fn setup_failed(what: &str, hresult: u32) -> RadioState {
    match hresult {
        0 => RadioState::Unsupported(format!("{what}: no Bluetooth adapter")),
        E_ACCESSDENIED => RadioState::Unauthorized(format!(
            "Windows refused Bluetooth to this process ({what}: E_ACCESSDENIED): check the \
             Bluetooth and radio privacy settings"
        )),
        code => RadioState::Unsupported(format!("{what}: HRESULT 0x{code:08X}")),
    }
}

// ── What goes to and comes from WinRT ───────────────────────────────────────

/// A radio call, queued for the driver.
#[derive(Debug)]
pub(crate) enum Cmd {
    Services(Vec<[u8; 16]>, Option<[u8; 16]>),
    Scan(bool),
    Connect {
        conn: ConnId,
        addr: Addr,
        service: [u8; 16],
    },
    Disconnect(ConnId),
    /// The radio was dropped: end everything and stop.
    Stop,
}

/// A central subscribed to a published service, as WinRT reports it
/// (`device`: WinRT's device id, never logged).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Subscriber {
    pub(crate) device: String,
    pub(crate) max_tx: usize,
    pub(crate) max_rx: usize,
}

/// What [`Core`] asks of WinRT. Every call returns at once; what WinRT
/// answers comes back as a [`Core`] input.
pub(crate) trait Os {
    /// Create service `t`'s provider and characteristic; [`Core::created`]
    /// follows (one creation per service at a time).
    fn create(&mut self, t: [u8; 16]);
    /// (Re)start `t`'s provider: connectable, and discoverable when `on_air`
    /// (its UUID is the advert). A running one is stopped first; a failure
    /// comes back as [`Core::aborted`].
    fn advertise(&mut self, t: [u8; 16], on_air: bool);
    /// Stop `t`'s provider and drop it.
    fn withdraw(&mut self, t: [u8; 16]);
    /// Start or stop the watcher; an unexpected stop comes back as
    /// [`Core::scan_stopped`].
    fn scan(&mut self, on: bool);
    /// Connect to `addr` and subscribe to `t`'s characteristic: then
    /// [`Core::central_up`] or [`Core::central_failed`].
    fn connect(&mut self, conn: ConnId, addr: Addr, t: [u8; 16]);
    /// Route a central connection's sends; called before its `Connected`.
    fn central_up(&mut self, conn: ConnId, max_tx: usize);
    /// Route a peripheral connection's sends (notifications to `device` on
    /// `t`); called before its `Connected`.
    fn peripheral_up(&mut self, conn: ConnId, t: [u8; 16], device: &str, max_tx: usize);
    /// `conn` ended: drop its send route and the WinRT objects it holds (a
    /// central's link, or its connect under way).
    fn ended(&mut self, conn: ConnId);
}

// ── The state machine ───────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Made {
    /// Wanted, not created yet (the radio is off).
    Absent,
    Creating,
    /// `on_air`: how it was last started (`None`: not started).
    Ready {
        on_air: Option<bool>,
    },
    Failed(Instant),
}

/// One published service's provider.
struct Svc {
    made: Made,
    /// False once withdrawn while its creation is under way: the result is
    /// turned down.
    wanted: bool,
    /// The centrals subscribed now, by device id.
    subscribers: BTreeMap<String, Subscriber>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scan {
    Off,
    On,
    Failed(Instant),
}

enum Conn {
    Central {
        service: [u8; 16],
        /// Notifications that arrived before `Connected` (`None`: up).
        early: Option<Vec<Vec<u8>>>,
        deadline: Instant,
    },
    Peripheral {
        service: [u8; 16],
        device: String,
    },
}

/// Writes from a central whose subscription is not known yet.
struct Early {
    since: Instant,
    frames: Vec<Vec<u8>>,
}

/// The backend's state machine: it publishes the services and the advert the
/// engine asks for, scans, connects and keeps every connection's state,
/// emitting the radio's events. Every input is a method; every output is an
/// [`Os`] call or an event.
pub(crate) struct Core<O: Os> {
    pub(crate) os: O,
    events: EventTx,
    caps: RadioCaps,
    powered: bool,
    alive: bool,
    services: BTreeMap<[u8; 16], Svc>,
    advert: Option<[u8; 16]>,
    want_scan: bool,
    scan: Scan,
    /// The last `Seen` per address and its UUIDs.
    seen: HashMap<Addr, (Instant, Vec<[u8; 16]>)>,
    conns: BTreeMap<ConnId, Conn>,
    silenced: HashMap<([u8; 16], String), Instant>,
    early: HashMap<([u8; 16], String), Early>,
    next_peripheral: ConnId,
    /// Connections whose events the queue lost: ended once the current
    /// input is handled.
    lost: Vec<ConnId>,
    /// The last WinRT error logged (each distinct one once in a row).
    logged: Option<String>,
}

impl<O: Os> Core<O> {
    pub(crate) fn new(os: O, events: EventTx, caps: RadioCaps, powered: bool) -> Self {
        Self {
            os,
            events,
            caps,
            powered,
            alive: true,
            services: BTreeMap::new(),
            advert: None,
            want_scan: false,
            scan: Scan::Off,
            seen: HashMap::new(),
            conns: BTreeMap::new(),
            silenced: HashMap::new(),
            early: HashMap::new(),
            // Peripheral connections are even; the radio handle numbers
            // central ones odd.
            next_peripheral: 2,
            lost: Vec::new(),
            logged: None,
        }
    }

    /// Tell the engine the radio's power.
    pub(crate) fn start(&mut self) {
        let state = if self.powered {
            RadioState::PoweredOn
        } else {
            RadioState::PoweredOff
        };
        self.emit(RadioEvent::State(state));
    }

    /// False once the radio was dropped: the driver stops.
    pub(crate) fn alive(&self) -> bool {
        self.alive
    }

    /// Events the queue dropped so far.
    pub(crate) fn dropped(&self) -> u64 {
        self.events.dropped()
    }

    /// A creation of `t` is under way (the driver keeps what it made only
    /// then).
    pub(crate) fn creating(&self, t: &[u8; 16]) -> bool {
        self.services
            .get(t)
            .is_some_and(|s| s.made == Made::Creating)
    }

    /// `conn` is a central connect still under way (the driver keeps its
    /// link only then).
    pub(crate) fn connecting(&self, conn: ConnId) -> bool {
        matches!(
            self.conns.get(&conn),
            Some(Conn::Central { early: Some(_), .. })
        )
    }

    /// `t` is a provider in use: its subscribers are worth keeping.
    pub(crate) fn serving(&self, t: &[u8; 16]) -> bool {
        self.services
            .get(t)
            .is_some_and(|s| matches!(s.made, Made::Ready { .. }))
    }

    // ── Inputs ──────────────────────────────────────────────────────────

    pub(crate) fn command(&mut self, cmd: Cmd, now: Instant) {
        if !self.alive {
            return;
        }
        match cmd {
            Cmd::Services(list, advertise) => {
                let want: BTreeSet<[u8; 16]> = list.into_iter().collect();
                self.advert = advertise.filter(|t| want.contains(t));
                let gone: Vec<[u8; 16]> = self
                    .services
                    .iter()
                    .filter(|(t, s)| s.wanted && !want.contains(*t))
                    .map(|(t, _)| *t)
                    .collect();
                for t in gone {
                    self.withdraw(t, now);
                }
                for t in want {
                    let svc = self.services.entry(t).or_insert_with(|| Svc {
                        made: Made::Absent,
                        wanted: true,
                        subscribers: BTreeMap::new(),
                    });
                    svc.wanted = true;
                }
                self.apply();
            }
            Cmd::Scan(on) => {
                self.want_scan = on;
                self.apply_scan();
            }
            Cmd::Connect {
                conn,
                addr,
                service,
            } => {
                if self.conns.contains_key(&conn) {
                    // The radio handle never numbers two alike.
                } else if !self.powered || !self.caps.central {
                    self.emit(RadioEvent::Disconnected { conn });
                } else {
                    self.conns.insert(
                        conn,
                        Conn::Central {
                            service,
                            early: Some(Vec::new()),
                            deadline: now + CONNECT_BUDGET,
                        },
                    );
                    self.os.connect(conn, addr, service);
                }
            }
            Cmd::Disconnect(conn) => self.end(conn, true, now),
            Cmd::Stop => self.shutdown(now),
        }
        self.settle(now);
    }

    /// The radio turned on or off (`Windows.Devices.Radios`).
    pub(crate) fn power(&mut self, on: bool, now: Instant) {
        if !self.alive || on == self.powered {
            return;
        }
        self.powered = on;
        if on {
            self.emit(RadioEvent::State(RadioState::PoweredOn));
            self.apply();
            self.apply_scan();
        } else {
            self.emit(RadioEvent::State(RadioState::PoweredOff));
            self.end_all(now);
            for svc in self.services.values_mut() {
                if let Made::Ready { on_air } = &mut svc.made {
                    // The radio stopped them; started again at power on.
                    *on_air = None;
                }
                svc.subscribers.clear();
            }
            if self.scan == Scan::On {
                self.os.scan(false);
            }
            self.scan = Scan::Off;
            self.seen.clear();
            self.early.clear();
            self.silenced.clear();
        }
        self.settle(now);
    }

    /// The creation of `t` ended: its provider is ready (the driver keeps
    /// it), or WinRT refused it.
    pub(crate) fn created(&mut self, t: [u8; 16], result: Result<(), String>, now: Instant) {
        let Some(svc) = self.services.get_mut(&t) else {
            return;
        };
        if svc.made != Made::Creating {
            return;
        }
        if !svc.wanted {
            self.services.remove(&t);
            self.os.withdraw(t);
            return;
        }
        match result {
            Ok(()) => {
                svc.made = Made::Ready { on_air: None };
                self.apply();
            }
            Err(why) => {
                svc.made = Made::Failed(now);
                self.os.withdraw(t);
                self.note("GATT service", &why);
            }
        }
        self.settle(now);
    }

    /// `t`'s advertising was aborted (or could not start): its connections
    /// end and the provider is made again after [`RETRY`].
    pub(crate) fn aborted(&mut self, t: [u8; 16], why: &str, now: Instant) {
        if !self.alive || !self.serving(&t) {
            return;
        }
        self.end_service_conns(&t, now);
        if let Some(svc) = self.services.get_mut(&t) {
            svc.made = Made::Failed(now);
            svc.subscribers.clear();
        }
        self.os.withdraw(t);
        self.note("advertising", why);
        self.settle(now);
    }

    /// The centrals subscribed to `t` now.
    pub(crate) fn subscribers(&mut self, t: [u8; 16], list: Vec<Subscriber>, now: Instant) {
        if !self.alive || !self.serving(&t) {
            return;
        }
        let new: BTreeMap<String, Subscriber> =
            list.into_iter().map(|s| (s.device.clone(), s)).collect();
        let Some(svc) = self.services.get_mut(&t) else {
            return;
        };
        let old = std::mem::replace(&mut svc.subscribers, new.clone());
        for device in old.keys().filter(|d| !new.contains_key(*d)) {
            let key = (t, device.clone());
            self.silenced.remove(&key);
            self.early.remove(&key);
            if let Some(conn) = self.peripheral_conn(&t, device) {
                self.end(conn, false, now);
            }
        }
        for (device, sub) in &new {
            if self.peripheral_conn(&t, device).is_none() && !self.is_silenced(&t, device, now) {
                self.open_peripheral(t, sub, now);
            }
        }
        self.settle(now);
    }

    /// A central wrote `bytes` to `t`'s characteristic.
    pub(crate) fn written(&mut self, t: [u8; 16], device: String, bytes: Vec<u8>, now: Instant) {
        if !self.alive || !self.serving(&t) {
            return;
        }
        if let Some(conn) = self.peripheral_conn(&t, &device) {
            self.emit(RadioEvent::Frame { conn, bytes });
        } else if self.is_silenced(&t, &device, now) {
            // Its connection was ended here: ignored (see the module doc).
        } else if let Some(sub) = self
            .services
            .get(&t)
            .and_then(|s| s.subscribers.get(&device))
            .cloned()
        {
            // Subscribed, and its silence is over: a new connection.
            if let Some(conn) = self.open_peripheral(t, &sub, now) {
                self.emit(RadioEvent::Frame { conn, bytes });
            }
        } else {
            let key = (t, device);
            if !self.early.contains_key(&key) && self.early.len() >= MAX_PERIPHERAL {
                return;
            }
            let early = self.early.entry(key).or_insert(Early {
                since: now,
                frames: Vec::new(),
            });
            if early.frames.len() < EARLY_FRAMES {
                early.frames.push(bytes);
            }
        }
        self.settle(now);
    }

    /// An advert from `addr`: its service UUIDs and RSSI.
    pub(crate) fn advert(
        &mut self,
        addr: Addr,
        uuids: Vec<[u8; 16]>,
        rssi: i16,
        connectable: bool,
        now: Instant,
    ) {
        if !self.alive || !connectable || self.scan != Scan::On {
            return;
        }
        let uuids = candidates(uuids);
        if uuids.is_empty() {
            return;
        }
        if let Some((at, last)) = self.seen.get(&addr) {
            if *last == uuids && now.saturating_duration_since(*at) < SEEN_EVERY {
                return;
            }
        } else if self.seen.len() >= MAX_DEVICES {
            let oldest = self
                .seen
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(a, _)| *a);
            if let Some(a) = oldest {
                self.seen.remove(&a);
            }
        }
        self.seen.insert(addr, (now, uuids.clone()));
        self.emit(RadioEvent::Seen {
            addr: addr.radio_addr(),
            uuids,
            rssi,
        });
        self.settle(now);
    }

    /// The watcher stopped by itself (radio off, refused, aborted): it is
    /// started again after [`RETRY`].
    pub(crate) fn scan_stopped(&mut self, why: &str, now: Instant) {
        if self.alive && self.scan == Scan::On {
            self.scan = Scan::Failed(now);
            self.note("scan", why);
        }
    }

    /// A central connect is up: the send route, then `Connected`, then the
    /// notifications that came first.
    pub(crate) fn central_up(&mut self, conn: ConnId, max_tx: usize, max_rx: usize, now: Instant) {
        let up = match self.conns.get_mut(&conn) {
            Some(Conn::Central { service, early, .. }) if early.is_some() => {
                Some((*service, early.take().unwrap_or_default()))
            }
            _ => None,
        };
        let Some((service, early)) = up else {
            // Ended meanwhile: drop the link.
            self.os.ended(conn);
            return;
        };
        self.os.central_up(conn, max_tx);
        self.emit(RadioEvent::Connected {
            conn,
            role: Role::Central,
            service,
            max_tx,
            max_rx,
        });
        for bytes in early {
            self.emit(RadioEvent::Frame { conn, bytes });
        }
        self.settle(now);
    }

    /// A central connect failed.
    pub(crate) fn central_failed(&mut self, conn: ConnId, why: &str, now: Instant) {
        if self.connecting(conn) {
            self.note("connect", why);
            self.end(conn, false, now);
            self.settle(now);
        }
    }

    /// A notification on a central connection.
    pub(crate) fn frame(&mut self, conn: ConnId, bytes: Vec<u8>, now: Instant) {
        match self.conns.get_mut(&conn) {
            Some(Conn::Central {
                early: Some(early), ..
            }) => {
                if early.len() < EARLY_FRAMES {
                    early.push(bytes);
                } else {
                    self.end(conn, false, now);
                }
            }
            Some(Conn::Central { early: None, .. }) => {
                self.emit(RadioEvent::Frame { conn, bytes });
            }
            _ => {}
        }
        self.settle(now);
    }

    /// `conn`'s link went down, or a send on it failed.
    pub(crate) fn lost(&mut self, conn: ConnId, now: Instant) {
        self.end(conn, false, now);
        self.settle(now);
    }

    /// Room again on `conn` after a [`Sent::WouldBlock`].
    pub(crate) fn writable(&mut self, conn: ConnId, now: Instant) {
        if self.conns.contains_key(&conn) {
            self.emit(RadioEvent::Writable { conn });
            self.settle(now);
        }
    }

    /// Deadlines, retries and owed events.
    pub(crate) fn tick(&mut self, now: Instant) {
        if !self.alive {
            return;
        }
        let late: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| {
                matches!(c, Conn::Central { early: Some(_), deadline, .. } if *deadline <= now)
            })
            .map(|(id, _)| *id)
            .collect();
        for conn in late {
            self.end(conn, false, now);
        }
        for svc in self.services.values_mut() {
            if let Made::Failed(at) = svc.made {
                if now.saturating_duration_since(at) >= RETRY {
                    svc.made = Made::Absent;
                }
            }
        }
        if let Scan::Failed(at) = self.scan {
            if now.saturating_duration_since(at) >= RETRY {
                self.scan = Scan::Off;
            }
        }
        self.silenced
            .retain(|_, at| now.saturating_duration_since(*at) < SILENCE);
        self.early
            .retain(|_, e| now.saturating_duration_since(e.since) < EARLY_WAIT);
        self.apply();
        self.apply_scan();
        self.events.flush();
        self.settle(now);
    }

    // ── Outputs ─────────────────────────────────────────────────────────

    /// Create what is wanted, then start each ready provider as wanted:
    /// first the ones that leave the air, then the one that goes on it.
    fn apply(&mut self) {
        if !self.alive || !self.powered {
            return;
        }
        let absent: Vec<[u8; 16]> = self
            .services
            .iter()
            .filter(|(_, s)| s.wanted && s.made == Made::Absent)
            .map(|(t, _)| *t)
            .collect();
        for t in absent {
            if let Some(svc) = self.services.get_mut(&t) {
                svc.made = Made::Creating;
            }
            self.os.create(t);
        }
        let mut starts: Vec<([u8; 16], bool)> = self
            .services
            .iter()
            .filter_map(|(t, s)| match s.made {
                Made::Ready { on_air } if s.wanted => {
                    let want = self.advert == Some(*t);
                    (on_air != Some(want)).then_some((*t, want))
                }
                _ => None,
            })
            .collect();
        // Off the air first: at most one token on air (RNL1 §3).
        starts.sort_by_key(|(_, on_air)| *on_air);
        for (t, on_air) in starts {
            if let Some(svc) = self.services.get_mut(&t) {
                svc.made = Made::Ready {
                    on_air: Some(on_air),
                };
            }
            self.os.advertise(t, on_air);
        }
    }

    fn apply_scan(&mut self) {
        if !self.alive {
            return;
        }
        let want = self.want_scan && self.powered && self.caps.central;
        match (want, self.scan) {
            (true, Scan::Off) => {
                self.os.scan(true);
                self.scan = Scan::On;
            }
            (false, Scan::On) => {
                self.os.scan(false);
                self.scan = Scan::Off;
                self.seen.clear();
            }
            (false, Scan::Failed(_)) => self.scan = Scan::Off,
            _ => {}
        }
    }

    /// Withdraw `t`: its connections end and its provider is dropped (or
    /// turned down when its creation ends).
    fn withdraw(&mut self, t: [u8; 16], now: Instant) {
        self.end_service_conns(&t, now);
        self.early.retain(|(s, _), _| *s != t);
        self.silenced.retain(|(s, _), _| *s != t);
        let Some(svc) = self.services.get_mut(&t) else {
            return;
        };
        match svc.made {
            Made::Creating => {
                svc.wanted = false;
                svc.subscribers.clear();
            }
            Made::Ready { .. } => {
                self.services.remove(&t);
                self.os.withdraw(t);
            }
            Made::Absent | Made::Failed(_) => {
                self.services.remove(&t);
            }
        }
    }

    fn open_peripheral(&mut self, t: [u8; 16], sub: &Subscriber, now: Instant) -> Option<ConnId> {
        let open = self
            .conns
            .values()
            .filter(|c| matches!(c, Conn::Peripheral { .. }))
            .count();
        if open >= MAX_PERIPHERAL {
            return None;
        }
        let conn = self.next_peripheral;
        self.next_peripheral += 2;
        self.conns.insert(
            conn,
            Conn::Peripheral {
                service: t,
                device: sub.device.clone(),
            },
        );
        self.os.peripheral_up(conn, t, &sub.device, sub.max_tx);
        self.emit(RadioEvent::Connected {
            conn,
            role: Role::Peripheral,
            service: t,
            max_tx: sub.max_tx,
            max_rx: sub.max_rx,
        });
        if let Some(early) = self.early.remove(&(t, sub.device.clone())) {
            if now.saturating_duration_since(early.since) < EARLY_WAIT {
                for bytes in early.frames {
                    self.emit(RadioEvent::Frame { conn, bytes });
                }
            }
        }
        Some(conn)
    }

    fn peripheral_conn(&self, t: &[u8; 16], device: &str) -> Option<ConnId> {
        self.conns.iter().find_map(|(id, c)| match c {
            Conn::Peripheral { service, device: d } if service == t && d == device => Some(*id),
            _ => None,
        })
    }

    fn is_silenced(&self, t: &[u8; 16], device: &str, now: Instant) -> bool {
        self.silenced
            .get(&(*t, device.to_owned()))
            .is_some_and(|at| now.saturating_duration_since(*at) < SILENCE)
    }

    fn end_service_conns(&mut self, t: &[u8; 16], now: Instant) {
        let conns: Vec<ConnId> = self
            .conns
            .iter()
            .filter(|(_, c)| matches!(c, Conn::Peripheral { service, .. } if service == t))
            .map(|(id, _)| *id)
            .collect();
        for conn in conns {
            self.end(conn, false, now);
        }
    }

    /// End `conn` with exactly one `Disconnected` (`local`: this side ended
    /// it, so a peripheral's central is silenced).
    fn end(&mut self, conn: ConnId, local: bool, now: Instant) {
        let Some(c) = self.conns.remove(&conn) else {
            return;
        };
        if let (Conn::Peripheral { service, device }, true) = (c, local) {
            self.silenced.insert((service, device), now);
        }
        self.os.ended(conn);
        self.emit(RadioEvent::Disconnected { conn });
    }

    fn end_all(&mut self, now: Instant) {
        let all: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in all {
            self.end(conn, false, now);
        }
    }

    /// The radio was dropped: every connection ends, every provider and the
    /// watcher stop.
    fn shutdown(&mut self, now: Instant) {
        self.end_all(now);
        let ready: Vec<[u8; 16]> = self
            .services
            .iter()
            .filter(|(_, s)| matches!(s.made, Made::Ready { .. }))
            .map(|(t, _)| *t)
            .collect();
        for t in ready {
            self.os.withdraw(t);
        }
        self.services.clear();
        if self.scan == Scan::On {
            self.os.scan(false);
        }
        self.scan = Scan::Off;
        self.alive = false;
    }

    fn emit(&mut self, ev: RadioEvent) {
        if let Err(Some(conn)) = self.events.emit(ev) {
            self.lost.push(conn);
        }
    }

    /// End the connections whose events were lost.
    fn settle(&mut self, now: Instant) {
        while let Some(conn) = self.lost.pop() {
            self.end(conn, false, now);
        }
    }

    /// Log a WinRT error once in a row (a name or a code, never a device).
    fn note(&mut self, what: &str, why: &str) {
        let line = format!("{what}: {why}");
        if self.logged.as_ref() != Some(&line) {
            eprintln!("raven-node nearby: WinRT {line}");
            self.logged = Some(line);
        }
    }
}

// ── The send table ──────────────────────────────────────────────────────────

/// A connection's writer task, as the [`Table`] queues frames for it.
pub(crate) trait Push {
    /// Queue `frame`; false when the writer is gone.
    fn push(&self, frame: Vec<u8>) -> bool;
}

impl Push for mpsc::UnboundedSender<Vec<u8>> {
    fn push(&self, frame: Vec<u8>) -> bool {
        self.send(frame).is_ok()
    }
}

/// How each live connection sends, shared by the radio handle (the engine's
/// sends) and the driver (which adds and removes connections, and counts the
/// frames a writer task passed on).
pub(crate) struct Table<W> {
    slots: HashMap<ConnId, Slot<W>>,
}

struct Slot<W> {
    writer: W,
    max_tx: usize,
    queued: usize,
    /// A send found the window full: one `Writable` is owed.
    want: bool,
}

impl<W> Default for Table<W> {
    fn default() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }
}

impl<W: Push> Table<W> {
    pub(crate) fn add(&mut self, conn: ConnId, writer: W, max_tx: usize) {
        self.slots.insert(
            conn,
            Slot {
                writer,
                max_tx,
                queued: 0,
                want: false,
            },
        );
    }

    pub(crate) fn remove(&mut self, conn: ConnId) {
        self.slots.remove(&conn);
    }

    /// Queue a frame on `conn` for its writer task: an error for an unknown
    /// connection or a frame that is empty or over `max_tx`.
    pub(crate) fn send(&mut self, conn: ConnId, frame: &[u8]) -> Result<Sent, String> {
        let slot = self.slots.get_mut(&conn).ok_or("not connected")?;
        if frame.is_empty() || frame.len() > slot.max_tx {
            return Err(format!(
                "a frame of {} bytes on a link of max_tx {}",
                frame.len(),
                slot.max_tx
            ));
        }
        if slot.queued >= SEND_WINDOW {
            slot.want = true;
            return Ok(Sent::WouldBlock);
        }
        if !slot.writer.push(frame.to_vec()) {
            return Err("not connected".into());
        }
        slot.queued += 1;
        Ok(Sent::Queued)
    }

    /// `conn`'s writer task passed one frame on: true when a send waits for
    /// room (one `Writable` is owed now).
    pub(crate) fn sent(&mut self, conn: ConnId) -> bool {
        let Some(slot) = self.slots.get_mut(&conn) else {
            return false;
        };
        slot.queued = slot.queued.saturating_sub(1);
        if slot.want && slot.queued < SEND_WINDOW {
            slot.want = false;
            return true;
        }
        false
    }
}
