//! The helper's state machine: everything raven-nearby-helper decides,
//! with no CoreBluetooth in it, so it is tested on every platform the
//! helper builds on. `cb` (macOS) feeds it CoreBluetooth's callbacks and
//! raven-node's commands, carries out its [`Os`] calls, and writes the
//! lines it queues ([`Machine::take_out`]) to stdout.
//!
//! **Peripheral.** One primary service `T` per published token, with one
//! characteristic `C(T)`: WriteWithoutResponse | Write | Notify, no Read,
//! no encryption (RNL1 §4). Only an added service is advertised, as the
//! advert's only UUID; a withdrawn token goes off air before anything else
//! changes, so at most one token is ever on air. A connection is one central
//! subscribed to one service. Notifications go to that central only.
//! CoreBluetooth cannot drop a central, so a connection this side ends is
//! silenced: that central's writes are ignored for [`SILENCE`] unless it
//! unsubscribes first.
//!
//! **Central.** Scanning reports adverts that carry candidate tokens (never
//! a Bluetooth SIG UUID), at most once per [`SEEN_EVERY`] per device unless
//! its UUIDs change; only such devices are remembered (at most
//! [`MAX_DEVICES`], forgotten [`DEVICE_TTL`] after the last advert). A
//! connect is one link per device: `cb` connects, finds `T` and `C(T)`, and
//! subscribes; the connection is up when the subscription is
//! ([`Machine::central_up`]), or ends after [`CONNECT_BUDGET`]. Frames go
//! out as Write Commands.
//!
//! **Sending.** Each connection queues what CoreBluetooth cannot take yet
//! and sends it when CoreBluetooth says it is ready again; each frame that
//! leaves the queue is one `sent` (raven-node's send window).
//!
//! **Power.** Both managers must be powered on. When the radio goes off,
//! CoreBluetooth drops every connection, service and advert: each
//! connection gets its `disconnected`, and what raven-node still wants is
//! set up again when the power comes back.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::proto::{self, FromHelper, Power, Side, ToHelper};

/// How long a connect may take to come up (raven-node gives up sooner).
pub(crate) const CONNECT_BUDGET: Duration = Duration::from_secs(20);
/// A refused service or advert is tried again after this.
pub(crate) const RETRY: Duration = Duration::from_secs(10);
/// A device that keeps advertising is `seen` at most this often (a change
/// of its UUIDs at once).
pub(crate) const SEEN_EVERY: Duration = Duration::from_secs(1);
/// A device not seen this long is forgotten, unless a connection uses it.
pub(crate) const DEVICE_TTL: Duration = Duration::from_secs(60);
/// Devices remembered at once.
pub(crate) const MAX_DEVICES: usize = 256;
/// Writes from a central whose connection this side ended are ignored this
/// long, unless it unsubscribes first.
pub(crate) const SILENCE: Duration = Duration::from_secs(10);
/// Notifications held for a central connection before it is up.
pub(crate) const EARLY_FRAMES: usize = 8;
/// Connections at once, each way (raven-node keeps at most 8 knocking and
/// 4 pipes).
pub(crate) const MAX_CONNS: usize = 16;
/// Frames one connection may queue (raven-node's window is 16): more is a
/// fault, and the connection ends.
pub(crate) const QUEUE: usize = 32;
/// Why the helper gets no radio when macOS refuses Bluetooth to it.
pub(crate) const NOT_ALLOWED: &str = "macOS has not allowed Bluetooth for RavenNearby: allow it \
     in System Settings > Privacy & Security > Bluetooth";
/// Why the helper gets no radio on a Mac without Bluetooth LE.
pub(crate) const NO_LE: &str = "this Mac has no Bluetooth LE";

/// The Bluetooth base UUID's last 12 bytes: a 16- or 32-bit UUID written
/// long, never an RNB1 token (whose byte 6 starts with the version nibble
/// 4). As BlueZ's and WinRT's.
const SIG_BASE_TAIL: [u8; 12] = [
    0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// A CoreBluetooth manager's state (`CBManagerState`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CbState {
    Unknown,
    Resetting,
    Unsupported,
    Unauthorized,
    PoweredOff,
    PoweredOn,
}

impl CbState {
    /// `CBManagerState`'s raw value (an unknown value is `Unknown`).
    pub(crate) fn from_raw(v: isize) -> Self {
        match v {
            1 => Self::Resetting,
            2 => Self::Unsupported,
            3 => Self::Unauthorized,
            4 => Self::PoweredOff,
            5 => Self::PoweredOn,
            _ => Self::Unknown,
        }
    }
}

/// The radio's state from the two managers', or `None` while one is
/// still unknown (macOS asking the user, or the manager starting).
pub(crate) fn combine(cm: CbState, pm: CbState) -> Option<(Power, &'static str)> {
    use CbState::*;
    if cm == Unauthorized || pm == Unauthorized {
        return Some((Power::Unauthorized, NOT_ALLOWED));
    }
    if cm == Unsupported || pm == Unsupported {
        return Some((Power::Unsupported, NO_LE));
    }
    if cm == Unknown || pm == Unknown {
        return None;
    }
    if cm == PoweredOn && pm == PoweredOn {
        Some((Power::On, ""))
    } else {
        Some((Power::Off, ""))
    }
}

/// A Bluetooth SIG UUID, not a candidate token.
pub(crate) fn is_sig_uuid(u: &[u8; 16]) -> bool {
    u[4..] == SIG_BASE_TAIL
}

/// The candidate tokens among an advert's service UUIDs: the ones that are
/// not the SIG's, each once, in order, at most [`proto::MAX_UUIDS`].
pub(crate) fn candidates(uuids: &[[u8; 16]]) -> Vec<[u8; 16]> {
    let mut out: Vec<[u8; 16]> = Vec::new();
    for u in uuids {
        if out.len() == proto::MAX_UUIDS {
            break;
        }
        if !is_sig_uuid(u) && !out.contains(u) {
            out.push(*u);
        }
    }
    out
}

/// A link's frame size from what CoreBluetooth reports (RNL1 §4).
pub(crate) fn frame_limit(reported: usize) -> usize {
    reported.clamp(proto::MIN_TX, proto::MAX_FRAME)
}

/// What [`Machine`] asks of CoreBluetooth. Every call returns at once; what
/// CoreBluetooth answers comes back as a [`Machine`] input.
pub(crate) trait Os {
    /// Publish service `t` with its one characteristic `c`;
    /// [`Machine::added`] follows.
    fn add(&mut self, t: [u8; 16], c: [u8; 16]);
    /// Withdraw service `t` (added or still being added).
    fn remove(&mut self, t: [u8; 16]);
    /// Advertise exactly `t` (any earlier advert stops first), or nothing;
    /// a refusal comes back as [`Machine::advertising`].
    fn advertise(&mut self, t: Option<[u8; 16]>);
    fn scan(&mut self, on: bool);
    /// Connect to `dev` (a device [`Machine::discovered`] kept) and
    /// subscribe to characteristic `c` of service `t`: then
    /// [`Machine::central_up`] or [`Machine::central_down`]. False: `dev`
    /// is not known.
    fn connect(&mut self, dev: &str, t: [u8; 16], c: [u8; 16]) -> bool;
    /// End `dev`'s link or the connect under way (no callback needed).
    fn cancel(&mut self, dev: &str);
    /// One Write Command on `dev`'s link. False: not now
    /// ([`Machine::central_ready`] follows).
    fn write(&mut self, dev: &str, frame: &[u8]) -> bool;
    /// One notification of `t` to `central` only. False: CoreBluetooth's
    /// queue is full ([`Machine::peripheral_ready`] follows).
    fn notify(&mut self, t: [u8; 16], central: &str, frame: &[u8]) -> bool;
    /// `dev` is no longer remembered: let go of its peripheral object.
    fn forget(&mut self, dev: &str);
    /// No connection uses `central` any more: let go of it.
    fn forget_central(&mut self, central: &str);
    /// The radio went off: CoreBluetooth dropped every link, service and
    /// advert; let go of every object kept for them.
    fn reset(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Added {
    Pending,
    Yes,
    Failed(Instant),
}

enum Link {
    Central {
        dev: String,
        t: [u8; 16],
        /// Notifications that came before the link was up (`None`: up).
        early: Option<Vec<Vec<u8>>>,
        deadline: Instant,
    },
    Peripheral {
        t: [u8; 16],
        central: String,
    },
}

struct Conn {
    link: Link,
    max_tx: usize,
    queue: VecDeque<Vec<u8>>,
}

struct Device {
    seen: Instant,
    /// The last `seen` line: when, and its UUIDs.
    said: Option<(Instant, Vec<[u8; 16]>)>,
}

/// How a connection ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    /// CoreBluetooth said so.
    Remote,
    /// This side ended it: cancel the link, or silence the central.
    Local,
    /// The radio or the service went away: nothing left to undo.
    Quiet,
}

/// The helper's state (see the module doc). Every input is a method; every
/// output is an [`Os`] call or a line in [`Machine::take_out`].
pub(crate) struct Machine<O: Os> {
    pub(crate) os: O,
    out: Vec<FromHelper>,
    cm: CbState,
    pm: CbState,
    told: Option<(Power, &'static str)>,
    powered: bool,
    stopped: bool,
    /// What raven-node wants published (service to characteristic), and
    /// advertised.
    want: BTreeMap<[u8; 16], [u8; 16]>,
    advert: Option<[u8; 16]>,
    /// What CoreBluetooth was asked to publish, and how it went.
    services: BTreeMap<[u8; 16], (Added, [u8; 16])>,
    on_air: Option<[u8; 16]>,
    adv_retry: Option<Instant>,
    want_scan: bool,
    scanning: bool,
    devices: HashMap<String, Device>,
    conns: BTreeMap<u64, Conn>,
    by_dev: HashMap<String, u64>,
    by_central: HashMap<([u8; 16], String), u64>,
    silenced: HashMap<([u8; 16], String), Instant>,
    next_peripheral: u64,
}

impl<O: Os> Machine<O> {
    pub(crate) fn new(os: O) -> Self {
        Self {
            os,
            out: Vec::new(),
            cm: CbState::Unknown,
            pm: CbState::Unknown,
            told: None,
            powered: false,
            stopped: false,
            want: BTreeMap::new(),
            advert: None,
            services: BTreeMap::new(),
            on_air: None,
            adv_retry: None,
            want_scan: false,
            scanning: false,
            devices: HashMap::new(),
            conns: BTreeMap::new(),
            by_dev: HashMap::new(),
            by_central: HashMap::new(),
            silenced: HashMap::new(),
            // The helper's own connections are even; raven-node numbers
            // the ones it opens odd.
            next_peripheral: 2,
        }
    }

    /// The lines queued for raven-node since the last call.
    pub(crate) fn take_out(&mut self) -> Vec<FromHelper> {
        std::mem::take(&mut self.out)
    }

    /// The service a characteristic belongs to, among those asked of
    /// CoreBluetooth.
    pub(crate) fn service_of_char(&self, c: &[u8; 16]) -> Option<[u8; 16]> {
        self.services
            .iter()
            .find(|(_, (_, ch))| ch == c)
            .map(|(t, _)| *t)
    }

    /// A connection uses `central` (`cb` keeps its object only then).
    pub(crate) fn has_central(&self, central: &str) -> bool {
        self.by_central.keys().any(|(_, c)| c == central)
    }

    // ── Inputs ──────────────────────────────────────────────────────────

    /// One line from raven-node. A line that does not make sense is
    /// ignored (a frame is answered with its `sent`, so the window holds).
    pub(crate) fn command(&mut self, cmd: ToHelper, now: Instant) {
        if self.stopped {
            return;
        }
        match cmd {
            ToHelper::Services {
                services,
                advertise,
            } => {
                if services.len() > proto::MAX_SERVICES {
                    return;
                }
                let Some(want) = services
                    .iter()
                    .map(|g| {
                        Some((
                            proto::uuid_from(&g.service)?,
                            proto::uuid_from(&g.characteristic)?,
                        ))
                    })
                    .collect::<Option<BTreeMap<_, _>>>()
                else {
                    return;
                };
                let advert = match advertise.as_deref().map(proto::uuid_from) {
                    None => None,
                    Some(Some(t)) if want.contains_key(&t) => Some(t),
                    Some(_) => return,
                };
                self.want = want;
                self.advert = advert;
            }
            ToHelper::Scan { on } => self.want_scan = on,
            ToHelper::Connect {
                conn,
                dev,
                service,
                characteristic,
            } => self.connect(conn, &dev, &service, &characteristic, now),
            ToHelper::Send { conn, b64 } => self.send(conn, &b64, now),
            ToHelper::Disconnect { conn } => self.end(conn, End::Local, now),
        }
        self.apply(now);
    }

    /// The central manager's state changed.
    pub(crate) fn cm_state(&mut self, s: CbState, now: Instant) {
        self.cm = s;
        self.power(now);
    }

    /// The peripheral manager's state changed.
    pub(crate) fn pm_state(&mut self, s: CbState, now: Instant) {
        self.pm = s;
        self.power(now);
    }

    /// An advert from `dev`. True: the device is remembered now (`cb`
    /// keeps its peripheral object until [`Os::forget`]).
    pub(crate) fn discovered(
        &mut self,
        dev: &str,
        uuids: &[[u8; 16]],
        connectable: Option<bool>,
        rssi: i16,
        now: Instant,
    ) -> bool {
        let known = self.devices.contains_key(dev);
        if !self.powered
            || self.stopped
            || connectable == Some(false)
            || dev.is_empty()
            || dev.len() > proto::MAX_DEV
        {
            return known;
        }
        let cands = candidates(uuids);
        if cands.is_empty() {
            return known;
        }
        if !known && self.devices.len() >= MAX_DEVICES {
            // Make room: the device seen longest ago that no link uses.
            let by_dev = &self.by_dev;
            let Some(old) = self
                .devices
                .iter()
                .filter(|(d, _)| !by_dev.contains_key(*d))
                .min_by_key(|(_, v)| v.seen)
                .map(|(d, _)| d.clone())
            else {
                return false;
            };
            self.devices.remove(&old);
            self.os.forget(&old);
        }
        let d = self.devices.entry(dev.to_owned()).or_insert(Device {
            seen: now,
            said: None,
        });
        d.seen = now;
        let fresh = match &d.said {
            Some((at, said)) => *said != cands || now.saturating_duration_since(*at) >= SEEN_EVERY,
            None => true,
        };
        if fresh {
            d.said = Some((now, cands.clone()));
            self.out.push(FromHelper::Seen {
                dev: dev.to_owned(),
                uuids: cands.iter().map(proto::uuid_hex).collect(),
                rssi,
            });
        }
        true
    }

    /// `dev`'s link is subscribed to its characteristic; `max_tx` is
    /// CoreBluetooth's largest Write Command on it.
    pub(crate) fn central_up(&mut self, dev: &str, max_tx: usize) {
        let Some(&conn) = self.by_dev.get(dev) else {
            return;
        };
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        let Link::Central { t, early, .. } = &mut c.link else {
            return;
        };
        let Some(held) = early.take() else {
            return;
        };
        let max_tx = frame_limit(max_tx);
        c.max_tx = max_tx;
        self.out.push(FromHelper::Connected {
            conn,
            role: Side::Central,
            service: proto::uuid_hex(t),
            max_tx,
            max_rx: max_tx,
        });
        for f in held {
            self.out.push(FromHelper::Frame {
                conn,
                b64: proto::b64_of(&f),
            });
        }
    }

    /// `dev`'s link failed or ended.
    pub(crate) fn central_down(&mut self, dev: &str, now: Instant) {
        if let Some(&conn) = self.by_dev.get(dev) {
            self.end(conn, End::Remote, now);
        }
    }

    /// A notification from `dev`.
    pub(crate) fn notified(&mut self, dev: &str, bytes: Vec<u8>, now: Instant) {
        let Some(&conn) = self.by_dev.get(dev) else {
            return;
        };
        if !(1..=proto::MAX_FRAME).contains(&bytes.len()) {
            return;
        }
        let Some(Conn {
            link: Link::Central { early, .. },
            ..
        }) = self.conns.get_mut(&conn)
        else {
            return;
        };
        match early {
            None => self.out.push(FromHelper::Frame {
                conn,
                b64: proto::b64_of(&bytes),
            }),
            Some(held) if held.len() < EARLY_FRAMES => held.push(bytes),
            Some(_) => self.end(conn, End::Local, now),
        }
    }

    /// `dev`'s link can take Write Commands again.
    pub(crate) fn central_ready(&mut self, dev: &str) {
        if let Some(&conn) = self.by_dev.get(dev) {
            self.pump(conn);
        }
    }

    /// CoreBluetooth added service `t`, or refused it.
    pub(crate) fn added(&mut self, t: [u8; 16], ok: bool, now: Instant) {
        let Some((state, _)) = self.services.get_mut(&t) else {
            return;
        };
        if *state != Added::Pending {
            return;
        }
        *state = if ok { Added::Yes } else { Added::Failed(now) };
        self.apply(now);
    }

    /// CoreBluetooth started the advert, or refused it.
    pub(crate) fn advertising(&mut self, ok: bool, now: Instant) {
        if !ok && self.on_air.is_some() {
            self.on_air = None;
            self.adv_retry = Some(now + RETRY);
        }
    }

    /// `central` subscribed to service `t`'s characteristic; `max_tx` is
    /// its largest notification.
    pub(crate) fn subscribed(&mut self, t: [u8; 16], central: &str, max_tx: usize, now: Instant) {
        if !self.powered || self.stopped || !self.want.contains_key(&t) || !self.is_added(&t) {
            return;
        }
        let key = (t, central.to_owned());
        if self.silenced.get(&key).is_some_and(|until| now < *until) {
            return;
        }
        self.silenced.remove(&key);
        let peripheral = self
            .conns
            .values()
            .filter(|c| matches!(c.link, Link::Peripheral { .. }))
            .count();
        if self.by_central.contains_key(&key)
            || peripheral >= MAX_CONNS
            || self.next_peripheral >= proto::CONN_LIMIT
        {
            return;
        }
        let conn = self.next_peripheral;
        self.next_peripheral += 2;
        let max_tx = frame_limit(max_tx);
        self.conns.insert(
            conn,
            Conn {
                link: Link::Peripheral {
                    t,
                    central: central.to_owned(),
                },
                max_tx,
                queue: VecDeque::new(),
            },
        );
        self.by_central.insert(key, conn);
        self.out.push(FromHelper::Connected {
            conn,
            role: Side::Peripheral,
            service: proto::uuid_hex(&t),
            max_tx,
            max_rx: max_tx,
        });
    }

    /// `central` unsubscribed from service `t`'s characteristic.
    pub(crate) fn unsubscribed(&mut self, t: [u8; 16], central: &str, now: Instant) {
        let key = (t, central.to_owned());
        self.silenced.remove(&key);
        if let Some(&conn) = self.by_central.get(&key) {
            self.end(conn, End::Remote, now);
        }
    }

    /// `central` wrote `bytes` to service `t`'s characteristic.
    pub(crate) fn written(&mut self, t: [u8; 16], central: &str, bytes: &[u8]) {
        if !(1..=proto::MAX_FRAME).contains(&bytes.len()) {
            return;
        }
        if let Some(&conn) = self.by_central.get(&(t, central.to_owned())) {
            self.out.push(FromHelper::Frame {
                conn,
                b64: proto::b64_of(bytes),
            });
        }
    }

    /// CoreBluetooth can take notifications again.
    pub(crate) fn peripheral_ready(&mut self) {
        let conns: Vec<u64> = self
            .conns
            .iter()
            .filter(|(_, c)| matches!(c.link, Link::Peripheral { .. }) && !c.queue.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for conn in conns {
            self.pump(conn);
        }
    }

    /// Deadlines, retries and forgetting.
    pub(crate) fn tick(&mut self, now: Instant) {
        if self.stopped {
            return;
        }
        let late: Vec<u64> = self
            .conns
            .iter()
            .filter(|(_, c)| {
                matches!(c.link, Link::Central { early: Some(_), deadline, .. } if now >= deadline)
            })
            .map(|(id, _)| *id)
            .collect();
        for conn in late {
            self.end(conn, End::Local, now);
        }
        self.silenced.retain(|_, until| now < *until);
        let by_dev = &self.by_dev;
        let stale: Vec<String> = self
            .devices
            .iter()
            .filter(|(d, v)| {
                !by_dev.contains_key(*d) && now.saturating_duration_since(v.seen) >= DEVICE_TTL
            })
            .map(|(d, _)| d.clone())
            .collect();
        for dev in stale {
            self.devices.remove(&dev);
            self.os.forget(&dev);
        }
        self.apply(now);
    }

    /// raven-node is gone: stop advertising and scanning, end every link
    /// and withdraw every service. Nothing more is reported.
    pub(crate) fn stop(&mut self) {
        if std::mem::replace(&mut self.stopped, true) {
            return;
        }
        if self.on_air.take().is_some() {
            self.os.advertise(None);
        }
        if std::mem::take(&mut self.scanning) {
            self.os.scan(false);
        }
        for c in std::mem::take(&mut self.conns).into_values() {
            if let Link::Central { dev, .. } = c.link {
                self.os.cancel(&dev);
            }
        }
        for t in std::mem::take(&mut self.services).into_keys() {
            self.os.remove(t);
        }
        self.by_dev.clear();
        self.by_central.clear();
        self.out.clear();
    }

    // ── Inside ──────────────────────────────────────────────────────────

    fn power(&mut self, now: Instant) {
        let Some(state) = combine(self.cm, self.pm).filter(|_| !self.stopped) else {
            return;
        };
        let on = state.0 == Power::On;
        if self.powered && !on {
            // CoreBluetooth dropped every link, service and advert.
            let all: Vec<u64> = self.conns.keys().copied().collect();
            for conn in all {
                self.end(conn, End::Quiet, now);
            }
            self.services.clear();
            self.on_air = None;
            self.adv_retry = None;
            self.scanning = false;
            self.devices.clear();
            self.silenced.clear();
            self.os.reset();
        }
        self.powered = on;
        if self.told != Some(state) {
            self.told = Some(state);
            self.out.push(FromHelper::State {
                state: state.0,
                detail: state.1.to_owned(),
            });
        }
        self.apply(now);
    }

    /// Bring CoreBluetooth to what raven-node wants: withdrawals first
    /// (an unwanted token goes off air before anything else), then the new
    /// services, the advert and the scan.
    fn apply(&mut self, now: Instant) {
        if !self.powered || self.stopped {
            return;
        }
        if self.on_air.is_some_and(|t| Some(t) != self.advert) {
            self.os.advertise(None);
            self.on_air = None;
        }
        let gone: Vec<[u8; 16]> = self
            .services
            .keys()
            .filter(|t| !self.want.contains_key(*t))
            .copied()
            .collect();
        for t in gone {
            self.services.remove(&t);
            self.os.remove(t);
            let ended: Vec<u64> = self
                .by_central
                .iter()
                .filter(|((s, _), _)| *s == t)
                .map(|(_, c)| *c)
                .collect();
            for conn in ended {
                self.end(conn, End::Quiet, now);
            }
            self.silenced.retain(|(s, _), _| *s != t);
        }
        for (t, c) in self.want.clone() {
            let add = match self.services.get(&t) {
                None => true,
                Some((Added::Failed(at), _)) => now.saturating_duration_since(*at) >= RETRY,
                Some(_) => false,
            };
            if add {
                self.services.insert(t, (Added::Pending, c));
                self.os.add(t, c);
            }
        }
        let desired = self.advert.filter(|t| self.is_added(t));
        if desired.is_some() && self.on_air != desired && self.adv_retry.is_none_or(|at| now >= at)
        {
            self.os.advertise(desired);
            self.on_air = desired;
            self.adv_retry = None;
        }
        if self.want_scan != self.scanning {
            self.os.scan(self.want_scan);
            self.scanning = self.want_scan;
        }
    }

    /// Service `t` is published.
    fn is_added(&self, t: &[u8; 16]) -> bool {
        matches!(self.services.get(t), Some((Added::Yes, _)))
    }

    fn connect(&mut self, conn: u64, dev: &str, service: &str, ch: &str, now: Instant) {
        if conn.is_multiple_of(2) || conn >= proto::CONN_LIMIT || self.conns.contains_key(&conn) {
            return;
        }
        let central = self
            .conns
            .values()
            .filter(|c| matches!(c.link, Link::Central { .. }))
            .count();
        let t = proto::uuid_from(service);
        let ok = match (t, proto::uuid_from(ch)) {
            (Some(t), Some(c)) => {
                self.powered
                    && central < MAX_CONNS
                    && self.devices.contains_key(dev)
                    && !self.by_dev.contains_key(dev)
                    && self.os.connect(dev, t, c)
            }
            _ => false,
        };
        let (true, Some(t)) = (ok, t) else {
            self.out.push(FromHelper::Disconnected { conn });
            return;
        };
        self.conns.insert(
            conn,
            Conn {
                link: Link::Central {
                    dev: dev.to_owned(),
                    t,
                    early: Some(Vec::new()),
                    deadline: now + CONNECT_BUDGET,
                },
                max_tx: 0,
                queue: VecDeque::new(),
            },
        );
        self.by_dev.insert(dev.to_owned(), conn);
    }

    fn send(&mut self, conn: u64, b64: &str, now: Instant) {
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        let up = !matches!(c.link, Link::Central { early: Some(_), .. });
        let frame = proto::frame_from(b64).filter(|f| up && f.len() <= c.max_tx);
        let Some(frame) = frame else {
            // Not a frame this link can carry: dropped, its credit returned.
            self.out.push(FromHelper::Sent { conn });
            return;
        };
        if c.queue.len() >= QUEUE {
            self.end(conn, End::Local, now);
            return;
        }
        c.queue.push_back(frame);
        self.pump(conn);
    }

    /// Hand `conn`'s queued frames to CoreBluetooth while it takes them.
    fn pump(&mut self, conn: u64) {
        let Self { os, conns, out, .. } = self;
        let Some(c) = conns.get_mut(&conn) else {
            return;
        };
        while let Some(f) = c.queue.front() {
            let taken = match &c.link {
                Link::Central {
                    dev, early: None, ..
                } => os.write(dev, f),
                Link::Central { .. } => false,
                Link::Peripheral { t, central } => os.notify(*t, central, f),
            };
            if !taken {
                return;
            }
            c.queue.pop_front();
            out.push(FromHelper::Sent { conn });
        }
    }

    fn end(&mut self, conn: u64, how: End, now: Instant) {
        let Some(c) = self.conns.remove(&conn) else {
            return;
        };
        match c.link {
            Link::Central { dev, .. } => {
                self.by_dev.remove(&dev);
                if how == End::Local {
                    self.os.cancel(&dev);
                }
            }
            Link::Peripheral { t, central } => {
                if how == End::Local {
                    self.silenced.insert((t, central.clone()), now + SILENCE);
                }
                self.by_central.remove(&(t, central.clone()));
                if !self.by_central.keys().any(|(_, c)| *c == central) {
                    self.os.forget_central(&central);
                }
            }
        }
        self.out.push(FromHelper::Disconnected { conn });
    }
}
