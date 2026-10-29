//! The WinRT side of the Windows backend (Windows, feature `nearby-radio`):
//! [`open`], the radio handle [`WinrtRadio`], the driver task and every WinRT
//! call. The parent module's doc has the design; this part only moves
//! WinRT's objects, events and answers to and from [`Core`].

use std::collections::HashMap;
use std::fmt;
use std::future::IntoFuture;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use raven_core::nearby_link::char_uuid;
use tokio::runtime::Handle;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::AbortHandle;
use tokio::time::MissedTickBehavior;
use windows::core::{IInspectable, GUID};
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisementReceivedEventArgs, BluetoothLEAdvertisementWatcher,
    BluetoothLEAdvertisementWatcherStoppedEventArgs, BluetoothLEScanningMode,
};
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattCharacteristicProperties,
    GattClientCharacteristicConfigurationDescriptorValue, GattCommunicationStatus,
    GattDeviceService, GattLocalCharacteristic, GattLocalCharacteristicParameters,
    GattProtectionLevel, GattServiceProvider, GattServiceProviderAdvertisementStatus,
    GattServiceProviderAdvertisementStatusChangedEventArgs,
    GattServiceProviderAdvertisingParameters, GattSession, GattSubscribedClient,
    GattValueChangedEventArgs, GattWriteOption, GattWriteRequest, GattWriteRequestedEventArgs,
};
use windows::Devices::Bluetooth::{
    BluetoothAdapter, BluetoothAddressType, BluetoothCacheMode, BluetoothConnectionStatus,
    BluetoothError, BluetoothLEDevice,
};
use windows::Devices::Radios::{Radio as OsRadio, RadioState as OsRadioState};
use windows::Foundation::{Deferral, TypedEventHandler};
use windows::Storage::Streams::{DataReader, DataWriter, IBuffer};

use super::super::lock;
use super::super::radio::{
    ConnId, EventTx, Radio, RadioAddr, RadioCaps, RadioEvent, RadioState, Sent,
};
use super::{
    bt_error_name, candidates, caps, frame_limit, guid_u128, notify_limit, setup_failed, uuid_of,
    Adapter, Addr, AddrKind, Cmd, Core, Os, Server, Subscriber, Table, CONNECT_BUDGET,
    MAX_ADVERT_UUIDS, MAX_PERIPHERAL,
};

/// How long [`open`] waits for each WinRT setup call.
const OPEN_WAIT: Duration = Duration::from_secs(10);
/// The driver's tick when nothing happens (deadlines, retries, owed events).
const TICK: Duration = Duration::from_millis(250);
/// Subscribed centrals read per change (strangers can subscribe too).
const MAX_SUBSCRIBERS: u32 = 4 * MAX_PERIPHERAL as u32;
/// Service UUIDs read from one advert before [`candidates`] filters them.
const ADVERT_UUIDS_READ: u32 = 2 * MAX_ADVERT_UUIDS as u32;
/// ATT's "Invalid Offset" (a long write: RNL1 §4 has one frame per value).
const ATT_INVALID_OFFSET: u8 = 0x07;

type WinResult<T> = windows::core::Result<T>;

/// The UUID as WinRT's GUID.
fn guid(u: &[u8; 16]) -> GUID {
    GUID::from_u128(guid_u128(u))
}

fn hresult(e: &windows::core::Error) -> u32 {
    e.code().0 as u32
}

/// Why a WinRT step failed: an HRESULT, or a status WinRT answered with
/// (codes and names only, never a device).
enum Fail {
    Os(windows::core::Error),
    Status(&'static str, &'static str),
}

impl From<windows::core::Error> for Fail {
    fn from(e: windows::core::Error) -> Self {
        Self::Os(e)
    }
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os(e) => write!(f, "HRESULT 0x{:08X}", hresult(e)),
            Self::Status(what, status) => write!(f, "{what}: {status}"),
        }
    }
}

fn communication(status: GattCommunicationStatus, what: &'static str) -> Result<(), Fail> {
    let name = match status {
        GattCommunicationStatus::Success => return Ok(()),
        GattCommunicationStatus::Unreachable => "Unreachable",
        GattCommunicationStatus::ProtocolError => "ProtocolError",
        GattCommunicationStatus::AccessDenied => "AccessDenied",
        _ => "GattCommunicationStatus(unknown)",
    };
    Err(Fail::Status(what, name))
}

fn bluetooth(error: BluetoothError, what: &'static str) -> Result<(), Fail> {
    if error == BluetoothError::Success {
        Ok(())
    } else {
        Err(Fail::Status(what, bt_error_name(error.0)))
    }
}

// ── Buffers ─────────────────────────────────────────────────────────────────

/// A frame as a WinRT buffer.
pub(super) fn to_buffer(bytes: &[u8]) -> WinResult<IBuffer> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(bytes)?;
    writer.DetachBuffer()
}

/// A WinRT buffer's bytes (an ATT value: at most 512).
pub(super) fn buffer_bytes(buf: &IBuffer) -> WinResult<Vec<u8>> {
    let mut out = vec![0u8; buf.Length()? as usize];
    if !out.is_empty() {
        DataReader::FromBuffer(buf)?.ReadBytes(&mut out)?;
    }
    Ok(out)
}

// ── Messages to the driver ──────────────────────────────────────────────────

/// What reaches the driver: radio calls, WinRT's events and the answers of
/// the tasks it started.
enum Msg {
    Cmd(Cmd),
    Power(bool),
    Created {
        t: [u8; 16],
        made: Result<Served, Fail>,
    },
    Aborted {
        t: [u8; 16],
        why: &'static str,
    },
    Subscribers {
        t: [u8; 16],
        list: Vec<(Subscriber, GattSubscribedClient)>,
    },
    Written {
        t: [u8; 16],
        device: String,
        bytes: Vec<u8>,
    },
    Advert {
        addr: Addr,
        uuids: Vec<[u8; 16]>,
        rssi: i16,
        connectable: bool,
    },
    ScanStopped {
        gen: u64,
        why: &'static str,
    },
    CentralUp {
        conn: ConnId,
        link: Link,
        max: usize,
    },
    CentralFailed {
        conn: ConnId,
        why: String,
    },
    Frame {
        conn: ConnId,
        bytes: Vec<u8>,
    },
    Lost {
        conn: ConnId,
    },
    /// A writer task passed one frame on (`ok`), or failed.
    Sent {
        conn: ConnId,
        ok: bool,
    },
}

// ── Opening the radio ───────────────────────────────────────────────────────

/// One WinRT setup call, waited for up to [`OPEN_WAIT`].
fn wait<T, F>(rt: &Handle, what: &str, op: WinResult<F>) -> Result<T, RadioState>
where
    F: IntoFuture<Output = WinResult<T>>,
{
    let op = op.map_err(|e| setup_failed(what, hresult(&e)))?;
    match rt.block_on(tokio::time::timeout(OPEN_WAIT, op.into_future())) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(setup_failed(what, hresult(&e))),
        Err(_) => Err(RadioState::Unsupported(format!(
            "{what}: no answer within {} s",
            OPEN_WAIT.as_secs()
        ))),
    }
}

/// Whether WinRT lets this process be a GATT server: one provider for a
/// random UUID, never advertised, dropped at once.
fn probe_server(rt: &Handle) -> Server {
    let probe = GUID::new().and_then(GattServiceProvider::CreateAsync);
    match wait(rt, "GattServiceProvider", probe) {
        // Dropping the result releases the provider.
        Ok(made) => match made.Error() {
            Ok(e) if e == BluetoothError::Success => Server::Works,
            Ok(e) => Server::Refused(bt_error_name(e.0).into()),
            Err(e) => Server::Refused(format!("HRESULT 0x{:08X}", hresult(&e))),
        },
        Err(RadioState::Unauthorized(why) | RadioState::Unsupported(why)) => Server::Refused(why),
        Err(other) => Server::Refused(format!("{other:?}")),
    }
}

/// `On` is on; `Off` and `Disabled` are off; `Unknown` says nothing.
fn powered(state: OsRadioState) -> Option<bool> {
    match state {
        OsRadioState::On => Some(true),
        OsRadioState::Off | OsRadioState::Disabled => Some(false),
        _ => None,
    }
}

/// The default Bluetooth adapter as a [`Radio`]. Blocks briefly on WinRT:
/// call it on the blocking pool, inside the runtime.
pub(crate) fn open(tx: mpsc::Sender<RadioEvent>) -> Result<WinrtRadio, RadioState> {
    let rt =
        Handle::try_current().map_err(|_| RadioState::Unsupported("no tokio runtime".into()))?;
    let adapter = wait(&rt, "BluetoothAdapter", BluetoothAdapter::GetDefaultAsync())?;
    let info = Adapter {
        low_energy: adapter.IsLowEnergySupported().unwrap_or(false),
        central: adapter.IsCentralRoleSupported().unwrap_or(false),
        peripheral: adapter.IsPeripheralRoleSupported().unwrap_or(false),
    };
    let server = if info.peripheral {
        probe_server(&rt)
    } else {
        Server::NotTried
    };
    if let Server::Refused(why) = &server {
        eprintln!(
            "raven-node nearby: WinRT refused this process a GATT server ({why}): central only"
        );
    }
    let caps = caps(info, &server)?;
    let (inbox, inbox_rx) = mpsc::unbounded_channel();
    // The radio's power; without it, assume on (WinRT's own errors tell).
    let mut on = true;
    let mut power = None;
    match wait(&rt, "Radio", adapter.GetRadioAsync()) {
        Ok(radio) => {
            on = radio.State().ok().and_then(powered).unwrap_or(true);
            let tx = inbox.clone();
            let handler = TypedEventHandler::<OsRadio, IInspectable>::new(move |radio, _| {
                if let Some(on) = powered(radio.ok()?.State()?) {
                    let _ = tx.send(Msg::Power(on));
                }
                Ok(())
            });
            match radio.StateChanged(&handler) {
                Ok(token) => power = Some((radio, token)),
                Err(e) => eprintln!(
                    "raven-node nearby: WinRT radio state: HRESULT 0x{:08X}",
                    hresult(&e)
                ),
            }
        }
        Err(why) => eprintln!("raven-node nearby: WinRT radio state unknown: {why:?}"),
    }
    let shared = Arc::new(Shared {
        table: Mutex::new(Table::default()),
        overflows: AtomicU64::new(0),
    });
    let sys = Sys {
        inbox: inbox.clone(),
        shared: Arc::clone(&shared),
        providers: HashMap::new(),
        clients: HashMap::new(),
        gen: 0,
        watcher: None,
        pending: HashMap::new(),
        links: HashMap::new(),
        connects: HashMap::new(),
        writers: HashMap::new(),
    };
    let mut core = Core::new(sys, EventTx::new(tx), caps, on);
    core.start();
    rt.spawn(drive(core, inbox_rx, power));
    Ok(WinrtRadio {
        inbox,
        shared,
        caps,
        next: 1,
    })
}

// ── The radio handle ────────────────────────────────────────────────────────

/// What the radio handle and the driver share.
struct Shared {
    table: Mutex<Table<UnboundedSender<Vec<u8>>>>,
    /// Events the queue dropped (the driver copies the count here).
    overflows: AtomicU64,
}

/// The WinRT radio, as the engine holds it. Every call queues a command for
/// the driver and returns; a frame goes to its connection's writer task at
/// once.
pub(crate) struct WinrtRadio {
    inbox: UnboundedSender<Msg>,
    shared: Arc<Shared>,
    caps: RadioCaps,
    /// The next central connection's number (odd; the driver numbers
    /// peripheral ones even).
    next: ConnId,
}

impl WinrtRadio {
    fn push(&self, cmd: Cmd) -> Result<(), String> {
        self.inbox
            .send(Msg::Cmd(cmd))
            .map_err(|_| "the WinRT radio stopped".to_owned())
    }
}

impl Radio for WinrtRadio {
    fn caps(&self) -> RadioCaps {
        self.caps
    }

    fn set_services(
        &mut self,
        services: &[[u8; 16]],
        advertise: Option<[u8; 16]>,
    ) -> Result<(), String> {
        if !self.caps.peripheral && !services.is_empty() {
            return Err("this radio cannot be a peripheral".into());
        }
        if advertise.is_some_and(|t| !services.contains(&t)) {
            return Err("the advertised service is not published".into());
        }
        self.push(Cmd::Services(services.to_vec(), advertise))
    }

    fn set_scanning(&mut self, on: bool) -> Result<(), String> {
        if on && !self.caps.central {
            return Err("this radio cannot be a central".into());
        }
        self.push(Cmd::Scan(on))
    }

    fn connect(&mut self, addr: &RadioAddr, service: [u8; 16]) -> Result<ConnId, String> {
        if !self.caps.central {
            return Err("this radio cannot be a central".into());
        }
        let addr = Addr::parse(addr).ok_or("not a WinRT device address")?;
        let conn = self.next;
        self.next += 2;
        self.push(Cmd::Connect {
            conn,
            addr,
            service,
        })?;
        Ok(conn)
    }

    fn send(&mut self, conn: ConnId, frame: &[u8]) -> Result<Sent, String> {
        lock(&self.shared.table).send(conn, frame)
    }

    fn disconnect(&mut self, conn: ConnId) {
        let _ = self.push(Cmd::Disconnect(conn));
    }

    fn overflows(&self) -> u64 {
        self.shared.overflows.load(Ordering::Relaxed)
    }
}

impl Drop for WinrtRadio {
    /// The driver ends every connection, drops every WinRT object it holds
    /// and stops.
    fn drop(&mut self) {
        let _ = self.push(Cmd::Stop);
    }
}

// ── The driver ──────────────────────────────────────────────────────────────

async fn drive(
    mut core: Core<Sys>,
    mut inbox: UnboundedReceiver<Msg>,
    power: Option<(OsRadio, i64)>,
) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    while core.alive() {
        tokio::select! {
            msg = inbox.recv() => match msg {
                Some(msg) => handle(&mut core, msg, Instant::now()),
                None => break,
            },
            _ = tick.tick() => core.tick(Instant::now()),
        }
        core.os
            .shared
            .overflows
            .store(core.dropped(), Ordering::Relaxed);
    }
    if let Some((radio, token)) = power {
        let _ = radio.RemoveStateChanged(token);
    }
    // Dropping the core drops every WinRT object it holds, and the event
    // queue: the engine sees the radio end.
}

fn handle(core: &mut Core<Sys>, msg: Msg, now: Instant) {
    match msg {
        Msg::Cmd(cmd) => core.command(cmd, now),
        Msg::Power(on) => core.power(on, now),
        Msg::Created { t, made } => match made {
            Ok(served) if core.creating(&t) => {
                core.os.providers.insert(t, served);
                core.created(t, Ok(()), now);
            }
            // Turned down (withdrawn meanwhile): dropped here.
            Ok(_) => {}
            Err(why) => core.created(t, Err(why.to_string()), now),
        },
        Msg::Aborted { t, why } => core.aborted(t, why, now),
        Msg::Subscribers { t, list } => {
            if !core.serving(&t) {
                return;
            }
            core.os.clients.retain(|(s, _), _| *s != t);
            let mut subs = Vec::with_capacity(list.len());
            for (sub, client) in list {
                core.os.clients.insert((t, sub.device.clone()), client);
                subs.push(sub);
            }
            core.subscribers(t, subs, now);
        }
        Msg::Written { t, device, bytes } => core.written(t, device, bytes, now),
        Msg::Advert {
            addr,
            uuids,
            rssi,
            connectable,
        } => core.advert(addr, uuids, rssi, connectable, now),
        Msg::ScanStopped { gen, why } => {
            if gen == core.os.gen {
                core.os.watcher = None;
                core.scan_stopped(why, now);
            }
        }
        Msg::CentralUp { conn, link, max } => {
            if core.connecting(conn) {
                core.os.pending.insert(conn, link);
                core.central_up(conn, max, max, now);
            }
        }
        Msg::CentralFailed { conn, why } => core.central_failed(conn, &why, now),
        Msg::Frame { conn, bytes } => core.frame(conn, bytes, now),
        Msg::Lost { conn } => core.lost(conn, now),
        Msg::Sent { conn, ok } => {
            if !ok {
                core.lost(conn, now);
            } else if lock(&core.os.shared.table).sent(conn) {
                core.writable(conn, now);
            }
        }
    }
}

// ── WinRT, as Core asks for it ──────────────────────────────────────────────

/// The WinRT objects the driver keeps, and the tasks it started.
struct Sys {
    inbox: UnboundedSender<Msg>,
    shared: Arc<Shared>,
    providers: HashMap<[u8; 16], Served>,
    /// The centrals subscribed to each service, by device id.
    clients: HashMap<([u8; 16], String), GattSubscribedClient>,
    /// The watcher's generation: a stop of an older one is not news.
    gen: u64,
    watcher: Option<Watching>,
    /// A central link the driver handed over, until [`Core::central_up`]
    /// takes it.
    pending: HashMap<ConnId, Link>,
    links: HashMap<ConnId, Link>,
    connects: HashMap<ConnId, AbortHandle>,
    writers: HashMap<ConnId, AbortHandle>,
}

impl Sys {
    fn route(&mut self, conn: ConnId, max_tx: usize, writer: impl WriteOne) {
        let (tx, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(write_frames(conn, writer, rx, self.inbox.clone()));
        self.writers.insert(conn, task.abort_handle());
        lock(&self.shared.table).add(conn, tx, max_tx);
    }
}

impl Os for Sys {
    fn create(&mut self, t: [u8; 16]) {
        let inbox = self.inbox.clone();
        tokio::spawn(async move {
            let made = make_service(t, inbox.clone()).await;
            let _ = inbox.send(Msg::Created { t, made });
        });
    }

    fn advertise(&mut self, t: [u8; 16], on_air: bool) {
        let Some(served) = self.providers.get(&t) else {
            return;
        };
        if let Err(e) = served.advertise(on_air) {
            eprintln!(
                "raven-node nearby: WinRT advertising: HRESULT 0x{:08X}",
                hresult(&e)
            );
            let _ = self.inbox.send(Msg::Aborted {
                t,
                why: "StartAdvertising refused",
            });
        }
    }

    fn withdraw(&mut self, t: [u8; 16]) {
        self.providers.remove(&t);
        self.clients.retain(|(s, _), _| *s != t);
    }

    fn scan(&mut self, on: bool) {
        self.gen += 1;
        self.watcher = None;
        if on {
            match watch(self.gen, &self.inbox) {
                Ok(w) => self.watcher = Some(w),
                Err(e) => {
                    eprintln!(
                        "raven-node nearby: WinRT scan: HRESULT 0x{:08X}",
                        hresult(&e)
                    );
                    let _ = self.inbox.send(Msg::ScanStopped {
                        gen: self.gen,
                        why: "the watcher did not start",
                    });
                }
            }
        }
    }

    fn connect(&mut self, conn: ConnId, addr: Addr, t: [u8; 16]) {
        let inbox = self.inbox.clone();
        let task = tokio::spawn(async move {
            let msg = match tokio::time::timeout(CONNECT_BUDGET, open_link(conn, addr, t, &inbox))
                .await
            {
                Ok(Ok((link, max))) => Msg::CentralUp { conn, link, max },
                Ok(Err(why)) => Msg::CentralFailed {
                    conn,
                    why: why.to_string(),
                },
                Err(_) => Msg::CentralFailed {
                    conn,
                    why: "no link within the connect budget".into(),
                },
            };
            let _ = inbox.send(msg);
        });
        self.connects.insert(conn, task.abort_handle());
    }

    fn central_up(&mut self, conn: ConnId, max_tx: usize) {
        self.connects.remove(&conn);
        let Some(link) = self.pending.remove(&conn) else {
            return;
        };
        if let Some(chr) = link.chr.clone() {
            self.route(conn, max_tx, chr);
        }
        self.links.insert(conn, link);
    }

    fn peripheral_up(&mut self, conn: ConnId, t: [u8; 16], device: &str, max_tx: usize) {
        let (Some(served), Some(client)) = (
            self.providers.get(&t),
            self.clients.get(&(t, device.to_owned())),
        ) else {
            return;
        };
        let to = (served.chr.clone(), client.clone());
        self.route(conn, max_tx, to);
    }

    fn ended(&mut self, conn: ConnId) {
        lock(&self.shared.table).remove(conn);
        if let Some(task) = self.writers.remove(&conn) {
            task.abort();
        }
        if let Some(task) = self.connects.remove(&conn) {
            task.abort();
        }
        self.pending.remove(&conn);
        self.links.remove(&conn);
    }
}

// ── Sending ─────────────────────────────────────────────────────────────────

/// One frame out on a connection: a Write Command as the central, a
/// notification to that one central as the peripheral.
trait WriteOne: Send + 'static {
    fn write_one(&self, frame: &[u8]) -> impl std::future::Future<Output = bool> + Send;
}

impl WriteOne for GattCharacteristic {
    async fn write_one(&self, frame: &[u8]) -> bool {
        let op = to_buffer(frame).and_then(|buf| {
            self.WriteValueWithOptionAsync(&buf, GattWriteOption::WriteWithoutResponse)
        });
        match op {
            Ok(op) => op
                .await
                .is_ok_and(|s| s == GattCommunicationStatus::Success),
            Err(_) => false,
        }
    }
}

impl WriteOne for (GattLocalCharacteristic, GattSubscribedClient) {
    async fn write_one(&self, frame: &[u8]) -> bool {
        let (chr, client) = self;
        let op =
            to_buffer(frame).and_then(|buf| chr.NotifyValueForSubscribedClientAsync(&buf, client));
        match op {
            Ok(op) => op
                .await
                .and_then(|r| r.Status())
                .is_ok_and(|s| s == GattCommunicationStatus::Success),
            Err(_) => false,
        }
    }
}

/// A connection's writer task: its frames, one WinRT write at a time, in
/// order; the first failure ends the connection.
async fn write_frames(
    conn: ConnId,
    writer: impl WriteOne,
    mut frames: UnboundedReceiver<Vec<u8>>,
    inbox: UnboundedSender<Msg>,
) {
    while let Some(frame) = frames.recv().await {
        let ok = writer.write_one(&frame).await;
        let _ = inbox.send(Msg::Sent { conn, ok });
        if !ok {
            return;
        }
    }
}

// ── Peripheral ──────────────────────────────────────────────────────────────

/// One published service's WinRT objects. Dropping it stops the provider and
/// removes its handlers.
struct Served {
    provider: GattServiceProvider,
    chr: GattLocalCharacteristic,
    write_token: Option<i64>,
    subs_token: Option<i64>,
    status_token: Option<i64>,
    writes: Option<AbortHandle>,
}

impl Served {
    /// Start advertising (stopping first if it runs): connectable, and
    /// discoverable when `on_air`.
    fn advertise(&self, on_air: bool) -> WinResult<()> {
        let status = self.provider.AdvertisementStatus()?;
        if status == GattServiceProviderAdvertisementStatus::Started
            || status == GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData
        {
            self.provider.StopAdvertising()?;
        }
        let params = GattServiceProviderAdvertisingParameters::new()?;
        params.SetIsConnectable(true)?;
        params.SetIsDiscoverable(on_air)?;
        self.provider.StartAdvertisingWithParameters(&params)
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        if let Some(token) = self.write_token.take() {
            let _ = self.chr.RemoveWriteRequested(token);
        }
        if let Some(token) = self.subs_token.take() {
            let _ = self.chr.RemoveSubscribedClientsChanged(token);
        }
        if let Some(token) = self.status_token.take() {
            let _ = self.provider.RemoveAdvertisementStatusChanged(token);
        }
        let _ = self.provider.StopAdvertising();
        if let Some(task) = self.writes.take() {
            task.abort();
        }
    }
}

/// A central's write, as WriteRequested hands it over.
struct Write {
    device: String,
    request: BoxFuture<'static, WinResult<GattWriteRequest>>,
    deferral: Deferral,
}

/// Service `t`'s provider and characteristic (RNL1 §4), with its handlers.
async fn make_service(t: [u8; 16], inbox: UnboundedSender<Msg>) -> Result<Served, Fail> {
    let made = GattServiceProvider::CreateAsync(guid(&t))?.await?;
    bluetooth(made.Error()?, "GattServiceProvider")?;
    let provider = made.ServiceProvider()?;
    let op = {
        let params = GattLocalCharacteristicParameters::new()?;
        params.SetCharacteristicProperties(
            GattCharacteristicProperties::WriteWithoutResponse
                | GattCharacteristicProperties::Write
                | GattCharacteristicProperties::Notify,
        )?;
        params.SetWriteProtectionLevel(GattProtectionLevel::Plain)?;
        provider
            .Service()?
            .CreateCharacteristicAsync(guid(&char_uuid(&t)), &params)?
    };
    let made = op.await?;
    bluetooth(made.Error()?, "GattLocalCharacteristic")?;
    let chr = made.Characteristic()?;
    let (writes_tx, writes_rx) = mpsc::unbounded_channel();
    let writes = tokio::spawn(take_writes(t, writes_rx, inbox.clone()));
    let mut served = Served {
        provider,
        chr,
        write_token: None,
        subs_token: None,
        status_token: None,
        writes: Some(writes.abort_handle()),
    };
    // Writes go through one task per service, in the order WinRT raised
    // them.
    let on_write = TypedEventHandler::<GattLocalCharacteristic, GattWriteRequestedEventArgs>::new(
        move |_, args| {
            let args = args.ok()?;
            let device = args.Session()?.DeviceId()?.Id()?.to_string_lossy();
            let deferral = args.GetDeferral()?;
            let request = Box::pin(args.GetRequestAsync()?.into_future());
            let _ = writes_tx.send(Write {
                device,
                request,
                deferral,
            });
            Ok(())
        },
    );
    served.write_token = Some(served.chr.WriteRequested(&on_write)?);
    let tx = inbox.clone();
    let on_subscribers =
        TypedEventHandler::<GattLocalCharacteristic, IInspectable>::new(move |chr, _| {
            let list = subscribers_of(chr.ok()?)?;
            let _ = tx.send(Msg::Subscribers { t, list });
            Ok(())
        });
    served.subs_token = Some(served.chr.SubscribedClientsChanged(&on_subscribers)?);
    let on_status = TypedEventHandler::<
        GattServiceProvider,
        GattServiceProviderAdvertisementStatusChangedEventArgs,
    >::new(move |_, args| {
        let args = args.ok()?;
        if args.Status()? == GattServiceProviderAdvertisementStatus::Aborted {
            let why = bt_error_name(args.Error()?.0);
            let _ = inbox.send(Msg::Aborted { t, why });
        }
        Ok(())
    });
    served.status_token = Some(served.provider.AdvertisementStatusChanged(&on_status)?);
    Ok(served)
}

/// The centrals subscribed to `chr` now (at most [`MAX_SUBSCRIBERS`]).
fn subscribers_of(
    chr: &GattLocalCharacteristic,
) -> WinResult<Vec<(Subscriber, GattSubscribedClient)>> {
    let list = chr.SubscribedClients()?;
    let mut out = Vec::new();
    for i in 0..list.Size()?.min(MAX_SUBSCRIBERS) {
        let client = list.GetAt(i)?;
        let session = client.Session()?;
        let sub = Subscriber {
            device: session.DeviceId()?.Id()?.to_string_lossy(),
            max_tx: notify_limit(client.MaxNotificationSize()?),
            max_rx: frame_limit(session.MaxPduSize()?),
        };
        out.push((sub, client));
    }
    Ok(out)
}

/// A service's writes, in order: each answered (a Write Request) and its
/// deferral completed, then its bytes to the driver.
async fn take_writes(
    t: [u8; 16],
    mut writes: UnboundedReceiver<Write>,
    inbox: UnboundedSender<Msg>,
) {
    while let Some(w) = writes.recv().await {
        let got = take_write(w.request).await;
        let _ = w.deferral.Complete();
        if let Ok(Some(bytes)) = got {
            let _ = inbox.send(Msg::Written {
                t,
                device: w.device,
                bytes,
            });
        }
    }
}

async fn take_write(
    request: BoxFuture<'static, WinResult<GattWriteRequest>>,
) -> WinResult<Option<Vec<u8>>> {
    let req = request.await?;
    let respond = req.Option()? == GattWriteOption::WriteWithResponse;
    if req.Offset()? != 0 {
        // One frame is one whole ATT value (RNL1 §4): no long writes.
        if respond {
            req.RespondWithProtocolError(ATT_INVALID_OFFSET)?;
        }
        return Ok(None);
    }
    let bytes = buffer_bytes(&req.Value()?)?;
    if respond {
        req.Respond()?;
    }
    Ok(Some(bytes))
}

// ── Central ─────────────────────────────────────────────────────────────────

/// The passive watcher. Dropping it stops it and removes its handlers.
struct Watching {
    watcher: BluetoothLEAdvertisementWatcher,
    received: Option<i64>,
    stopped: Option<i64>,
}

impl Drop for Watching {
    fn drop(&mut self) {
        let _ = self.watcher.Stop();
        if let Some(token) = self.received.take() {
            let _ = self.watcher.RemoveReceived(token);
        }
        if let Some(token) = self.stopped.take() {
            let _ = self.watcher.RemoveStopped(token);
        }
    }
}

fn addr_kind(kind: WinResult<BluetoothAddressType>) -> AddrKind {
    match kind {
        Ok(k) if k == BluetoothAddressType::Public => AddrKind::Public,
        Ok(k) if k == BluetoothAddressType::Random => AddrKind::Random,
        _ => AddrKind::Unspecified,
    }
}

/// A new passive watcher (generation `gen`), started.
fn watch(gen: u64, inbox: &UnboundedSender<Msg>) -> WinResult<Watching> {
    let mut w = Watching {
        watcher: BluetoothLEAdvertisementWatcher::new()?,
        received: None,
        stopped: None,
    };
    w.watcher
        .SetScanningMode(BluetoothLEScanningMode::Passive)?;
    let tx = inbox.clone();
    let on_advert = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementReceivedEventArgs,
    >::new(move |_, args| {
        let args = args.ok()?;
        let list = args.Advertisement()?.ServiceUuids()?;
        let mut uuids = Vec::new();
        for i in 0..list.Size()?.min(ADVERT_UUIDS_READ) {
            uuids.push(uuid_of(list.GetAt(i)?.to_u128()));
        }
        // Most adverts name no candidate token: not worth a message.
        let uuids = candidates(uuids);
        if uuids.is_empty() {
            return Ok(());
        }
        let _ = tx.send(Msg::Advert {
            addr: Addr::new(
                args.BluetoothAddress()?,
                addr_kind(args.BluetoothAddressType()),
            ),
            uuids,
            rssi: args.RawSignalStrengthInDBm()?,
            connectable: args.IsConnectable().unwrap_or(true),
        });
        Ok(())
    });
    w.received = Some(w.watcher.Received(&on_advert)?);
    let tx = inbox.clone();
    let on_stop = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementWatcherStoppedEventArgs,
    >::new(move |_, args| {
        let why = args
            .ok()
            .and_then(|a| a.Error())
            .map_or("stopped", |e| bt_error_name(e.0));
        let _ = tx.send(Msg::ScanStopped { gen, why });
        Ok(())
    });
    w.stopped = Some(w.watcher.Stopped(&on_stop)?);
    w.watcher.Start()?;
    Ok(w)
}

/// A central connection's WinRT objects. Dropping it removes its handlers,
/// lets go of the link and closes the device.
struct Link {
    device: BluetoothLEDevice,
    session: Option<GattSession>,
    service: Option<GattDeviceService>,
    chr: Option<GattCharacteristic>,
    value_token: Option<i64>,
    status_token: Option<i64>,
}

impl Drop for Link {
    fn drop(&mut self) {
        if let (Some(chr), Some(token)) = (&self.chr, self.value_token.take()) {
            let _ = chr.RemoveValueChanged(token);
        }
        if let Some(token) = self.status_token.take() {
            let _ = self.device.RemoveConnectionStatusChanged(token);
        }
        if let Some(session) = &self.session {
            let _ = session.SetMaintainConnection(false);
            let _ = session.Close();
        }
        if let Some(service) = &self.service {
            let _ = service.Close();
        }
        let _ = self.device.Close();
    }
}

/// Connect to `addr`, find service `t` and its characteristic (uncached) and
/// subscribe: the link and its `min(ATT_MTU - 3, 512)`.
async fn open_link(
    conn: ConnId,
    addr: Addr,
    t: [u8; 16],
    inbox: &UnboundedSender<Msg>,
) -> Result<(Link, usize), Fail> {
    let device = match addr.kind {
        AddrKind::Public => BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(
            addr.raw,
            BluetoothAddressType::Public,
        )?,
        AddrKind::Random => BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(
            addr.raw,
            BluetoothAddressType::Random,
        )?,
        AddrKind::Unspecified => BluetoothLEDevice::FromBluetoothAddressAsync(addr.raw)?,
    }
    .await?;
    let mut link = Link {
        device,
        session: None,
        service: None,
        chr: None,
        value_token: None,
        status_token: None,
    };
    let op = GattSession::FromDeviceIdAsync(&link.device.BluetoothDeviceId()?)?;
    let session = op.await?;
    session.SetMaintainConnection(true)?;
    link.session = Some(session);

    let op = link
        .device
        .GetGattServicesForUuidWithCacheModeAsync(guid(&t), BluetoothCacheMode::Uncached)?;
    let found = op.await?;
    communication(found.Status()?, "service")?;
    let service = {
        let list = found.Services()?;
        if list.Size()? == 0 {
            return Err(Fail::Status("service", "not found"));
        }
        list.GetAt(0)?
    };
    link.service = Some(service.clone());

    let op = service.GetCharacteristicsForUuidWithCacheModeAsync(
        guid(&char_uuid(&t)),
        BluetoothCacheMode::Uncached,
    )?;
    let found = op.await?;
    communication(found.Status()?, "characteristic")?;
    let chr = {
        let list = found.Characteristics()?;
        if list.Size()? == 0 {
            return Err(Fail::Status("characteristic", "not found"));
        }
        list.GetAt(0)?
    };
    link.chr = Some(chr.clone());
    let tx = inbox.clone();
    // The handler is not Send: registered and dropped before the next await.
    link.value_token = Some({
        let on_value = TypedEventHandler::<GattCharacteristic, GattValueChangedEventArgs>::new(
            move |_, args| {
                let bytes = buffer_bytes(&args.ok()?.CharacteristicValue()?)?;
                let _ = tx.send(Msg::Frame { conn, bytes });
                Ok(())
            },
        );
        chr.ValueChanged(&on_value)?
    });
    let op = chr.WriteClientCharacteristicConfigurationDescriptorAsync(
        GattClientCharacteristicConfigurationDescriptorValue::Notify,
    )?;
    communication(op.await?, "subscribe")?;

    let tx = inbox.clone();
    let on_status = TypedEventHandler::<BluetoothLEDevice, IInspectable>::new(move |device, _| {
        if device.ok()?.ConnectionStatus()? == BluetoothConnectionStatus::Disconnected {
            let _ = tx.send(Msg::Lost { conn });
        }
        Ok(())
    });
    link.status_token = Some(link.device.ConnectionStatusChanged(&on_status)?);
    if link.device.ConnectionStatus()? == BluetoothConnectionStatus::Disconnected {
        return Err(Fail::Status("link", "disconnected"));
    }
    let mtu = match &link.session {
        Some(session) => session.MaxPduSize()?,
        None => 0,
    };
    Ok((link, frame_limit(mtu)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::nearby_link::uuid_string;

    /// RNL1 §4 frames through WinRT buffers and back, every size a frame
    /// can have (the conversion each send and receive makes).
    #[test]
    fn buffers_round_trip() {
        for len in [0usize, 1, 2, 20, 64, 244, 512] {
            let frame: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let buf = to_buffer(&frame).unwrap();
            assert_eq!(buf.Length().unwrap() as usize, len);
            assert_eq!(buffer_bytes(&buf).unwrap(), frame, "{len}");
        }
    }

    /// WinRT's GUID for each vector token reads as RNL1's text form and
    /// gives the token back.
    #[test]
    fn guids_match_the_vectors_in_winrt() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/nearby/rnb1_tokens_001.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for tok in v["expected"]["tokens"].as_array().unwrap() {
            let t: [u8; 16] = hex::decode(tok["token_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let want =
                u128::from_str_radix(tok["windows_guid_u128_hex"].as_str().unwrap(), 16).unwrap();
            let g = guid(&t);
            assert_eq!(g.to_u128(), want);
            assert_eq!(uuid_of(g.to_u128()), t);
            assert_eq!(format!("{g:?}").to_lowercase(), uuid_string(&t));
            assert_eq!(
                format!("{:?}", guid(&char_uuid(&t))).to_lowercase(),
                tok["char_uuid_string"].as_str().unwrap()
            );
        }
    }

    /// The names logged for WinRT's BluetoothError are its own.
    #[test]
    fn bluetooth_error_names_match_winrt() {
        for (e, name) in [
            (BluetoothError::Success, "Success"),
            (BluetoothError::RadioNotAvailable, "RadioNotAvailable"),
            (BluetoothError::ResourceInUse, "ResourceInUse"),
            (BluetoothError::DeviceNotConnected, "DeviceNotConnected"),
            (BluetoothError::OtherError, "OtherError"),
            (BluetoothError::DisabledByPolicy, "DisabledByPolicy"),
            (BluetoothError::NotSupported, "NotSupported"),
            (BluetoothError::DisabledByUser, "DisabledByUser"),
            (BluetoothError::ConsentRequired, "ConsentRequired"),
            (
                BluetoothError::TransportNotSupported,
                "TransportNotSupported",
            ),
        ] {
            assert_eq!(bt_error_name(e.0), name);
        }
        assert_eq!(
            addr_kind(Ok(BluetoothAddressType::Random)),
            AddrKind::Random
        );
        assert_eq!(
            addr_kind(Ok(BluetoothAddressType::Public)),
            AddrKind::Public
        );
        assert_eq!(
            addr_kind(Ok(BluetoothAddressType::Unspecified)),
            AddrKind::Unspecified
        );
        assert_eq!(powered(OsRadioState::On), Some(true));
        assert_eq!(powered(OsRadioState::Disabled), Some(false));
        assert_eq!(powered(OsRadioState::Unknown), None);
    }
}
