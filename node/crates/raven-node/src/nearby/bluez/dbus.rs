//! The D-Bus side of the BlueZ backend (glibc Linux, feature
//! `nearby-radio`): [`open`] reads the adapter and starts the `raven-bluez`
//! thread, which turns zbus 1.9.3 messages into [`Core`] inputs and
//! [`Core`]'s calls into messages; the acquired sockets move on tokio's
//! `AsyncFd`. See [`super`] for the design.

use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use raven_core::nearby_link::MAX_FRAME;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use zbus::{Connection, Message, MessageHeader, MessageType};
use zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use super::super::bluez_mgmt;
use super::super::lock;
use super::super::radio::{
    ConnId, EventTx, Privacy, Radio, RadioAddr, RadioCaps, RadioEvent, RadioState, Sent,
    BLUEZ_NOT_RUNNING, NO_SYSTEM_BUS,
};
use super::{
    is_device_of, uuid_parse, Answer, Args, Bus, Call, Cmd, Core, DeviceProps, Expect, Incoming,
    Objects, Prop, Props, Remote, Reply, Route, Signal, Start, Table, ADAPTER, ADVERTISEMENT,
    ADV_MANAGER, BLUEZ, BUS_DAEMON, DEVICE, GATT_CHAR, GATT_MANAGER, GATT_SERVICE, OBJECT_MANAGER,
    PROPERTIES,
};

/// The thread's tick when nothing happens (deadlines, retries, owed events).
const TICK: Duration = Duration::from_millis(250);
/// How long the stopping thread tries to flush its last calls.
const LAST_FLUSH: Duration = Duration::from_millis(200);
/// BlueZ's signals this process acts on (D-Bus match rules).
const MATCH_RULES: [&str; 3] = [
    "type='signal',sender='org.bluez',interface='org.freedesktop.DBus.ObjectManager'",
    "type='signal',sender='org.bluez',interface='org.freedesktop.DBus.Properties',\
     member='PropertiesChanged',path_namespace='/org/bluez'",
    "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',\
     member='NameOwnerChanged',arg0='org.bluez'",
];
/// A remote object's interfaces and properties, as BlueZ's
/// GetManagedObjects and InterfacesAdded carry them.
type Ifaces = HashMap<String, HashMap<String, OwnedValue>>;
type ManagedObjects = HashMap<OwnedObjectPath, Ifaces>;

fn unsupported(why: impl Into<String>) -> RadioState {
    RadioState::Unsupported(why.into())
}

/// A D-Bus error's name (never its text, which may name a device).
fn error_name(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, _, _) => name.clone(),
        other => other.to_string(),
    }
}

/// What a refused setup call means for the radio.
fn refused(what: &str, e: &zbus::Error) -> RadioState {
    let name = error_name(e);
    match name.as_str() {
        "org.freedesktop.DBus.Error.AccessDenied" => RadioState::Unauthorized(format!(
            "the system bus refused {what} to this user ({name}): check the org.bluez D-Bus policy"
        )),
        "org.freedesktop.DBus.Error.NameHasNoOwner"
        | "org.freedesktop.DBus.Error.ServiceUnknown" => unsupported(BLUEZ_NOT_RUNNING),
        _ => unsupported(format!("BlueZ {what}: {name}")),
    }
}

// ── Opening the radio ───────────────────────────────────────────────────────

/// The adapter [`open`] picked.
struct Picked {
    path: String,
    powered: bool,
    central: bool,
    peripheral: bool,
}

/// The BlueZ radio on `adapter` (`hci0`, ...; `None`: the first adapter BlueZ
/// lists). Blocks briefly on the system bus: call it on the blocking pool,
/// inside the runtime.
pub(crate) fn open(
    adapter: Option<&str>,
    tx: mpsc::Sender<RadioEvent>,
) -> Result<BluezRadio, RadioState> {
    let rt = tokio::runtime::Handle::try_current().map_err(|_| unsupported("no tokio runtime"))?;
    // No queue: zbus would keep (and later hand out last first) what it read
    // during the blocking calls below, all of it older than the tree they
    // read.
    let conn = Connection::new_system()
        .map_err(|e| unsupported(format!("{NO_SYSTEM_BUS} ({e})")))?
        .set_max_queued(0);
    let owner: String = conn
        .call_method(
            Some(BUS_DAEMON),
            "/org/freedesktop/DBus",
            Some(BUS_DAEMON),
            "GetNameOwner",
            &BLUEZ,
        )
        .and_then(|m| m.body::<String>().map_err(zbus::Error::from))
        .map_err(|e| refused("GetNameOwner", &e))?;
    // Match first, then read the tree, so no change falls in between.
    for rule in MATCH_RULES {
        conn.call_method(
            Some(BUS_DAEMON),
            "/org/freedesktop/DBus",
            Some(BUS_DAEMON),
            "AddMatch",
            &rule,
        )
        .map_err(|e| refused("AddMatch", &e))?;
    }
    let objects: ManagedObjects = conn
        .call_method(
            Some(BLUEZ),
            "/",
            Some(OBJECT_MANAGER),
            "GetManagedObjects",
            &(),
        )
        .and_then(|m| m.body::<ManagedObjects>().map_err(zbus::Error::from))
        .map_err(|e| refused("GetManagedObjects", &e))?;
    let picked = pick_adapter(&objects, adapter)?;
    let info = bluez_mgmt::adapter_index(&picked.path).and_then(bluez_mgmt::read_info);
    if info.is_some_and(|i| !i.le()) {
        return Err(unsupported("the Bluetooth adapter has no Bluetooth LE"));
    }
    let caps = RadioCaps {
        central: picked.central,
        peripheral: picked.peripheral,
        l2cap: false,
        // Unknown counts as public (O5-12).
        address_privacy: if info.is_some_and(|i| i.privacy()) {
            Privacy::Random
        } else {
            Privacy::Public
        },
        // BlueZ notifies every subscriber (see the module doc).
        per_central_notify: false,
    };
    let devices: Vec<(String, DeviceProps)> = objects
        .iter()
        .filter(|(path, _)| is_device_of(&picked.path, path.as_str()))
        .filter_map(|(path, ifaces)| {
            ifaces
                .get(DEVICE)
                .map(|p| (path.as_str().to_owned(), device_props(p)))
        })
        .collect();
    let (wake_rx, wake_tx) =
        UnixDatagram::pair().map_err(|e| unsupported(format!("wake socket: {e}")))?;
    for s in [&wake_rx, &wake_tx] {
        s.set_nonblocking(true)
            .map_err(|e| unsupported(format!("wake socket: {e}")))?;
    }
    // The thread polls the bus socket itself (see the module doc).
    set_nonblocking(conn.as_raw_fd()).map_err(|e| unsupported(format!("system bus: {e}")))?;
    let shared = Arc::new(Shared {
        inbox: Mutex::new(Inbox::default()),
        wake: wake_tx,
        table: Mutex::new(Table::default()),
        overflows: AtomicU64::new(0),
    });
    let events = EventTx::new(tx);
    let bus = DbusBus {
        me: conn.unique_name().map(str::to_owned),
        conn: conn.clone(),
        shared: Arc::clone(&shared),
        events: events.clone(),
        rt,
        unread: HashMap::new(),
        io: HashMap::new(),
    };
    let start = Start {
        adapter: picked.path,
        bluez: owner,
        caps,
        powered: picked.powered,
        devices,
    };
    let core = Core::new(bus, events, start, Instant::now());
    let thread_shared = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("raven-bluez".to_owned())
        .spawn(move || run(core, &conn, &wake_rx, &thread_shared))
        .map_err(|e| unsupported(format!("raven-bluez thread: {e}")))?;
    Ok(BluezRadio {
        shared,
        caps,
        next: 1,
    })
}

/// The adapter to use: `want` (`hci0`, ...), or the first BlueZ lists.
fn pick_adapter(objects: &ManagedObjects, want: Option<&str>) -> Result<Picked, RadioState> {
    let mut adapters: Vec<(&str, &Ifaces)> = objects
        .iter()
        .filter(|(path, ifaces)| {
            path.as_str().starts_with("/org/bluez/") && ifaces.contains_key(ADAPTER)
        })
        .map(|(path, ifaces)| (path.as_str(), ifaces))
        .collect();
    adapters.sort_by_key(|(path, _)| *path);
    let (path, ifaces) = match want {
        Some(name) => adapters
            .into_iter()
            .find(|(path, _)| path.rsplit('/').next() == Some(name)),
        None => adapters.into_iter().next(),
    }
    .ok_or_else(|| unsupported("no Bluetooth adapter"))?;
    let props = ifaces.get(ADAPTER).cloned().unwrap_or_default();
    let roles = prop_strs(&props, "Roles");
    let has_role = |role: &str| roles.as_ref().is_none_or(|r| r.iter().any(|x| x == role));
    Ok(Picked {
        path: path.to_owned(),
        powered: prop_bool(&props, "Powered").unwrap_or(false),
        central: has_role("central"),
        peripheral: has_role("peripheral")
            && ifaces.contains_key(GATT_MANAGER)
            && ifaces.contains_key(ADV_MANAGER),
    })
}

// ── The radio handle ────────────────────────────────────────────────────────

/// What the radio handle, the thread and the I/O tasks share.
struct Shared {
    inbox: Mutex<Inbox>,
    /// The wake socket's sending end; the thread polls the other.
    wake: UnixDatagram,
    table: Mutex<Table<Writer>>,
    /// Events the queue dropped (the thread copies the count here).
    overflows: AtomicU64,
}

#[derive(Default)]
struct Inbox {
    cmds: VecDeque<Cmd>,
    /// A wake is on its way: the thread has not taken the commands yet.
    woken: bool,
}

impl Shared {
    /// Queue `cmd` and wake the thread (once until it takes the queue).
    fn push(&self, cmd: Cmd) {
        let wake = {
            let mut inbox = lock(&self.inbox);
            inbox.cmds.push_back(cmd);
            !std::mem::replace(&mut inbox.woken, true)
        };
        if wake {
            let _ = self.wake.send(&[1]);
        }
    }

    fn take(&self) -> VecDeque<Cmd> {
        let mut inbox = lock(&self.inbox);
        inbox.woken = false;
        std::mem::take(&mut inbox.cmds)
    }
}

/// The BlueZ radio, as the engine holds it. Every call queues a command for
/// the `raven-bluez` thread and returns; a central connection's frames are
/// written to its socket here at once.
pub(crate) struct BluezRadio {
    shared: Arc<Shared>,
    caps: RadioCaps,
    /// The next central connection's number (odd; the thread numbers
    /// peripheral ones even).
    next: ConnId,
}

impl Radio for BluezRadio {
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
        self.shared
            .push(Cmd::Services(services.to_vec(), advertise));
        Ok(())
    }

    fn set_scanning(&mut self, on: bool) -> Result<(), String> {
        if on && !self.caps.central {
            return Err("this radio cannot be a central".into());
        }
        self.shared.push(Cmd::Scan(on));
        Ok(())
    }

    fn connect(&mut self, addr: &RadioAddr, service: [u8; 16]) -> Result<ConnId, String> {
        if !self.caps.central {
            return Err("this radio cannot be a central".into());
        }
        let conn = self.next;
        self.next += 2;
        self.shared.push(Cmd::Connect {
            conn,
            device: addr.0.clone(),
            service,
        });
        Ok(conn)
    }

    fn send(&mut self, conn: ConnId, frame: &[u8]) -> Result<Sent, String> {
        let route = lock(&self.shared.table).route(conn, frame.len())?;
        match route {
            Route::Write(writer) => writer.send(frame),
            Route::Notify => {
                self.shared.push(Cmd::Notify {
                    conn,
                    frame: frame.to_vec(),
                });
                Ok(Sent::Queued)
            }
            Route::Full => Ok(Sent::WouldBlock),
        }
    }

    fn disconnect(&mut self, conn: ConnId) {
        self.shared.push(Cmd::Disconnect(conn));
    }

    fn overflows(&self) -> u64 {
        self.shared.overflows.load(Ordering::Relaxed)
    }
}

impl Drop for BluezRadio {
    /// The thread ends every connection, drops the links it made and stops;
    /// BlueZ withdraws this process's applications, advert and discovery
    /// when its bus connection closes.
    fn drop(&mut self) {
        self.shared.push(Cmd::Stop);
    }
}

// ── A central connection's sockets ──────────────────────────────────────────

/// A central connection's write socket (AcquireWrite: one Write Command per
/// packet).
struct Writer {
    fd: AsyncFd<OwnedFd>,
    /// A send found the socket full: one `Writable` is owed.
    want: AtomicBool,
    room: Notify,
}

impl Writer {
    fn send(&self, frame: &[u8]) -> Result<Sent, String> {
        match send_packet(self.fd.get_ref().as_raw_fd(), frame) {
            Ok(_) => Ok(Sent::Queued),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.want.store(true, Ordering::Release);
                self.room.notify_one();
                Ok(Sent::WouldBlock)
            }
            Err(e) => Err(format!("nearby socket: {e}")),
        }
    }

    /// Until the socket has room after a full one.
    async fn room(&self) -> io::Result<()> {
        loop {
            if !self.want.load(Ordering::Acquire) {
                self.room.notified().await;
                continue;
            }
            let mut guard = self.fd.writable().await?;
            if poll_one(self.fd.get_ref().as_raw_fd(), libc::POLLOUT, 0) & libc::POLLOUT != 0 {
                return Ok(());
            }
            guard.clear_ready();
        }
    }
}

/// A central connection's I/O: each packet on the notify socket is a frame;
/// room again on a full write socket is a `Writable`. Ends (and tells the
/// thread) when a socket closes or fails, or the event queue lost one of
/// its events; the thread aborts it when the connection ends.
async fn central_io(
    conn: ConnId,
    reader: AsyncFd<OwnedFd>,
    writer: Arc<Writer>,
    events: EventTx,
    shared: Arc<Shared>,
) {
    // A packet longer than a frame shows as MAX_FRAME + 1 bytes (a
    // SOCK_SEQPACKET read truncates it), which the pipe refuses.
    let mut buf = vec![0u8; MAX_FRAME + 1];
    loop {
        tokio::select! {
            ready = reader.readable() => {
                let Ok(mut guard) = ready else { break };
                match guard.try_io(|fd| recv_packet(fd.as_raw_fd(), &mut buf)) {
                    Ok(Ok(n)) if n > 0 => {
                        let bytes = buf[..n.min(buf.len())].to_vec();
                        if events.emit(RadioEvent::Frame { conn, bytes }).is_err() {
                            break;
                        }
                    }
                    // Closed (BlueZ ended the link) or failed.
                    Ok(_) => break,
                    Err(_would_block) => {}
                }
            }
            room = writer.room() => {
                if room.is_err() {
                    break;
                }
                if writer.want.swap(false, Ordering::AcqRel)
                    && events.emit(RadioEvent::Writable { conn }).is_err()
                {
                    break;
                }
            }
        }
    }
    shared.push(Cmd::Down(conn));
}

fn send_packet(fd: RawFd, frame: &[u8]) -> io::Result<usize> {
    // SAFETY: send(2) of `frame`'s bytes on a socket this process owns.
    let n = unsafe {
        libc::send(
            fd,
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

fn recv_packet(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: recv(2) into `buf`, at most its length.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl(2) F_GETFL/F_SETFL on a descriptor this process owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Our own copy of a socket a reply carried (the message closes its own).
fn own_fd(fd: RawFd) -> Option<OwnedFd> {
    // SAFETY: fcntl(2) F_DUPFD_CLOEXEC on a descriptor the reply owns.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return None;
    }
    // SAFETY: `dup` is a new descriptor that nothing else owns.
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    set_nonblocking(owned.as_raw_fd()).ok()?;
    Some(owned)
}

/// poll(2) on one descriptor; its `revents` (0 on timeout or error).
fn poll_one(fd: RawFd, events: libc::c_short, timeout_ms: libc::c_int) -> libc::c_short {
    let mut p = [libc::pollfd {
        fd,
        events,
        revents: 0,
    }];
    // SAFETY: poll(2) on a one-element array that lives across the call.
    let n = unsafe { libc::poll(p.as_mut_ptr(), 1, timeout_ms) };
    if n > 0 {
        p[0].revents
    } else {
        0
    }
}

// ── The bus side of Core ────────────────────────────────────────────────────

struct DbusBus {
    conn: Connection,
    /// This connection's unique name (the sender of what it sends).
    me: Option<String>,
    shared: Arc<Shared>,
    events: EventTx,
    rt: tokio::runtime::Handle,
    /// Central connections up but not read yet (their Connected is on its
    /// way).
    unread: HashMap<ConnId, (AsyncFd<OwnedFd>, Arc<Writer>)>,
    /// Central connections' I/O tasks.
    io: HashMap<ConnId, JoinHandle<()>>,
}

impl Bus for DbusBus {
    type Fd = OwnedFd;

    fn call(&mut self, call: Call) -> Result<u32, String> {
        let msg = call_message(self.me.as_deref(), &call).map_err(|e| e.to_string())?;
        self.conn.send_message(msg).map_err(|e| error_name(&e))
    }

    fn notify(&mut self, conn: ConnId, chr: &str, value: &[u8]) {
        let changed = HashMap::from([("Value", Value::from(value.to_vec()))]);
        let body = (GATT_CHAR, changed, Vec::<&str>::new());
        // Broadcast: BlueZ watches its applications' PropertiesChanged.
        let _ = self
            .conn
            .emit_signal(None, chr, PROPERTIES, "PropertiesChanged", &body);
        if lock(&self.shared.table).notified(conn)
            && self.events.emit(RadioEvent::Writable { conn }).is_err()
        {
            self.shared.push(Cmd::Down(conn));
        }
    }

    fn central_up(
        &mut self,
        conn: ConnId,
        notify: OwnedFd,
        write: OwnedFd,
        max_tx: usize,
        _max_rx: usize,
    ) {
        let _rt = self.rt.enter();
        let (Ok(reader), Ok(fd)) = (
            AsyncFd::with_interest(notify, Interest::READABLE),
            AsyncFd::with_interest(write, Interest::WRITABLE),
        ) else {
            self.shared.push(Cmd::Down(conn));
            return;
        };
        let writer = Arc::new(Writer {
            fd,
            want: AtomicBool::new(false),
            room: Notify::new(),
        });
        lock(&self.shared.table).central(conn, Arc::clone(&writer), max_tx);
        self.unread.insert(conn, (reader, writer));
    }

    fn start_reading(&mut self, conn: ConnId) {
        let Some((reader, writer)) = self.unread.remove(&conn) else {
            return;
        };
        let task = self.rt.spawn(central_io(
            conn,
            reader,
            writer,
            self.events.clone(),
            Arc::clone(&self.shared),
        ));
        self.io.insert(conn, task);
    }

    fn peripheral_up(&mut self, conn: ConnId, max_tx: usize) {
        lock(&self.shared.table).peripheral(conn, max_tx);
    }

    fn ended(&mut self, conn: ConnId) {
        lock(&self.shared.table).remove(conn);
        self.unread.remove(&conn);
        if let Some(task) = self.io.remove(&conn) {
            // Its sockets close with it.
            task.abort();
        }
    }
}

// ── Messages ────────────────────────────────────────────────────────────────

/// A call to BlueZ as a message.
fn call_message(me: Option<&str>, call: &Call) -> zbus::Result<Message> {
    let (path, iface, member) = (call.path.as_str(), Some(call.iface), call.member);
    let none: HashMap<&str, Value<'_>> = HashMap::new();
    Ok(match &call.args {
        Args::None => Message::method(me, Some(BLUEZ), path, iface, member, &())?,
        Args::Options => Message::method(me, Some(BLUEZ), path, iface, member, &none)?,
        Args::Register(obj) => {
            let obj = ObjectPath::try_from(obj.as_str())?;
            Message::method(me, Some(BLUEZ), path, iface, member, &(obj, &none))?
        }
        Args::Unregister(obj) => {
            let obj = ObjectPath::try_from(obj.as_str())?;
            Message::method(me, Some(BLUEZ), path, iface, member, &obj)?
        }
        Args::LeFilter => {
            let filter = HashMap::from([
                ("Transport", Value::from("le")),
                ("DuplicateData", Value::from(true)),
            ]);
            Message::method(me, Some(BLUEZ), path, iface, member, &filter)?
        }
    })
}

fn prop_value(p: &Prop) -> Value<'static> {
    match p {
        Prop::Str(s) => Value::from(s.clone()),
        Prop::Bool(b) => Value::from(*b),
        Prop::Path(s) => ObjectPath::try_from(s.clone())
            .map(Value::ObjectPath)
            .unwrap_or_else(|_| Value::from(String::new())),
        Prop::Strs(v) => Value::from(v.clone()),
    }
}

fn props_value(props: &Props) -> HashMap<&'static str, Value<'static>> {
    props.iter().map(|(k, v)| (*k, prop_value(v))).collect()
}

fn objects_value(
    objects: &Objects,
) -> HashMap<ObjectPath<'static>, HashMap<&'static str, HashMap<&'static str, Value<'static>>>> {
    objects
        .iter()
        .filter_map(|(path, ifaces)| {
            let path = ObjectPath::try_from(path.clone()).ok()?;
            let ifaces = ifaces.iter().map(|(i, p)| (*i, props_value(p))).collect();
            Some((path, ifaces))
        })
        .collect()
}

/// Answer `call` (a method call BlueZ made) with `answer`.
fn answer_call(conn: &Connection, call: &Message, answer: Answer) {
    let me = conn.unique_name();
    let reply = match answer {
        Answer::Objects(objects) => Message::method_reply(me, call, &objects_value(&objects)),
        Answer::Props(props) => Message::method_reply(me, call, &props_value(&props)),
        Answer::Prop(prop) => Message::method_reply(me, call, &prop_value(&prop)),
        Answer::Unit => Message::method_reply(me, call, &()),
        Answer::Error(name) => Message::method_error(me, call, name, &name),
    };
    if let Ok(reply) = reply {
        let _ = conn.send_message(reply);
    }
}

fn prop<T: TryFrom<OwnedValue>>(p: &HashMap<String, OwnedValue>, key: &str) -> Option<T> {
    p.get(key).cloned().and_then(|v| T::try_from(v).ok())
}

fn prop_bool(p: &HashMap<String, OwnedValue>, key: &str) -> Option<bool> {
    prop(p, key)
}

fn prop_strs(p: &HashMap<String, OwnedValue>, key: &str) -> Option<Vec<String>> {
    prop(p, key)
}

fn prop_path(p: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    prop::<OwnedObjectPath>(p, key).map(|o| o.as_str().to_owned())
}

fn prop_uuid(p: &HashMap<String, OwnedValue>, key: &str) -> Option<[u8; 16]> {
    prop::<String>(p, key).and_then(|s| uuid_parse(&s))
}

fn device_props(p: &HashMap<String, OwnedValue>) -> DeviceProps {
    DeviceProps {
        uuids: prop_strs(p, "UUIDs").map(|v| v.iter().filter_map(|s| uuid_parse(s)).collect()),
        rssi: prop(p, "RSSI"),
        connected: prop_bool(p, "Connected"),
        resolved: prop_bool(p, "ServicesResolved"),
    }
}

/// The remote GATT services and characteristics in BlueZ's
/// GetManagedObjects.
fn remotes(objects: &ManagedObjects) -> Vec<Remote> {
    let mut out = Vec::new();
    for (path, ifaces) in objects {
        let path = path.as_str();
        if let Some(p) = ifaces.get(GATT_SERVICE) {
            if let (Some(uuid), Some(device)) = (prop_uuid(p, "UUID"), prop_path(p, "Device")) {
                out.push(Remote::Service {
                    path: path.to_owned(),
                    uuid,
                    device,
                });
            }
        }
        if let Some(p) = ifaces.get(GATT_CHAR) {
            if let (Some(uuid), Some(service)) = (prop_uuid(p, "UUID"), prop_path(p, "Service")) {
                out.push(Remote::Char {
                    path: path.to_owned(),
                    uuid,
                    service,
                });
            }
        }
    }
    out
}

fn decode_reply(msg: &Message, expect: Expect) -> Reply<OwnedFd> {
    let bad = || Reply::Failed("a reply of the wrong form".to_owned());
    match expect {
        Expect::Nothing => Reply::Done,
        Expect::Objects => match msg.body::<ManagedObjects>() {
            Ok(objects) => Reply::Objects(remotes(&objects)),
            Err(_) => bad(),
        },
        Expect::Socket => match msg.body::<(zvariant::Fd, u16)>() {
            Ok((fd, mtu)) => match own_fd(fd.as_raw_fd()) {
                Some(fd) => Reply::Socket { fd, mtu },
                None => bad(),
            },
            Err(_) => bad(),
        },
    }
}

fn decode_signal(h: &MessageHeader<'_>, msg: &Message) -> Option<Signal> {
    let iface = h.interface().ok().flatten()?;
    let member = h.member().ok().flatten()?;
    match (iface, member) {
        (OBJECT_MANAGER, "InterfacesAdded") => {
            let (path, ifaces) = msg.body::<(OwnedObjectPath, Ifaces)>().ok()?;
            let path = path.as_str().to_owned();
            if let Some(p) = ifaces.get(ADAPTER) {
                return Some(Signal::Adapter {
                    path,
                    powered: prop_bool(p, "Powered"),
                });
            }
            ifaces.get(DEVICE).map(|p| Signal::Device {
                path,
                props: device_props(p),
            })
        }
        (OBJECT_MANAGER, "InterfacesRemoved") => {
            let (path, ifaces) = msg.body::<(OwnedObjectPath, Vec<String>)>().ok()?;
            Some(Signal::Removed {
                path: path.as_str().to_owned(),
                ifaces,
            })
        }
        (PROPERTIES, "PropertiesChanged") => {
            let path = h.path().ok().flatten()?.as_str().to_owned();
            let (on, changed, _invalidated) = msg
                .body::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
                .ok()?;
            match on.as_str() {
                ADAPTER => Some(Signal::Adapter {
                    path,
                    powered: prop_bool(&changed, "Powered"),
                }),
                DEVICE => Some(Signal::Device {
                    path,
                    props: device_props(&changed),
                }),
                _ => None,
            }
        }
        (BUS_DAEMON, "NameOwnerChanged") => {
            let (name, _old, new) = msg.body::<(String, String, String)>().ok()?;
            (name == BLUEZ).then(|| Signal::Owner((!new.is_empty()).then_some(new)))
        }
        _ => None,
    }
}

fn decode_call(h: &MessageHeader<'_>, msg: &Message) -> Incoming {
    let iface = h.interface().ok().flatten();
    let member = h.member().ok().flatten().unwrap_or("");
    match (iface, member) {
        (Some(OBJECT_MANAGER), "GetManagedObjects") => Incoming::ManagedObjects,
        (Some(PROPERTIES), "GetAll") => msg
            .body::<String>()
            .map_or(Incoming::Other, Incoming::GetAll),
        (Some(PROPERTIES), "Get") => msg
            .body::<(String, String)>()
            .map_or(Incoming::Other, |(i, p)| Incoming::Get(i, p)),
        (Some(GATT_CHAR), "WriteValue") => {
            match msg.body::<(Vec<u8>, HashMap<String, OwnedValue>)>() {
                Ok((value, options)) => Incoming::Write {
                    value,
                    device: prop_path(&options, "device"),
                    mtu: prop(&options, "mtu"),
                },
                Err(_) => Incoming::Other,
            }
        }
        (Some(GATT_CHAR), "StartNotify") => Incoming::StartNotify,
        (Some(GATT_CHAR), "StopNotify") => Incoming::StopNotify,
        (Some(GATT_CHAR), "ReadValue") => Incoming::Read,
        (Some(ADVERTISEMENT), "Release") => Incoming::Release,
        _ => Incoming::Other,
    }
}

/// One message from the bus into [`Core`].
fn dispatch(conn: &Connection, core: &mut Core<DbusBus>, msg: &Message, now: Instant) {
    let Ok(h) = msg.header() else {
        return;
    };
    let Ok(kind) = h.message_type() else {
        return;
    };
    match kind {
        MessageType::MethodReturn | MessageType::Error => {
            let Some(serial) = h.reply_serial().ok().flatten() else {
                return;
            };
            let Some(expect) = core.expects(serial) else {
                return;
            };
            let reply = if kind == MessageType::Error {
                let name = h.error_name().ok().flatten().unwrap_or("error");
                Reply::Failed(name.to_owned())
            } else {
                decode_reply(msg, expect)
            };
            core.reply(serial, reply, now);
        }
        MessageType::Signal => {
            if let Some(sig) = decode_signal(&h, msg) {
                let sender = h.sender().ok().flatten();
                core.signal(sender, sig, now);
            }
        }
        MessageType::MethodCall => {
            let path = h
                .path()
                .ok()
                .flatten()
                .map(|p| p.as_str().to_owned())
                .unwrap_or_default();
            let sender = h.sender().ok().flatten().map(str::to_owned);
            let answer = core.call(sender.as_deref(), &path, decode_call(&h, msg), now);
            answer_call(conn, msg, answer);
        }
        MessageType::Invalid => {}
    }
}

// ── The thread ──────────────────────────────────────────────────────────────

/// The `raven-bluez` thread: commands, then the bus, then deadlines, until
/// the radio is dropped or BlueZ, the adapter or the bus goes away.
fn run(mut core: Core<DbusBus>, conn: &Connection, wake: &UnixDatagram, shared: &Shared) {
    let bus_fd = conn.as_raw_fd();
    let tick_ms = libc::c_int::try_from(TICK.as_millis()).unwrap_or(250);
    // Read until the socket has nothing, then poll.
    let mut backlog = true;
    let mut last_tick = Instant::now();
    core.start();
    while core.alive() {
        let now = Instant::now();
        for cmd in shared.take() {
            core.command(cmd, now);
        }
        if now.saturating_duration_since(last_tick) >= TICK {
            core.tick(now);
            last_tick = now;
        }
        shared.overflows.store(core.dropped(), Ordering::Relaxed);
        if !core.alive() {
            break;
        }
        let out = flush_pending(conn);
        let mut fds = [
            libc::pollfd {
                fd: bus_fd,
                events: libc::POLLIN | libc::POLLRDHUP | if out { libc::POLLOUT } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = if backlog { 0 } else { tick_ms };
        // SAFETY: poll(2) on a two-element array that lives across the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if n < 0 {
            continue;
        }
        let (bus, woke) = (fds[0].revents, fds[1].revents);
        if woke & libc::POLLIN != 0 {
            let mut buf = [0u8; 64];
            while wake.recv(&mut buf).is_ok() {}
        }
        // A closed bus socket: zbus 1.9.3 would spin reading it.
        if bus & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL | libc::POLLRDHUP) != 0 {
            core.shutdown(
                Some("the system bus connection closed"),
                false,
                Instant::now(),
            );
            break;
        }
        if backlog || bus & libc::POLLIN != 0 {
            match conn.receive_message() {
                Ok(msg) => {
                    backlog = true;
                    dispatch(conn, &mut core, &msg, Instant::now());
                }
                Err(zbus::Error::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    backlog = false;
                }
                Err(e) => {
                    let why = format!("D-Bus: {}", error_name(&e));
                    core.shutdown(Some(&why), false, Instant::now());
                    break;
                }
            }
        }
    }
    // The links this side made are being dropped (Device1.Disconnect): let
    // those calls out before the connection closes.
    let deadline = Instant::now() + LAST_FLUSH;
    while flush_pending(conn) && Instant::now() < deadline {
        poll_one(bus_fd, libc::POLLOUT, 50);
    }
    shared.overflows.store(core.dropped(), Ordering::Relaxed);
}

/// Write what zbus holds back; true while some of it still waits for room.
fn flush_pending(conn: &Connection) -> bool {
    matches!(conn.flush(), Err(zbus::Error::Io(e)) if e.kind() == io::ErrorKind::WouldBlock)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::super::super::bluez_mgmt;
    use super::super::super::radio::{Radio, RadioEvent, RadioState, Sent, EVENT_QUEUE};
    use super::open;

    /// BlueZ's emulated controllers (btvirt) report the Linux Foundation's
    /// company identifier; a real adapter never does.
    const VIRTUAL_MANUFACTURER: u16 = 0x05f1;
    const WAIT: Duration = Duration::from_secs(60);

    async fn next_matching<T>(
        rx: &mut mpsc::Receiver<RadioEvent>,
        mut f: impl FnMut(&RadioEvent) -> Option<T>,
    ) -> T {
        tokio::time::timeout(WAIT, async {
            loop {
                let ev = rx.recv().await.expect("the radio ended");
                if let Some(t) = f(&ev) {
                    return t;
                }
            }
        })
        .await
        .expect("no such event in time")
    }

    /// P5.29, advisory (CI job `nearby-btvirt`): the BlueZ backend end to
    /// end on two virtual controllers (btvirt over hci_vhci, BlueZ running):
    /// hci0 publishes and advertises a token, hci1 scans, sees it,
    /// connects and subscribes; one frame crosses each way; a disconnect
    /// ends both sides. Runs only with RAVEN_LAB_BLUEZ_BTVIRT=1, and only
    /// on emulated controllers: a real radio is refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "needs BlueZ and two btvirt controllers (RAVEN_LAB_BLUEZ_BTVIRT=1)"]
    async fn btvirt_two_controllers_carry_a_frame_each_way() {
        if std::env::var("RAVEN_LAB_BLUEZ_BTVIRT").as_deref() != Ok("1") {
            eprintln!("skipped: RAVEN_LAB_BLUEZ_BTVIRT=1 is not set");
            return;
        }
        for index in [0u16, 1] {
            let info = bluez_mgmt::read_info(index).expect("READ_INFO");
            assert_eq!(
                info.manufacturer, VIRTUAL_MANUFACTURER,
                "hci{index} is not an emulated controller: refusing a real radio"
            );
        }
        let (tx_a, mut rx_a) = mpsc::channel(EVENT_QUEUE);
        let (tx_b, mut rx_b) = mpsc::channel(EVENT_QUEUE);
        let mut a = tokio::task::spawn_blocking(move || open(Some("hci0"), tx_a))
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("hci0: {e:?}"));
        let mut b = tokio::task::spawn_blocking(move || open(Some("hci1"), tx_b))
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("hci1: {e:?}"));
        for rx in [&mut rx_a, &mut rx_b] {
            next_matching(rx, |ev| {
                matches!(ev, RadioEvent::State(RadioState::PoweredOn)).then_some(())
            })
            .await;
        }
        assert!(a.caps().peripheral, "hci0 has no peripheral role");
        // The alice-advertises token of shared-vectors/rvn1/nearby.
        let t: [u8; 16] = hex::decode("062a8ac69e024abbab83f9eabb5e8d99")
            .unwrap()
            .try_into()
            .unwrap();
        a.set_services(&[t], Some(t)).unwrap();
        b.set_scanning(true).unwrap();
        let addr = next_matching(&mut rx_b, |ev| match ev {
            RadioEvent::Seen { addr, uuids, .. } if uuids.contains(&t) => Some(addr.clone()),
            _ => None,
        })
        .await;
        let conn_b = b.connect(&addr, t).unwrap();
        let max_tx = next_matching(&mut rx_b, |ev| match ev {
            RadioEvent::Connected { conn, max_tx, .. } if *conn == conn_b => Some(*max_tx),
            RadioEvent::Disconnected { conn } if *conn == conn_b => panic!("connect failed"),
            _ => None,
        })
        .await;
        assert!(max_tx >= 20);
        let hello = b"hello from the central".to_vec();
        loop {
            match b.send(conn_b, &hello).unwrap() {
                Sent::Queued => break,
                Sent::WouldBlock => {
                    next_matching(&mut rx_b, |ev| {
                        matches!(ev, RadioEvent::Writable { conn } if *conn == conn_b).then_some(())
                    })
                    .await;
                }
            }
        }
        let conn_a = next_matching(&mut rx_a, |ev| match ev {
            RadioEvent::Connected { conn, service, .. } if *service == t => Some(*conn),
            _ => None,
        })
        .await;
        let got = next_matching(&mut rx_a, |ev| match ev {
            RadioEvent::Frame { conn, bytes } if *conn == conn_a => Some(bytes.clone()),
            _ => None,
        })
        .await;
        assert_eq!(got, hello);
        let answer = b"hello from the peripheral".to_vec();
        assert_eq!(a.send(conn_a, &answer).unwrap(), Sent::Queued);
        let got = next_matching(&mut rx_b, |ev| match ev {
            RadioEvent::Frame { conn, bytes } if *conn == conn_b => Some(bytes.clone()),
            _ => None,
        })
        .await;
        assert_eq!(got, answer);
        b.disconnect(conn_b);
        next_matching(&mut rx_b, |ev| {
            matches!(ev, RadioEvent::Disconnected { conn } if *conn == conn_b).then_some(())
        })
        .await;
        next_matching(&mut rx_a, |ev| {
            matches!(ev, RadioEvent::Disconnected { conn } if *conn == conn_a).then_some(())
        })
        .await;
    }
}
