//! The cross-process nearby ether (tests and debug builds only; Nearby
//! design step 5.5). `raven-node nearby-ether` serves one in-process
//! [`Ether`] to every lab raven-node started with
//! `RAVEN_LAB_NEARBY_ETHER=127.0.0.1:PORT` (and the nearby lab switch);
//! each one's [`HubRadio`] is a fake radio on it, spoken to over loopback
//! TCP. Works the same on Linux, macOS and Windows.
//!
//! The protocol is internal test JSON, one object per line of at most
//! [`MAX_LINE`] bytes, never frozen and never in a release build:
//! - **To the hub:** `hello` first (`name`, `central_only`,
//!   `public_address`), then `services`, `scan`, `connect` (with the
//!   client's own odd connection number), `send` (the frame in base64) and
//!   `disconnect`.
//! - **From the hub:** `state`, `seen`, `connected` (the hub numbers the
//!   connections other radios open to this one with even numbers), `frame`,
//!   `sent`, `down` and `error`.
//! - **Flow:** a client keeps at most [`HUB_WINDOW`] frames per connection
//!   that the hub has not yet passed to the ether (`sent`); one more is
//!   [`Sent::WouldBlock`], and the `sent` that makes room gives one
//!   `Writable`. The hub holds a frame the ether would block until the
//!   ether's `Writable`.
//! - **Control** (the harness, not a radio: carrier_matrix C50-C56 and the
//!   fault matrix's nearby scenarios): `control` first, then `power` (a
//!   radio's Bluetooth switch, by name), `fault` (arm a lost frame or a cut
//!   link, counted from then), `adverts` (every token that went on air),
//!   `hellos` (the knock HELLOs a radio observer captured), `radios` and
//!   `stats` (frames crossed, whether the armed faults happened); each is
//!   answered `ok`, `adverts`, `hellos`, `radios`, `stats` or `error`.
//!
//! Only loopback: the hub listens on and accepts loopback addresses only,
//! and a client connects to a loopback address only. UUIDs are lowercase
//! hex of their 16 bytes.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use raven_core::nearby_link::Role;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::fake::{Ether, EtherParams, FakeOpts};
use super::lock;
use super::radio::{
    ConnId, EventTx, Privacy, Radio, RadioAddr, RadioCaps, RadioEvent, RadioState, Sent,
    EVENT_QUEUE,
};

/// The lab variable naming the hub a lab raven-node's radio uses.
pub(crate) const LAB_ETHER: &str = "RAVEN_LAB_NEARBY_ETHER";
/// The longest protocol line (a 512-byte frame in base64 is 684 bytes).
pub(crate) const MAX_LINE: usize = 4096;
/// Frames a client may have on their way per connection.
pub(crate) const HUB_WINDOW: usize = 8;
/// Lines a client may have waiting to be written to the hub.
const OUT_QUEUE: usize = 1024;
const HUB_CONNECT: Duration = Duration::from_secs(2);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ToHub {
    Hello {
        name: String,
        #[serde(default)]
        central_only: bool,
        #[serde(default)]
        public_address: bool,
    },
    Services {
        services: Vec<String>,
        advertise: Option<String>,
    },
    Scan {
        on: bool,
    },
    Connect {
        conn: u64,
        addr: String,
        service: String,
    },
    Send {
        conn: u64,
        b64: String,
    },
    Disconnect {
        conn: u64,
    },
    /// The first line of a control session.
    Control,
    Power {
        name: String,
        on: bool,
    },
    Fault {
        #[serde(default)]
        drop_after: Option<u64>,
        #[serde(default)]
        disconnect_after: Option<u64>,
    },
    Adverts,
    Hellos,
    Radios,
    Stats,
}

/// One token that went on air ([`super::fake::AdvertRecord`]).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct AdvertLine {
    radio: String,
    uuids: Vec<String>,
}

/// One captured knock HELLO and the service it was written to.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct HelloLine {
    service: String,
    b64: String,
}

/// One radio on the ether.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RadioLine {
    name: String,
    on: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "ev", rename_all = "snake_case")]
enum FromHub {
    State {
        state: String,
        #[serde(default)]
        detail: Option<String>,
    },
    Seen {
        addr: String,
        uuids: Vec<String>,
        rssi: i16,
    },
    Connected {
        conn: u64,
        role: String,
        service: String,
        max_tx: usize,
        max_rx: usize,
    },
    Frame {
        conn: u64,
        b64: String,
    },
    Sent {
        conn: u64,
    },
    Down {
        conn: u64,
    },
    Error {
        error: String,
    },
    Ok,
    Adverts {
        records: Vec<AdvertLine>,
    },
    Hellos {
        hellos: Vec<HelloLine>,
    },
    Radios {
        radios: Vec<RadioLine>,
    },
    Stats {
        crossed: u64,
        dropped: bool,
        cut: bool,
    },
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn uuid_hex(u: &[u8; 16]) -> String {
    hex::encode(u)
}

fn uuid_from(s: &str) -> Result<[u8; 16], String> {
    let mut u = [0u8; 16];
    hex::decode_to_slice(s, &mut u).map_err(|_| format!("not a 16-byte hex UUID: {s:?}"))?;
    Ok(u)
}

fn role_text(role: Role) -> &'static str {
    match role {
        Role::Central => "central",
        Role::Peripheral => "peripheral",
    }
}

fn state_line(st: &RadioState) -> FromHub {
    let (state, detail) = match st {
        RadioState::PoweredOn => ("on", None),
        RadioState::PoweredOff => ("off", None),
        RadioState::Unauthorized(d) => ("unauthorized", Some(d.clone())),
        RadioState::Unsupported(d) => ("unsupported", Some(d.clone())),
    };
    FromHub::State {
        state: state.into(),
        detail,
    }
}

fn state_from(state: &str, detail: Option<String>) -> RadioState {
    let detail = detail.unwrap_or_default();
    match state {
        "on" => RadioState::PoweredOn,
        "off" => RadioState::PoweredOff,
        "unauthorized" => RadioState::Unauthorized(detail),
        _ => RadioState::Unsupported(detail),
    }
}

/// One protocol line, or `None` at the end of the stream. A line over
/// [`MAX_LINE`] or one that does not parse is an error.
async fn read_msg<R, T>(r: &mut R, buf: &mut Vec<u8>) -> io::Result<Option<T>>
where
    R: AsyncBufRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    buf.clear();
    let n = (&mut *r)
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', buf)
        .await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        if n > MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        return Ok(None);
    }
    serde_json::from_slice(buf)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn line<T: Serialize>(m: &T) -> String {
    let mut s = serde_json::to_string(m).unwrap_or_default();
    s.push('\n');
    s
}

/// The lab hub address of this process: `RAVEN_LAB_NEARBY_ETHER`, read only
/// in a debug build with the nearby lab switch on (`RAVEN_LAB_TEST_A=1` and
/// `RAVEN_LAB_NEARBY=1`). A value that is not a loopback `IP:PORT` is an
/// error.
pub(crate) fn lab_ether() -> Result<Option<SocketAddr>, String> {
    if !raven_core::pair_init::lab_switch(raven_core::nearby_gate::LAB_NEARBY) {
        return Ok(None);
    }
    match raven_core::p2p_gate::lab_switch(LAB_ETHER) {
        None => Ok(None),
        Some(v) => parse_loopback(&v).map(Some),
    }
}

/// A loopback `IP:PORT` with a port.
pub(crate) fn parse_loopback(v: &str) -> Result<SocketAddr, String> {
    let bad = || format!("{LAB_ETHER} must be a loopback IP:PORT, e.g. 127.0.0.1:40000");
    let a: SocketAddr = v.trim().parse().map_err(|_| bad())?;
    if !a.ip().is_loopback() || a.port() == 0 {
        return Err(bad());
    }
    Ok(a)
}

/// `raven-node nearby-ether`: refuse without the nearby lab switch (exit
/// 3) or with a bad listen address or MTU (exit 2); else listen, print the
/// port when asked, and serve until stopped (exit 1 on an error).
pub(crate) async fn run_cli(listen: SocketAddr, print_port: bool, params: EtherParams) -> i32 {
    if !raven_core::pair_init::lab_switch(raven_core::nearby_gate::LAB_NEARBY) {
        eprintln!("nearby-ether: {}", raven_core::NEARBY_HOLD);
        return 3;
    }
    if !listen.ip().is_loopback() {
        eprintln!("nearby-ether: --listen must be a loopback address");
        return 2;
    }
    if let Err(e) = params.check() {
        eprintln!("nearby-ether: {e}");
        return 2;
    }
    let listener = match TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("nearby-ether: cannot listen: {e}");
            return 1;
        }
    };
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    if print_port {
        println!("{port}");
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
    }
    eprintln!("nearby-ether: listening on loopback port {port}");
    match serve(listener, params).await {
        Ok(never) => match never {},
        Err(e) => {
            eprintln!("nearby-ether: {e}");
            1
        }
    }
}

/// Serve one ether to every loopback client of `listener`.
pub(crate) async fn serve(listener: TcpListener, params: EtherParams) -> io::Result<Infallible> {
    let ether = Ether::new(params);
    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let _ = stream.set_nodelay(true);
        tokio::spawn(session(stream, ether.clone()));
    }
}

/// One client: its fake radio on the ether, driven by its lines, its
/// events written back.
async fn session(stream: TcpStream, ether: Ether) {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut buf = Vec::new();
    let (name, central_only, public_address) = match read_msg(&mut reader, &mut buf).await {
        Ok(Some(ToHub::Hello {
            name,
            central_only,
            public_address,
        })) => (name, central_only, public_address),
        Ok(Some(ToHub::Control)) => {
            while let Ok(Some(m)) = read_msg::<_, ToHub>(&mut reader, &mut buf).await {
                if w.write_all(line(&control(&ether, m)).as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
            }
            return;
        }
        _ => return,
    };
    let (tx, mut events) = mpsc::channel(EVENT_QUEUE);
    let opts = FakeOpts {
        central_only,
        public_address,
    };
    let mut radio = ether.radio_with(&name, tx, opts);
    let (in_tx, mut inbox) = mpsc::channel::<ToHub>(64);
    let lines = tokio::spawn(async move {
        while let Ok(Some(m)) = read_msg(&mut reader, &mut buf).await {
            if in_tx.send(m).await.is_err() {
                break;
            }
        }
    });
    let mut s = Session::default();
    'serve: loop {
        let out = tokio::select! {
            m = inbox.recv() => match m {
                Some(m) => s.on_client(&mut radio, m),
                None => break,
            },
            ev = events.recv() => match ev {
                Some(ev) => s.on_event(&mut radio, ev),
                None => break,
            },
        };
        for m in out {
            if w.write_all(line(&m).as_bytes()).await.is_err() {
                break 'serve;
            }
        }
    }
    lines.abort();
    // Dropping the radio cuts its links: the other ends are told.
    drop(radio);
}

/// One request of a control session (the harness), answered at once.
fn control(ether: &Ether, m: ToHub) -> FromHub {
    match m {
        ToHub::Power { name, on } => match ether.set_power(&name, on) {
            0 => FromHub::Error {
                error: format!("no radio named {name:?}"),
            },
            _ => FromHub::Ok,
        },
        ToHub::Fault {
            drop_after,
            disconnect_after,
        } => {
            ether.arm_faults(drop_after, disconnect_after);
            FromHub::Ok
        }
        ToHub::Adverts => FromHub::Adverts {
            records: ether
                .adverts()
                .into_iter()
                .map(|r| AdvertLine {
                    radio: r.radio,
                    uuids: r.uuids.iter().map(uuid_hex).collect(),
                })
                .collect(),
        },
        ToHub::Hellos => FromHub::Hellos {
            hellos: ether
                .hellos()
                .into_iter()
                .map(|(service, frame)| HelloLine {
                    service: uuid_hex(&service),
                    b64: b64().encode(frame),
                })
                .collect(),
        },
        ToHub::Radios => FromHub::Radios {
            radios: ether
                .radios()
                .into_iter()
                .map(|(name, on)| RadioLine { name, on })
                .collect(),
        },
        ToHub::Stats => {
            let (crossed, dropped, cut) = ether.fault_stats();
            FromHub::Stats {
                crossed,
                dropped,
                cut,
            }
        }
        _ => FromHub::Error {
            error: "not a control request".into(),
        },
    }
}

/// The hub's side of one client: connection numbers both ways, and frames
/// the ether would block.
#[derive(Default)]
struct Session {
    wire_of: HashMap<ConnId, u64>,
    ether_of: HashMap<u64, ConnId>,
    held: HashMap<ConnId, VecDeque<Vec<u8>>>,
    next_even: u64,
}

impl Session {
    fn on_client(&mut self, radio: &mut impl Radio, m: ToHub) -> Vec<FromHub> {
        let err = |error: String| vec![FromHub::Error { error }];
        match m {
            ToHub::Hello { .. } => err("hello twice".into()),
            ToHub::Services {
                services,
                advertise,
            } => {
                let parsed: Result<Vec<_>, _> = services.iter().map(|s| uuid_from(s)).collect();
                let adv = advertise.as_deref().map(uuid_from).transpose();
                match (parsed, adv) {
                    (Ok(svc), Ok(adv)) => match radio.set_services(&svc, adv) {
                        Ok(()) => Vec::new(),
                        Err(e) => err(e),
                    },
                    (Err(e), _) | (_, Err(e)) => err(e),
                }
            }
            ToHub::Scan { on } => match radio.set_scanning(on) {
                Ok(()) => Vec::new(),
                Err(e) => err(e),
            },
            ToHub::Connect {
                conn,
                addr,
                service,
            } => {
                if conn % 2 == 0 || self.ether_of.contains_key(&conn) {
                    return err(format!("connection number {conn} is not a free odd one"));
                }
                let connected =
                    uuid_from(&service).and_then(|t| radio.connect(&RadioAddr(addr), t));
                match connected {
                    Ok(ec) => {
                        self.wire_of.insert(ec, conn);
                        self.ether_of.insert(conn, ec);
                        Vec::new()
                    }
                    Err(_) => vec![FromHub::Down { conn }],
                }
            }
            ToHub::Send { conn, b64: data } => {
                let Some(&ec) = self.ether_of.get(&conn) else {
                    // Ended meanwhile: its `down` is on its way.
                    return Vec::new();
                };
                let Ok(frame) = b64().decode(data) else {
                    radio.disconnect(ec);
                    return err("a frame that is not base64".into());
                };
                let held = self.held.entry(ec).or_default();
                held.push_back(frame);
                self.pass(radio, ec)
            }
            ToHub::Disconnect { conn } => {
                if let Some(&ec) = self.ether_of.get(&conn) {
                    radio.disconnect(ec);
                }
                Vec::new()
            }
            ToHub::Control
            | ToHub::Power { .. }
            | ToHub::Fault { .. }
            | ToHub::Adverts
            | ToHub::Hellos
            | ToHub::Radios
            | ToHub::Stats => err("a control request in a radio session".into()),
        }
    }

    /// Pass held frames of `ec` to the ether until it would block.
    fn pass(&mut self, radio: &mut impl Radio, ec: ConnId) -> Vec<FromHub> {
        let mut out = Vec::new();
        let Some(&conn) = self.wire_of.get(&ec) else {
            return out;
        };
        let Some(held) = self.held.get_mut(&ec) else {
            return out;
        };
        while let Some(frame) = held.front() {
            match radio.send(ec, frame) {
                Ok(Sent::Queued) => {
                    held.pop_front();
                    out.push(FromHub::Sent { conn });
                }
                Ok(Sent::WouldBlock) => break,
                Err(error) => {
                    held.clear();
                    radio.disconnect(ec);
                    out.push(FromHub::Error { error });
                    break;
                }
            }
        }
        out
    }

    fn on_event(&mut self, radio: &mut impl Radio, ev: RadioEvent) -> Vec<FromHub> {
        match ev {
            RadioEvent::State(st) => vec![state_line(&st)],
            RadioEvent::Seen { addr, uuids, rssi } => vec![FromHub::Seen {
                addr: addr.0,
                uuids: uuids.iter().map(uuid_hex).collect(),
                rssi,
            }],
            RadioEvent::Connected {
                conn: ec,
                role,
                service,
                max_tx,
                max_rx,
            } => {
                let conn = match self.wire_of.get(&ec) {
                    Some(&c) => c,
                    None => {
                        self.next_even += 2;
                        let c = self.next_even;
                        self.wire_of.insert(ec, c);
                        self.ether_of.insert(c, ec);
                        c
                    }
                };
                vec![FromHub::Connected {
                    conn,
                    role: role_text(role).into(),
                    service: uuid_hex(&service),
                    max_tx,
                    max_rx,
                }]
            }
            RadioEvent::Frame { conn: ec, bytes } => match self.wire_of.get(&ec) {
                Some(&conn) => vec![FromHub::Frame {
                    conn,
                    b64: b64().encode(bytes),
                }],
                None => Vec::new(),
            },
            RadioEvent::Writable { conn: ec } => self.pass(radio, ec),
            RadioEvent::Disconnected { conn: ec } => {
                self.held.remove(&ec);
                match self.wire_of.remove(&ec) {
                    Some(conn) => {
                        self.ether_of.remove(&conn);
                        vec![FromHub::Down { conn }]
                    }
                    None => Vec::new(),
                }
            }
        }
    }
}

/// A fake radio on a hub, as a lab raven-node uses it.
pub(crate) struct HubRadio {
    out: mpsc::Sender<String>,
    shared: Arc<Mutex<Client>>,
    events: EventTx,
    caps: RadioCaps,
    reader: JoinHandle<()>,
}

#[derive(Default)]
struct Client {
    /// The last odd connection number used.
    last: u64,
    conns: HashMap<u64, Window>,
}

#[derive(Default)]
struct Window {
    /// 0 until `connected`.
    max_tx: usize,
    in_flight: usize,
    want: bool,
}

impl HubRadio {
    /// Connect to the hub at `addr` (loopback only) as `name`. Needs a
    /// tokio runtime; waits at most 2 s for the TCP connect.
    pub(crate) fn connect(
        addr: SocketAddr,
        name: &str,
        opts: FakeOpts,
        tx: mpsc::Sender<RadioEvent>,
    ) -> Result<Self, String> {
        if !addr.ip().is_loopback() {
            return Err("the nearby ether hub must be on loopback".into());
        }
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
        let no_hub = |e: io::Error| format!("nearby ether hub at {addr}: {e}");
        let std = std::net::TcpStream::connect_timeout(&addr, HUB_CONNECT).map_err(no_hub)?;
        let _ = std.set_nodelay(true);
        std.set_nonblocking(true).map_err(no_hub)?;
        let _guard = handle.enter();
        let stream = TcpStream::from_std(std).map_err(no_hub)?;
        let (r, mut w) = stream.into_split();
        let (out, mut out_rx) = mpsc::channel::<String>(OUT_QUEUE);
        let hello = ToHub::Hello {
            name: name.to_owned(),
            central_only: opts.central_only,
            public_address: opts.public_address,
        };
        out.try_send(line(&hello))
            .map_err(|_| "hub queue".to_string())?;
        handle.spawn(async move {
            while let Some(l) = out_rx.recv().await {
                if w.write_all(l.as_bytes()).await.is_err() {
                    return;
                }
            }
            let _ = w.shutdown().await;
        });
        let events = EventTx::new(tx);
        let shared = Arc::new(Mutex::new(Client::default()));
        let reader = handle.spawn(read_hub(
            BufReader::new(r),
            shared.clone(),
            events.clone(),
            out.clone(),
        ));
        Ok(Self {
            out,
            shared,
            events,
            caps: RadioCaps {
                central: true,
                peripheral: !opts.central_only,
                l2cap: false,
                address_privacy: if opts.public_address {
                    Privacy::Public
                } else {
                    Privacy::Random
                },
                per_central_notify: true,
            },
            reader,
        })
    }

    fn put(&self, m: &ToHub) -> Result<(), String> {
        self.out
            .try_send(line(m))
            .map_err(|_| "the nearby ether hub is gone or not reading".into())
    }
}

/// The hub's lines as this radio's events. When the hub goes, every
/// connection ends and the radio is off.
async fn read_hub(
    mut r: BufReader<tokio::net::tcp::OwnedReadHalf>,
    shared: Arc<Mutex<Client>>,
    events: EventTx,
    out: mpsc::Sender<String>,
) {
    let mut buf = Vec::new();
    let lose = |conn: u64| {
        let _ = out.try_send(line(&ToHub::Disconnect { conn }));
    };
    while let Ok(Some(m)) = read_msg::<_, FromHub>(&mut r, &mut buf).await {
        match m {
            FromHub::State { state, detail } => {
                let _ = events.emit(RadioEvent::State(state_from(&state, detail)));
            }
            FromHub::Seen { addr, uuids, rssi } => {
                let Ok(uuids) = uuids
                    .iter()
                    .map(|u| uuid_from(u))
                    .collect::<Result<Vec<_>, _>>()
                else {
                    continue;
                };
                let _ = events.emit(RadioEvent::Seen {
                    addr: RadioAddr(addr),
                    uuids,
                    rssi,
                });
            }
            FromHub::Connected {
                conn,
                role,
                service,
                max_tx,
                max_rx,
            } => {
                let Ok(service) = uuid_from(&service) else {
                    lose(conn);
                    continue;
                };
                let role = if role == "central" {
                    Role::Central
                } else {
                    Role::Peripheral
                };
                lock(&shared).conns.entry(conn).or_default().max_tx = max_tx;
                let ev = RadioEvent::Connected {
                    conn,
                    role,
                    service,
                    max_tx,
                    max_rx,
                };
                if let Err(Some(c)) = events.emit(ev) {
                    lose(c);
                }
            }
            FromHub::Frame { conn, b64: data } => {
                let Ok(bytes) = b64().decode(data) else {
                    lose(conn);
                    continue;
                };
                if let Err(Some(c)) = events.emit(RadioEvent::Frame { conn, bytes }) {
                    lose(c);
                }
            }
            FromHub::Sent { conn } => {
                let room = {
                    let mut st = lock(&shared);
                    let Some(w) = st.conns.get_mut(&conn) else {
                        continue;
                    };
                    w.in_flight = w.in_flight.saturating_sub(1);
                    let room = w.want && w.in_flight < HUB_WINDOW;
                    if room {
                        w.want = false;
                    }
                    room
                };
                if room {
                    if let Err(Some(c)) = events.emit(RadioEvent::Writable { conn }) {
                        lose(c);
                    }
                }
            }
            FromHub::Down { conn } => {
                lock(&shared).conns.remove(&conn);
                let _ = events.emit(RadioEvent::Disconnected { conn });
            }
            FromHub::Error { error } => eprintln!("nearby-ether: {error}"),
            // Answers of a control session; never sent to a radio.
            FromHub::Ok
            | FromHub::Adverts { .. }
            | FromHub::Hellos { .. }
            | FromHub::Radios { .. }
            | FromHub::Stats { .. } => {}
        }
    }
    let conns: Vec<u64> = lock(&shared).conns.drain().map(|(c, _)| c).collect();
    for conn in conns {
        let _ = events.emit(RadioEvent::Disconnected { conn });
    }
    let _ = events.emit(RadioEvent::State(RadioState::PoweredOff));
}

impl Radio for HubRadio {
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
        self.put(&ToHub::Services {
            services: services.iter().map(uuid_hex).collect(),
            advertise: advertise.as_ref().map(uuid_hex),
        })
    }

    fn set_scanning(&mut self, on: bool) -> Result<(), String> {
        self.put(&ToHub::Scan { on })
    }

    fn connect(&mut self, addr: &RadioAddr, service: [u8; 16]) -> Result<ConnId, String> {
        let conn = {
            let mut st = lock(&self.shared);
            st.last = if st.last == 0 { 1 } else { st.last + 2 };
            let conn = st.last;
            st.conns.insert(conn, Window::default());
            conn
        };
        let m = ToHub::Connect {
            conn,
            addr: addr.0.clone(),
            service: uuid_hex(&service),
        };
        if let Err(e) = self.put(&m) {
            lock(&self.shared).conns.remove(&conn);
            return Err(e);
        }
        Ok(conn)
    }

    fn send(&mut self, conn: ConnId, frame: &[u8]) -> Result<Sent, String> {
        {
            let mut st = lock(&self.shared);
            let w = st
                .conns
                .get_mut(&conn)
                .filter(|w| w.max_tx > 0)
                .ok_or("not connected")?;
            if frame.is_empty() || frame.len() > w.max_tx {
                return Err(format!(
                    "a frame of {} bytes on a link of max_tx {}",
                    frame.len(),
                    w.max_tx
                ));
            }
            if w.in_flight >= HUB_WINDOW {
                w.want = true;
                return Ok(Sent::WouldBlock);
            }
            w.in_flight += 1;
        }
        self.put(&ToHub::Send {
            conn,
            b64: b64().encode(frame),
        })?;
        Ok(Sent::Queued)
    }

    fn disconnect(&mut self, conn: ConnId) {
        if lock(&self.shared).conns.contains_key(&conn) {
            let _ = self.put(&ToHub::Disconnect { conn });
        }
    }

    fn overflows(&self) -> u64 {
        self.events.dropped()
    }
}

impl Drop for HubRadio {
    /// The writer finishes its lines and closes the connection; the hub
    /// then drops this radio's fake twin, which cuts its links.
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[cfg(test)]
mod tests;
