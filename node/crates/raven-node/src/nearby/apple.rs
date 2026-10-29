//! The macOS backend of the nearby radio (RNL1 §3-§4, §8-§9; Nearby design
//! step 5.10; owner decision O5-10): CoreBluetooth in a helper process.
//! raven-node uses it on macOS with feature `nearby-radio`; its pure parts
//! are tested on every platform.
//!
//! **Process split.** CoreBluetooth runs in `raven-nearby-helper`
//! (`src/bin/raven-nearby-helper/`), shipped as `RavenNearby.app` whose
//! Info.plist carries `NSBluetoothAlwaysUsageDescription`
//! (`macos/RavenNearby.app`). raven-node spawns it and speaks [`proto`]
//! over its stdin and stdout; its stderr is raven-node's. The helper holds
//! no keys: it sees tokens, characteristic UUIDs, device handles and RNK1 or
//! RNP1 frames, nothing else. raven-node itself never links CoreBluetooth,
//! so a macOS privacy refusal that kills the helper (SIGABRT) cannot touch
//! raven-node, its code signature or its Keychain access.
//!
//! **Finding the helper** ([`helper_path`]): `RAVEN_NEARBY_HELPER` when set
//! (an absolute path to the helper or to its .app; nothing else is tried),
//! else `RavenNearby.app` next to the raven-node executable, else
//! `~/Library/Application Support/Raven/RavenNearby.app`, where the macOS
//! installer puts it. Tests never look anywhere.
//!
//! **Start.** The helper's first line is `hello` with [`proto::VERSION`]
//! within [`HELLO_WAIT`], or why it cannot run (`unauthorized` without the
//! usage description); then the open fails with that state and no radio
//! exists.
//!
//! **Connections.** raven-node numbers the ones it opens (odd), the helper
//! those centrals open to it (even), both below 2^32 on the wire. Each
//! helper start is a new generation in the upper 32 bits of [`ConnId`], so
//! a number is never used again after a restart.
//!
//! **Sending.** At most [`SEND_WINDOW`] frames per connection may be on
//! their way to CoreBluetooth (the helper answers each with `sent`); one
//! more is [`Sent::WouldBlock`], and the `sent` that makes room gives one
//! `Writable`.
//!
//! **Capabilities.** Central and peripheral, notifications to one central
//! (`updateValue:forCharacteristic:onSubscribedCentrals:`). macOS advertises
//! from a random resolvable private address (Bluetooth LE privacy on Apple
//! platforms), so the address privacy is `Random`; owner row N7 captures
//! the advert to confirm it before any flip (RNL1 §3, owner decision O5-12).
//!
//! **When the helper ends on its own** (a crash, a macOS SIGABRT, a kill):
//! every connection gets its `Disconnected`, the radio says why
//! (`Unauthorized` after SIGABRT) and its event queue closes, so the engine
//! ends and the service makes a new radio on a later poll. A start that
//! fails or a helper that ends that way doubles the wait before the next
//! start ([`BACKOFF_FIRST`] up to [`BACKOFF_MAX`]: no crash report every
//! poll); a radio that came up resets it.

// Only the macOS build with `nearby-radio` uses all of this; the tests
// build it on every platform.
#![cfg_attr(
    not(all(target_os = "macos", feature = "nearby-radio")),
    allow(dead_code)
)]

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use raven_core::nearby_link::{char_uuid, Role};
use tokio::sync::mpsc;

use super::lock;
use super::radio::{
    ConnId, EventTx, Privacy, Radio, RadioAddr, RadioCaps, RadioEvent, RadioState, Sent,
};
use proto::{FromHelper, Gatt, Power, Side, ToHelper};

pub(crate) mod proto;
#[cfg(test)]
mod tests;

/// Where the helper is, when set (see the module doc).
pub(crate) const HELPER_ENV: &str = "RAVEN_NEARBY_HELPER";
/// The helper's bundle.
pub(crate) const BUNDLE: &str = "RavenNearby.app";
/// The helper's executable inside [`BUNDLE`].
pub(crate) const EXECUTABLE: &str = "raven-nearby-helper";
/// Where the macOS installer puts [`BUNDLE`], under the home directory.
pub(crate) const INSTALL_DIR: &str = "Library/Application Support/Raven";
/// How long the helper may take to say `hello`.
pub(crate) const HELLO_WAIT: Duration = Duration::from_secs(5);
/// Frames a connection may have on their way to CoreBluetooth.
pub(crate) const SEND_WINDOW: usize = 16;
/// How long a stopped helper may take to exit before it is killed.
pub(crate) const REAP_WAIT: Duration = Duration::from_secs(3);
/// The wait after the first failed start; it doubles with each failure.
pub(crate) const BACKOFF_FIRST: Duration = Duration::from_secs(60);
/// The longest wait between starts.
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(3600);
/// No helper was found.
pub(crate) const NO_HELPER: &str =
    "the nearby helper (RavenNearby.app) is not installed: run the macOS installer";
const HELPER_GONE: &str = "the nearby helper is gone";
const WIRE_MASK: u64 = proto::CONN_LIMIT - 1;

/// The radio's capabilities (see the module doc).
pub(crate) fn caps() -> RadioCaps {
    RadioCaps {
        central: true,
        peripheral: true,
        l2cap: false,
        address_privacy: Privacy::Random,
        per_central_notify: true,
    }
}

// ── Finding the helper ──────────────────────────────────────────────────────

/// The helper's executable for `p`: `p` itself, or the executable inside
/// it when it is an .app.
pub(crate) fn executable_in(p: &Path) -> PathBuf {
    if p.extension().is_some_and(|e| e == "app") {
        p.join("Contents").join("MacOS").join(EXECUTABLE)
    } else {
        p.to_path_buf()
    }
}

/// The helper this process would start (see the module doc); never one in
/// a test build.
pub(crate) fn helper_path() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    }
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    find_helper(
        std::env::var_os(HELPER_ENV).map(PathBuf::from),
        exe_dir,
        std::env::var_os("HOME").map(PathBuf::from),
        |p| p.is_file(),
    )
}

/// [`helper_path`] from its inputs: `env` alone when it is set (only an
/// absolute path counts), else the bundle next to raven-node, else the
/// installed one.
pub(crate) fn find_helper(
    env: Option<PathBuf>,
    exe_dir: Option<PathBuf>,
    home: Option<PathBuf>,
    exists: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    if let Some(p) = env.filter(|p| !p.as_os_str().is_empty()) {
        let exe = executable_in(&p);
        return (p.is_absolute() && exists(&exe)).then_some(exe);
    }
    [
        exe_dir.map(|d| d.join(BUNDLE)),
        home.map(|h| h.join(INSTALL_DIR).join(BUNDLE)),
    ]
    .into_iter()
    .flatten()
    .map(|app| executable_in(&app))
    .find(|exe| exists(exe))
}

// ── Back-off ────────────────────────────────────────────────────────────────

/// The wait between helper starts after failures (see the module doc).
#[derive(Default)]
pub(crate) struct Backoff {
    streak: u32,
    until: Option<Instant>,
    last: Option<RadioState>,
}

impl Backoff {
    /// `Err` with the last failure while the wait runs.
    pub(crate) fn check(&self, now: Instant) -> Result<(), RadioState> {
        match (self.until, &self.last) {
            (Some(until), Some(last)) if now < until => Err(last.clone()),
            _ => Ok(()),
        }
    }

    /// A start failed, or the helper ended on its own, with `state`.
    pub(crate) fn failed(&mut self, now: Instant, state: RadioState) {
        let wait = BACKOFF_FIRST
            .saturating_mul(1u32 << self.streak.min(16))
            .min(BACKOFF_MAX);
        self.streak = self.streak.saturating_add(1);
        self.until = Some(now + wait);
        self.last = Some(state);
    }

    /// The radio came up.
    pub(crate) fn healthy(&mut self) {
        *self = Self::default();
    }
}

fn backoff() -> Arc<Mutex<Backoff>> {
    static BACKOFF: OnceLock<Arc<Mutex<Backoff>>> = OnceLock::new();
    Arc::clone(BACKOFF.get_or_init(Arc::default))
}

// ── Opening ─────────────────────────────────────────────────────────────────

/// The radio of this Mac: the helper found by [`helper_path`], started
/// (after any back-off wait).
pub(crate) fn open(tx: mpsc::Sender<RadioEvent>) -> Result<HelperRadio, RadioState> {
    let backoff = backoff();
    lock(&backoff).check(Instant::now())?;
    let Some(exe) = helper_path() else {
        let state = RadioState::Unsupported(NO_HELPER.into());
        note(&state);
        return Err(state);
    };
    let opened = open_at(&exe, tx, Some(Arc::clone(&backoff)), HELLO_WAIT);
    if let Err(state) = &opened {
        note(state);
        lock(&backoff).failed(Instant::now(), state.clone());
    }
    opened
}

/// Log why the radio is not there, each distinct reason once in a row (the
/// service's own line names the state only). No device is ever named.
fn note(state: &RadioState) {
    static LAST: Mutex<Option<String>> = Mutex::new(None);
    let line = match state {
        RadioState::Unauthorized(why) | RadioState::Unsupported(why) => why.clone(),
        RadioState::PoweredOn | RadioState::PoweredOff => return,
    };
    let mut last = lock(&LAST);
    if last.as_ref() != Some(&line) {
        if !cfg!(test) {
            eprintln!("raven-node nearby: {line}");
        }
        *last = Some(line);
    }
}

/// Start the helper at `exe` and wait up to `hello_wait` for its `hello`.
pub(crate) fn open_at(
    exe: &Path,
    tx: mpsc::Sender<RadioEvent>,
    backoff: Option<Arc<Mutex<Backoff>>>,
    hello_wait: Duration,
) -> Result<HelperRadio, RadioState> {
    let mut child = Command::new(exe)
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| RadioState::Unsupported(format!("the nearby helper did not start: {e}")))?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(RadioState::Unsupported(
            "the nearby helper did not start: no pipes".into(),
        ));
    };
    start(stdin, stdout, Some(child), tx, backoff, hello_wait)
}

/// The radio over a helper's stdin (`w`) and stdout (`r`); `child` is the
/// helper process, if there is one to reap.
pub(crate) fn start(
    w: impl Write + Send + 'static,
    r: impl Read + Send + 'static,
    child: Option<Child>,
    tx: mpsc::Sender<RadioEvent>,
    backoff: Option<Arc<Mutex<Backoff>>>,
    hello_wait: Duration,
) -> Result<HelperRadio, RadioState> {
    static GENERATION: AtomicU64 = AtomicU64::new(0);
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    let (out, out_rx) = std_mpsc::channel::<String>();
    let link = Arc::new(Link {
        out: Mutex::new(Some(out)),
        table: Mutex::new(Table::default()),
        child: Mutex::new(child),
        stopped: AtomicBool::new(false),
        overflows: AtomicU64::new(0),
        generation,
    });
    let spawned = std::thread::Builder::new()
        .name("nearby-helper-out".into())
        .spawn(move || write_helper(w, out_rx));
    let (hello_tx, hello_rx) = std_mpsc::sync_channel(1);
    let reader = {
        let link = Arc::clone(&link);
        let events = EventTx::new(tx);
        std::thread::Builder::new()
            .name("nearby-helper-in".into())
            .spawn(move || read_helper(BufReader::new(r), &link, &events, &hello_tx, backoff))
    };
    if spawned.is_err() || reader.is_err() {
        link.stop(Duration::ZERO);
        return Err(RadioState::Unsupported(
            "the nearby helper could not be served (no thread)".into(),
        ));
    }
    match hello_rx.recv_timeout(hello_wait) {
        Ok(Ok(())) => Ok(HelperRadio { link }),
        Ok(Err(state)) => {
            link.stop(REAP_WAIT);
            Err(state)
        }
        Err(_) => {
            link.stop(Duration::ZERO);
            Err(RadioState::Unsupported(
                "the nearby helper did not answer".into(),
            ))
        }
    }
}

// ── The radio ───────────────────────────────────────────────────────────────

/// The helper as this process's [`Radio`].
pub(crate) struct HelperRadio {
    link: Arc<Link>,
}

/// What the radio, its reader and its writer share.
struct Link {
    /// To the writer thread; `None` once stopped (the helper's stdin then
    /// closes and it exits).
    out: Mutex<Option<std_mpsc::Sender<String>>>,
    table: Mutex<Table>,
    child: Mutex<Option<Child>>,
    /// raven-node stopped the helper: its end is not news.
    stopped: AtomicBool,
    overflows: AtomicU64,
    generation: u64,
}

#[derive(Default)]
struct Table {
    /// The last odd wire number used.
    last: u64,
    conns: HashMap<ConnId, Window>,
}

#[derive(Default)]
struct Window {
    /// 0 until `connected`.
    max_tx: usize,
    in_flight: usize,
    want: bool,
}

impl Link {
    fn put(&self, m: &ToHelper) -> Result<(), String> {
        match &*lock(&self.out) {
            Some(out) => out
                .send(proto::line(m))
                .map_err(|_| HELPER_GONE.to_string()),
            None => Err(HELPER_GONE.into()),
        }
    }

    /// raven-node's number for wire number `wire`.
    fn conn_of(&self, wire: u64) -> Option<ConnId> {
        (wire != 0 && wire < proto::CONN_LIMIT).then_some((self.generation << 32) | wire)
    }

    /// The wire number of `conn`, if it is of this helper.
    fn wire_of(&self, conn: ConnId) -> Option<u64> {
        (conn >> 32 == self.generation).then_some(conn & WIRE_MASK)
    }

    /// Tell the helper to end `conn` (it lost an event, or broke the
    /// protocol); its `disconnected` follows.
    fn lose(&self, conn: ConnId) {
        if let Some(wire) = self.wire_of(conn) {
            let _ = self.put(&ToHelper::Disconnect { conn: wire });
        }
    }

    /// Stop the helper: its stdin closes, and it is killed if it has not
    /// exited within `grace` (on another thread).
    fn stop(self: &Arc<Self>, grace: Duration) {
        self.stopped.store(true, Ordering::SeqCst);
        lock(&self.out).take();
        let link = Arc::clone(self);
        let reaped = std::thread::Builder::new()
            .name("nearby-helper-reap".into())
            .spawn(move || {
                link.reap(grace);
            });
        if reaped.is_err() {
            if let Some(c) = lock(&self.child).as_mut() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// The helper's exit status: waits up to `grace` for it to exit, then
    /// kills it. `None` without a process.
    fn reap(&self, grace: Duration) -> Option<ExitStatus> {
        let until = Instant::now() + grace;
        loop {
            {
                let mut child = lock(&self.child);
                let c = child.as_mut()?;
                match c.try_wait() {
                    Ok(Some(status)) => return Some(status),
                    Ok(None) if Instant::now() >= until => {
                        let _ = c.kill();
                        return c.wait().ok();
                    }
                    Ok(None) => {}
                    Err(_) => return None,
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The helper's stdin: lines in order until the radio lets go.
fn write_helper(mut w: impl Write, lines: std_mpsc::Receiver<String>) {
    for l in lines {
        if w.write_all(l.as_bytes()).and_then(|()| w.flush()).is_err() {
            return;
        }
    }
}

/// What the helper's state line means for the radio.
pub(crate) fn state_of(state: Power, detail: String) -> RadioState {
    match state {
        Power::On => RadioState::PoweredOn,
        Power::Off => RadioState::PoweredOff,
        Power::Unauthorized => RadioState::Unauthorized(detail),
        Power::Unsupported => RadioState::Unsupported(detail),
    }
}

/// What a helper that ended on its own means for the radio. SIGABRT is
/// what macOS sends a process it refuses Bluetooth to.
pub(crate) fn ended_state(status: Option<ExitStatus>) -> RadioState {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        match status.and_then(|s| s.signal()) {
            Some(libc::SIGABRT) => {
                return RadioState::Unauthorized(
                    "the nearby helper was stopped (SIGABRT), as macOS does when Bluetooth is \
                     not allowed for RavenNearby: allow it in System Settings > Privacy & \
                     Security > Bluetooth"
                        .into(),
                )
            }
            Some(sig) => {
                return RadioState::Unsupported(format!(
                    "the nearby helper was stopped by signal {sig}"
                ))
            }
            None => {}
        }
    }
    match status.and_then(|s| s.code()) {
        Some(code) => RadioState::Unsupported(format!("the nearby helper ended (exit {code})")),
        None => RadioState::Unsupported("the nearby helper ended".into()),
    }
}

/// The helper's stdout: its `hello` (answered on `hello`), then its events
/// until it ends (see the module doc).
fn read_helper(
    mut r: impl std::io::BufRead,
    link: &Arc<Link>,
    events: &EventTx,
    hello: &std_mpsc::SyncSender<Result<(), RadioState>>,
    backoff: Option<Arc<Mutex<Backoff>>>,
) {
    let mut buf = Vec::new();
    let first = match proto::read_line(&mut r, &mut buf) {
        Ok(true) => Some(proto::parse::<FromHelper>(&buf)),
        _ => None,
    };
    let started = match first {
        Some(Some(FromHelper::Hello { v })) if v == proto::VERSION => Ok(()),
        Some(Some(FromHelper::Hello { v })) => Err(RadioState::Unsupported(format!(
            "the nearby helper speaks protocol {v}, this raven-node {}: install the \
             RavenNearby.app of this release",
            proto::VERSION
        ))),
        Some(Some(FromHelper::State {
            state: state @ (Power::Unauthorized | Power::Unsupported),
            detail,
        })) => Err(state_of(state, detail)),
        Some(_) => Err(RadioState::Unsupported(
            "the nearby helper did not start (an unexpected first line)".into(),
        )),
        None => Err(ended_state(link.reap(REAP_WAIT))),
    };
    let ok = started.is_ok();
    let _ = hello.send(started);
    if !ok {
        return;
    }
    while let Ok(true) = proto::read_line(&mut r, &mut buf) {
        if let Some(m) = proto::parse::<FromHelper>(&buf) {
            on_line(link, events, m, backoff.as_deref());
            link.overflows.store(events.dropped(), Ordering::Relaxed);
        }
    }
    if link.stopped.load(Ordering::SeqCst) {
        return;
    }
    // The helper ended on its own: every connection ends, the radio says
    // why, and `events` (the queue's only sender) goes, which ends the
    // engine.
    let why = ended_state(link.reap(REAP_WAIT));
    lock(&link.out).take();
    let conns: Vec<ConnId> = lock(&link.table).conns.drain().map(|(c, _)| c).collect();
    for conn in conns {
        let _ = events.emit(RadioEvent::Disconnected { conn });
    }
    let _ = events.emit(RadioEvent::State(why.clone()));
    if let Some(b) = backoff {
        note(&why);
        lock(&b).failed(Instant::now(), why);
    }
}

/// One line of the running helper.
fn on_line(link: &Link, events: &EventTx, m: FromHelper, backoff: Option<&Mutex<Backoff>>) {
    let lost = |r: Result<(), Option<ConnId>>| {
        if let Err(Some(c)) = r {
            link.lose(c);
        }
    };
    match m {
        FromHelper::Hello { .. } => {}
        FromHelper::State { state, detail } => {
            let state = state_of(state, detail);
            if state == RadioState::PoweredOn {
                if let Some(b) = backoff {
                    lock(b).healthy();
                }
            }
            let _ = events.emit(RadioEvent::State(state));
        }
        FromHelper::Seen { dev, uuids, rssi } => {
            if dev.is_empty() || dev.len() > proto::MAX_DEV || uuids.len() > proto::MAX_UUIDS {
                return;
            }
            let Some(uuids) = uuids
                .iter()
                .map(|u| proto::uuid_from(u))
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let _ = events.emit(RadioEvent::Seen {
                addr: RadioAddr(dev),
                uuids,
                rssi,
            });
        }
        FromHelper::Connected {
            conn: wire,
            role,
            service,
            max_tx,
            max_rx,
        } => {
            let Some(conn) = link.conn_of(wire) else {
                return;
            };
            let sizes = proto::MIN_TX..=proto::MAX_FRAME;
            let service = proto::uuid_from(&service);
            let fits = {
                let mut t = lock(&link.table);
                let known = t.conns.get(&conn).map(|w| w.max_tx);
                let fits = service.is_some()
                    && sizes.contains(&max_tx)
                    && sizes.contains(&max_rx)
                    && match role {
                        // One raven-node opened, still connecting.
                        Side::Central => !wire.is_multiple_of(2) && known == Some(0),
                        Side::Peripheral => wire.is_multiple_of(2) && known.is_none(),
                    };
                if fits {
                    t.conns.entry(conn).or_default().max_tx = max_tx;
                }
                fits
            };
            let Some(service) = service.filter(|_| fits) else {
                link.lose(conn);
                return;
            };
            let role = match role {
                Side::Central => Role::Central,
                Side::Peripheral => Role::Peripheral,
            };
            lost(events.emit(RadioEvent::Connected {
                conn,
                role,
                service,
                max_tx,
                max_rx,
            }));
        }
        FromHelper::Frame { conn: wire, b64 } => {
            let Some(conn) = link.conn_of(wire) else {
                return;
            };
            if !lock(&link.table)
                .conns
                .get(&conn)
                .is_some_and(|w| w.max_tx > 0)
            {
                return;
            }
            match proto::frame_from(&b64) {
                Some(bytes) => lost(events.emit(RadioEvent::Frame { conn, bytes })),
                None => link.lose(conn),
            }
        }
        FromHelper::Sent { conn: wire } => {
            let Some(conn) = link.conn_of(wire) else {
                return;
            };
            let room = {
                let mut t = lock(&link.table);
                let Some(w) = t.conns.get_mut(&conn) else {
                    return;
                };
                w.in_flight = w.in_flight.saturating_sub(1);
                let room = w.want && w.in_flight < SEND_WINDOW;
                if room {
                    w.want = false;
                }
                room
            };
            if room {
                lost(events.emit(RadioEvent::Writable { conn }));
            }
        }
        FromHelper::Disconnected { conn: wire } => {
            let Some(conn) = link.conn_of(wire) else {
                return;
            };
            if lock(&link.table).conns.remove(&conn).is_some() {
                let _ = events.emit(RadioEvent::Disconnected { conn });
            }
        }
    }
}

fn gatt(t: &[u8; 16]) -> Gatt {
    Gatt {
        service: proto::uuid_hex(t),
        characteristic: proto::uuid_hex(&char_uuid(t)),
    }
}

impl Radio for HelperRadio {
    fn caps(&self) -> RadioCaps {
        caps()
    }

    fn set_services(
        &mut self,
        services: &[[u8; 16]],
        advertise: Option<[u8; 16]>,
    ) -> Result<(), String> {
        if services.len() > proto::MAX_SERVICES {
            return Err("too many services for the nearby helper".into());
        }
        if advertise.is_some_and(|t| !services.contains(&t)) {
            return Err("the advertised service is not published".into());
        }
        self.link.put(&ToHelper::Services {
            services: services.iter().map(gatt).collect(),
            advertise: advertise.as_ref().map(proto::uuid_hex),
        })
    }

    fn set_scanning(&mut self, on: bool) -> Result<(), String> {
        self.link.put(&ToHelper::Scan { on })
    }

    fn connect(&mut self, addr: &RadioAddr, service: [u8; 16]) -> Result<ConnId, String> {
        if addr.0.is_empty() || addr.0.len() > proto::MAX_DEV {
            return Err("not a device of this radio".into());
        }
        let conn = {
            let mut t = lock(&self.link.table);
            let wire = if t.last == 0 { 1 } else { t.last + 2 };
            let conn = self
                .link
                .conn_of(wire)
                .ok_or("the nearby helper ran out of connection numbers")?;
            t.last = wire;
            t.conns.insert(conn, Window::default());
            conn
        };
        let g = gatt(&service);
        let m = ToHelper::Connect {
            conn: conn & WIRE_MASK,
            dev: addr.0.clone(),
            service: g.service,
            characteristic: g.characteristic,
        };
        if let Err(e) = self.link.put(&m) {
            lock(&self.link.table).conns.remove(&conn);
            return Err(e);
        }
        Ok(conn)
    }

    fn send(&mut self, conn: ConnId, frame: &[u8]) -> Result<Sent, String> {
        let wire = self.link.wire_of(conn).ok_or("not connected")?;
        {
            let mut t = lock(&self.link.table);
            let w = t
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
            if w.in_flight >= SEND_WINDOW {
                w.want = true;
                return Ok(Sent::WouldBlock);
            }
            w.in_flight += 1;
        }
        let m = ToHelper::Send {
            conn: wire,
            b64: proto::b64_of(frame),
        };
        if let Err(e) = self.link.put(&m) {
            if let Some(w) = lock(&self.link.table).conns.get_mut(&conn) {
                w.in_flight = w.in_flight.saturating_sub(1);
            }
            return Err(e);
        }
        Ok(Sent::Queued)
    }

    fn disconnect(&mut self, conn: ConnId) {
        if lock(&self.link.table).conns.contains_key(&conn) {
            self.link.lose(conn);
        }
    }

    fn overflows(&self) -> u64 {
        self.link.overflows.load(Ordering::Relaxed)
    }
}

impl Drop for HelperRadio {
    /// The helper's stdin closes: it stops advertising and scanning, drops
    /// its links and exits (killed after [`REAP_WAIT`] if it does not).
    fn drop(&mut self) {
        self.link.stop(REAP_WAIT);
    }
}
