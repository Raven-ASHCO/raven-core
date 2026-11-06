//! The loopback Tor helper (debug builds only; `raven-node
//! tor-loopback-helper`): the helper protocol of [`super::proto`] with no
//! Tor network, so the onion carrier is tested end to end on one computer
//! (design §5; automated tests never touch the real Tor network).
//!
//! Its "onion service" is a loopback listener whose port it writes into the
//! registry directory under the hex of its onion key; a connect request
//! looks the key up there and connects to that port. Everything else is the
//! real protocol: the config line, the events, the token on both loopback
//! streams, the virtual port, the connect replies, ping and stop.
//!
//! Lab knobs (environment, read at start, for the supervisor's tests):
//! - `RAVEN_LAB_TOR_LOOPBACK_STALL=1`: bootstrap stops at 15 % and never
//!   finishes (Arti #2726);
//! - `RAVEN_LAB_TOR_LOOPBACK_OBSOLETE=1`: once ready, say Arti's obsolete
//!   version words on stderr and exit with 1 (Arti #1932);
//! - `RAVEN_LAB_TOR_LOOPBACK_DELAY_MS=<ms>`: every connect takes this long
//!   (a Tor rendezvous);
//! - `RAVEN_LAB_TOR_LOOPBACK_LATENCY_MS=<ms>`: on every stream this helper
//!   connects, each byte arrives this long after it was sent, both ways (a
//!   Tor circuit's one-way delay);
//! - `RAVEN_LAB_TOR_LOOPBACK_ONE_CIRCUIT=1` (on every helper of a test):
//!   every stream one helper connects to one "onion service" rides one
//!   circuit, as Arti keeps a rendezvous circuit for the streams that follow
//!   (the service side counts them under one circuit number);
//! - `RAVEN_LAB_TOR_LOOPBACK_READY_MS=<ms>`: the bootstrap takes this long
//!   before the helper is ready (a Tor start);
//! - `RAVEN_LAB_TOR_LOOPBACK_STALE_MS=<ms>`: the circuit the default
//!   isolation group shares is dead (the friend's network path vanished
//!   with no DESTROY back, audit T6): a connect try in that group waits this
//!   long and ends "tor timeout", as Arti's stream connect timeout ends a
//!   BEGIN that gets no CONNECTED; a try in any other group works;
//! - `RAVEN_LAB_TOR_LOOPBACK_COUNT=1`: the helper keeps its connect counts
//!   in [`COUNT_FILE`] under its state directory ([`Counts`]).
//!
//! Tests only (no variable): [`Knobs::rendezvous`], the price of a fresh
//! rendezvous, paid once per isolation group and onion key, and
//! [`Knobs::kill`]: every circuit the helper built so far dies with no word
//! when the test says so (`kill_circuits`), as one whose far end vanished
//! (audit T6). With neither, a connect behaves as above.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::proto::{self, Command, Config, ConnectReply, Event};
use super::LineReader;

const STALL_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_STALL";
const OBSOLETE_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_OBSOLETE";
const DELAY_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_DELAY_MS";
const LATENCY_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_LATENCY_MS";
const ONE_CIRCUIT_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_ONE_CIRCUIT";
const READY_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_READY_MS";
const STALE_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_STALE_MS";
const COUNT_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_COUNT";
/// How long one connect may take, as the Arti helper's.
const CONNECT_WAIT: Duration = Duration::from_secs(44);
/// The loopback helper's onion key seed, under the state directory.
const KEY_FILE: &str = "loopback_hs.key";
/// Where [`COUNT_ENV`] keeps the connect counts, under the state directory.
pub(crate) const COUNT_FILE: &str = "loopback_connects";

/// Behaviour knobs (see the module doc).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Knobs {
    pub(crate) stall: bool,
    pub(crate) obsolete: bool,
    pub(crate) delay: Duration,
    pub(crate) latency: Duration,
    /// [`ONE_CIRCUIT_ENV`]: this helper's client number, sent first on
    /// every stream it connects; the service side reads it.
    pub(crate) one_circuit: Option<u64>,
    /// [`READY_ENV`]: how long the bootstrap takes.
    pub(crate) ready: Duration,
    /// [`STALE_ENV`]: how long a try in the default isolation group waits
    /// before it ends "tor timeout" (zero: that group works); a try in a
    /// group whose circuit was killed ([`Self::kill`]) waits as long.
    pub(crate) stale: Duration,
    /// [`COUNT_ENV`].
    pub(crate) count: bool,
    /// Tests only: what the first try in an isolation group to an onion
    /// service pays before its connect (a fresh rendezvous: the descriptor,
    /// the introduction and the rendezvous circuits); the tries after it in
    /// that group ride the circuit it built and pay [`Self::delay`] alone
    /// (Arti keeps a rendezvous circuit for 10 minutes after its last use;
    /// a test is shorter). Zero: no rendezvous price.
    pub(crate) rendezvous: Duration,
    /// Tests only: the test's kill count (`kill_circuits`). A circuit
    /// built before its last rise is dead: its streams carry nothing more
    /// and never close, and a try in its group waits [`Self::stale`] and
    /// ends "tor timeout". `None`: no circuit dies.
    pub(crate) kill: Option<&'static AtomicU64>,
}

/// One helper life's connect counts ([`COUNT_ENV`]), kept in [`COUNT_FILE`]
/// as one line: `connects=N tries=N stale=N`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    /// Connect requests from raven-node with the right token and port.
    pub(crate) connects: u64,
    /// Connect tries made for them (a first try, and a fresh one after a
    /// failure worth it).
    pub(crate) tries: u64,
    /// Tries that met the dead shared circuit ([`STALE_ENV`]).
    pub(crate) stale: u64,
}

impl Counts {
    /// The counts in `state_dir` (all zero when there are none yet).
    #[cfg(test)]
    pub(crate) fn read(state_dir: &Path) -> Self {
        let text = std::fs::read_to_string(state_dir.join(COUNT_FILE)).unwrap_or_default();
        let mut counts = Self::default();
        for (name, value) in text
            .split_whitespace()
            .filter_map(|pair| pair.split_once('='))
        {
            let value = value.parse().unwrap_or(0);
            match name {
                "connects" => counts.connects = value,
                "tries" => counts.tries = value,
                "stale" => counts.stale = value,
                _ => {}
            }
        }
        counts
    }

    fn line(&self) -> String {
        format!(
            "connects={} tries={} stale={}\n",
            self.connects, self.tries, self.stale
        )
    }
}

/// [`Counts`] as they change, written to `file` each time (`None`: not
/// kept).
#[derive(Clone)]
struct Counter(Option<Arc<(PathBuf, std::sync::Mutex<Counts>)>>);

impl Counter {
    fn new(knobs: &Knobs, state_dir: &Path) -> Self {
        Self(knobs.count.then(|| {
            let file = state_dir.join(COUNT_FILE);
            let _ = std::fs::remove_file(&file);
            Arc::new((file, std::sync::Mutex::new(Counts::default())))
        }))
    }

    fn add(&self, f: impl FnOnce(&mut Counts)) {
        let Some(kept) = &self.0 else {
            return;
        };
        let (file, counts) = &**kept;
        let mut counts = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut counts);
        let _ = raven_core::paths::atomic_write_private(file, counts.line().as_bytes());
    }
}

impl Knobs {
    fn from_env() -> Self {
        let on = |name| std::env::var(name).is_ok_and(|v| v == "1");
        let ms = |name| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map_or(Duration::ZERO, |ms| Duration::from_millis(ms.min(60_000)))
        };
        Self {
            stall: on(STALL_ENV),
            obsolete: on(OBSOLETE_ENV),
            delay: ms(DELAY_ENV),
            latency: ms(LATENCY_ENV),
            one_circuit: on(ONE_CIRCUIT_ENV).then(rand::random::<u64>),
            ready: ms(READY_ENV),
            stale: ms(STALE_ENV),
            count: on(COUNT_ENV),
            rendezvous: Duration::ZERO,
            kill: None,
        }
    }
}

/// Tests: every circuit the helper whose [`Knobs::kill`] is `kill` built so
/// far dies with no word (its far end vanished, no DESTROY came back; audit
/// T6). A circuit it builds after this works.
#[cfg(test)]
pub(crate) fn kill_circuits(kill: &AtomicU64) {
    kill.fetch_add(1, Ordering::SeqCst);
}

/// The circuits one helper life built: per isolation group and onion key,
/// the kill count when it was built ([`Life`]).
type Circuits = std::collections::HashMap<(Option<u64>, [u8; 32]), u64>;

/// When a circuit was built, against its helper's kill count
/// ([`Knobs::kill`]).
#[derive(Clone, Copy)]
struct Life {
    kill: Option<&'static AtomicU64>,
    built: u64,
}

impl Life {
    /// The kill count now (0 without one: no circuit dies).
    fn now(kill: Option<&'static AtomicU64>) -> u64 {
        kill.map_or(0, |k| k.load(Ordering::SeqCst))
    }

    /// A circuit built now.
    fn new(kill: Option<&'static AtomicU64>) -> Self {
        Self {
            kill,
            built: Self::now(kill),
        }
    }

    /// It died since it was built.
    fn dead(&self) -> bool {
        self.built < Self::now(self.kill)
    }
}

/// `raven-node tor-loopback-helper --registry DIR`: serve on this process's
/// stdin and stdout; the exit code.
pub(crate) async fn run_cli(registry: PathBuf) -> i32 {
    let knobs = Knobs::from_env();
    match serve(
        Box::pin(tokio::io::stdin()),
        Box::pin(tokio::io::stdout()),
        registry,
        knobs,
    )
    .await
    {
        Ok(Ended::Stopped) => 0,
        Ok(Ended::Obsolete) => {
            eprintln!("Shutting down because of unsupported software version.");
            1
        }
        Err(e) => {
            eprintln!("tor-loopback-helper: {e}");
            2
        }
    }
}

/// The loopback helper inside raven-node's process (feature
/// `tor-embedded`, [`super::InProcess`]): [`serve`] on in-memory pipes, the
/// knobs from the environment, as [`run_cli`] reads them.
#[cfg(feature = "tor-embedded")]
pub(crate) async fn serve_in_process<R, W>(input: R, output: W, registry: PathBuf) -> i32
where
    R: AsyncRead + Send + 'static,
    W: AsyncWrite + Send + 'static,
{
    match serve(
        Box::pin(input),
        Box::pin(output),
        registry,
        Knobs::from_env(),
    )
    .await
    {
        Ok(Ended::Stopped) => 0,
        // As the Arti helper in process says it.
        Ok(Ended::Obsolete) => super::arti::EXIT_OBSOLETE,
        Err(e) => {
            eprintln!("raven-node onion: in-process loopback helper: {e}");
            2
        }
    }
}

/// How [`serve`] ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Ended {
    /// Stop, or stdin closed.
    Stopped,
    /// The obsolete knob.
    Obsolete,
}

/// The helper on `input` and `output` (the config line first).
pub(crate) async fn serve(
    input: Pin<Box<dyn AsyncRead + Send>>,
    mut output: Pin<Box<dyn AsyncWrite + Send>>,
    registry: PathBuf,
    knobs: Knobs,
) -> Result<Ended, String> {
    let mut lines = LineReader::new(input);
    let first = lines.next_line().await.ok_or("no config line")?;
    let config: Config = serde_json::from_str(&first).map_err(|_| "bad config line")?;
    if config.v != proto::PROTO_VERSION {
        return Err("unknown protocol version".into());
    }
    let token = proto::parse_token(&config.token).ok_or("bad token")?;
    let forward: std::net::SocketAddr = config.forward.parse().map_err(|_| "bad forward")?;
    let state_dir = PathBuf::from(&config.state_dir);
    let hs = hs_identity(&state_dir)?;
    let hs_id = hs.public_key_bytes();

    for (pct, stage) in [(10u8, "handshaking"), (15, "consensus")] {
        let ev = Event::Progress {
            pct,
            blocked: None,
            stage: Some(stage.into()),
        };
        send(&mut output, &ev).await?;
    }
    // A Tor start that takes a while.
    tokio::time::sleep(knobs.ready).await;
    if knobs.stall {
        // Never ready; answers nothing; waits to be killed.
        loop {
            if lines.next_line().await.is_none() {
                return Ok(Ended::Stopped);
            }
        }
    }
    send(
        &mut output,
        &Event::Progress {
            pct: 100,
            blocked: None,
            stage: Some("usable".into()),
        },
    )
    .await?;

    // The "onion service": a loopback port, registered under its key.
    let service = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| e.to_string())?;
    let service_addr = service.local_addr().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&registry).map_err(|e| e.to_string())?;
    let entry = registry.join(hex::encode(hs_id));
    std::fs::write(&entry, service_addr.to_string()).map_err(|e| e.to_string())?;
    let _registered = Unregister(entry);
    let accepting = tokio::spawn(accept_service(
        service,
        forward,
        token,
        knobs.one_circuit.is_some(),
    ));
    let _accepting = AbortOnDrop(accepting);

    // The connect port.
    let connect = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| e.to_string())?;
    let connect_addr = connect.local_addr().map_err(|e| e.to_string())?;
    let connecting = tokio::spawn(accept_connects(
        connect,
        token,
        config.port,
        Arc::new(registry.clone()),
        knobs,
        Counter::new(&knobs, &state_dir),
    ));
    let _connecting = AbortOnDrop(connecting);
    send(
        &mut output,
        &Event::Ready {
            connect: connect_addr.to_string(),
        },
    )
    .await?;
    send(
        &mut output,
        &Event::Onion {
            hs_id: hex::encode(hs_id),
        },
    )
    .await?;
    send(
        &mut output,
        &Event::Service {
            state: proto::ServiceState::Running.word().into(),
            reason: None,
        },
    )
    .await?;
    if knobs.obsolete {
        return Ok(Ended::Obsolete);
    }
    while let Some(line) = lines.next_line().await {
        match serde_json::from_str::<Command>(&line) {
            Ok(Command::Ping { n }) => send(&mut output, &Event::Pong { n }).await?,
            // Its own "service" reached as a friend would: registered.
            Ok(Command::SelfCheck { n }) => {
                let reached = registry.join(hex::encode(hs_id)).is_file();
                let reason = (!reached).then(|| "no descriptor".to_string());
                send(&mut output, &Event::SelfCheck { n, reached, reason }).await?;
            }
            Ok(Command::Stop) => break,
            Err(_) => {}
        }
    }
    Ok(Ended::Stopped)
}

/// One event line, flushed.
async fn send(out: &mut Pin<Box<dyn AsyncWrite + Send>>, ev: &Event) -> Result<(), String> {
    out.write_all(proto::line(ev).as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    out.flush().await.map_err(|e| e.to_string())
}

/// The loopback helper's onion key: a seed kept in the state directory, so
/// a restarted helper keeps its "address" (as Arti's keystore does).
fn hs_identity(state_dir: &Path) -> Result<raven_core::identity::Identity, String> {
    let path = state_dir.join(KEY_FILE);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(raven_core::identity::Identity::from_seed(&seed));
        }
    }
    let seed: [u8; 32] = rand::random();
    std::fs::create_dir_all(state_dir).map_err(|e| e.to_string())?;
    raven_core::paths::atomic_write_private(&path, &seed)?;
    Ok(raven_core::identity::Identity::from_seed(&seed))
}

struct Unregister(PathBuf);

impl Drop for Unregister {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Every stream into the "onion service" goes to raven-node's forward
/// listener, the token and a circuit number first (each stream here is its
/// own "circuit"; with `one_circuit`, each connecting helper's streams
/// share one, [`ONE_CIRCUIT_ENV`]).
async fn accept_service(
    listener: TcpListener,
    forward: std::net::SocketAddr,
    token: [u8; 32],
    one_circuit: bool,
) {
    let circuits = Arc::new(std::sync::Mutex::new((
        0u64,
        std::collections::HashMap::new(),
    )));
    loop {
        let Ok((mut inbound, _)) = listener.accept().await else {
            continue;
        };
        let circuits = Arc::clone(&circuits);
        tokio::spawn(async move {
            let client = if one_circuit {
                let mut id = [0u8; 8];
                let read =
                    tokio::time::timeout(Duration::from_secs(10), inbound.read_exact(&mut id));
                if !matches!(read.await, Ok(Ok(_))) {
                    return;
                }
                Some(u64::from_be_bytes(id))
            } else {
                None
            };
            let circuit = {
                let mut c = circuits
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let (next, by_client) = &mut *c;
                match client {
                    Some(client) => *by_client.entry(client).or_insert_with(|| {
                        *next += 1;
                        *next
                    }),
                    None => {
                        *next += 1;
                        *next
                    }
                }
            };
            let Ok(mut out) = TcpStream::connect(forward).await else {
                return;
            };
            let _ = out.set_nodelay(true);
            if out
                .write_all(&proto::encode_forward(&token, circuit))
                .await
                .is_err()
            {
                return;
            }
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut out).await;
        });
    }
}

/// raven-node's connect requests: the token, a registered key and the
/// virtual port, then the bytes.
async fn accept_connects(
    listener: TcpListener,
    token: [u8; 32],
    port: u16,
    registry: Arc<PathBuf>,
    knobs: Knobs,
    counter: Counter,
) {
    let (delay, latency, one_circuit) = (knobs.delay, knobs.latency, knobs.one_circuit);
    // Each friend's isolation group, for this helper life (as the Arti
    // helper's), and the circuits built in them.
    let book = Arc::new(std::sync::Mutex::new(proto::IsolationBook::new(new_group)));
    let circuits: Arc<std::sync::Mutex<Circuits>> = Arc::default();
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let (registry, counter, book) = (registry.clone(), counter.clone(), book.clone());
        let circuits = circuits.clone();
        tokio::spawn(async move {
            let mut req = [0u8; proto::CONNECT_REQUEST_LEN];
            if stream.read_exact(&mut req).await.is_err() {
                return;
            }
            let Some((hs_id, asked, flags)) = proto::decode_connect(&req, &token) else {
                // Not raven-node: closed without a word.
                return;
            };
            if proto::unknown_flags(flags) {
                let refused = ConnectReply::Failed(proto::UNKNOWN_FLAGS.into());
                let _ = stream.write_all(&refused.encode()).await;
                return;
            }
            if asked != port {
                let _ = stream
                    .write_all(&ConnectReply::Unreachable("port refused".into()).encode())
                    .await;
                return;
            }
            counter.add(|c| c.connects += 1);
            // As the Arti helper: the first try in the friend's isolation
            // group, one more in a new group after a failure worth it (here
            // the registry is read again, as Arti fetches the descriptor
            // again); the flags as there (speed design M5).
            let opened =
                proto::connect_in_groups(CONNECT_WAIT, &book, hs_id, flags, |group, _within| {
                    let (registry, counter) = (registry.clone(), counter.clone());
                    let circuits = circuits.clone();
                    let built = lock(&circuits).get(&(group, hs_id)).map(|&built| Life {
                        kill: knobs.kill,
                        built,
                    });
                    let dead = (group.is_none() && !knobs.stale.is_zero())
                        || built.is_some_and(|life| life.dead());
                    async move {
                        counter.add(|c| {
                            c.tries += 1;
                            c.stale += u64::from(dead);
                        });
                        if dead {
                            tokio::time::sleep(knobs.stale).await;
                            return Err(ConnectReply::Timeout("tor timeout".into()));
                        }
                        let built = match built {
                            Some(life) => life,
                            None => {
                                tokio::time::sleep(knobs.rendezvous).await;
                                let life = Life::new(knobs.kill);
                                let built =
                                    *lock(&circuits).entry((group, hs_id)).or_insert(life.built);
                                Life { built, ..life }
                            }
                        };
                        tokio::time::sleep(delay).await;
                        let target = std::fs::read_to_string(registry.join(hex::encode(hs_id)))
                            .ok()
                            .and_then(|t| t.trim().parse::<std::net::SocketAddr>().ok())
                            .ok_or_else(|| ConnectReply::Unreachable("no descriptor".into()))?;
                        let mut out = TcpStream::connect(target)
                            .await
                            .map_err(|_| ConnectReply::Unreachable("rendezvous failed".into()))?;
                        if let Some(client) = one_circuit {
                            out.write_all(&client.to_be_bytes()).await.map_err(|_| {
                                ConnectReply::Unreachable("rendezvous failed".into())
                            })?;
                        }
                        Ok((out, built))
                    }
                })
                .await;
            let (out, built) = match opened {
                Ok(opened) => opened,
                Err(reply) => {
                    let _ = stream.write_all(&reply.encode()).await;
                    return;
                }
            };
            if stream.write_all(&ConnectReply::Ok.encode()).await.is_err() {
                return;
            }
            let _ = out.set_nodelay(true);
            relay(stream, out, latency, built).await;
        });
    }
}

fn lock(circuits: &std::sync::Mutex<Circuits>) -> std::sync::MutexGuard<'_, Circuits> {
    circuits
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A loopback isolation group no connect used yet.
fn new_group() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Both ways between `a` and `b`, each chunk arriving `latency` after it
/// was read (a Tor circuit's one-way delay; [`LATENCY_ENV`]), an end of
/// stream too; a plain copy without one, unless its circuit (`built`) may
/// die ([`Knobs::kill`]).
async fn relay(mut a: TcpStream, mut b: TcpStream, latency: Duration, built: Life) {
    if latency.is_zero() && built.kill.is_none() {
        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
        return;
    }
    let (a_read, a_write) = a.into_split();
    let (b_read, b_write) = b.into_split();
    tokio::join!(
        delayed_copy(a_read, b_write, latency, built),
        delayed_copy(b_read, a_write, latency, built),
    );
}

/// One way of [`relay`]: once its circuit is dead ([`Life::dead`]) nothing
/// more arrives, not even the end of the stream.
async fn delayed_copy(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    latency: Duration,
    built: Life,
) {
    // `None`: the end of stream, which travels as long as the bytes do.
    let (tx, mut rx) =
        tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Option<Vec<u8>>)>();
    let read = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let got = match from.read(&mut buf).await {
                Ok(n) if n > 0 => Some(buf[..n].to_vec()),
                _ => None,
            };
            let end = got.is_none();
            if tx
                .send((tokio::time::Instant::now() + latency, got))
                .is_err()
                || end
            {
                return;
            }
        }
    };
    let write = async move {
        while let Some((at, bytes)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            if built.dead() {
                std::future::pending::<()>().await;
            }
            match bytes {
                Some(bytes) if to.write_all(&bytes).await.is_ok() => {}
                _ => break,
            }
        }
        let _ = to.shutdown().await;
    };
    tokio::join!(read, write);
}
