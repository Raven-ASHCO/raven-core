//! Arti (the Rust Tor implementation) for one raven-node: the Tor helper's
//! own code, shared by the `raven-tor-helper` program (feature `tor`, its
//! own process: src/bin/raven-tor-helper/main.rs) and the in-process helper
//! (feature `tor-embedded`, for the iOS app, which may start no helper
//! process: [`super::InProcess`]). Both speak the protocol of [`super::proto`]
//! with raven-node: one config line in, events out, `ping`, `self-check`
//! and `stop` in; the program over its stdin and stdout, the in-process
//! helper over in-memory pipes. Everything below is the same in both.
//!
//! It runs a Tor client and one onion service (nickname `raven`, key kept by
//! Arti under the profile's `tor/` directory), forwards every accepted
//! stream on the virtual port to raven-node's forward listener (token and
//! circuit number first), and opens Tor streams to onion services for
//! raven-node's connect requests (token checked). It never sees a Raven key
//! or a message: the Raven link runs end to end inside the streams.
//!
//! Both kinds of stream ride the helper channel ([`super::channel`],
//! version 4: a socket pair on macOS and Linux, loopback ports on
//! Windows), and on each the helper proves the token first.
//!
//! It ends when its input closes (raven-node is gone) or on `stop`.
//!
//! Its output carries events only. Its only log subscriber
//! ([`upload_rounds`]) reads one Arti debug line, the descriptor upload
//! round's counts: Arti's other log lines (which may name relays) go
//! nowhere, and none of its events names an onion address of a friend.
//!
//! Arti's defaults, except: channel padding `reduced` (laptops and
//! phones), no exit circuits built ahead of need, a stream's BEGIN given
//! up after [`STREAM_CONNECT_TIMEOUT`], at most [`MAX_STREAMS_PER_CIRCUIT`]
//! streams per rendezvous circuit and an introduction rate limit sent to
//! the introduction points. The service keeps at most
//! [`MAX_RENDEZVOUS_CIRCUITS`] rendezvous circuits and closes one that went
//! [`RENDEZVOUS_IDLE`] without a stream ([`keep_rendezvous`]).
//! No bridges, no pluggable transports, no proof-of-work, no experimental
//! APIs.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::{HasKind as _, IsolationToken, StreamPrefs, TorClient};
use futures::stream::BoxStream;
use futures::{Stream, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tor_rtcompat::PreferredRuntime;

use super::channel;
use super::proto::{self, Command, Config, ConnectReply, Event, ServiceState};

/// How long one Tor connect may take (raven-node waits 45 s in all).
const CONNECT_WAIT: Duration = Duration::from_secs(44);

/// How long Arti waits for CONNECTED after a stream's BEGIN, once it has
/// the rendezvous circuit (its `connect_timeout`, 10 s by default). The
/// descriptor fetch, the introduction and the rendezvous keep their own
/// timeouts. A healthy BEGIN is one onion round trip (typically under a
/// second); one on a shared circuit whose far end vanished with no DESTROY
/// gets no answer at all (audit T6), and the fresh try in a new group
/// starts only after it.
const STREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(6);

/// Streams one rendezvous circuit may hold open at once; one more tears the
/// circuit down (RAVEN_ONION_CARRIER_V1 §5).
const MAX_STREAMS_PER_CIRCUIT: u32 = 8;

/// Introductions per second our introduction points pass on, and their
/// burst (the EST_INTRO DoS extension; C Tor's defaults are 25 and 200, a
/// personal service needs far fewer).
const INTRO_RATE_PER_S: u32 = 5;
const INTRO_BURST: u32 = 20;

/// Rendezvous circuits the helper keeps at once (TOR-5): a newcomer closes
/// the one that has gone longest without a stream, or is refused while each
/// carries one (RAVEN_ONION_CARRIER_V1 §5). raven-node holds at most 16
/// links, so most of them are quiet.
const MAX_RENDEZVOUS_CIRCUITS: usize = 64;

/// A rendezvous circuit that has carried no stream for this long is closed
/// (TOR-5). A client keeps its own rendezvous circuit as long after its last
/// use (Arti, RAVEN_ONION_CARRIER_V1 §10), so a friend's next dial still
/// finds its circuit.
const RENDEZVOUS_IDLE: Duration = Duration::from_secs(10 * 60);

/// Events to raven-node, one writer.
#[derive(Clone)]
struct Events(mpsc::UnboundedSender<Event>);

impl Events {
    fn say(&self, ev: Event) {
        let _ = self.0.send(ev);
    }

    /// A failure caused by the network or Tor (raven-node decides).
    fn error(&self, what: &str) {
        self.say(Event::Error {
            what: what.into(),
            local: false,
        });
    }

    /// A failure on this computer: Tor cannot start here, whatever the
    /// network.
    fn local(&self, what: &str) {
        self.say(Event::Error {
            what: what.into(),
            local: true,
        });
    }

    /// An Arti error as its fixed tag ([`kind_tag`]).
    fn arti(&self, during: &str, kind: arti_client::ErrorKind) {
        let (tag, local) = kind_tag(kind);
        self.say(Event::Error {
            what: format!("{during}: {tag}"),
            local,
        });
    }
}

/// The exit code of a helper life the Tor network found too old: it requires
/// a protocol this Arti lacks (Arti #1932). Arti's own `exit(1)` is replaced
/// by a hook (third_party/arti-client-0.47.0-raven/RAVEN_DELTA.md); the host
/// then says [`OBSOLETE_WORDS`] where raven-node reads the helper's stderr.
pub(crate) const EXIT_OBSOLETE: i32 = 5;
/// The words raven-node's supervisor reads as "too old" (upstream Arti's).
pub(crate) const OBSOLETE_WORDS: &str = "Shutting down because of unsupported software version.";

/// One helper life's "too old" signal.
#[derive(Default)]
pub(crate) struct TooOld {
    /// The signal came (read after the life ended).
    pub(crate) said: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

/// The current life's signal: Arti's hook is set once per process, and an
/// in-process helper has many lives.
static TOO_OLD: std::sync::Mutex<Option<Arc<TooOld>>> = std::sync::Mutex::new(None);

/// The Tor network requires a protocol this Arti lacks: this life ends.
fn too_old() {
    if let Some(life) = TOO_OLD.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        life.said.store(true, std::sync::atomic::Ordering::Release);
        life.notify.notify_one();
    }
}

/// This life gets the "too old" signal: Arti's hook (set once) and the
/// errors that say the same at start.
pub(crate) fn watch_too_old() -> Arc<TooOld> {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let _ = arti_client::raven_delta::on_unsupported_software(Box::new(too_old));
    });
    let life = Arc::new(TooOld::default());
    *TOO_OLD.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&life));
    life
}

/// The helper on `input` (raven-node's lines) and `output` (its events),
/// until `input` closes, `stop`, or Tor gives up for good; the exit code
/// (0 asked to stop, 2 a bad config line, 4 Tor gave up, [`EXIT_OBSOLETE`]
/// the Tor network requires a newer Tor). `handed`: what raven-node handed
/// a helper in its own process besides the pipes ([`channel::Handed`]).
pub(crate) async fn serve<R, W>(input: R, output: W, handed: channel::Handed) -> i32
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    let events = Events(tx);
    let writer = tokio::spawn(async move {
        let mut out = output;
        while let Some(ev) = rx.recv().await {
            if out.write_all(proto::line(&ev).as_bytes()).await.is_err()
                || out.flush().await.is_err()
            {
                break;
            }
        }
    });
    let mut stdin = BufReader::new(input).lines();
    let Ok(Some(first)) = stdin.next_line().await else {
        return refused(events, writer).await;
    };
    let Ok(config) = serde_json::from_str::<Config>(&first) else {
        events.local("bad config line");
        return refused(events, writer).await;
    };
    if config.v != proto::PROTO_VERSION {
        events.local("unknown protocol version");
        return refused(events, writer).await;
    }
    let Some(token) = proto::parse_token(&config.token) else {
        events.local("bad token");
        return refused(events, writer).await;
    };
    // The helper channel (macOS, Linux) or raven-node's loopback forward
    // listener (Windows).
    let forward = match channel::ToNode::from_config(&config.forward, handed) {
        Ok(to_node) => to_node,
        Err(what) => {
            events.local(what);
            return refused(events, writer).await;
        }
    };
    let state_dir = PathBuf::from(&config.state_dir);
    if config.fresh_state {
        set_guard_state_aside(&state_dir);
    }
    upload_rounds::install(events.clone());
    let obsolete = watch_too_old();

    // Everything Tor does runs in this task; stdin ends it.
    let (checks, check_requests) = mpsc::unbounded_channel::<u64>();
    let mut tor = tokio::spawn(tor_main(
        state_dir,
        token,
        forward,
        config.port,
        events.clone(),
        check_requests,
    ));
    let mut code = 0;
    loop {
        tokio::select! {
            line = stdin.next_line() => match line {
                Ok(Some(line)) => match serde_json::from_str::<Command>(&line) {
                    Ok(Command::Ping { n }) => events.say(Event::Pong { n }),
                    Ok(Command::SelfCheck { n }) => {
                        let _ = checks.send(n);
                    }
                    Ok(Command::Stop) => break,
                    Err(_) => {}
                },
                // raven-node is gone.
                _ => break,
            },
            // Tor gave up for good (its error event said why): exit, so
            // raven-node starts a fresh helper with backoff.
            _ = &mut tor => {
                code = 4;
                break;
            }
            // The Tor network requires a protocol this Arti lacks: this
            // client must stop (the host tells raven-node, which keeps Tor
            // off).
            () = obsolete.notify.notified() => break,
        }
    }
    if obsolete.said.load(std::sync::atomic::Ordering::Acquire) {
        code = EXIT_OBSOLETE;
    }
    tor.abort();
    said(events, writer).await;
    code
}

/// [`said`], then 2: the config line refused.
async fn refused(events: Events, writer: tokio::task::JoinHandle<()>) -> i32 {
    said(events, writer).await;
    2
}

/// `events` closed and its writer given half a second to write what is
/// left: the helper's last words reach raven-node before [`serve`]
/// returns (a helper process exits right after, and a line still with
/// the writer task would be lost).
async fn said(events: Events, writer: tokio::task::JoinHandle<()>) {
    drop(events);
    let _ = tokio::time::timeout(Duration::from_millis(500), writer).await;
}

/// The guard state (Arti's `state/` under its state directory) set aside,
/// keys and cache kept (Arti issue #2534: guard state that poisons itself).
fn set_guard_state_aside(state_dir: &Path) {
    let guards = state_dir.join("state").join("state");
    if guards.is_dir() {
        let aside = state_dir.join("state").join("state.old");
        let _ = std::fs::remove_dir_all(&aside);
        let _ = std::fs::rename(&guards, &aside);
    }
}

async fn tor_main(
    state_dir: PathBuf,
    token: [u8; proto::TOKEN_LEN],
    forward: channel::ToNode,
    port: u16,
    events: Events,
    mut check_requests: mpsc::UnboundedReceiver<u64>,
) {
    let config = match client_config(&state_dir) {
        Ok(c) => c,
        Err(_) => return events.local("Tor configuration refused"),
    };
    let client = match TorClient::with_runtime(match PreferredRuntime::current() {
        Ok(rt) => rt,
        Err(_) => return events.local("no runtime"),
    })
    .config(config)
    .create_unbootstrapped()
    {
        Ok(c) => c,
        Err(e) => {
            // A cached consensus already says this Arti is too old.
            if e.kind() == arti_client::ErrorKind::SoftwareDeprecated {
                too_old();
            }
            return events.arti("Tor client not created", e.kind());
        }
    };

    // Bootstrap progress, as percent and Tor's own word for a blockage.
    let mut progress = client.bootstrap_events();
    let reporter = {
        let events = events.clone();
        tokio::spawn(async move {
            let mut last: Option<(u8, Option<&'static str>, &'static str)> = None;
            while let Some(status) = progress.next().await {
                let pct = (status.as_frac().clamp(0.0, 1.0) * 100.0) as u8;
                let blocked = status
                    .blocked()
                    .map(|b| proto::blockage_word(&b.kind().to_string()));
                // Only the fixed word leaves this process (the display
                // names times, a stuck one may name a relay).
                let stage = proto::stage_word(&status.to_string());
                if last != Some((pct, blocked, stage)) {
                    last = Some((pct, blocked, stage));
                    events.say(Event::Progress {
                        pct,
                        blocked: blocked.map(String::from),
                        stage: Some(stage.into()),
                    });
                }
            }
        })
    };
    if let Err(e) = client.bootstrap().await {
        // raven-node's watchdogs decide; a cause on this computer is said
        // as such. Too old for the Tor network ends this life.
        if e.kind() == arti_client::ErrorKind::SoftwareDeprecated {
            too_old();
        }
        events.arti("bootstrap failed", e.kind());
        reporter.abort();
        return std::future::pending().await;
    }

    // Outbound: raven-node's connect requests, on the channel (macOS,
    // Linux) or a loopback port of this helper's own (Windows).
    let keys = channel::Keys::new(&token);
    let (connects, connect) = match &forward {
        #[cfg(unix)]
        channel::ToNode::Channel(conduit) => (
            Connects::Channel(Arc::clone(conduit)),
            channel::CONDUIT.to_string(),
        ),
        channel::ToNode::Port(_) => {
            let listener = match TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await {
                Ok(l) => l,
                Err(_) => return events.local("connect port could not be opened"),
            };
            let connect = match listener.local_addr() {
                Ok(a) => a,
                Err(_) => return events.local("connect port has no address"),
            };
            (Connects::Port(listener), connect.to_string())
        }
    };
    tokio::spawn(accept_connects(connects, client.clone(), keys.clone()));
    events.say(Event::Ready { connect });

    // Inbound: the onion service.
    let nickname = match "raven".parse() {
        Ok(n) => n,
        Err(_) => return events.local("bad service nickname"),
    };
    let svc_config = match OnionServiceConfigBuilder::default()
        .nickname(nickname)
        // A client opening more streams than this on one rendezvous
        // circuit gets the circuit torn down (Tor's
        // HiddenServiceMaxStreamsCloseCircuit). A friend's dial is one
        // stream; raven-node also counts its slots per circuit.
        .max_concurrent_streams_per_circuit(MAX_STREAMS_PER_CIRCUIT)
        // DoS parameters sent to our introduction points: they pass on at
        // most this many introductions per second (burst as given).
        .rate_limit_at_intro(Some(tor_hsservice::config::TokenBucketConfig::new(
            INTRO_RATE_PER_S,
            INTRO_BURST,
        )))
        .build()
    {
        Ok(c) => c,
        Err(_) => return events.local("onion service configuration refused"),
    };
    let (service, requests) = match client.launch_onion_service(svc_config) {
        Ok(Some(s)) => s,
        Ok(None) => return events.error("onion service disabled"),
        Err(e) => return events.arti("onion service not launched", e.kind()),
    };
    let own = match service.onion_address() {
        Some(hs_id) => {
            let bytes: [u8; 32] = hs_id.into();
            events.say(Event::Onion {
                hs_id: hex::encode(bytes),
            });
            hs_id
        }
        None => return events.error("onion service has no key"),
    };
    // Self-checks: our own service reached as a friend would reach it.
    {
        let (client, events) = (client.clone(), events.clone());
        tokio::spawn(async move {
            while let Some(n) = check_requests.recv().await {
                let (reached, reason) = match self_check(&client, &own).await {
                    Ok(()) => (true, None),
                    Err(reply) => (false, Some(reply.reason().to_string())),
                };
                events.say(Event::SelfCheck { n, reached, reason });
            }
        });
    }
    {
        let events = events.clone();
        let mut states = service.status_events();
        tokio::spawn(async move {
            let mut last = None;
            while let Some(status) = states.next().await {
                let state = service_state(status.state());
                let reason = problem_reason(status.current_problem());
                if last != Some((state, reason)) {
                    last = Some((state, reason));
                    events.say(Event::Service {
                        state: state.word().into(),
                        reason: reason.map(String::from),
                    });
                }
            }
        });
    }
    keep_rendezvous(Box::pin(requests), move |request, circuit| {
        forward_stream(request, forward.clone(), keys.clone(), port, circuit)
    })
    .await;
    // The service ended (it should not): raven-node notices nothing more
    // and restarts the helper when it stops answering.
    events.error("onion service ended");
    drop(service);
}

/// One rendezvous request as the accept loop sees it: Arti's
/// [`tor_hsservice::RendRequest`], or a test's.
trait Rendezvous: Send + 'static {
    /// A request for a stream on the circuit.
    type Request: Send + 'static;

    /// Build the circuit to the client's rendezvous point: the circuit's
    /// stream requests, or `None` if it failed. The circuit lives as long as
    /// they and its streams are held (tor-hsservice `RendRequest::accept`).
    fn open(self) -> impl Future<Output = Option<BoxStream<'static, Self::Request>>> + Send;
}

impl Rendezvous for tor_hsservice::RendRequest {
    type Request = tor_hsservice::StreamRequest;

    async fn open(self) -> Option<BoxStream<'static, Self::Request>> {
        self.accept().await.ok().map(StreamExt::boxed)
    }
}

/// The onion service's rendezvous circuits, each with its streams
/// (`serve`). Each circuit gets its own number, sent to raven-node after the
/// token with each of its streams: raven-node counts its slots per circuit,
/// so one client cannot take them all. The numbers are opaque and never
/// reused in this life.
///
/// Each circuit is an introduction someone made, and its client may keep it
/// with no stream for as long as it likes (TOR-5). So at most
/// [`MAX_RENDEZVOUS_CIRCUITS`] are kept: a newcomer closes the circuit that
/// has gone longest without a stream, and is refused while every circuit
/// carries one (no link in use is cut for it); and a circuit with no stream
/// for [`RENDEZVOUS_IDLE`] is closed.
async fn keep_rendezvous<R, F, Fut>(mut requests: impl Stream<Item = R> + Unpin, serve: F)
where
    R: Rendezvous,
    F: Fn(R::Request, u64) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut live: BTreeMap<u64, Kept> = BTreeMap::new();
    let mut circuits: u64 = 0;
    while let Some(rend) = requests.next().await {
        // Circuits that ended (their client closed them, idle, not built).
        live.retain(|_, kept| !kept.close.is_closed());
        if live.len() >= MAX_RENDEZVOUS_CIRCUITS && !make_room(&mut live) {
            // Refused: the request is dropped, as Arti's
            // `RendRequest::reject` does (the client hears nothing).
            continue;
        }
        circuits += 1;
        let usage = Arc::new(Mutex::new(Usage::Quiet(Instant::now())));
        let (close, closed) = oneshot::channel();
        live.insert(
            circuits,
            Kept {
                usage: Arc::clone(&usage),
                close,
            },
        );
        tokio::spawn(keep_circuit(rend, circuits, usage, closed, serve.clone()));
    }
}

/// Whether a rendezvous circuit carries a stream: its task and the keeper
/// both read it, under its lock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Usage {
    /// No stream since this instant (or since the circuit came).
    Quiet(Instant),
    /// At least one stream is open.
    Busy,
    /// The keeper closed it for a newcomer: no stream starts on it.
    Closed,
}

/// A rendezvous circuit the keeper holds.
struct Kept {
    usage: Arc<Mutex<Usage>>,
    /// Dropped to close the circuit; closed once the circuit's task ended.
    close: oneshot::Sender<()>,
}

fn usage_of(usage: &Mutex<Usage>) -> std::sync::MutexGuard<'_, Usage> {
    usage.lock().unwrap_or_else(|e| e.into_inner())
}

/// Close the circuit that has gone longest without a stream (the older one
/// on a tie); `false` when every circuit carries a stream. Under its lock, so
/// no stream starts on the circuit chosen.
fn make_room(live: &mut BTreeMap<u64, Kept>) -> bool {
    loop {
        let quietest = live
            .iter()
            .filter_map(|(&number, kept)| match *usage_of(&kept.usage) {
                Usage::Quiet(since) => Some((since, number)),
                Usage::Busy | Usage::Closed => None,
            })
            .min();
        let Some((_, number)) = quietest else {
            return false;
        };
        let mut state = usage_of(&live[&number].usage);
        // A stream may have started since it was read.
        if matches!(*state, Usage::Quiet(_)) {
            *state = Usage::Closed;
            drop(state);
            // Its sender dropped: the circuit's task ends, and with it the
            // circuit.
            live.remove(&number);
            return true;
        }
    }
}

/// Ready once the circuit has gone [`RENDEZVOUS_IDLE`] without a stream;
/// pending while it carries one.
async fn idle(usage: &Mutex<Usage>) {
    let now = *usage_of(usage);
    match now {
        Usage::Quiet(since) => tokio::time::sleep_until(since + RENDEZVOUS_IDLE).await,
        Usage::Busy | Usage::Closed => std::future::pending().await,
    }
}

/// Rendezvous circuit number `circuit`: built, then its streams served until
/// it ends, which ends them too: its client closed it, the keeper closed it
/// for a newcomer (`closed`), or it went [`RENDEZVOUS_IDLE`] without a
/// stream. Dropping its stream requests and streams closes the circuit
/// (tor-hsservice `RendRequest::accept`).
async fn keep_circuit<R, F, Fut>(
    rend: R,
    circuit: u64,
    usage: Arc<Mutex<Usage>>,
    mut closed: oneshot::Receiver<()>,
    serve: F,
) where
    R: Rendezvous,
    F: Fn(R::Request, u64) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut requests = tokio::select! {
        biased;
        _ = &mut closed => return,
        opened = rend.open() => match opened {
            Some(requests) => requests,
            None => return,
        },
        () = idle(&usage) => return,
    };
    let mut streams = JoinSet::new();
    // The client can open no more streams here (the circuit is closing).
    let mut ended = false;
    loop {
        tokio::select! {
            biased;
            _ = &mut closed => return,
            Some(_) = streams.join_next(), if !streams.is_empty() => {
                if streams.is_empty() {
                    if ended {
                        return;
                    }
                    *usage_of(&usage) = Usage::Quiet(Instant::now());
                }
            }
            request = requests.next(), if !ended => match request {
                Some(request) => {
                    {
                        let mut state = usage_of(&usage);
                        if *state == Usage::Closed {
                            return;
                        }
                        *state = Usage::Busy;
                    }
                    streams.spawn(serve(request, circuit));
                }
                None if streams.is_empty() => return,
                None => ended = true,
            },
            () = idle(&usage) => return,
        }
    }
}

/// The Tor client's configuration: its state and cache under `state_dir`,
/// Arti's defaults otherwise but for the module doc's.
fn client_config(state_dir: &Path) -> Result<arti_client::TorClientConfig, String> {
    let mut builder =
        TorClientConfigBuilder::from_directories(state_dir.join("state"), state_dir.join("cache"));
    builder.channel().padding(tor_config::PaddingLevel::Reduced);
    // No exit circuits built ahead of need (audit S9): Raven opens onion
    // streams only. With no circuit counted as enough, Arti's launcher
    // builds none (its threshold), not even the DNS ones it predicts
    // whatever the ports.
    builder
        .preemptive_circuits()
        .disable_at_threshold(0)
        .set_initial_predicted_ports(vec![]);
    // A BEGIN on a dead shared rendezvous circuit is given up after 6 s,
    // not 10 (audit T6).
    builder
        .stream_timeouts()
        .connect_timeout(STREAM_CONNECT_TIMEOUT);
    builder.build().map_err(|e| e.to_string())
}

/// An Arti error kind as a short fixed tag, and whether its cause is on
/// this computer (never Arti's message, which may name a relay or a path).
fn kind_tag(kind: arti_client::ErrorKind) -> (&'static str, bool) {
    use arti_client::ErrorKind as K;
    match kind {
        K::FsPermissions => ("folder permissions", true),
        K::PersistentStateAccessFailed | K::CacheAccessFailed | K::KeystoreAccessFailed => {
            ("its folder cannot be used", true)
        }
        K::PersistentStateCorrupted | K::CacheCorrupted | K::KeystoreCorrupted => {
            ("damaged files in its folder", true)
        }
        K::LocalResourceAlreadyInUse => ("its folder is in use by another Tor", true),
        K::LocalResourceExhausted => ("out of memory or file handles", true),
        K::ClockSkew => ("this computer's clock looks wrong", true),
        K::NoHomeDirectory | K::InvalidConfig | K::InvalidConfigTransition => {
            ("configuration", true)
        }
        K::Internal | K::BadApiUsage | K::NotImplemented | K::FeatureDisabled => {
            ("internal error", true)
        }
        K::SoftwareDeprecated => ("this Tor version is too old", false),
        K::LocalNetworkError => ("local network error", false),
        K::TorNetworkTimeout | K::TorAccessFailed => ("no answer from the Tor network", false),
        K::TorDirectoryError | K::TorDirectoryUnusable | K::DirectoryExpired => {
            ("Tor directory", false)
        }
        _ => ("other", false),
    }
}

/// Arti's current onion service problem as a fixed phrase of
/// [`proto::SERVICE_REASONS`] (never its text: it may name a relay).
fn problem_reason(problem: Option<&tor_hsservice::status::Problem>) -> Option<&'static str> {
    use tor_hsservice::status::{DescUploadRetryError as Upload, Problem};
    use tor_hsservice::IptError as Ipt;
    Some(match problem? {
        Problem::DescriptorUpload(errors) => match errors.first() {
            Some(Upload::Timeout(_)) => "descriptor upload timed out",
            Some(Upload::MaxRetryCountExceeded(_)) => "descriptor upload retries ran out",
            _ => "descriptor upload failed",
        },
        Problem::Ipt(errors) => match errors.first() {
            Some(Ipt::Timeout) => "intro point stopped answering",
            Some(Ipt::IntroPointNotListed) => "intro point left the directory",
            _ => "intro point failed",
        },
        _ => "service error",
    })
}

fn service_state(state: tor_hsservice::status::State) -> ServiceState {
    use tor_hsservice::status::State as S;
    match state {
        S::Shutdown => ServiceState::Shutdown,
        S::Bootstrapping => ServiceState::Bootstrapping,
        S::DegradedReachable => ServiceState::DegradedReachable,
        S::DegradedUnreachable => ServiceState::DegradedUnreachable,
        S::Running => ServiceState::Running,
        S::Recovering => ServiceState::Recovering,
        S::Broken => ServiceState::Broken,
        _ => ServiceState::Broken,
    }
}

/// One onion stream: only BEGIN on the virtual port is accepted (anything
/// else gets END/DONE, as other onion services answer); its bytes go to
/// raven-node's forward listener, the token and its circuit's number first
/// ([`proto::encode_forward`]). Version 4: over the helper channel, this
/// helper's hello first ([`channel::helper_forward`]).
async fn forward_stream(
    request: tor_hsservice::StreamRequest,
    forward: channel::ToNode,
    keys: channel::Keys,
    port: u16,
    circuit: u64,
) {
    use tor_cell::relaycell::msg::{Connected, End, EndReason};
    let wanted = matches!(
        request.request(),
        tor_proto::stream::IncomingStreamRequest::Begin(begin) if begin.port() == port
    );
    if !wanted {
        let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
        return;
    }
    let Ok(mut node) = forward.open(tcp_to).await else {
        let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
        return;
    };
    if channel::helper_forward(&mut node, &keys, circuit)
        .await
        .is_err()
    {
        let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
        return;
    }
    let Ok(mut tor) = request.accept(Connected::new_empty()).await else {
        return;
    };
    let _ = tokio::io::copy_bidirectional(&mut tor, &mut node).await;
}

/// A TCP stream to raven-node's forward listener at `addr`, Nagle off.
async fn tcp_to(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Where raven-node's connect streams come from: this helper life's
/// channel (macOS, Linux), or a loopback port of its own (Windows).
enum Connects {
    Port(TcpListener),
    #[cfg(unix)]
    Channel(Arc<channel::Conduit>),
}

impl Connects {
    /// The next connect stream (Nagle off on TCP; one from anywhere but
    /// loopback is dropped); `None` once the channel ended (raven-node is
    /// gone, and this helper's stdin ends it).
    async fn next(&self) -> Option<channel::Stream<TcpStream>> {
        loop {
            match self {
                Self::Port(listener) => match listener.accept().await {
                    Ok((stream, peer)) if peer.ip().is_loopback() => {
                        let _ = stream.set_nodelay(true);
                        return Some(channel::Stream::Net(stream));
                    }
                    Ok(_) => {}
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                },
                #[cfg(unix)]
                Self::Channel(conduit) => match conduit.accept().await {
                    Ok(Some(stream)) => return Some(channel::Stream::Pair(stream)),
                    Ok(None) => return None,
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                },
            }
        }
    }
}

/// raven-node's connect requests: the token, an onion key and the port;
/// one reply byte (and a short reason); then the bytes. Version 4: raven-node
/// proves the token where it was ([`channel::helper_connect`]), after this
/// helper did; on a loopback port at most [`channel::PENDING_MAX`]
/// connections wait for their hello at once (the oldest is closed for a
/// newcomer).
async fn accept_connects(
    connects: Connects,
    client: Arc<TorClient<PreferredRuntime>>,
    keys: channel::Keys,
) {
    // Each friend's isolation group, for this helper life (audit T6).
    let book = Arc::new(std::sync::Mutex::new(proto::IsolationBook::new(
        IsolationToken::new,
    )));
    let pending =
        matches!(connects, Connects::Port(_)).then(|| Arc::new(channel::Pending::default()));
    while let Some(mut stream) = connects.next().await {
        let (client, book) = (client.clone(), book.clone());
        let (keys, pending) = (keys.clone(), pending.clone());
        tokio::spawn(async move {
            // One try with Arti: to the onion service `hs_id` on `port`, in
            // `group` (`None`: the default one).
            let open = |group: Option<IsolationToken>, hs_id: [u8; 32], port: u16| {
                let client = client.clone();
                async move {
                    let addr = onion_text(&tor_hscrypto::pk::HsId::from(hs_id));
                    let mut prefs = StreamPrefs::new();
                    prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
                    if let Some(group) = group {
                        prefs.set_isolation(group);
                    }
                    client
                        .connect_with_prefs((addr.as_str(), port), &prefs)
                        .await
                        .map_err(|e| connect_reply(e.kind()))
                }
            };
            let asked = answer_connect(&mut stream, &keys, pending.as_deref(), &book, open);
            if let Some(mut tor) = asked.await {
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut tor).await;
            }
        });
    }
}

/// One connect request of raven-node on `stream` ([`accept_connects`]):
/// its token checked, its flags known, the Tor stream opened by
/// [`proto::connect_in_groups`] with `open` making each try (`open(group,
/// hs_id, port)`), and the reply written. The Tor stream once the reply
/// said it opened; `None` when the request was not raven-node's (closed
/// without a word), was refused, or found no stream. Version 4: the hello
/// first ([`channel::helper_connect_in`], with the loopback port's
/// `pending`), the token checked as raven-node's proof.
async fn answer_connect<S, G, T, O, Fut>(
    stream: &mut S,
    keys: &channel::Keys,
    pending: Option<&channel::Pending>,
    book: &std::sync::Mutex<proto::IsolationBook<G>>,
    open: O,
) -> Option<T>
where
    S: AsyncRead + AsyncWrite + Unpin,
    G: Clone + PartialEq,
    O: Fn(Option<G>, [u8; 32], u16) -> Fut,
    Fut: Future<Output = Result<T, ConnectReply>>,
{
    // Not raven-node: closed without a word, before its request is read.
    let (hs_id, port, flags) = channel::helper_connect_in(stream, keys, pending).await?;
    // A flag this version does not know: refused, never served as if it
    // were clear.
    if proto::unknown_flags(flags) {
        let refused = ConnectReply::Failed(proto::UNKNOWN_FLAGS.into());
        let _ = stream.write_all(&refused.encode()).await;
        return None;
    }
    // The first try in the friend's isolation group (the default one until
    // a fresh try worked or a first try timed out), one more with fresh
    // circuits (a new group: Arti fetches the descriptor again) after a
    // failure worth it, within the same wait (field test round 8: a
    // friend's node had just restarted). Arti hands every connect of one
    // group the same rendezvous circuit while it looks open, a dead one too
    // (audit T6). The flags (speed design M5, hedge gate only): a first try
    // in a new group, or a fresh try beside a first one with no stream
    // after 2 s.
    let opened = proto::connect_in_groups(CONNECT_WAIT, book, hs_id, flags, |group, _within| {
        open(group, hs_id, port)
    })
    .await;
    match opened {
        Ok(tor) => stream
            .write_all(&ConnectReply::Ok.encode())
            .await
            .is_ok()
            .then_some(tor),
        Err(reply) => {
            let _ = stream.write_all(&reply.encode()).await;
            None
        }
    }
}

/// Reach our own onion service `own` as a friend would: a new isolation
/// group for every try (a fresh descriptor fetch, new circuits), on
/// [`proto::SELF_CHECK_PORT`], within one connect wait and its second try.
/// The service refuses that port (END, DONE): that answer means the
/// descriptor, an introduction point and a rendezvous all worked.
async fn self_check(
    client: &Arc<TorClient<PreferredRuntime>>,
    own: &tor_hscrypto::pk::HsId,
) -> Result<(), ConnectReply> {
    let addr = onion_text(own);
    proto::connect_with_retry(CONNECT_WAIT, |_fresh, _within| {
        let (client, addr) = (client.clone(), addr.clone());
        async move {
            let mut prefs = StreamPrefs::new();
            prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
            prefs.new_isolation_group();
            match client
                .connect_with_prefs((addr.as_str(), proto::SELF_CHECK_PORT), &prefs)
                .await
            {
                Ok(_stream) => Ok(()),
                Err(e) if service_answered(e.kind()) => Ok(()),
                Err(e) => Err(connect_reply(e.kind())),
            }
        }
    })
    .await
}

/// The service itself answered the stream request (it refused the port):
/// Arti's kinds for an END cell (`tor-cell` relaycell msg.rs).
fn service_answered(kind: arti_client::ErrorKind) -> bool {
    use arti_client::ErrorKind as K;
    matches!(
        kind,
        K::RemoteStreamClosed
            | K::RemoteStreamError
            | K::RemoteStreamReset
            | K::RemoteConnectionRefused
            | K::ExitPolicyRejected
    )
}

/// The one Arti log line the helper reads: a descriptor upload round's
/// counts ([`proto::upload_round`]), sent as [`Event::Uploads`]. A
/// subscriber that enables nothing else, so every other Arti log line
/// stays off.
mod upload_rounds {
    use super::{proto, Event, Events};
    use tracing::field::{Field, Visit};
    use tracing::level_filters::LevelFilter;
    use tracing::subscriber::Interest;
    use tracing::{span, Metadata, Subscriber};

    /// Where Arti's publisher logs from.
    const TARGET: &str = "tor_hsservice::publish";

    struct Rounds;

    /// Where the counts go: the helper life that runs now (a process's
    /// subscriber is set once; an in-process helper has many lives).
    static SINK: std::sync::Mutex<Option<Events>> = std::sync::Mutex::new(None);

    /// This life's events get the counts; the subscriber is set once.
    pub(super) fn install(events: Events) {
        *SINK.lock().unwrap_or_else(|e| e.into_inner()) = Some(events);
        let _ = tracing::subscriber::set_global_default(Rounds);
    }

    impl Subscriber for Rounds {
        fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
            if self.enabled(metadata) {
                Interest::always()
            } else {
                Interest::never()
            }
        }

        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            metadata.is_event()
                && metadata.target().starts_with(TARGET)
                && *metadata.level() <= tracing::Level::DEBUG
        }

        fn max_level_hint(&self) -> Option<LevelFilter> {
            Some(LevelFilter::DEBUG)
        }

        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut message = Message(None);
            event.record(&mut message);
            if let Some((ok, of)) = message.0.as_deref().and_then(proto::upload_round) {
                if let Some(events) = SINK.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                    events.say(Event::Uploads { ok, of });
                }
            }
        }

        fn enter(&self, _: &span::Id) {}

        fn exit(&self, _: &span::Id) {}
    }

    /// The event's message, formatted (Arti's fixed words and two numbers
    /// for the line we want; any other line is dropped unread).
    struct Message(Option<String>);

    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = Some(format!("{value:?}"));
            }
        }
    }
}

/// A failed Tor connect's reply to raven-node (fixed reasons, never an
/// address).
fn connect_reply(kind: arti_client::ErrorKind) -> ConnectReply {
    match kind {
        arti_client::ErrorKind::BootstrapRequired => {
            ConnectReply::NotReady("not bootstrapped".into())
        }
        arti_client::ErrorKind::TorNetworkTimeout
        | arti_client::ErrorKind::RemoteNetworkTimeout => {
            ConnectReply::Timeout("tor timeout".into())
        }
        arti_client::ErrorKind::OnionServiceNotFound => {
            ConnectReply::Unreachable("no descriptor".into())
        }
        arti_client::ErrorKind::OnionServiceNotRunning => {
            ConnectReply::Unreachable("service not running".into())
        }
        arti_client::ErrorKind::OnionServiceConnectionFailed => {
            ConnectReply::Unreachable("rendezvous failed".into())
        }
        _ => ConnectReply::Failed("tor connect failed".into()),
    }
}

/// The `.onion` text of an onion key, for Arti's connect call only (never
/// printed: [`safelog`] redacts it in Arti's own displays).
fn onion_text(hs_id: &tor_hscrypto::pk::HsId) -> String {
    use safelog::DisplayRedacted as _;
    hs_id.display_unredacted().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Audit S9: Raven opens onion streams only, so its Tor client builds
    /// no exit circuits ahead of need (Arti's defaults keep two for ports
    /// 80 and 443, and DNS ones, rebuilt in every helper life).
    #[test]
    fn the_client_builds_no_exit_circuits_ahead() {
        let config = client_config(Path::new("/nonexistent/raven-tor")).unwrap();
        let preemptive: &arti_client::config::circ::PreemptiveCircuitConfig = config.as_ref();
        let text = format!("{preemptive:?}");
        assert!(text.contains("disable_at_threshold: 0"), "{text}");
        assert!(text.contains("initial_predicted_ports: []"), "{text}");
    }

    /// Audit T6: a BEGIN on a dead shared rendezvous circuit is given up
    /// after 6 s (Arti's default is 10 s); then the fresh try starts.
    #[test]
    fn the_client_gives_up_a_begin_after_six_seconds() {
        let text = format!(
            "{:?}",
            client_config(Path::new("/nonexistent/raven-tor")).unwrap()
        );
        let timeouts = text
            .split_once("stream_timeouts: ")
            .and_then(|(_, rest)| rest.split_once('}'))
            .map_or("", |(timeouts, _)| timeouts);
        assert!(timeouts.contains("connect_timeout: 6s"), "{text}");
    }

    /// A config line the helper refuses gets its words to raven-node before
    /// [`serve`] returns: a helper process exits right after (its runtime
    /// ends, and a line still with the writer task is lost), and raven-node
    /// says "install Raven again" for another version only when the words
    /// came. One thread: nothing runs between `serve`'s return and the read.
    #[tokio::test]
    async fn the_words_for_a_refused_config_line_are_written_before_serve_returns() {
        let good = Config {
            v: proto::PROTO_VERSION,
            state_dir: "/nonexistent/raven-tor".into(),
            token: hex::encode([1u8; proto::TOKEN_LEN]),
            forward: "127.0.0.1:9".into(),
            port: 4242,
            fresh_state: false,
        };
        let line = |config: Config| proto::line(&config);
        let refused = [
            (
                line(Config {
                    v: proto::PROTO_VERSION + 1,
                    ..good.clone()
                }),
                "unknown protocol version",
            ),
            ("not a config\n".to_string(), "bad config line"),
            (
                line(Config {
                    token: "00".into(),
                    ..good.clone()
                }),
                "bad token",
            ),
            (
                line(Config {
                    forward: "192.0.2.1:9".into(),
                    ..good.clone()
                }),
                "forward address is not loopback",
            ),
        ];
        for (first, words) in refused {
            let (mut to_helper, input) = tokio::io::duplex(4096);
            let (output, mut from_helper) = tokio::io::duplex(4096);
            to_helper.write_all(first.as_bytes()).await.unwrap();
            assert_eq!(serve(input, output, channel::Handed::Nothing).await, 2);
            let mut got = vec![0u8; 4096];
            let n = futures::FutureExt::now_or_never(from_helper.read(&mut got))
                .unwrap_or_else(|| panic!("no words yet when serve returned: {words}"))
                .unwrap();
            let said = String::from_utf8_lossy(&got[..n]);
            assert!(said.contains(words), "{words}: {said}");
        }
    }

    // ── The rendezvous circuits (TOR-5), with fake clients ─────────────────

    use std::collections::BTreeSet;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};

    /// One stream on a fake circuit: open until the test drops its sender.
    type FakeStream = oneshot::Receiver<()>;

    /// The fake circuits the keeper holds and has opened, by the number of
    /// their client (1, 2, … in the order they came).
    #[derive(Default)]
    struct Book {
        live: Mutex<BTreeSet<usize>>,
        opened: Mutex<BTreeSet<usize>>,
    }

    /// A client's rendezvous: the circuit opens at once and lives while the
    /// keeper holds its stream requests; the client sends its streams.
    struct Fake {
        number: usize,
        book: Arc<Book>,
        streams: UnboundedReceiver<FakeStream>,
    }

    /// A fake circuit's stream requests: the circuit is live while they are
    /// held, until the client closes it (drops its sender).
    struct FakeStreams {
        streams: UnboundedReceiver<FakeStream>,
        number: usize,
        book: Arc<Book>,
    }

    impl Drop for FakeStreams {
        fn drop(&mut self) {
            self.book.live.lock().unwrap().remove(&self.number);
        }
    }

    impl Stream for FakeStreams {
        type Item = FakeStream;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<FakeStream>> {
            self.get_mut().streams.poll_next_unpin(cx)
        }
    }

    impl Rendezvous for Fake {
        type Request = FakeStream;

        async fn open(self) -> Option<BoxStream<'static, FakeStream>> {
            self.book.live.lock().unwrap().insert(self.number);
            self.book.opened.lock().unwrap().insert(self.number);
            let streams = FakeStreams {
                streams: self.streams,
                number: self.number,
                book: self.book,
            };
            Some(streams.boxed())
        }
    }

    /// The clients of one keeper.
    struct Clients {
        book: Arc<Book>,
        keeper: UnboundedSender<Fake>,
        next: usize,
    }

    impl Clients {
        /// A keeper whose streams stay open until their client ends them.
        fn new() -> Clients {
            let (keeper, requests) = unbounded();
            tokio::spawn(keep_rendezvous(
                requests,
                |stream: FakeStream, _| async move {
                    let _ = stream.await;
                },
            ));
            Clients {
                book: Arc::default(),
                keeper,
                next: 0,
            }
        }

        /// A new client's rendezvous; the sender for its streams (held by
        /// the test: the client never closes its circuit itself).
        fn rendezvous(&mut self) -> UnboundedSender<FakeStream> {
            self.next += 1;
            let (client, streams) = unbounded();
            self.keeper
                .unbounded_send(Fake {
                    number: self.next,
                    book: Arc::clone(&self.book),
                    streams,
                })
                .unwrap();
            client
        }

        fn live(&self) -> Vec<usize> {
            self.book.live.lock().unwrap().iter().copied().collect()
        }

        fn opened(&self) -> Vec<usize> {
            self.book.opened.lock().unwrap().iter().copied().collect()
        }
    }

    /// A stream on the circuit of `client`, open until the sender returned
    /// is dropped.
    fn open_stream(client: &UnboundedSender<FakeStream>) -> oneshot::Sender<()> {
        let (end, stream) = oneshot::channel();
        client.unbounded_send(stream).unwrap();
        end
    }

    /// Everything that can run runs (the clock is paused: it moves 1 ms).
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    /// TOR-5: a client may keep a rendezvous circuit with no stream for as
    /// long as it likes, and each introduction costs the helper a circuit.
    /// The helper keeps at most 64: a newcomer closes the one that has gone
    /// longest without a stream (all as long here: the oldest).
    #[tokio::test(start_paused = true)]
    async fn the_helper_keeps_at_most_64_rendezvous_circuits() {
        let mut clients = Clients::new();
        let _held: Vec<_> = (0..65).map(|_| clients.rendezvous()).collect();
        settle().await;
        let live = clients.live();
        assert_eq!(live.len(), MAX_RENDEZVOUS_CIRCUITS, "{live:?}");
        assert!(!live.contains(&1), "the oldest made room: {live:?}");
        assert!(live.contains(&65), "the newcomer got its circuit: {live:?}");
        tokio::time::sleep(RENDEZVOUS_IDLE + Duration::from_secs(1)).await;
        assert_eq!(clients.live(), Vec::<usize>::new(), "none left idle");
    }

    /// TOR-5: a circuit with no stream for 10 minutes is closed; before
    /// that it is kept (the client's own reuse window, so a friend's next
    /// connect still finds its circuit).
    #[tokio::test(start_paused = true)]
    async fn a_rendezvous_circuit_with_no_stream_for_10_minutes_closes() {
        let mut clients = Clients::new();
        let _held: Vec<_> = (0..3).map(|_| clients.rendezvous()).collect();
        settle().await;
        tokio::time::sleep(RENDEZVOUS_IDLE - Duration::from_secs(1)).await;
        assert_eq!(clients.live(), [1, 2, 3], "kept for the reuse window");
        tokio::time::sleep(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(clients.live(), Vec::<usize>::new(), "10 min and 1 s idle");
    }

    /// TOR-5: a circuit that carries a stream is neither closed for a
    /// newcomer nor by the idle limit; it closes 10 minutes after its last
    /// stream ended.
    #[tokio::test(start_paused = true)]
    async fn a_circuit_that_carries_a_stream_is_kept() {
        let mut clients = Clients::new();
        let friend = clients.rendezvous();
        settle().await;
        let link = open_stream(&friend);
        settle().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        let _strangers: Vec<_> = (0..64).map(|_| clients.rendezvous()).collect();
        settle().await;
        let live = clients.live();
        assert_eq!(live.len(), MAX_RENDEZVOUS_CIRCUITS, "{live:?}");
        assert!(live.contains(&1), "it carries a stream: {live:?}");
        assert!(
            !live.contains(&2),
            "the first quiet one made room: {live:?}"
        );
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert_eq!(clients.live(), [1], "an hour with its stream open");
        drop(link);
        settle().await;
        tokio::time::sleep(RENDEZVOUS_IDLE - Duration::from_secs(1)).await;
        assert_eq!(clients.live(), [1], "kept for the reuse window");
        tokio::time::sleep(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(clients.live(), Vec::<usize>::new());
    }

    /// TOR-5: the circuit quiet longest makes room, not the oldest: one
    /// whose stream ended a moment ago is kept.
    #[tokio::test(start_paused = true)]
    async fn a_newcomer_closes_the_circuit_quiet_longest() {
        let mut clients = Clients::new();
        let first = clients.rendezvous();
        settle().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        let _others: Vec<_> = (0..63).map(|_| clients.rendezvous()).collect();
        settle().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        let link = open_stream(&first);
        settle().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(link);
        settle().await;
        let _newcomer = clients.rendezvous();
        settle().await;
        let live = clients.live();
        assert_eq!(live.len(), MAX_RENDEZVOUS_CIRCUITS, "{live:?}");
        assert!(live.contains(&1), "its stream ended last: {live:?}");
        assert!(!live.contains(&2), "quiet since it came: {live:?}");
        assert!(live.contains(&65), "{live:?}");
    }

    /// TOR-5: when every circuit carries a stream (raven-node holds at most
    /// 16 links, so these are streams it is closing), a newcomer is refused:
    /// no link in use is cut for it.
    #[tokio::test(start_paused = true)]
    async fn when_every_circuit_carries_a_stream_a_newcomer_is_refused() {
        let mut clients = Clients::new();
        let held: Vec<_> = (0..64).map(|_| clients.rendezvous()).collect();
        settle().await;
        let _links: Vec<_> = held.iter().map(open_stream).collect();
        settle().await;
        let _newcomer = clients.rendezvous();
        settle().await;
        assert_eq!(clients.live(), (1..=64).collect::<Vec<_>>());
        assert!(!clients.opened().contains(&65), "{:?}", clients.opened());
    }

    /// A circuit its client closed leaves its place to a newcomer at once.
    #[tokio::test(start_paused = true)]
    async fn a_circuit_its_client_closed_leaves_room() {
        let mut clients = Clients::new();
        let mut held: Vec<_> = (0..64).map(|_| clients.rendezvous()).collect();
        settle().await;
        drop(held.remove(0));
        settle().await;
        let _newcomer = clients.rendezvous();
        settle().await;
        assert_eq!(clients.live(), (2..=65).collect::<Vec<_>>());
    }

    // ── Connect requests (version 3 flags, speed design M5), fake tries ────

    /// A new group number for the connect tests' isolation books.
    fn next_group() -> u32 {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// The tries of one fake connect: each one's group and when it began.
    type TriesMade = Vec<(Option<u32>, Duration)>;

    /// One connect request with `flags` through [`answer_connect`], each try
    /// made by a fake Tor: a try in the default group meets a dead circuit
    /// (Arti gives up its BEGIN after [`STREAM_CONNECT_TIMEOUT`]), a try in
    /// any other group opens a stream after 1 s. The reply raven-node reads,
    /// whether a Tor stream was handed back, and each try as (its group, when
    /// it began).
    async fn connect_with_flags(
        book: &Mutex<proto::IsolationBook<u32>>,
        flags: u8,
    ) -> (ConnectReply, bool, TriesMade) {
        let keys = channel::Keys::new(&[5u8; proto::TOKEN_LEN]);
        let (mut node, mut helper) = tokio::io::duplex(1024);
        // raven-node's side: the hello (version 4), then its request.
        let asking = {
            let keys = keys.clone();
            async move {
                let proof = channel::node_connect(&mut node, &keys).await.unwrap();
                node.write_all(&proto::encode_connect(&proof, &[6u8; 32], 4242, flags))
                    .await
                    .unwrap();
                node
            }
        };
        let began = Instant::now();
        let tries: Arc<Mutex<TriesMade>> = Arc::default();
        let log = Arc::clone(&tries);
        let open = move |group: Option<u32>, hs_id: [u8; 32], port: u16| {
            assert_eq!((hs_id, port), ([6u8; 32], 4242), "the request's own");
            log.lock().unwrap().push((group, began.elapsed()));
            async move {
                if group.is_none() {
                    tokio::time::sleep(STREAM_CONNECT_TIMEOUT).await;
                    return Err(ConnectReply::Timeout("tor timeout".into()));
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(tokio::io::duplex(64).0)
            }
        };
        let answering = async {
            let opened = answer_connect(&mut helper, &keys, None, book, open).await;
            drop(helper);
            opened
        };
        let (opened, mut node) = tokio::join!(answering, asking);
        let mut head = [0u8; 2];
        node.read_exact(&mut head).await.unwrap();
        let mut reason = vec![0u8; usize::from(head[1])];
        node.read_exact(&mut reason).await.unwrap();
        let tries = tries.lock().unwrap().clone();
        (
            ConnectReply::decode(head[0], &reason),
            opened.is_some(),
            tries,
        )
    }

    /// Version 3 in the real helper (the loopback helper's twin is
    /// `onion::tests::a_connect_with_an_unknown_flag_is_refused`): a request
    /// with a flag this version does not know (bits 1 and 2 are kept for the
    /// keep-warm probe and optimistic data) is refused with no Tor try, never
    /// served as if it were clear; the known flags reach the tries. Flags 0 is
    /// version 2's request: the first try in the friend's group (here the
    /// default one, its circuit dead), the fresh one after Arti gave it up.
    /// A hedge starts the fresh try 2 s after a first one with no stream;
    /// fresh first makes the first try in a new group, with no hedge.
    #[tokio::test(start_paused = true)]
    async fn a_connect_with_an_unknown_flag_is_refused_and_known_flags_reach_the_tries() {
        for flags in [1u8 << 1, 1 << 2, 1 << 7, (1 << 1) | proto::CONNECT_HEDGE] {
            let book = Mutex::new(proto::IsolationBook::new(next_group));
            let (reply, opened, tries) = connect_with_flags(&book, flags).await;
            assert_eq!(
                reply,
                ConnectReply::Failed(proto::UNKNOWN_FLAGS.into()),
                "{flags:#x}"
            );
            assert!(!opened && tries.is_empty(), "{flags:#x}: {tries:?}");
        }
        let secs = Duration::from_secs;
        // (flags, the first try's group is the default one, when the fresh try began)
        for (flags, first_default, fresh_at) in [
            (0, true, STREAM_CONNECT_TIMEOUT),
            (proto::CONNECT_HEDGE, true, proto::CONNECT_HEDGE_AFTER),
            (proto::CONNECT_FRESH_FIRST, false, secs(0)),
            (proto::CONNECT_FLAGS, false, secs(0)),
        ] {
            let book = Mutex::new(proto::IsolationBook::new(next_group));
            let (reply, opened, tries) = connect_with_flags(&book, flags).await;
            assert_eq!((reply, opened), (ConnectReply::Ok, true), "{flags:#x}");
            let fresh = *tries.last().expect("a try");
            assert!(fresh.0.is_some(), "{flags:#x}: {tries:?}");
            assert_eq!(fresh.1, fresh_at, "{flags:#x}: {tries:?}");
            assert_eq!(tries.len(), if first_default { 2 } else { 1 }, "{flags:#x}");
            assert_eq!(tries[0].0.is_none(), first_default, "{flags:#x}: {tries:?}");
        }
    }
}
