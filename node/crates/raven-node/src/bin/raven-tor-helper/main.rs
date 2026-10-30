//! raven-tor-helper: Arti (the Rust Tor implementation) for one raven-node,
//! in its own process (lab; `protocol/RAVEN_ONION_CARRIER_V1.md` §6, design
//! `docs/design/2026-10-tor-fallback.md` §3.1).
//!
//! raven-node starts it, writes one config line on its stdin and reads its
//! events on stdout ([`proto`]). It runs a Tor client and one onion service
//! (nickname `raven`, key kept by Arti under the profile's `tor/` directory),
//! forwards every accepted stream on the virtual port to raven-node's forward
//! listener (token and circuit number first), and opens Tor streams to onion services for
//! raven-node's connect requests (token checked). It never sees a Raven key
//! or a message: the Raven link runs end to end inside the streams.
//!
//! It exits when its stdin closes (raven-node is gone) or on `stop`. If Arti
//! panics or calls `exit(1)` (an obsolete protocol version, Arti #1932), only
//! this process ends; raven-node restarts it with backoff.
//!
//! Its stdout carries events only. Its only log subscriber
//! ([`upload_rounds`]) reads one Arti debug line, the descriptor upload
//! round's counts: Arti's other log lines (which may name relays) go
//! nowhere, and none of its events names an onion address of a friend.
//!
//! Arti's defaults, except: channel padding `reduced` (laptops), at most
//! [`MAX_STREAMS_PER_CIRCUIT`] streams per rendezvous circuit and an
//! introduction rate limit sent to the introduction points. No bridges, no
//! pluggable transports, no proof-of-work, no experimental APIs.

#[path = "../../onion/proto.rs"]
#[allow(dead_code)]
mod proto;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::{HasKind as _, StreamPrefs, TorClient};
use futures::StreamExt;
use proto::{Command, Config, ConnectReply, Event, ServiceState};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tor_rtcompat::PreferredRuntime;

/// How long one Tor connect may take (raven-node waits 45 s in all).
const CONNECT_WAIT: Duration = Duration::from_secs(44);

/// Streams one rendezvous circuit may hold open at once; one more tears the
/// circuit down (RAVEN_ONION_CARRIER_V1 §5).
const MAX_STREAMS_PER_CIRCUIT: u32 = 8;

/// Introductions per second our introduction points pass on, and their
/// burst (the EST_INTRO DoS extension; C Tor's defaults are 25 and 200, a
/// personal service needs far fewer).
const INTRO_RATE_PER_S: u32 = 5;
const INTRO_BURST: u32 = 20;

fn main() {
    // Two workers: Tor in its own small pool, never the node's.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => std::process::exit(3),
    };
    let code = runtime.block_on(run());
    // Do not wait for Arti's background tasks: raven-node is gone or asked.
    runtime.shutdown_timeout(Duration::from_secs(1));
    std::process::exit(code);
}

/// Events to stdout, one writer.
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

async fn run() -> i32 {
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    let events = Events(tx);
    let writer = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        while let Some(ev) = rx.recv().await {
            if out.write_all(proto::line(&ev).as_bytes()).await.is_err()
                || out.flush().await.is_err()
            {
                break;
            }
        }
    });
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let Ok(Some(first)) = stdin.next_line().await else {
        return 2;
    };
    let Ok(config) = serde_json::from_str::<Config>(&first) else {
        events.local("bad config line");
        return 2;
    };
    if config.v != proto::PROTO_VERSION {
        events.local("unknown protocol version");
        return 2;
    }
    let Some(token) = proto::parse_token(&config.token) else {
        events.local("bad token");
        return 2;
    };
    let Ok(forward) = config.forward.parse::<SocketAddr>() else {
        events.local("bad forward address");
        return 2;
    };
    if !forward.ip().is_loopback() {
        events.local("forward address is not loopback");
        return 2;
    }
    let state_dir = PathBuf::from(&config.state_dir);
    if config.fresh_state {
        set_guard_state_aside(&state_dir);
    }
    upload_rounds::install(events.clone());

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
        }
    }
    tor.abort();
    drop(events);
    let _ = tokio::time::timeout(Duration::from_millis(500), writer).await;
    code
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
    forward: SocketAddr,
    port: u16,
    events: Events,
    mut check_requests: mpsc::UnboundedReceiver<u64>,
) {
    let mut builder =
        TorClientConfigBuilder::from_directories(state_dir.join("state"), state_dir.join("cache"));
    builder.channel().padding(tor_config::PaddingLevel::Reduced);
    let config = match builder.build() {
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
        Err(e) => return events.arti("Tor client not created", e.kind()),
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
        // as such.
        events.arti("bootstrap failed", e.kind());
        reporter.abort();
        return std::future::pending().await;
    }

    // Outbound: raven-node's connect requests.
    let listener = match TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await {
        Ok(l) => l,
        Err(_) => return events.local("connect port could not be opened"),
    };
    let connect = match listener.local_addr() {
        Ok(a) => a,
        Err(_) => return events.local("connect port has no address"),
    };
    tokio::spawn(accept_connects(listener, client.clone(), token));
    events.say(Event::Ready {
        connect: connect.to_string(),
    });

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
    // Each rendezvous circuit gets its own number, sent to raven-node after
    // the token with each of its streams: raven-node counts its slots per
    // circuit, so one client cannot take them all. The numbers are opaque
    // and never reused in this life.
    let mut requests = Box::pin(requests);
    let mut circuits: u64 = 0;
    while let Some(rend) = requests.next().await {
        circuits += 1;
        let circuit = circuits;
        tokio::spawn(async move {
            let Ok(mut streams) = rend.accept().await else {
                return;
            };
            while let Some(request) = streams.next().await {
                tokio::spawn(forward_stream(request, forward, token, port, circuit));
            }
        });
    }
    // The service ended (it should not): raven-node notices nothing more
    // and restarts the helper when it stops answering.
    events.error("onion service ended");
    drop(service);
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
/// ([`proto::encode_forward`]).
async fn forward_stream(
    request: tor_hsservice::StreamRequest,
    forward: SocketAddr,
    token: [u8; proto::TOKEN_LEN],
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
    let Ok(mut node) = TcpStream::connect(forward).await else {
        let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
        return;
    };
    let _ = node.set_nodelay(true);
    if node
        .write_all(&proto::encode_forward(&token, circuit))
        .await
        .is_err()
    {
        return;
    }
    let Ok(mut tor) = request.accept(Connected::new_empty()).await else {
        return;
    };
    let _ = tokio::io::copy_bidirectional(&mut tor, &mut node).await;
}

/// raven-node's connect requests: the token, an onion key and the port;
/// one reply byte (and a short reason); then the bytes.
async fn accept_connects(
    listener: TcpListener,
    client: Arc<TorClient<PreferredRuntime>>,
    token: [u8; proto::TOKEN_LEN],
) {
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let client = client.clone();
        tokio::spawn(async move {
            let mut req = [0u8; proto::CONNECT_REQUEST_LEN];
            let read = tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut req));
            if !matches!(read.await, Ok(Ok(_))) {
                return;
            }
            // Not raven-node: closed without a word.
            let Some((hs_id, port)) = proto::decode_connect(&req, &token) else {
                return;
            };
            let _ = stream.set_nodelay(true);
            let target = tor_hscrypto::pk::HsId::from(hs_id);
            let addr = onion_text(&target);
            // One more try with fresh circuits (a new isolation group: Arti
            // fetches the descriptor again) after a failure worth it, within
            // the same wait (field test round 8: a friend's node had just
            // restarted).
            let opened = proto::connect_with_retry(CONNECT_WAIT, |fresh, _within| {
                let (client, addr) = (client.clone(), addr.clone());
                async move {
                    let mut prefs = StreamPrefs::new();
                    prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
                    if fresh {
                        prefs.new_isolation_group();
                    }
                    client
                        .connect_with_prefs((addr.as_str(), port), &prefs)
                        .await
                        .map_err(|e| connect_reply(e.kind()))
                }
            })
            .await;
            match opened {
                Ok(mut tor) => {
                    if stream.write_all(&ConnectReply::Ok.encode()).await.is_err() {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tor).await;
                }
                Err(reply) => {
                    let _ = stream.write_all(&reply.encode()).await;
                }
            }
        });
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

    struct Rounds(Events);

    /// This process's subscriber, once.
    pub(super) fn install(events: Events) {
        let _ = tracing::subscriber::set_global_default(Rounds(events));
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
                self.0.say(Event::Uploads { ok, of });
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
