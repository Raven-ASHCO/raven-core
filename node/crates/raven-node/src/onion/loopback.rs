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
//!   (a Tor rendezvous).

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::proto::{self, Command, Config, ConnectReply, Event};
use super::LineReader;

const STALL_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_STALL";
const OBSOLETE_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_OBSOLETE";
const DELAY_ENV: &str = "RAVEN_LAB_TOR_LOOPBACK_DELAY_MS";
/// How long one connect may take, as the Arti helper's.
const CONNECT_WAIT: Duration = Duration::from_secs(44);
/// The loopback helper's onion key seed, under the state directory.
const KEY_FILE: &str = "loopback_hs.key";

/// Behaviour knobs (see the module doc).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Knobs {
    pub(crate) stall: bool,
    pub(crate) obsolete: bool,
    pub(crate) delay: Duration,
}

impl Knobs {
    fn from_env() -> Self {
        let on = |name| std::env::var(name).is_ok_and(|v| v == "1");
        Self {
            stall: on(STALL_ENV),
            obsolete: on(OBSOLETE_ENV),
            delay: std::env::var(DELAY_ENV)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map_or(Duration::ZERO, |ms| Duration::from_millis(ms.min(60_000))),
        }
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
    let accepting = tokio::spawn(accept_service(service, forward, token));
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
        knobs.delay,
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
/// own "circuit").
async fn accept_service(listener: TcpListener, forward: std::net::SocketAddr, token: [u8; 32]) {
    let mut circuits: u64 = 0;
    loop {
        let Ok((mut inbound, _)) = listener.accept().await else {
            continue;
        };
        circuits += 1;
        let circuit = circuits;
        tokio::spawn(async move {
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
    delay: Duration,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut req = [0u8; proto::CONNECT_REQUEST_LEN];
            if stream.read_exact(&mut req).await.is_err() {
                return;
            }
            let Some((hs_id, asked)) = proto::decode_connect(&req, &token) else {
                // Not raven-node: closed without a word.
                return;
            };
            if asked != port {
                let _ = stream
                    .write_all(&ConnectReply::Unreachable("port refused".into()).encode())
                    .await;
                return;
            }
            // As the Arti helper: one more try after a failure worth it
            // (here the registry is read again, as Arti fetches the
            // descriptor again).
            let opened = proto::connect_with_retry(CONNECT_WAIT, |_fresh, _within| {
                let registry = registry.clone();
                async move {
                    tokio::time::sleep(delay).await;
                    let target = std::fs::read_to_string(registry.join(hex::encode(hs_id)))
                        .ok()
                        .and_then(|t| t.trim().parse::<std::net::SocketAddr>().ok())
                        .ok_or_else(|| ConnectReply::Unreachable("no descriptor".into()))?;
                    TcpStream::connect(target)
                        .await
                        .map_err(|_| ConnectReply::Unreachable("rendezvous failed".into()))
                }
            })
            .await;
            let mut out = match opened {
                Ok(out) => out,
                Err(reply) => {
                    let _ = stream.write_all(&reply.encode()).await;
                    return;
                }
            };
            if stream.write_all(&ConnectReply::Ok.encode()).await.is_err() {
                return;
            }
            let _ = out.set_nodelay(true);
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut out).await;
        });
    }
}
