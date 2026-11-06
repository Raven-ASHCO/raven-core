//! Tests only: loopback "sockets" in memory, so an onion test can run the
//! loopback Tor model ([`super::loopback`]) on tokio's paused clock
//! (`#[tokio::test(start_paused = true)]`) and time a send in the model's
//! own round trips, whatever the load on the computer.
//!
//! Why not real sockets: a paused clock moves to the next timer as soon as
//! no task can run, and bytes on their way through a real socket are no
//! such task, so a latency of the model or a reply wait would end early.
//! In memory a write wakes its reader at once: only the model's own timers
//! (a connect's delay, a byte's latency, a rendezvous, a dead circuit's
//! timeout) and the code's own waits move the clock, and local work costs
//! no time at all.
//!
//! A [`Listener`] holds an address of its own in 127.0.77.0/24 (never a
//! socket) until it is dropped; [`connect`] reaches it through a pipe in
//! memory. Any other address is a real TCP connect, as before.

use std::cell::Cell;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::io::DuplexStream;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// A TCP stream, or a pipe in memory.
pub(crate) type Stream = tokio_util::either::Either<TcpStream, DuplexStream>;

/// What one way of a pipe holds before its writer waits.
const PIPE_BYTES: usize = 256 * 1024;

/// The address of every [`Listener`] (its port is its own): no socket.
const MEMORY_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 77, 1);

type Ports = HashMap<SocketAddr, mpsc::UnboundedSender<DuplexStream>>;

/// The listeners in memory now, by address.
static PORTS: Mutex<Option<Ports>> = Mutex::new(None);
static NEXT_PORT: AtomicU16 = AtomicU16::new(1);

thread_local! {
    /// This thread runs a test whose every stream is in memory
    /// ([`MemoryOnly`]).
    static MEMORY_ONLY: Cell<bool> = const { Cell::new(false) };
}

fn ports() -> MutexGuard<'static, Option<Ports>> {
    PORTS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A listener in memory.
pub(crate) struct Listener {
    addr: SocketAddr,
    incoming: mpsc::UnboundedReceiver<DuplexStream>,
}

impl Listener {
    /// A listener at an address no other one holds.
    pub(crate) fn bind() -> Self {
        let mut ports = ports();
        let ports = ports.get_or_insert_with(HashMap::new);
        let addr = loop {
            let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed).max(1);
            let addr = SocketAddr::from((MEMORY_IP, port));
            if !ports.contains_key(&addr) {
                break addr;
            }
        };
        let (tx, incoming) = mpsc::unbounded_channel();
        ports.insert(addr, tx);
        Self { addr, incoming }
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The next stream [`connect`] opened to it.
    pub(crate) async fn accept(&mut self) -> io::Result<Stream> {
        self.incoming
            .recv()
            .await
            .map(Stream::Right)
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(ports) = ports().as_mut() {
            ports.remove(&self.addr);
        }
    }
}

/// A stream to `addr`: a pipe to the [`Listener`] there (refused when none
/// is), or else a TCP stream, Nagle off. Refused too on a thread under
/// [`MemoryOnly`]: a real socket there would let the paused clock run ahead
/// of its bytes.
pub(crate) async fn connect(addr: SocketAddr) -> io::Result<Stream> {
    if addr.ip() == MEMORY_IP {
        let refused = || io::Error::from(io::ErrorKind::ConnectionRefused);
        let listener = ports().as_ref().and_then(|p| p.get(&addr).cloned());
        let (ours, theirs) = tokio::io::duplex(PIPE_BYTES);
        listener
            .ok_or_else(refused)?
            .send(theirs)
            .map_err(|_| refused())?;
        return Ok(Stream::Right(ours));
    }
    if MEMORY_ONLY.with(Cell::get) {
        return Err(io::Error::other("a test in memory dialled a real socket"));
    }
    let stream = TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    Ok(Stream::Left(stream))
}

/// While it lives, [`connect`] on this thread reaches listeners in memory
/// only (a test on the paused clock: a current thread runtime runs all its
/// tasks on the test's thread).
pub(crate) struct MemoryOnly(());

impl MemoryOnly {
    pub(crate) fn new() -> Self {
        MEMORY_ONLY.with(|on| on.set(true));
        Self(())
    }
}

impl Drop for MemoryOnly {
    fn drop(&mut self) {
        MEMORY_ONLY.with(|on| on.set(false));
    }
}

mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A pipe carries bytes both ways and its end; a dropped listener's
    /// address is refused, never dialled as a socket; under MemoryOnly a
    /// real listener is refused too, by the guard (no socket is opened),
    /// and reached once MemoryOnly is gone.
    #[tokio::test(start_paused = true)]
    async fn a_listener_in_memory_is_reached_and_then_gone() {
        let mut listener = Listener::bind();
        let addr = listener.local_addr();
        assert_eq!(addr.ip(), MEMORY_IP);
        let mut ours = connect(addr).await.unwrap();
        let mut theirs = listener.accept().await.unwrap();
        ours.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        theirs.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        theirs.write_all(b"pong").await.unwrap();
        theirs.shutdown().await.unwrap();
        let mut back = Vec::new();
        ours.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"pong");
        drop(listener);
        let gone = connect(addr).await.map(|_| ()).unwrap_err();
        assert_eq!(gone.kind(), io::ErrorKind::ConnectionRefused);
        // A real listener at a free loopback port (never one of Raven's
        // own): a connect to it works, so only the guard can refuse it.
        let socket = loop {
            let socket = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = socket.local_addr().unwrap().port();
            if !(7420..=7427).contains(&port) && port != 17420 {
                break socket;
            }
        };
        let real = socket.local_addr().unwrap();
        let only = MemoryOnly::new();
        let refused = connect(real).await.map(|_| ()).unwrap_err();
        assert_eq!(
            refused.kind(),
            io::ErrorKind::Other,
            "the guard refused it, not the socket: {refused}"
        );
        assert!(refused.to_string().contains("dialled a real socket"));
        drop(only);
        let reached = connect(real).await.expect("a real socket once it is gone");
        assert!(matches!(reached, Stream::Left(_)), "a TCP stream");
    }
}
