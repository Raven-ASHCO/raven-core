//! The helper channel: how raven-node and its Tor helper reach each other
//! for the onion streams, and how each side proves itself on every stream
//! (`protocol/RAVEN_ONION_CARRIER_V1.md` §6, version 4; security review
//! 2026-11, TOR-4). Shared, file for file, by raven-node (`crate::onion`)
//! and the helpers (`raven-tor-helper`, the loopback helper, the helper in
//! raven-node's own process), as [`super::proto`] is.
//!
//! - **Where the streams go.** On macOS and Linux, one socket pair per
//!   helper life and never a name or a port: a helper process inherits its
//!   end (its config line says `fd:<n>`, [`pair::inherit`]), a helper in
//!   raven-node's process (the iOS app) is handed its end ([`Handed`],
//!   config `conduit`). Every stream, either way, is a fresh socket pair
//!   whose one end goes over the channel ([`Conduit`], SCM_RIGHTS): no other
//!   program, of this user or another, can open one. The opener keeps its
//!   copy of that end until the other side answers on it
//!   ([`pair::PairStream`]; macOS would collect an end in flight with no
//!   other copy). On Windows the streams
//!   stay on loopback TCP (raven-node's forward listener, the helper's
//!   connect port), and each listener holds at most [`PENDING_MAX`]
//!   connections that still owe their hello ([`Pending`]).
//! - **Who proves first.** On every stream raven-node sends a random
//!   challenge; the helper answers with a nonce of its own and its proof
//!   (HMAC-SHA256 under the helper key); raven-node checks it, and only then
//!   sends its own proof (under the node key) and its request. Both keys come
//!   from the helper life's token ([`Keys`]), which never travels on a
//!   stream. A program in the helper's place learns a random challenge and
//!   nothing else; a copied exchange fails on the next stream's fresh nonce.
//!   Each wait is [`HELLO_WAIT`]: the other side answers at once.
//!
//! The request layouts are those of version 3: a proof rides where the
//! token did ([`proto::encode_connect`], [`proto::encode_forward`]).
//!
//! Items only a helper uses are marked
//! `#[cfg_attr(not(debug_assertions), allow(dead_code))]` (a release
//! raven-node has no loopback helper); raven-tor-helper allows dead code in
//! its copy of this file.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Notify;

use super::proto;

#[cfg(unix)]
pub(crate) use pair::Conduit;

/// How long either side waits for the other's next hello message. The other
/// side answers at once, so only a program that is neither waits this long.
pub(crate) const HELLO_WAIT: Duration = Duration::from_secs(2);
/// A challenge or a nonce: random bytes, new on every stream.
pub(crate) const NONCE_LEN: usize = 32;
/// A proof (HMAC-SHA256), where version 3 carried the token.
pub(crate) const PROOF_LEN: usize = proto::TOKEN_LEN;
/// The helper's hello on a connect stream: its nonce, then its proof.
pub(crate) const CONNECT_HELLO_LEN: usize = NONCE_LEN + PROOF_LEN;
/// The helper's hello on a forward stream: its nonce, then the forward
/// header ([`proto::encode_forward`], its proof where the token was).
pub(crate) const FORWARD_HELLO_LEN: usize = NONCE_LEN + proto::FORWARD_HEADER_LEN;
/// Connections at most that wait on a loopback listener of the channel
/// (Windows) for their hello; one more closes the oldest ([`Pending`]).
pub(crate) const PENDING_MAX: usize = 32;
/// [`proto::Config::forward`] for a helper in raven-node's process, and
/// [`proto::Event::Ready`]'s `connect` whenever the streams ride the
/// channel.
pub(crate) const CONDUIT: &str = "conduit";
/// [`proto::Config::forward`] for a channel a helper process inherited:
/// `fd:<n>`.
pub(crate) const INHERITED: &str = "fd:";

/// Where every key and proof of this version starts.
const LABEL: &[u8] = b"raven/onion-helper-channel/v4";

// ── Keys and proofs ─────────────────────────────────────────────────────────

/// One helper life's two keys, from its token: the helper proves itself
/// with one, raven-node with the other, so a proof one side gives never
/// stands for the other side's.
#[derive(Clone)]
pub(crate) struct Keys {
    helper: [u8; 32],
    node: [u8; 32],
}

impl Keys {
    pub(crate) fn new(token: &[u8; proto::TOKEN_LEN]) -> Self {
        Self {
            helper: hmac_sha256(token, &[LABEL, b"/helper"]),
            node: hmac_sha256(token, &[LABEL, b"/node"]),
        }
    }
}

/// Which stream a proof is for: one for a connect never opens a forward.
#[derive(Clone, Copy)]
enum Kind {
    Connect,
    Forward,
}

impl Kind {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Connect => b"/connect",
            Self::Forward => b"/forward",
        }
    }
}

/// The helper's proof on one stream: over raven-node's challenge, then the
/// helper's nonce.
fn helper_proof(
    keys: &Keys,
    kind: Kind,
    challenge: &[u8; NONCE_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; PROOF_LEN] {
    hmac_sha256(
        &keys.helper,
        &[LABEL, kind.tag(), b"/helper", challenge, nonce],
    )
}

/// raven-node's proof on one stream: over the helper's nonce, then
/// raven-node's challenge.
fn node_proof(
    keys: &Keys,
    kind: Kind,
    challenge: &[u8; NONCE_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; PROOF_LEN] {
    hmac_sha256(&keys.node, &[LABEL, kind.tag(), b"/node", nonce, challenge])
}

/// HMAC-SHA256 (RFC 2104) of the concatenated `parts`, under a key of one
/// block (64 bytes) at most.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    assert!(key.len() <= BLOCK, "an HMAC key of one block at most");
    let mut inner = Vec::with_capacity(BLOCK + parts.iter().map(|p| p.len()).sum::<usize>());
    let mut outer = Vec::with_capacity(BLOCK + 32);
    for i in 0..BLOCK {
        let k = key.get(i).copied().unwrap_or(0);
        inner.push(k ^ 0x36);
        outer.push(k ^ 0x5c);
    }
    for part in parts {
        inner.extend_from_slice(part);
    }
    outer.extend_from_slice(&raven_core::release_sign::sha256(&inner));
    raven_core::release_sign::sha256(&outer)
}

/// `step` within [`HELLO_WAIT`]; the error is fixed words.
async fn in_time<T>(step: impl Future<Output = io::Result<T>>) -> Result<T, &'static str> {
    match tokio::time::timeout(HELLO_WAIT, step).await {
        Ok(Ok(got)) => Ok(got),
        Ok(Err(_)) => Err("the stream ended during its hello"),
        Err(_) => Err("no hello in time"),
    }
}

/// The two halves of a hello: a nonce, then a proof.
fn nonce_and_proof(hello: &[u8; CONNECT_HELLO_LEN]) -> ([u8; NONCE_LEN], [u8; PROOF_LEN]) {
    let mut nonce = [0u8; NONCE_LEN];
    let mut proof = [0u8; PROOF_LEN];
    nonce.copy_from_slice(&hello[..NONCE_LEN]);
    proof.copy_from_slice(&hello[NONCE_LEN..]);
    (nonce, proof)
}

// ── The hellos ──────────────────────────────────────────────────────────────

/// raven-node's side of a connect stream: its challenge, then the helper's
/// nonce and proof, checked. Returns raven-node's own proof, for the
/// request's token field ([`proto::encode_connect`]). A peer that is not
/// this life's helper got a random challenge and nothing else.
pub(crate) async fn node_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    keys: &Keys,
) -> Result<[u8; PROOF_LEN], &'static str> {
    let challenge: [u8; NONCE_LEN] = rand::random();
    in_time(stream.write_all(&challenge)).await?;
    let mut hello = [0u8; CONNECT_HELLO_LEN];
    in_time(stream.read_exact(&mut hello)).await?;
    let (nonce, proof) = nonce_and_proof(&hello);
    if !proto::token_eq(
        &proof,
        &helper_proof(keys, Kind::Connect, &challenge, &nonce),
    ) {
        return Err("the Tor helper did not prove itself");
    }
    Ok(node_proof(keys, Kind::Connect, &challenge, &nonce))
}

/// raven-node's side of a forward stream: its challenge, then the helper's
/// nonce and forward header, its proof checked, then raven-node's own
/// proof. Returns the stream's circuit number ([`proto::decode_forward`]).
/// A peer that is not this life's helper got a random challenge and
/// nothing else, and no Raven byte follows.
pub(crate) async fn node_forward<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    keys: &Keys,
) -> Result<u64, &'static str> {
    let challenge: [u8; NONCE_LEN] = rand::random();
    in_time(stream.write_all(&challenge)).await?;
    let mut hello = [0u8; FORWARD_HELLO_LEN];
    in_time(stream.read_exact(&mut hello)).await?;
    let mut nonce = [0u8; NONCE_LEN];
    let mut head = [0u8; proto::FORWARD_HEADER_LEN];
    nonce.copy_from_slice(&hello[..NONCE_LEN]);
    head.copy_from_slice(&hello[NONCE_LEN..]);
    let circuit = proto::decode_forward(
        &head,
        &helper_proof(keys, Kind::Forward, &challenge, &nonce),
    )
    .ok_or("a local connection without the proof of the Tor helper")?;
    in_time(stream.write_all(&node_proof(keys, Kind::Forward, &challenge, &nonce))).await?;
    Ok(circuit)
}

/// The helper's side of a connect stream: raven-node's challenge answered
/// with this helper's nonce and proof, then raven-node's proof checked
/// before the rest of its request is read. The request (onion key, port,
/// flags); `None` when the peer is not raven-node (closed without a word,
/// its request never read) or stayed silent for [`HELLO_WAIT`].
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) async fn helper_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    keys: &Keys,
) -> Option<([u8; 32], u16, u8)> {
    let mut challenge = [0u8; NONCE_LEN];
    in_time(stream.read_exact(&mut challenge)).await.ok()?;
    let nonce: [u8; NONCE_LEN] = rand::random();
    let mut hello = [0u8; CONNECT_HELLO_LEN];
    hello[..NONCE_LEN].copy_from_slice(&nonce);
    hello[NONCE_LEN..].copy_from_slice(&helper_proof(keys, Kind::Connect, &challenge, &nonce));
    in_time(stream.write_all(&hello)).await.ok()?;
    let want = node_proof(keys, Kind::Connect, &challenge, &nonce);
    let mut req = [0u8; proto::CONNECT_REQUEST_LEN];
    in_time(stream.read_exact(&mut req[..PROOF_LEN]))
        .await
        .ok()?;
    let mut got = [0u8; PROOF_LEN];
    got.copy_from_slice(&req[..PROOF_LEN]);
    if !proto::token_eq(&got, &want) {
        return None;
    }
    in_time(stream.read_exact(&mut req[PROOF_LEN..]))
        .await
        .ok()?;
    proto::decode_connect(&req, &want)
}

/// [`helper_connect`] while the connection holds a place in `pending` (a
/// loopback connect port's, Windows): a newcomer past [`PENDING_MAX`]
/// closes the oldest. `None` for `pending`: the channel, which only
/// raven-node reaches.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) async fn helper_connect_in<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    keys: &Keys,
    pending: Option<&Pending>,
) -> Option<([u8; 32], u16, u8)> {
    let Some(pending) = pending else {
        return helper_connect(stream, keys).await;
    };
    let (place, kicked) = pending.enter();
    let asked = tokio::select! {
        biased;
        asked = helper_connect(stream, keys) => asked,
        () = kicked.notified() => None,
    };
    pending.leave(place);
    asked
}

/// The helper's side of a forward stream: raven-node's challenge answered
/// with this helper's nonce and the forward header (its proof, then
/// `circuit`), then raven-node's proof checked. Only then may the stream
/// carry an onion stream's bytes; `Err` when the peer is not raven-node or
/// stayed silent for [`HELLO_WAIT`].
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) async fn helper_forward<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    keys: &Keys,
    circuit: u64,
) -> Result<(), &'static str> {
    let mut challenge = [0u8; NONCE_LEN];
    in_time(stream.read_exact(&mut challenge)).await?;
    let nonce: [u8; NONCE_LEN] = rand::random();
    let proof = helper_proof(keys, Kind::Forward, &challenge, &nonce);
    let mut hello = [0u8; FORWARD_HELLO_LEN];
    hello[..NONCE_LEN].copy_from_slice(&nonce);
    hello[NONCE_LEN..].copy_from_slice(&proto::encode_forward(&proof, circuit));
    in_time(stream.write_all(&hello)).await?;
    let mut got = [0u8; PROOF_LEN];
    in_time(stream.read_exact(&mut got)).await?;
    if proto::token_eq(&got, &node_proof(keys, Kind::Forward, &challenge, &nonce)) {
        Ok(())
    } else {
        Err("raven-node did not prove itself")
    }
}

// ── Loopback listeners (Windows): connections that still owe their hello ───

/// A loopback listener's connections that still owe their hello (raven-node's
/// forward listener, the helper's connect port; Windows, and tests): a
/// newcomer past [`PENDING_MAX`] closes the oldest.
#[derive(Default)]
pub(crate) struct Pending(Mutex<PendingState>);

#[derive(Default)]
struct PendingState {
    next: u64,
    waiting: VecDeque<(u64, Arc<Notify>)>,
}

impl Pending {
    /// A new connection's place, and its "closed for a newcomer" signal.
    pub(crate) fn enter(&self) -> (u64, Arc<Notify>) {
        let mut st = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if st.waiting.len() >= PENDING_MAX {
            if let Some((_, oldest)) = st.waiting.pop_front() {
                // Stores a permit: the wake-up is not lost if that task has
                // not polled yet.
                oldest.notify_one();
            }
        }
        let id = st.next;
        st.next += 1;
        let kicked = Arc::new(Notify::new());
        st.waiting.push_back((id, Arc::clone(&kicked)));
        (id, kicked)
    }

    pub(crate) fn leave(&self, id: u64) {
        let mut st = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        st.waiting.retain(|(w, _)| *w != id);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .waiting
            .len()
    }
}

// ── Streams, and how a helper reaches raven-node ────────────────────────────

/// A stream of the channel: on loopback TCP (`N`, the caller's TCP stream;
/// in tests maybe one in memory) or a socket pair (macOS, Linux).
pub(crate) enum Stream<N> {
    Net(N),
    #[cfg(unix)]
    Pair(pair::PairStream),
}

impl<N: AsyncRead + Unpin> AsyncRead for Stream<N> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Net(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            Self::Pair(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<N: AsyncWrite + Unpin> AsyncWrite for Stream<N> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Net(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            Self::Pair(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Net(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(unix)]
            Self::Pair(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Net(s) => s.is_write_vectored(),
            #[cfg(unix)]
            Self::Pair(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Net(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            Self::Pair(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Net(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Pair(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// What raven-node handed a helper besides its stdin and stdout.
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) enum Handed {
    /// Nothing: a helper process (on macOS and Linux it inherited its
    /// channel end, `fd:<n>`), or a helper in raven-node's process with no
    /// channel (Windows).
    Nothing,
    /// A helper in raven-node's process: its end of the channel. It never
    /// takes a descriptor by number.
    #[cfg(unix)]
    #[cfg_attr(not(any(test, feature = "tor-embedded")), allow(dead_code))]
    Pair(std::os::unix::net::UnixStream),
}

/// How a helper reaches raven-node ([`proto::Config::forward`]).
#[derive(Clone)]
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(crate) enum ToNode {
    /// Windows (and tests): raven-node's forward listener on loopback;
    /// raven-node reaches the helper on a loopback connect port of the
    /// helper's own.
    Port(SocketAddr),
    /// macOS and Linux: the channel, both ways.
    #[cfg(unix)]
    Channel(Arc<Conduit>),
}

#[cfg_attr(not(debug_assertions), allow(dead_code))]
impl ToNode {
    /// From the config line's `forward` and what raven-node `handed` this
    /// helper; the error is the helper's fixed words for it.
    pub(crate) fn from_config(forward: &str, handed: Handed) -> Result<Self, &'static str> {
        #[cfg(unix)]
        {
            let inherited = forward.strip_prefix(INHERITED);
            let end = match (forward == CONDUIT, inherited, handed) {
                (true, _, Handed::Pair(end)) => Some(end),
                (false, Some(number), Handed::Nothing) => Some(pair::take_inherited(number)?),
                (true, _, Handed::Nothing) | (false, Some(_), Handed::Pair(_)) => {
                    return Err("bad forward address");
                }
                (false, None, _) => None,
            };
            if let Some(end) = end {
                return Conduit::helper(end)
                    .map(|conduit| Self::Channel(Arc::new(conduit)))
                    .map_err(|_| "the helper channel could not be opened");
            }
        }
        #[cfg(not(unix))]
        let _ = handed;
        let addr: SocketAddr = forward.parse().map_err(|_| "bad forward address")?;
        if !addr.ip().is_loopback() {
            return Err("forward address is not loopback");
        }
        Ok(Self::Port(addr))
    }

    /// A new stream to raven-node, for one onion stream: over the channel,
    /// or by `dial` to its forward listener. Its hello comes next
    /// ([`helper_forward`]).
    pub(crate) async fn open<N, F, Fut>(&self, dial: F) -> io::Result<Stream<N>>
    where
        F: FnOnce(SocketAddr) -> Fut,
        Fut: Future<Output = io::Result<N>>,
    {
        match self {
            Self::Port(addr) => dial(*addr).await.map(Stream::Net),
            #[cfg(unix)]
            Self::Channel(conduit) => conduit.open().await.map(Stream::Pair),
        }
    }
}

// ── The socket pair channel (macOS, Linux) ──────────────────────────────────

#[cfg(unix)]
pub(crate) mod pair {
    use std::io;
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
    use tokio::net::UnixStream;

    /// The kind byte with a connect stream (raven-node to its helper).
    const TO_HELPER: u8 = b'c';
    /// The kind byte with a forward stream (the helper to raven-node).
    const TO_NODE: u8 = b'f';

    /// No SIGPIPE from a write to a peer that is gone (a process that does
    /// not ignore it, as an app may not, would end): Linux says so per call.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const SEND_FLAGS: libc::c_int = 0;
    /// A descriptor that arrives is closed on exec from its first moment
    /// where the system can do that.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const RECV_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const RECV_FLAGS: libc::c_int = 0;

    /// Room for one descriptor's control message, aligned for its header.
    #[repr(C, align(8))]
    struct Control([u8; 64]);

    /// One side of a helper life's channel ([`new_channel`]): a socket pair
    /// end that carries, for each stream, one end of a fresh socket pair
    /// (SCM_RIGHTS) and one byte that says its kind.
    pub(crate) struct Conduit {
        sock: UnixStream,
        sends: u8,
        takes: u8,
    }

    impl Conduit {
        /// raven-node's end: it opens connect streams and takes forward
        /// streams. In a tokio runtime.
        pub(crate) fn node(end: StdUnixStream) -> io::Result<Self> {
            Self::new(end, TO_HELPER, TO_NODE)
        }

        /// The helper's end. In the helper's tokio runtime.
        #[cfg_attr(not(debug_assertions), allow(dead_code))]
        pub(crate) fn helper(end: StdUnixStream) -> io::Result<Self> {
            Self::new(end, TO_NODE, TO_HELPER)
        }

        fn new(end: StdUnixStream, sends: u8, takes: u8) -> io::Result<Self> {
            no_sigpipe(&end)?;
            end.set_nonblocking(true)?;
            Ok(Self {
                sock: UnixStream::from_std(end)?,
                sends,
                takes,
            })
        }

        /// A new stream to the other side: one end of a fresh socket pair
        /// goes over the channel, the other is returned, and with it this
        /// side's copy of the end it sent, until the other side answers on
        /// that end ([`PairStream`]). macOS and iOS collect a socket whose
        /// every copy is in a message in flight whenever a Unix socket closes
        /// anywhere on the system: closed at once, the other side would take
        /// a dead stream (its reads end at once, writes to it are lost). No
        /// fixed wait would do: an end may stay in flight longer, while an
        /// app is suspended. The opener reads first on both kinds (a connect
        /// stream's hello, a forward stream's challenge), within
        /// [`super::HELLO_WAIT`]; a stream the other side never answers
        /// shows its end only when that wait ran out.
        pub(crate) async fn open(&self) -> io::Result<PairStream> {
            let (ours, theirs) = StdUnixStream::pair()?;
            no_sigpipe(&ours)?;
            no_sigpipe(&theirs)?;
            let (sock, fd) = (self.sock.as_raw_fd(), theirs.as_raw_fd());
            self.sock
                .async_io(Interest::WRITABLE, || send_fd(sock, self.sends, fd))
                .await?;
            ours.set_nonblocking(true)?;
            Ok(PairStream {
                sock: UnixStream::from_std(ours)?,
                sent: Some(theirs),
            })
        }

        /// The next stream the other side opened; `None` once the channel
        /// ended (the other side is gone).
        pub(crate) async fn accept(&self) -> io::Result<Option<PairStream>> {
            let sock = self.sock.as_raw_fd();
            loop {
                let got = self
                    .sock
                    .async_io(Interest::READABLE, || recv_fd(sock))
                    .await?;
                let Some((kind, fd)) = got else {
                    return Ok(None);
                };
                // A byte with no socket, or a stream of the other kind: closed.
                let Some(fd) = fd.filter(|_| kind == self.takes) else {
                    continue;
                };
                let stream = StdUnixStream::from(fd);
                stream.set_nonblocking(true)?;
                return Ok(Some(PairStream {
                    sock: UnixStream::from_std(stream)?,
                    sent: None,
                }));
            }
        }
    }

    /// One stream of the channel: an end of a socket pair of its own. The
    /// side that opened it ([`Conduit::open`]) keeps its copy of the end it
    /// sent until a byte, or the end, comes from the other side: then the
    /// other side holds that end, and no copy of it is in flight any more.
    pub(crate) struct PairStream {
        sock: UnixStream,
        /// The opener's copy of the end it sent, until the other side
        /// answers on it.
        sent: Option<StdUnixStream>,
    }

    impl AsRawFd for PairStream {
        fn as_raw_fd(&self) -> RawFd {
            self.sock.as_raw_fd()
        }
    }

    impl AsyncRead for PairStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let room = buf.remaining();
            let read = Pin::new(&mut this.sock).poll_read(cx, buf);
            if room > 0 && matches!(read, Poll::Ready(Ok(()))) {
                // The other side wrote on its end, or shut it: it has it.
                this.sent = None;
            }
            read
        }
    }

    impl AsyncWrite for PairStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().sock).poll_write(cx, buf)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().sock).poll_write_vectored(cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            self.sock.is_write_vectored()
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().sock).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().sock).poll_shutdown(cx)
        }
    }

    /// A new channel for one helper life: raven-node's end, and the helper's.
    /// The helper's descriptor is above stdin, stdout and stderr (a start
    /// that sets those up never takes its number) and closed on exec until
    /// [`inherit`] clears that in the helper process alone.
    pub(crate) fn new_channel() -> io::Result<(StdUnixStream, StdUnixStream)> {
        let (node, helper) = StdUnixStream::pair()?;
        Ok((node, above_stdio(helper)?))
    }

    fn above_stdio(end: StdUnixStream) -> io::Result<StdUnixStream> {
        if end.as_raw_fd() > 2 {
            return Ok(end);
        }
        // SAFETY: fcntl on a descriptor `end` owns; the copy is a new
        // descriptor, owned below.
        let fd = unsafe { libc::fcntl(end.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is open and nothing else owns it.
        Ok(unsafe { StdUnixStream::from_raw_fd(fd) })
    }

    /// The helper process `cmd` starts keeps `end` across its exec, and only
    /// it: every other descriptor of raven-node is closed on exec (Rust opens
    /// them so), and `end` stays so in raven-node, so no other program gets
    /// the channel. The helper's config line names it ([`super::INHERITED`]).
    #[cfg_attr(feature = "tor-embedded", allow(dead_code))]
    pub(crate) fn inherit(cmd: &mut tokio::process::Command, end: &StdUnixStream) {
        let fd = end.as_raw_fd();
        // SAFETY: the closure runs in the child between fork and exec and
        // calls fcntl alone, which is async-signal-safe; `fd` is open there
        // (the child has raven-node's descriptors until its exec).
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    /// A helper process's inherited end of the channel, by the number its
    /// config line names (`fd:<n>`): only a Unix socket above stderr, and
    /// closed on exec from now on (the helper starts no program).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub(super) fn take_inherited(number: &str) -> Result<StdUnixStream, &'static str> {
        let fd: RawFd = number.parse().map_err(|_| "bad forward address")?;
        if fd <= 2 || !is_unix_socket(fd) {
            return Err("bad forward address");
        }
        // SAFETY: fcntl on an open descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err("bad forward address");
        }
        // SAFETY: raven-node handed this process `fd` for the channel, and
        // nothing else in this process owns it.
        Ok(unsafe { StdUnixStream::from_raw_fd(fd) })
    }

    /// `fd` is a Unix domain socket.
    fn is_unix_socket(fd: RawFd) -> bool {
        // SAFETY: an all zero sockaddr_storage is valid; getsockname writes
        // at most `len` bytes into it.
        let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let got = unsafe {
            libc::getsockname(
                fd,
                (&mut addr as *mut libc::sockaddr_storage).cast(),
                &mut len,
            )
        };
        got == 0 && libc::c_int::from(addr.ss_family) == libc::AF_UNIX
    }

    /// Waits until `stream` has a byte to read, or its end, without taking
    /// it (as [`tokio::net::TcpStream::peek`]): how many bytes a peek saw.
    pub(crate) async fn peek_one(stream: &PairStream) -> io::Result<usize> {
        let fd = stream.as_raw_fd();
        stream
            .sock
            .async_io(Interest::READABLE, || {
                let mut one = 0u8;
                // SAFETY: a buffer of one byte.
                let n = unsafe { libc::recv(fd, (&mut one as *mut u8).cast(), 1, libc::MSG_PEEK) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            })
            .await
    }

    /// No SIGPIPE from a write to a socket whose peer is gone (Apple systems
    /// say so per socket).
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn no_sigpipe(sock: &StdUnixStream) -> io::Result<()> {
        let on: libc::c_int = 1;
        // SAFETY: an int option on an open socket.
        let set = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&on as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if set == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fn no_sigpipe(_sock: &StdUnixStream) -> io::Result<()> {
        Ok(())
    }

    /// One byte, `kind`, with the descriptor `fd` on the channel `sock`.
    pub(super) fn send_fd(sock: RawFd, kind: u8, fd: RawFd) -> io::Result<()> {
        let mut byte = [kind];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = Control([0; 64]);
        // SAFETY: the size of one descriptor's control message (a const fn).
        let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as libc::c_uint) } as usize;
        // SAFETY: an all zero msghdr is a valid empty one.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        // SAFETY: msg_control holds `space` bytes, room for the header and
        // one descriptor; CMSG_FIRSTHDR returns its start.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as libc::c_uint) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        }
        // SAFETY: msg points at live buffers of the lengths it names.
        let sent = unsafe { libc::sendmsg(sock, &msg, SEND_FLAGS) };
        match sent {
            n if n < 0 => Err(io::Error::last_os_error()),
            1 => Ok(()),
            _ => Err(io::ErrorKind::WriteZero.into()),
        }
    }

    /// One message of the channel `sock`: its kind byte and the Unix socket
    /// that came with it (any other descriptor that came is closed); `None`
    /// at the channel's end.
    fn recv_fd(sock: RawFd) -> io::Result<Option<(u8, Option<OwnedFd>)>> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = Control([0; 64]);
        // SAFETY: an all zero msghdr is a valid empty one.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = control.0.len() as _;
        // SAFETY: msg points at live buffers of the lengths it names.
        let got = unsafe { libc::recvmsg(sock, &mut msg, RECV_FLAGS) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        // Every descriptor that came is this process's now: the first one
        // kept, any other closed.
        let mut taken: Option<OwnedFd> = None;
        // SAFETY: the kernel wrote `msg_controllen` bytes of well formed
        // control messages; each descriptor is read unaligned from its data.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    let data = libc::CMSG_DATA(cmsg);
                    let bytes =
                        ((*cmsg).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                    for i in 0..bytes / size_of::<RawFd>() {
                        let fd = std::ptr::read_unaligned(
                            data.add(i * size_of::<RawFd>()).cast::<RawFd>(),
                        );
                        let owned = OwnedFd::from_raw_fd(fd);
                        if taken.is_none() {
                            taken = Some(owned);
                        }
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
        if got == 0 && taken.is_none() {
            return Ok(None);
        }
        let truncated = msg.msg_flags & libc::MSG_CTRUNC != 0;
        let taken = taken.filter(|fd| {
            // SAFETY: fcntl on a descriptor `fd` owns.
            let closed_on_exec =
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0;
            !truncated && closed_on_exec && is_unix_socket(fd.as_raw_fd())
        });
        Ok(Some((byte[0], taken)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test cases 1 and 2.
    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], &[b"Hi There"])),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(hmac_sha256(
                b"Jefe",
                &[b"what do ya want ", b"for nothing?"]
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// The helper key and the node key differ, and both change with the
    /// token; the token itself is neither.
    #[test]
    fn each_side_has_its_own_key_from_the_token() {
        let (a, b) = (Keys::new(&[1; 32]), Keys::new(&[2; 32]));
        assert_ne!(a.helper, a.node);
        assert_ne!(a.helper, b.helper);
        assert_ne!(a.node, b.node);
        assert!(a.helper != [1; 32] && a.node != [1; 32]);
    }

    /// The node's side and the helper's side of one connect stream: the
    /// helper gets the request; on the wire, neither the token nor either key.
    #[tokio::test(start_paused = true)]
    async fn a_connect_hello_gives_the_helper_the_request() {
        let token = [7u8; proto::TOKEN_LEN];
        let keys = Keys::new(&token);
        let (mut node, mut helper) = tokio::io::duplex(1024);
        let helping = {
            let keys = keys.clone();
            tokio::spawn(async move { helper_connect(&mut helper, &keys).await })
        };
        let proof = node_connect(&mut node, &keys)
            .await
            .expect("the helper proved itself");
        node.write_all(&proto::encode_connect(&proof, &[9; 32], 7422, 0))
            .await
            .unwrap();
        assert_eq!(helping.await.unwrap(), Some(([9; 32], 7422, 0)));
        assert!(proof != token && proof != keys.node && proof != keys.helper);
    }

    /// The node's side and the helper's side of one forward stream: the node
    /// gets the circuit number, the helper the node's proof.
    #[tokio::test(start_paused = true)]
    async fn a_forward_hello_gives_the_node_the_circuit() {
        let keys = Keys::new(&[8u8; proto::TOKEN_LEN]);
        let (mut node, mut helper) = tokio::io::duplex(1024);
        let helping = {
            let keys = keys.clone();
            tokio::spawn(async move { helper_forward(&mut helper, &keys, 41).await })
        };
        assert_eq!(node_forward(&mut node, &keys).await, Ok(41));
        assert_eq!(helping.await.unwrap(), Ok(()));
    }

    /// A peer in the helper's place that cannot prove itself is left with
    /// raven-node's random challenge alone: no proof, no request.
    #[tokio::test(start_paused = true)]
    async fn the_node_says_nothing_more_to_a_helper_without_the_key() {
        let (mut node, mut stranger) = tokio::io::duplex(1024);
        let listening = tokio::spawn(async move {
            let mut challenge = [0u8; NONCE_LEN];
            stranger.read_exact(&mut challenge).await.unwrap();
            stranger
                .write_all(&[0x33; CONNECT_HELLO_LEN])
                .await
                .unwrap();
            let mut rest = Vec::new();
            let _ = stranger.read_to_end(&mut rest).await;
            rest
        });
        let keys = Keys::new(&[5u8; proto::TOKEN_LEN]);
        assert!(node_connect(&mut node, &keys).await.is_err());
        drop(node);
        assert!(
            listening.await.unwrap().is_empty(),
            "nothing after the challenge"
        );
    }

    /// A wrong proof from raven-node's side is refused before the rest of its
    /// request is read: the helper is done the moment the proof is in (no
    /// wait, the onion key never sent), and a proof from another stream (a
    /// copy) is as wrong as any.
    #[tokio::test(start_paused = true)]
    async fn a_wrong_or_copied_proof_is_refused_before_the_request_is_read() {
        let keys = Keys::new(&[6u8; proto::TOKEN_LEN]);
        // One whole exchange, its proof kept.
        let (mut node, mut helper) = tokio::io::duplex(1024);
        let helping = {
            let keys = keys.clone();
            tokio::spawn(async move { helper_connect(&mut helper, &keys).await })
        };
        let first = node_connect(&mut node, &keys).await.unwrap();
        node.write_all(&proto::encode_connect(&first, &[1; 32], 7422, 0))
            .await
            .unwrap();
        assert!(helping.await.unwrap().is_some());
        for proof in [first, [0u8; PROOF_LEN]] {
            let (mut node, mut helper) = tokio::io::duplex(1024);
            let helping = {
                let keys = keys.clone();
                tokio::spawn(async move { helper_connect(&mut helper, &keys).await })
            };
            node.write_all(&[0x44; NONCE_LEN]).await.unwrap();
            let mut hello = [0u8; CONNECT_HELLO_LEN];
            node.read_exact(&mut hello).await.unwrap();
            let began = tokio::time::Instant::now();
            node.write_all(&proof).await.unwrap();
            assert_eq!(helping.await.unwrap(), None);
            assert_eq!(began.elapsed(), Duration::ZERO, "refused at once");
        }
    }

    /// A copy of a helper's forward hello is refused by raven-node: its
    /// challenge is new on every stream.
    #[tokio::test(start_paused = true)]
    async fn a_copied_forward_hello_is_refused() {
        let keys = Keys::new(&[4u8; proto::TOKEN_LEN]);
        let (mut node, mut helper) = tokio::io::duplex(1024);
        let helping = {
            let keys = keys.clone();
            tokio::spawn(async move {
                let mut copy = [0u8; FORWARD_HELLO_LEN];
                let mut challenge = [0u8; NONCE_LEN];
                helper.read_exact(&mut challenge).await.unwrap();
                // As helper_forward, the hello kept.
                let nonce = [0x21; NONCE_LEN];
                let proof = helper_proof(&keys, Kind::Forward, &challenge, &nonce);
                copy[..NONCE_LEN].copy_from_slice(&nonce);
                copy[NONCE_LEN..].copy_from_slice(&proto::encode_forward(&proof, 3));
                helper.write_all(&copy).await.unwrap();
                // Its end stays open for raven-node's proof.
                (copy, helper)
            })
        };
        assert_eq!(node_forward(&mut node, &keys).await, Ok(3));
        let (copy, _helper) = helping.await.unwrap();
        let (mut node, mut stranger) = tokio::io::duplex(1024);
        stranger.write_all(&copy).await.unwrap();
        assert!(node_forward(&mut node, &keys).await.is_err());
    }

    /// Each side gives up on a peer that says nothing after [`HELLO_WAIT`],
    /// at every step.
    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_is_dropped_after_the_hello_wait() {
        let keys = Keys::new(&[3u8; proto::TOKEN_LEN]);
        let (mut a, _silent_a) = tokio::io::duplex(1024);
        let began = tokio::time::Instant::now();
        assert_eq!(helper_connect(&mut a, &keys).await, None);
        assert_eq!(began.elapsed(), HELLO_WAIT);
        let (mut b, _silent_b) = tokio::io::duplex(1024);
        let began = tokio::time::Instant::now();
        assert!(node_connect(&mut b, &keys).await.is_err());
        assert_eq!(began.elapsed(), HELLO_WAIT);
        let (mut c, _silent_c) = tokio::io::duplex(1024);
        let began = tokio::time::Instant::now();
        assert!(node_forward(&mut c, &keys).await.is_err());
        assert_eq!(began.elapsed(), HELLO_WAIT);
        let (mut d, _silent_d) = tokio::io::duplex(1024);
        let began = tokio::time::Instant::now();
        assert!(helper_forward(&mut d, &keys, 1).await.is_err());
        assert_eq!(began.elapsed(), HELLO_WAIT);
        // A node that sent its challenge and then went silent: the helper
        // waits once more, no longer.
        let (mut e, mut half) = tokio::io::duplex(1024);
        half.write_all(&[0; NONCE_LEN]).await.unwrap();
        let began = tokio::time::Instant::now();
        assert_eq!(helper_connect(&mut e, &keys).await, None);
        assert_eq!(began.elapsed(), HELLO_WAIT);
    }

    /// A gated connect gives up its place when its hello ends, and the 33rd
    /// waiting connection closes the oldest.
    #[tokio::test(start_paused = true)]
    async fn the_pending_gate_closes_the_oldest_for_a_newcomer() {
        let keys = Keys::new(&[2u8; proto::TOKEN_LEN]);
        let pending = Arc::new(Pending::default());
        let mut peers = Vec::new();
        let mut waits = Vec::new();
        for _ in 0..PENDING_MAX + 1 {
            let (mut ours, theirs) = tokio::io::duplex(1024);
            peers.push(theirs);
            let (keys, pending) = (keys.clone(), Arc::clone(&pending));
            waits.push(tokio::spawn(async move {
                helper_connect_in(&mut ours, &keys, Some(&pending)).await
            }));
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let oldest = waits.remove(0);
        let began = tokio::time::Instant::now();
        assert_eq!(oldest.await.unwrap(), None);
        assert_eq!(began.elapsed(), Duration::ZERO, "closed at once");
        assert_eq!(pending.len(), PENDING_MAX);
        for wait in waits {
            assert_eq!(wait.await.unwrap(), None);
        }
        assert_eq!(pending.len(), 0, "every place given back");
    }

    /// `fd:<n>` is a Unix socket a helper process inherited, never another
    /// descriptor or one of stdin, stdout and stderr; `conduit` only with an
    /// end handed over in process, which never takes a number; a port only
    /// on loopback.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_config_names_a_channel_or_a_loopback_port() {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let file = tempfile::tempfile().unwrap();
        let not_a_socket = format!("{INHERITED}{}", file.as_raw_fd());
        assert!(ToNode::from_config(&not_a_socket, Handed::Nothing).is_err());
        assert!(file.metadata().is_ok(), "a refused number stays open");
        assert!(ToNode::from_config("fd:2", Handed::Nothing).is_err());
        assert!(ToNode::from_config(CONDUIT, Handed::Nothing).is_err());
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let number = format!("{INHERITED}{}", theirs.as_raw_fd());
        let (_keep, handed) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(ToNode::from_config(&number, Handed::Pair(handed)).is_err());
        let fd = theirs.into_raw_fd();
        assert!(matches!(
            ToNode::from_config(&format!("{INHERITED}{fd}"), Handed::Nothing),
            Ok(ToNode::Channel(_))
        ));
        drop(ours);
        let (_keep, handed) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(matches!(
            ToNode::from_config(CONDUIT, Handed::Pair(handed)),
            Ok(ToNode::Channel(_))
        ));
        assert!(matches!(
            ToNode::from_config("127.0.0.1:9", Handed::Nothing),
            Ok(ToNode::Port(_))
        ));
        assert_eq!(
            ToNode::from_config("192.0.2.1:9", Handed::Nothing).err(),
            Some("forward address is not loopback")
        );
    }

    /// `step` within a few seconds: a dead stream fails a test at once
    /// instead of holding it.
    #[cfg(unix)]
    async fn soon<T>(step: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), step)
            .await
            .expect("within 5 s")
    }

    /// Streams both ways over one channel: each side takes only the kind
    /// the other opens; a descriptor that arrives is closed on exec; the
    /// end of the channel ends `accept`; a peek takes no byte.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_channel_carries_streams_both_ways() {
        use std::os::fd::AsRawFd;
        let (node_end, helper_end) = pair::new_channel().unwrap();
        assert!(helper_end.as_raw_fd() > 2);
        let (node, helper) = (
            Conduit::node(node_end).unwrap(),
            Conduit::helper(helper_end).unwrap(),
        );
        let mut dialled = soon(node.open()).await.unwrap();
        let mut asked = soon(helper.accept())
            .await
            .unwrap()
            .expect("a connect stream");
        // SAFETY: fcntl on an open descriptor.
        let flags = unsafe { libc::fcntl(asked.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        soon(dialled.write_all(b"to the helper")).await.unwrap();
        assert_eq!(soon(pair::peek_one(&asked)).await.unwrap(), 1);
        let mut got = [0u8; 13];
        soon(asked.read_exact(&mut got)).await.unwrap();
        assert_eq!(&got, b"to the helper");
        let mut forwarded = soon(helper.open()).await.unwrap();
        let mut came = soon(node.accept())
            .await
            .unwrap()
            .expect("a forward stream");
        soon(forwarded.write_all(b"to the node")).await.unwrap();
        let mut got = [0u8; 11];
        soon(came.read_exact(&mut got)).await.unwrap();
        assert_eq!(&got, b"to the node");
        // A node end never takes a connect stream (the kind its own side
        // opens), nor a helper end a forward stream.
        let (node_end, helper_end) = pair::new_channel().unwrap();
        let (node, helper) = (
            Conduit::node(node_end).unwrap(),
            Conduit::node(helper_end).unwrap(),
        );
        let _wrong = soon(helper.open()).await.unwrap();
        drop(helper);
        assert!(
            soon(node.accept()).await.unwrap().is_none(),
            "skipped, then the end"
        );
    }

    /// What `stream` holds right now, without a wait: `Some(0)` its end,
    /// `Some(1)` a byte to read, `None` nothing yet.
    #[cfg(unix)]
    fn peek_now(stream: &impl std::os::fd::AsRawFd) -> Option<usize> {
        let mut one = 0u8;
        // SAFETY: a buffer of one byte.
        let n = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                (&mut one as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n >= 0 {
            return Some(n as usize);
        }
        let e = io::Error::last_os_error();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
        None
    }

    /// The opener keeps its copy of the end it sent until the other side
    /// answers on it, and no longer: a stream the other side took and
    /// closed without a word shows no end while that copy is kept (it goes
    /// with the stream, which its hello wait ends); once the other side
    /// wrote, its close ends the stream at once.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_opener_keeps_the_sent_end_until_the_other_side_answers() {
        let (node_end, helper_end) = pair::new_channel().unwrap();
        let (node, helper) = (
            Conduit::node(node_end).unwrap(),
            Conduit::helper(helper_end).unwrap(),
        );
        let unanswered = soon(node.open()).await.unwrap();
        drop(
            soon(helper.accept())
                .await
                .unwrap()
                .expect("a connect stream"),
        );
        assert_eq!(peek_now(&unanswered), None, "an end while the copy is kept");
        let mut answered = soon(node.open()).await.unwrap();
        let mut taken = soon(helper.accept())
            .await
            .unwrap()
            .expect("a connect stream");
        soon(taken.write_all(b"h")).await.unwrap();
        let mut one = [0u8; 1];
        soon(answered.read_exact(&mut one)).await.unwrap();
        drop(taken);
        assert_eq!(peek_now(&answered), Some(0), "its end, at once");
    }

    /// No stream dies on its way over the channel (security review 2026-11,
    /// onion3): macOS and iOS collect a socket whose every copy is in a
    /// message in flight whenever a Unix socket closes somewhere, and the
    /// side that takes it then holds a dead stream (its reads end at once).
    /// Streams both ways, each in the order of its hello (a connect stream's
    /// opener speaks first, a forward stream's taker), while two threads
    /// close Unix sockets that carry descriptors: every stream carries its
    /// bytes both ways.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_stream_dies_in_flight_while_unix_sockets_close() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream as StdUnixStream;
        use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
        const STREAMS: usize = 2000;
        let stop = Arc::new(AtomicBool::new(false));
        let closing: Vec<_> = (0..2)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Relaxed) {
                        let (a, b) = StdUnixStream::pair().unwrap();
                        let (x, y) = StdUnixStream::pair().unwrap();
                        let _ = pair::send_fd(a.as_raw_fd(), b'x', x.as_raw_fd());
                        // `x` in flight to `b`, then every one closed.
                        drop((x, y, b, a));
                    }
                })
            })
            .collect();
        let (node_end, helper_end) = pair::new_channel().unwrap();
        let (node, helper) = (
            Conduit::node(node_end).unwrap(),
            Conduit::helper(helper_end).unwrap(),
        );
        let mut dead = None;
        for i in 0..STREAMS {
            let connect = i % 2 == 0;
            let (opener, taker) = if connect {
                (&node, &helper)
            } else {
                (&helper, &node)
            };
            let carried = tokio::time::timeout(HELLO_WAIT, async {
                let mut opened = opener.open().await?;
                let mut taken = taker.accept().await?.ok_or(io::ErrorKind::UnexpectedEof)?;
                let mut one = [0u8; 1];
                if connect {
                    opened.write_all(b"c").await?;
                    taken.read_exact(&mut one).await?;
                    taken.write_all(b"h").await?;
                    opened.read_exact(&mut one).await?;
                } else {
                    taken.write_all(b"c").await?;
                    opened.read_exact(&mut one).await?;
                    opened.write_all(b"h").await?;
                    taken.read_exact(&mut one).await?;
                }
                io::Result::Ok(())
            })
            .await;
            if !matches!(carried, Ok(Ok(()))) {
                dead = Some((i, carried));
                break;
            }
        }
        stop.store(true, Relaxed);
        for thread in closing {
            thread.join().unwrap();
        }
        assert!(dead.is_none(), "a stream died on its way: {dead:?}");
    }
}
