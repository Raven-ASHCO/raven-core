//! The WebSocket subset of RWS1 (`protocol/RAVEN_WSS_TRANSPORT_V1.md` §5):
//! the HTTP/1.1 upgrade both ways, and [`WsStream`], which turns binary
//! messages into the byte stream libp2p runs on. Raven's own binary-only
//! subset of RFC 6455 (owner decision O4-1: no WebSocket crate). The frame
//! codec is raven-core's [`raven_core::ws_frame`]; heads are parsed with
//! httparse and the accept value's SHA-1 is ring's legacy SHA-1, both
//! already in the build.
//!
//! - [`client`]: `GET /` with Host, `Upgrade: websocket`,
//!   `Connection: Upgrade`, a fresh random key and version 13; no Origin,
//!   subprotocol, extension or User-Agent. It takes only a `101` with the
//!   right `Sec-WebSocket-Accept` and no extension or subprotocol.
//! - [`server`]: a `GET /` with exactly one Host, `Upgrade: websocket`,
//!   `Connection: upgrade`, exactly one valid key and exactly one version
//!   13 gets the `101` (no Server header); anything else gets
//!   [`NOT_FOUND`], then the connection is closed.
//! - Heads are at most [`WS_MAX_HEADER_BLOCK`] bytes through their blank
//!   line and at most [`WS_MAX_HEADERS`] headers, both ways, with CRLF
//!   line ends only.
//! - [`WsStream`]: each write is one binary frame of at most
//!   [`MAX_SEND_PAYLOAD`] bytes, a client's with a fresh random mask. Reads
//!   join messages, answer a ping with a pong and a close with a close
//!   (then end), and answer a frame the subset refuses with a close
//!   carrying its code (a text message 1003) and an error. Raven sends no
//!   pings: libp2p's ping keeps proxies and NATs awake.
//!
//! Vectors: `shared-vectors/rvn1/wss/rws1_ws_handshake_001.json` (checked
//! here) and `rws1_ws_frames_001.json` (checked in raven-core).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::io::{AsyncRead, AsyncWrite};
use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use raven_core::ws_frame::{
    accept_token, apply_mask, close_code, encode, parse_head, valid_key, Reassembly, WsClose,
    OP_BINARY, OP_CLOSE, OP_PING, OP_PONG, WS_MAX_HEADERS, WS_MAX_HEADER_BLOCK,
};

/// Largest payload of a frame Raven sends: one write, at most this much.
pub const MAX_SEND_PAYLOAD: usize = 16 * 1024;

/// What a server answers to anything but a WebSocket upgrade of `/`,
/// before it closes the connection (RWS1 §5).
pub const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Room a read of the stream underneath gets, at least.
const READ_CHUNK: usize = 16 * 1024;

/// A read buffer with more room than this is shrunk once little of it is
/// in use: one large frame does not pin its memory for the connection's
/// life.
const SHRINK_ABOVE: usize = 4 * READ_CHUNK;

/// SHA-1, for `Sec-WebSocket-Accept` only.
fn sha1(data: &[u8]) -> [u8; 20] {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    let mut out = [0u8; 20];
    out.copy_from_slice(digest.as_ref());
    out
}

/// The `Sec-WebSocket-Accept` value for a key.
fn accept(key: &str) -> String {
    accept_token(sha1, key)
}

/// The client's upgrade request.
fn request(host: &str, key: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes()
}

/// The server's `101` for a request carrying this key.
fn response(key: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        accept(key)
    )
    .into_bytes()
}

fn invalid(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

/// Upgrades a new connection (TLS already on it) as the client. `host` is
/// the Host value: the SNI name or the IP literal (an IPv6 one in
/// brackets), with `:port` when the port is not 443.
pub async fn client<S>(io: S, host: &str) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = STANDARD.encode(rand::random::<[u8; 16]>());
    client_with_key(io, host, &key).await
}

async fn client_with_key<S>(mut io: S, host: &str, key: &str) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if host.is_empty() || !host.bytes().all(|b| matches!(b, 0x21..=0x7e)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket: not a Host value",
        ));
    }
    io.write_all(&request(host, key)).await?;
    io.flush().await?;
    let (head, rest) = match read_head(&mut io).await {
        Ok(read) => read,
        Err(HeadError::Io(e)) => return Err(e),
        Err(HeadError::TooLarge) => return Err(invalid("websocket: reply head over 8192 bytes")),
    };
    check_response(&head, key)?;
    Ok(WsStream::new(io, true, rest))
}

/// Serves the upgrade on a new connection (TLS already on it): a valid
/// upgrade of `/` gets the `101` and the stream; anything else gets
/// [`NOT_FOUND`], the connection is closed and this fails.
pub async fn server<S>(mut io: S) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (head, rest) = match read_head(&mut io).await {
        Ok(read) => read,
        Err(HeadError::Io(e)) => return Err(e),
        Err(HeadError::TooLarge) => (Vec::new(), Vec::new()),
    };
    match check_request(&head) {
        Some(key) => {
            io.write_all(&response(&key)).await?;
            io.flush().await?;
            Ok(WsStream::new(io, false, rest))
        }
        None => {
            // The refusal stands whether or not the 404 gets through.
            let _ = not_found(&mut io).await;
            Err(invalid("websocket: not an upgrade of /"))
        }
    }
}

async fn not_found<S: AsyncWrite + Unpin>(io: &mut S) -> io::Result<()> {
    io.write_all(NOT_FOUND).await?;
    io.flush().await?;
    io.close().await
}

/// Why [`read_head`] stopped.
enum HeadError {
    /// No blank line within [`WS_MAX_HEADER_BLOCK`] bytes.
    TooLarge,
    Io(io::Error),
}

/// Reads one HTTP head, through its blank line, of at most
/// [`WS_MAX_HEADER_BLOCK`] bytes. Returns it and the bytes read after it,
/// which are the stream's first bytes.
async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> Result<(Vec<u8>, Vec<u8>), HeadError> {
    let mut buf = vec![0u8; WS_MAX_HEADER_BLOCK];
    let mut filled = 0;
    while filled < buf.len() {
        let n = io.read(&mut buf[filled..]).await.map_err(HeadError::Io)?;
        if n == 0 {
            return Err(HeadError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        let from = filled.saturating_sub(3);
        filled += n;
        if let Some(at) = buf[from..filled].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = from + at + 4;
            let rest = buf[end..filled].to_vec();
            buf.truncate(end);
            return Ok((buf, rest));
        }
    }
    Err(HeadError::TooLarge)
}

/// A head that starts with its start line and ends its lines with CRLF
/// only. httparse would also take a bare LF as a line end and skip empty
/// lines before the start line; the subset takes neither.
fn crlf_only(head: &[u8]) -> bool {
    head.first().is_some_and(|b| !matches!(b, b'\r' | b'\n'))
        && head.iter().enumerate().all(|(i, &b)| match b {
            b'\r' => head.get(i + 1) == Some(&b'\n'),
            b'\n' => head[i - 1] == b'\r',
            _ => true,
        })
}

fn trim(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// The values of every header with this (lower-case) name.
fn values<'a>(
    headers: &'a [httparse::Header<'a>],
    name: &'a str,
) -> impl Iterator<Item = &'a [u8]> + 'a {
    headers
        .iter()
        .filter(move |h| h.name.eq_ignore_ascii_case(name))
        .map(|h| trim(h.value))
}

/// Whether the comma-separated values of a header list `token`, in any
/// case.
fn lists(headers: &[httparse::Header<'_>], name: &str, token: &str) -> bool {
    values(headers, name).any(|v| {
        v.split(|&b| b == b',')
            .any(|t| trim(t).eq_ignore_ascii_case(token.as_bytes()))
    })
}

/// The value of a header that must be there exactly once.
fn single<'a>(headers: &'a [httparse::Header<'a>], name: &'a str) -> Option<&'a [u8]> {
    let mut all = values(headers, name);
    let first = all.next()?;
    all.next().is_none().then_some(first)
}

/// The key of an upgrade request the server answers with `101`, or none
/// (RWS1 §5).
fn check_request(head: &[u8]) -> Option<String> {
    if !crlf_only(head) {
        return None;
    }
    let mut headers = [httparse::EMPTY_HEADER; WS_MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(head) != Ok(httparse::Status::Complete(head.len())) {
        return None;
    }
    if req.method != Some("GET") || req.path != Some("/") || req.version != Some(1) {
        return None;
    }
    let h = &*req.headers;
    if values(h, "host").count() != 1
        || !lists(h, "upgrade", "websocket")
        || !lists(h, "connection", "upgrade")
        || single(h, "sec-websocket-version") != Some(&b"13"[..])
    {
        return None;
    }
    let key = std::str::from_utf8(single(h, "sec-websocket-key")?).ok()?;
    valid_key(key).then(|| key.to_owned())
}

/// Whether the client takes a reply to its request with this key (RWS1
/// §5).
fn check_response(head: &[u8], key: &str) -> io::Result<()> {
    let mut headers = [httparse::EMPTY_HEADER; WS_MAX_HEADERS];
    let mut res = httparse::Response::new(&mut headers);
    if !crlf_only(head) || res.parse(head) != Ok(httparse::Status::Complete(head.len())) {
        return Err(invalid("websocket: malformed reply"));
    }
    if res.version != Some(1) || res.code != Some(101) {
        let code = res.code.unwrap_or(0);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket: the relay answered HTTP {code}, not 101"),
        ));
    }
    let h = &*res.headers;
    if !lists(h, "upgrade", "websocket") || !lists(h, "connection", "upgrade") {
        return Err(invalid("websocket: not an upgrade reply"));
    }
    if single(h, "sec-websocket-accept") != Some(accept(key).as_bytes()) {
        return Err(invalid("websocket: wrong Sec-WebSocket-Accept"));
    }
    if values(h, "sec-websocket-extensions").next().is_some()
        || values(h, "sec-websocket-protocol").next().is_some()
    {
        return Err(invalid(
            "websocket: an extension or subprotocol nobody offered",
        ));
    }
    Ok(())
}

fn refused_frame(close: WsClose) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("websocket: refused a frame, closed with {}", close.code()),
    )
}

/// One frame [`WsStream`] took off the wire.
enum Frame {
    /// The frame ended a message.
    Message(Vec<u8>),
    /// A ping, with its payload.
    Ping(Vec<u8>),
    /// A close.
    Close,
    /// A pong, or a fragment of a message that goes on.
    Other,
}

/// Where reading stands.
#[derive(Clone, Copy)]
enum ReadEnd {
    Open,
    /// A close came (and was answered), or the stream ended between frames.
    Eof,
    /// A frame the subset refuses came; the close carried this code.
    Refused(WsClose),
}

/// A WebSocket connection as a byte stream (RWS1 §5): what libp2p's
/// multistream-select, Noise and Yamux run on. Built by [`client`] or
/// [`server`].
pub struct WsStream<S> {
    io: S,
    /// A client masks what it sends and reads unmasked frames; a server
    /// the reverse.
    client: bool,
    /// Bytes read and not yet taken as frames: `rbuf[rpos..rlen]`. The
    /// rest of `rbuf` is room for the next read (kept, not zeroed again).
    rbuf: Vec<u8>,
    rpos: usize,
    rlen: usize,
    msg: Reassembly,
    /// A message received and not yet read: `ready[ready_pos..]`.
    ready: Vec<u8>,
    ready_pos: usize,
    read_end: ReadEnd,
    /// Whole frames not yet written: `wbuf[wpos..]`.
    wbuf: Vec<u8>,
    wpos: usize,
    /// The payload of the latest ping not yet answered (RFC 6455 §5.5.3:
    /// only the latest needs a pong).
    pong: Option<Vec<u8>>,
    /// A close is queued or sent: nothing is sent after it.
    closing: bool,
}

impl<S> WsStream<S> {
    fn new(io: S, client: bool, first: Vec<u8>) -> Self {
        Self {
            io,
            client,
            rlen: first.len(),
            rbuf: first,
            rpos: 0,
            msg: Reassembly::new(),
            ready: Vec::new(),
            ready_pos: 0,
            read_end: ReadEnd::Open,
            wbuf: Vec::new(),
            wpos: 0,
            pong: None,
            closing: false,
        }
    }

    /// A fresh masking key for a client's frame; none for a server's.
    fn mask(&self) -> Option<[u8; 4]> {
        self.client.then(rand::random)
    }

    /// Queues a close with this code, unless one is queued or sent; an
    /// unanswered ping is then left unanswered.
    fn queue_close(&mut self, close: WsClose) {
        if !self.closing {
            self.closing = true;
            self.pong = None;
            let mask = self.mask();
            encode(OP_CLOSE, &close.payload(), mask, &mut self.wbuf);
        }
    }

    /// Takes the next whole frame off `rbuf`, if one is there.
    fn next_frame(&mut self) -> Result<Option<Frame>, WsClose> {
        let wire = &mut self.rbuf[self.rpos..self.rlen];
        let Some(head) = parse_head(wire, !self.client)? else {
            return Ok(None);
        };
        let Some(payload) = wire.get_mut(head.hdr_len..head.frame_len()) else {
            return Ok(None);
        };
        if let Some(key) = head.mask {
            apply_mask(payload, key, 0);
        }
        let frame = match head.op {
            OP_PING => Frame::Ping(payload.to_vec()),
            OP_PONG => Frame::Other,
            OP_CLOSE => {
                close_code(payload)?;
                Frame::Close
            }
            op => match self.msg.push(head.fin, op, payload)? {
                Some(message) => Frame::Message(message),
                None => Frame::Other,
            },
        };
        self.rpos += head.frame_len();
        Ok(Some(frame))
    }
}

impl<S: AsyncWrite + Unpin> WsStream<S> {
    /// Writes out the queued frames, then the pong of an unanswered ping.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            while self.wpos < self.wbuf.len() {
                let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.wbuf[self.wpos..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.wpos += n;
            }
            self.wbuf.clear();
            self.wpos = 0;
            match self.pong.take() {
                Some(payload) if !self.closing => {
                    let mask = self.mask();
                    encode(OP_PONG, &payload, mask, &mut self.wbuf);
                }
                _ => return Poll::Ready(Ok(())),
            }
        }
    }

    /// Sends what the reading side queued (a pong, a close) as far as the
    /// stream takes it now. Whatever stays queued goes out with the next
    /// write, flush or close; an error shows up there too.
    fn push_replies(&mut self, cx: &mut Context<'_>) {
        if let Poll::Ready(Ok(())) = self.poll_send(cx) {
            let _ = Pin::new(&mut self.io).poll_flush(cx);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // A reply the stream did not take at once goes on going out while
        // the connection is read, also when nothing else is written.
        if this.wpos < this.wbuf.len() || this.pong.is_some() {
            this.push_replies(cx);
        }
        loop {
            if this.ready_pos < this.ready.len() {
                let n = buf.len().min(this.ready.len() - this.ready_pos);
                buf[..n].copy_from_slice(&this.ready[this.ready_pos..this.ready_pos + n]);
                this.ready_pos += n;
                if this.ready_pos == this.ready.len() {
                    // Read whole: its memory goes now, not with the next
                    // message (review A-7).
                    this.ready = Vec::new();
                    this.ready_pos = 0;
                }
                return Poll::Ready(Ok(n));
            }
            match this.read_end {
                ReadEnd::Open => {}
                ReadEnd::Eof => return Poll::Ready(Ok(0)),
                ReadEnd::Refused(close) => return Poll::Ready(Err(refused_frame(close))),
            }
            match this.next_frame() {
                Ok(Some(Frame::Message(message))) => {
                    this.ready = message;
                    this.ready_pos = 0;
                }
                Ok(Some(Frame::Ping(payload))) => {
                    this.pong = Some(payload);
                    this.push_replies(cx);
                }
                Ok(Some(Frame::Other)) => {}
                Ok(Some(Frame::Close)) => {
                    this.queue_close(WsClose::NORMAL);
                    this.push_replies(cx);
                    this.read_end = ReadEnd::Eof;
                }
                Err(close) => {
                    this.queue_close(close);
                    this.push_replies(cx);
                    this.read_end = ReadEnd::Refused(close);
                }
                Ok(None) => {
                    // Need more bytes: move what is left of a frame to the
                    // front (once per frame taken), make room, then read.
                    if this.rpos > 0 {
                        this.rbuf.copy_within(this.rpos..this.rlen, 0);
                        this.rlen -= this.rpos;
                        this.rpos = 0;
                    }
                    // A large frame grew `rbuf` (to about twice
                    // WS_MAX_MESSAGE); once little of it is in use, give that
                    // back instead of keeping it for the connection's life
                    // (review A-7).
                    if this.rlen <= READ_CHUNK && this.rbuf.capacity() > SHRINK_ABOVE {
                        this.rbuf.truncate(this.rlen + READ_CHUNK);
                        this.rbuf.shrink_to_fit();
                    }
                    if this.rbuf.len() - this.rlen < READ_CHUNK {
                        this.rbuf.resize(this.rlen + READ_CHUNK, 0);
                    }
                    let room = &mut this.rbuf[this.rlen..];
                    let n = ready!(Pin::new(&mut this.io).poll_read(cx, room))?;
                    if n == 0 {
                        // Ended without a close: the end between frames and
                        // messages, a cut otherwise.
                        if this.rlen == 0 && !this.msg.is_open() {
                            this.read_end = ReadEnd::Eof;
                            return Poll::Ready(Ok(0));
                        }
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.rlen += n;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    /// One binary frame per call, of at most [`MAX_SEND_PAYLOAD`] bytes.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closing {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket: closed",
            )));
        }
        ready!(this.poll_send(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_SEND_PAYLOAD);
        let mask = this.mask();
        encode(OP_BINARY, &buf[..n], mask, &mut this.wbuf);
        // The frame is taken either way; start sending it now.
        if let Poll::Ready(Err(e)) = this.poll_send(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    /// Sends a close 1000 (unless a close went out already), then closes
    /// the stream underneath.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.queue_close(WsClose::NORMAL);
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.io).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raven_core::ws_frame::{
        encode_head, Head, OP_CONTINUATION, OP_TEXT, WS_GUID, WS_MAX_MESSAGE,
    };
    use serde_json::Value;
    use std::collections::HashSet;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

    /// A tokio duplex half seen through the futures IO traits, which the
    /// TLS stream of a real connection has.
    struct Compat(DuplexStream);

    impl AsyncRead for Compat {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut rb = tokio::io::ReadBuf::new(buf);
            ready!(tokio::io::AsyncRead::poll_read(
                Pin::new(&mut self.0),
                cx,
                &mut rb
            ))?;
            Poll::Ready(Ok(rb.filled().len()))
        }
    }

    impl AsyncWrite for Compat {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
        }

        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
        }
    }

    /// Fails a test that stops making progress instead of letting it hang:
    /// everything here runs on in-memory pipes and normally takes well under
    /// a second, so this bounds a regression, not a product timing.
    async fn within<T>(test: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(60), test)
            .await
            .expect("the test made no progress for 60 s")
    }

    /// A connection: one end for the code under test, the raw other end.
    fn pair() -> (Compat, DuplexStream) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Compat(a), b)
    }

    fn vector(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/wss")
            .join(name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
        serde_json::from_str(&raw).unwrap()
    }

    fn text(v: &Value) -> &str {
        v.as_str().unwrap()
    }

    /// Reads up to and including the first blank line.
    async fn read_http_head(raw: &mut DuplexStream) -> Vec<u8> {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let b = raw.read_u8().await.expect("a whole head");
            head.push(b);
        }
        head
    }

    /// Reads one whole frame off the raw end (`wire` keeps what follows
    /// it): its head and its unmasked payload.
    async fn read_frame(
        raw: &mut DuplexStream,
        wire: &mut Vec<u8>,
        masked: bool,
    ) -> (Head, Vec<u8>) {
        loop {
            if let Some(h) = parse_head(wire, masked).expect("a frame the subset takes") {
                if wire.len() >= h.frame_len() {
                    let mut payload = wire[h.hdr_len..h.frame_len()].to_vec();
                    if let Some(k) = h.mask {
                        apply_mask(&mut payload, k, 0);
                    }
                    wire.drain(..h.frame_len());
                    return (h, payload);
                }
            }
            let mut chunk = [0u8; 4096];
            let n = raw.read(&mut chunk).await.unwrap();
            assert!(n > 0, "the stream ended inside a frame");
            wire.extend_from_slice(&chunk[..n]);
        }
    }

    fn client_frame(op: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode(op, payload, Some(MASK), &mut out);
        out
    }

    fn server_frame(op: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode(op, payload, None, &mut out);
        out
    }

    /// RFC 6455 §1.3 with ring's legacy SHA-1 injected into raven-core's
    /// accept_token, and the digest the handshake vector records.
    #[test]
    fn accept_token_matches_the_rfc6455_kat() {
        let v = vector("rws1_ws_handshake_001.json");
        assert_eq!(text(&v["inputs"]["key"]), KEY);
        assert_eq!(accept(KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(accept(KEY), text(&v["expected"]["accept"]));
        let mut input = KEY.as_bytes().to_vec();
        input.extend_from_slice(WS_GUID);
        assert_eq!(hex::encode(sha1(&input)), text(&v["expected"]["sha1_hex"]));
        assert_eq!(NOT_FOUND, text(&v["expected"]["not_found"]).as_bytes());
    }

    /// The handshake vector over tokio::io::duplex: the client's exact
    /// request for each Host value; the server's exact 101 for every
    /// request it takes, and the 404 then the end for every other (paths,
    /// methods, versions, missing or doubled headers, bad keys, more than
    /// 32 headers, a head over 8192 bytes); the client taking only the
    /// replies the vector says it takes.
    #[tokio::test]
    async fn ws_handshake_vectors_match() {
        within(async {
            let v = vector("rws1_ws_handshake_001.json");
            let e = &v["expected"];
            for case in e["requests"].as_array().unwrap() {
                let (io, mut raw) = pair();
                let host = text(&case["host"]).to_owned();
                let key = text(&case["key"]).to_owned();
                let (got, ()) = tokio::join!(client_with_key(io, &host, &key), async {
                    let head = read_http_head(&mut raw).await;
                    assert_eq!(head, text(&case["request"]).as_bytes());
                    raw.write_all(&response(&key)).await.unwrap();
                });
                got.expect("the client takes the 101");
            }
            let (mut accepted, mut refused) = (0, 0);
            for case in e["server"].as_array().unwrap() {
                let why = text(&case["why"]);
                let (io, mut raw) = pair();
                let request = text(&case["request"]).as_bytes().to_vec();
                let reply = text(&case["reply"]).as_bytes().to_vec();
                let take = case["accepted"].as_bool().unwrap();
                let (got, seen) = tokio::join!(server(io), async {
                    let _ = raw.write_all(&request).await;
                    let mut seen = vec![0u8; reply.len()];
                    raw.read_exact(&mut seen).await.expect("a reply");
                    if !take {
                        // The 404, then the end of the stream.
                        let mut more = Vec::new();
                        raw.read_to_end(&mut more).await.unwrap();
                        assert!(more.is_empty(), "{why}: bytes after the 404");
                    }
                    seen
                });
                assert_eq!(seen, reply, "{why}");
                assert_eq!(got.is_ok(), take, "{why}");
                if take {
                    accepted += 1;
                } else {
                    refused += 1;
                }
            }
            assert!(accepted >= 4 && refused >= 20, "{accepted} {refused}");
            for case in e["client"].as_array().unwrap() {
                let why = text(&case["why"]);
                let (io, mut raw) = pair();
                let reply = text(&case["response"]).as_bytes().to_vec();
                let (got, ()) =
                    tokio::join!(client_with_key(io, "relay.example.org", KEY), async {
                        read_http_head(&mut raw).await;
                        let _ = raw.write_all(&reply).await;
                        raw.shutdown().await.unwrap();
                    });
                assert_eq!(got.is_ok(), case["accepted"].as_bool().unwrap(), "{why}");
            }
        })
        .await;
    }

    /// The server refusals the step names, one by one: a wrong path gets
    /// the 404 and the close; a head over 8192 bytes and one with more
    /// than 32 headers are refused the same way; a connection that ends
    /// inside its head gets no reply.
    #[tokio::test]
    async fn server_refuses_with_404_and_close() {
        within(async {
            let ok = String::from_utf8(request("relay.example.org", KEY)).unwrap();
            let wrong_path = ok.replacen("GET / ", "GET /raven ", 1);
            let extra: String = (0..28).map(|i| format!("X-{i}: 1\r\n")).collect();
            let many = ok.replacen("\r\n\r\n", &format!("\r\n{extra}\r\n"), 1);
            let pad = "a".repeat(WS_MAX_HEADER_BLOCK);
            let large = ok.replacen("\r\n\r\n", &format!("\r\nX-Pad: {pad}\r\n\r\n"), 1);
            for request in [wrong_path, many, large] {
                let (io, mut raw) = pair();
                let (got, reply) = tokio::join!(server(io), async {
                    let _ = raw.write_all(request.as_bytes()).await;
                    let mut reply = Vec::new();
                    raw.read_to_end(&mut reply).await.unwrap();
                    reply
                });
                assert_eq!(reply, NOT_FOUND);
                assert_eq!(got.err().unwrap().kind(), io::ErrorKind::InvalidData);
            }
            let (io, mut raw) = pair();
            let (got, reply) = tokio::join!(server(io), async {
                raw.write_all(&ok.as_bytes()[..40]).await.unwrap();
                raw.shutdown().await.unwrap();
                let mut reply = Vec::new();
                raw.read_to_end(&mut reply).await.unwrap();
                reply
            });
            assert!(reply.is_empty());
            assert_eq!(got.err().unwrap().kind(), io::ErrorKind::UnexpectedEof);
            // The client refuses to put a line break in its Host value.
            let (io, _raw) = pair();
            let got = client(io, "relay.example.org\r\nX: 1").await;
            assert_eq!(got.err().unwrap().kind(), io::ErrorKind::InvalidInput);
        })
        .await;
    }

    /// Frames that follow the 101 in the same read are the stream's first
    /// bytes; so are frames a client sends right behind its request.
    #[tokio::test]
    async fn bytes_after_the_head_are_read_first() {
        within(async {
            let (io, mut raw) = pair();
            let (ws, ()) = tokio::join!(client_with_key(io, "relay.example.org", KEY), async {
                read_http_head(&mut raw).await;
                let mut reply = response(KEY);
                reply.extend_from_slice(&server_frame(OP_BINARY, b"early"));
                raw.write_all(&reply).await.unwrap();
            });
            let mut ws = ws.unwrap();
            let mut got = [0u8; 16];
            let n = futures::AsyncReadExt::read(&mut ws, &mut got)
                .await
                .unwrap();
            assert_eq!(&got[..n], b"early");
            let (io, mut raw) = pair();
            let mut first = request("relay.example.org", KEY);
            first.extend_from_slice(&client_frame(OP_BINARY, b"eager"));
            let (ws, ()) = tokio::join!(server(io), async {
                raw.write_all(&first).await.unwrap();
            });
            let mut ws = ws.unwrap();
            let n = futures::AsyncReadExt::read(&mut ws, &mut got)
                .await
                .unwrap();
            assert_eq!(&got[..n], b"eager");
        })
        .await;
    }

    /// 1 MiB written by a client goes out as 64 binary frames of 16 KiB,
    /// each FIN, each with its own random mask; then 1 MiB goes both ways
    /// between a client and a server that met through the handshake.
    #[tokio::test]
    async fn ws_stream_round_trips_1_mib_through_64_messages() {
        within(async {
            let data: Vec<u8> = (0..1usize << 20).map(|i| (i * 7 % 256) as u8).collect();
            let (io, mut raw) = pair();
            let mut ws = WsStream::new(io, true, Vec::new());
            let ((), (frames, masks)) = tokio::join!(
                async {
                    futures::AsyncWriteExt::write_all(&mut ws, &data)
                        .await
                        .unwrap();
                    futures::AsyncWriteExt::flush(&mut ws).await.unwrap();
                },
                async {
                    let mut wire = Vec::new();
                    let mut got = Vec::new();
                    let mut masks = HashSet::new();
                    let mut frames = 0;
                    while got.len() < data.len() {
                        let (h, payload) = read_frame(&mut raw, &mut wire, true).await;
                        assert!(h.fin && h.op == OP_BINARY && h.len == MAX_SEND_PAYLOAD as u64);
                        masks.insert(h.mask.unwrap());
                        got.extend_from_slice(&payload);
                        frames += 1;
                    }
                    assert!(wire.is_empty());
                    assert_eq!(got, data);
                    (frames, masks.len())
                }
            );
            assert_eq!(frames, 64);
            assert!(masks > 60, "a fresh mask per frame: {masks} distinct");

            let (a, b) = tokio::io::duplex(64 * 1024);
            let (c, s) = tokio::join!(client(Compat(a), "relay.example.org"), server(Compat(b)));
            let (mut c, mut s) = (c.unwrap(), s.unwrap());
            let echo = async {
                let mut got = vec![0u8; data.len()];
                futures::AsyncReadExt::read_exact(&mut s, &mut got)
                    .await
                    .unwrap();
                futures::AsyncWriteExt::write_all(&mut s, &got)
                    .await
                    .unwrap();
                futures::AsyncWriteExt::flush(&mut s).await.unwrap();
                got
            };
            let send = async {
                futures::AsyncWriteExt::write_all(&mut c, &data)
                    .await
                    .unwrap();
                futures::AsyncWriteExt::flush(&mut c).await.unwrap();
                let mut back = vec![0u8; data.len()];
                futures::AsyncReadExt::read_exact(&mut c, &mut back)
                    .await
                    .unwrap();
                back
            };
            let (at_server, at_client) = tokio::join!(echo, send);
            assert_eq!(at_server, data);
            assert_eq!(at_client, data);
        })
        .await;
    }

    /// Frames that arrive in small pieces: through a pipe of one byte, a
    /// 16-bit and a 7-bit length frame with a ping between them read the
    /// same as whole ones and the pong goes out a byte at a time too;
    /// through a pipe of 11 bytes, a 64-bit length frame whose head is cut
    /// inside its masking key.
    #[tokio::test]
    async fn frames_arriving_in_small_pieces() {
        within(async {
            let first: Vec<u8> = (0..300u32).map(|i| (i % 13) as u8).collect();
            let large: Vec<u8> = (0..65_536u32).map(|i| (i % 17) as u8).collect();
            for (pipe, frames) in [
                (
                    1,
                    vec![
                        (OP_BINARY, first),
                        (OP_PING, b"p".to_vec()),
                        (OP_BINARY, b"tail".to_vec()),
                    ],
                ),
                (11, vec![(OP_BINARY, large)]),
            ] {
                let (a, mut raw) = tokio::io::duplex(pipe);
                let mut ws = WsStream::new(Compat(a), false, Vec::new());
                let input: Vec<u8> = frames
                    .iter()
                    .flat_map(|(op, p)| client_frame(*op, p))
                    .collect();
                let data: Vec<u8> = frames
                    .iter()
                    .filter(|(op, _)| *op == OP_BINARY)
                    .flat_map(|(_, p)| p.clone())
                    .collect();
                let pings = frames.iter().filter(|(op, _)| *op == OP_PING).count();
                let (got, pongs) = tokio::join!(
                    async {
                        let mut got = vec![0u8; data.len()];
                        futures::AsyncReadExt::read_exact(&mut ws, &mut got)
                            .await
                            .unwrap();
                        futures::AsyncWriteExt::flush(&mut ws).await.unwrap();
                        got
                    },
                    async {
                        raw.write_all(&input).await.unwrap();
                        let mut wire = Vec::new();
                        let mut pongs = Vec::new();
                        for _ in 0..pings {
                            let (h, payload) = read_frame(&mut raw, &mut wire, false).await;
                            pongs.push((h.op, payload));
                        }
                        pongs
                    }
                );
                assert_eq!(got, data, "pipe of {pipe}");
                assert_eq!(pongs, vec![(OP_PONG, b"p".to_vec()); pings]);
            }
        })
        .await;
    }

    /// A ping is answered with a pong carrying its payload, on both sides
    /// (a client's pong masked), while reading goes on.
    #[tokio::test]
    async fn ping_is_answered_with_pong() {
        within(async {
            for client_side in [false, true] {
                let (io, mut raw) = pair();
                let mut ws = WsStream::new(io, client_side, Vec::new());
                let frame = |op, payload: &[u8]| {
                    if client_side {
                        server_frame(op, payload)
                    } else {
                        client_frame(op, payload)
                    }
                };
                let (got, (pong, payload)) = tokio::join!(
                    async {
                        let mut got = [0u8; 16];
                        let n = futures::AsyncReadExt::read(&mut ws, &mut got)
                            .await
                            .unwrap();
                        got[..n].to_vec()
                    },
                    async {
                        raw.write_all(&frame(OP_PING, b"are you there"))
                            .await
                            .unwrap();
                        raw.write_all(&frame(OP_BINARY, b"data")).await.unwrap();
                        let mut wire = Vec::new();
                        read_frame(&mut raw, &mut wire, client_side).await
                    }
                );
                assert_eq!(got, b"data");
                assert_eq!(pong.op, OP_PONG);
                assert_eq!(pong.mask.is_some(), client_side);
                assert_eq!(payload, b"are you there");
            }
        })
        .await;
    }

    /// A close from the peer is answered with a close 1000 and reads end;
    /// writing afterwards fails. Our own close sends a close 1000, then
    /// ends the stream underneath.
    #[tokio::test]
    async fn peer_close_gives_eof() {
        within(async {
            let (io, mut raw) = pair();
            let mut ws = WsStream::new(io, false, Vec::new());
            raw.write_all(&client_frame(OP_BINARY, b"last"))
                .await
                .unwrap();
            raw.write_all(&client_frame(OP_CLOSE, &1000u16.to_be_bytes()))
                .await
                .unwrap();
            let mut got = Vec::new();
            futures::AsyncReadExt::read_to_end(&mut ws, &mut got)
                .await
                .unwrap();
            assert_eq!(got, b"last");
            let mut wire = Vec::new();
            let (h, payload) = read_frame(&mut raw, &mut wire, false).await;
            assert_eq!((h.op, payload), (OP_CLOSE, vec![0x03, 0xe8]));
            let err = futures::AsyncWriteExt::write_all(&mut ws, b"more")
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
            let mut buf = [0u8; 4];
            assert_eq!(
                futures::AsyncReadExt::read(&mut ws, &mut buf)
                    .await
                    .unwrap(),
                0
            );

            let (io, mut raw) = pair();
            let mut ws = WsStream::new(io, true, Vec::new());
            futures::AsyncWriteExt::close(&mut ws).await.unwrap();
            let mut rest = Vec::new();
            raw.read_to_end(&mut rest).await.unwrap();
            let h = parse_head(&rest, true).unwrap().unwrap();
            assert_eq!((h.op, h.frame_len()), (OP_CLOSE, rest.len()));
            let mut payload = rest[h.hdr_len..].to_vec();
            apply_mask(&mut payload, h.mask.unwrap(), 0);
            assert_eq!(payload, [0x03, 0xe8]);
        })
        .await;
    }

    /// Reads a frame the subset refuses: the reader sends a close with the
    /// code and fails, and keeps failing.
    async fn refused_with(input: Vec<u8>) -> u16 {
        let (io, mut raw) = pair();
        let mut ws = WsStream::new(io, false, Vec::new());
        let mut buf = [0u8; 64];
        let (got, ()) = tokio::join!(futures::AsyncReadExt::read(&mut ws, &mut buf), async {
            raw.write_all(&input).await.unwrap();
        });
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let again = futures::AsyncReadExt::read(&mut ws, &mut buf).await;
        assert_eq!(again.unwrap_err().kind(), io::ErrorKind::InvalidData);
        let mut wire = Vec::new();
        let (h, payload) = read_frame(&mut raw, &mut wire, false).await;
        assert_eq!(h.op, OP_CLOSE);
        u16::from_be_bytes([payload[0], payload[1]])
    }

    /// A text message closes with 1003, in one frame or as a first
    /// fragment.
    #[tokio::test]
    async fn plain_text_frame_closes_1003() {
        within(async {
            assert_eq!(refused_with(client_frame(OP_TEXT, b"Hello")).await, 1003);
            let mut fragment = Vec::new();
            encode_head(false, OP_TEXT, 2, Some(MASK), &mut fragment);
            fragment.extend_from_slice(&[b'H' ^ MASK[0], b'e' ^ MASK[1]]);
            assert_eq!(refused_with(fragment).await, 1003);
        })
        .await;
    }

    /// Review A-7: one message of WS_MAX_MESSAGE bytes, read whole, leaves
    /// no large buffer behind once a small message follows: neither the
    /// read buffer nor the message.
    #[tokio::test]
    async fn a_large_message_does_not_pin_its_memory() {
        within(async {
            let (io, mut raw) = pair();
            let mut ws = WsStream::new(io, false, Vec::new());
            let big: Vec<u8> = (0..WS_MAX_MESSAGE).map(|i| i as u8).collect();
            let mut got = vec![0u8; WS_MAX_MESSAGE];
            let ((), read) = tokio::join!(
                async {
                    raw.write_all(&client_frame(OP_BINARY, &big)).await.unwrap();
                },
                futures::AsyncReadExt::read_exact(&mut ws, &mut got)
            );
            read.unwrap();
            assert!(got == big, "the large message as sent");
            assert!(ws.rbuf.capacity() > SHRINK_ABOVE, "it grew the buffer");
            assert_eq!(ws.ready.capacity(), 0, "the message read whole is freed");
            raw.write_all(&client_frame(OP_BINARY, b"small"))
                .await
                .unwrap();
            let mut small = [0u8; 5];
            futures::AsyncReadExt::read_exact(&mut ws, &mut small)
                .await
                .unwrap();
            assert_eq!(&small, b"small");
            assert!(
                ws.rbuf.capacity() <= SHRINK_ABOVE,
                "read buffer kept {} bytes",
                ws.rbuf.capacity()
            );
            assert_eq!(ws.ready.capacity(), 0);
        })
        .await;
    }

    /// A frame over 262144 bytes closes with 1009 before its payload
    /// comes, and so does a message that grows past it in fragments.
    #[tokio::test]
    async fn oversized_message_closes_1009() {
        within(async {
            let mut head = Vec::new();
            encode_head(
                true,
                OP_BINARY,
                WS_MAX_MESSAGE as u64 + 1,
                Some(MASK),
                &mut head,
            );
            assert_eq!(refused_with(head).await, 1009);
            let mut two = Vec::new();
            let big = vec![0u8; WS_MAX_MESSAGE];
            encode_head(false, OP_BINARY, big.len() as u64, Some(MASK), &mut two);
            two.extend_from_slice(&big);
            encode_head(true, OP_CONTINUATION, 1, Some(MASK), &mut two);
            two.push(0);
            assert_eq!(refused_with(two).await, 1009);
        })
        .await;
    }

    /// The other refusals close with 1002: an unmasked frame from a
    /// client, RSV bits, a continuation with nothing open, a 1-byte close.
    #[tokio::test]
    async fn protocol_violations_close_1002() {
        within(async {
            for input in [
                server_frame(OP_BINARY, b"plain"),
                {
                    let mut f = client_frame(OP_BINARY, b"x");
                    f[0] |= 0x40;
                    f
                },
                client_frame(OP_CONTINUATION, b"x"),
                client_frame(OP_CLOSE, &[3]),
            ] {
                assert_eq!(refused_with(input).await, 1002);
            }
        })
        .await;
    }

    /// The stream ending between frames is the end; ending inside a frame
    /// or a message is an error.
    #[tokio::test]
    async fn eof_inside_a_frame_is_an_error() {
        within(async {
            let (io, mut raw) = pair();
            let mut ws = WsStream::new(io, false, Vec::new());
            raw.write_all(&client_frame(OP_BINARY, b"whole"))
                .await
                .unwrap();
            raw.shutdown().await.unwrap();
            let mut got = Vec::new();
            futures::AsyncReadExt::read_to_end(&mut ws, &mut got)
                .await
                .unwrap();
            assert_eq!(got, b"whole");

            let cut = client_frame(OP_BINARY, b"whole");
            let mut fragment = Vec::new();
            encode_head(false, OP_BINARY, 1, Some(MASK), &mut fragment);
            fragment.push(b'a' ^ MASK[0]);
            for input in [cut[..cut.len() - 1].to_vec(), fragment] {
                let (io, mut raw) = pair();
                let mut ws = WsStream::new(io, false, Vec::new());
                raw.write_all(&input).await.unwrap();
                raw.shutdown().await.unwrap();
                let mut got = Vec::new();
                let err = futures::AsyncReadExt::read_to_end(&mut ws, &mut got)
                    .await
                    .unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            }
        })
        .await;
    }
}
