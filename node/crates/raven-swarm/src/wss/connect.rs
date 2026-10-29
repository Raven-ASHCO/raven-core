//! The HTTP CONNECT client of RWS1 (`protocol/RAVEN_WSS_TRANSPORT_V1.md`
//! §7): behind a network's HTTPS proxy, a WSS relay dial first asks the
//! proxy for a tunnel to the relay, then runs TLS (§4) inside it.
//!
//! - [`connect_request`]: `CONNECT <authority> HTTP/1.1`, the same Host,
//!   and `Proxy-Authorization: Basic` when the proxy URL carried a user
//!   name; nothing else (no User-Agent, owner decision O4-4).
//! - [`parse_reply`]: the proxy's reply head. Any 2xx opens the tunnel and
//!   keeps the bytes after the head, 407 reports the Proxy-Authenticate
//!   schemes, any other status is refused, and anything that is not an
//!   HTTP/1.x head within [`HTTP_HEADER_MAX`] bytes and [`HTTP_HEADERS_MAX`]
//!   headers is malformed, decided as soon as the bytes show it.
//! - [`tunnel`]: the proxy's own name goes to the system resolver (an
//!   internal name like `proxy.corp` works); the target is sent as text
//!   and never resolved here, so behind a proxy the proxy resolves the
//!   relay's name. The [`Tunnel`] replays the bytes the proxy sent after its
//!   reply head before anything else.
//! - [`ProxyError`] has fixed texts: no proxy host, URL, credential or
//!   tunnel target ever appears in an error, so none reaches a log (§9).
//!
//! Vectors: `shared-vectors/rvn1/wss/rws1_connect_request_001.json` and
//! `rws1_connect_reply_001.json`, from the independent Python reference
//! `protocol/reference/raven_protocol/connect.py`.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::io::{AsyncRead, AsyncWrite};
use futures::stream::{FuturesUnordered, StreamExt as _};
use libp2p::tcp::tokio::TcpStream;
use raven_core::net_proxy::ProxyUrl;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroizing;

/// Largest reply head, through its blank line (RWS1 §7).
pub const HTTP_HEADER_MAX: usize = 8192;

/// Most header lines a reply head may have (RWS1 §7).
pub const HTTP_HEADERS_MAX: usize = 32;

/// How a reply head starts; a reply that differs from it is malformed at
/// once.
const STATUS_PREFIX: &[u8] = b"HTTP/1.";

/// Room one read of the reply gets, at most.
const READ_CHUNK: usize = 1024;

/// Proxy-Authenticate schemes Raven names; any other is [`OTHER_SCHEME`].
/// Only Basic is supported (owner decision O4-4).
const SCHEMES: [&str; 5] = ["Basic", "Digest", "NTLM", "Negotiate", "Bearer"];

/// How a Proxy-Authenticate scheme outside [`SCHEMES`] is reported: the
/// proxy's own text never reaches an error.
pub const OTHER_SCHEME: &str = "other";

/// Where a proxied WSS dial goes first: the proxy's `host:port` (an IPv6
/// address in brackets) and, only in memory, its Basic credential.
/// `Debug` shows neither.
#[derive(Clone)]
pub struct ProxyEndpoint {
    /// `host:port` of the proxy, for the system resolver.
    pub addr: String,
    /// The `Proxy-Authorization: Basic` value (base64 of `user:pass`).
    pub basic: Option<Zeroizing<String>>,
}

impl From<&ProxyUrl> for ProxyEndpoint {
    fn from(url: &ProxyUrl) -> Self {
        let addr = if url.host().contains(':') {
            format!("[{}]:{}", url.host(), url.port())
        } else {
            format!("{}:{}", url.host(), url.port())
        };
        ProxyEndpoint {
            addr,
            basic: url.basic().map(|b| Zeroizing::new(b.to_owned())),
        }
    }
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyEndpoint")
            .field("addr", &"<redacted>")
            .field("basic", &self.basic.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Why a CONNECT tunnel was not opened. Every text is fixed; a 407 names
/// only the schemes Raven knows ([`OTHER_SCHEME`] for the rest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// The tunnel target or the credential holds a byte a request line
    /// cannot carry (not 0x21..0x7e).
    Target,
    /// The proxy's name did not resolve, or none of its addresses took the
    /// connection.
    Unreachable,
    /// The connection to the proxy failed or ended before its reply head
    /// was whole.
    Closed,
    /// 407: the schemes the proxy offered, and whether Raven sent Basic
    /// credentials (then the proxy refused them; they are never retried).
    Auth {
        schemes: Vec<&'static str>,
        sent_basic: bool,
    },
    /// Any status other than 2xx and 407.
    Refused(u16),
    /// Not an HTTP/1.x reply head within [`HTTP_HEADER_MAX`] bytes and
    /// [`HTTP_HEADERS_MAX`] headers.
    Malformed,
}

impl ProxyError {
    /// A 407 that Raven cannot answer: no credentials were sent and the
    /// proxy does not offer Basic (NTLM or Negotiate, say).
    pub fn unsupported_auth(&self) -> bool {
        matches!(self, ProxyError::Auth { schemes, sent_basic: false }
            if !schemes.contains(&"Basic"))
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Target => f.write_str("proxy: not a tunnel target"),
            ProxyError::Unreachable => f.write_str("proxy: unreachable"),
            ProxyError::Closed => f.write_str("proxy: the connection ended before its reply"),
            ProxyError::Auth {
                sent_basic: true, ..
            } => f.write_str("proxy: refused the credentials (HTTP 407)"),
            ProxyError::Auth { schemes, .. } if schemes.contains(&"Basic") => {
                f.write_str("proxy: wants a user name and password (HTTP 407)")
            }
            ProxyError::Auth { schemes, .. } if schemes.is_empty() => {
                f.write_str("proxy: wants an authentication it does not name (HTTP 407)")
            }
            ProxyError::Auth { schemes, .. } => write!(
                f,
                "proxy: wants an authentication Raven does not support (HTTP 407: {})",
                schemes.join(", ")
            ),
            ProxyError::Refused(code) => write!(f, "proxy: refused the tunnel (HTTP {code})"),
            ProxyError::Malformed => f.write_str("proxy: not an HTTP proxy reply"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// The [`ProxyError`] inside an error of [`tunnel`], if any.
pub fn proxy_error(e: &io::Error) -> Option<&ProxyError> {
    e.get_ref()?.downcast_ref()
}

fn proxy_err(kind: io::ErrorKind, e: ProxyError) -> io::Error {
    io::Error::new(kind, e)
}

/// The CONNECT request for a tunnel to `authority` (`name:port`,
/// `a.b.c.d:port` or `[v6]:port`), with the Basic value when there is one.
pub fn connect_request(authority: &str, basic: Option<&str>) -> Vec<u8> {
    let mut r = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(b) = basic {
        r.push_str("Proxy-Authorization: Basic ");
        r.push_str(b);
        r.push_str("\r\n");
    }
    r.push_str("\r\n");
    r.into_bytes()
}

/// What the client makes of a proxy's whole reply head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Any 2xx: the tunnel is open; `leftover` are the bytes after the
    /// head, which are tunnel data.
    Tunnel { leftover: Vec<u8> },
    /// 407: the Proxy-Authenticate schemes, each once, in the order offered.
    AuthRequired { schemes: Vec<&'static str> },
    /// Any other status.
    Refused(u16),
    /// Not an HTTP/1.x reply head within the limits.
    Malformed,
}

/// What the bytes a proxy sent so far say, or none while more are needed
/// (RWS1 §7; `raven_protocol/connect.py` states the same rules):
///
/// 1. the head is `buf` through its first CRLF CRLF, or all of `buf` when
///    there is none yet;
/// 2. it starts with `HTTP/1.` (or a prefix of it while shorter), and its
///    lines end with CRLF only: a bare LF or CR is malformed;
/// 3. no CRLF CRLF yet: malformed once `buf` holds [`HTTP_HEADER_MAX`]
///    bytes, otherwise more bytes are needed;
/// 4. a head over [`HTTP_HEADER_MAX`] bytes is malformed;
/// 5. httparse must take the head whole: `HTTP/1.0` or `HTTP/1.1`, one
///    space, three digits, nothing or a space and a reason; at most
///    [`HTTP_HEADERS_MAX`] headers of a token name, `:` at once and a
///    value; reason and values only HTAB, SP, VCHAR and obs-text.
///
/// Once this decides, more bytes never change the decision.
pub fn parse_reply(buf: &[u8]) -> Option<Reply> {
    let end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4);
    let head = &buf[..end.unwrap_or(buf.len())];
    let k = head.len().min(STATUS_PREFIX.len());
    if head[..k] != STATUS_PREFIX[..k] || !line_ends_ok(head) {
        return Some(Reply::Malformed);
    }
    let Some(end) = end else {
        return (buf.len() >= HTTP_HEADER_MAX).then_some(Reply::Malformed);
    };
    if end > HTTP_HEADER_MAX {
        return Some(Reply::Malformed);
    }
    let mut headers = [httparse::EMPTY_HEADER; HTTP_HEADERS_MAX];
    let mut res = httparse::Response::new(&mut headers);
    if res.parse(head) != Ok(httparse::Status::Complete(end)) {
        return Some(Reply::Malformed);
    }
    Some(match res.code {
        Some(200..=299) => Reply::Tunnel {
            leftover: buf[end..].to_vec(),
        },
        Some(407) => Reply::AuthRequired {
            schemes: auth_schemes(res.headers),
        },
        Some(code) => Reply::Refused(code),
        None => Reply::Malformed,
    })
}

/// Every LF follows a CR and every CR is followed by an LF; a CR that ends
/// the bytes so far is still open.
fn line_ends_ok(head: &[u8]) -> bool {
    head.iter().enumerate().all(|(i, &b)| match b {
        b'\n' => i > 0 && head[i - 1] == b'\r',
        b'\r' => head.get(i + 1).is_none_or(|&next| next == b'\n'),
        _ => true,
    })
}

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The schemes of the Proxy-Authenticate headers: each comma-separated
/// element that starts with a token followed by nothing or white space
/// (and not by `=`: that is an auth-param), by its name in [`SCHEMES`] or
/// [`OTHER_SCHEME`]; each scheme once, in the order offered.
fn auth_schemes(headers: &[httparse::Header<'_>]) -> Vec<&'static str> {
    let mut out = Vec::new();
    let values = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("proxy-authenticate"));
    for h in values {
        for scheme in elements(h.value).into_iter().filter_map(scheme) {
            if !out.contains(&scheme) {
                out.push(scheme);
            }
        }
    }
    out
}

/// The comma-separated elements of a header value, trimmed; a comma inside
/// a quoted string (with backslash escapes) does not separate.
fn elements(value: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, &b) in value.iter().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else if b == b'"' {
            quoted = true;
        } else if b == b',' {
            out.push(value[start..i].trim_ascii());
            start = i + 1;
        }
    }
    out.push(value[start..].trim_ascii());
    out
}

fn scheme(element: &[u8]) -> Option<&'static str> {
    let n = element.iter().take_while(|&&b| is_token(b)).count();
    let rest = &element[n..];
    if n == 0
        || rest.first().is_some_and(|&b| b != b' ' && b != b'\t')
        || rest.trim_ascii().starts_with(b"=")
    {
        return None;
    }
    let name = &element[..n];
    Some(
        SCHEMES
            .into_iter()
            .find(|s| s.as_bytes().eq_ignore_ascii_case(name))
            .unwrap_or(OTHER_SCHEME),
    )
}

/// Bytes a request line or header can carry as they are.
fn request_safe(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| matches!(b, 0x21..=0x7e))
}

/// Opens a CONNECT tunnel to `authority` through the proxy. The proxy's
/// own name goes to the system resolver; `authority` is sent as it is and
/// never resolved here. Every error carries a [`ProxyError`]
/// ([`proxy_error`]) and its fixed text. The connection timeout of the
/// dial around this bounds it.
pub async fn tunnel(proxy: ProxyEndpoint, authority: String) -> io::Result<Tunnel> {
    let basic = proxy.basic.as_deref().map(String::as_str);
    if !request_safe(&authority) || basic.is_some_and(|b| !request_safe(b)) {
        return Err(proxy_err(io::ErrorKind::InvalidInput, ProxyError::Target));
    }
    let addrs = tokio::net::lookup_host(proxy.addr.as_str())
        .await
        .map_err(|e| proxy_err(e.kind(), ProxyError::Unreachable))?;
    let mut s = connect_first(addrs).await?;
    let closed = |e: io::Error| proxy_err(e.kind(), ProxyError::Closed);
    s.set_nodelay(true).map_err(closed)?;
    let request = Zeroizing::new(connect_request(&authority, basic));
    s.write_all(&request).await.map_err(closed)?;
    drop(request);
    let mut buf = Vec::with_capacity(512);
    loop {
        // parse_reply decides once buf holds HTTP_HEADER_MAX bytes, so
        // there is always room here.
        let start = buf.len();
        buf.resize(start + (HTTP_HEADER_MAX - start).min(READ_CHUNK), 0);
        let n = s.read(&mut buf[start..]).await.map_err(closed)?;
        buf.truncate(start + n);
        if n == 0 {
            return Err(proxy_err(io::ErrorKind::UnexpectedEof, ProxyError::Closed));
        }
        let Some(reply) = parse_reply(&buf) else {
            continue;
        };
        return match reply {
            Reply::Tunnel { leftover } => Ok(Tunnel::proxied(leftover, TcpStream(s))),
            Reply::AuthRequired { schemes } => Err(proxy_err(
                io::ErrorKind::PermissionDenied,
                ProxyError::Auth {
                    schemes,
                    sent_basic: basic.is_some(),
                },
            )),
            Reply::Refused(code) => Err(proxy_err(
                io::ErrorKind::ConnectionRefused,
                ProxyError::Refused(code),
            )),
            Reply::Malformed => Err(proxy_err(io::ErrorKind::InvalidData, ProxyError::Malformed)),
        };
    }
}

/// How long [`connect_first`] waits on one of the proxy's addresses before
/// it also tries the next (RFC 8305's Connection Attempt Delay); the
/// earlier attempts keep running.
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// The resolver's order with the address families alternating (RFC 8305
/// §4): the first family first, then one of the other, and so on.
fn interleave_families(addrs: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut addrs = addrs.peekable();
    let Some(first_v6) = addrs.peek().map(SocketAddr::is_ipv6) else {
        return Vec::new();
    };
    let (mut first, mut other): (VecDeque<_>, VecDeque<_>) =
        addrs.partition(|a| a.is_ipv6() == first_v6);
    let mut out = Vec::with_capacity(first.len() + other.len());
    while !first.is_empty() || !other.is_empty() {
        out.extend(first.pop_front());
        out.extend(other.pop_front());
    }
    out
}

/// Connects to the proxy's addresses, happy-eyeballs style (RFC 8305,
/// review B-3): [`race_addrs`] with a TCP connect.
async fn connect_first(
    addrs: impl Iterator<Item = SocketAddr>,
) -> io::Result<tokio::net::TcpStream> {
    race_addrs(addrs, tokio::net::TcpStream::connect).await
}

/// Tries `addrs` with `connect`: the families alternate
/// ([`interleave_families`]), a new attempt starts every [`ATTEMPT_DELAY`]
/// or as soon as one fails, the earlier ones keep running, and the first
/// that succeeds wins (the others are dropped). An address that drops SYNs
/// silently (a broken IPv6 network) therefore never holds the dial past the
/// next address, and the dial's own timeout still bounds the whole.
async fn race_addrs<T, F, Fut>(addrs: impl Iterator<Item = SocketAddr>, connect: F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let mut waiting = interleave_families(addrs).into_iter();
    let mut running = FuturesUnordered::new();
    let mut last = io::ErrorKind::NotFound;
    loop {
        if running.is_empty() {
            match waiting.next() {
                Some(addr) => running.push(connect(addr)),
                None => return Err(proxy_err(last, ProxyError::Unreachable)),
            }
        }
        let more = !waiting.as_slice().is_empty();
        tokio::select! {
            done = running.next() => match done {
                Some(Ok(s)) => return Ok(s),
                Some(Err(e)) => {
                    last = e.kind();
                    if let Some(addr) = waiting.next() {
                        running.push(connect(addr));
                    }
                }
                None => {}
            },
            () = tokio::time::sleep(ATTEMPT_DELAY), if more => {
                if let Some(addr) = waiting.next() {
                    running.push(connect(addr));
                }
            }
        }
    }
}

/// The byte stream TLS runs on: a TCP connection to the relay, or a CONNECT
/// tunnel through a proxy.
#[derive(Debug)]
pub enum Tunnel {
    Direct(TcpStream),
    /// Through a proxy: the bytes it sent after its reply head come first.
    Proxied(Prefixed<TcpStream>),
}

impl Tunnel {
    /// A TCP connection straight to the relay.
    pub fn direct(s: TcpStream) -> Self {
        Tunnel::Direct(s)
    }

    fn proxied(leftover: Vec<u8>, s: TcpStream) -> Self {
        Tunnel::Proxied(Prefixed::new(leftover, s))
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Tunnel::Direct(s) => Pin::new(s).poll_read(cx, buf),
            Tunnel::Proxied(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Tunnel::Direct(s) => Pin::new(s).poll_write(cx, buf),
            Tunnel::Proxied(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Tunnel::Direct(s) => Pin::new(s).poll_flush(cx),
            Tunnel::Proxied(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Tunnel::Direct(s) => Pin::new(s).poll_close(cx),
            Tunnel::Proxied(s) => Pin::new(s).poll_close(cx),
        }
    }
}

/// A stream whose reads first return `prefix`, then the stream's own bytes.
/// Writes go straight to the stream.
#[derive(Debug)]
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Prefixed {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = buf.len().min(this.prefix.len() - this.pos);
            buf[..n].copy_from_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(n));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use serde_json::Value;

    const BASIC: &str = "dXNlcjpwYXNz";

    /// Fails a test that stops making progress instead of letting it hang:
    /// everything here runs on loopback and normally takes well under a
    /// second, so this bounds a regression, not a product timing.
    async fn within<T>(test: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(std::time::Duration::from_secs(60), test)
            .await
            .expect("the test made no progress for 60 s")
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

    /// The reply bytes of a reply case: `reply` (ASCII text) or `reply_hex`.
    fn reply_bytes(case: &Value) -> Vec<u8> {
        match case.get("reply_hex") {
            Some(h) => hex::decode(text(h)).unwrap(),
            None => text(&case["reply"]).as_bytes().to_vec(),
        }
    }

    /// The decision of a reply case, as parse_reply gives it.
    fn expected_reply(case: &Value) -> Option<Reply> {
        Some(match text(&case["outcome"]) {
            "incomplete" => return None,
            "tunnel" => Reply::Tunnel {
                leftover: hex::decode(text(&case["leftover_hex"])).unwrap(),
            },
            "auth" => Reply::AuthRequired {
                schemes: case["schemes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| {
                        SCHEMES
                            .into_iter()
                            .chain([OTHER_SCHEME])
                            .find(|k| *k == text(s))
                            .expect("a scheme Raven names")
                    })
                    .collect(),
            },
            "refused" => Reply::Refused(case["code"].as_u64().unwrap() as u16),
            "malformed" => Reply::Malformed,
            other => panic!("unknown outcome {other}"),
        })
    }

    /// The reply with its leftover bytes dropped: what more bytes must not
    /// change once parse_reply has decided.
    fn decision(r: &Reply) -> Reply {
        match r {
            Reply::Tunnel { .. } => Reply::Tunnel {
                leftover: Vec::new(),
            },
            other => other.clone(),
        }
    }

    /// The invariants every input keeps: a decision once 8192 bytes are
    /// there; a tunnel's leftover is what follows a whole head of at most
    /// 8192 bytes; a prefix gives no decision or the same one.
    fn check_invariants(input: &[u8], cut: usize) {
        let whole = parse_reply(input);
        if input.len() >= HTTP_HEADER_MAX {
            assert!(whole.is_some(), "no decision at {} bytes", input.len());
        }
        if let Some(Reply::Tunnel { leftover }) = &whole {
            let head = &input[..input.len() - leftover.len()];
            assert!(head.ends_with(b"\r\n\r\n") && head.starts_with(STATUS_PREFIX));
            assert!(head.len() <= HTTP_HEADER_MAX);
            assert!(!head[..head.len() - 4].windows(4).any(|w| w == b"\r\n\r\n"));
        }
        if let Some(part) = parse_reply(&input[..cut.min(input.len())]) {
            let whole = whole.expect("a prefix decided, the whole did not");
            assert_eq!(decision(&part), decision(&whole));
        }
    }

    /// The exact requests of the vector, with and without the Basic value
    /// of `user:pass`.
    #[test]
    fn connect_request_bytes_match_vectors() {
        let v = vector("rws1_connect_request_001.json");
        assert_eq!(text(&v["inputs"]["basic"]), BASIC);
        let cases = v["expected"]["requests"].as_array().unwrap();
        assert_eq!(cases.len(), 6);
        for case in cases {
            let basic = case["basic"].as_str();
            let got = connect_request(text(&case["authority"]), basic);
            assert_eq!(got, text(&case["request"]).as_bytes(), "{case}");
        }
        assert_eq!(
            connect_request("[2001:db8::7]:8443", Some(BASIC)),
            b"CONNECT [2001:db8::7]:8443 HTTP/1.1\r\nHost: [2001:db8::7]:8443\r\n\
              Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n"
        );
    }

    /// Every reply of the vector decides as the Python reference does
    /// (leftover bytes kept, 407 schemes listed, 403 refused, oversized
    /// and 33-header heads malformed, HTTP/1.0 200 a tunnel), and every
    /// prefix of it needs more bytes or decides the same.
    #[test]
    fn connect_reply_table() {
        let v = vector("rws1_connect_reply_001.json");
        assert_eq!(v["inputs"]["max_header_block"], HTTP_HEADER_MAX);
        assert_eq!(v["inputs"]["max_headers"], HTTP_HEADERS_MAX);
        let cases = v["expected"]["replies"].as_array().unwrap();
        let mut outcomes = std::collections::BTreeMap::new();
        for case in cases {
            let raw = reply_bytes(case);
            assert_eq!(parse_reply(&raw), expected_reply(case), "{}", case["why"]);
            *outcomes.entry(text(&case["outcome"])).or_insert(0) += 1;
            let step = if raw.len() > 1024 { 61 } else { 1 };
            for cut in (0..raw.len()).step_by(step) {
                check_invariants(&raw, cut);
            }
        }
        assert!(outcomes.values().all(|&n| n >= 5), "{outcomes:?}");
        let find = |why: &str| {
            let case = cases.iter().find(|c| c["why"] == why).unwrap();
            parse_reply(&reply_bytes(case))
        };
        assert_eq!(
            find("HTTP/1.0 200 with leftover bytes"),
            Some(Reply::Tunnel {
                leftover: b"leftover".to_vec()
            })
        );
        assert_eq!(
            find("407 offering NTLM, Negotiate and Basic, one header each"),
            Some(Reply::AuthRequired {
                schemes: vec!["NTLM", "Negotiate", "Basic"]
            })
        );
        assert_eq!(find("403"), Some(Reply::Refused(403)));
        for why in [
            "a head of 8193 bytes",
            "8192 bytes and no blank line yet",
            "33 headers",
        ] {
            assert_eq!(find(why), Some(Reply::Malformed), "{why}");
        }
        assert_eq!(find("8191 bytes and no blank line yet"), None);
    }

    /// A bounded randomized run (fixed seed, so a failure reproduces):
    /// random bytes, vector replies with bytes flipped, cut, inserted or
    /// removed, and generated heads with up to 40 headers. Nothing panics
    /// and the invariants of [`check_invariants`] hold.
    #[test]
    fn parse_reply_random_inputs_never_panic() {
        let v = vector("rws1_connect_reply_001.json");
        let seeds: Vec<Vec<u8>> = v["expected"]["replies"]
            .as_array()
            .unwrap()
            .iter()
            .map(reply_bytes)
            .collect();
        let mut rng = StdRng::seed_from_u64(0x5257_5331_0007);
        const SPECIAL: &[u8] = b"\r\n:, \t\"=\\H";
        for round in 0..6000 {
            let input: Vec<u8> = match round % 3 {
                0 => {
                    let len = if rng.gen_bool(0.1) {
                        rng.gen_range(8000..8400)
                    } else {
                        rng.gen_range(0..64)
                    };
                    let mut b: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
                    if rng.gen_bool(0.5) && !b.is_empty() {
                        let n = b.len().min(STATUS_PREFIX.len());
                        b[..n].copy_from_slice(&STATUS_PREFIX[..n]);
                    }
                    b
                }
                1 => {
                    let mut b = seeds[rng.gen_range(0..seeds.len())].clone();
                    for _ in 0..rng.gen_range(1..4) {
                        let at = rng.gen_range(0..=b.len());
                        match rng.gen_range(0..4) {
                            0 if at < b.len() => b[at] = rng.gen(),
                            1 => b.insert(at, SPECIAL[rng.gen_range(0..SPECIAL.len())]),
                            2 if at < b.len() => {
                                b.remove(at);
                            }
                            _ => b.truncate(at),
                        }
                    }
                    b
                }
                _ => {
                    let code: u16 = if rng.gen_bool(0.5) {
                        [200, 204, 407, 403][rng.gen_range(0..4)]
                    } else {
                        rng.gen_range(0..1000)
                    };
                    let mut h = format!("HTTP/1.{} {code:03} R\r\n", rng.gen_range(0..2));
                    for i in 0..rng.gen_range(0..40) {
                        if rng.gen_bool(0.3) {
                            h.push_str("Proxy-Authenticate: ");
                            h.push_str(
                                [
                                    "Basic realm=\"a,b\"",
                                    "NTLM",
                                    "negotiate x==",
                                    "Digest a = b, c=\"d\"",
                                    "X-Y",
                                    "\"q\\\"\", =",
                                ][rng.gen_range(0..6)],
                            );
                            h.push_str("\r\n");
                        } else {
                            h.push_str(&format!(
                                "X-{i}: {}\r\n",
                                "v".repeat(rng.gen_range(0..300))
                            ));
                        }
                    }
                    h.push_str("\r\n");
                    let mut b = h.into_bytes();
                    b.extend((0..rng.gen_range(0..16)).map(|_| rng.gen::<u8>()));
                    b
                }
            };
            let cut = rng.gen_range(0..=input.len());
            check_invariants(&input, cut);
        }
    }

    /// A one-connection proxy on 127.0.0.1: reads the request head, sends
    /// `reply`, then echoes what follows (when `echo`) and closes. Returns
    /// its port and the request head it read.
    async fn one_shot_proxy(reply: Vec<u8>, echo: bool) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(s.read_u8().await.unwrap());
            }
            s.write_all(&reply).await.unwrap();
            let mut chunk = [0u8; 256];
            if echo {
                loop {
                    let n = s.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    s.write_all(&chunk[..n]).await.unwrap();
                }
            }
            head
        });
        (port, task)
    }

    fn endpoint(url: &str) -> ProxyEndpoint {
        let url = raven_core::net_proxy::parse_proxy_url(url).unwrap();
        ProxyEndpoint::from(&url)
    }

    /// Review B-3 (RFC 8305): the proxy's addresses alternate by family, and
    /// one that never answers (SYNs dropped on a broken IPv6 network) holds
    /// the dial only [`ATTEMPT_DELAY`] before the next starts; a failure
    /// starts the next at once; the first success wins; all failing is
    /// `Unreachable`. On paused time, so the delays are exact. Tried in
    /// sequence (the code before), the silent address hangs the dial and
    /// [`within`] fails it.
    #[tokio::test(start_paused = true)]
    async fn proxy_addresses_race_so_a_silent_one_does_not_hang_the_dial() {
        use std::sync::{Arc, Mutex};
        let a = |text: &str| text.parse::<SocketAddr>().unwrap();
        let (v6a, v6b, v4a, v4b) = (
            a("[2001:db8::1]:3128"),
            a("[2001:db8::2]:3128"),
            a("192.0.2.1:3128"),
            a("192.0.2.2:3128"),
        );
        assert_eq!(
            interleave_families([v6a, v6b, v4a, v4b].into_iter()),
            [v6a, v4a, v6b, v4b]
        );
        assert_eq!(
            interleave_families([v4a, v6a, v6b].into_iter()),
            [v4a, v6a, v6b]
        );
        assert!(interleave_families(std::iter::empty()).is_empty());

        // `silent` never answers, `refused` fails at once, the rest connect.
        let run = |addrs: Vec<SocketAddr>, silent: Vec<SocketAddr>, refused: Vec<SocketAddr>| {
            let tried = Arc::new(Mutex::new(Vec::new()));
            let log = tried.clone();
            let started = tokio::time::Instant::now();
            async move {
                let got = race_addrs(addrs.into_iter(), move |addr| {
                    log.lock().unwrap().push(addr);
                    let (silent, refused) = (silent.contains(&addr), refused.contains(&addr));
                    async move {
                        if silent {
                            std::future::pending::<()>().await;
                        }
                        if refused {
                            return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                        }
                        Ok(addr)
                    }
                })
                .await;
                let tried = tried.lock().unwrap().clone();
                (got, tried, started.elapsed())
            }
        };
        let (got, tried, took) = within(run(vec![v6a, v4a], vec![v6a], vec![])).await;
        assert_eq!(got.unwrap(), v4a);
        assert_eq!(tried, [v6a, v4a]);
        assert_eq!(took, ATTEMPT_DELAY);
        // A refusal starts the next at once.
        let (got, tried, took) = within(run(vec![v6a, v4a], vec![], vec![v6a])).await;
        assert_eq!(got.unwrap(), v4a);
        assert_eq!(tried, [v6a, v4a]);
        assert_eq!(took, Duration::ZERO);
        // Two silent v6 addresses before the v4 ones: the v4 one is second.
        let (got, tried, _) = within(run(vec![v6a, v6b, v4a, v4b], vec![v6a, v6b], vec![])).await;
        assert_eq!(got.unwrap(), v4a);
        assert_eq!(tried, [v6a, v4a]);
        // All refused: unreachable, every address tried once.
        let (got, tried, _) = within(run(vec![v6a, v4a], vec![], vec![v6a, v4a])).await;
        let err = got.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(proxy_error(&err), Some(&ProxyError::Unreachable));
        assert_eq!(tried, [v6a, v4a]);
        let (got, tried, _) = within(run(vec![], vec![], vec![])).await;
        assert_eq!(
            proxy_error(&got.unwrap_err()),
            Some(&ProxyError::Unreachable)
        );
        assert!(tried.is_empty());
    }

    /// Through a proxy named `localhost` (the system resolver finds it; an
    /// address that refuses is skipped): the target name goes to the proxy
    /// as text, and the bytes after an HTTP/1.0 200 come first.
    #[tokio::test]
    async fn tunnel_carries_the_name_and_replays_leftover_bytes() {
        within(async {
            let reply = b"HTTP/1.0 200 Connection established\r\n\r\nEARLY".to_vec();
            let (port, proxy) = one_shot_proxy(reply, true).await;
            let p = endpoint(&format!("http://localhost:{port}"));
            assert_eq!(p.addr, format!("localhost:{port}"));
            let mut t = tunnel(p, "relay.invalid:443".to_owned()).await.unwrap();
            assert!(matches!(t, Tunnel::Proxied(_)));
            let mut early = [0u8; 5];
            t.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"EARLY");
            t.write_all(b"ping").await.unwrap();
            let mut echo = [0u8; 4];
            t.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"ping");
            t.close().await.unwrap();
            assert_eq!(
                proxy.await.unwrap(),
                connect_request("relay.invalid:443", None)
            );
        })
        .await;
    }

    /// The Basic value goes to the proxy in the request, and no error, nor
    /// the endpoint's Debug, shows it, the user name, the password, the
    /// proxy's address or port, or the target.
    #[tokio::test]
    async fn basic_credentials_are_sent_and_never_in_errors() {
        within(async {
            // Distinctive credentials, so that no fixed text can contain them.
            let basic = STANDARD.encode("proxy-usr:hunter2pw");
            let secrets = |port: u16| {
                [
                    basic.clone(),
                    "proxy-usr".to_owned(),
                    "hunter2pw".to_owned(),
                    "127.0.0.1".to_owned(),
                    "localhost".to_owned(),
                    port.to_string(),
                    "relay.invalid".to_owned(),
                    "no-port-here".to_owned(),
                ]
            };
            let clean = |e: &io::Error, port: u16| {
                let shown = format!("{e} {e:?}");
                for s in secrets(port) {
                    assert!(!shown.contains(&s), "{s:?} in {shown}");
                }
            };
            let authenticate = |schemes: &str| {
                format!(
                    "HTTP/1.1 407 Proxy Authentication Required\r\n\
                     Proxy-Authenticate: {schemes}\r\n\r\n"
                )
                .into_bytes()
            };
            let cases: Vec<(Vec<u8>, bool, io::ErrorKind, ProxyError)> = vec![
                (
                    authenticate("Basic realm=\"proxy-usr hunter2pw\""),
                    true,
                    io::ErrorKind::PermissionDenied,
                    ProxyError::Auth {
                        schemes: vec!["Basic"],
                        sent_basic: true,
                    },
                ),
                (
                    authenticate("Negotiate, NTLM, relay.invalid"),
                    false,
                    io::ErrorKind::PermissionDenied,
                    ProxyError::Auth {
                        schemes: vec!["Negotiate", "NTLM", OTHER_SCHEME],
                        sent_basic: false,
                    },
                ),
                (
                    b"HTTP/1.1 403 proxy-usr hunter2pw relay.invalid\r\n\r\n".to_vec(),
                    true,
                    io::ErrorKind::ConnectionRefused,
                    ProxyError::Refused(403),
                ),
                (
                    b"SSH-2.0-relay.invalid\r\n".to_vec(),
                    true,
                    io::ErrorKind::InvalidData,
                    ProxyError::Malformed,
                ),
                (
                    b"HTTP/1.1 200 OK\r\n".to_vec(),
                    true,
                    io::ErrorKind::UnexpectedEof,
                    ProxyError::Closed,
                ),
            ];
            for (reply, with_basic, kind, want) in cases {
                let (port, proxy) = one_shot_proxy(reply, false).await;
                let url = if with_basic {
                    format!("http://proxy-usr:hunter2pw@127.0.0.1:{port}")
                } else {
                    format!("http://127.0.0.1:{port}")
                };
                let p = endpoint(&url);
                assert_eq!(p.basic.is_some(), with_basic);
                let shown = format!("{p:?}");
                for s in secrets(port) {
                    assert!(!shown.contains(&s), "{s:?} in {shown}");
                }
                let e = tunnel(p, "relay.invalid:443".to_owned()).await.unwrap_err();
                assert_eq!((e.kind(), proxy_error(&e)), (kind, Some(&want)), "{e}");
                clean(&e, port);
                let head = proxy.await.unwrap();
                let sent = with_basic.then_some(basic.as_str());
                assert_eq!(head, connect_request("relay.invalid:443", sent));
                let line = format!("\r\nProxy-Authorization: Basic {basic}\r\n");
                assert_eq!(
                    head.windows(line.len()).any(|w| w == line.as_bytes()),
                    with_basic
                );
            }
            assert!(ProxyError::Auth {
                schemes: vec!["Negotiate", "NTLM"],
                sent_basic: false,
            }
            .unsupported_auth());
            assert!(!ProxyError::Auth {
                schemes: vec!["NTLM", "Basic"],
                sent_basic: false,
            }
            .unsupported_auth());

            // A proxy that is not listening, a proxy address without a port
            // (refused before any lookup), a target that could inject a
            // header line.
            let gone = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = gone.local_addr().unwrap().port();
            drop(gone);
            let e = tunnel(
                endpoint(&format!("http://proxy-usr:hunter2pw@127.0.0.1:{port}")),
                "relay.invalid:443".to_owned(),
            )
            .await
            .unwrap_err();
            assert_eq!(proxy_error(&e), Some(&ProxyError::Unreachable), "{e}");
            clean(&e, port);
            let mut p = endpoint("http://proxy-usr:hunter2pw@127.0.0.1:3128");
            p.addr = "no-port-here".to_owned();
            let e = tunnel(p, "relay.invalid:443".to_owned()).await.unwrap_err();
            assert_eq!(proxy_error(&e), Some(&ProxyError::Unreachable), "{e}");
            clean(&e, 3128);
            for target in [
                "relay.invalid:443\r\nX-Injected: 1",
                "",
                "relay invalid:443",
            ] {
                let p = endpoint("http://proxy-usr:hunter2pw@127.0.0.1:3128");
                let e = tunnel(p, target.to_owned()).await.unwrap_err();
                assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
                assert_eq!(proxy_error(&e), Some(&ProxyError::Target));
                clean(&e, 3128);
            }
            assert_eq!(endpoint("http://[::1]:3128").addr, "[::1]:3128");
        })
        .await;
    }

    /// Reads that return the prefix in pieces, then the stream's bytes.
    #[tokio::test]
    async fn prefixed_reads_the_prefix_first() {
        let mut p = Prefixed::new(b"abcde".to_vec(), &b"fgh"[..]);
        let mut two = [0u8; 2];
        assert_eq!(p.read(&mut two).await.unwrap(), 2);
        assert_eq!(&two, b"ab");
        let mut rest = Vec::new();
        p.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"cdefgh");
    }
}
