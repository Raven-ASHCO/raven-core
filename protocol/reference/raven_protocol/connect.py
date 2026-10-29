# protocol/reference/raven_protocol/connect.py
"""The HTTP CONNECT client and the listener's first-byte check of RWS1
(protocol/RAVEN_WSS_TRANSPORT_V1.md sections 7 and 6), standard library only.

An independent implementation of node/crates/raven-swarm/src/wss/connect.rs (connect_request,
parse_reply, the Proxy-Authenticate schemes) and of the first-byte check in wss/mod.rs (demux).
The Rust side parses the reply head with httparse; this module states the same rules directly.
"""
import re

MAX_HEADER_BLOCK = 8192      # the reply head, through its blank line
MAX_HEADERS = 32             # header lines of the reply head
STATUS_PREFIX = b"HTTP/1."

TOKEN_CHARS = frozenset(b"!#$%&'*+-.^_`|~0123456789"
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
# What a reason phrase and a header value may hold: HTAB, SP, VCHAR and obs-text (RFC 9110/9112).
FIELD_CHARS = frozenset([0x09] + list(range(0x20, 0x7F)) + list(range(0x80, 0x100)))
STATUS_LINE = re.compile(rb"HTTP/1\.([01]) ([0-9]{3})(?: (.*))?", re.DOTALL)

# Proxy-Authenticate schemes by their lower-case name; any other scheme is reported as "other".
SCHEMES = {"basic": "Basic", "digest": "Digest", "ntlm": "NTLM", "negotiate": "Negotiate",
           "bearer": "Bearer"}
OTHER = "other"

# Outcomes of parse_reply.
TUNNEL, AUTH, REFUSED, MALFORMED = "tunnel", "auth", "refused", "malformed"

# The first byte a client sends to a two-protocol listener (section 6).
TLS_HANDSHAKE = 0x16          # a TLS handshake record: TLS, then the WebSocket upgrade
MULTISTREAM = 0x13            # the varint 19 before "/multistream/1.0.0\n": raw libp2p


def connect_request(authority, basic=None):
    """The CONNECT request for a tunnel to authority (name:port, a.b.c.d:port or [v6]:port);
    basic is the Proxy-Authorization Basic value (base64 of user:pass) or None. Nothing else:
    no User-Agent, no Proxy-Connection."""
    r = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
    if basic is not None:
        r += f"Proxy-Authorization: Basic {basic}\r\n"
    return (r + "\r\n").encode("ascii")


def _line_ends_ok(head):
    """Every LF follows a CR and every CR is followed by an LF (a CR at the very end of the bytes
    so far is still open)."""
    for i, c in enumerate(head):
        if c == 0x0A and (i == 0 or head[i - 1] != 0x0D):
            return False
        if c == 0x0D and i + 1 < len(head) and head[i + 1] != 0x0A:
            return False
    return True


def _elements(value):
    """The comma-separated elements of a header value; commas inside a quoted string (with
    backslash escapes) do not separate."""
    out, cur, quoted, escaped = [], bytearray(), False, False
    for c in value:
        if quoted:
            if escaped:
                escaped = False
            elif c == 0x5C:
                escaped = True
            elif c == 0x22:
                quoted = False
        elif c == 0x22:
            quoted = True
        elif c == 0x2C:
            out.append(bytes(cur))
            cur = bytearray()
            continue
        cur.append(c)
    out.append(bytes(cur))
    return [e.strip(b" \t") for e in out]


def auth_schemes(values):
    """The schemes of Proxy-Authenticate values: each element that starts with a token followed
    by nothing or by white space (and not by "=": that is an auth-param), by its canonical name
    or "other"; each scheme once, in the order offered."""
    out = []
    for value in values:
        for e in _elements(value):
            n = 0
            while n < len(e) and e[n] in TOKEN_CHARS:
                n += 1
            if n == 0:
                continue
            rest = e[n:]
            if rest and rest[0] not in (0x20, 0x09):
                continue
            if rest.lstrip(b" \t").startswith(b"="):
                continue
            name = SCHEMES.get(e[:n].decode("ascii").lower(), OTHER)
            if name not in out:
                out.append(name)
    return out


def parse_reply(buf):
    """What the client makes of the proxy's reply so far: None (more bytes needed), or a tuple:
    (TUNNEL, leftover bytes) for any 2xx, (AUTH, schemes) for 407, (REFUSED, code) for any other
    status, (MALFORMED,) otherwise. The rules, in this order:
    1. the head is buf through its first CRLF CRLF, or all of buf when there is none yet;
    2. the head starts with HTTP/1. (or a prefix of it while shorter), and its lines end with
       CRLF only (a bare LF or CR is malformed);
    3. no CRLF CRLF yet: malformed once buf holds MAX_HEADER_BLOCK bytes, else more bytes needed;
    4. a head longer than MAX_HEADER_BLOCK is malformed;
    5. the status line is HTTP/1.0 or HTTP/1.1, one space, three digits, then nothing or one space
       and a reason phrase; at most MAX_HEADERS header lines, each a token name, ":" at once,
       then a value; reason and values hold only HTAB, SP, VCHAR and obs-text."""
    end = buf.find(b"\r\n\r\n")
    head = buf[:end + 4] if end >= 0 else buf
    k = min(len(head), len(STATUS_PREFIX))
    if head[:k] != STATUS_PREFIX[:k] or not _line_ends_ok(head):
        return (MALFORMED,)
    if end < 0:
        return (MALFORMED,) if len(buf) >= MAX_HEADER_BLOCK else None
    if end + 4 > MAX_HEADER_BLOCK:
        return (MALFORMED,)
    lines = head[:end].split(b"\r\n")
    m = STATUS_LINE.fullmatch(lines[0])
    if m is None or any(c not in FIELD_CHARS for c in (m.group(3) or b"")):
        return (MALFORMED,)
    if len(lines) - 1 > MAX_HEADERS:
        return (MALFORMED,)
    headers = []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if not sep or not name or any(c not in TOKEN_CHARS for c in name):
            return (MALFORMED,)
        if any(c not in FIELD_CHARS for c in value):
            return (MALFORMED,)
        headers.append((name.decode("ascii").lower(), value.strip(b" \t")))
    code = int(m.group(2))
    if 200 <= code <= 299:
        return (TUNNEL, buf[end + 4:])
    if code == 407:
        return (AUTH, auth_schemes([v for n, v in headers if n == "proxy-authenticate"]))
    return (REFUSED, code)


def demux(first):
    """What a two-protocol listener does with a connection by the bytes it sent first (only the
    first byte counts; empty: nothing came within the wait, or the connection ended): "tls",
    "raw" or "refused" (closed with no reply)."""
    if not first:
        return "refused"
    if first[0] == TLS_HANDSHAKE:
        return "tls"
    if first[0] == MULTISTREAM:
        return "raw"
    return "refused"
