# protocol/reference/raven_protocol/websocket.py
"""The WebSocket subset of RWS1 (protocol/RAVEN_WSS_TRANSPORT_V1.md section 5), standard library only.

Raven's own binary-only subset of RFC 6455 (owner decision O4-1). An independent implementation of
node/crates/raven-core/src/ws_frame.rs (frames: encode, parse_head, Reassembly, close_code,
accept_token, valid_key) and of the HTTP/1.1 upgrade in node/crates/raven-swarm/src/wss/ws.rs
(client_request, server_response, check_request, check_response). Refusals of a frame carry the
close code (WsClose.code); refusals of a head carry a short reason (Refused.why) that only the
vectors' descriptions use.
"""
import base64
import binascii
import hashlib
import struct

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_MESSAGE = 262_144        # a message and a frame, in bytes (more closes with TOO_BIG)
MAX_HEADER_BLOCK = 8192      # an HTTP head, through its blank line
MAX_HEADERS = 32             # header lines of an HTTP head
MAX_CONTROL = 125            # the payload of a close, ping or pong
MAX_SEND_PAYLOAD = 16_384    # what Raven puts in one frame it sends (one write)

CONTINUATION, TEXT, BINARY, CLOSE, PING, PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
DATA = (CONTINUATION, TEXT, BINARY)
CONTROL = (CLOSE, PING, PONG)

NORMAL, PROTOCOL, UNSUPPORTED_DATA, TOO_BIG = 1000, 1002, 1003, 1009

NOT_FOUND = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
TOKEN_CHARS = frozenset(b"!#$%&'*+-.^_`|~0123456789"
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


class WsClose(Exception):
    """A frame the subset refuses; code is the close code the reader sends."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Refused(ValueError):
    """An HTTP head the upgrade refuses (the server answers NOT_FOUND)."""

    def __init__(self, why):
        super().__init__(why)
        self.why = why


# ---- frames -----------------------------------------------------------------------------------

def apply_mask(data, key, offset=0):
    """XOR with the 4-byte masking key; offset is the payload position data starts at."""
    return bytes(b ^ key[(offset + i) % 4] for i, b in enumerate(data))


def encode_head(fin, op, length, mask=None):
    """A frame head: the minimal length form (7, 16 or 64 bits), then the masking key if any."""
    m = 0x80 if mask is not None else 0
    head = bytes([(0x80 if fin else 0) | op])
    if length <= 125:
        head += bytes([m | length])
    elif length <= 0xFFFF:
        head += bytes([m | 126]) + struct.pack(">H", length)
    else:
        head += bytes([m | 127]) + struct.pack(">Q", length)
    return head + (bytes(mask) if mask is not None else b"")


def encode(op, payload, mask=None, fin=True):
    """One frame; a client frame carries a mask, a server frame none."""
    body = apply_mask(payload, mask) if mask is not None else bytes(payload)
    return encode_head(fin, op, len(payload), mask) + body


def parse_head(b, expect_masked):
    """None when more bytes are needed, else (fin, op, mask or None, length, head length).

    The checks run in this order; the first that fails raises WsClose:
      1. RSV1-3 set: PROTOCOL;
      2. an opcode other than 0, 1, 2, 8, 9, 10: PROTOCOL;
      3. a control frame (8-10) without FIN or with a 7-bit length over 125: PROTOCOL;
      4. a mask bit that differs from expect_masked: PROTOCOL;
      5. a 16-bit length under 126 or a 64-bit length under 65536 (not the minimal form): PROTOCOL;
      6. a length over MAX_MESSAGE: TOO_BIG.
    Fewer than 2 bytes, or a head cut inside its extended length or mask, needs more bytes.
    """
    if len(b) < 2:
        return None
    b0, b1 = b[0], b[1]
    if b0 & 0x70:
        raise WsClose(PROTOCOL)
    fin, op = bool(b0 & 0x80), b0 & 0x0F
    if op not in DATA + CONTROL:
        raise WsClose(PROTOCOL)
    short = b1 & 0x7F
    if op in CONTROL and (not fin or short > MAX_CONTROL):
        raise WsClose(PROTOCOL)
    masked = bool(b1 & 0x80)
    if masked != expect_masked:
        raise WsClose(PROTOCOL)
    if short == 126:
        if len(b) < 4:
            return None
        length, at = struct.unpack(">H", bytes(b[2:4]))[0], 4
        if length < 126:
            raise WsClose(PROTOCOL)
    elif short == 127:
        if len(b) < 10:
            return None
        length, at = struct.unpack(">Q", bytes(b[2:10]))[0], 10
        if length <= 0xFFFF:
            raise WsClose(PROTOCOL)
    else:
        length, at = short, 2
    if length > MAX_MESSAGE:
        raise WsClose(TOO_BIG)
    mask = None
    if masked:
        if len(b) < at + 4:
            return None
        mask, at = bytes(b[at:at + 4]), at + 4
    return fin, op, mask, length, at


class Reassembly:
    """Joins a message's data frames: binary, then continuations, the last with FIN."""

    def __init__(self):
        self.buf = b""
        self.open = False

    def push(self, fin, op, payload):
        """The complete message when FIN ends one, else None. Raises WsClose:
        a continuation with no message open, or a binary or text frame while one is open: PROTOCOL;
        a text frame: UNSUPPORTED_DATA; a message over MAX_MESSAGE: TOO_BIG."""
        if op == CONTINUATION:
            if not self.open:
                raise WsClose(PROTOCOL)
        elif op in (TEXT, BINARY):
            if self.open:
                raise WsClose(PROTOCOL)
            if op == TEXT:
                raise WsClose(UNSUPPORTED_DATA)
        else:
            raise WsClose(PROTOCOL)
        if len(self.buf) + len(payload) > MAX_MESSAGE:
            raise WsClose(TOO_BIG)
        self.buf += bytes(payload)
        self.open = not fin
        if not fin:
            return None
        message, self.buf = self.buf, b""
        return message


def close_code(payload):
    """The status code of a received close (None when it has no payload); a 1-byte payload is a
    protocol error. A reason after the code is ignored."""
    if not payload:
        return None
    if len(payload) == 1:
        raise WsClose(PROTOCOL)
    return struct.unpack(">H", bytes(payload[:2]))[0]


def read_frames(data, expect_masked):
    """Reads frames in a row: data frames through Reassembly, pings and pongs skipped, a close
    ends the reading. Returns (messages, outcome, code): outcome "end" (the input ran out), "close"
    (code: the close's status code or None) or "fail" (code: the close code the reader sends)."""
    messages, msg, at = [], Reassembly(), 0
    try:
        while True:
            head = parse_head(data[at:], expect_masked)
            if head is None:
                return messages, "end", None
            fin, op, mask, length, hdr = head
            if len(data) - at < hdr + length:
                return messages, "end", None
            payload = data[at + hdr:at + hdr + length]
            if mask is not None:
                payload = apply_mask(payload, mask)
            at += hdr + length
            if op == CLOSE:
                return messages, "close", close_code(payload)
            if op in DATA:
                done = msg.push(fin, op, payload)
                if done is not None:
                    messages.append(done)
    except WsClose as e:
        return messages, "fail", e.code


# ---- the HTTP/1.1 upgrade ----------------------------------------------------------------------

def accept_token(key):
    """Sec-WebSocket-Accept: base64(SHA-1(key || GUID)), key as sent (base64 text)."""
    return base64.b64encode(hashlib.sha1(key.encode("ascii") + GUID).digest()).decode("ascii")


def valid_key(key):
    """A Sec-WebSocket-Key: padded base64 (RFC 4648) of exactly 16 bytes, in its canonical form
    (no other characters, no non-zero bits in the last character)."""
    try:
        raw = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 16 and base64.b64encode(raw).decode("ascii") == key


def client_request(host, key):
    """The client's upgrade request: GET /, no Origin, subprotocol, extension or User-Agent."""
    return (f"GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode("ascii")


def server_response(key):
    """The server's 101 for a request with this key; no Server header."""
    return (f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_token(key)}\r\n\r\n").encode("ascii")


def _head(raw):
    """(start line, [(lower-case name, value)]) of one HTTP head: through the first blank line,
    at most MAX_HEADER_BLOCK bytes and MAX_HEADERS header lines, lines ended by CRLF, header names
    of token characters followed at once by ':', values trimmed of spaces and tabs."""
    end = raw.find(b"\r\n\r\n")
    if end < 0 or end + 4 > MAX_HEADER_BLOCK:
        raise Refused("head over 8192 bytes or unterminated")
    if end + 4 != len(raw):
        raise Refused("bytes after the head")
    lines = raw[:end].split(b"\r\n")
    if any(b"\r" in line or b"\n" in line for line in lines):
        raise Refused("a bare CR or LF")
    if len(lines) - 1 > MAX_HEADERS:
        raise Refused("more than 32 headers")
    headers = []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if not sep or not name or any(c not in TOKEN_CHARS for c in name):
            raise Refused("a malformed header line")
        if any(c < 0x20 and c != 0x09 or c == 0x7F for c in value):
            raise Refused("a control character in a header value")
        headers.append((name.decode("ascii").lower(), value.strip(b" \t").decode("latin-1")))
    return lines[0], headers


def _values(headers, name):
    return [v for n, v in headers if n == name]


def _has_token(headers, name, token):
    return any(t.strip(" \t").lower() == token for v in _values(headers, name) for t in v.split(","))


def check_request(raw):
    """The key of an upgrade request the server answers with 101; raises Refused otherwise (the
    server then answers NOT_FOUND and closes). Required: `GET / HTTP/1.1`, exactly one Host,
    Upgrade lists websocket and Connection lists upgrade (any case), exactly one
    Sec-WebSocket-Version of 13 and exactly one valid Sec-WebSocket-Key. Other headers (Origin,
    an offered subprotocol or extension) are ignored, and none is selected."""
    start, headers = _head(raw)
    parts = start.split(b" ")
    if len(parts) != 3 or parts[0] != b"GET" or parts[2] != b"HTTP/1.1":
        raise Refused("not GET ... HTTP/1.1")
    if parts[1] != b"/":
        raise Refused("a path other than /")
    if len(_values(headers, "host")) != 1:
        raise Refused("no Host or more than one")
    if not _has_token(headers, "upgrade", "websocket"):
        raise Refused("no Upgrade: websocket")
    if not _has_token(headers, "connection", "upgrade"):
        raise Refused("no Connection: upgrade")
    if _values(headers, "sec-websocket-version") != ["13"]:
        raise Refused("Sec-WebSocket-Version is not one 13")
    keys = _values(headers, "sec-websocket-key")
    if len(keys) != 1 or not valid_key(keys[0]):
        raise Refused("not one valid Sec-WebSocket-Key")
    return keys[0]


def check_response(raw, key):
    """None for a 101 the client accepts; raises Refused otherwise. Required: `HTTP/1.1 101`,
    Upgrade lists websocket and Connection lists upgrade (any case), exactly one
    Sec-WebSocket-Accept equal to accept_token(key), and no Sec-WebSocket-Extensions or
    Sec-WebSocket-Protocol (the client offered none)."""
    start, headers = _head(raw)
    parts = start.split(b" ", 2)
    if len(parts) < 2 or parts[0] != b"HTTP/1.1" or parts[1] != b"101":
        raise Refused("not HTTP/1.1 101")
    if not _has_token(headers, "upgrade", "websocket"):
        raise Refused("no Upgrade: websocket")
    if not _has_token(headers, "connection", "upgrade"):
        raise Refused("no Connection: upgrade")
    if _values(headers, "sec-websocket-accept") != [accept_token(key)]:
        raise Refused("not one matching Sec-WebSocket-Accept")
    if _values(headers, "sec-websocket-extensions") or _values(headers, "sec-websocket-protocol"):
        raise Refused("an extension or subprotocol nobody offered")
    return None
