#!/usr/bin/env python3
# protocol/reference/generate_wss.py
"""Deterministic generator for the Raven WSS Transport V1 (RWS1) vectors (Python standard library only).

Source of truth: raven_protocol.via, raven_protocol.net_proxy, raven_protocol.websocket,
raven_protocol.connect  |  Spec:
protocol/RAVEN_WSS_TRANSPORT_V1.md. Writes <out>/p2p/via_*.json and <out>/wss/rws1_*.json (default
out: shared-vectors/rvn1). This generator owns p2p/via_*.json and wss/*.json only; other generators
write other files under p2p/.

    python3 -I generate_wss.py            # write the vectors
    python3 -I generate_wss.py --check    # exit 1 if any file on disk differs
"""
import argparse, base64, hashlib, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from raven_protocol import connect, net_proxy, via  # noqa: E402
from raven_protocol import websocket as ws  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
# Each owned file pattern, relative to <out>: what --check compares and reports as not generated.
OWNED = ("p2p/via_*.json", "wss/*.json")
RELAY_KEY = bytes([0x52]) * 32
CONTACT_KEY = bytes([0x43]) * 32
R = via.peer_id_from_ed25519_public(RELAY_KEY)
C = via.peer_id_from_ed25519_public(CONTACT_KEY)
V4 = "/ip4/203.0.113.7"


def vec(name, desc, inputs, expected):
    return {"name": name, "description": desc, "protocol_version": "rvn1",
            "spec_reference": "RAVEN_WSS_TRANSPORT_V1.md", "deterministic": True,
            "inputs": inputs, "expected": expected}


def long_name(n):
    """A DNS name of n characters in labels of 63 (section 2.1)."""
    return "".join("." if i % 64 == 0 else "a" for i in range(1, n + 1))


ACCEPT = [
    (f"{V4}/tcp/443/tls/ws/p2p/{R}", "WSS on TCP 443 (no SNI: an IP literal)"),
    (f"{V4}/tcp/443/wss/p2p/{R}", "the deprecated libp2p alias /wss, stored as /tls/ws"),
    (f"{V4}/tcp/8443/tls/sni/Relay.Example.ORG/ws/p2p/{R}", "an SNI name after an IP host, lower-cased; "
     "any port"),
    (f"/ip6/2001:DB8:0::7/tcp/443/tls/sni/relay.example.org/ws/p2p/{R}", "an SNI name after an IPv6 host; "
     "canonical IPv6 text"),
    (f"/dns4/Relay.Example.org/tcp/443/tls/ws/p2p/{R}", "a DNS host (which is the SNI name), lower-cased"),
    (f"/dns/relay.example.org/tcp/7423/tls/ws/p2p/{R}", "WSS on another port: its raw sibling is the same "
     "port"),
    (f"/dns6/relay.example.net/tcp/443/wss/p2p/{R}", "/wss after a /dns6 host"),
    (f"  {V4}/tcp/443/tls/ws/p2p/{R}  ", "surrounding spaces are trimmed"),
    (f"{V4}/tcp/443/tls/ws/p2p/{C}", "a WSS address that names the contact itself (a direct address)"),
    (f"{V4}/tcp/443/p2p/{R}", "raw TCP 443: a WSS sibling by convention (section 2.3 (b))"),
    (f"{V4}/tcp/7423/p2p/{R}", "raw TCP on another port: no sibling"),
    (f"{V4}/udp/443/quic-v1/p2p/{R}", "QUIC: no sibling, no suffix"),
    (f"/dns/{long_name(223)}/tcp/443/wss/p2p/{R}", "/wss whose /tls/ws form is exactly 300 characters"),
]

REJECT = [
    (f"{V4}/tcp/7423/ws/p2p/{R}", "plain /ws (no TLS)"),
    (f"{V4}/tcp/443/tls/p2p/{R}", "/tls without /ws"),
    (f"{V4}/tcp/443/x-parity-ws/%2F/p2p/{R}", "the old /x-parity-ws form"),
    (f"{V4}/tcp/443/x-parity-wss/%2F/p2p/{R}", "the old /x-parity-wss form"),
    (f"{V4}/tcp/443/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g/p2p/{R}", "/certhash"),
    (f"{V4}/tcp/443/https/p2p/{R}", "/https"),
    (f"{V4}/tcp/443/http-path/%2Fraven/p2p/{R}", "/http-path"),
    (f"{V4}/tcp/443/tls/http/p2p/{R}", "/tls/http"),
    (f"{V4}/tcp/443/noise/p2p/{R}", "/noise"),
    (f"/dns4/relay.example.org/tcp/443/tls/sni/relay.example.org/ws/p2p/{R}", "/tls/sni after a DNS host "
     "(the DNS name already is the SNI name)"),
    (f"{V4}/tcp/443/tls/sni/203.0.113.8/ws/p2p/{R}", "an IPv4 literal as SNI name"),
    (f"{V4}/tcp/443/tls/sni/-bad/ws/p2p/{R}", "an SNI name that is no plausible DNS name"),
    (f"{V4}/tcp/443/tls/sni/relay.example.org/p2p/{R}", "/tls/sni/NAME without /ws"),
    (f"{V4}/udp/443/quic-v1/tls/ws/p2p/{R}", "a WSS suffix on QUIC"),
    (f"{V4}/udp/443/quic-v1/wss/p2p/{R}", "/wss on QUIC"),
    (f"{V4}/tcp/443/tls/ws/p2p/{R}/p2p-circuit/p2p/{C}", "a circuit through a WSS address"),
    (f"{V4}/tcp/443/tls/ws/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g/p2p/{R}",
     "/tls/ws followed by /certhash"),
    (f"{V4}/tcp/443/tls/ws/ws/p2p/{R}", "/tls/ws/ws"),
    (f"{V4}/tcp/443/wss/tls/ws/p2p/{R}", "/wss/tls/ws"),
    (f"{V4}/tcp/443/TLS/ws/p2p/{R}", "multiaddr names are case-sensitive"),
    (f"{V4}/tcp/443/tls/ws", "no /p2p/<PeerId>"),
    (f"{V4}/tcp/443/tls/ws/p2p/{R}/", "a trailing /"),
    (f"/dns/{long_name(226)}/tcp/443/wss/p2p/{R}", "/wss whose /tls/ws form is 303 characters"),
    (f"/dns/{long_name(226)}/tcp/443/tls/ws/p2p/{R}", "a 303-character address"),
    (f"/dns4/203.0.113.7/tcp/443/tls/ws/p2p/{R}", "an IPv4 literal as a DNS name (TLS cannot send it as SNI)"),
    (f"/dns4/relay-.example.org/tcp/443/tls/ws/p2p/{R}", "a label ending in -"),
    (f"/dns/relay.123/tcp/443/p2p/{R}", "an all-digit last label"),
    (f"/dns/{'a' * 64}.example.org/tcp/443/tls/ws/p2p/{R}", "a label over 63 characters"),
    (f"{V4}/tcp/443/tls/sni/relay-.example.org/ws/p2p/{R}", "an SNI name with a label ending in -"),
    (f"/ip4/0.0.0.0/tcp/443/tls/ws/p2p/{R}", "an unspecified host"),
    (f"{V4}/tcp/0/tls/ws/p2p/{R}", "port 0"),
    (f"{V4}/tcp/443/tls/ws/p2p/not-a-peer", "no PeerId"),
]


# Proxy settings (section 8.1): (input, why). The outcome comes from raven_protocol.net_proxy.
SETTINGS = [
    ("", "empty: auto"),
    ("  AUTO ", "auto, any case, surrounding white space trimmed"),
    ("off", "off"),
    ("Off", "off, any case"),
    ("http://proxy.example:3128", "an http:// proxy"),
    ("proxy.example:3128", "a bare host:port is http"),
    ("http://proxy.example", "no port: 80"),
    ("proxy.example", "a bare host: http, port 80"),
    ("HTTP://Proxy.Example:8080/", "scheme any case, host lower-cased, one trailing / allowed"),
    ("\thttp://proxy.example:3128\r\n", "tab, CR and LF around it are trimmed"),
    ("http://proxy_1.corp.example:3128", "an underscore in a label"),
    ("http://proxy.example.:3128", "a trailing dot (a fully qualified name) is kept"),
    ("http://127.0.0.1:3128", "a proxy on this computer (cntlm, px)"),
    ("http://192.0.2.7:65535", "an IPv4 address; the highest port"),
    ("http://[2001:db8::1]:3128", "an IPv6 address in brackets"),
    ("[2001:DB8:0::1]:8080", "a bare [IPv6]:port; canonical IPv6 text"),
    ("http://[::ffff:192.0.2.7]:3128", "an IPv4-mapped IPv6 address is its IPv4 address"),
    ("http://user:pass@proxy.example:3128", "Basic credentials: base64 of user:pass"),
    ("http://us%65r:p%40ss%3Aword@proxy.example:3128", "user name and password percent-decoded"),
    ("http://user:p@ss@proxy.example:3128", "the last @ ends the user part"),
    ("http://user@proxy.example", "a user name alone: an empty password"),
    ("http://:pass@proxy.example", "an empty user name"),
    ("http://user:%C3%A9t%C3%A9@proxy.example", "a UTF-8 password, as bytes"),
    ("user:pass@proxy.example:3128", "credentials in a bare host:port"),
    ("https://proxy.example:443", "an HTTPS proxy"),
    ("HTTPS://user:pass@proxy.example", "an HTTPS proxy with credentials"),
    ("socks5://127.0.0.1:1080", "SOCKS5"),
    ("socks5h://proxy.example:1080", "SOCKS5 with remote names"),
    ("socks://proxy.example", "SOCKS"),
    ("socks4a://proxy.example:1080", "SOCKS4a"),
    ("pac", "the word pac"),
    ("WPAD", "the word wpad"),
    ("http://wpad.example/proxy.pac", "a PAC URL"),
    ("http://wpad.example/proxy.PAC?v=2", "a PAC URL with a query"),
    ("file:///etc/proxy.pac", "a PAC file"),
    ("http://wpad/wpad.dat", "the WPAD file"),
    ("ftp://proxy.example:21", "another scheme"),
    ("://proxy.example", "an empty scheme"),
    ("http//proxy.example", "no :// - a host part with a path"),
    ("http://proxy.example:3128/path", "a path"),
    ("http://proxy.example:3128?x=1", "a query"),
    ("http://proxy.example:3128#top", "a fragment"),
    ("http://proxy.example:0", "port 0"),
    ("http://proxy.example:65536", "port above 65535"),
    ("http://proxy.example:", "an empty port"),
    ("http://proxy.example:08080", "a leading zero"),
    ("http://proxy.example:+80", "a sign"),
    ("http://proxy.example:31:28", "two ports"),
    ("http://", "no host"),
    ("http://:3128", "an empty host"),
    ("http://0.0.0.0:3128", "the unspecified IPv4 address"),
    ("http://[::]:3128", "the unspecified IPv6 address"),
    ("http://224.0.0.1:3128", "a multicast address"),
    ("http://255.255.255.255:3128", "the broadcast address"),
    ("http://2001:db8::1:3128", "an IPv6 address without brackets"),
    ("http://[2001:db8::1", "an unclosed bracket"),
    ("http://[2001:db8::1]x", "text after the bracket"),
    ("http://[fe80::1%25en0]:3128", "an IPv6 zone"),
    ("http://[192.0.2.7]:3128", "an IPv4 address in brackets"),
    ("http://-proxy.example", "a label starting with -"),
    ("http://proxy..example", "an empty label"),
    ("http://256.1.1.1:3128", "a last label of digits: no IPv4 address"),
    ("http://10.1:3128", "a short IPv4 form"),
    ("http://@proxy.example", "an empty user part"),
    ("http://us%zzer:pass@proxy.example", "a bad percent escape"),
    ("http://user:pass%4@proxy.example", "a cut percent escape"),
    ("http://us%3Aer:pass@proxy.example", "a colon in the user name"),
    ("http://user:pa%0Ass@proxy.example", "a control character in the password"),
    ("http://proxy example:3128", "a space inside"),
    ("http://pr\u00f6xy.example:3128", "a non-ASCII character"),
    ("http://" + "a" * 1012 + ".example", "longer than 1024 bytes"),
]

# Windows proxy strings (section 8.2; WinHTTP lpszProxy, ProxyServer): (input, why).
WINDOWS = [
    ("http=a.example:1;https=b.example:2", "the https= entry"),
    ("b.example:2", "one entry for every scheme"),
    ("http=a.example:1;b.example:2;c.example:3", "the first bare entry serves https"),
    ("b.example:2;HTTPS=c.example:3", "an https= entry wins over a bare one, any case"),
    (" http=a.example:1  https=b.example:2 ", "white space separates entries too"),
    ("https=http://b.example:2", "an entry may carry http://"),
    ("https=;socks=s.example:1080;c.example:3", "an empty https= entry and socks= are skipped"),
    ("socks=s.example:1080", "socks= alone: none"),
    ("http=a.example:1", "http= alone: none"),
    ("", "empty: none"),
    (";;", "only separators: none"),
]

# Bypass lists (section 8.3): (list, why, [(host, port), ...]); the outcome comes from Bypass.
H = 443
LISTS = [
    ("", "an empty list: loopback, link-local and localhost names only",
     [("127.0.0.1", H), ("127.9.9.9", 7423), ("::1", H), ("[::1]", H), ("169.254.10.20", H),
      ("fe80::1", H), ("[FE80::1]", H), ("localhost", H), ("LOCALHOST.", H), ("relay.localhost", H),
      ("::ffff:127.0.0.1", H), ("192.0.2.7", H), ("relay.example.org", H), ("fd00::1", H),
      ("fec0::1", H), ("notlocalhost", H)]),
    ("*", "every host", [("relay.example.org", H), ("203.0.113.7", 7423), ("[2001:db8::7]", H)]),
    ("example.com", "a domain: it and every name under it, on a label boundary",
     [("example.com", H), ("www.example.com", H), ("a.b.example.com", 7423), ("EXAMPLE.COM", H),
      ("www.example.com.", H), ("notexample.com", H), ("example.com.evil.net", H), ("example.co", H),
      ("com", H)]),
    (".example.com", "a leading dot is optional: the same as example.com",
     [("example.com", H), ("www.example.com", H), ("notexample.com", H)]),
    ("example.com.", "a trailing dot is ignored", [("example.com", H), ("www.example.com", H)]),
    ("EXAMPLE.org", "entries ignore case", [("www.example.org", H), ("example.org", H)]),
    ("*.example.com", "a glob: names under it, not the domain itself",
     [("www.example.com", H), ("a.b.example.com", H), ("example.com", H), ("notexample.com", H)]),
    ("relay-*.example.net", "a glob inside a name",
     [("relay-1.example.net", H), ("relay-.example.net", H), ("relay.example.net", H)]),
    ("10.*", "a glob over an IP address's text", [("10.9.8.7", H), ("110.9.8.7", H), ("10.example", H)]),
    ("*.local", "the macOS default", [("printer.local", H), ("local", H), ("printer.local.", H)]),
    ("192.0.2.7", "an IPv4 address",
     [("192.0.2.7", H), ("192.0.2.8", H), ("[::ffff:192.0.2.7]", H), ("192.0.2.7.example", H)]),
    ("2001:db8::7", "an IPv6 address", [("2001:db8::7", H), ("[2001:DB8:0::7]", H), ("2001:db8::8", H)]),
    ("[2001:db8::7]", "an IPv6 address in brackets", [("2001:db8::7", 7423)]),
    ("10.0.0.0/8", "a CIDR", [("10.1.2.3", H), ("11.0.0.1", H), ("ten.example", H)]),
    ("172.16/12", "the macOS short form", [("172.20.1.1", H), ("172.31.255.255", H), ("172.32.0.1", H)]),
    ("169.254/16", "the macOS default (link-local, which bypasses anyway)", [("169.254.1.2", H)]),
    ("192.168/16, 10/8", "short forms with one and two parts",
     [("192.168.7.7", H), ("10.200.0.1", H), ("192.169.0.1", H)]),
    ("192.0.2.130/25", "host bits past the prefix are cleared",
     [("192.0.2.129", H), ("192.0.2.1", H)]),
    ("0.0.0.0/0", "a zero-length IPv4 prefix: every IPv4 address",
     [("203.0.113.7", H), ("2001:db8::7", H), ("relay.example.org", H)]),
    ("2001:db8::/32", "an IPv6 CIDR", [("2001:db8:1::1", H), ("2001:db9::1", H), ("192.0.2.7", H)]),
    ("example.com:8443", "a port: only dials to that port",
     [("example.com", 8443), ("example.com", H), ("www.example.com", 8443)]),
    ("192.0.2.7:443", "an IPv4 address with a port", [("192.0.2.7", 443), ("192.0.2.7", 7423)]),
    ("[2001:db8::7]:443", "an IPv6 address with a port", [("2001:db8::7", 443), ("2001:db8::7", 80)]),
    ("10.0.0.0/8:7423", "a CIDR with a port", [("10.9.9.9", 7423), ("10.9.9.9", H)]),
    ("*.corp.example:443", "a glob with a port", [("relay.corp.example", 443), ("relay.corp.example", 80)]),
    ("<local>", "Windows: names without a dot",
     [("intranet", H), ("INTRANET", H), ("intranet.example", H), ("192.0.2.7", H), ("2001:db8::7", H)]),
    ("example.com, .example.net;10.*  <local>\tfd00::/8\n*.local",
     "separators: comma, semicolon, space, tab and newline",
     [("www.example.com", H), ("example.net", H), ("10.1.1.1", H), ("intranet", H), ("fd00::1", H),
      ("printer.local", H), ("example.org", H)]),
    ("example.com:abc [::1 :443 10.0.0.0/33 -bad- 1.2.3.4/x 256.1.1.1 fe80::%en0/64 ok.example",
     "entries that fit no form are ignored",
     [("example.com", H), ("ok.example", H), ("a.ok.example", H), ("256.1.1.1", H), ("10.0.0.1", H)]),
]


# The WebSocket subset (section 5). Client frames carry this masking key (RFC 6455 section 5.7).
WS_MASK = bytes.fromhex("37fa213d")
WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="          # RFC 6455 section 1.3
WS_KEY2 = "AQIDBAUGBwgJCgsMDQ4PEA=="         # bytes 1..16
WHOLE_MAX = 126       # frames with a payload up to this long are written out whole
MESSAGE_HEX_MAX = 64  # messages up to this long are written out whole


def ws_pattern(n):
    """A payload of n bytes: byte i is i mod 251."""
    return bytes(i % 251 for i in range(n))


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# Binary frames, both ways: (payload length, why).
WS_DATA = [
    (0, "an empty binary frame"),
    (5, "'Hello' as a binary frame (RFC 6455 section 5.7 shows it as text, 0x81)"),
    (125, "the longest 7-bit length"),
    (126, "the shortest 16-bit length"),
    (65535, "the longest 16-bit length"),
    (65536, "the shortest 64-bit length (RFC 6455 section 5.7: a 64 KiB binary message)"),
]

# Control frames, both ways: (opcode, payload, why).
WS_CONTROL = [
    (ws.CLOSE, ws.NORMAL.to_bytes(2, "big"), "close 1000: normal closure"),
    (ws.CLOSE, ws.PROTOCOL.to_bytes(2, "big"), "close 1002: a frame the subset refuses"),
    (ws.CLOSE, ws.UNSUPPORTED_DATA.to_bytes(2, "big"), "close 1003: a text message"),
    (ws.CLOSE, ws.TOO_BIG.to_bytes(2, "big"), "close 1009: a message over 262144 bytes"),
    (ws.CLOSE, b"", "a close without a status code"),
    (ws.PING, b"Hello", "ping 'Hello' (RFC 6455 section 5.7)"),
    (ws.PONG, b"Hello", "pong 'Hello' (RFC 6455 section 5.7)"),
    (ws.PING, b"", "an empty ping"),
    (ws.PONG, b"", "an empty pong"),
    (ws.PING, ws_pattern(125), "the longest control payload"),
]

# Heads parse_head reads: (head bytes, expect_masked, why).
WS_HEADS = [
    (ws.encode_head(True, ws.BINARY, 5, WS_MASK), True, "a client frame"),
    (ws.encode_head(True, ws.BINARY, 5), False, "a server frame"),
    (ws.encode_head(False, ws.BINARY, 3, WS_MASK), True, "the first fragment of a message"),
    (ws.encode_head(False, ws.CONTINUATION, 3, WS_MASK), True, "a continuation, not the last"),
    (ws.encode_head(True, ws.CONTINUATION, 0), False, "the last continuation, empty"),
    (ws.encode_head(True, ws.TEXT, 5, WS_MASK), True, "a text frame: its head is read, its message refused"),
    (ws.encode_head(True, ws.PING, 125, WS_MASK), True, "the longest control payload"),
    (ws.encode_head(True, ws.CLOSE, 2), False, "a close"),
    (ws.encode_head(True, ws.BINARY, 126), False, "a 16-bit length"),
    (ws.encode_head(True, ws.BINARY, 65536, WS_MASK), True, "a 64-bit length"),
    (ws.encode_head(True, ws.BINARY, ws.MAX_MESSAGE, WS_MASK), True, "the largest frame: 262144 bytes"),
]

# Heads cut short: parse_head asks for more bytes. (hex, expect_masked, why)
WS_INCOMPLETE = [
    ("", True, "nothing"),
    ("82", True, "one byte"),
    ("c2", True, "one byte with RSV1 set: nothing is checked before two bytes"),
    ("82fe00", True, "a 16-bit length cut"),
    ("827f00000000000100", False, "a 64-bit length cut"),
    ("828537fa21", True, "a masking key cut"),
    ("82fe007e37", True, "a masking key cut after a 16-bit length"),
]

# Heads parse_head refuses: (hex, expect_masked, why); the close code comes from the reference.
WS_REJECT = [
    ("c28537fa213d", True, "RSV1 set (no extension was agreed)"),
    ("a28537fa213d", True, "RSV2 set"),
    ("928537fa213d", True, "RSV3 set"),
    ("f0ff", True, "every bit of the first byte set"),
    ("838537fa213d", True, "opcode 3 (reserved, data)"),
    ("878537fa213d", True, "opcode 7 (reserved, data)"),
    ("8b8037fa213d", True, "opcode 0xB (reserved, control)"),
    ("8f00", False, "opcode 0xF (reserved, control)"),
    ("098537fa213d", True, "a ping without FIN"),
    ("0802", False, "a close without FIN"),
    ("89fe007e37fa213d", True, "a ping of 126 bytes"),
    ("8a7e007e", False, "a pong of 126 bytes"),
    ("887f", False, "a close with a 64-bit length"),
    ("820548656c6c6f", True, "an unmasked frame from a client"),
    ("828537fa213d7f9f4d5158", False, "a masked frame from a server"),
    ("827f0000000000040001", True, "an unmasked client frame over the limit: the mask check comes first"),
    ("82fe007d37fa213d", True, "125 in the 16-bit form (not minimal)"),
    ("827e0000", False, "0 in the 16-bit form (not minimal)"),
    ("82ff000000000000ffff37fa213d", True, "65535 in the 64-bit form (not minimal)"),
    ("827f000000000000007e", False, "126 in the 64-bit form (not minimal)"),
    ("82ff0000000000040001", True, "262145 bytes, one over the limit (refused before its masking key)"),
    ("827f0000000000100000", False, "1 MiB"),
    ("82ff800000000000000037fa213d", True, "a 64-bit length with its top bit set"),
    ("827fffffffffffffffff", False, "the largest 64-bit length"),
]


def frame(fin, op, payload=None, length=None):
    """A frame of a sequence: payload bytes, or a length whose payload is ws_pattern(length)."""
    return (fin, op, payload if payload is not None else ws_pattern(length))


# Frame sequences read in a row (ws.read_frames): (expect_masked, frames, why).
WS_SEQUENCES = [
    (True, [frame(True, ws.BINARY, b"Hello")], "one binary message"),
    (True, [frame(False, ws.BINARY, b"Hel"), frame(True, ws.PING, b"p"), frame(False, ws.CONTINUATION, b""),
            frame(True, ws.PONG, b""), frame(True, ws.CONTINUATION, b"lo")],
     "a message in three fragments, with a ping and a pong between them"),
    (True, [frame(True, ws.BINARY, b"")], "an empty message"),
    (True, [frame(True, ws.BINARY, b"a"), frame(True, ws.BINARY, b"b"),
            frame(True, ws.CLOSE, ws.NORMAL.to_bytes(2, "big")), frame(True, ws.BINARY, b"c")],
     "two messages, then a close 1000: nothing after the close is read"),
    (True, [frame(True, ws.CLOSE, b"")], "a close without a status code"),
    (True, [frame(False, ws.BINARY, b"ab"), frame(True, ws.CLOSE, (1001).to_bytes(2, "big") + b"bye")],
     "a close inside a message (the message is dropped; the reason text is ignored)"),
    (True, [frame(True, ws.CLOSE, b"\x03")], "a close with a 1-byte payload"),
    (True, [frame(True, ws.TEXT, b"Hello")], "a text message"),
    (True, [frame(False, ws.TEXT, b"He")], "the first fragment of a text message"),
    (True, [frame(True, ws.CONTINUATION, b"x")], "a continuation with no message open"),
    (True, [frame(False, ws.BINARY, b"a"), frame(True, ws.BINARY, b"b")], "a binary frame while a message is open"),
    (True, [frame(False, ws.BINARY, b"a"), frame(True, ws.TEXT, b"b")],
     "a text frame while a message is open: the open message decides"),
    (True, [frame(True, ws.PING, length=125), frame(True, ws.BINARY, b"x")], "the longest ping, then a message"),
    (True, [frame(False, ws.BINARY, length=131072), frame(True, ws.CONTINUATION, length=131072)],
     "a message of exactly 262144 bytes in two fragments"),
    (True, [frame(False, ws.BINARY, length=262144), frame(True, ws.CONTINUATION, length=1)],
     "a message one byte over the limit, in two fragments"),
    (False, [frame(False, ws.BINARY, b"He"), frame(True, ws.PING, b""), frame(True, ws.CONTINUATION, b"llo")],
     "a fragmented message from a server"),
    (False, [frame(True, ws.TEXT, b"Hello")], "a text message from a server"),
]


def ws_frame_case(n, why):
    payload = b"Hello" if n == 5 else ws_pattern(n)
    client, server = ws.encode(ws.BINARY, payload, WS_MASK), ws.encode(ws.BINARY, payload)
    chead, shead = ws.parse_head(client, True)[4], ws.parse_head(server, False)[4]
    case = {"why": why, "payload_len": n,
            "client_head_hex": client[:chead].hex(), "server_head_hex": server[:shead].hex(),
            "client_frame_len": len(client), "server_frame_len": len(server),
            "client_frame_sha256": sha256_hex(client), "server_frame_sha256": sha256_hex(server)}
    if n <= WHOLE_MAX:
        case.update({"payload_hex": payload.hex(), "client_frame_hex": client.hex(),
                     "server_frame_hex": server.hex()})
    return case


def ws_control_case(op, payload, why):
    case = {"why": why, "op": op, "payload_hex": payload.hex(),
            "client_frame_hex": ws.encode(op, payload, WS_MASK).hex(),
            "server_frame_hex": ws.encode(op, payload).hex()}
    if op == ws.CLOSE:
        case["close_code"] = ws.close_code(payload)
    return case


def ws_head_case(head, masked, why):
    fin, op, mask, length, hdr = ws.parse_head(head, masked)
    assert hdr == len(head) and ws.encode_head(fin, op, length, mask) == head, why
    return {"head_hex": head.hex(), "expect_masked": masked, "why": why, "fin": fin, "op": op,
            "mask_hex": mask.hex() if mask is not None else None, "len": length, "hdr_len": hdr}


def ws_reject_case(text, masked, why):
    try:
        ws.parse_head(bytes.fromhex(text), masked)
    except ws.WsClose as e:
        return {"head_hex": text, "expect_masked": masked, "why": why, "close": e.code}
    raise RuntimeError(f"parse_head accepted a reject case: {text}")


def ws_message(m):
    out = {"len": len(m), "sha256": sha256_hex(m)}
    if len(m) <= MESSAGE_HEX_MAX:
        out["hex"] = m.hex()
    return out


def ws_sequence_case(masked, frames, why):
    data = b"".join(ws.encode(op, p, WS_MASK if masked else None, fin) for fin, op, p in frames)
    messages, outcome, code = ws.read_frames(data, masked)
    out = []
    for fin, op, p in frames:
        f = {"fin": fin, "op": op}
        f.update({"payload_hex": p.hex()} if len(p) <= MESSAGE_HEX_MAX or p != ws_pattern(len(p))
                 else {"payload_len": len(p)})
        out.append(f)
    return {"why": why, "expect_masked": masked, "frames": out,
            "messages": [ws_message(m) for m in messages], "outcome": outcome, "code": code}


def http(*lines):
    """An HTTP head from its lines (CRLF after each, then the blank line)."""
    return "".join(line + "\r\n" for line in lines) + "\r\n"


def upgrade(host="relay.example.org", key=WS_KEY, first="GET / HTTP/1.1", drop=(), extra=()):
    """A client upgrade request; drop removes header lines by name, extra appends lines."""
    lines = [first, f"Host: {host}", "Upgrade: websocket", "Connection: Upgrade", f"Sec-WebSocket-Key: {key}",
             "Sec-WebSocket-Version: 13"]
    return http(*[x for x in lines if x.split(":")[0] not in drop], *extra)


def switching(accept=None, first="HTTP/1.1 101 Switching Protocols", drop=(), extra=()):
    """A server 101 for WS_KEY; drop and extra as in upgrade()."""
    lines = [first, "Upgrade: websocket", "Connection: Upgrade",
             f"Sec-WebSocket-Accept: {accept or ws.accept_token(WS_KEY)}"]
    return http(*[x for x in lines if x.split(":")[0] not in drop], *extra)


def padded(head, size):
    """head with one X-Pad header line added that makes it exactly size bytes."""
    pad = size - len(head) - len("X-Pad: \r\n")
    return head[:-2] + "X-Pad: " + "a" * pad + "\r\n\r\n"


PADS = [f"X-Pad-{i:02}: 1" for i in range(30)]
SERVER_ACCEPTS = [
    (upgrade(), "the client request for relay.example.org"),
    ("GET / HTTP/1.1\r\nhost: 203.0.113.7:8443\r\nUser-Agent: test\r\nOrigin: https://example.org\r\n"
     "UPGRADE: WebSocket\r\nconnection: keep-alive, Upgrade\r\nsec-websocket-key: " + WS_KEY2 + "\r\n"
     "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Extensions: permessage-deflate\r\n"
     "sec-websocket-version:13 \t\r\n\r\n",
     "names and tokens in any case, token lists, values trimmed; Origin, User-Agent and an offered "
     "subprotocol and extension are ignored (none is selected)"),
    (upgrade(extra=PADS[:27]), "exactly 32 headers"),
    (padded(upgrade(), 8192), "a head of exactly 8192 bytes"),
]
SERVER_REFUSES = [
    (upgrade(first="GET /x HTTP/1.1"), "a path other than /"),
    (upgrade(first="GET /?a=1 HTTP/1.1"), "a query"),
    (upgrade(first="GET http://relay.example.org/ HTTP/1.1"), "the absolute form"),
    (upgrade(first="POST / HTTP/1.1"), "POST"),
    (upgrade(first="get / HTTP/1.1"), "a lower-case method"),
    (upgrade(first="GET / HTTP/1.0"), "HTTP/1.0"),
    (upgrade(first="GET  / HTTP/1.1"), "two spaces in the request line"),
    (upgrade(drop=("Host",)), "no Host"),
    (upgrade(extra=["Host: relay.example.net"]), "two Host headers"),
    (upgrade(drop=("Upgrade",)), "no Upgrade"),
    (upgrade(drop=("Upgrade",), extra=["Upgrade: h2c"]), "Upgrade: h2c"),
    (upgrade(drop=("Connection",), extra=["Connection: keep-alive"]), "Connection without upgrade"),
    (upgrade(drop=("Sec-WebSocket-Version",), extra=["Sec-WebSocket-Version: 8"]), "version 8"),
    (upgrade(drop=("Sec-WebSocket-Version",)), "no Sec-WebSocket-Version"),
    (upgrade(extra=["Sec-WebSocket-Version: 13"]), "two Sec-WebSocket-Version headers"),
    (upgrade(drop=("Sec-WebSocket-Key",)), "no Sec-WebSocket-Key"),
    (upgrade(key="AQIDBAUGBwgJCgsMDQ4P"), "a key of 15 bytes"),
    (upgrade(key="dGhlIHNhbXBsZSBub25jZQ"), "a key without its padding"),
    (upgrade(key="dGhlIHNhbXBsZSBub25jZR=="), "a key with non-zero bits in its last character"),
    (upgrade(key="dGhlIHNhbXBsZSBub25j ZQ=="), "a key with a space inside"),
    (upgrade(extra=[f"Sec-WebSocket-Key: {WS_KEY2}"]), "two Sec-WebSocket-Key headers"),
    (upgrade(extra=PADS[:28]), "33 headers"),
    (padded(upgrade(), 8193), "a head of 8193 bytes"),
    ("GET / HTTP/1.1\r\nHost: relay.example.org\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
     f"Sec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n", "a bare LF line end"),
    (upgrade(extra=["X-Bad header"]), "a header line without a colon"),
    (upgrade(drop=("Host",), extra=["Host : relay.example.org"]), "a space before the colon"),
    ("PRI * HTTP/2.0\r\n\r\n", "the HTTP/2 preface"),
]
CLIENT_ACCEPTS = [
    (switching(), "the server 101 for the RFC 6455 key"),
    ("HTTP/1.1 101 OK\r\nserver: x\r\nUPGRADE: WebSocket\r\nCONNECTION: upgrade\r\n"
     f"sec-websocket-accept: {ws.accept_token(WS_KEY)}\r\n\r\n",
     "names and tokens in any case, another reason phrase, an extra header"),
    (switching(first="HTTP/1.1 101"), "no reason phrase"),
    (switching(extra=PADS[:29]), "exactly 32 headers"),
    (padded(switching(), 8192), "a head of exactly 8192 bytes"),
]
CLIENT_REFUSES = [
    (ws.NOT_FOUND.decode("ascii"), "404 (a relay refusing the upgrade)"),
    (http("HTTP/1.1 200 OK", "Content-Length: 0"), "200"),
    (http("HTTP/1.1 426 Upgrade Required", "Sec-WebSocket-Version: 13"), "426"),
    (switching(first="HTTP/1.0 101 Switching Protocols"), "HTTP/1.0"),
    (switching(accept=ws.accept_token(WS_KEY2)), "the accept value of another key"),
    (switching(drop=("Sec-WebSocket-Accept",)), "no Sec-WebSocket-Accept"),
    (switching(extra=[f"Sec-WebSocket-Accept: {ws.accept_token(WS_KEY)}"]), "two Sec-WebSocket-Accept headers"),
    (switching(drop=("Upgrade",)), "no Upgrade"),
    (switching(drop=("Upgrade",), extra=["Upgrade: h2c"]), "Upgrade: h2c"),
    (switching(drop=("Connection",)), "no Connection"),
    (switching(extra=["Sec-WebSocket-Extensions: permessage-deflate"]), "an extension"),
    (switching(extra=["Sec-WebSocket-Protocol: chat"]), "a subprotocol"),
    (switching(extra=PADS[:30]), "33 headers"),
    (padded(switching(), 8193), "a head of 8193 bytes"),
]


def ws_server_case(text, why):
    raw = text.encode("ascii")
    try:
        key = ws.check_request(raw)
    except ws.Refused:
        return {"request": text, "why": why, "accepted": False, "reply": ws.NOT_FOUND.decode("ascii")}
    return {"request": text, "why": why, "accepted": True, "key": key,
            "reply": ws.server_response(key).decode("ascii")}


def ws_client_case(text, why):
    try:
        ws.check_response(text.encode("ascii"), WS_KEY)
    except ws.Refused:
        return {"response": text, "why": why, "accepted": False}
    return {"response": text, "why": why, "accepted": True}


def ws_vectors():
    # The RFC 6455 known answers, from an implementation that shares nothing with the cases below.
    assert ws.accept_token(WS_KEY) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    assert ws.encode(ws.TEXT, b"Hello").hex() == "810548656c6c6f"
    assert ws.encode(ws.TEXT, b"Hello", WS_MASK).hex() == "818537fa213d7f9f4d5158"
    assert ws.encode(ws.BINARY, b"Hello", WS_MASK).hex() == "828537fa213d7f9f4d5158"
    assert ws.encode(ws.PING, b"Hello").hex() == "890548656c6c6f"
    assert ws.encode(ws.PONG, b"Hello", WS_MASK).hex() == "8a8537fa213d7f9f4d5158"
    assert ws.encode(ws.BINARY, bytes(256))[:4].hex() == "827e0100"
    assert ws.encode(ws.BINARY, bytes(65536))[:10].hex() == "827f0000000000010000"
    handshake = vec(
        "WebSocket upgrade: the accept value, the client request and the server reply",
        "The RFC 6455 section 1.3 key and its Sec-WebSocket-Accept, with the SHA-1 digest under the base64. "
        "Each request case: the client's exact request for a Host value and key. Each server case: an "
        "HTTP head a client sends, whether the server upgrades, and its exact reply (101 with the accept "
        "value, else the 404, after which it closes). Each client case: a reply to the request for the "
        "RFC 6455 key, and whether the client takes it. Section 5; raven_protocol/websocket.py",
        {"key": WS_KEY, "guid": ws.GUID.decode("ascii"), "max_header_block": ws.MAX_HEADER_BLOCK,
         "max_headers": ws.MAX_HEADERS},
        {"accept": ws.accept_token(WS_KEY),
         "sha1_hex": hashlib.sha1(WS_KEY.encode("ascii") + ws.GUID).hexdigest(),
         "not_found": ws.NOT_FOUND.decode("ascii"),
         "requests": [{"host": h, "key": k, "request": ws.client_request(h, k).decode("ascii")}
                      for h, k in (("relay.example.org", WS_KEY), ("203.0.113.7:8443", WS_KEY),
                                   ("[2001:db8::7]", WS_KEY2))],
         "server": [ws_server_case(t, w) for t, w in SERVER_ACCEPTS + SERVER_REFUSES],
         "client": [ws_client_case(t, w) for t, w in CLIENT_ACCEPTS + CLIENT_REFUSES]})
    frames = vec(
        "WebSocket frames: binary and control frames both ways, frame heads, and frame sequences",
        "Client frames carry the masking key 37fa213d, server frames none. Each data case: a binary "
        "frame's head both ways, the whole frame's length and SHA-256, and, up to 126 payload bytes, the "
        "payload and the whole frames (otherwise byte i of the payload is i mod 251). Each control case: "
        "a close, ping or pong frame both ways. Heads: what parse_head reads; incomplete: heads it needs "
        "more bytes for; reject: heads it refuses, with the close code. Each sequence: frames read in a "
        "row (data frames joined into messages, pings and pongs skipped, a close ends the reading; a "
        "frame gives its payload, or a length whose payload is the i mod 251 pattern), the messages "
        "(length, SHA-256 and, up to 64 bytes, the bytes) and the outcome: end (the input ran out), "
        "close (code: its status code) or fail (code: the close code sent). Section 5; "
        "raven_protocol/websocket.py",
        {"mask_hex": WS_MASK.hex(), "max_message": ws.MAX_MESSAGE, "max_control": ws.MAX_CONTROL,
         "payload_pattern": "byte i is i mod 251"},
        {"data": [ws_frame_case(n, w) for n, w in WS_DATA],
         "control": [ws_control_case(o, p, w) for o, p, w in WS_CONTROL],
         "heads": [ws_head_case(h, m, w) for h, m, w in WS_HEADS],
         "incomplete": [{"head_hex": t, "expect_masked": m, "why": w} for t, m, w in WS_INCOMPLETE
                        if ws.parse_head(bytes.fromhex(t), m) is None],
         "reject": [ws_reject_case(t, m, w) for t, m, w in WS_REJECT],
         "sequences": [ws_sequence_case(m, f, w) for m, f, w in WS_SEQUENCES]})
    assert len(frames["expected"]["incomplete"]) == len(WS_INCOMPLETE)
    return handshake, frames


# The CONNECT client (section 7): tunnel targets, with and without the Basic value of user:pass.
BASIC_USER_PASS = b"user:pass"
BASIC = "dXNlcjpwYXNz"
AUTHORITIES = [
    ("relay.example.org:443", "a /dns* host: the name goes to the proxy and is never resolved here"),
    ("203.0.113.7:443", "an IPv4 host"),
    ("[2001:db8::7]:8443", "an IPv6 host in brackets, on another port"),
]


def reply(*lines, rest=b""):
    """A proxy reply head from its lines (CRLF after each, then the blank line), then rest."""
    return "".join(line + "\r\n" for line in lines).encode("latin-1") + b"\r\n" + rest


def reply_padded(head, size):
    """head with one X-Pad header line added that makes it exactly size bytes."""
    pad = size - len(head) - len(b"X-Pad: \r\n")
    return head[:-2] + b"X-Pad: " + b"a" * pad + b"\r\n\r\n"


OK200 = "HTTP/1.1 200 Connection established"
AUTH407 = "HTTP/1.1 407 Proxy Authentication Required"
RPADS = [f"X-Pad-{i:02}: 1" for i in range(33)]
CONNECT_REPLIES = [
    (reply(OK200), "200: the tunnel is open"),
    (reply(OK200, rest=b"\x16\x03\x03\x00\x05early"), "bytes after the head are tunnel data, kept for TLS"),
    (reply("HTTP/1.0 200 Connection established", rest=b"leftover"), "HTTP/1.0 200 with leftover bytes"),
    (reply("HTTP/1.1 200"), "no reason phrase"),
    (reply("HTTP/1.1 200 "), "an empty reason phrase"),
    (reply("HTTP/1.1 204 No Content"), "any 2xx"),
    (reply("HTTP/1.1 299 Whatever"), "any 2xx (299)"),
    (reply(OK200, "Proxy-Agent: corp-proxy/1.0", "content-length: 12", "Transfer-Encoding: chunked"),
     "Content-Length and Transfer-Encoding of a 2xx reply are ignored"),
    (reply("HTTP/1.1 200 été", rest=b"x"), "obs-text in the reason phrase"),
    (reply(OK200, "X-Note:\tvalue with\ttabs \t", "X-Empty:", "X-Obs: é"),
     "tabs in a value, an empty value, obs-text in a value"),
    (reply(OK200, *RPADS[:32]), "exactly 32 headers"),
    (reply_padded(reply(OK200), 8192), "a head of exactly 8192 bytes"),
    (reply_padded(reply(OK200), 8190) + b"0123456789",
     "a head under 8192 bytes and more bytes after it than fit in 8192: the head decides"),
    (reply(AUTH407, 'Proxy-Authenticate: Basic realm="corp"'), "407 offering Basic"),
    (reply(AUTH407, "Proxy-Authenticate: NTLM", "Proxy-Authenticate: Negotiate",
           'Proxy-Authenticate: Basic realm="corp"'), "407 offering NTLM, Negotiate and Basic, one header each"),
    (reply(AUTH407, 'Proxy-Authenticate: Basic realm="a, b", Digest realm="c", qop="auth", nonce="n", NEGOTIATE'),
     "several challenges in one header; a comma inside a quoted string; names in any case"),
    (reply(AUTH407, "proxy-authenticate: Negotiate YIIBhgYGKwYBBQUCoA==",
           'Proxy-Authenticate: Digest realm="x", algorithm = MD5'),
     "a token68 after the scheme; an auth-param with spaces around ="),
    (reply(AUTH407, "Proxy-Authenticate: X-Corp-SSO token=1", "Proxy-Authenticate: Bearer",
           "Proxy-Authenticate: x-corp-sso"), "an unknown scheme is other; each scheme once"),
    (reply(AUTH407, 'Proxy-Authenticate: , ,"quoted", =x, realm="r"'), "elements that are no scheme"),
    (reply(AUTH407), "407 without Proxy-Authenticate: no scheme"),
    (reply("HTTP/1.0 407 Proxy Authentication Required", "Proxy-Authenticate: Negotiate"), "HTTP/1.0 407"),
    (reply("HTTP/1.1 403 Forbidden", "Content-Length: 0"), "403"),
    (reply("HTTP/1.1 502 Bad Gateway", rest=b"<html>...</html>"), "502 with a body"),
    (reply("HTTP/1.1 400 Bad Request"), "400"),
    (reply("HTTP/1.1 101 Switching Protocols"), "101 is not a 2xx"),
    (reply("HTTP/1.1 301 Moved Permanently", "Location: http://proxy.example/"), "301"),
    (reply("HTTP/1.1 999 Odd"), "any other three digits"),
    (reply_padded(reply(OK200), 8193), "a head of 8193 bytes"),
    (b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 8168, "8192 bytes and no blank line yet"),
    (reply(OK200, *RPADS[:33]), "33 headers"),
    (reply("HTTP/2 200"), "HTTP/2"),
    (reply("HTTP/1.2 200 OK"), "HTTP/1.2"),
    (reply("http/1.1 200 OK"), "a lower-case protocol name"),
    (reply("HTTP/1.1  200 OK"), "two spaces before the code"),
    (reply("HTTP/1.1 20 OK"), "a two-digit code"),
    (reply("HTTP/1.1 2000 OK"), "a four-digit code"),
    (reply("HTTP/1.1 200\tOK"), "a tab after the code"),
    (reply("HTTP/1.1 200 O\x01K"), "a control byte in the reason phrase"),
    (b"HTTP/1.1 200 OK\nProxy-Agent: x\r\n\r\n", "a bare LF"),
    (b"HTTP/1.1 200 OK\r\rX: y\r\n\r\n", "a bare CR"),
    (b"\r\nHTTP/1.1 200 OK\r\n\r\n", "an empty line before the status line"),
    (reply(OK200, "X-Bad header"), "a header line without a colon"),
    (reply(OK200, "X-Bad : y"), "a space before the colon"),
    (reply(OK200, "X-A: 1", " folded"), "a folded line"),
    (reply(OK200, ": no name"), "an empty header name"),
    (reply(OK200, "X-é: y"), "obs-text in a header name"),
    (reply(OK200, "X-Ctl: a\x01b"), "a control byte in a value"),
    (reply(OK200, "X-Del: a\x7fb"), "DEL in a value"),
    (b"SSH-2.0-OpenSSH_9.6\r\n", "not HTTP: decided at the first byte that differs from HTTP/1."),
    (bytes.fromhex("15030300020228"), "a TLS alert (an https:// proxy)"),
    (bytes.fromhex("05ff"), "a SOCKS5 reply"),
    (b"HTTP/1.1 200 OK\n", "a bare LF before the head is whole"),
    (b"", "nothing yet"),
    (b"H", "the first byte"),
    (b"HTTP/1.", "the protocol name so far"),
    (b"HTTP/1.1 200 Connection established\r\n", "the status line"),
    (b"HTTP/1.1 200 Connection established\r\n\r", "a CR at the end so far"),
    (b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic", "inside a header"),
    (b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 8167, "8191 bytes and no blank line yet"),
]

# The first bytes a two-protocol listener sees (section 6): (hex, why).
DEMUX = [
    ("16030100f8010000f40303", "a TLS ClientHello record: TLS, then the WebSocket upgrade"),
    ("16", "0x16 alone decides"),
    ("132f6d756c746973747265616d2f312e302e300a", "0x13 /multistream/1.0.0 LF: raw libp2p"),
    ("13", "0x13 alone decides"),
    ("474554202f20485454502f312e310d0a", "plain HTTP (GET / HTTP/1.1)"),
    ("434f4e4e454354", "an HTTP CONNECT"),
    ("15030300020228", "a TLS alert record"),
    ("17030300", "a TLS application data record"),
    ("8001", "an SSLv2-style hello"),
    ("05010000", "a SOCKS5 greeting"),
    ("12", "0x12 (the varint 18)"),
    ("00", "0x00"),
    ("ff", "0xff"),
    ("", "nothing within the wait, or the connection ended"),
]


def connect_reply_case(raw, why):
    case = {"why": why}
    if raw.isascii():
        case["reply"] = raw.decode("ascii")
    else:
        case["reply_hex"] = raw.hex()
    r = connect.parse_reply(raw)
    if r is None:
        assert len(raw) < connect.MAX_HEADER_BLOCK, why
        case["outcome"] = "incomplete"
    elif r[0] == connect.TUNNEL:
        case.update({"outcome": r[0], "leftover_hex": r[1].hex()})
    elif r[0] == connect.AUTH:
        case.update({"outcome": r[0], "schemes": r[1]})
    elif r[0] == connect.REFUSED:
        case.update({"outcome": r[0], "code": r[1]})
    else:
        case["outcome"] = r[0]
    return case


def connect_vectors():
    assert base64.b64encode(BASIC_USER_PASS).decode("ascii") == BASIC
    request = vec(
        "HTTP CONNECT requests",
        "Each case: a tunnel target (authority) and the Proxy-Authorization Basic value or null, and the "
        "client's exact request. The Basic value is base64 of user:pass (RFC 7617). Section 7; "
        "raven_protocol/connect.py",
        {"basic_user_pass": BASIC_USER_PASS.decode("ascii"), "basic": BASIC},
        {"requests": [{"authority": a, "why": w, "basic": b, "request": connect.connect_request(a, b).decode("ascii")}
                      for a, w in AUTHORITIES for b in (None, BASIC)]})
    replies = vec(
        "HTTP CONNECT replies",
        "Each case: the bytes a proxy sent so far (reply as text, or reply_hex when not ASCII) and what the "
        "client makes of them: tunnel (any 2xx; leftover_hex: the bytes after the head, which are tunnel "
        "data), auth (407; schemes: the Proxy-Authenticate schemes, canonical names or other, each once), "
        "refused (any other status; code), malformed (not an HTTP/1.x reply head within 8192 bytes and 32 "
        "headers, decided as soon as the bytes show it) or incomplete (more bytes needed). Section 7; "
        "raven_protocol/connect.py",
        {"max_header_block": connect.MAX_HEADER_BLOCK, "max_headers": connect.MAX_HEADERS,
         "schemes": sorted(connect.SCHEMES.values()) + [connect.OTHER]},
        {"replies": [connect_reply_case(r, w) for r, w in CONNECT_REPLIES]})
    demux = vec(
        "Two-protocol listener: the first byte",
        "Each case: the first bytes a client sent to a relay's WSS listener (only the first byte counts; "
        "empty: nothing came within the wait, or the connection ended) and what the listener does: tls "
        "(TLS, then the WebSocket upgrade), raw (libp2p as on a raw TCP listener) or refused (closed with "
        "no reply). Section 6; raven_protocol/connect.py",
        {"wait_seconds": 10},
        {"cases": [{"first_hex": h, "why": w, "outcome": connect.demux(bytes.fromhex(h))} for h, w in DEMUX]})
    return request, replies, demux


def setting_case(text, why):
    case = {"input": text, "why": why, "credentials": net_proxy.has_credentials(text)}
    try:
        setting = net_proxy.parse_setting(text)
    except net_proxy.ProxyError as e:
        case.update({"error": e.code, "kind": e.kind})
        return case
    case.update({"setting": setting[0], "display": net_proxy.setting_display(setting)})
    if setting[0] == "url":
        u = setting[1]
        case.update({"host": u.host, "port": u.port, "basic": u.basic})
        if u.basic is None:  # the canonical text reads back the same
            assert net_proxy.parse_proxy_url(u.display()) == u, text
    return case


def list_case(text, why, checks):
    bypass = net_proxy.Bypass.parse(text)
    return {"list": text, "why": why,
            "checks": [{"host": h, "port": p, "bypass": bypass.bypasses(h, p)} for h, p in checks]}


def accept_case(text, why):
    canonical, peer = via.parse_via(text)
    assert via.parse_via(canonical) == (canonical, peer), text
    return {"input": text, "why": why, "canonical": canonical, "peer_id": peer,
            "is_wss": via.is_wss(canonical), "tcp_port": via.tcp_port(canonical),
            "raw_sibling": via.raw_sibling(canonical), "wss_sibling": via.wss_sibling(canonical),
            "dial_forms": {"gate_closed": via.relay_dial_forms(canonical, False, False),
                           "raw_first": via.relay_dial_forms(canonical, True, False),
                           "wss_first": via.relay_dial_forms(canonical, True, True)}}


def reject_case(text, why):
    try:
        via.parse_via(text)
    except via.ViaError as e:
        return {"input": text, "why": why, "error": e.code}
    raise RuntimeError(f"the grammar accepted a reject case: {text}")


def build():
    out = {}
    out["p2p/via_001.json"] = vec(
        "via= grammar: WebSocket over TLS, siblings and dial forms",
        "Each accept case: the input, its canonical text (what a via is stored as) and PeerId, whether it "
        "is WSS, its TCP port, its raw and WSS siblings (section 2.3) and relay_dial_forms with the WSS "
        "gate closed, open with raw first, and open with WSS first. Each reject case: the input and the "
        "step that refuses it (raven_protocol/via.py error codes). PeerIds: Ed25519 keys 0x52 x 32 "
        "(relay) and 0x43 x 32 (contact)",
        {"relay_ed25519_public_hex": RELAY_KEY.hex(), "relay_peer_id": R,
         "contact_ed25519_public_hex": CONTACT_KEY.hex(), "contact_peer_id": C,
         "max_multiaddr_chars": via.MAX_MULTIADDR_CHARS},
        {"accept": [accept_case(t, w) for t, w in ACCEPT],
         "reject": [reject_case(t, w) for t, w in REJECT]})
    out["wss/rws1_proxy_url_001.json"] = vec(
        "Proxy settings, proxy URLs and Windows proxy strings",
        "Each setting case: the input, whether node policy refuses it as carrying credentials (any @), "
        "and either the setting (auto, off or url: host, port, the Basic value or null, the redacted "
        "display) or the refusal (error: the rule's code; kind: https, socks, pac or invalid, what a "
        "status line says). Each Windows case: the entry a WSS dial uses, or null. Section 7 and 8; "
        "raven_protocol/net_proxy.py",
        {"default_port": net_proxy.DEFAULT_PORT, "max_text_bytes": net_proxy.MAX_TEXT,
         "trimmed": "space, tab, CR, LF"},
        {"settings": [setting_case(t, w) for t, w in SETTINGS],
         "windows": [{"input": t, "why": w, "entry": net_proxy.parse_windows_proxy(t)} for t, w in WINDOWS]})
    out["wss/rws1_no_proxy_001.json"] = vec(
        "Bypass lists (NO_PROXY, macOS ExceptionsList, Windows ProxyOverride)",
        "Each list case: the list as one string and, for each check, a host (a DNS name or an IP "
        "address, IPv6 with or without brackets), the dial's port, and whether the dial goes direct. "
        "Loopback and link-local addresses and localhost names always bypass. Section 8; "
        "raven_protocol/net_proxy.py",
        {"separators": "comma, semicolon, space, tab, CR, LF"},
        {"lists": [list_case(t, w, c) for t, w, c in LISTS]})
    out["wss/rws1_ws_handshake_001.json"], out["wss/rws1_ws_frames_001.json"] = ws_vectors()
    (out["wss/rws1_connect_request_001.json"], out["wss/rws1_connect_reply_001.json"],
     out["wss/rws1_demux_001.json"]) = connect_vectors()
    return out


def render(obj):
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def owned_on_disk(base):
    names = set()
    for pattern in OWNED:
        names.update(p.relative_to(base).as_posix() for p in base.glob(pattern))
    return sorted(names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO_ROOT / "shared-vectors/rvn1"))
    ap.add_argument("--check", action="store_true", help="exit 1 if any file on disk differs")
    args = ap.parse_args()
    base = pathlib.Path(args.out)
    planned = build()
    if args.check:
        drift = [name for name, obj in planned.items()
                 if not (base / name).is_file() or (base / name).read_text(encoding="utf-8") != render(obj)]
        extra = [name for name in owned_on_disk(base) if name not in planned] if base.is_dir() else []
        for name in drift:
            print("DRIFT", base / name)
        for name in extra:
            print("NOT GENERATED", base / name)
        if drift or extra:
            sys.exit(1)
        print(f"WSS vectors OK ({len(planned)} files)")
        return
    for name, obj in planned.items():
        (base / name).parent.mkdir(parents=True, exist_ok=True)
        (base / name).write_text(render(obj), encoding="utf-8")
    print("wrote", ", ".join(str(base / name) for name in planned))


if __name__ == "__main__":
    main()
