# protocol/reference/raven_protocol/via.py
"""The via= address grammar (protocol/RAVEN_WSS_TRANSPORT_V1.md section 2), standard library only.

An independent implementation of raven-core's p2p_route::parse_via (the address of a relay, or
a direct address of a contact, in cards, the contact book, node policy and RRH1 address
entries), its ViaAddr helpers (is_wss, tcp_port, raw_sibling, wss_sibling) and relay_dial_forms
(section 2.3). Mirrors node/crates/raven-core/src/p2p_route.rs.

    via   = host "/tcp/" port [wss] "/p2p/" peer  /  host "/udp/" port "/quic-v1/p2p/" peer
    host  = "/ip4/" v4 / "/ip6/" v6 / ("/dns/" | "/dns4/" | "/dns6/") name
    wss   = "/tls/ws"  /  "/tls/sni/" name "/ws"        (/tls/sni/ only after an IP host)

Input /wss is stored as /tls/ws. Errors carry a code (ViaError.code); the vectors record it.
"""
import ipaddress

MAX_MULTIADDR_CHARS = 300
ED25519_PEER_ID_PREFIX = bytes([0x00, 0x24, 0x08, 0x01, 0x12, 0x20])
PEER_ID_CHARS = 52
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# The multiaddr names of WebSocket, TLS and their relatives: after a transport only the wss
# forms above are accepted.
WS_FAMILY = ("tls", "ws", "wss", "sni", "certhash", "x-parity-ws", "x-parity-wss", "http", "https",
             "http-path", "noise")

# Error codes: the parse step that refused the text.
NOT_MULTIADDR = "not_multiaddr"    # longer than 300 bytes, or a byte outside 0x21..0x7e
SYNTAX = "syntax"                  # no leading /, a missing or extra part, nothing like the grammar
HOST = "host"                      # not an IP of that family, not a plausible DNS name
NO_SINGLE_HOST = "no_single_host"  # unspecified, broadcast or multicast IP
PORT = "port"                      # not 1-65535 in plain decimal
TRANSPORT = "transport"            # neither tcp/PORT nor udp/PORT/quic-v1
WSS_SUFFIX = "wss_suffix"          # after /tcp/PORT, a WebSocket/TLS form other than the two above
QUIC_SUFFIX = "quic_suffix"        # a WebSocket/TLS form after /udp/PORT/quic-v1
CIRCUIT = "circuit"                # p2p-circuit anywhere
PEER_ID = "peer_id"                # not a canonical Ed25519 PeerId
TOO_LONG = "too_long"              # over 300 characters once /wss is written /tls/ws


class ViaError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def b58encode(data):
    zeros = len(data) - len(data.lstrip(b"\0"))
    n = int.from_bytes(data, "big")
    digits = ""
    while n:
        n, r = divmod(n, 58)
        digits = B58[r] + digits
    return "1" * zeros + digits


def b58decode(text):
    zeros = len(text) - len(text.lstrip("1"))
    n = 0
    for c in text[zeros:]:
        i = B58.find(c)
        if i < 0:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * zeros + body


def peer_id_from_ed25519_public(public):
    if len(public) != 32:
        raise ValueError("an Ed25519 public key has 32 bytes")
    return b58encode(ED25519_PEER_ID_PREFIX + public)


def normalize_peer_id(text):
    """The canonical text of an Ed25519 PeerId (12D3KooW..., 52 characters); ViaError otherwise."""
    t = text.strip()
    if len(t) != PEER_ID_CHARS or not t.startswith("12D3KooW"):
        raise ViaError(PEER_ID)
    raw = b58decode(t)
    if raw is None or len(raw) != len(ED25519_PEER_ID_PREFIX) + 32 \
            or raw[:len(ED25519_PEER_ID_PREFIX)] != ED25519_PEER_ID_PREFIX:
        raise ViaError(PEER_ID)
    if peer_id_from_ed25519_public(raw[len(ED25519_PEER_ID_PREFIX):]) != t:
        raise ViaError(PEER_ID)
    return t


def plausible_dns_name(name):
    """A name TLS can send as SNI (section 2.1, rustls ServerName's rule): at most 253 characters,
    one trailing dot allowed, labels of 1-63 letters, digits and '-', none starting or ending with
    '-', the last label not all digits (so never an IPv4 literal)."""
    labels = name[:-1] if name.endswith(".") else name
    if not labels or len(name) > 253:
        return False
    parts = labels.split(".")
    for label in parts:
        if not 0 < len(label) <= 63 or label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isascii() and (c.isalnum() or c == "-") for c in label):
            return False
    return not parts[-1].isdigit()


def sni_name_ok(name):
    """A plausible DNS name that is not an IPv4 literal (TLS never sends an IP as SNI)."""
    if not plausible_dns_name(name):
        return False
    try:
        ipaddress.IPv4Address(name)
    except ValueError:
        return True
    return False


def parse_host(kind, value):
    if kind == "ip4":
        try:
            ip = ipaddress.IPv4Address(value)
        except ValueError:
            raise ViaError(HOST) from None
        if ip.is_unspecified or ip.is_multicast or ip == ipaddress.IPv4Address("255.255.255.255"):
            raise ViaError(NO_SINGLE_HOST)
        return f"/ip4/{ip}"
    if kind == "ip6":
        if "%" in value:  # a scope id: not part of the grammar
            raise ViaError(HOST)
        try:
            ip = ipaddress.IPv6Address(value)
        except ValueError:
            raise ViaError(HOST) from None
        if ip.is_unspecified or ip.is_multicast:
            raise ViaError(NO_SINGLE_HOST)
        return f"/ip6/{ip.compressed}"
    if kind in ("dns", "dns4", "dns6") and plausible_dns_name(value):
        return f"/{kind}/{value.lower()}"
    raise ViaError(HOST)


def parse_port(text):
    if not text.isascii() or not text.isdigit() or str(int(text)) != text or not 0 < int(text) <= 65535:
        raise ViaError(PORT)
    return int(text)


def wss_suffix(rest, host_is_ip):
    """(canonical suffix, parts taken) of the optional WebSocket-over-TLS suffix after /tcp/PORT."""
    if rest[:1] == ["wss"]:
        return "/tls/ws", 1
    if rest[:2] == ["tls", "ws"]:
        return "/tls/ws", 2
    if len(rest) >= 4 and rest[0] == "tls" and rest[1] == "sni" and rest[3] == "ws" and host_is_ip \
            and sni_name_ok(rest[2]):
        return f"/tls/sni/{rest[2].lower()}/ws", 4
    if rest and rest[0] in WS_FAMILY:
        raise ViaError(WSS_SUFFIX)
    return "", 0


def parse_via(text):
    """The canonical text and the terminal PeerId of a via= address; ViaError otherwise."""
    t = text.strip()
    raw = t.encode("utf-8")
    if len(raw) > MAX_MULTIADDR_CHARS or not all(0x21 <= b <= 0x7E for b in raw):
        raise ViaError(NOT_MULTIADDR)
    if not t.startswith("/"):
        raise ViaError(SYNTAX)
    parts = t[1:].split("/")
    if len(parts) < 2:
        raise ViaError(SYNTAX)
    out = parse_host(parts[0], parts[1])
    if parts[2:3] == ["tcp"] and len(parts) > 3:
        out += f"/tcp/{parse_port(parts[3])}"
        i = 4
    elif parts[2:3] == ["udp"] and parts[4:5] == ["quic-v1"]:
        out += f"/udp/{parse_port(parts[3])}/quic-v1"
        i = 5
    else:
        raise ViaError(TRANSPORT)
    rest = parts[i:]
    if parts[2] == "tcp":
        suffix, took = wss_suffix(rest, parts[0] in ("ip4", "ip6"))
        out += suffix
        i += took
    elif rest and rest[0] in WS_FAMILY:
        raise ViaError(QUIC_SUFFIX)
    if parts[i:i + 1] == ["p2p"] and len(parts) == i + 2:
        peer = normalize_peer_id(parts[i + 1])
        out += f"/p2p/{peer}"
        if len(out) > MAX_MULTIADDR_CHARS:
            raise ViaError(TOO_LONG)
        return out, peer
    if "p2p-circuit" in parts:
        raise ViaError(CIRCUIT)
    raise ViaError(SYNTAX)


def _parts(canonical):
    return canonical.split("/")[1:]


def is_wss(canonical):
    p = _parts(canonical)
    return p[2:3] == ["tcp"] and p[4:5] == ["tls"]


def tcp_port(canonical):
    p = _parts(canonical)
    return int(p[3]) if p[2:3] == ["tcp"] else None


def peer_of(canonical):
    return _parts(canonical)[-1]


def raw_sibling(canonical):
    """The raw libp2p TCP form of a WSS address (section 2.3 (a)); None for any other."""
    if not is_wss(canonical):
        return None
    p = _parts(canonical)
    return f"/{p[0]}/{p[1]}/tcp/{p[3]}/p2p/{peer_of(canonical)}"


def wss_sibling(canonical):
    """The WSS form of a raw TCP 443 address (section 2.3 (b)); None for any other."""
    if is_wss(canonical) or tcp_port(canonical) != 443:
        return None
    p = _parts(canonical)
    return f"/{p[0]}/{p[1]}/tcp/443/tls/ws/p2p/{peer_of(canonical)}"


def relay_dial_forms(canonical, wss_ok, prefer_wss):
    """The forms a dialer tries for one relay address, best first (section 2.3)."""
    if is_wss(canonical):
        raw, wss = raw_sibling(canonical), canonical
    elif tcp_port(canonical) == 443:
        raw, wss = canonical, wss_sibling(canonical)
    else:
        return [canonical]
    if not wss_ok:
        return [raw]
    return [wss, raw] if prefer_wss else [raw, wss]
