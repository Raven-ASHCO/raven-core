# protocol/reference/raven_protocol/portmap.py
"""Raven Port Mapping Profile V1 (protocol/RAVEN_PORT_MAPPING_V1.md), standard library only.

The NAT-PMP (RFC 6886) and PCP (RFC 6887) subset Raven's client uses with the OS default
router: the requests it sends, the strict reply decoder, the server-epoch rule (RFC 6887
section 8.5) and the MAP nonce. The reply encoders are the router's side, for vectors and
tests only: Raven never sends a reply. Mirrors node/crates/raven-core/src/portmap.rs.
"""
import hashlib
import ipaddress
import struct

PCP_PORT = 5351
MAX_PCP = 1100
PCP_VERSION = 2
NATPMP_VERSION = 0
PCP_OP_ANNOUNCE = 0
PCP_OP_MAP = 1
NATPMP_OP_EXTERNAL_ADDR = 0
NATPMP_OP_MAP_UDP = 1
NATPMP_OP_MAP_TCP = 2
TCP = 6
UDP = 17
REQUESTED_LIFETIME_S = 7200
# An IPv6 pinhole asks a shorter lease (RAVEN_PORT_MAPPING_V1 §6).
PINHOLE_LIFETIME_S = 3600
NONCE_KEY_DOMAIN = b"raven/pcp-nonce-key/v1"
PCP_HEADER = 24
MAP_DATA = 36
RESPONSE_BIT = 0x80

# PCP result codes (RFC 6887 section 7.4) and NAT-PMP result codes (RFC 6886 section 3.5).
PCP_SUCCESS = 0
PCP_UNSUPP_VERSION = 1
PCP_NOT_AUTHORIZED = 2
PCP_NO_RESOURCES = 8
PCP_CANNOT_PROVIDE_EXTERNAL = 11
PCP_ADDRESS_MISMATCH = 12
NATPMP_SUCCESS = 0
NATPMP_UNSUPP_VERSION = 1


class ReplyError(ValueError):
    """A reply the client ignores. `code` is the reason, the same string the Rust codec gives."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def v6_form(ip):
    """The 16-byte address field: IPv6 as is, IPv4 as ::ffff:a.b.c.d."""
    a = ipaddress.ip_address(ip)
    return bytes(10) + b"\xff\xff" + a.packed if a.version == 4 else a.packed


def from_v6_form(b16):
    """Text of a 16-byte address field: an IPv4-mapped address reads as the IPv4 address."""
    a = ipaddress.IPv6Address(bytes(b16))
    return str(a.ipv4_mapped) if a.ipv4_mapped is not None else str(a)


def unspecified_external(client):
    """The suggested external address of a MAP request: ::ffff:0.0.0.0 for an IPv4 client, :: for IPv6."""
    return v6_form("0.0.0.0") if ipaddress.ip_address(client).version == 4 else bytes(16)


def pcp_request(op, lifetime, client, mapping=None):
    """A PCP request (R=0, no options): the 24-byte header, then the 36-byte MAP data if `mapping`
    (nonce, proto, internal_port, suggested_port, suggested_ip as 16 bytes) is given."""
    b = bytes([PCP_VERSION, op & 0x7F, 0, 0]) + struct.pack(">I", lifetime) + v6_form(client)
    if mapping is not None:
        b += (mapping["nonce"] + bytes([mapping["proto"], 0, 0, 0])
              + struct.pack(">HH", mapping["internal_port"], mapping["suggested_port"])
              + mapping["suggested_ip"])
    return b


def natpmp_request(op, internal_port=0, suggested_port=0, lifetime=0):
    """A NAT-PMP request: 2 bytes for the external address (op 0), else 12 bytes."""
    if op == NATPMP_OP_EXTERNAL_ADDR:
        return bytes([NATPMP_VERSION, op])
    return bytes([NATPMP_VERSION, op, 0, 0]) + struct.pack(">HHI", internal_port, suggested_port, lifetime)


def decode_reply(b, sent_pcp_op=None, sent_natpmp_op=None):
    """Strict decode of a reply from the gateway, given the requests outstanding. Returns a dict
    (kind pcp, natpmp_external_addr, natpmp_map or natpmp_only); raises ReplyError otherwise."""
    b = bytes(b)
    if not b:
        raise ReplyError("length")
    if b[0] == PCP_VERSION:
        if sent_pcp_op is None:
            raise ReplyError("unexpected")
        return _decode_pcp(b, sent_pcp_op)
    if b[0] == NATPMP_VERSION:
        if sent_pcp_op is not None and _natpmp_only(b, sent_pcp_op):
            return {"kind": "natpmp_only"}
        if sent_natpmp_op is None:
            raise ReplyError("unexpected")
        return _decode_natpmp(b, sent_natpmp_op)
    raise ReplyError("version")


def _natpmp_only(b, sent_pcp_op):
    # A NAT-PMP-only router answers a PCP request "unsupported version" (RFC 6887 section 9,
    # RFC 6886 section 3.5): version 0, result 1, opcode 0 (the RFC 6886 figure) or 128 + the
    # request's opcode (what miniupnpd sends), 8 bytes (12 or 16 accepted).
    return (len(b) in (8, 12, 16) and b[1] in (0, RESPONSE_BIT | sent_pcp_op)
            and struct.unpack(">H", b[2:4])[0] == NATPMP_UNSUPP_VERSION)


def _decode_pcp(b, sent_op):
    if len(b) < PCP_HEADER or len(b) > MAX_PCP or len(b) % 4:
        raise ReplyError("length")
    if not b[1] & RESPONSE_BIT:
        raise ReplyError("not_response")
    opcode = b[1] & 0x7F
    if opcode != sent_op or opcode > PCP_OP_MAP:
        raise ReplyError("opcode")
    result = b[3]
    lifetime, epoch = struct.unpack(">II", b[4:12])
    at = PCP_HEADER
    mapping = None
    if opcode == PCP_OP_MAP:
        if len(b) >= PCP_HEADER + MAP_DATA:
            d = b[at:at + MAP_DATA]
            internal_port, external_port = struct.unpack(">HH", d[16:20])
            mapping = {"nonce_hex": d[:12].hex(), "protocol": d[12], "internal_port": internal_port,
                       "external_port": external_port, "external_ip": from_v6_form(d[20:36])}
            at += MAP_DATA
        elif result == PCP_SUCCESS:
            raise ReplyError("length")
    _check_options(b[at:])
    return {"kind": "pcp", "opcode": opcode, "result": result, "lifetime": lifetime, "epoch": epoch,
            "map": mapping}


def _check_options(rest):
    # Each option: code u8, reserved u8, length u16, data padded to 4 bytes. An optional option
    # (code >= 128) is skipped; Raven sends none, so any mandatory one (code < 128) is unknown.
    while rest:
        if len(rest) < 4:
            raise ReplyError("malformed_option")
        code = rest[0]
        padded = (struct.unpack(">H", rest[2:4])[0] + 3) & ~3
        if 4 + padded > len(rest):
            raise ReplyError("malformed_option")
        if code < 128:
            raise ReplyError("mandatory_option")
        rest = rest[4 + padded:]


def _decode_natpmp(b, sent_op):
    if len(b) < 2:
        raise ReplyError("length")
    if not b[1] & RESPONSE_BIT:
        raise ReplyError("not_response")
    if sent_op > NATPMP_OP_MAP_TCP or b[1] != RESPONSE_BIT | sent_op:
        raise ReplyError("opcode")
    if len(b) != (12 if sent_op == NATPMP_OP_EXTERNAL_ADDR else 16):
        raise ReplyError("length")
    result, epoch = struct.unpack(">HI", b[2:8])
    if sent_op == NATPMP_OP_EXTERNAL_ADDR:
        return {"kind": "natpmp_external_addr", "result": result, "epoch": epoch,
                "external_ip": str(ipaddress.IPv4Address(b[8:12]))}
    internal_port, external_port, lifetime = struct.unpack(">HHI", b[8:16])
    return {"kind": "natpmp_map", "protocol": UDP if sent_op == NATPMP_OP_MAP_UDP else TCP,
            "result": result, "epoch": epoch, "internal_port": internal_port,
            "external_port": external_port, "lifetime": lifetime}


def epoch_lost(prev, curr):
    """RFC 6887 section 8.5 (also used for NAT-PMP): has the server lost its state? `prev` is the
    previous (server epoch, client seconds) or None for the first answer; `curr` the new one."""
    if prev is None:
        return False
    (prev_server, prev_client), (curr_server, curr_client) = prev, curr
    if curr_server + 1 < prev_server:
        return True
    c = max(curr_client - prev_client, 0)
    s = max(curr_server - prev_server, 0)
    return c + 2 < s - s // 16 or s + 2 < c - c // 16


def nonce_key(seed):
    """SHA-256(NONCE_KEY_DOMAIN || raven seed)."""
    return hashlib.sha256(NONCE_KEY_DOMAIN + bytes(seed)).digest()


def pcp_nonce(key, gateway_ip, internal_ip, proto, port):
    """SHA-256(key || gateway IP (16 bytes, IPv4-mapped) || internal IP (16 bytes) || protocol u8
    || be16 port)[0..12]: the router asked is part of it, so routers of other networks see other nonces."""
    return hashlib.sha256(bytes(key) + v6_form(gateway_ip) + v6_form(internal_ip) + bytes([proto])
                          + struct.pack(">H", port)).digest()[:12]


# The router's side (vectors and tests only).

def pcp_reply(op, result, lifetime, epoch, data=b"", options=b""):
    """A PCP response: version 2, R=1, the 24-byte header, then opcode data and options."""
    return (bytes([PCP_VERSION, RESPONSE_BIT | op, 0, result]) + struct.pack(">II", lifetime, epoch)
            + bytes(12) + bytes(data) + bytes(options))


def map_data(nonce, proto, internal_port, external_port, external_ip):
    """The 36-byte MAP opcode data; `external_ip` is an address text."""
    return (bytes(nonce) + bytes([proto, 0, 0, 0]) + struct.pack(">HH", internal_port, external_port)
            + v6_form(external_ip))


def natpmp_external_reply(result, epoch, external_ip):
    return bytes([NATPMP_VERSION, RESPONSE_BIT]) + struct.pack(">HI", result, epoch) \
        + ipaddress.IPv4Address(external_ip).packed


def natpmp_map_reply(op, result, epoch, internal_port, external_port, lifetime):
    return bytes([NATPMP_VERSION, RESPONSE_BIT | op]) + struct.pack(
        ">HIHHI", result, epoch, internal_port, external_port, lifetime)


def natpmp_unsupported_version(op_byte, epoch):
    """A NAT-PMP router's 8-byte answer to a request of another version."""
    return bytes([NATPMP_VERSION, op_byte]) + struct.pack(">HI", NATPMP_UNSUPP_VERSION, epoch)
