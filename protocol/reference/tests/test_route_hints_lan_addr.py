"""RAVEN Route Hints V1 LAN_ADDR entry (RAVEN_ROUTE_HINTS_V1.md §16, draft):
the Python reference re-reads the LAN_ADDR frames (written by Rust under
RAVEN_REGEN_RRH1_VECTORS=1) with the decode rules of §16.1."""

import ipaddress
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
VEC = REPO / "shared-vectors/rvn1/route_hints"

T_LAN_ADDR = 0x09
MAX_LAN_ADDR = 2


def load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def entries(frame):
    """(type, value) of a well-formed RRH1 frame, in frame order."""
    assert frame[:5] == b"RRH1\x01"
    out, rest = [], frame[17:]
    while rest:
        kind, length = rest[0], int.from_bytes(rest[1:3], "big")
        value = rest[3 : 3 + length]
        assert len(value) == length
        out.append((kind, value))
        rest = rest[3 + length :]
    return out


def canonical(text):
    """The `ip:port` text as written back (IPv6 in RFC 5952 form in
    brackets), or None when it does not parse."""
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or str(int(port)) != port or not 0 < int(port) < 65536:
        return None, None
    if host.startswith("[") and host.endswith("]"):
        try:
            ip = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None, None
        if ip.ipv4_mapped is not None:
            return None, None
        return f"[{ip.compressed}]:{port}", ip
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        return None, None
    return f"{ip}:{port}", ip


def local_network(ip):
    """Loopback, private or link-local IPv4; loopback or unique-local IPv6.
    Never IPv6 link-local (no zone travels)."""
    if ip.version == 4:
        return ip.is_loopback or ip.is_link_local or ip in ipaddress.ip_network("10.0.0.0/8") \
            or ip in ipaddress.ip_network("172.16.0.0/12") or ip in ipaddress.ip_network("192.168.0.0/16")
    return ip.is_loopback or ip in ipaddress.ip_network("fc00::/7")


def lan_addr(value):
    """§16.1: the address of one LAN_ADDR value, or None (dropped alone)."""
    if not 10 <= len(value) <= 48:
        return None
    try:
        text = value[1:].decode("ascii")
    except UnicodeDecodeError:
        return None
    written, ip = canonical(text)
    if written != text or ip is None or not local_network(ip):
        return None
    return text


def decode_lan_addrs(frame):
    kept, dropped = [], 0
    for kind, value in entries(frame):
        if kind != T_LAN_ADDR:
            continue
        addr = lan_addr(value)
        if addr is not None and len(kept) < MAX_LAN_ADDR and addr not in kept:
            kept.append(addr)
        else:
            dropped += 1
    return kept, dropped


def test_lan_addr_frame():
    v = load("rrh1_lan_addr_001.json")
    frame = bytes.fromhex(v["expected"]["frame_hex"])
    assert len(frame) == v["expected"]["frame_len"]
    es = entries(frame)
    assert [k for k, _ in es] == sorted(k for k, _ in es), "ascending type order"
    decoded = v["expected"]["decoded"]["lan_addrs"]
    values = [value for kind, value in es if kind == T_LAN_ADDR]
    assert [value.hex() for value in values] == [d["value_hex"] for d in decoded]
    assert all(value[0] == 0 for value in values), "no flag defined: sent as 0"
    assert decode_lan_addrs(frame) == ([d["addr"] for d in decoded], 0)
    # A receiver built before §16 skips 0x09: the Phase 2 frame's entries.
    older = [(k, val) for k, val in es if k != T_LAN_ADDR]
    phase2 = bytes.fromhex(v["expected"]["phase2_frame_hex"])
    assert older == entries(phase2)


def test_lan_addr_bad_entries_are_dropped_alone():
    v = load("negative/rrh1_lan_addr_bad_001.json")
    frame = bytes.fromhex(v["inputs"]["frame_hex"])
    kept, dropped = decode_lan_addrs(frame)
    assert kept == [e["addr"] for e in v["expected"]["lan_addrs"]]
    assert dropped == v["expected"]["dropped"] == 4
    assert v["expected"]["frame_kept"] is True
