"""RAVEN LAN Beacon V1 (RAVEN_LAN_BEACON_V1.md, draft): keys and datagrams.

An independent reference for the Rust code (``raven_core::lan_beacon``) and
the vectors in ``shared-vectors/rvn1/lan_beacon`` (which Rust writes and
:mod:`tests.test_lan_beacon` recomputes from their inputs):

- the Ed25519 point checks and the Edwards-to-Montgomery map
  ``u = (1 + y) / (1 - y) mod p`` are written out by hand here;
- X25519 (the scalar ``SHA-512(seed)[:32]`` through ``X25519PrivateKey``),
  HKDF-SHA256 and HMAC-SHA256 come from ``cryptography``.

Pure and deterministic: no socket, no clock, no randomness. Every nonce,
padding slot, slot position and tail is an argument (a real sender draws
them fresh for every datagram).

The v1 amendment of Phase 6b (made before the beacon's production flip): a
sender puts 0..=31 random bytes after a query's 160 and 0..=15 after an
answer's 48 (:func:`with_tail`); a receiver reads the first 160 (48) bytes
of any datagram of 160..=191 (48..=63) bytes and ignores the rest
(:func:`kind_of`).
"""

import hashlib
import ipaddress
from typing import NamedTuple, Optional

from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

GROUP_V4 = "239.255.74.20"
GROUP_V6 = "ff02::8000:7420"
BEACON_PORT = 7420
SLOTS = 8
SLOT_LEN = 18
NONCE_LEN = 16
QUERY_LEN = NONCE_LEN + SLOTS * SLOT_LEN  # 160
ANSWER_LEN = 48
QUERY_TAIL_MAX = 31  # random bytes a sender may put after a query
ANSWER_TAIL_MAX = 15  # and after an answer
QUERY_MAX_LEN = QUERY_LEN + QUERY_TAIL_MAX  # 191
ANSWER_MAX_LEN = ANSWER_LEN + ANSWER_TAIL_MAX  # 63
EPOCH_SECS = 600
U64_MAX = 2**64 - 1

R2_PAIR_SALT = b"rvn1/r2-pair/v1"
MEDIUM_BLE = 0x01  # Bluetooth LE nearby (RAVEN_NEARBY_LINK_V1, raven_protocol.nearby)
MEDIUM_LAN = 0x02

# edwards25519
P = 2**255 - 19
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1)


class BadKey(ValueError):
    """A contact key that gets no beacon keys (spec §2.1)."""


class NonContributory(ValueError):
    """X25519 gave the all-zero shared secret (spec §2.1)."""


class PairKeys(NamedTuple):
    """One contact's beacon keys, seen from the owner of the book."""

    peer: bytes  # the contact's Ed25519 identity key
    q_out: bytes  # K_q(me -> peer): this node's queries naming the contact
    q_in: bytes  # K_q(peer -> me): the contact's queries naming this node
    r_out: bytes  # K_r(me -> peer): this node's answers to the contact
    r_in: bytes  # K_r(peer -> me): the contact's answers to this node


def ed25519_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def x25519_scalar(seed: bytes) -> bytes:
    """A's Ed25519 secret scalar bytes, SHA-512(seed)[0..32] (X25519 clamps them)."""
    return hashlib.sha512(seed).digest()[:32]


def _decompress(enc: bytes) -> tuple:
    """(x, y) of a 32-byte Ed25519 point encoding, read leniently as
    ed25519-dalek does (y taken mod p, the sign bit applied even to x = 0);
    :func:`_compress` then shows whether the encoding was canonical."""
    if len(enc) != 32:
        raise BadKey("not 32 bytes")
    n = int.from_bytes(enc, "little")
    sign, y = n >> 255, (n & ((1 << 255) - 1)) % P
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        raise BadKey("not a point")
    if x & 1 != sign:
        x = (P - x) % P
    return x, y


def _compress(point: tuple) -> bytes:
    x, y = point
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _add(p1: tuple, p2: tuple) -> tuple:
    """Twisted Edwards addition (a = -1); complete on edwards25519."""
    (x1, y1), (x2, y2) = p1, p2
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, P - 2, P) % P
    return x3, y3


def _small_order(point: tuple) -> bool:
    """[8]P is the identity: one of the 8 points of order 1, 2, 4 or 8."""
    q = point
    for _ in range(3):
        q = _add(q, q)
    return q == IDENTITY


def check_contact_key(own_public: bytes, peer: bytes) -> tuple:
    """The point of a usable contact key, else BadKey (spec §2.1): it decodes,
    is canonically encoded (re-compressing gives the same bytes), is not of
    small order and is not the own key."""
    peer = bytes(peer)
    point = _decompress(peer)
    if _compress(point) != peer:
        raise BadKey("not canonically encoded")
    if _small_order(point):
        raise BadKey("small order")
    if peer == bytes(own_public):
        raise BadKey("the own key")
    return point


def _u_of(point: tuple) -> bytes:
    """The Montgomery u-coordinate (1 + y) / (1 - y) mod p of an Edwards point."""
    _, y = point
    return ((1 + y) * pow(1 - y, P - 2, P) % P).to_bytes(32, "little")


def montgomery_u(public: bytes) -> bytes:
    """The Montgomery u-coordinate of an Ed25519 public key."""
    return _u_of(_decompress(bytes(public)))


def x25519(scalar: bytes, u: bytes) -> bytes:
    """X25519(scalar, u); the all-zero result when OpenSSL refuses it."""
    try:
        return X25519PrivateKey.from_private_bytes(scalar).exchange(
            X25519PublicKey.from_public_bytes(u)
        )
    except ValueError:  # OpenSSL refuses to return an all-zero secret
        return bytes(32)


def root_from(scalar: bytes, peer_u: bytes, me: bytes, peer: bytes) -> bytes:
    """K_root after the key checks: Z = X25519(scalar, peer_u), the
    contributory check, HKDF-SHA256(salt 'rvn1/r2-pair/v1', Z,
    info 'root' || lo || hi)."""
    z = x25519(scalar, peer_u)
    if z == bytes(32):
        raise NonContributory("all-zero shared secret")
    lo, hi = sorted([bytes(me), bytes(peer)])
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=R2_PAIR_SALT, info=b"root" + lo + hi
    ).derive(z)


def pair_root(own_seed: bytes, peer: bytes) -> bytes:
    """The R2 pairwise root of own_seed's identity with the contact key peer."""
    me = ed25519_public(own_seed)
    point = check_contact_key(me, peer)
    return root_from(x25519_scalar(own_seed), _u_of(point), me, bytes(peer))


def medium_key(root: bytes, medium: int) -> bytes:
    """HKDF-Expand-SHA256(PRK root, info 'medium' || medium, 32)."""
    return HKDFExpand(
        algorithm=hashes.SHA256(), length=32, info=b"medium" + bytes([medium])
    ).derive(root)


def _hmac(key: bytes, *parts: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    for part in parts:
        mac.update(part)
    return mac.finalize()


def pair_keys(own_seed: bytes, peer: bytes) -> PairKeys:
    """The beacon keys of own_seed's identity for the contact key peer."""
    peer = bytes(peer)
    lan = medium_key(pair_root(own_seed, peer), MEDIUM_LAN)
    me = ed25519_public(own_seed)
    return PairKeys(
        peer=peer,
        q_out=_hmac(lan, b"query", me, peer),
        q_in=_hmac(lan, b"query", peer, me),
        r_out=_hmac(lan, b"reply", me, peer),
        r_in=_hmac(lan, b"reply", peer, me),
    )


def epoch_at(unix_seconds: int) -> int:
    return unix_seconds // EPOCH_SECS


def epoch_key(query_key: bytes, epoch: int) -> bytes:
    """K_q,e = HMAC(K_q, 'epoch' || u64 big-endian e)."""
    return _hmac(query_key, b"epoch", epoch.to_bytes(8, "big"))


def ip16(ip) -> bytes:
    """IPv4 as ::ffff:a.b.c.d, IPv6 as its 16 bytes (a zone is never part)."""
    addr = ip if not isinstance(ip, str) else ipaddress.ip_address(ip)
    if addr.version == 4:
        return bytes(10) + b"\xff\xff" + addr.packed
    return addr.packed


def query_tag(query_key: bytes, epoch: int, nonce: bytes, src) -> bytes:
    """A query slot's h: HMAC(K_q,e, nonce || ip16(src))."""
    return _hmac(epoch_key(query_key, epoch), nonce, ip16(src))


def build_query(nonce, positions, padding, epoch, src, port, targets) -> bytes:
    """A query (160 bytes, before :func:`with_tail`): targets[i] (PairKeys) in
    slot positions[i] and the padding slots in the other slots, in slot
    order."""
    if len(nonce) != NONCE_LEN or len(positions) != len(targets):
        raise ValueError("one position per target and a 16-byte nonce")
    if len(targets) + len(padding) != SLOTS or len(set(positions)) != len(positions):
        raise ValueError("distinct positions and one padding per other slot")
    slots = [None] * SLOTS
    for keys, pos in zip(targets, positions):
        h = query_tag(keys.q_out, epoch, nonce, src)
        port_x = bytes(a ^ b for a, b in zip(port.to_bytes(2, "big"), h[16:18]))
        slots[pos] = h[:16] + port_x
    free = [pos for pos in range(SLOTS) if slots[pos] is None]
    for pos, pad in zip(free, padding):
        if len(pad) != SLOT_LEN:
            raise ValueError("a padding slot is 18 bytes")
        slots[pos] = bytes(pad)
    return bytes(nonce) + b"".join(slots)


def kind_of(length: int) -> Optional[str]:
    """'query' for 160..=191 bytes, 'answer' for 48..=63, None (dropped)
    for any other length."""
    if QUERY_LEN <= length <= QUERY_MAX_LEN:
        return "query"
    if ANSWER_LEN <= length <= ANSWER_MAX_LEN:
        return "answer"
    return None


def with_tail(datagram: bytes, tail: bytes) -> bytes:
    """A query (160 bytes) or an answer (48) as a sender puts it on the wire:
    with tail after it, at most 31 (15) bytes, which receivers ignore. A real
    sender draws the tail's length uniformly and its bytes at random."""
    most = {QUERY_LEN: QUERY_TAIL_MAX, ANSWER_LEN: ANSWER_TAIL_MAX}.get(len(datagram))
    if most is None:
        raise ValueError("a query or an answer of its exact length")
    if len(tail) > most:
        raise ValueError("a tail of at most 31 bytes (a query) or 15 (an answer)")
    return bytes(datagram) + bytes(tail)


def match_query(q: bytes, src, now_epoch: int, book) -> list:
    """(index in book, the querier's port) for every contact of book the query
    names, in book order, at most one match each. A query of 160..=191 bytes
    is read as its first 160 (the tail is ignored); [] for another length."""
    if kind_of(len(q)) != "query":
        return []
    q = q[:QUERY_LEN]
    nonce = q[:NONCE_LEN]
    slots = [q[NONCE_LEN + i * SLOT_LEN : NONCE_LEN + (i + 1) * SLOT_LEN] for i in range(SLOTS)]
    found = []
    for index, keys in enumerate(book):
        port = None
        for epoch in range(max(now_epoch - 1, 0), min(now_epoch + 1, U64_MAX) + 1):
            h = query_tag(keys.q_in, epoch, nonce, src)
            for slot in slots:
                if constant_time.bytes_eq(slot[:16], h[:16]) and port is None:
                    port = int.from_bytes(bytes([slot[16] ^ h[16], slot[17] ^ h[17]]), "big")
        if port is not None:
            found.append((index, port))
    return found


def answer_tag(reply_key: bytes, q_nonce: bytes, r_nonce: bytes, src, dst) -> bytes:
    """An answer's h: HMAC(K_r, q_nonce || r_nonce || ip16(src) || ip16(dst))."""
    return _hmac(reply_key, q_nonce, r_nonce, ip16(src), ip16(dst))


def build_answer(r_nonce, keys: PairKeys, q_nonce, src, dst, port: int) -> bytes:
    """An answer (48 bytes, before :func:`with_tail`) to a query of keys.peer:
    src is this node's bound address, dst the query's source, port this
    node's listener port."""
    if len(r_nonce) != NONCE_LEN:
        raise ValueError("a 16-byte r_nonce")
    h = answer_tag(keys.r_out, q_nonce, r_nonce, src, dst)
    port_x = bytes(a ^ b for a, b in zip(port.to_bytes(2, "big"), h[:2]))
    return bytes(r_nonce) + port_x + h[2:]


def open_answer(a: bytes, keys: PairKeys, q_nonce, src, dst) -> Optional[int]:
    """The port in an answer of keys.peer to this node's query q_nonce, or None
    (another length, a tag that does not verify, or port 0). An answer of
    48..=63 bytes is read as its first 48 (the tail is ignored)."""
    if kind_of(len(a)) != "answer":
        return None
    r_nonce, rest = a[:NONCE_LEN], a[NONCE_LEN:ANSWER_LEN]
    h = answer_tag(keys.r_in, q_nonce, r_nonce, src, dst)
    if not constant_time.bytes_eq(rest[2:], h[2:]):
        return None
    port = int.from_bytes(bytes([rest[0] ^ h[0], rest[1] ^ h[1]]), "big")
    return port or None
