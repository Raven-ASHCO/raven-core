"""RAVEN Link Padding V1 (RAVEN_LINK_PADDING_V1.md, draft): PAD1 frames, the
receiver's rules, one side's state on a link, and the two places PAD1 is
negotiated (RIH1 hello caps bit 9, RLX1 LINK_CAPS bit 9).

An independent reference for the Rust code (``raven_core::link_padding``) and
the vectors in ``shared-vectors/rvn1/link`` (which Rust writes and
:mod:`tests.test_link_padding` checks against this module).

Pure and deterministic: the padding is zeros, nothing is random.
"""

from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"RPD1"
VERSION = 0x01
HEADER_LEN = 8
BUCKETS = (512, 4_096, 16_384, 65_519)  # the last is MAX_TRANSPORT_PLAINTEXT
MAX_INNER = BUCKETS[-1] - HEADER_LEN  # 65,511

# RIH1 hello caps: bits 0-7 node capabilities, bits 8-31 link features.
CAP_INTERNET = 1 << 1
CAP_LINK_RRH1 = 1 << 8
CAP_LINK_PAD1 = 1 << 9


class Pad1Error(ValueError):
    """A refused frame (spec §6); ``code`` is the name the vectors use."""

    def __init__(self, code: str):
        super().__init__(f"PAD1 {code}")
        self.code = code


def bucket_for(inner_len: int) -> Optional[int]:
    """The frame length of an ``inner_len``-byte inner frame, or None."""
    if inner_len < 1:
        return None
    return next((t for t in BUCKETS if t >= HEADER_LEN + inner_len), None)


def wrap(inner: bytes) -> bytes:
    """``inner`` padded to the smallest bucket that holds it (spec §2, §5)."""
    if inner.startswith(MAGIC):
        raise Pad1Error("NESTED")
    total = bucket_for(len(inner))
    if total is None:
        raise Pad1Error("BAD_LENGTH")
    head = MAGIC + bytes([VERSION, 0]) + len(inner).to_bytes(2, "big")
    return head + inner + bytes(total - HEADER_LEN - len(inner))


def unwrap(frame: bytes) -> bytes:
    """The inner frame, checked in the order of spec §6."""
    if not frame.startswith(MAGIC):
        raise Pad1Error("BAD_MAGIC")
    if len(frame) not in BUCKETS:
        raise Pad1Error("BAD_BUCKET")
    if frame[4] != VERSION:
        raise Pad1Error("BAD_VERSION")
    if frame[5] != 0:
        raise Pad1Error("BAD_RESERVED")
    inner_len = int.from_bytes(frame[6:8], "big")
    if inner_len == 0 or inner_len > len(frame) - HEADER_LEN:
        raise Pad1Error("BAD_LENGTH")
    inner = frame[HEADER_LEN : HEADER_LEN + inner_len]
    if any(frame[HEADER_LEN + inner_len :]):
        raise Pad1Error("NONZERO_PADDING")
    if inner.startswith(MAGIC):
        raise Pad1Error("NESTED")
    return inner


class PadState:
    """One side of one link (spec §4, §6)."""

    def __init__(self, reads: bool, negotiated: bool):
        self.reads = reads  # this side offered PAD1 and reads RPD1 frames
        self.negotiated = negotiated  # this side wraps what it sends
        self.peer_started = False  # the peer's first RPD1 frame arrived

    @classmethod
    def off(cls):
        """No PAD1: frames pass untouched both ways."""
        return cls(False, False)

    @classmethod
    def agreed(cls, both: bool):
        """Internet direct, p2p, nearby, and the LAN listener."""
        return cls(both, both)

    @classmethod
    def lan_dialer(cls, offered: bool):
        """Reads RPD1 at once, wraps after the listener's first RPD1 frame."""
        return cls(offered, False)

    def on_send(self, frame: bytes) -> bytes:
        return wrap(frame) if self.negotiated else frame

    def on_recv(self, frame: bytes) -> bytes:
        if not self.reads:
            return frame
        if frame.startswith(MAGIC):
            inner = unwrap(frame)
            self.peer_started = True
            self.negotiated = True
            return inner
        if self.peer_started:
            raise Pad1Error("UNPADDED")
        return frame


# ── Negotiation: RLX1 LINK_CAPS (RAVEN_ROUTE_HINTS_V1 §3.2) ─────────────────

RLX1_MAGIC = b"RLX1"
RLX1_VERSION = 1
RLX1_MAX_LEN = 64
EXT_LINK_CAPS = 0x01


def rlx1_payload(caps: int) -> bytes:
    """The dialer's message-3 payload: empty for caps 0."""
    if caps == 0:
        return b""
    return RLX1_MAGIC + bytes([RLX1_VERSION, EXT_LINK_CAPS, 4]) + caps.to_bytes(4, "big")


def rlx1_caps(payload: bytes) -> int:
    """The LINK_CAPS a listener reads; 0 for an empty or malformed payload."""
    if not 5 <= len(payload) <= RLX1_MAX_LEN or payload[:4] != RLX1_MAGIC or payload[4] != RLX1_VERSION:
        return 0
    seen, caps, rest = set(), 0, payload[5:]
    while rest:
        if len(rest) < 2 or len(rest) < 2 + rest[1]:
            return 0
        kind, value, rest = rest[0], rest[2 : 2 + rest[1]], rest[2 + rest[1] :]
        if kind in seen:
            return 0
        seen.add(kind)
        if kind == EXT_LINK_CAPS:
            if len(value) != 4:
                return 0
            caps = int.from_bytes(value, "big")
    return caps


# ── Negotiation: the RIH1 hello (RAVEN_TRANSPORT_INTERFACE_V1 §3) ────────────

HELLO_MAGIC = b"RIH1"
HELLO_SIG_DOMAIN = b"rvn1/internet-hello/v1"
NOISE_STATIC_SALT = b"rvn1/lan-noise/v1"
NOISE_STATIC_INFO = b"static-x25519"


def ed25519_public(seed: bytes) -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def noise_static_public(seed: bytes) -> bytes:
    """The Noise static public key derived from an identity seed."""
    okm = HKDF(algorithm=hashes.SHA256(), length=32, salt=NOISE_STATIC_SALT, info=NOISE_STATIC_INFO).derive(seed)
    key = X25519PrivateKey.from_private_bytes(okm).public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def hello_signing_bytes(role: int, caps: int, handshake_hash: bytes, noise_static: bytes, ed_pub: bytes) -> bytes:
    return HELLO_SIG_DOMAIN + bytes([role]) + caps.to_bytes(4, "big") + handshake_hash + noise_static + ed_pub


def pack_hello(seed: bytes, role: int, caps: int, handshake_hash: bytes) -> bytes:
    """``RIH1 || caps || ed_pub || sig`` of the identity ``seed``."""
    ed_pub = ed25519_public(seed)
    msg = hello_signing_bytes(role, caps, handshake_hash, noise_static_public(seed), ed_pub)
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    return HELLO_MAGIC + caps.to_bytes(4, "big") + ed_pub + sig
