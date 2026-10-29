"""RAVEN Transparency Log V1 (RAVEN_TRANSPARENCY_LOG_V1.md, draft): log
entries (§2), RFC 6962 hashing (§3), signed tree heads (§4), snapshots (§5)
and their checks and prefix consistency (§6).

An independent reference for the Rust code (``raven_core::tlog``) and the
``rtl1_*`` vectors in ``shared-vectors/rvn1/update`` (which Rust writes and
:mod:`tests.test_tlog` checks against this module, computing every root on
its own and building every signed tree head and snapshot again byte for
byte). Key sets and signature blocks are :mod:`raven_protocol.advisory`'s.

Pure: no clock, no randomness.
"""

import hashlib
from typing import List, NamedTuple, Sequence, Tuple

from . import advisory as ad

MAGIC = b"RTL1"
VERSION = 0x01
KIND_STH = 0x01
KIND_SNAPSHOT = 0x02
ENTRY_LEN = 41
STH_SIGNED_LEN = 88
MAX_STH_LEN = STH_SIGNED_LEN + 1 + ad.SIG_ENTRY_LEN * ad.KEYSET_MAX_KEYS
SNAPSHOT_HEADER_LEN = 12
MAX_LOG_ENTRIES = 1_400
MAX_SNAPSHOT_LEN = SNAPSHOT_HEADER_LEN + ENTRY_LEN * MAX_LOG_ENTRIES + 2 + MAX_STH_LEN
STH_SIGNING_DOMAIN = b"rvn1/tlog/sth/v1\0"

MANIFEST, ADVISORY, KEY_SET = 1, 2, 3
TYPE_NAMES = {MANIFEST: "MANIFEST", ADVISORY: "ADVISORY", KEY_SET: "KEY_SET"}


class Rtl1Error(ValueError):
    """Refused tree head or snapshot bytes (§4, §5); ``code`` is the name
    the vectors use."""

    def __init__(self, code: str):
        super().__init__(f"RTL1 {code}")
        self.code = code


class LogCheckError(ValueError):
    """A decoded snapshot refused by :func:`check` (§6): a signature block
    code (:class:`raven_protocol.advisory.SigError`) or ``BAD_ROOT``."""

    def __init__(self, code: str):
        super().__init__(f"RTL1 CHECK {code}")
        self.code = code


class Entry(NamedTuple):
    type: int
    digest: bytes
    logged_at_ms: int

    def encode(self) -> bytes:
        return bytes([self.type]) + self.digest + self.logged_at_ms.to_bytes(8, "big")


def decode_entry(data: bytes) -> Entry:
    """Exactly one entry; type 0 is reserved, types 4..=255 are kept."""
    if len(data) != ENTRY_LEN:
        raise Rtl1Error("TRUNCATED")
    if data[0] == 0:
        raise Rtl1Error("BAD_ENTRY_TYPE")
    return Entry(data[0], bytes(data[1:33]), int.from_bytes(data[33:], "big"))


def leaf_hash(leaf: bytes) -> bytes:
    """RFC 6962 §2.1: SHA-256(0x00 || leaf)."""
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_of_leaf_hashes(hashes: Sequence[bytes]) -> bytes:
    """MTH over leaf hashes: split at the largest power of two below n."""
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashes[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(root_of_leaf_hashes(hashes[:k]), root_of_leaf_hashes(hashes[k:]))


def mth(entries: Sequence[Entry]) -> bytes:
    return root_of_leaf_hashes([leaf_hash(e.encode()) for e in entries])


def contains(entries: Sequence[Entry], type_: int, digest: bytes) -> bool:
    return any(e.type == type_ and e.digest == digest for e in entries)


def consistency(stored: Sequence[Entry], new: Sequence[Entry]) -> str:
    """§6: EXTENDS, SAME, OLDER or SPLIT."""
    common = min(len(stored), len(new))
    if list(stored[:common]) != list(new[:common]):
        return "SPLIT"
    if len(new) > len(stored):
        return "EXTENDS"
    return "SAME" if len(new) == len(stored) else "OLDER"


class Sth(NamedTuple):
    tree_size: int
    root_hash: bytes
    timestamp_ms: int
    key_set_digest: bytes
    sigs: List[Tuple[int, bytes]]
    data: bytes

    def signing_input(self) -> bytes:
        return STH_SIGNING_DOMAIN + self.data[:STH_SIGNED_LEN]

    def verify(self, key_set: ad.KeySet) -> None:
        """Raises :class:`raven_protocol.advisory.SigError`."""
        if self.key_set_digest != key_set.digest():
            raise ad.SigError("WRONG_KEY_SET")
        key_set.verify_sigs(self.signing_input(), self.sigs)


class Snapshot(NamedTuple):
    entries: List[Entry]
    sth: Sth


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.at = 0

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise Rtl1Error("TRUNCATED")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def header(self, kind: int) -> None:
        if self.take(4) != MAGIC:
            raise Rtl1Error("BAD_MAGIC")
        if self.uint(1) != VERSION:
            raise Rtl1Error("BAD_VERSION")
        if self.uint(1) != kind:
            raise Rtl1Error("BAD_KIND")
        if self.uint(2) != 0:
            raise Rtl1Error("BAD_RESERVED")


def decode_sth(data: bytes) -> Sth:
    """Strict decode in the order of §4; raises :class:`Rtl1Error`."""
    data = bytes(data)
    if len(data) > MAX_STH_LEN:
        raise Rtl1Error("TOO_LONG")
    r = _Reader(data)
    r.header(KIND_STH)
    tree_size = r.uint(8)
    if tree_size == 0:
        raise Rtl1Error("BAD_TREE_SIZE")
    root_hash = r.take(32)
    timestamp_ms = r.uint(8)
    key_set_digest = r.take(32)
    try:
        sigs = ad.decode_sig_block(data[STH_SIGNED_LEN:])
    except ad.SigError:
        raise Rtl1Error("BAD_SIG_BLOCK") from None
    return Sth(tree_size, root_hash, timestamp_ms, key_set_digest, sigs, data)


def decode_snapshot(data: bytes) -> Snapshot:
    """Strict decode in the order of §5; raises :class:`Rtl1Error`."""
    data = bytes(data)
    if len(data) > MAX_SNAPSHOT_LEN:
        raise Rtl1Error("TOO_LONG")
    r = _Reader(data)
    r.header(KIND_SNAPSHOT)
    count = r.uint(4)
    if count == 0:
        raise Rtl1Error("BAD_TREE_SIZE")
    if count > MAX_LOG_ENTRIES:
        raise Rtl1Error("TOO_MANY_ENTRIES")
    entries = [decode_entry(r.take(ENTRY_LEN)) for _ in range(count)]
    sth_bytes = r.take(r.uint(2))
    if r.at != len(data):
        raise Rtl1Error("TRAILING_BYTES")
    sth = decode_sth(sth_bytes)
    if sth.tree_size != count:
        raise Rtl1Error("SIZE_MISMATCH")
    return Snapshot(entries, sth)


def check(snapshot: Snapshot, key_set: ad.KeySet) -> None:
    """§6: the tree head is signed by ``key_set``, then the entries hash to
    its root; raises :class:`LogCheckError`."""
    try:
        snapshot.sth.verify(key_set)
    except ad.SigError as e:
        raise LogCheckError(e.code) from None
    if mth(snapshot.entries) != snapshot.sth.root_hash:
        raise LogCheckError("BAD_ROOT")


def encode_sth_body(tree_size: int, root_hash: bytes, timestamp_ms: int, key_set_digest: bytes) -> bytes:
    """The 88 signed bytes (not checked: decode checks)."""
    return (
        MAGIC
        + bytes([VERSION, KIND_STH, 0, 0])
        + tree_size.to_bytes(8, "big")
        + root_hash
        + timestamp_ms.to_bytes(8, "big")
        + key_set_digest
    )


def build_sth(body: bytes, signers: Sequence[Tuple[int, bytes]]) -> bytes:
    """``body`` signed by each ``(key_index, seed)`` in order."""
    message = STH_SIGNING_DOMAIN + body
    return body + ad.encode_sig_block([(i, ad.sign(seed, message)) for i, seed in signers])


def encode_snapshot(entries: Sequence[Entry], sth: bytes) -> bytes:
    out = bytearray(MAGIC)
    out += bytes([VERSION, KIND_SNAPSHOT, 0, 0])
    out += len(entries).to_bytes(4, "big")
    for e in entries:
        out += e.encode()
    out += len(sth).to_bytes(2, "big") + sth
    return bytes(out)
