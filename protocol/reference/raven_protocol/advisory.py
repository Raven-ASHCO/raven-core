"""RAVEN Security Advisory V1 (RAVEN_SECURITY_ADVISORY_V1.md, draft): release
key sets and signature blocks (§2), RAD1 advisories (§3, §5), their
verification (§6) and succession (§7).

An independent reference for the Rust code (``raven_core::release_keys`` and
``raven_core::advisory``) and the vectors in ``shared-vectors/rvn1/update``
(which Rust writes and :mod:`tests.test_advisory` checks against this module,
building every signed advisory again byte for byte: Ed25519 signatures are
deterministic).

Pure: no clock, no randomness.
"""

import hashlib
from typing import List, NamedTuple, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import ed25519_strict

# §2: key sets and signature blocks.
KEYSET_ALG_ED25519 = 0x01
KEYSET_MAX_KEYS = 8
KEYSET_DIGEST_DOMAIN = b"rvn1/release-keys/v1\0"
SIG_ENTRY_LEN = 65

# §3: advisories.
MAGIC = b"RAD1"
VERSION = 0x01
HEADER_LEN = 88
MAX_RAD1_LEN = 32_768
MAX_ENTRIES = 64
MAX_TARGET_LEN = 64
MAX_ARG_LEN = 1_024
SIGNING_DOMAIN = b"rvn1/advisory/v1\0"
DIGEST_DOMAIN = b"rvn1/advisory/digest/v1\0"

SUITE_STATUS = 0x01
RELEASE_FLOOR = 0x02
FEATURE_HOLD = 0x03
NOTICE = 0x04
KEY_SET = 0x05
KIND_NAMES = {
    SUITE_STATUS: "SUITE_STATUS",
    RELEASE_FLOOR: "RELEASE_FLOOR",
    FEATURE_HOLD: "FEATURE_HOLD",
    NOTICE: "NOTICE",
    KEY_SET: "KEY_SET",
}
INFO, DEPRECATED, BROKEN = 0, 1, 2
SEVERITY_NAMES = ("INFO", "DEPRECATED", "BROKEN")
FEATURE_PREFIX = "feature/"
TARGET_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789._/-")

# edwards25519
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


class KeySetError(ValueError):
    """Refused key set bytes (§2.1); ``code`` is the name the vectors use."""

    def __init__(self, code: str):
        super().__init__(f"KEYSET {code}")
        self.code = code


class SigError(ValueError):
    """A refused signature block (§2.3)."""

    def __init__(self, code: str):
        super().__init__(f"SIG {code}")
        self.code = code


class Rad1Error(ValueError):
    """Refused advisory bytes (§5)."""

    def __init__(self, code: str):
        super().__init__(f"RAD1 {code}")
        self.code = code


def usable_key(enc: bytes) -> bool:
    """§2.1 rule 6: the canonical encoding of a curve point, not of small
    order (as ed25519-dalek's decompress, ``is_weak`` and a re-encode)."""
    if len(enc) != 32 or ed25519_strict.is_small_order_encoding(enc):
        return False
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    sign = enc[31] >> 7
    if y >= _P:
        return False
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return sign == 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    return (x * x - x2) % _P == 0


def public_key(seed: bytes) -> bytes:
    """The Ed25519 public key of a 32-byte seed."""
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def sign(seed: bytes, message: bytes) -> bytes:
    """An Ed25519 signature (deterministic)."""
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


class KeySet:
    """A release key set (§2.1): ``threshold`` of ``keys`` must sign."""

    def __init__(self, threshold: int, keys: Sequence[bytes]):
        keys = [bytes(k) for k in keys]
        if not 1 <= len(keys) <= KEYSET_MAX_KEYS:
            raise KeySetError("BAD_COUNT")
        if not 1 <= threshold <= len(keys):
            raise KeySetError("BAD_THRESHOLD")
        for i, key in enumerate(keys):
            if not usable_key(key):
                raise KeySetError("WEAK_KEY")
            if key in keys[:i]:
                raise KeySetError("DUPLICATE_KEY")
        self.threshold = threshold
        self.keys = keys

    @classmethod
    def decode(cls, data: bytes) -> "KeySet":
        """Strict decode in the order of §2.1."""
        if len(data) < 3:
            raise KeySetError("BAD_LENGTH")
        alg, threshold, n = data[0], data[1], data[2]
        if alg != KEYSET_ALG_ED25519:
            raise KeySetError("UNSUPPORTED_ALG")
        if not 1 <= n <= KEYSET_MAX_KEYS:
            raise KeySetError("BAD_COUNT")
        if len(data) != 3 + 32 * n:
            raise KeySetError("BAD_LENGTH")
        return cls(threshold, [data[3 + 32 * i : 35 + 32 * i] for i in range(n)])

    @classmethod
    def of_seeds(cls, threshold: int, seeds: Sequence[bytes]) -> "KeySet":
        return cls(threshold, [public_key(s) for s in seeds])

    def encode(self) -> bytes:
        return bytes([KEYSET_ALG_ED25519, self.threshold, len(self.keys)]) + b"".join(self.keys)

    def digest(self) -> bytes:
        return hashlib.sha256(KEYSET_DIGEST_DOMAIN + self.encode()).digest()

    def verify_sigs(self, signing_input: bytes, sigs: Sequence[Tuple[int, bytes]]) -> None:
        """§2.3 rules 3-6; raises :class:`SigError`."""
        if any(a[0] >= b[0] for a, b in zip(sigs, sigs[1:])):
            raise SigError("KEY_INDEX_ORDER")
        if any(i >= len(self.keys) for i, _ in sigs):
            raise SigError("UNKNOWN_KEY_INDEX")
        if len(sigs) < self.threshold:
            raise SigError("BELOW_THRESHOLD")
        for i, sig in sigs:
            if not ed25519_strict.verify(self.keys[i], sig, signing_input):
                raise SigError("BAD_SIGNATURE")

    def verify_block(self, signing_input: bytes, block: bytes) -> None:
        self.verify_sigs(signing_input, decode_sig_block(block))


def decode_sig_block(block: bytes) -> List[Tuple[int, bytes]]:
    """Exactly one signature block (§2.2)."""
    if not block or len(block) != 1 + SIG_ENTRY_LEN * block[0]:
        raise SigError("MALFORMED")
    return [
        (block[1 + SIG_ENTRY_LEN * i], bytes(block[2 + SIG_ENTRY_LEN * i : 1 + SIG_ENTRY_LEN * (i + 1)]))
        for i in range(block[0])
    ]


def encode_sig_block(sigs: Sequence[Tuple[int, bytes]]) -> bytes:
    return bytes([len(sigs)]) + b"".join(bytes([i]) + s for i, s in sigs)


class Entry(NamedTuple):
    kind: int
    severity: int
    target: str
    arg: bytes
    text_id: int


def kind_name(kind: int) -> str:
    return KIND_NAMES.get(kind, "UNKNOWN")


def understood(kind: int) -> bool:
    return kind in KIND_NAMES


def target_well_formed(target: bytes) -> bool:
    """§3.2: 1..=64 bytes of [a-z0-9._/-], no empty segment."""
    return (
        1 <= len(target) <= MAX_TARGET_LEN
        and all(b in TARGET_BYTES for b in target)
        and all(target.split(b"/"))
    )


def _entry_fits(kind: int, target: str, arg: bytes) -> bool:
    """A known kind's rule for its target and argument (§3.2)."""
    if kind == SUITE_STATUS:
        return "/" in target and not target.startswith(FEATURE_PREFIX) and not arg
    if kind == RELEASE_FLOOR:
        return target == "raven" and len(arg) == 8 and int.from_bytes(arg, "big") >= 1
    if kind == FEATURE_HOLD:
        gate = target[len(FEATURE_PREFIX) :] if target.startswith(FEATURE_PREFIX) else None
        return gate is not None and "/" not in gate and not arg
    if kind == NOTICE:
        if target != "notice" or not arg:
            return False
        try:
            arg.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True
    if kind == KEY_SET:
        if target != "keys":
            return False
        try:
            KeySet.decode(arg)
        except KeySetError:
            return False
        return True
    return True


class Advisory(NamedTuple):
    serial: int
    issued_at_ms: int
    key_set_digest: bytes
    prev_digest: bytes
    entries: List[Entry]
    sigs: List[Tuple[int, bytes]]
    data: bytes
    signed_len: int

    def signing_input(self) -> bytes:
        return SIGNING_DOMAIN + self.data[: self.signed_len]

    def digest(self) -> bytes:
        return hashlib.sha256(DIGEST_DOMAIN + self.data).digest()

    def verify(self, key_set: KeySet) -> None:
        """§6.1 step 2; raises :class:`SigError`."""
        if self.key_set_digest != key_set.digest():
            raise SigError("WRONG_KEY_SET")
        key_set.verify_sigs(self.signing_input(), self.sigs)


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.at = 0

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise Rad1Error("TRUNCATED")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")


def decode(data: bytes) -> Advisory:
    """Strict decode in the order of §5; raises :class:`Rad1Error`."""
    data = bytes(data)
    if len(data) > MAX_RAD1_LEN:
        raise Rad1Error("TOO_LONG")
    r = _Reader(data)
    if r.take(4) != MAGIC:
        raise Rad1Error("BAD_MAGIC")
    if r.uint(1) != VERSION:
        raise Rad1Error("BAD_VERSION")
    if r.uint(1) != 0:
        raise Rad1Error("BAD_FLAGS")
    count = r.uint(2)
    if count > MAX_ENTRIES:
        raise Rad1Error("TOO_MANY_ENTRIES")
    serial = r.uint(8)
    if serial == 0:
        raise Rad1Error("BAD_SERIAL")
    issued_at_ms = r.uint(8)
    key_set_digest = r.take(32)
    prev_digest = r.take(32)
    if (serial == 1) != (prev_digest == bytes(32)):
        raise Rad1Error("BAD_PREV")
    entries: List[Entry] = []
    for _ in range(count):
        kind = r.uint(1)
        if kind == 0:
            raise Rad1Error("BAD_KIND")
        severity = r.uint(1)
        if severity > BROKEN:
            raise Rad1Error("BAD_SEVERITY")
        target_len = r.uint(1)
        if not 1 <= target_len <= MAX_TARGET_LEN:
            raise Rad1Error("BAD_TARGET")
        raw_target = r.take(target_len)
        if not target_well_formed(raw_target):
            raise Rad1Error("BAD_TARGET")
        target = raw_target.decode("ascii")
        arg_len = r.uint(2)
        if arg_len > MAX_ARG_LEN:
            raise Rad1Error("BAD_ARG")
        arg = r.take(arg_len)
        text_id = r.uint(2)
        if severity == BROKEN and kind in (RELEASE_FLOOR, NOTICE, KEY_SET):
            raise Rad1Error("BAD_SEVERITY")
        if not _entry_fits(kind, target, arg):
            raise Rad1Error("BAD_ENTRY")
        if any(e.kind == kind and e.target == target for e in entries):
            raise Rad1Error("DUPLICATE_ENTRY")
        entries.append(Entry(kind, severity, target, arg, text_id))
    signed_len = r.at
    try:
        sigs = decode_sig_block(data[signed_len:])
    except SigError:
        raise Rad1Error("BAD_SIG_BLOCK") from None
    return Advisory(serial, issued_at_ms, key_set_digest, prev_digest, entries, sigs, data, signed_len)


def encode_body(
    serial: int,
    issued_at_ms: int,
    key_set_digest: bytes,
    prev_digest: bytes,
    entries: Sequence[Entry],
) -> bytes:
    """The bytes before the signature block (not checked: decode checks)."""
    out = bytearray(MAGIC)
    out += bytes([VERSION, 0])
    out += len(entries).to_bytes(2, "big")
    out += serial.to_bytes(8, "big") + issued_at_ms.to_bytes(8, "big")
    out += key_set_digest + prev_digest
    for e in entries:
        target = e.target.encode("ascii")
        out += bytes([e.kind, e.severity, len(target)]) + target
        out += len(e.arg).to_bytes(2, "big") + e.arg + e.text_id.to_bytes(2, "big")
    return bytes(out)


def build(body: bytes, signers: Sequence[Tuple[int, bytes]]) -> bytes:
    """``body`` signed by each ``(key_index, seed)`` in order."""
    message = SIGNING_DOMAIN + body
    return body + encode_sig_block([(i, sign(seed, message)) for i, seed in signers])


def succession(stored: Optional[Tuple[int, bytes]], new: Advisory) -> str:
    """§7: how a verified advisory follows the stored ``(serial, digest)``."""
    if stored is None:
        return "FIRST"
    serial, digest = stored
    if new.serial < serial:
        return "ROLLBACK"
    if new.serial == serial:
        return "SAME" if new.digest() == digest else "EQUIVOCATION"
    if new.serial == serial + 1:
        return "NEXT" if new.prev_digest == digest else "EQUIVOCATION"
    return "GAP"
