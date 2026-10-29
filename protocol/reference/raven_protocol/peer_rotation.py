# protocol/reference/raven_protocol/peer_rotation.py
"""P2P PeerId rotation V1 (protocol/RAVEN_P2P_PEER_ROTATION_V1.md): the epoch keys, the epoch
phase, the announced schedule and the relay schedule text.

An independent implementation of raven-core's peer_rotation (epoch_seed, epoch_public, phase_s,
epoch_at, next_boundary_unix, own_schedule, format_relay_schedule, parse_relay_schedule). Uses
the `cryptography` package for Ed25519 (requirements.txt). Errors of the relay schedule parse carry
a code (RelayScheduleError.code); the vectors record it.
"""
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import via

EPOCH_KEY_DOMAIN = b"raven/libp2p-epoch-key/v1"
EPOCH_PHASE_DOMAIN = b"raven/libp2p-epoch-phase/v1"
LEGACY_KEY_DOMAIN = b"raven/libp2p-peer-key/v1"
DEFAULT_EPOCH_S = 28 * 86_400
AHEAD = 6
MAX_SCHEDULE = 8
RELAY_SCHEDULE_PREFIX = "raven-relay-schedule/1"
MAX_RELAY_SCHEDULE = 13
RELAY_SCHEDULE_MAX_LEN = len(RELAY_SCHEDULE_PREFIX) + MAX_RELAY_SCHEDULE * (1 + 20 + 1 + 52)
U64_MAX = 2**64 - 1

# Error codes of parse_relay_schedule: the rule that refused the text.
NOT_ONE_LINE = "not_one_line"  # over RELAY_SCHEDULE_MAX_LEN after trimming, or a byte other than 0x20..0x7e
VERSION = "version"            # raven-relay-schedule/<other>
PREFIX = "prefix"              # does not start with raven-relay-schedule/1
ENTRY = "entry"                # an entry without ':'
EPOCH = "epoch"                # not canonical decimal (digits, no leading zero but 0), or over 2^64 - 1
PEER_ID = "peer_id"            # not a canonical Ed25519 PeerId
ORDER = "order"                # epochs not strictly increasing
DUPLICATE = "duplicate"        # a PeerId twice
EMPTY = "empty"                # no entry
TOO_MANY = "too_many"          # more than 13 entries


class RelayScheduleError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _public(secret_seed):
    key = Ed25519PrivateKey.from_private_bytes(bytes(secret_seed))
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def legacy_seed(seed):
    """The non-rotating libp2p key seed: SHA-256("raven/libp2p-peer-key/v1" || seed)."""
    return hashlib.sha256(LEGACY_KEY_DOMAIN + bytes(seed)).digest()


def legacy_peer_id(seed):
    return via.peer_id_from_ed25519_public(_public(legacy_seed(seed)))


def epoch_seed(seed, e):
    """SHA-256("raven/libp2p-epoch-key/v1" || be64(e) || seed): epoch e's Ed25519 secret seed."""
    return hashlib.sha256(EPOCH_KEY_DOMAIN + e.to_bytes(8, "big") + bytes(seed)).digest()


def epoch_public(seed, e):
    return _public(epoch_seed(seed, e))


def epoch_peer_id(seed, e):
    return via.peer_id_from_ed25519_public(epoch_public(seed, e))


def phase_s(seed, length):
    """be64(SHA-256("raven/libp2p-epoch-phase/v1" || seed)[0..8]) mod length (0 reads as 1)."""
    digest = hashlib.sha256(EPOCH_PHASE_DOMAIN + bytes(seed)).digest()
    return int.from_bytes(digest[:8], "big") % max(length, 1)


def epoch_at(seed, unix_s, length):
    return min(unix_s + phase_s(seed, length), U64_MAX) // max(length, 1)


def next_boundary_unix(seed, unix_s, length):
    length = max(length, 1)
    return max(min((epoch_at(seed, unix_s, length) + 1) * length, U64_MAX) - phase_s(seed, length), 0)


def own_schedule(seed, active):
    """The previous epoch, active and AHEAD more, each with its public key."""
    return [(e, epoch_public(seed, e)) for e in range(max(active - 1, 0), min(active + AHEAD, U64_MAX) + 1)]


def format_relay_schedule(seed, start, n):
    n = min(max(n, 1), MAX_RELAY_SCHEDULE)
    parts = [RELAY_SCHEDULE_PREFIX]
    for e in range(start, min(start + n, U64_MAX + 1)):
        parts.append(f"{e}:{epoch_peer_id(seed, e)}")
    return " ".join(parts)


def _epoch(text):
    if not text or not all("0" <= c <= "9" for c in text) or (len(text) > 1 and text[0] == "0"):
        raise RelayScheduleError(EPOCH)
    e = int(text)
    if e > U64_MAX:
        raise RelayScheduleError(EPOCH)
    return e


def parse_relay_schedule(text):
    """[(epoch, canonical PeerId)] of a relay schedule text; RelayScheduleError otherwise."""
    line = text.strip()
    if len(line) > RELAY_SCHEDULE_MAX_LEN or any(not (0x20 <= ord(c) <= 0x7E) for c in line):
        raise RelayScheduleError(NOT_ONE_LINE)
    tokens = [t for t in line.split(" ") if t]
    if not tokens or tokens[0] != RELAY_SCHEDULE_PREFIX:
        if tokens and tokens[0].startswith("raven-relay-schedule/"):
            raise RelayScheduleError(VERSION)
        raise RelayScheduleError(PREFIX)
    out = []
    for token in tokens[1:]:
        if len(out) == MAX_RELAY_SCHEDULE:
            raise RelayScheduleError(TOO_MANY)
        if ":" not in token:
            raise RelayScheduleError(ENTRY)
        epoch_text, peer = token.split(":", 1)
        e = _epoch(epoch_text)
        try:
            canonical = via.normalize_peer_id(peer)
        except via.ViaError:
            raise RelayScheduleError(PEER_ID) from None
        if canonical != peer:
            raise RelayScheduleError(PEER_ID)
        if out and out[-1][0] >= e:
            raise RelayScheduleError(ORDER)
        if any(p == peer for _, p in out):
            raise RelayScheduleError(DUPLICATE)
        out.append((e, peer))
    if not out:
        raise RelayScheduleError(EMPTY)
    return out
