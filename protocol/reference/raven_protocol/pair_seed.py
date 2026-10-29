"""RAVEN Route Hints V1 §14 (RAVEN_ROUTE_HINTS_V1.md, draft): the PAIR_SEED
entry (type 0x08), the pair seed KDF and the leader rule.

An independent reference for the Rust code (``raven_core::pair_seed``) and the
vectors ``shared-vectors/rvn1/pair_seed/kdf_001.json`` and
``route_hints/rrh1_pair_seed_001.json`` (which Rust writes and
:mod:`tests.test_pair_seed` checks against this module). ``K_pair`` takes the
R2 pairwise root's place in ``raven_protocol.lan_beacon.medium_key``
(RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3a): medium 0x01 Bluetooth LE, 0x02 the LAN
beacon, 0x03 the link knock.

Pure and deterministic: the seed is an argument (a real leader draws 32
random bytes for every proposal).
"""

from typing import NamedTuple, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

T_PAIR_SEED = 0x08
ENTRY_LEN = 40
KDF_INFO = b"rvn1/pair-seed/v1"


class SeedEntry(NamedTuple):
    generation: int
    seed: bytes
    acked: int


def pair_key(root: bytes, seed: bytes) -> bytes:
    """HKDF-SHA256(salt root, ikm seed, info 'rvn1/pair-seed/v1', 32)."""
    assert len(root) == 32 and len(seed) == 32
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=root, info=KDF_INFO).derive(seed)


def is_leader(me: bytes, peer: bytes) -> bool:
    """The numerically smaller identity key (32 bytes, big-endian) leads."""
    return bytes(me) < bytes(peer)


def encode_entry(e: SeedEntry) -> bytes:
    return e.generation.to_bytes(4, "big") + bytes(e.seed) + e.acked.to_bytes(4, "big")


def decode_entry(value: bytes) -> Optional[SeedEntry]:
    """The entry, or None (dropped alone): a length other than 40,
    generation 0 or an all-zero seed."""
    if len(value) != ENTRY_LEN:
        return None
    generation = int.from_bytes(value[:4], "big")
    seed = bytes(value[4:36])
    acked = int.from_bytes(value[36:], "big")
    if generation == 0 or seed == bytes(32):
        return None
    return SeedEntry(generation, seed, acked)
