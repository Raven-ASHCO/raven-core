"""RAVEN Link Knock V1 (RAVEN_LINK_KNOCK_V1.md, draft): the knock in Noise XX
message 1, the proof in message 2, both decision tables and the padded
message 3 payload.

An independent reference for the Rust code (``raven_core::link_knock``) and
the vectors ``shared-vectors/rvn1/link/rlk1_*`` and
``lan/noise_xx_handshake_003.json`` (which Rust writes and
:mod:`tests.test_link_knock` checks against this module). The pairwise root
and the medium key are the LAN beacon's (``raven_protocol.lan_beacon``,
RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3a) with medium byte 0x03.

Pure and deterministic: nonces and trailing bytes are arguments (a real
dialer and listener draw them fresh for every connection).
"""

from typing import NamedTuple, Optional

from cryptography.hazmat.primitives import constant_time

from raven_protocol import lan_beacon as lb
from raven_protocol import link_padding as lp

MEDIUM_LINK = 0x03
E_LEN = 32
NONCE_LEN = 16
TAG_LEN = 16
PROOF_LEN = 16
PAD_MAX = 31
M1_PAYLOAD_MIN = NONCE_LEN + TAG_LEN  # 32
M1_PAYLOAD_MAX = M1_PAYLOAD_MIN + PAD_MAX  # 63
M2_PAYLOAD_MIN = PROOF_LEN  # 16
M2_PAYLOAD_MAX = PROOF_LEN + PAD_MAX  # 47
DAY_MS = 86_400_000
MAX_BOOK = 1_024
REPLAY_ENTRIES = 4_096
REPLAY_TTL_MS = 3 * DAY_MS  # the knock's day and the days next to it (it was 2)

EXT_PAD = 0x7E  # RLX1 entry type (RAVEN_ROUTE_HINTS_V1 §3.2)


class KnockKeys(NamedTuple):
    """One contact's knock keys, seen from the owner of the book."""

    peer: bytes  # the contact's Ed25519 identity key
    q_out: bytes  # kq(me -> peer): this node's knocks
    q_in: bytes  # kq(peer -> me): the contact's knocks
    r_out: bytes  # kr(me -> peer): this node's proofs
    r_in: bytes  # kr(peer -> me): the contact's proofs


def day_of(unix_ms: int) -> int:
    return unix_ms // DAY_MS


def link_key(own_seed: bytes, peer: bytes) -> bytes:
    """K_link = medium_key(pair_root(own, peer), 0x03)."""
    return lb.medium_key(lb.pair_root(own_seed, peer), MEDIUM_LINK)


def knock_keys(own_seed: bytes, peer: bytes) -> KnockKeys:
    peer = bytes(peer)
    k = link_key(own_seed, peer)
    me = lb.ed25519_public(own_seed)
    return KnockKeys(
        peer=peer,
        q_out=lb._hmac(k, b"knock-q", me, peer),
        q_in=lb._hmac(k, b"knock-q", peer, me),
        r_out=lb._hmac(k, b"knock-r", me, peer),
        r_in=lb._hmac(k, b"knock-r", peer, me),
    )


def m1_tag(kq: bytes, day: int, nonce: bytes, e: bytes) -> bytes:
    """HMAC(kq, 'rlk1/m1' || day u32 BE || nonce16 || e)[0..16]."""
    return lb._hmac(kq, b"rlk1/m1", day.to_bytes(4, "big"), nonce, e)[:TAG_LEN]


def m2_proof(kr: bytes, nonce: bytes, e: bytes, s: bytes) -> bytes:
    """HMAC(kr, 'rlk1/m2' || nonce16 || e || s)[0..16]."""
    return lb._hmac(kr, b"rlk1/m2", nonce, e, s)[:PROOF_LEN]


def m1_payload(keys: KnockKeys, day: int, e: bytes, nonce: bytes, pad: bytes) -> bytes:
    """``nonce || tag || pad`` (pad at most 31 bytes)."""
    return nonce + m1_tag(keys.q_out, day, nonce, e) + pad[:PAD_MAX]


def m2_payload(keys: KnockKeys, nonce: bytes, e: bytes, s: bytes, pad: bytes) -> bytes:
    """``proof || pad`` (pad at most 31 bytes)."""
    return m2_proof(keys.r_out, nonce, e, s) + pad[:PAD_MAX]


class M1Match(NamedTuple):
    index: int
    peer: bytes
    nonce: bytes
    e: bytes


def match_m1(book, raw_m1: bytes, day: int) -> Optional[M1Match]:
    """The contact of ``book`` (a list of KnockKeys) whose knock is in the raw
    XX message 1 ``e || payload``, on the listener's day or a day next to it;
    None for a payload of another length, no match or more than one. Every
    contact and day is tried; tags are compared in constant time."""
    if len(raw_m1) < E_LEN:
        return None
    e, payload = raw_m1[:E_LEN], raw_m1[E_LEN:]
    if not M1_PAYLOAD_MIN <= len(payload) <= M1_PAYLOAD_MAX:
        return None
    nonce, tag = payload[:NONCE_LEN], payload[NONCE_LEN:M1_PAYLOAD_MIN]
    days = [max(day - 1, 0), day, min(day + 1, 2**32 - 1)]
    found = []
    for i, keys in enumerate(list(book)[:MAX_BOOK]):
        hit = False
        for d in days:
            hit |= constant_time.bytes_eq(m1_tag(keys.q_in, d, nonce, e), tag)
        if hit:
            found.append(i)
    if len(found) != 1:
        return None
    return M1Match(found[0], book[found[0]].peer, nonce, e)


def check_m2(keys: KnockKeys, nonce: bytes, e: bytes, s: bytes, payload: bytes) -> bool:
    """Does a message 2 payload prove the contact (the static s it carried)?"""
    if not M2_PAYLOAD_MIN <= len(payload) <= M2_PAYLOAD_MAX:
        return False
    return constant_time.bytes_eq(m2_proof(keys.r_in, nonce, e, s), payload[:PROOF_LEN])


class ReplayCache:
    """Matched nonces, each remembered for three days, at most 4,096."""

    def __init__(self):
        self.order = []  # (at_ms, nonce), oldest first

    def replayed(self, nonce: bytes, now_ms: int) -> bool:
        self.order = [(at, n) for at, n in self.order if now_ms - at < REPLAY_TTL_MS or now_ms < at]
        if any(n == nonce for _, n in self.order):
            return True
        if len(self.order) >= REPLAY_ENTRIES:
            self.order.pop(0)
        self.order.append((now_ms, nonce))
        return False


# ── Decision tables (spec §4, §5) ───────────────────────────────────────────

LEGACY, STRICT, SILENT = "legacy", "strict", "silent"


def listener_mode(setting: str, every_contact_knocks: bool) -> str:
    """setting: 'automatic', 'on' or 'off' (node_policy security_silent_to_strangers)."""
    if setting == "on":
        return SILENT
    if setting == "off":
        return LEGACY
    return STRICT if every_contact_knocks else LEGACY


def answer(mode: str, matched: bool) -> str:
    """'fresh+proof', 'fresh', 'derived' or 'close'."""
    if matched:
        return "fresh+proof"
    return {LEGACY: "derived", STRICT: "fresh", SILENT: "close"}[mode]


def dialer_step(proof_ok: bool, pin: str, floor_knock: bool) -> str:
    """pin: 'none', 'match' or 'mismatch'. 'fresh', 'derived', 'stop_pin' or 'stop_knock'."""
    if proof_ok:
        return "fresh"
    if pin == "mismatch":
        return "stop_pin"
    if pin == "match":
        return "derived"
    return "stop_knock" if floor_knock else "derived"


# ── Message 3 (spec §6) ─────────────────────────────────────────────────────


def rlx1_padded_min_len(caps: int) -> int:
    return 5 + (6 if caps else 0) + 2


def rlx1_payload_padded(caps: int, total: int) -> bytes:
    """RLX1 with LINK_CAPS (none for caps 0) and one PAD entry of zeros to
    ``total`` bytes, kept within min..64."""
    total = min(max(total, rlx1_padded_min_len(caps)), lp.RLX1_MAX_LEN)
    out = lp.RLX1_MAGIC + bytes([lp.RLX1_VERSION])
    if caps:
        out += bytes([lp.EXT_LINK_CAPS, 4]) + caps.to_bytes(4, "big")
    pad = total - len(out) - 2
    return out + bytes([EXT_PAD, pad]) + bytes(pad)
