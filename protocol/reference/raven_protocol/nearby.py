"""RAVEN Nearby Link V1 (RAVEN_NEARBY_LINK_V1.md, draft): RNB1 keys and
tokens, the RNK1 knock, RNP1 frames and the pipe state machine.

An independent reference for the Rust code (``raven_core::nearby_link``) and
the vectors in ``shared-vectors/rvn1/nearby`` (which Rust writes and
:mod:`tests.test_nearby_vectors` recomputes from their inputs). The R2
pairwise root is the LAN beacon reference's
(:func:`raven_protocol.lan_beacon.pair_root`): one root per pair, shared by
every medium, with the Bluetooth LE medium byte ``0x01`` here.

Pure and deterministic: no radio, no clock, no randomness. Every nonce is an
argument (a real knock draws them fresh).
"""

import hashlib
from typing import NamedTuple, Optional

from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from raven_protocol import lan_beacon as lb

NEARBY_LINK_PROLOGUE = b"raven/nearby-link/v1"
EPOCH_MS = 900_000
MIN_FRAME = 64
MAX_FRAME = 512
W0 = 8
W_MAX = 64
MAX_CONTROL_RUN = 64
VERSION = 0x01
FLAGS_V1 = 0x00
HELLO_LEN = 35
CHALLENGE_LEN = 35
PROOF_LEN = 17
DATA_HEADER = 4
LAST_DATA_SEQ = 0xFFFE  # a sender whose next seq is 65535 must FIN
U64_MAX = 2**64 - 1

KIND_HELLO = 0x01
KIND_CHALLENGE = 0x02
KIND_PROOF = 0x03
KIND_OPEN = 0x10
KIND_DATA = 0x11
KIND_CREDIT = 0x12
KIND_FIN = 0x13
KIND_RESET = 0x1F

RESET_CODES = {
    "PROTOCOL": 1,
    "IDLE": 2,
    "LIMIT": 3,
    "SHUTDOWN": 4,
    "MTU": 5,
    "DUPLICATE": 6,
}


class PipeError(ValueError):
    """A frame that ends the pipe; ``name`` is its RESET code's name."""

    def __init__(self, name: str):
        super().__init__(name)
        self.name = name

    @property
    def code(self) -> int:
        return RESET_CODES[self.name]

    def reset(self) -> bytes:
        return bytes([KIND_RESET, self.code])


class PairKeys(NamedTuple):
    """One contact's RNB1 keys, seen from this node."""

    me: bytes  # this node's Ed25519 identity key
    peer: bytes  # the contact's Ed25519 identity key
    k_ble: bytes  # K_medium(0x01) of the R2 root
    k_tok: bytes
    k_knock: bytes


def _expand(prk: bytes, info: bytes) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(prk)


def _hmac(key: bytes, *parts: bytes) -> bytes:
    mac = hmac.HMAC(key, hashes.SHA256())
    for part in parts:
        mac.update(part)
    return mac.finalize()


def keys_from_root(root: bytes, me: bytes, peer: bytes) -> PairKeys:
    """K_ble = K_medium(0x01); K_tok and K_knock expand from it."""
    ble = lb.medium_key(root, lb.MEDIUM_BLE)
    return PairKeys(
        me=bytes(me),
        peer=bytes(peer),
        k_ble=ble,
        k_tok=_expand(ble, b"RNB1-token"),
        k_knock=_expand(ble, b"RNB1-knock"),
    )


def pair_keys(own_seed: bytes, peer: bytes) -> PairKeys:
    """The RNB1 keys of own_seed's identity for the contact key peer (the
    contact-key checks and errors of lan_beacon.pair_root)."""
    return keys_from_root(lb.pair_root(own_seed, peer), lb.ed25519_public(own_seed), peer)


def epoch_of(unix_ms: int) -> int:
    return unix_ms // EPOCH_MS


def scan_epochs(now_epoch: int) -> list:
    """The epochs a scanner at now_epoch accepts (within u64)."""
    return list(range(max(now_epoch - 1, 0), min(now_epoch + 1, U64_MAX) + 1))


def _v4_bits(b: bytes) -> bytes:
    out = bytearray(b)
    out[6] = (out[6] & 0x0F) | 0x40
    out[8] = (out[8] & 0x3F) | 0x80
    return bytes(out)


def token_hmac_input(epoch: int, advertiser: bytes) -> bytes:
    return b"RNB1" + bytes([VERSION, lb.MEDIUM_BLE]) + epoch.to_bytes(8, "big") + bytes(advertiser)


def token(k_tok: bytes, epoch: int, advertiser: bytes) -> bytes:
    """T(epoch, advertiser), with the RFC 9562 version-4 bits."""
    return _v4_bits(_hmac(k_tok, token_hmac_input(epoch, advertiser))[:16])


def char_uuid(t: bytes) -> bytes:
    return _v4_bits(hashlib.sha256(b"RNB1-char" + bytes(t)).digest()[:16])


def uuid_string(u: bytes) -> str:
    h = bytes(u).hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def uuid_ota_le(u: bytes) -> bytes:
    return bytes(reversed(bytes(u)))


def windows_guid_u128(u: bytes) -> int:
    return int.from_bytes(bytes(u), "big")


# RNK1 knock (§5)


def hello_tag(k_knock: bytes, t: bytes, flags_c: int, nonce_c: bytes) -> bytes:
    return _hmac(k_knock, b"RNK1/hello", t, bytes([flags_c]), nonce_c)[:16]


def _transcript(flags_c, nonce_c, flags_p, nonce_p) -> bytes:
    return bytes([flags_c]) + bytes(nonce_c) + bytes([flags_p]) + bytes(nonce_p)


def challenge_tag(k_knock, t, flags_c, nonce_c, flags_p, nonce_p) -> bytes:
    return _hmac(k_knock, b"RNK1/resp", t, _transcript(flags_c, nonce_c, flags_p, nonce_p))[:16]


def proof_tag(k_knock, t, flags_c, nonce_c, flags_p, nonce_p) -> bytes:
    return _hmac(k_knock, b"RNK1/proof", t, _transcript(flags_c, nonce_c, flags_p, nonce_p))[:16]


def hello(k_knock: bytes, t: bytes, flags_c: int, nonce_c: bytes) -> bytes:
    tag = hello_tag(k_knock, t, flags_c, nonce_c)
    return bytes([KIND_HELLO, VERSION, flags_c]) + bytes(nonce_c) + tag


def challenge(k_knock, t, flags_c, nonce_c, flags_p, nonce_p) -> bytes:
    tag = challenge_tag(k_knock, t, flags_c, nonce_c, flags_p, nonce_p)
    return bytes([KIND_CHALLENGE, VERSION, flags_p]) + bytes(nonce_p) + tag


def proof(k_knock, t, flags_c, nonce_c, flags_p, nonce_p) -> bytes:
    return bytes([KIND_PROOF]) + proof_tag(k_knock, t, flags_c, nonce_c, flags_p, nonce_p)


def answer_hello(k_knock: bytes, t: bytes, frame: bytes, nonce_p: bytes, replay: set) -> Optional[bytes]:
    """The peripheral: a CHALLENGE only for a version-1 HELLO on service t
    whose tag verifies and whose nonce_c is not in replay (then added);
    None means silence."""
    try:
        f = decode(frame, MAX_FRAME)
    except PipeError:
        return None
    if f["kind"] != "HELLO" or f["version"] != VERSION:
        return None
    if not constant_time.bytes_eq(hello_tag(k_knock, t, f["flags"], f["nonce"]), f["tag"]):
        return None
    if (bytes(t), f["nonce"]) in replay:
        return None
    replay.add((bytes(t), f["nonce"]))
    return challenge(k_knock, t, f["flags"], f["nonce"], FLAGS_V1, nonce_p)


def proof_for(k_knock: bytes, t: bytes, flags_c: int, nonce_c: bytes, frame: bytes) -> Optional[bytes]:
    """The central: the PROOF for a version-1 CHALLENGE whose tag verifies."""
    try:
        f = decode(frame, MAX_FRAME)
    except PipeError:
        return None
    if f["kind"] != "CHALLENGE" or f["version"] != VERSION:
        return None
    want = challenge_tag(k_knock, t, flags_c, nonce_c, f["flags"], f["nonce"])
    if not constant_time.bytes_eq(want, f["tag"]):
        return None
    return proof(k_knock, t, flags_c, nonce_c, f["flags"], f["nonce"])


# RNP1 frames (§6)


def decode(buf: bytes, max_rx: int) -> dict:
    """One frame as a dict (kind name and fields), else PipeError: MTU when
    longer than max_rx (at most 512), PROTOCOL for an empty frame, an unknown
    kind, a wrong length, a channel other than 0 or 1, or a CREDIT add
    outside 1..64."""
    buf = bytes(buf)
    if len(buf) > min(max_rx, MAX_FRAME):
        raise PipeError("MTU")
    if not buf:
        raise PipeError("PROTOCOL")
    kind = buf[0]

    def fixed(n):
        if len(buf) != n:
            raise PipeError("PROTOCOL")

    def chan(c):
        if c > 1:
            raise PipeError("PROTOCOL")
        return c

    if kind in (KIND_HELLO, KIND_CHALLENGE):
        fixed(HELLO_LEN)
        return {
            "kind": "HELLO" if kind == KIND_HELLO else "CHALLENGE",
            "version": buf[1],
            "flags": buf[2],
            "nonce": buf[3:19],
            "tag": buf[19:35],
        }
    if kind == KIND_PROOF:
        fixed(PROOF_LEN)
        return {"kind": "PROOF", "tag": buf[1:]}
    if kind == KIND_OPEN:
        fixed(2)
        return {"kind": "OPEN", "chan": chan(buf[1])}
    if kind == KIND_DATA:
        if len(buf) <= DATA_HEADER:
            raise PipeError("PROTOCOL")
        return {
            "kind": "DATA",
            "chan": chan(buf[1]),
            "seq": int.from_bytes(buf[2:4], "big"),
            "payload": buf[4:],
        }
    if kind == KIND_CREDIT:
        fixed(4)
        add = int.from_bytes(buf[2:4], "big")
        if not 1 <= add <= W_MAX:
            raise PipeError("PROTOCOL")
        return {"kind": "CREDIT", "chan": chan(buf[1]), "add": add}
    if kind == KIND_FIN:
        fixed(4)
        return {"kind": "FIN", "chan": chan(buf[1]), "next_seq": int.from_bytes(buf[2:4], "big")}
    if kind == KIND_RESET:
        fixed(2)
        return {"kind": "RESET", "code": buf[1]}
    raise PipeError("PROTOCOL")


def encode(f: dict) -> bytes:
    """The bytes of an RNP1 frame dict (OPEN, DATA, CREDIT, FIN, RESET)."""
    k = f["kind"]
    if k == "OPEN":
        return bytes([KIND_OPEN, f["chan"]])
    if k == "DATA":
        return bytes([KIND_DATA, f["chan"]]) + f["seq"].to_bytes(2, "big") + bytes(f["payload"])
    if k == "CREDIT":
        return bytes([KIND_CREDIT, f["chan"]]) + f["add"].to_bytes(2, "big")
    if k == "FIN":
        return bytes([KIND_FIN, f["chan"]]) + f["next_seq"].to_bytes(2, "big")
    if k == "RESET":
        return bytes([KIND_RESET, f["code"]])
    raise ValueError(f"not an RNP1 frame kind: {k}")


class _Chan:
    def __init__(self):
        self.opened = False
        self.tx_seq = self.rx_seq = 0
        self.tx_credit = self.rx_credit = 0
        self.fin_tx = self.fin_rx = False

    def active(self) -> bool:
        return self.opened and not (self.fin_tx and self.fin_rx)

    def start(self):
        self.__init__()
        self.opened = True
        self.tx_credit = self.rx_credit = W0


class PipeState:
    """The receive rules of one pipe after UP (§6), as the negative vectors
    exercise them, plus the local OPEN, DATA and FIN of the sender."""

    def __init__(self, role: str, max_tx: int, max_rx: int):
        if max_tx < MIN_FRAME or max_rx < MIN_FRAME:
            raise PipeError("MTU")
        self.role = role
        self.max_tx = min(max_tx, MAX_FRAME)
        self.max_rx = min(max_rx, MAX_FRAME)
        self.chans = [_Chan(), _Chan()]
        self.control_run = 0
        self.dead = False

    def own_chan(self) -> int:
        return 0 if self.role == "central" else 1

    def on_rx_bytes(self, buf: bytes) -> tuple:
        try:
            return self.on_rx(decode(buf, self.max_rx))
        except PipeError:
            self.dead = True
            raise

    def on_rx(self, f: dict) -> tuple:
        if self.dead:
            raise PipeError("PROTOCOL")
        try:
            out = self._apply(f)
        except PipeError:
            self.dead = True
            raise
        if out[0] == "reset":
            self.dead = True
        return out

    def _apply(self, f: dict) -> tuple:
        k = f["kind"]
        if k in ("HELLO", "CHALLENGE", "PROOF"):
            raise PipeError("PROTOCOL")
        if k == "DATA":
            c = self.chans[f["chan"]]
            if (
                not c.active()
                or c.fin_rx
                or f["seq"] != c.rx_seq
                or f["seq"] > LAST_DATA_SEQ
                or c.rx_credit == 0
            ):
                raise PipeError("PROTOCOL")
            c.rx_seq += 1
            c.rx_credit -= 1
            self.control_run = 0
            return ("deliver", f["chan"], f["payload"])
        if k == "RESET":
            return ("reset", f["code"])
        self.control_run += 1
        if self.control_run > MAX_CONTROL_RUN:
            raise PipeError("LIMIT")
        c = self.chans[f["chan"]]
        if k == "OPEN":
            if f["chan"] == self.own_chan() or c.active():
                raise PipeError("PROTOCOL")
            c.start()
            return ("opened", f["chan"])
        if k == "CREDIT":
            if not c.active() or c.tx_credit + f["add"] > W_MAX:
                raise PipeError("PROTOCOL")
            c.tx_credit += f["add"]
            return ("credit", f["chan"])
        if k == "FIN":
            if not c.active() or c.fin_rx or f["next_seq"] != c.rx_seq:
                raise PipeError("PROTOCOL")
            c.fin_rx = True
            return ("fined", f["chan"])
        raise PipeError("PROTOCOL")

    def open(self) -> Optional[bytes]:
        c = self.chans[self.own_chan()]
        if self.dead or c.active():
            return None
        c.start()
        return encode({"kind": "OPEN", "chan": self.own_chan()})

    def send_data(self, chan: int, payload: bytes) -> Optional[bytes]:
        c = self.chans[chan]
        if self.dead or not c.active() or c.fin_tx or c.tx_credit == 0 or c.tx_seq > LAST_DATA_SEQ:
            return None
        if not 1 <= len(payload) <= self.max_tx - DATA_HEADER:
            raise ValueError("payload outside 1..max_tx - 4")
        frame = encode({"kind": "DATA", "chan": chan, "seq": c.tx_seq, "payload": payload})
        c.tx_seq += 1
        c.tx_credit -= 1
        self.control_run = 0
        return frame

    def grant(self, chan: int, add: int) -> bytes:
        """CREDIT of add frames on chan (the receiver delivered them)."""
        c = self.chans[chan]
        if not 1 <= add <= W_MAX - c.rx_credit:
            raise ValueError("credit past 64 outstanding")
        c.rx_credit += add
        return encode({"kind": "CREDIT", "chan": chan, "add": add})
