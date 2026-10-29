"""RAVEN Update Exchange V1 (RAVEN_UPDATE_EXCHANGE_V1.md, draft): the RUP1
frames friends pass advisories, log snapshots and release bundles with
(§3), their decode rules (§4), the dial classifier (§5) and what a listener
does with a frame (§6).

An independent reference for the Rust code (``raven_core::update_exchange``)
and the ``rup1_*`` vectors in ``shared-vectors/rvn1/update`` (which Rust
writes and :mod:`tests.test_update_exchange` checks against this module,
building every frame again byte for byte). Chunk audit paths are
:mod:`raven_protocol.release_bundle`'s.

A frame decodes to ``(req_id, op, fields)``; ``fields`` is a dict:

- HAVE: ``adv_serial``, ``adv_digest``, ``log_size``, ``log_root``,
  ``offers`` (a list of :class:`Offer`);
- GET_ADVISORY, GET_LOG: nothing; GET_MANIFEST: ``manifest_digest``;
  GET_CHUNKS: ``manifest_digest``, ``first``, ``count``; GET_ROTATION:
  ``key_set_digest``;
- ADVISORY: ``rad1``, ``snapshot``; LOG: ``snapshot``; MANIFEST:
  ``manifest``, ``snapshot``;
- CHUNK: ``index``, ``bytes``, ``path`` (a list of 32-byte hashes);
- CHUNKS_END: ``code`` (0: every chunk asked for was sent), ``sent``;
- ERROR: ``code``.

Pure: no clock, no randomness.
"""

from typing import Dict, List, NamedTuple, Tuple

from . import advisory as ad
from . import link_padding as lp
from . import release_bundle as rb
from . import tlog

MAGIC = b"RUP1"
VERSION = 0x01
HEADER_LEN = 10
MAX_FRAME_LEN = lp.MAX_INNER  # 65,511
NO_REQ_ID = bytes(4)

OP_HAVE = 0x01
OP_GET_ADVISORY = 0x02
OP_GET_LOG = 0x03
OP_GET_MANIFEST = 0x04
OP_GET_CHUNKS = 0x05
OP_GET_ROTATION = 0x06  # added under version 1 (Phase 6 review)
OP_ADVISORY = 0x82
OP_LOG = 0x83
OP_MANIFEST = 0x84
OP_CHUNK = 0x85
OP_CHUNKS_END = 0x86
OP_ERROR = 0xFF
OP_NAMES = {
    OP_HAVE: "HAVE",
    OP_GET_ADVISORY: "GET_ADVISORY",
    OP_GET_LOG: "GET_LOG",
    OP_GET_MANIFEST: "GET_MANIFEST",
    OP_GET_CHUNKS: "GET_CHUNKS",
    OP_GET_ROTATION: "GET_ROTATION",
    OP_ADVISORY: "ADVISORY",
    OP_LOG: "LOG",
    OP_MANIFEST: "MANIFEST",
    OP_CHUNK: "CHUNK",
    OP_CHUNKS_END: "CHUNKS_END",
    OP_ERROR: "ERROR",
}
REQUESTS = (OP_GET_ADVISORY, OP_GET_LOG, OP_GET_MANIFEST, OP_GET_CHUNKS, OP_GET_ROTATION)
TERMINAL_REPLIES = (OP_ADVISORY, OP_LOG, OP_MANIFEST, OP_CHUNKS_END, OP_ERROR)
# Which reply answers which request (ERROR answers any).
ANSWERS = {
    OP_GET_ADVISORY: (OP_ADVISORY,),
    OP_GET_LOG: (OP_LOG,),
    OP_GET_MANIFEST: (OP_MANIFEST,),
    OP_GET_CHUNKS: (OP_CHUNK, OP_CHUNKS_END),
    OP_GET_ROTATION: (OP_ADVISORY,),
}

ERROR_NAMES = {
    1: "UNSUPPORTED",
    2: "NOT_FOUND",
    3: "BUSY",
    4: "RATE_LIMITED",
    5: "POLICY_DENIED",
    6: "MALFORMED",
}

MAX_OFFERS = 4
MAX_CHUNKS_PER_REQUEST = 8
MAX_CHUNKS_PER_DIAL = 16
HAVE_FIXED_LEN = 8 + 32 + 4 + 32 + 1
OFFER_FIXED_LEN = 8 + 1 + 32 + 8
MAX_HAVE_LEN = HEADER_LEN + HAVE_FIXED_LEN + MAX_OFFERS * (OFFER_FIXED_LEN + rb.MAX_TARGET_LEN)
GET_CHUNKS_LEN = HEADER_LEN + 32 + 4 + 1
GET_ROTATION_LEN = HEADER_LEN + 32
MAX_CHUNK_FRAME_LEN = HEADER_LEN + 4 + 4 + rb.CHUNK_SIZE + 1 + 32 * rb.MAX_CHUNK_PATH_LEN
MAX_MANIFEST_FRAME_LEN = HEADER_LEN + 2 + rb.MAX_MANIFEST_LEN + tlog.MAX_SNAPSHOT_LEN
MAX_LOG_FRAME_LEN = HEADER_LEN + tlog.MAX_SNAPSHOT_LEN
ADVISORY_ALWAYS_FITS = MAX_FRAME_LEN - HEADER_LEN - 2 - tlog.MAX_SNAPSHOT_LEN

CAP_LINK_RUP1 = 1 << 10


class Rup1Error(ValueError):
    """Refused RUP1 bytes (§4); ``code`` is the name the vectors use."""

    def __init__(self, code: str):
        super().__init__(f"RUP1 {code}")
        self.code = code


class Offer(NamedTuple):
    build_serial: int
    target: bytes
    manifest_digest: bytes
    payload_len: int


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def take(self, n: int) -> bytes:
        if len(self.data) - self.at < n:
            raise Rup1Error("TRUNCATED")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def int(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def rest(self) -> bytes:
        out = self.data[self.at :]
        self.at = len(self.data)
        return out

    def end(self) -> None:
        if self.at != len(self.data):
            raise Rup1Error("TRAILING_BYTES")


def is_rup1(frame: bytes) -> bool:
    return frame[:4] == MAGIC


def _v1_op(frame: bytes):
    if is_rup1(frame) and len(frame) >= HEADER_LEN and frame[4] == VERSION:
        return frame[5]
    return None


def expects_reply(frame: bytes) -> bool:
    """§5: a version 1 request (HAVE never)."""
    return _v1_op(frame) in REQUESTS


def is_terminal_reply(frame: bytes) -> bool:
    """§5: a version 1 reply that ends a request (CHUNK never)."""
    return _v1_op(frame) in TERMINAL_REPLIES


def role(op: int) -> str:
    if op == OP_HAVE:
        return "ONE_WAY"
    if op in REQUESTS:
        return "REQUEST"
    return "TERMINAL_REPLY" if op in TERMINAL_REPLIES else "REPLY"


def _check_refs(adv_serial: int, adv_digest: bytes, log_size: int, log_root: bytes) -> None:
    if (adv_serial == 0) != (adv_digest == bytes(32)):
        raise Rup1Error("BAD_ADVISORY_REF")
    if log_size > tlog.MAX_LOG_ENTRIES or (log_size == 0) != (log_root == bytes(32)):
        raise Rup1Error("BAD_LOG_REF")


def _decode_have(r: _Reader) -> Dict:
    adv_serial, adv_digest = r.int(8), r.take(32)
    if (adv_serial == 0) != (adv_digest == bytes(32)):
        raise Rup1Error("BAD_ADVISORY_REF")
    log_size, log_root = r.int(4), r.take(32)
    _check_refs(adv_serial, adv_digest, log_size, log_root)
    n = r.int(1)
    if n > MAX_OFFERS:
        raise Rup1Error("TOO_MANY_OFFERS")
    offers: List[Offer] = []
    for _ in range(n):
        serial = r.int(8)
        if serial == 0:
            raise Rup1Error("BAD_SERIAL")
        target_len = r.int(1)
        if not 1 <= target_len <= rb.MAX_TARGET_LEN:
            raise Rup1Error("BAD_TARGET")
        target = r.take(target_len)
        if not rb.target_well_formed(target):
            raise Rup1Error("BAD_TARGET")
        digest, payload_len = r.take(32), r.int(8)
        if not 1 <= payload_len <= rb.MAX_PAYLOAD_LEN:
            raise Rup1Error("BAD_PAYLOAD_LEN")
        if any(o.manifest_digest == digest for o in offers):
            raise Rup1Error("DUPLICATE_OFFER")
        offers.append(Offer(serial, target, digest, payload_len))
    return {
        "adv_serial": adv_serial,
        "adv_digest": adv_digest,
        "log_size": log_size,
        "log_root": log_root,
        "offers": offers,
    }


def _snapshot(data: bytes) -> bytes:
    if not 1 <= len(data) <= tlog.MAX_SNAPSHOT_LEN:
        raise Rup1Error("BAD_SNAPSHOT_LEN")
    return data


def _check_range(first: int, count: int) -> None:
    if not 1 <= count <= MAX_CHUNKS_PER_REQUEST:
        raise Rup1Error("BAD_COUNT")
    if first + count > rb.MAX_CHUNKS:
        raise Rup1Error("BAD_INDEX")


def decode(frame: bytes) -> Tuple[bytes, int, Dict]:
    """§4, in order: the magic, the header and the frame length, the
    version, the op, the op's fields with their caps, nothing after them."""
    if not is_rup1(frame):
        raise Rup1Error("NOT_RUP1")
    if len(frame) < HEADER_LEN:
        raise Rup1Error("TRUNCATED")
    if len(frame) > MAX_FRAME_LEN:
        raise Rup1Error("TOO_LONG")
    if frame[4] != VERSION:
        raise Rup1Error("BAD_VERSION")
    op, req_id = frame[5], bytes(frame[6:HEADER_LEN])
    r = _Reader(bytes(frame[HEADER_LEN:]))
    if op == OP_HAVE:
        if req_id != NO_REQ_ID:
            raise Rup1Error("NONZERO_REQ_ID")
        fields = _decode_have(r)
    elif op in (OP_GET_ADVISORY, OP_GET_LOG):
        fields = {}
    elif op == OP_GET_MANIFEST:
        fields = {"manifest_digest": r.take(32)}
    elif op == OP_GET_ROTATION:
        fields = {"key_set_digest": r.take(32)}
    elif op == OP_GET_CHUNKS:
        fields = {"manifest_digest": r.take(32), "first": r.int(4), "count": r.int(1)}
        _check_range(fields["first"], fields["count"])
    elif op in (OP_ADVISORY, OP_MANIFEST):
        n = r.int(2)
        cap, code, key = (
            (ad.MAX_RAD1_LEN, "BAD_RAD1_LEN", "rad1")
            if op == OP_ADVISORY
            else (rb.MAX_MANIFEST_LEN, "BAD_MANIFEST_LEN", "manifest")
        )
        if not 1 <= n <= cap:
            raise Rup1Error(code)
        artifact = r.take(n)
        fields = {key: artifact, "snapshot": _snapshot(r.rest())}
    elif op == OP_LOG:
        fields = {"snapshot": _snapshot(r.rest())}
    elif op == OP_CHUNK:
        index = r.int(4)
        if index >= rb.MAX_CHUNKS:
            raise Rup1Error("BAD_INDEX")
        n = r.int(4)
        if not 1 <= n <= rb.CHUNK_SIZE:
            raise Rup1Error("BAD_CHUNK_LEN")
        data = r.take(n)
        path_len = r.int(1)
        if path_len > rb.MAX_CHUNK_PATH_LEN:
            raise Rup1Error("BAD_PATH_LEN")
        hashes = r.take(32 * path_len)
        fields = {
            "index": index,
            "bytes": data,
            "path": [hashes[i : i + 32] for i in range(0, len(hashes), 32)],
        }
    elif op == OP_CHUNKS_END:
        fields = {"code": r.int(1), "sent": r.int(1)}
        if fields["sent"] > MAX_CHUNKS_PER_REQUEST:
            raise Rup1Error("BAD_COUNT")
    elif op == OP_ERROR:
        fields = {"code": r.int(1)}
        if fields["code"] == 0:
            raise Rup1Error("BAD_CODE")
    else:
        raise Rup1Error("UNKNOWN_OP")
    r.end()
    return req_id, op, fields


def encode(req_id: bytes, op: int, fields: Dict) -> bytes:
    """The frame; refuses what :func:`decode` refuses (checked by decoding
    the result)."""
    f = fields
    if op == OP_HAVE:
        if len(f["offers"]) > MAX_OFFERS:
            raise Rup1Error("TOO_MANY_OFFERS")
        body = (
            f["adv_serial"].to_bytes(8, "big")
            + f["adv_digest"]
            + f["log_size"].to_bytes(4, "big")
            + f["log_root"]
            + bytes([len(f["offers"])])
        )
        for o in f["offers"]:
            body += (
                o.build_serial.to_bytes(8, "big")
                + bytes([len(o.target)])
                + o.target
                + o.manifest_digest
                + o.payload_len.to_bytes(8, "big")
            )
    elif op in (OP_GET_ADVISORY, OP_GET_LOG):
        body = b""
    elif op == OP_GET_MANIFEST:
        body = f["manifest_digest"]
    elif op == OP_GET_ROTATION:
        body = f["key_set_digest"]
    elif op == OP_GET_CHUNKS:
        body = f["manifest_digest"] + f["first"].to_bytes(4, "big") + bytes([f["count"]])
    elif op == OP_ADVISORY:
        body = len(f["rad1"]).to_bytes(2, "big") + f["rad1"] + f["snapshot"]
    elif op == OP_LOG:
        body = f["snapshot"]
    elif op == OP_MANIFEST:
        body = len(f["manifest"]).to_bytes(2, "big") + f["manifest"] + f["snapshot"]
    elif op == OP_CHUNK:
        body = (
            f["index"].to_bytes(4, "big")
            + len(f["bytes"]).to_bytes(4, "big")
            + f["bytes"]
            + bytes([len(f["path"])])
            + b"".join(f["path"])
        )
    elif op == OP_CHUNKS_END:
        body = bytes([f["code"], f["sent"]])
    elif op == OP_ERROR:
        body = bytes([f["code"]])
    else:
        raise Rup1Error("UNKNOWN_OP")
    frame = MAGIC + bytes([VERSION, op]) + req_id + body
    if decode(frame) != (req_id, op, fields):
        raise Rup1Error("NOT_CANONICAL")
    return frame


def listener(frame: bytes) -> str:
    """§6: what a listener does with a frame from its dialer: ``REQUEST``,
    ``HAVE``, ``ERROR UNSUPPORTED``, ``ERROR MALFORMED`` or ``DROP`` (it
    never answers a reply or a HAVE)."""
    if not is_rup1(frame) or len(frame) < HEADER_LEN:
        return "DROP"
    if frame[4] != VERSION:
        return "ERROR UNSUPPORTED"
    op = frame[5]
    try:
        decode(frame)
        ok = True
    except Rup1Error:
        ok = False
    if op == OP_HAVE:
        return "HAVE" if ok else "DROP"
    if op in REQUESTS:
        return "REQUEST" if ok else "ERROR MALFORMED"
    if op >= 0x80:
        return "DROP"
    return "ERROR UNSUPPORTED"


def answered_by(request: Tuple[int, Dict], reply: Tuple[int, Dict]) -> bool:
    """§5: can ``reply`` answer ``request`` (both ``(op, fields)``)?"""
    (q_op, q), (a_op, a) = request, reply
    if q_op not in REQUESTS:
        return False
    if a_op == OP_ERROR:
        return True
    if a_op not in ANSWERS[q_op]:
        return False
    if a_op == OP_CHUNK:
        return q["first"] <= a["index"] < q["first"] + q["count"]
    if a_op == OP_CHUNKS_END:
        return a["sent"] <= q["count"]
    return True


def chunk_checks(root: bytes, payload_len: int, fields: Dict) -> bool:
    """The fetcher's check before writing a chunk (RRB1 ``check_chunk``):
    its length is the chunk's and its path leads to the chunk root."""
    start = fields["index"] * rb.CHUNK_SIZE
    if start >= payload_len or len(fields["bytes"]) != min(rb.CHUNK_SIZE, payload_len - start):
        return False
    count = -(-payload_len // rb.CHUNK_SIZE)
    leaf = tlog.leaf_hash(fields["bytes"])
    return rb.verify_chunk_path(root, count, fields["index"], leaf, fields["path"])
