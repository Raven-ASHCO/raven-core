"""RAVEN Release Bundle V1 (RAVEN_RELEASE_BUNDLE_V1.md, draft): release
manifests (RRB1, §3-§4), payload chunks and their audit paths (§5), the
``.rrb`` container (RRBC, §6) and bundle verification (§7).

An independent reference for the Rust code (``raven_core::release_bundle``)
and the ``rrb1_*`` / ``rrbc_*`` vectors in ``shared-vectors/rvn1/update``
(which Rust writes and :mod:`tests.test_release_bundle` checks against this
module, building every signed manifest and container again byte for byte,
computing every chunk root and audit path by the RFC 6962 definitions and
running every verification case). Key sets, signature blocks and advisories
are :mod:`raven_protocol.advisory`'s; logs are :mod:`raven_protocol.tlog`'s.

Pure: no clock, no randomness.
"""

import hashlib
from typing import List, NamedTuple, Optional, Sequence, Tuple

from . import advisory as ad
from . import tlog

MAGIC = b"RRB1"
VERSION = 0x01
KIND_MANIFEST = 0x01
MAX_FILES = 16
MAX_VERSION_LEN = 32
MAX_TARGET_LEN = 64
SOURCE_COMMIT_LEN = 20
MAX_TOOLCHAIN_LEN = 32
CHUNK_SIZE = 61_440
MAX_PAYLOAD_LEN = 64 * 1024 * 1024
MAX_CHUNKS = -(-MAX_PAYLOAD_LEN // CHUNK_SIZE)
MAX_CHUNK_PATH_LEN = 11
MAX_PATH_LEN = 64
MAX_PATH_SEGMENTS = 3
PATH_ROOTS = (b"bin", b"docs")
MAX_NOTES_LEN = 2_048
FILE_FIXED_LEN = 1 + 1 + 8 + 8 + 32 + 32
MANIFEST_FIXED_LEN = 8 + 8 + 8 + 32 + 1 + 1 + SOURCE_COMMIT_LEN + 1 + 8 + 4 + 8 + 32 + 32 + 2
MAX_MANIFEST_LEN = (
    MANIFEST_FIXED_LEN
    + MAX_VERSION_LEN
    + MAX_TARGET_LEN
    + MAX_TOOLCHAIN_LEN
    + MAX_FILES * (FILE_FIXED_LEN + MAX_PATH_LEN)
    + MAX_NOTES_LEN
    + 1
    + ad.SIG_ENTRY_LEN * ad.KEYSET_MAX_KEYS
)
SIGNING_DOMAIN = b"rvn1/release-manifest/v1\0"
DIGEST_DOMAIN = b"rvn1/release-manifest/digest/v1\0"

CONTAINER_MAGIC = b"RRBC"
CONTAINER_VERSION = 0x01

_DIGITS = frozenset(b"0123456789")
_ALNUM = frozenset(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_SUFFIX_BYTES = _ALNUM | frozenset(b".+-")
_TARGET_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789_.-")
_TOOLCHAIN_BYTES = _ALNUM | frozenset(b"._+-")
_PATH_BYTES = _ALNUM | frozenset(b"._-")
_DEVICES = (b"con", b"prn", b"aux", b"nul")


class Rrb1Error(ValueError):
    """Refused manifest bytes (§4); ``code`` is the name the vectors use."""

    def __init__(self, code: str):
        super().__init__(f"RRB1 {code}")
        self.code = code


class RrbcError(ValueError):
    """Refused container bytes (§6); ``inner`` is a refused part's own code."""

    def __init__(self, code: str, inner: Optional[str] = None):
        super().__init__(f"RRBC {code} {inner or ''}".strip())
        self.code = code
        self.inner = inner


class BundleError(ValueError):
    """A bundle refused by :func:`verify_bundle` (§7)."""

    def __init__(self, code: str, inner: Optional[str] = None, file_index: Optional[int] = None):
        super().__init__(f"RRB1 {code} {inner or ''}".strip())
        self.code = code
        self.inner = inner
        self.file_index = file_index


# §3.2-§3.3: field rules.


def version_well_formed(v: bytes) -> bool:
    """1..=32 bytes: three dot-separated digit runs, then nothing or a ``-``
    or ``+`` suffix of [0-9A-Za-z.+-] with at least one byte after the sign."""
    if not 1 <= len(v) <= MAX_VERSION_LEN:
        return False
    cut = min([i for i in (v.find(b"-"), v.find(b"+")) if i >= 0], default=len(v))
    core, suffix = v[:cut], v[cut:]
    parts = core.split(b".")
    if len(parts) != 3 or not all(p and all(b in _DIGITS for b in p) for p in parts):
        return False
    return not suffix or (len(suffix) > 1 and all(b in _SUFFIX_BYTES for b in suffix))


def target_well_formed(t: bytes) -> bool:
    """1..=64 bytes of [a-z0-9_.-], two or more non-empty ``-`` segments."""
    segments = t.split(b"-")
    return (
        1 <= len(t) <= MAX_TARGET_LEN
        and all(b in _TARGET_BYTES for b in t)
        and len(segments) >= 2
        and all(segments)
    )


def toolchain_well_formed(t: bytes) -> bool:
    """1..=32 bytes of [0-9A-Za-z._+-]."""
    return 1 <= len(t) <= MAX_TOOLCHAIN_LEN and all(b in _TOOLCHAIN_BYTES for b in t)


def _windows_device(segment: bytes) -> bool:
    stem = segment.split(b".")[0].lower()
    if stem in _DEVICES:
        return True
    return len(stem) == 4 and stem[:3] in (b"com", b"lpt") and stem[3] in _DIGITS


def path_well_formed(p: bytes) -> bool:
    """1..=64 bytes; 2 or 3 ``/`` segments, the first ``bin`` or ``docs``;
    each segment [A-Za-z0-9._-]+, not ending in ``.``, not a Windows device."""
    if not 1 <= len(p) <= MAX_PATH_LEN:
        return False
    segments = p.split(b"/")
    return (
        2 <= len(segments) <= MAX_PATH_SEGMENTS
        and segments[0] in PATH_ROOTS
        and all(
            s and all(b in _PATH_BYTES for b in s) and not s.endswith(b".") and not _windows_device(s)
            for s in segments
        )
    )


def paths_collide(a: bytes, b: bytes) -> bool:
    """The same file ignoring ASCII case, or one a directory of the other."""
    a, b = a.lower(), b.lower()
    return a == b or b.startswith(a + b"/") or a.startswith(b + b"/")


# §3-§4: the manifest.


class FileEntry(NamedTuple):
    path: bytes
    mode: int
    offset: int
    size: int
    sha256: bytes
    rebuild_sha256: bytes


class Manifest(NamedTuple):
    build_serial: int
    created_at_ms: int
    key_set_digest: bytes
    version: bytes
    target: bytes
    source_commit: bytes
    toolchain: bytes
    min_advisory_serial: int
    chunk_size: int
    payload_len: int
    payload_chunk_root: bytes
    payload_sha256: bytes
    files: List[FileEntry]
    notes: bytes
    sigs: List[Tuple[int, bytes]]
    data: bytes
    signed_len: int

    def signing_input(self) -> bytes:
        return SIGNING_DOMAIN + self.data[: self.signed_len]

    def digest(self) -> bytes:
        return hashlib.sha256(DIGEST_DOMAIN + self.data).digest()

    def verify(self, key_set: ad.KeySet) -> None:
        """Raises :class:`raven_protocol.advisory.SigError`."""
        if self.key_set_digest != key_set.digest():
            raise ad.SigError("WRONG_KEY_SET")
        key_set.verify_sigs(self.signing_input(), self.sigs)

    def chunk_count(self) -> int:
        return -(-self.payload_len // self.chunk_size)

    def chunk_len(self, index: int) -> Optional[int]:
        start = index * self.chunk_size
        return min(self.payload_len - start, self.chunk_size) if 0 <= start < self.payload_len else None

    def check_chunk(self, index: int, chunk: bytes, path: Sequence[bytes]) -> bool:
        return (
            self.chunk_len(index) == len(chunk)
            and len(path) <= MAX_CHUNK_PATH_LEN
            and verify_chunk_path(self.payload_chunk_root, self.chunk_count(), index, tlog.leaf_hash(chunk), path)
        )


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.at = 0

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise Rrb1Error("TRUNCATED")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def short(self, max_len: int, ok, code: str) -> bytes:
        n = self.uint(1)
        if not 1 <= n <= max_len:
            raise Rrb1Error(code)
        value = self.take(n)
        if not ok(value):
            raise Rrb1Error(code)
        return value


def decode_manifest(data: bytes) -> Manifest:
    """Strict decode in the order of §4; raises :class:`Rrb1Error`."""
    data = bytes(data)
    if len(data) > MAX_MANIFEST_LEN:
        raise Rrb1Error("TOO_LONG")
    r = _Reader(data)
    if r.take(4) != MAGIC:
        raise Rrb1Error("BAD_MAGIC")
    if r.uint(1) != VERSION:
        raise Rrb1Error("BAD_VERSION")
    if r.uint(1) != KIND_MANIFEST:
        raise Rrb1Error("BAD_KIND")
    file_count = r.uint(1)
    if not 1 <= file_count <= MAX_FILES:
        raise Rrb1Error("BAD_FILE_COUNT")
    if r.uint(1) != 0:
        raise Rrb1Error("BAD_RESERVED")
    build_serial = r.uint(8)
    if build_serial == 0:
        raise Rrb1Error("BAD_SERIAL")
    created_at_ms = r.uint(8)
    key_set_digest = r.take(32)
    version = r.short(MAX_VERSION_LEN, version_well_formed, "BAD_RELEASE_VERSION")
    target = r.short(MAX_TARGET_LEN, target_well_formed, "BAD_TARGET")
    source_commit = r.take(SOURCE_COMMIT_LEN)
    toolchain = r.short(MAX_TOOLCHAIN_LEN, toolchain_well_formed, "BAD_TOOLCHAIN")
    min_advisory_serial = r.uint(8)
    chunk_size = r.uint(4)
    if chunk_size != CHUNK_SIZE:
        raise Rrb1Error("BAD_CHUNK_SIZE")
    payload_len = r.uint(8)
    if not 1 <= payload_len <= MAX_PAYLOAD_LEN:
        raise Rrb1Error("BAD_PAYLOAD_LEN")
    payload_chunk_root = r.take(32)
    payload_sha256 = r.take(32)
    files: List[FileEntry] = []
    end = 0
    for _ in range(file_count):
        path = r.short(MAX_PATH_LEN, path_well_formed, "BAD_PATH")
        if any(paths_collide(f.path, path) for f in files):
            raise Rrb1Error("DUPLICATE_PATH")
        mode = r.uint(1)
        if mode > 1:
            raise Rrb1Error("BAD_MODE")
        offset = r.uint(8)
        if offset < end:
            raise Rrb1Error("OVERLAP")
        if offset > end:
            raise Rrb1Error("GAP")
        size = r.uint(8)
        end = offset + size
        if end > payload_len:
            raise Rrb1Error("BAD_COVERAGE")
        files.append(FileEntry(path, mode, offset, size, r.take(32), r.take(32)))
    if end != payload_len:
        raise Rrb1Error("BAD_COVERAGE")
    notes_len = r.uint(2)
    if notes_len > MAX_NOTES_LEN:
        raise Rrb1Error("BAD_NOTES")
    notes = r.take(notes_len)
    try:
        notes.decode("utf-8")
    except UnicodeDecodeError:
        raise Rrb1Error("BAD_NOTES") from None
    signed_len = r.at
    try:
        sigs = ad.decode_sig_block(data[signed_len:])
    except ad.SigError:
        raise Rrb1Error("BAD_SIG_BLOCK") from None
    return Manifest(
        build_serial,
        created_at_ms,
        key_set_digest,
        version,
        target,
        source_commit,
        toolchain,
        min_advisory_serial,
        chunk_size,
        payload_len,
        payload_chunk_root,
        payload_sha256,
        files,
        notes,
        sigs,
        data,
        signed_len,
    )


def _short(value: bytes) -> bytes:
    return bytes([len(value)]) + value


def encode_manifest_body(
    *,
    build_serial: int,
    created_at_ms: int,
    key_set_digest: bytes,
    version: bytes,
    target: bytes,
    source_commit: bytes,
    toolchain: bytes,
    min_advisory_serial: int,
    payload_len: int,
    payload_chunk_root: bytes,
    payload_sha256: bytes,
    files: Sequence[FileEntry],
    notes: bytes,
    chunk_size: int = CHUNK_SIZE,
) -> bytes:
    """The bytes before the signature block (not checked: decode checks)."""
    out = bytearray(MAGIC)
    out += bytes([VERSION, KIND_MANIFEST, len(files), 0])
    out += build_serial.to_bytes(8, "big") + created_at_ms.to_bytes(8, "big") + key_set_digest
    out += _short(version) + _short(target) + source_commit + _short(toolchain)
    out += min_advisory_serial.to_bytes(8, "big") + chunk_size.to_bytes(4, "big")
    out += payload_len.to_bytes(8, "big") + payload_chunk_root + payload_sha256
    for f in files:
        out += _short(f.path) + bytes([f.mode]) + f.offset.to_bytes(8, "big") + f.size.to_bytes(8, "big")
        out += f.sha256 + f.rebuild_sha256
    out += len(notes).to_bytes(2, "big") + notes
    return bytes(out)


def build_manifest(body: bytes, signers: Sequence[Tuple[int, bytes]]) -> bytes:
    """``body`` signed by each ``(key_index, seed)`` in order."""
    message = SIGNING_DOMAIN + body
    return body + ad.encode_sig_block([(i, ad.sign(seed, message)) for i, seed in signers])


def pack(files: Sequence[Tuple[bytes, int, bytes, bytes]]) -> Tuple[List[FileEntry], bytes]:
    """``(path, mode, content, rebuild_sha256)`` back to back: the entries and
    the payload."""
    entries, payload = [], b""
    for path, mode, content, rebuild in files:
        entries.append(FileEntry(path, mode, len(payload), len(content), hashlib.sha256(content).digest(), rebuild))
        payload += content
    return entries, payload


# §5: chunks.


def chunk_leaf_hashes(payload: bytes, chunk_size: int = CHUNK_SIZE) -> List[bytes]:
    return [tlog.leaf_hash(payload[i : i + chunk_size]) for i in range(0, len(payload), chunk_size)]


def chunk_root(payload: bytes, chunk_size: int = CHUNK_SIZE) -> bytes:
    return tlog.root_of_leaf_hashes(chunk_leaf_hashes(payload, chunk_size))


def chunk_path(index: int, leaves: Sequence[bytes]) -> List[bytes]:
    """RFC 6962 §2.1.1 PATH(m, D[n]), from the leaf's sibling up."""
    n = len(leaves)
    if n <= 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if index < k:
        return chunk_path(index, leaves[:k]) + [tlog.root_of_leaf_hashes(leaves[k:])]
    return chunk_path(index - k, leaves[k:]) + [tlog.root_of_leaf_hashes(leaves[:k])]


def verify_chunk_path(root: bytes, count: int, index: int, leaf: bytes, path: Sequence[bytes]) -> bool:
    """RFC 9162 §2.1.3.2: does ``path`` prove ``leaf`` is leaf ``index`` of a
    tree of ``count`` leaves with this ``root``?"""
    if index >= count:
        return False
    fn, sn, r = index, count - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = tlog.node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = tlog.node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# §6: the container.


class Parts(NamedTuple):
    manifest: Manifest
    snapshot: tlog.Snapshot
    advisory: Optional[ad.Advisory]
    payload: bytes


def encode_container(manifest: bytes, snapshot: bytes, advisory: bytes, payload: bytes) -> bytes:
    out = bytearray(CONTAINER_MAGIC) + bytes([CONTAINER_VERSION, 0, 0, 0])
    for part in (manifest, snapshot, advisory):
        out += len(part).to_bytes(4, "big") + part
    return bytes(out + payload)


def open_container(data: bytes) -> Parts:
    """Decode a container in the order of §6; raises :class:`RrbcError`."""
    data = bytes(data)
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if at + n > len(data):
            raise RrbcError("TRUNCATED")
        at += n
        return data[at - n : at]

    if take(4) != CONTAINER_MAGIC:
        raise RrbcError("BAD_MAGIC")
    if take(1)[0] != CONTAINER_VERSION:
        raise RrbcError("BAD_VERSION")
    if take(3) != b"\0\0\0":
        raise RrbcError("BAD_RESERVED")
    n = int.from_bytes(take(4), "big")
    if not 1 <= n <= MAX_MANIFEST_LEN:
        raise RrbcError("BAD_MANIFEST_LEN")
    try:
        manifest = decode_manifest(take(n))
    except Rrb1Error as e:
        raise RrbcError("MANIFEST", e.code) from None
    n = int.from_bytes(take(4), "big")
    if not 1 <= n <= tlog.MAX_SNAPSHOT_LEN:
        raise RrbcError("BAD_SNAPSHOT_LEN")
    try:
        snapshot = tlog.decode_snapshot(take(n))
    except tlog.Rtl1Error as e:
        raise RrbcError("SNAPSHOT", e.code) from None
    n = int.from_bytes(take(4), "big")
    if n > ad.MAX_RAD1_LEN:
        raise RrbcError("BAD_ADVISORY_LEN")
    advisory = None
    if n:
        try:
            advisory = ad.decode(take(n))
        except ad.Rad1Error as e:
            raise RrbcError("ADVISORY", e.code) from None
    payload = take(manifest.payload_len)
    if at != len(data):
        raise RrbcError("TRAILING_BYTES")
    return Parts(manifest, snapshot, advisory, payload)


# §7: verification.


class Ctx(NamedTuple):
    key_set: Optional[ad.KeySet]
    stored_log: List[tlog.Entry]
    installed_serial: int
    target: bytes
    release_floor: int
    allow_downgrade: bool


class Verified(NamedTuple):
    authority: str
    consistency: str
    release_floor: int


def _release_floor(advisory: ad.Advisory) -> Optional[int]:
    for e in advisory.entries:
        if e.kind == ad.RELEASE_FLOOR:
            return int.from_bytes(e.arg, "big")
    return None


def verify_bundle(parts: Parts, ctx: Ctx) -> Verified:
    """§7 in order; raises :class:`BundleError`."""
    ks = ctx.key_set
    if ks is None:
        raise BundleError("NO_RELEASE_KEYS")
    m = parts.manifest
    authority = "SIGNED"
    try:
        m.verify(ks)
    except ad.SigError as e:
        if e.code != "WRONG_KEY_SET":
            raise BundleError("MANIFEST_SIG", e.code) from None
        authority = "LOGGED"
    try:
        tlog.check(parts.snapshot, ks)
    except tlog.LogCheckError as e:
        raise BundleError("LOG", e.code) from None
    entries = parts.snapshot.entries
    if not tlog.contains(entries, tlog.MANIFEST, m.digest()):
        if authority == "LOGGED":
            raise BundleError("MANIFEST_SIG", "WRONG_KEY_SET")
        raise BundleError("UNLOGGED")
    consistency = tlog.consistency(ctx.stored_log, entries)
    if consistency == "SPLIT":
        raise BundleError("SPLIT_VIEW")
    floor = ctx.release_floor
    if parts.advisory is not None:
        try:
            parts.advisory.verify(ks)
        except ad.SigError as e:
            raise BundleError("ADVISORY_SIG", e.code) from None
        if not tlog.contains(entries, tlog.ADVISORY, parts.advisory.digest()):
            raise BundleError("ADVISORY_UNLOGGED")
        adv_floor = _release_floor(parts.advisory)
        if adv_floor is not None:
            floor = max(floor, adv_floor)
    if m.target != ctx.target:
        raise BundleError("WRONG_TARGET")
    if m.build_serial <= ctx.installed_serial and not ctx.allow_downgrade:
        raise BundleError("DOWNGRADE")
    if m.build_serial < floor:
        raise BundleError("BELOW_FLOOR")
    payload = parts.payload
    if len(payload) != m.payload_len:
        raise BundleError("PAYLOAD_LENGTH")
    if chunk_root(payload, m.chunk_size) != m.payload_chunk_root:
        raise BundleError("BAD_CHUNK_ROOT")
    if hashlib.sha256(payload).digest() != m.payload_sha256:
        raise BundleError("BAD_PAYLOAD_HASH")
    for i, f in enumerate(m.files):
        if hashlib.sha256(payload[f.offset : f.offset + f.size]).digest() != f.sha256:
            raise BundleError("BAD_FILE_HASH", file_index=i)
    return Verified(authority, consistency, floor)
