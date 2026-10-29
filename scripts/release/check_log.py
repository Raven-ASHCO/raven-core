#!/usr/bin/env python3
"""Audit a Raven release log folder: the public ``raven-release-log``
repository (design D §3, owner decision OD6b-22; the folder
``raven-release log append`` keeps, docs/RELEASE_KEY_CEREMONY.md).

Usage:
  check_log.py <log-folder> [--key-set FILE ...] [--against <other copy>]
  check_log.py --self-test

What is checked (exit 1 on any problem; warnings do not fail):

- ``entries.bin``: whole 41-byte RTL1 entries (type 1 manifest, 2 advisory,
  3 key set), at most 1,400 (RTL1 v1 snapshots carry no more; a warning from
  1,000 on, since RTL2 with proofs must ship first), no entry twice,
  ``logged_at_ms`` never going back.
- ``sth/<n>.rtl1``: a tree head of exactly n entries whose root is the
  RFC 6962 root of the first n entries. The newest entries without a tree
  head are a warning.
- ``advisories/*.rad1``, ``manifests/*.rrb1``, ``keysets/*.keyset``: each
  one is listed in the log, and each advisory and manifest the log lists
  has its file.
- ``snapshot.rtl1`` (when present): its entries are the first entries of
  ``entries.bin`` and its tree head is ``sth/<n>.rtl1``.
- ``--key-set`` (a release key set file, bytes or hex; give every set the
  log has used): every tree head, advisory and manifest that names one of
  them is signed by it. This needs the Python reference
  (``protocol/reference``) and its ``cryptography`` package; without them
  the check stops (exit 2) rather than pass unchecked.
- ``--against``: another copy of the log (a mirror, an earlier clone, a
  friend's): one must be the beginning of the other. Two copies that
  disagree are a split view: the signers showed two histories.

Standard library only, except for the signature checks.
"""

import argparse
import hashlib
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

ENTRY_LEN = 41
MAX_LOG_ENTRIES = 1_400
WARN_LOG_ENTRIES = 1_000
STH_SIGNED_LEN = 88
MANIFEST, ADVISORY, KEY_SET = 1, 2, 3
TYPE_NAMES = {MANIFEST: "MANIFEST", ADVISORY: "ADVISORY", KEY_SET: "KEY_SET"}
ADVISORY_DIGEST_DOMAIN = b"rvn1/advisory/digest/v1\0"
MANIFEST_DIGEST_DOMAIN = b"rvn1/release-manifest/digest/v1\0"
KEYSET_DIGEST_DOMAIN = b"rvn1/release-keys/v1\0"

REPO = Path(__file__).resolve().parents[2]


class Report:
    def __init__(self) -> None:
        self.problems: List[str] = []
        self.warnings: List[str] = []

    def problem(self, text: str) -> None:
        self.problems.append(text)

    def warn(self, text: str) -> None:
        self.warnings.append(text)


# ── RFC 6962 (RAVEN_TRANSPARENCY_LOG_V1 §3) ─────────────────────────


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_of(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(root_of(leaves[:k]), root_of(leaves[k:]))


def mth(entries: Sequence[bytes]) -> bytes:
    return root_of([leaf_hash(e) for e in entries])


# ── Files ───────────────────────────────────────────────────────────


def read_entries(folder: Path, report: Report) -> Optional[List[bytes]]:
    path = folder / "entries.bin"
    if not path.is_file():
        report.problem(f"{path}: missing")
        return None
    data = path.read_bytes()
    if len(data) % ENTRY_LEN:
        report.problem(f"{path}: {len(data)} bytes, not whole {ENTRY_LEN}-byte entries")
        return None
    entries = [data[i : i + ENTRY_LEN] for i in range(0, len(data), ENTRY_LEN)]
    if not entries:
        report.problem(f"{path}: empty")
    if len(entries) > MAX_LOG_ENTRIES:
        report.problem(f"{path}: {len(entries)} entries, more than the {MAX_LOG_ENTRIES} RTL1 v1 carries")
    elif len(entries) >= WARN_LOG_ENTRIES:
        report.warn(
            f"{path}: {len(entries)} entries: RTL2 (with audit proofs) must ship before the log reaches {MAX_LOG_ENTRIES}"
        )
    seen = set()
    last_at = 0
    for i, e in enumerate(entries):
        kind, digest, at = e[0], e[1:33], int.from_bytes(e[33:], "big")
        if kind == 0:
            report.problem(f"entry {i + 1}: type 0 is reserved")
        elif kind not in TYPE_NAMES:
            report.warn(f"entry {i + 1}: type {kind} is not known to this checker")
        if (kind, digest) in seen:
            report.problem(f"entry {i + 1}: {TYPE_NAMES.get(kind, kind)} {digest.hex()} is listed twice")
        seen.add((kind, digest))
        if at < last_at:
            report.problem(f"entry {i + 1}: logged at {at} ms, before entry {i} ({last_at} ms)")
        last_at = max(last_at, at)
    return entries


def parse_sth(data: bytes) -> Tuple[int, bytes, int, bytes]:
    """(tree_size, root, timestamp_ms, key_set_digest); raises ValueError."""
    if len(data) < STH_SIGNED_LEN + 1:
        raise ValueError("too short")
    if data[:4] != b"RTL1" or data[4] != 1 or data[5] != 1 or data[6:8] != b"\0\0":
        raise ValueError("not an RTL1 tree head")
    count = data[STH_SIGNED_LEN]
    if len(data) != STH_SIGNED_LEN + 1 + 65 * count:
        raise ValueError("malformed signature block")
    size = int.from_bytes(data[8:16], "big")
    if size == 0:
        raise ValueError("tree size 0")
    return size, data[16:48], int.from_bytes(data[48:56], "big"), data[56:88]


def read_key_set(path: Path) -> bytes:
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii").strip()
        if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) % 2 == 0:
            raw = bytes.fromhex(text)
    except UnicodeDecodeError:
        pass
    if len(raw) < 3 or raw[0] != 1 or not 1 <= raw[2] <= 8 or len(raw) != 3 + 32 * raw[2]:
        raise ValueError(f"{path}: not a release key set")
    return raw


def key_set_digest(raw: bytes) -> bytes:
    return hashlib.sha256(KEYSET_DIGEST_DOMAIN + raw).digest()


class Signatures:
    """The Python reference's verifiers, for the key sets given."""

    def __init__(self, key_sets: Sequence[bytes]):
        sys.path.insert(0, str(REPO / "protocol" / "reference"))
        try:
            from raven_protocol import advisory as ad  # noqa: E402
            from raven_protocol import release_bundle as rb  # noqa: E402
            from raven_protocol import tlog  # noqa: E402
        except ImportError as e:
            raise RuntimeError(
                f"signature checks need the Python reference in protocol/reference and its "
                f"`cryptography` package ({e})"
            ) from None
        self.ad, self.rb, self.tlog = ad, rb, tlog
        self.sets = {}
        for raw in key_sets:
            ks = ad.KeySet.decode(raw)
            self.sets[ks.digest()] = ks

    def check(self, what: str, decode, data: bytes, report: Report) -> None:
        try:
            artifact = decode(data)
        except ValueError as e:
            report.problem(f"{what}: does not decode ({e})")
            return
        ks = self.sets.get(artifact.key_set_digest)
        if ks is None:
            report.warn(f"{what}: names key set {artifact.key_set_digest.hex()}, not one given: not checked")
            return
        try:
            artifact.verify(ks)
        except ValueError as e:
            report.problem(f"{what}: not signed by key set {artifact.key_set_digest.hex()} ({e})")


def check(folder: Path, key_sets: Sequence[bytes] = (), against: Optional[Path] = None) -> Report:
    report = Report()
    sigs = Signatures(key_sets) if key_sets else None
    entries = read_entries(folder, report)
    if entries is None:
        return report
    listed = {(e[0], e[1:33]) for e in entries}

    # Tree heads.
    heads = {}
    for path in sorted((folder / "sth").glob("*.rtl1")) if (folder / "sth").is_dir() else []:
        data = path.read_bytes()
        try:
            size, root, _, _ = parse_sth(data)
        except ValueError as e:
            report.problem(f"{path}: {e}")
            continue
        if path.stem != str(size):
            report.problem(f"{path}: a tree head of {size} entries")
        if size > len(entries):
            report.problem(f"{path}: {size} entries, the log has {len(entries)}")
        elif mth(entries[:size]) != root:
            report.problem(f"{path}: its root is not that of the first {size} entries")
        heads[size] = data
        if sigs:
            sigs.check(str(path), sigs.tlog.decode_sth, data, report)
    if entries and len(entries) not in heads:
        report.warn(f"no signed tree head for all {len(entries)} entries yet (sth/{len(entries)}.rtl1)")

    # Published artifacts.
    published = set()
    for sub, kind, suffix, domain in (
        ("advisories", ADVISORY, ".rad1", ADVISORY_DIGEST_DOMAIN),
        ("manifests", MANIFEST, ".rrb1", MANIFEST_DIGEST_DOMAIN),
    ):
        for path in sorted((folder / sub).glob("*" + suffix)) if (folder / sub).is_dir() else []:
            data = path.read_bytes()
            digest = hashlib.sha256(domain + data).digest()
            published.add((kind, digest))
            if (kind, digest) not in listed:
                report.problem(f"{path}: not listed in the log")
            if sigs:
                decode = sigs.ad.decode if kind == ADVISORY else sigs.rb.decode_manifest
                sigs.check(str(path), decode, data, report)
    for path in sorted((folder / "keysets").glob("*.keyset")) if (folder / "keysets").is_dir() else []:
        try:
            digest = key_set_digest(read_key_set(path))
        except ValueError as e:
            report.problem(str(e))
            continue
        published.add((KEY_SET, digest))
        if (KEY_SET, digest) not in listed:
            report.problem(f"{path}: not listed in the log")
    for kind, digest in sorted(listed):
        if kind in (ADVISORY, MANIFEST) and (kind, digest) not in published:
            report.problem(f"the log lists {TYPE_NAMES[kind]} {digest.hex()}, but its file is not published")

    # The newest snapshot.
    snap = folder / "snapshot.rtl1"
    if snap.is_file():
        data = snap.read_bytes()
        ok = data[:4] == b"RTL1" and len(data) >= 14 and data[4] == 1 and data[5] == 2
        count = int.from_bytes(data[8:12], "big") if ok else 0
        end = 12 + ENTRY_LEN * count
        if not ok or len(data) < end + 2:
            report.problem(f"{snap}: not an RTL1 snapshot")
        else:
            if [data[12 + ENTRY_LEN * i : 12 + ENTRY_LEN * (i + 1)] for i in range(count)] != entries[:count]:
                report.problem(f"{snap}: its entries are not the log's first {count}")
            sth_len = int.from_bytes(data[end : end + 2], "big")
            if data[end + 2 :] != heads.get(count) or len(data) != end + 2 + sth_len:
                report.problem(f"{snap}: its tree head is not sth/{count}.rtl1")

    # Another copy.
    if against is not None:
        other_report = Report()
        other = read_entries(against, other_report)
        if other is None:
            report.problem(f"{against}: {'; '.join(other_report.problems)}")
        else:
            common = min(len(entries), len(other))
            if entries[:common] != other[:common]:
                first = next(i for i in range(common) if entries[i] != other[i])
                report.problem(
                    f"SPLIT VIEW: {folder} and {against} disagree from entry {first + 1} on: "
                    "the signers showed two histories (keep both copies as evidence)"
                )
    return report


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Audit a Raven release log folder.")
    parser.add_argument("folder", nargs="?", type=Path)
    parser.add_argument("--key-set", action="append", type=Path, default=[])
    parser.add_argument("--against", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.folder is None:
        parser.error("give the log folder")
    try:
        key_sets = [read_key_set(p) for p in args.key_set]
        report = check(args.folder, key_sets, args.against)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"check_log: {e}", file=sys.stderr)
        return 2
    for w in report.warnings:
        print(f"warning: {w}")
    for p in report.problems:
        print(f"PROBLEM: {p}")
    entries = (args.folder / "entries.bin").stat().st_size // ENTRY_LEN if (args.folder / "entries.bin").is_file() else 0
    if report.problems:
        print(f"check_log: {len(report.problems)} problem(s) in {args.folder}")
        return 1
    signed = "signatures checked" if key_sets else "signatures not checked (no --key-set)"
    print(f"check_log: OK, {entries} entries, {signed}")
    return 0


# ── Self-test ───────────────────────────────────────────────────────


def _entry(kind: int, digest: bytes, at: int) -> bytes:
    return bytes([kind]) + digest + at.to_bytes(8, "big")


def _sth_body(entries: Sequence[bytes], ks_digest: bytes) -> bytes:
    return (
        b"RTL1\x01\x01\x00\x00"
        + len(entries).to_bytes(8, "big")
        + mth(entries)
        + (1_792_800_000_000).to_bytes(8, "big")
        + ks_digest
    )


def self_test() -> int:
    failures = []

    def expect(name: str, report: Report, problems: bool, warnings: bool = False) -> None:
        if bool(report.problems) != problems or (warnings and not report.warnings):
            failures.append(f"{name}: problems={report.problems} warnings={report.warnings}")

    advisory_bytes = b"RAD1 stand-in bytes (structure is not checked without --key-set)"
    manifest_bytes = b"RRB1 stand-in bytes"
    ks_raw = bytes([1, 2, 1]) + bytes(32)
    adv_digest = hashlib.sha256(ADVISORY_DIGEST_DOMAIN + advisory_bytes).digest()
    man_digest = hashlib.sha256(MANIFEST_DIGEST_DOMAIN + manifest_bytes).digest()
    entries = [
        _entry(ADVISORY, adv_digest, 10),
        _entry(MANIFEST, man_digest, 11),
        _entry(KEY_SET, key_set_digest(ks_raw), 12),
    ]
    zero_sigs = b"\x00"

    def make(folder: Path, entries: Sequence[bytes], heads: Sequence[int] = (3,)) -> Path:
        (folder / "sth").mkdir(parents=True)
        (folder / "advisories").mkdir()
        (folder / "manifests").mkdir()
        (folder / "keysets").mkdir()
        (folder / "entries.bin").write_bytes(b"".join(entries))
        for n in heads:
            (folder / "sth" / f"{n}.rtl1").write_bytes(_sth_body(entries[:n], bytes(32)) + zero_sigs)
        (folder / "advisories" / "1.rad1").write_bytes(advisory_bytes)
        (folder / "manifests" / "1-x86_64-unknown-linux-gnu.rrb1").write_bytes(manifest_bytes)
        (folder / "keysets" / "next.keyset").write_bytes(ks_raw.hex().encode() + b"\n")
        return folder

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        good = make(root / "good", entries, (2, 3))
        expect("a good log", check(good), False)
        sth = (good / "sth" / "3.rtl1").read_bytes()
        (good / "snapshot.rtl1").write_bytes(
            b"RTL1\x01\x02\x00\x00" + (3).to_bytes(4, "big") + b"".join(entries) + len(sth).to_bytes(2, "big") + sth
        )
        expect("a good log with its snapshot", check(good), False)

        bad = make(root / "bad-root", entries)
        (bad / "sth" / "3.rtl1").write_bytes(_sth_body(entries[:2] + [entries[0]], bytes(32)) + zero_sigs)
        expect("a tree head with another root", check(bad), True)

        bad = make(root / "misnamed", entries)
        os.rename(bad / "sth" / "3.rtl1", bad / "sth" / "4.rtl1")
        expect("a misnamed tree head", check(bad), True)

        bad = make(root / "twice", entries + [_entry(ADVISORY, adv_digest, 13)], ())
        expect("an entry listed twice", check(bad), True)

        bad = make(root / "back", entries + [_entry(ADVISORY, bytes(32), 1)], ())
        expect("an entry logged in the past", check(bad), True)

        bad = make(root / "trailing", entries)
        with open(bad / "entries.bin", "ab") as f:
            f.write(b"\x01")
        expect("trailing bytes", check(bad), True)

        bad = make(root / "unlisted", entries)
        (bad / "advisories" / "2.rad1").write_bytes(b"another advisory")
        expect("a published advisory the log does not list", check(bad), True)

        bad = make(root / "unpublished", entries)
        (bad / "manifests" / "1-x86_64-unknown-linux-gnu.rrb1").unlink()
        expect("a listed manifest without its file", check(bad), True)

        no_head = make(root / "no-head", entries, (2,))
        expect("the newest entries without a tree head", check(no_head), False, warnings=True)

        many = [_entry(KEY_SET, hashlib.sha256(i.to_bytes(4, "big")).digest(), 20 + i) for i in range(WARN_LOG_ENTRIES)]
        big = make(root / "big", entries + many, ())
        expect("1,000 entries warn", check(big), False, warnings=True)
        many = [_entry(KEY_SET, hashlib.sha256(i.to_bytes(4, "big")).digest(), 20 + i) for i in range(MAX_LOG_ENTRIES)]
        too_big = make(root / "too-big", entries + many, ())
        expect("more than 1,400 entries", check(too_big), True)

        longer = make(root / "longer", entries + [_entry(KEY_SET, bytes(32), 14)], (3, 4))
        expect("a copy that extends this one", check(good, against=longer), False)
        expect("a copy this one extends", check(longer, against=good), False)
        split = make(root / "split", [entries[0], entries[2], entries[1]], ())
        report = check(good, against=split)
        expect("a split view", report, True)
        if not any("SPLIT VIEW" in p for p in report.problems):
            failures.append(f"a split view is named: {report.problems}")

        signature_note = signature_self_test(root, failures)

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print(f"check_log self-test: OK ({signature_note})")
    return 0


def signature_self_test(root: Path, failures: List[str]) -> str:
    """With the Python reference: tree heads, an advisory and a manifest
    signed by the published test keys check; one signature, or a changed
    one, does not."""
    try:
        sigs = Signatures([])
    except RuntimeError as e:
        return f"signature checks skipped: {e}"
    ad, rb, tlog = sigs.ad, sigs.rb, sigs.tlog
    seeds = [bytes([b]) * 32 for b in (0x11, 0x22, 0x33)]
    ks = ad.KeySet.of_seeds(2, seeds)
    ks_raw = ks.encode()
    two = [(0, seeds[0]), (2, seeds[2])]
    advisory = ad.build(ad.encode_body(1, 1_792_800_000_000, ks.digest(), bytes(32), []), two)
    files, payload = rb.pack([(b"bin/raven", 1, b"\x7fELF test", bytes(32))])
    manifest = rb.build_manifest(
        rb.encode_manifest_body(
            build_serial=1,
            created_at_ms=1_792_800_000_000,
            key_set_digest=ks.digest(),
            version=b"0.1.0",
            target=b"x86_64-unknown-linux-gnu",
            source_commit=bytes(20),
            toolchain=b"1.98.0",
            min_advisory_serial=0,
            payload_len=len(payload),
            payload_chunk_root=rb.chunk_root(payload),
            payload_sha256=hashlib.sha256(payload).digest(),
            files=files,
            notes=b"",
        ),
        two,
    )
    entries = [
        _entry(ADVISORY, hashlib.sha256(ADVISORY_DIGEST_DOMAIN + advisory).digest(), 1),
        _entry(MANIFEST, hashlib.sha256(MANIFEST_DIGEST_DOMAIN + manifest).digest(), 2),
    ]

    def make(name: str, heads: Sequence[Tuple[int, Sequence[Tuple[int, bytes]]]]) -> Path:
        folder = root / name
        for sub in ("sth", "advisories", "manifests"):
            (folder / sub).mkdir(parents=True)
        (folder / "entries.bin").write_bytes(b"".join(entries))
        (folder / "advisories" / "1.rad1").write_bytes(advisory)
        (folder / "manifests" / "1-x86_64-unknown-linux-gnu.rrb1").write_bytes(manifest)
        for n, signers in heads:
            body = _sth_body(entries[:n], ks.digest())
            (folder / "sth" / f"{n}.rtl1").write_bytes(tlog.build_sth(body, signers))
        return folder

    good = make("signed", [(1, two), (2, [(1, seeds[1]), (2, seeds[2])])])
    report = check(good, [ks_raw])
    if report.problems or report.warnings:
        failures.append(f"a signed log: {report.problems} {report.warnings}")
    weak = make("one-signature", [(2, [(0, seeds[0])])])
    if not check(weak, [ks_raw]).problems:
        failures.append("a tree head with one signature passed")
    changed = make("changed-signature", [(2, two)])
    head = bytearray((changed / "sth" / "2.rtl1").read_bytes())
    head[-1] ^= 1
    (changed / "sth" / "2.rtl1").write_bytes(bytes(head))
    if not check(changed, [ks_raw]).problems:
        failures.append("a changed signature passed")
    other = ad.KeySet.of_seeds(2, [bytes([b]) * 32 for b in (0x44, 0x55, 0x66)])
    report = check(good, [other.encode()])
    if report.problems or not report.warnings:
        failures.append(f"another key set is reported, not refused: {report.problems} {report.warnings}")
    return "signature checks run"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
