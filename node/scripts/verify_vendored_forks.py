#!/usr/bin/env python3
"""Provenance of the crates.io forks Raven vendors (security review 2026-11, DEP-5).

The forks under node/third_party/ are wired in through [patch.crates-io] as
path dependencies, so Cargo.lock holds no checksum for them, and only review
of node/third_party/ stood between an undeclared edit (arti-client's circuit
code, the secret-service session DH) and a release. node/third_party/forks.json
records, for each fork, its crates.io archive (name, version, SHA-256) and its
delta: the upstream files it modifies and the files it adds, each with the
SHA-256 of the fork's bytes, and the upstream files it leaves out. This checks
that every file git tracks in a fork's folder is upstream's byte for byte,
except exactly that delta, and that the folder holds nothing else (no
symlink, no submodule, no file the record does not name). A fork whose delta
has a dedicated verifier (libsqlite3-sys-raven: the SQLite amalgamation and
the build.rs pins) names it in the record, and CI must run that verifier.
Every [patch.crates-io] path in node/Cargo.toml must have a record, and every
folder in node/third_party/ must be a record or an entry of not_forks.

  verify_vendored_forks.py --crate-dir DIR   # <name>-<version>.crate files in DIR
                                             # (offline: ~/.cargo/registry/cache/index.crates.io-*)
  verify_vendored_forks.py --download DIR    # fetch them into DIR from static.crates.io first
  add --self-test                            # planted changes to copies must be caught

Each archive must match its pinned SHA-256 whichever way it came. Reads only;
the self test changes copies in a temporary folder. Exit 0 when every check
passes, 1 when one fails, 2 when it cannot check.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
REPO = SCRIPT_DIR.parent.parent
TABLE = Path("node/third_party/forks.json")
WORKFLOWS = Path(".github/workflows")
CRATE_URL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class CannotCheck(Exception):
    """The check could not run (input missing or malformed): exit 2."""


class ForkMismatch(Exception):
    """A fork, or its archive, is not what its record says: exit 1."""

    def __init__(self, problems: List[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relative_path(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise CannotCheck(f"{what}: not a path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise CannotCheck(f"{what}: not a plain relative path: {value!r}")
    return value


def pin_map(value: Any, what: str) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise CannotCheck(f"{what}: not an object")
    for path, pin in value.items():
        relative_path(path, what)
        if not isinstance(pin, str) or not SHA256_HEX.match(pin):
            raise CannotCheck(f"{what} {path}: not a SHA256 pin")
    return value


def load_table(repo: Path) -> Dict[str, Any]:
    try:
        document = json.loads((repo / TABLE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CannotCheck(f"cannot read {TABLE}: {error}") from error
    if document.get("schema") != 1:
        raise CannotCheck(f"{TABLE}: schema must be exactly 1")
    forks = document.get("forks")
    if not isinstance(forks, list) or not forks:
        raise CannotCheck(f"{TABLE}: no forks")
    seen = set()
    for fork in forks:
        try:
            path = relative_path(fork["path"], "fork path")
            if not path.startswith("node/third_party/") or path.count("/") != 2:
                raise CannotCheck(f"{path}: a fork lives directly in node/third_party/")
            for key in ("lock_name", "lock_version"):
                if not isinstance(fork[key], str) or not fork[key]:
                    raise CannotCheck(f"{path}: {key} missing")
            upstream = fork["upstream"]
            for key in ("name", "version"):
                if not isinstance(upstream[key], str) or not upstream[key]:
                    raise CannotCheck(f"{path}: upstream {key} missing")
            if not SHA256_HEX.match(upstream["crate_sha256"]):
                raise CannotCheck(f"{path}: upstream crate_sha256 is not a SHA256")
        except (KeyError, TypeError) as error:
            raise CannotCheck(f"{TABLE}: malformed fork record {fork!r}") from error
        if path in seen:
            raise CannotCheck(f"{TABLE}: {path} recorded twice")
        seen.add(path)
        if ("delta" in fork) == ("delta_verifier" in fork):
            raise CannotCheck(f"{path}: give exactly one of delta and delta_verifier")
        if "delta" in fork:
            delta = fork["delta"]
            modified = pin_map(delta.get("modified"), f"{path} modified")
            added = pin_map(delta.get("added"), f"{path} added")
            removed = delta.get("removed")
            if not isinstance(removed, list):
                raise CannotCheck(f"{path}: removed must be a list")
            for item in removed:
                relative_path(item, f"{path} removed")
            if (set(modified) & set(added)) or (set(removed) & (set(modified) | set(added))):
                raise CannotCheck(f"{path}: a file is declared twice in the delta")
        else:
            relative_path(fork["delta_verifier"], f"{path} delta_verifier")
    not_forks = document.get("not_forks", [])
    if not isinstance(not_forks, list):
        raise CannotCheck(f"{TABLE}: not_forks must be a list")
    for entry in not_forks:
        if not isinstance(entry, dict) or not isinstance(entry.get("why"), str) or not entry["why"].strip():
            raise CannotCheck(f"{TABLE}: a not_forks entry needs a path and a why: {entry!r}")
        relative_path(entry.get("path"), "not_forks path")
    return document


def upstream_files(archive: bytes, name: str, version: str) -> Dict[str, bytes]:
    """The archive's regular files by relative path, read in memory (nothing is extracted)."""
    root = f"{name}-{version}"
    files: Dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != root:
                    raise CannotCheck(f"{root}.crate: unsafe member {member.name!r}")
                if member.isdir():
                    continue
                if not member.isreg():
                    raise CannotCheck(f"{root}.crate: {member.name} is not a regular file")
                relative = str(PurePosixPath(*path.parts[1:]))
                if relative in files:
                    raise CannotCheck(f"{root}.crate: {relative} twice")
                handle = tar.extractfile(member)
                if handle is None:
                    raise CannotCheck(f"{root}.crate: cannot read {member.name}")
                files[relative] = handle.read()
    except (tarfile.TarError, OSError, EOFError) as error:
        raise CannotCheck(f"{root}.crate: not a readable archive: {error}") from error
    if not files:
        raise CannotCheck(f"{root}.crate: empty")
    return files


def tracked_files(repo: Path, fork_path: str) -> Dict[str, bytes]:
    """What git tracks in the fork's folder, read from the working tree."""
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-s", "-z", "--", fork_path + "/"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise CannotCheck(f"git ls-files failed in {repo}: {result.stderr.decode(errors='replace').strip()}")
    files: Dict[str, bytes] = {}
    problems = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        meta, _, raw_path = record.partition(b"\t")
        mode = meta.split()[0].decode()
        repo_path = raw_path.decode("utf-8", errors="surrogateescape")
        relative = repo_path[len(fork_path) + 1 :]
        if mode not in ("100644", "100755"):
            problems.append(f"{relative}: git keeps it as mode {mode}, not a regular file")
            continue
        on_disk = repo / repo_path
        if on_disk.is_symlink() or not on_disk.is_file():
            problems.append(f"{relative}: not a regular file in the working tree")
            continue
        files[relative] = on_disk.read_bytes()
    if problems:
        raise ForkMismatch(problems)
    if not files:
        raise CannotCheck(f"{fork_path}: git tracks no files there")
    return files


def compare(fork: Dict[str, Any], upstream: Dict[str, bytes], tracked: Dict[str, bytes]) -> List[str]:
    delta = fork["delta"]
    modified: Dict[str, str] = delta["modified"]
    added: Dict[str, str] = delta["added"]
    removed = set(delta["removed"])
    problems = []
    for relative in sorted(upstream):
        data = upstream[relative]
        if relative in removed:
            if relative in tracked:
                problems.append(f"{relative}: declared left out, but the fork has it")
            continue
        if relative not in tracked:
            problems.append(f"{relative}: upstream file missing from the fork (not declared left out)")
            continue
        if relative in modified:
            if tracked[relative] == data:
                problems.append(f"{relative}: declared modified, but it is the upstream file")
            elif sha256(tracked[relative]) != modified[relative]:
                problems.append(
                    f"{relative}: modified, but not the pinned modification "
                    f"(SHA256 {sha256(tracked[relative])}, pinned {modified[relative]})"
                )
        elif tracked[relative] != data:
            problems.append(f"{relative}: changed from upstream, and the record does not declare it")
    for relative in sorted(tracked):
        if relative in upstream:
            continue
        if relative not in added:
            problems.append(f"{relative}: not in upstream, and the record does not declare it added")
        elif sha256(tracked[relative]) != added[relative]:
            problems.append(
                f"{relative}: added, but not the pinned file "
                f"(SHA256 {sha256(tracked[relative])}, pinned {added[relative]})"
            )
    for relative in sorted(modified):
        if relative not in upstream:
            problems.append(f"{relative}: declared modified, but upstream has no such file")
    for relative in sorted(added):
        if relative in upstream:
            problems.append(f"{relative}: declared added, but upstream has it")
        elif relative not in tracked:
            problems.append(f"{relative}: declared added, but the fork does not have it")
    for relative in sorted(removed):
        if relative not in upstream:
            problems.append(f"{relative}: declared left out, but upstream has no such file")
    return problems


def archive_name(fork: Dict[str, Any]) -> str:
    return f"{fork['upstream']['name']}-{fork['upstream']['version']}.crate"


def fetch(fork: Dict[str, Any], directory: Path) -> None:
    target = directory / archive_name(fork)
    if target.exists():
        return
    url = CRATE_URL.format(**fork["upstream"])
    partial = target.with_name(target.name + ".part")
    result = subprocess.run(
        ["curl", "-A", "cargo/1.97", "-fsSL", "--retry", "3", "--retry-delay", "5", url, "-o", str(partial)],
        check=False,
    )
    if result.returncode != 0:
        raise CannotCheck(f"cannot download {url}")
    partial.replace(target)


def archive_for(fork: Dict[str, Any], directory: Path) -> bytes:
    path = directory / archive_name(fork)
    if path.is_symlink() or not path.is_file():
        raise CannotCheck(f"no archive {path}")
    data = path.read_bytes()
    pinned = fork["upstream"]["crate_sha256"]
    if sha256(data) != pinned:
        raise ForkMismatch([f"{path.name}: SHA256 {sha256(data)}, pinned {pinned}"])
    return data


def patch_paths(repo: Path) -> Dict[str, str]:
    """[patch.crates-io] path entries of node/Cargo.toml: crate name to its path from the repo root."""
    entries: Dict[str, str] = {}
    section = None
    for line in (repo / "node/Cargo.toml").read_text(encoding="utf-8").splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("["):
            section = stripped
            continue
        if section != "[patch.crates-io]" or not stripped:
            continue
        match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*\{.*\bpath\s*=\s*"([^"]+)"', stripped)
        if not match:
            raise CannotCheck(f"node/Cargo.toml: a [patch.crates-io] entry that is not a path: {stripped}")
        entries[match.group(1)] = "node/" + match.group(2).rstrip("/")
    return entries


def coverage(repo: Path, document: Dict[str, Any]) -> List[str]:
    problems = []
    forks = {fork["path"]: fork for fork in document["forks"]}
    for name, path in sorted(patch_paths(repo).items()):
        fork = forks.get(path)
        if fork is None:
            problems.append(f"node/Cargo.toml patches {name} with {path}, which {TABLE} does not record")
        elif fork["lock_name"] != name:
            problems.append(f"{path}: recorded as {fork['lock_name']}, patched in as {name}")
    not_forks = {entry["path"] for entry in document.get("not_forks", [])}
    third_party = repo / "node/third_party"
    for folder in sorted(p for p in third_party.iterdir() if p.is_dir()):
        path = f"node/third_party/{folder.name}"
        if path not in forks and path not in not_forks:
            problems.append(f"{path}: neither a recorded fork nor in not_forks")
    workflows = "".join(p.read_text(encoding="utf-8") for p in sorted((repo / WORKFLOWS).glob("*.yml")))
    for fork in document["forks"]:
        verifier = fork.get("delta_verifier")
        if verifier is None:
            continue
        if not (repo / verifier).is_file():
            problems.append(f"{fork['path']}: its delta verifier {verifier} does not exist")
        elif verifier not in workflows:
            problems.append(f"{fork['path']}: no workflow runs its delta verifier {verifier}")
    return problems


def verify(repo: Path, directory: Path, document: Dict[str, Any], quiet: bool = False) -> List[str]:
    problems = [f"coverage: {problem}" for problem in coverage(repo, document)]
    for fork in document["forks"]:
        if "delta" not in fork:
            if not quiet:
                print(f"{fork['path']}: delta checked by {fork['delta_verifier']}")
            continue
        try:
            archive = archive_for(fork, directory)
            upstream = upstream_files(archive, fork["upstream"]["name"], fork["upstream"]["version"])
            found = compare(fork, upstream, tracked_files(repo, fork["path"]))
        except ForkMismatch as mismatch:
            found = mismatch.problems
        problems += [f"{fork['path']}: {problem}" for problem in found]
        if not found and not quiet:
            delta = fork["delta"]
            print(
                f"{fork['path']}: {archive_name(fork)} (pinned SHA256) plus "
                f"{len(delta['modified'])} modified, {len(delta['added'])} added and "
                f"{len(delta['removed'])} left out, as recorded"
            )
    return problems


def git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def self_test(repo: Path, directory: Path, document: Dict[str, Any]) -> List[str]:
    """Planted changes to copies of each fork must be caught; the copies as they are must pass."""
    failures = []
    full = [fork for fork in document["forks"] if "delta" in fork]
    with tempfile.TemporaryDirectory(prefix="raven-fork-provenance.") as temporary:
        base = Path(temporary)

        def fresh(fork: Dict[str, Any]) -> Path:
            copy = base / f"copy-{len(list(base.iterdir()))}"
            target = copy / fork["path"]
            target.mkdir(parents=True)
            for relative, data in tracked_files(repo, fork["path"]).items():
                (target / relative).parent.mkdir(parents=True, exist_ok=True)
                (target / relative).write_bytes(data)
            git("init", "-q", cwd=copy)
            return copy

        def problems_in(copy: Path, fork: Dict[str, Any], record: Dict[str, Any]) -> List[str]:
            # -f: a planted file counts as committed even where the fork's
            # .gitignore names it (Cargo.lock), as a forced add would be.
            git("add", "-A", "-f", cwd=copy)
            try:
                archive = archive_for(record, directory)
                upstream = upstream_files(archive, record["upstream"]["name"], record["upstream"]["version"])
                return compare(record, upstream, tracked_files(copy, fork["path"]))
            except ForkMismatch as mismatch:
                return mismatch.problems

        for fork in full:
            delta = fork["delta"]
            upstream = upstream_files(archive_for(fork, directory), fork["upstream"]["name"], fork["upstream"]["version"])
            plain = sorted(p for p in upstream if p not in delta["modified"] and p not in delta["removed"])
            cases = []

            def case(name, change, record=fork):
                cases.append((name, change, record))

            case("an undeclared change to an upstream file", lambda root: _append(root / plain[0]))
            case("an undeclared new file", lambda root: (root / "planted.rs").write_bytes(b"// planted\n"))
            case("a changed modification", lambda root: _append(root / sorted(delta["modified"])[0]))
            if delta["added"]:
                case("a changed added file", lambda root: _append(root / sorted(delta["added"])[0]))
            case("a missing upstream file", lambda root: (root / plain[0]).unlink())
            case("a symlink", lambda root: os.symlink("Cargo.toml", str(root / "planted-link")))
            if delta["removed"]:
                left_out = sorted(delta["removed"])[0]
                case(
                    "a file declared left out, put back",
                    lambda root, left_out=left_out: (root / left_out).write_bytes(upstream[left_out]),
                )
            pinned = fork["upstream"]["crate_sha256"]
            other = dict(fork, upstream=dict(fork["upstream"], crate_sha256=("0" if pinned[0] != "0" else "1") + pinned[1:]))
            case("another archive pin", lambda root: None, other)

            copy = fresh(fork)
            clean = problems_in(copy, fork, fork)
            if clean:
                failures.append(f"{fork['path']}: an unchanged copy must pass, got {clean}")
            for name, change, record in cases:
                copy = fresh(fork)
                change(copy / fork["path"])
                if not problems_in(copy, fork, record):
                    failures.append(f"{fork['path']}: {name} was not caught")
        if not full:
            failures.append("no fork with a recorded delta to test")
    return failures


def _append(path: Path) -> None:
    path.write_bytes(path.read_bytes() + b"\n// planted\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Checks every vendored crates.io fork in node/third_party against its crates.io archive "
        "plus the delta node/third_party/forks.json records. Exit 0 when every check passes, 1 when one "
        "fails, 2 when it cannot check."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--crate-dir", type=Path, help="folder holding the .crate archives (offline)")
    source.add_argument("--download", type=Path, help="folder to download the archives into first")
    parser.add_argument("--self-test", action="store_true", help="also check that planted changes are caught")
    parser.add_argument("--repo", type=Path, default=REPO, help=argparse.SUPPRESS)
    args = parser.parse_args()
    repo = args.repo.resolve()
    try:
        document = load_table(repo)
        directory = args.crate_dir or args.download
        if args.download:
            directory.mkdir(parents=True, exist_ok=True)
            for fork in document["forks"]:
                if "delta" in fork:
                    fetch(fork, directory)
        problems = verify(repo, directory, document)
        if args.self_test:
            problems += [f"self test: {failure}" for failure in self_test(repo, directory, document)]
    except CannotCheck as error:
        print(f"FORK_PROVENANCE_CANNOT_CHECK: {error}", file=sys.stderr)
        return 2
    for problem in problems:
        print(f"FORK_PROVENANCE_FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    tested = " and its self test" if args.self_test else ""
    print(f"FORK_PROVENANCE_OK: every recorded fork is its crates.io archive plus the recorded delta{tested}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
