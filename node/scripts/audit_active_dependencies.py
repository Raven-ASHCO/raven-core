#!/usr/bin/env python3
"""Audit RustSec advisories against Raven's resolved, buildable dependency graph.

`cargo audit` correctly audits every package recorded in Cargo.lock, including
optional dependencies which none of Raven's features can enable.  This wrapper
keeps that broad scan, then fails closed against Cargo's union of Raven's
all-feature/all-target graph.  A lock-only vulnerability is accepted only when
an exact, time-bounded review entry exists in `rustsec-inactive-advisories.json`.

The policy deliberately has no advisory-ID-only ignore.  If an excepted
package becomes buildable, changes version, expires, disappears, or a new
lock-only advisory appears, CI stops for a fresh review.

RustSec matches advisories only against crates.io packages, and Cargo.lock
records the vendored forks ([patch.crates-io] and path dependencies under
third_party) with no source, so cargo audit alone never checks them.  The
audit therefore reads a copy of Cargo.lock in which every fork recorded in
third_party/forks.json is the crates.io crate it was forked from (its
upstream name and version, the crates.io source, the archive checksum),
and applies the same policy to what it finds there.  Every other package
outside crates.io must be a workspace member or be declared, with a reason
and a review date, in non_registry_packages of the policy; anything else
stops the audit (security review 2026-11, DEP-4).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Callable, NamedTuple


SCRIPT_DIR = Path(__file__).resolve().parent
NODE_ROOT = SCRIPT_DIR.parent
DEFAULT_POLICY = SCRIPT_DIR / "rustsec-inactive-advisories.json"
PACKAGE_LINE = re.compile(r"^([A-Za-z0-9_-]+) v([^\s]+)(?:\s|$)")
HARD_WARNING_KINDS = {"unsound", "yanked"}
# The source Cargo.lock gives crates.io packages, the only ones RustSec checks.
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
# A reviewed policy entry is good for at most this long (about six months).
MAX_REVIEW_DAYS = 183
LOCK_KEYS = ("name", "version", "source", "checksum", "dependencies")
LOCK_STRING = re.compile(r'^(name|version|source|checksum) = "([^"\\]*)"$')
LOCK_DEPENDENCY = re.compile(r'^ "([^"\\]*)",$')
LOCK_REFERENCE = re.compile(r"^([^ ()]+)(?: ([^ ()]+))?(?: \(([^ ()]+)\))?$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class AuditFailure(RuntimeError):
    """A fail-closed audit or input error."""


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=NODE_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def validate_cargo_audit_version() -> None:
    result = run(["cargo", "audit", "--version"])
    if result.returncode != 0:
        raise AuditFailure(
            "cargo-audit 0.22.2 is required but is not callable: "
            + result.stderr.strip()
        )
    fields = result.stdout.strip().split()
    if len(fields) < 2 or fields[1] != "0.22.2":
        raise AuditFailure(
            "cargo-audit must be exactly 0.22.2; got " + result.stdout.strip()
        )


def resolved_packages() -> set[tuple[str, str]]:
    result = run(
        [
            "cargo",
            "tree",
            "--locked",
            "--workspace",
            "--target",
            "all",
            "--all-features",
            "--format",
            "{p}",
            "--prefix",
            "none",
        ]
    )
    if result.returncode != 0:
        raise AuditFailure(
            "cargo tree could not resolve the all-feature/all-target graph:\n"
            + result.stderr.strip()
        )

    packages: set[tuple[str, str]] = set()
    for line in result.stdout.splitlines():
        match = PACKAGE_LINE.match(line)
        if match:
            packages.add((match.group(1), match.group(2)))
    if not packages:
        raise AuditFailure("cargo tree returned no parseable packages")
    return packages


def rustsec_report(lockfile: Path | None = None) -> dict[str, Any]:
    command = ["cargo", "audit", "--json"]
    if lockfile is not None:
        command += ["--file", str(lockfile)]
    result = run(command)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        detail = result.stderr.strip() or result.stdout[:500].strip()
        raise AuditFailure(f"cargo audit did not return valid JSON: {detail}") from error

    if not isinstance(report.get("vulnerabilities", {}).get("list"), list):
        raise AuditFailure("cargo audit JSON is missing vulnerabilities.list")
    # Exit 1 is cargo-audit's expected result when a vulnerability is found.
    if result.returncode not in (0, 1):
        raise AuditFailure(
            f"cargo audit exited unexpectedly ({result.returncode}): "
            + result.stderr.strip()
        )
    return report


class Policy(NamedTuple):
    """The reviewed entries of the advisory policy file, by exact key."""

    inactive: dict[tuple[str, str, str], dict[str, Any]]
    non_registry: dict[tuple[str, str, str], dict[str, Any]]


def reviewed_entries(
    items: Any, key_fields: tuple[str, ...], what: str
) -> dict[tuple[str, ...], dict[str, Any]]:
    """Entries keyed by key_fields, each with a reason and a review date that has not passed."""
    if not isinstance(items, list):
        raise AuditFailure(f"{what} entries must be a list")
    entries: dict[tuple[str, ...], dict[str, Any]] = {}
    today = dt.date.today()
    for entry in items:
        try:
            key = tuple(entry[name] for name in key_fields)
            review_by = dt.date.fromisoformat(entry["review_by"])
            reason = entry["reason"].strip()
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise AuditFailure(f"malformed {what} entry: {entry!r}") from error
        if not all(isinstance(part, str) and part for part in key):
            raise AuditFailure(f"malformed {what} entry: {entry!r}")
        if key in entries:
            raise AuditFailure(f"duplicate {what} entry: {key}")
        if not reason:
            raise AuditFailure(f"{what} entry has no rationale: {key}")
        if review_by < today:
            raise AuditFailure(f"{what} review expired on {review_by.isoformat()}: {key}")
        if (review_by - today).days > MAX_REVIEW_DAYS:
            raise AuditFailure(
                f"{what} review date {review_by.isoformat()} is more than "
                f"{MAX_REVIEW_DAYS} days ahead: {key}"
            )
        entries[key] = entry
    return entries


def load_policy(path: Path) -> Policy:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditFailure(f"cannot read advisory policy {path}: {error}") from error
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise AuditFailure("inactive-advisory policy schema must be exactly 1")
    return Policy(
        inactive=reviewed_entries(
            document.get("inactive_vulnerability_exceptions", []),
            ("advisory_id", "package", "version"),
            "inactive-advisory",
        ),
        non_registry=reviewed_entries(
            document.get("non_registry_packages", []),
            ("package", "version", "source"),
            "non_registry_packages",
        ),
    )


# ── The forks, audited as the crates.io crates they were forked from ────────


class Fork(NamedTuple):
    path: str
    lock_name: str
    lock_version: str
    name: str
    version: str
    crate_sha256: str


def load_forks(path: Path) -> list[Fork]:
    """The fork table (third_party/forks.json) as far as the audit needs it."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        records = document["forks"]
        forks = [
            Fork(
                path=record["path"],
                lock_name=record["lock_name"],
                lock_version=record["lock_version"],
                name=record["upstream"]["name"],
                version=record["upstream"]["version"],
                crate_sha256=record["upstream"]["crate_sha256"],
            )
            for record in records
        ]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise AuditFailure(f"cannot read the fork table {path}: {error}") from error
    if not isinstance(document, dict) or document.get("schema") != 1 or not forks:
        raise AuditFailure(f"the fork table {path} must be schema 1 with at least one fork")
    for fork in forks:
        if not all(isinstance(value, str) and value for value in fork):
            raise AuditFailure(f"the fork table {path} has an incomplete record: {fork.path}")
        if not SHA256_HEX.match(fork.crate_sha256):
            raise AuditFailure(f"{fork.path}: upstream crate_sha256 is not a SHA256")
        # A fork may add build metadata (+raven...) to the version it forked.
        if fork.lock_version.split("+", 1)[0] != fork.version:
            raise AuditFailure(
                f"{fork.path}: Cargo.lock version {fork.lock_version} is not the "
                f"upstream version {fork.version} (plus build metadata)"
            )
    keys = Counter((fork.lock_name, fork.lock_version) for fork in forks)
    twice = sorted(f"{name} {version}" for (name, version), n in keys.items() if n > 1)
    if twice:
        raise AuditFailure(f"the fork table {path} records {', '.join(twice)} twice")
    return forks


def parse_lock(text: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Cargo.lock (version 3 or 4) as its header lines and its packages.

    Strict: a line this does not read stops the audit, so render_lock gives
    back exactly the same bytes."""
    if not text.endswith("\n"):
        raise AuditFailure("Cargo.lock does not end with a newline")
    header: list[str] = []
    packages: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_dependencies = False
    after_blank = False
    for number, line in enumerate(text[:-1].split("\n"), 1):
        where = f"Cargo.lock:{number}"
        if in_dependencies:
            if line == "]":
                in_dependencies = False
                continue
            match = LOCK_DEPENDENCY.match(line)
            if match is None or current is None:
                raise AuditFailure(f"{where}: a dependency line this audit does not read: {line!r}")
            current["dependencies"].append(match.group(1))
            continue
        if line == "[[package]]":
            if current is not None and not after_blank:
                raise AuditFailure(f"{where}: packages are not separated by one blank line")
            current = {}
            packages.append(current)
            after_blank = False
            continue
        if current is None:
            header.append(line)
            continue
        if after_blank:
            raise AuditFailure(f"{where}: a line this audit does not read: {line!r}")
        if line == "":
            after_blank = True
            continue
        key = "dependencies" if line == "dependencies = [" else None
        match = LOCK_STRING.match(line)
        if key is None and match is None:
            raise AuditFailure(f"{where}: a line this audit does not read: {line!r}")
        key = key or match.group(1)
        if key in current:
            raise AuditFailure(f"{where}: {key} twice in one package")
        if key == "dependencies":
            current[key] = []
            in_dependencies = True
        else:
            current[key] = match.group(2)
    if in_dependencies or after_blank:
        raise AuditFailure("Cargo.lock ends inside a package")
    versions = [line for line in header if line.startswith("version = ")]
    if versions not in (["version = 3"], ["version = 4"]):
        raise AuditFailure(f"Cargo.lock format {versions} is not version 3 or 4")
    if any(line and not line.startswith("#") and line not in versions for line in header):
        raise AuditFailure("Cargo.lock has a header line this audit does not read")
    for package in packages:
        if "name" not in package or "version" not in package:
            raise AuditFailure(f"Cargo.lock has a package without a name or version: {package!r}")
        if list(package) != [key for key in LOCK_KEYS if key in package]:
            raise AuditFailure(f"Cargo.lock lists the fields of {package['name']} in another order")
    return header, packages


def render_lock(lock: tuple[list[str], list[dict[str, Any]]]) -> str:
    header, packages = lock
    lines = list(header)
    for index, package in enumerate(packages):
        if index:
            lines.append("")
        lines.append("[[package]]")
        for key in LOCK_KEYS:
            if key not in package:
                continue
            if key == "dependencies":
                lines.append("dependencies = [")
                lines += [f' "{reference}",' for reference in package[key]]
                lines.append("]")
            else:
                lines.append(f'{key} = "{package[key]}"')
    return "\n".join(lines) + "\n"


def without_precise(source: str | None) -> str | None:
    """A source as a dependency reference writes it (git: no #commit)."""
    return source.split("#", 1)[0] if source else source


def reference_resolver(packages: list[dict[str, Any]]) -> Callable[[str], int]:
    """Maps a dependency reference ("name", "name version", "name version (source)") to its package."""
    by_name: dict[str, list[int]] = {}
    for index, package in enumerate(packages):
        by_name.setdefault(package["name"], []).append(index)

    def resolve(reference: str) -> int:
        match = LOCK_REFERENCE.match(reference)
        if match is None:
            raise AuditFailure(f"Cargo.lock: a dependency this audit does not read: {reference!r}")
        name, version, source = match.groups()
        found = [
            index
            for index in by_name.get(name, [])
            if (version is None or packages[index]["version"] == version)
            and (source is None or without_precise(packages[index].get("source")) == source)
        ]
        if len(found) != 1:
            raise AuditFailure(
                f"Cargo.lock: the dependency {reference!r} names {len(found)} packages, not one"
            )
        return found[0]

    return resolve


def reference_encoder(packages: list[dict[str, Any]]) -> Callable[[int], str]:
    """The reference Cargo writes for a package: its name alone when no other
    package has that name, else with its version, else with its source too."""
    versions: dict[str, Counter[str]] = {}
    for package in packages:
        versions.setdefault(package["name"], Counter())[package["version"]] += 1

    def encode(index: int) -> str:
        name, version = packages[index]["name"], packages[index]["version"]
        if versions[name][version] > 1:
            source = without_precise(packages[index].get("source"))
            return f"{name} {version}" + (f" ({source})" if source else "")
        if len(versions[name]) > 1:
            return f"{name} {version}"
        return name

    return encode


class AuditedLock(NamedTuple):
    """The copy of Cargo.lock cargo audit reads."""

    text: str
    # Cargo.lock (name, version) of each fork to its crates.io (name, version).
    forks: dict[tuple[str, str], tuple[str, str]]
    notices: list[str]

    def audit_terms(self, packages: set[tuple[str, str]]) -> set[tuple[str, str]]:
        return {self.forks.get(package, package) for package in packages}

    def labels(self) -> dict[tuple[str, str], str]:
        return {
            audited: f" (the vendored fork {name} {version})"
            for (name, version), audited in self.forks.items()
        }


def audited_lockfile(
    text: str,
    forks: list[Fork],
    workspace: set[tuple[str, str]],
    non_registry: dict[tuple[str, str, str], dict[str, Any]],
) -> AuditedLock:
    """Cargo.lock with every recorded fork as its crates.io crate; fails closed on any other unknown source."""
    header, packages = parse_lock(text)
    resolve = reference_resolver(packages)
    resolved = [[resolve(reference) for reference in package.get("dependencies", [])] for package in packages]
    by_lock_key = {(fork.lock_name, fork.lock_version): fork for fork in forks}
    problems: list[str] = []
    mapping: dict[tuple[str, str], tuple[str, str]] = {}
    found_forks: set[tuple[str, str]] = set()
    declared_seen: set[tuple[str, str, str]] = set()
    notices: list[str] = []
    for index, package in enumerate(packages):
        name, version, source = package["name"], package["version"], package.get("source")
        fork = by_lock_key.get((name, version))
        if fork is not None:
            found_forks.add((name, version))
            if source is not None or "checksum" in package:
                # The patch no longer applies and Cargo took the crate from elsewhere.
                problems.append(
                    f"{name} {version}: recorded as the fork {fork.path}, but Cargo.lock "
                    f"takes it from {source}"
                )
                continue
            rewritten: dict[str, Any] = {
                "name": fork.name,
                "version": fork.version,
                "source": CRATES_IO_SOURCE,
                "checksum": fork.crate_sha256,
            }
            if "dependencies" in package:
                rewritten["dependencies"] = package["dependencies"]
            packages[index] = rewritten
            mapping[(name, version)] = (fork.name, fork.version)
        elif source == CRATES_IO_SOURCE:
            continue
        elif source is None:
            if (name, version) not in workspace:
                problems.append(
                    f"{name} {version}: a path dependency that is neither a workspace member "
                    "nor a fork recorded in third_party/forks.json"
                )
        elif (name, version, source) in non_registry:
            declared_seen.add((name, version, source))
            entry = non_registry[(name, version, source)]
            notices.append(
                f"not checked by RustSec (declared, review by {entry['review_by']}): "
                f"{name} {version} from {source}: {entry['reason'].strip()}"
            )
        else:
            problems.append(
                f"{name} {version} from {source}: RustSec does not check this source, "
                "and the policy does not declare it in non_registry_packages"
            )
    for (name, version), fork in sorted(by_lock_key.items()):
        if (name, version) not in found_forks:
            problems.append(
                f"{name} {version}: third_party/forks.json records the fork {fork.path}, "
                "but Cargo.lock does not hold it (the patch no longer applies)"
            )
    for name, version, source in sorted(set(non_registry) - declared_seen):
        problems.append(
            f"{name} {version}: a stale non_registry_packages entry, Cargo.lock does not take it from {source}"
        )
    counts = Counter((package["name"], package["version"]) for package in packages)
    for (name, version), count in sorted(counts.items()):
        if count > 1 and (name, version) in mapping.values():
            problems.append(f"{name} {version}: the audited lock would hold it {count} times")
    if problems:
        raise AuditFailure("\n  ".join(["Cargo.lock cannot be audited as it is:"] + problems))
    encode = reference_encoder(packages)
    for package, dependencies in zip(packages, resolved):
        if "dependencies" in package:
            package["dependencies"] = [encode(index) for index in dependencies]
    return AuditedLock(render_lock((header, packages)), mapping, notices)


def workspace_members() -> set[tuple[str, str]]:
    result = run(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"])
    if result.returncode != 0:
        raise AuditFailure("cargo metadata could not read the workspace:\n" + result.stderr.strip())
    try:
        metadata = json.loads(result.stdout)
        ids = set(metadata["workspace_members"])
        members = {(p["name"], p["version"]) for p in metadata["packages"] if p["id"] in ids}
    except (ValueError, KeyError, TypeError) as error:
        raise AuditFailure("cargo metadata returned no readable workspace members") from error
    if not members:
        raise AuditFailure("cargo metadata returned no workspace members")
    return members


def package_key(record: dict[str, Any]) -> tuple[str, str]:
    package = record.get("package", {})
    try:
        return package["name"], package["version"]
    except (KeyError, TypeError) as error:
        raise AuditFailure(f"advisory record has no exact package/version: {record!r}") from error


def advisory_key(record: dict[str, Any]) -> tuple[str, str, str]:
    try:
        advisory_id = record["advisory"]["id"]
    except (KeyError, TypeError) as error:
        raise AuditFailure(f"vulnerability record has no advisory ID: {record!r}") from error
    name, version = package_key(record)
    return advisory_id, name, version


def classify(
    report: dict[str, Any],
    active: set[tuple[str, str]],
    policy: dict[tuple[str, str, str], dict[str, Any]],
    labels: dict[tuple[str, str], str] | None = None,
) -> int:
    labels = labels or {}
    failures: list[str] = []
    reported_policy_keys: set[tuple[str, str, str]] = set()
    vulnerabilities = report["vulnerabilities"]["list"]

    for record in vulnerabilities:
        key = advisory_key(record)
        advisory_id, name, version = key
        if key in policy:
            reported_policy_keys.add(key)
        label = labels.get((name, version), "")
        if (name, version) in active:
            failures.append(
                f"ACTIVE VULNERABILITY {advisory_id}: {name} v{version}{label}"
            )
            continue
        entry = policy.get(key)
        if entry is None:
            failures.append(
                "UNREVIEWED LOCK-ONLY VULNERABILITY "
                f"{advisory_id}: {name} v{version}{label}"
            )
            continue
        print(
            "reviewed lock-only advisory "
            f"{advisory_id}: {name} v{version} "
            f"(review by {entry['review_by']})"
        )

    stale = set(policy) - reported_policy_keys
    for advisory_id, name, version in sorted(stale):
        failures.append(
            "STALE INACTIVE-ADVISORY EXCEPTION "
            f"{advisory_id}: {name} v{version}"
        )

    warnings = report.get("warnings", {})
    if not isinstance(warnings, dict):
        raise AuditFailure("cargo audit JSON warnings field is not an object")
    for kind, records in sorted(warnings.items()):
        for record in records:
            name, version = package_key(record)
            graph_state = "active" if (name, version) in active else "lock-only"
            print(f"RustSec {kind} notice ({graph_state}): {name} v{version}")
            if graph_state == "active" and kind in HARD_WARNING_KINDS:
                failures.append(
                    f"ACTIVE {kind.upper()} RUSTSEC NOTICE: {name} v{version}"
                )

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    print(
        "active dependency audit passed: "
        f"{len(active)} exact package versions resolved; "
        f"{len(vulnerabilities)} reviewed lock-only vulnerabilities; "
        "0 active vulnerabilities"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY,
        help="exact lock-only advisory review file",
    )
    parser.add_argument(
        "--forks",
        type=Path,
        default=None,
        help="the fork table (default: third_party/forks.json)",
    )
    args = parser.parse_args()
    try:
        validate_cargo_audit_version()
        policy = load_policy(args.policy)
        forks = load_forks(args.forks or NODE_ROOT / "third_party" / "forks.json")
        try:
            lock_text = (NODE_ROOT / "Cargo.lock").read_text(encoding="utf-8")
        except OSError as error:
            raise AuditFailure(f"cannot read Cargo.lock: {error}") from error
        audited = audited_lockfile(lock_text, forks, workspace_members(), policy.non_registry)
        for notice in audited.notices:
            print(notice)
        print(
            "forks audited as their crates.io versions: "
            + ", ".join(
                f"{name} {version}" + (f" (Cargo.lock {lock_version})" if lock_version != version else "")
                for (lock_name, lock_version), (name, version) in sorted(audited.forks.items())
            )
        )
        with tempfile.TemporaryDirectory(prefix="raven-rustsec-lock.") as folder:
            copy = Path(folder) / "Cargo.lock"
            copy.write_text(audited.text, encoding="utf-8")
            report = rustsec_report(copy)
        active = audited.audit_terms(resolved_packages())
        return classify(report, active, policy.inactive, audited.labels())
    except AuditFailure as error:
        print(f"ERROR: dependency audit failed closed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
