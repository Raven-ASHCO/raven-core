#!/usr/bin/env bash
# Release audit (Phase 6 P6.46, owner decision OD6b-28): the offline release
# tool `raven-release` (ash's non-default feature `release-tool`) is never
# part of a shipped Raven.
#
#  1. Feature graph: the release packages (raven-core, raven-node, ash,
#     raven-swarm, resolved together as a release build resolves them) do
#     not enable `ash/release-tool` (cargo tree; nothing is built).
#  2. Release scripts and CI: scripts/release/build_unsigned.sh and
#     build_reproducible.sh never name a feature, `--all-features` or the
#     tool, and no `--release` cargo command in .github/workflows does.
#  3. Self-test: check 1 fires on ash's graph with the feature on, check 2
#     on a planted release line (a check that cannot fire proves nothing).
#  --release-build: also build ash in release with no features and check
#     that cargo makes no raven-release executable (its artifact list).
#
# Usage: scripts/release_tool_feature_audit.sh [--release-build]
set -euo pipefail

NODE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$NODE/.." && pwd)"
cd "$NODE"

release_build=0
case "${1:-}" in
  "") ;;
  --release-build) release_build=1 ;;
  *)
    echo "usage: scripts/release_tool_feature_audit.sh [--release-build]" >&2
    exit 2
    ;;
esac

# graph_has_tool [features] — 0 when the release graph enables the tool.
graph_has_tool() {
  local tree
  # Inverted on ash: every feature of ash that is on appears as a node,
  # whoever turns it on (the command line or another package).
  tree="$(cargo tree --locked -p raven-core -p raven-node -p ash -p raven-swarm \
    ${1:+--features "$1"} -e features --target all --prefix none -i ash 2>&1)" || {
    echo "FAIL: cargo tree" >&2
    echo "$tree" >&2
    exit 2
  }
  if ! grep -q '^ash feature "default"' <<<"$tree"; then
    echo "FAIL: ash's default features are not in the graph: not the graph we think it is" >&2
    exit 2
  fi
  grep -q 'ash feature "release-tool"' <<<"$tree"
}

# The static check of release scripts and workflows (check 2), in Python:
# continuation lines joined, comments dropped. Arguments: files; with
# --self-test, planted lines instead.
static_check() {
  python3 -I - "$@" <<'PY'
import re, sys

TOOL = re.compile(r"release-tool|raven-release|--all-features")
FEATURES = re.compile(r"--features|-F\b")

def logical_lines(text):
    line = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#") and not line:
            continue
        if stripped.endswith("\\"):
            line += stripped[:-1] + " "
            continue
        yield line + stripped
        line = ""
    if line:
        yield line

def findings(name, text):
    out = []
    build_script = name.endswith((".sh",))
    for line in logical_lines(text):
        if build_script:
            if "cargo " in line and (TOOL.search(line) or FEATURES.search(line)):
                out.append(f"{name}: {line}")
        elif "cargo " in line and "--release" in line and TOOL.search(line):
            out.append(f"{name}: {line}")
    return out

args = sys.argv[1:]
if args == ["--self-test"]:
    planted = [
        ("build_unsigned.sh", "cargo build --locked --release -p ash --features release-tool"),
        ("build_unsigned.sh", "cargo build --locked --release -p ash \\\n  --all-features"),
        ("build_reproducible.sh", "(cd x && cargo build --locked --release -p ash -F release-tool)"),
        ("ci.yml", "          cargo build --locked --release -p ash --bin raven-release"),
    ]
    clean = [
        ("build_unsigned.sh", "# never --features release-tool\ncargo build --locked --release -p ash"),
        ("ci.yml", "cargo test --locked -p ash --features release-tool --test release_tool"),
    ]
    bad = [n for n, t in planted if not findings(n, t)] + [n for n, t in clean if findings(n, t)]
    if bad:
        sys.exit(f"FAIL: self-test: the static check is wrong for {bad}")
    print("PASS: self-test: the static check fires on planted release lines")
    sys.exit(0)
problems = []
for path in args:
    with open(path, encoding="utf-8") as f:
        problems += findings(path, f.read())
for p in problems:
    print(f"FAIL: enables the release tool in a release build: {p}", file=sys.stderr)
if problems:
    sys.exit(1)
print(f"PASS: {len(args)} release scripts and workflows never enable the release tool")
PY
}

status=0
if graph_has_tool; then
  echo "FAIL: the release feature graph enables ash/release-tool" >&2
  status=1
else
  echo "PASS: the release feature graph (raven-core, raven-node, ash, raven-swarm) has no release tool"
fi
if graph_has_tool ash/release-tool 2>/dev/null; then
  echo "PASS: self-test: the graph check detects ash/release-tool"
else
  echo "FAIL: self-test: the graph check did not detect ash/release-tool" >&2
  status=1
fi

static_check "$REPO/scripts/release/build_unsigned.sh" "$REPO/scripts/release/build_reproducible.sh" \
  "$REPO"/.github/workflows/*.yml || status=1
static_check --self-test || status=1

if [[ "$release_build" -eq 1 ]]; then
  # Cargo lists every executable it makes (fresh ones too).
  if cargo build --locked --release -p ash --message-format=json 2>/dev/null | python3 -I -c '
import json, sys
names = set()
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable"):
        names.add(m["target"]["name"])
if "ash" not in names or "raven" not in names:
    sys.exit(f"FAIL: the release build listed {sorted(names)}, not ash and raven")
if "raven-release" in names:
    sys.exit("FAIL: cargo build --release -p ash made raven-release")
print(f"PASS: cargo build --release -p ash makes {sorted(names)}, no raven-release")
'; then
    :
  else
    status=1
  fi
fi
exit "$status"
