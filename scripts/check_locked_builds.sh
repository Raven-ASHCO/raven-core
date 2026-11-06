#!/usr/bin/env bash
# Every cargo command in the scripts that build what Raven ships passes
# --locked (security review 2026-11, DEP-6): the release and package
# scripts, the installers, the nearby helper app and the iOS library.
# Without it, a Cargo.lock that no longer satisfies the manifests is
# resolved again, and crate versions nobody reviewed are built into the
# release instead of the build failing. Comments are skipped and
# continuation lines joined; a command that only lists or prints (cargo
# tree, metadata, --version) is not a build. Commands built up in a
# PowerShell argument array are not seen (both installers name --locked in
# theirs; scripts/check_install_helpers.sh and review cover them).
#
#   scripts/check_locked_builds.sh              # the scripts below
#   scripts/check_locked_builds.sh --self-test  # planted lines must be caught
#
# Exit 1 on a finding. Reads only.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

scan() {
  python3 -I - "$@" <<'PY'
import re, sys

# cargo [+toolchain] <a subcommand that compiles>, where a command starts:
# the line's start, after ( { ; & | (and so &&, ||, $( and PowerShell's &),
# after if, then, do and the like, and after VAR=value words. Not inside a
# message ("cargo build failed") or a word list (for tool in cargo rustc).
CMD_START = r"(?:^|[;&|({]|(?<![\w-])(?:if|elif|while|until|then|do|else|exec|env|time|!))\s*"
ASSIGNS = r"(?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|[^\s;&|]*)\s+)*"
BUILD = re.compile(
    CMD_START + ASSIGNS + r"cargo(?:\.exe)?\s+(?:\+\S+\s+)?"
    r"(build|rustc|run|test|bench|check|clippy|doc|install)(?![\w-])"
)
LOCKED = re.compile(r"(?<![\w-])--(locked|frozen)(?![\w-])")


def logical_lines(text, powershell):
    cont = "`" if powershell else "\\"
    line, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not line:
            start = n
            if stripped.startswith("#"):
                continue
        if stripped.endswith(cont):
            line += stripped[:-1] + " "
            continue
        yield start, line + stripped
        line = ""
    if line:
        yield start, line


def findings(name, text):
    out = []
    for n, line in logical_lines(text, name.endswith(".ps1")):
        for m in BUILD.finditer(line):
            if not LOCKED.search(line, m.end()):
                out.append((name, n, line.strip()))
    return out


args = sys.argv[1:]
if args == ["--self-test"]:
    caught = [
        ("build_xcframework.sh", 'cargo rustc -p raven-client --lib --release \\\n  --target "$t" --crate-type staticlib'),
        ("make-linux.sh", '(cd "$NODE" && cargo build --release -p ash -p raven-node)'),
        ("build_unsigned.sh", "cargo +1.98.0 build --release -p raven-node"),
        ("installer.sh", "cargo install --path crates/ash"),
        ("windows_service.ps1", "        cargo build -p raven-node -p ash --release `\n  --features raven-node/tor"),
        ("relay.sh", "cargo build --locked -p ash && cargo build -p raven-node --release"),
        ("make_bundle.sh", '(cd "$NODE" && CARGO_TARGET_DIR="$dir" cargo build --release -q -p ash)'),
        ("gate.sh", "if cargo build -p ash; then"),
        ("windows_relay.ps1", "    & cargo build -p raven-node"),
    ]
    clean = [
        ("build_xcframework.sh", 'cargo rustc --locked -p raven-client --lib --release \\\n  --target "$t"'),
        ("make-linux.sh", "cargo build --release \\\n  --locked -p ash"),
        ("build_unsigned.sh", "# cargo build --release (a comment)"),
        ("build_unsigned.sh", "cargo build --frozen --release -p ash"),
        ("audit.sh", "cargo tree -p ash --prefix none"),
        ("windows_service.ps1", "        cargo build --locked -p raven-node -p ash --release"),
        ("check.sh", 'command -v cargo >/dev/null || fail "cargo is missing"'),
        ("windows_service.ps1", '    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo build failed" }'),
        ("make-linux.sh", "  for tool in cargo rustc cc strip objdump git tar gzip; do"),
        ("make_bundle.sh", '(cd "$NODE" && CARGO_TARGET_DIR="$dir" cargo build --locked --release -q -p ash)'),
    ]
    bad = [n for n, t in caught if not findings(n, t)] + [n for n, t in clean if findings(n, t)]
    if bad:
        sys.exit(f"FAIL: self test: the --locked check is wrong for {bad}")
    print(f"PASS: self test: {len(caught)} planted builds without --locked caught, {len(clean)} lines left alone")
    sys.exit(0)

problems = []
for path in args:
    with open(path, encoding="utf-8") as f:
        problems += findings(path, f.read())
for name, n, line in problems:
    print(f"FAIL: {name}:{n}: a cargo build without --locked: {line}", file=sys.stderr)
if problems:
    sys.exit(1)
print(f"PASS: every cargo build in {len(args)} release, package, installer and iOS scripts passes --locked")
PY
}

if [[ "${1:-}" == "--self-test" ]]; then
  scan --self-test
  exit 0
fi
[[ $# -eq 0 ]] || {
  echo "usage: scripts/check_locked_builds.sh [--self-test]" >&2
  exit 2
}
files=()
while IFS= read -r f; do
  files+=("$f")
done < <(git ls-files -- 'scripts/release/*.sh' 'node/scripts/install/*.sh' 'node/scripts/install/*.ps1' \
  'node/scripts/ios/*.sh' 'node/scripts/build_nearby_helper_app.sh')
[[ "${#files[@]}" -gt 0 ]] || {
  echo "FAIL: no scripts to check (not a checkout?)" >&2
  exit 1
}
scan "${files[@]}"
