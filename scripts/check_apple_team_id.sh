#!/usr/bin/env bash
# No Apple development team id in the repository: a person's own signing
# team (10 letters and digits) must never come back as a default or a
# setting in a tracked file (a script's ${DEVELOPMENT_TEAM:-...}, an
# xcconfig's DEVELOPMENT_TEAM = ..., a project's DevelopmentTeam = ...;).
# Signing teams come from the environment or a local file kept out of git
# (Config/Team.local.xcconfig). Never prints a value it finds: only the
# file and the line number.
#
#   scripts/check_apple_team_id.sh              # every file `git ls-files` lists
#   scripts/check_apple_team_id.sh --self-test  # planted lines must be caught
#
# Exit 1 on a finding. Reads only.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

scan() {
  python3 -I - "$@" <<'PY'
import re, sys

# A team key, then an assignment or a shell default, then 10 letters and
# digits with at least one of each (Apple's team ids), quoted or not.
KEY = r"(DEVELOPMENT_TEAM|DevelopmentTeam|DEVELOPMENT_TEAM_ID|TEAM_ID|TeamID|teamID|team_id|TeamIdentifier)"
ASSIGN = re.compile(
    KEY + r"[\"']?\s*(:-|:=|=|:|\?=)\s*[\"']?([A-Z0-9]{10})(?![A-Za-z0-9])"
)


def team_like(value):
    return bool(re.search(r"[A-Z]", value)) and bool(re.search(r"[0-9]", value))


def findings(name, text):
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for m in ASSIGN.finditer(line):
            if team_like(m.group(3)):
                out.append((name, n))
    return out


args = sys.argv[1:]
if args and args[0] == "--self-test":
    value = "Q7" + "W2E3R4T5"  # put together here: no literal for the scan to find
    caught = [
        'DEVELOPMENT_TEAM="${DEVELOPMENT_TEAM:-%s}"' % value,
        "DEVELOPMENT_TEAM = %s" % value,
        "\t\t\t\tDevelopmentTeam = %s;" % value,
        'TEAM_ID="%s"' % value,
        "team_id: '%s'" % value,
    ]
    passed = [
        'DEVELOPMENT_TEAM="${DEVELOPMENT_TEAM:-}"',
        "DEVELOPMENT_TEAM = $(RAVEN_TEAM)",
        "DEVELOPMENT_TEAM=${DEVELOPMENT_TEAM}",
        'echo "development_team=set (not printed)"',
        "TEAM_ID = ABCDEFGHIJ",
    ]
    bad = 0
    for line in caught:
        if not findings("planted", line):
            print("SELF-TEST FAIL: not caught: a planted team id line", file=sys.stderr)
            bad = 1
    for line in passed:
        if findings("planted", line):
            print("SELF-TEST FAIL: caught a line without a team id: %r" % line, file=sys.stderr)
            bad = 1
    if bad:
        sys.exit(1)
    print("apple team id check self-test OK (%d caught, %d left alone)" % (len(caught), len(passed)))
    sys.exit(0)

found = []
for name in args:
    try:
        with open(name, "rb") as f:
            data = f.read()
    except OSError:
        continue
    if b"\0" in data[:8192]:
        continue
    found += findings(name, data.decode("utf-8", "replace"))
for name, n in found:
    print("APPLE_TEAM_ID: %s:%d sets a 10-character Apple team id (value not shown); take it from the "
          "environment or a local file kept out of git" % (name, n), file=sys.stderr)
if found:
    sys.exit(1)
print("no Apple team id in tracked files")
PY
}

if [[ "${1:-}" == "--self-test" ]]; then
  scan --self-test
  exit 0
fi
files=()
while IFS= read -r -d '' f; do
  files+=("$f")
done < <(git ls-files -z -- . ':!node/third_party')
scan "${files[@]}"
