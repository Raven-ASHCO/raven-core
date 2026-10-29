#!/usr/bin/env bash
# docs/OFFLINE_GUIDE.md (Phase 3 P3.24) and docs/SAFETY_OFFLINE.md (its
# safety guide, Phase 3 P3.C7) tell people what to type to talk without the
# Internet, so what they say must be what this build does. Checks, exit 1 on
# any violation:
#   1. in each guide, every `raven` / `ash` line in its fenced blocks names a
#      command of this build and every --flag on the line appears in that
#      command's --help, and every `<!-- gate: NAME=... -->` marker matches
#      the code: by scripts/check_safety_offline.sh (cutoff pack CP.15, folded
#      in here: RAVEN_SAFETY_DOC set to each guide in turn);
#   2. in each guide, "nothing to do" (any case, also wrapped over two lines)
#      appears only on a line, or under a heading, that says "when nearby
#      search is on": while the build holds nearby search, the user types an
#      address;
#   3. the offline guide links SAFETY_OFFLINE.md, and that guide links back;
#   4. the read-only OS commands the guide names run on this runner: Darwin
#      `networksetup -listallhardwareports`, `ipconfig getiflist`, `route -n
#      get default` (no default route is fine: a runner may have none) and
#      `socketfilterfw --getglobalstate`; Linux `ip -br addr` and `ip -6 addr
#      show scope link`; Windows (MINGW/MSYS/CYGWIN) every cmdlet the guide
#      names exists and `Get-NetIPAddress` runs. Nothing that changes the
#      system runs (no hotspot, no cable setup, no firewall rule).
#
# Usage: bash scripts/check_offline_guide.sh RAVEN_BIN [--self-test]
#   RAVEN_BIN: the built `raven` (target/debug/raven; `.exe` is tried on
#   Windows). Its folder must also hold `ash`. Build first:
#     (cd node && cargo build --locked -p ash -p raven-node)
#   --self-test: check_safety_offline.sh's own self-test passes; both guides
#   pass; scratch copies of the offline guide with a wrong flag, an unknown
#   subcommand, an unguarded "nothing to do" or no safety-guide link, and of
#   the safety guide with a wrong flag, an unguarded "nothing to do" or no
#   offline-guide link, each fail.
# Environment: RAVEN_OFFLINE_GUIDE (the guide; default docs/OFFLINE_GUIDE.md),
# RAVEN_SAFETY_GUIDE (the safety guide; default docs/SAFETY_OFFLINE.md).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $# -lt 1 || -z "${1:-}" || "$1" == --* ]]; then
  echo "usage: bash scripts/check_offline_guide.sh RAVEN_BIN [--self-test]" >&2
  exit 2
fi
bin="$1"
if [[ ! -x "$bin" && -x "$bin.exe" ]]; then
  bin="$bin.exe"
fi
if [[ ! -x "$bin" ]]; then
  echo "check_offline_guide: no raven at $1; build it first: (cd node && cargo build --locked -p ash -p raven-node)" >&2
  exit 2
fi
BIN_DIR="$(cd "$(dirname "$bin")" && pwd)"
GUIDE="${RAVEN_OFFLINE_GUIDE:-$REPO/docs/OFFLINE_GUIDE.md}"
SAFETY="${RAVEN_SAFETY_GUIDE:-$REPO/docs/SAFETY_OFFLINE.md}"
export NO_COLOR=1

# commands_and_gates DOC: check 1, by check_safety_offline.sh.
commands_and_gates() {
  RAVEN_BIN_DIR="$BIN_DIR" RAVEN_SAFETY_DOC="$1" bash "$REPO/scripts/check_safety_offline.sh"
}

# nothing_to_do DOC: check 2; prints each offending line, returns 1 on one.
nothing_to_do() {
  tr -d '\r' <"$1" | awk -v doc="$1" '
    function guarded() {
      return index(tolower(line), "when nearby search is on") || index(tolower(head), "when nearby search is on")
    }
    /^[[:space:]]*(```|~~~)/ { fence = !fence }
    !fence && /^#+[[:space:]]/ { head = $0 }
    {
      line = $0
      lower = tolower(line)
      hit = lower ~ /nothing[[:space:]]+to[[:space:]]+do/
      # Wrapped: "... nothing" / "to do ..." or "... nothing to" / "do ...".
      if (!hit && prev ~ /nothing[[:space:]]*$/ && lower ~ /^[[:space:]]*to[[:space:]]+do([^a-z]|$)/) hit = 1
      if (!hit && prev ~ /nothing[[:space:]]+to[[:space:]]*$/ && lower ~ /^[[:space:]]*do([^a-z]|$)/) hit = 1
      if (hit && !guarded()) {
        printf "OFFLINE_GUIDE_NOTHING_TO_DO: %s:%d says \"nothing to do\" outside \"when nearby search is on\": %s\n", doc, NR, line
        bad = 1
      }
      prev = lower
    }
    END { exit bad }' >&2
}

# safety_links DOC SAFETY_DOC: check 3.
safety_links() {
  local bad=0
  if ! grep -qF '(SAFETY_OFFLINE.md)' "$1"; then
    echo "OFFLINE_GUIDE_LINK: $1 does not link SAFETY_OFFLINE.md" >&2
    bad=1
  fi
  if ! grep -qF '(OFFLINE_GUIDE.md)' "$2"; then
    echo "OFFLINE_GUIDE_LINK: $2 does not link OFFLINE_GUIDE.md" >&2
    bad=1
  fi
  return "$bad"
}

# os_commands: check 4, for this runner.
os_commands() {
  local os
  os="$(uname -s)"
  case "$os" in
    Darwin)
      networksetup -listallhardwareports >/dev/null
      ipconfig getiflist >/dev/null
      route -n get default >/dev/null 2>&1 || true
      /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate >/dev/null
      ;;
    Linux)
      ip -br addr >/dev/null
      ip -6 addr show scope link >/dev/null
      ;;
    MINGW* | MSYS* | CYGWIN*)
      powershell.exe -NoProfile -Command "\$ErrorActionPreference = 'Stop'; Get-Command Get-NetIPAddress,Get-NetAdapter,Get-NetConnectionProfile,New-NetFirewallRule,Remove-NetFirewallRule | Out-Null; Get-NetIPAddress -AddressFamily IPv4 | Out-Null" >/dev/null
      ;;
    *)
      echo "check_offline_guide: no OS commands known for $os" >&2
      return 1
      ;;
  esac
  echo "OS commands OK ($os)"
}

# check_guide DOC SAFETY_DOC: checks 1-3 on the offline guide DOC and the
# safety guide SAFETY_DOC; prints a summary, returns 1 on a violation.
check_guide() {
  local doc=$1 safety=$2 bad=0 one
  for one in "$doc" "$safety"; do
    if [[ ! -f "$one" ]]; then
      echo "check_offline_guide: $one does not exist" >&2
      return 1
    fi
  done
  for one in "$doc" "$safety"; do
    commands_and_gates "$one" || bad=1
    nothing_to_do "$one" || bad=1
  done
  safety_links "$doc" "$safety" || bad=1
  if [[ "$bad" -ne 0 ]]; then
    return 1
  fi
  echo "offline and safety guides OK (${doc#"$REPO"/}, ${safety#"$REPO"/}: commands and gates match this build; \"nothing to do\" only when nearby search is on; linked with each other)"
}

# self_test: check_safety_offline.sh's self-test passes; both guides pass;
# seven broken scratch copies each fail.
self_test() {
  local dir rc=0 kind
  dir="$(mktemp -d)"
  if ! RAVEN_BIN_DIR="$BIN_DIR" bash "$REPO/scripts/check_safety_offline.sh" --self-test >/dev/null 2>&1; then
    echo "SELF_TEST_FAIL: check_safety_offline.sh --self-test failed" >&2
    rc=1
  fi
  if ! check_guide "$GUIDE" "$SAFETY" >/dev/null 2>&1; then
    echo "SELF_TEST_FAIL: the guides themselves were refused" >&2
    rc=1
  fi
  # The offline guide: a wrong flag on a real command line.
  sed -E 's/^raven lan status$/raven lan status --no-such-flag/' "$GUIDE" >"$dir/flag.md"
  # An unknown subcommand.
  sed -E 's/^raven lan status$/raven lan no-such-command/' "$GUIDE" >"$dir/sub.md"
  # "Nothing to do" outside the guarded heading (and wrapped over two lines).
  { cat "$GUIDE"; printf '\n## 10. Extra\n\nOn a cable there is nothing\nto do.\n'; } >"$dir/nothing.md"
  # No link to the safety guide.
  sed -E 's/\(SAFETY_OFFLINE\.md\)/(elsewhere.md)/g' "$GUIDE" >"$dir/link.md"
  for kind in flag sub nothing link; do
    if cmp -s "$GUIDE" "$dir/$kind.md"; then
      echo "SELF_TEST_FAIL: the '$kind' copy is unchanged (the guide moved on: update the self-test)" >&2
      rc=1
    elif check_guide "$dir/$kind.md" "$SAFETY" >/dev/null 2>&1; then
      echo "SELF_TEST_FAIL: the '$kind' copy passed" >&2
      rc=1
    fi
  done
  # The safety guide: a wrong flag, an unguarded "nothing to do", no link
  # back to the offline guide.
  sed -E 's/^( *)raven lan verified-only on$/\1raven lan verified-only on --no-such-flag/' "$SAFETY" >"$dir/safety-flag.md"
  { cat "$SAFETY"; printf '\n## 13. Extra\n\nOn a hotspot there is nothing to do.\n'; } >"$dir/safety-nothing.md"
  sed -E 's/\(OFFLINE_GUIDE\.md\)/(elsewhere.md)/g' "$SAFETY" >"$dir/safety-link.md"
  for kind in safety-flag safety-nothing safety-link; do
    if cmp -s "$SAFETY" "$dir/$kind.md"; then
      echo "SELF_TEST_FAIL: the '$kind' copy is unchanged (the safety guide moved on: update the self-test)" >&2
      rc=1
    elif check_guide "$GUIDE" "$dir/$kind.md" >/dev/null 2>&1; then
      echo "SELF_TEST_FAIL: the '$kind' copy passed" >&2
      rc=1
    fi
  done
  rm -rf "$dir"
  if [[ "$rc" -ne 0 ]]; then
    return 1
  fi
  echo "check_offline_guide self-test OK (check_safety_offline.sh's self-test passes; both guides pass; a wrong flag, an unknown subcommand, an unguarded \"nothing to do\" and a missing link each fail, in either guide)"
}

if [[ "${2:-}" == "--self-test" ]]; then
  self_test
  exit $?
fi
check_guide "$GUIDE" "$SAFETY"
os_commands
