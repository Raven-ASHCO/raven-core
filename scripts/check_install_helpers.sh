#!/usr/bin/env bash
# The relay kit's shared helpers (node/scripts/install/relay_common.sh) carry
# verbatim copies of two quoting functions: sd_quote from
# linux_systemd_user.sh (systemd unit words) and xml_escape from
# macos_launchd.sh (plist strings). A fix to one copy must reach the other:
# exit 1 when they differ, or when a function is missing.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="$REPO/node/scripts/install"
bad=0

# The function NAME from its `NAME() {` line to the first `}` at column 0.
extract() {
  awk -v start="^$1\\\\(\\\\) \\\\{" '$0 ~ start { on = 1 } on { print } on && /^\}/ { exit }' "$2"
}

check() {
  local name=$1 source=$2 copy=$3 a b
  a="$(extract "$name" "$INSTALL/$source")"
  b="$(extract "$name" "$INSTALL/$copy")"
  if [[ -z "$a" || -z "$b" ]]; then
    echo "INSTALL_HELPER_MISSING: $name() not found in $source or $copy" >&2
    bad=1
  elif [[ "$a" != "$b" ]]; then
    echo "INSTALL_HELPER_DRIFT: $name() differs between $source and $copy:" >&2
    diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") >&2 || true
    bad=1
  fi
}

check sd_quote linux_systemd_user.sh relay_common.sh
check xml_escape macos_launchd.sh relay_common.sh

if [[ "$bad" -ne 0 ]]; then
  exit 1
fi
echo "install helpers OK (sd_quote, xml_escape identical in relay_common.sh)"
