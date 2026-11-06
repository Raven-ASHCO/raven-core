#!/usr/bin/env bash
# Static self test of the installers' hardening (security review 2026-11).
# Nothing runs but bash -n, grep and awk on the installer files and on copies
# of them in a temporary folder: no installer runs, nothing is built, nothing
# is installed or started.
#
#   WINLIN-1  linux_relay.sh runs `raven-node relay --check` as the relay's
#             account (setpriv: its uid and gid, no new privileges, and
#             CAP_NET_BIND_SERVICE only when a port is below 1024), from a
#             copy root staged; root runs it only on a first install (no relay
#             account and no folder yet); and nothing in the relay folder is
#             chowned recursively as root.
#
# Then each check is shown to catch a copy that undoes it, so a check that
# can no longer fail is caught too. Runs on ubuntu CI and under macOS
# /bin/bash 3.2.
set -euo pipefail
INSTALL="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/raven-hardening.XXXXXX")"
trap 'rm -rf "$T"' EXIT
checks=0
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# FILE as commands, one per line: every line that ends in a backslash joined
# to the next, runs of blanks squeezed to one space, whole-line comments and
# empty lines dropped. With START and END (awk regexes), only the lines from
# the one matching START to the one before the next line matching END.
code_of() {
  awk -v start="${2:-}" -v end="${3:-}" '
    start != "" && !on { if ($0 ~ start) on = 1; else next }
    on && end != "" && $0 ~ end { exit }
    {
      if (sub(/\\$/, "")) { buf = buf $0 " "; next }
      line = buf $0; buf = ""
      gsub(/[ \t]+/, " ", line); sub(/^ /, "", line); sub(/ $/, "", line)
      if (line != "" && line !~ /^#/) print line
    }' "$1"
}

# The number of the first line of CODE that holds TEXT (a fixed string), or
# 0. With a third argument `line`, the first line that is exactly TEXT.
line_of() {
  local n
  if [[ "${3:-}" == line ]]; then
    n="$(grep -m 1 -nxF -- "$2" <<<"$1" || true)"
  else
    n="$(grep -m 1 -nF -- "$2" <<<"$1" || true)"
  fi
  n="${n%%:*}"
  echo "${n:-0}"
}

# How many lines of CODE hold TEXT.
count_of() {
  grep -cF -- "$2" <<<"$1" || true
}

# The first line of CODE that holds TEXT, or nothing.
first_with() {
  grep -m 1 -F -- "$2" <<<"$1" || true
}

# in_order WHAT N1 N2 ...: each line number is set (not 0) and greater than
# the one before it.
in_order() {
  local what=$1 prev=0 n
  shift
  checks=$((checks + 1))
  for n in "$@"; do
    if [[ "$n" -eq 0 || "$n" -le "$prev" ]]; then
      fail "$what"
      return 0
    fi
    prev=$n
  done
}

# WINLIN-1: linux_relay.sh (FILE) runs its check of the relay folder as the
# relay's account.
check_relay() {
  local file=$1 code step5 run frag
  local n_if n_stage n_run n_rm n_elif n_die n_else n_root n_low n_check
  checks=$((checks + 1))
  bash -n "$file" || fail "linux_relay.sh: bash -n"
  code="$(code_of "$file")"
  step5="$(code_of "$file" '^# 5[.] ' '^# 6[.] ')"

  checks=$((checks + 1))
  if grep -qE 'chown[[:space:]]+(-[[:alpha:]]*R|--recursive)' <<<"$code"; then
    fail "linux_relay.sh chowns recursively as root (WINLIN-1: never in the folder the relay account controls)"
  fi

  checks=$((checks + 1))
  if [[ "$(count_of "$code" 'relay --check')" -ne 2 || "$(count_of "$step5" 'relay --check')" -ne 2 ]]; then
    fail "linux_relay.sh runs relay --check other than twice in step 5 (as the relay account, and as root on a first install)"
  fi

  # The run as the relay's account: setpriv with its uid and gid, its
  # groups, no new privileges, the capability set, a clean environment and
  # root's staged copy, from /.
  run="$(first_with "$step5" '"$check_bin" relay --check --data-dir "$STATE_DIR"')"
  checks=$((checks + 1))
  if [[ -z "$run" || "$run" != '(cd / && as_root setpriv '* ]]; then
    fail "linux_relay.sh: the check of an existing relay folder is not (cd / && as_root setpriv ...) on the staged copy"
  fi
  for frag in '--reuid="$relay_uid"' '--regid="$relay_gid"' '--init-groups' '--no-new-privs' \
    '"${check_caps[@]}" -- env -i HOME="$STATE_DIR" PATH=/usr/bin:/bin "${check_env[@]}" "$check_bin"'; do
    checks=$((checks + 1))
    [[ "$run" == *"$frag"* ]] || fail "linux_relay.sh: the setpriv check lacks $frag"
  done
  checks=$((checks + 1))
  if [[ "$(line_of "$step5" 'if relay_uid="$(id -u "$RELAY_USER" 2>/dev/null)"; then' line)" -eq 0 \
    || "$(line_of "$step5" 'relay_gid="$(id -g "$RELAY_USER")"' line)" -eq 0 ]]; then
    fail "linux_relay.sh: the setpriv ids are not those of the relay account (id -u, id -g \$RELAY_USER)"
  fi

  # Capabilities: none, or CAP_NET_BIND_SERVICE alone when a port is below
  # 1024 (as the unit, step 8).
  checks=$((checks + 1))
  [[ "$(line_of "$step5" 'check_caps=(--inh-caps=-all)' line)" -ne 0 ]] \
    || fail "linux_relay.sh: the check does not start from no capabilities (check_caps=(--inh-caps=-all))"
  n_low="$(line_of "$step5" 'if [[ $low_port -eq 1 ]]; then' line)"
  in_order "linux_relay.sh: CAP_NET_BIND_SERVICE is not the only capability, given only when a port is below 1024" \
    "$n_low" "$(line_of "$step5" 'check_caps=(--inh-caps=-all,+net_bind_service --ambient-caps=+net_bind_service)' line)"
  n_check="$(line_of "$code" 'relay --check')"
  in_order "linux_relay.sh: low_port is not worked out once, before the check" \
    "$(line_of "$code" 'low_port=0' line)" "$n_check"
  checks=$((checks + 1))
  [[ "$(count_of "$code" 'low_port=0')" -eq 1 ]] || fail "linux_relay.sh: low_port is worked out more than once"
  checks=$((checks + 1))
  [[ -n "$(first_with "$code" 'command -v setpriv')" ]] || fail "linux_relay.sh does not ask for setpriv first"

  # The order: the account exists, then root's copy, the run, its removal;
  # a folder without the account is refused; root checks only what is
  # left, a first install.
  n_if="$(line_of "$step5" 'if relay_uid="$(id -u "$RELAY_USER" 2>/dev/null)"; then' line)"
  n_stage="$(line_of "$step5" 'as_root install -m 755 "$RELAY_NODE_BIN" "$check_bin"')"
  n_run="$(line_of "$step5" '"$check_bin" relay --check')"
  n_rm="$(line_of "$step5" 'as_root rm -f "$check_bin"' line)"
  n_elif="$(line_of "$step5" 'elif as_root test -e "$STATE_DIR" || as_root test -L "$STATE_DIR"; then' line)"
  n_die="$(line_of "$step5" 'relay_die "$STATE_DIR exists, but the user $RELAY_USER does not')"
  n_else="$(line_of "$step5" 'else' line)"
  n_root="$(line_of "$step5" '"$RELAY_NODE_BIN" relay --check')"
  in_order "linux_relay.sh step 5: not (account: stage, run as it, remove; folder without account: refuse; else root)" \
    "$n_if" "$n_stage" "$n_run" "$n_rm" "$n_elif" "$n_die" "$n_else" "$n_root"
  checks=$((checks + 1))
  [[ "$(line_of "$step5" 'check_bin="$LIB_DIR/.raven-node.check"' line)" -ne 0 ]] \
    || fail "linux_relay.sh: the staged copy is not in \$LIB_DIR (root owned)"
}

# FILE with TEXT (a fixed string) in its first line that holds it replaced
# by WITH (\n is a new line).
replace() {
  awk -v from="$2" -v to="$3" '
    !done && (i = index($0, from)) { $0 = substr($0, 1, i - 1) to substr($0, i + length(from)); done = 1 }
    { print }' "$1"
}

# caught WHAT CHECKER FILE TEXT WITH: CHECKER finds a problem in a copy of
# FILE with TEXT replaced by WITH (and that copy differs from FILE).
caught() {
  local what=$1 checker=$2 file=$3 copy before counted found
  checks=$((checks + 1))
  copy="$T/$(basename "$file").$checks"
  replace "$file" "$4" "$5" >"$copy"
  if cmp -s "$file" "$copy"; then
    fail "self test: the copy where $what is unchanged (its text moved?)"
    return 0
  fi
  before=$failures
  counted=$checks
  "$checker" "$copy" 2>/dev/null
  found=$((failures - before))
  failures=$before
  checks=$counted
  [[ $found -gt 0 ]] || fail "self test: a copy where $what passed the checks"
}

check_relay "$INSTALL/linux_relay.sh"

RELAY="$INSTALL/linux_relay.sh"
caught "the folder is chowned again" check_relay "$RELAY" \
  'as_root install -d -o "$RELAY_USER" -g "$RELAY_USER" -m 700 "$STATE_DIR"' \
  'as_root install -d -o "$RELAY_USER" -g "$RELAY_USER" -m 700 "$STATE_DIR"\nas_root chown -R "$RELAY_USER:$RELAY_USER" "$STATE_DIR"'
caught "the check runs as root" check_relay "$RELAY" \
  'as_root setpriv --reuid="$relay_uid" --regid="$relay_gid" --init-groups --no-new-privs' 'as_root'
caught "the check may gain privileges" check_relay "$RELAY" ' --no-new-privs' ''
caught "the check keeps the environment of root" check_relay "$RELAY" '-- env -i HOME=' '-- env HOME='
caught "the check runs the binary in the build folder" check_relay "$RELAY" \
  '"${check_env[@]}" "$check_bin" relay --check' '"${check_env[@]}" "$RELAY_NODE_BIN" relay --check'
caught "root checks every install" check_relay "$RELAY" \
  'if relay_uid="$(id -u "$RELAY_USER" 2>/dev/null)"; then' 'if false; then'
caught "a folder without the account is checked as root" check_relay "$RELAY" \
  'elif as_root test -e "$STATE_DIR" || as_root test -L "$STATE_DIR"; then' 'elif false; then'
caught "the check always has CAP_NET_BIND_SERVICE" check_relay "$RELAY" \
  'check_caps=(--inh-caps=-all)' 'check_caps=(--inh-caps=-all,+net_bind_service --ambient-caps=+net_bind_service)'
caught "a third check runs" check_relay "$RELAY" \
  'as_root systemctl daemon-reload' 'as_root env "$RELAY_NODE_BIN" relay --check --data-dir "$STATE_DIR"\nas_root systemctl daemon-reload'

if [[ "$failures" -ne 0 ]]; then
  echo "installer_hardening_selftest: $failures of $checks checks failed" >&2
  exit 1
fi
echo "installer_hardening_selftest OK ($checks checks; linux_relay.sh, each check caught a copy that undoes it)"
