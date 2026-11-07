#!/usr/bin/env bash
# Static self test of the installers' hardening (security review 2026-11).
# Nothing runs but bash -n, grep and awk on the installer files and on copies
# of them in a temporary folder, and two printing functions taken out of
# linux_systemd_user.sh: no installer runs, nothing is built, nothing is
# installed or started.
#
#   WINLIN-1  linux_relay.sh runs `raven-node relay --check` as the relay's
#             account (setpriv: its uid and gid, no new privileges, and
#             CAP_NET_BIND_SERVICE only when a port is below 1024), from a
#             copy root staged; root runs it only on a first install (no relay
#             account and no folder yet); and nothing in the relay folder is
#             chowned recursively as root.
#   PRIV-3    linux_systemd_user.sh's unit appends the service's output (a
#             line per message that arrives) to raven-node-service.log in the
#             profile, capped at 1 MiB, made owner only before the start, and
#             sends nothing to the systemd journal (no log at all where
#             systemd is older than 240 and cannot append to a file).
#   WINLIN-3  windows_service.ps1 and windows_relay.ps1 give -BinDir (the
#             programs a logon task starts) an explicit, protected ACL: one
#             Protect-BinDir, the same in both, that checks the owner, drops
#             what the folder inherited, allows only the user, SYSTEM and
#             Administrators, and reads the result back; called right after
#             the folder is made, never in render-only mode or an uninstall.
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
    "$n_low" "$(line_of "$step5" 'check_caps=("--inh-caps=-all,+net_bind_service" "--ambient-caps=+net_bind_service")' line)"
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

# The function NAME of FILE, from its `NAME() {` line to the first `}` at
# column 0 (as scripts/check_install_helpers.sh takes it).
fn_of() {
  awk -v start="^$1[(][)] [{]" '$0 ~ start { on = 1 } on { print } on && /^[}]/ { exit }' "$2"
}

# What FUNCTIONS (shell text) print for COMMAND, comment lines left out.
printed() {
  bash -c "$1"$'\n'"$2" 2>&1 | grep -v '^#' || true
}

# PRIV-3: linux_systemd_user.sh (FILE) gives the unit a log file in the
# profile, capped, and never the journal.
check_user_unit() {
  local file=$1 code unit fns out
  checks=$((checks + 1))
  bash -n "$file" || fail "linux_systemd_user.sh: bash -n"
  code="$(code_of "$file")"
  unit="$(fn_of render_unit "$file")"

  in_order "linux_systemd_user.sh: the unit does not take its output lines (service_log_lines) in [Service]" \
    "$(line_of "$unit" '[Service]' line)" "$(line_of "$unit" '$(service_log_lines)' line)" \
    "$(line_of "$unit" '[Install]' line)"
  checks=$((checks + 1))
  [[ "$(count_of "$unit" 'Standard')" -eq 0 ]] \
    || fail "linux_systemd_user.sh: render_unit sets an output of its own, besides service_log_lines"
  checks=$((checks + 1))
  if grep -qE '(StandardOutput|StandardError)=[^ ]*(journal|syslog|kmsg)' <<<"$code"; then
    fail "linux_systemd_user.sh sends the service output to the journal"
  fi
  checks=$((checks + 1))
  [[ "$(line_of "$code" 'SERVICE_LOG="${DATA_DIR}/raven-node-service.log"' line)" -ne 0 ]] \
    || fail "linux_systemd_user.sh: the service log is not raven-node-service.log in the profile"

  # What the unit says, from the two functions themselves.
  fns="$(fn_of sd_path "$file")"$'\n'"$(fn_of service_log_lines "$file")"
  out="$(printed "$fns" 'LOG_TO_FILE=1 SERVICE_LOG="/home/u/50%/raven-node-service.log" service_log_lines')"
  checks=$((checks + 1))
  [[ "$out" == 'StandardOutput=append:/home/u/50%%/raven-node-service.log
StandardError=inherit
Environment=RAVEN_SERVICE_LOG_MAX_BYTES=1048576' ]] \
    || fail "linux_systemd_user.sh: the unit does not append its output to the capped log file (got: ${out:-nothing})"
  out="$(printed "$fns" 'LOG_TO_FILE=0 SERVICE_LOG=/p/raven-node-service.log service_log_lines')"
  checks=$((checks + 1))
  [[ "$out" == 'StandardOutput=null
StandardError=null' ]] \
    || fail "linux_systemd_user.sh: a systemd that cannot append does not get null output (got: ${out:-nothing})"
  checks=$((checks + 1))
  [[ "$(line_of "$code" 'if [[ -n "$SD_VERSION" && "$SD_VERSION" -lt 240 ]]; then' line)" -ne 0 \
    && "$(count_of "$code" 'LOG_TO_FILE=0')" -eq 1 ]] \
    || fail "linux_systemd_user.sh: the log file is not used whenever systemd is 240 or later"

  # Made owner only before the start, never in render-only mode.
  in_order "linux_systemd_user.sh: the log file is not made owner only after render-only and before the start" \
    "$(line_of "$code" 'render_unit >"$UNIT"' line)" "$(line_of "$code" '(umask 077 && : >>"$SERVICE_LOG")')" \
    "$(line_of "$code" 'chmod 600 "$SERVICE_LOG"')" "$(line_of "$code" 'systemctl --user restart raven-node.service' line)"
  checks=$((checks + 1))
  [[ -n "$(first_with "$code" '*[[:cntrl:]]*)')" ]] \
    || fail "linux_systemd_user.sh: a data folder with a control character is not refused"
}

# The PowerShell function NAME of FILE, from its `function NAME(` line to the
# first `}` at column 0.
ps_fn_of() {
  awk -v start="^function $1[(]" '$0 ~ start { on = 1 } on { print } on && /^[}]/ { exit }' "$2"
}

# The number of the first line of CODE after line FROM that is exactly TEXT,
# or 0.
line_after() {
  awk -v from="$2" -v text="$3" 'NR > from + 0 && $0 == text { print NR; found = 1; exit }
    END { if (!found) print 0 }' <<<"$1"
}

# WINLIN-3: windows_service.ps1 (SERVICE) and windows_relay.ps1 (RELAY) give
# -BinDir an explicit, protected ACL.
check_windows() {
  local service=$1 relay=$2 fn frag code n_def n_new n_render n_else n_resolve
  fn="$(ps_fn_of Protect-BinDir "$service")"
  checks=$((checks + 1))
  if [[ -z "$fn" || "$fn" != "$(ps_fn_of Protect-BinDir "$relay")" ]]; then
    fail "Protect-BinDir is missing, or differs between windows_service.ps1 and windows_relay.ps1"
  fi
  for frag in '$allowed = @($user, "S-1-5-18", "S-1-5-32-544")' \
    'GetOwner([System.Security.Principal.SecurityIdentifier]).Value' \
    'if ($allowed -notcontains $owner) {' \
    '/inheritance:r /grant:r "*${user}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"' \
    'if ($LASTEXITCODE -ne 0) {' \
    'if (-not $acl.AreAccessRulesProtected) {' \
    'GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])'; do
    checks=$((checks + 1))
    [[ "$fn" == *"$frag"* ]] || fail "Protect-BinDir lacks $frag"
  done
  checks=$((checks + 1))
  if grep -qiE 'Set-Acl|SetAccessControl' <<<"$fn"; then
    fail "Protect-BinDir writes the ACL with Set-Acl (it asks for the audit privilege) instead of icacls"
  fi

  # windows_service.ps1: after the folder is made and resolved, in the branch
  # that is not render-only (that one shows -BinDir as given and changes
  # nothing), and only there.
  code="$(code_of "$service")"
  n_def="$(line_of "$code" 'function Protect-BinDir([string]$Dir) {' line)"
  n_render="$(line_of "$code" 'if ($renderOnly) {' line)"
  n_else="$(line_after "$code" "$n_render" '} else {')"
  n_new="$(line_after "$code" "$n_else" 'New-Item -ItemType Directory -Force -Path $BinDir | Out-Null')"
  n_resolve="$(line_after "$code" "$n_new" '$BinDir = (Resolve-Path -LiteralPath $BinDir).Path')"
  in_order "windows_service.ps1: Protect-BinDir is not defined first, then called right after -BinDir is made and resolved outside render-only" \
    "$n_def" "$n_render" "$n_else" "$n_new" "$n_resolve" "$(line_after "$code" "$n_resolve" 'Protect-BinDir $BinDir')"
  checks=$((checks + 1))
  [[ "$(line_after "$code" "$n_resolve" 'Protect-BinDir $BinDir')" -eq $((n_resolve + 1)) \
    && "$(count_of "$code" 'Protect-BinDir $BinDir')" -eq 1 ]] \
    || fail "windows_service.ps1: Protect-BinDir \$BinDir is not the one call, on the line after -BinDir is resolved"

  # windows_relay.ps1: right after -BinDir is made and resolved, before
  # kit.conf is read from it; not for -Uninstall, which only removes files.
  code="$(code_of "$relay")"
  n_def="$(line_of "$code" 'function Protect-BinDir([string]$Dir) {' line)"
  n_new="$(line_of "$code" 'New-Item -ItemType Directory -Force -Path $BinDir | Out-Null' line)"
  n_resolve="$(line_after "$code" "$n_new" '$BinDir = (Resolve-Path -LiteralPath $BinDir).Path')"
  in_order "windows_relay.ps1: Protect-BinDir is not defined first, then called right after -BinDir is made and resolved" \
    "$n_def" "$n_new" "$n_resolve" "$(line_of "$code" '$kitConf = Join-Path $BinDir "kit.conf"' line)"
  checks=$((checks + 1))
  [[ "$(line_after "$code" "$n_resolve" 'if (-not $Uninstall) { Protect-BinDir $BinDir }')" -eq $((n_resolve + 1)) \
    && "$(count_of "$code" 'Protect-BinDir $BinDir')" -eq 1 ]] \
    || fail "windows_relay.ps1: Protect-BinDir \$BinDir is not the one call, on the line after -BinDir is resolved"
}

# check_windows with a copy of one of the two scripts.
check_service_copy() {
  check_windows "$1" "$INSTALL/windows_relay.ps1"
}
check_relay_ps1_copy() {
  check_windows "$INSTALL/windows_service.ps1" "$1"
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
  'check_caps=(--inh-caps=-all)' 'check_caps=("--inh-caps=-all,+net_bind_service" "--ambient-caps=+net_bind_service")'
caught "a third check runs" check_relay "$RELAY" \
  'as_root systemctl daemon-reload' 'as_root env "$RELAY_NODE_BIN" relay --check --data-dir "$STATE_DIR"\nas_root systemctl daemon-reload'

check_user_unit "$INSTALL/linux_systemd_user.sh"

USER_UNIT="$INSTALL/linux_systemd_user.sh"
caught "the output goes to the journal" check_user_unit "$USER_UNIT" \
  "printf 'StandardOutput=append:%s\\\\n' \"\$(sd_path \"\$SERVICE_LOG\")\"" "printf 'StandardOutput=journal\\\\n'"
caught "stderr goes to the journal" check_user_unit "$USER_UNIT" \
  "printf 'StandardError=inherit\\\\n'" "printf 'StandardError=journal\\\\n'"
caught "the log has no cap" check_user_unit "$USER_UNIT" \
  "printf 'Environment=RAVEN_SERVICE_LOG_MAX_BYTES=1048576\\\\n'" ':'
caught "the unit takes no output lines" check_user_unit "$USER_UNIT" '$(service_log_lines)' ''
caught "a percent sign in the path is not doubled" check_user_unit "$USER_UNIT" \
  '"${1//%/%%}"' '"$1"'
caught "an old systemd falls back to the journal" check_user_unit "$USER_UNIT" \
  "printf 'StandardOutput=null\\\\n'" "printf 'StandardOutput=journal\\\\n'"
caught "the log file keeps the umask" check_user_unit "$USER_UNIT" \
  '(umask 077 && : >>"$SERVICE_LOG")' '(: >>"$SERVICE_LOG")'

check_windows "$INSTALL/windows_service.ps1" "$INSTALL/windows_relay.ps1"

SERVICE_PS1="$INSTALL/windows_service.ps1"
RELAY_PS1="$INSTALL/windows_relay.ps1"
caught "the service installer keeps the inherited ACL" check_service_copy "$SERVICE_PS1" 'Protect-BinDir $BinDir' ''
caught "the relay installer keeps the inherited ACL" check_relay_ps1_copy "$RELAY_PS1" \
  'if (-not $Uninstall) { Protect-BinDir $BinDir }' ''
caught "render-only changes the ACL" check_service_copy "$SERVICE_PS1" \
  '$BinDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BinDir)' \
  '$BinDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BinDir)\n    Protect-BinDir $BinDir'
caught "the folder keeps what it inherits" check_service_copy "$SERVICE_PS1" '/inheritance:r ' ''
caught "the two copies drift" check_relay_ps1_copy "$RELAY_PS1" '"*S-1-5-32-544:(OI)(CI)F"' '"*S-1-5-32-545:(OI)(CI)F"'
caught "the ACL is not read back" check_service_copy "$SERVICE_PS1" \
  'if (-not $acl.AreAccessRulesProtected) {' 'if ($false) {'
caught "any owner is taken" check_service_copy "$SERVICE_PS1" \
  'if ($allowed -notcontains $owner) {' 'if ($false) {'

if [[ "$failures" -ne 0 ]]; then
  echo "installer_hardening_selftest: $failures of $checks checks failed" >&2
  exit 1
fi
echo "installer_hardening_selftest OK ($checks checks; linux_relay.sh, linux_systemd_user.sh, windows_service.ps1 and windows_relay.ps1, each check caught a copy that undoes it)"
