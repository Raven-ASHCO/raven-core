#!/usr/bin/env bash
# Self-test of the macOS installer's Bluetooth nearby helper (Phase 5 P5.32;
# Nearby design step 5.10, owner decision O5-10): macos_launchd.sh with
# RAVEN_INSTALL_NEARBY_ONLY=1 copies RavenNearby.app to
# ~/Library/Application Support/Raven/, signs it (ad hoc here), checks it, and
# leaves the raven-node in RAVEN_BIN_DIR alone: its `codesign -dv` output and
# its bytes are the same before and after, so its Keychain access is too.
#
# A dry run: HOME, the bin dir and the profile are temporary; the environment
# holds only PATH and the case's variables; cargo and launchctl are stubs
# that fail, so an install that went past the helper fails here instead of
# acting. The bundle is built first (node/scripts/build_nearby_helper_app.sh
# --debug --no-sign, the only cargo run) and raven-node is this checkout's
# debug build (built when missing). No Bluetooth is touched: the helper's
# --check reads its own bundle and creates no CoreBluetooth manager.
#
# Cases: a first install and a re-install (the bundle replaced, signed ad hoc
# as org.raven.nearby, raven-node unchanged, no staging folder left, no
# profile, plist or agent); a bundle whose signature does not verify under
# RAVEN_NEARBY_SIGN=keep is refused and the installed one stays; invalid
# settings stop the install before anything is created; render-only with
# RAVEN_INSTALL_NEARBY_HELPER=1 installs no helper (the default since 2026-10:
# a release install builds the radio backend and installs the helper).
#
# macOS only (elsewhere it says so and exits 0). Runs under /bin/bash 3.2,
# the oldest bash the installers support: they run under the bash that runs
# this script.
set -euo pipefail
INSTALL="$(cd "$(dirname "$0")" && pwd)"
NODE="$(cd "$INSTALL/../.." && pwd)"
SH="${BASH:-bash}"
if [[ "$(uname -s)" != Darwin ]]; then
  echo "nearby_helper_selftest: macOS only (RavenNearby.app); nothing to do here"
  exit 0
fi
T="$(mktemp -d "${TMPDIR:-/tmp}/raven-nearby-install.XXXXXX")"
trap 'rm -rf "$T"' EXIT
checks=0
failures=0
rc=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
check() { # WHAT, then a command that must succeed
  local what=$1
  shift
  checks=$((checks + 1))
  "$@" >/dev/null 2>&1 || fail "$what"
  return 0
}

# Commands the helper install must never reach.
mkdir -p "$T/guard"
for cmd in cargo launchctl; do
  cat >"$T/guard/$cmd" <<EOF
#!/bin/sh
echo "nearby_helper_selftest: the helper install ran $cmd \$*" >&2
exit 99
EOF
  chmod 755 "$T/guard/$cmd"
done

# The bundle (unsigned, so every case signs its own copy) and raven-node.
bash "$NODE/scripts/build_nearby_helper_app.sh" "$T/build" --debug --no-sign >/dev/null
APP="$T/build/RavenNearby.app"
TARGET="${CARGO_TARGET_DIR:-$NODE/target}"
if [[ ! -x "$TARGET/debug/raven-node" ]]; then
  (cd "$NODE" && cargo build --locked -q -p raven-node --bin raven-node)
fi
mkdir -p "$T/bin"
cp "$TARGET/debug/raven-node" "$T/bin/raven-node"
DEST="$T/home/Library/Application Support/Raven/RavenNearby.app"

# signature FILE: what the installer compares, the same way.
signature() {
  codesign -dv --verbose=4 "$1" 2>&1 || true
  shasum -a 256 "$1" 2>&1 || true
}

# run_install [NAME=VALUE...]: one run of the installer in the temporary HOME; stdout
# in $T/out, stderr in $T/err, exit code in $rc.
run_install() {
  rc=0
  env -i PATH="$T/guard:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$T/home" \
    RAVEN_DATA_DIR="$T/profile" RAVEN_BIN_DIR="$T/bin" "$@" \
    "$SH" "$INSTALL/macos_launchd.sh" </dev/null >"$T/out" 2>"$T/err" || rc=$?
}

# installed WHAT: exit 0, raven-node unchanged, the bundle in place, signed
# ad hoc as org.raven.nearby, answering --check; nothing else created.
installed() {
  local what=$1 info answer
  checks=$((checks + 1))
  if [[ "$rc" -ne 0 ]]; then
    fail "$what: exit $rc: $(tr '\n' ' ' <"$T/err")"
    return 0
  fi
  checks=$((checks + 1))
  [[ "$(signature "$T/bin/raven-node")" == "$NODE_BEFORE" ]] \
    || fail "$what: raven-node's code signature or bytes changed"
  check "$what: the bundle verifies in place" codesign --verify --strict "$DEST"
  info="$(codesign -dv --verbose=4 "$DEST" 2>&1 || true)"
  checks=$((checks + 1))
  [[ "$info" == *"Identifier=org.raven.nearby"* && "$info" == *"Signature=adhoc"* ]] \
    || fail "$what: not signed ad hoc as org.raven.nearby: $(printf '%s' "$info" | tr '\n' ' ')"
  answer="$("$DEST/Contents/MacOS/raven-nearby-helper" --check </dev/null 2>/dev/null || true)"
  checks=$((checks + 1))
  [[ "$answer" == '{"ev":"hello","v":1}' ]] || fail "$what: --check answered '$answer'"
  checks=$((checks + 1))
  if ls -d "$T/home/Library/Application Support/Raven/".RavenNearby-install.* >/dev/null 2>&1; then
    fail "$what: a staging folder was left behind"
  fi
  checks=$((checks + 1))
  for path in "$T/profile" "$T/home/Library/LaunchAgents" "$T/bin/raven" "$T/bin/ash"; do
    [[ ! -e "$path" ]] || fail "$what: the helper-only install created ${path#"$T"/}"
  done
  says "$what" "raven-node was not re-signed"
  says "$what" "System Settings > Privacy & Security > Bluetooth"
  says "$what" "raven nearby enable"
  return 0
}

# says WHAT TEXT: the install's stdout holds TEXT.
says() {
  checks=$((checks + 1))
  grep -qF -- "$2" "$T/out" || fail "$1: the output lacks '$2'"
  return 0
}

# refused WHAT TEXT: exit 1 with TEXT on stderr, and nothing created.
refused() {
  checks=$((checks + 1))
  [[ "$rc" -eq 1 ]] || fail "$1: exit $rc, want 1"
  grep -qF -- "$2" "$T/err" || fail "$1: stderr lacks '$2': $(tr '\n' ' ' <"$T/err")"
  [[ ! -e "$T/home" && ! -e "$T/profile" ]] || fail "$1: a refused install created files"
  return 0
}

NODE_BEFORE="$(signature "$T/bin/raven-node")"
APP_BEFORE="$(signature "$APP/Contents/MacOS/raven-nearby-helper")"

# Invalid settings stop the install before anything is created.
run_install RAVEN_INSTALL_NEARBY_ONLY=yes
refused "RAVEN_INSTALL_NEARBY_ONLY=yes" "RAVEN_INSTALL_NEARBY_ONLY must be 1"
run_install RAVEN_INSTALL_NEARBY_HELPER=on
refused "RAVEN_INSTALL_NEARBY_HELPER=on" "RAVEN_INSTALL_NEARBY_HELPER must be 1"
run_install RAVEN_INSTALL_TOR_HELPER=yes
refused "RAVEN_INSTALL_TOR_HELPER=yes" "RAVEN_INSTALL_TOR_HELPER must be 1"
run_install RAVEN_INSTALL_NEARBY_ONLY=1 RAVEN_NEARBY_APP="$T/nothing.app"
refused "RAVEN_NEARBY_APP that is no bundle" "RAVEN_NEARBY_APP must name a built RavenNearby.app"
run_install RAVEN_INSTALL_NEARBY_ONLY=1 RAVEN_NEARBY_SIGN=keep
refused "RAVEN_NEARBY_SIGN=keep without RAVEN_NEARBY_APP" "RAVEN_NEARBY_SIGN=keep needs RAVEN_NEARBY_APP"
run_install RAVEN_INSTALL_NEARBY_ONLY=1 RAVEN_INSTALL_RENDER_ONLY=1 RAVEN_NEARBY_APP="$APP"
refused "helper-only with render-only" "cannot be combined"

# Render-only installs no helper, builds nothing and creates nothing.
run_install RAVEN_INSTALL_RENDER_ONLY=1 RAVEN_INSTALL_NEARBY_HELPER=1
checks=$((checks + 1))
[[ "$rc" -eq 0 ]] || fail "render-only with the helper: exit $rc: $(tr '\n' ' ' <"$T/err")"
checks=$((checks + 1))
grep -qF "RavenNearby.app: not installed (render-only" "$T/err" \
  || fail "render-only with the helper: stderr does not say the helper was not installed"
checks=$((checks + 1))
[[ ! -e "$T/home" && ! -e "$T/profile" ]] || fail "render-only with the helper created files"

# The dry run: a first install, then a re-install over it.
run_install RAVEN_INSTALL_NEARBY_ONLY=1 RAVEN_NEARBY_APP="$APP"
installed "first helper-only install"
run_install RAVEN_INSTALL_NEARBY_ONLY=1 RAVEN_NEARBY_APP="$APP"
installed "helper-only re-install"
checks=$((checks + 1))
[[ "$(signature "$APP/Contents/MacOS/raven-nearby-helper")" == "$APP_BEFORE" ]] \
  || fail "RAVEN_NEARBY_APP itself was changed (only its copy is signed)"
# The build facts follow `raven-node ble-status` of the raven-node in BIN_DIR.
BACKEND="$(env -i PATH=/usr/bin:/bin "$T/bin/raven-node" ble-status 2>/dev/null | sed -n 's/^nearby_backend=//p')"
if [[ "$BACKEND" == none ]]; then
  says "helper-only install, no backend" "has no Bluetooth backend"
else
  checks=$((checks + 1))
  if grep -qF "has no Bluetooth backend" "$T/out"; then
    fail "helper-only install, backend $BACKEND: the output says there is none"
  fi
fi
# The gate follows `raven-node ble-status` too: since 2026-10 a release or
# lab-free debug raven-node on macOS has nearby on, so the install says
# nothing about a hold; one that has it off says so.
GATE="$(env -i PATH=/usr/bin:/bin "$T/bin/raven-node" ble-status 2>/dev/null | sed -n 's/^nearby_gate=//p')"
if [[ "$GATE" == held ]]; then
  says "helper-only install, gate held" "This raven-node holds Bluetooth nearby"
else
  checks=$((checks + 1))
  if grep -qF "holds Bluetooth nearby" "$T/out"; then
    fail "helper-only install, gate $GATE: the output says nearby is held"
  fi
fi

# A bundle whose signature does not verify is refused under keep, and the
# installed one stays as it was.
INSTALLED_BEFORE="$(codesign -dv --verbose=4 "$DEST" 2>&1 || true)"
ditto "$APP" "$T/bad/RavenNearby.app"
codesign --force --sign - --identifier org.raven.nearby "$T/bad/RavenNearby.app" >/dev/null 2>&1
printf '\n' >>"$T/bad/RavenNearby.app/Contents/Info.plist"
run_install RAVEN_INSTALL_NEARBY_ONLY=1 RAVEN_NEARBY_APP="$T/bad/RavenNearby.app" RAVEN_NEARBY_SIGN=keep
checks=$((checks + 1))
[[ "$rc" -eq 1 ]] || fail "a bundle that does not verify: exit $rc, want 1"
checks=$((checks + 1))
grep -qF "its code signature does not verify" "$T/err" \
  || fail "a bundle that does not verify: stderr lacks the reason: $(tr '\n' ' ' <"$T/err")"
checks=$((checks + 1))
[[ "$(codesign -dv --verbose=4 "$DEST" 2>&1 || true)" == "$INSTALLED_BEFORE" ]] \
  || fail "a refused install changed the installed helper"
check "the installed helper still verifies after a refused install" codesign --verify --strict "$DEST"
checks=$((checks + 1))
[[ "$(signature "$T/bin/raven-node")" == "$NODE_BEFORE" ]] \
  || fail "a refused install changed raven-node"
checks=$((checks + 1))
if ls -d "$T/home/Library/Application Support/Raven/".RavenNearby-install.* >/dev/null 2>&1; then
  fail "a refused install left a staging folder"
fi

if [[ "$failures" -ne 0 ]]; then
  echo "nearby_helper_selftest: $failures of $checks checks failed" >&2
  exit 1
fi
echo "nearby_helper_selftest OK ($checks checks; macos_launchd.sh RAVEN_INSTALL_NEARBY_ONLY=1: RavenNearby.app signed and in place, raven-node's code signature unchanged)"
