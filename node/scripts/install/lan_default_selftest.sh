#!/usr/bin/env bash
# Self-test of the installers' LAN default (Phase 3 P3.7). macos_launchd.sh and
# linux_systemd_user.sh give the service the address the installed
# `raven-node lan-default` prints (`auto` once the build's B12 gate is open,
# else 127.0.0.1:7420); RAVEN_LAN_LISTEN wins; a raven-node that fails, is
# missing or prints anything else keeps 127.0.0.1:7420; an invalid
# RAVEN_LAN_LISTEN stops the install with exit 1. Phase 6b P6.36: the
# installers ask `raven-node lan-default --data-dir <the profile>` first, so a
# profile that picked a random LAN port gets it (127.0.0.1:PORT, and the
# printed lines name that port), and ask again without the flag when a
# raven-node refuses it (an older build). The build's auto:PORT goes into the
# service as a plain `auto` (Phase 6 review traffic-5): raven-node then
# listens on the profile's port at every start, so `raven lan port random`
# moves the installed service too; a RAVEN_LAN_LISTEN that names a port
# keeps it.
#
# Each case puts a stub raven-node into a temporary BIN_DIR and runs an
# installer with RAVEN_INSTALL_RENDER_ONLY=1: LAN_LISTEN= and the plist / unit
# on stdout, the install's LAN lines on stderr. Nothing real is touched: HOME,
# the profile and BIN_DIR are temporary, the environment holds only PATH and
# the case's variables, and cargo, launchctl, systemctl and loginctl are stubs
# that fail, so a render-only mode that went too far fails here instead of
# acting. The last check is that render-only created nothing.
#
# Runs on ubuntu and macOS CI (on macOS with /bin/bash 3.2, the oldest bash the
# installers support: they run under the bash that runs this script).
set -euo pipefail
INSTALL="$(cd "$(dirname "$0")" && pwd)"
SH="${BASH:-bash}"
T="$(mktemp -d "${TMPDIR:-/tmp}/raven-lan-default.XXXXXX")"
trap 'rm -rf "$T"' EXIT
checks=0
failures=0
rc=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# Commands a render-only run must never reach.
mkdir -p "$T/guard"
for cmd in cargo launchctl systemctl loginctl; do
  cat >"$T/guard/$cmd" <<EOF
#!/bin/sh
echo "lan_default_selftest: a render-only install ran $cmd \$*" >&2
exit 99
EOF
  chmod 755 "$T/guard/$cmd"
done

# stub NAME BODY: the BIN_DIR $T/NAME, whose raven-node runs BODY (sh) for
# `raven-node lan-default` and refuses any other arguments.
stub() {
  mkdir -p "$T/$1"
  cat >"$T/$1/raven-node" <<'EOF'
#!/bin/sh
if [ "$#" -ne 1 ] || [ "$1" != lan-default ]; then
  echo "stub raven-node: unexpected arguments: $*" >&2
  exit 98
fi
EOF
  printf '%s\n' "$2" >>"$T/$1/raven-node"
  chmod 755 "$T/$1/raven-node"
}
stub auto 'echo auto'
stub loopback 'echo 127.0.0.1:7420'
stub fails 'exit 1'
stub older 'echo "error: unrecognized subcommand" >&2; exit 2'
stub odd 'echo "auto --relay"'
stub twolines 'echo auto; echo auto'
# Notes every call: a refused RAVEN_LAN_LISTEN must stop the install before
# the build, so before raven-node is ever asked.
stub asked 'echo lan-default >>"$(dirname "$0")/calls"; echo auto'
# stub_profile NAME ANSWER: the BIN_DIR $T/NAME, whose raven-node prints
# ANSWER for `raven-node lan-default --data-dir <the profile>` (a profile
# that picked port 43210) and `auto` for a plain `lan-default`, and refuses
# anything else (another data dir among it).
stub_profile() {
  mkdir -p "$T/$1"
  cat >"$T/$1/raven-node" <<EOF
#!/bin/sh
if [ "\$#" -eq 3 ] && [ "\$1" = lan-default ] && [ "\$2" = --data-dir ] && [ "\$3" = "$T/profile" ]; then
  echo '$2'
  exit 0
fi
if [ "\$#" -eq 1 ] && [ "\$1" = lan-default ]; then
  echo auto
  exit 0
fi
echo "stub raven-node: unexpected arguments: \$*" >&2
exit 98
EOF
  chmod 755 "$T/$1/raven-node"
}
stub_profile picked auto:43210
stub_profile picked_held 127.0.0.1:43210

# render INSTALLER BIN [NAME=VALUE...]: one render-only run with BIN_DIR $T/BIN;
# stdout in $T/out, stderr in $T/err, exit code in $rc.
render() {
  local installer=$1 bin=$2
  shift 2
  rc=0
  env -i PATH="$T/guard:$PATH" HOME="$T/home" RAVEN_INSTALL_RENDER_ONLY=1 \
    RAVEN_DATA_DIR="$T/profile" RAVEN_BIN_DIR="$T/$bin" "$@" \
    "$SH" "$INSTALL/$installer" </dev/null >"$T/out" 2>"$T/err" || rc=$?
}

# expect INSTALLER WHAT WANT: exit 0, `LAN_LISTEN=WANT` first, and WANT after
# --lan-listen in the rendered plist (as is) or unit (a systemd word).
expect() {
  local inst=$1 what=$2 want=$3 got in_file
  checks=$((checks + 1))
  if [[ "$rc" -ne 0 ]]; then
    fail "$inst, $what: exit $rc: $(tr '\n' ' ' <"$T/err")"
    return 0
  fi
  got="$(head -n 1 "$T/out")"
  [[ "$got" == "LAN_LISTEN=$want" ]] || fail "$inst, $what: printed '$got', want 'LAN_LISTEN=$want'"
  if [[ "$inst" == macos_launchd.sh ]]; then
    in_file="$want"
    got="$(sed -n '/<string>--lan-listen<\/string>/{n;s/^[[:space:]]*<string>\(.*\)<\/string>[[:space:]]*$/\1/p;}' "$T/out")"
  else
    in_file="\"${want//%/%%}\""
    got="$(sed -n 's/^ExecStart=.* --lan-listen \("[^"]*"\) .*$/\1/p' "$T/out")"
  fi
  [[ "$got" == "$in_file" ]] || fail "$inst, $what: the rendered file has --lan-listen '$got', want '$in_file'"
  if [[ "$inst" == macos_launchd.sh ]] && command -v plutil >/dev/null 2>&1; then
    sed -n '2,$p' "$T/out" >"$T/plist"
    plutil -lint -s "$T/plist" >/dev/null 2>&1 || fail "$inst, $what: plutil -lint refuses the rendered plist"
  fi
  return 0
}

# says / says_not INSTALLER WHAT TEXT: the install's LAN lines (stderr) hold
# TEXT / do not.
says() {
  checks=$((checks + 1))
  grep -qF -- "$3" "$T/err" || fail "$1, $2: the LAN lines lack '$3'"
  return 0
}
says_not() {
  checks=$((checks + 1))
  if grep -qF -- "$3" "$T/err"; then
    fail "$1, $2: the LAN lines must not say '$3'"
  fi
  return 0
}

# refused INSTALLER WHAT TEXT: exit 1 with TEXT on stderr, nothing rendered,
# and raven-node never asked (the run used BIN_DIR $T/asked).
refused() {
  checks=$((checks + 1))
  [[ "$rc" -eq 1 ]] || fail "$1, $2: exit $rc, want 1"
  grep -qF -- "$3" "$T/err" || fail "$1, $2: stderr lacks '$3'"
  [[ ! -s "$T/out" ]] || fail "$1, $2: something was rendered: $(head -n 1 "$T/out")"
  [[ ! -e "$T/asked/calls" ]] || fail "$1, $2: refused only after asking raven-node (a real install would have built first)"
  rm -f "$T/asked/calls"
  return 0
}

for inst in macos_launchd.sh linux_systemd_user.sh; do
  # The build's default: auto (gate open), 127.0.0.1:7420 (gate closed), and
  # 127.0.0.1:7420 whenever the answer cannot be used.
  render "$inst" auto
  expect "$inst" "lan-default prints auto" auto
  says "$inst" "lan-default prints auto" "contacts only (TCP 7420; nearby search on UDP 7420)"
  says "$inst" "lan-default prints auto" "On a network you do not trust (cafe, hotel): raven lan off"
  says "$inst" "lan-default prints auto" "RAVEN_LAN_LISTEN=0.0.0.0:7420"
  if [[ "$inst" == macos_launchd.sh ]]; then
    says "$inst" "lan-default prints auto" "socketfilterfw --add $T/auto/raven-node"
    says "$inst" "lan-default prints auto" "socketfilterfw --unblockapp $T/auto/raven-node"
    says "$inst" "lan-default prints auto" "If macOS asks for Local Network access for raven-node, allow it"
  else
    for net in 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 169.254.0.0/16 fe80::/10 fc00::/7; do
      says "$inst" "lan-default prints auto" "ufw allow from $net to any port 7420 proto tcp"
      says "$inst" "lan-default prints auto" "ufw allow from $net to any port 7420 proto udp"
    done
    says "$inst" "lan-default prints auto" "firewall-cmd --get-active-zones"
    says "$inst" "lan-default prints auto" "firewall-cmd --zone=<that zone> --add-port=7420/tcp --add-port=7420/udp"
    says_not "$inst" "lan-default prints auto" "--zone=home"
  fi

  render "$inst" loopback
  expect "$inst" "lan-default prints 127.0.0.1:7420" 127.0.0.1:7420
  says "$inst" "lan-default prints 127.0.0.1:7420" "loopback only"
  says_not "$inst" "lan-default prints 127.0.0.1:7420" "RAVEN_LAN_LISTEN=auto"

  render "$inst" fails
  expect "$inst" "lan-default exits 1" 127.0.0.1:7420
  render "$inst" older
  expect "$inst" "an older raven-node without lan-default" 127.0.0.1:7420
  render "$inst" odd
  expect "$inst" "lan-default prints more than an address" 127.0.0.1:7420
  render "$inst" twolines
  expect "$inst" "lan-default prints two lines" 127.0.0.1:7420
  render "$inst" absent
  expect "$inst" "no raven-node in BIN_DIR" 127.0.0.1:7420

  # Phase 6b P6.36: the profile's own port (lan-default --data-dir), in
  # every line that names the TCP port; the nearby search stays on UDP 7420.
  # The file says a plain auto, which raven-node turns into the profile's
  # port at every start (Phase 6 review traffic-5), so a port picked later
  # with `raven lan port random` is the one the service listens on.
  render "$inst" picked
  expect "$inst" "the profile picked port 43210" auto
  checks=$((checks + 1))
  if grep -qF -- 'auto:43210' "$T/out"; then
    fail "$inst, the profile picked port 43210: the rendered file names the port"
  fi
  says "$inst" "the profile picked port 43210" "contacts only (TCP 43210; nearby search on UDP 7420)"
  says "$inst" "the profile picked port 43210" "RAVEN_LAN_LISTEN=0.0.0.0:43210"
  says_not "$inst" "the profile picked port 43210" "TCP 7420"
  if [[ "$inst" == linux_systemd_user.sh ]]; then
    says "$inst" "the profile picked port 43210" "ufw allow from 192.168.0.0/16 to any port 43210 proto tcp"
    says "$inst" "the profile picked port 43210" "--add-port=43210/tcp --add-port=7420/udp"
  fi
  render "$inst" picked_held
  expect "$inst" "the profile picked port 43210, build holds auto" 127.0.0.1:43210
  says "$inst" "the profile picked port 43210, build holds auto" "loopback only"
  if [[ "$inst" == linux_systemd_user.sh ]]; then
    says "$inst" "the profile picked port 43210, build holds auto" "RAVEN_LAN_LISTEN=<this-host-LAN-IP>:43210 and allow inbound TCP 43210"
  else
    says "$inst" "the profile picked port 43210, build holds auto" "RAVEN_LAN_LISTEN=<this-Mac-LAN-IP>:43210"
  fi
  # RAVEN_LAN_LISTEN still wins over the profile's port.
  render "$inst" picked RAVEN_LAN_LISTEN=auto:7441
  expect "$inst" "RAVEN_LAN_LISTEN=auto:7441 over the profile's port" auto:7441

  # RAVEN_LAN_LISTEN wins over the build's default.
  render "$inst" auto RAVEN_LAN_LISTEN=192.168.1.20:7420
  expect "$inst" "RAVEN_LAN_LISTEN=192.168.1.20:7420" 192.168.1.20:7420
  render "$inst" auto RAVEN_LAN_LISTEN='[fe80::1%en0]:7420'
  expect "$inst" "RAVEN_LAN_LISTEN with an IPv6 zone" '[fe80::1%en0]:7420'
  render "$inst" auto RAVEN_LAN_LISTEN=auto:7441
  expect "$inst" "RAVEN_LAN_LISTEN=auto:7441" auto:7441
  # auto:PORT moves the TCP port only: the nearby search stays on UDP 7420.
  says "$inst" "RAVEN_LAN_LISTEN=auto:7441" "contacts only (TCP 7441; nearby search on UDP 7420)"
  says_not "$inst" "RAVEN_LAN_LISTEN=auto:7441" "UDP 7441"
  if [[ "$inst" == linux_systemd_user.sh ]]; then
    says "$inst" "RAVEN_LAN_LISTEN=auto:7441" "ufw allow from 169.254.0.0/16 to any port 7441 proto tcp"
    says "$inst" "RAVEN_LAN_LISTEN=auto:7441" "ufw allow from 169.254.0.0/16 to any port 7420 proto udp"
    says_not "$inst" "RAVEN_LAN_LISTEN=auto:7441" "port 7441 proto udp"
    says "$inst" "RAVEN_LAN_LISTEN=auto:7441" "--add-port=7441/tcp --add-port=7420/udp"
  fi
  # Loopback chosen while the build allows auto: the hint names auto.
  render "$inst" auto RAVEN_LAN_LISTEN=127.0.0.1:7420
  expect "$inst" "RAVEN_LAN_LISTEN=127.0.0.1:7420, build allows auto" 127.0.0.1:7420
  says "$inst" "RAVEN_LAN_LISTEN=127.0.0.1:7420, build allows auto" "(re-run with RAVEN_LAN_LISTEN=auto, which your build allows)"
  # auto chosen while the build holds it: the lines say what it does there.
  render "$inst" loopback RAVEN_LAN_LISTEN=auto
  expect "$inst" "RAVEN_LAN_LISTEN=auto, build holds auto" auto
  says "$inst" "RAVEN_LAN_LISTEN=auto, build holds auto" "this build holds auto (LAN_AUTO_LISTEN_PRODUCTION_ENABLED=false)"
  says_not "$inst" "RAVEN_LAN_LISTEN=auto, build holds auto" "RAVEN_LAN_LISTEN=0.0.0.0:7420"

  # The rendered file is the whole one: other flags keep their place.
  render "$inst" auto RAVEN_INTERNET_LISTEN=0.0.0.0:7422
  expect "$inst" "with RAVEN_INTERNET_LISTEN" auto
  checks=$((checks + 1))
  grep -qF -- '--internet-listen' "$T/out" || fail "$inst, with RAVEN_INTERNET_LISTEN: the rendered file lacks --internet-listen"

  # Invalid input stops the install before anything is built, asked or
  # rendered.
  render "$inst" asked
  expect "$inst" "the recording raven-node" auto
  checks=$((checks + 1))
  [[ -e "$T/asked/calls" ]] || fail "$inst: the recording raven-node was not asked"
  rm -f "$T/asked/calls"
  render "$inst" asked RAVEN_LAN_LISTEN='0.0.0.0:7420 --relay'
  refused "$inst" "RAVEN_LAN_LISTEN with a space" "RAVEN_LAN_LISTEN must look like auto, 192.168.1.20:7420 or [::]:7420"
  render "$inst" asked RAVEN_LAN_LISTEN='0.0.0.0:7420;true'
  refused "$inst" "RAVEN_LAN_LISTEN with a semicolon" "RAVEN_LAN_LISTEN must look like auto, 192.168.1.20:7420 or [::]:7420"
  render "$inst" asked RAVEN_INSTALL_RENDER_ONLY=yes
  refused "$inst" "RAVEN_INSTALL_RENDER_ONLY=yes" "RAVEN_INSTALL_RENDER_ONLY must be 1"
done

# Render-only created nothing: no home files, no profile, no BIN_DIR.
checks=$((checks + 1))
for path in "$T/home" "$T/profile" "$T/absent"; do
  [[ ! -e "$path" ]] || fail "render-only created ${path#"$T"/}"
done

if [[ "$failures" -ne 0 ]]; then
  echo "lan_default_selftest: $failures of $checks checks failed" >&2
  exit 1
fi
echo "lan_default_selftest OK ($checks checks; macos_launchd.sh and linux_systemd_user.sh, RAVEN_INSTALL_RENDER_ONLY=1)"
