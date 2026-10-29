# shellcheck shell=bash
# Shared by the relay kit's installers (linux_relay.sh, macos_relay.sh; guide:
# docs/RELAY_KIT.md). Sourced, never run: the caller sets `set -euo pipefail`
# and RELAY_KIT_DIR (the folder of this file). Written for macOS /bin/bash 3.2
# too: no associative arrays, no ${x,,}, and every array it fills is non-empty
# before it is expanded under set -u.
#
# Settings come from the environment first, then kit.conf (KEY=VALUE lines the
# installer wrote on the last run), then the defaults. kit.conf is PARSED here,
# never sourced: a line that is not a known key with a plain value refuses the
# whole run.

# Exit codes of the installers (and of `raven-node relay --check`, passed on).
RELAY_EXIT_FAILED=1
RELAY_EXIT_SETTINGS=2

relay_die() {
  echo "relay kit: $1" >&2
  exit "${2:-$RELAY_EXIT_FAILED}"
}

relay_note() {
  echo "relay kit: $*"
}

# Every key kit.conf may hold. RAVEN_RELAY_DIR / _BIN_DIR / _USER are written
# by the installer for the raven-relay wrapper; the rest are settings.
RELAY_KNOWN_KEYS="RAVEN_RELAY_PORT RAVEN_RELAY_TCP443 RAVEN_RELAY_HOST RAVEN_RELAY_AUTONAT RAVEN_RELAY_COUNTS_EVERY RAVEN_RELAY_LAB RAVEN_RELAY_HARDENING RAVEN_RELAY_SYSTEM RAVEN_RELAY_DIR RAVEN_RELAY_BIN_DIR RAVEN_RELAY_USER"

# A kit.conf value: letters, digits and . _ : / @ [ ] - and spaces (a macOS
# home folder may hold one). No quote, $, backslash or ; ever.
RELAY_VALUE_RE='^[][A-Za-z0-9._:/@ -]*$'
# The relay's public address: an IP literal (IPv6 maybe in brackets) or a DNS
# name. raven-node checks the rest (--public-host).
RELAY_HOST_RE='^\[?[0-9A-Fa-f:.]+\]?$|^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$'

# relay_load_settings CONF: fill the RAVEN_RELAY_* settings (environment, then
# CONF when it exists, then the defaults) and check every one of them.
relay_load_settings() {
  local conf=$1 line k v n=0
  if [[ -n "${RAVEN_RELAY_OPEN+x}" ]]; then
    relay_die "RAVEN_RELAY_OPEN is refused: the kit never runs an open relay (one anyone may reserve on). Start raven-node relay by hand if you really mean that (raven-node relay --help)." "$RELAY_EXIT_SETTINGS"
  fi
  if [[ -f "$conf" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      n=$((n + 1))
      case "$line" in
        \#*|'') continue ;;
        RAVEN_RELAY_[A-Z0-9_]*=*)
          k=${line%%=*}
          v=${line#*=}
          case " $RELAY_KNOWN_KEYS " in
            *" $k "*) ;;
            *) relay_die "$conf line $n: unknown setting $k" "$RELAY_EXIT_SETTINGS" ;;
          esac
          [[ "$v" =~ $RELAY_VALUE_RE ]] || relay_die "$conf line $n: bad value for $k" "$RELAY_EXIT_SETTINGS"
          # The environment (and an earlier line) wins.
          [[ -n "${!k+x}" ]] || printf -v "$k" '%s' "$v"
          ;;
        *) relay_die "$conf line $n: not a RAVEN_RELAY_KEY=value line" "$RELAY_EXIT_SETTINGS" ;;
      esac
    done <"$conf"
  fi
  : "${RAVEN_RELAY_PORT:=7423}"
  : "${RAVEN_RELAY_TCP443:=direct}"
  : "${RAVEN_RELAY_HOST:=}"
  : "${RAVEN_RELAY_AUTONAT:=1}"
  : "${RAVEN_RELAY_COUNTS_EVERY:=300}"
  : "${RAVEN_RELAY_LAB:=0}"
  : "${RAVEN_RELAY_HARDENING:=full}"
  : "${RAVEN_RELAY_SYSTEM:=0}"
  if [[ ! "$RAVEN_RELAY_PORT" =~ ^[0-9]{1,5}$ ]] \
    || (( 10#$RAVEN_RELAY_PORT < 1 || 10#$RAVEN_RELAY_PORT > 65535 )); then
    relay_die "RAVEN_RELAY_PORT must be a port (1-65535), e.g. 7423" "$RELAY_EXIT_SETTINGS"
  fi
  RAVEN_RELAY_PORT=$((10#$RAVEN_RELAY_PORT))
  case "$RAVEN_RELAY_TCP443" in
    direct|7443|off) ;;
    *) relay_die "RAVEN_RELAY_TCP443 must be direct (listen on TCP 443), 7443 (listen on 7443; your router or firewall maps 443 to it) or off" "$RELAY_EXIT_SETTINGS" ;;
  esac
  if [[ "$RAVEN_RELAY_TCP443" == direct && "$RAVEN_RELAY_PORT" == 443 ]] \
    || [[ "$RAVEN_RELAY_TCP443" == 7443 && "$RAVEN_RELAY_PORT" == 7443 ]]; then
    relay_die "RAVEN_RELAY_PORT=$RAVEN_RELAY_PORT is already the TCP 443 listener: set RAVEN_RELAY_TCP443=off" "$RELAY_EXIT_SETTINGS"
  fi
  if [[ -n "$RAVEN_RELAY_HOST" && ! "$RAVEN_RELAY_HOST" =~ $RELAY_HOST_RE ]]; then
    relay_die "RAVEN_RELAY_HOST must be the public IP or DNS name friends reach this relay at, e.g. 203.0.113.7 or relay.example.org" "$RELAY_EXIT_SETTINGS"
  fi
  case "$RAVEN_RELAY_AUTONAT" in
    0|1) ;;
    *) relay_die "RAVEN_RELAY_AUTONAT must be 1 (answer reachability checks for your friends) or 0" "$RELAY_EXIT_SETTINGS" ;;
  esac
  if [[ ! "$RAVEN_RELAY_COUNTS_EVERY" =~ ^[0-9]{2,4}$ ]] \
    || (( 10#$RAVEN_RELAY_COUNTS_EVERY < 30 || 10#$RAVEN_RELAY_COUNTS_EVERY > 3600 )); then
    relay_die "RAVEN_RELAY_COUNTS_EVERY must be 30-3600 (seconds between two counts lines in the log)" "$RELAY_EXIT_SETTINGS"
  fi
  RAVEN_RELAY_COUNTS_EVERY=$((10#$RAVEN_RELAY_COUNTS_EVERY))
  case "$RAVEN_RELAY_LAB" in
    0|1) ;;
    *) relay_die "RAVEN_RELAY_LAB must be 1 (a debug lab build, not for real use) or 0" "$RELAY_EXIT_SETTINGS" ;;
  esac
  case "$RAVEN_RELAY_HARDENING" in
    full|basic) ;;
    *) relay_die "RAVEN_RELAY_HARDENING must be full or basic (Linux: basic drops the system-call filter)" "$RELAY_EXIT_SETTINGS" ;;
  esac
  case "$RAVEN_RELAY_SYSTEM" in
    0|1) ;;
    *) relay_die "RAVEN_RELAY_SYSTEM must be 1 (macOS: run at boot as a LaunchDaemon) or 0" "$RELAY_EXIT_SETTINGS" ;;
  esac
  return 0
}

# An absolute folder the kit may write into a plist, a unit or kit.conf.
relay_check_dir() {
  local name=$1 dir=$2
  case "$dir" in
    /*) ;;
    *) relay_die "$name must be an absolute path" "$RELAY_EXIT_SETTINGS" ;;
  esac
  if [[ ! "$dir" =~ $RELAY_VALUE_RE ]]; then
    relay_die "$name may hold only letters, digits, spaces and . _ / -" "$RELAY_EXIT_SETTINGS"
  fi
  case "$dir" in
    *'['*|*']'*|*:*|*@*) relay_die "$name may hold only letters, digits, spaces and . _ / -" "$RELAY_EXIT_SETTINGS" ;;
  esac
  return 0
}

# The ports the relay listens on with TCP (the first is also QUIC).
relay_tcp_ports() {
  printf '%s' "$RAVEN_RELAY_PORT"
  case "$RAVEN_RELAY_TCP443" in
    direct) printf ' 443' ;;
    7443) printf ' 7443' ;;
  esac
  return 0
}

# Fill RELAY_ARGS: the `raven-node relay` flags after --data-dir. Never the
# flag that serves anyone (a test and a CI tripwire check this file for it).
# shellcheck disable=SC2034  # RELAY_ARGS is used by the installers
relay_args() {
  RELAY_ARGS=(--listen "$RAVEN_RELAY_PORT")
  case "$RAVEN_RELAY_TCP443" in
    direct) RELAY_ARGS+=(--also-tcp 443) ;;
    7443) RELAY_ARGS+=(--also-tcp 7443:443) ;;
  esac
  if [[ -n "$RAVEN_RELAY_HOST" ]]; then
    RELAY_ARGS+=(--public-host "$RAVEN_RELAY_HOST")
  fi
  if [[ "$RAVEN_RELAY_AUTONAT" == 1 ]]; then
    RELAY_ARGS+=(--autonat-server)
  fi
  RELAY_ARGS+=(--counts-every "$RAVEN_RELAY_COUNTS_EVERY")
  return 0
}

# Find the binaries to install: RELAY_NODE_BIN (raven-node) and RELAY_CLI_BIN
# (raven, or ash: the same program). In order:
#   1. RAVEN_RELAY_PREBUILT=<dir> holding them (a release layout's bin/, a
#      cross build, CI's target/debug);
#   2. a release layout: this script's ../bin, when no ../../Cargo.toml exists;
#   3. cargo build --locked (release; debug with RAVEN_RELAY_LAB=1), run as
#      whoever runs the installer (it never re-runs itself under sudo).
# Then the binary must know the kit's flags.
# shellcheck disable=SC2034  # RELAY_NODE_BIN / RELAY_CLI_BIN are used by the installers
relay_binaries() {
  local src="" profile=release target help
  if [[ -n "${RAVEN_RELAY_PREBUILT:-}" ]]; then
    src=$RAVEN_RELAY_PREBUILT
    [[ -d "$src" ]] || relay_die "RAVEN_RELAY_PREBUILT=$src is not a folder" "$RELAY_EXIT_SETTINGS"
  elif [[ ! -f "$RELAY_KIT_DIR/../../Cargo.toml" && -x "$RELAY_KIT_DIR/../bin/raven-node" ]]; then
    src="$RELAY_KIT_DIR/../bin"
  else
    command -v cargo >/dev/null 2>&1 \
      || relay_die "cargo not found: install Rust (rustup, toolchain 1.98.0) or set RAVEN_RELAY_PREBUILT=<folder with raven-node and raven>"
    if [[ "$RAVEN_RELAY_LAB" == 1 ]]; then
      profile=debug
      cargo build --locked -p raven-node -p ash --manifest-path "$RELAY_KIT_DIR/../../Cargo.toml"
    else
      cargo build --locked -p raven-node -p ash --release --manifest-path "$RELAY_KIT_DIR/../../Cargo.toml"
    fi
    target=${CARGO_TARGET_DIR:-$RELAY_KIT_DIR/../../target}
    src="$target/$profile"
  fi
  src="$(CDPATH='' cd -- "$src" && pwd)"
  RELAY_NODE_BIN="$src/raven-node"
  RELAY_CLI_BIN="$src/raven"
  [[ -x "$RELAY_CLI_BIN" ]] || RELAY_CLI_BIN="$src/ash"
  [[ -x "$RELAY_NODE_BIN" ]] || relay_die "no raven-node in $src"
  [[ -x "$RELAY_CLI_BIN" ]] || relay_die "no raven (or ash) in $src"
  # Captured, not piped into grep -q: an early grep exit would fail the pipe.
  help="$("$RELAY_NODE_BIN" relay --help 2>&1 || true)"
  case "$help" in
    *--also-tcp*--public-host*--check*) ;;
    *) relay_die "this raven-node is too old for the kit (no --also-tcp / --public-host / --check): update it (git pull) or point RAVEN_RELAY_PREBUILT at a newer build" ;;
  esac
  return 0
}

# What `raven-node relay --check` said, for a person (its own lines came first).
relay_check_failed() {
  local rc=$1
  case "$rc" in
    3) echo "relay kit: this build holds p2p (P2P_PRODUCTION_ENABLED=false): the kit installs only a build with p2p on, or a lab build (RAVEN_RELAY_LAB=1, a debug build; not for real use)" >&2 ;;
    4)
      echo "relay kit: a listen port is busy or needs a privilege (lines above). A busy port (another program holds it, e.g. a web server on 443 or Raven itself on 7423): pick another port (RAVEN_RELAY_PORT=7428; 7424/7425 are a second Raven profile's, 7427 the friend relay's) or set RAVEN_RELAY_TCP443=off" >&2
      echo "relay kit: RAVEN_RELAY_TCP443=7443 fits only when the public TCP 443 is free for the relay and a router or a second IP maps it to 7443 here (or 443 needs a privilege here). Never redirect the 443 a web server serves: that takes the website down (docs/RELAY_KIT.md section 4)" >&2
      ;;
    5) echo "relay kit: the relay folder cannot be used (line above): it holds a Raven profile, or a relay already runs in it (stop that one first); or the --wss certificate or key cannot be used" >&2 ;;
    *) echo "relay kit: raven-node relay --check failed (exit $rc)" >&2 ;;
  esac
  return 0
}

# The relay's PeerId in a relay_status.json (its pretty-printed form): a sed
# script, for `sed -n "$RELAY_PEER_SED" FILE` (as root on Linux).
RELAY_PEER_SED='s/^  "peer_id": "\(12D3KooW[1-9A-HJ-NP-Za-km-z]*\)",$/\1/p'
# The process that wrote it.
# shellcheck disable=SC2034  # used by the installers
RELAY_PID_SED='s/^  "pid": \([0-9][0-9]*\),*$/\1/p'

# relay_peer_of FILE: that PeerId, or nothing (no file, no relay yet).
relay_peer_of() {
  sed -n "$RELAY_PEER_SED" "$1" 2>/dev/null || true
}

# kit.conf: the settings of this run, for the next one and the wrapper.
relay_kitconf_text() {
  local k
  echo "# Raven relay kit settings (docs/RELAY_KIT.md), written by the installer."
  echo "# Plain KEY=VALUE lines, parsed and never sourced. Re-running the installer"
  echo "# reuses them; an environment variable of the same name overrides a line."
  for k in $RELAY_KNOWN_KEYS; do
    if [[ -n "${!k+x}" ]]; then
      printf '%s=%s\n' "$k" "${!k}"
    fi
  done
}

# relay_print_firewall linux|macos: the rules to add yourself (never applied).
relay_print_firewall() {
  local os=$1 port=$RAVEN_RELAY_PORT p
  echo "Firewall (not changed by the kit; add the rules yourself):"
  if [[ "$os" == linux ]]; then
    printf '  ufw:       sudo ufw allow %s/tcp && sudo ufw allow %s/udp' "$port" "$port"
    for p in $(relay_tcp_ports); do
      [[ "$p" == "$port" ]] || printf ' && sudo ufw allow %s/tcp' "$p"
    done
    echo
    printf '  firewalld: sudo firewall-cmd --permanent --add-port=%s/tcp --add-port=%s/udp' "$port" "$port"
    for p in $(relay_tcp_ports); do
      [[ "$p" == "$port" ]] || printf ' --add-port=%s/tcp' "$p"
    done
    echo " && sudo firewall-cmd --reload"
    echo "  nftables:  allow inbound tcp dport { $(relay_tcp_ports | tr ' ' ',') } and udp dport $port"
    if [[ "$RAVEN_RELAY_TCP443" == 7443 ]]; then
      echo "  A VPS: in the provider's firewall / security group open TCP+UDP $port and TCP 443 (the public port, mapped to 7443 on the box), not 7443."
    else
      echo "  A VPS: open the same ports in the provider's firewall / security group too."
    fi
  else
    echo "  The macOS Application Firewall is off by default. If it is on, allow the relay:"
    echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add $RAVEN_RELAY_BIN_DIR/raven-node"
    echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp $RAVEN_RELAY_BIN_DIR/raven-node"
    echo "  (a rebuild may need this again)."
  fi
  local extra=""
  if [[ "$RAVEN_RELAY_TCP443" == direct ]]; then
    extra=", and TCP 443"
  elif [[ "$RAVEN_RELAY_TCP443" == 7443 ]]; then
    extra=", and TCP 443 to its port 7443"
  fi
  echo "Router (when this box is behind one): forward TCP+UDP ${port} to it${extra}."
  echo "  A router WAN address in 100.64.0.0/10 or a private range is carrier NAT: no forward can work there; use a VPS."
}

# The commands to give out next (WRAPPER is how the operator runs raven-relay).
relay_print_next_steps() {
  local wrapper=$1 installer=$2
  echo "Next:"
  echo "  1. ${wrapper} card                      the via= lines, and the 'raven relay use ...' line for each friend"
  echo "  2. ${wrapper} allow <PeerId>            for EVERY friend who sends or is reached through the relay"
  echo "     (each friend reads theirs from 'raven whoami --peer-id'; take it from them directly; deny removes one)"
  echo "  3. ${wrapper} status                    allow-list (friends' PeerIds, your labels), the relay's addresses, state, counts"
  echo "     (remove PeerIds, labels and public IPs before you share its output; the logs carry counts only)"
  echo "Privacy: the relay passes encrypted bytes only and holds no Raven identity. It learns both PeerIds and"
  echo "  IPs of every circuit, its timing and byte counts; never a message, never a Raven ID."
  echo "Update:    git pull --ff-only && ${installer}   (settings remembered in kit.conf; the PeerId is kept)"
  echo "Rollback:  RAVEN_RELAY_ROLLBACK=1 ${installer}"
  echo "Uninstall: RAVEN_RELAY_UNINSTALL=1 ${installer}   (keeps the key; RAVEN_RELAY_PURGE=1 also deletes it)"
  if [[ "$RAVEN_RELAY_LAB" == 1 ]]; then
    echo "LAB BUILD: a debug build with the lab unlock (RAVEN_LAB_TEST_A=1). Not for real use."
  fi
}

# Verbatim copies of linux_systemd_user.sh's sd_quote and macos_launchd.sh's
# xml_escape; scripts/check_install_helpers.sh fails when they drift.
# systemd.service(5): a word may be double-quoted (so spaces survive), and `%`
# and `$` are special inside it (specifiers / variable expansion).
sd_quote() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//%/%%}
  s=${s//\$/\$\$}
  printf '"%s"' "$s"
}
# Paths are written into XML: escape the three characters that are special there.
xml_escape() {
  local s=$1
  # Quoted patterns and replacements: bash >= 5.2 (patsub_replacement, on by
  # default) reads an unquoted `&` in the replacement as "the matched text",
  # which turned `<` into `<lt;`. Quoted, `&` is literal in every bash.
  s=${s//'&'/'&amp;'}
  s=${s//'<'/'&lt;'}
  s=${s//'>'/'&gt;'}
  printf '%s' "$s"
}
