#!/usr/bin/env bash
# Install user-scoped raven-node systemd unit (Linux). Never touches /bin/ash.
#
# LAN exposure follows the build, identically on every OS installer: the unit
# gets the address `raven-node lan-default` prints, which is `auto` (every
# network of this host, local sources and contacts only) once the build's B12
# gate (LAN_AUTO_LISTEN_PRODUCTION_ENABLED, the Phase 3 LAN amendment) is open,
# and 127.0.0.1:7420 (this host only) until then. A profile that picked a LAN
# port of its own (Phase 6b, a random port for new profiles) gets that port
# instead (auto:PORT, 127.0.0.1:PORT): the installer creates the profile first
# (`raven init`) and asks `raven-node lan-default --data-dir`. RAVEN_LAN_LISTEN
# overrides it:
#   RAVEN_LAN_LISTEN=192.168.1.20:7420 bash node/scripts/install/linux_systemd_user.sh
# (auto, auto:PORT, IP:PORT or [IPv6]:PORT); `raven lan off` closes LAN later.
# For `auto` the installer prints ufw / firewalld lines for its TCP port and
# the nearby search's UDP 7420 on local networks only; it never changes the
# firewall itself.
#
# RAVEN_INSTALL_RENDER_ONLY=1 builds, writes and starts nothing: it asks the
# raven-node already in RAVEN_BIN_DIR for the LAN default, prints LAN_LISTEN=
# and the unit (stdout) and the LAN lines of the install (stderr), and exits
# (node/scripts/install/lan_default_selftest.sh).
#
# The local Bluetooth stand-in (mock BLE) listens on 127.0.0.1:7421 unless
# RAVEN_BLE_LISTEN is set (127.0.0.1:0 = any free port), e.g. for a second
# profile or a test node beside another Raven on this computer:
#   RAVEN_BLE_LISTEN=127.0.0.1:0 bash node/scripts/install/linux_systemd_user.sh
#
# Internet direct exposure is opt-in the same way (no listener by default):
#   RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash node/scripts/install/linux_systemd_user.sh
# (a bare IP gets port 7422). Without it, `raven node internet on --listen
# 0.0.0.0:7422` turns it on later (applied when the service restarts). Opening
# the port in a firewall stays your decision; the installer only prints the rule.
#
# libp2p (relay + hole punching, TCP and UDP 7423) is opt-in the same way:
#   RAVEN_P2P_LISTEN=7423 bash node/scripts/install/linux_systemd_user.sh
# (a port = every interface, IPv4 + IPv6; IP:PORT = that address only; off =
# off even if `raven node p2p on` saved it). RAVEN_P2P_RELAYS=<multiaddr>[,<multiaddr>]
# (at most 2, each ending in /p2p/<relay PeerId>) keeps a reservation on those
# relays; RAVEN_P2P_RELAY=1 relays for your verified contacts (and the PeerIds
# in relay_allow.json) with this profile's own relay key, never your PeerId:
# the friend relay on TCP and UDP 7427, the consent `raven relay offer on`
# saves;
# RAVEN_UPNP=1|0 saves the router port-mapping choice (`raven node upnp on|off`).
# With RAVEN_UPNP unset, an interactive install that turns p2p listen on asks
# once (Enter = no); a non-interactive one never asks and leaves it unset (off).
#
# Lifetime: a `systemd --user` manager is torn down when the user's last
# session ends, so on a headless / SSH-managed host (Raspberry Pi bridge node)
# the daemon would stop at logout and not start at boot. Lingering fixes that
# but is a host-wide setting, so it is opt-in:
#   RAVEN_ENABLE_LINGER=1 bash node/scripts/install/linux_systemd_user.sh
# (or run `loginctl enable-linger "$USER"` yourself; it may need admin rights).
#
# Keystore (docs/design/2026-10-linux-keystore.md): with an unlocked desktop
# keyring (Secret Service) the keys go there. Otherwise RAVEN keeps them in a
# passphrase vault, and the background service needs the passphrase from a
# file only you can read (mode 0600/0400). Pass its path at install time:
#   RAVEN_KEYSTORE_PASSPHRASE_FILE=$HOME/.config/raven/keystore-passphrase \
#     bash node/scripts/install/linux_systemd_user.sh
# The unit then gets Environment=RAVEN_KEYSTORE_PASSPHRASE_FILE=<path> (the
# path only, never the passphrase). RAVEN_SYSTEMD_LOAD_CREDENTIAL=1 uses
# LoadCredential=raven-keystore-passphrase:<path> instead (needs a systemd
# whose user manager supports credentials).
#
# The Tor onion carrier (switched on in release builds in 2026-10 after the
# three-machine field test; not independently reviewed): this installer builds
# with the cargo feature `tor` and installs raven-tor-helper (Arti, the Tor
# client, in its own process) next to raven-node. raven-node starts it and
# keeps an onion service, so friends can reach this host from any network
# without a port forward; Tor relays are the only third party it talks to.
# RAVEN_INSTALL_TOR_HELPER=0 builds without it and removes an installed one
# (raven status then says "Tor: not built in this raven").
#
# Bluetooth nearby (Phase 5, docs/NEARBY.md) is in release builds on macOS
# only: Linux has no release Bluetooth backend, so this installer builds none
# and nearby stays lab-only here (NEARBY_PRODUCTION_ENABLED is false on
# Linux; a debug lab build with feature nearby-radio, glibc only, has the
# BlueZ backend). For that lab build: the user unit reaches BlueZ over the
# system bus as you: desktop distributions' org.bluez D-Bus policy allows the
# logged-in user (verify on yours: `raven nearby status` says "not allowed"
# when it does not; the fix is that policy, never root). Raven goes on the air
# only from a private Bluetooth address: an admin sets `Privacy = device` under
# [General] in /etc/bluetooth/main.conf and restarts bluetooth. Without it
# nearby stays inactive on this computer: it neither advertises, scans nor
# connects (a connect shows the fixed address as an advert does), and
# `raven nearby status` says so.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="${RAVEN_BIN_DIR:-$HOME/.local/bin}"
# Same profile resolution as `raven`/`ash` and raven-core (RAVEN_DATA_DIR, then
# ASH_DATA_DIR, then a legacy ~/.raven-ash while ~/.raven does not exist, else
# ~/.raven). Resolved BEFORE anything is created: `mkdir ~/.raven` below would
# otherwise orphan an existing legacy identity (contacts pinned its key) and flip
# plain `ash` onto a brand-new, empty profile.
resolve_data_dir() {
  if [[ -n "${RAVEN_DATA_DIR:-}" ]]; then
    printf '%s' "$RAVEN_DATA_DIR"
  elif [[ -n "${ASH_DATA_DIR:-}" ]]; then
    printf '%s' "$ASH_DATA_DIR"
  elif [[ -d "$HOME/.raven-ash" && ! -e "$HOME/.raven" ]]; then
    printf '%s' "$HOME/.raven-ash"
  else
    printf '%s' "$HOME/.raven"
  fi
}
DATA_DIR="$(resolve_data_dir)"
RENDER_ONLY="${RAVEN_INSTALL_RENDER_ONLY:-0}"
case "$RENDER_ONLY" in
  0|1) ;;
  *) echo "RAVEN_INSTALL_RENDER_ONLY must be 1 (print the unit, install nothing) or 0" >&2; exit 1 ;;
esac
TOR_HELPER="${RAVEN_INSTALL_TOR_HELPER:-1}"
case "$TOR_HELPER" in
  0|1) ;;
  *) echo "RAVEN_INSTALL_TOR_HELPER must be 1 (install raven-tor-helper, the Tor onion carrier's helper) or 0" >&2; exit 1 ;;
esac
# auto / auto:PORT / IP:PORT / [IPv6]:PORT / [IPv6%zone]:PORT characters only;
# raven-node validates the rest. The address itself is resolved after the
# binaries are installed (lan_default below); RAVEN_LAN_LISTEN is checked now,
# so a typo stops the install before the build.
lan_listen_ok() {
  [[ "$1" =~ ^(auto(:[0-9]{1,5})?|[][0-9A-Za-z.:%]+)$ ]]
}
LAN_LISTEN_HELP="RAVEN_LAN_LISTEN must look like auto, 192.168.1.20:7420 or [::]:7420"
if [[ -n "${RAVEN_LAN_LISTEN:-}" ]] && ! lan_listen_ok "$RAVEN_LAN_LISTEN"; then
  echo "$LAN_LISTEN_HELP" >&2
  exit 1
fi
BLE_LISTEN="${RAVEN_BLE_LISTEN:-127.0.0.1:7421}"
# IP:PORT / [IPv6]:PORT characters only; raven-node validates the rest.
if [[ ! "$BLE_LISTEN" =~ ^[][0-9A-Za-z.:]+$ ]]; then
  echo "RAVEN_BLE_LISTEN must look like 127.0.0.1:7421 or 127.0.0.1:0" >&2
  exit 1
fi
INTERNET_LISTEN="${RAVEN_INTERNET_LISTEN:-}"
# IP[:port] / [IPv6][:port] characters only; raven-node validates the rest.
if [[ -n "$INTERNET_LISTEN" && ! "$INTERNET_LISTEN" =~ ^[][0-9A-Za-z.:]+$ ]]; then
  echo "RAVEN_INTERNET_LISTEN must look like 0.0.0.0:7422 or [::]:7422" >&2
  exit 1
fi
# libp2p settings: empty = no flag (node_policy.json decides, as today).
P2P_LISTEN="${RAVEN_P2P_LISTEN:-}"
P2P_RELAYS="${RAVEN_P2P_RELAYS:-}"
P2P_RELAY="${RAVEN_P2P_RELAY:-}"
UPNP="${RAVEN_UPNP:-}"
# PORT / IP:PORT / [IPv6]:PORT / on / off characters only; raven-node validates the rest.
if [[ -n "$P2P_LISTEN" && ! "$P2P_LISTEN" =~ ^[][0-9A-Za-z.:]+$ ]]; then
  echo "RAVEN_P2P_LISTEN must look like 7423, 0.0.0.0:7423, [::]:7423 or off" >&2
  exit 1
fi
# Comma separated relay multiaddrs (spaces around commas are ignored).
P2P_RELAY_LIST=()
P2P_RELAYS_REST="${P2P_RELAYS},"
while [[ -n "$P2P_RELAYS" && -n "$P2P_RELAYS_REST" ]]; do
  P2P_RELAY_ENTRY="${P2P_RELAYS_REST%%,*}"
  P2P_RELAYS_REST="${P2P_RELAYS_REST#*,}"
  P2P_RELAY_ENTRY="${P2P_RELAY_ENTRY#"${P2P_RELAY_ENTRY%%[![:space:]]*}"}"
  P2P_RELAY_ENTRY="${P2P_RELAY_ENTRY%"${P2P_RELAY_ENTRY##*[![:space:]]}"}"
  [[ -n "$P2P_RELAY_ENTRY" ]] || continue
  if [[ ! "$P2P_RELAY_ENTRY" =~ ^/[0-9A-Za-z./:_-]+$ || "$P2P_RELAY_ENTRY" != */p2p/?* ]]; then
    echo "RAVEN_P2P_RELAYS entries must look like /ip4/203.0.113.7/tcp/7423/p2p/<relay PeerId>" >&2
    exit 1
  fi
  P2P_RELAY_LIST+=("$P2P_RELAY_ENTRY")
done
if [[ ${#P2P_RELAY_LIST[@]} -gt 2 ]]; then
  echo "RAVEN_P2P_RELAYS takes at most 2 relays" >&2
  exit 1
fi
case "$P2P_RELAY" in
  ""|0|1) ;;
  *) echo "RAVEN_P2P_RELAY must be 1 (relay for your verified contacts with this profile's own relay key, port 7427) or 0" >&2; exit 1 ;;
esac
case "$UPNP" in
  ""|0|1) ;;
  *) echo "RAVEN_UPNP must be 1 (map the p2p port on the router) or 0" >&2; exit 1 ;;
esac
PASSPHRASE_FILE="${RAVEN_KEYSTORE_PASSPHRASE_FILE:-}"
if [[ -n "${RAVEN_KEYSTORE_PASSPHRASE:-}" ]]; then
  echo "RAVEN_KEYSTORE_PASSPHRASE is refused: put the passphrase in a 0600 file and set RAVEN_KEYSTORE_PASSPHRASE_FILE" >&2
  exit 1
fi
if [[ -n "$PASSPHRASE_FILE" ]]; then
  case "$PASSPHRASE_FILE" in
    /*) ;;
    *) echo "RAVEN_KEYSTORE_PASSPHRASE_FILE must be an absolute path" >&2; exit 1 ;;
  esac
  if [[ "$PASSPHRASE_FILE" == *[\$%\"\\]* || "$PASSPHRASE_FILE" == *$'\n'* ]]; then
    echo "RAVEN_KEYSTORE_PASSPHRASE_FILE must not contain \$ % \" \\ or newlines" >&2
    exit 1
  fi
  if [[ ! -f "$PASSPHRASE_FILE" || -L "$PASSPHRASE_FILE" ]]; then
    echo "RAVEN_KEYSTORE_PASSPHRASE_FILE=$PASSPHRASE_FILE is not a regular file" >&2
    exit 1
  fi
  case "$(stat -c '%a' "$PASSPHRASE_FILE")" in
    600|400) ;;
    *) echo "RAVEN_KEYSTORE_PASSPHRASE_FILE must be mode 0600 or 0400 (chmod 600 $PASSPHRASE_FILE)" >&2; exit 1 ;;
  esac
fi
# True when this install turns the libp2p listener on (set and not "off").
p2p_listen_requested() {
  [[ -n "$P2P_LISTEN" ]] || return 1
  case "$P2P_LISTEN" in
    [Oo][Ff][Ff]) return 1 ;;
  esac
  return 0
}
# "relay" (no listening port) is retired: a node without a listener can never
# hole-punch, so it becomes 7423 (every interface), like `raven node p2p on
# --listen relay`; the firewall hint and the UPnP question then follow for it.
case "$P2P_LISTEN" in
  [Rr][Ee][Ll][Aa][Yy])
    P2P_LISTEN=7423
    echo "note: RAVEN_P2P_LISTEN=relay is retired: it opened no port, so hole punching could never work. Using 7423 (TCP and UDP, every interface) instead." >&2
    ;;
esac
# The libp2p port of RAVEN_P2P_LISTEN: "[v6]:port", "v4:port", a bare port or
# "on" (the default port); empty when off.
P2P_PORT=""
if p2p_listen_requested; then
  case "$P2P_LISTEN" in
    \[*\]:*) P2P_PORT="${P2P_LISTEN##*:}" ;;
    *:*:*) P2P_PORT=7423 ;;
    *:*) P2P_PORT="${P2P_LISTEN##*:}" ;;
    *[!0-9]*) P2P_PORT=7423 ;;
    *) P2P_PORT="$P2P_LISTEN" ;;
  esac
fi
# UPnP (owner decision Q8, "ask once at setup"): RAVEN_UPNP decides.
# Unset: an interactive install (stdin is a terminal) that opens a p2p port
# asks the same one-time question as `raven node p2p on`, unless node_policy.json
# already holds an answer ("upnp": true|false). Enter or EOF = no. Asked before
# the build so nobody waits for cargo to answer it; saved after install below.
UPNP_MODE=""
case "$UPNP" in
  1) UPNP_MODE=on ;;
  0) UPNP_MODE=off ;;
  *)
    if [[ -n "$P2P_PORT" && -t 0 && "$RENDER_ONLY" != 1 ]] \
      && ! grep -Eq '"upnp"[[:space:]]*:[[:space:]]*(true|false)' "$DATA_DIR/node_policy.json" 2>/dev/null; then
      printf '%s ' "Open TCP/UDP ${P2P_PORT} on your router automatically (UPnP) so friends can reach this node? [y/N]" >&2
      UPNP_ANSWER=""
      read -r UPNP_ANSWER || UPNP_ANSWER=""
      case "$UPNP_ANSWER" in
        [Yy]|[Yy][Ee][Ss]) UPNP_MODE=on ;;
        *) UPNP_MODE=off ;;
      esac
    fi
    ;;
esac
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/raven-node.service"

if [[ "$RENDER_ONLY" == 1 ]]; then
  # Render-only creates nothing: the folders are shown as given, made absolute.
  [[ "$BIN_DIR" == /* ]] || BIN_DIR="$PWD/$BIN_DIR"
  [[ "$DATA_DIR" == /* ]] || DATA_DIR="$PWD/$DATA_DIR"
else
  mkdir -p "$BIN_DIR" "$UNIT_DIR"
  # Identity, sessions and chat history live here: owner-only.
  mkdir -p "$DATA_DIR"
  chmod 700 "$DATA_DIR"
  # `systemd --user` starts the unit from the user's home: register absolute paths
  # only. A relative RAVEN_DATA_DIR / RAVEN_BIN_DIR would make the daemon serve (or
  # exec from) a different directory than the one `raven init` just created.
  BIN_DIR="$(CDPATH='' cd -- "$BIN_DIR" && pwd)"
  DATA_DIR="$(CDPATH='' cd -- "$DATA_DIR" && pwd)"
fi
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
# Internet direct listener: only when asked for (empty = no flag, so a later
# `raven node internet on` in node_policy.json decides).
internet_listen_args() {
  [[ -n "$INTERNET_LISTEN" ]] || return 0
  printf ' --internet-listen %s' "$(sd_quote "$INTERNET_LISTEN")"
}
# libp2p flags: only the ones asked for (none = the unit stays as before).
p2p_args() {
  local r
  if [[ -n "$P2P_LISTEN" ]]; then
    printf ' --p2p-listen %s' "$(sd_quote "$P2P_LISTEN")"
  fi
  if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]]; then
    for r in "${P2P_RELAY_LIST[@]}"; do
      printf ' --p2p-relay %s' "$(sd_quote "$r")"
    done
  fi
  if [[ "$P2P_RELAY" == "1" ]]; then
    printf ' --relay'
  fi
  return 0
}
# Passphrase vault: hand the service the passphrase *file* (never its contents).
keystore_unit_lines() {
  [[ -n "$PASSPHRASE_FILE" ]] || return 0
  if [[ "${RAVEN_SYSTEMD_LOAD_CREDENTIAL:-0}" == "1" ]]; then
    printf 'LoadCredential=raven-keystore-passphrase:%s\n' "$PASSPHRASE_FILE"
  else
    printf 'Environment=%s\n' "$(sd_quote "RAVEN_KEYSTORE_PASSPHRASE_FILE=${PASSPHRASE_FILE}")"
  fi
}
# Render-only builds and copies nothing: it asks the raven-node already in BIN_DIR.
if [[ "$RENDER_ONLY" != 1 ]]; then
  # --locked: build exactly the audited Cargo.lock. `tor` adds the
  # raven-tor-helper binary (raven-node itself never links Arti).
  build_features=()
  if [[ "$TOR_HELPER" == 1 ]]; then
    build_features=(--features raven-node/tor)
  fi
  cargo build --locked -p raven-node -p ash --release --manifest-path "$ROOT/Cargo.toml" \
    ${build_features[@]+"${build_features[@]}"}
  TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
  install -m 755 "$TARGET/release/raven-node" "$BIN_DIR/raven-node"
  install -m 755 "$TARGET/release/ash" "$BIN_DIR/raven"
  # The Tor helper sits next to raven-node, where raven-node looks for it.
  if [[ "$TOR_HELPER" == 1 ]]; then
    install -m 755 "$TARGET/release/raven-tor-helper" "$BIN_DIR/raven-tor-helper"
  elif [[ -e "$BIN_DIR/raven-tor-helper" ]]; then
    rm -f "$BIN_DIR/raven-tor-helper"
    echo "removed ${BIN_DIR}/raven-tor-helper (RAVEN_INSTALL_TOR_HELPER=0)"
  fi
  # `ash` is also the BusyBox / Alpine shell, and ~/.local/bin usually precedes
  # /bin in PATH: only add the alias when no other `ash` exists.
  EXISTING_ASH="$(PATH="${PATH//$BIN_DIR:/}" command -v ash 2>/dev/null || true)"
  if [[ -z "$EXISTING_ASH" && ! -e /bin/ash && ! -e /usr/bin/ash ]] \
    || [[ "$(readlink -f "$BIN_DIR/ash" 2>/dev/null || true)" == "$(readlink -f "$BIN_DIR/raven")" ]]; then
    ln -sfn "$BIN_DIR/raven" "$BIN_DIR/ash"
    echo "linked $BIN_DIR/ash -> raven (user-local only)"
  else
    echo "NOTE: a system 'ash' shell exists (${EXISTING_ASH:-/bin/ash}) — not shadowing it; use '$BIN_DIR/raven'"
  fi
fi

# Identity + prekey must exist before LAN preflight will keep the service up,
# and before the LAN default below: a new profile picks its LAN port here
# (Phase 6b, while that gate is live). On a host without a desktop keyring
# this creates the passphrase vault: from RAVEN_KEYSTORE_PASSPHRASE_FILE when
# set, else by asking twice on this terminal. Render-only creates nothing.
if [[ "$RENDER_ONLY" != 1 ]]; then
  "${BIN_DIR}/raven" --data-dir "${DATA_DIR}" init
fi

# The LAN address follows the build (hold B12): the installed raven-node
# prints `auto` once LAN_AUTO_LISTEN_PRODUCTION_ENABLED is on, else
# 127.0.0.1:7420, each on the port this profile picked where it picked one
# (`lan-default --data-dir`, Phase 6b). One without `--data-dir` (an older
# build) is asked again without it; one that fails or prints anything else
# (an older build without `lan-default`) keeps 127.0.0.1:7420.
# RAVEN_LAN_LISTEN wins.
lan_default() {
  local out
  out="$("${BIN_DIR}/raven-node" lan-default --data-dir "${DATA_DIR}" 2>/dev/null)" \
    || out="$("${BIN_DIR}/raven-node" lan-default 2>/dev/null)" || out=""
  if [[ -n "$out" ]] && lan_listen_ok "$out"; then
    printf '%s' "$out"
  else
    printf '127.0.0.1:7420'
  fi
}
# `auto` or `auto:PORT`, in any case (raven-node reads it so).
is_auto() {
  case "$1" in
    [Aa][Uu][Tt][Oo]|[Aa][Uu][Tt][Oo]:*) return 0 ;;
  esac
  return 1
}
LAN_DEFAULT="$(lan_default)"
LAN_LISTEN="${RAVEN_LAN_LISTEN:-$LAN_DEFAULT}"
lan_listen_ok "$LAN_LISTEN" || { echo "$LAN_LISTEN_HELP" >&2; exit 1; }
# The TCP port of the address (auto:PORT, IP:PORT, [IPv6]:PORT; 7420 for a
# bare `auto` and for port 0), for the lines printed below.
LAN_PORT=7420
if [[ "$LAN_LISTEN" == *:* && "${LAN_LISTEN##*:}" =~ ^[1-9][0-9]{0,4}$ ]]; then
  LAN_PORT="${LAN_LISTEN##*:}"
fi
# The build's auto:PORT goes into the service as a plain `auto`: raven-node
# then listens on the port this profile picked at every start, so `raven lan
# port random` moves the installed service too (Phase 6 review traffic-5).
# A RAVEN_LAN_LISTEN that names a port keeps it.
if [[ -z "${RAVEN_LAN_LISTEN:-}" ]] && is_auto "$LAN_LISTEN"; then
  LAN_LISTEN=auto
fi
# The nearby search (LAN beacon) always uses UDP 7420 (raven-core
# lan_beacon BEACON_PORT), whatever the TCP port of auto:PORT.
BEACON_UDP_PORT=7420

render_unit() {
  cat <<EOF
[Unit]
Description=RAVEN raven-node service (bridge + IPC)
After=network.target

[Service]
Type=simple
ExecStart=$(sd_quote "${BIN_DIR}/raven-node") service --data-dir $(sd_quote "${DATA_DIR}") --lan-listen $(sd_quote "${LAN_LISTEN}") --ble-listen $(sd_quote "${BLE_LISTEN}")$(internet_listen_args)$(p2p_args) --timeout-secs 0
Restart=on-failure
RestartSec=3
# Sandboxing that works in a --user manager without a mount namespace (the
# Protect*/ReadWritePaths/PrivateTmp family needs unprivileged user namespaces
# and fails the unit with status=226/NAMESPACE where those are disabled, so it
# is deliberately not set). AF_NETLINK stays allowed: interface enumeration
# (getifaddrs) uses it.
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
$(keystore_unit_lines)

[Install]
WantedBy=default.target
EOF
}
# What the install says about LAN (render-only prints it too, on stderr). The
# firewall lines are printed, never run.
lan_lines() {
  local net
  echo "LAN listen: ${LAN_LISTEN}"
  case "$LAN_LISTEN" in
    [Aa][Uu][Tt][Oo]|[Aa][Uu][Tt][Oo]:*)
      if is_auto "$LAN_DEFAULT"; then
        echo "LAN: every network of this host, contacts only (TCP ${LAN_PORT}; nearby search on UDP ${BEACON_UDP_PORT})"
        echo "  Contacts on a VPN (100.64.0.0/10, e.g. Tailscale) or at a public address are refused;"
        echo "  for them re-run with RAVEN_LAN_LISTEN=0.0.0.0:${LAN_PORT}."
      else
        echo "LAN: this build holds auto (LAN_AUTO_LISTEN_PRODUCTION_ENABLED=false), so it listens on 0.0.0.0:${LAN_PORT} from any source (contacts only)"
      fi
      echo "  Allow it yourself from your local networks only (the installer never changes the firewall), e.g. ufw:"
      # The networks auto admits: private IPv4, link-local (a cable between
      # two laptops), IPv6 link-local and unique local.
      for net in 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 169.254.0.0/16 fe80::/10 fc00::/7; do
        echo "    ufw allow from ${net} to any port ${LAN_PORT} proto tcp"
        echo "    ufw allow from ${net} to any port ${BEACON_UDP_PORT} proto udp"
      done
      echo "  or firewalld, in the zone of your network's interface (firewall-cmd --get-active-zones shows it):"
      echo "    firewall-cmd --zone=<that zone> --add-port=${LAN_PORT}/tcp --add-port=${BEACON_UDP_PORT}/udp (again with --permanent to keep it)"
      echo "  On a network you do not trust (cafe, hotel): raven lan off"
      ;;
    127.*|localhost:*|\[::1\]:*)
      echo "LAN peers cannot reach this node (loopback only). To accept LAN peers, re-run with"
      echo "  RAVEN_LAN_LISTEN=<this-host-LAN-IP>:${LAN_PORT} and allow inbound TCP ${LAN_PORT} (e.g. ufw allow ${LAN_PORT}/tcp)."
      if is_auto "$LAN_DEFAULT"; then
        echo "  (re-run with RAVEN_LAN_LISTEN=auto, which your build allows)"
      fi
      ;;
    *)
      echo "Exposed on ${LAN_LISTEN}: allow inbound TCP only from your LAN (e.g. ufw allow from 192.168.0.0/16 to any port ${LAN_PORT} proto tcp)." ;;
  esac
}
if [[ "$RENDER_ONLY" == 1 ]]; then
  echo "LAN_LISTEN=${LAN_LISTEN}"
  render_unit
  {
    echo "RAVEN_INSTALL_RENDER_ONLY=1: nothing was built, written or started (${UNIT} is unchanged)"
    lan_lines
  } >&2
  exit 0
fi
render_unit >"$UNIT"

systemctl --user daemon-reload
# The profile was created above, before the LAN default.
if [[ "$(cat "${DATA_DIR}/keystore.backend" 2>/dev/null || true)" == "passphrase-vault" && -z "$PASSPHRASE_FILE" ]]; then
  echo "NOTE: this profile's keys are in a passphrase vault, but the service was given no passphrase file."
  echo "  The service will fail to start until you re-run this installer with"
  echo "  RAVEN_KEYSTORE_PASSPHRASE_FILE=<file holding the passphrase, chmod 600> (see docs/INSTALL_Linux.md)."
fi
# The same p2p settings go into node_policy.json too, so `raven whoami --card`
# and `raven status` agree with the unit even while it is not running (its
# flags above still decide while it runs). stdin is /dev/null: never asks.
if [[ -n "$P2P_LISTEN" ]]; then
  if p2p_listen_requested; then
    P2P_SAVE_ARGS=(node p2p on --listen "$P2P_LISTEN")
    if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]]; then
      for r in "${P2P_RELAY_LIST[@]}"; do
        P2P_SAVE_ARGS+=(--relay "$r")
      done
    fi
  else
    P2P_SAVE_ARGS=(node p2p off)
  fi
  if ! "${BIN_DIR}/raven" --data-dir "${DATA_DIR}" "${P2P_SAVE_ARGS[@]}" </dev/null >/dev/null; then
    echo "WARN: could not save the p2p settings in node_policy.json (the unit still uses its flags); run '${BIN_DIR}/raven --data-dir ${DATA_DIR} ${P2P_SAVE_ARGS[*]}'"
  fi
fi
# Saved in node_policy.json before the (re)start below, which applies it.
UPNP_SAVED=""
if [[ -n "$UPNP_MODE" ]]; then
  if "${BIN_DIR}/raven" --data-dir "${DATA_DIR}" node upnp "$UPNP_MODE"; then
    UPNP_SAVED="$UPNP_MODE"
  else
    echo "WARN: could not save the UPnP choice; run '${BIN_DIR}/raven --data-dir ${DATA_DIR} node upnp ${UPNP_MODE}' and restart the unit"
  fi
fi
# `enable --now` is a no-op for an already-active unit, which would keep the
# previous binary running after an upgrade; `restart` also starts an inactive unit.
systemctl --user enable raven-node.service
systemctl --user restart raven-node.service
echo "enabled + (re)started systemd --user raven-node.service"
LINGER_USER="${USER:-$(id -un)}"
if [[ "${RAVEN_ENABLE_LINGER:-0}" == "1" ]]; then
  loginctl enable-linger "$LINGER_USER" \
    || echo "WARN: could not enable lingering; run 'loginctl enable-linger $LINGER_USER' (may need admin)"
fi
if [[ "$(loginctl show-user "$LINGER_USER" -p Linger 2>/dev/null || true)" == "Linger=no" ]]; then
  echo "NOTE: lingering is off: this user service stops when your last session ends and does not start at boot."
  echo "  Headless host? Run 'loginctl enable-linger $LINGER_USER' (or re-run with RAVEN_ENABLE_LINGER=1)."
fi
# Where the daemon really listens: a long data dir is served at
# /tmp/raven-<uid>/raven-<hash>.sock, not at <data-dir>/raven-node.sock. Ask the
# installed binary (`doctor` prints `ipc_endpoint=`) instead of guessing.
IPC_EP="$("${BIN_DIR}/raven" --data-dir "${DATA_DIR}" doctor 2>/dev/null \
  | sed -n 's/^[[:space:]]*ipc_endpoint=//p' | head -n1 || true)"
echo "IPC sock: ${IPC_EP:-<unknown: run '${BIN_DIR}/raven --data-dir ${DATA_DIR} doctor' and look for ipc_endpoint=>}"
lan_lines
if [[ -n "$INTERNET_LISTEN" ]]; then
  # "[v6]:port" or "v4:port"; a bare IP (IPv6 included) means the default port.
  case "$INTERNET_LISTEN" in
    \[*\]:*) INTERNET_PORT="${INTERNET_LISTEN##*:}" ;;
    *:*:*) INTERNET_PORT=7422 ;;
    *:*) INTERNET_PORT="${INTERNET_LISTEN##*:}" ;;
    *) INTERNET_PORT=7422 ;;
  esac
  echo "Internet listen: ${INTERNET_LISTEN} (only your contacts get an answer; anyone can see that the port is open)"
  echo "  Allow it yourself if you want it reachable: ufw allow ${INTERNET_PORT}/tcp (or firewalld / nftables / your cloud security group),"
  echo "  and forward TCP ${INTERNET_PORT} on your router if this host is behind NAT."
  echo "  Check: raven status (internet row)."
else
  echo "Internet listen: off (opt-in: re-run with RAVEN_INTERNET_LISTEN=0.0.0.0:7422, or 'raven node internet on' and restart the unit)"
fi
if p2p_listen_requested; then
  echo "p2p listen: ${P2P_LISTEN} (libp2p TCP+UDP ${P2P_PORT}; only your contacts get a Raven link; anyone can see that the port is open)"
  echo "  Allow it yourself if you want it reachable: ufw allow ${P2P_PORT}/tcp; ufw allow ${P2P_PORT}/udp (or firewalld / nftables / your cloud security group),"
  echo "  and forward TCP+UDP ${P2P_PORT} on your router if this host is behind NAT (or RAVEN_UPNP=1); without that a relay (RAVEN_P2P_RELAYS) still lets contacts reach you."
  echo "  Check: raven status (p2p row)."
elif [[ -n "$P2P_LISTEN" ]]; then
  echo "p2p listen: off (RAVEN_P2P_LISTEN=${P2P_LISTEN} overrides 'raven node p2p on')"
else
  echo "p2p listen: off (opt-in: re-run with RAVEN_P2P_LISTEN=7423, or 'raven node p2p on' and restart the unit)"
fi
if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]]; then
  echo "p2p relays: ${P2P_RELAY_LIST[*]} (a reservation is kept on each; a relay sees both PeerIds and IPs of every circuit, never your messages)"
fi
if [[ "$P2P_RELAY" == "1" ]]; then
  echo "relay: on for your verified contacts (and the PeerIds in ${DATA_DIR}/relay_allow.json), with this profile's own"
  echo "  relay key (never your PeerId) on TCP and UDP 7427; 'raven relay offer off' stops it, 'raven relay status' shows it."
  echo "  A saved 'raven relay offer off' wins over RAVEN_P2P_RELAY=1 ('raven relay offer on' to relay again); 'raven node hide-ip on' stops it too."
  echo "  Allow it yourself if you want it reachable: ufw allow 7427/tcp; ufw allow 7427/udp (or firewalld / nftables / your cloud security group),"
  echo "  and forward TCP+UDP 7427 on your router if this host is behind NAT."
fi
if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]] && ! p2p_listen_requested; then
  echo "NOTE: relays take effect only while p2p listen is on (RAVEN_P2P_LISTEN=7423 or 'raven node p2p on')."
fi
if [[ "$P2P_RELAY" == "1" ]] && ! p2p_listen_requested; then
  echo "NOTE: contacts are offered your relay once this host is confirmed reachable (p2p listen on: RAVEN_P2P_LISTEN=7423)"
  echo "  or once you name its address: raven relay offer on --external /ip4/<public IP>/tcp/7427"
fi
case "$UPNP_SAVED" in
  on) echo "UPnP: on (raven-node asks the router to map TCP/UDP ${P2P_PORT:-of the p2p port, when one is open}; it logs only the mapped port and success or failure)" ;;
  off) echo "UPnP: off ('raven node upnp on' changes it; applied when the unit restarts)" ;;
esac
if [[ "$TOR_HELPER" == 1 ]]; then
  echo "Tor: ${BIN_DIR}/raven-tor-helper, next to raven-node. raven-node starts it and keeps an onion service, so friends"
  echo "  can reach this host from any network without a port forward; Tor relays are the only third party it talks to."
  echo "  The first start can take a few minutes. Check: raven status (Tor row)."
else
  echo "Tor: not installed (RAVEN_INSTALL_TOR_HELPER=0); raven status says \"Tor: not built in this raven\"."
fi
echo "Bluetooth nearby: not in release builds on Linux (macOS only so far)."
echo "export PATH=\"${BIN_DIR}:\$PATH\""
