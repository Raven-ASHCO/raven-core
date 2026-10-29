#!/usr/bin/env bash
# Install user-scoped raven-node launchd agent (macOS). Does NOT touch /bin/ash.
#
# LAN exposure follows the build, identically on every OS installer: the agent
# gets the address `raven-node lan-default` prints, which is `auto` (every
# network of this Mac, local sources and contacts only) once the build's B12
# gate (LAN_AUTO_LISTEN_PRODUCTION_ENABLED, the Phase 3 LAN amendment) is open,
# and 127.0.0.1:7420 (this Mac only) until then. A profile that picked a LAN
# port of its own (Phase 6b, a random port for new profiles) gets that port
# instead (auto:PORT, 127.0.0.1:PORT): the installer creates the profile first
# (`raven init`) and asks `raven-node lan-default --data-dir`. RAVEN_LAN_LISTEN
# overrides it:
#   RAVEN_LAN_LISTEN=192.168.1.20:7420 bash node/scripts/install/macos_launchd.sh
# (auto, auto:PORT, IP:PORT or [IPv6]:PORT); `raven lan off` closes LAN later.
#
# RAVEN_INSTALL_RENDER_ONLY=1 builds, writes and starts nothing: it asks the
# raven-node already in RAVEN_BIN_DIR for the LAN default, prints LAN_LISTEN=
# and the plist (stdout) and the LAN lines of the install (stderr), and exits
# (node/scripts/install/lan_default_selftest.sh).
#
# The local Bluetooth stand-in (mock BLE) listens on 127.0.0.1:7421 unless
# RAVEN_BLE_LISTEN is set (127.0.0.1:0 = any free port), e.g. for a second
# profile or a test node beside another Raven on this computer:
#   RAVEN_BLE_LISTEN=127.0.0.1:0 bash node/scripts/install/macos_launchd.sh
#
# Internet direct exposure is opt-in the same way (no listener by default):
#   RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash node/scripts/install/macos_launchd.sh
# (a bare IP gets port 7422). Without it, `raven node internet on --listen
# 0.0.0.0:7422` turns it on later (applied when the agent restarts).
#
# libp2p (relay + hole punching, TCP and UDP 7423) is opt-in the same way:
#   RAVEN_P2P_LISTEN=7423 bash node/scripts/install/macos_launchd.sh
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
# The release build carries the Tor onion carrier and Bluetooth nearby
# (switched on in 2026-10 after the three-machine field test; not
# independently reviewed). This installer builds raven-node with the cargo
# features `tor` and `nearby-radio` and installs both helpers:
# - raven-tor-helper (Arti, the Tor client, in its own process) next to
#   raven-node in RAVEN_BIN_DIR. raven-node starts it and keeps an onion
#   service so friends can reach this Mac from any network; Tor relays are
#   the only third party it talks to. RAVEN_INSTALL_TOR_HELPER=0 builds
#   without it and removes an installed one (raven status then says "Tor: not
#   built in this raven").
# - RavenNearby.app, the Bluetooth radio helper. Bluetooth stays off until
#   `raven nearby enable` (verified contacts only). The radio runs in the
#   helper app, which holds no keys; raven-node is never re-signed for it, so
#   its code signature and Keychain access stay as they are. The installer
#   builds RavenNearby.app (node/scripts/build_nearby_helper_app.sh), signs it
#   ad hoc and copies it to ~/Library/Application Support/Raven/, where
#   raven-node looks for it. RAVEN_INSTALL_NEARBY_HELPER=0 builds raven-node
#   without the radio backend and installs no helper.
# RAVEN_NEARBY_SIGN="Developer ID Application: ..." signs it with that
# identity instead (hardened runtime); RAVEN_NEARBY_APP=<built RavenNearby.app>
# copies that bundle instead of building one (RAVEN_NEARBY_SIGN=keep keeps its
# signature, e.g. a notarized one). RAVEN_INSTALL_NEARBY_ONLY=1 installs the
# helper alone: nothing else is built, no plist is written, nothing starts, and
# the raven-node in RAVEN_BIN_DIR stays as it is (installed earlier, or a lab
# build). Either way the install checks that
# raven-node's code signature is the same before and after the helper
# (node/scripts/install/nearby_helper_selftest.sh runs it as a dry run).
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
  *) echo "RAVEN_INSTALL_RENDER_ONLY must be 1 (print the plist, install nothing) or 0" >&2; exit 1 ;;
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
# Comma separated relay multiaddrs (spaces around commas are ignored). Written
# for macOS /bin/bash 3.2 too: an empty array is never expanded under set -u.
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
# The Bluetooth nearby helper (see the top): checked before anything is built
# or created, like every other setting.
NEARBY_HELPER="${RAVEN_INSTALL_NEARBY_HELPER:-1}"
TOR_HELPER="${RAVEN_INSTALL_TOR_HELPER:-1}"
NEARBY_ONLY="${RAVEN_INSTALL_NEARBY_ONLY:-0}"
NEARBY_APP="${RAVEN_NEARBY_APP:-}"
NEARBY_SIGN="${RAVEN_NEARBY_SIGN:--}"
case "$NEARBY_HELPER" in
  0|1) ;;
  *) echo "RAVEN_INSTALL_NEARBY_HELPER must be 1 (install RavenNearby.app, the Bluetooth nearby helper) or 0" >&2; exit 1 ;;
esac
case "$TOR_HELPER" in
  0|1) ;;
  *) echo "RAVEN_INSTALL_TOR_HELPER must be 1 (install raven-tor-helper, the Tor onion carrier's helper) or 0" >&2; exit 1 ;;
esac
case "$NEARBY_ONLY" in
  0|1) ;;
  *) echo "RAVEN_INSTALL_NEARBY_ONLY must be 1 (install RavenNearby.app only) or 0" >&2; exit 1 ;;
esac
if [[ "$NEARBY_ONLY" == 1 && "$RENDER_ONLY" == 1 ]]; then
  echo "RAVEN_INSTALL_NEARBY_ONLY=1 and RAVEN_INSTALL_RENDER_ONLY=1 cannot be combined" >&2
  exit 1
fi
if [[ "$NEARBY_ONLY" == 1 || -n "$NEARBY_APP" ]]; then
  NEARBY_HELPER=1
fi
if [[ -n "$NEARBY_APP" ]]; then
  [[ "$NEARBY_APP" == /* ]] || NEARBY_APP="$PWD/$NEARBY_APP"
  if [[ ! -f "$NEARBY_APP/Contents/Info.plist" || ! -x "$NEARBY_APP/Contents/MacOS/raven-nearby-helper" ]]; then
    echo "RAVEN_NEARBY_APP must name a built RavenNearby.app (node/scripts/build_nearby_helper_app.sh)" >&2
    exit 1
  fi
fi
if [[ "$NEARBY_SIGN" == keep && -z "$NEARBY_APP" ]]; then
  echo "RAVEN_NEARBY_SIGN=keep needs RAVEN_NEARBY_APP (a bundle that is signed already)" >&2
  exit 1
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
LABEL="com.raven.raven-node"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"

# Where raven-node looks for the nearby helper (raven-node src/nearby/apple.rs
# INSTALL_DIR and BUNDLE).
NEARBY_DIR="$HOME/Library/Application Support/Raven"
NEARBY_DEST="$NEARBY_DIR/RavenNearby.app"
NEARBY_STAGE=""
# What the helper install must leave alone: the `codesign -dv` and the bytes
# of the raven-node in BIN_DIR ("absent" when there is none yet).
node_signature() {
  local f="$BIN_DIR/raven-node"
  if [[ ! -e "$f" ]]; then
    printf 'absent'
    return 0
  fi
  codesign -dv --verbose=4 "$f" 2>&1 || true
  shasum -a 256 "$f" 2>&1 || true
}
# A failed helper install removes its staging folder; an installed bundle
# from before stays in place.
nearby_fail() {
  if [[ -n "$NEARBY_STAGE" ]]; then
    rm -rf "$NEARBY_STAGE"
  fi
  echo "RavenNearby.app was not installed: $1" >&2
  exit 1
}
# Build (or take RAVEN_NEARBY_APP), sign, check, then put RavenNearby.app in
# place. The raven-node in BIN_DIR is never touched: its signature is
# compared before and after.
install_nearby_helper() {
  local before after app answer
  local sign=(codesign --force --sign "$NEARBY_SIGN" --identifier org.raven.nearby)
  before="$(node_signature)"
  mkdir -p "$NEARBY_DIR"
  NEARBY_STAGE="$(mktemp -d "$NEARBY_DIR/.RavenNearby-install.XXXXXX")" \
    || nearby_fail "cannot create a staging folder in $NEARBY_DIR"
  app="$NEARBY_STAGE/RavenNearby.app"
  if [[ -n "$NEARBY_APP" ]]; then
    ditto "$NEARBY_APP" "$app" || nearby_fail "cannot copy $NEARBY_APP"
  else
    bash "$ROOT/scripts/build_nearby_helper_app.sh" "$NEARBY_STAGE" --no-sign \
      || nearby_fail "the build failed (node/scripts/build_nearby_helper_app.sh)"
  fi
  if [[ "$NEARBY_SIGN" != keep ]]; then
    if [[ "$NEARBY_SIGN" != - ]]; then
      sign+=(--options runtime --timestamp)
    fi
    "${sign[@]}" "$app" || nearby_fail "codesign --sign '$NEARBY_SIGN' failed"
  fi
  codesign --verify --strict "$app" || nearby_fail "its code signature does not verify"
  answer="$("$app/Contents/MacOS/raven-nearby-helper" --check </dev/null 2>/dev/null)" || answer=""
  if [[ "$answer" != '{"ev":"hello","v":1}' ]]; then
    nearby_fail "it does not find its Bluetooth usage description (--check answered '$answer')"
  fi
  if [[ -e "$NEARBY_DEST" ]]; then
    mv "$NEARBY_DEST" "$NEARBY_STAGE/RavenNearby.old.app" || nearby_fail "cannot move the installed one aside"
  fi
  if ! mv "$app" "$NEARBY_DEST"; then
    if [[ -e "$NEARBY_STAGE/RavenNearby.old.app" ]]; then
      mv "$NEARBY_STAGE/RavenNearby.old.app" "$NEARBY_DEST" || true
    fi
    nearby_fail "cannot move it to $NEARBY_DEST"
  fi
  rm -rf "$NEARBY_STAGE"
  NEARBY_STAGE=""
  after="$(node_signature)"
  if [[ "$before" != "$after" ]]; then
    echo "ERROR: ${BIN_DIR}/raven-node changed while RavenNearby.app was installed; its code signature (and Keychain access) is not the one it had" >&2
    exit 1
  fi
}
# What the install says about the helper, and what this raven-node build
# does with it (`raven-node ble-status`; nothing when it cannot answer).
nearby_lines() {
  local how status gate backend
  case "$NEARBY_SIGN" in
    -) how="signed ad hoc" ;;
    keep) how="signature kept as built" ;;
    *) how="signed: $NEARBY_SIGN" ;;
  esac
  echo "Bluetooth nearby helper: ${NEARBY_DEST} (${how}; it holds no keys)"
  echo "  raven-node was not re-signed: its code signature, and so its Keychain access, are unchanged."
  echo "  Nearby stays off until you turn it on: raven nearby enable (verified contacts only; it says once what nearby devices can see)."
  echo "  The first time the radio starts, macOS asks whether RavenNearby may use Bluetooth: allow it. Later:"
  echo "    System Settings > Privacy & Security > Bluetooth (RavenNearby on), then restart the agent:"
  echo "    launchctl kickstart -k gui/$(id -u)/${LABEL}"
  status="$("${BIN_DIR}/raven-node" ble-status 2>/dev/null)" || status=""
  gate="$(printf '%s\n' "$status" | sed -n 's/^nearby_gate=//p' | head -n 1)"
  backend="$(printf '%s\n' "$status" | sed -n 's/^nearby_backend=//p' | head -n 1)"
  if [[ "$backend" == none ]]; then
    echo "  NOTE: ${BIN_DIR}/raven-node has no Bluetooth backend (built without feature nearby-radio), so it never starts the helper;"
    echo "    re-run this installer without RAVEN_INSTALL_NEARBY_ONLY (and without RAVEN_INSTALL_NEARBY_HELPER=0) to rebuild it with one."
  fi
  if [[ "$gate" == held ]]; then
    echo "  This raven-node holds Bluetooth nearby (its build has it off): raven-node never starts the radio; raven nearby status says held."
  fi
  if [[ -e "$BIN_DIR/RavenNearby.app" ]]; then
    echo "  NOTE: ${BIN_DIR}/RavenNearby.app, next to raven-node, wins over the installed one; remove it to use this one."
  fi
  echo "  Guide: docs/NEARBY.md"
}

# The helper alone: no build of raven-node or ash, no profile, no plist, no
# agent start.
if [[ "$NEARBY_ONLY" == 1 ]]; then
  [[ "$BIN_DIR" == /* ]] || BIN_DIR="$PWD/$BIN_DIR"
  if [[ ! -e "$BIN_DIR/raven-node" ]]; then
    echo "NOTE: no raven-node in ${BIN_DIR} yet: install it first (this installer without RAVEN_INSTALL_NEARBY_ONLY)"
  fi
  install_nearby_helper
  nearby_lines
  exit 0
fi

if [[ "$RENDER_ONLY" == 1 ]]; then
  # Render-only creates nothing: the folders are shown as given, made absolute.
  [[ "$BIN_DIR" == /* ]] || BIN_DIR="$PWD/$BIN_DIR"
  [[ "$DATA_DIR" == /* ]] || DATA_DIR="$PWD/$DATA_DIR"
else
  mkdir -p "$BIN_DIR" "$HOME/Library/LaunchAgents"
  # Identity, sessions and chat history live here: owner-only.
  mkdir -p "$DATA_DIR"
  chmod 700 "$DATA_DIR"
  # launchd starts the agent with cwd=/: register absolute paths only. A relative
  # RAVEN_DATA_DIR / RAVEN_BIN_DIR would make the agent serve (or exec from) a
  # different directory than the one `raven init` just created.
  BIN_DIR="$(CDPATH='' cd -- "$BIN_DIR" && pwd)"
  DATA_DIR="$(CDPATH='' cd -- "$DATA_DIR" && pwd)"
fi
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
# Internet direct listener: only when asked for (no flag otherwise, so a later
# `raven node internet on` in node_policy.json decides).
internet_listen_plist_args() {
  [[ -n "$INTERNET_LISTEN" ]] || return 0
  printf '    <string>--internet-listen</string>\n    <string>%s</string>\n' "$(xml_escape "$INTERNET_LISTEN")"
}
# libp2p flags: only the ones asked for. Printed into the same line of the plist
# as the Internet flags, so with nothing set the plist stays as before.
p2p_plist_args() {
  local r
  if [[ -n "$P2P_LISTEN" ]]; then
    printf '    <string>--p2p-listen</string>\n    <string>%s</string>\n' "$(xml_escape "$P2P_LISTEN")"
  fi
  if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]]; then
    for r in "${P2P_RELAY_LIST[@]}"; do
      printf '    <string>--p2p-relay</string>\n    <string>%s</string>\n' "$(xml_escape "$r")"
    done
  fi
  if [[ "$P2P_RELAY" == "1" ]]; then
    printf '    <string>--relay</string>\n'
  fi
  return 0
}
# Render-only builds and copies nothing: it asks the raven-node already in BIN_DIR.
if [[ "$RENDER_ONLY" != 1 ]]; then
  # --locked: build exactly the audited Cargo.lock. `tor` adds the
  # raven-tor-helper binary (raven-node itself never links Arti); the nearby
  # helper's raven-node carries the macOS radio backend (it spawns the
  # helper; it never links CoreBluetooth itself).
  build_features=()
  if [[ "$TOR_HELPER" == 1 ]]; then
    build_features+=(--features raven-node/tor)
  fi
  if [[ "$NEARBY_HELPER" == 1 ]]; then
    build_features+=(--features raven-node/nearby-radio)
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
  # Optional ash launcher only if safe (not overwriting /bin/ash)
  if [[ ! -e /bin/ash ]] || [[ "$(readlink -f "$BIN_DIR/ash" 2>/dev/null || true)" == "$BIN_DIR/raven" ]]; then
    ln -sfn "$BIN_DIR/raven" "$BIN_DIR/ash"
    echo "linked $BIN_DIR/ash -> raven (user-local only)"
  else
    echo "NOTE: system /bin/ash exists — use '$BIN_DIR/raven' (never overwrite /bin/ash)"
  fi
  # The helper goes in place before the agent (re)starts below, and after
  # raven-node, whose signature it must leave as it is.
  if [[ "$NEARBY_HELPER" == 1 ]]; then
    install_nearby_helper
  fi
fi

# Identity + prekey must exist before LAN preflight will keep the service up,
# and before the LAN default below: a new profile picks its LAN port here
# (Phase 6b, while that gate is live). Render-only creates nothing.
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

# RAVEN_SERVICE_LOG_MAX_BYTES caps raven-node.log / .err at 1 MiB: raven-node
# truncates them in place past the cap, and only when launchd opened them with
# O_APPEND (a descriptor without it is left alone, so this is safe either way).
render_plist() {
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml_escape "${BIN_DIR}")/raven-node</string>
    <string>service</string>
    <string>--data-dir</string>
    <string>$(xml_escape "${DATA_DIR}")</string>
    <string>--lan-listen</string>
    <string>$(xml_escape "${LAN_LISTEN}")</string>
    <string>--ble-listen</string>
    <string>$(xml_escape "${BLE_LISTEN}")</string>
$(internet_listen_plist_args; p2p_plist_args)
    <string>--timeout-secs</string>
    <string>0</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$(xml_escape "${DATA_DIR}")/raven-node.log</string>
  <key>StandardErrorPath</key><string>$(xml_escape "${DATA_DIR}")/raven-node.err</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RAVEN_SERVICE_LOG_MAX_BYTES</key><string>1048576</string>
  </dict>
</dict>
</plist>
EOF
}
# What the install says about LAN (render-only prints it too, on stderr).
lan_lines() {
  echo "LAN listen: ${LAN_LISTEN}"
  case "$LAN_LISTEN" in
    [Aa][Uu][Tt][Oo]|[Aa][Uu][Tt][Oo]:*)
      if is_auto "$LAN_DEFAULT"; then
        echo "LAN: every network of this Mac, contacts only (TCP ${LAN_PORT}; nearby search on UDP ${BEACON_UDP_PORT})"
        echo "  Contacts on a VPN (100.64.0.0/10, e.g. Tailscale) or at a public address are refused;"
        echo "  for them re-run with RAVEN_LAN_LISTEN=0.0.0.0:${LAN_PORT}."
      else
        echo "LAN: this build holds auto (LAN_AUTO_LISTEN_PRODUCTION_ENABLED=false), so it listens on 0.0.0.0:${LAN_PORT} from any source (contacts only)"
      fi
      echo "  If the macOS firewall is on, allow raven-node yourself:"
      echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ${BIN_DIR}/raven-node"
      echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ${BIN_DIR}/raven-node"
      echo "  On a network you do not trust (cafe, hotel): raven lan off"
      echo "  If macOS asks for Local Network access for raven-node, allow it"
      ;;
    127.*|localhost:*|\[::1\]:*)
      echo "LAN peers cannot reach this node (loopback only). To accept LAN peers, re-run with"
      echo "  RAVEN_LAN_LISTEN=<this-Mac-LAN-IP>:${LAN_PORT} and allow raven-node in the macOS firewall."
      if is_auto "$LAN_DEFAULT"; then
        echo "  (re-run with RAVEN_LAN_LISTEN=auto, which your build allows)"
      fi
      ;;
    *)
      echo "Exposed on ${LAN_LISTEN}: allow inbound TCP ${LAN_PORT} on the LAN only (System Settings → Network → Firewall)." ;;
  esac
}
if [[ "$RENDER_ONLY" == 1 ]]; then
  echo "LAN_LISTEN=${LAN_LISTEN}"
  render_plist
  {
    echo "RAVEN_INSTALL_RENDER_ONLY=1: nothing was built, written or started (${PLIST} is unchanged)"
    if [[ "$NEARBY_HELPER" == 1 ]]; then
      echo "RavenNearby.app: not installed (render-only; it would go to ${NEARBY_DEST})"
    fi
    lan_lines
  } >&2
  exit 0
fi
render_plist >"$PLIST"

# The profile was created above, before the LAN default.
# The same p2p settings go into node_policy.json too, so `raven whoami --card`
# and `raven status` agree with the agent even while it is not running (its
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
    echo "WARN: could not save the p2p settings in node_policy.json (the agent still uses its flags); run '${BIN_DIR}/raven --data-dir ${DATA_DIR} ${P2P_SAVE_ARGS[*]}'"
  fi
fi
# Saved in node_policy.json before the agent (re)starts below, which applies it.
UPNP_SAVED=""
if [[ -n "$UPNP_MODE" ]]; then
  if "${BIN_DIR}/raven" --data-dir "${DATA_DIR}" node upnp "$UPNP_MODE"; then
    UPNP_SAVED="$UPNP_MODE"
  else
    echo "WARN: could not save the UPnP choice; run '${BIN_DIR}/raven --data-dir ${DATA_DIR} node upnp ${UPNP_MODE}' and restart the agent"
  fi
fi

launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || true
# `raven lock` may have disabled the agent ("keep Raven stopped"): bootstrap
# refuses a disabled service, which would abort this script under set -e.
# Installing is an explicit start, so turn it back on first.
launchctl enable "gui/$(id -u)/${LABEL}"
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed launchd agent ${LABEL}"
echo "data-dir=${DATA_DIR}"
# Where the daemon really listens: a long data dir is served at
# /tmp/raven-<uid>/raven-<hash>.sock, not at <data-dir>/raven-node.sock. Ask the
# installed binary (`doctor` prints `ipc_endpoint=`) instead of guessing.
IPC_EP="$("${BIN_DIR}/raven" --data-dir "${DATA_DIR}" doctor 2>/dev/null \
  | sed -n 's/^[[:space:]]*ipc_endpoint=//p' | head -n1 || true)"
echo "IPC sock: ${IPC_EP:-<unknown: run '${BIN_DIR}/raven --data-dir ${DATA_DIR} doctor' and look for ipc_endpoint=>} (service = lan_direct + ipc)"
lan_lines
if [[ -n "$INTERNET_LISTEN" ]]; then
  echo "Internet listen: ${INTERNET_LISTEN} (only your contacts get an answer; anyone can see that the port is open)"
  echo "  If the macOS firewall is on, allow raven-node yourself:"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ${BIN_DIR}/raven-node"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ${BIN_DIR}/raven-node"
  echo "  (an unsigned rebuild may need this again) and forward the TCP port on your router if you are behind NAT."
  echo "  Check: raven status (internet row)."
else
  echo "Internet listen: off (opt-in: re-run with RAVEN_INTERNET_LISTEN=0.0.0.0:7422, or 'raven node internet on' and restart the agent)"
fi
if p2p_listen_requested; then
  echo "p2p listen: ${P2P_LISTEN} (libp2p TCP+UDP ${P2P_PORT}; only your contacts get a Raven link; anyone can see that the port is open)"
  echo "  The macOS Application Firewall is off by default. If it is on, allow raven-node yourself:"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ${BIN_DIR}/raven-node"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ${BIN_DIR}/raven-node"
  echo "  (an unsigned rebuild may need this again) and forward TCP+UDP ${P2P_PORT} on your router if you are behind NAT (or RAVEN_UPNP=1);"
  echo "  without that a relay (RAVEN_P2P_RELAYS) still lets contacts reach you."
  echo "  Check: raven status (p2p row)."
elif [[ -n "$P2P_LISTEN" ]]; then
  echo "p2p listen: off (RAVEN_P2P_LISTEN=${P2P_LISTEN} overrides 'raven node p2p on')"
else
  echo "p2p listen: off (opt-in: re-run with RAVEN_P2P_LISTEN=7423, or 'raven node p2p on' and restart the agent)"
fi
if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]]; then
  echo "p2p relays: ${P2P_RELAY_LIST[*]} (a reservation is kept on each; a relay sees both PeerIds and IPs of every circuit, never your messages)"
fi
if [[ "$P2P_RELAY" == "1" ]]; then
  echo "relay: on for your verified contacts (and the PeerIds in ${DATA_DIR}/relay_allow.json), with this profile's own"
  echo "  relay key (never your PeerId) on TCP and UDP 7427; 'raven relay offer off' stops it, 'raven relay status' shows it."
  echo "  A saved 'raven relay offer off' wins over RAVEN_P2P_RELAY=1 ('raven relay offer on' to relay again); 'raven node hide-ip on' stops it too."
  echo "  If the macOS firewall is on, allow raven-node yourself:"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ${BIN_DIR}/raven-node"
  echo "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ${BIN_DIR}/raven-node"
  echo "  and forward TCP+UDP 7427 on your router if you are behind NAT."
fi
if [[ ${#P2P_RELAY_LIST[@]} -gt 0 ]] && ! p2p_listen_requested; then
  echo "NOTE: relays take effect only while p2p listen is on (RAVEN_P2P_LISTEN=7423 or 'raven node p2p on')."
fi
if [[ "$P2P_RELAY" == "1" ]] && ! p2p_listen_requested; then
  echo "NOTE: contacts are offered your relay once this computer is confirmed reachable (p2p listen on: RAVEN_P2P_LISTEN=7423)"
  echo "  or once you name its address: raven relay offer on --external /ip4/<public IP>/tcp/7427"
fi
case "$UPNP_SAVED" in
  on) echo "UPnP: on (raven-node asks the router to map TCP/UDP ${P2P_PORT:-of the p2p port, when one is open}; it logs only the mapped port and success or failure)" ;;
  off) echo "UPnP: off ('raven node upnp on' changes it; applied when the agent restarts)" ;;
esac
if [[ "$TOR_HELPER" == 1 ]]; then
  echo "Tor: ${BIN_DIR}/raven-tor-helper, next to raven-node. raven-node starts it and keeps an onion service, so friends"
  echo "  can reach this Mac from any network without a port forward; Tor relays are the only third party it talks to."
  echo "  The first start can take a few minutes. Check: raven status (Tor row)."
else
  echo "Tor: not installed (RAVEN_INSTALL_TOR_HELPER=0); raven status says \"Tor: not built in this raven\"."
fi
if [[ "$NEARBY_HELPER" == 1 ]]; then
  nearby_lines
fi
echo "PATH tip: export PATH=\"${BIN_DIR}:\$PATH\""
