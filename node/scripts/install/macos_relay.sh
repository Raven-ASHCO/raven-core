#!/usr/bin/env bash
# Raven relay kit, macOS (an always-on Mac): one command installs a dedicated
# relay for your friends as a launchd agent. Guide: docs/RELAY_KIT.md.
#
#   RAVEN_RELAY_HOST=<public IP or DNS name> bash node/scripts/install/macos_relay.sh
#
# The relay is `raven-node relay`: it holds NO Raven identity and touches no
# keystore, only its own libp2p key (relay_key.ed25519), and it relays only
# between the PeerIds you allow (`raven-relay allow <PeerId>`). It passes
# encrypted bytes. It learns both PeerIds and IPs of every circuit, its timing
# and byte counts; never a message, never a Raven ID. Its log (relay.log, cut
# at 1 MiB, checked at every start too) carries counts only. What
# `raven-relay status` prints is for you: the allow-list (friends' PeerIds and
# your labels) and the relay's own addresses too. A relay that cannot start
# (exit 2 to 5) waits 5 minutes before launchd starts it again. A Mac that
# sleeps relays nothing.
#
# Settings (environment, else kit.conf from the last run, else the default):
#   RAVEN_RELAY_HOST=<IP|DNS>   the address friends reach it at (cards name it)
#   RAVEN_RELAY_PORT=7423       TCP + QUIC port. A Mac that already runs Raven
#                               with p2p on 7423 needs another one: 7428
#                               (7424/7425: a second profile's; 7427: the
#                               friend relay's), and that port forwarded
#   RAVEN_RELAY_TCP443=direct   also TCP 443 for networks that let only HTTPS
#                               out; 7443 = listen on 7443, your router maps
#                               443 to it; off = no 443
#   RAVEN_RELAY_AUTONAT=1       answer reachability checks for your friends
#   RAVEN_RELAY_COUNTS_EVERY=300  seconds between two counts lines (30-3600)
#   RAVEN_RELAY_SYSTEM=1        a LaunchDaemon (sudo): starts at boot without
#                               a login, still as you
#   RAVEN_RELAY_DIR=~/.raven-relay           key, allow-list, status, log
#   RAVEN_RELAY_BIN_DIR=~/.local/lib/raven-relay   binaries, .prev, kit.conf
#   RAVEN_RELAY_LAB=1           a debug build with the lab unlock (tests only)
# Binaries: RAVEN_RELAY_PREBUILT=<folder with raven-node and raven>, else a
# release layout's bin/, else `cargo build --locked`.
# Actions: RAVEN_RELAY_ADOPT=<folder> (take a hand-run relay's key and
# allow-list), RAVEN_RELAY_ROLLBACK=1, RAVEN_RELAY_UNINSTALL=1 (keeps the key;
# RAVEN_RELAY_PURGE=1 deletes it). Update: re-run the same command; the
# PeerId must stay the same (else the old binaries come back).
# CI hooks: RAVEN_RELAY_NO_LOAD=1 (write and lint the plist, start nothing),
# RAVEN_RELAY_PLIST_DIR=<dir>, RAVEN_RELAY_WRAPPER_DIR=<dir> (default
# ~/.local/bin).
#
# Exit codes: 0 ok; 1 failed (rolled back when there was an older install);
# 2 bad settings; 3 this build holds p2p; 4 a port is busy or needs a
# privilege; 5 the relay folder cannot be used. The kit never changes the
# firewall or the energy settings: it prints what to do.
set -euo pipefail
RELAY_KIT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=relay_common.sh
. "$RELAY_KIT_DIR/relay_common.sh"

LABEL=com.raven.relay
INSTALLER="bash node/scripts/install/macos_relay.sh"
# The settings file sits with the binaries: find it before the settings load.
BIN_DIR="${RAVEN_RELAY_BIN_DIR:-$HOME/.local/lib/raven-relay}"
relay_check_dir RAVEN_RELAY_BIN_DIR "$BIN_DIR"
relay_load_settings "$BIN_DIR/kit.conf"
: "${RAVEN_RELAY_DIR:=$HOME/.raven-relay}"
: "${RAVEN_RELAY_BIN_DIR:=$BIN_DIR}"
[[ "$RAVEN_RELAY_BIN_DIR" == "$BIN_DIR" ]] \
  || relay_die "RAVEN_RELAY_BIN_DIR in kit.conf differs from the folder it is in ($BIN_DIR)" "$RELAY_EXIT_SETTINGS"
relay_check_dir RAVEN_RELAY_DIR "$RAVEN_RELAY_DIR"
[[ -z "${RAVEN_RELAY_USER:-}" ]] || relay_die "RAVEN_RELAY_USER is Linux only: on macOS the relay runs as you" "$RELAY_EXIT_SETTINGS"
unset RAVEN_RELAY_HARDENING RAVEN_RELAY_USER
RELAY_DIR=$RAVEN_RELAY_DIR
WRAPPER_DIR="${RAVEN_RELAY_WRAPPER_DIR:-$HOME/.local/bin}"
relay_check_dir RAVEN_RELAY_WRAPPER_DIR "$WRAPPER_DIR"
WRAPPER="$WRAPPER_DIR/raven-relay"
STATUS="$RELAY_DIR/relay_status.json"
if [[ "$RAVEN_RELAY_SYSTEM" == 1 ]]; then
  DOMAIN=system
  PLIST_DIR="${RAVEN_RELAY_PLIST_DIR:-/Library/LaunchDaemons}"
else
  DOMAIN="gui/$(id -u)"
  PLIST_DIR="${RAVEN_RELAY_PLIST_DIR:-$HOME/Library/LaunchAgents}"
fi
PLIST="$PLIST_DIR/$LABEL.plist"
NO_LOAD="${RAVEN_RELAY_NO_LOAD:-0}"
relay_args

# A LaunchDaemon's plist must belong to root; everything else is yours.
as_plist_owner() {
  if [[ "$RAVEN_RELAY_SYSTEM" == 1 && -z "${RAVEN_RELAY_PLIST_DIR:-}" && $EUID -ne 0 ]]; then
    sudo -- "$@"
  else
    "$@"
  fi
}

loaded() {
  launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1
}

stop_relay() {
  if loaded; then
    as_plist_owner launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    # bootout returns before the process is gone; it holds the folder's lock.
    sleep 1
  fi
}

start_relay() {
  as_plist_owner launchctl bootstrap "$DOMAIN" "$PLIST"
}

show_log() {
  echo "--- tail -n 30 $RELAY_DIR/relay.log ---" >&2
  tail -n 30 "$RELAY_DIR/relay.log" >&2 2>/dev/null || true
}

swap_prev() {
  local b
  for b in raven-node raven; do
    [[ -f "$BIN_DIR/$b.prev" ]] || return 1
  done
  for b in raven-node raven; do
    mv -f "$BIN_DIR/$b" "$BIN_DIR/.$b.swap"
    mv -f "$BIN_DIR/$b.prev" "$BIN_DIR/$b"
    mv -f "$BIN_DIR/.$b.swap" "$BIN_DIR/$b.prev"
  done
}

# Wait up to 20 s for the started relay: its status file is written by the
# process launchd runs, lists the listen ports and (on an update) the PeerId
# it had before.
verify_started() {
  local want_peer=$1 i main pid peer ok port
  for i in $(seq 1 20); do
    sleep 1
    main="$(launchctl print "$DOMAIN/$LABEL" 2>/dev/null | sed -n 's/^[[:space:]]pid = \([0-9][0-9]*\)$/\1/p' || true)"
    pid="$(sed -n "$RELAY_PID_SED" "$STATUS" 2>/dev/null || true)"
    [[ -n "$main" && "$pid" == "$main" ]] || continue
    ok=1
    for port in $(relay_tcp_ports); do
      grep -Eq "\"/ip[46]/[^\"]*/tcp/${port}\"" "$STATUS" || ok=0
    done
    [[ $ok -eq 1 ]] || continue
    peer="$(relay_peer_of "$STATUS")"
    if [[ -n "$want_peer" && "$peer" != "$want_peer" ]]; then
      echo "relay kit: the relay's PeerId changed ($want_peer -> ${peer:-none}): its key was not kept" >&2
      return 1
    fi
    RELAY_PEER=$peer
    echo "relay kit: relay up after ${i}s (pid $pid)"
    return 0
  done
  echo "relay kit: the relay did not report its ports within 20 s" >&2
  return 1
}

if [[ "${RAVEN_RELAY_UNINSTALL:-0}" == 1 ]]; then
  peer="$(relay_peer_of "$STATUS")"
  stop_relay
  as_plist_owner rm -f "$PLIST"
  rm -f "$WRAPPER"
  rm -f "$BIN_DIR/raven-node" "$BIN_DIR/raven" "$BIN_DIR/raven-node.prev" "$BIN_DIR/raven.prev" "$BIN_DIR/kit.conf"
  rmdir "$BIN_DIR" 2>/dev/null || true
  relay_note "removed the launchd job, the wrapper and the binaries"
  if [[ "${RAVEN_RELAY_PURGE:-0}" == 1 ]]; then
    if [[ -n "$peer" ]]; then
      relay_note "deleting the relay key: friends' via= lines naming ${peer} stop working"
    fi
    rm -f "$RELAY_DIR/relay_key.ed25519" "$RELAY_DIR/relay_allow.json" "$RELAY_DIR/relay_status.json" \
      "$RELAY_DIR/relay.log" "$RELAY_DIR"/.relay*.lock.sqlite*
    rmdir "$RELAY_DIR" 2>/dev/null || relay_note "kept $RELAY_DIR: it holds other files"
    relay_note "purged the relay key and allow-list"
  else
    relay_note "kept $RELAY_DIR (key${peer:+ of $peer} and allow-list): a re-install keeps the PeerId; RAVEN_RELAY_PURGE=1 deletes them"
  fi
  exit 0
fi

if [[ "${RAVEN_RELAY_ROLLBACK:-0}" == 1 ]]; then
  [[ -f "$PLIST" ]] || relay_die "no relay installed here ($PLIST)"
  old_peer="$(relay_peer_of "$STATUS")"
  stop_relay
  swap_prev || relay_die "no previous binaries to roll back to ($BIN_DIR/*.prev)"
  RELAY_PEER=""
  if [[ "$NO_LOAD" != 1 ]]; then
    start_relay
    if ! verify_started "$old_peer"; then
      show_log
      relay_die "the rolled-back relay did not come up (RAVEN_RELAY_ROLLBACK=1 again swaps back)"
    fi
  fi
  relay_note "rolled back to the previous binaries${RELAY_PEER:+ (PeerId $RELAY_PEER kept)}"
  exit 0
fi

# 3. The binaries to install.
relay_binaries

# 4. What runs now. A running relay holds its ports and its folder's lock.
was_loaded=0
if [[ "$NO_LOAD" != 1 ]] && loaded; then
  was_loaded=1
fi
old_peer="$(relay_peer_of "$STATUS")"
if [[ $was_loaded -eq 1 ]]; then
  stop_relay
fi
restart_old() {
  if [[ $was_loaded -eq 1 ]]; then
    start_relay || true
    relay_note "the relay that ran before was started again (unchanged)"
  fi
}

# 5. The NEW binary checks the gate, the folder and every port before anything
# is replaced, as you (the agent runs as you). It creates nothing.
check_env=(NO_COLOR=1)
if [[ "$RAVEN_RELAY_LAB" == 1 ]]; then
  check_env+=(RAVEN_LAB_TEST_A=1)
fi
rc=0
env -u RAVEN_LAB_TEST_A "${check_env[@]}" "$RELAY_NODE_BIN" relay --check --data-dir "$RELAY_DIR" "${RELAY_ARGS[@]}" || rc=$?
if [[ $rc -ne 0 ]]; then
  relay_check_failed "$rc"
  restart_old
  exit "$rc"
fi

# 6. The relay folder (owner-only), and a hand-run relay's key when asked.
mkdir -p "$RELAY_DIR"
chmod 700 "$RELAY_DIR"
if [[ -n "${RAVEN_RELAY_ADOPT:-}" ]]; then
  adopt=$RAVEN_RELAY_ADOPT
  if [[ -e "$RELAY_DIR/relay_key.ed25519" ]]; then
    relay_note "$RELAY_DIR already has a relay key: RAVEN_RELAY_ADOPT ignored (its PeerId is kept)"
  else
    if [[ -L "$adopt/relay_key.ed25519" || ! -f "$adopt/relay_key.ed25519" ]]; then
      relay_die "RAVEN_RELAY_ADOPT=$adopt holds no relay_key.ed25519 (the folder of a raven-node relay you ran by hand)"
    fi
    install -m 600 "$adopt/relay_key.ed25519" "$RELAY_DIR/relay_key.ed25519"
    if [[ -f "$adopt/relay_allow.json" ]]; then
      install -m 600 "$adopt/relay_allow.json" "$RELAY_DIR/relay_allow.json"
    fi
    adopted="$(relay_peer_of "$adopt/relay_status.json")"
    relay_note "adopted the relay key${adopted:+ of $adopted} and allow-list from $adopt (stop that relay: both cannot run)"
    old_peer=$adopted
  fi
fi
# launchd appends the relay's stderr here: created by you, owner-only.
touch "$RELAY_DIR/relay.log"
chmod 600 "$RELAY_DIR/relay.log"

# 7. Binaries, each replaced in one rename, the old one kept as .prev.
mkdir -p "$BIN_DIR" "$WRAPPER_DIR"
BIN_DIR="$(CDPATH='' cd -- "$BIN_DIR" && pwd)"
RAVEN_RELAY_BIN_DIR=$BIN_DIR
had_prev=0
for b in raven-node raven; do
  if [[ "$b" == raven-node ]]; then src=$RELAY_NODE_BIN; else src=$RELAY_CLI_BIN; fi
  if [[ -f "$BIN_DIR/$b" ]]; then
    cp -p "$BIN_DIR/$b" "$BIN_DIR/$b.prev"
    had_prev=1
  fi
  install -m 755 "$src" "$BIN_DIR/.$b.new"
  mv -f "$BIN_DIR/.$b.new" "$BIN_DIR/$b"
done
# The wrapper, with this kit.conf's path written in.
sed "s|^KIT_CONF=''\$|KIT_CONF='$BIN_DIR/kit.conf'|" "$RELAY_KIT_DIR/raven-relay.sh" >"$WRAPPER_DIR/.raven-relay.new"
chmod 755 "$WRAPPER_DIR/.raven-relay.new"
mv -f "$WRAPPER_DIR/.raven-relay.new" "$WRAPPER"
relay_kitconf_text >"$BIN_DIR/.kit.conf.new"
chmod 644 "$BIN_DIR/.kit.conf.new"
mv -f "$BIN_DIR/.kit.conf.new" "$BIN_DIR/kit.conf"

# 8. The plist. Every path and value goes through xml_escape.
plist_args() {
  local a
  for a in "$BIN_DIR/raven-node" relay --data-dir "$RELAY_DIR" "${RELAY_ARGS[@]}"; do
    printf '    <string>%s</string>\n' "$(xml_escape "$a")"
  done
}
user_name_key=""
if [[ "$RAVEN_RELAY_SYSTEM" == 1 ]]; then
  user_name_key="  <key>UserName</key><string>$(xml_escape "$(id -un)")</string>"
fi
lab_env=""
if [[ "$RAVEN_RELAY_LAB" == 1 ]]; then
  lab_env="    <key>RAVEN_LAB_TEST_A</key><string>1</string>"
fi
new_plist="$(mktemp "${TMPDIR:-/tmp}/raven-relay-plist.XXXXXX")"
cat >"$new_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
$user_name_key
  <key>ProgramArguments</key>
  <array>
$(plist_args)
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key><false/>
  </dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Standard</string>
  <key>SoftResourceLimits</key>
  <dict>
    <key>NumberOfFiles</key><integer>4096</integer>
  </dict>
  <key>HardResourceLimits</key>
  <dict>
    <key>NumberOfFiles</key><integer>4096</integer>
  </dict>
  <key>StandardOutPath</key><string>/dev/null</string>
  <key>StandardErrorPath</key><string>$(xml_escape "$RELAY_DIR")/relay.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NO_COLOR</key><string>1</string>
    <key>RAVEN_SERVICE_LOG_MAX_BYTES</key><string>1048576</string>
    <key>RAVEN_RELAY_EXIT_PAUSE_SECS</key><string>300</string>
$lab_env
  </dict>
</dict>
</plist>
EOF
if ! plutil -lint "$new_plist" >/dev/null; then
  plutil -lint "$new_plist" >&2 || true
  rm -f "$new_plist"
  restart_old
  relay_die "the generated plist does not lint (a bug in the kit)"
fi
as_plist_owner mkdir -p "$PLIST_DIR"
as_plist_owner install -m 644 "$new_plist" "$PLIST"
rm -f "$new_plist"
if [[ "$NO_LOAD" == 1 ]]; then
  relay_note "RAVEN_RELAY_NO_LOAD=1: wrote $PLIST and the binaries, started nothing"
  exit 0
fi
stop_relay
start_relay

# 9. Verify; undo an update that does not come up as the same relay.
RELAY_PEER=""
if ! verify_started "$old_peer"; then
  show_log
  if [[ $had_prev -eq 1 ]] && swap_prev; then
    stop_relay
    start_relay || true
    relay_die "the new relay did not come up: the previous binaries are back (RAVEN_RELAY_ROLLBACK=1 swaps again)"
  fi
  stop_relay
  relay_die "the relay did not come up (job unloaded; the plist is kept for a look: $PLIST)"
fi

# 10. What to do next.
echo
if [[ -n "$old_peer" ]]; then
  echo "relay PeerId: $RELAY_PEER (kept: friends' via= lines still work)"
else
  echo "relay PeerId: $RELAY_PEER (new: give friends the card below)"
fi
echo "listening: TCP $(relay_tcp_ports | tr ' ' ',') and UDP (QUIC) $RAVEN_RELAY_PORT ($DOMAIN/$LABEL)"
if [[ -z "$RAVEN_RELAY_HOST" ]]; then
  echo "NOTE: no RAVEN_RELAY_HOST: cards name only what the relay sees itself; re-run with RAVEN_RELAY_HOST=<public IP or DNS name>, or use 'raven-relay card --host <it>'"
fi
relay_print_firewall macos
echo "A Mac that sleeps relays nothing: System Settings > Energy (or Battery > Options) > prevent automatic sleeping (not changed by the kit)."
echo "Logs: $RELAY_DIR/relay.log (counts only, cut at 1 MiB), or: raven-relay logs"
case ":$PATH:" in
  *":$WRAPPER_DIR:"*) ;;
  *) echo "PATH tip: export PATH=\"$WRAPPER_DIR:\$PATH\"" ;;
esac
relay_print_next_steps "raven-relay" "$INSTALLER"
