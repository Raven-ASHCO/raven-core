#!/usr/bin/env bash
# Raven relay kit, Linux (a Raspberry Pi, a small VPS, any always-on box):
# one command installs a dedicated relay for your friends as a hardened system
# service. Guide: docs/RELAY_KIT.md.
#
#   RAVEN_RELAY_HOST=<public IP or DNS name> bash node/scripts/install/linux_relay.sh
#
# It asks for sudo for the system part (run it as your own user; root works
# too). The relay is `raven-node relay`: it holds NO Raven identity and touches
# no keystore, only its own libp2p key (relay_key.ed25519), and it relays only
# between the PeerIds you allow (`raven-relay allow --card ...`). It passes
# encrypted bytes. It learns both PeerIds and IPs of every circuit, its timing
# and byte counts; never a message, never a Raven ID. Its logs (journald)
# carry counts only.
#
# What `raven-relay status` prints is for you: the allow-list (friends'
# PeerIds and your labels) and the relay's own addresses too.
#
# Settings (environment, else kit.conf from the last run, else the default):
#   RAVEN_RELAY_HOST=<IP|DNS>   the address friends reach it at (cards name it)
#   RAVEN_RELAY_PORT=7423       TCP + QUIC port (7424/7425: a second Raven
#                               profile's; 7427: the friend relay's; else 7428)
#   RAVEN_RELAY_TCP443=direct   also TCP 443 for networks that let only HTTPS
#                               out (the unit gets CAP_NET_BIND_SERVICE);
#                               7443 = listen on 7443, your router (or a
#                               second IP's redirect) maps a free public 443
#                               to it, never a web server's 443; off = no 443
#   RAVEN_RELAY_AUTONAT=1       answer reachability checks (two relays of a
#                               friend on different networks confirm "public")
#   RAVEN_RELAY_COUNTS_EVERY=300  seconds between two counts lines (30-3600)
#   RAVEN_RELAY_HARDENING=full  basic drops the system-call filter (older
#                               systemd / Pi OS where full breaks the relay)
#   RAVEN_RELAY_LAB=1           a debug build with the lab unlock (tests only)
# Binaries: RAVEN_RELAY_PREBUILT=<folder with raven-node and raven>, else a
# release layout's bin/, else `cargo build --locked` (needs about 2 GB RAM).
# Actions:
#   RAVEN_RELAY_ADOPT=<folder>  take the key and allow-list of a relay you ran
#                               by hand, so friends' via= lines keep working
#   RAVEN_RELAY_ROLLBACK=1      swap back the previous binaries
#   RAVEN_RELAY_UNINSTALL=1     remove the service (keeps key and allow-list;
#                               RAVEN_RELAY_PURGE=1 deletes them and the user)
# Update: re-run the same command. kit.conf remembers the settings, the key and
# the allow-list are untouched, and the PeerId must stay the same (else the old
# binaries come back).
#
# Fixed paths (the raven-relay wrapper needs no configuration):
#   /usr/local/lib/raven-relay   binaries, their .prev copies, kit.conf
#   /var/lib/raven-relay         key, allow-list, status (user raven-relay, 0700)
#   /etc/systemd/system/raven-relay.service, /usr/local/bin/raven-relay
#
# Exit codes: 0 ok; 1 failed (rolled back when there was an older install);
# 2 bad settings; 3 this build holds p2p; 4 a port is busy or needs a
# privilege; 5 the relay folder cannot be used. The kit never opens a
# firewall: it prints the rules.
set -euo pipefail
RELAY_KIT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=relay_common.sh
. "$RELAY_KIT_DIR/relay_common.sh"

LIB_DIR=/usr/local/lib/raven-relay
STATE_DIR=/var/lib/raven-relay
RELAY_USER=raven-relay
UNIT=/etc/systemd/system/raven-relay.service
WRAPPER=/usr/local/bin/raven-relay
KIT_CONF="$LIB_DIR/kit.conf"
STATUS="$STATE_DIR/relay_status.json"
INSTALLER="bash node/scripts/install/linux_relay.sh"

# Root for the system part only: sudo when not root already.
as_root() {
  if [[ $EUID -eq 0 ]]; then
    "$@"
  else
    sudo -- "$@"
  fi
}

for tool in systemctl install sed; do
  command -v "$tool" >/dev/null 2>&1 || relay_die "$tool not found: the Linux kit needs systemd (systemctl)"
done
# A user's PATH may lack /usr/sbin (Debian, Raspberry Pi OS); sudo's has it.
if ! command -v useradd >/dev/null 2>&1 && [[ ! -x /usr/sbin/useradd && ! -x /sbin/useradd ]]; then
  relay_die "useradd not found: the Linux kit creates a system user for the relay"
fi
if [[ $EUID -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
  relay_die "run as root, or install sudo"
fi
if ! command -v runuser >/dev/null 2>&1 && ! command -v sudo >/dev/null 2>&1; then
  relay_die "runuser (util-linux) or sudo is needed to run the relay commands as $RELAY_USER"
fi

relay_load_settings "$KIT_CONF"
# Fixed on Linux: refuse anything else rather than half-use it.
if [[ "${RAVEN_RELAY_DIR:-$STATE_DIR}" != "$STATE_DIR" || "${RAVEN_RELAY_BIN_DIR:-$LIB_DIR}" != "$LIB_DIR" \
  || "${RAVEN_RELAY_USER:-$RELAY_USER}" != "$RELAY_USER" ]]; then
  relay_die "RAVEN_RELAY_DIR / _BIN_DIR / _USER are fixed on Linux ($STATE_DIR, $LIB_DIR, $RELAY_USER)" "$RELAY_EXIT_SETTINGS"
fi
RAVEN_RELAY_DIR=$STATE_DIR
RAVEN_RELAY_BIN_DIR=$LIB_DIR
RAVEN_RELAY_USER=$RELAY_USER
unset RAVEN_RELAY_SYSTEM
relay_args

# Whether the unit is running now.
unit_active() {
  systemctl is-active --quiet raven-relay 2>/dev/null
}

# The PeerId in the status file, or nothing.
status_peer() {
  as_root sed -n "$RELAY_PEER_SED" "$STATUS" 2>/dev/null || true
}

# The last lines of the relay's log, after a failure.
show_journal() {
  echo "--- journalctl -u raven-relay -n 30 ---" >&2
  as_root journalctl -u raven-relay -n 30 --no-pager >&2 2>/dev/null || true
}

# Swap each binary with its .prev copy (rollback, and undoing a failed update).
swap_prev() {
  local b
  for b in raven-node raven; do
    as_root test -f "$LIB_DIR/$b.prev" || return 1
  done
  for b in raven-node raven; do
    as_root mv -f "$LIB_DIR/$b" "$LIB_DIR/.$b.swap"
    as_root mv -f "$LIB_DIR/$b.prev" "$LIB_DIR/$b"
    as_root mv -f "$LIB_DIR/.$b.swap" "$LIB_DIR/$b.prev"
  done
}

# Wait up to 20 s for the started relay: its status file is written by the
# unit's main process, lists the listen ports and (on an update) the PeerId
# it had before.
verify_started() {
  local want_peer=$1 i main pid peer ok port
  for i in $(seq 1 20); do
    sleep 1
    if systemctl is-failed --quiet raven-relay 2>/dev/null; then
      echo "relay kit: the relay stopped (systemctl status raven-relay)" >&2
      return 1
    fi
    main="$(systemctl show -p MainPID --value raven-relay 2>/dev/null || true)"
    pid="$(as_root sed -n "$RELAY_PID_SED" "$STATUS" 2>/dev/null || true)"
    [[ -n "$main" && "$main" != 0 && "$pid" == "$main" ]] || continue
    ok=1
    for port in $(relay_tcp_ports); do
      as_root grep -Eq "\"/ip[46]/[^\"]*/tcp/${port}\"" "$STATUS" || ok=0
    done
    [[ $ok -eq 1 ]] || continue
    peer="$(status_peer)"
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
  peer="$(status_peer)"
  as_root systemctl disable --now raven-relay 2>/dev/null || true
  as_root rm -f "$UNIT" "$WRAPPER"
  as_root rm -rf "$LIB_DIR"
  as_root systemctl daemon-reload
  relay_note "removed the service, the wrapper and the binaries"
  if [[ "${RAVEN_RELAY_PURGE:-0}" == 1 ]]; then
    if [[ -n "$peer" ]]; then
      relay_note "deleting the relay key: friends' via= lines naming ${peer} stop working"
    fi
    as_root rm -rf "$STATE_DIR"
    if id -u "$RELAY_USER" >/dev/null 2>&1; then
      as_root userdel "$RELAY_USER" || relay_note "could not remove the user $RELAY_USER (userdel $RELAY_USER)"
    fi
    relay_note "purged $STATE_DIR and the user $RELAY_USER"
  else
    relay_note "kept $STATE_DIR (key${peer:+ of $peer} and allow-list) and the user $RELAY_USER: a re-install keeps the PeerId; RAVEN_RELAY_PURGE=1 deletes them"
  fi
  exit 0
fi

if [[ "${RAVEN_RELAY_ROLLBACK:-0}" == 1 ]]; then
  [[ -f "$UNIT" ]] || relay_die "no relay installed here"
  old_peer="$(status_peer)"
  as_root systemctl stop raven-relay 2>/dev/null || true
  swap_prev || relay_die "no previous binaries to roll back to ($LIB_DIR/*.prev)"
  as_root systemctl restart raven-relay
  if ! verify_started "$old_peer"; then
    show_journal
    relay_die "the rolled-back relay did not come up (RAVEN_RELAY_ROLLBACK=1 again swaps back)"
  fi
  relay_note "rolled back to the previous binaries (PeerId ${RELAY_PEER} kept)"
  exit 0
fi

# 3. The binaries to install: built or found as whoever runs this script.
relay_binaries

# 4. What runs now. A running relay holds its ports and its folder's lock.
was_active=0
if unit_active; then
  was_active=1
fi
old_peer="$(status_peer)"
if [[ $was_active -eq 1 ]]; then
  as_root systemctl stop raven-relay
fi
restart_old() {
  if [[ $was_active -eq 1 ]]; then
    as_root systemctl start raven-relay || true
    relay_note "the relay that ran before was started again (unchanged)"
  fi
}

# 5. The NEW binary checks the gate, the folder and every port before anything
# is replaced: as root, so 443 is probed as the unit (CAP_NET_BIND_SERVICE)
# will bind it. It creates nothing.
check_env=(NO_COLOR=1)
if [[ "$RAVEN_RELAY_LAB" == 1 ]]; then
  check_env+=(RAVEN_LAB_TEST_A=1)
fi
rc=0
as_root env -u RAVEN_LAB_TEST_A "${check_env[@]}" "$RELAY_NODE_BIN" relay --check --data-dir "$STATE_DIR" "${RELAY_ARGS[@]}" || rc=$?
if [[ $rc -ne 0 ]]; then
  relay_check_failed "$rc"
  restart_old
  exit "$rc"
fi

# 6. The service account, and a manual relay's key when asked to adopt it.
if ! id -u "$RELAY_USER" >/dev/null 2>&1; then
  nologin="$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)"
  as_root useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home --shell "$nologin" "$RELAY_USER"
  relay_note "created the system user $RELAY_USER"
fi
as_root install -d -o "$RELAY_USER" -g "$RELAY_USER" -m 700 "$STATE_DIR"
# Everything in it belongs to the relay's account (the check ran as root and
# may have touched its lock file).
as_root chown -R "$RELAY_USER:$RELAY_USER" "$STATE_DIR"
if [[ -n "${RAVEN_RELAY_ADOPT:-}" ]]; then
  adopt=$RAVEN_RELAY_ADOPT
  if as_root test -e "$STATE_DIR/relay_key.ed25519"; then
    relay_note "$STATE_DIR already has a relay key: RAVEN_RELAY_ADOPT ignored (its PeerId is kept)"
  else
    if as_root test -L "$adopt/relay_key.ed25519" || ! as_root test -f "$adopt/relay_key.ed25519"; then
      relay_die "RAVEN_RELAY_ADOPT=$adopt holds no relay_key.ed25519 (the folder of a raven-node relay you ran by hand)"
    fi
    as_root install -o "$RELAY_USER" -g "$RELAY_USER" -m 600 "$adopt/relay_key.ed25519" "$STATE_DIR/relay_key.ed25519"
    if as_root test -f "$adopt/relay_allow.json"; then
      as_root install -o "$RELAY_USER" -g "$RELAY_USER" -m 600 "$adopt/relay_allow.json" "$STATE_DIR/relay_allow.json"
    fi
    adopted="$(as_root sed -n "$RELAY_PEER_SED" "$adopt/relay_status.json" 2>/dev/null || true)"
    relay_note "adopted the relay key${adopted:+ of $adopted} and allow-list from $adopt (stop that relay: both cannot run)"
    old_peer=$adopted
  fi
fi

# 7. Binaries, each replaced in one rename, the old one kept as .prev.
as_root install -d -m 755 "$LIB_DIR"
had_prev=0
for b in raven-node raven; do
  if [[ "$b" == raven-node ]]; then src=$RELAY_NODE_BIN; else src=$RELAY_CLI_BIN; fi
  if as_root test -f "$LIB_DIR/$b"; then
    as_root cp -p "$LIB_DIR/$b" "$LIB_DIR/$b.prev"
    had_prev=1
  fi
  as_root install -m 755 "$src" "$LIB_DIR/.$b.new"
  as_root mv -f "$LIB_DIR/.$b.new" "$LIB_DIR/$b"
done
# The wrapper, with this kit.conf's path written in.
sed "s|^KIT_CONF=''\$|KIT_CONF='$KIT_CONF'|" "$RELAY_KIT_DIR/raven-relay.sh" \
  | as_root tee "$LIB_DIR/.raven-relay.new" >/dev/null
as_root chmod 755 "$LIB_DIR/.raven-relay.new"
as_root mv -f "$LIB_DIR/.raven-relay.new" "$WRAPPER"
relay_kitconf_text | as_root tee "$LIB_DIR/.kit.conf.new" >/dev/null
as_root chmod 644 "$LIB_DIR/.kit.conf.new"
as_root mv -f "$LIB_DIR/.kit.conf.new" "$KIT_CONF"

# 8. The unit. Every ExecStart word goes through sd_quote.
exec_start="$(sd_quote "$LIB_DIR/raven-node") relay --data-dir $(sd_quote "$STATE_DIR")"
for a in "${RELAY_ARGS[@]}"; do
  case "$a" in
    --*) exec_start="$exec_start $a" ;;
    *) exec_start="$exec_start $(sd_quote "$a")" ;;
  esac
done
low_port=0
for p in $(relay_tcp_ports); do
  if [[ $p -lt 1024 ]]; then
    low_port=1
  fi
done
if [[ $low_port -eq 1 ]]; then
  caps="# A listen port is below 1024: only this capability, nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
else
  caps="CapabilityBoundingSet="
fi
if [[ "$RAVEN_RELAY_HARDENING" == full ]]; then
  syscalls="MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM"
else
  syscalls="# RAVEN_RELAY_HARDENING=basic: no MemoryDenyWriteExecute / SystemCallFilter."
fi
lab_env=""
if [[ "$RAVEN_RELAY_LAB" == 1 ]]; then
  lab_env="# LAB BUILD (RAVEN_RELAY_LAB=1): the debug lab unlock. Not for real use.
Environment=RAVEN_LAB_TEST_A=1"
fi
as_root tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=Raven relay for your friends (raven-node relay; holds no Raven identity)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=10

[Service]
Type=simple
User=$RELAY_USER
Group=$RELAY_USER
ExecStart=$exec_start
Restart=on-failure
RestartSec=10
# 2 bad flags, 3 held (P2P_PRODUCTION_ENABLED=false), 5 the folder: a restart
# cannot fix them. 4 (a port busy) can clear, so it restarts.
RestartPreventExitStatus=2 3 5
TimeoutStopSec=5
StateDirectory=raven-relay
StateDirectoryMode=0700
UMask=0077
$caps
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
$syscalls
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
MemoryMax=256M
TasksMax=256
LimitNOFILE=4096
IPAccounting=yes
Environment=NO_COLOR=1
$lab_env

[Install]
WantedBy=multi-user.target
EOF
as_root systemctl daemon-reload
as_root systemctl enable raven-relay
# `restart`, not `enable --now`: an update must replace the running binary.
as_root systemctl restart raven-relay

# 9. Verify; undo an update that does not come up as the same relay.
RELAY_PEER=""
if ! verify_started "$old_peer"; then
  show_journal
  if [[ $had_prev -eq 1 ]] && swap_prev; then
    as_root systemctl restart raven-relay || true
    relay_die "the new relay did not come up: the previous binaries are back (RAVEN_RELAY_ROLLBACK=1 swaps again)"
  fi
  as_root systemctl disable --now raven-relay 2>/dev/null || true
  relay_die "the relay did not come up (service stopped; files kept for a look: systemctl cat raven-relay)"
fi

# 10. What to do next.
echo
if [[ -n "$old_peer" ]]; then
  echo "relay PeerId: $RELAY_PEER (kept: friends' via= lines still work)"
else
  echo "relay PeerId: $RELAY_PEER (new: give friends the card below)"
fi
echo "listening: TCP $(relay_tcp_ports | tr ' ' ',') and UDP (QUIC) $RAVEN_RELAY_PORT as user $RELAY_USER"
if [[ -z "$RAVEN_RELAY_HOST" ]]; then
  echo "NOTE: no RAVEN_RELAY_HOST: cards name only what the relay sees itself; re-run with RAVEN_RELAY_HOST=<public IP or DNS name>, or use 'sudo raven-relay card --host <it>'"
fi
relay_print_firewall linux
echo "Logs: journalctl -u raven-relay (counts only), or: sudo raven-relay logs"
relay_print_next_steps "sudo raven-relay" "$INSTALLER"
