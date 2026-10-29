#!/bin/sh
# raven-relay: run the relay commands for the relay the kit installed
# (linux_relay.sh / macos_relay.sh; guide: docs/RELAY_KIT.md). Installed as
# /usr/local/bin/raven-relay (Linux) or ~/.local/bin/raven-relay (macOS).
#
#   raven-relay card                  the via= lines and the `raven relay use` line for friends
#   raven-relay allow <PeerId>        let a friend use the relay (their `raven whoami --peer-id`)
#   raven-relay allow --card '<card>' the same from a lab card that names a PeerId
#   raven-relay allow --cards FILE    several lab cards at once (all or nothing)
#   raven-relay deny <PeerId>         stop letting one use it
#   raven-relay status                allow-list (PeerIds, labels), the relay's addresses, state, counts
#   raven-relay logs                  the relay's last log lines (counts only)
#   raven-relay probe <via>...        from OUTSIDE your network: do the addresses answer?
#
# allow/deny/status/card are `raven --data-dir <relay folder> relay ...`, run
# as the account the relay runs as (Linux: raven-relay, through sudo), so the
# allow-list stays readable by the relay. POSIX sh; settings come from the
# kit's kit.conf, parsed (never sourced).
set -eu

# The installer writes its kit.conf path into the next line.
KIT_CONF=''

die() {
  echo "raven-relay: $1" >&2
  exit "${2:-1}"
}

usage() {
  cat <<'EOF'
raven-relay card                  the via= lines and the `raven relay use` line for friends
raven-relay allow <PeerId>        let a friend use the relay (their `raven whoami --peer-id`)
raven-relay allow --card '<card>' the same from a lab card that names a PeerId
raven-relay allow --cards FILE    several lab cards at once (all or nothing)
raven-relay deny <PeerId>         stop letting one use it
raven-relay status                allow-list (PeerIds, labels), the relay's addresses, state, counts
raven-relay logs                  the relay's last log lines (counts only)
raven-relay probe <via>...        from OUTSIDE your network: do the addresses answer?
Guide: docs/RELAY_KIT.md
EOF
}

if [ -z "$KIT_CONF" ]; then
  for c in /usr/local/lib/raven-relay/kit.conf "${HOME:-/nonexistent}/.local/lib/raven-relay/kit.conf"; do
    if [ -f "$c" ]; then
      KIT_CONF=$c
      break
    fi
  done
fi
[ -n "$KIT_CONF" ] && [ -f "$KIT_CONF" ] || die "no relay kit here (kit.conf not found): install one with node/scripts/install/linux_relay.sh or macos_relay.sh"

DIR=''
BIN=''
RUSER=''
SYSTEM=0
n=0
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  case $line in
    '#'* | '') continue ;;
    RAVEN_RELAY_DIR=*) DIR=${line#*=} ;;
    RAVEN_RELAY_BIN_DIR=*) BIN=${line#*=} ;;
    RAVEN_RELAY_USER=*) RUSER=${line#*=} ;;
    RAVEN_RELAY_SYSTEM=*) SYSTEM=${line#*=} ;;
    RAVEN_RELAY_[A-Z0-9_]*=*) ;;
    *) die "$KIT_CONF line $n: not a RAVEN_RELAY_KEY=value line" ;;
  esac
done <"$KIT_CONF"
for v in "$DIR" "$BIN"; do
  case $v in
    /*) ;;
    *) die "$KIT_CONF: RAVEN_RELAY_DIR and RAVEN_RELAY_BIN_DIR must be absolute paths" ;;
  esac
  case $v in
    *[!A-Za-z0-9._/\ -]*) die "$KIT_CONF: bad folder name $v" ;;
  esac
done
case $RUSER in
  '') ;;
  [a-z_]*[!a-z0-9_-]* | [!a-z_]*) die "$KIT_CONF: bad RAVEN_RELAY_USER" ;;
esac
case $SYSTEM in
  0 | 1) ;;
  *) die "$KIT_CONF: bad RAVEN_RELAY_SYSTEM" ;;
esac

[ $# -gt 0 ] || {
  usage
  exit 2
}
cmd=$1

case $cmd in
  -h | --help | help)
    usage
    exit 0
    ;;
  probe)
    # From outside: as the caller, no account switch (a throwaway key, nothing
    # reserved; prints ports only).
    shift
    exec "$BIN/raven-node" relay-probe "$@"
    ;;
  allow | deny | status | card | logs) ;;
  *) die "unknown command '$cmd' (raven-relay help)" 2 ;;
esac

# Linux: the relay's own account runs the relay commands. Anyone else goes
# through sudo first; root switches with runuser (sudo -u without it).
me=$(id -un)
if [ -n "$RUSER" ] && [ "$me" != "$RUSER" ] && [ "$(id -u)" -ne 0 ]; then
  exec sudo -- "$0" "$@"
fi

# Run `raven --data-dir DIR relay ARGS...` as the relay's account.
run_cli() {
  if [ -n "$RUSER" ] && [ "$me" != "$RUSER" ]; then
    if command -v runuser >/dev/null 2>&1; then
      runuser -u "$RUSER" -- env -i HOME="$DIR" PATH=/usr/bin:/bin TERM="${TERM:-dumb}" NO_COLOR="${NO_COLOR:-}" \
        "$BIN/raven" --data-dir "$DIR" relay "$@"
    else
      sudo -u "$RUSER" -- env -i HOME="$DIR" PATH=/usr/bin:/bin TERM="${TERM:-dumb}" NO_COLOR="${NO_COLOR:-}" \
        "$BIN/raven" --data-dir "$DIR" relay "$@"
    fi
  else
    "$BIN/raven" --data-dir "$DIR" relay "$@"
  fi
}

# A cards file is read by the relay's account, which cannot read your home:
# copy it into the relay folder first (Linux, as root); the copies go at exit.
cleanup() {
  rm -f "$DIR"/.raven-relay-cards."$$".*
}
copy_for_relay() {
  c="$DIR/.raven-relay-cards.$$.$1"
  install -o "$RUSER" -g "$RUSER" -m 600 "$2" "$c" || die "cannot copy $2 for the relay"
  printf '%s' "$c"
}

case $cmd in
  allow)
    if [ -n "$RUSER" ] && [ "$me" != "$RUSER" ]; then
      trap cleanup EXIT
      # Rebuild the arguments: each FILE after --card / --cards becomes a copy.
      i=0
      count=$#
      file_next=0
      while [ "$i" -lt "$count" ]; do
        a=$1
        shift
        i=$((i + 1))
        if [ "$file_next" -eq 1 ] && [ -f "$a" ]; then
          a=$(copy_for_relay "$i" "$a")
        fi
        file_next=0
        case $a in
          --card | --cards) file_next=1 ;;
          --card=* | --cards=*)
            v=${a#*=}
            if [ -f "$v" ]; then
              a="${a%%=*}=$(copy_for_relay "$i" "$v")"
            fi
            ;;
        esac
        set -- "$@" "$a"
      done
    fi
    run_cli "$@"
    ;;
  deny | card)
    shift
    run_cli "$cmd" "$@"
    ;;
  status)
    shift
    run_cli status "$@"
    echo
    if command -v systemctl >/dev/null 2>&1 && [ -n "$RUSER" ]; then
      # Counts only: state, restarts, bytes in and out, memory.
      systemctl show raven-relay -p ActiveState -p NRestarts -p IPIngressBytes -p IPEgressBytes -p MemoryCurrent || true
    elif command -v launchctl >/dev/null 2>&1; then
      if [ "$SYSTEM" = 1 ]; then
        domain=system
      else
        domain="gui/$(id -u)"
      fi
      # Its top-level lines only (one leading tab): state, runs, last exit code.
      launchctl print "$domain/com.raven.relay" 2>/dev/null \
        | sed -E -n 's/^[[:space:]](state|runs|last exit code) = (.*)$/launchd_\1=\2/p' \
        | sed 's/^launchd_last exit code=/launchd_last_exit_code=/' || true
    fi
    ;;
  logs)
    if command -v journalctl >/dev/null 2>&1 && [ -n "$RUSER" ]; then
      journalctl -u raven-relay -n 100 --no-pager
    elif [ -f "$DIR/relay.log" ]; then
      tail -n 100 "$DIR/relay.log"
    else
      die "no relay log found (macOS: $DIR/relay.log)"
    fi
    ;;
esac
