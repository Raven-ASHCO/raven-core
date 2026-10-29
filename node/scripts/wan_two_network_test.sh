#!/usr/bin/env bash
# Two-network test kit (R7a/R7b/R8 evidence, and the Phase 1 real rows R3, R5,
# R9 and R14): Raven over the Internet carriers between machines on DIFFERENT
# networks, without flipping any production gate. Debug build + the lab unlock
# (RAVEN_LAB_TEST_A=1) open Internet direct and p2p for this test only; release
# builds ignore the unlock.
#
# Two-node mode. Run the same steps on both machines (A and B), in a test
# profile that is not your real ~/.raven:
#
#   node/scripts/wan_two_network_test.sh setup NAME [PUBLIC_IP]
#       build, create the test identity, enable Internet direct (7422) and p2p
#       (7423, UPnP on), start raven-node, print this machine's card.
#   node/scripts/wan_two_network_test.sh add 'raven-card/…' TAG FINGERPRINT
#       add the other machine's card as a VERIFIED contact (compare the
#       fingerprint with what the other screen shows).
#   node/scripts/wan_two_network_test.sh send TAG [auto|internet|p2p] [COUNT]
#       send COUNT numbered messages and print each outcome.
#   node/scripts/wan_two_network_test.sh addr TAG --lan IP:PORT | --internet IP:PORT
#                                            | --via MULTIADDR | --clear lan|internet
#       change how this machine reaches the contact TAG.
#   node/scripts/wan_two_network_test.sh card
#       print this machine's card and fingerprint again.
#   node/scripts/wan_two_network_test.sh report [ROW]
#       write wan-report-NAME[-ROW]-<UTC>.txt (status, outbox, inbox, node log,
#       NAT facts, three-node runs) for the analysis. It contains public keys,
#       addresses and test texts, never a private key: redact the public IPs
#       before sharing it.
#   node/scripts/wan_two_network_test.sh stop
#
# Friend custody over the internet (Phase 3 item 3, owner rows R10/R10b; held
# by FRIEND_CUSTODY_PRODUCTION_ENABLED=false and FRIEND_CUSTODY_WAN_ENABLED=
# false: every two-node command here runs with the debug switches
# RAVEN_LAB_CUSTODY_WAN=1 and RAVEN_LAB_ROUTE_HINTS=1, custodians ride route
# hints):
#   node/scripts/wan_two_network_test.sh custodian on|off
#       hold sealed mail for your verified contacts (`ash node custody on
#       --yes`; the custodian's profile) or stop taking new mail, then
#       restart raven-node so its route hints carry the offer.
#   node/scripts/wan_two_network_test.sh mailbox on
#       use friends as mailboxes (`ash custody use on --yes`): leave sealed
#       copies with a friend who offers, and collect your own mail there.
#   node/scripts/wan_two_network_test.sh wait-held TAG [SECS]
#       wait (default 120 s) until `ash outbox list` says a friend holds what
#       waits for TAG ('held by').
#   node/scripts/wan_two_network_test.sh hand-off TAG
#       leave what waits for TAG with a friend now (`ash outbox hand-off`).
#   node/scripts/wan_two_network_test.sh custody-status
#       counts only: mailbox choice, mail friends, offers, what this machine
#       holds for others, items held by friends.
#
# Friend relays (Phase 2, held by FRIEND_RELAY_PRODUCTION_ENABLED=false: these
# commands turn on the debug switches RAVEN_LAB_FRIEND_RELAY=1 and
# RAVEN_LAB_ROUTE_HINTS=1 for this test home, and every later command here
# keeps them):
#   node/scripts/wan_two_network_test.sh friend-host [PUBLIC_IP]   (reachable machine)
#       relay for your verified contacts with this profile's OWN relay key
#       (never your Raven PeerId) on FRIEND_PORT (7427, TCP and UDP):
#       `ash relay offer on` (naming PUBLIC_IP:7427 when the address is known:
#       the argument, or setup's PUBLIC_IP), restart raven-node, wait for the
#       friend relay's `up` line, then print `ash relay card` (the friend
#       relay's own key) and the router forward for 7427. Contacts learn the
#       relay from your route hints: nobody needs a new card.
#   node/scripts/wan_two_network_test.sh friend-use TAG       (machine behind NAT)
#       no relay set by hand at all (the saved ones are cleared): raven-node
#       picks relays from what contacts offer. Restart, send TAG one message
#       (its route hints bring the offer back) and wait up to 60 s for `ash
#       doctor` to show a relay_N_source=offer slot, reserved. Between these
#       two machines a message rides a direct connection or the host's own
#       connection (connection reversal): the host's relay admits its
#       contacts, not the host itself, so this is no three-node proof (the
#       rows with two more operators are: friend-sleep).
#   node/scripts/wan_two_network_test.sh friend-sleep
#       print the R13 steps: a friend relay's laptop lid closed, with two
#       other operators; delivery continues and nothing thrashes after it
#       wakes.
#   node/scripts/wan_two_network_test.sh friend-dry-run
#       friend-host and friend-use on this one machine, on loopback, each in a
#       test home of its own: the user's relay is the host's, picked from its
#       offer and reserved. Not a WAN claim.
#
# Three-node mode: a true circuit. R relays between A and B; the sender is not
# the relay and has no connection to the recipient before it sends. The rows
# R3, R5, R9 and R14 are run step by step from an unpublished test checklist.
# On the relay machine R (for example a VPS with a public IPv4; debug build):
#   vps-relay start HOST [--kit]
#                              start a dedicated relay in its own folder
#                              (BASE/relay3, not a profile) on RELAY_PORT, naming
#                              HOST (this machine's public IP or DNS name), and
#                              print the VIA for A, B and S. --kit (Linux):
#                              install the relay kit's system unit instead
#                              (node/scripts/install/linux_relay.sh with the lab
#                              unlock: TCP+QUIC RELAY_PORT and TCP 443; it asks
#                              for sudo), so R8, R18 and R19 run on the real
#                              unit; allow, status, card and report then go
#                              through `sudo raven-relay`
#   vps-relay allow CARD [LABEL]
#                              let a node use R (its card's p2p=). Run it for A
#                              AND B: R relays only between peers on its list
#                              (its circle); for R14 also for the stranger S
#   vps-relay status           allow-list and counts (reservations, circuits)
#   vps-relay card             the relay's via= lines and the `raven relay use`
#                              line for friends
#   vps-relay probe IP PORT [VIA...]
#                              does IP:PORT accept TCP from here? (R3: with the
#                              home forward removed it must be UNREACHABLE);
#                              each VIA (or `probe VIA...` alone): does it answer
#                              as the relay it names (raven-node relay-probe:
#                              ports only, nothing reserved)
#   vps-relay report ROW       write relay3-report-ROW-<UTC>.txt
#   vps-relay stop             (--kit: stops the unit; the line it prints
#                              uninstalls it)
# For R8 on A (443-only egress):
#   egress443 print [RESOLVER] print the egress filter (only TCP 443 out, and DNS
#                              to RESOLVER) for macOS pf and Linux nftables, with
#                              the commands to apply and remove it. Printed
#                              only, never applied
# On A and B:
#   three setup NAME VIA       build, create the test identity, Internet direct
#                              off, LAN on loopback only, p2p listening on
#                              P2P_PORT with a reservation on VIA and no UPnP (no
#                              side path); print the card (via=R only) and the
#                              fingerprint, then wait up to 180 s for R to accept
#                              the reservation (run `vps-relay allow` meanwhile)
#   three add CARD TAG FINGERPRINT
#                              add the other node's card as a VERIFIED contact
#                              with no LAN or Internet route; refuses (exit 2)
#                              unless TAG is reached only through relays (a via=
#                              naming the contact itself is a direct address)
#   three send TAG [COUNT]     restart this node (no prior connection to TAG),
#                              then send COUNT (default 10) messages with
#                              --carrier p2p: outcome, path= label and seconds per
#                              message go to three-TAG-<UTC>.tsv; queued ones are
#                              awaited up to 120 s
#   three rate TAG [SESSIONS]  how often DCUtR upgrades a fresh session (default
#                              5): restart, send, wait 30 s for an upgrade, send
#   three stranger CARD FINGERPRINT
#                              R14: a stranger profile S (BASE/stranger, no relay
#                              of its own) pins B's card; B does not know S.
#                              Prints S's card (R must allow it) and the capture
#                              commands, then sends one probe, which B's peer
#                              gate must refuse before any Raven link
#   three stop
#   three-dry-run              all of the above on this one machine, on loopback:
#                              R, A, B and S in a fresh temp folder; 3/3 delivered
#                              path=relayed and the stranger refused. Not a WAN
#                              claim.
#
# Environment:
#   RAVEN_WAN_HOME             test profiles (default ~/raven-wan-test); never ~/.raven
#   RAVEN_WAN_BIN              ash + raven-node (default $CARGO_TARGET_DIR/debug,
#                              else node/target/debug)
#   RAVEN_WAN_LAN_PORT, RAVEN_WAN_INET_PORT, RAVEN_WAN_P2P_PORT
#                              7420, 7422, 7423
#   RAVEN_WAN_RELAY_PORT       the relay's port (default 7423; 7424 when it shares a
#                              machine with a service, e.g. an always-on desktop)
#   RAVEN_WAN_RELAY_TRANSPORT  quic (default) or tcp: the VIA vps-relay gives out.
#                              tcp where a network blocks UDP; record which
#   RAVEN_WAN_FRIEND_PORT      the friend relay's port (default 7427)
#   RAVEN_WAN_BIND             listen on this IP only (p2p, relay, stranger), e.g.
#                              127.0.0.1 as the dry run does; default every interface
#   RAVEN_WAN_SKIP_BUILD=1     use the binaries as they are
#   RAVEN_WAN_DRY_DIR          a dry run's folder (must be empty; default a new
#                              mktemp -d folder, kept afterwards)
#
# Nothing here touches ~/.raven or any real contact.
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$ROOT/target}"
[[ "$target_dir" == /* ]] || target_dir="$ROOT/$target_dir"
BIN="${RAVEN_WAN_BIN:-$target_dir/debug}"
BASE="${RAVEN_WAN_HOME:-$HOME/raven-wan-test}"
LAN_PORT="${RAVEN_WAN_LAN_PORT:-7420}"
INET_PORT="${RAVEN_WAN_INET_PORT:-7422}"
P2P_PORT="${RAVEN_WAN_P2P_PORT:-7423}"
RELAY_PORT="${RAVEN_WAN_RELAY_PORT:-7423}"
RELAY_TRANSPORT="${RAVEN_WAN_RELAY_TRANSPORT:-quic}"
FRIEND_PORT="${RAVEN_WAN_FRIEND_PORT:-7427}"
BIND="${RAVEN_WAN_BIND:-}"
export RAVEN_LAB_TEST_A=1
# Friend custody over the internet and the route hints it rides (Phase 3
# item 3; both held in release builds). Three-node mode (three, vps-relay)
# keeps route hints off: its cards must stay raven-card/2 with via= (the
# relay-only check), as the rows R3, R5, R9 and R14 were defined.
export RAVEN_LAB_CUSTODY_WAN=1
case "${1:-}" in
  three | three-dry-run | vps-relay) unset RAVEN_LAB_ROUTE_HINTS ;;
  *) export RAVEN_LAB_ROUTE_HINTS=1 ;;
esac
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file
export RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
# Plain output: the outcomes and path= labels below are read from it.
export NO_COLOR=1
# Debug-only switches never apply to a real row: one widens the hole-punch
# candidates to loopback / private addresses, another drops the listener.
# Service settings come from the profile, not from this shell.
# So do the friend relay's loopback listener and fast relay-choice timers
# (R13 measures the real ones) and the profile-key relay, and friend
# custody's fast timers and old-build pretence (R10 measures the real ones).
unset RAVEN_LAB_P2P_LOCAL_CANDIDATES RAVEN_LAB_P2P_RELAY_ONLY RAVEN_LAB_P2P_PING \
  RAVEN_LAB_NETWATCH_EVENTS RAVEN_LAB_NET_TAG RAVEN_P2P_LISTEN RAVEN_P2P_RELAYS \
  RAVEN_P2P_RELAY RAVEN_INTERNET_LISTEN RAVEN_LAB_FRIEND_RELAY_LISTEN \
  RAVEN_LAB_RELAY_SELECT RAVEN_LAB_P2P_PROFILE_RELAY RAVEN_LAB_CUSTODY_AFTER_MS \
  RAVEN_LAB_CUSTODY_FETCH_MS RAVEN_LAB_CUSTODY_PRETEND_OLD \
  RAVEN_LAB_CUSTODY_BASE_OPS_ONLY RAVEN_LAB_CUSTODY_HANDOFF RAVEN_LAB_CUSTODY_FORWARD_MS
# A loopback dry run (friend-dry-run) only: loopback addresses may be offered
# and dialled, and the friend relay listens on RAVEN_WAN_BIND alone.
if [[ "${RAVEN_WAN_DRY_LOOPBACK:-0}" == "1" ]]; then
  export RAVEN_LAB_P2P_LOCAL_CANDIDATES=1
  export RAVEN_LAB_FRIEND_RELAY_LISTEN="${BIND:-127.0.0.1}:$FRIEND_PORT"
fi
# A test home that runs friend relays (friend-host / friend-use) keeps their
# switches for every command.
if [[ -f "$BASE/.friend" ]]; then
  export RAVEN_LAB_FRIEND_RELAY=1 RAVEN_LAB_ROUTE_HINTS=1
fi
case "$RELAY_TRANSPORT" in
  quic | tcp) ;;
  *)
    echo "RAVEN_WAN_RELAY_TRANSPORT must be quic or tcp, not '$RELAY_TRANSPORT'" >&2
    exit 2
    ;;
esac

LINE_HOST_UP='raven-node p2p: host up'
LINE_RESERVED='raven-node p2p: reservation accepted'
LINE_GATE='raven-node p2p: peer gate reloaded'
LINE_GATE_REFUSED='raven-node p2p: refused a connection from a peer that is not a verified contact'
LINE_DCUTR='raven-node p2p: direct connection upgraded (dcutr)'
LINE_PUNCH_FAILED='raven-node p2p: hole punch failed'
LINE_RELAY_UP='raven-node relay: up'
LINE_FRIEND_UP='raven-node friend relay: up'
HINT_NODE_REFUSED="the contact's node refused the p2p connection at once"
HINT_RELAY_REFUSED="the contact's relay refused this node"
# A human runs `vps-relay allow` while this waits; the reservation is retried
# with a backoff that grows to 60 s.
RESERVE_WAIT=180
QUEUED_WAIT=120
UPGRADE_WAIT=30

name_file="$BASE/.name"
RELAY_DIR="$BASE/relay3"
STRANGER_DIR="$BASE/stranger"
dir_for() { printf '%s/%s' "$BASE" "$1"; }
current() {
  [[ -f "$name_file" ]] || { echo "run setup first" >&2; exit 2; }
  cat "$name_file"
}
ash() { "$BIN/ash" --data-dir "$(dir_for "$(current)")" "$@"; }
ash_in() {
  local d=$1
  shift
  "$BIN/ash" --data-dir "$d" "$@"
}
build_bins() {
  if [[ "${RAVEN_WAN_SKIP_BUILD:-0}" != "1" ]]; then
    (cd "$ROOT" && cargo build --locked -q -p ash -p raven-node)
  fi
}
init_profile() {
  if [[ ! -f "$1/identity.seed" ]]; then
    mkdir -p "$1"
    chmod 700 "$1"
    "$BIN/ash" --data-dir "$1" init >/dev/null
    "$BIN/ash" --data-dir "$1" prekey publish >/dev/null
  fi
}
# listen_on PORT: PORT on every interface, or RAVEN_WAN_BIND:PORT.
listen_on() {
  if [[ -n "$BIND" ]]; then
    printf '%s:%s' "$BIND" "$1"
  else
    printf '%s' "$1"
  fi
}
utc() { date -u +%Y%m%dT%H%M%SZ; }
now_ms() { python3 -I -c 'import time; print(int(time.time() * 1000))'; }
log_size() {
  if [[ -f "$1" ]]; then
    wc -c <"$1" | tr -d ' '
  else
    echo 0
  fi
}
# log_count FILE TEXT [FROM]: lines with TEXT after byte FROM.
log_count() {
  if [[ -f "$1" ]]; then
    tail -c "+$((${3:-0} + 1))" "$1" | grep -cF -- "$2" || true
  else
    echo 0
  fi
}
# wait_log FILE TEXT SECS [FROM]: TEXT shows up in FILE after byte FROM
# within SECS (a deadline loop instead of a guess at how long startup takes).
wait_log() {
  local file=$1 text=$2 deadline=$((SECONDS + $3)) from=${4:-0}
  while :; do
    if [[ -f "$file" ]] && tail -c "+$((from + 1))" "$file" | grep -F -- "$text" >/dev/null; then
      return 0
    fi
    ((SECONDS < deadline)) || return 1
    sleep 0.5
  done
}
# with_timeout SECS CMD...: `timeout` where there is one (Linux), else perl's
# alarm (macOS has no timeout).
with_timeout() {
  local secs=$1
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  else
    perl -e 'alarm shift; exec @ARGV or exit 127' "$secs" "$@"
  fi
}
# stop_pid PIDFILE DIR: stop the process PIDFILE names (only a raven-node of
# DIR: a stale pid that now belongs to something else is left alone) and wait
# up to 10 s for it to go.
stop_pid() {
  local pid deadline=$((SECONDS + 10))
  [[ -f "$1" ]] || return 0
  pid="$(cat "$1")"
  if kill -0 "$pid" 2>/dev/null \
    && ps -ww -p "$pid" -o command= 2>/dev/null | grep -F -- "--data-dir $2" >/dev/null; then
    kill "$pid" 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null; do
      if ((SECONDS >= deadline)); then
        kill -9 "$pid" 2>/dev/null || true
        break
      fi
      sleep 0.2
    done
  fi
  rm -f "$1"
}
# (Re)start raven-node; extra service flags (e.g. --relay) live in service.flags,
# a LAN listen address other than 0.0.0.0:LAN_PORT in lan.listen (three-node
# mode: loopback only). It is up once it answers on its IPC socket.
# NODE_LOG_FROM: where this start's lines begin in node.log.
NODE_LOG_FROM=0
start_node() {
  local D="$1" flags=() lan="0.0.0.0:$LAN_PORT" pid deadline=$((SECONDS + 30))
  stop_pid "$D/node.pid" "$D"
  if [[ -f "$D/service.flags" ]]; then
    read -r -a flags <"$D/service.flags"
  fi
  if [[ -f "$D/lan.listen" ]]; then
    lan="$(cat "$D/lan.listen")"
  fi
  NODE_LOG_FROM="$(log_size "$D/node.log")"
  nohup "$BIN/raven-node" service --data-dir "$D" --lan-listen "$lan" \
    --ble-listen 127.0.0.1:0 ${flags[@]+"${flags[@]}"} >>"$D/node.log" 2>&1 &
  pid=$!
  echo "$pid" >"$D/node.pid"
  until "$BIN/ash" --data-dir "$D" ipc-ping >/dev/null 2>&1; do
    if ! kill -0 "$pid" 2>/dev/null || ((SECONDS >= deadline)); then
      echo "raven-node in $D did not come up:" >&2
      tail -c "+$((NODE_LOG_FROM + 1))" "$D/node.log" | tail -n 20 >&2
      exit 1
    fi
    sleep 0.3
  done
}
node_running() {
  [[ -f "$1/node.pid" ]] && kill -0 "$(cat "$1/node.pid")" 2>/dev/null
}
# restart_reserved DIR: restart the node (it then has no connection to anyone
# but its relay) and wait for its reservation on R.
restart_reserved() {
  start_node "$1"
  if ! wait_log "$1/node.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$NODE_LOG_FROM"; then
    echo "no reservation on R within ${RESERVE_WAIT}s: is R up, and this node on its allow-list (vps-relay allow)?" >&2
    tail -c "+$((NODE_LOG_FROM + 1))" "$1/node.log" | grep -E "p2p|relay|reserv" | tail -n 6 >&2 || true
    exit 1
  fi
}

# relay_only DIR TAG: in DIR's contact book, TAG is reached only through
# relays: a p2p= PeerId and via= addresses none of which names the contact
# itself (that would be its own direct address), and no LAN or Internet
# route. Exit 2 otherwise.
relay_only() {
  python3 -I - "$1/contacts.json" "$2" <<'PY'
import json
import sys

path, tag = sys.argv[1], sys.argv[2]


def refuse(why):
    print(f"relay-only check: @{tag}: {why}", file=sys.stderr)
    sys.exit(2)


try:
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
except (OSError, ValueError) as e:
    refuse(f"cannot read the contact book ({e})")
rows = [r for r in rows if isinstance(r, dict) and tag in (r.get("petname"), r.get("public_tag"))]
if not rows:
    refuse("no such contact")
for r in rows:
    peer = r.get("p2p") or ""
    vias = r.get("p2p_via") or []
    if not peer:
        refuse("no p2p= PeerId (add the contact's raven-card/2)")
    if not vias:
        refuse("no via= (the card must name the relay)")
    for via in vias:
        parts = via.split("/")
        named = [parts[i + 1] for i, p in enumerate(parts[:-1]) if p == "p2p"]
        if peer in named:
            refuse(f"a via= names the contact itself, a direct address, not a relay: {via}")
    if r.get("lan_dial") or r.get("internet_dial"):
        refuse("has a LAN or Internet route (three-node mode clears both)")
print(f"relay-only: @{tag} is reached through {len(vias)} relay via= only, no LAN or Internet route")
PY
}

# send_p2p DIR TAG TEXT: one verbose `ash send --carrier p2p`. Sets SEND_OUT,
# SEND_STATUS (delivered | queued | other), SEND_PATH (the path= label: direct,
# reversed, relayed or hole_punched), SEND_MID, SEND_T0 (ms) and SEND_SECS.
send_p2p() {
  local t1 line
  SEND_T0="$(now_ms)"
  SEND_OUT="$(printf '%s\n' "$3" | RAVEN_VERBOSE=1 "$BIN/ash" --data-dir "$1" send \
    --contact "@$2" --carrier p2p 2>&1)" || true
  t1="$(now_ms)"
  SEND_SECS="$(secs_since "$SEND_T0" "$t1")"
  SEND_STATUS=other
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in
      "status delivered"*"confirmed receipt"*)
        SEND_STATUS=delivered
        break
        ;;
      "not delivered yet"*) SEND_STATUS=queued ;;
    esac
  done <<<"$SEND_OUT"
  SEND_PATH="$(grep -oE ' path=[a-z_]+' <<<"$SEND_OUT" | tail -n 1 | cut -d= -f2 || true)"
  SEND_MID="$(grep -oE 'mid=[0-9a-f]{8}' <<<"$SEND_OUT" | head -n 1 | cut -d= -f2 || true)"
  if [[ -z "$SEND_MID" ]]; then
    SEND_MID="$(grep -oE 'message [0-9a-f]{8}' <<<"$SEND_OUT" | head -n 1 | cut -d' ' -f2 || true)"
  fi
}
# secs_since T0_MS T1_MS: seconds with one decimal.
secs_since() {
  local ms=$(($2 - $1))
  printf '%d.%d' $((ms / 1000)) $((ms % 1000 / 100))
}
# outbox_field DIR MID KEY: one row of `ash outbox status MID` (state, path).
outbox_field() {
  ash_in "$1" outbox status "$2" </dev/null 2>/dev/null | awk -v k="$3" '$1 == k { print $2; exit }' \
    || true
}

# summarize TSV: delivered x/n, the path labels, median and max seconds.
summarize() {
  python3 -I - "$1" <<'PY'
import statistics
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    rows = [line.rstrip("\n").split("\t") for line in f][1:]
sent = [r for r in rows if "->" not in r[2]]
done = [r for r in rows if r[2] in ("delivered", "queued->delivered")]
paths = {}
for r in done:
    paths[r[3]] = paths.get(r[3], 0) + 1
secs = [float(r[4]) for r in done]
labels = ", ".join(f"{k} {v}" for k, v in sorted(paths.items())) or "none"
timing = f"; seconds median {statistics.median(secs):.1f}, max {max(secs):.1f}" if secs else ""
print(f"delivered {len(done)}/{len(sent)}; paths: {labels}{timing}")
PY
}
# path_counts DIR: the path= labels of every three-node TSV in DIR.
path_counts() {
  python3 -I - "$1" <<'PY'
import glob
import os
import sys

counts = {}
for name in sorted(glob.glob(os.path.join(sys.argv[1], "three-*.tsv"))):
    with open(name, encoding="utf-8") as f:
        lines = [line.rstrip("\n").split("\t") for line in f]
    head = lines[0] if lines else []
    cols = [i for i, h in enumerate(head) if h in ("path", "first_path", "second_path")]
    for row in lines[1:]:
        for i in cols:
            if i < len(row) and row[i] != "-":
                counts[row[i]] = counts.get(row[i], 0) + 1
print(", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "no three-node sends yet")
PY
}

# host_ma HOST: the multiaddr prefix of an IPv4 / IPv6 address or DNS name.
host_ma() {
  local h="${1#\[}"
  h="${h%\]}"
  if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf '/ip4/%s' "$h"
  elif [[ "$h" == *:* ]]; then
    printf '/ip6/%s' "$h"
  else
    printf '/dns/%s' "$h"
  fi
}

# kit_mode: the relay is the relay kit's system unit (`vps-relay start HOST
# --kit`), driven through `sudo raven-relay`.
kit_mode() { [[ -f "$RELAY_DIR/kit" ]]; }
# relay_cli ARGS...: `raven relay ARGS` on R, in kit mode as the relay's own
# account (sudo raven-relay ARGS).
relay_cli() {
  if kit_mode; then
    sudo raven-relay "$@"
  else
    ash_in "$RELAY_DIR" relay "$@"
  fi
}

vps_relay() {
  local sub="${1:-help}" host ma from card_lines line tcp_via="" quic_via="" via other deadline kit=0
  shift || true
  case "$sub" in
    start)
      host="${1:?vps-relay start HOST [--kit] (the public IP or DNS name of this machine)}"
      [[ "${2:-}" != "--kit" ]] || kit=1
      build_bins
      mkdir -p "$RELAY_DIR"
      chmod 700 "$RELAY_DIR"
      ma="$(host_ma "$host")"
      stop_pid "$RELAY_DIR/relay.pid" "$RELAY_DIR"
      if [[ "$kit" == 1 ]]; then
        # The relay kit's hardened system unit (docs/RELAY_KIT.md) on this
        # debug build with the lab unlock: TCP+QUIC RELAY_PORT and TCP 443.
        if [[ "$(uname -s)" != Linux ]]; then
          echo "--kit installs the Linux relay kit (systemd); on macOS run node/scripts/install/macos_relay.sh" >&2
          exit 2
        fi
        RAVEN_RELAY_LAB=1 RAVEN_RELAY_HOST="$host" RAVEN_RELAY_PORT="$RELAY_PORT" \
          RAVEN_RELAY_PREBUILT="$BIN" bash "$ROOT/scripts/install/linux_relay.sh"
        : >"$RELAY_DIR/kit"
      else
        rm -f "$RELAY_DIR/kit"
        from="$(log_size "$RELAY_DIR/relay.log")"
        nohup "$BIN/raven-node" relay --data-dir "$RELAY_DIR" --listen "$(listen_on "$RELAY_PORT")" \
          --external "$ma/tcp/$RELAY_PORT" --external "$ma/udp/$RELAY_PORT/quic-v1" \
          >>"$RELAY_DIR/relay.log" 2>&1 &
        echo "$!" >"$RELAY_DIR/relay.pid"
        if ! wait_log "$RELAY_DIR/relay.log" "$LINE_RELAY_UP" 30 "$from"; then
          echo "the relay did not come up:" >&2
          tail -c "+$((from + 1))" "$RELAY_DIR/relay.log" | tail -n 20 >&2
          exit 1
        fi
      fi
      # `relay card` reads the PeerId from relay_status.json (written within
      # seconds of the start). The kit's card names its own addresses (TCP,
      # TCP 443, QUIC); this relay's the host given here.
      deadline=$((SECONDS + 30))
      if [[ "$kit" == 1 ]]; then
        until card_lines="$(relay_cli card 2>/dev/null)" && [[ -n "$card_lines" ]]; do
          if ((SECONDS >= deadline)); then
            echo "the kit's relay gave no card within 30 s (sudo raven-relay status)" >&2
            exit 1
          fi
          sleep 0.5
        done
      else
        until card_lines="$(ash_in "$RELAY_DIR" relay card --host "$host" --port "$RELAY_PORT" --quic 2>/dev/null)"; do
          if ((SECONDS >= deadline)); then
            echo "the relay wrote no relay_status.json within 30 s" >&2
            exit 1
          fi
          sleep 0.5
        done
      fi
      while IFS= read -r line; do
        case "$line" in
          via=*/quic-v1/*) quic_via="${line#via=}" ;;
          via=*/tcp/443/*) ;;
          via=*/tcp/*) tcp_via="${line#via=}" ;;
        esac
      done <<<"$card_lines"
      if [[ "$RELAY_TRANSPORT" == quic ]]; then
        via="$quic_via" other="tcp: $tcp_via"
      else
        via="$tcp_via" other="quic: $quic_via"
      fi
      printf '%s\n' "$via" >"$RELAY_DIR/via"
      echo "=== relay up ($RELAY_TRANSPORT): on A and B run   three setup NAME '$via'"
      echo "(the other transport, $other)"
      if [[ "$kit" == 1 ]]; then
        echo "(the kit's card, with its TCP 443 line: vps-relay card)"
      fi
      echo "then here, for each card they print:   vps-relay allow '<card>'"
      ;;
    allow)
      [[ -d "$RELAY_DIR" ]] || { echo "start the relay first: vps-relay start HOST" >&2; exit 2; }
      relay_cli allow --card "${1:?vps-relay allow CARD [LABEL]}" --label "${2:-}"
      ;;
    status)
      relay_cli status
      ;;
    card)
      [[ -d "$RELAY_DIR" ]] || { echo "start the relay first: vps-relay start HOST" >&2; exit 2; }
      relay_cli card
      ;;
    probe)
      # From outside R's network. `probe IP PORT [VIA...]`: does IP:PORT
      # accept TCP from here; `probe VIA...` (or VIAs after IP PORT): does
      # each relay address answer as the relay it names (raven-node
      # relay-probe: a throwaway key, nothing reserved, ports only).
      local vias=()
      if [[ "${1:-}" == /* || "${1:-}" == via=* ]]; then
        vias=("$@")
      else
        local ip="${1:?vps-relay probe IP PORT [VIA...] | probe VIA...}"
        local port="${2:?vps-relay probe IP PORT [VIA...] | probe VIA...}"
        shift 2
        vias=("$@")
        # shellcheck disable=SC2016 # $0 and $1 expand in the inner bash.
        if with_timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$ip" "$port" 2>/dev/null; then
          echo "reachable: $ip:$port accepts TCP connections from here"
        else
          echo "UNREACHABLE: $ip:$port accepted no TCP connection within 5 s"
        fi
      fi
      if [[ ${#vias[@]} -gt 0 ]]; then
        build_bins
        "$BIN/raven-node" relay-probe "${vias[@]}" || true
      fi
      ;;
    report)
      local row="${1:?vps-relay report ROW}" out
      out="$PWD/relay3-report-$row-$(utc).txt"
      {
        echo "### relay for row $row  $(date -u +%FT%TZ)  $(uname -sm)  transport $RELAY_TRANSPORT$(kit_mode && echo '  (relay kit unit)')"
        echo "### via"; cat "$RELAY_DIR/via" 2>/dev/null || true
        echo "### relay status"; relay_cli status 2>&1 || true
        if kit_mode; then
          echo "### relay card"; relay_cli card 2>&1 || true
          echo
          echo "### relay log (tail)"; sudo raven-relay logs 2>&1 | tail -n 200 || true
        else
          echo "### relay_status.json"; cat "$RELAY_DIR/relay_status.json" 2>/dev/null || true
          echo
          echo "### relay log (tail)"; tail -n 200 "$RELAY_DIR/relay.log" 2>/dev/null || true
        fi
      } >"$out"
      echo "wrote $out (it names this relay's public address: redact before sharing)"
      ;;
    stop)
      if kit_mode; then
        sudo systemctl stop raven-relay
        echo "relay kit unit stopped (it starts again at boot; remove it with:" \
          "sudo env RAVEN_RELAY_UNINSTALL=1 bash $ROOT/scripts/install/linux_relay.sh)"
      else
        stop_pid "$RELAY_DIR/relay.pid" "$RELAY_DIR"
        echo "relay stopped"
      fi
      ;;
    *)
      echo "vps-relay start HOST [--kit] | allow CARD [LABEL] | status | card | probe IP PORT [VIA...] | probe VIA... | report ROW | stop" >&2
      exit 2
      ;;
  esac
}

# egress443 print [RESOLVER]: the R8 egress filter (only TCP 443 out, and DNS
# to RESOLVER), for macOS pf and for Linux nftables. Printed only, never
# applied: the operator applies one with sudo for the row and removes it
# afterwards (real row R8). The nftables rules are the
# netns only443 case's (node/scripts/netns_nat_dcutr.sh).
egress443() {
  local sub="${1:-help}" resolver family=ip
  case "$sub" in
    print)
      resolver="${2:-$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf 2>/dev/null || true)}"
      resolver="${resolver:-<your DNS resolver IP>}"
      [[ "$resolver" != *:* ]] || family=ip6
      case "$resolver" in
        127.* | ::1)
          echo "# $resolver is a local stub resolver (systemd-resolved): give the one it forwards to"
          echo "# (resolvectl dns), or a relay named by DNS cannot be resolved while the filter is on."
          ;;
      esac
      cat <<EOF
# R8 egress filter: only TCP 443 (and DNS to $resolver) leaves this machine.
# Printed only; nothing was applied. Apply ONE of the two with sudo for the
# row, check that the relay row of 'raven status' holds its reservation on
# the 443 address, and remove the filter afterwards.

# ---- macOS (pf; the default pf.conf evaluates anchors under com.apple/*) ----
# save the four rules below as /tmp/r8.pf.conf, then:
#   sudo pfctl -a com.apple/raven-r8 -f /tmp/r8.pf.conf && sudo pfctl -E   # note the token it prints
# remove afterwards:
#   sudo pfctl -a com.apple/raven-r8 -F all && sudo pfctl -X <token>
pass out quick on lo0 all
pass out quick proto tcp from any to any port 443
pass out quick proto udp from any to $resolver port 53
block drop out quick proto { tcp udp } all

# ---- Linux (nftables) ----
# save the table below as /tmp/r8.nft, then:   sudo nft -f /tmp/r8.nft
# counters while the row runs:                 sudo nft list counters table inet r443
# remove afterwards:                           sudo nft delete table inet r443
table inet r443 {
  counter tcp443 {
  }
  counter dropped {
  }
  counter tcp7423 {
  }
  counter tcp7427 {
  }
  chain out {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    tcp dport 443 counter name "tcp443" accept
    $family daddr $resolver udp dport 53 accept
    tcp dport 7423 counter name "tcp7423"
    tcp dport 7427 counter name "tcp7427"
    counter name "dropped" drop
  }
}
EOF
      ;;
    *)
      echo "egress443 print [RESOLVER]   (prints the R8 egress filter for pf and nftables; never applies it)" >&2
      exit 2
      ;;
  esac
}

three_setup() {
  local name="${1:?three setup NAME VIA}" via="${2:?three setup NAME VIA}" D
  via="${via#via=}"
  if [[ "$via" != /*/p2p/* ]]; then
    echo "VIA must be the relay's multiaddr ending in /p2p/<its PeerId> (vps-relay start prints it)" >&2
    exit 2
  fi
  mkdir -p "$BASE"
  printf '%s' "$name" >"$name_file"
  D="$(dir_for "$name")"
  build_bins
  init_profile "$D"
  # R is the only way in: no relay role, LAN on loopback only, no Internet
  # direct, no UPnP mapping. p2p always listens (a node without a listener can
  # never hole-punch), but the card names only R.
  rm -f "$D/service.flags"
  printf '%s' "$via" >"$D/three.via"
  printf '127.0.0.1:%s' "$LAN_PORT" >"$D/lan.listen"
  ash_in "$D" node internet off >/dev/null
  ash_in "$D" node p2p on --listen "$(listen_on "$P2P_PORT")" --relay "$via" --no-upnp >/dev/null
  echo "=== your card (via=R only): give it to the other machine, and to R (vps-relay allow) ==="
  ash_in "$D" whoami --card --via "$via"
  echo
  ash_in "$D" whoami | grep -i fingerprint
  start_node "$D"
  echo "=== waiting up to ${RESERVE_WAIT}s for R to accept this node (on R: vps-relay allow '<the card above>') ==="
  if ! wait_log "$D/node.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$NODE_LOG_FROM"; then
    echo "no reservation on R yet: is this node on R's allow-list? (three send waits again)" >&2
    tail -c "+$((NODE_LOG_FROM + 1))" "$D/node.log" | grep -E "p2p|relay|reserv" | tail -n 6 >&2 || true
    exit 1
  fi
  tail -c "+$((NODE_LOG_FROM + 1))" "$D/node.log" | grep -E "host up|reservation" | tail -n 4 || true
}

three_add() {
  local card="${1:?three add CARD TAG FINGERPRINT}" tag="${2:?three add CARD TAG FINGERPRINT}"
  local fp="${3:?three add CARD TAG FINGERPRINT}" D from
  D="$(dir_for "$(current)")"
  from="$(log_size "$D/node.log")"
  ash contact add --card "$card" --petname "$tag" --tag "$tag" --verify-fp "$fp"
  ash contact set-addr --tag "$tag" --clear lan --clear internet >/dev/null
  relay_only "$D" "$tag"
  # The running node's peer gate re-reads the contact book within seconds; a
  # circuit from the new contact before then is refused like a stranger's.
  if node_running "$D" && ! wait_log "$D/node.log" "$LINE_GATE" 30 "$from"; then
    echo "warning: the running node's peer gate did not reload within 30 s" >&2
  fi
}

three_send() {
  local tag="${1:?three send TAG [COUNT]}" count="${2:-10}" D tsv i text pending="" left
  local n mid t0 state path deadline
  [[ "$count" =~ ^[1-9][0-9]?$ ]] || { echo "COUNT must be 1-99" >&2; exit 2; }
  D="$(dir_for "$(current)")"
  relay_only "$D" "$tag"
  restart_reserved "$D"
  tsv="$D/three-$tag-$(utc).tsv"
  printf 'n\tutc\tstatus\tpath\tseconds\tmid\n' >"$tsv"
  for i in $(seq 1 "$count"); do
    text="three-$(current)-$tag-$i-$(date -u +%H%M%S)"
    send_p2p "$D" "$tag" "$text"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$i" "$(utc)" "$SEND_STATUS" "${SEND_PATH:--}" \
      "$SEND_SECS" "${SEND_MID:--}" >>"$tsv"
    echo "  $i/$count  $SEND_STATUS  path=${SEND_PATH:-none}  ${SEND_SECS}s"
    if [[ "$SEND_STATUS" == queued && -n "$SEND_MID" ]]; then
      pending+="$i $SEND_MID $SEND_T0"$'\n'
    elif [[ "$SEND_STATUS" == other ]]; then
      grep -vE '^[[:space:]]*$' <<<"$SEND_OUT" | tail -n 3 | sed 's/^/      /' || true
    fi
  done
  # Queued ones: the outbox keeps retrying them.
  deadline=$((SECONDS + QUEUED_WAIT))
  while [[ -n "$pending" ]]; do
    left=""
    while read -r n mid t0; do
      [[ -n "$n" ]] || continue
      state="$(outbox_field "$D" "$mid" state)"
      if [[ "$state" == delivered || ( -n "$state" && "$state" != queued && "$state" != sent \
        && "$state" != held ) || $SECONDS -ge $deadline ]]; then
        path="$(outbox_field "$D" "$mid" path)"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$(utc)" "queued->${state:-unknown}" "${path:--}" \
          "$(secs_since "$t0" "$(now_ms)")" "$mid" >>"$tsv"
        echo "  $n/$count  queued -> ${state:-unknown}  path=${path:-none}"
      else
        left+="$n $mid $t0"$'\n'
      fi
    done <<<"$pending"
    pending="$left"
    [[ -z "$pending" ]] || sleep 2
  done
  echo "=== @$tag: $(summarize "$tsv")"
  echo "    dcutr upgrades: $(log_count "$D/node.log" "$LINE_DCUTR" "$NODE_LOG_FROM"), hole punch failed: $(log_count "$D/node.log" "$LINE_PUNCH_FAILED" "$NODE_LOG_FROM") (this node's log, since the restart)"
  echo "wrote $tsv"
}

three_rate() {
  local tag="${1:?three rate TAG [SESSIONS]}" sessions="${2:-5}" D tsv s from t0 up up_s
  local st1 p1 upgrades=0
  [[ "$sessions" =~ ^[1-9][0-9]?$ ]] || { echo "SESSIONS must be 1-99" >&2; exit 2; }
  D="$(dir_for "$(current)")"
  relay_only "$D" "$tag"
  tsv="$D/three-rate-$tag-$(utc).tsv"
  printf 'session\tfirst_status\tfirst_path\tupgraded\tupgrade_s\tsecond_status\tsecond_path\n' >"$tsv"
  for s in $(seq 1 "$sessions"); do
    restart_reserved "$D"
    from="$(log_size "$D/node.log")"
    send_p2p "$D" "$tag" "rate-$(current)-$tag-s$s-1-$(date -u +%H%M%S)"
    st1="$SEND_STATUS" p1="${SEND_PATH:--}"
    t0=$SECONDS
    if wait_log "$D/node.log" "$LINE_DCUTR" "$UPGRADE_WAIT" "$from"; then
      up=yes up_s=$((SECONDS - t0))
    else
      up=no up_s=-
    fi
    send_p2p "$D" "$tag" "rate-$(current)-$tag-s$s-2-$(date -u +%H%M%S)"
    # Upgraded: this node logged it, or a message went hole-punched (the
    # other side may be the one that logs it).
    if [[ "$up" == yes || "$p1" == hole_punched || "$SEND_PATH" == hole_punched ]]; then
      upgrades=$((upgrades + 1))
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$s" "$st1" "$p1" "$up" "$up_s" "$SEND_STATUS" \
      "${SEND_PATH:--}" >>"$tsv"
    echo "  session $s/$sessions: #1 $st1 path=$p1; dcutr line within ${UPGRADE_WAIT}s: $up; #2 $SEND_STATUS path=${SEND_PATH:-none}"
  done
  echo "=== @$tag: DCUtR upgraded $upgrades of $sessions fresh sessions (this node logged it, or a message went hole_punched)"
  echo "wrote $tsv"
}

three_stranger() {
  local card="${1:?three stranger CARD FINGERPRINT}" fp="${2:?three stranger CARD FINGERPRINT}"
  local S="$STRANGER_DIR" via s_card from why
  via="$(grep -oE ' via=[^ ]+' <<<" $card" | head -n 1 | cut -d= -f2- || true)"
  [[ -n "$via" ]] || { echo "the card has no via=: B's card from three setup names R" >&2; exit 2; }
  build_bins
  init_profile "$S"
  # A profile of its own (not BASE/.name), no relay of its own, LAN on
  # loopback on any free port, p2p on any free port: it reaches B only
  # through B's relay, like any holder of B's card.
  rm -f "$S/service.flags"
  printf '127.0.0.1:0' >"$S/lan.listen"
  ash_in "$S" node internet off >/dev/null
  ash_in "$S" node p2p on --listen "$(listen_on 0)" --no-upnp >/dev/null
  ash_in "$S" contact add --card "$card" --petname target --tag target --verify-fp "$fp" >/dev/null
  ash_in "$S" contact set-addr --tag target --clear lan --clear internet >/dev/null
  relay_only "$S" target
  s_card="$(ash_in "$S" whoami --card --via "$via" | grep '^raven-card/2 ')"
  start_node "$S"
  from="$NODE_LOG_FROM"
  wait_log "$S/node.log" "$LINE_HOST_UP" 60 "$from" || { echo "S's p2p host did not start" >&2; exit 1; }
  cat <<EOF
=== R14: a stranger S (this profile) holds B's card; B does not know S ===
1. On R: vps-relay allow '$s_card'
   R relays only within its circle: without this R refuses S, and B's own
   peer gate is never asked.
2. Captures (sudo), started before the probe:
     on B:  sudo tcpdump -ni <B's WAN interface> -w r14-b.pcap host <S's public IP>
     on S:  sudo tcpdump -ni <S's interface> -w r14-s.pcap host <B's public IP>
   The interface: \`route -n get default\` (macOS) or \`ip route show default\` (Linux).
EOF
  if [[ -t 0 ]]; then
    read -r -p "3. Press Enter to send the probe. " _ || true
  fi
  send_p2p "$S" target "r14-stranger-probe-$(utc)"
  if [[ "$SEND_STATUS" == queued && -n "$SEND_MID" ]]; then
    # Not a retry later: the probe is one attempt.
    ash_in "$S" outbox cancel "$SEND_MID" --yes >/dev/null 2>&1 || true
  fi
  stop_pid "$S/node.pid" "$S"
  printf '%s\n' "$SEND_OUT" | grep -vE '^[[:space:]]*$' | tail -n 4 | sed 's/^/    /' || true
  if [[ "$SEND_STATUS" == delivered ]]; then
    echo "R14 FAIL: the stranger's probe was delivered"
    exit 1
  fi
  if grep -F LINK_NOT_ACCEPTED <<<"$SEND_OUT" >/dev/null; then
    echo "R14 FAIL: the probe reached B's Raven link (LINK_NOT_ACCEPTED): B's peer gate did not refuse it first"
    exit 1
  fi
  if [[ "$(log_count "$S/node.log" "$LINE_DCUTR" "$from")" != 0 \
    || "$(log_count "$S/node.log" "$LINE_PUNCH_FAILED" "$from")" != 0 ]]; then
    echo "R14 FAIL: S logged a hole punch: DCUtR ran on its circuit to B"
    exit 1
  fi
  if grep -F "$HINT_RELAY_REFUSED" <<<"$SEND_OUT" >/dev/null; then
    echo "R14 INCONCLUSIVE: R refused S (S is not in R's circle), so B's peer gate was never asked: vps-relay allow S's card (above) and repeat"
    exit 1
  fi
  if grep -F "$HINT_NODE_REFUSED" <<<"$SEND_OUT" >/dev/null; then
    why="B's node refused it at once"
  else
    why="S's error names no refusal: B's gate line and count below are the evidence"
  fi
  echo "R14 probe refused (expected): not delivered$([[ "$SEND_STATUS" == queued ]] && echo " (queued, cancelled)"), no Raven link, no hole punch on S; $why"
  echo "Then: on B, raven status shows p2p_gate 'refused N connection(s)' one higher and node.log the"
  echo "      line '$LINE_GATE_REFUSED'; stop both captures:"
  echo "      tcpdump -r r14-b.pcap | wc -l   and   tcpdump -r r14-s.pcap | wc -l   must both be 0"
}

three_stop() {
  if [[ -f "$name_file" ]]; then
    stop_pid "$(dir_for "$(current)")/node.pid" "$(dir_for "$(current)")"
  fi
  stop_pid "$STRANGER_DIR/node.pid" "$STRANGER_DIR"
  echo "stopped"
}

# ── three-dry-run: every role is this script with its own home on loopback ──
DRY=""
DRY_PORT=""
# free_loopback_port: a 127.0.0.1 port free for TCP and UDP both (empty when
# none was found).
free_loopback_port() {
  python3 -I -c '
import socket
for _ in range(50):
    t = socket.socket()
    t.bind(("127.0.0.1", 0))
    port = t.getsockname()[1]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.bind(("127.0.0.1", port))
    except OSError:
        continue
    finally:
        t.close()
        u.close()
    print(port)
    break
'
}
dry_role() {
  local home=$1
  shift
  RAVEN_WAN_HOME="$DRY/$home" RAVEN_WAN_BIND=127.0.0.1 RAVEN_WAN_LAN_PORT=0 \
    RAVEN_WAN_P2P_PORT=0 RAVEN_WAN_RELAY_PORT="$DRY_PORT" RAVEN_WAN_SKIP_BUILD=1 \
    "$SELF" "$@" </dev/null
}
dry_cleanup() {
  local role job
  for job in $(jobs -p); do
    kill "$job" 2>/dev/null || true
  done
  for role in a b s; do
    dry_role "$role" three stop >/dev/null 2>&1 || true
  done
  dry_role r vps-relay stop >/dev/null 2>&1 || true
}
dry_fail() {
  echo "DRY RUN FAILED: $1" >&2
  if [[ -n "${2:-}" && -f "$2" ]]; then
    tail -n 25 "$2" | sed 's/^/    /' >&2
  fi
  echo "(logs and profiles kept in $DRY)" >&2
  exit 1
}
# wait_card FILE: the raven-card/2 line a backgrounded `three setup` prints.
wait_card() {
  local deadline=$((SECONDS + 120)) card
  while :; do
    card="$(grep -m 1 '^raven-card/2 ' "$1" 2>/dev/null || true)"
    if [[ -n "$card" ]]; then
      printf '%s' "$card"
      return 0
    fi
    ((SECONDS < deadline)) || return 1
    sleep 0.5
  done
}
card_fp() {
  local fp="${1##* fingerprint=}"
  printf '%s' "${fp%% *}"
}
# relayed_rows TSV: "<delivered relayed> <sent>" of a three send TSV.
relayed_rows() {
  awk -F'\t' 'NR > 1 && $3 !~ /->/ { n++; if ($3 == "delivered" && $4 == "relayed") ok++ }
    END { print ok + 0, n + 0 }' "$1"
}

three_dry_run() {
  local a_pid b_pid a_card b_card s_card a_fp b_fp via b_from tsv ok n relayed=0 sent=0
  local s_peer b_log rc=0 tmp="${TMPDIR:-/tmp}"
  DRY="${RAVEN_WAN_DRY_DIR:-}"
  if [[ -z "$DRY" ]]; then
    DRY="$(mktemp -d "${tmp%/}/raven-wan-dry.XXXXXX")"
  elif [[ -d "$DRY" && -n "$(ls -A "$DRY")" ]]; then
    echo "RAVEN_WAN_DRY_DIR=$DRY is not empty: the dry run needs fresh profiles" >&2
    exit 2
  fi
  mkdir -p "$DRY"
  build_bins
  DRY_PORT="$(free_loopback_port)"
  [[ -n "$DRY_PORT" ]] || { echo "no free loopback port for the relay" >&2; exit 2; }
  trap dry_cleanup EXIT
  echo "=== three-node dry run on loopback in $DRY (relay 127.0.0.1:$DRY_PORT, $RELAY_TRANSPORT)"

  dry_role r vps-relay start 127.0.0.1 >"$DRY/r.start.out" 2>&1 || dry_fail "R: vps-relay start" "$DRY/r.start.out"
  via="$(cat "$DRY/r/relay3/via")"
  echo "R: up, VIA $via"
  # A and B wait for their reservation, as on real machines, while R allows
  # the cards they print (R relays only within its circle: both of them).
  dry_role a three setup alice "$via" >"$DRY/a.setup.out" 2>&1 &
  a_pid=$!
  dry_role b three setup bob "$via" >"$DRY/b.setup.out" 2>&1 &
  b_pid=$!
  a_card="$(wait_card "$DRY/a.setup.out")" || dry_fail "A printed no card" "$DRY/a.setup.out"
  b_card="$(wait_card "$DRY/b.setup.out")" || dry_fail "B printed no card" "$DRY/b.setup.out"
  dry_role r vps-relay allow "$a_card" alice >>"$DRY/r.allow.out" 2>&1 || dry_fail "R: allow A" "$DRY/r.allow.out"
  dry_role r vps-relay allow "$b_card" bob >>"$DRY/r.allow.out" 2>&1 || dry_fail "R: allow B" "$DRY/r.allow.out"
  wait "$a_pid" || dry_fail "A: three setup (no reservation)" "$DRY/a.setup.out"
  wait "$b_pid" || dry_fail "B: three setup (no reservation)" "$DRY/b.setup.out"
  echo "A, B: listening on loopback, each reserved on R"
  a_fp="$(card_fp "$a_card")"
  b_fp="$(card_fp "$b_card")"
  dry_role a three add "$b_card" bob "$b_fp" >"$DRY/a.add.out" 2>&1 || dry_fail "A: three add bob" "$DRY/a.add.out"
  dry_role b three add "$a_card" alice "$a_fp" >"$DRY/b.add.out" 2>&1 || dry_fail "B: three add alice" "$DRY/b.add.out"
  grep -h '^relay-only:' "$DRY/a.add.out" "$DRY/b.add.out" || true
  # S's identity now, so R can allow it before the probe: only a member of
  # R's circle reaches B's own peer gate.
  init_profile "$DRY/s/stranger"
  s_card="$(ash_in "$DRY/s/stranger" whoami --card --via "$via" | grep '^raven-card/2 ')"
  s_peer="${s_card##* p2p=}"
  s_peer="${s_peer%% *}"
  dry_role r vps-relay allow "$s_card" stranger >>"$DRY/r.allow.out" 2>&1 || dry_fail "R: allow S" "$DRY/r.allow.out"

  # Each send restarts its sender first: no connection to the recipient.
  dry_role a three send bob 2 >"$DRY/a.send.out" 2>&1 || dry_fail "A: three send bob" "$DRY/a.send.out"
  dry_role b three send alice 1 >"$DRY/b.send.out" 2>&1 || dry_fail "B: three send alice" "$DRY/b.send.out"
  grep -h '^===' "$DRY/a.send.out" "$DRY/b.send.out" || true
  for tsv in "$DRY"/a/alice/three-bob-*.tsv "$DRY"/b/bob/three-alice-*.tsv; do
    [[ -f "$tsv" ]] || dry_fail "no TSV written ($tsv)"
    read -r ok n <<<"$(relayed_rows "$tsv")"
    relayed=$((relayed + ok)) sent=$((sent + n))
  done
  if [[ "$relayed" -ne 3 || "$sent" -ne 3 ]]; then
    dry_fail "$relayed of $sent messages delivered with path=relayed (want 3 of 3)" "$DRY/a.send.out"
  fi
  echo "sends: 3/3 delivered, path=relayed"

  b_log="$DRY/b/bob/node.log"
  b_from="$(log_size "$b_log")"
  dry_role s three stranger "$b_card" "$b_fp" >"$DRY/s.out" 2>&1 || rc=$?
  if [[ "$rc" -ne 0 ]] || ! grep -F 'R14 probe refused (expected)' "$DRY/s.out" >/dev/null; then
    dry_fail "the stranger's probe was not refused as expected (exit $rc)" "$DRY/s.out"
  fi
  wait_log "$b_log" "$LINE_GATE_REFUSED" 15 "$b_from" \
    || dry_fail "B logged no peer gate refusal of the stranger" "$b_log"
  if tail -c "+$((b_from + 1))" "$b_log" | grep -F 'p2p inbound' >/dev/null; then
    dry_fail "the stranger reached B's Raven link (a 'p2p inbound' line)" "$b_log"
  fi
  if grep -F -- "$s_peer" "$b_log" >/dev/null; then
    dry_fail "B's log names the stranger's PeerId (refusals are counts only)" "$b_log"
  fi
  # A failing `inbox` is a failure, never an empty inbox.
  ash_in "$DRY/b/bob" inbox >"$DRY/b-inbox.out" 2>&1 \
    || dry_fail "B's inbox could not be read" "$DRY/b-inbox.out"
  if grep -F 'r14-stranger-probe' "$DRY/b-inbox.out" >/dev/null; then
    dry_fail "B's inbox holds the stranger's probe"
  fi
  echo "stranger: refused by B's peer gate before any Raven link (counts-only log line, no PeerId)"
  dry_role r vps-relay status 2>/dev/null | grep -E 'allow_list|counts' || true
  echo "DRY RUN OK (loopback, not a WAN claim)"
  echo "(logs and profiles kept in $DRY)"
}

# ── friend relays (Phase 2) ──────────────────────────────────────────────────

# friend_on: this test home runs friend relays from now on (a marker the
# next commands read): the debug switches for this process too.
friend_on() {
  : >"$BASE/.friend"
  export RAVEN_LAB_FRIEND_RELAY=1 RAVEN_LAB_ROUTE_HINTS=1
}
# clear_saved_relays DIR: no relay set by hand in DIR's node_policy.json
# (`ash node p2p on --relay` only replaces them): offers alone choose.
clear_saved_relays() {
  python3 -I - "$1/node_policy.json" <<'PY'
import json
import os
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        policy = json.load(f)
except FileNotFoundError:
    sys.exit(0)
if policy.pop("p2p_relays", None) is not None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
PY
}
# offered_reserved DIR: DIR's doctor shows a relay slot picked from an offer
# (relay_N_source=offer) whose reservation is held (relay_N: reserved).
offered_reserved() {
  local out n
  out="$(ash_in "$1" doctor </dev/null 2>/dev/null || true)"
  for n in $(grep -oE 'relay_[0-9]+_source=offer' <<<"$out" | grep -oE '[0-9]+' || true); do
    if grep -Eq "^ *relay_${n}: reserved " <<<"$out"; then
      return 0
    fi
  done
  return 1
}

friend_host() {
  local D public_ip args=(relay offer on)
  D="$(dir_for "$(current)")"
  public_ip="${1:-$(cat "$D/public_ip" 2>/dev/null || true)}"
  friend_on
  # Consent lives in node_policy.json now; the old --relay flag is not used.
  rm -f "$D/service.flags"
  if [[ "$FRIEND_PORT" != "7427" ]]; then
    args+=(--port "$FRIEND_PORT")
  fi
  if [[ -n "$public_ip" ]]; then
    args+=(--external "$(host_ma "$public_ip")/tcp/$FRIEND_PORT")
  fi
  ash "${args[@]}"
  start_node "$D"
  if ! wait_log "$D/node.log" "$LINE_FRIEND_UP" 30 "$NODE_LOG_FROM"; then
    echo "the friend relay did not come up within 30 s:" >&2
    tail -c "+$((NODE_LOG_FROM + 1))" "$D/node.log" | grep -E "friend relay|FRIEND_RELAY" | tail -n 6 >&2 || true
    exit 1
  fi
  tail -c "+$((NODE_LOG_FROM + 1))" "$D/node.log" | grep -E "friend relay|p2p: host up" | tail -n 4 || true
  echo "=== your friend relay (its own key, not your Raven PeerId) ==="
  ash relay card
  echo "=== router forward ==="
  echo "only if this machine is behind a router you control: forward TCP and UDP $FRIEND_PORT to it"
  echo "(or \`ash node upnp on\`). Contacts get the relay from your route hints; nobody needs a new card."
}

friend_use() {
  local tag="${1:?friend-use TAG}" D deadline
  D="$(dir_for "$(current)")"
  friend_on
  rm -f "$D/service.flags"
  clear_saved_relays "$D"
  start_node "$D"
  # One message to TAG: its route hints answer with TAG's offer.
  printf 'wan-friend-use-%s-%s\n' "$(current)" "$(date +%H%M%S)" \
    | ash send --contact "@$tag" 2>&1 | tail -3 || true
  deadline=$((SECONDS + 60))
  until offered_reserved "$D"; do
    if ((SECONDS >= deadline)); then
      echo "no relay picked from an offer within 60 s (is friend-host running on @$tag's machine, and @$tag your verified contact there?)" >&2
      ash doctor 2>/dev/null | grep -E 'relay_|friend_relay' >&2 || true
      exit 1
    fi
    sleep 1
  done
  ash doctor | grep -E 'relay_offer=|relay_[0-9]+:' || true
  echo "=== your card through the relays you hold (contacts learn them by themselves) ==="
  ash whoami --card
}

friend_sleep() {
  cat <<'EOF'
R13: a friend relay's laptop sleeps (lid closed), with two other operators.
Owner-run: debug build and the lab unlock (this script), test homes only,
never ~/.raven or a live profile. Real timers: a relay that stopped answering
is replaced after 10 minutes of loss while another path shows this node is
online, and a replaced relay is not taken back for 30 minutes.

Machines: three operators O1 (the laptop), O2 and O3, each reachable from the
internet (a public IP, UPnP, or a forward of TCP and UDP 7427); B behind a
NAT; C, the sender, anywhere.

 1. Every machine: setup NAME [PUBLIC_IP]. Exchange cards with `add` (each
    operator adds B and C; B adds the three operators and C; C adds B).
 2. O1, O2, O3: friend-host [PUBLIC_IP]  (nothing to send to anyone: contacts
    learn the relay from route hints).
 3. B: friend-use O1, then friend-use O2, then friend-use O3 (one message to
    each: its offer comes back). `ash doctor` then shows relay_1_source=offer
    and relay_2_source=offer, both reserved; relay_standby=1.
 4. C: send B auto 3  (each delivered).
 5. B: `ash status`, note whose relay `relay 1` is. Close that laptop's lid
    (sleep, not shut down); note the time T0.
 6. C: send B auto 1, once a minute for 15 minutes: every message delivered
    (note the longest wait: gap_s).
 7. B: within about 12 minutes of T0 its node.log says `raven-node p2p: relay
    replaced` and `ash status` names the third operator's relay (replaced_s).
 8. Open the lid (T1). The woken operator's node.log says `raven-node
    netwatch: woke from sleep`; for 30 minutes B logs no second `relay
    replaced` and keeps its new relay.
 9. Every machine: report R13. Redact public IPs before sharing the reports.
EOF
}

# ── friend-dry-run: friend-host and friend-use on loopback ────────────────────
DRY_FRIEND_PORT=""
dry_friend() {
  local home=$1
  shift
  RAVEN_WAN_HOME="$DRY/$home" RAVEN_WAN_BIND=127.0.0.1 RAVEN_WAN_LAN_PORT=0 \
    RAVEN_WAN_P2P_PORT=0 RAVEN_WAN_FRIEND_PORT="$DRY_FRIEND_PORT" RAVEN_WAN_DRY_LOOPBACK=1 \
    RAVEN_WAN_SKIP_BUILD=1 "$SELF" "$@" </dev/null
}
dry_friend_cleanup() {
  local role
  for role in h u; do
    dry_friend "$role" stop >/dev/null 2>&1 || true
  done
}

friend_dry_run() {
  local role name D h u h_card u_card host_lan tmp="${TMPDIR:-/tmp}"
  DRY="${RAVEN_WAN_DRY_DIR:-}"
  if [[ -z "$DRY" ]]; then
    DRY="$(mktemp -d "${tmp%/}/raven-wan-friend-dry.XXXXXX")"
  elif [[ -d "$DRY" && -n "$(ls -A "$DRY")" ]]; then
    echo "RAVEN_WAN_DRY_DIR=$DRY is not empty: the dry run needs fresh profiles" >&2
    exit 2
  fi
  mkdir -p "$DRY"
  build_bins
  DRY_FRIEND_PORT="$(free_loopback_port)"
  [[ -n "$DRY_FRIEND_PORT" ]] || { echo "no free loopback port for the friend relay" >&2; exit 2; }
  trap dry_friend_cleanup EXIT
  echo "=== friend relay dry run on loopback in $DRY (friend relay 127.0.0.1:$DRY_FRIEND_PORT)"
  # Two test homes, each one profile: p2p on loopback, no UPnP, LAN on
  # loopback, no Internet direct.
  for role in h u; do
    name=host
    [[ "$role" == "h" ]] || name=user
    mkdir -p "$DRY/$role"
    printf '%s' "$name" >"$DRY/$role/.name"
    D="$DRY/$role/$name"
    init_profile "$D"
    printf '127.0.0.1:0' >"$D/lan.listen"
    ash_in "$D" node p2p on --listen 127.0.0.1:0 --no-upnp >/dev/null </dev/null
  done
  h="$DRY/h/host"
  u="$DRY/u/user"
  h_card="$(ash_in "$h" whoami --card </dev/null | grep '^raven-card/')"
  u_card="$(ash_in "$u" whoami --card </dev/null | grep '^raven-card/')"
  ash_in "$h" contact add --card "$u_card" --petname user --tag user --verify-fp "$(card_fp "$u_card")" \
    </dev/null >"$DRY/h.add.out" 2>&1 || dry_fail "host: contact add user" "$DRY/h.add.out"
  ash_in "$u" contact add --card "$h_card" --petname host --tag host --verify-fp "$(card_fp "$h_card")" \
    </dev/null >"$DRY/u.add.out" 2>&1 || dry_fail "user: contact add host" "$DRY/u.add.out"

  dry_friend h friend-host 127.0.0.1 >"$DRY/h.friend-host.out" 2>&1 \
    || dry_fail "host: friend-host" "$DRY/h.friend-host.out"
  grep -q '^via=' "$DRY/h.friend-host.out" || dry_fail "host: relay card printed no via= line" "$DRY/h.friend-host.out"
  echo "host: friend relay up on 127.0.0.1:$DRY_FRIEND_PORT, its own key"
  host_lan="$(sed -n 's/.*raven-node lan_direct: listen //p' "$h/node.log" | tail -n 1)"
  [[ -n "$host_lan" ]] || dry_fail "host: no LAN listener in its log" "$h/node.log"
  ash_in "$u" contact set-addr @host --lan "$host_lan" </dev/null >/dev/null \
    || dry_fail "user: set-addr @host"
  dry_friend u friend-use host >"$DRY/u.friend-use.out" 2>&1 \
    || dry_fail "user: friend-use host" "$DRY/u.friend-use.out"
  grep -E 'relay_offer=|relay_[0-9]+:' "$DRY/u.friend-use.out" || true
  if grep -F '12D3Koo' "$h/node.log" "$u/node.log" >/dev/null; then
    dry_fail "a node log names a PeerId (counts only)"
  fi
  echo "user: relay picked from the host's offer, reserved"
  echo "DRY RUN OK (loopback, not a WAN claim)"
  echo "(logs and profiles kept in $DRY)"
}

cmd="${1:-help}"
shift || true
case "$cmd" in
  setup)
    name="${1:?setup NAME [PUBLIC_IP]}"
    public_ip="${2:-}"
    mkdir -p "$BASE"
    printf '%s' "$name" >"$name_file"
    D="$(dir_for "$name")"
    build_bins
    init_profile "$D"
    # Two-node mode: LAN on every interface (no three-node markers), and no
    # friend relays until friend-host or friend-use.
    rm -f "$D/lan.listen" "$D/three.via"
    if [[ -f "$BASE/.friend" ]]; then
      rm -f "$BASE/.friend"
      unset RAVEN_LAB_FRIEND_RELAY
    fi
    "$BIN/ash" --data-dir "$D" node internet on --listen "0.0.0.0:$INET_PORT" >/dev/null
    "$BIN/ash" --data-dir "$D" node p2p on --listen "$P2P_PORT" --upnp >/dev/null
    [[ -n "$public_ip" ]] && printf '%s' "$public_ip" >"$D/public_ip"
    start_node "$D"
    wait_log "$D/node.log" "$LINE_HOST_UP" 30 "$NODE_LOG_FROM" || true
    echo "=== node ($name) ==="
    grep -E "listen|p2p|upnp|autonat|relay|failed" "$D/node.log" | tail -12 || true
    echo
    echo "=== your card (give it to the other machine) ==="
    if [[ -n "$public_ip" ]]; then
      "$BIN/ash" --data-dir "$D" whoami --card --inet "$public_ip:$INET_PORT" \
        --via "/ip4/$public_ip/tcp/$P2P_PORT/p2p/$("$BIN/ash" --data-dir "$D" whoami --card | grep -oE 'p2p=12D3Koo[1-9A-HJ-NP-Za-km-z]+' | cut -d= -f2)"
    else
      "$BIN/ash" --data-dir "$D" whoami --card
    fi
    echo
    "$BIN/ash" --data-dir "$D" whoami | grep -i fingerprint
    ;;
  addr)
    tag="${1:?addr TAG --lan IP:PORT | --internet IP:PORT | --via MULTIADDR | --clear lan|internet}"
    shift
    ash contact set-addr --tag "$tag" "$@"
    ash contact list
    ;;
  card)
    D="$(dir_for "$(current)")"
    ash whoami --card
    ash whoami | grep -i fingerprint
    ;;
  add)
    card="${1:?add CARD TAG FINGERPRINT}"
    tag="${2:?add CARD TAG FINGERPRINT}"
    fp="${3:?add CARD TAG FINGERPRINT}"
    ash contact add --card "$card" --petname "$tag" --tag "$tag" --verify-fp "$fp"
    ash contact list
    ;;
  send)
    tag="${1:?send TAG [carrier] [count]}"
    carrier="${2:-auto}"
    count="${3:-3}"
    for i in $(seq 1 "$count"); do
      start=$(date +%s)
      printf 'wan-%s-%s-%s\n' "$(current)" "$i" "$(date +%H%M%S)" \
        | ash send --contact "@$tag" --carrier "$carrier" 2>&1 | tail -3 || true
      echo "  (${i}/${count} took $(( $(date +%s) - start ))s)"
    done
    ;;
  friend-host)
    # On the reachable machine: relay for your verified contacts with this
    # profile's own relay key, offered to them in route hints.
    friend_host "$@"
    ;;
  friend-use)
    # On the machine behind NAT: no relay set by hand; pick from offers. It
    # keeps listening on P2P_PORT (a node without a listener can never
    # hole-punch).
    friend_use "$@"
    ;;
  friend-sleep)
    friend_sleep
    ;;
  friend-dry-run)
    friend_dry_run
    ;;
  report)
    row="${1:-}"
    D="$(dir_for "$(current)")"
    out="$PWD/wan-report-$(current)${row:+-$row}-$(utc).txt"
    {
      echo "### machine: $(current)${row:+  row: $row}  $(date -u +%FT%TZ)  $(uname -sm)"
      echo "### local addresses"; (ifconfig 2>/dev/null || ip addr 2>/dev/null) | grep -E "inet6? " || true
      echo "### status"; ash status 2>&1 || true
      echo "### outbox"; ash outbox list 2>&1 || true
      echo "### inbox"; ash inbox 2>&1 || true
      echo "### contacts"; ash contact list 2>&1 || true
      echo "### three-node runs (three send / three rate)"
      for f in "$D"/three-*.tsv; do
        [[ -f "$f" ]] || continue
        echo "## $(basename "$f")"
        cat "$f"
      done
      echo "### friend custody (counts only)"
      ash custody status 2>&1 || true
      ash node custody status 2>&1 || true
      echo "outbox items held by friends (IN_CUSTODY): $(ash outbox list 2>/dev/null | grep -cF 'held by' || true)"
      echo "left with a friend (deposit lines): $(log_count "$D/node.log" 'raven-node custody: left ')"
      echo "fetched from a friend (fetch lines): $(log_count "$D/node.log" 'raven-node custody: fetched ')"
      echo "### path labels (three-node sends)"; path_counts "$D"
      echo "### hole punching (whole node log)"
      echo "dcutr upgrades: $(log_count "$D/node.log" "$LINE_DCUTR")"
      echo "hole punch failed: $(log_count "$D/node.log" "$LINE_PUNCH_FAILED")"
      echo "### node log (tail)"; tail -200 "$D/node.log" 2>/dev/null || true
    } >"$out"
    echo "wrote $out"
    ;;
  stop)
    D="$(dir_for "$(current)")"
    [[ -f "$D/node.pid" ]] && kill "$(cat "$D/node.pid")" 2>/dev/null || true
    echo "stopped"
    ;;
  custodian)
    D="$(dir_for "$(current)")"
    case "${1:-}" in
      on) ash node custody on --yes ;;
      off) ash node custody off ;;
      *)
        echo "custodian on|off" >&2
        exit 2
        ;;
    esac
    # A fresh start announces the offer (or its end) in route hints.
    start_node "$D"
    ash custody status
    ;;
  mailbox)
    [[ "${1:-}" == "on" ]] || { echo "mailbox on" >&2; exit 2; }
    ash custody use on --yes
    ash custody status
    ;;
  wait-held)
    tag="${1:?wait-held TAG [SECS]}"
    deadline=$((SECONDS + ${2:-120}))
    until ash outbox list 2>/dev/null | grep -i -- "to $tag" | grep -Fq 'held by'; do
      if ((SECONDS >= deadline)); then
        echo "nothing for @$tag is held by a friend after ${2:-120}s:" >&2
        ash outbox list >&2 || true
        exit 1
      fi
      sleep 2
    done
    ash outbox list | grep -i -- "to $tag" | grep -F 'held by'
    ;;
  hand-off)
    tag="${1:?hand-off TAG}"
    ash outbox hand-off --contact "@$tag"
    ;;
  custody-status)
    ash custody status
    ash node custody status
    echo "outbox items held by friends: $(ash outbox list 2>/dev/null | grep -cF 'held by' || true)"
    ;;
  vps-relay)
    vps_relay "$@"
    ;;
  egress443)
    egress443 "$@"
    ;;
  three)
    sub="${1:-help}"
    shift || true
    case "$sub" in
      setup) three_setup "$@" ;;
      add) three_add "$@" ;;
      send) three_send "$@" ;;
      rate) three_rate "$@" ;;
      stranger) three_stranger "$@" ;;
      stop) three_stop ;;
      *)
        echo "three setup NAME VIA | add CARD TAG FP | send TAG [COUNT] | rate TAG [SESSIONS] | stranger CARD FP | stop" >&2
        exit 2
        ;;
    esac
    ;;
  three-dry-run)
    three_dry_run
    ;;
  *)
    awk 'NR > 1 && /^set -euo pipefail/ { exit } NR > 1' "$0"
    ;;
esac
