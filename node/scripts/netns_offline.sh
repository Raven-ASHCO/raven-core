#!/usr/bin/env bash
# Cutoff pack (CP.15): Raven with no internet provider, in Linux network
# namespaces. Sibling of netns_nat_dcutr.sh (same helpers and style). Every
# case is advisory: reported, and the script exits 1 when one fails, but the
# lab CI job runs it with continue-on-error.
#
# Every namespace gets its own /etc/netns/<ns>/resolv.conf (a name server at
# 192.0.2.53, a TEST-NET black hole: no case has a route to it, or a router
# drops it) and nsswitch.conf (`hosts: files dns`, so no mDNS: a host's avahi
# must never answer for a namespace). IPv6 is off in every namespace, so the
# packet counters see no neighbour discovery. Counters are named nft counters
# on the bridges (`nft list counter bridge ...`).
#
# Cases (all advisory; RAVEN_NETNS_CASES picks some, in order):
#   lan-noprovider     one bridge 192.168.2.0/24 with A (.10) and B (.20), no
#                      default route, the cutoff gates open for both
#                      (RAVEN_LAB_OFFLINE=1 RAVEN_LAB_NOISE_PIN=1: CP.9's
#                      switch). Unverified contacts with literal routes:
#                      A -> B and B -> A delivered, each exactly once. A's
#                      route for B becomes `x-nohost.local:7420`: the send
#                      ends queued within 10 s saying "could not be found on
#                      this network" (CP.5); A's route goes back to B's
#                      number and the message arrives exactly once without a
#                      new send. The bridge's counters: 0 packets from A or
#                      B to anything but the other one and UDP 53; A's
#                      `raven doctor` makes no internet claim.
#   router-dead-uplink a router R (192.168.3.1) whose WAN veth drops
#                      everything forwarded to it and which drops DNS; A and B
#                      with a default route through R. The LAN part as
#                      lan-noprovider (the name lookup now times out at R).
#                      Then A runs with the p2p lab unlock (RAVEN_LAB_TEST_A=1)
#                      and a relay `via=` on the dead WAN (the relay runs
#                      behind it, unreachable). Carol, a verified contact A
#                      met once on this LAN (a session), is then saved with a
#                      p2p route only and her node is stopped: A -> Carol
#                      ends queued within 8 s with no VPS, port-forward or
#                      UPnP advice; right after it A -> B and B -> A are
#                      delivered within 8 s each (Carol's worker attempt
#                      does not hold the LAN contact up), and A's `raven
#                      doctor`, the p2p host up, makes no internet claim.
#                      Whether the text says "asleep, switched off or
#                      offline" is recorded: Phase 2's no_route reason does
#                      not apply, because a default route exists.
#   hotspot-ap         the access point AP owns bridge br-ap 10.42.0.1/24 and
#                      has no uplink and no forwarding; clients C1 (.2) and
#                      C2 (.3) route through .1. First the three meet on a
#                      home bridge (192.168.1.1-3): verified contacts,
#                      sessions both ways; then each moves to the hotspot
#                      (their saved addresses are the old 192.168.1.x ones).
#                      (1) Today, no switch: AP -> C1 and C1 -> AP end queued
#                      on the stale addresses; after C1's
#                      `contact set-dial --tag ap --lan-dial 10.42.0.1:7420`
#                      C1 -> AP is delivered and C1's queued message arrives
#                      once; AP's queued message reaches C1 only after C1's
#                      first link (AP dials back where C1 came from).
#                      (2) A client reaching the AP with no typed address
#                      needs CP.13's gateway candidate, which was not built
#                      (owner decision OD-C5): not run.
#                      (3) Phase 3 P3.C5, the LAN beacon
#                      (RAVEN_LAB_LAN_BEACON=1, UDP 7420 inside the
#                      namespaces): C1 -> C2 and C2 -> C1, whose saved
#                      addresses are still the old ones and with no address
#                      typed, are each delivered by the send within 15 s
#                      through what the beacon found ("found on your network
#                      now"), and neither book saves the find.
#                      (4) Isolation: an nft rule on br-ap drops C1 <-> C2.
#                      C1 -> C2 (at C2's new address) ends queued with a LAN
#                      no-answer text; then with lab custody (AP listed by
#                      both as custodian, RAVEN_LAB_TEST_A=1) C1 -> C2 is
#                      delivered once through AP and C2's ACK comes back to C1
#                      through AP.
#   cable-linklocal    A and B on one veth pair, IPv4 link-local only
#                      (169.254.10.1/16 and 169.254.20.2/16). Two rounds on
#                      fresh profiles, A with RAVEN_LAB_OFFLINE=0 (before
#                      CP.10) and =1: A's node starts with
#                      `--lan-listen 169.254.10.1:7420` before that address
#                      exists (netwatch: "watching (0 networks)", its first
#                      view; `raven doctor`: addr_not_here), the address is added
#                      once the bind retry has backed off to 16 s, and the
#                      listener binds within one more retry (35 s) with
#                      addr_not_here gone. Gate open: netwatch logs
#                      "link-local network only (a cable?)"; closed: no such
#                      line. Both rounds: A -> B and B -> A delivered once.
#                      A third round (Phase 3 P3.C5) on fresh profiles with
#                      IPv6 on the veth pair (fe80::10 and fe80::20, static,
#                      no DAD): both nodes listen with `--lan-listen
#                      auto:7420` under RAVEN_LAB_LAN_AUTO=1 (0.0.0.0 and
#                      [::]), each saves the other as `[fe80::...%eth0]:7420`
#                      (a link-local address with its zone), and A -> B and
#                      B -> A are delivered once each.
#   three-rooms        route hints + custody + CP.14 (RAVEN_LAB_TEST_A=1,
#                      custody timers, RAVEN_LAB_NOISE_PIN=1; route hints from
#                      the rooms on). Addresses in 192.168.0.0/16, so a
#                      laptop keeps its address on any bridge. A, B and C meet
#                      at home (verified, pinned, sessions; A and B chose C as
#                      each other's custodian; C turns custody on), then:
#                      room1 holds A and C, room2 holds B only. In the rooms
#                      C listens on 0.0.0.0:7420 (the default bind), so only
#                      its networks say that it moved. A -> B is left with
#                      C. C's veth moves to room2 with a new address
#                      (192.168.2.31) while its node runs: B gets the message
#                      exactly once within 40 s (C's announce to the
#                      recipients it holds mail for), and B's log shows the
#                      custody fetch it came by. C moves back to room1 with
#                      another new address (192.168.1.32; its node restarts
#                      there): B's ACK reaches A through C. C ends with 0
#                      unreleased rows (released rows stay until they
#                      expire: friend custody errata rule 9). The rooms are
#                      separate bridges, so A and B never share a link.
#   three-rooms-beacon three-rooms with route hints off in the rooms and the
#                      LAN beacon on instead (Phase 3 P3.C5,
#                      RAVEN_LAB_LAN_BEACON=1): beacon plus custody only. C's
#                      move to room2 is a network change for its beacon, whose
#                      join round names B (C holds mail for B); B answers,
#                      fetches the message exactly once within 40 s, and B's
#                      ACK reaches A through C after C's move back. No RRH1
#                      is learned in the rooms.
#
# Topology: one namespace per laptop (hA, hB, ...), a switch namespace per
# bridge (no address on it, except br-ap, which is the AP's own), veth pairs
# created inside the namespaces (nothing appears on the host), every name with
# a per-run prefix. No namespace has a route to the real Internet.
#
# HONEST CLAIM: a software substitute for a dead router, a hotspot and a
# cable. It does not replace the owner's hardware checks (macOS Internet
# Sharing and Windows Mobile Hotspot with no upstream, client isolation on
# phone hotspots, Bluetooth PAN) or real row R11j.
#
# Written on macOS and NOT run locally (macOS has no network namespaces); the
# lab CI job nat-sim-linux (.github/workflows/raven-serverless-lab.yml) runs it
# on ubuntu-latest, advisory.
#
# Usage: build the debug binaries first, as yourself (never cargo as root):
#   (cd node && cargo build --locked -p ash -p raven-node)
#   sudo -E env "PATH=$PATH" bash node/scripts/netns_offline.sh
# or let the script re-run itself under `sudo -E`:
#   RAVEN_NETNS_ALLOW_SUDO=1 bash node/scripts/netns_offline.sh
# Environment:
#   RAVEN_BIN_DIR       raven + raven-node (default <repo>/node/target/debug)
#   RAVEN_NETNS_TMP     base dir for the per-run temp dirs (kept afterwards;
#                       default: a mktemp -d dir, removed unless RAVEN_NETNS_KEEP=1)
#   RAVEN_NETNS_CASES   the cases, space (or comma) separated, in order
#                       (default: all six)
# Exit: 0 = every selected case passed, 1 = one failed, 2 = cannot run here
# (not Linux or root, missing tools or binaries, a release build path, or an
# nftables preflight found no bridge counters).
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT="$(cd "$(dirname "$SELF")/.." && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "netns_offline: Linux only (network namespaces + nftables)" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  if [[ "${RAVEN_NETNS_ALLOW_SUDO:-0}" == "1" ]]; then
    echo "netns_offline: not root; re-running under sudo -E (RAVEN_NETNS_ALLOW_SUDO=1)" >&2
    exec sudo -E env "PATH=$PATH" bash "$SELF" "$@"
  fi
  echo "netns_offline: needs root (it creates network namespaces, bridges and nftables rules)." >&2
  echo "  Run: sudo -E env \"PATH=\$PATH\" bash $SELF" >&2
  echo "  or:  RAVEN_NETNS_ALLOW_SUDO=1 bash $SELF   (re-runs itself under sudo -E)" >&2
  exit 2
fi

BIN_DIR="${RAVEN_BIN_DIR:-$ROOT/target/debug}"
NODE="$BIN_DIR/raven-node"
RAVEN="$BIN_DIR/raven"
case "$BIN_DIR" in
  */release | */release/*)
    echo "netns_offline: RAVEN_BIN_DIR=$BIN_DIR is a release build path. The lab switches" >&2
    echo "  (RAVEN_LAB_OFFLINE, RAVEN_LAB_NOISE_PIN, RAVEN_LAB_TEST_A) only work in debug builds." >&2
    exit 2
    ;;
esac
for bin in "$NODE" "$RAVEN"; do
  if [[ ! -x "$bin" ]]; then
    echo "netns_offline: missing $bin; build it first (as yourself, not root):" >&2
    echo "  (cd $ROOT && cargo build --locked -p ash -p raven-node)" >&2
    exit 2
  fi
done
for tool in ip nft timeout sysctl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "netns_offline: missing '$tool' (Debian/Ubuntu: apt-get install -y iproute2 nftables coreutils procps)" >&2
    exit 2
  fi
done
HAVE_PY=0
if command -v python3 >/dev/null 2>&1; then
  HAVE_PY=1
fi

# Same lab environment for every process (debug locked-file backends, as the
# other harnesses use). A service that a CLI command starts by itself listens
# on loopback only. Every lab switch is off unless a case sets it (LAB_ENV),
# Phase 3's and Phase 4's included (as netns_nat_dcutr.sh), and no proxy
# setting reaches a process: each runs with RAVEN_P2P_PROXY=off, so neither
# the environment's nor the host's system proxy is used.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_SESSION_BACKEND=locked-file
export RAVEN_PREKEY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
export RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0
export NO_COLOR=1
unset RAVEN_P2P_LISTEN RAVEN_P2P_RELAYS RAVEN_P2P_RELAY RAVEN_INTERNET_LISTEN \
  RAVEN_DATA_DIR ASH_DATA_DIR ASH_LAN_DIAL RAVEN_VERBOSE ASH_VERBOSE RAVEN_TRACE_LOG \
  RAVEN_SERVICE_LOG_MAX_BYTES RAVEN_LAB_TEST_A RAVEN_LAB_P2P_PING RAVEN_LAB_NETWATCH_EVENTS \
  RAVEN_LAB_NET_TAG RAVEN_LAB_P2P_LOCAL_CANDIDATES RAVEN_LAB_P2P_RELAY_ONLY \
  RAVEN_LAB_ROUTE_HINTS RAVEN_LAB_HINTS_NO_ANNOUNCE RAVEN_LAB_FRIEND_RELAY \
  RAVEN_LAB_FRIEND_RELAY_LISTEN RAVEN_LAB_RELAY_SELECT RAVEN_LAB_P2P_PROFILE_RELAY \
  RAVEN_LAB_OFFLINE RAVEN_LAB_NOISE_PIN RAVEN_LAB_LAN_DEFAULT_PORT RAVEN_LAB_LAN_GATEWAY \
  RAVEN_LAB_CLOCK_FILE RAVEN_LAB_SESSION_RESET RAVEN_LAB_CUSTODY_WAN \
  RAVEN_LAB_CUSTODY_AFTER_MS RAVEN_LAB_CUSTODY_FETCH_MS RAVEN_LAB_CUSTODY_PRETEND_OLD \
  RAVEN_LAB_CUSTODY_BASE_OPS_ONLY RAVEN_LAB_CUSTODY_HANDOFF RAVEN_LAB_CUSTODY_FORWARD_MS \
  RAVEN_LAB_AT_REST RAVEN_LAB_ERASE_ROOT RAVEN_LAB_AT_REST_KEY_FAULT \
  RAVEN_LAB_RETENTION_GRACE_MS RAVEN_LAB_LOGIN_ITEM_ROOT RAVEN_LAB_LOGIN_ITEM_TOOLS \
  RAVEN_LAB_LAN_AUTO RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK RAVEN_LAB_LAN_BEACON \
  RAVEN_LAB_LAN_BEACON_PORT RAVEN_LAB_LAN_BEACON_FAMILY RAVEN_LAB_LAN_BEACON_BUS \
  RAVEN_LAB_WSS RAVEN_LAB_WSS_PROXY RAVEN_P2P_PROXY HTTPS_PROXY https_proxy \
  ALL_PROXY all_proxy NO_PROXY no_proxy RAVEN_LAB_PORT_MAP RAVEN_LAB_V6_PINHOLE \
  RAVEN_LAB_NAT_CLASS RAVEN_LAB_NAT_CLASS_FORCE RAVEN_LAB_PEER_ROTATION \
  RAVEN_LAB_PEER_EPOCH_S RAVEN_LAB_PORTMAP_GATEWAY RAVEN_LAB_PORTMAP_LIFETIME \
  RAVEN_LAB_SESSION_RENEWAL RAVEN_LAB_SESSION_LIFETIME_MS RAVEN_LAB_HORIZON \
  RAVEN_LAB_LETTER RAVEN_LAB_NEARBY RAVEN_LAB_NEARBY_ETHER \
  RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR RAVEN_LAB_NEARBY_FOREGROUND_MS RAVEN_LAB_NET_AUDIT \
  RAVEN_LAB_NEARBY_ONLY RAVEN_LAB_BLUEZ_BTVIRT \
  RAVEN_LAB_LEARNING RAVEN_LAB_LEARNING_TUNE RAVEN_LAB_LEARNING_SEALER \
  RAVEN_LAB_SECURITY_EVENTS RAVEN_LAB_SECURITY_RESPONSES RAVEN_LAB_SUITE_FLOOR \
  RAVEN_LAB_LINK_PADDING RAVEN_LAB_LINK_KNOCK RAVEN_LAB_RANDOM_PORT RAVEN_LAB_PAIR_SEED \
  RAVEN_LAB_LOCAL_PROTECTION RAVEN_LAB_ADVISORY RAVEN_LAB_RELEASE_BUNDLE \
  RAVEN_LAB_MESH_UPDATE RAVEN_LAB_SEC_PENALTY_LOOPBACK RAVEN_LAB_RELEASE_KEYS_FILE \
  RAVEN_LAB_UPDATE_AUTO_APPROVE RAVEN_LAB_UPDATE_CLAIM_NEWER \
  2>/dev/null || true
export RAVEN_P2P_PROXY=off

ALL_CASES="lan-noprovider router-dead-uplink hotspot-ap cable-linklocal three-rooms three-rooms-beacon"
IFS=', ' read -r -a CASE_ARGS <<<"${RAVEN_NETNS_CASES:-$ALL_CASES}"
CASE_LIST=()
for name in ${CASE_ARGS[@]+"${CASE_ARGS[@]}"}; do
  [[ -n "$name" ]] || continue
  if [[ " $ALL_CASES " != *" $name "* ]]; then
    echo "netns_offline: RAVEN_NETNS_CASES names an unknown case '$name' (cases: $ALL_CASES)" >&2
    exit 2
  fi
  if [[ " ${CASE_LIST[*]-} " != *" $name "* ]]; then
    CASE_LIST+=("$name")
  fi
done
if [[ ${#CASE_LIST[@]} -eq 0 ]]; then
  echo "netns_offline: RAVEN_NETNS_CASES names no case (cases: $ALL_CASES)" >&2
  exit 2
fi

# Bounds (seconds). Every wait is a deadline loop on an observable condition
# and fails with all logs printed.
CLI_TIMEOUT=60
SEND_TIMEOUT=120
START_WAIT=30
INBOX_WAIT=15
# A name that resolves nowhere: the send ends within this (the lookup is
# bounded by resolv.conf's 2 s and raven's own 5 s).
NAME_SEND_MAX=10
# A queued message after its route was fixed (the worker's next attempt).
FIXED_DELIVER=150
# router-dead-uplink: every send of the p2p part.
DEAD_SEND_MAX=8
# hotspot-ap: AP's queued message after C1's first link; custody.
DIAL_BACK_WAIT=30
CUSTODY_HELD_WAIT=60
CUSTODY_FETCH_WAIT=60
CUSTODY_ACK_WAIT=150
# cable-linklocal: netwatch's line, and the bind within one retry (30 s at
# most, plus the time to see the line).
NETWATCH_WAIT=15
BIND_BACKOFF_WAIT=45
BIND_AFTER_ADDR=35
# three-rooms: B's fetch after C's node starts in room2 (10 s settle, then
# the announce link and the fetch).
ROOMS_FETCH=40
# hotspot-ap (3): a send that finds the contact through the LAN beacon.
BEACON_FIND_MAX=15

# The port every node listens on inside its namespace (namespaces do not
# share ports with the host or with each other).
PORT=7420
# The name server every namespace is given: TEST-NET, never answered.
DNS_BLACKHOLE=192.0.2.53
# The relay address on router-dead-uplink's dead WAN (TEST-NET-3).
DEAD_RELAY_IP=203.0.113.1

LINE_LISTEN='raven-node lan_direct: listen '
LINE_BIND_FAILED='lan_direct failed: lan_direct bind '
# A watcher that starts with no address settles a baseline of none; "no
# network; waiting for one" comes only when networks it saw are gone.
LINE_WATCHING_NONE='raven-node netwatch: watching (0 networks)'
LINE_CABLE='raven-node netwatch: link-local network only (a cable?)'
LINE_HOST_UP='raven-node p2p: host up'
NOT_FOUND='could not be found on this network'
# A send delivered through what the LAN beacon found (ash send).
BEACON_FOUND='found on your network now'
ASLEEP='asleep, switched off or offline'
# A custody fetch that brought an ACK (raven-node custody.rs).
ACK_FETCHED_RE='custody: fetched messages=[0-9]+ acks=[1-9]'
# What `raven doctor` must never say on a network without a provider.
INTERNET_CLAIM_RE='reachable from the internet|internet (is )?(up|ok|reachable|available|working)|you are online|reach_class: (public|relayed|unconfirmed)'
# Advice that makes no sense without an internet provider.
ONLINE_ADVICE_RE='VPS|port.?forward|UPnP'

# Per-run prefix: never touches (or deletes) a namespace this script did not make.
NSP="rvo$$"

BASE_OWNED=0
if [[ -n "${RAVEN_NETNS_TMP:-}" ]]; then
  BASE="$RAVEN_NETNS_TMP"
  mkdir -p "$BASE"
else
  BASE="$(mktemp -d)"
  BASE_OWNED=1
fi
BASE="$(cd "$BASE" && pwd)"

# Namespaces with our prefix: kill whatever still runs inside, delete them and
# their /etc/netns files.
teardown_net() {
  local ns pids
  for ns in $(ip netns list 2>/dev/null | awk -v p="${NSP}-" 'index($1, p) == 1 { print $1 }'); do
    pids="$(ip netns pids "$ns" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      # shellcheck disable=SC2086 # one PID per word
      kill -KILL $pids 2>/dev/null || true
    fi
    ip netns del "$ns" 2>/dev/null || true
  done
  for ns in /etc/netns/"${NSP}"-*; do
    [[ -d "$ns" ]] || continue
    rm -rf "$ns"
  done
}

main_cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  teardown_net
  if [[ "$BASE_OWNED" == "1" && "${RAVEN_NETNS_KEEP:-0}" != "1" ]]; then
    rm -rf "$BASE"
  else
    echo "netns_offline: run dirs (logs under */logs) kept in $BASE" >&2
  fi
  exit "$rc"
}
trap main_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- per-run helpers (used inside the run subshell) -------------------------

PIDS=()
MODE=""
LOGS=""
RUN=""
# The lab switches of the current phase, for every raven and raven-node.
LAB_ENV=()
# Bridge namespaces whose counters a failed run prints.
SWITCHES=()

dump_logs() {
  local f ns
  if [[ -z "$LOGS" || ! -d "$LOGS" ]]; then
    return 0
  fi
  echo "===== logs of the $MODE run ($LOGS) =====" >&2
  for f in "$LOGS"/*; do
    [[ -f "$f" ]] || continue
    echo "----- $(basename "$f")" >&2
    cat "$f" >&2 || true
  done
  for ns in ${SWITCHES[@]+"${SWITCHES[@]}"}; do
    echo "----- $ns: nft list ruleset" >&2
    ip netns exec "$ns" nft list ruleset >&2 2>/dev/null || true
  done
  echo "===== end of logs ($MODE) =====" >&2
}

fail() {
  echo "NETNS_OFFLINE_FAIL ($MODE): $*" >&2
  dump_logs
  exit 1
}

# note WHAT: a recorded fact (not a pass condition), in the run's output.
note() {
  echo "  recorded: $*"
}

stop_pid() {
  local pid=$1 i
  kill -TERM "$pid" 2>/dev/null || true
  for ((i = 0; i < 50; i++)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

stop_procs() {
  local pid
  if [[ ${#PIDS[@]} -eq 0 ]]; then
    return 0
  fi
  for pid in "${PIDS[@]}"; do
    stop_pid "$pid"
  done
  PIDS=()
}

run_cleanup() {
  trap - EXIT INT TERM
  stop_procs
  teardown_net
}

# now_ms: milliseconds since the epoch (GNU date).
now_ms() {
  echo $(($(date +%s%N) / 1000000))
}

# within MS LIMIT: true when no more than LIMIT whole seconds passed since MS.
within() {
  [[ $(($(now_ms) - $1)) -le $(($2 * 1000)) ]]
}

# ns_add NS: a namespace with lo up, IPv6 off, and its own resolv.conf (the
# black-hole name server, 2 s per try) and nsswitch.conf (no mDNS).
ns_add() {
  local ns=$1
  ip netns add "$ns"
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  mkdir -p "/etc/netns/$ns"
  printf 'nameserver %s\noptions timeout:2 attempts:1\n' "$DNS_BLACKHOLE" >"/etc/netns/$ns/resolv.conf"
  printf '%s\n' 'passwd: files' 'group: files' 'shadow: files' 'hosts: files dns' \
    'networks: files' 'protocols: files' 'services: files' 'ethers: files' 'rpc: files' \
    >"/etc/netns/$ns/nsswitch.conf"
}

# switch_add NS BR: a switch namespace holding bridge BR (no address).
switch_add() {
  ns_add "$1"
  ip -n "$1" link add "$2" type bridge
  ip -n "$1" link set "$2" up
  SWITCHES+=("$1")
}

# plug HOST HOST_IF SW BR PORT CIDR: a veth from HOST (HOST_IF, with CIDR
# unless it is empty) to port PORT of bridge BR in SW.
plug() {
  local host=$1 hif=$2 sw=$3 br=$4 port=$5 cidr=$6
  ip -n "$sw" link add "$port" type veth peer name "$hif" netns "$host"
  ip -n "$sw" link set "$port" master "$br"
  ip -n "$sw" link set "$port" up
  if [[ -n "$cidr" ]]; then
    ip -n "$host" addr add "$cidr" dev "$hif"
  fi
  ip -n "$host" link set "$hif" up
}

# move_port FROM_SW PORT TO_SW BR: a laptop carried to another room: its
# veth's switch end moves to bridge BR in TO_SW (the laptop sees its link go
# down and up).
move_port() {
  local from=$1 port=$2 to=$3 br=$4
  ip -n "$from" link set "$port" netns "$to"
  ip -n "$to" link set "$port" master "$br"
  ip -n "$to" link set "$port" up
}

# no_default_route NS: fails when NS has one.
no_default_route() {
  if [[ -n "$(ip -n "$1" route show default 2>/dev/null)" ]]; then
    fail "$1 has a default route; this case must have none"
  fi
}

# nft_counter NS FAMILY TABLE NAME: the packets of a named counter. Status 1
# and no output when that is not a number (a broken read never passes as 0).
nft_counter() {
  local n
  n="$(ip netns exec "$1" nft list counter "$2" "$3" "$4" 2>/dev/null \
    | awk '{ for (i = 1; i < NF; i++) if ($i == "packets") { print $(i + 1); exit } }')" || true
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  echo "$n"
}

# bridge_count SW NAME: the packets of SW's raven_off counter NAME.
bridge_count() {
  nft_counter "$1" bridge raven_off "$2" || fail "cannot read the nft counter $2 in $1"
}

# pair_counters SW A_IP B_IP: SW's bridge counts, per sender, the packets to
# the other one (a_peer, b_peer), to UDP 53 (a_dns, b_dns) and to anything
# else (a_other, b_other).
pair_counters() {
  local sw=$1 a=$2 b=$3
  ip netns exec "$sw" nft -f - <<EOF || fail "nft rejected the bridge counters in $sw"
table bridge raven_off {
  counter a_peer {
  }
  counter a_dns {
  }
  counter a_other {
  }
  counter b_peer {
  }
  counter b_dns {
  }
  counter b_other {
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr $a ip daddr $b counter name "a_peer" accept
    ip saddr $a udp dport 53 counter name "a_dns" accept
    ip saddr $a counter name "a_other"
    ip saddr $b ip daddr $a counter name "b_peer" accept
    ip saddr $b udp dport 53 counter name "b_dns" accept
    ip saddr $b counter name "b_other"
  }
}
EOF
}

# reset_pair_counters SW: zero SW's pair counters.
reset_pair_counters() {
  local name
  for name in a_peer a_dns a_other b_peer b_dns b_other; do
    ip netns exec "$1" nft reset counter bridge raven_off "$name" >/dev/null \
      || fail "cannot reset the nft counter $name in $1"
  done
}

# rv NS DIR ARGS...: `raven --data-dir DIR ARGS...` inside NS with the phase's
# lab switches, bounded by CLI_TIMEOUT, stdin closed.
rv() {
  local ns=$1 dir=$2
  shift 2
  timeout "$CLI_TIMEOUT" ip netns exec "$ns" env ${LAB_ENV[@]+"${LAB_ENV[@]}"} \
    "$RAVEN" --data-dir "$dir" "$@" </dev/null
}

# require_alive PID...: fails when one has exited.
require_alive() {
  local pid
  for pid in "$@"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      fail "process $pid exited early"
    fi
  done
}

# wait_line LOG FIXED_TEXT SECS PID...: until LOG contains FIXED_TEXT.
wait_line() {
  local log=$1 text=$2 secs=$3 deadline
  shift 3
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if grep -Fq -- "$text" "$log" 2>/dev/null; then
      return 0
    fi
    require_alive "$@"
    sleep 0.2
  done
  fail "'$text' not in $(basename "$log") within ${secs}s"
}

# wait_ipc NS DIR SECS PID: until the daemon answers `raven ipc-ping`.
wait_ipc() {
  local ns=$1 dir=$2 secs=$3 pid=$4 deadline
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if rv "$ns" "$dir" ipc-ping >/dev/null 2>&1; then
      return 0
    fi
    require_alive "$pid"
    sleep 0.2
  done
  fail "daemon for $dir did not answer ipc-ping within ${secs}s"
}

# start_node NS DIR LOG LISTEN [WAIT] [EXTRA...]: raven-node service in NS
# listening on LISTEN, output in LOGS/LOG. WAIT "bound" (the default) waits
# for the LAN listener, "unbound" for its first failed bind (an address not
# on this host yet), "auto" for the IPv6 socket of `auto:PORT` ([::]:PORT,
# bound after 0.0.0.0:PORT). Sets NODE_PID.
NODE_PID=""
start_node() {
  local ns=$1 dir=$2 log=$3 listen=$4 want=${5:-bound}
  shift 4
  [[ $# -eq 0 ]] || shift
  ip netns exec "$ns" env ${LAB_ENV[@]+"${LAB_ENV[@]}"} "$NODE" service --data-dir "$dir" \
    --lan-listen "$listen" --ble-listen 127.0.0.1:0 --timeout-secs 0 "$@" \
    >"$LOGS/$log" 2>&1 &
  NODE_PID=$!
  PIDS+=("$NODE_PID")
  if [[ "$want" == "unbound" ]]; then
    wait_line "$LOGS/$log" "$LINE_BIND_FAILED$listen" "$START_WAIT" "$NODE_PID"
  elif [[ "$want" == "auto" ]]; then
    wait_line "$LOGS/$log" "${LINE_LISTEN}[::]:${listen#auto:}" "$START_WAIT" "$NODE_PID"
  else
    wait_line "$LOGS/$log" "$LINE_LISTEN$listen" "$START_WAIT" "$NODE_PID"
  fi
  wait_ipc "$ns" "$dir" "$START_WAIT" "$NODE_PID"
}

# raven_init NS DIR NAME: init + prekey publish; sets INIT_ADDR, INIT_PUB and
# INIT_FP.
INIT_ADDR=""
INIT_PUB=""
INIT_FP=""
raven_init() {
  local ns=$1 dir=$2 name=$3 out
  mkdir -p "$dir"
  chmod 700 "$dir"
  out="$LOGS/$name.init.out"
  rv "$ns" "$dir" init >"$out" 2>&1 || fail "raven init ($name) failed"
  INIT_ADDR="$(sed -n 's/^address=//p' "$out" | head -n 1)"
  INIT_PUB="$(sed -n 's/^pub_hex=//p' "$out" | head -n 1)"
  INIT_FP="$(sed -n 's/^fingerprint=//p' "$out" | head -n 1)"
  if [[ -z "$INIT_ADDR" || -z "$INIT_PUB" || -z "$INIT_FP" ]]; then
    fail "raven init ($name) printed no address= / pub_hex= / fingerprint= line"
  fi
  rv "$ns" "$dir" prekey publish >"$LOGS/$name.prekey.out" 2>&1 \
    || fail "raven prekey publish ($name) failed"
}

# add_contact NS DIR TAG ADDR PUB DIAL [FP]: contact TAG (also its petname)
# with the LAN route DIAL; verified (pinned) when FP is given.
add_contact() {
  local ns=$1 dir=$2 tag=$3 addr=$4 pub=$5 dial=$6 fp=${7:-}
  local -a verify=()
  if [[ -n "$fp" ]]; then
    verify=(--verify-fp "$fp")
  fi
  rv "$ns" "$dir" contact add --address "$addr" --pub-hex "$pub" --petname "$tag" --tag "$tag" \
    --lan-dial "$dial" ${verify[@]+"${verify[@]}"} >>"$LOGS/contacts.out" 2>&1 \
    || fail "contact add $tag in $dir failed"
}

# set_lan NS DIR TAG DIAL: TAG's saved LAN route becomes DIAL.
set_lan() {
  rv "$1" "$2" contact set-addr --tag "$3" --lan "$4" >>"$LOGS/contacts.out" 2>&1 \
    || fail "contact set-addr --tag $3 --lan $4 in $2 failed"
}

# send_msg NS DIR TAG TEXT LABEL: `raven send --contact @TAG`, TEXT on stdin.
# Sets SEND_STATUS (DELIVERED, QUEUED, NOT_SENT, UNCONFIRMED, REFUSED or
# OTHER, read from the CLI's own outcome lines as the fault matrix reads
# them) and SEND_MS (how long it took); the output is LOGS/LABEL.send.out.
SEND_STATUS=""
SEND_MS=0
send_msg() {
  local ns=$1 dir=$2 tag=$3 text=$4 label=$5 out t0
  out="$LOGS/$label.send.out"
  t0=$(now_ms)
  printf '%s\n' "$text" | timeout "$SEND_TIMEOUT" ip netns exec "$ns" \
    env ${LAB_ENV[@]+"${LAB_ENV[@]}"} "$RAVEN" --data-dir "$dir" send --contact "@$tag" \
    >"$out" 2>&1 || true
  SEND_MS=$(($(now_ms) - t0))
  SEND_STATUS="$(awk '
    { sub(/^[[:space:]]+/, "") }
    /^status delivered/ && /confirmed receipt/ { print "DELIVERED"; found = 1; exit }
    { line[NR] = $0 }
    END {
      if (found) exit
      for (i = 1; i <= NR; i++) {
        if (line[i] ~ /^not delivered yet/) { print "QUEUED"; exit }
        if (line[i] ~ /^NOT SENT/) { print "NOT_SENT"; exit }
        if (line[i] ~ /^sent, delivery unconfirmed/) { print "UNCONFIRMED"; exit }
        if (line[i] ~ /^send refused/) { print "REFUSED"; exit }
      }
      print "OTHER"
    }' "$out")"
  echo "  $label: $SEND_STATUS in $((SEND_MS / 1000)).$(((SEND_MS % 1000) / 100))s"
}

# expect_send WANT WHAT: the last send ended WANT.
expect_send() {
  if [[ "$SEND_STATUS" != "$1" ]]; then
    fail "$2 ended $SEND_STATUS, not $1"
  fi
}

# inbox_count NS DIR TEXT: how many times TEXT is in the inbox, in INBOX_N
# (not printed: a `fail` in a command substitution would end only that
# subshell). A `raven inbox` that fails is tried again a second later (a
# transient failure under load), INBOX_TRIES times in all; one that keeps
# failing fails the run. A failed read is never read as 0 messages.
INBOX_N=0
INBOX_TRIES=3
inbox_count() {
  local out="$LOGS/inbox-count.out" try
  for ((try = 1; ; try++)); do
    if rv "$1" "$2" inbox >"$out" 2>&1; then
      break
    fi
    if ((try >= INBOX_TRIES)); then
      fail "raven inbox of $2 failed $try times in a row"
    fi
    cp "$out" "$LOGS/inbox-count.failed.out"
    note "raven inbox of $2 failed (try $try of $INBOX_TRIES); trying again"
    sleep 1
  done
  INBOX_N="$(grep -cF -- "$3" "$out" || true)"
}

# wait_inbox NS DIR TEXT SECS: until TEXT is in the inbox; then it must be
# there exactly once (2 s later). Sets WAITED_MS.
WAITED_MS=0
wait_inbox() {
  local ns=$1 dir=$2 text=$3 secs=$4 t0 n
  t0=$(now_ms)
  while :; do
    inbox_count "$ns" "$dir" "$text"
    n=$INBOX_N
    if [[ "$n" -ge 1 ]]; then
      break
    fi
    if ! within "$t0" "$secs"; then
      fail "'$text' not in the inbox of $dir within ${secs}s"
    fi
    sleep 0.5
  done
  WAITED_MS=$(($(now_ms) - t0))
  sleep 2
  inbox_count "$ns" "$dir" "$text"
  n=$INBOX_N
  if [[ "$n" -ne 1 ]]; then
    fail "the inbox of $dir shows '$text' $n times, expected exactly once"
  fi
}

# wait_log_re LOG ERE SECS: until a line of LOG matches ERE. Sets WAITED_MS.
wait_log_re() {
  local log=$1 re=$2 secs=$3 t0
  t0=$(now_ms)
  while ! grep -Eq -- "$re" "$log" 2>/dev/null; do
    if ! within "$t0" "$secs"; then
      fail "no line matching '$re' in $(basename "$log") within ${secs}s"
    fi
    sleep 0.5
  done
  WAITED_MS=$(($(now_ms) - t0))
}

# no_internet_claim NS DIR NAME: NAME's `raven doctor` says nothing about a
# working internet connection.
no_internet_claim() {
  local out="$LOGS/$3.doctor.out"
  rv "$1" "$2" doctor >"$out" 2>&1 || true
  if grep -iEq -- "$INTERNET_CLAIM_RE" "$out"; then
    fail "raven doctor ($3) claims internet: $(grep -iE -- "$INTERNET_CLAIM_RE" "$out" | head -n 3)"
  fi
  note "$3 doctor summary: $(sed -n '/^SUMMARY/,/^(technical/p' "$out" | tr -s ' ' | tr '\n' ' ' | cut -c1-300)"
}

# relay_peer_id FILE: relay_status.json's peer_id (nothing while the file is
# absent or partial).
relay_peer_id() {
  if [[ "$HAVE_PY" == "1" ]]; then
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["peer_id"])' "$1" 2>/dev/null || true
  else
    sed -n 's/.*"peer_id"[[:space:]]*:[[:space:]]*"\([1-9A-HJ-NP-Za-km-z]*\)".*/\1/p' "$1" | head -n 1
  fi
}

# no_online_advice FILE WHAT: FILE suggests no VPS, port forward or UPnP.
no_online_advice() {
  if grep -iEq -- "$ONLINE_ADVICE_RE" "$1"; then
    fail "$2 gives advice that needs an internet provider: $(grep -iE -- "$ONLINE_ADVICE_RE" "$1" | head -n 2)"
  fi
}

# new_run NAME: the run's dirs; sets RUN and LOGS.
new_run() {
  MODE=$1
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  RUN="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$RUN/logs"
  mkdir -p "$LOGS"
  echo "=== $MODE run (dirs under $RUN) ==="
}

# ---- the LAN part shared by lan-noprovider and router-dead-uplink ------------

# lan_part TAG SW A_NS B_NS A_IP B_IP: init A and B (sets A_DIR, B_DIR,
# A_PID, A_ADDR and A_PUB), unverified contacts with literal routes, delivery both ways,
# then a name route that is queued within NAME_SEND_MAX with the not-found
# text and delivered once the number is back.
A_DIR=""
B_DIR=""
A_PID=""
A_ADDR=""
A_PUB=""
lan_part() {
  local tag=$1 sw=$2 a_ns=$3 b_ns=$4 a_ip=$5 b_ip=$6 b_addr b_pub
  A_DIR="$RUN/a"
  B_DIR="$RUN/b"
  raven_init "$a_ns" "$A_DIR" a
  A_ADDR="$INIT_ADDR"
  A_PUB="$INIT_PUB"
  raven_init "$b_ns" "$B_DIR" b
  b_addr="$INIT_ADDR"
  b_pub="$INIT_PUB"
  start_node "$a_ns" "$A_DIR" a.service.log "$a_ip:$PORT"
  A_PID="$NODE_PID"
  start_node "$b_ns" "$B_DIR" b.service.log "$b_ip:$PORT"
  add_contact "$a_ns" "$A_DIR" bob "$b_addr" "$b_pub" "$b_ip:$PORT"
  add_contact "$b_ns" "$B_DIR" alice "$A_ADDR" "$A_PUB" "$a_ip:$PORT"
  reset_pair_counters "$sw"

  echo "--- literal routes both ways"
  send_msg "$a_ns" "$A_DIR" bob "$tag-a2b" a2b
  expect_send DELIVERED "A -> B"
  wait_inbox "$b_ns" "$B_DIR" "$tag-a2b" "$INBOX_WAIT"
  send_msg "$b_ns" "$B_DIR" alice "$tag-b2a" b2a
  expect_send DELIVERED "B -> A"
  wait_inbox "$a_ns" "$A_DIR" "$tag-b2a" "$INBOX_WAIT"

  echo "--- a computer name instead of B's number"
  set_lan "$a_ns" "$A_DIR" bob "x-nohost.local:$PORT"
  send_msg "$a_ns" "$A_DIR" bob "$tag-name" name
  expect_send QUEUED "A -> B at x-nohost.local"
  if [[ "$SEND_MS" -gt $((NAME_SEND_MAX * 1000)) ]]; then
    fail "the send to a name that resolves nowhere took ${SEND_MS} ms (at most ${NAME_SEND_MAX} s)"
  fi
  grep -Fq -- "$NOT_FOUND" "$LOGS/name.send.out" \
    || fail "the name send does not say '$NOT_FOUND'"
  inbox_count "$b_ns" "$B_DIR" "$tag-name"
  if ((INBOX_N != 0)); then
    fail "'$tag-name' arrived while A's route was a name nobody answers"
  fi
  set_lan "$a_ns" "$A_DIR" bob "$b_ip:$PORT"
  wait_inbox "$b_ns" "$B_DIR" "$tag-name" "$FIXED_DELIVER"
  note "the queued message arrived $((WAITED_MS / 1000)) s after the number was saved again"
}

# ---- lan-noprovider ------------------------------------------------------------

run_lan_noprovider() {
  local sw="${NSP}-sw" ha="${NSP}-hA" hb="${NSP}-hB" a_other b_other
  new_run lan-noprovider
  switch_add "$sw" br0
  ns_add "$ha"
  ns_add "$hb"
  plug "$ha" eth0 "$sw" br0 pa 192.168.2.10/24
  plug "$hb" eth0 "$sw" br0 pb 192.168.2.20/24
  no_default_route "$ha"
  no_default_route "$hb"
  pair_counters "$sw" 192.168.2.10 192.168.2.20
  LAB_ENV=(RAVEN_LAB_OFFLINE=1 RAVEN_LAB_NOISE_PIN=1)
  lan_part noprov "$sw" "$ha" "$hb" 192.168.2.10 192.168.2.20
  a_other="$(bridge_count "$sw" a_other)"
  b_other="$(bridge_count "$sw" b_other)"
  note "bridge: a_peer=$(bridge_count "$sw" a_peer) b_peer=$(bridge_count "$sw" b_peer)" \
    "a_dns=$(bridge_count "$sw" a_dns) b_dns=$(bridge_count "$sw" b_dns) a_other=$a_other b_other=$b_other"
  if [[ "$a_other" -ne 0 || "$b_other" -ne 0 ]]; then
    fail "packets to something other than the peer or UDP 53: A $a_other, B $b_other"
  fi
  no_internet_claim "$ha" "$A_DIR" a
}

# ---- router-dead-uplink --------------------------------------------------------

run_router_dead_uplink() {
  local sw="${NSP}-sw" r="${NSP}-r" up="${NSP}-up" ha="${NSP}-hA" hb="${NSP}-hB"
  local hc="${NSP}-hC" a_other b_other relay_dir relay_pid peer deadline via
  local c_dir c_addr c_pub c_fp c_peer c_pid t_c
  new_run router-dead-uplink
  switch_add "$sw" br0
  ns_add "$r"
  ns_add "$up"
  ns_add "$ha"
  ns_add "$hb"
  ns_add "$hc"
  plug "$r" lan "$sw" br0 pr 192.168.3.1/24
  plug "$ha" eth0 "$sw" br0 pa 192.168.3.10/24
  plug "$hb" eth0 "$sw" br0 pb 192.168.3.20/24
  plug "$hc" eth0 "$sw" br0 pc 192.168.3.30/24
  ip -n "$ha" route add default via 192.168.3.1
  ip -n "$hb" route add default via 192.168.3.1
  ip -n "$hc" route add default via 192.168.3.1
  # The dead uplink: R forwards nothing to its WAN, and answers no DNS.
  ip -n "$r" link add wan type veth peer name uplink netns "$up"
  ip -n "$r" addr add 203.0.113.2/24 dev wan
  ip -n "$r" link set wan up
  ip -n "$up" addr add "$DEAD_RELAY_IP/24" dev uplink
  ip -n "$up" link set uplink up
  ip -n "$r" route add default via "$DEAD_RELAY_IP"
  ip netns exec "$r" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$r" nft -f - <<'EOF' || fail "nft rejected the dead uplink's ruleset"
table ip raven_dead {
  counter dns {
  }
  counter wan_out {
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    oifname "wan" udp dport 53 counter name "dns" drop
    oifname "wan" tcp dport 53 counter name "dns" drop
    oifname "wan" counter name "wan_out" drop
  }
  chain input {
    type filter hook input priority 0; policy accept;
    udp dport 53 counter name "dns" drop
    tcp dport 53 counter name "dns" drop
  }
}
EOF
  pair_counters "$sw" 192.168.3.10 192.168.3.20
  LAB_ENV=(RAVEN_LAB_OFFLINE=1 RAVEN_LAB_NOISE_PIN=1)
  lan_part dead "$sw" "$ha" "$hb" 192.168.3.10 192.168.3.20
  a_other="$(bridge_count "$sw" a_other)"
  b_other="$(bridge_count "$sw" b_other)"
  note "bridge: a_dns=$(bridge_count "$sw" a_dns) b_dns=$(bridge_count "$sw" b_dns)" \
    "a_other=$a_other b_other=$b_other; R: dns=$(nft_counter "$r" ip raven_dead dns || echo '?')" \
    "wan_out=$(nft_counter "$r" ip raven_dead wan_out || echo '?')"
  if [[ "$a_other" -ne 0 || "$b_other" -ne 0 ]]; then
    fail "the LAN part sent packets to something other than the peer or UDP 53: A $a_other, B $b_other"
  fi
  no_internet_claim "$ha" "$A_DIR" a

  echo "--- the p2p lab unlock and a relay behind the dead WAN"
  relay_dir="$RUN/relay"
  mkdir -p "$relay_dir"
  chmod 700 "$relay_dir"
  LAB_ENV=(RAVEN_LAB_OFFLINE=1 RAVEN_LAB_NOISE_PIN=1 RAVEN_LAB_TEST_A=1)
  ip netns exec "$up" env RAVEN_LAB_TEST_A=1 "$NODE" relay --data-dir "$relay_dir" \
    --listen "$DEAD_RELAY_IP:7423" >"$LOGS/relay.log" 2>&1 &
  relay_pid=$!
  PIDS+=("$relay_pid")
  peer=""
  deadline=$((SECONDS + START_WAIT))
  while ((SECONDS < deadline)) && [[ -z "$peer" ]]; do
    if [[ -s "$relay_dir/relay_status.json" ]]; then
      peer="$(relay_peer_id "$relay_dir/relay_status.json")"
    fi
    require_alive "$relay_pid"
    sleep 0.2
  done
  [[ -n "$peer" ]] || fail "relay_status.json with a peer_id not written within ${START_WAIT}s"
  via="/ip4/$DEAD_RELAY_IP/tcp/7423/p2p/$peer"
  # Carol: a verified contact A met on this LAN once (a session), whose only
  # saved route is then p2p through the relay behind the dead WAN.
  c_dir="$RUN/c"
  raven_init "$hc" "$c_dir" c
  c_addr="$INIT_ADDR"
  c_pub="$INIT_PUB"
  c_fp="$INIT_FP"
  rv "$hc" "$c_dir" whoami --card --via "$via" >"$LOGS/c.card.out" 2>&1 || fail "raven whoami --card (C) failed"
  c_peer="$(grep -m 1 -oE ' p2p=[1-9A-HJ-NP-Za-km-z]+' "$LOGS/c.card.out" | cut -d= -f2 || true)"
  [[ -n "$c_peer" ]] || fail "Carol's card has no p2p= field"
  start_node "$hc" "$c_dir" c.service.log "192.168.3.30:$PORT"
  c_pid="$NODE_PID"
  add_contact "$ha" "$A_DIR" carol "$c_addr" "$c_pub" "192.168.3.30:$PORT" "$c_fp"
  add_contact "$hc" "$c_dir" alice "$A_ADDR" "$A_PUB" "192.168.3.10:$PORT"
  send_msg "$ha" "$A_DIR" carol "dead-carol-lan" carol-lan
  expect_send DELIVERED "A -> Carol on the LAN (the session)"
  stop_pid "$c_pid"
  rv "$ha" "$A_DIR" contact set-addr --tag carol --clear lan >>"$LOGS/contacts.out" 2>&1 \
    || fail "A set-addr carol --clear lan failed"
  rv "$ha" "$A_DIR" contact set-addr --tag carol --p2p "$c_peer" --via "$via" >>"$LOGS/contacts.out" 2>&1 \
    || fail "A set-addr carol --p2p --via failed"
  stop_pid "$A_PID"
  start_node "$ha" "$A_DIR" a2.service.log "192.168.3.10:$PORT" bound \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$via"
  A_PID="$NODE_PID"
  wait_line "$LOGS/a2.service.log" "$LINE_HOST_UP" "$START_WAIT" "$A_PID"
  reset_pair_counters "$sw"

  send_msg "$ha" "$A_DIR" carol "dead-p2p" p2p
  t_c=$SEND_MS
  expect_send QUEUED "A -> Carol (p2p only, the relay behind the dead uplink)"
  if [[ "$t_c" -gt $((DEAD_SEND_MAX * 1000)) ]]; then
    fail "A -> Carol (p2p only) took ${t_c} ms (at most ${DEAD_SEND_MAX} s)"
  fi
  no_online_advice "$LOGS/p2p.send.out" "A -> Carol"
  if grep -Fq -- "$ASLEEP" "$LOGS/p2p.send.out"; then
    note "A -> Carol says '$ASLEEP'"
  else
    note "A -> Carol does not say '$ASLEEP': $(tr -s ' \n' ' ' <"$LOGS/p2p.send.out" | cut -c1-300)"
  fi
  send_msg "$ha" "$A_DIR" bob "dead-lan" lan
  expect_send DELIVERED "A -> B right after the p2p send"
  if [[ "$SEND_MS" -gt $((DEAD_SEND_MAX * 1000)) ]]; then
    fail "A -> B took ${SEND_MS} ms while Carol's message waits (at most ${DEAD_SEND_MAX} s)"
  fi
  wait_inbox "$hb" "$B_DIR" "dead-lan" "$INBOX_WAIT"
  send_msg "$hb" "$B_DIR" alice "dead-lan-back" back
  expect_send DELIVERED "B -> A"
  if [[ "$SEND_MS" -gt $((DEAD_SEND_MAX * 1000)) ]]; then
    fail "B -> A took ${SEND_MS} ms (at most ${DEAD_SEND_MAX} s)"
  fi
  wait_inbox "$ha" "$A_DIR" "dead-lan-back" "$INBOX_WAIT"
  note "p2p part: R wan_out=$(nft_counter "$r" ip raven_dead wan_out || echo '?')" \
    "(A's dials toward the relay, all dropped), bridge a_other=$(bridge_count "$sw" a_other)"
  # Where a claim could appear: the p2p host is up (its reach_class and
  # internet rows are printed), its relay behind the dead uplink. The LAN
  # parts' checks above run with no p2p host, where doctor prints neither.
  no_internet_claim "$ha" "$A_DIR" a-p2p
}

# ---- hotspot-ap ------------------------------------------------------------------

# hs_start ENV_TAG: the three nodes on the hotspot (AP, C1, C2).
AP_PID=""
C1_PID=""
C2_PID=""
hs_start() {
  start_node "$NS_AP" "$AP_DIR" "ap.$1.log" "10.42.0.1:$PORT"
  AP_PID="$NODE_PID"
  start_node "$NS_C1" "$C1_DIR" "c1.$1.log" "10.42.0.2:$PORT"
  C1_PID="$NODE_PID"
  start_node "$NS_C2" "$C2_DIR" "c2.$1.log" "10.42.0.3:$PORT"
  C2_PID="$NODE_PID"
}

hs_stop() {
  stop_pid "$AP_PID"
  stop_pid "$C1_PID"
  stop_pid "$C2_PID"
}

NS_AP=""
NS_C1=""
NS_C2=""
AP_DIR=""
C1_DIR=""
C2_DIR=""
run_hotspot_ap() {
  local home="${NSP}-home" ap_addr ap_pub ap_fp c1_addr c1_pub c1_fp c2_addr c2_pub c2_fp
  local ns port held deadline iso
  NS_AP="${NSP}-ap"
  NS_C1="${NSP}-c1"
  NS_C2="${NSP}-c2"
  new_run hotspot-ap
  AP_DIR="$RUN/ap"
  C1_DIR="$RUN/c1"
  C2_DIR="$RUN/c2"
  switch_add "$home" br0
  ns_add "$NS_AP"
  ns_add "$NS_C1"
  ns_add "$NS_C2"
  # Home: where they met (the addresses their cards keep).
  plug "$NS_AP" eth0 "$home" br0 hap 192.168.1.1/24
  plug "$NS_C1" eth0 "$home" br0 hc1 192.168.1.2/24
  plug "$NS_C2" eth0 "$home" br0 hc2 192.168.1.3/24
  # The hotspot: AP's own bridge, the clients' second link down until they move.
  ip -n "$NS_AP" link add br-ap type bridge
  ip -n "$NS_AP" addr add 10.42.0.1/24 dev br-ap
  ip -n "$NS_AP" link set br-ap up
  ip netns exec "$NS_AP" sysctl -qw net.ipv4.ip_forward=0
  ip -n "$NS_AP" link add p1 type veth peer name wlan0 netns "$NS_C1"
  ip -n "$NS_AP" link add p2 type veth peer name wlan0 netns "$NS_C2"
  for port in p1 p2; do
    ip -n "$NS_AP" link set "$port" master br-ap
    ip -n "$NS_AP" link set "$port" up
  done
  SWITCHES+=("$NS_AP")
  ip netns exec "$NS_AP" nft -f - <<'EOF' || fail "nft rejected br-ap's table"
table bridge raven_off {
  counter iso {
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
  }
}
EOF

  echo "--- they meet at home: verified contacts, sessions both ways"
  LAB_ENV=()
  raven_init "$NS_AP" "$AP_DIR" ap
  ap_addr="$INIT_ADDR"; ap_pub="$INIT_PUB"; ap_fp="$INIT_FP"
  raven_init "$NS_C1" "$C1_DIR" c1
  c1_addr="$INIT_ADDR"; c1_pub="$INIT_PUB"; c1_fp="$INIT_FP"
  raven_init "$NS_C2" "$C2_DIR" c2
  c2_addr="$INIT_ADDR"; c2_pub="$INIT_PUB"; c2_fp="$INIT_FP"
  start_node "$NS_AP" "$AP_DIR" ap.home.log "192.168.1.1:$PORT"
  AP_PID="$NODE_PID"
  start_node "$NS_C1" "$C1_DIR" c1.home.log "192.168.1.2:$PORT"
  C1_PID="$NODE_PID"
  start_node "$NS_C2" "$C2_DIR" c2.home.log "192.168.1.3:$PORT"
  C2_PID="$NODE_PID"
  add_contact "$NS_AP" "$AP_DIR" c1 "$c1_addr" "$c1_pub" "192.168.1.2:$PORT" "$c1_fp"
  add_contact "$NS_AP" "$AP_DIR" c2 "$c2_addr" "$c2_pub" "192.168.1.3:$PORT" "$c2_fp"
  add_contact "$NS_C1" "$C1_DIR" ap "$ap_addr" "$ap_pub" "192.168.1.1:$PORT" "$ap_fp"
  add_contact "$NS_C1" "$C1_DIR" c2 "$c2_addr" "$c2_pub" "192.168.1.3:$PORT" "$c2_fp"
  add_contact "$NS_C2" "$C2_DIR" ap "$ap_addr" "$ap_pub" "192.168.1.1:$PORT" "$ap_fp"
  add_contact "$NS_C2" "$C2_DIR" c1 "$c1_addr" "$c1_pub" "192.168.1.2:$PORT" "$c1_fp"
  send_msg "$NS_AP" "$AP_DIR" c1 home-ap-c1 home1; expect_send DELIVERED "home AP -> C1"
  send_msg "$NS_AP" "$AP_DIR" c2 home-ap-c2 home2; expect_send DELIVERED "home AP -> C2"
  send_msg "$NS_C1" "$C1_DIR" ap home-c1-ap home3; expect_send DELIVERED "home C1 -> AP"
  send_msg "$NS_C1" "$C1_DIR" c2 home-c1-c2 home4; expect_send DELIVERED "home C1 -> C2"
  send_msg "$NS_C2" "$C2_DIR" ap home-c2-ap home5; expect_send DELIVERED "home C2 -> AP"
  send_msg "$NS_C2" "$C2_DIR" c1 home-c2-c1 home6; expect_send DELIVERED "home C2 -> C1"
  hs_stop

  echo "--- to the hotspot: nobody has the others' new addresses"
  for ns in "$NS_AP" "$NS_C1" "$NS_C2"; do
    ip -n "$ns" addr flush dev eth0
    ip -n "$ns" link set eth0 down
  done
  ip -n "$NS_C1" addr add 10.42.0.2/24 dev wlan0
  ip -n "$NS_C1" link set wlan0 up
  ip -n "$NS_C1" route add default via 10.42.0.1
  ip -n "$NS_C2" addr add 10.42.0.3/24 dev wlan0
  ip -n "$NS_C2" link set wlan0 up
  ip -n "$NS_C2" route add default via 10.42.0.1
  hs_start hotspot

  echo "--- (1) today: stale addresses, then a typed one"
  send_msg "$NS_AP" "$AP_DIR" c1 hs-ap2c1 ap2c1
  expect_send QUEUED "AP -> C1 at C1's old address"
  send_msg "$NS_C1" "$C1_DIR" ap hs-c1-stale stale
  expect_send QUEUED "C1 -> AP at AP's old address"
  note "C1 -> AP on the stale address: $(tr -s ' \n' ' ' <"$LOGS/stale.send.out" | cut -c1-240)"
  inbox_count "$NS_C1" "$C1_DIR" hs-ap2c1
  if ((INBOX_N != 0)); then
    fail "AP's message reached C1 before C1 ever connected to the hotspot"
  fi
  rv "$NS_C1" "$C1_DIR" contact set-dial --tag ap --lan-dial "10.42.0.1:$PORT" \
    >>"$LOGS/contacts.out" 2>&1 || fail "C1 contact set-dial ap failed"
  send_msg "$NS_C1" "$C1_DIR" ap hs-c1-fixed fixed
  expect_send DELIVERED "C1 -> AP after set-dial 10.42.0.1:$PORT"
  wait_inbox "$NS_AP" "$AP_DIR" hs-c1-fixed "$INBOX_WAIT"
  wait_inbox "$NS_C1" "$C1_DIR" hs-ap2c1 "$DIAL_BACK_WAIT"
  note "AP's queued message reached C1 $((WAITED_MS / 1000)) s after C1's first link"
  wait_inbox "$NS_AP" "$AP_DIR" hs-c1-stale "$FIXED_DELIVER"
  note "C1's queued message arrived $((WAITED_MS / 1000)) s after that"
  echo "--- (2) a client finding the AP with no typed address: CP.13 not built, not run"

  echo "--- (3) the LAN beacon: C1 <-> C2 with only their old addresses saved"
  hs_stop
  LAB_ENV=(RAVEN_LAB_LAN_BEACON=1)
  hs_start beacon
  beacon_find "$NS_C1" "$C1_DIR" c2 hs-beacon-c1c2 c1c2 "C1 -> C2"
  wait_inbox "$NS_C2" "$C2_DIR" hs-beacon-c1c2 "$INBOX_WAIT"
  beacon_find "$NS_C2" "$C2_DIR" c1 hs-beacon-c2c1 c2c1 "C2 -> C1"
  wait_inbox "$NS_C1" "$C1_DIR" hs-beacon-c2c1 "$INBOX_WAIT"
  # The book (plain: these profiles are not sealed) keeps C2's old address
  # only: a find is never saved.
  grep -Fq -- "192.168.1.3:$PORT" "$C1_DIR/contacts.json" \
    || fail "C1's book lost C2's old address"
  if grep -Fq -- "10.42.0.3" "$C1_DIR/contacts.json"; then
    fail "C1's book saved what the beacon found for C2"
  fi
  hs_stop
  LAB_ENV=()
  hs_start hotspot2

  echo "--- (4) client isolation, then custody through the AP"
  # The clients tell each other (and C2 the AP) their new addresses.
  rv "$NS_C2" "$C2_DIR" contact set-dial --tag ap --lan-dial "10.42.0.1:$PORT" \
    >>"$LOGS/contacts.out" 2>&1 || fail "C2 contact set-dial ap failed"
  rv "$NS_C1" "$C1_DIR" contact set-dial --tag c2 --lan-dial "10.42.0.3:$PORT" \
    >>"$LOGS/contacts.out" 2>&1 || fail "C1 contact set-dial c2 failed"
  rv "$NS_C2" "$C2_DIR" contact set-dial --tag c1 --lan-dial "10.42.0.2:$PORT" \
    >>"$LOGS/contacts.out" 2>&1 || fail "C2 contact set-dial c1 failed"
  ip netns exec "$NS_AP" nft add rule bridge raven_off forward \
    iifname '"p1"' oifname '"p2"' counter name '"iso"' drop
  ip netns exec "$NS_AP" nft add rule bridge raven_off forward \
    iifname '"p2"' oifname '"p1"' counter name '"iso"' drop
  send_msg "$NS_C1" "$C1_DIR" c2 hs-iso iso
  expect_send QUEUED "C1 -> C2 behind client isolation"
  note "C1 -> C2 behind isolation: $(tr -s ' \n' ' ' <"$LOGS/iso.send.out" | cut -c1-240)"
  hs_stop
  LAB_ENV=(RAVEN_LAB_TEST_A=1 RAVEN_LAB_CUSTODY_AFTER_MS=0 RAVEN_LAB_CUSTODY_FETCH_MS=1000)
  hs_start custody
  rv "$NS_AP" "$AP_DIR" node custody on --yes >"$LOGS/ap.custody.out" 2>&1 || fail "AP node custody on failed"
  rv "$NS_C1" "$C1_DIR" contact set-addr --tag c2 --custodian @ap >>"$LOGS/contacts.out" 2>&1 \
    || fail "C1 set-addr --custodian @ap failed"
  rv "$NS_C2" "$C2_DIR" contact set-addr --tag c1 --custodian @ap >>"$LOGS/contacts.out" 2>&1 \
    || fail "C2 set-addr --custodian @ap failed"
  send_msg "$NS_C1" "$C1_DIR" c2 hs-via-ap via
  if [[ "$SEND_STATUS" == "DELIVERED" ]]; then
    fail "C1 -> C2 was delivered directly through the isolation rule"
  fi
  held=""
  deadline=$((SECONDS + CUSTODY_HELD_WAIT))
  while ((SECONDS < deadline)); do
    held="$(rv "$NS_AP" "$AP_DIR" node custody status 2>/dev/null | sed -n 's/.*held \([0-9]*\) sealed.*/\1/p' | head -n 1)"
    if [[ -n "$held" && "$held" -ge 1 ]]; then
      break
    fi
    sleep 1
  done
  [[ -n "$held" && "$held" -ge 1 ]] || fail "AP holds nothing for C2 within ${CUSTODY_HELD_WAIT}s"
  wait_inbox "$NS_C2" "$C2_DIR" hs-via-ap "$CUSTODY_FETCH_WAIT"
  note "C2 fetched the message from AP $((WAITED_MS / 1000)) s after AP held it"
  wait_log_re "$LOGS/c1.custody.log" "$ACK_FETCHED_RE" "$CUSTODY_ACK_WAIT"
  note "C2's ACK reached C1 through AP $((WAITED_MS / 1000)) s later"
  inbox_count "$NS_C2" "$C2_DIR" hs-iso
  note "hs-iso (queued before custody) reached C2 $INBOX_N time(s)"
  iso="$(nft_counter "$NS_AP" bridge raven_off iso)" || fail "cannot read br-ap's iso counter"
  [[ "$iso" -gt 0 ]] || fail "the isolation rule dropped nothing: C1 never tried C2 directly"
  note "br-ap dropped $iso frames between C1 and C2"
}

# beacon_find NS DIR TAG TEXT LABEL WHAT: a send with no right address saved
# that the LAN beacon delivers: DELIVERED within BEACON_FIND_MAX, through a
# find.
beacon_find() {
  send_msg "$1" "$2" "$3" "$4" "$5"
  expect_send DELIVERED "$6 through the beacon"
  if [[ "$SEND_MS" -gt $((BEACON_FIND_MAX * 1000)) ]]; then
    fail "$6 through the beacon took ${SEND_MS} ms (at most ${BEACON_FIND_MAX} s)"
  fi
  grep -Fq -- "$BEACON_FOUND" "$LOGS/$5.send.out" \
    || fail "$6 does not say '$BEACON_FOUND'"
  note "$6: $(grep -F -- "$BEACON_FOUND" "$LOGS/$5.send.out" | head -n 1 | tr -s ' ')"
}

# ---- cable-linklocal ---------------------------------------------------------------

# cable_round GATE: one round on fresh profiles, A with RAVEN_LAB_OFFLINE=GATE.
cable_round() {
  local gate=$1 ha="${NSP}-hA" hb="${NSP}-hB" a_dir b_dir a_addr a_pub b_addr b_pub
  local a_pid b_pid log t_add tag="cable$1" bind_ms
  a_dir="$RUN/a$gate"
  b_dir="$RUN/b$gate"
  log="a$gate.service.log"
  ip -n "$ha" addr flush dev eth0
  LAB_ENV=()
  raven_init "$ha" "$a_dir" "a$gate"
  a_addr="$INIT_ADDR"; a_pub="$INIT_PUB"
  raven_init "$hb" "$b_dir" "b$gate"
  b_addr="$INIT_ADDR"; b_pub="$INIT_PUB"
  add_contact "$ha" "$a_dir" bob "$b_addr" "$b_pub" "169.254.20.2:$PORT"
  add_contact "$hb" "$b_dir" alice "$a_addr" "$a_pub" "169.254.10.1:$PORT"
  start_node "$hb" "$b_dir" "b$gate.service.log" "169.254.20.2:$PORT"
  b_pid="$NODE_PID"

  echo "--- round RAVEN_LAB_OFFLINE=$gate: A's node starts before its address exists"
  LAB_ENV=(RAVEN_LAB_OFFLINE="$gate")
  start_node "$ha" "$a_dir" "$log" "169.254.10.1:$PORT" unbound
  a_pid="$NODE_PID"
  wait_line "$LOGS/$log" "$LINE_WATCHING_NONE" "$NETWATCH_WAIT" "$a_pid"
  rv "$ha" "$a_dir" doctor >"$LOGS/a$gate.doctor.before.out" 2>&1 || true
  grep -Fq -- "receiving: no (addr_not_here 169.254.10.1:$PORT)" "$LOGS/a$gate.doctor.before.out" \
    || fail "A's doctor does not say addr_not_here before the address exists"
  # One more retry after this takes up to 30 s (RESTART_BACKOFF_MAX).
  wait_line "$LOGS/$log" "retrying in 16s" "$BIND_BACKOFF_WAIT" "$a_pid"
  ip -n "$ha" addr add 169.254.10.1/16 dev eth0
  t_add=$(now_ms)
  wait_line "$LOGS/$log" "$LINE_LISTEN""169.254.10.1:$PORT" "$BIND_AFTER_ADDR" "$a_pid"
  bind_ms=$(($(now_ms) - t_add))
  note "A bound 169.254.10.1:$PORT $((bind_ms / 1000)) s after the address was added"
  if [[ "$gate" == "1" ]]; then
    wait_line "$LOGS/$log" "$LINE_CABLE" "$NETWATCH_WAIT" "$a_pid"
  else
    sleep "$NETWATCH_WAIT"
    if grep -Fq -- "$LINE_CABLE" "$LOGS/$log"; then
      fail "netwatch counted the cable with RAVEN_LAB_OFFLINE=0"
    fi
  fi
  note "A's netwatch lines: $(grep -F 'raven-node netwatch:' "$LOGS/$log" | tr '\n' '|' | cut -c1-300)"
  rv "$ha" "$a_dir" doctor >"$LOGS/a$gate.doctor.after.out" 2>&1 || true
  if grep -Fq -- "addr_not_here" "$LOGS/a$gate.doctor.after.out"; then
    fail "A's doctor still says addr_not_here after the bind"
  fi

  send_msg "$ha" "$a_dir" bob "$tag-a2b" "a2b$gate"
  expect_send DELIVERED "A -> B over the cable"
  wait_inbox "$hb" "$b_dir" "$tag-a2b" "$INBOX_WAIT"
  send_msg "$hb" "$b_dir" alice "$tag-b2a" "b2a$gate"
  expect_send DELIVERED "B -> A over the cable"
  wait_inbox "$ha" "$a_dir" "$tag-b2a" "$INBOX_WAIT"
  stop_pid "$a_pid"
  stop_pid "$b_pid"
}

run_cable_linklocal() {
  local ha="${NSP}-hA" hb="${NSP}-hB"
  new_run cable-linklocal
  ns_add "$ha"
  ns_add "$hb"
  ip -n "$ha" link add eth0 type veth peer name eth0 netns "$hb"
  ip -n "$ha" link set eth0 up
  ip -n "$hb" addr add 169.254.20.2/16 dev eth0
  ip -n "$hb" link set eth0 up
  no_default_route "$ha"
  no_default_route "$hb"
  cable_round 0
  cable_round 1
  cable_fe80
}

# cable_fe80: the third round on fresh profiles (P3.C5): IPv6 link-local
# with its zone, `auto` listeners under RAVEN_LAB_LAN_AUTO=1.
cable_fe80() {
  local ha="${NSP}-hA" hb="${NSP}-hB" a_dir="$RUN/a6" b_dir="$RUN/b6" a_addr a_pub b_addr b_pub
  local a_pid b_pid ns
  echo "--- round fe80: auto listeners, link-local addresses with their zone"
  for ns in "$ha" "$hb"; do
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.eth0.disable_ipv6=0
  done
  ip -n "$ha" addr add fe80::10/64 dev eth0 nodad
  ip -n "$hb" addr add fe80::20/64 dev eth0 nodad
  LAB_ENV=()
  raven_init "$ha" "$a_dir" a6
  a_addr="$INIT_ADDR"; a_pub="$INIT_PUB"
  raven_init "$hb" "$b_dir" b6
  b_addr="$INIT_ADDR"; b_pub="$INIT_PUB"
  add_contact "$ha" "$a_dir" bob "$b_addr" "$b_pub" "[fe80::20%eth0]:$PORT"
  add_contact "$hb" "$b_dir" alice "$a_addr" "$a_pub" "[fe80::10%eth0]:$PORT"
  LAB_ENV=(RAVEN_LAB_LAN_AUTO=1)
  start_node "$hb" "$b_dir" b6.service.log "auto:$PORT" auto
  b_pid="$NODE_PID"
  start_node "$ha" "$a_dir" a6.service.log "auto:$PORT" auto
  a_pid="$NODE_PID"
  rv "$ha" "$a_dir" lan status >"$LOGS/a6.lan.out" 2>&1 || true
  note "A's lan status: $(tr -s ' \n' ' ' <"$LOGS/a6.lan.out" | cut -c1-200)"
  send_msg "$ha" "$a_dir" bob cable6-a2b a2b6
  expect_send DELIVERED "A -> B at [fe80::20%eth0]"
  wait_inbox "$hb" "$b_dir" cable6-a2b "$INBOX_WAIT"
  send_msg "$hb" "$b_dir" alice cable6-b2a b2a6
  expect_send DELIVERED "B -> A at [fe80::10%eth0]"
  wait_inbox "$ha" "$a_dir" cable6-b2a "$INBOX_WAIT"
  stop_pid "$a_pid"
  stop_pid "$b_pid"
}

# ---- three-rooms ---------------------------------------------------------------------

# unreleased DIR: rows of DIR's friend custody store not released yet (read
# only; "?" without python3 or a store).
unreleased() {
  if [[ "$HAVE_PY" != "1" || ! -f "$1/friend_custody.sqlite" ]]; then
    echo "?"
    return 0
  fi
  python3 - "$1/friend_custody.sqlite" <<'EOF' 2>/dev/null || echo "?"
import sqlite3, sys
con = sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True)
print(con.execute('SELECT COUNT(*) FROM custody_objects_v1 WHERE released_at_ms IS NULL').fetchone()[0])
EOF
}

# run_three_rooms [WAY]: WAY "hints" (the default: route hints on in the
# rooms) or "beacon" (route hints off, the LAN beacon on: three-rooms-beacon).
run_three_rooms() {
  local way=${1:-hints}
  local home="${NSP}-home" r1="${NSP}-room1" r2="${NSP}-room2"
  local ha="${NSP}-hA" hb="${NSP}-hB" hc="${NSP}-hC" a_dir b_dir c_dir
  local a_addr a_pub a_fp b_addr b_pub b_fp c_addr c_pub c_fp a_pid b_pid c_pid
  local held deadline n pins_dir pin1 pin2 f
  if [[ "$way" == "beacon" ]]; then
    new_run three-rooms-beacon
  else
    new_run three-rooms
  fi
  a_dir="$RUN/a"
  b_dir="$RUN/b"
  c_dir="$RUN/c"
  switch_add "$home" br0
  switch_add "$r1" br1
  switch_add "$r2" br2
  ns_add "$ha"
  ns_add "$hb"
  ns_add "$hc"
  # One /16: a laptop keeps its address in any room; the rooms are separate
  # links, so only laptops in the same room can reach each other.
  plug "$ha" eth0 "$home" br0 pa 192.168.1.10/16
  plug "$hb" eth0 "$home" br0 pb 192.168.2.20/16
  plug "$hc" eth0 "$home" br0 pc 192.168.1.30/16

  echo "--- at home: verified, pinned, sessions; C holds mail for A and B (route hints off)"
  LAB_ENV=(RAVEN_LAB_TEST_A=1 RAVEN_LAB_CUSTODY_AFTER_MS=0 RAVEN_LAB_CUSTODY_FETCH_MS=1000
    RAVEN_LAB_NOISE_PIN=1)
  raven_init "$ha" "$a_dir" a
  a_addr="$INIT_ADDR"; a_pub="$INIT_PUB"; a_fp="$INIT_FP"
  raven_init "$hb" "$b_dir" b
  b_addr="$INIT_ADDR"; b_pub="$INIT_PUB"; b_fp="$INIT_FP"
  raven_init "$hc" "$c_dir" c
  c_addr="$INIT_ADDR"; c_pub="$INIT_PUB"; c_fp="$INIT_FP"
  start_node "$ha" "$a_dir" a.home.log "192.168.1.10:$PORT"
  a_pid="$NODE_PID"
  start_node "$hb" "$b_dir" b.home.log "192.168.2.20:$PORT"
  b_pid="$NODE_PID"
  start_node "$hc" "$c_dir" c.home.log "192.168.1.30:$PORT"
  c_pid="$NODE_PID"
  add_contact "$ha" "$a_dir" bob "$b_addr" "$b_pub" "192.168.2.20:$PORT" "$b_fp"
  add_contact "$ha" "$a_dir" carol "$c_addr" "$c_pub" "192.168.1.30:$PORT" "$c_fp"
  add_contact "$hb" "$b_dir" alice "$a_addr" "$a_pub" "192.168.1.10:$PORT" "$a_fp"
  add_contact "$hb" "$b_dir" carol "$c_addr" "$c_pub" "192.168.1.30:$PORT" "$c_fp"
  add_contact "$hc" "$c_dir" alice "$a_addr" "$a_pub" "192.168.1.10:$PORT" "$a_fp"
  add_contact "$hc" "$c_dir" bob "$b_addr" "$b_pub" "192.168.2.20:$PORT" "$b_fp"
  rv "$hc" "$c_dir" node custody on --yes >"$LOGS/c.custody.out" 2>&1 || fail "C node custody on failed"
  rv "$ha" "$a_dir" contact set-addr --tag bob --custodian @carol >>"$LOGS/contacts.out" 2>&1 \
    || fail "A set-addr --custodian @carol failed"
  rv "$hb" "$b_dir" contact set-addr --tag alice --custodian @carol >>"$LOGS/contacts.out" 2>&1 \
    || fail "B set-addr --custodian @carol failed"
  send_msg "$ha" "$a_dir" bob rooms-home-ab home1; expect_send DELIVERED "home A -> B"
  send_msg "$ha" "$a_dir" carol rooms-home-ac home2; expect_send DELIVERED "home A -> C"
  send_msg "$hb" "$b_dir" carol rooms-home-bc home3; expect_send DELIVERED "home B -> C"
  for n in "$a_dir:$b_pub:$c_pub" "$b_dir:$a_pub:$c_pub" "$c_dir:$a_pub:$b_pub"; do
    IFS=: read -r pins_dir pin1 pin2 <<<"$n"
    grep -qi -- "$pin1" "$pins_dir/lan_noise_pins.json" 2>/dev/null \
      && grep -qi -- "$pin2" "$pins_dir/lan_noise_pins.json" 2>/dev/null \
      || fail "$pins_dir does not hold both noise pins after the home links"
  done
  stop_pid "$a_pid"
  stop_pid "$b_pid"
  stop_pid "$c_pid"

  move_port "$home" pa "$r1" br1
  move_port "$home" pb "$r2" br2
  move_port "$home" pc "$r1" br1
  if [[ "$way" == "beacon" ]]; then
    echo "--- room1: A and C; room2: B alone (the LAN beacon on from here, no route hints)"
    LAB_ENV+=(RAVEN_LAB_LAN_BEACON=1)
  else
    echo "--- room1: A and C; room2: B alone (route hints on from here)"
    LAB_ENV+=(RAVEN_LAB_ROUTE_HINTS=1)
  fi
  start_node "$hb" "$b_dir" b.room2.log "192.168.2.20:$PORT"
  b_pid="$NODE_PID"
  start_node "$ha" "$a_dir" a.room1.log "192.168.1.10:$PORT"
  a_pid="$NODE_PID"
  # The default bind: a move shows only in C's networks (no new listen
  # address, no restart), as on a laptop that changes rooms.
  start_node "$hc" "$c_dir" c.room1.log "0.0.0.0:$PORT"
  c_pid="$NODE_PID"
  send_msg "$ha" "$a_dir" bob rooms-1 r1
  if [[ "$SEND_STATUS" == "DELIVERED" ]]; then
    fail "A -> B was delivered although B is in another room"
  fi
  held=""
  deadline=$((SECONDS + CUSTODY_HELD_WAIT))
  while ((SECONDS < deadline)); do
    held="$(rv "$hc" "$c_dir" node custody status 2>/dev/null | sed -n 's/.*held \([0-9]*\) sealed.*/\1/p' | head -n 1)"
    if [[ -n "$held" && "$held" -ge 1 ]]; then
      break
    fi
    sleep 1
  done
  [[ -n "$held" && "$held" -ge 1 ]] || fail "C holds nothing for B within ${CUSTODY_HELD_WAIT}s"

  echo "--- C walks to room2 with a new address, its node running"
  ip -n "$hc" addr flush dev eth0
  move_port "$r1" pc "$r2" br2
  ip -n "$hc" addr add 192.168.2.31/16 dev eth0
  wait_inbox "$hb" "$b_dir" rooms-1 "$ROOMS_FETCH"
  note "B fetched A's message from C $((WAITED_MS / 1000)) s after C got its room2 address"
  # A and B never share a link: what B got came through C.
  wait_log_re "$LOGS/b.room2.log" 'custody: fetched messages=[1-9]' "$INBOX_WAIT"

  echo "--- C walks back to room1 with another new address"
  # B's ACK for A is left with C first (a second row; released rows stay).
  held=""
  deadline=$((SECONDS + CUSTODY_HELD_WAIT))
  while ((SECONDS < deadline)); do
    held="$(rv "$hc" "$c_dir" node custody status 2>/dev/null | sed -n 's/.*held \([0-9]*\) sealed.*/\1/p' | head -n 1)"
    if [[ -n "$held" && "$held" -ge 2 ]]; then
      break
    fi
    sleep 1
  done
  [[ -n "$held" && "$held" -ge 2 ]] || fail "B's ACK for A was not left with C within ${CUSTODY_HELD_WAIT}s"
  stop_pid "$c_pid"
  ip -n "$hc" addr flush dev eth0
  move_port "$r2" pc "$r1" br1
  ip -n "$hc" addr add 192.168.1.32/16 dev eth0
  start_node "$hc" "$c_dir" c.room1b.log "0.0.0.0:$PORT"
  c_pid="$NODE_PID"
  wait_log_re "$LOGS/a.room1.log" "$ACK_FETCHED_RE" "$CUSTODY_ACK_WAIT"
  note "B's ACK reached A through C $((WAITED_MS / 1000)) s after C's node started in room1 again"
  # A releases what it fetched right after the fetch.
  deadline=$((SECONDS + 30))
  n="$(unreleased "$c_dir")"
  while [[ "$n" != "?" && "$n" != "0" ]] && ((SECONDS < deadline)); do
    sleep 1
    n="$(unreleased "$c_dir")"
  done
  note "C's custody store: $n unreleased row(s);" \
    "$(rv "$hc" "$c_dir" node custody status 2>/dev/null | head -n 1)"
  if [[ "$n" != "?" && "$n" -ne 0 ]]; then
    fail "C still holds $n unreleased row(s) after B's message and B's ACK were fetched"
  fi
  inbox_count "$hb" "$b_dir" rooms-1
  if ((INBOX_N != 1)); then
    fail "B's inbox does not show A's message exactly once at the end"
  fi
  if [[ "$way" == "beacon" ]]; then
    # No route hints anywhere: no profile holds a learned RRH1 (the file
    # appears with the first one; these profiles are not sealed).
    for f in "$a_dir" "$b_dir" "$c_dir"; do
      if [[ -f "$f/learned_routes.json" ]]; then
        fail "$f learned route hints with RAVEN_LAB_ROUTE_HINTS off"
      fi
    done
    note "B's nearby search row: $(rv "$hb" "$b_dir" lan status 2>/dev/null | grep -F 'nearby search' | tr -s ' ' | head -n 1)"
  fi
}

# ---- preflight (exit 2: cannot run here) ----------------------------------

# preflight_fail WHAT ERR_FILE: why this host cannot run the cases; exit 2.
preflight_fail() {
  echo "netns_offline: cannot run here: $1 ($(nft --version 2>/dev/null || echo 'nft: no version'), kernel $(uname -r)):" >&2
  cat "$2" >&2 2>/dev/null || true
  exit 2
}

# preflight_nft: a bridge in a scratch namespace takes a bridge-family table
# with named counters that can be listed and reset.
preflight_nft() {
  local ns="${NSP}-probe" err="$BASE/nft-preflight.err"
  if ! ip netns add "$ns" 2>"$err"; then
    preflight_fail "cannot create a network namespace" "$err"
  fi
  if ! ip -n "$ns" link add br0 type bridge 2>"$err"; then
    preflight_fail "cannot create a bridge in a namespace" "$err"
  fi
  if ! ip netns exec "$ns" nft -f - >"$err" 2>&1 <<'EOF'
table bridge raven_off {
  counter a_other {
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr 192.0.2.1 udp dport 53 accept
    ip saddr 192.0.2.1 counter name "a_other"
    iifname "p1" oifname "p2" drop
  }
}
EOF
  then
    preflight_fail "nftables rejects a bridge table with named counters" "$err"
  fi
  if ! nft_counter "$ns" bridge raven_off a_other >/dev/null \
    || ! ip netns exec "$ns" nft reset counter bridge raven_off a_other >"$err" 2>&1; then
    preflight_fail "nftables cannot list or reset a bridge counter" "$err"
  fi
  ip netns del "$ns" 2>/dev/null || true
  echo "nft preflight: bridge tables with named counters load ($(nft --version 2>/dev/null))"
}

# pass_text CASE: what a PASS of CASE showed.
pass_text() {
  case "$1" in
    lan-noprovider) echo "no default route: literal routes both ways once, a name queued with the not-found text and delivered after the fix, 0 packets to anyone else, no internet claim" ;;
    router-dead-uplink) echo "dead uplink: the LAN part as lan-noprovider; a p2p-only send ends within ${DEAD_SEND_MAX} s with no VPS or port-forward advice and does not hold up the LAN contact" ;;
    hotspot-ap) echo "stale addresses queued, a typed AP address delivers, the AP reaches a client after its first link; the beacon finds client <-> client within ${BEACON_FIND_MAX} s; isolated clients reach each other through the AP's custody, ACK included" ;;
    cable-linklocal) echo "169.254-only cable: the listener binds within one retry of the address, the cable line only with the gate open, delivery both ways in both rounds; fe80 with its zone under auto listeners" ;;
    three-rooms) echo "A's message reaches B once through C walking between rooms, the ACK comes back, 0 packets between A and B, C holds nothing unreleased" ;;
    three-rooms-beacon) echo "three-rooms with the LAN beacon and custody only (no route hints): B fetches once, the ACK comes back, no RRH1 learned" ;;
  esac
}

# ---- main -------------------------------------------------------------------

echo "netns_offline: binaries from $BIN_DIR, run dirs under $BASE, namespaces ${NSP}-*, cases '${CASE_LIST[*]}'"
preflight_nft
RESULTS=()
# Each run in its own subshell (own traps, own cleanup) so the later ones
# still happen and report after a failure. Plain statements, not `if`
# conditions: errexit stays on inside them.
set +e
for name in "${CASE_LIST[@]}"; do
  echo "##### $name"
  (
    set -e
    case "$name" in
      lan-noprovider) run_lan_noprovider ;;
      router-dead-uplink) run_router_dead_uplink ;;
      hotspot-ap) run_hotspot_ap ;;
      cable-linklocal) run_cable_linklocal ;;
      three-rooms) run_three_rooms hints ;;
      three-rooms-beacon) run_three_rooms beacon ;;
    esac
  )
  rc=$?
  RESULTS+=("$name $rc")
done
set -e

echo "=== summary: ${#CASE_LIST[@]} case(s), all advisory ==="
FAILED=0
for row in "${RESULTS[@]}"; do
  read -r name rc <<<"$row"
  if [[ "$rc" -eq 0 ]]; then
    printf '%-20s PASS (%s)\n' "$name:" "$(pass_text "$name")"
  else
    printf '%-20s FAIL (exit %s)\n' "$name:" "$rc"
    FAILED=1
  fi
done
echo "CLAIM: software substitute (netns, bridges, nftables) for a dead router, a hotspot and a cable;"
echo "CLAIM: debug build with lab switches; LAN_NOISE_PIN and OFFLINE_LAN production gates false"
if [[ "$FAILED" -ne 0 ]]; then
  echo "NETNS_OFFLINE_FAIL" >&2
  exit 1
fi
echo "NETNS_OFFLINE_PASS"
