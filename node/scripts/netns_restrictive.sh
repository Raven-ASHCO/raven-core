#!/usr/bin/env bash
# Phase 4 (protocol/RAVEN_WSS_TRANSPORT_V1.md, RWS1): Raven on networks that
# let little out, in Linux network namespaces and nftables. A relay R listens
# with `--wss 443` (one port, WSS and raw libp2p: RWS1 §6) and on TCP+QUIC
# 7423; A sits behind a router rA that restricts what leaves, B behind a plain
# masquerade router. Every case is advisory: reported, and the script exits 1
# when one fails, but the lab CI job (restrictive-net-linux) runs it with
# continue-on-error.
#
# It sources node/scripts/netns_nat_dcutr.sh (RAVEN_NETNS_LIB=1) for its
# helpers, its cone topology (setup_net) and its environment scrub, and so
# takes the same RAVEN_NETNS_WAN_PREFIX scheme: the simulated Internet is
# WAN.0.0/16 (default 11.0), R on WAN.0.1. Debug build; the lab unlock
# RAVEN_LAB_TEST_A=1 and, per process, the WSS gate's switch RAVEN_LAB_WSS=1
# (and RAVEN_LAB_WSS_PROXY=1 for A in proxyonly) while
# WSS_PRODUCTION_ENABLED and WSS_PROXY_PRODUCTION_ENABLED are false.
#
# A names R by its 443 address in WSS form, B by R's raw 7423. Both cards
# name R's raw 443 address (`via=` holds no WSS form: RWS1 §2.3); a circuit
# rides the connection its sender already holds to R. Each case pins A and
# B to each other, then sends 10 messages each way with `--carrier p2p`:
# each must be `path=relayed` and arrive exactly once, and the case ends with
# 'delivered 10/10 both ways'.
#
# Cases (all advisory; RAVEN_NETNS_CASES picks some, in order):
#   only443    rA forwards only TCP to port 443 and DNS from hA (table ip
#              raven_restrict, counters tcp443 and dropped). A reserves over
#              R's 443, raw libp2p or WSS (the raw form is tried first:
#              RWS1 §2.3); the transport is reported. tcp443 > 0.
#   tlsonly    rA lets nothing from hA through but DNS, and REDIRECTs TCP 443
#              to a transparent TLS-only gate on rA itself
#              (node/scripts/lib/tiny_connect_proxy.py --mode tls-gate): a
#              connection whose first byte is not a TLS record (0x16) is
#              closed. A's raw attempt must be dropped by the gate (its log:
#              `gate drop ... first=13`), and WSS must win: A's reservation
#              within 30 s of its start, its status row `relay over WSS`.
#   proxyonly  an HTTPS proxy in a namespace of its own (px, WAN.27.10:3128,
#              tiny_connect_proxy.py, which alone resolves relay.test to R);
#              rA forwards from hA only TCP to px:3128 and drops the rest,
#              DNS included. A names R `/dns4/relay.test/tcp/443/tls/ws` with
#              RAVEN_P2P_PROXY=http://WAN.27.10:3128: the proxy's log must
#              show `CONNECT relay.test:443 200` (the name, never resolved by
#              A) and TLS through every tunnel, A's status row `relay over WSS
#              through the HTTPS proxy` and `restricted network (relay only)`,
#              and A's log neither the proxy's address nor relay.test.
#
# Topology: netns_nat_dcutr.sh's cone run (hA 192.168.1.2 -- rA -- pub --
# rB -- hB 192.168.2.2, R on WAN.0.1 in pub), plus for proxyonly px on
# WAN.27.10/24 -- WAN.27.1 pub. rA keeps its masquerade table (ip raven_nat);
# the case's own table (ip raven_restrict) adds the restriction in front of
# it (a forward chain at priority -10: a packet must pass both).
#
# HONEST CLAIM: a software substitute for the owner-run rows R8w and R8p
# (node/scripts/r8_only_443.sh): one kernel, a lab gate and a lab proxy, not
# a company network or a hotel portal.
#
# Written on macOS and NOT run locally (macOS has no network namespaces).
#
# Usage: build the debug binaries first, as yourself (never cargo as root):
#   (cd node && cargo build --locked -p ash -p raven-node)
#   sudo -E env "PATH=$PATH" bash node/scripts/netns_restrictive.sh
# or let the script re-run itself under `sudo -E`:
#   RAVEN_NETNS_ALLOW_SUDO=1 bash node/scripts/netns_restrictive.sh
# Environment: RAVEN_BIN_DIR, RAVEN_NETNS_TMP, RAVEN_NETNS_KEEP and
# RAVEN_NETNS_WAN_PREFIX as in netns_nat_dcutr.sh; RAVEN_NETNS_CASES the
# cases here (default "only443 tlsonly proxyonly").
# Exit: 0 = every case passed, 1 = one failed, 2 = cannot run here (not Linux
# or root, missing tools or binaries, or the nftables preflight failed).
set -euo pipefail

RESTRICTIVE_SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
RESTRICTIVE_DIR="$(dirname "$RESTRICTIVE_SELF")"
PROXY_PY="$RESTRICTIVE_DIR/lib/tiny_connect_proxy.py"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "netns_restrictive: Linux only (network namespaces + nftables)" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  if [[ "${RAVEN_NETNS_ALLOW_SUDO:-0}" == "1" ]]; then
    echo "netns_restrictive: not root; re-running under sudo -E (RAVEN_NETNS_ALLOW_SUDO=1)" >&2
    exec sudo -E env "PATH=$PATH" bash "$RESTRICTIVE_SELF" "$@"
  fi
  echo "netns_restrictive: needs root (it creates network namespaces and nftables rules)." >&2
  echo "  Run: sudo -E env \"PATH=\$PATH\" bash $RESTRICTIVE_SELF" >&2
  echo "  or:  RAVEN_NETNS_ALLOW_SUDO=1 bash $RESTRICTIVE_SELF   (re-runs itself under sudo -E)" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "netns_restrictive: needs python3 (the lab proxy and gate, node/scripts/lib/tiny_connect_proxy.py)" >&2
  exit 2
fi

# The cases here, read before the library parses RAVEN_NETNS_CASES as its own.
ALL_RESTRICTIVE="only443 tlsonly proxyonly"
IFS=', ' read -r -a RESTRICTIVE_ARGS <<<"${RAVEN_NETNS_CASES:-$ALL_RESTRICTIVE}"
unset RAVEN_NETNS_CASES RAVEN_NETNS_REPEAT
RESTRICTIVE_LIST=()
for name in ${RESTRICTIVE_ARGS[@]+"${RESTRICTIVE_ARGS[@]}"}; do
  [[ -n "$name" ]] || continue
  if [[ " $ALL_RESTRICTIVE " != *" $name "* ]]; then
    echo "netns_restrictive: RAVEN_NETNS_CASES names an unknown case '$name' (cases: $ALL_RESTRICTIVE)" >&2
    exit 2
  fi
  if [[ " ${RESTRICTIVE_LIST[*]-} " != *" $name "* ]]; then
    RESTRICTIVE_LIST+=("$name")
  fi
done
if [[ ${#RESTRICTIVE_LIST[@]} -eq 0 ]]; then
  echo "netns_restrictive: RAVEN_NETNS_CASES names no case (cases: $ALL_RESTRICTIVE)" >&2
  exit 2
fi

# The helpers, the topology, the environment scrub (RAVEN_P2P_PROXY=off for
# every process unless a case sets its own) and the EXIT trap that removes
# every namespace of this run.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=netns_nat_dcutr.sh
RAVEN_NETNS_LIB=1 source "$RESTRICTIVE_DIR/netns_nat_dcutr.sh"

# Bounds (seconds), each a deadline on an observable condition.
WSS_WIN=30
RESTRICT_RESERVE=60
MESSAGES=10
PROXY_PORT=3128
GATE_PORT=8443
# The relay's name in proxyonly: only the proxy resolves it.
RELAY_NAME="relay.test"
LINE_RELAY_UP='raven-node relay: up ('
TEXT_WSS_ROW='relay over WSS'
TEXT_PROXY_ROW='relay over WSS through the HTTPS proxy'
TEXT_RESTRICTED_ROW='restricted network (relay only)'
NS_PX="${NSP}-px"

# restrict_ruleset CASE: rA's extra table for CASE (in front of raven_nat).
restrict_ruleset() {
  case "$1" in
    only443)
      cat <<EOF
table ip raven_restrict {
  counter tcp443 {
  }
  counter dropped {
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "lan" tcp dport 443 counter name "tcp443" accept
    iifname "lan" meta l4proto { tcp, udp } th dport 53 accept
    iifname "lan" counter name "dropped" drop
  }
}
EOF
      ;;
    tlsonly)
      cat <<EOF
table ip raven_restrict {
  counter redirected {
  }
  counter dropped {
  }
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    iifname "lan" tcp dport 443 counter name "redirected" redirect to :$GATE_PORT
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "lan" meta l4proto { tcp, udp } th dport 53 accept
    iifname "lan" counter name "dropped" drop
  }
}
EOF
      ;;
    proxyonly)
      cat <<EOF
table ip raven_restrict {
  counter to_proxy {
  }
  counter dropped {
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "lan" ip daddr $WAN.27.10 tcp dport $PROXY_PORT counter name "to_proxy" accept
    iifname "lan" counter name "dropped" drop
  }
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "lan" meta l4proto { tcp, udp } th dport 53 counter name "dropped" drop
  }
}
EOF
      ;;
  esac
}

# restrict_counter NAME: rA's raven_restrict counter NAME.
restrict_counter() {
  nft_counter "$NS_RA" ip raven_restrict "$1" || fail "cannot read rA's counter $1"
}

# setup_px: the proxy's namespace on the simulated Internet, routed by pub.
setup_px() {
  ip netns add "$NS_PX"
  ip -n "$NS_PX" link set lo up
  ip -n "$NS_PUB" link add wp type veth peer name eth0 netns "$NS_PX"
  ip -n "$NS_PUB" addr add "$WAN.27.1/24" dev wp
  ip -n "$NS_PUB" link set wp up
  ip -n "$NS_PX" addr add "$WAN.27.10/24" dev eth0
  ip -n "$NS_PX" link set eth0 up
  ip -n "$NS_PX" route add default via "$WAN.27.1"
}

# p2p_row NS DIR NAME [ENV...]: the `p2p` row of NAME's `raven status`.
p2p_row() {
  local ns=$1 dir=$2 name=$3
  shift 3
  in_ns "$ns" env "$@" "$RAVEN" --data-dir "$dir" status >"$LOGS/$name.status.out" 2>&1 || true
  awk '$1 == "p2p" { $1 = ""; print; exit }' "$LOGS/$name.status.out"
}

run_restrictive() {
  local run_dir a b relay_pid a_pid b_pid peer="" deadline a_fp b_fp a_card b_card card
  local v7423 v443 a_via row transport="" i t_start reserved_s=""
  local -a a_env b_env
  MODE=$1
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r"
  a="$run_dir/a"
  b="$run_dir/b"
  mkdir -p "$LOGS" "$R" "$a" "$b"
  chmod 700 "$R" "$a" "$b"
  echo "=== $MODE run (dirs under $run_dir) ==="
  setup_net "masquerade"
  if [[ "$MODE" == "proxyonly" ]]; then
    setup_px
  fi
  restrict_ruleset "$MODE" | ip netns exec "$NS_RA" nft -f - || fail "nft rejected rA's $MODE table"
  ip netns exec "$NS_RA" nft list table ip raven_restrict >>"$LOGS/topology.log" 2>&1 || true

  echo "--- relay R in pub: TCP+QUIC $WAN.0.1:7423, WSS and raw libp2p on TCP 443"
  ip netns exec "$NS_PUB" env RAVEN_LAB_WSS=1 "$NODE" relay --data-dir "$R" \
    --listen "$WAN.0.1:7423" --wss 443 >"$LOGS/relay.log" 2>&1 &
  relay_pid=$!
  PIDS+=("$relay_pid")
  wait_line "$LOGS/relay.log" "$LINE_RELAY_UP" "$RELAY_WAIT" "$relay_pid"
  if ! grep -F -- "$LINE_RELAY_UP" "$LOGS/relay.log" | grep -Fq 'wss=on ('; then
    fail "the relay's up line names no WSS listener (wss=on): is RAVEN_LAB_WSS=1 reaching it?"
  fi
  deadline=$((SECONDS + RELAY_WAIT))
  while ((SECONDS < deadline)); do
    if [[ -s "$R/relay_status.json" ]]; then
      peer="$(relay_peer_id "$R/relay_status.json")"
      [[ -z "$peer" ]] || break
    fi
    require_alive "$relay_pid"
    sleep 0.2
  done
  if [[ ! "$peer" =~ ^[1-9A-HJ-NP-Za-km-z]+$ ]]; then
    fail "relay_status.json with a base58 peer_id not written within ${RELAY_WAIT}s"
  fi
  v7423="/ip4/$WAN.0.1/tcp/7423/p2p/$peer"
  v443="/ip4/$WAN.0.1/tcp/443/p2p/$peer"
  a_env=(RAVEN_LAB_WSS=1)
  b_env=(RAVEN_LAB_WSS=1)
  case "$MODE" in
    proxyonly)
      a_via="/dns4/$RELAY_NAME/tcp/443/tls/ws/p2p/$peer"
      a_env+=(RAVEN_LAB_WSS_PROXY=1 "RAVEN_P2P_PROXY=http://$WAN.27.10:$PROXY_PORT")
      ;;
    *) a_via="/ip4/$WAN.0.1/tcp/443/tls/ws/p2p/$peer" ;;
  esac

  echo "--- init A (hA) and B (hB); both cards name R's raw 443 address"
  VIA="$v443"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  raven_card "$NS_HA" "$a" a
  a_card="$CARD"
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  for card in "$a_card" "$b_card"; do
    in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$card" >>"$LOGS/relay.allow.out" 2>&1 \
      || fail "raven relay allow failed"
  done

  case "$MODE" in
    tlsonly)
      echo "--- the TLS-only gate on rA (REDIRECT of TCP 443 to :$GATE_PORT)"
      ip netns exec "$NS_RA" python3 -I "$PROXY_PY" --mode tls-gate --listen "0.0.0.0:$GATE_PORT" \
        --log "$LOGS/gate.log" >"$LOGS/gate.out" 2>&1 &
      PIDS+=("$!")
      wait_line "$LOGS/gate.out" "tiny_connect_proxy: listening" 10 "$!"
      ;;
    proxyonly)
      echo "--- the HTTPS proxy in px ($WAN.27.10:$PROXY_PORT; it alone resolves $RELAY_NAME)"
      ip netns exec "$NS_PX" python3 -I "$PROXY_PY" --listen "$WAN.27.10:$PROXY_PORT" \
        --map "$RELAY_NAME=$WAN.0.1" --log "$LOGS/proxy.log" >"$LOGS/proxy.out" 2>&1 &
      PIDS+=("$!")
      wait_line "$LOGS/proxy.out" "tiny_connect_proxy: listening" 10 "$!"
      ;;
  esac

  echo "--- services: A ($a_via), B (R's 7423), each listening on 7423"
  t_start=$SECONDS
  ip netns exec "$NS_HA" env "${a_env[@]}" "$NODE" service --data-dir "$a" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$a_via" --timeout-secs 0 \
    >"$LOGS/a.service.log" 2>&1 &
  a_pid=$!
  PIDS+=("$a_pid")
  ip netns exec "$NS_HB" env "${b_env[@]}" "$NODE" service --data-dir "$b" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$v7423" --timeout-secs 0 \
    >"$LOGS/b.service.log" 2>&1 &
  b_pid=$!
  PIDS+=("$b_pid")
  if [[ "$MODE" == "tlsonly" ]]; then
    wait_line "$LOGS/a.service.log" "$LINE_RESERVED" "$WSS_WIN" "$a_pid" "$relay_pid"
  else
    wait_line "$LOGS/a.service.log" "$LINE_RESERVED" "$RESTRICT_RESERVE" "$a_pid" "$relay_pid"
  fi
  reserved_s=$((SECONDS - t_start))
  wait_line "$LOGS/b.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$b_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"

  # What A's status says, once its row has settled (the restricted line
  # follows the reservation within a tick).
  deadline=$((SECONDS + 30))
  while :; do
    row="$(p2p_row "$NS_HA" "$a" a "${a_env[@]}")"
    case "$MODE" in
      only443) [[ "$row" != *"reservations 1/1"* ]] || break ;;
      tlsonly) [[ "$row" != *"$TEXT_WSS_ROW"* ]] || break ;;
      proxyonly) [[ "$row" != *"$TEXT_PROXY_ROW"* || "$row" != *"$TEXT_RESTRICTED_ROW"* ]] || break ;;
    esac
    ((SECONDS < deadline)) || fail "A's p2p row never said what $MODE expects: $row"
    sleep 1
  done
  echo "A reserved after ${reserved_s}s; p2p row:$row"
  case "$MODE" in
    only443)
      if [[ "$row" == *"$TEXT_WSS_ROW"* ]]; then transport=wss; else transport=tcp; fi
      [[ "$(restrict_counter tcp443)" -gt 0 ]] || fail "rA forwarded no new connection to port 443"
      ;;
    tlsonly)
      transport=wss
      grep -Eq 'gate drop [0-9.]+:443 first=13' "$LOGS/gate.log" \
        || fail "the gate dropped no raw libp2p attempt (first byte 0x13): A did not try the raw form first"
      grep -Eq 'gate pass [0-9.]+:443 first=16' "$LOGS/gate.log" || fail "the gate passed no TLS connection"
      ;;
    proxyonly)
      transport=wss-proxy
      grep -Fq "CONNECT $RELAY_NAME:443 200" "$LOGS/proxy.log" \
        || fail "the proxy was not asked CONNECT $RELAY_NAME:443 (the name, unresolved)"
      if grep -E '^[0-9.]+ CONNECT ' "$LOGS/proxy.log" | grep -Fv " CONNECT $RELAY_NAME:443 " | grep -q .; then
        fail "the proxy was asked for something other than $RELAY_NAME:443"
      fi
      if grep -E '^[0-9.]+ tunnel ' "$LOGS/proxy.log" | grep -Fv ' first=16' | grep -q .; then
        fail "a tunnel through the proxy did not start with a TLS record"
      fi
      if grep -Fq -e "$RELAY_NAME" -e "$WAN.27.10" "$LOGS/a.service.log"; then
        fail "A's log names the relay's name or the proxy's address"
      fi
      ;;
  esac

  echo "--- pin each other (verified contacts only use p2p)"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"
  wait_line "$LOGS/a.service.log" "$LINE_GATE_ONE" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_GATE_ONE" 30 "$b_pid"

  echo "--- $MESSAGES messages each way over --carrier p2p, each relayed and exactly once"
  for ((i = 1; i <= MESSAGES; i++)); do
    send_check "$NS_HA" "$a" bob "restrictive-$MODE-a2b-$i" "a2b-$i"
    require_path "$PATH_RELAYED" "message $i A -> B"
    inbox_once "$NS_HB" "$b" "restrictive-$MODE-a2b-$i" "b-$i"
    send_check "$NS_HB" "$b" alice "restrictive-$MODE-b2a-$i" "b2a-$i"
    require_path "$PATH_RELAYED" "message $i B -> A"
    inbox_once "$NS_HA" "$a" "restrictive-$MODE-b2a-$i" "a-$i"
  done
  if grep -Fq '12D3KooW' "$LOGS/a.service.log" "$LOGS/b.service.log"; then
    fail "a service log names a PeerId"
  fi
  echo "RESULT $MODE: delivered $MESSAGES/$MESSAGES both ways (A's relay transport $transport, reserved after ${reserved_s}s, every message $PATH_RELAYED)"
}

# ---- main -------------------------------------------------------------------

echo "netns_restrictive: binaries from $BIN_DIR, run dirs under $BASE, namespaces ${NSP}-*, cases '${RESTRICTIVE_LIST[*]}'"
preflight_nft
RESULTS=()
set +e
for name in "${RESTRICTIVE_LIST[@]}"; do
  echo "##### $name"
  (
    set -e
    run_restrictive "$name"
  )
  RESULTS+=("$name $?")
done
set -e

echo "=== summary: ${#RESTRICTIVE_LIST[@]} case(s), all advisory ==="
FAILED=0
for row in "${RESULTS[@]}"; do
  read -r name rc <<<"$row"
  if [[ "$rc" -eq 0 ]]; then
    printf '%-10s PASS (delivered %s/%s both ways)\n' "$name:" "$MESSAGES" "$MESSAGES"
  else
    printf '%-10s FAIL (exit %s)\n' "$name:" "$rc"
    FAILED=1
  fi
done
echo "CLAIM: software substitute (netns + nftables, a lab TLS gate and proxy); does NOT replace the owner-run rows R8w / R8p"
echo "CLAIM: debug build with RAVEN_LAB_TEST_A=1 RAVEN_LAB_WSS=1; WSS_PRODUCTION_ENABLED=false"
if [[ "$FAILED" -ne 0 ]]; then
  echo "NETNS_RESTRICTIVE_FAIL" >&2
  exit 1
fi
echo "NETNS_RESTRICTIVE_PASS"
