#!/usr/bin/env bash
# Owner-run real rows R8w, R8p and R8m (Phase 4, protocol/RAVEN_WSS_TRANSPORT_V1.md,
# RWS1): Raven on a laptop whose network lets little out. This script turns
# THIS computer into such a network for the length of the row, runs it, and
# puts the firewall back as it was.
#
#   R8w  only TCP 443 (and DNS to your resolver) leaves this computer; the
#        relay runs on a VPS with `raven-node relay --wss 443`, and this
#        laptop names it by its `/tls/ws` address.
#   R8p  nothing leaves but TCP to an HTTPS proxy (squid, or
#        node/scripts/lib/tiny_connect_proxy.py on another machine), DNS
#        included. The proxy is set in the system (macOS: Network > Proxies >
#        Secure Web Proxy; Linux: environment.d, or HTTPS_PROXY in this
#        shell): raven-node must find it itself, so RAVEN_P2P_PROXY is
#        cleared here. This proves system detection.
#   R8m  (optional) R8w through a TLS-intercepting proxy (mitmproxy) with the
#        relay on a real domain certificate (`--wss-cert`/`--wss-key`, via
#        `/dns4/<domain>/tcp/443/tls/ws`): the filter is R8w's or R8p's
#        (--proxy given: R8p's).
#
# The firewall (needs sudo; the script asks for it only for these commands):
#   macOS  pf rules in the anchor com.apple/raven_r8 (the default pf.conf
#          evaluates com.apple/*), pf enabled with a reference of this run
#          (`pfctl -E`); afterwards the anchor is flushed and the reference
#          released (`pfctl -X`), so pf is exactly as enabled as before.
#   Linux  nftables table inet raven_r8 (an output chain: loopback, replies
#          to connections made to this computer, and the row's own traffic;
#          everything else this computer starts is dropped, connections
#          already open included); afterwards the table is deleted.
# A trap restores the firewall on every exit (an error, Ctrl-C, TERM). Run
# it on the laptop itself, never over a remote session you depend on.
#
# Before the row a preflight must show the filter working: TCP 443 to the
# relay host open (R8p: the proxy open and the relay host's 443 closed) and
# TCP 7423 to it closed. If not, nothing else runs.
#
# The row uses the two-network kit's test home (node/scripts/wan_two_network_test.sh:
# RAVEN_WAN_HOME, default ~/raven-wan-test; never ~/.raven): run its `three
# setup NAME VIA` first, with VIA the relay's `/tls/ws` address for R8w (R8p:
# the same; the proxy carries it), and pin the other machine (`three add`).
# Then this script:
#   1. applies the filter and runs the preflight;
#   2. A -> B: `wan_two_network_test.sh three send TAG COUNT` (the node is
#      restarted under the filter, so no connection made before it survives;
#      the WSS lab switches RAVEN_LAB_WSS=1, and for R8p RAVEN_LAB_WSS_PROXY=1,
#      reach it from here);
#   3. B -> A: waits up to RAVEN_R8_WAIT seconds (default 900) for COUNT new
#      messages from the other machine, which runs `wan_two_network_test.sh
#      three send <its tag for this laptop> COUNT` meanwhile;
#   4. writes node/proof_artifacts/R8<w|p|m>-<macos|linux>-<UTC date>.txt:
#      counts, path labels, the relay transport (IPC relay_paths) and receipt
#      times only, no address, name, key or message text.
# Pass bar: COUNT/COUNT delivered each way, every A -> B message `relayed`,
# each B -> A message exactly once, and the relay transport `wss` (R8w) or
# `wss-proxy` (R8p).
#
# Usage:
#   node/scripts/r8_only_443.sh --i-understand --mode w|p|m --relay-host HOST --tag TAG
#                               [--proxy HOST:PORT] [--resolver IP] [--count N]
#   node/scripts/r8_only_443.sh --print-rules --mode w|p|m ...   (print the filter only)
# Environment: RAVEN_WAN_HOME and RAVEN_WAN_BIN as in the kit; RAVEN_R8_WAIT.
# Exit: 0 = the row passed, 1 = it failed (the artifact says why), 2 = bad
# arguments or this computer cannot run it.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF_DIR/.." && pwd)"
KIT="$SELF_DIR/wan_two_network_test.sh"
target_dir="${CARGO_TARGET_DIR:-$ROOT/target}"
[[ "$target_dir" == /* ]] || target_dir="$ROOT/$target_dir"
BIN="${RAVEN_WAN_BIN:-$target_dir/debug}"
HOME_DIR="${RAVEN_WAN_HOME:-$HOME/raven-wan-test}"
WAIT_B="${RAVEN_R8_WAIT:-900}"
ANCHOR="com.apple/raven_r8"
NFT_TABLE="raven_r8"

usage() {
  sed -n '2,/^set -euo pipefail/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
  exit 2
}

MODE=""
RELAY_HOST=""
TAG=""
PROXY=""
RESOLVER=""
COUNT=10
UNDERSTOOD=0
PRINT_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --i-understand) UNDERSTOOD=1 ;;
    --print-rules) PRINT_ONLY=1 ;;
    --mode) MODE="${2:-}"; shift ;;
    --relay-host) RELAY_HOST="${2:-}"; shift ;;
    --tag) TAG="${2:-}"; shift ;;
    --proxy) PROXY="${2:-}"; shift ;;
    --resolver) RESOLVER="${2:-}"; shift ;;
    --count) COUNT="${2:-}"; shift ;;
    -h | --help) usage ;;
    *) echo "r8_only_443: unknown argument '$1'" >&2; usage ;;
  esac
  shift
done

case "$MODE" in
  w | m) ;;
  p) [[ -n "$PROXY" ]] || { echo "r8_only_443: --mode p needs --proxy HOST:PORT (the proxy the system names)" >&2; exit 2; } ;;
  *) echo "r8_only_443: --mode must be w, p or m" >&2; exit 2 ;;
esac
# R8m through an explicit proxy filters as R8p does.
FILTER=w
if [[ "$MODE" == p || ( "$MODE" == m && -n "$PROXY" ) ]]; then
  FILTER=p
fi
[[ -n "$RELAY_HOST" ]] || { echo "r8_only_443: --relay-host HOST (the relay's IP or DNS name) is required" >&2; exit 2; }
[[ "$COUNT" =~ ^[1-9][0-9]?$ ]] || { echo "r8_only_443: --count must be 1-99" >&2; exit 2; }
case "$(uname -s)" in
  Darwin) OS=macos ;;
  Linux) OS=linux ;;
  *) echo "r8_only_443: macOS or Linux only (Windows: r8_only_443.ps1)" >&2; exit 2 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "r8_only_443: needs python3" >&2; exit 2; }

# resolve HOST: its first IPv4 or IPv6 address (before the filter: DNS may be
# blocked afterwards).
resolve() {
  python3 -I -c 'import socket, sys; print(socket.getaddrinfo(sys.argv[1], None, type=socket.SOCK_STREAM)[0][4][0])' "$1"
}
PROXY_IP=""
PROXY_PORT=""
if [[ -n "$PROXY" ]]; then
  PROXY_PORT="${PROXY##*:}"
  [[ "$PROXY_PORT" =~ ^[0-9]+$ ]] || { echo "r8_only_443: --proxy must be HOST:PORT" >&2; exit 2; }
  PROXY_IP="$(resolve "${PROXY%:*}")" || { echo "r8_only_443: cannot resolve the proxy host" >&2; exit 2; }
fi
if [[ "$FILTER" == w && -z "$RESOLVER" ]]; then
  if [[ "$OS" == macos ]]; then
    RESOLVER="$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/ { print $3; exit }')"
  else
    RESOLVER="$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf 2>/dev/null || true)"
  fi
  case "$RESOLVER" in
    "" | 127.* | ::1)
      echo "r8_only_443: give --resolver IP (the DNS server this computer asks; a local stub such as 127.0.0.53 forwards elsewhere)" >&2
      exit 2
      ;;
  esac
fi

# The filter, as text.
pf_rules() {
  echo "pass out quick on lo0 all"
  if [[ "$FILTER" == w ]]; then
    echo "pass out quick proto tcp from any to any port 443 keep state"
    echo "pass out quick proto { tcp udp } from any to $RESOLVER port 53 keep state"
  else
    echo "pass out quick proto tcp from any to $PROXY_IP port $PROXY_PORT keep state"
  fi
  echo "block drop out quick all"
}
nft_rules() {
  local fam=ip
  cat <<EOF
table inet $NFT_TABLE {
  chain out {
    type filter hook output priority 0; policy accept;
    oifname "lo" accept
    ct direction reply accept
EOF
  if [[ "$FILTER" == w ]]; then
    [[ "$RESOLVER" != *:* ]] || fam=ip6
    echo "    tcp dport 443 accept"
    echo "    $fam daddr $RESOLVER meta l4proto { tcp, udp } th dport 53 accept"
  else
    [[ "$PROXY_IP" != *:* ]] || fam=ip6
    echo "    $fam daddr $PROXY_IP tcp dport $PROXY_PORT accept"
  fi
  cat <<EOF
    counter drop
  }
}
EOF
}

if [[ "$PRINT_ONLY" == 1 ]]; then
  if [[ "$OS" == macos ]]; then
    echo "# pf anchor $ANCHOR"
    pf_rules
  else
    nft_rules
  fi
  exit 0
fi

if [[ "$UNDERSTOOD" != 1 ]]; then
  cat >&2 <<EOF
r8_only_443: this blocks almost all network traffic of THIS computer for the
length of the row (filter $FILTER: $([[ "$FILTER" == w ]] && echo "only TCP 443 and DNS" || echo "only the proxy") may leave),
then puts the firewall back. Run it on the laptop itself. Add --i-understand
to go on; --print-rules shows the filter without applying it.
EOF
  exit 2
fi
[[ -f "$HOME_DIR/.name" ]] || { echo "r8_only_443: no test home in $HOME_DIR: run wan_two_network_test.sh three setup NAME VIA first" >&2; exit 2; }
D="$HOME_DIR/$(cat "$HOME_DIR/.name")"
case "$D" in
  "$HOME/.raven" | "$HOME/.raven/"*) echo "r8_only_443: refusing the real profile $D" >&2; exit 2 ;;
esac
[[ -f "$D/contacts.json" ]] || { echo "r8_only_443: $D holds no profile" >&2; exit 2; }
[[ -x "$BIN/ash" && -x "$BIN/raven-node" ]] || { echo "r8_only_443: no debug ash/raven-node in $BIN (build them, or set RAVEN_WAN_BIN)" >&2; exit 2; }

# ---- the filter, restored on every exit ----------------------------------
PF_TOKEN=""
APPLIED=0
restore() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ "$APPLIED" == 1 ]]; then
    if [[ "$OS" == macos ]]; then
      sudo pfctl -a "$ANCHOR" -F all >/dev/null 2>&1 || echo "r8_only_443: FLUSH FAILED: run: sudo pfctl -a $ANCHOR -F all" >&2
      if [[ -n "$PF_TOKEN" ]]; then
        sudo pfctl -X "$PF_TOKEN" >/dev/null 2>&1 || echo "r8_only_443: run: sudo pfctl -X $PF_TOKEN" >&2
      fi
    else
      sudo nft delete table inet "$NFT_TABLE" 2>/dev/null || echo "r8_only_443: DELETE FAILED: run: sudo nft delete table inet $NFT_TABLE" >&2
    fi
    echo "r8_only_443: firewall restored"
  fi
  exit "$rc"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

sudo -v
if [[ "$OS" == macos ]]; then
  if [[ -n "$(sudo pfctl -a "$ANCHOR" -s rules 2>/dev/null)" ]]; then
    echo "r8_only_443: the anchor $ANCHOR already holds rules (an earlier run not restored?): sudo pfctl -a $ANCHOR -F all" >&2
    exit 2
  fi
  rules="$(mktemp)"
  pf_rules >"$rules"
  APPLIED=1
  sudo pfctl -a "$ANCHOR" -f "$rules" 2>/dev/null
  rm -f "$rules"
  PF_TOKEN="$(sudo pfctl -E 2>&1 | awk -F': ' '/[Tt]oken/ { print $2; exit }')"
else
  if sudo nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    echo "r8_only_443: the table inet $NFT_TABLE exists (an earlier run not restored?): sudo nft delete table inet $NFT_TABLE" >&2
    exit 2
  fi
  APPLIED=1
  nft_rules | sudo nft -f -
fi
echo "r8_only_443: filter $FILTER applied ($([[ "$OS" == macos ]] && echo "pf anchor $ANCHOR" || echo "nftables table inet $NFT_TABLE"))"

# ---- preflight -----------------------------------------------------------
# tcp_open HOST PORT: a TCP connection opens within 5 s.
tcp_open() {
  python3 -I -c 'import socket, sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5).close()' "$1" "$2" 2>/dev/null
}
relay_ip="$RELAY_HOST"
if [[ "$FILTER" == w ]]; then
  tcp_open "$RELAY_HOST" 443 || { echo "r8_only_443: preflight: the relay host's TCP 443 does not open under the filter" >&2; exit 1; }
  PREFLIGHT="443 open, 7423 blocked"
else
  tcp_open "$PROXY_IP" "$PROXY_PORT" || { echo "r8_only_443: preflight: the proxy does not open under the filter" >&2; exit 1; }
  relay_ip="$(resolve "$RELAY_HOST" 2>/dev/null || true)"
  if [[ -n "$relay_ip" ]] && tcp_open "$relay_ip" 443; then
    echo "r8_only_443: preflight: the relay host's TCP 443 opens directly: the filter does not hold" >&2
    exit 1
  fi
  PREFLIGHT="proxy open, direct 443 blocked, 7423 blocked"
fi
if [[ -n "$relay_ip" ]] && tcp_open "$relay_ip" 7423; then
  echo "r8_only_443: preflight: TCP 7423 to the relay host opens: the filter does not hold (macOS: is /etc/pf.conf loaded? sudo pfctl -f /etc/pf.conf)" >&2
  exit 1
fi
echo "r8_only_443: preflight: $PREFLIGHT"

# ---- the row --------------------------------------------------------------
# relay_facts SOCKET: "<relay_paths joined by commas> <proxy word>" from the
# running raven-node's IPC Status.
relay_facts() {
  python3 -I - "$1" <<'PY'
import json
import socket
import struct
import sys

body = json.dumps({"op": "status", "v": 1}).encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(10)
    s.connect(sys.argv[1])
    s.sendall(struct.pack(">I", len(body)) + body)
    n = struct.unpack(">I", s.recv(4, socket.MSG_WAITALL))[0]
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
p2p = json.loads(data).get("p2p") or {}
paths = ",".join(p for p in p2p.get("relay_paths", []) if p) or "none"
print(paths, p2p.get("proxy") or "none")
PY
}

# a_to_b_counts TSV: "<sent> <delivered> <path=count,...> <median s> <max s>"
# from the kit's `three send` table (a queued message's final row counts).
a_to_b_counts() {
  python3 -I - "$1" <<'PY'
import sys

rows = []
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        rows = [line.rstrip("\n").split("\t") for line in f][1:]
except OSError:
    pass
final = {}
for r in rows:
    if len(r) >= 5:
        final[r[0]] = r
done = [r for r in final.values() if r[2] in ("delivered", "queued->delivered")]
paths = {}
for r in done:
    paths[r[3]] = paths.get(r[3], 0) + 1
secs = sorted(float(r[4]) for r in done if r[4].replace(".", "", 1).isdigit())
med = secs[len(secs) // 2] if secs else "-"
print(len(final), len(done), ",".join(f"{k}={v}" for k, v in sorted(paths.items())) or "none",
      med, secs[-1] if secs else "-")
PY
}

export RAVEN_LAB_WSS=1
if [[ "$FILTER" == p ]]; then
  export RAVEN_LAB_WSS_PROXY=1
fi
# The proxy must come from the system (or this shell's HTTPS_PROXY on Linux).
unset RAVEN_P2P_PROXY
if [[ "$OS" == macos ]]; then
  unset HTTPS_PROXY https_proxy ALL_PROXY all_proxy
fi
inbox_texts() {
  "$BIN/ash" --data-dir "$D" inbox 2>/dev/null | grep -oE 'three-[A-Za-z0-9_.-]+-[0-9]+-[0-9]{6}' || true
}
before="$(mktemp)"
inbox_texts | sort -u >"$before"
t0=$SECONDS
RAVEN_WAN_SKIP_BUILD=1 bash "$KIT" three send "$TAG" "$COUNT" || true
tsv="$(ls -t "$D"/three-"$TAG"-*.tsv 2>/dev/null | head -n 1 || true)"
# The relay transport this row used (IPC Status p2p.relay_paths) and where
# raven-node's proxy came from (p2p.proxy: a fixed word).
read -r TRANSPORT PROXY_SOURCE <<<"$(relay_facts "$D/raven-node.sock" 2>/dev/null || echo "unknown unknown")"
echo "r8_only_443: A -> B done; now run on the other machine: wan_two_network_test.sh three send <its tag for this laptop> $COUNT (waiting up to ${WAIT_B}s)"
received=0
last_s=""
deadline=$((SECONDS + WAIT_B))
while ((SECONDS < deadline)); do
  received="$(inbox_texts | sort -u | comm -13 "$before" - | wc -l | tr -d ' ')"
  if [[ "$received" -ge "$COUNT" ]]; then
    last_s=$((SECONDS - t0))
    break
  fi
  sleep 5
done
dupes="$(inbox_texts | sort | uniq -d | comm -13 "$before" - | wc -l | tr -d ' ')"
rm -f "$before"

# ---- the artifact: counts only ---------------------------------------------
a_to_b="$(a_to_b_counts "$tsv")"
read -r sent delivered paths median max <<<"$a_to_b"
want_transport=wss
[[ "$FILTER" == w ]] || want_transport=wss-proxy
result=FAIL
if [[ "$sent" == "$COUNT" && "$delivered" == "$COUNT" && "$paths" == "relayed=$COUNT" \
  && "$received" -ge "$COUNT" && "$dupes" == 0 && ",$TRANSPORT," == *",$want_transport,"* ]]; then
  result=PASS
fi
mkdir -p "$ROOT/proof_artifacts"
artifact="$ROOT/proof_artifacts/R8$MODE-$OS-$(date -u +%Y%m%d).txt"
{
  echo "row R8$MODE"
  echo "os $OS"
  echo "utc $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "filter $([[ "$FILTER" == w ]] && echo "only TCP 443 and DNS out" || echo "only the HTTPS proxy out (DNS blocked)")"
  echo "preflight $PREFLIGHT"
  echo "relay_transport $TRANSPORT (pass bar: $want_transport)"
  echo "proxy_source $PROXY_SOURCE"
  echo "a_to_b sent $sent delivered $delivered paths $paths median_s $median max_s $max"
  echo "b_to_a received $received of $COUNT duplicates $dupes last_after_s ${last_s:--}"
  echo "result $result"
} >"$artifact"
cat "$artifact"
echo "r8_only_443: wrote $artifact (counts only)"
[[ "$result" == PASS ]]
