#!/usr/bin/env bash
# Update mesh test kit (Phase 6b P6.51, real row R31): three laptops on one
# local network with NO uplink (a Wi-Fi network without Internet, or a travel
# router with its WAN port unplugged) pass a Raven security notice and a
# release from one to the next over RUP1 (protocol/RAVEN_UPDATE_EXCHANGE_V1.md),
# with no server, without flipping any production gate. A debug build and the
# lab switches open the three update gates (RAVEN_LAB_ADVISORY,
# RAVEN_LAB_RELEASE_BUNDLE, RAVEN_LAB_MESH_UPDATE, with RAVEN_LAB_TEST_A=1) for
# this test only; release builds ignore them. The notice and the release are
# signed with the PUBLISHED TEST KEYS (shared-vectors/rvn1/update/keyset_001.json):
# anyone can sign with them, so only these test profiles trust them
# (RAVEN_LAB_RELEASE_KEYS_FILE).
#
# Run the same steps on every laptop (A, B, C), each in a test home of its own,
# never your real ~/.raven:
#
#   node/scripts/update_mesh_test.sh setup NAME [IP]
#       build ash and raven-node (and, on A, raven-release), copy the programs
#       into the test home's bin/ (everything runs from there, so an install
#       can only ever change that copy), create the test profile, start
#       raven-node on IP:PORT (default every interface, port 47431) and print
#       this laptop's line for `add` on the others.
#   node/scripts/update_mesh_test.sh add TAG ADDRESS PUB_HEX FINGERPRINT IP:PORT
#       add a laptop as a VERIFIED contact (compare the fingerprint with what
#       its screen shows). Updates pass between verified contacts only. Chain
#       them A - B - C: A and C need not know each other.
#   node/scripts/update_mesh_test.sh publish            (on A only)
#       make test notice #1 and release 5 (a small raven-node script and a
#       1.5 MB document: 26 chunks, so the notice, the manifest and the chunks
#       fit the 6 requests a friend serves a minute) with the test keys, list both in a test release log,
#       and import them here.
#   node/scripts/update_mesh_test.sh link TAG
#       send TAG one message: the link that carries the notice and the offer.
#       On B: `link A`; on C: `link B` (after B has the release).
#   node/scripts/update_mesh_test.sh approve [CODE]
#       list the releases friends offer, or approve one (`raven update
#       download CODE` asks y/N here). Raven fetches nothing before.
#   node/scripts/update_mesh_test.sh status
#       `raven update status`: the notice, the log, what waits, what came.
#   node/scripts/update_mesh_test.sh report [ROW]
#       write update-report-NAME[-ROW]-<UTC>.txt (status, the offers, the
#       node's update lines and security notices) for the analysis. It names
#       test keys and the test home, never a private key.
#   node/scripts/update_mesh_test.sh stop
#       stop the raven-node this kit started (by its pid).
#
# Expected (R31): `status` on B, then on C, says notice #1 within a minute of
# their `link`, with no command; after `approve`, B (then C) says "Raven
# 1.5.0 (build 5) from <friend> is downloaded and checked". Nothing installs:
# installing is `raven update install`, a separate typed approval (carrier
# matrix C89 tests it in a temp prefix).
#
#   node/scripts/update_mesh_test.sh dry-run
#       all of the above on this one computer, on loopback: A, B and C in a
#       fresh temp folder with random ports, the approvals given by the lab
#       switch RAVEN_LAB_UPDATE_AUTO_APPROVE=1 instead of a person; checks each
#       hop, then stops every node it started. Not an R31 claim.
#   node/scripts/update_mesh_test.sh selftest
#       check, in a temp folder with stand-in programs (no build, no node),
#       that the programs are never written over while one of them runs.
#
# The programs go into bin/ only through a temp file renamed over the old
# one, and never while a program of that name runs from bin/: on Apple
# silicon the kernel kills a program whose file was written over in place
# (its code signature no longer matches), and a rename under it would leave
# the test running an older build than bin/ says. `publish` adds only
# raven-release; `setup` stops its node before it puts new programs in.
#
# Environment:
#   RAVEN_UPDATE_TEST_HOME   the test home (default ~/raven-update-mesh-test);
#                            never ~/.raven
#   RAVEN_UPDATE_TEST_PORT   the LAN port (default 47431)
#   RAVEN_UPDATE_TEST_BIN    the build's programs (default $CARGO_TARGET_DIR/debug,
#                            else node/target/debug)
#   RAVEN_UPDATE_SKIP_BUILD=1  use the programs as they are
#   RAVEN_UPDATE_DRY_DIR     a dry run's folder (must be empty; default a new
#                            mktemp -d folder, removed when the run passes)
#
# Nothing here touches ~/.raven, the keychain or any real contact.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$ROOT/target}"
[[ "$target_dir" == /* ]] || target_dir="$ROOT/$target_dir"
BUILD="${RAVEN_UPDATE_TEST_BIN:-$target_dir/debug}"
HOME_DIR="${RAVEN_UPDATE_TEST_HOME:-$HOME/raven-update-mesh-test}"
PORT="${RAVEN_UPDATE_TEST_PORT:-47431}"

# The lab environment of every command and node here: the test backends, the
# three update gates' switches, the security events' switch, the at-rest
# seal (erase stays inside the test home), no proxy; no other lab switch of
# the caller's shell.
for var in $(env | sed -n 's/^\(RAVEN_LAB_[A-Z0-9_]*\)=.*/\1/p'); do
  unset "$var"
done
unset RAVEN_DATA_DIR ASH_DATA_DIR RAVEN_INTERNET_LISTEN RAVEN_P2P_LISTEN RAVEN_P2P_RELAYS \
  RAVEN_P2P_RELAY RAVEN_PEER ASH_LAN_DIAL RAVEN_KEYSTORE_PASSPHRASE \
  RAVEN_KEYSTORE_PASSPHRASE_FILE RAVEN_KEYSTORE_BACKEND RAVEN_TRACE_LOG 2>/dev/null || true
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file
export RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 RAVEN_P2P_PROXY=off NO_COLOR=1
export RAVEN_LAB_TEST_A=1 RAVEN_LAB_ADVISORY=1 RAVEN_LAB_RELEASE_BUNDLE=1
export RAVEN_LAB_MESH_UPDATE=1 RAVEN_LAB_SECURITY_EVENTS=1 RAVEN_LAB_AT_REST=1

die() {
  echo "update_mesh_test: $*" >&2
  exit 1
}

# The kit's own test home: `$1`, never ~/.raven or the home folder itself.
use_home() {
  local home="$1"
  case "$home" in
    "$HOME" | "$HOME/" | "$HOME/.raven" | "$HOME/.raven/"*) die "refusing $home as a test home" ;;
  esac
  mkdir -p "$home"
  chmod 700 "$home"
  HOME_DIR="$(cd "$home" && pwd -P)"
  PROFILE="$HOME_DIR/profile"
  KIT_BIN="$HOME_DIR/bin"
  export RAVEN_LAB_ERASE_ROOT="$HOME_DIR"
  export RAVEN_LAB_RELEASE_KEYS_FILE="$HOME_DIR/release-keys.hex"
  # The published test key set (2 of 3), for this test home only.
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["expected"]["key_set_hex"])' \
    "$REPO/shared-vectors/rvn1/update/keyset_001.json" >"$RAVEN_LAB_RELEASE_KEYS_FILE"
}

raven() { "$KIT_BIN/raven" --data-dir "$PROFILE" "$@"; }

# The pids of the processes that run the program file `$1` now (empty:
# none): lsof lists a process whose text is that file; the command line
# catches one started by that path (a script runs as `/bin/sh PATH ...`), and
# a system without lsof.
pids_running() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  { lsof -t -- "$f" 2>/dev/null || true
    ps -A -o pid= -o args= 2>/dev/null | awk -v f="$f" '$2 == f || $3 == f { print $1 }'
  } | sort -un | tr '\n' ' ' | sed 's/ $//'
}

# Put the program `$1` into `$2` without ever writing over a running one:
# nothing to do when `$2` holds the same bytes already; refused while a
# process runs from `$2`; else copied into a temp file next to it, then
# renamed over it (atomic: `$2` is the old program or the new one, never
# half of one).
install_prog() {
  local from="$1" to="$2" pids tmp
  [[ -x "$from" ]] || die "$from is missing"
  if [[ -e "$to" ]] && cmp -s "$from" "$to"; then
    return 0
  fi
  pids="$(pids_running "$to")"
  [[ -z "$pids" ]] ||
    die "refusing to replace $to: it runs now (pid $pids). A running program is never written over; stop it first (this kit's node: update_mesh_test.sh stop), then run this again"
  tmp="$(mktemp "$(dirname "$to")/.$(basename "$to").new.XXXXXX")" || die "cannot make a temp file next to $to"
  if ! cp "$from" "$tmp" || ! chmod 755 "$tmp"; then
    rm -f "$tmp"
    die "cannot copy $from next to $to"
  fi
  pids="$(pids_running "$to")"
  if [[ -n "$pids" ]]; then
    rm -f "$tmp"
    die "refusing to replace $to: it started meanwhile (pid $pids); stop it first, then run this again"
  fi
  mv -f "$tmp" "$to" || {
    rm -f "$tmp"
    die "cannot rename the new $(basename "$to") into place"
  }
}

# Build the programs named (raven, raven-node, raven-release) unless
# RAVEN_UPDATE_SKIP_BUILD=1. Only cargo's own target folder changes.
compile() {
  local prog cli=0 tool=0
  for prog in "$@"; do
    case "$prog" in
      raven | raven-node) cli=1 ;;
      raven-release) tool=1 ;;
      *) die "compile: unknown program $prog" ;;
    esac
  done
  [[ "${RAVEN_UPDATE_SKIP_BUILD:-}" != 1 ]] || return 0
  if [[ "$cli" == 1 ]]; then
    (cd "$ROOT" && cargo build --locked -q -p ash -p raven-node)
  fi
  if [[ "$tool" == 1 ]]; then
    (cd "$ROOT" && cargo build --locked -q -p ash --features release-tool --bin raven-release)
  fi
}

# Put the programs named from the build into the test home's bin/ with
# install_prog. Only the programs named are touched.
put_in() {
  local prog
  mkdir -p "$KIT_BIN"
  for prog in "$@"; do
    if [[ ! -x "$BUILD/$prog" ]]; then
      if [[ "$prog" == raven-release ]]; then
        die "$BUILD/raven-release is missing (cargo build --locked -p ash --features release-tool --bin raven-release)"
      fi
      die "$BUILD/$prog is missing (cargo build --locked -p ash -p raven-node)"
    fi
    install_prog "$BUILD/$prog" "$KIT_BIN/$prog"
  done
}

build() {
  compile "$@"
  put_in "$@"
}

# Start this home's raven-node on `$1` (IP:PORT) and wait for its listener.
start_node() {
  local listen="$1" log="$HOME_DIR/node.log"
  : >"$log"
  "$KIT_BIN/raven-node" service --data-dir "$PROFILE" --lan-listen "$listen" \
    --ble-listen 127.0.0.1:0 </dev/null >>"$log" 2>&1 &
  echo $! >"$HOME_DIR/node.pid"
  local i
  for ((i = 0; i < 200; i++)); do
    if grep -q 'raven-node lan_direct: listen ' "$log" && grep -q 'raven-node at_rest: ' "$log" &&
      raven ipc-ping >/dev/null 2>&1; then
      DIAL="$(grep -m 1 'raven-node lan_direct: listen ' "$log" | awk '{print $NF}')"
      printf '%s\n' "$DIAL" >"$HOME_DIR/dial.txt"
      return 0
    fi
    kill -0 "$(cat "$HOME_DIR/node.pid")" 2>/dev/null || die "raven-node exited: $(tail -n 5 "$log")"
    sleep 0.1
  done
  die "raven-node did not come up: $(tail -n 5 "$log")"
}

stop_node() {
  local pid
  [[ -f "$HOME_DIR/node.pid" ]] || return 0
  pid="$(cat "$HOME_DIR/node.pid")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    local i
    for ((i = 0; i < 50; i++)); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$HOME_DIR/node.pid"
}

field() { sed -n "s/^$1=//p" | head -n 1; }

cmd_setup() {
  local name="$1" ip="${2:-0.0.0.0}" init
  [[ "$name" =~ ^[a-z][a-z0-9-]{0,15}$ ]] || die "NAME: 1-16 of a-z, 0-9, - (a letter first)"
  compile raven raven-node
  # This home's node runs from bin/: stop it before its program is replaced.
  stop_node
  put_in raven raven-node
  if [[ ! -f "$PROFILE/contacts.json" ]]; then
    mkdir -p "$PROFILE"
    chmod 700 "$PROFILE"
    init="$(raven init)"
    printf '%s\n' "$init" >"$HOME_DIR/identity.txt"
    raven prekey publish >/dev/null
  fi
  start_node "$ip:$PORT"
  local id="$HOME_DIR/identity.txt"
  echo "$name: started on $DIAL. On the other laptops:"
  echo "  node/scripts/update_mesh_test.sh add $name $(field address <"$id") $(field pub_hex <"$id") \\"
  echo "      $(field fingerprint <"$id") <this laptop's IP>:$PORT"
}

cmd_add() {
  local tag="$1" address="$2" pub="$3" fp="$4" dial="$5"
  raven contact add --address "$address" --pub-hex "$pub" --petname "$tag" --tag "$tag" \
    --verify-fp "$fp" --lan-dial "$dial"
}

# The test project's release tool, in its own folder of the test home.
rel() { (cd "$HOME_DIR/project" && "$KIT_BIN/raven-release" "$@" >/dev/null); }

signed() {
  local draft="$1" out="$2" k
  shift 2
  for k in "$@"; do rel sign --key-set keys.keyset --test-key "$k" "$draft"; done
  local sigs=()
  for k in "$@"; do sigs+=("$draft.sig-$k"); done
  rel combine --key-set keys.keyset --draft "$draft" --out "$out" "${sigs[@]}"
}

cmd_publish() {
  # Only the release tool: the node started by `setup` runs from bin/.
  [[ -x "$KIT_BIN/raven-release" ]] || build raven-release
  local p="$HOME_DIR/project" at=1792800000000 target
  rm -rf "$p"
  mkdir -p "$p/log" "$p/files/bin" "$p/files/docs"
  target="$(rustc -vV | sed -n 's/^host: //p')"
  rel keyset --threshold 2 --out keys.keyset $(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["expected"]["public_keys_hex"]))' \
    "$REPO/shared-vectors/rvn1/update/keyset_001.json")
  printf '{"serial": 1, "issued_at_ms": %s, "entries": [{"kind": "NOTICE", "text": "R31: a test notice passed between laptops."}]}\n' \
    "$at" >"$p/notice-1.json"
  rel advisory --key-set keys.keyset --spec notice-1.json --out notice-1.draft
  signed notice-1.draft notice-1.rad1 0 2
  printf '#!/bin/sh\nexit 0\n' >"$p/files/bin/raven-node"
  python3 -c 'import hashlib,sys; open(sys.argv[1],"wb").write(hashlib.shake_256(b"R31").digest(1536*1024))' \
    "$p/files/docs/blob.bin"
  printf 'Raven 1.5.0: an R31 test release.\n' >"$p/notes.txt"
  rel manifest --key-set keys.keyset --build-serial 5 --version 1.5.0 --target "$target" \
    --source-commit 0123456789abcdef0123456789abcdef01234567 --toolchain 1.98.0 \
    --created-at-ms "$at" --notes notes.txt --file "bin/raven-node=$p/files/bin/raven-node" \
    --file "docs/blob.bin=$p/files/docs/blob.bin" --out manifest-5.draft
  signed manifest-5.draft manifest-5.rrb1 0 1
  rel log append --log log --key-set keys.keyset --at-ms "$((at + 1000))" notice-1.rad1 manifest-5.rrb1
  local size=$(($(wc -c <"$p/log/entries.bin") / 41))
  rel sth --log log --key-set keys.keyset --timestamp-ms "$((at + 2000))"
  rel sign --key-set keys.keyset --test-key 1 "tree-head-$size.draft"
  rel sign --key-set keys.keyset --test-key 2 "tree-head-$size.draft"
  rel combine --key-set keys.keyset --draft "tree-head-$size.draft" --log log \
    "tree-head-$size.draft.sig-1" "tree-head-$size.draft.sig-2"
  rel log snapshot --log log --key-set keys.keyset
  rel pack --key-set keys.keyset --manifest manifest-5.rrb1 --log log --files files --out raven-5.rrb
  raven update import "$p/notice-1.rad1" --log "$p/log/snapshot.rtl1"
  raven update import "$p/raven-5.rrb"
}

cmd_link() { raven send --contact "@$1" <<<"update mesh link"; }

cmd_approve() {
  if [[ $# -eq 0 ]]; then
    raven update download
  else
    raven update download "$1"
  fi
}

cmd_report() {
  local row="${1:-}" name out
  name="$(basename "$HOME_DIR")"
  out="$HOME_DIR/update-report-$name${row:+-$row}-$(date -u +%Y%m%dT%H%M%SZ).txt"
  {
    echo "== raven update status"
    raven update status || true
    echo "== raven update download"
    raven update download || true
    echo "== raven security"
    raven security || true
    echo "== node log: update lines"
    grep -E 'raven-node updates:|update_exchange' "$HOME_DIR/node.log" | tail -n 50 || true
  } >"$out" 2>&1
  echo "wrote $out"
}

# ── The dry run: A, B and C on loopback ─────────────────────────────────────

# Wait up to 120 s for `raven update status` in home `$1` to contain `$2`.
wait_status() {
  local home="$1" want="$2" i
  for ((i = 0; i < 480; i++)); do
    if "$KIT_BIN/raven" --data-dir "$home/profile" update status 2>/dev/null | grep -qF -- "$want"; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

cmd_dry_run() {
  # Global, not local: the EXIT trap below stops the nodes from it.
  DRY_DIR="${RAVEN_UPDATE_DRY_DIR:-}"
  if [[ -z "$DRY_DIR" ]]; then
    DRY_DIR="$(mktemp -d)"
  else
    mkdir -p "$DRY_DIR"
    [[ -z "$(ls -A "$DRY_DIR")" ]] || die "$DRY_DIR is not empty"
  fi
  DRY_DIR="$(cd "$DRY_DIR" && pwd -P)"
  local dir="$DRY_DIR"
  echo "dry run in $dir"
  local name ok=1
  in_home() {
    use_home "$DRY_DIR/$1"
    KIT_BIN="$DRY_DIR/bin"
  }
  cleanup() {
    local n
    for n in a b c; do
      [[ -d "$DRY_DIR/$n" ]] || continue
      in_home "$n"
      stop_node
    done
  }
  trap cleanup EXIT
  for name in a b c; do
    in_home "$name"
    if [[ "$name" == a ]]; then
      build raven raven-node raven-release
    fi
    mkdir -p "$PROFILE"
    chmod 700 "$PROFILE"
    raven init >"$HOME_DIR/identity.txt"
    raven prekey publish >/dev/null
    start_node 127.0.0.1:0
  done
  # Pin the dry run's laptop `$2` (its home) as `$1` here.
  pin() {
    local id="$DRY_DIR/$2/identity.txt"
    cmd_add "$1" "$(field address <"$id")" "$(field pub_hex <"$id")" \
      "$(field fingerprint <"$id")" "$(cat "$DRY_DIR/$2/dial.txt")" >/dev/null
  }
  in_home a && pin bob b
  in_home b && pin alice a && pin carol c
  in_home c && pin bob b
  in_home a && cmd_publish >/dev/null
  check() {
    if "$@"; then
      echo "PASS  ${*: -1}"
    else
      echo "FAIL  ${*: -1}"
      ok=0
    fi
  }
  local code
  for hop in "b alice" "c bob"; do
    set -- $hop
    in_home "$1"
    cmd_link "$2" >/dev/null
    check wait_status "$dir/$1" "from the Raven project: #1"
    code="$({ raven update download || true; } | sed -n 's/.*raven update download \([0-9a-f]\{8\}\).*/\1/p' | head -n 1)"
    if [[ -z "$code" ]]; then
      echo "FAIL  $1 was offered no release"
      ok=0
      continue
    fi
    if ! RAVEN_LAB_UPDATE_AUTO_APPROVE=1 raven update download "$code" >/dev/null; then
      echo "FAIL  $1 could not approve $code"
      ok=0
      continue
    fi
    check wait_status "$dir/$1" "is downloaded and checked"
  done
  trap - EXIT
  cleanup
  if [[ "$ok" == 1 ]]; then
    echo "dry run: PASS (a notice and a release passed A -> B -> C on loopback)"
    [[ -n "${RAVEN_UPDATE_DRY_DIR:-}" ]] || rm -rf "$dir"
  else
    echo "dry run: FAIL (kept $dir)"
    exit 1
  fi
}

# ── The self-test: a running program is never written over ───────────────

# Stand-ins for the programs, no build and no node: shell scripts that sleep
# (a script runs as `/bin/sh PATH ...`, which pids_running sees as a process
# of PATH, as lsof sees a binary's text). Checks what `setup`, `publish` and
# a dry run do to bin/ while this home's node runs and after it stopped.
cmd_selftest() {
  ST_DIR="$(mktemp -d)"
  ST_DIR="$(cd "$ST_DIR" && pwd -P)"
  ST_PID=""
  local dir="$ST_DIR" pass=0 fail=0 out="$ST_DIR/out.txt" prog i
  st_cleanup() {
    [[ -z "$ST_PID" ]] || kill "$ST_PID" 2>/dev/null || true
    [[ -z "$ST_PID" ]] || wait "$ST_PID" 2>/dev/null || true
    rm -rf "$ST_DIR"
  }
  trap st_cleanup EXIT
  check() {
    if eval "$2"; then
      echo "PASS  $1"
      pass=$((pass + 1))
    else
      echo "FAIL  $1"
      fail=$((fail + 1))
    fi
  }
  # `stand_in DIR VERSION`: the three programs, each saying its version.
  stand_in() {
    mkdir -p "$1"
    for prog in raven raven-node raven-release; do
      # Seconds of 1 s each: stopped, it leaves no sleep behind for long.
      printf '#!/bin/sh\n# %s %s\ni=0\nwhile [ "$i" -lt "${1:-0}" ]; do sleep 1; i=$((i + 1)); done\n' \
        "$prog" "$2" >"$1/$prog"
      chmod 755 "$1/$prog"
    done
  }
  no_temp_left() { [[ -z "$(ls -A "$KIT_BIN" | grep '^\.' || true)" ]]; }
  stand_in "$dir/old" 1
  stand_in "$dir/new" 2
  KIT_BIN="$dir/bin"
  export RAVEN_UPDATE_SKIP_BUILD=1

  BUILD="$dir/old"
  check "a new bin/ gets the three programs" \
    "(build raven raven-node raven-release) >'$out' 2>&1 && cmp -s '$dir/old/raven-node' '$KIT_BIN/raven-node' && cmp -s '$dir/old/raven-release' '$KIT_BIN/raven-release'"
  ln "$KIT_BIN/raven-node" "$dir/node-link"
  "$KIT_BIN/raven-node" 120 </dev/null >/dev/null 2>&1 &
  ST_PID=$!
  for ((i = 0; i < 50; i++)); do
    [[ -z "$(pids_running "$KIT_BIN/raven-node")" ]] || break
    sleep 0.1
  done
  check "the node that runs from bin/ is seen (pid $ST_PID)" \
    "[[ \" \$(pids_running '$KIT_BIN/raven-node') \" == *' $ST_PID '* ]]"

  BUILD="$dir/new"
  rm -f "$KIT_BIN/raven-release"
  check "publish's step (raven-release only) passes while the node runs" \
    "(build raven-release) >'$out' 2>&1 && cmp -s '$dir/new/raven-release' '$KIT_BIN/raven-release'"
  check "... and leaves the running raven-node as it was" \
    "cmp -s '$dir/old/raven-node' '$KIT_BIN/raven-node' && kill -0 $ST_PID"
  check "setup's programs while the node runs: refused" \
    "! (build raven raven-node) >'$out' 2>&1 && grep -q 'refusing to replace .*raven-node: it runs now' '$out'"
  check "... the refusal says how to go on" "grep -q 'stop it first' '$out'"
  check "... the running raven-node is untouched and still runs" \
    "cmp -s '$dir/old/raven-node' '$KIT_BIN/raven-node' && kill -0 $ST_PID"
  check "the same program again while it runs: nothing to do" \
    "(install_prog '$dir/old/raven-node' '$KIT_BIN/raven-node') >'$out' 2>&1 && kill -0 $ST_PID"
  check "no temp file is left in bin/" "no_temp_left"

  kill "$ST_PID" 2>/dev/null || true
  wait "$ST_PID" 2>/dev/null || true
  ST_PID=""
  check "the node stopped: the new raven-node goes in" \
    "(build raven raven-node) >'$out' 2>&1 && cmp -s '$dir/new/raven-node' '$KIT_BIN/raven-node' && [[ -x '$KIT_BIN/raven-node' ]]"
  check "... by a rename: the old file was never written over (its hard link keeps version 1)" \
    "cmp -s '$dir/old/raven-node' '$dir/node-link'"
  check "no temp file is left in bin/" "no_temp_left"
  trap - EXIT
  st_cleanup
  echo "selftest: $pass passed, $fail failed"
  [[ "$fail" == 0 ]]
}

cmd="${1:-}"
[[ $# -gt 0 ]] && shift
case "$cmd" in
  setup)
    [[ $# -ge 1 ]] || die "setup NAME [IP]"
    use_home "$HOME_DIR"
    cmd_setup "$@"
    ;;
  add)
    [[ $# -eq 5 ]] || die "add TAG ADDRESS PUB_HEX FINGERPRINT IP:PORT"
    use_home "$HOME_DIR"
    cmd_add "$@"
    ;;
  publish) use_home "$HOME_DIR" && cmd_publish ;;
  link)
    [[ $# -eq 1 ]] || die "link TAG"
    use_home "$HOME_DIR"
    cmd_link "$1"
    ;;
  approve) use_home "$HOME_DIR" && cmd_approve "$@" ;;
  status) use_home "$HOME_DIR" && raven update status ;;
  report) use_home "$HOME_DIR" && cmd_report "$@" ;;
  stop) use_home "$HOME_DIR" && stop_node ;;
  dry-run) cmd_dry_run ;;
  selftest) cmd_selftest ;;
  *) sed -n '2,78p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
