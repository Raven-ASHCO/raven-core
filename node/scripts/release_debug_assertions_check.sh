#!/usr/bin/env bash
# A build of the release profile with debug assertions on never compiles
# raven-core, ash or raven-node, and a plain release build still does
# (security review 2026-11, DEP-3).
#
# Every lab switch reader (the RAVEN_LAB_* switches, the locked-file key
# stores, the lab commands) is live only under debug_assertions, and a
# release profile can switch that on: CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS
# set to true, RUSTFLAGS with -Cdebug-assertions, or a per-package profile
# override. Each of the three crates holds a const assert against it in its
# src/lib.rs. This checks each crate with a per-package override of its own,
# so no crate leans on the assert of a crate below it, and checks that what
# stops the build is that crate's assert.
#
#   bash scripts/release_debug_assertions_check.sh check [--offline]
#   bash scripts/release_debug_assertions_check.sh --self-test
#                       # this script against a stand in cargo (no build):
#                       # a crate that compiles, stops for another reason or
#                       # is not the one that stops, and a plain release
#                       # check that fails, are each caught
#
# Run from node/ (CI: working-directory node). It runs cargo check of the
# release profile: no code is generated, no program is made and none is run;
# --offline is passed on to cargo. bash 3.2.
set -euo pipefail

MESSAGE="debug assertions in a release build open the lab gates"
CRATES="raven-core ash raven-node"

fail() {
  echo "release_debug_assertions_check: $*" >&2
  exit 1
}

# --self-test: run this script against a stand in cargo.
self_test() {
  local script failed=0
  script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  # Global: the EXIT trap runs after this function returns.
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/raven-release-da-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/bin" "$tmp/node"
  # STUB_ASSERTS: the crates whose assert stops a build with debug
  # assertions; STUB_OTHER: crates that stop for another reason; STUB_BLAME:
  # the crate the error names (default: the one checked); STUB_PLAIN=1: the
  # plain release check fails.
  cat >"$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_LOG"
crate=""
for a in "$@"; do
  case "$a" in
    profile.release.package.*.debug-assertions=true)
      crate="${a#profile.release.package.}"
      crate="${crate%.debug-assertions=true}"
      ;;
  esac
done
if [[ -z "$crate" ]]; then
  if [[ "${STUB_PLAIN:-0}" == 1 ]]; then
    echo 'error: could not compile `ash` (bin "raven") due to 1 previous error' >&2
    exit 101
  fi
  exit 0
fi
case " ${STUB_ASSERTS:-} " in
  *" $crate "*)
    echo "error[E0080]: evaluation panicked: debug assertions in a release build open the lab gates" >&2
    echo "error: could not compile \`${STUB_BLAME:-$crate}\` (lib) due to 1 previous error" >&2
    exit 101
    ;;
esac
case " ${STUB_OTHER:-} " in
  *" $crate "*)
    echo "error[E0425]: cannot find value \`x\` in this scope" >&2
    echo "error: could not compile \`$crate\` (lib) due to 1 previous error" >&2
    exit 101
    ;;
esac
exit 0
STUB
  chmod +x "$tmp/bin/cargo"
  check() {
    if [[ "$1" != 0 ]]; then
      echo "release_debug_assertions_check: SELFTEST FAIL: $2" >&2
      failed=1
    fi
  }
  # stub <log> [VAR=value...] -- [args...]: this script against the stand in.
  stub() {
    local log="$1"
    shift
    local vars=()
    while [[ "$1" != -- ]]; do
      vars+=("$1")
      shift
    done
    shift
    (cd "$tmp/node" && env PATH="$tmp/bin:$PATH" STUB_LOG="$log" ${vars[@]+"${vars[@]}"} \
      bash "$script" check "$@" >"$log.out" 2>&1)
  }
  local all="STUB_ASSERTS=raven-core ash raven-node"

  stub "$tmp/pass.log" "$all" -- --offline
  check $? "every crate stopped by its own assert must pass"
  [[ "$(grep -c -- '^check --locked --offline --release ' "$tmp/pass.log")" == 4 ]]
  check $? "it must make four release checks (one plain, one per crate), each --locked and --offline"
  local crate
  for crate in $CRATES; do
    grep -q -- "-p $crate --lib --bins --config profile.release.package.$crate.debug-assertions=true\$" "$tmp/pass.log"
    check $? "$crate must be checked with debug assertions on for itself only"
  done
  grep -q 'PASS: raven-core, ash and raven-node' "$tmp/pass.log.out"
  check $? "a pass must say so"

  stub "$tmp/online.log" "$all" --
  check $? "without --offline it must pass too"
  if grep -q -- '--offline' "$tmp/online.log"; then check 1 "--offline must be passed on only when given"; fi

  if stub "$tmp/missing.log" "STUB_ASSERTS=raven-core raven-node" --; then
    check 1 "a crate that compiles with debug assertions in the release profile must fail"
  fi
  grep -q 'ash compiles in the release profile with debug assertions on' "$tmp/missing.log.out"
  check $? "the failure must name the crate that compiles"

  if stub "$tmp/other.log" "STUB_ASSERTS=raven-core raven-node" STUB_OTHER=ash --; then
    check 1 "a crate that stops for another reason must fail"
  fi
  if stub "$tmp/blame.log" "$all" STUB_BLAME=raven-core --; then
    check 1 "a crate stopped by the assert of another crate must fail"
  fi
  if stub "$tmp/plain.log" "$all" STUB_PLAIN=1 --; then
    check 1 "a plain release check that fails must fail"
  fi

  if [[ "$failed" -ne 0 ]]; then
    exit 1
  fi
  echo "PASS: self test: a crate that compiles, one that stops for another reason or at another assert, and a failing plain release check are each caught"
}

run_check() {
  local offline="" crate rc
  [[ "$#" -le 1 ]] || fail "usage: release_debug_assertions_check.sh check [--offline], or --self-test"
  case "${1:-}" in
    "") ;;
    --offline) offline=--offline ;;
    *) fail "usage: release_debug_assertions_check.sh check [--offline], or --self-test" ;;
  esac
  # Global: the EXIT trap runs after this function returns.
  log="$(mktemp "${TMPDIR:-/tmp}/raven-release-da.XXXXXX")"
  trap 'rm -f "$log"' EXIT
  # The asserts must not stop a release build without debug assertions.
  if ! cargo check --locked ${offline:+"$offline"} --release -p raven-core -p ash -p raven-node \
    --lib --bins >"$log" 2>&1; then
    cat "$log" >&2
    fail "the release profile without debug assertions does not compile (above)"
  fi
  echo "release_debug_assertions_check: the release profile without debug assertions compiles"
  for crate in $CRATES; do
    rc=0
    cargo check --locked ${offline:+"$offline"} --release -p "$crate" --lib --bins \
      --config "profile.release.package.$crate.debug-assertions=true" >"$log" 2>&1 || rc=$?
    if [[ "$rc" -eq 0 ]]; then
      fail "$crate compiles in the release profile with debug assertions on, so its lab switches would be live (its const assert in src/lib.rs is missing)"
    fi
    if ! grep -qF "$MESSAGE" "$log" || ! grep -qF "could not compile \`$crate\`" "$log"; then
      cat "$log" >&2
      fail "$crate in the release profile with debug assertions on stopped for another reason (above), not at its own assert"
    fi
    echo "release_debug_assertions_check: $crate stops at its assert in the release profile with debug assertions on"
  done
  echo "PASS: raven-core, ash and raven-node each refuse the release profile with debug assertions on, and compile without them"
}

case "${1:-}" in
  --self-test) self_test ;;
  check)
    shift
    run_check "$@"
    ;;
  *) fail "usage: release_debug_assertions_check.sh check [--offline], or --self-test" ;;
esac
