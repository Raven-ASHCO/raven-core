#!/usr/bin/env bash
# Release builds read none of the RAVEN_LAB_* switches, and every production
# flag holds its pinned value: the release test sets that prove it, in one
# place for every OS CI runs (Linux, macOS and Windows), so the gate evidence
# docs/EVIDENCE.md and docs/SECURITY_REVIEW_SCOPE.md describe comes from
# each of them, not from Linux alone (security review 2026-11, DEP-2).
#
#   bash scripts/release_inert_tests.sh switches   # every lab switch set, then the
#                                                  # gate, switch and flag tests
#   bash scripts/release_inert_tests.sh pinned     # no lab switch set: the inert and
#                                                  # production_flag tests
#   bash scripts/release_inert_tests.sh --print switches|pinned
#                                                  # print the switches and commands only
#   bash scripts/release_inert_tests.sh --self-test
#                                                  # this script against a stand in cargo
#                                                  # (no build): the switches reach the
#                                                  # tests, pinned clears them, a run of
#                                                  # no test or a failed run stops it
#
# Run from node/ (CI: working-directory node). It builds and runs release
# test binaries (cargo test --locked --release); it starts no node and uses
# no network. Each cargo test must run at least one test: a filter list that
# matches nothing on some OS would otherwise pass in silence. bash 3.2 and
# Git Bash on Windows (temporary files go through cygpath when it exists).
set -euo pipefail

fail() {
  echo "release_inert_tests: $*" >&2
  exit 1
}

# --self-test: run this script against a stand in cargo in a temporary
# node folder and check what the tests would see.
self_test() {
  local script failed=0
  script="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  # Global: the EXIT trap runs after this function returns.
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/raven-release-inert-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/bin" "$tmp/node/crates/raven-core"
  : >"$tmp/node/Cargo.toml"
  cat >"$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
{
  printf 'run test_a=%s stray=%s' "${RAVEN_LAB_TEST_A:-unset}" "${RAVEN_LAB_STRAY:-unset}"
  if [[ -f "${RAVEN_LAB_CLOCK_FILE:-/nonexistent}" ]]; then printf ' clock=file'; else printf ' clock=none'; fi
  printf ' args=%s\n' "$*"
} >>"$STUB_LOG"
echo "test result: ok. ${STUB_PASSED:-3} passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.01s"
exit "${STUB_EXIT:-0}"
STUB
  chmod +x "$tmp/bin/cargo"
  check() {
    if [[ "$1" != 0 ]]; then
      echo "release_inert_tests: SELFTEST FAIL: $2" >&2
      failed=1
    fi
  }
  # stub <log> <mode> [VAR=value...]: this script against the stand in.
  stub() {
    local log="$1" mode="$2"
    shift 2
    (cd "$tmp/node" && env PATH="$tmp/bin:$PATH" STUB_LOG="$log" RUNNER_TEMP="$tmp" "$@" \
      bash "$script" "$mode" >"$log.out" 2>&1)
  }

  stub "$tmp/switches.log" switches RAVEN_LAB_STRAY=1
  check $? "switches with every test passing must pass"
  [[ "$(grep -c '^run test_a=1 stray=1 clock=file args=test --locked --release ' "$tmp/switches.log")" == 3 ]]
  check $? "switches must make three release test runs with every switch and the lab clock file set"
  grep -q -- '--features nearby-radio --lib -- netwatch:: ' "$tmp/switches.log"
  check $? "switches must test raven-node with the nearby radio built in"
  grep -q 'PASS: switches, 9 release tests in 3 runs' "$tmp/switches.log.out"
  check $? "switches must count the tests the runs report"

  stub "$tmp/pinned.log" pinned RAVEN_LAB_STRAY=1 RAVEN_LAB_TEST_A=1
  check $? "pinned with every test passing must pass"
  [[ "$(grep -c '^run test_a=unset stray=unset clock=none args=test --locked --release ' "$tmp/pinned.log")" == 2 ]]
  check $? "pinned must clear every RAVEN_LAB_* switch of the caller before its two runs"

  if stub "$tmp/none.log" pinned STUB_PASSED=0; then check 1 "a run of no test must fail"; fi
  grep -q 'no test ran' "$tmp/none.log.out"
  check $? "a run of no test must say so"

  if stub "$tmp/fail.log" switches STUB_EXIT=101; then check 1 "a failed run must fail"; fi
  [[ "$(grep -c '^run ' "$tmp/fail.log")" == 1 ]]
  check $? "a failed run must stop the script"

  [[ "$failed" == 0 ]] || exit 1
  echo "RELEASE_INERT_TESTS_SELFTEST_OK"
}
if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

print_only=0
if [[ "${1:-}" == "--print" ]]; then
  print_only=1
  shift
fi
mode="${1:-}"
case "$mode" in
  switches | pinned) ;;
  *) fail "usage: release_inert_tests.sh [--print] switches|pinned, or --self-test" ;;
esac

# Every lab switch the release test set proves inert, set at once (a lab
# build would act on each), with what each group proves. The paths need
# not exist: a release build must not read them. Moved here unchanged
# from the Linux step of raven-serverless.yml.
sw() { printf '%s=%s\n' "$1" "$2"; }
lab_switches() {
  sw RAVEN_LAB_TEST_A '1'
  sw RAVEN_LAB_ROUTE_HINTS '1'
  sw RAVEN_LAB_HINTS_NO_ANNOUNCE '1'
  sw RAVEN_LAB_FRIEND_RELAY '1'
  sw RAVEN_LAB_FRIEND_RELAY_LISTEN '127.0.0.1:0'
  sw RAVEN_LAB_RELAY_SELECT '1,1,1'
  sw RAVEN_LAB_P2P_PROFILE_RELAY '1'
  sw RAVEN_LAB_P2P_LOCAL_CANDIDATES '1'
  sw RAVEN_LAB_P2P_RELAY_ONLY '1'
  sw RAVEN_LAB_NET_TAG 'lab'
  sw RAVEN_LAB_P2P_PING '2,1'
  sw RAVEN_LAB_SESSION_RESET '1'
  sw RAVEN_LAB_CUSTODY_WAN '1'
  sw RAVEN_LAB_CUSTODY_AFTER_MS '1'
  sw RAVEN_LAB_CUSTODY_FETCH_MS '1'
  sw RAVEN_LAB_CUSTODY_PRETEND_OLD '1'
  # Phase 5 (P5.13): a custodian without the letter ops.
  sw RAVEN_LAB_CUSTODY_BASE_OPS_ONLY '1'
  # Phase 5 (P5.17): multi-hop custody's lab unlock; (P5.21) the
  # forwarder's interval.
  sw RAVEN_LAB_CUSTODY_HANDOFF '1'
  sw RAVEN_LAB_CUSTODY_FORWARD_MS '1'
  sw RAVEN_LAB_OFFLINE '1'
  sw RAVEN_LAB_NOISE_PIN '1'
  sw RAVEN_LAB_LAN_DEFAULT_PORT '17420'
  sw RAVEN_LAB_LAN_AUTO '1'
  sw RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK '1'
  sw RAVEN_LAB_LAN_BEACON '1'
  sw RAVEN_LAB_LAN_BEACON_PORT '17421'
  sw RAVEN_LAB_LAN_BEACON_FAMILY 'v6'
  sw RAVEN_LAB_LAN_BEACON_BUS '/tmp/raven-lab-beacon-bus'
  # The privacy pack's (PP.1): never read in release; a release build
  # seals without RAVEN_LAB_AT_REST.
  sw RAVEN_LAB_AT_REST '1'
  sw RAVEN_LAB_ERASE_ROOT '/tmp/raven-lab-erase-root'
  sw RAVEN_LAB_AT_REST_KEY_FAULT 'unavailable'
  sw RAVEN_LAB_RETENTION_GRACE_MS '1'
  sw RAVEN_LAB_LOGIN_ITEM_ROOT '/tmp/raven-lab-login-items'
  sw RAVEN_LAB_LOGIN_ITEM_TOOLS '/tmp/raven-lab-login-tools'
  # Phase 5 (P5.3): the horizon's and the letters' lab unlocks.
  sw RAVEN_LAB_HORIZON '1'
  sw RAVEN_LAB_LETTER '1'
  # Groups (docs/design/2026-10-groups.md): the lab unlock.
  sw RAVEN_LAB_GROUPS '1'
  # Phase 5 (P5.25-P5.28): nearby's lab unlock, its ether hub, the
  # public-address allowance, the shorter foreground and the network
  # audit: never read in release.
  sw RAVEN_LAB_NEARBY '1'
  sw RAVEN_LAB_NEARBY_ETHER '127.0.0.1:9'
  sw RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR '1'
  sw RAVEN_LAB_NEARBY_FOREGROUND_MS '1'
  # Offline mesh carry Phase 0: the field test's Bluetooth-only
  # switch; no gate reads it in release (raven-core
  # `nearby_gate::tests::nearby_only_closes_and_never_opens`).
  sw RAVEN_LAB_NEARBY_ONLY '1'
  # The Tor onion carrier (on in release builds since 2026-10): its
  # close switch, the helper path, the loopback helper and the race's
  # head start are never read in release (raven-core `onion_gate::`).
  sw RAVEN_LAB_TOR '1'
  sw RAVEN_TOR_HELPER '/tmp/raven-lab-no-tor-helper'
  sw RAVEN_LAB_TOR_LOOPBACK '/tmp/raven-lab-tor-loopback'
  sw RAVEN_LAB_TOR_HEAD_START_MS '1'
  sw RAVEN_LAB_NET_AUDIT '/tmp/raven-lab-net-audit'
  # Phase 4 (P4.1): its six gates stay at their consts and its
  # harness values are never read.
  sw RAVEN_LAB_WSS '1'
  sw RAVEN_LAB_WSS_PROXY '1'
  sw RAVEN_LAB_PORT_MAP '1'
  sw RAVEN_LAB_V6_PINHOLE '1'
  sw RAVEN_LAB_NAT_CLASS '1'
  sw RAVEN_LAB_PEER_ROTATION '1'
  sw RAVEN_LAB_PORTMAP_GATEWAY '127.0.0.1:5351'
  sw RAVEN_LAB_PORTMAP_LIFETIME '8'
  sw RAVEN_LAB_NAT_CLASS_FORCE 'varies'
  sw RAVEN_LAB_PEER_EPOCH_S '10'
  # Auto-reach: STUN discovery and serverless punching stay at their
  # consts (on in release builds since 2026-10) and their harness
  # values are never read (raven-core
  # `portmap_gate::lab_switches_are_inert_in_release`).
  sw RAVEN_LAB_STUN_DISCOVERY '1'
  sw RAVEN_LAB_SERVERLESS_PUNCH '1'
  sw RAVEN_LAB_STUN_SERVERS '127.0.0.1:9'
  sw RAVEN_LAB_STUN_REFRESH_S '5'
  sw RAVEN_LAB_PUNCH_SLOT_S '5'
  # Phase 6a (P6.2): learning connectivity's unlock, its harness
  # timings and the sealer fault; learning stays shut, untuned and
  # sealed in release (raven-core
  # `learning_lab_switches_are_inert_without_debug_assertions`).
  sw RAVEN_LAB_LEARNING '1'
  sw RAVEN_LAB_LEARNING_TUNE '1,1,1'
  sw RAVEN_LAB_LEARNING_SEALER 'unavailable'
  # Phase 6b (P6.21): the sensing gates' switches; no SEC_* event is
  # noted or answered and no session profile is refused in release
  # (raven-core `security_lab_switches_are_inert_without_debug_assertions`
  # and `security_gate::`, raven-node `security::` with its gates
  # shut).
  sw RAVEN_LAB_SECURITY_EVENTS '1'
  sw RAVEN_LAB_SECURITY_RESPONSES '1'
  sw RAVEN_LAB_SUITE_FLOOR '1'
  # Phase 6b (P6.26): the penalty box's loopback switch; loopback stays
  # exempt in release (raven-core
  # `penalty_loopback_switch_is_inert_without_debug_assertions`).
  sw RAVEN_LAB_SEC_PENALTY_LOOPBACK '1'
  # Phase 6b (P6.34): PAD1 link padding's lab switch; no link offers
  # or sends RPD1 in release (raven-node `link::`).
  sw RAVEN_LAB_LINK_PADDING '1'
  # Phase 6b (P6.35): the RLK1 link knock's lab switch; no dial knocks
  # and no listener reads a knock in release (raven-node
  # `link_knock::`).
  sw RAVEN_LAB_LINK_KNOCK '1'
  # Phase 6b (P6.36): the random LAN port's lab switch; no new
  # profile picks a port and none is read in release (raven-core
  # `random_port_lab_switch_is_inert_in_release`).
  sw RAVEN_LAB_RANDOM_PORT '1'
  # Phase 6b (P6.38): pair seeds' lab switch; no RRH1 carries a seed
  # and every beacon, knock and Bluetooth key comes from the root in
  # release (raven-core `pair_seed::`, raven-node `pair_seed::`).
  sw RAVEN_LAB_PAIR_SEED '1'
  # Phase 6b (P6.40): Lock now v2's lab switch; nothing locks and
  # Status has no `locked` in release.
  sw RAVEN_LAB_LOCAL_PROTECTION '1'
  # Phase 6b (P6.44): the advisory gate's switch; the update state
  # reads and writes nothing in release, and the lab release key
  # set (written below) is never read there.
  sw RAVEN_LAB_ADVISORY '1'
  # Phase 6b (P6.47): the release bundle gate's switch; `raven
  # update` stages, installs and records nothing in release.
  sw RAVEN_LAB_RELEASE_BUNDLE '1'
  # Phase 6b (P6.48): the mesh update gate's switch; the RUP1
  # exchange (`update_exchange::live`) stays shut in release.
  sw RAVEN_LAB_MESH_UPDATE '1'
  # Phase 6b (P6.49): the lab download approval and install word;
  # nothing is approved or typed by itself in release.
  sw RAVEN_LAB_UPDATE_AUTO_APPROVE '1'
  # Phase 6b (P6.51): the lab friend whose HAVE claims a newer
  # notice than it holds; no HAVE claims anything it lacks in release.
  sw RAVEN_LAB_UPDATE_CLAIM_NEWER '1'
}

# raven-core: every gate module, and each switch test by name.
core_inert=(
  lan_gate:: p2p_gate:: route_hints:: route_memory:: relay_select:: reach_diag:: clock:: horizon::
  wss_gate:: portmap_gate:: gateway:: nearby_gate:: lab_audit:: pair_seed:: security_gate::
  lan_gate::tests::learning_lab_switches_are_inert_without_debug_assertions
  lan_gate::tests::security_lab_switches_are_inert_without_debug_assertions
  lan_gate::tests::penalty_loopback_switch_is_inert_without_debug_assertions
  learning::tests::lab_tune_parse_table
  session_reset::tests::session_reset_lab_switch_is_inert_without_debug_assertions
  custody_gate::tests::handoff_live_needs_custody_and_its_own_switch
  at_rest::tests::key_fault_switch_is_inert_without_debug_assertions
  node_policy::tests::random_port_lab_switch_is_inert_in_release
  update_state::tests::release_keys_file_is_inert_without_debug_assertions
  update_state::tests::the_bundle_gate_is_inert_without_debug_assertions
  update_exchange::tests::the_exchange_is_inert_without_debug_assertions
  update_downloads::tests::auto_approve_is_inert_without_debug_assertions
  group::tests::the_lab_switch_is_inert_without_debug_assertions
  onion_gate:: internet_gate::
  custody_gate::tests::custody_flags_are_on_and_handoff_stays_off
  custody_gate::tests::gates_follow_the_consts_and_the_debug_close_switches
  custody_gate::tests::hold_text_names_the_flag_and_the_close_switch
  pair_init::tests::lab_gate_and_test_a_gate_are_inert_without_debug_assertions
  app_channel::tests::production_flags_are_on
  release_plan_is_byte_identical_with_the_gate_off
)
# Phase 5 (review cross-6): nearby's service, the custody handoff forwarder
# and the letter steps read their real gates here too, once as built by
# default and once with the platform radio built in (nearby-radio, the build
# that has a real radio backend).
node_inert=(
  netwatch:: p2p:: proxy:: hints:: friend_relay:: link:: link_knock:: pair_seed:: relay_listen_is_retired_unless_the_test_switch
  lan_default_lab_switch_is_inert_in_release
  the_lab_foreground_ttl_only_shortens_and_only_in_the_lab
  lab_bus_port_and_family_overrides_are_inert_without_debug_assertions
  nearby::tests::a_service_with_the_gate_closed_creates_no_radio
  custody::tests::forward_hops_are_nobody_with_the_handoff_gate_closed
  custody::tests::an_encounter_with_the_custody_gate_off_is_a_no_op
  letters::tests::the_letter_steps_do_nothing_with_the_letter_gate_closed
  lock_v2_lab_switch_is_inert_in_release
  update_exchange::tests::with_the_gate_shut_nothing_is_offered_sent_or_taken
  update_exchange::tests::the_newer_claim_is_inert_without_debug_assertions
  security::tests::nothing_is_noted_or_reported_while_the_gate_is_shut
  security::tests::status_is_reported_only_while_the_gate_is_live
  ipc_server::tests::seal_under_session_refused_without_lab_unlock
)

total=0
runs=0
# run_tests <command...>: runs it (or prints it with --print), shows its
# output, and fails unless it passed and ran at least one test.
run_tests() {
  if [[ "$print_only" == 1 ]]; then
    printf '%s\n' "$*"
    return 0
  fi
  local log="$work/cargo-test.log" ran
  echo "release_inert_tests: $*"
  if ! "$@" 2>&1 | tee "$log"; then
    fail "FAIL: $*"
  fi
  ran="$(awk '/^test result: /{ for (i = 2; i <= NF; i++) if ($i == "passed;") n += $(i - 1) } END { print n + 0 }' "$log")"
  [[ "$ran" -gt 0 ]] || fail "FAIL: no test ran: $*"
  total=$((total + ran))
  runs=$((runs + 1))
}

if [[ "$print_only" == 1 ]]; then
  if [[ "$mode" == switches ]]; then
    while IFS= read -r assignment; do
      printf 'export %s\n' "$assignment"
    done <<<"$(lab_switches)"
    printf 'export %s=<file>\n' RAVEN_LAB_NETWATCH_EVENTS RAVEN_LAB_CLOCK_FILE RAVEN_LAB_RELEASE_KEYS_FILE
  else
    echo "unset every RAVEN_LAB_* variable"
  fi
else
  [[ -f Cargo.toml && -d crates/raven-core ]] || fail "run it from node/ (the workspace folder)"
  # Git Bash on Windows: the shell and the test binaries name a folder
  # differently (/c/... and C:/...).
  if command -v cygpath >/dev/null 2>&1; then
    shell_path() { cygpath -u "$1"; }
    native_path() { cygpath -m "$1"; }
  else
    shell_path() { printf '%s\n' "$1"; }
    native_path() { printf '%s\n' "$1"; }
  fi
  work_parent="$(shell_path "${RUNNER_TEMP:-${TMPDIR:-/tmp}}")"
  work="$(mktemp -d "${work_parent%/}/raven-release-inert.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  if [[ "$mode" == switches ]]; then
    while IFS= read -r assignment; do
      export "$assignment"
    done <<<"$(lab_switches)"
    # Lab inputs a lab build would read: a network event script, a clock and
    # a release key set (documentation addresses only).
    printf 'up 192.0.2.10/24\negress none\n' >"$work/netwatch-events"
    printf '864000000\n' >"$work/lab-clock"
    printf '%s\n' 010203d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f017cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce >"$work/lab-release-keys"
    RAVEN_LAB_NETWATCH_EVENTS="$(native_path "$work/netwatch-events")"
    RAVEN_LAB_CLOCK_FILE="$(native_path "$work/lab-clock")"
    RAVEN_LAB_RELEASE_KEYS_FILE="$(native_path "$work/lab-release-keys")"
    export RAVEN_LAB_NETWATCH_EVENTS RAVEN_LAB_CLOCK_FILE RAVEN_LAB_RELEASE_KEYS_FILE
  else
    # The pinned values, with no lab switch from the caller.
    for name in $(compgen -e); do
      case "$name" in
        RAVEN_LAB_*) unset "$name" ;;
      esac
    done
  fi
fi

if [[ "$mode" == switches ]]; then
  run_tests cargo test --locked --release -p raven-core --lib -- "${core_inert[@]}"
  run_tests cargo test --locked --release -p raven-node --lib -- "${node_inert[@]}"
  run_tests cargo test --locked --release -p raven-node --features nearby-radio --lib -- "${node_inert[@]}"
else
  run_tests cargo test --locked --release -p raven-core --lib -- inert production_flag
  run_tests cargo test --locked --release -p raven-node --bins -- inert production_flag
fi
[[ "$print_only" == 1 ]] || echo "release_inert_tests: PASS: $mode, $total release tests in $runs runs"
