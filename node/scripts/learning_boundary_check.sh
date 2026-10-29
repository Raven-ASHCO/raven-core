#!/usr/bin/env bash
# Learning connectivity's source boundary (Phase 6a P6.17, design "Phase 6a"):
# learning only reorders what the static planner already allows and keeps
# what it learned on this computer. Its code (raven-core src/learning.rs and
# src/learning/, raven-node src/learning.rs) never:
#   1. writes the user's settings: save_policy, set_hide_ip, relay_offer,
#      `custody_use =` (an assignment; a comparison is fine), relay_allow;
#   2. opens a gate: `*PRODUCTION_ENABLED = true` (with or without `: bool`);
#   3. reads or writes the contact book by its file name (contacts.json);
#   4. puts anything it learned into what other computers receive: the
#      RRH1 route hints, RLB1 local offer and RFC1 custody encoders
#      (route_hints::encode, encode_local_offer, friend_custody::encode*).
# Product code only: a `#[cfg(test)]` test module (and a tests.rs file) may
# plant a contact book for its fixtures. Static only: no build.
# `--self-test` proves each rule fires.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# One pattern per rule (grep -E).
RULES=(
  'save_policy'
  'set_hide_ip'
  'relay_offer'
  'custody_use[[:space:]]*=([^=]|$)'
  'PRODUCTION_ENABLED([[:space:]]*:[[:space:]]*bool)?[[:space:]]*=[[:space:]]*true'
  'contacts\.json'
  'relay_allow'
  'route_hints::encode'
  'encode_local_offer'
  'friend_custody::encode'
)

# The learning sources under `node` (product code only), one per line.
sources() {
  local node="$1"
  {
    if [[ -d "$node/crates/raven-core/src" ]]; then
      find "$node/crates/raven-core/src" -maxdepth 1 -name 'learning*.rs' -type f
    fi
    if [[ -d "$node/crates/raven-core/src/learning" ]]; then
      find "$node/crates/raven-core/src/learning" -name '*.rs' -type f ! -name 'tests.rs'
    fi
    if [[ -f "$node/crates/raven-node/src/learning.rs" ]]; then
      echo "$node/crates/raven-node/src/learning.rs"
    fi
  } | LC_ALL=C sort
}

# FILE's lines as `FILE:LINE:text`, up to its test module (a `#[cfg(test)]`
# line followed by `mod tests`).
product_lines() {
  awk '
    held != "" {
      if ($0 ~ /^[[:space:]]*(pub(\(crate\))?[[:space:]]+)?mod tests/) exit
      print FILENAME ":" held_nr ":" held
      held = ""
    }
    /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ { held = $0; held_nr = NR; next }
    { print FILENAME ":" NR ":" $0 }
  ' "$1"
}

check_tree() {
  local node="$1" failures=0 files f rule hits
  files="$(sources "$node")"
  if [[ -z "$files" ]] || ! grep -q 'raven-node/src/learning.rs$' <<<"$files"; then
    echo "LEARNING_BOUNDARY_FAIL: learning sources not found under $node" >&2
    return 1
  fi
  local all=""
  while IFS= read -r f; do
    all+="$(product_lines "$f")"$'\n'
  done <<<"$files"
  for rule in "${RULES[@]}"; do
    hits="$(grep -E -- "$rule" <<<"$all" || true)"
    if [[ -n "$hits" ]]; then
      echo "LEARNING_BOUNDARY_FAIL: learning code matches /$rule/:" >&2
      echo "${hits//$node\//}" >&2
      failures=$((failures + 1))
    fi
  done
  return "$failures"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/node/crates/raven-core/src" "$tmp/node/crates/raven-node/src"
  cp "$ROOT/node/crates/raven-core/src/learning.rs" "$tmp/node/crates/raven-core/src/"
  cp -R "$ROOT/node/crates/raven-core/src/learning" "$tmp/node/crates/raven-core/src/learning"
  cp "$ROOT/node/crates/raven-node/src/learning.rs" "$tmp/node/crates/raven-node/src/"
  check_tree "$tmp/node" >/dev/null 2>&1 || { echo "self-test: clean tree must pass" >&2; return 1; }

  local node_src="$tmp/node/crates/raven-node/src/learning.rs"
  local core_src="$tmp/node/crates/raven-core/src/learning/rank.rs"
  cp "$node_src" "$tmp/node.bak"
  cp "$core_src" "$tmp/core.bak"
  local line target
  for line in \
    'fn rogue(d: &Path, p: &NodePolicy) { let _ = save_policy(d, p); }' \
    'fn rogue(p: &mut NodePolicy) { p.set_hide_ip(true); }' \
    'fn rogue(p: &mut NodePolicy) { p.relay_offer = Some(true); }' \
    'fn rogue(p: &mut NodePolicy) { p.custody_use = Some(true); }' \
    'pub const ROGUE_PRODUCTION_ENABLED: bool = true;' \
    'const BOOK: &str = "contacts.json";' \
    'fn rogue(d: &Path) { let _ = raven_core::relay_allow::tag_contact(d, "", &[]); }' \
    'fn rogue(h: &Hints) -> Vec<u8> { raven_core::route_hints::encode(h) }' \
    'fn rogue(o: &Offer) -> Vec<u8> { encode_local_offer(o) }' \
    'fn rogue(r: &Req) -> Vec<u8> { raven_core::friend_custody::encode_request(&[0; 8], r) }'; do
    for target in "$node_src" "$core_src"; do
      # Product code (the top of the file): the rule fires.
      { echo "$line"; cat "$target"; } >"$target.new" && mv "$target.new" "$target"
      if check_tree "$tmp/node" >/dev/null 2>&1; then
        echo "self-test: rule did not fire in ${target#"$tmp"/}: $line" >&2
        return 1
      fi
      cp "$tmp/node.bak" "$node_src"
      cp "$tmp/core.bak" "$core_src"
    done
  done
  # A comparison is not an assignment. (The clean tree above proves a test
  # module may plant a book: raven-node's learning tests write one.)
  { echo 'fn fine(p: &NodePolicy) -> bool { p.custody_use == Some(true) }'; cat "$node_src"; } \
    >"$node_src.new" && mv "$node_src.new" "$node_src"
  check_tree "$tmp/node" >/dev/null 2>&1 \
    || { echo "self-test: a comparison must pass" >&2; return 1; }
  echo "LEARNING_BOUNDARY_SELFTEST_OK"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi
check_tree "$ROOT/node"
echo "LEARNING_BOUNDARY_OK"
