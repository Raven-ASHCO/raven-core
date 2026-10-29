#!/usr/bin/env bash
# Self-test for scripts/release/cargo_config_guard.sh (Phase 6 review
# lock-updates-local-5): a cargo configuration in a folder above the build
# folder, in it, or in the build's cargo home stops the reproducible build;
# none lets it run. Needs no build; runs in a moment.
#
# Usage: bash scripts/release/cargo_config_guard_selftest.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release/cargo_config_guard.sh
source "$HERE/cargo_config_guard.sh"

D="$(mktemp -d "${TMPDIR:-/tmp}/cargo-config-guard.XXXXXX")"
D="$(cd "$D" && pwd -P)"
trap 'rm -rf "$D"' EXIT

check() {
  echo "FAIL: $*" >&2
  exit 1
}

root="$D/outer/raven-reproducible"
home="$root/cargo"
mkdir -p "$root/src/node" "$home"

# A configuration somewhere above this test's folder (not this test's own)
# would make every case fail: say so instead.
if ! raven_no_outer_cargo_config "$root" "$home" 2>"$D/err"; then
  cat "$D/err" >&2
  check "a cargo configuration above $D already exists; the test cannot run here"
fi

# A planted one above the build folder (as another account could leave in
# /tmp/.cargo), either name.
for name in config.toml config; do
  mkdir -p "$D/outer/.cargo"
  printf '[build]\nrustc-wrapper = "/nonexistent/planted"\n' >"$D/outer/.cargo/$name"
  rc=0
  raven_no_outer_cargo_config "$root" "$home" 2>"$D/err" || rc=$?
  [[ "$rc" -eq 1 ]] || check "a $name above the build folder must stop the build (rc=$rc)"
  grep -q "$D/outer/.cargo/$name" "$D/err" || check "the error must name $D/outer/.cargo/$name"
  rm -rf "$D/outer/.cargo"
done

# A dangling symlink counts too.
mkdir -p "$D/outer/.cargo"
ln -s "$D/nowhere" "$D/outer/.cargo/config.toml"
rc=0
raven_no_outer_cargo_config "$root" "$home" 2>/dev/null || rc=$?
[[ "$rc" -eq 1 ]] || check "a symlinked config must stop the build (rc=$rc)"
rm -rf "$D/outer/.cargo"

# In the build folder itself, and in its cargo home.
mkdir -p "$root/.cargo"
: >"$root/.cargo/config.toml"
rc=0
raven_no_outer_cargo_config "$root" "$home" 2>/dev/null || rc=$?
[[ "$rc" -eq 1 ]] || check "a config in the build folder must stop the build (rc=$rc)"
rm -rf "$root/.cargo"
: >"$home/config.toml"
rc=0
raven_no_outer_cargo_config "$root" "$home" 2>"$D/err" || rc=$?
[[ "$rc" -eq 1 ]] || check "a config in the cargo home must stop the build (rc=$rc)"
grep -q "$home/config.toml" "$D/err" || check "the error must name the cargo home's config"
rm -f "$home/config.toml"

# The source's own configuration, below the build folder, is not refused.
mkdir -p "$root/src/.cargo"
: >"$root/src/.cargo/config.toml"
raven_no_outer_cargo_config "$root" "$home" || check "the source's own configuration is allowed"

echo "CARGO_CONFIG_GUARD_SELFTEST_OK"
