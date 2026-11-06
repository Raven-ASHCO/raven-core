#!/usr/bin/env bash
# Self-test for scripts/release/cargo_config_guard.sh (Phase 6 review
# lock-updates-local-5; security review 2026-11 DEP-1): a cargo
# configuration in a folder above the build folder, in it, or in the build's
# cargo home stops the reproducible build; none lets it run. So does a
# rustup toolchain file above it, a build folder that is a symlink, and an
# outer .cargo another account could write into while cargo starts; the
# build folder is made private, and the pinned toolchain is always exported.
# Needs no build (rustc and cargo are stand-in scripts); runs in a moment.
#
# Usage: bash scripts/release/cargo_config_guard_selftest.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release/cargo_config_guard.sh
source "$HERE/cargo_config_guard.sh"

D="$(mktemp -d "${TMPDIR:-/tmp}/cargo-config-guard.XXXXXX")"
D="$(cd "$D" && pwd -P)"
trap 'rm -rf "$D"' EXIT

failed=0
check() {
  echo "FAIL: $*" >&2
  failed=1
}

# The mode letters of a path (drwx------), without following a symlink.
mode_of() {
  ls -ldn "$1" | cut -c1-10
}

root="$D/outer/raven-reproducible"
home="$root/cargo"
mkdir -p "$root/src/node" "$home"

# A configuration somewhere above this test's folder (not this test's own)
# would make every case fail: say so instead.
if ! raven_no_outer_cargo_config "$root" "$home" 2>"$D/err"; then
  cat "$D/err" >&2
  echo "FAIL: a cargo configuration above $D already exists; the test cannot run here" >&2
  exit 1
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
rm -rf "$root/src/.cargo"

# 1. The build folder planted as a symlink to a folder of the builder's
# (macOS /tmp has no protected_symlinks): refused before the build empties
# its src/, and the folder it points to keeps its files. A new build folder
# is private (0700), and one left by an older build is made private.
mkdir -p "$D/victim/src"
: >"$D/victim/src/keep"
ln -s "$D/victim" "$D/outer/planted-root"
rc=0
got="$(raven_prepare_build_root "$D/outer/planted-root" 2>"$D/err")" || rc=$?
if [[ "$rc" -eq 0 ]]; then
  # What build_reproducible.sh does next with the folder it is given.
  rm -rf "$got/src"
  check "a build folder that is a symlink must be refused (it was used as $got)"
fi
[[ -f "$D/victim/src/keep" ]] || check "the folder a planted symlink points to must keep its files"
rc=0
got="$(raven_prepare_build_root "$D/outer/new-root" 2>"$D/err")" || rc=$?
[[ "$rc" -eq 0 && "$got" == "$D/outer/new-root" ]] || check "a new build folder must be made (rc=$rc, got $got)"
[[ "$(mode_of "$D/outer/new-root")" == drwx------ ]] \
  || check "a new build folder must be private, not $(mode_of "$D/outer/new-root")"
mkdir -m 755 "$D/outer/old-root"
rc=0
raven_prepare_build_root "$D/outer/old-root" >/dev/null 2>"$D/err" || rc=$?
[[ "$rc" -eq 0 && "$(mode_of "$D/outer/old-root")" == drwx------ ]] \
  || check "an older build folder of this user must be made private (rc=$rc, $(mode_of "$D/outer/old-root"))"
: >"$D/outer/file-root"
rc=0
raven_prepare_build_root "$D/outer/file-root" >/dev/null 2>"$D/err" || rc=$?
[[ "$rc" -eq 1 ]] || check "a build folder that is a file must be refused (rc=$rc)"

# 2. The .cargo beside the build folder (/tmp/.cargo for the real build):
# an empty one another account owns or can write passes both config checks,
# and a config renamed into it while cargo starts is read and never seen.
# It must be a real folder of the builder (or root) that nobody else can
# write; when there is none, the builder makes it (0755).
mkdir -m 777 "$D/outer/.cargo"
rc=0
raven_claim_outer_cargo_dir "$D/outer" 2>"$D/err" || rc=$?
[[ "$rc" -eq 1 ]] || check "an outer .cargo that others can write must stop the build (rc=$rc)"
grep -q "$D/outer/.cargo" "$D/err" || check "the error must name $D/outer/.cargo"
rmdir "$D/outer/.cargo"
ln -s "$D/victim" "$D/outer/.cargo"
rc=0
raven_claim_outer_cargo_dir "$D/outer" 2>/dev/null || rc=$?
[[ "$rc" -eq 1 ]] || check "an outer .cargo that is a symlink must stop the build (rc=$rc)"
rm -f "$D/outer/.cargo"
rc=0
raven_claim_outer_cargo_dir "$D/outer" 2>"$D/err" || rc=$?
[[ "$rc" -eq 0 ]] || check "a missing outer .cargo must be made, not refused (rc=$rc)"
[[ -d "$D/outer/.cargo" && ! -L "$D/outer/.cargo" && -O "$D/outer/.cargo" ]] \
  || check "the outer .cargo must be made, a folder of this user"
[[ -d "$D/outer/.cargo" && "$(mode_of "$D/outer/.cargo")" == drwxr-xr-x ]] \
  || check "the outer .cargo must be made 0755"
[[ "${raven_outer_cargo_made:-}" == "$D/outer/.cargo" ]] \
  || check "the build must know it made the outer .cargo (to remove it at the end)"
rc=0
raven_claim_outer_cargo_dir "$D/outer" 2>/dev/null || rc=$?
[[ "$rc" -eq 0 ]] || check "an outer .cargo of the builder must pass again (rc=$rc)"
[[ -z "${raven_outer_cargo_made:-}" ]] \
  || check "an outer .cargo that was there already is not for the build to remove"
rm -rf "$D/outer/.cargo"

# 3. A rustup toolchain file above the build folder: rustup takes the
# nearest one, and a path toolchain in it names any cargo and rustc. The
# pinned RUSTUP_TOOLCHAIN outranks it; this is the tripwire.
for name in rust-toolchain.toml rust-toolchain; do
  printf '[toolchain]\npath = "/nonexistent/planted"\n' >"$D/outer/$name"
  rc=0
  raven_no_outer_cargo_config "$root" "$home" 2>"$D/err" || rc=$?
  [[ "$rc" -eq 1 ]] || check "a $name above the build folder must stop the build (rc=$rc)"
  grep -q "$D/outer/$name" "$D/err" || check "the error must name $D/outer/$name"
  rm -f "$D/outer/$name"
done

# 4. RUSTUP_TOOLCHAIN is exported even when the rustc on PATH already says
# the pinned version (so a toolchain file or a directory override decides
# nothing), the version is checked from the build's own folder, and another
# version is refused. rustc and cargo are stand-ins here.
fake="$D/fakebin"
mkdir -p "$fake"
printf '#!/bin/sh\necho "rustc ${FAKE_VERSION:-1.98.0} (stand-in 2026-01-01)"\n' >"$fake/rustc"
printf '#!/bin/sh\necho "cargo ${FAKE_VERSION:-1.98.0} (stand-in 2026-01-01)"\n' >"$fake/cargo"
chmod 755 "$fake/rustc" "$fake/cargo"
rc=0
(
  unset RUSTUP_TOOLCHAIN
  PATH="$fake:$PATH"
  raven_pin_toolchain 1.98.0 "$root/src" >/dev/null 2>"$D/err" || exit 2
  [[ "${RUSTUP_TOOLCHAIN:-unset}" == 1.98.0 ]] || exit 3
) || rc=$?
case "$rc" in
  0) ;;
  2) check "the pinned toolchain must be accepted: $(cat "$D/err")" ;;
  *) check "RUSTUP_TOOLCHAIN must be exported as 1.98.0 even when rustc already says 1.98.0 (rc=$rc)" ;;
esac
rc=0
(
  unset RUSTUP_TOOLCHAIN
  PATH="$fake:$PATH"
  export FAKE_VERSION=1.97.0
  raven_pin_toolchain 1.98.0 "$root/src" >/dev/null 2>"$D/err"
) || rc=$?
[[ "$rc" -eq 1 ]] || check "another rustc version must be refused (rc=$rc)"

# 5. reproduce_check.sh pins the manifest's toolchain before its first
# rustc, and refuses a manifest toolchain that is not a plain version
# (rustup would take a folder there, and the manifest is not verified). Its
# rustc is a stand-in that notes RUSTUP_TOOLCHAIN and names a host no bundle
# is for, so the check stops there: nothing is cloned or built. The bundle
# is the small RRBC vector, and a copy naming a folder as its toolchain.
seen="$D/rustc-seen"
fake5="$D/fakebin5"
mkdir -p "$fake5"
printf '#!/bin/sh\nprintf "%%s\\n" "${RUSTUP_TOOLCHAIN:-unset}" >>"%s"\necho "host: stand-in-host"\n' "$seen" >"$fake5/rustc"
chmod 755 "$fake5/rustc"
python3 -I - "$HERE/../../shared-vectors/rvn1/update/rrbc_small_001.json" "$D/small.rrb" "$D/folder.rrb" <<'PY'
import json, sys

container = bytes.fromhex(json.load(open(sys.argv[1]))["expected"]["container_hex"])
assert container.count(b"\x061.98.0") == 1
open(sys.argv[2], "wb").write(container)
open(sys.argv[3], "wb").write(container.replace(b"\x061.98.0", b"\x06/tmp/x"))
PY
rc=0
(
  unset RUSTUP_TOOLCHAIN
  PATH="$fake5:$PATH" bash "$HERE/reproduce_check.sh" "$D/small.rrb" --work "$D/work" >/dev/null 2>"$D/err"
) || rc=$?
[[ "$rc" -eq 2 && ! -e "$D/work" ]] || check "reproduce_check.sh must stop at the host check (rc=$rc)"
[[ "$(cat "$seen" 2>/dev/null)" == 1.98.0 ]] \
  || check "reproduce_check.sh must pin the manifest toolchain before rustc runs (rustc saw: $(tr '\n' ' ' <"$seen" 2>/dev/null))"
: >"$seen"
rc=0
(
  unset RUSTUP_TOOLCHAIN
  PATH="$fake5:$PATH" bash "$HERE/reproduce_check.sh" "$D/folder.rrb" --work "$D/work" >/dev/null 2>"$D/err"
) || rc=$?
[[ "$rc" -eq 2 && ! -s "$seen" ]] \
  || check "a manifest toolchain that is not a plain version must stop reproduce_check.sh before rustc (rc=$rc)"

[[ "$failed" -eq 0 ]] || exit 1
echo "CARGO_CONFIG_GUARD_SELFTEST_OK"
