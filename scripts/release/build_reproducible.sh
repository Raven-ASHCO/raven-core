#!/usr/bin/env bash
# Reproducible release build (Phase 6 P6.46, design D §9, owner decision
# OD6b-27): the binaries scripts/release/build_unsigned.sh ships, built so
# that anyone building the same commit with the same toolchain on the same
# kind of system gets the same bytes, wherever the checkout is and whoever
# builds it.
#
#   scripts/release/build_reproducible.sh --out <new folder> [--allow-dirty]
#       [--source <checkout>]   (default: the checkout holding this script)
#       [--keep]                (keep the build folder afterwards)
#
# Writes <out>/bin/ (ash, raven-node, raven-swarm), <out>/docs/ (the install
# guides), <out>/BUILDINFO (source commit and its time, toolchain, target,
# version, build serial) and <out>/SHA256SUMS.
#
# What makes it reproducible: the pinned toolchain (rustc 1.98.0, as CI);
# `cargo build --locked --release` with no incremental build;
# SOURCE_DATE_EPOCH from the commit time; and a fixed build path: the
# commit's tracked files are copied to /tmp/raven-reproducible/src and built
# there with a cargo home of its own (/tmp/raven-reproducible/cargo, no user
# configuration), both remapped to /raven and /cargo for Rust and C. Cargo
# also reads a .cargo/config(.toml) in every folder above the one it builds
# in, and /tmp is open to every local account: the build stops if one is
# there (or in the build folder or its cargo home), before cargo runs and
# again after it (scripts/release/cargo_config_guard.sh). Absolute
# paths still reach object files (a crate's own folder, compiled in and then
# dropped by the linker) and change how the linker lays the binary out; a
# fixed path keeps them the same. On macOS the linker also writes no debug
# map (it names the toolchain's files by their path in the user's home).
#
# These are the binaries before platform signing (notarization,
# Authenticode): their hashes are each file's rebuild_sha256 in the release
# manifest (make_bundle.sh), which reproduce_check.sh compares. On Linux the
# shipped binaries are these bytes; on macOS and Windows the comparison is
# best effort. The offline release tool (ash feature `release-tool`) is
# never built here (node/scripts/release_tool_feature_audit.sh checks this
# file). A release is built from a clean checkout of a commit;
# --allow-dirty (the checkout's tracked files as they are) is for dry runs
# only and is recorded in BUILDINFO. One build at a time per machine; the
# build folder belongs to the user who made it.
set -euo pipefail

TOOLCHAIN="1.98.0"
ROOT="/tmp/raven-reproducible"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release/cargo_config_guard.sh
source "$HERE/cargo_config_guard.sh"

usage() {
  echo "usage: scripts/release/build_reproducible.sh --out <new folder> [--allow-dirty] [--source <checkout>] [--keep]"
}

out=""
allow_dirty=0
keep=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      out="$2"
      shift 2
      ;;
    --source)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      REPO="$(cd "$2" && pwd -P)"
      shift 2
      ;;
    --allow-dirty)
      allow_dirty=1
      shift
      ;;
    --keep)
      keep=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "build_reproducible: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done
if [[ -z "$out" ]]; then
  usage >&2
  exit 2
fi
if [[ -e "$out" ]] && [[ -n "$(ls -A "$out" 2>/dev/null)" ]]; then
  echo "build_reproducible: $out is not empty" >&2
  exit 2
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# The toolchain: the rustc on PATH when it is the pinned one, else the
# pinned one through rustup (which installs it on first use). The build's
# own cargo home below must not hide rustup's toolchains.
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
rustc_version="$(rustc --version 2>/dev/null || true)"
case "$rustc_version" in
  "rustc $TOOLCHAIN "*) ;;
  *)
    export RUSTUP_TOOLCHAIN="$TOOLCHAIN"
    rustc_version="$(rustc --version)"
    ;;
esac
case "$rustc_version" in
  "rustc $TOOLCHAIN "*) ;;
  *)
    echo "build_reproducible: needs rustc $TOOLCHAIN (rustup toolchain install $TOOLCHAIN); found: $rustc_version" >&2
    exit 1
    ;;
esac
target="$(rustc -vV | sed -n 's/^host: //p')"

commit="$(git -C "$REPO" rev-parse HEAD)"
dirty=0
if [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]]; then
  dirty=1
  if [[ "$allow_dirty" -ne 1 ]]; then
    echo "build_reproducible: the checkout has uncommitted changes; a release is built from a clean commit (--allow-dirty for a dry run)" >&2
    exit 1
  fi
fi
SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct HEAD)"
export SOURCE_DATE_EPOCH

# The fixed build folder: this user's, one build at a time, a fresh copy of
# the tracked files every time (the cargo home is kept: downloads only).
mkdir -p "$ROOT"
ROOT="$(cd "$ROOT" && pwd -P)"
if [[ ! -O "$ROOT" ]]; then
  echo "build_reproducible: $ROOT belongs to another user; remove it first" >&2
  exit 1
fi
if ! mkdir "$ROOT/.lock" 2>/dev/null; then
  echo "build_reproducible: another reproducible build is running ($ROOT/.lock)" >&2
  exit 1
fi
cleanup() {
  if [[ "$keep" -eq 0 ]]; then
    rm -rf "$ROOT/src"
  fi
  rmdir "$ROOT/.lock" 2>/dev/null || true
}
trap cleanup EXIT
SRC="$ROOT/src"
rm -rf "$SRC"
mkdir -p "$SRC" "$ROOT/cargo"
(cd "$REPO" && git ls-files -z | tar --null -T - -cf -) | tar -xf - -C "$SRC"
NODE="$SRC/node"

version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' "$NODE/Cargo.toml" | head -n 1)"
build_serial="$(sed -n 's/^pub const BUILD_SERIAL: u64 = \([0-9_]*\);$/\1/p' \
  "$NODE/crates/raven-core/src/update_state/release_build.rs" | tr -d '_')"
if [[ -z "$version" || -z "$build_serial" ]]; then
  echo "build_reproducible: cannot read the version or BUILD_SERIAL from the source" >&2
  exit 1
fi

export CARGO_HOME="$ROOT/cargo"
unset RUSTFLAGS RUSTDOCFLAGS
flags=("--remap-path-prefix=$SRC=/raven" "--remap-path-prefix=$CARGO_HOME=/cargo")
case "$target" in
  *-apple-*)
    # No debug map in the binary (-S): it would name the standard library's
    # files by their path under the user's home, and LC_UUID hashes it.
    # Nothing is lost: release binaries carry no debug information.
    flags+=("-Clink-arg=-Wl,-S")
    ;;
esac
CARGO_ENCODED_RUSTFLAGS="$(
  IFS=$'\037'
  echo "${flags[*]}"
)"
export CARGO_ENCODED_RUSTFLAGS
export CFLAGS="-ffile-prefix-map=$SRC=/raven -ffile-prefix-map=$CARGO_HOME=/cargo"
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$NODE/target/reproducible"
export CARGO_TERM_COLOR=never

echo "build_reproducible: $commit ($target, rustc $TOOLCHAIN, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH) in $SRC"
# No cargo configuration but the source's own: none above the build folder
# (another account can write /tmp/.cargo), in it, or in its cargo home.
if ! raven_no_outer_cargo_config "$ROOT" "$CARGO_HOME"; then
  echo "build_reproducible: a cargo configuration outside the source would change this build; remove it (and find out who put it there), then build again" >&2
  exit 1
fi
# The same packages as build_unsigned.sh; no features.
(cd "$NODE" && cargo build --locked --release -p raven-node -p ash -p raven-swarm)
if ! raven_no_outer_cargo_config "$ROOT" "$CARGO_HOME"; then
  echo "build_reproducible: a cargo configuration appeared during the build; its binaries are not used" >&2
  exit 1
fi

exe=""
case "$target" in
  *windows*) exe=".exe" ;;
esac
mkdir -p "$out/bin" "$out/docs"
for name in ash raven-node raven-swarm; do
  cp "$CARGO_TARGET_DIR/release/$name$exe" "$out/bin/$name$exe"
  chmod 755 "$out/bin/$name$exe"
done
for doc in INSTALL_macOS.md INSTALL_Linux.md INSTALL_Windows.md SERVERLESS_MODEL.md; do
  cp "$SRC/docs/$doc" "$out/docs/$doc"
  chmod 644 "$out/docs/$doc"
done

{
  echo "source_commit=$commit"
  echo "source_date_epoch=$SOURCE_DATE_EPOCH"
  echo "toolchain=$TOOLCHAIN"
  echo "target=$target"
  echo "version=$version"
  echo "build_serial=$build_serial"
  echo "dirty=$dirty"
} >"$out/BUILDINFO"
(
  cd "$out"
  for f in bin/* docs/*; do
    echo "$(sha256_of "$f")  $f"
  done | LC_ALL=C sort -k2
) >"$out/SHA256SUMS"

cat "$out/SHA256SUMS"
echo "OUT=$out"
echo "REPRODUCIBLE_BUILD_OK"
