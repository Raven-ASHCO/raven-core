#!/usr/bin/env bash
# Builds the downloadable Linux package of Raven core:
#   <out>/raven-linux-<arch>-<version>.tar.gz and <out>/raven-linux-<arch>-<version>.tar.gz.sha256
# for x86_64 or aarch64, from this checkout. Run it on the Linux it is for
# (Ubuntu 24.04 is what it is made on: a CI runner for x86_64, a Lima Ubuntu
# VM on an Apple silicon Mac for aarch64):
#
#   scripts/release/make-linux.sh [--out DIR] [--target-dir DIR] [--from DIR] [--keep]
#
# Build tools (Ubuntu 24.04):
#   sudo apt-get install -y build-essential pkg-config cmake perl git curl
#   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.98.0
# (Rust 1.98.0 is what CI uses; build-essential brings gcc, make, strip and
# objdump; aws-lc-sys, ring, SQLCipher, zstd and xz build C code with them.)
#
# Steps:
#   1. raven (the CLI and terminal app, ash's `raven` binary), raven-node and
#      raven-tor-helper: `cargo build --release --locked -p ash -p raven-node
#      --features raven-node/tor` (Tor's helper, no Bluetooth: Linux release
#      builds have none; never the offline release tool). Build-machine
#      paths are rewritten as the macOS and Windows packages do: rustc
#      --remap-path-prefix and the C compiler's -ffile-prefix-map turn the
#      home folder into "~", and the repository, the target folder,
#      CARGO_HOME and RUSTUP_HOME into /raven-core, /target, /cargo and
#      /rustup. The flags change cargo's fingerprint: a target folder shared
#      with plain builds is rebuilt in full (--target-dir keeps them apart).
#      A cargo configuration outside the source (a folder above it, or
#      CARGO_HOME) stops the build, as for the reproducible build
#      (scripts/release/cargo_config_guard.sh).
#   2. The symbols are stripped, and every program is checked: an ELF for
#      this architecture, and no build-machine path in it (the home folder,
#      the user name as a folder under /home, any /Users/ path, the
#      repository, the target folder, CARGO_HOME, RUSTUP_HOME). The build
#      stops if one is found.
#   3. The folder raven-linux-<arch>-<version>/: bin/ (the three programs),
#      install.sh and uninstall.sh (per user: ~/.local/bin and a systemd user
#      service, as docs/INSTALL_Linux.md; install.sh runs
#      node/scripts/install/linux_systemd_user.sh, shipped as lib/, with
#      RAVEN_PREBUILT_DIR), README.txt, CHANGELOG.md, LICENSE, NOTICE,
#      BUILD-INFO.txt (commit, toolchain, target, the glibc it needs) and
#      SHA256SUMS. Then the archive (GNU tar: sorted names, owner 0, the
#      commit's time; gzip without a name or time) and its .sha256
#      ("<hash>  <name>").
#
# --from DIR packages the three programs in DIR instead of building them (a
# CI step that built them already; scripts/release/make-linux-selftest.sh).
# The checks of step 2 still run. --keep keeps the staged folder next to the
# archive (by default it is removed, so no release raven is left lying
# around). Nothing here runs a Raven program: a release raven runs on your
# real profile (~/.raven). The package is not signed.
set -euo pipefail

REPO="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
NODE="$REPO/node"
# The only feature a release package builds with. Never `release-tool`
# (node/scripts/release_tool_feature_audit.sh) and no Bluetooth.
FEATURES="raven-node/tor"

say() { echo "==> $*"; }
die() {
  echo "make-linux: $*" >&2
  exit 1
}

OUT="$REPO/dist"
TARGET_DIR="${CARGO_TARGET_DIR:-$NODE/target}"
FROM=""
KEEP=0
ARCH="${RAVEN_LINUX_ARCH:-$(uname -m)}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:?--out needs a folder}"; shift 2 ;;
    --target-dir) TARGET_DIR="${2:?--target-dir needs a folder}"; shift 2 ;;
    --from) FROM="${2:?--from needs a folder}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h | --help) sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1 (try --help)" ;;
  esac
done
case "$ARCH" in
  x86_64 | amd64) ARCH=x86_64; OBJDUMP_ARCH=x86-64; RUST_TARGET=x86_64-unknown-linux-gnu ;;
  aarch64 | arm64) ARCH=aarch64; OBJDUMP_ARCH=aarch64; RUST_TARGET=aarch64-unknown-linux-gnu ;;
  *) die "Raven's Linux package is for x86_64 or aarch64, not $ARCH" ;;
esac

VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"$/\1/p' "$NODE/Cargo.toml" | head -n 1)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] \
  || die "no version in node/Cargo.toml [workspace.package] (found '$VERSION')"
NAME="raven-linux-$ARCH-$VERSION"

# Portable spellings (GNU on Linux; the self-test also runs on macOS).
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
full_path() {
  local p=$1
  mkdir -p "$p"
  (CDPATH='' cd -- "$p" && pwd -P)
}

OUT="$(full_path "$OUT")"
COMMIT="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)"
if [[ "$COMMIT" != unknown ]] && [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
  COMMIT="$COMMIT (with local changes)"
fi
EPOCH="$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || date +%s)"

# ── 1. Build ────────────────────────────────────────────────────────────────
if [[ -z "$FROM" ]]; then
  [[ "$(uname -s)" == Linux ]] || die "build it on Linux (this is $(uname -s)); --from packages programs built elsewhere"
  [[ "$(uname -m)" == "$ARCH" || ("$(uname -m)" == arm64 && "$ARCH" == aarch64) ]] \
    || die "this computer is $(uname -m); build the $ARCH package on a $ARCH Linux"
  for tool in cargo rustc cc strip objdump git tar gzip; do
    command -v "$tool" >/dev/null 2>&1 \
      || die "$tool is missing (Ubuntu: sudo apt-get install -y build-essential pkg-config cmake perl git; Rust from rustup.rs)"
  done
  CARGO_HOME_DIR="$(full_path "${CARGO_HOME:-$HOME/.cargo}")"
  RUSTUP_HOME_DIR="$(full_path "${RUSTUP_HOME:-$HOME/.rustup}")"
  TARGET_DIR="$(full_path "$TARGET_DIR")"
  # No cargo configuration from outside the source (a wrapper, a linker or
  # [env] there would change what ships): as the reproducible build checks.
  # shellcheck source=scripts/release/cargo_config_guard.sh
  source "$REPO/scripts/release/cargo_config_guard.sh"
  raven_no_outer_cargo_config "$(dirname "$REPO")" "$CARGO_HOME_DIR" \
    || die "remove the cargo configuration named above (or build in a clean account), then run this again"
  case "$HOME$REPO$TARGET_DIR$CARGO_HOME_DIR$RUSTUP_HOME_DIR" in
    *[[:space:]]*) die "a path has a space; RUSTFLAGS cannot carry it (HOME, the repository, the target folder, CARGO_HOME, RUSTUP_HOME)" ;;
  esac
  # The last matching prefix wins (rustc and gcc alike): the home folder
  # first, then the more precise folders inside or outside it.
  remaps=("$HOME=~" "$REPO=/raven-core" "$TARGET_DIR=/target" "$CARGO_HOME_DIR=/cargo" "$RUSTUP_HOME_DIR=/rustup")
  rust_remap=""
  c_remap=""
  for m in "${remaps[@]}"; do
    rust_remap+=" --remap-path-prefix=$m"
    c_remap+=" -ffile-prefix-map=$m"
  done
  export RUSTFLAGS="${RUSTFLAGS:-}$rust_remap"
  export CFLAGS="${CFLAGS:-}$c_remap"
  export CXXFLAGS="${CXXFLAGS:-}$c_remap"
  export CARGO_TARGET_DIR="$TARGET_DIR"
  say "Building raven, raven-node and raven-tor-helper $VERSION ($RUST_TARGET, release, features: $FEATURES, build paths rewritten)"
  (cd "$NODE" && cargo build --release --locked -p ash -p raven-node --features "$FEATURES")
  FROM="$TARGET_DIR/release"
  RAVEN_SRC="$FROM/raven"
  TOOLCHAIN="$(rustc --version 2>/dev/null || echo unknown)"
  BUILT_ON="$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-}") || true)"
  [[ -n "$BUILT_ON" ]] || BUILT_ON="Linux"
else
  FROM="$(CDPATH='' cd -- "$FROM" && pwd -P)" || die "--from: no folder $FROM"
  RAVEN_SRC="$FROM/raven"
  CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
  RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
  TOOLCHAIN="not known (programs built elsewhere, packaged with --from)"
  BUILT_ON="${RAVEN_LINUX_BUILT_ON:-Linux}"
fi
for f in "$RAVEN_SRC" "$FROM/raven-node" "$FROM/raven-tor-helper"; do
  [[ -f "$f" ]] || die "no program $f"
done

# ── 2. Stage, strip and check ───────────────────────────────────────────────
WORK="$OUT/$NAME"
rm -rf "$WORK"
mkdir -p "$WORK/bin" "$WORK/lib"
install -m 755 "$RAVEN_SRC" "$WORK/bin/raven"
install -m 755 "$FROM/raven-node" "$WORK/bin/raven-node"
install -m 755 "$FROM/raven-tor-helper" "$WORK/bin/raven-tor-helper"
cleanup() { [[ "$KEEP" == 1 ]] || rm -rf "$WORK"; }
trap cleanup EXIT

ON_LINUX=0
[[ "$(uname -s)" == Linux ]] && ON_LINUX=1
if [[ "$ON_LINUX" == 1 ]]; then
  strip "$WORK"/bin/*
fi
glibc_needs=""
for f in "$WORK"/bin/*; do
  magic="$(head -c 4 "$f" | od -An -c | tr -d ' \n')"
  if [[ "$magic" == '177ELF' ]]; then
    if [[ "$ON_LINUX" == 1 ]]; then
      header="$(objdump -f "$f")"
      grep -qi "architecture: .*$OBJDUMP_ARCH" <<<"$header" \
        || die "$(basename "$f") is not an $ARCH program"
      glibc_needs+="$(objdump -T "$f" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//')"$'\n'
    fi
  elif [[ -n "${RAVEN_LINUX_SELFTEST:-}" ]]; then
    : # the self-test packages stand-ins, not programs
  else
    die "$(basename "$f") is not a Linux (ELF) program"
  fi
done
# The newest glibc symbol version any program needs.
GLIBC="$(printf '%s' "$glibc_needs" | grep -E '^[0-9]' | sort -V 2>/dev/null | tail -n 1 || true)"
[[ -n "$GLIBC" ]] || GLIBC=unknown
# No build-machine path in any program: the home folder and the user name as
# a folder (/home/<user>/), any /Users/ path, and the folders the build used
# (each with its slash, so only a path inside it counts).
leaks=("$HOME/" "/home/${USER:-$(id -un)}/" "$REPO/" "$CARGO_HOME_DIR/" "$RUSTUP_HOME_DIR/")
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  leaks+=("$CARGO_TARGET_DIR/")
fi
found=0
for f in "$WORK"/bin/*; do
  # No macOS home folder at all either (a checkout a Lima VM mounts from the
  # Mac lives under /Users/).
  for leak in "${leaks[@]}" "/Users/"; do
    [[ ${#leak} -ge 5 ]] || continue
    if LC_ALL=C grep -aqF -- "$leak" "$f"; then
      echo "make-linux: $(basename "$f") names a build-machine path: $leak" >&2
      found=1
    fi
  done
done
[[ "$found" == 0 ]] || die "build-machine paths left in the programs (step 2 above); nothing was packaged"
if [[ "$GLIBC" == unknown ]]; then
  say "Programs checked: $ARCH, no build-machine path (glibc not read: not on Linux)"
else
  say "Programs checked: $ARCH, no build-machine path, they need glibc $GLIBC or newer"
fi

# ── 3. The package ──────────────────────────────────────────────────────────
install -m 755 "$REPO/scripts/release/linux/install.sh" "$WORK/install.sh"
install -m 755 "$REPO/scripts/release/linux/uninstall.sh" "$WORK/uninstall.sh"
install -m 755 "$NODE/scripts/install/linux_systemd_user.sh" "$WORK/lib/linux_systemd_user.sh"
install -m 644 "$REPO/LICENSE" "$WORK/LICENSE"
install -m 644 "$REPO/NOTICE" "$WORK/NOTICE"
install -m 644 "$REPO/CHANGELOG.md" "$WORK/CHANGELOG.md"
printf '%s\n' "$ARCH" >"$WORK/ARCH"
glibc_words="glibc $GLIBC or newer"
[[ "$GLIBC" != unknown ]] || glibc_words="a glibc as new as the build machine's or newer"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" -e "s/@GLIBC@/$glibc_words/g" \
  -e "s|@BUILT_ON@|$BUILT_ON|g" \
  "$REPO/scripts/release/linux/README.txt" >"$WORK/README.txt"
chmod 644 "$WORK/README.txt" "$WORK/ARCH"
{
  echo "Raven core $VERSION for Linux ($ARCH)"
  echo "source: https://github.com/Raven-ASHCO/raven-core"
  echo "commit: $COMMIT"
  echo "target: $RUST_TARGET"
  echo "toolchain: $TOOLCHAIN"
  echo "built on: $BUILT_ON"
  echo "features: $FEATURES"
  echo "needs: $glibc_words, systemd user services"
  echo "built: $(date -u -d "@$EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$EPOCH" +%Y-%m-%dT%H:%M:%SZ) (the commit's time)"
} >"$WORK/BUILD-INFO.txt"
chmod 644 "$WORK/BUILD-INFO.txt"
# The staged texts name no build-machine path either.
for f in "$WORK"/*.txt "$WORK"/*.sh "$WORK"/lib/*.sh; do
  for leak in "${leaks[@]}"; do
    [[ ${#leak} -ge 5 ]] || continue
    if LC_ALL=C grep -aqF -- "$leak" "$f"; then
      die "$(basename "$f") names a build-machine path: $leak"
    fi
  done
done
(
  cd "$WORK"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort | sed 's|^\./||' | while IFS= read -r f; do
    sha256 "$f"
  done
) >"$WORK/SHA256SUMS"
chmod 644 "$WORK/SHA256SUMS"

TAR="$OUT/$NAME.tar.gz"
rm -f "$TAR" "$TAR.sha256"
if [[ "$(tar --version 2>/dev/null || true)" == *"GNU tar"* ]]; then
  tar -C "$OUT" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" \
    --format=gnu -cf - "$NAME" | gzip -9 -n >"$TAR"
else
  # Not GNU tar (the self-test on macOS): the same files, not byte for byte
  # reproducible.
  tar -C "$OUT" -cf - "$NAME" | gzip -9 -n >"$TAR"
fi
(cd "$OUT" && sha256 "$NAME.tar.gz") >"$TAR.sha256"
say "Package: $TAR"
say "Checksum: $TAR.sha256 ($(cut -d' ' -f1 <"$TAR.sha256"))"
[[ "$KEEP" == 1 ]] && say "Staged folder kept: $WORK"
echo "LINUX_PACKAGE_OK $NAME"
