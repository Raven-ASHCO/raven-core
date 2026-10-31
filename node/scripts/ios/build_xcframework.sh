#!/usr/bin/env bash
# Builds Raven's engine for iPhone and iPad: raven-client with its node
# embedded (the node, Tor and the IPC all inside the app; docs/IOS.md) as a
# static library for aarch64-apple-ios (devices) and aarch64-apple-ios-sim
# (Apple silicon simulators), packaged as RavenClient.xcframework with the C
# header (include/raven_client.h) and a module map (`import RavenClient` in
# Swift).
#
# Usage (from anywhere):
#   node/scripts/ios/build_xcframework.sh            # release, Tor in process
#   PROFILE=debug node/scripts/ios/build_xcframework.sh
#   FEATURES=embedded-node node/scripts/ios/build_xcframework.sh   # no Tor
#   FEATURES="tor-embedded nearby-embedded" node/scripts/ios/build_xcframework.sh
#                       # Bluetooth nearby in process too (the module map
#                       # then links CoreBluetooth, Foundation and libobjc)
#   OUT=/some/dir node/scripts/ios/build_xcframework.sh
#
# Needs: Xcode with the iOS SDK (its license accepted), and the two Rust
# targets (rustup target add aarch64-apple-ios aarch64-apple-ios-sim). It
# stops with what to do when one is missing, before building anything.
#
# A debug build honours the lab switches and the file-backed key stores
# (tests, the simulator); a release build refuses both, as on the desktop.
#
# A release library keeps no build-machine path (and so no user name) in
# its strings: the panic locations of the dependencies name their source
# files under CARGO_HOME (~/.cargo/registry/src/...), and the C code keeps
# __FILE__ paths. As the macOS and Windows packages do, rustc's
# --remap-path-prefix and the C compiler's -ffile-prefix-map rewrite the
# home folder to "~", and the checkout, the target folder, CARGO_HOME (its
# registry sources too) and RUSTUP_HOME to /raven-core, /target, /cargo and
# /rustup; RUSTFLAGS and CFLAGS already set are kept. Then every slice is
# checked with `strings -a`: a "/Users/" path, the home folder or the
# checkout in it stops the script. On by default for release, off for debug
# (a debugger then finds the sources); RAVEN_REMAP_PATHS=0|1 overrides. The
# flags change cargo's fingerprint, so the iOS targets are rebuilt in full
# once.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
NODE="$ROOT/node"
PROFILE="${PROFILE:-release}"
FEATURES="${FEATURES:-tor-embedded}"
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
TARGET_DIR="${CARGO_TARGET_DIR:-$NODE/target}"
OUT="${OUT:-$TARGET_DIR/ios}"
# The oldest iOS the library is built for (Swift concurrency, BGTaskScheduler).
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"

fail() {
  echo "build_xcframework: $*" >&2
  exit 1
}

case "$PROFILE" in
  release) CARGO_PROFILE_FLAG=(--release); PROFILE_DIR=release ;;
  debug) CARGO_PROFILE_FLAG=(); PROFILE_DIR=debug ;;
  *) fail "PROFILE must be release or debug (got '$PROFILE')" ;;
esac

# ── What must be there first ─────────────────────────────────────────────────
[[ "$(uname -s)" == "Darwin" ]] || fail "iOS libraries are built on a Mac (with Xcode)"
command -v xcrun >/dev/null 2>&1 || fail "xcrun is missing: install Xcode from the App Store"
if ! sdk_out="$(xcrun --sdk iphoneos --show-sdk-path 2>&1)"; then
  if grep -qi "license" <<<"$sdk_out"; then
    fail "Xcode's license is not accepted yet: run 'sudo xcodebuild -license accept' (or open Xcode once), then run this again"
  fi
  fail "no iOS SDK ($sdk_out): install Xcode (not only the Command Line Tools) and select it: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"
fi
xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1 \
  || fail "no iOS Simulator SDK: install Xcode's iOS platform (Xcode > Settings > Components)"
command -v xcodebuild >/dev/null 2>&1 || fail "xcodebuild is missing: install Xcode"
command -v cargo >/dev/null 2>&1 || fail "cargo is missing: install Rust (rustup)"
installed="$(rustup target list --installed 2>/dev/null || true)"
for t in "${TARGETS[@]}"; do
  grep -qx "$t" <<<"$installed" \
    || fail "the Rust target $t is missing: rustup target add ${TARGETS[*]}"
done

# ── Build-machine paths ──────────────────────────────────────────────────────
REMAP="${RAVEN_REMAP_PATHS:-}"
if [[ -z "$REMAP" ]]; then
  if [[ "$PROFILE" == release ]]; then REMAP=1; else REMAP=0; fi
fi
[[ "$REMAP" == 0 || "$REMAP" == 1 ]] || fail "RAVEN_REMAP_PATHS must be 0 or 1"
ROOT_REAL="$(cd "$ROOT" && pwd -P)"
mkdir -p "$TARGET_DIR"
TARGET_REAL="$(cd "$TARGET_DIR" && pwd -P)"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
if [[ "$REMAP" == 1 ]]; then
  case "$HOME$ROOT$ROOT_REAL$TARGET_DIR$TARGET_REAL$CARGO_HOME_DIR$RUSTUP_HOME_DIR" in
    *[[:space:]]*) fail "a path has a space (HOME, the checkout, the target folder, CARGO_HOME, RUSTUP_HOME): RUSTFLAGS cannot carry it; RAVEN_REMAP_PATHS=0 builds without the rewrite" ;;
  esac
  # The last matching prefix wins (rustc and clang alike): the home folder
  # first, then the more precise folders inside or outside it.
  remaps=("$HOME=~" "$ROOT=/raven-core" "$ROOT_REAL=/raven-core" "$TARGET_DIR=/target"
    "$TARGET_REAL=/target" "$CARGO_HOME_DIR=/cargo" "$CARGO_HOME_DIR/registry/src=/cargo/registry/src"
    "$RUSTUP_HOME_DIR=/rustup")
  rust_remap=""
  c_remap=""
  for m in "${remaps[@]}"; do
    rust_remap+=" --remap-path-prefix=$m"
    c_remap+=" -ffile-prefix-map=$m"
  done
  export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${rust_remap# }"
  export CFLAGS="${CFLAGS:+$CFLAGS }${c_remap# }"
  export CXXFLAGS="${CXXFLAGS:+$CXXFLAGS }${c_remap# }"
fi

# ── Build ────────────────────────────────────────────────────────────────────
cd "$NODE"
for t in "${TARGETS[@]}"; do
  echo "build_xcframework: raven-client ($PROFILE, features: $FEATURES) for $t"
  # Only the static library: the rlib and cdylib forms are for the desktop.
  # The debug profile's flag list is empty: macOS's bash 3.2 calls an empty
  # array unbound under set -u, so it expands only when it has a word.
  cargo rustc -p raven-client --lib ${CARGO_PROFILE_FLAG[@]+"${CARGO_PROFILE_FLAG[@]}"} \
    --features "$FEATURES" --target "$t" --crate-type staticlib
  lib="$TARGET_DIR/$t/$PROFILE_DIR/libraven_client.a"
  [[ -f "$lib" ]] || fail "no $lib after the build"
  # --no-llvm-bc: Rust's standard library objects carry LLVM bitcode newer
  # than Xcode's LLVM reads (the linker ignores it; nm would fail on it).
  # grep reads all of nm's output (no -q): an early exit would fail the
  # pipe under pipefail.
  nm -gU --no-llvm-bc "$lib" 2>/dev/null | grep "_raven_call$" >/dev/null \
    || fail "$lib does not export raven_call"
done

# ── Package ──────────────────────────────────────────────────────────────────
stage="$OUT/stage"
rm -rf "$stage" "$OUT/RavenClient.xcframework"
mkdir -p "$stage/include"
cp "$NODE/crates/raven-client/include/raven_client.h" "$stage/include/"
# Bluetooth nearby in process (raven-node's objc2 CoreBluetooth code): a
# static library carries no link directives, so the module map names them.
nearby_links=""
case " $FEATURES " in
  *" nearby-embedded "*)
    nearby_links='    link framework "CoreBluetooth"
    link framework "Foundation"
    link "objc"
'
    ;;
esac
{
  printf '%s\n' 'module RavenClient {' '    header "raven_client.h"' \
    '    link framework "Security"' '    link framework "SystemConfiguration"' \
    '    link framework "CoreFoundation"' '    link "iconv"'
  printf '%s' "$nearby_links"
  printf '%s\n' '    export *' '}'
} >"$stage/include/module.modulemap"
args=()
for t in "${TARGETS[@]}"; do
  args+=(-library "$TARGET_DIR/$t/$PROFILE_DIR/libraven_client.a" -headers "$stage/include")
done
xcodebuild -create-xcframework "${args[@]}" -output "$OUT/RavenClient.xcframework" >/dev/null
rm -rf "$stage"

# ── No build-machine path in what ships ─────────────────────────────────────
# Every slice's strings: no macOS home folder at all ("/Users/"), and none of
# this build's folders.
if [[ "$REMAP" == 1 ]]; then
  leaked=0
  found_strings="$(mktemp "${TMPDIR:-/tmp}/raven-xcf-strings.XXXXXX")"
  while IFS= read -r slice; do
    # Read once into a file: grep -q on a pipe would end strings early,
    # and under pipefail a found path would read as not found.
    strings -a "$slice" >"$found_strings"
    n="$(grep -cF "/Users/" "$found_strings" || true)"
    if [[ "$n" != 0 ]]; then
      echo "build_xcframework: ${slice#"$OUT"/} has $n strings with a /Users/ path, for example:" >&2
      grep -F "/Users/" "$found_strings" | head -n 3 | sed 's/^/  /' >&2 || true
      leaked=1
    fi
    for path in "$HOME/" "$ROOT_REAL/" "$TARGET_REAL/" "$CARGO_HOME_DIR/" "$RUSTUP_HOME_DIR/"; do
      if [[ "$(grep -cF -- "$path" "$found_strings" || true)" != 0 ]]; then
        echo "build_xcframework: ${slice#"$OUT"/} names the build folder $path" >&2
        leaked=1
      fi
    done
  done < <(find "$OUT/RavenClient.xcframework" -name 'libraven_client.a')
  rm -f "$found_strings"
  if [[ "$leaked" != 0 ]]; then
    rm -rf "$OUT/RavenClient.xcframework"
    fail "build-machine paths left in the library (above): the XCFramework was removed"
  fi
  echo "build_xcframework: no build-machine path in any slice (strings -a: 0 with /Users/)"
fi
echo "build_xcframework: $OUT/RavenClient.xcframework"
for t in "${TARGETS[@]}"; do
  lib="$TARGET_DIR/$t/$PROFILE_DIR/libraven_client.a"
  echo "  $t: $(du -h "$lib" | cut -f1) ($(lipo -info "$lib" 2>/dev/null | sed 's/.*: //'))"
done
cat <<'NOTE'
Link it in Xcode: add RavenClient.xcframework to the app target ("Do Not
Embed": it is a static library). `import RavenClient` links what it needs
(Security, SystemConfiguration, CoreFoundation, libiconv: the module map
says so). Set RAVEN_DATA_DIR first, and call raven_call / raven_free off
the main thread (docs/IOS.md).
NOTE
