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
#   OUT=/some/dir node/scripts/ios/build_xcframework.sh
#
# Needs: Xcode with the iOS SDK (its license accepted), and the two Rust
# targets (rustup target add aarch64-apple-ios aarch64-apple-ios-sim). It
# stops with what to do when one is missing, before building anything.
#
# A debug build honours the lab switches and the file-backed key stores
# (tests, the simulator); a release build refuses both, as on the desktop.
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

# ── Build ────────────────────────────────────────────────────────────────────
cd "$NODE"
for t in "${TARGETS[@]}"; do
  echo "build_xcframework: raven-client ($PROFILE, features: $FEATURES) for $t"
  # Only the static library: the rlib and cdylib forms are for the desktop.
  cargo rustc -p raven-client --lib "${CARGO_PROFILE_FLAG[@]}" \
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
cat >"$stage/include/module.modulemap" <<'MAP'
module RavenClient {
    header "raven_client.h"
    link framework "Security"
    link framework "SystemConfiguration"
    link framework "CoreFoundation"
    link "iconv"
    export *
}
MAP
args=()
for t in "${TARGETS[@]}"; do
  args+=(-library "$TARGET_DIR/$t/$PROFILE_DIR/libraven_client.a" -headers "$stage/include")
done
xcodebuild -create-xcframework "${args[@]}" -output "$OUT/RavenClient.xcframework" >/dev/null
rm -rf "$stage"
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
