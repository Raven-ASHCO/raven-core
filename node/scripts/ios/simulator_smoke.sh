#!/usr/bin/env bash
# Links RavenClient.xcframework's simulator library into a small C program
# (smoke/raven_smoke.c), as an app links it, and runs it inside a booted iOS
# Simulator: a new profile in the iOS Keychain, the embedded node started,
# paused, a mail check while paused, resumed, stopped. One process, no
# raven-node program. docs/IOS.md section 10.
#
# Usage:
#   node/scripts/ios/build_xcframework.sh          # first (release by default)
#   node/scripts/ios/simulator_smoke.sh            # the booted simulator
#   UDID=<simulator id> node/scripts/ios/simulator_smoke.sh
#
# The program carries keychain entitlements the way Xcode gives a simulator
# build its own (an __entitlements section, ad-hoc signed), with a test
# access group of its own; it deletes its items at the end. It never boots
# or shuts down a simulator.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
NODE="$ROOT/node"
TARGET_DIR="${CARGO_TARGET_DIR:-$NODE/target}"
XCF="${XCF:-$TARGET_DIR/ios/RavenClient.xcframework}"
SLICE="$XCF/ios-arm64-simulator"
GROUP="RAVENSMOKE.app.raven.smoke"

fail() {
  echo "simulator_smoke: $*" >&2
  exit 1
}

[[ -f "$SLICE/libraven_client.a" ]] || fail "no $SLICE/libraven_client.a: run build_xcframework.sh first"
xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1 || fail "no iOS Simulator SDK (Xcode)"
UDID="${UDID:-$(xcrun simctl list devices booted | awk -F '[()]' '/Booted/{print $2; exit}')}"
[[ -n "$UDID" ]] || fail "no booted simulator: boot one (xcrun simctl boot <id>) or set UDID"

work="$(mktemp -d "${TMPDIR:-/tmp}/raven-smoke.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cat >"$work/ent.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>application-identifier</key>
  <string>$GROUP</string>
  <key>keychain-access-groups</key>
  <array><string>$GROUP</string></array>
</dict>
</plist>
PLIST
xcrun --sdk iphonesimulator clang -target arm64-apple-ios16.0-simulator -O1 \
  -I "$SLICE/Headers" "$NODE/scripts/ios/smoke/raven_smoke.c" "$SLICE/libraven_client.a" \
  -framework Security -framework SystemConfiguration -framework CoreFoundation -liconv \
  -Wl,-sectcreate,__TEXT,__entitlements,"$work/ent.plist" -o "$work/raven_smoke"
codesign -f -s - "$work/raven_smoke" >/dev/null 2>&1
home="$(xcrun simctl getenv "$UDID" HOME)"
profile="$home/Library/Application Support/RavenSmoke-$$"
mkdir -p "$profile"
echo "simulator_smoke: $UDID, profile $profile"
status=0
xcrun simctl spawn "$UDID" "$work/raven_smoke" "$profile" "$GROUP" || status=$?
rm -rf "$profile"
exit "$status"
