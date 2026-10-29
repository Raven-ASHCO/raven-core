#!/usr/bin/env bash
# Build RavenNearby.app, the macOS nearby radio helper (P5.31; Nearby design
# step 5.10; owner decision O5-10).
#
#   bash node/scripts/build_nearby_helper_app.sh OUT_DIR [--debug] [--sign IDENTITY | --no-sign]
#
# Builds raven-nearby-helper (cargo, feature nearby-radio; release unless
# --debug), assembles OUT_DIR/RavenNearby.app from
# node/crates/raven-node/macos/RavenNearby.app (its Info.plist carries
# NSBluetoothAlwaysUsageDescription), and signs the bundle: ad hoc by default
# (IDENTITY "-"), or with a Developer ID identity (hardened runtime). Then it
# runs `raven-nearby-helper --check` from the bundle, which must answer hello:
# --check reads the bundle's usage description and touches no Bluetooth.
#
# It installs nothing and never starts the radio. The raven-node binary is not
# rebuilt or re-signed here. raven-node finds the bundle next to itself, in
# ~/Library/Application Support/Raven/, or at RAVEN_NEARBY_HELPER.
set -euo pipefail

usage() {
  echo "usage: $0 OUT_DIR [--debug] [--sign IDENTITY | --no-sign]" >&2
  exit 2
}

[[ $# -ge 1 && -n "$1" ]] || usage
OUT="$1"
shift
PROFILE=release
IDENTITY=-
SIGN=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug) PROFILE=debug ;;
    --sign)
      [[ $# -ge 2 && -n "$2" ]] || usage
      IDENTITY="$2"
      shift
      ;;
    --no-sign) SIGN=0 ;;
    *) usage ;;
  esac
  shift
done

if [[ "$(uname -s)" != Darwin ]]; then
  echo "RavenNearby.app is built on macOS only" >&2
  exit 1
fi

NODE="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$NODE/crates/raven-node/macos/RavenNearby.app"
TARGET="${CARGO_TARGET_DIR:-$NODE/target}"
APP="$OUT/RavenNearby.app"

plutil -lint "$TEMPLATE/Contents/Info.plist" >/dev/null

build=(cargo build --locked -p raven-node --features nearby-radio --bin raven-nearby-helper)
if [[ "$PROFILE" == release ]]; then
  build+=(--release)
fi
(cd "$NODE" && "${build[@]}")

mkdir -p "$OUT"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$TEMPLATE/Contents/Info.plist" "$APP/Contents/Info.plist"
cp "$TARGET/$PROFILE/raven-nearby-helper" "$APP/Contents/MacOS/raven-nearby-helper"
chmod 755 "$APP/Contents/MacOS/raven-nearby-helper"

if [[ "$SIGN" == 1 ]]; then
  sign=(codesign --force --sign "$IDENTITY" --identifier org.raven.nearby)
  if [[ "$IDENTITY" != - ]]; then
    sign+=(--options runtime --timestamp)
  fi
  "${sign[@]}" "$APP"
  codesign --verify --strict "$APP"
fi

answer="$("$APP/Contents/MacOS/raven-nearby-helper" --check </dev/null)"
if [[ "$answer" != '{"ev":"hello","v":1}' ]]; then
  echo "RavenNearby.app does not find its usage description: $answer" >&2
  exit 1
fi
echo "built $APP ($PROFILE, $([[ "$SIGN" == 1 ]] && echo "signed: $IDENTITY" || echo unsigned))"
