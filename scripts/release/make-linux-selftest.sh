#!/usr/bin/env bash
# Self-test of scripts/release/make-linux.sh's packaging, with nothing built
# and nothing installed: stand-ins for the three programs are packaged with
# --from (on any OS), then the archive is checked: its name, every file in
# it and nothing else, its .sha256, SHA256SUMS inside, the README filled in,
# the scripts' syntax; and a program that names a build-machine path, or is
# not a program, is refused. The installer is never run.
#
#   scripts/release/make-linux-selftest.sh
set -euo pipefail
REPO="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
MAKE="$REPO/scripts/release/make-linux.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
bad=0
fail() {
  echo "FAIL: $*" >&2
  bad=1
}
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"$/\1/p' "$REPO/node/Cargo.toml" | head -n 1)"
NAME="raven-linux-x86_64-$VERSION"
mkdir -p "$T/bins"
for f in raven raven-node raven-tor-helper; do
  printf '#!/bin/sh\necho "stand-in for %s"\n' "$f" >"$T/bins/$f"
  chmod 755 "$T/bins/$f"
done

if ! RAVEN_LINUX_SELFTEST=1 RAVEN_LINUX_ARCH=x86_64 bash "$MAKE" --from "$T/bins" --out "$T/out" --keep \
  >"$T/make.log" 2>&1; then
  cat "$T/make.log" >&2
  fail "make-linux.sh --from stand-ins failed"
fi
TAR="$T/out/$NAME.tar.gz"
[[ -f "$TAR" ]] || fail "no $NAME.tar.gz"
[[ -f "$TAR.sha256" ]] || fail "no $NAME.tar.gz.sha256"
if [[ -f "$TAR" && -f "$TAR.sha256" ]]; then
  (cd "$T/out" && sha256 -c "$NAME.tar.gz.sha256" >/dev/null) || fail "the .sha256 does not match the archive"
  grep -q "  $NAME.tar.gz\$" "$TAR.sha256" || fail "the .sha256 does not name the archive: $(cat "$TAR.sha256")"
  want="$(printf '%s\n' ARCH BUILD-INFO.txt CHANGELOG.md LICENSE NOTICE README.txt SHA256SUMS \
    bin/raven bin/raven-node bin/raven-tor-helper install.sh lib/linux_systemd_user.sh uninstall.sh \
    | sed "s|^|$NAME/|" | LC_ALL=C sort)"
  have="$(tar -tzf "$TAR" | grep -v '/$' | LC_ALL=C sort)"
  [[ "$want" == "$have" ]] || fail "the archive holds other files:"$'\n'"$(diff <(echo "$want") <(echo "$have") || true)"
  mkdir -p "$T/unpacked"
  tar -C "$T/unpacked" -xzf "$TAR"
  P="$T/unpacked/$NAME"
  (cd "$P" && sha256 -c SHA256SUMS >/dev/null) || fail "SHA256SUMS does not match the files"
  for f in bin/raven bin/raven-node bin/raven-tor-helper install.sh uninstall.sh lib/linux_systemd_user.sh; do
    [[ -x "$P/$f" ]] || fail "$f is not executable"
  done
  for f in install.sh uninstall.sh lib/linux_systemd_user.sh; do
    bash -n "$P/$f" || fail "$f: syntax"
  done
  grep -q "^Raven $VERSION for Linux (x86_64)" "$P/README.txt" || fail "README.txt: no version and architecture"
  if grep -q '@[A-Z]*@' "$P/README.txt"; then
    fail "README.txt keeps a placeholder: $(grep '@[A-Z]*@' "$P/README.txt")"
  fi
  [[ "$(cat "$P/ARCH")" == x86_64 ]] || fail "ARCH is not x86_64"
  grep -q "^commit: " "$P/BUILD-INFO.txt" || fail "BUILD-INFO.txt has no commit"
  grep -q 'RAVEN_PREBUILT_DIR="$HERE/bin"' "$P/install.sh" || fail "install.sh does not install this package's programs"
  cmp -s "$P/LICENSE" "$REPO/LICENSE" || fail "LICENSE differs"
  cmp -s "$P/NOTICE" "$REPO/NOTICE" || fail "NOTICE differs"
  if grep -rqF -- "$HOME/" "$P"; then
    fail "a packaged file names this computer's home folder"
  fi
fi
[[ -d "$T/out/$NAME" ]] || fail "--keep did not keep the staged folder"

# Without --keep the staged folder goes.
rm -rf "$T/out2"
RAVEN_LINUX_SELFTEST=1 RAVEN_LINUX_ARCH=x86_64 bash "$MAKE" --from "$T/bins" --out "$T/out2" >/dev/null 2>&1 \
  || fail "a second run failed"
[[ ! -e "$T/out2/$NAME" ]] || fail "the staged folder was left behind"

# A program that names a build-machine path is refused, and nothing is packaged.
mkdir -p "$T/leaky"
cp "$T/bins/"* "$T/leaky/"
printf 'panicked at %s/.cargo/registry/src/x.rs\n' "$HOME" >>"$T/leaky/raven-node"
if RAVEN_LINUX_SELFTEST=1 RAVEN_LINUX_ARCH=x86_64 bash "$MAKE" --from "$T/leaky" --out "$T/out3" >"$T/leak.log" 2>&1; then
  fail "a program naming the home folder was packaged"
fi
grep -q "build-machine path" "$T/leak.log" || fail "the refusal does not say why: $(cat "$T/leak.log")"
[[ ! -e "$T/out3/$NAME.tar.gz" ]] || fail "an archive was written after the refusal"

# Outside the self-test, a file that is no Linux program is refused.
if RAVEN_LINUX_ARCH=x86_64 bash "$MAKE" --from "$T/bins" --out "$T/out4" >"$T/elf.log" 2>&1; then
  fail "stand-ins were packaged as programs"
fi
grep -q "not a Linux (ELF) program" "$T/elf.log" || fail "the refusal does not say why: $(cat "$T/elf.log")"

# An architecture it is not for.
if RAVEN_LINUX_ARCH=riscv64 bash "$MAKE" --from "$T/bins" --out "$T/out5" >/dev/null 2>&1; then
  fail "riscv64 was accepted"
fi

if [[ "$bad" -ne 0 ]]; then
  exit 1
fi
echo "make-linux self-test OK ($NAME.tar.gz: 13 files, checksums, no build-machine path)"
