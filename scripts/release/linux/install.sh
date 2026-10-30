#!/usr/bin/env bash
# Sets Raven up for you (this user only, no root) from this package: the
# programs go to ~/.local/bin, your profile is ~/.raven, and raven-node runs
# as a systemd user service (raven-node.service). Run it again from a newer
# package to update; your profile stays as it is.
#
# It is Raven's Linux installer (lib/linux_systemd_user.sh) with the
# programs of this package instead of a build. Its options are environment
# variables, for example:
#   RAVEN_LAN_LISTEN=auto ./install.sh        listen on your local networks
#   RAVEN_INTERNET_LISTEN=0.0.0.0:7422 ./install.sh
#   RAVEN_P2P_LISTEN=7423 ./install.sh        peer-to-peer and hole punching
#   RAVEN_INSTALL_TOR_HELPER=0 ./install.sh   without Tor
#   RAVEN_KEYSTORE_PASSPHRASE_FILE=<file> ./install.sh   a host without a desktop keyring
#   RAVEN_ENABLE_LINGER=1 ./install.sh        keep running after you log out
# Every option is described at the top of lib/linux_systemd_user.sh.
set -euo pipefail
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
if [[ "$(uname -s)" != Linux ]]; then
  echo "This package is Raven for Linux; this computer runs $(uname -s)." >&2
  exit 1
fi
want="$(cat "$HERE/ARCH" 2>/dev/null || true)"
have="$(uname -m)"
if [[ -n "$want" && "$want" != "$have" ]]; then
  echo "This package is for $want computers; this one is $have. Download raven-linux-$have." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "Raven runs its background program as a systemd user service, and this computer has no systemctl." >&2
  exit 1
fi
RAVEN_PREBUILT_DIR="$HERE/bin" exec bash "$HERE/lib/linux_systemd_user.sh" "$@"
