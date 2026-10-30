#!/usr/bin/env bash
# Removes what install.sh set up: the systemd user service raven-node.service
# and the programs in ~/.local/bin (or RAVEN_BIN_DIR). Your profile (your
# identity, friends and messages in ~/.raven) stays: to delete it as well,
# run `raven erase` BEFORE this script, while raven is still installed.
set -euo pipefail
BIN_DIR="${RAVEN_BIN_DIR:-$HOME/.local/bin}"
UNIT="$HOME/.config/systemd/user/raven-node.service"
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now raven-node.service 2>/dev/null || true
fi
if [[ -e "$UNIT" ]]; then
  rm -f "$UNIT"
  systemctl --user daemon-reload 2>/dev/null || true
  echo "removed the service raven-node.service"
fi
# `ash` only when it is the link install.sh made to raven (never a system ash).
if [[ -L "$BIN_DIR/ash" && "$(readlink "$BIN_DIR/ash")" == "$BIN_DIR/raven" ]]; then
  rm -f "$BIN_DIR/ash"
fi
for f in raven raven-node raven-tor-helper; do
  if [[ -e "$BIN_DIR/$f" ]]; then
    rm -f "$BIN_DIR/$f"
    echo "removed $BIN_DIR/$f"
  fi
done
echo "Raven is uninstalled. Your profile stays where it was (~/.raven unless you chose another folder)."
