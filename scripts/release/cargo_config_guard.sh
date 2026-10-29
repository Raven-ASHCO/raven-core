#!/usr/bin/env bash
# Sourced by scripts/release/build_reproducible.sh (Phase 6 review
# lock-updates-local-5). Cargo reads .cargo/config.toml (and the older
# .cargo/config) in the folder it runs in and in every folder above it, and
# then in its cargo home; there is no switch to turn that off. The
# reproducible build runs under /tmp, which every local account can write:
# a config another account leaves in /tmp/.cargo (a rustc wrapper, a linker,
# [env]) would run code as the builder and change the binaries whose hashes
# are signed. The source's own configuration (tracked files, below the build
# folder) is not this function's business.
#
#   raven_no_outer_cargo_config <build folder> [<cargo home>]
#
# Returns 1, naming each one on stderr, when <build folder> or a folder
# above it up to / holds .cargo/config or .cargo/config.toml, or when
# <cargo home> holds config or config.toml; 0 otherwise. Reads only.

raven_no_outer_cargo_config() {
  local dir="$1" home="${2:-}" found=0 name
  while :; do
    for name in config config.toml; do
      if [[ -e "$dir/.cargo/$name" || -L "$dir/.cargo/$name" ]]; then
        echo "cargo configuration outside the source: $dir/.cargo/$name" >&2
        found=1
      fi
    done
    [[ "$dir" == "/" ]] && break
    dir="$(dirname "$dir")"
  done
  if [[ -n "$home" ]]; then
    for name in config config.toml; do
      if [[ -e "$home/$name" || -L "$home/$name" ]]; then
        echo "cargo configuration in the build's cargo home: $home/$name" >&2
        found=1
      fi
    done
  fi
  [[ "$found" -eq 0 ]]
}
