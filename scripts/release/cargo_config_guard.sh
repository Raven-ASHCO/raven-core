#!/usr/bin/env bash
# Sourced by scripts/release/build_reproducible.sh (Phase 6 review
# lock-updates-local-5; security review 2026-11 DEP-1), and for
# raven_no_outer_cargo_config by scripts/release/make-linux.sh. The
# reproducible build runs under /tmp, which every local account can write.
# What another account leaves there must never run as the builder or
# change the binaries whose hashes are signed:
#
#  - Cargo reads .cargo/config.toml (and the older .cargo/config) in the
#    folder it runs in and in every folder above it, and then in its cargo
#    home; there is no switch to turn that off. A config in /tmp/.cargo (a
#    rustc wrapper, a linker, [env]) runs code as the builder.
#  - rustup takes the nearest rust-toolchain.toml (or rust-toolchain) above
#    the folder a cargo or rustc proxy starts in, and a path toolchain there
#    names any cargo and rustc.
#  - The build folder itself, if another account planted it as a symlink,
#    leads the build (and its rm -rf of src/) into a folder of the builder.
#
# The source's own configuration (tracked files, below the build folder) is
# not these functions' business.
#
#   raven_no_outer_cargo_config <build folder> [<cargo home>]
#       Returns 1, naming each one on stderr, when <build folder> or a
#       folder above it up to / holds .cargo/config or .cargo/config.toml,
#       or rust-toolchain or rust-toolchain.toml, or when <cargo home> holds
#       config or config.toml; 0 otherwise. Reads only.
#   raven_prepare_build_root <folder>
#       Makes <folder> (mkdir, not mkdir -p) or takes the one an earlier
#       build of this user left, makes it private (0700) and prints its
#       real path. Returns 1, saying why on stderr, when it is a symlink, not
#       a folder, another account's, or in a folder where another account
#       could replace it (writable by others without the sticky bit /tmp
#       has, or owned by another account).
#   raven_claim_outer_cargo_dir <folder>
#       Makes <folder>/.cargo (empty, 0755) or checks the one there: a real
#       folder of this user or root that nobody else can write, in a folder
#       where nobody else can replace it. Then no other account can put a
#       config there while cargo starts, between raven_no_outer_cargo_config
#       before the build and after it. Returns 1, saying why, otherwise.
#       Sets raven_outer_cargo_made to the folder when it made it (the
#       build removes it again at the end, so the next account's build can
#       make its own), else to "".
#   raven_pin_toolchain <toolchain> [<folder>]
#       Exports RUSTUP_TOOLCHAIN=<toolchain> (it outranks every toolchain
#       file and directory override) and checks, from <folder> (default:
#       here), that rustc and cargo are that version (a rustc that is not
#       rustup's ignores the variable). Returns 1, saying what it found,
#       otherwise.

raven_no_outer_cargo_config() {
  local dir="$1" home="${2:-}" found=0 name
  while :; do
    for name in config config.toml; do
      if [[ -e "$dir/.cargo/$name" || -L "$dir/.cargo/$name" ]]; then
        echo "cargo configuration outside the source: $dir/.cargo/$name" >&2
        found=1
      fi
    done
    for name in rust-toolchain rust-toolchain.toml; do
      if [[ -e "$dir/$name" || -L "$dir/$name" ]]; then
        echo "rustup toolchain file outside the source: $dir/$name" >&2
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

# The mode letters (drwxr-xr-x) and the owner's uid of a path, without
# following a symlink: "<mode> <uid>". Portable (GNU and BSD ls).
raven_mode_and_owner() {
  local info
  info="$(ls -ldn "$1" 2>/dev/null)" || return 1
  printf '%s %s\n' "${info:0:10}" "$(awk '{print $3}' <<<"$info")"
}

# 0 when the folder is this user's or root's, and the group and others
# cannot write it.
raven_only_owner_writes() {
  local mode uid
  read -r mode uid <<<"$(raven_mode_and_owner "$1")" || return 1
  [[ "${mode:0:1}" == d ]] || return 1
  [[ "$uid" == "$(id -u)" || "$uid" == 0 ]] || return 1
  case "$mode" in
    ?????w???? | ????????w?) return 1 ;;
  esac
}

# 0 when no other account can remove or rename what this user puts in the
# folder: it is this user's or root's, and whoever else can write it is
# held back by the sticky bit (as in /tmp).
raven_entries_stay() {
  local mode uid
  read -r mode uid <<<"$(raven_mode_and_owner "$1")" || return 1
  [[ "${mode:0:1}" == d ]] || return 1
  [[ "$uid" == "$(id -u)" || "$uid" == 0 ]] || return 1
  case "$mode" in
    ?????w???? | ????????w?)
      case "$mode" in
        *t | *T) ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

raven_prepare_build_root() {
  local parent root
  parent="$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)" || {
    echo "no folder $(dirname "$1") for the build folder" >&2
    return 1
  }
  root="$parent/$(basename "$1")"
  if ! raven_entries_stay "$parent"; then
    echo "another account could replace the build folder in $parent (it is not sticky, or not owned by this user or root)" >&2
    return 1
  fi
  if [[ -L "$root" ]]; then
    echo "the build folder $root is a symlink: remove it, and find out who put it there" >&2
    return 1
  fi
  mkdir -m 700 "$root" 2>/dev/null || true
  if [[ -L "$root" || ! -d "$root" ]]; then
    echo "the build folder $root is not a folder: remove it, and find out who put it there" >&2
    return 1
  fi
  if [[ ! -O "$root" ]]; then
    echo "the build folder $root belongs to another account: have it removed, and find out who put it there" >&2
    return 1
  fi
  chmod 700 "$root" || return 1
  printf '%s\n' "$root"
}

# shellcheck disable=SC2034  # raven_outer_cargo_made is read by build_reproducible.sh
raven_claim_outer_cargo_dir() {
  local dir="$1/.cargo"
  raven_outer_cargo_made=""
  if ! raven_entries_stay "$1"; then
    echo "another account could replace $dir (its folder is not sticky, or not owned by this user or root)" >&2
    return 1
  fi
  if mkdir -m 755 "$dir" 2>/dev/null; then
    raven_outer_cargo_made="$dir"
  fi
  if [[ -L "$dir" || ! -d "$dir" ]]; then
    echo "$dir is not a folder: remove it, and find out who put it there" >&2
    return 1
  fi
  if ! raven_only_owner_writes "$dir"; then
    echo "$dir belongs to another account or others can write it: have it removed, and find out who put it there" >&2
    return 1
  fi
}

raven_pin_toolchain() {
  local toolchain="$1" dir="${2:-.}" tool version
  export RUSTUP_TOOLCHAIN="$toolchain"
  for tool in rustc cargo; do
    version="$(cd "$dir" && "$tool" --version 2>/dev/null)" || version=""
    case "$version" in
      "$tool $toolchain "*) ;;
      *)
        echo "needs $tool $toolchain (rustup toolchain install $toolchain); found in $dir: ${version:-nothing}" >&2
        return 1
        ;;
    esac
  done
}
