#!/usr/bin/env bash
# Release bundle kit (Phase 6 P6.46, design D §4 and §9): from the output of
# build_reproducible.sh to the manifest draft the release keys sign, and
# from the signed manifest to the deterministic .rrb container.
#
#   scripts/release/make_bundle.sh draft --build <build folder> --key-set <file>
#       --out <new folder> [--signed <folder>] [--notes <file>]
#       [--min-advisory-serial <n>] [--dry-run-serial <n>]
#   scripts/release/make_bundle.sh pack --out <that folder> --key-set <file>
#       --log <log folder> [--advisory <signed .rad1>]
#
# draft: stages the files to ship in <out>/files/ (bin/ from --signed, the
# platform-signed binaries, when given, else the build's own; docs/ from the
# build), takes each file's rebuild_sha256 from the build's SHA256SUMS (the
# bytes before platform signing) and the commit, toolchain, target, version
# and build serial from its BUILDINFO, and writes
# <out>/manifest-<target>.draft. created_at_ms is the commit time, so the
# same build gives the same draft. A dirty build or a build serial of 0 (a
# development build) is refused unless --dry-run-serial names a serial for
# a ceremony dry run.
# pack: after the ceremony (signatures combined into
# <out>/manifest-<target>.rrb1, listed in the log, the tree head signed),
# writes <out>/raven-<version>-<target>.rrb and its .sha256.
#
# The tool is $RAVEN_RELEASE when set, else raven-release built here into
# node/target/release-tool (its own folder: the ash feature `release-tool`
# never touches the binaries that ship, and nothing named raven-release is
# ever staged).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
NODE="$REPO/node"

usage() {
  sed -n '6,10p' "${BASH_SOURCE[0]}" | sed 's/^#   //; s/^#       /    /'
}

die() {
  echo "make_bundle: $*" >&2
  exit 1
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

tool() {
  if [[ -n "${RAVEN_RELEASE:-}" ]]; then
    "$RAVEN_RELEASE" "$@"
    return
  fi
  local dir="$NODE/target/release-tool"
  if [[ ! -x "$dir/release/raven-release" ]]; then
    echo "make_bundle: building raven-release into $dir" >&2
    (cd "$NODE" && CARGO_TARGET_DIR="$dir" cargo build --locked --release -q -p ash \
      --features release-tool --bin raven-release)
  fi
  "$dir/release/raven-release" "$@"
}

# One value of a BUILDINFO file (key=value lines).
buildinfo_value() {
  local value
  value="$(sed -n "s/^$2=//p" "$1" | head -n 1)"
  [[ -n "$value" ]] || die "$1: no $2"
  printf '%s' "$value"
}

# The BUILDINFO of a build_reproducible.sh output.
read_buildinfo() {
  [[ -f "$1" ]] || die "$1: missing (run build_reproducible.sh)"
  info_source_commit="$(buildinfo_value "$1" source_commit)"
  info_source_date_epoch="$(buildinfo_value "$1" source_date_epoch)"
  info_toolchain="$(buildinfo_value "$1" toolchain)"
  info_target="$(buildinfo_value "$1" target)"
  info_version="$(buildinfo_value "$1" version)"
  info_build_serial="$(buildinfo_value "$1" build_serial)"
  info_dirty="$(buildinfo_value "$1" dirty)"
}

cmd="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi
build="" key_set="" out="" signed="" notes="" min_advisory=0 dry_serial="" log="" advisory=""
while [[ $# -gt 0 ]]; do
  [[ $# -ge 2 ]] || { usage >&2; exit 2; }
  case "$1" in
    --build) build="$2" ;;
    --key-set) key_set="$2" ;;
    --out) out="$2" ;;
    --signed) signed="$2" ;;
    --notes) notes="$2" ;;
    --min-advisory-serial) min_advisory="$2" ;;
    --dry-run-serial) dry_serial="$2" ;;
    --log) log="$2" ;;
    --advisory) advisory="$2" ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift 2
done

case "$cmd" in
  draft)
    [[ -n "$build" && -n "$key_set" && -n "$out" ]] || { usage >&2; exit 2; }
    read_buildinfo "$build/BUILDINFO"
    serial="$info_build_serial"
    if [[ -n "$dry_serial" ]]; then
      echo "make_bundle: DRY RUN: build serial $dry_serial in the manifest (the binaries say $serial)" >&2
      serial="$dry_serial"
    else
      [[ "$info_dirty" == "0" ]] || die "the build is of a dirty checkout: no release (--dry-run-serial for a dry run)"
      [[ "$serial" != "0" ]] || die "BUILD_SERIAL is 0 (a development build): the release commit sets it"
    fi
    if [[ -e "$out" ]] && [[ -n "$(ls -A "$out" 2>/dev/null)" ]]; then
      die "$out is not empty"
    fi
    mkdir -p "$out/files/bin" "$out/files/docs"
    cp "$build/BUILDINFO" "$out/BUILDINFO"
    bin_from="${signed:-$build}"
    args=()
    for src in "$bin_from"/bin/* "$build"/docs/*; do
      [[ -f "$src" && ! -L "$src" ]] || die "$src is not a regular file"
      name="$(basename "$src")"
      case "$name" in
        raven-release*) die "$src: the offline release tool never ships" ;;
      esac
      sub="$(basename "$(dirname "$src")")"
      rel="$sub/$name"
      cp "$src" "$out/files/$rel"
      rebuild="$(awk -v p="$rel" '$2 == p { print $1 }' "$build/SHA256SUMS")"
      [[ -n "$rebuild" ]] || die "$rel is not in $build/SHA256SUMS"
      args+=(--file "$rel=$out/files/$rel" --rebuild "$rel=$rebuild")
    done
    if [[ -z "$notes" ]]; then
      notes="$out/notes.txt"
      printf 'Raven %s for %s.\n' "$info_version" "$info_target" >"$notes"
    fi
    tool manifest --key-set "$key_set" --build-serial "$serial" --version "$info_version" \
      --target "$info_target" --source-commit "$info_source_commit" \
      --toolchain "$info_toolchain" --created-at-ms "$((info_source_date_epoch * 1000))" \
      --min-advisory-serial "$min_advisory" --notes "$notes" "${args[@]}" \
      --out "$out/manifest-$info_target.draft"
    echo "Next (offline): raven-release sign, one key per run, then combine into $out/manifest-$info_target.rrb1"
    ;;
  pack)
    [[ -n "$out" && -n "$key_set" && -n "$log" ]] || { usage >&2; exit 2; }
    read_buildinfo "$out/BUILDINFO"
    manifest="$out/manifest-$info_target.rrb1"
    [[ -f "$manifest" ]] || die "$manifest: missing (combine the manifest's signatures first)"
    bundle="$out/raven-$info_version-$info_target.rrb"
    tool pack --key-set "$key_set" --manifest "$manifest" --log "$log" \
      ${advisory:+--advisory "$advisory"} --files "$out/files" --out "$bundle"
    echo "$(sha256_of "$bundle")  $(basename "$bundle")" >"$bundle.sha256"
    cat "$bundle.sha256"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
