#!/usr/bin/env bash
# Reproducible-build check of a release bundle (Phase 6 P6.46, design D §9,
# owner decision OD6b-27): rebuild the bundle's source commit with
# build_reproducible.sh and compare each file with the manifest's
# rebuild_sha256 (the bytes before platform signing).
#
#   scripts/release/reproduce_check.sh <bundle.rrb> [--repo <git url or folder>]
#       [--work <new folder>] [--keep]
#
# The source comes from --repo (default: this checkout), cloned into the
# work folder and checked out at the manifest's commit; nothing in the
# checkout you run this from changes. It builds with the commit's own
# build_reproducible.sh (or this one, with --source, for a commit that has
# none), on the bundle's target only. It checks reproducibility, not
# signatures: `raven update verify` (or `raven-release verify`) does that.
# Exit 0 when every file matches, 1 when one does not, 2 when it cannot
# check.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$HERE/../.." && pwd -P)"

usage() {
  echo "usage: scripts/release/reproduce_check.sh <bundle.rrb> [--repo <git url or folder>] [--work <new folder>] [--keep]"
}

bundle=""
repo="$REPO"
work=""
keep=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo | --work)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      if [[ "$1" == "--repo" ]]; then repo="$2"; else work="$2"; fi
      shift 2
      ;;
    --keep)
      keep=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      usage >&2
      exit 2
      ;;
    *)
      bundle="$1"
      shift
      ;;
  esac
done
[[ -n "$bundle" && -f "$bundle" ]] || { usage >&2; exit 2; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# The manifest's fields (RAVEN_RELEASE_BUNDLE_V1 §3, §6), read with the
# standard library only; the container is not verified here.
fields="$(python3 -I - "$bundle" <<'PY'
import sys

data = open(sys.argv[1], "rb").read(1 << 16)
if data[:4] != b"RRBC" or data[4] != 1:
    sys.exit("not an RRBC bundle")
n = int.from_bytes(data[8:12], "big")
m = data[12 : 12 + n]
if len(m) != n or m[:4] != b"RRB1":
    sys.exit("no RRB1 manifest")
at = 8
def take(k):
    global at
    out = m[at : at + k]
    if len(out) != k:
        sys.exit("truncated manifest")
    at += k
    return out
def short():
    return take(take(1)[0])
count = m[6]
serial = int.from_bytes(take(8), "big")
take(8 + 32)
version = short().decode("ascii")
target = short().decode("ascii")
commit = take(20).hex()
toolchain = short().decode("ascii")
take(8 + 4 + 8 + 32 + 32)
safe = lambda s: all(c.isalnum() or c in "._+-/" for c in s)
for value in (version, target, toolchain):
    if not safe(value):
        sys.exit("unexpected characters in the manifest")
print(f"commit={commit}\ntarget={target}\ntoolchain={toolchain}\nversion={version}\nserial={serial}")
for _ in range(count):
    path = short().decode("ascii")
    take(1 + 8 + 8)
    sha, rebuild = take(32).hex(), take(32).hex()
    if not safe(path):
        sys.exit("unexpected characters in a path")
    print(f"file {path} {sha} {rebuild}")
PY
)" || { echo "reproduce_check: cannot read $bundle" >&2; exit 2; }

value_of() { sed -n "s/^$1=//p" <<<"$fields"; }
commit="$(value_of commit)"
target="$(value_of target)"
toolchain="$(value_of toolchain)"
echo "bundle: Raven $(value_of version) for $target, build serial $(value_of serial), commit $commit, toolchain $toolchain"

host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ "$host" != "$target" ]]; then
  echo "reproduce_check: this bundle is for $target; rebuild it on that platform (this one is $host)" >&2
  exit 2
fi

if [[ -z "$work" ]]; then
  work="$(mktemp -d "${TMPDIR:-/tmp}/raven-reproduce.XXXXXX")"
else
  [[ ! -e "$work" || -z "$(ls -A "$work" 2>/dev/null)" ]] || { echo "reproduce_check: $work is not empty" >&2; exit 2; }
  mkdir -p "$work"
fi
cleanup() {
  if [[ "$keep" -eq 0 ]]; then
    rm -rf "$work"
  else
    echo "kept: $work"
  fi
}
trap cleanup EXIT

git clone --quiet --no-checkout "$repo" "$work/src"
if ! git -C "$work/src" checkout --quiet --detach "$commit" 2>/dev/null; then
  echo "reproduce_check: commit $commit is not in $repo (fetch it, or give --repo)" >&2
  exit 2
fi
script="$work/src/scripts/release/build_reproducible.sh"
if [[ -f "$script" ]]; then
  bash "$script" --out "$work/out"
else
  echo "note: commit $commit has no build_reproducible.sh; using this checkout's" >&2
  bash "$HERE/build_reproducible.sh" --source "$work/src" --out "$work/out"
fi
built_toolchain="$(sed -n 's/^toolchain=//p' "$work/out/BUILDINFO")"
if [[ "$built_toolchain" != "$toolchain" ]]; then
  echo "reproduce_check: the commit builds with rustc $built_toolchain, the manifest says $toolchain" >&2
  exit 2
fi

status=0
while read -r word path sha rebuild; do
  [[ "$word" == "file" ]] || continue
  if [[ ! -f "$work/out/$path" ]]; then
    echo "MISSING   $path (the rebuild has no such file)"
    status=1
    continue
  fi
  got="$(sha256_of "$work/out/$path")"
  if [[ "$got" == "$rebuild" ]]; then
    if [[ "$sha" == "$rebuild" ]]; then
      echo "MATCH     $path"
    else
      echo "MATCH     $path (before platform signing)"
    fi
  else
    echo "MISMATCH  $path: rebuilt $got, the manifest says $rebuild"
    status=1
  fi
done <<<"$fields"
if [[ "$status" -eq 0 ]]; then
  echo "REPRODUCED: every file of the bundle was rebuilt byte for byte"
else
  echo "NOT REPRODUCED: see above"
fi
exit "$status"
