#!/usr/bin/env bash
# docs/ is the single source of truth. A node/*.md whose basename also exists
# in docs/ must be a short pointer stub to that docs/ file — never a second,
# silently diverging copy (the stale node/ copies once contradicted docs/ on
# security status). The relay kit guide and the install guides must not link
# to a file that does not exist. Exit 1 on any violation.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
bad=0
for f in node/*.md; do
  base="${f##*/}"
  [[ -f "docs/$base" ]] || continue
  lines=$(wc -l <"$f" | tr -d ' ')
  if [[ "$lines" -gt 12 ]] || ! grep -qF "(../docs/$base)" "$f"; then
    echo "DUPLICATE_DOC: $f duplicates docs/$base — replace it with a pointer stub to ../docs/$base" >&2
    bad=1
  fi
done
# links_resolve FILE...: every relative link `](path)` in each FILE names a
# file that exists (an #anchor is stripped; web links and same-page anchors
# are not checked). Sets bad=1 on a broken one.
links_resolve() {
  local f dir link target
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    dir="${f%/*}"
    while IFS= read -r link; do
      target="${link#](}"
      target="${target%)}"
      target="${target%%#*}"
      case "$target" in
        ''|http://*|https://*|mailto:*) continue ;;
      esac
      if [[ ! -e "$dir/$target" ]]; then
        echo "BROKEN_DOC_LINK: $f links to $target, which does not exist" >&2
        bad=1
      fi
    done < <(grep -oE '\]\([^)]*\)' "$f" || true)
  done
}
# Second pass: in the guides people follow step by step (the relay kit, the
# install guides and the offline guide), every relative link resolves.
links_resolve docs/RELAY_KIT.md docs/INSTALL_*.md docs/OFFLINE_GUIDE.md
# Third pass (Phase 4 review E-1): the router leases the port-mapping waiver,
# the design's risk list, the spec and the install guides state are the ones
# raven-core asks for (an IPv4 mapping, an IPv6 pinhole).
lease_of() {
  sed -nE "s/^pub const $1: u32 = ([0-9]+);/\\1/p" node/crates/raven-core/src/portmap.rs
}
v4_s=$(lease_of REQUESTED_LIFETIME_S)
v6_s=$(lease_of PINHOLE_LIFETIME_S)
if [[ -z "$v4_s" || -z "$v6_s" || $((v6_s % 3600)) -ne 0 ]]; then
  echo "LEASE_DOC: cannot read whole-hour leases from raven-core portmap.rs" >&2
  bad=1
else
  lease_says() { # file, phrase
    if ! grep -qF -- "$2" "$1"; then
      echo "LEASE_DOC: $1 lacks \"$2\" (raven-core asks ${v4_s} s / pinholes ${v6_s} s)" >&2
      bad=1
    fi
  }
  lease_says docs/WAIVER_PORT_MAP_DRAFT.md "leases of ${v6_s} s"
  lease_says docs/WAIVER_PORT_MAP_DRAFT.md "up to ${v4_s} s, a pinhole"
  lease_says docs/WAIVER_PORT_MAP_DRAFT.md "up to ${v6_s} s)"
  lease_says docs/WAIVER_PORT_MAP_DRAFT.md "${v4_s} s / ${v6_s} s leases"
  lease_says protocol/RAVEN_PORT_MAPPING_V1.md "Every IPv4 mapping asks for ${v4_s} s"
  lease_says protocol/RAVEN_PORT_MAPPING_V1.md "every IPv6 pinhole for ${v6_s} s"
  for f in docs/INSTALL_*.md; do
    lease_says "$f" "A yes opens a $((v6_s / 3600))-hour pinhole"
  done
fi
# Fourth pass (Phase 6 P6.52): the Phase 6b documents. Their relative links
# resolve; every Phase 6b gate (`pub const NAME: bool = VALUE;` in raven-core
# security_gate.rs) is named with the state the code gives it ("`NAME =
# VALUE`") in at least one waiver draft, so a flipped gate fails here until
# its papers say so; and no line outside a code
# block says that passive listening can be detected (a line that names both
# "passive" and "detect..." must also say that it cannot be).
P6B_WAIVERS=(docs/WAIVER_SECURITY_SENSING_DRAFT.md docs/WAIVER_TRAFFIC_ANALYSIS_DRAFT.md
  docs/WAIVER_LOCAL_PROTECTION_DRAFT.md docs/WAIVER_SECURITY_UPDATES_DRAFT.md)
P6B_DOCS=(docs/THREAT_MODEL.md docs/SECURITY_EVENTS.md docs/SAFETY_OFFLINE.md
  docs/SIGNING_NOTARIZATION_CHECKLIST.md docs/RELEASE_KEY_CEREMONY.md
  "${P6B_WAIVERS[@]}" docs/design/2026-10-traffic-analysis.md
  docs/design/2026-10-suite-retirement.md)
for f in "${P6B_DOCS[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "P6B_DOC: $f is missing" >&2
    bad=1
  fi
done
links_resolve "${P6B_DOCS[@]}"
p6b_gates=$(sed -nE 's/^pub const ([A-Z0-9_]+_PRODUCTION_ENABLED): bool = (true|false);.*/\1 = \2/p' \
  node/crates/raven-core/src/security_gate.rs)
if [[ -z "$p6b_gates" ]]; then
  echo "P6B_GATE_DOC: cannot read the gates of raven-core security_gate.rs" >&2
  bad=1
fi
while IFS= read -r gate; do
  [[ -n "$gate" ]] || continue
  if ! grep -qF -- "\`$gate\`" "${P6B_WAIVERS[@]}"; then
    echo "P6B_GATE_DOC: no Phase 6b waiver draft names \`$gate\` (the state in security_gate.rs)" >&2
    bad=1
  fi
done <<<"$p6b_gates"
for f in "${P6B_DOCS[@]}"; do
  [[ -f "$f" ]] || continue
  tr -d '\r' <"$f" | awk -v doc="$f" '
    /^[[:space:]]*(```|~~~)/ { fence = !fence; next }
    fence { next }
    {
      l = tolower($0)
      if (l ~ /passive/ && l ~ /detect/ \
        && l !~ /(cannot|can.t|can not|undetectable|never|none|nothing|nobody|no one|(^|[^a-z])not([^a-z]|$))/) {
        printf "PASSIVE_DETECTION_CLAIM: %s:%d reads as if passive listening could be detected: %s\n", doc, NR, $0
        bad = 1
      }
    }
    END { exit bad }' >&2 || bad=1
done
if [[ "$bad" -ne 0 ]]; then
  exit 1
fi
echo "doc pointers OK (node/*.md duplicates are stubs to docs/; relative links in RELAY_KIT.md, INSTALL_*.md, OFFLINE_GUIDE.md and the Phase 6b documents resolve; router leases match raven-core; every Phase 6b gate is named with its state; no claim that passive listening is detected)"
