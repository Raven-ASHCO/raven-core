#!/usr/bin/env bash
# docs/SAFETY_OFFLINE.md tells people what to type, so what it says must be
# what this build does. Two checks, exit 1 on any violation:
#   1. every line in a fenced code block that starts with `raven` or `ash`
#      names a command that exists: each subcommand is listed under
#      "Commands:" in its parent's --help, and each --flag (or -x) appears in
#      the final command's --help; then the whole line, `--help` appended,
#      must parse (clap itself: an argument the command does not take, such
#      as `raven contact remove Sam`, or an option missing its value, exits 2
#      before --help is honoured). Quoted strings and `<placeholders>` count
#      as one word each; a pipe, redirect, `;` or `&` ends the command;
#   2. every `<!-- gate: NAME=true|false|macos ... -->` marker (the guide's
#      "not in this version" rows and its pre-flip paragraphs) matches
#      `const NAME: bool = ...;` in node/crates/raven-core/src (`macos`: a
#      const that is `cfg!(target_os = "macos")`, on in macOS builds only).
#      A flipped gate fails here until the guide is updated with it.
# The guide must hold at least one command line and one gate marker (an empty
# match never passes).
#
# Folded into scripts/check_offline_guide.sh (Phase 3 P3.C7), which runs this
# on docs/SAFETY_OFFLINE.md and docs/OFFLINE_GUIDE.md, adds the "nothing to
# do" rule and the links between them, and runs this self-test from its own:
# CI calls that script. This one still runs alone, as below.
#
# Usage: bash scripts/check_safety_offline.sh [--self-test]
# Environment: RAVEN_BIN_DIR (the debug build holding raven and ash; default
# $CARGO_TARGET_DIR/debug, else node/target/debug), RAVEN_SAFETY_DOC (the
# guide; default docs/SAFETY_OFFLINE.md). Build first:
#   (cd node && cargo build --locked -p ash -p raven-node)
# Runs on Linux, macOS and Windows (Git Bash; the binaries end in .exe there).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

if [[ -n "${RAVEN_BIN_DIR:-}" ]]; then
  BIN_DIR="$RAVEN_BIN_DIR"
elif [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  BIN_DIR="$CARGO_TARGET_DIR/debug"
else
  BIN_DIR="$REPO/node/target/debug"
fi
GATE_SRC="$REPO/node/crates/raven-core/src"
export NO_COLOR=1

# bin_path NAME: the binary for `raven` or `ash` (NAME.exe on Windows).
bin_path() {
  if [[ -x "$BIN_DIR/$1" ]]; then
    echo "$BIN_DIR/$1"
  elif [[ -x "$BIN_DIR/$1.exe" ]]; then
    echo "$BIN_DIR/$1.exe"
  else
    return 1
  fi
}

for name in raven ash; do
  if ! bin_path "$name" >/dev/null; then
    echo "check_safety_offline: no $name in $BIN_DIR; build it first: (cd node && cargo build --locked -p ash -p raven-node)" >&2
    exit 2
  fi
done

# help_of BIN WORD...: BIN WORD... --help, without carriage returns. Status 1
# when the command does not exist (clap exits non-zero).
help_of() {
  local out
  out="$("$@" --help </dev/null 2>&1)" || return 1
  printf '%s\n' "$out" | tr -d '\r'
}

# subcommands HELP: the names listed under "Commands:" (one per line).
subcommands() {
  printf '%s\n' "$1" | awk '
    /^Commands:/ { on = 1; next }
    on && /^[^ ]/ { on = 0 }
    on && /^  [a-z0-9][a-z0-9-]*( |$)/ { print $1 }'
}

# has_flag HELP FLAG: FLAG appears in HELP as a whole option word.
has_flag() {
  printf '%s\n' "$1" | grep -qE -- "(^|[[:space:],[])$2([[:space:],=]|\]|$)"
}

# parses BIN ARG...: BIN ARG... --help exits 0 (clap parsed the line; nothing
# runs). Prints clap's first error line otherwise.
parses() {
  local out
  if out="$("$@" --help </dev/null 2>&1)"; then
    return 0
  fi
  printf '%s\n' "$out" | tr -d '\r' | grep -m 1 -E '^error' || printf '%s\n' "$out" | head -n 1
  return 1
}

# check_line LINE: one `raven ...` / `ash ...` line; prints what is wrong and
# returns 1, or returns 0.
check_line() {
  local line=$1 bin words word help subs flag i descend=1 why
  local -a path=()
  # Drop a trailing comment, then quoted strings and <placeholders> (one
  # word each), then whatever a pipe, redirect, `;` or `&` adds.
  line="${line%%[[:space:]]#*}"
  line="$(printf '%s\n' "$line" | sed -E "s/\"[^\"]*\"/Q/g; s/'[^']*'/Q/g; s/<[A-Za-z][A-Za-z0-9_ .-]*>/X/g")"
  line="${line%%[|;&<>]*}"
  read -r -a words <<<"$line"
  bin="$(bin_path "${words[0]}")" || {
    echo "  '${words[0]}' is not a binary of this build"
    return 1
  }
  help="$(help_of "$bin")" || {
    echo "  ${words[0]} --help failed"
    return 1
  }
  for ((i = 1; i < ${#words[@]}; i++)); do
    word="${words[$i]}"
    if [[ "$word" == -* ]]; then
      descend=0
      continue
    fi
    [[ "$descend" == 1 ]] || continue
    subs="$(subcommands "$help")"
    if [[ -z "$subs" ]]; then
      descend=0
      continue
    fi
    if ! printf '%s\n' "$subs" | grep -qxF -- "$word"; then
      # A command with subcommands takes this word as an argument only when
      # its usage line names one besides [OPTIONS] and the command
      # ([ARGS], <NAME>...); otherwise it is unknown.
      if printf '%s\n' "$help" | grep -E '^Usage:' \
        | sed -E 's/\[OPTIONS\]|\[COMMAND\]|<COMMAND>//g' | grep -qE '<[A-Z_]+>|\[[A-Z_]+\]'; then
        descend=0
        continue
      fi
      echo "  '${words[0]} ${path[*]-} $word': no such subcommand"
      return 1
    fi
    path+=("$word")
    help="$(help_of "$bin" "${path[@]}")" || {
      echo "  '${words[0]} ${path[*]} --help' failed"
      return 1
    }
  done
  for ((i = 1; i < ${#words[@]}; i++)); do
    word="${words[$i]}"
    [[ "$word" == -* ]] || continue
    flag="${word%%=*}"
    [[ "$flag" =~ ^-{1,2}[A-Za-z0-9][A-Za-z0-9-]*$ ]] || {
      echo "  '$word' is not an option"
      return 1
    }
    if ! has_flag "$help" "$flag"; then
      echo "  '${words[0]} ${path[*]-}' has no option $flag"
      return 1
    fi
  done
  if ! why="$(parses "$bin" "${words[@]:1}")"; then
    echo "  '${words[*]}' does not parse: $why"
    return 1
  fi
  return 0
}

# fenced_commands DOC: the `raven` / `ash` lines of DOC's fenced code blocks
# (a leading `$ ` prompt is dropped), one per line.
fenced_commands() {
  tr -d '\r' <"$1" | awk '
    /^[[:space:]]*(```|~~~)/ { fence = !fence; next }
    fence {
      sub(/^[[:space:]]+/, "")
      sub(/^\$[[:space:]]+/, "")
      if ($0 ~ /^(raven|ash)([[:space:]]|$)/) print
    }'
}

# gate_markers DOC: NAME=VALUE of every gate marker in DOC, one per line.
gate_markers() {
  tr -d '\r' <"$1" | grep -oE '<!-- gate: [A-Z0-9_]+=(true|false|macos)' | sed 's/^<!-- gate: //' || true
}

# gate_value NAME: the value of `const NAME: bool = ...;` (exactly one):
# true, false, or macos for `cfg!(target_os = "macos")`.
gate_value() {
  local found
  found="$(grep -rhoE --include='*.rs' "const $1: bool = (true|false|cfg!\(target_os = \"macos\"\));" "$GATE_SRC" || true)"
  if [[ "$(printf '%s\n' "$found" | grep -c .)" -ne 1 ]]; then
    return 1
  fi
  printf '%s\n' "$found" | sed -E 's/.*= (true|false);/\1/; s/.*= cfg!\(target_os = "macos"\);/macos/'
}

# check_doc DOC: both checks; prints a summary, returns 1 on a violation.
check_doc() {
  local doc=$1 bad=0 n_cmd=0 n_gate=0 line why marker name want have
  if [[ ! -f "$doc" ]]; then
    echo "check_safety_offline: $doc does not exist" >&2
    return 1
  fi
  while IFS= read -r line; do
    n_cmd=$((n_cmd + 1))
    if ! why="$(check_line "$line")"; then
      echo "SAFETY_DOC_COMMAND: $doc: \`$line\`" >&2
      echo "$why" >&2
      bad=1
    fi
  done < <(fenced_commands "$doc")
  while IFS= read -r marker; do
    [[ -n "$marker" ]] || continue
    n_gate=$((n_gate + 1))
    name="${marker%%=*}"
    want="${marker#*=}"
    if ! have="$(gate_value "$name")"; then
      echo "SAFETY_DOC_GATE: $doc names $name, which is not exactly one bool const in $GATE_SRC" >&2
      bad=1
    elif [[ "$have" != "$want" ]]; then
      echo "SAFETY_DOC_GATE: $doc says $name=$want, the code says $have: update the guide with the gate" >&2
      bad=1
    fi
  done < <(gate_markers "$doc")
  if [[ "$n_cmd" -eq 0 ]]; then
    echo "SAFETY_DOC_EMPTY: no raven/ash line in a fenced block of $doc" >&2
    bad=1
  fi
  if [[ "$n_gate" -eq 0 ]]; then
    echo "SAFETY_DOC_EMPTY: no gate marker in $doc" >&2
    bad=1
  fi
  if [[ "$bad" -ne 0 ]]; then
    return 1
  fi
  echo "safety guide OK (${doc#"$REPO"/}: $n_cmd command lines exist in --help, $n_gate gate markers match the code)"
}

# write_doc FILE COMMAND MARKER: a one-command guide for the self-test.
write_doc() {
  printf '# t\n\n```sh\n%s\n```\n\nrow %s\n' "$2" "$3" >"$1"
}

# --self-test: good guides pass; an unknown subcommand, an unknown flag, an
# argument the command does not take, an option missing its value, one
# argument too many, a wrong gate value, an unknown gate and a guide with no
# command each fail.
self_test() {
  local dir rc=0 kind
  dir="$(mktemp -d)"
  write_doc "$dir/good.md" 'raven contact set-dial --petname Sam --lan-dial 10.42.0.1:7420   # comment' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/good2.md" 'raven contact remove --petname "Sam B" | tail -n 1' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/good3.md" 'raven contact verify <name>' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/good4.md" 'raven nearby status' \
    '<!-- gate: NEARBY_PRODUCTION_ENABLED=macos -->'
  for kind in good good2 good3 good4; do
    if ! check_doc "$dir/$kind.md" >/dev/null 2>&1; then
      echo "SELF_TEST_FAIL: the '$kind' guide was refused" >&2
      rc=1
    fi
  done
  write_doc "$dir/sub.md" 'raven contact no-such-command --petname Sam' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/flag.md" 'ash send --contact Sam --no-such-flag' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/gate.md" 'raven listen' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=false -->'
  write_doc "$dir/unknown.md" 'raven listen' \
    '<!-- gate: NO_SUCH_PRODUCTION_ENABLED=false -->'
  write_doc "$dir/empty.md" 'echo nothing to check' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/arg.md" 'raven contact remove Sam' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/value.md" 'raven send --contact' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/extra.md" 'raven contact verify Sam Bob Extra' \
    '<!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true -->'
  write_doc "$dir/os.md" 'raven nearby status' \
    '<!-- gate: NEARBY_PRODUCTION_ENABLED=false -->'
  for kind in sub flag gate unknown empty arg value extra os; do
    if check_doc "$dir/$kind.md" >/dev/null 2>&1; then
      echo "SELF_TEST_FAIL: the '$kind' guide passed" >&2
      rc=1
    fi
  done
  rm -rf "$dir"
  if [[ "$rc" -ne 0 ]]; then
    return 1
  fi
  echo "check_safety_offline self-test OK (4 good guides pass, 9 bad ones fail)"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit $?
fi
check_doc "${RAVEN_SAFETY_DOC:-$REPO/docs/SAFETY_OFFLINE.md}"
