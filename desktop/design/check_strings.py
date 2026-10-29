#!/usr/bin/env python3
"""Check desktop/design/strings.en.json against the three desktop apps.

    python3 desktop/design/check_strings.py            # check; exit 1 on a problem
    python3 desktop/design/check_strings.py --usage K  # where each app uses key K (prefix with * for all)

Each app lives in its own repository (raven-macos, raven-linux, raven-windows). Name the
checkouts to check with RAVEN_APP_MACOS, RAVEN_APP_LINUX and RAVEN_APP_WINDOWS (each one
optional; by default desktop/macos, desktop/linux and desktop/windows next to this folder, as
in a combined checkout). An app whose folder is missing is skipped, and the check that no key
is left unused runs only when all three apps are there.

Fails when:
  - the file has a duplicate key or a value that is not a text or a list of texts;
  - an app looks up a key the file does not have;
  - a call fills a placeholder its text does not have, or leaves one of its text's
    placeholders unfilled (only calls whose key and arguments are written out are checked:
    macOS tr(.key, ["name": ...]), Linux trf("key", &[("name", ...)]), Windows
    Loc.Format("key", ("name", ...)));
  - a key is used by no app (and no packaging script).

How keys are found follows each app's own test (macOS StringsTests, Linux strings.rs,
Windows StringKeysTests): macOS through the `Str` enum, Linux through tr/trf/tr_list and key
literals, Windows through key literals in C# and {h:Str Key=...} in XAML. Test code is checked
for placeholders but does not count as a use. Standard library only.
"""
import json
import os
import re
import sys
from collections import defaultdict

DESIGN = os.path.dirname(os.path.abspath(__file__))
DESKTOP = os.path.dirname(DESIGN)
APP_ROOTS = {
    app: os.path.abspath(os.environ.get(f"RAVEN_APP_{app.upper()}") or os.path.join(DESKTOP, app))
    for app in ("macos", "linux", "windows")
}
STRINGS = os.path.join(DESIGN, "strings.en.json")

# Keys a packaging script reads too (kept even if no app code used them).
SCRIPT_KEYS = {
    "setup.receive.body": "macos/scripts/make-app.sh (the Local Network prompt in Info.plist)",
}

# The string table's own tests fill placeholders wrongly on purpose.
TABLE_TESTS = {"StringsTests.swift", "strings.rs", "StringKeysTests.cs"}

PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")


def load_strings():
    dups = []

    def hook(pairs):
        seen = {}
        for k, v in pairs:
            if k in seen:
                dups.append(k)
            seen[k] = v
        return seen

    with open(STRINGS, encoding="utf-8") as f:
        table = json.load(f, object_pairs_hook=hook)
    return table, dups


def walk(root, exts):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".build", "target", "bin", "obj", ".swiftpm")]
        for name in sorted(fn):
            if name.endswith(exts):
                yield os.path.join(dp, name)


def call_args(text, start):
    """The text between the parenthesis at text[start-1] and its match (strings skipped)."""
    depth, i, n = 1, start, len(text)
    while i < n and depth:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        i += 1
    return text[start:i - 1]


def top_level(args, opener, closer):
    """Pieces of args at depth 0, split on commas (strings skipped)."""
    out, depth, cur, i = [], 0, [], 0
    while i < len(args):
        c = args[i]
        if c == '"':
            j = i + 1
            while j < len(args) and args[j] != '"':
                j += 2 if args[j] == "\\" else 1
            cur.append(args[i:j + 1])
            i = j + 1
            continue
        if c in opener:
            depth += 1
        elif c in closer:
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


class Use:
    def __init__(self, app, path, line, names, test):
        self.app, self.path, self.line, self.names, self.test = app, path, line, names, test


def present(app):
    return os.path.isdir(APP_ROOTS[app])


def shown(path):
    """A path relative to the app checkout it belongs to (or to this folder's parent)."""
    for app, root in APP_ROOTS.items():
        if path.startswith(root + os.sep):
            return f"{app}/{os.path.relpath(path, root)}"
    return os.path.relpath(path, DESKTOP)


def scan_macos(uses, keys):
    root = APP_ROOTS["macos"]
    enum_file = os.path.join(root, "Sources", "RavenUI", "Support", "Strings.swift")
    with open(enum_file, encoding="utf-8") as f:
        enum_text = f.read()
    cases = dict(re.findall(r'^\s*case (\w+) = "([^"]+)"', enum_text, re.M))
    for folder, test in (("Sources", False), ("Tests", True)):
        for path in walk(os.path.join(root, folder), (".swift",)):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            body = text if path != enum_file else text.split("public final class Strings")[1]
            # Every reference to a Str case is a use (keys travel in arrays and switches).
            for m in re.finditer(r"\.(\w+)\b", body):
                if m.group(1) in cases:
                    uses[cases[m.group(1)]].append(Use("macos", path, line_of(body, m.start()), None, test))
            for m in re.finditer(r"\btr\(\s*\.(\w+)", body):
                if m.group(1) not in cases:
                    if test and os.path.basename(path) in TABLE_TESTS:
                        continue  # the table's own test names tr(.key) in its messages
                    keys["unknown"].append(("macos", path, line_of(body, m.start()), m.group(1)))
                    continue
                parts = top_level(call_args(body, m.start() + 3), "([{", ")]}")  # after "tr("
                names = set()
                if len(parts) > 1:
                    arg = parts[1]
                    if not (arg.startswith("[") and arg.endswith("]")):
                        continue  # arguments built elsewhere: not checked
                    inner = arg[1:-1].strip()
                    if inner != ":":
                        for piece in top_level(inner, "([{", ")]}"):
                            km = re.match(r'"(\w+)"\s*:', piece)
                            if not km:
                                names = None
                                break
                            names.add(km.group(1))
                if names is not None:
                    uses[cases[m.group(1)]].append(Use("macos", path, line_of(body, m.start()), names, test))
    return set(cases.values())


def scan_linux(uses, keys, known):
    root = APP_ROOTS["linux"]
    for folder in ("src", "tests"):
        for path in walk(os.path.join(root, folder), (".rs",)):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            cut = text.find("#[cfg(test)]")
            code_end = len(text) if cut < 0 or folder == "tests" else cut
            in_tests = folder == "tests"
            for m in re.finditer(r'(?<![\w.])(tr|trf|tr_list)\(\s*"([^"]+)"', text):
                key = m.group(2)
                test = in_tests or m.start() >= code_end
                if key not in known:
                    if not (path.endswith("strings.rs") and test):
                        keys["unknown"].append(("linux", path, line_of(text, m.start()), key))
                    continue
                names = set()
                if m.group(1) == "trf":
                    parts = top_level(call_args(text, m.start(1) + len(m.group(1)) + 1), "([{", ")]}")
                    arg = parts[1] if len(parts) > 1 else ""
                    if arg.startswith("&[") and arg.endswith("]"):
                        for piece in top_level(arg[2:-1], "([{", ")]}"):
                            km = re.match(r'\(\s*"(\w+)"\s*,', piece)
                            if not km:
                                names = None
                                break
                            names.add(km.group(1))
                    else:
                        names = None
                uses[key].append(Use("linux", path, line_of(text, m.start()), names, test))
            # Keys handed around as literals (for example check_intro_key) are uses too.
            for m in re.finditer(r'"([a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+)"', text[:code_end]):
                if m.group(1) in known:
                    uses[m.group(1)].append(Use("linux", path, line_of(text, m.start()), None, in_tests))


def scan_windows(uses, keys, known):
    root = APP_ROOTS["windows"]
    models = open(os.path.join(root, "src", "Raven.Windows.Core", "Engine", "Models.cs"), encoding="utf-8").read()
    ops = set(re.findall(r'public const string \w+ = "([a-z_]+\.[a-z_.]+)";', models.split("class RavenErrorCodes")[0]))
    prefixes = {k.split(".")[0] for k in known}
    for folder, test in (("src", False), ("tests", True)):
        for path in walk(os.path.join(root, folder), (".cs", ".xaml")):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            if path.endswith(".xaml"):
                for m in re.finditer(r"\{h:Str Key=([A-Za-z0-9.]+)\}", text):
                    key = m.group(1)
                    if key not in known:
                        keys["unknown"].append(("windows", path, line_of(text, m.start()), key))
                    else:
                        uses[key].append(Use("windows", path, line_of(text, m.start()), set(), test))
                continue
            if not test:
                for m in re.finditer(r'"([a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+)"', text):
                    key = m.group(1)
                    if key.split(".")[0] not in prefixes or key in ops:
                        continue
                    if key not in known:
                        keys["unknown"].append(("windows", path, line_of(text, m.start()), key))
                    else:
                        uses[key].append(Use("windows", path, line_of(text, m.start()), None, test))
            for m in re.finditer(r"\bLoc\.(Get|Format)\(", text):
                parts = top_level(call_args(text, m.end()), "([{", ")]}")
                if not parts:
                    continue
                cand = re.findall(r'"([a-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+)"', parts[0])
                if not cand:
                    continue  # a key from a variable: not checked
                names = set()
                for piece in parts[1:]:
                    km = re.match(r'\(\s*"(\w+)"\s*,', piece)
                    if not km:
                        names = None
                        break
                    names.add(km.group(1))
                if test and m.group(1) == "Get":
                    names = None  # a test may read a text with its placeholders on purpose
                for key in cand:
                    if key in known:
                        uses[key].append(Use("windows", path, line_of(text, m.start()), names, test))
                    elif test and m.group(1) == "Get":
                        pass  # tests may look up a missing key on purpose
                    else:
                        keys["unknown"].append(("windows", path, line_of(text, m.start()), key))


def main(argv):
    table, dups = load_strings()
    problems = [f"duplicate key in strings.en.json: {k}" for k in dups]
    known = {k for k in table if not k.startswith("_")}
    for k in sorted(known):
        v = table[k]
        if not (isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))):
            problems.append(f"{k}: not a text or a list of texts")
    uses = defaultdict(list)
    keys = defaultdict(list)
    found = [app for app in ("macos", "linux", "windows") if present(app)]
    if not found:
        print("no app checkout found: set RAVEN_APP_MACOS, RAVEN_APP_LINUX or RAVEN_APP_WINDOWS")
        return 2
    mac_cases = scan_macos(uses, keys) if present("macos") else set(known)
    if present("linux"):
        scan_linux(uses, keys, known)
    if present("windows"):
        scan_windows(uses, keys, known)

    if len(argv) > 2 and argv[1] == "--usage":
        for want in argv[2:]:
            for k in sorted(known):
                if k == want or (want.endswith("*") and k.startswith(want[:-1])):
                    print(f"{k}: {table[k]!r}")
                    for u in uses.get(k, []):
                        names = "?" if u.names is None else ",".join(sorted(u.names))
                        print(f"    {u.app:7} {shown(u.path)}:{u.line} [{names}]{' (test)' if u.test else ''}")
        return 0

    for app, path, line, key in keys["unknown"]:
        problems.append(f"{app}: {shown(path)}:{line} uses {key!r}, which strings.en.json does not have")
    for k in sorted(mac_cases - known):
        problems.append(f"macos: Str case for {k!r}, which strings.en.json does not have")
    for k in sorted(known):
        text = table[k]
        if not isinstance(text, str):
            continue
        need = set(PLACEHOLDER.findall(text))
        for u in uses.get(k, []):
            if u.names is None or (u.test and os.path.basename(u.path) in TABLE_TESTS):
                continue
            where = f"{u.app}: {shown(u.path)}:{u.line} {k}"
            extra, missing = sorted(u.names - need), sorted(need - u.names)
            if extra:
                problems.append(f"{where} fills {extra}, which its text does not have")
            if missing:
                problems.append(f"{where} leaves {missing} unfilled")
    used = {k for k, us in uses.items() if any(not u.test for u in us)}
    if len(found) == 3:
        for k in sorted(known - used - set(SCRIPT_KEYS)):
            problems.append(f"{k}: no app uses it (remove it, or use it)")
    else:
        print(f"apps checked: {', '.join(found)} (the unused-key check needs all three)")

    apps = defaultdict(set)
    for k, us in uses.items():
        for u in us:
            if not u.test:
                apps[u.app].add(k)
    print(f"strings.en.json: {len(known)} keys; used by macOS {len(apps['macos'])}, "
          f"Linux {len(apps['linux'])}, Windows {len(apps['windows'])}; "
          f"{sum(1 for us in uses.values() for u in us if u.names is not None)} calls' placeholders checked")
    for p in problems:
        print("problem:", p)
    print("ok" if not problems else f"{len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
