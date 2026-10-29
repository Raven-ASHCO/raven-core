# Raven desktop: shared design and engine contract

Raven has native desktop apps for **macOS** (SwiftUI), **Windows** (WinUI 3, C#) and **Linux**
(GTK 4, Rust). They share one design, one set of texts and one engine. The shared parts live here,
in `raven-core`; each app lives in its own repository and uses `raven-core` as a git submodule at
`core/`:

| Repository | What |
|---|---|
| `raven-macos` | SwiftUI app (Swift package; macOS 13 or newer) |
| `raven-windows` | WinUI 3 app (C#, .NET 8, Windows App SDK) |
| `raven-linux` | GTK 4 app (Rust, gtk4-rs) |

| Folder in this repository | What |
|---|---|
| `design/` | `DESIGN.md` (screens, motion, per-platform notes), `tokens.json` (colours light and dark, type, spacing, motion), `strings.en.json` (every text the apps show, English only, one text per key for all three apps, checked by `check_strings.py`), `raven-security-words-v1.txt` (the security word list the apps' debug-only demo engines embed), `assets/` (logo files), `mockups/` (open in a browser) |
| `api/` | `API.md`: the JSON contract between the apps and the engine (`raven-client`: one C function, JSON in and out); `NETWORK_PARITY.md`: every way the terminal Raven connects, and what the apps can see and change of it |

The engine itself is `node/crates/raven-client` (a Rust library built on the CLI's own code, one C
function `raven_call()`); see its `README.md` and `STATUS.md`. The apps ship `raven-node`, the
background program that carries messages, next to themselves.

## Status

The apps are **in development**. Nothing is packaged or signed, and there is nothing to download
yet. Release builds of the engine keep every lab feature off (only direct messaging on the local
network is on); debug builds honour the `RAVEN_LAB_*` switches for testing, always on a throwaway
profile (`RAVEN_DATA_DIR`), never your real one.

## Checking the shared strings

`design/check_strings.py` checks `strings.en.json` against the apps' code: every key an app uses
exists, and every call fills exactly its text's placeholders. Point it at the app checkouts you
have (each variable is optional); the check that no key is left unused runs only when all three
are given:

```sh
RAVEN_APP_MACOS=../raven-macos RAVEN_APP_LINUX=../raven-linux RAVEN_APP_WINDOWS=../raven-windows \
  python3 desktop/design/check_strings.py
```

## App identity (one id, three spellings)

| Where | Id | Why this spelling |
|---|---|---|
| Linux (desktop file, AppStream, D-Bus, icons, Flathub) | `io.github.raven_ashco.Raven` | Flathub's rule for GitHub projects: the organisation name with `-` turned into `_` |
| macOS (`CFBundleIdentifier`) | `io.github.raven-ashco.Raven` | bundle ids allow letters, digits, `-` and `.` only |
| Windows (MSIX `Identity Name`, AppUserModelID, single-instance key) | `io.github.raven-ashco.Raven` | same character rule as macOS |

The display name is **Raven** everywhere.

## Rules

English only; no personal names; every new dependency pinned and reviewed; honest motion (an
animation shows something that really happens).
