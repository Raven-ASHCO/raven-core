# Raven core

Raven is a private messenger with no central server. Each person's identity is a key on their
own computer; friends add each other by exchanging a card and checking each other's **security
words** in person or on a call; messages are end-to-end encrypted and travel directly between
the two computers, or through friends, never through a company's server.

This repository holds everything the Raven apps share:

| Folder | What |
|---|---|
| `node/` | The Rust workspace: `raven-core` (protocol library: identity, envelopes, sessions, encrypted storage), `raven-node` (the background program that carries messages), `ash` (the `raven` command line and terminal app), `raven-swarm` (libp2p host), `raven-client` (the engine the desktop apps call), and two lab-only FFI crates |
| `protocol/` | The wire specifications (`RAVEN_*`, `ATSAM_*`) and a Python reference implementation (`protocol/reference/`) |
| `shared-vectors/` | Deterministic test vectors, checked against both the Rust code and the Python reference |
| `desktop/` | The desktop engine's JSON contract (`api/API.md`) and the design shared by the three apps (`design/`: tokens, every text, logo, security word list) |
| `docs/` | Guides (install, offline use, relay kit, security words), design documents, the threat model and the release-gate records |
| `scripts/` | Proof, smoke and check scripts used by CI |

Related repositories, each using this one as a git submodule at `core/`:

| Repository | What |
|---|---|
| `raven-macos`, `raven-windows`, `raven-linux` | The desktop apps (SwiftUI, WinUI 3, GTK 4) |
| `raven-mesh-macos`, `raven-mesh-windows`, `raven-mesh-linux` | Bluetooth nearby (messages between laptops with no network), per operating system |

Website: https://raven-messager.com

## Status: early, not reviewed, nothing to download yet

- **Pre-release.** No independent security review has happened yet. Read the
  [security errata](protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) and the
  [threat model](docs/THREAT_MODEL.md) before relying on anything here.
- **Release builds are deliberately small.** In a release build only direct messaging between
  two computers on the same local network is switched on. Everything else (Internet direct,
  peer-to-peer and relays, the Tor onion carrier, friends keeping mail for each other, Bluetooth
  nearby, port mapping, sealed letters, lock while running, security notices, updates) is a
  **lab feature**: it is compiled in, tested in CI, and held off by a gate in the code
  (`*_PRODUCTION_ENABLED = false`) until it has been tested on real hardware and released (the
  release records are unsigned drafts in `docs/WAIVER_*`). Debug builds can turn lab features on
  with `RAVEN_LAB_*` environment variables, for testing only.
- **The desktop apps are in development.** Nothing is packaged, signed or notarised, and there
  are no downloads yet.
- Some documents and code comments refer to internal planning documents that are not part of
  this repository.

## Build

Install Rust with [rustup](https://rustup.rs). CI uses Rust 1.98.0.

```sh
cd node
cargo build --release --locked -p ash -p raven-node
```

This gives `target/release/raven` (the command line and terminal app; `ash` is the same program
under its older name) and `target/release/raven-node` (the background program). The install
guides set them up as a login service: [Linux](docs/INSTALL_Linux.md),
[macOS](docs/INSTALL_macOS.md), [Windows](docs/INSTALL_Windows.md). Using Raven with no Internet
(a router with a dead uplink, a hotspot, a cable): read [the safety guide](docs/SAFETY_OFFLINE.md)
and [the offline guide](docs/OFFLINE_GUIDE.md).

The desktop engine:

```sh
cd node
cargo build --release --locked -p raven-client -p raven-node
```

## Test

Tests must never touch your real profile or your system's keychain. Use the file-backed test
stores, which only debug builds accept:

```sh
cd node
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file \
       RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file \
       RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
cargo test --locked -p raven-core
cargo test --locked -p raven-client
cargo check --locked --workspace --exclude raven-fb-ffi
```

`raven-fb-ffi` (a lab-only binding) also needs `protoc` (Protocol Buffers compiler) to build.
The Python reference: `cd protocol/reference && python3 -m pip install -r requirements.txt &&
python3 -m pytest -q`.

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md)
- Security issues: please do not open a public issue; write to security@raven-messager.com
  ([SECURITY.md](SECURITY.md)).
- License: GNU Affero General Public License v3.0 ([LICENSE](LICENSE)). The Raven name, logo and
  app icons are covered separately by [TRADEMARK.md](TRADEMARK.md) and
  [ASSET_LICENSE.md](ASSET_LICENSE.md).
