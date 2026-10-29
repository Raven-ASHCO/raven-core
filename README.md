# Raven core

[![Raven B1 Always-On](https://github.com/Raven-ASHCO/raven-core/actions/workflows/raven-b1-always-on.yml/badge.svg)](https://github.com/Raven-ASHCO/raven-core/actions/workflows/raven-b1-always-on.yml)
[![Raven Serverless Node](https://github.com/Raven-ASHCO/raven-core/actions/workflows/raven-serverless.yml/badge.svg)](https://github.com/Raven-ASHCO/raven-core/actions/workflows/raven-serverless.yml)

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

## Status: early, not independently reviewed, nothing to download yet

- **Pre-release (version 0.1.0).** No independent security review has happened yet. An internal
  review in October 2026 found problems that this version fixes; it is no substitute for an
  independent one. Read the [security errata](protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) and
  the [threat model](docs/THREAT_MODEL.md) before relying on anything here.
- **What release builds have.** Direct messaging between two computers on the same local
  network, and, since October 2026, the features that passed the
  [three-machine field test](docs/FIELD_TEST_2026_10.md) (switched on after that test, **not
  independently reviewed**):
  - **Friends on other networks:** Internet direct, peer-to-peer with hole punching (also
    between two friends behind NAT with no server), relays run by friends, router port mapping
    (UPnP, NAT-PMP, PCP, IPv6 pinholes), routes friends tell each other inside their encrypted
    links, finding this computer's public address with STUN (Cloudflare and Google only), and
    the Tor onion carrier, raced against the direct paths so a friend stays reachable from any
    network.
  - **A friend who is away:** friends keep sealed mail for each other over the local network
    and the internet, the sender keeps retrying in the background, and a message keeps trying
    for up to 7 days.
  - **Groups** of up to 16 people; the creator is the only admin.
  - **Bluetooth nearby** between Macs, with no network at all. **macOS only:** Windows and
    Linux release builds have no Bluetooth backend.
  - **The app channel** for RDAP, Raven's companion for software agents: agent tasks and answers
    travel through the Raven node between verified contacts, over the same carriers. A node takes
    them only from a verified contact, only of the two RDAP types, within size and rate limits
    ([RAVEN_APP_PAYLOAD_V1](protocol/RAVEN_APP_PAYLOAD_V1.md) §3.1). On macOS any program running
    as the same user can use it without a Keychain dialog (an accepted residual:
    [threat model](docs/THREAT_MODEL.md) §3.16).
- **What the field test showed, and what it did not.** Three computers, one person, debug builds
  with these features switched on: a phone hotspot and a home network reached each other 10 / 10
  in every direction over Tor (about 8 to 27 s per message); a computer that was off for 5
  minutes got 5 / 5 and 5 / 5 afterwards; a Bluetooth chain carried 10 / 10 both ways; the group
  checks passed; every message arrived exactly once. Hole punching never connected in that test
  (every message between the two networks went over Tor), the home router answered no
  port-mapping request (so port mapping was on but not exercised), and the onion service was unreachable
  for part of a long idle night and took up to 9 minutes to become reachable after a start. A
  small test is evidence, not proof.
- **Still your choice.** Listening for Internet direct and peer-to-peer (`raven node internet
  on`, `raven node p2p on`), router port mapping (`raven node upnp on`), relaying for friends
  (`raven relay offer on`), keeping mail for friends and asking friends to keep yours, and
  Bluetooth (`raven nearby enable`, and its background mail) each stay off until you turn them
  on. `raven node stun off` stops the STUN query. So with the defaults, two friends on different
  networks reach each other over Tor; once one of them turns a listener on, their encrypted link
  tells the other how to reach it directly.
- **No Raven server.** Raven runs no server. The only third parties are the Tor relays (for the
  onion carrier) and the two STUN servers, which answer a bare "what is my address" query. A
  contact card carries your key, your onion address (signed by your key) and, only if you add one
  yourself, a local-network address (`--lan`). Release builds never put an Internet address, a
  network ID (PeerId) or a relay into a card, and ignore them in a card they read: nothing signs
  them, so they could steer a connection to someone else. The addresses Raven finds travel only
  inside encrypted links between verified friends.
- **Lab features.** Everything else (sealed letters, mail passed on between two friends, relays
  over WebSocket on port 443 and web proxies, rotating network IDs,
  the LAN beacon, learning connectivity, lock while running, security notices, updates passed on
  by friends, link padding and knock, and more) is compiled in, tested in CI, and held off by a
  gate in the code (`*_PRODUCTION_ENABLED = false`). Debug builds can turn lab features on with
  `RAVEN_LAB_*` environment variables, for testing only; see [docs/ROADMAP.md](docs/ROADMAP.md).
  Older documents (the `docs/WAIVER_*` drafts, design documents, protocol status tables) still
  describe the switched-on features as held: they record the state before October 2026.
- **The desktop apps are in development.** Nothing is packaged, signed or notarised, and there
  are no downloads yet.
- Some documents and code comments refer to internal planning documents that are not part of
  this repository.

## Evidence

What backs the claims above, and what does not exist yet:

- [docs/EVIDENCE.md](docs/EVIDENCE.md): what is tested and how (test counts per crate, shared test
  vectors checked by Rust and a Python reference, 30 fuzz targets, CI), and a "not done yet" list.
- [docs/FIELD_TEST_2026_10.md](docs/FIELD_TEST_2026_10.md): three computers on a home network and a
  phone hotspot, debug builds with lab features on. What worked, what failed, what is open.
- [docs/HOW_RAVEN_CONNECTS.md](docs/HOW_RAVEN_CONNECTS.md): finding someone with no directory, NAT,
  an offline recipient, and checking a friend's identity, each with its status and limits.
- [docs/SECURITY_REVIEW_SCOPE.md](docs/SECURITY_REVIEW_SCOPE.md): a package for an independent
  security reviewer.
- [docs/ROADMAP.md](docs/ROADMAP.md): each lab feature, its evidence so far, and what is still
  needed before release builds get it; packaging.

The CI badges above show the two workflows that run on every push; [EVIDENCE.md](docs/EVIDENCE.md)
says what each checks.

## How to help

- **Review** the protocol and the code. [SECURITY_REVIEW_SCOPE.md](docs/SECURITY_REVIEW_SCOPE.md)
  lists what to look at first.
- **Run the field test** on your own computers and networks, and send a report with the
  [field test template](.github/ISSUE_TEMPLATE/field_test_report.md). Never post addresses, network
  names, cards or security words.
- **Report bugs** in an issue ([bug template](.github/ISSUE_TEMPLATE/bug_report.md)).
- **Security problems:** privately, never in a public issue: [SECURITY.md](SECURITY.md).
- Code contributions: [CONTRIBUTING.md](CONTRIBUTING.md) has good places to start.

## Build

Install Rust with [rustup](https://rustup.rs). CI uses Rust 1.98.0.

```sh
cd node
# macOS: with the Tor helper and the Bluetooth radio backend
cargo build --release --locked -p ash -p raven-node \
  --features raven-node/tor,raven-node/nearby-radio
bash scripts/build_nearby_helper_app.sh OUT_DIR   # RavenNearby.app, the Bluetooth helper
# Linux and Windows: with the Tor helper (no Bluetooth backend in release builds)
cargo build --release --locked -p ash -p raven-node --features raven-node/tor
```

This gives `target/release/raven` (the command line and terminal app; `ash` is the same program
under its older name), `target/release/raven-node` (the background program) and
`target/release/raven-tor-helper` (the Tor client, Arti, in its own process: keep it next to
`raven-node`, which says "Tor: not built in this raven" without it). A build without these
features still works, without Tor and Bluetooth. The install guides build with them and set
everything up as a login service: [Linux](docs/INSTALL_Linux.md),
[macOS](docs/INSTALL_macOS.md), [Windows](docs/INSTALL_Windows.md). Using Raven with no Internet
(a router with a dead uplink, a hotspot, a cable): read [the safety guide](docs/SAFETY_OFFLINE.md)
and [the offline guide](docs/OFFLINE_GUIDE.md).

The desktop engine:

```sh
cd node
cargo build --release --locked -p raven-client -p raven-node --features raven-node/tor
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

A debug build with no `RAVEN_LAB_*` variable behaves like a release build. A switched-on feature
can be closed again in a debug build with its switch set to `0` (for example `RAVEN_LAB_TOR=0`
keeps a test node off the Tor network, `RAVEN_LAB_TEST_A=0` closes Internet direct, p2p and
friends keeping mail); a release build reads none of them. The lab unlock `RAVEN_LAB_TEST_A=1`
(debug builds only) also lets cards carry and read Internet and p2p routes again, for the lab
test harnesses.

`raven-fb-ffi` (a lab-only binding) also needs `protoc` (Protocol Buffers compiler) to build.
The Python reference: `cd protocol/reference && python3 -m pip install -r requirements.txt &&
python3 -m pytest -q`.

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md)
- Security issues: please do not open a public issue; write to security@raven-messager.com
  ([SECURITY.md](SECURITY.md)).
- Copyright (C) 2026 ASHCO. License: GNU Affero General Public License v3.0
  ([LICENSE](LICENSE); notice and pending additional terms in [NOTICE](NOTICE)). The Raven name,
  logo and app icons are covered separately by [TRADEMARK.md](TRADEMARK.md) and
  [ASSET_LICENSE.md](ASSET_LICENSE.md).
