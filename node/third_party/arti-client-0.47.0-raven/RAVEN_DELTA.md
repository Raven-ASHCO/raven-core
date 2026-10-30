# Raven delta over arti-client 0.47.0

Upstream: crates.io `arti-client` 0.47.0 (MIT OR Apache-2.0, The Tor
Project; sha256 `43e6531f26fe6f44d71dabdc63b7845bae81547cc738aa942f0e3e482f776388`),
used by `raven-node`'s Tor helper (feature `tor`) and its in-process Tor
(feature `tor-embedded`, the iOS app). Wired through `[patch.crates-io]` in
`node/Cargo.toml`; outside the workspace (`exclude`). The commit before the
patch is the unchanged crates.io copy (without the `Cargo.lock` it ships for
its examples).

## Why

arti#1932: when a fresh consensus lists a Tor subprotocol as *required* and
this Arti lacks it, `TorClient`'s protocol status monitor writes a message on
stderr and calls `std::process::exit(1)`. In the `raven-tor-helper` process
that only ends the helper. In Raven's iOS app Tor runs inside the app's own
process (an iOS app may start no helper), so it would end the app.

## Change

| File | Change |
|---|---|
| `src/raven_delta.rs` (new) | `on_unsupported_software(hook)`: set once per process, the hook runs instead of the exit (the program must then drop its clients); without a hook, upstream's message, five-second wait and `exit(1)`, unchanged. `simulate_unsupported_software` (doc-hidden) runs that path with a made-up report, for the embedding program's tests |
| `src/client.rs` | the fatal closure of `enforce_protocol_recommendations` calls `raven_delta::unsupported_software` |
| `src/lib.rs` | `pub mod raven_delta;` |
| `Cargo.toml` | description notes the patch |

Raven sets the hook in `raven-node/src/onion/arti.rs` (both the helper
program and the in-process helper): that helper life ends and raven-node
turns Tor off for the rest of its run ("Tor: off: this version is too old
for the Tor network; update Raven"). Its tests: raven-node `onion::tests`.

Drop this fork once Arti offers a way for a program to be told instead of
exiting (arti#1932) and Raven moves to that release.
