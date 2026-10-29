# Raven delta over saturating-time 0.5.0

Upstream: crates.io `saturating-time` 0.5.0 (MIT OR Apache-2.0, The Tor Project),
used by `tor-netdoc` 0.47.0 in the lab Tor helper (`raven-node` feature `tor`).
Wired through `[patch.crates-io]` in `node/Cargo.toml`; outside the workspace
(`exclude`). The commit before the patch is the unchanged crates.io copy.

## Why

arti#2726: on Windows `SystemTime` counts 100 ns ticks, so `checked_add` of
less than 100 ns returns the same value. `find_limit` then never fails and
never ends. tor-netdoc calls `saturating_add`/`saturating_sub` while it checks
the consensus, so Tor bootstrap spins at 15 % forever on Windows.

## Change

| File | Change |
|---|---|
| `src/internal.rs` | `SaturatingTime: PartialEq`; `find_limit` returns when a step leaves the value unchanged; tests `coarse_clock_limits_terminate` (100 ns mock clock) and `system_time_limits_terminate` (real clock, run by Raven CI on Windows) |
| `src/lib.rs` | `saturating_add`/`saturating_sub` use `unwrap_or_else` (limit only looked up on overflow) |
| `Cargo.toml` | description notes the patch |

Drop this fork once a fixed crates.io release is in `Cargo.lock`.
