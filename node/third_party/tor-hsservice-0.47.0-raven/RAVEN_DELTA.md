# Raven delta over tor-hsservice 0.47.0

Upstream: crates.io `tor-hsservice` 0.47.0 (MIT OR Apache-2.0, The Tor Project),
sha256 `55809560d9295dcc2ee77002c5a4275d1f5f5a54203de7cd6acb52215f5344bd`,
used by `arti-client` 0.47.0 in the lab Tor helper (`raven-node` feature `tor`).
Wired through `[patch.crates-io]` in `node/Cargo.toml`; outside the workspace
(`exclude`). The commit before the patch is the unchanged crates.io copy
(without the `Cargo.lock` it ships).

## Why

The descriptor publisher adds a reupload timer (60 to 120 minutes) on every
upload result (`Reactor::handle_upload_results`) and takes one away only when
it fires. A timer that fires marks the descriptor dirty for every HsDir of its
time period: a whole reupload, whose result adds a timer again. So the uploads
that timers cause keep the number of timers as it is, and every upload that no
timer asked for (a new consensus that moves an HsDir, a changed introduction
point, an HsDir tried again) leaves one more timer behind for as long as its
time period lasts. Only timers that fire within the same minute fall together
(the upload rate limit).

An onion service that stays up therefore uploads its descriptor more and more
often. In the log of a helper that ran for days, the upload rounds grew from
1 to 8 an hour in the first hours to 35 to 55 an hour after a day, and the
helper's check of its own address failed more often in the ten minutes after
many whole uploads (37 % against 20 %). Every upload is a new descriptor
revision at the HsDirs and new circuits for the helper.

## Change

| File | Change |
|---|---|
| `src/raven_delta.rs` | new: `push_unless_waiting`, which adds a timer only when none like it waits |
| `src/publish/reactor.rs` | `handle_upload_results` adds a reupload timer only when the time period has none; the one that waits, the earlier, stays. Otherwise it logs `descriptor reupload already scheduled` (debug) |
| `src/lib.rs` | `pub mod raven_delta` |
| `Cargo.toml` | description notes the patch |

The earlier timer is the one to keep: when it fires, every HsDir of the time
period gets the descriptor again, so no HsDir waits longer for its reupload
than upstream's 120 minutes. A later timer in its place could be put off again
and again by uploads to single HsDirs, and an HsDir drops a descriptor it has
held for its lifetime.

The crate's own tests need crates that Raven does not vendor. The patch is
tested from `raven-node` (feature `tor`):
`the_hsservice_patch_keeps_one_reupload_timer_per_time_period` plays two days
of one time period with upstream's rule and with this one.

Drop this fork once a crates.io release that keeps one reupload timer per time
period is in `Cargo.lock`.
