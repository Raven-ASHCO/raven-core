# Handoff: release/0.1.1 (not for publishing: remove this file before any public push)

Branch `release/0.1.1` = public main `e27a5a6` + `feature/ios-embedded` (fast-forward) + the
commits below. Local commits only; nothing pushed.

## Done

- Engine (raven-client): `messages.handoff {budget_ms?}`; `via_name` on held messages (and on
  `receipt` / `state` events; state events also carry `path`, `path_kind`); group `receipts[].held_by`;
  `path_kind` / `path` on members' group messages; `NetworkStatus.carry.friends_carry_mine.names`
  and `mail.check` `names` (who a mail check asks); Tor start percentage documented and tested for
  release engines. raven-core `group::MessageView.copies` (copy id per member).
- Tor on mobile data: one API name, `tor_wifi_only` (default false). `network.set {tor_on_cellular}`
  is BAD_REQUEST naming `tor_wifi_only`. API.md, docs/IOS.md, raven-client STATUS.md updated.
- `raven contact list/show`: a way Raven does not use now says why ("off on this computer", "once
  you verify them", "off: your IP stays hidden from them"). `raven whoami`'s invite line unchanged.
- Version 0.1.1 (workspace Cargo.toml, Cargo.lock, fuzz/Cargo.lock also synced with raven-core's iOS
  keychain deps, RavenNearby.app plist, build_unsigned.sh default, README, docs), CHANGELOG.md.
- Linux package: `scripts/release/make-linux.sh` (+ `make-linux-selftest.sh`, templates in
  `scripts/release/linux/`, `RAVEN_PREBUILT_DIR` in `node/scripts/install/linux_systemd_user.sh`,
  `.github/workflows/raven-linux-package.yml` manual x86_64 job, INSTALL_Linux.md sections).
  Fails on any build-machine path in the binaries ($HOME, /home/<user>/, any /Users/ path, the
  checkout, target, CARGO_HOME, RUSTUP_HOME).
- `node/scripts/ios/build_xcframework.sh`: release builds rewrite build paths (RUSTFLAGS
  `--remap-path-prefix`, CFLAGS `-ffile-prefix-map`; existing flags kept; `RAVEN_REMAP_PATHS=0|1`)
  and fail when `strings -a` of a slice finds a /Users/ path (expected 0). Not yet run (see below).
- Docs: README status (downloads coming, iPhone app in development / TestFlight, Bluetooth macOS
  only), docs/IOS.md, install guides open with the version and where downloads are prepared,
  ROADMAP packages table.

## Verified (on the code before the last two commits' small follow-ups)

Test env: `RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file
RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1`,
`CARGO_INCREMENTAL=0`, a separate `CARGO_TARGET_DIR`, after `cargo build --locked -p ash -p raven-node`:

- fmt clean; raven-core 2412 passed / 6 ignored; raven-node 1261 / 69 ignored; ash 3271 / 3 ignored;
  raven-client 92 (incl. net_handoff, net_custody, groups); embedded e2e (`--features tor-embedded
  --test embedded`) passed. The hand-off follow-up re-ran raven-client lib + net_handoff: passed.
- make-linux-selftest.sh, check_doc_pointers.sh, check_install_helpers.sh passed; scanner clean.

## Remaining

1. Clippy `-D warnings`: the CI sets (raven-serverless.yml "clippy" step), plain `-p raven-client`,
   `-p raven-node --features tor`, fuzz, and `-p raven-client --features tor-embedded` for
   `--target aarch64-apple-ios` and `aarch64-apple-ios-sim`.
2. Checkers: `freeze_protocol_hashes.sh --check`, `keychain_guard_check.sh`, `harness_util_selftest.sh`,
   `lan_default_selftest.sh`, `check_offline_guide.sh <debug raven>`, `check_safety_offline.sh`,
   `desktop/design/check_strings.py`, `release_tool_feature_audit.sh`, `sqlcipher_release_feature_audit.sh`.
   shellcheck is not installed on the build Mac: CI's shellcheck step is unverified for the new scripts.
3. `node/scripts/ios/build_xcframework.sh` (release, path rewrite: first full rebuild of both iOS
   targets), expect "0 with /Users/"; then boot one iOS 27.2 simulator that nobody else uses,
   `UDID=<id> node/scripts/ios/simulator_smoke.sh`, shut that simulator down.
4. Release build of the desktop shipped configuration, compile only (never run a release binary
   beyond --help): `cargo build --locked --release -p ash -p raven-node -p raven-client --features
   raven-node/tor,raven-node/nearby-radio`, warning-free.
5. Linux package on Linux: aarch64 in an Ubuntu 24.04 VM, x86_64 via the workflow. Note: the Lima VM
   `raven-linux` on the build Mac runs Ubuntu 26.04; a package built there needs 26.04's glibc.
6. iOS app changes (raven-ios), not done here: `tor_on_cellular` -> `tor_wifi_only` (inverted) in
   `network.set` and `NetworkStatus`; call `network.path` from NWPathMonitor; a message a friend holds
   is `state: sent` with `path_kind` friend/handoff + `via_name` (the app keys "held" on `waiting`);
   group `held_by` can come with state `sent`; optional `mail.check` `names`; Engine.xcconfig path to
   the new XCFramework; README "What waits for the engine" table is now implemented.
7. Delete this file before publishing.
