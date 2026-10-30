# Raven on iPhone and iPad

> **Status: the engine is ready for an iOS app; the app itself does not exist
> yet.** The node, its IPC and Tor run inside one process, behind the same
> C function the desktop apps call. Tested on macOS and in the iOS
> Simulator (three engines, each running its node in its own process, with
> no `raven-node` program; the iOS Keychain; the release XCFramework linked
> into a small program). Section 10 says what ran where and what waits for
> a device.

## 1. Why one process

On macOS, Windows and Linux the app's engine (`raven-client`, one C function,
JSON in and out: [`desktop/api/API.md`](../desktop/api/API.md)) starts a
separate `raven-node` program, which starts `raven-tor-helper` (Arti) and,
on macOS, the `RavenNearby.app` Bluetooth helper. iOS lets an app start no
other process, and it suspends an app shortly after it leaves the screen.
So on iOS everything runs inside the app:

```text
 Swift app ── raven_call(JSON) ──► raven-client (engine)
                                      │  the CLI's own code (ash, engine bridge)
                                      │  IPC: the same frames, over a socket pair
                                      ▼
                                raven-node service (embedded)
                                 runtime "raven-node-worker" (2 threads)
                                 ├─ LAN direct listener and dials
                                 ├─ Internet direct, p2p host (where their gates allow)
                                 ├─ outbox worker, custody fetcher, route hints, ...
                                 └─ Tor: Arti on its own runtime "raven-tor-worker"
                                     (2 threads), the helper's code, in process
                                 profile folder: stores, logs; keys: iOS Keychain
```

The service is the program's own code (`raven-node service`): the same
profile layout, stores, carriers, workers and supervisors. Nothing in it
calls `exit`: a failure ends the node, never the app.

### 1.1 The local IPC stays

Every client of the node (the engine, the CLI's code inside it) still talks
the node's IPC: the same length-prefixed JSON frames, the same server code,
the same peer check. Only the rendezvous differs. Instead of the socket file
`<profile>/raven-node.sock`, a connect makes a socket pair and hands one end
to the node registered for that profile in this process
(`raven_core::ipc::inproc`; the server is `ipc_server::run_inproc_server`).
Why not the socket file:

- an app's container path is 80 to 90 bytes before the profile's own
  folder, so `<profile>/raven-node.sock` does not fit `sun_path` (103
  bytes), and the short fallback under `/tmp` cannot be created inside the
  app sandbox;
- a pair leaves nothing on disk for another program to find, and nothing
  stale after iOS suspends or ends the app.

The node still takes its instance lock (`raven-node.sock.lock` in the
profile): one node per profile, embedded or not.

### 1.2 One node per process

The service keeps process-wide state (the p2p host, the custody park map,
the Tor helper's life, the log), exactly as the program does. So one process
runs at most one embedded node, for one profile; a second profile is
refused. That is what an iOS app needs. The tests that need two or three
friends run each engine in a process of its own (section 9).

### 1.3 How it is built and chosen

| Crate | Feature | What it adds |
|---|---|---|
| raven-node | `embedded` | the library's `embedded` host: start, stop, pause, resume, mail check; the in-process IPC server; the node's log in the profile |
| raven-node | `tor-embedded` | Tor in process (section 6) |
| raven-client | `embedded-node` | the engine's embedded mode: the CLI's start goes to the embedded host, IPC connects in process only |
| raven-client | `tor-embedded` | `embedded-node` plus raven-node's `tor-embedded` |

raven-node is now a library (`src/lib.rs`) with the `raven-node` program as
its command line (`src/main.rs`); the desktop builds are unchanged and do
not turn these features on.

On iOS the embedded mode is the only one: building raven-client for iOS
without `embedded-node` is a compile error. On macOS (and Linux) a build
with the feature uses it when `RAVEN_NODE_MODE=embedded` is set; that is how
it is tested.

## 2. The engine's operations on iOS

The contract is [`desktop/api/API.md`](../desktop/api/API.md), unchanged,
plus three lifecycle operations (embedded node only; elsewhere they answer
`NOT_AVAILABLE_YET`):

| Operation | Args | Result |
|---|---|---|
| `node.pause` | – | `NodeStatus` + `{was_running}`: the node stopped cleanly and stays stopped |
| `node.resume` | – | `NodeStatus`: the pause ends and the node starts as `node.start` starts it |
| `mail.check` | `{budget_ms?}` | `{custody: "on" \| "off", started_node, completed, new_messages, elapsed_ms}` |

`NodeStatus` gains `embedded: true`, `paused`, and `state` `paused` or
`mail_check`. While paused, `node.start` and a send are refused (the
detail starts with `PAUSED`): such a message is `failed` with nothing
written, and `messages.retry` sends it once the app is open again. `node.stop` stops the node in process (never a
signal: its pid is the app's own).

## 3. The app's lifecycle

1. **Launch.** Set `RAVEN_DATA_DIR` (section 4) before the first
   `raven_call`. Then `profile.state`, and `identity.create` for a new
   profile; `node.start` (or `node.resume` after a pause).
2. **To the background** (`sceneDidEnterBackground`): call `node.pause`
   inside `beginBackgroundTask`. It closes the listeners, sends the p2p
   host's goodbyes, ends Tor's circuits and its helper, saves what learning
   saw, and flushes the security ledger: about a second, eight at most. The
   node holds no socket while the app is suspended.
3. **Back to the foreground** (`sceneWillEnterForeground`): `node.resume`.
   The node listens on the profile's own port again (the one it picked), so
   friends' saved addresses still work; Tor's guard and directory caches
   are in the profile, so it is ready again in seconds.
4. **Background refresh** (`BGAppRefreshTask`, about 30 s): call
   `mail.check {"budget_ms": 25000}` off the main thread, then
   `setTaskCompleted(success:)` and schedule the next request. It returns
   within its budget whatever the network does (every custody dial is cut
   at the budget, and the small node it started is stopped with a few
   seconds to spare). `new_messages` says how many arrived: show a local
   notification that names nobody and quotes nothing ("New message in
   Raven"); the text is read when the app opens.
5. **Events** (`events.poll`) only while a window is visible, as on the
   desktop.

`mail.check` on a paused node does not resume it: it starts a small node
for the check (IPC, the outbox worker and the custody fetcher; no listener,
no Tor, no p2p host, no radio), waits for one full fetch pass over the
friends who hold mail, and stops it. On a running node it asks for a fetch
pass now and waits for it. It is refused while the profile is locked or
being erased.

## 4. Where the profile lives

- `RAVEN_DATA_DIR` = `Library/Application Support/Raven` in the app's
  container (create it first). Not `Documents` (visible in the Files app),
  not `Caches` or `tmp` (iOS deletes them). The default `~/.raven` would be
  the container's root, which an app may not write.
- Exclude the folder from backups (`URLResourceValues.isExcludedFromBackup`):
  the keys never leave the device (section 5), so a backup restored
  elsewhere could not open the sealed files anyway, and the folder's
  metadata has no business in a backup.
- File protection: keep the default
  `completeUntilFirstUserAuthentication`. `complete` would make the stores
  unreadable while the phone is locked, which is exactly when a background
  refresh runs.
- **Bound to its place in the container.** A profile's keychain accounts
  and the AADs of its sealed files are derived from the profile folder's
  path (so a copy elsewhere opens nothing). iOS moves an app's container to
  a new path when the app is reinstalled or updated, which would have made
  every profile unreadable after an update. On iOS the binding is therefore
  the path below the container (`raven_core::paths::profile_binding_path`:
  `ios-app-container/Library/Application Support/Raven`), which stays the
  same; desktops keep the canonical absolute path, unchanged.
- The node's log is `raven-node-service.log` in the profile (0600, started
  afresh past 1 MiB), as for a node the CLI starts: states, counts and short
  tags, never an address, a key or a message.

## 5. Keys: the iOS Keychain

**macOS today** uses the login keychain, the legacy file-based keychain:
the add-only creates of the identity seed and the chat-history key go
through `SecKeychainAddGenericPassword` (the `SecKeychain` API, macOS only),
and every other read, write and delete through `SecItem*` without
`kSecUseDataProtectionKeychain`, which on macOS also reaches the legacy
keychain (with its per-program access lists and dialogs). Neither exists on
iOS.

**iOS** (`raven_core::apple_keychain`) uses the data-protection keychain,
in the app's own access group. Every item Raven adds there is:

- `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: readable while the
  phone is locked once it was unlocked after a restart (a background refresh
  needs that), never in a backup restored to another device;
- `kSecAttrSynchronizable = false`: never in iCloud Keychain.

An update changes the value only, so an item keeps that protection. The
items are the same as on macOS (service, then account derived from the
profile folder): `app.raven.node.identity` (the identity seed, add-only),
`app.raven.node.atsam-indexed-session` (session secrets),
`app.raven.node.prekey-lifecycle` (prekey state),
`app.raven.node.chat-history.v1` (K_hist, add-only; it also wraps the
privacy pack's at-rest key). The identity's backend marker is
`ios-keychain`. `raven erase`'s code deletes them on iOS too.

Not on iOS: a Raven passphrase (Lock v2 moves the keys into a passphrase
vault on macOS and Linux). On a phone the passcode protects the keychain;
the offer says so.

Before the first unlock after a restart every keychain read fails
(`errSecInteractionNotAllowed`, -25308): the node does not start and the
engine says the keys are not available yet. iOS runs no background refresh
before that first unlock anyway.

The keychain path ran in the iOS Simulator (section 10); it needs the
app's keychain entitlements (its access group), and it has not run on a
device yet.

## 6. Tor in the app

With `tor-embedded`, Tor runs in the node's process: the code of
`raven-tor-helper` (`src/onion/arti.rs`, shared by the program and the
in-process helper) on a thread and a two-worker runtime of its own, speaking
the same protocol to the node over in-memory pipes instead of stdin and
stdout. Everything else is unchanged:

- the same onion identity: Arti keeps the onion service's key under
  `<profile>/tor/` (0700), and the node signs and publishes the same
  binding;
- the same self-check: Tor's own client reaches the onion service as a
  friend would, before the node calls it reachable;
- the same token-checked streams between the node and Tor on 127.0.0.1
  (loopback inside the app: no Local Network prompt);
- the same supervisor: watchdogs, restarts with backoff, a restart on a
  network change; every life gets fresh pipes and a fresh runtime, and
  ending a life drops that runtime with every circuit and socket.

What a separate process gave and the app loses:

- **Arti's `exit(1)`.** When a fresh consensus marks a Tor protocol as
  *required* that this Arti lacks, Arti calls `std::process::exit(1)`
  (`arti-client` 0.47 `protostatus`, Arti #1932). The helper process used to
  absorb that; in the app it ends the app. A cached consensus that says so
  is caught at start instead (Tor then reports "this Tor version is too old"
  and the app keeps running), so this happens at most once per such
  consensus. Keeping Arti current avoids it; patching that call out of Arti
  is an owner decision (section 11).
- **A Tor thread that spins** (Arti #2726) can be left behind but not
  killed.
- A panic in Arti is caught: that life ends and the supervisor starts
  another.

Tor stops with the node on `node.pause` (the onion service is unreachable
while the app is in the background) and is not started for a mail check.
Real Arti in process has bootstrapped and published its onion service on
macOS and in the iOS Simulator (`tor_in_process_bootstraps`, which needs
the Tor network); the automated test uses the loopback helper in process.

## 7. Bluetooth nearby on iOS (not built)

Nearby is held on iOS (`NEARBY_PRODUCTION_ENABLED` is true on macOS only)
and no iOS radio is built. The macOS radio runs CoreBluetooth in
`raven-nearby-helper` (objc2-core-bluetooth) behind a line protocol
(`nearby/apple/proto.rs`); iOS needs it in process. The plan, smallest
first:

1. Build the helper's CoreBluetooth code (`bin/raven-nearby-helper/cb.rs`,
   `machine.rs`) as a module of raven-node for `target_os = "ios"` (the
   objc2 crates are the owner-approved set; their `cfg` widens to iOS).
2. Replace what is a process's: lines to stdout become lines to a socket
   pair, stdin's commands come from its other end, and the `exit` after a
   panic in a CoreBluetooth callback becomes "close the pipe, drop the
   managers" (the node then sees the helper gone, as today).
3. Give `nearby/apple.rs` a spawner like Tor's (`onion::InProcess`):
   generic reader and writer instead of a `Child`'s stdin and stdout.
4. The app's Info.plist needs `NSBluetoothAlwaysUsageDescription` (the
   helper's existing check reads the main bundle, which is the app's).

What iOS allows in the background, and what that means for RNL1:

- A background app may advertise only with the `bluetooth-peripheral`
  background mode; its service UUIDs then move to the "overflow area",
  which only an iOS device scanning for that UUID sees, and the local name
  is dropped.
- A background app may scan only for listed service UUIDs (with
  `bluetooth-central`), with no duplicates and longer intervals; a
  discovery wakes the app for about 10 seconds.
- The app must opt in to state preservation and restoration
  (`CBCentralManagerOptionRestoreIdentifierKey`) to be relaunched for
  Bluetooth events after iOS ended it; nothing relaunches it after the user
  swipes it away.
- So two phones in their pockets find each other only when one scans
  for the other's current service UUID: RNL1's rotating per-contact tokens
  must be computable ahead (they are, from the pair's keys), and the app
  must list the UUIDs of the contacts it wants to meet, refreshed as they
  rotate. A desktop in range finds a backgrounded phone the same way.
- The Simulator has no Bluetooth: all of this needs two devices.

Background Bluetooth is the one way an iOS Raven could carry mail with no
network at all; it is also the hardest to make reliable. It should come
after the app works with the network (owner decision).

## 8. How mail reaches a phone without a push server

There is no push server (owner decision): no Apple or Google service learns
who writes to whom, or when. Mail arrives in three ways:

1. **The app is open.** The node runs: friends deliver directly (LAN,
   Internet direct, p2p, Tor), and the node also collects from friends who
   hold its mail, every minute.
2. **Background refresh.** iOS wakes the app now and then (it decides when:
   from how the app is used, a few times a day at best, never after the
   user swiped the app away, nor with Background App Refresh or Low Power
   Mode off) and `mail.check` collects what friends hold.
3. **Friends hold sealed copies** (friend custody). When a friend cannot
   reach the phone, their node leaves the message, sealed end to end, with a
   mutual friend who carries for friends (`carry_for_friends`), typically a
   desktop that is always on. That friend cannot read it. The phone collects
   it the next time it is open or refreshed, and the sender's message says
   "Held by a friend" until the receipt comes back.

What this means: a phone receives quickly while Raven is open, and
otherwise when it next opens or refreshes, provided a friend holds its mail.
Between two phones with no always-on friend, a message waits on the sender's
phone until both apps are open at the same time.

## 9. Building and testing

```sh
# The XCFramework (needs Xcode with its license accepted, and the two targets):
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
node/scripts/ios/build_xcframework.sh          # release, Tor in process
PROFILE=debug node/scripts/ios/build_xcframework.sh
```

`node/scripts/ios/simulator_smoke.sh` then links the simulator slice into a
small C program (`smoke/raven_smoke.c`) and runs it in the booted
simulator (section 10). The build script stops with what to do when Xcode,
its license, the iOS SDK or a Rust target is missing. It builds the static library only (`cargo rustc
--crate-type staticlib`) and packages `RavenClient.xcframework`
(`ios-arm64` and `ios-arm64-simulator`) with `raven_client.h` and a module
map (`import RavenClient`).

C code built for iOS with Xcode's clang (all build): `ring` and `aws-lc-sys`
(rustls and QUIC for the p2p host), `libsqlite3-sys` (Raven's SQLite),
`zstd-sys` and `liblzma-sys` (Arti's directory compression). Nothing else in
the tree needs the SDK.

Tests on macOS (`node/`, with the file-backed stores):

```sh
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file \
  RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file \
  RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
cargo test -p raven-client --features tor-embedded --test embedded
cargo test -p raven-client --features tor-embedded --test embedded -- --ignored tor_in_process_bootstraps
```

`embedded_engines_end_to_end` runs three engines (this process and two
copies of the test binary), each with its node in process and no
`raven-node` program to find: friends verified by their words, a message
each way with its signed receipt, Tor in process ready (loopback helper),
`node.pause` (listener closed, a start refused, the next message left with
the third friend), `mail.check` collecting it within its budget while the
node stays paused, `node.resume`, and a direct delivery again.

## 10. What has run where

| | macOS | iOS Simulator (iOS 27.2) | iPhone / iPad |
|---|---|---|---|
| Embedded node, in-process IPC, `node.pause` / `node.resume` / `mail.check` | `embedded_engines_end_to_end` | the same test, its three engines in three simulator processes | not yet |
| Tor in process, loopback helper | in that test | in that test | not yet |
| Tor in process, real Arti (bootstrap, onion service publishing) | `tor_in_process_bootstraps` | the same test | not yet |
| iOS Keychain backend (add-only, read, update, `cku` protection, not synchronized, account listing, identity marker `ios-keychain`) | – | `apple_keychain::tests` | not yet |
| Container-relative profile binding | – | `paths::tests` | not yet |
| `RavenClient.xcframework` (release) linked by Xcode's clang into a C program: new identity in the Keychain, node started, paused, mail check, resumed, stopped | – | `simulator_smoke.sh` | not yet |
| Local Network permission, background refresh, file protection, App Store signing | – | – | not yet |
| Bluetooth nearby | – | no Bluetooth | not built |

How the simulator runs were made: test binaries built for
`aarch64-apple-ios-sim` and started with `xcrun simctl spawn`, each with
the keychain entitlements Xcode gives a simulator build (an
`__entitlements` section, ad-hoc signed); without them every keychain call
answers -34018 (missing entitlement), which is also why the file-backed lab
stores refuse to start there (they require a keychain proven empty). On a
device the app's own entitlements play that part.

Notes from the build: the library is about 160 MB per slice before the app
links it (the linker keeps what is used). Rust's standard library carries
LLVM bitcode newer than Xcode's LLVM reads; the linker ignores it, but
`nm` needs `--no-llvm-bc`.

## 11. iOS limits and decisions for the owner

Limits found while preparing the build:

- **No helper processes**: hence the embedded node and Tor in process; the
  nearby helper has no iOS form yet (section 7).
- **Local Network permission** (iOS 14+): the first LAN connect or listen
  asks the user; the app needs `NSLocalNetworkUsageDescription`. Without
  it LAN dials fail at once ("No route to host"), which Raven already
  explains (as on macOS 15). UDP broadcast and multicast (the LAN beacon,
  UPnP's discovery) also need Apple's multicast entitlement
  (`com.apple.developer.networking.multicast`), granted on request.
- **Interfaces**: `getifaddrs` works on iOS; Raven already skips `utun*`
  (VPN), `awdl*` and `llw*` (peer-to-peer Wi-Fi). Cellular is `pdp_ip*`:
  a phone on cellular is behind the carrier's NAT, so friends reach it
  only through a relay, Tor or a friend's custody.
- **Background**: no listening while suspended; background refresh is
  rare and at iOS's discretion; force-quit stops it until the next open.
- **Memory**: a background task gets less memory than a foreground app;
  the mail check's node runs no listener, Tor or p2p host for that reason.

Decisions:

1. **App Store and the AGPL.** Raven is AGPL-3.0-or-later; the App Store's
   terms add restrictions the GPL family does not allow, which has kept GPL
   apps off the store before. Distribution (App Store, TestFlight, or
   another way) needs a decision and possibly a licence exception for the
   app.
2. **Arti's `exit(1)` in the app** (section 6): accept it with prompt Arti
   updates, or keep a small patch of `arti-client` (as the tree already
   keeps one for `saturating-time`) that turns it into "Tor off".
3. **Tor on phones**: on by its gate, as on the desktop. On cellular data
   it costs a few MB per bootstrap and battery while the app is open; an
   app setting (Wi-Fi only, off) may be wanted.
4. **Bluetooth nearby on iOS** (section 7): now, or after the app works on
   the network.
5. **Notifications**: a background refresh that found mail shows a local
   notification that names nobody (section 3); the wording is the
   owner's.
