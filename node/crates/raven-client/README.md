# raven-client

The engine of Raven's desktop apps. The apps call one function with a JSON request and get a JSON
response back; the contract (every operation, the envelope, the types, the events and the error
codes) is `desktop/api/API.md`. `STATUS.md` says what is done and what is not verified.

The engine runs inside the app. It is the CLI's own code (`crates/ash`, reached through its
library target and `src/engine_bridge.rs`) on the same profile the CLI uses, so the app, `raven`
and `ash` see one identity and one contact list. Message delivery stays in the background
`raven-node`, which the engine starts and stops the way the CLI does.

```c
char *raven_call(const char *request_json);  /* never NULL; free with raven_free */
void  raven_free(char *response);
```

- Thread-safe. `raven_call` may block (starting raven-node takes a few seconds): call it off the
  UI thread. `events.poll` never blocks.
- A NULL or non-UTF-8 request is answered with `BAD_REQUEST`; a panic inside with `INTERNAL`.
- Every response is checked: no field named like `seed`, `private_key`, `secret`, `plaintext` or
  `recovery`, and every string is sanitised (control characters, bidi controls and zero-width
  characters removed).

## Building

From `node/` (the pinned toolchain, Rust 1.98):

```sh
cargo build -p raven-client             # debug: target/debug/
cargo build -p raven-client --release   # release: target/release/
cargo build -p raven-node --release     # the background program the app ships next to itself
```

One build gives all three forms (`crate-type = ["rlib", "staticlib", "cdylib"]`):

| File | Used by |
|---|---|
| `libraven_client.a` | macOS app (static library) |
| `raven_client.dll` (+ `raven_client.dll.lib`) | Windows app (`DllImport`) |
| `libraven_client.rlib` | Linux app and the tests (Rust) |

The header is `include/raven_client.h`. The crate is a workspace member but not a default member,
so a plain `cargo build` in `node/` does not build it.

## Profile, environment and raven-node

- Profile folder: `RAVEN_DATA_DIR`, else `ASH_DATA_DIR`, else `~/.raven` (the CLI's lookup). The
  secret-store variables the CLI honours (`RAVEN_IDENTITY_BACKEND` and friends) apply unchanged.
- The engine opens the profile as the CLI does before every command (cli.rs `run`): it refuses a
  profile whose erase or key change did not finish, loads the at-rest key of a sealed profile (and
  seals a plain one where the build seals), and prunes what the privacy pack forgets while no
  raven-node runs. See `STATUS.md`, "Opening the profile".
- The app's settings are written only once the identity exists (raven-core refuses to create an
  identity in a folder holding files it does not know): `desktop_settings.json` (atomic,
  owner-only; nothing in it names anyone), the user's name in `desktop_private.rms` (sealed once
  the profile is), and the chat-keeping time as the privacy pack's own setting (`privacy.json`).
- `node.start` (and a send, when nothing runs) starts raven-node as the user's background process
  with the CLI's own start (`ext.rs`): the program is `RAVEN_NODE_BIN` when set (an engine
  addition), else `raven-node` next to the app's executable (macOS: `Contents/MacOS/raven-node`
  in the app bundle), else the CLI's lookup. It listens on the network while the setting
  `receive` is on (`RAVEN_SERVICE_LAN_LISTEN`, else the profile's own port on every interface, as
  the CLI starts it) and on `127.0.0.1` (a free port) while it is off. It inherits the engine's
  environment, lab switches included (a debug raven-node honours them; a release one ignores them).
- The network ops (`src/network.rs`, desktop/api/NETWORK_PARITY.md) run the CLI's own commands on
  the same `node_policy.json` the CLI reads, and read the gates in this process and the running
  raven-node's Status.
- `node.stop` follows the CLI's rules: never a login service (launchd, systemd, the scheduled
  task); on macOS and Linux the process this profile's raven-node reports; on Windows only a
  process this app started.

## macOS (SwiftUI): static library and module map

1. Build `libraven_client.a` for each architecture and join them:

   ```sh
   cargo build -p raven-client --release --target aarch64-apple-darwin
   cargo build -p raven-client --release --target x86_64-apple-darwin
   lipo -create -output libraven_client.a \
     target/aarch64-apple-darwin/release/libraven_client.a \
     target/x86_64-apple-darwin/release/libraven_client.a
   ```

2. Give Swift a module (`CRavenClient`, the name the app's `RavenClientEngine.swift` expects): a
   folder with `raven_client.h` and this `module.modulemap`:

   ```
   module CRavenClient {
       header "raven_client.h"
       link "raven_client"
       export *
   }
   ```

   In SwiftPM, a `systemLibrary` target over that folder (or an `.xcframework` binary target made
   with `xcodebuild -create-xcframework -library libraven_client.a -headers <folder>`).

3. Link what the engine uses besides the system library: `-framework Security -framework
   CoreFoundation -liconv` (the Keychain; `cargo rustc -p raven-client --lib --crate-type
   staticlib -- --print native-static-libs` prints the list for the toolchain in use).

4. Call it off the main thread:

   ```swift
   import CRavenClient

   let response = request.withCString { raven_call($0) }
   defer { raven_free(response) }
   let json = String(cString: response!)
   ```

5. Ship `raven-node` in `Contents/MacOS/` next to the app's executable, signed with the app
   (`node/SIGNING_NOTARIZATION_CHECKLIST.md`).

## Windows (WinUI 3, C#): DLL and DllImport

1. `cargo build -p raven-client --release --target x86_64-pc-windows-msvc` (and
   `aarch64-pc-windows-msvc`), then ship `raven_client.dll` and `raven-node.exe` next to the app.

2. Declare the two functions; marshal the request as UTF-8 and free the response with
   `raven_free` (never with the CLR's allocator):

   ```csharp
   using System.Runtime.InteropServices;

   static partial class RavenNative
   {
       [LibraryImport("raven_client", StringMarshalling = StringMarshalling.Utf8)]
       private static partial IntPtr raven_call(string requestJson);

       [LibraryImport("raven_client")]
       private static partial void raven_free(IntPtr response);

       public static string Call(string requestJson)
       {
           IntPtr p = raven_call(requestJson);          // never IntPtr.Zero
           try { return Marshal.PtrToStringUTF8(p)!; }
           finally { raven_free(p); }
       }
   }
   ```

   (`[DllImport("raven_client", CallingConvention = CallingConvention.Cdecl)]` with a `byte[]`
   holding the NUL-terminated UTF-8 request works the same on older targets.) Run it on a
   background thread (`Task.Run`).

## Linux (GTK 4, Rust): path dependency

The Linux app is Rust and calls `raven_client::call()` directly (or keeps a
`raven_client::Client`). In `desktop/linux/Cargo.toml`:

```toml
[dependencies]
raven-client = { path = "../../node/crates/raven-client" }

# The node workspace's audited SQLCipher fork: patches apply only from the
# root project, so the app repeats the node workspace's patch.
[patch.crates-io]
libsqlite3-sys = { path = "../../node/third_party/libsqlite3-sys-raven" }
```

Its own `Cargo.lock` then pins raven-client's dependencies; keep them at the versions of
`node/Cargo.lock` (copy the entries, then `cargo build --locked`). Call it from a worker thread
and hand results back to the GTK main loop (`glib::MainContext::channel` or
`glib::idle_add_once`). Ship `raven-node` next to the app's executable (or set `RAVEN_NODE_BIN`
in the launcher).

## Tests

Every test uses throwaway profiles and the file-backed secret stores, and never listens on a
fixed port:

```sh
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file \
       RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file \
       RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
cargo build                     # raven-node, for tests/delivery.rs
cargo test -p raven-client
```

`tests/delivery.rs` starts two real raven-node processes on `127.0.0.1` (free ports) and stops
them; without a built raven-node it says so and passes. The network tests (`tests/network.rs`,
`net_internet.rs`, `net_p2p.rs`, `net_custody.rs`, `net_nearby.rs`) do the same with the `raven`
CLI and, for p2p, a local `raven-node relay`, each with the lab switches it needs set in its own
process. The release check of the gates:

```sh
RAVEN_LAB_TEST_A=1 RAVEN_LAB_NEARBY=1 ... cargo test --release -p raven-client --lib network::
```
