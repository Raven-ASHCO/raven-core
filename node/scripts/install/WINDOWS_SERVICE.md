# Windows — always-on raven-node + named-pipe IPC notes

**Do not** replace system shells. Prefer `raven.exe` as the unambiguous CLI; `ash.exe` is an alternate name for the same binary.

## Install script

```powershell
# From repo:
#   powershell -ExecutionPolicy Bypass -File node/scripts/install/windows_service.ps1
# CI / layout-only (no RavenNodeBridge logon task):
#   powershell -ExecutionPolicy Bypass -File node/scripts/install/windows_service.ps1 -SkipScheduledTask
```

See `windows_service.ps1` for build + Task Scheduler registration. This is a **per-user Task Scheduler** task (not an SCM service flip).

**Profile.** `-DataDir` defaults to the profile `raven.exe` / `ash.exe` use without `--data-dir` (`RAVEN_DATA_DIR`, then `ASH_DATA_DIR`, then `%USERPROFILE%\.raven`), so a plain `raven.exe doctor` talks to the daemon that serves your profile. Binaries go to `-BinDir` (default `%LOCALAPPDATA%\RavenNode`). The named pipe is **per user, not per profile** (`ipc_endpoint` ignores the data dir on Windows): with any other `-DataDir`, pass `--data-dir <that dir>` to every `raven.exe` / `ash.exe` command, otherwise the CLI pings (and dials through) a daemon that serves a different profile; do not run two profiles' daemons as the same user.

**Upgrade = re-run the installer.** After the release build succeeds it stops the running daemon (the task's instance, plus any hand-started `raven-node.exe` from the same `-BinDir`), replaces the binaries (a locked `raven.exe`/`ash.exe` is renamed to `*.old` first), re-registers the task and starts it. The task has no execution time limit (`PT0S`; the Task Scheduler default of 72h would otherwise stop the always-on daemon after three days), restarts on failure, and ignores a second start while one instance runs. A task registered by an older copy of the script keeps the 72h limit until the installer is re-run. `-TaskName <name> -NoStart` registers a differently named task without launching it (used by CI to assert the settings). Keep `windows_service.ps1` ASCII-only: `powershell.exe` 5.1 reads a BOM-less file as ANSI and an em dash then breaks a string literal.

CI (`rust-windows` in `raven-serverless.yml`) exercises this helper beyond parse-only: it runs the script with `-DataDir` / `-BinDir` under `$env:RUNNER_TEMP` and `-SkipScheduledTask` so release binaries are built and copied (`raven-node.exe`, `raven.exe`, `ash.exe`) without registering a persistent per-user logon task on the runner. Leave `-SkipScheduledTask` off for a real local install. The LAN default follows `raven-node lan-default`, the same rule as the Linux/macOS installers: `127.0.0.1:7420` (this PC only) while the build holds `--lan-listen auto` (B12 hold, `LAN_AUTO_LISTEN_PRODUCTION_ENABLED = false`), and `auto` (every network of this PC, local sources and contacts only) once the Phase 3 LAN amendment opens it. For `auto` the installer prints two Private-profile firewall rules (TCP on its port, 7420 unless `auto:PORT`, and UDP 7420 for the nearby search) to run in an elevated PowerShell and never changes the firewall itself; on a network you do not trust, `raven lan off`. `-LanListen <addr>:7420` or `-LanListen auto` is the explicit choice. CI checks that a release build installs with `lan-listen=127.0.0.1:7420`; with `RAVEN_INSTALL_RENDER_ONLY=1` the script builds, copies, stops and registers nothing and only prints `lan-listen=`, the task's arguments and the LAN lines (CI also checks that it refuses an invalid `-LanListen`). The local Bluetooth stand-in (mock BLE) listens on `127.0.0.1:7421` unless `-BleListen` (or `RAVEN_BLE_LISTEN`, as on Linux and macOS) names another address; `127.0.0.1:0` takes any free port, for a test node beside another Raven.

## Per-user background process (V1)

`raven-node service` is the always-on command: named-pipe IPC + LAN + bridge (parity with Unix `service`).

```powershell
$Data = Join-Path $env:USERPROFILE ".raven"   # the CLI default profile
Start-Process -FilePath "$env:LOCALAPPDATA\RavenNode\raven-node.exe" `
  -ArgumentList @("service","--data-dir",$Data,"--lan-listen","auto","--ble-listen","127.0.0.1:7421","--timeout-secs","0") `
  -WindowStyle Hidden
```

`auto` is every network with local sources only once the build's gate is open; until then it means `0.0.0.0:7420` from any source (still contacts only). Pass `127.0.0.1:7420` instead to keep the daemon on this PC, as the installer does while the gate is closed.

Dedicated IPC only: `raven-node ipc --data-dir $Data`.

## Bluetooth nearby

No installer turns Bluetooth nearby on, and `windows_service.ps1` changes nothing for it: `raven.exe nearby enable` does, in a build that has it (feature `nearby-radio`; held while `NEARBY_PRODUCTION_ENABLED = false`). The nearby radio uses WinRT Bluetooth in raven-node's user session, which is what the logon task gives it; a Windows service (session 0) is not supported for nearby (row N8 of [`PHYSICAL_NEARBY_LAPTOPS.md`](../../../docs/PHYSICAL_NEARBY_LAPTOPS.md) tests the logon task). `raven.exe nearby status` shows whether this PC's adapter, and Windows for an unpackaged process, allow the peripheral role: "on, central only" means it reaches contacts that advertise for it, never the other way round, and two central-only PCs cannot reach each other. Guide: [`docs/NEARBY.md`](../../../docs/NEARBY.md).

## Named pipe IPC

- Server binds the per-user pipe `\\.\pipe\raven-node-<user SID>` (`WINDOWS_NAMED_PIPE` prefix) with a **current-user DACL** (no World/Everyone ACE) and `FILE_FLAG_FIRST_PIPE_INSTANCE`. DACL setup is **fail-closed**: if the descriptor cannot be built, the process does not bind. Clients open the pipe with `SECURITY_IDENTIFICATION` and refuse a server process owned by another user (squatted pipe). The owner check reads the server process token, so run `raven-node` and `ash` at the same elevation: a non-elevated `ash` cannot read an elevated daemon's token and refuses to talk to it (fail closed). The logon task above runs non-elevated.
- Framing is the same length-prefixed JSON as Unix UDS (`raven-core::ipc`, IPC_VERSION=1): Ping, Status, SetPolicy, EnqueueSealed, LanDial. JSON keys naming secrets (`seed` / `private_key` / `plaintext` / `recovery`) are refused; EnqueueSealed is already-sealed only.
- `ipc_endpoint(data_dir)` selects the Unix socket vs this pipe so callers cannot UDS-only on Windows. ash, `ash ipc-ping`, and `ash doctor` use `ipc_client::ipc_ping` / `ipc_endpoint` (never a UDS-only probe). Successful Ping prints `daemon_presence: present` (not `up`). Connect fail is `down`. `IpcEndpoint::Unsupported` is `blocked (reason=ipc_transport_missing)` — never a soft pass / ✓. Ping ≠ ready ≠ send_path.
- Software path: framing + refuse-secret-fields are shared; OS bind is platform-specific.

## Try / Proven

`rust-windows` (MSVC) must compile `raven-node` including this server. Unit tests cover the exact pipe name and current-user DACL construction.

**Proven** for named-pipe bind/DACL requires a Windows CI cite after merge (`rust-windows` job: `cargo test -p raven-node` / `cargo build -p raven-node`). Do not claim Proven from Linux/macOS CI alone.

## Dedicated relay (logon task)

`windows_relay.ps1` is the Windows part of the relay kit ([`docs/RELAY_KIT.md`](../../../docs/RELAY_KIT.md)): a dedicated relay for your friends (`raven-node relay`) that holds **no Raven identity**, only its own libp2p key (`relay_key.ed25519`), and relays only between the PeerIds you allow.

```powershell
#   powershell -ExecutionPolicy Bypass -File node/scripts/install/windows_relay.ps1 -PublicHost 203.0.113.7
```

- **Folders.** `-RelayDir` (default `%LOCALAPPDATA%\RavenRelay`, the folder `INSTALL_Windows.md` uses for a relay run by hand, so its PeerId is kept) holds the key, `relay_allow.json` and `relay_status.json`. `-BinDir` (default `%LOCALAPPDATA%\RavenRelayBin`) holds `raven-node.exe`, `raven.exe`, their `.prev` copies, `kit.conf` and `raven-relay.cmd`. Neither may contain `"`, `%` or a newline.
- **Settings.** `-Port 7423` (TCP + QUIC), `-Tcp443 direct|7443|off` (also TCP 443 for networks that let only HTTPS out; Windows has no privileged ports, but http.sys or IIS may hold 443, and then the check says so), `-PublicHost`, `-NoAutonat`, `-CountsEvery 300`. What you do not pass comes from `kit.conf` (plain `KEY=VALUE` lines the last run wrote; parsed, never run), so an update is a plain re-run.
- **Binaries.** `cargo build --locked` (release; debug with `-Lab`) or `-Prebuilt <dir>`. The new `raven-node.exe relay --check` looks at the gate, the folder and every port before anything is replaced: exit 3 is a build that holds p2p (`P2P_PRODUCTION_ENABLED=false`; until that flips, only `-Lab` debug builds install), 4 a busy port, 5 the folder. The running relay (the task's, then any `raven-node.exe` from `-BinDir`) is stopped first, the old binaries stay as `.prev`, and after the start the relay must report its ports and the same PeerId within 20 s, else the `.prev` binaries come back. `-Rollback` swaps them by hand.
- **Logon task** (design Q9, owner decision K3): `-TaskName` (default `RavenRelay`) runs at logon with the same Task Scheduler settings as `windows_service.ps1` (`PT0S`, start when available, restart on failure, one instance). It runs only while you are signed in, and a sleeping PC relays nothing. There is no Windows service and no boot-time task for the relay. Under `-Lab` only, the action is `cmd.exe /d /s /c "set RAVEN_LAB_TEST_A=1&& ..."`.
- **Commands.** `raven-relay.cmd` in `-BinDir` is `raven.exe --data-dir <RelayDir> relay ...`: `raven-relay card`, `raven-relay allow --card '<card>'` (every friend who sends or is reached through the relay; compare the fingerprint), `raven-relay deny`, `raven-relay status`. Task Scheduler keeps no stderr: `raven-relay status` (allow-list, state and counts from `relay_status.json`) is the log.
- **Firewall.** Never changed; the script prints the Private-profile rules (TCP 7423 and 443, UDP 7423, for that `raven-node.exe`) to run in an elevated PowerShell.
- **Uninstall.** `windows_relay.ps1 -Uninstall` removes the task and the binaries and keeps `-RelayDir` (the key: a re-install keeps the PeerId; delete the folder yourself to forget it).

CI (`rust-windows`) parses this script, runs it with `-SkipScheduledTask -Prebuilt target\debug -Lab` under `$env:RUNNER_TEMP`, then registers `-TaskName RavenRelayCI-<pid> -NoStart` to assert the task's arguments and settings, and always unregisters it.

## Uninstall

Stop the scheduled task / process; delete the binaries in `-BinDir` (`$env:LOCALAPPDATA\RavenNode` by default). The profile (`$env:USERPROFILE\.raven` by default) holds your identity, contacts and history: keep or back it up unless you really want to discard them. Never delete unrelated `ash.exe` on PATH that is not Raven's.
