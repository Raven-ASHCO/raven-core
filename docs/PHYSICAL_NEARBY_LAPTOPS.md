# Bluetooth nearby between laptops: hardware rows N1-N12 (operator)

**Status:** owner-run, **open** (`BLOCKED_HARDWARE` until a person runs the
rows on real laptops). Nothing here is run, signed or flipped yet. Results go
to `node/proof_artifacts/nearby/<ROW>-<UTC>/` (git-ignored) and are attached
to the signature record of [`WAIVER_NEARBY_DRAFT.md`](WAIVER_NEARBY_DRAFT.md)
(§7). The rows come from the Nearby design (`docs/roadmap/plans/phase45-design.json`,
`.designs[3]`, owner decisions O5-10 to O5-13); the user guide is
[`NEARBY.md`](NEARBY.md) and the wire is
[`RAVEN_NEARBY_LINK_V1.md`](../protocol/RAVEN_NEARBY_LINK_V1.md) (RNL1).

This is the laptop-to-laptop profile. The older phone bridge (iOS GATT
mesh) is [`PHYSICAL_BLE_THREE_DEVICE.md`](PHYSICAL_BLE_THREE_DEVICE.md), a
different, legacy profile.

**Order:** N1 (two Macs) first: the owner's own hardware is two Macs and
the macOS backend's discovery chain, MTU and write flow control run on a
radio for the first time there (cutoff addendum). Then N7 and N8 on macOS,
then the other operating systems.

| Row | What | Laptops | Section |
|---|---|---|---|
| N1 | Mac to Mac (MacBook and Mac Studio), 10 each way | 2 Macs | 4 |
| N2 | Mac to Linux, `Privacy = device` on and off | Mac, Linux | 4 |
| N3 | Mac to Windows (Windows central-only, lab allowance until N7w) | Mac, Windows | 4 |
| N4 | Linux to Windows; record the central-only result | Linux, Windows | 4 |
| N5 | range walk: 1/5/10/20/30 m, 1 and 2 walls | any pair | 5 |
| N6 | throughput: 20 queued messages and one 48 KB message | any pair | 5 |
| N7 | privacy capture with a third device | each OS that advertises + sniffer | 6 |
| N8 | background service: launchd agent with the helper app, systemd user unit, logon task | each OS | 7 |
| N9 | lid close, sleep and Bluetooth off mid-transfer; recovery with no user action | any pair | 8 |
| N10 | mule A to C to B over nearby (custody lab) | 3 laptops | 8 |
| N11 | carrier order: Wi-Fi on (LAN wins), Wi-Fi off (nearby takes over) | any pair | 9 |
| N12 | 2.4 GHz coexistence: throughput with Wi-Fi busy and off | any pair | 9 |

## 0. Purpose and honest claim

- Real radios, real operating systems. Every `*_PRODUCTION_ENABLED` gate
  stays `false`, `NEARBY_PRODUCTION_ENABLED` included: the rows run a
  **debug** build of the commit under test with feature `nearby-radio` and
  the lab switches `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_NEARBY=1`, exported in
  every shell before every command (section 2). Release builds never read
  them. Nothing here flips a gate.
- Software stand-ins do not replace these rows: carrier_matrix C50-C53 and
  C56 and the fault matrix's s63-s67 and s72-s74 run on a fake Bluetooth
  "air" on loopback (`raven-node nearby-ether`); the macOS helper's tests
  run with no radio; CI's advisory `nearby-btvirt` job runs BlueZ on
  emulated controllers; `nearby_helper_selftest.sh` is a dry run of the
  installer. None of them touches a real radio or a real stack's quirks.
- **Test homes only:** `~/raven-nearby-test/<NAME>`, created for these rows.
  Never `~/.raven`, a live node's folder, or a profile an older binary still
  uses: a build of this tree seals a profile at its first start (a debug
  build only with `RAVEN_LAB_AT_REST=1`, which these rows do not set), and
  older builds then refuse it. The test identities use the `locked-file`
  backends (debug builds only): their keys sit unencrypted on disk, so they
  are for these rows only.
- **Ports:** a Raven node you already run keeps its ports. The test nodes
  listen on LAN port **7440** (any free port works; record it).
- **Wi-Fi off** on both laptops (and no cable) unless the row says
  otherwise: Bluetooth must be the only path. Turning Wi-Fi, Bluetooth and
  system settings on and off, `main.conf`, and the sniffer are yours to run.
- Records name no address, device name or Bluetooth address of anyone
  else's device (section 3).

## 1. Gear (owner decision O13)

- The MacBook and the Mac Studio (N1, and the Mac side of N2, N3, N5-N12).
- A Linux laptop with BlueZ 5.64 or newer (or a Raspberry Pi 4/5), with
  `sudo` for `/etc/bluetooth/main.conf` and `btmon`.
- A Windows 10 (1803 or newer) or 11 laptop.
- A third device as the privacy sniffer (N7): a Linux machine with `btmon`
  and `bluetoothctl`, or a phone with nRF Connect for Mobile. Optional: a
  Bluetooth LE connection sniffer (an nRF52840 dongle with nRF Sniffer for
  Bluetooth LE and Wireshark) for the replay part of N7.
- A third laptop (any OS) as the friend in N10.
- A tape measure, and two rooms with one and two walls between them (N5).

## 2. Every laptop: build, test home, meet once, turn nearby on

### 2.1 Build (from `node/` of a checkout of the commit under test)

```bash
cd node
cargo build --locked -p ash -p raven-node --features raven-node/nearby-radio
# macOS only: RavenNearby.app next to the debug raven-node (found there first), signed ad hoc
bash scripts/build_nearby_helper_app.sh "${CARGO_TARGET_DIR:-target}/debug" --debug
```

Windows (PowerShell, in `node\`):

```powershell
cargo build --locked -p ash -p raven-node --features raven-node/nearby-radio
```

### 2.2 Every terminal

`NAME` is the laptop's name in the rows: `A` and `B` for the two Macs,
`L` for the Linux laptop, `W` for the Windows laptop and `C` for the third
laptop of N10; its tag in the other laptops' contact books is the same
letter in lower case. Run this in `node/` in every new terminal:

```bash
export NAME=A
export T="$HOME/raven-nearby-test/$NAME"
BIN="$(cd "${CARGO_TARGET_DIR:-target}/debug" && pwd)"
export BIN
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file \
  RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file \
  RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 RAVEN_LAB_TEST_A=1 RAVEN_LAB_NEARBY=1 NO_COLOR=1
r() { "$BIN/raven" --data-dir "$T" "$@"; }
# send_n TAG ROW COUNT: numbered messages to TAG; each prints its outcome and seconds
send_n() {
  local i start
  for i in $(seq 1 "$3"); do
    start=$(date +%s)
    printf '%s %s->%s %s/%s %s\n' "$2" "$NAME" "$1" "$i" "$3" "$(date -u +%H:%M:%S)" \
      | RAVEN_VERBOSE=1 "$BIN/raven" --data-dir "$T" send --contact "@$1" 2>&1 | tail -n 3
    echo "  ($i/$3: $(( $(date +%s) - start )) s)"
  done
}
```

Windows (PowerShell, in `node\`; `W` is the Windows laptop's name in the
rows):

```powershell
$env:NAME = "W"
$T = Join-Path $env:USERPROFILE "raven-nearby-test\W"
$BIN = (Resolve-Path ".\target\debug").Path   # or (Join-Path $env:CARGO_TARGET_DIR "debug")
$env:RAVEN_IDENTITY_BACKEND = "locked-file"; $env:RAVEN_SESSION_BACKEND = "locked-file"
$env:RAVEN_PREKEY_BACKEND = "locked-file"; $env:RAVEN_CHAT_HISTORY_BACKEND = "locked-file"
$env:RAVEN_ALLOW_EPHEMERAL_DATA_DIR = "1"; $env:RAVEN_LAB_TEST_A = "1"; $env:RAVEN_LAB_NEARBY = "1"
$env:NO_COLOR = "1"
function r { & "$BIN\raven.exe" --data-dir $T @args }
function Send-N($tag, $row, $count) {
  $env:RAVEN_VERBOSE = "1"
  foreach ($i in 1..$count) {
    $start = Get-Date
    "$row $($env:NAME)->$tag $i/$count $((Get-Date).ToUniversalTime().ToString('HH:mm:ss'))" |
      & "$BIN\raven.exe" --data-dir $T send --contact "@$tag" 2>&1 | Select-Object -Last 3
    "  ($i/$count`: $([int]((Get-Date) - $start).TotalSeconds) s)"
  }
  Remove-Item Env:RAVEN_VERBOSE
}
```

### 2.3 Create the test home and start the node

```bash
mkdir -p "$T" && chmod 700 "$T"
r init
r prekey publish
"$BIN/raven-node" service --data-dir "$T" --lan-listen 0.0.0.0:7440 \
  --ble-listen 127.0.0.1:0 --timeout-secs 0 >>"$T/node.log" 2>&1 &
echo $! >"$T/node.pid"
r ipc-ping
```

Stop it later by its pid: `kill "$(cat "$T/node.pid")"`.

Windows:

```powershell
New-Item -ItemType Directory -Force $T | Out-Null
r init
r prekey publish
$node = Start-Process -FilePath "$BIN\raven-node.exe" -PassThru -WindowStyle Hidden `
  -RedirectStandardError "$T\node.log" -RedirectStandardOutput "$T\node.out" `
  -ArgumentList @("service", "--data-dir", "`"$T`"", "--lan-listen", "0.0.0.0:7440",
                  "--ble-listen", "127.0.0.1:0", "--timeout-secs", "0")
r ipc-ping
```

Stop it later: `Stop-Process -Id $node.Id`.

### 2.4 Meet once over the local network

Bluetooth keys come from each other's device certificate, which a first
link over any other carrier leaves behind. With Wi-Fi on and both laptops
on the same network:

```bash
r whoami --card --lan <this laptop's LAN IP>:7440
r whoami | grep -i fingerprint
```

(Windows: `r whoami | Select-String -Pattern fingerprint`.) On the other
laptop, add that card as a **verified** contact after comparing the words
with the first screen, tagged with the first laptop's letter (here A adds
B):

```bash
r contact add --card '<the card>' --petname B --tag b --verify-fp '<the words the other screen shows>'
r contact list
echo "meet $NAME" | RAVEN_VERBOSE=1 "$BIN/raven" --data-dir "$T" send --contact @b --carrier lan
```

Both directions must say `status delivered`. Every pair of laptops in a row
meets this way once (all three pairs for N10).

### 2.5 Turn nearby on

```bash
r nearby enable
r nearby status
r doctor | grep nearby
```

The first `enable` prints the consent once (record it, with this computer's
Bluetooth name replaced by `<bt-name>`). Expected rows: `nearby on`,
`bluetooth on` (Windows: `on, central only` is possible, section 4 N3),
`address random, changing` (Linux only with `Privacy = device`; Windows:
`nearby inactive`, by design in this build: export
`RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR=1` before the Windows node starts for
every Windows row until N7w has settled which address Windows uses). On macOS the first radio
start asks for Bluetooth (section 7 N8 says what to record).

Then Wi-Fi off on both laptops (and unplug any cable) for every row except
N11 and N12.

## 3. Record for every row

`node/proof_artifacts/nearby/<ROW>-<UTC>/` holds:

- `row.txt`: the row, the date, the commit under test, who ran it, each
  laptop's OS and version and model, the Bluetooth chip where the OS shows
  it (macOS `system_profiler SPBluetoothDataType`, Linux `bluetoothctl show`
  and `bluetoothctl --version`, Windows Device Manager), the lab switches,
  and the distance between the laptops;
- delivered out of 10 in each direction, each exactly once (count the texts
  in the receiver's `r inbox`), with the seconds `send_n` printed per
  message and the carrier: `carrier=nearby_dial` on a delivered send line,
  or `carrier nearby_dial` in `r outbox status <id>` for one that waited;
- **time to receipt**: the UTC time in each text against when it showed in
  the receiver's `r inbox`, and the time from `r nearby enable` (or Bluetooth
  on) to the first delivery (discovery);
- **RSSI and distance**: RSSI as the sniffer device (section 1) shows it
  for the advertising laptop, held next to the receiving one;
- **max_tx** (the frame size: the ATT MTU minus 3, at most 512): this build
  does not print it; record it from a capture that shows the MTU exchange
  (`btmon` on a Linux end, or a connection sniffer), else "not recorded";
- **bytes/s** (N6, N12): message bytes over seconds from send to receipt;
- `r nearby status` and `r doctor | grep nearby` of each laptop before and
  after (counts only), and the node log's nearby and delivery lines:
  `grep -E 'nearby|outbox: delivered' "$T/node.log" | tail -n 40` (they
  name no device and no key);
- the pass or fail against the row's bar, and anything that surprised you.

Replace every Bluetooth address, device name and network name in the
records (`<bt-addr-1>`, `<bt-name>`); keep raw sniffer captures (N7) on
your own machine: they hold the addresses of every device around you.

## 4. Operating-system pairs

### N1: Mac to Mac (MacBook and Mac Studio), first

- Both Macs: section 2, then Wi-Fi off (and the Mac Studio's Ethernet
  unplugged).
- A: `send_n b N1 10`; B: `send_n a N1 10`.
- Record the Bluetooth prompt and section 7 N8's macOS items for this
  hand-started node too (which app the prompt names; what System Settings >
  Privacy & Security > Bluetooth lists).
- macOS backend items exercised here for the first time: discovery (scan,
  connect, service and characteristic lookup, subscribe), the MTU (max_tx),
  and write-without-response flow control under 10 messages in a row. On
  any failure keep the node log: the helper's own lines are in it, prefixed
  `raven-node nearby:`.
- Pass: 10/10 each way, each once, `carrier nearby_dial`; `r doctor` on both
  names central and peripheral in `roles=` and says `address=random`.

### N2: Mac to Linux

- Linux first with `Privacy = device` (an admin edits `/etc/bluetooth/main.conf`:
  `Privacy = device` under `[General]`, then `sudo systemctl restart bluetooth`;
  restart the test node). Linux's `address` row says `random, changing`:
  this also shows that the unprivileged management read (READ_INFO) works
  on this distribution.
- 10 each way (`send_n l N2 10` on the Mac, `send_n a N2 10` on Linux).
- Then `Privacy` off again (restart bluetooth and the node): Linux's
  `address` row says nearby is inactive and Linux neither advertises nor
  connects (its connects would come from the fixed public address). Send 3
  each way, with the Mac also advertising for Linux (`r nearby on @l --for
  1h` on the Mac): nothing is delivered over nearby, the messages wait in
  `r outbox`, and Linux's `in range` row stays 0. Record both.
- Linux items: `bluetoothctl --version`; Linux's max_tx (BlueZ passes the
  MTU with each write; an ATT MTU of 23 gives 20-byte frames, below the
  64-byte minimum, and the link then stays silent by design: record it if
  it happens).
- Pass: 10/10 each way with `Privacy = device`; with Privacy off, no
  nearby delivery either way and no connect from Linux.

### N3: Mac to Windows

- This build counts every Windows address as public (it cannot tell which
  address WinRT advertises or connects from), so Windows nearby is inactive
  unless its node started with `RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR=1` (a
  debug build with the lab switches; N7w settles the address). With it,
  the Mac advertises for Windows: on the Mac `r nearby on @w --for 1h`.
- 10 each way (`send_n w N3 10` on the Mac, `Send-N a N3 10` on Windows).
- Windows items:
  - the `bluetooth` row: `on` or `on, central only` (GattServiceProvider in
    an unpackaged process, and the adapter's peripheral role);
  - the frame sizes WinRT gives at subscription (MaxNotificationSize,
    MaxPduSize: under 64 the link stays silent);
  - Write Commands arriving in order: any `RESET` or `PROTOCOL` line in
    either node log is a failure to record;
  - uncached GATT lookups across an ID change: keep the run going past a
    quarter hour (the IDs change at :00, :15, :30 and :45 UTC) and send 3
    more each way after it;
  - when the Mac leaves (Bluetooth off on the Mac), Windows' `in range` row
    drops to 0: record how long that takes.
- Pass: 10/10 each way with the Mac advertising.

### N4: Linux to Windows

- Linux with `Privacy = device` (Windows does not advertise, so Linux must),
  and the Windows node with `RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR=1` as in N3;
  on Linux `r nearby on @w --for 1h`.
- 10 each way. If the Windows adapter has no peripheral role, record the
  central-only result (it is the expected one in this build anyway).
- Then one attempt with Linux's `Privacy` off: Linux neither advertises
  nor connects, so nothing is delivered; both sides must stay honest
  (messages wait in `r outbox`, `in range 0`). Two Windows PCs can never reach each other in
  this build either; no row is needed for that.
- Pass: 10/10 each way with `Privacy = device`.

## 5. Range and throughput

### N5: range walk

- The pair that did best in section 4 (two Macs if nothing else). A stays;
  B moves to 1, 5, 10, 20 and 30 m with a line of sight, then behind one
  wall and two walls.
- At each spot: `send_n` 3 each way, the RSSI of A's advert at B (sniffer
  phone next to B; A advertises: `r nearby on @b --for 1h` on A), and the
  seconds per message.
- Note where delivery stops, and whether it resumes on the way back with
  no user action. With Windows in the pair, note how long its `in range`
  row takes to drop after B leaves.
- Pass: no fixed bar; the waiver needs the curve.

### N6: throughput

- 20 queued: B's Bluetooth off; A `send_n b N6 20` (all wait: `r outbox`).
  B's Bluetooth on: the seconds until all 20 are in B's `r inbox`, in order.
- One 48 KB message:

  ```bash
  { printf 'N6 big %s ' "$(date -u +%H:%M:%S)"; head -c 49000 /dev/zero | tr '\0' x; echo; } \
    | RAVEN_VERBOSE=1 "$BIN/raven" --data-dir "$T" send --contact @b
  ```

  bytes/s = 49000 over the seconds from send to receipt.
- Below about 5 KB/s, say so: the optional L2CAP fast path (design step
  5.13, owner decision O12) is decided on this row.
- Pass: all 21 delivered, each once; the 20 in order.

## 6. Privacy

### N7: privacy capture with a third device

Run it for each OS: N7m (macOS), N7l (Linux with `Privacy = device`, then
without it), and N7w (Windows, lab only: Windows advertises and connects
only with `RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR=1` exported before its node
starts; the question is which address WinRT uses for each). The advertiser
A: `r nearby on @b --for 1h`; B is off or out of range.

**Watch the air** for 20 minutes, across a quarter hour:

- Linux sniffer: `sudo btmon -w n7-air.btsnoop` in one terminal and
  `bluetoothctl` then `scan on` in another; or nRF Connect's scanner on a
  phone (A appears and disappears with `r nearby off @b` / `on`).
- The advert holds Flags and exactly one 128-bit service UUID: no Local
  Name, Manufacturer Data, Service Data, TX Power or Appearance, and the
  scan response holds nothing of Raven's.
- The address is random (btmon says "Random", or a resolvable private
  address: the first hex digit is 4 to 7) and changes: record how often.
- The UUID changes at each quarter hour (UTC); at most one Raven UUID is on
  the air at a time, also while A rotates two contacts (`r nearby on @c`
  as well, with a third contact).
- `r nearby off @b`: the advert stops within seconds.
- Windows (N7w): with the provider for a second contact connectable but not
  discoverable, nothing more is on the air; and record the address type.
  Random (and a random InitA, below): the owner may switch Windows to
  `Random` (one line, `winrt::caps`); public: Windows nearby stays
  inactive.

**Be a stranger** (nRF Connect on the phone, connected to A):

- Read Generic Access > Device Name and, on macOS, Device Information
  (Manufacturer Name, Model Number): record what they show (as
  `<bt-name>` and the model).
- The Raven service has one characteristic: Write, Write Without Response,
  Notify, no Read.
- Subscribe (enable notifications): nothing arrives from a Mac or Windows
  peripheral. On a Linux A with a live link to B, the encrypted
  notifications of that link do arrive (the disclosed BlueZ broadcast):
  record their sizes only.
- Write 35 random bytes starting `01 01` (a fake knock), three times:
  nothing comes back, A's `r doctor` shows `knock_silenced=` going up, and A
  ignores the connection after three invalid frames (macOS and Windows
  cannot drop it; Linux may).
- Replay: only with a connection sniffer that captured a real knock between
  A and B: write it again from the stranger; nothing comes back. Without
  one, write "replay not run (no connection sniffer); covered by carrier
  matrix C51 and the RNK1 negative vectors".

**Watch a connect** (A as the central; review nearby-1). B advertises for A
(`r nearby on @a --for 1h` on B) and A has nothing to send:

- With a connection sniffer (nRF Sniffer for Bluetooth LE with Wireshark,
  or an Ubertooth), capture A's CONNECT_IND and record its initiator
  address (InitA) type: random (a resolvable or non-resolvable private
  address) is the pass; public is a fail to report. N7w decides Windows
  with it: random for both the advert and InitA, and the owner may switch
  Windows to `Random`; public for either, and Windows stays inactive.
- N7l without `Privacy = device`: A makes no connect at all (no CONNECT_IND
  from A, A's `in range` stays 0) and `r doctor` prints `nearby_fix: nearby
  inactive`.
- A beacon played back (review nearby-4): record B's advertised UUID with
  the phone, stop B, and advertise that UUID from the phone (nRF Connect's
  advertiser) near A within 15 minutes: A connects to the phone at most
  twice for it, then ignores it (`r doctor` on A; the phone's connection
  log). Record the count.
- Pass: flags and one rotating UUID from a random address, no name or data,
  silence to the stranger, A's connects from a random address (none at all
  from a public one), at most two connects to a played-back UUID; the
  exposure recorded for THREAT_MODEL §1.1.

## 7. The background service

### N8: launchd agent, systemd user unit, logon task

**macOS** (launchd agent with the helper app). Stop the hand-started test
node first (`kill "$(cat "$T/node.pid")"`). The agent gets its own label,
never `com.raven.raven-node`, and finds the debug helper through
`RAVEN_NEARBY_HELPER`:

```bash
cat >"$HOME/Library/LaunchAgents/org.raven.nearby-test.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.raven.nearby-test</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN/raven-node</string>
    <string>service</string>
    <string>--data-dir</string><string>$T</string>
    <string>--lan-listen</string><string>0.0.0.0:7440</string>
    <string>--ble-listen</string><string>127.0.0.1:0</string>
    <string>--timeout-secs</string><string>0</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$T/node.log</string>
  <key>StandardErrorPath</key><string>$T/node.err</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RAVEN_IDENTITY_BACKEND</key><string>locked-file</string>
    <key>RAVEN_SESSION_BACKEND</key><string>locked-file</string>
    <key>RAVEN_PREKEY_BACKEND</key><string>locked-file</string>
    <key>RAVEN_CHAT_HISTORY_BACKEND</key><string>locked-file</string>
    <key>RAVEN_ALLOW_EPHEMERAL_DATA_DIR</key><string>1</string>
    <key>RAVEN_LAB_TEST_A</key><string>1</string>
    <key>RAVEN_LAB_NEARBY</key><string>1</string>
    <key>RAVEN_NEARBY_HELPER</key><string>$BIN/RavenNearby.app</string>
  </dict>
</dict>
</plist>
EOF
plutil -lint "$HOME/Library/LaunchAgents/org.raven.nearby-test.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/org.raven.nearby-test.plist"
r ipc-ping
```

(`$BIN` and `$T` must hold no `&`, `<` or `>`.) Record:

- the Bluetooth prompt: which app it names; what System Settings > Privacy &
  Security > Bluetooth lists afterwards; and the TCC log of the decision:
  `log show --last 15m --style compact --predicate 'subsystem == "com.apple.TCC"' | grep -i -E 'bluetooth|raven'`;
- any `SIGABRT` line in `$T/node.err` ("the nearby helper was stopped
  (SIGABRT)");
- 3 messages each way; then reboot, log in, and 3 more each way with no new
  prompt and nothing started by hand.

If the prompt names raven-node or the terminal app, or the helper is
stopped with SIGABRT, record it exactly: the fix (starting the helper with
the responsibility for it disclaimed, or through LaunchServices) is a code
change that must land before any flip. To see the prompt again later:
`tccutil reset BluetoothAlways org.raven.nearby` (it resets Raven Nearby's
answer only). Remove the agent afterwards:
`launchctl bootout "gui/$(id -u)/org.raven.nearby-test"` and delete the
plist.

The installed layout (`~/Library/Application Support/Raven/RavenNearby.app`,
put there by `RAVEN_INSTALL_NEARBY_HELPER=1 bash scripts/install/macos_launchd.sh`)
is the release path; it waits for a build without the lab switches and so
for the flip. Its copy-and-sign step is tested by
`scripts/install/nearby_helper_selftest.sh`.

**Linux** (systemd user unit). Stop the hand-started node first. Paths
must hold no spaces:

```bash
mkdir -p "$HOME/.config/systemd/user"
cat >"$HOME/.config/systemd/user/raven-nearby-test.service" <<EOF
[Unit]
Description=Raven nearby test node (lab)

[Service]
Environment=RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file
Environment=RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file
Environment=RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 RAVEN_LAB_TEST_A=1 RAVEN_LAB_NEARBY=1
ExecStart=$BIN/raven-node service --data-dir $T --lan-listen 0.0.0.0:7440 --ble-listen 127.0.0.1:0 --timeout-secs 0
Restart=on-failure

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now raven-nearby-test.service
r ipc-ping
```

Record: the `bluetooth` row says `on` with the unit running as you (the
distribution's `org.bluez` policy allows the user; no root); the `address`
row with `Privacy = device` on and off; 3 each way; reboot (on a headless
machine `loginctl enable-linger "$USER"` first) and 3 more each way.
Remove: `systemctl --user disable --now raven-nearby-test.service` and
delete the file.

**Windows** (logon task). Stop the hand-started node first. The task runs a
small `.cmd` in the test home:

```powershell
@"
@echo off
set RAVEN_IDENTITY_BACKEND=locked-file
set RAVEN_SESSION_BACKEND=locked-file
set RAVEN_PREKEY_BACKEND=locked-file
set RAVEN_CHAT_HISTORY_BACKEND=locked-file
set RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
set RAVEN_LAB_TEST_A=1
set RAVEN_LAB_NEARBY=1
"$BIN\raven-node.exe" service --data-dir "$T" --lan-listen 0.0.0.0:7440 --ble-listen 127.0.0.1:0 --timeout-secs 0 >> "$T\node.log" 2>&1
"@ | Set-Content -Encoding ASCII (Join-Path $T "nearby-test.cmd")
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/d /c `"$(Join-Path $T 'nearby-test.cmd')`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
Register-ScheduledTask -TaskName RavenNearbyTest -Action $action -Trigger $trigger | Out-Null
Start-ScheduledTask -TaskName RavenNearbyTest
r ipc-ping
```

Record: the `bluetooth` row (`on`, or `on, central only` when Windows
refuses the GATT server to this unpackaged process: the node log says
"central only"); 3 each way; sign out and in again and 3 more each way.
Remove: `Unregister-ScheduledTask -TaskName RavenNearbyTest -Confirm:$false`.

Pass (each OS): delivery after a reboot or a new login with no user action;
on macOS the prompt names RavenNearby and no SIGABRT happens.

## 8. Interruptions and the mule

### N9: lid close, sleep and Bluetooth off mid-transfer

- During N6's 48 KB message: close A's lid for 2 minutes, then open it. The
  message arrives exactly once later, with no user action (a broken link is
  never resumed: the outbox sends the whole message again). Record the
  seconds to recovery.
- Bluetooth off on B in the middle of a transfer; B's `r nearby status`
  says off and how to fix it; on again after 1 minute: delivered once.
- On a Linux advertiser: Bluetooth off and on (`bluetoothctl power off`,
  `power on`); B finds it again (BlueZ registers the advert again).
- Battery (optional): an hour idle with `r nearby on @b --for 1h` against an
  hour with `r nearby disable`: macOS `pmset -g batt`, Linux
  `upower -i "$(upower -e | grep BAT | head -n 1)"`, Windows
  `powercfg /batteryreport`.
- Pass: every message exactly once, no restart, no user action.

### N10: mule A to C to B over nearby (custody lab)

Three laptops; every pair met once (section 2.4). C is the friend who holds
mail. Friend custody is gated too (`FRIEND_CUSTODY_PRODUCTION_ENABLED =
false`; the debug lab unlock opens it); its own record is
[`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md).

- C: `r node custody on --yes`. A: `r contact set-addr @b --custodian @c`.
  B: `r contact set-addr @a --custodian @c`.
- C advertises for whoever it holds mail for ("background mail", its own
  consent, owner decision OD-C8):

  ```bash
  r nearby background-mail on --yes
  r nearby enable
  ```

- `r nearby enable` on all three. B's Bluetooth off (or B out of range). A:
  `r nearby on @c --for 1h`, then `echo "N10 via C" | r send --contact @b`.
- Wait until C's `r node custody status` holds 1. A's Bluetooth off (or A
  leaves). B's on, near C: B receives it exactly once; B's node log has
  `custody: fetched messages=`.
- Pass: delivered once through C, with C's held and released counts.

## 9. Coexistence with Wi-Fi

### N11: carrier order

- Wi-Fi on, both laptops on the same network, the LAN addresses from 2.4
  saved. A: `send_n b N11 5`: each `carrier=lan_dial`.
- Wi-Fi off on both: `send_n b N11 5`: each `carrier=nearby_dial`.
- Wi-Fi on again: 5 more. While a Bluetooth link to B is still up it goes
  first (by design); once it has been idle for 30 s it closes and the LAN
  wins again. Record which carrier each message took.
- Pass: LAN while Wi-Fi is on and no Bluetooth link is up; Bluetooth when
  Wi-Fi is off; no message lost or doubled at a switch.

### N12: 2.4 GHz coexistence

- Both laptops on Wi-Fi (record the band; 2.4 GHz if the router lets you
  choose) with a large download running on A, and Bluetooth forced: the N6
  48 KB message three times with `--carrier nearby` added to the `send`.
- The same three times with Wi-Fi off.
- Record bytes/s for each; compare. A drop to less than half with Wi-Fi
  busy is worth a note in the waiver.

## 10. After the rows

- Stop every test node by its pid (`kill "$(cat "$T/node.pid")"`,
  `Stop-Process -Id $node.Id`), and remove the N8 agent, unit and task.
- Undo `Privacy = device` on Linux if you do not want it, and reset Raven
  Nearby's Bluetooth answer on macOS if you like
  (`tccutil reset BluetoothAlways org.raven.nearby`).
- The test homes hold unencrypted test keys: delete
  `~/raven-nearby-test` when the records are saved.

## 11. Verify items from the backend steps, by row

| Item | Row |
|---|---|
| macOS: discovery chain, MTU, write-without-response flow control | N1 |
| macOS: the advert's address is random (`apple::caps` says `Random`) | N7m |
| macOS: which process the Bluetooth permission belongs to under launchd; no SIGABRT | N8 |
| Linux: unprivileged READ_INFO (the privacy bit) | N2, N8 |
| Linux: the `org.bluez` D-Bus policy per distribution | N8 |
| Linux: WriteValue's `mtu` option; ATT 23 gives 20-byte frames and silence | N2 |
| Linux: the advert registered again after a power cycle | N9 |
| Linux: `Privacy = device` on and off | N2, N7l, N8 |
| Linux: a connect to an ID the device no longer advertises fails once (10 s gap) | N2 (across a quarter hour) |
| Windows: which address a GattServiceProvider advert uses | N7w |
| Every OS: the initiator address (InitA) of a central's CONNECT_IND is random; none from a public address | N7m, N7l, N7w |
| Windows: GattServiceProvider in an unpackaged logon-task process | N3, N8 |
| Windows: connectable but not discoverable puts nothing on the air; stop and start keeps a central's subscription | N7w, N3 |
| Windows: Write Commands arrive in order | N3, N6 |
| Windows: MaxNotificationSize and MaxPduSize at subscription | N3 |
| Windows: uncached GATT lookups against a peer whose ID changes every 15 min | N3 |
| Windows: ConnectionStatusChanged after the peer leaves | N3, N5 |

Not a hardware row: the advisory CI job `nearby-btvirt` expects BlueZ's
emulator to report the Linux Foundation manufacturer id 0x05F1; if a
runner shows another, that job fails loudly without touching a radio.
