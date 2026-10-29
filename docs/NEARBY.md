# Bluetooth nearby: messages between laptops with no network

> **Not in this version.** Bluetooth nearby is held in every build
> (`NEARBY_PRODUCTION_ENABLED = false`) <!-- gate: NEARBY_PRODUCTION_ENABLED=false -->
> until the owner signs [`WAIVER_NEARBY_DRAFT.md`](WAIVER_NEARBY_DRAFT.md)
> after the hardware rows in
> [`PHYSICAL_NEARBY_LAPTOPS.md`](PHYSICAL_NEARBY_LAPTOPS.md). Until then
> `raven nearby status` says "held in this build" and every other `raven
> nearby` command changes nothing. This guide says how it works once it is
> released, and how developers try it today (section 9).

Bluetooth nearby lets two laptops (macOS, Linux, Windows) exchange Raven
messages over Bluetooth LE when there is no Wi-Fi, cable, hotspot or
Internet between them. It is one more way for a message to travel, like the
local network: the message is the same end-to-end encrypted object, and the
receipt comes back the same way. The specification is
[`RAVEN_NEARBY_LINK_V1.md`](../protocol/RAVEN_NEARBY_LINK_V1.md) (RNL1).

It is **not**:

- the phone mesh of the older iOS app (that is
  [`PHYSICAL_BLE_THREE_DEVICE.md`](PHYSICAL_BLE_THREE_DEVICE.md), a separate
  legacy profile);
- a Bluetooth network between two computers (Bluetooth PAN): that is an
  ordinary IP link, see [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) section 3;
- Bluetooth pairing: Raven never pairs or bonds devices and never trusts a
  pairing.

## 1. Who can reach you

Only your **verified** contacts, one hop, in radio range (a room or two;
the exact range is measured by row N5). For a contact to be found:

- you verified them (compared the security words): `raven contact verify
  @bob`;
- your two computers have linked at least once before, over any carrier
  (the local network, Internet direct or p2p). That link leaves each side
  the other's device certificate, from which the Bluetooth keys come. A
  contact added from a card who never linked with you cannot be found over
  Bluetooth, and first contact over Bluetooth does not exist;
- the contact is not blocked or revoked;
- both clocks are within about 15 minutes of each other (the Bluetooth IDs
  change every 15 minutes, and a computer further off in time finds nobody,
  silently);
- raven-node runs on both (`raven listen`, or the login service), and both
  have Bluetooth on.

## 2. Turn it on, once

```bash
raven nearby enable
raven nearby status
```

The first `enable` says once what nearby devices can see (section 4),
including this computer's Bluetooth name as a device that connects reads
it. Then raven-node:

- **listens** (passive Bluetooth scan) for your verified contacts;
- **connects** to a contact it hears advertising for it, also with nothing
  to send (that contact has something for you), and only from a random
  Bluetooth address (sections 6 and 7);
- **advertises** a random-looking ID that only one contact can recognise,
  and only while you have something to send to that contact: a send or an
  open chat makes the contact "foreground" for 15 minutes while messages
  wait. At most one ID is on the air at a time, and at most two contacts
  take turns.

Advertising for one contact on purpose (for a meeting), and stopping it:

```bash
raven nearby on @bob --for 30m
raven nearby off @bob
raven nearby off
```

Turning nearby off again (raven-node stops all Bluetooth work):

```bash
raven nearby disable
```

Sending needs nothing new. `auto` tries the local network first and
Bluetooth last, unless a Bluetooth link to that contact is already up; then
it goes first. To send over Bluetooth only:

```bash
raven send --contact @bob --carrier nearby
```

A message that cannot go yet waits in `raven outbox` and raven-node tries
again; `raven outbox status <id>` says `carrier nearby_dial` once it went
over Bluetooth, and `raven status` says the last delivery went over
Bluetooth nearby.

**Background mail** (advertising for every contact you have mail waiting
for, or keep mail for as their mail friend, not only for the ones you just
wrote to; cutoff addendum F11d) is off until you turn it on with its own
consent (owner decision OD-C8, 2026-10-28):

```bash
raven nearby background-mail on      # says what nearby devices can then see; asks first
raven nearby background-mail status
raven nearby background-mail off
```

While it is on and such mail waits, nearby devices can see a random
Bluetooth ID (changing every 15 minutes, at most two contacts at a time)
without any send of yours: they cannot tell whom it is for, but they can see
that this computer advertises, and so that it keeps or waits with mail for
someone, and for how long. Bluetooth also keeps scanning (more battery on a
laptop). It needs nearby itself on and never turns it on. Off a terminal,
`on` needs `--yes` (exit 2 without it), as `raven node custody on` does.
`raven nearby status` shows a `background` row while it is on, and `raven
doctor`'s `nearby:` line ends `background_mail=yes|no`.

**Friends who keep mail** (friend custody, held in this build as well,
[`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md)): when a
Bluetooth link to such a friend comes up, raven-node asks it at once for
the mail it keeps for you, leaves with it what waits for the contacts that
use it as their mail friend, and hands it what you keep for it to carry on;
at most once every 5 minutes per friend.

## 3. What `raven nearby status` and `raven doctor` show

| Row | Values |
|---|---|
| `nearby` | held in this build; off; on (verified contacts only); raven-node not running |
| `bluetooth` | on; on, central only (this computer can only connect to contacts that advertise); off; not allowed (permission, section 5-7); no Bluetooth LE; no Bluetooth support in this build of raven-node; the RavenNearby helper is missing, outdated or did not run (section 5); the Bluetooth service is not running (section 6); Raven's own state is not ready (section 8) |
| `address` | random, changing; or nearby inactive because the adapter would use a fixed public address: this computer then neither advertises nor connects (Linux, section 6; Windows, section 7) |
| `in range` | contacts in range now, connections up, and how many contacts this computer advertises for |
| `background` | shown only while background mail is on (OD-C8, section 2): it also advertises for the contacts it keeps or has mail for |

`raven doctor` prints one `nearby:` line with the same facts as keys
(`radio=`, `roles=`, `address=`, `advertising=`, `rotating=`, `in_range=`,
`pipes=`, `knock_silenced=`, `background_mail=`; `knock_silenced` counts
connection attempts this computer stayed silent to) and a `nearby_fix:` line
when something needs you. No row ever names a contact key, a Bluetooth ID,
an address or a device name.

A raven-node with the radio's fixed public address on the air (Windows
today, Linux without `Privacy = device`) carries nothing over nearby, so it
plans no nearby route and its custody offer does not count nearby either
(offline mesh carry research, Phase 0).

**Lab only (debug builds): Bluetooth only for Raven.** For the field test's
Bluetooth-only computer, `RAVEN_LAB_NEARBY_ONLY=1` (with
`RAVEN_LAB_TEST_A=1`, set for both raven-node and `raven`) closes LAN, the LAN
beacon, Internet direct and p2p (and with it the relay, port mapping and
WSS) in that process, without touching the computer's network. raven-node
logs `raven-node: lab nearby-only (RAVEN_LAB_NEARBY_ONLY=1): ...` once at
its start and binds no LAN port; `raven doctor` prints `nearby_only: on`;
the custody lines of its log name the carrier (`left N with a friend
(nearby_dial)`, `fetched ... (nearby_dial)`). A release build never reads
it.

## 4. What other people can see

| Who | What they can learn |
|---|---|
| Anyone in radio range with a Bluetooth scanner | That a computer advertises one random-looking ID, which changes every 15 minutes, only while its user is sending to a nearby contact (with background mail on, also while mail waits for a contact or is kept for one, section 2); its random Bluetooth address, how often it advertises, the signal strength, and the sizes and timing of the encrypted exchange. When this computer connects to a contact that advertises for it (also with nothing to send), a radio sniffer sees the connection come from this computer's random address. Sightings within one 15-minute period can be linked, and so can sightings across an address change that does not fall at the same moment as an ID change. |
| Someone who recorded a contact's Bluetooth ID | The ID is a random-looking UUID anyone in range can copy. Played back near this computer within about 30 minutes of when the contact advertised it, it makes this computer connect (from its random address) as if the contact were there, at most twice per recorded ID: so the person who played it back learns that the computer the contact had something for is in range. Nothing else: no name, key, address book entry or message, and after two tries this computer ignores that ID. |
| A device that connects to this computer | What the operating system itself shows to any connecting device: this computer's **Bluetooth name** (usually the computer's name) and, on macOS, its **model**. It also sees that there is one service with one characteristic. It gets no answer from Raven unless it is the contact the service is for. On Linux it can subscribe and see the encrypted traffic of that one contact's link while it is up (its sizes and timing, never its content). |
| Your contact | That you are in range, and when. |

No Raven identity, fingerprint, address, PeerId or Raven marker is ever
advertised, and a stranger never learns your Raven key (the knock comes
before any Raven handshake). The full table is in
[`THREAT_MODEL.md`](THREAT_MODEL.md) (section 1.1) and in RNL1 §9.

What you can do:

- If your computer's name is your own name, rename it before you enable
  nearby: macOS System Settings > General > About > Name; Windows Settings >
  System > About > Rename this PC; Linux `hostnamectl set-hostname --pretty
  "<name>"` (or `Name =` in `/etc/bluetooth/main.conf`).
- `raven nearby disable` (or Bluetooth off) where you do not want to be
  seen sending.
- Nearby is for verified contacts only; there is no setting that admits
  others.

## 5. macOS: the RavenNearby helper and the Bluetooth permission

macOS gives Bluetooth only to an app that says why it needs it. The radio
therefore runs in a small helper app, **RavenNearby.app** (`org.raven.nearby`),
which raven-node starts and talks to over a private pipe. The helper holds
no keys: it sees the random IDs and encrypted frames, nothing else.
raven-node itself never uses CoreBluetooth and is never re-signed for it,
so its code signature, and with it the Keychain access you allowed, stays
as it is.

**Install the helper** with the login service (from `node/`):

```bash
RAVEN_INSTALL_NEARBY_HELPER=1 bash scripts/install/macos_launchd.sh
```

This builds raven-node with Bluetooth support (feature `nearby-radio`),
builds RavenNearby.app, signs it ad hoc and copies it to
`~/Library/Application Support/Raven/RavenNearby.app`. It does not turn
nearby on. Variants:

- `RAVEN_INSTALL_NEARBY_ONLY=1`: the helper alone, next to a raven-node you
  installed before (nothing else is built, written or started);
- `RAVEN_NEARBY_SIGN="Developer ID Application: <name> (<team>)"`: sign it
  with your Developer ID (hardened runtime) instead of ad hoc;
- `RAVEN_NEARBY_APP=<path>/RavenNearby.app`: install a bundle built before
  (`bash scripts/build_nearby_helper_app.sh <dir>`), and with
  `RAVEN_NEARBY_SIGN=keep` keep its signature (a notarized bundle).

Every run checks the bundle's signature, runs `raven-nearby-helper --check`
(it reads its usage description and touches no Bluetooth), and checks that
raven-node's code signature is the same before and after
(`scripts/install/nearby_helper_selftest.sh` tests this).

**Where raven-node looks for the helper**, in this order:
`RAVEN_NEARBY_HELPER` (an absolute path to the helper or its .app; nothing
else is tried when it is set), `RavenNearby.app` next to the raven-node
executable, then `~/Library/Application Support/Raven/RavenNearby.app`.
When none is there, or the one found belongs to another release or stops,
the `bluetooth` row says the RavenNearby helper is missing, outdated or did
not run: install it as above, then restart raven-node.

**Allow Bluetooth.** The first time the radio starts (after `raven nearby
enable`), macOS asks whether RavenNearby may use Bluetooth: allow it. If
you said no, or the row says `not allowed`: System Settings > Privacy &
Security > Bluetooth, turn RavenNearby on, then restart raven-node
(`launchctl kickstart -k gui/$(id -u)/com.raven.raven-node` for the login
service, or stop and start `raven listen`). Which program macOS lists there
for a raven-node started by launchd is still being verified (row N8): if it
lists raven-node or your terminal app instead of RavenNearby, allow that
entry and note it for the row.

When macOS refuses, it stops the helper (SIGABRT) and nothing else:
raven-node reports `not allowed` and tries again after 1 minute, then
2, 4 and so on up to 1 hour, so you get no crash report every few seconds.

macOS advertises from a random private address that changes on its own
(row N7 confirms this on hardware).

## 6. Linux: BlueZ, its access policy and `Privacy = device`

raven-node talks to BlueZ (`bluetoothd`) over the system D-Bus. Builds for
glibc Linux with feature `nearby-radio` have it; static (musl) builds say
"no Bluetooth support in this build of raven-node".

- **Access.** The user service (`node/scripts/install/linux_systemd_user.sh`)
  runs as you, not as root. Desktop distributions allow the logged-in user
  to use `org.bluez` on the system bus by default; on others the
  distribution's D-Bus policy for `org.bluez` decides (often membership of
  a `bluetooth` group). When it refuses, the `bluetooth` row says
  `not allowed`. Never run raven-node as root for this.
- **Private address.** Raven advertises only from a private (random)
  Bluetooth address. BlueZ uses the adapter's fixed public address unless
  an administrator sets, in `/etc/bluetooth/main.conf`:

  ```ini
  [General]
  Privacy = device
  ```

  and restarts Bluetooth (`sudo systemctl restart bluetooth`). Without it
  the `address` row says "nearby inactive ... set Privacy = device": this
  computer then neither advertises nor connects, because a connection
  carries the address it comes from in the clear just as an advert does.
  Raven reads the setting through the kernel's Bluetooth management
  interface, without root (row N8 checks that each distribution allows
  this; when it cannot be read, Raven assumes the public address and stays
  inactive).
- **BlueZ must run.** When `bluetoothd` is stopped or disabled the
  `bluetooth` row says the Bluetooth service is not running: `sudo
  systemctl enable --now bluetooth`. raven-node tries again by itself every
  30 seconds.
- **Disclosed limitation.** BlueZ sends a notification to every device
  subscribed to a service, so a stranger that connects and subscribes to the
  service for one contact sees that link's encrypted traffic (sizes and
  timing, never content). macOS and Windows send to the one contact only.
- BlueZ remembers every ID a device ever advertised, so a connection to an
  ID that has since changed fails once and is retried after 10 seconds.
- The adapter must be powered (`bluetoothctl show` says `Powered: yes`).

## 7. Windows: the peripheral role and the logon task

raven-node uses WinRT Bluetooth in your user session; the logon task that
`node/scripts/install/windows_service.ps1` registers runs it there (a
Windows service is not supported for nearby).

- **Can this PC advertise?** `raven nearby status`: `bluetooth on` means
  both roles; `on, central only` means the adapter (or Windows, for a
  program that is not a packaged app) does not offer the peripheral role.
  A central-only PC reaches contacts that advertise for it, and both
  directions then use that link; two central-only PCs can never reach each
  other.
- **This build does not use Bluetooth from Windows yet.** Windows does not
  say which address its adverts or its connections go out from, so Raven
  treats both as the PC's fixed public address: a Windows PC neither
  advertises nor connects (the `address` row says nearby is inactive) until
  row N7w shows that Windows uses a random address. Lab runs can try it
  anyway with `RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR=1` (debug builds only);
  a Windows PC then reaches a Mac, or a Linux laptop with `Privacy = device`,
  that advertises for it (`raven nearby on @<the Windows contact> --for 1h`
  on that computer when it has nothing to send itself).
- `not allowed` means Windows refused Bluetooth to raven-node: check the
  Bluetooth and radio entries under Settings > Privacy & security (their
  names differ between Windows versions).

## 8. When nothing arrives

| What you see | Why | What to do |
|---|---|---|
| `held in this build` | the build holds nearby | nothing: this version cannot use it |
| `raven-node is not running` | no raven-node | `raven listen`, or start the login service |
| `no Bluetooth support in this build of raven-node` | built without feature `nearby-radio` (or a static Linux build) | install with Bluetooth support (section 5 on macOS) |
| `the RavenNearby helper is missing, outdated or did not run` (macOS) | RavenNearby.app is not installed, belongs to another release, or stopped | `RAVEN_INSTALL_NEARBY_HELPER=1 bash scripts/install/macos_launchd.sh`, then restart raven-node (section 5) |
| `the Bluetooth service is not running` (Linux) | `bluetoothd` is stopped or disabled, or there is no system D-Bus | `sudo systemctl enable --now bluetooth`; raven-node tries again by itself (section 6) |
| `Raven's own state is not ready` | this profile's identity, sessions or disk space are not ready, so nearby did not start | the other lines of `raven doctor`; raven-node tries again by itself |
| `no Bluetooth LE on this computer` | no Bluetooth adapter, or one without Bluetooth LE | a computer (or USB adapter) with Bluetooth LE |
| `nearby inactive` (the `address` row) | the adapter would use its fixed public address (Linux without `Privacy = device`; Windows in this build) | section 6 (Linux); section 7 (Windows) |
| `not allowed` | the operating system refused Bluetooth | sections 5-7 |
| `off` | Bluetooth is off | turn it on |
| `0 contacts in range` for a while | not verified; never linked before; clocks more than 15 minutes apart; out of range; neither side advertises (nothing waiting and no `nearby on`); both sides central-only | check each; `raven nearby on @bob --for 30m` on the side that can advertise |
| a contact in range is not connected to for up to 15 minutes | this computer's last two connections to the ID it advertises failed (a weak link, or someone played that ID back elsewhere), so it waits for the contact's next ID | wait for the next quarter hour, or `raven nearby on @bob` so the contact connects to you |
| a message waits although the contact is in range | the link broke mid-message (Raven never resends half a message: the next try sends it whole) | wait for the next try, or `raven outbox retry <id>` |
| `NEARBY_BUSY` in `raven outbox status` | the contact is in range, but every nearby link is in use: a computer keeps at most 4 at once, and this one or the contact's has 4 (or is still setting them up) | nothing: raven-node tries again by itself, and a link that carries nothing for 30 seconds ends |

A Bluetooth link whose packets are too small (an adapter that negotiates
fewer than 64 bytes) stays silent on purpose; such adapters are rare.

## 9. Developers: trying it today

Lab builds only: a debug build with Bluetooth support and both lab
switches, in a test profile, never `~/.raven` or a profile you use
(a build of this tree seals a profile at its first start; a debug build only
with `RAVEN_LAB_AT_REST=1`). From `node/`:

```bash
cargo build --locked -p ash -p raven-node --features raven-node/nearby-radio
bash scripts/build_nearby_helper_app.sh "${CARGO_TARGET_DIR:-target}/debug" --debug   # macOS only
export RAVEN_LAB_TEST_A=1 RAVEN_LAB_NEARBY=1
```

The second line puts RavenNearby.app next to the debug raven-node, where it
is found first. Release builds read neither switch. The step-by-step
hardware rows, with test homes, are
[`PHYSICAL_NEARBY_LAPTOPS.md`](PHYSICAL_NEARBY_LAPTOPS.md). Without
hardware, `raven-node nearby-ether` (debug builds) is a fake Bluetooth
"air" on loopback that the carrier matrix (C50-C53, C56) and the fault
matrix (`RAVEN_FAULT_NEARBY=1`, s63-s67, s67b and s72-s74) use; no real radio is
opened there.

## 10. More

- Per-system notes and helpers: the `raven-mesh-macos`, `raven-mesh-linux` and
  `raven-mesh-windows` repositories. The carrier itself (all three radio
  backends and the macOS helper's source) lives here, in `raven-node`.
- Specification: [`RAVEN_NEARBY_LINK_V1.md`](../protocol/RAVEN_NEARBY_LINK_V1.md).
- Threat model: [`THREAT_MODEL.md`](THREAT_MODEL.md) section 1.1.
- Waiver draft (unsigned): [`WAIVER_NEARBY_DRAFT.md`](WAIVER_NEARBY_DRAFT.md).
- Hardware rows N1-N12: [`PHYSICAL_NEARBY_LAPTOPS.md`](PHYSICAL_NEARBY_LAPTOPS.md).
