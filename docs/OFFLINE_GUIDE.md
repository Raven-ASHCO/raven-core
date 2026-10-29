# Talking without the Internet: two laptops, one local link

This guide sets up the link itself: two laptops on the same Wi-Fi or router
with no Internet, one laptop's hotspot, or a cable, on macOS, Linux and
Windows. Read the safety guide [SAFETY_OFFLINE.md](SAFETY_OFFLINE.md) first:
what Raven protects on such a network, what it does not, and how to stop it
on networks you don't trust.

Some of what Raven does on a local network is still held off in release
builds. Those parts are marked **when on in your build**, and section 6 lists
them. `raven lan status` (section 1) tells you what your build does.
`scripts/check_offline_guide.sh` checks every `raven` line below against the
build's `--help`, and every switch named in section 6 against the code.

## 0. Summary

- Raven needs only a shared IP link between the two laptops: the same Wi-Fi
  or router with no uplink (section 2), one laptop's hotspot or a Bluetooth
  network (section 3), or a cable (section 4).
- Raven over Bluetooth itself, Wi-Fi Direct and relaying through a third
  laptop do not work (section 8).
- A message written while you are apart waits until your secure connection
  with that friend ends: up to a day after it was set up (`raven contact
  list` says until when). **When on in your build**, Raven renews that
  connection while you are together, so a message written after a meeting
  can wait at least 12 h (10 h when only one of you can reach the other) and
  up to 24 h.

## 1. Once, before you go offline

**Start with `raven lan status`** while Raven runs:

```sh
raven lan status
```

The first row, `LAN:`, says how this computer uses the local network:

- `on - all networks of this computer, contacts only`: Raven listens on every
  network this computer joins, and only your contacts can connect. Nothing to
  change.
- `this computer only (127.0.0.1:7420)`: Raven listens on this computer only,
  so a friend next to you cannot reach you. See "This computer only" below.
- `off - raven lan on`: you turned the local network off. `raven lan on`
  turns it on again.
- `on` with nothing after it: Raven is not running here, so only the saved
  setting is shown. Start it (`raven listen`) and look again.

The `nearby search` row says whether Raven can find your friends on a new
network by itself, without an address typed:

- `on (answers only your contacts) ...`: nearby search runs (section 2 then
  needs nothing from you).
- `held in this build`: this build does not search. Type your friend's
  address once (below).
- `waiting for a local network`, `off while LAN is off`: it starts when there
  is a network and LAN is on.

**This computer only.** Unless you chose an address, the install scripts
start Raven's login service listening on this computer only while listening
on every network is held in your build (section 6). Install it again so that
it listens on your networks:

```sh
RAVEN_LAN_LISTEN=auto bash node/scripts/install/macos_launchd.sh       # macOS
RAVEN_LAN_LISTEN=auto bash node/scripts/install/linux_systemd_user.sh  # Linux
```

```powershell
.\node\scripts\install\windows_service.ps1 -LanListen auto
```

<!-- gate: LAN_AUTO_LISTEN_PRODUCTION_ENABLED=false: the paragraph below is its pre-flip form; replace it when the gate flips. -->
In this build `auto` means `0.0.0.0:7420` from any source (contacts only):
the installer says "this build holds auto". Raven still talks only to your
contacts, but anyone on the network can see that it listens. For one meeting
without installing again, run `raven listen` in a window and keep it open
(stop the login service first; `raven doctor` says how).

**Become contacts in person**, if you are not yet. One of you prints a card
line, the other adds it and reads the security words aloud to compare:

```sh
raven whoami --card
raven contact add --card '<card line>' --verify-fp '<security words>'
```

**While nearby search is held, type your friend's address once.** Ask them
for the address `raven listen` shows on their laptop (section 2 says how to
see your own):

```sh
raven contact set-addr --petname Bob --lan 192.168.1.31:7420
```

An IPv6 link-local address (`fe80::...`, always there on a cable) needs its
zone, the name of your network interface. On Windows the zone is the
interface's number (`ifIndex` in `Get-NetAdapter`):

```sh
raven contact set-addr --petname Bob --lan '[fe80::1%en5]:7420'   # macOS (Linux: %enp0s31f6)
raven contact set-addr --petname Bob --lan '[fe80::1%12]:7420'    # Windows
```

**On networks you do not trust** (a cafe, a hotel), turn the local network
off, and on again later. `raven lan on --for 1h` turns it on for a meeting
only:

```sh
raven lan off
raven lan on
raven lan on --for 1h
```

## 2. Same Wi-Fi or router, no Internet

A home router whose Internet is down still connects the laptops on it.

### When nearby search is on

Nothing to do when nearby search is on: Raven finds your friend on this
network and learns their address and port by itself, and waiting messages go
out.

### While nearby search is held

Type your friend's address once (section 1), as their `raven listen` shows
it. To see your own address:

```sh
ipconfig getifaddr en0                       # macOS (Wi-Fi is usually en0)
ip -br addr                                  # Linux
```

```powershell
Get-NetIPAddress -AddressFamily IPv4         # Windows
```

Guest and hotel Wi-Fi often keep devices apart, so friends cannot reach each
other there. Make a hotspot (section 3) or use a cable (section 4) instead.

## 3. One laptop makes a hotspot

The other laptop joins it. Use a long password. The hotspot laptop's address
is the one to type on the other side.

- **Linux** (NetworkManager 1.16 or later). The hotspot laptop gets
  10.42.0.1/24 by default. Check that the Wi-Fi card can host (`AP` in the
  list), start the hotspot, see its address, and stop it afterwards:

  ```sh
  iw list | grep -A10 'Supported interface modes' | grep -w AP
  nmcli device wifi hotspot ifname wlan0 ssid RavenLocal password '<long passphrase>'
  nmcli -f GENERAL.STATE,IP4.ADDRESS device show wlan0
  nmcli connection down Hotspot
  ```

- **Windows 10 and 11**: Settings > Network & internet > Mobile hotspot. The
  hotspot laptop gets 192.168.137.1. It may refuse to start without an
  Internet connection to share (UNVERIFIED: row R11d). On the hotspot laptop
  itself, the hotspot's network is unidentified, so Windows puts it in the
  Public profile: allow Raven there for the meeting with the temporary rules
  in section 5 (UNVERIFIED: row R11d+).
- **Linux with firewalld** (Fedora, for example): NetworkManager puts the
  hotspot's interface in the `nm-shared` firewall zone, which lets in only
  what a hotspot itself needs. Open port 7420 there for the meeting (it lasts
  until firewalld reloads or the laptop restarts; UNVERIFIED: row R11h):

  ```sh
  sudo firewall-cmd --zone=nm-shared --add-port=7420/tcp --add-port=7420/udp
  ```

- **macOS**: System Settings > General > Sharing > Internet Sharing. "Share
  your connection from" may need an interface even with no uplink. Whether it
  starts with no uplink is UNVERIFIED (row R11e); the hotspot laptop is
  usually 192.168.2.1.
- **A phone hotspot** works like a router if it keeps its clients connected
  without mobile data, and if it does not keep them apart (UNVERIFIED: row
  R11f). A phone hotspot may keep its clients apart, so friends cannot reach
  each other: use a laptop hotspot.

**A Bluetooth network instead of Wi-Fi** (Bluetooth PAN). Two laptops paired
over Bluetooth can share an ordinary IP network. Raven's local network
messages run over it unchanged, with typed addresses (section 1): it carries a
few hundred kB/s, enough for text. UNVERIFIED on every system (row R11i):

- **Windows**: Settings > Network & internet > Mobile hotspot, "Share over"
  Bluetooth; the other laptop joins it through its Bluetooth settings.
- **Linux**: BlueZ's network access point (NAP) through NetworkManager, on
  either side.
- **macOS**: not checked yet.

## 4. A cable

Ethernet, or USB-C and Thunderbolt adapters; any cable works (both sides
swap the wires themselves).

- Both sides give themselves a 169.254.x.x address once nobody hands one out
  (macOS and Windows do it by themselves, which can take up to a minute).
  An IPv6 `fe80::` address is always there; typed, it needs its zone
  (section 1).
- **Mac to Mac**: Thunderbolt Bridge.

  ```sh
  networksetup -getinfo "Thunderbolt Bridge"
  ```

- **Linux**: a link-local connection on the cable's interface:

  ```sh
  nmcli connection add type ethernet ifname <if> con-name raven-cable ipv4.method link-local ipv6.method link-local
  nmcli connection up raven-cable
  ip -br addr show <if>
  ```

- **Windows**: automatic. The network shows as "Unidentified network" in the
  Public profile: see section 5 for the firewall.

  ```powershell
  Get-NetIPAddress -InterfaceAlias Ethernet
  ```

**After you plug in.** Raven's network watch does not notice a link that has
only link-local addresses (169.254.x.x, `fe80::`), so waiting messages do
not go out at once:

- **when on in your build**, nearby search checks the interfaces every 15-60
  s, notices the cable, and finds your friend on it;
- otherwise try waiting messages again yourself (Raven also retries them by
  itself, at most 10 minutes apart):

  ```sh
  raven outbox list
  raven outbox retry <id>
  ```

## 5. Firewalls on a local-only link

- **macOS**. See whether the firewall is on; when it is, allow raven-node
  (installed in `~/.local/bin` by the install script). Allow the "Local
  Network" prompt for raven-node if macOS shows it.

  ```sh
  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ~/.local/bin/raven-node
  sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ~/.local/bin/raven-node
  ```

- **Linux with ufw**. Allow port 7420, TCP for messages and UDP for nearby
  search, from the cable and hotspot ranges only:

  ```sh
  sudo ufw allow from 169.254.0.0/16 to any port 7420 proto tcp
  sudo ufw allow from 169.254.0.0/16 to any port 7420 proto udp
  sudo ufw allow from 10.42.0.0/24 to any port 7420 proto tcp
  sudo ufw allow from 10.42.0.0/24 to any port 7420 proto udp
  sudo ufw allow from fe80::/10 to any port 7420 proto tcp
  sudo ufw allow from fe80::/10 to any port 7420 proto udp
  ```

- **Linux with firewalld**: see the hotspot in section 3 (zone `nm-shared`).
- **Windows**, in an elevated PowerShell. A cable, or a hotspot with no
  Internet (on the hotspot laptop too), shows as "Unidentified network", and
  Windows puts it in the Public profile. For the meeting only, allow TCP and
  UDP 7420 from the networks this laptop is on (`LocalSubnet`), then remove
  both rules:

  ```powershell
  Get-NetConnectionProfile
  New-NetFirewallRule -DisplayName "Raven LAN (local link)" -Direction Inbound -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol TCP -LocalPort 7420 -Profile Public -RemoteAddress LocalSubnet
  New-NetFirewallRule -DisplayName "Raven LAN search (local link)" -Direction Inbound -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol UDP -LocalPort 7420 -Profile Public -RemoteAddress LocalSubnet
  Remove-NetFirewallRule -DisplayName "Raven LAN (local link)"
  Remove-NetFirewallRule -DisplayName "Raven LAN search (local link)"
  ```

  **Why this differs from the installer's rules.** The installer prints two
  lasting rules for the Private profile ("Raven LAN", TCP 7420, and "Raven LAN
  search", UDP 7420): for your home network, which you marked private. They
  do not apply to a Public network. A lasting Public rule would open Raven on
  every cafe and hotel network too, so the rules here are for one meeting,
  limited to the local subnet, and removed afterwards.

## 6. What Raven does in each case

| Case | Your address | How Raven finds your friend | Waiting messages | Limits |
|---|---|---|---|---|
| Same Wi-Fi or router, no Internet | from the router (192.168.x.x, 10.x.x.x) | nearby search when on in your build, else the address you typed | go out when the network changes, or at the next retry | guest Wi-Fi may keep devices apart |
| Laptop hotspot | from the hotspot (10.42.0.x on Linux, 192.168.137.x on Windows, 192.168.2.x on macOS) | the same | the same | the hotspot may not start without Internet (rows R11d, R11e) |
| Cable | 169.254.x.x and `fe80::` | the same; a typed `fe80::` address needs its zone | at the next retry, or `raven outbox retry` (section 4) | Windows: Public profile (section 5) |
| Bluetooth PAN | from the laptop that shares the network | the address you typed | the same | a few hundred kB/s; UNVERIFIED (row R11i) |

What each part does, **when on in your build**:

| Part | What it does | In this build |
|---|---|---|
| Messages over a local network with typed addresses <!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true --> | Contacts reach each other at the address saved for them. A contact you did not verify is dialled only at a local-network address (10/8, 172.16/12, 192.168/16, 169.254/16, `fe80::/10`); `raven lan verified-only on` leaves them out entirely | on |
| Listen on every network <!-- gate: LAN_AUTO_LISTEN_PRODUCTION_ENABLED=false --> | `auto` listens on every interface, IPv4 and IPv6, and lets in local sources only | held: `auto` is `0.0.0.0:7420` (section 1) |
| Network watch | Notices a new network (Wi-Fi, a hotspot, a router) and tries waiting messages at once. Not a link with only link-local addresses | on |
| Network watch on a cable alone <!-- gate: OFFLINE_LAN_PRODUCTION_ENABLED=false --> | Counts a 169.254.x.x address as a network when nothing else is there, so a cable is noticed at once | held |
| Nearby search <!-- gate: LAN_BEACON_PRODUCTION_ENABLED=false --> | Asks the network for your contacts with a token that changes, with no Raven marker, and learns a friend's address and port, the IPv6 zone too | held |
| Route memory | After the Internet or p2p failed on this network, starts with the route that worked; LAN stays first on a network where it works | test builds only |
| Session renewal <!-- gate: SESSION_RENEWAL_PRODUCTION_ENABLED=false --> | Renews your secure connection with a friend while you are together, so messages written after the meeting wait at least 12 h | held |
| Friends who hold mail <!-- gate: FRIEND_CUSTODY_PRODUCTION_ENABLED=true --> | A friend's laptop on the same link holds sealed messages for a contact who is away, until they come back | on (October 2026), after a yes on both sides ([`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) section 9) |

Internet and p2p routes, where your build has them, fail at once on a link
with no uplink, and may take up to 45 s to time out on a hotspot whose
default route goes nowhere; LAN routes are planned first.

**Learning, when on in your build** <!-- gate: LEARNING_PRODUCTION_ENABLED=false -->
(held in this build): Raven tries first, for each friend on each network,
the way that reached them there before, waits less on a way that stopped
answering, and, when friends hold your mail, leaves it with the ones you
meet most. It only orders the
routes and the mail friends you already have: it does not find an address,
so on a new network you still type your friend's address (or nearby search
finds it, when on). Nothing it learns leaves this laptop. `raven learning
status` explains, one line per friend, why a way goes first; `raven
learning reset` forgets what was learned (`--contact NAME` for one friend),
and `raven learning off` stops it.

## 7. Check that it works

```sh
raven status
raven doctor
raven send --contact Bob
raven outbox list
ping -c 3 192.168.1.31        # macOS and Linux (Windows: ping -n 3)
```

`raven send` reads the message from what you type after it; finish with
Ctrl-D (on Windows: Ctrl-Z, then Enter). It ends with `status delivered`
when your friend's laptop confirmed it.

## 8. Not supported

- Raven over Bluetooth itself on Windows and Linux (`raven nearby` is in
  release builds on macOS only, since October 2026)
  <!-- gate: NEARBY_PRODUCTION_ENABLED=macos --> and Wi-Fi Direct. A
  Bluetooth network (PAN, section 3) is an ordinary IP link, not Raven over
  Bluetooth. How Raven over Bluetooth works: [`NEARBY.md`](NEARBY.md).
- Relaying a message through a third laptop.
- More than 7 days apart without meeting: a message stops trying 7 days
  after you wrote it <!-- gate: LONG_HORIZON_PRODUCTION_ENABLED=true --> (before
  October 2026: when your secure connection with that friend ended, a day).

## 9. Verification status

| Command | Verified on | How |
|---|---|---|
| Every `raven ...` line in this guide | the debug build on Linux, macOS and Windows | `scripts/check_offline_guide.sh` in CI: the command exists and takes every option on the line |
| `networksetup -listallhardwareports`, `networksetup -getinfo "Thunderbolt Bridge"`, `ipconfig getifaddr en0`, `ipconfig getiflist`, `route -n get default`, `socketfilterfw --getglobalstate` | macOS 26 (2026-10-22), and the macOS CI runner | run read-only while writing this guide; the CI check runs `networksetup -listallhardwareports`, `ipconfig getiflist`, `route -n get default` and `socketfilterfw --getglobalstate` |
| `ip -br addr`, `ip -6 addr show scope link` | the Ubuntu CI runner | run read-only by the CI check |
| `Get-NetIPAddress`, `Get-NetAdapter`, `Get-NetConnectionProfile`, `New-NetFirewallRule`, `Remove-NetFirewallRule` | the Windows CI runner | the CI check finds every cmdlet and runs `Get-NetIPAddress` read-only; the firewall rules are never added there |
| `socketfilterfw --add` / `--unblockapp`, `ufw allow`, `firewall-cmd --add-port` | not run | they change the firewall: owner rows (`firewall-cmd`: R11h) |
| Router with the Internet unplugged | not yet | owner row R11a |
| `nmcli` hotspot | not yet | owner row R11b |
| Cable: Thunderbolt Bridge, `nmcli` link-local, Windows automatic address | not yet | owner row R11c |
| Windows Mobile hotspot without Internet | not yet | owner row R11d (UNVERIFIED) |
| macOS Internet Sharing without uplink | not yet | owner row R11e (UNVERIFIED) |
| Phone hotspot without mobile data | not yet | owner row R11f (UNVERIFIED) |
| Windows Mobile hotspot host in the Public profile | not yet | owner row R11d+ (UNVERIFIED) |
| Linux `nmcli` hotspot with firewalld (`nm-shared`) | not yet | owner row R11h (UNVERIFIED) |
| Bluetooth PAN, Windows and Linux (macOS if possible) | not yet | owner row R11i (UNVERIFIED) |
