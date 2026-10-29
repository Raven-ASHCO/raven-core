# Run a relay for your friends (relay kit)

One command per OS turns an always-on box (a Raspberry Pi at home, a small VPS,
an always-on Mac or PC) into a relay your friends use to reach each other when
neither can reach the other directly. It is `raven-node relay`, installed as a
service with the same settings on every OS:

| OS | One command | Runs as |
|---|---|---|
| Linux (Pi, VPS) | `RAVEN_RELAY_HOST=<public IP or DNS name> bash node/scripts/install/linux_relay.sh` | a hardened system unit, user `raven-relay` |
| macOS | `RAVEN_RELAY_HOST=<public IP or DNS name> bash node/scripts/install/macos_relay.sh` | a launchd agent (or daemon), as you |
| Windows | `powershell -ExecutionPolicy Bypass -File node/scripts/install/windows_relay.ps1 -PublicHost <public IP or DNS name>` | a logon task, as you |

The scripts: [`linux_relay.sh`](../node/scripts/install/linux_relay.sh),
[`macos_relay.sh`](../node/scripts/install/macos_relay.sh),
[`windows_relay.ps1`](../node/scripts/install/windows_relay.ps1), the shared
[`relay_common.sh`](../node/scripts/install/relay_common.sh) and the
`raven-relay` command they install
([`raven-relay.sh`](../node/scripts/install/raven-relay.sh)).

## 0. Status

**P2P is on in release builds since October 2026.** `P2P_PRODUCTION_ENABLED`
is `true` (switched on after the three-machine field test, not independently
reviewed; the unsigned [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md)
and its Phase 2 amendment, which covers relays on TCP 443, the installers and
the Windows logon task, were not signed first), and a relay is part of P2P. So
the kit installs **release builds**. It still refuses a build that holds p2p
(exit 3): such a `raven-node relay` refuses to start (`P2P_HOLD`).
`RAVEN_RELAY_LAB=1` (`-Lab` on Windows) installs a debug build with the lab
unlock instead. A lab build is for tests, not for real use, and the installers
say so.

**WSS on 443 is still held.** The kit installs a raw libp2p listener on TCP 443.
A relay that also answers as HTTPS on that port (`raven-node relay --wss 443`,
for networks that let only web traffic or an HTTPS proxy out) needs
`WSS_PRODUCTION_ENABLED`, which waits for
[`WAIVER_WSS_PROXY_DRAFT.md`](WAIVER_WSS_PROXY_DRAFT.md); the kit's units move
from `--also-tcp 443` to `--wss 443` in the commit that flips it. Until then
`--wss` is lab-only (debug, `RAVEN_LAB_TEST_A=1 RAVEN_LAB_WSS=1`): the install
guides' "Be the relay for your friends" section shows it by hand.

## 1. What a relay does and does not do

A friend behind a NAT keeps a reservation on your relay. Another friend dials
them through it, and libp2p then tries to turn the relayed connection into a
direct one (hole punching). The relay passes encrypted bytes along: the Raven
link inside is end-to-end between your friends.

- It holds **no Raven identity**: no Raven ID, no keystore, no messages. Its
  only key is its own libp2p key (`relay_key.ed25519`, owner-only), so its
  PeerId is not yours.
- It relays only **between the PeerIds you allowed** (`relay_allow.json`),
  both ends of every circuit (consent by circle, section 6). Anyone else is
  refused right after the libp2p handshake. No list admits nobody; an
  unreadable one admits nobody too.
- Its logs carry **counts only** (reservations, circuits, refusals), never an
  address or a friend's PeerId. `raven-relay status` is for you: it lists the
  allow-list (each friend's PeerId and the label you gave it) and the relay's
  own PeerId and addresses, so replace those before you share its output.
- There are no project relays: no relay address is compiled into Raven, and
  the kit never runs an open relay (one that serves anyone).

What it learns (the same table as the waiver, section 14):

| The relay learns | It does not learn |
|---|---|
| Both PeerIds and IP addresses of every circuit, when it opens, how long it lasts and how many bytes pass; who keeps a reservation; with `--autonat-server`, the addresses it is asked to probe | Raven IDs (though you know which friend each PeerId you allowed belongs to, section 6; a lab card maps a PeerId to a Raven ID), message text, PairInit, RLB1 offers, route tags, message IDs |

## 2. Pick a box

- **A Raspberry Pi 4/5 at home** with a port forward on your router. Cheap and
  always on, but only if your router has a public address (the CGNAT check
  below).
- **A small VPS** (about EUR 5 a month, 1 vCPU, 1-2 GB RAM, a public IPv4).
  Works behind any home network, and port 443 is easy there.
- **An always-on Mac** (one that never sleeps).
- **A Windows PC**: a logon task only, so it relays while you are signed in and
  awake (design Q9). Fine for a test, poor as the only relay of a circle.

**CGNAT check.** Look at your router's WAN (Internet) address. If it is in
100.64.0.0/10 or a private range (10.x, 172.16-31.x, 192.168.x), your provider
puts you behind carrier NAT: no port forward can reach your box. Use a VPS.

## 3. A Pi with a port forward

1. A 64-bit Raspberry Pi OS (or Debian/Ubuntu). Give the Pi a fixed LAN
   address (a DHCP reservation on the router).
2. Get the code and a toolchain (or binaries built elsewhere, step 3):

   ```bash
   sudo apt-get update && sudo apt-get install -y build-essential pkg-config git
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.98.0
   . "$HOME/.cargo/env"
   git clone https://github.com/Raven-ASHCO/RAVEN.git raven && cd raven
   ```

3. Install. A build needs about 2 GB of RAM and takes a while on a Pi; with
   less, add swap, or build on another machine for aarch64 and point
   `RAVEN_RELAY_PREBUILT=<folder with raven-node and raven>` at the result.
   Your public IP (or a dynamic-DNS name for it) goes into the relay's `via=`
   lines (`raven-relay card`, section 7):

   ```bash
   RAVEN_RELAY_HOST=<your public IP or dynamic-DNS name> bash node/scripts/install/linux_relay.sh
   ```

   (A debug lab build instead: add `RAVEN_RELAY_LAB=1`; section 0.)
4. On the router, forward **TCP and UDP 7423** and **TCP 443** to the Pi. If
   the router's public 443 is free but a program on the Pi holds port 443,
   forward the router's 443 to the Pi's port 7443 instead and install with
   `RAVEN_RELAY_TCP443=7443`. If the router's 443 already goes to a web
   server (on the Pi or another box), install with `RAVEN_RELAY_TCP443=off`:
   friends then have no 443 fallback.
5. Test from outside your network: copy the `via=` lines of
   `sudo raven-relay card` to a laptop on a phone hotspot and run
   `raven-node relay-probe <via>...` there (`raven-relay probe <via>...` on a
   box with the kit; a lab build needs `RAVEN_LAB_TEST_A=1` in front). It dials
   each address with a throwaway key, reserves nothing, and prints one
   `tcp/7423: reachable ...` line per address (ports only). A `/tls/ws` line
   is probed over WSS, never through a proxy (`wss/443: ...`); while the WSS
   gate is closed it says `not probed: WSS_HOLD`.

## 4. A EUR 5 VPS

1. The same commands as the Pi (section 3, steps 2-3). With 1 GB of RAM, add
   2 GB of swap for the build, or build elsewhere and use
   `RAVEN_RELAY_PREBUILT`.
2. Open the ports in **both** the provider's firewall (security group) and the
   VPS's own:

   ```bash
   sudo ufw allow 7423/tcp && sudo ufw allow 7423/udp && sudo ufw allow 443/tcp
   ```

3. TCP 443 is direct: the unit holds `CAP_NET_BIND_SERVICE` and nothing else
   (no root). With a web server already on 443, use `RAVEN_RELAY_TCP443=off`
   (friends then have no 443 fallback). Two ways keep a fallback: a second
   public IP for the relay, with `RAVEN_RELAY_TCP443=7443` and an nftables
   redirect of that IP's 443 only (`ip daddr <second IP> tcp dport 443
   redirect to :7443`), or a protocol multiplexer in front of both. Never
   redirect the 443 your web server serves to 7443: every HTTPS visitor would
   reach the relay, and the website goes down. Without any redirect, the
   cards' 443 line reaches the web server and never works.

## 5. macOS and Windows

**macOS.** `bash node/scripts/install/macos_relay.sh` (with `RAVEN_RELAY_HOST`)
installs a launchd agent `com.raven.relay` running as you, with the relay folder
`~/.raven-relay` (the folder the install guides use for a relay run by hand, so
its PeerId is kept), binaries in `~/.local/lib/raven-relay` and `raven-relay` in
`~/.local/bin`. `RAVEN_RELAY_SYSTEM=1` writes a LaunchDaemon instead (sudo), so
the relay starts at boot without a login, still as you. A non-root process may
listen on TCP 443 on current macOS; if the check says the port needs a
privilege, use `RAVEN_RELAY_TCP443=7443` and map 443 to 7443 on the router. A
Mac that already runs Raven with p2p on 7423 needs another relay port:
`RAVEN_RELAY_PORT=7428`, forwarded the same way (7424/7425 are a second Raven
profile's, 7427 the friend relay's). A Mac that sleeps relays nothing: turn
automatic sleep off in System Settings (the kit does not).

**Windows.** `windows_relay.ps1` registers a per-user logon task with the same
Task Scheduler settings as the node's own task, the relay folder
`%LOCALAPPDATA%\RavenRelay` and `raven-relay.cmd` next to the binaries in
`%LOCALAPPDATA%\RavenRelayBin`. Parameters: `-PublicHost`, `-Port`,
`-Tcp443 direct|7443|off` (http.sys or IIS may already hold 443), `-NoAutonat`,
`-Prebuilt`, `-Lab`, `-Uninstall`, `-Rollback`. Details:
[`WINDOWS_SERVICE.md`](../node/scripts/install/WINDOWS_SERVICE.md).

## 6. Add your friends (consent by circle)

The relay serves a circuit only when **both** ends are on its allow-list. So
allow every friend who is reached through the relay **and** every friend who
sends through it.

1. Each friend sends you their network ID (PeerId): the one line
   `raven whoami --peer-id` prints. Get it from the friend directly (in
   person, by voice, or in a message you trust): nothing signs a PeerId, and
   one changed on its way would let someone else use your relay in your
   friend's place.
2. For each friend: `sudo raven-relay allow <PeerId>` (macOS and Windows: no
   sudo), with `--label <name>` if you want your own note in `raven-relay
   status`. `raven-relay` passes its `allow` arguments on to `raven relay
   allow`.
3. `--card '<card>'` and `--cards FILE` (one card per line, all or nothing:
   one bad line allows nobody) read only lab cards now, from a debug build
   with the lab unlock (`RAVEN_LAB_TEST_A=1`). A card from a release build
   carries no PeerId, and `raven-relay allow --card` then says `that card
   names no PeerId (a card carries no network ID in this raven): ask your
   friend for the line raven whoami --peer-id prints and allow that PeerId`.
   For a lab card it prints the card's fingerprint to compare with that
   friend, and on a terminal it asks once before allowing.
4. To stop: `sudo raven-relay deny <PeerId>`. A running relay drops them
   within seconds.

`raven-relay` runs these as the account the relay runs as (Linux:
`raven-relay`), so the allow-list stays readable by the relay. Never edit
`relay_allow.json` as root: a file the relay cannot read admits nobody.

A friend you allow can see when the other members are online (they can try a
circuit to them). Allow only people who already know each other.

**Friends whose network ID rotates** (Phase 4, lab-only while
`PEER_ROTATION_PRODUCTION_ENABLED` is false). A friend who turned on `raven
node p2p rotate on` gets a new PeerId every 28 days. Your relay is not their
contact and never hears their route hints, so they send you the line their
`raven relay schedule` prints (`raven-relay-schedule/1` and their PeerIds for
about the next 6 months), and you add it in one step:

```bash
sudo raven-relay allow --schedule 'raven-relay-schedule/1 ...'   # the whole line, quoted (macOS and Windows: no sudo)
```

Each PeerId is allowed until a week after its epoch ends (`raven-relay status`
shows `[for N more day(s)]` or `[expired]`), expired entries are dropped when
the next schedule is added, and pasting the same line twice changes nothing. A
friend you allowed by hand (a PeerId, or a lab card with `--card`) stays
allowed without an end. Ask for a
new line about every 6 months: until you add it, the relay refuses their new
PeerId at the next epoch, and when none of their relays accepts it their node
goes back to the previous one (`postponed`) and tries again later. Give the
line itself, or `-` and the line on standard input: the relay's own account
cannot read a file in your home.

## 7. How a contact adds your relay

1. You run `sudo raven-relay card`. It prints the relay's `via=` lines
   (TCP 7423, TCP 443, QUIC 7423) and, on stderr, the one line to give each
   friend: `raven relay use via=<TCP 7423> via=<TCP 443>`. That line never
   names a loopback or local-network address: a relay installed without
   `RAVEN_RELAY_HOST` that knows only those gives no line and asks for
   `sudo raven-relay card --host <public IP or DNS name>`. In
   `RAVEN_RELAY_TCP443=7443` mode the card names the public 443, which the
   router or nftables maps to 7443.
2. Each friend runs that line once, then restarts their node
   (`raven relay use` saves the relay like `raven node p2p on --relay ...`).
3. Nobody sends a new card: a card names no relay. Each friend's verified
   contacts learn your relay from that friend's route hints, inside their
   encrypted link, once they are connected (over Tor or the local network).
   Each friend sends you their network ID (`raven whoami --peer-id`), as
   `raven relay use` reminds them.
4. You allow every one of them (section 6).
5. Each friend checks `raven status`: the relay row says the reservation is
   held.

Why TCP 7423 and TCP 443: the two addresses of one relay are one reservation
with a fallback. On a network that lets only HTTPS out, the reservation moves
to the 443 address. `raven relay use` takes at most 2 lines, so the pair fills
it; route hints carry up to 4 addresses of at most 2 relays, which leaves room
for a second relay's pair. (A lab card: a `raven-card/2` carries at most 2
`via=` lines, a `raven-card/3` up to 4 addresses of at most 2 relays.)

## 8. Firewall notes

The kit never changes a firewall; each installer prints the rules.

- **Linux.** ufw: `sudo ufw allow 7423/tcp`, `7423/udp`, `443/tcp`. firewalld:
  `sudo firewall-cmd --permanent --add-port=7423/tcp --add-port=7423/udp
  --add-port=443/tcp && sudo firewall-cmd --reload`. nftables: allow inbound
  `tcp dport { 7423, 443 }` and `udp dport 7423`. A VPS: the provider's
  firewall too.
- **macOS.** The Application Firewall is off by default. If it is on:
  `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add <bin dir>/raven-node`
  and `--unblockapp` the same path (again after a rebuild).
- **Windows.** In an elevated PowerShell, the Private profile only, never
  Public: `New-NetFirewallRule` for TCP 7423 and 443 and UDP 7423, `-Program`
  the relay's `raven-node.exe` (the installer prints the exact lines).
- **Routers.** Forward TCP+UDP 7423 and TCP 443 (or 443 to 7443). Many routers
  do not "hairpin": a friend on your own home network may not reach the relay
  through your public address. That is a router limit, not a relay fault; test
  from outside (section 3, step 5).

## 9. Resource limits

The kit uses the friends-only defaults of `raven-node relay` (a relay you run
by hand can change them with its flags, each refused above its hard maximum):

| Limit | Default | Hard max | Flag |
|---|---:|---:|---|
| Reservations in total | 128 | 1024 | `--max-reservations` |
| Reservations per friend / per IP | 2 / 4 | 2 / 16 | - |
| Reservation lifetime | 30 min | 2 h | `--reservation-secs` |
| Circuits in total | 64 | 256 | `--max-circuits` |
| Circuits per friend (opened by them or to them) | 4 | 8 | - |
| Circuit lifetime | 5 min | 30 min | `--circuit-secs` |
| Bytes per circuit (both ways) | 2 MiB | 16 MiB | `--circuit-bytes` |
| Connections in total / per IP | 256 / 8 | 1024 / 32 | - |

The Linux unit also caps the process: `MemoryMax=256M`, `TasksMax=256`,
`LimitNOFILE=4096`; the macOS plist and the Windows task allow 4096 files.

**Bandwidth, worst case** (a guess, not a measurement): 64 circuits, each
carrying its full 2 MiB every 5 minutes, is about 3.6 Mbit/s, roughly 1.1 TB a
month if it never stops. A circle that sends text uses far less: most circuits
carry a few KiB before hole punching moves the friends to a direct connection.
On Linux, `IPAccounting` counts the bytes: `sudo raven-relay status` prints
`IPIngressBytes` and `IPEgressBytes`.

## 10. Logs and status

The logs carry counts only: never a friend's address or PeerId. The counts
line is written at most every 300 s, and only when a count changed
(`RAVEN_RELAY_COUNTS_EVERY`).

- `raven-relay status`: allow-list (each friend's PeerId and your label),
  state, the relay's own PeerId and listen addresses, counts; then the service
  manager's view (Linux: `ActiveState`, `NRestarts`, bytes in and out, memory;
  macOS: launchd state, runs, last exit code). Replace the PeerIds, labels and
  public IPs before you share it.
- `raven-relay logs`: Linux `journalctl -u raven-relay`; macOS the last lines
  of `~/.raven-relay/relay.log` (cut back to empty past 1 MiB, checked at every
  start too). Windows keeps no log (Task Scheduler drops stderr): `raven-relay
  status` is the view.
- A relay that cannot start for a lasting reason (exit 2 to 5, section 13):
  the Linux unit does not restart it after exits 2, 3 and 5; on macOS it waits
  5 minutes before it exits, so launchd starts it again at most every 5
  minutes. `raven-relay logs` says why.

## 11. Update, rollback, adopt

- **Update:** `git pull --ff-only`, then the same install command. `kit.conf`
  (next to the binaries) remembers every setting; the key and the allow-list
  are never touched. The new binary runs `raven-node relay --check` before
  anything is replaced (a held build, a busy port or a bad folder changes
  nothing and restarts the old relay), the old binaries stay as `.prev`, and
  after the restart the relay must report its ports and **the same PeerId**
  within 20 s, else the `.prev` binaries come back.
- **Rollback:** `RAVEN_RELAY_ROLLBACK=1` with the install command (Windows:
  `-Rollback`) swaps the `.prev` binaries back.
- **Adopt a relay you ran by hand:** `RAVEN_RELAY_ADOPT=<its folder>` (Linux
  and macOS) copies its `relay_key.ed25519` and `relay_allow.json` into the
  kit's folder when that folder has no key yet, so friends' `via=` lines keep
  working. Stop the hand-run relay first. On macOS and Windows the kit's
  default folder is already the one the install guides use.

`kit.conf` is plain `KEY=VALUE` lines. The installers parse it (they never run
it) and refuse an unknown key or a value with anything but letters, digits,
spaces and `. _ : / @ [ ] -`. An environment variable of the same name wins
over a line.

## 12. Uninstall and purge

- `RAVEN_RELAY_UNINSTALL=1 bash node/scripts/install/linux_relay.sh` stops the
  relay and removes the unit, `raven-relay` and the binaries. It keeps
  `/var/lib/raven-relay` (the key and the allow-list) and the `raven-relay`
  user, so a re-install keeps the PeerId.
- Add `RAVEN_RELAY_PURGE=1` to delete them too. It prints the PeerId your
  friends lose: their `via=` lines stop working.
- macOS: the same variables with `macos_relay.sh`. Windows: `-Uninstall`
  keeps `%LOCALAPPDATA%\RavenRelay`; delete it yourself to forget the PeerId.

## 13. Troubleshooting

- **Exit codes** of every installer: 0 ok; 1 failed (rolled back when there was
  an older install); 2 bad settings; 3 the build holds p2p (section 0); 4 a
  listen port is busy or needs a privilege; 5 the relay folder holds a Raven
  profile or a relay already runs in it, or (`--wss-cert`/`--wss-key`) the WSS
  certificate or key cannot be read or does not match: fix it, then start the
  relay again (`raven-node relay --check` names it).
- **443 needs a privilege** (exit 4 on Linux without the unit, or on an old
  macOS): use the kit's unit (Linux), or `RAVEN_RELAY_TCP443=7443` with the
  router's 443 mapped to 7443.
- **443 or 7423 is busy** (a web server, Raven itself): pick another port,
  `RAVEN_RELAY_PORT=7428` (not 7424/7425, a second Raven profile's, nor 7427,
  the friend relay's), or `RAVEN_RELAY_TCP443=off` when a web server holds
  443. `RAVEN_RELAY_TCP443=7443` helps only when the public 443 is free for the
  relay, a router or a second IP mapping it to 7443 (section 4, step 3).
- **A network that inspects 443** and expects TLS may still drop libp2p on TCP
  443. WebSocket over TLS on 443 comes in Phase 4.
- **A DNS name** in `RAVEN_RELAY_HOST` is looked up again before each
  reservation, so a dynamic-DNS name follows your home IP. A name with an AAAA
  record gives friends IPv6 too.
- **The relay runs but nobody reserves:** `raven-relay status` shows refused
  reservations when a friend is missing from the allow-list (section 6); none
  at all usually means the port forward or a firewall (section 3, step 5).
- **The PeerId changed** after an update: the installer restores the old
  binaries and stops. The key file was lost or replaced; restore it from a
  backup of the relay folder.

## 14. Privacy and residual risks

| Observer | Learns | Does not learn |
|---|---|---|
| The relay (you, and whoever controls the box) | Both PeerIds and IPs of every circuit, its timing, duration and bytes; who reserves; with `--autonat-server`, the addresses it is asked to probe | Raven IDs (unless it also holds lab cards), message text, PairInit, RLB1, route tags, message IDs |
| A relay operator who knows whose PeerId is whose (you allowed each friend's PeerId, or hold their lab cards) | The friend graph: who talks to whom | Message contents |
| Friends who use the relay, and their verified contacts | Its PeerId and its public address (in the `raven relay use` line, and in the route hints of friends who use it) | Your Raven ID: the relay key is not yours |
| Anyone who connects to the relay's ports | That a libp2p relay listens there, and its PeerId | Anything else: it is refused before any relay protocol runs |
| The VPS provider or ISP | IPs, ports, timing and volume of the relay's traffic | Contents |

The residuals of [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md)
section 4 apply: a relay can refuse, delay or drop circuits (it cannot read or
forge Raven traffic); a member can tell when other members are online; the
listening ports are visible to the whole Internet and a flood can keep friends
out; and an operator who knows whose PeerId is whose (from the allow-list, or
from lab cards) maps circuits to people.

The owner-run rows for the kit (a Pi with a port forward, a VPS, a 443-only
network, a Windows logon task) are in
an unpublished test checklist.
