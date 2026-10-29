# Install Raven Serverless (Windows)

Also see [`node/WINDOWS.md`](../node/WINDOWS.md) and [`node/scripts/install/WINDOWS_SERVICE.md`](../node/scripts/install/WINDOWS_SERVICE.md).

Unix `node/scripts/install.sh` is **not** an installer (fail-closed). It never
was a Windows path. Use the release-build steps below.

## Native build

```powershell
cd node
cargo build --locked -p raven-core -p raven-node -p ash --release --features raven-node/tor
.\target\release\ash.exe --data-dir $env:TEMP\raven-data init
.\target\release\ash.exe --data-dir $env:TEMP\raven-data doctor
```

**What a release build carries (October 2026).** Direct messaging on the local network, and the
features switched on after the three-machine field test ([`FIELD_TEST_2026_10.md`](FIELD_TEST_2026_10.md);
not independently reviewed): Internet direct, peer-to-peer with hole punching and relays run by
friends, router port mapping, route hints, finding this computer's public address with STUN
(Cloudflare and Google only), the Tor onion carrier (below), friends keeping sealed mail for each
other, messages that keep trying for up to 7 days, groups of up to 16, and the app channel for
RDAP (it takes app payloads from verified contacts only, of registered types, within size limits,
at most 30 a minute per sender and type and 120 in all:
[`RAVEN_APP_PAYLOAD_V1.md`](../protocol/RAVEN_APP_PAYLOAD_V1.md) §3.1); Bluetooth nearby on macOS only. `windows_service.ps1` builds with the cargo feature `tor` and puts `raven-tor-helper.exe` next to `raven-node.exe` (`-NoTor` leaves it out). Windows has no release Bluetooth backend. Listening for Internet direct and peer-to-peer, router port mapping,
relaying for friends, keeping mail for friends, using friends as mailboxes and Bluetooth each stay
off until you turn them on, so across networks two friends reach each other over Tor until they
turn a listener on; once they are connected, route hints carry their other addresses (a card
carries only the onion address, and a LAN one if its owner adds it). Paragraphs below that
still name a `*_PRODUCTION_ENABLED = false`
gate describe features that stay held, or say so.

Task Scheduler / service helper: `scripts/install/windows_service.ps1`
(builds with `--locked`). Its default `-DataDir` is the profile `raven.exe` /
`ash.exe` use without `--data-dir` (`RAVEN_DATA_DIR`, then `ASH_DATA_DIR`, then
`%USERPROFILE%\.raven`); binaries go to `%LOCALAPPDATA%\RavenNode` (`-BinDir`).
The named pipe is per user, not per profile, so a daemon installed with any other
`-DataDir` must be addressed with `--data-dir <that dir>` on every CLI command, or
the CLI would ping a daemon that serves a different profile.

**LAN exposure follows the build (same rule on every OS installer):** the
helper asks the installed binary where to listen (`raven-node.exe
lan-default`). Until the Phase 3 LAN amendment
([`WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md`](WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md),
unsigned) is signed and `LAN_AUTO_LISTEN_PRODUCTION_ENABLED` flips, that is
`127.0.0.1:7420`, so LAN peers cannot reach the task. After the flip it is
`auto`: every network of this PC, contacts only, and only from local sources
(private, link-local, unique-local or on-link addresses; a VPN at
100.64.0.0/10 or a public address is refused). While the gate is closed,
`auto` means `0.0.0.0:7420` from any source (contacts only), which is also
what a bare `raven-node.exe service` without `--lan-listen` binds: always pass
an explicit address when you start it by hand. Pass `-LanListen auto` or
`-LanListen <LAN-IP>:7420` to choose. For a LAN listen the helper prints two
firewall rules to run in an elevated PowerShell (it never changes the
firewall itself), for the Private profile only, never Public:

```powershell
New-NetFirewallRule -DisplayName "Raven LAN" -Direction Inbound -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol TCP -LocalPort 7420 -Profile Private
New-NetFirewallRule -DisplayName "Raven LAN search" -Direction Inbound -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol UDP -LocalPort 7420 -Profile Private
```

With `-LanListen auto:PORT` the TCP rule names that port; the nearby search
stays on UDP 7420.

On a link with no Internet (a hotspot or a cable), Windows may file the
network as Public: [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) §5 has a temporary
rule for that case, removed afterwards.

On a network you do not trust (a cafe, a hotel), turn the local network off;
it applies at once and is saved in `node_policy.json`:

```powershell
raven lan off                  # no LAN listener, no nearby search, no LAN dial; messages wait
raven lan status               # the LAN and nearby search rows
raven lan on                   # back on (raven lan on --for 1h: only for a meeting)
raven lan verified-only on     # LAN only with contacts whose fingerprint you confirmed
```

When a message waits, `raven status` and the send say why: `lan_off` ("You
turned the local network off (`raven lan on` turns it on). Your messages wait
here.") or `lan_no_answer` ("None of your friends answered on this network
..."): the Wi-Fi may keep devices apart, so make a hotspot
([`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) §3). [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md)
§4 says what each setting protects.

**Without the internet.** LAN delivery needs no internet provider: a router
whose internet is down, a laptop hotspot or a cable between two computers is
enough, with addresses typed as numbers. Read [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md)
before you rely on it: what Raven protects there, what it does not, and how to
stop it on networks you don't trust. The cutoff pack's two LAN gates
(`LAN_NOISE_PIN_PRODUCTION_ENABLED`: stop before telling another computer at a
friend's old address who you are; `OFFLINE_LAN_PRODUCTION_ENABLED`: the queue,
wake and dial rules for networks without a provider) stay `false` until the
pack's adversarial review is clean, under the unsigned amendment
[`WAIVER_LAN_DIRECT_CUTOFF_AMENDMENT_DRAFT.md`](WAIVER_LAN_DIRECT_CUTOFF_AMENDMENT_DRAFT.md);
debug builds open them with `RAVEN_LAB_NOISE_PIN=1` and `RAVEN_LAB_OFFLINE=1`.

**No Internet: two laptops.** See [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) for a
same-Wi-Fi network without uplink, a hotspot, a cable, and the firewall on
Windows (what `raven lan status` tells you, and what to type while nearby search
is held in your build).

**Friend mailboxes.** When a contact cannot be reached,
raven-node can leave a sealed copy of your message with a friend you both
verified, and collect mail that friends hold for you. Each needs its own yes:
`raven custody use on` (use friends as mailboxes; asked once, and `raven
status` may ask it once) and, on a computer that is often on, `raven node
custody on` (hold mail for your friends; it asks y/N on a terminal, scripts
pass `--yes`). A friend's Raven can't read your messages, but it learns both
Raven identities, when and how big each message is, when it is collected and
the IP addresses it sees; its signed copy stays until it is collected or
expires (at most 24 hours). [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) §9
explains it. Release builds have friend mailboxes since October 2026, over the local network and
the internet (switched on after the three-machine field test, before the unsigned
[`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md) was signed); each
still needs its own yes above. `raven custody
status` and `raven node custody status` show counts only. A waiting message
in `raven outbox list` may carry one of these codes: `MAILBOX_OFF` (you have
not turned friend mailboxes on), `NO_SHARED_CUSTODIAN` (the contact collects
mail only from friends you have not verified), `CUSTODIAN_NOT_OFFERING` (the
friend the contact named does not offer to hold mail for you, or not over the
internet).

**Internet direct is opt-in too (off by default).** It lets your verified
contacts reach this computer over TCP port **7422** (7421 is mock BLE's, 7423
is reserved for libp2p). A card carries no Internet address: `raven whoami
--card --inet` is refused, except in a debug build with the lab unlock
(`RAVEN_LAB_TEST_A=1`). While p2p runs too (below), raven-node tells each
verified contact this address inside your encrypted link once you are
connected over Tor or the local network: the public IP that STUN found, with
this port (route hints; not while you hide your IP from them or turned STUN
off). Otherwise tell them the address yourself, and they type it (`raven
contact set-addr --internet HOST:PORT`). Only your contacts get an answer:
anyone else completes
the Noise handshake and is disconnected before this node names itself, but a
scanner still learns that something listens on that port. Release builds have
Internet direct since October 2026 (`INTERNET_DIRECT_PRODUCTION_ENABLED = true`); the
listener stays your choice.
`raven status` shows an `internet` row: `YES` only while the running service
really has the listener up.

```powershell
# at install time
.\node\scripts\install\windows_service.ps1 -InternetListen 0.0.0.0:7422
# or later (saved in node_policy.json, applied when the task restarts)
raven.exe node internet on --listen 0.0.0.0:7422
Stop-ScheduledTask -TaskName RavenNodeBridge; Start-ScheduledTask -TaskName RavenNodeBridge
raven.exe node internet off      # closes it again at the next restart
```

Firewall: on the first non-loopback listen Defender Firewall may show "Windows
Security Alert"; allowing needs an administrator and dismissing it creates a
block rule. The installer prints, and never runs, the rule to add in an
elevated PowerShell (Private profile only, never Public; outbound needs no rule):

```powershell
New-NetFirewallRule -DisplayName "Raven node" -Direction Inbound `
  -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol TCP -LocalPort 7422 -Profile Private
```

Forward TCP 7422 on your router if the PC is behind NAT. The logon task runs only
while you are signed in, so a Windows PC is reachable only then. Contacts:
`raven contact add --card "<their card line>"` saves their key, their signed
onion address and a card's `lan=` address; it takes no `inet=`, `p2p=` or
`via=` from a card; when a card holds them, one line on stderr says so (`note: Raven ignored
this card's inet=, p2p= and via=: ...`). Their Internet address reaches you in
their route hints once you are connected, or you type it: `--internet-dial
HOST:PORT` on `raven contact add`, or `raven contact set-addr --petname <name>
--internet HOST:PORT`. Then `raven send --contact <name>` (LAN address first,
then Internet; `--carrier lan|internet` forces one). Internet delivery is for
verified contacts only. A contact whose fingerprint you have not confirmed
(`--verify-fp` when adding) is reached over the LAN carrier only, and only when
every address its LAN route resolves to is on your local network: loopback,
private (10/8, 172.16/12, 192.168/16), link-local (169.254/16, fe80::/10) or
unique-local IPv6 (fc00::/7); a public or CGNAT (100.64/10) address is refused
and nothing is dialled. Your Internet listener treats an unverified contact like
a stranger, and so does your LAN listener when it connects from outside those
ranges. A card's `lan=` address is dialled only at such a local-network
address, even for a verified contact; a LAN address you type on this computer
(`--lan-dial`, `contact set-dial`) may lie anywhere.

**Toolchain:** install Rust with [rustup](https://rustup.rs) (current stable);
older compilers fail at dependency resolution (rustc 1.83.0: the locked graph
needs edition 2024; its highest declared `rust-version` is 1.88). CI is validated
on rustc 1.98.0 only; the exact minimum is not yet verified.

## Tor onion carrier

Release builds have the Tor onion carrier since October 2026 (switched on after the three-machine
field test, where a phone hotspot and a home network reached each other over Tor 10 / 10 in
every direction; not independently reviewed). The installer builds with the cargo feature `tor`
and puts `raven-tor-helper.exe` (Arti, the Tor client, in its own process) next to `raven-node.exe`;
raven-node starts it and keeps an onion service, so a friend can reach this computer from any
network with no port forward and no address typed. Tor relays are the only third party it
talks to; Tor is only a pipe, and the Raven link inside it is end-to-end as on every other
path. Your card carries your onion address (signed by your key) and no IP address unless you
add a LAN one yourself (`--lan`), so the first link between two friends on different networks
goes over Tor; route hints then carry their other addresses inside it. Raven
races the direct paths against Tor and uses whichever connects first; over Tor a message took
about 8 to 27 seconds in the field test.

`raven status` has a `Tor` row (starting, ready, blocked on this network). The first start can
take a few minutes. Known open problems: the onion service was unreachable for part of a long
idle night, and took from about 10 seconds to 9 minutes to become reachable after a start.
`-NoTor` installs no helper (and removes one): `raven.exe status` then says "Tor: not built in this raven". A debug build closes the carrier with `RAVEN_LAB_TOR=0`.

## libp2p: relay and hole punching

**libp2p is opt-in too.** It is phase P3
of the transports plan
([`design/2026-10-transports-internet-mesh-bridge.md`](design/2026-10-transports-internet-mesh-bridge.md)
§3.5-§3.7). It is meant for two contacts who are both behind a home router
(NAT), with no public IP, port forward or IPv6 between them, so Internet direct
cannot connect them. Each keeps a reservation on a relay that both can reach;
one dials the other through the relay, and libp2p then tries to turn the
relayed connection into a direct one by hole punching (DCUtR). The relay can be
a contact's computer that offers relaying (`raven relay offer on`, with a relay
key of its own) or a dedicated always-on box (the relay kit,
[`RELAY_KIT.md`](RELAY_KIT.md)). It only passes encrypted bytes along: the
Raven link inside runs end to end between the two contacts.

The gate is `P2P_PRODUCTION_ENABLED` in
`node/crates/raven-core/src/p2p_gate.rs`: on in release builds since October 2026
(switched on after the three-machine field test; the unsigned
[`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) was not signed first). A debug build
closes it with `RAVEN_LAB_TEST_A=0`: `raven-node` then never listens, dials, reserves or
advertises libp2p and logs one line starting `P2P_HOLD:`. Hole punching has not yet connected
two real homes: in the field test the phone hotspot's NAT was the kind Raven does not punch,
and messages between the two networks went over Tor. While p2p listens, raven-node also asks
two public STUN servers (Cloudflare and Google) which public address they see, every 20
minutes; it tells that address only to verified friends, inside encrypted links (route
hints), never in a card. `raven node stun off` stops the query.

Route hints, relaying for your contacts and automatic relay choice (the
any-network plan's Phase 2) sit behind gates of their own,
`ROUTE_HINTS_PRODUCTION_ENABLED` and `FRIEND_RELAY_PRODUCTION_ENABLED`, both on in release
builds since October 2026; relaying for your contacts is still your own `raven relay offer on`.
Debug builds close them with `RAVEN_LAB_ROUTE_HINTS=0` and `RAVEN_LAB_FRIEND_RELAY=0`; while
they are closed, raven-node sends no route hints, never relays for your contacts and never
picks a relay by itself, and `raven relay offer` and `raven relay auto` say so. Their real-world rows are in
an unpublished test checklist.

Phase 4 of the any-network plan (networks that let only web traffic out,
router port mapping with NAT-PMP, PCP and IPv6 pinholes, the NAT mapping
class, and a network ID that changes) sits behind six more gates. Three are on in release builds since October 2026:
`PORT_MAP_PRODUCTION_ENABLED`, `V6_PINHOLE_PRODUCTION_ENABLED` and
`NAT_CLASS_PRODUCTION_ENABLED` (debug builds close them with `RAVEN_LAB_PORT_MAP=0`,
`RAVEN_LAB_V6_PINHOLE=0` and `RAVEN_LAB_NAT_CLASS=0`). Three stay `false`:
`WSS_PRODUCTION_ENABLED` and `WSS_PROXY_PRODUCTION_ENABLED`
(`node/crates/raven-core/src/wss_gate.rs`; debug `RAVEN_LAB_WSS=1` and
`RAVEN_LAB_WSS_PROXY=1`), and `PEER_ROTATION_PRODUCTION_ENABLED`
(`node/crates/raven-core/src/portmap_gate.rs`; debug `RAVEN_LAB_PEER_ROTATION=1`), each with
`RAVEN_LAB_TEST_A=1`. They wait for unsigned drafts:
[`WAIVER_WSS_PROXY_DRAFT.md`](WAIVER_WSS_PROXY_DRAFT.md) and §10 of the p2p relay draft (the
port-mapping draft, [`WAIVER_PORT_MAP_DRAFT.md`](WAIVER_PORT_MAP_DRAFT.md), was not signed
before its gates were switched on). While they are off, `raven-node relay --wss` exits with
`WSS_HOLD`, no proxy is used and the network ID stays fixed; the commands below say so when
you use them. `raven doctor --router` is not gated: it is a read-only question to your
own router (below).

libp2p uses TCP **and** UDP (QUIC) port **7423**, for the endpoint service and
a dedicated relay alike (LAN direct stays on TCP 7420, mock BLE on 7421,
loopback only, and Internet direct on TCP 7422). Relaying for your contacts
uses a port of its own, TCP and UDP **7427**.

In PowerShell a bare `@name` means splatting, so quote contact names that start
with `@` (`'@carol'`), as below.

### Turn p2p on

```powershell
# at install time (-P2pListen, like -InternetListen; -P2pRelays a,b and -Upnp 1|0 too)
.\node\scripts\install\windows_service.ps1 -P2pListen 7423
# or later (saved in node_policy.json, applied when the task restarts)
raven.exe node p2p on --listen 7423
Stop-ScheduledTask -TaskName RavenNodeBridge; Start-ScheduledTask -TaskName RavenNodeBridge
raven.exe node p2p off           # stops it again at the next restart
```

The service reads `--p2p-listen`, then `RAVEN_P2P_LISTEN`, then
`node_policy.json` (`p2p_listen`). `7423` or `on` listens on every interface,
IPv4 and IPv6, TCP and QUIC; `IP:PORT` listens on that address only; empty or
`off` is off, the default; `relay` is retired (a node without a listener can
never hole-punch): the service says so and listens like `on`. `raven status`
shows a `p2p` row: `YES` only while the libp2p host is really up, with its
reachability class (`public`, `mapped`, `relayed`, `unreachable` or `unknown`;
`public` only when two independent AutoNAT checks agree: two of your own relays
on different networks, each started with `--autonat-server`) and active relay
reservations, then `p2p_peer` (this node's PeerId) and `p2p_listen` (its listen
and relay addresses). A REACHABILITY section says the same in words: `internet`
(the class), `checks` (how many independent checks reached you), a `relay 1` /
`relay 2` row per relay (reserved and for how long, its last ping, or when it is
tried next; its host and port, never a PeerId) and `what to do`, the one next
step when contacts outside this network cannot reach you. `raven doctor` prints
the same as `reach_class:` and `relay_N:` lines and makes that step its next
step once nothing on this computer needs fixing. With route hints on, `raven
status` also shows `route hints` (on, how many contacts this node told, how many
it learned from) and `hide my IP`; while this computer relays for your contacts,
`relaying`; and in REACHABILITY, `spare relays` (relays your contacts offer that
automatic choice could switch to) and `circle` (who in your circle offers
relaying and who can be reached directly from the internet, by name only). When
raven-node could not reach a contact over the internet since it started, a NOT
REACHABLE NOW section names each one with the reason in a few words (offline, a
relay that is not answering, turned away, both behind NAT, no relay, no answer
at its internet address), how many messages wait for it and how long ago, then
one `what to do` row; `raven doctor` counts them per reason
(`unreachable_contacts:`), and `raven outbox list` says why each waiting message
waits. With no route to the internet (no default route), `what to do` says that
only people on this network (Wi-Fi, hotspot or cable) can be reached, and
suggests no relay, relay kit, VPS or port forward. A hotspot or router whose own
internet is down still gives this computer a default route, so RAVEN cannot
tell it apart (it never probes an outside host) and keeps its usual advice
there. A LAST DELIVERY section (LAN
too) names each contact raven-node delivered to since it started and how: `same
network (LAN)`, `Internet direct`, `direct over the internet` (or `… (hole
punched)`), `over the connection they opened to you` or `through a relay`; it is
kept in memory only and never shows an address. While the service runs, the row
shows the service's own setting and where it came from (`--p2p-listen`,
`RAVEN_P2P_LISTEN` or `node_policy.json`), so a setting the installer passed as
a flag shows up too; the installer also saves what `-P2pListen` sets with `raven
node p2p on`, so `raven status` agrees with the service while it is stopped (a
release card carries no p2p route). If another program already holds the port, the service does
not share it: it logs `p2p failed: listen port 7423/tcp is already in use by
another program (another raven-node?); it is not opened and is retried`, keeps
the rest of the host running, `p2p_listen` says `(none open yet: its port is
busy, or its address is not on this computer)`, and once the port is free it
logs `raven-node p2p: listen port 7423/tcp is open now`. (A program that starts
later and binds 7423 with `SO_REUSEADDR` can still share the port on Windows,
since libp2p does not bind it exclusively.) Its log lines hold categories and
counts only, never a PeerId or an address: `raven-node p2p: host up
(listeners=<n>)`, `raven-node p2p: reservation accepted (active=<k>)`,
`raven-node p2p: reservation lost (active=<k>)` and `raven-node p2p: direct
connection upgraded (dcutr)`, and `raven-node p2p: link via a direct connection`
/ `raven-node p2p: link via the relay` whenever the kind of a contact's link
changes. Ctrl-C in a console that runs `raven-node.exe service` closes its
libp2p connections first, so a relay frees the reservation at once.
`Stop-ScheduledTask` ends the process at once instead; the restarted node still
reserves again within seconds (a relay keeps up to two reservations per peer
while the old one times out).

Firewall: on the first non-loopback listen Defender Firewall may show "Windows
Security Alert"; allowing needs an administrator and dismissing it creates a
block rule. RAVEN prints, and never runs, the two rules to add in an elevated
PowerShell (Private profile only, never Public; outbound needs no rule). Add
them on a relay and on any node that should accept direct connections:

```powershell
New-NetFirewallRule -DisplayName "Raven node p2p" -Direction Inbound `
  -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol TCP -LocalPort 7423 -Profile Private
New-NetFirewallRule -DisplayName "Raven node p2p" -Direction Inbound `
  -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol UDP -LocalPort 7423 -Profile Private
```

While Windows treats the current network as Public, these rules do not apply
and nothing gets in. A node that only reaches its contacts through a relay
needs no port forward. A relay, or a node that should accept direct
connections, has to be reachable on TCP and UDP 7423 from the Internet: a
public IP, global IPv6, a port forward on the router, or UPnP (below).

### Reach a contact through a relay

Both contacts do this, with the relay's address (its operator prints it with
`raven relay card`, below). With route hints on and a contact who offers
relaying, nothing needs doing: automatic relay choice (below) picks it.

```powershell
# a relay a friend runs: paste the lines its `raven relay card` printed
raven.exe relay use via=/ip4/203.0.113.7/tcp/7423/p2p/12D3KooW... via=/ip4/203.0.113.7/tcp/443/p2p/12D3KooW...
# or with raven node p2p on (one address, or the relay Carol offers you):
raven.exe node p2p on --listen 7423 --relay /ip4/203.0.113.7/tcp/7423/p2p/12D3KooW...
raven.exe node p2p on --listen 7423 --relay '@carol'
Stop-ScheduledTask -TaskName RavenNodeBridge; Start-ScheduledTask -TaskName RavenNodeBridge
# your network ID, for the relay's operator (they run: raven-relay allow <PeerId>);
# your verified contacts learn your relays inside your encrypted links once connected
raven.exe whoami --peer-id
raven.exe send --contact bob                  # auto: LAN, Internet direct, then p2p
raven.exe send --contact bob --carrier p2p    # p2p only
```

- `raven relay use` takes the `via=` lines of a relay's `raven relay card`
  (with or without `via=`, at most 2: its TCP 7423 and TCP 443 lines). They are
  one relay with a fallback: on a network that lets only HTTPS out, the
  reservation moves to the 443 address. It saves them like `raven node p2p on
  --relay` and turns p2p on (port 7423) when it was off; restart the task
  and give the relay's operator your network ID (`raven whoami --peer-id`):
  they allow it (`raven-relay allow <PeerId>`). Your verified contacts learn
  this relay inside your encrypted links once you are connected; no card
  carries it.


- `--relay` on `raven node p2p on` names a relay this node keeps a reservation
  on and renews before it expires (repeatable, at most 2; saved as
  `p2p_relays`; the service flag is `--p2p-relay <MULTIADDR>`, the environment
  variable `RAVEN_P2P_RELAYS`, comma separated). A relay address ends in
  `/p2p/<relay PeerId>`. `'@carol'` takes the relay Carol offers you (she runs
  `raven relay offer on`; her route hints bring the offer), two addresses of
  it when it is the only relay given; without an offer it says so. No relay
  address is compiled into RAVEN. This is not `raven relay offer`, which makes
  your computer relay for your contacts (next section).
- A relay address may use a name (`/dns/relay.example.org/tcp/7423/p2p/...`,
  also `/dns4` and `/dns6`): it stays a name, is resolved again before every
  reservation attempt, and every address it resolves to is tried in turn; a
  name that does not resolve yet is retried. The `p2p` row counts every
  configured relay (`reservations <active>/<configured>`).
- Cards: a card carries no PeerId, relay or Internet address (no key signs
  them, so anyone who handles a card could change them unseen). `raven whoami
  --card` prints a `raven-card/1` line: your key, your signed onion address
  (`onion=`, once Tor is up) and a LAN address only if you add one (`--lan`).
  It refuses `--inet` and `--via`, and `raven node p2p on` adds nothing to it;
  `--compat` leaves `onion=` out, for a raven too old to read it. Your verified
  contacts learn your PeerId and relays from your route hints once you are
  connected (over Tor or the local network). `raven whoami --peer-id` prints
  your PeerId, one line, for a relay's operator. `raven contact add --card`
  reads `raven-card/1`, `/2` and `/3` but takes no PeerId, relay or Internet
  address from them. A debug build with the lab unlock (`RAVEN_LAB_TEST_A=1`)
  still writes and reads the old fields (`p2p=` and `via=` in a
  `raven-card/2`; `p2p=`, `p2pn=` and `relay=` in a `raven-card/3`) for the lab
  harnesses: [`RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md)
  §9 and §9.1. `raven contact set-addr --petname <name> --p2p <PeerId> --via
  <MULTIADDR>` edits the p2p route by hand (repeat `--via` for a second relay)
  and `--clear p2p` removes it.
- Order: `--carrier auto` tries LAN, then Internet direct, then p2p: a direct
  libp2p connection first, then through the relay, and on a relayed connection
  libp2p then tries the hole-punching upgrade (DCUtR). Hole punching usually
  fails when either side is behind a symmetric NAT or carrier-grade NAT (CGNAT,
  common on mobile networks and phone hotspots); the messages then keep going
  through the relay.
- Route hints: once a link is up, each side tells the other, inside the
  authenticated link, how to reach it now: its PeerId, its relays, its
  confirmed public addresses and its LAN port (a verified contact gets all of
  it; an unverified contact on your network gets the LAN port only). It tells a
  contact again only when that changed, or after 30 minutes on a link the two
  open anyway; no link is opened just for that unless something changed. So when a
  contact moves to another relay, port or network, you reach it without a new
  card, and a contact that changed something tells its recent contacts by
  itself. What a contact told you stays usable for up to 72 hours (at most 7
  days) unless a newer link replaces it, and its LAN port for 30 days after
  you learned it (friends who meet weekly find each other again on the same
  network); `raven contact remove` and a new p2p route (`raven contact
  set-addr --p2p`, `--via` or `--clear p2p`) forget it; a new LAN or Internet
  address, or the contact's new card added again, does not. Besides what you
  type yourself (`raven contact set-addr`), route hints are the only way a
  contact's PeerId, relays and Internet addresses reach you: a card carries
  none.
- Automatic relay choice: when a verified contact offers relaying, raven-node
  may reserve on that relay by itself, up to 2 relays in all, the relays you
  set by hand first and always. It keeps a relay while it works and replaces
  one only after it has not answered for 10 minutes while this computer is
  otherwise online, changes at most one relay every 5 minutes, and does not go
  back to a replaced relay for 30 minutes. `raven relay auto off` turns it off
  (only the relays you set are used; `raven relay auto on` turns it back on);
  `raven doctor` shows where each relay came from (`relay_N_source=offer` or
  `manual`).
- Hide my IP: `raven node hide-ip on` (every contact) or `raven contact
  hide-ip bob on` (one contact) keeps you reachable only through your relays
  for them: your route hints carry no address of yours, and there is no direct
  dial, no hole punching and no Identify with them. Raven reaches them only
  through a relay you use yourself, at your own address for it, never one
  only they name (they might run it) and never at an address they give for
  it. LAN links are not affected. An address a contact already learned stays usable to it until it
  expires (72 hours by default) or your next link replaces it. `raven status`
  shows `hide my IP: on (every contact)` or `off (1 contact hidden)`.
- Trust: a PeerId is only a hint and is never trusted. Every p2p link runs the
  Raven Noise handshake (prologue `raven/p2p-link/v1`) inside the libp2p stream
  and has to prove the contact's pinned key. p2p is for verified (pinned)
  contacts only, like Internet direct: a contact whose fingerprint you have not
  confirmed is never dialled over p2p, and your node answers it like a
  stranger.
- Peer gate: below the Raven link, your node's libp2p host admits only the
  PeerIds of your verified, unblocked contacts (learned from their route hints,
  or saved with `raven contact set-addr --p2p`), your relays, the relays your
  contacts' route hints name (it dials them, they cannot dial it) and, with
  the relay role, the PeerIds on your allow-list. Anyone else gets one libp2p
  handshake (it learns your PeerId) and a closed connection: no protocol list,
  no address, no hole punching, no Raven link. A verified contact whose PeerId
  your node has not learned yet is refused too: your first link with them goes
  over Tor or the local network, and its route hints bring the PeerId. `raven
  status` shows a `p2p_gate` row (verified contacts, relays and the connections
  refused; counts only), and a send that a contact's node (on a direct
  connection) or relay turned away says what to do (for a relay: ask its
  operator to `raven relay allow` you). A contact's node that refuses a
  circuit through a relay reads as
  offline: the relay's answer cannot tell the two apart. Hole punching
  offers and dials public (globally routable) addresses only, never a LAN,
  loopback or carrier-NAT one.

### Be the relay for your friends

**A Windows PC is a poor always-on relay.** Raven runs as a logon task, so
relaying for your contacts works only while you are signed in and the PC is
awake, and the relay kit's dedicated relay is a logon task too: it relays only
while you are signed in. RAVEN sets up no Windows service for a relay (Q9 of
the transports design). For a relay your friends rely on, prefer an always-on
Linux box (see [`INSTALL_Linux.md`](INSTALL_Linux.md)).

**Relaying for your contacts.** A computer that can be reached from the
internet (a public IP, UPnP, or a port forward) can relay for your verified
contacts, so that two of them who are both behind NAT reach each other:

```powershell
raven.exe relay offer on              # live: no restart needed
raven.exe relay offer on --also-443   # also TCP 443, for contacts on networks that allow only web ports
raven.exe relay offer off             # the relay stops within seconds
raven.exe relay status                # FRIEND RELAY, RELAYS YOU USE, ALLOW AND DENY
raven.exe relay deny '@dana'          # a contact you do not want to relay for
```

It is a relay of its own: its own key in the profile's `friend_relay/` folder,
never your Raven identity or PeerId, on TCP and UDP port **7427** (`--port`
changes it; `--external /dns4/home.example.net/tcp/7427` names the address
contacts reach it at when this computer cannot tell). It serves your verified
contacts (not one you hide your IP from or blocked), plus anyone you allowed
with `raven relay allow` (never a blocked contact) and minus your deny list,
only between each other, within fixed limits (at most 64 circuits, each 2
MiB and 5 minutes), and carries only encrypted bytes. It answers AutoNAT probes
for them, and with UPnP on it asks the router to map its port too. raven-node
offers it to your contacts inside their links (route hints), and their automatic
relay choice may use it: nobody needs a new card. Your contacts who use it learn
this computer's IP address; the relay sees their IP addresses and when they
talk, never their messages. A PC that sleeps, or whose user signs out, stops
relaying for that time: contacts that hold a second relay keep using it, and
automatic choice replaces yours after 10 minutes when another relay is offered
to them.

You are asked once, at the end of `raven status` on a terminal or on a bare
`raven relay offer`, and only while two independent checks confirm that this
computer can be reached from the internet. Enter or end of input means no; the
answer is saved and `raven status` shows it in a `relaying` row. A computer
reachable through its router's mapping gets a suggestion in that row instead,
and the first reachable computer of a circle can never be confirmed (the checks
need relays): run
`raven relay offer on --external /ip4/<its public IP>/tcp/7427` there. Until a
contact has reached the relay, it is offered to your contacts only with an
address named that way (or while UPnP maps its port, or once two independent
checks confirm this computer); `raven relay status` says when it is not
offered yet. The helper's `-P2pRelay`
(`raven-node service --relay`) is the same consent, unless you said no with
`raven relay offer off` (a saved no wins over it), and prints the firewall rules
for 7427; pass again every parameter you installed with, such as `-LanListen`,
because the helper registers the task again. Relaying under your own PeerId
(Phase 1's `service --relay`) is retired: release builds never do it. Add the
two rules it prints for TCP and UDP 7427 (Private profile only, in an elevated
PowerShell) and forward TCP and UDP 7427 as well if you forward ports. `raven
relay offer on` refuses while you hide your IP from every contact, and `raven
node hide-ip on` stops a running relay until it is off again: the relay would
show your IP to them.

An older `raven relay allow` or `raven relay deny` rewrites `relay_allow.json`
without its deny list, so the contacts you denied are relayed for again until
you deny them again with this version.

**A dedicated relay: the relay kit.** One command registers `raven-node relay`
as a per-user logon task (the same Task Scheduler settings as the node's own
task) on TCP and QUIC 7423 and TCP 443, in the relay folder
`%LOCALAPPDATA%\RavenRelay` with `raven-relay.cmd` next to its binaries, updates
that keep its PeerId, and an uninstall (`-Uninstall`); it prints the
Private-profile firewall rules and never applies them:
[`RELAY_KIT.md`](RELAY_KIT.md) and
[`WINDOWS_SERVICE.md`](../node/scripts/install/WINDOWS_SERVICE.md). When
http.sys or IIS already holds 443, use `-Tcp443 off`, or `-Tcp443 7443` only
if your router's public 443 is free for the relay and maps it to 7443 (never
when it already goes to that web server).

```powershell
powershell -ExecutionPolicy Bypass -File node/scripts/install/windows_relay.ps1 -PublicHost <public IP or DNS name>
```

The same relay by hand:

```powershell
raven-node.exe relay --data-dir "$env:LOCALAPPDATA\RavenRelay"   # TCP + QUIC 7423 on every interface
raven-node.exe relay --data-dir "$env:LOCALAPPDATA\RavenRelay" --also-tcp 443 --public-host relay.example.org
```

It holds no Raven identity and touches no keystore (no DPAPI identity). Its
folder holds only `relay_key.ed25519` (its own libp2p key; like every private
Raven file and folder it gets a protected ACL that allows only your Windows
account), `relay_allow.json`, `relay_status.json` and a lock file (one relay per
folder: a second `raven-node relay` on the same folder exits); give it a folder
of its own, not your profile. `--listen <PORT|IP:PORT>` changes the address,
`--autonat-server` answers reachability probes from its clients, and the limits
below can be tuned. `--also-tcp <LOCAL[:PUBLIC]>` adds a TCP port (at most 2:
`443`, or `7443:443` when the router maps 443 to 7443), `--public-host` names
the public IP or DNS name friends reach it at, with every port it listens on,
and `--check` checks the gate, the folder and every port, creates nothing and
exits: 0 ok, 3 held (the P2P gate is closed), 4 a port is busy or needs a
privilege, 5 the folder holds a Raven profile or another relay runs in it (2:
bad flags). The relay kit runs that check before it replaces anything, and keeps
the relay running while you are signed in (Task Scheduler keeps no log:
`raven-relay status` is the view).

If another program already holds its port, the relay exits with `relay
listen: port 7423/tcp is already in use by another program (another relay or
raven-node?); stop it or pick another --listen port`. In reservations it names
only its public (globally routable) listen addresses, an address you listen on
explicitly (`--listen 192.168.1.5:7423`), and each `--external <MULTIADDR>`
you pass (repeatable: `--external /ip4/203.0.113.7/tcp/7423`, `--external
/dns4/relay.example.org/tcp/7423`). Listening on every interface never
discloses its LAN or loopback addresses; behind a router, with no public
address on the box itself, forward the port and pass `--external` with the
router's public address, or it logs `raven-node relay: no public address known
...`. `raven relay status --data-dir <folder>` shows a `state` row: `not
running` while no relay holds the folder, `running`, or `running but its
status is <N>s old (stuck?)` (a running relay rewrites `relay_status.json` at
least every 10 s).

**Who may use it.** The allow-list is on by default: only PeerIds in
`relay_allow.json` may connect, reserve and open circuits, and circuits run only
between them (your circle: a friend reaches another friend through your relay
only when both are on the list). Anyone else is refused right after the libp2p
handshake. A missing allow-list means nobody may, and so does an unreadable or
corrupt one (it fails closed).

```powershell
raven.exe relay allow '@alice'        # a contact whose PeerId Raven learned from them
raven.exe relay allow 12D3KooW...     # or the PeerId itself (their `raven whoami --peer-id`)
raven.exe relay deny '@alice'
raven.exe relay status                # counts: reservations, circuits, refusals
raven.exe relay card --host 203.0.113.7   # via=/ip4/203.0.113.7/tcp/7423/p2p/<relay PeerId>
# a dedicated relay: name its folder (it has no contacts, so allow PeerIds)
raven.exe relay allow --data-dir "$env:LOCALAPPDATA\RavenRelay" 12D3KooW...
raven.exe relay card --data-dir "$env:LOCALAPPDATA\RavenRelay" --host 203.0.113.7
```

Without `--data-dir`, `raven relay` works on your profile's own
`relay_allow.json` and deny list (relaying for your contacts). `'@alice'` works
once Raven learned that contact's PeerId from them (after you are connected);
until then it asks for the PeerId they read out (`raven whoami --peer-id`).
Take a PeerId from the friend directly (in person, by voice, or in a message
you trust): nothing signs it. `raven relay allow` also takes `--card CARD`,
and `--cards FILE` for several at once, but only a lab card names a PeerId;
with a release card it says `that card names no PeerId (a card carries no
network ID in this raven)` and asks for the `raven whoami --peer-id` line.
`raven relay card` prints the relay's `via=` lines, TCP on its main port, its
TCP 443 line when it listens there, and QUIC, from the addresses the relay
names for itself (`--public-host`, `--external`), else its listen addresses
(`--host` and `--port` override them), and then the one line to give each
friend: `raven relay use via=<TCP 7423> via=<TCP 443>`. Without `--host` that
line names only an address friends elsewhere can reach (a DNS name or a public
IP): when the relay knows only loopback or local-network addresses it gives no
such line and asks for `--host`. A box whose own interface holds the public
IP (a VPS) installed with `-Tcp443 7443` names 443 there, the port friends
reach, not 7443. On a profile it prints
your friend relay's lines (its own key), never your PeerId.

**`--open`** (`raven-node relay --open`) serves anyone instead of the
allow-list, with stricter limits (32 reservations, 512 KiB per circuit) and a
printed notice. You would then relay encrypted traffic for people you do not
know, and anyone can tell whether a peer reserved on it is online; keep the
allow-list unless you mean that. The relay kit never passes `--open`.
`--relay-open` on `raven-node service` is now the same as `--relay` (relaying
for your verified contacts); an open relay for anyone has to be a dedicated
`raven-node relay --open`, which has its own key.

**WSS on TCP 443 (lab-only while `WSS_PRODUCTION_ENABLED` is false).** On a
network that lets only web traffic out, a contact may reach your relay only as
HTTPS. `raven-node relay --wss 443` makes TCP 443 take both: a connection that
starts with TLS is libp2p over WebSocket over TLS, any other is raw libp2p. So
`--wss 443` replaces `--also-tcp 443`; a raw and a WSS listener never share a
port, and `--public-host` names 443 as a plain TCP address too. The relay
serves a fresh self-signed certificate made at each start (`--wss-name <DNS>`
names it), or yours with `--wss-cert <fullchain.pem> --wss-key <privkey.pem>`,
which only networks whose proxy inspects TLS need (the relay warns when the key
file is readable by others). The certificate does not identify the relay: the
`/p2p/<relay PeerId>` at the end of every relay address does. `raven relay
card --wss --host <public IP or DNS name>` prints the `/tls/ws` lines for your
friends (`--wss-port` for another port). Raven has no ACME client: renew the
certificate with certbot (or any ACME client) and restart the relay after each
renewal, because it reads the files when it starts. The relay kit still
installs a raw TCP 443 listener; it moves to `--wss 443` when the WSS gate
flips.

Windows Defender Firewall asks once when the relay first listens on 443: allow
it on Private networks only, or add the rule the kit prints. An ACME client
for Windows (for example win-acme) can run a script after each renewal that
writes the PEM files where `--wss-cert` and `--wss-key` point and restarts the
relay's task (`Stop-ScheduledTask RavenRelay; Start-ScheduledTask RavenRelay`).

**Limits** (default / hard max): reservations 128 / 1024 in total, 2 / 2 per
peer and 4 / 16 per IP, each lasting 30 min / 2 h; circuits 64 / 256 in total
and 4 / 8 per peer, each lasting 5 min / 30 min and carrying 2 MiB / 16 MiB; 4
reservations and 30 circuits per minute per IP; established connections 256 /
1024 in total and 8 / 32 per IP. A dedicated relay tunes them with
`--max-reservations`, `--max-circuits`, `--circuit-bytes`, `--circuit-secs` and
`--reservation-secs`. "Per IP" means one IPv4 address or one IPv6 /64, and every
node and relay keeps 16 connection slots for its own dials that inbound
connections cannot take. Its log and `relay_status.json` hold counts only
(reservations, circuits, refusals); `relay_status.json` also keeps the relay's
own PeerId and listen addresses for `raven relay card`. Relaying for your
contacts uses the same defaults; `raven status` shows its `relaying` row.

### Router port mapping (UPnP, optional)

Contacts reach this computer directly only if the router lets TCP and UDP 7423
in (and, while it relays for your contacts, 7427). RAVEN can ask the router to
do that with UPnP, but never on its own. The first `raven node p2p on` you run
in a terminal, while the setting is still unset, asks once:

```text
Open TCP/UDP 7423 on your router automatically (UPnP) so friends can reach this node? [y/N]
```

Enter or end of input means no. The answer is saved in `node_policy.json`
(`upnp`) and never asked again. A run without a terminal (a script) never asks
and leaves it unset, which behaves as off. `--upnp` or `--no-upnp` on `raven
node p2p on` answers up front, `raven node upnp on` / `raven node upnp off`
changes it at any time (applied when the task restarts), and the installer takes
`-Upnp 1` or `-Upnp 0` (unset: an interactive install that turns p2p on may ask
the same question once; a non-interactive one never asks). When it is on, the
log shows only the mapped external port and whether it worked, never an IP
address: `raven-node p2p: upnp mapped port <port>` or `raven-node p2p: upnp
mapping failed`; `raven status` shows an `upnp` row (the setting and the mapping
result). While this computer relays for your contacts, the relay asks for its
own port (7427) the same way. A mapping opens the port to the whole Internet. It
cannot help when your ISP puts the router itself behind CGNAT (its WAN address
is in 100.64/10 or another private range). RAVEN speaks UPnP-IGD over IPv4 only;
a router that offers only NAT-PMP or PCP (some Apple and ISP routers) needs a
manual forward of TCP and UDP 7423.

**NAT-PMP, PCP and IPv6 pinholes.** With the PORT_MAP gate open (release builds since
October 2026),
the same yes lets raven-node ask the router with PCP first, then NAT-PMP, then
UPnP (one protocol per network), and the question says so:

```text
Let raven ask your router to open TCP/UDP 7423 automatically (UPnP, NAT-PMP or PCP) so friends can reach this node? [y/N]
```

Only your default router is asked, only for this computer's own outgoing IPv4
address (never a VPN or container address), with 2-hour leases renewed at
half; it asks again after every network change and when the router restarts.
`raven status` then shows a `router mapping` row (the protocol and the port;
`behind another NAT` when the router's own WAN address is private, in which
case the mapping is deleted and a relay is needed). On IPv6 there is no NAT,
but the router's firewall keeps contacts out: with the V6_PINHOLE gate open and
after a yes to the mapping question, `raven node p2p on` on a terminal asks a
second question once,

```text
Also open 7423 in your router's IPv6 firewall for this computer (PCP)? [y/N]
```

and `raven node ipv6-pinhole on|off` changes it (applied when the task
restarts; the UPnP answer never implies it). A yes opens a 1-hour pinhole,
renewed at half, for this computer's outgoing global IPv6 address only (an
`IPv6 pinhole` row). Removal is best effort: a clean stop deletes the mappings,
but after a crash, a sleep or a network change a mapping stays until its lease
ends. A mapping or a pinhole makes the port reachable from the whole Internet:
anyone who connects learns this node's PeerId (see "A network ID that changes"
below) and is refused by the peer gate. The friend relay's port 7427 keeps
UPnP only.

**What does my router speak?** `raven doctor --router` (any build, nothing to
turn on) sends your default router one PCP ANNOUNCE, one NAT-PMP address query
and one SSDP search, waits about 4 seconds, maps nothing and stores nothing,
and prints words only, never an address:

```text
router_gateway_v4=found
router_gateway_v6=found
router_pcp=yes
router_natpmp=yes
router_upnp_igd=no
router_ipv6_firewall_control=no
router_external_v4=global
```

`router_external_v4=behind_another_nat` means a mapping on this router cannot
help (carrier NAT); `router_gateway_v4=public_host` means this computer has a
public address itself and nothing is sent.

### Networks that let only web traffic out (WSS and HTTPS proxies)

Lab-only while `WSS_PRODUCTION_ENABLED` and `WSS_PROXY_PRODUCTION_ENABLED` are
false. Some networks (offices, hotels, schools) let only HTTPS out, often only
through a proxy. Raven then reaches its relays over WSS: libp2p inside a
WebSocket inside TLS on TCP 443. Use a relay that listens with `--wss 443` and
give `raven relay use` (or `raven node p2p on --relay`) its `/tls/ws` line, for
example `/dns4/relay.example.org/tcp/443/tls/ws/p2p/<relay PeerId>`. A lab
`raven-card/3` carries that line (and the relay's raw line), a lab
`raven-card/2` only the raw line; a release card names no relay (your route
hints tell your contacts your relays). Only relay dials use WSS or a proxy: contacts are
reached through those relays, and raw libp2p is never sent through a proxy.

raven-node finds the proxy itself, in this order: `--p2p-proxy` on `raven-node
service`; the `RAVEN_P2P_PROXY` environment variable; `raven node proxy
http://host:port` (saved in `node_policy.json`; `raven node proxy off` never
uses one, `raven node proxy auto` goes back to finding it); `HTTPS_PROXY` (or an
`http://` `ALL_PROXY`) with `NO_PROXY`; then the system setting. `HTTP_PROXY` is
never read. On Windows the system setting is Settings > Network & internet > Proxy >
Manual proxy setup ("Use a proxy server", with its exceptions): your account's
WinHTTP setting, which the logon task shares; a change is seen within about 30
seconds. "Use setup script" is a proxy script, which Raven cannot read.
"Automatically detect settings" is on by default; on its own raven-node
ignores it and dials directly (if your network really needs it, name the
`http://` proxy by hand). A proxy that needs a password:
`[Environment]::SetEnvironmentVariable('RAVEN_P2P_PROXY', 'http://user:password@proxy.example:3128', 'User')`
(Windows keeps it in your account's registry), then restart the task
(`Stop-ScheduledTask RavenNodeBridge; Start-ScheduledTask RavenNodeBridge`, or
sign out and in again).

Only `http://` proxies, without a password or with one (Basic). Proxy scripts
(PAC) and automatic detection (WPAD), Windows sign-in to the proxy (NTLM,
Kerberos), SOCKS and `https://` proxies are not supported: `raven status` says
which one it found, and you can name an `http://` proxy by hand. A user name
and password are never saved: `raven node proxy` refuses them, and they belong
only in the service's environment, as `RAVEN_P2P_PROXY=http://user:password@host:port`
(sent to the proxy as Basic over plain HTTP; other programs of your account can
read a process's environment). `raven node proxy` with no argument shows the
saved setting and where the running raven-node took its proxy from.

While a relay reservation goes through the proxy, raven-node offers no hole
punch and dials no direct address: everything goes through the relay, and the
`p2p` row of `raven status` says `relay over WSS through the HTTPS proxy;
restricted network (relay only)`. While WSS is held and every relay is
retrying, it says that this network may allow only web traffic.

### A network ID that changes (PeerId rotation)

Lab-only while `PEER_ROTATION_PRODUCTION_ENABLED` is false, and off by default
even after that. Your libp2p PeerId is fixed per profile: anyone who once
learned it (from an old card, by connecting to a mapped or pinholed port, or as
a TLS-intercepting proxy) can recognise this computer later. `raven node p2p
rotate on` changes it every epoch (28 days, at a moment only your profile
knows); `raven node p2p rotate off` goes back to the fixed one your older cards
name. A running raven-node follows within seconds. Your Raven ID, your
contacts' trust and every relay's own key do not change.

Contacts follow by themselves: their raven learns your coming PeerIds from
route hints. So rotation waits until every verified contact with a p2p route
runs a raven that can follow (the `p2p_rotation` row says `waiting: N contacts
cannot follow a rotating network ID yet`), then announces the coming PeerIds for
at least half an epoch (`starting`), then changes at each epoch boundary (`on`;
a few seconds of re-homing each time). Your lab cards then carry `p2pn=` (the
next PeerId) right after `p2p=` (a release card carries neither). A contact
that was offline for that whole announcing period, silent for more than six epochs, or holding a card older
than two epochs cannot reach you over p2p until it hears from you another way
(LAN, Internet direct) or gets a new card.

Relays that are your contacts (friend relays) follow by themselves too. A
dedicated relay is not a contact: give its operator the line `raven relay
schedule` prints (your PeerIds for about the next 6 months; `--epochs N`, 1 to
13), and they run `raven relay allow --schedule '<the line>'` (on a relay kit:
`raven-relay allow --schedule '<the line>'`); each entry expires a week after
its epoch. Do it again about every 6 months. When every relay you held turns a
new PeerId away, raven-node goes back to the previous one, the row says
`postponed` with that hint, and it tries again within 6 hours. `raven doctor`
prints `peer_rotation=<state> setting=<on|off|unset> waiting_on=<N>
gate=<open|held>`. Relays still see your IP address and timing, so they can
link an old and a new PeerId; contacts see every PeerId by design.

### What a relay learns

| A relay learns | A relay does not learn |
|---|---|
| Both PeerIds and IP addresses of every circuit, when it opens, how long it lasts and how many bytes pass; who keeps a reservation on it; with `--autonat-server`, the addresses it is asked to probe | Raven IDs (though its operator knows which friend each PeerId it admits belongs to, and a lab card maps a PeerId to a Raven ID), message text, PairInit, RLB1 offers, route tags, message IDs: all are inside libp2p Noise and, inside that, the Raven Noise link `raven/p2p-link/v1` |

A relay whose operator knows whose PeerId is whose (they allowed each
friend's PeerId, or hold lab cards) learns who talks to whom. Your PeerId is
stable (unless you turned PeerId rotation on, above), so it links you across
relays and networks; a stable public IPv6 listen address, which your route
hints tell your verified contacts, is a stable location identifier. Anyone
who connects to an open port 7423 learns that node's PeerId
(libp2p names itself in its handshake), but no Raven identity: the Raven link
answers your verified contacts only. libp2p's Identify exchange sends only
addresses confirmed as public (relay circuits, an address AutoNAT found
reachable, a UPnP mapping), never a node's LAN or loopback listen addresses.

Relaying for your contacts adds: the contacts who use your relay learn this
computer's IP address (it is in the offer their route hints carry); the
relay's PeerId is its own key's, not yours, but the route hints of those
contacts carry its address to their own contacts; and inside your circle
a member can tell whether another member is online. Route hints are not
signed, so they prove nothing to anyone else, but a contact can keep what it
was told.

## Bluetooth nearby (macOS only)

Bluetooth nearby lets your verified contacts' laptops in radio range get
your messages with no network at all ([`NEARBY.md`](NEARBY.md)). Release builds
have it on macOS only (since October 2026). Windows has no release Bluetooth backend:
`NEARBY_PRODUCTION_ENABLED` is false here, `windows_service.ps1` builds none, and nearby stays a lab
feature on Windows (a debug build with the feature `nearby-radio`, `RAVEN_LAB_TEST_A=1` and
`RAVEN_LAB_NEARBY=1`).

In that lab build the logon task runs raven-node in your user session, where its WinRT
Bluetooth radio runs; a Windows service is not supported for nearby.
`raven.exe nearby status` shows whether this PC's adapter offers the
peripheral role (`on, central only` when it does not). This build does not
use Bluetooth from Windows yet, because it cannot tell which address
Windows advertises and connects from: nearby stays inactive on a Windows PC
(no advert, no connect) until a hardware row shows the address is random.
Details: [`NEARBY.md`](NEARBY.md) section 7.

## Unsigned layout from macOS/Linux host

Cross-compile notes in `node/WINDOWS.md`. Prefer native Windows CI for release binaries you will Authenticode-sign.

## Updating Raven (not in this version)

**In this version, update Raven the way you installed it:** run the installer
again from a newer checkout (it copies the new programs over the old ones and
restarts the task). Your profile stays as it is.

`raven update` is built but held: in every build of this version it says
"Raven updates are not part of this version." Two things are missing before
it can be used. The update switches in the code are off
(`ADVISORY_PRODUCTION_ENABLED`, `RELEASE_BUNDLE_PRODUCTION_ENABLED` and
`MESH_UPDATE_PRODUCTION_ENABLED` are `false`), and no build holds the Raven
project's release keys yet: they are made at the key ceremony
([`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md)), and until then every
build says "This build has no Raven release keys; it can't check updates."
What it does once both exist:

```powershell
raven.exe update verify raven-1.5.0-x86_64-pc-windows-msvc.rrb  # check only, keep nothing
raven.exe update import raven-1.5.0-x86_64-pc-windows-msvc.rrb  # check it and keep it
raven.exe update install                                        # you type `install`
raven.exe update rollback                                       # back to the version before
raven.exe update                                                # what waits and what is kept
```

- **Import checks before it keeps anything:** two of the Raven project's three
  release keys signed the release, it is listed in the project's public
  release log, it is for this kind of computer (the target in its name), it
  is newer than the Raven you run, and every file matches its hash. The
  checked files wait in the profile (`updates/staged/`, at most two releases;
  `raven erase` removes them). A security notice from the Raven project
  (`.rad1`) is imported the same way, with the release log's `snapshot.rtl1`
  beside it (or `--log FILE`).
- **Install asks first:** it shows the version, the size, who signed it, its
  place in the public log and the release notes, and goes on only after you
  type `install`. Raven replaces its own programs only in the folder the
  running program is in, and only when that folder is writable, holds
  `raven-node`, none of the release's programs there is a link, and no package
  manager keeps it. It keeps each old program as `<name>.prev`, starts the
  new node and waits up to 20 seconds for it to answer; if it does not,
  everything goes back by itself. Otherwise Raven prints the steps to copy
  the checked files yourself and changes nothing. It never asks for an
  administrator's password and never runs a script or a file from the
  release. While Raven is locked it installs nothing (`raven update install`
  and `rollback` say "Raven is locked: run raven unlock first"): its restart
  could start Raven unlocked, or listening on another network address.
- **Your layout here:** the installer keeps `raven.exe` and `ash.exe` as two
  copies in `%LOCALAPPDATA%\RavenNode`, while a release names its
  command-line program `bin/ash.exe`. `raven update install` replaces both
  copies with it, and `raven-node.exe`; a copy that is running is renamed
  aside, never written over.
- **Older releases** only with `--allow-downgrade` and a typed `downgrade`,
  and never below the release floor a security notice sets.
- **Friends pass updates on** (when that part is on too): security notices
  pass from friend to friend by themselves; a release a friend holds is
  offered, `raven update download` lists the offers and downloads one only
  after you answer `y`, and you still install it yourself. Raven never
  contacts a server to look for updates.
- **On Windows:** a running program cannot be replaced or deleted, so Raven
  renames whatever is in the way aside first (`.raven-old`, deleted once it
  can be) and never writes over a running program. This has been tested with
  a stand-in that follows Windows' rules, not on a real Windows install yet.

## Signing

MSI / Authenticode steps: [`SIGNING_NOTARIZATION_CHECKLIST.md`](SIGNING_NOTARIZATION_CHECKLIST.md). This repo ships **unsigned** artifacts only.

## Identity seed

Windows stores the node seed as a **DPAPI**-protected `identity.seed` blob (user-bound). Legacy plaintext 32-byte files are migrated automatically. See [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).

The profile folder and every private file Raven writes there (and in a relay's
folder) get a protected ACL with a single entry: full access for your Windows
account. Nothing is inherited from the parent folder, and SYSTEM and
Administrators get no entry (an administrator can still take ownership, as
root can on Unix). Files that other programs create in the folder inherit the
same entry. The ACL is set before a file's contents are written and read back
afterwards; when that fails (for example a profile on a FAT32 or exFAT drive,
which has no ACLs) Raven refuses to use the folder instead of keeping private
state readable by others. Check it with `icacls "$env:USERPROFILE\.raven"`.
