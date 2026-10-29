# Install Raven Serverless (Linux)

`node/scripts/install.sh` is **not** a production installer. It fails closed
and does not put binaries on `PATH`. Use the release-build steps below
(`scripts/install/linux_systemd_user.sh`). Do not `curl | bash` a convenience
script.

> **Where your keys live.** With an unlocked desktop keyring (GNOME Keyring /
> KWallet, i.e. Secret Service) RAVEN stores its keys there. Without one (servers,
> SSH sessions, a Raspberry Pi bridge, musl builds) it keeps them in an encrypted
> file, `<data-dir>/keystore.vault`, protected by a **passphrase** you choose
> (Argon2id + XChaCha20-Poly1305). The choice is made once per profile and recorded
> in `<data-dir>/keystore.backend`; RAVEN never moves keys between the two on its
> own. Details: [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md) and
> [`design/2026-10-linux-keystore.md`](design/2026-10-linux-keystore.md).

### Passphrase vault in practice

- `raven init` / `ash init` on a terminal explains this and asks for the
  passphrase twice (nothing is echoed; at least 8 characters). Later runs ask once.
  There is no recovery without it.
- Non-interactive use (scripts, CI, the service) needs a passphrase **file**:

  ```bash
  mkdir -p ~/.config/raven && chmod 700 ~/.config/raven
  ( umask 077; printf '%s\n' 'your long passphrase' > ~/.config/raven/keystore-passphrase )
  export RAVEN_KEYSTORE_PASSPHRASE_FILE=~/.config/raven/keystore-passphrase
  ```

  The file must be a regular file owned by you with mode `0600` or `0400`. The
  passphrase itself is never accepted in an environment variable or on the command
  line (`RAVEN_KEYSTORE_PASSPHRASE` is refused). A file next to the data dir
  protects only against copies of the data dir *without* it: keep it out of
  backups that contain `keystore.vault`.
- `raven-node service` never prompts. Give it the file through the installer
  (below), or with systemd `LoadCredential=raven-keystore-passphrase:<file>`.
- Force the vault on a desktop with `RAVEN_KEYSTORE_BACKEND=vault` before the
  first `raven init` of a profile.

**Toolchain:** install Rust with [rustup](https://rustup.rs) (current stable);
distro-packaged compilers are usually too old (rustc 1.83.0 fails at dependency
resolution because the locked graph needs edition 2024; its highest declared
`rust-version` is 1.88). CI is validated on rustc 1.98.0 only; the exact minimum
is not yet verified.

## From source

```bash
cd node
cargo build --locked -p raven-node -p ash --release --features raven-node/tor
bash scripts/install/linux_systemd_user.sh
export PATH="$HOME/.local/bin:$PATH"
raven init        # `ash` is only aliased when no system ash shell exists
raven doctor
```

**What a release build carries (October 2026).** Direct messaging on the local network, and the
features switched on after the three-machine field test ([`FIELD_TEST_2026_10.md`](FIELD_TEST_2026_10.md);
not independently reviewed): Internet direct, peer-to-peer with hole punching and relays run by
friends, router port mapping, route hints, finding this computer's public address with STUN
(Cloudflare and Google only), the Tor onion carrier (below), friends keeping sealed mail for each
other, messages that keep trying for up to 7 days, groups of up to 16, and the app channel for
RDAP; Bluetooth nearby on macOS only. `linux_systemd_user.sh` builds with the cargo feature `tor` and puts `raven-tor-helper` next to `raven-node` (`RAVEN_INSTALL_TOR_HELPER=0` leaves it out). Linux has no release Bluetooth backend. Listening for Internet direct and peer-to-peer, router port mapping,
relaying for friends, keeping mail for friends, using friends as mailboxes and Bluetooth each stay
off until you turn them on. Paragraphs below that still name a `*_PRODUCTION_ENABLED = false`
gate describe features that stay held, or say so.

Headless host (no desktop keyring): pass the passphrase file so the unit can
unlock the vault. The unit gets `Environment=RAVEN_KEYSTORE_PASSPHRASE_FILE=<path>`
(the path only); `RAVEN_SYSTEMD_LOAD_CREDENTIAL=1` uses `LoadCredential=` instead:

```bash
RAVEN_KEYSTORE_PASSPHRASE_FILE=$HOME/.config/raven/keystore-passphrase \
  bash scripts/install/linux_systemd_user.sh
```

User systemd unit runs `raven-node service` (bridge + IPC). Does not require root.
The data directory (`~/.raven`) is created mode `0700`. The installer picks the
same profile `raven` / `ash` use without `--data-dir` (`RAVEN_DATA_DIR`, then
`ASH_DATA_DIR`, then a legacy `~/.raven-ash` while `~/.raven` does not exist, else
`~/.raven`), and writes *absolute*, quoted paths into the unit (`systemd --user`
starts it from your home directory, so a relative `RAVEN_DATA_DIR` /
`RAVEN_BIN_DIR` is resolved by the installer first).

**IPC socket location.** The daemon listens on `<data-dir>/raven-node.sock`. When
that path would be too long for a Unix socket (about 107 bytes on Linux) it serves
`/tmp/raven-<uid>/raven-<hash>.sock` instead (a private, owner-only directory).
The choice depends on the resolved data dir, never on how the path was spelled.
Do not hard-code the socket path: `raven doctor` (and the installer's last lines)
print the real `ipc_endpoint=`.

**LAN exposure follows the build (same rule on every OS installer):**
`scripts/install/linux_systemd_user.sh` asks the installed binary where to
listen (`raven-node lan-default`). Until the Phase 3 LAN amendment
([`WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md`](WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md),
unsigned) is signed and `LAN_AUTO_LISTEN_PRODUCTION_ENABLED` flips, that is
`127.0.0.1:7420`, so LAN peers cannot reach the service. After the flip it is
`auto`: every network of this host, contacts only, and only from local
sources (private, link-local, unique-local or on-link addresses; a VPN at
100.64.0.0/10 or a public address is refused). While the gate is closed,
`auto` means `0.0.0.0:7420` from any source (contacts only), which is also
what a bare `raven-node service` without `--lan-listen` binds: always pass an
explicit address when you start it by hand. To choose:

```bash
RAVEN_LAN_LISTEN=auto bash scripts/install/linux_systemd_user.sh
RAVEN_LAN_LISTEN=<this-host-LAN-IP>:7420 bash scripts/install/linux_systemd_user.sh
```

The installer prints the firewall lines and never runs them. Open TCP 7420
(the port of `auto:PORT` if you chose one), and for nearby search UDP 7420
(always 7420), to your local networks only: 192.168.0.0/16, 10.0.0.0/8,
172.16.0.0/12, 169.254.0.0/16 (a cable between two laptops), fe80::/10 and
fc00::/7. For example:

```bash
sudo ufw allow from 192.168.0.0/16 to any port 7420 proto tcp
sudo ufw allow from 192.168.0.0/16 to any port 7420 proto udp
# or firewalld, in your network's zone (firewall-cmd --get-active-zones shows it):
# firewall-cmd --zone=<that zone> --add-port=7420/tcp --add-port=7420/udp
```

On a network you do not trust (a cafe, a hotel), turn the local network off;
it applies at once and is saved in `node_policy.json`:

```bash
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
Linux (what `raven lan status` tells you, and what to type while nearby search
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

**Internet direct is opt-in too (off by default).** It lets contacts who have
your Internet address (`raven whoami --card --inet <public-ip-or-name>:7422`)
reach this computer over TCP port **7422** (7421 is mock BLE's, 7423 is
reserved for libp2p). Only your contacts get an answer: anyone else completes
the Noise handshake and is disconnected before this node names itself, but a
scanner still learns that something listens on that port. Release builds have
Internet direct since October 2026 (`INTERNET_DIRECT_PRODUCTION_ENABLED = true`); the
listener stays your choice.
`raven status` shows an `internet` row: `YES` only while the running service
really has the listener up.

```bash
# at install time
RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash scripts/install/linux_systemd_user.sh
# or later (saved in node_policy.json, applied when the service restarts)
raven node internet on --listen 0.0.0.0:7422
systemctl --user restart raven-node
raven node internet off          # closes it again at the next restart
```

The service reads `--internet-listen`, then `RAVEN_INTERNET_LISTEN`, then
`node_policy.json`; a bare IP gets port 7422 and an empty value is off.
Firewall: Linux shows no prompt, ufw / firewalld / nftables and cloud security
groups decide. Open the port yourself, e.g. `sudo ufw allow 7422/tcp`
(`firewall-cmd --add-port=7422/tcp --permanent` on firewalld), and forward TCP
7422 on your router if the host is behind NAT. A VPS with a public IP or a home
with global IPv6 (`[::]:7422`) needs no forwarding.

Contacts: `raven contact add --card '<their card line>'` saves their routes,
`raven contact set-addr --petname <name> --internet HOST:PORT` (or `--lan`, `--clear
internet`) edits them, and `raven send --contact <name>` tries their LAN
address first, then their Internet address (`--carrier lan|internet` forces
one). An address is only a hint: every connection still has to prove the
contact's pinned key. Internet delivery is for verified contacts only. A contact
whose fingerprint you have not confirmed (`--verify-fp` when adding) is reached
over the LAN carrier only, and only at an address on your local network:
loopback, private (10/8, 172.16/12, 192.168/16), link-local (169.254/16,
fe80::/10) or unique-local IPv6 (fc00::/7); a public or CGNAT (100.64/10)
address is never dialled. Your Internet listener treats an unverified contact
like a stranger, and so does your LAN listener when it connects from outside
those ranges.

## Tor onion carrier

Release builds have the Tor onion carrier since October 2026 (switched on after the three-machine
field test, where a phone hotspot and a home network reached each other over Tor 10 / 10 in
every direction; not independently reviewed). The installer builds with the cargo feature `tor`
and puts `raven-tor-helper` (Arti, the Tor client, in its own process) next to `raven-node`;
raven-node starts it and keeps an onion service, so a friend can reach this computer from any
network with no port forward and no address typed. Tor relays are the only third party it
talks to; Tor is only a pipe, and the Raven link inside it is end-to-end as on every other
path. Your card carries your onion address (signed by your key), never an IP address. Raven
races the direct paths against Tor and uses whichever connects first; over Tor a message took
about 8 to 27 seconds in the field test.

`raven status` has a `Tor` row (starting, ready, blocked on this network). The first start can
take a few minutes. Known open problems: the onion service was unreachable for part of a long
idle night, and took from about 10 seconds to 9 minutes to become reachable after a start.
`RAVEN_INSTALL_TOR_HELPER=0` installs no helper (and removes one): `raven status` then says "Tor: not built in this raven". A debug build closes the carrier with `RAVEN_LAB_TOR=0`.

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

### Turn p2p on

```bash
# at install time
RAVEN_P2P_LISTEN=7423 bash scripts/install/linux_systemd_user.sh
# or later (saved in node_policy.json, applied when the service restarts)
raven node p2p on --listen 7423
systemctl --user restart raven-node
raven node p2p off               # stops it again at the next restart
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
a flag shows up too; the installer also saves what `RAVEN_P2P_LISTEN` sets with
`raven node p2p on`, so `raven status` and `raven whoami --card` agree with the
service while it is stopped. If another program already holds the port, the
service does not share it: it logs `p2p failed: listen port 7423/tcp is already
in use by another program (another raven-node?); it is not opened and is
retried`, keeps the rest of the host running, `p2p_listen` says `(none open yet:
its port is busy, or its address is not on this computer)`, and once the port is
free it logs `raven-node p2p: listen port 7423/tcp is open now`. The log
(`journalctl --user -u raven-node`) holds categories and counts only, never a
PeerId or an address: `raven-node p2p: host up (listeners=<n>)`, `raven-node
p2p: reservation accepted (active=<k>)`, `raven-node p2p: reservation lost
(active=<k>)` and `raven-node p2p: direct connection upgraded (dcutr)`, and
`raven-node p2p: link via a direct connection` / `raven-node p2p: link via the
relay` whenever the kind of a contact's link changes. Stopping or restarting the
service (`systemctl --user stop|restart raven-node`, SIGTERM) closes its libp2p
connections first, so a relay frees its reservation at once and the restarted
node reserves again within seconds.

Firewall: Linux shows no prompt. RAVEN prints these rules and never runs them;
add them on a relay and on any node that should accept direct connections (or
the equivalent in firewalld, nftables or your cloud security group):

```bash
sudo ufw allow 7423/tcp
sudo ufw allow 7423/udp
```

A node that only reaches its contacts through a relay needs no port forward. A
relay, or a node that should accept direct connections, has to be reachable on
TCP and UDP 7423 from the Internet: a public IP, global IPv6, a port forward on
the router, or UPnP (below).

### Reach a contact through a relay

Both contacts do this, with the relay's address (its operator prints it with
`raven relay card`, below). With route hints on and a contact who offers
relaying, nothing needs doing: automatic relay choice (below) picks it.

```bash
# a relay a friend runs: paste the lines its `raven relay card` printed
raven relay use via=/ip4/203.0.113.7/tcp/7423/p2p/12D3KooW... via=/ip4/203.0.113.7/tcp/443/p2p/12D3KooW...
# or with raven node p2p on (one address, or the relay Carol offers you):
raven node p2p on --listen 7423 --relay /ip4/203.0.113.7/tcp/7423/p2p/12D3KooW...
raven node p2p on --listen 7423 --relay @carol
systemctl --user restart raven-node
# your card names your relays: give it to your contact, and add theirs
raven whoami --card
raven contact add --card '<their card line>'
raven send --contact bob                  # auto: LAN, Internet direct, then p2p
raven send --contact bob --carrier p2p    # p2p only
```

- `raven relay use` takes the `via=` lines of a relay's `raven relay card`
  (with or without `via=`, at most 2: its TCP 7423 and TCP 443 lines). They are
  one relay with a fallback: on a network that lets only HTTPS out, the
  reservation moves to the 443 address. It saves them like `raven node p2p on
  --relay` and turns p2p on (port 7423) when it was off; restart the service,
  send your new card to your contacts, and ask the relay's operator to allow
  you (`raven-relay allow --card`).


- `--relay` on `raven node p2p on` names a relay this node keeps a reservation
  on and renews before it expires (repeatable, at most 2; saved as
  `p2p_relays`; the service flag is `--p2p-relay <MULTIADDR>`, the environment
  variable `RAVEN_P2P_RELAYS`, comma separated). A relay address ends in
  `/p2p/<relay PeerId>`. `@carol` takes the relay Carol offers you (she runs
  `raven relay offer on`; her route hints bring the offer), two addresses of
  it when it is the only relay given; without an offer it says so. No relay
  address is compiled into RAVEN. This is not `raven relay offer`, which makes
  your computer relay for your contacts (next section).
- A relay address may use a name (`/dns/relay.example.org/tcp/7423/p2p/...`,
  also `/dns4` and `/dns6`): it stays a name, is resolved again before every
  reservation attempt, and every address it resolves to is tried in turn; a
  name that does not resolve yet is retried. The `p2p` row counts every
  configured relay (`reservations <active>/<configured>`).
- Cards: once p2p is configured, `raven whoami --card` prints a `raven-card/2`
  line with `p2p=<your PeerId>` and one `via=<relay multiaddr>` per `--via` (at
  most 2); `--inet` and `--lan` work as before. Without p2p it prints the old
  `raven-card/1` line. With route hints on it prints `raven-card/3` instead:
  your PeerId and up to 4 addresses of at most 2 home relays (`relay=`), and no
  address of yours (with `--inet`, `--lan` or a direct address it stays /1 or
  /2). Your contacts learn your addresses later, inside the link. Older ravens
  refuse a /3 card ("update raven"): `raven whoami --card --compat` prints the
  /1 or /2 line for them. `raven contact add --card` reads all three. Without
  `--via`, the card names the relays the running service uses (while it is
  stopped, those in `node_policy.json`). The card size limit fits the longest
  valid card (two relays, the longest addresses); `raven whoami --card` refuses
  to print a longer one. `raven contact set-addr --petname <name> --p2p <PeerId> --via
  <MULTIADDR>` edits the p2p route (repeat `--via` for a second relay) and
  `--clear p2p` removes it.
- Order: `--carrier auto` tries LAN, then Internet direct, then p2p: a direct
  libp2p connection first, then through the relay, and on a relayed connection
  libp2p then tries the hole-punching upgrade (DCUtR). Hole punching usually
  fails when either side is behind a symmetric NAT or carrier-grade NAT (CGNAT,
  common on mobile networks and phone hotspots); the messages then keep going
  through the relay.
- Route hints: once a link is up, each side tells the other, inside the
  authenticated link, how to reach it now: its relays, its confirmed public
  addresses and its LAN port (a verified contact gets all of it; an
  unverified contact on your network gets the LAN port only). It tells a
  contact again only when that changed, or after 30 minutes on a link the two
  open anyway; no link is opened just for that unless something changed. So when a
  contact moves to another relay, port or network, you reach it without a new
  card, and a contact that changed something tells its recent contacts by
  itself. What a contact told you stays usable for up to 72 hours (at most 7
  days) unless a newer link replaces it, and its LAN port for 30 days after
  you learned it (friends who meet weekly find each other again on the same
  network); `raven contact remove` and a new p2p route (`raven contact
  set-addr --p2p`, `--via` or `--clear p2p`) forget it; a new LAN or Internet
  address, or the contact's new card added again, does not.
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
  `p2p=` PeerIds of your verified, unblocked contacts, your relays, the relays
  your contacts' `via=` lines name (it dials them, they cannot dial it) and,
  with the relay role, the PeerIds on your allow-list. Anyone else gets one
  libp2p handshake (it learns your PeerId, which your card already shows) and
  a closed connection: no protocol list, no address, no hole punching, no
  Raven link. Exchange cards both ways: a contact whose card you hold without
  `p2p=` is refused too. `raven status` shows a `p2p_gate` row (verified
  contacts, relays and the connections refused; counts only), and a send that
  a contact's node (on a direct connection) or relay turned away says what to
  do (send your card again, or ask the relay's operator to `raven relay allow`
  you). A contact's node that refuses a circuit through a relay reads as
  offline: the relay's answer cannot tell the two apart. Hole punching
  offers and dials public (globally routable) addresses only, never a LAN,
  loopback or carrier-NAT one.

### Be the relay for your friends

**Relaying for your contacts.** A computer that can be reached from the
internet (a public IP, UPnP, or a port forward) can relay for your verified
contacts, so that two of them who are both behind NAT reach each other:

```bash
raven relay offer on              # live: no restart needed
raven relay offer on --also-443   # also TCP 443, for contacts on networks that allow only web ports
raven relay offer off             # the relay stops within seconds
raven relay status                # FRIEND RELAY, RELAYS YOU USE, ALLOW AND DENY
raven relay deny @dana            # a contact you do not want to relay for
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
talk, never their messages. A computer that sleeps stops relaying for that time:
contacts that hold a second relay keep using it, and automatic choice replaces
yours after 10 minutes when another relay is offered to them.

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
offered yet. The installer's
`RAVEN_P2P_RELAY=1` (`raven-node service --relay`) is the same consent, unless
you said no with `raven relay offer off` (a saved no wins over it), and prints
the firewall hint for 7427; pass again every other variable you installed
with, such as `RAVEN_LAN_LISTEN`, because the installer rewrites the unit.
Relaying under your own PeerId (Phase 1's `service --relay`) is retired: release
builds never do it. Allow 7427 in the firewall (`sudo ufw allow 7427/tcp` and
`sudo ufw allow 7427/udp`, or the equivalent) and forward TCP and UDP 7427 as
well if you forward ports. `raven relay offer on` refuses while you hide your IP
from every contact, and `raven node hide-ip on` stops a running relay until it
is off again: the relay would show your IP to them.

An older `raven relay allow` or `raven relay deny` rewrites `relay_allow.json`
without its deny list, so the contacts you denied are relayed for again until
you deny them again with this version.

**A dedicated relay: the relay kit.** On an always-on box (a home server, a
Raspberry Pi, a small VPS) one command installs `raven-node relay` as a
hardened system unit run as its own `raven-relay` user, holding only
`CAP_NET_BIND_SERVICE` (for TCP 443), on TCP and QUIC 7423 and TCP 443, with a
`raven-relay` command (`sudo raven-relay status`, `card`, `allow`, `deny`,
`logs`), updates that keep its PeerId, and an uninstall:
[`RELAY_KIT.md`](RELAY_KIT.md) (a Pi with a port forward, a EUR 5 VPS).

```bash
RAVEN_RELAY_HOST=<public IP or DNS name> bash node/scripts/install/linux_relay.sh
```

The same relay by hand (a port below 1024 needs a privilege, which the kit's
unit grants; by hand use 7443 and map 443 to it on the router):

```bash
raven-node relay --data-dir ~/.raven-relay      # TCP + QUIC 7423 on every interface
raven-node relay --data-dir ~/.raven-relay --also-tcp 7443:443 --public-host relay.example.org
```

It holds no Raven identity and touches no keystore (no Secret Service, no
passphrase vault), so it restarts without anyone typing a passphrase. Its folder
holds only `relay_key.ed25519` (its own libp2p key, mode `0600`),
`relay_allow.json`, `relay_status.json` and a lock file (one relay per folder: a
second `raven-node relay` on the same folder exits); give it a folder of its
own, not your profile. `--listen <PORT|IP:PORT>` changes the address,
`--autonat-server` answers reachability probes from its clients, and the limits
below can be tuned. `--also-tcp <LOCAL[:PUBLIC]>` adds a TCP port (at most 2:
`443`, or `7443:443` when the router maps 443 to 7443), `--public-host` names
the public IP or DNS name friends reach it at, with every port it listens on,
and `--check` checks the gate, the folder and every port, creates nothing and
exits: 0 ok, 3 held (the P2P gate is closed), 4 a port is busy or needs a
privilege, 5 the folder holds a Raven profile or another relay runs in it (2:
bad flags). The relay kit runs that check before it replaces anything, and keeps
the relay running for you.

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

```bash
raven relay allow @alice          # the PeerId (p2p=) from Alice's card
raven relay allow 12D3KooW...     # or the PeerId itself
raven relay deny @alice
raven relay status                # counts: reservations, circuits, refusals
raven relay card --host 203.0.113.7   # via=/ip4/203.0.113.7/tcp/7423/p2p/<relay PeerId>
# a dedicated relay: name its folder (it has no contacts, so allow PeerIds)
raven relay allow --data-dir ~/.raven-relay 12D3KooW...
raven relay card --data-dir ~/.raven-relay --host 203.0.113.7
```

Without `--data-dir`, `raven relay` works on your profile's own
`relay_allow.json` and deny list (relaying for your contacts); `raven relay
allow` also takes `--card CARD`, and `--cards FILE` for several at once.
`raven relay card` prints the relay's `via=` lines, TCP on its main port, its
TCP 443 line when it listens there, and QUIC, from the addresses the relay
names for itself (`--public-host`, `--external`), else its listen addresses
(`--host` and `--port` override them), and then the one line to give each
friend: `raven relay use via=<TCP 7423> via=<TCP 443>`. Without `--host` that
line names only an address friends elsewhere can reach (a DNS name or a public
IP): when the relay knows only loopback or local-network addresses it gives no
such line and asks for `--host`. A box whose own interface holds the public
IP (a VPS) installed with `RAVEN_RELAY_TCP443=7443` names 443 there, the port
friends reach, not 7443. On a profile it prints
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

Below port 1024 the relay needs `CAP_NET_BIND_SERVICE`. The kit's unit has it;
a unit of your own needs these lines in its `[Service]` section:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

A certbot deploy hook that hands the renewed files to the relay's account and
restarts it, as `/etc/letsencrypt/renewal-hooks/deploy/raven-relay.sh` (mode
`0755`), for a relay started with `--wss-cert /var/lib/raven-relay/wss-fullchain.pem
--wss-key /var/lib/raven-relay/wss-privkey.pem`:

```bash
#!/bin/sh
set -e
install -o raven-relay -g raven-relay -m 600 "$RENEWED_LINEAGE/fullchain.pem" /var/lib/raven-relay/wss-fullchain.pem
install -o raven-relay -g raven-relay -m 600 "$RENEWED_LINEAGE/privkey.pem" /var/lib/raven-relay/wss-privkey.pem
systemctl restart raven-relay
```

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
changes it at any time (applied when the service restarts), and the installer
takes `RAVEN_UPNP=1` or `RAVEN_UPNP=0` (unset: an interactive install that turns
p2p on may ask the same question once; a non-interactive one never asks). When
it is on, the log shows only the mapped external port and whether it worked,
never an IP address: `raven-node p2p: upnp mapped port <port>` or `raven-node
p2p: upnp mapping failed`; `raven status` shows an `upnp` row (the setting and
the mapping result). While this computer relays for your contacts, the relay
asks for its own port (7427) the same way. A mapping opens the port to the whole
Internet. It cannot help when your ISP puts the router itself behind CGNAT (its
WAN address is in 100.64/10 or another private range). RAVEN speaks UPnP-IGD
over IPv4 only; a router that offers only NAT-PMP or PCP (some Apple and ISP
routers) needs a manual forward of TCP and UDP 7423.

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

and `raven node ipv6-pinhole on|off` changes it (applied when the service
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
example `/dns4/relay.example.org/tcp/443/tls/ws/p2p/<relay PeerId>`. A
`raven-card/3` carries that line (and the relay's raw line); a `raven-card/2`
carries only the raw line. Only relay dials use WSS or a proxy: contacts are
reached through those relays, and raw libp2p is never sent through a proxy.

raven-node finds the proxy itself, in this order: `--p2p-proxy` on `raven-node
service`; the `RAVEN_P2P_PROXY` environment variable; `raven node proxy
http://host:port` (saved in `node_policy.json`; `raven node proxy off` never
uses one, `raven node proxy auto` goes back to finding it); `HTTPS_PROXY` (or an
`http://` `ALL_PROXY`) with `NO_PROXY`; then the system setting. `HTTP_PROXY` is
never read. On Linux there is no system setting Raven reads: the systemd user service
sees only its own environment. Put `HTTPS_PROXY=http://proxy.example:3128` (and
`NO_PROXY=...`) in `~/.config/environment.d/50-proxy.conf` and log in again, or
add them to the unit with `systemctl --user edit raven-node`
(`[Service]`, `Environment=HTTPS_PROXY=http://proxy.example:3128`), then
`systemctl --user restart raven-node`. A proxy that needs a password goes the
same way as `Environment=RAVEN_P2P_PROXY=http://user:password@proxy.example:3128`
(that drop-in is a file in your home: keep it readable by you only).

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
a few seconds of re-homing each time). Your cards then carry `p2pn=` (the next
PeerId) right after `p2p=`. A contact that was offline for that whole
announcing period, silent for more than six epochs, or holding a card older
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
| Both PeerIds and IP addresses of every circuit, when it opens, how long it lasts and how many bytes pass; who keeps a reservation on it; with `--autonat-server`, the addresses it is asked to probe | Raven IDs (unless it also holds cards, which map a PeerId to a Raven ID), message text, PairInit, RLB1 offers, route tags, message IDs: all are inside libp2p Noise and, inside that, the Raven Noise link `raven/p2p-link/v1` |

A relay that also holds your friends' cards learns who talks to whom, at the
PeerId level. Your PeerId is stable (unless you turned PeerId rotation on,
above), so it links you across relays and
networks; a stable public IPv6 listen address in a card is a stable location
identifier. Anyone who connects to an open port 7423 learns that node's PeerId
(libp2p names itself in its handshake), but no Raven identity: the Raven link
answers your verified contacts only. libp2p's Identify exchange sends only
addresses confirmed as public (relay circuits, an address AutoNAT found
reachable, a UPnP mapping), never a node's LAN or loopback listen addresses.

Relaying for your contacts adds: the contacts who use your relay learn this
computer's IP address (it is in the offer their route hints carry); the
relay's PeerId is its own key's, not yours, but the cards and route hints of
those contacts carry its address to their own contacts; and inside your circle
a member can tell whether another member is online. Route hints are not
signed, so they prove nothing to anyone else, but a contact can keep what it
was told.

## Bluetooth nearby (macOS only)

Bluetooth nearby lets your verified contacts' laptops in radio range get
your messages with no network at all ([`NEARBY.md`](NEARBY.md)). Release builds
have it on macOS only (since October 2026). Linux has no release Bluetooth backend:
`NEARBY_PRODUCTION_ENABLED` is false here, `linux_systemd_user.sh` builds none, and nearby stays a lab
feature on Linux (a debug build with the feature `nearby-radio`, `RAVEN_LAB_TEST_A=1` and
`RAVEN_LAB_NEARBY=1`). What it needs here, for that lab build: What it will need here:

- **BlueZ access without root.** The user service reaches BlueZ over the
  system D-Bus as you. Desktop distributions allow the logged-in user;
  elsewhere the distribution's `org.bluez` policy decides (often a
  `bluetooth` group). `raven nearby status` says `not allowed` when it
  refuses.
- **A private address.** Raven advertises and connects only from a private
  Bluetooth address. An administrator sets `Privacy = device` under
  `[General]` in `/etc/bluetooth/main.conf` and restarts Bluetooth; without
  it nearby stays inactive on this computer (no advert, no connect).
- **BlueZ running.** `sudo systemctl enable --now bluetooth`; `raven nearby
  status` says when the Bluetooth service is not running.
- **A glibc build.** Static (musl) builds have no Bluetooth backend.
- **Disclosed:** BlueZ sends a link's encrypted notifications to every
  device subscribed to its service (sizes and timing, never content).

Details: [`NEARBY.md`](NEARBY.md) section 6.

## Unsigned tarball

```bash
bash scripts/release/build_unsigned.sh
tar xzf dist/raven-serverless-*-linux-*.tar.gz
cd raven-serverless-*/
./bin/ash --data-dir ./raven-data init
```

If you then start the daemon by hand, bind it explicitly, e.g.
`./bin/raven-node service --data-dir ./raven-data --lan-listen 127.0.0.1:7420`
(the bare default is `0.0.0.0:7420`).

**Checksums are integrity-only.** `SHA256SUMS.txt` ships *inside* the tarball, so
a tampered archive can carry a matching file; checking it only detects accidental
corruption after extraction. For authenticity, compare the separate
`<archive>.tar.gz.sha256` written next to the tarball against a hash you obtained
out-of-band from the builder over a trusted channel (or use a signature). Signing/
packages (deb/rpm) are operator-owned — not produced unsigned.

## Updating Raven (not in this version)

**In this version, update Raven the way you installed it:** run the
installer again from a newer checkout (it copies the new programs over the
old ones and restarts the user service), or unpack a newer tarball. Your
profile stays as it is.

`raven update` is built but held: in every build of this version it says
"Raven updates are not part of this version." Two things are missing before
it can be used. The update switches in the code are off
(`ADVISORY_PRODUCTION_ENABLED`, `RELEASE_BUNDLE_PRODUCTION_ENABLED` and
`MESH_UPDATE_PRODUCTION_ENABLED` are `false`), and no build holds the Raven
project's release keys yet: they are made at the key ceremony
([`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md)), and until then every
build says "This build has no Raven release keys; it can't check updates."
What it does once both exist:

```bash
raven update verify raven-1.5.0-x86_64-unknown-linux-gnu.rrb  # check only, keep nothing
raven update import raven-1.5.0-x86_64-unknown-linux-gnu.rrb  # check it and keep it
raven update install                                          # you type `install`
raven update rollback                                         # back to the version before
raven update                                                  # what waits and what is kept
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
- **Your layout here:** the installer puts `raven` in `~/.local/bin` with
  `ash` as a link to it (or no `ash`, when another `ash` is on the system),
  while a release names its command-line program `bin/ash`. `raven update
  install` replaces `raven` with it and leaves the `ash` link as it is, so it
  names the new program; it never writes through a link and adds no `ash` of
  its own. The unsigned tarball's layout (`bin/ash`, with `bin/raven` a link
  to it) is replaced in place the same way. Programs in the Nix store or a
  snap are never replaced: update them with that package manager.
- **Older releases** only with `--allow-downgrade` and a typed `downgrade`,
  and never below the release floor a security notice sets.
- **Friends pass updates on** (when that part is on too): security notices
  pass from friend to friend by themselves; a release a friend holds is
  offered, `raven update download` lists the offers and downloads one only
  after you answer `y`, and you still install it yourself. Raven never
  contacts a server to look for updates.
- **On Linux:** the swap has been tested in a temporary folder only, not on a
  real installed system yet.

## Notes

- `ash` is also the BusyBox / Alpine shell. The installer only links `~/.local/bin/ash` → `raven` when no other `ash` is on the system; otherwise use `raven`.
- No central message server is configured; see `SERVERLESS_MODEL.md`.
- Identity seed storage: Secret Service when an unlocked keyring answers, else the passphrase vault (above). The mode `0600` `locked-file` seed is a debug/lab/CI-only override that Release builds refuse — see [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).
