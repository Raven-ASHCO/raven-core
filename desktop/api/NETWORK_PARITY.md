# Network parity: the terminal Raven and the desktop apps

Every way a Raven node connects to friends, or helps them connect, and how much of it the desktop
apps can see and change. The source is the code on `feature/desktop-app` after the merge of the main
line at `86cd5cd` (Phases 4, 5 and 6): `raven-core` (the gates and `node_policy`), `ash` (`cli.rs`,
`ext.rs`, `p2p_cli.rs`, `custody_cli.rs`, `nearby_cli.rs`, `lock_cli.rs`, `security_cli.rs`,
`update_install.rs`, `router_probe.rs`), the terminal app (`ash/src/tui/`), `raven-node` and the
desktop engine `raven-client`. The contract is `API.md`; the ops named in the last column are
specified there and implemented in `node/crates/raven-client/src/network.rs` (done in this round,
with the tests named under "Proof").

## How gates work

- Every unfinished way sits behind a `*_PRODUCTION_ENABLED` constant in `raven-core`, all `false`
  except `LAN_DIRECT_PRODUCTION_ENABLED`. A release build never reads a lab switch: every switch is
  read under `cfg!(debug_assertions)`, so a release engine and a release raven-node keep a held way
  off whatever the environment says.
- A **debug** build opens a gate with its lab switch. Most need `RAVEN_LAB_TEST_A=1` as well as
  their own switch (`p2p_gate::lab_flag` and the security gates want exactly `1`;
  `pair_init::lab_switch` also takes `true` or `yes`). The LAN-side switches
  (`RAVEN_LAB_LAN_BEACON`, `RAVEN_LAB_LAN_AUTO`, `RAVEN_LAB_OFFLINE`, `RAVEN_LAB_NOISE_PIN`) and
  `RAVEN_LAB_ROUTE_HINTS` work without `RAVEN_LAB_TEST_A`.
- A security notice from the Raven project can close a gate (`suite_policy::hold_allows`); it never
  opens one.
- Each program decides with its own build: the engine reads its own environment, and the raven-node
  it starts inherits that environment (ext.rs `start_daemon` never clears it) and reads the switches
  again itself. A debug engine with a release raven-node therefore shows a way as `lab` while the
  node keeps it off; `network.status` reports what the node says it runs as well as the gate.

States used below and by `network.status`: **on** (released and switched on), **off** (available,
switched off), **preview** (held in this build), **lab** (on only through a debug build's lab
switch), **not on this OS**.

## The table

| Way | Gate and lab switch (debug only) | CLI and terminal app | Desktop API before this round | Gap | This round |
|---|---|---|---|---|---|
| **LAN direct** | `LAN_DIRECT_PRODUCTION_ENABLED = true` (on). Offline LAN and LAN noise pins: `OFFLINE_LAN`, `LAN_NOISE_PIN` (`RAVEN_LAB_OFFLINE`, `RAVEN_LAB_NOISE_PIN`; approved for release once the cutoff pack is signed off) | `raven lan on\|off`, `lan on --for 30m\|1h\|…`, `lan verified-only on\|off`, `lan status` (`cli.rs` `lan_switch`, `lan_open_for`, `lan_status_lines`); `raven listen`; `raven contact set-addr --lan`. Status/doctor `LAN` row (`lan_row_with`). Terminal app: NET ways "This Wi-Fi or cable", "A laptop's hotspot", "Meeting in person"; Settings "Receive messages on this computer" | `node.status` (`listening`, `receive`, `not_receiving: lan_off`), `contacts.set_address {lan}`, sends plan LAN routes as the CLI does; `raven lan off` is read but cannot be changed | Turn LAN on/off or on for a meeting; see the LAN row | `network.status` carrier `lan` (setting, meeting end, listening addresses, the doctor's LAN row); `network.set {lan, lan_for}` through `lan_switch` / `lan_open_for` |
| **LAN beacon** (finding friends on a new network) | `LAN_BEACON_PRODUCTION_ENABLED = false`; `RAVEN_LAB_LAN_BEACON=1`. Listening on every network: `LAN_AUTO_LISTEN` (`RAVEN_LAB_LAN_AUTO=1`) | Automatic: a send asks raven-node (`LanLocate`) where the friend is now (`beacon_routes`). Status/doctor `LAN search` row (`nearby_row`), `Status.lan.beacon` counts. Terminal app: used by its sends, not shown | Sends use beacon finds (since the first merge) | Not shown | `network.status` carrier `lan_beacon` with the node's beacon state |
| **Internet direct** | `INTERNET_DIRECT_PRODUCTION_ENABLED = false`; `RAVEN_LAB_TEST_A=1` | `raven node internet on --listen 0.0.0.0:7422 \| off` (`cmd_node_internet`, `node_policy.internet_listen`, applied at the node's restart); `raven contact set-addr --internet`; `raven whoami --card --inet`; status `internet` row (`internet_reach_row`). Terminal app: NET "Over the internet" (gate words only) | `NodeStatus.carriers.internet` (`preview`/`on`) and `lab` | No setting, no contact route, no status beyond the gate | `network.set {internet, internet_listen}` (refused while held); carrier `internet` (setting, listening, capability); `contacts.set_routes {internet}` |
| **Port mapping and the router check** | `PORT_MAP` (on P2P; `RAVEN_LAB_PORT_MAP`), `V6_PINHOLE` (`RAVEN_LAB_V6_PINHOLE`), `NAT_CLASS` (`RAVEN_LAB_NAT_CLASS`). The router probe is allowed in release (owner decision O4-10) | `raven node upnp on\|off`, `raven node ipv6-pinhole on\|off`, the one question in `raven node p2p on`; `raven doctor --router` (`router_probe::probe`, read-only PCP/NAT-PMP/SSDP); status rows `upnp`, `router mapping`, `IPv6 pinhole` (`Status.p2p.port_map`). Internet direct (7422) is never mapped: the CLI prints a firewall hint | Nothing | Everything | `network.set {port_mapping}`; carrier `port_mapping` with `Status.p2p.upnp` / `port_map`; `network.check {router: true}` runs the CLI's router probe |
| **WebSocket/TLS on 443 and proxies** | `WSS` (on P2P; `RAVEN_LAB_WSS`), `WSS_PROXY` (`RAVEN_LAB_WSS_PROXY`). No SOCKS; `HTTP_PROXY` is never read | `raven node proxy [auto\|off\|http://host:port]` (`p2p_cli::node_proxy_set` / `node_proxy_show`; credentials only in `RAVEN_P2P_PROXY`); `raven relay card --wss`; `raven relay offer on --also-443` (plain TCP 443 on a friend relay). Status: `p2p_paths`, proxy rows (`Status.p2p.relay_paths`, `proxy`, `proxy_source`) | Nothing | Everything | `network.set {proxy}` through `node_proxy_set` (refuses user names and passwords); carriers `websocket` and `proxy` from `Status.p2p` |
| **p2p: relays and hole punching** | `P2P_PRODUCTION_ENABLED = false`; `RAVEN_LAB_TEST_A=1`. Friend relays: `FRIEND_RELAY` (`RAVEN_LAB_FRIEND_RELAY=1`). PeerId rotation: `PEER_ROTATION` | `raven node p2p on [--listen] [--relay MULTIADDR\|NAME]… [--upnp]`, `p2p off`, `p2p rotate` (`cmd_node_p2p_with`); `raven relay use/allow/deny/auto/status/card`; status REACHABILITY and `p2p_*` rows, doctor `reach_class`, `relay_N`. Terminal app: NET "Over the internet", "Peer-to-peer" in use, last path "p2p · relayed" | `carriers.p2p`, `lab`; cards carry the p2p route; delivered path "p2p · relayed" | No setting, no relays, no reachability | `network.set {p2p, p2p_listen, relays}`; carriers `p2p` and `friend_relay`; `network.status.relays` (relay health, source, the friend who offers it) and listen addresses |
| **Friend custody** (store-and-forward, the mesh) | `FRIEND_CUSTODY_PRODUCTION_ENABLED = false`; `RAVEN_LAB_TEST_A=1`; over the internet `FRIEND_CUSTODY_WAN_ENABLED` (`RAVEN_LAB_CUSTODY_WAN`) | `raven node custody on [--yes]\|off [--purge]\|status` (carry for friends), `raven custody use on\|off\|status`, `custody home`, `contact set-addr --custodian @C`, `outbox hand-off`; the mailbox question after a queued send; `raven contact show`. Terminal app: NET "A friend carries messages" (gate words), outbox codes explained | `carriers.custody`, `lab`; custody outbox codes explained | No consent, no state in either direction, no per-friend custodians | `network.set {carry_for_friends, friends_carry_mine}` (the consent text in the result); `network.status.carry` in both directions; `contacts.routes` / `contacts.set_routes {custodians}` |
| **Sealed letters** | `ASYNC_LETTER` (on `LONG_HORIZON` and custody; `RAVEN_LAB_HORIZON=1`, `RAVEN_LAB_LETTER=1`) | Automatic. `raven node custody status` (letters held, letters left: `ext::letters_left_rows`), `raven outbox status` letter rows | Nothing; letter outbox codes fall back to generic text | Not shown; no path label | Carrier `letters`; message `path_kind: letter` / outbox codes explained |
| **Multi-hop handoff** | `CUSTODY_HANDOFF` (`RAVEN_LAB_CUSTODY_HANDOFF=1`) | `raven node custody handoff on\|off` (`custody_cli::handoff_switch`), counts in `node custody status` (`handoff_status_lines`), `Coverage::TwoFriends` in doctor and `contact show` | Nothing | Everything | `network.set {handoff}`; carrier `handoff` with the counts; message `path_kind: handoff` |
| **Route hints and cards with routes** | `ROUTE_HINTS_PRODUCTION_ENABLED = false`; `RAVEN_LAB_ROUTE_HINTS=1` | `raven whoami --card` (`raven-card/1`, `/2`, `/3`), `contact add --card`, `contact set-addr --lan/--internet/--p2p/--via/--clear`, `raven node hide-ip`, `raven contact hide-ip`; status `route hints` and `hide my IP` rows; `contact verify` shows what a friend told. Terminal app: add-friend shows the card's routes | `card.make`, `card.parse` (route kinds), `contacts.add` saves the card's routes; `contacts.set_address` (LAN only); the p2p route is kept but never shown | A friend's routes, learned routes and hide-IP are not shown or changeable | `contacts.routes` (saved routes, what the friend told, hide IP); `contacts.set_routes`; `network.set {hide_ip}`; carrier `route_hints` |
| **Bluetooth nearby** | `NEARBY_PRODUCTION_ENABLED = false`; `RAVEN_LAB_TEST_A=1` + `RAVEN_LAB_NEARBY=1`; the radio needs raven-node's `nearby-radio` feature (BlueZ on glibc Linux, WinRT on Windows, the RavenNearby helper on macOS); lab ether `RAVEN_LAB_NEARBY_ETHER` | `raven nearby enable\|disable\|on NAME [--for]\|off\|status` (`nearby_cli::cmd_nearby`), `send --carrier nearby`; status NEARBY rows, doctor `nearby:`. Terminal app: plans nearby routes, sends the foreground hint; NET shows Bluetooth as "Not in this version" | Since the merge: sends plan the nearby route and report "Bluetooth nearby" | Not shown, cannot be enabled | `network.set {nearby}` through `cmd_nearby`; carrier `nearby` (radio, in range, address privacy, `not_on_this_os` where no backend exists) |
| **Node policy flags `bridge`, `store`, `relay`** | No gate | `raven node bridge\|store\|relay on\|off` (`set_node_flag`, turns AUTO off); status BRIDGE section, doctor `policy bridge= store= relay=`. **What they do:** `bridge` lets raven-node pass on sealed legacy mesh envelopes that arrive on its bridge listeners (loopback only in a node the CLI or app starts); RVN1 messages to friends do not use it. `store` only matters when the next hop is not ready, which raven-node never reports today: no effect in practice. `relay` is read by nothing in raven-node: no effect. Lending a relay to friends is `raven relay offer` (`FRIEND_RELAY`) | Nothing | Everything, and honest words for what they do | `network.set {bridge, store, relay}` through `node_policy::update_policy` with AUTO off as the CLI does, each with its honest effect; `network.set {relay_for_friends}` for `raven relay offer` |
| **Random listen port** | `LISTEN_PORT_RANDOM` (`RAVEN_LAB_RANDOM_PORT=1`) | Automatic for a new profile (`load_or_create_profile_identity`); `raven lan port random`; the node starts on the profile's port (`default_service_lan_listen_for`) | **Was wrong:** a profile made in the app picked no port and a node the app started used 7420. Fixed in `c1aaa3b` | The port is not shown | `network.status.port` |
| **Link knock and padding** | `LINK_KNOCK` (`RAVEN_LAB_LINK_KNOCK=1`), `LINK_PADDING` (`RAVEN_LAB_LINK_PADDING=1`) | Automatic; no command (the silent-to-strangers setting has no CLI either). Indirect counts in `raven security` | Nothing | Nothing to change; the state is not shown | `network.status.protections` (`link_knock`, `link_padding`) |
| **Lock v2** | `LOCAL_PROTECTION` (`RAVEN_LAB_LOCAL_PROTECTION=1`) | `raven lock [--yes]`, `raven unlock`, `raven passphrase`; v2 when the node answers `Status.locked` (`lock_cli::node_lock_v2`), else Lock now v1 (stop the node). Terminal app: LOCKED screen, idle lock | `privacy.lock` is NOT_AVAILABLE_YET; `privacy.unlock` clears a v1 lock | No v2 lock or unlock | `lock.state`, `lock.now`, `lock.unlock {passphrase?}` through `lock_once` / `unlock_once`; NOT_AVAILABLE_YET (naming `raven lock`) where the node does not serve v2 |
| **Updates from friends** | `ADVISORY` → `RELEASE_BUNDLE` → `MESH_UPDATE` (`RAVEN_LAB_ADVISORY`, `RAVEN_LAB_RELEASE_BUNDLE`, `RAVEN_LAB_MESH_UPDATE`) and a release key set | `raven update status\|import\|verify\|download\|install\|rollback` (`update_install`). Terminal app: UPDATES overlay, NET row | Nothing | Status | `updates.status` (read-only, `update_install::view(dir, false)`); install stays CLI-only |
| **Security events** | `SECURITY_EVENTS` (`RAVEN_LAB_SECURITY_EVENTS=1`); responses and the suite floor on top | `raven security [explain N\|resolve N\|clear] [--json]`; status SECURITY rows, doctor rows, the note before a send. Terminal app: SEC screen | Nothing | The view | `security.status` (`security_cli::app_read`, no write) |

## Message paths

raven-node reports a carrier (`lan_dial`, `internet_dial`, `p2p_dial`, `nearby_dial`) and, for p2p,
a path (`direct`, `reversed`, `relayed`, `hole_punched`); relays say their transport (`tcp`, `quic`,
`wss`, `wss-proxy`). A message a friend held carries no path of its own: the outbox says it was held
(`in_custody`), passed on (`custody_forwarded`) or waits as a letter (`WAITING_FOR_CARRIER`,
`CARRIER_FULL`, `NO_SHARED_CARRIER`). Before this round the engine labelled LAN, Internet and p2p
only. `API.md` now lists every label with a stable `path_kind`.

## Proof (this round)

Real engines and raven-nodes on 127.0.0.1, throwaway profiles, free ports
(`node/crates/raven-client/tests/`): LAN direct between two profiles (`network.rs`), Internet direct
with `RAVEN_LAB_TEST_A` (`net_internet.rs`: the node the engine starts inherits the switch and opens
the listener), p2p relayed through a local `raven-node relay` as the carrier matrix's C6
(`net_p2p.rs`), friend custody with the recipient offline and a third friend holding the message
(`net_custody.rs`), Bluetooth nearby on the fake ether (`net_nearby.rs`; no real radio), the
bridge/store/relay flags reaching the policy `raven doctor` prints and every held way refused
(`network.rs`), and every lab switch inert in a release build (`src/network.rs`, run with
`cargo test --release -p raven-client --lib network::` and every switch set). Not proven here: real
Bluetooth, real routers (port mapping, the router probe against hardware), WebSocket relays, two
machines on different networks.

## What the screens need next

- **All three:** a Network screen built from `network.status` (one row per way: name, state chip,
  reason, a switch where `can_set`, Details with `detail`); the consent sheets for exactly
  `carry_for_friends`, `friends_carry_mine` and `handoff` (`texts`, then `agreed: true`; API.md's
  consent rule), and no sheet for `relay_for_friends` or the bridge/store/relay flags, whose
  honest effect stands beside the switch; "Restart
  the background program" when `restart_needed`; a Check network page from `network.check` (router
  check behind a button); a friend's Routes panel (`contacts.routes`, Internet/p2p entry, mail
  friends); the message path chip from `path_kind`; Security notices, Lock (passphrase field) and
  Updates as read-only pages while their gates are shut.
- **macOS:** the Local Network permission note for `network.check {router: true}`; nearby needs the
  RavenNearby helper app beside Raven.app before it can leave `preview`.
- **Windows:** nearby stays inactive until row N7w (Windows may use the PC's fixed Bluetooth address);
  the engine's `running` for nearby follows raven-node's rule (a public address keeps the radio
  off the air unless a debug build's `RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR` allows it), so it reads
  not running there; the firewall wording for Internet direct and p2p ports.
- **Linux:** nearby needs BlueZ and `Privacy = device`; the network page in the GTK sidebar and the
  tray's status line.

## What stays in the terminal

- Installing an update (`raven update install`), the passphrase (`raven passphrase`), Lock now v1
  (`raven lock` where the node has no v2), relay allow lists and dedicated relays (`raven relay
  allow`, `raven-node relay`), PeerId rotation and the IPv6 pinhole question, purging held mail
  (`raven node custody off --purge`), resolving security notices.
- The terminal app itself does not offer most of these settings either (its NET screen shows the
  gate words only); the desktop apps get them first through this contract.
