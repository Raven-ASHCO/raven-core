# Phase 4 real rows (operator checklist)

**Status:** owner-run, **open**. The one checklist for every Phase 4 row; results
go to `node/proof_artifacts/p4-<ROW>-<UTC>/` (git-ignored) with public IPs
redacted, and are attached to the signature record of the waiver draft that
names the row. The rows are defined in
[`design/2026-10-any-network-reachability.md`](design/2026-10-any-network-reachability.md)
("Real-world test matrix") and the Phase 4 plan
(`docs/roadmap/plans/phase45-design.json`). The plan calls R25-R27 "R15-R17";
Phase 2 already holds those numbers
([`P2_REAL_ROWS_CHECKLIST.md`](P2_REAL_ROWS_CHECKLIST.md)).

| Row | What | Waiver draft | Section |
|---|---|---|---|
| R2b | a NAT-PMP-only or PCP-only router: direct, no relay | [`WAIVER_PORT_MAP_DRAFT.md`](WAIVER_PORT_MAP_DRAFT.md) | 3 |
| R2c | IPv6 behind the router's firewall, a PCP pinhole: inbound direct over IPv6 | [`WAIVER_PORT_MAP_DRAFT.md`](WAIVER_PORT_MAP_DRAFT.md) | 3 |
| R8w | only TCP 443 out; a VPS relay with `--wss 443` | [`WAIVER_WSS_PROXY_DRAFT.md`](WAIVER_WSS_PROXY_DRAFT.md) | 4 |
| R8p | nothing out but an HTTPS proxy set in the system | [`WAIVER_WSS_PROXY_DRAFT.md`](WAIVER_WSS_PROXY_DRAFT.md) | 4 |
| R8m | (optional) a TLS-intercepting proxy, the relay on a real domain certificate | [`WAIVER_WSS_PROXY_DRAFT.md`](WAIVER_WSS_PROXY_DRAFT.md) | 4 |
| R25 | the NAT classifier on real networks (the plan's R15) | [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) §11 | 5 |
| R26 | both laptops on different hotspots: punches skipped, relayed 10/10 (the plan's R16) | [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) §11 | 5 |
| R27 | PeerId rotation across lab-shortened epochs (the plan's R17) | [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) §11 | 6 |
| `doctor --router` | the probe's lines from every router you can reach | [`WAIVER_PORT_MAP_DRAFT.md`](WAIVER_PORT_MAP_DRAFT.md) | 2 |

R8 itself (raw 443 through a kit relay) stays a Phase 2 row.

## 0. Purpose and honest claim

- Real networks and real routers. Every `*_PRODUCTION_ENABLED` gate stays
  `false`, the six Phase 4 gates included (`WSS`, `WSS_PROXY`, `PORT_MAP`,
  `V6_PINHOLE`, `NAT_CLASS`, `PEER_ROTATION`): the rows run debug builds of
  this tree with the lab unlock (`RAVEN_LAB_TEST_A=1`, which
  `node/scripts/wan_two_network_test.sh` sets) and each row's own switches,
  exported in the shell before every command of the script on every machine
  (the script passes them to the node). Nothing here flips a gate.
- Route hints carry the NAT class and the PeerId schedule, so R25-R27 need
  `RAVEN_LAB_ROUTE_HINTS=1` too, and a friend relay `RAVEN_LAB_FRIEND_RELAY=1`.
- Software stand-ins do not replace these rows: carrier_matrix C40-C46, the
  fault scenarios s50-s53 and the netns cases (`netns_restrictive.sh`
  `only443` / `tlsonly` / `proxyonly`; `netns_nat_dcutr.sh` `pcp`, `pcp-cgn`,
  `v6pin`, `classify`, `punch-skip`) run on one kernel with fake routers and
  proxies.
- Test profiles only (`RAVEN_WAN_HOME`, default `~/raven-wan-test`), never
  `~/.raven`, a live node's folder, or a profile an older binary still uses: a
  build of this tree seals a profile at its first start (a debug build only
  with `RAVEN_LAB_AT_REST=1`), and older builds then refuse it. A running owner
  node keeps its ports; give the test nodes ports of their own.
- Never point `RAVEN_LAB_PORTMAP_GATEWAY` at anything for these rows: with it
  set, the probe and the mapper talk to that address only (the doctor's SSDP
  search included), which is the lab's fake router, not yours, and the node
  never starts UPnP-IGD (not with the PORT_MAP gate closed, and not after a
  silent probe: it logs `no PCP or NAT-PMP answer; UPnP not tried (lab
  router)` instead of `trying UPnP`).

## 1. Gear

- A VPS with a public IPv4 (and IPv6 for R2c's other end, if the home side
  lacks it), about EUR 5 a month, for the dedicated relay of R8w, R8p, R25-R27;
  for R25 a second relay on another /24 (a second VPS, or a friend relay on a
  home line with a port forward).
- For R2b, a router that speaks NAT-PMP or PCP but not UPnP: OpenWrt with
  miniupnpd and UPnP off (`enable_upnp=no`, `enable_pcp_pmp=yes`), or an Apple
  AirPort. For R2c, a router with IPv6 on the WAN, a default-deny IPv6 firewall
  and PCP (miniupnpd with IPv6), and a contact with IPv6.
- For R8w/R8p, sudo (macOS, Linux) or an administrator (Windows) on the laptop
  to filter its own egress, and for R8p an HTTPS proxy on another machine:
  squid, or `node/scripts/lib/tiny_connect_proxy.py --listen 0.0.0.0:3128`
  on a private LAN for the length of the row only (a lab tool, never a proxy
  for real traffic). For R8m, mitmproxy and a domain with a certificate for
  the relay.
- For R25 and R26, a phone hotspot, a second phone hotspot or a SIM dongle,
  and a home line.
- For R27, two laptops on two networks and an always-on computer that both
  have as a contact (the friend relay).

## 2. Record for every row

`node/proof_artifacts/p4-<ROW>-<UTC>/` holds:

- `row.txt`: the row, the date, the commit under test, who ran it, the OS of
  each machine, each network by kind only (home line, phone hotspot, SIM
  dongle, VPS provider; router model for R2b/R2c), the switches exported;
- `raven doctor --router` from each network a node sat on (its lines name no
  address; on macOS a refused probe adds a Local Network line: allow the
  terminal app under System Settings > Privacy & Security > Local Network and
  run it again);
- `raven status` and `raven doctor` of each node after the sends, with every
  PeerId, label and public IP replaced (`<peer-1>`, `<label-1>`,
  `<public-ip>`);
- the `path=` of every delivery (`three send` writes
  `three-TAG-<UTC>.tsv`) and the counts-only daemon lines the row names;
- the R8 scripts' own file (`node/proof_artifacts/R8<w|p|m>-<os>-<date>.txt`)
  moved into the row folder;
- the pass or fail against the bar below, and anything that surprised you.

**`raven doctor --router` on every router** you can reach (home, office,
friends' routers with their consent, a hotspot): save the seven
`router_*=` lines per router in `p4-doctor-router-<UTC>/<kind>.txt`. They decide
O4-9's question: a router with `router_ipv6_firewall_control=yes` and
`router_pcp=no` is the evidence the skipped P4.22 (UPnP-IGDv2 pinholes) waits
for.

## 3. The router rows

### R2b: a NAT-PMP-only or PCP-only router

- Laptop B behind that router, with no port forward and no UPnP; first
  `raven doctor --router` there: `router_pcp=yes` or `router_natpmp=yes`, and
  `router_upnp_igd=no`. Laptop A on another network; a relay R on the VPS
  (`vps-relay start <public IP>`), both allowed on it.
- On both, `export RAVEN_LAB_ROUTE_HINTS=1`; on B also
  `export RAVEN_LAB_PORT_MAP=1`. Run `three setup` and `three add` as in the
  P1 checklist, then on B
  `ash --data-dir "$RAVEN_WAN_HOME/<NAME>" node upnp on` (the consent, which
  covers NAT-PMP and PCP for IPv4).
- B: `three send A 1` (restarts B's node); B's log shows
  `router port mapped (PCP, port <port> tcp+udp)` or the same with `NAT-PMP`,
  and
  `raven status` a `router mapping` row.
- A: `three send B 10`; B: `three send A 10`.
- Stop B's node (`three stop`) and, where the router shows its mapping table,
  record whether the mapping is gone (removal is best effort; a crash or a
  network change leaves it until its lease ends).
- Pass: 10/10 both ways; after the first message (route hints) A's sends to B
  are `path=direct` with no relay circuit for them on R
  (`vps-relay status` counts) and no hole punch.

### R2c: IPv6 behind the router's firewall, a PCP pinhole

- Laptop B behind a router with IPv6 and its default IPv6 firewall (inbound
  closed), PCP on: `raven doctor --router` shows `router_gateway_v6=found` and
  `router_pcp=yes`. Laptop A anywhere with global IPv6.
- On B also `export RAVEN_LAB_V6_PINHOLE=1` (with `RAVEN_LAB_PORT_MAP=1`), then
  `ash --data-dir "$RAVEN_WAN_HOME/<NAME>" node ipv6-pinhole on` after the
  UPnP yes; restart B's node. B's log: `IPv6 pinhole open on the router
  (PCP)`; `raven status`: the `IPv6 pinhole` row open.
- Control first: with `node ipv6-pinhole off`, A's direct dial to B's IPv6
  address fails (inbound closed) and messages go relayed.
- Then A: `three send B 10`.
- Pass: 10/10 with A's dial inbound to B over IPv6 `path=direct`; with the
  pinhole off, relayed. If the router has `router_ipv6_firewall_control=yes`
  and `router_pcp=no`, record that and stop: that is the IGDv2 case (P4.22).

## 4. The restrictive-network rows

The relay for all three, on the VPS, by hand (the relay kit keeps raw 443 until
the WSS flip): a debug build of this tree, its own folder, never a profile:

```sh
export RAVEN_LAB_TEST_A=1 RAVEN_LAB_WSS=1
BIN=<cargo target dir>/debug          # the debug build of the commit under test
sudo systemd-run --unit raven-r8-relay -p AmbientCapabilities=CAP_NET_BIND_SERVICE \
  -p User="$USER" --setenv=RAVEN_LAB_TEST_A=1 --setenv=RAVEN_LAB_WSS=1 \
  "$BIN/raven-node" relay --data-dir "$HOME/raven-r8-relay" \
  --wss 443 --public-host <public IP or DNS name>
"$BIN/raven" relay card --data-dir "$HOME/raven-r8-relay" --wss --host <public IP or DNS name>
"$BIN/raven" relay allow --data-dir "$HOME/raven-r8-relay" --card '<card of A>'   # and B
```

(`--public-host` names the TCP 443 port as a plain TCP address too: the same
port takes raw libp2p.) For R8m add `--wss-cert <fullchain.pem> --wss-key
<privkey.pem>` and use the `/dns4/<domain>/tcp/443/tls/ws/...` line. Stop it
afterwards with `sudo systemctl stop raven-r8-relay`.

On laptop A run `three setup NAME VIA` with the relay's `/tls/ws` line as VIA
and `three add` the other machine B (any network), then the script, from the
repository: `node/scripts/r8_only_443.sh` (macOS, Linux; sudo) or
`node\scripts\r8_only_443.ps1` (Windows; an administrator, never over Remote
Desktop). It applies the filter, checks it (443 open, 7423 closed), restarts
A's node under it with the WSS switches, sends, waits for B's messages
(B runs `three send <tag of A> 10` meanwhile), writes its file and always puts
the firewall back. `--print-rules` prints the filter without applying it.

### R8w: only TCP 443 out

```sh
node/scripts/r8_only_443.sh --i-understand --mode w --relay-host <relay host> --tag bob
```

- Pass: 10/10 both ways, every A -> B message `relayed`, each B -> A message
  once, relay transport `wss`. Record whether the relay bound 443 as an
  ordinary user on macOS, if the relay ran on a Mac.

### R8p: only an HTTPS proxy out

- Set the proxy in the system, not in Raven: macOS System Settings > Network >
  (the service) > Details > Proxies > Secure web proxy (HTTPS); Windows
  Settings > Network & internet > Proxy > Use a proxy server; Linux
  `~/.config/environment.d/` (`HTTPS_PROXY=http://<proxy>:3128`, then log in
  again) or `HTTPS_PROXY` in this shell. The script clears `RAVEN_P2P_PROXY`
  and exports `RAVEN_LAB_WSS_PROXY=1`.

```sh
node/scripts/r8_only_443.sh --i-understand --mode p --proxy <proxy host>:3128 \
  --relay-host <relay host> --tag bob
```

- Pass: 10/10 both ways as in R8w, relay transport `wss-proxy`; A's `raven
  status` p2p row says "relay over WSS through the HTTPS proxy; restricted
  network (relay only)". Record the time to the first delivery (the 10 s
  connection timeout covers proxy, CONNECT, TLS, WebSocket, Noise and Yamux).

### R8m (optional): a TLS-intercepting proxy

- mitmproxy as the system proxy (R8p's filter, `--proxy`) or as a transparent
  gate, the relay with an operator certificate for a real domain.
- Pass: 10/10 both ways, relay transport `wss-proxy` (or `wss`). Also record
  the self-signed case once: the dial fails and the status says so (expected:
  interception needs an operator certificate).

## 5. The NAT class rows

On every node: `export RAVEN_LAB_ROUTE_HINTS=1 RAVEN_LAB_NAT_CLASS=1`.

### R25: the classifier on real networks

- Laptop A with two relays on different /24 networks (the VPS relay R and a
  second relay R2), both allowing A: after `three setup NAME <VIA of R>`, add
  R2 with `ash --data-dir "$RAVEN_WAN_HOME/<NAME>" node p2p on --listen <the
  same listen address> --relay <VIA of R> --relay <VIA of R2> --no-upnp` and
  restart the node (`three send <tag> 1`).
- On each network in turn (the home line, a phone hotspot, a SIM dongle): let
  the node hold both reservations for 2 minutes, then save `raven doctor`
  (`nat_mapping: tcp=.. quic=.. observers=.. punch_skipped=.. punch_failed=..`)
  and the `p2p_nat` row of `raven status`, and the daemon line
  `NAT mapping <tcp word> (tcp), <quic word> (quic) from N networks`.
- Pass: on each network `observers=2` and a class recorded for TCP and QUIC
  (`unknown` with two observers is a finding to record, not a pass).

### R26: both laptops on different hotspots

- A and B each on its own phone hotspot (or one on a SIM dongle), the VPS
  relay R, both allowed, cards exchanged.
- A: `three send B 10`; B: `three send A 10`; then `three rate B 5` on A.
- Pass: 10/10 both ways, every message `relayed`; after the first message (the
  route hint exchange) each daemon log shows `hole punch skipped (both NAT
  mappings vary); staying on the relay` (or `(two attempts failed on this
  network)` when a class stays unknown: record which), no `direct connection
  upgraded`, and `raven doctor` `punch_skipped` of 1 or more. Record the data
  used on each hotspot during the row.

## 6. PeerId rotation

### R27: rotation across lab-shortened epochs

- A and B on two networks; the VPS relay R (a dedicated relay: not a
  contact); F, an always-on computer that both have as a verified contact, with
  `raven relay offer on` (a friend relay). All of them use test homes.
- On A, B, F and in R's operator shell:
  `export RAVEN_LAB_ROUTE_HINTS=1 RAVEN_LAB_FRIEND_RELAY=1
  RAVEN_LAB_PEER_ROTATION=1 RAVEN_LAB_PEER_EPOCH_S=600` (the same epoch length
  everywhere: a relay computes expiry with its own).
- B: `ash --data-dir "$RAVEN_WAN_HOME/<NAME>" node p2p rotate on`. B's
  `p2p_rotation` row goes `waiting` until A and F have announced `capable`
  (one route hint exchange each), then `starting` (the coming network IDs
  are announced), then `on` at the first boundary at least half an epoch
  later.
- B: `ash --data-dir ... relay schedule` prints one line; R's operator runs
  `raven relay allow --data-dir <relay folder> --schedule -` and pastes it (on
  a kit relay `sudo raven-relay allow --schedule -`; the kit's wrapper clears
  the environment, so the entries then expire on a 28-day reckoning, later
  than the lab epochs, which this row does not test).
- Across at least three boundaries: A sends 3 messages to B after each
  boundary, B sends 3 to A.
- Postponement: R's operator denies B's next-epoch PeerId
  (`raven relay deny --data-dir <relay folder> <PeerId>`); at that boundary B's
  log shows `network ID rotation postponed`, its row `postponed`, and messages
  still arrive (through F, or the previous ID on R).
- Pass: every message delivered exactly once; B's status `peer_id` changes at
  each boundary (record how many distinct values, never the values); B's log
  says `network ID rotated (epoch boundary)` and no log of A, B, F
  or R names a PeerId (search each log for B's PeerIds: 0 hits); A's dials
  carry the counts-only `peer_epoch=current` (or `other`) token.
- Known limit to note, not to test: a contact offline for the whole announcing
  period cannot follow over p2p until a route hint reaches it another way or
  a new card is exchanged.
