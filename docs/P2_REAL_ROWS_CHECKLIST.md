# Phase 2 real rows (operator checklist)

**Status:** owner-run, **open**. The one checklist for every Phase 2 row; results
go to `node/proof_artifacts/p2-<ROW>-<UTC>/` (git-ignored) with public IPs
redacted, and are attached to the signature record of the Phase 2 amendment of
[`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md). The rows are defined
in [`design/2026-10-any-network-reachability.md`](design/2026-10-any-network-reachability.md)
("Real-world test matrix"). The rows:

| Row | What | Section |
|---|---|---|
| R8 | 443-only egress through a kit relay | 3 |
| R18 | a Raspberry Pi with a port forward (kit) | 3 |
| R19 | a EUR 5 VPS (kit) | 3 |
| R20 | a Windows logon-task relay (advisory) | 3 |
| R3/R5/R9 | the Phase 1 rows again after a relay change, without new cards | 4 |
| R15 | hide my IP (packet capture) | 4 |
| R16 | a LAN listen-port change between two Macs | 4 |
| R13 | a friend relay laptop closes its lid, with two other operators | 5 |
| R17 | a friend relay laptop moves to another UPnP network | 5 |
| R9-d, R13-d, R-off, R14-d | what the diagnosis says (exact texts) | 6 |
| R-noroute | a laptop with no default route: no internet-side advice | 6 |

## 0. Purpose and honest claim

- Real networks and real boxes. Every `*_PRODUCTION_ENABLED` gate stays
  `false`: the kit installs lab builds only (`RAVEN_RELAY_LAB=1`, a debug build
  with the lab unlock; [`RELAY_KIT.md`](RELAY_KIT.md) section 0), and the test
  profiles use the lab unlock too. Route hints need the debug switch
  `RAVEN_LAB_ROUTE_HINTS=1` and friend relays `RAVEN_LAB_FRIEND_RELAY=1`:
  `wan_two_network_test.sh friend-host` / `friend-use` set both for their
  test home; for the other rows export `RAVEN_LAB_ROUTE_HINTS=1` in the shell
  before every command of the script on every machine (the script passes it to
  the node). Nothing here flips a gate.
- Software stand-ins do not replace these rows: CI installs the kit on a GitHub
  runner (Linux unit, macOS plist, Windows task) and the carrier matrix and
  netns cases run on one kernel.
- Test profiles only (`RAVEN_WAN_HOME`, default `~/raven-wan-test`), never
  `~/.raven`, `~/raven-try` or a live node.

## 1. Gear

- A Raspberry Pi 4 or 5 (64-bit OS) on a home router that has a public WAN
  address (not CGNAT: [`RELAY_KIT.md`](RELAY_KIT.md) section 2) and allows a
  port forward.
- A small Linux VPS with a public IPv4 (about EUR 5 a month).
- Laptop 1 and laptop 2 (or the Mac Studio), a phone hotspot, and for R8 sudo
  on a Mac or Linux laptop to restrict egress (pf or nftables).
- For R20, a Windows 10/11 PC.
- For R13 and R17, three laptops or desktops that can each be reached from the
  internet (a public IP, UPnP, or a forward of TCP and UDP 7427), one of them
  a laptop; for R17 a second network with a UPnP router.
- For R15, sudo for `tcpdump` on B; for R16, two Macs on one home network.
- For the diagnosis rows, two phone hotspots (or a phone and a SIM dongle),
  and for R-noroute a network that gives the laptop no default route: a Wi-Fi
  or cable network where the laptop has a manual IP address and no router
  (gateway) set, or a cable between two laptops with only self-assigned
  (169.254.x.x) addresses.

## 2. Record for every row

`node/proof_artifacts/p2-<ROW>-<UTC>/` holds:

- `row.txt`: the row, the date, the commit under test, who ran it, both
  networks (kind only: home Wi-Fi, hotspot, VPS provider; no IPs);
- the installer output (public IPs replaced by `<public-ip>`);
- `raven-relay status` before and after, with every friend PeerId, label and
  public IP replaced (`<peer-1>`, `<label-1>`, `<public-ip>`): status lists the
  allow-list and the relay's own addresses, it is not counts only; and `raven
  status` of each laptop after the sends (the relay row);
- the `path=` of every delivery (`raven send` output or the daemon log line);
- for the diagnosis rows, the **exact** texts: the `raven send` output, the
  REACHABILITY and NOT REACHABLE NOW sections of `raven status`, `raven
  doctor`, and `raven outbox list` where a message waits, each with the time
  it first showed;
- the pass or fail against the bar below, and anything that surprised you.

## 3. The relay kit rows

### R8: 443-only egress through a kit relay

- The relay: the VPS of R19, installed with `linux_relay.sh` and
  `RAVEN_RELAY_TCP443=direct` (the default), or with
  `wan_two_network_test.sh vps-relay start <public IP> --kit`, which runs the
  same installer on the lab build.
- Laptop A behind an egress filter that allows only TCP 443 and DNS (macOS pf
  or Linux nftables; write the rule set into `row.txt`), laptop B on another
  network. `node/scripts/wan_two_network_test.sh egress443 print [RESOLVER]`
  prints both rule sets with the commands that apply and remove them; it
  never applies anything. Remove the filter when the row is done. Both ran
  `raven relay use` with the relay's TCP 7423 and TCP 443 lines, both are on
  the relay's allow-list, and they exchanged cards.
- 10 messages each way (`raven send`), the sender's node restarted before
  the first one so it holds no earlier connection.
- Pass: 10/10 both ways with `path=relayed`; A's `raven status` relay row shows
  the reservation held on the **443** address (the 7423 one is filtered), and
  `raven-relay status` counts circuits.

### R18: a Raspberry Pi with a port forward

- Install on the Pi: `RAVEN_RELAY_HOST=<public IP or DNS name> RAVEN_RELAY_LAB=1
  bash node/scripts/install/linux_relay.sh`; forward TCP+UDP 7423 and TCP 443
  on the router; `raven-node relay-probe` from a phone hotspot prints
  `reachable` for every line.
- Two friends (laptops on two other networks) run `raven relay use ...`, are
  allowed with `raven-relay allow --card`, and exchange cards.
- 10 messages each way.
- Reboot the Pi and do **not** log in: the relay is back with the same PeerId
  (`raven-relay status`) and the friends reserve again on their own.
- Update by re-running the same command: the installer says the PeerId is
  kept.
- After 24 h: record the log volume of the unit
  (`journalctl -u raven-relay --since -24h | wc -c`) and how many counts lines
  it wrote.
- Pass: 10/10 relayed both ways, same PeerId after the reboot and the update,
  and the logs hold counts only (no IP, no friend PeerId).

### R19: a EUR 5 VPS

- Install as in R18 on the VPS; open TCP+UDP 7423 and TCP 443 in the provider's
  firewall and with ufw (the lines the installer printed).
- The same two friends, 10 messages each way.
- Record `sudo raven-relay status` after the 10 messages: `MemoryCurrent`,
  `IPIngressBytes`, `IPEgressBytes`, `NRestarts`.
- Pass: 10/10 relayed both ways, `NRestarts=0`, and the unit runs as user
  `raven-relay` with only `CAP_NET_BIND_SERVICE`.

### R20: a Windows logon-task relay (advisory)

- Install with `windows_relay.ps1 -PublicHost <it> -Lab` and the printed
  Private-profile firewall rules; forward the ports if the PC is behind a
  router.
- Two friends as in R18, 10 messages each way.
- Then sign out, and separately let the PC sleep: record what the friends see
  (the reservation is lost; `raven status` and the send text) and how long
  until it is back after sign-in or wake.
- Pass (advisory): 10/10 relayed while signed in and awake; the sign-out and
  sleep behaviour recorded, matching the Q9 stance (no relay while signed out
  or asleep).

## 4. The route hint rows

Every machine runs with `RAVEN_LAB_ROUTE_HINTS=1` (section 0). `raven status`
then shows a `route hints` row (`on (lab) · told N contacts · learned from
N`) and a `hide my IP` row.

### R3/R5/R9 after a relay change, without new cards

- Set up R3, R5 and R9 as in
  [`P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md`](P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md)
  (three-node mode), with route hints on, plus a second relay R2 (a second
  VPS, or a kit relay of R18/R19) that allows A and B.
- 10 messages each way through R, as in Phase 1.
- B moves to R2: `raven relay use` with R2's lines (or `three setup NAME
  VIA` with R2's VIA), and its node restarts. Nobody exchanges cards.
- A sends 10 messages to B (each `three send` restarts A first).
- Pass: 10/10 `path=relayed`, through R2 (`vps-relay status` on R2 counts
  circuits, on R none after the move); A's `contacts.json` is byte-identical
  before and after (compare checksums); A's `route hints` row says it learned
  from B.

### R15: hide my IP

- A and B in two-node mode (`setup`) on two networks, both using one relay
  (a kit relay, `raven relay use`), with A reachable from the internet (a
  public IP, UPnP or a forward of 7423), so that without hiding A and B link
  directly or hole-punch.
- Control: 3 messages each way; at least one is `direct`, `reversed` or
  `hole_punched`.
- On A: `raven contact hide-ip <B> on`, then one message to B (its route hints
  withdraw A's address). Restart both nodes.
- On B, capture: `sudo tcpdump -n -i any host <A's public IP>` (the IP stays in
  your notes, never in the artifacts).
- 10 messages each way.
- Pass: 10/10 `path=relayed` both ways, no DCUtR upgrade line in either log,
  and the capture shows no packet between B and A's public IP. A's `raven
  status` says `hide my IP: off (1 contact hidden)`.
- Variant (B's own relay): B also runs a kit relay on a third host and uses it
  beside the shared one (`raven relay use`), so B's route hints name it. Capture
  on that third host: `sudo tcpdump -n -i any host <A's public IP>`. Pass: 5
  messages each way are `relayed` through the shared relay, and that capture
  shows no packet from A.

### R16: a LAN listen-port change between two Macs

- Mac 1 and Mac 2 on one home network, two-node mode, route hints on; one run
  with verified contacts (`add` with the fingerprint) and one with unverified
  ones (the LAN-only rule: they get the LAN port only).
- 3 messages each way.
- Mac 2 stops and comes back on another LAN port:
  `RAVEN_WAN_LAN_PORT=7431 node/scripts/wan_two_network_test.sh setup NAME`
  (same test home, so the same identity).
- Mac 1 sends 3 messages before Mac 2 sends anything, then 3 after Mac 2 sent
  one.
- Pass: every message delivered once; the messages Mac 1 queued arrive
  within 30 s of Mac 2's return (its announce) or of its first message; no
  address typed; after Mac 1's next `raven send` its contact book holds the
  new port (`lan_dial` of Mac 2 in Mac 1's `contacts.json`). Optional: one Mac
  on a build from before route hints: every message once, nothing learned.

## 5. The friend relay rows

### R13: a friend relay laptop closes its lid

`node/scripts/wan_two_network_test.sh friend-sleep` prints the steps: three
operators O1 (the laptop), O2 and O3, each `friend-host`; B behind a NAT holds
two relays picked from the offers (`friend-use` each operator once; `raven
doctor` `relay_1_source=offer`, `relay_2_source=offer`, `relay_standby=1`);
C sends. Close the lid of B's first relay's operator and keep sending, one
message a minute for 15 minutes; then open the lid.

- Pass: every message delivered (record the longest wait, `gap_s`); B logs
  `raven-node p2p: relay replaced` within about 12 minutes of the lid closing
  (`replaced_s`; the real timers: 10 minutes of loss, then the replacement);
  after the lid opens, B logs no second `relay replaced` for 30 minutes and
  keeps its new relay. These timers are the owner's guesses: record whether
  they felt right.

### R17: a friend relay laptop moves to another UPnP network

- Operator O (a laptop) on network 1 with UPnP on (`setup` turns it on),
  `friend-host`; B behind a NAT `friend-use O` and holds O's relay plus a
  second offered relay (a second operator, as in R13); C sends to B.
- 3 messages C -> B.
- Move O to network 2 (another UPnP router) without stopping it. Its
  netwatch notices the change, the friend relay starts over with the same key,
  and UPnP maps its port on the new router.
- Pass: within 10 minutes B holds O's relay at its new address (`raven
  status` relay rows; no card exchanged, B's `contacts.json` unchanged), and 3
  more messages C -> B are delivered once, `relayed`. Record how long B took to
  follow (`follow_s`).

## 6. The diagnosis rows

What each text should say is listed in
[`../protocol/RAVEN_ERROR_CODES_V1.md`](../protocol/RAVEN_ERROR_CODES_V1.md)
section 2.1 (the reasons) and in the install guides (the `circle` row and the
NOT REACHABLE NOW section). Record each text exactly (section 2); no text may
name an address or a PeerId.

### R9-d: both on phone hotspots, no relay

- A and B on two different phone hotspots, p2p on, no relay set, no
  contact who offers relaying.
- A sends to B. Record A's send text, its `raven status` (REACHABILITY and NOT
  REACHABLE NOW) and `raven doctor`.
- Then start a kit relay (R19's VPS), both `raven relay use` its lines and are
  allowed (`raven-relay allow --card`); do **not** send again.
- Pass: the text says both are behind NAT and names the three fixes (a
  friend who offers relaying, the relay kit, a port forward); the doctor
  counts `both_nat=1`; after the relay, the waiting message is delivered with
  no new send (record the time from `raven relay use` to delivery).

### R13-d: the friend relay laptop sleeps

- R13's setup, but B holds only the sleeping laptop's relay (no standby).
- Close the lid; C sends to B.
- Pass: C's text says B's relay is not answering (asleep or switched off) and
  that the message waits; B's `raven status` W1 advice names the operator
  ("ask … to wake that computer"); both within 60 s of the lid closing
  (record time-to-text). Open the lid: the message is delivered once (record
  time-to-delivery).

### R-off: the recipient's lid closes

- A and B on one kit relay, both reserved. Close B's lid (sleep).
- A sends to B.
- Pass: A's text says B is offline (B's relay answered that B is not
  connected) and that raven-node keeps trying; `raven outbox list` says
  `offline: not connected to their relay`. Record how long until the text
  shows. Open B's lid: delivered once.

### R14-d: a stranger with a card is refused

- With R14 ([`P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md`](P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md)):
  the stranger S holds B's card, B does not know S.
- Pass: S's send says it was turned away and what to do (B's RAVEN does not
  have S's card); B logs only the counts-only gate refusal; the R14 captures
  show no packet between S and B (no candidate used).

### R-noroute: a laptop with no default route

What raven-node can tell is a local fact only: whether this computer has a
default route (it never probes an outside host). A hotspot or router whose
upstream is dead (a phone hotspot with mobile data off, a router with its WAN
cable out) still hands out a default gateway by DHCP, so raven-node cannot
tell it from a working network: there the texts keep their relay and NAT
reasons (`relay_asleep`, `both_nat`) and their internet-side advice. This row
therefore uses a network with **no default route**.

- A laptop and a contact on one network where the laptop has no default
  route: on macOS, Wi-Fi or Ethernet > Details > TCP/IP, Configure IPv4
  Manually with an address and subnet mask and an empty Router field (or a
  cable between two laptops with only self-assigned 169.254.x.x addresses);
  check with `route -n get default` (macOS) or `ip route show default`
  (Linux) that there is none. The P2P lab unlock on; the contact's LAN address
  saved; another contact reachable only over the internet.
- Send to both; record the send texts, `raven status` and `raven doctor`.
- Pass: no text advises a relay, the relay kit, a VPS, UPnP or a port
  forward; `raven status` says this computer has no route to the internet and
  that only people on this network can be reached (W0); `raven doctor` says
  `internet_route: none`; LAN delivery to the contact on the same network 3/3.
- Also record, as information only (not a pass condition): the same sends on
  a phone hotspot with mobile data off. Expected there: no W0, and the relay
  or NAT reason with its advice, because the hotspot still gives a default
  route.
