# Phase 3 real rows (operator checklist)

**Status:** owner-run, **open**. Nothing here is run, signed or flipped yet.
The one checklist for every Phase 3 row; results go to
`node/proof_artifacts/p3-<ROW>-<UTC>/` (git-ignored) with IP addresses
redacted, and are attached to the signature record of
[`WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md`](WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md)
(R1, R1b, R11a-f, R21-R24) or [`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md)
(R10, R10b, R10r, R11g); R11j goes to the cutoff pack's
[`WAIVER_LAN_DIRECT_CUTOFF_AMENDMENT_DRAFT.md`](WAIVER_LAN_DIRECT_CUTOFF_AMENDMENT_DRAFT.md)
(§5, "Hardware, open"), and R11d+, R11e+, R11h and R11i go with the
statements of [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) they verify. The rows of
sections 3-6 are defined in
[`design/2026-10-any-network-reachability.md`](design/2026-10-any-network-reachability.md)
("Real-world test matrix"); section 7 defines the cutoff study's additions.
The rows:

| Row | What | Section |
|---|---|---|
| R1 | same home Wi-Fi, no addresses typed | 3 |
| R1b | guest Wi-Fi with client isolation | 3 |
| R21 | `raven lan off` at a cafe (tcpdump) | 3 |
| R22 | a DHCP move | 3 |
| R23 | cross-OS LAN pairs, with the Windows numeric zone | 3 |
| R11a | a router with its WAN unplugged | 4 |
| R11b | a Linux `nmcli` hotspot | 4 |
| R11c | a cable, per OS pair | 4 |
| R11d | a Windows Mobile hotspot without Internet | 4 |
| R11e | macOS Internet Sharing without uplink | 4 |
| R11f | a phone hotspot without mobile data | 4 |
| R10, R10b, R10r | friend custody over the internet (the Mac Studio as custodian) | 5 |
| R11g | a custodian laptop on an offline LAN | 5 |
| R24 | session renewal across a long absence | 6 |
| R11e+ | macOS Internet Sharing without uplink: one typed address, and a launchd-started node | 7 |
| R11d+ | a Windows Mobile hotspot host in the Public profile | 7 |
| R11h | a Fedora `nmcli` hotspot with firewalld (`nm-shared`) | 7 |
| R11i | Bluetooth PAN, Windows and Linux (macOS if possible) | 7 |
| R11j | M0: another Raven laptop at a friend's old DHCP address (tcpdump) | 7 |

## 0. Purpose and honest claim

- Real networks and real machines. Every `*_PRODUCTION_ENABLED` gate stays
  `false`: the rows run debug builds with lab switches, exported in the shell
  on every machine before every command:
  - LAN rows (sections 3 and 4): `RAVEN_LAB_LAN_BEACON=1` (nearby search) and,
    where a row says so, `RAVEN_LAB_LAN_AUTO=1` with `--lan-listen auto`;
  - custody rows (section 5): `RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_ROUTE_HINTS=1`
    and `RAVEN_LAB_CUSTODY_WAN=1` (`wan_two_network_test.sh` exports the last
    two in two-node mode), plus `RAVEN_LAB_LAN_BEACON=1` for R11g;
  - renewal (section 6): `RAVEN_LAB_SESSION_RENEWAL=1`;
  - the cutoff rows (section 7): `RAVEN_LAB_OFFLINE=1` and
    `RAVEN_LAB_NOISE_PIN=1` (the two cutoff gates, always together, as they
    flip), and nothing else unless the row says so.
  Release builds never read these switches. Nothing here flips a gate.
- Software stand-ins do not replace these rows: carrier_matrix C27-C36,
  C38 and C39 (there is no C37), lan_fault_matrix s04, s30p/s30w/s30r and
  s80-s99, and the netns `lan-*`, `custody` and `netns_offline.sh` cases run
  on one kernel ([`NAT_SOFTWARE_SIM.md`](NAT_SOFTWARE_SIM.md)).
- **Test homes only** (`RAVEN_WAN_HOME`, default `~/raven-wan-test`, or a
  `--data-dir` you created for the row), never `~/.raven`, a live profile or
  a node already listening on 7420. On a machine that runs another Raven
  node, give the test node a free LAN port (`RAVEN_WAN_LAN_PORT`) and record
  it.
- The steps that change a system (a hotspot, a cable address, a firewall
  rule, `tcpdump`) are yours to run; [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md)
  §3-§5 has the commands, still marked UNVERIFIED until these rows pass.

## 1. Gear

- Two Macs, or a Mac and a Linux or Windows machine; for R23 one of each pair
  (Mac and Linux, Mac and Windows).
- An Ethernet cable or USB/Thunderbolt adapters (R11c).
- A router whose WAN cable can be unplugged (R11a), a guest Wi-Fi with client
  isolation (R1b), a phone hotspot (R11f), and a cafe or other shared Wi-Fi
  (R21).
- A Linux laptop with NetworkManager (R11b), a Windows 10/11 laptop (R11d).
- The Mac Studio with the D15 forward (TCP and UDP 7423) as the custodian
  (R10, R10b), and for R10r also as the friend relay (7427).
- `sudo` for `tcpdump` (R21, R11j; optional elsewhere).
- For section 7: a Fedora laptop with NetworkManager and firewalld (R11h);
  Bluetooth on the Windows and the Linux laptop (R11i); a Mac user account
  with no other Raven login service (R11e+, see there); a third laptop that
  runs a Raven test node of its own (R11j).

## 2. Record for every row

`node/proof_artifacts/p3-<ROW>-<UTC>/` holds:

- `row.txt`: the row, the date, the commit under test, who ran it, the OS
  pair, the network kind (home Wi-Fi, guest Wi-Fi, hotspot, cable, cafe; no
  IPs, no network or router names), and the lab switches set;
- delivered out of 10 in each direction, the `path=` of every delivery, and
  the time from send (or from the network coming up) to receipt;
- `raven status` and `raven doctor` of each machine before and after: the
  `LAN`, `nearby search`, `old address` and `clocks` rows, and for custody the
  mailbox rows; `raven lan status` for the LAN rows;
- the beacon counts (`nearby search ... last 10 min: N sent, N answered`);
- for custody: `wan_two_network_test.sh custody-status` and `report ROW`
  (counts only), the held and released counts of the custodian;
- the pass or fail against the row's bar, or "cannot host" where a row
  allows it, and anything that surprised you;
- every IP address replaced (`<lan-a>`, `<lan-b>`, `<public-ip>`), every
  PeerId and label replaced (`<peer-1>`, `<label-1>`).

## 3. Local network rows (items 1 and 2)

Set up two test homes with `node/scripts/wan_two_network_test.sh setup NAME`
on each machine and exchange cards (`add` with the fingerprint). Then remove
any LAN address the cards carried, so nothing is typed:
`wan_two_network_test.sh addr TAG --clear lan` on both sides. Two-node mode
listens on `0.0.0.0:7420`, which is what `auto` means while its gate is
closed; a row that needs `auto` itself starts the node by hand after `stop`:
`RAVEN_LAB_LAN_AUTO=1 RAVEN_LAB_LAN_BEACON=1 raven-node service --data-dir
<test home>/NAME --lan-listen auto`.

### R1: same home Wi-Fi, no addresses typed

- Both machines on the home Wi-Fi, nearby search on (lab), no LAN address
  saved.
- 10 messages each way (`send TAG auto 10`).
- Reboot both machines, start the test nodes again, 10 more each way. On
  macOS, note whether the Local Network prompt appears for `raven-node`, and
  allow it.
- Pass: 10/10 each way, `path=` LAN, found by nearby search (the send line says
  "found on your network now ... not saved"), no address typed, nothing saved to the
  contact book by the beacon.

### R1b: guest Wi-Fi with client isolation

- Both machines on a guest Wi-Fi that keeps clients apart.
- 3 messages each way.
- Pass: nearby search is unanswered, the send and `raven doctor` say
  `lan_no_answer` ("None of your friends answered on this network ..."), and
  the messages stay queued and honest; once p2p is live in your build (lab:
  `RAVEN_LAB_TEST_A=1`), they are delivered over the internet path instead.

### R21: `raven lan off` at a cafe

- One machine on a cafe or other shared Wi-Fi, a capture running:
  `sudo tcpdump -n -i <wifi interface> port 7420` (keep the capture private;
  the artifacts get the packet counts only).
- `raven lan off`, then `raven send` to a contact and `raven lan status`.
- From the second machine on the same Wi-Fi (if you have one), try to connect
  to TCP 7420 of the first.
- `raven lan on`, and one message once the contact is back on a LAN.
- Pass: while off, no UDP 7420 leaves the machine, TCP 7420 is refused, and
  nothing is dialled on the LAN; the send says the local network is off
  (`raven lan on` turns it on); `raven lan on` restores listening and the
  message is delivered.

### R22: a DHCP move

- Both machines on the home Wi-Fi, linked once (one message each way).
- Change one machine's address: renew its lease, or change its reservation on
  the router and reconnect.
- The other machine sends 3 messages right after the move, before the moved
  one sends anything.
- Pass: the queued messages are delivered within 30 s of the moved machine's
  network coming back, with no address typed.

### R23: cross-OS LAN pairs

- Mac and Linux, then Mac and Windows, on one home Wi-Fi. On Windows, apply
  the two firewall rules the installer prints (TCP and UDP 7420, `-Profile
  Private`); on Linux the ufw or firewalld lines the installer prints.
- 10 messages each way over IPv4, found by nearby search.
- IPv6 link-local: start both nodes with `--lan-listen auto` (section 3),
  save each other as `raven contact set-addr --petname <name> --lan
  "[fe80::...%<zone>]:7420"` (the zone is an interface name on macOS and
  Linux, a number on Windows), 3 messages each way.
- Pass: 10/10 and 3/3 each way on both pairs; the Windows numeric zone is kept
  in `lan_seen` and in the saved route.

## 4. Offline link rows (item 5: no Internet)

Every row here has no internet at all. Pass bar for each: 10/10 each way
with no address typed, wherever the link exists. Rows R11d, R11e and R11f
record "cannot host" (with the exact error) instead of failing when the
system refuses to create the network. Record which side hosted.

### R11a: a router with its WAN unplugged

- Unplug the router's internet cable (or its WAN port); both machines stay on
  its Wi-Fi.
- Pass: 10/10 each way, found by nearby search; `raven status` says Raven
  works on this network without the internet.

### R11b: a Linux `nmcli` hotspot

- The Linux laptop makes a hotspot ([`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) §3),
  the other machine joins it.
- Pass: 10/10 each way; record the hotspot subnet and whether the clients can
  reach each other.

### R11c: a cable, per OS pair

- A cable between two machines with only self-assigned addresses (169.254 on
  IPv4, fe80 with its zone on IPv6): Mac and Mac (Thunderbolt Bridge), Mac and
  Linux (`nmcli` link-local), Mac and Windows (automatic address).
- Pass: 10/10 each way per pair; netwatch logs a link-local network; record
  how long the addresses took to appear.

### R11d: a Windows Mobile hotspot without Internet

- The Windows laptop shares a network with no uplink.
- Pass: 10/10 each way, or "cannot host" recorded.

### R11e: macOS Internet Sharing without uplink

- The Mac shares Wi-Fi with no uplink.
- Pass: 10/10 each way, or "cannot host" recorded.

### R11f: a phone hotspot without mobile data

- A phone hotspot with mobile data off (or no SIM); both laptops join.
- Pass: 10/10 each way, or "cannot host" recorded; record whether the phone
  keeps its clients apart.

## 5. Friend custody rows (item 3)

Two-node mode on three machines, every command with the custody switches of
section 0. The Mac Studio is a separate test profile `mac-studio` that both
laptops pin, on the D15 forward of TCP and UDP 7423, with
`wan_two_network_test.sh custodian on`. Both laptops run `mailbox on`, have
exchanged one message each way within the last hour (so the session has at
least 12 h left), and `custody-status` names `@mac-studio` among the mail
friends. Pass bar for every custody row: 10/10 each way, delivered on wake,
within 24 h.

### R10: recipient asleep, sender away, the Mac Studio holds the mail

- Laptop A on the iPhone hotspot, laptop B on the home Wi-Fi.
- B closes its lid.
- A sends 10 numbered messages, then `wait-held B` (or `hand-off B`); A closes
  its lid once they are held by 1 friend.
- After at least 30 minutes, open B: all 10 arrive exactly once within 2
  minutes of B's network coming up.
- Open A: all 10 show delivered within 2 minutes.
- Repeat with the roles swapped.
- Beacon part: one run with B's address changed by DHCP on the home Wi-Fi
  while it sleeps (`RAVEN_LAB_LAN_BEACON=1` on B and the Mac Studio): B's
  custody fetch finds the Mac Studio through nearby search.
- Renewal part: one run with `RAVEN_LAB_SESSION_RENEWAL=1` on all three: the
  laptops meet at session hour 13 or later (the renewal is logged), then B
  sleeps 20 h; delivered on wake.
- Record the path label of each deposit and fetch, the time to receipt, and
  the Mac Studio's held and released counts.

### R10b: the custodian restarts

- As R10, but the Mac Studio's raven-node is restarted between deposit and
  fetch, and once the machine is rebooted.
- Pass: 10/10 each way, nothing lost, nothing delivered twice.

### R10r (optional): relay and custodian on one node

- The Mac Studio is also the Phase 2 friend relay (`raven relay offer on`);
  both laptops on two different phone hotspots.
- Pass: 10/10 each way; deposits follow the "not on a relay" attempt; the
  relay and the custodian keep their own consents and counts.

### R11g: a custodian laptop on an offline LAN

- A router with its WAN unplugged (as R11a); a third laptop C on its Wi-Fi
  with `custodian on`; nearby search on everywhere.
- A sends while B is away, then A leaves; B arrives.
- Pass: B gets each message exactly once from C over the LAN only, 10/10, no
  address typed; B's ACK reaches A through C when A returns.

## 6. Session renewal row (item 4)

### R24: renewal across a long absence

- Two machines with `RAVEN_LAB_SESSION_RENEWAL=1`, linked on one network.
- Meet at session hour 12 or later: the node log shows `renewed a session`.
- B leaves (lid closed, or off the network) for 20 h.
- One hour after B left, A sends 3 messages; `raven outbox list` gives them a
  deadline at least 23 h away.
- B returns.
- Pass: the 3 messages are delivered on return, exactly once, and no reset or
  re-seal ran (`raven doctor`, node log). A compressed lab variant on real
  Macs sets `RAVEN_LAB_SESSION_LIFETIME_MS` on the first send (debug builds),
  recorded as such; it does not replace the 20 h run.

## 7. The cutoff study's rows (offline additions)

The cutoff study added these after Phase 3's matrix was written; the offline
guide cites them. Every row: test homes only, two-node mode or a node started
by hand with `--data-dir <test home>`, the switches of section 0, the record
of section 2. Rows R11e+, R11d+ and R11h may record "cannot host" (with the
exact error) as R11d-f do.

### R11e+: macOS Internet Sharing without uplink, one typed address

- The Mac shares Wi-Fi with no uplink (as R11e); a second laptop joins it.
- Both test nodes listen on `0.0.0.0:7420` with the section 7 switches;
  nearby search off. Only the client saves an address: the host's,
  `raven contact set-addr --petname <host> --lan 192.168.2.1:7420` (or the
  address the host really has; record it as `<lan-host>`). The host saves
  nothing.
- The client sends 10 first; then the host sends 10 back with nothing typed
  (it learned the client from the client's link, cutoff F7).
- launchd part: stop the hand-started node on the hotspot Mac, then install
  the login service from this commit into the test home: `RAVEN_DATA_DIR=<test home>
  RAVEN_BIN_DIR=<test bin dir> RAVEN_LAN_LISTEN=<lan-host>:7420 bash
  node/scripts/install/macos_launchd.sh`. The installer replaces the login
  service `com.raven.raven-node` of the user who runs it, so run it in a
  macOS user account that has no other Raven service (a separate test user
  is the safe choice). It builds a release build, which reads no lab
  switch: the host types the client's address too. 10 messages each way.
  Remove it afterwards: `launchctl bootout gui/$(id -u)/com.raven.raven-node`
  and delete `~/Library/LaunchAgents/com.raven.raven-node.plist` of that
  test user.
- Record whether macOS asked for Local Network access for `raven-node`, what
  System Settings > Privacy & Security > Local Network shows for it, and any
  `EHOSTUNREACH` ("No route to host") in `<test home>/raven-node.log`,
  `raven-node.err` or an outbox `why`, before and after allowing it.
- Pass: 10/10 each way in both parts, the reverse direction with nothing
  typed on the host in the first part; the launchd-started node reaches the
  client (or the exact error and the setting that fixed it are recorded).

### R11d+: a Windows Mobile hotspot host in the Public profile

- The Windows laptop hosts the Mobile hotspot (with no uplink if it starts
  that way, R11d; otherwise with one, recorded); a second laptop joins it.
  The Windows test node listens on `0.0.0.0:7420`.
- `Get-NetConnectionProfile` on the host: record the profile of the
  hotspot's adapter (expected: Public).
- Without any Public rule: the client sends 3 messages to the host's typed
  address (`192.168.137.1:7420`). Record whether they are refused or queued.
- Add the two temporary rules of [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) §5
  (with `-Program` naming the `raven-node.exe` you run for the row), then 10
  messages each way.
- Remove both rules (`Remove-NetFirewallRule`, §5) and check with
  `Get-NetFirewallRule -DisplayName "Raven LAN*"` that only the installer's
  Private rules, if any, are left.
- Pass: with the rules, 10/10 each way; the result without them recorded;
  nothing left in the Public profile afterwards.

### R11h: a Fedora `nmcli` hotspot with firewalld

- The Fedora laptop hosts the hotspot ([`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md)
  §3); a second laptop joins it. The Fedora test node listens on
  `0.0.0.0:7420`.
- `sudo firewall-cmd --get-active-zones`: record the hotspot interface's
  zone (expected: `nm-shared`).
- Before any change: the client sends 3 messages to the host's typed
  address (`10.42.0.1:7420`, or the address the host has). Record whether
  TCP 7420 is refused; for UDP 7420, set `RAVEN_LAB_LAN_BEACON=1` on both for
  this part and record the `nearby search` counts of `raven lan status`.
- Run the guide's line (`sudo firewall-cmd --zone=nm-shared
  --add-port=7420/tcp --add-port=7420/udp`), then 10 messages each way.
- `sudo firewall-cmd --reload`, and check with `sudo firewall-cmd
  --zone=nm-shared --list-ports` that 7420 is closed again (the guide says
  the rule lasts until a reload or a restart).
- Pass: with the rule, 10/10 each way; the result without it recorded; the
  port closed after the reload.

### R11i: Bluetooth PAN

- Windows and Linux: the Windows laptop shares over Bluetooth (Settings >
  Network & internet > Mobile hotspot, "Share over" Bluetooth) and the Linux
  laptop joins it through BlueZ and NetworkManager; then the other way
  round if both sides can host. macOS too if it can join or host (record
  "cannot host" or "cannot join" otherwise).
- Record the setup time: from the start of pairing to both sides having an
  IP address on the link.
- Both test nodes listen on `0.0.0.0:7420`; each saves the other's typed
  address on the link (section 1 of the guide). 10 messages each way.
- Record the throughput: the round trip of `ping` on the link and the time
  to copy a 1 MB file over it with a tool already on both machines (for
  example `scp`, or `iperf3` if installed), and the time from send to
  receipt of the Raven messages.
- Pass: 10/10 each way per pair that can host; setup time and throughput
  recorded.

### R11j: M0 on hardware, another Raven laptop at a friend's old address

- Three laptops on the home Wi-Fi with the section 7 switches: A, its friend
  B, and C, another Raven test node that is not B (a contact of A or a
  stranger; record which). Nearby search off. A saves B's LAN address
  (from B's card, or typed: `raven contact set-addr --petname B --lan
  <lan-b>:7420`).
- A and B link once on the LAN (one message each way): A now holds B's
  noise pin.
- B leaves the network (lid closed or Wi-Fi off). C takes B's old address
  (B's DHCP reservation moved to C on the router, or C set to that address
  by hand while B is away) and listens on B's port.
- On A: `sudo tcpdump -n -i <wifi interface> -w <private file> host <lan-b>
  and tcp port 7420` (keep the capture private; the artifacts get the counts
  only). A sends 3 messages to B.
- Pass: on every connection from A to `<lan-b>`, A sends one frame (Noise
  message 1, its ephemeral key) and C answers one frame (Noise message 2),
  then A closes the connection: no third frame from A, so no identity bind;
  the send says that something else answered at B's address and that Raven
  stopped before telling it who you are; `raven outbox list` keeps the
  messages queued (`WRONG_IDENTITY`); C learns nothing about A (no link and
  no message from A in C's log or inbox).
  Then C leaves, B comes back on its address and sends to A: A's 3 messages
  reach B exactly once with no `raven outbox retry`.
- Optional contrast, recorded as such: the same with
  `RAVEN_LAB_NOISE_PIN=0 RAVEN_LAB_OFFLINE=0` on A shows A's third frame
  going to C (the identity bind, today's behaviour without M0).

## 8. What the results feed

- The starting parameters of the beacon and of renewal are re-checked against
  R1, R11a-f and R24 (Phase 3 owner decision "starting parameters").
- The LAN amendment's flips: `LAN_AUTO_LISTEN` and `SESSION_RENEWAL` after
  signature; `LAN_BEACON` only after R2 revision 4 approval, the crypto review
  and Swift parity.
- The custody record's flips: `FRIEND_CUSTODY_PRODUCTION_ENABLED` after R11g;
  `FRIEND_CUSTODY_WAN_ENABLED` after R10 and R10b, once p2p is live.
- [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) §9 drops "UNVERIFIED" from a
  statement only after its row passed: R11d and R11d+ (the Windows hotspot
  and its Public profile), R11e and R11e+ (macOS Internet Sharing, the
  launchd node), R11h (`nm-shared`), R11i (Bluetooth PAN).
- R11j is the cutoff amendment's hardware row for M0 (§5 there); the two
  cutoff gates, `OFFLINE_LAN_PRODUCTION_ENABLED` and
  `LAN_NOISE_PIN_PRODUCTION_ENABLED`, stay `false` until the owner signs
  that amendment.
