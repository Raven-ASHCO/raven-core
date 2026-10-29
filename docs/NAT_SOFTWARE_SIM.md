# NAT / multi-homed software substitutes

**Live multi-NAT / CGNAT / DCUtR:** still `BLOCKED_HARDWARE` (see `node/NAT_TRAVERSAL.md`).

Sprint 0 inventory of raven-swarm status vs that target: [`docs/network/raven-swarm-connectivity-matrix.md`](network/raven-swarm-connectivity-matrix.md).

## What this Mac can automate

| Tool | Script / command | Proves |
|---|---|---|
| Docker dual bridge nets | `scripts/nat_docker_sim.sh` | Two peers on isolated L2 cannot dial each other; a dual-homed relay can reach both |
| pfctl | present at `/sbin/pfctl` | Operator may add divert rules; **not** automated here (needs root + careful host policy) |
| Linux `unshare` netns | **not** on macOS | Use Linux CI / VM for true netns (C7, below) |
| Localhost carrier checks | `bridge_abc_demo`, `internet_dial_smoke`, `libp2p_swarm_smoke` | Bridge/store software behavior plus an explicit raw-Internet production hold |
| Phase 2 on loopback | `cargo test -p raven-node --test carrier_matrix -- --ignored` (C17-C26, C35) and `scripts/lan_fault_matrix.py` (s04/s04b/s04c/s04p with `RAVEN_FAULT_HINTS=1`; s39-s49 with `RAVEN_FAULT_P2P=1`, s41-s44 also with `RAVEN_FAULT_FRIEND=1`; s48o also with `RAVEN_FAULT_NETWATCH=1`) | Route hints, friend relays and automatic relay choice, the relay kit, and why a contact cannot be reached (C26, s48, s48c, s49), including no route to the internet (C35, s48o: LAN only, no relay, VPS, UPnP or port advice). Lab switches only, every gate off; one machine, no NAT |
| Phase 3 LAN on loopback | `cargo test -p raven-node --test carrier_matrix -- --ignored` (C27-C30) and `scripts/lan_fault_matrix.py` with `RAVEN_FAULT_BEACON=1` (s04, s80-s84, s86, s87) | The LAN listener on every interface (`--lan-listen auto`: both families, local sources only, `raven lan off` and `on` live) and the contact-only LAN beacon: C29 over real multicast (a free UDP port, never 7420; skipped only with `RAVEN_HARNESS_NO_MULTICAST=1`), the rest on a lab bus (127.0.0.1 only) with a Sniffer that hears every datagram. Lab switches only, both gates off; one machine, no NAT |
| Phase 3 renewal and custody on loopback | `cargo test -p raven-node --test carrier_matrix -- --ignored` (C31-C34) and `scripts/lan_fault_matrix.py` with `RAVEN_FAULT_RENEW=1` (s85, s85b) or `RAVEN_FAULT_CUSTODY=1 RAVEN_FAULT_P2P=1 RAVEN_FAULT_HINTS=1` (s30p, s30w; s30r also with `RAVEN_FAULT_FRIEND=1`) | Session renewal near a session's end and its fallback side (C31, s85, s85b: what waits keeps about a day). Friend custody over p2p: announced custodians, deposits and fetches over relay circuits with a byte scan of the custodian's files (C32, s30p), the two WAN switches and the refusals (C33, s30w), a friend relay and a custodian on one node (C34, s30r). Real rows: [`P3_REAL_ROWS_CHECKLIST.md`](P3_REAL_ROWS_CHECKLIST.md). Lab switches only, every gate off; one machine, no NAT |
| Friend relay rehearsal | `node/scripts/wan_two_network_test.sh friend-dry-run` | `friend-host` and `friend-use` on loopback, each in its own test home: the user's relay is the host's, picked from its offer and reserved. Not a WAN claim |
| Three-node rehearsal | `node/scripts/wan_two_network_test.sh three-dry-run` | A relay, two always-listening nodes and a stranger on loopback: 3/3 messages `path=relayed` through a true circuit, the stranger refused by the recipient's peer gate. No NAT; a rehearsal of the real rows R3/R5/R9/R14 ([`P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md`](P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md)), not a WAN claim |

## Run Docker substitute

```bash
bash scripts/nat_docker_sim.sh
# → RESULT=PASS under node/proof_artifacts/nat_docker_*/
```

Requires Docker Desktop running. If Docker is absent/stopped, the script **SKIP**s (exit 0) so CI hosts without Docker stay green; treat SKIP as “substitute not executed”.

## Operator pf sketch (manual, root)

```bash
# Example only — do not paste blindly into production hosts.
# Create two utun/VM interfaces, assign RFC1918 ranges, deny direct A↔B, allow A/B→relay.
sudo pfctl -s rules   # inspect current
```

Document any pf experiment under `node/proof_artifacts/` (no secrets).

## Linux network namespaces: C7 (`node/scripts/netns_nat_dcutr.sh`)

A relay R in a "pub" namespace (the simulated Internet), two routers that do
nftables masquerade, and one `raven-node service` behind each router (debug
build, lab unlock `RAVEN_LAB_TEST_A=1`, P2P gate off). Linux and root only:
`RAVEN_NETNS_ALLOW_SUDO=1 bash node/scripts/netns_nat_dcutr.sh`. Every send is
verbose and must print its `path=` label (direct, reversed, relayed or
hole_punched).

| Case | NAT | Expected |
|---|---|---|
| cone | plain `masquerade` (port-preserving) | R14 first: a stranger S in R's circle, holding B's card, sends; B's peer gate refuses it (counts-only log line, no Raven link, no DCUtR on S) and the counters below stay 0. Then A and B hole-punch: the third message is `path=hole_punched` and the counters move |
| symmetric | `masquerade random,fully-random` | Every message `relayed`, delivered once; an upgrade fails the run (the NAT would not be symmetric) |
| cone-private | cone, on a private 10.0 "Internet" | Every message `relayed`, no upgrade, `lan_to_other` 0 on both routers: private candidates are never offered or dialled |
| swap | cone, plus a second router for A | netwatch sees A's uplink move, the p2p host re-homes on the same relay, A's queued messages arrive exactly once |
| shifted, v6fw, reach, hints | advisory, only when named | port-rewriting NAT; IPv6 behind stateful firewalls; AutoNAT "public" needs two relays on different networks; route hints (RRH1, the one case with `RAVEN_LAB_ROUTE_HINTS=1`): a public B's direct address learned through RRH1, then after B's uplink swap delivery through a circuit within 30 s and no packet to B's old address |
| only443 | advisory, only when named; cone, plus an egress filter in A's namespace (only new TCP connections to port 443 leave; nft counters `tcp443`, `dropped`, `tcp7423`, `tcp7427`) | the relay kit's 443 fallback: R listens on TCP 7423 and TCP 443 (`--also-tcp 443`), A names both addresses of R (one relay), B its 7423. A reserves within 40 s over 443 (`tcp443` > 0, and its first try of 7423 dropped: `tcp7423` > 0), A and B are `relayed` both ways, and no hole punch (A can reach nothing but 443). Then a friend relay on 443 (route hints and `RAVEN_LAB_FRIEND_RELAY=1` from here): an operator O with no NAT runs `raven relay offer on --also-443` and names only its 443 address; A and B reach O through R, get O's offer in its route hints and reserve on it (A over 443); with R stopped, A and B are `relayed` through O, and A's filter counts connections to 443 and none to 7427. The one 443-only case; ten green runs before it may become required |
| friend | advisory, only when named (route hints and `RAVEN_LAB_FRIEND_RELAY=1` in this run only); its own topology: three operators A, D, E with public addresses, B behind a cone NAT, C behind a symmetric one | each operator offers relaying on 7427 (`raven relay offer on --external`); B and C set no relay, link each operator once and must then hold 2 relays picked from the offers (`raven doctor` `relay_N_source=offer`, reserved). After a card exchange, C -> B and B -> C are `relayed`, and rC's counter `c_direct_est` (established flows to anyone but the operators) stays 0 |
| friend-sleep | advisory, only when named; the friend topology, with fast relay choice and pings (`RAVEN_LAB_RELAY_SELECT=20,10,5`, `RAVEN_LAB_P2P_PING=5,2`) | `kill -STOP` the operator of B's first relay (a closed laptop lid): B logs `relay replaced` within 60 s and C -> B is still delivered; after `kill -CONT` no second replacement within 60 s (no thrash). The software stand-in for real row R13 |
| diag | advisory, only when named; the cone topology, R (with `--autonat-server`) from step 2 on | why a contact cannot be reached, from A's send and its IPC status: without listeners or a relay A's first message gives `both_nat` and the status says `NOT reachable` with W3; with R, A <-> B are `relayed` or `hole_punched`; R frozen with `kill -STOP` gives `relay_asleep` (`relay=mine1`) and W1, and after `kill -CONT` the message arrives once; B stopped gives `contact_offline`. No log names a PeerId, no reason line an address |
| lan-move, lan-ll, lan-isolated, lan-nonlocal | advisory, only when named (Phase 3: `RAVEN_LAB_LAN_AUTO=1` and `RAVEN_LAB_LAN_BEACON=1` in these runs only, no p2p); their own topology: one bridge, no router, no default route (lan-nonlocal adds a router to a host on a global-looking `WAN.30.0/24`) | lan-move: A and B listen with `--lan-listen auto` and pin each other with no address; the first message each way goes through a beacon find; with their addresses saved, both links go down, a message each way waits, both come back renumbered from 10.77.1.0/24 to 10.88.1.0/24 and the queued messages arrive within 30 s; tcpdump on the bridge carries only the beacon's UDP to port 7420 (queries 160-191 bytes, answers 48-63) (239.255.74.20, ff02::8000:7420, a subnet broadcast), no constant window and nothing that names either side. lan-ll: IPv6 link-local only, delivered through a `[fe80::…%eth0]` find. lan-isolated: both bridge ports isolated (a guest Wi-Fi): the next message stays queued, the beacon is unanswered, no book changes. lan-nonlocal: a routed, non-local source's connection to the `auto` listener is closed before a byte and counted (no address logged) |
| custody | advisory, only when named (Phase 3 item 3: route hints, `RAVEN_LAB_CUSTODY_WAN=1` and s30's custody timers in this run only); symmetric routers, plus a public custodian C (`WAN.31.10`, no NAT); pub's own counters `a_b` and `b_a` count packets between A's and B's networks | C offers to hold mail, A and B use friend mailboxes, nobody names a custodian (offers and tags ride route hints). B down: A's message is left with C (a `p2p_dial` deposit); A down, B up: B has it exactly once and leaves its ACK with C; B down, A up: A fetches the ACK. `a_b` and `b_a` stay 0 from the deposit on, and no custody line names an address, a PeerId or a key |
| pcp, pcp-cgn, v6pin | advisory, only when named (Phase 4: `RAVEN_LAB_PORT_MAP=1` and route hints in these runs only, v6pin also `RAVEN_LAB_V6_PINHOLE=1`); rB runs miniupnpd (apt package `miniupnpd-nftables`, lab job only) with NAT-PMP/PCP on, UPnP off and secure mode, its rules in the script's own `inet raven_upnp` table; pcp-cgn puts rB's WAN on 100.64.2.2 behind a carrier router rC (`masquerade random,fully-random`); v6pin adds IPv6 under the unallocated 3ffe:0:0::/48 with rB's stateful IPv6 filter in front of miniupnpd's pinholes | pcp: B (`raven node upnp on`) logs `router port mapped (PCP`; A learns B's mapped address through RRH1 on a first message (`relayed` or `hole_punched`), restarts, and its next message is `path=direct` with rB's `wan_dnat_7423` counter growing and no DCUtR upgrade after the restart. pcp-cgn: `behind another NAT`, miniupnpd's DNAT table empty after B's delete, `relayed` both ways. v6pin: `IPv6 pinhole open on the router (PCP)`, then `path=direct` to B's IPv6 through the pinhole (rB's `wan_v6_7423` grows); exit 2 (cannot run) when miniupnpd was built without IPv6. Each stays advisory until 10 green runs in a row |
| classify, punch-skip | advisory, only when named (Phase 4 P4.24: `RAVEN_LAB_NAT_CLASS=1` in these runs only, punch-skip also route hints); their own topology: R1 and R2 on two /24s, A behind rA (punch-skip: B behind rB too) | classify: A on both relays classifies its NAT from what they see (`raven doctor` line `nat_mapping: tcp=...`): plain masquerade `stable_kept`, the shift of 7423 to :30000 `stable_shifted`, `masquerade random,fully-random` `varies`, the topology rebuilt for each. punch-skip: both symmetric and `varies`; a first message carries the RRH1 exchange (NAT_CLASS), both restart, then two messages are `path=relayed` exactly once, both log `hole punch skipped (both`, and neither router's `lan_to_other` grows. Each stays advisory until 10 green runs in a row |
| learn-flaky | advisory, only when named (Phase 6a P6.18: `RAVEN_LAB_LEARNING=1` in its second half only, a lab network tag `RAVEN_LAB_NET_TAG` in the run); its own topology: A, B and a stranger S on one LAN bridge whose ports to A and B lose 30 % of packets (`tc netem`) in 2-minute bursts, and a routed "internet" between A and B through pub (`WAN.40` and `WAN.41`, no NAT, no default route); hS's nft counter `from_a` counts packets from A | A pins B with B's LAN address and Internet direct listener, and Carol, whose saved LAN address is S's (a node that does not know A). The same 20 sends A -> B, one every 6 s from the start of a loss burst, first with learning off (the static order: the lab's route memory cleared before each send), then on: the p95 send time with learning is at most half the one without, every message arrives exactly once, and `from_a` (zeroed after A's one send to Carol) stays 0. Advisory until 10 green runs in a row |

**Why the simulated Internet uses a global-looking prefix.** Hole punching
offers and dials globally routable addresses only (raven-swarm `gate.rs`
`AddrRule::GlobalOnly`, by `host.rs` `is_global_ipv4`), which drops RFC 1918,
RFC 6598 (100.64/10) and RFC 5737 candidates. On a 10.x "Internet" DCUtR would
have nothing to offer and the cone case could never upgrade. The default
`RAVEN_NETNS_WAN_PREFIX=11.0` passes that check. It is real Internet space,
but nothing here can reach it: the namespaces have no interface on the host
and pub has no default route (checked at setup). The debug switch
`RAVEN_LAB_P2P_LOCAL_CANDIDATES` is never set. cone-private is the contrast:
the same NAT on 10.0 stays relayed.

**Kernel counters.** Each router's nft table carries two named counters,
zeroed after the setup's own pings:
- `lan_to_other`: packets forwarded from its LAN to any address but R's;
- `wan_from_other`: packets arriving on its WAN side from any address but R's
  (counted in prerouting, before unsolicited ones are dropped).

With the relay as the only path both stay 0; a direct path moves them. They
prove which paths were used, not what was said: DCUtR is encrypted end to end.
carrier_matrix C15 and C16 (an in-process spy at the end of the circuit)
prove that nothing was sent to a stranger.

**Running and CI.** `RAVEN_NETNS_CASES` (default `cone symmetric cone-private
swap`), `RAVEN_NETNS_REPEAT` (1-5) and `RAVEN_NETNS_WAN_PREFIX` choose what
runs. The lab job's advisory step names every advisory case, the lan-* runs
among them. The advisory cases run only when named, and each joins the blocking set
only after ten consecutive green runs of its own (for example
`RAVEN_NETNS_REPEAT=5` green twice). Exit 0 means every required case passed in
every iteration, 1 means one failed, and 2 means it cannot run here. CI must
treat 2 as a failure, never a skip. The lab workflow job `nat-sim-linux` stays
advisory until 10 consecutive green iterations of the required cases are
recorded there by run id. Then its `continue-on-error` is deleted. The owner's
P2P flip commit makes it a required check.

## Linux network namespaces: no internet provider (`node/scripts/netns_offline.sh`)

The cutoff pack's cases: Raven between laptops with no internet provider at
all. Same helpers and rules as the C7 script (Linux and root only, debug
build, exit 2 when it cannot run), every case advisory, run once in the lab
job's own step. Each namespace gets its own `resolv.conf` (a name server at
192.0.2.53 that nothing answers) and `nsswitch.conf` (`hosts: files dns`, no
mDNS), IPv6 is off (except in cable-linklocal's fe80 round), and the bridges
carry named nft counters (`table bridge raven_off`). Phase 3 P3.C5 added the
LAN beacon's rows: hotspot-ap (3), cable-linklocal's fe80 round and
three-rooms-beacon (the beacon on UDP 7420 inside the namespaces only).

| Case | Topology | Expected |
|---|---|---|
| lan-noprovider | one bridge 192.168.2.0/24, A and B, no default route; `RAVEN_LAB_OFFLINE=1 RAVEN_LAB_NOISE_PIN=1` | literal routes both ways, each message once; a `x-nohost.local:7420` route queued within 10 s with "could not be found on this network", delivered once the number is saved again; 0 packets from A or B to anything but the other one and UDP 53; `raven doctor` makes no internet claim |
| router-dead-uplink | a router whose WAN drops everything and which drops DNS; A and B route through it | the LAN part as above; then A with the p2p lab unlock and a relay behind the dead WAN: a p2p-only contact's send ends within 8 s with no VPS, port-forward or UPnP advice, and the LAN sends right after it are delivered within 8 s each; `raven doctor` with the p2p host up makes no internet claim |
| hotspot-ap | an AP namespace owning `br-ap` 10.42.0.1/24, no uplink, no forwarding; C1 and C2 behind it after meeting on a home bridge (their cards keep the old 192.168.1.x addresses) | stale addresses end queued; after C1 types the AP's address its sends are delivered, and the AP's queued message reaches C1 after C1's first link; with an nft isolation rule between the clients, C1 -> C2 is queued, then delivered once through the AP's friend custody (lab), with C2's ACK back the same way; (3) with `RAVEN_LAB_LAN_BEACON=1`, C1 -> C2 and C2 -> C1 with only the old addresses saved are delivered by the send within 15 s through the beacon's find ("found on your network now"), never saved |
| cable-linklocal | one veth pair, 169.254/16 only; two rounds, `RAVEN_LAB_OFFLINE=0` and `=1` | netwatch starts with "watching (0 networks)"; a listener started before its 169.254 address exists binds within one retry after the address appears, and `raven doctor` drops `addr_not_here`; netwatch logs "link-local network only (a cable?)" only with the gate open; delivery both ways in both rounds; a third round with IPv6 on, `--lan-listen auto:7420` under `RAVEN_LAB_LAN_AUTO=1` and each contact saved as `[fe80::...%eth0]:7420`: delivery both ways |
| three-rooms | route hints and custody (lab): A only in room1, B only in room2 (separate bridges), C on 0.0.0.0:7420 carried between them with a new address each time (to room2 while its node runs, back after a restart) | A's message reaches B through C exactly once (B's log shows the custody fetch), B's ACK reaches A through C, and C ends with no unreleased row |
| three-rooms-beacon | three-rooms with route hints off in the rooms and `RAVEN_LAB_LAN_BEACON=1`: beacon plus custody only | C's move to room2 is a network change for its beacon, whose join round names B; B fetches A's message exactly once within 40 s, B's ACK reaches A through C, C ends empty, and no profile learned an RRH1 |

## Honest claim

Software substitutes **maximize** confidence that routing policy + relay/store paths work.  
They **do not** replace a carrier-grade NAT matrix or libp2p DCUtR on the public Internet.
Those are the owner-run real rows R3, R5, R9 and R14:
[`P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md`](P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md); for
Phase 2 (route hints, friend relays, the relay kit, the diagnosis) the rows in
[`P2_REAL_ROWS_CHECKLIST.md`](P2_REAL_ROWS_CHECKLIST.md); for Phase 3 (the local
network, friend custody, session renewal) the rows in
[`P3_REAL_ROWS_CHECKLIST.md`](P3_REAL_ROWS_CHECKLIST.md).
