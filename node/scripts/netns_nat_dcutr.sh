#!/usr/bin/env bash
# C7 (docs/design/2026-10-transports-internet-mesh-bridge.md section 6.4): libp2p relay
# + DCUtR hole punching between two raven-node services that sit behind
# simulated NATs, built from Linux network namespaces and nftables.
#
# What it proves (debug build, lab unlock RAVEN_LAB_TEST_A=1, P2P gate off).
# Every send is verbose and must print its `path=` label (direct, reversed,
# relayed or hole_punched): how the link travelled, not a guess from logs.
# Required cases (a failure fails the script):
#   cone           each router does plain `masquerade` (Linux keeps the source
#                  port where it can, so one inside port maps to one outside
#                  port for every destination). A and B reserve on relay R.
#                  R14 first, before A and B ever talk: a stranger S in hA
#                  (`--p2p-listen 0.0.0.0:7424`, no relay of its own) holds
#                  B's card; B does not know S. S is on R's allow-list: R
#                  relays only within its circle, so only a circle member's
#                  circuit reaches B's own peer gate at all. S's `raven send
#                  --carrier p2p` must fail, never with LINK_NOT_ACCEPTED (no
#                  Raven link); B's gate refuses the circuit before accepting
#                  it, so R answers CONNECTION_FAILED and S reads that B is
#                  offline (why=contact_offline, neither refusal hint: review
#                  fix C-relay-kit-1, as carrier C6 and fault s35); B logs the
#                  counts-only gate refusal, no "p2p inbound" line and not S's
#                  PeerId; S logs no hole punch; and the routers' kernel
#                  counters rA lan_to_other, rB lan_to_other and rB
#                  wan_from_other stay 0: no packet went anywhere but R, so no
#                  candidate was used. Then A -> B #1 (relayed or
#                  hole_punched), B -> A, A -> B #2, a service logs
#                  "raven-node p2p: direct connection upgraded (dcutr)", and
#                  A -> B #3 must be `path=hole_punched` with rA lan_to_other
#                  and rB wan_from_other above 0 (a direct path existed).
#   symmetric      the routers do `masquerade random,fully-random` (a new
#                  outside port per destination, the stage-8 substitute):
#                  every message is `path=relayed` and arrives exactly once.
#                  The dcutr upgrade line fails the run: then the NAT is not
#                  symmetric and the simulation is invalid. Hole-punch
#                  failures and the counters are reported.
#   cone-private   cone routers on a private "Internet" (10.0, this run only,
#                  whatever RAVEN_NETNS_WAN_PREFIX says): every message is
#                  `path=relayed`, no upgrade, and lan_to_other stays 0 on
#                  both routers. The hole-punch rule never offers or dials a
#                  private candidate: this is its kernel-level proof.
#   swap           (Phase 0b) cone routers plus a second router rA2 for A. After
#                  the first messages B goes down and A queues 2 messages; then
#                  A's uplink is swapped (eth0 flushed and down, eth1 behind rA2
#                  up, a new default route). Within 20 s A's log must show that
#                  netwatch saw it through the real netlink events:
#                  "raven-node netwatch: network changed (1 new, 1 gone, 1 now)"
#                  ending ", p2p re-homing", then "raven-node p2p: re-homed
#                  (network changed)" and a second "reservation accepted" (the
#                  same relay R, through rA2). B comes back: both queued
#                  messages arrive exactly once within 90 s, then a third
#                  message is delivered; whether DCUtR upgraded again is
#                  reported, not required.
# Advisory cases (reported, never fatal; none is in the default list):
#   shifted        (Phase 1 item 3) an endpoint-independent NAT that
#                  rewrites the port: each router maps its host's port 7423
#                  (TCP and UDP) to WAN:30000 (`snat to`) before masquerade.
#                  libp2p-identify 0.48 turns what R observes (WAN:30000) into
#                  WAN:7423 (behaviour.rs:350-397), which nothing forwards;
#                  only the raw observation R reported, which the candidate
#                  book keeps, can upgrade. A and B run with `--p2p-listen
#                  relay`, the retired setting, which must log that it is
#                  retired and listen on 7423 anyway. The third message A -> B
#                  must be `path=hole_punched`.
#   v6fw           symmetric IPv4 NAT (no IPv4 upgrade), and global
#                  IPv6 on both hosts behind a stateful ip6 forward chain on
#                  each router (outbound and replies only), with an IPv4-only
#                  relay. Nobody can observe the hosts' IPv6, so only their
#                  own preferred IPv6 source address, which the candidate book
#                  offers, can upgrade. `--p2p-listen 7423` (every interface).
#                  The third message A -> B must be `path=hole_punched`.
#   reach          (Phase 1 item 5) its own topology: three relays,
#                  each `raven-node relay --autonat-server`, R1 and R3 in one
#                  /24, R2 in another; P and Q on global-looking addresses with
#                  no NAT, N behind a masquerade. AutoNAT `public` needs two
#                  relays on different networks: P (R1 + R2) must report
#                  `nat=public` and class public; Q (R1 + R3: one /24, one
#                  opinion) `unconfirmed` although both relays reached it, and
#                  never public; N (R1) `private`, class relayed, then
#                  unreachable once R1 is stopped. Read from IPC Status (python3)
#                  and the p2p row of `raven status`; each wait up to 240 s.
#   hints          (Phase 2 item 1, RRH1 route hints; the only case with the
#                  debug switch RAVEN_LAB_ROUTE_HINTS=1, unset for every
#                  other one) its own topology: R1 and R2 on two /24s, each
#                  `--autonat-server`; B public (no NAT) and confirmed by
#                  both, A behind a masquerade. A learns B's DIRECT address
#                  from B's route hints (RRH1) and, its node restarted so
#                  that no connection is left to ride, A -> B #1 is
#                  `path=direct` while R1 carries no circuit. B's uplink
#                  then swaps behind a masquerade router (as in swap): B
#                  re-homes, and A's next message is delivered through a
#                  circuit within 30 s of the swap. Once A holds B's
#                  new-generation hints (no DIRECT), rA's nft counter of
#                  packets to B's old address stays flat for 10 s, and a
#                  third message adds no packet to it. Advisory until
#                  Phase 1's 10-green rule applies to it.
#   only443        (Phase 2 item 4, the relay kit; the only 443-only case)
#                  cone routers, and R listens on TCP 443 too
#                  (`--also-tcp 443`; root in its namespace needs no
#                  capability). hA gets an egress filter of its own (an
#                  nft inet table in hA only): loopback and replies pass, a
#                  new TCP connection to port 443 passes and is counted
#                  (tcp443), anything else is dropped and counted
#                  (dropped; tcp7423 the part to R's main port). A's relays
#                  are R's TCP 7423 and TCP 443 (one relay, a fallback
#                  address), B's R's TCP 7423. A must reserve within 40 s,
#                  over the fallback: tcp443 > 0, and dropped > 0 from the
#                  first 7423 attempt (tcp7423 > 0); A -> B and
#                  B -> A are `path=relayed`; and no service logs a DCUtR
#                  upgrade (A cannot reach B's candidates). Then the friend
#                  relay run (Phase 2 items 2-3, friend relays and route
#                  hints on from here): an operator O (hO, no NAT) relays for
#                  A and B with a key of its own on TCP+QUIC 7427 and, with
#                  `raven relay offer on --also-443`, on TCP 443, naming its
#                  443 address only. A and B start over (A's filter stays,
#                  both keep R), reach O through R, get O's offer in its
#                  route hints and each reserve on O (A over 443); after a
#                  message each way through R (their hints now name O), R
#                  stops and A -> B and B -> A are `path=relayed` through O.
#                  hA's filter counts new connections to 443 (> 0) and none
#                  to 7427 (tcp7427 = 0). The logs of a failed run print the
#                  counters. Advisory until 10 consecutive green runs.
#   friend         (Phase 2 items 2-3, friend relays; route hints and
#                  RAVEN_LAB_FRIEND_RELAY=1 in this run only) its own
#                  topology: three operators A, D and E on public addresses
#                  (no NAT), each with `raven relay offer on --external
#                  <its address>:7427`; B behind a cone NAT, C behind a
#                  symmetric one, neither with a relay set by hand. The
#                  operators pin everyone, B and C the operators; B and C
#                  first link each operator directly (one message each:
#                  its route hints carry its offer), then each must hold 2
#                  relays picked from the offers, reserved (`raven doctor`
#                  relay_N_source=offer). They exchange their new cards (the
#                  relays they picked) and pin each other: C -> B and B -> C
#                  must be `path=relayed`, and rC's counter c_direct_est
#                  (C's packets of established flows to anyone but the three
#                  operators) stays 0: the only paths that worked were to
#                  relays (a hole-punch try that got no answer is not
#                  established; lan_to_other counts those and is reported).
#                  Three operators: one is the standby friend-sleep needs.
#   friend-sleep   the friend topology and setup, with fast relay choice and
#                  pings for B and C (RAVEN_LAB_RELAY_SELECT=20,10,5,
#                  RAVEN_LAB_P2P_PING=5,2). `kill -STOP` the operator of B's
#                  first relay (a laptop lid closed): B must log `relay
#                  replaced` within 60 s, and C -> B is still delivered;
#                  after `kill -CONT` no second `relay replaced` within 60 s
#                  (B keeps its new relay: no thrash).
#   diag           (Phase 2 item 5, why a contact cannot be reached) the cone
#                  topology, the reasons in order, read from A's send and
#                  from its IPC Status (python3). A and B without a listening
#                  port and with no relay: A's first message gives both_nat,
#                  and A's status internet row says `NOT reachable` with W3
#                  as what to do. Relay R on pub with --autonat-server, A and
#                  B listen on 7423 and reserve on it: A -> B and B -> A are
#                  `path=relayed` or `hole_punched`. A restarts (no
#                  connection to B left), then `kill -STOP` on R: A's queued
#                  message gives relay_asleep with relay=mine1, A's what to
#                  do is W1, and after `kill -CONT` it is delivered once. B's
#                  service stops while R runs: contact_offline. No log names
#                  a PeerId, and A's reason lines name no address.
#   lan-move       (Phase 3 items 1-2, the LAN listener on every interface
#                  and the LAN beacon, RAVEN_LAN_BEACON_V1; the lan-* runs
#                  alone set RAVEN_LAB_LAN_AUTO=1 and RAVEN_LAB_LAN_BEACON=1,
#                  each in its own subshell, and run no p2p host and no p2p
#                  lab unlock) an offline LAN: one bridge, no router, no
#                  default route. A and B listen with `--lan-listen auto`
#                  (TCP and UDP 7420 inside their namespaces only) and pin
#                  each other with no address: the first message each way is
#                  delivered through a beacon find. Each then saves the
#                  other's address; both links go down and a message each
#                  way waits (queued); both come back renumbered from
#                  10.77.1.0/24 to 10.88.1.0/24 (the real netlink watcher
#                  sees it), and the queued messages are delivered within 30 s
#                  (something waits, so each beacon's join round names the
#                  other: owner decision OD-C7); the books still name the old
#                  addresses. tcpdump on the bridge (when the runner has it)
#                  carries only UDP to port 7420, 160..=191 or 48..=63 bytes
#                  (a random tail since Phase 6b W-B3), to 239.255.74.20,
#                  ff02::8000:7420 or a subnet broadcast, with no 4-byte
#                  window the same in every query's first 160 bytes or every
#                  answer's first 48, and no key, rvn1 address, 'rvn1' or
#                  'raven' in the clear.
#   lan-ll         the same bridge with IPv6 link-local only, no IPv4 at all
#                  (a cable with no DHCP server): the first message each way
#                  is delivered through a [fe80::...%eth0] find, the zone kept.
#   lan-isolated   (the guest Wi-Fi of real row R1b) lan-move's LAN; after a
#                  first message through the beacon both bridge ports are
#                  isolated (`bridge link set dev pa isolated on`, and pb: an
#                  isolated port reaches only ports that are not): the next
#                  message stays queued (P3.23 adds LAN_NO_ANSWER), A's beacon
#                  keeps asking and nothing answers, and no contact book
#                  changes.
#   lan-nonlocal   lan-move's LAN plus a router rL (no NAT) to hX on the
#                  global-looking WAN.30.0/24; hA has a route (not a default
#                  route) to it. hX's plain TCP connection to A's `auto`
#                  listener is closed before a byte and A logs the counts-only
#                  line ("1 since start", no address); a plain connection
#                  from B (on-link) stays open.
#   custody        (Phase 3 item 3, friend custody over the internet; route
#                  hints, the WAN custody switch RAVEN_LAB_CUSTODY_WAN=1 and
#                  s30's custody timers in this run only) the symmetric
#                  topology plus a public custodian C (hC, no NAT). A, B and
#                  C reserve on R and pin each other from cards; C runs `node
#                  custody on --yes`, A and B `custody use on --yes`, nobody
#                  names a custodian: C's offer and the pair-blinded tags
#                  ride route hints (one message to C each, then one each way
#                  between A and B). 1. B down: A's message is left with C
#                  (`held by 1 friend`, a p2p_dial deposit line). 2. A down,
#                  B up: B's inbox has it exactly once, and B leaves its ACK
#                  with C. 3. B down, A up: A fetches the ACK from C. pub's
#                  own counters of packets between A's and B's networks
#                  (a_b, b_a; zeroed after the warm-ups' hole-punch tries)
#                  stay 0, and no custody line names an address, a PeerId
#                  or a key.
#   pcp            (Phase 4, router port mapping, RAVEN_PORT_MAPPING_V1;
#                  the pcp runs alone set RAVEN_LAB_PORT_MAP=1 and route
#                  hints, each in its own subshell) the cone topology, and
#                  rB runs miniupnpd (apt package miniupnpd-nftables, owner
#                  decision O4-15) with enable_pcp_pmp=yes, enable_upnp=no,
#                  secure_mode=yes, its rules in this script's table inet
#                  raven_upnp; raven_nat accepts DNATed flows (`ct status
#                  dnat accept`). B (`raven node upnp on`) must log "router
#                  port mapped (PCP"; A -> B #0 is relayed or hole_punched
#                  and brings A B's route hints with the mapped address as
#                  DIRECT; A restarts (no connection left to ride) and #1
#                  must be `path=direct`, rB's counter wan_dnat_7423 (packets
#                  in from the WAN through a mapping to 7423) must grow, and
#                  no DCUtR upgrade may follow the restart. Exit 2 without
#                  miniupnpd.
#   pcp-cgn        pcp's router behind a carrier NAT: rB's WAN is
#                  100.64.2.2 behind rC (`masquerade random,fully-random`),
#                  and miniupnpd serves anyway (ext_allow_private_ipv4=yes),
#                  reporting 100.64.2.2. B must log "router is behind another
#                  NAT", miniupnpd's DNAT table must be empty after B's
#                  delete, and A -> B and B -> A are `path=relayed`.
#   v6pin          pcp plus IPv6 under 3ffe:0:0::/48 (an unallocated former
#                  6bone prefix: global-looking, as unreachable as WAN, where
#                  2001:db8::/32 would be refused by is_global_ipv6), rB's
#                  IPv6 filter stateful (outbound and replies) behind
#                  miniupnpd's pinholes, and RAVEN_LAB_V6_PINHOLE=1 with `raven
#                  node ipv6-pinhole on` for B. B must log "IPv6 pinhole open
#                  on the router (PCP)"; after A's restart #1 is
#                  `path=direct` and rB's counter wan_v6_7423 grows. Exit 2
#                  when this miniupnpd was built without IPv6.
#   classify       (Phase 4 P4.24; RAVEN_LAB_NAT_CLASS=1 in this run's
#                  subshell only) its own topology: R1 and R2 on two /24s,
#                  both A's relays (`--p2p-listen 0.0.0.0:7423`), A behind
#                  rA. rA runs plain masquerade, then the shifted rule (its
#                  host's 7423 to WAN:30000), then `masquerade
#                  random,fully-random`, the topology rebuilt for each (no
#                  conntrack entry carries over). A's `raven doctor` must
#                  say `nat_mapping: tcp=stable_kept`, then `stable_shifted`,
#                  then `varies`, and A's log the counts-only "NAT mapping"
#                  line naming no address. The QUIC class is reported (A
#                  reaches its relays over TCP).
#   punch-skip     (Phase 4 P4.24; RAVEN_LAB_NAT_CLASS=1 and route hints in
#                  this run's subshell only) classify's topology with B
#                  behind rB too, both routers symmetric, A and B on R1 and
#                  R2: both classify `varies`. A -> B #1 carries the RRH1
#                  exchange (each stores the other's NAT_CLASS); A and B
#                  restart (no connection left to ride), their classes come
#                  back, and #2 and #3 are `path=relayed` exactly once, both
#                  logs say "hole punch skipped (both" after the restart, and
#                  neither router's lan_to_other counter grows from then on
#                  (no hole-punch dial).
#   learn-flaky    (Phase 6a P6.18, learning connectivity; the only case with
#                  its debug switch RAVEN_LAB_LEARNING=1, set in its own
#                  subshell for its second half) its own topology: A, B and
#                  a stranger S on one LAN bridge, whose ports to A and B
#                  lose 30 % of packets (tc netem) in 2-minute bursts, and a
#                  routed "internet" between A and B through pub on the WAN
#                  prefix (no NAT, no default route). A pins B with B's LAN
#                  address and B's Internet direct listener, and pins
#                  Carol, whose saved LAN address is S's (a node that does
#                  not know A, so it never delivered). The same 20 sends
#                  A -> B, one every 6 s from the start of a loss burst,
#                  first with learning off (the static order, the lab's
#                  route memory cleared before each send), then on: the
#                  p95 send time with learning is at most half the one
#                  without, every message arrives exactly once, and hS's
#                  nft counter of packets from A (from_a, zeroed after A's
#                  one send to Carol) stays 0: learning's probes never go to
#                  a stranger. Advisory until 10 consecutive green runs.
#
# Topology (rebuilt from scratch for each run; no interface is created on the
# host, and every namespace name carries a per-run prefix). WAN is the
# simulated Internet's /16 prefix (RAVEN_NETNS_WAN_PREFIX, default 11.0). It
# must look global: hole punching offers and dials globally routable addresses
# only (raven-swarm gate.rs AddrRule::GlobalOnly, by host.rs is_global_ipv4),
# which drops RFC 1918, RFC 6598 (100.64/10) and RFC 5737 candidates, so a
# 10.x "Internet" would leave DCUtR nothing to offer and the cone run would
# never upgrade. 11.0.0.0/8 passes that check. It is real Internet space, but
# nothing here can reach it: the namespaces have no interface on the host and
# pub has no default route (checked at setup). No lab switch widens the rule:
# RAVEN_LAB_P2P_LOCAL_CANDIDATES is unset for every process. cone-private is
# the contrast: the same cone NAT on 10.0 never upgrades.
#
#   hA 192.168.1.2 -- 192.168.1.1 rA WAN.1.2 -- WAN.1.1 \
#                    (nft masquerade)                     pub: relay R on WAN.0.1
#   hB 192.168.2.2 -- 192.168.2.1 rB WAN.2.2 -- WAN.2.1 /   (routes the links)
#   cone run only: the stranger S runs in hA next to A (p2p port 7424)
#   swap run only: hA eth1 (down, no address until the swap)
#      192.168.3.2 -- 192.168.3.1 rA2 WAN.3.2 -- WAN.3.1 (pub)
#   v6fw run only: IPv6 under 2c0f:fff0:a::/48 (global-looking like WAN, and
#      as unreachable: pub has no IPv6 default route either, checked)
#      hA 2c0f:fff0:a:1::2 -- :1::1 rA :f1::2 -- :f1::1 \
#                                                      pub (routes the /64s)
#      hB 2c0f:fff0:a:2::2 -- :2::1 rB :f2::2 -- :f2::1 /
#   reach run (its own namespaces; pub routes every link):
#      pub: R1 WAN.11.1, R3 WAN.11.2 (R1's /24), R2 WAN.12.1, on lo
#      hP WAN.13.10 -- WAN.13.1 pub (no NAT)
#      hQ WAN.15.10 -- WAN.15.1 pub (no NAT)
#      hN 192.168.4.2 -- 192.168.4.1 rN WAN.14.2 -- WAN.14.1 pub (masquerade)
#   hints run (its own namespaces; pub routes every link):
#      pub: R1 WAN.11.1, R2 WAN.12.1 (two /24s), on lo
#      hA 192.168.4.2 -- 192.168.4.1 rA WAN.14.2 -- WAN.14.1 pub (masquerade;
#         counter to_old_b: forwarded packets to B's first address)
#      hB WAN.13.10 -- WAN.13.1 pub (no NAT) until the swap, then
#      hB eth1 192.168.5.2 -- 192.168.5.1 rB2 WAN.16.2 -- WAN.16.1 pub (masquerade)
#   only443 run: the cone topology; R on WAN.0.1 TCP 7423 (and QUIC) and TCP
#      443; hA's own egress filter (table inet r443: tcp443, dropped, tcp7423,
#      tcp7427); for the friend relay run, hO WAN.26.10 -- WAN.26.1 pub (no NAT)
#   friend runs (their own namespaces; pub routes every link):
#      hA WAN.21.10, hD WAN.22.10, hE WAN.23.10 -- WAN.2x.1 pub (no NAT)
#      hB 192.168.6.2 -- 192.168.6.1 rB WAN.24.2 -- WAN.24.1 pub (masquerade)
#      hC 192.168.7.2 -- 192.168.7.1 rC WAN.25.2 -- WAN.25.1 pub (masquerade
#         random,fully-random; counter c_direct_est)
#   diag run: the cone topology; R (with --autonat-server) on WAN.0.1 only
#      from its second step on
#   custody run: the cone topology's namespaces with symmetric routers, plus
#      hC WAN.31.10 -- WAN.31.1 pub (no NAT); pub counts a_b and b_a
#   lan-* runs (their own namespaces; no router and no default route):
#      sw: bridge br0, ports pa (hA), pb (hB), and lan-nonlocal's pr (rL)
#      hA eth0 10.77.1.2/24, hB eth0 10.77.1.3/24 (lan-move: then
#         10.88.1.2 and .3); lan-ll: IPv6 link-local only
#      lan-nonlocal: rL lan 10.77.1.1/24, wan WAN.30.1/24 -- hX WAN.30.10/24
#   classify and punch-skip runs (their own namespaces; pub routes every link):
#      pub: R1 WAN.11.1, R2 WAN.12.1 (two /24s), on lo
#      hA 192.168.4.2 -- 192.168.4.1 rA WAN.14.2 -- WAN.14.1 pub
#      punch-skip: hB 192.168.5.2 -- 192.168.5.1 rB WAN.16.2 -- WAN.16.1 pub
#   learn-flaky run (its own namespaces; pub routes the two WAN links):
#      sw: bridge br0, ports pa (hA), pb (hB), ps (hS); netem loss on pa, pb
#      hA eth0 10.77.1.2/24, hB eth0 10.77.1.3/24, hS eth0 10.77.1.9/24
#      hA eth1 WAN.40.10/24 -- WAN.40.1 pub, hB eth1 WAN.41.10/24 -- WAN.41.1
#      pub (a route to the other's /24 each; hS counts packets from hA)
#   pcp runs: the cone topology, miniupnpd on rB (lan 192.168.2.1:5351);
#      pcp-cgn: hB 192.168.2.2 -- 192.168.2.1 rB 100.64.2.2 -- 100.64.2.1 rC
#         WAN.2.2 -- WAN.2.1 pub; v6pin: setup_v6's addresses under 3ffe:0:0
#
# The routers drop unsolicited inbound packets (like a home router) and forward
# only lan -> wan plus replies; pub has no route to any 192.168 network, so A
# and B can reach each other only through the NATs.
#
# Kernel evidence: each router's nft table carries two named counters, read
# with `nft list counter` and zeroed after the setup's own pings (one of them
# must fail, and would count):
#   lan_to_other    forwarded lan -> wan packets to any address but R's
#   wan_from_other  packets arriving on wan from any address but R's
# (counted in prerouting, before the drop of unsolicited ones). With the
# relay as the only path both stay 0; a direct path moves them. DCUtR itself
# is encrypted end to end, so counters prove which paths were used, not what
# was said: carrier_matrix C15/C16's in-process spy proves no candidate was
# sent to a stranger.
#
# HONEST CLAIM: a software substitute. It does NOT replace the physical rows R7b
# (DCUtR between two homes behind consumer NAT + a VPS relay) and R8 (relay-only
# behind CGNAT): Linux conntrack is not every consumer router, and both
# "Internet" links are one kernel (docs/NAT_SOFTWARE_SIM.md "Honest claim").
#
# Written on macOS and NOT run locally (macOS has no network namespaces); the
# lab CI job nat-sim-linux (.github/workflows/raven-serverless-lab.yml) runs it
# on ubuntu-latest, advisory (continue-on-error) until 10 consecutive green
# iterations of the required cases are recorded there (its dispatch input
# nat_sim_repeat sets RAVEN_NETNS_REPEAT).
#
# Usage: build the debug binaries first, as yourself (never cargo as root):
#   (cd node && cargo build --locked -p ash -p raven-node)
#   sudo -E env "PATH=$PATH" bash node/scripts/netns_nat_dcutr.sh
# or let the script re-run itself under `sudo -E`:
#   RAVEN_NETNS_ALLOW_SUDO=1 bash node/scripts/netns_nat_dcutr.sh
# Environment:
#   RAVEN_BIN_DIR              raven + raven-node (default <repo>/node/target/debug)
#   RAVEN_NETNS_TMP            base dir for the per-run temp dirs (kept afterwards;
#                              default: a mktemp -d dir, removed unless RAVEN_NETNS_KEEP=1)
#   RAVEN_NETNS_ALLOW_RELEASE=1  run against a release build path anyway (only
#                              useful once P2P_PRODUCTION_ENABLED is true)
#   RAVEN_NETNS_WAN_PREFIX     the simulated Internet's first two octets (default
#                              11.0; two numbers 0-255). A private prefix such as
#                              10.0 makes the cone run fail: no global candidates
#                              (cone-private always uses 10.0)
#   RAVEN_NETNS_CASES          the cases, space (or comma) separated, in order
#                              (default "cone symmetric cone-private swap"; the
#                              advisory ones only when named: shifted v6fw reach hints
#                              only443 friend friend-sleep diag lan-move lan-ll
#                              lan-isolated lan-nonlocal custody pcp pcp-cgn
#                              v6pin classify punch-skip)
#   RAVEN_NETNS_REPEAT         run the case list this many times, 1-5 (default 1);
#                              one PASS/FAIL line per case and iteration
# Exit: 0 = every required case met its expectations in every iteration,
# 1 = one failed, 2 = cannot run here (not Linux or root, missing tools or
# binaries, or an nftables preflight in a scratch namespace found no named
# counters or no `masquerade random,fully-random`). CI must treat 2 as a
# failure, never as a skip. The advisory cases are reported, never fatal.
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT="$(cd "$(dirname "$SELF")/.." && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "netns_nat_dcutr: Linux only (network namespaces + nftables); see docs/NAT_SOFTWARE_SIM.md for macOS substitutes" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  if [[ "${RAVEN_NETNS_ALLOW_SUDO:-0}" == "1" ]]; then
    echo "netns_nat_dcutr: not root; re-running under sudo -E (RAVEN_NETNS_ALLOW_SUDO=1)" >&2
    exec sudo -E env "PATH=$PATH" bash "$SELF" "$@"
  fi
  echo "netns_nat_dcutr: needs root (it creates network namespaces and nftables NAT rules)." >&2
  echo "  Run: sudo -E env \"PATH=\$PATH\" bash $SELF" >&2
  echo "  or:  RAVEN_NETNS_ALLOW_SUDO=1 bash $SELF   (re-runs itself under sudo -E)" >&2
  exit 2
fi

BIN_DIR="${RAVEN_BIN_DIR:-$ROOT/target/debug}"
NODE="$BIN_DIR/raven-node"
RAVEN="$BIN_DIR/raven"
case "$BIN_DIR" in
  */release | */release/*)
    if [[ "${RAVEN_NETNS_ALLOW_RELEASE:-0}" != "1" ]]; then
      echo "netns_nat_dcutr: RAVEN_BIN_DIR=$BIN_DIR is a release build path. The lab unlock" >&2
      echo "  RAVEN_LAB_TEST_A=1 only works in debug builds, so a release raven-node keeps the p2p" >&2
      echo "  gate closed (P2P_PRODUCTION_ENABLED=false: it logs P2P_HOLD and never listens) and this" >&2
      echo "  test cannot pass. Use target/debug, or set RAVEN_NETNS_ALLOW_RELEASE=1 once the gate is open." >&2
      exit 2
    fi
    ;;
esac
for bin in "$NODE" "$RAVEN"; do
  if [[ ! -x "$bin" ]]; then
    echo "netns_nat_dcutr: missing $bin; build it first (as yourself, not root):" >&2
    echo "  (cd $ROOT && cargo build --locked -p ash -p raven-node)" >&2
    exit 2
  fi
done
for tool in ip nft timeout sysctl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "netns_nat_dcutr: missing '$tool' (Debian/Ubuntu: apt-get install -y iproute2 nftables coreutils procps)" >&2
    exit 2
  fi
done
if ! command -v python3 >/dev/null 2>&1 && ! command -v jq >/dev/null 2>&1; then
  echo "netns_nat_dcutr: needs python3 (or jq) to read relay_status.json" >&2
  exit 2
fi

# Same lab environment for every process (debug locked-file backends, as the
# other smokes use). Caller settings that would change the services are dropped:
# flags beat env, but RAVEN_P2P_RELAY=1 alone would turn A and B into relays.
export RAVEN_IDENTITY_BACKEND=locked-file
export RAVEN_CHAT_HISTORY_BACKEND=locked-file
export RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1
export RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0
export NO_COLOR=1
export RAVEN_LAB_TEST_A=1
# The hole-punch address rule stays the production one (global only): this
# simulation's Internet is global-looking instead.
# RAVEN_LAB_P2P_RELAY_ONLY would keep the shifted run's retired `relay`
# setting from listening. Route hints (RAVEN_LAB_ROUTE_HINTS) are on only in
# the hints run, which exports the switch in its own subshell (the announcer
# hold and friend custody's switches never). The friend
# relay switches (Phase 2) are off unless a case sets them itself, and so are
# the cutoff pack's (its two held gates, default LAN port, gateway and clock),
# the privacy pack's and Phase 3's (the LAN listener's `auto` and the LAN
# beacon: only the lan-* runs that need them, each in its own subshell; friend
# custody's: only the custody run, in its own subshell). So are
# Phase 4's lab switches and harness values, and no proxy setting reaches a
# process: each runs with RAVEN_P2P_PROXY=off, so neither the environment's
# nor the host's system proxy is used (netns_restrictive.sh's proxyonly case
# sets its own).
unset RAVEN_P2P_LISTEN RAVEN_P2P_RELAYS RAVEN_P2P_RELAY RAVEN_INTERNET_LISTEN \
  RAVEN_DATA_DIR ASH_DATA_DIR RAVEN_LAB_P2P_PING RAVEN_LAB_NETWATCH_EVENTS \
  RAVEN_LAB_NET_TAG RAVEN_LAB_P2P_LOCAL_CANDIDATES RAVEN_LAB_P2P_RELAY_ONLY \
  RAVEN_LAB_ROUTE_HINTS RAVEN_LAB_FRIEND_RELAY RAVEN_LAB_FRIEND_RELAY_LISTEN \
  RAVEN_LAB_RELAY_SELECT RAVEN_LAB_P2P_PROFILE_RELAY RAVEN_LAB_OFFLINE \
  RAVEN_LAB_NOISE_PIN RAVEN_LAB_LAN_DEFAULT_PORT RAVEN_LAB_LAN_GATEWAY \
  RAVEN_LAB_CLOCK_FILE RAVEN_LAB_AT_REST RAVEN_LAB_ERASE_ROOT RAVEN_LAB_AT_REST_KEY_FAULT \
  RAVEN_LAB_RETENTION_GRACE_MS RAVEN_LAB_LOGIN_ITEM_ROOT RAVEN_LAB_LOGIN_ITEM_TOOLS \
  RAVEN_LAB_LAN_AUTO RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK RAVEN_LAB_LAN_BEACON \
  RAVEN_LAB_LAN_BEACON_PORT RAVEN_LAB_LAN_BEACON_FAMILY RAVEN_LAB_LAN_BEACON_BUS \
  RAVEN_LAB_WSS RAVEN_LAB_WSS_PROXY RAVEN_P2P_PROXY HTTPS_PROXY https_proxy \
  ALL_PROXY all_proxy NO_PROXY no_proxy RAVEN_LAB_PORT_MAP RAVEN_LAB_V6_PINHOLE \
  RAVEN_LAB_NAT_CLASS RAVEN_LAB_NAT_CLASS_FORCE RAVEN_LAB_PEER_ROTATION \
  RAVEN_LAB_PEER_EPOCH_S RAVEN_LAB_PORTMAP_GATEWAY RAVEN_LAB_PORTMAP_LIFETIME \
  RAVEN_LAB_HINTS_NO_ANNOUNCE RAVEN_LAB_CUSTODY_WAN RAVEN_LAB_CUSTODY_AFTER_MS \
  RAVEN_LAB_CUSTODY_FETCH_MS RAVEN_LAB_CUSTODY_PRETEND_OLD \
  RAVEN_LAB_CUSTODY_BASE_OPS_ONLY RAVEN_LAB_CUSTODY_HANDOFF RAVEN_LAB_CUSTODY_FORWARD_MS \
  RAVEN_LAB_SESSION_RENEWAL RAVEN_LAB_SESSION_LIFETIME_MS RAVEN_LAB_HORIZON \
  RAVEN_LAB_LETTER RAVEN_LAB_NEARBY RAVEN_LAB_NEARBY_ETHER \
  RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR RAVEN_LAB_NEARBY_FOREGROUND_MS RAVEN_LAB_NET_AUDIT \
  RAVEN_LAB_NEARBY_ONLY RAVEN_LAB_BLUEZ_BTVIRT \
  RAVEN_LAB_LEARNING RAVEN_LAB_LEARNING_TUNE RAVEN_LAB_LEARNING_SEALER \
  RAVEN_LAB_SECURITY_EVENTS RAVEN_LAB_SECURITY_RESPONSES RAVEN_LAB_SUITE_FLOOR \
  RAVEN_LAB_LINK_PADDING RAVEN_LAB_LINK_KNOCK RAVEN_LAB_RANDOM_PORT RAVEN_LAB_PAIR_SEED \
  RAVEN_LAB_LOCAL_PROTECTION RAVEN_LAB_ADVISORY RAVEN_LAB_RELEASE_BUNDLE \
  RAVEN_LAB_MESH_UPDATE RAVEN_LAB_SEC_PENALTY_LOOPBACK RAVEN_LAB_RELEASE_KEYS_FILE \
  RAVEN_LAB_UPDATE_AUTO_APPROVE RAVEN_LAB_UPDATE_CLAIM_NEWER \
  2>/dev/null || true
export RAVEN_P2P_PROXY=off

# The simulated Internet: WAN.0.1 is R, WAN.<n>.0/24 the router links.
WAN="${RAVEN_NETNS_WAN_PREFIX:-11.0}"
if [[ ! "$WAN" =~ ^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$ ]]; then
  echo "netns_nat_dcutr: RAVEN_NETNS_WAN_PREFIX must be two numbers 0-255 (like 11.0), not '$WAN'" >&2
  exit 2
fi
# cone-private's "Internet" (RFC 1918), whatever RAVEN_NETNS_WAN_PREFIX says.
PRIVATE_WAN="10.0"

# The cases, each once per iteration, in the order given (duplicates dropped).
REQUIRED_CASES="cone symmetric cone-private swap"
ADVISORY_CASES="shifted v6fw reach hints only443 friend friend-sleep diag lan-move lan-ll lan-isolated lan-nonlocal custody pcp pcp-cgn v6pin classify punch-skip learn-flaky"
IFS=', ' read -r -a CASE_ARGS <<<"${RAVEN_NETNS_CASES:-$REQUIRED_CASES}"
CASE_LIST=()
for name in ${CASE_ARGS[@]+"${CASE_ARGS[@]}"}; do
  [[ -n "$name" ]] || continue
  if [[ " $REQUIRED_CASES $ADVISORY_CASES " != *" $name "* ]]; then
    echo "netns_nat_dcutr: RAVEN_NETNS_CASES names an unknown case '$name' (cases: $REQUIRED_CASES $ADVISORY_CASES)" >&2
    exit 2
  fi
  if [[ " ${CASE_LIST[*]-} " != *" $name "* ]]; then
    CASE_LIST+=("$name")
  fi
done
if [[ ${#CASE_LIST[@]} -eq 0 ]]; then
  echo "netns_nat_dcutr: RAVEN_NETNS_CASES names no case (cases: $REQUIRED_CASES $ADVISORY_CASES)" >&2
  exit 2
fi
REPEAT="${RAVEN_NETNS_REPEAT:-1}"
if [[ ! "$REPEAT" =~ ^[1-5]$ ]]; then
  echo "netns_nat_dcutr: RAVEN_NETNS_REPEAT must be a whole number 1-5, not '$REPEAT'" >&2
  exit 2
fi
# advisory CASE: reported, never fatal.
advisory() {
  [[ " $ADVISORY_CASES " == *" $1 "* ]]
}

# Bounds (seconds). Every wait below is a deadline loop on an observable
# condition and fails with all logs printed.
RELAY_WAIT=30
RESERVE_WAIT=90
CLI_TIMEOUT=60
SEND_TIMEOUT=120
INBOX_WAIT=15
DCUTR_WAIT=90
DCUTR_OBSERVE=20
SWAP_BACKOFF=25
SWAP_NOTICE=20
SWAP_DELIVER=90
# cone run: how long to watch the routers' counters after the stranger's
# probe (a hole punch would dial within a second or two of the circuit).
R14_OBSERVE=5
# reach run: each AutoNAT client tests a candidate within its 15 s probe
# interval once its relay is connected.
REACH_WAIT=240
# hints run: delivery after B's uplink swap, how long A may take to hold
# B's new-generation hints, and how long rA's counter must then stay flat.
HINTS_DELIVER=30
HINTS_LEARN=60
HINTS_FLAT=10
# only443 run: A's reservation over the 443 fallback (its first dial, to the
# filtered 7423, times out after the host's 10 s connection timeout).
ONLY443_RESERVE=40
# friend-sleep run: B replaces a stopped operator's relay within this, and no
# second replacement may follow in this long after the operator continues.
FRIEND_REPLACE=60
FRIEND_STICKY=60
# diag run: how long A may take to give a reason, and to deliver the queued
# message once the stopped relay continues (its outbox may be in a long
# backoff by then).
DIAG_REASON=120
DIAG_DELIVER=180
# lan-* runs (Phase 3): the LAN before and after the renumbering (lan-move),
# how long a node may take to bring its LAN beacon up, how long queued
# messages may take once both are on the new network, and how long an
# isolated sender keeps asking in vain.
LAN_OLD="10.77.1"
LAN_NEW="10.88.1"
LAN_UP_WAIT=60
LAN_DELIVER=30
LAN_ISOLATED_WATCH=45
# learn-flaky run (Phase 6a): sends per half, the gap between them, the
# length of a loss burst (and of the clear spell after it) and its loss.
LEARN_SENDS=20
LEARN_GAP=6
LEARN_BURST=120
LEARN_LOSS="30%"
# classify and punch-skip runs: how long a node may take to classify its
# NAT (Identify reports what each relay saw as soon as it is connected).
NATCLASS_WAIT=90

LINE_HOLD='P2P_HOLD:'
LINE_RESERVED='raven-node p2p: reservation accepted'
LINE_DCUTR='raven-node p2p: direct connection upgraded (dcutr)'
LINE_PUNCH_FAILED='raven-node p2p: hole punch failed'
LINE_HOST_UP='raven-node p2p: host up'
LINE_GATE_ONE='raven-node p2p: peer gate reloaded (verified contacts 1,'
LINE_GATE_TWO='raven-node p2p: peer gate reloaded (verified contacts 2,'
# The peer gate's counts-only refusal (no PeerId), and the Raven link's own
# refusal of a non-contact, which a gated stranger must never reach.
LINE_GATE_REFUSED='raven-node p2p: refused a connection from a peer that is not a verified contact'
LINE_INBOUND='p2p inbound'
LINE_NETCHANGE='raven-node netwatch: network changed (1 new, 1 gone, 1 now)'
LINE_REHOMING=', p2p re-homing'
LINE_REHOMED='raven-node p2p: re-homed (network changed)'
LINE_RETIRED='raven-node p2p: listen setting "relay" is retired'
LINE_REACH='raven-node p2p: reachability '
# Phase 4 (P4.24): the NAT_CLASS lab, the classifier's line and a skip.
LINE_NATCLASS_LAB='raven-node p2p: lab NAT mapping classes and hole-punch skips'
LINE_NATCLASS='raven-node p2p: NAT mapping '
LINE_PUNCH_SKIPPED='raven-node p2p: hole punch skipped (both'
LINE_REPLACED='raven-node p2p: relay replaced'
LINE_FRIEND_UP='raven-node friend relay: up'
# custody run: a node's mail friend chosen from an offer, and a deposit
# (`left N with a friend (p2p_dial, relayed)`).
LINE_MAIL_FRIENDS='raven-node custody: mail friends now 1'
LINE_CUSTODY_LEFT='raven-node custody: left '
# lan-* runs: the LAN listener on both families (`auto`, its first socket),
# the beacon running, a beacon find in `raven send`'s route lines, and the
# counts-only line of a connection `auto` closed for its source.
LINE_LAN_AUTO='raven-node lan_direct: listen 0.0.0.0:7420'
LINE_BEACON_ON='raven-node lan_beacon: on ('
TEXT_FOUND='(found on your network now'
LINE_NON_LOCAL='closed a connection from outside the local network before reading it ('
# diag run: the line a dial with a reason logs (its token only).
LINE_UNREACHABLE='raven-node p2p: a contact is unreachable ('
# What a failed p2p dial adds when the contact's own node turned it away at
# once, and when its relay did (that one asks for `raven relay allow`). A
# node that refuses a circuit through a relay gives neither: the relay's
# CONNECTION_FAILED reads as the contact being offline (C-relay-kit-1).
HINT_NODE_REFUSED="the contact's node refused the p2p connection at once"
HINT_RELAY_REFUSED="the contact's relay refused this node"
# `raven send` path labels.
PATH_RELAYED='relayed'
PATH_PUNCHED='hole_punched'
# shifted run: the outside port each router maps its host's 7423 to.
SHIFT_PORT=30000
# v6fw run: the simulated Internet's IPv6 (the WAN prefix's twin).
V6='2c0f:fff0:a'

# Per-run prefix: never touches (or deletes) a namespace this script did not make.
NSP="rvn$$"
NS_PUB="${NSP}-pub"
NS_RA="${NSP}-rA"
NS_RB="${NSP}-rB"
NS_RA2="${NSP}-rA2"
NS_RB2="${NSP}-rB2"
NS_HA="${NSP}-hA"
NS_HB="${NSP}-hB"
NS_HP="${NSP}-hP"
NS_HQ="${NSP}-hQ"
NS_RN="${NSP}-rN"
NS_HN="${NSP}-hN"
NS_HD="${NSP}-hD"
NS_HE="${NSP}-hE"
NS_RC="${NSP}-rC"
NS_HC="${NSP}-hC"
NS_HO="${NSP}-hO"
NS_SW="${NSP}-sw"
NS_HS="${NSP}-hS"
NS_RL="${NSP}-rL"
NS_HX="${NSP}-hX"

BASE_OWNED=0
if [[ -n "${RAVEN_NETNS_TMP:-}" ]]; then
  BASE="$RAVEN_NETNS_TMP"
  mkdir -p "$BASE"
else
  BASE="$(mktemp -d)"
  BASE_OWNED=1
fi
BASE="$(cd "$BASE" && pwd)"

# Namespaces with our prefix: kill whatever still runs inside, then delete them.
teardown_net() {
  local ns pids
  for ns in $(ip netns list 2>/dev/null | awk -v p="${NSP}-" 'index($1, p) == 1 { print $1 }'); do
    pids="$(ip netns pids "$ns" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      # shellcheck disable=SC2086 # one PID per word
      kill -KILL $pids 2>/dev/null || true
    fi
    ip netns del "$ns" 2>/dev/null || true
  done
}

main_cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  teardown_net
  if [[ "$BASE_OWNED" == "1" && "${RAVEN_NETNS_KEEP:-0}" != "1" ]]; then
    rm -rf "$BASE"
  else
    echo "netns_nat_dcutr: run dirs (logs under */logs) kept in $BASE" >&2
  fi
  exit "$rc"
}
trap main_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---- per-run helpers (used inside the run subshell) -------------------------

PIDS=()
MODE=""
LOGS=""
R=""
VIA=""

dump_logs() {
  local f
  if [[ -z "$LOGS" || ! -d "$LOGS" ]]; then
    return 0
  fi
  echo "===== logs of the $MODE run ($LOGS) =====" >&2
  for f in "$LOGS"/*; do
    [[ -f "$f" ]] || continue
    echo "----- $(basename "$f")" >&2
    cat "$f" >&2 || true
  done
  if [[ -n "$R" && -s "$R/relay_status.json" ]]; then
    echo "----- relay_status.json" >&2
    cat "$R/relay_status.json" >&2 || true
    echo >&2
  fi
  dump_routers
  echo "===== end of logs ($MODE) =====" >&2
}

# dump_routers: each router namespace of this run that still exists, with its
# nft ruleset, its named counters and (when conntrack is installed) its
# connection tracking table.
dump_routers() {
  local ns
  for ns in "$NS_RA" "$NS_RB" "$NS_RA2" "$NS_RN" "$NS_RB2" "$NS_RC"; do
    if ! ip netns list 2>/dev/null | awk -v n="$ns" '$1 == n { found = 1 } END { exit !found }'; then
      continue
    fi
    echo "----- $ns: nft list ruleset" >&2
    in_ns "$ns" nft list ruleset >&2 || true
    echo "----- $ns: counters lan_to_other=$(counter "$ns" lan_to_other || echo '?')" \
      "wan_from_other=$(counter "$ns" wan_from_other || echo '?')" >&2
    if command -v conntrack >/dev/null 2>&1; then
      echo "----- $ns: conntrack -L" >&2
      in_ns "$ns" conntrack -L >&2 || true
    fi
  done
  # The only443 run's egress filter on hA.
  if ip netns exec "$NS_HA" nft list table inet r443 >/dev/null 2>&1; then
    echo "----- $NS_HA: egress filter tcp443=$(nft_counter "$NS_HA" inet r443 tcp443 || echo '?')" \
      "dropped=$(nft_counter "$NS_HA" inet r443 dropped || echo '?')" \
      "tcp7423=$(nft_counter "$NS_HA" inet r443 tcp7423 || echo '?')" \
      "tcp7427=$(nft_counter "$NS_HA" inet r443 tcp7427 || echo '?')" >&2
  fi
  # The friend runs' count of C's established flows to anyone but the operators.
  if ip netns exec "$NS_RC" nft list table ip raven_friend >/dev/null 2>&1; then
    echo "----- $NS_RC: c_direct_est=$(nft_counter "$NS_RC" ip raven_friend c_direct_est || echo '?')" >&2
  fi
}

fail() {
  echo "NETNS_NAT_DCUTR_FAIL ($MODE): $*" >&2
  dump_logs
  exit 1
}

stop_procs() {
  local pid alive i
  if [[ ${#PIDS[@]} -eq 0 ]]; then
    return 0
  fi
  for pid in "${PIDS[@]}"; do
    # A process stopped by a friend-sleep run would hold the TERM pending.
    kill -CONT "$pid" 2>/dev/null || true
    kill -TERM "$pid" 2>/dev/null || true
  done
  for ((i = 0; i < 50; i++)); do
    alive=0
    for pid in "${PIDS[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then alive=1; fi
    done
    [[ "$alive" -eq 1 ]] || break
    sleep 0.1
  done
  for pid in "${PIDS[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  PIDS=()
}

run_cleanup() {
  trap - EXIT INT TERM
  stop_procs
  teardown_net
}

# in_ns NS CMD...: CMD inside NS, bounded by CLI_TIMEOUT.
in_ns() {
  local ns=$1
  shift
  timeout "$CLI_TIMEOUT" ip netns exec "$ns" "$@"
}

# Fails when any of the given PIDs has exited.
require_alive() {
  local pid
  for pid in "$@"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      fail "process $pid exited early"
    fi
  done
}

# Fails when a log says the p2p gate is closed.
check_hold() {
  local log
  for log in "$@"; do
    if grep -Fq -- "$LINE_HOLD" "$log" 2>/dev/null; then
      fail "$(basename "$log") logged $LINE_HOLD: the p2p gate is closed. The lab unlock RAVEN_LAB_TEST_A=1 only works in debug builds ($NODE)."
    fi
  done
}

# wait_line LOG FIXED_TEXT SECS PID...: until LOG contains FIXED_TEXT.
wait_line() {
  local log=$1 text=$2 secs=$3 deadline
  shift 3
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if grep -Fq -- "$text" "$log" 2>/dev/null; then
      return 0
    fi
    check_hold "$log"
    require_alive "$@"
    sleep 0.2
  done
  fail "'$text' not in $(basename "$log") within ${secs}s"
}

# wait_ipc NS DATA_DIR SECS PID: until the daemon answers `raven ipc-ping`.
wait_ipc() {
  local ns=$1 dir=$2 secs=$3 pid=$4 deadline
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if in_ns "$ns" "$RAVEN" --data-dir "$dir" ipc-ping >/dev/null 2>&1; then
      return 0
    fi
    require_alive "$pid"
    sleep 0.2
  done
  fail "daemon for $dir did not answer ipc-ping within ${secs}s"
}

# Prints relay_status.json's peer_id (nothing while the file is absent or partial).
relay_peer_id() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["peer_id"])' "$1" 2>/dev/null || true
  else
    jq -er '.peer_id' "$1" 2>/dev/null || true
  fi
}

# nat_ruleset MASQ RELAY_IP [PRE]: a router's nft table. NAT out of "wan"
# (PRE: NAT rules that come before the masquerade), forward lan -> wan and
# replies only, drop unsolicited inbound, and the two named counters of every
# packet that is not to or from the relay (see the header).
nat_ruleset() {
  local masq=$1 relay=$2 pre=${3:-}
  cat <<EOF
table ip raven_nat {
  counter lan_to_other {
  }
  counter wan_from_other {
  }
  chain prerouting {
    type filter hook prerouting priority -150; policy accept;
    iifname "wan" ip saddr != $relay counter name "wan_from_other"
  }
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    $pre
    oifname "wan" $masq
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "lan" oifname "wan" ip daddr != $relay counter name "lan_to_other"
    ct state established,related accept
    iifname "lan" oifname "wan" accept
  }
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "wan" ct state new drop
  }
}
EOF
}

# nat_rules NS MASQ RELAY_IP [PRE]: one router namespace, forwarding on, with
# nat_ruleset.
nat_rules() {
  local ns=$1 masq=$2 relay=$3 pre=${4:-}
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  nat_ruleset "$masq" "$relay" "$pre" | ip netns exec "$ns" nft -f - \
    || fail "nft rejected the router ruleset in $ns ('$masq')"
}

# counter NS NAME: the packets NS's named counter NAME has seen. Status 1 and
# no output when that is not a number (a broken read never passes as 0).
counter() {
  nft_counter "$1" ip raven_nat "$2"
}

# nft_counter NS FAMILY TABLE NAME: the packets of any named counter, read as
# counter reads them.
nft_counter() {
  local n
  n="$(ip netns exec "$1" nft list counter "$2" "$3" "$4" 2>/dev/null \
    | awk '{ for (i = 1; i < NF; i++) if ($i == "packets") { print $(i + 1); exit } }')" || true
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  echo "$n"
}

# reset_counters: zero rA's and rB's named counters.
reset_counters() {
  local ns name
  for ns in "$NS_RA" "$NS_RB"; do
    for name in lan_to_other wan_from_other; do
      ip netns exec "$ns" nft reset counter ip raven_nat "$name" >/dev/null \
        || fail "cannot reset the nft counter $name in $ns"
    done
  done
}

# read_counters: rA's and rB's counters into CNT_A_LAN, CNT_A_WAN, CNT_B_LAN
# and CNT_B_WAN (lan_to_other, wan_from_other), and one line saying them.
CNT_A_LAN=""
CNT_A_WAN=""
CNT_B_LAN=""
CNT_B_WAN=""
read_counters() {
  CNT_A_LAN="$(counter "$NS_RA" lan_to_other)" || fail "cannot read rA's nft counter lan_to_other"
  CNT_A_WAN="$(counter "$NS_RA" wan_from_other)" || fail "cannot read rA's nft counter wan_from_other"
  CNT_B_LAN="$(counter "$NS_RB" lan_to_other)" || fail "cannot read rB's nft counter lan_to_other"
  CNT_B_WAN="$(counter "$NS_RB" wan_from_other)" || fail "cannot read rB's nft counter wan_from_other"
  echo "counters (packets not to or from R): rA lan_to_other=$CNT_A_LAN wan_from_other=$CNT_A_WAN," \
    "rB lan_to_other=$CNT_B_LAN wan_from_other=$CNT_B_WAN"
}

setup_net() {
  local masq=$1 ns
  for ns in "$NS_PUB" "$NS_RA" "$NS_RB" "$NS_HA" "$NS_HB"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  # veth pairs are created inside the namespaces: nothing appears on the host.
  ip -n "$NS_PUB" link add wa type veth peer name wan netns "$NS_RA"
  ip -n "$NS_PUB" link add wb type veth peer name wan netns "$NS_RB"
  ip -n "$NS_RA" link add lan type veth peer name eth0 netns "$NS_HA"
  ip -n "$NS_RB" link add lan type veth peer name eth0 netns "$NS_HB"
  # pub = "the Internet": R on WAN.0.1, one link per router, routes between them.
  ip -n "$NS_PUB" addr add "$WAN.0.1/32" dev lo
  ip -n "$NS_PUB" addr add "$WAN.1.1/24" dev wa
  ip -n "$NS_PUB" addr add "$WAN.2.1/24" dev wb
  ip -n "$NS_PUB" link set wa up
  ip -n "$NS_PUB" link set wb up
  ip netns exec "$NS_PUB" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$NS_RA" addr add "$WAN.1.2/24" dev wan
  ip -n "$NS_RA" addr add 192.168.1.1/24 dev lan
  ip -n "$NS_RA" link set wan up
  ip -n "$NS_RA" link set lan up
  ip -n "$NS_RA" route add default via "$WAN.1.1"
  ip -n "$NS_RB" addr add "$WAN.2.2/24" dev wan
  ip -n "$NS_RB" addr add 192.168.2.1/24 dev lan
  ip -n "$NS_RB" link set wan up
  ip -n "$NS_RB" link set lan up
  ip -n "$NS_RB" route add default via "$WAN.2.1"
  ip -n "$NS_HA" addr add 192.168.1.2/24 dev eth0
  ip -n "$NS_HA" link set eth0 up
  ip -n "$NS_HA" route add default via 192.168.1.1
  ip -n "$NS_HB" addr add 192.168.2.2/24 dev eth0
  ip -n "$NS_HB" link set eth0 up
  ip -n "$NS_HB" route add default via 192.168.2.1
  if [[ "$MODE" == "shifted" ]]; then
    nat_rules "$NS_RA" "$masq" "$WAN.0.1" "$(shift_rules 192.168.1.2 "$WAN.1.2")"
    nat_rules "$NS_RB" "$masq" "$WAN.0.1" "$(shift_rules 192.168.2.2 "$WAN.2.2")"
  else
    nat_rules "$NS_RA" "$masq" "$WAN.0.1"
    nat_rules "$NS_RB" "$masq" "$WAN.0.1"
  fi
  # WAN is global-looking address space: the simulation must not route out.
  if [[ -n "$(ip -n "$NS_PUB" route show default 2>/dev/null)" ]]; then
    fail "pub has a default route: the simulated Internet ($WAN.0.0/16) must not reach the real one"
  fi
  {
    echo "== $MODE: routers do '$masq', WAN $WAN.0.0/16"
    ip netns exec "$NS_RA" nft list ruleset
  } >"$LOGS/topology.log" 2>&1
  # Sanity (when ping exists): both hosts reach R through their NAT, and neither
  # reaches the other's private address.
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HA" ping -c 1 -W 2 "$WAN.0.1" >>"$LOGS/topology.log" 2>&1 || fail "hA cannot reach R ($WAN.0.1) through rA"
    in_ns "$NS_HB" ping -c 1 -W 2 "$WAN.0.1" >>"$LOGS/topology.log" 2>&1 || fail "hB cannot reach R ($WAN.0.1) through rB"
    if in_ns "$NS_HA" ping -c 1 -W 1 192.168.2.2 >>"$LOGS/topology.log" 2>&1; then
      fail "hA reaches hB's private address directly: the topology leaks"
    fi
  fi
  # The pings above count (the one that must fail goes to a non-relay address).
  reset_counters
  if [[ "$MODE" == "v6fw" ]]; then
    setup_v6
  fi
}

# shift_rules HOST WAN_IP: the shifted run's endpoint-independent port
# rewrite, HOST's 7423 to WAN_IP:SHIFT_PORT for every destination.
shift_rules() {
  printf 'oifname "wan" ip saddr %s tcp sport 7423 snat to %s:%s\n' "$1" "$2" "$SHIFT_PORT"
  printf '    oifname "wan" ip saddr %s udp sport 7423 snat to %s:%s\n' "$1" "$2" "$SHIFT_PORT"
}

# The v6fw run's IPv6: global-looking addresses on both hosts, routed by pub,
# and a stateful forward chain on each router (outbound and replies only, as
# a home router's IPv6 firewall does). No NAT for IPv6.
setup_v6() {
  local ns
  for ns in "$NS_PUB" "$NS_RA" "$NS_RB"; do
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.forwarding=1
  done
  ip -n "$NS_PUB" -6 addr add "$V6:f1::1/64" dev wa nodad
  ip -n "$NS_PUB" -6 addr add "$V6:f2::1/64" dev wb nodad
  ip -n "$NS_PUB" -6 route add "$V6:1::/64" via "$V6:f1::2"
  ip -n "$NS_PUB" -6 route add "$V6:2::/64" via "$V6:f2::2"
  ip -n "$NS_RA" -6 addr add "$V6:f1::2/64" dev wan nodad
  ip -n "$NS_RA" -6 addr add "$V6:1::1/64" dev lan nodad
  ip -n "$NS_RA" -6 route add default via "$V6:f1::1"
  ip -n "$NS_RB" -6 addr add "$V6:f2::2/64" dev wan nodad
  ip -n "$NS_RB" -6 addr add "$V6:2::1/64" dev lan nodad
  ip -n "$NS_RB" -6 route add default via "$V6:f2::1"
  ip -n "$NS_HA" -6 addr add "$V6:1::2/64" dev eth0 nodad
  ip -n "$NS_HA" -6 route add default via "$V6:1::1"
  ip -n "$NS_HB" -6 addr add "$V6:2::2/64" dev eth0 nodad
  ip -n "$NS_HB" -6 route add default via "$V6:2::1"
  for ns in "$NS_RA" "$NS_RB"; do
    ip netns exec "$ns" nft -f - <<EOF
table ip6 raven_fw {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "lan" oifname "wan" accept
  }
}
EOF
  done
  if [[ -n "$(ip -n "$NS_PUB" -6 route show default 2>/dev/null)" ]]; then
    fail "pub has an IPv6 default route: $V6::/48 must not reach the real Internet"
  fi
  {
    echo "== $MODE: IPv6 $V6::/48 behind a stateful ip6 forward chain"
    ip netns exec "$NS_RA" nft list table ip6 raven_fw
  } >>"$LOGS/topology.log" 2>&1
  # Sanity (when ping exists): hA reaches pub over IPv6, but not hB
  # unsolicited (the firewall drops it).
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HA" ping -6 -c 1 -W 2 "$V6:f2::1" >>"$LOGS/topology.log" 2>&1 \
      || fail "hA cannot reach pub over IPv6 ($V6:f2::1)"
    if in_ns "$NS_HA" ping -6 -c 1 -W 1 "$V6:2::2" >>"$LOGS/topology.log" 2>&1; then
      fail "hA reaches hB's IPv6 unsolicited: rB's firewall is not stateful"
    fi
  fi
}

# The swap run's second router for A: pub "wc" WAN.3.1 -- rA2 "wan" WAN.3.2,
# rA2 "lan" 192.168.3.1 -- hA "eth1", which stays down with no address until
# the swap (A's netwatch must not see it before).
setup_swap_router() {
  ip netns add "$NS_RA2"
  ip -n "$NS_RA2" link set lo up
  ip -n "$NS_PUB" link add wc type veth peer name wan netns "$NS_RA2"
  ip -n "$NS_RA2" link add lan type veth peer name eth1 netns "$NS_HA"
  ip -n "$NS_PUB" addr add "$WAN.3.1/24" dev wc
  ip -n "$NS_PUB" link set wc up
  ip -n "$NS_RA2" addr add "$WAN.3.2/24" dev wan
  ip -n "$NS_RA2" addr add 192.168.3.1/24 dev lan
  ip -n "$NS_RA2" link set wan up
  ip -n "$NS_RA2" link set lan up
  ip -n "$NS_RA2" route add default via "$WAN.3.1"
  nat_rules "$NS_RA2" "masquerade" "$WAN.0.1"
  {
    echo "== $MODE: second router rA2 (masquerade), hA eth1 down until the swap"
    ip netns exec "$NS_RA2" nft list ruleset
  } >>"$LOGS/topology.log" 2>&1
}

# Swap hA's uplink from rA to rA2, as a laptop moving to another network.
swap_uplink() {
  ip -n "$NS_HA" addr flush dev eth0
  ip -n "$NS_HA" link set eth0 down
  ip -n "$NS_HA" addr add 192.168.3.2/24 dev eth1
  ip -n "$NS_HA" link set eth1 up
  ip -n "$NS_HA" route add default via 192.168.3.1
}

# raven_init NS DIR NAME: init + prekey publish; sets INIT_FP (the
# fingerprint), INIT_ADDR and INIT_PUB.
INIT_FP=""
INIT_ADDR=""
INIT_PUB=""
raven_init() {
  local ns=$1 dir=$2 name=$3 out addr pub fp
  out="$LOGS/$name.init.out"
  in_ns "$ns" "$RAVEN" --data-dir "$dir" init >"$out" 2>&1 || fail "raven init ($name) failed"
  addr="$(sed -n 's/^address=//p' "$out" | head -n 1)"
  pub="$(sed -n 's/^pub_hex=//p' "$out" | head -n 1)"
  fp="$(sed -n 's/^fingerprint=//p' "$out" | head -n 1)"
  if [[ -z "$addr" || -z "$pub" || -z "$fp" ]]; then
    fail "raven init ($name) printed no address= / pub_hex= / fingerprint= line"
  fi
  in_ns "$ns" "$RAVEN" --data-dir "$dir" prekey publish >"$LOGS/$name.prekey.out" 2>&1 \
    || fail "raven prekey publish ($name) failed"
  INIT_FP="$fp"
  INIT_ADDR="$addr"
  INIT_PUB="$pub"
}

# raven_card NS DIR NAME: sets CARD to the one raven-card/2 line (with via=$VIA),
# or in the hints run (route hints on) the raven-card/3 line (relay=$VIA).
CARD=""
raven_card() {
  local ns=$1 dir=$2 name=$3 out card
  out="$LOGS/$name.card.out"
  in_ns "$ns" "$RAVEN" --data-dir "$dir" whoami --card --via "$VIA" >"$out" 2>&1 \
    || fail "raven whoami --card ($name) failed"
  card="$(grep -m 1 -E '^raven-card/[23] ' "$out" || true)"
  if [[ -z "$card" ]]; then
    fail "raven whoami --card --via ($name) printed no raven-card/2 (or /3) line"
  fi
  if [[ "$card" != *" p2p="* ]]; then
    fail "the $name card has no p2p= field"
  fi
  CARD="$card"
}

# send_check NS DIR TO TEXT TAG: `raven send --carrier p2p` must report
# delivered. Verbose, so its detail line ends with how the link travelled:
# LAST_PATH is that `path=` label, and a send without one fails.
LAST_PATH=""
send_check() {
  local ns=$1 dir=$2 to=$3 text=$4 tag=$5 rc=0
  printf '%s\n' "$text" | timeout "$SEND_TIMEOUT" ip netns exec "$ns" env RAVEN_VERBOSE=1 \
    "$RAVEN" --data-dir "$dir" send --contact "@$to" --carrier p2p \
    >"$LOGS/$tag.send.out" 2>"$LOGS/$tag.send.err" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    fail "send $tag exited $rc"
  fi
  if ! awk 'tolower($0) ~ /status/ && tolower($0) ~ /delivered/ { found = 1 } END { exit !found }' \
    "$LOGS/$tag.send.out"; then
    fail "send $tag did not print a 'status ... delivered' line"
  fi
  LAST_PATH="$(grep -oE ' path=[a-z_]+' "$LOGS/$tag.send.out" | tail -n 1 | cut -d= -f2 || true)"
  if [[ -z "$LAST_PATH" ]]; then
    fail "send $tag printed no path= label (raven send --verbose names how the link travelled)"
  fi
  echo "$tag: delivered, path=$LAST_PATH"
}

# require_path WANT WHAT: the last send travelled WANT (alternatives joined
# by |, like "relayed|hole_punched").
require_path() {
  if [[ "|$1|" != *"|$LAST_PATH|"* ]]; then
    fail "$2 travelled path=$LAST_PATH, not $1"
  fi
}

# relayed_only WHAT: in the runs where nothing may hole-punch (symmetric,
# cone-private), the last send travelled through R.
relayed_only() {
  case "$MODE" in
    symmetric | cone-private) require_path "$PATH_RELAYED" "$1" ;;
  esac
}

# inbox_once NS DIR TEXT TAG [SECS]: the receiver's inbox shows TEXT exactly
# once (waiting up to SECS, default INBOX_WAIT, for it to arrive).
inbox_once() {
  local ns=$1 dir=$2 text=$3 tag=$4 wait=${5:-$INBOX_WAIT} out deadline count
  out="$LOGS/$tag.inbox.out"
  deadline=$((SECONDS + wait))
  while :; do
    in_ns "$ns" "$RAVEN" --data-dir "$dir" inbox >"$out" 2>&1 || fail "raven inbox ($tag) failed"
    count="$(grep -cF -- "$text" "$out" || true)"
    if [[ "$count" -ge 1 ]] || ((SECONDS >= deadline)); then
      break
    fi
    sleep 0.5
  done
  if [[ "$count" -ne 1 ]]; then
    fail "inbox ($tag) shows '$text' $count times, expected exactly once"
  fi
}

# send_queued NS DIR TO TEXT TAG: `raven send --carrier p2p` must end queued
# (not delivered yet: raven-node's outbox keeps the message).
send_queued() {
  local ns=$1 dir=$2 to=$3 text=$4 tag=$5 rc=0
  printf '%s\n' "$text" | timeout "$SEND_TIMEOUT" ip netns exec "$ns" "$RAVEN" --data-dir "$dir" \
    send --contact "@$to" --carrier p2p >"$LOGS/$tag.send.out" 2>"$LOGS/$tag.send.err" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    fail "send $tag succeeded while the receiver is down"
  fi
  if ! grep -Fq 'not delivered yet' "$LOGS/$tag.send.out" "$LOGS/$tag.send.err"; then
    fail "send $tag (exit $rc) was not queued"
  fi
}

# count_lines LOG FIXED_TEXT: how many lines of LOG contain FIXED_TEXT.
count_lines() {
  local n
  n="$(grep -cF -- "$2" "$1" 2>/dev/null)" || true
  echo "${n:-0}"
}

# left DEADLINE: whole seconds until DEADLINE (a $SECONDS value), at least 1.
left() {
  local n=$(($1 - SECONDS))
  echo $((n > 1 ? n : 1))
}

# dcutr_count: DCUtR upgrade lines in both service logs so far.
dcutr_count() {
  echo $(($(count_lines "$LOGS/a.service.log" "$LINE_DCUTR") + $(count_lines "$LOGS/b.service.log" "$LINE_DCUTR")))
}

# wait_count LOG FIXED_TEXT N SECS PID...: until LOG has N lines with FIXED_TEXT.
wait_count() {
  local log=$1 text=$2 want=$3 secs=$4 deadline
  shift 4
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if [[ "$(count_lines "$log" "$text")" -ge "$want" ]]; then
      return 0
    fi
    require_alive "$@"
    sleep 0.2
  done
  fail "fewer than $want '$text' lines in $(basename "$log") within ${secs}s"
}

# dcutr_seen: true when either service logged the DCUtR upgrade.
dcutr_seen() {
  grep -Fq -- "$LINE_DCUTR" "$LOGS/a.service.log" "$LOGS/b.service.log" 2>/dev/null
}

# ---- one run ----------------------------------------------------------------

run_case() {
  local masq run_dir a b s relay_pid a_pid b_pid s_pid peer deadline a_fp b_fp a_card b_card s_card
  local listen="0.0.0.0:7423" only log punch_failed
  MODE=$1
  case "$MODE" in
    cone | cone-private | swap | shifted) masq="masquerade" ;;
    symmetric | v6fw) masq="masquerade random,fully-random" ;;
    *) echo "unknown run $MODE" >&2; exit 1 ;;
  esac
  case "$MODE" in
    # The retired setting: it must listen on 7423 anyway.
    shifted) listen="relay" ;;
    # Every interface, IPv4 and IPv6.
    v6fw) listen="7423" ;;
    # This run only (its own subshell): a private "Internet".
    cone-private) WAN="$PRIVATE_WAN" ;;
  esac
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r"
  a="$run_dir/a"
  b="$run_dir/b"
  s="$run_dir/s"
  mkdir -p "$LOGS" "$R" "$a" "$b"
  chmod 700 "$R" "$a" "$b"
  echo "=== $MODE run: routers do '$masq', WAN $WAN.0.0/16 (dirs under $run_dir) ==="

  setup_net "$masq"
  if [[ "$MODE" == "swap" ]]; then
    setup_swap_router
  fi

  echo "--- relay R in pub on $WAN.0.1:7423"
  ip netns exec "$NS_PUB" "$NODE" relay --data-dir "$R" --listen "$WAN.0.1:7423" \
    >"$LOGS/relay.log" 2>&1 &
  relay_pid=$!
  PIDS+=("$relay_pid")
  peer=""
  deadline=$((SECONDS + RELAY_WAIT))
  while ((SECONDS < deadline)); do
    if [[ -s "$R/relay_status.json" ]]; then
      peer="$(relay_peer_id "$R/relay_status.json")"
      [[ -z "$peer" ]] || break
    fi
    check_hold "$LOGS/relay.log"
    require_alive "$relay_pid"
    sleep 0.2
  done
  if [[ -z "$peer" ]]; then
    fail "relay_status.json with a peer_id not written within ${RELAY_WAIT}s"
  fi
  if [[ ! "$peer" =~ ^[1-9A-HJ-NP-Za-km-z]+$ ]]; then
    fail "relay peer_id is not a base58 PeerId"
  fi
  VIA="/ip4/$WAN.0.1/tcp/7423/p2p/$peer"
  echo "VIA=$VIA"

  echo "--- init A (hA) and B (hB), cards with via=, allow both on R"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  raven_card "$NS_HA" "$a" a
  a_card="$CARD"
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  : >"$LOGS/relay.allow.out"
  if [[ "$MODE" == "cone" ]]; then
    echo "--- init the stranger S (hA): in R's circle, unknown to B"
    mkdir -p "$s"
    chmod 700 "$s"
    raven_init "$NS_HA" "$s" s
    raven_card "$NS_HA" "$s" s
    s_card="$CARD"
    # First: R reads its whole list, so A's and B's reservations below show
    # that S is on it too. R relays only within its circle; a stranger
    # outside it is refused by R and never reaches B's gate.
    in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$s_card" >>"$LOGS/relay.allow.out" 2>&1 \
      || fail "raven relay allow (S) failed"
  fi
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$a_card" >>"$LOGS/relay.allow.out" 2>&1 \
    || fail "raven relay allow (A) failed"
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$b_card" >>"$LOGS/relay.allow.out" 2>&1 \
    || fail "raven relay allow (B) failed"

  echo "--- services: A in hA, B in hB (p2p $listen, relay R)"
  ip netns exec "$NS_HA" "$NODE" service --data-dir "$a" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen "$listen" --p2p-relay "$VIA" --timeout-secs 0 \
    >"$LOGS/a.service.log" 2>&1 &
  a_pid=$!
  PIDS+=("$a_pid")
  ip netns exec "$NS_HB" "$NODE" service --data-dir "$b" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen "$listen" --p2p-relay "$VIA" --timeout-secs 0 \
    >"$LOGS/b.service.log" 2>&1 &
  b_pid=$!
  PIDS+=("$b_pid")
  wait_line "$LOGS/a.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$a_pid" "$relay_pid"
  wait_line "$LOGS/b.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$b_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"
  echo "both services hold a reservation on R"
  if [[ "$listen" == "relay" ]]; then
    for log in "$LOGS/a.service.log" "$LOGS/b.service.log"; do
      grep -Fq -- "$LINE_RETIRED" "$log" \
        || fail "$(basename "$log"): --p2p-listen relay did not log that it is retired"
    done
  fi

  if [[ "$MODE" == "cone" ]]; then
    echo "--- stranger S in hA (p2p 0.0.0.0:7424, no relay of its own)"
    ip netns exec "$NS_HA" "$NODE" service --data-dir "$s" \
      --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
      --p2p-listen 0.0.0.0:7424 --timeout-secs 0 \
      >"$LOGS/s.service.log" 2>&1 &
    s_pid=$!
    PIDS+=("$s_pid")
    wait_line "$LOGS/s.service.log" "$LINE_HOST_UP" "$RESERVE_WAIT" "$s_pid"
    wait_ipc "$NS_HA" "$s" 30 "$s_pid"
  fi

  echo "--- pin each other (verified contacts only use p2p)"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"
  # Each gate re-reads contacts.json within a second; B's must hold A before
  # A's first circuit arrives, or B refuses it like a stranger's.
  wait_line "$LOGS/a.service.log" "$LINE_GATE_ONE" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_GATE_ONE" 30 "$b_pid"

  if [[ "$MODE" == "cone" ]]; then
    in_ns "$NS_HA" "$RAVEN" --data-dir "$s" contact add --card "$b_card" \
      --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/s.contact.out" 2>&1 || fail "S contact add bob failed"
    wait_line "$LOGS/s.service.log" "$LINE_GATE_ONE" 30 "$s_pid"
    run_r14
  fi

  echo "--- A -> B and B -> A over --carrier p2p"
  send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-1" a2b-1
  inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-1" b-1
  relayed_only "the first message A -> B"
  if [[ "$MODE" == "cone" ]]; then
    # A had no connection to B: the relay, or DCUtR already done.
    require_path "$PATH_RELAYED|$PATH_PUNCHED" "the first message A -> B"
  fi
  send_check "$NS_HB" "$b" alice "hello-$MODE-b2a-1" b2a-1
  inbox_once "$NS_HA" "$a" "hello-$MODE-b2a-1" a-1
  relayed_only "the message B -> A"
  echo "delivered both ways"

  if [[ "$MODE" == "swap" ]]; then
    run_swap
    return 0
  fi

  echo "--- second message A -> B"
  send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-2" a2b-2
  inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-2" b-2
  relayed_only "the second message A -> B"
  check_hold "$LOGS/a.service.log" "$LOGS/b.service.log"

  if [[ "$MODE" == "cone" ]]; then
    wait_dcutr "$DCUTR_WAIT" "$a_pid" "$b_pid"
    if ! dcutr_seen; then
      fail "no service logged '$LINE_DCUTR' within ${DCUTR_WAIT}s (cone NAT: hole punching expected)"
    fi
    echo "--- third message A -> B (after the upgrade)"
    send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-3" a2b-3
    inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-3" b-3
    require_path "$PATH_PUNCHED" "the third message A -> B (after the upgrade)"
    read_counters
    if [[ "$CNT_A_LAN" -eq 0 || "$CNT_B_WAN" -eq 0 ]]; then
      fail "a hole-punched message but rA lan_to_other=$CNT_A_LAN, rB wan_from_other=$CNT_B_WAN: the routers saw no direct path"
    fi
    echo "RESULT cone: R14 stranger refused by B's gate with 0 direct packets; delivered both ways; DCUtR upgraded the relayed connection, the next message was $PATH_PUNCHED and the routers counted the direct path"
  elif [[ "$MODE" == "shifted" || "$MODE" == "v6fw" ]]; then
    if [[ "$MODE" == "shifted" ]]; then
      only="the raw address R observed (port $SHIFT_PORT)"
    else
      only="the hosts' own IPv6"
    fi
    wait_dcutr "$DCUTR_WAIT" "$a_pid" "$b_pid"
    if ! dcutr_seen; then
      fail "no service logged '$LINE_DCUTR' within ${DCUTR_WAIT}s (only $only can upgrade)"
    fi
    echo "--- third message A -> B (after the upgrade)"
    send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-3" a2b-3
    inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-3" b-3
    if [[ "$LAST_PATH" != "$PATH_PUNCHED" ]]; then
      fail "the third message travelled '${LAST_PATH:-unlabelled}', not $PATH_PUNCHED"
    fi
    echo "RESULT $MODE: delivered both ways; DCUtR upgraded through $only, and the next message was $PATH_PUNCHED"
  else
    # symmetric, cone-private: nothing may upgrade.
    if [[ "$MODE" == "symmetric" ]]; then
      only="the NAT is not symmetric: this simulation is invalid"
    else
      only="a private candidate was offered and dialled"
    fi
    wait_dcutr "$DCUTR_OBSERVE" "$a_pid" "$b_pid"
    if dcutr_seen; then
      fail "a service logged '$LINE_DCUTR' ($only)"
    fi
    echo "--- third message A -> B"
    send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-3" a2b-3
    inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-3" b-3
    relayed_only "the third message A -> B"
    if dcutr_seen; then
      fail "a service logged '$LINE_DCUTR' ($only)"
    fi
    read_counters
    punch_failed=$(($(count_lines "$LOGS/a.service.log" "$LINE_PUNCH_FAILED") + $(count_lines "$LOGS/b.service.log" "$LINE_PUNCH_FAILED")))
    if [[ "$MODE" == "cone-private" ]]; then
      if [[ "$CNT_A_LAN" -ne 0 || "$CNT_B_LAN" -ne 0 ]]; then
        fail "on a private WAN rA lan_to_other=$CNT_A_LAN, rB lan_to_other=$CNT_B_LAN: a host sent to an address other than R's"
      fi
      echo "RESULT cone-private: every message $PATH_RELAYED, no upgrade, 0 packets out of either LAN to anything but R ($punch_failed hole-punch failure lines)"
    else
      echo "RESULT symmetric: every message $PATH_RELAYED, no upgrade ($punch_failed hole-punch failure lines; the counters above are the punch attempts the routers saw)"
    fi
  fi
  if [[ -s "$R/relay_status.json" ]]; then
    echo "relay_status.json: $(tr -d '\n' <"$R/relay_status.json")"
  fi
}

# run_r14: the cone run's stranger probe, before A and B ever talk (uses
# run_case's locals). S is in R's circle, so R hands its circuit to B; B's
# peer gate must refuse it before any protocol runs (no Identify, no DCUtR,
# so no candidate), and nothing may leave either LAN for anyone but R. R
# then answers CONNECTION_FAILED, which S cannot tell from B being gone: S
# reads that B is offline, with no refusal hint (carrier C6, fault s35).
run_r14() {
  local rc=0 out err s_peer text="r14-stranger-$MODE"
  out="$LOGS/s-probe.send.out"
  err="$LOGS/s-probe.send.err"
  s_peer="${s_card##* p2p=}"
  s_peer="${s_peer%% *}"
  if [[ ! "$s_peer" =~ ^[1-9A-HJ-NP-Za-km-z]+$ ]]; then
    fail "the S card's p2p= is not a base58 PeerId"
  fi
  echo "--- R14: the stranger S (in R's circle, unknown to B) sends to B over --carrier p2p"
  reset_counters
  printf '%s\n' "$text" | timeout "$SEND_TIMEOUT" ip netns exec "$NS_HA" env RAVEN_VERBOSE=1 \
    "$RAVEN" --data-dir "$s" send --contact @bob --carrier p2p >"$out" 2>"$err" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    fail "the stranger's send to B succeeded"
  fi
  if grep -Fq -- LINK_NOT_ACCEPTED "$out" "$err"; then
    fail "the stranger reached B's Raven link (LINK_NOT_ACCEPTED): B's peer gate did not refuse it first"
  fi
  if ! grep -Fq -- "why=contact_offline" "$out" "$err"; then
    fail "the stranger's send (exit $rc) does not read B as offline (why=contact_offline)"
  fi
  if grep -Fq -e "$HINT_NODE_REFUSED" -e "$HINT_RELAY_REFUSED" "$out" "$err"; then
    fail "the stranger's send (exit $rc) names a refusal: a circuit B's gate refused reads as offline"
  fi
  wait_line "$LOGS/b.service.log" "$LINE_GATE_REFUSED" 15 "$b_pid" "$relay_pid"
  if grep -Fq -- "$LINE_INBOUND" "$LOGS/b.service.log"; then
    fail "b.service.log has a '$LINE_INBOUND' line: the stranger reached the Raven link"
  fi
  if grep -Fq -- "$s_peer" "$LOGS/b.service.log"; then
    fail "b.service.log names the stranger's PeerId (refusals are counts only)"
  fi
  sleep "$R14_OBSERVE"
  if grep -Fq -e "$LINE_DCUTR" -e "$LINE_PUNCH_FAILED" "$LOGS/s.service.log"; then
    fail "the stranger logged a hole punch: DCUtR ran on its refused circuit"
  fi
  read_counters
  if [[ "$CNT_A_LAN" -ne 0 || "$CNT_B_LAN" -ne 0 || "$CNT_B_WAN" -ne 0 ]]; then
    fail "R14: a packet went past R (rA lan_to_other=$CNT_A_LAN, rB lan_to_other=$CNT_B_LAN, rB wan_from_other=$CNT_B_WAN)"
  fi
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" inbox >"$LOGS/b-r14.inbox.out" 2>&1 || fail "raven inbox (R14) failed"
  if grep -Fq -- "$text" "$LOGS/b-r14.inbox.out"; then
    fail "B's inbox holds the stranger's message"
  fi
  kill -TERM "$s_pid" 2>/dev/null || true
  wait "$s_pid" 2>/dev/null || true
  echo "R14: the stranger was refused by B's peer gate (exit $rc), no Raven link, no hole punch, 0 packets past R"
}

# wait_dcutr SECS PID...: until a service logs the upgrade (no failure on timeout).
wait_dcutr() {
  local secs=$1 deadline
  shift
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if dcutr_seen; then
      return 0
    fi
    require_alive "$@"
    sleep 0.5
  done
  return 0
}

# run_swap: the swap run after the first exchange (uses run_case's locals).
run_swap() {
  local queued deadline line dcutr_before
  echo "--- swap: B goes down, A queues 2 messages, the backoff grows (${SWAP_BACKOFF}s)"
  kill -TERM "$b_pid" 2>/dev/null || true
  wait "$b_pid" 2>/dev/null || true
  for queued in 1 2; do
    send_queued "$NS_HA" "$a" bob "queued-$MODE-$queued" "queued-$queued"
  done
  sleep "$SWAP_BACKOFF"
  require_alive "$a_pid" "$relay_pid"
  if [[ "$(count_lines "$LOGS/a.service.log" 'raven-node netwatch: network changed')" -ne 0 ]]; then
    fail "A's netwatch acted on a change before the swap"
  fi
  dcutr_before="$(dcutr_count)"

  echo "--- swap A's uplink: eth0 (rA) out, eth1 (rA2) in, new default route"
  swap_uplink
  deadline=$((SECONDS + SWAP_NOTICE))
  wait_line "$LOGS/a.service.log" "$LINE_NETCHANGE" "$(left "$deadline")" "$a_pid" "$relay_pid"
  line="$(grep -F -- "$LINE_NETCHANGE" "$LOGS/a.service.log" | head -n 1)"
  if [[ "$line" != *"$LINE_REHOMING" ]]; then
    fail "the change was acted on without re-homing p2p: '$line'"
  fi
  wait_line "$LOGS/a.service.log" "$LINE_REHOMED" "$(left "$deadline")" "$a_pid" "$relay_pid"
  wait_count "$LOGS/a.service.log" "$LINE_RESERVED" 2 "$(left "$deadline")" "$a_pid" "$relay_pid"
  echo "A re-homed on R through rA2 within $((SECONDS + SWAP_NOTICE - deadline))s of the swap"

  echo "--- B comes back: both queued messages within ${SWAP_DELIVER}s, exactly once"
  ip netns exec "$NS_HB" "$NODE" service --data-dir "$b" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$VIA" --timeout-secs 0 \
    >>"$LOGS/b.service.log" 2>&1 &
  b_pid=$!
  PIDS+=("$b_pid")
  deadline=$((SECONDS + SWAP_DELIVER))
  wait_count "$LOGS/b.service.log" "$LINE_RESERVED" 2 "$RESERVE_WAIT" "$b_pid" "$relay_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"
  for queued in 1 2; do
    inbox_once "$NS_HB" "$b" "queued-$MODE-$queued" "b-queued-$queued" "$(left "$deadline")"
  done
  echo "both queued messages delivered exactly once within $((SECONDS + SWAP_DELIVER - deadline))s of B's return"

  echo "--- third message A -> B on the new network"
  send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-3" a2b-3
  inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-3" b-3
  wait_dcutr_since "$dcutr_before" "$DCUTR_OBSERVE" "$a_pid" "$b_pid"
  if [[ "$(dcutr_count)" -gt "$dcutr_before" ]]; then
    echo "RESULT swap: uplink swap noticed, re-homed on the same relay, queued messages delivered exactly once; DCUtR upgraded again after the swap (advisory)"
  else
    echo "RESULT swap: uplink swap noticed, re-homed on the same relay, queued messages delivered exactly once; no DCUtR upgrade after the swap (advisory)"
  fi
}

# wait_dcutr_since N SECS PID...: until more than N upgrade lines (no failure
# on timeout).
wait_dcutr_since() {
  local before=$1 secs=$2 deadline
  shift 2
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    if [[ "$(dcutr_count)" -gt "$before" ]]; then
      return 0
    fi
    require_alive "$@"
    sleep 0.5
  done
  return 0
}

# ---- the reach run (Phase 1 item 5, advisory) --------------------------------

# Its own topology (see the header): three relays on pub's lo, P and Q
# routed by pub with no NAT, N behind rN's masquerade.
setup_reach_net() {
  local ns dev
  for ns in "$NS_PUB" "$NS_HP" "$NS_HQ" "$NS_RN" "$NS_HN"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip -n "$NS_PUB" link add wp type veth peer name eth0 netns "$NS_HP"
  ip -n "$NS_PUB" link add wq type veth peer name eth0 netns "$NS_HQ"
  ip -n "$NS_PUB" link add wn type veth peer name wan netns "$NS_RN"
  ip -n "$NS_RN" link add lan type veth peer name eth0 netns "$NS_HN"
  # R1 and R3 share a /24 (one network, one opinion); R2 has its own.
  ip -n "$NS_PUB" addr add "$WAN.11.1/32" dev lo
  ip -n "$NS_PUB" addr add "$WAN.11.2/32" dev lo
  ip -n "$NS_PUB" addr add "$WAN.12.1/32" dev lo
  ip -n "$NS_PUB" addr add "$WAN.13.1/24" dev wp
  ip -n "$NS_PUB" addr add "$WAN.15.1/24" dev wq
  ip -n "$NS_PUB" addr add "$WAN.14.1/24" dev wn
  for dev in wp wq wn; do
    ip -n "$NS_PUB" link set "$dev" up
  done
  ip netns exec "$NS_PUB" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$NS_HP" addr add "$WAN.13.10/24" dev eth0
  ip -n "$NS_HP" link set eth0 up
  ip -n "$NS_HP" route add default via "$WAN.13.1"
  ip -n "$NS_HQ" addr add "$WAN.15.10/24" dev eth0
  ip -n "$NS_HQ" link set eth0 up
  ip -n "$NS_HQ" route add default via "$WAN.15.1"
  ip -n "$NS_RN" addr add "$WAN.14.2/24" dev wan
  ip -n "$NS_RN" addr add 192.168.4.1/24 dev lan
  ip -n "$NS_RN" link set wan up
  ip -n "$NS_RN" link set lan up
  ip -n "$NS_RN" route add default via "$WAN.14.1"
  ip -n "$NS_HN" addr add 192.168.4.2/24 dev eth0
  ip -n "$NS_HN" link set eth0 up
  ip -n "$NS_HN" route add default via 192.168.4.1
  nat_rules "$NS_RN" "masquerade" "$WAN.11.1"
  if [[ -n "$(ip -n "$NS_PUB" route show default 2>/dev/null)" ]]; then
    fail "pub has a default route: the simulated Internet ($WAN.0.0/16) must not reach the real one"
  fi
  {
    echo "== reach: rN does 'masquerade'; P and Q have no NAT"
    ip netns exec "$NS_RN" nft list ruleset
  } >"$LOGS/topology.log" 2>&1
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HP" ping -c 1 -W 2 "$WAN.12.1" >>"$LOGS/topology.log" 2>&1 || fail "hP cannot reach R2 ($WAN.12.1)"
    in_ns "$NS_HQ" ping -c 1 -W 2 "$WAN.11.2" >>"$LOGS/topology.log" 2>&1 || fail "hQ cannot reach R3 ($WAN.11.2)"
    in_ns "$NS_HN" ping -c 1 -W 2 "$WAN.11.1" >>"$LOGS/topology.log" 2>&1 || fail "hN cannot reach R1 ($WAN.11.1) through rN"
    in_ns "$NS_PUB" ping -c 1 -W 2 "$WAN.13.10" >>"$LOGS/topology.log" 2>&1 || fail "pub cannot reach P ($WAN.13.10): P must have no NAT"
  fi
}

# start_reach_relay NAME IP: `raven-node relay --autonat-server` in pub on
# IP:7423, its folder $run_dir/NAME; sets RELAY_VIA and RELAY_PID.
RELAY_VIA=""
RELAY_PID=""
start_reach_relay() {
  local name=$1 ip=$2 dir pid peer="" deadline
  dir="$run_dir/$name"
  mkdir -p "$dir"
  chmod 700 "$dir"
  ip netns exec "$NS_PUB" "$NODE" relay --data-dir "$dir" --listen "$ip:7423" --autonat-server \
    >"$LOGS/$name.log" 2>&1 &
  pid=$!
  PIDS+=("$pid")
  deadline=$((SECONDS + RELAY_WAIT))
  while ((SECONDS < deadline)); do
    if [[ -s "$dir/relay_status.json" ]]; then
      peer="$(relay_peer_id "$dir/relay_status.json")"
      [[ -z "$peer" ]] || break
    fi
    check_hold "$LOGS/$name.log"
    require_alive "$pid"
    sleep 0.2
  done
  if [[ ! "$peer" =~ ^[1-9A-HJ-NP-Za-km-z]+$ ]]; then
    fail "$name wrote no relay_status.json with a base58 peer_id within ${RELAY_WAIT}s"
  fi
  RELAY_VIA="/ip4/$ip/tcp/7423/p2p/$peer"
  RELAY_PID="$pid"
}

# reach_facts NS DIR: one line from the running service's IPC Status, states
# and counts only: "nat=<verdict> reach=<class> reached=<n> failed=<n>
# not_counted=<n> checks=<relay 1>,<relay 2>" (a relay's own check of us, `-`
# while it has none); empty while the service does not answer.
reach_facts() {
  local ns=$1 dir=$2 ep
  ep="$(in_ns "$ns" "$RAVEN" --data-dir "$dir" ipc-ping 2>/dev/null | sed -n 's/.* endpoint=//p' | head -n 1 || true)"
  if [[ -z "$ep" ]]; then
    return 0
  fi
  python3 - "$ep" 2>/dev/null <<'PY' || true
import json, socket, struct, sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(sys.argv[1])
body = json.dumps({"op": "status", "v": 1}).encode()
s.sendall(struct.pack(">I", len(body)) + body)


def read(n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


(size,) = struct.unpack(">I", read(4))
p2p = json.loads(read(size)).get("p2p") or {}
c = p2p.get("nat_checks") or {}
checks = ",".join(r.get("check") or "-" for r in p2p.get("relay_health") or [])
print(
    "nat=%s reach=%s reached=%d failed=%d not_counted=%d checks=%s"
    % (
        p2p.get("nat", ""),
        p2p.get("reach", ""),
        c.get("reached", 0),
        c.get("failed", 0),
        c.get("not_counted", 0),
        checks,
    )
)
PY
}

# wait_facts NS DIR NAME GLOB SECS PID...: until reach_facts matches GLOB.
FACTS=""
wait_facts() {
  local ns=$1 dir=$2 name=$3 want=$4 secs=$5 deadline
  shift 5
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    FACTS="$(reach_facts "$ns" "$dir")"
    # shellcheck disable=SC2053 # $want is a glob on purpose
    if [[ "$FACTS" == $want ]]; then
      echo "$name: $FACTS" >>"$LOGS/reach.facts.log"
      return 0
    fi
    check_hold "$LOGS/$name.service.log"
    require_alive "$@"
    sleep 2
  done
  fail "$name's status is '${FACTS:-no answer}', not '$want', after ${secs}s"
}

# reach_row NS DIR NAME CLASS: the p2p row of `raven status` names CLASS.
reach_row() {
  local ns=$1 dir=$2 name=$3 class=$4 row
  row="$(in_ns "$ns" "$RAVEN" --data-dir "$dir" status 2>&1 | grep -m 1 -E '^[[:space:]]*p2p[[:space:]]' || true)"
  echo "$name: $row" >>"$LOGS/reach.facts.log"
  if [[ "$row" != *"reachability: $class;"* ]]; then
    fail "$name's p2p status row does not say 'reachability: $class': '${row:-no p2p row}'"
  fi
}

# start_reach_node NS DIR NAME VIA...: `raven-node service` listening on
# 0.0.0.0:7423 with a reservation on each VIA; sets NODE_PID.
NODE_PID=""
start_reach_node() {
  local ns=$1 dir=$2 name=$3 via args=()
  shift 3
  for via in "$@"; do
    args+=(--p2p-relay "$via")
  done
  ip netns exec "$ns" "$NODE" service --data-dir "$dir" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 "${args[@]}" --timeout-secs 0 \
    >"$LOGS/$name.service.log" 2>&1 &
  NODE_PID=$!
  PIDS+=("$NODE_PID")
}

run_reach() {
  local run_dir p q n v1 v2 v3 r1_pid r2_pid r3_pid p_pid q_pid n_pid p_card q_card n_card card log line
  MODE=reach
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if ! command -v python3 >/dev/null 2>&1; then
    fail "the reach run reads IPC Status with python3, which is missing"
  fi

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r1"
  p="$run_dir/p"
  q="$run_dir/q"
  n="$run_dir/n"
  mkdir -p "$LOGS" "$p" "$q" "$n"
  chmod 700 "$p" "$q" "$n"
  echo "=== reach run: AutoNAT needs two relays on different networks (dirs under $run_dir) ==="
  setup_reach_net

  echo "--- relays R1 $WAN.11.1, R3 $WAN.11.2 (one /24), R2 $WAN.12.1, each with --autonat-server"
  start_reach_relay r1 "$WAN.11.1"
  v1="$RELAY_VIA"
  r1_pid="$RELAY_PID"
  start_reach_relay r2 "$WAN.12.1"
  v2="$RELAY_VIA"
  r2_pid="$RELAY_PID"
  start_reach_relay r3 "$WAN.11.2"
  v3="$RELAY_VIA"
  r3_pid="$RELAY_PID"

  echo "--- init P (hP), Q (hQ), N (hN); allow P, Q, N on R1, P on R2, Q on R3"
  VIA="$v1"
  raven_init "$NS_HP" "$p" p
  raven_card "$NS_HP" "$p" p
  p_card="$CARD"
  raven_init "$NS_HQ" "$q" q
  raven_card "$NS_HQ" "$q" q
  q_card="$CARD"
  raven_init "$NS_HN" "$n" n
  raven_card "$NS_HN" "$n" n
  n_card="$CARD"
  for card in "$p_card" "$q_card" "$n_card"; do
    in_ns "$NS_PUB" "$RAVEN" --data-dir "$run_dir/r1" relay allow --card "$card" \
      >>"$LOGS/relay.allow.out" 2>&1 || fail "raven relay allow on R1 failed"
  done
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$run_dir/r2" relay allow --card "$p_card" \
    >>"$LOGS/relay.allow.out" 2>&1 || fail "raven relay allow (P) on R2 failed"
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$run_dir/r3" relay allow --card "$q_card" \
    >>"$LOGS/relay.allow.out" 2>&1 || fail "raven relay allow (Q) on R3 failed"

  echo "--- services: P (R1 + R2), Q (R1 + R3), N (R1), each listening on 7423"
  start_reach_node "$NS_HP" "$p" p "$v1" "$v2"
  p_pid="$NODE_PID"
  start_reach_node "$NS_HQ" "$q" q "$v1" "$v3"
  q_pid="$NODE_PID"
  start_reach_node "$NS_HN" "$n" n "$v1"
  n_pid="$NODE_PID"
  wait_count "$LOGS/p.service.log" "$LINE_RESERVED" 2 "$RESERVE_WAIT" "$p_pid" "$r1_pid" "$r2_pid"
  wait_count "$LOGS/q.service.log" "$LINE_RESERVED" 2 "$RESERVE_WAIT" "$q_pid" "$r1_pid" "$r3_pid"
  wait_line "$LOGS/n.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$n_pid" "$r1_pid"
  wait_ipc "$NS_HP" "$p" 30 "$p_pid"
  wait_ipc "$NS_HQ" "$q" 30 "$q_pid"
  wait_ipc "$NS_HN" "$n" 30 "$n_pid"
  echo "every reservation is held"

  echo "--- (a) P: R1 and R2 (two /24s) both reached it: public"
  wait_facts "$NS_HP" "$p" p "nat=public reach=public reached=2 failed=0 * checks=reached,reached" \
    "$REACH_WAIT" "$p_pid" "$r1_pid" "$r2_pid"
  wait_line "$LOGS/p.service.log" "${LINE_REACH}public (2 of 2 independent checks)" 10 "$p_pid"
  reach_row "$NS_HP" "$p" p public

  echo "--- (b) Q: R1 and R3 (one /24) both reached it: one opinion, unconfirmed"
  wait_facts "$NS_HQ" "$q" q "nat=unconfirmed reach=relayed reached=1 failed=0 * checks=reached,reached" \
    "$REACH_WAIT" "$q_pid" "$r1_pid" "$r3_pid"
  wait_line "$LOGS/q.service.log" "${LINE_REACH}relayed (1 of 2 independent checks)" 10 "$q_pid"
  reach_row "$NS_HQ" "$q" q relayed

  echo "--- (c) N behind NAT: R1's dial-back cannot reach it: private, relayed"
  wait_facts "$NS_HN" "$n" n "nat=private reach=relayed reached=0 failed=1 * checks=failed" \
    "$REACH_WAIT" "$n_pid" "$r1_pid"
  reach_row "$NS_HN" "$n" n relayed

  echo "--- (d) R1 stops: N has no relay left: unreachable"
  kill -TERM "$r1_pid" 2>/dev/null || true
  wait "$r1_pid" 2>/dev/null || true
  wait_facts "$NS_HN" "$n" n "nat=private reach=unreachable *" "$REACH_WAIT" "$n_pid"
  wait_line "$LOGS/n.service.log" "${LINE_REACH}unreachable (0 of 2 independent checks)" 10 "$n_pid"
  reach_row "$NS_HN" "$n" n unreachable

  # Q was never public; the reachability lines name no address or PeerId.
  if grep -Fq -- "${LINE_REACH}public" "$LOGS/q.service.log"; then
    fail "Q logged '${LINE_REACH}public' with two relays in one /24"
  fi
  for log in "$LOGS/p.service.log" "$LOGS/q.service.log" "$LOGS/n.service.log"; do
    while IFS= read -r line; do
      if [[ "$line" == *"$WAN."* || "$line" == *"12D3Koo"* || "$line" == *"/p2p/"* ]]; then
        fail "$(basename "$log") names an address or a PeerId: '$line'"
      fi
    done < <(grep -F -- "$LINE_REACH" "$log" || true)
  done
  echo "RESULT reach: P public (two relays on two networks), Q unconfirmed and never public (two relays in one /24), N private behind NAT: relayed, then unreachable once its relay stopped"
}

# ---- the hints run (Phase 2 item 1, RRH1 route hints; advisory) -------------

# Its own topology (see the header): R1 and R2 on pub's lo, B public on
# WAN.13.10 (its second uplink behind rB2 stays down until the swap), A
# behind rA's masquerade, whose counter to_old_b counts every forwarded
# packet to B's first address.
setup_hints_net() {
  local ns dev old_b=$1
  for ns in "$NS_PUB" "$NS_RA" "$NS_HA" "$NS_HB" "$NS_RB2"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip -n "$NS_PUB" link add wa type veth peer name wan netns "$NS_RA"
  ip -n "$NS_RA" link add lan type veth peer name eth0 netns "$NS_HA"
  ip -n "$NS_PUB" link add wb type veth peer name eth0 netns "$NS_HB"
  ip -n "$NS_PUB" link add wc type veth peer name wan netns "$NS_RB2"
  ip -n "$NS_RB2" link add lan type veth peer name eth1 netns "$NS_HB"
  ip -n "$NS_PUB" addr add "$WAN.11.1/32" dev lo
  ip -n "$NS_PUB" addr add "$WAN.12.1/32" dev lo
  ip -n "$NS_PUB" addr add "$WAN.14.1/24" dev wa
  ip -n "$NS_PUB" addr add "$WAN.13.1/24" dev wb
  ip -n "$NS_PUB" addr add "$WAN.16.1/24" dev wc
  for dev in wa wb wc; do
    ip -n "$NS_PUB" link set "$dev" up
  done
  ip netns exec "$NS_PUB" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$NS_RA" addr add "$WAN.14.2/24" dev wan
  ip -n "$NS_RA" addr add 192.168.4.1/24 dev lan
  ip -n "$NS_RA" link set wan up
  ip -n "$NS_RA" link set lan up
  ip -n "$NS_RA" route add default via "$WAN.14.1"
  ip -n "$NS_HA" addr add 192.168.4.2/24 dev eth0
  ip -n "$NS_HA" link set eth0 up
  ip -n "$NS_HA" route add default via 192.168.4.1
  ip -n "$NS_HB" addr add "$old_b/24" dev eth0
  ip -n "$NS_HB" link set eth0 up
  ip -n "$NS_HB" route add default via "$WAN.13.1"
  ip -n "$NS_RB2" addr add "$WAN.16.2/24" dev wan
  ip -n "$NS_RB2" addr add 192.168.5.1/24 dev lan
  ip -n "$NS_RB2" link set wan up
  ip -n "$NS_RB2" link set lan up
  ip -n "$NS_RB2" route add default via "$WAN.16.1"
  nat_rules "$NS_RA" "masquerade" "$WAN.11.1"
  nat_rules "$NS_RB2" "masquerade" "$WAN.11.1"
  # Every forwarded packet from A's network to B's first address, counted
  # before the NAT (a separate table: its accept ends nothing for raven_nat).
  ip netns exec "$NS_RA" nft -f - <<EOF || fail "nft rejected rA's to_old_b counter"
table ip raven_hints {
  counter to_old_b {
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "lan" oifname "wan" ip daddr $old_b counter name "to_old_b"
  }
}
EOF
  if [[ -n "$(ip -n "$NS_PUB" route show default 2>/dev/null)" ]]; then
    fail "pub has a default route: the simulated Internet ($WAN.0.0/16) must not reach the real one"
  fi
  {
    echo "== hints: rA does 'masquerade' (+ counter to_old_b), B public on $old_b, rB2 masquerade after the swap"
    ip netns exec "$NS_RA" nft list ruleset
  } >"$LOGS/topology.log" 2>&1
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HA" ping -c 1 -W 2 "$old_b" >>"$LOGS/topology.log" 2>&1 || fail "hA cannot reach B ($old_b) through rA"
    in_ns "$NS_PUB" ping -c 1 -W 2 "$old_b" >>"$LOGS/topology.log" 2>&1 || fail "pub cannot reach B ($old_b): B must have no NAT"
  fi
  ip netns exec "$NS_RA" nft reset counter ip raven_hints to_old_b >/dev/null \
    || fail "cannot reset rA's counter to_old_b"
}

# old_b_packets: rA's to_old_b counter (fails on a broken read).
old_b_packets() {
  local n
  n="$(ip netns exec "$NS_RA" nft list counter ip raven_hints to_old_b 2>/dev/null \
    | awk '{ for (i = 1; i < NF; i++) if ($i == "packets") { print $(i + 1); exit } }')" || true
  [[ "$n" =~ ^[0-9]+$ ]] || fail "cannot read rA's nft counter to_old_b"
  echo "$n"
}

# Swap hB's uplink: eth0 (public) out, eth1 behind rB2 in.
swap_uplink_b() {
  ip -n "$NS_HB" addr flush dev eth0
  ip -n "$NS_HB" link set eth0 down
  ip -n "$NS_HB" addr add 192.168.5.2/24 dev eth1
  ip -n "$NS_HB" link set eth1 up
  ip -n "$NS_HB" route add default via 192.168.5.1
}

# learned_direct_to DIR PUB IP: "yes" when DIR's learned_routes.json holds a
# DIRECT address of the contact PUB on IP, else "no".
learned_direct_to() {
  python3 - "$1/learned_routes.json" "$2" "$3" <<'PY' 2>/dev/null || echo no
import json, sys

path, pub, ip = sys.argv[1:4]
try:
    entries = json.load(open(path))
except (OSError, ValueError):
    entries = []
hit = any(
    e.get("pub_hex", "").lower() == pub.lower()
    and any(("/ip4/%s/" % ip) in d for d in e.get("direct", []))
    for e in entries
    if isinstance(e, dict)
)
print("yes" if hit else "no")
PY
}

# relay_circuits DIR: the relay's open circuits (its relay_status.json).
relay_circuits() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["counts"]["circuits"])' \
    "$1/relay_status.json" 2>/dev/null || echo "?"
}

# send_any NS DIR TO TEXT TAG: a verbose `raven send --carrier p2p` that may
# be delivered (LAST_PATH its path= label) or queued (LAST_PATH "queued",
# LAST_MID its message id); anything else fails.
LAST_MID=""
send_any() {
  local ns=$1 dir=$2 to=$3 text=$4 tag=$5 rc=0
  printf '%s\n' "$text" | timeout "$SEND_TIMEOUT" ip netns exec "$ns" env RAVEN_VERBOSE=1 \
    "$RAVEN" --data-dir "$dir" send --contact "@$to" --carrier p2p \
    >"$LOGS/$tag.send.out" 2>"$LOGS/$tag.send.err" || rc=$?
  LAST_MID="$(grep -ohE 'mid=[0-9a-f]{8}' "$LOGS/$tag.send.out" "$LOGS/$tag.send.err" | head -n 1 | cut -d= -f2 || true)"
  if [[ "$rc" -eq 0 ]]; then
    LAST_PATH="$(grep -oE ' path=[a-z_]+' "$LOGS/$tag.send.out" | tail -n 1 | cut -d= -f2 || true)"
    [[ -n "$LAST_PATH" ]] || fail "send $tag printed no path= label"
  elif grep -Fq 'not delivered yet' "$LOGS/$tag.send.out" "$LOGS/$tag.send.err"; then
    LAST_PATH="queued"
  else
    fail "send $tag exited $rc and was not queued"
  fi
  echo "$tag: ${LAST_PATH}"
}

run_hints() {
  local run_dir a b v1 v2 r1_pid r2_pid a_pid b_pid a_card b_card a_fp b_fp b_pub
  local old_b="$WAN.13.10" deadline swapped before after flat line
  MODE=hints
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if ! command -v python3 >/dev/null 2>&1; then
    fail "the hints run reads IPC Status and learned_routes.json with python3, which is missing"
  fi
  # This run's subshell only: route hints on for every process, fast pings
  # (a dead direct connection is noticed within seconds of the swap).
  export RAVEN_LAB_ROUTE_HINTS=1
  export RAVEN_LAB_P2P_PING=2,1

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r1"
  a="$run_dir/a"
  b="$run_dir/b"
  mkdir -p "$LOGS" "$a" "$b"
  chmod 700 "$a" "$b"
  echo "=== hints run: B public then behind NAT, A learns it through RRH1 (dirs under $run_dir) ==="
  setup_hints_net "$old_b"

  echo "--- relays R1 $WAN.11.1 and R2 $WAN.12.1 (two /24s), each with --autonat-server"
  start_reach_relay r1 "$WAN.11.1"
  v1="$RELAY_VIA"
  r1_pid="$RELAY_PID"
  start_reach_relay r2 "$WAN.12.1"
  v2="$RELAY_VIA"
  r2_pid="$RELAY_PID"

  echo "--- init A (hA) and B (hB), raven-card/3 cards naming R1, both allowed on R1 and R2"
  VIA="$v1"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  b_pub="$(sed -n 's/^pub_hex=//p' "$LOGS/b.init.out" | head -n 1)"
  raven_card "$NS_HA" "$a" a
  a_card="$CARD"
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  for card in "$a_card" "$b_card"; do
    in_ns "$NS_PUB" "$RAVEN" --data-dir "$run_dir/r1" relay allow --card "$card" \
      >>"$LOGS/relay.allow.out" 2>&1 || fail "raven relay allow on R1 failed"
    in_ns "$NS_PUB" "$RAVEN" --data-dir "$run_dir/r2" relay allow --card "$card" \
      >>"$LOGS/relay.allow.out" 2>&1 || fail "raven relay allow on R2 failed"
  done

  echo "--- services: B (R1 + R2, public), A (R1, behind rA), each listening on 7423"
  start_reach_node "$NS_HB" "$b" b "$v1" "$v2"
  b_pid="$NODE_PID"
  start_reach_node "$NS_HA" "$a" a "$v1"
  a_pid="$NODE_PID"
  wait_count "$LOGS/b.service.log" "$LINE_RESERVED" 2 "$RESERVE_WAIT" "$b_pid" "$r1_pid" "$r2_pid"
  wait_line "$LOGS/a.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$a_pid" "$r1_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"
  wait_line "$LOGS/a.service.log" "$LINE_GATE_ONE" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_GATE_ONE" 30 "$b_pid"

  echo "--- B public: R1 and R2 both reached it"
  wait_facts "$NS_HB" "$b" b "nat=public reach=public *" "$REACH_WAIT" "$b_pid" "$r1_pid" "$r2_pid"

  echo "--- #0 A -> B: A learns B's DIRECT ($old_b) from B's route hints"
  send_check "$NS_HA" "$a" bob "hints-0" hints-0
  inbox_once "$NS_HB" "$b" "hints-0" b-0
  deadline=$((SECONDS + HINTS_LEARN))
  while [[ "$(learned_direct_to "$a" "$b_pub" "$old_b")" != "yes" ]]; do
    ((SECONDS < deadline)) || fail "A holds no DIRECT address of B on $old_b within ${HINTS_LEARN}s"
    require_alive "$a_pid" "$b_pid"
    sleep 1
  done

  echo "--- A restarts (no connection left to ride), then #1 A -> B is direct"
  kill -TERM "$a_pid" 2>/dev/null || true
  wait "$a_pid" 2>/dev/null || true
  ip netns exec "$NS_HA" "$NODE" service --data-dir "$a" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$v1" --timeout-secs 0 \
    >>"$LOGS/a.service.log" 2>&1 &
  a_pid=$!
  PIDS+=("$a_pid")
  wait_count "$LOGS/a.service.log" "$LINE_RESERVED" 2 "$RESERVE_WAIT" "$a_pid" "$r1_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  before="$(old_b_packets)"
  send_check "$NS_HA" "$a" bob "hints-1" hints-1
  inbox_once "$NS_HB" "$b" "hints-1" b-1
  require_path "direct" "#1 A -> B (B's DIRECT address from its route hints)"
  after="$(old_b_packets)"
  if [[ "$after" -le "$before" ]]; then
    fail "#1 was direct, yet rA counted no packet to $old_b ($before -> $after)"
  fi
  deadline=$((SECONDS + 10))
  while [[ "$(relay_circuits "$run_dir/r1")" != "0" ]]; do
    ((SECONDS < deadline)) || fail "R1 still carries a circuit after the direct #1 ($(relay_circuits "$run_dir/r1"))"
    sleep 0.5
  done
  echo "#1 direct: rA counted $((after - before)) packets to $old_b, R1 carries no circuit"

  echo "--- B's uplink swaps behind rB2: B re-homes on its relays"
  swap_uplink_b
  swapped=$SECONDS
  deadline=$((SECONDS + SWAP_NOTICE))
  wait_line "$LOGS/b.service.log" "$LINE_NETCHANGE" "$(left "$deadline")" "$b_pid" "$r1_pid"
  line="$(grep -F -- "$LINE_NETCHANGE" "$LOGS/b.service.log" | head -n 1)"
  if [[ "$line" != *"$LINE_REHOMING" ]]; then
    fail "B's change was acted on without re-homing p2p: '$line'"
  fi
  wait_line "$LOGS/b.service.log" "$LINE_REHOMED" "$(left "$deadline")" "$b_pid" "$r1_pid"

  echo "--- #2 A -> B within ${HINTS_DELIVER}s of the swap, through a circuit"
  wait_count "$LOGS/b.service.log" "$LINE_RESERVED" 3 "$(left $((swapped + HINTS_DELIVER)))" "$b_pid" "$r1_pid"
  # A's lab pings (every 2 s, 1 s timeout) close its dead direct connection
  # to B's old address within a round or two: #2 must not ride it.
  while ((SECONDS < swapped + 4)); do
    sleep 0.5
  done
  send_any "$NS_HA" "$a" bob "hints-2" hints-2
  inbox_once "$NS_HB" "$b" "hints-2" b-2 "$(left $((swapped + HINTS_DELIVER)))"
  if [[ "$LAST_PATH" == "queued" ]]; then
    [[ -n "$LAST_MID" ]] || fail "#2 was queued without a message id"
    in_ns "$NS_HA" "$RAVEN" --data-dir "$a" outbox status "$LAST_MID" >"$LOGS/hints-2.status.out" 2>&1 \
      || fail "raven outbox status ($LAST_MID) failed"
    LAST_PATH="$(sed -n 's/^  path *//p' "$LOGS/hints-2.status.out" | head -n 1)"
  fi
  require_path "$PATH_RELAYED" "#2 A -> B after B's swap"
  echo "#2 delivered through a circuit $((SECONDS - swapped))s after the swap"

  echo "--- A holds B's new-generation hints: no DIRECT on $old_b"
  deadline=$((SECONDS + HINTS_LEARN))
  while [[ "$(learned_direct_to "$a" "$b_pub" "$old_b")" != "no" ]]; do
    ((SECONDS < deadline)) || fail "A still holds B's old DIRECT address $old_b after ${HINTS_LEARN}s"
    require_alive "$a_pid" "$b_pid"
    sleep 1
  done
  before="$(old_b_packets)"
  sleep "$HINTS_FLAT"
  flat="$(old_b_packets)"
  if [[ "$flat" -ne "$before" ]]; then
    fail "rA's counter to $old_b grew ($before -> $flat) after A dropped the address"
  fi
  echo "--- #3 A -> B adds no packet to $old_b"
  send_check "$NS_HA" "$a" bob "hints-3" hints-3
  inbox_once "$NS_HB" "$b" "hints-3" b-3
  after="$(old_b_packets)"
  if [[ "$after" -ne "$flat" ]]; then
    fail "#3 sent $((after - flat)) packets to B's old address $old_b"
  fi
  for log in "$LOGS/a.service.log" "$LOGS/b.service.log"; do
    if grep -F -- 'raven-node hints' "$log" | grep -qE "$WAN\.|12D3Koo|/p2p/"; then
      fail "$(basename "$log") has a route-hints line naming an address or a PeerId"
    fi
  done
  echo "RESULT hints: #1 direct to B's address learned through RRH1; after B's swap #2 through a circuit within ${HINTS_DELIVER}s; then no packet to B's old address (flat for ${HINTS_FLAT}s, none for #3, path=$LAST_PATH)"
}

# ---- the custody run (Phase 3 item 3, friend custody over the internet) ----

# The custody run's public custodian C: pub "wk" WAN.31.1 -- hC eth0
# WAN.31.10 (no NAT), and pub's own table raven_custody counting every
# forwarded packet between A's and B's networks (a_b, b_a): with A and B
# behind symmetric NATs and C holding the mail, both stay 0 from the
# deposit on.
setup_custody_host() {
  ip netns add "$NS_HC"
  ip -n "$NS_HC" link set lo up
  ip -n "$NS_PUB" link add wk type veth peer name eth0 netns "$NS_HC"
  ip -n "$NS_PUB" addr add "$WAN.31.1/24" dev wk
  ip -n "$NS_PUB" link set wk up
  ip -n "$NS_HC" addr add "$WAN.31.10/24" dev eth0
  ip -n "$NS_HC" link set eth0 up
  ip -n "$NS_HC" route add default via "$WAN.31.1"
  ip netns exec "$NS_PUB" nft -f - <<NFT || fail "nft rejected pub's custody counters"
table ip raven_custody {
  counter a_b {
  }
  counter b_a {
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    ip saddr $WAN.1.0/24 ip daddr $WAN.2.0/24 counter name "a_b"
    ip saddr $WAN.2.0/24 ip daddr $WAN.1.0/24 counter name "b_a"
  }
}
NFT
  {
    echo "== custody: public custodian C on $WAN.31.10; pub counts a_b and b_a"
    ip netns exec "$NS_PUB" nft list table ip raven_custody
  } >>"$LOGS/topology.log" 2>&1
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HA" ping -c 1 -W 2 "$WAN.31.10" >>"$LOGS/topology.log" 2>&1 || fail "hA cannot reach C ($WAN.31.10)"
    in_ns "$NS_HB" ping -c 1 -W 2 "$WAN.31.10" >>"$LOGS/topology.log" 2>&1 || fail "hB cannot reach C ($WAN.31.10)"
  fi
}

# custody_packets NAME: pub's custody counter NAME (fails on a broken read).
custody_packets() {
  local n
  n="$(nft_counter "$NS_PUB" ip raven_custody "$1")" || fail "cannot read pub's nft counter $1"
  echo "$n"
}

# custody_start NS DIR NAME: (re)start NAME's service in NS (p2p on 7423,
# relay R), its log appended; sets NODE_PID and waits for its reservation
# (the Nth in its log: CUSTODY_STARTS[NAME]) and IPC.
declare -A CUSTODY_STARTS=()
custody_start() {
  local ns=$1 dir=$2 name=$3 n
  ip netns exec "$ns" "$NODE" service --data-dir "$dir" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$VIA" --timeout-secs 0 \
    >>"$LOGS/$name.service.log" 2>&1 &
  NODE_PID=$!
  PIDS+=("$NODE_PID")
  n=$((${CUSTODY_STARTS[$name]:-0} + 1))
  CUSTODY_STARTS[$name]=$n
  wait_count "$LOGS/$name.service.log" "$LINE_RESERVED" "$n" "$RESERVE_WAIT" "$NODE_PID"
  wait_ipc "$ns" "$dir" 30 "$NODE_PID"
}

# custody_stop PID: stop one service and wait for it.
custody_stop() {
  kill -TERM "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

# custodian_tags DIR PUB: how many custodian tags DIR's learned_routes.json
# keeps from the contact PUB (0 when none).
custodian_tags() {
  python3 - "$1/learned_routes.json" "$2" <<'PY' 2>/dev/null || echo 0
import json, sys

path, pub = sys.argv[1:3]
try:
    entries = json.load(open(path))
except (OSError, ValueError):
    entries = []
print(sum(len(e.get("custodian_tags") or []) for e in entries
          if isinstance(e, dict) and e.get("pub_hex", "").lower() == pub.lower()))
PY
}

run_custody() {
  local run_dir a b c relay_pid a_pid b_pid c_pid peer deadline a_fp b_fp c_fp a_pub b_pub
  local a_card b_card c_card ab ba text="custody-netns-1"
  MODE=custody
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if ! command -v python3 >/dev/null 2>&1; then
    fail "the custody run reads learned_routes.json with python3, which is missing"
  fi
  # This run's subshell only: route hints (custody rides RRH1), the WAN
  # custody switch and s30's custody timers for every process.
  export RAVEN_LAB_ROUTE_HINTS=1 RAVEN_LAB_CUSTODY_WAN=1
  export RAVEN_LAB_CUSTODY_AFTER_MS=0 RAVEN_LAB_CUSTODY_FETCH_MS=1000

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r"
  a="$run_dir/a"
  b="$run_dir/b"
  c="$run_dir/c"
  mkdir -p "$LOGS" "$R" "$a" "$b" "$c"
  chmod 700 "$R" "$a" "$b" "$c"
  echo "=== custody run: A and B behind symmetric NATs, C a public custodian (dirs under $run_dir) ==="
  setup_net "masquerade random,fully-random"
  setup_custody_host

  echo "--- relay R in pub on $WAN.0.1:7423"
  ip netns exec "$NS_PUB" "$NODE" relay --data-dir "$R" --listen "$WAN.0.1:7423" \
    >"$LOGS/relay.log" 2>&1 &
  relay_pid=$!
  PIDS+=("$relay_pid")
  peer=""
  deadline=$((SECONDS + RELAY_WAIT))
  while ((SECONDS < deadline)); do
    if [[ -s "$R/relay_status.json" ]]; then
      peer="$(relay_peer_id "$R/relay_status.json")"
      [[ -z "$peer" ]] || break
    fi
    check_hold "$LOGS/relay.log"
    require_alive "$relay_pid"
    sleep 0.2
  done
  [[ -n "$peer" ]] || fail "relay_status.json with a peer_id not written within ${RELAY_WAIT}s"
  VIA="/ip4/$WAN.0.1/tcp/7423/p2p/$peer"

  echo "--- init A (hA), B (hB) and C (hC), raven-card/3 cards naming R, all on R's list"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  a_pub="$INIT_PUB"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  b_pub="$INIT_PUB"
  raven_init "$NS_HC" "$c" c
  c_fp="$INIT_FP"
  raven_card "$NS_HA" "$a" a
  a_card="$CARD"
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  raven_card "$NS_HC" "$c" c
  c_card="$CARD"
  for card in "$a_card" "$b_card" "$c_card"; do
    in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$card" >>"$LOGS/relay.allow.out" 2>&1 \
      || fail "raven relay allow failed"
  done

  echo "--- services A, B and C (p2p 7423, relay R)"
  custody_start "$NS_HA" "$a" a
  a_pid="$NODE_PID"
  custody_start "$NS_HB" "$b" b
  b_pid="$NODE_PID"
  custody_start "$NS_HC" "$c" c
  c_pid="$NODE_PID"

  echo "--- everyone pins everyone (cards only: no LAN or Internet route)"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" --petname bob --tag bob \
    --verify-fp "$b_fp" >>"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$c_card" --petname carol --tag carol \
    --verify-fp "$c_fp" >>"$LOGS/a.contact.out" 2>&1 || fail "A contact add carol failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" --petname alice --tag alice \
    --verify-fp "$a_fp" >>"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$c_card" --petname carol --tag carol \
    --verify-fp "$c_fp" >>"$LOGS/b.contact.out" 2>&1 || fail "B contact add carol failed"
  in_ns "$NS_HC" "$RAVEN" --data-dir "$c" contact add --card "$a_card" --petname alice --tag alice \
    --verify-fp "$a_fp" >>"$LOGS/c.contact.out" 2>&1 || fail "C contact add alice failed"
  in_ns "$NS_HC" "$RAVEN" --data-dir "$c" contact add --card "$b_card" --petname bob --tag bob \
    --verify-fp "$b_fp" >>"$LOGS/c.contact.out" 2>&1 || fail "C contact add bob failed"
  wait_line "$LOGS/a.service.log" "$LINE_GATE_TWO" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_GATE_TWO" 30 "$b_pid"
  wait_line "$LOGS/c.service.log" "$LINE_GATE_TWO" 30 "$c_pid"

  echo "--- C holds mail for friends; A and B use friend mailboxes (nobody names a custodian)"
  in_ns "$NS_HC" "$RAVEN" --data-dir "$c" node custody on --yes >"$LOGS/c.custody.out" 2>&1 \
    || fail "C node custody on --yes failed"
  grep -Fq 'ok friend custody on' "$LOGS/c.custody.out" || fail "C's custody consent was not saved"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" custody use on --yes >"$LOGS/a.mailbox.out" 2>&1 \
    || fail "A custody use on --yes failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" custody use on --yes >"$LOGS/b.mailbox.out" 2>&1 \
    || fail "B custody use on --yes failed"

  echo "--- C's offer reaches A and B; then A and B tell each other their mail friend"
  send_check "$NS_HA" "$a" carol "custody-warm-ac" warm-ac
  send_check "$NS_HB" "$b" carol "custody-warm-bc" warm-bc
  wait_line "$LOGS/a.service.log" "$LINE_MAIL_FRIENDS" 90 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_MAIL_FRIENDS" 90 "$b_pid"
  send_check "$NS_HA" "$a" bob "custody-warm-ab" warm-ab
  send_check "$NS_HB" "$b" alice "custody-warm-ba" warm-ba
  deadline=$((SECONDS + 60))
  until [[ "$(custodian_tags "$a" "$b_pub")" -ge 1 && "$(custodian_tags "$b" "$a_pub")" -ge 1 ]]; do
    ((SECONDS < deadline)) || fail "A and B hold no custodian tag from each other within 60s"
    require_alive "$a_pid" "$b_pid" "$c_pid"
    sleep 1
  done
  # Hole-punch tries the warm-up circuits started are over by now; from
  # here on nothing may pass between A's and B's networks.
  sleep "$DCUTR_OBSERVE"
  for name in a_b b_a; do
    ip netns exec "$NS_PUB" nft reset counter ip raven_custody "$name" >/dev/null \
      || fail "cannot reset pub's counter $name"
  done

  echo "--- 1. B down; A's message is left with C"
  custody_stop "$b_pid"
  send_queued "$NS_HA" "$a" bob "$text" deposit
  deadline=$((SECONDS + 60))
  until in_ns "$NS_HA" "$RAVEN" --data-dir "$a" outbox list 2>/dev/null | grep -Fq 'held by 1 friend'; do
    ((SECONDS < deadline)) || fail "A's outbox says no friend holds the message within 60s"
    require_alive "$a_pid" "$c_pid"
    sleep 1
  done
  grep -F -- "$LINE_CUSTODY_LEFT" "$LOGS/a.service.log" | grep -Fq 'p2p_dial' \
    || fail "A's deposit line names no p2p_dial"

  echo "--- 2. A down; B up fetches it from C, and leaves its ACK with C"
  custody_stop "$a_pid"
  custody_start "$NS_HB" "$b" b
  b_pid="$NODE_PID"
  inbox_once "$NS_HB" "$b" "$text" fetched 60
  wait_line "$LOGS/b.service.log" "$LINE_CUSTODY_LEFT" 60 "$b_pid"

  echo "--- 3. B down; A up fetches the ACK from C"
  custody_stop "$b_pid"
  custody_start "$NS_HA" "$a" a
  a_pid="$NODE_PID"
  deadline=$((SECONDS + 60))
  until grep -Eq 'raven-node custody: fetched messages=[0-9]+ acks=[1-9]' "$LOGS/a.service.log"; do
    ((SECONDS < deadline)) || fail "A fetched no ACK from C within 60s"
    require_alive "$a_pid" "$c_pid"
    sleep 1
  done
  ab="$(custody_packets a_b)"
  ba="$(custody_packets b_a)"
  echo "pub counters between A's and B's networks: a_b=$ab b_a=$ba"
  if [[ "$ab" -ne 0 || "$ba" -ne 0 ]]; then
    fail "packets passed between A's and B's networks (a_b=$ab b_a=$ba): custody must go through C only"
  fi
  for log in "$LOGS/a.service.log" "$LOGS/b.service.log" "$LOGS/c.service.log"; do
    if grep -F -- 'raven-node custody' "$log" | grep -qE "$WAN\.|12D3Koo|/p2p/|[0-9a-f]{64}"; then
      fail "$(basename "$log") has a custody line naming an address, a PeerId or a key"
    fi
  done
  echo "RESULT custody: deposit, fetch and ACK through the public custodian C, exactly once; 0 packets between A's and B's networks"
}

# ---- the friend runs (Phase 2 items 2-3, friend relays; advisory) -----------

# Their own topology (see the header): operators A, D and E public (no NAT),
# each on a /24 of its own; B behind rB's cone NAT, C behind rC's symmetric
# one. Both routers count with the three operators as "the relay"
# (lan_to_other, wan_from_other), and rC's own table raven_friend counts C's
# packets of established flows to anyone but the operators (c_direct_est: a
# direct path that worked; a hole-punch attempt that got no answer is not
# established).
FRIEND_OPS=""
setup_friend_net() {
  local ns i host
  for ns in "$NS_PUB" "$NS_HA" "$NS_HD" "$NS_HE" "$NS_RB" "$NS_HB" "$NS_RC" "$NS_HC"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip netns exec "$NS_PUB" sysctl -qw net.ipv4.ip_forward=1
  i=21
  for host in "$NS_HA" "$NS_HD" "$NS_HE"; do
    ip -n "$NS_PUB" link add "w$i" type veth peer name eth0 netns "$host"
    ip -n "$NS_PUB" addr add "$WAN.$i.1/24" dev "w$i"
    ip -n "$NS_PUB" link set "w$i" up
    ip -n "$host" addr add "$WAN.$i.10/24" dev eth0
    ip -n "$host" link set eth0 up
    ip -n "$host" route add default via "$WAN.$i.1"
    i=$((i + 1))
  done
  FRIEND_OPS="{ $WAN.21.10, $WAN.22.10, $WAN.23.10 }"
  ip -n "$NS_PUB" link add w24 type veth peer name wan netns "$NS_RB"
  ip -n "$NS_PUB" link add w25 type veth peer name wan netns "$NS_RC"
  ip -n "$NS_RB" link add lan type veth peer name eth0 netns "$NS_HB"
  ip -n "$NS_RC" link add lan type veth peer name eth0 netns "$NS_HC"
  ip -n "$NS_PUB" addr add "$WAN.24.1/24" dev w24
  ip -n "$NS_PUB" addr add "$WAN.25.1/24" dev w25
  ip -n "$NS_PUB" link set w24 up
  ip -n "$NS_PUB" link set w25 up
  ip -n "$NS_RB" addr add "$WAN.24.2/24" dev wan
  ip -n "$NS_RB" addr add 192.168.6.1/24 dev lan
  ip -n "$NS_RC" addr add "$WAN.25.2/24" dev wan
  ip -n "$NS_RC" addr add 192.168.7.1/24 dev lan
  for ns in "$NS_RB" "$NS_RC"; do
    ip -n "$ns" link set wan up
    ip -n "$ns" link set lan up
  done
  ip -n "$NS_RB" route add default via "$WAN.24.1"
  ip -n "$NS_RC" route add default via "$WAN.25.1"
  ip -n "$NS_HB" addr add 192.168.6.2/24 dev eth0
  ip -n "$NS_HB" link set eth0 up
  ip -n "$NS_HB" route add default via 192.168.6.1
  ip -n "$NS_HC" addr add 192.168.7.2/24 dev eth0
  ip -n "$NS_HC" link set eth0 up
  ip -n "$NS_HC" route add default via 192.168.7.1
  nat_rules "$NS_RB" "masquerade" "$FRIEND_OPS"
  nat_rules "$NS_RC" "masquerade random,fully-random" "$FRIEND_OPS"
  ip netns exec "$NS_RC" nft -f - <<EOF || fail "nft rejected rC's c_direct_est counter"
table ip raven_friend {
  counter c_direct_est {
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "lan" oifname "wan" ip daddr != $FRIEND_OPS ct state established counter name "c_direct_est"
  }
}
EOF
  if [[ -n "$(ip -n "$NS_PUB" route show default 2>/dev/null)" ]]; then
    fail "pub has a default route: the simulated Internet ($WAN.0.0/16) must not reach the real one"
  fi
  {
    echo "== $MODE: operators $WAN.21.10, $WAN.22.10, $WAN.23.10 public; rB masquerade, rC masquerade random,fully-random"
    ip netns exec "$NS_RB" nft list ruleset
    ip netns exec "$NS_RC" nft list ruleset
  } >"$LOGS/topology.log" 2>&1
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HB" ping -c 1 -W 2 "$WAN.21.10" >>"$LOGS/topology.log" 2>&1 || fail "hB cannot reach A ($WAN.21.10) through rB"
    in_ns "$NS_HC" ping -c 1 -W 2 "$WAN.23.10" >>"$LOGS/topology.log" 2>&1 || fail "hC cannot reach E ($WAN.23.10) through rC"
    if in_ns "$NS_HC" ping -c 1 -W 1 192.168.6.2 >>"$LOGS/topology.log" 2>&1; then
      fail "hC reaches hB's private address directly: the topology leaks"
    fi
  fi
  ip netns exec "$NS_RC" nft reset counter ip raven_friend c_direct_est >/dev/null \
    || fail "cannot reset rC's counter c_direct_est"
}

# friend_ns NAME, friend_tag NAME, friend_ip NAME: a friend run's node (a, d,
# e: the operators; b, c), its petname, an operator's public address.
friend_ns() {
  case "$1" in
    a) echo "$NS_HA" ;;
    d) echo "$NS_HD" ;;
    e) echo "$NS_HE" ;;
    b) echo "$NS_HB" ;;
    c) echo "$NS_HC" ;;
  esac
}
friend_tag() {
  case "$1" in
    a) echo alice ;;
    d) echo dave ;;
    e) echo erin ;;
    b) echo bob ;;
    c) echo carol ;;
  esac
}
friend_ip() {
  case "$1" in
    a) echo "$WAN.21.10" ;;
    d) echo "$WAN.22.10" ;;
    e) echo "$WAN.23.10" ;;
  esac
}

# friend_start NAME [VAR=VALUE...]: NAME's service (run_friend's run_dir) in
# its namespace, with more environment; p2p on 7423, no relay set by hand.
# Its pid goes to run_dir/NAME.pid.
friend_start() {
  local k=$1 pid
  shift
  ip netns exec "$(friend_ns "$k")" env "$@" "$NODE" service --data-dir "$run_dir/$k" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 --p2p-listen 0.0.0.0:7423 --timeout-secs 0 \
    >"$LOGS/$k.service.log" 2>&1 &
  pid=$!
  PIDS+=("$pid")
  echo "$pid" >"$run_dir/$k.pid"
}

friend_pid() {
  cat "$run_dir/$1.pid"
}

# friend_card NAME: NAME's card from its running service into
# run_dir/NAME.card. An operator's names its own public p2p address (B and C
# dial it directly to learn its offer); B's and C's whatever their service
# holds (at first only their PeerId, later the relays they picked).
friend_card() {
  local k=$1 ns out peer
  ns="$(friend_ns "$k")"
  out="$LOGS/$k.card.out"
  in_ns "$ns" "$RAVEN" --data-dir "$run_dir/$k" whoami --card >"$out" 2>&1 \
    || fail "raven whoami --card ($k) failed"
  peer="$(grep -m 1 -oE ' p2p=[1-9A-HJ-NP-Za-km-z]+' "$out" | cut -d= -f2 || true)"
  [[ -n "$peer" ]] || fail "the $k card names no p2p= PeerId"
  case "$k" in
    a | d | e)
      in_ns "$ns" "$RAVEN" --data-dir "$run_dir/$k" whoami --card \
        --via "/ip4/$(friend_ip "$k")/tcp/7423/p2p/$peer" >"$out" 2>&1 \
        || fail "raven whoami --card --via ($k) failed"
      ;;
  esac
  grep -m 1 -E '^raven-card/[23] ' "$out" >"$run_dir/$k.card" || fail "no card line for $k"
}

# friend_pin NAME OTHER: NAME pins OTHER's card (its fingerprint compared).
friend_pin() {
  local k=$1 o=$2 tag
  tag="$(friend_tag "$o")"
  in_ns "$(friend_ns "$k")" "$RAVEN" --data-dir "$run_dir/$k" contact add \
    --card "$(cat "$run_dir/$o.card")" --petname "$tag" --tag "$tag" \
    --verify-fp "$(cat "$run_dir/$o.fp")" >>"$LOGS/$k.contact.out" 2>&1 \
    || fail "$k contact add $tag failed"
}

# friend_slots NAME SECS: until NAME's doctor says it holds two relays picked
# from offers, both reserved.
friend_slots() {
  local k=$1 secs=$2 deadline out="$LOGS/$1.doctor.out"
  deadline=$((SECONDS + secs))
  while :; do
    in_ns "$(friend_ns "$k")" "$RAVEN" --data-dir "$run_dir/$k" doctor >"$out" 2>&1 || true
    if grep -Fq 'relay_1_source=offer relay_2_source=offer' "$out" \
      && grep -Eq '^ *relay_1: reserved ' "$out" && grep -Eq '^ *relay_2: reserved ' "$out"; then
      return 0
    fi
    ((SECONDS < deadline)) || fail "$k holds no 2 reserved relays picked from offers within ${secs}s"
    require_alive "$(friend_pid "$k")"
    sleep 1
  done
}

# run_friend MODE: friend (offers only, relayed past a symmetric NAT) or
# friend-sleep (an operator stopped and continued).
run_friend() {
  local run_dir k o first sleeper replaced n est raw from_other member_env=()
  MODE=$1
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  # This run's subshell only: friend relays, and route hints (the offers
  # ride RRH1), for every process.
  export RAVEN_LAB_ROUTE_HINTS=1 RAVEN_LAB_FRIEND_RELAY=1
  if [[ "$MODE" == "friend-sleep" ]]; then
    # B and C: relay choice in seconds, and pings every 5 s (a stopped
    # operator is noticed at once).
    member_env=("RAVEN_LAB_RELAY_SELECT=20,10,5" "RAVEN_LAB_P2P_PING=5,2")
  fi

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R=""
  mkdir -p "$LOGS"
  for k in a d e b c; do
    mkdir -p "$run_dir/$k"
    chmod 700 "$run_dir/$k"
  done
  echo "=== $MODE run: operators A, D and E public with friend relays; B behind a cone NAT, C behind a symmetric one (dirs under $run_dir) ==="
  setup_friend_net

  echo "--- init; each operator turns relaying for its contacts on (port 7427, its public address named)"
  for k in a d e b c; do
    raven_init "$(friend_ns "$k")" "$run_dir/$k" "$k"
    echo "$INIT_FP" >"$run_dir/$k.fp"
  done
  for k in a d e; do
    in_ns "$(friend_ns "$k")" "$RAVEN" --data-dir "$run_dir/$k" relay offer on \
      --external "/ip4/$(friend_ip "$k")/tcp/7427" >"$LOGS/$k.offer.out" 2>&1 \
      || fail "raven relay offer on ($k) failed"
  done

  echo "--- services: everyone listens on 7423; B and C set no relay"
  for k in a d e; do
    friend_start "$k"
  done
  for k in b c; do
    friend_start "$k" ${member_env[@]+"${member_env[@]}"}
  done
  for k in a d e; do
    wait_line "$LOGS/$k.service.log" "$LINE_FRIEND_UP" "$RESERVE_WAIT" "$(friend_pid "$k")"
  done
  for k in a d e b c; do
    wait_ipc "$(friend_ns "$k")" "$run_dir/$k" 30 "$(friend_pid "$k")"
  done

  echo "--- cards and pins: the operators pin everyone; B and C pin the operators"
  for k in a d e b c; do
    friend_card "$k"
  done
  for k in a d e; do
    for o in a d e b c; do
      [[ "$o" == "$k" ]] || friend_pin "$k" "$o"
    done
    wait_line "$LOGS/$k.service.log" 'raven-node p2p: peer gate reloaded (verified contacts 4,' 30 "$(friend_pid "$k")"
  done
  for k in b c; do
    for o in a d e; do
      friend_pin "$k" "$o"
    done
    wait_line "$LOGS/$k.service.log" 'raven-node p2p: peer gate reloaded (verified contacts 3,' 30 "$(friend_pid "$k")"
  done

  echo "--- B and C link each operator directly (one message each): its route hints carry its offer"
  for k in b c; do
    for o in a d e; do
      send_check "$(friend_ns "$k")" "$run_dir/$k" "$(friend_tag "$o")" "friend-$MODE-$k-to-$o" "$k-to-$o"
    done
  done
  for k in b c; do
    friend_slots "$k" "$RESERVE_WAIT"
  done
  echo "B and C each hold 2 relays picked from the operators' offers, reserved"

  echo "--- B and C exchange cards (each names the 2 relays it holds) and pin each other"
  friend_card b
  friend_card c
  friend_pin b c
  friend_pin c b
  for k in b c; do
    wait_line "$LOGS/$k.service.log" 'raven-node p2p: peer gate reloaded (verified contacts 4,' 30 "$(friend_pid "$k")"
  done

  if [[ "$MODE" == "friend" ]]; then
    ip netns exec "$NS_RC" nft reset counter ip raven_friend c_direct_est >/dev/null \
      || fail "cannot reset rC's counter c_direct_est"
    echo "--- C -> B and B -> C: relayed through an operator's friend relay"
    send_check "$NS_HC" "$run_dir/c" bob "friend-c2b-1" c2b-1
    inbox_once "$NS_HB" "$run_dir/b" "friend-c2b-1" b-c2b-1
    require_path "$PATH_RELAYED" "the message C -> B"
    send_check "$NS_HB" "$run_dir/b" carol "friend-b2c-1" b2c-1
    inbox_once "$NS_HC" "$run_dir/c" "friend-b2c-1" c-b2c-1
    require_path "$PATH_RELAYED" "the message B -> C"
    # Long enough for a hole punch to be tried (C's symmetric NAT defeats it).
    sleep "$DCUTR_OBSERVE"
    est="$(nft_counter "$NS_RC" ip raven_friend c_direct_est)" || fail "cannot read rC's counter c_direct_est"
    raw="$(counter "$NS_RC" lan_to_other)" || fail "cannot read rC's counter lan_to_other"
    from_other="$(counter "$NS_RB" wan_from_other)" || fail "cannot read rB's counter wan_from_other"
    echo "counters: rC c_direct_est=$est (established flows to anyone but the operators), lan_to_other=$raw (hole-punch tries included), rB wan_from_other=$from_other"
    if [[ "$est" -ne 0 ]]; then
      fail "C kept $est packets of established flows to an address that is no operator's: a direct path past rC"
    fi
  else
    echo "--- the operator of B's first relay goes to sleep (SIGSTOP)"
    first="$(in_ns "$NS_HB" "$RAVEN" --data-dir "$run_dir/b" status 2>/dev/null \
      | grep -m 1 -E '^ *relay 1 ' | grep -oE "[a-z]+'s relay" | cut -d"'" -f1 || true)"
    case "$first" in
      alice) sleeper=a ;;
      dave) sleeper=d ;;
      erin) sleeper=e ;;
      *) fail "B's first relay is no operator's ('$first')" ;;
    esac
    replaced="$(count_lines "$LOGS/b.service.log" "$LINE_REPLACED")"
    kill -STOP "$(friend_pid "$sleeper")"
    wait_count "$LOGS/b.service.log" "$LINE_REPLACED" $((replaced + 1)) "$FRIEND_REPLACE" "$(friend_pid b)"
    echo "B replaced $first's sleeping relay"
    send_check "$NS_HC" "$run_dir/c" bob "friend-sleep-c2b" c2b-sleep
    inbox_once "$NS_HB" "$run_dir/b" "friend-sleep-c2b" b-c2b-sleep
    kill -CONT "$(friend_pid "$sleeper")"
    echo "--- $first wakes: B keeps its new relay (no second replacement within ${FRIEND_STICKY}s)"
    sleep "$FRIEND_STICKY"
    require_alive "$(friend_pid "$sleeper")" "$(friend_pid b)"
    n="$(count_lines "$LOGS/b.service.log" "$LINE_REPLACED")"
    if [[ "$n" -ne $((replaced + 1)) ]]; then
      fail "B replaced a relay $((n - replaced)) times; once expected (it went back to $first's?)"
    fi
  fi
  for k in a d e b c; do
    if grep -q '12D3Koo' "$LOGS/$k.service.log"; then
      fail "$k's log names a PeerId"
    fi
  done
  if [[ "$MODE" == "friend" ]]; then
    echo "RESULT friend: B and C each picked 2 relays from offers only; C -> B and B -> C relayed; C kept no established flow to anyone but the operators"
  else
    echo "RESULT friend-sleep: B replaced the sleeping operator's relay within ${FRIEND_REPLACE}s, C -> B still delivered, and no second replacement after the operator woke"
  fi
}

# ---- the diag run (Phase 2 item 5, why a contact is unreachable; advisory) --

# diag_reasons NS DIR: the reason blocks (`reach: why=…`) of the running
# service's IPC Status `unreachable` rows, one per line (states and ages
# only: no key, PeerId or address); empty while it answers nothing.
diag_reasons() {
  local ns=$1 dir=$2 ep
  ep="$(in_ns "$ns" "$RAVEN" --data-dir "$dir" ipc-ping 2>/dev/null | sed -n 's/.* endpoint=//p' | head -n 1 || true)"
  if [[ -z "$ep" ]]; then
    return 0
  fi
  python3 - "$ep" 2>/dev/null <<'PY' || true
import json, socket, struct, sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(sys.argv[1])
body = json.dumps({"op": "status", "v": 1}).encode()
s.sendall(struct.pack(">I", len(body)) + body)


def read(n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


(size,) = struct.unpack(">I", read(4))
for row in json.loads(read(size)).get("unreachable") or []:
    print(row.get("reason", ""))
PY
}

# wait_reason NS DIR NAME GLOB SECS PID...: until one of diag_reasons'
# lines matches GLOB (logged to diag.reasons.log).
wait_reason() {
  local ns=$1 dir=$2 name=$3 want=$4 secs=$5 deadline line
  shift 5
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    while IFS= read -r line; do
      # shellcheck disable=SC2053 # $want is a glob on purpose
      if [[ "$line" == $want ]]; then
        echo "$name: $line" >>"$LOGS/diag.reasons.log"
        return 0
      fi
    done < <(diag_reasons "$ns" "$dir")
    require_alive "$@"
    sleep 1
  done
  fail "$name gave no reason matching '$want' within ${secs}s (last: '$(diag_reasons "$ns" "$dir" | tr '\n' '|')')"
}

# diag_status NS DIR TAG: `raven status` into $LOGS/TAG.status.out.
diag_status() {
  in_ns "$1" "$RAVEN" --data-dir "$2" status >"$LOGS/$3.status.out" 2>&1 \
    || fail "raven status ($3) failed"
}

# wait_status_text NS DIR TAG FIXED_TEXT SECS PID...: until `raven status`
# prints FIXED_TEXT (the what-to-do advice changes while a relay is tried
# again, so it is polled every second).
wait_status_text() {
  local ns=$1 dir=$2 tag=$3 text=$4 secs=$5 deadline
  shift 5
  deadline=$((SECONDS + secs))
  while ((SECONDS < deadline)); do
    diag_status "$ns" "$dir" "$tag"
    if grep -Fq -- "$text" "$LOGS/$tag.status.out"; then
      return 0
    fi
    require_alive "$@"
    sleep 1
  done
  fail "raven status ($tag) never said '$text' within ${secs}s"
}

# send_undelivered NS DIR TO TEXT TAG: a `raven send --carrier p2p` that is
# not delivered (queued, or NOT SENT for a first message); its output in
# $LOGS/TAG.send.out (stdout and stderr).
send_undelivered() {
  local ns=$1 dir=$2 to=$3 text=$4 tag=$5 rc=0
  printf '%s\n' "$text" | timeout "$SEND_TIMEOUT" ip netns exec "$ns" "$RAVEN" --data-dir "$dir" \
    send --contact "@$to" --carrier p2p >"$LOGS/$tag.send.out" 2>&1 || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    fail "send $tag was delivered; it should not be"
  fi
}

# start_diag_node NS DIR NAME LISTEN [VIA]: `raven-node service` with
# --p2p-listen LISTEN (and a reservation on VIA); its log is appended to
# $LOGS/NAME.service.log, so a restart keeps the earlier lines. LISTEN
# `relay` is the retired no-listener mode, kept by the debug
# RAVEN_LAB_P2P_RELAY_ONLY=1 for that one process. Sets NODE_PID.
start_diag_node() {
  local ns=$1 dir=$2 name=$3 listen=$4 via=${5:-} envs=(env) args=()
  if [[ "$listen" == "relay" ]]; then
    envs+=(RAVEN_LAB_P2P_RELAY_ONLY=1)
  fi
  if [[ -n "$via" ]]; then
    args+=(--p2p-relay "$via")
  fi
  ip netns exec "$ns" "${envs[@]}" "$NODE" service --data-dir "$dir" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen "$listen" ${args[@]+"${args[@]}"} --timeout-secs 0 \
    >>"$LOGS/$name.service.log" 2>&1 &
  NODE_PID=$!
  PIDS+=("$NODE_PID")
}

# diag_card NS DIR NAME: CARD is the running service's card, which must
# name a PeerId and no relay (`raven whoami --card`).
diag_card() {
  local ns=$1 dir=$2 name=$3 out
  out="$LOGS/$name.card.out"
  in_ns "$ns" "$RAVEN" --data-dir "$dir" whoami --card >"$out" 2>&1 \
    || fail "raven whoami --card ($name) failed"
  CARD="$(grep -m 1 -E '^raven-card/[23] ' "$out" || true)"
  if [[ "$CARD" != *" p2p="* || "$CARD" == *" via="* || "$CARD" == *" relay="* ]]; then
    fail "the running $name card should name a PeerId and no relay: '$CARD'"
  fi
}

# stop_diag_node PID: SIGTERM, and wait for it.
stop_diag_node() {
  kill -TERM "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

# The diag run: the cone topology (setup_net), every reason the "nobody
# reachable" diagnosis gives on a real NAT, in order. (1) No relay, and A
# and B without a listening port (A can be reached by nobody: its class is
# unreachable, not unknown): A's first message gives both_nat, and A's
# status says `NOT reachable` and W3. (2) Relay R on pub with
# --autonat-server, both reserve and listen on 7423: A -> B and B -> A are
# delivered, relayed or hole_punched (recorded). (3) A restarts (no
# connection to B is left), then R is stopped with SIGSTOP (a laptop
# relay asleep): A's queued message gives relay_asleep with relay=mine1
# and A's what-to-do is W1; after SIGCONT it is delivered once. (4) B's
# service stops while R runs: contact_offline.
run_diag() {
  local run_dir a b a_pid b_pid relay_pid a_fp b_fp a_card b_card log n line
  MODE=diag
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if ! command -v python3 >/dev/null 2>&1; then
    fail "the diag run reads IPC Status with python3, which is missing"
  fi

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r"
  a="$run_dir/a"
  b="$run_dir/b"
  mkdir -p "$LOGS" "$a" "$b"
  chmod 700 "$a" "$b"
  echo "=== diag run: cone routers, WAN $WAN.0.0/16, no relay at first (dirs under $run_dir) ==="
  setup_net "masquerade"

  echo "--- (1) A (hA) and B (hB), no listening port, no relay: both behind NAT"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  start_diag_node "$NS_HA" "$a" a relay
  a_pid="$NODE_PID"
  start_diag_node "$NS_HB" "$b" b relay
  b_pid="$NODE_PID"
  wait_line "$LOGS/a.service.log" "$LINE_HOST_UP" "$RESERVE_WAIT" "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_HOST_UP" "$RESERVE_WAIT" "$b_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"
  diag_card "$NS_HA" "$a" a
  a_card="$CARD"
  diag_card "$NS_HB" "$b" b
  b_card="$CARD"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"
  wait_line "$LOGS/a.service.log" "$LINE_GATE_ONE" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_GATE_ONE" 30 "$b_pid"
  send_undelivered "$NS_HA" "$a" bob "diag-nat" diag-nat
  for line in "why=both_nat" "you and bob are both behind NAT" "Nobody in your circle can be reached"; do
    grep -Fq -- "$line" "$LOGS/diag-nat.send.out" || fail "A's send to B does not say '$line'"
  done
  wait_reason "$NS_HA" "$a" a '*why=both_nat*' 10 "$a_pid"
  diag_status "$NS_HA" "$a" a-nat
  grep -Eq '^ *internet +NOT reachable from the internet: behind NAT and no working relay' \
    "$LOGS/a-nat.status.out" || fail "A's internet row does not say 'NOT reachable' (see a-nat.status.out)"
  grep -Fq 'nobody in your circle can be reached from the internet, so nobody outside this network can reach you' \
    "$LOGS/a-nat.status.out" || fail "A's what-to-do is not W3 (see a-nat.status.out)"
  echo "A -> B: both_nat; A's status: NOT reachable, W3"

  echo "--- (2) relay R on $WAN.0.1 with --autonat-server; A and B listen on 7423 and reserve"
  start_reach_relay r "$WAN.0.1"
  relay_pid="$RELAY_PID"
  VIA="$RELAY_VIA"
  echo "VIA=$VIA"
  raven_card "$NS_HA" "$a" a
  a_card="$CARD"
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  : >"$LOGS/relay.allow.out"
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$a_card" >>"$LOGS/relay.allow.out" 2>&1 \
    || fail "raven relay allow (A) failed"
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$b_card" >>"$LOGS/relay.allow.out" 2>&1 \
    || fail "raven relay allow (B) failed"
  # Each holds the other's relay, as the other's new card says.
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact set-addr @bob --via "$VIA" >>"$LOGS/a.contact.out" 2>&1 \
    || fail "A contact set-addr @bob --via failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact set-addr @alice --via "$VIA" >>"$LOGS/b.contact.out" 2>&1 \
    || fail "B contact set-addr @alice --via failed"
  stop_diag_node "$a_pid"
  stop_diag_node "$b_pid"
  start_diag_node "$NS_HA" "$a" a 0.0.0.0:7423 "$VIA"
  a_pid="$NODE_PID"
  start_diag_node "$NS_HB" "$b" b 0.0.0.0:7423 "$VIA"
  b_pid="$NODE_PID"
  wait_line "$LOGS/a.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$a_pid" "$relay_pid"
  wait_line "$LOGS/b.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$b_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"
  send_check "$NS_HA" "$a" bob "diag-a2b" diag-a2b
  inbox_once "$NS_HB" "$b" "diag-a2b" b-diag-a2b
  require_path "$PATH_RELAYED|$PATH_PUNCHED" "A -> B through R"
  send_check "$NS_HB" "$b" alice "diag-b2a" diag-b2a
  inbox_once "$NS_HA" "$a" "diag-b2a" a-diag-b2a
  require_path "$PATH_RELAYED|$PATH_PUNCHED" "B -> A through R"
  echo "delivered both ways (last path=$LAST_PATH)"

  echo "--- (3) A restarts, then R is stopped (SIGSTOP): relay_asleep, W1"
  stop_diag_node "$a_pid"
  n="$(count_lines "$LOGS/a.service.log" "$LINE_RESERVED")"
  start_diag_node "$NS_HA" "$a" a 0.0.0.0:7423 "$VIA"
  a_pid="$NODE_PID"
  wait_count "$LOGS/a.service.log" "$LINE_RESERVED" $((n + 1)) "$RESERVE_WAIT" "$a_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  kill -STOP "$relay_pid"
  send_queued "$NS_HA" "$a" bob "diag-asleep" diag-asleep
  wait_reason "$NS_HA" "$a" a '*why=relay_asleep*relay=mine1*' "$DIAG_REASON" "$a_pid"
  wait_status_text "$NS_HA" "$a" a-asleep "what to do    your relay is not answering" "$DIAG_REASON" "$a_pid"
  kill -CONT "$relay_pid"
  inbox_once "$NS_HB" "$b" "diag-asleep" b-diag-asleep "$DIAG_DELIVER"
  echo "A -> B: relay_asleep (relay=mine1), W1; delivered once after SIGCONT"

  echo "--- (4) B's service stops while R runs: contact_offline"
  stop_diag_node "$b_pid"
  send_queued "$NS_HA" "$a" bob "diag-offline" diag-offline
  wait_reason "$NS_HA" "$a" a '*why=contact_offline*' "$DIAG_REASON" "$a_pid" "$relay_pid"
  wait_status_text "$NS_HA" "$a" a-offline "bob's computer is not connected to its relay" 30 "$a_pid"

  for log in "$LOGS/a.service.log" "$LOGS/b.service.log" "$LOGS/r.log"; do
    if grep -q '12D3Koo' "$log"; then
      fail "$(basename "$log") names a PeerId"
    fi
  done
  while IFS= read -r line; do
    if [[ "$line" == *"$WAN."* || "$line" == *"192.168."* || "$line" == *"/p2p/"* ]]; then
      fail "a.service.log's reason line names an address: '$line'"
    fi
  done < <(grep -F -- "$LINE_UNREACHABLE" "$LOGS/a.service.log" || true)
  echo "RESULT diag: both_nat with W3, then $LAST_PATH through R, relay_asleep (relay=mine1) with W1 while R slept, then contact_offline"
}

# ---- the only443 run (Phase 2 item 4, the relay kit; advisory) ----------------

# hA's egress filter (an inet table in hA only, so A's processes and nothing
# else): loopback and established or related packets pass, a new TCP
# connection to port 443 passes and is counted (tcp443), anything else is
# dropped and counted (dropped; tcp7423 counts the part of it that tried R's
# main port, tcp7427 a friend relay's port). `wan_two_network_test.sh
# egress443 print` prints the same rules for the owner's R8 row.
egress443_ruleset() {
  cat <<'EOF'
table inet r443 {
  counter tcp443 {
  }
  counter dropped {
  }
  counter tcp7423 {
  }
  counter tcp7427 {
  }
  chain out {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    tcp dport 443 counter name "tcp443" accept
    tcp dport 7423 counter name "tcp7423"
    tcp dport 7427 counter name "tcp7427"
    counter name "dropped" drop
  }
}
EOF
}

# egress_counter NAME: hA's egress filter counter NAME (fails on a broken read).
egress_counter() {
  nft_counter "$NS_HA" inet r443 "$1" || fail "cannot read hA's egress counter $1"
}

run_only443() {
  local run_dir a b relay_pid a_pid b_pid peer="" deadline a_fp b_fp a_card b_card card
  local v7423 v443 tcp443 dropped tcp7423 tcp7427
  MODE=only443
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r"
  a="$run_dir/a"
  b="$run_dir/b"
  mkdir -p "$LOGS" "$R" "$a" "$b"
  chmod 700 "$R" "$a" "$b"
  echo "=== only443 run: A may open TCP 443 only, R listens on 7423 and 443 (dirs under $run_dir) ==="
  setup_net "masquerade"

  echo "--- relay R in pub on $WAN.0.1:7423 (TCP + QUIC) and TCP 443"
  ip netns exec "$NS_PUB" "$NODE" relay --data-dir "$R" --listen "$WAN.0.1:7423" --also-tcp 443 \
    >"$LOGS/relay.log" 2>&1 &
  relay_pid=$!
  PIDS+=("$relay_pid")
  wait_line "$LOGS/relay.log" "raven-node relay: up (listeners=3; tcp ports 7423,443;" "$RELAY_WAIT" "$relay_pid"
  deadline=$((SECONDS + RELAY_WAIT))
  while ((SECONDS < deadline)); do
    if [[ -s "$R/relay_status.json" ]]; then
      peer="$(relay_peer_id "$R/relay_status.json")"
      [[ -z "$peer" ]] || break
    fi
    require_alive "$relay_pid"
    sleep 0.2
  done
  if [[ ! "$peer" =~ ^[1-9A-HJ-NP-Za-km-z]+$ ]]; then
    fail "relay_status.json with a base58 peer_id not written within ${RELAY_WAIT}s"
  fi
  v7423="/ip4/$WAN.0.1/tcp/7423/p2p/$peer"
  v443="/ip4/$WAN.0.1/tcp/443/p2p/$peer"
  VIA="$v7423"

  echo "--- init A (hA) and B (hB); A's card names both addresses of R, B's the 7423 one"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" whoami --card --via "$v7423" --via "$v443" \
    >"$LOGS/a.card.out" 2>&1 || fail "raven whoami --card (a) failed"
  a_card="$(grep -m 1 -E '^raven-card/2 ' "$LOGS/a.card.out" || true)"
  if [[ "$a_card" != *" via=$v7423"* || "$a_card" != *" via=$v443"* ]]; then
    fail "A's card does not name both addresses of R"
  fi
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  for card in "$a_card" "$b_card"; do
    in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$card" >>"$LOGS/relay.allow.out" 2>&1 \
      || fail "raven relay allow failed"
  done

  echo "--- hA's egress filter: only new TCP connections to port 443 leave hA"
  egress443_ruleset | ip netns exec "$NS_HA" nft -f - || fail "nft rejected hA's egress filter"
  ip netns exec "$NS_HA" nft list table inet r443 >>"$LOGS/topology.log" 2>&1 || true
  # Nothing in hA has opened a TCP connection yet. (dropped may already count
  # hA's own IPv6 router solicitations: eth0 sends them on its own.)
  tcp443="$(egress_counter tcp443)"
  tcp7423="$(egress_counter tcp7423)"
  if [[ "$tcp443" -ne 0 || "$tcp7423" -ne 0 ]]; then
    fail "hA's TCP egress counters are not 0 before A starts (tcp443=$tcp443 tcp7423=$tcp7423)"
  fi

  echo "--- services: A (R's 7423, then its 443 fallback), B (R's 7423), each listening on 7423"
  ip netns exec "$NS_HA" "$NODE" service --data-dir "$a" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$v7423" --p2p-relay "$v443" --timeout-secs 0 \
    >"$LOGS/a.service.log" 2>&1 &
  a_pid=$!
  PIDS+=("$a_pid")
  ip netns exec "$NS_HB" "$NODE" service --data-dir "$b" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$v7423" --timeout-secs 0 \
    >"$LOGS/b.service.log" 2>&1 &
  b_pid=$!
  PIDS+=("$b_pid")
  wait_line "$LOGS/a.service.log" "$LINE_RESERVED" "$ONLY443_RESERVE" "$a_pid" "$relay_pid"
  tcp443="$(egress_counter tcp443)"
  dropped="$(egress_counter dropped)"
  tcp7423="$(egress_counter tcp7423)"
  echo "A reserved: egress counters tcp443=$tcp443 dropped=$dropped (tcp7423=$tcp7423)"
  if [[ "$tcp443" -eq 0 ]]; then
    fail "A reserved, yet hA's filter passed no new connection to port 443 (tcp443=0)"
  fi
  if [[ "$dropped" -eq 0 || "$tcp7423" -eq 0 ]]; then
    fail "hA's filter dropped no packet to R's 7423: A did not try it first (dropped=$dropped tcp7423=$tcp7423)"
  fi
  wait_line "$LOGS/b.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$b_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"

  echo "--- pin each other (verified contacts only use p2p)"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"
  wait_line "$LOGS/a.service.log" "$LINE_GATE_ONE" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_GATE_ONE" 30 "$b_pid"

  echo "--- A -> B and B -> A over --carrier p2p: relayed (A through R's 443)"
  send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-1" a2b-1
  inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-1" b-1
  require_path "$PATH_RELAYED" "the message A -> B"
  send_check "$NS_HB" "$b" alice "hello-$MODE-b2a-1" b2a-1
  inbox_once "$NS_HA" "$a" "hello-$MODE-b2a-1" a-1
  require_path "$PATH_RELAYED" "the message B -> A"
  wait_dcutr "$DCUTR_OBSERVE" "$a_pid" "$b_pid"
  if dcutr_seen; then
    fail "a service logged '$LINE_DCUTR': A's filter lets only TCP 443 out, so no candidate can work"
  fi
  tcp443="$(egress_counter tcp443)"
  dropped="$(egress_counter dropped)"
  tcp7423="$(egress_counter tcp7423)"
  echo "only443, dedicated relay: A reserved over R's TCP 443 fallback, relayed both ways, no DCUtR upgrade (egress tcp443=$tcp443 dropped=$dropped tcp7423=$tcp7423)"
  run_only443_friend
  echo "RESULT only443: A reserved over R's TCP 443 fallback and over a friend relay's TCP 443 (its only offered address), relayed both ways each time, no DCUtR upgrade, nothing sent to port 7427 (egress tcp443=$tcp443 tcp7427=$tcp7427)"
}

# The only443 run's operator O: hO on WAN.26.10 (no NAT), routed by pub.
setup_only443_operator() {
  ip netns add "$NS_HO"
  ip -n "$NS_HO" link set lo up
  ip -n "$NS_PUB" link add wo type veth peer name eth0 netns "$NS_HO"
  ip -n "$NS_PUB" addr add "$WAN.26.1/24" dev wo
  ip -n "$NS_PUB" link set wo up
  ip -n "$NS_HO" addr add "$WAN.26.10/24" dev eth0
  ip -n "$NS_HO" link set eth0 up
  ip -n "$NS_HO" route add default via "$WAN.26.1"
}

# only443_offered NS DIR NAME: until NAME's doctor says its first relay is
# the one set by hand (R) and its second one picked from an offer, reserved.
only443_offered() {
  local ns=$1 dir=$2 name=$3 pid=$4 deadline out="$LOGS/$3.doctor.out"
  deadline=$((SECONDS + RESERVE_WAIT))
  while :; do
    in_ns "$ns" "$RAVEN" --data-dir "$dir" doctor >"$out" 2>&1 || true
    if grep -Fq 'relay_1_source=manual relay_2_source=offer' "$out" \
      && grep -Eq '^ *relay_2: reserved ' "$out"; then
      return 0
    fi
    ((SECONDS < deadline)) || fail "$name holds no reserved relay picked from O's offer within ${RESERVE_WAIT}s"
    require_alive "$pid"
    sleep 1
  done
}

# The only443 run's friend relay run (Phase 2 items 2-3; uses run_only443's
# locals): operator O relays for A and B with a key of its own on 7427 and,
# with relay_also_443, on TCP 443, and offers its 443 address only. A (its
# egress filter still on) and B start over with friend relays and route
# hints on, keeping R; they reach O through R, and O's route hints carry the
# offer: each reserves on O (A over 443). After a message each way through
# R (their route hints name O now), R stops, and A -> B and B -> A are
# relayed through O. hA's filter counted new connections to 443
# (tcp443 > 0) and none to 7427 (tcp7427 = 0).
run_only443_friend() {
  local o o_fp o_card o_pid o_relay a2_pid b2_pid pid deadline name log
  echo "--- friend relay run: operator O ($WAN.26.10, no NAT) offers its friend relay on TCP 443 only"
  # This run's subshell only, from here on: friend relays and route hints.
  export RAVEN_LAB_ROUTE_HINTS=1 RAVEN_LAB_FRIEND_RELAY=1
  setup_only443_operator
  o="$run_dir/o"
  mkdir -p "$o"
  chmod 700 "$o"
  raven_init "$NS_HO" "$o" o
  o_fp="$INIT_FP"
  raven_card "$NS_HO" "$o" o
  o_card="$CARD"
  in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$o_card" >>"$LOGS/relay.allow.out" 2>&1 \
    || fail "raven relay allow (O) failed"
  in_ns "$NS_HO" "$RAVEN" --data-dir "$o" relay offer on --also-443 \
    --external "/ip4/$WAN.26.10/tcp/443" >"$LOGS/o.offer.out" 2>&1 || fail "raven relay offer on (O) failed"
  ip netns exec "$NS_HO" "$NODE" service --data-dir "$o" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$v7423" --timeout-secs 0 \
    >"$LOGS/o.service.log" 2>&1 &
  o_pid=$!
  PIDS+=("$o_pid")
  wait_line "$LOGS/o.service.log" "$LINE_FRIEND_UP" "$RELAY_WAIT" "$o_pid" "$relay_pid"
  if ! grep -F -- "$LINE_FRIEND_UP" "$LOGS/o.service.log" | grep -Fq 'tcp ports 7427,443;'; then
    fail "O's friend relay does not listen on TCP 7427 and 443"
  fi
  wait_line "$LOGS/o.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$o_pid" "$relay_pid"
  wait_ipc "$NS_HO" "$o" 30 "$o_pid"
  o_relay=""
  deadline=$((SECONDS + RELAY_WAIT))
  until [[ "$o_relay" =~ ^[1-9A-HJ-NP-Za-km-z]+$ ]]; do
    ((SECONDS < deadline)) || fail "O's friend relay wrote no base58 peer_id within ${RELAY_WAIT}s"
    sleep 0.5
    o_relay="$(relay_peer_id "$o/friend_relay/relay_status.json")"
  done

  echo "--- A and B start over with friend relays on (A's filter stays, both keep R)"
  for pid in "$a_pid" "$b_pid"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  deadline=$((SECONDS + 15))
  while kill -0 "$a_pid" 2>/dev/null || kill -0 "$b_pid" 2>/dev/null; do
    ((SECONDS < deadline)) || fail "A or B did not stop within 15 s"
    sleep 0.2
  done
  ip netns exec "$NS_HA" "$NODE" service --data-dir "$a" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$v7423" --p2p-relay "$v443" --timeout-secs 0 \
    >"$LOGS/a2.service.log" 2>&1 &
  a2_pid=$!
  PIDS+=("$a2_pid")
  ip netns exec "$NS_HB" "$NODE" service --data-dir "$b" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen 0.0.0.0:7423 --p2p-relay "$v7423" --timeout-secs 0 \
    >"$LOGS/b2.service.log" 2>&1 &
  b2_pid=$!
  PIDS+=("$b2_pid")
  wait_line "$LOGS/a2.service.log" "$LINE_RESERVED" "$ONLY443_RESERVE" "$a2_pid" "$relay_pid"
  wait_line "$LOGS/b2.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$b2_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a2_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b2_pid"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$o_card" \
    --petname otto --tag otto --verify-fp "$o_fp" >>"$LOGS/a.contact.out" 2>&1 || fail "A contact add otto failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$o_card" \
    --petname otto --tag otto --verify-fp "$o_fp" >>"$LOGS/b.contact.out" 2>&1 || fail "B contact add otto failed"
  in_ns "$NS_HO" "$RAVEN" --data-dir "$o" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >>"$LOGS/o.contact.out" 2>&1 || fail "O contact add alice failed"
  in_ns "$NS_HO" "$RAVEN" --data-dir "$o" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >>"$LOGS/o.contact.out" 2>&1 || fail "O contact add bob failed"
  wait_line "$LOGS/a2.service.log" "$LINE_GATE_TWO" 30 "$a2_pid"
  wait_line "$LOGS/b2.service.log" "$LINE_GATE_TWO" 30 "$b2_pid"
  wait_line "$LOGS/o.service.log" "$LINE_GATE_TWO" 30 "$o_pid"
  for name in tcp443 dropped tcp7423 tcp7427; do
    ip netns exec "$NS_HA" nft reset counter inet r443 "$name" >/dev/null \
      || fail "cannot reset hA's egress counter $name"
  done

  echo "--- A -> O and B -> O through R: O's route hints carry its offer, and both reserve on it"
  send_check "$NS_HA" "$a" otto "hello-$MODE-a2o" a2o
  send_check "$NS_HB" "$b" otto "hello-$MODE-b2o" b2o
  only443_offered "$NS_HA" "$a" a "$a2_pid"
  only443_offered "$NS_HB" "$b" b "$b2_pid"

  echo "--- A -> B and B -> A through R: their route hints name O now"
  send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-2" a2b-2
  inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-2" b-2
  send_check "$NS_HB" "$b" alice "hello-$MODE-b2a-2" b2a-2
  inbox_once "$NS_HA" "$a" "hello-$MODE-b2a-2" a-2
  deadline=$((SECONDS + 30))
  until grep -Fq "/tcp/443/p2p/$o_relay" "$a/learned_routes.json" 2>/dev/null \
    && grep -Fq "/tcp/443/p2p/$o_relay" "$b/learned_routes.json" 2>/dev/null; do
    ((SECONDS < deadline)) || fail "A and B did not learn each other's relay on O within 30 s"
    sleep 0.5
  done

  echo "--- R stops: A and B reach each other only through O's TCP 443"
  kill -TERM "$relay_pid" 2>/dev/null || true
  send_check "$NS_HA" "$a" bob "hello-$MODE-a2b-3" a2b-3
  inbox_once "$NS_HB" "$b" "hello-$MODE-a2b-3" b-3
  require_path "$PATH_RELAYED" "the message A -> B through O"
  send_check "$NS_HB" "$b" alice "hello-$MODE-b2a-3" b2a-3
  inbox_once "$NS_HA" "$a" "hello-$MODE-b2a-3" a-3
  require_path "$PATH_RELAYED" "the message B -> A through O"
  tcp443="$(egress_counter tcp443)"
  tcp7427="$(egress_counter tcp7427)"
  echo "friend relay run: egress tcp443=$tcp443 tcp7427=$tcp7427"
  if [[ "$tcp443" -eq 0 ]]; then
    fail "A was relayed through O, yet hA's filter passed no new connection to port 443"
  fi
  if [[ "$tcp7427" -ne 0 ]]; then
    fail "A sent $tcp7427 packets to port 7427, an address O never offered"
  fi
  for log in "$LOGS/a2.service.log" "$LOGS/b2.service.log" "$LOGS/o.service.log"; do
    if grep -q '12D3Koo' "$log"; then
      fail "$(basename "$log") names a PeerId"
    fi
  done
}

# ---- the lan runs (Phase 3 items 1-2, the LAN listener on every interface
# and the LAN beacon; advisory) ---------------------------------------------

# setup_lan_net FAMILY: an offline LAN: one bridge br0 in the switch
# namespace sw, no router and no default route, hA and hB plugged into it
# (ports pa and pb). FAMILY v4: hA $LAN_OLD.2/24 and hB $LAN_OLD.3/24, with
# their IPv6 link-local addresses; ll: IPv6 link-local only, no IPv4 at all
# (a cable with no DHCP server). Duplicate address detection is off, so a
# link-local address works as soon as its link is up.
setup_lan_net() {
  local family=$1 ns
  for ns in "$NS_SW" "$NS_HA" "$NS_HB"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_dad=0
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.accept_dad=0
  done
  ip -n "$NS_SW" link add br0 type bridge
  ip -n "$NS_SW" link set br0 up
  lan_plug "$NS_HA" pa
  lan_plug "$NS_HB" pb
  if [[ "$family" == "v4" ]]; then
    ip -n "$NS_HA" addr add "$LAN_OLD.2/24" dev eth0
    ip -n "$NS_HB" addr add "$LAN_OLD.3/24" dev eth0
  fi
  for ns in "$NS_HA" "$NS_HB"; do
    if [[ -n "$(ip -n "$ns" route show default 2>/dev/null)" ]]; then
      fail "$ns has a default route: this LAN must have none"
    fi
  done
  {
    echo "== $MODE: one bridge, no router, no default route ($family)"
    ip -n "$NS_HA" addr show dev eth0
    ip -n "$NS_HB" addr show dev eth0
  } >"$LOGS/topology.log" 2>&1
}

# lan_plug NS PORT: a veth from NS (eth0, up) to port PORT of br0 in sw.
lan_plug() {
  ip -n "$NS_SW" link add "$2" type veth peer name eth0 netns "$1"
  ip -n "$NS_SW" link set "$2" master br0
  ip -n "$NS_SW" link set "$2" up
  ip -n "$1" link set eth0 up
}

# setup_lan_router: lan-nonlocal's routed network: a router rL (no NAT,
# forwarding on) with a port on br0 ($LAN_OLD.1/24, port pr) and a link to
# hX on the global-looking $WAN.30.0/24 (hX .10, its default route via rL).
# hA reaches that network through rL by a route, not a default route.
setup_lan_router() {
  local ns
  for ns in "$NS_RL" "$NS_HX"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip -n "$NS_SW" link add pr type veth peer name lan netns "$NS_RL"
  ip -n "$NS_SW" link set pr master br0
  ip -n "$NS_SW" link set pr up
  ip -n "$NS_RL" addr add "$LAN_OLD.1/24" dev lan
  ip -n "$NS_RL" link set lan up
  ip -n "$NS_RL" link add wan type veth peer name eth0 netns "$NS_HX"
  ip -n "$NS_RL" addr add "$WAN.30.1/24" dev wan
  ip -n "$NS_RL" link set wan up
  ip netns exec "$NS_RL" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$NS_HX" addr add "$WAN.30.10/24" dev eth0
  ip -n "$NS_HX" link set eth0 up
  ip -n "$NS_HX" route add default via "$WAN.30.1"
  ip -n "$NS_HA" route add "$WAN.30.0/24" via "$LAN_OLD.1"
  {
    echo "== $MODE: router rL ($LAN_OLD.1, $WAN.30.1), hX $WAN.30.10; hA's routes:"
    ip -n "$NS_HA" route show
  } >>"$LOGS/topology.log" 2>&1
}

# lan_start NS DIR NAME: `raven-node service` in NS with `--lan-listen auto`
# (0.0.0.0:7420 and [::]:7420 inside NS, local sources only), waited for
# until its listener, IPC and LAN beacon are up. Sets LAN_PID.
LAN_PID=""
lan_start() {
  local ns=$1 dir=$2 log="$LOGS/$3.service.log"
  ip netns exec "$ns" "$NODE" service --data-dir "$dir" --lan-listen auto \
    --ble-listen 127.0.0.1:0 --timeout-secs 0 >"$log" 2>&1 &
  LAN_PID=$!
  PIDS+=("$LAN_PID")
  wait_line "$log" "$LINE_LAN_AUTO" "$LAN_UP_WAIT" "$LAN_PID"
  wait_ipc "$ns" "$dir" 30 "$LAN_PID"
  wait_line "$log" "$LINE_BEACON_ON" "$LAN_UP_WAIT" "$LAN_PID"
}

# lan_pin NS DIR TAG ADDR PUB FP: TAG (also its petname) pinned by its
# security code, with no address: a card with none.
lan_pin() {
  in_ns "$1" "$RAVEN" --data-dir "$2" contact add --address "$4" --pub-hex "$5" \
    --petname "$3" --tag "$3" --verify-fp "$6" >>"$LOGS/contacts.out" 2>&1 \
    || fail "contact add $3 in $2 failed"
}

# lan_set NS DIR TAG DIAL: TAG's saved LAN address becomes DIAL.
lan_set() {
  in_ns "$1" "$RAVEN" --data-dir "$2" contact set-addr "@$3" --lan "$4" \
    >>"$LOGS/contacts.out" 2>&1 || fail "contact set-addr @$3 --lan $4 in $2 failed"
}

# lan_send NS DIR TAG TEXT LABEL: `raven send --contact @TAG` (carrier
# auto), TEXT on stdin, its output in LOGS/LABEL.send.out. Sets LAN_SEND to
# the outcome its own lines give: DELIVERED, QUEUED, NOT_SENT or OTHER.
LAN_SEND=""
lan_send() {
  local ns=$1 dir=$2 tag=$3 text=$4 label=$5 out
  out="$LOGS/$label.send.out"
  printf '%s\n' "$text" | timeout "$SEND_TIMEOUT" ip netns exec "$ns" "$RAVEN" \
    --data-dir "$dir" send --contact "@$tag" >"$out" 2>&1 || true
  LAN_SEND="$(awk '
    { sub(/^[[:space:]]+/, "") }
    /^status delivered/ && /confirmed receipt/ { print "DELIVERED"; found = 1; exit }
    { line[NR] = $0 }
    END {
      if (found) exit
      for (i = 1; i <= NR; i++) {
        if (line[i] ~ /^not delivered yet/) { print "QUEUED"; exit }
        if (line[i] ~ /^NOT SENT/) { print "NOT_SENT"; exit }
      }
      print "OTHER"
    }' "$out")"
  echo "$label: $LAN_SEND"
}

# lan_expect WANT WHAT: the last lan_send ended WANT.
lan_expect() {
  if [[ "$LAN_SEND" != "$1" ]]; then
    fail "$2 ended $LAN_SEND, not $1"
  fi
}

# lan_found LABEL PATTERN: the send LABEL dialled a beacon find matching the
# extended regex PATTERN (its `LAN dial ... (found on your network now` line).
lan_found() {
  if ! grep -F -- "$TEXT_FOUND" "$LOGS/$1.send.out" | grep -Eq -- "$2"; then
    fail "send $1 dialled no beacon find like '$2'"
  fi
}

# lan_inbox_count NS DIR TEXT TAG: how many times TEXT is in the inbox, in
# LAN_INBOX_N (not printed: a `fail` in a command substitution would end
# only that subshell). A `raven inbox` that fails fails the run, as in
# inbox_once: it is never read as 0 messages.
LAN_INBOX_N=0
lan_inbox_count() {
  local out="$LOGS/$4.inbox.out"
  in_ns "$1" "$RAVEN" --data-dir "$2" inbox >"$out" 2>&1 || fail "raven inbox ($4) failed"
  LAN_INBOX_N="$(grep -cF -- "$3" "$out" || true)"
}

# lan_nearby NS DIR: "SENT ANSWERED", the beacon's queries sent and
# answered in the last 10 min as `raven lan status` says them ("- -"
# without its nearby search row).
lan_nearby() {
  in_ns "$1" "$RAVEN" --data-dir "$2" lan status 2>/dev/null \
    | sed -n 's/.*nearby search.*last 10 min: \([0-9][0-9]*\) sent, \([0-9][0-9]*\) answered.*/\1 \2/p' \
    | head -n 1 | grep . || echo "- -"
}

# raw_read NS HOST PORT SECS: a plain TCP connection from NS that sends
# nothing: "closed N" when the other side closed it within SECS after N
# bytes (a reset too), "open" when it stayed open, "refused" when nothing
# accepted it.
raw_read() {
  ip netns exec "$1" python3 - "$2" "$3" "$4" <<'PY'
import socket
import sys

host, port, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
try:
    s = socket.create_connection((host, port), timeout=5)
except OSError:
    print('refused')
    sys.exit(0)
s.settimeout(secs)
got = 0
try:
    while True:
        data = s.recv(256)
        if not data:
            break
        got += len(data)
except socket.timeout:
    print('open')
    sys.exit(0)
except OSError:
    pass
print(f'closed {got}')
PY
}

# lan_capture_start: tcpdump on br0, every UDP datagram the bridge carries,
# into RUN_DIR/bridge.pcap (out of the logs: binary); nothing, and a note,
# when this runner has no tcpdump. Sets CAPTURE_PID.
CAPTURE_PID=""
lan_capture_start() {
  if ! command -v tcpdump >/dev/null 2>&1; then
    echo "note: no tcpdump on this runner: the bridge capture is not checked"
    return 0
  fi
  ip netns exec "$NS_SW" tcpdump -i br0 -U -n -w "$run_dir/bridge.pcap" udp \
    >"$LOGS/tcpdump.log" 2>&1 &
  CAPTURE_PID=$!
  PIDS+=("$CAPTURE_PID")
  wait_line "$LOGS/tcpdump.log" "listening on" 10 "$CAPTURE_PID"
}

# lan_capture_check A_PUB B_PUB A_ADDR B_ADDR BROADCAST...: with tcpdump
# stopped, every UDP datagram on the bridge must be the beacon's: to port
# 7420, 160..=191 bytes (a query) or 48..=63 (an answer; Phase 6b W-B3: a
# random tail of up to 31 or 15 bytes), to 239.255.74.20, ff02::8000:7420
# or one of the subnet BROADCAST addresses; at least one query and one
# answer; no 4-byte window the same in the first 160 bytes of every
# distinct query, nor in the first 48 of every distinct answer; no key (raw
# or hex), rvn1 address, 'rvn1' or 'raven' in any of them.
lan_capture_check() {
  if [[ -z "$CAPTURE_PID" ]]; then
    return 0
  fi
  kill -INT "$CAPTURE_PID" 2>/dev/null || true
  wait "$CAPTURE_PID" 2>/dev/null || true
  if ! python3 - "$run_dir/bridge.pcap" "$@" >"$LOGS/capture.out" 2>&1 <<'PY'
import ipaddress
import struct
import sys

path, a_pub, b_pub, a_addr, b_addr, *broadcast = sys.argv[1:]
allowed = {'239.255.74.20', 'ff02::8000:7420', *broadcast}
raw = open(path, 'rb').read()
if raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
    end = '<'
elif raw[:4] in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
    end = '>'
else:
    sys.exit('capture: not a pcap file')
link = struct.unpack(end + 'I', raw[20:24])[0]
seen, bad, off = [], [], 24
while off + 16 <= len(raw):
    incl = struct.unpack(end + 'I', raw[off + 8:off + 12])[0]
    frame = raw[off + 16:off + 16 + incl]
    off += 16 + incl
    if link == 1:
        kind, ip = struct.unpack('>H', frame[12:14])[0], frame[14:]
    elif link == 113:
        kind, ip = struct.unpack('>H', frame[14:16])[0], frame[16:]
    else:
        sys.exit(f'capture: link type {link}')
    if kind == 0x0800:
        proto, dst, l4 = ip[9], str(ipaddress.IPv4Address(ip[16:20])), ip[(ip[0] & 15) * 4:]
    elif kind == 0x86DD:
        proto, dst, l4 = ip[6], str(ipaddress.IPv6Address(ip[24:40])), ip[40:]
    else:
        continue
    if proto != 17:
        continue
    dport, ulen = struct.unpack('>HH', l4[2:6])
    data = l4[8:ulen]
    seen.append((dst, data))
    if dport != 7420 or dst not in allowed or not (160 <= len(data) <= 191 or 48 <= len(data) <= 63):
        bad.append(f'{dst} port {dport}, {len(data)} bytes')


def constant(group):
    if len(group) < 2:
        return []
    first, *rest = list(group)
    return [i for i in range(len(first) - 3) if all(g[i:i + 4] == first[i:i + 4] for g in rest)]


queries = {d for _, d in seen if 160 <= len(d) <= 191}
answers = {d for _, d in seen if 48 <= len(d) <= 63}
words = [w.lower().encode() for w in (a_pub, b_pub, a_addr, b_addr, 'rvn1', 'raven')]
keys = [bytes.fromhex(a_pub), bytes.fromhex(b_pub)]
named = sorted({w.decode()[:12] for _, d in seen for w in words if w in d.lower()}
               | {k.hex()[:12] for _, d in seen for k in keys if k in d})
print(f'capture: {len(seen)} UDP datagrams, {len(queries)} distinct queries, '
      f'{len(answers)} distinct answers, to {sorted({x for x, _ in seen})}')
problems = []
if bad:
    problems.append(f'not the beacon: {bad[:5]}')
if not queries or not answers:
    problems.append('no query or no answer')
heads = ({d[:160] for d in queries}, {d[:48] for d in answers})
if constant(heads[0]) or constant(heads[1]):
    problems.append(f'constant windows: queries {constant(heads[0])}, answers {constant(heads[1])}')
if named:
    problems.append(f'in the clear: {named}')
if problems:
    sys.exit('capture: ' + '; '.join(problems))
PY
  then
    fail "the bridge capture holds more than the beacon's datagrams: $(tail -n 1 "$LOGS/capture.out")"
  fi
  cat "$LOGS/capture.out"
}

# run_lan CASE: one lan-* run (see the header), with this run's own lab
# switches.
run_lan() {
  local run_dir a b a_pid b_pid a_addr a_pub a_fp b_addr b_pub b_fp family=v4 line r
  MODE=$1
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  # This run's switches only (its own subshell): the LAN listener on every
  # interface (`--lan-listen auto`) and the LAN beacon, each behind its lab
  # unlock while LAN_AUTO_LISTEN_PRODUCTION_ENABLED and
  # LAN_BEACON_PRODUCTION_ENABLED stay false. No p2p host runs here, so no
  # p2p lab unlock either.
  export RAVEN_LAB_LAN_AUTO=1 RAVEN_LAB_LAN_BEACON=1
  unset RAVEN_LAB_TEST_A
  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  a="$run_dir/a"
  b="$run_dir/b"
  mkdir -p "$LOGS" "$a" "$b"
  chmod 700 "$a" "$b"
  if [[ "$MODE" == "lan-ll" ]]; then
    family=ll
  fi
  echo "=== $MODE run: one bridge, no router, no default route (dirs under $run_dir) ==="
  setup_lan_net "$family"
  if [[ "$MODE" == "lan-move" ]]; then
    lan_capture_start
  fi
  raven_init "$NS_HA" "$a" a
  a_addr="$INIT_ADDR"
  a_pub="$INIT_PUB"
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_addr="$INIT_ADDR"
  b_pub="$INIT_PUB"
  b_fp="$INIT_FP"
  lan_start "$NS_HA" "$a" a
  a_pid="$LAN_PID"
  if [[ "$MODE" == "lan-nonlocal" ]]; then
    run_lan_nonlocal
    return 0
  fi
  lan_start "$NS_HB" "$b" b
  b_pid="$LAN_PID"
  # Cards with no address: only the beacon can say where the other one is.
  lan_pin "$NS_HA" "$a" bob "$b_addr" "$b_pub" "$b_fp"
  lan_pin "$NS_HB" "$b" alice "$a_addr" "$a_pub" "$a_fp"
  # Each beacon reads its contact book again within a second of a change.
  sleep 2
  case "$MODE" in
    lan-move) run_lan_move ;;
    lan-ll) run_lan_ll ;;
    lan-isolated) run_lan_isolated ;;
  esac
}

# run_lan_move: lan-move's steps (uses run_lan's locals).
run_lan_move() {
  local t0 ns host pair
  echo "--- the first message each way, between cards with no address"
  lan_send "$NS_HA" "$a" bob "lan-move-first-a2b" first-a2b
  lan_expect DELIVERED "the first A -> B"
  lan_found first-a2b "LAN dial $LAN_OLD\.3:7420 "
  inbox_once "$NS_HB" "$b" "lan-move-first-a2b" b-first
  lan_send "$NS_HB" "$b" alice "lan-move-first-b2a" first-b2a
  lan_expect DELIVERED "the first B -> A"
  inbox_once "$NS_HA" "$a" "lan-move-first-b2a" a-first
  echo "--- each saves the other's address; both leave and a message each way waits"
  lan_set "$NS_HA" "$a" bob "$LAN_OLD.3:7420"
  lan_set "$NS_HB" "$b" alice "$LAN_OLD.2:7420"
  ip -n "$NS_HA" link set eth0 down
  ip -n "$NS_HB" link set eth0 down
  lan_send "$NS_HA" "$a" bob "lan-move-queued-a2b" queued-a2b
  lan_expect QUEUED "A -> B while both are away"
  lan_send "$NS_HB" "$b" alice "lan-move-queued-b2a" queued-b2a
  lan_expect QUEUED "B -> A while both are away"
  echo "--- both come back renumbered to $LAN_NEW.0/24"
  for pair in "$NS_HA:2" "$NS_HB:3"; do
    ns="${pair%:*}"
    host="${pair##*:}"
    ip -n "$ns" addr flush dev eth0 scope global
    ip -n "$ns" addr add "$LAN_NEW.$host/24" dev eth0
    ip -n "$ns" link set eth0 up
  done
  t0=$SECONDS
  inbox_once "$NS_HB" "$b" "lan-move-queued-a2b" b-queued "$LAN_DELIVER"
  inbox_once "$NS_HA" "$a" "lan-move-queued-b2a" a-queued "$(left $((t0 + LAN_DELIVER)))"
  echo "queued messages delivered both ways $((SECONDS - t0))s after the renumbering"
  require_alive "$a_pid" "$b_pid"
  # A find is never saved: the books still name the old addresses.
  grep -Fq -- "$LAN_OLD.3:7420" "$a/contacts.json" || fail "A's book no longer names $LAN_OLD.3:7420"
  grep -Fq -- "$LAN_OLD.2:7420" "$b/contacts.json" || fail "B's book no longer names $LAN_OLD.2:7420"
  lan_capture_check "$a_pub" "$b_pub" "$a_addr" "$b_addr" "$LAN_OLD.255" "$LAN_NEW.255"
  echo "RESULT lan-move: the first messages through the beacon with no address saved; after both renumbered, the queued messages both ways within ${LAN_DELIVER}s; the bridge carried only the beacon's datagrams"
}

# run_lan_ll: lan-ll's steps (uses run_lan's locals).
run_lan_ll() {
  echo "--- IPv6 link-local only: the first message each way"
  lan_send "$NS_HA" "$a" bob "lan-ll-a2b" ll-a2b
  lan_expect DELIVERED "A -> B over link-local"
  lan_found ll-a2b 'LAN dial \[fe80:[0-9a-f:]*%eth0\]:7420 '
  inbox_once "$NS_HB" "$b" "lan-ll-a2b" b-ll
  lan_send "$NS_HB" "$b" alice "lan-ll-b2a" ll-b2a
  lan_expect DELIVERED "B -> A over link-local"
  inbox_once "$NS_HA" "$a" "lan-ll-b2a" a-ll
  require_alive "$a_pid" "$b_pid"
  echo "RESULT lan-ll: delivered both ways through a [fe80::...%eth0] find, the zone kept"
}

# run_lan_isolated: lan-isolated's steps (uses run_lan's locals).
run_lan_isolated() {
  local books sent0 answered0 sent1 answered1
  echo "--- a first message through the beacon, then client isolation"
  lan_send "$NS_HA" "$a" bob "lan-isolated-first" iso-first
  lan_expect DELIVERED "the first A -> B"
  inbox_once "$NS_HB" "$b" "lan-isolated-first" b-first
  books="$(cat "$a/contacts.json" "$b/contacts.json" | sha256sum)"
  read -r sent0 answered0 <<<"$(lan_nearby "$NS_HA" "$a")"
  # An isolated port reaches only ports that are not isolated: both are.
  ip netns exec "$NS_SW" bridge link set dev pa isolated on
  ip netns exec "$NS_SW" bridge link set dev pb isolated on
  lan_send "$NS_HA" "$a" bob "lan-isolated-waits" iso-waits
  lan_expect QUEUED "A -> B behind client isolation"
  sleep "$LAN_ISOLATED_WATCH"
  read -r sent1 answered1 <<<"$(lan_nearby "$NS_HA" "$a")"
  echo "A's beacon, last 10 min: $sent0 -> $sent1 sent, $answered0 -> $answered1 answered"
  if [[ ! "$sent0$sent1$answered0$answered1" =~ ^[0-9]+$ ]]; then
    fail "A's nearby search row has no counts"
  fi
  if ((sent1 <= sent0)); then
    fail "A's beacon asked for B no more while isolated"
  fi
  if ((answered1 != answered0)); then
    fail "an answer crossed the isolated bridge"
  fi
  lan_inbox_count "$NS_HB" "$b" "lan-isolated-waits" b-isolated
  if ((LAN_INBOX_N != 0)); then
    fail "the message crossed the isolated bridge"
  fi
  if [[ "$(cat "$a/contacts.json" "$b/contacts.json" | sha256sum)" != "$books" ]]; then
    fail "a contact book changed"
  fi
  require_alive "$a_pid" "$b_pid"
  echo "RESULT lan-isolated: the beacon unanswered, the message queued, nothing else changed"
}

# run_lan_nonlocal: lan-nonlocal's steps (uses run_lan's locals; only A's
# node runs).
run_lan_nonlocal() {
  setup_lan_router
  echo "--- a plain connection from B (on-link), then from hX ($WAN.30.10, routed)"
  r="$(raw_read "$NS_HB" "$LAN_OLD.2" 7420 2)"
  [[ "$r" == "open" ]] || fail "B's plain connection (on-link) ended '$r', not open"
  r="$(raw_read "$NS_HX" "$LAN_OLD.2" 7420 10)"
  [[ "$r" == "closed 0" ]] || fail "hX's plain connection (routed, not local) ended '$r', not closed before a byte"
  wait_line "$LOGS/a.service.log" "${LINE_NON_LOCAL}1 since start" 10 "$a_pid"
  line="$(grep -F -- "$LINE_NON_LOCAL" "$LOGS/a.service.log" | head -n 1)"
  if [[ "$line" == *"$WAN.30."* || "$line" == *"$LAN_OLD."* ]]; then
    fail "the line names an address: $line"
  fi
  echo "RESULT lan-nonlocal: a routed non-local source closed before a byte and counted (no address logged); an on-link one admitted"
}

# ---- the port-mapping runs (Phase 4, RAVEN_PORT_MAPPING_V1; advisory) -------

# rB is the home router's NAT-PMP/PCP server: miniupnpd from the apt package
# miniupnpd-nftables (owner decision O4-15: the lab job only, nothing ships
# with it), with UPnP off and secure mode on, in rB's namespace only. Its
# nftables rules go to a table of this script's (raven_upnp), hooked
# before raven_nat; raven_nat's forward chain accepts what was DNATed, and
# rB's own table raven_pcp counts the forwarded packets to 7423 that came
# in from the WAN through a mapping (wan_dnat_7423). The v6pin run's IPv6
# filter on rB is raven_upnp's forward chain itself (miniupnpd's pinholes,
# then outbound and replies only), so that a pinhole is the one way in.
LINE_PCP_MAPPED='raven-node p2p: router port mapped (PCP, port '
LINE_PCP_CGN='raven-node p2p: router is behind another NAT (carrier NAT): no mapping'
LINE_PCP_PINHOLE='raven-node p2p: IPv6 pinhole open on the router (PCP)'
# How long B may take to map (the probe ends after 3.75 s), and to delete
# its mapping once it saw the carrier NAT.
PCP_WAIT=30
PCP_DELETE_WAIT=15
# The v6pin run's IPv6: an unallocated former 6bone prefix, global-looking
# like WAN (2001:db8::/32 is refused by is_global_ipv6) and as unreachable:
# pub has no IPv6 default route (setup_v6 checks it).
V6PIN='3ffe:0:0'

# The pcp-cgn run's topology: the cone one, but rB's WAN (100.64.2.2) sits
# behind the carrier router rC (WAN.2.2, `masquerade random,fully-random`,
# so no hole punch gets past it either).
setup_cgn_net() {
  local ns
  for ns in "$NS_PUB" "$NS_RA" "$NS_RB" "$NS_RC" "$NS_HA" "$NS_HB"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip -n "$NS_PUB" link add wa type veth peer name wan netns "$NS_RA"
  ip -n "$NS_PUB" link add wb type veth peer name wan netns "$NS_RC"
  ip -n "$NS_RC" link add lan type veth peer name wan netns "$NS_RB"
  ip -n "$NS_RA" link add lan type veth peer name eth0 netns "$NS_HA"
  ip -n "$NS_RB" link add lan type veth peer name eth0 netns "$NS_HB"
  ip -n "$NS_PUB" addr add "$WAN.0.1/32" dev lo
  ip -n "$NS_PUB" addr add "$WAN.1.1/24" dev wa
  ip -n "$NS_PUB" addr add "$WAN.2.1/24" dev wb
  ip -n "$NS_PUB" link set wa up
  ip -n "$NS_PUB" link set wb up
  ip netns exec "$NS_PUB" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$NS_RA" addr add "$WAN.1.2/24" dev wan
  ip -n "$NS_RA" addr add 192.168.1.1/24 dev lan
  ip -n "$NS_RA" link set wan up
  ip -n "$NS_RA" link set lan up
  ip -n "$NS_RA" route add default via "$WAN.1.1"
  ip -n "$NS_RC" addr add "$WAN.2.2/24" dev wan
  ip -n "$NS_RC" addr add 100.64.2.1/24 dev lan
  ip -n "$NS_RC" link set wan up
  ip -n "$NS_RC" link set lan up
  ip -n "$NS_RC" route add default via "$WAN.2.1"
  ip -n "$NS_RB" addr add 100.64.2.2/24 dev wan
  ip -n "$NS_RB" addr add 192.168.2.1/24 dev lan
  ip -n "$NS_RB" link set wan up
  ip -n "$NS_RB" link set lan up
  ip -n "$NS_RB" route add default via 100.64.2.1
  ip -n "$NS_HA" addr add 192.168.1.2/24 dev eth0
  ip -n "$NS_HA" link set eth0 up
  ip -n "$NS_HA" route add default via 192.168.1.1
  ip -n "$NS_HB" addr add 192.168.2.2/24 dev eth0
  ip -n "$NS_HB" link set eth0 up
  ip -n "$NS_HB" route add default via 192.168.2.1
  nat_rules "$NS_RA" "masquerade" "$WAN.0.1"
  nat_rules "$NS_RC" "masquerade random,fully-random" "$WAN.0.1"
  nat_rules "$NS_RB" "masquerade" "$WAN.0.1"
  if [[ -n "$(ip -n "$NS_PUB" route show default 2>/dev/null)" ]]; then
    fail "pub has a default route: the simulated Internet ($WAN.0.0/16) must not reach the real one"
  fi
  {
    echo "== pcp-cgn: rA masquerade; rB masquerade on 100.64.2.2 behind rC (masquerade random,fully-random)"
    ip netns exec "$NS_RC" nft list ruleset
  } >"$LOGS/topology.log" 2>&1
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HA" ping -c 1 -W 2 "$WAN.0.1" >>"$LOGS/topology.log" 2>&1 || fail "hA cannot reach R ($WAN.0.1) through rA"
    in_ns "$NS_HB" ping -c 1 -W 2 "$WAN.0.1" >>"$LOGS/topology.log" 2>&1 || fail "hB cannot reach R ($WAN.0.1) through rB and rC"
  fi
  reset_counters
}

# upnp_ruleset: rB's tables for miniupnpd (see above).
upnp_ruleset() {
  cat <<'NFT'
table inet raven_upnp {
  chain forward {
    type filter hook forward priority -5; policy accept;
    jump miniupnpd
    meta nfproto ipv6 ct state established,related accept
    meta nfproto ipv6 iifname "lan" oifname "wan" accept
    meta nfproto ipv6 counter drop
  }
  chain miniupnpd {
  }
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    jump prerouting_miniupnpd
  }
  chain prerouting_miniupnpd {
  }
  chain postrouting {
    type nat hook postrouting priority 99; policy accept;
    jump postrouting_miniupnpd
  }
  chain postrouting_miniupnpd {
  }
}
table ip raven_pcp {
  counter wan_dnat_7423 {
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "wan" ct status dnat tcp dport 7423 counter name "wan_dnat_7423"
    iifname "wan" ct status dnat udp dport 7423 counter name "wan_dnat_7423"
  }
}
table ip6 raven_pin {
  counter wan_v6_7423 {
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "wan" tcp dport 7423 counter name "wan_v6_7423"
    iifname "wan" udp dport 7423 counter name "wan_v6_7423"
  }
}
NFT
}

# miniupnpd_conf DIR: rB's miniupnpd.conf (the run's MODE picks the extras).
miniupnpd_conf() {
  cat <<CONF
ext_ifname=wan
listening_ip=lan
enable_pcp_pmp=yes
enable_upnp=no
secure_mode=yes
lease_file=$1/upnp.leases
upnp_table_name=raven_upnp
upnp_nat_table_name=raven_upnp
upnp_forward_chain=miniupnpd
upnp_nat_chain=prerouting_miniupnpd
upnp_nat_postrouting_chain=postrouting_miniupnpd
CONF
  case "$MODE" in
    # The carrier NAT: serve anyway and report 100.64.2.2, which B must
    # recognise as not routable (miniupnpd refuses a reserved WAN address
    # otherwise).
    pcp-cgn) echo "ext_allow_private_ipv4=yes" ;;
    v6pin) echo "ipv6_listening_ip=$V6PIN:2::1" ;;
  esac
  echo "allow 1024-65535 192.168.2.0/24 1024-65535"
  echo "deny 0-65535 0.0.0.0/0 0-65535"
}

# start_miniupnpd DIR: rB's tables, then miniupnpd in the foreground (its
# log in LOGS, its PID in PIDS). Sets UPNP_PID.
UPNP_PID=""
start_miniupnpd() {
  local dir=$1
  upnp_ruleset | ip netns exec "$NS_RB" nft -f - || fail "nft rejected rB's miniupnpd tables"
  # raven_nat drops what is not a reply: a mapped flow is DNATed first.
  ip netns exec "$NS_RB" nft insert rule ip raven_nat forward ct status dnat accept \
    || fail "cannot let rB forward DNATed flows"
  if [[ "$MODE" == "v6pin" ]]; then
    # setup_v6's IPv6 filter on rB would drop a pinholed flow too:
    # raven_upnp's forward chain is rB's IPv6 filter in this run.
    ip netns exec "$NS_RB" nft delete table ip6 raven_fw || fail "cannot drop rB's raven_fw table"
  fi
  miniupnpd_conf "$dir" >"$dir/miniupnpd.conf"
  cp "$dir/miniupnpd.conf" "$LOGS/miniupnpd.conf"
  ip netns exec "$NS_RB" miniupnpd -d -f "$dir/miniupnpd.conf" -P "$dir/miniupnpd.pid" \
    >"$LOGS/miniupnpd.log" 2>&1 &
  UPNP_PID=$!
  PIDS+=("$UPNP_PID")
  sleep 1
  require_alive "$UPNP_PID"
}

# upnp_dnat_rules: the DNAT rules miniupnpd holds now in rB.
upnp_dnat_rules() {
  local n
  n="$(ip netns exec "$NS_RB" nft list chain inet raven_upnp prerouting_miniupnpd 2>/dev/null \
    | grep -c ' dnat ')" || true
  echo "${n:-0}"
}

# learned_direct_on DIR PUB TEXT: "yes" when DIR's learned_routes.json holds
# a DIRECT address of the contact PUB containing TEXT (`/ip6/<addr>/`).
learned_direct_on() {
  python3 - "$1/learned_routes.json" "$2" "$3" <<'PY' 2>/dev/null || echo no
import json, sys

path, pub, text = sys.argv[1:4]
try:
    entries = json.load(open(path))
except (OSError, ValueError):
    entries = []
hit = any(
    e.get("pub_hex", "").lower() == pub.lower() and any(text in d for d in e.get("direct", []))
    for e in entries
    if isinstance(e, dict)
)
print("yes" if hit else "no")
PY
}

# start_pcp_node NS DIR NAME LISTEN: a service on R (LOGS/NAME.service.log,
# appended to). Sets NODE_PID.
start_pcp_node() {
  ip netns exec "$1" "$NODE" service --data-dir "$2" \
    --lan-listen 127.0.0.1:0 --ble-listen 127.0.0.1:0 \
    --p2p-listen "$4" --p2p-relay "$VIA" --timeout-secs 0 \
    >>"$LOGS/$3.service.log" 2>&1 &
  NODE_PID=$!
  PIDS+=("$NODE_PID")
}

run_pcp() {
  local run_dir a b u relay_pid counter=() a_pid b_pid peer deadline a_card b_card a_fp b_fp b_pub
  local listen="0.0.0.0:7423" want_direct before after dcutr_before n
  MODE=$1
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  # Exit 2 (cannot run here; reported, never fatal: these runs are advisory).
  if ! command -v miniupnpd >/dev/null 2>&1; then
    echo "netns_nat_dcutr: the $MODE run needs miniupnpd (apt-get install --no-install-recommends miniupnpd-nftables)" >&2
    exit 2
  fi
  if [[ "$MODE" == "v6pin" ]] && ! miniupnpd --version 2>&1 | grep -qi 'ipv6'; then
    echo "netns_nat_dcutr: this miniupnpd was built without IPv6 ($(miniupnpd --version 2>&1 | head -n 2 | tr '\n' ' ')): v6pin cannot run here" >&2
    exit 2
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    fail "the $MODE run reads learned_routes.json and IPC Status with python3, which is missing"
  fi
  # This run's subshell only: route hints (B's mapped address reaches A as
  # DIRECT) and the PORT_MAP gate's lab switch (A has no consent, so only
  # B asks its router); v6pin adds the V6_PINHOLE switch.
  export RAVEN_LAB_ROUTE_HINTS=1
  export RAVEN_LAB_PORT_MAP=1
  if [[ "$MODE" == "v6pin" ]]; then
    export RAVEN_LAB_V6_PINHOLE=1
    # Every interface, IPv4 and IPv6 (as v6fw).
    listen="7423"
  fi

  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  R="$run_dir/r"
  a="$run_dir/a"
  b="$run_dir/b"
  u="$run_dir/upnp"
  mkdir -p "$LOGS" "$R" "$a" "$b" "$u"
  chmod 700 "$R" "$a" "$b" "$u"
  echo "=== $MODE run: miniupnpd (NAT-PMP/PCP, UPnP off) on rB (dirs under $run_dir) ==="
  if [[ "$MODE" == "pcp-cgn" ]]; then
    setup_cgn_net
  else
    setup_net "masquerade"
    if [[ "$MODE" == "v6pin" ]]; then
      V6="$V6PIN"
      setup_v6
    fi
  fi
  start_miniupnpd "$u"

  echo "--- relay R in pub on $WAN.0.1:7423"
  ip netns exec "$NS_PUB" "$NODE" relay --data-dir "$R" --listen "$WAN.0.1:7423" \
    >"$LOGS/relay.log" 2>&1 &
  relay_pid=$!
  PIDS+=("$relay_pid")
  peer=""
  deadline=$((SECONDS + RELAY_WAIT))
  while ((SECONDS < deadline)); do
    if [[ -s "$R/relay_status.json" ]]; then
      peer="$(relay_peer_id "$R/relay_status.json")"
      [[ -z "$peer" ]] || break
    fi
    check_hold "$LOGS/relay.log"
    require_alive "$relay_pid"
    sleep 0.2
  done
  [[ -n "$peer" ]] || fail "relay_status.json with a peer_id not written within ${RELAY_WAIT}s"
  VIA="/ip4/$WAN.0.1/tcp/7423/p2p/$peer"

  echo "--- init A and B, cards naming R, both allowed; B's router consent"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  b_pub="$INIT_PUB"
  raven_card "$NS_HA" "$a" a
  a_card="$CARD"
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  for card in "$a_card" "$b_card"; do
    in_ns "$NS_PUB" "$RAVEN" --data-dir "$R" relay allow --card "$card" >>"$LOGS/relay.allow.out" 2>&1 \
      || fail "raven relay allow failed"
  done
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" node upnp on >"$LOGS/b.consent.out" 2>&1 \
    || fail "raven node upnp on (B) failed"
  if [[ "$MODE" == "v6pin" ]]; then
    in_ns "$NS_HB" "$RAVEN" --data-dir "$b" node ipv6-pinhole on >>"$LOGS/b.consent.out" 2>&1 \
      || fail "raven node ipv6-pinhole on (B) failed"
  fi

  echo "--- services: A in hA, B in hB (p2p $listen, relay R)"
  start_pcp_node "$NS_HA" "$a" a "$listen"
  a_pid="$NODE_PID"
  start_pcp_node "$NS_HB" "$b" b "$listen"
  b_pid="$NODE_PID"
  wait_line "$LOGS/a.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$a_pid" "$relay_pid"
  wait_line "$LOGS/b.service.log" "$LINE_RESERVED" "$RESERVE_WAIT" "$b_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  wait_ipc "$NS_HB" "$b" 30 "$b_pid"
  case "$MODE" in
    pcp) wait_line "$LOGS/b.service.log" "$LINE_PCP_MAPPED" "$PCP_WAIT" "$b_pid" "$UPNP_PID" ;;
    pcp-cgn) wait_line "$LOGS/b.service.log" "$LINE_PCP_CGN" "$PCP_WAIT" "$b_pid" "$UPNP_PID" ;;
    v6pin) wait_line "$LOGS/b.service.log" "$LINE_PCP_PINHOLE" "$PCP_WAIT" "$b_pid" "$UPNP_PID" ;;
  esac
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"
  wait_line "$LOGS/a.service.log" "$LINE_GATE_ONE" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_GATE_ONE" 30 "$b_pid"

  if [[ "$MODE" == "pcp-cgn" ]]; then
    echo "--- B saw the carrier NAT: its mapping is deleted, then relayed both ways"
    deadline=$((SECONDS + PCP_DELETE_WAIT))
    while [[ "$(upnp_dnat_rules)" != "0" ]]; do
      ((SECONDS < deadline)) || fail "miniupnpd still holds $(upnp_dnat_rules) DNAT rule(s) after B saw the carrier NAT"
      sleep 0.5
    done
    if grep -Fq -- "$LINE_PCP_MAPPED" "$LOGS/b.service.log"; then
      fail "B reported a mapping behind the carrier NAT"
    fi
    send_check "$NS_HA" "$a" bob "pcp-cgn-a2b" pcp-cgn-a2b
    inbox_once "$NS_HB" "$b" "pcp-cgn-a2b" b-cgn
    require_path "$PATH_RELAYED" "A -> B behind the carrier NAT"
    send_check "$NS_HB" "$b" alice "pcp-cgn-b2a" pcp-cgn-b2a
    inbox_once "$NS_HA" "$a" "pcp-cgn-b2a" a-cgn
    require_path "$PATH_RELAYED" "B -> A behind the carrier NAT"
    pcp_logs_clean
    echo "RESULT pcp-cgn: behind another NAT, miniupnpd's table empty after the delete, relayed both ways"
    return 0
  fi

  # rB's count of what came in through the mapping: FAMILY TABLE NAME.
  if [[ "$MODE" == "v6pin" ]]; then
    want_direct="/ip6/$V6PIN:2::2/"
    counter=(ip6 raven_pin wan_v6_7423)
  else
    want_direct="/ip4/$WAN.2.2/"
    counter=(ip raven_pcp wan_dnat_7423)
  fi
  echo "--- #0 A -> B: A learns B's mapped address (DIRECT $want_direct) from B's route hints"
  send_check "$NS_HA" "$a" bob "$MODE-0" "$MODE-0"
  inbox_once "$NS_HB" "$b" "$MODE-0" b-0
  require_path "$PATH_RELAYED|$PATH_PUNCHED" "#0 A -> B"
  deadline=$((SECONDS + HINTS_LEARN))
  while [[ "$(learned_direct_on "$a" "$b_pub" "$want_direct")" != "yes" ]]; do
    ((SECONDS < deadline)) || fail "A holds no DIRECT address of B with $want_direct within ${HINTS_LEARN}s"
    require_alive "$a_pid" "$b_pid"
    sleep 1
  done

  echo "--- A restarts (no connection left to ride), then #1 A -> B is direct through the router's mapping"
  kill -TERM "$a_pid" 2>/dev/null || true
  wait "$a_pid" 2>/dev/null || true
  dcutr_before="$(dcutr_count)"
  n="$(count_lines "$LOGS/a.service.log" "$LINE_RESERVED")"
  start_pcp_node "$NS_HA" "$a" a "$listen"
  a_pid="$NODE_PID"
  wait_count "$LOGS/a.service.log" "$LINE_RESERVED" $((n + 1)) "$RESERVE_WAIT" "$a_pid" "$relay_pid"
  wait_ipc "$NS_HA" "$a" 30 "$a_pid"
  before="$(nft_counter "$NS_RB" "${counter[@]}")" || fail "cannot read rB's counter ${counter[*]}"
  send_check "$NS_HA" "$a" bob "$MODE-1" "$MODE-1"
  inbox_once "$NS_HB" "$b" "$MODE-1" b-1
  require_path "direct" "#1 A -> B (B's mapped address from its route hints)"
  after="$(nft_counter "$NS_RB" "${counter[@]}")" || fail "cannot read rB's counter ${counter[*]}"
  if [[ "$after" -le "$before" ]]; then
    fail "#1 was direct, yet rB's counter ${counter[2]} stayed at $before"
  fi
  if [[ "$(dcutr_count)" -ne "$dcutr_before" ]]; then
    fail "a DCUtR upgrade after A's restart: #1 was not the mapping's doing"
  fi
  pcp_logs_clean
  echo "RESULT $MODE: B's router mapped its port, #1 direct through it (rB ${counter[2]} $before -> $after), no DCUtR after A's restart"
}

# pcp_logs_clean: no log names a PeerId, and no router line an address.
pcp_logs_clean() {
  local log
  for log in "$LOGS/a.service.log" "$LOGS/b.service.log"; do
    if grep -Fq '12D3Koo' "$log"; then
      fail "$(basename "$log") names a PeerId"
    fi
    if grep -E 'router|pinhole' "$log" | grep -qE "$WAN\.|192\.168\.|100\.64\.|$V6PIN:"; then
      fail "$(basename "$log") has a router line naming an address"
    fi
  done
}

# ---- preflight (exit 2: cannot run here) ----------------------------------

# preflight_fail WHAT ERR_FILE: why this host cannot run the cases; exit 2.
preflight_fail() {
  echo "netns_nat_dcutr: cannot run here: $1 ($(nft --version 2>/dev/null || echo 'nft: no version'), kernel $(uname -r)):" >&2
  cat "$2" >&2 2>/dev/null || true
  exit 2
}

# preflight_nft: what the routers need, tried once in a scratch namespace
# before any case: named counters (load, list, reset) and the symmetric
# run's `masquerade random,fully-random`.
preflight_nft() {
  local ns="${NSP}-probe" err="$BASE/nft-preflight.err"
  if ! ip netns add "$ns" 2>"$err"; then
    preflight_fail "cannot create a network namespace" "$err"
  fi
  if ! ip netns exec "$ns" nft -f - >"$err" 2>&1 <<'EOF'
table ip raven_probe {
  counter probe {
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    counter name "probe"
  }
}
EOF
  then
    preflight_fail "nftables has no named counters" "$err"
  fi
  if ! nat_ruleset "masquerade random,fully-random" 192.0.2.1 | ip netns exec "$ns" nft -f - >"$err" 2>&1; then
    preflight_fail "nftables rejects the routers' ruleset with 'masquerade random,fully-random'" "$err"
  fi
  if ! ip netns exec "$ns" nft list counter ip raven_nat lan_to_other >"$err" 2>&1 \
    || ! counter "$ns" lan_to_other >/dev/null; then
    preflight_fail "nftables lists no 'packets N' for a named counter" "$err"
  fi
  if ! ip netns exec "$ns" nft reset counter ip raven_nat lan_to_other >"$err" 2>&1; then
    preflight_fail "nftables cannot reset a named counter" "$err"
  fi
  ip netns del "$ns" 2>/dev/null || true
  echo "nft preflight: named counters and masquerade random,fully-random load ($(nft --version 2>/dev/null))"
}

# pass_text CASE: what a PASS of CASE showed.
# ---- the classify and punch-skip runs (Phase 4 P4.24; advisory) ----------

# setup_natclass_net MASQ PRE_A [WITH_B PRE_B]: pub with R1 and R2 on two
# /24s, A behind rA ('MASQ', its PRE rules first) and, when WITH_B is 1, B
# behind rB the same way. Each router's counters count packets to or from
# anyone but the two relays.
setup_natclass_net() {
  local masq=$1 pre_a=$2 with_b=${3:-0} pre_b=${4:-} ns relays
  relays="{ $WAN.11.1, $WAN.12.1 }"
  for ns in "$NS_PUB" "$NS_RA" "$NS_HA"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip -n "$NS_PUB" addr add "$WAN.11.1/32" dev lo
  ip -n "$NS_PUB" addr add "$WAN.12.1/32" dev lo
  ip -n "$NS_PUB" link add wa type veth peer name wan netns "$NS_RA"
  ip -n "$NS_RA" link add lan type veth peer name eth0 netns "$NS_HA"
  ip -n "$NS_PUB" addr add "$WAN.14.1/24" dev wa
  ip -n "$NS_PUB" link set wa up
  ip netns exec "$NS_PUB" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$NS_RA" addr add "$WAN.14.2/24" dev wan
  ip -n "$NS_RA" addr add 192.168.4.1/24 dev lan
  ip -n "$NS_RA" link set wan up
  ip -n "$NS_RA" link set lan up
  ip -n "$NS_RA" route add default via "$WAN.14.1"
  ip -n "$NS_HA" addr add 192.168.4.2/24 dev eth0
  ip -n "$NS_HA" link set eth0 up
  ip -n "$NS_HA" route add default via 192.168.4.1
  nat_rules "$NS_RA" "$masq" "$relays" "$pre_a"
  if [[ "$with_b" == "1" ]]; then
    for ns in "$NS_RB" "$NS_HB"; do
      ip netns add "$ns"
      ip -n "$ns" link set lo up
    done
    ip -n "$NS_PUB" link add wb type veth peer name wan netns "$NS_RB"
    ip -n "$NS_RB" link add lan type veth peer name eth0 netns "$NS_HB"
    ip -n "$NS_PUB" addr add "$WAN.16.1/24" dev wb
    ip -n "$NS_PUB" link set wb up
    ip -n "$NS_RB" addr add "$WAN.16.2/24" dev wan
    ip -n "$NS_RB" addr add 192.168.5.1/24 dev lan
    ip -n "$NS_RB" link set wan up
    ip -n "$NS_RB" link set lan up
    ip -n "$NS_RB" route add default via "$WAN.16.1"
    ip -n "$NS_HB" addr add 192.168.5.2/24 dev eth0
    ip -n "$NS_HB" link set eth0 up
    ip -n "$NS_HB" route add default via 192.168.5.1
    nat_rules "$NS_RB" "$masq" "$relays" "$pre_b"
  fi
  if [[ -n "$(ip -n "$NS_PUB" route show default 2>/dev/null)" ]]; then
    fail "pub has a default route: the simulated Internet ($WAN.0.0/16) must not reach the real one"
  fi
  {
    echo "== $MODE: rA does '$masq' (pre: ${pre_a:-none})"
    ip netns exec "$NS_RA" nft list ruleset
  } >>"$LOGS/topology.log" 2>&1
  if command -v ping >/dev/null 2>&1; then
    in_ns "$NS_HA" ping -c 1 -W 2 "$WAN.11.1" >>"$LOGS/topology.log" 2>&1 || fail "hA cannot reach R1 ($WAN.11.1)"
    in_ns "$NS_HA" ping -c 1 -W 2 "$WAN.12.1" >>"$LOGS/topology.log" 2>&1 || fail "hA cannot reach R2 ($WAN.12.1)"
  fi
}

# natclass_line NS DIR: the `nat_mapping:` line of `raven doctor` (empty
# while there is none).
natclass_line() {
  in_ns "$1" "$RAVEN" --data-dir "$2" doctor 2>/dev/null | grep -m 1 -oE 'nat_mapping: .*' || true
}

# wait_natclass NS DIR NAME WANT PID...: until NAME's doctor says
# `nat_mapping: tcp=WANT`.
NATCLASS=""
wait_natclass() {
  local ns=$1 dir=$2 name=$3 want=$4 deadline
  shift 4
  deadline=$((SECONDS + NATCLASS_WAIT))
  while ((SECONDS < deadline)); do
    NATCLASS="$(natclass_line "$ns" "$dir")"
    if [[ "$NATCLASS" == "nat_mapping: tcp=$want "* ]]; then
      echo "$name: $NATCLASS" >>"$LOGS/natclass.log"
      return 0
    fi
    require_alive "$@"
    sleep 2
  done
  fail "$name's doctor says '${NATCLASS:-no nat_mapping line}', not 'nat_mapping: tcp=$want' after ${NATCLASS_WAIT}s"
}

# natclass_logs_clean LOG: the classifier's and the skip lines name no
# address, port or PeerId.
natclass_logs_clean() {
  local line
  while IFS= read -r line; do
    if [[ "$line" == *"$WAN."* || "$line" == *"192.168."* || "$line" == *"12D3Koo"* \
      || "$line" == *"7423"* || "$line" == *"$SHIFT_PORT"* ]]; then
      fail "$(basename "$1") names an address, port or PeerId: '$line'"
    fi
  done < <(grep -F -e "$LINE_NATCLASS" -e 'hole punch skipped' "$1" || true)
}

# start_natclass_node NS DIR NAME V1 V2: `raven-node service` on
# 0.0.0.0:7423 with reservations on V1 and V2; sets NODE_PID, waits for
# both reservations and IPC.
start_natclass_node() {
  local ns=$1 dir=$2 name=$3 v1=$4 v2=$5 log
  log="$LOGS/$name.service.log"
  if [[ -s "$log" ]]; then
    mv "$log" "$LOGS/$name.service.$SECONDS.log"
  fi
  start_reach_node "$ns" "$dir" "$name" "$v1" "$v2"
  wait_count "$log" "$LINE_RESERVED" 2 "$RESERVE_WAIT" "$NODE_PID"
  wait_ipc "$ns" "$dir" 30 "$NODE_PID"
  grep -Fq -- "$LINE_NATCLASS_LAB" "$log" \
    || fail "$name did not log '$LINE_NATCLASS_LAB': the NAT_CLASS lab is not on (debug build, RAVEN_LAB_TEST_A=1)"
}

# stop_pid PID: stop one process this run started (TERM, then KILL).
stop_pid() {
  local pid=$1 i
  kill -TERM "$pid" 2>/dev/null || true
  for ((i = 0; i < 50; i++)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

run_natclass() {
  local run_dir a b v1 v2 r1_pid r2_pid a_pid b_pid card a_card b_card a_fp b_fp sub masq pre want
  local la lb rdir
  MODE=$1
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  # This run's subshell only: the NAT_CLASS gate's lab switch; punch-skip
  # also needs route hints (the classes travel in RRH1).
  export RAVEN_LAB_NAT_CLASS=1
  if [[ "$MODE" == "punch-skip" ]]; then
    export RAVEN_LAB_ROUTE_HINTS=1
  fi
  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  mkdir -p "$LOGS"
  echo "=== $MODE run: R1 $WAN.11.1 and R2 $WAN.12.1 on two /24s (dirs under $run_dir) ==="

  if [[ "$MODE" == "classify" ]]; then
    for sub in cone shifted symmetric; do
      case "$sub" in
        cone) masq="masquerade" pre="" want="stable_kept" ;;
        shifted) masq="masquerade" pre="$(shift_rules 192.168.4.2 "$WAN.14.2")" want="stable_shifted" ;;
        symmetric) masq="masquerade random,fully-random" pre="" want="varies" ;;
      esac
      echo "--- $sub: rA does '$masq'${pre:+ after the shift to :$SHIFT_PORT}; A must classify $want"
      stop_procs
      teardown_net
      setup_natclass_net "$masq" "$pre"
      R="$run_dir/$sub.r1"
      start_reach_relay "$sub.r1" "$WAN.11.1"
      v1="$RELAY_VIA"
      start_reach_relay "$sub.r2" "$WAN.12.1"
      v2="$RELAY_VIA"
      a="$run_dir/$sub.a"
      mkdir -p "$a"
      chmod 700 "$a"
      VIA="$v1"
      raven_init "$NS_HA" "$a" "$sub.a"
      raven_card "$NS_HA" "$a" "$sub.a"
      for rdir in "$run_dir/$sub.r1" "$run_dir/$sub.r2"; do
        in_ns "$NS_PUB" "$RAVEN" --data-dir "$rdir" relay allow --card "$CARD" \
          >>"$LOGS/relay.allow.out" 2>&1 || fail "raven relay allow on $(basename "$rdir") failed"
      done
      start_natclass_node "$NS_HA" "$a" "$sub.a" "$v1" "$v2"
      wait_natclass "$NS_HA" "$a" "$sub.a" "$want" "$NODE_PID"
      wait_line "$LOGS/$sub.a.service.log" "${LINE_NATCLASS}$want (tcp)" 10 "$NODE_PID"
      natclass_logs_clean "$LOGS/$sub.a.service.log"
      echo "$sub: $NATCLASS"
    done
    echo "RESULT classify: cone stable_kept, shifted stable_shifted, symmetric varies"
    return 0
  fi

  # punch-skip: both symmetric, both on R1 and R2.
  setup_natclass_net "masquerade random,fully-random" "" 1 ""
  R="$run_dir/r1"
  start_reach_relay r1 "$WAN.11.1"
  v1="$RELAY_VIA"
  r1_pid="$RELAY_PID"
  start_reach_relay r2 "$WAN.12.1"
  v2="$RELAY_VIA"
  r2_pid="$RELAY_PID"
  a="$run_dir/a"
  b="$run_dir/b"
  mkdir -p "$a" "$b"
  chmod 700 "$a" "$b"
  VIA="$v1"
  raven_init "$NS_HA" "$a" a
  a_fp="$INIT_FP"
  raven_card "$NS_HA" "$a" a
  a_card="$CARD"
  raven_init "$NS_HB" "$b" b
  b_fp="$INIT_FP"
  raven_card "$NS_HB" "$b" b
  b_card="$CARD"
  for card in "$a_card" "$b_card"; do
    for rdir in "$run_dir/r1" "$run_dir/r2"; do
      in_ns "$NS_PUB" "$RAVEN" --data-dir "$rdir" relay allow --card "$card" \
        >>"$LOGS/relay.allow.out" 2>&1 || fail "raven relay allow on $(basename "$rdir") failed"
    done
  done
  start_natclass_node "$NS_HA" "$a" a "$v1" "$v2"
  a_pid="$NODE_PID"
  start_natclass_node "$NS_HB" "$b" b "$v1" "$v2"
  b_pid="$NODE_PID"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --card "$b_card" \
    --petname bob --tag bob --verify-fp "$b_fp" >"$LOGS/a.contact.out" 2>&1 || fail "A contact add bob failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --card "$a_card" \
    --petname alice --tag alice --verify-fp "$a_fp" >"$LOGS/b.contact.out" 2>&1 || fail "B contact add alice failed"
  wait_line "$LOGS/a.service.log" "$LINE_GATE_ONE" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_GATE_ONE" 30 "$b_pid"
  wait_natclass "$NS_HA" "$a" a varies "$a_pid"
  wait_natclass "$NS_HB" "$b" b varies "$b_pid"

  echo "--- A -> B #1: the RRH1 exchange carries each side's NAT_CLASS"
  send_check "$NS_HA" "$a" bob "punch-skip-1" ps1
  inbox_once "$NS_HB" "$b" "punch-skip-1" b-ps1
  require_path "$PATH_RELAYED" "#1"

  echo "--- restart A and B: no connection left to ride; their classes come back"
  stop_pid "$a_pid"
  stop_pid "$b_pid"
  start_natclass_node "$NS_HA" "$a" a "$v1" "$v2"
  a_pid="$NODE_PID"
  start_natclass_node "$NS_HB" "$b" b "$v1" "$v2"
  b_pid="$NODE_PID"
  wait_natclass "$NS_HA" "$a" a varies "$a_pid" "$r1_pid" "$r2_pid"
  wait_natclass "$NS_HB" "$b" b varies "$b_pid" "$r1_pid" "$r2_pid"
  la="$(counter "$NS_RA" lan_to_other)" || fail "cannot read rA's nft counter lan_to_other"
  lb="$(counter "$NS_RB" lan_to_other)" || fail "cannot read rB's nft counter lan_to_other"

  echo "--- A -> B #2 and #3: relayed, the hole punch skipped on both sides"
  send_check "$NS_HA" "$a" bob "punch-skip-2" ps2
  inbox_once "$NS_HB" "$b" "punch-skip-2" b-ps2
  require_path "$PATH_RELAYED" "#2"
  wait_line "$LOGS/a.service.log" "$LINE_PUNCH_SKIPPED" 30 "$a_pid"
  wait_line "$LOGS/b.service.log" "$LINE_PUNCH_SKIPPED" 30 "$b_pid"
  # Long enough for a hole-punch dial to have left (DCUtR dials at once).
  sleep "$DCUTR_OBSERVE"
  send_check "$NS_HA" "$a" bob "punch-skip-3" ps3
  inbox_once "$NS_HB" "$b" "punch-skip-3" b-ps3
  require_path "$PATH_RELAYED" "#3"
  if grep -Fq -e "$LINE_DCUTR" -e "$LINE_PUNCH_FAILED" "$LOGS/a.service.log" "$LOGS/b.service.log"; then
    fail "a hole punch ran after the restart (an upgrade or a failure line)"
  fi
  if [[ "$(counter "$NS_RA" lan_to_other)" != "$la" || "$(counter "$NS_RB" lan_to_other)" != "$lb" ]]; then
    read_counters
    fail "a packet left a LAN for anyone but the relays after the restart: a hole-punch dial"
  fi
  natclass_logs_clean "$LOGS/a.service.log"
  natclass_logs_clean "$LOGS/b.service.log"
  echo "RESULT punch-skip: classes exchanged over RRH1; after the restart #2 and #3 relayed exactly once, both sides skipped the hole punch, no packet past the relays"
}

# ---- the learn-flaky run (Phase 6a P6.18, learning connectivity; advisory) --

# setup_learn_net: learn-flaky's topology (the header's). hS's table inet
# raven_learn counts every packet that reaches it from hA (from_a).
setup_learn_net() {
  local ns
  for ns in "$NS_SW" "$NS_HA" "$NS_HB" "$NS_HS" "$NS_PUB"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip -n "$NS_SW" link add br0 type bridge
  ip -n "$NS_SW" link set br0 up
  lan_plug "$NS_HA" pa
  lan_plug "$NS_HB" pb
  lan_plug "$NS_HS" ps
  ip -n "$NS_HA" addr add "$LAN_OLD.2/24" dev eth0
  ip -n "$NS_HB" addr add "$LAN_OLD.3/24" dev eth0
  ip -n "$NS_HS" addr add "$LAN_OLD.9/24" dev eth0
  ip netns exec "$NS_PUB" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$NS_PUB" link add la type veth peer name eth1 netns "$NS_HA"
  ip -n "$NS_PUB" link add lb type veth peer name eth1 netns "$NS_HB"
  ip -n "$NS_PUB" addr add "$WAN.40.1/24" dev la
  ip -n "$NS_PUB" addr add "$WAN.41.1/24" dev lb
  ip -n "$NS_PUB" link set la up
  ip -n "$NS_PUB" link set lb up
  ip -n "$NS_HA" addr add "$WAN.40.10/24" dev eth1
  ip -n "$NS_HB" addr add "$WAN.41.10/24" dev eth1
  ip -n "$NS_HA" link set eth1 up
  ip -n "$NS_HB" link set eth1 up
  ip -n "$NS_HA" route add "$WAN.41.0/24" via "$WAN.40.1"
  ip -n "$NS_HB" route add "$WAN.40.0/24" via "$WAN.41.1"
  for ns in "$NS_HA" "$NS_HB" "$NS_HS" "$NS_PUB"; do
    if [[ -n "$(ip -n "$ns" route show default 2>/dev/null)" ]]; then
      fail "$ns has a default route: this run must have none"
    fi
  done
  ip netns exec "$NS_HS" nft -f - <<NFT || fail "cannot load hS's counter table"
table inet raven_learn {
  counter from_a {
  }
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr $LAN_OLD.2 counter name "from_a"
  }
}
NFT
  {
    echo "== $MODE: one LAN bridge (A, B, S), an internet through pub ($WAN.40/41)"
    ip -n "$NS_HA" addr show
    ip -n "$NS_HA" route show
    ip -n "$NS_HB" route show
  } >"$LOGS/topology.log" 2>&1
}

# learn_loss PCT: the bridge's ports to A and B lose PCT of the packets
# they carry (netem; 0% is none).
learn_loss() {
  local port
  for port in pa pb; do
    ip netns exec "$NS_SW" tc qdisc replace dev "$port" root netem loss "$1" \
      || fail "tc netem on $port failed"
  done
}

# learn_start NS DIR NAME [INET]: raven-node on the LAN (0.0.0.0:7420 in
# NS) and, with INET, Internet direct on INET:7422. Sets LEARN_PID.
LEARN_PID=""
learn_start() {
  local ns=$1 dir=$2 log="$LOGS/$3.service.log" inet=${4:-}
  local args=(service --data-dir "$dir" --lan-listen 0.0.0.0:7420 --ble-listen 127.0.0.1:0
    --timeout-secs 0)
  if [[ -n "$inet" ]]; then
    args+=(--internet-listen "$inet:7422")
  fi
  echo "===== start $(date +%s)" >>"$log"
  ip netns exec "$ns" "$NODE" "${args[@]}" >>"$log" 2>&1 &
  LEARN_PID=$!
  PIDS+=("$LEARN_PID")
  wait_ipc "$ns" "$dir" 60 "$LEARN_PID"
}

# learn_half LABEL: LEARN_SENDS sends A -> B on a fixed LEARN_GAP cadence
# from the start of a loss burst (the bursts toggle in the background),
# each one's milliseconds in LOGS/LABEL.ms; LEARN_P95 is their 95th
# percentile. With learning off, A's route memory (the lab's G2, which
# learning replaces while on) is cleared before each send: the static
# order, as a release build has it. Uses run_learn_flaky's `a`.
LEARN_P95=0
learn_half() {
  local label=$1 i t0 t1 toggler due start
  : >"$LOGS/$label.ms"
  learn_loss "$LEARN_LOSS"
  (
    while :; do
      sleep "$LEARN_BURST"
      learn_loss 0%
      sleep "$LEARN_BURST"
      learn_loss "$LEARN_LOSS"
    done
  ) &
  toggler=$!
  PIDS+=("$toggler")
  start=$SECONDS
  for ((i = 1; i <= LEARN_SENDS; i++)); do
    due=$((start + (i - 1) * LEARN_GAP))
    if ((SECONDS < due)); then
      sleep $((due - SECONDS))
    fi
    if [[ "$label" == "off" ]]; then
      rm -f "$a/route_memory.json"
    fi
    t0="$(date +%s%N)"
    printf '%s\n' "learn-$label-$i" | timeout "$SEND_TIMEOUT" ip netns exec "$NS_HA" \
      "$RAVEN" --data-dir "$a" send --contact @bob >"$LOGS/$label-$i.send.out" 2>&1 || true
    t1="$(date +%s%N)"
    echo $(((t1 - t0) / 1000000)) >>"$LOGS/$label.ms"
  done
  kill "$toggler" 2>/dev/null || true
  wait "$toggler" 2>/dev/null || true
  learn_loss 0%
  LEARN_P95="$(sort -n "$LOGS/$label.ms" | awk -v n="$LEARN_SENDS" \
    '{ v[NR] = $1 } END { k = int((95 * n + 99) / 100); print v[k] }')"
  echo "$label: p95 ${LEARN_P95} ms over $LEARN_SENDS sends ($(paste -sd' ' "$LOGS/$label.ms"))"
}

run_learn_flaky() {
  local run_dir a b c s a_pid b_pid s_pid a_addr a_pub a_fp b_addr b_pub b_fp c_addr c_pub c_fp
  local p95_off p95_on from_a i
  MODE=learn-flaky
  trap run_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  # Learning keys what it learns by the network; with no default route
  # here, a lab tag of this run's names it (both halves, this subshell).
  export RAVEN_LAB_NET_TAG=learn-flaky
  run_dir="$(mktemp -d "$BASE/$MODE.XXXXXX")"
  LOGS="$run_dir/logs"
  a="$run_dir/a"
  b="$run_dir/b"
  c="$run_dir/c"
  s="$run_dir/s"
  mkdir -p "$LOGS" "$a" "$b" "$c" "$s"
  chmod 700 "$a" "$b" "$c" "$s"
  echo "=== $MODE run: a lossy LAN and a routed internet (dirs under $run_dir) ==="
  setup_learn_net
  raven_init "$NS_HA" "$a" a
  a_addr="$INIT_ADDR"
  a_pub="$INIT_PUB"
  a_fp="$INIT_FP"
  raven_init "$NS_HB" "$b" b
  b_addr="$INIT_ADDR"
  b_pub="$INIT_PUB"
  b_fp="$INIT_FP"
  raven_init "$NS_HS" "$c" c
  c_addr="$INIT_ADDR"
  c_pub="$INIT_PUB"
  c_fp="$INIT_FP"
  raven_init "$NS_HS" "$s" s
  learn_start "$NS_HB" "$b" b "$WAN.41.10"
  b_pid="$LEARN_PID"
  learn_start "$NS_HS" "$s" s
  s_pid="$LEARN_PID"
  learn_start "$NS_HA" "$a" a "$WAN.40.10"
  a_pid="$LEARN_PID"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --address "$b_addr" --pub-hex "$b_pub" \
    --petname bob --tag bob --lan-dial "$LAN_OLD.3:7420" --verify-fp "$b_fp" \
    >>"$LOGS/contacts.out" 2>&1 || fail "A's contact add bob failed"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact set-addr @bob --internet "$WAN.41.10:7422" \
    >>"$LOGS/contacts.out" 2>&1 || fail "A's set-addr @bob --internet failed"
  in_ns "$NS_HA" "$RAVEN" --data-dir "$a" contact add --address "$c_addr" --pub-hex "$c_pub" \
    --petname carol --tag carol --lan-dial "$LAN_OLD.9:7420" --verify-fp "$c_fp" \
    >>"$LOGS/contacts.out" 2>&1 || fail "A's contact add carol failed"
  in_ns "$NS_HB" "$RAVEN" --data-dir "$b" contact add --address "$a_addr" --pub-hex "$a_pub" \
    --petname alice --tag alice --lan-dial "$LAN_OLD.2:7420" --verify-fp "$a_fp" \
    >>"$LOGS/contacts.out" 2>&1 || fail "B's contact add alice failed"
  lan_send "$NS_HA" "$a" bob "learn-warm" warm
  lan_expect DELIVERED "A's first message to B"
  # Carol's saved address is a stranger's node: it never delivers, and
  # from here on nothing of A's may reach it.
  lan_send "$NS_HA" "$a" carol "learn-carol" carol
  ip netns exec "$NS_HS" nft reset counter inet raven_learn from_a >/dev/null \
    || fail "cannot reset hS's counter"
  echo "--- learning off: the static order"
  learn_half off
  p95_off="$LEARN_P95"
  echo "--- learning on (RAVEN_LAB_LEARNING=1 for A's processes)"
  stop_pid "$a_pid"
  export RAVEN_LAB_LEARNING=1
  learn_start "$NS_HA" "$a" a "$WAN.40.10"
  a_pid="$LEARN_PID"
  learn_half on
  p95_on="$LEARN_P95"
  for i in $(seq 1 "$LEARN_SENDS"); do
    inbox_once "$NS_HB" "$b" "learn-off-$i" "b-off-$i" 60
    inbox_once "$NS_HB" "$b" "learn-on-$i" "b-on-$i" 60
  done
  from_a="$(nft_counter "$NS_HS" inet raven_learn from_a)" || fail "cannot read hS's counter"
  require_alive "$a_pid" "$b_pid" "$s_pid"
  echo "p95 off ${p95_off} ms, on ${p95_on} ms; packets from A to the stranger: $from_a"
  if ((from_a != 0)); then
    fail "A sent $from_a packet(s) to the stranger's node after its one send to Carol"
  fi
  if ((p95_on * 2 > p95_off)); then
    fail "learning's p95 (${p95_on} ms) is not at most half the static order's (${p95_off} ms)"
  fi
  echo "RESULT learn-flaky: p95 ${p95_off} ms -> ${p95_on} ms with learning, every message once, nothing to the stranger"
}

pass_text() {
  case "$1" in
    cone) echo "R14 stranger refused by B's gate with 0 packets past R; relay delivery both ways, DCUtR upgrade, then $PATH_PUNCHED with the direct path counted" ;;
    symmetric) echo "every message $PATH_RELAYED, exactly once; no DCUtR upgrade" ;;
    cone-private) echo "private WAN: every message $PATH_RELAYED, no upgrade, 0 packets out of either LAN to anything but R" ;;
    swap) echo "uplink swap noticed, p2p re-homed on the same relay, queued messages delivered exactly once" ;;
    shifted) echo "port-shifting NAT: hole-punched through the raw observed port, retired relay setting listens" ;;
    v6fw) echo "symmetric IPv4, stateful IPv6 firewall: hole-punched through the hosts' own IPv6" ;;
    reach) echo "public needs two relays on different networks; one /24 is one opinion; behind NAT private, then unreachable without its relay" ;;
    hints) echo "direct through RRH1; after the recipient's swap delivered through a circuit, no packet to its old address" ;;
    only443) echo "443-only egress: reserved over the relay's TCP 443 fallback and over a friend relay's TCP 443, relayed both ways, no hole punch, nothing to 7427" ;;
    friend) echo "relays picked from offers only; relayed past a symmetric NAT, no established flow to anyone but the operators" ;;
    friend-sleep) echo "a stopped operator's relay replaced once, delivery kept, no second replacement after it woke" ;;
    diag) echo "both_nat with W3, delivered through R, relay_asleep (relay=mine1) with W1 while R slept, then contact_offline" ;;
    lan-move) echo "no address saved: the first messages through the beacon; renumbered, the queued ones both ways within ${LAN_DELIVER}s; only beacon datagrams on the bridge" ;;
    lan-ll) echo "IPv6 link-local only: delivered both ways through a [fe80::...%eth0] find" ;;
    lan-isolated) echo "client isolation: beacon unanswered, message queued, books unchanged" ;;
    lan-nonlocal) echo "a routed non-local source closed before a byte (counted, no address logged)" ;;
    custody) echo "deposit, fetch and ACK through a public custodian, exactly once; 0 packets between the two NATed networks" ;;
    pcp) echo "miniupnpd mapped B's port over PCP; after A learned it through RRH1, direct through the mapping (DNAT counted), no DCUtR" ;;
    pcp-cgn) echo "behind another NAT: the mapping deleted (miniupnpd's table empty), relayed both ways" ;;
    v6pin) echo "IPv6 pinhole open over PCP; direct to B's IPv6 through it" ;;
    classify) echo "cone stable_kept, shifted stable_shifted, symmetric varies (two relays on two /24s)" ;;
    punch-skip) echo "both symmetric: classes exchanged over RRH1, then every message $PATH_RELAYED with the hole punch skipped and no packet past the relays" ;;
    learn-flaky) echo "a lossy LAN: learning's p95 send time at most half the static order's, every message once, nothing to the stranger" ;;
  esac
}

# netns_restrictive.sh (Phase 4) sources this file for the helpers, the
# topology and the environment above, with RAVEN_NETNS_LIB=1: nothing below
# runs then (run as a script, it ignores the setting).
if [[ "${RAVEN_NETNS_LIB:-0}" == "1" && "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

# ---- main -------------------------------------------------------------------

echo "netns_nat_dcutr: binaries from $BIN_DIR, run dirs under $BASE, namespaces ${NSP}-*, cases '${CASE_LIST[*]}' x $REPEAT"
preflight_nft
# One "CASE ITERATION EXIT" row per run.
RESULTS=()
# Each run in its own subshell (own traps, own cleanup) so the later ones
# still happen and report after a failure. Plain statements, not `if`
# conditions: errexit stays on inside them.
set +e
for ((iter = 1; iter <= REPEAT; iter++)); do
  for name in "${CASE_LIST[@]}"; do
    echo "##### $name, iteration $iter of $REPEAT"
    (
      set -e
      if [[ "$name" == "reach" ]]; then
        run_reach
      elif [[ "$name" == "hints" ]]; then
        run_hints
      elif [[ "$name" == "only443" ]]; then
        run_only443
      elif [[ "$name" == "friend" || "$name" == "friend-sleep" ]]; then
        run_friend "$name"
      elif [[ "$name" == "diag" ]]; then
        run_diag
      elif [[ "$name" == lan-* ]]; then
        run_lan "$name"
      elif [[ "$name" == "custody" ]]; then
        run_custody
      elif [[ "$name" == pcp || "$name" == pcp-cgn || "$name" == v6pin ]]; then
        run_pcp "$name"
      elif [[ "$name" == classify || "$name" == punch-skip ]]; then
        run_natclass "$name"
      elif [[ "$name" == learn-flaky ]]; then
        run_learn_flaky
      else
        run_case "$name"
      fi
    )
    rc=$?
    RESULTS+=("$name $iter $rc")
  done
done
set -e

echo "=== summary: ${#CASE_LIST[@]} case(s) x $REPEAT iteration(s) ==="
for row in "${RESULTS[@]}"; do
  read -r name iter rc <<<"$row"
  note=""
  if advisory "$name"; then
    note="advisory; "
  fi
  if [[ "$rc" -eq 0 ]]; then
    printf '%-14s #%s PASS (%s%s)\n' "$name:" "$iter" "$note" "$(pass_text "$name")"
  else
    printf '%-14s #%s FAIL (%sexit %s)\n' "$name:" "$iter" "$note" "$rc"
  fi
done
# Per case: passes, and whether it both passed and failed (a flake).
FAILED=0
FLAKY=0
REQUIRED_RAN=0
for name in "${CASE_LIST[@]}"; do
  passed=0
  failed=0
  for row in "${RESULTS[@]}"; do
    read -r case_name _ rc <<<"$row"
    if [[ "$case_name" != "$name" ]]; then
      continue
    fi
    if [[ "$rc" -eq 0 ]]; then
      passed=$((passed + 1))
    else
      failed=$((failed + 1))
    fi
  done
  note=""
  if advisory "$name"; then
    note=" (advisory)"
  else
    REQUIRED_RAN=1
    if [[ "$failed" -gt 0 ]]; then
      FAILED=1
    fi
  fi
  if [[ "$passed" -gt 0 && "$failed" -gt 0 ]]; then
    FLAKY=$((FLAKY + 1))
    note="$note, FLAKY"
  fi
  printf '%-14s %s of %s passed%s\n' "$name:" "$passed" "$((passed + failed))" "$note"
done
echo "flaky cases (passed in one iteration, failed in another): $FLAKY"
# The green streak (raven-serverless-lab.yml) counts these.
if [[ "$REQUIRED_RAN" -eq 1 ]]; then
  GREEN=0
  for ((iter = 1; iter <= REPEAT; iter++)); do
    green=1
    for row in "${RESULTS[@]}"; do
      read -r case_name it rc <<<"$row"
      if [[ "$it" == "$iter" && "$rc" -ne 0 ]] && ! advisory "$case_name"; then
        green=0
      fi
    done
    GREEN=$((GREEN + green))
  done
  echo "green iterations (every required case passed): $GREEN of $REPEAT"
fi
echo "CLAIM: software NAT substitute (netns + nftables masquerade); does NOT replace physical rows R7b / R8"
echo "CLAIM: debug build with RAVEN_LAB_TEST_A=1; P2P_PRODUCTION_ENABLED=false (not WAN Proven)"
if [[ "$FAILED" -ne 0 ]]; then
  echo "NETNS_NAT_DCUTR_FAIL" >&2
  exit 1
fi
echo "NETNS_NAT_DCUTR_PASS"
