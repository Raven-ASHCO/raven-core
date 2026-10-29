#!/usr/bin/env python3
"""LAN fault matrix: real `ash` + `raven-node service` processes on loopback.

Each scenario builds fresh nodes, injects one fault class, and records what the
sender reported, what the receiver's inbox holds (exactly once) and how long
delivery took: receiver offline and back, several messages while offline, the
receiver's address changing (port; IP on the same port), lost receiver state,
connection resets, a slow link, a black-holed link, both sides sending at once,
a crash during a burst, queue drain timing, and 20 queued messages in order.

Debug binaries and the lab locked-file backends only (never an OS keystore).
Python 3.10+, standard library only.

  cargo build -p ash -p raven-node            # in node/
  python3 scripts/lan_fault_matrix.py node/target/debug /tmp/raven-fault [s03 s14 ...]
  python3 scripts/lan_fault_matrix.py --self-test   # the environment scrub

The nodes never see the caller's own Raven settings (listen ports, relays,
the relay role, data dir, verbose) or proxy settings (Phase 4: every node runs
with RAVEN_P2P_PROXY=off): see CALLER_SETTINGS.

s37 (also by default) checks what `ash status` says about the last delivery
to a contact: a LAST DELIVERY row naming its petname and the path in words
('same network (LAN)'), never an address, gone once raven-node restarts (it is
kept in memory only); `ash doctor` says `reach_class: off` without a p2p host.
s90 and s93 (also by default; cutoff pack CP.6, release behaviour): s90, a
verified contact's saved address turned into a black hole (and, without an
IPv6 route, an address with no route): the sends are queued quickly with a
deadline on this computer's clock (its own zone only), nothing goes while he stays
silent, and his own link delivers each exactly once within 10 s
(lan_seen.json holds where he came from); s93, a first message to a contact
whose address is dead: NOT SENT within 6 s with the first-message rule ('a
first message needs you and Bob both online', E1), nothing waiting (its two
nodes keep the horizon held; under RAVEN_FAULT_HORIZON=1 a third node with
the horizon parks the same first message: HORIZON_PARKED, waiting in its
outbox).
s95 (also by default; cutoff pack CP.5, release behaviour): a node listening
on loopback says in `ash status` that friends cannot reach it ('ONLY THIS
COMPUTER'), and one set to listen on an address that is not on this computer
(192.0.2.10:7499) says so ('is not on this computer now'), never 'busy port';
`ash doctor` keys `receiving: local_only (...)` and `receiving: no
(addr_not_here ...)`.
s121 (also by default; privacy pack PP.15, Lock now v1, release behaviour):
Bob runs `raven lock --yes` while Alice has 3 messages for him: his node
stops and stays stopped (his `raven status` says so first; his own send is
refused and starts nothing), hers are QUEUED with a deadline and retried,
never NOT SENT; after `raven unlock` all 3 arrive exactly once within 10 s
of his node answering (his first message is the link that wakes her queue).
s117 (also by default; privacy pack PP.16, `raven erase`, release
behaviour): Alice erases her profile in a pseudo-terminal while her node
runs and Raven's own (lab) login item names her profile: her node stops,
the item is unloaded, turned off and removed through the shims, and nothing
of her profile is left; Bob's node (the same process) and Carol still
exchange both ways, each message once.
s122 (also by default since PP.19; privacy pack PP.8,
clear_sticks_across_session_expiry; LabClock on both profiles): Bob sends
Alice three messages and Alice deletes her chat with him (`raven chats
delete`): neither her history (read with the lab chat-history key) nor
`raven inbox` shows them; Bob's newest envelope sent again as it was (`ash
lab lan-dial-sealed`) is answered with an ACK and not shown; 25 h later
(both clocks; Alice's node restarted, so its prune archived and dropped the
session) none of the three is back, and Bob's next message, over a new
secure connection, shows once.
s124 (privacy pack PP.18, the downgrade path; with
RAVEN_FAULT_PRIVACY_OLD_BIN=<the build before the pack, kept by PP.1>, M0
noise pins on in both builds): Alice moves between that build and this one.
Her old build's plain profile is sealed by this build's node; the old build on the
sealed profile fails closed (its `contact list` says the book is corrupt,
its node admits nobody, Bob's message stays QUEUED, contacts.json,
lan_noise_pins.rms and blocked_pubs.json byte for byte) and what it wrote in
plain is recorded; this build seals that again and Bob's queued message
arrives once; `raven privacy unseal` (it stops her node) leaves a profile
this build seals no more and the old build exchanges with; `raven privacy
seal-now` seals it again. Then Carol's old node on a plain profile: this
build's `raven status` migrates nothing, says the restart line, and her node
still admits Bob.
s120 (privacy pack PP.19, an old profile sealed; with
RAVEN_FAULT_PRIVACY_OLD_BIN as s124, M0 noise pins and route hints on in both
builds): Alice and Bob are made and used by that build (a session,
sightings, pins, learned routes, two messages each way), Alice messages
Carol and removes her, and Alice's message to Bob waits in its outbox while
he is away. Both then start this build, Bob on his old port first: each node
seals the whole profile at its start (before anything of this build sends,
no file name names a friend, Carol included), `raven privacy status --json` says
sealed with no registered file plain and every SQLite store keyed, the old
history is all there (RVNHIST2 now), the waiting message arrives exactly
once and both ways deliver. With both nodes stopped, carrier_matrix C87's
check over both data dirs finds nothing that names the friend (key, rvn1
address, PeerId, address, petname, tag, loopback IP, the SQLite stores' raw
bytes with every message id; no file name names the key), while the same
check over a copy of the old profiles does.
RAVEN_FAULT_PRIVACY=1 runs every privacy pack scenario: s117 and s120-s125
(s117, s121 and s122 also run by default; s120 and s124 run with
RAVEN_FAULT_PRIVACY_OLD_BIN too, and fail without it, so a forgotten build
never reads as a pass; s123 also runs with RAVEN_FAULT_OFFLINE=1 and s125 with
RAVEN_FAULT_CUSTODY=1; a scenario two lists name runs once).
RAVEN_FAULT_PRIVACY_OLD_BIN and s04c's RAVEN_FAULT_OLD_BIN (below) name two
different older builds, so neither scenario ever runs against the other's
(review E-harness-docs-ci-9).
s115 (Phase 6b P6.34, with carrier_matrix C86 part 1; RAVEN_FAULT_PADDING=1:
the padding nodes run with the debug switch RAVEN_LAB_LINK_PADDING=1 and
RAVEN_LAB_TEST_A=1): PAD1 link padding over LAN, every contact route through
a proxy that records each connection's two directions (and changes nothing).
Two padding nodes: every message once, and every message after the dialer's
bind on a dial that offered PAD1 is a bucket plus the tag (a frame-less probe
offers nothing). A padding node and one without, both ways round: every
message once, nothing padded, no padding refusal in either log.
RAVEN_FAULT_PADDING_OLD_BIN=<dir with a pre-6b ash and raven-node> (a third
older build, its own variable) runs that build as the side without, and adds
the gate-off check: two nodes of this build without the switch and two of
the older build carry exactly the same message lengths.
RAVEN_FAULT_KNOCK=1 (Phase 6b P6.35, with carrier_matrix C86 part 2) runs
s115's RLK1 link knock phases (alone, or after the PAD1 ones with
RAVEN_FAULT_PADDING=1): every node with the noise pins (M0,
RAVEN_LAB_NOISE_PIN=1), the knocking ones with RAVEN_LAB_LINK_KNOCK=1 and
RAVEN_LAB_TEST_A=1. Two knocking nodes: every message once and every
handshake knocked both ways (message 1 64-95 bytes, message 2 112-143,
message 3 71-128). A knocking node and an M0-only one (RAVEN_FAULT_PADDING_OLD_BIN's
older build when given), both ways round: every message once, the knocking
side's handshakes knocked and the other's plain, no pin mismatch in either
log. The impostor rows (s113) wait for P6.32.
RAVEN_FAULT_RANDOM_PORT=1 (Phase 6b P6.36, design B section 4) runs s04r, a
random LAN listen port: its nodes run with route hints (RAVEN_LAB_ROUTE_HINTS=1)
and without the LAN beacon, the switching ones with the debug switch
RAVEN_LAB_RANDOM_PORT=1 and RAVEN_LAB_TEST_A=1. A profile created with the
switch picks a port in 20,001-49,151 that is never 7420 (`raven-node
lan-default --data-dir` names it), one created without it keeps the default
port when the switch comes on later; an existing profile's `raven lan port
random`, then a plain `--lan-listen auto` start: raven-node listens on the new
port, the contact with the old card learns it from the announce link (route
hints) and her queued message arrives once; a restart keeps the port. No
node ever listens on 7420 (a start with `auto` is refused unless the profile
names its own port).

s116 (Phase 6b P6.40; RAVEN_FAULT_LOCK_V2=1: Bob's node and ash run with
the debug switch RAVEN_LAB_LOCAL_PROTECTION=1 and RAVEN_LAB_TEST_A=1): Lock
now v2 with queued messages. `raven lock --yes` keeps Bob's node running,
locked (status says so; his own send is refused, nothing queued); a dial to
his port is refused while Alice's 3 sends wait QUEUED and retried; `raven
unlock` opens the same node's port again and all 3 arrive exactly once.

s118 and s119 (Phase 6b P6.51, the update harness, with carrier_matrix C88
and C89; RAVEN_FAULT_UPDATES=1: every node and ash runs with the update
gates' debug switches RAVEN_LAB_ADVISORY=1, RAVEN_LAB_RELEASE_BUNDLE=1 and
RAVEN_LAB_MESH_UPDATE=1, the Lab Test A unlock, the security events' switch
and the published test release key set as its lab key set; the notices,
logs and releases are made with this build's raven-release, built with
`cargo build --locked -p ash --features release-tool --bin raven-release`).
s118 (was s98): a security notice passed A -> B -> C over LAN with no
command, twice (#1, then #2 with the log grown): each hop's Status.updates
names it, each taker's ledger has SEC_ADVISORY_APPLIED, `ash update status`
says #2 everywhere, nothing quarantined. s119 (was s99): Alice and Bob hold
release 5 (64 chunks); Bob's node is down; Carol is offered it by Alice and
fetches nothing until she approves (`ash update download CODE` with the lab
approval); Alice's node is killed once 16 chunks arrived; Bob comes up and
offers the same release: Carol fetches only what she lacks (her bitmap only
grows), the whole release verifies and waits for the install approval.
RAVEN_FAULT_PHASE6=1 runs s117 with every Phase 6 switch on, after Alice's
profile took a notice and a release from Bob, imported one and agreed a pair
seed with Bob: the erase leaves none of the Phase 6 files either.

Exit 0 only when every selected scenario passes. s05 (lost receiver state)
is a known open item, and so is s04 (port change) without route hints.
RAVEN_FAULT_HINTS=1 turns on route hints (RRH1, the debug switch
RAVEN_LAB_ROUTE_HINTS=1) for every ash and raven-node: s04 passes (Bob's
first link tells Alice his new port: learned_by_inbound, and `raven send`
saves it back: saved_lan_dial), and it adds s04b (Bob back on a new port
sends nothing: his announce link tells Alice, and her queued message
arrives within 30 s), s04c (one side without route hints, both ways round;
RAVEN_FAULT_OLD_BIN=<dir with a pre-RRH1 ash and raven-node> runs a real
old build there: every message once, no dispatcher refusal, nothing
learned), s04p (s04 between verified contacts: the full snapshot) and s89
(Phase 3 P3.C1, weekly_meeting_keeps_the_port; LabClock on both profiles:
Bob's listener moves and his announce tells Alice the new port, then both
stop and 7 days pass, the hint expiring; Bob back on that port and silent,
Alice's next message reaches him exactly once over the LAN port her expired
hint kept, with no typed address and no inbound link from him first, and
`raven send` saves that address into her book); with
RAVEN_FAULT_P2P=1 as well, s39 (Bob moves from relay R1 to R2: Alice learns
it through his announce, with no new card) and s40 (Bob's p2p port moves:
Alice's stale direct hint fails at once and the relay delivers, her next
LAN link brings the new address, and the next message goes direct).
Opt-in scenarios: s15, the route
memory with a black-holed LAN and a live Internet listener
(RAVEN_FAULT_ROUTE_MEMORY=1), s30 (RAVEN_FAULT_CUSTODY=1), s31
(RAVEN_FAULT_APP=1), s32 (RAVEN_FAULT_RDAP=<an RDAP tree with its .venv>:
RDAP's own `ask` over Raven on the LAN) and, with it too, RDAP beyond the
LAN: s32b over Internet direct only (Bob's node away and back on the same
port: the second task waits in Alice's outbox and is answered within 90 s
of his return), s32c through a relay only (`relayed` both ways, the probe
pairs on p2p, no PeerId in a log), s32d where the answer rides Alice's own
connection (`direct` to Bob, `reversed` back) and s32e with no session and
two dead routes ahead of p2p (AppSubmit's probe dials both, then pairs on
p2p; a build before that probe fails it); and with
RAVEN_FAULT_NETWATCH=1: s33, the sender's network changing while a message
waits; s34, a network switch while 5 messages to 2 contacts wait (the old
network refuses every connection; after the switch all are delivered within
30 s, exactly once, in order; then a wake from sleep round); and s34c, the
same switch without the netwatch line, which records how long the backoff
alone takes. With RAVEN_FAULT_P2P=1 (libp2p, debug lab unlock): s35, a
stranger in the relay's circle who holds Bob's verified card is refused by
Bob's peer gate before his Raven link runs, its send reads as if Bob were
offline (no refusal hint), and Alice still reaches Bob exactly once; s36, how each p2p delivery travelled
(the `path=` of a verbose send): (a) with the debug local-candidates switch
two nodes on one relay go from `relayed` to `hole_punched`; (c) then one's
path to the relay is blackholed and its next message is still delivered,
`hole_punched`; (b) Alice dials Bob's own address (`direct`), Bob answers
over Alice's connection (`reversed`), and a message Bob queued while Alice
was away is delivered by his outbox over her next connection (`reversed`);
(d) two nodes without a listener (the retired relay-only mode, debug switch)
stay `relayed` and never hole-punch; s38, two always-listening nodes on one
relay whose path goes dark for 30 s (both lose their reservation, a message
waits) and heals: both reserve again and the message is delivered exactly
once within 180 s (heal_to_reserved_s, heal_to_delivered_s); and s38b, the
relay killed and restarted in its own folder on its port (same PeerId and
via): a message sent while it was down is delivered once within 180 s.
Also with RAVEN_FAULT_P2P=1, the relay kit (docs/RELAY_KIT.md): s45, a
relay on its main port and an `--also-tcp` port (the kit's 443), each
behind a proxy; the main one refuses every connection, and Alice, who
saved both addresses with `raven relay use` (one relay, a fallback),
reserves on the fallback within 15 s (`reservations 1/1`,
time_to_reserved_s) and 3 messages go `relayed`, each once; s46, the kit's
relay stopped by SIGTERM (exit 0, both lose their reservation within 5 s,
a message waits) and restarted in its folder (same PeerId and card lines,
reserved again within 30 s, the message once within 60 s; a SIGKILL round
is recorded only); and s47, the relay's circle changed with no restart:
after a first message, `raven relay deny` takes Bob out (his reservation
ends, his retries are refused, Alice's message waits), and `raven relay
allow --card` brings him back: he reserves within 70 s and the message
arrives once. None of them changes s01-s14 or s37.
With RAVEN_FAULT_FRIEND=1 (run it with RAVEN_FAULT_P2P=1 and
RAVEN_FAULT_HINTS=1): friend relays (Phase 2, the debug switch
RAVEN_LAB_FRIEND_RELAY=1, route hints on; FRIEND_ENV): an operator relays for
its verified contacts with a relay key of its own, its consent written into
node_policy.json and its loopback address named, and offers the relay in its
route hints; members listen nowhere and set no relay. s41: Bob and Carol pick
Alice's relay from her offer (reserved; its PeerId is not hers) and are
`relayed` to each other through it, every message exactly once. s42: three
operators, Bob and Carol on 2 relays each; the operator of Bob's first relay
is frozen with SIGSTOP for 90 s: Bob replaces it within 60 s, Carol's
messages keep arriving in order, once each (replaced_s, gap_s), and after
SIGCONT the operator logs `woke from sleep` and Bob replaces nothing more
for 60 s. s43: Alice's network changes (lab netwatch) and her relay starts
over on a new port with the same key: Bob, who also holds a relay set by
hand, follows within 60 s with no reselection (follow_s), tells Carol, and
Carol reaches him through the moved relay once. s44: Alice turns relaying
off: her relay stops, Bob's reservation ends, and her next route hints make
Bob drop the relay at once (`relay dropped (offer withdrawn)`, withdrawn_s).
Each result records how long its phases took (`*_s`).
With RAVEN_FAULT_P2P=1, why a contact cannot be reached (Phase 2 item 5, the
diagnosis): s48, a relay frozen with SIGSTOP (a sleeping laptop): Alice's
message waits, and within 60 s of the stop her status says the relay is not
answering (her W1 advice and Bob's NOT REACHABLE NOW row: w1_s, row_s); after
SIGCONT it is delivered once and the section goes; s48c, Bob's raven-node
frozen instead while R stays up and keeps his reservation: while Alice's relay
row says OK, no row blames her relay or a card, and the row says `offline`
within 45 s (offline_s); and s49, two nodes with
no listening port and no relay: Alice's message is queued with both_nat and
the 'nobody in your circle' fixes, and `ash doctor` counts it; once both use
a new relay it is delivered with no new send. With RAVEN_FAULT_NETWATCH=1 as
well, s48o (cutoff study F9): s49's setup with no default route on Alice (lab
netwatch `egress none`): her queued message says so and that it goes out on
the same network, never a relay, a VPS, a port forward or UPnP; once a route
is back (`egress 0a`) a fresh send says both_nat again.
With RAVEN_FAULT_WSS=1, Phase 4's restrictive networks (RWS1, held by
WSS_PRODUCTION_ENABLED and WSS_PROXY_PRODUCTION_ENABLED: the relay and both
nodes run with the debug switch RAVEN_LAB_WSS=1, Alice with
RAVEN_LAB_WSS_PROXY=1 too). Relay R has a WSS listener on a port of its own
and names only a closed port (`--external`); the HTTPS proxy is
node/scripts/lib/tiny_connect_proxy.py, the only one that resolves
`relay.invalid`, which is how Alice names R (`/dns4/relay.invalid/tcp/<P>/
tls/ws`), with RAVEN_P2P_PROXY naming the proxy (the only scenarios that set
one); Bob reserves on R's raw TCP address. macOS or Linux, no root. s50
(proxy_outage_and_return): Alice reserves through the proxy (`ash status`:
relay over WSS through the HTTPS proxy, restricted network) and a message
each way is `relayed`, every tunnel starting with a TLS record; the proxy
is killed mid-conversation for 10 s while 3 of her messages and 1 of Bob's
wait, and after it is back on its port she reserves again and all 4 arrive
exactly once (back_to_reserved_s, back_to_delivered_s). s51
(proxy_wants_negotiate): a proxy that answers 407 with Negotiate and NTLM:
within 30 s her raven-node reports it (IPC proxy_auth `unsupported`) and
her status, doctor and `ash node proxy` say it needs Windows sign-in, not
supported, while a LAN message each way is delivered once. In both, her log
names no PeerId, proxy address or relay name.
With RAVEN_FAULT_PORTMAP=1, Phase 4's router port mapping
(RAVEN_PORT_MAPPING_V1, held by PORT_MAP_PRODUCTION_ENABLED: the mapped node
runs with the debug switch RAVEN_LAB_PORT_MAP=1 and its router named by
RAVEN_LAB_PORTMAP_GATEWAY, FakePcp, a standard-library PCP router on
127.0.0.1; never the real router). s52 (router_restart_remaps): Bob maps
his p2p port (8 s leases) and Alice and Bob reach each other through a
relay; Alice goes away and Bob queues 3 messages for her, the router
restarts meanwhile (every mapping lost, epoch 0), and Bob maps again within
10 s ('router restarted; port mapped again'); when Alice is back all 3
arrive exactly once with nothing left waiting, and Bob never starts a real
UPnP search (review E-2).
With RAVEN_FAULT_P2P=1 and RAVEN_FAULT_ROTATION=1, Phase 4's PeerId
rotation (RAVEN_P2P_PEER_ROTATION_V1, held by
PEER_ROTATION_PRODUCTION_ENABLED: the nodes run with its debug switch
RAVEN_LAB_PEER_ROTATION=1 and 30 s epochs). s53
(rotation_boundary_with_queued_messages): Bob turns rotation on and gives
the relay his schedule; once he rotated and Alice heard it, his node stops
across an epoch boundary with 5 messages queued for him, and when he comes
back under the new PeerId all 5 arrive exactly once, in order, within 60 s;
no log names a PeerId.
With RAVEN_FAULT_AUTOREACH=1, auto-reach (docs/design/2026-10-auto-reach.md;
held by STUN_DISCOVERY_PRODUCTION_ENABLED and SERVERLESS_PUNCH_PRODUCTION_ENABLED:
the nodes run with the debug switches RAVEN_LAB_STUN_DISCOVERY=1 and, for
s148, RAVEN_LAB_NAT_CLASS=1 and RAVEN_LAB_SERVERLESS_PUNCH=1, and ask only two
fake STUN servers on 127.0.0.1, RAVEN_LAB_STUN_SERVERS; never a public one).
Nodes meet over Internet direct links, which carry route hints but no
same-LAN address, so a p2p address is learned only from STUN discovery. s146
(discovered_address_offered): Bob's node finds its public address from the
p2p port itself (anchored), and his friend relay, turned on with no
--external, is offered within 30 s naming it with the relay's ports; Carol's
(no STUN switch) never is; Alice learns Bob's offer and discovered DIRECT
addresses (none from Carol) and reserves on his relay. s147
(reached_after_moving): Alice keeps no route to Bob and Carol but their
PeerIds ("moved"); her p2p message to Bob reaches the address his hints told
her (`direct`), her automatic one goes to his INET_DIRECT address, Bob's node
counts its port as reached from outside (reach class public), and her p2p
message to Carol is never delivered. s148 (serverless_punch): three nodes
behind simulated endpoint-independent NATs that shift ports and drop what they
did not ask for (NatBox); with no LAN, relay or saved route, Alice's message
to an idle Bob is delivered over a punched QUIC connection (both dial at the
slot both derive), then Bob's to her; Carol, without the punch switch, never
gets hers (her NAT drops everything). Each records its timings and the NAT
box's passed and dropped datagrams.
With RAVEN_FAULT_OFFLINE=1, the cutoff pack (after Phase 2): every ash and
raven-node runs with its two held gates open (the debug switches
RAVEN_LAB_OFFLINE=1 and RAVEN_LAB_NOISE_PIN=1, not the lab unlock
RAVEN_LAB_TEST_A, which the scenarios that need it set themselves) and
RAVEN_LAB_LAN_DEFAULT_PORT naming a free port chosen per scenario, so no node
ever dials 7420 where the pack guesses the default port. Its scenarios are
s90-s99 (s90p, s91b, s93b, s96w), added by the pack's steps. A scenario that needs
days to pass moves one profile's wall clock with LabClock (CP.3: a file of
its own, and the lab unlock on that profile's ash and raven-node; each jump
ahead reads as one wake from sleep). s91 and s95 run without the switch
(release behaviour, in the default list). s91 (F5, today's wait): Bob is
away 150 s and comes back silent on the same address (a phone back on a
laptop's hotspot): it records Alice's `next try` text before his return and
the delivery time, which comes at that next try (the study's 170 s is
recorded, not required: the backoff step then is 80-240 s). s90p (M0, noise
pins):
Alice and Bob link once, then Bob goes down and X, another raven-node
profile, starts on his old port: Alice's send ends within 2 s, queued with
the 'something else answered' text; X stops, Bob restarts on that port and
sends to Alice, and her queued message reaches him exactly once with no
`ash outbox retry` (what X received is carrier_matrix C39's job). s91b
(F5): s91 with Carol, linked to Alice at the start like Bob (Alice holds
both noise pins); after Bob's return Carol links to Alice, and Bob's message
is delivered within 15 s of her link (Alice logs 'a contact answered on this
network; retrying 1 others'), each message exactly once. s92
(F1): Alice's saved route for Bob, with whom she has a session, becomes a
computer name that resolves nowhere (x-nohost.local on his port); with the
gate closed for one send it is today's NOT SENT CONTACT_NOT_VERIFIED; open,
an unverified Bob's message is QUEUED within 6 s saying his computer name
was not found (held NOT_REACHABLE, never CONTACT_NOT_VERIFIED), a verified
Bob's too with the same cause, and once `contact set-addr` puts his address
back both arrive exactly once with no new send. s93b
(M2): Alice's clock moves 25 h past a pairing while Bob is down; after her
raven-node restarts (which prunes the expired session) her send is NOT SENT
saying the secure connection with Bob ended, never 'a first message', and
nothing is queued. s99 (F10 / M11, clock skew; LabClock on both, Bob's
moved): Bob 4 min ahead delivers both ways; 10 min ahead, Bob holds Alice's
message once but she refuses his ACK (her send stays 'sent, delivery
unconfirmed' and names the clocks), her node refuses his message and her
`ash status` says 'Bob's clock is about 10 min ahead of yours', and Bob's
send after a second unanswered try carries the same-time hint; once both
clocks agree again (Bob set right, six minutes later) both messages arrive
exactly once and are acknowledged, and no clocks row is left. With
RAVEN_FAULT_NETWATCH=1 as well, s98 (F6, link-local cable): Alice's lab
netwatch file goes from `down` of every address ('no network; waiting for
one') to only `up 169.254.10.2/16` (a cable with no DHCP server) while her
message to Bob waits on a backoff of 15 s or more; with the gate closed for
her (RAVEN_LAB_OFFLINE=0) nothing is noticed and the backoff alone delivers
(recorded), open one `link-local network only (a cable?)` line within 4 s
and delivery within 6 s of it; each message exactly once.
With RAVEN_FAULT_CUSTODY=1, cutoff F8 (CP.14, a custodian that moved): every
node runs with s30's custody timers and M0 (RAVEN_LAB_NOISE_PIN=1); Alice,
Bob and Carol link once with route hints off (each pins the others; no one
holds an RRH1 from anyone), Carol is the custodian they chose. s96
(custodian_walks, w1/w2): Bob away, Alice's message held by Carol, Alice
gone, Carol back on a new port, Bob back on his: with RAVEN_FAULT_HINTS=1
Carol's announce reaches Bob because she holds mail for him, he fetches it
exactly once within 30 s, his ACK reaches Alice through Carol, and Carol
holds nothing unreleased at the end; without route hints today's failure is
recorded (nothing in 120 s), not required. With RAVEN_FAULT_HINTS=1 too,
s96w (custodian_moves_keeping_its_listener): the same trio, Carol on
0.0.0.0:<her port> with a lab netwatch file and Bob's saved address for
her one where she is not (where she was before she moved); Alice's message
held by Carol, Bob back and unable to reach her; Carol's network moves
(lab netwatch down/up) with her listener unchanged: her announce reaches
Bob, who fetches the message exactly once within 30 s of the move. And
s97 (three_people_two_rooms; LabClock shared by the three): room 1 (Alice
and Carol) at t0, 3 messages left with Carol; room 2 (Carol on a new port,
Bob) at t0 + 2 h, each once and in order; room 1 again (Carol on another
port) at t0 + 4 h, the ACKs reach Alice. Its variant (late/) reaches room 2
only at t0 + 25 h: the message expired, Alice's outbox says so, Bob gets
nothing and Carol holds 0 rows after her start's maintenance.
With RAVEN_FAULT_CUSTODY=1 and RAVEN_FAULT_HINTS=1, s126
(two_addressed_mail_friends_stay_quiet; E1): Alice and Bob each carry mail
for friends and use the other as a mail friend, Carol uses both; route
hints and custody handoff on. Alice and Bob listen on both families
(`auto`) and dial each other at different addresses (127.0.0.1 one way,
localhost, ::1 first, the other), so each sees the other at two addresses,
as mac-a saw mac-b on cable and Wi-Fi. After a message each way between all
three, 75 s of nothing: each node tells its route hints at most 30 times
and no log line folds more than 20 (before custody::peer_seen was spaced,
a link from a friend made its fetch due at once and the two fetched from
each other back to back: one line held "and 80 more like it in the last
30s").
With RAVEN_FAULT_CUSTODY=1 (or RAVEN_FAULT_PRIVACY=1), the privacy pack's s125
(PP.17, custody_release_deletes; sealed profiles): s30's trio, Bob away;
Alice's message is held by Carol, keyed and sealed; Bob back fetches it once
and releases it: Carol's store keeps only its released digest (the keyed digest
and the expiry hour). With Carol's node stopped (the checkpoint) no file in her
data dir holds Alice's or Bob's key (raw, hex, base64) and her store holds the
payload neither as stored nor in clear; back up, a replay of the same deposit
from Alice's node (`ash lab custody-deposit`) is DUPLICATE and stores nothing.
With RAVEN_FAULT_CUSTODY=1, RAVEN_FAULT_P2P=1 and RAVEN_FAULT_HINTS=1 (Phase
3 P3.22, friend custody over the internet: the WAN custody switch
RAVEN_LAB_CUSTODY_WAN=1, CUSTODY_P2P_ENV): relay R; Alice, Bob and Carol
pinned from cards naming only R (no LAN or Internet route); Carol runs `node
custody on --yes`, Alice and Bob `custody use on --yes`, and nobody names a
custodian: Carol's offer and the pair-blinded tags ride route hints (until
'mail friends now 1' and each holds the other's tag). s30p
(via_a_friend_over_p2p): Bob away, Alice's message held by Carol within
60 s; Alice away, Bob back has it exactly once within 60 s; Bob away, Alice
back fetches his ACK from Carol within 60 s and her outbox says delivered.
Neither book holds 'custodians', Carol's store (and its WAL) holds no RVPI1,
RVPR1, RLB1 or message text, no log a 64-hex value, and every `left N with
a friend` line names p2p_dial. s30w (wan_custody_needs_both_switches):
Carol without the WAN switch offers without its WAN bit: Alice's message
says CUSTODIAN_NOT_OFFERING and Carol holds nothing after 60 s; a crafted
DEPOSIT over a lab P2pDial (IPC `p2p_dial`) is answered HOLD and makes no
store file; Carol restarted with the switch, her offer gains the WAN bit
and the message is held within 60 s (the changed offer retries what waits).
With RAVEN_FAULT_FRIEND=1 as well, s30r (relay_and_custodian_on_one_node):
Carol is the friend relay (her own relay key) and the mail friend of Alice
and Bob, members who listen nowhere; Bob away, Alice's circuit to him
through Carol's relay finds no reservation (contact_offline) before her
message is left with Carol; Bob back has it once; the relay status holds
counts only.
With RAVEN_FAULT_OFFLINE=1 (or RAVEN_FAULT_PRIVACY=1), the privacy pack's s123
(PP.7, addresses_forgotten_after_30_days; LabClock on both profiles, route
hints on): Bob sends to Alice, and her sealed data dir shows his sighting
(lan_seen.json) and his route hints (learned_routes.json), read through the
harness's RMS1 opener; with Alice's node down both clocks move 31 days ahead
and her next command (no raven-node answers) runs one prune: no sighting of Bob
and no learned address of his is left on her disk (a bare tombstone at most: no
IP or port, its generation and times to the day), and his saved route in her
book stays. Alice starts again on her port; Bob sends to her again (a new
secure connection: theirs ended a day after it was set up) and his sighting is
learned again; a message from Alice to Bob is then delivered exactly once. Its
second half (PP.9; Alice keeps chats for 30 days, the retention grace
overridden to 0): the same prune took Bob's first message, 31 days old, out of
her history; with her node down again her clock moves 29 days on and one prune
keeps the 29-day-old messages, then 2 more days and the next prune takes them.
RAVEN_FAULT_BEACON=1 (Phase 3 P3.12) gives every ash and raven-node the LAN
beacon (its debug switch RAVEN_LAB_LAN_BEACON=1) on a lab bus of the
scenario's own (RAVEN_LAB_LAN_BEACON_BUS=<root>/bus, whose line names
<root>/net1): every datagram stays on 127.0.0.1 ephemeral ports, never UDP
7420 or a real interface. A Sniffer registers on such a bus like a node and
hears every datagram. Scenarios whose contacts must not find each other on
one LAN run without it (without_beacon): s90 (release behaviour), s15, s32b,
s34 and s34c, s89, s92 and s98 (a path that is tried only when the LAN
cannot reach the contact, or a network that dies while the contact's node
runs on), and the p2p, friend relay and custody families (peers on other
networks, recipients that cannot be reached). s04 then must deliver
after-move-1 before Bob's own message, with no route hint
(delivered_before_bob_s: Bob waits up to 90 s for it; with nothing waiting
he sends no join round, owner decision OD-C7, so Alice's send or outbox
asks her beacon); with RAVEN_FAULT_HINTS=1 too it records the path
(path1). And it selects the beacon's scenarios, route
hints off in each: s80 (both_move_to_a_new_network, the plan's new s33):
verified Alice and Bob, saved addresses through proxies, each on a bus file
of their own and a lab netwatch file; the proxies die, Alice moves to net2
and her m1 waits, 10 s later Bob moves and sends m2: m1 exactly once within
15 s of his move, m2 delivered by the send or within 15 s, both contact
books unchanged, each side found the other (IPC Status counts), no
`lan_beacon:` line names an address. s84 (unverified_contacts_find_each_
other): s80 with unpinned contacts. s81 (quiet_receiver_dhcp_move): Bob's
old address dies (his proxy) while he is away, he comes back on another
port and sends nothing; Alice's queued message arrives exactly once within
30 s through her beacon alone (no route hint learned, her book unchanged).
s82 (beacon_capture_has_no_marker): a Sniffer, Alice and Bob, and Carol, a
stranger holding both as contacts; eight bus moves with a search each, then
Carol's searches: at least 12 distinct queries and 6 answers, every datagram
160..=191 or 48..=63 bytes (Phase 6b W-B3: a random tail on each, so the
lengths vary), no 4-byte window the same in every query or every answer,
no key, rvn1 address, fingerprint, PeerId, 'rvn1', 'raven', loopback address
or listener port in the clear; Carol gets no answer and Alice and Bob send
her none. s83 (lan_off_on, P3.6's s53): `raven lan off` on Bob closes his
port within 2 s and takes his beacon off the bus; Alice's message waits,
her beacon asks and the Sniffer hears nothing from Bob; `raven lan on`
delivers it exactly once within 30 s. Since P3.C2, s86
(meeting_mode_closes_on_time; LabClock on both profiles): Bob runs `raven
lan on --for 30m`; 31 minutes later on both clocks his port refuses within
seconds, his `raven lan status` says when listening stopped, and Alice's
message waits (queued); `raven lan on` on Bob delivers it exactly once
within 30 s, with no new send; meanwhile (P3.12) his beacon has left the bus
and the Sniffer hears nothing from it. Since P3.C3, s87 (beacon_clock_skew;
the beacon on the scenario's lab bus, LabClock on Bob): Bob 8 minutes
ahead, each finds the other three times at its listener across bus moves,
and the matches made only at the epoch next to theirs, at a time in the
receiver's epoch that shows more than five minutes, give clock rows (`raven
status`: Bob's clock about N min or more ahead on Alice's, Alice's about N
min or more behind on Bob's, N from 5 to 8: the bound shown, never more
than the 8 minutes; review A-3); Bob 25 minutes ahead and on
a new port, with nothing to send, sends no join round (owner decision
OD-C7), Alice's message to him waits, her beacon cannot find him, and her
nearby search row says no answer from Bob and to check that both laptops
show the same time. Since P3.C5, s91 under RAVEN_FAULT_BEACON=1 also
records the beacon's part (Bob answered Alice's query; within_15_s): the
delivery still comes at Alice's next try, since a query names Bob only
when her outbox wants him and Bob, with nothing waiting, sends no join
round (OD-C7's stated cost), so the bound stays her next try. With
RAVEN_FAULT_CUSTODY=1 as well, the beacon versions of the custody walks
(route hints off, the beacon carries every find): s96
(custodian_walks): Bob back first, then Carol on a new port; her join
round names Bob, he answers and fetches the message exactly once within
30 s of her start, his ACK reaches Alice through Carol, Carol ends empty;
its variant (moved/) brings Bob back on a new port too. s97
(three_people_two_rooms): each room a bus of its own and everyone on a
new port in every room, no address typed, the same checks and no RRH1.
And s88 (hotspot_isolation_ap_custodian): C1 and C2 on a SplitBus where
each hears only AP, their custodian, and on new ports: C1's message is
queued (no find for C2), left with AP within 60 s, fetched by C2 exactly
once within 60 s, and the ACK comes back to C1 within 150 s; neither
client ever finds the other.
RAVEN_FAULT_RENEW=1 (Phase 3 P3.15) gives every ash and raven-node session
renewal (its debug switch RAVEN_LAB_SESSION_RENEWAL=1), so any other list
runs with renewal on, and records each scenario's renewals
(renewed_lines): a scenario that moves no clock a day ahead keeps every
session above 12 h, and a renewal there fails it. It selects s85
(session_renewed_before_it_ends): Alice's first send starts an 11 h session
(RAVEN_LAB_SESSION_LIFETIME_MS on that `ash send` only); Bob, who did not
start it, renews it once (`renewed a session (primary`) and both advertise
`session_renewal`; Bob goes down, Alice's message is queued `in about N h`
with N >= 23 (not 11), and is delivered once when he is back on his port;
his reply is delivered, and no further renewal follows. s85b
(fallback_when_the_contact_does_not_renew): Bob runs without the switch,
Alice's session lasts 9 h 30 min, so she renews it herself (`(fallback`),
Bob logs none, and the same delivery checks hold.
s94 (also by default; cutoff study, a Phase 5 scenario of P5.9; LabClock
shared by both profiles): Alice and Bob pair, both stop, the clock moves 25 h
ahead, Alice starts again and sends 3 while Bob is away, then Bob is back.
Horizon gate closed: each is NOT SENT with CP.6's 'secure connection with Bob
ended' text and her history holds no `queued` row for them; with
RAVEN_FAULT_HORIZON=1 each is parked and all 3 reach Bob once and in order.
RAVEN_FAULT_HORIZON=1 (Phase 5 P5.9, the long message horizon, design
docs/design/2026-10-beyond-24h.md) gives every ash and raven-node the
horizon's debug switch (RAVEN_LAB_HORIZON=1 with the Lab Test A unlock), so
any other list runs with it on, and selects s60-s60c; each moves a LabClock
of its own shared by Alice and Bob. s60
(offline_three_days_sender_online): Bob away, two messages queued, the clock
25 h ahead: Alice's restarted node prunes the session and lists both as
waiting (history queued); at 72 h a third send is parked (HORIZON_PARKED,
never NOT SENT); Bob back on his port: all 3 reach him once and in order
within 60 s, her history says delivered, and one horizon step logged
`resealed=3`. s60b (offline_past_deadline): the same two, Bob back after 7
days and 1 hour: both expired with 'time ran out before Bob could be
reached', nothing reaches him and his store holds no session (no PairInit).
s60c (clock_back_while_parked): with both parked the clock moves 2 days back,
then 3 ahead: the deadlines never move, and each is delivered once, sealed
again once.
RAVEN_FAULT_LETTER=1 (Phase 5 P5.16, sealed letters, RAL1) gives every ash
and raven-node the letter gate's debug switch (RAVEN_LAB_LETTER=1 with the
horizon's and the Lab Test A unlock), so s30 under RAVEN_FAULT_CUSTODY=1 runs
with letters on (its message may go as a letter), and selects s61-s62, s75
and s76-s76c: Alice, Bob and Carol (custody on, listed by both for each
other) on one LabClock with friend custody's timers. s61
(offline_three_days_via_friend_letter): Bob away, Alice sends, Carol holds
one letter; Alice away, Bob back at 72 h takes it (once) and leaves his
REPLY; Alice back at 73 h: delivered, Carol holds no letter. s61b
(letter_then_direct_return; only Alice lists Carol): Bob back at 48 h while
Alice is online: the letter session is completed directly, one inbox row,
Carol emptied by Alice's withdraw. s62 (letter_base_ops_custodian): Carol
with RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1: no letter anywhere, the base deposit
and s30's 60 s bounds. s75 (letter_mule_two_rooms): s61 with Carol between
two rooms, Bob at 30 h and Alice at 50 h, never running together. s76
(letter_week): Bob back at 6 d 23 h: delivered. s76b
(letter_week_ran_out): at 7 d 1 h the letter is gone, nothing reaches Bob,
and Alice's outbox says when it ran out on this computer's clock. s76c
(twenty_in_one_day): 20 sends, 16 in the day's letter session and 4 parked,
the next day's session takes the 4; all 20 reach Bob once and in order.
RAVEN_FAULT_HANDOFF=1 (Phase 5 P5.23, multi-hop custody, RHW1) gives every
ash and raven-node the handoff gate's debug switch (RAVEN_LAB_CUSTODY_HANDOFF=1
with the Lab Test A unlock and the forwarder's 500 ms interval), so s30 under
RAVEN_FAULT_CUSTODY=1 runs with it on and passes only when no HANDOFF frame
is sent (Carol, a custodian both list, turns handoff on: Alice's worker
leaves nothing to pass on and Carol's handoff row counts no forward row), and
selects s68-s71 and s97b: Alice and Bob each list a friend of their own (Fred,
Gina) who know each other but not the far end; Alice and Bob pin the far
friend by key only, route hints on. s68 (two_friends_chain, carrier_matrix
C54 with timings): Bob away, Alice's message is left with Fred to pass on,
handed to Gina; Alice away, Bob fetches it and his ACK goes Gina -> Fred;
Alice back fetches the ACK: delivered, exactly once, Alice and Bob never
together, and no file of Fred's names Bob (sealed files opened), none of
Gina's names Alice. s69 (mule_hands_on_later): Gina is away when Fred takes
it; she comes back on her port and Fred hands it on; Bob fetches it once.
s70 (new_session_tags_late): a 60 s first session; Alice's next message
pairs again while Gina is away, and Bob leaves before he could register the
new tags: Gina answers TAG_UNKNOWN and Fred keeps the row; Bob back
registers, Fred delivers, Bob fetches it once. s71 (old_or_closed_custodian,
C55): Fred behind a closed link gate (HOLD) and then with
RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1 (UNSUPPORTED): a mutual custodian holds
each message, Fred keeps no forward row or tag, no strike, and after the
UNSUPPORTED Fred still takes a plain deposit. s97b (two_friends_ran_out, the
cutoff addendum's s97 on the chain, one LabClock): 25 h later Fred and Gina
hold nothing, Alice's outbox says when time ran out (local time), nothing
reaches Bob.
RAVEN_FAULT_NEARBY=1 (Phase 5 P5.28, Bluetooth nearby,
protocol/RAVEN_NEARBY_LINK_V1.md; its gate closed) selects s63-s66 and
s72-s74, and with RAVEN_FAULT_CUSTODY=1 also s67, s67b and s128. Their nodes run with the
nearby lab switch (RAVEN_LAB_NEARBY=1 with the Lab Test A unlock) on the
scenario's own fake Bluetooth ether (`raven-node nearby-ether`, loopback
only; EtherHub), never a real radio. The contacts meet once on the LAN, then
their saved LAN addresses become dead ports, without the LAN beacon,
internet or p2p: nearby is the only path. s63 (nearby_happy_path): 3
messages each way, each once and in order, delivered in the history. s64
(link_drop_mid_transfer): the hub cuts the link in the middle of a 48 KB
message; the outbox's next try delivers it once. s65 (radio_off_on): Bob's
Bluetooth off (his `raven nearby status` says so, with the fix), Alice's 3
messages wait; on again: all 3 once and in order within 60 s. s66
(stale_session_repaired): 25 h on one LabClock; Alice's send is NOT SENT
cleanly (nothing waits), then `raven nearby on @bob` and the next send sets
up a new session over nearby, delivered once, and Bob's reply comes back.
s67 (mule_via_a_friend): Carol keeps mail and advertises for whom she
holds it for (nearby background mail); Alice leaves her message to Bob with
Carol over nearby; Alice's radio off, Bob's on: he collects it from Carol
once. s67b (deposit_on_encounter, review nearby-7): Alice's message to Bob
backs off while Bob and Carol are out of range; when Carol comes into range
the pipe makes Alice retry what Carol may carry at once (within 30 s, not
after the backoff), and Bob collects it from Carol once. s72 (nearby_background_encounter; RAVEN_LAB_NEARBY_FOREGROUND_MS
shortens the 15 min): radios that meet after the user's work ran out get
nothing in 45 s without background mail, and the message with it. s73
(nearby_clock_skew; a LabClock each): Bob 20 min ahead (two token epochs):
nothing in 45 s; 10 min ahead (one epoch): delivered once, and Alice's
`raven status` gives CP.7's clock wording for Bob. s74
(three_contacts_in_range): 2 messages for each of three contacts in range at
once: at most 2 advertised for at a time, every queue drains, each message
once and in order. s128 (nearby_only_carry_chain, offline mesh carry
research Phase 0, the field test's T1/T2): Alice has the LAN only, Carol is
the bridge (LAN and the ether, mail friend of both, background mail on with
`raven nearby background-mail on --yes`), Bob is Bluetooth only for Raven
(RAVEN_LAB_NEARBY_ONLY=1, after one LAN meeting): Alice's 3 go to Carol over
the LAN and reach Bob over nearby once each within 5 minutes of his radio
coming on, receipts back to Alice; Bob's 3 go to Carol over nearby and reach
Alice over the LAN, receipts back to Bob; Bob's log, outbox and TCP
connections show nearby alone.
RAVEN_FAULT_LEARNING=1 (Phase 6a P6.18, learning connectivity, its gate
held) gives every ash and raven-node learning's debug switch
(RAVEN_LAB_LEARNING=1) and the harness timings
RAVEN_LAB_LEARNING_TUNE=60,15,3600 (so s30 under RAVEN_FAULT_CUSTODY=1 runs
with learning on too), and selects s100-s104 and s106, with
RAVEN_FAULT_CUSTODY=1 also s105. Each runs its nodes on a lab network tag
of its own, with the Lab Test A unlock, no route hints and no beacon
(learning_env); Bob's LAN route goes through a LinkProxy, which reads the
dialer's records (a probe writes 4, a link with frames more) and whose
black hole is a connect that gets no answer. s100 (learning_flaky_lan):
16 sends on a 5 s cadence while the LAN flaps black hole / pass every 4
sends (20 s), with learning and without (the static order: the lab's
route memory cleared before each send): learning's total send time is at
most 0.6x, fewer sends pay the LAN wait, each message once, at most 2
duplicates.
s101 (learning_per_network): RAVEN_LAB_NET_TAG home / office (a restart
each move), the office LAN a black hole: Internet first at the office
after one wait, LAN first at home at once, each network its own row.
s102 (learning_reset_and_off): `learning reset --contact bob`, `off
--forget` (learning.bin deleted), `on`: the static order after each, and
node_policy.json changed by ash alone. s103 (probes_revive_a_healed_lan;
tune 300,15,3600, up to 35 min): the LAN dead 3 min, then healed and quiet:
frame-less probes bring LAN first back, none carries a frame, within the
budget. s104 (learning_ages_out; LabClock +3 d, the send before the
explorer's first tick, so no probe ran): LAN first again purely by
decay, the row cold or kept. s105
(carry_choice_by_encounters; LabClock): Bob's announced friend Gus and
Alice's listed Fay; Alice meets Fay each day, never Gus: her mail for
Bob is left with Fay first (`Left with Fay first (you meet often`), at most
two friends; off, Gus then Fay; Bob back next to Fay gets each once and
the receipts credit Fay; two more expire (+25 h) and Fay's record falls.
s106 (learning_never_probes_strangers): a stranger behind a contact's old
route, a blocked and an unverified contact get no probe (their proxies
count none); every probe goes to the active verified contact.
Scenario numbers, one registry for every phase (Phase 6 P6.1; the same
registry is in carrier_matrix.rs): Phases 0-1: C1-C16, s01-s38b. Phase 2:
C17-C26 (+C7f), C35 (F9), s32b-s32e, s39-s49 (+s48c, s48o). Cutoff pack:
C36-C39, s90-s93, s95-s99 (+s90p, s91b, s93b, s96w). Privacy pack: C87,
C90-C93, s117, s120-s129. Phase 3: C27-C34, s80-s89 (+s85b). Phase 4:
C40-C49 (uses C40-C46), s50-s59 (uses s50-s53). Phase 5: C50-C69 (uses
C50-C56; C56 is the cutoff study's), s60-s79 (+b/c variants), plus s94 and
s97b inside the cutoff block (registered by CP.1). Phase 6a: C70-C79 (uses
C70-C74), s100-s109 (uses s100-s106), real rows L1-L4. Phase 6b: C80-C89
(C87 is the privacy pack's), s110-s119 (s117 is the privacy pack's), real
rows R30-R35 and R37 (R34 is the privacy pack's; R36 dropped). Phase 6c:
C100-C109, s130-s145. The cutoff study's C40-C44 are C35, C36, C37 (not
built, OD-C5), C38 and C56 in carrier_matrix.rs; C39 is M0's. Phase 6 also
holds RIH1/RLX1 caps bits 9 (PAD1) and 10 (RUP1), RRH1 entry type 0x08
(T_PAIR_SEED, the next free type in the route hints spec's own range), RLX1
entry type 0x7E (padding), rendezvous medium 0x03 (link knock), the local
event codes SEC_* 1-78 (docs/SECURITY_EVENTS.md: local, not wire) and the
at-rest kinds 11 (capability floor), 12 (pair seeds), 22 (learning store)
and 23 (update state) that at_rest::Kind reserves, then 96 and up.
Taken by the privacy pack (PP.19): carrier_matrix C87, C90 and C91
(C92 and C93 are free), s117 and s120-s125 here (s126-s129 are free).
Phase 3 (P3.0, P3.C0): its plan steps take C27-C34, s80-s85b and
s30p/s30w/s30r, and use s04; its cutoff steps (P3.C1-P3.C8) take s86-s89;
C35-C39 and s90-s99 stay the cutoff pack's.
Phase 4 (P4.0): C40-C49, s50-s59; real rows R2b, R2c, R8w, R8p, R8m and
R25-R27 (the plan's R15-R17; Phase 2 holds R15-R20). Phase 5: C50-C69
(C56 stays the cutoff pack's), s60-s79; real rows R28-R29 (the plan's
R18-R19) and N1-N12. Taken by multi-hop custody (P5.23): carrier_matrix C54,
C55, s68-s71 here and the cutoff addendum's s97b.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import zlib
from pathlib import Path

# The caller's own settings that a node falls back to when a scenario passes
# no flag (the same list carrier_matrix's Profile::env drops): an Internet
# listener (RAVEN_INTERNET_LISTEN=0.0.0.0:7422 would make every node bind
# 7422), p2p listen ports, relays to dial (a real VPS relay in RAVEN_P2P_RELAYS)
# or the relay role itself (RAVEN_P2P_RELAY=1), another data dir or peer, the
# caller's keystore (a vault backend or its passphrase), a trace log, and
# verbose output. Each would silently change what s35-s38 measure.
CALLER_SETTINGS = (
    'RAVEN_INTERNET_LISTEN', 'RAVEN_P2P_LISTEN', 'RAVEN_P2P_RELAYS', 'RAVEN_P2P_RELAY',
    'RAVEN_PEER', 'RAVEN_DATA_DIR', 'ASH_DATA_DIR', 'ASH_LAN_DIAL',
    'RAVEN_KEYSTORE_PASSPHRASE', 'RAVEN_KEYSTORE_PASSPHRASE_FILE', 'RAVEN_KEYSTORE_BACKEND',
    'RAVEN_TRACE_LOG', 'RAVEN_VERBOSE', 'ASH_VERBOSE',
    # ash's cap on a service log it redirected: raven-node would truncate
    # these logs (stdout and stderr are the node's log file here).
    'RAVEN_SERVICE_LOG_MAX_BYTES',
    # Phase 4 (P4.1): the caller's proxy settings, Raven's own and the usual
    # variables; every node runs with RAVEN_P2P_PROXY=off instead
    # (harness_env), so this computer's own proxy is never used either.
    'RAVEN_P2P_PROXY', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy',
    'NO_PROXY', 'no_proxy',
)
# Debug lab switches a scenario sets itself when it needs one. Hole punching
# keeps the production rule (global addresses only) unless a scenario sets
# RAVEN_LAB_P2P_LOCAL_CANDIDATES (s36 (a): loopback candidates); `--p2p-listen
# relay` is retired (it listens on 7423 anyway) unless a scenario asks for the
# no-listener switch RAVEN_LAB_P2P_RELAY_ONLY.
LAB_SWITCHES = (
    'RAVEN_LAB_TEST_A', 'RAVEN_LAB_NETWATCH_EVENTS', 'RAVEN_LAB_NET_TAG',
    'RAVEN_LAB_P2P_PING', 'RAVEN_LAB_P2P_LOCAL_CANDIDATES', 'RAVEN_LAB_P2P_RELAY_ONLY',
    # Friend custody's: only s30 sets its two timers (CUSTODY_ENV); a caller's
    # WAN unlock or old-peer pretence would change what every scenario runs.
    'RAVEN_LAB_CUSTODY_AFTER_MS', 'RAVEN_LAB_CUSTODY_FETCH_MS', 'RAVEN_LAB_CUSTODY_WAN',
    'RAVEN_LAB_CUSTODY_PRETEND_OLD',
    # Phase 5 (P5.13): a custodian without the letter ops; s62 sets it.
    'RAVEN_LAB_CUSTODY_BASE_OPS_ONLY',
    # Phase 5 (P5.17): multi-hop custody's lab unlock, never a caller's value;
    # (P5.21) the forwarder's interval while rows wait.
    'RAVEN_LAB_CUSTODY_HANDOFF', 'RAVEN_LAB_CUSTODY_FORWARD_MS',
    # Route hints (RRH1): on for every node only with RAVEN_FAULT_HINTS=1
    # (HINTS), so a caller's own value never decides what s04 measures; the
    # announcer hold is carrier_matrix C20's only.
    'RAVEN_LAB_ROUTE_HINTS', 'RAVEN_LAB_HINTS_NO_ANNOUNCE',
    # Friend relays (Phase 2): off unless a scenario sets them, so a caller's
    # value never turns the Phase 1 scenarios (s35-s38) into Phase 2 runs.
    'RAVEN_LAB_FRIEND_RELAY', 'RAVEN_LAB_FRIEND_RELAY_LISTEN', 'RAVEN_LAB_RELAY_SELECT',
    'RAVEN_LAB_P2P_PROFILE_RELAY',
    # The cutoff pack's: on only with RAVEN_FAULT_OFFLINE=1 (OFFLINE), the
    # clock and gateway only where a scenario sets them.
    'RAVEN_LAB_OFFLINE', 'RAVEN_LAB_NOISE_PIN', 'RAVEN_LAB_LAN_DEFAULT_PORT',
    'RAVEN_LAB_LAN_GATEWAY', 'RAVEN_LAB_CLOCK_FILE',
    # The privacy pack's (PP.1): the harness sets RAVEN_LAB_AT_REST=1 and
    # RAVEN_LAB_ERASE_ROOT=<the run's root> itself (privacy_env), never the
    # caller's values; the other four only where a scenario sets them.
    'RAVEN_LAB_AT_REST', 'RAVEN_LAB_ERASE_ROOT', 'RAVEN_LAB_AT_REST_KEY_FAULT',
    'RAVEN_LAB_RETENTION_GRACE_MS', 'RAVEN_LAB_LOGIN_ITEM_ROOT', 'RAVEN_LAB_LOGIN_ITEM_TOOLS',
    # Phase 3 (P3.5): `--lan-listen auto`'s lab unlock and the switch that
    # counts loopback as not local (C27): only where a scenario sets them,
    # so a caller's value never changes what a node's listener admits.
    'RAVEN_LAB_LAN_AUTO', 'RAVEN_LAB_LAN_SOURCE_DENY_LOOPBACK',
    # Phase 3 (P3.8): the LAN beacon's lab unlock, never a caller's value;
    # only this harness sets it (P3.12: for RAVEN_FAULT_BEACON=1). Its port,
    # family and loopback bus (P3.10) likewise.
    'RAVEN_LAB_LAN_BEACON', 'RAVEN_LAB_LAN_BEACON_PORT', 'RAVEN_LAB_LAN_BEACON_FAMILY',
    'RAVEN_LAB_LAN_BEACON_BUS',
    # Phase 3 (P3.13): session renewal's lab unlock and the shorter lifetime
    # of the sessions a node starts, never a caller's value.
    'RAVEN_LAB_SESSION_RENEWAL', 'RAVEN_LAB_SESSION_LIFETIME_MS',
    # Phase 5 (P5.3): the horizon's and the letters' lab unlocks, never a
    # caller's value.
    'RAVEN_LAB_HORIZON', 'RAVEN_LAB_LETTER',
    # Phase 5 (P5.25-P5.28): the nearby carrier's lab unlock, its ether hub,
    # the public-address allowance and the shorter foreground, never a
    # caller's value; only the nearby scenarios set them (NEARBY_ENV).
    'RAVEN_LAB_NEARBY', 'RAVEN_LAB_NEARBY_ETHER', 'RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR',
    'RAVEN_LAB_NEARBY_FOREGROUND_MS', 'RAVEN_LAB_NET_AUDIT',
    # Offline mesh carry Phase 0: the Bluetooth-only node (no LAN, Internet
    # direct, p2p or beacon), never a caller's value; only s128 sets it.
    'RAVEN_LAB_NEARBY_ONLY',
    # Phase 5 (P5.29): the BlueZ btvirt test's opt-in (an ignored raven-node
    # test reads it; no node does), never a caller's value.
    'RAVEN_LAB_BLUEZ_BTVIRT',
    # Phase 4 (P4.1): its gates' lab switches (WSS and its proxy, port
    # mapping, IPv6 pinholes, the NAT class, PeerId rotation) and harness
    # values, only where a scenario sets them.
    'RAVEN_LAB_WSS', 'RAVEN_LAB_WSS_PROXY', 'RAVEN_LAB_PORT_MAP', 'RAVEN_LAB_V6_PINHOLE',
    'RAVEN_LAB_NAT_CLASS', 'RAVEN_LAB_NAT_CLASS_FORCE', 'RAVEN_LAB_PEER_ROTATION',
    'RAVEN_LAB_PEER_EPOCH_S', 'RAVEN_LAB_PORTMAP_GATEWAY', 'RAVEN_LAB_PORTMAP_LIFETIME',
    # Auto-reach: STUN discovery and serverless punching, their fake STUN
    # servers and timings, never a caller's value (no scenario ever asks a
    # public STUN server); only the auto-reach scenarios set them.
    'RAVEN_LAB_STUN_DISCOVERY', 'RAVEN_LAB_SERVERLESS_PUNCH', 'RAVEN_LAB_STUN_SERVERS',
    'RAVEN_LAB_STUN_REFRESH_S', 'RAVEN_LAB_PUNCH_SLOT_S',
    # Phase 6a (P6.2): learning's lab unlock, its harness timings and the
    # sealer fault (C73), never a caller's value.
    'RAVEN_LAB_LEARNING', 'RAVEN_LAB_LEARNING_TUNE', 'RAVEN_LAB_LEARNING_SEALER',
    # Phase 6b (P6.21): the eleven security gates' lab unlocks, never a
    # caller's value; only the scenarios that test a gate set its switch.
    'RAVEN_LAB_SECURITY_EVENTS', 'RAVEN_LAB_SECURITY_RESPONSES', 'RAVEN_LAB_SUITE_FLOOR',
    'RAVEN_LAB_LINK_PADDING', 'RAVEN_LAB_LINK_KNOCK', 'RAVEN_LAB_RANDOM_PORT',
    'RAVEN_LAB_PAIR_SEED', 'RAVEN_LAB_LOCAL_PROTECTION', 'RAVEN_LAB_ADVISORY',
    'RAVEN_LAB_RELEASE_BUNDLE', 'RAVEN_LAB_MESH_UPDATE',
    # Phase 6b (P6.26): the penalty box bans loopback too, never a caller's
    # value (every node here talks over loopback).
    'RAVEN_LAB_SEC_PENALTY_LOOPBACK',
    # Phase 6b (P6.44): the lab release key set, never a caller's value.
    'RAVEN_LAB_RELEASE_KEYS_FILE',
    # Phase 6b (P6.49): the lab download approval and install word (C89),
    # never a caller's value.
    'RAVEN_LAB_UPDATE_AUTO_APPROVE',
    # Phase 6b (P6.51): the lab friend that claims a newer notice than it
    # holds (C88), never a caller's value.
    'RAVEN_LAB_UPDATE_CLAIM_NEWER',
    # Groups' lab unlock, never a caller's value (raven-client's groups
    # tests set it in their own process).
    'RAVEN_LAB_GROUPS',
    # The Tor onion carrier's lab unlock, its loopback helper and that
    # helper's faults, and the race's head start, never a caller's value; no
    # scenario here reaches the real Tor network (carrier_matrix C95 sets
    # them for its own profiles).
    'RAVEN_LAB_TOR', 'RAVEN_LAB_TOR_LOOPBACK', 'RAVEN_LAB_TOR_HEAD_START_MS',
    'RAVEN_LAB_TOR_LOOPBACK_STALL', 'RAVEN_LAB_TOR_LOOPBACK_OBSOLETE',
    'RAVEN_LAB_TOR_LOOPBACK_DELAY_MS',
)
# The debug lab switches a caller's value may reach the nodes through: the
# session-reset level (the caller's opt-in to the reset scenarios, RESET_ON)
# and the Windows pipe name (ignored on Unix, where this harness runs). The
# self-test fails on any RAVEN_LAB_* name in the Rust tree in neither list.
LAB_PASS_THROUGH = ('RAVEN_LAB_SESSION_RESET', 'RAVEN_LAB_IPC_PIPE_SUFFIX')


def harness_env(base: dict) -> dict:
    """Every node's environment: `base` with the lab backends, without the
    caller's settings and lab switches, a service that ash starts by itself
    listening on loopback (never 0.0.0.0:7420), and no proxy
    (RAVEN_P2P_PROXY=off, so neither the environment's nor this computer's
    system proxy is used; s50 and s51 set their own)."""
    env = dict(base)
    for key in CALLER_SETTINGS + LAB_SWITCHES:
        env.pop(key, None)
    env.update(
        RAVEN_IDENTITY_BACKEND='locked-file',
        RAVEN_SESSION_BACKEND='locked-file',
        RAVEN_PREKEY_BACKEND='locked-file',
        RAVEN_CHAT_HISTORY_BACKEND='locked-file',
        RAVEN_ALLOW_EPHEMERAL_DATA_DIR='1',
        RAVEN_SERVICE_LAN_LISTEN='127.0.0.1:0',
        RAVEN_P2P_PROXY='off',
    )
    return env


def privacy_env(env: dict, root: Path) -> dict:
    """`env` for the nodes of a run under `root` (privacy pack PP.1): a
    debug build of the pack may seal their profiles (RAVEN_LAB_AT_REST=1) and
    erase only under `root` (RAVEN_LAB_ERASE_ROOT). Set here, never taken
    from the caller."""
    return dict(env, RAVEN_LAB_AT_REST='1', RAVEN_LAB_ERASE_ROOT=str(root))


# Files that make a folder a Raven profile (its identity bookkeeping and its
# contact book).
PROFILE_MARKERS = ('identity.backend', 'identity.binding', 'keystore.backend', 'contacts.json')


def profile_dir_refusal(path: Path, root: Path, home: Path | None = None) -> str:
    """Why `path` must not be a profile this harness creates, or '' (privacy
    pack PP.1). A build of the pack seals the profiles its nodes start in, so
    every one lies under the run's root `root`, which is neither the home
    folder nor above it, is no Raven profile itself (a live one), and neither
    lies in ~/.raven."""
    home = (home or Path.home()).resolve()
    p, r = path.resolve(), root.resolve()
    if r == home or r in home.parents:
        return f'the run root {r} is the home folder or above it'
    raven_home = home / '.raven'
    for d in (r, p):
        if d == raven_home or raven_home in d.parents:
            return f'{d} is in ~/.raven'
    if r not in p.parents:
        return f'{p} is not under the run root {r}'
    for d in (r, *(q for q in p.parents if r in q.parents)):
        if any((d / m).exists() for m in PROFILE_MARKERS):
            return f'{d} is a Raven profile'
    return ''


def require_profile_dir(path: Path) -> None:
    """Refuse (raise) a profile directory outside this run's root (OUT)."""
    why = profile_dir_refusal(path, OUT)
    if why:
        raise RuntimeError(f'refusing profile directory {path}: {why}')


# RDAP's own settings a caller may have exported (another home, a Raven data
# dir or whoami file to bind, tokens, revocations, an LLM provider): s32's
# RDAP processes see none of them, nor the caller's Raven settings.
RDAP_CALLER_PREFIXES = ('RDAP_', 'TEAM_')
RDAP_CALLER_SETTINGS = ('RAVEN_WHOAMI_FILE',)


def rdap_env(home: Path, base: dict | None = None) -> dict:
    """An RDAP process's environment in s32-s32e: the nodes' ENV (the lab
    backends, none of the caller's settings; `base` through harness_env
    instead, for the self-test), without RDAP's own caller settings, for the
    RDAP home `home` (lab unlock on, as its nodes; no bytecode written into
    the RDAP tree)."""
    env = dict(ENV) if base is None else harness_env(base)
    for key in list(env):
        if key.startswith(RDAP_CALLER_PREFIXES) or key in RDAP_CALLER_SETTINGS:
            del env[key]
    env.update(RDAP_HOME=str(home), RAVEN_LAB_TEST_A='1', PYTHONUTF8='1',
               PYTHONDONTWRITEBYTECODE='1')
    return env


# The lab clock's bound either way (raven_core::clock::LAB_CLOCK_MAX_OFFSET_MS).
LAB_CLOCK_MAX_OFFSET_MS = 400 * 24 * 3600 * 1000


class LabClock:
    """One profile's lab wall clock (cutoff pack CP.3, Phase 5 P5.1): the
    signed offset in ms that its ash and raven-node add to the system clock,
    kept in a file of the scenario's own (`path`, under its root; never
    shared between scenarios). The offset applies only in a debug build with
    the lab unlock, so `env` sets RAVEN_LAB_CLOCK_FILE and RAVEN_LAB_TEST_A=1
    together, and `attach` gives both to the node's ash and raven-node: ash
    computes deadlines and expiry texts and must see the node's clock. The
    processes read the file again at most every 200 ms, while they run. A
    jump ahead looks like a wake from sleep to netwatch (intended): a
    scenario using this expects one WOKE change per jump."""

    WOKE = 'raven-node netwatch: woke from sleep'

    def __init__(self, path: Path, offset_ms: int = 0) -> None:
        self.path = Path(path)
        self.offset_ms = 0
        self.set(offset_ms)

    def set(self, ms: int) -> None:
        """The clock `ms` off the system clock (at most 400 days either way)."""
        ms = int(ms)
        if abs(ms) > LAB_CLOCK_MAX_OFFSET_MS:
            raise ValueError(f'lab clock offset {ms} ms is beyond 400 days')
        # Replaced whole, so a reader never sees half a number.
        tmp = self.path.with_name(self.path.name + '.tmp')
        tmp.write_text(f'{ms}\n')
        os.replace(tmp, self.path)
        self.offset_ms = ms

    def advance(self, ms: int) -> None:
        """Moves the clock by `ms` (negative: back)."""
        self.set(self.offset_ms + int(ms))

    def env(self, base: dict) -> dict:
        """`base` with this clock and the lab unlock it needs."""
        return dict(base, RAVEN_LAB_CLOCK_FILE=str(self.path), RAVEN_LAB_TEST_A='1')

    def attach(self, node: 'Node') -> None:
        """The node's ash and raven-node run on this clock from their next
        start (attach before `start`, or stop and start again)."""
        node.env = self.env(node.env)


def lab_clock_self_test() -> bool:
    """LabClock writes whole signed numbers, moves both ways, refuses more
    than 400 days, and names its file and the lab unlock for a node."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'alice.clock'
        clock = LabClock(path)
        texts = [path.read_text()]
        clock.set(2 * 86_400_000)
        texts.append(path.read_text())
        clock.advance(-3 * 86_400_000)
        texts.append(path.read_text())
        try:
            clock.advance(-LAB_CLOCK_MAX_OFFSET_MS)
            refused = False
        except ValueError:
            refused = True
        env = clock.env(harness_env({'RAVEN_LAB_CLOCK_FILE': 'from-the-caller'}))
        ok = (texts == ['0\n', '172800000\n', '-86400000\n'] and refused
              and path.read_text() == '-86400000\n' and clock.offset_ms == -86_400_000
              and env['RAVEN_LAB_CLOCK_FILE'] == str(path) and env['RAVEN_LAB_TEST_A'] == '1'
              and sorted(p.name for p in Path(tmp).iterdir()) == ['alice.clock'])
    print(f"{'PASS' if ok else 'FAIL'}  lab_clock  files={texts}")
    return ok


# ── The sealed contact book (privacy pack PP.4) ─────────────────────────────
# A build of the pack seals each profile's contacts.json (RMS1) once one of its
# nodes or commands ran there. The scenarios that look into a book open it
# here, standard library only, with the lab chat-history key every process of
# this harness uses (the locked-file backends of a debug build), never a
# keychain item: K_hist = SHA-256("raven/chat-history/test-lab-key/v1" || the
# profile's real path) unwraps meta_key.rmk ("RMK1" 0x01, ChaCha20-Poly1305
# under the path-bound AAD), whose epoch key opens the book (XChaCha20-Poly1305,
# key HKDF-SHA256(salt "rvn1/meta/v1", info "meta-file")). Formats:
# docs/design/2026-10-at-rest-metadata.md section 2.

def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _rounds(s: list) -> None:
    def qr(a: int, b: int, c: int, d: int) -> None:
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 7)
    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)


_SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]


def _chacha_block(key: bytes, counter: int, nonce12: bytes) -> bytes:
    st = _SIGMA + list(struct.unpack('<8I', key)) + [counter] + list(struct.unpack('<3I', nonce12))
    w = st[:]
    _rounds(w)
    return struct.pack('<16I', *[(w[i] + st[i]) & 0xffffffff for i in range(16)])


def _hchacha(key: bytes, nonce16: bytes) -> bytes:
    st = _SIGMA + list(struct.unpack('<8I', key)) + list(struct.unpack('<4I', nonce16))
    _rounds(st)
    return struct.pack('<8I', *(st[0:4] + st[12:16]))


def _chacha_xor(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        stream = _chacha_block(key, 1 + i // 64, nonce12)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], stream))
    return bytes(out)


def _poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s, p, acc = int.from_bytes(key[16:], 'little'), (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b'\x01', 'little')) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, 'little')


def _aead_tag(key: bytes, nonce12: bytes, ct: bytes, aad: bytes) -> bytes:
    pad = lambda b: b'\x00' * ((16 - len(b) % 16) % 16)  # noqa: E731
    mac = aad + pad(aad) + ct + pad(ct) + struct.pack('<QQ', len(aad), len(ct))
    return _poly1305(_chacha_block(key, 0, nonce12)[:32], mac)


def _chacha_aead(key: bytes, nonce12: bytes, data: bytes, aad: bytes, seal: bool) -> bytes:
    """ChaCha20-Poly1305 (RFC 8439): seal `data`, or open `data` (ct || tag;
    ValueError when the tag does not match)."""
    import hmac
    if seal:
        ct = _chacha_xor(key, nonce12, data)
        return ct + _aead_tag(key, nonce12, ct, aad)
    ct, tag = data[:-16], data[-16:]
    if len(data) < 16 or not hmac.compare_digest(_aead_tag(key, nonce12, ct, aad), tag):
        raise ValueError('sealed bytes failed authentication')
    return _chacha_xor(key, nonce12, ct)


def _xchacha_aead(key: bytes, nonce24: bytes, data: bytes, aad: bytes, seal: bool) -> bytes:
    return _chacha_aead(_hchacha(key, nonce24[:16]), b'\x00' * 4 + nonce24[16:], data, aad, seal)


def _hkdf32(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    import hashlib
    import hmac
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b'\x01', hashlib.sha256).digest()


def open_rms1(raw: bytes, epoch_keys: dict) -> bytes:
    """An RMS1 file's plaintext: `"RMS1" 0x01 kind epoch nonce[24] ct tag`
    opened with the key of its epoch (`epoch_keys`: epoch -> 32 bytes)."""
    if raw[:5] != b'RMS1\x01' or len(raw) < 50:
        raise ValueError('not an RMS1 file')
    kind, epoch = raw[5], int.from_bytes(raw[6:10], 'big')
    key = _hkdf32(b'rvn1/meta/v1', epoch_keys[epoch], b'meta-file')
    aad = b'rvn1/meta-seal/v1' + bytes([kind]) + raw[6:10]
    return _xchacha_aead(key, raw[10:34], raw[34:], aad, seal=False)


def open_row(raw: bytes, epoch_keys: dict, label: str, pk: bytes) -> bytes:
    """A sealed SQLite value of a sealed profile (privacy pack PP.12-PP.14):
    `0x01 epoch nonce[24] ct tag` under the epoch's meta-row key, bound to
    its table (or `<table>.<column>`) and its row's key as stored."""
    if raw[:1] != b'\x01' or len(raw) < 45:
        raise ValueError('not a sealed SQLite value')
    epoch = int.from_bytes(raw[1:5], 'big')
    key = _hkdf32(b'rvn1/meta/v1', epoch_keys[epoch], b'meta-row')
    aad = b'rvn1/meta-row/v1' + label.encode() + b'\x00' + pk + raw[1:5]
    return _xchacha_aead(key, raw[5:29], raw[29:], aad, seal=False)


def profile_epoch_keys(profile: Path) -> dict:
    """`profile`'s epoch keys (epoch -> 32 bytes), unwrapped from meta_key.rmk
    with the lab chat-history key."""
    import hashlib
    real = os.path.realpath(profile).encode()
    k_hist = hashlib.sha256(b'raven/chat-history/test-lab-key/v1' + real).digest()
    rmk = (profile / 'meta_key.rmk').read_bytes()
    if rmk[:5] != b'RMK1\x01':
        raise ValueError('meta_key.rmk: not a key file this harness reads')
    aad = hashlib.sha256(b'raven/meta-key/v1/' + real).digest()
    payload = json.loads(_chacha_aead(k_hist, rmk[5:17], rmk[17:], aad, seal=False))
    return {e['e']: bytes.fromhex(e['k']) for e in payload['epochs']}


def sealed_plain(profile: Path, name: str) -> bytes | None:
    """`profile`'s file `name` as plaintext bytes: sealed (RMS1) once a node or
    command of this build ran there (the book since PP.4, the friend-key
    files since PP.5), or plain; None when it is missing."""
    path = profile / name
    if not path.is_file():
        return None
    raw = path.read_bytes()
    if not raw.startswith(b'RMS1'):
        return raw
    return open_rms1(raw, profile_epoch_keys(profile))


def learned_rows(node) -> list:
    """`node`'s learned_routes.json rows (sealed since privacy pack PP.6, or
    plain); [] when there is none."""
    raw = sealed_plain(node.dir, 'learned_routes.json')
    if raw is None:
        return []
    rows = json.loads(raw)
    return rows if isinstance(rows, list) else []


def book_plain(profile: Path) -> bytes:
    """`profile`'s contacts.json as JSON bytes, sealed (RMS1) or plain."""
    got = sealed_plain(profile, 'contacts.json')
    if got is None:
        raise FileNotFoundError(profile / 'contacts.json')
    return got


def noise_pins_text(profile: Path) -> str:
    """`profile`'s noise pins (M0) as JSON text: lan_noise_pins.rms once the
    profile is sealed (privacy pack PP.5), lan_noise_pins.json before; ''
    when it holds none."""
    for name in ('lan_noise_pins.rms', 'lan_noise_pins.json'):
        got = sealed_plain(profile, name)
        if got is not None:
            return got.decode()
    return ''


def book_rows(profile: Path) -> list:
    """`profile`'s contact book rows (sealed or plain)."""
    return json.loads(book_plain(profile))


def open_rvnhist2(raw: bytes, epoch_keys: dict) -> bytes:
    """A sealed profile's chat history (privacy pack PP.10): `"RVNHIST2"
    epoch nonce[24] ct tag`, XChaCha20-Poly1305 under the epoch's key
    HKDF-SHA256(salt "rvn1/meta/v1", info "history"), AAD "rvn1/history/v2"
    || epoch."""
    if raw[:8] != b'RVNHIST2' or len(raw) < 8 + 4 + 24 + 16:
        raise ValueError('not an RVNHIST2 file')
    epoch = int.from_bytes(raw[8:12], 'big')
    key = _hkdf32(b'rvn1/meta/v1', epoch_keys[epoch], b'history')
    return _xchacha_aead(key, raw[12:36], raw[36:], b'rvn1/history/v2' + raw[8:12], seal=False)


def history_entries(profile: Path) -> list:
    """`profile`'s chat history rows (dicts), oldest first; [] when there is
    none. A sealed profile's chat_history.json is "RVNHIST2" (PP.10:
    open_rvnhist2 with the profile's epoch keys); before that it is
    "RVNHIST1", a 12-byte nonce and ChaCha20-Poly1305 under the lab
    chat-history key (K_hist above), with AAD SHA-256("raven/chat-history/v1/"
    || the profile's real path)."""
    import hashlib
    path = profile / 'chat_history.json'
    if not path.is_file():
        return []
    raw = path.read_bytes()
    if raw[:8] == b'RVNHIST2':
        plain = open_rvnhist2(raw, profile_epoch_keys(profile))
        return json.loads(plain).get('entries', [])
    if raw[:8] != b'RVNHIST1' or len(raw) < 8 + 12 + 16:
        raise ValueError('chat_history.json: not a history file this harness reads')
    real = os.path.realpath(profile).encode()
    k_hist = hashlib.sha256(b'raven/chat-history/test-lab-key/v1' + real).digest()
    aad = hashlib.sha256(b'raven/chat-history/v1/' + real).digest()
    plain = _chacha_aead(k_hist, raw[8:20], raw[20:], aad, seal=False)
    return json.loads(plain).get('entries', [])


def history_bodies(profile: Path) -> list:
    """`profile`'s chat history, the bodies oldest first; [] when there is
    none (history_entries)."""
    return [entry.get('body', '') for entry in history_entries(profile)]


def sealed_book_self_test() -> bool:
    """The pure-Python primitives against RFC 8439 2.8.2, the XChaCha20 draft
    A.3.1, and the RMS1 and sealed-row vectors raven-core pins
    (formats_are_pinned); then a
    whole profile (key file and book) made here and read back."""
    import hashlib
    import tempfile
    k = bytes(range(0x80, 0xa0))
    aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
          b"the future, sunscreen would be it.")
    n12 = bytes.fromhex('070000004041424344454647')
    ok = _chacha_aead(k, n12, pt, aad, seal=True)[-16:].hex() == '1ae10b594f09e26a7e902ecbd0600691'
    n24 = bytes.fromhex('404142434445464748494a4b4c4d4e4f5051525354555657')
    sealed = _xchacha_aead(k, n24, pt, aad, seal=True)
    ok = ok and sealed[-16:].hex() == 'c0875924c1c7987947deafd8780acf49'
    ok = ok and _xchacha_aead(k, n24, sealed, aad, seal=False) == pt
    try:
        _xchacha_aead(k, n24, sealed[:-1] + bytes([sealed[-1] ^ 1]), aad, seal=False)
        ok = False
    except ValueError:
        pass
    file_key = _hkdf32(b'rvn1/meta/v1', b'\x22' * 32, b'meta-file')
    ok = ok and file_key.hex() == '050d844a3c9666d505d0858af354680921c1102d5f9a935d7bef1653106e9661'
    pinned = bytes.fromhex('524d5331010100000001' + '44' * 24 + '858ed5c86583468aaac50d6fda961e313af7')
    ok = ok and open_rms1(pinned, {1: b'\x22' * 32}) == b'[]'
    # A sealed SQLite value (PP.12-PP.14): the vector raven-core pins.
    row_key = _hkdf32(b'rvn1/meta/v1', b'\x22' * 32, b'meta-row')
    ok = ok and row_key.hex() == '860e8e55113f76d8f568ab1f6b7b5d36360ea0da9156cbe177ff7b9aa7aa6ed2'
    pinned_row = bytes.fromhex('0100000001' + '55' * 24 + 'ca8ca507005eda16525f59d8bd2a05996db87a17')
    ok = ok and open_row(pinned_row, {1: b'\x22' * 32}, 'owed_acks_v1', b'pk') == b'meta'
    try:
        open_row(pinned_row, {1: b'\x22' * 32}, 'owed_acks_v1', b'pq')
        ok = False
    except ValueError:
        pass
    with tempfile.TemporaryDirectory() as tmp:
        prof = Path(tmp) / 'p'
        prof.mkdir()
        real = os.path.realpath(prof).encode()
        k_hist = hashlib.sha256(b'raven/chat-history/test-lab-key/v1' + real).digest()
        payload = json.dumps({'v': 1, 'k_index': '11' * 32, 'epochs': [{'e': 1, 'k': '22' * 32}],
                              'current': 1}, separators=(',', ':')).encode()
        nonce = b'\x07' * 12
        aad = hashlib.sha256(b'raven/meta-key/v1/' + real).digest()
        (prof / 'meta_key.rmk').write_bytes(
            b'RMK1\x01' + nonce + _chacha_aead(k_hist, nonce, payload, aad, seal=True))
        rows = [{'petname': 'Bob', 'pub_hex': 'ab' * 32}]
        body = json.dumps(rows).encode()
        head = b'RMS1\x01\x01' + (1).to_bytes(4, 'big')
        n24 = b'\x09' * 24
        (prof / 'contacts.json').write_bytes(head + n24 + _xchacha_aead(
            file_key, n24, body, b'rvn1/meta-seal/v1\x01' + (1).to_bytes(4, 'big'), seal=True))
        ok = ok and book_rows(prof) == rows
        # The noise pins (PP.5): none, then plain, then the sealed file
        # (kind 16) in its place.
        ok = ok and noise_pins_text(prof) == ''
        pins = json.dumps({'v': 2, 'pins': [{'c': 'ab' * 32, 'd': 'cd' * 32}]}).encode()
        (prof / 'lan_noise_pins.json').write_bytes(pins)
        ok = ok and noise_pins_text(prof) == pins.decode()
        (prof / 'lan_noise_pins.json').unlink()
        head = b'RMS1\x01\x10' + (1).to_bytes(4, 'big')
        (prof / 'lan_noise_pins.rms').write_bytes(head + n24 + _xchacha_aead(
            file_key, n24, pins, b'rvn1/meta-seal/v1\x10' + (1).to_bytes(4, 'big'), seal=True))
        ok = ok and noise_pins_text(prof) == pins.decode()
        # The chat history (PP.8's s122 reads it): none, then one row.
        ok = ok and history_bodies(prof) == []
        hist = json.dumps({'entries': [{'body': 's122-m1'}]}).encode()
        aad = hashlib.sha256(b'raven/chat-history/v1/' + real).digest()
        (prof / 'chat_history.json').write_bytes(
            b'RVNHIST1' + nonce + _chacha_aead(k_hist, nonce, hist, aad, seal=True))
        ok = ok and history_bodies(prof) == ['s122-m1']
        # PP.10: the RVNHIST2 vector raven-core pins (epoch_formats_are_pinned),
        # then a sealed profile's history under its epoch key.
        pinned = bytes.fromhex(
            '52564e484953543200000001' + '66' * 24
            + '3b5af0b44f7eb440a1e1da6c314bc4dc8ed6321785e78b3c3b5cab35657b')
        ok = ok and open_rvnhist2(pinned, {1: b'\x22' * 32}) == b'{"entries":[]}'
        hist_key = _hkdf32(b'rvn1/meta/v1', b'\x22' * 32, b'history')
        epoch = (1).to_bytes(4, 'big')
        (prof / 'chat_history.json').write_bytes(b'RVNHIST2' + epoch + n24 + _xchacha_aead(
            hist_key, n24, hist, b'rvn1/history/v2' + epoch, seal=True))
        ok = ok and history_bodies(prof) == ['s122-m1']
    print(f"{'PASS' if ok else 'FAIL'}  sealed_book")
    return ok


def privacy_self_test(caller: dict) -> bool:
    """The privacy pack's harness rules (PP.1): the nodes get
    RAVEN_LAB_AT_REST=1 and the run's root as RAVEN_LAB_ERASE_ROOT, none of
    the caller's privacy switches, and a profile directory outside the run's
    root (or in ~/.raven, or in a live profile) is refused."""
    env = privacy_env(harness_env(caller), Path('/lab/run'))
    others = ('RAVEN_LAB_AT_REST_KEY_FAULT', 'RAVEN_LAB_RETENTION_GRACE_MS',
              'RAVEN_LAB_LOGIN_ITEM_ROOT', 'RAVEN_LAB_LOGIN_ITEM_TOOLS')
    eok = (env.get('RAVEN_LAB_AT_REST') == '1' and env.get('RAVEN_LAB_ERASE_ROOT') == '/lab/run'
           and not any(k in env for k in others))
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        home, run = t / 'home', t / 'home' / 'runs' / 'r1'
        (home / '.raven').mkdir(parents=True)
        live = home / 'live'
        live.mkdir()
        (live / 'identity.backend').write_text('locked-file\n')
        run.mkdir(parents=True)
        cases = {
            'ok': (run / 's01' / 'a', run, True),
            'ok_nested': (run / 's04' / 'a-hints' / 'a', run, True),
            'outside': (t / 'elsewhere' / 'a', run, False),
            'the_root': (run, run, False),
            'home_raven': (home / '.raven', run, False),
            'root_is_home': (home / 'a', home, False),
            'root_above_home': (t / 'a', t, False),
            'root_in_raven': (home / '.raven' / 'x' / 'a', home / '.raven' / 'x', False),
            'root_is_live': (live / 's01' / 'a', live, False),
            'escapes': (run / '..' / 'a', run, False),
        }
        got = {name: profile_dir_refusal(path, root, home) == ''
               for name, (path, root, _) in cases.items()}
        bad = sorted(name for name, (_, _, want) in cases.items() if got[name] != want)
    ok = eok and not bad
    print(f"{'PASS' if ok else 'FAIL'}  privacy_harness  env={eok} wrong={bad}")
    return ok


# `sizeof(sun_path)` minus the NUL, as raven_core::ipc's UNIX_SOCKET_PATH_MAX.
UNIX_SOCKET_PATH_MAX = 103 if sys.platform == 'darwin' or 'bsd' in sys.platform else 107


def node_socket_path(data_dir: Path) -> Path:
    """Where the raven-node of `data_dir` listens, as raven_core::ipc's
    `default_socket_path` decides it: `<data dir>/raven-node.sock` (the data
    dir with symlinks resolved), or, when that does not fit `sun_path`, the
    short per-user `/tmp/raven-<euid>/raven-<hash>.sock`. A long run root
    used to send every IPC request of a long scenario name (s60's
    `s60_offline_three_days_sender_online`, s105) to a socket nobody
    listens on, so its helpers (`waiting_deadlines`, `carry_rows`, ...) read
    nothing and the scenario failed, depending only on the run root's
    length."""
    base = os.path.realpath(data_dir)
    direct = Path(base) / 'raven-node.sock'
    if len(os.fsencode(str(direct))) <= UNIX_SOCKET_PATH_MAX:
        return direct
    digest = hashlib.sha256(b'raven/ipc-socket/v1\0' + os.fsencode(base)).hexdigest()[:16]
    short = Path(f'/tmp/raven-{os.geteuid()}') / f'raven-{digest}.sock'
    return short if len(os.fsencode(str(short))) <= UNIX_SOCKET_PATH_MAX else direct


def socket_path_self_test() -> bool:
    """`node_socket_path` keeps a short data dir's own socket, gives a long
    one the per-user short path (the same for a symlinked spelling of it),
    and never returns a path that does not fit `sun_path`."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        short = Path(tmp) / 'a'
        short.mkdir()
        long_dir = Path(tmp) / ('x' * 60) / ('y' * 60) / 'a'
        long_dir.mkdir(parents=True)
        link = Path(tmp) / 'l'
        link.symlink_to(long_dir)
        got_short, got_long, got_link = (node_socket_path(d) for d in (short, long_dir, link))
        fits = all(len(os.fsencode(str(p))) <= UNIX_SOCKET_PATH_MAX
                   for p in (got_short, got_long))
        ok = (got_short == Path(os.path.realpath(short)) / 'raven-node.sock'
              and got_long.parent == Path(f'/tmp/raven-{os.geteuid()}')
              and re.fullmatch(r'raven-[0-9a-f]{16}\.sock', got_long.name) is not None
              and got_link == got_long and fits)
    print(f"{'PASS' if ok else 'FAIL'}  socket_path  short={got_short.name} long={got_long}")
    return ok


def self_test() -> int:
    """`--self-test` (no build, no process): none of a caller's settings or
    lab switches reaches a node, nor an RDAP process of s32; the LabClock
    helper writes what the nodes read."""
    # The settings named here reach no node whatever CALLER_SETTINGS and
    # LAB_SWITCHES say (the cutoff pack's switches among them).
    named = ('RAVEN_KEYSTORE_PASSPHRASE_FILE', 'RAVEN_KEYSTORE_BACKEND', 'RAVEN_TRACE_LOG',
             'RAVEN_LAB_OFFLINE', 'RAVEN_LAB_NOISE_PIN', 'RAVEN_LAB_LAN_DEFAULT_PORT',
             'RAVEN_LAB_LAN_GATEWAY', 'RAVEN_LAB_CLOCK_FILE')
    caller = {key: 'from-the-caller' for key in CALLER_SETTINGS + LAB_SWITCHES + named}
    caller.update(RAVEN_SERVICE_LAN_LISTEN='0.0.0.0:7420', RAVEN_LAB_SESSION_RESET='1')

    def leaks(env: dict, base: dict) -> list:
        # The caller's own value got through (the session-reset switch may).
        return sorted(k for k, v in env.items()
                      if base.get(k) == v and k != 'RAVEN_LAB_SESSION_RESET')

    env = harness_env(caller)
    leaked = leaks(env, caller)
    ok = (not leaked and env['RAVEN_SERVICE_LAN_LISTEN'] == '127.0.0.1:0'
          and env['RAVEN_LAB_SESSION_RESET'] == '1' and env['RAVEN_P2P_PROXY'] == 'off')
    print(f"{'PASS' if ok else 'FAIL'}  harness_env  leaked={leaked} "
          f"lan_listen={env.get('RAVEN_SERVICE_LAN_LISTEN')} "
          f"p2p_proxy={env.get('RAVEN_P2P_PROXY')}")
    rdap_caller = dict(caller, RDAP_HOME='/caller/home', RDAP_RAVEN_DATA_DIR='/caller/node',
                       TEAM_REVOCATIONS='/caller/rev', TEAM_LLM_PROVIDER='caller',
                       RAVEN_WHOAMI_FILE='/caller/whoami.json')
    home = Path('/lab/rdap-bob')
    renv = rdap_env(home, rdap_caller)
    rleaked = leaks(renv, rdap_caller)
    rok = (not rleaked and renv['RDAP_HOME'] == str(home)
           and renv['RAVEN_SERVICE_LAN_LISTEN'] == '127.0.0.1:0'
           and renv['RAVEN_IDENTITY_BACKEND'] == 'locked-file'
           and renv['RAVEN_P2P_PROXY'] == 'off'
           and renv['PYTHONDONTWRITEBYTECODE'] == '1')
    print(f"{'PASS' if rok else 'FAIL'}  rdap_env  leaked={rleaked}")
    # Every lab switch the Rust tree reads is scrubbed or deliberately passed
    # on, so a new one cannot leak in unnoticed (carrier_matrix's
    # Profile::env drops the same LAB_SWITCHES).
    crates = Path(__file__).resolve().parent.parent / 'node' / 'crates'
    sok = True
    if crates.is_dir():
        names = set()
        for src in crates.rglob('*.rs'):
            names.update(re.findall(r'RAVEN_LAB_[A-Z0-9_]*[A-Z0-9]', src.read_text(errors='replace')))
        unlisted = sorted(names - set(LAB_SWITCHES) - set(LAB_PASS_THROUGH))
        matrix = crates / 'raven-node' / 'tests' / 'carrier_matrix.rs'
        text = matrix.read_text(errors='replace') if matrix.is_file() else ''
        # The names Profile::env removes: its first `for k in [...]` list.
        body = text.split('fn env(&self, cmd: &mut Command)', 1)[-1].split('] {', 1)[0]
        # (Lower-case names too: the proxy variables come in both cases.)
        dropped = set(re.findall(r'"([A-Za-z0-9_]+)"', body)) if text else set()
        unsynced = sorted(set(LAB_SWITCHES + CALLER_SETTINGS) - dropped) if text else []
        sok = not unlisted and not unsynced
        print(f"{'PASS' if sok else 'FAIL'}  lab_switches  rust_names={len(names)} "
              f"unlisted={unlisted} not_in_carrier_matrix={unsynced}")
    else:
        print('SKIP  lab_switches  (no node/crates next to this script)')
    nok = netns_scrub_self_test(crates.parent / 'scripts')
    lok = lab_clock_self_test()
    pok = privacy_self_test(caller)
    bok = sealed_book_self_test()
    spok = socket_path_self_test()
    return 0 if ok and rok and sok and nok and lok and pok and bok and spok else 1


def netns_scrubbed(script: Path) -> set:
    """The names `script`'s `unset` lines remove (continuation lines
    joined), with those of each netns_*.sh it sources (netns_restrictive.sh
    takes netns_nat_dcutr.sh's scrub)."""
    text = script.read_text(errors='replace')
    names = set()
    for m in re.finditer(r'^[ \t]*unset[ \t]+((?:[^\n]*\\\n)*[^\n]*)', text, re.M):
        names.update(re.findall(r'[A-Za-z_][A-Za-z0-9_]*', m.group(1)))
    for lib in set(re.findall(r'^[^#\n]*\bsource\s+"[^"]*/(netns_[a-z0-9_]+\.sh)"', text, re.M)):
        if lib != script.name and (script.parent / lib).is_file():
            names |= netns_scrubbed(script.parent / lib)
    return names


def netns_scrub_self_test(scripts: Path) -> bool:
    """Review E-3: every node/scripts/netns_*.sh removes each lab switch and
    proxy setting this harness scrubs (LAB_SWITCHES, the proxy part of
    CALLER_SETTINGS) and runs its processes with RAVEN_P2P_PROXY=off, so a
    caller's exported switch (they re-run under `sudo -E`) never opens a
    gate in their nodes."""
    if not scripts.is_dir():
        print('SKIP  netns_scrub  (no node/scripts next to this script)')
        return True
    proxy = ('RAVEN_P2P_PROXY', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy',
             'NO_PROXY', 'no_proxy')
    want = set(LAB_SWITCHES) | set(proxy)
    missing = {}
    for script in sorted(scripts.glob('netns_*.sh')):
        lost = sorted(want - netns_scrubbed(script))
        text = script.read_text(errors='replace')
        if 'export RAVEN_P2P_PROXY=off' not in text and 'netns_nat_dcutr.sh' not in text:
            lost.append('export RAVEN_P2P_PROXY=off')
        if lost:
            missing[script.name] = lost
    ok = not missing
    print(f"{'PASS' if ok else 'FAIL'}  netns_scrub  missing={missing}")
    return ok


if __name__ == '__main__' and sys.argv[1:] == ['--self-test']:
    sys.exit(self_test())

BIN = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
ONLY = set(sys.argv[3:])
ASH = str(BIN / 'ash')
NODE = str(BIN / 'raven-node')

ENV = privacy_env(harness_env(os.environ), OUT)
# The cutoff pack's two gates are held in this build
# (OFFLINE_LAN_PRODUCTION_ENABLED and LAN_NOISE_PIN_PRODUCTION_ENABLED false):
# RAVEN_FAULT_OFFLINE=1 opens both for every ash and raven-node (every env made
# from ENV below), and main() names a free port for RAVEN_LAB_LAN_DEFAULT_PORT
# before each scenario (offline_default_port). No lab unlock (RAVEN_LAB_TEST_A).
OFFLINE = os.environ.get('RAVEN_FAULT_OFFLINE') == '1'
if OFFLINE:
    ENV.update(RAVEN_LAB_OFFLINE='1', RAVEN_LAB_NOISE_PIN='1')
# Route hints are held in this build (ROUTE_HINTS_PRODUCTION_ENABLED=false):
# RAVEN_FAULT_HINTS=1 turns on the debug switch for every ash and raven-node
# process (each reads it itself). ENV_NO_HINTS is a node without it (s04c,
# and s90, which records release behaviour).
HINTS = os.environ.get('RAVEN_FAULT_HINTS') == '1'
# The LAN beacon is held in this build (LAN_BEACON_PRODUCTION_ENABLED=false):
# RAVEN_FAULT_BEACON=1 (Phase 3 P3.12) turns on its debug switch for every
# ash and raven-node (every env made from ENV, ENV_NO_HINTS too; the
# scenarios that keep it off say so with without_beacon), and main()
# gives each scenario a lab bus of its own before it starts (beacon_bus), so
# every datagram stays on 127.0.0.1 ephemeral ports: never UDP 7420, never a
# real interface. It selects the beacon's scenarios (s80-s84) and, since P3.C2
# and P3.C3, s86 and s87; with RAVEN_FAULT_CUSTODY=1 (P3.C5) also s88, s96's
# and s97's beacon versions (s97 runs without RAVEN_FAULT_HINTS then).
BEACON = os.environ.get('RAVEN_FAULT_BEACON') == '1'
if BEACON:
    ENV['RAVEN_LAB_LAN_BEACON'] = '1'
# Session renewal is held in this build (SESSION_RENEWAL_PRODUCTION_ENABLED
# false): RAVEN_FAULT_RENEW=1 (Phase 3 P3.15) turns on its debug switch for
# every ash and raven-node (every env made from ENV), selects s85 and s85b,
# and main() records each scenario's renewals (renewed_lines): one that never
# moves a clock keeps every session above 12 h and must have none.
RENEW = os.environ.get('RAVEN_FAULT_RENEW') == '1'
if RENEW:
    ENV['RAVEN_LAB_SESSION_RENEWAL'] = '1'
RENEWED_LINE = 'raven-node renewal: renewed a session ('
# The long message horizon is held in this build
# (LONG_HORIZON_PRODUCTION_ENABLED=false): RAVEN_FAULT_HORIZON=1 (Phase 5
# P5.9) turns on its debug switch RAVEN_LAB_HORIZON=1, with the Lab Test A
# unlock it needs, for every ash and raven-node (every env made from ENV), so
# any other list runs with the horizon on, and selects s60, s60b and s60c.
HORIZON = os.environ.get('RAVEN_FAULT_HORIZON') == '1'
if HORIZON:
    ENV.update(RAVEN_LAB_HORIZON='1', RAVEN_LAB_TEST_A='1')
# Sealed letters are held too (ASYNC_LETTER_PRODUCTION_ENABLED=false):
# RAVEN_FAULT_LETTER=1 (Phase 5 P5.16) turns on their debug switch
# RAVEN_LAB_LETTER=1 with the horizon's and the Lab Test A unlock for every
# ash and raven-node (so s30 runs with the letter gate on under
# RAVEN_FAULT_CUSTODY=1 as well), and selects s61, s61b, s62, s75 and
# s76-s76c (each with friend custody's timers, CUSTODY_ENV, and a LabClock).
LETTER = os.environ.get('RAVEN_FAULT_LETTER') == '1'
if LETTER:
    ENV.update(RAVEN_LAB_HORIZON='1', RAVEN_LAB_LETTER='1', RAVEN_LAB_TEST_A='1')
# Multi-hop custody is held too (CUSTODY_HANDOFF_PRODUCTION_ENABLED=false):
# RAVEN_FAULT_HANDOFF=1 (Phase 5 P5.23) turns on its debug switch
# RAVEN_LAB_CUSTODY_HANDOFF=1 with the Lab Test A unlock and the forwarder's
# lab interval (RAVEN_LAB_CUSTODY_FORWARD_MS=500) for every ash and raven-node
# (so s30 under RAVEN_FAULT_CUSTODY=1 runs with the handoff gate on and checks
# that no HANDOFF frame is sent), and selects s68-s71 and s97b (HANDOFF_ENV:
# friend custody's timers and route hints).
HANDOFF = os.environ.get('RAVEN_FAULT_HANDOFF') == '1'
if HANDOFF:
    ENV.update(RAVEN_LAB_CUSTODY_HANDOFF='1', RAVEN_LAB_CUSTODY_FORWARD_MS='500',
               RAVEN_LAB_TEST_A='1')
# Learning connectivity is held too (LEARNING_PRODUCTION_ENABLED=false):
# RAVEN_FAULT_LEARNING=1 (Phase 6a P6.18) turns on its debug switch
# RAVEN_LAB_LEARNING=1 with the harness timings RAVEN_LAB_LEARNING_TUNE
# (LEARNING_TUNE: probe gap 60 s, recovering gap 15 s, half-life 1 h) for
# every ash and raven-node (every env made from ENV), so any other list runs
# with learning on (s30 under RAVEN_FAULT_CUSTODY=1 too), and selects
# s100-s104 and s106, and with RAVEN_FAULT_CUSTODY=1 also s105.
LEARNING = os.environ.get('RAVEN_FAULT_LEARNING') == '1'
LEARNING_TUNE = '60,15,3600'
if LEARNING:
    ENV.update(RAVEN_LAB_LEARNING='1', RAVEN_LAB_LEARNING_TUNE=LEARNING_TUNE)


def without_beacon(env: dict) -> dict:
    """`env` with the LAN beacon held, as a release build holds it. Under
    RAVEN_FAULT_BEACON=1 this is for scenarios whose contacts must not find
    each other on one LAN: they record release behaviour, or a path that is
    tried only when the contact cannot be reached on the LAN (a relay, a
    custodian, a route hint, a route memory), or a network that dies or
    hides a contact while its node keeps running (a dead proxy, a name that
    resolves nowhere). On one lab bus the beacon would find that contact's
    listener at once; s80-s84 are the beacon's own versions of these
    faults."""
    return {k: v for k, v in env.items() if not k.startswith('RAVEN_LAB_LAN_BEACON')}


def without_horizon(env: dict) -> dict:
    """`env` with the long message horizon and the letters held, as a release
    build holds them: for a scenario that records release behaviour (s93)
    when RAVEN_FAULT_HORIZON=1 or RAVEN_FAULT_LETTER=1 gives every env made
    from ENV their switches."""
    return {k: v for k, v in env.items() if k not in ('RAVEN_LAB_HORIZON', 'RAVEN_LAB_LETTER')}


ENV_NO_HINTS = dict(ENV)
if HINTS:
    ENV['RAVEN_LAB_ROUTE_HINTS'] = '1'
# s04c's optional pre-RRH1 build (a directory holding its ash and
# raven-node), run by the side without the switch.
OLD_BIN = os.environ.get('RAVEN_FAULT_OLD_BIN', '')
# s120 and s124's build before the privacy pack (PP.1's snapshot): a
# variable of its own, since s04c's older build is another one (review
# E-harness-docs-ci-9: one setting for both ran s120 and s124 against a
# pre-RRH1 build, and gave s04c the pack's older build).
PRIVACY_OLD_BIN = os.environ.get('RAVEN_FAULT_PRIVACY_OLD_BIN', '')
# Phase 6b P6.34: PAD1 link padding is held (LINK_PADDING_PRODUCTION_ENABLED
# false). RAVEN_FAULT_PADDING=1 selects s115, whose padding nodes run with its
# debug switch RAVEN_LAB_LINK_PADDING=1 and the Lab Test A unlock (PAD_ENV);
# its optional older build is RAVEN_FAULT_PADDING_OLD_BIN=<dir with a pre-6b
# ash and raven-node>, a variable of its own like the privacy pack's (s04c's
# RAVEN_FAULT_OLD_BIN is a pre-RRH1 build).
PADDING = os.environ.get('RAVEN_FAULT_PADDING') == '1'
PADDING_OLD_BIN = os.environ.get('RAVEN_FAULT_PADDING_OLD_BIN', '')
PAD_ENV = dict(ENV_NO_HINTS, RAVEN_LAB_TEST_A='1', RAVEN_LAB_LINK_PADDING='1')
# Phase 6b P6.35: the RLK1 link knock is held (LINK_KNOCK_PRODUCTION_ENABLED
# false). RAVEN_FAULT_KNOCK=1 selects s115's knock phases, whose nodes run
# with the noise pins (M0, RAVEN_LAB_NOISE_PIN=1) and, the knocking ones, the
# debug switch RAVEN_LAB_LINK_KNOCK=1 (KNOCK_ENV; M0_ENV: pins only); the
# older build is RAVEN_FAULT_PADDING_OLD_BIN's (pre-6b, with M0).
KNOCK = os.environ.get('RAVEN_FAULT_KNOCK') == '1'
M0_ENV = dict(ENV_NO_HINTS, RAVEN_LAB_TEST_A='1', RAVEN_LAB_NOISE_PIN='1')
KNOCK_ENV = dict(M0_ENV, RAVEN_LAB_LINK_KNOCK='1')
# Phase 6b P6.36: a random LAN listen port is held
# (LISTEN_PORT_RANDOM_PRODUCTION_ENABLED false). RAVEN_FAULT_RANDOM_PORT=1
# selects s04r: route hints on and the LAN beacon held for every node
# (PORT_HINTS_ENV; the beacon would find the new port by itself), the nodes
# that pick or switch a port with the debug switch RAVEN_LAB_RANDOM_PORT=1
# and the Lab Test A unlock (RANDOM_PORT_ENV).
RANDOM_PORT = os.environ.get('RAVEN_FAULT_RANDOM_PORT') == '1'
PORT_HINTS_ENV = without_beacon(dict(ENV_NO_HINTS, RAVEN_LAB_ROUTE_HINTS='1'))
RANDOM_PORT_ENV = dict(PORT_HINTS_ENV, RAVEN_LAB_TEST_A='1', RAVEN_LAB_RANDOM_PORT='1')
# Phase 6b P6.40: Lock now v2 is held (LOCAL_PROTECTION_PRODUCTION_ENABLED
# false). RAVEN_FAULT_LOCK_V2=1 selects s116, whose locking side (its node
# and its ash) runs with the debug switch RAVEN_LAB_LOCAL_PROTECTION=1 and
# the Lab Test A unlock (LOCK_ENV).
LOCK_V2 = os.environ.get('RAVEN_FAULT_LOCK_V2') == '1'
LOCK_ENV = dict(ENV, RAVEN_LAB_TEST_A='1', RAVEN_LAB_LOCAL_PROTECTION='1')
# Phase 6b P6.51: the update harness. Its gates are held
# (ADVISORY_PRODUCTION_ENABLED, RELEASE_BUNDLE_PRODUCTION_ENABLED and
# MESH_UPDATE_PRODUCTION_ENABLED false) and no release build has a release key
# set: RAVEN_FAULT_UPDATES=1 selects s118 and s119, whose nodes and ash run
# with the three gates' debug switches, the Lab Test A unlock and the
# security events' switch (UPD_ENV), and the test release key set as the lab
# key set (updates_env); their notices, logs and releases are made with this
# build's raven-release (built with `--features release-tool`).
# RAVEN_FAULT_PHASE6=1 runs s117 with every Phase 6 switch on (PHASE6_ENV,
# route hints too: pair seeds sit on them), after its profiles passed a notice
# and a release and agreed a pair seed.
UPDATES = os.environ.get('RAVEN_FAULT_UPDATES') == '1'
UPD_ENV = dict(ENV, RAVEN_LAB_TEST_A='1', RAVEN_LAB_ADVISORY='1', RAVEN_LAB_RELEASE_BUNDLE='1',
               RAVEN_LAB_MESH_UPDATE='1', RAVEN_LAB_SECURITY_EVENTS='1')
PHASE6 = os.environ.get('RAVEN_FAULT_PHASE6') == '1'
PHASE6_ENV = dict(UPD_ENV, RAVEN_LAB_LEARNING='1', RAVEN_LAB_SECURITY_RESPONSES='1',
                  RAVEN_LAB_SUITE_FLOOR='1', RAVEN_LAB_LINK_PADDING='1', RAVEN_LAB_LINK_KNOCK='1',
                  RAVEN_LAB_RANDOM_PORT='1', RAVEN_LAB_PAIR_SEED='1',
                  RAVEN_LAB_LOCAL_PROTECTION='1', RAVEN_LAB_UPDATE_AUTO_APPROVE='1',
                  RAVEN_LAB_ROUTE_HINTS='1')
# The privacy pack's scenarios (PP.19): s120-s125 and s117 (s117 and s121
# run by default anyway). s120 and s124 need RAVEN_FAULT_PRIVACY_OLD_BIN and
# fail without it, so a forgotten setting never reads as a pass.
PRIVACY = os.environ.get('RAVEN_FAULT_PRIVACY') == '1'
# The libp2p carrier is held in this build (P2P_PRODUCTION_ENABLED=false):
# its scenarios run with the debug lab unlock. Their peers sit on different
# networks behind relays, so they run without the LAN beacon (one lab bus
# would make them LAN neighbours, and the beacon would carry what the relays
# should), and so do the friend relays' (FRIEND_ENV).
P2P_ENV = without_beacon(dict(ENV, RAVEN_LAB_TEST_A='1'))
# Nodes reachable only through their relays (no listening port): the retired
# `--p2p-listen relay`, kept by its debug test switch.
P2P_RELAY_ONLY_ENV = dict(P2P_ENV, RAVEN_LAB_P2P_RELAY_ONLY='1')
# Phase 4 (RWS1): relays over WebSocket/TLS and the HTTPS proxy of those
# dials are held in this build (WSS_PRODUCTION_ENABLED and
# WSS_PROXY_PRODUCTION_ENABLED false). RAVEN_FAULT_WSS=1 selects s50 and s51,
# whose relays and nodes run with the debug switch RAVEN_LAB_WSS=1, and the
# node behind the proxy with RAVEN_LAB_WSS_PROXY=1 and its own
# RAVEN_P2P_PROXY (the only scenarios that set one).
WSS = os.environ.get('RAVEN_FAULT_WSS') == '1'
WSS_ENV = dict(P2P_ENV, RAVEN_LAB_WSS='1')
WSS_PROXY_ENV = dict(WSS_ENV, RAVEN_LAB_WSS_PROXY='1')


class Node:
    def __init__(self, name: str, root: Path, env: dict | None = None,
                 bin_dir: str = '') -> None:
        """`bin_dir`: run another build's ash and raven-node (s04c's old
        peer); this build's by default."""
        self.env = env or ENV
        self.ash_bin = str(Path(bin_dir) / 'ash') if bin_dir else ASH
        self.node_bin = str(Path(bin_dir) / 'raven-node') if bin_dir else NODE
        self.name = name
        self.dir = root / name
        require_profile_dir(self.dir)
        self.dir.mkdir(parents=True)
        self.log_path = root / f'{name}.node.log'
        self.proc: subprocess.Popen | None = None
        self.dial = ''
        self.inet = ''
        self.address = ''
        self.pub = ''
        self.starts = 0

    def ash(self, *args: str, stdin: str | None = None, timeout: float = 120,
            extra_env: dict | None = None):
        """`extra_env`: more environment for this one command only."""
        return subprocess.run(
            [self.ash_bin, '--data-dir', str(self.dir), *args],
            input=stdin, capture_output=True, text=True, timeout=timeout,
            env=dict(self.env, **extra_env) if extra_env else self.env,
        )

    def init(self) -> None:
        out = self.ash('init').stdout
        self.address = re.search(r'^address=(\S+)', out, re.M).group(1)
        self.pub = re.search(r'^pub_hex=(\S+)', out, re.M).group(1)
        r = self.ash('prekey', 'publish')
        assert r.returncode == 0, r.stderr

    def start(self, port: int = 0, host: str = '127.0.0.1',
              inet_port: int | None = None, extra: tuple | list = (),
              bound: bool = True, listen: str = '') -> None:
        """`inet_port`: also listen for Internet direct on 127.0.0.1 (lab).
        `extra`: more service arguments (the p2p host's, say). `bound`: wait
        for the LAN listener (False: for its first failed bind instead, an
        address that is not on this computer; `dial` stays empty).
        `listen`: the `--lan-listen` value itself, in place of host:port
        (s04r's plain `auto`: the port its profile picked). A node whose
        environment carries over nearby alone (RAVEN_LAB_NEARBY_ONLY=1,
        s128) binds no LAN port: it is up once it says so and answers IPC
        (`dial` stays empty)."""
        self.starts += 1
        log = open(self.log_path, 'a')
        log.write(f'\n===== start #{self.starts} port={port} t={time.time():.1f}\n')
        log.flush()
        inet = [] if inet_port is None else ['--internet-listen', f'127.0.0.1:{inet_port}']
        self.proc = subprocess.Popen(
            [self.node_bin, 'service', '--data-dir', str(self.dir),
             '--lan-listen', listen or f'{host}:{port}', '--ble-listen', '127.0.0.1:0', *inet,
             *extra],
            stdout=log, stderr=subprocess.STDOUT, env=self.env,
        )
        deadline = time.time() + 30
        marker = f'===== start #{self.starts} '
        while time.time() < deadline:
            text = self.log_path.read_text(errors='replace')
            text = text[text.rfind(marker):]
            # Only a complete line (newline-terminated) ending in host:port.
            m = re.search(r'lan_direct: listen\S*.*?(\S+:\d+)[ \t]*\n', text)
            i = re.search(r'internet_direct: listen (\S+:\d+)[ \t]*\n', text)
            # Privacy pack PP.4: the node admits nobody until it says its
            # at-rest state (its contact book can be read from then on).
            rest = 'raven-node at_rest: ' in text or self.node_bin != NODE
            if (m and rest and (inet_port is None or i)
                    and self.ash('ipc-ping', timeout=10).returncode == 0):
                self.dial = m.group(1)
                self.inet = i.group(1) if i else ''
                return
            if (not bound and 'lan_direct failed: lan_direct bind ' in text
                    and self.ash('ipc-ping', timeout=10).returncode == 0):
                return
            if (self.env.get('RAVEN_LAB_NEARBY_ONLY') == '1' and rest
                    and NEARBY_ONLY_LINE in text
                    and self.ash('ipc-ping', timeout=10).returncode == 0):
                self.dial = ''
                return
            if self.proc.poll() is not None:
                raise RuntimeError(f'{self.name} node exited: {text[-2000:]}')
            time.sleep(0.1)
        raise RuntimeError(f'{self.name} node did not come up')

    def stop(self, hard: bool = False) -> None:
        if self.proc and self.proc.poll() is None:
            (self.proc.kill if hard else self.proc.terminate)()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self.proc = None

    def fingerprint(self) -> str:
        out = self.ash('whoami').stdout
        # The groups are not fixed-width (`ntXZ-SCgx-Cb`): read the field.
        m = re.search(r'fingerprint\s+(\S+)', out)
        assert m, out
        return m.group(1)

    def add_pinned(self, other: 'Node', tag: str, dial: str | None = None) -> None:
        r = self.ash('contact', 'add', '--address', other.address, '--pub-hex', other.pub,
                     '--petname', tag.capitalize(), '--tag', tag,
                     '--lan-dial', dial or other.dial, '--verify-fp', other.fingerprint())
        assert r.returncode == 0, r.stdout + r.stderr

    def add_pinned_internet(self, other: 'Node', tag: str) -> None:
        """Pin `other` with its Internet direct listener as the only route
        (no LAN route): `other` started with `inet_port`."""
        assert other.inet, f'{other.name} has no Internet listener'
        r = self.ash('contact', 'add', '--address', other.address, '--pub-hex', other.pub,
                     '--petname', tag.capitalize(), '--tag', tag,
                     '--internet-dial', other.inet, '--verify-fp', other.fingerprint())
        assert r.returncode == 0, r.stdout + r.stderr

    def p2p_card(self, via: str) -> str:
        """This node's card naming `via`: `raven-card/2` (`via=`), or, while
        route hints are on and `via` is a relay, `raven-card/3` (`relay=`)."""
        r = self.ash('whoami', '--card', '--via', via)
        kinds = [('raven-card/2 ', ' via=')]
        if self.env.get('RAVEN_LAB_ROUTE_HINTS') == '1':
            kinds.append(('raven-card/3 ', ' relay='))
        line = next((l for l in r.stdout.splitlines()
                     for prefix, field in kinds if l.startswith(prefix) and field in l), '')
        assert ' p2p=' in line, r.stdout + r.stderr
        return line

    def add_card(self, card: str, tag: str, fp: str | None = None) -> None:
        """Add a contact from its card; pinned when `fp` (its fingerprint) is
        given."""
        verify = ['--verify-fp', fp] if fp else []
        r = self.ash('contact', 'add', '--card', card, '--petname', tag.capitalize(),
                     '--tag', tag, *verify)
        assert r.returncode == 0, r.stdout + r.stderr

    def add(self, other: 'Node', tag: str, dial: str | None = None) -> None:
        r = self.ash('contact', 'add', '--address', other.address, '--pub-hex', other.pub,
                     '--petname', tag.capitalize(), '--tag', tag,
                     '--lan-dial', dial or other.dial)
        assert r.returncode == 0, r.stdout + r.stderr

    def send(self, tag: str, text: str, timeout: float = 120, carrier: str = '',
             extra_env: dict | None = None):
        """`carrier`: `--carrier` (auto when empty). `extra_env`: more
        environment for this one `ash send` (s85: the lifetime of the session
        it starts)."""
        t0 = time.time()
        pick = ('--carrier', carrier) if carrier else ()
        r = self.ash('send', '--contact', f'@{tag}', *pick, stdin=text + '\n', timeout=timeout,
                     extra_env=extra_env)
        return r.returncode, (r.stdout + r.stderr).strip(), time.time() - t0

    def inbox(self) -> str:
        return self.ash('inbox').stdout

    def outbox(self) -> str:
        r = self.ash('outbox', 'list')
        return (r.stdout + r.stderr).strip()

    def card(self) -> str:
        """`ash whoami --card` while this node runs: with its p2p host up a
        `raven-card/2` naming its PeerId (`p2p=`) and the relays it holds."""
        r = self.ash('whoami', '--card')
        line = next((l for l in r.stdout.splitlines() if l.startswith('raven-card/')), '')
        assert ' p2p=' in line, r.stdout + r.stderr
        return line

    def set_lan(self, tag: str, dial: str) -> None:
        """`contact set-addr @tag --lan dial`: a LAN route, the link that
        carries route hints (and relay offers) between two test nodes."""
        r = self.ash('contact', 'set-addr', f'@{tag}', '--lan', dial)
        assert r.returncode == 0, r.stdout + r.stderr

    def relay_offer(self, on: bool, external: list | None = None) -> None:
        """Consent for the friend relay as a user gives it: `ash relay offer
        on|off` (no terminal: nothing is asked), with `--external` for each
        address of `external` (the addresses it names; None or [] keeps the
        saved ones). raven-node reads the policy again once node_policy.json's
        stamp changes. In a sealed profile (every profile here) the command
        saves the addresses only in the sealed sidecar node_policy_peers.rms
        and node_policy.json without them, so a running node reads them from
        there (review E-harness-docs-ci-7: this wrote node_policy.json itself
        before, which left the relay's own address in plain and never took
        that path); both are checked."""
        args = ['relay', 'offer', 'on' if on else 'off']
        for addr in (external or []) if on else []:
            args += ['--external', addr]
        r = self.ash(*args)
        assert r.returncode == 0, r.stdout + r.stderr
        policy = json.loads((self.dir / 'node_policy.json').read_text())
        assert policy.get('relay_offer') is on, policy
        if is_rms1(self.dir / 'contacts.json'):
            assert 'relay_external' not in policy, policy
            if external:
                assert is_rms1(self.dir / 'node_policy_peers.rms'), \
                    'the relay addresses are not in the sealed node_policy_peers.rms'

    def friend_relay(self) -> dict:
        """The friend relay's relay_status.json (its own key's PeerId, listen
        addresses, counts), or {} while there is none."""
        try:
            # Sealed (RMS1 kind 30) in a sealed profile (privacy pack PP.6).
            raw = sealed_plain(self.dir, 'friend_relay/relay_status.json')
            return json.loads(raw) if raw is not None else {}
        except (OSError, ValueError):
            return {}

    def status_json(self) -> dict:
        """What the running raven-node reports about relays, as `ash doctor`
        prints it for scripts (ash has no `status --json`): its key=value
        facts (`relay_offer=yes friend_relay=up friend_relay_members=2 …
        relay_1_source=offer`) and each slot's state (`relay_1: reserved`
        gives relay_1=reserved)."""
        facts: dict = {}
        for line in self.ash('doctor').stdout.splitlines():
            line = line.strip()
            m = re.match(r'(relay_\d+): (\S+)', line)
            if m:
                facts[m.group(1)] = m.group(2)
                continue
            for token in line.split():
                key, sep, value = token.partition('=')
                if sep and re.fullmatch(r'[a-z0-9_]+', key):
                    facts.setdefault(key, value)
        return facts

    def sigstop(self) -> None:
        """Freeze the whole raven-node (SIGSTOP): a laptop asleep with its lid
        closed, every socket open and silent. macOS and Linux only."""
        os.kill(self.proc.pid, signal.SIGSTOP)

    def sigcont(self) -> None:
        os.kill(self.proc.pid, signal.SIGCONT)


# What a recording Proxy keeps of one direction of one connection.
PROXY_RECORD_CAP = 4 << 20


class Proxy:
    """Loopback TCP proxy with switchable faults (mode is read per connection;
    `kill_live` also ends the connections already open). `record` (s115):
    it also keeps what each connection carried, each direction apart
    (`streams`, `messages`); it never changes a byte."""

    def __init__(self, target: str, record: bool = False) -> None:
        host, port = target.rsplit(':', 1)
        self.target = (host, int(port))
        self.record = record
        # Per connection: [from the client, from the target].
        self.streams: list[list[bytearray]] = []
        self.mode = 'pass'          # pass | blackhole | refuse | reset_after | delay
        self.reset_after = 200      # bytes forwarded (either way) before RST
        self.reset_budget = 0       # connections still to sabotage
        self.delay = 0.0
        self.conns = 0
        self.live: list[socket.socket] = []
        self.live_lock = threading.Lock()
        self.lsock = socket.socket()
        self.lsock.bind(('127.0.0.1', 0))
        self.lsock.listen(64)
        self.addr = f'127.0.0.1:{self.lsock.getsockname()[1]}'
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self.lsock.accept()
            except OSError:
                return
            self.conns += 1
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def kill_live(self) -> None:
        """Reset (SO_LINGER 0) every connection open now, like a network that
        went away: a mode change alone only affects new connections."""
        with self.live_lock:
            live, self.live = self.live, []
        for s in live:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                s.shutdown(socket.SHUT_RD)   # wakes the pump blocked in recv
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _handle(self, client: socket.socket) -> None:
        mode = self.mode
        if mode == 'blackhole':
            # Held, never answered (`kill_live` resets it too).
            with self.live_lock:
                self.live.append(client)
            time.sleep(120)
            with self.live_lock:
                self.live = [s for s in self.live if s is not client]
            client.close()
            return
        if mode == 'refuse':
            # The old network is gone: a connect fails at once, not by timeout.
            client.close()
            return
        sabotage = mode == 'reset_after' and self.reset_budget > 0
        if sabotage:
            self.reset_budget -= 1
        try:
            upstream = socket.create_connection(self.target, timeout=5)
        except OSError:
            client.close()
            return
        # The 5 s is for the connect only: a quiet upstream (a relay
        # reservation between pings) must not end the connection.
        upstream.settimeout(None)
        budget = [self.reset_after if sabotage else None]
        lock = threading.Lock()
        with self.live_lock:
            self.live += [client, upstream]
        logs = [bytearray(), bytearray()]
        if self.record:
            self.streams.append(logs)

        def pump(src: socket.socket, dst: socket.socket, log: bytearray) -> None:
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    if self.record and len(log) < PROXY_RECORD_CAP:
                        log.extend(data)
                    if self.delay:
                        time.sleep(self.delay)
                    with lock:
                        if budget[0] is not None:
                            if len(data) >= budget[0]:
                                dst.sendall(data[:budget[0]])
                                raise ConnectionResetError('injected reset')
                            budget[0] -= len(data)
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                with self.live_lock:
                    self.live = [s for s in self.live if s not in (src, dst)]
                for s in (src, dst):
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
                        s.close()
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(client, upstream, logs[0]), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client, logs[1]), daemon=True).start()

    def messages(self) -> list:
        """`record`: each connection's `u32_be(len) || message` lengths, as
        (the client's, the target's); a cut last message is left out."""
        def lengths(buf: bytes) -> list:
            out, at = [], 0
            while at + 4 <= len(buf):
                n = struct.unpack('>I', buf[at:at + 4])[0]
                if at + 4 + n > len(buf):
                    break
                out.append(n)
                at += 4 + n
            return out
        return [(lengths(bytes(up)), lengths(bytes(down))) for up, down in self.streams]


class RelayProc:
    """A dedicated `raven-node relay` on 127.0.0.1 (its own folder, no Raven
    identity, debug lab unlock); its allow-list holds no one at first.
    `extra`: more relay arguments (`--external`, say). The relay kit's flags:
    `also_tcp` (`--also-tcp` ports: TCP-only listeners, e.g. its 443) and
    `public_host` (`--public-host`: it names every listening port at that
    host; fixed ports only). Phase 4: `wss` adds `--wss 127.0.0.1:<port>`, a
    two-protocol listener on a port of its own (WSS and raw libp2p, RWS1
    §6), and needs `env` WSS_ENV (the WSS gate's lab switch); `wss_via` is
    its `/tls/ws` address and `wss_port` its port (kept on a restart)."""

    def __init__(self, root: Path, port: int = 0, name: str = 'relay',
                 extra: tuple | list = (), also_tcp: tuple | list = (),
                 public_host: str | None = None, wss: bool = False,
                 env: dict | None = None) -> None:
        self.dir = root / name
        require_profile_dir(self.dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = root / f'{name}.log'
        self.port = port
        self.extra = tuple(extra)
        self.also_tcp = tuple(str(p) for p in also_tcp)
        self.public_host = public_host
        self.wss = wss
        self.env = env or P2P_ENV
        self.proc: subprocess.Popen | None = None
        self.via = ''
        self.peer = ''
        self.wss_via = ''
        self.wss_port = 0
        self.start()

    def start(self) -> None:
        log = open(self.log_path, 'a')
        log.write(f'\n===== relay start port={self.port} t={time.time():.1f}\n')
        log.flush()
        kit = [arg for p in self.also_tcp for arg in ('--also-tcp', p)]
        if self.public_host:
            kit += ['--public-host', self.public_host]
        if self.wss:
            kit += ['--wss', f'127.0.0.1:{self.wss_port}']
        self.proc = subprocess.Popen(
            [NODE, 'relay', '--data-dir', str(self.dir), '--listen', f'127.0.0.1:{self.port}',
             *kit, *self.extra],
            stdout=log, stderr=subprocess.STDOUT, env=self.env,
        )

        def port_of(addr: str, kind: str) -> str:
            return addr.split(f'/{kind}/', 1)[1].split('/')[0]

        deadline = time.time() + 30
        while time.time() < deadline:
            st = self.status()
            addrs = st.get('listen_addrs', [])
            # The main TCP port is not an `--also-tcp` one (with --listen
            # 127.0.0.1:0, TCP and QUIC get two different ports), nor the
            # WSS listener's, which is listed in both forms (`…/tls/ws`, and
            # plain: its port takes raw libp2p too).
            wss = [a for a in addrs if a.endswith('/tls/ws')]
            wss_ports = tuple(port_of(a, 'tcp') for a in wss)
            tcp = [a for a in addrs if '/tcp/' in a and not a.endswith('/tls/ws')]
            main = [a for a in tcp if port_of(a, 'tcp') not in self.also_tcp + wss_ports]
            # The status file of this process (a restart rewrites it), with
            # every listener open.
            if (main and len(tcp) == 1 + len(self.also_tcp) + len(wss)
                    and len(wss) == int(self.wss) and st.get('peer_id')
                    and st.get('pid') == self.proc.pid):
                self.peer = st['peer_id']
                self.via = f"{main[0]}/p2p/{self.peer}"
                self.port = int(port_of(main[0], 'tcp'))
                if wss:
                    self.wss_via = f"{wss[0]}/p2p/{self.peer}"
                    self.wss_port = int(wss_ports[0])
                return
            if self.proc.poll() is not None:
                raise RuntimeError('relay exited: '
                                   + self.log_path.read_text(errors='replace')[-2000:])
            time.sleep(0.2)
        raise RuntimeError('relay did not come up')

    def via_on(self, port: int | str) -> str:
        """This relay's `via` on TCP `port` of 127.0.0.1 (a proxy in front of
        it, say)."""
        return f'/ip4/127.0.0.1/tcp/{port}/p2p/{self.peer}'

    def status(self) -> dict:
        """relay_status.json (counts only), or {} while there is none."""
        try:
            return json.loads((self.dir / 'relay_status.json').read_text())
        except (OSError, ValueError):
            return {}

    def counts(self) -> dict:
        return self.status().get('counts', {})

    def wait_counts(self, pred, secs: float) -> dict | None:
        """The counts once `pred(counts)` holds (rewritten every 2 s)."""
        t0 = time.time()
        while time.time() - t0 < secs:
            c = self.counts()
            if c and pred(c):
                return c
            time.sleep(0.5)
        return None

    def ash(self, *args: str) -> subprocess.CompletedProcess:
        """`ash --data-dir <relay folder> <args>`."""
        return subprocess.run([ASH, '--data-dir', str(self.dir), *args],
                              capture_output=True, text=True, timeout=60, env=P2P_ENV)

    def allow(self, card: str) -> None:
        r = self.ash('relay', 'allow', '--card', card)
        assert r.returncode == 0, r.stdout + r.stderr

    def card(self) -> list:
        """The `via=` lines of `raven relay card` (stdout), in order."""
        r = self.ash('relay', 'card')
        assert r.returncode == 0, r.stdout + r.stderr
        return [l[4:] for l in r.stdout.splitlines() if l.startswith('via=')]

    def stop(self, graceful: bool = True) -> int | None:
        """SIGTERM (the relay closes its listeners and connections and exits
        0), killed after 5 s; or at once with `graceful=False`. Returns the
        exit status (None when it was not running)."""
        rc = None
        if self.proc and self.proc.poll() is None:
            (self.proc.terminate if graceful else self.proc.kill)()
            try:
                rc = self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                rc = self.proc.wait(5)
        self.proc = None
        return rc


TINY_PROXY = Path(__file__).resolve().parent.parent / 'node' / 'scripts' / 'lib' / \
    'tiny_connect_proxy.py'
# The relay's name in s50 and s51: only the proxy resolves it (to 127.0.0.1),
# so a node can reach the relay by it through the proxy alone.
PROXY_ONLY_NAME = 'relay.invalid'


class ConnectProxyProc:
    """Phase 4 (s50, s51): node/scripts/lib/tiny_connect_proxy.py, an HTTPS
    (CONNECT) proxy on 127.0.0.1 in a process of its own, which resolves
    PROXY_ONLY_NAME itself. `auth`: it answers every CONNECT 407 offering
    those schemes (`Negotiate,NTLM`: a proxy that wants a Windows sign-in)
    and tunnels nothing. `kill()` ends it at once, every tunnel with it;
    `start()` brings it back on the same port. Its log has one line per
    CONNECT and per tunnel closed (target, answer, the client's first byte,
    byte counts), never a payload."""

    def __init__(self, root: Path, name: str = 'proxy', auth: str = '') -> None:
        self.log_path = root / f'{name}.log'
        self.port_file = root / f'{name}.port'
        self.auth = auth
        self.port = 0
        self.proc: subprocess.Popen | None = None
        self.start()

    def start(self) -> None:
        self.port_file.unlink(missing_ok=True)
        args = [sys.executable, '-I', str(TINY_PROXY), '--listen', f'127.0.0.1:{self.port}',
                '--map', f'{PROXY_ONLY_NAME}=127.0.0.1', '--log', str(self.log_path),
                '--port-file', str(self.port_file)]
        if self.auth:
            args += ['--auth', self.auth]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # main() ends it after the scenario (its argv names no data dir).
        _CHILDREN.append(self.proc)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                self.port = int(self.port_file.read_text().strip())
                return
            except (OSError, ValueError):
                pass
            if self.proc.poll() is not None:
                raise RuntimeError(f'the proxy exited ({self.proc.returncode})')
            time.sleep(0.1)
        raise RuntimeError('the proxy did not start')

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(5)

    def url(self) -> str:
        return f'http://127.0.0.1:{self.port}'

    def lines(self, kind: str = '') -> list:
        """Its log lines (after the timestamp) that start with `kind`."""
        try:
            text = self.log_path.read_text(errors='replace')
        except OSError:
            return []
        rows = [l.split(' ', 1)[1] for l in text.splitlines() if ' ' in l]
        return [r for r in rows if r.startswith(kind)]


def pair(root: Path, a_dial: str | None = None, b_dial: str | None = None,
         env: dict | None = None):
    """Alice and Bob, started, each the other's contact at its listener
    (`a_dial`, `b_dial` instead when given); `env` for both (ENV)."""
    a, b = Node('a', root, env), Node('b', root, env)
    a.init(); b.init()
    a.start(); b.start()
    a.add(b, 'bob', b_dial)
    b.add(a, 'alice', a_dial)
    return a, b


def count(inbox: str, text: str) -> int:
    return len(re.findall(r'(?<![\w-])' + re.escape(text) + r'(?![\w-])', inbox))


def wait_inbox(node: Node, text: str, secs: float) -> float | None:
    t0 = time.time()
    while time.time() - t0 < secs:
        if count(node.inbox(), text):
            return time.time() - t0
        time.sleep(1)
    return None


def status_word(out: str) -> str:
    """The send outcome, from the CLI's own outcome lines."""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('status delivered') and 'confirmed receipt' in line:
            return 'DELIVERED'
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('not delivered yet'):
            return 'QUEUED'
        if line.startswith('NOT SENT'):
            return 'NOT_SENT'
        if line.startswith('sent, delivery unconfirmed'):
            return 'UNCONFIRMED'
        if line.startswith('send refused'):
            return 'REFUSED'
    return 'OTHER: ' + (out.splitlines()[-1][:80] if out else '(empty)')


# ----------------------------------------------------------------- scenarios
def s01_happy(root: Path) -> dict:
    a, b = pair(root)
    rcs = []
    for i in range(10):
        rc, out, dt = a.send('bob', f'happy-{i}')
        rcs.append((rc, status_word(out), round(dt, 2)))
    inbox = b.inbox()
    dup = [i for i in range(10) if count(inbox, f'happy-{i}') != 1]
    return dict(ok=all(r[0] == 0 for r in rcs) and not dup, sends=rcs, not_exactly_once=dup)


def s02_receiver_offline_then_back(root: Path) -> dict:
    a, b = pair(root)
    a.send('bob', 'warmup')            # establish the session first
    b.stop()
    rc, out, dt = a.send('bob', 'while-offline-1')
    b.start(port=int(b.dial.rsplit(':', 1)[1]))
    took = wait_inbox(b, 'while-offline-1', 180)
    return dict(ok=took is not None and count(b.inbox(), 'while-offline-1') == 1,
                send=(rc, status_word(out), round(dt, 1)), delivered_after_s=took,
                outbox=a.outbox()[-400:])


def s03_two_messages_while_offline(root: Path) -> dict:
    a, b = pair(root)
    a.send('bob', 'warmup')
    b.stop()
    r1 = a.send('bob', 'offline-msg-1')
    r2 = a.send('bob', 'offline-msg-2')
    r3 = a.send('bob', 'offline-msg-3')
    b.start(port=int(b.dial.rsplit(':', 1)[1]))
    t1 = wait_inbox(b, 'offline-msg-1', 180)
    time.sleep(20)
    inbox = b.inbox()
    got = {k: count(inbox, f'offline-msg-{k}') for k in (1, 2, 3)}
    return dict(ok=all(v == 1 for v in got.values()),
                sends=[(r[0], status_word(r[1])) for r in (r1, r2, r3)],
                send_text_2=r2[1][-300:], inbox_counts=got, first_after_s=t1)


def learned_entry(node: Node, other: Node) -> dict | None:
    """What `node` learned from `other`'s route hints (its
    learned_routes.json entry, counts and the LAN part), None without one."""
    try:
        entries = learned_rows(node)
    except (OSError, ValueError):
        return None
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict) and e.get('pub_hex', '').lower() == other.pub.lower():
            lan = e.get('lan') or {}
            relays = {r.rsplit('/p2p/', 1)[-1] for r in e.get('relays', [])}
            direct = e.get('direct', []) + lan.get('local_direct', [])
            ports = sorted({int(m.group(1)) for d in direct
                            for m in [re.search(r'/(?:tcp|udp)/(\d+)', d)] if m})
            return dict(generation=e.get('generation'), via=e.get('via'),
                        lan_port=lan.get('lan_port'), lan_ip=lan.get('lan_ip'),
                        relays=len(relays), relay_addrs=len(e.get('relays', [])),
                        direct=len(direct), direct_ports=ports)
    return None


def saved_lan_dial(node: Node, other: Node) -> str | None:
    """The `lan_dial` `node`'s contact book holds for `other`."""
    try:
        contacts = book_rows(node.dir)
    except (OSError, ValueError, KeyError):
        return None
    return next((c.get('lan_dial') for c in contacts
                 if c.get('pub_hex', '').lower() == other.pub.lower()), None)


def s04_receiver_address_changes(root: Path, pinned: bool = False) -> dict:
    """Bob comes back on another port. With RAVEN_FAULT_HINTS=1 his first
    link to Alice tells her the new port (RRH1 LAN_PORT: learned_by_inbound),
    her queued after-move-1 goes there, and `raven send` saves it back
    (saved_lan_dial == new). Without the switch it is the known gap.
    `pinned`: both contacts verified (s04p: the full snapshot).
    With RAVEN_FAULT_BEACON=1 (Phase 3 P3.12) the LAN beacon closes the gap
    without route hints: after-move-1 must reach Bob before his own message
    to Alice (whose query would also tell her his port), so Bob waits up to
    90 s for it before he sends (delivered_before_bob_s). With nothing
    waiting Bob sends no join round at his start (owner decision OD-C7):
    Alice's send asks her beacon for him, or, when what it found before
    the move is still fresh (2 min), her outbox does once its dial there
    failed, as soon as her beacon's 15 s between queries naming him allow
    (its retry after that, about 10-30 s on). path1 records how
    after-move-1 travelled."""
    if pinned:
        a, b = Node('a', root), Node('b', root)
        a.init(); b.init()
        a.start(); b.start()
        a.add_pinned(b, 'bob')
        b.add_pinned(a, 'alice')
    else:
        a, b = pair(root)
    a.send('bob', 'warmup')
    old = b.dial
    b.stop()
    b.start(port=0)                     # comes back on a new port (DHCP-like)
    new = b.dial
    rc, out, dt = a.send('bob', 'after-move-1')
    before_bob = None
    if BEACON:
        waited = wait_inbox(b, 'after-move-1', 90)
        before_bob = None if waited is None else round(waited, 1)
    b.send('alice', 'bob-says-hi')      # inbound traffic from the new address
    learned_by_inbound = learned_entry(a, b)
    rc2, out2, _ = a.send('bob', 'after-move-2')
    time.sleep(15)
    inbox = b.inbox()
    res = dict(ok=count(inbox, 'after-move-1') == 1 and count(inbox, 'after-move-2') == 1,
               old=old, new=new, send1=(rc, status_word(out)), send2=(rc2, status_word(out2)),
               got1=count(inbox, 'after-move-1'), got2=count(inbox, 'after-move-2'),
               hints=HINTS, learned_by_inbound=learned_by_inbound,
               saved_lan_dial=saved_lan_dial(a, b))
    if BEACON:
        # What could have told Alice the new port: a route hint naming it,
        # her beacon's finds (answered queries), or both (raven-node logs
        # no route per delivery).
        hint_port = (learned_by_inbound or {}).get('lan_port')
        res['ok'] = res['ok'] and before_bob is not None
        res.update(beacon=True, delivered_before_bob_s=before_bob,
                   path1=send_route(out), alice_beacon=beacon_counts(a),
                   hint_named_the_new_port=hint_port == int(new.rsplit(':', 1)[1]))
    return res


def s04p_pinned(root: Path) -> dict:
    """s04 with both contacts verified: Bob's hints are the full snapshot
    (an unverified contact on the LAN is told only the LAN port)."""
    return s04_receiver_address_changes(root, pinned=True)


def s04b_moved_contact_announces(root: Path) -> dict:
    """RRH1 (RAVEN_FAULT_HINTS=1): Alice and Bob learn each other's route
    hints (a message each way). Bob stops; Alice queues after-move-1. Bob
    comes back on a new port and sends nothing: his announcer sees its LAN
    listener moved (after its 10 s settle) and opens an announce link to
    Alice, who learns the new port, and her outbox delivers after-move-1
    exactly once within 30 s of Bob's start."""
    a, b = pair(root)
    warm = [status_word(a.send('bob', 'warmup-a2b')[1]),
            status_word(b.send('alice', 'warmup-b2a')[1])]
    # Bob has someone to tell: he learned Alice's hints.
    bob_knows_alice = learned_entry(b, a) is not None
    old = b.dial
    b.stop()
    rc, out, _ = a.send('bob', 'after-move-1')
    mark = log_size(b)
    b.start(port=0)
    t0 = time.time()
    took = wait_inbox(b, 'after-move-1', 30)
    took = None if took is None else round(time.time() - t0, 1)
    b_log = b.log_path.read_text(errors='replace')[mark:]
    announced = 'raven-node hints: routes changed; telling ' in b_log
    learned = learned_entry(a, b)
    new_port = int(b.dial.rsplit(':', 1)[1])
    return dict(ok=took is not None and count(b.inbox(), 'after-move-1') == 1
                and status_word(out) == 'QUEUED' and bob_knows_alice and announced
                and learned is not None and learned['lan_port'] == new_port,
                warmup=warm, old=old, new=b.dial, send=(rc, status_word(out)),
                bob_knew_alice=bob_knows_alice, announce_line=announced,
                delivered_after_start_s=took, learned=learned)


# s04c's two kinds of node: with the route-hints switch and without (the old
# peer), whatever RAVEN_FAULT_HINTS says.
ENV_HINTS = dict(ENV_NO_HINTS, RAVEN_LAB_ROUTE_HINTS='1')
# What neither side of a mixed pair may log: a frame the dispatcher refused
# (an RRH1 an old peer could not read would show here) or a failed handshake
# (an RLX1 payload an old listener could not take).
MIXED_BAD = ('dispatch:', 'not RavenEnvelopeV1')
MIXED_HANDSHAKE = re.compile(r'(?i)^.*inbound.*(?:handshake|noise|decrypt).*$', re.M)


def s04c_mixed_builds(root: Path) -> dict:
    """One node with route hints and one without, both orientations; with
    RAVEN_FAULT_OLD_BIN=<dir holding a pre-RRH1 ash and raven-node> the
    side without them runs that build (a true old peer). Verified contacts
    (the full snapshot side). 3 messages each way, each exactly once; no
    'dispatch:', 'not RavenEnvelopeV1' or failed handshake in either log;
    no learned_routes.json on either side (the old side sends no hint)."""
    rounds = {}
    for on in ('a', 'b'):
        sub = root / f'{on}-hints'
        sub.mkdir()
        nodes = {n: Node(n, sub, ENV_HINTS if n == on else ENV_NO_HINTS,
                         '' if n == on else OLD_BIN) for n in ('a', 'b')}
        a, b = nodes['a'], nodes['b']
        for n in (a, b):
            n.init()
            n.start()
        a.add_pinned(b, 'bob')
        b.add_pinned(a, 'alice')
        sends = []
        for i in range(3):
            sends.append(status_word(a.send('bob', f'mixed-{on}-a2b-{i}')[1]))
            sends.append(status_word(b.send('alice', f'mixed-{on}-b2a-{i}')[1]))
        for i in range(3):
            wait_inbox(b, f'mixed-{on}-a2b-{i}', 60)
            wait_inbox(a, f'mixed-{on}-b2a-{i}', 60)
        ib, ia = b.inbox(), a.inbox()
        once = (all(count(ib, f'mixed-{on}-a2b-{i}') == 1 for i in range(3))
                and all(count(ia, f'mixed-{on}-b2a-{i}') == 1 for i in range(3)))
        logs = {n.name: n.log_path.read_text(errors='replace') for n in (a, b)}
        bad = {name: [l for l in log.splitlines() if any(x in l for x in MIXED_BAD)]
               + MIXED_HANDSHAKE.findall(log) for name, log in logs.items()}
        learned_files = [n.name for n in (a, b) if (n.dir / 'learned_routes.json').exists()]
        for n in (a, b):
            n.stop()
        rounds[f'{on}_has_hints'] = dict(
            ok=once and not any(bad.values()) and not learned_files,
            old_build=bool(OLD_BIN), sends=sends, exactly_once=once,
            bad_lines={k: v[:3] for k, v in bad.items() if v}, learned_files=learned_files)
    return dict(ok=all(r['ok'] for r in rounds.values()), **rounds)


# What an expired route hint's entry may keep (Phase 3 P3.C1): a tombstone's
# fields and its LAN part's IP and port, with the network they belong to.
KEPT_HINT = {'pub_hex', 'generation', 'received_at_ms', 'expires_at_ms', 'via', 'offers', 'lan'}
KEPT_LAN = {'generation', 'received_at_ms', 'expires_at_ms', 'lan_port', 'lan_ip', 'local_tag'}
# What raven-node logs when its announcer tells contacts that its routes moved.
ANNOUNCE_LINE = 'raven-node hints: routes changed; telling '


def picked_lan_port(node: Node) -> int | None:
    """The LAN port `node`'s profile picked (Phase 6b P6.36: node_policy.json
    `lan_listen_port`, a plain setting), None without one."""
    try:
        port = json.loads((node.dir / 'node_policy.json').read_text()).get('lan_listen_port')
    except (OSError, ValueError, AttributeError):
        return None
    return port if isinstance(port, int) else None


def node_lan_default(node: Node, env: dict) -> str:
    """What `raven-node lan-default --data-dir <node's profile>` prints with
    `env` (the installers' answer; it opens and writes nothing)."""
    r = subprocess.run([node.node_bin, 'lan-default', '--data-dir', str(node.dir)],
                       capture_output=True, text=True, timeout=30, env=env)
    return r.stdout.strip() if r.returncode == 0 else f'exit {r.returncode}: {r.stderr[-200:]}'


def random_lan_port_ok(port: int | None) -> bool:
    """A port a profile may pick: inside 20,000-59,999 and below IANA's
    dynamic range (raven-core skips 20,000 and 49,152 and up), never 7420."""
    return isinstance(port, int) and 20_000 < port < 49_152 and port != 7420


def start_on_picked_port(node: Node) -> None:
    """Start `node` with a plain `--lan-listen auto` (raven-node takes the
    port its profile picked), only once its profile names a port and
    raven-node says so: never a start that would listen on 7420."""
    port = picked_lan_port(node)
    said = node_lan_default(node, node.env)
    if not random_lan_port_ok(port) or not said.endswith(f':{port}'):
        raise RuntimeError(f'{node.name}: no picked port to start on '
                           f'(policy {port}, lan-default {said!r})')
    node.start(listen='auto')


def s04r_random_port_learned(root: Path) -> dict:
    """Phase 6b P6.36 (RAVEN_FAULT_RANDOM_PORT=1), design B section 4.
    (new) A profile created with the switch picks its LAN port (never 7420,
    inside the range) and `raven-node lan-default --data-dir` names it; a
    profile created without the switch keeps the default port when the
    switch comes on later (`raven init` again writes nothing), and
    lan-default says 127.0.0.1:7420 for it. (moved) Alice and Bob, route
    hints on both and the beacon held, trade a message each way while Bob
    listens where his card says (127.0.0.1, an OS-chosen port standing in
    for 7420). Bob stops and his existing profile runs `raven lan port
    random` (it says the old and the new port and who needs the new card);
    Alice queues a message; Bob starts with a plain `--lan-listen auto`:
    raven-node listens on the picked port, his announcer tells Alice, and
    her message arrives exactly once within 30 s, Alice having learned the
    port node_policy.json names. (restart) Bob starts again with `auto` on
    the same port, and Alice's next message arrives once."""
    phases = {}
    sub = root / 'new'
    sub.mkdir()
    new = Node('new', sub, RANDOM_PORT_ENV)
    new.init()
    port = picked_lan_port(new)
    said_new = node_lan_default(new, RANDOM_PORT_ENV)
    old = Node('old', sub, PORT_HINTS_ENV)
    old.init()
    before = picked_lan_port(old)
    again = old.ash('init', extra_env=dict(RAVEN_LAB_TEST_A='1', RAVEN_LAB_RANDOM_PORT='1'))
    after = picked_lan_port(old)
    said_old = node_lan_default(old, RANDOM_PORT_ENV)
    phases['new'] = dict(ok=random_lan_port_ok(port) and said_new.endswith(f':{port}')
                         and before is None and again.returncode == 0 and after is None
                         and said_old == '127.0.0.1:7420',
                         picked=port, lan_default_new=said_new, existing_before=before,
                         existing_after=after, lan_default_existing=said_old)
    a = Node('a', root, PORT_HINTS_ENV)
    b = Node('b', root, PORT_HINTS_ENV)
    a.init(); b.init()
    a.start(); b.start()
    a.add(b, 'bob')
    b.add(a, 'alice')
    warm = [status_word(a.send('bob', 's04r-warmup-a2b')[1]),
            status_word(b.send('alice', 's04r-warmup-b2a')[1])]
    bob_knew_alice = learned_entry(b, a) is not None
    card = b.dial
    b.stop()
    switched = b.ash('lan', 'port', 'random',
                     extra_env=dict(RAVEN_LAB_TEST_A='1', RAVEN_LAB_RANDOM_PORT='1'))
    moved = picked_lan_port(b)
    said = (switched.stdout + switched.stderr).strip()
    rc, out, _ = a.send('bob', 's04r-after-switch')
    b.env = RANDOM_PORT_ENV
    mark = log_size(b)
    start_on_picked_port(b)
    t0 = time.time()
    took = wait_inbox(b, 's04r-after-switch', 30)
    took = None if took is None else round(time.time() - t0, 1)
    bound = int(b.dial.rsplit(':', 1)[1])
    announced = ANNOUNCE_LINE in b.log_path.read_text(errors='replace')[mark:]
    learned = learned_entry(a, b)
    phases['moved'] = dict(
        ok=switched.returncode == 0 and random_lan_port_ok(moved)
        and f'LAN port {moved} (was 7420)' in said and 'need your new card' in said
        and status_word(out) == 'QUEUED' and bob_knew_alice and bound == moved
        and took is not None and count(b.inbox(), 's04r-after-switch') == 1
        and announced and (learned or {}).get('lan_port') == moved,
        warmup=warm, bob_knew_alice=bob_knew_alice, card=card, picked=moved,
        listens=b.dial, send=(rc, status_word(out)), delivered_after_start_s=took,
        announce_line=announced, learned=learned, said=said[-400:],
        saved_lan_dial=saved_lan_dial(a, b))
    b.stop()
    start_on_picked_port(b)
    rc2, out2, _ = a.send('bob', 's04r-after-restart')
    took2 = wait_inbox(b, 's04r-after-restart', 30)
    phases['restart'] = dict(
        ok=b.dial.endswith(f':{moved}') and took2 is not None
        and count(b.inbox(), 's04r-after-restart') == 1,
        listens=b.dial, send=(rc2, status_word(out2)),
        delivered_s=None if took2 is None else round(took2, 1))
    for n in (a, b):
        n.stop()
    return dict(ok=all(p['ok'] for p in phases.values()), **phases)


def s89_weekly_meeting_keeps_the_port(root: Path) -> dict:
    """Phase 3 P3.C1 (cutoff F11c; RAVEN_FAULT_HINTS=1, LabClock on both
    profiles). Before t0 Bob's listener moves to a new port and his announce
    tells Alice (as in s04b); she sends him nothing, so her book keeps his
    old port. Both stop; 7 days pass on both clocks (the route hints expired
    after 72 h). With no node answering, Alice's next command prunes her
    learned routes: Bob's entry keeps only its LAN part (his new port).
    Bob starts on that same port and Alice on hers; neither sends. Past the
    first look of Bob's announcer (10 s) he has told nobody and no link of
    his reached her (her sighting of him is still the one from before t0).
    Alice's next message then reaches him exactly once over the port her
    expired hint kept, with no typed address, and `raven send` saves that
    address into her book. No LAN beacon under RAVEN_FAULT_BEACON=1
    (without_beacon): its find would go first, and a find is never saved."""
    ca, cb = LabClock(root / 'alice.clock'), LabClock(root / 'bob.clock')
    a = Node('a', root, env=ca.env(without_beacon(ENV_HINTS)))
    b = Node('b', root, env=cb.env(without_beacon(ENV_HINTS)))
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = [status_word(a.send('bob', 's89-warmup-a2b')[1]),
            status_word(b.send('alice', 's89-warmup-b2a')[1])]
    # Bob has someone to tell: he learned Alice's hints.
    bob_knew_alice = learned_entry(b, a) is not None
    old = b.dial
    b.stop()
    mark = log_size(b)
    b.start(port=0)                     # his listener moves (DHCP-like)
    new = b.dial
    new_port = int(new.rsplit(':', 1)[1])
    t_move = time.time()
    learned = learned_entry(a, b)
    while time.time() - t_move < 45 and (learned or {}).get('lan_port') != new_port:
        time.sleep(0.5)
        learned = learned_entry(a, b)
    learned_s = round(time.time() - t_move, 1)
    announced = ANNOUNCE_LINE in b.log_path.read_text(errors='replace')[mark:]
    a_port = int(a.dial.rsplit(':', 1)[1])
    a.stop()
    b.stop()
    book_before = saved_lan_dial(a, b)
    seen_before = lan_seen_entry(a, b)
    ca.advance(7 * DAY_MS)
    cb.advance(7 * DAY_MS)
    listed = a.ash('outbox', 'list')
    lab_now = time.time() * 1000 + ca.offset_ms
    rows = [r for r in learned_rows(a)
            if isinstance(r, dict) and r.get('pub_hex', '').lower() == b.pub.lower()]
    kept = rows[0].get('lan') if len(rows) == 1 and isinstance(rows[0].get('lan'), dict) else {}
    kept_ok = (len(rows) == 1 and rows[0].get('expires_at_ms', lab_now) < lab_now
               and set(rows[0]) <= KEPT_HINT and set(kept) <= KEPT_LAN
               and kept.get('lan_port') == new_port and kept.get('lan_ip') == '127.0.0.1')
    mark = log_size(b)
    b.start(port=new_port)              # back on that same port, silent
    t_back = time.time()
    a.start(port=a_port)                # where Bob's book and hints knew her
    time.sleep(max(0.0, 15 - (time.time() - t_back)))
    told_again = ANNOUNCE_LINE in b.log_path.read_text(errors='replace')[mark:]
    seen_at_send = lan_seen_entry(a, b)
    rc, out, send_s = a.send('bob', 's89-weekly')
    got = wait_inbox(b, 's89-weekly', 20)
    time.sleep(2)
    once = count(b.inbox(), 's89-weekly')
    book_after = saved_lan_dial(a, b)
    return dict(
        ok=warm == ['DELIVERED', 'DELIVERED'] and bob_knew_alice and new != old
        and (learned or {}).get('lan_port') == new_port and book_before == old
        and listed.returncode == 0 and kept_ok and not told_again
        and seen_before is not None and seen_at_send == seen_before
        and rc == 0 and status_word(out) == 'DELIVERED' and got is not None and once == 1
        and book_after == new,
        warmup=warm, bob_knew_alice=bob_knew_alice, old=old, new=new,
        learned_after_move=learned, learned_s=learned_s, announce_line=announced,
        book_before=book_before, kept_after_7_days=rows, kept_lan_part_ok=kept_ok,
        bob_told_someone_after_7_days=told_again,
        no_inbound_link_first=seen_at_send == seen_before,
        send=(rc, status_word(out), round(send_s, 1)), delivered_s=got, exactly_once=once,
        book_after=book_after, send_text=out[-400:], outbox=a.outbox()[-300:])


def tcp_accepts(addr: str, timeout: float = 1.0) -> bool:
    """Whether something accepts a TCP connection at `addr` (`host:port`)."""
    host, port = addr.rsplit(':', 1)
    try:
        with socket.create_connection((host.strip('[]'), int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def s86_meeting_mode_closes_on_time(root: Path) -> dict:
    """Phase 3 P3.C2 (cutoff M1, meeting mode; RAVEN_FAULT_BEACON=1, LabClock
    on both profiles). Bob runs `raven lan on --for 30m` with his node on a
    fixed loopback port (it says so: only this computer can connect, review
    B-2), and Alice's warmup reaches him. Both clocks move 31 minutes
    on: within seconds Bob's node has closed his port (a connect is refused)
    and his `raven lan status` says when listening stopped. Alice's next
    message waits (queued, not in Bob's inbox). `raven lan on` on Bob: his
    port opens again and the message arrives exactly once within 30 s, with
    no new send. Both run the LAN beacon on the scenario's lab bus (P3.12),
    and a Sniffer there hears every datagram: from the meeting time's end
    until `raven lan on`, Bob's beacon has left the bus and nothing comes
    from it, while Alice's may ask for him."""
    env, bus_file = beacon_env(root, ENV)
    sniff = Sniffer(bus_file)
    ca, cb = LabClock(root / 'alice.clock'), LabClock(root / 'bob.clock')
    a = Node('a', root, env=ca.env(env))
    b = Node('b', root, env=cb.env(env))
    a.init(); b.init()
    a.start()
    a_bus = bus_port_of(sniff, set())
    b.start(port=free_tcp_port())
    b_bus = bus_port_of(sniff, {a_bus})
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    opened = b.ash('lan', 'on', '--for', '30m')
    # Bob's node listens on loopback (one host), so the step says only this
    # computer can connect, never "Open to friends" (Phase 3 review B-2).
    opened_ok = (opened.returncode == 0 and opened.stdout.startswith('LAN on until ')
                 and 'but for this computer only: raven-node listens on 127.0.0.1:'
                 in opened.stdout
                 and 'Open to friends' not in opened.stdout
                 and 'The running raven-node turned LAN on now.' in opened.stdout)
    warm = status_word(a.send('bob', 's86-warmup')[1])
    open_before = tcp_accepts(b.dial)
    mark = log_size(b)
    ca.advance(31 * 60_000)
    cb.advance(31 * 60_000)
    t_move = time.time()
    closed_s = None
    while time.time() - t_move < 15:
        if not tcp_accepts(b.dial):
            closed_s = round(time.time() - t_move, 1)
            break
        time.sleep(0.2)
    over_line = 'the meeting time is over' in b.log_path.read_text(errors='replace')[mark:]
    # Bob's beacon leaves the bus with LAN (its entry goes with its socket).
    left_s = wait_for(lambda: b_bus not in bus_ports(sniff.dir).values(), 15)
    t_left = time.time()
    status = b.ash('lan', 'status')
    lines = status.stdout.splitlines()
    status_ok = (status.returncode == 0 and len(lines) > 1
                 and lines[0] == 'LAN: off - the meeting time is over (raven lan on --for 1h)'
                 and lines[1].startswith('Stopped listening ')
                 and lines[1].endswith('Your messages wait for the next meeting. '
                                       '`raven lan on --for 1h` opens it again.'))
    rc, out, send_s = a.send('bob', 's86-waits')
    word = status_word(out)
    time.sleep(3)
    waited = count(b.inbox(), 's86-waits') == 0 and not tcp_accepts(b.dial)
    on_bus = sorted(set(bus_ports(sniff.dir).values()) - {sniff.port})
    heard = sniff.captured(t_left)
    silent = dict(bob_left_s=left_s, bob_datagrams=sum(1 for _, p, _ in heard if p == b_bus),
                  others=sum(1 for _, p, _ in heard if p not in (a_bus, b_bus)),
                  alice_datagrams=sum(1 for _, p, _ in heard if p == a_bus),
                  on_bus_ok=on_bus == [a_bus])
    silent_ok = (a_bus is not None and b_bus is not None and left_s is not None
                 and silent['bob_datagrams'] == 0 and silent['others'] == 0
                 and silent['on_bus_ok'])
    reopened = b.ash('lan', 'on')
    got = wait_inbox(b, 's86-waits', 30)
    time.sleep(2)
    once = count(b.inbox(), 's86-waits')
    open_after = tcp_accepts(b.dial)
    return dict(
        ok=opened_ok and warm == 'DELIVERED' and open_before and closed_s is not None
        and status_ok and word == 'QUEUED' and waited and reopened.returncode == 0
        and got is not None and once == 1 and open_after and silent_ok,
        opened=opened_ok, opened_text=opened.stdout[-300:], warmup=warm,
        port_open_before=open_before, port_refused_after_s=closed_s,
        node_said_meeting_over=over_line, lan_status=status.stdout[-500:],
        lan_status_ok=status_ok, send=(rc, word, round(send_s, 1)), waited=waited,
        lan_on=reopened.returncode, delivered_s=got, exactly_once=once,
        port_open_after=open_after, bob_silent_on_the_bus=silent_ok, bus=silent,
        send_text=out[-400:])


def beacon_env(root: Path, base: dict) -> tuple[dict, Path]:
    """`base` with the LAN beacon on the lab bus for one scenario's nodes
    (Phase 3 P3.C3; since P3.12 the bus RAVEN_FAULT_BEACON=1 gives every
    node of the scenario, [`beacon_bus`]): its debug lab switch, and
    RAVEN_LAB_LAN_BEACON_BUS naming the file <root>/bus whose first line is
    the bus directory (<root>/net1 at first). Every datagram stays on
    127.0.0.1 ephemeral ports (never UDP 7420, never a real interface).
    Rewriting the line ([`move_bus`]) moves every node of the scenario to
    another bus: a network change for each. Returns the env and the file."""
    bus_file = root / 'bus'
    if not bus_file.is_file():
        move_bus(bus_file, root / 'net1')
    return dict(base, RAVEN_LAB_LAN_BEACON='1',
                RAVEN_LAB_LAN_BEACON_BUS=str(bus_file)), bus_file


def beacon_bus(root: Path) -> Path:
    """RAVEN_FAULT_BEACON=1 (Phase 3 P3.12): main() gives the scenario under
    `root` a lab bus of its own before it starts. <root>/bus names
    <root>/net1, and ENV and every env this module made from it (they carry
    RAVEN_LAB_LAN_BEACON) name that file, so the envs a scenario makes from
    them while it runs do too. A node that stops (no unwinding) leaves its
    entry behind on its bus; the next scenario's bus is another directory.
    Returns the file."""
    bus_file = root / 'bus'
    (root / 'net1').mkdir(parents=True, exist_ok=True)
    move_bus(bus_file, root / 'net1')
    for env in list(globals().values()):
        if isinstance(env, dict) and env.get('RAVEN_LAB_LAN_BEACON') == '1':
            env['RAVEN_LAB_LAN_BEACON_BUS'] = str(bus_file)
    return bus_file


def move_bus(bus_file: Path, bus_dir: Path) -> None:
    """Every node on `bus_file` moves to `bus_dir` (each reads the file again
    within a second)."""
    tmp = bus_file.with_name(bus_file.name + '.tmp')
    tmp.write_text(f'{bus_dir}\n')
    os.replace(tmp, bus_file)


def bus_members(bus_dir: Path) -> int:
    """How many nodes are registered on the bus in `bus_dir`."""
    try:
        return sum(1 for p in bus_dir.iterdir() if p.suffix == '.port')
    except OSError:
        return 0


def node_ipc(node: Node, req: dict, timeout: float = 10) -> dict:
    """One local IPC request to the node's raven-node, as ash sends it (its
    socket, `node_socket_path`; a 4-byte big-endian length, then JSON)."""
    body = json.dumps(req).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(node_socket_path(node.dir)))
        s.sendall(struct.pack('>I', len(body)) + body)
        head = s.recv(4, socket.MSG_WAITALL)
        n = struct.unpack('>I', head)[0]
        data = b''
        while len(data) < n:
            chunk = s.recv(n - len(data))
            if not chunk:
                break
            data += chunk
    return json.loads(data)


def lan_locate(asker: Node, other: Node, wait_ms: int = 1500) -> list:
    """Where `asker`'s LAN beacon finds `other` now (IPC LanLocate, as a send
    asks it): dial strings, or none."""
    r = node_ipc(asker, {'op': 'lan_locate', 'v': 1, 'peer_pub_hex': other.pub,
                         'wait_ms': wait_ms})
    return r.get('dials') or []


def nearby_row(node: Node) -> str:
    """The `nearby search` row of the node's `raven lan status` ('' when
    none)."""
    return status_row(node.ash('lan', 'status').stdout, 'nearby search') or ''


# RAVEN_LAN_BEACON_V1 §3-§5: the only datagram lengths. A query is 160
# bytes and an answer 48, each with a random tail of up to 31 (15) bytes
# since the Phase 6b amendment (W-B3), which receivers ignore.
QUERY_LEN, ANSWER_LEN = 160, 48
QUERY_LENS, ANSWER_LENS = range(160, 192), range(48, 64)
# Every Sniffer of the running scenario: main() stops what is left.
_SNIFFERS: list = []


class Sniffer:
    """Phase 3 P3.12: a listener on a scenario's LAN beacon lab bus (the bus
    file's first line names the directory). It registers a port of its own
    there as each node's beacon does, so every datagram a node sends "to
    the group" comes to it too, and it follows the bus file when the
    scenario moves the bus. It sends nothing; it records each datagram:
    when, from which bus port (the sending beacon's own), and the bytes."""

    def __init__(self, bus_file: Path) -> None:
        self.bus_file = bus_file
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.name = f'{os.urandom(8).hex()}.port'
        self.dir: Path | None = None
        self.seen: list = []
        self.lock = threading.Lock()
        self.live = True
        self._follow()
        _SNIFFERS.append(self)
        threading.Thread(target=self._run, daemon=True).start()

    def _follow(self) -> None:
        """Be registered on the directory the bus file names now."""
        try:
            named = Path(self.bus_file.read_text().splitlines()[0].strip())
        except (OSError, IndexError):
            return
        if named == self.dir:
            return
        if self.dir is not None:
            (self.dir / self.name).unlink(missing_ok=True)
        named.mkdir(parents=True, exist_ok=True)
        tmp = named / (self.name + '.tmp')
        tmp.write_text(f'{self.port}\n')
        os.replace(tmp, named / self.name)
        self.dir = named

    def _run(self) -> None:
        looked = time.time()
        while self.live:
            if time.time() - looked >= 0.2:
                self._follow()
                looked = time.time()
            try:
                data, (_, port) = self.sock.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.seen.append((time.time(), port, data))

    def captured(self, since: float = 0.0, until: float | None = None) -> list:
        """(time, bus port, bytes) of each datagram heard from `since` on
        (until `until`)."""
        with self.lock:
            return [s for s in self.seen
                    if s[0] >= since and (until is None or s[0] < until)]

    def stop(self) -> None:
        self.live = False
        if self.dir is not None:
            (self.dir / self.name).unlink(missing_ok=True)
        self.sock.close()


def stop_sniffers() -> None:
    """Stop every Sniffer of the scenario that ended (main())."""
    for s in _SNIFFERS:
        s.stop()
    _SNIFFERS.clear()


def bus_ports(bus_dir: Path | None) -> dict:
    """{entry name: port} of everything registered on the bus in
    `bus_dir` (a node's beacon, a Sniffer)."""
    ports: dict = {}
    try:
        entries = list(bus_dir.iterdir()) if bus_dir is not None else []
    except OSError:
        return ports
    for p in entries:
        if p.suffix == '.port':
            try:
                ports[p.name] = int(p.read_text().strip())
            except (OSError, ValueError):
                pass
    return ports


def bus_port_of(sniff: Sniffer, known: set, secs: float = 20) -> int | None:
    """The bus port of the beacon that registers on `sniff`'s bus next:
    the one port there that is neither the Sniffer's nor in `known` (a
    node's beacon opens once its node has loaded the profile), waited
    for."""
    new: set = set()

    def one() -> bool:
        new.clear()
        new.update(set(bus_ports(sniff.dir).values()) - known - {sniff.port})
        return len(new) == 1
    return next(iter(new)) if wait_for(one, secs) is not None else None


def beacon_counts(node: Node) -> dict:
    """The node's LAN beacon counts as IPC Status reports them
    (`lan.beacon`: state, counts, echo_ok; {} without them)."""
    try:
        status = node_ipc(node, {'op': 'status', 'v': 1})
    except (OSError, ValueError, struct.error):
        return {}
    return (status.get('lan') or {}).get('beacon') or {}


# What would name an address or a key in a log line: an IPv4 address, an
# IPv6 literal or zone, a port after a colon, a 64-hex key.
ADDRESS_LIKE = re.compile(r'\d{1,3}(\.\d{1,3}){3}|[\[\]%]|:\d|\b[0-9a-fA-F]{64}\b')


def beacon_lines(node: Node) -> list:
    """The `raven-node lan_beacon:` lines of the node's log."""
    # From the marker on: the UTC time a line starts with is no address.
    return [line[line.index('raven-node lan_beacon:'):]
            for line in node.log_path.read_text(errors='replace').splitlines()
            if 'raven-node lan_beacon:' in line]


def send_route(out: str) -> str:
    """How a `raven send` travelled, from its own lines: delivered by the
    send (through a LAN route the beacon found, or a saved or learned one),
    or queued for raven-node's outbox."""
    word = status_word(out)
    if word == 'DELIVERED':
        return ('the send, through a beacon find' if 'found on your network now' in out
                else 'the send, through a saved or learned route')
    return f'{word}: then raven-node\'s outbox' if word == 'QUEUED' else word


def s87_beacon_clock_skew(root: Path) -> dict:
    """Phase 3 P3.C3 (cutoff F11b; RAVEN_FAULT_BEACON=1, LabClock on Bob).
    Both nodes run the LAN beacon on a lab bus of their own (127.0.0.1
    only). After warmups both ways, Bob's clock moves 8 minutes ahead.
    Three times the bus moves (a network change for both) and Bob's beacon
    looks for Alice, then three times Alice's for Bob: each is found at its
    listener (IPC LanLocate), and the matches, made only at the epoch next
    to the receiver's, give a skew note. A match next door shows only the
    skew between it and the receiver's epoch edge (review A-3), so each
    half waits for a stretch of Alice's epoch where it shows more than five
    minutes: Bob's queries 125 to 290 s into it (Alice sees them one epoch
    ahead and at least 310 s ahead), Alice's 430 to 590 s into it (Bob,
    120 s further on, sees them one epoch behind and at least 309 s
    behind). Alice's `raven status` says Bob's clock is about N min or more
    ahead, Bob's says Alice's is about N min or more behind, N from 5 to 8
    (never more than the real 8 minutes). Then Bob
    stops, his clock moves to 25 minutes ahead and he starts on a new port
    (as in s04); with nothing waiting he sends no join round (owner decision
    OD-C7: his nearby row says 0 sent). Alice's message to him waits
    (queued): her beacon cannot find him now (two epochs apart: LanLocate
    empty) and, once two of her rounds got no answer, her nearby search row
    says no answer from Bob and asks to check that both laptops show the
    same time."""
    env, bus_file = beacon_env(root, ENV)
    cb = LabClock(root / 'bob.clock')
    a = Node('a', root, env=env)
    b = Node('b', root, env=cb.env(env))
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = [status_word(a.send('bob', 's87-warmup-a2b')[1]),
            status_word(b.send('alice', 's87-warmup-b2a')[1])]
    # Bob 8 minutes ahead: his epoch is one ahead of Alice's from 2 minutes
    # after each of her epoch's start (600 s) to its end. A match shows only
    # the skew between it and the receiver's epoch edge (review A-3): Bob's
    # queries show Alice more than five minutes while under 300 s into her
    # epoch, Alice's show Bob more than five minutes while over 421 s into
    # hers. Each half waits for its stretch.
    def wait_until(lo: float, hi: float) -> float:
        pos = time.time() % 600
        wait = 0.0 if lo <= pos <= hi else round((lo - pos) % 600, 1)
        time.sleep(wait)
        return wait

    waited = wait_until(125, 200)
    cb.set(8 * 60_000)
    time.sleep(1.5)

    def move(n: int) -> bool:
        bus_dir = root / f'bus-{n}'
        move_bus(bus_file, bus_dir)
        t = time.time()
        while time.time() - t < 10:
            if bus_members(bus_dir) == 2:
                time.sleep(0.5)
                return True
            time.sleep(0.1)
        return False

    t_phase = time.time()
    moved, found_alice, found_bob = [], [], []
    for n in (2, 3, 4):
        moved.append(move(n))
        found_alice.append(lan_locate(b, a))
    alice_half_s = round(time.time() - t_phase, 1)
    waited_bob_half = wait_until(430, 520)
    for n in (5, 6, 7):
        moved.append(move(n))
        found_bob.append(lan_locate(a, b))
    phase_s = round(time.time() - t_phase, 1)
    alice_clocks = status_row(a.ash('status').stdout, 'clocks')
    bob_clocks = status_row(b.ash('status').stdout, 'clocks')
    check = " Check the time and time zone on both laptops."
    ahead = re.compile(r"Bob's clock is about [5-8] min or more ahead of yours: messages from "
                       r"Bob are refused until the clocks agree\." + re.escape(check) + "$")
    behind = re.compile(r"Alice's clock is about [5-8] min or more behind yours: Alice refuses "
                        r"your messages until the clocks agree\." + re.escape(check) + "$")
    # Bob 25 minutes ahead, back on a new port with nothing to send.
    old_dial = b.dial
    b.stop()
    cb.set(25 * 60_000)
    b.start()
    time.sleep(3)
    bob_row = nearby_row(b)
    rc, out, send_s = a.send('bob', 's87-waits')
    word = status_word(out)
    hint = 'no answer from Bob; if Bob is here, check that both laptops show the same time'
    t_send = time.time()
    hint_s = None
    while time.time() - t_send < 90:
        if hint in nearby_row(a):
            hint_s = round(time.time() - t_send, 1)
            break
        time.sleep(2)
    alice_row = nearby_row(a)
    not_found = lan_locate(a, b, 0)
    waited_inbox = count(b.inbox(), 's87-waits')
    a.stop()
    b.stop()
    return dict(
        ok=warm == ['DELIVERED', 'DELIVERED'] and all(moved)
        and found_alice == [[a.dial]] * 3 and found_bob == [[old_dial]] * 3
        and ahead.match(alice_clocks or '') is not None
        and behind.match(bob_clocks or '') is not None
        and b.dial != old_dial and 'last 10 min: 0 sent' in bob_row
        and word == 'QUEUED' and hint_s is not None and not_found == []
        and waited_inbox == 0,
        warmup=warm, waited_for_the_epoch_s=waited, alice_half_s=alice_half_s,
        waited_for_bobs_half_s=waited_bob_half, bus_moved=moved, phase_s=phase_s,
        bob_found_alice=found_alice, alice_found_bob=found_bob, alice_dial=a.dial,
        bob_old_dial=old_dial, alice_clock_rows=alice_clocks, bob_clock_rows=bob_clocks,
        bob_new_dial=b.dial, bob_nearby_after_restart=bob_row,
        send=(rc, word, round(send_s, 1)), hint_after_s=hint_s, alice_nearby=alice_row,
        locate_at_25_min=not_found, bob_inbox_count=waited_inbox, send_text=out[-400:])


def both_move(root: Path, tag: str, pinned: bool) -> dict:
    """s80 and s84 (Phase 3 P3.12, the plan's 'new s33'; RAVEN_FAULT_BEACON=1,
    route hints off: a hint learned at the warmup would name the real port,
    which never moves on loopback). Alice and Bob, `pinned` or not, each
    with a bus file of their own naming net1 and a lab netwatch file; each
    saved the other's address as a proxy (PA, PB); a warmup each way. Their
    network goes: both proxies refuse everything from now on; Alice moves
    to net2 (her netwatch file says the network changed) and sends m1, which
    waits; 10 s later Bob moves to net2 (his netwatch file too) and sends
    m2. Pass: m1 exactly once within 15 s of Bob joining; m2 delivered by
    the send (through LanLocate) or within 15 s; both contact books name
    the proxies still; each side found the other on net2 (IPC Status: one of
    its queries answered there, or it answered one of the other's) and no
    `lan_beacon:` log line names an address. With nothing waiting Bob sends
    no join round when he joins (owner decision OD-C7): a query for m2 (his
    send's, or his outbox's when the send, which saw a LAN link with Alice
    less than 2 min old, does not wait for the beacon) names Alice and
    carries his port, which tells her where he is."""
    net1, net2 = root / 'net1', root / 'net2'
    nodes = {}
    for name, ip in (('a', '192.0.2.10'), ('b', '192.0.2.20')):
        bus, nw = root / f'bus-{name}', root / f'{name}-net.txt'
        move_bus(bus, net1)
        nw.write_text(f'up {ip}/24\n')
        env = dict(ENV_NO_HINTS, RAVEN_LAB_LAN_BEACON='1', RAVEN_LAB_LAN_BEACON_BUS=str(bus),
                   RAVEN_LAB_NETWATCH_EVENTS=str(nw))
        nodes[name] = (Node(name, root, env), bus, nw)
    (a, bus_a, nw_a), (b, bus_b, nw_b) = nodes['a'], nodes['b']
    a.init(); b.init()
    a.start(); b.start()
    pa, pb = Proxy(a.dial), Proxy(b.dial)
    if pinned:
        a.add_pinned(b, 'bob', pb.addr)
        b.add_pinned(a, 'alice', pa.addr)
    else:
        a.add(b, 'bob', pb.addr)
        b.add(a, 'alice', pa.addr)
    on_net1 = wait_for(lambda: bus_members(net1) == 2, 20)
    warm = [status_word(a.send('bob', f'{tag}-warmup-a2b')[1]),
            status_word(b.send('alice', f'{tag}-warmup-b2a')[1])]
    books = (saved_lan_dial(a, b), saved_lan_dial(b, a))
    marks = (log_size(a), log_size(b))
    before = {'a': beacon_counts(a), 'b': beacon_counts(b)}
    # The old network goes: every connection to either proxy is refused.
    for p in (pa, pb):
        p.mode = 'refuse'
        p.kill_live()
    move_bus(bus_a, net2)
    with open(nw_a, 'a') as f:
        f.write('down 192.0.2.10/24\nup 198.51.100.10/24\n')
    a_moved = wait_for(lambda: bus_members(net2) == 1, 10)
    a_noticed = wait_log(a, 'raven-node netwatch: network changed', 10, marks[0])
    t_m1 = time.time()
    rc1, out1, s1 = a.send('bob', f'{tag}-m1')
    time.sleep(max(0.0, 10 - (time.time() - t_m1)))
    early = count(b.inbox(), f'{tag}-m1')
    move_bus(bus_b, net2)
    with open(nw_b, 'a') as f:
        f.write('down 192.0.2.20/24\nup 198.51.100.20/24\n')
    t_join = time.time()
    b_moved = wait_for(lambda: bus_members(net2) == 2, 10)
    b_noticed = wait_log(b, 'raven-node netwatch: network changed', 10, marks[1])
    rc2, out2, s2 = b.send('alice', f'{tag}-m2')
    m1_s = m2_s = None
    while time.time() - t_join < 15 and None in (m1_s, m2_s):
        if m1_s is None and count(b.inbox(), f'{tag}-m1'):
            m1_s = round(time.time() - t_join, 1)
        if m2_s is None and count(a.inbox(), f'{tag}-m2'):
            m2_s = round(time.time() - t_join, 1)
        time.sleep(0.5)
    time.sleep(2)
    once = [count(b.inbox(), f'{tag}-m1'), count(a.inbox(), f'{tag}-m2')]
    books_after = (saved_lan_dial(a, b), saved_lan_dial(b, a))
    counts = {'a': beacon_counts(a), 'b': beacon_counts(b)}
    lines = {n.name: beacon_lines(n) for n in (a, b)}
    named = [l for ls in lines.values() for l in ls if ADDRESS_LIKE.search(l)]
    m2_word = status_word(out2)
    # A side found the other on net2 when one of its queries was answered
    # there, or it answered (it matched) a query carrying the other's port.
    found_on_net2 = {
        k: sum(counts[k].get(f, 0) - before[k].get(f, 0)
               for f in ('answered_10m', 'answers_sent_10m')) for k in counts}
    found = all(v >= 1 for v in found_on_net2.values())
    return dict(
        ok=on_net1 is not None and warm == ['DELIVERED', 'DELIVERED']
        and books == (pb.addr, pa.addr) and a_moved is not None and b_moved is not None
        and status_word(out1) == 'QUEUED' and early == 0
        and m1_s is not None and (m2_word == 'DELIVERED' or m2_s is not None)
        and once == [1, 1] and books_after == books and found and not named,
        pinned=pinned, warmup=warm, saved=books, alice_moved_s=a_moved,
        alice_netwatch_s=None if a_noticed is None else round(a_noticed, 1),
        m1=(rc1, status_word(out1), round(s1, 1)), m1_before_bob_joined=early,
        bob_moved_s=b_moved, bob_netwatch_s=None if b_noticed is None else round(b_noticed, 1),
        m2=(rc2, m2_word, round(s2, 1)), m2_route=send_route(out2),
        m1_after_bob_joined_s=m1_s, m2_after_bob_joined_s=m2_s, exactly_once=once,
        books_unchanged=books_after == books, beacon=counts, found_on_net2=found_on_net2,
        beacon_log_lines={k: sorted(set(v)) for k, v in lines.items()},
        lines_naming_an_address=named, m1_text=out1[-300:], m2_text=out2[-400:])


def s80_both_move_to_a_new_network(root: Path) -> dict:
    """Phase 3 P3.12: both verified contacts move to a new network
    ([`both_move`])."""
    return both_move(root, 's80', pinned=True)


def s81_quiet_receiver_dhcp_move(root: Path) -> dict:
    """Phase 3 P3.12 (RAVEN_FAULT_BEACON=1; route hints off, so RRH1 can tell
    Alice nothing). Alice saved Bob's address as a proxy PB; a warmup
    reaches him. Bob's laptop leaves: his node stops, his old address is
    gone for good (PB refuses everything) and Alice's message waits
    (queued). Bob comes back on another port (a DHCP move: a new address on
    the same network) and sends nothing; with nothing waiting he sends no
    join round either (owner decision OD-C7). Alice's outbox asks her beacon
    for him once its dial to what the beacon found before failed, and the
    message arrives exactly once within 30 s of his return. Her contact
    book still names PB and she learned no route hint."""
    a, b = Node('a', root, ENV_NO_HINTS), Node('b', root, ENV_NO_HINTS)
    a.init(); b.init()
    a.start(); b.start()
    pb = Proxy(b.dial)
    a.add_pinned(b, 'bob', pb.addr)
    b.add_pinned(a, 'alice')
    warm = status_word(a.send('bob', 's81-warmup')[1])
    old = b.dial
    b.stop()
    pb.mode = 'refuse'
    pb.kill_live()
    rc, out, send_s = a.send('bob', 's81-m1')
    b.start(port=0)
    t_back = time.time()
    took = wait_inbox(b, 's81-m1', 30)
    took = None if took is None else round(time.time() - t_back, 1)
    time.sleep(2)
    once = count(b.inbox(), 's81-m1')
    counts = beacon_counts(a)
    return dict(
        ok=warm == 'DELIVERED' and status_word(out) == 'QUEUED' and b.dial != old
        and took is not None and once == 1
        and saved_lan_dial(a, b) == pb.addr and learned_entry(a, b) is None
        and counts.get('answered_10m', 0) >= 1,
        warmup=warm, send=(rc, status_word(out), round(send_s, 1)), old=old, new=b.dial,
        delivered_after_back_s=took, exactly_once=once, saved_lan_dial=saved_lan_dial(a, b),
        learned=learned_entry(a, b), alice_beacon=counts, outbox=a.outbox()[-300:])


def constant_windows(datagrams: set) -> list:
    """Offsets where a 4-byte window holds the same bytes in every one of
    `datagrams` (two or more, all of one length)."""
    if len(datagrams) < 2:
        return []
    first, *rest = list(datagrams)
    return [i for i in range(len(first) - 3)
            if all(d[i:i + 4] == first[i:i + 4] for d in rest)]


def s82_beacon_capture_has_no_marker(root: Path) -> dict:
    """Phase 3 P3.12 (RAVEN_FAULT_BEACON=1): what a passive listener on the
    network hears. A Sniffer on the scenario's bus, Alice and Bob (verified
    contacts) and Carol, a stranger who holds both as contacts while
    neither holds her. After a warmup each way the bus moves eight times (a
    network change for everyone: what was found goes) and Alice and Bob in
    turn look for each other (IPC LanLocate, as a send asks). Then Carol
    looks for each of them three times. Pass: the Sniffer heard at least 12
    queries and 6 answers (distinct datagrams), every datagram 160..=191 or
    48..=63 bytes and more than one length of each (Phase 6b W-B3: random
    tails); no 4-byte window of a query's first 160 bytes holds the same
    bytes in every query, nor of an answer's first 48 in every answer; no
    datagram holds a key (raw or hex), an rvn1 address, a
    fingerprint, a PeerId, 'rvn1', 'raven', the loopback address or a
    listener port as text, and no listener port as two bytes in more than
    two datagrams (chance alone: about one in 400 per port and datagram).
    Carol gets no answer (nothing found, none answered in her counts, no
    answer-sized datagram while she asks) and Alice and Bob send her none
    (their answers-sent counts do not move)."""
    env, bus_file = beacon_env(root, ENV_NO_HINTS)
    sniff = Sniffer(bus_file)
    a, b, c = Node('a', root, env), Node('b', root, env), Node('c', root, env)
    for n in (a, b, c):
        n.init()
    for n in (a, b, c):
        n.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    c.add(a, 'alice')
    c.add(b, 'bob')
    # Each beacon reads the contact book again within a second of a change.
    on_bus = wait_for(lambda: len(bus_ports(sniff.dir)) == 4, 20)
    time.sleep(1.5)
    warm = [status_word(a.send('bob', 's82-warmup-a2b')[1]),
            status_word(b.send('alice', 's82-warmup-b2a')[1])]
    finds = []
    for n in range(2, 10):
        net = root / f'net{n}'
        move_bus(bus_file, net)
        moved = wait_for(lambda: len(bus_ports(net)) == 4, 10) is not None
        asker, other = (a, b) if n % 2 == 0 else (b, a)
        # The beacons share one source address here (127.0.0.1): each
        # answers a source 4 queries at once, then one per 2 s.
        time.sleep(2.5)
        finds.append((moved, len(lan_locate(asker, other))))
        # The second copies (100-400 ms after the first, which waits up to
        # 500 ms) go out on this bus too.
        time.sleep(1)
    time.sleep(2.5)
    sent_before = {n.name: beacon_counts(n).get('answers_sent_10m') for n in (a, b)}
    t_carol = time.time()
    carol = []
    for other in (a, b, a, b, a, b):
        carol.append(lan_locate(c, other))
        time.sleep(2.5)
    sent_after = {n.name: beacon_counts(n).get('answers_sent_10m') for n in (a, b)}
    carol_counts = beacon_counts(c)
    heard = sniff.captured()
    t0 = heard[0][0] if heard else 0.0
    timeline = [(round(t - t0, 2), port, len(d), hashlib.sha256(d).hexdigest()[:6])
                for t, port, d in heard]
    answers_to_carol = [d for t, _, d in heard if t >= t_carol and len(d) in ANSWER_LENS]
    lengths = sorted({len(d) for _, _, d in heard})
    queries = {d for _, _, d in heard if len(d) in QUERY_LENS}
    answers = {d for _, _, d in heard if len(d) in ANSWER_LENS}
    distinct = {d for _, _, d in heard}
    # The tails are random: the windows are looked for in what precedes them.
    constant = {'queries': constant_windows({d[:QUERY_LEN] for d in queries}),
                'answers': constant_windows({d[:ANSWER_LEN] for d in answers})}
    tails_vary = (len({len(d) for d in queries}) > 1 and len({len(d) for d in answers}) > 1)
    # Words are looked for in any case; raw bytes as they are.
    words = [('rvn1', 'rvn1'), ('raven', 'raven'), ('127.0.0.1', '127.0.0.1')]
    raw = [('the loopback address (4 bytes)', bytes([127, 0, 0, 1]))]
    port_bytes = {}
    for n in (a, b, c):
        fp, port = n.fingerprint(), port_of(n)
        words += [(f'{n.name}: key (hex)', n.pub), (f'{n.name}: rvn1 address', n.address),
                  (f'{n.name}: fingerprint', fp),
                  (f'{n.name}: fingerprint (no dashes)', fp.replace('-', '')),
                  (f'{n.name}: PeerId', peer_id_of(n)),
                  (f'{n.name}: listener port (text)', str(port))]
        raw.append((f'{n.name}: key', bytes.fromhex(n.pub)))
        port_bytes[n.name] = sum(1 for d in distinct
                                 if struct.pack('>H', port) in d or struct.pack('<H', port) in d)
    found_in_clear = sorted(
        {what for what, word in words for d in distinct if word.lower().encode() in d.lower()}
        | {what for what, needle in raw for d in distinct if needle in d})
    stranger_ok = (all(f == [] for f in carol) and carol_counts.get('answered_10m') == 0
                   and carol_counts.get('queries_10m', 0) >= len(carol) and not answers_to_carol
                   and sent_before == sent_after)
    return dict(
        ok=on_bus is not None and warm == ['DELIVERED', 'DELIVERED']
        and all(m and k > 0 for m, k in finds)
        and set(lengths) <= set(QUERY_LENS) | set(ANSWER_LENS) and len(queries) >= 12
        and len(answers) >= 6 and tails_vary
        and not constant['queries'] and not constant['answers']
        and not found_in_clear and max(port_bytes.values()) <= 2 and stranger_ok,
        warmup=warm, finds=finds, datagrams=len(heard), lengths=lengths,
        tails_vary=tails_vary,
        distinct_queries=len(queries), distinct_answers=len(answers),
        constant_windows=constant, found_in_the_clear=found_in_clear,
        port_as_two_bytes=port_bytes, carol_found=carol, carol_beacon=carol_counts,
        answers_while_carol_asked=len(answers_to_carol),
        answers_sent_before_carol=sent_before, answers_sent_after_carol=sent_after,
        stranger_ok=stranger_ok, timeline=timeline)


def s83_lan_off_on(root: Path) -> dict:
    """Phase 3 P3.12 (P3.6's s53; RAVEN_FAULT_BEACON=1). Alice and Bob
    (verified; Bob on a fixed free port) and a Sniffer on their bus; a
    warmup reaches Bob. `raven lan off` on Bob: his port refuses within 2 s
    and his beacon leaves the bus. Alice's message waits (queued; the
    LAN_NO_ANSWER reason comes with P3.23). Once her outbox's dial to what
    her beacon found before failed (nothing found is left), her beacon asks
    for Bob (IPC LanLocate, as a send asks) and gets no answer: the Sniffer
    hears her query and nothing from Bob, from his `lan off` on. `raven lan
    on`: his port opens again, his beacon is back on the bus, and the
    message arrives exactly once within 30 s with no new send."""
    env, bus_file = beacon_env(root, ENV)
    sniff = Sniffer(bus_file)
    a, b = Node('a', root, env), Node('b', root, env)
    a.init(); b.init()
    a.start()
    a_bus = bus_port_of(sniff, set())
    b.start(port=free_tcp_port())
    b_bus = bus_port_of(sniff, {a_bus})
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = status_word(a.send('bob', 's83-warmup')[1])
    off = b.ash('lan', 'off')
    t_off = time.time()
    refused_s = wait_for(lambda: not tcp_accepts(b.dial, 0.5), 10)
    left_s = wait_for(lambda: b_bus not in bus_ports(sniff.dir).values(), 10)
    rc, out, send_s = a.send('bob', 's83-m1')
    word = status_word(out)
    stale_gone = wait_for(lambda: lan_locate(a, b, 0) == [], 60)
    t_ask = time.time()
    asked, alice_queries = [], 0
    for _ in range(3):
        # A user send's queries naming Bob go 2 s apart at least: asked
        # sooner after the warmup's, this one names nobody.
        time.sleep(2.5)
        asked += lan_locate(a, b, 1500)
        alice_queries = sum(1 for _, p, d in sniff.captured(t_ask)
                            if p == a_bus and len(d) in QUERY_LENS)
        if alice_queries:
            break
    time.sleep(3.5)
    t_on = time.time()
    heard = sniff.captured(t_off + 0.5, t_on)
    from_bob = sum(1 for _, p, _ in heard if p != a_bus)
    waited = count(b.inbox(), 's83-m1') == 0
    on = b.ash('lan', 'on')
    open_s = wait_for(lambda: tcp_accepts(b.dial, 0.5), 10)
    back_s = wait_for(lambda: bus_port_of(sniff, {a_bus}, 0.5) is not None, 10)
    got = wait_inbox(b, 's83-m1', 30)
    got = None if got is None else round(time.time() - t_on, 1)
    time.sleep(2)
    once = count(b.inbox(), 's83-m1')
    return dict(
        ok=a_bus is not None and b_bus is not None and warm == 'DELIVERED'
        and off.returncode == 0 and refused_s is not None and refused_s <= 2
        and left_s is not None and word == 'QUEUED' and stale_gone is not None
        and asked == [] and alice_queries >= 1 and from_bob == 0 and waited
        and on.returncode == 0 and open_s is not None and back_s is not None
        and got is not None and once == 1,
        warmup=warm, lan_off=(off.returncode, off.stdout.strip()[-200:]),
        port_refused_after_s=refused_s, beacon_left_bus_s=left_s,
        send=(rc, word, round(send_s, 1)), old_find_gone_s=stale_gone, alice_asked=asked,
        alice_queries_heard=alice_queries, heard_from_bob=from_bob, waited=waited,
        lan_on=(on.returncode, on.stdout.strip()[-200:]), port_open_again_s=open_s,
        beacon_back_s=back_s, delivered_after_lan_on_s=got, exactly_once=once,
        send_text=out[-300:])


def s84_unverified_contacts_find_each_other(root: Path) -> dict:
    """Phase 3 P3.12 (the plan's s54): s80 between contacts neither has
    verified ([`both_move`]): the beacon answers an unverified contact from
    a local source, and the LAN gate admits it."""
    return both_move(root, 's84', pinned=False)


def renewal_round(root: Path, a_env: dict, b_env: dict, lifetime_ms: int,
                  role: str) -> dict:
    """Phase 3 P3.15: Alice's first send starts a session of `lifetime_ms`
    (RAVEN_LAB_SESSION_LIFETIME_MS on that `ash send` only); the side whose
    turn `role` is ('primary': Bob, who did not start it; 'fallback': Alice,
    who did) renews it once on that link. Bob then goes down, Alice's
    message waits with a deadline about a day out (not the old session's),
    and is delivered once when Bob is back on his port; Bob's reply too. No
    other renewal follows (one settle, 15 s, after the last link)."""
    a, b = Node('a', root, a_env), Node('b', root, b_env)
    a.init(); b.init()
    a.start(); b.start()
    a.add(b, 'bob'); b.add(a, 'alice')
    renewer, other = (b, a) if role == 'primary' else (a, b)
    rc, out, _ = a.send('bob', 'warmup',
                        extra_env={'RAVEN_LAB_SESSION_LIFETIME_MS': str(lifetime_ms)})
    caps = node_ipc(renewer, {'op': 'status', 'v': 1}).get('capabilities') or []
    renewed = wait_log(renewer, f'{RENEWED_LINE}{role})', 90)
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    rc2, out2, _ = a.send('bob', 'while-away')
    h = re.search(r'in about (\d+) h', out2)
    b.start(port=port)
    took = wait_inbox(b, 'while-away', 90)
    rc3, out3, _ = b.send('alice', 'reply')
    marks = {n.name: log_size(n) for n in (a, b)}
    again = wait_until(lambda: any(RENEWED_LINE in n.log_path.read_text(errors='replace')
                                   [marks[n.name]:] for n in (a, b)), 20)
    lines = {n.name: n.log_path.read_text(errors='replace').count(RENEWED_LINE)
             for n in (a, b)}
    return dict(ok=status_word(out) == 'DELIVERED' and 'session_renewal' in caps
                and renewed is not None and status_word(out2) == 'QUEUED'
                and h is not None and int(h.group(1)) >= 23 and took is not None
                and count(b.inbox(), 'while-away') == 1 and status_word(out3) == 'DELIVERED'
                and count(a.inbox(), 'reply') == 1 and again is None
                and lines[renewer.name] == 1 and lines[other.name] == 0,
                warmup=status_word(out), capability='session_renewal' in caps,
                renewed_s=renewed, away_send=(rc2, status_word(out2)),
                hours_left=h and int(h.group(1)), delivered_after_back_s=took,
                reply=status_word(out3), renewals=lines, renewed_again_s=again,
                away_text=out2[-400:])


def s85_session_renewed_before_it_ends(root: Path) -> dict:
    """Phase 3 P3.15 (item 4; RAVEN_FAULT_RENEW=1): an 11 h session
    Alice started is renewed by Bob (primary) after the settle, and what
    Alice queues while he is away keeps about a day ([`renewal_round`])."""
    env = dict(ENV, RAVEN_LAB_SESSION_RENEWAL='1')
    return renewal_round(root, env, env, 11 * 3_600_000, 'primary')


def s85b_fallback_when_the_contact_does_not_renew(root: Path) -> dict:
    """Phase 3 P3.15 (item 4, fallback; RAVEN_FAULT_RENEW=1): Bob runs without
    the switch (an older build, or the gate off). Alice started the session
    (9 h 30 min), so she is the fallback side and renews below 10 h on her
    own link; Bob logs no renewal ([`renewal_round`])."""
    a_env = dict(ENV, RAVEN_LAB_SESSION_RENEWAL='1')
    b_env = {k: v for k, v in ENV.items() if k != 'RAVEN_LAB_SESSION_RENEWAL'}
    return renewal_round(root, a_env, b_env, 34_200_000, 'fallback')


# A sealed profile's at-rest key file and its mode (privacy pack): the kept
# contacts and device files are sealed under that key (the book since PP.4,
# the device registry and key since PP.5), so a lost-state scenario keeps them
# with the identity, as a backup of the folder would.
AT_REST_ROOT = ('meta_key.rmk', 'privacy.json')


def s05_receiver_loses_state(root: Path) -> dict:
    a, b = pair(root)
    a.send('bob', 'warmup')
    b.stop()
    # Lost sessions/prekeys/history, kept identity + device key + contacts
    # (restored from an older backup, or app data partly wiped).
    keep_prefixes = ('identity', '.identity', 'device_', '.device', 'contacts') + AT_REST_ROOT
    removed = []
    for p in list(b.dir.iterdir()):
        if p.name.startswith(keep_prefixes):
            continue
        removed.append(p.name)
        shutil.rmtree(p) if p.is_dir() else p.unlink()
    # Prekey ids are seconds since 2020 (lost-state recovery §4), and the
    # first install published twice within one second (id = clock + 1). A
    # republish within that same second would offer an equal id with other
    # keys (refused as equivocation until phase 2b). A real reinstall takes
    # longer than that.
    time.sleep(2.1)
    r = b.ash('prekey', 'publish')
    b.start(port=int(b.dial.rsplit(':', 1)[1]))
    rc, out, dt = a.send('bob', 'after-reinstall')
    time.sleep(10)
    return dict(ok=count(b.inbox(), 'after-reinstall') == 1, removed=removed,
                prekey_publish_rc=r.returncode, send=(rc, status_word(out)),
                send_text=out[-400:])


def s06_flaky_link_resets(root: Path) -> dict:
    a, b = Node('a', root), Node('b', root)
    a.init(); b.init(); a.start(); b.start()
    proxy = Proxy(b.dial)
    a.add(b, 'bob', proxy.addr)
    b.add(a, 'alice')
    a.send('bob', 'warmup')
    results = []
    for i in range(8):
        proxy.mode, proxy.reset_budget, proxy.reset_after = 'reset_after', 1, 150 + 97 * i
        rc, out, dt = a.send('bob', f'flaky-{i}')
        results.append((rc, status_word(out), round(dt, 1)))
    proxy.mode = 'pass'
    time.sleep(5)
    for i in range(8):
        wait_inbox(b, f'flaky-{i}', 120)
    inbox = b.inbox()
    counts = {i: count(inbox, f'flaky-{i}') for i in range(8)}
    return dict(ok=all(v == 1 for v in counts.values()), sends=results, inbox_counts=counts,
                proxy_conns=proxy.conns)


def s07_slow_link(root: Path) -> dict:
    a, b = Node('a', root), Node('b', root)
    a.init(); b.init(); a.start(); b.start()
    proxy = Proxy(b.dial)
    proxy.delay = 0.8
    a.add(b, 'bob', proxy.addr)
    b.add(a, 'alice')
    results = []
    for i in range(3):
        rc, out, dt = a.send('bob', f'slow-{i}', timeout=240)
        results.append((rc, status_word(out), round(dt, 1)))
    proxy.delay = 0
    for i in range(3):
        wait_inbox(b, f'slow-{i}', 120)
    inbox = b.inbox()
    counts = {i: count(inbox, f'slow-{i}') for i in range(3)}
    return dict(ok=all(v == 1 for v in counts.values()), sends=results, inbox_counts=counts)


def s08_blackhole_then_heal(root: Path) -> dict:
    a, b = Node('a', root), Node('b', root)
    a.init(); b.init(); a.start(); b.start()
    proxy = Proxy(b.dial)
    a.add(b, 'bob', proxy.addr)
    b.add(a, 'alice')
    a.send('bob', 'warmup')
    proxy.mode = 'blackhole'
    rc, out, dt = a.send('bob', 'into-the-void', timeout=240)
    proxy.mode = 'pass'
    took = wait_inbox(b, 'into-the-void', 900)
    return dict(ok=took is not None and count(b.inbox(), 'into-the-void') == 1,
                send=(rc, status_word(out), round(dt, 1)), delivered_after_heal_s=took)


def s09_bidirectional_concurrent(root: Path) -> dict:
    a, b = pair(root)
    out: dict = {}

    def run(node: Node, tag: str, prefix: str) -> None:
        out[prefix] = [node.send(tag, f'{prefix}-{i}')[0] for i in range(5)]

    ta = threading.Thread(target=run, args=(a, 'bob', 'a2b'))
    tb = threading.Thread(target=run, args=(b, 'alice', 'b2a'))
    ta.start(); tb.start(); ta.join(); tb.join()
    time.sleep(10)
    ib, ia = b.inbox(), a.inbox()
    c_ab = {i: count(ib, f'a2b-{i}') for i in range(5)}
    c_ba = {i: count(ia, f'b2a-{i}') for i in range(5)}
    return dict(ok=all(v == 1 for v in (*c_ab.values(), *c_ba.values())),
                rcs=out, a2b=c_ab, b2a=c_ba)


def s10_receiver_crash_during_burst(root: Path) -> dict:
    a, b = pair(root)
    a.send('bob', 'warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    results = []
    for i in range(12):
        if i in (3, 7):
            b.stop(hard=True)
        if i in (5, 10):
            b.start(port=port)
        rc, out, dt = a.send('bob', f'burst-{i}')
        results.append((i, rc, status_word(out)))
    if b.proc is None:
        b.start(port=port)
    deadline = time.time() + 300
    while time.time() < deadline:
        inbox = b.inbox()
        if all(count(inbox, f'burst-{i}') for i in range(12)):
            break
        time.sleep(3)
    inbox = b.inbox()
    counts = {i: count(inbox, f'burst-{i}') for i in range(12)}
    return dict(ok=all(v == 1 for v in counts.values()), sends=results, inbox_counts=counts,
                outbox=a.outbox()[-600:])


def lan_ip() -> str:
    for iface in ('en0', 'en1'):
        r = subprocess.run(['ipconfig', 'getifaddr', iface], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    return ''


def s11_receiver_ip_changes_same_port(root: Path) -> dict:
    """DHCP-like move: Bob keeps his port, his old address (127.0.0.1) stops answering."""
    lan = lan_ip()
    if not lan:
        return dict(ok=True, skipped='no LAN IP on en0/en1')
    a, b = Node('a', root), Node('b', root)
    a.init(); b.init()
    a.start(host=lan); b.start(host=lan)
    port = b.dial.rsplit(':', 1)[1]
    a.add(b, 'bob', f'127.0.0.1:{port}')    # stale: Bob no longer listens there
    b.add(a, 'alice')
    r0 = b.send('alice', 'hello-from-bob')   # Bob reaches Alice from his new address
    r1 = a.send('bob', 'after-ip-change')
    time.sleep(3)
    r2 = a.send('bob', 'second-after-change')
    contacts = book_rows(a.dir)
    saved = [c.get('lan_dial') for c in contacts]
    inbox = b.inbox()
    return dict(ok=count(inbox, 'after-ip-change') == 1 and count(inbox, 'second-after-change') == 1,
                bob_to_alice=status_word(r0[1]), send1=status_word(r1[1]), send2=status_word(r2[1]),
                send1_tail=r1[1][-300:], saved_lan_dial=saved, new=f'{lan}:{port}')


def s12_offline_queue_drain_timing(root: Path) -> dict:
    """Three messages queued while Bob is down: when does each arrive after he is back?"""
    a, b = pair(root)
    a.send('bob', 'warmup')
    b.stop()
    for k in (1, 2, 3):
        a.send('bob', f'drain-{k}')
    port = int(b.dial.rsplit(':', 1)[1])
    b.start(port=port)
    t0 = time.time()
    arrived: dict = {}
    while time.time() - t0 < 240 and len(arrived) < 3:
        inbox = b.inbox()
        for k in (1, 2, 3):
            if k not in arrived and count(inbox, f'drain-{k}'):
                arrived[k] = round(time.time() - t0, 1)
        time.sleep(1)
    inbox = b.inbox()
    return dict(ok=all(count(inbox, f'drain-{k}') == 1 for k in (1, 2, 3)) and max(arrived.values(), default=999) < 60,
                arrived_after_s=arrived, outbox=a.outbox()[-500:])


def s13_drain_trace(root: Path) -> dict:
    """s12 with a full trace: each send's outcome, outbox and inbox every 2 s."""
    a, b = pair(root)
    a.send('bob', 'warmup')
    b.stop()
    sends = {}
    for k in (1, 2, 3):
        rc, out, dt = a.send('bob', f'trace-{k}')
        sends[k] = (rc, status_word(out), out[-160:])
    after_sends = a.outbox()
    port = int(b.dial.rsplit(':', 1)[1])
    b.start(port=port)
    t0 = time.time()
    timeline = []
    last = None
    while time.time() - t0 < 150:
        inbox = b.inbox()
        got = tuple(k for k in (1, 2, 3) if count(inbox, f'trace-{k}'))
        ob = re.sub(r'\s+', ' ', a.outbox())[:300]
        if (got, ob) != last:
            timeline.append((round(time.time() - t0, 1), got, ob))
            last = (got, ob)
        if len(got) == 3:
            break
        time.sleep(2)
    inbox = b.inbox()
    return dict(ok=all(count(inbox, f'trace-{k}') == 1 for k in (1, 2, 3)),
                sends=sends, outbox_after_sends=after_sends, timeline=timeline)


def s14_twenty_queued_in_order(root: Path) -> dict:
    """20 messages while Bob is down (> 16 frames per dial): labels, then order."""
    a, b = pair(root)
    a.send('bob', 'warmup')
    b.stop()
    statuses = [status_word(a.send('bob', f'ordered-{k:02d}')[1]) for k in range(20)]
    # The worker merges a message kicked during an in-flight attempt right
    # after that attempt: let its view settle (a second or two) before judging.
    t_settle = time.time()
    listing = a.outbox()
    while sum('ordered-' in l for l in listing.splitlines()) < 20 and time.time() - t_settle < 10:
        time.sleep(0.5)
        listing = a.outbox()
    settle_s = round(time.time() - t_settle, 1)
    sent_lines = [l for l in listing.splitlines() if 'ordered-' in l and ' sent ' in l]
    queued_lines = [l for l in listing.splitlines() if 'ordered-' in l and ' queued ' in l]
    b.start(port=int(b.dial.rsplit(':', 1)[1]))
    t0 = time.time()
    while time.time() - t0 < 120:
        inbox = b.inbox()
        if all(count(inbox, f'ordered-{k:02d}') for k in range(20)):
            break
        time.sleep(1)
    inbox = b.inbox()
    counts = {k: count(inbox, f'ordered-{k:02d}') for k in range(20)}
    positions = sorted(range(20), key=lambda k: inbox.find(f'ordered-{k:02d}'))
    other = [l for l in listing.splitlines() if 'ordered-' in l and l not in sent_lines and l not in queued_lines]
    return dict(other_lines=other, settle_s=settle_s,
                ok=all(v == 1 for v in counts.values()) and positions == list(range(20))
                and not sent_lines and len(queued_lines) == 20,
                statuses=sorted(set(statuses)), labelled_sent=len(sent_lines),
                labelled_queued=len(queued_lines), arrival_order=positions,
                counts=counts, took_s=round(time.time() - t0, 1))


def status_section(status: str, header: str) -> str:
    """The rows of one `ash status` section, from its header line to the next
    blank line ('' when the section is missing)."""
    i = status.find(header + ' \u2500')
    if i < 0:
        return ''
    rest = status[i:].split('\n', 1)
    return rest[1].split('\n\n', 1)[0] if len(rest) > 1 else ''


# The last row of `ash status` for a profile whose keys are in the lab file
# backend (cutoff pack CP.8): every harness profile is one.
LAB_WARNING = ('This profile keeps its keys unencrypted (lab file backend): '
               'use it for tests only, never for real messages.')


def status_verdict_text(status: str) -> str:
    """`ash status` without its lab-profile warning, so that its verdict is
    the end again."""
    text = status.rstrip()
    if text.endswith(LAB_WARNING):
        text = text[:-len(LAB_WARNING)].rstrip()
    return text


def status_row(text: str, key: str) -> str | None:
    """The value of the first `  key   value` row."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(key) and line[len(key):len(key) + 1].isspace():
            return line[len(key):].strip()
    return None


def s37_status_names_the_last_path(root: Path) -> dict:
    """`ash status` names how the last delivery to Bob travelled: a LAST
    DELIVERY row with his petname and 'same network (LAN)', no address or
    port; `ash doctor` says `reach_class: off` (no p2p host). Kept in memory
    only: after Alice's node restarts the section is gone."""
    a, b = pair(root)
    a.send('bob', 'warmup')
    rc, out, dt = a.send('bob', 'path-1')
    t0 = time.time()
    status = a.ash('status').stdout
    status_s = round(time.time() - t0, 2)
    section = status_section(status, 'LAST DELIVERY')
    row = status_row(section, 'Bob')
    port = b.dial.rsplit(':', 1)[1]
    row_ok = (row is not None and row.startswith('same network (LAN), ')
              and row.endswith(' ago') and '127.0.0.1' not in row
              and f':{port}' not in row and '(since raven-node started)' in status)
    t0 = time.time()
    doctor = a.ash('doctor').stdout
    doctor_s = round(time.time() - t0, 2)
    doctor_ok = 'reach_class: off (p2p host not running)' in doctor
    paths_line = next((l.strip() for l in doctor.splitlines()
                       if l.strip().startswith('last_paths:')), None)
    a.stop()
    a.start(port=int(a.dial.rsplit(':', 1)[1]))
    after = a.ash('status').stdout
    gone = 'LAST DELIVERY' not in after
    return dict(ok=rc == 0 and row_ok and doctor_ok and gone
                and count(b.inbox(), 'path-1') == 1,
                send=(rc, status_word(out), round(dt, 2)), row=row,
                section=section, doctor_last_paths=paths_line,
                no_reachability_section='REACHABILITY' not in status,
                gone_after_restart=gone, status_s=status_s, doctor_s=doctor_s)


# ------------------------------------------- session reset (lab switch on)
# Run only with RAVEN_LAB_SESSION_RESET=1 (design 2026-10-lost-state-recovery
# §21.5): both ash and raven-node inherit it from ENV.
RESET_ON = os.environ.get('RAVEN_LAB_SESSION_RESET', '') in ('1', '2')


def wipe(node: Node, keep: tuple = ('identity', '.identity', 'device_', '.device',
                                    'contacts')) -> list:
    """Lose the node's Raven state except `keep` (name prefixes) and the
    at-rest key root (AT_REST_ROOT); re-publish a prekey like a fresh install
    does (after >1 s, see s05)."""
    removed = []
    for p in list(node.dir.iterdir()):
        if p.name.startswith(keep + AT_REST_ROOT):
            continue
        removed.append(p.name)
        shutil.rmtree(p) if p.is_dir() else p.unlink()
    time.sleep(2.1)
    r = node.ash('prekey', 'publish')
    assert r.returncode == 0, r.stdout + r.stderr
    return removed


def s05b_queued_then_receiver_loses_state(root: Path) -> dict:
    """Queued while Bob is down; Bob comes back wiped. raven-node's worker
    alone (no new send) retires the lost session, pairs again and delivers."""
    a, b = pair(root)
    a.send('bob', 'warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    sends = [a.send('bob', f'q{i}')[:2] for i in (1, 2, 3)]
    sends = [(rc, status_word(out)) for rc, out in sends]
    wipe(b)
    b.start(port=port)
    waited = {f'q{i}': wait_inbox(b, f'q{i}', 120) for i in (1, 2, 3)}
    inbox = b.inbox()
    order = [inbox.find(f'q{i}') for i in (1, 2, 3)]
    counts = {f'q{i}': count(inbox, f'q{i}') for i in (1, 2, 3)}
    return dict(ok=all(v == 1 for v in counts.values()) and order == sorted(order),
                sends=sends, waited=waited, counts=counts, order=order,
                outbox=a.outbox()[-600:])


def s05d_receiver_loses_state_and_certificate(root: Path) -> dict:
    """Like s05, but Bob also gets a new device certificate (E2): the next
    send pairs again without any session query."""
    a, b = pair(root)
    a.send('bob', 'warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    removed = wipe(b, keep=('identity', '.identity', 'contacts'))
    b.start(port=port)
    rc, out, dt = a.send('bob', 'after-new-cert')
    time.sleep(3)
    a_log = a.log_path.read_text(errors='replace')
    b_log = b.log_path.read_text(errors='replace')
    return dict(ok=count(b.inbox(), 'after-new-cert') == 1
                and status_word(out) == 'DELIVERED'
                and 'NO_PEER_CERT' not in a_log
                and "answered a contact's session check" not in b_log,
                removed=removed, send=(rc, status_word(out)), send_text=out[-400:])


def s22_four_wipes_end_in_loop_hold(root: Path) -> dict:
    """Bob loses his state four times in one day: three automatic rounds,
    then RAVEN holds the backlog until the user confirms (`outbox resend`)."""
    a, b = pair(root)
    a.send('bob', 'warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    words = []
    for i in range(1, 5):
        b.stop()
        wipe(b)
        b.start(port=port)
        rc, out, dt = a.send('bob', f'wipe{i}')
        words.append((rc, status_word(out), 'no longer had your secure connection' in out,
                      'PEER_RESET_LOOP' in out))
        if i < 4:
            time.sleep(61)  # the reset cooldown (design §20)
    history_failed = 'failed' in a.ash('outbox', 'list').stdout
    r = a.ash('outbox', 'resend', '--contact', '@bob')
    resent = r.returncode, (r.stdout + r.stderr).strip()[-300:]
    got4 = wait_inbox(b, 'wipe4', 60)
    inbox = b.inbox()
    # Each wipe also erases Bob's inbox: wipe1-3 are proven by their verified
    # ACKs (DELIVERED); the inbox now holds exactly the released wipe4.
    ok = (all(w[1] == 'DELIVERED' and w[2] for w in words[:3])
          and words[3][3] and not history_failed and got4 is not None
          and count(inbox, 'wipe4') == 1)
    return dict(ok=ok, sends=words, resend=resent, got4=got4,
                history_failed=history_failed)


# --------------------------------------- friend custody (lab unlock on)
# Custody is for a recipient who cannot be reached: without the LAN beacon
# (on one lab bus it would reach him, and carry the ACKs custody carries).
# P3.C5's beacon versions (s88, s96, s97) add it on purpose, each with
# nodes that are never on the bus at the same time or cannot hear each
# other.
CUSTODY_ENV = without_beacon(ENV)
CUSTODY_ENV.update(RAVEN_LAB_TEST_A='1', RAVEN_LAB_CUSTODY_AFTER_MS='0',
                   RAVEN_LAB_CUSTODY_FETCH_MS='1000')


def has_default_route() -> bool:
    """A UDP connect to a documentation address (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1', 9))
            return s.getsockname()[0] != '0.0.0.0'
    except OSError:
        return False


def s15_route_memory(root: Path) -> dict:
    """G2 (lab only: RAVEN_LAB_TEST_A=1 on both nodes): Bob's LAN address is
    black-holed by the proxy, his Internet listener is up. The first send
    waits out the LAN probe and goes over the Internet; the next one goes
    there first (no LAN connection). A message queued while Bob is down: its
    send finds the remembered route dead (forgotten); Alice's worker delivers
    it over the Internet after its LAN dial times out, which teaches the
    memory again, and the next send goes straight to the Internet. Bob then
    reaches Alice's LAN listener from a new address: sends go LAN first
    again. The network tag is the real one unless this machine has no default
    route (then RAVEN_LAB_NET_TAG, the debug lab override). No LAN beacon
    under RAVEN_FAULT_BEACON=1 (without_beacon): it would find Bob's real
    LAN port past the black hole."""
    env = without_beacon(dict(ENV, RAVEN_LAB_TEST_A='1'))
    real_tag = has_default_route()
    if not real_tag:
        env['RAVEN_LAB_NET_TAG'] = 's15'
    a, b = Node('a', root, env), Node('b', root, env)
    a.init()
    b.init()
    a.start()
    b.start(inet_port=0)
    proxy = Proxy(b.dial)
    a.add_pinned(b, 'bob', dial=proxy.addr)
    r = a.ash('contact', 'set-addr', '@bob', '--internet', b.inet)
    assert r.returncode == 0, r.stdout + r.stderr
    b.add_pinned(a, 'alice')
    memory = a.dir / 'route_memory.json'

    def remembered() -> list:
        try:
            raw = sealed_plain(a.dir, memory.name)
            return [f"{e['route']['carrier']} {e['route']['dial']}"
                    for e in json.loads(raw if raw is not None else b'')]
        except (OSError, ValueError, KeyError, TypeError):
            return []

    def send(text: str) -> dict:
        conns = proxy.conns
        rc, out, dt = a.send('bob', text)
        return dict(status=status_word(out), s=round(dt, 1), lan_conns=proxy.conns - conns)

    inet = f'internet {b.inet}'
    warm = send('rm-warmup')
    proxy.mode = 'blackhole'
    first = send('rm-1')
    learned_by_send = remembered()
    second = send('rm-2')
    port, inet_port = int(b.dial.rsplit(':', 1)[1]), int(b.inet.rsplit(':', 1)[1])
    b.stop()
    queued = send('rm-queued')
    after_dead = remembered()
    b.start(port=port, inet_port=inet_port)
    took = wait_inbox(b, 'rm-queued', 180)
    learned_by_worker = remembered()
    third = send('rm-3')
    r = b.send('alice', 'rm-hello')
    after_sighting = remembered()
    proxy.mode = 'pass'
    lan_again = send('rm-lan')
    inbox = b.inbox()
    once = all(count(inbox, t) == 1 for t in
               ('rm-warmup', 'rm-1', 'rm-2', 'rm-queued', 'rm-3', 'rm-lan'))
    ok = (warm['status'] == 'DELIVERED'
          and first['status'] == 'DELIVERED' and learned_by_send == [inet]
          and second['status'] == 'DELIVERED' and second['lan_conns'] == 0
          and second['s'] < 3
          and queued['status'] == 'QUEUED' and after_dead == []
          and took is not None and learned_by_worker == [inet]
          and third['status'] == 'DELIVERED' and third['lan_conns'] == 0
          and third['s'] < 3
          and after_sighting == []
          and lan_again['status'] == 'DELIVERED' and lan_again['lan_conns'] >= 1
          and once)
    return dict(ok=ok, real_tag=real_tag, warmup=warm, send1=first,
                learned_by_send=learned_by_send, send2=second, queued=queued,
                after_dead_route=after_dead, delivered_after_bob_back_s=took,
                learned_by_worker=learned_by_worker, send3=third,
                bob_to_alice=status_word(r[1]), after_sighting=after_sighting,
                lan_again=lan_again, exactly_once=once)


def s30_via_a_friend(root: Path) -> dict:
    """Bob is offline; Alice's message is left with Carol (a friend both
    verified and chose), and Bob fetches it from Carol when he is back.
    With RAVEN_FAULT_LETTER=1 (the letter gate on, P5.16) it may go as a
    sealed letter instead of the base deposit (Carol serves letters): then
    Carol holds a letter, Bob takes it, and his ACK comes back in his REPLY
    letter; the same 60 s bounds. With RAVEN_FAULT_HANDOFF=1 (the handoff
    gate on, P5.23) Carol also turns handoff on: Carol is a custodian both
    list (and, with RAVEN_FAULT_HINTS=1, one Bob announces), so she gets a
    plain DEPOSIT and no HANDOFF frame is sent: Alice's worker never leaves
    anything to pass on and Carol's handoff row counts nothing."""
    a, b, c = (Node(n, root, CUSTODY_ENV) for n in ('a', 'b', 'c'))
    for n in (a, b, c):
        n.init()
        n.start()
    for x, y, tag in ((a, b, 'bob'), (a, c, 'carol'), (b, a, 'alice'), (b, c, 'carol'),
                      (c, a, 'alice'), (c, b, 'bob')):
        x.add_pinned(y, tag)
    on = c.ash('node', 'custody', 'on', '--yes')
    handoff_on = c.ash('node', 'custody', 'handoff', 'on').returncode if HANDOFF else 0
    for x, tag in ((a, 'bob'), (b, 'alice')):
        r = x.ash('contact', 'set-addr', '--tag', tag, '--custodian', '@carol')
        assert r.returncode == 0, r.stdout + r.stderr
    a.send('bob', 'warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    rc, out, dt = a.send('bob', 'via-carol')
    held = None
    t0 = time.time()
    while time.time() - t0 < 60:
        st = c.ash('node', 'custody', 'status').stdout
        m = re.search(r'held (\d+) sealed', st)
        letter = re.search(r'^letters\s+held (\d+) sealed letter', st, re.M)
        if (m and int(m.group(1)) >= 1) or (LETTER and letter and int(letter.group(1)) >= 1):
            held = time.time() - t0
            break
        time.sleep(1)
    # Alice goes offline too: only Carol can now hand the message to Bob.
    a.stop()
    b.start(port=port)
    got = wait_inbox(b, 'via-carol', 60)
    time.sleep(3)
    b_log = b.log_path.read_text(errors='replace')
    # Alice back: Bob's ACK (left with Carol, or owed directly) reaches her.
    a.start()
    # Bob's dial address for Alice is stale (she came back on a new port), so
    # the ACK can only come back through Carol.
    acked = None
    t1 = time.time()
    while time.time() - t1 < 60:
        a_log = a.log_path.read_text(errors='replace')
        if (re.search(r'custody: fetched messages=\d+ acks=[1-9]', a_log)
                or (LETTER and re.search(r'custody: letters fetched=\d+ accepted=[1-9]', a_log))):
            acked = time.time() - t1
            break
        time.sleep(1)
    a_out = a.outbox()
    # P5.23: no HANDOFF frame (nothing left to pass on, no forward row).
    c_handoff = handoff_counts(c) if HANDOFF else {}
    forwarded = HANDOFF_LEFT in a.log_path.read_text(errors='replace')
    no_handoff = (not HANDOFF or (handoff_on == 0 and not forwarded and c_handoff.get('on')
                                  and c_handoff['waiting'] + c_handoff['handed']
                                  + c_handoff['refused'] == 0))
    return dict(ok=held is not None and got is not None and acked is not None
                and count(b.inbox(), 'via-carol') == 1
                and ('custody: fetched messages=' in b_log
                     or (LETTER and 'custody: letters fetched=' in b_log)) and no_handoff,
                letter_gate=LETTER, as_letter='custody: letters fetched=' in b_log,
                handoff_gate=HANDOFF, a_forwarded=forwarded, c_handoff=c_handoff,
                custody_on=on.returncode, send=(rc, status_word(out)), held_after=held,
                fetched_after=got, acked_after=acked, a_outbox=a_out[-400:],
                b_custody=[l for l in b_log.splitlines() if 'custody' in l][-3:])


# ------------------------------- friend custody over p2p (Phase 3 P3.22)
# RAVEN_FAULT_CUSTODY=1, RAVEN_FAULT_P2P=1 and RAVEN_FAULT_HINTS=1 (s30r also
# RAVEN_FAULT_FRIEND=1): custodians announced in route hints (RRH1 custody
# entries), deposits and fetches over libp2p links behind the WAN custody
# switch (RAVEN_LAB_CUSTODY_WAN=1). No `--custodian` anywhere: Alice and Bob
# use the friend mailbox Carol offers.
CUSTODY_P2P_ENV = dict(CUSTODY_ENV, RAVEN_LAB_ROUTE_HINTS='1', RAVEN_LAB_CUSTODY_WAN='1')
CUSTODY_P2P_NO_WAN_ENV = {k: v for k, v in CUSTODY_P2P_ENV.items()
                          if k != 'RAVEN_LAB_CUSTODY_WAN'}
MAIL_FRIENDS = 'raven-node custody: mail friends now '
LEFT_WITH_FRIEND = 'raven-node custody: left '
# What must never sit in a custodian's store: the pairing and link records
# (PairInit RVPI1 / RVPR1, the RLB1 bind) or a message in clear.
CUSTODY_FORBIDDEN = (b'RVPI1', b'RVPR1', b'RLB1')
HEX64 = re.compile(r'\b[0-9a-fA-F]{64}\b')


def p2p_start(via: str) -> tuple:
    """A node's p2p host on loopback with one relay (s30p, s30w)."""
    return ('--p2p-listen', '127.0.0.1:0', '--p2p-relay', via)


def custody_p2p_trio(root: Path, env: dict, c_env: dict) -> tuple:
    """Alice, Bob and Carol on relay R, pinned to each other from cards
    naming only R (p2p only: no LAN or Internet route in any book). Carol
    turns custody on (`node custody on --yes`), Alice and Bob turn friend
    mailboxes on (`custody use on --yes`). Returns (relay, a, b, c, what the
    setup did)."""
    relay = RelayProc(root)
    a, b = Node('a', root, env), Node('b', root, env)
    c = Node('c', root, c_env)
    nodes = (a, b, c)
    for n in nodes:
        n.init()
    cards = {n.name: n.p2p_card(relay.via) for n in nodes}
    for n in nodes:
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda k: k.get('allowed_peers') == 3, 30)
    for n in nodes:
        n.start(extra=p2p_start(relay.via))
    reserved = [wait_log(n, RESERVED, 60) for n in nodes]
    fps = {n.name: n.fingerprint() for n in nodes}
    for x in nodes:
        for y in nodes:
            if x is not y:
                x.add_card(cards[y.name], TAGS[y.name], fps[y.name])
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 2,', 30)
             for n in nodes]
    on = c.ash('node', 'custody', 'on', '--yes')
    use = [x.ash('custody', 'use', 'on', '--yes') for x in (a, b)]
    no_routes = all(not any(row.get('lan_dial') or row.get('internet_dial')
                            for row in book_rows(n.dir)) for n in nodes)
    ok = (allowed is not None and all(t is not None for t in reserved + gates)
          and on.returncode == 0 and 'ok friend custody on' in on.stdout
          and all(r.returncode == 0 for r in use) and no_routes)
    return relay, a, b, c, dict(ok=ok, custody_on=on.returncode,
                                mailbox_on=[r.returncode for r in use],
                                p2p_only_books=no_routes)


def custody_tags_from(node: Node, other: Node) -> int:
    """How many custodian tags `node` keeps from `other`'s route hints."""
    try:
        rows = learned_rows(node)
    except (OSError, ValueError):
        return 0
    return sum(len(e.get('custodian_tags') or []) for e in rows if isinstance(e, dict)
               and e.get('pub_hex', '').lower() == other.pub.lower())


def custody_offer_from(node: Node, other: Node) -> int | None:
    """The CUSTODY_OFFER flags `node` keeps from `other` (None: no offer)."""
    try:
        rows = learned_rows(node)
    except (OSError, ValueError):
        return None
    return next((e.get('custody_offer') for e in rows if isinstance(e, dict)
                 and e.get('pub_hex', '').lower() == other.pub.lower()), None)


def mailbox_ready(a: Node, b: Node, c: Node, tag_secs: float = 60) -> dict:
    """Warm-ups a -> c and b -> c (Carol's route hints bring her offer),
    'mail friends now 1' on Alice and Bob, then a -> b and b -> a (their
    hints carry Carol's pair-blinded tag) until each holds the other's tag."""
    warm = [send_path(a, 'carol', 'p2p-warm-ac', 'p2p')[1],
            send_path(b, 'carol', 'p2p-warm-bc', 'p2p')[1]]
    home = [wait_log(n, MAIL_FRIENDS + '1', 90) for n in (a, b)]
    pair = [send_path(a, 'bob', 'p2p-warm-ab', 'p2p')[1],
            send_path(b, 'alice', 'p2p-warm-ba', 'p2p')[1]]
    tags = wait_until(lambda: custody_tags_from(a, b) >= 1 and custody_tags_from(b, a) >= 1,
                      tag_secs)
    return dict(ok=warm == ['DELIVERED'] * 2 and all(t is not None for t in home)
                and pair == ['DELIVERED'] * 2 and tags is not None,
                warmups=warm + pair, mail_friends_s=[took(t) for t in home],
                tags_s=took(tags))


def custody_store_scan(node: Node, texts: tuple) -> list:
    """What a custodian's store files (friend_custody.sqlite and its WAL)
    hold that they never may: RVPI1, RVPR1, RLB1 or a message text."""
    found = []
    for path in sorted(node.dir.glob('friend_custody.sqlite*')):
        data = path.read_bytes()
        found += [f'{path.name}: {needle.decode()}' for needle in CUSTODY_FORBIDDEN + tuple(
            t.encode() for t in texts) if needle in data]
    return found


def logs_with_hex64(*paths: Path) -> list:
    return [p.name for p in paths if p.exists() and HEX64.search(p.read_text(errors='replace'))]


def rfc1_deposit_frame(recipient_hex: str) -> bytes:
    """A crafted RFC1 DEPOSIT (version 1, op 0x01; s30w): its object is
    nothing a custodian would store, so only the custodian's gate decides
    the answer."""
    rso1 = b'RSO1' + bytes(124)
    return (b'RFC1' + bytes([1, 0x01]) + b'\xd5' * 8 + bytes.fromhex(recipient_hex)
            + struct.pack('>I', len(rso1)) + rso1)


def p2p_custody_deposit(node: Node, custodian: Node, recipient: Node) -> str:
    """The crafted DEPOSIT over a lab P2pDial from `node` to `custodian`
    (raven-node takes RFC1 on an IPC dial only in a lab run): the deposit
    answer's code name, or what went wrong."""
    import base64
    peer = p2p_peer(custodian.card())
    frame = base64.b64encode(rfc1_deposit_frame(recipient.pub)).decode()
    r = node_ipc(node, {'op': 'p2p_dial', 'v': 1, 'multiaddr': f'/p2p/{peer}',
                        'expected_pub_hex': custodian.pub, 'frames_b64': [frame]},
                 timeout=90)
    if r.get('ok') != 'p2p_dial_result':
        return f"no dial result: {r.get('code') or r}"
    names = {0: 'OK', 1: 'DUPLICATE', 2: 'POLICY_DENIED', 3: 'HOLD', 4: 'NOT_VERIFIED'}
    for f in r.get('frames_b64') or []:
        reply = base64.b64decode(f)
        if reply[:4] == b'RFC1' and len(reply) == 14 + 33 and reply[5] == 0x81:
            return names.get(reply[14], f'code {reply[14]}')
    return 'no deposit answer'


def s30p_via_a_friend_over_p2p(root: Path) -> dict:
    """Phase 3 item 3 (RAVEN_FAULT_CUSTODY=1, RAVEN_FAULT_P2P=1 and
    RAVEN_FAULT_HINTS=1): s30 over the internet carriers. Relay R; Alice, Bob
    and Carol pinned from cards naming only R, the WAN custody switch on
    (RAVEN_LAB_CUSTODY_WAN=1). Carol offers to hold mail, Alice and Bob turn
    friend mailboxes on; nobody names a custodian (no `--custodian`). Bob
    stops; Alice's message is held by Carol within 60 s (over p2p); Alice
    stops, Bob starts and has it exactly once within 60 s; Bob stops, Alice
    starts and fetches his ACK from Carol within 60 s, her outbox saying
    delivered. Neither book names a custodian, Carol's store holds no
    RVPI1/RVPR1/RLB1 and no message text, no log a 64-hex value, and every
    custody line names p2p_dial."""
    relay, a, b, c, setup = custody_p2p_trio(root, CUSTODY_P2P_ENV, CUSTODY_P2P_ENV)
    ready = mailbox_ready(a, b, c)
    offer = custody_offer_from(a, c)
    text = 's30p-via-carol'
    b.stop()
    rc, out, _ = a.send('bob', text)
    queued = status_word(out)
    mid = (re.search(r'mid=([0-9a-f]{8})', out) or [None, ''])[1]
    held = wait_for(lambda: (held_for(c, b) or 0) >= 1, 60)
    scan_held = custody_store_scan(c, (text,))
    a.stop()
    b.start(extra=p2p_start(relay.via))
    got = wait_for(lambda: count(b.inbox(), text) >= 1, 60)
    # Bob's ACK: Alice is away, so it is left with Carol for her.
    ack_held = wait_for(lambda: (held_for(c, a) or 0) >= 1, 60)
    time.sleep(3)
    once = count(b.inbox(), text)
    b.stop()
    mark = log_size(a)
    a.start(extra=p2p_start(relay.via))
    acked = wait_for(lambda: ACK_VIA_CUSTODIAN.search(
        a.log_path.read_text(errors='replace')[mark:]) is not None, 60)
    delivered = wait_until(lambda: any(i['id'] == mid and i['state'] == 'delivered'
                                       for i in outbox_items(a)), 30) if mid else None
    for n in (a, b, c):
        n.stop()
    relay.stop()
    books = {n.name: b'"custodians"' in book_plain(n.dir) for n in (a, b)}
    scan_end = custody_store_scan(c, (text,))
    logs = [n.log_path for n in (a, b, c)] + [relay.log_path]
    hex_logs = logs_with_hex64(*logs)
    left = [l for n in (a, b) for l in n.log_path.read_text(errors='replace').splitlines()
            if LEFT_WITH_FRIEND in l]
    return dict(
        ok=setup['ok'] and ready['ok'] and offer is not None and offer & 0x01 == 0x01
        and queued == 'QUEUED' and held is not None and got is not None and once == 1
        and ack_held is not None and acked is not None and delivered is not None
        and not any(books.values()) and not scan_held and not scan_end and not hex_logs
        and len(left) >= 2 and all('p2p_dial' in l for l in left),
        setup=setup, mailbox=ready, offer_flags=offer, send=(rc, queued),
        held_s=held, fetched_s=got, ack_held_s=ack_held, ack_fetched_s=acked,
        a_delivered_s=took(delivered), exactly_once=once, books_name_custodians=books,
        store_findings=scan_held + scan_end, logs_with_64_hex=hex_logs,
        custody_lines=[l.split('raven-node ', 1)[-1] for l in left])


def s30w_wan_custody_needs_both_switches(root: Path) -> dict:
    """Phase 3 item 3 (as s30p): Carol starts without the WAN custody switch.
    Her offer lacks the WAN bit, so Alice's message for the absent Bob says
    CUSTODIAN_NOT_OFFERING and Carol holds nothing after 60 s; a crafted
    DEPOSIT over a lab P2pDial is answered HOLD and creates no store at
    Carol's. Carol restarted with the switch: her offer gains the WAN bit
    and Alice's message is held by her within 60 s."""
    relay, a, b, c, setup = custody_p2p_trio(root, CUSTODY_P2P_ENV, CUSTODY_P2P_NO_WAN_ENV)
    ready = mailbox_ready(a, b, c)
    offer_before = custody_offer_from(a, c)
    text = 's30w-needs-wan'
    b.stop()
    rc, out, _ = a.send('bob', text)
    sent_at = time.time()
    queued = status_word(out)
    code = None

    def not_offering() -> bool:
        nonlocal code
        code = a.outbox()
        # CUSTODIAN_NOT_OFFERING, in the list's words.
        return "doesn't hold messages for you, or not over the internet" in code

    said = wait_until(not_offering, 60)
    time.sleep(max(0.0, 60 - (time.time() - sent_at)))
    held_without = held_for(c, b)
    store_before = sorted(p.name for p in c.dir.glob('friend_custody.sqlite*'))
    crafted = p2p_custody_deposit(a, c, b)
    store_after = sorted(p.name for p in c.dir.glob('friend_custody.sqlite*'))
    c.stop()
    c.env = CUSTODY_P2P_ENV
    c.start(extra=p2p_start(relay.via))
    t0 = time.time()
    wan_bit = wait_until(lambda: ((custody_offer_from(a, c) or 0) & 0x01) == 0x01, 60)
    held = wait_for(lambda: (held_for(c, b) or 0) >= 1, max(1.0, 60 - (time.time() - t0)))
    held_s = None if held is None else round(time.time() - t0, 1)
    for n in (a, c):
        n.stop()
    relay.stop()
    return dict(
        ok=setup['ok'] and ready['ok'] and offer_before is not None
        and offer_before & 0x01 == 0 and queued == 'QUEUED' and said is not None
        and held_without == 0 and crafted == 'HOLD' and not store_before and not store_after
        and wan_bit is not None and held is not None,
        setup=setup, mailbox=ready, offer_flags_without_switch=offer_before,
        send=(rc, queued), not_offering_s=took(said), held_after_60s=held_without,
        crafted_deposit=crafted, store_files=store_before + store_after,
        wan_bit_s=took(wan_bit), held_after_restart_s=held_s,
        a_outbox=[l.strip() for l in (code or '').splitlines() if 'CUSTOD' in l][:3])


def s30r_relay_and_custodian_on_one_node(root: Path) -> dict:
    """Phase 3 item 3 (as s30p, and RAVEN_FAULT_FRIEND=1): Carol runs the
    Phase 2 friend relay and holds mail; Alice and Bob listen nowhere, pick
    her relay from its offer and her as mail friend. Bob stops: Alice's
    circuit to him through Carol's relay finds no reservation (NotOnRelay:
    contact_offline), and her message is deposited with Carol's identity;
    Bob returns, fetches it and has one inbox row. Carol's relay PeerId is
    not her profile's, and its status holds counts only."""
    env = dict(RAVEN_LAB_CUSTODY_AFTER_MS='0', RAVEN_LAB_CUSTODY_FETCH_MS='1000',
               RAVEN_LAB_CUSTODY_WAN='1', RAVEN_LAB_TEST_A='1')
    nodes, ready = friend_nodes(root, 'c', 'ab', env=env)
    a, b, c = nodes['a'], nodes['b'], nodes['c']
    on = c.ash('node', 'custody', 'on', '--yes')
    use = [x.ash('custody', 'use', 'on', '--yes').returncode for x in (a, b)]
    named = offer_friend_relay(c, 2)
    asks = [lan_send(x, 'carol', f's30r-{x.name}-to-c') for x in (a, b)]
    reserved = wait_until(lambda: offered_slots(a, 1) and offered_slots(b, 1), 60)
    home = [wait_log(n, MAIL_FRIENDS + '1', 90) for n in (a, b)]
    hints = [lan_send(a, 'bob', 's30r-hints-ab'), lan_send(b, 'alice', 's30r-hints-ba')]
    tags = wait_until(lambda: custody_tags_from(a, b) >= 1 and custody_tags_from(b, a) >= 1
                      and (learned_entry(a, b) or {}).get('relays', 0) >= 1, 60)
    relay_peer = c.friend_relay().get('peer_id', '')
    profile_peer = p2p_peer(c.card())
    b.stop()
    mark = log_size(a)
    # No forced carrier: a send that forces one is never left with a friend.
    rc, word, path = send_path(a, 'bob', 's30r-via-carol')
    held = wait_for(lambda: (held_for(c, b) or 0) >= 1, 60)
    a_log = a.log_path.read_text(errors='replace')[mark:]
    offline = a_log.find('raven-node p2p: a contact is unreachable (contact_offline)')
    left = a_log.find(LEFT_WITH_FRIEND)
    b.start(extra=('--p2p-listen', 'relay'))
    got = wait_for(lambda: count(b.inbox(), 's30r-via-carol') >= 1, 60)
    time.sleep(3)
    once = count(b.inbox(), 's30r-via-carol')
    status = c.friend_relay()
    status_text = json.dumps(status)
    members = [p2p_peer(n.card()) for n in (a, b)]
    counts_only = (isinstance(status.get('counts'), dict)
                   and not any(m in status_text for m in members)
                   and not any(n.pub.lower() in status_text.lower() for n in (a, b, c)))
    return dict(
        ok=ready and on.returncode == 0 and use == [0, 0] and named is not None
        and asks == ['DELIVERED'] * 2 and reserved is not None
        and all(t is not None for t in home) and hints == ['DELIVERED'] * 2
        and tags is not None and relay_peer != '' and relay_peer != profile_peer
        and word == 'QUEUED' and held is not None and 0 <= offline < left
        and got is not None and once == 1 and counts_only,
        ready=ready, custody_on=on.returncode, mailbox_on=use, offer_asks=asks,
        relay_reserved_s=took(reserved), mail_friends_s=[took(t) for t in home],
        hints_lan=hints, tags_s=took(tags), relay_key_is_its_own=relay_peer != profile_peer,
        send=(rc, word, path), held_s=held, not_on_relay_first=0 <= offline < left,
        deposit=(a_log[left:].splitlines() or [''])[0].split('raven-node ', 1)[-1],
        fetched_s=got, exactly_once=once, relay_status_counts_only=counts_only,
        relay_counts=status.get('counts'))


def s31_app_channel(root: Path) -> dict:
    """RDAP's agent payload over raven-node (app channel, lab): no prior
    session, so Alice's node pairs itself; Bob's node keeps the payload out
    of chat and serves it to its one consumer."""
    env = dict(ENV)
    env.update(RAVEN_LAB_TEST_A='1')
    a, b = Node('a', root, env), Node('b', root, env)
    for n in (a, b):
        n.init()
        n.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    sub = a.ash('lab', 'app-submit', '--to', '@bob', '--ref', 'task-1', '--body', 'agent task 1')
    m = re.search(r'mid=([0-9a-f]{32})', sub.stdout)
    got, inbox_out = None, ''
    t0 = time.time()
    while time.time() - t0 < 60:
        inbox_out = b.ash('lab', 'app-inbox', '--wait-ms', '2000').stdout
        if 'agent task 1' in inbox_out:
            got = time.time() - t0
            break
    chat = b.ash('inbox').stdout
    status = ''
    t1 = time.time()
    while m and time.time() - t1 < 60:
        status = a.ash('outbox', 'status', m.group(1)[:8]).stdout
        if 'delivered' in status:
            break
        time.sleep(1)
    dup = a.ash('lab', 'app-submit', '--to', '@bob', '--ref', 'task-1', '--body', 'agent task 1')
    conflict = a.ash('lab', 'app-submit', '--to', '@bob', '--ref', 'task-1', '--body', 'other')
    sm = re.search(r'sender_device=([0-9a-f]{64}) mid=([0-9a-f]{32})', inbox_out)
    acked = b.ash('lab', 'app-ack', '--sender-device-hex', sm.group(1),
                  '--message-id-hex', sm.group(2)).stdout if sm else ''
    after = b.ash('lab', 'app-inbox').stdout
    return dict(ok=bool(m) and got is not None and 'agent task 1' not in chat
                and 'delivered' in status and '(duplicate)' in dup.stdout
                and 'APP_CLIENT_REF_CONFLICT' in (conflict.stdout + conflict.stderr)
                and '1 removed' in acked and 'agent task 1' not in after
                and 'agent payload' in status,
                submit=(sub.returncode, sub.stdout.strip()[-200:], sub.stderr.strip()[-300:]),
                got_after=got, chat_has_it='agent task 1' in chat, status=status.strip()[-200:],
                dup=dup.stdout.strip()[-120:], conflict=(conflict.stdout + conflict.stderr)[-160:],
                acked=acked.strip(), after=after.strip()[-120:])


RDAP_TREE = os.environ.get('RAVEN_FAULT_RDAP', '')
# Every process the RDAP helpers below start (RDAP workers and commands) and
# s32c's relay: an RDAP process names no `data-dir <root>/` in its argv, so
# main()'s pkill misses it. main() ends what is still alive after each
# scenario (end_children).
_CHILDREN: list = []


def end_children() -> None:
    """Terminate every process in _CHILDREN still alive, give them 5 s, kill
    the rest, and clear the list (main(), after each scenario)."""
    alive = [p for p in _CHILDREN if p.poll() is None]
    for p in alive:
        p.terminate()
    deadline = time.time() + 5
    for p in alive:
        try:
            p.wait(max(0.0, deadline - time.time()))
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    _CHILDREN.clear()


def rdap_cmd(*argv: str) -> list:
    """`rdap <argv>` with RDAP_TREE's own venv."""
    tree = Path(RDAP_TREE)
    return [str(tree / '.venv' / 'bin' / 'python'), str(tree / 'rdap.py'), *argv]


def rdap_run(home: Path, *argv: str, timeout: float = 150) -> subprocess.CompletedProcess:
    """`rdap <argv>` in the RDAP home `home`, in _CHILDREN while it runs;
    killed at `timeout` (its stderr then says so)."""
    proc = subprocess.Popen(rdap_cmd(*argv), env=rdap_env(home), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _CHILDREN.append(proc)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        err += f'\n(killed after {timeout} s)'
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def rdap_ask(homes: dict, text: str, wait: int) -> tuple:
    """Alice's `rdap ask <text> --name bob --wait <wait>`: (the process, its
    seconds). The subprocess gets 60 s past `--wait`, so it never dies at
    that boundary."""
    t0 = time.time()
    proc = rdap_run(homes['alice'], 'ask', text, '--name', 'bob', '--wait', str(wait),
                    timeout=wait + 60)
    return proc, round(time.time() - t0, 1)


def bind_rdap_homes(root: Path, a: Node, b: Node) -> dict:
    """Two RDAP homes, `alice` bound to `a`'s node and `bob` to `b`'s (init
    --no-internet, raven-bind --from-node --raven-channel), each trusting
    the other's raven key through raven-node: {'alice': home, 'bob': home}."""
    homes = {}
    for n, name in ((a, 'alice'), (b, 'bob')):
        home = root / f'rdap-{name}'
        home.mkdir()
        homes[name] = home
        who = n.ash('whoami', '--json').stdout
        (n.dir / 'whoami.public.json').write_text(who)
        init = rdap_run(home, 'init', '--name', name, '--role', 'test', '--no-internet')
        bind = rdap_run(home, 'raven-bind', '--from-node', str(n.dir), '--raven-channel')
        assert init.returncode == 0 and bind.returncode == 0, init.stderr + bind.stdout + bind.stderr
    pin = {name: f'raven:{n.address}:{n.pub}' for n, name in ((a, 'alice'), (b, 'bob'))}
    t1 = rdap_run(homes['alice'], 'trust', pin['bob'], '--name', 'bob', '--via', 'raven')
    t2 = rdap_run(homes['bob'], 'trust', pin['alice'], '--name', 'alice', '--via', 'raven')
    assert t1.returncode == 0 and t2.returncode == 0, t1.stdout + t1.stderr + t2.stdout + t2.stderr
    return homes


class RdapWorker:
    """`rdap start --provider echo` in `home`: serves the raven-channel tasks
    its node holds, logging to <root>/rdap-<tag>-worker.log; in _CHILDREN.
    `ready`: its serving line came within 30 s (it says so once its node
    took it as the app channel's consumer)."""

    def __init__(self, root: Path, home: Path, tag: str) -> None:
        self.log_path = root / f'rdap-{tag}-worker.log'
        mark = self.log_path.stat().st_size if self.log_path.exists() else 0
        with open(self.log_path, 'a') as log:
            self.proc = subprocess.Popen(rdap_cmd('start', '--provider', 'echo'),
                                         env=rdap_env(home), stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=subprocess.STDOUT)
        _CHILDREN.append(self.proc)
        self.ready = False
        deadline = time.time() + 30
        while time.time() < deadline and self.proc.poll() is None:
            if '] serving ' in self.text(mark):
                self.ready = True
                break
            time.sleep(0.2)

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)

    def text(self, since: int = 0) -> str:
        """The log from byte offset `since`."""
        try:
            return self.log_path.read_bytes()[since:].decode(errors='replace')
        except OSError:
            return ''


def answered(proc: subprocess.CompletedProcess, token: str) -> bool:
    """`rdap ask` printed Bob's verified answer, carrying `token`."""
    return (proc.returncode == 0 and token in proc.stdout
            and 'verified answer from bob via raven-node' in proc.stdout)


def outbox_items(node: Node) -> list:
    """Every item `ash outbox list` shows (waiting and recently finished),
    with the state, carrier, path and attempts its `outbox status` gives."""
    out = node.ash('outbox', 'list').stdout
    items = []
    for mid in re.findall(r'^\s+([0-9a-f]{8})\s', out, re.M):
        st = node.ash('outbox', 'status', mid).stdout
        items.append(dict(id=mid, what=(st.splitlines() or [''])[0].strip(),
                          state=outbox_field(st, 'state'), carrier=outbox_field(st, 'carrier'),
                          path=outbox_field(st, 'path'), attempts=outbox_field(st, 'attempts')))
    return items


def agent_items(items: list) -> list:
    """The agent payload (RDAP) rows of `outbox_items`."""
    return [i for i in items if 'agent payload' in i['what']]


def settled_agent_items(node: Node, secs: float = 20) -> list:
    """The node's agent items once each is delivered (or at the deadline):
    an answer's sender may still be waiting for its ACK when `ask` prints."""
    t0 = time.time()
    while True:
        items = agent_items(outbox_items(node))
        if (items and all(i['state'] == 'delivered' for i in items)) or time.time() - t0 >= secs:
            return items
        time.sleep(0.5)


def carriers_used(*nodes: Node) -> set:
    """Every carrier an outbox item of these nodes names."""
    return {i['carrier'] for n in nodes for i in outbox_items(n) if i['carrier']}


PROBE = 'raven-node app: probe '


def probe_line(node: Node, since: int = 0) -> str | None:
    """The last AppSubmit probe line (`raven-node app: probe …`, from that
    text on) in the node's log after offset `since`, or None."""
    text = node.log_path.read_text(errors='replace')[since:]
    lines = [l[l.index(PROBE):].strip() for l in text.splitlines() if PROBE in l]
    return lines[-1] if lines else None


def clear_book_routes(node: Node, tag: str) -> None:
    """`contact set-addr @tag --clear lan --clear internet`: p2p only."""
    r = node.ash('contact', 'set-addr', f'@{tag}', '--clear', 'lan', '--clear', 'internet')
    assert r.returncode == 0, r.stdout + r.stderr


def book_row(node: Node, other: Node) -> dict:
    """The routes `node`'s contact book holds for `other`."""
    contacts = book_rows(node.dir)
    row = next((c for c in contacts if c.get('pub_hex', '').lower() == other.pub.lower()), {})
    return {k: row.get(k) for k in ('lan_dial', 'internet_dial', 'p2p', 'p2p_via')
            if row.get(k) not in (None, '', [])}


def in_chat(nodes: tuple, tokens: tuple) -> list:
    """The tokens some node's chat inbox holds (an agent payload never)."""
    inboxes = [n.inbox() for n in nodes]
    return [t for t in tokens if any(t in inbox for inbox in inboxes)]


def s32_rdap_over_raven(root: Path) -> dict:
    """RDAP tasks over Raven end to end (app channel, lab): two bound RDAP
    homes, no HTTP; Alice's `rdap ask` reaches Bob's agent through the two
    raven-nodes and the verified answer comes back the same way."""
    env = dict(ENV)
    env.update(RAVEN_LAB_TEST_A='1')
    a, b = Node('a', root, env), Node('b', root, env)
    for n in (a, b):
        n.init()
        n.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    homes = bind_rdap_homes(root, a, b)
    worker = RdapWorker(root, homes['bob'], 'bob')
    try:
        ask, took = rdap_ask(homes, 'RAVEN_A2A_OK_M4 please', 60)
    finally:
        worker.stop()
    bob_out = worker.text()
    chat = b.ash('inbox').stdout
    seeds = [p for p in homes['alice'].rglob('device_ed25519.seed')
             if 'retired' not in p.parts] + [p for p in homes['bob'].rglob('device_ed25519.seed')
                                             if 'retired' not in p.parts]
    outputs = list((homes['bob'] / 'team-repo' / '.team' / 'outputs').rglob('*.md')) \
        if (homes['bob'] / 'team-repo' / '.team' / 'outputs').exists() else []
    return dict(
        ok=answered(ask, 'RAVEN_A2A_OK_M4')
        and 'RAVEN_A2A_OK_M4' not in chat and not seeds and not outputs,
        ask=(ask.returncode, ask.stdout[-400:], ask.stderr[-400:]), seconds_to_answer=took,
        bob_worker=bob_out[-500:], chat_has_it='RAVEN_A2A_OK_M4' in chat,
        seeds_left=[str(p) for p in seeds], outputs_written=[str(p) for p in outputs])


def s32b_rdap_over_internet(root: Path) -> dict:
    """RDAP over Internet direct only (study x1): each node pins the other
    with its Internet listener as the only route. Ask #1 is answered and
    every agent payload on both nodes went internet_dial. Bob's worker and
    node stop; ask #2 waits in Alice's outbox (queued, attempted) and is
    answered within 90 s of Bob's return on the same Internet port. Alice
    probes nothing after ask #1 (the session stands), nothing goes
    lan_dial, and neither chat inbox holds a token. No LAN beacon under
    RAVEN_FAULT_BEACON=1 (without_beacon): Internet direct only."""
    env = without_beacon(dict(ENV, RAVEN_LAB_TEST_A='1'))
    a, b = Node('a', root, env), Node('b', root, env)
    ports = {}
    for n in (a, b):
        n.init()
        ports[n.name] = free_tcp_port()       # kept for Bob's restart
        n.start(inet_port=ports[n.name])
    a.add_pinned_internet(b, 'bob')
    b.add_pinned_internet(a, 'alice')
    homes = bind_rdap_homes(root, a, b)
    workers = [RdapWorker(root, homes['bob'], 'bob')]
    second: list = []
    wait2 = 150
    thread = None
    try:
        ask1, s1 = rdap_ask(homes, 'RAVEN_A2A_INET_1 please', 60)
        first_probe = probe_line(a)
        items1 = [settled_agent_items(n) for n in (a, b)]
        mark = log_size(a)
        workers[-1].stop()
        b.stop()
        thread = threading.Thread(
            target=lambda: second.append(
                rdap_ask(homes, 'RAVEN_A2A_INET_2 while bob is away', wait2) + (time.time(),)),
            daemon=True)
        thread.start()
        time.sleep(8)
        waiting = a.outbox()
        m = re.search(r'^\s+[0-9a-f]{8}\s+queued\s+agent payload.*?\battempts (\d+)',
                      waiting, re.M)
        b.start(inet_port=ports['b'])
        back = time.time()
        workers.append(RdapWorker(root, homes['bob'], 'bob'))
        thread.join(wait2 + 70)
    finally:
        for w in workers:
            w.stop()
        if thread is not None:
            thread.join(wait2 + 70)
    ask2, s2, done = second[0] if second else (None, None, None)
    after_return = None if done is None else round(done - back, 1)
    later_probe = probe_line(a, mark)
    used = carriers_used(a, b)
    chat = in_chat((a, b), ('RAVEN_A2A_INET_1', 'RAVEN_A2A_INET_2'))
    return dict(
        ok=answered(ask1, 'RAVEN_A2A_INET_1')
        and all(items and all(i['carrier'] == 'internet_dial' for i in items)
                for items in items1)
        and m is not None and int(m.group(1)) >= 1
        and ask2 is not None and answered(ask2, 'RAVEN_A2A_INET_2')
        and after_return is not None and after_return <= 90
        and later_probe is None and 'lan_dial' not in used and not chat,
        ask1=(ask1.returncode, ask1.stdout[-300:], ask1.stderr[-300:]), ask1_s=s1,
        first_probe=first_probe, a_items_1=items1[0], b_items_1=items1[1],
        a_outbox_while_bob_down=waiting[-600:],
        queued_attempts=int(m.group(1)) if m else None,
        ask2=None if ask2 is None else (ask2.returncode, ask2.stdout[-300:], ask2.stderr[-300:]),
        ask2_s=s2, answer_after_return_s=after_return, probe_after_ask1=later_probe,
        carriers=sorted(used), tokens_in_chat=chat,
        worker_ready=[w.ready for w in workers], bob_worker=workers[-1].text()[-500:])


GATE_1 = 'raven-node p2p: peer gate reloaded (verified contacts 1,'


def s32c_rdap_over_relay(root: Path) -> dict:
    """RDAP over p2p through a relay only (study x2): relay-only nodes (no
    listening port), card routes, no LAN or Internet route. The ask is
    answered, every agent payload on both nodes went p2p_dial `relayed`
    (the relay counts a circuit), Alice's probe line is `p2p_dial offer`
    alone, and no node log names a PeerId."""
    relay = RelayProc(root)
    _CHILDREN.append(relay.proc)
    worker = None
    try:
        a, b = Node('a', root, P2P_RELAY_ONLY_ENV), Node('b', root, P2P_RELAY_ONLY_ENV)
        for n in (a, b):
            n.init()
        cards = {n.name: n.p2p_card(relay.via) for n in (a, b)}
        for n in (a, b):
            relay.allow(cards[n.name])
        allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30)
        for n in (a, b):
            n.start(extra=('--p2p-listen', 'relay', '--p2p-relay', relay.via))
        reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b)]
        a.add_card(cards['b'], 'bob', b.fingerprint())
        b.add_card(cards['a'], 'alice', a.fingerprint())
        gates = [wait_log(n, GATE_1, 30) for n in (a, b)]
        clear_book_routes(a, 'bob')
        clear_book_routes(b, 'alice')
        homes = bind_rdap_homes(root, a, b)
        worker = RdapWorker(root, homes['bob'], 'bob')
        ask, took = rdap_ask(homes, 'RAVEN_A2A_RELAY please', 60)
        items = [settled_agent_items(n) for n in (a, b)]
        counts = relay.wait_counts(lambda c: c.get('circuits', 0) >= 1, 10) or relay.counts()
    finally:
        if worker is not None:
            worker.stop()
        relay.stop()
    used = carriers_used(a, b)
    probe = probe_line(a)
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=allowed is not None and None not in reserved + gates
        and answered(ask, 'RAVEN_A2A_RELAY')
        and all(it and all((i['carrier'], i['path']) == ('p2p_dial', 'relayed') for i in it)
                for it in items)
        and counts.get('circuits', 0) >= 1
        and not used & {'lan_dial', 'internet_dial'}
        and probe == PROBE + 'p2p_dial offer' and '12D3KooW' not in logs,
        ask=(ask.returncode, ask.stdout[-300:], ask.stderr[-300:]), seconds_to_answer=took,
        a_items=items[0], b_items=items[1], carriers=sorted(used), probe=probe,
        relay_counts=counts, peer_id_in_logs='12D3KooW' in logs, worker_ready=worker.ready,
        bob_worker=worker.text()[-500:])


def reversal_pair(root: Path) -> tuple:
    """s32d's and s32e's two p2p nodes, no relay (study x3): Alice listens
    on a loopback port, Bob on a fixed one that his card names (his own
    address); Alice's card is `p2p=` only, so Bob reaches her only over a
    connection she opened (`--compat` while route hints are on: a
    raven-card/2 either way). Both pinned, the peer gates reloaded, and
    Bob's book holds no LAN or Internet route for Alice. Returns (a, b,
    setup facts)."""
    a, b = Node('a', root, P2P_ENV), Node('b', root, P2P_ENV)
    for n in (a, b):
        n.init()
    b_port = free_tcp_port()
    a.start(extra=('--p2p-listen', '127.0.0.1:0'))
    b.start(extra=('--p2p-listen', f'127.0.0.1:{b_port}'))
    up = [wait_log(n, 'raven-node p2p: host up (listeners=2', 30) for n in (a, b)]
    m = re.search(r'p2p_peer\s+(12D3KooW\S+)', b.ash('status').stdout)
    assert m, 'no p2p_peer row in b status'
    b_card = b.p2p_card(f'/ip4/127.0.0.1/tcp/{b_port}/p2p/{m.group(1)}')
    compat = ('--compat',) if HINTS else ()
    a_out = a.ash('whoami', '--card', *compat)
    a_card = next((l for l in a_out.stdout.splitlines() if l.startswith('raven-card/2 ')), '')
    assert ' p2p=' in a_card and ' via=' not in a_card, a_out.stdout + a_out.stderr
    a.add_card(b_card, 'bob', b.fingerprint())
    b.add_card(a_card, 'alice', a.fingerprint())
    gates = [wait_log(n, GATE_1, 30) for n in (a, b)]
    clear_book_routes(b, 'alice')
    return a, b, dict(up=up, gates=gates)


def s32d_rdap_answer_by_reversal(root: Path) -> dict:
    """RDAP over p2p where the answer can only ride the asker's own
    connection (study x3): no LAN or Internet route either way; Alice's task
    is p2p_dial `direct` to Bob's address, Bob's answer p2p_dial `reversed`
    (his outbox logs `delivered 1 (p2p_dial, reversed)`)."""
    a, b, setup = reversal_pair(root)
    clear_book_routes(a, 'bob')
    homes = bind_rdap_homes(root, a, b)
    worker = None
    try:
        worker = RdapWorker(root, homes['bob'], 'bob')
        ask, took = rdap_ask(homes, 'RAVEN_A2A_REVERSAL please', 60)
        a_items, b_items = (settled_agent_items(n) for n in (a, b))
    finally:
        if worker is not None:
            worker.stop()
    used = carriers_used(a, b)
    reversed_line = 'raven-node outbox: delivered 1 (p2p_dial, reversed)' in \
        b.log_path.read_text(errors='replace')
    return dict(
        ok=None not in setup['up'] + setup['gates'] and answered(ask, 'RAVEN_A2A_REVERSAL')
        and bool(a_items)
        and all((i['carrier'], i['path']) == ('p2p_dial', 'direct') for i in a_items)
        and bool(b_items)
        and all((i['carrier'], i['path']) == ('p2p_dial', 'reversed') for i in b_items)
        and reversed_line and not used & {'lan_dial', 'internet_dial'},
        **setup, ask=(ask.returncode, ask.stdout[-300:], ask.stderr[-300:]),
        seconds_to_answer=took, a_items=a_items, b_items=b_items, carriers=sorted(used),
        b_delivered_reversed=reversed_line, a_probe=probe_line(a), worker_ready=worker.ready,
        bob_worker=worker.text()[-500:])


# Every LAN route, then the Internet route, each dialled and failed (a
# `skipped` route was not dialled), then the offer on p2p.
PROBE_PAST_TWO = re.compile(
    r'raven-node app: probe (lan_dial (?!skipped,)\S+, )+internet_dial (?!skipped,)\S+, '
    r'p2p_dial offer$')


def s32e_rdap_probe_past_two_routes(root: Path) -> dict:
    """RDAP's own `ask` with no session yet (study x4, after step 6b):
    Alice's book holds a LAN and an Internet address for Bob ahead of his
    p2p route, each a proxy that closes every connection at once; Bob's
    book for Alice is p2p only. AppSubmit's pairing probe dials LAN and
    Internet first and pairs on p2p (Alice's probe line, the proof; each
    proxy also counts a connection), the task is delivered on p2p_dial, and
    Bob's answer rides Alice's connection (`reversed`) with no probe of his
    (he holds the session). A pre-6b build fails here: every submit is
    APP_PEER_UNREACHABLE (its probe tried the first two routes only)."""
    a, b, setup = reversal_pair(root)
    dead = (Proxy('127.0.0.1:9'), Proxy('127.0.0.1:9'))
    for p in dead:
        p.mode = 'refuse'
    worker = None
    try:
        r = a.ash('contact', 'set-addr', '@bob', '--lan', dead[0].addr,
                  '--internet', dead[1].addr)
        assert r.returncode == 0, r.stdout + r.stderr
        row = book_row(a, b)
        assert all(row.get(k) for k in ('lan_dial', 'internet_dial', 'p2p')), row
        homes = bind_rdap_homes(root, a, b)
        worker = RdapWorker(root, homes['bob'], 'bob')
        before = [p.conns for p in dead]
        ask, took = rdap_ask(homes, 'RAVEN_A2A_PROBE please', 60)
        dialled = [p.conns - n for p, n in zip(dead, before)]
        a_items, b_items = (settled_agent_items(n) for n in (a, b))
    finally:
        if worker is not None:
            worker.stop()
        for p in dead:
            p.lsock.close()
    probe = probe_line(a)
    return dict(
        ok=None not in setup['up'] + setup['gates'] and answered(ask, 'RAVEN_A2A_PROBE')
        and probe is not None and PROBE_PAST_TWO.match(probe) is not None
        and all(n >= 1 for n in dialled)
        and bool(a_items) and all(i['carrier'] == 'p2p_dial' for i in a_items)
        and bool(b_items)
        and all((i['carrier'], i['path']) == ('p2p_dial', 'reversed') for i in b_items)
        and probe_line(b) is None,
        **setup, routes=sorted(row), ask=(ask.returncode, ask.stdout[-300:], ask.stderr[-300:]),
        seconds_to_answer=took, probe=probe, dead_route_conns=dialled, a_items=a_items,
        b_items=b_items, b_probe=probe_line(b), worker_ready=worker.ready,
        bob_worker=worker.text()[-500:])


def outbox_field(out: str, key: str) -> str | None:
    """One field of `ash outbox status` (`  attempts    4`)."""
    m = re.search(rf'^\s*{key}\s+(.+?)\s*$', out, re.M)
    return m.group(1) if m else None


def next_try_s(value: str | None) -> int | None:
    """`next try` in seconds (`now` is 0, `in 23 s`, `in 4 min`)."""
    if value == 'now':
        return 0
    m = re.fullmatch(r'in (\d+) (s|min)', value or '')
    return int(m.group(1)) * (60 if m.group(2) == 'min' else 1) if m else None


def s33_network_change(root: Path) -> dict:
    """G1: Alice's network changes (netwatch fed by the debug lab event file)
    while her message to Bob, who is down, backs off: one acted-on change, an
    immediate retry on a fresh backoff, then delivery exactly once when Bob is
    back on his port."""
    net = root / 'a-net.txt'
    net.write_text('up 192.0.2.10/24\n')
    env = dict(ENV)
    env['RAVEN_LAB_NETWATCH_EVENTS'] = str(net)
    a, b = Node('a', root, env), Node('b', root)
    a.init()
    b.init()
    a.start()
    b.start()
    a.add(b, 'bob')
    b.add(a, 'alice')
    a.send('bob', 'warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    rc, out, _ = a.send('bob', 'after-netchange')
    m = re.search(r'mid=([0-9a-f]{8})', out)
    if not m:
        return dict(ok=False, send=(rc, status_word(out)), out=out[-400:])
    mid = m.group(1)

    def status() -> tuple[int, int | None]:
        st = a.ash('outbox', 'status', mid).stdout
        return int(outbox_field(st, 'attempts') or 0), next_try_s(outbox_field(st, 'next try'))

    t0 = time.time()
    attempts, nxt = status()
    while attempts < 4 and time.time() - t0 < 120:
        time.sleep(0.5)
        attempts, nxt = status()
    backed_off = dict(attempts=attempts, next_try_s=nxt, after_s=round(time.time() - t0, 1))
    with open(net, 'a') as f:
        f.write('down 192.0.2.10/24\nup 198.51.100.7/24\n')
    t1 = time.time()
    retried = None
    while time.time() - t1 < 20:
        n, nxt = status()
        if n > attempts and nxt is not None and nxt <= 8:
            retried = dict(after_s=round(time.time() - t1, 1), attempts=n, next_try_s=nxt)
            break
        time.sleep(0.5)
    b.start(port=port)
    took = wait_inbox(b, 'after-netchange', 90)
    log = a.log_path.read_text(errors='replace')
    changes = [l for l in log.splitlines() if 'raven-node netwatch: network changed' in l]
    return dict(ok=backed_off['attempts'] >= 4 and (backed_off['next_try_s'] or 0) >= 15
                and retried is not None and retried['after_s'] <= 12
                and took is not None and count(b.inbox(), 'after-netchange') == 1
                and len(changes) == 1,
                send=(rc, status_word(out)), backed_off=backed_off,
                retry_after_change=retried, delivered_after_bob_back_s=took,
                changes=changes, outbox=a.outbox()[-400:])


def wait_log(node: Node, text: str, secs: float, since: int = 0) -> float | None:
    """Seconds until `text` is in the node's log after offset `since`."""
    t0 = time.time()
    while time.time() - t0 < secs:
        if text in node.log_path.read_text(errors='replace')[since:]:
            return time.time() - t0
        time.sleep(0.2)
    return None


def log_size(node: Node) -> int:
    return len(node.log_path.read_text(errors='replace'))


def wait_attempts(node: Node, mid: str, n: int, secs: float, next_s: int = 0) -> dict:
    """The outbox status of `mid` once it has had `n` attempts and waits at
    least `next_s` for the next one (or at the deadline)."""
    t0 = time.time()
    while True:
        st = node.ash('outbox', 'status', mid).stdout
        attempts = int(outbox_field(st, 'attempts') or 0)
        wait = next_try_s(outbox_field(st, 'next try')) or 0
        if (attempts >= n and wait >= next_s) or time.time() - t0 >= secs:
            return dict(attempts=attempts, next_try_s=next_try_s(outbox_field(st, 'next try')),
                        after_s=round(time.time() - t0, 1))
        time.sleep(0.5)


def wait_backed_off(node: Node, mids: list, next_s: int, secs: float) -> dict:
    """Until every object in `mids` waits at least `next_s` for its next try
    (each has its own backoff; the first one due would retry its contact's
    older ones too), or the deadline."""
    t0 = time.time()
    while True:
        waits = []
        for mid in mids:
            st = node.ash('outbox', 'status', mid).stdout
            waits.append(next_try_s(outbox_field(st, 'next try')) or 0)
        if min(waits) >= next_s or time.time() - t0 >= secs:
            return dict(min_next_try_s=min(waits), after_s=round(time.time() - t0, 1))
        time.sleep(0.5)


def wait_all(nodes_texts: list, secs: float) -> float | None:
    """Seconds until every (node, text) is in its inbox."""
    t0 = time.time()
    while time.time() - t0 < secs:
        inboxes: dict = {}
        for n, _ in nodes_texts:
            if n.name not in inboxes:
                inboxes[n.name] = n.inbox()
        if all(count(inboxes[n.name], t) for n, t in nodes_texts):
            return time.time() - t0
        time.sleep(0.5)
    return None


def network_switch(root: Path, netwatch: bool) -> dict:
    """Alice reaches Bob and Carol through proxies (her "network"). The old
    network dies (every connection refused at once) while 3 messages to Bob
    and 2 to Carol wait and back off; then a new network works. With
    `netwatch` her lab event file says so (a network gone, one new). No LAN
    beacon under RAVEN_FAULT_BEACON=1 (without_beacon): the lab bus does not
    die with the proxies."""
    net = root / 'a-net.txt'
    net.write_text('up 192.0.2.10/24\n')
    base = without_beacon(ENV)
    env = dict(base, RAVEN_LAB_NETWATCH_EVENTS=str(net))
    a, b, c = Node('a', root, env), Node('b', root, base), Node('c', root, base)
    for n in (a, b, c):
        n.init()
        n.start()
    pb, pc = Proxy(b.dial), Proxy(c.dial)
    a.add(b, 'bob', pb.addr)
    a.add(c, 'carol', pc.addr)
    b.add(a, 'alice')
    c.add(a, 'alice')
    baseline = wait_log(a, 'raven-node netwatch: watching (1 network)', 30)
    warm = [status_word(a.send('bob', 'warmup-b')[1]), status_word(a.send('carol', 'warmup-c')[1])]
    for p in (pb, pc):
        p.mode = 'refuse'
        p.kill_live()
    texts = [(b, f'switch-b-{k}') for k in (1, 2, 3)] + [(c, f'switch-c-{k}') for k in (1, 2)]
    outs = {t: a.send('bob' if n is b else 'carol', t)[1] for n, t in texts}
    statuses = {t: status_word(o) for t, o in outs.items()}
    mids = [m.group(1) for m in (re.search(r'mid=([0-9a-f]{8})', o) for o in outs.values()) if m]
    # Each send restarts the backoff; wait until it grew again for all five.
    backed_off = wait_attempts(a, mids[0], 4, 120) if mids else None
    quiet = wait_backed_off(a, mids, 15, 180) if len(mids) == len(texts) else None
    for p in (pb, pc):
        p.mode = 'pass'
    mark = log_size(a)
    if netwatch:
        with open(net, 'a') as f:
            f.write('down 192.0.2.10/24\nup 198.51.100.7/24\n')
    t0 = time.time()
    noticed = wait_log(a, 'raven-node netwatch: network changed', 10, mark) if netwatch else None
    took = wait_all(texts, 30 if netwatch else 300)
    if took is not None:
        took = round(time.time() - t0, 1)
    counts = {t: count(n.inbox(), t) for n, t in texts}
    bob_inbox = b.inbox()
    order = sorted((1, 2, 3), key=lambda k: bob_inbox.find(f'switch-b-{k}'))
    return dict(a=a, b=b, net=net, pb=pb, baseline_s=baseline, warm=warm, statuses=statuses,
                backed_off=backed_off, quiet=quiet,
                noticed_s=None if noticed is None else round(noticed, 1),
                all_delivered_s=took, counts=counts, bob_order=order)


def s34_network_switch_queued(root: Path) -> dict:
    """Phase 0b: Alice's network switches while 5 messages to 2 contacts back
    off; netwatch notices within 10 s and all 5 are delivered within 30 s of
    the switch, exactly once, Bob's in order. Then a wake from sleep round."""
    r = network_switch(root, netwatch=True)
    a, b, net, pb = r.pop('a'), r.pop('b'), r.pop('net'), r.pop('pb')
    pb.mode = 'refuse'
    pb.kill_live()
    rc, out, _ = a.send('bob', 'wake-b-1')
    m = re.search(r'mid=([0-9a-f]{8})', out)
    wake_backed_off = wait_attempts(a, m.group(1), 4, 120, next_s=15) if m else None
    pb.mode = 'pass'
    mark = log_size(a)
    with open(net, 'a') as f:
        f.write('wake\n')
    t1 = time.time()
    woke = wait_log(a, 'raven-node netwatch: woke from sleep', 10, mark)
    got = wait_inbox(b, 'wake-b-1', 30)
    wake_delivered = None if got is None else round(time.time() - t1, 1)
    log = a.log_path.read_text(errors='replace')
    r.update(
        ok=(r['quiet'] or {}).get('min_next_try_s', 0) >= 15
        and r['noticed_s'] is not None and r['noticed_s'] <= 10
        and r['all_delivered_s'] is not None and r['all_delivered_s'] <= 30
        and all(v == 1 for v in r['counts'].values()) and r['bob_order'] == [1, 2, 3]
        and all(v == 'QUEUED' for v in r['statuses'].values())
        and woke is not None and wake_delivered is not None and wake_delivered <= 30
        and count(b.inbox(), 'wake-b-1') == 1
        and log.count('raven-node netwatch: network changed') == 1,
        wake_send=(rc, status_word(out)), wake_backed_off=wake_backed_off,
        woke_s=None if woke is None else round(woke, 1), wake_delivered_s=wake_delivered,
        netwatch=[l for l in log.splitlines() if 'raven-node netwatch:' in l][-4:])
    return r


def s34c_switch_without_netwatch(root: Path) -> dict:
    """s34's control: the same switch with no netwatch line; the backoff alone
    delivers (took_s shows what netwatch gains)."""
    r = network_switch(root, netwatch=False)
    for k in ('a', 'b', 'net', 'pb'):
        r.pop(k)
    r['took_s'] = r.pop('all_delivered_s')
    r['ok'] = r['took_s'] is not None and all(v == 1 for v in r['counts'].values())
    return r


def s35_p2p_stranger_is_refused(root: Path) -> dict:
    """Phase 1 (peer gate, p2p): Alice, Bob and S reach each other only
    through a relay whose allow-list holds all three (one circle). Alice and
    Bob pin each other's cards; S pins Bob's, Bob does not know S. Bob's
    peer gate refuses the circuit before he accepts it (one counts-only
    line, no Raven link, no PeerId in his log); the relay then answers
    CONNECTION_FAILED, which cannot be told from a contact that is gone, so
    S's p2p send fails as if Bob were offline, with no refusal hint (review
    fix C-relay-kit-1); Alice -> Bob is then delivered exactly once."""
    relay = RelayProc(root)
    a, b, s = (Node(n, root, P2P_RELAY_ONLY_ENV) for n in ('a', 'b', 's'))
    for n in (a, b, s):
        n.init()
    cards = {n.name: n.p2p_card(relay.via) for n in (a, b, s)}
    for n in (a, b, s):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 3, 30)
    p2p = ('--p2p-listen', 'relay', '--p2p-relay', relay.via)
    for n in (a, b, s):
        n.start(extra=p2p)
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b, s)]
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    s.add_card(cards['b'], 'bob', b.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b, s)]
    mark = log_size(b)
    t0 = time.time()
    r = s.ash('send', '--contact', '@bob', '--carrier', 'p2p', stdin='s35-stranger-probe\n')
    s_out = (r.stdout + r.stderr).strip()
    s_took = round(time.time() - t0, 1)
    gate_line = wait_log(
        b, 'raven-node p2p: refused a connection from a peer that is not a verified contact',
        15, mark)
    rc, out, dt = a.send('bob', 's35-after-the-stranger')
    got = wait_inbox(b, 's35-after-the-stranger', 60)
    b_log = b.log_path.read_text(errors='replace')
    inbox = b.inbox()
    hints = ("the contact's node refused the p2p connection at once",
             "the contact's relay refused this node")
    return dict(
        ok=all(t is not None for t in reserved + gates) and allowed is not None
        and r.returncode != 0 and 'P2P_UNREACHABLE' in s_out
        and 'why=contact_offline' in s_out and not any(h in s_out for h in hints)
        and 'LINK_NOT_ACCEPTED' not in s_out
        and gate_line is not None and 'p2p inbound' not in b_log and '12D3KooW' not in b_log
        and count(inbox, 's35-stranger-probe') == 0
        and got is not None and count(inbox, 's35-after-the-stranger') == 1,
        stranger=(r.returncode, s_out[-400:]), stranger_s=s_took,
        gate_line_s=None if gate_line is None else round(gate_line, 1),
        b_gate=[l for l in b_log.splitlines() if 'raven-node p2p: refused' in l][-2:],
        after=(rc, status_word(out), round(dt, 1)), delivered_after_s=got,
        relay_counts=relay.counts())


def free_tcp_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def send_path(node: Node, tag: str, text: str, carrier: str = 'auto') -> tuple:
    """A verbose send: (exit code, outcome word, its `path=` token or '')."""
    r = subprocess.run(
        [node.ash_bin, '--data-dir', str(node.dir), 'send', '--contact', f'@{tag}',
         '--carrier', carrier],
        input=text + '\n', capture_output=True, text=True, timeout=120,
        env=dict(node.env, RAVEN_VERBOSE='1'))
    out = (r.stdout + r.stderr).strip()
    m = re.search(r' path=(\S+)', r.stdout)
    return r.returncode, status_word(out), m.group(1) if m else ''


def s36_p2p_paths(root: Path) -> dict:
    """Phase 1 items 3-4 (p2p path labels, hole punching, deliberate
    reversal). (a) Erin and Fred listen on loopback with the debug
    local-candidates switch and reserve on a relay (Erin through a proxy):
    Erin -> Fred is `relayed` (or already `hole_punched`), DCUtR upgrades
    within 30 s, and the next message is `hole_punched`. (c) Then Erin's
    proxy to the relay is blackholed and its open connection reset: her
    next message is still delivered, `hole_punched`, over the direct
    connection. (b) Alice and Bob listen on loopback, no relay; Alice pins
    Bob's card naming his own address, Bob pins Alice's with `p2p=` only.
    Alice -> Bob is `direct`, Bob -> Alice rides her connection
    (`reversed`). Alice restarts: Bob's next message is queued (no address
    of hers); she writes again and Bob's outbox delivers it over her new
    connection (`reversed`), exactly once. (d) Carol and Dave have no
    listener (relay-only, debug switch): three sends through the relay are
    all `relayed` and no hole punch happens within 20 s."""
    # (a) relayed, then hole-punched (loopback candidates: debug lab switch).
    upgrade = 'raven-node p2p: direct connection upgraded (dcutr)'
    relay_a = RelayProc(root, name='relay-a')
    lab_env = dict(P2P_ENV, RAVEN_LAB_P2P_LOCAL_CANDIDATES='1')
    e, f = Node('e', root, lab_env), Node('f', root, lab_env)
    for n in (e, f):
        n.init()
    proxy = Proxy(f'127.0.0.1:{relay_a.port}')
    r_peer = relay_a.via.rsplit('/p2p/', 1)[1]
    e_via = f"/ip4/127.0.0.1/tcp/{proxy.addr.rsplit(':', 1)[1]}/p2p/{r_peer}"
    cards_a = {n.name: n.p2p_card(relay_a.via) for n in (e, f)}
    for n in (e, f):
        relay_a.allow(cards_a[n.name])
    allowed_a = relay_a.wait_counts(lambda x: x.get('allowed_peers') == 2, 30)
    e.start(extra=('--p2p-listen', '127.0.0.1:0', '--p2p-relay', e_via))
    f.start(extra=('--p2p-listen', '127.0.0.1:0', '--p2p-relay', relay_a.via))
    reserved_a = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (e, f)]
    lab_lines = [wait_log(n, 'raven-node p2p: lab hole punching also offers', 5) for n in (e, f)]
    e.add_card(cards_a['f'], 'fred', f.fingerprint())
    f.add_card(cards_a['e'], 'erin', e.fingerprint())
    gates_a = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
               for n in (e, f)]
    punch = {'e2f_1': send_path(e, 'fred', 's36-punch-1', 'p2p')}
    t0 = time.time()
    upgraded_s = None
    while time.time() - t0 < 30:
        if any(upgrade in n.log_path.read_text(errors='replace') for n in (e, f)):
            upgraded_s = round(time.time() - t0, 1)
            break
        time.sleep(0.2)
    punch['e2f_2'] = send_path(e, 'fred', 's36-punch-2', 'p2p')
    part_a = (allowed_a is not None
              and all(t is not None for t in reserved_a + lab_lines + gates_a)
              and punch['e2f_1'][1] == 'DELIVERED'
              and punch['e2f_1'][2] in ('relayed', 'hole_punched')
              and upgraded_s is not None
              and punch['e2f_2'][1:] == ('DELIVERED', 'hole_punched'))
    # (c) the fault: Erin's relay path dies after the upgrade.
    mark = log_size(e)
    proxy.mode = 'blackhole'
    proxy.kill_live()
    relay_lost = wait_log(e, 'raven-node p2p: reservation lost', 30, mark)
    punch['e2f_after_cut'] = send_path(e, 'fred', 's36-after-the-relay-cut', 'p2p')
    f_inbox = f.inbox()
    part_c = (relay_lost is not None
              and punch['e2f_after_cut'][1:] == ('DELIVERED', 'hole_punched')
              and all(count(f_inbox, t) == 1
                      for t in ('s36-punch-1', 's36-punch-2', 's36-after-the-relay-cut')))
    e_paths = [l.strip() for l in e.ash('status').stdout.splitlines()
               if l.strip().startswith('p2p_paths ')]
    for n in (e, f):
        n.stop()
    relay_a.stop()

    # (b) direct, then reversed.
    a, b = Node('a', root, P2P_ENV), Node('b', root, P2P_ENV)
    for n in (a, b):
        n.init()
    b_port = free_tcp_port()
    a.start(extra=('--p2p-listen', '127.0.0.1:0'))
    b.start(extra=('--p2p-listen', f'127.0.0.1:{b_port}'))
    up = [wait_log(n, 'raven-node p2p: host up (listeners=2', 30) for n in (a, b)]
    b_peer = re.search(r'p2p_peer\s+(12D3KooW\S+)', b.ash('status').stdout).group(1)
    b_card = b.p2p_card(f'/ip4/127.0.0.1/tcp/{b_port}/p2p/{b_peer}')
    a_card = next((l for l in a.ash('whoami', '--card').stdout.splitlines()
                   if l.startswith('raven-card/2 ')), '')
    a.add_card(b_card, 'bob', b.fingerprint())
    b.add_card(a_card, 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    paths = {}
    paths['a2b'] = send_path(a, 'bob', 's36-a-to-b', 'p2p')
    paths['b2a'] = send_path(b, 'alice', 's36-b-to-a')
    a.stop(hard=True)
    rc, out, _ = b.send('alice', 's36-queued-while-away')
    queued = status_word(out)
    m = re.search(r'mid=([0-9a-f]{8})', out)
    mid = m.group(1) if m else ''
    first_try = wait_attempts(b, mid, 1, 60) if mid else None
    mark = log_size(a)
    a.start(extra=('--p2p-listen', '127.0.0.1:0'))
    up.append(wait_log(a, 'raven-node p2p: host up (listeners=2', 30, mark))
    paths['a2b_again'] = send_path(a, 'bob', 's36-a-to-b-again', 'p2p')
    b.ash('outbox', 'retry', mid)
    t0 = time.time()
    st = ''
    while time.time() - t0 < 90:
        st = b.ash('outbox', 'status', mid).stdout
        if outbox_field(st, 'state') == 'delivered':
            break
        time.sleep(0.5)
    worker = (outbox_field(st, 'state'), outbox_field(st, 'carrier'), outbox_field(st, 'path'))
    worker_s = round(time.time() - t0, 1)
    worker_line = wait_log(b, 'raven-node outbox: delivered 1 (p2p_dial, reversed)', 15)
    a_inbox = a.inbox()
    part_b = (all(t is not None for t in up + gates) and ' via=' not in a_card
              and paths['a2b'][1:] == ('DELIVERED', 'direct')
              and paths['b2a'][1:] == ('DELIVERED', 'reversed')
              and queued == 'QUEUED' and mid != ''
              and worker == ('delivered', 'p2p_dial', 'reversed') and worker_line is not None
              and count(a_inbox, 's36-queued-while-away') == 1
              and count(a_inbox, 's36-b-to-a') == 1)
    b_paths = [l.strip() for l in b.ash('status').stdout.splitlines()
               if l.strip().startswith('p2p_paths ')]
    for n in (a, b):
        n.stop()

    # (d) relay-only: never upgraded.
    relay = RelayProc(root)
    c, d = Node('c', root, P2P_RELAY_ONLY_ENV), Node('d', root, P2P_RELAY_ONLY_ENV)
    for n in (c, d):
        n.init()
    cards = {n.name: n.p2p_card(relay.via) for n in (c, d)}
    for n in (c, d):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda x: x.get('allowed_peers') == 2, 30)
    for n in (c, d):
        n.start(extra=('--p2p-listen', 'relay', '--p2p-relay', relay.via))
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (c, d)]
    c.add_card(cards['d'], 'dave', d.fingerprint())
    d.add_card(cards['c'], 'carol', c.fingerprint())
    gates_d = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
               for n in (c, d)]
    relayed = [send_path(c, 'dave', f's36-relayed-{i}', 'p2p') for i in range(1, 3)]
    punched = [wait_log(n, 'direct connection upgraded (dcutr)', 20) for n in (c, d)]
    relayed.append(send_path(c, 'dave', 's36-relayed-3', 'p2p'))
    d_inbox = d.inbox()
    part_d = (allowed is not None and all(t is not None for t in reserved + gates_d)
              and all(r[1:] == ('DELIVERED', 'relayed') for r in relayed)
              and punched == [None, None]
              and all(count(d_inbox, f's36-relayed-{i}') == 1 for i in range(1, 4)))
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b, c, d, e, f))
    return dict(
        ok=part_a and part_b and part_c and part_d and '12D3KooW' not in logs,
        part_a=part_a, part_b=part_b, part_c=part_c, part_d=part_d, punch=punch,
        upgraded_s=upgraded_s, relay_lost_s=None if relay_lost is None else round(relay_lost, 1),
        e_paths=e_paths, paths=paths, queued=(queued, mid),
        first_try=first_try, worker=worker, worker_s=worker_s,
        worker_line_s=None if worker_line is None else round(worker_line, 1),
        relayed=relayed, punched=punched, relay_counts=relay.counts(), b_paths=b_paths)


# How long the p2p host may take to recover from a relay outage (reconnect
# backoff 1 s doubling to 60 s, then the outbox's own backoff: nothing kicks
# the outbox when a reservation comes back).
RELAY_RECOVERY_S = 180
# raven_swarm::RECONNECT_MAX: the longest a relay slot waits between two
# tries (half to all of min(60 s, 2^attempt s)), so after a relay is back a
# slot may try again only that long after (review E-harness-docs-ci-6).
RECONNECT_MAX_S = 60


def slot_retry_in_s(node: Node) -> int | None:
    """How long until the node's relay slot 1 tries again (`ash doctor`'s
    `relay_1: retrying ... retry_in_s=N`), or None while it is not waiting
    for a retry (dialling, say)."""
    m = re.search(r'^\s*relay_1: retrying .*\bretry_in_s=(\d+)', node.ash('doctor').stdout, re.M)
    return int(m.group(1)) if m else None


def relay_pair(root: Path, relay: RelayProc, via: str) -> tuple:
    """Alice and Bob, both listening on loopback, each with one reservation
    on `relay` at `via` (both on its allow-list: it relays only within its
    circle), pinned to each other from cards naming only that relay (no LAN
    route). Returns (alice, bob, every setup step was seen)."""
    a, b = Node('a', root, P2P_ENV), Node('b', root, P2P_ENV)
    for n in (a, b):
        n.init()
    cards = {n.name: n.p2p_card(via) for n in (a, b)}
    for n in (a, b):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30)
    for n in (a, b):
        n.start(extra=('--p2p-listen', '127.0.0.1:0', '--p2p-relay', via))
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b)]
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    return a, b, allowed is not None and all(t is not None for t in reserved + gates)


def queued_send(node: Node, tag: str, text: str) -> tuple:
    """A send expected to wait in the outbox: (outcome word, its mid or '')."""
    _, out, _ = node.send(tag, text)
    m = re.search(r'mid=([0-9a-f]{8})', out)
    return status_word(out), m.group(1) if m else ''


def relay_recovery(a: Node, b: Node, text: str, mid: str, since: dict, t0: float) -> dict:
    """After the relay is back at `t0`: seconds until both hold a reservation
    again and until `text` (object `mid`, queued on Alice) is in Bob's
    inbox, each within RELAY_RECOVERY_S; then how it travelled and whether
    anything is left waiting on Alice. `next_try_at_reserved_s`: once both
    hold a reservation again and the message has not arrived yet, how long
    Alice's outbox still waits before it tries `mid` again (`ash outbox
    status`; its own backoff while the relay was down)."""
    seen: dict = {}
    next_try = None
    while len(seen) < 3 and time.time() - t0 < RELAY_RECOVERY_S:
        for n in (a, b):
            if (n.name not in seen and 'raven-node p2p: reservation accepted'
                    in n.log_path.read_text(errors='replace')[since[n.name]:]):
                seen[n.name] = round(time.time() - t0, 1)
        if 'delivered' not in seen and count(b.inbox(), text):
            seen['delivered'] = round(time.time() - t0, 1)
        if mid and next_try is None and 'a' in seen and 'b' in seen and 'delivered' not in seen:
            # Read until the item says when (not while a try is under way).
            next_try = next_try_s(outbox_field(a.ash('outbox', 'status', mid).stdout,
                                               'next try'))
        time.sleep(0.5)
    heal_to_reserved = max(seen[k] for k in ('a', 'b')) if 'a' in seen and 'b' in seen else None
    st = a.ash('outbox', 'status', mid).stdout if mid else ''
    outbox = a.outbox()
    return dict(heal_to_reserved_s=heal_to_reserved, heal_to_delivered_s=seen.get('delivered'),
                next_try_at_reserved_s=next_try,
                copies=count(b.inbox(), text),
                delivered_via=(outbox_field(st, 'state'), outbox_field(st, 'carrier'),
                               outbox_field(st, 'path')),
                a_outbox_empty='Nothing waiting' in outbox, a_outbox=outbox[-300:])


def recovered(rec: dict) -> bool:
    """Delivered once within RELAY_RECOVERY_S of the heal, over the relay
    again, and nothing left waiting."""
    return (rec['heal_to_reserved_s'] is not None and rec['heal_to_delivered_s'] is not None
            and rec['heal_to_delivered_s'] <= RELAY_RECOVERY_S and rec['copies'] == 1
            and rec['delivered_via'] == ('delivered', 'p2p_dial', 'relayed')
            and rec['a_outbox_empty'])


def s38_relay_outage_then_heal(root: Path) -> dict:
    """Phase 1 item 8: Alice and Bob always listen yet reach each other only
    through a relay, which they reach through a proxy. m1 is delivered,
    `relayed`. Then the relay's path goes dark for 30 s (the proxy blackholes
    new connections and resets the open ones): both lose their reservation,
    and m2 is queued. After the heal both reserve again and m2 is delivered
    exactly once within 180 s, with nothing left waiting on Alice."""
    r_port = free_tcp_port()
    proxy = Proxy(f'127.0.0.1:{r_port}')
    p_port = proxy.addr.rsplit(':', 1)[1]
    # R names only the proxy (`--external`; its own listen addresses stay
    # unnamed, in Identify too), so the proxy is the one path to R: a node
    # that lost R cannot reach it some other way during the outage.
    relay = RelayProc(root, port=r_port, extra=('--external', f'/ip4/127.0.0.1/tcp/{p_port}'))
    r_peer = relay.via.rsplit('/p2p/', 1)[1]
    via = f'/ip4/127.0.0.1/tcp/{p_port}/p2p/{r_peer}'
    a, b, ready = relay_pair(root, relay, via)
    m1 = send_path(a, 'bob', 's38-m1')
    marks = {n.name: log_size(n) for n in (a, b)}
    proxy.mode = 'blackhole'
    proxy.kill_live()
    t_out = time.time()
    lost = [wait_log(n, 'raven-node p2p: reservation lost', 30, marks[n.name]) for n in (a, b)]
    m2 = queued_send(a, 'bob', 's38-m2')
    # The outage itself: 30 s with no path to the relay.
    time.sleep(max(0.0, 30 - (time.time() - t_out)))
    since = {n.name: log_size(n) for n in (a, b)}
    proxy.mode = 'pass'
    # A dropped SYN leaves no connection behind; the loopback proxy did
    # accept the dials it held (each still pins its port pair), so they end
    # with the outage.
    proxy.kill_live()
    t_heal = time.time()
    rec = relay_recovery(a, b, 's38-m2', m2[1], since, t_heal)
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and m1[1:] == ('DELIVERED', 'relayed') and None not in lost
        and m2[0] == 'QUEUED' and recovered(rec) and count(b.inbox(), 's38-m1') == 1
        and '12D3KooW' not in logs,
        ready=ready, m1=m1, lost_s=[None if t is None else round(t, 1) for t in lost], m2=m2,
        outage_s=round(t_heal - t_out, 1), **rec, relay_counts=relay.counts())


def s38b_relay_restart_same_key(root: Path) -> dict:
    """Phase 1 item 8: the relay itself goes away (killed hard) and comes back
    in the same folder on the same port, so with the same key, PeerId and
    `via`. A message Alice sends while it is down is queued, and delivered
    exactly once within 180 s of the restart."""
    relay = RelayProc(root)
    via_before = relay.via
    a, b, ready = relay_pair(root, relay, relay.via)
    m0 = send_path(a, 'bob', 's38b-m0')
    marks = {n.name: log_size(n) for n in (a, b)}
    relay.stop(graceful=False)
    lost = [wait_log(n, 'raven-node p2p: reservation lost', 30, marks[n.name]) for n in (a, b)]
    m3 = queued_send(a, 'bob', 's38b-m3')
    since = {n.name: log_size(n) for n in (a, b)}
    relay.start()
    t_restart = time.time()
    rec = relay_recovery(a, b, 's38b-m3', m3[1], since, t_restart)
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and m0[1:] == ('DELIVERED', 'relayed') and None not in lost
        and m3[0] == 'QUEUED' and relay.via == via_before and recovered(rec)
        and count(b.inbox(), 's38b-m0') == 1 and '12D3KooW' not in logs,
        ready=ready, m0=m0, lost_s=[None if t is None else round(t, 1) for t in lost], m3=m3,
        same_peer_and_via=relay.via == via_before, **rec, relay_counts=relay.counts())


def learned_relays(node: Node, other: Node) -> set:
    """The relay PeerIds in `node`'s learned entry for `other` (kept inside
    the harness: results name counts and yes/no only)."""
    try:
        entries = learned_rows(node)
    except (OSError, ValueError):
        return set()
    return {r.rsplit('/p2p/', 1)[-1] for e in entries if isinstance(e, dict)
            and e.get('pub_hex', '').lower() == other.pub.lower() for r in e.get('relays', [])}


def s39_p2p_relay_moves(root: Path) -> dict:
    """RRH1 over p2p (RAVEN_FAULT_P2P=1 and RAVEN_FAULT_HINTS=1): relays R_A,
    R1 and R2 each allow Alice and Bob. Alice reserves on R_A, Bob on R1;
    Alice's card for Bob is a raven-card/3 naming R1, Bob's for Alice names
    R_A. m1 is `relayed` (Alice learns Bob's relay R1). Bob stops, Alice
    queues m2, and Bob comes back on R2 only: his announce link (his relays
    changed) tells Alice, with no new card, and m2 arrives exactly once
    within 60 s of Bob's start; Alice's contacts.json is unchanged and her
    learned entry for Bob names 1 relay, R2."""
    r_a, r1, r2 = (RelayProc(root, name=n) for n in ('relay-a', 'relay-1', 'relay-2'))
    a, b = Node('a', root, P2P_ENV), Node('b', root, P2P_ENV)
    for n in (a, b):
        n.init()
    a_card, b_card = a.p2p_card(r_a.via), b.p2p_card(r1.via)
    for r in (r_a, r1, r2):
        r.allow(a_card)
        r.allow(b_card)
    allowed = [r.wait_counts(lambda c: c.get('allowed_peers') == 2, 30) for r in (r_a, r1, r2)]
    a.start(extra=('--p2p-listen', '127.0.0.1:0', '--p2p-relay', r_a.via))
    b.start(extra=('--p2p-listen', '127.0.0.1:0', '--p2p-relay', r1.via))
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b)]
    a.add_card(b_card, 'bob', b.fingerprint())
    b.add_card(a_card, 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    m1 = send_path(a, 'bob', 's39-m1', 'p2p')
    r1_id, r2_id = (r.via.rsplit('/p2p/', 1)[1] for r in (r1, r2))
    before = learned_relays(a, b)
    book = (a.dir / 'contacts.json').read_bytes()
    b.stop()
    m2 = queued_send(a, 'bob', 's39-m2')
    mark = log_size(b)
    b.start(extra=('--p2p-listen', '127.0.0.1:0', '--p2p-relay', r2.via))
    t0 = time.time()
    reserved.append(wait_log(b, 'raven-node p2p: reservation accepted', 60, mark))
    got = wait_inbox(b, 's39-m2', max(1.0, 60 - (time.time() - t0)))
    took = None if got is None else round(time.time() - t0, 1)
    after = learned_relays(a, b)
    st = a.ash('outbox', 'status', m2[1]).stdout if m2[1] else ''
    announced = 'raven-node hints: routes changed; telling ' in \
        b.log_path.read_text(errors='replace')[mark:]
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    entry = learned_entry(a, b)
    return dict(
        ok=all(c is not None for c in allowed) and None not in reserved + gates
        and m1[1:] == ('DELIVERED', 'relayed') and before == {r1_id}
        and m2[0] == 'QUEUED' and took is not None and count(b.inbox(), 's39-m2') == 1
        and count(b.inbox(), 's39-m1') == 1 and after == {r2_id}
        and (a.dir / 'contacts.json').read_bytes() == book and announced
        and '12D3KooW' not in logs,
        m1=m1, learned_r1_first=before == {r1_id}, m2=m2, delivered_after_start_s=took,
        delivered_via=(outbox_field(st, 'state'), outbox_field(st, 'carrier'),
                       outbox_field(st, 'path')),
        learned=entry, learned_r2_only=after == {r2_id}, announce_line=announced,
        contacts_unchanged=(a.dir / 'contacts.json').read_bytes() == book,
        relay_counts={n: r.counts() for n, r in (('r_a', r_a), ('r1', r1), ('r2', r2))})


def p2p_port(node: Node) -> int | None:
    """The TCP port of the node's p2p listener (its `p2p_listen` status row)."""
    row = status_row(node.ash('status').stdout, 'p2p_listen') or ''
    m = re.search(r'/ip4/127\.0\.0\.1/tcp/(\d+)', row)
    return int(m.group(1)) if m else None


def s40_stale_direct_hint(root: Path) -> dict:
    """RRH1 over LAN and p2p (RAVEN_FAULT_P2P=1 and RAVEN_FAULT_HINTS=1):
    Alice and Bob each hold the other's card (relay R) and LAN route. A LAN
    message each way: Bob's route hints tell Alice his p2p listen address
    (a same-network address, sent on LAN links only; on loopback nothing
    confirms a global one). Bob comes back on his LAN port with a new p2p
    port, and Alice's p2p #1 dials the stale address (refused at once) and
    the relay together: delivered, `relayed`, within 30 s. Alice's next LAN
    link (a LAN message) carries Bob's hints again: his new p2p address.
    R stops, and its relayed connection with it (#2 would ride it:
    connected first), and #2 is `direct` to Bob's new port. Without a
    default route the network tag that guards a same-network address is
    unknown: skipped."""
    if not has_default_route():
        return dict(ok=True, skipped='no default route (no network tag)')
    relay = RelayProc(root)
    a, b = Node('a', root, P2P_ENV), Node('b', root, P2P_ENV)
    for n in (a, b):
        n.init()
    cards = {n.name: n.p2p_card(relay.via) for n in (a, b)}
    for n in (a, b):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30)
    p2p = ('--p2p-listen', '127.0.0.1:0', '--p2p-relay', relay.via)
    for n in (a, b):
        n.start(extra=p2p)
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b)]
    for x, y, tag in ((a, b, 'bob'), (b, a, 'alice')):
        x.add_card(cards[y.name], tag, y.fingerprint())
        r = x.ash('contact', 'set-addr', f'@{tag}', '--lan', y.dial)
        assert r.returncode == 0, r.stdout + r.stderr
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    warm = [status_word(a.send('bob', 's40-warm-a2b')[1]),
            status_word(b.send('alice', 's40-warm-b2a')[1])]
    old_port = p2p_port(b)
    first = learned_entry(a, b)
    lan_port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    mark = log_size(b)
    b.start(port=lan_port, extra=p2p)
    reserved.append(wait_log(b, 'raven-node p2p: reservation accepted', 60, mark))
    new_port = p2p_port(b)
    t0 = time.time()
    m1 = send_path(a, 'bob', 's40-1', 'p2p')
    m1_s = round(time.time() - t0, 1)
    got1 = wait_inbox(b, 's40-1', max(1.0, 30 - (time.time() - t0)))
    stale_until_lan = learned_entry(a, b)
    lan = status_word(a.send('bob', 's40-lan', carrier='lan')[1])
    learned = None
    t1 = time.time()
    while time.time() - t1 < 15:
        learned = learned_entry(a, b)
        if learned and new_port in learned['direct_ports']:
            break
        time.sleep(0.5)
    a_mark = log_size(a)
    relay.stop()
    lost = wait_log(a, 'raven-node p2p: reservation lost', 30, a_mark)
    m2 = send_path(a, 'bob', 's40-2', 'p2p')
    inbox = b.inbox()
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=allowed is not None and None not in reserved + gates
        and warm == ['DELIVERED', 'DELIVERED'] and old_port is not None
        and first is not None and old_port in first['direct_ports']
        and new_port is not None and new_port != old_port
        and m1[1:] == ('DELIVERED', 'relayed') and got1 is not None
        and lan == 'DELIVERED' and learned is not None and new_port in learned['direct_ports']
        and old_port not in learned['direct_ports']
        and lost is not None and m2[1:] == ('DELIVERED', 'direct')
        and all(count(inbox, t) == 1 for t in ('s40-1', 's40-lan', 's40-2'))
        and '12D3KooW' not in logs,
        warmup=warm, p2p_port_moved=old_port != new_port, learned_first=first, m1=m1,
        m1_s=m1_s, before_the_lan_link=stale_until_lan, lan_send=lan,
        learned_after_lan=learned, relay_gone_s=None if lost is None else round(lost, 1),
        m2=m2)


# ------------------------------------------------------------- the relay kit

def relay_use(node: Node, *vias: str) -> str:
    """`ash relay use via=… …` (what a friend pastes from `raven relay card`)."""
    r = node.ash('relay', 'use', *(f'via={v}' for v in vias))
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout.strip()


def saved_card(node: Node) -> str:
    """`ash whoami --card` without --via: the relays `relay use` saved."""
    r = node.ash('whoami', '--card')
    line = next((l for l in r.stdout.splitlines() if l.startswith('raven-card/')), '')
    assert ' p2p=' in line, r.stdout + r.stderr
    return line


def s45_relay_443_fallback(root: Path) -> dict:
    """Relay kit (RAVEN_FAULT_P2P=1): a relay on two TCP ports (its main port
    and an `--also-tcp` one, the kit's 443), each behind a proxy. The
    proxy in front of the main port refuses every connection (a network
    that lets only 443 out); Alice saved both addresses with `raven relay
    use` (one relay, a fallback address), Bob the main port directly. Alice
    reserves within 15 s on the fallback, her status says `reservations
    1/1`, and 3 messages to Bob are each `relayed` and arrive once."""
    p2 = free_tcp_port()
    relay = RelayProc(root, also_tcp=(p2,))
    refuse = Proxy(f'127.0.0.1:{relay.port}')
    refuse.mode = 'refuse'
    passing = Proxy(f'127.0.0.1:{p2}')
    a, b = Node('a', root, P2P_ENV), Node('b', root, P2P_ENV)
    for n in (a, b):
        n.init()
    use = relay_use(a, relay.via_on(refuse.addr.rsplit(':', 1)[1]),
                    relay.via_on(passing.addr.rsplit(':', 1)[1]))
    relay_use(b, relay.via)
    cards = {n.name: saved_card(n) for n in (a, b)}
    for n in (a, b):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30)
    # Their relays come from what `relay use` saved; only the port is set here.
    for n in (a, b):
        n.start(extra=('--p2p-listen', '127.0.0.1:0'))
    reserved = wait_log(a, 'raven-node p2p: reservation accepted', 15)
    b_reserved = wait_log(b, 'raven-node p2p: reservation accepted', 60)
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    row = status_row(a.ash('status').stdout, 'p2p') or ''
    sends = [send_path(a, 'bob', f's45-m{k}', 'p2p') for k in (1, 2, 3)]
    inbox = b.inbox()
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=allowed is not None and reserved is not None and b_reserved is not None
        and None not in gates and '1 relay saved (2 addresses' in use
        and refuse.conns >= 1 and passing.conns >= 1 and 'reservations 1/1' in row
        and all(s[1:] == ('DELIVERED', 'relayed') for s in sends)
        and all(count(inbox, f's45-m{k}') == 1 for k in (1, 2, 3))
        and logs.count('raven-node p2p: reservation accepted') == 2
        and '12D3KooW' not in logs,
        time_to_reserved_s=None if reserved is None else round(reserved, 1),
        primary_refused=refuse.conns, fallback_conns=passing.conns,
        p2p_row=row[:160], sends=sends, relay_counts=relay.counts())


def s46_relay_graceful_restart(root: Path) -> dict:
    """Relay kit (RAVEN_FAULT_P2P=1): the kit's relay (`--also-tcp`,
    `--public-host`) between Alice and Bob. m1 is delivered; then the relay
    is asked to stop (SIGTERM, as systemd does on an update): it exits 0
    with `stopped (2 connection(s) closed)`, and both lose their reservation
    within 5 s, not at a ping timeout. m2 waits in Alice's outbox while it is
    down. Restarted in the same folder it has the same PeerId and card
    lines. Each relay slot backs off while the relay is down (half to all of
    min(60 s, 2^tries s): it may try again up to RECONNECT_MAX_S after the
    restart, and nothing nudges it): both reserve again within 30 s of their
    slot's next try (read from `ash doctor` at the restart; RECONNECT_MAX_S
    when a slot is not waiting then), and m2 arrives exactly once within 30 s
    of Alice's next try of it once both are reserved (her outbox backs off
    too; review E-harness-docs-ci-6: the old bounds, 30 s and 60 s from the
    restart, were shorter than these backoffs). A second round with SIGKILL
    is recorded only."""
    p1, p2 = free_tcp_port(), free_tcp_port()
    relay = RelayProc(root, port=p1, also_tcp=(p2,), public_host='127.0.0.1')
    card_before, peer_before = relay.card(), relay.peer
    a, b, ready = relay_pair(root, relay, relay.via)
    m1 = send_path(a, 'bob', 's46-m1', 'p2p')
    marks = {n.name: log_size(n) for n in (a, b)}
    t_stop = time.time()
    exit_code = relay.stop(graceful=True)
    stopped = 'raven-node relay: stopped (2 connection(s) closed)' in \
        relay.log_path.read_text(errors='replace')
    lost = [wait_log(n, 'raven-node p2p: reservation lost',
                     max(0.2, 5 - (time.time() - t_stop)), marks[n.name]) for n in (a, b)]
    m2 = queued_send(a, 'bob', 's46-m2')
    since = {n.name: log_size(n) for n in (a, b)}
    relay.start()
    t_restart = time.time()
    retry_in = {n.name: slot_retry_in_s(n) for n in (a, b)}
    same = relay.peer == peer_before and relay.card() == card_before
    rec = relay_recovery(a, b, 's46-m2', m2[1], since, t_restart)
    reserve_bound = 30 + max(RECONNECT_MAX_S if v is None else v for v in retry_in.values())
    deliver_bound = None if rec['heal_to_reserved_s'] is None else (
        rec['heal_to_reserved_s'] + (rec['next_try_at_reserved_s'] or 0) + 30)
    # Recorded only: the same stop by SIGKILL (the kernel still closes the
    # sockets of a killed process on this host).
    marks = {n.name: log_size(n) for n in (a, b)}
    t_kill = time.time()
    relay.stop(graceful=False)
    killed_lost = [wait_log(n, 'raven-node p2p: reservation lost',
                            max(1.0, 60 - (time.time() - t_kill)), marks[n.name])
                   for n in (a, b)]
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and m1[1:] == ('DELIVERED', 'relayed') and exit_code == 0 and stopped
        and None not in lost and m2[0] == 'QUEUED' and same and recovered(rec)
        and rec['heal_to_reserved_s'] <= reserve_bound
        and rec['heal_to_delivered_s'] <= deliver_bound
        and count(b.inbox(), 's46-m1') == 1 and '12D3KooW' not in logs,
        ready=ready, m1=m1, exit_code=exit_code, stopped_line=stopped,
        slot_retry_in_at_restart_s=retry_in, reserve_bound_s=reserve_bound,
        deliver_bound_s=deliver_bound,
        lost_after_sigterm_s=[None if t is None else round(t, 1) for t in lost], m2=m2,
        same_peer_and_card=same, card_lines=len(card_before), **rec,
        lost_after_sigkill_s=[None if t is None else round(t, 1) for t in killed_lost])


def s47_circle_allow_is_live(root: Path) -> dict:
    """Relay kit (RAVEN_FAULT_P2P=1): the relay's circle changes with no
    restart of anything. Alice and Bob, both in it, exchange a first
    message (a first message is never queued: it needs the contact online).
    `raven relay deny <Bob>`: he loses his reservation and his retries are
    refused (the relay counts them), and Alice's next message waits in her
    outbox. `raven relay allow --card <Bob>`: he reserves again within 70 s
    (his reconnect backoff is capped at 60 s; the relay re-reads its list
    every 2 s) and the message arrives exactly once."""
    relay = RelayProc(root)
    a, b, ready = relay_pair(root, relay, relay.via)
    m0 = send_path(a, 'bob', 's47-m0', 'p2p')
    b_card = b.p2p_card(relay.via)
    b_peer = re.search(r' p2p=(\S+)', b_card).group(1)

    def refusals(c: dict) -> int:
        return c.get('connections_refused', 0) + c.get('reservations_refused', 0)

    before = refusals(relay.counts())
    mark = log_size(b)
    r = relay.ash('relay', 'deny', b_peer)
    denied = r.returncode == 0
    lost = wait_log(b, 'raven-node p2p: reservation lost', 30, mark)
    refused = relay.wait_counts(lambda c: refusals(c) > before, 60)
    m = queued_send(a, 'bob', 's47-m')
    mark = log_size(b)
    t_allow = time.time()
    relay.allow(b_card)
    b_reserved = wait_log(b, 'raven-node p2p: reservation accepted', 70, mark)
    got = wait_inbox(b, 's47-m', max(1.0, RELAY_RECOVERY_S - (time.time() - t_allow)))
    got_s = None if got is None else round(time.time() - t_allow, 1)
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and m0[1:] == ('DELIVERED', 'relayed') and denied and lost is not None
        and refused is not None and m[0] == 'QUEUED' and b_reserved is not None
        and got is not None and count(b.inbox(), 's47-m') == 1 and '12D3KooW' not in logs,
        ready=ready, m0=m0, denied=denied, lost_s=None if lost is None else round(lost, 1),
        refused_after_deny=None if refused is None else refusals(refused) - before, queued=m,
        b_reserved_after_allow_s=None if b_reserved is None else round(b_reserved, 1),
        delivered_after_allow_s=got_s, relay_counts=relay.counts())


# ------------------------------------------------------------ friend relays

# Phase 2 items 2-3, behind FRIEND_RELAY_PRODUCTION_ENABLED=false: the debug
# switch RAVEN_LAB_FRIEND_RELAY=1 on top of the p2p lab unlock and route
# hints (offers ride RRH1). An operator's friend relay listens on loopback
# only (RAVEN_LAB_FRIEND_RELAY_LISTEN: port 0, or a fixed port where it must
# outlive a restart), and loopback addresses may be offered and dialled
# (RAVEN_LAB_P2P_LOCAL_CANDIDATES), which nothing outside a one-machine
# harness sets.
FRIEND_ENV = dict(P2P_ENV, RAVEN_LAB_ROUTE_HINTS='1', RAVEN_LAB_FRIEND_RELAY='1',
                  RAVEN_LAB_FRIEND_RELAY_LISTEN='127.0.0.1:0',
                  RAVEN_LAB_P2P_LOCAL_CANDIDATES='1')
# A member: no listener (the retired `--p2p-listen relay`, kept by its debug
# switch) and no relay set by hand, so it is reachable only through the
# relays it picks from its contacts' offers.
FRIEND_MEMBER_ENV = dict(FRIEND_ENV, RAVEN_LAB_P2P_RELAY_ONLY='1')
FRIEND_UP = 'raven-node friend relay: up'
RELAY_CHOSEN = 'raven-node p2p: relay chosen (offered by a contact'
RELAY_REPLACED = 'raven-node p2p: relay replaced'
OFFER_WITHDRAWN = 'raven-node p2p: relay dropped (offer withdrawn)'
RESERVED = 'raven-node p2p: reservation accepted'
RESERVATION_LOST = 'raven-node p2p: reservation lost'
TAGS = {'a': 'alice', 'b': 'bob', 'c': 'carol', 'd': 'dave', 'e': 'erin'}


def wait_until(pred, secs: float, step: float = 0.5) -> float | None:
    """Seconds until `pred()` holds, or None after `secs`."""
    t0 = time.time()
    while True:
        if pred():
            return time.time() - t0
        if time.time() - t0 >= secs:
            return None
        time.sleep(step)


def took(t: float | None) -> float | None:
    return None if t is None else round(t, 1)


def friend_nodes(root: Path, operators: str, members: str, env: dict | None = None,
                 own_env: dict | None = None, extra: dict | None = None,
                 before_start=None) -> tuple:
    """Operators (listening p2p hosts, each with a friend relay that is off
    until `offer_friend_relay`) and members (FRIEND_MEMBER_ENV), all started.
    Everyone pins everyone from a running card (`p2p=`, no relay yet) and
    holds everyone's LAN route: the LAN links carry route hints, and the
    relay offers in them. `env`: more for every node; `own_env` and `extra`
    (more service arguments): per node name; `before_start(nodes)` runs
    after `init`. Returns (the nodes by name, every gate admitted every
    contact)."""
    nodes: dict = {}
    for k in operators + members:
        base = FRIEND_ENV if k in operators else FRIEND_MEMBER_ENV
        nodes[k] = Node(k, root, dict(base, **(env or {}), **(own_env or {}).get(k, {})))
    for n in nodes.values():
        n.init()
    if before_start:
        before_start(nodes)
    for k, n in nodes.items():
        n.start(extra=('--p2p-listen', '127.0.0.1:0' if k in operators else 'relay',
                       *(extra or {}).get(k, ())))
    cards = {k: n.card() for k, n in nodes.items()}
    fps = {k: n.fingerprint() for k, n in nodes.items()}
    for x in nodes.values():
        for k, y in nodes.items():
            if x is not y:
                x.add_card(cards[k], TAGS[k], fps[k])
                x.set_lan(TAGS[k], y.dial)
    gate = f'raven-node p2p: peer gate reloaded (verified contacts {len(nodes) - 1},'
    ready = all(wait_log(n, gate, 30) is not None for n in nodes.values())
    return nodes, ready


def friend_relay_tcp(node: Node, since: int, old: str = '', secs: float = 30) -> str | None:
    """The loopback TCP address (`/ip4/127.0.0.1/tcp/N`) the node's friend
    relay listens on once this run of it is up (an `up` line after `since`,
    an address other than `old`)."""
    if wait_log(node, FRIEND_UP, secs, since) is None:
        return None
    found: list = []

    def listening() -> bool:
        st = node.friend_relay()
        tcp = [a for a in st.get('listen_addrs', []) if '/tcp/' in a and a != old]
        found[:] = tcp[:1]
        return bool(tcp) and node.proc is not None and st.get('pid') == node.proc.pid

    return found[0] if wait_until(listening, secs, 0.2) is not None else None


def offered_to(node: Node) -> int:
    """`offered to` of `ash relay status` (FRIEND RELAY): how many verified
    contacts the running friend relay is offered to now (0 while it offers
    nothing)."""
    m = re.search(r'offered to\s+(\d+) contact', node.ash('relay', 'status').stdout)
    return int(m.group(1)) if m else 0


def offer_friend_relay(node: Node, members: int, external=None, secs: float = 30) -> str | None:
    """Turn the node's friend relay on, then name the address its members
    reach it at (`relay_external`: `external(tcp)`, or its TCP listen
    address itself; on loopback nothing else makes an address worth
    offering), and wait until it is offered to `members` contacts. The
    address named, or None."""
    mark = log_size(node)
    node.relay_offer(True)
    tcp = friend_relay_tcp(node, mark)
    if tcp is None:
        return None
    named = external(tcp) if external else tcp
    node.relay_offer(True, [named])
    return named if wait_until(lambda: offered_to(node) >= members, secs) is not None else None


def offers_from(node: Node, operator: Node) -> int:
    """How many relay offers `node` keeps from `operator` (its
    learned_routes.json entry)."""
    try:
        entries = learned_rows(node)
    except (OSError, ValueError):
        return 0
    return sum(len(e.get('offers') or []) for e in entries if isinstance(e, dict)
               and e.get('pub_hex', '').lower() == operator.pub.lower())


def offered_slots(node: Node, n: int) -> bool:
    """The node holds `n` relays picked from offers, each reserved
    (`relay_i_source=offer` and `relay_i: reserved` in its doctor)."""
    f = node.status_json()
    return all(f.get(f'relay_{i}_source') == 'offer' and f.get(f'relay_{i}') == 'reserved'
               for i in range(1, n + 1))


def lan_send(node: Node, to: str, text: str) -> str:
    return status_word(node.send(to, text, carrier='lan')[1])


def p2p_peer(card: str) -> str:
    return re.search(r' p2p=(\S+)', card).group(1)


def friend_logs_clean(nodes) -> bool:
    """No log names a PeerId, and no friend relay, relay choice or route
    hints line names an address (counts and ports only)."""
    for n in nodes:
        text = n.log_path.read_text(errors='replace')
        if '12D3KooW' in text:
            return False
        for line in text.splitlines():
            if (('friend relay' in line or 'raven-node p2p: relay ' in line
                 or 'raven-node hints' in line) and ('/ip4/' in line or '127.0.0.1' in line)):
                return False
    return True


def s41_friend_relay_offer_and_select(root: Path) -> dict:
    """Friend relay (RAVEN_FAULT_FRIEND=1): Alice turns her friend relay on
    (`ash relay offer on`, its loopback address named with `--external`: in
    her sealed profile only the sealed sidecar holds it). Bob and Carol
    listen nowhere and set no relay; everyone pins everyone. Bob and Carol
    each send Alice one LAN message, whose route hints answer with her
    offer: within 30 s each holds her relay as `relay 1`, picked from the
    offer and reserved. Her friend relay's PeerId is its own (not her p2p
    PeerId), with 2 members and 2 reservations. A LAN message each way
    tells Bob and Carol each other's relay; then Carol -> Bob and Bob ->
    Carol are `relayed` through Alice's relay, each exactly once. No log
    names a PeerId, nor a relay line an address."""
    nodes, ready = friend_nodes(root, 'a', 'bc')
    a, b, c = nodes['a'], nodes['b'], nodes['c']
    t0 = time.time()
    named = offer_friend_relay(a, 2)
    offer_s = took(time.time() - t0)
    asks = [lan_send(x, 'alice', f's41-{x.name}-to-a') for x in (b, c)]
    t1 = time.time()
    learned = wait_until(lambda: offers_from(b, a) == 1 and offers_from(c, a) == 1, 30)
    reserved = wait_until(lambda: offered_slots(b, 1) and offered_slots(c, 1), 30)
    reserved_s = took(None if reserved is None else time.time() - t1)
    relay_peer = a.friend_relay().get('peer_id', '')
    a_facts = wait_until(lambda: a.status_json().get('friend_relay_reserved') == '2', 15)
    facts = a.status_json()
    hints = [lan_send(b, 'carol', 's41-hints-b2c'), lan_send(c, 'bob', 's41-hints-c2b')]
    knows = wait_until(lambda: (learned_entry(c, b) or {}).get('relays', 0) >= 1
                       and (learned_entry(b, c) or {}).get('relays', 0) >= 1, 30)
    c2b = send_path(c, 'bob', 's41-c2b', 'p2p')
    b2c = send_path(b, 'carol', 's41-b2c', 'p2p')
    inbox_b, inbox_c = b.inbox(), c.inbox()
    a_log = a.log_path.read_text(errors='replace')
    return dict(
        ok=ready and named is not None and asks == ['DELIVERED', 'DELIVERED']
        and learned is not None and reserved is not None and relay_peer != ''
        and relay_peer != p2p_peer(a.card()) and a_facts is not None
        and facts.get('friend_relay') == 'up' and facts.get('friend_relay_members') == '2'
        and hints == ['DELIVERED', 'DELIVERED'] and knows is not None
        and c2b[1:] == ('DELIVERED', 'relayed') and b2c[1:] == ('DELIVERED', 'relayed')
        and count(inbox_b, 's41-c2b') == 1 and count(inbox_c, 's41-b2c') == 1
        and FRIEND_UP in a_log and friend_logs_clean(nodes.values()),
        ready=ready, offer_on_s=offer_s, offer_asks=asks, offers_learned_s=took(learned),
        reserved_s=reserved_s, own_relay_key=relay_peer != p2p_peer(a.card()),
        friend_relay=dict(state=facts.get('friend_relay'),
                          members=facts.get('friend_relay_members'),
                          reserved=facts.get('friend_relay_reserved')),
        hints_lan=hints, relays_learned_s=took(knows), c2b=c2b, b2c=b2c,
        copies=[count(inbox_b, 's41-c2b'), count(inbox_c, 's41-b2c')],
        b_facts={k: v for k, v in b.status_json().items() if k.startswith('relay_')},
        relay_counts=a.friend_relay().get('counts'))


def free_tcp_udp_port() -> int:
    """A loopback port free for TCP and UDP both (a friend relay listens on
    TCP and QUIC at one fixed port)."""
    for _ in range(64):
        with socket.socket() as t, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            t.bind(('127.0.0.1', 0))
            port = t.getsockname()[1]
            try:
                u.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise RuntimeError('no loopback port free for TCP and UDP')


def relay_rows(node: Node) -> dict:
    """The `relay N` rows of `ash status`, by slot (`OK — Alice's relay
    (127.0.0.1:N), reserved for …`)."""
    rows = {}
    for line in node.ash('status').stdout.splitlines():
        m = re.match(r'\s*relay (\d+)\s+(.+)$', line)
        if m:
            rows[int(m.group(1))] = m.group(2).strip()
    return rows


def row_owner(row: str) -> str:
    """The node name of the operator a relay row names (`Alice's relay`)."""
    m = re.search(r"(\w+)'s relay", row)
    names = {v: k for k, v in TAGS.items()}
    return names.get(m.group(1).lower(), '') if m else ''


def learned_relay_addrs(node: Node, other: Node) -> list:
    """The relay addresses `node` learned from `other`'s route hints."""
    try:
        entries = learned_rows(node)
    except (OSError, ValueError):
        return []
    return [r for e in entries if isinstance(e, dict)
            and e.get('pub_hex', '').lower() == other.pub.lower() for r in e.get('relays', [])]


def s42_friend_relay_sleeps(root: Path) -> dict:
    """Friend relay (RAVEN_FAULT_FRIEND=1): three operators (Alice, Dave and
    Erin; one is the standby) offer their friend relays, each on a fixed
    loopback port so a restart keeps its address. Bob and Carol listen
    nowhere and pick 2 each (RAVEN_LAB_RELAY_SELECT=20,10,5, pings every
    5 s: RAVEN_LAB_P2P_PING=5,2). The operator of Bob's first relay is frozen with SIGSTOP (a laptop asleep, every
    socket open and silent) for 90 s: Bob logs `relay replaced` within 60 s,
    and Carol's messages to Bob, one every 15 s, keep arriving, in order and
    each exactly once (replaced_s; gap_s, the longest a message took to show
    up in Bob's inbox). After SIGCONT the operator logs `woke from sleep`,
    and Bob keeps his new relay: no second `relay replaced` within 60 s."""
    ports = {k: free_tcp_udp_port() for k in 'ade'}
    # Pings every 5 s (2 s timeout): a frozen relay is noticed within
    # seconds, not after the 15 s + 5 s default round.
    nodes, ready = friend_nodes(
        root, 'ade', 'bc', env={'RAVEN_LAB_RELAY_SELECT': '20,10,5', 'RAVEN_LAB_P2P_PING': '5,2'},
        own_env={k: {'RAVEN_LAB_FRIEND_RELAY_LISTEN': f'127.0.0.1:{p}'} for k, p in ports.items()})
    b, c = nodes['b'], nodes['c']
    ops = [nodes[k] for k in 'ade']
    named = [offer_friend_relay(o, 4) for o in ops]
    asks = [lan_send(x, TAGS[o.name], f's42-{x.name}-to-{o.name}') for x in (b, c) for o in ops]
    picked = wait_until(lambda: offered_slots(b, 2) and offered_slots(c, 2), 60)
    hints = [lan_send(b, 'carol', 's42-hints-b2c'), lan_send(c, 'bob', 's42-hints-c2b')]
    knows = wait_until(lambda: (learned_entry(c, b) or {}).get('relays', 0) == 2, 30)
    before = relay_rows(b)
    first = row_owner(before.get(1, ''))
    if not (ready and None not in named and picked is not None and first in ('a', 'd', 'e')):
        return dict(ok=False, ready=ready, named=[n is not None for n in named], asks=asks,
                    picked_s=took(picked), b_rows=before)
    sleeper = nodes[first]
    marks = {n.name: log_size(n) for n in nodes.values()}
    sends: list = []
    arrived: dict = {}
    replaced_s = lost_s = None
    t_stop = time.time()
    sleeper.sigstop()
    try:
        while time.time() - t_stop < 90:
            due = len(sends) * 15
            if time.time() - t_stop >= due:
                text = f's42-m{len(sends) + 1}'
                sends.append((text, time.time(), send_path(c, 'bob', text, 'p2p')))
            b_log = b.log_path.read_text(errors='replace')[marks['b']:]
            if lost_s is None and RESERVATION_LOST in b_log:
                lost_s = round(time.time() - t_stop, 1)
            if replaced_s is None and RELAY_REPLACED in b_log:
                replaced_s = round(time.time() - t_stop, 1)
            inbox = b.inbox()
            for text, sent_at, _ in sends:
                if text not in arrived and count(inbox, text):
                    arrived[text] = round(time.time() - sent_at, 1)
            time.sleep(1)
    finally:
        sleeper.sigcont()
    t_cont = time.time()
    after_mark = log_size(b)
    woke = wait_log(sleeper, 'raven-node netwatch: woke from sleep', 30, marks[sleeper.name])
    all_in = wait_until(lambda: all(count(b.inbox(), t) for t, _, _ in sends), 60)
    inbox = b.inbox()
    for text, sent_at, _ in sends:
        if text not in arrived and count(inbox, text):
            arrived[text] = round(time.time() - sent_at, 1)
    # Stickiness: 60 s after the operator woke, no second replacement.
    time.sleep(max(0.0, 60 - (time.time() - t_cont)))
    second = b.log_path.read_text(errors='replace')[after_mark:].count(RELAY_REPLACED)
    after = relay_rows(b)
    order = [inbox.find(t) for t, _, _ in sends]
    copies = [count(inbox, t) for t, _, _ in sends]
    return dict(
        ok=knows is not None and hints == ['DELIVERED', 'DELIVERED']
        and replaced_s is not None and replaced_s <= 60 and woke is not None
        and all_in is not None and copies == [1] * len(sends) and order == sorted(order)
        and second == 0 and first not in {row_owner(r) for r in after.values()}
        and len(after) == 2 and all(r.startswith('OK') for r in after.values())
        and friend_logs_clean(nodes.values()),
        ready=ready, asks=asks, picked_s=took(picked), frozen=first, lost_s=lost_s,
        replaced_s=replaced_s,
        gap_s=max(arrived.values()) if len(arrived) == len(sends) else None,
        arrival_s=arrived, sends=[(t, s[1:]) for t, _, s in sends], copies=copies,
        in_order=order == sorted(order), woke_s=took(woke), second_replacement=second,
        b_relays_before=sorted(row_owner(r) for r in before.values()),
        b_relays_after=sorted(row_owner(r) for r in after.values()))


def s43_relay_moves(root: Path) -> dict:
    """Friend relay (RAVEN_FAULT_FRIEND=1): Alice offers her friend relay;
    Bob listens nowhere and holds a dedicated relay R he set by hand (slot
    1) and Alice's, picked from her offer (slot 2); Carol picks Alice's.
    Alice's network changes (lab netwatch line): her friend relay starts
    over on a new port with the same key, and she names the new address.
    Her next route hints carry it: Bob follows within 60 s (follow_s), the
    same slot re-reserved at the new address, with no relay chosen or
    replaced, and his own announce tells Carol. R stops, and Carol -> Bob
    is `relayed` through Alice's relay at its new address, exactly once."""
    net = root / 'a-net.txt'
    net.write_text('up 192.0.2.20/24\n')
    relay = RelayProc(root)

    def allow(nodes: dict) -> None:
        for k in 'ab':
            relay.allow(nodes[k].p2p_card(relay.via))

    nodes, ready = friend_nodes(root, 'a', 'bc', own_env={'a': {'RAVEN_LAB_NETWATCH_EVENTS': str(net)}},
                                extra={'b': ('--p2p-relay', relay.via)}, before_start=allow)
    a, b, c = nodes['a'], nodes['b'], nodes['c']
    baseline = wait_log(a, 'raven-node netwatch: watching (1 network)', 30)
    old = offer_friend_relay(a, 2)
    peer_before = a.friend_relay().get('peer_id')

    def b_slots() -> bool:
        f = b.status_json()
        return (f.get('relay_1_source'), f.get('relay_2_source')) == ('manual', 'offer') \
            and f.get('relay_1') == f.get('relay_2') == 'reserved'

    # A first link each way: the offer answers it, and Alice's announcer
    # tells only contacts whose route hints it holds.
    asks = [lan_send(x, 'alice', f's43-{x.name}-to-a') for x in (b, c)]
    t_told = time.time()
    held = wait_until(lambda: b_slots() and offered_slots(c, 1), 60)
    hints = [lan_send(b, 'carol', 's43-hints-b2c'), lan_send(c, 'bob', 's43-hints-c2b')]
    knows = wait_until(lambda: (learned_entry(c, b) or {}).get('relays', 0) == 2, 30)
    if not (ready and baseline is not None and old is not None and held is not None):
        return dict(ok=False, ready=ready, baseline=baseline is not None, offered=old is not None,
                    asks=asks, held_s=took(held), b_facts=b.status_json())
    # A relay does not move twice a minute: the move comes after Alice's
    # announcer may link to Bob again (one announce link per contact a
    # minute), so his first news of it is the one measured.
    time.sleep(max(0.0, 65 - (time.time() - t_told)))
    marks = {n.name: log_size(n) for n in nodes.values()}
    t_move = time.time()
    with open(net, 'a') as f:
        f.write('down 192.0.2.20/24\nup 198.51.100.8/24\n')
    new = friend_relay_tcp(a, marks['a'], old=old, secs=60)
    if new is None:
        return dict(ok=False, error='the friend relay did not start over on a new port')
    a.relay_offer(True, [new])
    new_port = new.rsplit('/', 1)[1]
    follow = wait_until(lambda: any(f'127.0.0.1:{new_port})' in r and r.startswith('OK')
                                    for r in relay_rows(b).values()), 60)
    follow_s = took(None if follow is None else time.time() - t_move)
    b_rows = relay_rows(b)
    b_after = b.log_path.read_text(errors='replace')[marks['b']:]
    reselected = RELAY_CHOSEN in b_after or RELAY_REPLACED in b_after
    told = wait_until(lambda: any(f'/tcp/{new_port}/' in r for r in learned_relay_addrs(c, b)), 60)
    relay.stop()
    c2b = send_path(c, 'bob', 's43-c2b', 'p2p')
    inbox = b.inbox()
    return dict(
        ok=asks == hints == ['DELIVERED', 'DELIVERED'] and knows is not None
        and follow is not None and follow_s <= 60 and not reselected and told is not None
        and a.friend_relay().get('peer_id') == peer_before
        and c2b[1:] == ('DELIVERED', 'relayed') and count(inbox, 's43-c2b') == 1
        and friend_logs_clean(nodes.values()),
        ready=ready, held_s=took(held), moved_port=old != new, follow_s=follow_s,
        reselected=reselected, b_rows=b_rows, carol_told_s=took(told),
        same_key=a.friend_relay().get('peer_id') == peer_before, c2b=c2b,
        copies=count(inbox, 's43-c2b'))


def s44_consent_off_withdraws(root: Path) -> dict:
    """Friend relay (RAVEN_FAULT_FRIEND=1): Bob holds Alice's relay, picked
    from her offer. Alice turns relaying off (`ash relay offer off`): her
    friend relay stops within 10 s and Bob's reservation ends with it; her
    route hints, announced to Bob, no longer carry the offer, and Bob drops
    the relay at once (`relay dropped (offer withdrawn)`, within 30 s of the
    off; his store keeps no offer of hers and his status no relay row)."""
    nodes, ready = friend_nodes(root, 'a', 'b')
    a, b = nodes['a'], nodes['b']
    named = offer_friend_relay(a, 1)
    ask = lan_send(b, 'alice', 's44-b-to-a')
    held = wait_until(lambda: offered_slots(b, 1), 30)
    marks = {n.name: log_size(n) for n in (a, b)}
    t_off = time.time()
    a.relay_offer(False)
    stopped = wait_log(a, 'raven-node friend relay: stopped (', 10, marks['a'])
    lost = wait_log(b, RESERVATION_LOST, 30, marks['b'])
    withdrawn = wait_log(b, OFFER_WITHDRAWN, max(1.0, 30 - (time.time() - t_off)), marks['b'])
    withdrawn_s = took(None if withdrawn is None else time.time() - t_off)
    gone = wait_until(lambda: offers_from(b, a) == 0 and not relay_rows(b), 15)
    return dict(
        ok=ready and named is not None and ask == 'DELIVERED' and held is not None
        and stopped is not None and lost is not None and withdrawn is not None
        and gone is not None and 'raven-node friend relay: turned off' in
        a.log_path.read_text(errors='replace')[marks['a']:] and friend_logs_clean((a, b)),
        ready=ready, held_s=took(held), relay_stopped_s=took(stopped),
        reservation_lost_s=took(lost), withdrawn_s=withdrawn_s,
        offers_left=offers_from(b, a), b_relay_rows=relay_rows(b))


RESET_SCENARIOS = [s05b_queued_then_receiver_loses_state,
                   s05d_receiver_loses_state_and_certificate,
                   s22_four_wipes_end_in_loop_hold]


# ---- why a contact cannot be reached (any-network plan, Phase 2 item 5) ----

# What the diagnosis says, as `ash send` and `ash status` word it. NO_ROUTE_ADVICE:
# words that would send someone without a route to the internet after a fix
# on the internet side (the relay kit, a VPS, a port forward, UPnP, a relay
# offer).
NOT_REACHABLE = 'NOT REACHABLE NOW'
NOBODY_REACHABLE = 'Nobody in your circle can be reached'
NO_ROUTE_ADVICE = ('relay kit', 'RELAY_KIT', 'VPS', 'Raspberry', 'forward port', 'UPnP',
                   'raven relay offer', 'offer relaying')


def not_reachable_row(node: Node, tag: str) -> str:
    """`tag`'s row in the node's NOT REACHABLE NOW section ('' when none)."""
    section = status_section(node.ash('status').stdout, NOT_REACHABLE)
    return status_row(section, tag.capitalize()) or ''


def section_gone(node: Node) -> bool:
    return not status_section(node.ash('status').stdout, NOT_REACHABLE)


def nat_pair(root: Path, a_env: dict | None = None) -> tuple:
    """Alice and Bob with their p2p host on, no listening port (the retired
    mode, P2P_RELAY_ONLY_ENV) and no relay, saved with `ash node p2p on` as
    a user would; pinned to each other from cards that name no relay. One
    message each way over a LAN route opens their session, then the LAN
    routes are cleared: the p2p route is all that is left. `a_env`: Alice's
    environment (P2P_RELAY_ONLY_ENV by default). Returns (alice, bob, every
    setup step was seen)."""
    a = Node('a', root, a_env or P2P_RELAY_ONLY_ENV)
    b = Node('b', root, P2P_RELAY_ONLY_ENV)
    ok = True
    for n in (a, b):
        n.init()
        ok &= n.ash('node', 'p2p', 'on', '--listen', 'relay', '--no-upnp').returncode == 0
        n.start()
        ok &= wait_log(n, 'raven-node p2p: host up (listeners=0, relays=0)', 30) is not None
    cards = {n.name: n.card() for n in (a, b)}
    ok &= not any(' via=' in c for c in cards.values())
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    a.set_lan('bob', b.dial)
    b.set_lan('alice', a.dial)
    ok &= all(wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
              is not None for n in (a, b))
    ok &= lan_send(a, 'bob', 'nat-warm-ab') == 'DELIVERED'
    ok &= lan_send(b, 'alice', 'nat-warm-ba') == 'DELIVERED'
    clear_book_routes(a, 'bob')
    clear_book_routes(b, 'alice')
    return a, b, ok


def s48_relay_sleeps_then_wakes(root: Path) -> dict:
    """Diagnosis (RAVEN_FAULT_P2P=1): Alice and Bob reach each other only
    through relay R (no listener: the retired mode), and a first message is
    delivered. R is frozen with SIGSTOP, as a sleeping laptop: TCP connects
    hang instead of being refused. Alice sends, and the result records what
    her send said and how long after the SIGSTOP `ash status` says R `is
    not answering`: her REACHABILITY advice (W1, w1_s) and Bob's NOT
    REACHABLE NOW row (row_s, `no path — your relay at … is not answering
    (you both use it)`); both within 60 s. After SIGCONT the message is
    delivered once with no new send (delivered_s) and the section is gone
    (section_gone_after_cont_s)."""
    relay = RelayProc(root)
    a, b = (Node(n, root, P2P_RELAY_ONLY_ENV) for n in ('a', 'b'))
    for n in (a, b):
        n.init()
    cards = {n.name: n.p2p_card(relay.via) for n in (a, b)}
    for n in (a, b):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30)
    for n in (a, b):
        n.start(extra=('--p2p-listen', 'relay', '--p2p-relay', relay.via))
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b)]
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    ready = allowed is not None and None not in reserved + gates
    m1 = send_path(a, 'bob', 's48-m1', 'p2p')
    # The first text that says so, and when (seconds after the SIGSTOP).
    seen: dict = {}
    texts = {'w1': '', 'row': ''}
    os.kill(relay.proc.pid, signal.SIGSTOP)
    t_stop = time.time()
    try:
        rc, sent, send_s = a.send('bob', 's48-m2', carrier='p2p')
        m = re.search(r'mid=([0-9a-f]{8})', sent)
        mid = m.group(1) if m else ''

        def asleep() -> bool:
            status = a.ash('status').stdout
            now = {'w1': status_row(status_section(status, 'REACHABILITY'), 'what to do'),
                   'row': status_row(status_section(status, NOT_REACHABLE), 'Bob')}
            for key, text in now.items():
                if f'{key}_s' not in seen and 'is not answering' in (text or ''):
                    seen[f'{key}_s'] = round(time.time() - t_stop, 1)
                    texts[key] = text
            return len(seen) == 2

        wait_until(asleep, 90, 1)
    finally:
        os.kill(relay.proc.pid, signal.SIGCONT)
    t_cont = time.time()
    delivered = wait_inbox(b, 's48-m2', RELAY_RECOVERY_S)
    gone = wait_until(lambda: section_gone(a), 60, 1)
    gone_s = None if gone is None else time.time() - t_cont
    st = a.ash('outbox', 'status', mid).stdout if mid else ''
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and m1[1:] == ('DELIVERED', 'relayed') and status_word(sent) == 'QUEUED'
        and (seen.get('w1_s') or 99) <= 60 and (seen.get('row_s') or 99) <= 60
        and texts['w1'].startswith('your relay is not answering')
        and texts['row'].startswith('no path \u2014 your relay at 127.0.0.1:')
        and 'is not answering (you both use it)' in texts['row']
        and delivered is not None and count(b.inbox(), 's48-m2') == 1
        and gone is not None and '12D3KooW' not in logs,
        ready=ready, m1=m1, send=(rc, status_word(sent), round(send_s, 1)),
        send_text=sent[-700:], **seen, **texts,
        delivered_s=None if delivered is None else round(delivered, 1),
        section_gone_after_cont_s=took(gone_s),
        delivered_via=(outbox_field(st, 'state'), outbox_field(st, 'carrier'),
                       outbox_field(st, 'path')),
        relay_counts=relay.counts())


def s48c_contact_sleeps_relay_awake(root: Path) -> dict:
    """Diagnosis (RAVEN_FAULT_P2P=1): s48's setup, but Bob's raven-node is
    frozen with SIGSTOP (a laptop asleep or off Wi-Fi without closing) while
    relay R stays up and keeps Bob's reservation until it notices (about a
    minute). Alice restarts first, so no connection to Bob is left. For 60 s
    after the stop, while Alice's `relay 1` row says OK, Bob's NOT REACHABLE
    NOW row never blames her relay (`is not answering`) or a card (`turned
    away`), and it says `offline` within 45 s (offline_s). After SIGCONT the
    message is delivered once with no new send."""
    relay = RelayProc(root)
    a, b = (Node(n, root, P2P_RELAY_ONLY_ENV) for n in ('a', 'b'))
    for n in (a, b):
        n.init()
    cards = {n.name: n.p2p_card(relay.via) for n in (a, b)}
    for n in (a, b):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30)
    extra = ('--p2p-listen', 'relay', '--p2p-relay', relay.via)
    for n in (a, b):
        n.start(extra=extra)
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b)]
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    m1 = send_path(a, 'bob', 's48c-m1', 'p2p')
    # Alice restarts: no connection to Bob is left (as the netns diag case).
    mark = log_size(a)
    a.stop()
    a.start(extra=extra)
    again = wait_log(a, 'raven-node p2p: reservation accepted', 60, mark)
    ready = allowed is not None and None not in reserved + gates + [again]
    wrong: list = []
    seen: dict = {}
    os.kill(b.proc.pid, signal.SIGSTOP)
    t_stop = time.time()
    try:
        rc, sent, send_s = a.send('bob', 's48c-m2', carrier='p2p')
        m = re.search(r'mid=([0-9a-f]{8})', sent)
        mid = m.group(1) if m else ''

        def look() -> bool:
            status = a.ash('status').stdout
            relay1 = status_row(status_section(status, 'REACHABILITY'), 'relay 1') or ''
            row = status_row(status_section(status, NOT_REACHABLE), 'Bob') or ''
            at = round(time.time() - t_stop, 1)
            if relay1.startswith('OK') and ('is not answering' in row or 'turned away' in row):
                wrong.append((at, relay1, row))
            if 'offline_s' not in seen and row.startswith('offline'):
                seen['offline_s'] = at
                seen['offline_row'] = row
            return time.time() - t_stop >= 60

        wait_until(look, 90, 2)
    finally:
        os.kill(b.proc.pid, signal.SIGCONT)
    delivered = wait_inbox(b, 's48c-m2', RELAY_RECOVERY_S)
    st = a.ash('outbox', 'status', mid).stdout if mid else ''
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and m1[1:] == ('DELIVERED', 'relayed') and status_word(sent) == 'QUEUED'
        and not wrong and (seen.get('offline_s') or 99) <= 45
        and delivered is not None and count(b.inbox(), 's48c-m2') == 1
        and '12D3KooW' not in logs,
        ready=ready, m1=m1, send=(rc, status_word(sent), round(send_s, 1)),
        send_text=sent[-700:], wrong=wrong[:5], **seen,
        delivered_s=None if delivered is None else round(delivered, 1),
        delivered_via=(outbox_field(st, 'state'), outbox_field(st, 'carrier'),
                       outbox_field(st, 'path')),
        relay_counts=relay.counts())


def s49_nobody_reachable_then_a_relay(root: Path) -> dict:
    """Diagnosis (RAVEN_FAULT_P2P=1): Alice and Bob with no listening port
    and no relay (nat_pair). Alice's p2p message is queued with both_nat and
    the 'nobody in your circle' fixes, and `ash doctor` counts it. Then a
    relay R: `ash node p2p on --relay <R>` on both, R allows both cards,
    each saves the relay on the other's contact (`contact set-addr --via`,
    what the other's new card would say: no dial uses one's own relays for
    a contact that names none), and both services restart. The queued
    message is delivered once with no new send (delivered_s), nothing waits
    on Alice and the NOT REACHABLE NOW section is gone."""
    a, b, ready = nat_pair(root)
    rc, sent, send_s = a.send('bob', 's49-m1', carrier='p2p')
    row = not_reachable_row(a, 'bob')
    doctor = a.ash('doctor').stdout
    counted = 'unreachable_contacts: 1 (raven status names them) both_nat=1' in doctor
    relay = RelayProc(root)
    for n, tag in ((a, 'bob'), (b, 'alice')):
        ready &= n.ash('node', 'p2p', 'on', '--listen', 'relay', '--relay', relay.via,
                       '--no-upnp').returncode == 0
        relay.allow(n.p2p_card(relay.via))
        r = n.ash('contact', 'set-addr', f'@{tag}', '--via', relay.via)
        ready &= r.returncode == 0
    ready &= relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30) is not None
    marks = {n.name: log_size(n) for n in (a, b)}
    for n in (a, b):
        n.stop()
        n.start()
    t_restart = time.time()
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60, marks[n.name])
                for n in (a, b)]
    delivered = wait_inbox(b, 's49-m1', RELAY_RECOVERY_S)
    delivered_s = None if delivered is None else time.time() - t_restart
    gone = wait_until(lambda: section_gone(a), 60, 1)
    # The item leaves Alice's outbox only once her ACK is back, which may
    # come after Bob has the message and after the section is gone (that
    # section says nothing about the ACK): waited for, never read once
    # (review E-harness-docs-ci-5).
    emptied = wait_until(lambda: 'Nothing waiting' in a.outbox(), 30, 1)
    outbox = a.outbox()
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and status_word(sent) == 'QUEUED'
        and 'both behind NAT' in sent and NOBODY_REACHABLE in sent
        and '`raven relay offer on`' in sent and 'forward port 7423 (TCP and UDP)' in sent
        and row.startswith('no path \u2014 you and Bob are both behind NAT') and counted
        and None not in reserved and delivered is not None and count(b.inbox(), 's49-m1') == 1
        and emptied is not None and 'Nothing waiting' in outbox and gone is not None
        and '12D3KooW' not in logs,
        ready=ready, send=(rc, status_word(sent), round(send_s, 1)), send_text=sent[-900:],
        row=row, doctor_counted=counted,
        reserved_s=[took(t) for t in reserved], delivered_after_restart_s=took(delivered_s),
        section_gone_s=took(gone), outbox_emptied_s=took(emptied), a_outbox=outbox[-300:],
        relay_counts=relay.counts())


def s48o_no_route_never_advises_a_relay(root: Path) -> dict:
    """Diagnosis without a route (RAVEN_FAULT_P2P=1 and
    RAVEN_FAULT_NETWATCH=1; cutoff study F9): s49's setup, and Alice's
    netwatch reads a lab file that says `egress none` (no default route).
    Alice's queued p2p message says she has no route to the internet and
    that it goes out on the same network (LocalOnly), never the 'nobody in
    your circle' fixes or any internet-side one (NO_ROUTE_ADVICE), and her
    status says so (W0, the collapsed NOT REACHABLE NOW row). Then `egress
    0a` (a route is back): `ash doctor` drops `internet_route: none`
    (route_back_s), and a fresh send says both_nat with s49's fixes again."""
    net = root / 'a-net.txt'
    net.write_text('up 192.0.2.48/24\negress none\n')
    a, b, ready = nat_pair(root, dict(P2P_RELAY_ONLY_ENV, RAVEN_LAB_NETWATCH_EVENTS=str(net)))
    rc, sent, send_s = a.send('bob', 's48o-m1', carrier='p2p')
    status = a.ash('status').stdout
    doctor = a.ash('doctor').stdout
    advice = [w for w in NO_ROUTE_ADVICE if w in sent + status + doctor]
    w0 = status_row(status_section(status, 'REACHABILITY'), 'what to do') or ''
    row = status_row(status_section(status, NOT_REACHABLE), 'contacts') or ''
    with open(net, 'a') as f:
        f.write('egress 0a\n')
    back = wait_until(lambda: 'internet_route: none' not in a.ash('doctor').stdout, 30)
    rc2, sent2, send2_s = a.send('bob', 's48o-m2', carrier='p2p')
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and status_word(sent) == 'QUEUED'
        and 'this computer has no route to the internet right now, so RAVEN can reach Bob '
            'only on the same network as you' in sent
        and 'Nothing to do: it goes out when you and Bob are on the same network, or when '
            'this computer can reach the internet again.' in sent
        and NOBODY_REACHABLE not in sent and not advice
        and w0.startswith('this computer has no route to the internet right now')
        and row.startswith('this computer has no route to the internet')
        and 'internet_route: none' in doctor
        and back is not None and status_word(sent2) == 'QUEUED'
        and 'both behind NAT' in sent2 and NOBODY_REACHABLE in sent2
        and count(b.inbox(), 's48o-m1') == 0 and '12D3KooW' not in logs,
        ready=ready, send=(rc, status_word(sent), round(send_s, 1)), send_text=sent[-700:],
        advice_words=advice, w0=w0, row=row, route_back_s=took(back),
        send_after_route=(rc2, status_word(sent2), round(send2_s, 1)),
        send_after_route_text=sent2[-700:])


# Phase 4 (RWS1; RAVEN_FAULT_WSS=1): what `ash status` and the doctor say.
WSS_PROXY_ROW = 'relay over WSS through the HTTPS proxy'
RESTRICTED_ROW = 'restricted network (relay only)'
NTLM_HINT = 'the HTTPS proxy needs Windows sign-in (NTLM/Kerberos), not supported'
# s50: how long the proxy stays killed.
PROXY_OUTAGE_S = 10


def p2p_info(node: Node) -> dict:
    """The running raven-node's p2p facts (IPC Status `p2p`), {} without."""
    try:
        return node_ipc(node, {'op': 'status', 'v': 1}).get('p2p') or {}
    except (OSError, ValueError, struct.error):
        return {}


def wss_proxy_pair(root: Path, auth: str = '') -> tuple:
    """Phase 4 (RAVEN_FAULT_WSS=1): relay R with a WSS listener on a port of
    its own (RelayProc wss), and the HTTPS proxy P (ConnectProxyProc, `auth`
    as there). Alice listens nowhere (the retired no-listener mode) and
    names R only as `/dns4/relay.invalid/tcp/<R's WSS port>/tls/ws`, which
    only P resolves, with RAVEN_P2P_PROXY naming P. Bob listens on loopback
    and reserves on R's raw TCP address with no proxy. On loopback Alice
    could dial any of R's own addresses, so nothing tells her one: R names
    only a closed port (`--external`, in Identify too), and so do both
    cards. A circuit rides the connection its sender already holds to R
    (Bob's reservation; Alice's, through P), as on a network that lets
    only the proxy out: Alice reaches R through P alone. Each pins the
    other's card. Returns (alice, bob, relay, proxy, every setup step was
    seen); Alice's reservation is not waited for."""
    closed = free_tcp_port()
    relay = RelayProc(root, wss=True, env=WSS_ENV,
                      extra=('--external', f'/ip4/127.0.0.1/tcp/{closed}'))
    proxy = ConnectProxyProc(root, auth=auth)
    a_via = f'/dns4/{PROXY_ONLY_NAME}/tcp/{relay.wss_port}/tls/ws/p2p/{relay.peer}'
    a = Node('a', root, dict(WSS_PROXY_ENV, RAVEN_LAB_P2P_RELAY_ONLY='1',
                             RAVEN_P2P_PROXY=proxy.url()))
    b = Node('b', root, WSS_ENV)
    for n in (a, b):
        n.init()
    cards = {n.name: n.p2p_card(relay.via_on(closed)) for n in (a, b)}
    for n in (a, b):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30)
    a.start(extra=('--p2p-listen', 'relay', '--p2p-relay', a_via))
    b.start(extra=('--p2p-listen', '127.0.0.1:0', '--p2p-relay', relay.via))
    reserved = wait_log(b, 'raven-node p2p: reservation accepted', 60)
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    ready = allowed is not None and reserved is not None and None not in gates
    return a, b, relay, proxy, ready


def proxy_leaks(node: Node, proxy: ConnectProxyProc) -> list:
    """What the node's log must never name (RWS1 §8): a PeerId, the proxy's
    address, the relay's name only the proxy resolves."""
    log = node.log_path.read_text(errors='replace')
    return [what for what in ('12D3KooW', f'127.0.0.1:{proxy.port}', PROXY_ONLY_NAME)
            if what in log]


def s50_proxy_outage_and_return(root: Path) -> dict:
    """Phase 4 (RWS1; RAVEN_FAULT_WSS=1): Alice reaches her relay only over
    WSS through the HTTPS proxy (wss_proxy_pair). She reserves through it
    (IPC relay_paths `wss-proxy`, restricted; her `ash status` p2p row says
    both in words) and a message each way is `relayed`, every tunnel the
    proxy carried starting with a TLS record (0x16). Then the proxy is
    killed mid-conversation (its tunnels end with it): Alice loses her
    reservation, her 3 messages to Bob and Bob's 1 to her wait. After
    PROXY_OUTAGE_S the proxy comes back on its port: Alice reserves through
    it again and all 4 are delivered, each exactly once, within
    RELAY_RECOVERY_S, with nothing left waiting. No log of hers names a
    PeerId, the proxy's address or the relay's name."""
    a, b, relay, proxy, ready = wss_proxy_pair(root)
    reserved = wait_log(a, 'raven-node p2p: reservation accepted', 60)
    info = {}
    wait_until(lambda: (info.update(p2p_info(a)) or info.get('restricted')), 30)
    row = status_row(a.ash('status').stdout, 'p2p') or ''
    m1 = send_path(a, 'bob', 's50-m1', 'p2p')
    m2 = send_path(b, 'alice', 's50-m2', 'p2p')
    tunnels_before = proxy.lines('tunnel ')

    marks = {n.name: log_size(n) for n in (a, b)}
    proxy.kill()
    t_out = time.time()
    lost = wait_log(a, 'raven-node p2p: reservation lost', 60, marks['a'])
    texts_ab = ['s50-q1', 's50-q2', 's50-q3']
    queued = [queued_send(a, 'bob', t) for t in texts_ab]
    queued.append(queued_send(b, 'alice', 's50-q4'))
    # The outage itself: PROXY_OUTAGE_S with no proxy (Alice's relay slot
    # retries and fails meanwhile).
    time.sleep(max(0.0, PROXY_OUTAGE_S - (time.time() - t_out)))
    since = log_size(a)
    proxy.start()
    t_back = time.time()
    back = wait_log(a, 'raven-node p2p: reservation accepted', RELAY_RECOVERY_S, since)
    delivered = wait_until(lambda: all(count(b.inbox(), t) for t in texts_ab)
                           and count(a.inbox(), 's50-q4'), RELAY_RECOVERY_S, 1)
    delivered_s = None if delivered is None else round(time.time() - t_back, 1)
    emptied = wait_until(lambda: all('Nothing waiting' in n.outbox() for n in (a, b)), 60, 1)
    copies = {t: count(b.inbox(), t) for t in texts_ab}
    copies['s50-q4'] = count(a.inbox(), 's50-q4')
    tunnels = proxy.lines('tunnel ')
    connects = proxy.lines('CONNECT ')
    want = f'CONNECT {PROXY_ONLY_NAME}:{relay.wss_port} 200'
    leaks = proxy_leaks(a, proxy)
    return dict(
        ok=ready and reserved is not None and info.get('relay_paths') == ['wss-proxy']
        and info.get('restricted') is True and WSS_PROXY_ROW in row and RESTRICTED_ROW in row
        and m1[1:] == ('DELIVERED', 'relayed') and m2[1:] == ('DELIVERED', 'relayed')
        and len(tunnels_before) >= 1 and lost is not None
        and [q[0] for q in queued] == ['QUEUED'] * 4 and back is not None
        and delivered is not None and set(copies.values()) == {1} and emptied is not None
        and len(tunnels) > len(tunnels_before)
        and all(t.endswith(' first=16') for t in tunnels)
        and all(c == want for c in connects) and not leaks,
        ready=ready, reserved_s=took(reserved), relay_paths=info.get('relay_paths'),
        restricted=info.get('restricted'), p2p_row=row, m1=m1, m2=m2,
        lost_s=took(lost), queued=[q[0] for q in queued],
        outage_s=round(t_back - t_out, 1), back_to_reserved_s=took(back),
        back_to_delivered_s=delivered_s, outboxes_emptied_s=took(emptied), copies=copies,
        tunnels=len(tunnels), tunnels_tls_only=all(t.endswith(' first=16') for t in tunnels),
        connects_named=sorted(set(connects)), a_log_names=leaks, relay_counts=relay.counts())


def s51_proxy_wants_negotiate(root: Path) -> dict:
    """Phase 4 (RWS1; RAVEN_FAULT_WSS=1): wss_proxy_pair with a proxy that
    answers every CONNECT 407 offering Negotiate and NTLM (a company proxy
    that wants a Windows sign-in), and a LAN route each way. Alice never
    reserves; within 30 s her raven-node reports the 407 (IPC proxy_auth
    `unsupported`), and her `ash status` p2p row, `ash doctor` and `ash node
    proxy` say the proxy needs Windows sign-in, not supported. The LAN path
    is unaffected: a message each way is delivered over the LAN, once. The
    proxy tunnelled nothing, and Alice's log names no PeerId, proxy address
    or relay name."""
    a, b, relay, proxy, ready = wss_proxy_pair(root, auth='Negotiate,NTLM')
    a.set_lan('bob', b.dial)
    b.set_lan('alice', a.dial)
    want = f'CONNECT {PROXY_ONLY_NAME}:{relay.wss_port} 407 (Negotiate,NTLM)'
    asked = wait_until(lambda: want in proxy.lines('CONNECT '), 30)
    reported = wait_until(lambda: p2p_info(a).get('proxy_auth') == 'unsupported', 30)
    row = status_row(a.ash('status').stdout, 'p2p') or ''
    doctor = a.ash('doctor').stdout
    shown = a.ash('node', 'proxy').stdout
    rc1, out1, _ = a.send('bob', 's51-lan-ab')
    rc2, out2, _ = b.send('alice', 's51-lan-ba')
    copies = (count(b.inbox(), 's51-lan-ab'), count(a.inbox(), 's51-lan-ba'))
    leaks = proxy_leaks(a, proxy)
    return dict(
        ok=ready and asked is not None and reported is not None and NTLM_HINT in row
        and NTLM_HINT in doctor and f'note: {NTLM_HINT}' in shown
        and status_word(out1) == status_word(out2) == 'DELIVERED' and copies == (1, 1)
        and 'raven-node p2p: reservation accepted' not in a.log_path.read_text(errors='replace')
        and not proxy.lines('tunnel ') and not leaks,
        ready=ready, asked_407_s=took(asked), reported_s=took(reported), p2p_row=row,
        doctor_says=NTLM_HINT in doctor, node_proxy=shown[-400:],
        lan=(rc1, status_word(out1), rc2, status_word(out2)), copies=copies,
        connects=sorted(set(proxy.lines('CONNECT '))), a_log_names=leaks)



# Phase 4 (RAVEN_PORT_MAPPING_V1; RAVEN_FAULT_PORTMAP=1): router port mapping
# is held by PORT_MAP_PRODUCTION_ENABLED. s52's mapped node runs with the
# debug switch RAVEN_LAB_PORT_MAP=1, its router named by
# RAVEN_LAB_PORTMAP_GATEWAY (FakePcp on 127.0.0.1, never the real router),
# 8 s leases (RAVEN_LAB_PORTMAP_LIFETIME, renewed every 4 s) and loopback as
# a lab address (RAVEN_LAB_P2P_LOCAL_CANDIDATES=1).
PORTMAP = os.environ.get('RAVEN_FAULT_PORTMAP') == '1'
# s52: how long a router restart may take to be followed by a new mapping.
REMAP_S = 10
MAPPED_PCP_LINE = 'raven-node p2p: router port mapped (PCP, port '
REMAPPED_LINE = 'raven-node p2p: router restarted; port mapped again'
# Review E-2: lines only libp2p-upnp's real gateway search leads to. A node
# whose router RAVEN_LAB_PORTMAP_GATEWAY names never starts that search (a
# silent FakePcp gives 'UPnP not tried (lab router)'); s52 fails on either.
UPNP_SEARCH_LINES = ('raven-node p2p: no PCP or NAT-PMP answer; trying UPnP',
                     'raven-node p2p: upnp ')


class FakePcp:
    """A PCP router (RFC 6887, ANNOUNCE and MAP only) on 127.0.0.1, on a
    thread of its own, built with struct from the RFC's field tables. It
    answers no NAT-PMP (version 0), so a client settles on PCP, and maps
    every port to the same port on 127.0.0.1 (where the node listens:
    nothing to forward, no real address ever named). `restart()` is a
    router restart: every mapping lost, the epoch from 0 again. Counts:
    `announces`, `maps` (lifetime > 0) and `deletes` (lifetime 0)."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.addr = f'127.0.0.1:{self.sock.getsockname()[1]}'
        self.lock = threading.Lock()
        self.epoch_start = time.monotonic()
        # (protocol, internal port) -> the nonce that owns the mapping.
        self.mappings: dict = {}
        self.announces = self.maps = self.deletes = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def restart(self) -> None:
        with self.lock:
            self.mappings.clear()
            self.epoch_start = time.monotonic()

    def held(self) -> int:
        with self.lock:
            return len(self.mappings)

    def stop(self) -> None:
        self.sock.close()

    def _serve(self) -> None:
        while True:
            try:
                req, src = self.sock.recvfrom(1100)
            except OSError:
                return
            with self.lock:
                answer = self.answer(req)
            if answer:
                try:
                    self.sock.sendto(answer, src)
                except OSError:
                    return

    def answer(self, req: bytes) -> bytes | None:
        """The answer to one request (None: NAT-PMP, a response, too short)."""
        if len(req) < 24 or req[0] != 2 or req[1] & 0x80:
            return None
        op = req[1]
        epoch = int(time.monotonic() - self.epoch_start)

        def header(result: int, lifetime: int) -> bytes:
            # version, R + opcode, reserved, result, lifetime, epoch, 96 reserved bits
            return struct.pack('!BBBBII12x', 2, 0x80 | op, 0, result, lifetime, epoch)

        if op == 0:
            self.announces += 1
            return header(0, 0)
        if op != 1 or len(req) < 60:
            return header(4 if op != 1 else 3, 0)  # UNSUPP_OPCODE, MALFORMED_REQUEST
        (lifetime,) = struct.unpack('!I', req[4:8])
        nonce, proto = req[24:36], req[36]
        (internal,) = struct.unpack('!H', req[40:42])
        key = (proto, internal)
        if self.mappings.get(key, nonce) != nonce:
            return header(2, 0) + req[24:60]  # NOT_AUTHORIZED: another nonce owns it
        if lifetime == 0:
            self.deletes += 1
            self.mappings.pop(key, None)
            return header(0, 0) + req[24:60]
        self.maps += 1
        self.mappings[key] = nonce
        granted = min(lifetime, 7200)
        external = bytes(10) + b'\xff\xff' + socket.inet_aton('127.0.0.1')
        return (header(0, granted) + nonce + bytes([proto, 0, 0, 0])
                + struct.pack('!HH', internal, internal) + external)


def s52_router_restart_remaps(root: Path) -> dict:
    """Phase 4 (RAVEN_PORT_MAPPING_V1; RAVEN_FAULT_PORTMAP=1): Bob maps his
    p2p port on FakePcp (`ash node upnp on`; 8 s leases), and Alice and Bob
    reach each other through relay R (relay_pair's setup). A message each
    way is delivered. Alice's node stops and Bob queues 3 messages for her;
    while they wait the router restarts (every mapping lost, epoch 0): Bob
    logs 'router restarted; port mapped again' and FakePcp holds his
    mappings again within REMAP_S. Alice comes back: all 3 arrive exactly
    once within RELAY_RECOVERY_S and nothing is left waiting on Bob. No log
    names a PeerId, no router line an address, and Bob never fell back to
    a real UPnP search (UPNP_SEARCH_LINES)."""
    pcp = FakePcp()
    relay = RelayProc(root)
    b_env = dict(P2P_ENV, RAVEN_LAB_PORT_MAP='1', RAVEN_LAB_PORTMAP_GATEWAY=pcp.addr,
                 RAVEN_LAB_PORTMAP_LIFETIME='8', RAVEN_LAB_P2P_LOCAL_CANDIDATES='1')
    a, b = Node('a', root, P2P_ENV), Node('b', root, b_env)
    for n in (a, b):
        n.init()
    consent = b.ash('node', 'upnp', 'on').returncode == 0
    cards = {n.name: n.p2p_card(relay.via) for n in (a, b)}
    for n in (a, b):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers') == 2, 30)
    p2p = ('--p2p-listen', '127.0.0.1:0', '--p2p-relay', relay.via)
    for n in (a, b):
        n.start(extra=p2p)
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b)]
    mapped = wait_log(b, MAPPED_PCP_LINE, 30)
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    ready = (consent and allowed is not None and None not in reserved + gates
             and mapped is not None)
    m1 = send_path(a, 'bob', 's52-m1', 'p2p')
    m2 = send_path(b, 'alice', 's52-m2', 'p2p')

    a.stop()
    texts = ['s52-q1', 's52-q2', 's52-q3']
    queued = [queued_send(b, 'alice', t) for t in texts]
    since = log_size(b)
    maps_before = pcp.maps
    pcp.restart()
    remapped = wait_until(
        lambda: REMAPPED_LINE in b.log_path.read_text(errors='replace')[since:]
        and pcp.held() >= 1, REMAP_S, 0.2)
    a.start(extra=p2p)
    t_back = time.time()
    delivered = wait_until(lambda: all(count(a.inbox(), t) for t in texts), RELAY_RECOVERY_S, 1)
    delivered_s = None if delivered is None else round(time.time() - t_back, 1)
    emptied = wait_until(lambda: 'Nothing waiting' in b.outbox(), 60, 1)
    copies = {t: count(a.inbox(), t) for t in texts}
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    addressed = [line for line in logs.splitlines()
                 if 'router' in line and '127.0.0.1' in line]
    b_log = b.log_path.read_text(errors='replace')
    upnp_lines = [line for line in b_log.splitlines()
                  if any(u in line for u in UPNP_SEARCH_LINES)]
    pcp.stop()
    return dict(
        ok=ready and m1[1] == 'DELIVERED' and m2[1] == 'DELIVERED'
        and [q[0] for q in queued] == ['QUEUED'] * 3 and remapped is not None
        and pcp.maps > maps_before and delivered is not None and set(copies.values()) == {1}
        and emptied is not None and '12D3KooW' not in logs and not addressed
        and not upnp_lines,
        ready=ready, mapped_s=took(mapped), m1=m1, m2=m2, queued=[q[0] for q in queued],
        remapped_s=took(remapped), router=dict(announces=pcp.announces, maps=pcp.maps,
                                               deletes=pcp.deletes),
        back_to_delivered_s=delivered_s, copies=copies, outbox_emptied_s=took(emptied),
        router_lines_with_an_address=len(addressed), upnp_search_lines=len(upnp_lines),
        relay_counts=relay.counts())

# Phase 4 (RAVEN_P2P_PEER_ROTATION_V1; RAVEN_FAULT_P2P=1 and
# RAVEN_FAULT_ROTATION=1): PeerId rotation is held by
# PEER_ROTATION_PRODUCTION_ENABLED. s53's nodes run with its debug switch
# RAVEN_LAB_PEER_ROTATION=1, a 30 s epoch (RAVEN_LAB_PEER_EPOCH_S), route
# hints (the schedule rides RRH1) and loopback as a lab address.
ROTATION = os.environ.get('RAVEN_FAULT_ROTATION') == '1'
ROTATION_EPOCH_S = 30
ROTATION_ENV = dict(P2P_ENV, RAVEN_LAB_ROUTE_HINTS='1', RAVEN_LAB_P2P_LOCAL_CANDIDATES='1',
                    RAVEN_LAB_PEER_ROTATION='1', RAVEN_LAB_PEER_EPOCH_S=str(ROTATION_EPOCH_S))
ROTATED_LINE = 'raven-node p2p: network ID rotated (epoch boundary)'


def stored_schedule(node: Node) -> dict:
    """The PeerId schedule `node` stores for its one contact (sealed
    peer_schedules.json), or {}."""
    raw = sealed_plain(node.dir, 'peer_schedules.json')
    try:
        all_ = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return next(iter(all_.values()), {}) if isinstance(all_, dict) else {}


def s53_rotation_boundary_with_queued_messages(root: Path) -> dict:
    """Phase 4 (RAVEN_P2P_PEER_ROTATION_V1 §9.1; RAVEN_FAULT_P2P=1 and
    RAVEN_FAULT_ROTATION=1): Bob turns PeerId rotation on (`ash node p2p
    rotate on`) and relay R gets his `ash relay schedule` (13 epochs of
    30 s). Alice and Bob reach each other through R, a message each way.
    Alice can follow, so Bob announces his coming PeerIds and rotates at a
    boundary ('network ID rotated'); Alice hears it and a third message is
    delivered under his new PeerId. Bob's node then stops and Alice queues 5
    messages for him while at least one more epoch boundary passes; Bob comes
    back under that epoch's PeerId and all 5 arrive exactly once, in order,
    within 60 s of his start. No log names a PeerId."""
    relay = RelayProc(root)
    a, b = Node('a', root, ROTATION_ENV), Node('b', root, ROTATION_ENV)
    for n in (a, b):
        n.init()
    on = b.ash('node', 'p2p', 'rotate', 'on').returncode == 0
    line = b.ash('relay', 'schedule', '--epochs', '13').stdout.strip()
    installed = subprocess.run(
        [ASH, '--data-dir', str(relay.dir), 'relay', 'allow', '--schedule', line],
        capture_output=True, text=True, timeout=60, env=ROTATION_ENV).returncode == 0
    cards = {n.name: n.p2p_card(relay.via) for n in (a, b)}
    for n in (a, b):
        relay.allow(cards[n.name])
    allowed = relay.wait_counts(lambda c: c.get('allowed_peers', 0) >= 15, 30)
    p2p = ('--p2p-listen', '127.0.0.1:0', '--p2p-relay', relay.via)
    for n in (a, b):
        n.start(extra=p2p)
    reserved = [wait_log(n, 'raven-node p2p: reservation accepted', 60) for n in (a, b)]
    a.add_card(cards['b'], 'bob', b.fingerprint())
    b.add_card(cards['a'], 'alice', a.fingerprint())
    gates = [wait_log(n, 'raven-node p2p: peer gate reloaded (verified contacts 1,', 30)
             for n in (a, b)]
    ready = (on and installed and allowed is not None and None not in reserved + gates)
    m1 = send_path(a, 'bob', 's53-m1', 'p2p')
    m2 = send_path(b, 'alice', 's53-m2', 'p2p')
    rotated = wait_log(b, ROTATED_LINE, 4 * ROTATION_EPOCH_S)
    heard = wait_until(lambda: stored_schedule(a).get('rotating') is True, 60, 1)
    m3 = send_path(a, 'bob', 's53-m3', 'p2p')
    peer_before = status_row(b.ash('status').stdout, 'p2p_peer') or ''

    b.stop()
    texts = [f's53-q{i}' for i in range(1, 6)]
    queued = [queued_send(a, 'bob', t) for t in texts]
    # At least one epoch boundary passes while Bob is away.
    time.sleep(ROTATION_EPOCH_S + 5)
    b.start(extra=p2p)
    t_back = time.time()
    delivered = wait_until(lambda: all(count(b.inbox(), t) for t in texts), 60, 1)
    delivered_s = None if delivered is None else round(time.time() - t_back, 1)
    inbox = b.inbox()
    copies = {t: count(inbox, t) for t in texts}
    order = [inbox.find(t) for t in texts]
    in_order = min(order) >= 0 and order == sorted(order)
    peer_after = status_row(b.ash('status').stdout, 'p2p_peer') or ''
    logs = ''.join(n.log_path.read_text(errors='replace') for n in (a, b))
    return dict(
        ok=ready and m1[1] == 'DELIVERED' and m2[1] == 'DELIVERED' and rotated is not None
        and heard is not None and m3[1] == 'DELIVERED' and [q[0] for q in queued] == ['QUEUED'] * 5
        and delivered is not None and set(copies.values()) == {1} and in_order
        and peer_after != peer_before and '12D3KooW' not in logs,
        ready=ready, m1=m1, m2=m2, rotated_s=took(rotated), heard_s=took(heard), m3=m3,
        queued=[q[0] for q in queued], back_to_delivered_s=delivered_s, copies=copies,
        in_order=in_order, new_peer_id=peer_after != peer_before, relay_counts=relay.counts())

def s90p_pinned_stale_address_answered_by_another_node(root: Path) -> dict:
    """Cutoff M0 (RAVEN_FAULT_OFFLINE=1: the noise pin gate open on every
    node). Alice and Bob link once, so Alice pins Bob's Noise static. Bob
    goes down and X, another raven-node profile (not Alice's contact),
    starts on his old port: Alice's dial stops after Noise message 2, and
    her send ends within 2 s, queued with the 'something else answered'
    text (send_s). X stops, Bob restarts on his old port and sends to Alice:
    her queued message reaches him exactly once, with no explicit retry
    (delivered_after_s: Bob's inbound link clears the scoped block)."""
    a, b = pair(root)
    warm = a.send('bob', 's90p-warmup')
    pinned = b.pub in noise_pins_text(a.dir)
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    x = Node('x', root)
    x.init()
    x.start(port=port)
    rc, out, send_s = a.send('bob', 's90p-m1')
    x.stop()
    b.start(port=port)
    back = b.send('alice', 's90p-bob-back')
    took = wait_inbox(b, 's90p-m1', 60)
    time.sleep(2)
    once = count(b.inbox(), 's90p-m1') == 1
    return dict(
        ok=warm[0] == 0 and pinned and status_word(out) == 'QUEUED'
        and "something else answered at Bob's address" in out
        and 'so RAVEN stopped before telling it who you are' in out
        and send_s <= 2 and b.dial.endswith(f':{port}') and back[0] == 0
        and took is not None and once,
        pinned=pinned, send=(rc, status_word(out), round(send_s, 2)), send_text=out[-600:],
        bob_back=(back[0], status_word(back[1])), delivered_after_s=took, exactly_once=once,
        outbox=a.outbox()[-400:])


# A deadline as the CLI words it on this computer's clock (cutoff pack CP.6):
# 'today 14:05 (in about 3 h)', 'tomorrow 09:10 (...)', 'Tue 14:05 (...)',
# 'Thu 23 Oct 14:05', or 'in about 22 h' when the local offset is unknown.
def local_zone_label() -> str:
    """This computer's zone as Raven labels a clock time (E2 r38): `UTC`,
    `UTC+1`, `UTC-5`, `UTC+5:30`."""
    off = time.localtime().tm_gmtoff
    if off == 0:
        return 'UTC'
    sign = '-' if off < 0 else '+'
    h, m = abs(off) // 3600, abs(off) % 3600 // 60
    return f'UTC{sign}{h}' if m == 0 else f'UTC{sign}{h}:{m:02}'


def only_local_zone(text: str) -> bool:
    """Every time `text` names is on this computer's clock (CP.6: never a
    time on another clock; E2 r38: a clock time names this computer's zone,
    `(UTC+1)`): no zone label but this computer's own, and no ISO UTC
    stamp."""
    labels = re.findall(r'\(UTC(?:[+-]\d{1,2}(?::\d{2})?)?\b', text)
    stamps = re.search(r'\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d)?Z', text)
    return not stamps and all(l[1:] == local_zone_label() for l in labels)


LOCAL_DEADLINE = re.compile(
    r'until ((today|tomorrow|Mon|Tue|Wed|Thu|Fri|Sat|Sun) (\d{1,2} [A-Z][a-z]{2} )?'
    r'\d\d:\d\d|in (about \d+ (min|h|days)|less than a minute))')


def has_ipv6_route() -> bool:
    """A UDP connect to a documentation address (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(('2001:db8::1', 9))
            return True
    except OSError:
        return False


def lan_seen_ip(node: Node, other: Node) -> str | None:
    """The source IP `node`'s lan_seen.json holds for `other`."""
    entry = lan_seen_entry(node, other)
    return None if entry is None else entry.get('ip')


def lan_seen_entry(node: Node, other: Node) -> dict | None:
    """`node`'s lan_seen.json entry for `other` (its IP and when: an inbound
    link from `other` an hour or more after it rewrites the time)."""
    try:
        raw = sealed_plain(node.dir, 'lan_seen.json')
        seen = json.loads(raw) if raw is not None else []
    except (OSError, ValueError):
        return None
    return next((e for e in seen if isinstance(e, dict)
                 and e.get('pub_hex', '').lower() == other.pub.lower()), None)


def s90_stale_address_inbound_learns(root: Path) -> dict:
    """Cutoff M2 and the inbound sighting (release behaviour, no switch).
    Alice and Bob are verified and share a session; then Alice's saved
    address for Bob becomes a black hole (192.0.2.10 on his real port) and,
    where this computer has no IPv6 route, also an address with no route
    ([2001:db8::10] on that port). Her sends are queued within 7 s (black
    hole) / 1 s (no route): the text starts 'not delivered yet', says he may
    be 'on another network, or have a new IP address', names a deadline on
    this computer's clock (never UTC). Bob stays up and silent for 45 s:
    nothing is delivered. Then Bob sends to Alice: her raven-node records
    where he came from (lan_seen.json) and delivers each queued message
    exactly once within 10 s of his link. Route hints stay off for both
    (ENV_NO_HINTS), also under RAVEN_FAULT_HINTS=1: with them Bob's RRH1
    names his real port, and the silent part would deliver at once. So does
    the LAN beacon, which RAVEN_FAULT_BEACON=1 leaves off here
    (without_beacon: Alice's beacon would find Bob's real port)."""
    env = without_beacon(ENV_NO_HINTS)
    a, b = Node('a', root, env), Node('b', root, env)
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = a.send('bob', 's90-warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    a.set_lan('bob', f'192.0.2.10:{port}')
    t_first = time.time()
    rc, out, send_s = a.send('bob', 's90-m1')
    sends = {'black_hole': (rc, status_word(out), round(send_s, 1))}
    texts = {'black_hole': out}
    tokens = ['s90-m1']
    v6 = not has_ipv6_route()
    if v6:
        a.set_lan('bob', f'[2001:db8::10]:{port}')
        rc6, out6, send6_s = a.send('bob', 's90-m2')
        sends['no_route'] = (rc6, status_word(out6), round(send6_s, 1))
        texts['no_route'] = out6
        tokens.append('s90-m2')
    limits = {'black_hole': 7, 'no_route': 1}
    # The outcome line (a progress line about the dial may come first).
    lines = {k: next((l.strip() for l in t.splitlines()
                      if l.strip().startswith('not delivered yet')), '')
             for k, t in texts.items()}
    worded = {
        k: 'on another network, or have a new IP address' in line
        and bool(LOCAL_DEADLINE.search(line)) and only_local_zone(texts[k])
        for k, line in lines.items()}
    time.sleep(max(0.0, 45 - (time.time() - t_first)))
    silent = {t: count(b.inbox(), t) for t in tokens}
    t_link = time.time()
    back = b.send('alice', 's90-bob-hello')
    took: dict = {t: None for t in tokens}
    while time.time() - t_link < 12 and None in took.values():
        inbox = b.inbox()
        for t in tokens:
            if took[t] is None and count(inbox, t):
                took[t] = round(time.time() - t_link, 1)
        time.sleep(0.5)
    time.sleep(2)
    once = {t: count(b.inbox(), t) for t in tokens}
    seen = lan_seen_ip(a, b)
    return dict(
        ok=warm[0] == 0 and all(w[1] == 'QUEUED' and w[2] <= limits[k] for k, w in sends.items())
        and all(worded.values()) and not any(silent.values()) and back[0] == 0
        and all(v is not None and v <= 10 for v in took.values())
        and all(n == 1 for n in once.values()) and seen == '127.0.0.1',
        sends=sends, worded=worded, ipv6_case=v6, delivered_while_silent=silent,
        bob_back=(back[0], status_word(back[1])), delivered_after_link_s=took,
        exactly_once=once, lan_seen_ip=seen,
        send_text={k: line[:700] for k, line in lines.items()}, outbox=a.outbox()[-400:])


def s91_access_point_waits(root: Path) -> dict:
    """Cutoff F5 (CP.12; release behaviour, no switch: today's wait). Bob
    is away 150 s and comes back on the same address, silent, like a phone
    that left a laptop's hotspot and rejoined it: the host's own addresses
    never changed, so only Alice's backoff retries. Records Alice's `next
    try` text just before his return (next_try_before_return) and how long
    delivery took after it (delivered_after_s), exactly once. Delivery
    comes at that next try (bound: it plus 10 s). The study's bound of 170 s
    is recorded (within_170_s), not required: after 150 s away the backoff
    step is 80-240 s, so about one run in eight waits longer. F5 cannot
    shorten this while Bob is Alice's only contact (s91b needs another
    contact's link); that case needs the Phase 3 beacon (P3.C5).

    With RAVEN_FAULT_BEACON=1 (P3.C5; both on the scenario's lab bus) it
    records the beacon's part too: Alice's beacon counts just before his
    return and both nodes' after the delivery (Bob answered Alice's
    query: answers_sent_10m), and whether the delivery came within 15 s
    of his return (within_15_s). The bound stays Alice's next try: a
    query names Bob only when one of Alice's sources wants him (her
    outbox, in an attempt), and Bob, with nothing waiting, sends no join
    round when he comes back (owner decision OD-C7), so the beacon finds
    him at her next attempt, not before."""
    a, b = pair(root)
    warm = a.send('bob', 's91-warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    t_away = time.time()
    rc, out, send_s = a.send('bob', 's91-m1')
    m = re.search(r'mid=([0-9a-f]{8})', out)
    time.sleep(max(0.0, 150 - (time.time() - t_away)))
    st = a.ash('outbox', 'status', m.group(1)).stdout if m else ''
    next_try = outbox_field(st, 'next try')
    attempts = int(outbox_field(st, 'attempts') or 0)
    away_s = round(time.time() - t_away, 1)
    a_before = beacon_counts(a) if BEACON else {}
    b.start(port=port)
    took = wait_inbox(b, 's91-m1', 255)
    time.sleep(2)
    once = count(b.inbox(), 's91-m1')
    bound = None if next_try_s(next_try) is None else next_try_s(next_try) + 10
    beacon = {}
    if BEACON:
        a_after, b_after = beacon_counts(a), beacon_counts(b)
        beacon = dict(alice_before_return=a_before, alice_after=a_after, bob_after=b_after,
                      bob_answered=int(b_after.get('answers_sent_10m') or 0) >= 1,
                      within_15_s=took is not None and took <= 15)
    return dict(
        ok=warm[0] == 0 and status_word(out) == 'QUEUED' and m is not None
        and bound is not None and took is not None and took <= bound and once == 1,
        send=(rc, status_word(out), round(send_s, 1)), away_s=away_s,
        next_try_before_return=next_try, attempts_before_return=attempts,
        delivered_after_s=None if took is None else round(took, 1),
        within_170_s=took is not None and took <= 170, exactly_once=once,
        outbox=a.outbox()[-400:], **({'beacon': beacon} if BEACON else {}))


SIBLING_WOKE = 'raven-node outbox: a contact answered on this network; retrying 1 others'


def s91b_sibling_link_wakes_the_queue(root: Path) -> dict:
    """Cutoff F5 (CP.12; RAVEN_FAULT_OFFLINE=1). s91 with a third node,
    Carol: Alice, Bob and Carol link once at the start, so Alice holds both
    noise pins. Bob is away about 150 s (longer if Alice's next try is
    under 30 s off, so her backoff cannot be what delivers) and comes back
    silent on his address; then Carol links to Alice (she sends): Bob's
    message is delivered within 15 s of that link (delivered_after_link_s;
    next_try_before_link is what Alice's backoff alone would have waited)
    and Alice logs 'a contact answered on this network; retrying 1 others'.
    Each message exactly once."""
    a, b = pair(root)
    c = Node('c', root)
    c.init()
    c.start()
    a.add(c, 'carol')
    c.add(a, 'alice')
    warm = [a.send('bob', 's91b-warmup')[0], a.send('carol', 's91b-warmup-c')[0]]
    pins = noise_pins_text(a.dir)
    pinned = b.pub in pins and c.pub in pins
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    t_away = time.time()
    rc, out, send_s = a.send('bob', 's91b-m1')
    m = re.search(r'mid=([0-9a-f]{8})', out)
    mid = m.group(1) if m else ''
    time.sleep(max(0.0, 150 - (time.time() - t_away)))
    t_wait = time.time()
    while mid and time.time() - t_wait < 90:
        st = a.ash('outbox', 'status', mid).stdout
        if (next_try_s(outbox_field(st, 'next try')) or 0) >= 30:
            break
        time.sleep(0.5)
    away_s = round(time.time() - t_away, 1)
    b.start(port=port)
    next_try = outbox_field(a.ash('outbox', 'status', mid).stdout, 'next try') if mid else None
    early = count(b.inbox(), 's91b-m1')
    since = log_size(a)
    t_link = time.time()
    back = c.send('alice', 's91b-carol-hello')
    took = None
    while time.time() - t_link < 60 and took is None:
        if count(b.inbox(), 's91b-m1'):
            took = round(time.time() - t_link, 1)
        time.sleep(0.5)
    time.sleep(2)
    woke = a.log_path.read_text(errors='replace')[since:].count(SIBLING_WOKE)
    once = {'s91b-m1': count(b.inbox(), 's91b-m1'),
            's91b-carol-hello': count(a.inbox(), 's91b-carol-hello')}
    return dict(
        ok=warm == [0, 0] and pinned and status_word(out) == 'QUEUED' and m is not None
        and (next_try_s(next_try) or 0) >= 15 and early == 0 and back[0] == 0
        and took is not None and took <= 15 and woke == 1
        and once == {'s91b-m1': 1, 's91b-carol-hello': 1},
        warmups=warm, pinned=pinned, send=(rc, status_word(out), round(send_s, 1)),
        away_s=away_s, next_try_before_link=next_try, delivered_before_link=early,
        carol_link=(back[0], status_word(back[1]), round(back[2], 1)),
        delivered_after_link_s=took, woke_lines=woke, exactly_once=once,
        outbox=a.outbox()[-400:])


def s92_name_route_while_away(root: Path) -> dict:
    """Cutoff F1 (CP.9; RAVEN_FAULT_OFFLINE=1). Alice and Bob link once (a
    session), then Alice's saved route for Bob becomes a computer name that
    resolves nowhere (x-nohost.local on his port): Bob is away. One send with
    the gate closed (RAVEN_LAB_OFFLINE=0 for that ash only) records today's
    NOT SENT ... CONTACT_NOT_VERIFIED. Gate open: (a) Bob unverified, the send
    is QUEUED within 6 s saying his computer name x-nohost.local could not be
    found, and raven-node holds it as NOT_REACHABLE (never
    CONTACT_NOT_VERIFIED); (b) Bob verified (pinned), QUEUED with the same
    cause, never 'could not be completed'. Then `contact set-addr` back to
    his literal address: both messages arrive exactly once with no new send
    (delivered_after_s); the gate-closed one never does. No LAN beacon under
    RAVEN_FAULT_BEACON=1 (without_beacon): Bob's node keeps running, and the
    beacon would find it past the name."""
    a, b = pair(root, env=without_beacon(ENV))
    warm = a.send('bob', 's92-warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    name = f'x-nohost.local:{port}'
    not_found = ("Bob's computer name x-nohost.local could not be found on this network "
                 '(Bob may be away, or on another network)')
    a.set_lan('bob', name)
    gate_open = a.env
    a.env = dict(gate_open, RAVEN_LAB_OFFLINE='0')
    rc0, out0, send0_s = a.send('bob', 's92-closed')
    a.env = gate_open
    rc1, out1, send1_s = a.send('bob', 's92-m1')
    # raven-node's first attempts (each waits for the name, up to 5 s).
    mid1, last1 = item_id(a, 's92-m1'), None
    t0 = time.time()
    while mid1 and last1 is None and time.time() - t0 < 30:
        last1 = outbox_field(a.ash('outbox', 'status', mid1).stdout, 'last error')
        time.sleep(1)
    a.add_pinned(b, 'bob', name)
    rc2, out2, send2_s = a.send('bob', 's92-m2')
    a.set_lan('bob', b.dial)
    tokens = ('s92-m1', 's92-m2')
    took: dict = {t: None for t in tokens}
    t_fix = time.time()
    while time.time() - t_fix < 150 and None in took.values():
        inbox = b.inbox()
        for t in tokens:
            if took[t] is None and count(inbox, t):
                took[t] = round(time.time() - t_fix, 1)
        time.sleep(1)
    time.sleep(2)
    inbox = b.inbox()
    once = {t: count(inbox, t) for t in tokens + ('s92-closed',)}
    return dict(
        ok=warm[0] == 0 and status_word(out0) == 'NOT_SENT' and 'CONTACT_NOT_VERIFIED' in out0
        and f'{name} could not be resolved' in out0
        and status_word(out1) == 'QUEUED' and send1_s <= 6 and not_found in out1
        and 'CONTACT_NOT_VERIFIED' not in out1 and last1 == 'NOT_REACHABLE'
        and status_word(out2) == 'QUEUED' and not_found in out2
        and 'could not be completed' not in out2
        and all(v is not None for v in took.values())
        and once == {'s92-m1': 1, 's92-m2': 1, 's92-closed': 0},
        warmup=(warm[0], status_word(warm[1])),
        gate_closed=(rc0, status_word(out0), round(send0_s, 1)), gate_closed_text=out0[-500:],
        unverified=(rc1, status_word(out1), round(send1_s, 1)), unverified_text=out1[-500:],
        unverified_last_error=last1,
        verified=(rc2, status_word(out2), round(send2_s, 1)), verified_text=out2[-500:],
        delivered_after_s=took, exactly_once=once, outbox=a.outbox()[-400:])


def s93_first_message_unreachable(root: Path) -> dict:
    """Cutoff M2 (release behaviour, no switch): a first message to a
    contact with no session, at an address where nothing listens, is NOT
    SENT within 6 s with the first-message rule `raven contact list` says
    too ('a first message needs you and Bob both online'; E1), and nothing
    waits in the outbox. Alice and Bob run with the horizon held
    (without_horizon), as a release build holds it. With the
    horizon on (RAVEN_FAULT_HORIZON=1 or RAVEN_FAULT_LETTER=1; Phase 5 P5.8)
    Carol sends the same first message and it is parked instead: QUEUED
    with HORIZON_PARKED within 6 s, waiting in her outbox."""
    held = without_horizon(ENV)
    a, b = Node('a', root, held), Node('b', root, held)
    a.init(); b.init()
    a.start()
    a.add(b, 'bob', f'127.0.0.1:{free_tcp_port()}')
    rc, out, send_s = a.send('bob', 's93-m1')
    outbox = a.outbox()
    res = dict(
        ok=rc != 0 and status_word(out) == 'NOT_SENT' and send_s <= 6
        and 'It was not kept: a first message needs you and Bob both online' in out
        and 'secure connection with Bob ended' not in out
        and outbox.startswith('Nothing waiting') and 'queued' not in outbox,
        send=(rc, status_word(out), round(send_s, 1)), send_text=out[-600:], outbox=outbox[-300:])
    if ENV.get('RAVEN_LAB_HORIZON') == '1':
        c = Node('c', root)
        c.init()
        c.start()
        c.add(b, 'bob', f'127.0.0.1:{free_tcp_port()}')
        rc2, out2, send2_s = c.send('bob', 's93-m2')
        outbox2 = c.outbox()
        res.update(
            ok=res['ok'] and status_word(out2) == 'QUEUED' and send2_s <= 6
            and 'HORIZON_PARKED' in out2 and 'Nothing was queued' not in out2
            and 'waiting' in outbox2 and 's93-m2' in outbox2,
            horizon_send=(rc2, status_word(out2), round(send2_s, 1)),
            horizon_text=out2[-600:], horizon_outbox=outbox2[-300:])
    return res


def s93b_session_ended_says_meet_first(root: Path) -> dict:
    """Cutoff M2 (RAVEN_FAULT_OFFLINE=1; LabClock, so both profiles run with
    the lab unlock). Alice and Bob pair (a message delivered), Bob goes
    down, and Alice's clock moves 25 h ahead: their session (a day from its
    PairInit) has ended. Her raven-node restarts, which prunes the expired
    session; her next send is NOT SENT and says the secure connection with
    Bob ended (never 'a first message needs'), and nothing waits in her
    outbox or is marked queued. One wake from sleep per jump."""
    clock = LabClock(root / 'alice.clock')
    a = Node('a', root, env=clock.env(ENV))
    b = Node('b', root, env=dict(ENV, RAVEN_LAB_TEST_A='1'))
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = a.send('bob', 's93b-warmup')
    b.stop()
    since = log_size(a)
    clock.advance(25 * 3600 * 1000)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    a.stop()
    a.start()
    rc, out, send_s = a.send('bob', 's93b-m1')
    outbox = a.outbox()
    return dict(
        ok=warm[0] == 0 and status_word(warm[1]) == 'DELIVERED' and rc != 0
        and status_word(out) == 'NOT_SENT'
        and "RAVEN's secure connection with Bob ended" in out
        and 'Send it when you meet.' in out
        and 'a first message needs' not in out and only_local_zone(out)
        and 'queued' not in outbox and 's93b-m1' not in outbox and woke is not None,
        warmup=(warm[0], status_word(warm[1])), woke_s=woke,
        send=(rc, status_word(out), round(send_s, 1)), send_text=out[-700:],
        outbox=outbox[-300:])


# The clock sentences of cutoff pack CP.7 (ash ext.rs, cli.rs).
CLOCK_AHEAD = ("Bob's clock is about 10 min ahead of yours: messages from Bob are refused until "
               "the clocks agree. Check the time and time zone on both laptops.")
CLOCKS_DIFFER = ("Bob's clock and yours differ by about 10 min, so RAVEN can't set up a secure "
                 "connection. Check the time and time zone on both laptops.")
# Only the confirmation was refused (the message went out): review
# C-time-deadlines-6.
ACKS_REFUSED = ("Bob's clock and yours differ by about 10 min, so Bob's confirmations are refused "
                "here; Bob may have the message. Check the time and time zone on both laptops.")
SAME_TIME_HINT = ('If this keeps happening while you are together, check that both laptops show '
                  'the same time.')


def item_id(node: Node, text: str) -> str | None:
    """The outbox id of the waiting message whose preview holds `text`."""
    return next((i['id'] for i in outbox_items(node) if text in i['what']), None)


def wait_state(node: Node, mid: str | None, state: str, secs: float) -> float | None:
    """Seconds until `ash outbox status mid` says `state` (a finished
    message too: its history keeps the state)."""
    t0 = time.time()
    while mid and time.time() - t0 < secs:
        if outbox_field(node.ash('outbox', 'status', mid).stdout, 'state') == state:
            return time.time() - t0
        time.sleep(1)
    return None


def s99_clock_skew(root: Path) -> dict:
    """Cutoff F10 / M11 (CP.7; RAVEN_FAULT_OFFLINE=1). Both profiles run on
    a LabClock (so both have the lab unlock); only Bob's moves. Bob 4 min
    ahead: delivered and acknowledged both ways. Bob 10 min ahead: Alice's
    message reaches Bob exactly once (it is in his past), but she refuses
    his ACK (the same five-minute window), so her send stays 'sent, delivery
    unconfirmed' and says Bob's confirmations are refused because of the
    clocks (he may have it); Bob's message is refused by Alice's
    node, which then shows 'Bob's clock is about 10 min ahead of yours' in
    `raven status` (doctor counts it). Bob's first send is queued; once his
    node has had no answer twice, his next send carries the same-time hint.
    Then Bob sets his clock right and six minutes pass, which both clocks
    show 6 min ahead of the system clock (Bob back from +10, Alice's one
    wake from sleep): what Bob sealed while ahead was in the future of
    Alice and of his own store (which held it, `last error CLOCK`) and is in
    time now. Alice's wake retry brings back Bob's owed ACK, which delivers
    her message; Bob's queued message reaches her exactly once and her ACK
    delivers it; neither `raven status` has a clocks row any more."""
    minute = 60_000
    a_clock = LabClock(root / 'alice.clock')
    b_clock = LabClock(root / 'bob.clock', 4 * minute)
    a = Node('a', root, env=a_clock.env(ENV))
    b = Node('b', root, env=b_clock.env(ENV))
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    # Bob 4 min ahead: inside the window both ways.
    a4 = a.send('bob', 's99-a4')
    b4 = b.send('alice', 's99-b4')
    b_since = log_size(b)
    b_clock.set(10 * minute)
    b_woke = wait_log(b, LabClock.WOKE, 15, b_since)
    # Alice -> Bob: Bob holds it once; his ACK is 10 min in her future.
    rc, a10, _ = a.send('bob', 's99-a10')
    held = wait_inbox(b, 's99-a10', 15)
    # Bob -> Alice: refused by her node (in her future).
    _, b10, _ = b.send('alice', 's99-b10-1')
    a_status = a.ash('status').stdout
    a_doctor = a.ash('doctor').stdout
    clocks_row = status_row(a_status, 'clocks') or ''
    # Bob's next send: his node has had no answer twice by now.
    _, b10b, _ = b.send('alice', 's99-b10-2')
    refused = count(a.inbox(), 's99-b10-1')
    a10_id = item_id(a, 's99-a10')
    a10_state = outbox_field(a.ash('outbox', 'status', a10_id).stdout, 'state') if a10_id else None
    b10_id = item_id(b, 's99-b10-1')
    # Bob sets his clock right and 6 minutes pass: both clocks agree, 6 min
    # past the system clock (only the difference counts). What Bob sealed
    # while ahead is in time again for Alice and for his own store, which
    # held it meanwhile (`last error CLOCK`). Alice's jump is a wake: it
    # retries her message, whose owed ACK Bob sends back.
    b_clock.set(6 * minute)
    a_since = log_size(a)
    a_clock.set(6 * minute)
    a_woke = wait_log(a, LabClock.WOKE, 15, a_since)
    acked_a = wait_state(a, a10_id, 'delivered', 30)
    got_b = wait_inbox(a, 's99-b10-1', 60)
    acked_b = wait_state(b, b10_id, 'delivered', 30)
    time.sleep(2)
    once = {t: count(n.inbox(), t) for n, t in ((b, 's99-a10'), (a, 's99-b10-1'))}
    after_rows = [status_row(n.ash('status').stdout, 'clocks') for n in (a, b)]
    return dict(
        ok=status_word(a4[1]) == 'DELIVERED' and status_word(b4[1]) == 'DELIVERED'
        and b_woke is not None and held is not None
        and status_word(a10) == 'UNCONFIRMED' and ACKS_REFUSED in a10
        and CLOCKS_DIFFER not in a10
        and a10_state not in (None, 'delivered')
        and status_word(b10) == 'QUEUED' and refused == 0
        and clocks_row == CLOCK_AHEAD and 'clock_skew_contacts: 1' in a_doctor
        and SAME_TIME_HINT in b10b and CLOCKS_DIFFER not in b10b
        and a_woke is not None and acked_a is not None and got_b is not None
        and acked_b is not None and all(n == 1 for n in once.values())
        and after_rows == [None, None],
        plus4=(status_word(a4[1]), status_word(b4[1])), bob_woke_s=b_woke,
        a10=(rc, status_word(a10)), a10_text=a10[-700:], a10_state=a10_state,
        bob_held_a10_s=held, b10=status_word(b10), b10_text=b10[-500:],
        clocks_row=clocks_row, doctor_count='clock_skew_contacts: 1' in a_doctor,
        b10_2=status_word(b10b), b10_2_text=b10b[-500:], alice_woke_s=a_woke,
        a10_acked_after_reset_s=acked_a, b10_delivered_after_reset_s=got_b,
        b10_acked_after_reset_s=acked_b, exactly_once=once, clocks_rows_after=after_rows)


# The netwatch line of a change to IPv4 link-local networks alone (cutoff
# pack CP.10, F6).
CABLE_LINE = 'raven-node netwatch: link-local network only (a cable?)'


def cable_round(root: Path, tag: str, gate: str) -> dict:
    """One s98 round on fresh nodes; Alice's raven-node and ash run with
    RAVEN_LAB_OFFLINE=`gate`."""
    net = root / f'a-{tag}-net.txt'
    net.write_text('up 192.0.2.10/24\n')
    # No LAN beacon (without_beacon): the lab bus does not die with the proxy.
    base = without_beacon(ENV)
    env = dict(base, RAVEN_LAB_NETWATCH_EVENTS=str(net), RAVEN_LAB_OFFLINE=gate)
    a, b = Node(f'a-{tag}', root, env), Node(f'b-{tag}', root, base)
    a.init(); b.init()
    a.start(); b.start()
    pb = Proxy(b.dial)
    a.add(b, 'bob', pb.addr)
    b.add(a, 'alice')
    baseline = wait_log(a, 'raven-node netwatch: watching (1 network)', 30)
    warm = status_word(a.send('bob', f's98-{tag}-warmup')[1])
    pb.mode = 'refuse'
    pb.kill_live()
    text = f's98-{tag}'
    rc, out, _ = a.send('bob', text)
    m = re.search(r'mid=([0-9a-f]{8})', out)
    mark = log_size(a)
    with open(net, 'a') as f:
        f.write('down 192.0.2.10/24\n')
    offline = wait_log(a, 'raven-node netwatch: no network; waiting for one', 15, mark)
    # Long enough that delivery on the backoff alone is told apart.
    backed_off = wait_attempts(a, m.group(1), 4, 150, next_s=15) if m else None
    pb.mode = 'pass'
    mark = log_size(a)
    with open(net, 'a') as f:
        f.write('up 169.254.10.2/16\n')
    t_up = time.time()
    noticed = got = None
    while got is None and time.time() - t_up < 150:
        if noticed is None and CABLE_LINE in a.log_path.read_text(errors='replace')[mark:]:
            noticed = round(time.time() - t_up, 1)
        if count(b.inbox(), text):
            got = round(time.time() - t_up, 1)
        time.sleep(0.25)
    time.sleep(2)
    lines = [l for l in a.log_path.read_text(errors='replace')[mark:].splitlines()
             if 'raven-node netwatch:' in l]
    once, outbox = count(b.inbox(), text), a.outbox()[-300:]
    # The next round runs on fresh nodes: these go now.
    a.stop()
    b.stop()
    return dict(
        baseline_s=baseline, warm=warm, send=(rc, status_word(out)),
        offline_s=None if offline is None else round(offline, 1), backed_off=backed_off,
        noticed_s=noticed, delivered_after_up_s=got,
        delivered_after_line_s=None if got is None or noticed is None
        else round(got - noticed, 1),
        cable_lines=sum(CABLE_LINE in l for l in lines),
        changed_lines=sum('raven-node netwatch: network changed' in l for l in lines),
        netwatch_after_up=lines[-3:], exactly_once=once, outbox=outbox)


def s98_cable_link_local(root: Path) -> dict:
    """Cutoff F6 (CP.10; RAVEN_FAULT_OFFLINE=1 and RAVEN_FAULT_NETWATCH=1).
    Alice reaches Bob through a proxy; her lab netwatch file starts on
    192.0.2.10/24. The proxy refuses every connection while her message to
    Bob waits; her network goes (`down` of every address: 'no network;
    waiting for one') and her backoff grows to 15 s or more; then the proxy
    passes again and the file says only `up 169.254.10.2/16` (a cable
    between two laptops with no DHCP server). Two rounds on fresh nodes.
    Gate closed for Alice (RAVEN_LAB_OFFLINE=0): nothing is noticed and the
    backoff alone delivers (closed delivered_after_up_s, recorded: 10 s or
    more). Open: one `link-local network only (a cable?)` line (no `network
    changed`) within 4 s of the up line, and delivery within 6 s of that
    line (the outbox's 5 s network spread, G1/G5, which F6 leaves as it
    is). Each message exactly once."""
    closed = cable_round(root, 'closed', '0')
    opened = cable_round(root, 'open', '1')

    def common(r: dict) -> bool:
        return (r['baseline_s'] is not None and r['warm'] == 'DELIVERED'
                and r['send'][1] == 'QUEUED' and r['offline_s'] is not None
                and ((r['backed_off'] or {}).get('next_try_s') or 0) >= 15
                and r['delivered_after_up_s'] is not None and r['exactly_once'] == 1
                and r['changed_lines'] == 0)

    return dict(
        ok=common(closed) and common(opened)
        and closed['cable_lines'] == 0 and closed['noticed_s'] is None
        and closed['delivered_after_up_s'] >= 10
        and opened['cable_lines'] == 1 and opened['noticed_s'] is not None
        and opened['noticed_s'] <= 4 and opened['delivered_after_line_s'] <= 6,
        gate_closed=closed, gate_open=opened)


# ------------------------- cutoff F8: a custodian that moved (CP.14)
# RAVEN_FAULT_CUSTODY=1 (and RAVEN_FAULT_HINTS=1 for F8 itself): friend
# custody's timers as s30, M0 on every node (RAVEN_LAB_NOISE_PIN=1: the
# first links record the noise pins the held-recipient announce needs) and a
# free default LAN port, so no node ever guesses 7420.
def walk_env(hints: bool) -> dict:
    """s96/s97's node environment, route hints on or off."""
    env = dict(CUSTODY_ENV, RAVEN_LAB_NOISE_PIN='1',
               RAVEN_LAB_LAN_DEFAULT_PORT=str(free_tcp_port()))
    if hints:
        env['RAVEN_LAB_ROUTE_HINTS'] = '1'
    else:
        env.pop('RAVEN_LAB_ROUTE_HINTS', None)
    return env


# A custody fetch that brought an ACK (raven-node custody.rs).
ACK_VIA_CUSTODIAN = re.compile(r'custody: fetched messages=\d+ acks=[1-9]')


def custody_rows(node: Node) -> list | None:
    """The node's friend custody rows as (recipient pub hex, released,
    expires_at_ms), read-only from its store (None while it cannot be
    read; [] without a store). A sealed profile's store (privacy pack
    PP.17, schema 2) keys the recipient and keeps the clear values in each
    row's sealed meta, opened here with the profile's epoch keys. A RELEASE
    deletes the row there and in this build's clear store (only the digest
    stays, custody_released_v1), so a released row is one an older build
    kept."""
    import sqlite3
    path = node.dir / 'friend_custody.sqlite'
    if not path.exists():
        return []
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=10)
        try:
            cols = [r[1] for r in con.execute('PRAGMA table_info(custody_objects_v1)')]
            if 'kh_object_digest' in cols:
                sealed = con.execute('SELECT kh_object_digest, meta FROM custody_objects_v1').fetchall()
            else:
                sealed = None
                rows = con.execute('SELECT lower(hex(recipient)), released_at_ms IS NOT NULL, '
                                   'expires_at_ms FROM custody_objects_v1').fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return None
    if sealed is None:
        return [(r, bool(rel), int(exp)) for r, rel, exp in rows]
    try:
        keys = profile_epoch_keys(node.dir)
        out = []
        for kd, meta in sealed:
            m = json.loads(open_row(bytes(meta), keys, 'custody_objects_v1', bytes(kd)))
            out.append((m['recipient'].lower(), False, int(m['expires_at_ms'])))
    except (OSError, ValueError, KeyError):
        return None
    return out


def custody_objects(node: Node) -> list | None:
    """A sealed profile's custody objects (PP.17) as (kh_object_digest, the
    payload as stored, the RSO1 opened with the profile's epoch keys,
    recipient pub hex); None while the store cannot be read or is not
    keyed."""
    import sqlite3
    path = node.dir / 'friend_custody.sqlite'
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=10)
        try:
            rows = con.execute('SELECT kh_object_digest, rso1, meta FROM custody_objects_v1').fetchall()
        finally:
            con.close()
        keys = profile_epoch_keys(node.dir)
        out = []
        for kd, rso1, meta in rows:
            kd, rso1 = bytes(kd), bytes(rso1)
            m = json.loads(open_row(bytes(meta), keys, 'custody_objects_v1', kd))
            plain = open_row(rso1, keys, 'custody_objects_v1.rso1', kd)
            out.append((kd, rso1, plain, m['recipient'].lower()))
        return out
    except (sqlite3.Error, OSError, ValueError, KeyError):
        return None


def custody_released(node: Node) -> list | None:
    """The released digests a custodian keeps (custody_released_v1: the
    column names, then the rows); None while it cannot be read."""
    import sqlite3
    path = node.dir / 'friend_custody.sqlite'
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=10)
        try:
            cols = [r[1] for r in con.execute('PRAGMA table_info(custody_released_v1)')]
            rows = con.execute('SELECT * FROM custody_released_v1').fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return None
    return [cols] + [tuple(bytes(v) if isinstance(v, (bytes, memoryview)) else v for v in r)
                     for r in rows]


def key_needles(pub_hex: str) -> list:
    """A friend's key as a file may hold it: raw, hex in either case, base64."""
    import base64
    raw = bytes.fromhex(pub_hex)
    return [raw, pub_hex.lower().encode(), pub_hex.upper().encode(),
            base64.b64encode(raw), base64.b64encode(raw).rstrip(b'='),
            base64.urlsafe_b64encode(raw).rstrip(b'=')]


def files_holding(profile: Path, needles: list) -> list:
    """Every file below `profile` whose raw bytes or name hold one of
    `needles` (carrier_matrix C87's rule: the lab key backends' files stand
    in for the keystore, debug builds only, and are left out)."""
    hits = []
    for path in sorted(profile.rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(profile).as_posix()
        if (name.startswith(('indexed-session-secrets/', 'prekey-lifecycle-secrets/'))
                or name == 'prekey_lifecycle.protected'):
            continue
        data = path.read_bytes()
        if any(needle in data or needle in name.encode() for needle in needles):
            hits.append(name)
    return hits


def held_for(node: Node, other: Node, now_ms: float | None = None) -> int | None:
    """Unreleased, unexpired custody rows `node` holds for `other`."""
    rows = custody_rows(node)
    if rows is None:
        return None
    now_ms = time.time() * 1000 if now_ms is None else now_ms
    return sum(1 for r, rel, exp in rows if r == other.pub.lower() and not rel and exp > now_ms)


def wait_for(pred, secs: float) -> float | None:
    """Seconds until `pred()` is true, or None at the deadline."""
    t0 = time.time()
    while time.time() - t0 < secs:
        if pred():
            return round(time.time() - t0, 1)
        time.sleep(0.5)
    return None


def learned_from(node: Node, other: Node) -> bool:
    """`node` holds an RRH1 snapshot from `other` (learned_routes.json)."""
    try:
        entries = learned_rows(node)
    except (OSError, ValueError):
        return False
    return any(e.get('pub_hex', '').lower() == other.pub.lower() for e in entries)


def port_of(node: Node) -> int:
    return int(node.dial.rsplit(':', 1)[1])


def new_port(*not_these: int) -> int:
    """A free loopback port none of `not_these`."""
    while True:
        port = free_tcp_port()
        if port not in not_these:
            return port


def wait_settled(node: Node, n: int, secs: float) -> list:
    """The node's outbox items once `n` of them are delivered (or at the
    deadline)."""
    t0 = time.time()
    while True:
        items = outbox_items(node)
        if (sum(i['state'] == 'delivered' for i in items) >= n
                or time.time() - t0 >= secs):
            return items
        time.sleep(0.5)


def custody_trio(root: Path, setup_env: dict, env: dict) -> tuple:
    """Alice, Bob and Carol (s96, s97): each verifies the other two, Alice
    and Bob choose Carol as each other's custodian, and Carol turns custody
    on. They link once with route hints off (`setup_env`), so each pins the
    others' noise keys (M0) while no one holds an RRH1 from anyone (w2: Bob
    never told Carol his routes). Then every node is stopped and runs with
    `env` from its next start, on its own port. Returns the nodes and what
    the setup did."""
    a, b, c = (Node(n, root, setup_env) for n in ('a', 'b', 'c'))
    for n in (a, b, c):
        n.init()
        n.start()
    for x, y, tag in ((a, b, 'bob'), (a, c, 'carol'), (b, a, 'alice'), (b, c, 'carol'),
                      (c, a, 'alice'), (c, b, 'bob')):
        x.add_pinned(y, tag)
    on = c.ash('node', 'custody', 'on', '--yes')
    for x, tag in ((a, 'bob'), (b, 'alice')):
        r = x.ash('contact', 'set-addr', '--tag', tag, '--custodian', '@carol')
        assert r.returncode == 0, r.stdout + r.stderr
    warm = [a.send('bob', 'trio-ab')[0], a.send('carol', 'trio-ac')[0],
            b.send('carol', 'trio-bc')[0]]

    def pins(n: Node, *others: Node) -> bool:
        text = noise_pins_text(n.dir).lower()
        return all(o.pub.lower() in text for o in others)

    pinned = pins(a, b, c) and pins(b, a, c) and pins(c, a, b)
    for n in (a, b, c):
        n.stop()
        n.env = env
    hints_seen = [learned_from(x, y) for x in (a, b, c) for y in (a, b, c) if x is not y]
    return a, b, c, dict(ok=on.returncode == 0 and warm == [0, 0, 0] and pinned
                         and not any(hints_seen),
                         custody_on=on.returncode, warmups=warm, pinned=pinned,
                         rrh1_after_setup=sum(hints_seen))


def s96_custodian_walks(root: Path) -> dict:
    """Cutoff F8 (CP.14; RAVEN_FAULT_CUSTODY=1, w1/w2). Alice, Bob and
    Carol (custody_trio: pinned, never an RRH1 between them). Bob is away;
    Alice sends, and Carol holds the message; Alice leaves; Carol comes
    back on a new port; Bob returns on his old port. With RAVEN_FAULT_HINTS=1
    Carol's announce reaches Bob because she holds mail for him (he never
    sent her an RRH1): he learns her new port and fetches the message
    exactly once within 30 s of his return (fetched_after_return_s). He
    leaves his ACK with Carol and goes; Alice returns on her old port and
    the ACK reaches her through Carol (acked_after_return_s), and at the end
    Carol holds nothing unreleased. Without route hints today's failure is
    recorded, not required: Bob gets nothing in 120 s
    (fetched_within_120_s_today). With RAVEN_FAULT_BEACON=1 it is
    s96_with_the_beacon instead (P3.C5; route hints off)."""
    if BEACON:
        return s96_with_the_beacon(root)
    a, b, c, setup = custody_trio(root, walk_env(False), walk_env(HINTS))
    pa, pb, pc = port_of(a), port_of(b), port_of(c)
    a.start(port=pa)
    c.start(port=pc)
    rc, out, _ = a.send('bob', 's96-m1')
    held_s = wait_for(lambda: (held_for(c, b) or 0) >= 1, 60)
    b_told_c = learned_from(c, b)
    a.stop()
    c.stop()
    c.start(port=new_port(pa, pb, pc))
    b.start(port=pb)
    if not HINTS:
        got = wait_inbox(b, 's96-m1', 120)
        return dict(ok=setup['ok'] and status_word(out) == 'QUEUED' and held_s is not None,
                    setup=setup, send=(rc, status_word(out)), held_after_s=held_s,
                    fetched_within_120_s_today=got, today_fails=got is None)
    got = wait_inbox(b, 's96-m1', 30)
    # Bob released the message at Carol and left his ACK there for Alice.
    acked_at_c = wait_for(lambda: held_for(c, b) == 0 and (held_for(c, a) or 0) >= 1, 60)
    b_log = b.log_path.read_text(errors='replace')
    b.stop()
    since = log_size(a)
    a.start(port=pa)
    t_back = time.time()
    acked = wait_for(lambda: ACK_VIA_CUSTODIAN.search(
        a.log_path.read_text(errors='replace')[since:]) is not None, 150)
    emptied = wait_for(lambda: held_for(c, a) == 0 and held_for(c, b) == 0, 30)
    a_back_s = round(time.time() - t_back, 1)
    once = count(b.inbox(), 's96-m1')
    fetch_lines = [l for l in b_log.splitlines() if 'custody: fetched messages=' in l]
    return dict(
        ok=setup['ok'] and status_word(out) == 'QUEUED' and held_s is not None
        and not b_told_c and got is not None and got <= 30 and once == 1
        and acked_at_c is not None and acked is not None and emptied is not None,
        setup=setup, send=(rc, status_word(out)), held_after_s=held_s,
        bob_rrh1_at_carol_before=b_told_c, fetched_after_return_s=got, exactly_once=once,
        bob_fetch_lines=fetch_lines[-3:], ack_left_with_carol_s=acked_at_c,
        acked_after_return_s=acked, carol_empty_s=emptied, alice_back_s=a_back_s,
        carol_rows=custody_rows(c), a_outbox=a.outbox()[-400:])


def s96_with_the_beacon(root: Path) -> dict:
    """s96 under RAVEN_FAULT_BEACON=1 (P3.C5; RAVEN_FAULT_CUSTODY=1, route
    hints off, every node on the scenario's lab bus from its first start
    after custody_trio's links). Bob away; Alice's message is held by
    Carol; Alice leaves. Bob comes back on his old port, then Carol walks
    in on a new port: her start's join round names Bob, the one recipient
    she holds rows for (owner decision OD-C7: something waits), Bob
    answers it (his beacon's answers_sent_10m) and so has her new port,
    and he fetches the message exactly once within 30 s of her start
    (fetched_after_carol_s). No RRH1 anywhere and no address typed. He
    leaves his ACK with Carol and goes; Alice comes back on her old port,
    her custody fetch finds Carol through her own beacon and the ACK
    reaches her, and Carol ends with nothing unreleased. Variant (moved/,
    fresh trio): Bob also comes back on a new port; the same fetch."""
    main = s96_beacon_round(root, bob_moves=False)
    moved_root = root / 'moved'
    moved_root.mkdir()
    moved = s96_beacon_round(moved_root, bob_moves=True)
    return dict(main, ok=main['ok'] and moved['ok'], moved=moved)


def s96_beacon_round(root: Path, bob_moves: bool) -> dict:
    """One round of s96_with_the_beacon on a fresh trio under `root` (the
    ACK's way back only when Bob does not move: the variant checks the
    fetch)."""
    env, _ = beacon_env(root, walk_env(False))
    a, b, c, setup = custody_trio(root, walk_env(False), env)
    pa, pb, pc = port_of(a), port_of(b), port_of(c)
    a.start(port=pa)
    c.start(port=pc)
    rc, out, _ = a.send('bob', 's96-m1')
    held_s = wait_for(lambda: (held_for(c, b) or 0) >= 1, 60)
    a.stop()
    c.stop()
    b_port = new_port(pa, pb, pc) if bob_moves else pb
    b.start(port=b_port)
    # Bob's own search for Carol (his custody fetch) finds nothing yet.
    time.sleep(3)
    c.start(port=new_port(pa, pb, pc, b_port))
    got = wait_inbox(b, 's96-m1', 30)
    b_counts = beacon_counts(b)
    c_counts = beacon_counts(c)
    once = count(b.inbox(), 's96-m1')
    learned = [learned_from(x, y) for x in (b, c) for y in (b, c) if x is not y]
    res = dict(setup=setup, send=(rc, status_word(out)), held_after_s=held_s,
               bob_port=('new' if bob_moves else 'old'),
               fetched_after_carol_s=None if got is None else round(got, 1),
               exactly_once=once, bob_beacon=b_counts, carol_beacon=c_counts,
               rrh1_seen=sum(learned))
    ok = (setup['ok'] and status_word(out) == 'QUEUED' and held_s is not None
          and got is not None and got <= 30 and once == 1
          and int(b_counts.get('answers_sent_10m') or 0) >= 1 and not any(learned))
    if bob_moves:
        b.stop()
        c.stop()
        return dict(ok=ok, **res)
    acked_at_c = wait_for(lambda: held_for(c, b) == 0 and (held_for(c, a) or 0) >= 1, 60)
    b.stop()
    since = log_size(a)
    a.start(port=pa)
    acked = wait_for(lambda: ACK_VIA_CUSTODIAN.search(
        a.log_path.read_text(errors='replace')[since:]) is not None, 150)
    emptied = wait_for(lambda: held_for(c, a) == 0 and held_for(c, b) == 0, 30)
    states = [i['state'] for i in outbox_items(a) if i['state'] != 'delivered'] if acked else None
    a.stop()
    c.stop()
    return dict(ok=ok and acked_at_c is not None and acked is not None and emptied is not None,
                **res, ack_left_with_carol_s=acked_at_c, acked_after_return_s=acked,
                carol_empty_s=emptied, alice_not_delivered=states,
                carol_rows=custody_rows(c))


def s96w_custodian_moves_keeping_its_listener(root: Path) -> dict:
    """Cutoff F8 on the default bind (E-custody-harness-docs-1;
    RAVEN_FAULT_CUSTODY=1 RAVEN_FAULT_HINTS=1). custody_trio; then Carol
    listens on 0.0.0.0:<her port> with a lab netwatch file (one network),
    and Bob's saved address for her is a port where nothing listens (where
    she was before she moved: the saved address and the one she was last
    seen at both go nowhere). Alice sends, Carol holds the message, Alice
    leaves; Bob comes back and for 10 s cannot reach Carol (the control).
    Then only Carol's network moves (lab netwatch `down`, `up`): no new
    listen address, no restart. Her announce reaches Bob because she holds
    mail for him, he learns where she is and fetches the message exactly
    once within 30 s of the move. Before the fix her route hints generation
    never moved for a wildcard listener: nothing in 30 s."""
    a, b, c, setup = custody_trio(root, walk_env(False), walk_env(True))
    pa, pb, pc = port_of(a), port_of(b), port_of(c)
    gone = new_port(pa, pb, pc)
    moved = b.ash('contact', 'set-dial', '--tag', 'carol', '--lan-dial', f'127.0.0.1:{gone}')
    net = root / 'carol.netwatch'
    net.write_text('up 192.168.1.30/24\n')
    c.env = dict(c.env, RAVEN_LAB_NETWATCH_EVENTS=str(net))
    c.start(port=pc, host='0.0.0.0')
    # Her first look at what she tells (route hints' generation) is over
    # before she holds anything: a start alone never names Bob.
    looked = wait_for(lambda: (c.dir / 'route_hints_state.json').is_file(), 40)
    a.start(port=pa)
    rc, out, _ = a.send('bob', 's96w-m1')
    held_s = wait_for(lambda: (held_for(c, b) or 0) >= 1, 60)
    a.stop()
    b.start(port=pb)
    early = wait_inbox(b, 's96w-m1', 10)
    since = log_size(c)
    with net.open('a') as f:
        f.write('down 192.168.1.30/24\nup 10.42.0.5/24\n')
    got = wait_inbox(b, 's96w-m1', 30)
    c_log = c.log_path.read_text(errors='replace')[since:]
    once = count(b.inbox(), 's96w-m1')
    return dict(
        ok=setup['ok'] and moved.returncode == 0 and c.dial == f'0.0.0.0:{pc}'
        and looked is not None and status_word(out) == 'QUEUED' and held_s is not None
        and early is None and got is not None and got <= 30 and once == 1,
        setup=setup, set_dial=moved.returncode, carol_listen=c.dial,
        first_look_s=looked, send=(rc, status_word(out)), held_after_s=held_s,
        before_the_move=early, fetched_after_move_s=got, exactly_once=once,
        carol_lines=[l for l in c_log.splitlines()
                     if 'netwatch:' in l or 'hints:' in l][-6:])


def hint_lines(node: Node, since: int) -> list:
    """The route-hint lines `node` logged after its first `since` lines:
    (kind, events) per line, kind 'told' or 'learned', events the line's own
    plus the ones it folds ("and N more like it")."""
    out = []
    for line in node.log_path.read_text(errors='replace').splitlines()[since:]:
        kind = ('told' if 'told a contact our routes' in line
                else 'learned' if "learned a contact's routes" in line else None)
        if kind:
            more = re.search(r'\(and (\d+) more like it', line)
            out.append((kind, 1 + (int(more.group(1)) if more else 0)))
    return out


def s126_two_addressed_mail_friends_stay_quiet(root: Path) -> dict:
    """E1 (RAVEN_FAULT_CUSTODY=1, RAVEN_FAULT_HINTS=1): mac-b logged "told a
    contact our routes ... (and 62 more like it in the last 30s)" window after
    window, mac-a the same and "learned a contact's routes" nearly as often,
    and no custody line (a fetch that finds nothing says nothing). Alice and
    Bob carry mail for friends and each uses the other as a mail friend;
    Carol uses both. Alice and Bob listen on both families and dial each
    other at different addresses, so each sees the other at two (its learned
    link address moves with each link's direction). A message each way
    between all three, then 75 s of nothing: each node's route-hint lines
    count at most 30 tellings, and none folds more than 20."""
    env = dict(ENV, RAVEN_LAB_TEST_A='1', RAVEN_LAB_ROUTE_HINTS='1',
               RAVEN_LAB_CUSTODY_HANDOFF='1', RAVEN_LAB_LAN_AUTO='1')
    a, b, c = (Node(n, root, env) for n in ('a', 'b', 'c'))
    pa, pb = free_tcp_port(), free_tcp_port()
    a.init()
    a.start(listen=f'auto:{pa}')
    b.init()
    b.start(listen=f'auto:{pb}')
    c.init()
    c.start()
    a.add_pinned(b, 'bob', f'127.0.0.1:{pb}')
    b.add_pinned(a, 'alice', f'localhost:{pa}')
    a.add_pinned(c, 'carol')
    b.add_pinned(c, 'carol')
    c.add_pinned(a, 'alice', f'127.0.0.1:{pa}')
    c.add_pinned(b, 'bob', f'127.0.0.1:{pb}')
    consents = [n.ash(*args).returncode for n in (a, b)
                for args in (('node', 'custody', 'on', '--yes'),
                             ('node', 'custody', 'handoff', 'on'))]
    consents += [n.ash('custody', 'use', 'on', '--yes').returncode for n in (a, b, c)]
    sends = [status_word(x.send(tag, f's126-{x.name}-{tag}')[1])
             for x, tag in ((a, 'bob'), (b, 'alice'), (c, 'alice'), (c, 'bob'),
                            (a, 'carol'), (b, 'carol'))]
    time.sleep(5)
    marks = {n.name: len(n.log_path.read_text(errors='replace').splitlines())
             for n in (a, b, c)}
    time.sleep(75)
    seen = {n.name: hint_lines(n, marks[n.name]) for n in (a, b, c)}
    told = {k: sum(e for kind, e in v if kind == 'told') for k, v in seen.items()}
    learned = {k: sum(e for kind, e in v if kind == 'learned') for k, v in seen.items()}
    widest = {k: max([e for _, e in v] or [0]) for k, v in seen.items()}
    for n in (a, b, c):
        n.stop()
    return dict(
        ok=not any(consents) and sends == ['DELIVERED'] * 6
        and all(t <= 30 for t in told.values()) and all(w <= 20 for w in widest.values()),
        consents=consents, sends=sends, told_75s=told, learned_75s=learned,
        widest_line=widest)


def s127_friend_back_after_minutes(root: Path) -> dict:
    """E1 item I (RAVEN_FAULT_BEACON=1, RAVEN_FAULT_HINTS=1; the field's
    switches with LOCK_ENV's lab unlock). Win-c's two messages to mac-b
    waited ~70 s after mac-b's node came back (attempts 6 and 8: the
    outbox's backoff); mac-b's own announce never reached win-c. Alice, Bob
    and Carol know each other and link once; Bob's node stops, Alice sends 2
    messages and Carol 1, Bob stays away 150 s (the backoff passes a
    minute), then comes back on the same port without route hints (so
    nothing of his tells them he is back). Each message arrives within 20 s
    of his return, once, and Alice's outbox keeps when each arrived."""
    env = dict(LOCK_ENV, RAVEN_LAB_ROUTE_HINTS='1', RAVEN_LAB_CUSTODY_HANDOFF='1',
               RAVEN_LAB_HORIZON='1')
    a, b, c = (Node(n, root, env) for n in ('a', 'b', 'c'))
    for n in (a, b, c):
        n.init()
        n.start(port=free_tcp_port())
    for x, y, tag in ((a, b, 'bob'), (a, c, 'carol'), (b, a, 'alice'), (b, c, 'carol'),
                      (c, a, 'alice'), (c, b, 'bob')):
        x.add_pinned(y, tag)
    warm = [status_word(x.send(tag, f's127-warm-{x.name}')[1])
            for x, tag in ((a, 'bob'), (c, 'bob'), (b, 'alice'), (b, 'carol'))]
    b_port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    texts = ['s127-a1', 's127-a2', 's127-c1']
    sends = [status_word(a.send('bob', 's127-a1')[1]), status_word(a.send('bob', 's127-a2')[1]),
             status_word(c.send('bob', 's127-c1')[1])]
    away = 150
    time.sleep(away)
    before = a.outbox()
    b.env = {k: v for k, v in b.env.items() if k != 'RAVEN_LAB_ROUTE_HINTS'}
    b.start(port=b_port)
    t_back = time.time()
    arrived: dict = {}
    while time.time() - t_back < 240 and len(arrived) < 3:
        inbox = b.inbox()
        for t in texts:
            if t not in arrived and count(inbox, t):
                arrived[t] = round(time.time() - t_back, 1)
        time.sleep(0.5)
    settled = wait_until(lambda: 'Nothing waiting' in a.outbox(), 30, 1)
    rows = a.ash('outbox', 'list').stdout
    time.sleep(2)
    once = exactly_once(b, texts)
    for n in (a, b, c):
        n.stop()
    return dict(
        ok=warm == ['DELIVERED'] * 4 and sends == ['QUEUED'] * 3
        and len(arrived) == 3 and max(arrived.values()) <= 20
        and all(n == 1 for n in once.values()),
        warm=warm, sends=sends, away_s=away, outbox_before=before[-600:],
        arrived_after_s=arrived, outbox_settled_s=settled, exactly_once=once,
        alice_rows=[l.strip() for l in rows.splitlines() if 's127-a' in l])


TOLD_SET = re.compile(r'told a contact our routes \(([^)]*)\); contact (#[0-9a-f]+), (\w+), ')
CONTACT_TAG = re.compile(r'; contact (#[0-9a-f]+), ')


def hint_events(node: Node, since: int = 0) -> dict:
    """`node`'s route-hint lines after its first `since` lines, per contact
    tag: {'told': events, 'learned': events, 'sets': the distinct told route
    sets ('relays=0, direct=2, lan=yes, offers=0')}; events count a line's
    own and the ones it folds."""
    out: dict = {}
    for line in node.log_path.read_text(errors='replace').splitlines()[since:]:
        kind = ('told' if 'told a contact our routes' in line
                else 'learned' if "learned a contact's routes" in line else None)
        tag = CONTACT_TAG.search(line)
        if not kind or not tag:
            continue
        more = re.search(r'\(and (\d+) more like it', line)
        row = out.setdefault(tag.group(1), dict(told=0, learned=0, sets=set()))
        row[kind] += 1 + (int(more.group(1)) if more else 0)
        told = TOLD_SET.search(line)
        if told:
            row['sets'].add(told.group(1))
    return out


def audit_lines(path: Path) -> int:
    """Outbound TCP connects the lab net audit file counted so far."""
    try:
        return sum(1 for l in path.read_text().splitlines() if l.startswith('connect_'))
    except OSError:
        return 0


def s129_idle_friends_settle(root: Path) -> dict:
    """E2 night (RAVEN_FAULT_CUSTODY=1 RAVEN_FAULT_HINTS=1): with nothing to
    send all night, win-c told each friend its route hints about 4 times a
    minute and learned theirs twice ("on every custody poll and incoming
    dial"), and told one friend two route sets within a second: "direct=0"
    on its own custody dials and "direct=2" on the friend's dials. Alice, Bob
    and Carol each carry mail for friends and use both others as mail friends
    (`raven node custody on`, `raven custody use on`), with route hints and
    the p2p host on (its loopback listen addresses go out as same-LAN DIRECT
    entries). All three listen on both families, and each pair dials each
    other at different addresses (127.0.0.1 one way, localhost, that is ::1,
    the other), as win-c reached a friend at two addresses. A message each
    way between all three, then RAVEN_FAULT_IDLE_S (default 600) idle
    seconds on the real timers: per friend and hour, the links each node
    opened (its lab net audit's connects) and its route-hint events (told,
    learned), and the route sets each contact was told. Then a message each
    way again: each DELIVERED within seconds. Pre-fix (cabcc3ae): each node
    linked each friend about 2 times a minute both ways and told each one
    two sets."""
    idle = float(os.environ.get('RAVEN_FAULT_IDLE_S', '600'))
    env = dict(without_beacon(ENV), RAVEN_LAB_TEST_A='1', RAVEN_LAB_ROUTE_HINTS='1',
               RAVEN_LAB_LAN_AUTO='1')
    names = ('a', 'b', 'c')
    audit = {n: root / f'{n}.audit' for n in names}
    a, b, c = (Node(n, root, dict(env, RAVEN_LAB_NET_AUDIT=str(audit[n]))) for n in names)
    ports = {}
    for n in (a, b, c):
        n.init()
        ports[n.name] = free_tcp_port()
        n.start(listen=f'auto:{ports[n.name]}', extra=('--p2p-listen', '127.0.0.1:0'))
    v4 = lambda n: f'127.0.0.1:{ports[n.name]}'  # noqa: E731
    named = lambda n: f'localhost:{ports[n.name]}'  # noqa: E731
    for x, y, tag, dial in ((a, b, 'bob', v4(b)), (b, a, 'alice', named(a)),
                            (a, c, 'carol', named(c)), (c, a, 'alice', v4(a)),
                            (b, c, 'carol', v4(c)), (c, b, 'bob', named(b))):
        x.add_pinned(y, tag, dial)
    consents = [n.ash(*args).returncode for n in (a, b, c)
                for args in (('node', 'custody', 'on', '--yes'), ('custody', 'use', 'on', '--yes'))]
    pairs = ((a, 'bob'), (b, 'alice'), (a, 'carol'), (c, 'alice'), (b, 'carol'), (c, 'bob'))
    warm = [status_word(x.send(tag, f's129-warm-{x.name}-{tag}')[1]) for x, tag in pairs]
    time.sleep(20)
    marks = {n.name: len(n.log_path.read_text(errors='replace').splitlines()) for n in (a, b, c)}
    links0 = {k: audit_lines(p) for k, p in audit.items()}
    t0 = time.time()
    time.sleep(idle)
    span = time.time() - t0
    links = {k: audit_lines(p) - links0[k] for k, p in audit.items()}
    seen = {n.name: hint_events(n, marks[n.name]) for n in (a, b, c)}
    whole = {n.name: hint_events(n) for n in (a, b, c)}
    hour = 3600 / span
    # Two friends each.
    links_h = {k: round(v / 2 * hour, 1) for k, v in links.items()}
    told_h = {k: {t: round(r['told'] * hour, 1) for t, r in v.items()} for k, v in seen.items()}
    learned_h = {k: {t: round(r['learned'] * hour, 1) for t, r in v.items()}
                 for k, v in seen.items()}
    sets = {k: {t: sorted(r['sets']) for t, r in v.items()} for k, v in whole.items()}
    announces = {n.name: n.log_path.read_text(errors='replace').count(
        'routes changed; telling') for n in (a, b, c)}
    after = []
    for x, tag in pairs:
        rc, out, secs = x.send(tag, f's129-after-{x.name}-{tag}')
        after.append((status_word(out), round(secs, 1)))
    for n in (a, b, c):
        n.stop()
    worst = lambda d: max([v for row in d.values() for v in row.values()] or [0])  # noqa: E731
    return dict(
        ok=not any(consents) and warm == ['DELIVERED'] * 6
        and all(w == 'DELIVERED' and s <= 15 for w, s in after)
        and max(links_h.values()) <= 40 and worst(told_h) <= 12 and worst(learned_h) <= 6
        and all(len(s) <= 1 for row in sets.values() for s in row.values()),
        consents=consents, warm=warm, idle_s=round(span), links_per_friend_hour=links_h,
        told_per_friend_hour=told_h, learned_per_friend_hour=learned_h, told_sets=sets,
        announce_lines=announces, after=after)


def s97_three_people_two_rooms(root: Path) -> dict:
    """Cutoff F8 (CP.14; RAVEN_FAULT_CUSTODY=1 RAVEN_FAULT_HINTS=1; LabClock
    shared by the three, with the lab unlock). custody_trio, then: room 1
    at t0, Alice and Carol (Bob away): Alice sends 3 messages, Carol holds
    them. Room 2 at t0 + 2 h, Carol (a new port) and Bob: Carol's announce
    reaches Bob, who fetches the 3, each once and in order, releases them
    and leaves his ACKs with Carol. Room 1 again at t0 + 4 h, Carol (a new
    port again) and Alice: the ACKs reach Alice through Carol (her 3
    messages delivered), and Carol holds nothing unreleased. Variant on a
    fresh trio (late/): room 1 at t0, Alice's message is left with Carol;
    the clock moves to t0 + 25 h while Alice's node runs elsewhere: the
    message expired on the way (a day's session), and her outbox and
    history say so (`outbox status`: state expired; the row: `expired ...
    last: Raven stopped trying: this message waited too long`), never
    silence. Room 2 only then, Carol (a new port)
    and Bob: Bob gets nothing, and Carol's start (its maintenance) leaves
    her store empty ('held 0'). (Bob does not move; Bob moving too needs
    the Phase 3 beacon, P3.C5.)

    With RAVEN_FAULT_BEACON=1 (P3.C5; RAVEN_FAULT_CUSTODY=1, route hints
    off) the same rooms run with the beacon: each room is a lab bus of its
    own (<root>/room1, <root>/room2; the bus file moves before the room's
    nodes start), and Alice, Bob and Carol all come up on new ports in
    every room, so no saved address is right and none is typed: each finds
    the others there through the beacon alone (`rooms` records each room's
    ports and, at its end, each node's beacon counts)."""
    hour = 3600 * 1000
    clock = LabClock(root / 'trio.clock')
    run_env, bus_file = (beacon_env(root, walk_env(False)) if BEACON
                         else (walk_env(True), None))
    a, b, c, setup = custody_trio(root, clock.env(walk_env(False)), clock.env(run_env))
    pa, pb, pc = port_of(a), port_of(b), port_of(c)
    taken = [pa, pb, pc]
    rooms: list = []

    def enter(name: str, *nodes: Node) -> None:
        """`nodes` come into room `name`: Carol on a new port after the
        first room; with the beacon everyone on a new port in every room,
        on the room's bus."""
        if bus_file is not None:
            move_bus(bus_file, root / name)
        ports = {}
        for n in nodes:
            port = {a: pa, b: pb, c: pc}[n]
            if bus_file is not None or (n is c and rooms):
                port = new_port(*taken)
            taken.append(port)
            n.start(port=port)
            ports[n.name] = port
        rooms.append(dict(room=name, ports=ports))

    def leave(*nodes: Node) -> None:
        if bus_file is not None:
            rooms[-1]['beacon'] = {n.name: beacon_counts(n) for n in nodes}
        for n in nodes:
            n.stop()

    texts = ['s97-m1', 's97-m2', 's97-m3']
    # Room 1, t0.
    enter('room1', a, c)
    sends = [status_word(a.send('bob', t)[1]) for t in texts]
    held_s = wait_for(lambda: (held_for(c, b, time.time() * 1000 + clock.offset_ms) or 0) >= 3,
                      90)
    leave(a, c)
    # Room 2, t0 + 2 h.
    clock.advance(2 * hour)
    enter('room2', c, b)
    now = lambda: time.time() * 1000 + clock.offset_ms  # noqa: E731
    got = wait_for(lambda: all(count(b.inbox(), t) for t in texts), 60)
    left = wait_for(lambda: held_for(c, b, now()) == 0 and (held_for(c, a, now()) or 0) >= 1, 60)
    inbox = b.inbox()
    once = [count(inbox, t) for t in texts]
    at = [inbox.find(t) for t in texts]
    in_order = all(x >= 0 for x in at) and at == sorted(at)
    leave(b, c)
    # Room 1 again, t0 + 4 h.
    clock.advance(2 * hour)
    since = log_size(a)
    enter('room1', c, a)
    acked = wait_for(lambda: ACK_VIA_CUSTODIAN.search(
        a.log_path.read_text(errors='replace')[since:]) is not None, 150)
    emptied = wait_for(lambda: held_for(c, a, now()) == 0 and held_for(c, b, now()) == 0, 30)
    states = sorted(i['state'] for i in wait_settled(a, 3, 30))
    leave(a, c)
    rrh1 = sum(learned_from(x, y) for x in (a, b, c) for y in (a, b, c) if x is not y)
    main_ok = (setup['ok'] and sends == ['QUEUED'] * 3 and held_s is not None
               and got is not None and once == [1, 1, 1] and in_order and left is not None
               and acked is not None and emptied is not None
               and states == ['delivered'] * 3 and (bus_file is None or rrh1 == 0))

    # The variant: room 2 only after a day.
    late_root = root / 'late'
    late_root.mkdir()
    late_clock = LabClock(late_root / 'trio.clock')
    late_env, late_bus = (beacon_env(late_root, walk_env(False)) if BEACON
                          else (walk_env(True), None))
    la, lb, lc, late_setup = custody_trio(late_root, late_clock.env(walk_env(False)),
                                          late_clock.env(late_env))
    qa, qb, qc = port_of(la), port_of(lb), port_of(lc)
    late_taken = [qa, qb, qc]

    def late_port(n: Node) -> int:
        """Carol on a new port; with the beacon everyone."""
        port = {la: qa, lb: qb, lc: qc}[n]
        if late_bus is not None or n is lc:
            port = new_port(*late_taken)
            late_taken.append(port)
        return port

    if late_bus is not None:
        move_bus(late_bus, late_root / 'room1')
    la.start(port=late_port(la))
    lc.start(port=qc if late_bus is None else late_port(lc))
    late_send = status_word(la.send('bob', 's97-late')[1])
    late_now = lambda: time.time() * 1000 + late_clock.offset_ms  # noqa: E731
    late_held = wait_for(lambda: (held_for(lc, lb, late_now()) or 0) >= 1, 60)
    late_mid = item_id(la, 's97-late')
    lc.stop()
    # A day later, Alice still on (elsewhere): her message ran out of time.
    since = log_size(la)
    late_clock.advance(25 * hour)
    late_woke = wait_log(la, LabClock.WOKE, 15, since)
    late_state = wait_state(la, late_mid, 'expired', 60)
    late_outbox = la.outbox()
    row = next((l for l in late_outbox.splitlines() if late_mid and late_mid in l), '')
    la.stop()
    # Room 2 only now.
    if late_bus is not None:
        move_bus(late_bus, late_root / 'room2')
    lc.start(port=late_port(lc))
    lb.start(port=late_port(lb))
    time.sleep(20)
    late_got = count(lb.inbox(), 's97-late')
    status = lc.ash('node', 'custody', 'status').stdout
    m = re.search(r'held (\d+) sealed', status)
    carol_rows = int(m.group(1)) if m else None
    lb.stop()
    lc.stop()
    late_ok = (late_setup['ok'] and late_send == 'QUEUED' and late_held is not None
               and late_mid is not None and late_state is not None
               and re.search(r'\bexpired\b.*last: Raven stopped trying: this message waited '
                             r'too long', row) is not None
               and late_got == 0 and carol_rows == 0)
    return dict(
        ok=main_ok and late_ok, setup=setup, beacon=bus_file is not None, sends=sends,
        held_after_s=held_s, room2_fetched_s=got, exactly_once=once, in_order=in_order,
        room2_acks_left_s=left, room1_acked_s=acked, carol_empty_s=emptied,
        alice_states=states, rrh1_seen=rrh1, rooms=rooms,
        late=dict(setup=late_setup, send=late_send, held_after_s=late_held,
                  woke_s=late_woke, alice_expired_s=late_state,
                  alice_outbox_row=row.strip()[:200],
                  bob_got=late_got, carol_status=status.strip()[:160], carol_rows=carol_rows))


class SplitBus:
    """P3.C5: a LAN beacon lab bus on which not everyone hears everyone (a
    hotspot with client isolation). Each node has a bus file and directory
    of its own (<root>/<name>.bus naming <root>/<name>.net), where its beacon
    registers its port; a node's beacon sends "to the group" by sending to
    every port listed in its own directory. A thread copies each node's
    own entries (`<16 hex>.port`) into the directories of the nodes it is
    heard by (`hears[x]` lists whom x hears), as `m-<x>-<entry>`, and takes
    a copy away once its entry is gone. Datagrams stay on 127.0.0.1
    ephemeral ports, as on the shared bus."""

    def __init__(self, root: Path, hears: dict) -> None:
        self.hears = hears
        self.dirs = {}
        self.files = {}
        for name in hears:
            self.dirs[name] = root / f'{name}.net'
            self.dirs[name].mkdir(parents=True, exist_ok=True)
            self.files[name] = root / f'{name}.bus'
            move_bus(self.files[name], self.dirs[name])
        self.live = True
        _SNIFFERS.append(self)
        threading.Thread(target=self._run, daemon=True).start()

    def env(self, name: str, base: dict) -> dict:
        """`base` with the beacon on `name`'s side of the bus."""
        return dict(base, RAVEN_LAB_LAN_BEACON='1',
                    RAVEN_LAB_LAN_BEACON_BUS=str(self.files[name]))

    def own(self, name: str) -> dict:
        """{entry: port text} of what `name`'s beacon registered itself."""
        out = {}
        for p in self.dirs[name].glob('*.port'):
            if not p.name.startswith('m-'):
                try:
                    out[p.name] = p.read_text()
                except OSError:
                    pass
        return out

    def sync(self) -> None:
        for listener, speakers in self.hears.items():
            want = {f'm-{listener}-{k}': v for k, v in self.own(listener).items()}
            for speaker in speakers:
                d = self.dirs[speaker]
                for p in d.glob(f'm-{listener}-*.port'):
                    if p.name not in want:
                        p.unlink(missing_ok=True)
                for entry, text in want.items():
                    path = d / entry
                    try:
                        if path.is_file() and path.read_text() == text:
                            continue
                    except OSError:
                        pass
                    tmp = d / (entry + '.tmp')
                    tmp.write_text(text)
                    os.replace(tmp, path)

    def ports_heard_by(self, speaker: str) -> set:
        """The ports `speaker`'s beacon sends to now (its directory)."""
        return set(bus_ports(self.dirs[speaker]).values())

    def _run(self) -> None:
        while self.live:
            try:
                self.sync()
            except OSError:
                pass
            time.sleep(0.2)

    def stop(self) -> None:
        self.live = False


def s88_hotspot_isolation_ap_custodian(root: Path) -> dict:
    """Phase 3 P3.C5 (hotspot_isolation_ap_custodian; RAVEN_FAULT_BEACON=1
    RAVEN_FAULT_CUSTODY=1, route hints off). A phone hotspot with client
    isolation: C1 (Alice) and C2 (Bob) cannot hear each other, both hear
    the access point AP (Carol). custody_trio's links (on no bus: pinned,
    sessions, no RRH1; AP is the custodian both chose, custody on), then
    the three come up on a SplitBus (C1 and C2 each hear AP only, AP hears
    both) and on new ports: no saved address is right and none is typed.
    C1's message to C2 is queued (C1's beacon finds no C2: its queries
    reach AP alone), left with AP within 60 s (C1 found AP through the
    beacon), fetched by C2 exactly once within 60 s, and C2's ACK comes
    back to C1 through AP within 150 s (C1's outbox says delivered). C1 and
    C2 never learn where the other is: C1's beacon finds no C2 at the end
    (IPC LanLocate), neither directory ever lists the other's port, and no
    RRH1 is held. Records the send text and every wait."""
    split = SplitBus(root, {'c1': ['ap'], 'c2': ['ap'], 'ap': ['c1', 'c2']})
    base = walk_env(False)
    a, b, c, setup = custody_trio(root, base, base)
    a.env, b.env, c.env = split.env('c1', base), split.env('c2', base), split.env('ap', base)
    taken = [port_of(a), port_of(b), port_of(c)]
    ports = {}
    for n, side in ((c, 'ap'), (a, 'c1'), (b, 'c2')):
        port = new_port(*taken)
        taken.append(port)
        n.start(port=port)
        ports[side] = port
    on_bus = wait_for(lambda: all(len(split.ports_heard_by(s)) >= {'ap': 3}.get(s, 2)
                                  for s in ('c1', 'c2', 'ap')), 30)
    since = log_size(a)
    rc, out, send_s = a.send('bob', 's88-m1')
    mid = item_id(a, 's88-m1')
    held_s = wait_for(lambda: (held_for(c, b) or 0) >= 1, 60)
    got = wait_inbox(b, 's88-m1', 60)
    acked = wait_for(lambda: ACK_VIA_CUSTODIAN.search(
        a.log_path.read_text(errors='replace')[since:]) is not None, 150)
    delivered = wait_state(a, mid, 'delivered', 30) if acked is not None else None
    time.sleep(2)
    once = count(b.inbox(), 's88-m1')
    c1_finds = lan_locate(a, b)
    c2_finds = lan_locate(b, a)
    leaked = (any(f':{ports["c2"]}' in d for d in c1_finds)
              or any(f':{ports["c1"]}' in d for d in c2_finds))
    split_ok = (ports['c2'] not in split.ports_heard_by('c1')
                and ports['c1'] not in split.ports_heard_by('c2'))
    counts = {n.name: beacon_counts(n) for n in (a, b, c)}
    rrh1 = sum(learned_from(x, y) for x in (a, b, c) for y in (a, b, c) if x is not y)
    fetch_lines = [l for l in b.log_path.read_text(errors='replace').splitlines()
                   if 'custody: fetched messages=' in l]
    c1_outbox = a.outbox()[-300:]
    for n in (a, b, c):
        n.stop()
    return dict(
        ok=setup['ok'] and on_bus is not None and status_word(out) == 'QUEUED'
        and held_s is not None and got is not None and once == 1 and acked is not None
        and delivered is not None and not c1_finds and not c2_finds and not leaked
        and split_ok and rrh1 == 0,
        setup=setup, on_bus_s=on_bus, send=(rc, status_word(out), round(send_s, 1)),
        send_text=out[-1200:], held_by_ap_s=held_s, c2_fetched_s=None if got is None
        else round(got, 1), exactly_once=once, ack_back_s=acked, c1_delivered_s=delivered,
        c1_finds_c2=c1_finds, c2_finds_c1=c2_finds, isolated=split_ok, beacon=counts,
        rrh1_seen=rrh1, c2_fetch_lines=fetch_lines[-3:], c1_outbox=c1_outbox)


def s125_custody_release_deletes(root: Path) -> dict:
    """Privacy pack PP.17 (RAVEN_FAULT_CUSTODY=1 or RAVEN_FAULT_PRIVACY=1;
    the harness's profiles are sealed, RAVEN_LAB_AT_REST=1). s30's trio: Bob
    away, Alice's message is left with Carol (her store keeps it keyed and
    sealed: it is read here with her epoch keys); Alice goes, Bob comes
    back, fetches it exactly once and releases it: Carol's store holds no
    row for it any more, only its released digest (the keyed digest and the
    expiry hour, nothing else). Then Carol's node stops (its connections
    close: the checkpoint) and no file in her data dir holds Alice's or
    Bob's key (raw, hex in either case, base64), and her store's bytes hold
    neither the payload as it was stored nor the object in clear. Carol and
    Alice back: Alice's node replays the same deposit (`ash lab
    custody-deposit`, the same RSO1): Carol answers DUPLICATE and stores
    nothing, and Bob's inbox still holds the message once. The letters stay
    held whatever RAVEN_FAULT_LETTER says: with them Alice's message would
    go as a sealed letter, whose release this scenario does not read (s61's
    checks do)."""
    import base64
    env = {k: v for k, v in CUSTODY_ENV.items() if k != 'RAVEN_LAB_LETTER'}
    a, b, c = (Node(n, root, env) for n in ('a', 'b', 'c'))
    for n in (a, b, c):
        n.init()
        n.start()
    for x, y, tag in ((a, b, 'bob'), (a, c, 'carol'), (b, a, 'alice'), (b, c, 'carol'),
                      (c, a, 'alice'), (c, b, 'bob')):
        x.add_pinned(y, tag)
    on = c.ash('node', 'custody', 'on', '--yes')
    for x, tag in ((a, 'bob'), (b, 'alice')):
        r = x.ash('contact', 'set-addr', '--tag', tag, '--custodian', '@carol')
        assert r.returncode == 0, r.stdout + r.stderr
    warm = a.send('bob', 's125-warmup')[0]
    b_port, c_port = port_of(b), port_of(c)
    b.stop()
    rc, out, _ = a.send('bob', 's125-m1')
    held_s = wait_for(lambda: (held_for(c, b) or 0) >= 1, 60)
    objects = custody_objects(c) or []
    mine = [o for o in objects if o[3] == b.pub.lower()]
    kd, stored, rso1 = mine[0][:3] if len(mine) == 1 else (b'', b'', b'')
    a.stop()
    b.start(port=b_port)
    got = wait_inbox(b, 's125-m1', 60)

    def released_now() -> bool:
        rows = custody_released(c)
        left = custody_objects(c)
        return (rows is not None and left is not None and len(rows) >= 2
                and any(r[0] == kd for r in rows[1:]) and all(o[0] != kd for o in left))

    released_s = wait_for(released_now, 60) if kd else None
    released = custody_released(c) or [[]]
    once_before = count(b.inbox(), 's125-m1')
    # The checkpoint: Carol's node stops, its last connection takes the WAL
    # into the main file.
    c.stop()
    store_path = c.dir / 'friend_custody.sqlite'
    store_bytes = store_path.read_bytes() if store_path.exists() else b''
    wal = Path(f'{store_path}-wal')
    wal_bytes = wal.read_bytes() if wal.exists() else b''
    leaks = files_holding(c.dir, key_needles(a.pub) + key_needles(b.pub))
    scanned = len(files_holding(c.dir, [b'']))
    payload_left = bool(stored) and (stored in store_bytes + wal_bytes
                                     or rso1 in store_bytes + wal_bytes)
    c.start(port=c_port)
    a.start()
    replay = a.ash('lab', 'custody-deposit', '--dial', c.dial, '--custodian-pub-hex', c.pub,
                   '--recipient-pub-hex', b.pub,
                   '--rso1-b64', base64.b64encode(rso1).decode()) if rso1 else None
    duplicate = replay is not None and 'custody_deposit=Duplicate' in replay.stdout
    after = custody_objects(c)
    stored_again = after is None or any(o[0] == kd for o in after)
    once = count(b.inbox(), 's125-m1')
    ok = (on.returncode == 0 and warm == 0 and held_s is not None and len(mine) == 1
          and got is not None and once_before == 1 and released_s is not None
          and released[0] == ['kh_object_digest', 'prune_after_hour']
          and scanned >= 10 and not leaks and not payload_left and duplicate
          and not stored_again and once == 1)
    return dict(ok=ok, custody_on=on.returncode, warmup=warm, send=(rc, status_word(out)),
                held_after_s=held_s, objects_for_bob=len(mine), fetched_after_s=got,
                released_after_s=released_s, released_columns=released[0],
                released_digests=len(released) - 1, files_scanned=scanned,
                files_with_a_key=leaks,
                payload_left=payload_left, wal_left=len(wal_bytes),
                replay=(replay.returncode, replay.stdout.strip()[-120:],
                        replay.stderr.strip()[-300:]) if replay else None,
                duplicate=duplicate, stored_again=stored_again, exactly_once=once)


def s95_status_on_loopback_and_vanished_bind(root: Path) -> dict:
    """Cutoff F2 (CP.5; release behaviour, no switch). Alice's node listens
    on 127.0.0.1: her `ash status` receiving row starts 'ONLY THIS COMPUTER'
    (never YES), its verdict says friends cannot reach her, and `ash doctor`
    keys `receiving: local_only (127.0.0.1:P)`. Bob's node is set to listen
    on 192.0.2.10:7499 (TEST-NET-1, on no interface): it keeps running
    without a listener, his row says the address 'is not on this computer
    now', never 'busy port', and doctor keys `receiving: no (addr_not_here
    192.0.2.10:7499)`. (That his node binds once the address appears needs
    an address that appears: netns cable-linklocal, CP.15.)"""
    a = Node('alice', root)
    a.init()
    a.start()
    a_status = a.ash('status').stdout
    a_doctor = a.ash('doctor').stdout
    a_row = status_row(a_status, 'receiving') or ''
    b = Node('bob', root)
    b.init()
    b.start(port=7499, host='192.0.2.10', bound=False)
    b_status = b.ash('status').stdout
    b_doctor = b.ash('doctor').stdout
    b_row = status_row(b_status, 'receiving') or ''
    b_log = b.log_path.read_text(errors='replace')
    return dict(
        ok=a_row.startswith('ONLY THIS COMPUTER') and a.dial in a_row
        and status_verdict_text(a_status).endswith(
            f'friends cannot reach you: raven-node listens on this computer only ({a.dial}).')
        and a_status.rstrip().endswith(LAB_WARNING)
        and f'receiving: local_only ({a.dial})' in a_doctor
        and b_row.startswith('NO \u2014 raven-node is set to listen on 192.0.2.10:7499')
        and 'is not on this computer now' in b_row
        and 'busy port' not in b_status + b_doctor
        and 'receiving: no (addr_not_here 192.0.2.10:7499)' in b_doctor
        and 'raven-node lan_direct: listen ' not in b_log,
        alice_row=a_row, alice_listen=a.dial,
        alice_verdict=status_verdict_text(a_status)[-160:],
        bob_row=b_row, bob_verdict=status_verdict_text(b_status)[-200:],
        doctor_keys=[line.strip() for line in (a_doctor + b_doctor).splitlines()
                     if line.strip().startswith('receiving:')])


def last_sent_envelope(node: Node) -> bytes | None:
    """The sealed envelope of `node`'s newest outgoing message, as its
    session store keeps it until the session goes (read-only; None while it
    cannot be read). A sealed profile's store keeps it sealed (PP.14:
    schema 3), opened here with the profile's epoch key."""
    import sqlite3
    path = node.dir / 'indexed_sessions.sqlite'
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=10)
        try:
            columns = {r[1] for r in con.execute('PRAGMA table_info(endpoint_outbox)')}
            keyed = 'kh_envelope' in columns
            row = con.execute(
                'SELECT session_id, ' + ('kh_object_digest' if keyed else 'object_digest')
                + ', immutable_envelope_bytes FROM endpoint_outbox '
                'WHERE kind = 1 ORDER BY rowid DESC LIMIT 1').fetchone()
        finally:
            con.close()
    except sqlite3.Error:
        return None
    if not row:
        return None
    if not keyed:
        return bytes(row[2])
    return open_row(bytes(row[2]), profile_epoch_keys(node.dir),
                    'endpoint_outbox.immutable_envelope_bytes', bytes(row[0]) + bytes(row[1]))


def session_heads(node: Node) -> int | None:
    """How many sessions `node`'s store holds (read-only; None while it
    cannot be read)."""
    import sqlite3
    path = node.dir / 'indexed_sessions.sqlite'
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=10)
        try:
            return int(con.execute('SELECT COUNT(*) FROM indexed_session_heads').fetchone()[0])
        finally:
            con.close()
    except sqlite3.Error:
        return None


# What raven-node logs when a deleted message comes again (PP.8).
DELETED_AGAIN = 'raven: a deleted message arrived again; answered, not shown'


LOCKED_LINE = 'Raven is locked (stopped). Run `raven unlock` to start it again.'
LOCKED_TEXT = 'Raven is locked. Run `raven unlock` to start it again.'


def first_status_line(out: str) -> str:
    """The first line under `raven status`'s STATUS header."""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines[1] if len(lines) > 1 and lines[0].startswith('STATUS') else ''


def s121_lock_v1_with_queued_messages(root: Path) -> dict:
    """Privacy pack PP.15 (Lock now v1; release behaviour, no switch). The
    harness's own nodes, no login item (Bob's lab login-item folders are
    empty: a debug build's `raven lock` refuses without them). Alice and
    Bob are verified and share a session. Bob runs `raven lock --yes`: his
    node stops (SIGTERM to the pid its Status reports) and stays stopped.
    While he is locked his `raven status` says so first, his own `raven send`
    is refused without starting a node, and Alice's 3 sends are QUEUED with a
    deadline on this computer's clock, never NOT SENT, and retried. Bob runs
    `raven unlock`: his node starts again on his port (as a send starts it)
    and his first message to Alice is the link that wakes her queue (s90):
    all 3 arrive exactly once within 10 s of his node answering."""
    a, b = Node('a', root), Node('b', root)
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = a.send('bob', 's121-warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    items, tools = root / 'login-items', root / 'login-tools'
    items.mkdir()
    tools.mkdir()
    bob_env = dict(b.env, RAVEN_LAB_LOGIN_ITEM_ROOT=str(items),
                   RAVEN_LAB_LOGIN_ITEM_TOOLS=str(tools),
                   RAVEN_SERVICE_LAN_LISTEN=f'127.0.0.1:{port}')

    def bob(*args: str, stdin: str = '') -> subprocess.CompletedProcess:
        return subprocess.run([b.ash_bin, '--data-dir', str(b.dir), *args], input=stdin,
                              capture_output=True, text=True, timeout=120, env=bob_env)

    lock = bob('lock', '--yes')
    try:
        b.proc.wait(10)
    except subprocess.TimeoutExpired:
        pass
    node_ended = b.proc.poll() is not None
    b.proc = None if node_ended else b.proc
    status_locked = first_status_line(bob('status').stdout)
    own = bob('send', '--contact', '@alice', stdin='s121-bob-locked\n')
    own_out = own.stdout + own.stderr
    no_node = b.ash('ipc-ping', timeout=10).returncode != 0
    sends = [a.send('bob', f's121-m{i}') for i in (1, 2, 3)]
    queued = [status_word(out) == 'QUEUED' and bool(LOCAL_DEADLINE.search(out))
              and 'NOT SENT' not in out for _, out, _ in sends]
    m = re.search(r'mid=([0-9a-f]{8})', sends[0][1])
    attempts = 0
    t_wait = time.time()
    while m and time.time() - t_wait < 30:
        attempts = int(outbox_field(a.ash('outbox', 'status', m.group(1)).stdout, 'attempts')
                       or 0)
        if attempts >= 2:
            break
        time.sleep(1)
    early = {f's121-m{i}': count(b.inbox(), f's121-m{i}') for i in (1, 2, 3)}
    unlock = bob('unlock')
    t_up = time.time()
    started = re.search(r'started raven-node \(process (\d+)\)', unlock.stderr)
    pid = int(started.group(1)) if started else None
    try:
        answering = b.ash('ipc-ping', timeout=10).returncode == 0
        status_after = first_status_line(bob('status').stdout)
        hello = b.send('alice', 's121-bob-back')
        texts = [f's121-m{i}' for i in (1, 2, 3)]
        took = None
        while time.time() - t_up < 12 and took is None:
            inbox = b.inbox()
            if all(count(inbox, t) for t in texts):
                took = round(time.time() - t_up, 1)
            time.sleep(0.5)
        time.sleep(2)
        once = {t: count(b.inbox(), t) for t in texts}
    finally:
        # The node `raven unlock` started (detached): stopped by its pid.
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    return dict(
        ok=warm[0] == 0 and lock.returncode == 0
        and 'Raven is stopped.' in lock.stdout.splitlines() and node_ended
        and status_locked == LOCKED_LINE and own.returncode != 0 and LOCKED_TEXT in own_out
        and no_node and all(queued) and attempts >= 2 and not any(early.values())
        and unlock.returncode == 0
        and unlock.stdout.splitlines()[-2:] == ['Starting Raven again...',
                                                'Raven is running. Friends can reach you.']
        and pid is not None and answering and status_after != LOCKED_LINE
        and hello[0] == 0 and took is not None and took <= 10
        and all(n == 1 for n in once.values()),
        warmup=warm[0], lock=(lock.returncode, lock.stdout[-300:], lock.stderr[-300:]),
        node_ended=node_ended, status_while_locked=status_locked,
        own_send=(own.returncode, own_out[-300:]), no_node_started=no_node,
        sends=[(rc, status_word(out), round(dt, 1)) for rc, out, dt in sends],
        queued_with_deadline=queued, attempts_before_unlock=attempts,
        delivered_while_locked=early,
        unlock=(unlock.returncode, unlock.stdout[-300:], unlock.stderr[-300:]),
        unlocked_pid=pid, answering=answering, status_after=status_after,
        bob_back=(hello[0], status_word(hello[1])), delivered_after_up_s=took,
        exactly_once=once, outbox=a.outbox()[-400:])


# Lock now v2's words (P6.40): `raven lock`'s first line, `raven status`'s
# first line while the node runs locked, `raven unlock`'s first line, and a
# send refused while it is locked.
LOCKED_V2_SCREEN = "Raven is locked. Friends can't reach you; your messages wait here."
LOCKED_V2_STATUS = ("Raven is locked. Friends can't reach you; your messages wait here. Run "
                    "`raven unlock` to open it.")
UNLOCKED_V2 = 'Raven is unlocked. Friends can reach you again.'
LOCKED_V2_TEXT = 'Raven is locked. Run `raven unlock` to open it again.'


def port_refuses(dial: str) -> bool:
    """A TCP connect to `dial` (host:port) is refused at once."""
    host, port = dial.rsplit(':', 1)
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False


def s116_lock_v2_with_queued_messages(root: Path) -> dict:
    """Phase 6b P6.40 (RAVEN_FAULT_LOCK_V2=1; Lock now v2 with its debug
    switch on Bob's side, LOCK_ENV). Alice and Bob are verified and share a
    session; Bob's listener has a fixed port. Bob runs `raven lock --yes`:
    his node keeps running (the same pid answers Ping) and says it is
    locked; `raven status` says so first, with the keychain profile's honest
    line in the lock's words, and his own `raven send` is refused without
    queueing. A friend dialing his port is refused (the listener is closed),
    and Alice's 3 sends are QUEUED with a deadline on this computer's clock,
    retried, and none arrives. Bob runs `raven unlock` (a keychain profile:
    no passphrase): the same node opens his port again, and his first
    message to Alice is the link that wakes her queue (s90): all 3 arrive
    exactly once within 15 s of the unlock. Alice is never refused as a
    stranger (E1: while the unlock's key loader held Bob's book, her links
    were 'not a local contact'; now they wait for it or close unjudged). No
    listener says it failed after the unlock (E1: on Windows the LAN
    listener's first try met 'Access is denied' and said so)."""
    a, b = Node('a', root), Node('b', root, env=LOCK_ENV)
    a.init(); b.init()
    a.start()
    b.start(port=free_tcp_port())
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = a.send('bob', 's116-warmup')
    pid = b.proc.pid
    lock = b.ash('lock', '--yes', timeout=60)
    still_running = b.proc.poll() is None and b.ash('ipc-ping', timeout=10).returncode == 0
    status_locked = first_status_line(b.ash('status').stdout)
    own = b.send('alice', 's116-bob-locked')
    refused = port_refuses(b.dial)
    sends = [a.send('bob', f's116-m{i}') for i in (1, 2, 3)]
    queued = [status_word(out) == 'QUEUED' and bool(LOCAL_DEADLINE.search(out))
              and 'NOT SENT' not in out for _, out, _ in sends]
    m = re.search(r'mid=([0-9a-f]{8})', sends[0][1])
    attempts = 0
    t_wait = time.time()
    while m and time.time() - t_wait < 30:
        attempts = int(outbox_field(a.ash('outbox', 'status', m.group(1)).stdout, 'attempts')
                       or 0)
        if attempts >= 2:
            break
        time.sleep(1)
    refused_later = port_refuses(b.dial)
    texts = [f's116-m{i}' for i in (1, 2, 3)]
    early = {t: count(b.inbox(), t) for t in texts}
    unlock = b.ash('unlock', timeout=60)
    t_up = time.time()
    reopened = None
    while time.time() - t_up < 15 and reopened is None:
        if not port_refuses(b.dial):
            reopened = round(time.time() - t_up, 1)
        time.sleep(0.2)
    status_after = first_status_line(b.ash('status').stdout)
    hello = b.send('alice', 's116-bob-back')
    took = None
    while time.time() - t_up < 17 and took is None:
        inbox = b.inbox()
        if all(count(inbox, t) for t in texts):
            took = round(time.time() - t_up, 1)
        time.sleep(0.5)
    time.sleep(2)
    once = {t: count(b.inbox(), t) for t in texts}
    same_node = b.proc.poll() is None and b.proc.pid == pid
    log = b.log_path.read_text(errors='replace')
    lock_lines = [l for l in log.splitlines() if 'raven-node lock:' in l]
    after_unlock = log.rpartition('lock: unlocked')[2].splitlines()
    failed_after = [l for l in after_unlock
                    if re.search(r'\b(lan_direct|internet_direct|p2p|friend_relay):? failed', l)]
    for n in (a, b):
        n.stop()
    lock_out = lock.stdout.splitlines()
    return dict(
        ok=warm[0] == 0 and lock.returncode == 0 and lock_out[:1] == [LOCKED_V2_SCREEN]
        and any('Anyone who can log in as you can open them' in l for l in lock_out)
        and still_running and status_locked == LOCKED_V2_STATUS
        and own[0] != 0 and 'NOT SENT, nothing queued' in own[1] and LOCKED_V2_TEXT in own[1]
        and refused and refused_later and all(queued) and attempts >= 2
        and not any(early.values())
        and unlock.returncode == 0 and unlock.stdout.splitlines()[:1] == [UNLOCKED_V2]
        and reopened is not None and status_after != LOCKED_V2_STATUS
        and hello[0] == 0 and took is not None and took <= 15
        and all(n == 1 for n in once.values()) and same_node
        and any(l.endswith('lock: locked') for l in lock_lines)
        and any(l.endswith('lock: unlocked') for l in lock_lines)
        and 'not a local contact' not in log and not failed_after,
        warmup=warm[0], lock=(lock.returncode, lock.stdout[-400:], lock.stderr[-300:]),
        node_kept_running=still_running, status_while_locked=status_locked,
        own_send=(own[0], own[1][-300:]), dial_refused=refused,
        dial_refused_later=refused_later,
        sends=[(rc, status_word(out), round(dt, 1)) for rc, out, dt in sends],
        queued_with_deadline=queued, attempts_while_locked=attempts,
        delivered_while_locked=early,
        unlock=(unlock.returncode, unlock.stdout[-300:], unlock.stderr[-300:]),
        port_reopened_s=reopened, status_after=status_after,
        bob_back=(hello[0], status_word(hello[1])), delivered_after_unlock_s=took,
        exactly_once=once, same_node=same_node, lock_log=lock_lines[-6:],
        failed_after_unlock=failed_after[:4],
        refused_as_stranger=log.count('not a local contact'))


# ── Phase 6b P6.51: the update harness (s118, s119; s117 with every switch) ──

# The published test release keys (shared-vectors/rvn1/update/keyset_001.json:
# the seeds 0x11, 0x22, 0x33 x 32, threshold 2). Anyone can sign with them:
# only a debug build's raven-release does, and only a lab key set trusts them.
TEST_KEY_SET = json.loads(
    (Path(__file__).resolve().parent.parent / 'shared-vectors' / 'rvn1' / 'update'
     / 'keyset_001.json').read_text())['expected']
# The offline release tool of a debug build (`cargo build --locked -p ash
# --features release-tool --bin raven-release`): s118 and s119 make their
# notices, logs and releases with it and the test keys.
RELEASE_TOOL = str(BIN / 'raven-release')


def updates_env(base: dict, root: Path) -> dict:
    """`base` with the test key set as the lab release key set
    (RAVEN_LAB_RELEASE_KEYS_FILE, a file in the run's root)."""
    keys = root / 'release-keys.hex'
    keys.write_text(TEST_KEY_SET['key_set_hex'] + '\n')
    return dict(base, RAVEN_LAB_RELEASE_KEYS_FILE=str(keys))


class TestProject:
    """The Raven project of the update scenarios (P6.51): its release log
    folder and artifacts in `root/project`, made by the release tool with the
    published test keys as docs/RELEASE_KEY_CEREMONY.md describes (notices
    signed by keys 0 and 2, releases by 0 and 1, tree heads by 1 and 2)."""

    def __init__(self, root: Path) -> None:
        if not Path(RELEASE_TOOL).is_file():
            raise RuntimeError(f'{RELEASE_TOOL} is missing: cargo build --locked -p ash '
                               '--features release-tool --bin raven-release')
        self.dir = root / 'project'
        (self.dir / 'log').mkdir(parents=True)
        self.at = 1792800000000
        self.tool('keyset', '--threshold', '2', '--out', 'keys.keyset',
                  *TEST_KEY_SET['public_keys_hex'])

    def tool(self, *args: str) -> str:
        r = subprocess.run([RELEASE_TOOL, *args], cwd=self.dir, capture_output=True,
                           text=True, timeout=120, env=ENV)
        if r.returncode != 0:
            raise RuntimeError(f'raven-release {" ".join(args[:2])}: {r.stderr[-800:]}')
        return r.stdout

    def signed(self, draft: str, out: str, keys: tuple) -> Path:
        for k in keys:
            self.tool('sign', '--key-set', 'keys.keyset', '--test-key', str(k), draft)
        self.tool('combine', '--key-set', 'keys.keyset', '--draft', draft, '--out', out,
                  *[f'{draft}.sig-{k}' for k in keys])
        return self.dir / out

    def advisory(self, serial: int, text: str, previous: Path | None = None) -> Path:
        """Signed notice `serial` (a NOTICE entry), after `previous`."""
        self.at += 86400000
        spec = self.dir / f'advisory-{serial}.json'
        spec.write_text(json.dumps({'serial': serial, 'issued_at_ms': self.at,
                                    'entries': [{'kind': 'NOTICE', 'text': text}]}))
        prev = ['--previous', str(previous)] if previous else []
        self.tool('advisory', '--key-set', 'keys.keyset', '--spec', spec.name, *prev,
                  '--out', f'advisory-{serial}.draft')
        return self.signed(f'advisory-{serial}.draft', f'advisory-{serial}.rad1', (0, 2))

    def release(self, serial: int, files: dict) -> Path:
        """Signed manifest of release `serial` for this computer: `files`
        (`bin/...` or `docs/...` -> bytes) in `files-<serial>/`."""
        self.at += 86400000
        folder = self.dir / f'files-{serial}'
        args = []
        for path, data in files.items():
            (folder / path).parent.mkdir(parents=True, exist_ok=True)
            (folder / path).write_bytes(data)
            args += ['--file', f'{path}={folder / path}']
        (self.dir / f'notes-{serial}.txt').write_text(f'Raven 1.{serial}.0 (update harness).\n')
        self.tool('manifest', '--key-set', 'keys.keyset', '--build-serial', str(serial),
                  '--version', f'1.{serial}.0', '--target', host_target(),
                  '--source-commit', '0123456789abcdef0123456789abcdef01234567',
                  '--toolchain', '1.98.0', '--created-at-ms', str(self.at),
                  '--notes', f'notes-{serial}.txt', *args, '--out', f'manifest-{serial}.draft')
        return self.signed(f'manifest-{serial}.draft', f'manifest-{serial}.rrb1', (0, 1))

    def log(self, *artifacts: Path) -> Path:
        """List `artifacts`, sign the tree head of the whole log and write its
        snapshot: a copy of it (`snapshot-<size>.rtl1`)."""
        self.at += 86400000
        self.tool('log', 'append', '--log', 'log', '--key-set', 'keys.keyset',
                  '--at-ms', str(self.at), *map(str, artifacts))
        size = (self.dir / 'log' / 'entries.bin').stat().st_size // 41
        self.tool('sth', '--log', 'log', '--key-set', 'keys.keyset',
                  '--timestamp-ms', str(self.at + 1))
        draft = f'tree-head-{size}.draft'
        for k in (1, 2):
            self.tool('sign', '--key-set', 'keys.keyset', '--test-key', str(k), draft)
        self.tool('combine', '--key-set', 'keys.keyset', '--draft', draft, '--log', 'log',
                  f'{draft}.sig-1', f'{draft}.sig-2')
        snapshot = self.dir / 'log' / 'snapshot.rtl1'
        snapshot.unlink(missing_ok=True)
        self.tool('log', 'snapshot', '--log', 'log', '--key-set', 'keys.keyset')
        copy = self.dir / f'snapshot-{size}.rtl1'
        shutil.copyfile(snapshot, copy)
        return copy

    def pack(self, serial: int, manifest: Path) -> Path:
        """The .rrb bundle of `manifest` (listed in the log)."""
        self.tool('pack', '--key-set', 'keys.keyset', '--manifest', str(manifest),
                  '--log', 'log', '--files', f'files-{serial}', '--out', f'raven-{serial}.rrb')
        return self.dir / f'raven-{serial}.rrb'


def host_target() -> str:
    """This computer's target triple (`rustc -vV`'s host), the target of a
    release raven-node fetches for itself."""
    out = subprocess.run(['rustc', '-vV'], capture_output=True, text=True, timeout=60).stdout
    return re.search(r'^host: (\S+)', out, re.M).group(1)


def node_updates(node: Node) -> dict:
    """The node's Status.updates (counts only; {} while its exchange does
    not run)."""
    try:
        return node_ipc(node, {'op': 'status', 'v': 1}).get('updates') or {}
    except (OSError, ValueError, struct.error):
        return {}


def ledger_kinds(node: Node) -> list:
    """The event kinds of the rows in `node`'s security ledger (its kind
    column is plain; subjects and texts are sealed)."""
    import sqlite3
    path = node.dir / 'security_events.sqlite'
    if not path.exists():
        return []
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=5)
        try:
            return [k for (k,) in con.execute(
                'SELECT kind FROM sec_alerts UNION ALL SELECT kind FROM sec_counts')]
        finally:
            con.close()
    except sqlite3.Error:
        return []


# Security event codes (docs/SECURITY_EVENTS.md).
SEC_ADVISORY_APPLIED = 77
SEC_BUNDLE_FORGED = 73


def import_update(node: Node, path: Path, log: Path | None = None):
    args = ['update', 'import', str(path)] + (['--log', str(log)] if log else [])
    return node.ash(*args)


def incoming_chunks(node: Node) -> tuple[str, int]:
    """The download under way in `updates/incoming/` (its digest folder) and
    how many chunks its bitmap holds (one bit per chunk)."""
    root = node.dir / 'updates' / 'incoming'
    for folder in sorted(root.iterdir()) if root.is_dir() else []:
        bitmap = folder / 'chunks'
        if bitmap.is_file():
            return folder.name, sum(bin(b).count('1') for b in bitmap.read_bytes())
    return '', 0


def offer_code(node: Node) -> str:
    """The code of the first offer `ash update download` lists."""
    m = re.search(r'raven update download ([0-9a-f]{8})', node.ash('update', 'download').stdout)
    return m.group(1) if m else ''


def s118_mesh_advisory_a_b_c(root: Path) -> dict:
    """Phase 6b P6.51 (was s98; RAVEN_FAULT_UPDATES=1, the update gates'
    debug switches with the test release key set, UPD_ENV): a security
    notice passed A -> B -> C over LAN with no command. Alice imports notice
    #1 (signed by the test keys, listed in the log); Bob messages Alice and
    takes it from her, Carol messages Bob and takes it from him (each node's
    Status.updates says #1 and its ledger has SEC_ADVISORY_APPLIED); then
    #2 (after #1, the log grown) goes the same way. `ash update status`
    says each node's notice; no node quarantined anything."""
    env = updates_env(UPD_ENV, root)
    project = TestProject(root)
    first = project.advisory(1, 'Update Raven when you can (update harness #1).')
    log1 = project.log(first)
    a, b, c = Node('a', root, env=env), Node('b', root, env=env), Node('c', root, env=env)
    for n in (a, b, c):
        n.init()
        n.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    b.add_pinned(c, 'carol')
    c.add_pinned(b, 'bob')
    imported = import_update(a, first, log1)
    rounds = []
    for serial, note in ((1, None), (2, 'Update Raven when you can (update harness #2).')):
        if note:
            notice = project.advisory(serial, note, previous=first)
            imported = import_update(a, notice, project.log(notice))
        hops = {}
        for sender, tag, taker in ((b, 'alice', b), (c, 'bob', c)):
            sent = sender.send(tag, f's118-{serial}-{sender.name}')
            hops[taker.name] = dict(
                sent=status_word(sent[1]),
                took_s=took(wait_until(
                    lambda: node_updates(taker).get('advisory_serial') == serial, 60)))
        rounds.append(dict(serial=serial, imported=imported.returncode, hops=hops))
    status = {n.name: n.ash('update', 'status').stdout.strip()[-300:] for n in (a, b, c)}
    applied = {n.name: SEC_ADVISORY_APPLIED in ledger_kinds(n) for n in (b, c)}
    quarantined = {n.name: node_updates(n).get('quarantined') for n in (a, b, c)}
    return dict(
        ok=all(r['imported'] == 0 and all(h['sent'] == 'DELIVERED' and h['took_s'] is not None
                                          for h in r['hops'].values()) for r in rounds)
        and all(applied.values()) and all(q == 0 for q in quarantined.values())
        and all('#2' in s for s in status.values()),
        rounds=rounds, applied_events=applied, quarantined=quarantined, update_status=status)


def s119_mesh_release_resumed_from_a_second_friend(root: Path) -> dict:
    """Phase 6b P6.51 (was s99; RAVEN_FAULT_UPDATES=1, UPD_ENV): a release
    passed over the mesh with the download approval, and resumed from a
    second friend after the first link dropped. Alice and Bob both hold
    release 5 (imported: a 4 MB document, 64 chunks); Bob's node is down.
    Carol messages Alice and is offered it: nothing is fetched until she
    approves (`ash update download CODE` with the lab approval). Once her
    bitmap holds 16 chunks Alice's node is killed (the link drops mid
    download); Carol keeps what arrived. Bob's node starts, Carol messages
    him and is offered the same release by him: she fetches only the chunks
    she lacks (the bitmap only grows), the whole release verifies, and
    `ash update status` says it is ready to install. Nothing quarantined,
    no SEC_BUNDLE_FORGED."""
    env = updates_env(UPD_ENV, root)
    project = TestProject(root)
    blob = hashlib.shake_256(b's119').digest(64 * 61440 - 4096)
    manifest = project.release(5, {
        'bin/raven-node': b'#!/bin/sh\nexit 0\n',
        'docs/blob.bin': blob,
    })
    project.log(manifest)
    bundle = project.pack(5, manifest)
    a, b, c = Node('a', root, env=env), Node('b', root, env=env), Node('c', root, env=env)
    b_port = free_tcp_port()
    for n in (a, b, c):
        n.init()
        n.start(port=b_port if n is b else 0)
    b_dial = b.dial
    c.add_pinned(a, 'alice')
    c.add_pinned(b, 'bob')
    a.add_pinned(c, 'carol')
    b.add_pinned(c, 'carol')
    imports = [import_update(n, bundle).returncode for n in (a, b)]
    b.stop()
    sent_a = c.send('alice', 's119-to-alice')
    offered = wait_until(lambda: node_updates(c).get('offers') == 1, 60)
    early = wait_until(lambda: incoming_chunks(c)[1] > 0, 4)
    code = offer_code(c)
    approve = c.ash('update', 'download', code, extra_env=dict(RAVEN_LAB_UPDATE_AUTO_APPROVE='1'))
    seen = []
    t0 = time.time()
    while time.time() - t0 < 60:
        _, have = incoming_chunks(c)
        seen.append(have)
        if have >= 16:
            break
        time.sleep(0.05)
    a.stop(hard=True)
    _, at_drop = incoming_chunks(c)
    time.sleep(2)
    _, after_drop = incoming_chunks(c)
    b.start(port=b_port)
    sent_b = c.send('bob', 's119-to-bob')
    t1 = time.time()
    ready = None
    while time.time() - t1 < 120 and ready is None:
        _, have = incoming_chunks(c)
        seen.append(have)
        if node_updates(c).get('ready') == 1:
            ready = round(time.time() - t1, 1)
        time.sleep(0.2)
    digest, final = incoming_chunks(c)
    grows = all(x <= y for x, y in zip(seen, seen[1:]))
    status = c.ash('update', 'status').stdout
    verified = bool(digest) and (c.dir / 'updates' / 'incoming' / digest / 'verified').exists()
    kinds = ledger_kinds(c)
    upd = node_updates(c)
    for n in (b, c):
        n.stop()
    return dict(
        ok=imports == [0, 0] and status_word(sent_a[1]) == 'DELIVERED'
        and offered is not None and early is None and approve.returncode == 0
        and '(lab: approved by RAVEN_LAB_UPDATE_AUTO_APPROVE)' in approve.stdout
        and 0 < at_drop < 64 and at_drop <= after_drop < 64 and b_dial.endswith(f':{b_port}')
        and status_word(sent_b[1]) == 'DELIVERED' and ready is not None and final == 64
        and grows and verified and 'is downloaded and checked: raven update install' in status
        and upd.get('quarantined') == 0 and SEC_BUNDLE_FORGED not in kinds,
        imports=imports, sent_to_alice=status_word(sent_a[1]), offered_s=took(offered),
        fetched_before_approval=early is not None, approve=approve.stdout[-300:],
        chunks_when_alice_dropped=at_drop, chunks_2s_later=after_drop,
        sent_to_bob=status_word(sent_b[1]), ready_after_bob_s=ready, chunks_final=final,
        bitmap_only_grew=grows, verified=verified, update_status=status[-400:],
        updates=upd, event_kinds=sorted(set(kinds)))


def login_item_fixture(data_dir: Path, items: Path, tools: Path, log: Path) -> str:
    """Raven's own login item for `data_dir` as the installer writes it
    (enough of it for ash's node_control) in `items`, and fake `launchctl` /
    `systemctl` in `tools` that write their arguments to `log`: the item's
    file name on this system."""
    items.mkdir(parents=True, exist_ok=True)
    tools.mkdir(parents=True, exist_ok=True)
    data = str(data_dir.resolve())
    if sys.platform == 'darwin':
        name = 'com.raven.raven-node.plist'
        text = ('<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n'
                '  <key>Label</key><string>com.raven.raven-node</string>\n'
                '  <key>ProgramArguments</key>\n  <array>\n'
                '    <string>/opt/raven/bin/raven-node</string>\n'
                '    <string>service</string>\n    <string>--data-dir</string>\n'
                f'    <string>{data}</string>\n  </array>\n'
                '  <key>KeepAlive</key><true/>\n</dict>\n</plist>\n')
    else:
        name = 'raven-node.service'
        text = ('[Unit]\nDescription=Raven node\n\n[Service]\n'
                f'ExecStart="/opt/raven/bin/raven-node" service --data-dir "{data}"\n')
    (items / name).write_text(text)
    for tool in ('launchctl', 'systemctl'):
        path = tools / tool
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$(basename \"$0\") $*\" >> '{log}'\n")
        path.chmod(0o755)
    return name


def erase_on_a_terminal(node: Node, env: dict) -> tuple[int | None, str]:
    """`raven erase` for `node` in a pseudo-terminal (it takes its word only
    from a terminal): waits for the question, pauses as a person reading it
    would, then types `erase`. Its exit code (None: it did not end and was
    killed) and what the terminal showed."""
    import pty
    import select
    master, slave = pty.openpty()
    proc = subprocess.Popen([node.ash_bin, '--data-dir', str(node.dir), 'erase'],
                            stdin=slave, stdout=slave, stderr=slave, env=env,
                            start_new_session=True)
    os.close(slave)
    screen = bytearray()

    def read(seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select([master], [], [], 0.1)
            if not ready:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:
                return
            if not chunk:
                return
            screen.extend(chunk)

    t0 = time.time()
    while (b'Type erase to confirm:' not in screen and proc.poll() is None
           and time.time() - t0 < 60):
        read(0.2)
    if b'Type erase to confirm:' in screen:
        read(1.2)
        os.write(master, b'erase\n')
        t1 = time.time()
        while proc.poll() is None and time.time() - t1 < 120:
            read(0.2)
        read(0.3)
    code = proc.poll()
    if code is None:
        proc.kill()
        proc.wait(5)
    os.close(master)
    return code, screen.decode(errors='replace')


def s117_phase6_imports(a: Node, b: Node, root: Path) -> 'TestProject':
    """s117 under RAVEN_FAULT_PHASE6=1: Bob imports notice #1 and release 5,
    Alice release 4 (each from the test project); Alice's next link with Bob
    brings her the notice and Bob's offer, which the lab approval downloads."""
    project = TestProject(root)
    notice = project.advisory(1, 'Update Raven when you can (s117).')
    four = project.release(4, {'bin/raven-node': b'#!/bin/sh\nexit 0\n'})
    five = project.release(5, {'bin/raven-node': b'#!/bin/sh\nexit 0\n'})
    log = project.log(notice, four, five)
    for node, path, with_log in ((b, notice, log), (b, project.pack(5, five), None),
                                 (a, project.pack(4, four), None)):
        r = import_update(node, path, with_log)
        assert r.returncode == 0, r.stdout + r.stderr
    return project


def s117_phase6_files(a: Node) -> dict:
    """The Phase 6 files Alice's profile holds once her notice and download
    from Bob are in and their RRH1 frames agreed a pair seed (lane 6b's
    P6.38; s117 under RAVEN_FAULT_PHASE6=1)."""
    took_s = wait_until(lambda: node_updates(a).get('advisory_serial') == 1
                        and node_updates(a).get('ready') == 1
                        and (a.dir / 'pair_seeds.json').exists(), 60)
    names = ('updates/state', 'updates/downloads', 'updates/staged/4', 'updates/incoming',
             'security_events.sqlite', 'capability_floor.json', 'pair_seeds.json')
    held = {n: (a.dir / n).exists() for n in names}
    return dict(ok=took_s is not None and all(held.values()), took_s=took(took_s), held=held)


def s117_erase_one_profile(root: Path) -> dict:
    """Privacy pack PP.16 (`raven erase`, release behaviour, no gate; was
    Phase 6b's s97), real processes. Alice and Bob exchange, Bob and Carol
    are friends too. Alice runs `raven erase` in a pseudo-terminal with her
    node running and Raven's own login item for her profile (the lab's
    folders, fake launchctl / systemctl): her node stops (SIGTERM to the pid
    its Status reports), the item is unloaded, turned off and removed through
    the shims, and nothing of her profile is left. Bob's node (the same
    process) and Carol still exchange both ways, each message once.
    With RAVEN_FAULT_PHASE6=1 (Phase 6b P6.51) every node runs with every
    Phase 6 switch on (PHASE6_ENV) and Alice's profile holds the Phase 6
    files before the erase (s117_phase6_files): a notice and a release she
    took from Bob, a release she imported, her security ledger, capability
    floor and pair seeds. Nothing of them is left either."""
    env = updates_env(PHASE6_ENV, root) if PHASE6 else None
    a, b, c = Node('a', root, env=env), Node('b', root, env=env), Node('c', root, env=env)
    for node in (a, b, c):
        node.init()
        node.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    b.add_pinned(c, 'carol')
    c.add_pinned(b, 'bob')
    project = s117_phase6_imports(a, b, root) if PHASE6 else None
    to_b = a.send('bob', 's117-from-alice')
    to_a = b.send('alice', 's117-from-bob')
    phase6 = s117_phase6_files(a) if project else {}
    b_pid = b.proc.pid
    items, tools = root / 'login-items', root / 'login-tools'
    log = root / 'login-calls.log'
    item = login_item_fixture(a.dir, items, tools, log)
    env = dict(a.env, RAVEN_LAB_LOGIN_ITEM_ROOT=str(items),
               RAVEN_LAB_LOGIN_ITEM_TOOLS=str(tools))
    t0 = time.time()
    code, screen = erase_on_a_terminal(a, env)
    took = round(time.time() - t0, 1)
    try:
        a.proc.wait(10)
    except subprocess.TimeoutExpired:
        pass
    a_node_ended = a.proc.poll() is not None
    if a_node_ended:
        a.proc = None
    profile_left = a.dir.exists()
    item_left = (items / item).exists()
    calls = log.read_text().splitlines() if log.exists() else []
    if sys.platform == 'darwin':
        want = ['launchctl bootout gui/', 'launchctl disable gui/']
    else:
        want = ['systemctl --user stop raven-node.service',
                'systemctl --user disable --now raven-node.service',
                'systemctl --user daemon-reload']
    calls_ok = len(calls) == len(want) and all(c.startswith(w) for c, w in zip(calls, want))
    b_to_c = b.send('carol', 's117-bob-after')
    c_to_b = c.send('bob', 's117-carol-after')
    time.sleep(1)
    once = dict(carol=count(c.inbox(), 's117-bob-after'),
                bob=count(b.inbox(), 's117-carol-after'),
                bob_keeps=count(b.inbox(), 's117-from-alice'))
    b_same = b.proc is not None and b.proc.poll() is None and b.proc.pid == b_pid
    erased = 'Erased: identity, friends, chats, waiting messages and ' in screen
    return dict(
        ok=to_b[0] == 0 and status_word(to_b[1]) == 'DELIVERED' and to_a[0] == 0
        and status_word(to_a[1]) == 'DELIVERED' and code == 0 and erased and a_node_ended
        and not profile_left and not item_left and calls_ok
        and b_to_c[0] == 0 and status_word(b_to_c[1]) == 'DELIVERED'
        and c_to_b[0] == 0 and status_word(c_to_b[1]) == 'DELIVERED'
        and all(n == 1 for n in once.values()) and b_same
        and (not PHASE6 or phase6.get('ok', False)),
        phase6=phase6, before=(status_word(to_b[1]), status_word(to_a[1])), erase_exit=code,
        erase_s=took, erased_line=erased, screen=screen[-600:], a_node_ended=a_node_ended,
        profile_left=profile_left, login_item_left=item_left, shim_calls=calls,
        after=(status_word(b_to_c[1]), status_word(c_to_b[1])), exactly_once=once,
        bob_same_node=b_same)


def s122_clear_sticks_across_session_expiry(root: Path) -> dict:
    """Privacy pack PP.8 (by default since PP.19, with the cutoff gates open
    under RAVEN_FAULT_OFFLINE=1; LabClock on both profiles). Bob sends Alice
    three messages; Alice deletes her chat with Bob (`raven chats delete
    --yes`): her history and `raven inbox` hold none of them.
    Bob's newest envelope comes again as it was (`ash lab lan-dial-sealed`,
    as if its ACK was lost): Alice answers it with an ACK and shows nothing.
    With Alice's node down both clocks move 25 h ahead (their session ended a
    day after its PairInit); her node starts again and its prune archives
    and drops the session: none of the three is back. Bob's next message (a
    new secure connection) shows once."""
    import base64
    ca, cb = LabClock(root / 'alice.clock'), LabClock(root / 'bob.clock')
    a = Node('a', root, env=ca.env(ENV))
    b = Node('b', root, env=cb.env(ENV))
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    texts = ('s122-m1', 's122-m2', 's122-m3')

    def shown() -> list:
        """The three wherever Alice could see them: history, then inbox."""
        bodies, inbox = history_bodies(a.dir), a.inbox()
        return [t for t in texts if any(t in body for body in bodies)] + [
            t for t in texts if count(inbox, t)]

    sent = [status_word(b.send('alice', t)[1]) for t in texts]
    before = shown()
    deleted = a.ash('chats', 'delete', '--petname', 'Bob', '--yes')
    after_delete = shown()
    envelope = last_sent_envelope(b)
    since = log_size(a)
    resend = None
    if envelope is not None:
        resend = b.ash('lab', 'lan-dial-sealed', '--dial', a.dial, '--expected-pub-hex', a.pub,
                       '--envelope-b64', base64.b64encode(envelope).decode())
    answered = wait_log(a, DELETED_AGAIN, 10, since)
    after_resend = shown()
    a_port = int(a.dial.rsplit(':', 1)[1])
    a.stop()
    ca.advance(25 * 3600 * 1000)
    cb.advance(25 * 3600 * 1000)
    a.start(port=a_port)
    pruned = wait_for(lambda: session_heads(a) == 0, 30)
    after_expiry = shown()
    back = b.send('alice', 's122-after')
    got = wait_inbox(a, 's122-after', 20)
    time.sleep(2)
    once = count(a.inbox(), 's122-after')
    in_history = sum(1 for body in history_bodies(a.dir) if 's122-after' in body)
    return dict(
        ok=sent == ['DELIVERED'] * 3 and before == list(texts) * 2
        and deleted.returncode == 0
        and 'Deleted your chat with Bob on this computer (3 messages).' in deleted.stdout
        and after_delete == [] and resend is not None and resend.returncode == 0
        # Alice's RLB1 offer and her ACK (without the fix: an error, no ACK).
        and 'O6_M3_LAN_DIAL_SEALED=OK replies=2' in resend.stdout
        and answered is not None and after_resend == []
        and pruned is not None and after_expiry == []
        and status_word(back[1]) == 'DELIVERED' and got is not None and once == 1
        and in_history == 1,
        sent=sent, shown_before=before, delete=(deleted.returncode, deleted.stdout[-200:]),
        shown_after_delete=after_delete,
        resend=None if resend is None else (resend.returncode, resend.stdout[:80]),
        answered_s=answered, shown_after_resend=after_resend, pruned_s=pruned,
        shown_after_expiry=after_expiry, back=(back[0], status_word(back[1])),
        after_s=got, after_in_inbox=once, after_in_history=in_history)


def learned_text(node: Node) -> str:
    """`node`'s learned_routes.json as JSON text (sealed or plain), '' when
    there is none."""
    raw = sealed_plain(node.dir, 'learned_routes.json')
    return raw.decode() if raw is not None else ''


# What a forgotten tombstone keeps (privacy pack PP.7, OD-C10).
BARE_TOMBSTONE = {'pub_hex', 'generation', 'received_at_ms', 'expires_at_ms', 'via'}
DAY_MS = 86_400_000


def s123_addresses_forgotten_after_30_days(root: Path) -> dict:
    """Privacy pack PP.7 (RAVEN_FAULT_OFFLINE=1 or RAVEN_FAULT_PRIVACY=1;
    LabClock on both profiles, route hints on). Bob sends to Alice: her
    sealed data dir shows his sighting and his route hints (read through the
    harness's RMS1 opener). With Alice's node down both clocks move 31 days
    ahead; her next command (no raven-node answers: ash prunes at its start)
    leaves no sighting of Bob and no learned address of his on her disk (at
    most a bare tombstone, times to the day), and his saved route in her
    book stays. Alice starts again on her port; Bob sends to her again
    (their secure connection ended a day after it was set up, so a new one),
    and his sighting is learned again; Alice's message to Bob is then
    delivered exactly once. Second half (PP.9): Alice keeps chats for 30
    days (`raven chats keep 30d`; the retention grace overridden to 0):
    Bob's first message is in her history and the prune 31 days on took it
    out; with her node down again, 29 days on one prune keeps the messages
    of that day (Bob's second, her own), 2 more days on the next takes
    Bob's."""
    ca, cb = LabClock(root / 'alice.clock'), LabClock(root / 'bob.clock')
    a = Node('a', root, env=dict(ca.env(ENV_HINTS), RAVEN_LAB_RETENTION_GRACE_MS='0'))
    b = Node('b', root, env=cb.env(ENV_HINTS))
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    keep_set = a.ash('chats', 'keep', '30d').returncode == 0
    hello = b.send('alice', 's123-hello')
    hello_kept = 's123-hello' in history_bodies(a.dir)

    def b_rows() -> list:
        return [r for r in learned_rows(a)
                if isinstance(r, dict) and r.get('pub_hex', '').lower() == b.pub.lower()]

    t0 = time.time()
    while time.time() - t0 < 10 and not any('lan' in r for r in b_rows()):
        time.sleep(0.5)
    seen_before = lan_seen_ip(a, b)
    learned_before = [sorted(r) for r in b_rows()]
    sealed = {name: (a.dir / name).read_bytes().startswith(b'RMS1')
              for name in ('lan_seen.json', 'learned_routes.json')
              if (a.dir / name).is_file()}
    a_port = int(a.dial.rsplit(':', 1)[1])
    a.stop()
    ca.advance(31 * DAY_MS)
    cb.advance(31 * DAY_MS)
    pruned = a.ash('outbox', 'list')
    seen_after = lan_seen_ip(a, b)
    rows_after = b_rows()
    text_after = learned_text(a)
    bare = all(set(r) <= BARE_TOMBSTONE
               and all(r.get(k, 1) % DAY_MS == 0
                       for k in ('generation', 'received_at_ms', 'expires_at_ms'))
               for r in rows_after)
    book_keeps = b.dial in book_plain(a.dir).decode()
    hello_gone = 's123-hello' not in history_bodies(a.dir)
    a.start(port=a_port)
    back = b.send('alice', 's123-back')
    seen_again = lan_seen_ip(a, b)
    rc, out, _ = a.send('bob', 's123-m1')
    got = wait_inbox(b, 's123-m1', 20)
    time.sleep(2)
    once = count(b.inbox(), 's123-m1')
    # PP.9, second half: Alice's node down again; 29 days on one prune keeps
    # the chats of day 31, 2 more days on the next one takes them.
    a.stop()
    ca.advance(29 * DAY_MS)
    young = a.ash('outbox', 'list')
    kept_29 = history_bodies(a.dir)
    ca.advance(2 * DAY_MS)
    old = a.ash('outbox', 'list')
    left_31 = history_bodies(a.dir)
    return dict(
        ok=hello[0] == 0 and status_word(hello[1]) == 'DELIVERED'
        and seen_before == '127.0.0.1' and any('lan' in r for r in learned_before)
        and all(sealed.values()) and len(sealed) == 2
        and pruned.returncode == 0 and seen_after is None and bare
        and '127.0.0.1' not in text_after and book_keeps
        and back[0] == 0 and status_word(back[1]) == 'DELIVERED'
        and seen_again == '127.0.0.1'
        and rc == 0 and got is not None and once == 1
        and keep_set and hello_kept and hello_gone
        and young.returncode == 0 and 's123-back' in kept_29 and 's123-m1' in kept_29
        and old.returncode == 0 and 's123-back' not in left_31,
        hello=(hello[0], status_word(hello[1])), seen_before=seen_before,
        learned_fields_before=learned_before, sealed=sealed,
        seen_after_31_days=seen_after, learned_after_31_days=rows_after,
        bare_tombstone=bare, book_keeps_saved_route=book_keeps,
        back=(back[0], status_word(back[1]), back[1][-300:]), seen_again=seen_again,
        send=(rc, status_word(out)), delivered_s=got, exactly_once=once,
        keep_30d_set=keep_set, hello_in_history=hello_kept, hello_gone_after_31_days=hello_gone,
        history_after_29_days=kept_29, history_after_31_days=left_31,
        outbox=a.outbox()[-300:])



# Privacy pack PP.18: what the new build says (the UX copy).
UNSEALED_TEXT = ('This profile is not encrypted (you ran `raven privacy unseal`). To encrypt '
                 'it again: `raven privacy seal-now`.')
OLDER_BUILD_TEXT = ('An older Raven version wrote some of this profile\'s files unencrypted. '
                    'Raven encrypted them again.')
RESTART_TEXT = 'Raven was updated. Restart Raven so it can finish the update:'
# What the book error of a build before the pack on a sealed contacts.json
# names (`contacts.json: stream did not contain valid UTF-8` in the PP.1
# snapshot, `contacts.json corrupt ...` where it parses).
OLD_BOOK_ERROR = 'contacts.json'
# Files of a sealed profile an older build may write in plain (R06, R07):
# advisory files it rewrites, its own fresh pins, a fresh owed-ACK store
# beside the one it set aside, and the files plain by design (the legacy
# bridge queues, the settings).
OLDER_MAY_WRITE = re.compile(
    r'^(lan_seen\.json|learned_routes\.json|route_memory\.json|lan_noise_pins\.json'
    r'|owed_acks\.sqlite|owed_acks\.sqlite\.corrupt-\d+|queue\.sqlite|forward_queue\.sqlite'
    r'|node_policy\.json)$')


def is_rms1(path: Path) -> bool:
    """`path` exists and is sealed (RMS1)."""
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'RMS1'
    except FileNotFoundError:
        return False


def profile_files(d: Path) -> dict:
    """The profile's files and their bytes, but its lock databases, SQLite
    sidecars, sockets and logs (what any run touches)."""
    out = {}
    for p in sorted(d.rglob('*')):
        if not p.is_file():
            continue
        name = str(p.relative_to(d))
        if (name.endswith(('.lock.sqlite', '-wal', '-shm', '.log', '.sock', '.lock'))
                or '.tmp.' in name):
            continue
        out[name] = p.read_bytes()
    return out


def start_fail_closed(node: Node, port: int) -> str:
    """Start `node`'s raven-node on 127.0.0.1:`port` and wait (30 s at most)
    until it answers IPC and its LAN listener either listens or says it did
    not start: an older build on a sealed profile does not (s124). What its
    log said: `listening`, or the failure line."""
    node.starts += 1
    log = open(node.log_path, 'a')
    log.write(f'\n===== start #{node.starts} port={port} t={time.time():.1f}\n')
    log.flush()
    node.proc = subprocess.Popen(
        [node.node_bin, 'service', '--data-dir', str(node.dir),
         '--lan-listen', f'127.0.0.1:{port}', '--ble-listen', '127.0.0.1:0'],
        stdout=log, stderr=subprocess.STDOUT, env=node.env,
    )
    marker = f'===== start #{node.starts} '
    deadline = time.time() + 30
    while time.time() < deadline:
        text = node.log_path.read_text(errors='replace')
        text = text[text.rfind(marker):]
        failed = re.search(r'^(?:\S+Z )?lan_direct failed: [^\n]*$', text, re.M)
        listening = re.search(r'lan_direct: listen\S*.*?(\S+:\d+)[ \t]*\n', text)
        if (failed or listening) and node.ash('ipc-ping', timeout=10).returncode == 0:
            return 'listening' if listening else failed.group(0)
        if node.proc.poll() is not None:
            raise RuntimeError(f'{node.name} node exited: {text[-2000:]}')
        time.sleep(0.1)
    raise RuntimeError(f'{node.name} node did not answer')


def s124_downgrade_and_back(root: Path) -> dict:
    """Privacy pack PP.18, the tested downgrade path (needs
    RAVEN_FAULT_PRIVACY_OLD_BIN, the build before the pack that PP.1 kept; M0
    noise pins on in both builds). 1: A (old build, plain profile) and B (this
    build, sealed) exchange. 2: A runs this build: its profile is sealed at
    its node's start, both ways deliver. 3: A runs the old build again
    without unsealing: its `contact list` fails with the book error, its
    node admits nobody (B's message stays QUEUED), and contacts.json,
    lan_noise_pins.rms and blocked_pubs.json stay byte for byte (what it
    wrote in plain is recorded). 4: A runs this build: it seals again what
    the old one wrote (`raven status` says so once when it wrote any of
    them), keeps its sealed pins, and B's queued message arrives exactly once
    (A's first message wakes B's queue). 5: `raven privacy unseal --yes`
    (it stops A's node) and one more command of this build (`raven status`)
    seal nothing; the old build then exchanges both ways. 6: `raven privacy
    seal-now`: sealed again, both ways deliver. 7 (R11): C runs the old
    build's node on a plain profile; a `raven status` of this build migrates
    nothing and says the restart line, and C's old node still admits B."""
    if not PRIVACY_OLD_BIN:
        raise RuntimeError('s124 needs RAVEN_FAULT_PRIVACY_OLD_BIN (the build before the '
                           'privacy pack)')
    items, tools = root / 'login-items', root / 'login-tools'
    items.mkdir()
    tools.mkdir()
    env = dict(ENV, RAVEN_LAB_NOISE_PIN='1', RAVEN_LAB_LOGIN_ITEM_ROOT=str(items),
               RAVEN_LAB_LOGIN_ITEM_TOOLS=str(tools))
    old_ash, old_node = (str(Path(PRIVACY_OLD_BIN) / 'ash'),
                         str(Path(PRIVACY_OLD_BIN) / 'raven-node'))

    def build(node: Node, old: bool) -> None:
        node.ash_bin, node.node_bin = (old_ash, old_node) if old else (ASH, NODE)

    def exchange(tag: str) -> dict:
        sends = (a.send('bob', f'{tag}-a2b'), b.send('alice', f'{tag}-b2a'))
        got = (wait_inbox(b, f'{tag}-a2b', 60), wait_inbox(a, f'{tag}-b2a', 60))
        time.sleep(1)
        once = count(b.inbox(), f'{tag}-a2b') == 1 and count(a.inbox(), f'{tag}-b2a') == 1
        return dict(ok=all(t is not None for t in got) and once,
                    sends=[status_word(out) for _, out, _ in sends],
                    took=[None if t is None else round(t, 1) for t in got])

    phases = {}
    a, b = Node('a', root, env, PRIVACY_OLD_BIN), Node('b', root, env)
    a.init()
    b.init()
    a.start()
    b.start()
    port = int(a.dial.rsplit(':', 1)[1])
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    # A stranger on A's block list (as an older build keeps it).
    (a.dir / 'blocked_pubs.json').write_text(json.dumps({'pub_hex': ['ee' * 32]}, indent=2))
    one = exchange('s124-p1')
    phases['1_old_and_new'] = dict(
        one, a_plain=not is_rms1(a.dir / 'contacts.json'),
        b_sealed=is_rms1(b.dir / 'contacts.json'))
    phases['1_old_and_new']['ok'] = (one['ok'] and phases['1_old_and_new']['a_plain']
                                     and phases['1_old_and_new']['b_sealed'])

    # 2: A on this build: sealed at its node's start.
    a.stop()
    build(a, old=False)
    a.start(port)
    two = exchange('s124-p2')
    sealed_files = {n: is_rms1(a.dir / n) for n in
                    ('contacts.json', 'blocked_pubs.json', 'lan_noise_pins.rms')}
    phases['2_a_new_seals'] = dict(two, sealed=sealed_files,
                                   ok=two['ok'] and all(sealed_files.values()))

    # 3: A on the old build again, without unsealing.
    a.stop()
    build(a, old=True)
    before = profile_files(a.dir)
    kept = ('contacts.json', 'lan_noise_pins.rms', 'blocked_pubs.json')
    listing = a.ash('contact', 'list')
    # Its node fails closed: it answers IPC but its LAN listener does not
    # start (the sealed device registry does not read), or admits nobody.
    refused = start_fail_closed(a, port)
    queued = b.send('alice', 's124-p3-b2a')
    time.sleep(8)
    in_a = count(a.ash('inbox').stdout, 's124-p3-b2a')
    a.stop()
    after = profile_files(a.dir)
    wrote_plain = sorted(n for n, data in after.items()
                         if before.get(n) != data and data[:4] != b'RMS1')
    phases['3_old_on_sealed'] = dict(
        ok=listing.returncode != 0 and OLD_BOOK_ERROR in (listing.stdout + listing.stderr)
        and status_word(queued[1]) == 'QUEUED' and in_a == 0
        and all(before.get(n) == after.get(n) and n in before for n in kept)
        and not [n for n in wrote_plain if not OLDER_MAY_WRITE.match(n)],
        contact_list=(listing.returncode, (listing.stdout + listing.stderr)[-200:]),
        b_send=status_word(queued[1]), delivered_to_old=in_a, old_node_listener=refused,
        kept_identical={n: before.get(n) == after.get(n) for n in kept},
        wrote_plain=wrote_plain,
        unexpected_plain=[n for n in wrote_plain if not OLDER_MAY_WRITE.match(n)])

    # 4: this build again: sealed again, the queued message once.
    build(a, old=False)
    a.start(port)
    resealed = {n: is_rms1(a.dir / n) for n in wrote_plain
                if n in ('lan_seen.json', 'learned_routes.json', 'route_memory.json')}
    pins_plain_gone = not (a.dir / 'lan_noise_pins.json').exists()
    asides_left = sorted(p.name for p in a.dir.glob('owed_acks.sqlite.corrupt-*'))
    status_four = a.ash('status')
    noted = OLDER_BUILD_TEXT in status_four.stdout + status_four.stderr
    leftovers = [n for n in wrote_plain
                 if n in ('lan_seen.json', 'learned_routes.json', 'route_memory.json',
                          'lan_noise_pins.json')]
    wake = a.send('bob', 's124-p4-a2b')
    took = wait_inbox(a, 's124-p3-b2a', 60)
    time.sleep(2)
    once = count(a.inbox(), 's124-p3-b2a')
    phases['4_new_again'] = dict(
        ok=all(resealed.values()) and pins_plain_gone and is_rms1(a.dir / 'lan_noise_pins.rms')
        and not asides_left and (noted or not leftovers) and took is not None and once == 1
        and wait_inbox(b, 's124-p4-a2b', 30) is not None,
        resealed=resealed, pins_plain_gone=pins_plain_gone, asides_left=asides_left,
        older_note=noted, leftovers=leftovers, wake_send=status_word(wake[1]),
        queued_delivered_s=None if took is None else round(took, 1), queued_once=once)

    # 5: the way back, then the old build.
    unseal = a.ash('privacy', 'unseal', '--yes')
    node_gone = False
    if a.proc is not None:
        try:
            a.proc.wait(10)
            node_gone = True
        except subprocess.TimeoutExpired:
            pass
        a.proc = None if node_gone else a.proc
    status_five = a.ash('status')
    plain_now = {n: not is_rms1(a.dir / n) for n in
                 ('contacts.json', 'blocked_pubs.json', 'lan_seen.json')}
    no_key = not (a.dir / 'meta_key.rmk').exists()
    pins_back = (a.dir / 'lan_noise_pins.json').exists() and not (
        a.dir / 'lan_noise_pins.rms').exists()
    history_v1 = (a.dir / 'chat_history.json').read_bytes()[:8] == b'RVNHIST1'
    build(a, old=True)
    old_list = a.ash('contact', 'list')
    a.start(port)
    five = exchange('s124-p5')
    a.stop()
    phases['5_unseal_then_old'] = dict(
        ok=unseal.returncode == 0
        and 'Done. You can now start the older Raven version.' in unseal.stdout
        and node_gone and status_five.returncode == 0 and UNSEALED_TEXT in status_five.stderr
        and all(plain_now.values()) and no_key and pins_back and history_v1
        and old_list.returncode == 0 and five['ok'],
        unseal=(unseal.returncode, unseal.stdout[-300:], unseal.stderr[-300:]),
        node_stopped=node_gone, unsealed_line=UNSEALED_TEXT in status_five.stderr,
        plain=plain_now, key_file_gone=no_key, pins_back=pins_back, history_rvnhist1=history_v1,
        old_contact_list=old_list.returncode, exchange=five)

    # 6: this build, sealed again on request.
    build(a, old=False)
    seal_now = a.ash('privacy', 'seal-now')
    sealed_again = is_rms1(a.dir / 'contacts.json')
    a.start(port)
    six = exchange('s124-p6')
    phases['6_seal_now'] = dict(
        ok=seal_now.returncode == 0 and sealed_again and six['ok']
        and 'encrypted on this computer again' in seal_now.stdout,
        seal_now=(seal_now.returncode, seal_now.stdout[-300:], seal_now.stderr[-300:]),
        sealed_again=sealed_again, exchange=six)
    a.stop()

    # 7 (R11): an old node runs on a plain profile; this build's command
    # migrates nothing.
    c = Node('c', root, env, PRIVACY_OLD_BIN)
    c.init()
    c.start()
    c.add_pinned(b, 'bob')
    b.add_pinned(c, 'carol')
    first = b.send('carol', 's124-p7-first')
    got_first = wait_inbox(c, 's124-p7-first', 60)
    status_new = subprocess.run([ASH, '--data-dir', str(c.dir), 'status'], capture_output=True,
                                text=True, timeout=120, env=env)
    # privacy.json may note the day the restart line was said; no mode.
    recorded = (json.loads((c.dir / 'privacy.json').read_text())
                if (c.dir / 'privacy.json').exists() else {})
    untouched = (not is_rms1(c.dir / 'contacts.json') and not (c.dir / 'meta_key.rmk').exists()
                 and recorded.get('mode') in (None, 'plain'))
    later = b.send('carol', 's124-p7-after')
    got_later = wait_inbox(c, 's124-p7-after', 60)
    c.stop()
    phases['7_old_node_interlock'] = dict(
        ok=got_first is not None and untouched and RESTART_TEXT in status_new.stderr
        and got_later is not None,
        migrated_nothing=untouched, restart_line=RESTART_TEXT in status_new.stderr,
        b_to_old_node=[status_word(first[1]), status_word(later[1])])
    b.stop()
    return dict(ok=all(p['ok'] for p in phases.values()), old_build=PRIVACY_OLD_BIN != '',
                **phases)


# carrier_matrix C87's rules for a copied data dir: the lab key backends'
# files stand in for the keystore (debug builds only: a release build keeps
# those secrets in the keychain), and SQLite stores are read as raw bytes.
LAB_KEYSTORE_FILE = re.compile(r'^(indexed-session-secrets/.*|prekey_lifecycle\.protected)$')
SQLITE_SUFFIXES = ('.sqlite', '.sqlite3', '.sqlite-wal', '.sqlite-shm', '.sqlite-journal',
                   '.sqlite3-wal', '.sqlite3-shm', '.sqlite3-journal')
# Any multiaddr naming a PeerId, for `whoami --card --via` (nothing is dialled
# or saved; it only makes the card name this profile's own PeerId).
CARD_VIA = '/ip4/192.0.2.1/tcp/9/p2p/12D3KooWJWoaqZhDaoEFshF7Rh1bpY9ohihFhzcW6d69Lr2NASuq'


def copy_files(src: Path, dst: Path) -> None:
    """Every regular file below `src` copied to `dst` (folders made; sockets
    and the like left out), as a copied laptop folder would hold it."""
    for p in sorted(src.rglob('*')):
        if p.is_file() and not p.is_symlink():
            target = dst / p.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, target)


def peer_id_of(node: Node) -> str:
    """`node`'s own PeerId (the `p2p=` of its card; no p2p host needed)."""
    out = node.ash('whoami', '--card', '--via', CARD_VIA).stdout
    m = re.search(r' p2p=(12D3KooW\w+)', out)
    assert m, out
    return m.group(1)


def record_key_of(init_pub: bytes, init_addr: str, resp_pub: bytes, resp_addr: str,
                  init_id: bytes) -> bytes:
    """The session store's record key as anyone can work it out from public
    values: an unkeyed SHA-256 of the domain, the length-prefixed profile id
    and both rvn1 addresses, then both device keys and the init_id."""
    import hashlib
    h = hashlib.sha256(b'rvn1/indexed-session/record-key/v1')
    for v in (b'ATSAM/indexed-session/v1', init_addr.encode(), resp_addr.encode()):
        h.update(len(v).to_bytes(4, 'big') + v)
    h.update(init_pub + resp_pub + init_id)
    return h.digest()


def record_keys_naming(profile: Path, own: Node, friend: Node) -> list:
    """carrier_matrix C87's record-key check (review B-sealed-stores-1): every
    16-byte value of a clear column of `profile`'s session store (raw, or 32
    hex digits) and every 32-hex run of a file name below `profile`, taken as
    the init_id of a session between `own` and `friend` in either role (a
    primary device: the address and the device key come from the key). Each
    one whose record key the store holds is a finding: it tells which friend
    that session is with."""
    import sqlite3
    path = profile / 'indexed_sessions.sqlite'
    if not path.exists():
        return []
    candidates = set()
    try:
        con = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=10)
        try:
            stored = {bytes(r[0]) for r in
                      con.execute('SELECT record_key FROM indexed_session_heads')}
            tables = [r[0] for r in
                      con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
            for table in tables:
                for row in con.execute(f'SELECT * FROM "{table}"'):
                    for v in row:
                        if isinstance(v, (bytes, memoryview)) and len(v) == 16:
                            candidates.add(bytes(v))
                        elif isinstance(v, str) and re.fullmatch(r'[0-9a-fA-F]{32}', v):
                            candidates.add(bytes.fromhex(v))
        finally:
            con.close()
    except sqlite3.Error as e:
        return [f'indexed_sessions.sqlite: not readable for the record-key check ({e})']
    for p in profile.rglob('*'):
        name = p.relative_to(profile).as_posix()
        for i in range(len(name) - 31):
            if re.fullmatch(r'[0-9a-fA-F]{32}', name[i:i + 32]):
                candidates.add(bytes.fromhex(name[i:i + 32]))
    me, them = bytes.fromhex(own.pub), bytes.fromhex(friend.pub)
    roles = ((me, own.address, them, friend.address), (them, friend.address, me, own.address))
    return [f'indexed_sessions.sqlite: a record key names the friend (init_id {c.hex()})'
            for c in sorted(candidates) for role in roles
            if record_key_of(*role, c) in stored]


def friend_metadata_leaks(profile: Path, friend: Node, names: tuple, dial: str,
                          peer_id: str, message_ids: list, own: Node | None = None) -> list:
    """carrier_matrix C87's check over `profile` as it lies on disk (no node
    running): what names `friend` there. No file holds the friend's key (hex
    in either case, base64 with and without padding, URL-safe), rvn1
    address, PeerId, LAN address, petname or tag (`names`) or the loopback IP;
    no file name names the key; and every SQLite store and sidecar (WAL and
    free pages included) holds none of those as bytes, nor the raw key, nor
    a message id of `message_ids` (hex either case, raw). With `own` (the
    profile's own node), no session record key names the friend either
    (`record_keys_naming`). The lab key backends' files are left out. Each
    finding as `file: what`."""
    import base64
    key = bytes.fromhex(friend.pub)
    texts = [friend.pub.lower(), friend.pub.upper(), base64.b64encode(key).decode(),
             base64.b64encode(key).decode().rstrip('='),
             base64.urlsafe_b64encode(key).decode().rstrip('='),
             friend.address, peer_id, dial, *names, '127.0.0.1']
    raw_needles = [('the raw key', key)]
    for mid in message_ids:
        raw_needles += [(f'message id {mid}', mid.lower().encode()),
                        (f'message id {mid} (upper case)', mid.upper().encode()),
                        (f'message id {mid} (raw)', bytes.fromhex(mid))]
    leaks = []
    for p in sorted(profile.rglob('*')):
        if not p.is_file():
            continue
        name = p.relative_to(profile).as_posix()
        if friend.pub.lower() in name.lower():
            leaks.append(f'{name}: its name names the key')
        if LAB_KEYSTORE_FILE.match(name):
            continue
        raw = p.read_bytes()
        found = [repr(t) for t in texts if t.encode() in raw]
        if name.endswith(SQLITE_SUFFIXES):
            found += [what for what, needle in raw_needles if needle in raw]
        leaks += [f'{name}: {what}' for what in found]
    if own is not None:
        leaks += record_keys_naming(profile, own, friend)
    return leaks


def s120_seal_migrates_an_old_profile(root: Path) -> dict:
    """Privacy pack PP.19 (needs RAVEN_FAULT_PRIVACY_OLD_BIN, the build before
    the pack that PP.1 kept; M0 noise pins and route hints on in both builds, so
    the old profiles hold pins, learned routes and a hint state too). 1: A
    and B on the old build (plain profiles) add each other and exchange two
    messages each way (a session, sightings, history); A also messages C
    once and then removes her (`contact remove`), which leaves the old
    build's send lock named by C's key behind. 2: B goes away and A's
    message to him waits in the old build's outbox; A stops. 3: both on
    this build, B on his old port first: each node seals its whole profile
    at its start (`raven-node at_rest: sealed N file(s)`, then `sealed`);
    before anything of this build sends, no file name below either profile
    names a friend, C included (review E-harness-docs-ci-1: nothing would
    ever send to her again); `raven privacy status --json` says sealed, no
    registered file plain and every SQLite store keyed; the old history is
    all there (RVNHIST2 now); the waiting message arrives exactly once (if
    it has not within 20 s, a message from B wakes A's queue); one more
    message each way; the session count before and after is recorded. 4:
    both nodes stopped, carrier_matrix C87's check over both data dirs finds
    nothing that names the friend, nor anything of A's that names C (the
    same check over a copy of each old profile, taken in 2, finds the
    friend in its contact book, and C's key in a file name of A's)."""
    if not PRIVACY_OLD_BIN:
        raise RuntimeError('s120 needs RAVEN_FAULT_PRIVACY_OLD_BIN (the build before the '
                           'privacy pack)')
    env = dict(ENV, RAVEN_LAB_NOISE_PIN='1', RAVEN_LAB_ROUTE_HINTS='1')
    a, b = Node('a', root, env, PRIVACY_OLD_BIN), Node('b', root, env, PRIVACY_OLD_BIN)
    # C, a friend A removes on the old build (review E-harness-docs-ci-1).
    c = Node('c', root, env, PRIVACY_OLD_BIN)
    tags = {'a': 'alicezq', 'b': 'bobzq', 'c': 'carolzq'}
    for n in (a, b, c):
        n.init()
        n.start()
    a.add_pinned(b, tags['b'])
    b.add_pinned(a, tags['a'])
    a.add_pinned(c, tags['c'])
    c.add_pinned(a, tags['a'])
    phases = {}

    # 1: the old build, plain profiles.
    sent, got = [], []
    for i in (1, 2):
        sent += [status_word(a.send(tags['b'], f's120-old-a2b-{i}')[1]),
                 status_word(b.send(tags['a'], f's120-old-b2a-{i}')[1])]
        got += [wait_inbox(b, f's120-old-a2b-{i}', 30), wait_inbox(a, f's120-old-b2a-{i}', 30)]
    learned = wait_for(lambda: learned_from(a, b) and learned_from(b, a), 20)
    # A messages C once, then removes her: the old build's `contact remove`
    # leaves the send lock named by her key.
    to_c = status_word(a.send(tags['c'], 's120-old-a2c')[1])
    got_c = wait_inbox(c, 's120-old-a2c', 30)
    removed = a.ash('contact', 'remove', '--petname', tags['c'].capitalize(), '--yes')
    c_dial, c_peer_id = c.dial, peer_id_of(c)
    c.stop()
    c_lock_left = (a.dir / f'.send_{c.pub.lower()}.lock.sqlite').exists()
    plain = {n.name: not is_rms1(n.dir / 'contacts.json') and not (n.dir / 'meta_key.rmk').exists()
             for n in (a, b)}
    phases['1_old_build'] = dict(
        ok=sent == ['DELIVERED'] * 4 and all(t is not None for t in got)
        and learned is not None and all(plain.values()) and to_c == 'DELIVERED'
        and got_c is not None and removed.returncode == 0 and c_lock_left,
        sent=sent, learned_s=learned, plain=plain, sent_to_c=to_c,
        c_removed=removed.returncode == 0, c_lock_left_by_the_old_build=c_lock_left)

    # 2: B away; A's message waits in the old build's outbox.
    a_port, b_port = port_of(a), port_of(b)
    b.stop()
    queued = a.send(tags['b'], 's120-queued')
    a.stop()
    dials = {'a': a.dial, 'b': b.dial}
    before = {n.name: history_bodies(n.dir) for n in (a, b)}
    old_ids = {n.name: [e.get('message_id_hex', '') for e in history_entries(n.dir)
                        if e.get('message_id_hex')] for n in (a, b)}
    old_files = {n.name: sorted(profile_files(n.dir)) for n in (a, b)}
    # A copy of each old profile (outside every profile folder): phase 4's
    # check must find the friend there, or it proves nothing.
    old_copies = {n.name: root / 'old-copies' / n.name for n in (a, b)}
    for n in (a, b):
        copy_files(n.dir, old_copies[n.name])
    heads_before = {n.name: session_heads(n) for n in (a, b)}
    phases['2_queued_in_the_old_build'] = dict(
        ok=status_word(queued[1]) == 'QUEUED' and all(len(v) >= 4 for v in before.values()),
        send=status_word(queued[1]), history_rows={k: len(v) for k, v in before.items()},
        files=old_files)

    # 3: this build; B on his old port first.
    for n in (a, b):
        n.ash_bin, n.node_bin = ASH, NODE
    marks = {}
    for n, port in ((b, b_port), (a, a_port)):
        marks[n.name] = len(n.log_path.read_text(errors='replace'))
        n.start(port)

    def start_log(n: Node) -> str:
        return n.log_path.read_text(errors='replace')[marks[n.name]:]

    sealed_at_start = {}
    for n in (a, b):
        settled = wait_for(lambda: re.search(r'^(?:\S+Z )?raven-node at_rest: sealed[ \t]*$',
                                             start_log(n), re.M) is not None, 30)
        count_line = re.search(r'raven-node at_rest: sealed (\d+) file\(s\)', start_log(n))
        sealed_at_start[n.name] = dict(settled_s=settled,
                                       files=int(count_line.group(1)) if count_line else 0)
    # Before anything of this build sends (review E-harness-docs-ci-1): no
    # file name below either profile names a friend. The older build's
    # per-friend send locks were named by the key; the sealing pass at the
    # start deletes them (review B-sealed-stores-4), C's too, whom no send
    # and no `contact remove` would ever reach again. B queued nothing and C
    # is not A's friend any more: theirs must be gone at once. A's queued
    # message to B may hold his for a moment; the pass of the next ash
    # command (`privacy status` below) deletes it, still before any send.
    friends_of = {'a': (b, c), 'b': (a,)}

    def names_naming_a_friend() -> dict:
        found = {}
        for n in (a, b):
            keys = [f.pub.lower() for f in friends_of[n.name]]
            hits = sorted(p.relative_to(n.dir).as_posix() for p in n.dir.rglob('*')
                          if any(k in p.name.lower() for k in keys))
            if hits:
                found[n.name] = hits
        return found

    names_at_seal = names_naming_a_friend()
    a_queued_lock = f'.send_{b.pub.lower()}.lock.sqlite'
    names_ok_at_seal = 'b' not in names_at_seal and all(
        name in (a_queued_lock, a_queued_lock + '-journal') for name in names_at_seal.get('a', []))
    status = {}
    for n in (a, b):
        r = n.ash('privacy', 'status', '--json')
        try:
            report = json.loads(r.stdout)
        except ValueError:
            report = {}
        stores = report.get('stores', [])
        status[n.name] = dict(
            mode=report.get('mode'), plain=report.get('files', {}).get('plain'),
            sealed=len(report.get('files', {}).get('sealed') or []),
            stores={s.get('file'): (s.get('user_version'), s.get('keyed')) for s in stores},
            ok=r.returncode == 0 and report.get('mode') == 'sealed'
            and report.get('files', {}).get('plain') == []
            and bool(stores) and all(s.get('keyed') for s in stores))
    names_before_sends = names_naming_a_friend()
    after = {n.name: history_bodies(n.dir) for n in (a, b)}
    history_kept = {
        k: all(after[k].count(body) == before[k].count(body) for body in before[k])
        and (n.dir / 'chat_history.json').read_bytes()[:8] == b'RVNHIST2'
        for k, n in (('a', a), ('b', b))}
    pins = {n.name: is_rms1(n.dir / 'lan_noise_pins.rms')
            and not (n.dir / 'lan_noise_pins.json').exists() for n in (a, b)}
    sealed_files = {n.name: {f: is_rms1(n.dir / f) for f in (
        'contacts.json', 'lan_seen.json', 'learned_routes.json', 'route_hints_state.json',
        'device_registry.json', 'peer_device_certs.json', 'prekey_store.json')}
        for n in (a, b)}
    early = wait_inbox(b, 's120-queued', 20)
    wake = None
    if early is None:
        wake = status_word(b.send(tags['a'], 's120-new-b2a-wake')[1])
    took = early if early is not None else wait_inbox(b, 's120-queued', 60)
    time.sleep(2)
    once = count(b.inbox(), 's120-queued')
    new = [status_word(a.send(tags['b'], 's120-new-a2b')[1]),
           status_word(b.send(tags['a'], 's120-new-b2a')[1])]
    new_got = [wait_inbox(b, 's120-new-a2b', 30), wait_inbox(a, 's120-new-b2a', 30)]
    phases['3_this_build_seals_at_start'] = dict(
        ok=all(s['settled_s'] is not None and s['files'] > 0 for s in sealed_at_start.values())
        and names_ok_at_seal and not names_before_sends
        and all(s['ok'] for s in status.values()) and all(history_kept.values())
        and all(pins.values()) and all(all(v.values()) for v in sealed_files.values())
        and took is not None and once == 1 and wake in (None, 'DELIVERED')
        and new == ['DELIVERED'] * 2 and all(t is not None for t in new_got),
        sealed_at_start=sealed_at_start, privacy_status=status, history_kept=history_kept,
        pins_sealed=pins, sealed_files=sealed_files,
        file_names_naming_a_friend=dict(at_seal=names_at_seal, before_sends=names_before_sends),
        queued_delivered_s=None if took is None else round(took, 1),
        woken_by_b=wake, queued_once=once, new_sends=new,
        session_heads=dict(before=heads_before, after={n.name: session_heads(n) for n in (a, b)}))

    # 4: C87's check over both data dirs, the nodes stopped.
    ids = {n.name: [e.get('message_id_hex', '') for e in history_entries(n.dir)
                    if e.get('message_id_hex')] for n in (a, b)}
    peer_ids = {n.name: peer_id_of(n) for n in (a, b)}
    a.stop()
    b.stop()
    leaks, old_leaks = {}, {}
    for n, friend in ((a, b), (b, a)):
        name = tags[friend.name]
        names = (name, name.capitalize())
        leaks[n.name] = friend_metadata_leaks(n.dir, friend, names, dials[friend.name],
                                              peer_ids[friend.name], ids[n.name], own=n)
        old_leaks[n.name] = friend_metadata_leaks(old_copies[n.name], friend, names,
                                                  dials[friend.name], peer_ids[friend.name],
                                                  old_ids[n.name], own=n)
    # C, removed on the old build: nothing of A's names her either; the copy
    # of A's old profile does (her send lock's file name).
    c_names = (tags['c'], tags['c'].capitalize())
    leaks['a_of_c'] = friend_metadata_leaks(a.dir, c, c_names, c_dial, c_peer_id, ids['a'], own=a)
    old_leaks['a_of_c'] = friend_metadata_leaks(old_copies['a'], c, c_names, c_dial, c_peer_id,
                                                old_ids['a'], own=a)
    phases['4_no_friend_metadata'] = dict(
        ok=not any(leaks.values()) and all(len(v) >= 7 for v in ids.values())
        and all(any(f.startswith('contacts.json: ') for f in old_leaks[k]) for k in ('a', 'b'))
        and any(f.endswith(': its name names the key') for f in old_leaks['a_of_c']),
        message_ids={k: len(v) for k, v in ids.items()}, leaks=leaks,
        old_copy_findings={k: len(v) for k, v in old_leaks.items()},
        old_copy_files={k: sorted({f.split(':', 1)[0] for f in v}) for k, v in old_leaks.items()})
    return dict(ok=all(p['ok'] for p in phases.values()), old_build=PRIVACY_OLD_BIN != '',
                **phases)


# ------------------------------------------- the long message horizon (5a)
# Phase 5 P5.9 (design docs/design/2026-10-beyond-24h.md). With
# RAVEN_FAULT_HORIZON=1 (HORIZON) every ash and raven-node parks a message
# whose envelope ran out, or one sent while its contact cannot be reached and
# no session is left, until its deadline (7 days after it was written), and
# sets up a new session and seals it again under the same message id when the
# contact is back. Each scenario moves one LabClock of its own, shared by both
# profiles (their file under the scenario's root).

# What the worker logs after a horizon step that changed something (P5.7).
HORIZON_LINE = re.compile(
    r'raven-node outbox: horizon: parked=(\d+) resealed=(\d+) expired=(\d+)')
HOUR_MS = 3_600_000


def horizon_steps(node: Node) -> list:
    """The node's horizon log lines, as (parked, resealed, expired)."""
    return [tuple(int(g) for g in m.groups())
            for m in HORIZON_LINE.finditer(node.log_path.read_text(errors='replace'))]


def waiting_deadlines(node: Node) -> dict:
    """Message id (hex) -> deadline (Unix ms) of each parked (`waiting`)
    message the running raven-node lists (IPC OutboxList); {} while it does
    not answer."""
    try:
        r = node_ipc(node, {'op': 'outbox_list', 'v': 1, 'limit': 200})
    except (OSError, ValueError, struct.error):
        return {}
    return {i['message_id_hex']: int(i.get('expires_at_ms') or 0)
            for i in r.get('items') or [] if i.get('state') == 'waiting'}


def out_states(node: Node, texts: list) -> dict:
    """text -> the delivery state of each outgoing history row with that
    body (one row per message: a second row is a copy shown twice)."""
    rows = [e for e in history_entries(node.dir) if e.get('direction') == 'out']
    return {t: [e.get('delivery') for e in rows if e.get('body', '').strip() == t]
            for t in texts}


def all_states(node: Node, texts: list, state: str) -> bool:
    return all(v == [state] for v in out_states(node, texts).values())


def inbox_once_in_order(node: Node, texts: list) -> tuple:
    """How often each of `texts` is in the node's inbox, and whether they
    show in that order."""
    inbox = node.inbox()
    counts = {t: count(inbox, t) for t in texts}
    pos = [inbox.find(t) for t in texts]
    return counts, -1 not in pos and pos == sorted(pos)


def kick_parked(node: Node) -> str:
    """`raven outbox retry` for one parked message: the worker tries its
    contact now (a returning contact found at once, as a wake from sleep or
    the LAN beacon would). '' when nothing is parked."""
    mids = sorted(waiting_deadlines(node))
    if not mids:
        return ''
    r = node.ash('outbox', 'retry', mids[0][:8])
    return (r.stdout + r.stderr).strip()[-200:]


def horizon_setup(root: Path, tag: str) -> tuple:
    """The first part of s60-s60c. Alice and Bob, pinned, on one LabClock;
    a warm-up message delivered; Bob down; Alice sends `tag`-d0-a and
    `tag`-d0-b (queued under their session). The clock moves 25 h ahead, so
    both envelopes and the session (a day from its PairInit) ran out; Alice's
    node starts again, and its prune drops the session. Passes when her
    outbox lists both as waiting until 7 days after they were written, her
    history still says queued, and her store holds no session (no K_root
    left). Returns (a, b, clock, Bob's port, the texts, the report)."""
    clock = LabClock(root / 'lab.clock')
    a = Node('a', root, env=clock.env(ENV))
    b = Node('b', root, env=clock.env(ENV))
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = a.send('bob', f'{tag}-warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    b.stop()
    texts = [f'{tag}-d0-a', f'{tag}-d0-b']
    t_send = int(time.time() * 1000)
    sends = [a.send('bob', t) for t in texts]
    since = log_size(a)
    clock.advance(25 * HOUR_MS)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    a.stop()
    a.start()
    pruned = wait_for(lambda: session_heads(a) == 0, 30)
    parked = wait_for(lambda: len(waiting_deadlines(a)) == 2, 60)
    deadlines = waiting_deadlines(a)
    states = out_states(a, texts)
    # Each deadline is 7 days after its message was written (system clock:
    # the lab clock stood at 0 then), never later.
    in_window = bool(deadlines) and all(
        t_send + 7 * DAY_MS - 5_000 <= d <= int(time.time() * 1000) + 7 * DAY_MS
        for d in deadlines.values())
    report = dict(
        ok=warm[0] == 0 and status_word(warm[1]) == 'DELIVERED'
        and all(status_word(s[1]) == 'QUEUED' for s in sends)
        and pruned is not None and parked is not None and len(deadlines) == 2 and in_window
        and all(v == ['queued'] for v in states.values()),
        warmup=status_word(warm[1]), sends=[status_word(s[1]) for s in sends], woke_s=woke,
        pruned_s=pruned, parked_s=parked, deadlines=deadlines, deadline_in_window=in_window,
        history=states)
    return a, b, clock, port, texts, report


def s60_offline_three_days_sender_online(root: Path) -> dict:
    """Phase 5a (RAVEN_FAULT_HORIZON=1; design s50). horizon_setup, then the
    clock stands 72 h ahead and Alice sends `s60-d3-c`: no session is left
    and Bob cannot be reached, so it is parked (queued, `HORIZON_PARKED`),
    never NOT SENT. Bob starts on his port with the same clock and Alice's
    outbox tries him (`raven outbox retry`). Passes when all 3 reach Bob
    exactly once and in order within 60 s, Alice's history says delivered
    for each, and her log shows one horizon step that sealed all 3 again
    (`resealed=3`) after one new session."""
    a, b, clock, port, texts, setup = horizon_setup(root, 's60')
    since = log_size(a)
    clock.set(72 * HOUR_MS)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    rc, out, _ = a.send('bob', 's60-d3-c')
    texts.append('s60-d3-c')
    parked = waiting_deadlines(a)
    b.start(port=port)
    kick = kick_parked(a)
    arrived = wait_until(lambda: all(count(b.inbox(), t) for t in texts), 60, 1)
    time.sleep(5)  # a second copy would be in by now
    counts, in_order = inbox_once_in_order(b, texts)
    delivered = wait_until(lambda: all_states(a, texts, 'delivered'), 30, 1)
    steps = horizon_steps(a)
    return dict(
        ok=setup['ok'] and status_word(out) == 'QUEUED' and 'HORIZON_PARKED' in out
        and 'NOT SENT' not in out and len(parked) == 3 and arrived is not None
        and all(v == 1 for v in counts.values()) and in_order and delivered is not None
        and any(s[1] == 3 for s in steps),
        setup=setup, woke_72h_s=woke, d3_send=(rc, status_word(out)), d3_text=out[-500:],
        parked=len(parked), kick=kick, arrived_s=took(arrived), counts=counts,
        in_order=in_order, history=out_states(a, texts), horizon_steps=steps,
        outbox=a.outbox()[-400:])


def s60b_offline_past_deadline(root: Path) -> dict:
    """Phase 5a (RAVEN_FAULT_HORIZON=1; design s50b). horizon_setup, then
    the clock stands 7 days and 1 hour ahead (past both deadlines) and Bob
    starts on his port. Passes when Alice's history says expired for both,
    her outbox says why (time ran out before Bob could be reached), nothing
    reaches Bob, and Bob's store holds no session: Alice sent no PairInit."""
    a, b, clock, port, texts, setup = horizon_setup(root, 's60b')
    mids = sorted(setup['deadlines'])
    since = log_size(a)
    clock.set(7 * DAY_MS + HOUR_MS)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    b.start(port=port)
    kick = kick_parked(a)
    expired = wait_until(lambda: all_states(a, texts, 'expired'), 90, 1)
    time.sleep(10)  # time for a PairInit that must not come
    listing = a.outbox()
    statuses = [a.ash('outbox', 'status', mid[:8]).stdout for mid in mids]
    why = [s for s in [listing] + statuses if 'time ran out before Bob could be reached' in s]
    heads = session_heads(b)
    inbox = b.inbox()
    steps = horizon_steps(a)
    return dict(
        ok=setup['ok'] and expired is not None and bool(why)
        and all(count(inbox, t) == 0 for t in texts) and heads == 0
        and not any(s[1] for s in steps) and not waiting_deadlines(a),
        setup=setup, woke_s=woke, kick=kick, expired_s=took(expired),
        history=out_states(a, texts), why_shown=len(why), bob_sessions=heads,
        bob_inbox={t: count(inbox, t) for t in texts}, horizon_steps=steps,
        outbox=listing[-400:], status=[s[-300:] for s in statuses])


def s60c_clock_back_while_parked(root: Path) -> dict:
    """Phase 5a (RAVEN_FAULT_HORIZON=1; design s50c). horizon_setup (both
    parked), then the clock moves 2 days back and Alice's outbox tries Bob
    (still down), then 3 days ahead and again. Bob starts on his port.
    Passes when both deadlines are unchanged after each move (set once,
    never extended), both reach Bob exactly once and in order, and Alice's
    node sealed each again only once (no extra copy)."""
    a, b, clock, port, texts, setup = horizon_setup(root, 's60c')
    before = setup['deadlines']
    clock.advance(-2 * DAY_MS)
    time.sleep(1)
    kicks = [kick_parked(a)]
    time.sleep(5)
    back = waiting_deadlines(a)
    since = log_size(a)
    clock.advance(3 * DAY_MS)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    kicks.append(kick_parked(a))
    time.sleep(5)
    ahead = waiting_deadlines(a)
    b.start(port=port)
    kicks.append(kick_parked(a))
    arrived = wait_until(lambda: all(count(b.inbox(), t) for t in texts), 60, 1)
    time.sleep(5)
    counts, in_order = inbox_once_in_order(b, texts)
    delivered = wait_until(lambda: all_states(a, texts, 'delivered'), 30, 1)
    steps = horizon_steps(a)
    return dict(
        ok=setup['ok'] and back == before and ahead == before and arrived is not None
        and all(v == 1 for v in counts.values()) and in_order and delivered is not None
        and sum(s[1] for s in steps) == 2,
        setup=setup, deadlines_after_back=back, deadlines_after_ahead=ahead,
        woke_ahead_s=woke, kicks=kicks, arrived_s=took(arrived), counts=counts,
        in_order=in_order, history=out_states(a, texts), horizon_steps=steps)


def s94_session_expired_while_apart(root: Path) -> dict:
    """Cutoff study (a Phase 5 scenario, P5.9; LabClock shared by both
    profiles). Alice and Bob pair (a message delivered), both stop, and the
    clock moves 25 h ahead: their session ended a day after its PairInit.
    Alice's node starts again (its prune drops the session) and she sends 3
    messages while Bob is still away; then Bob comes back on his port.
    Horizon gate closed (by default, release behaviour): each send is NOT
    SENT with CP.6's text (the secure connection with Bob ended), her
    history holds no `queued` row for them, and nothing reaches Bob. With
    RAVEN_FAULT_HORIZON=1: each is queued (parked), and after the re-pair all
    3 reach Bob exactly once and in order within 90 s, delivered in her
    history."""
    clock = LabClock(root / 'lab.clock')
    a = Node('a', root, env=clock.env(ENV))
    b = Node('b', root, env=clock.env(ENV))
    a.init(); b.init()
    a.start(); b.start()
    a.add_pinned(b, 'bob')
    b.add_pinned(a, 'alice')
    warm = a.send('bob', 's94-warmup')
    port = int(b.dial.rsplit(':', 1)[1])
    a.stop()
    b.stop()
    clock.advance(25 * HOUR_MS)
    a.start()
    pruned = wait_for(lambda: session_heads(a) == 0, 30)
    texts = ['s94-m1', 's94-m2', 's94-m3']
    sends = [a.send('bob', t) for t in texts]
    words = [status_word(s[1]) for s in sends]
    b.start(port=port)
    common = dict(horizon=HORIZON, warmup=status_word(warm[1]), pruned_s=pruned, sends=words,
                  send_text=sends[0][1][-500:])
    ok = warm[0] == 0 and status_word(warm[1]) == 'DELIVERED' and pruned is not None
    if HORIZON:
        kick = kick_parked(a)
        arrived = wait_until(lambda: all(count(b.inbox(), t) for t in texts), 90, 1)
        time.sleep(5)
        counts, in_order = inbox_once_in_order(b, texts)
        delivered = wait_until(lambda: all_states(a, texts, 'delivered'), 30, 1)
        return dict(
            ok=ok and words == ['QUEUED'] * 3 and all('HORIZON_PARKED' in s[1] for s in sends)
            and arrived is not None and all(v == 1 for v in counts.values()) and in_order
            and delivered is not None,
            **common, kick=kick, arrived_s=took(arrived), counts=counts, in_order=in_order,
            history=out_states(a, texts), horizon_steps=horizon_steps(a))
    time.sleep(15)
    counts, _ = inbox_once_in_order(b, texts)
    states = out_states(a, texts)
    outbox = a.outbox()
    return dict(
        ok=ok and words == ['NOT_SENT'] * 3
        and all("RAVEN's secure connection with Bob ended" in s[1] for s in sends)
        and not any('queued' in v for v in states.values())
        and all(v == 0 for v in counts.values()) and not any(t in outbox for t in texts),
        **common, counts=counts, history=states, outbox=outbox[-300:])


# ------------------------------------------------- sealed letters (5b)
# Phase 5 P5.16 (design docs/design/2026-10-beyond-24h.md, RAL1 in
# protocol/RAVEN_ASYNC_LETTER_V1.md). With RAVEN_FAULT_LETTER=1 (LETTER) every
# ash and raven-node has the letter gate open: a message for a contact who
# stays away moves into a letter session, sealed into a letter that a friend
# custodian (one both list) holds up to 7 days; the contact takes it, and his
# REPLY (PairResponse and ACKs) comes back the same way. Each scenario has
# friend custody's timers (CUSTODY_ENV) and moves one LabClock of its own,
# shared by its three profiles.

# `raven node custody status`: the custodian's own letters (P5.16).
LETTERS_HELD = re.compile(r'^letters\s+held (\d+) sealed letter', re.M)
OBJECTS_HELD = re.compile(r'held (\d+) sealed object')
# The fetcher's letter round and the worker's letter step (P5.15).
LETTER_FETCH_LINE = re.compile(
    r'raven-node custody: letters fetched=(\d+) accepted=(\d+) kept=(\d+) refused=(\d+)')
LETTER_SEALED = 'raven-node custody: letters: sealed='
LETTERS_LEFT = re.compile(r'raven-node custody: left (\d+) letters with a friend')
LETTER_DIRECT = 'raven-node outbox: letters: session completed directly'


def custody_counts(node: Node) -> tuple:
    """(sealed objects, sealed letters) `node` holds as a custodian, from
    `raven node custody status` (-1: not shown)."""
    out = node.ash('node', 'custody', 'status').stdout
    objects, letters = OBJECTS_HELD.search(out), LETTERS_HELD.search(out)
    return (int(objects.group(1)) if objects else -1,
            int(letters.group(1)) if letters else -1)


def letters_held(node: Node) -> int:
    return custody_counts(node)[1]


def letter_fetches(node: Node, since: int = 0) -> list:
    """The node's letter rounds that took something, as (fetched, accepted,
    kept, refused), from log offset `since`."""
    text = node.log_path.read_text(errors='replace')[since:]
    return [tuple(int(g) for g in m.groups()) for m in LETTER_FETCH_LINE.finditer(text)]


def letters_left(node: Node, since: int = 0) -> int:
    """Letters the node's worker left with a friend, from log offset
    `since`."""
    text = node.log_path.read_text(errors='replace')[since:]
    return sum(int(m.group(1)) for m in LETTERS_LEFT.finditer(text))


def kick_outbox(node: Node) -> str:
    """`raven outbox retry` for the first message still on its way (any
    state but delivered and ended): the worker tries that contact now."""
    try:
        r = node_ipc(node, {'op': 'outbox_list', 'v': 1, 'limit': 200})
    except (OSError, ValueError, struct.error):
        return ''
    mids = [i['message_id_hex'] for i in r.get('items') or []
            if i.get('state') not in ('delivered', 'expired', 'cancelled', 'failed')]
    if not mids:
        return ''
    out = node.ash('outbox', 'retry', mids[0][:8])
    return (out.stdout + out.stderr).strip()[-200:]


def letter_trio(root: Path, tag: str, c_extra: dict | None = None,
                listed_by: tuple = ('a', 'b')) -> tuple:
    """Alice, Bob and Carol on one LabClock (letter gate on), pinned to each
    other; Carol's custody on; each of `listed_by` lists Carol for the other
    (`contact set-addr --custodian`); a warm-up from Alice delivered to Bob
    (their 24 h session, and her copy of his prekey bundle). Then a few
    fetch passes, so each fetcher has asked Carol for letters and knows
    whether she serves them (the worker letters only for a custodian known
    to). `c_extra`: more environment for Carol's processes. Returns (a, b,
    c, clock, Bob's port, the report)."""
    clock = LabClock(root / 'lab.clock')
    env = clock.env(CUSTODY_ENV)
    a, b = Node('a', root, env), Node('b', root, env)
    c = Node('c', root, dict(env, **(c_extra or {})))
    for n in (a, b, c):
        n.init()
        n.start()
    for x, y, who in ((a, b, 'bob'), (a, c, 'carol'), (b, a, 'alice'), (b, c, 'carol'),
                      (c, a, 'alice'), (c, b, 'bob')):
        x.add_pinned(y, who)
    on = c.ash('node', 'custody', 'on', '--yes')
    listed = []
    for x, who in ((a, 'bob'), (b, 'alice')):
        if x.name in listed_by:
            r = x.ash('contact', 'set-addr', '--tag', who, '--custodian', '@carol')
            listed.append(r.returncode)
    warm = a.send('bob', f'{tag}-warmup')
    time.sleep(5)
    port = int(b.dial.rsplit(':', 1)[1])
    report = dict(ok=on.returncode == 0 and all(rc == 0 for rc in listed) and warm[0] == 0
                  and status_word(warm[1]) == 'DELIVERED',
                  custody_on=on.returncode, listed=listed, warmup=status_word(warm[1]))
    return a, b, c, clock, port, report


def s61_offline_three_days_via_friend_letter(root: Path) -> dict:
    """Phase 5b (RAVEN_FAULT_LETTER=1; design s51). letter_trio, then
    letter_round_trip with `via-letter`: Bob back after 72 h (their session,
    and the letter's direct copy, ran out long ago), Alice at 73 h. Passes
    when Bob has `via-letter` once, Alice's history says delivered after
    his REPLY, and Carol holds no letter (Bob released the LETTER, Alice the
    REPLY)."""
    a, b, c, clock, port, setup = letter_trio(root, 's61')
    trip = letter_round_trip(a, b, c, clock, port, 'via-letter', 72 * HOUR_MS, 73 * HOUR_MS)
    return dict(ok=setup['ok'] and trip['ok'], setup=setup, **{
        k: v for k, v in trip.items() if k != 'ok'})


def s61b_letter_then_direct_return(root: Path) -> dict:
    """Phase 5b (RAVEN_FAULT_LETTER=1; design s51b). letter_trio, but only
    Alice lists Carol (Bob never takes letters from her, so the direct path
    alone decides); Bob stops and Alice sends `back-direct`: Carol holds
    the letter. The clock moves 48 h ahead while Alice stays online, and Bob
    starts on his port; Alice's outbox tries him. Passes when Alice's node
    completed the letter session directly (her kept PairInit replayed, his
    PairResponse back), Bob has `back-direct` exactly once, Alice's history
    says delivered, and Carol holds no letter (Alice withdrew it)."""
    a, b, c, clock, port, setup = letter_trio(root, 's61b', listed_by=('a',))
    b.stop()
    rc, out, _ = a.send('bob', 'back-direct')
    held = wait_until(lambda: letters_held(c) == 1, 90, 1)
    since = log_size(a)
    clock.advance(48 * HOUR_MS)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    b.start(port=port)
    kick = kick_outbox(a)
    got = wait_until(lambda: count(b.inbox(), 'back-direct') >= 1, 90, 1)
    delivered = wait_until(lambda: all_states(a, ['back-direct'], 'delivered'), 60, 1)
    direct = wait_log(a, LETTER_DIRECT, 30, since)
    empty = wait_until(lambda: letters_held(c) == 0, 90, 1)
    time.sleep(5)  # a second copy would be in by now
    n = count(b.inbox(), 'back-direct')
    return dict(
        ok=setup['ok'] and held is not None and direct is not None and got is not None
        and n == 1 and delivered is not None and empty is not None,
        setup=setup, send=(rc, status_word(out)), held_s=took(held), woke_s=woke, kick=kick,
        completed_directly_s=took(direct), b_got_s=took(got), b_inbox=n,
        a_delivered_s=took(delivered), c_empty_s=took(empty), c_counts=custody_counts(c),
        b_letter_rounds=letter_fetches(b))


def s62_letter_base_ops_custodian(root: Path) -> dict:
    """Phase 5b (RAVEN_FAULT_LETTER=1; design s52): Carol runs with
    RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1, so she answers every letter op
    UNSUPPORTED, as a custodian built before letters does. s30 on the
    letter trio: Bob stops, Alice sends `via-base`; Alice stops, Bob starts
    on his port; Alice starts again. Passes when nothing went into a letter
    (Alice sealed none, Carol holds none), the base deposit carried it, and
    s30's timing within 24 h holds: Carol holds the sealed object within
    60 s, Bob has it once within 60 s, and his ACK reaches Alice through
    Carol within 60 s."""
    a, b, c, clock, port, setup = letter_trio(
        root, 's62', c_extra={'RAVEN_LAB_CUSTODY_BASE_OPS_ONLY': '1'})
    b.stop()
    rc, out, _ = a.send('bob', 'via-base')
    held = wait_until(lambda: custody_counts(c)[0] >= 1, 60, 1)
    letters = letters_held(c)
    a.stop()
    since_b = log_size(b)
    b.start(port=port)
    got = wait_until(lambda: count(b.inbox(), 'via-base') >= 1, 60, 1)
    time.sleep(3)
    b_log = b.log_path.read_text(errors='replace')[since_b:]
    since_a = log_size(a)
    a.start()
    acked = wait_until(lambda: re.search(
        r'custody: fetched messages=\d+ acks=[1-9]',
        a.log_path.read_text(errors='replace')[since_a:]) is not None, 60, 1)
    a_log = a.log_path.read_text(errors='replace')
    b_all = b.log_path.read_text(errors='replace')
    return dict(
        ok=setup['ok'] and held is not None and letters == 0 and got is not None
        and count(b.inbox(), 'via-base') == 1 and 'custody: fetched messages=' in b_log
        and acked is not None and LETTER_SEALED not in a_log and LETTER_SEALED not in b_all
        and letters_held(c) == 0,
        setup=setup, send=(rc, status_word(out)), held_s=took(held), c_letters=letters,
        b_got_s=took(got), acked_s=took(acked), a_sealed_letter=LETTER_SEALED in a_log,
        b_sealed_letter=LETTER_SEALED in b_all, c_counts=custody_counts(c))


def letter_round_trip(a: Node, b: Node, c: Node, clock: LabClock, port: int, text: str,
                      b_at_ms: int, a_at_ms: int) -> dict:
    """The rest of s61 (and s75, s76): Bob is away and Alice sends `text`;
    Carol holds one letter. Alice leaves; the clock stands `b_at_ms` ahead
    and Bob starts on his port: he takes the letter and leaves his REPLY
    with Carol, then leaves; the clock stands `a_at_ms` ahead and Alice
    starts: she takes the REPLY. Alice and Bob never run at the same time.
    `ok` when Bob has `text` once, Alice's history says delivered and Carol
    holds no letter."""
    b.stop()
    rc, out, _ = a.send('bob', text)
    held = wait_until(lambda: letters_held(c) == 1, 90, 1)
    sealed = LETTER_SEALED in a.log_path.read_text(errors='replace')
    objects = custody_counts(c)[0]
    a.stop()
    clock.set(b_at_ms)
    since_b = log_size(b)
    apart = [a.proc is None]
    b.start(port=port)
    got = wait_until(lambda: count(b.inbox(), text) >= 1, 90, 1)
    # Bob's REPLY (his PairResponse and the ACK) is left with Carol.
    replied = wait_until(lambda: letters_left(b, since_b) >= 1, 90, 1)
    time.sleep(3)
    b_count = count(b.inbox(), text)
    b_fetch = letter_fetches(b, since_b)
    b.stop()
    clock.set(a_at_ms)
    since_a = log_size(a)
    apart.append(b.proc is None)
    a.start()
    delivered = wait_until(lambda: all_states(a, [text], 'delivered'), 90, 1)
    empty = wait_until(lambda: letters_held(c) == 0, 60, 1)
    return dict(
        ok=held is not None and sealed and got is not None and b_count == 1
        and replied is not None and delivered is not None and empty is not None and all(apart),
        send=(rc, status_word(out)), held_s=took(held), a_sealed_letter=sealed,
        c_objects_after_send=objects, b_got_s=took(got), b_inbox=b_count,
        b_replied_s=took(replied), b_letter_rounds=b_fetch, a_delivered_s=took(delivered),
        a_letter_rounds=letter_fetches(a, since_a), c_empty_s=took(empty),
        history=out_states(a, [text]), never_together=all(apart), c_counts=custody_counts(c))


def s75_letter_mule_two_rooms(root: Path) -> dict:
    """Cutoff addendum (RAVEN_FAULT_LETTER=1; the study's B, the carrier
    both list, is Carol here, and its C is Bob). The three are linked once
    at t0 (letter_trio). Room 1, Alice and Carol: Bob is away and Alice
    sends `via-mule`; Carol carries one letter. At +30 h Carol is in room 2
    with Bob (Alice away): he takes it and leaves his REPLY with her. At
    +50 h she is back with Alice (Bob away), who takes the REPLY. On one
    loopback the rooms are who runs: after t0 Alice and Bob never run at
    the same time, so Carol is the only way between them. Passes when Bob
    has `via-mule` once, Alice's history says delivered, and Carol ends
    with no letter."""
    a, b, c, clock, port, setup = letter_trio(root, 's75')
    trip = letter_round_trip(a, b, c, clock, port, 'via-mule', 30 * HOUR_MS, 50 * HOUR_MS)
    return dict(ok=setup['ok'] and trip['ok'], setup=setup, **{
        k: v for k, v in trip.items() if k != 'ok'})


def s76_letter_week(root: Path) -> dict:
    """Cutoff addendum, letter week (RAVEN_FAULT_LETTER=1): the s61 walk
    with Bob back at +6 d 23 h, an hour before the letter runs out, and
    Alice 10 minutes later. Passes as s61: delivered."""
    a, b, c, clock, port, setup = letter_trio(root, 's76')
    trip = letter_round_trip(a, b, c, clock, port, 'week-late', 6 * DAY_MS + 23 * HOUR_MS,
                             6 * DAY_MS + 23 * HOUR_MS + 10 * 60_000)
    return dict(ok=setup['ok'] and trip['ok'], setup=setup, **{
        k: v for k, v in trip.items() if k != 'ok'})


def s76b_letter_week_ran_out(root: Path) -> dict:
    """Cutoff addendum, letter week (RAVEN_FAULT_LETTER=1): Bob is away and
    Alice sends `week-gone`; Carol holds the letter. Alice stays online; the
    clock moves 7 days and 1 hour ahead and Carol starts again on her port
    (her start drops what ran out); Alice's outbox tries Bob. Passes when
    Carol holds no letter, Alice's history says expired and her outbox says
    when time ran out on this computer's clock (`raven outbox list` or
    `status`; never UTC), and nothing reaches Bob when he is back."""
    a, b, c, clock, port, setup = letter_trio(root, 's76b')
    c_port = int(c.dial.rsplit(':', 1)[1])
    b.stop()
    rc, out, _ = a.send('bob', 'week-gone')
    held = wait_until(lambda: letters_held(c) == 1, 90, 1)
    mid = next((m for m, s in outbox_mids(a) if s != 'delivered'), '')
    c.stop()
    since = log_size(a)
    clock.set(7 * DAY_MS + HOUR_MS)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    c.start(port=c_port)
    gone = wait_until(lambda: letters_held(c) == 0, 60, 1)
    kick = kick_outbox(a)
    expired = wait_until(lambda: all_states(a, ['week-gone'], 'expired'), 90, 1)
    status = a.ash('outbox', 'status', mid[:8]).stdout if mid else ''
    listing = a.outbox()
    why = next((s for s in (listing, status) if 'time ran out' in s), '')
    # When it ran out: a local time (`today at 09:10`), or how long ago
    # without the local offset; never UTC.
    local = bool(re.search(r'\b\d{2}:\d{2}\b|\bago\b', why)) and only_local_zone(why)
    b.start(port=port)
    time.sleep(10)  # time for a fetch, or a direct copy, that must bring nothing
    b_count = count(b.inbox(), 'week-gone')
    return dict(
        ok=setup['ok'] and held is not None and gone is not None and b_count == 0
        and expired is not None and bool(why) and local,
        setup=setup, send=(rc, status_word(out)), held_s=took(held), woke_s=woke,
        c_gone_s=took(gone), kick=kick, a_expired_s=took(expired),
        history=out_states(a, ['week-gone']), why=why[-400:], local_time=local,
        b_inbox=b_count, b_letter_rounds=letter_fetches(b))


def outbox_mids(node: Node) -> list:
    """(message id hex, state) of each row the running raven-node lists."""
    try:
        r = node_ipc(node, {'op': 'outbox_list', 'v': 1, 'limit': 200})
    except (OSError, ValueError, struct.error):
        return []
    return [(i['message_id_hex'], i.get('state', '')) for i in r.get('items') or []]


def letters_moved(node: Node, since: int = 0) -> int:
    """Messages the node's worker moved into letter sessions, from log
    offset `since`."""
    text = node.log_path.read_text(errors='replace')[since:]
    return sum(int(m.group(1)) for m in re.finditer(
        r'raven-node custody: letters: sealed=\d+ moved=(\d+)', text))


def s76c_twenty_in_one_day(root: Path) -> dict:
    """Cutoff addendum, letter week (RAVEN_FAULT_LETTER=1): Bob is away and
    Alice sends 20 messages. A letter session holds 16 (its provisional
    indices 0-15) and only one starts a day, so 16 move into letters for
    Carol and 4 stay where they are (their 24 h session). The clock moves
    25 h ahead: that session ran out, the 4 are parked, and the next day's
    letter session takes them. Alice leaves, Bob starts on his port and
    takes every letter; he leaves; Alice starts and takes his REPLYs.
    Alice stops only once the second day's letter is left with Carol.
    Passes when exactly 16 moved on the first day and 4 on the next, all
    20 reach Bob once and in order, and Alice's history says delivered for
    each."""
    a, b, c, clock, port, setup = letter_trio(root, 's76c')
    b.stop()
    texts = [f's76c-{i:02d}' for i in range(1, 21)]
    since = log_size(a)
    sends = [status_word(a.send('bob', t)[1]) for t in texts]
    first = wait_until(lambda: letters_moved(a, since) >= 16, 90, 1)
    time.sleep(5)  # a 17th would have moved by now
    first_day = dict(moved=letters_moved(a, since), letters=letters_held(c),
                     history=sorted({s[0] if s else '' for s in out_states(a, texts).values()}))
    since = log_size(a)
    clock.set(25 * HOUR_MS)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    kick = kick_outbox(a)
    second = wait_until(lambda: letters_moved(a, since) >= 4, 90, 1)
    # The 'sealed=' line comes before the worker dials Carol: wait for the
    # day's letter to be left with her before Alice stops (review letters-7).
    placed = wait_until(lambda: letters_left(a, since) >= 1
                        or letters_held(c) > first_day['letters'] >= 0, 60, 1)
    second_day = dict(moved=letters_moved(a, since), letters=letters_held(c))
    a.stop()
    clock.set(26 * HOUR_MS)
    since_b = log_size(b)
    b.start(port=port)
    arrived = wait_until(lambda: all(count(b.inbox(), t) for t in texts), 120, 1)
    replied = wait_until(lambda: letters_left(b, since_b) >= 1, 90, 1)
    time.sleep(5)
    counts, in_order = inbox_once_in_order(b, texts)
    b.stop()
    clock.set(27 * HOUR_MS)
    a.start()
    delivered = wait_until(lambda: all_states(a, texts, 'delivered'), 120, 1)
    states = out_states(a, texts)
    return dict(
        ok=setup['ok'] and first is not None and first_day['moved'] == 16
        and second is not None and second_day['moved'] == 4 and placed is not None
        and arrived is not None
        and all(v == 1 for v in counts.values()) and in_order and delivered is not None,
        setup=setup, sends=sorted(set(sends)), first_s=took(first), first_day=first_day,
        woke_s=woke, kick=kick, second_s=took(second), placed_s=took(placed),
        second_day=second_day,
        arrived_s=took(arrived), replied_s=took(replied),
        counts={t: n for t, n in counts.items() if n != 1}, in_order=in_order,
        delivered_s=took(delivered),
        history={t: s for t, s in states.items() if s != ['delivered']})


# ------------------------------------- custody handoff (Phase 5 P5.23, RHW1)
# protocol/RAVEN_CUSTODY_HANDOFF_V1.md. With RAVEN_FAULT_HANDOFF=1 (HANDOFF)
# every ash and raven-node has the handoff gate open (RAVEN_LAB_CUSTODY_HANDOFF
# with the Lab Test A unlock, the forwarder's interval 500 ms), so s30 under
# RAVEN_FAULT_CUSTODY=1 runs with it on, and s68-s71 and s97b run. Their four
# profiles: Alice and Bob each list a friend of their own for the other, Fred
# (Alice's) and Gina (Bob's), who know each other; Fred never pins Bob and
# Gina never pins Alice. Alice and Bob pin the far friend by key only (no
# route, never dialled): an RRH1 custodian tag is pair-blinded, so Alice can
# read Bob's announced Gina only as one of her own contacts. Route hints are
# on for all four (the announcements ride them).
HANDOFF_ENV = dict(CUSTODY_ENV, RAVEN_LAB_CUSTODY_HANDOFF='1',
                   RAVEN_LAB_CUSTODY_FORWARD_MS='500', RAVEN_LAB_ROUTE_HINTS='1')
# `raven node custody status`: the handoff row (P5.22).
HANDOFF_ROW = re.compile(
    r'^handoff (on|off)\s+passing on: (\d+) waiting, (\d+) handed on, (\d+) refused, '
    r'(\d+) bytes; registered tags: (\d+)', re.M)
# The worker's FORWARD line and the forwarder's pass line (P5.21).
HANDOFF_LEFT = 'with a friend to pass on'
HANDED_LINE = re.compile(
    r'raven-node custody: handed on (\d+) kept (\d+) refused (\d+) dropped (\d+)')
# Plain custody's and handoff's strike lines: a closed or old custodian gets
# neither from a refusal it answers.
STRIKE_LINES = ('deposit links within an hour', 'handoff links within an hour')
FETCHED_ACK = re.compile(r'raven-node custody: fetched messages=\d+ acks=[1-9]')


def handoff_counts(node: Node) -> dict:
    """The handoff row of `node`'s `raven node custody status` ({} when it
    shows none): rows waiting, handed on and refused, bytes, tags."""
    m = HANDOFF_ROW.search(node.ash('node', 'custody', 'status').stdout)
    if not m:
        return {}
    keys = ('waiting', 'handed', 'refused', 'bytes', 'tags')
    return dict(on=m.group(1) == 'on', **dict(zip(keys, (int(g) for g in m.groups()[1:]))))


def pin_key_only(node: Node, other: Node, tag: str) -> None:
    """Pin `other` (verified) with no route at all: `node` knows its key, to
    read the custodian tag a contact announced, and never dials it."""
    r = node.ash('contact', 'add', '--address', other.address, '--pub-hex', other.pub,
                 '--petname', tag.capitalize(), '--tag', tag, '--verify-fp', other.fingerprint())
    assert r.returncode == 0, r.stdout + r.stderr


def announced_inbox(node: Node, other: Node) -> bool:
    """`node` learned from `other`'s route hints a custodian with
    HANDOFF_INBOX (flag bit 0)."""
    try:
        rows = learned_rows(node)
    except (OSError, ValueError):
        return False
    return any(int(f) & 1 for e in rows if isinstance(e, dict)
               and e.get('pub_hex', '').lower() == other.pub.lower()
               for f in e.get('custodian_tag_flags') or [])


def strikes(node: Node) -> list:
    text = node.log_path.read_text(errors='replace')
    return [s for s in STRIKE_LINES if s in text]


def handoff_chain(root: Path, tag: str, clock: LabClock | None = None,
                  extra: dict | None = None, warm_env: dict | None = None) -> tuple:
    """Alice (a), Bob (b), Fred (f1) and Gina (f2) on HANDOFF_ENV (and
    `clock`, shared by all four); `extra`: more environment per node name.
    Pins: Alice Bob, Fred and Gina (key only); Bob Alice, Gina and Fred (key
    only); Fred Alice and Gina; Gina Bob and Fred. Fred and Gina turn custody
    and handoff on; Alice lists Fred for Bob, Bob Gina for Alice. A warm-up
    from Alice (their session; `warm_env` for that send), then each registers
    its session's tags at its own friend on its fetch dial, and a message
    each way carries the friend with HANDOFF_INBOX in route hints. Returns
    (a, b, f1, f2, the report)."""
    env = clock.env(HANDOFF_ENV) if clock else HANDOFF_ENV
    extra = extra or {}
    a, b, f1, f2 = (Node(n, root, dict(env, **extra.get(n, {})))
                    for n in ('a', 'b', 'f1', 'f2'))
    for n in (f1, f2, a, b):
        n.init()
        n.start()
    a.add_pinned(b, 'bob')
    a.add_pinned(f1, 'fred')
    pin_key_only(a, f2, 'gina')
    b.add_pinned(a, 'alice')
    b.add_pinned(f2, 'gina')
    pin_key_only(b, f1, 'fred')
    f1.add_pinned(a, 'alice')
    f1.add_pinned(f2, 'gina')
    f2.add_pinned(b, 'bob')
    f2.add_pinned(f1, 'fred')
    on = [f.ash('node', 'custody', *args).returncode
          for f in (f1, f2) for args in (('on', '--yes'), ('handoff', 'on'))]
    listed = [a.ash('contact', 'set-addr', '--tag', 'bob', '--custodian', '@fred').returncode,
              b.ash('contact', 'set-addr', '--tag', 'alice', '--custodian', '@gina').returncode]
    warm = a.send('bob', f'{tag}-warmup', extra_env=warm_env)
    warm_at = time.time()
    registered = wait_until(lambda: handoff_counts(f2).get('tags', 0) >= 1
                            and handoff_counts(f1).get('tags', 0) >= 1, 60, 1)
    hellos, announced = [], None
    for i in range(3):
        hellos.append(status_word(b.send('alice', f'{tag}-hello-{i}')[1]))
        hellos.append(status_word(a.send('bob', f'{tag}-hi-{i}')[1]))
        announced = wait_until(lambda: announced_inbox(a, b) and announced_inbox(b, a), 15)
        if announced is not None:
            break
    report = dict(ok=not any(on) and not any(listed) and status_word(warm[1]) == 'DELIVERED'
                  and registered is not None and announced is not None,
                  custody_on=on, listed=listed, warmup=status_word(warm[1]),
                  registered_s=took(registered), hellos=hellos,
                  announced=announced is not None, warm_at=round(warm_at, 1))
    return a, b, f1, f2, report


def port_of(node: Node) -> int:
    return int(node.dial.rsplit(':', 1)[1])


def names_in_files(node: Node, far: Node, text: str) -> list:
    """The files of `node` (its data dir and its node log) holding `far`'s
    public key (raw 32 bytes or hex, any case) or `text`, as stored or, for
    a sealed file (RMS1), once opened with the profile's key."""
    key = bytes.fromhex(far.pub)
    hexed = far.pub.lower().encode()
    found = []
    for path in [p for p in node.dir.rglob('*') if p.is_file()] + [node.log_path]:
        try:
            data = path.read_bytes()
            if data.startswith(b'RMS1'):
                data += sealed_plain(node.dir, str(path.relative_to(node.dir))) or b''
        except (OSError, ValueError, KeyError):
            pass
        if key in data or hexed in data.lower() or text.encode() in data:
            found.append(str(path.relative_to(path.parents[1])))
    return found


def s68_two_friends_chain(root: Path) -> dict:
    """Phase 5 handoff (RAVEN_FAULT_HANDOFF=1; design s40, carrier_matrix
    C54 with timings). handoff_chain; Bob leaves and Alice sends `two-hop`:
    her worker leaves it with Fred to pass on to Gina (held by 1 friend),
    Fred hands it on, Gina holds it. Alice leaves, Bob comes back on his port
    and fetches it from Gina; his ACK goes the mirrored way (a FORWARD at Gina,
    handed on to Fred, held there for Alice). Bob leaves, Alice comes back on
    a new port and fetches the ACK from Fred: delivered. Alice and Bob never
    run at the same time after the setup. Privacy: no file of Fred's (data dir
    and log) holds Bob's key, none of Gina's holds Alice's, and neither holds
    the text."""
    a, b, f1, f2, setup = handoff_chain(root, 's68')
    b_port = port_of(b)
    b.stop()
    t0 = time.time()
    rc, out, _ = a.send('bob', 'two-hop')
    held = wait_until(lambda: 'held by 1 friend' in a.outbox(), 60, 1)
    left = HANDOFF_LEFT in a.log_path.read_text(errors='replace')
    handed = wait_until(lambda: handoff_counts(f1).get('handed', 0) >= 1, 60, 1)
    at_f2 = wait_until(lambda: custody_counts(f2)[0] >= 1, 60, 1)
    a.stop()
    apart = [a.proc is None]
    t1 = time.time()
    b.start(port=b_port)
    fetched = wait_until(lambda: count(b.inbox(), 'two-hop') >= 1, 60, 1)
    ack_handed = wait_until(lambda: handoff_counts(f2).get('handed', 0) >= 1, 90, 1)
    ack_at_f1 = wait_until(lambda: custody_counts(f1)[0] >= 1, 60, 1)
    time.sleep(3)
    b_count = count(b.inbox(), 'two-hop')
    b.stop()
    apart.append(b.proc is None)
    t2 = time.time()
    a.start()
    acked = wait_until(lambda: FETCHED_ACK.search(a.log_path.read_text(errors='replace')),
                       60, 1)
    delivered = wait_until(lambda: all_states(a, ['two-hop'], 'delivered'), 60, 1)
    f1_names_b = names_in_files(f1, b, 'two-hop')
    f2_names_a = names_in_files(f2, a, 'two-hop')
    # The scan sees a key the friend does hold (its own contact's).
    control = names_in_files(f1, a, 'two-hop') and names_in_files(f2, b, 'two-hop')
    return dict(
        ok=setup['ok'] and status_word(out) == 'QUEUED' and held is not None and left
        and handed is not None and at_f2 is not None and fetched is not None and b_count == 1
        and ack_handed is not None and ack_at_f1 is not None and acked is not None
        and delivered is not None and all(apart) and not f1_names_b and not f2_names_a
        and bool(control) and not strikes(a) and not strikes(b),
        setup=setup, send=(rc, status_word(out)), held_after=took(held),
        a_left_to_pass_on=left, handed_after=took(handed), f2_held_after=took(at_f2),
        fetched_after=took(fetched), b_inbox=b_count, ack_handed_after=took(ack_handed),
        ack_at_f1_after=took(ack_at_f1), acked_after=took(acked),
        delivered_after=took(delivered), send_to_f2_s=round(t1 - t0, 1),
        b_round_s=round(t2 - t1, 1), never_together=all(apart),
        f1_files_naming_bob=f1_names_b, f2_files_naming_alice=f2_names_a,
        scan_control=bool(control), f1=handoff_counts(f1), f2=handoff_counts(f2), history=out_states(a, ['two-hop']))


def s69_mule_hands_on_later(root: Path) -> dict:
    """Phase 5 handoff (RAVEN_FAULT_HANDOFF=1; design s41). handoff_chain;
    Bob and Gina are away when Alice sends `mule-later`: Fred takes it to pass
    on and keeps it (Gina cannot be reached). Alice leaves; Gina comes back
    on her old port and Fred hands it on (his retry, or Gina seen); Bob comes
    back and fetches it from Gina, exactly once."""
    a, b, f1, f2, setup = handoff_chain(root, 's69')
    b_port, f2_port = port_of(b), port_of(f2)
    b.stop()
    f2.stop()
    rc, out, _ = a.send('bob', 'mule-later')
    held = wait_until(lambda: 'held by 1 friend' in a.outbox(), 60, 1)
    waiting = wait_until(lambda: handoff_counts(f1).get('waiting', 0) >= 1, 60, 1)
    time.sleep(5)
    kept = handoff_counts(f1)
    a.stop()
    f2.start(port=f2_port)
    handed = wait_until(lambda: handoff_counts(f1).get('handed', 0) >= 1, 240, 1)
    at_f2 = wait_until(lambda: custody_counts(f2)[0] >= 1, 60, 1)
    b.start(port=b_port)
    got = wait_until(lambda: count(b.inbox(), 'mule-later') >= 1, 90, 1)
    time.sleep(3)
    b_count = count(b.inbox(), 'mule-later')
    return dict(
        ok=setup['ok'] and status_word(out) == 'QUEUED' and held is not None
        and waiting is not None and kept.get('handed') == 0 and handed is not None
        and at_f2 is not None and got is not None and b_count == 1,
        setup=setup, send=(rc, status_word(out)), held_s=took(held), f1_kept=kept,
        handed_after_gina_back_s=took(handed), f2_held_s=took(at_f2), b_got_s=took(got),
        b_inbox=b_count, f1_passes=HANDED_LINE.findall(f1.log_path.read_text(errors='replace')))


def s70_new_session_tags_late(root: Path) -> dict:
    """Phase 5 handoff (RAVEN_FAULT_HANDOFF=1; design s42). handoff_chain
    with a first session of 60 s (RAVEN_LAB_SESSION_LIFETIME_MS on the
    warm-up). Gina leaves; once that session ended Alice's next message pairs
    again (`s70-repair`, delivered), and Bob leaves before he could register
    the new session's tags (Gina was away). Gina comes back; Alice sends
    `s70-late`: Fred takes it, Gina answers TAG_UNKNOWN and Fred keeps it,
    backing off. Alice leaves, Bob comes back and registers the new tags at
    Gina; Fred delivers on his next try and Bob fetches it, exactly once."""
    a, b, f1, f2, setup = handoff_chain(
        root, 's70', warm_env={'RAVEN_LAB_SESSION_LIFETIME_MS': '60000'})
    b_port, f2_port = port_of(b), port_of(f2)
    f2.stop()
    # The first session ends 60 s after the warm-up.
    time.sleep(max(0.0, setup['warm_at'] + 70 - time.time()))
    rc_r, out_r, _ = a.send('bob', 's70-repair')
    b.stop()
    f2.start(port=f2_port)
    tags_before = handoff_counts(f2).get('tags', 0)
    rc, out, _ = a.send('bob', 's70-late')
    held = wait_until(lambda: 'held by 1 friend' in a.outbox(), 60, 1)
    kept = wait_until(lambda: any(int(k) >= 1 for _, k, _, _ in HANDED_LINE.findall(
        f1.log_path.read_text(errors='replace'))), 60, 1)
    early = handoff_counts(f1)
    at_f2_early = custody_counts(f2)[0]
    a.stop()
    b.start(port=b_port)
    registered = wait_until(lambda: handoff_counts(f2).get('tags', 0) > tags_before, 60, 1)
    handed = wait_until(lambda: handoff_counts(f1).get('handed', 0) >= 1, 240, 1)
    got = wait_until(lambda: count(b.inbox(), 's70-late') >= 1, 90, 1)
    time.sleep(3)
    b_count = count(b.inbox(), 's70-late')
    return dict(
        ok=setup['ok'] and status_word(out_r) == 'DELIVERED' and status_word(out) == 'QUEUED'
        and held is not None and kept is not None and early.get('handed') == 0
        and at_f2_early == 0 and registered is not None and handed is not None
        and got is not None and b_count == 1,
        setup=setup, repair=(rc_r, status_word(out_r)), send=(rc, status_word(out)),
        held_s=took(held), f1_kept_s=took(kept), f1_early=early, f2_objects_early=at_f2_early,
        gina_tags_before=tags_before, registered_s=took(registered),
        handed_s=took(handed), b_got_s=took(got), b_inbox=b_count,
        f1_passes=HANDED_LINE.findall(f1.log_path.read_text(errors='replace')))


def s71_old_or_closed_custodian(root: Path) -> dict:
    """Phase 5 handoff (RAVEN_FAULT_HANDOFF=1; design s43, carrier_matrix
    C55). Alice lists Fred and Gina for Bob; Bob lists Gina (a mutual
    custodian here: Gina pins Alice too) and announces her with
    HANDOFF_INBOX, so Alice's plan is a FORWARD at Fred (next hop Gina) and a
    plain DEPOSIT at Gina. Fred pins Alice, Gina and Bob. Bob leaves.
    (a) Closed: Alice reaches Fred only over Internet direct and has WAN
    custody on, Fred has it off, so his link gate answers HOLD to whatever she
    sends: `closed-1` is held by Gina alone, Fred holds nothing, no forward
    row, and no strike anywhere. (b) Old: Alice and Fred start again (her
    parks are in memory), Fred with WAN custody on and
    RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1, so he answers the handoff ops
    UNSUPPORTED: `old-2` is held by Gina, handoff is parked at Fred only, and
    `old-3` is left with Fred as a plain deposit (custody there stays usable).
    Fred never keeps a forward row or takes a tag registration. Bob comes
    back: each message reaches him exactly once."""
    env = dict(HANDOFF_ENV)
    a = Node('a', root, dict(env, RAVEN_LAB_CUSTODY_WAN='1'))
    b, f1, f2 = (Node(n, root, env) for n in ('b', 'f1', 'f2'))
    for n in (f2, a, b):
        n.init()
        n.start()
    f1.init()
    f1.start(inet_port=0)
    inet_port = int(f1.inet.rsplit(':', 1)[1])
    a.add_pinned(b, 'bob')
    a.add_pinned_internet(f1, 'fred')
    a.add_pinned(f2, 'gina')
    b.add_pinned(a, 'alice')
    b.add_pinned(f2, 'gina')
    for x, y, who in ((f1, a, 'alice'), (f1, f2, 'gina'), (f1, b, 'bob'), (f2, a, 'alice'),
                      (f2, b, 'bob'), (f2, f1, 'fred')):
        x.add_pinned(y, who)
    on = [f.ash('node', 'custody', *args).returncode
          for f in (f1, f2) for args in (('on', '--yes'), ('handoff', 'on'))]
    listed = [a.ash('contact', 'set-addr', '--tag', 'bob', '--custodian', '@fred',
                    '--custodian', '@gina').returncode,
              b.ash('contact', 'set-addr', '--tag', 'alice', '--custodian', '@gina').returncode]
    warm = a.send('bob', 's71-warmup')
    registered = wait_until(lambda: handoff_counts(f2).get('tags', 0) >= 1, 60, 1)
    announced = None
    for i in range(3):
        b.send('alice', f's71-hello-{i}')
        announced = wait_until(lambda: announced_inbox(a, b), 15)
        if announced is not None:
            break
    b_port = port_of(b)
    b.stop()
    rc1, out1, _ = a.send('bob', 'closed-1')
    held1 = wait_until(lambda: 'held by 1 friend' in a.outbox(), 60, 1)
    time.sleep(5)
    closed = dict(f1_objects=custody_counts(f1)[0], f1=handoff_counts(f1),
                  f2_objects=custody_counts(f2)[0],
                  a_forwarded=HANDOFF_LEFT in a.log_path.read_text(errors='replace'))
    # (b) the old custodian
    a.stop()
    f1.stop()
    f1.env = dict(f1.env, RAVEN_LAB_CUSTODY_WAN='1', RAVEN_LAB_CUSTODY_BASE_OPS_ONLY='1')
    f1.start(inet_port=inet_port)
    a.start()
    rc2, out2, _ = a.send('bob', 'old-2')
    held2 = wait_until(lambda: custody_counts(f2)[0] >= 2, 60, 1)
    time.sleep(3)
    rc3, out3, _ = a.send('bob', 'old-3')
    mid3 = (re.search(r'mid=([0-9a-f]{8})', out3) or [None, ''])[1]
    plain_at_f1 = wait_until(lambda: custody_counts(f1)[0] >= 1 and mid3 and 'held by' in
                             a.ash('outbox', 'status', mid3).stdout, 60, 1)
    time.sleep(3)
    old = dict(f1_objects=custody_counts(f1)[0], f1=handoff_counts(f1),
               f2_objects=custody_counts(f2)[0])
    texts = ['closed-1', 'old-2', 'old-3']
    b.start(port=b_port)
    got = wait_until(lambda: all(count(b.inbox(), t) >= 1 for t in texts), 120, 1)
    time.sleep(3)
    counts = {t: count(b.inbox(), t) for t in texts}
    # No forward row and no tag registration at Fred: the handoff ops were
    # refused both times.
    no_rows = all(c.get('waiting', 0) + c.get('handed', 0) + c.get('refused', 0)
                  + c.get('tags', 0) == 0 for c in (closed['f1'], old['f1']))
    return dict(
        ok=not any(on) and not any(listed) and status_word(warm[1]) == 'DELIVERED'
        and registered is not None and announced is not None
        and status_word(out1) == 'QUEUED' and held1 is not None
        and closed['f1_objects'] == 0 and closed['f2_objects'] >= 1
        and held2 is not None and plain_at_f1 is not None and no_rows
        and not strikes(a) and got is not None and all(v == 1 for v in counts.values()),
        custody_on=on, listed=listed, warmup=status_word(warm[1]),
        registered_s=took(registered), announced=announced is not None,
        sends=[status_word(o) for o in (out1, out2, out3)], held_closed_s=took(held1),
        closed=closed, held_old_s=took(held2), plain_at_fred_s=took(plain_at_f1), old=old,
        strikes=strikes(a), b_got_s=took(got), b_counts=counts)


def s97b_two_friends_ran_out(root: Path) -> dict:
    """Cutoff addendum s97b (RAVEN_FAULT_HANDOFF=1): the s97 walk on the
    two-friend chain, one LabClock for the four. Bob is away and Alice sends
    `chain-gone`; Fred hands it on and Gina holds it. Alice stays online;
    the clock moves 25 h ahead (past the message's 24 h) and Fred and Gina
    start again on their ports. Passes when Fred keeps no forward row, Gina
    holds nothing, Alice's history says expired and her outbox says when
    time ran out on this computer's clock (never UTC), and nothing reaches
    Bob when he is back."""
    clock = LabClock(root / 'lab.clock')
    a, b, f1, f2, setup = handoff_chain(root, 's97b', clock=clock)
    b_port, f1_port, f2_port = port_of(b), port_of(f1), port_of(f2)
    b.stop()
    rc, out, _ = a.send('bob', 'chain-gone')
    handed = wait_until(lambda: handoff_counts(f1).get('handed', 0) >= 1, 60, 1)
    at_f2 = wait_until(lambda: custody_counts(f2)[0] >= 1, 60, 1)
    mid = next((m for m, s in outbox_mids(a) if s != 'delivered'), '')
    f1.stop()
    f2.stop()
    since = log_size(a)
    clock.set(DAY_MS + HOUR_MS)
    woke = wait_log(a, LabClock.WOKE, 15, since)
    f1.start(port=f1_port)
    f2.start(port=f2_port)
    f1_gone = wait_until(lambda: (lambda c: c.get('waiting', 1) + c.get('handed', 1) == 0)(
        handoff_counts(f1)), 60, 1)
    f2_gone = wait_until(lambda: custody_counts(f2)[0] == 0, 60, 1)
    kick = kick_outbox(a)
    expired = wait_until(lambda: all_states(a, ['chain-gone'], 'expired'), 90, 1)
    status = a.ash('outbox', 'status', mid[:8]).stdout if mid else ''
    listing = a.outbox()
    why = next((s for s in (listing, status) if 'time ran out' in s), '')
    local = bool(re.search(r'\b\d{2}:\d{2}\b|\bago\b', why)) and only_local_zone(why)
    b.start(port=b_port)
    time.sleep(10)
    b_count = count(b.inbox(), 'chain-gone')
    return dict(
        ok=setup['ok'] and status_word(out) == 'QUEUED' and handed is not None
        and at_f2 is not None and f1_gone is not None and f2_gone is not None
        and expired is not None and bool(why) and local and b_count == 0,
        setup=setup, send=(rc, status_word(out)), handed_s=took(handed),
        f2_held_s=took(at_f2), woke_s=woke, f1_gone_s=took(f1_gone),
        f2_gone_s=took(f2_gone), f1=handoff_counts(f1), kick=kick,
        a_expired_s=took(expired), history=out_states(a, ['chain-gone']),
        why=why[-400:], local_time=local, b_inbox=b_count)


# ------------------------------------------------- Bluetooth nearby (Phase 5)
# The nearby carrier (protocol/RAVEN_NEARBY_LINK_V1.md) is held in this build
# (NEARBY_PRODUCTION_ENABLED=false). RAVEN_FAULT_NEARBY=1 (P5.28) selects
# s63-s67 and s72-s74 (s67 and s67b also need RAVEN_FAULT_CUSTODY=1); their nodes run
# with the nearby lab switch (RAVEN_LAB_NEARBY=1 with the Lab Test A unlock)
# on one fake Bluetooth ether: the scenario's own `raven-node nearby-ether`
# hub on a loopback port (RAVEN_LAB_NEARBY_ETHER), never a real radio. Each
# pair meets once on the LAN first (nearby admits a verified contact by the
# certificate an earlier link left: RNL1 §0), then every saved LAN address is
# turned into a dead port, with no LAN beacon, internet or p2p: nearby is the
# only path.
NEARBY = os.environ.get('RAVEN_FAULT_NEARBY') == '1'
NEARBY_ENV = without_beacon(dict(ENV, RAVEN_LAB_TEST_A='1', RAVEN_LAB_NEARBY='1'))
NEARBY_TAGS = {'a': 'alice', 'b': 'bob', 'c': 'carol', 'd': 'dave'}
# The node's counts-only delivery line for the nearby carrier.
NEARBY_DELIVERED = re.compile(r'raven-node outbox: delivered \d+ \(nearby_dial')
# What a node that carries over nearby alone says once at its start
# (RAVEN_LAB_NEARBY_ONLY=1; raven_core::NEARBY_ONLY_NOTE).
NEARBY_ONLY_LINE = 'raven-node: lab nearby-only (RAVEN_LAB_NEARBY_ONLY=1)'


class EtherHub:
    """The scenario's fake Bluetooth ether (`raven-node nearby-ether`: debug
    builds with the nearby lab switch only) on 127.0.0.1, and its control
    session: a radio's power switch, an armed fault, and what went on air
    (`adverts`, the knock HELLOs a radio observer captured)."""

    def __init__(self, root: Path, extra: tuple | list = ()) -> None:
        import select
        self.log_path = root / 'ether.log'
        log = open(self.log_path, 'a')
        self.proc = subprocess.Popen(
            [NODE, 'nearby-ether', '--listen', '127.0.0.1:0', '--print-port', *extra],
            stdout=subprocess.PIPE, stderr=log, env=NEARBY_ENV, text=True)
        _CHILDREN.append(self.proc)
        ready, _, _ = select.select([self.proc.stdout], [], [], 30)
        line = self.proc.stdout.readline() if ready else ''
        if not line.strip().isdigit():
            raise RuntimeError(f'nearby-ether did not start: {self.log_path.read_text()[-500:]}')
        self.addr = f'127.0.0.1:{int(line)}'
        self.ctl = socket.create_connection(('127.0.0.1', int(line)), timeout=10)
        self.ctl_r = self.ctl.makefile('r')
        self.ctl.sendall(b'{"op":"control"}\n')

    def env(self, base: dict | None = None) -> dict:
        """A node's environment on this ether."""
        return dict(NEARBY_ENV if base is None else base, RAVEN_LAB_NEARBY_ETHER=self.addr)

    def ask(self, **req) -> dict:
        self.ctl.sendall((json.dumps(req) + '\n').encode())
        return json.loads(self.ctl_r.readline())

    def power(self, node: 'Node', on: bool) -> dict:
        """The Bluetooth switch of `node`'s radio (named by its pid)."""
        return self.ask(op='power', name=f'raven-node-{node.proc.pid}', on=on)

    def adverts(self) -> list:
        return self.ask(op='adverts')['records']


def nearby_status(node: Node) -> str:
    return node.ash('nearby', 'status').stdout


def nearby_on_air(node: Node) -> bool:
    """`raven nearby status` says the radio is on (the engine runs)."""
    return bool(re.search(r'^\s*bluetooth\s+on\b', nearby_status(node), re.M))


def nearby_nodes(root: Path, hub: EtherHub, names: str = 'ab', env: dict | None = None,
                 meet: bool = True, enable: bool = True, env_of: dict | None = None) -> list:
    """Nodes `names` on `hub`'s ether, pinned to each other (`env`, or a
    node's own from `env_of`). `meet`: each sends each other one message
    over the LAN first (certificates and sessions), then every saved LAN
    address becomes a dead port. `enable`: `raven nearby enable` on each,
    and wait for each radio."""
    nodes = [Node(n, root, env=hub.env((env_of or {}).get(n, env))) for n in names]
    for n in nodes:
        n.init()
        n.start()
    for x in nodes:
        for y in nodes:
            if x is not y:
                x.add_pinned(y, NEARBY_TAGS[y.name])
    if meet:
        for x in nodes:
            for y in nodes:
                if x is not y:
                    rc, out, _ = x.send(NEARBY_TAGS[y.name], f'meet-{x.name}{y.name}')
                    assert status_word(out) == 'DELIVERED', out[-500:]
        for x in nodes:
            for y in nodes:
                if x is not y:
                    x.set_lan(NEARBY_TAGS[y.name], f'127.0.0.1:{free_tcp_port()}')
    if enable:
        for n in nodes:
            r = n.ash('nearby', 'enable')
            assert r.returncode == 0 and 'ok nearby=on' in r.stdout, r.stdout + r.stderr
        for n in nodes:
            assert wait_until(lambda: nearby_on_air(n), 30) is not None, nearby_status(n)
    return nodes


def nearby_lines(node: Node) -> int:
    return len(NEARBY_DELIVERED.findall(node.log_path.read_text(errors='replace')))


def s63_nearby_happy_path(root: Path) -> dict:
    """Phase 5 (P5.28): Alice and Bob met once on the LAN; their LAN
    addresses are dead now and nothing else is on, so the fake Bluetooth
    ether is the only path. Alice sends Bob 3 messages and Bob sends Alice
    3: each arrives exactly once, in order, within 90 s, delivered in the
    sender's history, the nodes log their nearby deliveries (counts only),
    and `raven nearby status` counts the pipe."""
    hub = EtherHub(root)
    a, b = nearby_nodes(root, hub)
    ab = ['s63-ab-1', 's63-ab-2', 's63-ab-3']
    ba = ['s63-ba-1', 's63-ba-2', 's63-ba-3']
    words = [status_word(a.send('bob', t)[1]) for t in ab]
    arrived_ab = wait_until(lambda: all(count(b.inbox(), t) for t in ab), 90, 1)
    words += [status_word(b.send('alice', t)[1]) for t in ba]
    arrived_ba = wait_until(lambda: all(count(a.inbox(), t) for t in ba), 90, 1)
    time.sleep(3)
    counts_ab, order_ab = inbox_once_in_order(b, ab)
    counts_ba, order_ba = inbox_once_in_order(a, ba)
    delivered = wait_until(lambda: all_states(a, ab, 'delivered')
                           and all_states(b, ba, 'delivered'), 30, 1)
    lines = (nearby_lines(a), nearby_lines(b))
    status = nearby_status(a)
    return dict(
        ok=arrived_ab is not None and arrived_ba is not None
        and all(v == 1 for v in {**counts_ab, **counts_ba}.values()) and order_ab and order_ba
        and delivered is not None and sum(lines) >= 1
        and all(w in ('DELIVERED', 'QUEUED') for w in words),
        sends=words, arrived_ab_s=took(arrived_ab), arrived_ba_s=took(arrived_ba),
        counts=dict(**counts_ab, **counts_ba), in_order=(order_ab, order_ba),
        nearby_delivery_lines=lines, a_nearby_status=status[-400:])



def nearby_connected(node: Node) -> int:
    """Pipes up now, as `raven nearby status` counts them."""
    m = re.search(r'in range\s+\d+ contacts? in range now, (\d+) connected', nearby_status(node))
    return int(m.group(1)) if m else 0


def set_background_mail(node: Node, on: bool) -> None:
    """Nearby background mail (cutoff addendum F11d) as a user turns it on
    or off: `raven nearby background-mail on --yes` (its own consent, owner
    decision OD-C8) or `off`. The running node saves it and applies it at
    once; it never turns nearby itself on."""
    args = ('on', '--yes') if on else ('off',)
    r = node.ash('nearby', 'background-mail', *args)
    assert r.returncode == 0 and 'ok background mail' in r.stdout, r.stdout + r.stderr


def s64_nearby_link_drop_mid_transfer(root: Path) -> dict:
    """Phase 5 (P5.28): the radio link is cut in the middle of a 48 KB
    message (the hub cuts the link carrying the 41st frame after it is
    armed). Raven's outbox tries again over a new link: the message
    arrives exactly once, delivered in Alice's history, and Bob's reply
    goes back the same way."""
    hub = EtherHub(root)
    a, b = nearby_nodes(root, hub)
    warm = status_word(a.send('bob', 's64-warm')[1])
    warmed = wait_until(lambda: count(b.inbox(), 's64-warm') == 1, 90, 1)
    big = 's64-big ' + 'x' * (48 * 1024 - 64)
    assert hub.ask(op='fault', disconnect_after=40)['ev'] == 'ok'
    word = status_word(a.send('bob', big, timeout=180)[1])
    arrived = wait_until(lambda: count(b.inbox(), 's64-big') >= 1, 120, 1)
    stats = hub.ask(op='stats')
    reply = status_word(b.send('alice', 's64-reply')[1])
    back = wait_until(lambda: count(a.inbox(), 's64-reply') == 1, 90, 1)
    time.sleep(3)
    delivered = wait_until(lambda: all_states(a, ['s64-warm'], 'delivered')
                           and out_states(a, [big])[big] == ['delivered'], 60, 1)
    return dict(
        ok=warmed is not None and arrived is not None and stats.get('cut') is True
        and count(b.inbox(), 's64-big') == 1 and back is not None
        and delivered is not None,
        warm=warm, big_send=word, arrived_s=took(arrived), hub=stats, reply=reply,
        reply_s=took(back), big_copies=count(b.inbox(), 's64-big'),
        history=out_states(a, ['s64-warm'])
    )


def s65_nearby_radio_off_on(root: Path) -> dict:
    """Phase 5 (P5.28): Bob's Bluetooth is off (the hub's power switch):
    `raven nearby status` says so with the fix, and Alice's 3 messages
    wait (nothing reaches him in 15 s). Bob turns Bluetooth on: all 3
    arrive exactly once and in order within 60 s."""
    hub = EtherHub(root)
    a, b = nearby_nodes(root, hub)
    off = hub.power(b, False)
    said_off = wait_until(lambda: 'Bluetooth on in this computer' in nearby_status(b), 20)
    texts = ['s65-1', 's65-2', 's65-3']
    words = [status_word(a.send('bob', t)[1]) for t in texts]
    time.sleep(15)
    early = [count(b.inbox(), t) for t in texts]
    on = hub.power(b, True)
    t0 = time.time()
    arrived = wait_until(lambda: all(count(b.inbox(), t) for t in texts), 60, 1)
    time.sleep(3)
    counts, in_order = inbox_once_in_order(b, texts)
    return dict(
        ok=off.get('ev') == 'ok' and on.get('ev') == 'ok' and said_off is not None
        and words == ['QUEUED'] * 3 and early == [0, 0, 0] and arrived is not None
        and all(v == 1 for v in counts.values()) and in_order,
        sends=words, said_off_s=took(said_off), before_on=early,
        arrived_after_on_s=took(arrived), counts=counts, in_order=in_order,
        took_s=round(time.time() - t0, 1))


def s66_nearby_stale_session_repaired(root: Path) -> dict:
    """Phase 5 (P5.28; the plan's s53): Alice and Bob met (a session),
    then 25 h pass (one LabClock for both) while they are apart; their LAN
    addresses are dead. With no link up, Alice's message is refused cleanly
    (NOT SENT: the secure connection ended; nothing waits, nothing reaches
    Bob). `raven nearby on @bob` makes her computer findable; once Bob's
    radio connected, her next send sets up a new session over nearby (a
    PairInit on the nearby link, RNL1 §7) and is delivered exactly once, and
    Bob's reply comes back over it."""
    clock = LabClock(root / 'lab.clock')
    hub = EtherHub(root)
    a, b = nearby_nodes(root, hub, env=clock.env(NEARBY_ENV))
    a.stop()
    b.stop()
    clock.advance(25 * HOUR_MS)
    a.start()
    b.start()
    pruned = wait_for(lambda: session_heads(a) == 0, 30)
    for n in (a, b):
        assert wait_until(lambda: nearby_on_air(n), 30) is not None, nearby_status(n)
    rc, out, _ = a.send('bob', 's66-stale')
    refused = status_word(out)
    time.sleep(5)
    staged = 's66-stale' in a.outbox()
    on = a.ash('nearby', 'on', '@bob', '--for', '30m')
    linked = wait_until(lambda: nearby_connected(a) >= 1, 60, 1)
    word = status_word(a.send('bob', 's66-again')[1])
    arrived = wait_until(lambda: count(b.inbox(), 's66-again') == 1, 60, 1)
    reply = status_word(b.send('alice', 's66-reply')[1])
    back = wait_until(lambda: count(a.inbox(), 's66-reply') == 1, 60, 1)
    time.sleep(3)
    return dict(
        ok=pruned is not None and refused == 'NOT_SENT' and not staged
        and count(b.inbox(), 's66-stale') == 0 and on.returncode == 0
        and linked is not None and arrived is not None and back is not None
        and count(b.inbox(), 's66-again') == 1 and count(a.inbox(), 's66-reply') == 1,
        pruned_s=pruned, stale_send=refused, stale_text=out[-300:], staged=staged,
        nearby_on=(on.stdout + on.stderr)[-200:], linked_s=took(linked), again=word,
        arrived_s=took(arrived), reply=reply, reply_s=took(back))


def s67_nearby_mule_via_a_friend(root: Path) -> dict:
    """Phase 5 (P5.28; the plan's s54, RAVEN_FAULT_CUSTODY=1 too): Alice,
    Bob and Carol met once; Carol keeps mail for her friends (`raven node
    custody on`), Alice and Bob each name her for the other, and her node
    advertises for whoever she holds mail for (nearby background mail,
    cutoff addendum F11d). Bob's Bluetooth is off. Alice asks her computer
    to be findable for Carol (`raven nearby on @carol`): her message to Bob
    is left with Carol over nearby. Alice's Bluetooth goes off; Bob's comes
    on: Carol's radio finds him, he collects the message from her over
    nearby, exactly once."""
    env = dict(NEARBY_ENV, RAVEN_LAB_CUSTODY_AFTER_MS='0', RAVEN_LAB_CUSTODY_FETCH_MS='1000')
    hub = EtherHub(root)
    a, b, c = nearby_nodes(root, hub, names='abc', env=env, enable=False)
    on = c.ash('node', 'custody', 'on', '--yes')
    for x, tag in ((a, 'bob'), (b, 'alice')):
        r = x.ash('contact', 'set-addr', '--tag', tag, '--custodian', '@carol')
        assert r.returncode == 0, r.stdout + r.stderr
    set_background_mail(c, True)
    for n in (a, b, c):
        r = n.ash('nearby', 'enable')
        assert r.returncode == 0, r.stdout + r.stderr
    for n in (a, b, c):
        assert wait_until(lambda: nearby_on_air(n), 30) is not None, nearby_status(n)
    hub.power(b, False)
    near = a.ash('nearby', 'on', '@carol')
    rc, out, _ = a.send('bob', 's67-via-carol')
    held = None
    t0 = time.time()
    while time.time() - t0 < 120:
        st = c.ash('node', 'custody', 'status').stdout
        m = re.search(r'held (\d+) sealed', st)
        if m and int(m.group(1)) >= 1:
            held = time.time() - t0
            break
        time.sleep(1)
    hub.power(a, False)
    hub.power(b, True)
    got = wait_inbox(b, 's67-via-carol', 120)
    time.sleep(3)
    b_log = b.log_path.read_text(errors='replace')
    return dict(
        ok=on.returncode == 0 and near.returncode == 0 and held is not None
        and got is not None and count(b.inbox(), 's67-via-carol') == 1
        and 'custody: fetched messages=' in b_log,
        send=(rc, status_word(out)), held_after=took(held), fetched_after=took(got),
        b_custody=[l for l in b_log.splitlines() if 'custody' in l][-3:])


def s67b_nearby_deposit_on_encounter(root: Path) -> dict:
    """Phase 5 review nearby-7 (P5.33's deposit on an encounter, which had
    only an ad-hoc run; RAVEN_FAULT_CUSTODY=1 too): Alice names Carol as
    Bob's mail friend; Bob's and Carol's Bluetooth are off, so Alice's
    message to Bob waits and its tries back off (the second try comes 5-15 s
    after the first, the fourth 20-60 s after the third, and so on). After
    90 s Alice asks her computer to be findable for Carol (`raven nearby on
    @carol`) and Carol's Bluetooth comes on: the pipe that comes up makes
    Alice's node retry the contacts Carol may carry mail for at once (its
    counts-only line), and the message is left with Carol within 30 s,
    once. Bob's Bluetooth comes on: he collects it from Carol, exactly
    once."""
    env = dict(NEARBY_ENV, RAVEN_LAB_CUSTODY_AFTER_MS='0', RAVEN_LAB_CUSTODY_FETCH_MS='1000')
    hub = EtherHub(root)
    a, b, c = nearby_nodes(root, hub, names='abc', env=env, enable=False)
    on = c.ash('node', 'custody', 'on', '--yes')
    for x, tag in ((a, 'bob'), (b, 'alice')):
        r = x.ash('contact', 'set-addr', '--tag', tag, '--custodian', '@carol')
        assert r.returncode == 0, r.stdout + r.stderr
    set_background_mail(c, True)
    for n in (a, b, c):
        r = n.ash('nearby', 'enable')
        assert r.returncode == 0, r.stdout + r.stderr
    for n in (a, b, c):
        assert wait_until(lambda: nearby_on_air(n), 30) is not None, nearby_status(n)
    hub.power(b, False)
    hub.power(c, False)
    rc, out, _ = a.send('bob', 's67b-on-encounter')
    time.sleep(90)

    def held_by_carol() -> int:
        m = re.search(r'held (\d+) sealed', c.ash('node', 'custody', 'status').stdout)
        return int(m.group(1)) if m else 0
    before = held_by_carol()
    near = a.ash('nearby', 'on', '@carol')
    hub.power(c, True)
    held = wait_until(lambda: held_by_carol() >= 1, 30, 1)
    a_log = a.log_path.read_text(errors='replace')
    kicked = re.findall(r'custody: a mail friend is nearby; retrying (\d+) contacts', a_log)
    hub.power(a, False)
    hub.power(b, True)
    got = wait_inbox(b, 's67b-on-encounter', 120)
    time.sleep(3)
    return dict(
        ok=on.returncode == 0 and near.returncode == 0 and before == 0
        and held is not None and kicked[-1:] == ['1'] and got is not None
        and count(b.inbox(), 's67b-on-encounter') == 1,
        send=(rc, status_word(out)), held_before_the_encounter=before,
        held_after_the_encounter=took(held), encounter_kicks=kicked,
        fetched_after=took(got))


def s72_nearby_background_encounter(root: Path) -> dict:
    """Cutoff addendum (P5.28; the cutoff study's s72): the radios meet
    after the user's work ran out (RAVEN_LAB_NEARBY_FOREGROUND_MS=4000 for
    the 15 min). Alice's message to Bob waits while his Bluetooth is off.
    He comes back after her foreground ended: with nearby background mail
    off nothing is delivered in 45 s (the gap the study found: nobody
    advertises); with it on (F11d), her node advertises for him because
    mail waits, and the message arrives exactly once within 60 s."""
    hub = EtherHub(root)
    env = dict(NEARBY_ENV, RAVEN_LAB_NEARBY_FOREGROUND_MS='4000')
    a, b = nearby_nodes(root, hub, env=env)
    hub.power(b, False)
    word = status_word(a.send('bob', 's72-later')[1])
    time.sleep(8)
    hub.power(b, True)
    time.sleep(45)
    gap = count(b.inbox(), 's72-later')
    set_background_mail(a, True)
    arrived = wait_until(lambda: count(b.inbox(), 's72-later') == 1, 60, 1)
    time.sleep(3)
    return dict(
        ok=word == 'QUEUED' and gap == 0 and arrived is not None
        and count(b.inbox(), 's72-later') == 1,
        send=word, delivered_without_background_mail=gap,
        arrived_with_background_mail_s=took(arrived))


def lab_epoch_phase(clock: LabClock, minute: float) -> None:
    """Sets `clock` so that it reads `minute` minutes into a 15-minute
    nearby epoch now (RNL1 §3)."""
    now = int(time.time() * 1000)
    want = int(minute * 60_000)
    clock.set((want - now % 900_000) % 900_000)


def s73_nearby_clock_skew(root: Path) -> dict:
    """Cutoff addendum (P5.28; the cutoff study's s73): Bob's clock runs 20
    min ahead of Alice's, so their 15-minute token epochs differ by 2 (each
    clock on its own LabClock): his radio never recognises her advert, and
    her message waits (nothing in 45 s, nothing breaks). His clock comes
    back to 10 min ahead (one epoch apart, which nearby accepts): the
    message arrives exactly once, and Alice's `raven status` gives CP.7's
    clock wording for Bob (his receipt is dated 10 min ahead of her
    clock)."""
    hub = EtherHub(root)
    ca, cb = LabClock(root / 'a.clock'), LabClock(root / 'b.clock')
    a, b = nearby_nodes(root, hub, env_of={'a': ca.env(NEARBY_ENV), 'b': cb.env(NEARBY_ENV)})
    # 12 min into an epoch on Alice's clock: Bob's +20 min is 2 epochs on.
    lab_epoch_phase(ca, 12)
    cb.set(ca.offset_ms + 20 * 60_000)
    time.sleep(1)
    word = status_word(a.send('bob', 's73-skewed')[1])
    time.sleep(45)
    far = count(b.inbox(), 's73-skewed')
    cb.set(ca.offset_ms + 10 * 60_000)
    arrived = wait_until(lambda: count(b.inbox(), 's73-skewed') >= 1, 90, 1)
    clocks = wait_until(lambda: re.search(r"Bob's clock is about 10 min(utes)? ahead",
                                          a.ash('status').stdout) is not None, 60, 2)
    time.sleep(3)
    status = a.ash('status').stdout
    return dict(
        ok=word == 'QUEUED' and far == 0 and arrived is not None
        and count(b.inbox(), 's73-skewed') == 1 and clocks is not None,
        send=word, delivered_at_20_min=far, arrived_at_10_min_s=took(arrived),
        clock_row_s=took(clocks),
        clocks=[l.strip() for l in status.splitlines() if 'clock' in l.lower()][:3])


def s74_three_contacts_in_range(root: Path) -> dict:
    """Cutoff addendum (P5.28; the cutoff study's s74): Alice has 2
    messages waiting for each of Bob, Carol and Dave, whose Bluetooth is
    off. All three come into range at once: at most 2 of them are
    advertised for at a time (RNL1 §3), yet every queue drains, each
    message exactly once and in order, within 120 s."""
    hub = EtherHub(root)
    nodes = nearby_nodes(root, hub, names='abcd')
    a, others = nodes[0], nodes[1:]
    for n in others:
        hub.power(n, False)
    texts = {n.name: [f's74-{n.name}-1', f's74-{n.name}-2'] for n in others}
    words = [status_word(a.send(NEARBY_TAGS[n.name], t)[1]) for n in others
             for t in texts[n.name]]
    rotating = []
    for n in others:
        hub.power(n, True)

    def drained() -> bool:
        m = re.search(r'advertising for (\d+)', nearby_status(a))
        rotating.append(int(m.group(1)) if m else 0)
        return all(count(n.inbox(), t) for n in others for t in texts[n.name])
    arrived = wait_until(drained, 120, 1)
    time.sleep(3)
    counts, order = {}, []
    for n in others:
        c, o = inbox_once_in_order(n, texts[n.name])
        counts.update(c)
        order.append(o)
    return dict(
        ok=arrived is not None and all(v == 1 for v in counts.values()) and all(order)
        and max(rotating or [0]) <= 2,
        sends=words, drained_s=took(arrived), counts=counts, in_order=order,
        most_rotating=max(rotating or [0]))


class TcpPeers:
    """The remote TCP ports one process is connected to, sampled with
    `lsof` every half second in a thread until `stop()`: the proof that a
    node never dialled a port it must not (s128: Bob, Bluetooth only for
    Raven, never reaches Alice's or Carol's LAN listener). `available` is
    False where `lsof` is missing (the check is then skipped, said so)."""

    def __init__(self, pid: int) -> None:
        import threading
        self.pid = pid
        self.ports: set = set()
        self.samples = 0
        self.available = shutil.which('lsof') is not None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        if self.available:
            self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            r = subprocess.run(['lsof', '-nP', '-a', '-p', str(self.pid), '-iTCP'],
                               capture_output=True, text=True)
            for m in re.finditer(r'->[^\s]*:(\d+) \(', r.stdout):
                self.ports.add(int(m.group(1)))
            self.samples += 1
            self._stop.wait(0.5)

    def stop(self) -> None:
        self._stop.set()
        if self.available:
            self._thread.join(5)


def custody_carriers(node: Node, since: int = 0) -> list:
    """The carriers the node's custody lines name after log offset `since`:
    what it left with a mail friend and what it fetched from one."""
    text = node.log_path.read_text(errors='replace')[since:]
    return re.findall(r'raven-node custody: (?:left \d+ with a friend[^(]*|fetched messages=\d+ '
                      r'acks=\d+ refused=\d+ kept=\d+ )\(([a-z_]+)', text)


def s128_nearby_only_carry_chain(root: Path) -> dict:
    """Offline mesh carry research, Phase 0 (the field test's T1 and T2 on
    one computer, RAVEN_FAULT_NEARBY=1 with RAVEN_FAULT_CUSTODY=1): Alice
    has the LAN only (her node never joins the fake Bluetooth ether), Carol
    is the bridge (LAN and the ether, mail friend of both, background mail
    on with its own consent, `raven nearby background-mail on --yes`, owner
    decision OD-C8), and Bob is Bluetooth only for Raven (his node and ash
    with RAVEN_LAB_NEARBY_ONLY=1: no LAN listener, LAN dial or beacon, no
    Internet direct, no p2p; the computer's network is untouched). The three
    met once over the LAN (sessions, certificates); then Bob restarts
    nearby-only, so Alice and Carol know only his dead LAN address.
    T1, A -> B -> C: Bob's Bluetooth off, Alice sends 3: each is left with
    Carol over the LAN; Bob's Bluetooth on: Carol advertises for him (mail
    waits), he collects all 3 over nearby, exactly once, within 5 minutes
    of the radio coming on (the E2 rule), his receipts go back through
    Carol and Alice's history says delivered; Carol holds nothing at the
    end. T2, C -> A: Bob's Bluetooth off, he sends Alice 3 (queued); on
    again: left with Carol over nearby, Alice collects each over the LAN
    exactly once within 5 minutes, and her receipts reach Bob through Carol.
    Bob used nothing but nearby: his log has the nearby-only line and no
    LAN, Internet or p2p listener; every custody line of his names
    nearby_dial, as does every outbox item; his node never had a TCP
    connection to Alice's or Carol's LAN port; `raven doctor` says
    nearby_only on."""
    env = dict(NEARBY_ENV, RAVEN_LAB_CUSTODY_AFTER_MS='0', RAVEN_LAB_CUSTODY_FETCH_MS='1000')
    hub = EtherHub(root)
    # Alice: LAN only (no nearby gate, no ether); Carol and Bob on the ether.
    a = Node('a', root, env=dict(CUSTODY_ENV))
    b = Node('b', root, env=hub.env(env))
    c = Node('c', root, env=hub.env(env))
    nodes = (a, b, c)
    for n in nodes:
        n.init()
        n.start()
    for x in nodes:
        for y in nodes:
            if x is not y:
                x.add_pinned(y, NEARBY_TAGS[y.name])
    for x in nodes:
        for y in nodes:
            if x is not y:
                rc, out, _ = x.send(NEARBY_TAGS[y.name], f's128-meet-{x.name}{y.name}')
                assert status_word(out) == 'DELIVERED', out[-500:]
    on = c.ash('node', 'custody', 'on', '--yes')
    assert on.returncode == 0, on.stdout + on.stderr
    for x, tag in ((a, 'bob'), (b, 'alice')):
        r = x.ash('contact', 'set-addr', '--tag', tag, '--custodian', '@carol')
        assert r.returncode == 0, r.stdout + r.stderr
    background = c.ash('nearby', 'background-mail', 'on', '--yes')
    background_status = c.ash('nearby', 'background-mail', 'status').stdout
    # Bob becomes Bluetooth only for Raven: the same profile, restarted.
    b.stop()
    since = log_size(b)
    b.env = dict(b.env, RAVEN_LAB_NEARBY_ONLY='1')
    b.start()
    peers = TcpPeers(b.proc.pid)
    lan_ports = {int(n.dial.rsplit(':', 1)[1]) for n in (a, c)}
    for n in (b, c):
        r = n.ash('nearby', 'enable')
        assert r.returncode == 0, r.stdout + r.stderr
    for n in (b, c):
        assert wait_until(lambda: nearby_on_air(n), 30) is not None, nearby_status(n)
    doctor = b.ash('doctor').stdout

    def held_by_carol() -> int:
        m = re.search(r'held (\d+) sealed', c.ash('node', 'custody', 'status').stdout)
        return int(m.group(1)) if m else 0

    # T1: A -> C, over the LAN to Carol, then Bluetooth.
    hub.power(b, False)
    t1 = ['s128-t1-1', 's128-t1-2', 's128-t1-3']
    a_since = log_size(a)
    t1_sends = [status_word(a.send('bob', x)[1]) for x in t1]
    t1_held = wait_until(lambda: held_by_carol() >= 3, 120, 1)
    a_left = re.findall(r'raven-node custody: left (\d+) with a friend \(([a-z_]+)',
                        a.log_path.read_text(errors='replace')[a_since:])
    hub.power(b, True)
    t1_arrived = wait_until(lambda: all(count(b.inbox(), x) for x in t1), 300, 1)
    t1_receipts = wait_until(lambda: all_states(a, t1, 'delivered'), 120, 1)
    t1_empty = wait_until(lambda: held_by_carol() == 0, 120, 1)
    t1_counts, t1_order = inbox_once_in_order(b, t1)
    # T2: C -> A, Bluetooth first, then the LAN.
    hub.power(b, False)
    t2 = ['s128-t2-1', 's128-t2-2', 's128-t2-3']
    t2_sends = [status_word(b.send('alice', x)[1]) for x in t2]
    time.sleep(5)
    t2_early = [count(a.inbox(), x) for x in t2]
    hub.power(b, True)
    t2_held = wait_until(lambda: held_by_carol() >= 1 or all(count(a.inbox(), x) for x in t2),
                         60, 1)
    t2_arrived = wait_until(lambda: all(count(a.inbox(), x) for x in t2), 300, 1)
    t2_receipts = wait_until(lambda: all_states(b, t2, 'delivered'), 300, 1)
    time.sleep(3)
    t2_counts, t2_order = inbox_once_in_order(a, t2)
    peers.stop()
    b_log = b.log_path.read_text(errors='replace')[since:]
    b_custody = custody_carriers(b, since)
    b_carriers = carriers_used(b)
    forbidden = [l.strip() for l in b_log.splitlines()
                 if 'lan_direct: listen' in l or 'internet_direct: listen' in l
                 or 'p2p: host up' in l]
    lan_dials = sorted(lan_ports & peers.ports)
    return dict(
        ok=on.returncode == 0 and background.returncode == 0
        and 'ok background mail on' in background.stdout
        and background_status.startswith('background mail: on')
        and NEARBY_ONLY_LINE in b_log and 'nearby_only: on' in doctor
        and t1_sends == ['QUEUED'] * 3 and t1_held is not None
        and a_left and all(how == 'lan_dial' for _, how in a_left)
        and t1_arrived is not None and t1_arrived <= 300
        and all(v == 1 for v in t1_counts.values()) and t1_order
        and t1_receipts is not None and t1_empty is not None
        and t2_sends == ['QUEUED'] * 3 and t2_early == [0, 0, 0]
        and t2_held is not None and t2_arrived is not None and t2_arrived <= 300
        and all(v == 1 for v in t2_counts.values()) and t2_order
        and t2_receipts is not None
        and not forbidden and b_custody and set(b_custody) == {'nearby_dial'}
        and b_carriers <= {'nearby_dial'} and not lan_dials,
        background=(background.stdout + background.stderr).strip().splitlines()[:1],
        t1=dict(sends=t1_sends, held_by_carol_s=took(t1_held), alice_left=a_left,
                arrived_after_radio_s=took(t1_arrived), counts=t1_counts,
                in_order=t1_order, receipts_s=took(t1_receipts),
                carol_empty_s=took(t1_empty)),
        t2=dict(sends=t2_sends, before_radio=t2_early, left_with_carol_s=took(t2_held),
                arrived_after_radio_s=took(t2_arrived), counts=t2_counts,
                in_order=t2_order, receipts_s=took(t2_receipts)),
        bob=dict(nearby_only_line=NEARBY_ONLY_LINE in b_log,
                 doctor_says=[l.strip() for l in doctor.splitlines() if 'nearby' in l][:3],
                 custody_carriers=b_custody, outbox_carriers=sorted(b_carriers),
                 listeners=forbidden, lan_ports_dialled=lan_dials,
                 tcp_samples=peers.samples if peers.available else 'lsof missing'))


# ----------------------------------------------- Phase 6a: learning (P6.18)
LEARNING_KEYS = ('RAVEN_LAB_LEARNING', 'RAVEN_LAB_LEARNING_TUNE', 'RAVEN_LAB_LEARNING_SEALER')


def learning_env(on: bool, tag: str, tune: str = LEARNING_TUNE,
                 base: dict | None = None) -> dict:
    """A learning scenario's node env: `base` (ENV_NO_HINTS) with the Lab
    Test A unlock (Internet direct), a lab network tag of its own (`tag`,
    RAVEN_LAB_NET_TAG: the network learning keys what it learns by), no
    LAN beacon (it would find a listener past a dead proxy) and no route
    hints (LinkProxy tells a probe from a message dial by its records; an
    RRH1 would be one more), and learning on with `tune` or off."""
    env = without_beacon(dict(base or ENV_NO_HINTS, RAVEN_LAB_TEST_A='1', RAVEN_LAB_NET_TAG=tag))
    env.pop('RAVEN_LAB_ROUTE_HINTS', None)
    for key in LEARNING_KEYS:
        env.pop(key, None)
    if on:
        env.update(RAVEN_LAB_LEARNING='1', RAVEN_LAB_LEARNING_TUNE=tune)
    return env


# What a frame-less link's dialer writes (LinkProxy): Noise messages 1 and
# 3, its identity bind and its RLB1 offer.
LINK_RECORDS = 4


class LinkProxy:
    """A loopback TCP proxy in front of one Raven LAN listener (P6.18) that
    reads what the dialer writes as lan_direct's records (a 4-byte
    big-endian length, then that many bytes). Noise messages 1 and 3, the
    dialer's identity bind and its RLB1 offer are 4 records, so a link whose
    dialer wrote a 5th carried frames (a message, or an owed ACK) and one
    that ended with 4 or fewer was a probe (no frame; LINK_RECORDS). Route
    hints stay off where it is used: their RRH1 would be a 5th record.

    `set_mode`: `pass`, or `blackhole`: a host that went away, as carrier
    C70's TEST-NET address is. The listener stops accepting and its accept
    queue is filled by connections of its own, so a dialer's connect gets
    no answer at all (its SYN is dropped) and waits out its connect wait;
    the passed connections open then are cut. Each accepted connection is
    kept as a dict: mode, records, opened, cut (ended by such a cut)."""

    def __init__(self, target: str) -> None:
        host, port = target.rsplit(':', 1)
        self.target = (host, int(port))
        self.mode = 'pass'
        self.lock = threading.Lock()
        self.links: list = []
        self.live: list = []
        self.fillers: list = []
        self.filler_ports: set = set()
        self.lsock = socket.socket()
        self.lsock.bind(('127.0.0.1', 0))
        self.lsock.listen(1)
        self.lsock.settimeout(0.1)
        self.port = self.lsock.getsockname()[1]
        self.addr = f'127.0.0.1:{self.port}'
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            if self.mode == 'blackhole':
                time.sleep(0.05)
                continue
            try:
                client, peer = self.lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                filler = peer[1] in self.filler_ports
                self.filler_ports.discard(peer[1])
            if filler:
                self._close(client)
                continue
            client.settimeout(None)
            link = dict(mode=self.mode, records=0, opened=time.time(), cut=False)
            with self.lock:
                self.links.append(link)
            threading.Thread(target=self._handle, args=(client, link), daemon=True).start()

    @staticmethod
    def _records(buf: bytearray, link: dict) -> None:
        """Counts the complete records at the front of `buf` (and drops them)."""
        while len(buf) >= 4:
            n = int.from_bytes(buf[:4], 'big')
            if len(buf) < 4 + n:
                return
            del buf[:4 + n]
            link['records'] += 1

    @staticmethod
    def _close(*socks: socket.socket) -> None:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

    def _handle(self, client: socket.socket, link: dict) -> None:
        buf = bytearray()
        try:
            upstream = socket.create_connection(self.target, timeout=5)
        except OSError:
            self._close(client)
            return
        upstream.settimeout(None)
        pair = (client, upstream, link)
        with self.lock:
            self.live.append(pair)

        def pump(src: socket.socket, dst: socket.socket, count: bool) -> None:
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    if count:
                        buf.extend(data)
                        self._records(buf, link)
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                with self.lock:
                    if pair in self.live:
                        self.live.remove(pair)
                self._close(src, dst)

        threading.Thread(target=pump, args=(client, upstream, True), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client, False), daemon=True).start()

    def _fill(self) -> None:
        """Fills the listener's accept queue with connections of its own
        (until one no longer completes): new connects get no answer."""
        for _ in range(8):
            s = socket.socket()
            s.setblocking(False)
            s.connect_ex(('127.0.0.1', self.port))
            with self.lock:
                self.fillers.append(s)
                self.filler_ports.add(s.getsockname()[1])
            _, ready, _ = select.select([], [s], [], 0.3)
            if not ready or s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) != 0:
                return

    def set_mode(self, mode: str) -> None:
        """New connections get `mode` (`pass` or `blackhole`, above)."""
        if mode == self.mode:
            return
        self.mode = mode
        if mode == 'pass':
            with self.lock:
                fillers, self.fillers = self.fillers, []
            self._close(*fillers)
            return
        time.sleep(0.3)  # the accept loop sees the mode within 0.1 s
        self._fill()
        with self.lock:
            live, self.live = self.live, []
        for client, upstream, link in live:
            link['cut'] = True
            for s in (client, upstream):
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self._close(client, upstream)

    def since(self, t0: float) -> list:
        with self.lock:
            return [dict(l) for l in self.links if l['opened'] >= t0]

    def count(self, mode: str | None = None, t0: float = 0.0) -> int:
        return sum(1 for l in self.since(t0) if mode is None or l['mode'] == mode)


def learn_status(node: Node) -> dict:
    """`ash learning status --json`: raven-node's learning report (or one
    with only a `state`: held, off, not_running); {} when unreadable."""
    r = node.ash('learning', 'status', '--json', timeout=30)
    for line in reversed(r.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return {}


def learn_row(node: Node, other: Node) -> dict:
    """`node`'s learning row for `other` on its current network, {} without."""
    return next((row for row in learn_status(node).get('rows', [])
                 if row.get('peer_pub_hex', '').lower() == other.pub.lower()), {})


def learn_order(node: Node, other: Node) -> list:
    """The carrier order `node` uses for `other` on this network, as its
    row shows it ([] without a row: nothing learned, the static order)."""
    return learn_row(node, other).get('order', [])


def learn_why(node: Node, other: Node) -> str:
    """The `why=` token of `node`'s row for `other` ('' without a row)."""
    m = re.search(r'\bwhy=(\w+)', learn_row(node, other).get('why', ''))
    return m.group(1) if m else ''


def wait_learning(node: Node, state: str = 'on', secs: float = 30) -> float | None:
    """Seconds until `node` reports learning `state` (its service reads the
    switch every 2 s and loads the model then)."""
    return wait_until(lambda: learn_status(node).get('state') == state, secs, 1)


LAN_FAILED = re.compile(r'lan_dial \S+ did not answer; trying')


def vsend(node: Node, tag: str, text: str) -> dict:
    """A verbose `ash send` (RAVEN_VERBOSE=1): its outcome, seconds, the
    carrier it was delivered on (`carrier=`) and whether a LAN route was
    tried first and did not answer (`lan_failed`: its 'lan_dial … did not
    answer; trying …' line), the send's own record of what it dialled."""
    rc, out, dt = node.send(tag, text, extra_env={'RAVEN_VERBOSE': '1'})
    carrier = re.search(r'carrier=(\w+)', out)
    return dict(status=status_word(out), s=round(dt, 2),
                carrier=carrier.group(1) if carrier else '',
                lan_failed=bool(LAN_FAILED.search(out)), rc=rc, out=out[-600:])


def learning_pair(root: Path, env: dict, b_env: dict | None = None):
    """Alice and Bob (`env`; Bob `b_env` when given), verified both ways:
    Bob listens for Internet direct too, Alice's LAN route to him goes
    through a LinkProxy and she also holds his Internet route. Returns
    (a, b, proxy) once Alice's learning (if on) is loaded."""
    a, b = Node('a', root, env), Node('b', root, b_env or env)
    a.init(); b.init()
    a.start(); b.start(inet_port=0)
    lan = LinkProxy(b.dial)
    a.add_pinned(b, 'bob', dial=lan.addr)
    r = a.ash('contact', 'set-addr', '@bob', '--internet', b.inet)
    assert r.returncode == 0, r.stdout + r.stderr
    b.add_pinned(a, 'alice')
    if env.get('RAVEN_LAB_LEARNING') == '1':
        assert wait_learning(a) is not None, learn_status(a)
    return a, b, lan


def exactly_once(node: Node, texts: list) -> dict:
    inbox = node.inbox()
    return {t: count(inbox, t) for t in texts}


# s100's sends: one every FLAKY_CADENCE_S, the LAN flapping between a black
# hole and pass every FLAKY_PHASE sends (20 s at that cadence). The flaps
# happen between two sends, never during one, so both runs meet the same
# ones (a flap that falls inside a send turns it into a retry storm that
# says nothing about the order).
FLAKY_CADENCE_S = 5
FLAKY_PHASE = 4


def flaky_run(root: Path, on: bool) -> dict:
    """One s100 run: 16 sends on a FLAKY_CADENCE_S cadence, the LAN proxy a
    black hole for the first FLAKY_PHASE, then passing for the next, and so
    on (a cut on each black hole)."""
    root.mkdir(parents=True, exist_ok=True)
    a, b, lan = learning_pair(root, learning_env(on, 's100'))
    warm = vsend(a, 'bob', f's100-{root.name}-warm')
    memory = a.dir / 'route_memory.json'
    texts = [f's100-{root.name}-{i}' for i in range(16)]
    t0 = time.time()
    sends = []
    for i, text in enumerate(texts):
        time.sleep(max(0.0, t0 + FLAKY_CADENCE_S * i - time.time()))
        lan.set_mode('blackhole' if (i // FLAKY_PHASE) % 2 == 0 else 'pass')
        if not on:
            # Learning off is the static order, as a release build has it:
            # the lab-only route memory (G2, superseded while learning is
            # on) would otherwise send every later message by the Internet
            # for its 30 min lease.
            try:
                memory.unlink()
            except FileNotFoundError:
                pass
        sends.append(vsend(a, 'bob', text))
    lan.set_mode('pass')
    waited = lan.since(t0)
    all_texts = [f's100-{root.name}-warm'] + texts
    arrived = wait_until(lambda: all(c >= 1 for c in exactly_once(b, all_texts).values()),
                         180, 2)
    time.sleep(3)
    once = exactly_once(b, all_texts)
    return dict(
        ok=warm['status'] == 'DELIVERED' and arrived is not None
        and all(n == 1 for n in once.values()),
        total_s=round(sum(s['s'] for s in sends), 1),
        sends_paying_lan_wait=sum(1 for s in sends if s['lan_failed']),
        duplicates=sum(1 for l in waited if l['cut'] and l['records'] > LINK_RECORDS),
        statuses=[s['status'] for s in sends], seconds=[s['s'] for s in sends],
        carriers=[('lan,' if s['lan_failed'] else '') + s['carrier'] for s in sends],
        slow=[s['out'] for s in sends if s['s'] > 2.5][:4],
        not_exactly_once={t: n for t, n in once.items() if n != 1},
        probes_24h=learn_status(a).get('probes_24h') if on else None)


def s100_learning_flaky_lan(root: Path) -> dict:
    """Phase 6a (P6.18, RAVEN_FAULT_LEARNING=1): Alice's LAN route to Bob
    goes through a proxy that flaps between a black hole and pass every
    4 sends (20 s at a 5 s cadence; between two sends, cutting what was
    open at each black hole); Bob's Internet listener always works. 16
    sends, once with learning on and once with it off (the static order:
    the lab-only route memory is cleared before each send, as a release
    build has none).
    Learning's total send time is at most 0.6x the off run's, and it pays
    the LAN's black-hole wait (a connect that gets no answer, LinkProxy) in
    fewer sends (counted by each send's own 'did not answer' line); every
    message arrives exactly once in both runs, with at most 2 duplicates
    (frames written on a link a black hole then cut, so sent again)."""
    on = flaky_run(root / 'on', True)
    off = flaky_run(root / 'off', False)
    return dict(
        ok=on['ok'] and off['ok'] and on['total_s'] <= 0.6 * off['total_s']
        and on['sends_paying_lan_wait'] < off['sends_paying_lan_wait']
        and on['duplicates'] <= 2 and off['duplicates'] <= 2,
        ratio=round(on['total_s'] / max(off['total_s'], 0.1), 2), learning=on, off=off)


def s101_learning_per_network(root: Path) -> dict:
    """Phase 6a (P6.18): Alice's network alternates between 'home' and
    'office' (RAVEN_LAB_NET_TAG, her node restarted on each move); at home
    the LAN to Bob works, the office's LAN is a black hole (the proxy).
    Each network keeps its own order: at the office Alice goes Internet
    first after one black-hole wait; back home she goes LAN first at once
    (no LAN failure, delivered over the LAN); back at the office again the
    Internet first at once. Learning's rows differ per network."""
    env = {tag: learning_env(True, tag) for tag in ('home', 'office')}
    a, b, lan = learning_pair(root, env['home'], learning_env(True, 's101-bob'))

    def move(tag: str, mode: str) -> None:
        a.stop()
        a.env = env[tag]
        lan.set_mode(mode)
        a.start()
        assert wait_learning(a) is not None, learn_status(a)

    home = [vsend(a, 'bob', f's101-home-{i}') for i in range(3)]
    home_order = learn_order(a, b)
    move('office', 'blackhole')
    office = [vsend(a, 'bob', f's101-office-{i}') for i in range(4)]
    office_order = learn_order(a, b)
    move('home', 'pass')
    t_home = time.time()
    back_home = vsend(a, 'bob', 's101-home-back')
    home_lan_links = lan.count('pass', t_home)
    home_again = learn_order(a, b)
    move('office', 'blackhole')
    back_office = vsend(a, 'bob', 's101-office-back')
    office_again = learn_order(a, b)
    texts = ([f's101-home-{i}' for i in range(3)] + [f's101-office-{i}' for i in range(4)]
             + ['s101-home-back', 's101-office-back'])
    time.sleep(3)
    once = exactly_once(b, texts)
    return dict(
        ok=all(s['status'] == 'DELIVERED' and not s['lan_failed'] for s in home)
        and all(s['status'] == 'DELIVERED' for s in office) and office[0]['lan_failed']
        and office_order[:1] == ['internet_dial'] and home_order[:1] != ['internet_dial']
        and back_home['status'] == 'DELIVERED' and not back_home['lan_failed']
        and back_home['carrier'] == 'lan_dial' and home_lan_links >= 1
        and home_again[:1] != ['internet_dial']
        and back_office['status'] == 'DELIVERED' and not back_office['lan_failed']
        and back_office['carrier'] == 'internet_dial' and office_again[:1] == ['internet_dial']
        and all(n == 1 for n in once.values()),
        home=home, home_order=home_order, office=office, office_order=office_order,
        back_home=back_home, home_lan_links=home_lan_links, home_order_again=home_again,
        back_office=back_office, office_order_again=office_again,
        not_exactly_once={t: n for t, n in once.items() if n != 1})


def file_state(path: Path) -> tuple:
    """(mtime_ns, sha256) of `path`, or None while it does not exist."""
    try:
        return (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
    except FileNotFoundError:
        return None


def s102_learning_reset_and_off(root: Path) -> dict:
    """Phase 6a (P6.18): Alice learned to go Internet first to Bob (his LAN
    is a black hole). `ash learning reset --contact bob --yes`, then `ash
    learning off --forget`, then `ash learning on`: after each, her next
    send is in the static order again (LAN first, its black-hole wait
    paid); `off --forget` deletes learning.bin; node_policy.json's
    `learning` field changes only with ash's commands (raven-node never
    writes it: the file is the same after the sends that follow each)."""
    a, b, lan = learning_pair(root, learning_env(True, 's102'))
    lan.set_mode('blackhole')
    taught = [vsend(a, 'bob', f's102-learn-{i}') for i in range(3)]
    learned = learn_order(a, b)
    policy = a.dir / 'node_policy.json'
    steps = {}
    for name, args in (('reset', ('learning', 'reset', '--contact', 'bob', '--yes')),
                       ('off', ('learning', 'off', '--forget')),
                       ('on', ('learning', 'on'))):
        r = a.ash(*args)
        state = 'off' if name == 'off' else 'on'
        settled = wait_learning(a, state)
        written = file_state(policy)
        send = vsend(a, 'bob', f's102-after-{name}')
        try:
            field = json.loads(policy.read_text()).get('learning')
        except FileNotFoundError:
            field = None
        except (OSError, ValueError):
            field = 'unreadable'
        steps[name] = dict(rc=r.returncode, out=(r.stdout + r.stderr).strip()[-200:],
                           settled=settled is not None, send=send,
                           policy_learning=field,
                           policy_untouched_by_node=file_state(policy) == written,
                           learning_bin=(a.dir / 'learning.bin').exists())
    texts = [f's102-learn-{i}' for i in range(3)] + [f's102-after-{n}' for n in steps]
    time.sleep(3)
    once = exactly_once(b, texts)
    return dict(
        ok=learned[:1] == ['internet_dial']
        and all(s['rc'] == 0 and s['settled'] and s['send']['status'] == 'DELIVERED'
                and s['send']['lan_failed'] and s['policy_untouched_by_node']
                for s in steps.values())
        and steps['off']['policy_learning'] is False and not steps['off']['learning_bin']
        and steps['on']['policy_learning'] is not False
        and all(n == 1 for n in once.values()),
        taught=[s['status'] for s in taught], learned=learned, steps=steps,
        not_exactly_once={t: n for t, n in once.items() if n != 1})


def s103_probes_revive_a_healed_lan(root: Path) -> dict:
    """Phase 6a (P6.18): Alice learned Internet first to Bob while his LAN
    was dead (a black hole for 3 minutes, from her first send to it on),
    then the LAN heals and nobody sends anything for up to 35 minutes. Her
    explorer's probes (frame-less dials, counted at the LAN proxy: at most
    LINK_RECORDS records each) bring LAN first back, no probe carries a frame, and there
    are no more of them than the budget allows (a burst of 2, then 6 an
    hour). Harness gaps RAVEN_LAB_LEARNING_TUNE=300,15,3600: no probe
    while the LAN is dead (the budget is full when it heals), then the
    recovering gap of 15 s; the window is longer than the plan's 10 minutes
    because the 6-an-hour budget allows only one probe per 10 minutes once
    the burst is spent (P6.14's open item)."""
    a, b, lan = learning_pair(root, learning_env(True, 's103', tune='300,15,3600'))
    warm = vsend(a, 'bob', 's103-warm')
    lan.set_mode('blackhole')
    t_dead = time.time()
    dead = [vsend(a, 'bob', f's103-dead-{i}') for i in range(3)]
    learned = learn_order(a, b)
    time.sleep(max(0.0, t_dead + 180 - time.time()))
    lan.set_mode('pass')
    t_quiet = time.time()
    back = wait_until(lambda: learn_order(a, b)[:1] == ['lan_dial'], 35 * 60, 20)
    window_s = time.time() - t_quiet
    links = lan.since(t_quiet)
    probes = [l for l in links if l['records'] <= LINK_RECORDS]
    framed = [l for l in links if l['records'] > LINK_RECORDS]
    budget = 2 + int(window_s // 600)
    status = learn_status(a)
    after = vsend(a, 'bob', 's103-after')
    texts = ['s103-warm', 's103-after'] + [f's103-dead-{i}' for i in range(3)]
    time.sleep(3)
    once = exactly_once(b, texts)
    return dict(
        ok=warm['status'] == 'DELIVERED' and learned[:1] == ['internet_dial']
        and back is not None and 1 <= len(probes) <= budget and not framed
        and after['status'] == 'DELIVERED' and not after['lan_failed']
        and after['carrier'] == 'lan_dial' and all(n == 1 for n in once.values()),
        dead=[(s['status'], s['lan_failed'], s['s']) for s in dead], learned=learned,
        lan_first_again_s=took(back), probes_at_proxy=len(probes),
        framed_links=len(framed), budget=budget, probes_24h=status.get('probes_24h'),
        after=after, not_exactly_once={t: n for t, n in once.items() if n != 1})


def s104_learning_ages_out(root: Path) -> dict:
    """Phase 6a (P6.18, the cutoff pack's lab clock): Alice learned
    Internet first to Bob (his LAN a black hole), then his LAN heals and
    nobody sends. Both nodes stop, their shared LabClock moves 3 days on,
    both start again (Bob on his ports): Alice's next send, within her
    explorer's first minute (its first tick is a minute after the start,
    so no probe can have run: a long tuned probe gap alone would not stop
    the first probe of an arm never probed once it has gone 30 min
    unobserved), goes LAN first purely because what she learned decayed (a
    1-day half-life), and `ash learning status` names the row `cold` or
    `kept`, or none."""
    clock = LabClock(root / 'lab.clock')
    env = clock.env(learning_env(True, 's104', tune='604800,604800,3600'))
    a, b, lan = learning_pair(root, env)
    warm = vsend(a, 'bob', 's104-warm')
    lan.set_mode('blackhole')
    taught = [vsend(a, 'bob', f's104-learn-{i}') for i in range(3)]
    learned = learn_order(a, b)
    lan.set_mode('pass')
    # Counted now: three days on, `ash inbox` no longer lists them.
    before = exactly_once(b, ['s104-warm'] + [f's104-learn-{i}' for i in range(3)])
    port, inet_port = int(b.dial.rsplit(':', 1)[1]), int(b.inet.rsplit(':', 1)[1])
    a.stop()
    b.stop()
    clock.advance(3 * 86_400_000)
    b.start(port=port, inet_port=inet_port)
    a.start()
    t_start = time.time()
    assert wait_learning(a) is not None, learn_status(a)
    why = learn_why(a, b)
    probes = learn_status(a).get('probes_24h')
    t_send = time.time()
    after = vsend(a, 'bob', 's104-after')
    in_first_minute = time.time() - t_start < 60
    lan_links = lan.count('pass', t_send)
    time.sleep(3)
    once = dict(before, **exactly_once(b, ['s104-after']))
    return dict(
        ok=warm['status'] == 'DELIVERED' and learned[:1] == ['internet_dial']
        and why in ('', 'cold', 'kept') and probes == 0 and in_first_minute
        and after['status'] == 'DELIVERED' and not after['lan_failed']
        and after['carrier'] == 'lan_dial' and lan_links >= 1
        and all(n == 1 for n in once.values()),
        taught=[s['status'] for s in taught], learned=learned, why_after_3_days=why,
        probes_24h=probes, after=after, sent_in_first_minute=in_first_minute,
        lan_links=lan_links, not_exactly_once={t: n for t, n in once.items() if n != 1})


def s106_learning_never_probes_strangers(root: Path) -> dict:
    """Phase 6a (P6.18): Alice's explorer probes only verified, unblocked
    contacts she wrote to, on routes that delivered on this network. Her
    book: Bob (verified; his LAN delivered, then went dark so she learned
    Internet first, then healed: the positive control), Carol (verified,
    written to, but her saved LAN address is a proxy to a stranger's node
    that never delivered here), Dave (verified, delivered over the LAN,
    then blocked) and Erin (unverified, delivered over the LAN). Over 4
    minutes of quiet (harness probe gap 60 s) each proxy counts its
    connections: none reach Carol's, Dave's or Erin's; every probe goes to
    Bob's (at least one, all frame-less), as many as `probes_24h` says."""
    env = learning_env(True, 's106')
    a, b, lan = learning_pair(root, env)
    s, d, e = (Node(n, root, env) for n in ('s', 'd', 'e'))
    carol = Node('c', root, env)
    for n in (s, d, e, carol):
        n.init()
    for n in (s, d, e):
        n.start()
    proxies = {'carol': LinkProxy(s.dial), 'dave': LinkProxy(d.dial), 'erin': LinkProxy(e.dial)}
    a.add_pinned(carol, 'carol', dial=proxies['carol'].addr)
    a.add_pinned(d, 'dave', dial=proxies['dave'].addr)
    a.add(e, 'erin', dial=proxies['erin'].addr)
    d.add_pinned(a, 'alice')
    e.add(a, 'alice')
    first = {'bob': vsend(a, 'bob', 's106-bob-lan'),
             'dave': vsend(a, 'dave', 's106-dave'),
             'erin': vsend(a, 'erin', 's106-erin'),
             'carol': vsend(a, 'carol', 's106-carol')}
    lan.set_mode('blackhole')
    dark = [vsend(a, 'bob', f's106-bob-dark-{i}') for i in range(3)]
    learned = learn_order(a, b)
    lan.set_mode('pass')
    # Dave on Alice's block list: written while her node is stopped, and
    # sealed by it at its next start (as an older build's plain list is).
    a.stop()
    blocked = {'pub_hex': [d.pub]}
    (a.dir / 'blocked_pubs.json').write_text(json.dumps(blocked, indent=2))
    a.start()
    assert wait_learning(a) is not None, learn_status(a)
    t_quiet = time.time()
    time.sleep(240)
    seen = {name: len(p.since(t_quiet)) for name, p in proxies.items()}
    bob_links = lan.since(t_quiet)
    status = learn_status(a)
    return dict(
        ok=first['bob']['status'] == 'DELIVERED' and first['dave']['status'] == 'DELIVERED'
        and first['erin']['status'] == 'DELIVERED' and learned[:1] == ['internet_dial']
        and all(n == 0 for n in seen.values()) and len(bob_links) >= 1
        and all(l['records'] <= LINK_RECORDS for l in bob_links)
        and status.get('probes_24h') == len(bob_links),
        first={k: v['status'] for k, v in first.items()}, learned=learned,
        links_to_others=seen, probes_to_bob=len(bob_links),
        bob_framed=sum(1 for l in bob_links if l['records'] > LINK_RECORDS),
        probes_24h=status.get('probes_24h'),
        blocked_sealed=is_rms1(a.dir / 'blocked_pubs.json'))



def custody_held(node: Node) -> int:
    """How many sealed messages a custodian holds (`ash node custody
    status`: 'held N sealed'), 0 when it says none."""
    m = re.search(r'held (\d+) sealed', node.ash('node', 'custody', 'status').stdout)
    return int(m.group(1)) if m else 0


def carry_rows(node: Node, other: Node) -> list:
    """`node`'s carry choice for mail to `other` (IPC LearningPlan's carry
    rows, first left with first): [] while it learned nothing or is off."""
    try:
        plan = node_ipc(node, {'op': 'learning_plan', 'v': 1, 'peer_pub_hex': other.pub})
    except (OSError, ValueError):
        return []
    return plan.get('carry') or []


def friends_named(out: str) -> list:
    """The friends a queued text says raven-node leaves a sealed copy with,
    in its order ('… leaves a sealed copy with Fay and Gus …')."""
    m = re.search(r'leaves a sealed copy with (.+?) (?:after|within|once|in|as)\b', out)
    return re.findall(r'[A-Z][a-z]+', m.group(1)) if m else []


def carry_world(root: Path, env: dict) -> tuple:
    """s105's people: Alice, Bob and two friends who keep mail, Fay and Gus
    (`node custody on`), every one verified by every other, Alice's book
    holding Gus before Fay. Alice uses friends as mailboxes and collects
    from Fay only (`custody home @fay`), and lists Fay for Bob; Bob lists
    Gus for Alice, so his route hints announce Gus to her (she holds Gus's
    custody offer from her own link to him). Bob's candidates on Alice's
    side are therefore Gus (announced) then Fay (listed). Warm-ups carry
    the hints: Alice to Gus, Alice to Fay, Alice to Bob and back."""
    a, b, fay, gus = (Node(n, root, env) for n in ('a', 'b', 'fay', 'gus'))
    people = (a, b, fay, gus)
    for n in people:
        n.init()
    for n in people:
        n.start()
    for x, y, tag in ((a, gus, 'gus'), (a, fay, 'fay'), (a, b, 'bob'), (b, a, 'alice'),
                      (b, fay, 'fay'), (b, gus, 'gus'), (fay, a, 'alice'), (fay, b, 'bob'),
                      (gus, a, 'alice'), (gus, b, 'bob')):
        x.add_pinned(y, tag)
    steps = [n.ash('node', 'custody', 'on', '--yes') for n in (fay, gus)]
    steps += [a.ash('custody', 'use', 'on', '--yes'), a.ash('custody', 'home', '@fay'),
              a.ash('contact', 'set-addr', '--tag', 'bob', '--custodian', '@fay'),
              b.ash('contact', 'set-addr', '--tag', 'alice', '--custodian', '@gus')]
    for r in steps:
        assert r.returncode == 0, r.stdout + r.stderr
    warm = [status_word(x.send(tag, f's105-warm-{x.name}-{tag}')[1])
            for x, tag in ((a, 'gus'), (a, 'fay'), (a, 'bob'), (b, 'alice'))]
    return a, b, fay, gus, warm


def s105_carry_choice_by_encounters(root: Path) -> dict:
    """Phase 6a (P6.18, RAVEN_FAULT_CUSTODY=1, one LabClock): carry choice
    from Alice's own encounters (carry_world). With learning off, Bob away
    and Gus away too, Alice's message to Bob is left with Gus and Fay in
    that order (the static choice: Bob's announced Gus first), Fay takes
    it. With learning on: Gus goes away after the setup; each simulated day
    (the lab clock +1 d) Alice still links with Fay (her mailbox) and never
    with Gus. Two days on, Bob comes back for one message and leaves
    again; Alice's three messages are left with Fay first (her queued text
    says so: 'Left with Fay first (you meet often'; LearningPlan's carry
    rows, the worker's pick, too), never with more than two friends (the
    cap). Bob comes back next to Fay (Gus still away): each arrives exactly
    once and the receipts credit Fay (her carry row counts them delivered).
    Then Bob leaves for good: two more are left with Fay and expire (the
    lab clock +25 h), and Fay's carry record counts outcomes that did not
    deliver: her score falls."""
    base = without_beacon(dict(CUSTODY_ENV, RAVEN_LAB_ROUTE_HINTS='1'))
    for key in LEARNING_KEYS:
        base.pop(key, None)
    # Learning off: the static order.
    off_root = root / 'off'
    off_root.mkdir()
    a, b, fay, gus, warm_off = carry_world(off_root, base)
    gus.stop()
    b.stop()
    rc, out_off, _ = a.send('bob', 's105-off')
    off_named = friends_named(out_off)
    off_held = wait_until(lambda: custody_held(fay) >= 1, 90, 1)
    for n in (a, fay):
        n.stop()

    # Learning on.
    on_root = root / 'on'
    on_root.mkdir()
    clock = LabClock(on_root / 'lab.clock')
    env = clock.env(dict(base, RAVEN_LAB_LEARNING='1', RAVEN_LAB_LEARNING_TUNE=LEARNING_TUNE))
    a, b, fay, gus, warm_on = carry_world(on_root, env)
    assert wait_learning(a) is not None, learn_status(a)
    b_port = int(b.dial.rsplit(':', 1)[1])
    gus.stop()
    b.stop()
    days = []
    for day in (1, 2):
        clock.advance(86_400_000)
        # Alice collects from Fay (her fetch pass) and writes to her.
        a.send('fay', f's105-day-{day}')
        met = wait_until(lambda: any(r.get('met') == 'often' and
                                     r.get('peer_pub_hex', '').lower() == fay.pub.lower()
                                     for r in carry_rows(a, b)), 60, 2)
        days.append(dict(day=day, fay_often_s=took(met), carry=carry_rows(a, b)))
    # Bob back for one message (a session for today), then away again.
    b.start(port=b_port)
    back = status_word(a.send('bob', 's105-today')[1])
    b.stop()
    texts = [f's105-left-{i}' for i in range(3)]
    sends = [a.send('bob', t)[1] for t in texts]
    named = [friends_named(o) for o in sends]
    first_words = ['Left with Fay first (you meet often' in o for o in sends]
    pick = carry_rows(a, b)
    held = wait_until(lambda: custody_held(fay) >= 3, 120, 1)
    # Bob comes back next to Fay; Gus is still away.
    b.start(port=b_port)
    got = wait_until(lambda: all(count(b.inbox(), t) >= 1 for t in texts), 180, 2)
    settled = wait_until(lambda: 'Nothing waiting' in a.outbox(), 120, 2)
    time.sleep(3)
    once = exactly_once(b, texts + ['s105-today'])
    credited = wait_until(lambda: any(r.get('delivered', 0) >= 1 and
                                      r.get('peer_pub_hex', '').lower() == fay.pub.lower()
                                      for r in carry_rows(a, b)), 60, 2)
    before = next((r for r in carry_rows(a, b)
                   if r.get('peer_pub_hex', '').lower() == fay.pub.lower()), {})
    # Bob away for good: what Fay holds now expires.
    b.stop()
    later = [status_word(a.send('bob', f's105-late-{i}')[1]) for i in range(2)]
    held_late = wait_until(lambda: custody_held(fay) >= 2, 120, 1)
    clock.advance(25 * 3_600_000)

    def fay_row() -> dict:
        return next((r for r in carry_rows(a, b)
                     if r.get('peer_pub_hex', '').lower() == fay.pub.lower()), {})
    fell = wait_until(lambda: fay_row().get('outcomes', 0) > before.get('outcomes', 0)
                      and fay_row().get('delivered', 0) <= before.get('delivered', 0), 180, 3)
    after = fay_row()
    return dict(
        ok=warm_off == ['DELIVERED'] * 4 and off_named[:2] == ['Gus', 'Fay']
        and off_held is not None
        and warm_on == ['DELIVERED'] * 4 and back == 'DELIVERED'
        and all(n[:1] == ['Fay'] and len(n) <= 2 for n in named) and all(first_words)
        and pick[:1] and pick[0].get('peer_pub_hex', '').lower() == fay.pub.lower()
        and len(pick) <= 2 and held is not None and got is not None and settled is not None
        and all(n == 1 for n in once.values()) and credited is not None
        and held_late is not None and fell is not None,
        off=dict(send=status_word(out_off), named=off_named, fay_held_s=took(off_held),
                 text=out_off[-500:]),
        days=days, bob_back=back, named=named, said_fay_first=first_words,
        pick=pick, fay_held_s=took(held), delivered_s=took(got), outbox_settled_s=took(settled),
        not_exactly_once={t: n for t, n in once.items() if n != 1},
        fay_before_expiry=before, late=later, fay_after_expiry=after, score_fell_s=took(fell))


# A Noise transport message of a PAD1 frame (protocol/RAVEN_LINK_PADDING_V1.md
# §8): a bucket and the 16-byte tag.
PAD1_MESSAGES = {b + 16 for b in (512, 4_096, 16_384, 65_519)}
# The LAN bind (96 bytes) as a Noise transport message, and message 3 with an
# empty payload (the dialer's static and two tags): a dial that offered
# nothing, a frame-less probe or a build without PAD1.
PAD1_BIND = 96 + 16
PAD1_EMPTY_M3 = 64


def pad1_pair(root: Path, envs: tuple, bins: tuple = ('', '')) -> tuple:
    """Alice and Bob (`envs`, `bins`: their environments and builds), each
    pinning the other at a recording Proxy in front of the other's
    listener: (alice, bob, the proxy in front of alice, the one in front of
    bob)."""
    a, b = Node('a', root, envs[0], bins[0]), Node('b', root, envs[1], bins[1])
    for n in (a, b):
        n.init()
        n.start()
    pa, pb = Proxy(a.dial, record=True), Proxy(b.dial, record=True)
    a.add_pinned(b, 'bob', dial=pb.addr)
    b.add_pinned(a, 'alice', dial=pa.addr)
    return a, b, pa, pb


def pad1_exchange(a: Node, b: Node, label: str, n: int = 3) -> dict:
    """`n` messages each way, alternating; each must arrive exactly once."""
    sends = []
    for i in range(n):
        sends.append(status_word(a.send('bob', f'pad1-{label}-a2b-{i}')[1]))
        sends.append(status_word(b.send('alice', f'pad1-{label}-b2a-{i}')[1]))
    for i in range(n):
        wait_inbox(b, f'pad1-{label}-a2b-{i}', 60)
        wait_inbox(a, f'pad1-{label}-b2a-{i}', 60)
    ib, ia = b.inbox(), a.inbox()
    once = (all(count(ib, f'pad1-{label}-a2b-{i}') == 1 for i in range(n))
            and all(count(ia, f'pad1-{label}-b2a-{i}') == 1 for i in range(n)))
    return dict(sends=sends, exactly_once=once)


def pad1_connections(*proxies: Proxy) -> list:
    """The LAN connections the proxies carried past the bind: (dialer's
    message lengths: m1, m3, bind, frames; listener's: m2, bind, frames)."""
    return [(d, l) for p in proxies for d, l in p.messages() if len(d) >= 3 and len(l) >= 2]


def pad1_breaks(conns: list, padded: bool) -> list:
    """Where `conns` break PAD1's LAN rule (empty: nowhere). Both ends pad
    (`padded`) and the dial offered it (a payload in m3): every message after
    the dialer's bind is a bucket plus the tag, the listener's bind first.
    Otherwise nothing is padded: the listener's bind stays 96 bytes, and no
    message is a bucket's size."""
    bad = []
    for d, l in conns:
        frames = d[3:] + l[1:]
        if d[2] != PAD1_BIND:
            bad.append(('dialer bind', d, l))
        elif padded and d[1] > PAD1_EMPTY_M3:
            if not all(n in PAD1_MESSAGES for n in frames):
                bad.append(('not padded', d, l))
        elif l[1] != PAD1_BIND or any(n in PAD1_MESSAGES for n in frames):
            bad.append(('padded', d, l))
    return bad


# What neither side of a PAD1 pair may log: a link padding refusal (a frame
# that broke PAD1), and MIXED_BAD / MIXED_HANDSHAKE (s04c's).
PAD1_BAD = MIXED_BAD + ('link padding',)


def pad1_logs(*nodes: Node) -> dict:
    logs = {n.name: n.log_path.read_text(errors='replace') for n in nodes}
    bad = {name: [l for l in log.splitlines() if any(x in l for x in PAD1_BAD)]
           + MIXED_HANDSHAKE.findall(log) for name, log in logs.items()}
    return {k: v[:3] for k, v in bad.items() if v}


def knock_shapes(proxy: Proxy, dialer_knocks: bool, listener_knocks: bool) -> list:
    """Where the handshakes `proxy` carried break RLK1's shape
    (protocol/RAVEN_LINK_KNOCK_V1.md §6; empty: nowhere): message 1 is 32
    bytes, or 64-95 from a knocking dialer; message 2 96, or 112-143 from a
    knocking listener; message 3 64, or 71-128 from a knocking dialer (an
    RLX1 PAD entry; route hints are off here)."""
    bad = []
    for d, l in proxy.messages():
        if len(d) < 2 or not l:
            continue
        m1, m2, m3 = d[0], l[0], d[1]
        ok = ((64 <= m1 <= 95 and 71 <= m3 <= 128) if dialer_knocks else (m1 == 32 and m3 == 64))
        ok = ok and ((112 <= m2 <= 143) if listener_knocks else m2 == 96)
        if not ok:
            bad.append((m1, m2, m3))
    return bad


def knock_phases(root: Path) -> dict:
    """Phase 6b P6.35 (RAVEN_FAULT_KNOCK=1; with carrier_matrix C86 part 2):
    the RLK1 link knock between real nodes over LAN, every node with the
    noise pins (M0), every contact route through a recording Proxy.
    (knock_new) Two knocking nodes (KNOCK_ENV): 3 messages each way, each
    exactly once, every handshake knocked both ways (RLK1's sizes) and at
    least one each way. (knock_mixed_a, knock_mixed_b) A knocking node and an
    M0-only one, both ways round: with RAVEN_FAULT_PADDING_OLD_BIN=<dir with
    a pre-6b ash and raven-node> the M0-only one runs that build (its pins
    predate 6b), else this build without the knock switch: every message
    once, the knocking dialer's handshakes knocked and the M0-only
    listener's plain (no proof: its pin of the derived static decides), the
    M0-only dialer's plain and the knocking listener's message 2 jittered
    (legacy: the contact's floor lacks the knock), and no pin mismatch,
    padding refusal, dispatcher refusal or failed handshake in either log.
    The impostor rows (s113) wait for P6.32."""
    phases = {}
    sub = root / 'knock-new'
    sub.mkdir()
    a, b, pa, pb = pad1_pair(sub, (KNOCK_ENV, KNOCK_ENV))
    done = pad1_exchange(a, b, 'knock')
    breaks = knock_shapes(pa, True, True) + knock_shapes(pb, True, True)
    each_way = [len([1 for d, l in p.messages() if len(d) >= 2 and l]) for p in (pa, pb)]
    bad = knock_logs(a, b)
    for n in (a, b):
        n.stop()
    phases['knock_new'] = dict(ok=done['exactly_once'] and not breaks and min(each_way) >= 1
                               and not bad, **done, handshakes=each_way, breaks=breaks[:3],
                               bad_lines=bad)
    for knocker in ('a', 'b'):
        sub = root / f'knock-mixed-{knocker}'
        sub.mkdir()
        envs = tuple(KNOCK_ENV if n == knocker else M0_ENV for n in ('a', 'b'))
        bins = tuple('' if n == knocker else PADDING_OLD_BIN for n in ('a', 'b'))
        a, b, pa, pb = pad1_pair(sub, envs, bins)
        done = pad1_exchange(a, b, f'knock-mixed-{knocker}')
        # pa stands in front of a's listener (b dials a), pb of b's.
        a_knocks = knocker == 'a'
        breaks = (knock_shapes(pa, not a_knocks, a_knocks)
                  + knock_shapes(pb, a_knocks, not a_knocks))
        bad = knock_logs(a, b)
        for n in (a, b):
            n.stop()
        phases[f'knock_mixed_{knocker}'] = dict(ok=done['exactly_once'] and not breaks
                                                and not bad, **done, breaks=breaks[:3],
                                                bad_lines=bad)
    return phases


def knock_logs(*nodes: Node) -> dict:
    """pad1_logs, and a noise pin mismatch (M0 stopped a dial) or a link
    knock refusal in a log."""
    logs = {n.name: n.log_path.read_text(errors='replace') for n in nodes}
    bad = {name: [l for l in log.splitlines()
                  if any(x in l for x in PAD1_BAD + ('noise pin mismatch', 'link knock'))]
           + MIXED_HANDSHAKE.findall(log) for name, log in logs.items()}
    return {k: v[:3] for k, v in bad.items() if v}


def s115_pad1_mixed_builds(root: Path) -> dict:
    """Phase 6b P6.34 (RAVEN_FAULT_PADDING=1; with carrier_matrix C86 part 1):
    PAD1 link padding between real nodes over LAN, every contact route
    through a recording Proxy (each connection's directions apart; it never
    changes a byte). (new) Two padding nodes (PAD_ENV): 3 messages each way,
    each exactly once; on every connection whose dial offered PAD1 every
    message after the dialer's 96-byte bind is a bucket plus the tag (a
    frame-less probe offers nothing and is not padded), and at least one
    such connection each way. (mixed) A padding node and one without, both
    ways round: with RAVEN_FAULT_PADDING_OLD_BIN=<dir with a pre-6b ash and
    raven-node> the other runs that build, else this build without the
    switch (what an older build sends, spec §7): every message once, nothing
    padded (the listener's bind stays 96 bytes). Neither log of any pair has
    a padding refusal, a dispatcher refusal or a failed handshake. (off,
    with the older build only) Two nodes of this build without the switch
    and two of the older build run the same exchange: each proxy's
    connections carry exactly the same message lengths (the gate shut is
    byte-identical in size on the wire). The PAD1 phases run with
    RAVEN_FAULT_PADDING=1, the RLK1 link knock's (knock_phases) with
    RAVEN_FAULT_KNOCK=1."""
    phases = {}
    if PADDING:
        sub = root / 'new'
        sub.mkdir()
        a, b, pa, pb = pad1_pair(sub, (PAD_ENV, PAD_ENV))
        done = pad1_exchange(a, b, 'new')
        conns = pad1_connections(pa, pb)
        breaks = pad1_breaks(conns, True)
        each_way = [sum(1 for d, _ in pad1_connections(p) if d[1] > PAD1_EMPTY_M3) for p in (pa, pb)]
        bad = pad1_logs(a, b)
        for n in (a, b):
            n.stop()
        phases['new'] = dict(ok=done['exactly_once'] and not breaks and min(each_way) >= 1
                             and not bad, **done, padded_dials=each_way, breaks=breaks[:3],
                             bad_lines=bad)
        for padder in ('a', 'b'):
            sub = root / f'mixed-{padder}-pads'
            sub.mkdir()
            envs = tuple(PAD_ENV if n == padder else ENV_NO_HINTS for n in ('a', 'b'))
            bins = tuple('' if n == padder else PADDING_OLD_BIN for n in ('a', 'b'))
            a, b, pa, pb = pad1_pair(sub, envs, bins)
            done = pad1_exchange(a, b, f'mixed-{padder}')
            breaks = pad1_breaks(pad1_connections(pa, pb), False)
            bad = pad1_logs(a, b)
            for n in (a, b):
                n.stop()
            phases[f'{padder}_pads'] = dict(ok=done['exactly_once'] and not breaks and not bad,
                                            **done, breaks=breaks[:3], bad_lines=bad)
        if PADDING_OLD_BIN:
            seen = {}
            for name, bin_dir in (('this', ''), ('old', PADDING_OLD_BIN)):
                sub = root / f'off-{name}'
                sub.mkdir()
                a, b, pa, pb = pad1_pair(sub, (ENV_NO_HINTS, ENV_NO_HINTS), (bin_dir, bin_dir))
                done = pad1_exchange(a, b, 'off')
                for n in (a, b):
                    n.stop()
                seen[name] = dict(once=done['exactly_once'],
                                  lengths=[sorted(map(str, p.messages())) for p in (pa, pb)])
            same = seen['this']['lengths'] == seen['old']['lengths']
            phases['off'] = dict(ok=same and seen['this']['once'] and seen['old']['once'],
                                 same_lengths=same,
                                 this=seen['this']['lengths'], old=seen['old']['lengths'])
    if KNOCK:
        phases.update(knock_phases(root))
    return dict(ok=all(p['ok'] for p in phases.values()), old_build=PADDING_OLD_BIN != '',
                **phases)


# ── Auto-reach (docs/design/2026-10-auto-reach.md) ─────────────────────────
#
# RAVEN_FAULT_AUTOREACH=1 selects s146-s148. Their nodes run with the debug
# switches RAVEN_LAB_STUN_DISCOVERY=1 (and for s148 RAVEN_LAB_NAT_CLASS=1 and
# RAVEN_LAB_SERVERLESS_PUNCH=1) and RAVEN_LAB_TEST_A=1, and ask only the fake
# STUN servers below (RAVEN_LAB_STUN_SERVERS, two sockets on 127.0.0.1): no
# scenario ever reaches a public STUN server.
AUTOREACH = os.environ.get('RAVEN_FAULT_AUTOREACH') == '1'
AUTOREACH_ENV = without_beacon(dict(
    P2P_ENV, RAVEN_LAB_ROUTE_HINTS='1', RAVEN_LAB_P2P_LOCAL_CANDIDATES='1',
    RAVEN_LAB_STUN_DISCOVERY='1', RAVEN_LAB_STUN_REFRESH_S='5'))


class FakeStun:
    """Two STUN servers (RFC 8489 Binding only) on 127.0.0.1, on a thread of
    their own. Each answers a Binding request with XOR-MAPPED-ADDRESS and
    FINGERPRINT: the public endpoint `mapped(port)` gives for the request's
    source port (by default the same address and port: a NAT that keeps
    ports, with that port forwarded, which on loopback is the node's own
    listener). `asked[port]` counts requests per source port."""

    MAGIC = 0x2112A442

    def __init__(self, mapped=None) -> None:
        self.mapped = mapped or (lambda port: ('127.0.0.1', port))
        self.socks = []
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(('127.0.0.1', 0))
            self.socks.append(s)
        self.servers = ','.join(f'127.0.0.1:{s.getsockname()[1]}' for s in self.socks)
        self.asked: dict = {}
        self.lock = threading.Lock()
        for s in self.socks:
            threading.Thread(target=self._serve, args=(s,), daemon=True).start()

    def answer(self, req: bytes, src_port: int) -> bytes | None:
        if len(req) < 20 or struct.unpack('!HHI', req[:8]) != (0x0001, len(req) - 20, self.MAGIC):
            return None
        ip, port = self.mapped(src_port)
        raw_ip = struct.unpack('!I', socket.inet_aton(ip))[0]
        xma = struct.pack('!HHBBHI', 0x0020, 8, 0, 1, port ^ (self.MAGIC >> 16),
                          raw_ip ^ self.MAGIC)
        body_len = len(xma) + 8
        head = struct.pack('!HHI', 0x0101, body_len, self.MAGIC) + req[8:20]
        msg = head + xma
        fp = (zlib.crc32(msg) ^ 0x5354554E) & 0xFFFFFFFF
        return msg + struct.pack('!HHI', 0x8028, 4, fp)

    def _serve(self, s: socket.socket) -> None:
        while True:
            try:
                req, src = s.recvfrom(1500)
            except OSError:
                return
            with self.lock:
                self.asked[src[1]] = self.asked.get(src[1], 0) + 1
            out = self.answer(req, src[1])
            if out:
                try:
                    s.sendto(out, src)
                except OSError:
                    return

    def stop(self) -> None:
        for s in self.socks:
            s.close()


class NatBox:
    """Endpoint-independent NATs with address-and-port-dependent filtering,
    one per node, simulated on 127.0.0.1 (one thread): node `name` sits
    behind the public UDP port `public[name]`, its QUIC listener on
    `inside[name]`. A datagram a node sends to another node's public port
    is that node's outbound packet through its own public port (its NAT now
    expects answers from that destination for FILTER_S seconds); it reaches
    the other node (sent from the sender's public port) only when the other
    node's NAT expects the sender's public port (it sent there recently).
    Anything else is dropped. Nodes must dial each other's public ports:
    their QUIC listeners are reachable directly on loopback, so a scenario
    names only the public ones (fake STUN) and keeps TCP out (a NAT that
    shifts ports: no forward is guessed). Counts: `passed`, `dropped`."""

    FILTER_S = 30.0

    def __init__(self, inside: dict) -> None:
        self.inside = dict(inside)
        self.socks: dict = {}
        for name in inside:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(('127.0.0.1', 0))
            self.socks[name] = s
        self.public = {n: s.getsockname()[1] for n, s in self.socks.items()}
        self.by_inside = {port: n for n, port in self.inside.items()}
        self.by_public = {port: n for n, port in self.public.items()}
        # (node, remote public port) -> when the node last sent there.
        self.expects: dict = {}
        self.passed = 0
        self.dropped = 0
        self.lock = threading.Lock()
        threading.Thread(target=self._serve, daemon=True).start()

    def mapped(self, src_port: int) -> tuple:
        """The fake STUN's answer: a node's QUIC port maps to its public
        port; any other port (a refresh probe's) one port up (shifted)."""
        name = self.by_inside.get(src_port)
        return ('127.0.0.1', self.public[name] if name else src_port + 1)

    def _serve(self) -> None:
        while True:
            try:
                ready, _, _ = select.select(list(self.socks.values()), [], [], 0.5)
            except (OSError, ValueError):
                return  # stopped: the sockets are closed
            if not self.socks:
                return
            for s in ready:
                try:
                    data, src = s.recvfrom(65535)
                except OSError:
                    return
                to = self.by_public.get(s.getsockname()[1])
                sender = self.by_inside.get(src[1])
                if to is None or sender is None or to == sender:
                    with self.lock:
                        self.dropped += 1
                    continue
                now = time.monotonic()
                with self.lock:
                    self.expects[(sender, self.public[to])] = now
                    seen = self.expects.get((to, self.public[sender]))
                    ok = seen is not None and now - seen < self.FILTER_S
                    if ok:
                        self.passed += 1
                    else:
                        self.dropped += 1
                if ok:
                    try:
                        self.socks[sender].sendto(data, ('127.0.0.1', self.inside[to]))
                    except OSError:
                        pass

    def counts(self) -> dict:
        with self.lock:
            return dict(passed=self.passed, dropped=self.dropped)

    def stop(self) -> None:
        socks, self.socks = self.socks, {}
        for s in socks.values():
            s.close()


def reach_nodes(root: Path, specs: dict) -> tuple:
    """Nodes `specs` names (name -> (env, p2p listen port)), all started
    with a p2p listener on 127.0.0.1 and an Internet direct listener; everyone
    pins everyone from a running card (`p2p=`, no relay) and holds everyone's
    Internet direct address: the "together" link that carries route hints.
    Internet links carry only the global part of a snapshot (no same-LAN
    address, which the local-candidates switch would keep as a global one on
    loopback), so a contact learns a p2p address only from what STUN
    discovery found. No LAN route is set. (the nodes, every gate admitted
    every contact)."""
    nodes = {k: Node(k, root, env) for k, (env, _) in specs.items()}
    for n in nodes.values():
        n.init()
    for k, n in nodes.items():
        n.start(inet_port=free_tcp_port(), extra=('--p2p-listen', f'127.0.0.1:{specs[k][1]}'))
    cards = {k: n.card() for k, n in nodes.items()}
    fps = {k: n.fingerprint() for k, n in nodes.items()}
    for x in nodes.values():
        for k, y in nodes.items():
            if x is not y:
                x.add_card(cards[k], TAGS[k], fps[k])
                r = x.ash('contact', 'set-addr', f'@{TAGS[k]}', '--internet', y.inet)
                assert r.returncode == 0, r.stdout + r.stderr
    gate = f'raven-node p2p: peer gate reloaded (verified contacts {len(nodes) - 1},'
    ready = all(wait_log(n, gate, 30) is not None for n in nodes.values())
    return nodes, ready


def inet_send(node: Node, to: str, text: str) -> str:
    return status_word(node.send(to, text, carrier='internet')[1])


def learned_raw(node: Node, other: Node) -> dict:
    """`node`'s learned_routes.json row for `other`, as stored ({} without
    one)."""
    try:
        rows = learned_rows(node)
    except (OSError, ValueError):
        return {}
    return next((e for e in rows if isinstance(e, dict)
                 and e.get('pub_hex', '').lower() == other.pub.lower()), {})


def told_direct(node: Node, other: Node) -> list:
    """The global DIRECT addresses `node` keeps from `other`'s route hints."""
    return list(learned_raw(node, other).get('direct', []))


def s146_discovered_address_offered(root: Path) -> dict:
    """Auto-reach (RAVEN_FAULT_AUTOREACH=1, design §4): Bob's node asks the
    fake STUN servers, which answer like a router that keeps ports with his
    ports forwarded (on loopback: his own listeners), and finds his public
    address from the p2p port itself (anchored). His friend relay, turned on
    with no `--external`, is offered to his contacts within 30 s, naming
    that address with the relay's ports; Carol's (the same setup without the
    STUN switch: the field build) never is (`no public address to offer`).
    Alice, a member listening nowhere, learns over one Internet direct
    message Bob's offer and his discovered DIRECT addresses (QUIC and TCP,
    on his listen ports), none from Carol, and reserves on Bob's relay. No
    log names an address."""
    stun = FakeStun()
    ports = {k: free_tcp_udp_port() for k in 'abc'}
    relay_ports = {k: free_tcp_udp_port() for k in 'bc'}
    base = dict(AUTOREACH_ENV, RAVEN_LAB_STUN_SERVERS=stun.servers,
                RAVEN_LAB_FRIEND_RELAY='1')
    member = dict(base, RAVEN_LAB_P2P_RELAY_ONLY='1')
    without = {k: v for k, v in base.items() if k != 'RAVEN_LAB_STUN_DISCOVERY'}
    specs = {
        'a': (member, ports['a']),
        'b': (dict(base, RAVEN_LAB_FRIEND_RELAY_LISTEN=f'127.0.0.1:{relay_ports["b"]}'),
              ports['b']),
        'c': (dict(without, RAVEN_LAB_FRIEND_RELAY_LISTEN=f'127.0.0.1:{relay_ports["c"]}'),
              ports['c']),
    }
    try:
        nodes, ready = reach_nodes(root, specs)
        a, b, c = nodes['a'], nodes['b'], nodes['c']
        t0 = time.time()
        found = wait_until(lambda: b.status_json().get('public_addr') == 'found', 30)
        facts_b = b.status_json()
        b.relay_offer(True)
        c.relay_offer(True)
        offered = wait_until(lambda: offered_to(b) >= 2, 30)
        offered_s = took(None if offered is None else time.time() - t0)
        c_offered = offered_to(c)
        c_status = c.ash('relay', 'status').stdout
        asks = [inet_send(a, x, f's146-a-to-{x}') for x in ('bob', 'carol')]
        learned = wait_until(lambda: offers_from(a, b) == 1, 30)
        direct_b = told_direct(a, b)
        direct_c = told_direct(a, c)
        peer_b = p2p_peer(b.card())
        want = {f'/ip4/127.0.0.1/udp/{ports["b"]}/quic-v1/p2p/{peer_b}',
                f'/ip4/127.0.0.1/tcp/{ports["b"]}/p2p/{peer_b}'}
        offer = next((o for e in learned_rows(a) if isinstance(e, dict)
                      and e.get('pub_hex', '').lower() == b.pub.lower()
                      for o in e.get('offers') or []), {})
        reserved = wait_until(lambda: offered_slots(a, 1), 45)
        logs = ''.join(n.log_path.read_text(errors='replace') for n in nodes.values())
        stun_lines = [l for l in logs.splitlines() if 'raven-node autoreach:' in l]
        return dict(
            ok=ready and found is not None
            and facts_b.get('stun_class') in ('stable_kept', 'no_nat')
            and facts_b.get('anchored') == 'yes' and offered is not None and c_offered == 0
            and asks == ['DELIVERED', 'DELIVERED'] and learned is not None
            and want <= set(direct_b) and direct_c == []
            and f'/ip4/127.0.0.1/tcp/{relay_ports["b"]}' in offer.get('addrs', [])
            and offers_from(a, c) == 0 and reserved is not None
            and bool(stun_lines) and not any('127.0.0.1' in l for l in stun_lines)
            and stun.asked.get(ports['b'], 0) > 0 and stun.asked.get(ports['c'], 0) == 0,
            ready=ready, found_s=took(found), auto_reach_b={
                k: facts_b.get(k) for k in ('stun', 'public_addr', 'stun_class', 'anchored',
                                             'stun_answered')},
            offered_s=offered_s, carol_offered_to=c_offered,
            carol_says_no_address='no public address' in c_status or 'not offered' in c_status,
            asks=asks, learned_offer_s=took(learned), bob_direct=direct_b, carol_direct=direct_c,
            offer_addrs=offer.get('addrs'), reserved_s=took(reserved),
            stun_asked_from_p2p_port=stun.asked.get(ports['b'], 0), stun_lines=stun_lines[:4])
    finally:
        stun.stop()


def s147_reached_after_moving(root: Path) -> dict:
    """Auto-reach (RAVEN_FAULT_AUTOREACH=1, design §4.1): Alice, Bob and
    Carol talk over Internet direct ("together"; route hints ride those
    links). Bob's node found his public address with STUN (fake servers: a
    router that keeps ports, his forwarded); Carol's build has no STUN
    switch. Alice then "moves": her book keeps no route but their PeerIds
    (`contact set-addr --clear`), no relay anywhere. Her p2p message to Bob is
    delivered to the address his route hints told her (`direct`), and Bob's
    node counts the port as reached from outside (reach class public); her
    message with the automatic carrier is delivered too (Internet direct, to
    the INET_DIRECT address his hints named); her p2p message to Carol, whose
    hints named no address, is not delivered."""
    stun = FakeStun()
    ports = {k: free_tcp_udp_port() for k in 'abc'}
    base = dict(AUTOREACH_ENV, RAVEN_LAB_STUN_SERVERS=stun.servers)
    without = {k: v for k, v in base.items() if k != 'RAVEN_LAB_STUN_DISCOVERY'}
    specs = {'a': (base, ports['a']), 'b': (base, ports['b']), 'c': (without, ports['c'])}
    try:
        nodes, ready = reach_nodes(root, specs)
        a, b, c = nodes['a'], nodes['b'], nodes['c']
        found = wait_until(lambda: b.status_json().get('public_addr') == 'found', 30)
        asks = [inet_send(a, 'bob', 's147-together-a2b'), inet_send(b, 'alice', 's147-together-b2a'),
                inet_send(a, 'carol', 's147-together-a2c'), inet_send(c, 'alice', 's147-together-c2a')]
        quic = f'/ip4/127.0.0.1/udp/{ports["b"]}/quic-v1'
        learned = wait_until(lambda: any(d.startswith(quic) for d in told_direct(a, b))
                             and learned_raw(a, b).get('inet'), 30)
        inet_b = learned_raw(a, b).get('inet')
        direct_c = told_direct(a, c)
        clear_book_routes(a, 'bob')
        clear_book_routes(a, 'carol')
        t0 = time.time()
        a2b = send_path(a, 'bob', 's147-a2b-p2p', 'p2p')
        moved_s = took(time.time() - t0)
        auto = a.send('bob', 's147-a2b-auto', timeout=60)
        a2c = send_path(a, 'carol', 's147-a2c-p2p', 'p2p')
        late = wait_inbox(c, 's147-a2c-p2p', 15)
        reached = wait_until(lambda: b.status_json().get('reached_outside', '-') != '-', 15)
        facts_b = b.status_json()
        reach_b = re.search(r'reach_class: (\w+)', b.ash('doctor').stdout)
        return dict(
            ok=ready and found is not None and asks == ['DELIVERED'] * 4
            and learned is not None and direct_c == [] and not learned_raw(a, c).get('inet')
            and a2b[1:] == ('DELIVERED', 'direct') and count(b.inbox(), 's147-a2b-p2p') == 1
            and status_word(auto[1]) == 'DELIVERED' and count(b.inbox(), 's147-a2b-auto') == 1
            and a2c[1] != 'DELIVERED' and late is None
            and reached is not None and reach_b is not None and reach_b.group(1) == 'public',
            ready=ready, found_s=took(found), together=asks, learned_s=took(learned),
            alice_learned_bob_inet=inet_b, carol_direct=direct_c, a2b_p2p=a2b, a2b_p2p_s=moved_s,
            a2b_auto=status_word(auto[1]), a2c_p2p=a2c, a2c_delivered_s=took(late),
            bob_reached=facts_b.get('reached_outside'),
            bob_reach_class=reach_b.group(1) if reach_b else None)
    finally:
        stun.stop()


def s148_serverless_punch(root: Path) -> dict:
    """Auto-reach (RAVEN_FAULT_AUTOREACH=1, design §5): Alice, Bob and Carol
    each sit behind a simulated endpoint-independent NAT that shifts ports
    and drops what it did not ask for (NatBox; the fake STUN servers answer
    each node's QUIC port with its NAT's public port: stable_shifted, so no
    TCP, relay or Internet direct forward is guessed). They talk over
    Internet direct first (route hints: each learns the others' public QUIC
    endpoints and NAT classes), then keep no route but the PeerIds: no LAN,
    no relay anywhere. Alice and Bob run the serverless punch (3 s slots);
    Carol does not. Alice's message to Bob (Bob has nothing for her: he
    punches at the idle level, every 32 slots) is delivered once within
    120 s over the punched connection; then Bob's to Alice. Alice's to Carol
    stays undelivered for 60 s: Carol never dials, and her NAT drops every
    packet Alice sends."""
    ports = {k: free_tcp_udp_port() for k in 'abc'}
    nat = NatBox(ports)
    stun = FakeStun(nat.mapped)
    base = dict(AUTOREACH_ENV, RAVEN_LAB_STUN_SERVERS=stun.servers, RAVEN_LAB_NAT_CLASS='1',
                RAVEN_LAB_SERVERLESS_PUNCH='1', RAVEN_LAB_PUNCH_SLOT_S='3')
    without = {k: v for k, v in base.items() if k != 'RAVEN_LAB_SERVERLESS_PUNCH'}
    specs = {'a': (base, ports['a']), 'b': (base, ports['b']), 'c': (without, ports['c'])}
    try:
        nodes, ready = reach_nodes(root, specs)
        a, b, c = nodes['a'], nodes['b'], nodes['c']
        found = wait_until(lambda: all(n.status_json().get('stun_class') == 'stable_shifted'
                                       for n in nodes.values()), 30)
        asks = [inet_send(x, TAGS[y.name], f's148-together-{x.name}2{y.name}')
                for x in nodes.values() for y in nodes.values() if x is not y]
        pub = {k: f'/ip4/127.0.0.1/udp/{nat.public[k]}/quic-v1' for k in 'abc'}
        learned = wait_until(lambda: any(d.startswith(pub['b']) for d in told_direct(a, b))
                             and any(d.startswith(pub['a']) for d in told_direct(b, a))
                             and any(d.startswith(pub['c']) for d in told_direct(a, c)), 30)
        told = [d for n in nodes.values() for o in nodes.values() if n is not o
                for d in told_direct(n, o)]
        other_told = [d for d in told if '/tcp/' in d
                      or not any(d.startswith(p) for p in pub.values())]
        inet_told = [learned_raw(n, o).get('inet') for n in nodes.values()
                     for o in nodes.values() if n is not o if learned_raw(n, o).get('inet')]
        classes = learned_raw(a, b).get('nat_class')
        for x in nodes.values():
            for y in nodes.values():
                if x is not y:
                    clear_book_routes(x, TAGS[y.name])
        before = nat.counts()
        t0 = time.time()
        a2b = a.send('bob', 's148-a2b', timeout=60)
        a2c = a.send('carol', 's148-a2c', timeout=60)
        got = wait_inbox(b, 's148-a2b', 120)
        a2b_s = took(None if got is None else time.time() - t0)
        b2a = send_path(b, 'alice', 's148-b2a')
        c_late = wait_inbox(c, 's148-a2c', max(1.0, 60 - (time.time() - t0)))
        after = nat.counts()
        facts_a = a.status_json()
        facts_b = b.status_json()
        relays = [n.status_json().get('relay_1') for n in nodes.values()]
        return dict(
            ok=ready and found is not None and len(asks) == 6 and set(asks) == {'DELIVERED'}
            and learned is not None and other_told == [] and inet_told == []
            and status_word(a2b[1]) in ('QUEUED', 'DELIVERED') and got is not None
            and count(b.inbox(), 's148-a2b') == 1 and b2a[1] == 'DELIVERED'
            and count(a.inbox(), 's148-b2a') == 1 and c_late is None
            and after['passed'] > before['passed'] and relays == [None, None, None]
            and int(facts_a.get('punch_connected', '0')) + int(facts_b.get('punch_connected', '0'))
            >= 1,
            ready=ready, classes_s=took(found), together=asks, learned_s=took(learned),
            alice_learned_bob_nat_class=classes, other_told=other_told, inet_told=inet_told,
            a2b_first=status_word(a2b[1]), a2b_delivered_s=a2b_s, b2a=b2a,
            a2c=status_word(a2c[1]), a2c_delivered_s=took(c_late),
            nat_before=before, nat_after=after,
            punch_a={k: facts_a.get(k) for k in ('punch_targets', 'punch_tried',
                                                  'punch_connected', 'punch_skipped_class')},
            punch_b={k: facts_b.get(k) for k in ('punch_targets', 'punch_tried',
                                                  'punch_connected')})
    finally:
        stun.stop()
        nat.stop()


SCENARIOS = [
    s01_happy, s02_receiver_offline_then_back, s03_two_messages_while_offline,
    s04_receiver_address_changes] + (
    [s04b_moved_contact_announces, s04c_mixed_builds, s04p_pinned,
     s89_weekly_meeting_keeps_the_port] if HINTS else []) + [
    s05_receiver_loses_state, s06_flaky_link_resets,
    s07_slow_link, s08_blackhole_then_heal, s09_bidirectional_concurrent,
    s10_receiver_crash_during_burst, s11_receiver_ip_changes_same_port,
    s12_offline_queue_drain_timing, s13_drain_trace, s14_twenty_queued_in_order,
    s37_status_names_the_last_path, s90_stale_address_inbound_learns,
    s91_access_point_waits, s93_first_message_unreachable, s94_session_expired_while_apart,
    s95_status_on_loopback_and_vanished_bind, s121_lock_v1_with_queued_messages,
    s117_erase_one_profile, s122_clear_sticks_across_session_expiry,
] + (RESET_SCENARIOS if RESET_ON else []) + (
    [s120_seal_migrates_an_old_profile, s124_downgrade_and_back]
    if PRIVACY_OLD_BIN or PRIVACY else []) + (
    [s123_addresses_forgotten_after_30_days, s125_custody_release_deletes]
    if PRIVACY else []) + (
    [s15_route_memory] if os.environ.get('RAVEN_FAULT_ROUTE_MEMORY') == '1' else []) + (
    [s30_via_a_friend, s96_custodian_walks, s125_custody_release_deletes]
    if os.environ.get('RAVEN_FAULT_CUSTODY') == '1' else []) + (
    [s96w_custodian_moves_keeping_its_listener, s126_two_addressed_mail_friends_stay_quiet,
     s129_idle_friends_settle]
    if os.environ.get('RAVEN_FAULT_CUSTODY') == '1' and HINTS else []) + (
    [s97_three_people_two_rooms]
    if os.environ.get('RAVEN_FAULT_CUSTODY') == '1' and (HINTS or BEACON) else []) + (
    [s127_friend_back_after_minutes] if BEACON and HINTS else []) + (
    [s88_hotspot_isolation_ap_custodian]
    if os.environ.get('RAVEN_FAULT_CUSTODY') == '1' and BEACON else []) + (
    [s30p_via_a_friend_over_p2p, s30w_wan_custody_needs_both_switches]
    if os.environ.get('RAVEN_FAULT_CUSTODY') == '1'
    and os.environ.get('RAVEN_FAULT_P2P') == '1' and HINTS else []) + (
    [s30r_relay_and_custodian_on_one_node]
    if os.environ.get('RAVEN_FAULT_CUSTODY') == '1' and os.environ.get('RAVEN_FAULT_P2P') == '1'
    and os.environ.get('RAVEN_FAULT_FRIEND') == '1' and HINTS else []) + (
    [s31_app_channel] if os.environ.get('RAVEN_FAULT_APP') == '1' else []) + (
    [s32_rdap_over_raven, s32b_rdap_over_internet, s32c_rdap_over_relay,
     s32d_rdap_answer_by_reversal, s32e_rdap_probe_past_two_routes]
    if RDAP_TREE else []) + (
    [s33_network_change, s34_network_switch_queued, s34c_switch_without_netwatch]
    if os.environ.get('RAVEN_FAULT_NETWATCH') == '1' else []) + (
    [s35_p2p_stranger_is_refused, s36_p2p_paths, s38_relay_outage_then_heal,
     s38b_relay_restart_same_key, s45_relay_443_fallback, s46_relay_graceful_restart,
     s47_circle_allow_is_live]
    if os.environ.get('RAVEN_FAULT_P2P') == '1' else []) + (
    [s39_p2p_relay_moves, s40_stale_direct_hint]
    if os.environ.get('RAVEN_FAULT_P2P') == '1' and HINTS else []) + (
    [s41_friend_relay_offer_and_select, s42_friend_relay_sleeps, s43_relay_moves,
     s44_consent_off_withdraws]
    if os.environ.get('RAVEN_FAULT_FRIEND') == '1' else []) + (
    [s48_relay_sleeps_then_wakes, s48c_contact_sleeps_relay_awake,
     s49_nobody_reachable_then_a_relay]
    if os.environ.get('RAVEN_FAULT_P2P') == '1' else []) + (
    [s48o_no_route_never_advises_a_relay]
    if os.environ.get('RAVEN_FAULT_P2P') == '1'
    and os.environ.get('RAVEN_FAULT_NETWATCH') == '1' else []) + (
    [s50_proxy_outage_and_return, s51_proxy_wants_negotiate] if WSS else []) + (
    [s52_router_restart_remaps] if PORTMAP else []) + (
    [s53_rotation_boundary_with_queued_messages]
    if os.environ.get('RAVEN_FAULT_P2P') == '1' and ROTATION else []) + (
    [s90p_pinned_stale_address_answered_by_another_node, s91b_sibling_link_wakes_the_queue,
     s92_name_route_while_away, s93b_session_ended_says_meet_first, s99_clock_skew,
     s123_addresses_forgotten_after_30_days]
    if OFFLINE else []) + (
    [s98_cable_link_local]
    if OFFLINE and os.environ.get('RAVEN_FAULT_NETWATCH') == '1' else []) + (
    [s80_both_move_to_a_new_network, s81_quiet_receiver_dhcp_move,
     s82_beacon_capture_has_no_marker, s83_lan_off_on,
     s84_unverified_contacts_find_each_other, s86_meeting_mode_closes_on_time,
     s87_beacon_clock_skew] if BEACON else []) + (
    [s85_session_renewed_before_it_ends, s85b_fallback_when_the_contact_does_not_renew]
    if RENEW else []) + (
    [s60_offline_three_days_sender_online, s60b_offline_past_deadline,
     s60c_clock_back_while_parked] if HORIZON else []) + (
    [s61_offline_three_days_via_friend_letter, s61b_letter_then_direct_return,
     s62_letter_base_ops_custodian, s75_letter_mule_two_rooms, s76_letter_week,
     s76b_letter_week_ran_out, s76c_twenty_in_one_day] if LETTER else []) + (
    [s68_two_friends_chain, s69_mule_hands_on_later, s70_new_session_tags_late,
     s71_old_or_closed_custodian, s97b_two_friends_ran_out] if HANDOFF else []) + (
    [s63_nearby_happy_path, s64_nearby_link_drop_mid_transfer, s65_nearby_radio_off_on,
     s66_nearby_stale_session_repaired, s72_nearby_background_encounter,
     s73_nearby_clock_skew, s74_three_contacts_in_range] if NEARBY else []) + (
    [s67_nearby_mule_via_a_friend, s67b_nearby_deposit_on_encounter,
     s128_nearby_only_carry_chain]
    if NEARBY and os.environ.get('RAVEN_FAULT_CUSTODY') == '1' else []) + (
    [s100_learning_flaky_lan, s101_learning_per_network, s102_learning_reset_and_off,
     s103_probes_revive_a_healed_lan, s104_learning_ages_out,
     s106_learning_never_probes_strangers] if LEARNING else []) + (
    [s105_carry_choice_by_encounters]
    if LEARNING and os.environ.get('RAVEN_FAULT_CUSTODY') == '1' else []) + (
    [s115_pad1_mixed_builds] if PADDING or KNOCK else []) + (
    [s04r_random_port_learned] if RANDOM_PORT else []) + (
    [s116_lock_v2_with_queued_messages] if LOCK_V2 else []) + (
    [s146_discovered_address_offered, s147_reached_after_moving, s148_serverless_punch]
    if AUTOREACH else []) + (
    [s118_mesh_advisory_a_b_c, s119_mesh_release_resumed_from_a_second_friend]
    if UPDATES else [])
# Scenarios that move a node's clock (LabClock) a day or more, so a session
# may lapse and be set up again: with RAVEN_FAULT_RENEW=1 their renewals are
# recorded, not refused. s85 and s85b renew on purpose (each checks its own).
RENEW_MAY_RENEW = {'s85_session_renewed_before_it_ends',
                   's85b_fallback_when_the_contact_does_not_renew',
                   's89_weekly_meeting_keeps_the_port', 's93b_session_ended_says_meet_first',
                   's97_three_people_two_rooms', 's122_clear_sticks_across_session_expiry',
                   's123_addresses_forgotten_after_30_days', 's94_session_expired_while_apart',
                   's60_offline_three_days_sender_online', 's60b_offline_past_deadline',
                   's60c_clock_back_while_parked',
                   's61_offline_three_days_via_friend_letter',
                   's61b_letter_then_direct_return', 's75_letter_mule_two_rooms',
                   's76_letter_week', 's76b_letter_week_ran_out',
                   's76c_twenty_in_one_day', 's97b_two_friends_ran_out',
                   's66_nearby_stale_session_repaired', 's104_learning_ages_out',
                   's105_carry_choice_by_encounters'}
# A scenario two opt-in lists name (RAVEN_FAULT_PRIVACY=1 with
# RAVEN_FAULT_OFFLINE=1 or RAVEN_FAULT_CUSTODY=1) runs once.
SCENARIOS = list(dict.fromkeys(SCENARIOS))


def offline_default_port(port: int) -> None:
    """RAVEN_FAULT_OFFLINE: ENV and every env this module made from it (they
    carry RAVEN_LAB_OFFLINE) name `port` as the default LAN port, so a node
    that guesses it never dials 7420. A scenario's own envs, made from these
    while it runs, carry the same port."""
    for env in list(globals().values()):
        if isinstance(env, dict) and env.get('RAVEN_LAB_OFFLINE') == '1':
            env['RAVEN_LAB_LAN_DEFAULT_PORT'] = str(port)


def main() -> int:
    why = profile_dir_refusal(OUT / 'probe', OUT)
    if why:
        print(f'lan_fault_matrix: refusing {OUT} as the run root: {why}', file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    results = {}
    for fn in SCENARIOS:
        name = fn.__name__
        if ONLY and name not in ONLY and name.split('_')[0] not in ONLY:
            continue
        if OFFLINE:
            offline_default_port(free_tcp_port())
        root = OUT / name
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        if BEACON:
            beacon_bus(root)
        nodes_before = set()
        t0 = time.time()
        print(f'=== {name}', flush=True)
        try:
            res = fn(root)
        except Exception as exc:  # noqa: BLE001
            res = dict(ok=False, error=f'{type(exc).__name__}: {exc}',
                       trace=traceback.format_exc()[-1500:])
        finally:
            # RDAP processes first (their argv names no data dir), then the
            # nodes and relays, then the bus Sniffers.
            end_children()
            subprocess.run(['pkill', '-f', f'data-dir {root}/'], capture_output=True)
            stop_sniffers()
        if RENEW:
            res['renewed_lines'] = sum(
                p.read_text(errors='replace').count(RENEWED_LINE)
                for p in root.rglob('*.node.log'))
            if res['renewed_lines'] and name not in RENEW_MAY_RENEW:
                res.update(ok=False, renewal='a session renewed in a scenario whose '
                           'sessions never drop below 12 h')
        res['seconds'] = round(time.time() - t0, 1)
        results[name] = res
        print(json.dumps(res, indent=1, default=str)[:3000], flush=True)
    (OUT / 'results.json').write_text(json.dumps(results, indent=1, default=str))
    print('\nSUMMARY')
    for name, res in results.items():
        print(f"{'PASS' if res.get('ok') else 'FAIL'}  {name}  ({res['seconds']}s)")
    return 0 if all(r.get('ok') for r in results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
