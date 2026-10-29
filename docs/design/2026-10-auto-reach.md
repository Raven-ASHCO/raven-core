# Auto-reach: a node finds its own public address and friends punch to each other, serverless

| | |
|---|---|
| **Status** | Design for the lab build (branch `feature/auto-reach`). Built in stages behind two new gates, both `false`; every existing gate stays as it is. |
| **Gates** | `STUN_DISCOVERY_PRODUCTION_ENABLED = false` (debug `RAVEN_LAB_STUN_DISCOVERY=1`, on top of the p2p lab unlock `RAVEN_LAB_TEST_A=1`) and `SERVERLESS_PUNCH_PRODUCTION_ENABLED = false` (debug `RAVEN_LAB_SERVERLESS_PUNCH=1`, on top of STUN discovery and the NAT class gate). Both in `node/crates/raven-core/src/portmap_gate.rs`, const-asserted to need `P2P_PRODUCTION_ENABLED`. Release builds read neither switch. |
| **User switch** | `node_policy.stun` (`raven node stun on|off|status`): unset is on while the gate is live, `false` is off. Hide my IP for everyone (`raven node hide-ip on`) also stops every query. |
| **Owner decisions in force** | D1 stands (no project-run relay, mailbox or rendezvous server); D13 stands (no port prediction, no birthday punching, no public DHT); the only new outside contact allowed is a STUN Binding request to a public STUN server ("what is my public address", approved 2026-10-28); no `*_PRODUCTION_ENABLED` constant changes. |
| **Wire** | One new optional RRH1 entry, `0x24 INET_DIRECT` (route hints spec §13.3), sent only while STUN discovery is live. DIRECT (0x03) may now also carry a discovered, not yet confirmed address. No card field changes: a card never names a discovered address (owner rule 2026-10-28, §4.3). No other frame or envelope changes. |
| **Date** | 2026-10-28 |

## 1. Why

Field test of 2026-10-28 (build 183cbe68, lab set S5A: `TEST_A`, `HORIZON`,
`PORT_MAP`, `V6_PINHOLE`, `NAT_CLASS`, `ROUTE_HINTS`, `FRIEND_RELAY`,
`CUSTODY_WAN`; consents on for UPnP, the IPv6 pinhole, the relay offer, node
custody and custody use). Two Macs and a Windows laptop.

- The home router answers none of UPnP, NAT-PMP and PCP. Its NAT is
  endpoint-independent and port-preserving (RX0: three STUN servers saw the
  same public address and port), with address-and-port-dependent filtering
  (part 2 of the research, §2.3). No IPv6.
- The owner forwarded TCP 17422, TCP+UDP 17423 and TCP+UDP 17427 to mac-b.
- mac-b never learned its public address. Its status said "relaying YES, but
  this computer has no public address to offer", reachability `unknown`, so
  its relay offer and its route hints carried no internet address.
- When mac-a moved to a phone hotspot, both of its sends were queued with
  "you and mac-b are both behind NAT": mac-a had never been told an address
  of mac-b that works from outside.

The cause: every source of a public address in Raven needs something the
field did not have. UPnP and NAT-PMP/PCP need a router that answers. AutoNAT
needs a reachable relay or friend that runs an AutoNAT server, which in turn
needs a public address. The relay's `--external` needs a human who types the
address. The owner wants zero setup: the user only sends messages.

## 2. What is built

Four parts, in stages (each its own commit):

1. **STUN self-discovery** (§3): raven-node asks a few public STUN servers what
   address and port they see, from the p2p UDP port itself and from a spare
   port, and derives the public IPv4 address, the NAT mapping class and port
   preservation. It refreshes on network changes and every 20 minutes.
2. **Use of the address** (§4): the friend relay offers it without
   `--external`; route hints carry the p2p and Internet direct addresses,
   only inside the encrypted, authenticated links between verified friends
   (never in a card, a log or status); an address is "unconfirmed" until a
   contact connects in through it from outside, then "confirmed".
3. **Serverless hole punching** (§5): two verified friends that know each
   other's mapped endpoints and whose NATs map endpoint-independently both
   dial each other's QUIC endpoint from their own p2p port at the same
   moments, on a schedule both compute from the clock and their two keys. No
   relay, no coordinator, no port prediction.
4. **Fallbacks unchanged** (§6): friend relay (now with the discovered
   address), friend custody over the internet, LAN, Bluetooth, and the outbox's
   "friend is back" kick.

## 3. STUN self-discovery

### 3.1 The query

- STUN Binding request over UDP, RFC 8489 (RFC 5389 compatible): a 20-byte
  header (type `0x0001`, length 0, magic cookie `0x2112A442`, a random 96-bit
  transaction ID), no attributes. Nothing else is ever sent to a STUN server:
  no USERNAME, SOFTWARE, PeerId, key or Raven marker.
- Retransmission per RFC 8489 §6.2.1 with RTO 500 ms: requests at 0, 0.5 and
  1.5 s, within the probe's budget (1.6 s at an endpoint start, 3 s for a
  refresh).
- An answer is used only when it comes from the address the request went to,
  is a Binding success response (`0x0101`) with the magic cookie and the
  transaction ID of a request in flight, its length is consistent, its
  FINGERPRINT (when present) is right, and it holds no comprehension-required
  attribute this client does not know (RFC 8489 §6.3.3; the RFC 3489 and RFC
  5780 attributes servers still send are known). XOR-MAPPED-ADDRESS is read
  first, MAPPED-ADDRESS (older servers) otherwise. An unspecified, multicast,
  broadcast or port-0 mapped address is no answer.
- The codec is pure (`raven-core/src/stun.rs`) and tested with the RFC 5769
  sample messages.

### 3.2 Servers

A built-in list of two servers from two independent operators (owner
decision AR-1, 2026-10-28), IPv4 over UDP:

| Server | Operator |
|---|---|
| `stun.cloudflare.com:3478` | Cloudflare |
| `stun.l.google.com:19302` | Google |

- Names are resolved with the system resolver (no libp2p DNS transport, as for
  route names). Every probe asks both at once. The public address and
  endpoint count only when both answer and agree (two independent answers):
  one unauthenticated answer could be a spoofed UDP reply, and the address
  is advertised to friends (security review 2026-10-29 #3). When one does
  not answer (or its name does not resolve), nothing is advertised from
  that probe; the NAT class needs both too, so a punch waits for a probe
  both answer.
- Two answers count as independent only when they come from different IPv4
  addresses. A harness names its own servers with
  `RAVEN_LAB_STUN_SERVERS=IP:PORT[,IP:PORT]...` (debug builds with the lab
  unlock only, IP literals, at most 8); then distinct ports count as distinct
  servers, so a fake server on loopback can stand in. Automated tests never
  reach the public list.

### 3.3 From which local port

The mapping a friend can use is the one of the socket the friend's packets
reach: the p2p host's QUIC socket. libp2p-quic 0.14 owns that socket and
exposes no way to send a STUN request on it, and it does not set
`SO_REUSEPORT`, so a second socket cannot share the port while it is open.

- **Anchor probe.** At every endpoint generation (the host's start and every
  re-home: a network change, a wake from sleep, a lost path), before libp2p
  binds its listeners, raven-node binds a plain UDP socket to each IPv4 QUIC
  listen address (for example `0.0.0.0:17423`), sends the probe from it, and
  closes it. The listener then binds the same address and port, so its
  traffic leaves through the same NAT mapping (endpoint-independent mapping
  keys on the inside address and port). This gives the exact public
  endpoint of the p2p port. If the port cannot be bound in time (the previous
  generation still holds it), the anchor is skipped.
- **Refresh probe.** Every 20 minutes (`RAVEN_LAB_STUN_REFRESH_S` in a
  harness), from a fresh ephemeral port: it refreshes the public IP and the
  NAT class. When the public IP differs from the anchor's, every NAT mapping
  of this computer is gone anyway, so the host re-homes (at most once per 10
  minutes; a new reason `Rehome::PublicAddress`), which runs a new anchor.
  Failed refreshes back off from 30 s to 20 min.
- **Without an anchor** (none answered in time), the p2p QUIC endpoint is
  inferred only when the refresh probe found the NAT port-preserving: the
  public IP with the listen port. Otherwise no p2p address is derived; the
  public IP is still known for the relay and Internet direct ports.
- **Relay, TCP and Internet direct ports.** They are TCP (Internet direct,
  the p2p TCP listener) or TCP and QUIC on a port that only a forward or a
  router mapping can open; a UDP STUN query cannot tell whether a TCP forward
  exists. Their address is the public IP with the port they listen on,
  guessed only where the NAT keeps ports (`no_nat` or `stable_kept`: the
  field's home router): a NAT that shifts its outbound ports is rarely set up
  with a same-port forward, and the guess would cost every friend a dial
  that never answers. It is offered as unconfirmed until a contact comes in
  through it (§4.4).

### 3.4 Classification

From one socket's answers (§3.2: at least two independent servers):

- `no_nat`: the mapped IP is an address of this computer and the port is the
  local port;
- endpoint-independent: every server saw the same address and port. Then
  `stable_kept` when that port is the local port (port preservation), else
  `stable_shifted`;
- `varies`: the servers saw different addresses or ports (endpoint-dependent
  mapping: a hole punch cannot guess the port, and D13 forbids predicting it);
- `unknown`: fewer than two independent answers.

These are the words and codes of the Phase 4 NAT classifier
(`raven-swarm/src/natclass.rs`, RRH1 NAT_CLASS §13.1). The anchor's class
fills the QUIC IPv4 class whenever the classifier, which learns only from
relays and contacts on two networks at once, still says `unknown`; what the
classifier learns from real connections wins once it knows. So route hints'
NAT_CLASS entry, `raven status` and the hole-punch policy all see the STUN
class with no second relay.

### 3.5 What is kept and what is logged

- In memory only: the public IPv4 address, the anchor endpoints, the class,
  when each was learned, and which of the node's ports a contact has reached
  from outside. Nothing is written to disk, so a stolen profile holds no
  address history. A discovered address is used for 45 minutes after the
  last probe that saw it (a refresh is due every 20), and dropped at once on
  a network change.
- Logs say the class and whether the address changed, never an address or a
  port: `raven-node autoreach: public address found (NAT endpoint-independent,
  port kept; 2 of 2 servers)`, `... public address changed ...`, `... no STUN
  server answered (UDP blocked or offline); retrying`.

### 3.6 Privacy

- A STUN server learns this computer's public IP and port and the moment it
  asked, as any web site would. It learns nothing about Raven: the request is
  a bare 20-byte Binding request with no attributes, the kind WebRTC and VoIP
  clients send all day.
- Both operators on every probe, about 75 probes a day per computer (every
  20 minutes, plus one per network change).
- `raven node stun off` stops every query (also those already scheduled);
  `raven node hide-ip on` does too, since an address that is never shared
  need not be found. With the gate closed nothing is sent at all.
- Status, doctor and the consent text say it in these words: "Raven asks
  two public STUN servers (Cloudflare and Google) which internet address
  they see for this computer. They see that address and when you ask;
  nothing else is sent. Turn it off with `raven node stun off`."

### 3.7 What leaves this computer unencrypted

Owner rule (2026-10-28): everything private and encrypted. With auto-reach
live, exactly these leave the computer in a form others can read:

- **The STUN query** (plaintext UDP, by protocol): a 20-byte Binding request
  (type, length 0, magic cookie, random transaction ID) to
  `stun.cloudflare.com:3478` and `stun.l.google.com:19302`, every 20 minutes
  and after a network change; the answer is the IP address and port the
  server saw. Cloudflare and Google see that this IP and port asked a STUN
  server at that moment, nothing about Raven, the user, friends or messages:
  WebRTC calls send the same request all day. A network on the path sees the
  same and the answer, which only repeats the addresses in the packets' own
  headers.
- **Why not STUN over TLS (port 5349).** The query exists to learn the UDP
  mapping of the p2p QUIC port (the anchor, §3.3); a TCP/TLS connection's
  mapping says nothing about it. And TLS would hide only the request (a
  constant) and the answer (the sender's own address, which the server and
  the path read from the packet headers anyway): nothing a reader does not
  already have. So the plain UDP query stays, and no TLS STUN client was
  added.
- **The two server names** are resolved with the system resolver: in plain
  DNS unless the operating system uses encrypted DNS. It shows that this
  computer looks up those names.
- **Punch packets** are QUIC (TLS 1.3) between the two friends' public
  endpoints. Like every p2p dial, the path can read the QUIC Initial
  packets: a libp2p QUIC handshake (ALPN `libp2p`) between two IP addresses,
  at the times of the pair's schedule. No key, PeerId (the certificates
  travel in encrypted handshake packets), name or message is readable.

Everything else this feature adds travels encrypted and authenticated: the
discovered addresses (DIRECT, INET_DIRECT), the NAT class and the relay
offer go only inside RRH1, inside the Noise links between verified friends.
No card, log line, status or doctor output names an address.

## 4. Using the address

### 4.1 Route hints

- **DIRECT (0x03)** carries, after the confirmed addresses (UPnP mapped,
  AutoNAT confirmed, or reached from outside), the discovered p2p addresses:
  `/ip4/<public>/udp/<anchor or inferred port>/quic-v1` and, where the NAT
  keeps ports (§3.3), `/ip4/<public>/tcp/<p2p TCP listen port>`. At most 4 global entries as
  before, QUIC first within each group. Their change moves the generation, so
  contacts are told at once (announce links, §7 of the spec).
- **NAT_CLASS (0x22)** carries the STUN class (§3.4) when the classifier has
  none.
- **INET_DIRECT (0x24, new)** carries the Internet direct listener's public
  address while it listens: `flags u8 || ASCII ip:port` (flag bit 0
  CONFIRMED). A receiver keeps it from a pinned sender only, global IPs only
  (loopback under the lab local-candidates switch), at most 2, in the
  snapshot's global part, and plans it as an Internet route after the
  contact's saved one. Spec: `protocol/RAVEN_ROUTE_HINTS_V1.md` §13.3.
- Hide my IP (for everyone or for this contact) removes all three, as it
  removes DIRECT today.

So friends learn a reachable friend's public address while they are together
(LAN links carry the global part too) and can use it after one of them moves
to another network: the snapshot lives 72 h on the receiver.

### 4.2 The friend relay

- `externals()` takes the discovered public IP with the relay's own ports
  (TCP, QUIC, and TCP 443 while that listener is open), after the operator's
  `relay_external` and UPnP, like the host's confirmed IPs, where the NAT
  keeps ports (§3.3).
- An address found this way is **worth offering** without `--external`
  (spec §11.4 gains "or STUN discovery found the address"), without the
  CONFIRMED flag. The existing rule sets CONFIRMED once a member reserves from
  a globally routable IP; members rank confirmed offers higher (relay
  selection), so an unconfirmed offer is tried when nothing better exists.
- `raven relay status` and the `relaying` row then say "YES, for N verified
  contacts, but no contact has reached it from the internet yet: forward TCP
  and UDP 7427 on your router, or turn on UPnP" instead of "no public address
  to offer", and once a member reserved from outside, plain "YES".

### 4.3 The card

A card never names a discovered address (owner rule 2026-10-28, AR-2
revised): a card is copied around in plain text, so a public address must
not be in it. `raven whoami --card` is what it was before auto-reach; the
running node's status carries no address it could take. Readers are
unchanged: a `raven-card/2` that names a direct `via=` or an `inet=` (typed
by its owner, or printed by the lab build of `f8909989`) is read as before.
A friend that has never linked learns where to reach this computer from the
Tor onion address in the card (another branch), never from an IP; once they
link, route hints carry the public address inside the encrypted link.

### 4.4 Confirmation

An address is confirmed when an authenticated contact reaches this computer
through it from outside:

- p2p: an inbound libp2p connection (not a relay circuit) from a contact the
  peer gate admits, from a globally routable IP that is not this computer's
  own public IP (a hairpin through the home router proves nothing), on the
  TCP or QUIC listener: that transport's discovered address is confirmed for
  24 h, listed among the confirmed DIRECT entries, and the reachability
  class becomes `public` (a new fact in `reach_class`: an authenticated
  contact is stronger evidence than an AutoNAT server, which may lie);
- Internet direct: an inbound RIH1 link from such an address: the INET_DIRECT
  entry gets CONFIRMED;
- the friend relay: unchanged (a member's reservation from a global IP).

## 5. Serverless hole punching

### 5.1 When

A contact is a punch target while all of these hold:

- the gate is live (STUN discovery, the NAT class gate and
  `RAVEN_LAB_SERVERLESS_PUNCH`), and the p2p host has an IPv4 QUIC listener;
- the contact is verified and unblocked, and this node may show it its IP
  (hide my IP off for it);
- its live route hints name a PeerId and at least one global QUIC DIRECT
  endpoint, and its NAT_CLASS says its IPv4 QUIC mapping is `no_nat`,
  `stable_kept` or `stable_shifted`;
- this node's own QUIC class is one of those three (from STUN or the
  classifier);
- no connection to that PeerId is open now.

`varies` or `unknown` on either side skips the contact: with an
endpoint-dependent mapping the port the friend would need is unknown, and D13
forbids guessing it.

### 5.2 How

libp2p-quic 0.14 dials from the listener's socket when a listener of that
address family is open (`PortUse::Reuse`, the default), so a dial leaves from
the p2p port and through the very mapping STUN saw. When both friends dial
each other's mapped endpoint at about the same time:

1. A's first QUIC Initial opens A's NAT for B's endpoint and is dropped at
   B's NAT (B has not sent yet);
2. B's Initial opens B's NAT for A's endpoint and passes A's NAT, which now
   expects B's endpoint (address-and-port-dependent filtering); A's QUIC
   endpoint, which is also a server, answers and the handshake completes.
   Retransmitted Initials (after about 1 s and 3 s) cover a clock skew of a
   few seconds.

Both sides dial as clients, so up to two connections may form; the endpoint
allows 3 per peer, and libp2p uses either. This is what DCUtR's QUIC upgrade
does in libp2p 0.57 (both sides `connect` from the listener endpoint), minus
the relay that DCUtR needs to agree on the moment. TCP simultaneous open is
not attempted.

### 5.3 The schedule: meeting in time, no coordinator

The two friends agree on the moments without exchanging anything:

- Time is cut into slots of 30 s of Unix time (`RAVEN_LAB_PUNCH_SLOT_S` in a
  harness). Slot `n = floor(unix_ms / 30000)`.
- The pair's phase `p` and offset `d` come from
  `SHA-256("raven/punch/v2" || R || be64(day) || lower identity key ||
  higher identity key)`, where `R` is the pair's R2 root (a static X25519
  agreement of the two identity keys, `RAVEN_PRIVATE_RENDEZVOUS_V1` §5.3a)
  and `day = floor(unix_ms / 86400000)`: `p` from its first 4 bytes, `d`
  from the next 2, reduced to the first third of a slot. Both sides compute
  the same values, they change every UTC day, and an observer who knows
  both public keys (both cards) cannot (security review 2026-10-29 #5: v1
  hashed the two public keys only).
- A side at level `L` (0 to 5) takes part in slot `n` when
  `(n + p) mod 2^L == 0`, and dials at the slot's start plus `d`. The sets
  are nested, so two sides at levels `La` and `Lb` meet in every
  `2^max(La, Lb)`-th slot.
- Levels: a contact this node has something waiting for (its outbox holds an
  object for it, or one was just queued) is at level 0 (every 30 s) for its
  first two attempts, then one level up per two failed attempts, up to 5. A
  contact with nothing waiting stays at level 5 (every 16 minutes), so a
  friend that wants to deliver meets it within 16 minutes at most. A network
  change, a start or a contact's new route hints reset the failures.

### 5.4 Limits

- At most 4 attempts per slot in all (the lowest levels first, then the
  contacts tried longest ago); at most 8 contacts at level 5 (the most
  recently heard); at most 200 attempts per contact per 24 h; after 32
  failed attempts in a row a contact rests for 6 h.
- One attempt is one libp2p dial to the contact's (at most 2) QUIC endpoints
  under libp2p-quic's 5 s handshake timeout: about 3 to 4 Initial packets
  of 1,200 bytes when nobody answers, so about 0.4 MB a day for an
  unreachable idle friend, nothing while connected.
- Never toward a stranger: targets come from the verified contact book and
  their own route hints, and the peer gate still decides every connection.

### 5.5 After a punch

The connection is an ordinary contact connection: the outbox's p2p dial finds
it open (`Host::connect` returns at once), and a punch that connects calls
the outbox's "friend is back" kick (`outbox::peer_back`), so what waited goes
at once. Logs and status count punches (tried, connected, skipped and why),
never an address or a PeerId; a delivery over it is labelled `direct`.

## 6. Fallbacks stay

Nothing is removed. The p2p dial still tries saved routes, learned relays and
circuits; the friend relay now has an address to offer; friend custody over
the internet uses whatever path reaches the custodian (now also a discovered
direct address); LAN, the LAN beacon and Bluetooth nearby are untouched; and
`outbox::peer_back` (round 6) still kicks the outbox on any sign a friend is
back.

## 7. Failure cases

| Case | What happens |
|---|---|
| UDP blocked, or no STUN server answers | No address; logged once with "retrying"; refreshes back off to 20 min; everything works as today. |
| Carrier NAT (100.64/10 behind the operator) | STUN sees the operator's address. With an endpoint-independent carrier NAT, punching can work; with `varies`, it is skipped. The address is offered unconfirmed and never confirmed (no forward is possible). |
| Symmetric NAT (`varies`) | No punch; the p2p QUIC endpoint is not derived from a refresh; the relay and custody paths carry the traffic. |
| Port forward on another external port | The derived address uses the listen port, so friends' dials fail and nothing confirms it; `--external` still names the right one. |
| Public IP changes (ISP) | The next refresh sees it, the host re-homes, the anchor learns the new endpoint, route hints move the generation and announce it. |
| Both friends behind the same NAT | They meet over LAN; a punch toward the shared public IP needs the router to hairpin and simply fails otherwise. |
| A friend moved and its old endpoint is stale | Its punches go to the old endpoint and fail until a link (LAN, relay, custody, a forward) brings its new hints; nothing serverless can tell a moved friend's new endpoint to a friend behind address-dependent filtering. |
| Clocks more than a few seconds apart | Slots do not overlap; punches fail; the other paths work. |
| A STUN server lies | It can only make this node offer a wrong address (dials fail, nothing confirms it) or change the class; two independent answers must agree. It cannot learn or change anything about contacts. |

## 8. Wire and document changes

- `protocol/RAVEN_ROUTE_HINTS_V1.md`: DIRECT may carry discovered,
  unconfirmed addresses (sender rule, §6); §11.4 worth offering; new §13.3
  INET_DIRECT (0x24) with vectors `route_hints/rrh1_inet_direct_001.json` and
  `route_hints/negative/rrh1_inet_direct_bad_001.json`; §9 says a card never
  names a discovered address.
- `protocol/PROTOCOL_VERSIONS.md`: the route hints row names 0x24 and its
  gate; the freeze hashes are regenerated.
- `protocol/RAVEN_NAT_CONNECTIVITY_V1.md`: unchanged (it describes the old
  experimental binary).
- This document; the any-network plan's Phase 4 section points here.

## 9. Tests

- Unit: the STUN codec against the RFC 5769 sample request and IPv4 and IPv6
  responses, FINGERPRINT, every rejection rule; classification; the
  schedule (phase symmetry, nesting, level rules), limits and target
  selection; hint entries (DIRECT order, INET_DIRECT codec and receiver
  rules); the friend relay's externals and offer.
- Harness (`scripts/lan_fault_matrix.py`, `RAVEN_FAULT_AUTOREACH=1`; real
  `ash` and `raven-node` on loopback, two fake STUN servers on loopback,
  never the public list). The nodes meet over Internet direct links: they
  carry route hints but, unlike LAN links, no same-LAN address (which the
  harness's local-candidates switch would keep as a global one on
  loopback), so a p2p address is learned only from STUN discovery.
  - s146: a node whose fake STUN answer is a router that keeps ports with
    its ports forwarded (on loopback, its own listeners) finds its address
    from the p2p port (anchored) and offers its friend relay with no
    `--external`; a node without the switch does not; a member learns the
    offer and the discovered DIRECT addresses and reserves;
  - s147: a friend that learned that address while "together" reaches it
    after "moving" (no saved route but the PeerId, no relay): p2p `direct`
    to the discovered address, the automatic carrier to the INET_DIRECT
    address, the port then counted as reached from outside (reach class
    public); the control without the switch is never reached;
  - s148: three nodes behind simulated endpoint-independent NATs that shift
    ports and drop what they did not ask for (one Python NAT box), no LAN,
    relay or saved route: a message to an idle friend is delivered over a
    punched QUIC connection, and the node without the punch switch never
    gets its message.

## 10. Not done, and why

- **Port prediction / birthday punching** (D13): never.
- **TCP simultaneous open**: libp2p-tcp's port reuse makes it possible in
  theory, but it fails on most NATs that rewrite sequence numbers or send
  resets; QUIC is enough for punching.
- **STUN over TCP or on IPv6**: TCP forwards cannot be detected by STUN;
  IPv6 addresses are the host's own and are handled by listen addresses and
  pinholes.
- **Telling a moved friend's new endpoint without any path**: impossible
  without a third party reachable by both (the research's rendezvous limit).
- **Mapping keepalives on a non-port-preserving NAT**: if the p2p socket
  stays idle longer than the NAT's timeout, the mapping may move; the next
  re-home or refresh repairs it.

## 11. Three-machine field test (lab builds)

Debug builds, lab set S5A plus `RAVEN_LAB_STUN_DISCOVERY=1` and
`RAVEN_LAB_SERVERLESS_PUNCH=1` on all three machines (S5A already has
`RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_NAT_CLASS=1`, `RAVEN_LAB_ROUTE_HINTS=1` and
`RAVEN_LAB_FRIEND_RELAY=1`). No `RAVEN_LAB_STUN_SERVERS`: the public list. The
consents stay as in the field run; `raven node stun` is on by default.

| Row | Setup | Pass |
|---|---|---|
| F1 | mac-b at home with the forwards (TCP 17422, TCP+UDP 17423 and 17427); `raven node stun` on each machine | mac-b: public address found, NAT stable (port kept), anchored; `raven relay status` offered with no `--external` |
| F2 | mac-a and mac-b exchange a message at home (route hints), then mac-a moves to the phone hotspot and sends 10 | 10/10 delivered `direct` to the discovered address; mac-b's status then says reached from outside (reach class public) |
| F3 | mac-a on the hotspot reserves on mac-b's offered relay | the offer turns CONFIRMED; win-c and mac-a exchange through it if win-c can reach mac-b's public address from home (router hairpin), else custody at mac-b carries it |
| F4 | Serverless punch: remove the 17423 forward (keep 17427); mac-a on the hotspot exchanges a message with mac-b through mac-b's relay (route hints over the relayed link), then `raven relay offer off` on mac-b and only mac-b's node restarted (mac-a keeps running, so its hotspot mapping stays the one mac-b learned; a direct connection DCUtR made goes with the restart); mac-a sends 10 | `raven node stun` on mac-a says its hotspot NAT class; with `stable_*` on both sides the messages arrive over a punched connection within 16 minutes (punch counts in `raven doctor`); with `varies` the punch is skipped and the messages wait (recorded) |

## 12. Owner decisions asked

- **AR-1** Decided 2026-10-28: Cloudflare and Google only, both on every
  probe (each the other's fallback), every 20 minutes and on every network
  change.
- **AR-2** Decided 2026-10-28, then revised the same day by the owner rule
  "everything private and encrypted": a card never names the discovered
  public address; it travels only inside encrypted, authenticated links
  between verified friends (route hints; Tor once that branch lands).
- **AR-3** Decided 2026-10-28 (as recommended): a contact's inbound
  connection from outside makes the reach class `public`.
- **AR-4** Decided 2026-10-28 (as recommended): idle punching every 16
  minutes for at most 8 friends (about 0.4 MB a day per unreachable
  friend).
