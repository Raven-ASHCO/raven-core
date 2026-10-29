# DRAFT owner waiver: libp2p relay and hole punching (transports P3)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file (the doc comment of `p2p_gate.rs` only points here).
> `P2P_PRODUCTION_ENABLED` stays `false` until the owner signs a final copy
> (renamed to `docs/WAIVER_P2P_RELAY_<date>.md`), the exit conditions in §7 are
> met, and the gate-flip change (§8) is applied as its own reviewed commit. For
> this phase the design recommends an independent review, not only a waiver
> (design §8 Q1; §3 hold 3 below).

| | |
|---|---|
| **Waiver ID** | `WAIVER-P2P-RELAY-<date>` (to be assigned on signature) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md), whose §6 makes any scope extension without a new record a lapse condition. Independent of the Internet direct draft ([`WAIVER_INTERNET_DIRECT_DRAFT.md`](WAIVER_INTERNET_DIRECT_DRAFT.md)): either may be signed first, and neither covers the other's carrier |
| **Approver** | Protocol owner (signature pending) |
| **Date** | pending |
| **Decision** | Enable the libp2p carrier (direct TCP/QUIC, Circuit Relay v2, DCUtR; verified contacts only) and the relay role in default and release builds under this waiver, instead of waiting for an independent review |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set `P2P_PRODUCTION_ENABLED = false` in `node/crates/raven-core/src/p2p_gate.rs`. `PRODUCTION_NAT_CONNECTIVITY_ENABLED` (`node/crates/raven-swarm/src/connectivity.rs`) is not this gate: it belongs to the separate `raven-swarm-connectivity-experimental` binary, stays `false` whether or not this waiver is in force, and needs its own record to change |
| **Design** | [`design/2026-10-transports-internet-mesh-bridge.md`](design/2026-10-transports-internet-mesh-bridge.md) §2.1, §3.1-§3.3, §3.5-§3.7, §5 (row P3), §6.4-§6.5, §7.4, §8 (Q1, Q6-Q9, Q11, Q12) |
| **User docs** | `INSTALL_Linux.md`, `INSTALL_macOS.md`, `INSTALL_Windows.md`, section "libp2p: relay and hole punching" |
| **Phase 2 amendment** | §9, an unsigned draft of its own: route hints (RRH1) on p2p links, the friend relay, automatic relay choice, relays on TCP 443, the relay kit and the "nobody reachable" diagnosis |
| **Phase 3 amendment** | §10, an unsigned draft of its own: RFC1 friend custody on `/raven/link/1.0.0` links, with [`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md) as the other record |
| **Phase 4 amendment** | §11, an unsigned draft of its own: the NAT mapping class (RRH1 NAT_CLASS, skipping hopeless hole punches) and PeerId rotation per epoch (RRH1 PEER_SCHEDULE, card `p2pn=`, relay schedules). WSS on 443 and router port mapping have drafts of their own: [`WAIVER_WSS_PROXY_DRAFT.md`](WAIVER_WSS_PROXY_DRAFT.md), [`WAIVER_PORT_MAP_DRAFT.md`](WAIVER_PORT_MAP_DRAFT.md) |

## 1. Why a waiver is needed

Umbrella §9.1 ([`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](../protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md))
holds every relay and DCUtR flag until all of its holds pass, and its recorded
owner exception covers LAN direct only. The LAN waiver lists relay and DCUtR as
not covered (its §2). [`RAVEN_NAT_CONNECTIVITY_V1.md`](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md)
§6 adds its own production hold: ATSAM endpoint/session integration on Rust
**and iOS**, signed-ACK recovery, abuse testing across relay and AutoNAT
failures, explicit relay policy, mobile lifecycle handling and interop soak
tests.

P3 adds to `raven-node`: a supervised libp2p host in `raven-node service`
(opt-in `--p2p-listen`, TCP and QUIC on 7423), the Raven link protocol
`/raven/link/1.0.0`, reservations on up to two relays, DCUtR, an AutoNAT v2
client, the relay role (`raven-node relay`, `raven-node service --relay`), an
opt-in UPnP (IGD, IPv4) mapping, `raven-card/2` cards, `raven send --carrier p2p`
and `raven relay allow|deny|status|card`. It is the first public-facing libp2p
surface in Raven (Q1), and for contacts who are both behind NAT it is the only
confidential carrier, so also their only pairing path (design F6, §4.8).
Turning it on for users is a scope extension of a waived slice and needs this
record.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- **carrier:** the libp2p carrier of `raven-node`: libp2p TCP (Noise + Yamux)
  or QUIC-v1 connections, direct or through a Circuit Relay v2 circuit, with
  the DCUtR upgrade. Inside each connection one libp2p stream of protocol
  `/raven/link/1.0.0` runs Raven Noise XX with prologue `raven/p2p-link/v1`,
  the channel-bound RIH1 identity bind (same layout and verification as
  Internet direct, Transport Interface §3) and the RLB1 offer, then the same
  dispatcher as LAN and Internet direct;
- **link classes** (Carrier Conformance §3.2): `ENDPOINT_AUTHENTICATED` for a
  direct or DCUtR-upgraded connection, `OPAQUE_CIRCUIT` through a relay. A
  DCUtR upgrade runs a new stream and a new Raven handshake on the direct
  connection, and pending objects are retried byte-identically (Carrier
  Conformance §7.4);
- **objects:** as in the LAN waiver: PairInit V1 / PairResponse (accepted only
  from local contacts), `ATSAM/indexed-session/v1` RVNA1 `0x03` messages and
  sealed ACKs. The Raven link ends at the contact, relayed or not, so p2p is a
  confidential carrier in the sense of PairInit §7; PairInit is never placed in
  a relay-readable body;
- **peers:** verified (pinned) contacts only, in both directions. The dialer
  requires the responder's hello to name the pinned key. The responder answers
  only an initiator whose hello names a local, unblocked, pinned contact, and
  closes the stream for anyone else at the same point and with the same timing
  as for a stranger (stranger timing parity). The libp2p PeerId is never
  trusted for identity (Carrier Conformance §11.4 item 2, §11.5 item 7).
  Below the link, a peer gate (the third libp2p behaviour, before the relay,
  DCUtR, AutoNAT, Identify and the link protocol) admits only the `p2p=`
  PeerIds of verified, unblocked contacts, this node's relays, the relays a
  contact's `via=` names (outbound only) and, with the relay role, the
  allow-listed members; everyone else gets one libp2p Noise handshake and a
  closed connection, and a stranger's circuit is refused before this node
  accepts it;
- **addresses:** a PeerId and up to two relay multiaddrs (each ending in
  `/p2p/<relay PeerId>`) from the contact record or a `raven-card/2` (`p2p=`,
  `via=`), and relays the user names (`--p2p-relay`, `RAVEN_P2P_RELAYS`,
  `p2p_relays`, at most 2). None is compiled in, none is discovered through a
  DHT or rendezvous. The listener is off unless the user opts in;
- **reachability helpers:** AutoNAT v2 client (a hint only, never trust;
  `public` only when two of the node's own relays on different networks
  agree, each a /24 or /48 other than the other's and the tested address's
  own; each relay, started with `--autonat-server`, tests through its own
  client, so with one such relay the node is at most `unconfirmed`), Identify
  `/raven/identify/1.0.0` (with contacts, own relays and relay members only),
  DCUtR (with verified contacts only, offering and dialling globally routable
  addresses only), Ping; UPnP-IGD (IPv4; libp2p-upnp has no NAT-PMP or PCP)
  only after the user says yes (owner decision Q8, "ask once at setup"; unset
  behaves as off);
- **relay role:** a Circuit Relay v2 server in `raven-node relay --data-dir
  <dir>` (no Raven identity, no keystore; optional AutoNAT v2 server with
  `--autonat-server`) and in `raven-node service --relay` (shares the service's
  host, so its relay PeerId is the user's own PeerId). The allow-list
  (`relay_allow.json`) is on by default: the PeerIds on it may connect,
  reserve and open circuits, and circuits run only between them (consent by
  circle: the destination consents by reserving on its circle's relay, so a
  sender must be on the recipient's relay list too; libp2p-relay 0.22's
  circuit limiter never sees the destination, so per-destination consent is
  a Phase 2 decision). `--open` (dedicated relay) serves anyone, with
  stricter limits and a printed notice; `--relay-open` (service) serves any
  verified contact of the operator (the peer gate keeps strangers out), with
  the same limits. **Owner choice at signature:** keep open relays in scope,
  or exclude them, in which case release builds must refuse both flags.

Not covered (all remain held): Kademlia, any DHT or public peer record
(design F5), the libp2p rendezvous protocol, route hints inside links (RLB2 /
`RRH1`, design §3.1 item 2; RRH1 v1 is the subject of the Phase 2 amendment,
§9), the offline mailbox (`--mailbox`, P4), mesh and
bridge custody and `RHW1` (P2b), PairInit over any non-confidential carrier and
the asynchronous PairInit carrier (Q3), the separate
`raven-swarm-connectivity-experimental` binary and its flag, Swift / iOS, a
Windows SCM service for the relay (Q9), an aggregate relay bandwidth cap (the
`--max-mbps` idea of design §3.5 is not implemented), Object Sync over p2p, the
Hybrid Ratchet v2 / Full Braid lab, and any Session V2 claim. Raw Internet
direct on TCP 7422 is covered only by its own record.

## 3. Holds for this scope

### 3.1 Umbrella §9.1

| Hold | Status at signature (to fill) | Waived? |
|---|---|---|
| 1. Automated gates | Design §6.4 scenarios: C6 forced relay (`OPAQUE_CIRCUIT`, PairInit through the relay; A and B reach the relay through a recording TCP proxy, and everything it relayed holds no `RVPI1`, `RVPR1`, `RLB1` or `RIH1` magic, no message text and no Raven identity key or address; a stranger is refused by the relay's peer gate, a member of the relay's circle who is not the destination's contact by the destination's, each before any protocol runs and with a counts-only log line and a hint in the sender's error) on ubuntu, macOS and Windows; C7 DCUtR in the netns NAT simulation (`node/scripts/netns_nat_dcutr.sh`, ubuntu only; transports design §6.4), every required case each iteration: cone (first the R14 stranger in R's circle, refused by B's peer gate with 0 packets past R on the routers' kernel counters; then the next message is `path=hole_punched` and the counters show the direct path), symmetric (every message `path=relayed`; an upgrade fails the run), cone-private (`path=relayed`, 0 packets out of either LAN to anything but R) and swap (A's uplink moves: a p2p re-home on the same relay, the queued messages delivered exactly once). A `link via a direct connection` line alone is no pass: `direct` and `reversed` links print it too. Advisory job `nat-sim-linux` in `raven-serverless-lab.yml` until 10 consecutive green iterations are recorded (§7). C7 here is only this netns gate; the carrier_matrix app-channel test is C7a. C10 relay abuse (handshake, reservation and junk floods; contacts keep their slots) on ubuntu and macOS: today raven-swarm `host.rs` unit tests cover the allow-list (`allow_list_is_on_by_default_and_fails_closed`, `a_peer_off_the_allow_list_cannot_reserve`), the per-IP reservation cap (`per_ip_reservation_cap_holds_and_frees_on_close`), the reservation rate (`reservation_rate_is_per_source_and_spent_only_on_admissions`), the circuit byte and duration caps (`circuit_byte_cap_cuts_the_circuit`, `circuit_duration_cap_closes_the_circuit`) and the slots kept for a node's own dials (`limits_come_first_and_outbound_keeps_a_reserve`); the handshake flood and the junk flood have no test yet. C3 contact gating over p2p; C1 / C2 unchanged | Not waived |
| 2. All companions APPROVED | Not all approved. Carrier Conformance V1 is not APPROVED, and the link uses the RIH1 bind, which its §18 calls a legacy adapter (§4 item 10) | **Waived for this slice** |
| 3. Independent security review | Not done. The design recommends a focused external review of the public libp2p surface (relay server, AutoNAT server, Identify, the `/raven/link/1.0.0` responder, UPnP) before this flag flips (Q1). **Owner decision at signature:** commission that review, or waive it here with the reason written down | **Waived only if the owner records that decision** |
| 4. Physical rows / failure matrix | Umbrella §10.2 stage 7 (its DCUtR part) as row R7b, stage 8 as row R8, and the stage-12 slice for p2p (design §6.5): **must be recorded before signature**. Pending, owner-run | **Not waived** |
| 5. Indexed-session paths stay lab-gated | Live on this slice, as for LAN | **Waived for this slice**; never described as Session V2 |

### 3.2 NAT spec §6 production hold

| Requirement | Status at signature (to fill) | Waived? |
|---|---|---|
| ATSAM endpoint/session integration on Rust | The p2p link feeds the LAN / Internet dispatcher; C6 shows message 1, ACK, message 2 through a relay | Not waived |
| The same on iOS | Not done. Swift / iOS is out of scope (owner decision 2026-10-08, "terminals only") | **Waived**, recorded here so that it does not lapse silently (design Q12) |
| Signed-ACK recovery | The sealed ACK rides the same link; a lost ACK gives exact resend, Duplicate, ACK (C5); the P2a outbox worker returns ACKs later | Not waived |
| Abuse testing across relay and AutoNAT failures | C10, plus relay down, reservation lost and AutoNAT "unknown" cases | Not waived |
| Explicit relay policy | Allow-list by default and fail closed, the limits of §5, no compiled-in relay, `--open` explicit with a notice | Not waived |
| Mobile lifecycle handling | No mobile client in scope | **Waived** together with iOS parity |
| Interop soak tests | Setup and duration to be defined by the owner (for example the R7b setup left running for several days) | Not waived |

Carrier Conformance §19.2 adds for "Circuit Relay/DCUtR": explicit relay policy
(above), an opaque-stream proof (the C6 capture), new-context behaviour (a new
Raven handshake after DCUtR, C7) and physical rows 7-8 (R7b, R8).

## 4. Residual risks accepted

Everything in LAN waiver §4 applies unchanged: no forward secrecy and no
post-compromise security inside a 24 h session (profile §2.4), now for traffic
that a relay can record; no independent review or formal model; device key
equals identity key; no deniability; local-only revocation; Keychain prompts;
platform coverage. So do items 3 (metadata, the dialer's hello goes first), 4
(no FS / PCS for traffic that crosses the Internet), 5 (verified contacts only:
narrowed, not waived), 6 (Windows reachability) and 7 (clock skew) of the
Internet direct draft, now for p2p. In addition:

1. **Relay metadata** (design §3.5; the disclosure table Carrier Conformance
   §13 asks for):

   | Observer | Learns | Does not learn |
   |---|---|---|
   | A relay | Both PeerIds and IPs of every circuit, its timing, duration and byte count; who reserves; with `--autonat-server`, the probe targets | Raven IDs (unless it holds cards mapping PeerId to Raven ID), plaintext, PairInit, RLB1, route tags, message IDs: all inside libp2p Noise and, inside that, the Raven Noise link `raven/p2p-link/v1` |
   | A relay that also holds friends' cards | The friend graph at PeerId level | Message contents |
   | Anyone who connects to an open 7423 (not a contact, relay or member) | The node's PeerId (libp2p identifies itself in its Noise handshake; it is on the card anyway) and that a node listens; then the peer gate closes the connection | Identify (protocols, agent, observed or external addresses), DCUtR candidates, AutoNAT, the Raven link and the Raven ID: none of them runs for it. A stranger's circuit is refused before this node accepts it, so the stranger learns no address of the node at all |
   | Own relays and relay members (and contacts) | What Identify sends: its protocols, the agent `raven`, the address it observed for the peer, and only the node's **confirmed external** addresses (relay circuits, addresses AutoNAT v2 found reachable, a UPnP mapping, global IPv6; for a relay, the addresses of §5 "relay addresses") | Its listen addresses: Identify runs with `with_hide_listen_addrs(true)` and no listen-address push (checked against libp2p-identify 0.47: only the external set is sent), so LAN, link-local and loopback listen addresses are never published |
   | A holder of a `raven-card/2` | The mapping PeerId to Raven ID, and the relays named in `via=` (their IPs and PeerIds) | - |
   | Verified contacts and the relay during DCUtR | The address candidates exchanged for hole punching, offered to verified contacts only (the peer gate admits nobody else, and a relayed connection's DCUtR handler is built only past it): at most 8, all globally routable, in this order: the router mapping (UPnP) and addresses AutoNAT confirmed; the node's own global IPv6, only the address the OS sends from once known (usually a temporary one), else at most two; addresses the node's own relays, or at least two peers, observed it at on direct connections (the last 10 min); its own global IPv4 listen addresses; Identify's own guesses (at most 4). The relay sees that an exchange happens, inside Noise | LAN, loopback, link-local, ULA, CGNAT and documentation addresses, DNS names and circuits: never offered, and a hole-punch dial to one is refused. Nothing is offered to a stranger (carrier_matrix C16 proves it from inside the circuit) |
   | ISP / network observer | IPs, ports, timing, volume, that libp2p is in use | Contents |

   A relay can also refuse service, delay, drop or selectively degrade
   circuits (NAT spec §4); it cannot read or forge Raven traffic.
2. **Stable PeerId (Q6).** The libp2p key is derived from the Raven seed, so
   the PeerId is stable per profile. It links a user across relays and
   networks, and every card maps it to the Raven ID. Accepted for P3
   (reservations need a stable PeerId); per-epoch rotation announced through
   route hints may come later. A stable public IPv6 listen address in a card is
   a stable location identifier.
3. **PeerId disclosure of `service --relay`.** The relay PeerId is the user's
   own PeerId. It is disclosed to every friend who uses the relay, and every
   friend's card whose `via=` names the relay carries the user's PeerId and
   home IP to all of that friend's contacts. Anyone who also holds the user's
   card can then map that home IP to the user's Raven ID. The dedicated relay
   (`raven-node relay`, its own key) avoids this; the user docs and the
   installer output say so.
4. **Public listener exposure.** An opted-in node, and every relay, accepts
   libp2p connections from the whole Internet: anyone who connects learns the
   PeerId (item 1), and with the card the current IP of a Raven ID. Handshakes
   cost CPU and pre-auth slots; the limits of §5 and the existing per-IP caps
   bound it, but a distributed flood can still keep friends out. The per-/24
   (IPv4) and per-/48 (IPv6) pre-auth cap of design §3.4 is **not** what the
   libp2p listener applies: it caps pending (4) and established (8)
   connections per IPv4 address or IPv6 /64, and inbound connections in total
   leave 16 slots for the node's own dials (its relays and contacts), so a
   flood cannot lock a node out of its relay. Whether that is enough: **owner
   decision at signature**.
5. **Open relays (Q7).** With `--open` the operator relays encrypted traffic
   for strangers (`--relay-open` on a service: for any of the operator's
   verified contacts): bandwidth, abuse complaints and possible legal
   exposure land on the operator. Limits are stricter (32 reservations,
   512 KiB per circuit), but PeerIds are free, so per-peer limits are weak and
   the per-IP limits are the real bound. There is no aggregate bandwidth cap.
6. **UPnP (Q8).** Owner decision "ask once at setup": the first
   interactive `raven node p2p on` (or an interactive install that turns p2p
   on) asks once, Enter or EOF means no, the answer is saved; non-interactive
   runs never ask; unset behaves as off; `raven node upnp on|off`, `--upnp` /
   `--no-upnp` and `RAVEN_UPNP=1|0` change it. When on, it changes router state
   and exposes 7423 to the whole Internet. Mapping lifetime and clean-up after
   the node stops depend on the router **(verify)**; consumer UPnP stacks have a
   weak security record; behind CGNAT a mapping does not make the node
   reachable. Logs show only the mapped external port and success or failure.
7. **DCUtR limits.** Hole punching fails on symmetric NAT and CGNAT-to-CGNAT
   pairs (the published libp2p success rate of roughly 70 % is unverified,
   design §3.6). Such pairs stay relay-only, so the relay sees the metadata of
   their whole conversation. Each circuit is capped (5 min and 2 MiB by
   default), so longer exchanges open new circuits. Delivery then depends on a
   friend's relay staying up: a laptop, a Mac that sleeps or a Windows logon
   task is a poor relay (Q9).
8. **Two Internet stacks (Q11).** Raw RIH1 on TCP 7422 and libp2p on 7423
   double the audit surface. The design proposes to make libp2p direct the
   default after P3 and deprecate 7422 after one release. **Decision at P3 exit:
   to fill.**
9. **Third-party code on a public port.** rust-libp2p 0.56 (relay server and
   client, DCUtR, AutoNAT v2, Identify, QUIC, UPnP) has not been reviewed by
   us. Several API behaviours the design relies on are marked (verify), for
   example streams on limited (relayed) connections (design §3.2, Q17).
10. **Carrier Conformance gap.** The link binds identity with RIH1 (Transport
    Interface §3), which Carrier Conformance §18 lists as a legacy adapter. It
    has no `RVCM1` / `RVLN1` / `RVLB1` / `RVLC1` negotiation (§6) and no exporter
    (§7). Accepted by waiving hold 2; no Object Sync runs over p2p.
11. **AutoNAT server (optional, dedicated relay only).** It dials back
    addresses that clients ask it to probe, and so learns them. libp2p-autonat
    0.15 itself dials any address it is asked to (checked: no address filter);
    it only makes a client that asks for an address other than the one it
    connects from first send it 30-100 kB (the protocol's amplification check).
    `raven-node relay` adds a dial-back guard that refuses every outbound
    connection of the relay host to an address that is not globally routable
    (loopback, private, link-local, CGNAT `100.64/10`, ULA, documentation and
    benchmark ranges, multicast, broadcast, reserved), so it cannot be used to
    reach the relay's own LAN; a client can still have it send one connection
    attempt to any global address per request. Off unless `--autonat-server`
    is given.
12. **Port sharing on Windows.** libp2p-tcp binds with `SO_REUSEADDR` (and
    `SO_REUSEPORT` on Unix) and no `SO_EXCLUSIVEADDRUSE`. Before it binds,
    `raven-node` probe-binds every listen port with a plain socket and refuses
    a port another program already holds (one clear log line, retried with
    backoff; the dedicated relay exits). On Windows a program that starts
    *later* with `SO_REUSEADDR` can still bind the same port and take some of
    its connections; the Raven link still authenticates the contact, so this
    costs availability, not confidentiality.
13. **What the peer gate leaves open** (owner decision at signature: keep
    open relays in scope with this disclosure). The gate closes the leak of
    any-network plan §0 item 4 (anyone holding a card learned the node's
    current IP through DCUtR), but:
    - an `--open` relay still lets a stranger tell "reserved but refused"
      (the destination's gate refuses the circuit: `CONNECTION_FAILED`) from
      "not reserved" (`NO_RESERVATION`), so it learns whether a peer is
      online; no address leaks, because the destination refuses before it
      accepts the circuit, runs Noise, Identify or DCUtR;
    - inside a circle, a member can learn the same about the other members;
    - Identify still shows this node's confirmed external addresses (circuit
      addresses on its other relay, global IPv6, a UPnP mapping) to its own
      relays and to its relay members, a deliberate exception: own relays
      provide observed-address learning, and members need our observations
      of them;
    - a pinned contact whose `p2p=` PeerId is missing from the contact book
      (an old card, or one given one way only) is now refused at the libp2p
      level, before its Raven link: the fix shown to the user is to send
      cards both ways (the dial error says so, and `raven status` has a
      `p2p_gate` row);
    - relays serve circuits only between peers on their allow-list (consent
      by circle, §2): a contact of a member who is not on the relay's list
      cannot reach that member through it;
    - the gate's set can be about 1 s stale after a contact edit (re-read
      every second); our own dials admit the contact they checked at once,
      and a contact's inbound dial in that second is refused once and
      retried by its outbox;
    - contacts stay trusted for address steering: a contact can feed a fake
      observed address through Identify, which becomes a hole-punch
      candidate (offered to contacts only, and global only).

## 5. Compensating controls in place

- **Allow-list by default** on both relay forms: only PeerIds in
  `relay_allow.json` may connect, reserve and open circuits. A missing
  allow-list means nobody, an unreadable or corrupt one means nobody (fail
  closed). `raven relay allow|deny|status|card` manage and show it; a peer
  taken off the list loses its reservation and its connection.
- **Peer gate (third behaviour).** Every libp2p host composes a peer gate
  right after the connection limits and before every protocol
  (`raven_swarm::gate`; swarm-derive 0.36 asks the fields in declaration
  order and stops at the first denial, lib.rs:289-310, and libp2p-swarm 0.48
  then spawns no handler of any field, lib.rs:700-763). An endpoint admits
  verified, unblocked contacts' `p2p=` PeerIds, its relays, the relays a
  contact's `via=` names (outbound only) and, with the relay role, its
  listed members; a dedicated relay admits its allow-list (anyone with
  `--open`). A circuit is admitted for contacts only, and a stranger's
  circuit is refused at the pending stage, before this node accepts the
  relay's STOP or runs Noise. The set is read from contacts.json and the
  block list off the swarm loop, re-read within a second of a change, and a
  corrupt file admits no contact (fail closed; the relays still are). Its
  refusal names no peer. DCUtR and Identify run only on admitted
  connections of the classes they need (DCUtR: contacts; Identify: contacts,
  own relays, members; each AutoNAT client: its own relay).
- **DCUtR sends and dials global addresses only.** Hole-punch candidates are
  filtered to globally routable addresses before they are offered (to
  verified contacts only), and a hole-punch dial whose addresses are not all
  globally routable (or name another peer) is refused whole: never a LAN,
  loopback, link-local, ULA, CGNAT, documentation or NAT64/6to4-wrapped
  private address. The only exception is a debug lab switch
  (`RAVEN_LAB_P2P_LOCAL_CANDIDATES=1`, debug builds only) for one-machine
  harnesses; the netns harness never sets it (its simulated Internet is
  global-looking 11.0.0.0/16 that cannot route out).
- **Relays serve circuits only between allow-listed peers.** The circuit
  limiter checks the source against the allow-list before it spends any rate
  token (libp2p asks it before it looks the destination up, so a refused
  source gets `RESOURCE_LIMIT_EXCEEDED` whether or not the destination is
  reserved), and the destination is on the list because it reserved there.
- **Contact-gated, pinned-only responder** on `/raven/link/1.0.0`, with
  stranger timing parity: a stranger or an unpinned contact never receives the
  responder's hello, Raven identity or RLB1 offer. The dialer requires hello
  identity == pinned key, and RLB1 must bind exactly the hello's key.
- **Domain separation:** the prologue `raven/p2p-link/v1` keeps a LAN (no
  prologue) or raw Internet (`raven/internet/v1`) transcript from completing
  against a p2p endpoint, and the reverse.
- **PeerIds and relay data are hints only:** PeerIds, relay addresses and
  AutoNAT observations never feed identity or contact decisions (Carrier
  Conformance §11.5 item 7); AutoNAT is a reachability signal, not an
  authorization oracle (NAT spec §2.1).
- **Relay limits** (default / hard max; a dedicated relay tunes them with
  `--max-reservations`, `--max-circuits`, `--circuit-bytes`, `--circuit-secs`,
  `--reservation-secs`):

  | Knob | Default | Hard max |
  |---|---:|---:|
  | Reservations total | 128 | 1024 |
  | Reservations per peer | 2 (a friend's new connection after a restart reserves at once while the relay still holds the old one) | 2 |
  | Reservations per IP | 4 | 16 |
  | Reservation duration | 30 min | 2 h |
  | Circuits total | 64 | 256 |
  | Circuits per peer | 4 | 8 |
  | Circuit duration | 5 min | 30 min |
  | Circuit bytes | 2 MiB | 16 MiB |
  | Reservation rate per IP | 4/min | - |
  | Circuit rate per IP | 30/min | - |
  | Established connections total | 256 | 1024 |
  | Established inbound connections | total - 16 (16 kept for the host's own dials) | - |
  | Established connections per IP | 8 | 32 |
  | Sources tracked per rate table | 4096 (oldest evicted; pruned every tick) | - |
  | `--open` / `--relay-open` | 32 reservations, 512 KiB per circuit | - |

  Every per-IP knob (reservations, both rates, pending and established
  connections) keys on an IPv4 address or an IPv6 /64; libp2p's own per-IP
  rate limiters, which key on the exact address (a /128 for IPv6), are not
  used. The endpoint host (no relay role) allows 64 established connections,
  48 of them inbound, 16 pending, and 4 pending and 8 established per source.
  The connection
  limits are the first behaviours asked for every connection and the peer
  gate the third, so a denied connection never reaches DCUtR, AutoNAT,
  Identify, the relay or the Raven link.
- **Relay addresses:** a relay names (in reservations and to Identify) only its
  globally routable listen addresses, a specific address the operator listens
  on, and `--external` addresses; with an unspecified listen address
  (`0.0.0.0`, `::`) it never names its LAN, link-local or loopback addresses.
  With nothing it may name, it uses a loopback placeholder (libp2p rejects a
  reservation without addresses) and logs once that `--external` is needed.
  Expired listen addresses are withdrawn.
- **Busy ports and clean restarts:** every listen port is probe-bound before
  libp2p binds it (§4 item 12); a busy one is retried on its own (the rest of
  the host keeps running) and `raven status` says so. On SIGTERM / SIGINT
  (Ctrl-C on Windows) the service closes its libp2p connections and waits at
  most 1.5 s for them to close, so a relay frees the reservation at once and
  the restarted node reserves again within seconds.
- **Network changes (Phase 0b):** when netwatch reports a network gone, back
  from no network, a moved default route or a wake from sleep, or when every
  relay holding a reservation failed its pings and nothing else answered one
  (a path loss: no network change in sight), the host re-homes. It stops
  listening (libp2p-upnp is asked to drop the router mappings it made: best
  effort only, the old router may be out of reach by then, and a mapping left
  behind lapses with its 1 h lease), answers every waiting dial, closes every
  connection (at most 1 s), drops the whole endpoint and builds a fresh one on
  the SAME relays: new listeners, a new UPnP gateway search, a new AutoNAT
  client, empty DCUtR / Identify state. A re-homed endpoint dials each relay
  from a new local port (the old connection may still hold the listen port's
  TCP 4-tuple) and reserves on that connection; the relay takes it as the
  peer's second reservation (within the per-peer cap of 2), reaps the silent
  old one by ping and keeps counting the peer until its last reservation
  closes. Networks only added keep the endpoint (idle relay slots retry at
  once). A path loss restarts no outbox backoff; a change does (P2a
  amendment). Logged with counts only (below); C12 and C13 test it on the
  three OSes, the netns `swap` run on Linux.
- **One relay per folder:** `raven-node relay` holds a lock in its folder for
  its whole life (a second one exits), rewrites `relay_status.json` at least
  every 10 s, and `raven relay status` says `not running`, `running` or
  `running but its status is Ns old (stuck?)`.
- **Counts-only logs** (NAT spec §5): no PeerIds, addresses, message IDs,
  route tags or payloads. The log lines are `raven-node p2p: host up
  (listeners=<n>, relays=<n>)`, `reservation accepted (active=<k>)`,
  `reservation lost (active=<k>)`, `direct connection upgraded (dcutr)`, `link
  via a direct connection` / `link via the relay` (when the kind of a peer's
  link changes), `upnp mapped port <port>` / `upnp mapping failed (...)`,
  `listen port <port>/tcp is already in use by another program ...` / `listen
  port <port>/tcp is open now`, `a configured relay name does not resolve
  (yet); retrying`, `re-homed (<why>): listeners=<n>, relays=<n>` (why:
  `network changed`, `woke from sleep`, `default route moved` or `every relay
  stopped answering`), `refused a connection from a peer that is not a
  verified contact or a relay of this node` (at most once per 30 s, with how
  many more), `peer gate reloaded (verified contacts <n>, relays <n>)`, `the
  contact book or block list cannot be read: no contact is admitted over p2p
  until it is fixed (relays still are)`, the dedicated relay's
  `reservations=<n> circuits=<n> refused_reservations=<n>
  refused_circuits=<n> refused_connections=<n>`, netwatch's `network
  changed` / `woke from sleep` / `default route moved (<n> new, <n> gone, <n>
  now): ...` ending `, p2p re-homing` and `every relay stopped answering; p2p
  re-homing`, the debug-only `lab ping every <n>s, timeout <n>s (debug
  build)` and `lab hole punching also offers and dials loopback and private
  addresses (debug build)`, and `P2P_HOLD: ...`. The node's own PeerId and
  listen addresses appear only in `raven status` (IPC) and, for a relay, in
  `relay_status.json` for `raven relay card`.
- **No compiled-in relay**, no DHT, no rendezvous: relays come only from cards
  and user configuration, at most two.
- **Relay names in cards and settings:** a `/dns*` relay address is kept as a
  name and resolved again before every reservation attempt, and the attempts
  rotate through every address it resolves to; a name that does not resolve
  is retried with backoff.
- **Opt-in exposure:** no libp2p listener unless `--p2p-listen`,
  `RAVEN_P2P_LISTEN` or `raven node p2p on` asks for one; a corrupt
  `node_policy.json` fails closed (no listener, no relays, no mapping); UPnP
  unset behaves as off; installers print firewall rules and never apply them
  (Windows: Private profile only).
- **The dedicated relay holds no Raven identity** and touches no keystore: only
  `relay_key.ed25519` (mode `0600`; on Windows a protected DACL that allows
  only the current user, as for every private Raven file and folder),
  `relay_allow.json`, `relay_status.json` and its lock file.
- **Visible state:** `raven status` shows `p2p` (`YES` only while the host is
  really up; otherwise the running service's own setting and where it came
  from, a flag, an environment variable or `node_policy.json`), `p2p_peer`,
  `p2p_listen`, `p2p_gate` (verified contacts and relays admitted,
  connections refused; counts only), `upnp` (setting and mapping result) and
  `p2p_relay` rows; `relay_status.json` and `raven relay status` count the
  connections a relay's peer gate refused.
  `raven whoami --card` takes its `p2p=` / `via=` from the running service
  too, and refuses to print a card longer than the longest valid card.
- **The gate itself:** with the flag off, a release build never listens, dials,
  reserves or advertises libp2p and logs one `P2P_HOLD:` line.
- Same dispatcher, admission and session checks as LAN waiver §5.

## 6. Conditions

This waiver lapses, and the flag MUST be set back to `false`, if any of these
happens before it is renewed:

- a critical or high finding on the covered path, including the rust-libp2p
  components it uses, is confirmed and not fixed;
- the slice is extended beyond §2 (DHT, rendezvous, mailbox, mesh custody,
  route hints, a compiled-in or default relay, a Windows relay service, ...)
  without a new waiver or review;
- the relay allow-list stops being the default, or a log line starts carrying
  PeerIds, addresses or message IDs;
- the peer gate is removed, or moved behind a protocol behaviour (any field
  before it in `EndpointBehaviour` / `RelayBehaviour` other than the
  connection limits), or its tests are disabled
  (`the_gate_refuses_before_dcutr_identify_or_autonat_build_a_handler`,
  `limits_come_first_and_outbound_keeps_a_reserve`,
  `a_stranger_circuit_is_refused_and_learns_no_address` and C6's stranger
  cases);
- `PRODUCTION_NAT_CONNECTIVITY_ENABLED` is set to `true` without its own
  record;
- C6, C7 (the netns gate), C10 or C12-C16 is disabled or fails on any of its
  runners for more than one release;
- the LAN waiver it extends lapses or is withdrawn;
- the review-by date passes without renewal.

## 7. Exit conditions before signature

- CI green with C6, C10, C3 over p2p and C12-C16 (carrier_matrix on ubuntu,
  macOS and Windows: C12 network switch with a re-home on the same relay, C13
  silent relay path, C14 direct then reversed, C15 true three-node relay with
  listening nodes, C16 loopback hole punch; C15 and C16 carry the R14 spy),
  and C7 (ubuntu, netns: cone with the R14 stranger and kernel packet
  counters, symmetric, cone-private, swap): **open**. C7 is required green
  for signature. Until then it stays advisory (`continue-on-error`) in the lab
  workflow's `nat-sim-linux` job, and the green streak decides when that ends:
  10 consecutive green iterations of its required cases on the hosted image
  (for example two `workflow_dispatch` runs with `nat_sim_repeat=5`), recorded
  by run id in the job's comment; then `continue-on-error` is deleted. Moving
  the job into `raven-serverless.yml` as a required check is part of the
  owner's flip commit.
- Real rows R3, R5, R9 and R14, run per
  [`P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md`](P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md)
  (true circuits through a relay on a third machine, with
  `wan_two_network_test.sh`'s three-node mode) and recorded under
  `node/proof_artifacts/wan3-<ROW>-<UTC>/`, plus the stage-12 p2p slice:
  **open**. They replace R7b and R8: R3 (two homes behind consumer NAT, the
  forward removed, the relay on a VPS) covers R7b; R5 and R9 (one or both
  sides on a phone hotspot) cover R8; R14 adds the stranger with the card
  (refused by the destination's peer gate before DCUtR runs; the captures and
  their limits are in the checklist). The owner has no VPS yet, which these
  rows need (or another relay both sides can reach). Loopback and netns
  results do not replace these rows
  ([`NAT_SOFTWARE_SIM.md`](NAT_SOFTWARE_SIM.md), "Honest claim").
- Owner decision on hold 3 (independent review or a written waiver, Q1):
  **open**.
- Owner decisions recorded: iOS parity and mobile lifecycle waived ("terminals
  only", 2026-10-08): **decided**; UPnP "ask once at setup" (Q8): **decided**;
  stable PeerId accepted (Q6): **to record**; allow-list default and whether
  open relays stay in scope (Q7, §2): **to record**; two Internet stacks (Q11):
  **open**; soak setup and duration: **open**.
- The disclosure text (§4 item 1, and the `service --relay` PeerId note)
  shipped with the feature in the user docs and command output (Carrier
  Conformance §19.1 item 9).
- The gate-flip change applied as one reviewed commit: the flag; the
  `p2p_gate.rs` tests that assert it stays off (`production_flag_stays_false`,
  `gate_does_not_open_generic_live_enabled`); the spec amendments of §8; and a
  regenerated `docs/PROTOCOL_FREEZE_HASHES_V1.md`.

## 8. Frozen specs that would need amending at the flip

Section numbers and titles checked against the files on 2026-10-08. This draft
edits none of them, and the freeze manifest is not regenerated here.

1. [`protocol/RAVEN_NAT_CONNECTIVITY_V1.md`](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md)
   (its status line, "production disabled", "the isolated Rust experiment
   only", changes too):
   - **§1 Activation boundary.** Today: the `experimental-nat-connectivity`
     feature of `raven-swarm`, the separate
     `raven-swarm-connectivity-experimental` binary and
     `--enable-experimental-nat-connectivity`. Amend: `raven-node` now
     compiles these protocols behind the `p2p-host` Cargo feature and the
     runtime gate `P2P_PRODUCTION_ENABLED` (plus the user's opt-in listener);
     the experimental binary keeps its own rules. "No relay ... address is
     compiled in" stays; "accepted only from the operator for that invocation"
     becomes "from contact cards and the saved policy as well".
   - **§2 Behaviour and transport composition.** Add the Circuit Relay v2
     **server** role, the optional AutoNAT v2 server (today "client only
     (there is no AutoNAT server behaviour)"), Identify
     `/raven/identify/1.0.0` (today `/raven/connectivity/1.0.0`) and the
     payload protocol `/raven/link/1.0.0`. §2.1 (realtime-media boundary) is
     unchanged.
   - **§3 Fixed resource ceilings.** Add the relay-server ceilings of §5. They
     exceed the experiment's budget (established total 32, hard maximum 128;
     `MAX_ESTABLISHED_CONNECTIONS = 128` in `connectivity.rs`) against 256 /
     1024 for the relay, so they need their own table, and the section must
     say which budget the endpoint host uses. "At most eight explicit dial
     addresses and runs for at most one hour per invocation" does not fit a
     long-running service and needs a replacement rule.
   - **§4 Relay selection and address rules.** "One relay multiaddr" becomes
     up to two (`--p2p-relay`, `p2p_relays`, card `via=`), from cards or user
     configuration. The `/p2p-circuit` and terminal-peer rules stay.
   - **§5 Privacy and failure policy.** The logging rule stays (no PeerIds,
     relay / dial / listen addresses, message identifiers, routing tags or
     payloads in logs); add that `raven status` and `raven relay card` show the
     node's own PeerId and addresses on request and `relay_status.json` stores
     them. The sentence "No payload protocol is attached by this profile" sits
     in this section, not in §2: replace it with `/raven/link/1.0.0` carrying
     the Raven Noise link; the authenticate-before-durable-write rule stays.
   - **§6 Production hold.** Add a recorded owner exception naming this
     waiver, the waived iOS-parity and mobile-lifecycle requirements, and what
     stays held.
2. [`protocol/RAVEN_PAIR_INIT_V1.md`](../protocol/RAVEN_PAIR_INIT_V1.md) **§7
   Privacy/carrier and activation gaps.** Its recorded owner exception names
   LAN direct only and says "Every other carrier ... remains disabled". Add p2p
   (direct or circuit) as a confidential carrier under this waiver: PairInit
   rides inside the end-to-end Raven Noise link, never in a relay-readable
   body.
3. [`protocol/RAVEN_TRANSPORT_INTERFACE_V1.md`](../protocol/RAVEN_TRANSPORT_INTERFACE_V1.md)
   **§3 Internet framing (lab-gated).** Add the libp2p variant: stream
   `/raven/link/1.0.0`, prologue `raven/p2p-link/v1`, the same frame, RIH1,
   RLB1 and contact-gate rules, its gate and lab unlock. Two more places in
   the same file go stale: §5 "Discovery (DHT-ready)" (the "NAT / CGNAT /
   DCUtR ... BLOCKED_HARDWARE" note) and §6 "Target libp2p (ADR-0002)" (row
   "Circuit relay / DCUtR: Not complete").
4. [`protocol/RAVEN_CARRIER_CONFORMANCE_V1.md`](../protocol/RAVEN_CARRIER_CONFORMANCE_V1.md):
   - §3.2 "Link classes" and §7.4 "Circuit Relay and DCUtR" need no text
     change; the flip commit records how the carrier maps onto them (§2
     above).
   - §11.4 "Internet direct profile" and §11.5 "Circuit Relay and DCUtR
     profile" are requirement lists to check item by item; §11.4 item 2 is met
     by RIH1, not by the §6 negotiation (§4 item 10). §11.1 "Summary matrix"
     rows stay as they are.
   - The audit rows are in **§18 "Migration and current implementation audit"**,
     not in §11.4-§11.5: "NAT connectivity experiment" (today "currently has
     no endpoint payload/conformance binding") and "`RAVEN_TRANSPORT_INTERFACE_V1`
     `RIH1` and raw framing" (now also used inside libp2p). The per-profile
     blockers of the §19.2 row "Circuit Relay/DCUtR" are answered in §3.2 of
     this record.
5. Also needed, as in the Internet direct record: the umbrella's §9.1
   "Recorded owner exception (2026-10-07)" (it names relay and DCUtR as still
   held) and [`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](../protocol/ATSAM_INDEXED_SESSION_PROFILE_V1.md)
   §7 "Activation and vectors" ("every other carrier, relay, mailbox, and store
   path for this profile stays disabled").
6. [`docs/PROTOCOL_FREEZE_HASHES_V1.md`](PROTOCOL_FREEZE_HASHES_V1.md):
   regenerate with `scripts/freeze_protocol_hashes.sh` in the same commit (CI
   runs it with `--check`); version new identifiers in
   `protocol/PROTOCOL_VERSIONS.md` if the amended specs register them there.

## 9. Phase 2 amendment (DRAFT, unsigned)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** This section amends §2, §4, §5, §6, §7
> and §8 above for Phase 2 of the any-network plan
> ([`design/2026-10-any-network-reachability.md`](design/2026-10-any-network-reachability.md)
> §3, "Phase 2"). It can be signed only together with, or after, the record
> above. Its gates stay `false` until it is signed: `ROUTE_HINTS_PRODUCTION_ENABLED`
> (`node/crates/raven-core/src/route_hints.rs`) and
> `FRIEND_RELAY_PRODUCTION_ENABLED` (`node/crates/raven-core/src/p2p_gate.rs`).
> After signature each is flipped on its own, in its own reviewed commit
> (owner decision "waivers and flips at Phase 2 exit"). Debug builds open them
> with `RAVEN_LAB_ROUTE_HINTS=1` and `RAVEN_LAB_FRIEND_RELAY=1` (the second
> needs the p2p lab unlock `RAVEN_LAB_TEST_A=1`); release builds never read
> either switch.

| | |
|---|---|
| **Amendment ID** | `WAIVER-P2P-RELAY-<date>-P2` (to be assigned on signature) |
| **Covers** | route hints (RRH1 v1, with RELAY_OFFER) on p2p links; the friend relay on user machines, with its AutoNAT v2 server and relay-side UPnP; automatic relay selection; relays on TCP 443; the relay kit, including the Windows logon task; the "nobody reachable" diagnosis as local-only text |
| **Companion** | [`WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md`](WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md) (unsigned): RLX1 in LAN Noise XX message 3, RRH1 on LAN links, LAN_PORT to unverified local contacts, announce dials. Both are signed before either gate flips |
| **Specs** | [`RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md) (RRH1, RLX1, card v3 §9, RELAY_OFFER §11); [`RAVEN_ERROR_CODES_V1.md`](../protocol/RAVEN_ERROR_CODES_V1.md) §2.1 (the diagnosis reason block) |
| **User docs** | `INSTALL_macOS.md`, `INSTALL_Linux.md`, `INSTALL_Windows.md` (section "libp2p: relay and hole punching"); [`RELAY_KIT.md`](RELAY_KIT.md) |
| **Real rows** | [`P2_REAL_ROWS_CHECKLIST.md`](P2_REAL_ROWS_CHECKLIST.md) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-17 |
| **Review by** | the review-by date of the record above |

### 9.1 Scope added (§2)

The carrier, the link protocol, the peers (verified contacts only) and the
peer gate of §2 are unchanged. Added, and only in this combination:

- **Route hints (RRH1 v1) on the p2p link.** One unsigned, one-way control
  frame each way inside `/raven/link/1.0.0`, after both RLB1 offers, only when
  the other side set RIH1 caps bit 8 on this connection
  ([`RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md) §2-§8). It
  carries the sender's PeerId, the relays it holds a reservation on (at most 2
  relays, at most 2 addresses each), up to 4 confirmed global direct
  addresses (none while it hides its IP from the receiver), the custodians it
  listed for the receiver (only while friend custody is live, which this
  amendment does not cover) and up to 2 RELAY_OFFER records (§11). The full
  snapshot goes only to verified, unblocked contacts. A frame lives for its
  TTL (72 h by default; receivers clamp it to 60 s .. 7 days) and a newer
  generation replaces it. Receivers keep it in `learned_routes.json` and use
  it only to reach its sender: never forwarded, never re-sent, never put into
  their own frames or cards. A node whose snapshot changes may open announce
  links that carry only RRH1 to the contacts that sent it RRH1 recently
  (coalesced over 10 s, at most 64 contacts, at most once per contact per
  minute, retried after 1, 10 and 60 minutes; spec §7). RRH1 on Internet
  direct links stays with that carrier's own record
  ([`WAIVER_INTERNET_DIRECT_DRAFT.md`](WAIVER_INTERNET_DIRECT_DRAFT.md)); on LAN
  links with the companion LAN amendment.
- **Card v3 and hide my IP.** Once route hints are live, `raven whoami --card`
  prints `raven-card/3` (spec §9): the PeerId and up to 4 addresses of at most
  2 home relays (`relay=`), no address of the owner; `--compat` prints
  `raven-card/1` or `/2` for older ravens, which refuse `/3` with "update
  raven". `raven node hide-ip on|off` (everyone) and `raven contact hide-ip
  NAME on|off` (one contact) keep this node relayed only towards those
  contacts: no DIRECT entries, circuit-only dials through relays this node
  reserves on itself (never a relay only the contact names), no DCUtR, no
  Identify and no Internet-direct dials (spec §8); LAN links are not affected.
  A card never names a relay picked from a contact's offer (spec §9).
- **The friend relay.** `raven-node service` may relay for the profile's
  contacts as a Circuit Relay v2 server under a relay key of its own, never
  the profile PeerId (`raven-node/src/friend_relay.rs`):
  - its folder `<profile>/friend_relay/` holds no Raven identity, only
    `relay_key.ed25519` (made on first start), its status file and lock;
  - it listens on TCP and QUIC port **7427** (`raven relay offer on --port`
    changes it, never to a port Raven itself uses), and with `--also-443` on
    TCP 443 as well (best effort);
  - limits: `RelayLimits::friends` (the §5 table's defaults);
  - an AutoNAT v2 server behind the dial-back guard of §4 item 11, so two user
    relays can confirm `public` for each other's members;
  - relay-side UPnP: while the profile's UPnP setting is on, the relay asks
    the router to map its own ports (UPnP-IGD, IPv4), as the endpoint does
    for 7423 (§4 item 6);
  - **consent, asked once** (owner decision "relay consent prompt"):
    `raven relay offer on|off`, `raven-node service --relay`
    (`--relay-open` is an alias) or `RAVEN_P2P_RELAY=1`. The question is asked
    once, only on a terminal and only while two independent AutoNAT checks
    confirm this node `public`, at the end of `raven status` or on a bare
    `raven relay offer`; Enter or end of input is no, and the answer is saved.
    A `mapped` node gets a suggestion row instead. Consent is applied live
    (no restart); `offer off` stops the relay within seconds, a start flag
    included (a saved no wins over it), and so does hide my IP for every
    contact, until it is off;
  - **members** = the verified, unblocked contacts the p2p peer gate admits
    (a learned PeerId only once a p2p link proved it) + the profile's manual
    `relay_allow.json` − its deny list (`raven relay deny @contact`) − every
    PeerId of a blocked contact (a block holds over the manual list).
    Circuits run only between members (consent by circle, §2);
  - **the offer**: the relay is offered to each member inside RRH1
    (RELAY_OFFER, spec §11.4: its own key, at most 4 of the addresses it
    names, flags CONFIRMED / AUTONAT / PORT_443), only while it is up with an
    address worth offering, and never to a contact this node hides its IP
    from. `raven relay offer on` refuses while this node hides its IP from
    every contact;
  - **the profile-key relay is retired**: relaying under the profile PeerId
    (Phase 1's `service --relay`) survives only behind the debug switch
    `RAVEN_LAB_P2P_PROFILE_RELAY=1`. §4 item 3 no longer applies to release
    builds.
- **Automatic relay selection** (owner decision "automatic relay choice"; on by
  default inside the gate, `raven relay auto off` to opt out;
  `raven-core/src/relay_select.rs`): up to 2 relays in all, relays set by hand
  first and always; offered relays fill the slots left, only offers from
  verified contacts that arrived inside authenticated links. Sticky: a picked
  relay is replaced after 10 minutes of continuous loss while another path shows
  this node online, or after 2 minutes on probation without a first reservation;
  at most one replacement per 5 minutes; a replaced relay is not taken back for
  30 minutes; a relay that failed its probation here takes no slot back as a
  replacement for 1 hour, doubled with each failure up to 24 hours, and never
  replaces another that failed its own; nothing is replaced while nothing
  shows this node online (for example with no route to the internet): with
  every slot down, raven-node dials the offered relay that would take a slot
  (no reservation, at most once per 10 minutes) as that proof. Dropped at once
  when its offer is withdrawn, two contacts offer one relay key, its operator
  is no longer a verified contact, this node hides its IP from that operator,
  or the relay turns this node away as a non-member (skipped 10 minutes, 6
  hours only for a relay set by hand that nobody offers). Its memory
  (`relay_memory.json`) holds relay PeerIds and times only.
- **Relays on TCP 443.** A relay may listen on further TCP ports with the same
  protocol stack: `raven-node relay --also-tcp <LOCAL[:PUBLIC]>` (at most 2;
  the kit's 443, or 7443 mapped to 443) and `--public-host`, and the friend
  relay's `--also-443`. Two addresses of one relay are one reservation with a
  fallback (owner decision "cards and relay addresses" (c)); card v3 and RRH1
  carry up to 4 relay addresses for at most 2 relays.
- **The relay kit** ([`RELAY_KIT.md`](RELAY_KIT.md)): one command per OS that
  installs `raven-node relay` (its own key, the allow-list, no Raven identity)
  as a service: on Linux a hardened system unit run as the static
  `raven-relay` user with `CAP_NET_BIND_SERVICE` only (for TCP 443); on macOS a
  launchd agent (or daemon) run as the user; on Windows a **per-user logon
  task** (it relays only while the user is signed in and the PC is awake; still
  no SCM service, Q9). The installers refuse a build that holds p2p (exit 3),
  check every port before replacing anything (`raven-node relay --check`), keep
  the PeerId across updates (or roll back), print firewall rules and never
  apply them, and never pass `--open`. `raven relay use via=… via=…` saves a
  kit relay on a contact's node; `raven-node relay-probe` checks a port
  forward from outside with a throwaway key and reserves nothing. SIGTERM (or
  Ctrl-C) stops a relay gracefully: its connections close and reservations end
  at once.
- **The "nobody reachable" diagnosis.** When a p2p dial fails, raven-node adds
  a reason block (`; reach: why=<reason> …`,
  [`RAVEN_ERROR_CODES_V1.md`](../protocol/RAVEN_ERROR_CODES_V1.md) §2.1) to the
  local IPC error, the outbox item and `raven status`; ash turns it into a
  cause and a next step in `raven send`, `raven status` (the `circle` row and
  the NOT REACHABLE NOW section), `raven doctor` and `raven outbox`. The
  diagnosis uses only local facts (no probe of any outside host); with no
  default route it gives `no_route` and never advises a relay, the relay kit,
  a VPS or a port forward. A gateway whose upstream is dead still gives a
  default route, so it is not detected and keeps the relay and NAT reasons. It adds no network behaviour and sends nothing to
  peers, relays or custodians; the reason block and the logs carry no address,
  PeerId, key or name.

Moved out of "Not covered" (§2): route hints inside links, as RRH1 v1 only.
Still not covered: RLB2 hints, vouching (contact-of-contact circuits through a
friend relay; only the RRH1 entry type 0x21 is reserved for it, owner decision
"vouching"), a compiled-in, default or community relay, rendezvous, any DHT,
WebSocket or HTTP-proxy transports on 443 (Phase 4), NAT-PMP and PCP, a
Windows SCM relay service, an aggregate relay bandwidth cap, friend custody
over p2p (Phase 3, its own record) and Swift / iOS.

### 9.2 Residual risks added (§4)

1. **Route hints can be recorded.** RRH1 is deniable (no signature: the link
   authenticates it), not secret from its receiver: a verified contact learns
   this node's relays, confirmed global addresses and stable PeerId and can
   keep them.
2. **Hint lifetime.** A contact may keep using an address it was sent for up to
   the TTL after it changes, or after the user turns hide my IP on: 72 h by
   default, at most 7 days (owner decision "hint lifetime"). The next frame on
   any link withdraws it sooner.
3. **Steering.** A contact can make this node dial relays and global
   addresses it names (a relay's IP address, or what its DNS name resolves
   to, must be global too: never loopback or a local network), bounded by the
   plan size (2 relays, 4 global
   addresses), a dial concurrency of 2, and the rule that a learned PeerId is
   admitted by the peer gate only as a hidden contact (no DCUtR, no Identify)
   until a p2p link proves it. A contact can offer at most 2 relays; whether
   this node ever reserves on one is its own relay choice. The global rule
   covers route hints and every relay named by a DNS name, not an IP literal
   in the contact book: a relay a card names (`via=`, `relay=`), or one set
   with `raven relay use` or `--via`, is dialled at the address it gives,
   loopback or a local network's included. So a card a contact hands over can
   still make this node send fixed handshake bytes (multistream and Noise, or
   a QUIC Initial) to a local host and port on each p2p dial to that contact,
   blind, as before Phase 2. The other way round, a DNS relay name in the
   user's own book or settings that resolves only to a private or CGNAT
   address (split-horizon DNS, a 100.64/10 overlay network) is not dialled
   outside the debug lab, nor is a hide-my-IP circuit through such a relay of
   this node's own (item 4): name such a relay by its IP address. Names and
   literals are held to different rules on purpose (recorded owner decision in
   the Phase 2 review), to be settled before `ROUTE_HINTS_PRODUCTION_ENABLED`
   flips.
4. **Hide my IP has limits.** It stops DIRECT hints, direct dials, DCUtR and
   Identify towards the contacts it names, and it dials them only through
   relays this node reserves on itself, at this node's own addresses for them:
   never a relay only the contact names (the contact may run it), and never an
   address the contact gives for one of this node's relays (it could be the
   contact's own host, which a circuit dials while no connection to the relay
   is up). It does not hide the IP from the relays this node uses, from LAN
   contacts, from a contact that already holds an older snapshot (item 2), or,
   while this node's friend relay is on, from a contact that learns the
   relay's address from a member (item 5).
5. **The friend relay operator's exposure.** Members learn the operator's IP
   address (it is in the offer). The relay sees members' IPs, PeerIds, timing
   and byte counts (the §4 item 1 table, for a relay run on a home machine).
   A member's route hints name the relay's address and PeerId to every
   verified contact of the member that gets its full hints (its card never
   does): that PeerId is the relay key's, not the operator's, but the address
   is the operator's home IP. Such a contact may be one the operator never
   met, or one the operator hides its IP from (a contact both know): the
   operator can neither see nor stop this while it relays (recorded owner
   decision in the Phase 2 review: members re-advertise the relay, which is
   how they reach each other, carrier_matrix C21-C23), and the contact may
   keep the address for the hint lifetime (item 2) after the member stops
   using the relay. What the operator does control: a contact it hides its IP
   from, or has blocked, is no member by itself, so the relay turns it away
   when it uses that address (`raven relay allow` can still admit an
   unblocked one by hand), and `raven relay offer off` or hiding the IP from
   every contact stops the relay. The consent question says that the contacts
   of anyone who uses the relay learn its address, and
   `raven contact hide-ip NAME on` says so while the relay is on.
6. **Circle presence.** Inside a friend relay's circle a member can tell
   whether another member is online (reserved but refused versus not
   reserved), as §4 item 13 says for any circle. Vouching would widen this to
   guests and is deferred.
7. **Relays on user machines sleep and move.** A laptop relay closes its lid,
   a Windows logon-task relay stops at sign-out; selection replaces it only
   after 10 minutes, and messages wait in the outbox meanwhile. A relay that
   moves strands a member that holds only that relay until a link (or an
   announce) carries its new address; a member with a second relay follows
   through route hints.
8. **More public surface on user machines.** The friend relay adds a listener
   on 7427 (and 443 when asked), an AutoNAT v2 server (it dials back global
   addresses a member asks it to probe, one attempt per request, §4 item 11)
   and, with UPnP on, a second router mapping. Selection's timers are guesses
   to re-check in the R13 row.
9. **Kit hosts.** The kit runs a relay on a Pi, a VPS or a desktop: the VPS
   provider sees the relay's traffic metadata, and a home Pi's port forward
   exposes the relay's ports to the whole Internet. TCP 443 does not get
   through networks that inspect TLS (WebSocket over TLS is Phase 4).
10. **Diagnosis texts** tell the local user facts the node already had (for
    example that a contact's relay answered "no reservation", so the contact
    is offline). Nothing new reaches a peer.

### 9.3 Compensating controls added (§5)

- **Route hints:** strict codec with bounded fields (frame 17..4096 bytes,
  RELAY_OFFER at most 519 bytes), receiver rules that drop the whole frame or
  the entry (spec §5, §11.2-§11.3), counts-only `RRH1_MALFORMED` debug logs,
  never a close or a reply. Only pinned, unblocked senders' snapshots are kept
  (an unpinned sender's frame keeps only LAN_PORT, on LAN links). Offers that
  name the sender's own key, the receiver's own key or the receiver's own
  friend relay are dropped; offered IP addresses must be global. Vectors in
  `shared-vectors/rvn1/route_hints/`, fuzz target `rrh1_frame`.
- **Relays never use the profile identity.** The friend relay has its own
  key in its own folder; a dedicated relay holds no Raven identity; the
  profile-key relay is debug-only.
- **Consent and membership fail closed.** No relaying without saved consent
  (or the explicit start flag, which a saved no overrides), none while hide
  my IP is on for every contact; a contact the operator hides its IP from is
  no member by itself; a blocked contact is no member, the manual list
  included (an entry made with `raven relay allow @name` remembers the
  contact, and the block tags an older entry before it forgets the contact's
  learned PeerId); an unreadable contact book keeps the manual list only; an
  unreadable manual list or block list admits nobody; a denied contact stays
  denied.
  An older `raven relay allow|deny` rewrites `relay_allow.json` without its
  deny list, so those contacts are admitted again until denied again (stated
  in the install guides).
- **Selection bounds:** manual relays win; at most 2 relays; offers only from
  verified contacts over authenticated links; the hysteresis above; nothing
  replaced while offline; no relay a hidden operator would see.
- **The kit:** never passes `--open` (CI tripwire in
  `.github/workflows/raven-serverless.yml`); refuses a held build (exit 3), a
  busy or privileged port (exit 4) and a folder that holds a Raven profile or
  a running relay (exit 5); counts-only relay lines (`relay check: …` names
  ports only; `stopped (N connection(s) closed)`); the Linux unit's sandbox
  (`ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`,
  `PrivateTmp=yes`) and caps (`MemoryMax=256M`, `TasksMax=256`,
  `LimitNOFILE=4096`, `IPAccounting=yes`). Fuzz target `relay_inputs` covers
  what a person pastes and what a relay folder holds.
- **Diagnosis:** the reason block is ASCII, at most 120 bytes, without an
  address, PeerId, key or name; an unknown reason is shown as no reason;
  fuzz target `reach_tokens`. Tests check that no send, queue, status,
  doctor, outbox or relay text printed with no route to the internet advises
  a relay offer, the relay kit, a VPS, UPnP, a port forward or an address to
  name (ash `no_route_texts_never_suggest_internet_side_fixes`,
  `w0_replaces_w1_to_w3_and_suppresses_the_upnp_and_relay_prompts`,
  `no_route_relay_and_upnp_rows_advise_nothing_on_the_internet_side`,
  `internet_direct_step_without_a_route_advises_nothing_on_the_internet_side`;
  C35, s48o); help texts and `raven node upnp on`'s description are not
  advice.
- **Gates:** with `ROUTE_HINTS_PRODUCTION_ENABLED` and
  `FRIEND_RELAY_PRODUCTION_ENABLED` false a release build never sends RRH1,
  never sets caps bit 8 or RLX1, never relays for contacts and never picks a
  relay by itself (`FRIEND_RELAY_HOLD:` once); its wire is byte-identical to
  the build before Phase 2 (spec §3.4).

### 9.4 Conditions amended (§6)

In the extension item of §6, "route hints" now reads "route hints beyond
RAVEN_ROUTE_HINTS_V1 v1, or sent to unverified contacts beyond the LAN scope
of the companion LAN amendment", and "a Windows relay service" now reads "a
Windows relay run as an SCM service (the relay kit's per-user logon task is
covered by §9.1)". The amendment also lapses, and both Phase 2 gates MUST be
set back to `false`, if:

- a friend relay runs without the user's consent, or under the profile
  PeerId in a release build;
- a friend relay serves anyone but its members (vouched guests only after
  their own approval);
- automatic selection picks a relay that no verified contact offered (relays
  set by hand excepted), or relay offers are accepted outside authenticated
  links;
- a kit installer ships a relay address or passes `--open`;
- the diagnosis probes an outside host or sends anything to a peer, or a
  reason block or log line carries an address, PeerId, key or name;
- C17-C26 or the fault-matrix scenarios of §9.5 are disabled, or fail on any
  of their runners for more than one release.

### 9.5 Evidence before signature (§7)

All open until recorded; none of it replaces the real rows.

- **carrier_matrix** (`node/crates/raven-node/tests/carrier_matrix.rs`,
  ubuntu, macOS and Windows):
  - C17 LAN port change and old peers (RRH1);
  - C18 a new relay without new cards (card v3, an announce);
  - C19 hide my IP from one contact;
  - C20 a stale hint after the recipient's network change;
  - C21 a friend relay with its own key, picked from its offer, and
    `offer off`;
  - C22 a sleeping relay replaced without new cards, and no thrash after it
    wakes;
  - C23 a relay that moves is followed through RRH1;
  - C24 the kit's relay: listeners, card, fallback address, graceful stop;
  - C25 an installed kit on 443 (the Linux CI install step);
  - C26 every diagnosis reason explained (send, status, doctor, outbox);
  - C35 no route to the internet: LAN only, and no relay, VPS, UPnP or port
    advice (cutoff study F9);
  - C7f the app channel beyond the LAN (RDAP over Raven beyond the LAN, lab
    only; `APP_CHANNEL_PRODUCTION_ENABLED` stays held).
- **lan_fault_matrix** (`scripts/lan_fault_matrix.py`, macOS and Linux):
  s04/s04b/s04c/s04p (`RAVEN_FAULT_HINTS=1`; s04c also with a real pre-RRH1
  build, `RAVEN_FAULT_OLD_BIN`), s39 and s40 (route hints over p2p), s41-s44
  (friend relays), s45-s47 (the kit), s48, s48c, s49 and s48o (the
  diagnosis; s48o with `RAVEN_FAULT_NETWATCH=1`); and s32b-s32e (RDAP over
  Raven beyond the LAN, lab only; APP_CHANNEL stays held).
- **netns** (`node/scripts/netns_nat_dcutr.sh`, Linux, root; advisory until
  each has its green streak): `hints`, `friend`, `friend-sleep`, `only443`
  (with its friend relay run) and `diag`
  ([`NAT_SOFTWARE_SIM.md`](NAT_SOFTWARE_SIM.md)).
- **CI install smoke:** the Linux kit unit on 443 (blocking), the macOS plist
  (blocking) and the Windows logon task settings.
- **Fuzzing:** `rrh1_frame`, `relay_inputs` and `reach_tokens` in the stable
  smoke; a nightly campaign of each is recorded.
- **Vectors and freeze:** `shared-vectors/rvn1/route_hints/`,
  `lan/noise_xx_handshake_002.json`, and
  [`PROTOCOL_FREEZE_HASHES_V1.md`](PROTOCOL_FREEZE_HASHES_V1.md) checked.
- **Real rows** ([`P2_REAL_ROWS_CHECKLIST.md`](P2_REAL_ROWS_CHECKLIST.md),
  results under `node/proof_artifacts/p2-<ROW>-<UTC>/`): R8 (443-only through a
  kit relay), R13 (a friend relay laptop closes its lid, two other
  operators), R3/R5/R9 after a relay change without new cards, R15 (hide my
  IP, packet capture), R16 (LAN listen-port change), R17 (an operator laptop
  moves to another UPnP network), R18 (a Pi with a port forward), R19 (a EUR 5
  VPS), R20 (a Windows logon-task relay, advisory), and the diagnosis rows
  R9-d, R13-d, R-off, R14-d and R-noroute.
- **Owner decisions** of the Phase 2 plan
  (`docs/roadmap/plans/phase2-design.json`, `.review.owner_decisions`)
  recorded at signature. The recommended options are the ones built:
  LAN_PORT to unverified LAN contacts, two gates, a 72 h hint TTL, card v3
  with up to 4 relay addresses for 2 relays, the friend relay on 7427 (+443),
  the consent prompt, the retired profile-key relay, vouching deferred,
  automatic choice on, the UPnP question without "relay for them", the kit
  (TCP 7423 + 443 card pair, `--autonat-server` on, the Windows logon task, a
  dedicated Linux user, exit 3 on held builds, a text card only, the relay
  probe), and this signing order.

### 9.6 Frozen specs at the flips (§8)

On top of §8, in the same flip commits:

1. [`protocol/RAVEN_NAT_CONNECTIVITY_V1.md`](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md)
   §2: the composition gains the friend relay's swarm in `raven-node service`,
   relay-side UPnP and the AutoNAT v2 server on user machines; §4: a relay
   may listen on further TCP ports (for example 443) with the same protocol
   stack, and relays offered by verified contacts inside RRH1 are a relay
   source next to cards and user configuration.
2. [`protocol/RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md):
   its status line (production disabled) and the RRH1 row of
   [`protocol/PROTOCOL_VERSIONS.md`](../protocol/PROTOCOL_VERSIONS.md).
3. `docs/PROTOCOL_FREEZE_HASHES_V1.md` regenerated with
   `scripts/freeze_protocol_hashes.sh` in the same commit.

### 9.7 Signature

Not signed.

## 10. Phase 3 amendment (DRAFT, unsigned)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** This section amends §2 and §6 above
> for Phase 3 item 3 of the any-network plan
> ([`design/2026-10-any-network-reachability.md`](design/2026-10-any-network-reachability.md)
> §3, "Phase 3"): friend custody over the internet. It can be signed only
> together with, or after, the record above and its Phase 2 amendment (§9:
> custody offers and tags ride RRH1), and together with the custody record
> [`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md), which
> holds the custody scope, residual risks and real rows. Its gate,
> `FRIEND_CUSTODY_WAN_ENABLED` (`node/crates/raven-core/src/custody_gate.rs`),
> stays `false` until both are signed, real rows R10 and R10b are recorded and
> `P2P_PRODUCTION_ENABLED` is live; a compile-time tripwire refuses
> `FRIEND_CUSTODY_WAN_ENABLED` without `P2P_PRODUCTION_ENABLED`. Debug builds
> open it with `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_CUSTODY_WAN=1`; release
> builds never read either.

| | |
|---|---|
| **Amendment ID** | `WAIVER-P2P-RELAY-<date>-P3` (to be assigned on signature) |
| **Covers** | RFC1 V1 friend custody frames on `/raven/link/1.0.0` links between verified contacts (direct, hole-punched or relayed) |
| **Companion** | [`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md) (unsigned). The Internet direct draft ([`WAIVER_INTERNET_DIRECT_DRAFT.md`](WAIVER_INTERNET_DIRECT_DRAFT.md)) is unchanged: 7422 stays off and does not carry custody |
| **Specs** | [`RAVEN_FRIEND_CUSTODY_V1.md`](../protocol/RAVEN_FRIEND_CUSTODY_V1.md) §6 (the WAN link rule) and §10 (requester budgets); [`RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md) §12 |
| **Real rows** | [`P3_REAL_ROWS_CHECKLIST.md`](P3_REAL_ROWS_CHECKLIST.md): R10, R10b (R10r optional) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-22 |
| **Review by** | the review-by date of the record above |

### 10.1 Scope added (§2)

The carrier, the link protocol, the peers (verified contacts only) and the
peer gate of §2 are unchanged. Moved from "Not covered" to covered: **RFC1
friend custody on `/raven/link/1.0.0` links**, exactly as the custody record
scopes it (RVNA1 `0x03` messages and sealed ACKs between mutual pinned
contacts; custody offers and tags inside RRH1 only; the user's consent on
both sides). A friend relay and a custodian may run on one node with separate
consents, keys (the relay key on 7427 versus the profile identity), ports and
quotas; a relayed fetch stays inside `RelayLimits::friends` (at most 4 fetch
pages per trigger while the custodian's last path was relayed). The relay kit
can never be a custodian.

Still not covered: the offline mailbox (`--mailbox`), mesh and bridge custody
and `RHW1`, custody beyond RFC1 V1, and everything else §2 and §9.1 list.

### 10.2 Conditions amended (§6)

The extension item of §6 keeps "mesh custody" and adds **"custody beyond
RFC1 V1"**. This amendment also lapses, and `FRIEND_CUSTODY_WAN_ENABLED` MUST
be set back to `false`, if the custody record lapses or is withdrawn, or if
carrier_matrix C32-C34 or the fault-matrix scenarios s30p, s30w and s30r are
disabled or fail on any of their runners for more than one release.

### 10.3 Signature

Not signed.

## 11. Phase 4 amendment (DRAFT, unsigned)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** This section amends §2, §4, §5, §6, §7
> and §8 above for the NAT mapping class and PeerId rotation of Phase 4 of
> the any-network plan
> ([`design/2026-10-any-network-reachability.md`](design/2026-10-any-network-reachability.md)
> §3, "Phase 4"). It can be signed only together with, or after, the record
> above and its Phase 2 amendment (§9): both features ride route hints. Its
> gates stay `false` until it is signed: `NAT_CLASS_PRODUCTION_ENABLED` and
> `PEER_ROTATION_PRODUCTION_ENABLED`
> (`node/crates/raven-core/src/portmap_gate.rs`). After signature each is
> flipped on its own, in its own reviewed commit (owner decision O4-16).
> Debug builds open them with `RAVEN_LAB_NAT_CLASS=1` and
> `RAVEN_LAB_PEER_ROTATION=1`, each with the p2p lab unlock
> `RAVEN_LAB_TEST_A=1`; release builds never read either switch. Rotation stays
> an opt-in privacy setting, off by default, even after its flip (O4-13).

| | |
|---|---|
| **Amendment ID** | `WAIVER-P2P-RELAY-<date>-P4` (to be assigned on signature) |
| **Covers** | NAT_CLASS: the NAT mapping classifier, the RRH1 entry NAT_CLASS (0x22) and the hole-punch skip; PEER_ROTATION: per-epoch libp2p keys, the RRH1 entry PEER_SCHEDULE (0x23), the card field `p2pn=`, the relay schedule text and allow-list expiry |
| **Companions** | [`WAIVER_WSS_PROXY_DRAFT.md`](WAIVER_WSS_PROXY_DRAFT.md) (WSS on 443, HTTPS proxies) and [`WAIVER_PORT_MAP_DRAFT.md`](WAIVER_PORT_MAP_DRAFT.md) (NAT-PMP, PCP, IPv6 pinholes): unsigned drafts, signed and flipped independently of this amendment |
| **Specs** | [`RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md) §13 (NAT_CLASS §13.1, PEER_SCHEDULE §13.2, old peers §13.3; card v3 `p2pn=` §9); [`RAVEN_P2P_PEER_ROTATION_V1.md`](../protocol/RAVEN_P2P_PEER_ROTATION_V1.md) |
| **User docs** | `INSTALL_macOS.md`, `INSTALL_Linux.md`, `INSTALL_Windows.md` (section "libp2p: relay and hole punching"); [`RELAY_KIT.md`](RELAY_KIT.md) (relay schedules) |
| **Real rows** | [`P4_REAL_ROWS_CHECKLIST.md`](P4_REAL_ROWS_CHECKLIST.md): R25 and R26 (NAT class), R27 (rotation); the plan names them R15-R17, which Phase 2 already holds |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-22 |
| **Review by** | the review-by date of the record above |

### 11.1 Scope added (§2)

The carrier, the link protocol, the peers (verified contacts only), the peer
gate and route hints of §2 and §9 are unchanged. Added, and only in this
combination:

- **NAT mapping class (NAT_CLASS).** The node classifies its own IPv4 and
  IPv6 mappings, separately for TCP and QUIC, as `no_nat`,
  `stable_kept`, `stable_shifted`, `varies` or `unknown`, from Identify observations only:
  on direct, non-relayed, non-WSS outbound connections that reused the listen
  port, reported by its own relays or its contacts, and only from 2 observers
  on different /24 (IPv4) or /48 (IPv6) networks (owner decision O4-12).
  Observations expire, and a network change starts over. The class travels
  to verified contacts in the RRH1 entry NAT_CLASS (type 0x22, 5 bytes: four
  codes and two flags), never to a contact this node hides its IP from, and
  is kept only from a pinned sender whose P2P_ID passed. A malformed entry is
  dropped alone; the frame stays.
- **Hole-punch skip.** DCUtR is not attempted with a contact when both
  sides' IPv4 mappings vary and they share no global IPv6, or after 2 failed
  punches on the current network (a 6 h hold). The connection stays relayed;
  nothing else changes. No port prediction (D13).
- **PeerId rotation (PEER_ROTATION).** With `raven node p2p rotate on`
  (`node_policy.json` `peer_rotation`, off by default) the libp2p key changes
  every epoch: 28 days with a secret per-profile phase, the key of epoch `e`
  derived from the Raven seed (RAVEN_P2P_PEER_ROTATION_V1 §2-§3); the
  Raven identity, device keys and every relay's own key do not rotate. The
  node starts only when every pinned contact with a p2p route announced
  `capable` (`waiting` until then), announces the coming PeerIds for at
  least half an epoch first (`starting`), then re-homes at each boundary
  (`on`), and rolls back when every relay it held refuses the new ID
  (`postponed`, retried after 6 h at most).
- **What contacts learn.** While the gate is live every node sends the RRH1
  entry PEER_SCHEDULE (type 0x23): `capable` always; a rotating node adds its
  schedule (the previous epoch and 6 ahead, at most 8 PeerIds with their
  public keys), its epoch length and its active epoch. A rotating node's
  cards carry `p2pn=` (the next epoch's PeerId) right after `p2p=`. A
  receiver keeps a pinned contact's schedule in `peer_schedules.json` under
  the contact key; its peer gate and friend relay admit the contact's
  scheduled PeerIds around the contact's clock, and its dialler tries at most
  2 of them.
- **Relays that are not contacts.** `raven relay schedule` prints one line
  (`raven-relay-schedule/1`, up to 13 epochs, default 7, about 6 months) for a
  dedicated relay's operator; `raven relay allow --schedule <FILE|->` (also
  `raven-relay allow --schedule -`) adds each PeerId to `relay_allow.json`
  with an `expires_ms` a week after the latest end of its epoch. The file stays
  version 1, and an older relay ignores the field.
- **State at rest** (privacy rule): `peer_schedules.json` (RMS1 kind 66) and
  `peer_rotation_state.json` (kind 67, only when rotation became ready) are
  sealed in a sealed profile, owner only, under locks of their own, and
  registered in the file registry and the inventory of
  `docs/design/2026-10-at-rest-metadata.md`; `expires_ms` lives inside the
  already sealed `relay_allow.json`. Which key is in use and a rollback stay in
  memory.

Not covered: rotation on by default, epochs other than 28 days outside a debug
lab build, rotating the Raven identity or a relay's key, port prediction, a
NAT class sent to anyone but verified contacts, and any schedule exchange
outside authenticated links (a relay schedule is pasted by its operator).

### 11.2 Residual risks added (§4)

1. **A wrong skip.** A contact or relay that lies about an observed port can
   force `varies` and so remove hole punching with this node until the next
   re-home; relays still deliver. With one relay (the common case) the class
   stays unknown and only the "two failures" rule skips.
2. **Rotation churn.** One re-home per epoch: seconds without reachability,
   new reservations, AutoNAT starting over.
3. **Residual linkability.** Relays can still link an old and a new PeerId by
   timing and IP, and contacts see every PeerId by design. Rotation protects
   against strangers who learned a PeerId once (an old card, a scanner on a
   mapped or pinholed port, an intercepting proxy: the WSS draft's risk 1),
   not against relays or contacts.
4. **Contacts that cannot follow.** A contact that never updates keeps
   rotation `waiting` indefinitely. A contact offline for the whole announcing
   period, silent for more than 6 epochs, or holding a card older than 2
   epochs cannot reach the node over p2p until a route hint reaches it another
   way (LAN, Internet direct) or a new card is exchanged.
5. **Dedicated relays** need a fresh `raven relay schedule` about every 6
   months; until then they refuse the new ID and the node stays `postponed`.
   A relay computes expiry with its own epoch length, so a lab relay must run
   with the profile's lab epoch length.
6. **Wrong clocks.** Epochs are a function of wall time; a contact whose clock
   is off by days dials a future or past PeerId. The dial falls back to the
   hint's active epoch, but a large skew with no recent hint fails until the
   next link.
7. **Known gaps (for the review):** a relay that drops the current key in the
   middle of an epoch (not at a rotation) is not rolled back, the slot only
   retries; the hints offer refusal (`LinkKeys.local_p2p`) still names the
   fixed key.

### 11.3 Compensating controls added (§5)

- Both entries are checked on their own and dropped alone when malformed;
  NAT_CLASS and PEER_SCHEDULE are kept only from pinned senders (fuzz target
  `rrh1_phase4_tlvs`; negative vectors `route_hints/negative/rrh1_nat_class_*`
  and `rrh1_peer_schedule_*`).
- With either gate closed a node sends neither entry, uses the fixed key and
  prints no `p2pn=`: its bytes are Phase 2's. Reading a schedule, a relay
  schedule text or a `p2pn=` is harmless with the gate closed.
- Schedules are keyed by the authenticated contact key, never by a PeerId;
  every scheduled key is checked (a canonical, non-small-order Ed25519
  point); at most 8 entries per contact and 1024 contacts; entries behind the
  contact's clock are dropped; a block, a deny or a contact's removal forgets
  them.
- Logs say only that the ID rotated, was postponed or waits on a count of
  contacts, and that a punch was skipped; IPC status names only the PeerId of
  the key in use. No log line names a PeerId (C46, s53).
- The relay schedule text is parsed strictly (fuzz target
  `relay_schedule_text`, vectors `p2p/relay_schedule_text_001.json`); an
  allow-list entry never expires early, and expired entries are dropped.
- The rollback keeps a node reachable through relays that refuse the new ID.

### 11.4 Conditions amended (§6)

The amendment also lapses, and both Phase 4 gates MUST be set back to `false`,
if:

- rotation is turned on by default, or starts while a pinned p2p contact has
  not announced `capable`;
- a NAT class is sent to an unverified contact or one this node hides its IP
  from, or accepted from an unpinned sender; punches are skipped beyond the
  two rules of §11.1, or port prediction is added;
- a log line or IPC field names a PeerId other than the one in use, or a
  schedule is stored unsealed or keyed by a PeerId;
- the Raven identity, a device key or a relay's own key starts rotating
  under this record;
- C45, C46 or s53 is disabled, or fails on any of its runners for more than
  one release.

### 11.5 Evidence before signature (§7)

All open until recorded; none of it replaces the real rows.

- **carrier_matrix** (`--ignored`, ubuntu, macOS and Windows): C45 hopeless
  hole punches are skipped and stay relayed (with the control case that still
  punches); C46 PeerId rotation follows contacts and relays (a dedicated relay
  with the schedule installed, the postponement when its entries are removed,
  a contact without the capability keeping rotation `waiting`, no PeerId in
  any log).
- **lan_fault_matrix** (`RAVEN_FAULT_P2P=1 RAVEN_FAULT_ROTATION=1`): s53
  `rotation_boundary_with_queued_messages`.
- **netns** (`node/scripts/netns_nat_dcutr.sh`, advisory until each has its
  green streak): `classify` (cone, shifted, symmetric) and `punch-skip`.
- **Vectors and freeze:** `shared-vectors/rvn1/p2p/epoch_peer_id_001.json`,
  `epoch_phase_001.json`, `relay_schedule_text_001.json`,
  `card_p2pn_001.json`, the route hint vectors and negatives above, and
  [`PROTOCOL_FREEZE_HASHES_V1.md`](PROTOCOL_FREEZE_HASHES_V1.md) checked.
- **Real rows** ([`P4_REAL_ROWS_CHECKLIST.md`](P4_REAL_ROWS_CHECKLIST.md),
  results under `node/proof_artifacts/p4-<ROW>-<UTC>/`): R25 (the classifier
  on real networks: a home line, a phone hotspot, a SIM dongle, with two relays
  on different /24s), R26 (both laptops on different hotspots: no DCUtR
  attempt after the skip, relayed 10/10), R27 (rotation across a
  lab-shortened epoch with a dedicated relay holding the schedule and a
  friend relay: delivery continues, the status shows the new ID).
- **Owner decisions** recorded at signature (the recommended options are the
  ones built): O4-12 (classifier inputs and the two skip rules), O4-13
  (rotation opt-in, 28-day epochs, previous + 6 ahead, starts only when every
  contact is capable, automatic rollback, relay schedules about every 6
  months), O4-14 (the RRH1 ranges and card v3 room, recorded with the Phase 2
  amendment), O4-16 (three drafts; each gate flips on its own).

### 11.6 Frozen specs at the flips (§8)

On top of §8 and §9.6, in the same flip commits:

1. [`protocol/RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md)
   §13 and its PROTOCOL_VERSIONS row (the Phase 4 entries' gates);
   [`protocol/RAVEN_P2P_PEER_ROTATION_V1.md`](../protocol/RAVEN_P2P_PEER_ROTATION_V1.md)
   status line and §10, and its PROTOCOL_VERSIONS row.
2. [`protocol/RAVEN_NAT_CONNECTIVITY_V1.md`](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md)
   §5: a node's PeerId may change every epoch, and a node may decline DCUtR
   with a contact by the two rules above.
3. `docs/PROTOCOL_FREEZE_HASHES_V1.md` regenerated with
   `scripts/freeze_protocol_hashes.sh` in the same commit.

### 11.7 Signature

Not signed.
