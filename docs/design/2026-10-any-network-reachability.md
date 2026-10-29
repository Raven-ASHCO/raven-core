# Raven reachability plan: anyone, on any network, plus offline mesh

Date: 2026-10-15. Status: recommendation for the owner to decide on. Sources: five approach designs (A to E), three reviews of them, and read-only checks in the Raven tree of that date (`feature/reliability-and-mesh`). All effort figures are guesses; nothing has been measured.

---

## 0. Checked facts that shape this plan

1. **Today only LAN works for users, and it needs manual setup.**
   - Only `LAN_DIRECT_PRODUCTION_ENABLED` is true. `INTERNET_DIRECT_PRODUCTION_ENABLED`, `P2P_PRODUCTION_ENABLED`, `FRIEND_CUSTODY_PRODUCTION_ENABLED` and `FRIEND_CUSTODY_WAN_ENABLED` are false (`raven-core/src/*_gate.rs`).
   - The installers bind LAN to `127.0.0.1:7420` unless `RAVEN_LAN_LISTEN` is set (`node/scripts/install/macos_launchd.sh:42`).
   - There is no local discovery.
2. **Today's "relay" success did not use a relay circuit.** `Host::connect` returns at once if any connection to the peer already exists (`raven-node/src/p2p.rs:776-779`). So "Mac Studio -> laptop" rode the laptop's own outbound reservation connection. That is called connection reversal. A real A -> relay -> B circuit has only been shown on loopback (C6) and in network namespaces (C7).
3. **The laptop could never hole-punch.** `--p2p-listen relay` opens no listener (`raven-core/src/p2p_route.rs:388-405`). Without a listener, DCUtR (libp2p's hole punching) cannot work.
4. **Privacy hole in today's libp2p (P3) host.**
   - The endpoint has no PeerId gate (`raven-swarm/src/host.rs:1011-1022`).
   - When anyone opens a relayed connection to a node, libp2p-dcutr 0.15 sends that node's observed addresses right away. It then dials whatever addresses the other side sends back (`behaviour.rs:180-187`, `:303-310`, `PeerCondition::Always`).
   - All of this runs before the Raven contact gate. Relays only rate-limit circuit sources (`host.rs:541`).
   - So anyone holding your card (`p2p=` plus `via=`) can learn your current IP.
   - This must be fixed before P2P is turned on.
5. **Smaller corrections.**
   - Cards are not signed. They are only checked for self-consistency (`ash/src/cli.rs` ~1440).
   - About 10 strings say "UPnP/NAT-PMP", but only UPnP-IGD over IPv4 exists.
   - `nat_verdict` reports "public" if any single AutoNAT result says so (`p2p.rs:658-666`).
   - No endpoint runs an AutoNAT server, so status shows "unknown".
   - `BootstrapConfig.use_raven_defaults` defaults to true (`raven-core/src/bootstrap.rs:30-38`).
   - No network-change code exists in this worktree yet. Phase 0 is being written elsewhere and must be merged here first.
6. **Useful fact.** Many home lines have a public IPv4 address, not carrier NAT (the test line did). One port forward, or a UPnP-capable router, therefore makes such a home computer a reachable node for a whole circle of friends.

---

## 1. The short answer

**What will work after this plan:**
- **Same network, no internet needed.** Two laptops talk with no setup when they share any network: the same Wi-Fi or router, one laptop's or phone's hotspot, or a cable.
- **Over the internet, any mix of networks.** Home Wi-Fi, carrier NAT, a phone hotspot and a SIM modem all work. The connection is direct when the networks allow it, and goes through a relay otherwise. Raven picks the path, reacts to network changes and remembers what worked, so nobody types addresses or forwards ports.

**The hard limit no software can remove.** When neither person's machine can accept incoming connections, a third machine must exist that the internet can reach, and it must be online. That covers most laptops on hotspots, SIM internet, carrier NAT, or a home router without port mapping. The third machine can be:
- a friend's always-on computer with a public IP, port forward, UPnP or open IPv6; or
- a small relay someone in the circle runs: a Pi at home with a port forward, or a cheap VPS.

That machine only passes encrypted bytes and never sees messages. So "server=none" (no central message server) still holds, but honestly it is a helper server.

**The same kind of limit applies elsewhere:**
- Delivering to someone offline after the sender has also gone offline needs a friend's machine to hold the message.
- Networks that allow only TCP 443 need a relay on port 443.
- With no internet, laptops talk only if they share some network link. A Bluetooth-only mesh does not exist and is a later, expensive phase.
- Messages waiting longer than 24 hours expire until long-lived sessions are built.

---

## 2. Recommended architecture

**In one line:** friends first, direct when possible, a user-run relay as the safety net, and the local network when offline.

**What it is built from:**
- Approach A (friends are the infrastructure) as the backbone.
- The cheap core of D (direct first).
- Tier A of E (local network without internet).
- C (community relays) cut down to the relay a user runs themselves.

**Left out:**
- B, the public DHT.
- C's project-run default relays and signed directory. The owner can add an opt-in list later (decision D1).
- D's port prediction.
- E's Bluetooth carrier, for now.

### 2.1 One identity, one outbox, many pipes

Every path uses the same parts:
- the pinned Raven key;
- the same Raven Noise link (RIH1 identity bind and RLB1). `RavenLink` in `raven-node/src/internet_direct.rs` works over any byte stream;
- the same sessions;
- the same outbox, which resends the exact bytes and expires them after 24 h.

A new carrier is just a new pipe. Relays and custodians only ever see `libp2p-Noise(Raven-Noise(...))`.

### 2.2 Components

| # | Component | What it does | Built on (existing code) | Phase |
|---|---|---|---|---|
| C1 | Network watcher | Detects interface or address change, default-route change, wake from sleep, and relay ping loss. Then it closes stale connections, reserves relays again, re-runs UPnP and AutoNAT, and kicks the outbox and custody. | `if-watch` (already in Cargo.lock), relay-slot backoff `p2p.rs:585-640`, outbox `listener_up` hook | 0 |
| C2 | Planner with carrier memory | Remembers per contact the last route that delivered and on which network. Tries it first and drops stale direct routes after a network change. | `plan_object_routes` (`raven-core/src/outbox.rs:1127`), `lan_seen.rs` pattern | 0 |
| C3 | Safe libp2p endpoint | Always listens. A **peer gate** admits only pinned contacts, its own relays and AutoNAT dial-backs. Feeds IPv6, mapped and raw observed addresses to DCUtR. Uses existing connections first (connection reversal). | `build_endpoint_swarm` (`host.rs:1042-1121`), `DialBackGuard` (`host.rs:874-950`), `prefer_direct` | 1 |
| C4 | Reachability self-check | UPnP (ask once). AutoNAT v2 from 2 or more independent friends. Later, a NAT type check. Results appear in `raven status` and `raven doctor`. | AutoNAT v2 client and server, UPnP events (`p2p.rs:1028-1069`) | 1-2 |
| C5 | Route hints (RRH1) | A small frame sent inside every authenticated link: my relay circuits, confirmed direct addresses, a LAN hint, custodians, a generation number and an expiry. Kept in a learned-routes cache. Cards shrink to the PeerId plus home relays. | `lan_seen.rs`, `outbox.rs` `with_learned_lan_routes` | 2 |
| C6 | Relay role | A reachable node relays for its verified contacts. It uses its own relay key and never the user's profile PeerId. It also runs an AutoNAT server behind DialBackGuard. A user-run relay can listen on TCP 7423 and 443. | `raven-node relay` (`relay.rs`, `relay_key.ed25519`), `RelayLimits::friends`, `RelayGuard` | 2 |
| C7 | Relay selection | Picks up to 2 relays from friends' offers. Keeps them across network changes and changes them only after sustained failure. Announces changes through RRH1. | Relay slots (`p2p.rs`), `MAX_VIA = 2` | 2 |
| C8 | Local network fix | LAN listens on all interfaces behind the contact gate. A contact-only beacon (rotating token, no Raven marker) finds contacts. Keeps the IPv6 link-local scope. | `lan_direct.rs`, `lan_seen.rs`, Private Rendezvous R2 rules. Built: `raven-core/src/lan_gate.rs`, `lan_beacon.rs`, `raven-node/src/lan_ifaces.rs`; spec [`RAVEN_LAN_BEACON_V1.md`](../../protocol/RAVEN_LAN_BEACON_V1.md); tests C27-C30, s04, s80-s84 | 3 |
| C9 | Offline delivery | Friend custody over the internet, plus proactive re-pair before sessions expire. | `friend_custody.rs`, `custody_client.rs`, `raven-node/src/custody.rs` (lab-proven s30). Built: `raven-core/src/custody_home.rs`, `session_renewal.rs`, `raven-node/src/renewal.rs`; specs [`RAVEN_FRIEND_CUSTODY_V1.md`](../../protocol/RAVEN_FRIEND_CUSTODY_V1.md) §10, [`RAVEN_ROUTE_HINTS_V1.md`](../../protocol/RAVEN_ROUTE_HINTS_V1.md) §12; tests C31-C34, s30p/s30w/s30r, s85, s85b | 3 |
| C10 | Diagnosis | Status shows the path class (direct, reversed, relayed, hole-punched), relay health, and a plain "what to do" line. | `raven status`, existing NOT SENT / "stays queued" texts | 1-2 |

### 2.3 Dial plan for each message

Two attempts may run at once; dial concurrency 2 already exists.

1. An existing connection to the contact (connection reversal).
2. The route that last delivered to this contact, if still valid on this network (carrier memory).
3. LAN: an address learned from the beacon or the last authenticated link.
4. Direct global IPv6, then direct IPv4: public, UPnP-mapped, or from RRH1.
5. A circuit through the recipient's relay (`/R/p2p-circuit/p2p/B`). DCUtR then tries to upgrade to direct, and the Raven link moves onto the direct connection.
6. If the recipient is still unreachable after about 60 s and a shared custodian exists, deposit with the custodian. The outbox keeps retrying either way.
7. At 24 h the message expires and is clearly marked not delivered.

### 2.4 Privacy rules

These are preconditions, not options.

- **Peer gate first.** Neither DCUtR nor Identify ever talks to a PeerId that is not a pinned contact or one of the node's own relays. DCUtR dial targets are filtered to global addresses only.
- **Relays use their own key.** If a friend relayed under its profile PeerId (`service --relay` today), the friend's Raven-linkable identity and home IP would appear in every card of every person it relays for.
- **Route hints stay private.**
  - They travel only inside authenticated links.
  - They are authenticated by the Noise channel, not identity-signed records. That makes them deniable rather than transferable proof of where you were.
  - Never reuse `PeerRecord`, and never use a public DHT.
- **IP addresses go only to verified contacts.** A global and per-contact "hide my IP" switch keeps traffic relayed only.
- **No automatic jump to strangers' infrastructure.** Moving from friend relays to a VPS, or to a community relay, is an explicit user choice. This is required by Private Rendezvous §5.
- **Logs stay counts-only.** `use_raven_defaults` defaults to false.
- **At rest (the privacy pack).** What a profile stores on disk and how the privacy pack seals it: [`2026-10-at-rest-metadata.md`](2026-10-at-rest-metadata.md). The pack changes no wire byte and no route of this plan. On disk, the addresses it learns for a friend (sightings and RRH1 learned routes) are sealed and forgotten after 30 days without contact, while an address the user saved stays (sealed) until the user forgets it; outbox routes, relay memory and the friend relay's status and key are sealed; the relay multiaddrs in `node_policy.json` move to a sealed sidecar, `node_policy_peers.rms`; and a custodian deletes a released object at once (behind the custody gate). The user's text is [`SAFETY_OFFLINE.md`](../SAFETY_OFFLINE.md) sections 5-8, the threat rows T3a-T4 are [`THREAT_MODEL.md`](../THREAT_MODEL.md) §3.7a, and the owner-run real row R34 is [`PRIVACY_PACK_REAL_ROWS_R34_CHECKLIST.md`](../PRIVACY_PACK_REAL_ROWS_R34_CHECKLIST.md).

### 2.5 How a message travels in each of the 11 cases

"Reachable node" means a friend relay, a user-run relay, or the other party being reachable.

| Case | Path | Needs a reachable third node? | After the plan | Today |
|---|---|---|---|---|
| (1) Same LAN | LAN direct to the beacon-learned or last-seen address. If the Wi-Fi isolates clients (guest or hotel), it falls back to the internet path as in (3)-(9). | No | **Yes, zero setup** (Phase 3) | Works only with a hand-set address; breaks when the port changes (s04) |
| (2) Home router with UPnP / NAT-PMP / PCP | The node maps 7423 (asked once). At least 2 friends confirm it is public. Contacts dial it directly, and it can relay for friends. | No: it *is* the reachable node | **Yes** for UPnP-IGD routers. NAT-PMP-only or PCP-only routers behave like (3) until Phase 4. | Gated off |
| (3) Home router without mapping | The node reserves on a reachable node. The sender opens a circuit, and DCUtR usually upgrades to direct on home NATs, now that the node always listens. | Yes | **Usually** (yes when the circle has a reachable node; no otherwise) | Only with a manual port forward |
| (4) Carrier-grade NAT | Same as (3). Direct IPv6 if the ISP provides it. DCUtR success depends on how the carrier NAT behaves. | Yes | **Usually**, often relayed | No |
| (5) Phone hotspot | Same as (3). The laptop reserves again after every hotspot reconnect (Phase 0). The connection mostly stays relayed. | Yes | **Usually**, relayed | Worked only by reversal to the port-forwarded Mac Studio |
| (6) SIM / LTE / 5G modem | Like (5). An APN with a public IP behaves like (2). | Yes, mostly | **Usually**, relayed | No |
| (7) IPv6 available | Direct over IPv6 if inbound is allowed. Behind a firewall, the relay coordinates a simultaneous open. Both sides need IPv6. | Only behind a firewall (to coordinate) | **Usually** | No: IPv6 is never offered as a candidate today |
| (8) Only TCP 443 open | Only a relay listening on TCP 443 (Phase 2). WSS and HTTP proxy support come in Phase 4. Deep packet inspection and censorship are out of scope. | Yes, on 443 | **Sometimes**; usually after Phase 4 | No |
| (9) Both behind (4)/(5) | A circuit through the recipient's relay. Direct upgrade is rare. Circuit limits of 2 MiB and 5 min are fine for text. | **Yes, mandatory** | **Usually** if the circle has an always-on reachable node; **no** otherwise | No |
| (10) One party offline | The sender's outbox retries for up to 24 h. If the sender also leaves, a mutual friend holds the message, and the recipient fetches it on return. Phase 5a (lab only): past 24 h the message is parked until a deadline 7 days after it was written; when the recipient is back, the sender's node sets up a new session and sends it again under the same message id. Phase 5b (designed): a sealed letter left with a mutual friend covers "both left". | The custodian must be reachable by both | **Usually within 24 h**; up to 7 days while the sender's node stays up once 5a is enabled ([`2026-10-beyond-24h.md`](2026-10-beyond-24h.md)) | LAN retry only; custody is lab-only; 5a is lab-only |
| (11) No internet, laptops near each other | LAN direct over any shared link (Wi-Fi with no uplink, a hotspot, a cable) plus the beacon. One custody hop through a friend. Bluetooth comes later. | No | **Yes on a shared IP link; no on radio only** | Only with a hand-typed address |

**What the user should see when a path is missing** (C10, built in Phase 2 item 5). When a p2p dial fails, raven-node attaches a reason from local facts only (`contact_offline`, `relay_asleep`, `relay_refused`, `relay_off`, `relay_busy`, `not_admitted`, `both_nat`, `no_relay`, `direct_failed`, `no_route`: [`protocol/RAVEN_ERROR_CODES_V1.md`](../../protocol/RAVEN_ERROR_CODES_V1.md) §2.1), and ash words the cause and one next step in `raven send`, `raven status` (the `circle` row, the `what to do` row and the NOT REACHABLE NOW section), `raven doctor` and `raven outbox`. The fixes it names, in order of what the circle allows:
- ask a contact whose computer can be reached from the internet to offer relaying (`raven relay offer on` on that computer);
- run the relay kit ([`docs/RELAY_KIT.md`](../RELAY_KIT.md)) on a Pi with a forwarded port or a small VPS;
- turn on UPnP (`raven node upnp on`) or forward port 7423, TCP and UDP.

With no default route (`no_route`) none of these is offered: only people on the same network (Wi-Fi, hotspot or cable) can be reached, and the text says so. This is a local fact only (nothing probes an outside host): a hotspot or router whose upstream is dead still hands out a default route, so there the relay and NAT reasons and their advice stay.

---

## 3. Phased roadmap

| Phase | Goal | Size (guess) | Gate / waiver |
|---|---|---|---|
| 0 | Survive network changes (in progress) | in progress | No gate change |
| 1 | Correct and safe internet path | 10-15 d | Sign `WAIVER_P2P_RELAY`, then flip `P2P_PRODUCTION_ENABLED` |
| 2 | Contacts find each other; friends become the infrastructure | 15-25 d | Sign the Phase 2 amendments (P2P waiver §9, LAN route-hints amendment), then flip `ROUTE_HINTS` and `FRIEND_RELAY` separately |
| 3 | Local network and offline | 12-20 d | Amend the LAN waiver; custody waiver for both custody flags; R2 approval |
| 4 | Harder networks, only where real tests show the need | 20-35 d (+15-25 for community relays) | New waiver per transport or default relay |
| 5 | Later | 60 d+ | New gates |

### Phase 0: survive network changes (being fixed now)

**Deliverables:**
- **Network watcher (C1).** Uses `if-watch` events plus a periodic default-route poll. Detects wake from sleep (the wall clock jumps relative to the monotonic clock) and relay ping loss (15 s interval, 5 s timeout, `host.rs:990-991`).
- **Reaction.**
  - Close dead connections.
  - Reset relay backoff and reserve again on the *same* relays.
  - Re-run UPnP. libp2p-upnp searches for the gateway only once per process, so the behaviour must be recreated.
  - Re-run AutoNAT.
  - Kick the outbox and the custody fetcher.
  - Reset each contact's retry backoff, so queued messages do not wait up to the 10 min `RETRY_MAX` (`outbox.rs:1162`).
- **Route rotation.** A failed route moves to the next one at once, and direct routes learned on the old network are dropped.
- **Carrier choice.** Make the `--carrier auto` order explicit. Add carrier memory per contact, keyed by a network fingerprint (C2).

**Reused code:** `p2p.rs` relay slots and backoff; the outbox worker (`raven-node/src/outbox.rs`); `lan_seen.rs`.

**Tests:**
- Unit: backoff reset, memory ordering, network fingerprint.
- Harness: a netns step that swaps a node's uplink mid-test (extend `netns_nat_dcutr.sh`), and a fault-matrix scenario "network switch with queued messages".
- Real: row R12 (below).

**Gate:** none flipped. The LAN behaviour stays under the existing LAN waiver; the p2p parts stay lab-only.

**Status (2026-10-15, Phase 0 gap steps + Phase 0b):**
- **Done, watcher (C1):** `raven-node/src/netwatch.rs`: if-watch events, a wake-from-sleep clock (release builds too, one sentence in the P2a amendment draft), the default-route reading while a p2p host runs or route memory is live, and the p2p host's every-relay-silent hint.
- **Done, reaction:** the outbox and custody are due at once on a fresh backoff; the p2p host re-homes (a fresh endpoint on the same relays: new UPnP search, new AutoNAT client, DCUtR / Identify state emptied, reservations again at once from a new local port, UPnP mapping removal best effort); networks only added just retry idle relay slots; a silent relay path re-homes without a backoff restart. Route rotation (G3) and carrier memory per network tag (G2, lab-only) are in.
- **Evidence:** carrier_matrix C11 (outbox on a lab network change), C12 (switch: re-reserved on the same relay in < 15 s, 3 queued p2p messages exactly once, then a wake round) and C13 (silent relay path: path loss, no backoff restart) on the three CI OSes; fault matrix s33 and s34 / s34c (`RAVEN_FAULT_NETWATCH=1`: 5 queued messages to 2 contacts delivered within 30 s of the switch, against the backoff-only control); the `netns_nat_dcutr.sh` `swap` run (a real uplink swap behind a second NAT router, Linux, advisory CI).
- **Done, lab-only (0b step 6):** a learned LAN route (`lan_seen.rs`) whose address is on none of the networks netwatch last settled on is not dialled while route memory is live; saved routes always are.
- **Open:** the owner-run row R12.

**Exit:** after Wi-Fi <-> hotspot switches, queued messages go out without user action. Target is about 30 s (guess).

### Phase 1: correct and safe internet path

All of this stays inside the existing `WAIVER_P2P_RELAY_DRAFT` scope.

**Deliverables:**
1. **Peer gate.** A small behaviour placed first in `EndpointBehaviour` that denies connections from PeerIds that are not pinned contacts, its own relays, or AutoNAT dial-backs. Also a global-only filter on DCUtR dial targets. A test must prove the denial happens before the DCUtR handler is created.
2. **Always listen** on 7423 TCP and QUIC, IPv4 and IPv6. `--p2p-listen relay` becomes test-only, with a warning.
3. **Candidate injector.** Feeds own global IPv6, UPnP-mapped and raw observed addresses to DCUtR. This works around libp2p-identify 0.48 rewriting observed ports, which is inferred from the code and must be checked in C7.
4. **Deliberate connection reversal and path labels.** Label every delivery as direct, reversed, relayed or hole-punched, so tests can tell them apart. Today they cannot.
5. **`nat_verdict`** says "public" only when at least 2 independent servers agree.
6. **Cleanup.** Fix the about 10 "NAT-PMP" strings. Set `use_raven_defaults=false`. Refresh the stale `docs/network/raven-swarm-connectivity-matrix.md` and line 61 of `docs/SERVERLESS_MODEL.md`.
7. **`raven status` / `raven doctor`.** Show the reachability class, relay health, and a "what to do" line.
8. **`wan_two_network_test.sh`: true 3-node mode.** The sender is not the relay and has no prior connection to the recipient.

**Reused code:** `build_endpoint_swarm`, `DialBackGuard`, `p2p.rs` dial/connect/`prefer_direct`, `relay.rs`, `carrier_matrix` C6, and `netns_nat_dcutr.sh` (C7).

**Tests:**
- Unit: the peer gate allows and denies correctly.
- A stranger opening a circuit is denied, and no candidates are sent. carrier_matrix C15 and C16 prove this from inside the circuit with an in-process spy. As a stranger, the spy gets no Identify and no DCUtR, and dials nothing. As a pinned contact (the positive control), it gets circuit addresses only in C15 and is offered B's loopback candidate in C16. A packet capture cannot show what was sent, because DCUtR is encrypted end to end. C6 keeps its stranger cases at the relay and at the destination.
- True three-node relay with always-listening nodes: C15 (every message `path=relayed`). Also C14 (direct, then reversed) and C16 (loopback hole punch, then `path=hole_punched`).
- netns C7 (`netns_nat_dcutr.sh`), on a global-looking simulated Internet (`docs/NAT_SOFTWARE_SIM.md`):
  - **cone:** the R14 stranger first, with 0 packets past the relay on the routers' kernel counters; then an upgrade, and `path=hole_punched` with the direct path counted;
  - **symmetric:** every message relayed; an upgrade fails the run;
  - **cone-private:** a private "Internet"; relayed, with 0 direct packets;
  - **swap:** the Phase 0 uplink swap.
- C7 becomes blocking. `continue-on-error` is deleted after 10 consecutive green runs, recorded in the lab workflow. The owner's flip commit makes it a required check.
- Real rows R3, R5, R9 and R14, per `docs/P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md`. They use `wan_two_network_test.sh` in three-node mode, rehearsed on one machine with `three-dry-run`.

**Gate:**
- At exit, the owner signs `WAIVER_P2P_RELAY` with the real rows recorded, then flips `P2P_PRODUCTION_ENABLED`.
- `INTERNET_DIRECT` stays false (decision D5).
- Independent review: decision D6.

### Phase 2: contacts find each other, friends become the infrastructure

**Deliverables** (the plan is `docs/roadmap/plans/phase2-design.json`, steps P2.1-P2.29; every gate stays off):
1. **RRH1 route hints (C5).** Spec [`protocol/RAVEN_ROUTE_HINTS_V1.md`](../../protocol/RAVEN_ROUTE_HINTS_V1.md) (RRH1, RLX1, card v3 §9), vectors `shared-vectors/rvn1/route_hints/` and `lan/noise_xx_handshake_002.json`, a `PROTOCOL_VERSIONS` row, fuzz target `rrh1_frame` (P2.1-P2.2; harness P2.8).
   - A control frame after RLB1 on every link (P2.5), negotiated by RIH1 caps bit 8 or RLX1 in LAN message 3.
   - A learned-routes cache that the planners use (`raven-core/src/learned_routes.rs`, P2.3-P2.4, P2.6, P2.R1), and announce links when a snapshot changes.
   - Card v3 carries only the PeerId and the home relays; `--compat` prints /1 or /2. "Hide my IP" per contact and for everyone (D4, P2.7).
   - Gate `ROUTE_HINTS_PRODUCTION_ENABLED` (debug `RAVEN_LAB_ROUTE_HINTS=1`).
2. **Friend relay role (C6)** (`raven-node/src/friend_relay.rs`, P2.16-P2.19, P2.22).
   - Ask once; an explicit yes is required (`raven relay offer on|off`).
   - Members are built automatically from pinned contacts (not blocked ones, nor ones it hides its IP from), plus manual allow and minus a deny list.
   - Uses its own relay key, on port 7427 (optionally TCP 443).
   - Runs an AutoNAT v2 server behind DialBackGuard.
   - Uses `RelayLimits::friends`.
   - Offered to members inside RRH1 (`RELAY_OFFER`, spec §11, P2.17).
   - Gate `FRIEND_RELAY_PRODUCTION_ENABLED` (debug `RAVEN_LAB_FRIEND_RELAY=1`).
3. **Relay selection (C7).** Sticky, with hysteresis, and tolerant of a relay that sleeps (laptops, Windows logon tasks, design Q9): `raven-core/src/relay_select.rs` (P2.20-P2.21). Relays set by hand first; a relay is replaced after 10 minutes of loss while the node is otherwise online; at most one change per 5 minutes; no swap back within 30 minutes; `raven relay auto off` opts out.
4. **User-run relay kit** ([`docs/RELAY_KIT.md`](../RELAY_KIT.md), P2.9-P2.14).
   - One command per OS: a systemd system unit (Linux), a launchd agent or daemon (macOS), a logon task (Windows).
   - Listens on 7423 and on TCP 443 (`raven-node relay --also-tcp`, `--public-host`, `--check`).
   - `raven relay card` produces text to share (no QR crate in `Cargo.lock`; owner decision on the kit (f)); friends paste it into `raven relay use`.
   - A short guide for "a Pi with a port forward" and "a €5 VPS".
5. **"Nobody reachable in your circle"** diagnosis, with next steps (`raven-core/src/reach_diag.rs` on the circuit-failure classifier of P2.15; P2.24-P2.27; §2.5 above).

**Reused code:** `lan_seen.rs`, `relay.rs`, `relay_allow.rs`, the ask-once pattern in `ash/src/p2p_cli.rs:58-96`, `RelayGuard`, and `internet.rs` `CAP_RELAY` / `CAP_STORE`.

**Tests:**
- RRH1 vectors and fuzzing (`rrh1_frame`, `relay_inputs`, `reach_tokens`).
- carrier_matrix (three OSes): C17 LAN port change and old peers, C18 a new relay without new cards, C19 hide my IP, C20 the recipient changes network while the sender holds a stale hint, C21 a friend relay picked from its offer, C22 a sleeping relay replaced, C23 a relay that moves, C24 the kit's relay and its fallback address, C25 an installed kit on 443 (Linux CI), C26 every diagnosis reason; C35 (cutoff study) no route to the internet.
- lan_fault_matrix: s04 closed by route hints, s04b/s04c/s04p, s39-s40 (hints over p2p), s41-s44 (friend relays), s45-s47 (the kit), s48, s48c, s49 and s48o (the diagnosis).
- netns (advisory): `hints`, `only443`, `friend`, `friend-sleep`, `diag`; CI install smoke of the kit on the three OSes.
- Real ([`docs/P2_REAL_ROWS_CHECKLIST.md`](../P2_REAL_ROWS_CHECKLIST.md)):
  - R3, R5 and R9 still work after a relay change *without* exchanging cards again;
  - R13;
  - R8 through a user-run relay on 443;
  - R15-R20 and the diagnosis rows (matrix below).

**Gate:** sign the Phase 2 amendment of `WAIVER_P2P_RELAY` (its §9; §6 lists route hints as a lapse condition) and the LAN amendment [`docs/WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md`](../WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md); only then flip `ROUTE_HINTS_PRODUCTION_ENABLED` and `FRIEND_RELAY_PRODUCTION_ENABLED`, each in its own commit. Before any LAN flip, check the Swift/iOS LAN code against `noise_xx_handshake_002`.

**Status (2026-10-17):** items 1-5 are built behind their gates (both `false`) with the tests above; the netns cases and the real rows are open.

### Phase 3: local network and offline

**Deliverables:**
1. **LAN listens on all interfaces**, contact-gated. This changes the installer default.
   - Built (P3.2-P3.7): `--lan-listen auto` (both families, local sources only) behind `LAN_AUTO_LISTEN_PRODUCTION_ENABLED` (`raven-core/src/lan_gate.rs`); the installers follow `raven-node lan-default`, so they stay at 127.0.0.1:7420 until the flip; `raven lan off|on|status`, meeting mode and verified-only on the LAN ship ungated.
2. **Contact-only local beacon.**
   - It carries a port and a rotating token, follows the Private Rendezvous R2 rules, and has no constant Raven marker. Fix the `rvn1/nearby-adv` marker at `nearby.rs:39`.
   - It keeps the IPv6 zone.
   - It covers DHCP moves and discovery without a prior link. Fault s04 (port change) is closed by the beacon when the moved side is silent (no traffic or announce from it), and by RRH1 (Phase 2) otherwise.
   - Built (P3.8-P3.11): [`protocol/RAVEN_LAN_BEACON_V1.md`](../../protocol/RAVEN_LAN_BEACON_V1.md) (UDP 7420 to 239.255.74.20 and ff02::8000:7420, 160-byte queries and 48-byte answers) and `RAVEN_PRIVATE_RENDEZVOUS_V1` revision 4 §5.3a, behind `LAN_BEACON_PRODUCTION_ENABLED` (`raven-core/src/lan_beacon.rs`; the task in raven-node). The marker at `nearby.rs:39` is gone (P3.1).
3. **Friend custody over the internet.**
   - Custodians are announced in RRH1 (0x06 CUSTODY_OFFER, 0x07 CUSTODIAN_TAG; [`RAVEN_ROUTE_HINTS_V1.md`](../../protocol/RAVEN_ROUTE_HINTS_V1.md) §12), and each node picks at most 2 home custodians (`raven-core/src/custody_home.rs`).
   - Flipping `FRIEND_CUSTODY_PRODUCTION_ENABLED` and `FRIEND_CUSTODY_WAN_ENABLED` is not part of this work: both are owner actions after the custody waiver ([`docs/WAIVER_FRIEND_CUSTODY_DRAFT.md`](../WAIVER_FRIEND_CUSTODY_DRAFT.md)) is signed, the first after R11g, the second after R10 and R10b and only once P2P is live (a compile-time tripwire: WAN custody needs `P2P_PRODUCTION_ENABLED`).
   - The consent text says that the custodian learns both identities (`raven node custody on`, `raven custody use on`).
   - Design: [`2026-10-friend-custody.md`](2026-10-friend-custody.md) §19.
4. **Proactive re-pair** on every live link when less than 12 h of the session remain.
   - Built (P3.13-P3.15) as session renewal: `raven-core/src/session_renewal.rs` (policy and step) and `raven-node/src/renewal.rs` (the task), behind `SESSION_RENEWAL_PRODUCTION_ENABLED` (debug `RAVEN_LAB_SESSION_RENEWAL=1`).
5. **Offline guide:** how to make a local network on macOS, Linux and Windows: [`docs/OFFLINE_GUIDE.md`](../OFFLINE_GUIDE.md), with its safety guide [`docs/SAFETY_OFFLINE.md`](../SAFETY_OFFLINE.md).

**Tests:**
- s04 passes without route hints (the beacon; `RAVEN_FAULT_BEACON=1`).
- s80 (this plan's earlier "new s33"; s33 is Phase 0's network change): discovery after both people move to a new network; s81-s84 (a quiet receiver's DHCP move, a capture with no marker, `raven lan off` and `on`, unverified contacts).
- s30 over p2p: s30p, s30w and s30r; carrier_matrix C32-C34.
- Renewal: carrier_matrix C31, fault matrix s85 and s85b.
- carrier_matrix C27-C30 (the listener and the beacon); netns `lan-move`, `lan-ll`, `lan-isolated`, `lan-nonlocal` and `custody` ([`docs/NAT_SOFTWARE_SIM.md`](../NAT_SOFTWARE_SIM.md)).
- Real rows R1, R1b, R10, R10b, R10r, R11a-g and R21-R24, and the cutoff study's R11d+, R11e+, R11h, R11i and R11j ([`docs/P3_REAL_ROWS_CHECKLIST.md`](../P3_REAL_ROWS_CHECKLIST.md) section 7).

Numbering: Phase 3's carrier_matrix cases are C27-C34 (block C27-C39, with the cutoff study's C35-C39), its fault scenarios s80-s85b (block s80-s99, with the cutoff study's s86-s99) plus s04 and s30p/s30w/s30r, and its new real rows R11a-g and R21-R24 (C17-C26, s39-s49 and R15-R20 are Phase 2's; Phase 4 owns C40-C49 and s50-s59, Phase 5 C50-C69 and s60-s79; C35 is the cutoff study's no-route case). This replaces the earlier note (Phase 2, P2.28) that gave Phase 3 the scenarios right after s49.

**Gates:**
- LAN waiver amendment, because hold B12 keeps LAN exposure opt-in: [`docs/WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md`](../WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md) (unsigned; sections for `auto`, the beacon and renewal). Flip order after signing: `LAN_AUTO_LISTEN_PRODUCTION_ENABLED`, then `SESSION_RENEWAL_PRODUCTION_ENABLED`, then `LAN_BEACON_PRODUCTION_ENABLED` only after the R2 approval, the crypto review and Swift parity.
- Custody waiver covering both custody flags: [`docs/WAIVER_FRIEND_CUSTODY_DRAFT.md`](../WAIVER_FRIEND_CUSTODY_DRAFT.md) (unsigned), with the Phase 3 amendment of [`docs/WAIVER_P2P_RELAY_DRAFT.md`](../WAIVER_P2P_RELAY_DRAFT.md) (§10). Every flip is an owner action after signature.
- Approve the R2 part of `RAVEN_PRIVATE_RENDEZVOUS_V1` (revision 4).

**Status (2026-10-22):** items 1-5 are built behind their gates (all `false`) with the tests above; the waivers are unsigned drafts, the netns cases (Linux) and the real rows are open.

### Phase 4: harder networks, only where real tests show the need

**Status (2026-10-22):** built in a parallel lane (steps P4.0-P4.29; P4.22
skipped by O4-9), every gate `false`. The six Phase 4 gates are `WSS_PRODUCTION_ENABLED`,
`WSS_PROXY_PRODUCTION_ENABLED`, `PORT_MAP_PRODUCTION_ENABLED`,
`V6_PINHOLE_PRODUCTION_ENABLED`, `NAT_CLASS_PRODUCTION_ENABLED` and
`PEER_ROTATION_PRODUCTION_ENABLED`. They wait for three unsigned drafts:
`docs/WAIVER_WSS_PROXY_DRAFT.md`, `docs/WAIVER_PORT_MAP_DRAFT.md` and §11 of
`docs/WAIVER_P2P_RELAY_DRAFT.md`. Each gate flips on its own (owner decision
O4-16). Plan: `docs/roadmap/plans/phase45-design.json`.

**Deliverables:**
- **WSS (WebSocket over TLS) on 443, plus HTTP CONNECT proxy support**
  ([`RAVEN_WSS_TRANSPORT_V1.md`](../../protocol/RAVEN_WSS_TRANSPORT_V1.md), RWS1).
  - Names are resolved before libp2p, because `libp2p/dns` stays excluded
    (O4-7). Through a proxy the proxy resolves the relay's name, and SNI keeps
    the name.
  - The `via=` grammar learns `/tls/ws`.
  - A relay's TCP 443 serves raw libp2p and WSS as siblings on one port,
    split by the first byte (O4-3). The relay kit keeps raw 443 until the WSS
    flip.
  - Clients accept any relay certificate; libp2p Noise and `/p2p/<id>`
    authenticate the relay (O4-2).
  - Raven's own WebSocket subset, so no new crate (O4-1).
- **NAT-PMP, PCP and IPv6 pinholes**
  ([`RAVEN_PORT_MAPPING_V1.md`](../../protocol/RAVEN_PORT_MAPPING_V1.md)).
  - The gateway is searched again on every network change.
  - The UPnP yes covers IPv4 mapping; IPv6 pinholes ask once on their own
    (O4-11).
  - `raven doctor --router` probes the router first, read-only (O4-9, O4-10).
  - UPnP-IGDv2 pinholes (P4.22) were skipped: no real row has shown a router
    that needs them.
- **NAT classifier**, so hopeless hole-punch attempts are skipped (RRH1
  NAT_CLASS 0x22; O4-12).
- **PeerId rotation per epoch** (Q6, D14;
  [`RAVEN_P2P_PEER_ROTATION_V1.md`](../../protocol/RAVEN_P2P_PEER_ROTATION_V1.md)).
  - An opt-in setting, off by default even after a flip.
  - 28-day epochs. Contacts learn the schedule through RRH1 PEER_SCHEDULE
    (0x23), and cards carry `p2pn=`.
  - Dedicated relays take `raven relay schedule` (O4-13).
- **Auto-reach** (2026-10-28, lab only): a node asks public STUN servers for
  its own public address (owner-approved as a query only; D1 and D13 stand),
  offers it in route hints (DIRECT, INET_DIRECT 0x24), its friend relay's
  offer and its card, and two friends with endpoint-independent NATs punch to
  each other on a clock schedule both derive from their keys, with no relay
  or coordinator: [`2026-10-auto-reach.md`](2026-10-auto-reach.md), gates
  `STUN_DISCOVERY_PRODUCTION_ENABLED` and `SERVERLESS_PUNCH_PRODUCTION_ENABLED`
  (both `false`), harness s146-s148.
- **No community relay list.** D1 stands (O4-16). A list would need to be
  threshold-signed and opt-in, never compiled in as a default. It would need
  admission tickets, because the relay's per-IP caps (4 reservations and 8
  established connections per IP, `host.rs:164-189`) lock out users behind
  one shared carrier IP. It would also need amendments to the NAT spec (§1,
  §4) and a new waiver. None of it is built.

**Tests:**
- carrier_matrix C40-C42 (WSS, proxy, gate closed), C43-C44 (PCP/NAT-PMP,
  IPv6 pinhole), C45 (punch skip) and C46 (rotation);
- lan_fault_matrix s50-s51 (proxy outage, Negotiate), s52 (router restart)
  and s53 (rotation boundary);
- netns `netns_restrictive.sh` (`only443`, `tlsonly`, `proxyonly`) and
  `netns_nat_dcutr.sh` (`pcp`, `pcp-cgn`, `v6pin`, `classify`, `punch-skip`),
  advisory until each has its green streak;
- real rows R2b, R2c, R8w, R8p (R8m optional) and R25-R27
  (`docs/P4_REAL_ROWS_CHECKLIST.md`).

### Phase 5: later

- Past the 24 h limit ([`2026-10-beyond-24h.md`](2026-10-beyond-24h.md); D9 as refined below): sessions stay 24 h and each message gets a deadline of 7 days.
  - 5a, park and re-pair (built behind `LONG_HORIZON_PRODUCTION_ENABLED = false`, lab switch `RAVEN_LAB_HORIZON=1`): an expired message is parked, then sealed again under the same message id into a new session when the contact is back; no wire change. Harness s60, s60b, s60c and s94; waiver amendment draft [`WAIVER_LAN_DIRECT_HORIZON_AMENDMENT_DRAFT.md`](../WAIVER_LAN_DIRECT_HORIZON_AMENDMENT_DRAFT.md) (unsigned).
  - 5b, sealed letters (RAL1 over friend custody; `ASYNC_LETTER_PRODUCTION_ENABLED = false`): designed, not built.
  - The ratchet (HR3) stays the separate forward-secrecy program.
- A Bluetooth LE "nearby" carrier. It needs three native backends and a new `NEARBY` gate; about 40-60 d.
- A relay mailbox with recipient-issued deposit rights, only if custody coverage is not enough.
- Multi-hop delivery (RHW1): built behind `CUSTODY_HANDOFF_PRODUCTION_ENABLED = false` (lab switch
  `RAVEN_LAB_CUSTODY_HANDOFF=1`, on top of friend custody's): a two-custodian handoff A -> F1 -> F2 -> B
  ([`protocol/RAVEN_CUSTODY_HANDOFF_V1.md`](../../protocol/RAVEN_CUSTODY_HANDOFF_V1.md),
  [`2026-10-friend-custody.md`](2026-10-friend-custody.md) §20); harness C54, C55, s68-s71 and s97b;
  waiver draft [`WAIVER_FRIEND_CUSTODY_HANDOFF_DRAFT.md`](../WAIVER_FRIEND_CUSTODY_HANDOFF_DRAFT.md)
  (unsigned); real rows R28 and R29 ([`P5_REAL_ROWS_CHECKLIST.md`](../P5_REAL_ROWS_CHECKLIST.md)).
  The relay mailbox stays unbuilt (owner decision P5-MH-2).

**Deliberately not built:**
- a public DHT (B; design Q13 stands);
- compiled-in default relays;
- port prediction;
- Wi-Fi Direct automation;
- the legacy MeshEnvelope Bluetooth profile, which advertises the fingerprint.

### Phase 6a: learning connectivity (built, lab only)

The node learns, from its own delivery outcomes only, which of the routes
above to try first for each contact on each network, a few shorter waits
(never longer than today's), a bounded relay term, and which (at most two)
friends to leave a contact's mail with; it adds no route, carrier, peer or
wire format and shares nothing it learned. It finds no address: discovery
stays with route hints, the Phase 3 beacon and nearby. Built behind
`LEARNING_PRODUCTION_ENABLED = false` (lab switch `RAVEN_LAB_LEARNING=1`,
user switch `raven learning on|off`); harness C70-C74 and s100-s106 (block
C70-C79, s100-s109). Design: [`2026-10-learning-connectivity.md`](2026-10-learning-connectivity.md);
waiver draft [`WAIVER_LEARNING_DRAFT.md`](../WAIVER_LEARNING_DRAFT.md)
(unsigned); real rows L1-L4 ([`P6A_REAL_ROWS_CHECKLIST.md`](../P6A_REAL_ROWS_CHECKLIST.md)).

### Real-world test matrix

**For every row, record:**
- messages delivered out of 10, in both directions;
- the path label (direct, reversed, relayed or hole-punched);
- whether DCUtR upgraded to direct;
- the time until the receipt arrives;
- the OS pair.

Store results under `node/proof_artifacts/`. Today all pairs are Mac-to-Mac. Linux and Windows rows need hardware or VMs, and Windows needs its own logon-task row.

**Phase 2 rows** (R8, R13, R3/R5/R9 after a relay change, R15-R20 and the diagnosis rows): the operator steps are in `docs/P2_REAL_ROWS_CHECKLIST.md`, with results under `node/proof_artifacts/p2-<ROW>-<UTC>/`.

**Phase 4 rows** (R2b, R2c, R8w, R8p, R8m and R25-R27; R8 is split into the
Phase 2 row R8, raw 443 through a kit relay, and R8w/R8p/R8m for WSS and
proxies): the operator steps are in `docs/P4_REAL_ROWS_CHECKLIST.md`, with
results under `node/proof_artifacts/p4-<ROW>-<UTC>/`. The Phase 4 plan names
R25-R27 "R15-R17"; Phase 2 already holds those numbers.

**Phase 1 rows R3, R5, R9 and R14, and the Phase 0 row R12:** the operator steps are in `docs/P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md`. They use `node/scripts/wan_two_network_test.sh` in three-node mode, where the relay is a third machine and the sender has no prior connection. Results go to `node/proof_artifacts/wan3-<ROW>-<UTC>/`, which is git-ignored and attached to the waiver's signature record. Software stand-ins are carrier_matrix C15/C16 on loopback and the netns cases (C7). They do not replace these rows.

**Extra gear needed:**
- a third machine as relay (a €5 VPS is simplest; the Mac Studio cannot be both recipient and independent relay);
- a second phone or a SIM dongle;
- a UPnP-capable router;
- Linux and Windows machines.

| Row | Case | Setup | Pass bar (proposal) | Phase |
|---|---|---|---|---|
| R1 | (1) | Same home Wi-Fi, no addresses typed | 10/10, discovered automatically | 3 |
| R1b | (1) | Guest Wi-Fi with client isolation | Falls back to the internet path and delivers | 3 |
| R2 | (2) | UPnP router, no manual forward | Direct, no relay | 1 |
| R2b | (2) | A NAT-PMP-only or PCP-only router (OpenWrt/miniupnpd with UPnP off, or an Apple AirPort), PORT_MAP lab | Direct with no relay, 10/10 both ways | 4 |
| R2c | (7) | IPv6 behind the router's default firewall, a PCP pinhole (V6_PINHOLE lab) | Inbound direct over IPv6 | 4 |
| R3 | (3) | home router with the forward **removed**; relay on a VPS | 10/10 over a true circuit; DCUtR result recorded | 1 |
| R4 | (4) | A carrier-NAT fixed line, if available | Delivers; path recorded | 1 |
| R5 | (5) | Laptop on iPhone hotspot <-> home, relay on a VPS, laptop always listening | 10/10; DCUtR rate measured | 1 |
| R6 | (6) | SIM dongle or second phone | Delivers | 1 |
| R7 | (7) | IPv6 on both ends, default firewall | Direct over IPv6, or hole-punched | 1 |
| R8 | (8) | pf/nftables allows only outbound TCP 443; a relay kit relay on 443 | Delivers | 2 |
| R8w | (8) | Only TCP 443 (and DNS) out; a VPS relay with `--wss 443`, the laptop dials `/tls/ws` (`r8_only_443.sh` / `.ps1`) | 10/10 both ways, relayed, relay transport `wss` | 4 |
| R8p | (8) | Nothing out but an HTTPS proxy set in the OS (system detection) | 10/10 both ways, relayed, relay transport `wss-proxy` | 4 |
| R8m | (8) | Optional: a TLS-intercepting proxy, the relay on a real domain certificate | Recorded either way | 4 |
| R9 | (9) | Both laptops on different phone hotspots, relay on VPS or Mac Studio | 10/10 | 1 |
| R10 | (10) | Recipient asleep, sender sends and goes offline, Mac Studio is custodian | Delivered on wake, within 24 h | 3 |
| R10b | (10) | As R10, the custodian restarted (and rebooted once) between deposit and fetch | 10/10, nothing lost | 3 |
| R10r | (10) | Optional: the Mac Studio is also the friend relay; both laptops on two phone hotspots | 10/10, deposits after "not on a relay" | 3 |
| R11a | (11) | Router with WAN unplugged | 10/10, no address typed | 3 |
| R11b | (11) | Linux `nmcli` hotspot | 10/10, no address typed | 3 |
| R11c | (11) | Cable, per OS pair (169.254 and fe80 with its zone) | 10/10, no address typed | 3 |
| R11d | (11) | Windows Mobile hotspot without Internet | 10/10, or "cannot host" recorded | 3 |
| R11e | (11) | macOS Internet Sharing without uplink | 10/10, or "cannot host" recorded | 3 |
| R11f | (11) | Phone hotspot without mobile data | 10/10, or "cannot host" recorded; client isolation recorded | 3 |
| R11g | (11) | Custodian laptop on an offline LAN (router WAN unplugged); A sends while B is away | B gets it from C over LAN only, 10/10, no address typed | 3 |
| R12 | change | Switch Wi-Fi <-> hotspot on each side mid-conversation | Recovers in about 30 s or less, no user action | 0 |
| R13 | relay sleeps | The friend relay is a laptop that closes its lid, with two other operators | Re-selects relay; delivery continues; no thrash after the lid opens | 2 |
| R14 | privacy | A stranger with the card opens a circuit | Refused by B's peer gate (its count goes up by 1); 0 packets between the stranger and B in both captures, so no candidate was used. The capture cannot show what was sent (DCUtR is encrypted); C16 proves that nothing was | 1 |
| R15 | hide my IP | A hides its IP from B; a packet capture on B's network | No packet from A's public IP reaches B; every message `relayed` | 2 |
| R16 | LAN port | Two Macs on one LAN; one changes its LAN listen port | The other reaches it on the new port with no address typed | 2 |
| R17 | relay moves | A friend relay's laptop moves to another UPnP network | Its members follow without a card exchange | 2 |
| R18 | relay kit | A Raspberry Pi with a port forward runs the relay kit | 10/10 relayed; same PeerId after a reboot and an update | 2 |
| R19 | relay kit | A EUR 5 VPS runs the relay kit, 443 direct | 10/10 relayed; resource numbers recorded | 2 |
| R20 | relay sleeps | A Windows logon-task relay (advisory) | Relays while signed in; sign-out and sleep recorded | 2 |
| R25 | NAT class | The classifier on a home line, a phone hotspot and a SIM dongle, with 2 relays on different /24s (the Phase 4 plan's R15) | TCP and QUIC class recorded from 2 observers on each network | 4 |
| R26 | punch skip | Both laptops on different phone hotspots, NAT_CLASS lab (the plan's R16) | No DCUtR attempt after the skip; relayed 10/10 | 4 |
| R27 | rotation | PeerId rotation across lab-shortened epochs, a VPS relay with the schedule and a friend relay (the plan's R17) | Delivery continues; status shows the new ID; no PeerId in any log | 4 |
| R9-d, R13-d, R-off, R14-d | diagnosis | R9 with no relay, R13's lid, the recipient's lid, R14's stranger | The send, status and doctor texts name the right reason and fix | 2 |
| R21 | lan off | `raven lan off` at a cafe, with tcpdump | No UDP 7420 sent, TCP 7420 refused, nothing dialled on the LAN; `raven lan on` restores | 3 |
| R22 | DHCP move | One machine's LAN address changes | Queued messages delivered within 30 s, no address typed | 3 |
| R23 | cross-OS LAN | Mac and Linux, Mac and Windows, both ways, plus the Windows numeric IPv6 zone | 10/10 each way | 3 |
| R24 | renewal | Meet at session hour 12 or later, then 20 h apart | Queued text says at least 23 h; delivered on return | 3 |
| R-noroute | no route | A laptop with no default route (manual IP without a router, or a link-local cable); a gateway with a dead upstream still has a default route and is not detected | No relay, VPS or port advice; LAN delivery 3/3 | 2 |

---

## 4. Owner decisions

**D1. Who provides the reachable third node?**
- Recommended: friends' nodes plus user-run relays (a Pi or VPS), made one-command easy. No compiled-in or project-run default relays. Revisit an opt-in community list after the Phase 2 real tests.
- Trade-off: this keeps server=none and avoids concentrating metadata at a few operators. The cost: two strangers, both on mobile data, with no reachable friend, cannot talk until someone runs a relay. Only approach C gives zero-setup "anyone", and it contradicts NAT spec §1/§4 and the waiver §6 lapse rule.
- Phase 4 (owner decision O4-16): D1 stands. No community relay list was built; WSS on 443 and proxy support make user-run relays reachable from more networks instead.

**D2. Consent for the relay role.**
- Recommended: ask once, only on nodes confirmed public; an explicit yes is required; verified contacts only; the relay uses its own key.
- Trade-off: fewer relays than "default on", but honest consent and limited bandwidth exposure.

**D3. Peer gate before turning P2P on.**
- Recommended: yes, mandatory.
- Trade-off: a few days of work. It closes the leak where strangers learn IPs, the dials strangers can steer, and the filling of inbound slots.

**D4. Share IP addresses with verified contacts (direct connections and DCUtR).**
- Recommended: on by default for verified contacts only, with a global and per-contact "hide my IP" (relay only).
- Trade-off: a contact learns your IP and rough location; the alternative is that relays carry all traffic and see all the metadata.

**D5. Internet direct on 7422 versus libp2p (design Q11).**
- Recommended: ship libp2p only. Keep 7422 as a lab and fallback tool and leave `INTERNET_DIRECT` off.
- Trade-off: one stack to test and review, but no non-libp2p backup if libp2p has a bug.

**D6. Gate order and review.**
- Recommended: flip P2P at the end of Phase 1 under the signed waiver, with its 3-month review date. Commission the independent review of the public libp2p surface in parallel; it is required before wide public release. Amend for route hints in Phase 2 and for custody in Phase 3.
- Trade-off: real users sooner, versus outside assurance first.

**D7. LAN listens on all interfaces by default.**
- Recommended: yes, contact-gated, with the beacon and `raven lan off` for untrusted networks.
- Trade-off: on the same Wi-Fi, a prober can read the stable Noise static key, which can be used for tracking. The gain is zero-setup LAN and offline use.

**D8. Form of route hints.**
- Recommended: authenticated by the channel inside the link (deniable), not identity-signed records.
- Trade-off: hints cannot be forwarded through third parties. A later "lookup at a friend" (R3) would need sealing per contact pair.

**D9. The 24 h limit.**
- Recommended: proactive re-pair in Phase 3; long-lived sessions (the ratchet) as the first item of Phase 5.
- Trade-off: until then, "offline for more than a day" fails on every path.
- Refined in Phase 5 (owner decision O5-1, recommended option; the owner's explicit OK is still open): keep 24 h sessions and give each message a 7-day deadline. 5a parks and re-pairs (no wire change), 5b leaves sealed letters with a friend custodian; the ratchet stays a separate program ([`2026-10-beyond-24h.md`](2026-10-beyond-24h.md)).

**D10. Restrictive networks.**
- Recommended: relays on 443 in Phase 2 (cheap). WSS and proxy support in Phase 4. Anti-censorship is explicitly out of scope.

**D11. Port mapping.**
- Recommended: keep UPnP as "ask once, off by default". Fix the NAT-PMP strings now. Build NAT-PMP and PCP only if the real tests show routers that need them.

**D12. Offline mesh scope for v1.**
- Recommended: "same Wi-Fi, hotspot or cable", plus friend custody. Bluetooth is a separate later decision (Phase 5). No Wi-Fi Direct.
- Trade-off: no radio-only mesh for some months, but 40-60 d saved now.

**D13. Record "no".** No public DHT (Q13 stands) and no port prediction.

**D14. PeerId.** Keep it stable now; rotate it per epoch in Phase 4 (Q6).

**D15. The Mac Studio port forward.**
- Recommended: for testing your own use of Raven, forward 7423 and 7427, TCP and UDP (drop 7422): 7423 for the node, 7427 for its friend relay, which has its own key and port (Phase 2 owner decision on the friend relay port), so the Mac Studio is your circle's relay and custodian. Otherwise delete the rules, as today's notes say.

---

## 5. Risks and open questions

### Risks

1. **Hole-punch success on mobile networks is unmeasured.** The plan assumes relays carry most hotspot and SIM traffic. Circuit limits (2 MiB and 5 min per circuit) are fine for text. RDAP app-channel payloads or files may need more.
2. **Circles without an always-on reachable node fail cases (3)-(6) and (9) completely.** The only answers are the user-run relay or decision D1.
3. **Relays that sleep.** Laptops close their lids and Windows runs Raven as a logon task, so relay health and re-selection must be tested with a relay that sleeps.
4. **Relay per-IP caps.** Each relay allows 4 reservations and 8 established connections per IP. Many users behind one carrier IP could be refused, even at a busy friend relay.
5. **Peer-gate ordering inside the behaviour derive: verified.** libp2p-swarm-derive 0.36 builds `handle_established_*` as nested `select(select(f0?, f1?), f2?)` in field order (lib.rs:289-310; 339-360 outbound), so the first field that denies stops every later one, and libp2p-swarm 0.48 then spawns no handler of any field (lib.rs:700-763). The gate is the third field of both swarms; raven-swarm host.rs `the_gate_refuses_before_dcutr_identify_or_autonat_build_a_handler` (no DCUtR, Identify or AutoNAT handler for a refused stranger), `a_stranger_circuit_is_refused_and_learns_no_address` and `limits_come_first_and_outbound_keeps_a_reserve` (field order) prove it, and carrier_matrix C6 and lan_fault_matrix s35 show a stranger refused end to end. A libp2p upgrade must rerun them.
6. **libp2p-identify 0.48 port rewriting** may produce wrong hole-punch candidates behind carrier NAT. Verified: identify-0.48 behaviour.rs:350-397 turns an observed address whose port is not a listen port into `observed IP + listen port`. Fixed by the candidate book (raven-swarm candidates.rs, Phase 1 item 3), which keeps the raw observation from the node's own relays (or two peers) ahead of Identify's guess; the netns `shifted` run (advisory) can upgrade only through that raw port.
7. **Waiver lapse.** Extending scope (route hints, AutoNAT server role, relays on 443, community relays) without an amendment lapses the P2P waiver.
8. **Capacity.** One developer; Phases 1-3 come to about 40-60 d (guess).
9. **Only macOS is verified locally.** Windows TCP port reuse, Defender prompts, and macOS Local Network permissions are untested.
10. **Data cost and battery** of keepalives on hotspots (15 s ping per relay connection). This must be measured.
11. **Remaining privacy exposure.**
    - Relays see IPs, timing and PeerIds.
    - Custodians see both identities.
    - The stable PeerId and Noise static are tracking handles. Phase 4's PeerId rotation is opt-in and held, and it does not change the LAN Noise static.
12. **Accept-any TLS on WSS** (Phase 4). An active TLS interceptor can pose as a relay and learn the dialling endpoint's PeerId, exactly as on raw TCP 7423. A TLS-inspecting proxy needs an operator certificate for a real domain. The ClientHello does not look like a browser's. NTLM/Negotiate, PAC/WPAD, SOCKS and `https://` proxies are not supported. Users behind one proxy share its IP and so the relay's per-IP caps (risk 4). Details: `docs/WAIVER_WSS_PROXY_DRAFT.md` §4.
13. **Router state** (Phase 4). Removing a NAT-PMP/PCP mapping or an IPv6 pinhole is best effort only: a mapping stays until its lease ends (7200 s; a pinhole 3600 s). Routers implement both protocols inconsistently. A pinhole makes the listener scannable: the peer gate still refuses strangers, but they learn the PeerId. Only R2b/R2c are proof. Details: `docs/WAIVER_PORT_MAP_DRAFT.md` §4.
14. **Rotation limits** (Phase 4).
    - Each epoch costs one re-home.
    - Relays can still link an old and a new ID by timing and IP.
    - A contact that never updates blocks rotation (`waiting`). A contact offline for the whole announcing period, silent for more than 6 epochs, or holding a card older than 2 epochs needs a new hint or card.
    - Dedicated relays need a fresh schedule about every 6 months.
    - Wrong clocks pick the wrong epoch.

    Details: `docs/WAIVER_P2P_RELAY_DRAFT.md` §11.2.
15. **NAT class needs two observers** (Phase 4). With one relay the class stays unknown and only the "two failed punches" rule skips. A lying observer can force `varies` until the next re-home; relays still deliver.

### Open questions (answer with quick checks or real tests)

- Does the iPhone hotspot give the laptop IPv6? Does the home line have IPv6?
- Does the home router hairpin (connect two devices behind it through its public IP)?
- Do phone hotspots isolate their clients when there is no mobile data?
- Can macOS and Windows host a network with no upstream connection?
- How long do iOS hotspot and carrier NATs keep idle mappings? This sets the keepalive interval.
- What DCUtR success rate does R5 show once the laptop always listens?
- How common are NAT-PMP-only or PCP-only routers among target users?
- Where does the Phase 0 code currently live? It is not in raven-features yet and must be merged before Phase 1.