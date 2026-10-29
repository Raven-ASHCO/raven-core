# Raven-swarm connectivity matrix (Sprint 0)

**Owner surface:** `node/crates/raven-swarm` (Noise, TCP, Kademlia, relay, DCUtR, NAT/CGNAT, hole punching, peer routing, backpressure).  
**Assignment:** Sprint 0 Role #6 — P2P / libp2p Network Engineer, raven-swarm owner.  
**Published org mapping:** [docs/engineering/baseline-freeze/org-structure.md](../engineering/baseline-freeze/org-structure.md) names **#9 Network Lead** for D3 networking; [`.github/CODEOWNERS`](../../.github/CODEOWNERS) maps `/node/crates/raven-swarm/` to `@Raven-ASHCO/network`. This doc does not resolve that numbering; it inventories the crate.  
**Date of inventory:** 2026-09-04 (repo `main` at investigation time).  
**Founder addendum:** 2026-09-04 — [§0 terminal-to-terminal direct Internet](#0-founder-terminal-to-terminal-direct-internet) (read-only; no network-code change).  
**Execute addendum:** 2026-09-04 — [Execution evidence](#execution-evidence-2026-09-04) (live commands on `main` @ `1f66c40`; no WAN peer; no production-behavior change).  
**2026-10 status:** the transports P3 host is present: `raven_swarm::host` (Cargo feature `p2p-host`, endpoint + relay) and raven-node's p2p carrier and relay role (`src/p2p.rs`, `src/relay.rs`), all held by `P2P_PRODUCTION_ENABLED=false` (debug lab unlock `RAVEN_LAB_TEST_A=1` only). libp2p is pinned at 0.57. §1, §2.4–§2.11, §5 and §6 are refreshed for it; the rest of this file is still the 2026-09-04 inventory of the `raven-swarm` binaries, which are unchanged.  
**Constraint:** read-only investigation. No product requirements invented. Confidence is labeled **documented** (spec/ADR/TODO/test/comment) vs **inferred** (architecture intent from composition or rust-libp2p defaults).

**Status legend**

| Status | Meaning |
|--------|---------|
| **present** | Code exists and is exercised by a named test or CI smoke |
| **partial** | Code or composition exists; missing a role, production path, or a proving test |
| **missing** | No Raven-authored implementation of the axis |
| **untested** | Composed or configured, but no test asserts the behavior |

---

## 0. Founder: terminal-to-terminal direct Internet

**Question:** Can two Raven terminals on the public Internet establish a **direct** path today?  
**Constraint:** honesty from named tests only. No WAN claim without a proving test. This section does not change §2–§6; it answers the founder question against the same evidence.

**Terminal-to-terminal direct Internet today:** **No — not proven, and the shipping message path is fail-closed.** Two public-Internet terminals cannot be claimed to connect. `raven_core::internet` (RIH1) is a codec plus a negative `ATSAM_SESSION_REQUIRED` gate; default `raven-swarm` TCP+Noise works only on explicit localhost multiaddrs; the experimental relay/DCUtR/AutoNAT stack is production-disabled. No CI or in-tree smoke dials a non-`127.0.0.1` / non-RFC1918 peer.

| Path / mechanism | Proven? | Evidence (file + test/CI) | What blocks WAN today |
|------------------|---------|---------------------------|------------------------|
| `raven_core::internet` / InternetTransport (RIH1 hello + length-prefix) — ADR-0002 V1 first land | **lab indexed delivery** on `127.0.0.1` only (software); **fail-closed** for legacy `raven-node run`; **not** WAN | Codec: `node/crates/raven-core/src/internet.rs`. Live sockets: `node/crates/raven-node/src/internet_direct.rs`. Positive lab: `node/scripts/internet_indexed_two_node.sh` (`INTERNET_INDEXED_TWO_NODE_PASS` + `dial≠WAN`). Negative: `node/scripts/internet_dial_smoke.sh`. Gate: `INTERNET_DIRECT_PRODUCTION_ENABLED=false`; debug `RAVEN_LAB_TEST_A=1`. | **dial≠WAN.** localhost ≠ public-Internet peer. No CI job dials a distinct public WAN host. Multi-NAT / DCUtR still **BLOCKED_HARDWARE**. Named-pipe ≠ WAN. Production slice flag stays false. |
| Default `raven-swarm` libp2p TCP+Noise (explicit multiaddr) | **localhost-only** | `build_swarm` TCP+Noise+Yamux (`node/crates/raven-swarm/src/main.rs`); `cmd_dial` `swarm.dial(addr /p2p/<peer>)` — no listen. Smoke: `node/scripts/libp2p_swarm_smoke.sh` (`--listen /ip4/127.0.0.1/tcp/0`). CI: `rust-linux` + `rust-macos` “libp2p swarm smoke”. Test: `fixed_localhost_nodes_connect_over_noise_tcp` (`src/connectivity.rs`). Same claim as §2.1. | Default serve listen is loopback (`/ip4/127.0.0.1/tcp/0`). Dialer does not bind/advertise a WAN address. Operator *may* pass a public multiaddr (no filter), but **no** named test or CI job dials a non-loopback / non-RFC1918 peer. `OutgoingConnectionError` returns immediately — no NAT/relay fallback (§3.1). Public Kad **BLOCKED_HARDWARE** (Transport Interface §5–6). |
| Experimental NAT stack (Circuit Relay v2 client / DCUtR / AutoNAT v2 client) — **contrast only** | **blocked** (production-disabled); localhost composition only | Spec: `protocol/RAVEN_NAT_CONNECTIVITY_V1.md`. Gate: `PRODUCTION_NAT_CONNECTIVITY_ENABLED = false`; Cargo `experimental-nat-connectivity` **and** `--enable-experimental-nat-connectivity`. CI: `expect_failure_with_message` “…requires explicit runtime opt-in”. Tests: reservation + limits on `127.0.0.1` only (§2.4–§2.10, §4.1). | Dual compile/runtime hold. Default `raven-swarm` does not compose relay/DCUtR/AutoNAT. This binary has no two-client circuit, no `dcutr=direct_connection_established` test and no AutoNAT server (the P3 carrier in the next row has them). Live multi-NAT/CGNAT: `NAT_STATUS` **BLOCKED_HARDWARE**. Not a production path and not a WAN proof. |
| raven-node p2p carrier (transports P3, 2026-10): libp2p TCP+QUIC, Circuit Relay v2, DCUtR, AutoNAT v2, Raven Noise link per `/raven/link/1.0.0` stream | **held** (`P2P_PRODUCTION_ENABLED=false`); **loopback** circuit both ways, and a Linux netns NAT simulation (advisory) | `node/crates/raven-node/src/p2p.rs`, `src/relay.rs`, `node/crates/raven-swarm/src/host.rs`. Loopback: `carrier_matrix` C6 (A and B reachable only through relay R, both ways), C12 and C13 (re-home on a network change or a silent relay path) on ubuntu, macOS and Windows. Netns: `node/scripts/netns_nat_dcutr.sh` (C7: cone with the R14 stranger and kernel packet counters, symmetric, cone-private and uplink-swap runs), lab job `nat-sim-linux` (`continue-on-error` until a 10-run green streak). | Production gate closed. No real two-home, CGNAT or hotspot row is recorded (any-network plan R3, R5, R9, R14). Loopback and netns are not a WAN proof. |
| `plan_paths` Direct vs Internet vs Relay (`raven-core`) | **yes** as **policy order only** — not a live WAN dial | `node/crates/raven-core/src/transport.rs`: Direct if `peer_reachable_direct`; Internet if `local_has_internet && peer_reachable_internet`; Relay if `relay_enabled && local_has_internet`. Test: `relay_and_store_are_ordered_fallbacks_not_delivery_claims`. Defaults: `MessageRouter.relay_enabled = false`, `NodePolicy.relay = false`. | **Direct** ≠ public Internet (local/LAN reachability flag). **Internet** is a carrier label, not a proving dial. **Relay** is a policy bit, **not** Circuit Relay v2, and is off by default. No `raven-swarm` caller walks this list onto a WAN or `/p2p-circuit` dial (§3.3). |

`docs/adr/0002-internet-transport.md` and `node/adr/0002-internet-transport.md` now agree (2026-10-05): InternetTransport is a “V1 laboratory path” under production hold, there is no relay server, and the negative smoke is required. (This file's 2026-09-04 text recorded an earlier conflict between the two copies.) This section follows the ADR + CI gate: codec exists, message origination must refuse.

### Execution evidence (2026-09-04)

**Role:** #6 raven-swarm owner · **Phase:** try / execute (live proof; docs only).  
**Tree:** `origin/main` `1f66c40` (`chore(CODEOWNERS): B3 mlkem FFI crypto+core`).  
**Host:** Cursor Cloud Agent Linux (no public Raven peer; no invented WAN dial).  
**Toolchain:** snapshot `rustc 1.83.0` failed `edition2024` (`block-buffer-0.12.1`). Installed `rustc 1.98.1 (48a229cea 2026-09-01)` / `cargo 1.98.1` to match CI `dtolnay/rust-toolchain@stable`.  
**Identity harness:** raw script runs **exit 1** — GNU/Linux first-install requires a reachable Secret Service even with `RAVEN_IDENTITY_BACKEND=locked-file` (`secret-service connect: zbus error: I/O error: No such file or directory`). After `dbus-launch` + unlocked `gnome-keyring-daemon` + `RAVEN_IDENTITY_BACKEND=locked-file` (documented debug/CI override; **not** a production backend), the intended gates ran.

Commands from repo root (crate builds in `node/`):

| # | Command | Exit | Meaning |
|---|---------|------|---------|
| 1 | `cargo build -p raven-swarm -q` | **0** | Default swarm binary built (`~43s`). |
| 2 | `cargo build -p raven-node -q` | **0** | Node binary built (`~11s`; unused `fingerprint_of` warning only). |
| 3a | `bash node/scripts/libp2p_swarm_smoke.sh` (no session bus) | **1** | Identity store blocked serve; **not** a dial result. |
| 3b | same + session bus + `RAVEN_IDENTITY_BACKEND=locked-file` | **0** | Localhost TCP+Noise+Kad two-node smoke **PASS**. |
| 4a | `bash node/scripts/internet_dial_smoke.sh` (no session bus) | **1** | `init failed: secure store unavailable: secret-service connect: …` |
| 4b | same + session bus + `RAVEN_IDENTITY_BACKEND=locked-file` | **0** | Negative ATSAM gate **PASS** (fail-closed; sender `A_STATUS=1`). |
| 5 | `cargo test -p raven-swarm --all-features fixed_localhost_nodes_connect_over_noise_tcp -- --nocapture` | **0** | `connectivity::tests::fixed_localhost_nodes_connect_over_noise_tcp ... ok` |
| 6 | `cargo test -p raven-swarm --all-features fixed_localhost_nodes_connect_over_authenticated_quic -- --nocapture` | **0** | `…_over_authenticated_quic ... ok` |

Key log lines (3b — libp2p swarm smoke):

```
manual_peer_only=true
connection_established peer=12D3KooWKEv3KUcrzptFK7kYPqvPfpuCjhiGb1ECX4GhmD1Ftwgn
kad_get_ok dial=/ip4/127.0.0.1/tcp/40499
peer_record_verified=1
=== LIBP2P SWARM SMOKE OK (TCP/Kad, no FastAPI) ===
```

Key log lines (4b — internet dial smoke; sender log):

```
raven-node: listen 127.0.0.1:33901
ATSAM_SESSION_REQUIRED: no authenticated persisted ATSAM session is available
PASS: legacy InternetTransport remains fail-closed pending indexed endpoint wiring
```

(Receiver logged `listen 127.0.0.1:37389` only; no `DELIVERED` / `ACK delivered`.)

**Direct path after this run** (localhost proven; public Internet **not** claimed):

| Path | Proven? | Blocked? |
|------|---------|----------|
| Default `raven-swarm` TCP+Noise+Kad on **127.0.0.1** | **Yes** — smoke 3b exit 0 + test 5 | — |
| Experimental localhost authenticated QUIC | **Yes** — test 6 | — |
| `raven-node` InternetTransport **message origination** | **Yes, fail-closed** — smoke 4b exit 0, sender exit 1, `ATSAM_SESSION_REQUIRED` | Indexed ATSAM session + sealed ACK not wired |
| Two Raven terminals on the **public Internet** (T2T WAN) | **No** | **Untested / blocked (no proving harness)** — this host has no public peer; no non-`127.0.0.1` dial was attempted |
| Experimental Circuit Relay / DCUtR / AutoNAT | Not re-run | Still production-disabled (see §0 table) |

WAN remains **untested**. Localhost success is not a public-IP or NAT claim.

---

## 1. Where the code lives

Two libp2p hosts share the crate. They are **not** the same behaviour tree.

| Binary / module | Feature / runtime gate | Transports & behaviours | Production claim |
|-----------------|------------------------|-------------------------|------------------|
| `raven-swarm` (`src/main.rs`) | default build, no extra feature | TCP+Noise+Yamux, optional QUIC listen, Kademlia `/raven/kad/1.0.0`, Identify `/raven/identify/1.0.0`, Ping | Localhost smoke only. Comment at `src/main.rs:236–237`: this binary is **not** a Circuit Relay server. |
| `raven-swarm-connectivity-experimental` (`src/connectivity.rs` + `src/bin/raven-swarm-connectivity-experimental.rs`) | Cargo `experimental-nat-connectivity` **and** `--enable-experimental-nat-connectivity` | TCP+Noise+Yamux, QUIC, Circuit Relay v2 **client**, AutoNAT v2 **client**, DCUtR, Identify `/raven/connectivity/1.0.0`, Ping, `libp2p-connection-limits` | Production disabled. Spec: [`protocol/RAVEN_NAT_CONNECTIVITY_V1.md`](../../protocol/RAVEN_NAT_CONNECTIVITY_V1.md). Constant `PRODUCTION_NAT_CONNECTIVITY_ENABLED = false`. |
| `raven-swarm-mailbox-experimental` (`src/mailbox.rs`) | Cargo `experimental-offline-mailbox` **and** `--allow-experimental-mailbox` | TCP+Noise+Yamux + request-response `/raven/offline-mailbox/1.0.0` | Production disabled. Bounded store-carry, not NAT traversal. |
| `raven_swarm::host` (`src/host.rs`, 2026-10) | Cargo `p2p-host` (only raven-node enables it) **and** a `HostGate` for every builder, which raven-node obtains only while `raven_core::p2p_live_enabled()` holds (`P2P_PRODUCTION_ENABLED=false`, or the debug lab unlock) | **Endpoint** (`build_endpoint_swarm`): TCP+QUIC (IPv4 and IPv6), Circuit Relay v2 client, DCUtR, AutoNAT v2 client (Phase 1: one per relay slot), Identify `/raven/identify/1.0.0`, Ping, `connection_limits` + per-IP limits, opt-in UPnP-IGD (IPv4 only), `libp2p-stream` for `/raven/link/1.0.0`; the relay server too only under the debug switch `RAVEN_LAB_P2P_PROFILE_RELAY=1` (Phase 1's `service --relay` under the user's PeerId, retired). The friend relay (Phase 2) is a relay swarm of its own in the service, with its own key. **Relay** (`build_relay_swarm`): Circuit Relay v2 server with `RelayLimits` and the `RelayGuard` allow-list, optional AutoNAT v2 server behind `DialBackGuard`, Identify, Ping, limits. No Kademlia, no mailbox. | Held (production gate false). |
| raven-node `src/p2p.rs` / `src/relay.rs` (2026-10) | `raven-node service --p2p-listen …` (opt-in; also `RAVEN_P2P_LISTEN`, `raven node p2p on`) / `raven-node relay --data-dir <dir>`; the same gate | p2p carrier: supervised endpoint, reservations on at most 2 relays (`--p2p-relay`; none compiled in), the Raven Noise link inside every `/raven/link/1.0.0` stream, dial direct first and then circuits, re-home on a network change (Phase 0b); Phase 4 (lab-only while `WSS_PRODUCTION_ENABLED=false`): relays dialled at their WebSocket/TLS forms too, through the HTTPS proxy `--p2p-proxy` / `RAVEN_P2P_PROXY` / node policy names where one applies, and restricted (no hole punching, no direct dials) while a reservation rides it (`protocol/RAVEN_WSS_TRANSPORT_V1.md` §2.3, §7, §9). Dedicated relay with its own key (`relay_key.ed25519`) and `relay_allow.json`; `--wss` (Phase 4, lab-only while `WSS_PRODUCTION_ENABLED=false`) adds a two-protocol TCP listener that takes WebSocket/TLS and raw libp2p on one port (`protocol/RAVEN_WSS_TRANSPORT_V1.md` §6). | Held. Loopback C6/C12/C13 on 3 OSes; netns C7 advisory. |

Related **non-swarm** surfaces (in scope only as fallback / policy neighbors):

| Surface | Role vs swarm |
|---------|----------------|
| `raven_core::internet` | V1 laboratory (production hold) TCP hello+frame (`RIH1`). ADR-0002 “first land”. Fail-closed for message origination (`node/scripts/internet_dial_smoke.sh`). |
| `raven_core::transport::{plan_paths,select_path}` | Application carrier order: Direct → Internet → Relay → Bridge → Store. `PathChoice::Relay` is a **policy flag**, not Circuit Relay v2. |
| `raven_core::message_router::MessageRouter` | Defaults `relay_enabled: false`. `NodePolicy.relay` also defaults `false`. |
| `raven_core::discovery::NAT_STATUS` | Compile-time honesty string: live multi-NAT/CGNAT/DCUtR matrix not run. |
| `raven_core` `network_sim_1000` | Deterministic 1,000-node store-carry model. Spec says it does **not** exercise live libp2p/TCP/NAT/relay reservations. |
| `scripts/nat_docker_sim.sh` | Docker dual-bridge **topology** proof with Python TCP echo. Does not start `raven-swarm`. |

libp2p crate pin: `libp2p = 0.57` with default features `tcp`, `quic`, `noise`, `yamux`, `kad`, `identify`, `ping`. Relay / DCUtR / AutoNAT are **feature-gated** on `experimental-nat-connectivity` and `p2p-host` (`Cargo.toml`); `p2p-host` also enables `libp2p/upnp` and `libp2p-stream =0.5.0-alpha`. No `libp2p/dns`: raven-node resolves `/dns*/` relay names with the system resolver.

Circuit Relay **v1** does not appear in this repo (no `circuit-v1` / `/p2p-circuit/p2p/1.0.0` client). rust-libp2p 0.57 `libp2p/relay` is Circuit Relay v2.

---

## 2. Connectivity matrix

Desired behavior is taken from existing docs. Primary sources:

- ADR-0002 ([`docs/adr/0002-internet-transport.md`](../adr/0002-internet-transport.md)): V1 = `InternetTransport`; **target** = rust-libp2p QUIC+TCP+Noise, DHT, AutoNAT/relay/DCUtR where conditions permit.
- [`protocol/RAVEN_TRANSPORT_INTERFACE_V1.md`](../../protocol/RAVEN_TRANSPORT_INTERFACE_V1.md) §5–6: explicit multiaddr dial without live DHT for V1; public Kad and Circuit/DCUtR **BLOCKED_HARDWARE**.
- [`protocol/RAVEN_NAT_CONNECTIVITY_V1.md`](../../protocol/RAVEN_NAT_CONNECTIVITY_V1.md): experimental composition + resource ceilings + client-only relay/AutoNAT.
- [`protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](../../protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md) §12: desired libp2p order **Direct → relay connection → DCUtR upgrade; mailbox last**. Explicitly **do not** treat path metadata as trust, and **do not** put DCUtR before relay.
- [`docs/MASTER_ENGINEERING_CHECKLIST.md`](../MASTER_ENGINEERING_CHECKLIST.md) §31 / §35: AutoNAT, Circuit Relay v2, reservations, DCUtR, hole punch, relay fallback, NAT-class tests — all still unchecked boxes.
- rust-libp2p specs referenced in-tree: Circuit Relay v2, DCUtR.

### 2.1 Direct TCP dial (same LAN / public IP)

| | |
|--|--|
| **Desired** | Dial an explicit `host:port` / multiaddr and establish a session without requiring live DHT. **documented** — Transport Interface §5; ADR-0002 V1 path. Public-IP / cross-NAT dial is part of the §31 matrix and is **not** claimed done. |
| **Status** | **present** on localhost / same-host TCP. **untested** for public IP, distinct LAN, or WAN. |
| **Evidence** | Default swarm: `build_swarm` TCP+Noise (`src/main.rs:126–129`), `cmd_dial` `swarm.dial(remote_addr.with(P2p))` (`src/main.rs:329–333`). Tests: `fixed_localhost_nodes_connect_over_noise_tcp` (`src/connectivity.rs:493`). Smoke: `node/scripts/libp2p_swarm_smoke.sh`. CI: `.github/workflows/raven-serverless.yml` jobs `rust-linux` / `rust-macos` run that smoke. Experimental CLI default listen `/ip4/0.0.0.0/tcp/0`. |

### 2.2 Noise handshake / secure channel

| | |
|--|--|
| **Desired** | TCP (and relay streams) authenticate with libp2p Noise and multiplex with Yamux; QUIC uses QUIC transport security. Transport auth ≠ Raven E2EE. **documented** — NAT Connectivity §2; ADR-0002 invariants; Carrier Conformance. |
| **Status** | **present** for localhost TCP+Noise and authenticated QUIC. |
| **Evidence** | `noise::Config::new` + `yamux::Config::default` in both `build_swarm` and `build_connectivity_swarm` (`src/main.rs:126–129`, `src/connectivity.rs:246–252`). Tests: `fixed_localhost_nodes_connect_over_noise_tcp`, `fixed_localhost_nodes_connect_over_authenticated_quic`. Identify protocol strings `/raven/identify/1.0.0` (default) and `/raven/connectivity/1.0.0` (experiment). No custom Noise pattern; rust-libp2p XX defaults (**inferred**). |

### 2.3 Kademlia peer discovery / routing

| | |
|--|--|
| **Desired** | Signed `PeerRecord` MAY be published into a Kademlia DHT. The V1 laboratory path must still dial explicit multiaddrs. Public Internet Kad is **BLOCKED_HARDWARE**. **documented** — Transport Interface §5–6; Interop matrix “DHT discovery / live libp2p DHT network”. |
| **Status** | **partial**: local MemoryStore put/get + two-node smoke **present**. Routing table / provider records / public bootstrap DHT **missing**. Kad is **absent** from the NAT-connectivity behaviour. |
| **Evidence** | Protocol `/raven/kad/1.0.0` (`src/main.rs:22`). Server mode always (`kad.set_mode(Some(Mode::Server))`, `src/main.rs:137`). Query timeout 20s (`src/main.rs:135`). Serve writes local store then `put_record(..., Quorum::One)` (`src/main.rs:251–264`). Dial `get_record` after connect (`src/main.rs:364–366`) and verifies Ed25519 (`src/main.rs:376–382`). Smoke: `libp2p_swarm_smoke.sh`. Bootstrap is **manual-peer JSON** (`bootstrap-init` / `bootstrap-show`); `cmd_dial` prints `effective_peers()` but still dials the CLI `--peer` only (`src/main.rs:315–333`). `raven-swarm::connectivity` has **no** `kad` field. |

### 2.4 Circuit Relay v2 — client role

| | |
|--|--|
| **Desired** | Bounded Circuit Relay v2 client: operator-supplied relay ending in `/p2p/<peer>`, derive one `/p2p-circuit` reservation, no compiled-in relay address. Relay is not a trust grant. **documented** — NAT Connectivity §2, §4. |
| **Status** | **present** in the P3 carrier (2026-10, held): reservations on at most 2 relays and a circuit both ways between two clients through a dedicated relay, on loopback; real-network rows pending. Experimental binary: client transport + reservation request on localhost only. Default `raven-swarm` binary: **missing**. |
| **Evidence** | P3: relay slots in raven-node `src/p2p.rs` (renewed by libp2p; a lost or refused reservation is re-requested with backoff; a `/dns*/` relay is re-resolved before every attempt). `carrier_matrix` C6 (`c6_forced_relay_both_ways_and_strangers_are_refused`): A and B have no listener, reach R only through a recording proxy, and deliver both ways over the circuit; the relayed bytes hold no Raven magic, text or identity bytes. C12 / C13: a re-homed endpoint reserves again on the same relay. raven-swarm `host.rs` test `a_fresh_endpoint_reserves_again_while_the_old_one_still_holds_its_reservation`. Experimental binary (2026-09-04): feature `libp2p/relay` (`Cargo.toml`). `relay::client::Behaviour` (`src/connectivity.rs:226`). `with_relay_client(noise, yamux)` (`src/connectivity.rs:252`). `relay_reservation_address` (`src/connectivity.rs:194–219`). Test `operator_supplied_local_relay_accepts_a_client_reservation` (`src/connectivity.rs:519`) asserts `ReservationReqAccepted` only. Experimental CLI `--relay` (`src/bin/raven-swarm-connectivity-experimental.rs:41–42`, listen at `:78–82`). Event logs: `relay=reservation_accepted|renewed`, `outbound_circuit_established`, `inbound_circuit_established` (`:131–145`). |

### 2.5 Circuit Relay v2 — hop / server role

| | |
|--|--|
| **Desired** | Checklist §31: implement Circuit Relay v2, limit reservations / relayed bandwidth / streams. Security errata: Circuit Relay is a live byte relay, not a mailbox; iOS must not be assumed always-on hop. **documented** as a checklist/target, **not** as a Raven-operated public relay (NAT Connectivity §4: “Raven does not operate or prefer a relay in this profile”). |
| **Status** | **present** in raven-node (2026-10, held): `raven-node relay` (dedicated, own key, no Raven identity; the relay kit installs it) and, in Phase 2, the friend relay inside `raven-node service` (`raven-node/src/friend_relay.rs`: its own key, TCP+QUIC 7427, members = verified contacts + manual allow − deny; held by `FRIEND_RELAY_PRODUCTION_ENABLED=false`; `raven relay offer on`, `service --relay` and `--relay-open` are its consent). Relaying under the service's own PeerId is debug-only (`RAVEN_LAB_P2P_PROFILE_RELAY=1`). Allow-list on by default (members may connect, reserve and open circuits to each other; a peer gate refuses everyone else); a dedicated `--open` serves anyone, with stricter limits. Still **missing** in the `raven-swarm` binaries, where it exists only as a **test-only** hop helper. |
| **Evidence** | P3: `build_relay_swarm` / `RelayBehaviour` and `RelayLimits` (hard maxima `RELAY_HARD_MAX`) + `RelayGuard` (allow-list, per-IP reservation cap, per-source rates) in `src/host.rs`; raven-node `src/relay.rs` (`run_relay`). Tests in `host.rs`: `a_peer_off_the_allow_list_cannot_reserve`, `per_ip_reservation_cap_holds_and_frees_on_close`, `circuit_byte_cap_cuts_the_circuit`, `circuit_duration_cap_closes_the_circuit`. `carrier_matrix` C6 (a stranger cannot reserve on R) and the netns C7 runs. Experimental binary (2026-09-04): `TestRelayBehaviour` uses `relay::Behaviour::new` (`src/connectivity.rs:309–337`) solely for the reservation integration test. Experimental profile comment: “There is no relay service or AutoNAT server in this profile” (`src/connectivity.rs:222–223`). Default swarm comment: “It is not a Circuit Relay server” (`src/main.rs:236–237`). |

### 2.6 Circuit Relay v1

| | |
|--|--|
| **Desired** | Not specified. In-tree references are Circuit Relay **v2** only. **documented** (absence of v1 requirement). |
| **Status** | **missing** (not applicable to current rust-libp2p pin). |
| **Evidence** | Grep of `raven-swarm` / protocol NAT docs: v2 + `/p2p-circuit` only. |

### 2.7 Relay fallback when direct dial fails

| | |
|--|--|
| **Desired** | Architecture V2: Direct → **relay connection** → DCUtR upgrade; mailbox last. Checklist §35: attempt direct Internet P2P, NAT traversal, then relay fallback, then store-and-forward. Transport Interface `plan_paths`: Direct → Internet → Relay → Bridge → Store. **documented**. |
| **Status** | **present** in raven-node `p2p::dial` (2026-10, held): direct addresses first, then circuits through the contact's relays, at most two connection attempts at once (dial concurrency factor 2). Still **missing** as a libp2p sequencer in the `raven-swarm` binaries. Application `plan_paths` **present** as policy, default **off**, and not wired to Circuit Relay dials. |
| **Evidence** | P3: `dial` in raven-node `src/p2p.rs`; `with_dial_concurrency_factor(2)` in `build_endpoint_swarm` (`src/host.rs`); `carrier_matrix` C6 (`--carrier p2p` and `auto`). `raven-swarm` binaries (2026-09-04): see [§3 Relay fallback sequence](#3-relay-fallback-sequence-from-code). Default dial: `OutgoingConnectionError` returns immediately (`src/main.rs:369–370`). Experimental CLI dials operator `--dial` addresses up front; it does not wait for direct failure before reserving or dialing a circuit (`src/bin/raven-swarm-connectivity-experimental.rs:78–88`). `MessageRouter` default `relay_enabled: false` (`message_router.rs:63`); `NodePolicy.relay: false` (`node_policy.rs:36`). Test `relay_and_store_are_ordered_fallbacks_not_delivery_claims` (`transport.rs:222`) proves **policy order only**. |

### 2.8 DCUtR / hole punching

| | |
|--|--|
| **Desired** | DCUtR upgrades an **existing relayed** connection to direct. New authenticated connection ⇒ new Raven link context. Not WebRTC ICE. **documented** — NAT Connectivity §2 / §2.1; Carrier Conformance; Architecture V2 “do not take DCUtR before relay”. |
| **Status** | **partial** (2026-10): the P3 endpoint composes DCUtR, and the netns C7 cone run asserts the upgrade (advisory lab job); live rows R3 / R5 are pending. A Raven link never moves: after an upgrade the next link opens on the direct connection. Experimental binary: **untested** composition, no test waits for `dcutr=direct_connection_established`. Default swarm: **missing**. |
| **Evidence** | P3: `dcutr` in `EndpointBehaviour` (`src/host.rs`); `node/scripts/netns_nat_dcutr.sh` cone run (`raven-node p2p: direct connection upgraded (dcutr)`, then `path=hole_punched` with the routers' kernel counters showing the direct path), symmetric run (every message `relayed`). Experimental binary (2026-09-04): `dcutr: dcutr::Behaviour::new(local_peer_id)` (`src/connectivity.rs:270`). CLI match on `RavenConnectivityBehaviourEvent::Dcutr` (`src/bin/raven-swarm-connectivity-experimental.rs:124–129`). `NAT_STATUS` and `node/NAT_TRAVERSAL.md` list DCUtR live matrix as not run. No `#[test]` / smoke script references DCUtR success. |

### 2.9 Symmetric NAT / CGNAT paths

| | |
|--|--|
| **Desired** | Checklist §31: test public-to-NAT, NAT-to-NAT, carrier-grade NAT, restrictive firewalls. Transport Interface / `NAT_STATUS`: live matrix **BLOCKED_HARDWARE**. **documented**. |
| **Status** | **missing** in swarm tests. Software substitute is Docker L2 isolation (**not** symmetric NAT or CGNAT mapping). |
| **Evidence** | `raven_core::discovery::NAT_STATUS` (`discovery.rs:157–158`). `scripts/nat_docker_sim.sh` header: “Does NOT claim live CGNAT/DCUtR”. RESULT.txt `not_claimed=public_CGNAT,DCUtR,AutoNAT`. No netfilter `SNAT`/`MASQUERADE`/`--random` / cone-vs-symmetric harness. Linux `unshare` netns: documented as unused (`docs/NAT_SOFTWARE_SIM.md`). |

### 2.10 AutoNAT / observed address discovery

| | |
|--|--|
| **Desired** | Detect public reachability; advertise only valid addresses; AutoNAT is a reachability **signal**, never an authorization oracle. AutoNAT **client only** in the experiment; no compiled-in AutoNAT server. **documented** — NAT Connectivity §2, §5; checklist §31. |
| **Status** | **partial** (2026-10): AutoNAT v2 **client** on the P3 endpoint and an optional **server** on `raven-node relay --autonat-server`, whose dial-backs `DialBackGuard` limits to globally routable addresses. Phase 1 rule (any-network plan item 5): one client per relay slot, each scoped to its own relay, and `public` only when two of the node's own relays on different networks (/24 for IPv4, /48 for IPv6) both reached it; with one such relay status says at most `unconfirmed`. The verdict is a status hint, never trust. No CI test asserts a reachable verdict yet (netns `reach` run planned). Experimental binary: client only. Default swarm: Identify only, **no** AutoNAT. |
| **Evidence** | P3: `autonat` in `EndpointBehaviour`, `autonat_server` + `dial_back_guard` in `RelayBehaviour` (`src/host.rs`); test `dial_backs_reach_only_global_addresses`; the verdict in raven-node `src/p2p.rs` (`raven status` row `reachability`). Experimental binary (2026-09-04): `autonat::v2::client::Behaviour` (`src/connectivity.rs:228`, constructed `:271`). Defaults: probe interval 30s, max candidates 8, hard max 16 (`src/connectivity.rs:29, 119–120`). CLI logs `autonat=reachable|probe_failed` (`src/bin/raven-swarm-connectivity-experimental.rs:117–122`). Experimental Identify: `with_push_listen_addr_updates(true)`, cache 64 (`src/connectivity.rs:260–263`). Default Identify has no push-listen flag (`src/main.rs:138–141`). |

### 2.11 Backpressure / connection limits

| | |
|--|--|
| **Desired** | Finite connection budgets; no unlimited path. NAT Connectivity §3 table. Mailbox: bounded streams/bytes. Application forward queue: peer rate limits. **documented**. |
| **Status** | **present** on the P3 endpoint and relay (2026-10) and on the experimental NAT profile (limits + admission test). **partial** on mailbox (stream/byte/object caps). **missing** on default `raven-swarm` (no `connection_limits` behaviour). Yamux windowing left at rust-libp2p defaults (**inferred**, no Raven override). |
| **Evidence** | P3 (`src/host.rs`): the endpoint admits 64 established and 16 pending connections, 3 per peer, plus per-IP limits (`IpLimits`), with an outbound reserve (`OUTBOUND_RESERVE`); `limits` and `ip_limits` are asked first (test `limits_come_first_and_outbound_keeps_a_reserve`). The relay applies `RelayLimits` (validated against `RELAY_HARD_MAX`) and `RelayGuard`'s per-source rates, bounded tables (`rate_tables_are_bounded_and_pruned_on_the_timer`). Experimental profile (2026-09-04): `ConnectionBudget` defaults / hard maxima (`src/connectivity.rs:26–54`, `86–94`). Swarm: idle 90s, notify buffer 32, per-connection event buffer 32, dial concurrency 4, max negotiating inbound 64, connection timeout 10s (`src/connectivity.rs:277–287`). Test `zero_pending_inbound_budget_rejects_localhost_dial` (`src/connectivity.rs:562`). Mailbox: `MAX_CONCURRENT_STREAMS=32`, `MAX_REQUEST_SECONDS=8`, `MAX_REQUEST_BYTES`, `MAX_OBJECTS_PER_TAG=64` (`src/mailbox.rs:24–35`, `100–102`). Tests: `codec_rejects_oversize_and_noncanonical_frames`. Adjacent (not swarm): `ForwardQueue` `MAX_FORWARD_QUEUE=512`, per-peer 64 pending / 30 enqueues / 256 KiB per window (`forward_queue.rs:65–73`). Default swarm idle timeout 60s only (`src/main.rs:149`). |

### 2.12 Additional axes found in code

| Axis | Desired (confidence) | Status | Evidence |
|------|----------------------|--------|----------|
| QUIC listen / dial | Target rust-libp2p QUIC+TCP (**documented**, ADR-0002). | **partial**: listen attempted; localhost QUIC connect **present** in experimental tests; default serve may `quic_listen_skip` (`src/main.rs:200–203`); smoke prefers TCP dial address (`src/main.rs:220`). | `with_quic()` both hosts; test `fixed_localhost_nodes_connect_over_authenticated_quic`. |
| Identify / agent string | Connectivity profile Identify `/raven/connectivity/1.0.0` (**documented**). | **present** (protocol id). Observed-addr consumption **untested**. | See §2.10. |
| Manual bootstrap / no Raven defaults | §30 manual-peer-only (**documented** in smoke comments). | **present** for config file + smoke; **not** used as Kad bootstrap list in `cmd_dial`. | `bootstrap-init`, `node/scripts/bootstrap_manual_peer_smoke.sh`, CI. |
| PeerId ≠ Raven identity | Domain-separated libp2p key (**documented** in `src/main.rs` header). | **present**. | `libp2p_keypair_from_raven` (`src/main.rs:108–118`); smoke greps the note. |
| Experimental runtime hold | Feature gate insufficient without CLI ack (**documented**). | **present**. | `require_experimental_runtime_opt_in`; CI `expect_failure_with_message` in `raven-serverless.yml`. |
| Offline mailbox / store-carry | Mailbox last after live paths (**documented**, Architecture V2). | **partial**: gated PUT/GET localhost **present**; not a NAT fallback. | `localhost_put_survives_sender_disconnect_and_store_restart`; `node/scripts/swarm_mailbox_smoke.sh`. |
| Production NAT activation | ATSAM integration, abuse tests, relay policy, mobile lifecycle, soak (**documented**, NAT Connectivity §6). | **missing** (hold). | Spec §6; `PRODUCTION_NAT_CONNECTIVITY_ENABLED`. |

---

## 3. Relay fallback sequence (from code)

There are **three** “relay” stories. They are not one pipeline.

### 3.1 Default `raven-swarm` dial (no Circuit Relay)

```
operator supplies --peer multiaddr + --peer-id + --raven-pub-hex
        │
        ▼
load bootstrap.json  ──► print bootstrap_mode / peers
        │                 (not consulted as a dial fallback list)
        ▼
kad.add_address(peer, addr)
swarm.dial(addr /p2p/<peer>)
        │
        ├─ OutgoingConnectionError ──► return Err("dial error: …")   STOP
        ├─ wall clock > --timeout-secs (default 30s) ──► "dial timeout"
        └─ ConnectionEstablished
                │
                ▼
           kad.get_record(dht_key)     query timeout 20s
                │
                ├─ FoundRecord + Ed25519 verify ──► OK
                └─ GetRecord Err ──► return Err
```

No `/p2p-circuit` rewrite, no second dial, no store-carry handoff inside this binary.

### 3.2 Experimental connectivity binary (composition, not a fallback state machine)

Order in `main` (`src/bin/raven-swarm-connectivity-experimental.rs:58–88`):

1. Refuse unless `--enable-experimental-nat-connectivity`.
2. Bound `run_seconds` ∈ (0, 3600] and `--dial` count ≤ 8.
3. `build_connectivity_swarm` (TCP + QUIC + relay **client** + DCUtR + AutoNAT **client** + limits).
4. `listen_on(listen_tcp)` then `listen_on(listen_quic)`.
5. **If** `--relay` is set: `listen_on(relay_reservation_address(relay))` — reservation starts **now**, not after a failed direct dial.
6. **For each** `--dial`: `swarm.dial(addr)` immediately (queued). rust-libp2p may race up to `dial_concurrency_factor = 4` addresses; connection timeout 10s.
7. Event loop until deadline / SIGINT. Logs connection, AutoNAT, DCUtR, and relay circuit events. **No payload protocol.**

What this does **not** contain (searched; not present):

- a timeout that promotes a failed direct multiaddr to a `/p2p-circuit` dial;
- selection among multiple relays;
- automatic DCUtR *before* a relayed connection exists (library DCUtR also requires an existing relayed path — **inferred** from the libp2p DCUtR spec cited in-tree);
- mailbox fallback.

If the operator passes a `/p2p-circuit` address in `--dial`, rust-libp2p’s relay client would attempt that circuit (**inferred** from `with_relay_client`). Raven does not construct that address on failure.

### 3.3 Application `plan_paths` (raven-core, not raven-swarm)

```
if peer_reachable_direct          → Direct
if local_has_internet
   && peer_reachable_internet     → Internet
if relay_enabled
   && local_has_internet          → Relay      # policy bit, default false
if bridge_enabled && cross-radio  → Bridge
if store_enabled                  → Store
else                              → Unavailable
```

`select_path` returns the first entry. Comment at `transport.rs:107–109`: callers that retry should walk `plan_paths`, not recompute after each failure. No `raven-swarm` caller walks this list into Circuit Relay dials. `raven-node` bridge runtime copies `policy.relay` into `MessageRouter` (`bridge_run.rs:43`) but that router forwards **opaque envelopes** across LAN/mock-BLE — it does not open a libp2p circuit.

### 3.4 Desired order vs actual

| Step | Desired (Architecture V2 / checklist) | Actual `raven-swarm` |
|------|---------------------------------------|----------------------|
| 1 | Direct TCP/QUIC | Yes, if the operator/smoke supplies a reachable multiaddr |
| 2 | Relay **connection** (circuit) when direct fails | No automatic fallback. Reservation only if `--relay` given up front |
| 3 | DCUtR upgrade over that relayed connection | Behaviour present; untested; library-driven |
| 4 | Mailbox last | Separate experimental binary; not invoked from connectivity or default dial |

---

## 4. NAT simulation: covered vs desired

### 4.1 What runs today

| Harness | What it actually proves | libp2p / raven-swarm? | CI |
|---------|-------------------------|-----------------------|----|
| `fixed_localhost_nodes_connect_over_noise_tcp` | Two swarms on `127.0.0.1` TCP+Noise | Yes (experimental feature) | `cargo test -p raven-swarm --all-features --all-targets` in `rust-linux` |
| `fixed_localhost_nodes_connect_over_authenticated_quic` | Same for QUIC-v1 | Yes | same |
| `operator_supplied_local_relay_accepts_a_client_reservation` | Client reservation accepted by **test-only** hop on localhost | Yes (client + test hop) | same |
| `zero_pending_inbound_budget_rejects_localhost_dial` | Pending-inbound=0 refuses establish | Yes | same |
| `runtime_gate_*` / `relay_reservation_is_operator_supplied_*` / `unsafe_budget_*` | Config gates, address canonicalization | Yes | same |
| `node/scripts/libp2p_swarm_smoke.sh` | Two-node Kad put/get + Noise TCP on localhost | Default binary | `rust-linux`, `rust-macos`; also `scripts/final_serverless_proof.sh` step 13 |
| `node/scripts/bootstrap_manual_peer_smoke.sh` | Manual-peer bootstrap JSON | Default binary | `rust-linux`, `rust-macos` |
| `node/scripts/swarm_mailbox_smoke.sh` | Gated mailbox PUT/GET + restart | Mailbox binary | `rust-linux` |
| `scripts/nat_docker_sim.sh` | Two Docker bridge nets; A cannot TCP to B; dual-homed container can TCP-echo both | **No** | **Not** in `raven-serverless.yml`. Optional in `scripts/reliability_matrix_20.sh` (SKIP if no Docker / `SKIP_DOCKER=1`) |
| `cargo test -p raven-core --test network_sim_1000` | 1,000-node DTN policy model | **No** | `rust-linux` |
| `node/scripts/internet_dial_smoke.sh` | Raw InternetTransport origination **must fail** (`ATSAM_SESSION_REQUIRED`) | **No** (negative gate) | `rust-linux` |
| Experimental binary without flag | Process exits with opt-in error | Yes | `rust-linux` `expect_failure_with_message` |

`docs/NAT_SOFTWARE_SIM.md` also lists pfctl (manual, root, not automated) and Linux `unshare` (not used on the documented Mac path).

### 4.2 Desired but missing (from existing docs — not new requirements)

From checklist §31, Transport Interface §5–6, NAT Connectivity §6, `node/NAT_TRAVERSAL.md`, Interop matrix:

| Desired scenario | In-tree today |
|------------------|---------------|
| Public-to-public / public-to-NAT / NAT-to-public / NAT-to-NAT with **raven-swarm** | Missing |
| Symmetric NAT and CGNAT mapping behavior | Missing (Docker bridges are not CGNAT) |
| Restrictive firewall / Wi-Fi↔cellular / IP change | Missing |
| AutoNAT probes against a real or in-tree v2 server | Client only; no server; no test |
| Two-client circuit (A↔hop↔B) carrying Raven bytes | Missing (reservation only) |
| DCUtR success after circuit | Untested |
| DCUtR fail → remain on relay (safe fallback) | Untested |
| Relay loss / reconnection / reservation renewal under failure | Renewal is logged; not tested |
| Independently operated public relays | Missing (operator-supplied only; none shipped) |
| Public Internet Kademlia | BLOCKED_HARDWARE |
| Linux netns NAT classes | Documented as a gap; no harness |
| Production ATSAM-on-libp2p soak | Hold (spec §6) |

### 4.3 Reproducible gaps vs aspirational

**Reproducible** here means: a test, script, CI job, or marker that can be re-run and will show the gap (fail, skip, assert a hold, or is conspicuously absent next to a named claim).

#### Reproducible (can point at a file and re-run)

| Gap | Kind | Pointer |
|-----|------|---------|
| Live multi-NAT/CGNAT/DCUtR not claimed | Constant + unit test | `node/crates/raven-core/src/discovery.rs:157–158` (`NAT_STATUS`); test `nat_status_mentions_blocked_hardware` (`discovery.rs:203–205`) |
| Docker NAT sim is topology-only and **skips green** without Docker | Script SKIP exit 0 | `scripts/nat_docker_sim.sh:14–21`, `:34–44`; `not_claimed=public_CGNAT,DCUtR,AutoNAT` at `:186–190` |
| Docker NAT sim **not** in required CI | Workflow omission | `.github/workflows/raven-serverless.yml` has swarm/mailbox/internet smokes; no `nat_docker_sim.sh` |
| Raw Internet path is fail-closed (not a NAT proof) | Negative smoke | `node/scripts/internet_dial_smoke.sh:56–63` |
| No DCUtR / AutoNAT / circuit-through-hop test exists | Absence next to composed behaviours | `src/connectivity.rs` tests end at reservation + limits (`:423–598`); no `Dcutr` / `AutoNat` / `OutboundCircuitEstablished` assertion |
| Default swarm has no relay fallback | Immediate error | `src/main.rs:369–370` |
| Experimental host requires dual gate | CI-enforced hold | `raven-serverless.yml` `expect_failure_with_message` “…requires explicit runtime opt-in” |
| Checklist §31 still open | Unchecked boxes | `docs/MASTER_ENGINEERING_CHECKLIST.md:1048–1072` |
| Transport Interface still says Circuit/DCUtR incomplete | Spec status | `protocol/RAVEN_TRANSPORT_INTERFACE_V1.md:55`, `:64` |
| Interop matrix pending row | Spec status | `protocol/RAVEN_INTEROPERABILITY_MATRIX.md:21`, `:32` |
| `network_sim_1000` must not be read as NAT evidence | Spec + test header | `protocol/RAVEN_NETWORK_SIMULATION_1000_V1.md:13–16` |
| Application relay policy default off | Defaults | `message_router.rs:63`; `node_policy.rs:36` |

There are **no** `#[ignore]` / `#[should_panic]` DCUtR or NAT tests in `raven-swarm`. The gap is **missing coverage**, not a red or flaky test. No flake markers were found on the connectivity tests.

#### Aspirational (stated as future gates, not a failing harness)

- Carrier-grade NAT matrix on real networks (`node/NAT_TRAVERSAL.md` “Not yet run”).
- Independently operated public relays + abuse testing (NAT Connectivity §6).
- Mobile lifecycle / Wi-Fi–cellular transitions (checklist §31).
- Production enablement after ATSAM endpoint/session integration on Rust and iOS (NAT Connectivity §6).
- Treating Docker dual-bridge or localhost reservation as CGNAT/DCUtR (explicitly forbidden by `docs/NAT_SOFTWARE_SIM.md` “Honest claim”).

---

## 5. Config flags and CI map

| Flag / job | Effect |
|------------|--------|
| `experimental-nat-connectivity` | Compiles `connectivity` + `raven-swarm-connectivity-experimental`; pulls `libp2p/{autonat,dcutr,relay}` + `rand`. |
| `--enable-experimental-nat-connectivity` | Runtime ack; required in addition to the feature. |
| `--relay <multiaddr>` | Operator relay; must end in exactly one `/p2p/<peer>`. |
| `--dial <multiaddr>` | Repeatable, max 8. |
| `--listen-tcp` / `--listen-quic` | Default `0.0.0.0` ephemeral. |
| `--run-seconds` | Default 60; hard max 3600. |
| `experimental-offline-mailbox` / `--allow-experimental-mailbox` | Separate mailbox host. |
| Default `raven-swarm serve --quic` | Attempt QUIC listen; skip on error. |
| `p2p-host` (2026-10) | Compiles `raven_swarm::host` (endpoint + relay; `libp2p/{autonat,dcutr,relay,upnp}` + `libp2p-stream`). Only raven-node enables it. |
| `wss` (Phase 4) | Implies `p2p-host`. Compiles `raven_swarm::wss` (relays over WebSocket/TLS, `protocol/RAVEN_WSS_TRANSPORT_V1.md`); so far its TLS layer (`wss/tls.rs`: TLS 1.3 on aws-lc-rs, the relay's ephemeral or operator certificate), its WebSocket subset (`wss/ws.rs`: the upgrade and a byte stream over binary frames, on raven-core's `ws_frame`; no WebSocket crate) and its HTTP CONNECT client (`wss/connect.rs`: the proxy's name to the system resolver, the target never resolved locally, fixed error texts). Its crates (rustls, futures-rustls, rcgen, time, httparse, ring, base64, zeroize) were already built through libp2p: no new package. Only raven-node enables it; `WSS_PRODUCTION_ENABLED=false` holds it. |
| `P2P_PRODUCTION_ENABLED` (`raven-core/src/p2p_gate.rs`) | `false`: no host is built, so nothing listens, dials, reserves or advertises; debug builds open it with `RAVEN_LAB_TEST_A=1` (lab only). |
| `raven-node service --p2p-listen PORT\|IP:PORT\|relay\|off` | Opt-in endpoint (also `RAVEN_P2P_LISTEN`, `raven node p2p on`); default port 7423, TCP + QUIC, IPv4 + IPv6. |
| `--p2p-relay <multiaddr>` | Repeatable, at most 2, each ending in `/p2p/<relay PeerId>` (also `RAVEN_P2P_RELAYS`, node policy); none compiled in. |
| `--p2p-proxy auto\|off\|http://host:port` (Phase 4) | HTTPS proxy of relay dials over WebSocket/TLS (also `RAVEN_P2P_PROXY`, node policy `p2p_proxy`, which `raven node proxy` sets and shows without credentials; `auto`: `HTTPS_PROXY`, then the system settings); a bad value stops the host. Held by `WSS_PROXY_PRODUCTION_ENABLED=false`. `raven status` names a relay over WSS (through the proxy), the restricted network, and a proxy script (PAC) or a proxy that wants Windows sign-in (NTLM/Negotiate). |
| `service --relay` / `--relay-open` | Consent for the friend relay (Phase 2, held by `FRIEND_RELAY_PRODUCTION_ENABLED=false`): the service relays for the profile's verified contacts (not blocked ones, nor ones it hides its IP from), plus its manual `relay_allow.json`, minus its deny list, under a relay key of its own on TCP+QUIC 7427, never the user's PeerId (`--relay-open` is an alias). The Phase 1 relay under the user's own PeerId runs only with the debug switch `RAVEN_LAB_P2P_PROFILE_RELAY=1`. |
| `raven-node relay --data-dir <dir> [--open] [--autonat-server] [--external <multiaddr>] [--also-tcp <LOCAL[:PUBLIC]>] [--public-host <host>] [--check]` | Dedicated relay with its own key; optional AutoNAT v2 server (dial-backs to global addresses only); extra TCP ports such as 443; the relay kit installs it ([`../RELAY_KIT.md`](../RELAY_KIT.md)). Phase 4 (lab-only while `WSS_PRODUCTION_ENABLED=false`): `--wss <PORT\|IP:PORT>` adds the two-protocol WebSocket/TLS listener, and `raven relay card --wss [--host H] [--wss-port P]` prints its `/tls/ws` lines (a `--host` name as `/dns/<name>`, also the TLS name). |
| CI `carrier_matrix` (`cargo test -p raven-node --test carrier_matrix -- --ignored`) | ubuntu, macOS and Windows: C6 forced relay, C12 network switch, C13 silent relay path (debug lab unlock). |
| CI `cargo test -p raven-swarm --features p2p-host --lib` | macOS and Windows (ubuntu runs `--all-features`): the host's unit and loopback tests. |
| Lab CI `nat-sim-linux` (`raven-serverless-lab.yml`) | `node/scripts/netns_nat_dcutr.sh` (C7) on ubuntu, **advisory** (`continue-on-error`). |
| CI `cargo clippy -p raven-swarm --all-features` | Experimental trees and `p2p-host` must be warning-clean. |
| CI `cargo test -p raven-swarm --all-features --all-targets` | Runs §4.1 localhost proofs and the `p2p-host` tests. |
| CI does **not** run | `scripts/nat_docker_sim.sh`, public NAT, CGNAT or hotspot paths, an AutoNAT server check. DCUtR runs only in the advisory netns job. |

---

## 6. Honest summary

Localhost Noise/TCP, QUIC, Kad put/get, connection-limit admission, and a **client reservation** against a test hop are real in the `raven-swarm` binaries. Since 2026-10, raven-node's P3 carrier (held by `P2P_PRODUCTION_ENABLED=false`) adds a real Circuit Relay v2 **hop** (`raven-node relay`, `service --relay`), reservations on up to two relays, relay fallback in `p2p::dial`, and a re-home on network changes, proven on **loopback** on three OSes (C6, C12, C13); DCUtR upgrades only in the **advisory** Linux netns simulation (C7). AutoNAT has a client and an optional relay-side server, but no test yet asserts a reachable verdict, and the Phase 1 rule (`public` only from two of the node's own relays on different networks) is a design, not evidence. Real symmetric NAT / CGNAT / hotspot paths and any public DHT are **not proven**; loopback and netns runs are not a WAN claim.

Founder WAN question (two terminals on the public Internet, direct path): **not proven** — see [§0](#0-founder-terminal-to-terminal-direct-internet).

---

## 7. See also

- [§0 Founder: terminal-to-terminal direct Internet](#0-founder-terminal-to-terminal-direct-internet)
- [`protocol/RAVEN_NAT_CONNECTIVITY_V1.md`](../../protocol/RAVEN_NAT_CONNECTIVITY_V1.md)
- [`protocol/RAVEN_TRANSPORT_INTERFACE_V1.md`](../../protocol/RAVEN_TRANSPORT_INTERFACE_V1.md)
- [`docs/adr/0002-internet-transport.md`](../adr/0002-internet-transport.md)
- [`docs/NAT_SOFTWARE_SIM.md`](../NAT_SOFTWARE_SIM.md)
- [`node/NAT_TRAVERSAL.md`](../../node/NAT_TRAVERSAL.md)
- [`protocol/RAVEN_NETWORK_SIMULATION_1000_V1.md`](../../protocol/RAVEN_NETWORK_SIMULATION_1000_V1.md)
