# RAVEN Threat Model — Serverless P2P (Phase A)

> **2026-08-13 security correction:** RVN1 is under a production hold. The
> audit found a publicly derivable interim cipher, plaintext/unverified ACK
> paths, ACK-before-decrypt/commit, pre-authentication dedup poisoning, and
> unauthenticated mutable hop ceilings. Until the gates in
> [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md)
> pass, every older “Protected” verdict that depends on endpoint E2EE, ACK
> authentication, replay/dedup ordering, ratchet durability, or bounded
> multi-hop forwarding is superseded by **Not protected in the audited
> implementation / fail-closed containment in progress**. The adversary
> descriptions remain useful; they are not release evidence.

**Status:** Audited design record under the RVN1 production hold. The detailed
verdicts below describe the intended/frozen design and are **not release
claims**. The executable posture in the table immediately below is normative;
it supersedes every older `Protected` label until the corresponding gate is
closed. `raven-security/THREAT_MODEL.md` is retained only as a pre-pivot
historical snapshot.

### Current executable posture (2026-08-13)

| Area | Current verdict | Evidence / remaining gate |
|---|---|---|
| Content confidentiality | **Fail-closed, not production-enabled** (except the LAN-direct slice, see its row below) | Public-material demo sealers are disabled and plaintext carrier admission is rejected. Outside the LAN-direct slice, a transcript-bound, persisted ATSAM session is not yet active. |
| Message/ACK endpoint acceptance | **Fail-closed, production-disabled** | Rust and Swift (**OFF-MAIN**, unverified from this tree) reference actors now verify PairInit-bound device certificates, route/AAD/AEAD, exact inbox/outstanding rows, sealed ACKs, replay state, and recoverable message/ACK journals. Swift concrete Keychain/SQLCipher/queue adapters, a bound ACK sender, live wiring, and external review remain gates; the Rust actors are wired live only for the LAN-direct slice below. |
| Relay/store opacity | **Partially implemented** | Queues store immutable opaque envelopes and deduplicate by authenticated-object digest. Production route/mailbox keys still require the authenticated session actor. |
| Replay/dedup | **Implemented in disabled reference actors** | Relay cache poisoning by attacker-chosen IDs is contained. Rust and Swift (**OFF-MAIN**) reference actors commit authenticated object/logical-ID/ACK-nonce replay state with their ratchets; live paths remain disabled (except the LAN-direct slice below) until concrete adapters and integration pass review. |
| Resource exhaustion | **Bounded at audited wire boundaries** | Go bridge and raw Rust TCP handlers cap streams/handlers, declared bytes, frame size, and deadlines before allocation. The gated NAT profile also caps pending/established/per-peer connections and AutoNAT candidates. Peer scoring/Sybil resistance remains future work. |
| Hop/replication ceilings | **Cooperative-policy only** | RVN1 does not authenticate mutable hop fields. No Byzantine forwarding bound is claimed until a versioned custody wrapper exists. |
| Revocation freshness | **Partition-limited** | Local deny lists and certificate expiry work; V1 has no globally fresh signed revocation distribution guarantee. |
| LAN-direct slice (terminal to terminal) | **Live in default builds; unreviewed; not a release claim** | `raven_core::lan_gate::LAN_DIRECT_PRODUCTION_ENABLED = true` runs Noise XX, RLB1 identity binding, PairInit V1, indexed-session v1 and sealed ACKs between `raven-node service` daemons on a LAN; the four global `PRODUCTION_ENABLED` flags (PairInit, session store, prekey lifecycle, ATSAM indexed session) stay `false`. **Trust model:** the local contact book only (`peer_is_trusted`: any `contacts.json` key, pinned or not; fingerprint pinning is not enforced by default, and `raven lan verified-only on` enforces it on the LAN, Phase 3) plus the Noise-to-RLB1 identity binding. **Known limits:** no one-time prekeys are installed, so first-contact forward secrecy is bounded by signed-prekey rotation alone ([`RAVEN_PREKEY_LIFECYCLE_V1.md`](../protocol/RAVEN_PREKEY_LIFECYCLE_V1.md) §6); IP addresses, timing and sizes are visible on the wire (§3.4, §3.17); the in-tree CI proof is Linux-only and uses the debug `locked-file` identity override (`scripts/lan_direct_two_node.sh`). **Errata gates still open for it:** monotonic one-time-prekey consumption, Rust/Swift fixture exchange (Swift is off-main), the real-device matrix and the external review; the other release-gate items have not been assessed for this slice here, so their omission is not a pass. |
| LAN observer and prober (same Wi-Fi, hotspot or cable; Phase 3) | **Partially protected; the new exposure is gated off** (`LAN_AUTO_LISTEN_PRODUCTION_ENABLED`, `LAN_BEACON_PRODUCTION_ENABLED` = `false`) | **Prober:** anyone on the network who connects to TCP 7420 reads the listener's stable Noise static key in Noise message 2, before the contact gate runs, and can recognise the device on other networks; a passive observer cannot read it. `--lan-listen auto` (gated) listens on every local interface and closes non-local sources before a byte, which widens where such a probe works; rotation waits for Phase 4 (D7, D14). **Observer of the beacon** (gated, [`RAVEN_LAN_BEACON_V1.md`](../protocol/RAVEN_LAN_BEACON_V1.md) §11): UDP 7420 datagrams in two size ranges (queries 160-191 bytes, answers 48-63: a random tail on each, sent after a random 0-500 ms delay; Phase 6b amendment) to 239.255.74.20, ff02::8000:7420 or the subnet broadcast tell that a Raven node is on the network, and a query followed by an answer within 3 s tells that two devices there know each other and that one had something to deliver; no datagram carries an identity, a timestamp, a port in the clear or a constant byte, and beacon keys are static-static (no forward secrecy for tags and ports). **Phase 6b** (built, all gated off: `LINK_PADDING_PRODUCTION_ENABLED`, `LINK_KNOCK_PRODUCTION_ENABLED`, `LISTEN_PORT_RANDOM_PRODUCTION_ENABLED`, `PAIR_SEED_PRODUCTION_ENABLED` = `false`; §3.17, [`design/2026-10-traffic-analysis.md`](design/2026-10-traffic-analysis.md)): four frame-size classes, per-connection Noise statics behind the RLK1 knock with a fresh static or no answer for strangers, a random port for new profiles and rotating pair seeds; none is in this version, and none makes passive listening detectable. **Controls:** `raven lan off` (no listener, no beacon, no LAN dial), meeting mode (`raven lan on --for`), `raven lan verified-only on`, firewall rules for the Private profile only, the beacon only on a need. Paperwork: [`WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md`](WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md) (unsigned) §4; user guide [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) §4. Evidence: carrier_matrix C27-C30, fault matrix s82 (the capture has no marker) and s83, netns `lan-move` and `lan-nonlocal`. |
| Terminal profile at rest (privacy pack, 2026-10) | **Implemented, ungated (at-rest and user-invoked only); unreviewed; not a release claim** | A desktop profile's friend metadata, message records and chat history are sealed under keys wrapped by the profile's keystore key; `raven lock`, `raven erase` (crypto-erase) and `raven privacy unseal` exist. Rows T3a, T3b, T3-erase and T4 and their limits: §3.7a. No wire change. |
| Bluetooth nearby between laptops (Phase 5, RNL1) | **Gated off** (`NEARBY_PRODUCTION_ENABLED = false`; lab: debug `RAVEN_LAB_TEST_A=1` with `RAVEN_LAB_NEARBY=1`) | Verified contacts with a cached device certificate only; a pairwise token advertised only while there is work for that contact, from a random address; the RNK1 knock comes before any Noise byte, so a stranger in radio range gets silence and never the Noise static key. **Disclosed exposure** (§1.1): the OS shows any connecting device this computer's Bluetooth name (and its model on macOS), and a BlueZ peripheral sends one pair's encrypted notifications to every subscriber. Evidence: [`RAVEN_NEARBY_LINK_V1.md`](../protocol/RAVEN_NEARBY_LINK_V1.md) §9, `shared-vectors/rvn1/nearby/`, carrier_matrix C50-C53, fault scenarios s63-s67. Remaining: hardware rows N1-N12 (an unpublished test checklist) and the unsigned [`WAIVER_NEARBY_DRAFT.md`](WAIVER_NEARBY_DRAFT.md). |
| Phase 6b: attack sensing and responses, traffic-analysis measures, Lock v2, security updates | **Built; every gate `false`; unreviewed; not a release claim** | **Design A** (local `SEC_*` events, a sealed security ledger and the responses R1-R9; `SECURITY_EVENTS_PRODUCTION_ENABLED`, `SECURITY_RESPONSES_PRODUCTION_ENABLED`, `SUITE_FLOOR_PRODUCTION_ENABLED` = `false`; [`SECURITY_EVENTS.md`](SECURITY_EVENTS.md)): what is detected and answered, and what is not, in §3.3, §3.5, §3.10, §3.11, §3.14 and §3.15. **Design B** (padding, the knock, a random port, pair seeds): §3.4 and §3.17. **Lock v2** (`LOCAL_PROTECTION_PRODUCTION_ENABLED = false`): §3.7a row T3b. **Design D** (`ADVISORY_PRODUCTION_ENABLED`, `RELEASE_BUNDLE_PRODUCTION_ENABLED`, `MESH_UPDATE_PRODUCTION_ENABLED` = `false`, and no build has release keys yet: `RELEASE_KEY_SET_V1 = None` until the key ceremony, [`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md)): §3.5, §3.10 and §3.14. None of it makes passive listening detectable. Nothing is sent to anyone: the events are local codes. Paperwork (unsigned): [`WAIVER_SECURITY_SENSING_DRAFT.md`](WAIVER_SECURITY_SENSING_DRAFT.md), [`WAIVER_TRAFFIC_ANALYSIS_DRAFT.md`](WAIVER_TRAFFIC_ANALYSIS_DRAFT.md), [`WAIVER_LOCAL_PROTECTION_DRAFT.md`](WAIVER_LOCAL_PROTECTION_DRAFT.md), [`WAIVER_SECURITY_UPDATES_DRAFT.md`](WAIVER_SECURITY_UPDATES_DRAFT.md); real rows in an unpublished test checklist (R30 waits for the attack harness P6.32, which the owner set aside). |
| Release status | **HOLD** | iOS Release hard-disables RVN1, default Rust origination requires an authenticated session, and the external security review/real-device matrix has not happened. |

This document explains, in plain language, what RAVEN is designed to protect
and what it explicitly does not protect, for the serverless peer-to-peer
architecture: no trusted central server, delivery via mesh relays and
untrusted store-and-forward nodes, addressing via a DHT-backed alias layer,
and a single frozen wire object (`RavenEnvelopeV1`) carried unchanged across
every transport.

Honest scope statements are part of the security boundary, not a marketing
afterthought. A verdict of **partially protected** or **out of scope** next
to an adversary is not an admission of failure — it is the document doing
its job. Overclaiming is the actual defect.

Every citation below points at a committed, frozen spec in `protocol/` or a
byte-exact test vector in `shared-vectors/rvn1/`, or at a specific shipped
source file — except citations tagged **OFF-MAIN** (the `ios-native/…`
Swift/Go paths), which refer to a tree that is not in this repository and are
unverified-from-main: they are not evidence for this checkout (same convention
as [`crypto/ATSAM_KAT_CONSUMER_MATRIX_V1.md`](crypto/ATSAM_KAT_CONSUMER_MATRIX_V1.md)).
If a citation and the shipped code ever disagree, the code is
wrong until proven otherwise — see §4.

---

## 1. Assets we protect

RAVEN's serverless design exists to protect:

1. **Message content.** What people say to each other, end-to-end, at rest
   in transit through every relay and store node, no exceptions.
2. **Recipient identity at the relay/store layer.** A relay or store node
   handling an envelope should not learn who it is addressed to.
3. **Nearby-peer discovery privacy.** Who is in radio/network range of whom,
   in the eyes of someone who is not the user's contact.
4. **Long-term content secrecy for opted-in (Vault Mode) messages.** A
   message a user marks Vault Mode should remain confidential against
   future computational advances (including large-scale quantum
   computation), provided the pad conditions are met.

RAVEN does **not** primarily exist to protect:

- The fact that some traffic exists, or its timing/volume/shape.
- A user's identity or data on a device the user has already lost physical
  control over while unlocked.
- Uniqueness of human-readable names (the alias namespace is deliberately
  not globally unique — see §3.13).

### 1.1 Nearby discovery over Bluetooth LE (laptops; gated off)

Asset 3 for the Bluetooth nearby carrier
([`RAVEN_NEARBY_LINK_V1.md`](../protocol/RAVEN_NEARBY_LINK_V1.md), RNL1;
user guide [`NEARBY.md`](NEARBY.md)). It is held in every build
(`NEARBY_PRODUCTION_ENABLED = false`); the table is what a release would
disclose, and what hardware row N7 must confirm
(an unpublished test checklist) before the
unsigned [`WAIVER_NEARBY_DRAFT.md`](WAIVER_NEARBY_DRAFT.md) can be signed.

| Observer | What it can learn | What it cannot learn, and the control |
|---|---|---|
| Passive radio observer in range | That a laptop advertises one random-looking 128-bit UUID, which changes every 15 minutes, only while its user has something to send to a nearby contact (or ran `raven nearby on`); the random Bluetooth address, the advertising cadence, RSSI, and the sizes and timing of the encrypted exchange. A connection sniffer also sees each connect a laptop makes to a contact that advertises for it (also with nothing to send) and the random address it comes from. Sightings within one epoch are linkable, and so are sightings across an address change and a token change that do not happen at the same moment. | No identity, fingerprint, PeerId, IP address or Raven marker is advertised; no Local Name, manufacturer data or other field (RNL1 §3). Tokens are pairwise and keyed (RNB1 §2): their values link neither two contacts nor two epochs (the address and timing can, as said left). Advertising stops with the work, `raven nearby off` or `raven nearby disable`. |
| Device that connects (any OS) | What the OS's own GATT server shows any connecting device: the **GAP Device Name** (the computer's Bluetooth name) on every OS, and **Device Information (model)** on macOS. The shape of the Raven service: one service with one characteristic (WriteWithoutResponse, Write, Notify). | No RNK1 or RNP1 answer without the pair's `K_knock`: random and replayed HELLOs get silence (constant-time tags, a replay cache over two epochs), and the stable Noise static key is never sent before the knock (RNL1 §5). Raven cannot hide the OS's GATT data: the consent of `raven nearby enable` names the actual Bluetooth name, and the guide suggests renaming the computer (owner decision O5-12). |
| Subscriber on a BlueZ (Linux) peripheral | The encrypted notifications of the pair whose service it subscribed to, while that pair's pipe is up: ciphertext, sizes and timing. BlueZ notifies every subscriber of a characteristic (no per-device targeting). | Never a plaintext byte (Noise AEAD inside RNP1). macOS and Windows peripherals notify the one central only. Disclosed in RNL1 §9 and the user guide. |
| Active replayer of a recorded beacon | A token is a public UUID: someone who recorded one near a contact and plays it back elsewhere while it still matches (its epoch and the next one, up to about 30 minutes after it was advertised) makes the laptop it was meant for connect, as it would to the contact: so it learns that this laptop is in range, and sees its random address and the knock's first frame. | At most [`TOKEN_STRIKES`](../node/crates/raven-node/src/nearby/engine.rs) (2) connects per recorded token: a knock that gets no CHALLENGE verifying under the pair key counts against that token, and a token that failed twice in a row is not dialled again while it matches (review nearby-4). The replayer learns nothing else: no identity, no key (the knock is keyed), not who the contact is beyond what it saw where it recorded the token. Disclosed in the consent of `raven nearby enable` and the user guide. |
| Stranger holding connections | It can keep GATT connections open that macOS and Windows peripherals cannot drop. | Bounded to slot exhaustion (8 knocking connections, 4 pipes per process; RNL1 §8): a denial of service no worse than jamming the radio. After 3 invalid frames the connection is ignored (dropped where the OS allows). |
| A contact | That the user is in range, and when; that the user had something to send to them. | Nothing beyond what the contact already sees on any other carrier. |
| Linux adapter without `Privacy = device` | Nothing from Raven: a node whose controller would use its fixed public address neither advertises nor connects nor scans, because a connect's CONNECT_IND carries the initiator's address in the clear as an advert carries the advertiser's (review nearby-1). | The `address` status row and `raven doctor` say nearby is inactive and how to set `Privacy = device` (admin). Windows adverts and connects count as public until row N7w shows otherwise, so Windows nearby stays inactive (a debug lab run may allow it with `RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR=1`). |

Residual: a stranger with a scanner learns that a Raven-like GATT shape and
fixed knock sizes exist on a laptop (weak fingerprints visible only to
connecting or sniffing parties), and clocks more than about 15 minutes apart
break discovery silently (availability, not privacy).

---

## 2. How to read the table

Every row below is one of the 17 adversary classes in scope for this
document. **Verdict** is one of:

- **Protected** — a concrete, cited mechanism defeats this adversary for the
  stated goal.
- **Partially protected** — some sub-case is defended with a cited
  mechanism; another sub-case is explicitly out of scope, stated with a
  reason.
- **Out of scope** — RAVEN does not defend against this today. The reason is
  stated, and, where one exists, the future-work item that would change the
  verdict.

| # | Adversary | Verdict | Mechanism / reason |
|---|---|---|---|
| 3.1 | Malicious relay | Design target; production held | Opaque envelope/object queue exists; authenticated session-derived encryption and routing are not live |
| 3.2 | Malicious store node | Design target; production held | Opaque TTL store exists; mailbox derivation is vector-only and ACK deletion is forbidden |
| 3.3 | Malicious peer (direct connection) | Partially protected | Strict parser plus bounded Go/Rust connection, byte, deadline, and gated NAT admission; endpoint reference transaction exists but is not live; Phase 6b stranger sensing and the penalty box are built but gated off |
| 3.4 | Passive ISP | Partially protected | Transport Noise hides envelope bytes; connection metadata, exact frame sizes and (for a later quantum computer) the classical link layer stay exposed; PAD1 size classes are built but gated off |
| 3.5 | Active MITM | Partially protected | QR pairing + safety number; wrong-person pairing is user's responsibility; Phase 6b's impostor stop, tamper sensing and signed updates are built but gated off |
| 3.6 | Stolen locked device | Partially protected | iOS roots use device-only Keychain; terminal backend strength is platform-dependent |
| 3.7 | Stolen unlocked device | Out of scope | Endpoint sets the floor |
| 3.7a | Terminal profile at rest (refines 3.6 and 3.7 for the desktop data directory) | Partially protected | Sealed friend metadata under the keystore key (T3a); logged-in attacker unchanged, Lock v1 stops Raven (T3b); crypto-erase (T3-erase); custodian deletion gated (T4); Lock v2 built, gated off |
| 3.7b | Learning connectivity (Phase 6a; gated off) | Partially protected | Order-only and bounded by today's static plan and waits; a network attacker causes failures only (T1/T2); meeting and route failure history sealed (T3a), readable when logged in (T3b); custodians no more than today (T4) |
| 3.8 | Sybil swarm | Partially protected | Peer/store diversity + replication budget; Peer ID ≠ identity; full defense is future work |
| 3.9 | Eclipse attacker | Partially protected | Same mitigations as Sybil; full defense is future work |
| 3.10 | Replay attacker | Design implemented; production held | Relay object-digest cache and disabled Rust/Swift authenticated endpoint replay journals are bounded; concrete live integration remains; Phase 6b replay sensing, notice rollback refusal and responses are built but gated off |
| 3.11 | Spam attacker | Partially protected | Contact-first + message requests + blocking; no central moderation (by design); Phase 6b stranger throttling is built but gated off |
| 3.12 | DHT poisoning | Partially protected | Signed/versioned/expiry-bound/size-limited records |
| 3.13 | Alias impersonation | Design target | Identity-signed aliases exist; live discovery acceptance still needs the final session/device binding audit |
| 3.14 | Downgrade attacker | Incomplete; production held | Capabilities are signed, but the exact indexed-session profile must be transcript-bound by PairInit; Phase 6b link features (PAD1, RLK1) cannot be stripped by a third party and their loss is recorded (gated off) |
| 3.15 | Malformed-packet attacker | Partially protected | Strict cross-language envelope parsing and bounded framing are implemented; endpoint state-machine fuzzing remains; Phase 6b malformed-input events are built but gated off |
| 3.16 | Local malware | Out of scope | Endpoint sets the floor |
| 3.17 | Traffic analyst | Out of scope in this version | Explicit non-goal of the routing-tag design; passive observation is undetectable; Phase 6b padding, knock, random port and pair seeds are built but gated off, and cover traffic is not planned (OD6b-13) |

---

## 3. Adversary detail

### 3.1 Malicious relay

**Can do:** Run a mesh (BLE) or bridge (libp2p) relay node and forward
`RavenEnvelopeV1` traffic between strangers, with no trust relationship to
either party.

**Verdict: Design target; production held.**

**Intended mechanism:** RAVEN uses two independent encryption layers. Message content is
to be sealed by the recipient's session key before it ever reaches a relay
(`protocol/RAVEN_ENVELOPE_V1.md` §5, "No plaintext identities on the wire");
the recipient locator carried alongside it is not a stable identifier but a
rotating HMAC tag (`protocol/RAVEN_ROUTING_TAG_V1.md` §1–2) that changes
every message. A relay sees only `message_id` (meaningless CSPRNG),
`routing_tag` (rotates, unlinkable without `K_route`), and two opaque
ciphertext blobs. It cannot decrypt, cannot determine whether two envelopes
it has forwarded belong to the same conversation, and cannot forge
authorship: every immutable field is bound into the Ed25519 signature over
`signing_bytes` (`protocol/RAVEN_ENVELOPE_V1.md` §2), so a relay tampering
with `message_ciphertext` produces a signature that fails verification
(vector: `shared-vectors/rvn1/negative/envelope_tampered_body.json`,
`verify_result: reject`). A malicious relay also cannot forge a delivery
receipt on the recipient's behalf: `RavenAckV1` carries its own signature
under the acknowledging device's key, checked independently of the outer
envelope (`protocol/RAVEN_ACK_V1.md` §2; vector:
`shared-vectors/rvn1/negative/ack_wrong_signer.json`,
`verify_result: reject`).

**Current executable boundary:** the publicly derivable interim sealer and
unverified delivery transitions are disabled. Production-disabled Rust and
Swift actors implement the transcript-bound indexed session and recoverable
inbox/ACK transaction, but they have no approved live transport/UI wiring, so
the statements above remain design/test evidence rather than production claims.

**What still leaks:** Envelope size and forwarding timestamp at that relay.
That is a traffic-analysis question, addressed (and scoped out) at §3.17.

### 3.2 Malicious store node

**Can do:** Operate an offline-store relay that holds envelopes for
recipients who are not currently reachable, and inspect or tamper with
whatever it stores.

**Verdict: Design target; production held.**

**Intended mechanism:** A store node is architecturally the same untrusted party as a
relay (§3.1) — it never receives `K_route`, which lives only in the two
endpoints' key trees. A recipient explicitly presents a separately derived,
daily rotating `store_tag`; the store can link every access and object using
that same tag during its day window, as well as the source libp2p Peer ID, but
cannot derive another day's tag or map the capability to a Raven address. Vector
`shared-vectors/rvn1/routing/tag_unlinkable_001.json` demonstrates that two
tags derived from the same `K_route` at adjacent counters are structurally
unrelated byte strings. Content and authentication protections are
identical to §3.1.

**Current executable boundary:** the store validates strict opaque envelopes,
uses separately derived mailbox tags, enforces count/byte/stream/time limits,
persists atomically, and deletes only by TTL. A production-disabled libp2p
PUT/GET service proves sender-disconnect/store-restart/recipient retrieval.
Session-derived live mailbox keys, multi-store discovery/replication, and
authenticated endpoint retrieval are still held.

**What still leaks:** Size/timing, same-day tag reuse, source Peer ID, and how
long an envelope sat there before being claimed (queue-depth side channel).
These are not separately defended in V1.

### 3.3 Malicious peer (direct connection)

**Can do:** Open a direct libp2p stream or BLE GATT connection to a node
without being an authorized contact, and send it arbitrary bytes.

**Verdict: Partially protected.**

**Intended endpoint gate:** Once a frame reaches the envelope pipeline, the
required order is size → strict decode → TTL → local route/session → outer
authentication → AEAD open → transactional commit. Current release
containment rejects unknown or undecryptable bodies and emits no ACK. Disabled
Rust and Swift reference actors exercise this complete order and its crash
matrix, but the transaction is not active in the app/node, so this is not a
production claim.

**Current boundary:** the earlier pre-validation allocation gap is closed at
the audited transport layer. The Go bridge reserves nonblocking per-peer and
global stream/declared-byte budgets before allocation, bounds idempotency
keys, resets malformed or stalled streams, and releases reservations on every
exit. The raw Rust TCP listener independently enforces a 1 MiB frame ceiling,
64-handler global cap, idle/frame/write/lifetime deadlines, and exact reads.
These controls bound one peer's pre-parser resource footprint; they do not
replace authenticated endpoint admission, peer scoring, or Sybil resistance.

**Bluetooth nearby (laptops, gated off):** a GATT connection from a device
that is not a verified contact never reaches the envelope pipeline: the RNK1
knock answers only the pair's key and stays silent otherwise, within the
connection caps of RNL1 §8 (§1.1).

**Phase 6b sensing and responses (built, gated off; not in this version):**
held by `SECURITY_EVENTS_PRODUCTION_ENABLED` and
`SECURITY_RESPONSES_PRODUCTION_ENABLED` (both `false`; codes in
[`SECURITY_EVENTS.md`](SECURITY_EVENTS.md)).

- *Detected:* a stranger's failed or malformed handshake
  (`SEC_HANDSHAKE_FAIL`, `SEC_PREAUTH_MALFORMED`), a connection the contact
  gate or the block list refuses (`SEC_STRANGER_REFUSED`,
  `SEC_BLOCKED_REFUSED`), the p2p peer gate's refusals
  (`SEC_P2P_GATE_REFUSED`), a source at its connection cap, beacon replays and
  floods, knock replays. Each is about the network source only (IPv4 /32,
  IPv6 /64, in memory); the ledger keeps one count per kind and day, never an
  address, and nothing is sent to anyone.
- *Answered (R1, the penalty box):* 16 strikes in a minute ban the source for
  60 s, doubling up to 1 h (`SEC_PREAUTH_FLOOD`); the LAN and Internet
  listeners keep one probation connection per 10 s, so a contact behind the
  same address still gets through and clears the source; the p2p peer gate
  refuses a banned source before Noise and the beacon does not answer it.
  Memory only, at most 4,096 sources; loopback is never banned.
- *Not detected or not answered:* a stranger who stays under the strike rate,
  a flood spread over many addresses, drop-only behaviour, and what a prober
  learns before the contact gate (in this version the listener's lifelong
  Noise static: §3.17; the gated knock's strict and silent modes withhold
  it). Bans live in memory and end at a restart. No response blocks, unpins
  or removes a contact.

### 3.4 Passive ISP

**Can do:** Observe all traffic between a device and the internet — e.g. a
network operator, an ISP, or a Wi-Fi hotspot operator — for internet-bridge
(libp2p) traffic.

**Verdict: Partially protected.**

**Why (protected sub-case):** On the Rust side, the libp2p smoke host
(`node/crates/raven-swarm`) secures TCP with Noise and QUIC with libp2p's own
TLS-based transport security (not Noise), and the LAN-direct carrier is Noise
XX (`raven_core::lan_noise`). An on-path ISP therefore sees an encrypted
transport stream, not `RavenEnvelopeV1` bytes in the clear: it cannot read the
routing tag, the ciphertext, or the magic bytes without breaking the
transport-layer handshake. The original claim that the iOS/Go libp2p bridge
host uses `libp2p.DefaultSecurity` (Noise + TLS) cites
`ios-native/RAVEN/Libp2pBridge/bridge.go:135` (**OFF-MAIN**, unverified from
this tree). This is on top of, and independent from, the message-level E2EE
described in §3.1 — two layers, as stated in §1's asset list.

**Why (out-of-scope sub-case):** Transport encryption hides *content*, not
*shape*. An ISP still observes which IP addresses a device connects to, at
what times, for how long, and how many bytes flow, and nobody can detect an
observer that only watches. `protocol/
RAVEN_ROUTING_TAG_V1.md` §4 states this explicitly as a non-goal: routing
tags resist linkage at the tag-value layer, not global traffic analysis. In
this version every Raven link also shows each frame's exact size (a
cleartext 4-byte length before each Noise transport message: an ACK, a
PairInit and a text each have a recognisable size) and fixed handshake
sizes. Internet direct and p2p are themselves gated off in release
(`INTERNET_DIRECT_PRODUCTION_ENABLED`, `P2P_PRODUCTION_ENABLED` = `false`),
so in this version the Raven link such an observer sees is LAN direct, with
the same exposure.

**Phase 6b (built, gated off; not in this version):** PAD1 link padding
(`LINK_PADDING_PRODUCTION_ENABLED = false`,
[`RAVEN_LINK_PADDING_V1.md`](../protocol/RAVEN_LINK_PADDING_V1.md)) pads
every frame on a LAN, Internet direct, p2p or Bluetooth link where both sides
offer it to 512, 4,096, 16,384 or 65,519 bytes, and the RLK1 knock
(`LINK_KNOCK_PRODUCTION_ENABLED = false`) gives the handshake random sizes.
With both live an on-path observer still sees addresses, times, durations,
the number and direction of frames and each frame's size class; a link to a
peer without PAD1 is not padded. Cover traffic and timing obfuscation are
not planned (owner decision OD6b-13; assessment in
[`design/2026-10-traffic-analysis.md`](design/2026-10-traffic-analysis.md)
§7), and `protocol/RAVEN_CAPABILITIES_V1.md` defines no cover-traffic bit
(the routing-tag spec's pointer to a `coverTraffic` bit there is stale). See
§3.17.

**Recorded now, decrypted later (HNDL):** the transport layer is classical:
Noise XX over X25519 on every Raven link (and libp2p's Noise or TLS outside
p2p). An observer who records today and breaks X25519 later reads the link
layer: both identities (binds, hellos), route hints (addresses, ports, Phase
6b pair seeds) and, inside PAD1, the real frame sizes. Message content does
not open on that break alone: it is sealed by the end-to-end session, whose
PairInit V1 root mixes in an ML-KEM-768 secret. A post-quantum link
handshake is Phase 6c work, not in this version (design §6).

### 3.5 Active MITM

**Can do:** Sit on the network path during pairing or session setup and
attempt to substitute their own key material for a legitimate contact's.

**Verdict: Partially protected.**

**Protected sub-case:** a correctly scanned in-person QR code and a manually
compared safety number provide an out-of-band identity check. Signed device
certificates, prekey bundles, envelopes, and capability records prevent an
on-path party from altering those exact authenticated records unnoticed.

**Current boundary:** PairInit V1 now byte-binds the two device certificates,
responder prekey, hybrid contributions, roles, profile, and suite. It is
byte-for-byte verified by Python, Rust, and Swift (Swift is **OFF-MAIN**, unverified from this tree) but remains
production-disabled pending a confidential carrier, protected durable endpoint
state, one-time-prekey lifecycle, and external review. Older ad-hoc
pairing code is not evidence that every live message path has this binding.

**Why (user-responsibility sub-case):** Cryptographic pairing verifies "the
key I now hold matches the key the other device holds" — it cannot verify
"the human on the other end is who I think they are." An attacker who
successfully impersonates a contact during the in-person QR exchange itself
(e.g. a fake QR code, a compromised video-call impersonation) defeats
pairing at the human layer, not the cryptographic layer. This is explicitly
the user's responsibility, matching the pre-pivot model's §3.4. We also note
`SafetyNumberView.swift`'s (**OFF-MAIN**) own comment marks automated QR-based safety
number re-verification as a TODO; today the safety-number check is a manual
compare-in-person-or-by-call flow, not an automated re-scan.

**Who learns the dialer's identity (this version).** On LAN direct (and on
Internet direct once it is live) the dialer sends its signed identity bind
first, after Noise message 2; the listener answers with its own only to a
dialer that names one of its contacts. Noise authenticates nothing about the
listener before that bind, so whoever answers at the address dialled learns
the dialer's Raven identity, its IP address and when it sends (never
content: the bind and everything after it is checked against the contact's
key, and a wrong key ends the link). Two ways to be that listener:

- *At a contact's real address*: a reused DHCP lease, a planted listener or
  an ARP spoof on the same network. Not prevented in this version; M0 and
  the RLK1 knock below are the answer.
- *By steering the dial*: a card's route fields (`lan=`, `inet=`, `p2p=`,
  `via=`) are not signed (only `onion=` is), and comparing security words
  checks the key only, so someone who alters a card in transit can name
  their own host. A card's LAN route therefore keeps the local-network rule
  even after the contact is verified: it is dialled only at a loopback,
  private, link-local or unique-local address, whatever name it gives. Only
  a LAN address typed on this computer (`--lan-dial`, `contact set-dial`) or
  learned from the contact's own authenticated link may lie beyond the local
  network; a LAN address saved before this rule counts as a card's until it
  is typed again or learned. A card's Internet route (`inet=`) has no such
  limit and is the remaining card exposure once Internet direct is live;
  signed card routes are the planned fix.

**Phase 6b (built, gated off; not in this version):**

- *Impostor at a contact's address* (a reused DHCP address, a planted
  listener, an ARP spoof): with M0 (`LAN_NOISE_PIN_PRODUCTION_ENABLED =
  false`, the cutoff pack) and the RLK1 knock (`LINK_KNOCK_PRODUCTION_ENABLED
  = false`) the dialer stops before Noise message 3, so the impostor gets an
  ephemeral key and a random-looking tag, not the identity. With
  `SECURITY_EVENTS_PRODUCTION_ENABLED` the stop is `SEC_ADDRESS_IMPOSTOR`
  about the contact; at Suspicious (3 in 24 h) R5 forgets the learned LAN
  address another key answered at (the saved card address stays).
- *Tampering on the path* breaks the Noise tag (it cannot read or change
  content): `SEC_LINK_TAG_FAIL` about the contact's path on that network; at
  Suspicious R4 puts that path last for 10 minutes.
- *Key-change social engineering* ("I reinstalled, here is my new card"): the
  existing key-change refusal and the app's NAME-CLASH screen, now also
  `SEC_KEY_CHANGE_ATTEMPT` (an Alert: Raven kept the old key; compare
  security words before the new key is added).
- *Forged updates* (design D: `ADVISORY_PRODUCTION_ENABLED`,
  `RELEASE_BUNDLE_PRODUCTION_ENABLED` = `false`, and no release keys compiled
  yet): a security notice or release not signed by 2 of the 3 Raven release
  keys, or missing from the public release log, is refused
  (`SEC_ADVISORY_FORGED`, `SEC_BUNDLE_FORGED`, `SEC_UPDATE_UNLOGGED`) and
  attributed to the friend who passed it on, never blamed on them; two
  different views of the log freeze updates (`SEC_LOG_SPLIT_VIEW`). Someone
  with two release keys can still sign a malicious release; the person's
  typed approval, the public log and reproducible builds are the mitigations
  ([`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md) §1).
- *Not detected:* the wrong person at pairing time (above), a passive
  recorder, and a fully compromised contact device, which behaves exactly
  like the contact.

### 3.6 Stolen locked device

**Can do:** Gain physical possession of a device that is powered on but
locked (passcode/biometric not entered).

**Verdict: Partially protected; platform-dependent.**

**Why:** iOS roots are Keychain-backed, device-only, and excluded from
backup. Rust identity/session storage uses Keychain on macOS and DPAPI on
Windows. On GNU/Linux a Release build keeps them in the Secret Service keyring
when an unlocked one answers (created add-only and without a prompt, R1,
2026-10-08), and otherwise in the passphrase vault `keystore.vault` in the
profile (Argon2id and XChaCha20-Poly1305; the passphrase typed, or read from a
file only the user can read); musl and the other Unix targets use the vault
only. Each profile's choice is recorded in `keystore.backend` and never changes
silently (`docs/design/2026-10-linux-keystore.md`). The `0600` `locked-file`
seed (`RAVEN_IDENTITY_BACKEND=locked-file`) is a debug/lab/CI-only override
that Release builds refuse; it is not an approved fallback. The protected
session store is refused when no supported backend exists.

**Limit:** the current iOS root accessibility is
`AfterFirstUnlockThisDeviceOnly`. After the first unlock following boot, that
class can remain available while the screen is locked. It prevents simple
file-copy extraction but is not a claim that keys are cryptographically
unavailable throughout every locked interval. Notification previews, OS
compromise, memory capture, backup policy, and each desktop keyring's lock
state remain platform concerns.

What a desktop profile's data directory reveals to someone holding the
laptop or a copy of its disk (friend metadata, message records, the chat
history) is row T3a of §3.7a.

### 3.7 Stolen unlocked device

**Can do:** Gain physical possession of a device that is unlocked, or
compel the owner to unlock it.

**Verdict: Out of scope.**

**Why:** Once an attacker holds an unlocked device, they can read anything
the legitimate user's UI can display, and any key material Keychain
protection classes release for an unlocked device. No protocol-level
mechanism can distinguish "the legitimate user is looking at this screen"
from "an attacker is looking at this screen." This mirrors the pre-pivot
model's §3.6 (coercion/lawful access) — the floor is set by the endpoint's
OS-level unlock security, not by RAVEN.

For a desktop profile, `raven lock` (Lock v1) and what it does and does not
change are row T3b of §3.7a.

### 3.7a Terminal profile at rest (privacy pack, 2026-10)

**Scope.** The desktop profile of `raven` / `ash` and `raven-node` on macOS,
Linux and Windows: what someone who holds the laptop, or a copy of its disk,
learns from Raven's data directory. Design, file inventory, column audit and
evidence: [`design/2026-10-at-rest-metadata.md`](design/2026-10-at-rest-metadata.md);
the user's version: [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) sections 5-8. No
wire byte changes; no `*_PRODUCTION_ENABLED` gate was added (custody deletion
rides the existing custody gate). Release builds seal a profile at the first
start of the new build; debug builds only with the lab switch
`RAVEN_LAB_AT_REST=1`.

**Keys.** K_hist, the profile's existing chat-history key, lives in the OS
keystore (macOS login keychain, Secret Service, or the Linux passphrase vault
`keystore.vault`; on Windows a DPAPI-wrapped `chat_history_key.dpapi` in the
data dir) and is never rotated. It wraps `meta_key.rmk`, which holds the
index key (keyed lookups, by value type) and the epoch data keys (sealed
files RMS1, sealed SQLite values, history RVNHIST2, the outbound stage, app
rows). Data keys rotate by epoch after deletions; `raven privacy rotate-meta`
replaces the index key and the epochs.

| Row | Adversary | Verdict | Mechanism / reason |
|---|---|---|---|
| T3a | Laptop taken while off or locked, or a copy of its disk, without the user's login password, keyring password, Windows login or Raven passphrase | Partially protected | Every file and SQLite column that names a friend is sealed or keyed: the contact book, learned and sighted addresses, outbox routes, device and prekey caches, noise pins, route hint state, relay lists, the session store's heads, endpoint tables and receipts, owed ACKs, the app store's sender columns, custody rows (design §6-§7). A copy without K_hist opens none of them. Exceptions, written only by features gated off in release: the app store's outbox and pairing budget (design §7.2) and the legacy bridge queues (§7.5). Evidence: carrier_matrix C87 (a copied data dir, SQLite raw bytes and WAL included) and C90, fault scenario s120 (an older build's profile migrated, then the same check), `raven_core::at_rest` and `raven_core::privacy` tests. Not covered: settings and logs (plain by design), file names, sizes and times, and the limits below. |
| T3b | Laptop taken while the user is logged in, or anyone who can log in as the user | Out of scope (unchanged) | The keystore releases K_hist to any process of the user, so everything opens. `raven lock` (Lock v1) stops raven-node and keeps it stopped until `raven unlock` (sends do not start it again; the full-screen app asks before it starts it again; Raven's own login item is unloaded, and on request kept off at the next login). Only a passphrase-vault profile is really locked (its next start needs the passphrase); every lock text says that a keychain or DPAPI profile still opens for anyone logged in as the user. Lock v2 is built in Phase 6 (P6.40) and gated off (`LOCAL_PROTECTION_PRODUCTION_ENABLED = false`): a running raven-node that forgets every key while locked (the identity, the at-rest keys, the decrypted contact book, the vault key), closes its listener and refuses key loads until `raven unlock`; auto-lock on wake from sleep (on by default only with a Raven passphrase); and a Raven passphrase on macOS (the keys move from the login keychain into a vault). Windows and desktop-keyring Linux profiles cannot take a passphrase yet, so for them a lock still leaves the keys to anyone logged in as the user, and `ash` processes read their own keys while the node is locked (daemon-owned secrets are not built). Evidence: fault scenarios s121 (v1) and s116 (v2), `node_control` and lock tests; real row R37 open (an unpublished test checklist). |
| T3-erase | Laptop or disk taken after `raven erase` | Protected for what the data dir and the keystore held; partially for earlier copies | Erase deletes K_hist first (the keychain or Secret Service item, `chat_history_key.dpapi`, or `keystore.vault`), then the identity, session and prekey items, then only Raven's own files, and Raven's own login item: every sealed file, value, history, stage and app row is unreadable without K_hist (crypto-erase). A copy made earlier that does not hold K_hist stays sealed under a key that no longer exists; a whole-folder copy on Windows or of a vault profile holds it (opens with the Windows login or the passphrase), and a keychain backup (Time Machine) holds it too. Evidence: carrier_matrix C91, fault scenario s117, `raven_core::erase` tests. |
| T4 | A verified friend chosen as custodian (friend custody) | Partially protected; gated off (`FRIEND_CUSTODY_PRODUCTION_ENABLED = false`) | The custodian cannot read a deposited object (end-to-end sealed) but learns who wrote to whom and when, and holds a signed envelope (transferable proof that one friend wrote to another). A RELEASE deletes the object and both parties at once (a keyed digest and its expiry hour stay until that hour, for replay detection), and its open rows are keyed and sealed. The semantics change of errata rule 9 is the unsigned draft [`SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md`](SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md); it must be signed before the gate flips. Evidence: fault scenario s125, `raven_core::friend_custody` tests. |

**Honest limits** (design §10 has the full list):

1. **SSD and file-system remnants.** Plaintext written before a profile was
   sealed, the old frames of a truncated WAL and freed SQLite pages stay in
   freed disk blocks until they are overwritten. `secure_delete` and
   checkpoints clean the files, not the blocks; an overwrite on APFS or an
   SSD lands in new blocks. Only full-disk encryption (with TRIM) covers
   them.
2. **Backups and snapshots** (Time Machine, APFS snapshots, Windows restore
   points, any copy) keep sealed files and often the keystore that opens
   them. Erase cannot reach them.
3. **DPAPI is the Windows login.** Anyone who can use the user's Windows
   login (or its credentials) opens K_hist; its DPAPI-wrapped file lives in
   the data dir.
4. **Old `meta_key.rmk` copies.** Copies in backups or freed blocks are
   wrapped by the never-rotated K_hist, so with K_hist (the keychain, the
   vault passphrase or the Windows login) they open old epoch keys. Data-key
   rotation (deleted data unreadable with this computer's keys 1-2 days after
   the deletion) and `rotate-meta` help only against someone who does not
   also hold K_hist; only erase removes it.
5. **Keyed columns are equal inside one profile.** Equal values give equal
   keyed lookups, so the files show how many sessions, messages and ACKs
   involve the same (unknown) friend, when sessions began (to the hour) and
   the order messages arrived in. Nothing links across profiles.
6. **No freshness.** Someone who can write the data dir can put back an older
   sealed file (or replace the binary): local malware, §3.16.
7. **Downgrade.** An older build fails closed on a sealed profile (it cannot
   read the book) and may write small advisory files in plain, which the new
   build seals again; `raven privacy unseal` writes the profile back in plain
   on the user's typed request (fault scenario s124).

### 3.7b Learning connectivity (Phase 6a, gated off)

**Scope.** raven-node learns, from this computer's own dial outcomes only,
which carrier to try first for each contact on each network, a few shorter
waits, a bounded relay term and, while friend custody is in use, which (at
most two) friends hold a contact's mail. Design:
[`design/2026-10-learning-connectivity.md`](design/2026-10-learning-connectivity.md).
It is held in every build (`LEARNING_PRODUCTION_ENABLED = false`; debug lab
switch `RAVEN_LAB_LEARNING=1`), the user can turn it off (`raven learning
off`), and the unsigned [`WAIVER_LEARNING_DRAFT.md`](WAIVER_LEARNING_DRAFT.md)
must be signed before it flips. No wire byte changes. Adversaries T1-T4 and
asset A4 are the cutoff people report's
(`docs/roadmap/studies/cutoff-people-report.md` §1.2-§1.3).

What it keeps on the laptop:

| Row | Asset | What is kept | Protection |
|---|---|---|---|
| A4 | Meeting history (encounter rows) | Per verified friend, a decayed "met recently" estimate and the time of the last link (rounded down to the hour); per (custodian, recipient), how many held messages were delivered or ran out. Kept only while friend custody is live and in use (OD6a-14); never while it is not | Never shared with anyone (no transitivity); `learning.bin` sealed at rest (RMS1, at-rest kind 22, §3.7a's keys); friends named only by an HMAC key under a secret kept inside that file; no place, address or time-of-day field; rows dropped 30 days after their last update; at most 64 encounter and 128 carry rows. `raven learning reset`, `raven learning off --forget`, removing the contact and `raven erase` delete them |
| A4r | Route failure history | Per (contact, network, carrier): a decayed success estimate, success and failure times, round-trip estimates, the last 8 tries and the hours of the last try, receipt and probe; per relay, a decayed success estimate | The same file and keys; the network is an HMAC of the egress tag (the tag, an address or a PeerId is never stored, and no log line names one); at most 64 contacts, 8 networks each, 32 relays. Raw observations, the explorer's notes and the carry facts it caches from the contact book and settings stay in memory only |

Who can do what with it:

| Row | Adversary | Verdict | Mechanism / reason |
|---|---|---|---|
| T1/T2 | Observer or active stranger on the same network (guest Wi-Fi, router, hotspot host): drops, delays, resets | Partially protected: failures only | It can cause failures and slower samples, so demote the routes it disrupts. It cannot create a success: that needs an ACK on the Noise link authenticated to the contact. Traffic then moves to other routes the static plan already holds, which static would reach after its fixed waits, and slower samples lengthen waits only up to today's values. Probes add short authenticated links (at most 6 per hour for the whole node); a LAN or Internet probe goes only to an arm that delivered on this network within 7 days, because a LAN dialer sends its identity bind first, so a stranger now holding a stale address is never probed (fault scenario s106, netns `learn-flaky`). The rule is per arm: a newly learned LAN address of a verified contact whose LAN arm delivered here may be probed, under the same LAN checks as any dial |
| T4 | A verified friend chosen as custodian | Partially protected; gated off with friend custody | It learns what friend custody already shows it (who writes to whom, and when, §3.7a T4). Carry choice picks from the same candidates and never leaves more than 2 copies, so no more friends learn it than today. It cannot forge the recipient's sealed ACK, so it gains carry score only by delivering; a custodian colluding with the recipient can draw the sender's copies to itself, which the recipient already announced (bounded by that announcement and the cap) |
| T3a | Laptop taken while off or locked, or a copy of its disk | Partially protected | `learning.bin` is sealed like the rest of the profile and opens nothing without K_hist; its size and time show that learning ran |
| T3b | Laptop taken while logged in | Out of scope (unchanged) | The keystore opens the file: with the contact book it says "this laptop met friend X often recently" and "LAN to Y fails here", to the hour. It holds no place, address, time of day or message metadata beyond what the outbox already holds. Someone who can write the data dir can put back an older sealed file (§3.7a limit 6): an old model, inside the same bounds. Local malware: §3.16 |

**Bounded impact.** Whatever the evidence, learning only reorders the
carriers of the gated, filtered static plan; a learned plan that is not a
permutation of it falls back to static (pinned for an hour). For every
message the learned worst case is therefore at most the static worst case:
the same route set, waits clamped to [floor, today] (connect per address
5 s down to 1.5 s LAN and 2.5 s Internet, p2p connect 20 s to 8 s, first reply
30 s to 6 s), and the 20 s connect budget, 40 s dial and 45 s worker
deadlines unchanged. The order moves away from static only with a 25 %
better index and back with none, so it returns to static as soon as the
evidence allows. A relay operator gains its term (at most ±150, below
probation's -1000 and cooldown's -400) only by relaying for real, and the
term never starts a relay change. Corrupt, tampered or newer data gives
static plans; a missing key keeps learning in memory only. Learning never
writes the user's settings, the contact book or a gate, and never puts what
it learned into a frame, a card or a route hint
(`node/scripts/learning_boundary_check.sh`). Evidence: the simulator gate
`node/crates/raven-core/tests/learning_sim.rs` (the adaptive attacker that
black-holes the last working direct route gives 0.33x the static mean),
carrier_matrix C70-C74, fault scenarios s100-s106; remaining: real rows
L1-L4 (an unpublished test checklist).

### 3.8 Sybil swarm

**Can do:** Create a large number of cheap, independently-addressed peer
identities and use them to dominate a target's connection slots, routing
table, or store-node selection.

**Verdict: Partially protected.**

**Protected sub-case:** audited Go and Rust ingress paths enforce hard
connection/handler, stream, frame-byte, deadline, and aggregate-store limits.
These constrain resource use by each admitted transport identity.

**Cooperative-only fields:** `replication_budget` and `hop_limit` help honest
routers but are excluded from the RVN1 sender signature. A Byzantine relay can
reset them, and they therefore provide no Sybil security bound.

**Why (out-of-scope sub-case, stated honestly):** RAVEN does not yet
implement peer scoring, per-remote connection-count limits, or diverse
peer/store selection policy that would make a Sybil swarm's cost outweigh
its benefit — no such mechanism exists in the codebase as of this document.
A libp2p Peer ID is a hash of a locally-generated keypair, not an
authenticated identity; nothing prevents an adversary from generating many
Peer IDs cheaply. Full Sybil resistance (peer reputation, resource-bound
identity issuance, or a trusted bootstrap set) is future work, tracked
alongside the DHT hardening in §3.12.

### 3.9 Eclipse attacker

**Can do:** Surround a target node with adversary-controlled peers so that
all of the target's DHT/mesh connections go through the attacker, enabling
selective censorship or feeding the target a manipulated view of the
network (e.g. poisoned alias records, withheld envelopes).

**Verdict: Partially protected.**

**Why:** Signed DHT records prevent a surrounding attacker from forging the
record owner, but do not force that attacker to return or forward records.
RAVEN does not yet implement diverse/independent peer selection,
connection-count limits per subnet, or any other structural defense
specifically against eclipse positioning — this is the same gap as §3.8,
under a different attack goal (isolate rather than merely flood). We are
not claiming a censorship defense that does not exist. The unauthenticated
RVN1 hop fields do not change this result.

### 3.10 Replay attacker

**Can do:** Capture a valid, signed envelope and resend it later, hoping to
cause duplicate delivery or reuse of stale state.

**Verdict: Incomplete; production held.**

**Current protection:** strict TTL validation, immutable-object relay caches,
monotonic queue transitions, and bounded ratchet prototypes have negative
tests. Relays no longer durably deduplicate on an attacker-chosen public
message ID alone.

**A contact re-using a message id** (a modified client): message ids are
unique per sender device across sessions, and the first received text of a
message is final whatever the gates
([`ATSAM_ENDPOINT_TRANSACTION_V1.md`](../protocol/ATSAM_ENDPOINT_TRANSACTION_V1.md)
§3). While nothing re-seals (this version), another object under an id the
contact used in an earlier session is refused; with session reset or the
long horizon live it is taken as a copy, and a different text marks the
message ("the sender later sent different text as this same message") but
never replaces it. The seen record lasts 8 days; after that the chat
history's first-text rule still holds while the row is kept.

**Remaining gate:** endpoint replay acceptance must be committed atomically
with authenticated AEAD open, receive-ratchet/skipped-key state, inbox dedup,
and ACK-outbox intent. The indexed protected Rust store advances ratchets
without rollback, but it is deliberately not yet coupled to an inbox
transaction. Until that actor exists on both Rust and Swift, replay defense is
not production-complete.

**Phase 6b (built, gated off; not in this version):**

- *Detected and answered:* a contact's object replayed at a used index
  (`SEC_OBJECT_REPLAY`; R2 asks an early re-key, at most one per contact per
  6 h, inside the re-pair budget), a replayed knock (`SEC_KNOCK_REPLAY`: a
  cache of 4,096 matched nonces kept 2 days; answered as no match, R1 strike
  4), a replayed beacon query (`SEC_BEACON_REPLAY`, Phase 3's nonce cache), a
  custodian serving released objects again (`SEC_CUSTODIAN_REPLAY`), an older
  security notice (`SEC_ADVISORY_ROLLBACK`: ignored; monotonic serials, the
  prev-digest chain and the build's compiled floor), two notices with one
  serial (`SEC_ADVISORY_EQUIVOCATION`: updates freeze with both kept as
  evidence), and this disk's session state put back to an older copy
  (`SEC_LOCAL_ROLLBACK`; R3 rotates this computer's prekey and asks an early
  re-key of every contact with a live session, at most once per 6 h).
  Held by `SECURITY_EVENTS_PRODUCTION_ENABLED`,
  `SECURITY_RESPONSES_PRODUCTION_ENABLED` and `ADVISORY_PRODUCTION_ENABLED`
  (all `false`).
- *Not detected:* exact duplicate envelopes (harmless, ignored, no event); a
  recorded knock replayed after a node restart (the cache is in memory; the
  replay still cannot finish the handshake); a whole data folder restored
  together with its keystore (§3.16).

### 3.11 Spam attacker

**Can do:** Send unsolicited messages or connection/pairing attempts to
users who have not established a relationship with the sender.

**Verdict: Partially protected.**

**Why:** RAVEN's serverless design is contact-first: an unknown sender's
first message surfaces as a message request rather than landing directly in
an established conversation, and a recipient can block a contact or remove
them (removing per-pair key material — see the "swipe-to-remove a contact"
serverless key cleanup shipped in this branch). This raises the cost of
unsolicited contact relative to an open, discoverable inbox.

**Why not fully protected, stated plainly:** There is no central,
cross-user moderation layer, no shared spam-reputation service, and no
network-wide rate limiter — because there is no central operator to run
one. This is not an oversight; it is the direct, honest cost of removing
the central server. A traditional centralized messenger's server is
simultaneously its metadata-collection risk *and* an implicit anti-spam/
anti-abuse chokepoint (it can globally rate-limit an account, ban a
fingerprint, or throttle a sender across all recipients at once).
Decentralizing removes both at the same time. Per-identity local rate
limiting and per-contact blocking are local, per-recipient defenses, not a
network-wide one — a spammer blocked by one recipient is not thereby
blocked anywhere else.

**Phase 6b (built, gated off; not in this version):** strangers' connection
attempts are counted and floods banned by R1 as in §3.3; a contact's PairInit
flood over the claim quota is `SEC_PAIRINIT_FLOOD` (the quota existed
before); a depositor that floods a custodian with bad objects
(`SEC_DEPOSITOR_BAD_OBJECT`) is answered `RATE_LIMITED` for an hour after its
tenth refused object within an hour (R7). Still local and per recipient: a
spammer who is a contact stays a contact (the app's "Pause sending" is the
person's choice, never automatic), and RUP1 update requests are bounded by
quotas but raise no event (`SEC_UPDATE_FLOOD` is registered, not raised).

### 3.12 DHT poisoning

**Can do:** Inject false, stale, or oversized records into the DHT used for
alias resolution, attempting to redirect lookups, exhaust store capacity, or
squat abandoned names.

**Verdict: Partially protected.**

**Why:** `protocol/RAVEN_ALIAS_V1.md` §4 requires every published alias
record to satisfy four constraints simultaneously: **signed** (unsigned
records are discarded on receipt — nothing else binds the claim to an
identity); **versioned** (`sequence` is the version; replacement in the
store is keyed by `(alias, identity_address)` with last-write-wins by
`sequence`, never by receipt order, because receipt order is not
trustworthy in a store with multiple untrusted writers); **expiry-bound**
(a resolver treats a record as absent past `expires_at`, preventing
indefinite squatting of an abandoned name); and **size-limited** (both
variable-length fields are length-prefixed, and a store SHOULD impose a
practical cap well below the 65,535-byte theoretical ceiling, since nothing
resembling a human-typed alias needs to approach it). A stale-record replay
specifically is covered by the same monotonic-sequence rule as §3.13 (vector
`shared-vectors/rvn1/negative/alias_stale_sequence.json`).

**What is not yet covered:** Broader DHT-level resistance — e.g. an
adversary who controls enough of the DHT's keyspace neighborhood to
withhold or selectively serve records regardless of their validity (a
Kademlia-style routing attack, closely related to §3.8/§3.9) — is future
work, not addressed by record-level signing alone.

### 3.13 Alias impersonation

**Can do:** Attempt to claim, hijack, or roll back a human-readable alias
that legitimately belongs to someone else.

**Verdict: Partially protected; alias is discovery, not trust.**

**Why:** Every accepted alias record is self-signed by the identity it claims to
belong to — signed by `identity_address`'s own Ed25519 identity key over
domain-separated bytes (`protocol/RAVEN_ALIAS_V1.md` §1) — so an attacker
without that private key cannot forge a claim for someone else's address. A
captured, validly-signed *older* record cannot be replayed to roll an alias
back: a verifier holding a record at `sequence=N` for an alias must reject
any incoming record for the same alias/identity with `sequence <= N`, even
if validly signed (`protocol/RAVEN_ALIAS_V1.md` §2; vector:
`shared-vectors/rvn1/negative/alias_stale_sequence.json`,
`resolver_action: reject_stale`). When a lookup for a previously-resolved
alias returns a *different* address than last seen and pinned, the spec
requires surfacing a key-change warning before delivering to or trusting
the new identity — treated with the same severity as a contact's
fingerprint changing (`protocol/RAVEN_ALIAS_V1.md` §3, cross-referencing
`protocol/RAVEN_IDENTITY_V1.md` §3). Conflicting live claims for the same
alias string (a namespace-ambiguity case, not impersonation of a specific
identity — the namespace has no registrar and is not unique by design) MUST
be surfaced as ambiguous, never silently resolved by a predictable
tie-break, since a predictable tie-break is itself attacker-exploitable.
This proves control of that Raven identity, not the human's real-world name.
Only a pinned address/fingerprint or out-of-band verification establishes a
trusted contact; live alias discovery cannot silently replace that binding.

### 3.14 Downgrade attacker

**Can do:** Sit on-path or control a relay and attempt to force two peers
into negotiating a weaker capability set than both actually support (e.g.
stripping a post-quantum-hybrid or delivery-authentication bit).

**Verdict: Incomplete; production held.**

**Current protection:** `protocol/RAVEN_CAPABILITIES_V1.md` replaces the legacy unsigned
BLE `Capabilities` advertisement — which any on-path relay could read or
alter without either side detecting it (§2, citing
`ios-native/RAVEN/RAVEN/Core/Mesh/RUMProtocolV2.swift:155-218`, **OFF-MAIN**) — with a
self-signed, identity-bound, time-bound record. A verifier caches the
freshest signed capability set seen for a given identity and refuses to
silently accept a lower-capability claim unless that claim is itself
freshly signed and unexpired (§3): an attacker cannot replay an old,
validly-signed, lower-capability record once its `expires_at_ms` has
passed, and cannot forge a new one without the identity's private key.

**Remaining gate:** a signed record by itself does not bind the suite actually
used by a session. PairInit V1 now transcript-binds the exact suite, roles,
profile, certificates, and prekey contribution, but is production-disabled.
V1's capability record also has no
monotonic sequence field (unlike alias records) — freshness relies on
`expires_at_ms` alone. Two differently-signed records with *overlapping*
validity windows have no defined tie-break in V1; the spec recommends
negotiating to the intersection of claimed bits until a future version adds
a sequence field. This is a stated scope gap, not a vector-backed guarantee.

**Link features (Phase 6b, built, gated off; not in this version):** PAD1
padding (link caps bit 9) and the RLK1 knock are negotiated where a third
party cannot strip them: bit 9 rides in the signed RIH1 hello (Internet
direct, p2p, Bluetooth) or in the LAN dialer's RLX1 inside the Noise
handshake hash, and the knock tag binds the dialer's ephemeral key, so
tampering breaks the handshake instead of downgrading it
([`RAVEN_LINK_PADDING_V1.md`](../protocol/RAVEN_LINK_PADDING_V1.md) §3,
[`RAVEN_LINK_KNOCK_V1.md`](../protocol/RAVEN_LINK_KNOCK_V1.md) §3-§4). Only
a contact's own build can stop offering them (an older build after a
reinstall). The capability high-water mark
(`raven_core::capability_floor`) keeps the best a contact offered; a later
link without padding or the knock is a Suspicious `SEC_CAPABILITY_DOWNGRADE`,
recorded and shown but never refused, so a friend on an older build still
gets through, unpadded. The knock's mark is acted on: a dialer stops before
Noise message 3 when a contact whose mark shows the knock answers without a
proof (`SEC_ADDRESS_IMPOSTOR`), and a listener moves from legacy to strict
mode only once every contact's mark shows it. Held by
`SECURITY_EVENTS_PRODUCTION_ENABLED`, `LINK_PADDING_PRODUCTION_ENABLED` and
`LINK_KNOCK_PRODUCTION_ENABLED` (all `false`). What padding and the knock do
not hide even when they are not downgraded: §3.17.

**Session profiles and security updates (Phase 6b, built, gated off):** the
capability high-water mark also holds the best session profile a contact
offered; a profile below it is an Alert, refused only under
`SUITE_FLOOR_PRODUCTION_ENABLED` (`false`; profile 1 is the only profile, so
nothing is refused yet). An older security notice is ignored
(`SEC_ADVISORY_ROLLBACK`), and an older release refused
(`SEC_BUNDLE_DOWNGRADE`) unless the person passes `--allow-downgrade` and
types `downgrade`, never below a notice's release floor (design D;
`ADVISORY_PRODUCTION_ENABLED`, `RELEASE_BUNDLE_PRODUCTION_ENABLED` = `false`).
A notice marks a suite DEPRECATED (a warning) or BROKEN (refused at its
consult point) only with 2 of the 3 release keys and an entry in the public
log, and nothing local overrides BROKEN. Not answered: a contact whose build
really is older (recorded, never refused, so friends on older builds still
get through), and anyone holding two release keys.

### 3.15 Malformed-packet attacker

**Can do:** Send a structurally invalid, truncated, oversized, or
field-tampered `RavenEnvelopeV1` frame to a peer, relay, or store node.

**Verdict: Partially protected.**

**Implemented boundary:** Rust and Swift envelope decoders reject oversized,
unknown-type, unknown-flag, invalid-time, non-64-byte-auth, length-overflow,
trailing, and truncated objects before endpoint logic. Go and Rust transport
admission bounds declared sizes and stalled reads before allocation. Existing
negative vectors cover bad magic, tampering, expiry, and framing.

**Remaining gate:** the production-disabled PairInit, indexed session state,
ACK codec, store request protocol, and complete endpoint state machine still
need sustained fuzz campaigns and cross-platform stateful fuzzing. Therefore
strict envelope parsing is implemented, but malformed-input protection for
the whole future endpoint is not yet a complete claim.

The corrected endpoint order in
`protocol/ATSAM_ENDPOINT_TRANSACTION_V1.md` is size → strict decode/type/time →
bounded session/tag candidate → outer device authentication → read-only
object duplicate check → AEAD open → recoverable ratchet/inbox/dedup/ACK-intent
commit → ACK worker. Attacker-chosen IDs are not durably inserted before
authentication. A zeroed magic byte is
rejected at decode (vector:
`shared-vectors/rvn1/negative/envelope_bad_magic.json`,
`unpack_result: reject`); a body altered after signing fails at the
authenticate stage because the appended `SHA-256(message_ciphertext)` no
longer matches what was signed (vector:
`shared-vectors/rvn1/negative/envelope_tampered_body.json`,
`verify_result: reject`); an expired envelope is dropped at the TTL stage
before authentication is even attempted (vector:
`shared-vectors/rvn1/negative/envelope_expired.json`,
`relay_action: drop`).

The earlier allocate-before-validate bridge issue is closed by preallocation
budgets and exact length limits; it remains covered by regression tests.

**Phase 6b (built, gated off; not in this version):** malformed input before
authentication is `SEC_PREAUTH_MALFORMED` about the source (R1 strike 2); a
contact's frame that breaks a rule after authentication (for example a PAD1
violation, which closes the link) is `SEC_CONTACT_MALFORMED`, a Notice. The
new decoders (PAD1 frames, RLK1 message 1, RAD1 notices, RTL1 snapshots, RRB1
manifests, RRBC containers, RUP1 frames) each have a negative vector per rule,
a Python reference that checks the vectors byte for byte, and a fuzz target
(`pad1_frame`, `rlk1_m1`, `rad1_decode`, `rtl1_snapshot`, `rrb1_manifest`,
`rrbc_container`, `rup1_frame`); only smoke runs so far, no long campaign.
Not covered: stateful fuzzing of the endpoint, as above.

### 3.16 Local malware

**Can do:** Run arbitrary code with the legitimate user's OS-level
privileges on the user's own device — a jailbreak, a malicious app with
excessive permissions, or a supply-chain-compromised dependency.

**Verdict: Out of scope.**

**Why:** Once an attacker can execute code as the user, they can read
whatever the app can read, including decrypted plaintext and any key
material the OS releases to a running, authorized process. No
application-layer protocol can defend against a fully compromised endpoint
— this is the same floor as §3.7, restated for a software rather than
physical attack vector. Endpoint integrity (OS sandboxing, code signing,
jailbreak detection) is the user's and the OS vendor's responsibility, not
a RAVEN protocol guarantee.

### 3.17 Traffic analyst

**Can do:** Observe connection metadata — who connects to whom, when, how
often, and how much data flows — across relays, store nodes, or the
internet bridge, without necessarily controlling any of them, and correlate
that shape over time.

**Verdict: Out of scope in this version.** Phase 6b's measures are built but
gated off, and even with all of them live the analyst keeps most of the
shape (below).

**Why:** `protocol/RAVEN_ROUTING_TAG_V1.md` §4 states this as an explicit
non-goal: routing tags resist linkage *at the tag-value layer* — an
observer cannot tell from tag bytes alone that two envelopes share a
recipient — but they do not resist *global traffic analysis*. An adversary
watching timing, volume, envelope size, and network position across the
system can still correlate flows through side channels the tag design does
not touch (e.g. "an envelope of size X leaves peer A one hop before an
envelope of similar size arrives at peer B"). This is the same underlying
gap named in §3.4 (passive ISP) and §3.8/§3.9 (Sybil/eclipse positioning
enabling better vantage points for exactly this kind of correlation).
Closing it would require cover traffic, batching, or timing obfuscation,
which Raven does not do and does not plan (below).

**Passive observation is undetectable.** An analyst who only records sends
nothing, so no Raven mechanism, current or planned, can notice one. Every
measure below reduces what a recording shows; none detects the recorder.

**What this version shows** (a release build, every Phase 6b gate shut), to
anyone on the same network (Wi-Fi, hotspot, cable): IP addresses,
connection times and durations, each frame's exact size and the fixed
handshake sizes (§3.4), and TCP port 7420. To anyone who connects to the
listener it also hands the same Noise static key on every network (Noise XX
message 2; encrypted, so a passive observer does not see it), which links
the laptop across networks. MAC addresses and computer names (DHCP, mDNS)
come from the operating system; the user guide gives the habits that help
([`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) sections 2 and 4). Anyone who
learned that static as a contact (or a former one) can recognise the
listener's IP address with it.

**The onion carrier (gated off: `ONION_PRODUCTION_ENABLED = false`).**
Anyone holding a card can open an onion link and read Noise message 2
before the contact gate. The onion link therefore answers with a static of
its own (`RAVEN_ONION_CARRIER_V1.md` §5.1), derived under another HKDF salt
and used on onion links only, never the device static above: it names
nothing beyond the onion address the card already shows, and no LAN or
Internet listener answers with it, so it cannot tie an IP address to the
card's identity. The RIH1 hello still signs it. What stays: anyone holding
a card can tell when the onion service is online (§12 of that spec).

**Phase 6b (built, all gated off; none is in this version).** Each measure
and what it does not hide; the full inventory of identifiers is in
[`design/2026-10-traffic-analysis.md`](design/2026-10-traffic-analysis.md)
§2 and §4:

- **PAD1 link padding** (`LINK_PADDING_PRODUCTION_ENABLED = false`): four
  frame-size classes instead of exact sizes. Does not hide the number,
  timing, direction or class of frames, how long a link stays open, or
  anything on a link to a peer without PAD1.
- **RLK1 link knock** (`LINK_KNOCK_PRODUCTION_ENABLED = false`, never live
  in release without `LAN_NOISE_PIN_PRODUCTION_ENABLED`): when a contact
  knocks, both sides use Noise statics made for that connection only, and
  the handshake gets random sizes. A stranger gets the derived static while the
  listener is in legacy mode (until every contact's capability mark shows
  the knock), a fresh one in strict mode, and no message 2 in silent mode
  ("Silent to strangers"; no command sets it yet). Does not hide addresses,
  ports, timing, connection counts or durations, that Noise XX runs, or
  that something accepts TCP connections on the port.
- **A random port for new profiles**
  (`LISTEN_PORT_RANDOM_PRODUCTION_ENABLED = false`): hides "this is Raven"
  from someone who only looks for 7420. The port stays the same on every
  network, so it is itself a handle that links the laptop across networks;
  existing profiles keep 7420 until `raven lan port random`.
- **Beacon jitter and a join round only on need** (Phase 3's
  `LAN_BEACON_PRODUCTION_ENABLED = false`; an amendment before its flip):
  two size ranges and random delays instead of fixed ones. Does not hide
  that a Raven node is on the network, or that a query, a quick answer and
  a link mark two contacts.
- **Pair seeds** (`PAIR_SEED_PRODUCTION_ENABLED = false`): beacon, knock and
  Bluetooth keys from a seed two friends rotate every 7 days, so a later
  thief of only an identity key cannot attribute old recordings. Does not
  help for periods without a seed, for the root knock that follows any
  seeded knock that got no proof (whatever answers at a friend's address
  without the proof, a stale address or an impostor, draws one per dial:
  RAVEN_LINK_KNOCK_V1 §2, §8), against a full disk image plus keystore, or
  against a later X25519 break (the seeds travel inside Noise).

**What stays visible with every gate live:** that two devices talk, when,
for how long, and how much (in four classes); their addresses; that
something listens on a TCP port while listening is on (meeting mode,
`raven lan on --for`, which is in this version, limits that window).

**Cover traffic: not planned.** Owner decision OD6b-13 took the
recommended option: no cover traffic; padding, handshake jitter, silent mode
and meeting mode instead. Constant-rate cover costs radio, battery and
latency, defeats meeting mode, and on a LAN a steady flow between two
laptops is itself a fingerprint (assessment table: design §7).
`protocol/RAVEN_CAPABILITIES_V1.md` defines no `coverTraffic` bit; the
routing-tag spec's pointer to one is stale.

**HNDL on the link layer:** a recording kept for a future quantum computer
opens the classical link layer (identities, route hints, pair seeds, real
frame sizes; §3.4), not the message content. A post-quantum link handshake
is Phase 6c work, not in this version.

**Detection:** none for passive observation. Active misuse produces design
A events, themselves gated (`SECURITY_EVENTS_PRODUCTION_ENABLED = false`,
[`SECURITY_EVENTS.md`](SECURITY_EVENTS.md)): `SEC_KNOCK_REPLAY` (a replayed
knock), `SEC_ADDRESS_IMPOSTOR` (no proof from a knock-capable friend's
address), `SEC_CAPABILITY_DOWNGRADE` (padding or the knock gone),
`SEC_CONTACT_MALFORMED` (an unpadded frame after padding started). The
answers (`SECURITY_RESPONSES_PRODUCTION_ENABLED = false`): a replayed knock is
a strike against its source (R1); an address another key answered at is
forgotten (R5); a downgrade is recorded and shown, never refused, except that
the dialer stops at a knock-capable friend's address that gives no proof.

---

## 4. How we treat this document

This file is part of the security boundary, not marketing copy, carrying
forward the same posture as its pre-pivot predecessor.

If a finding shows that a claim in this document does not match the
behavior of the shipped protocol or app, we will:

1. Fix the document to match reality first.
2. Then fix the implementation.
3. Acknowledge the gap publicly.

In that order. An outdated "protected" claim that no longer matches shipped
behavior is a more serious defect than an honestly-stated gap — fix the
claim before anyone relies on it.

Every **protected** or **partially protected** verdict above cites either a
frozen `protocol/*.md` section, a specific `shared-vectors/rvn1/` vector
file, or a specific shipped source file and line. Every **out of scope**
verdict states its reason. If a future change to `protocol/` or the shipped
apps invalidates a citation here, update this document in the same change —
do not let the citations drift from what is actually running.
