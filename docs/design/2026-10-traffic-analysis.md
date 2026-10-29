# Traffic analysis: what Raven shows on the network, and what Phase 6b hides

| | |
|---|---|
| **Status** | Design record, not a wire spec. P6.39 (2026-10-24): the identifier inventory (section 2), what each measure does not hide (section 4), the observers (section 5), the link layer against a later quantum computer (section 6) and the cover-traffic assessment (section 7). Every measure here is built behind its own `*_PRODUCTION_ENABLED` gate, and **every one of those gates is `false`: none of them is in this version.** A release build puts on the network exactly what earlier builds did (section 2, "This version"). |
| **Plan** | `docs/roadmap/plans/phase6-design.json`, design B ("Traffic-analysis and unlinkability hardening"), steps P6.33-P6.39. |
| **Owner decisions** | OD6b-8 (PAD1 buckets), OD6b-9 (the RLK1 knock on top of M0, per-connection statics, silent to strangers as a setting), OD6b-10 (a random port for new profiles), OD6b-11 (beacon amendment before its flip), OD6b-12 (pair seeds), OD6b-13 (no cover traffic). |
| **Wire** | This document changes no byte. The wire lives in [`RAVEN_LINK_PADDING_V1.md`](../../protocol/RAVEN_LINK_PADDING_V1.md) (PAD1), [`RAVEN_LINK_KNOCK_V1.md`](../../protocol/RAVEN_LINK_KNOCK_V1.md) (RLK1), [`RAVEN_LAN_BEACON_V1.md`](../../protocol/RAVEN_LAN_BEACON_V1.md) §3 and §8 (beacon jitter and the join round, amended before the beacon's flip) and [`RAVEN_ROUTE_HINTS_V1.md`](../../protocol/RAVEN_ROUTE_HINTS_V1.md) §14 (the `PAIR_SEED` entry). |
| **Other readers' versions** | Users: [`SAFETY_OFFLINE.md`](../SAFETY_OFFLINE.md) section 4 ("What people near you can see") and section 12. Reviewers: [`THREAT_MODEL.md`](../THREAT_MODEL.md) §3.4, §3.14 and §3.17. Protocol inventory: [`PROTOCOL_VERSIONS.md`](../../protocol/PROTOCOL_VERSIONS.md) (PAD1 and RLK1 rows). |

Paths use this shorthand: `rc/` = `node/crates/raven-core/src/`, `rn/` = `node/crates/raven-node/src/`.
Symbols, not line numbers, anchor every reference.

## 1. The honest starting point

- **Passive listening cannot be detected.** Someone who only records (on the same Wi-Fi, hotspot or
  cable, in Bluetooth range, or on an Internet path) sends nothing, so nothing Raven does can notice
  them, and nothing in this document changes that. What such a listener learns depends only on what
  Raven puts on the air. The defence is to put less there: encryption, padding, identifiers that do
  not link, and listening only when needed (meeting mode, `raven lan on --for`).
- **What stays visible whatever Raven does:** that two devices talk, when, for how long, and roughly
  how much; their IP addresses; on a radio, that a device is there. No measure below hides these,
  and section 7 explains why cover traffic is not the answer.
- **In this version** every gate below is shut. The network sees the "This version" column of
  section 2: exact message sizes, port 7420, and a listener key that is the same on every network.

## 2. Identifier inventory (design B §1)

What can link a laptop, or a pair of friends, over time. "This version" is a release build with every
Phase 6b gate shut (and the Phase 3-5 gates as they are: the LAN beacon, p2p, PeerId rotation and
Bluetooth are off too). "Gates live" is what the gated code does once its gate is flipped.

| Identifier | Who sees it | This version | Gates live | Still links (honest) |
|---|---|---|---|---|
| IP addresses, connection times and durations | Anyone on the path | Visible | Visible | Always: Raven has no mix network and no relays that hide them on a LAN. |
| Listener's Noise static | Anyone who connects (Noise XX message 2; encrypted, so a passive listener does not see it) | Derived from the identity seed (`rc/lan_noise.rs` `derive_noise_static`): the same key on every network for the life of the identity | `LINK_KNOCK`: a fresh static per connection for a contact who knocked; for anyone else the derived static in **legacy** mode, a fresh one in **strict** mode, no message 2 at all in **silent** mode | Legacy mode lasts until every contact's capability floor shows the knock (then strict, automatically) or the user turns silent on; until then a stranger who connects still gets the lifelong key. |
| Dialer's Noise static | Whoever answers (message 3) | The derived static; M0 (`LAN_NOISE_PIN_PRODUCTION_ENABLED`, also `false`) would stop before message 3 at a key not pinned for that contact | A fresh static when the listener's proof verified; no message 3 at a knock-capable contact's address that gave no proof | A dial to a listener without the knock still sends the derived static once the M0 pin matches. |
| Signed bind / RIH1 hello | The contact, after the contact gate (inside Noise) | The identity (by design); but the LAN dialer sends its bind before it checks who answered, so whatever answers at a friend's old address gets it too (the gap M0 closes, gated off) | Unchanged for the contact; with the knock a dialer stops before message 3 at a knock-capable friend's address that gave no proof, so an impostor there gets nothing | It *is* the identity; the contact sees it, and so does anyone who later breaks X25519 on a recording (section 6). |
| Listen port | Anyone on the network | TCP 7420 for every profile | `LISTEN_PORT_RANDOM`: a random port for each new profile, between 20,001 and 49,151 with the well-known ports of common software skipped (`rc/node_policy.rs` `lan_port_pickable`); existing profiles keep 7420 until `raven lan port random` | A random port that stays the same is itself a handle: a laptop that listens on the same unusual port on every network it joins can be recognised by it. It hides "this is Raven" from someone who looks for 7420, not "this is the same laptop". |
| Handshake sizes | Anyone on the path | Fixed: message 1 32 bytes, message 2 96, message 3 64 (75 on LAN with RLX1) | `LINK_KNOCK`: 64-95, 112-143 and 64-128 bytes, random | The Noise XX pattern itself (three messages, their order, sizes in narrow ranges, a 4-byte length before each) stays recognisable. |
| Frame sizes | Anyone on the path | Exact: the cleartext 4-byte length before each Noise message gives every frame's size (an ACK 293 bytes, a PairInit 2,788, a text about its own length) | `LINK_PADDING`: four classes, 512 / 4,096 / 16,384 / 65,519 bytes plus the 16-byte tag, on links where both sides offered PAD1 | The number, timing, direction and class of frames; every frame on a link with a peer without PAD1; the LAN dialer's bind (96 bytes, fixed anyway) and the hellos. |
| LAN beacon (Phase 3) | Anyone on the segment | Not sent (`LAN_BEACON_PRODUCTION_ENABLED = false`) | Queries 160-191 bytes, answers 48-63, the first copy after a random 0-500 ms and the repeat 100-400 ms later; a join round only when something waits (a queued message, mail held for a friend, or meeting mode); tags keyed per pair, 10-minute epochs, keys from the pair seed (`PAIR_SEED`) or the R2 root | That a Raven node is on the network (UDP 7420, the group addresses, two size ranges); a query, then an answer within 3 s, then a TCP link marks two contacts. |
| Pair keys (beacon 0x02, knock 0x03, Bluetooth 0x01) | Whoever later holds an identity key, or breaks X25519 (section 6) | The R2 root: X25519 of the two identity keys (`rc/lan_beacon.rs` `pair_root`), no forward secrecy | `PAIR_SEED`: `K_pair` from a seed the two friends rotate every 7 days over authenticated links; the root stays the fallback | Periods without a seed (before the first, after one is lost); a full disk image plus keystore (seeds live in a sealed file); a later X25519 break (the seeds travel in RRH1 inside Noise). |
| libp2p PeerId (Phase 4) | Relays, p2p peers | p2p off (`P2P_PRODUCTION_ENABLED = false`) | 28-day epochs with `PEER_ROTATION` (`false`; an opt-in setting even after a flip). Reused as designed; 6b adds nothing | Within an epoch. |
| Bluetooth LE service UUIDs (Phase 5) | Anyone in radio range | Not sent (`NEARBY_PRODUCTION_ENABLED = false`) | Per-pair UUIDs, 15-minute epochs, keys from the pair seed when one exists | Radio presence; sightings inside one epoch; address and token rotation are not synchronised; the computer's Bluetooth name to a device that connects. |
| Routing tags, `dest_device_hint = 0` | Carriers | Per object | Unchanged | Sizes and times of carried objects. |
| Wi-Fi (MAC) address, computer name, mDNS and DHCP | The network | The operating system's behaviour, not Raven's | Guide text only ([`SAFETY_OFFLINE.md`](../SAFETY_OFFLINE.md) sections 2 and 4): a private Wi-Fi address and a plain computer name | A private address kept per network still links repeat visits to the same network; many systems announce the computer's name on every network. |

## 3. Gates and lab switches

Every gate stays `false` until the owner approves its own flip (README section 2, rule 3). A debug
build opens one with its lab switch; a release build reads none of them (CI's release "lab switches
inert" step runs the release tests with the beacon, PAD1, knock, random-port and pair-seed switches
set).

| Measure | Gate (all `false`) | Debug lab switch | Steps | Spec |
|---|---|---|---|---|
| PAD1 link padding (LAN, Internet direct, p2p, Bluetooth) | `LINK_PADDING_PRODUCTION_ENABLED` | `RAVEN_LAB_LINK_PADDING=1` with `RAVEN_LAB_TEST_A=1` | P6.33, P6.34 | [`RAVEN_LINK_PADDING_V1.md`](../../protocol/RAVEN_LINK_PADDING_V1.md) |
| RLK1 link knock, per-connection statics, handshake shape jitter, legacy / strict / silent (LAN and Internet direct) | `LINK_KNOCK_PRODUCTION_ENABLED` (a compile-time check keeps it shut in release while `LAN_NOISE_PIN_PRODUCTION_ENABLED` is) | `RAVEN_LAB_LINK_KNOCK=1` with `RAVEN_LAB_TEST_A=1` | P6.35 | [`RAVEN_LINK_KNOCK_V1.md`](../../protocol/RAVEN_LINK_KNOCK_V1.md) |
| A random listen port for new profiles | `LISTEN_PORT_RANDOM_PRODUCTION_ENABLED` | `RAVEN_LAB_RANDOM_PORT=1` with `RAVEN_LAB_TEST_A=1` | P6.36 | none: local (cards, route hints and beacon answers already carry the port) |
| Beacon length and timing jitter, join round only on need | Phase 3's `LAN_BEACON_PRODUCTION_ENABLED` (no gate of its own: an amendment before the flip) | `RAVEN_LAB_LAN_BEACON=1` | P6.37 | [`RAVEN_LAN_BEACON_V1.md`](../../protocol/RAVEN_LAN_BEACON_V1.md) §3, §8 |
| Pair-seed rotation | `PAIR_SEED_PRODUCTION_ENABLED` (on top of `ROUTE_HINTS_PRODUCTION_ENABLED`, also `false`) | `RAVEN_LAB_PAIR_SEED=1` with `RAVEN_LAB_TEST_A=1` and route hints live | P6.38 | [`RAVEN_ROUTE_HINTS_V1.md`](../../protocol/RAVEN_ROUTE_HINTS_V1.md) §14 |
| The `SEC_*` events that report active misuse (section 8) | `SECURITY_EVENTS_PRODUCTION_ENABLED` | `RAVEN_LAB_SECURITY_EVENTS=1` with `RAVEN_LAB_TEST_A=1` | P6.22-P6.29 | [`SECURITY_EVENTS.md`](../SECURITY_EVENTS.md) |

Not built: a command that sets "Silent to strangers" (`security_silent_to_strangers` in the node
policy exists, default automatic; RLK1 §10), and the settings rows of design B's UX ("Hide message
sizes on the network", "Silent to strangers: Automatic | On | Off").

## 4. What each measure does not hide

| Measure | Hides (once its gate is live) | Does not hide |
|---|---|---|
| PAD1 link padding | A frame's exact size: an observer sees one of four classes. ACKs and short texts share 512 bytes; PairInit, RLB1 offers and medium texts share 4,096, so "a new session started" does not stand out. | How many frames travel, when, in which direction, and how long a link stays open; each frame's class; the handshake sizes (the knock jitters those); anything on a link where one side has no PAD1 (an older build), since padding is negotiated per link and never forced. Cost: ACKs and short texts grow to 512 bytes, medium texts to 4 KiB; noticeable only on Bluetooth. |
| RLK1 link knock and per-connection statics | From a scanner or an impostor at a friend's address: the listener's lasting static (strict and silent modes) and the dialer's static (it stops before message 3); from anyone, that two connections came from the same laptop through its static. | IP addresses, ports, timing, connection counts and durations; that Noise XX runs (the pattern stays recognisable to a prober that gets message 2); a contact's identity from that contact; the lifelong static from strangers while the listener is in legacy mode. Not on the p2p link (its peer gate refuses strangers first; the PeerId is Phase 4's) or on Bluetooth (an RNK1 knock opens the pipe). |
| Handshake shape jitter (with RLK1) | The fixed 32 / 96 / 64-byte handshake. | The Noise XX pattern: three messages in a fixed order with sizes in narrow ranges. |
| Silent to strangers | From a scanner: that a Raven listener answers on the port. | That something accepts TCP connections on that port (the port closes only after message 1); it also shuts out contacts without the knock, which is why it is a setting and automatic mode stops at strict. No command sets it yet. |
| A random listen port | That a laptop runs Raven, from someone who only looks for port 7420. | The same laptop across networks (the port stays the same, see section 2); Raven, from someone who completes a handshake on the port; existing profiles keep 7420 until the user moves them. |
| Beacon jitter and join round on need | Fixed sizes and a fixed answer delay; a join round on every network change ("a Raven node just joined"). | That a Raven node is on the network; that a query and a quick answer followed by a link mark two contacts; nothing hides the beacon's group, port or two size ranges. |
| Pair seeds | Old beacon tags, knock tags and Bluetooth tokens from someone who later steals only an identity key (a seed-phrase backup, a keychain export). | Periods without a seed; the root knock that follows any seeded knock that got no proof (whatever answers at a friend's address without the proof draws one per dial, RAVEN_LINK_KNOCK_V1 §2); someone with a full disk image and the keystore (the seed file is sealed under the profile's at-rest keys, and old copies on an SSD stay readable while those keys exist); a later X25519 break, which reads the seeds from recorded RRH1 frames (section 6). After one side loses its seeds, the other side's seeded beacon queries and Bluetooth tokens go unrecognised until the next authenticated link (RAVEN_ROUTE_HINTS_V1 §14.3). |
| Meeting mode (`raven lan on --for`, in this version) | How long the laptop waits for connections: only while the meeting lasts. | Everything in section 1 while it is on. |

## 5. Observers (design B threat model, re-checked against the code)

| Observer | This version sees | With the 6b gates live, sees | Still sees (honest) |
|---|---|---|---|
| T1 passive, same network | IPs, MACs, port 7420, connection times and durations, exact frame sizes, fixed handshake sizes | IPs, MACs, the profile's port, times, durations, four size classes, handshake sizes in ranges | That two devices talk, when, how long, and how much (in classes). MAC and computer-name leaks are the operating system's (guide text). Undetectable. |
| T2 active stranger (scanner) | A Noise XX responder on 7420 that hands every dialer the same lifelong static | Legacy mode: the derived static (unchanged for strangers). Strict mode: a fresh static per probe. Silent mode: a TCP port that closes after message 1 | That something listens on a TCP port while listening is on (meeting mode limits the window). |
| T2 impostor at a friend's old address | The dialer's identity: its bind goes out before it checks who answered (the gap in SAFETY_OFFLINE section 1; M0 closes it, gated off) | An ephemeral key and a random-looking 32-byte tag, even without a pin when the friend is knock-capable | A connection attempt at that address and time. |
| T5 radio observer (Bluetooth, Phase 5) | Nothing from Raven (Bluetooth gated off) | Per-pair tokens, 15-minute epochs, keys from the pair seed | Radio presence, address rotation gaps (Phase 5 risk 6). |
| ISP on an Internet path (Internet direct, p2p) | Nothing from Internet direct or p2p: both are gated off in release (a LAN-direct link to a typed address that crosses it shows what T1 sees) | IPs, ports, times, durations, four size classes; RLK1 on Internet direct as on the LAN | As T1. |
| Recorder who keeps traffic for a future quantum computer | Section 6 | Section 6 | Section 6. |
| Later thief of an identity key | Can recompute every R2-rooted beacon and knock key, and so attribute recorded beacons and knocks | Only for periods without a pair seed | The root fallback window. |

## 6. The link layer against a later quantum computer (HNDL)

Every Raven link (LAN, Internet direct, the inner link of p2p and Bluetooth) is Noise XX over X25519:
classical. Someone who records a link today and breaks X25519 later ("harvest now, decrypt later")
opens everything the link layer carries:

- both sides' signed binds and hellos: who talked to whom, as identities;
- RRH1 route hints: addresses, ports, relay offers and **pair seeds**, so pair-seed forward secrecy
  does not hold against this recorder;
- PAD1's inner length, which rides inside the encryption: the real size of every recorded frame;
- the knock and beacon keys: the R2 root is itself an X25519 agreement of the two identity keys,
  which are public (cards), so every root-keyed tag becomes attributable, and seeded ones too once
  the seeds are read.

Message content does not open on the link-layer break alone: it travels inside the end-to-end
session, whose root (PairInit V1) mixes an ML-KEM-768 secret with the X25519 ones. A post-quantum
link handshake (ML-KEM-768 in Raven's own Noise handshake, RPQ1) is planned in Phase 6c
(`docs/roadmap/plans/phase6c-design.json`): **not in this version**. Even then logins stay
classical: recorded traffic would be protected, impersonation by a future quantum attacker would not
(roadmap README section 7).

## 7. Cover traffic: assessment (design B §6, owner decision OD6b-13)

| Option | Hides | Cost | Verdict |
|---|---|---|---|
| PAD1 size buckets | Message sizes (four classes) | 0.2-3.5 KB more per frame | **Do** (P6.33-P6.34; gated off) |
| Handshake shape jitter | Fixed handshake sizes | Tens of bytes | **Do** with the knock (P6.35; gated off) |
| Silent to strangers | That a Raven listener is there, from scanners | Needs every contact knock-capable | **Do**, automatic only up to strict; silent is a setting (P6.35; gated off, no command yet) |
| Constant-rate cover between contacts | When and how much two friends talk | Always-on links, radio and battery; a steady flow between two laptops on a LAN is itself a fingerprint; defeats meeting mode | **Do not** |
| Chaff frames inside an open link | The number of messages per meeting | Small; durations still visible | Not now (optional later) |
| Random send delays or batching | Typing and reply timing | Latency; an observer on the same LAN sees both ends anyway | **Do not** (custody deposits are already batched) |
| Cover beacons for nobody | Real queries | Multicast noise; the 8-slot padding already hides the number of targets | **Do not** |
| Decoy listeners | Which port is Raven | More attack surface | **Do not** |

The owner took the recommended option of OD6b-13: no cover traffic; padding, shape jitter, silent
mode and meeting mode instead. Cover traffic costs radio, battery and latency, defeats meeting mode,
and on a LAN a steady flow between two laptops is itself a fingerprint. So timing, volume and
duration stay visible (section 1). `RAVEN_CAPABILITIES_V1.md` defines no cover-traffic bit:
`RAVEN_ROUTING_TAG_V1.md` §4's pointer to a `coverTraffic` bit there is stale, and none is planned.
Phase 6c lists "optional meeting traffic shaping" as a later idea; it is not part of this assessment.

## 8. Detection

Passive listening: none, ever (section 1). Active misuse produces design A events, which are
themselves gated (`SECURITY_EVENTS_PRODUCTION_ENABLED = false`; [`SECURITY_EVENTS.md`](../SECURITY_EVENTS.md)):

| Event | When |
|---|---|
| `SEC_KNOCK_REPLAY` (11) | A recorded knock is played again (a cache of 4,096 matched nonces, 3 days, kept in the profile across restarts). |
| `SEC_ADDRESS_IMPOSTOR` (29) | A friend's address answers with another identity's bind, with a static other than the M0 pin, or (a knock-capable friend) without a proof. |
| `SEC_CAPABILITY_DOWNGRADE` (30) | A contact's link no longer shows padding or the knock it showed before (Suspicious; the link goes on: features are recorded, never refused). |
| `SEC_CONTACT_MALFORMED` (31) | A PAD1 refusal: an unpadded frame after the peer's first RPD1 frame, a nested or otherwise malformed RPD1 frame (the link closes). |
| `SEC_PAIR_SEED_ROOT` (35) | A contact matched with the root while a seed was expected (a Notice: the root keeps friends from being locked out). |

A third party cannot strip PAD1 or the knock: PAD1's bit 9 rides in the signed RIH1 hello (Internet,
p2p, Bluetooth) or in the LAN dialer's RLX1 inside the Noise handshake hash, and the knock tag binds
the dialer's ephemeral key. Only a contact's own build can stop offering them, which the capability
floor shows.

## 9. Evidence, and what waits

- **Pure code (raven-core):** PAD1 codec round trip for every length into the right bucket and every
  negative vector (`rc/link_padding.rs`); RLK1 tag and proof KATs, the constant-time compare, the day
  window, the replay cache and the legacy / strict / silent tables (`rc/link_knock.rs`); the padded
  beacon ranges (`rc/lan_beacon.rs` `kind_of`, `with_tail`); the random port's pick rules
  (`rc/node_policy.rs`); the pair-seed state machine and its property test (`rc/pair_seed.rs`). Fuzz
  targets `pad1_frame`, `rlk1_m1`, `lan_beacon_datagram`.
- **Real nodes:** carrier_matrix C86 part 1 (padding over LAN and Internet direct through a recording
  proxy; a padding node and one without, both ways), part 2 (knocked handshakes in their size ranges,
  two stranger probes see two statics in strict mode, no message 2 in silent mode, an M0-only peer
  still reaches a knocking node) and part 3 (pair seeds agreed, knocked with, lost and agreed again);
  fault matrix s115 (`RAVEN_FAULT_PADDING=1`, `RAVEN_FAULT_KNOCK=1`; with `RAVEN_FAULT_PADDING_OLD_BIN`
  an older build carries exactly the same message lengths as this one with the gate shut), s04r
  (`RAVEN_FAULT_RANDOM_PORT=1`) and s82 (the beacon's two ranges; the netns capture check on Linux).
- **Waits for P6.32** (the attack harness with traffic-tampering proxy modes, set aside by the owner
  on 2026-10-23): its rows C80-C85 and s110-s114, among them the impostor rows (s113) that put a
  fake listener at a friend's address, and the knock and padding rows that need a tampering proxy.
- **Owner equipment:** real row R35 (a meeting on a hotspot the owner controls, captured with
  tcpdump: sizes in the four classes, the knocked handshakes' ranges and silent mode), steps and
  bars in [`P6_REAL_ROWS_CHECKLIST.md`](../P6_REAL_ROWS_CHECKLIST.md) section 7. A capture cannot
  show that statics change per connection (Noise XX encrypts them); C86 is the evidence for that,
  and the row records it as not shown. The unsigned flip paperwork is
  [`WAIVER_TRAFFIC_ANALYSIS_DRAFT.md`](../WAIVER_TRAFFIC_ANALYSIS_DRAFT.md).
