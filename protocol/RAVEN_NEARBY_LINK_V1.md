# RAVEN Nearby Link V1 (RNL1): Bluetooth LE nearby carrier for terminal nodes

**Version:** 1 (`rvn1`). Parts: RNB1 (pairwise beacon tokens), RNK1 (knock), RNP1 (pipe) and the
Raven link with the Noise prologue `raven/nearby-link/v1`.

**Status:** Draft. Production is disabled (`NEARBY_PRODUCTION_ENABLED = false`, raven-core
`nearby_gate.rs`, which the carrier plumbing step adds). The lab switch `RAVEN_LAB_NEARBY=1` works in
debug builds only (owner decision O5-13: its own switch, because every lab harness already sets
`RAVEN_LAB_TEST_A`).

**Implements:** Private Rendezvous R2 under its revision-5 Bluetooth LE profile
([`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](RAVEN_PRIVATE_RENDEZVOUS_V1.md) §5.3b, for owner approval).

**Companions:** [`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](RAVEN_PRIVATE_RENDEZVOUS_V1.md) §3.1, §5.3,
§5.3a and §5.3b (R2); [`RAVEN_LAN_BEACON_V1.md`](RAVEN_LAN_BEACON_V1.md) §2.2 (the R2 pairwise root
and the medium registry); [`RAVEN_CARRIER_CONFORMANCE_V1.md`](RAVEN_CARRIER_CONFORMANCE_V1.md)
§3.2, §11.3 and §13; [`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md) §3;
[`RAVEN_BLE_FRAMING_V1.md`](RAVEN_BLE_FRAMING_V1.md) (RBF1 is untouched and is not used by this
profile).

**Audience:** re-implementers of the nearby carrier.
**Reference:** Rust `raven_core::nearby_link` (keys, tokens, knock, frames and the pipe state
machine), the Python reference `protocol/reference/raven_protocol/nearby.py`, and the vectors in
`shared-vectors/rvn1/nearby/` (§10).

---

## §0 Scope and layering

```
BLE radio: GATT (ATT Write Command / Handle Value Notification); L2CAP CoC reserved for a later revision
  -> RNK1 knock (before any Noise byte, pair-key MACs)
  -> RNP1 pipe (2 ordered byte channels, sequence numbers and credits)
  -> Raven link: Noise_XX_25519_ChaChaPoly_BLAKE2s, prologue "raven/nearby-link/v1",
     RIH1 hello, contact gate, RLB1, dispatch frames
     (byte-identical to Internet direct except the prologue)
  -> unchanged sealed endpoint objects and ACKs
```

- The link is one hop. Its class is `ENDPOINT_AUTHENTICATED` (Conformance §3.2).
- **RNP1 is stream framing beneath Noise.** It is NOT an endpoint-object fragment profile
  (Conformance §9.3). Endpoint objects are never fragmented at the endpoint layer: an RNP1 channel
  carries the Noise transport stream, and Noise AEAD fails closed on any corruption, loss or
  reordering that RNP1 did not already refuse.
- Only **pinned (verified) contacts** take part, and only when this node holds a valid, non-revoked
  cached device certificate for the contact, obtained from an earlier authenticated link (any
  carrier). A stale prekey does not matter: the certificate does.
- First contact over BLE is out of scope.
- BLE pairing and bonding are never used and never trusted.

## §1 Notation

- `||` is concatenation. `u16be` and `u64be` are big-endian. Labels are ASCII with no terminator.
- HMAC is HMAC-SHA256. HKDF is HKDF-SHA256 (RFC 5869).
- `[0..16]` is truncation to the first 16 bytes.
- `E_x` is the 32-byte Ed25519 identity key of `x` (the collapsed device tier: device key = identity
  key, [`WAIVER-LAN-DIRECT-2026-10-07`](../docs/WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) §4
  item 3).

## §2 RNB1: pair keys and beacon tokens

**Pair keys.** RNB1 defines no root of its own. It takes the R2 pairwise root that the LAN beacon
already uses (one root per pair, shared by every medium; LAN Beacon V1 §2.1-§2.2, R2 §5.3a item 2)
and the Bluetooth LE medium byte `0x01`:

```
Z       = X25519(own Ed25519 secret scalar, Montgomery(E_peer))      ; LAN Beacon V1 §2.1
          contact-key checks of LAN Beacon V1 §2.1: canonical point, not small order,
          not the own key; an all-zero Z is refused (non-contributory)
K_root  = HKDF(salt = "rvn1/r2-pair/v1", IKM = Z, info = "root" || E_lo || E_hi, L = 32)
          (E_lo, E_hi) = the two identity keys sorted bytewise
K_ble   = HKDF-Expand(PRK = K_root, info = "medium" || 0x01, L = 32)
K_tok   = HKDF-Expand(PRK = K_ble,  info = "RNB1-token", L = 32)
K_knock = HKDF-Expand(PRK = K_ble,  info = "RNB1-knock", L = 32)
```

- No RNB1 key is a message, session, route, mailbox or ACK key. They live in memory only, are
  wiped on drop, and are never stored or logged.
- Both sides of a pair compute the same keys. Medium `0x02` (the LAN beacon) takes its own key from
  the same root, so a key of one medium never verifies on the other.
- **Pair seeds** (Phase 6b, gated by `PAIR_SEED_PRODUCTION_ENABLED = false`;
  [`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §14): two contacts that share a pair seed
  take `K_ble` from `K_pair` in `K_root`'s place. A side advertises its token, and knocks on its
  own service, with its current seed's keys (the root's while it has none); a scanner matches the
  tokens of every key set it accepts (its current seed's, a leader's proposal's or its previous
  seed's, and always the root's) and knocks with the set whose token it saw. Frames are
  unchanged.

**Tokens.**

```
epoch   = floor(unix_ms / 900000)                                    ; 15 minutes
T(epoch, A) = HMAC(K_tok, "RNB1" || 0x01 version || 0x01 medium=BLE || u64be(epoch) || E_A)[0..16]
T[6]    = (T[6] & 0x0F) | 0x40 ;  T[8] = (T[8] & 0x3F) | 0x80        ; RFC 9562 version-4 layout
C       = SHA-256("RNB1-char" || T)[0..16], with the same version-4 bits ; characteristic UUID
```

- `A` is the **advertiser**: the side that advertises `T` and hosts its GATT service (the
  peripheral). Its contact scans for `T(epoch, A)`. The two directions have different tokens.
- **UUID text** is lowercase 8-4-4-4-12 over `T[0..16]` in order.
- **On air** (AD type 0x06/0x07) the bytes are `T` reversed (little-endian).
- **Windows GUID** = `GUID::from_u128(u128::from_be_bytes(T))`.
- A **scanner** at epoch `e` accepts `e-1`, `e` and `e+1` (within u64).
- The version-4 bits keep every token and characteristic UUID off the Bluetooth Base UUID
  (`xxxxxxxx-0000-1000-8000-00805f9b34fb`).

**KDF binding note.** The keys bind the two identity keys (lineage keys), not exact device
certificate digests as Private Rendezvous §3.1 describes. This is the deviation R2 §5.3a item 2
already records for the collapsed device tier: certificate renewal does not break discovery. When
per-device keys land, the certified device X25519 keys and both certificate digests replace the
identity keys under a new domain (a new version of this profile). Admission (§0, §7) still checks
the cached certificate and revocation before any key is derived.

## §3 Advertisement (R2 BLE profile)

- **Packet:** a legacy connectable ADV_IND carrying, besides any Flags the OS adds, exactly one
  128-bit service UUID: `T`.
  - No Local Name, Manufacturer Data, Service Data, TX Power or Appearance.
  - The scan response holds no Raven-chosen data.
- **Who advertises:** a node advertises `T(epoch, self)` for contact `P` only when:
  - (a) user-initiated work for `P` exists within `FOREGROUND_TTL` = 15 min (a send, an open chat,
    or `nearby on P --for`), and there is still queued work for `P`; or
  - (b) `nearby on P` was set explicitly.
- **Air limits:** at most 1 token on air; at most 2 contacts in rotation, with 5 s slots.
- **Address:** advertising MUST use a random (private) device address. A node whose controller would
  advertise from a public address does not advertise.
- **Scanning:** passive where the OS allows. A scan matches every eligible contact's
  `T(epoch±1, contact)`. Background scanning is allowed because it is passive.
- **What a match permits:** one bounded connect, then RNK1, then Noise. At most 1 attempt per
  contact per 10 s, and at most 4 pipes. A match is never trust, presence or contact evidence.

## §4 GATT profile

- **Primary service** UUID = `T`.
- **One characteristic**, UUID = `C`:
  - properties: WriteWithoutResponse | Write | Notify;
  - no Read;
  - no descriptors other than the CCCD (0x2902);
  - writable; no encryption or authentication required.
- **Direction:**
  - central -> peripheral: Write Command, or Write Request only if the stack cannot send Write
    Commands;
  - peripheral -> central: Notification, sent only to that central where the OS supports
    per-central targeting.
- **One RNK1 or RNP1 frame per ATT PDU.** Frames never span PDUs.
- **Frame size:** `max_tx = min(ATT_MTU - 3, 512)` per direction; the receiver's `max_rx` is the
  sender's `max_tx`.
  - A side whose `max_tx < 64` does not start the knock: the central sends no HELLO, and the
    peripheral stays silent.
- **Epoch rollover:** the service of epoch-1 stays published only while a pipe uses it, so there are
  at most 2 services per contact.

## §5 RNK1 knock (before any Noise byte)

```
HELLO     C->P  35 B: 0x01 || 0x01 version || flags_c || nonce_c[16] || tag_h[16]
          tag_h = HMAC(K_knock, "RNK1/hello" || T || flags_c || nonce_c)[0..16]
CHALLENGE P->C  35 B: 0x02 || 0x01 version || flags_p || nonce_p[16] || tag_p[16]
          tag_p = HMAC(K_knock, "RNK1/resp"  || T || flags_c || nonce_c || flags_p || nonce_p)[0..16]
PROOF     C->P  17 B: 0x03 || tag_c[16]
          tag_c = HMAC(K_knock, "RNK1/proof" || T || flags_c || nonce_c || flags_p || nonce_p)[0..16]
```

- `T` is the service the knock runs on (the peripheral's token). The first byte is the frame kind.
- **Nonces** are fresh CSPRNG output.
- **Flags:** bit 0 means "L2CAP capable" and is reserved (0 in V1). All other bits are 0 in V1.
  Every flag bit is covered by the MACs; a receiver ignores flag bits it does not know.
- **Tags** are compared in constant time.
- **When the peripheral answers.** It answers only a HELLO arriving on service `T` that meets all
  three conditions:
  - its version is 0x01;
  - `tag_h` verifies under that pair's `K_knock`;
  - its `nonce_c` is not in the replay cache (then it is added). The cache covers the current and
    previous epoch, at least 256 entries per token. Only a HELLO whose tag verified is ever added.
- **Otherwise the peripheral is completely silent.**
  - After 3 invalid frames it ignores the connection, and disconnects where the OS allows.
  - There is a 5 s deadline from subscription.
- **Central side.** The central sends PROOF only after a CHALLENGE of version 0x01 whose `tag_p`
  verifies. It aborts after 5 s.
- **Pipe UP.** The pipe is UP after the peripheral verifies PROOF. A knock kind after UP gets
  RESET(PROTOCOL).
- **Duplicate pipes.** If two pipes are UP for one pair, the one whose central has the
  lexicographically lower `E` survives. The other side sends RESET(DUPLICATE).

## §6 RNP1 frames (after UP)

| kind | name | body | total length |
|---|---|---|---|
| 0x10 | OPEN | chan u8 | 2 |
| 0x11 | DATA | chan u8, seq u16be, payload 1..max_tx-4 | 5..max_tx |
| 0x12 | CREDIT | chan u8, add u16be (1..64) | 4 |
| 0x13 | FIN | chan u8, next_seq u16be | 4 |
| 0x1F | RESET | code u8 | 2 |

- **Validity** (checked in this order):
  1. a frame longer than the receiver's `max_rx` gets RESET(MTU);
  2. an empty frame, an unknown kind, a wrong length, a chan other than 0 or 1, or a CREDIT `add`
     outside 1..64 gets RESET(PROTOCOL).
- **Channel ownership:**
  - chan 0 is opened only by the central; chan 1 only by the peripheral;
  - the opener is the Noise initiator on that channel; the other side runs the contact-gated
    responder;
  - each channel carries bytes both ways;
  - at most one instance per channel. A new OPEN is allowed only when the channel was never opened
    or both directions have FINed. OPEN of the other side's channel, or of a live instance, gets
    RESET(PROTOCOL).
- **Sequence numbers:** per instance and direction, starting at 0 and incrementing by 1 per DATA.
  They never wrap: the last DATA carries seq 65534, and a sender whose next seq is 65535 must FIN.
  A gap, a duplicate or seq 65535 gets RESET(PROTOCOL). DATA after the sender's FIN, or on a
  channel that is not open, gets RESET(PROTOCOL). FIN carries the sender's next seq; any other
  value gets RESET(PROTOCOL).
- **Credits:**
  - each direction of a new instance starts with 8 frames of credit; DATA consumes 1;
  - the receiver grants CREDIT as it delivers bytes to its link (the reference grants once at least
    4 frames are delivered and not yet granted, and stops granting after the sender's FIN);
  - outstanding credit is at most 64. DATA without credit, or CREDIT beyond 64, gets
    RESET(PROTOCOL).
- **Control frames** (OPEN, CREDIT, FIN) use no credit. More than 64 control frames received in a
  row, with no DATA sent or received between them, gets RESET(LIMIT). (DATA in either direction
  ends a run: the sender of a one-way transfer receives nothing but CREDITs.)
- **Channel content:** the Internet-direct link stream `(u32be length || Noise message)*`, with
  each Noise message at most 65535 bytes.
- **Timers:**
  - no open channel for 30 s: RESET(IDLE);
  - channel lifetime 300 s;
  - responder handshake deadline 20 s;
  - dial deadline 40 s.
- **RESET codes:** 1 PROTOCOL, 2 IDLE, 3 LIMIT, 4 SHUTDOWN, 5 MTU, 6 DUPLICATE.
  - After sending or receiving RESET (whatever its code), the pipe is dead and the central
    disconnects.
  - RNP1 does no retransmission. A broken pipe fails the dial, and the outbox retries the exact
    bytes.

## §7 Raven link on a channel

- **Link definition:** `RavenLink NEARBY_LINK = { prologue: "raven/nearby-link/v1", carrier:
  Nearby, name: "nearby", wire: "NEARBY" }`.
- **Unchanged parts:** XX, RIH1, the contact-gated responder, RLB1 and frames are exactly as in
  Internet direct. The distinct prologue means no TCP, libp2p or nearby transcript can complete
  against another.
- **Admission:** `carrier_allowed_for_contact(Nearby, pinned) = pinned`.
- **Key check:** the responder MUST close before sending its hello if the authenticated key is not
  the contact the pipe was knocked for.
- **PairInit** is allowed (endpoint-authenticated).
- **Friend custody (RFC1)** only under the `FRIEND_CUSTODY_*` gates.
- **Outbox route form:** `OutboxRoute { carrier: "nearby", dial: "nearby:<64 lowercase hex
  Ed25519>" }`.
  - It is derived live and never stored. Only an explicit lab `--carrier nearby` choice is stored.

## §8 Resource caps (per process)

- pipes: 4
- knocking connections: 8
- eligible contacts: 512 (scan table up to 1536 tokens)
- buffered per pipe: up to 2 x 64 x 512 B
- event queue: 256 (overflow disconnects that connection)

## §9 Disclosure (Conformance §13)

| Observer | What it can learn |
|---|---|
| Passive radio observer | That a laptop advertises one random-looking UUID, changing every 15 min, only while its user is sending to a nearby contact. It also sees the random address, cadence, RSSI and the sizes and timing of the encrypted exchange. Sightings within one epoch are linkable. |
| Device that connects | Whatever the OS GATT exposes: the GAP Device Name (the computer's Bluetooth name) and, on macOS, Device Information (model). It also sees one service with one characteristic. It gets no RNK1 or RNP1 response unless it holds `K_knock`. On a BlueZ peripheral, a subscriber also sees notifications of that pair's pipe: ciphertext and sizes. |
| Contact | Proximity and time. |

No identity, fingerprint, PeerId, address or Raven marker is ever advertised. The residual weak
fingerprints are the GATT shape (1 service, 1 characteristic with WwR|W|N) and the fixed knock
sizes, visible only to connecting or sniffing parties. A stranger never learns the stable Noise
static key: the knock comes first.

## §10 Vectors

`shared-vectors/rvn1/nearby/`:
- `rnb1_pair_keys_001.json`: for alice's pairs with bob and carol, `K_root` (the same bytes as
  `lan_beacon/lbcn_pair_keys_001.json`), `K_ble`, `K_tok` and `K_knock`, equal from both sides.
- `rnb1_tokens_001.json`: the pair alice-bob at epochs e0 and e0+1 with each side advertising: the
  HMAC input, the token, its text, on-air and Windows forms, and the characteristic UUID; the
  epochs a scanner at e0 accepts.
- `rnk1_knock_001.json`: alice (central) knocks on bob's service with fixed nonces and V1 flags:
  HELLO, CHALLENGE and PROOF; then HELLOs bob stays silent to (a replay, a flipped flag bit,
  version 2, a flipped tag bit, carol's HELLO).
- `rnp1_frames_001.json`: OPEN, DATA at the largest payload of max_tx 64, 185 and 512, CREDIT, FIN
  and RESET.
- `negative/rnb1_noncontributory_001.json`: small-order contact keys (refused before X25519) and
  Montgomery u-coordinates whose Z is all zero.
- `negative/rnp1_{bad_kind,short_data,credit_overflow,data_without_credit,seq_gap,chan_owner,data_too_long,knock_after_up}_001.json`:
  a role, `max_rx` and a frame sequence on a pipe that just came UP; the index of the refused frame,
  its error and the RESET it causes.

The people are alice and bob of `shared-vectors/v1/identities.json` (RFC 8032 §7.1 tests 1 and 2)
and carol (RFC 8032 test 3, inline): the LAN beacon vectors' people, so the vectors pin the shared
R2 root. `unix_ms` is 1700000000000, so e0 = 1888888.

Rust writes the files only under `RAVEN_REGEN_NEARBY_VECTORS=1` (raven-core test
`nearby_link::tests::nearby_known_answer_vectors`) and otherwise checks them. The Python reference
(`protocol/reference/raven_protocol/nearby.py`, test `tests/test_nearby_vectors.py`) recomputes
every vector from its inputs: this is the Rust and Python part of R2 §13.1's three-language
requirement. Swift does not apply in this repository (it holds no Apple nearby code); an Apple
implementation MUST match the same files before it takes part. Fuzz target: `rnp1_frame`
(`node/fuzz`).

## §11 Old peers and downgrade safety

- **Wire:** this is a new medium. No existing wire, vector or prologue changes. Old nodes never
  advertise or scan, so they are never knocked and never planned.
- **Versions:** a future version derives its keys under another domain (new labels or a new medium
  byte) and keeps RNP1 kinds it does not know refused, so a v1 node stays silent to its knocks.
- **IPC:** the new ops are `NearbyDial` and `NearbyControl`. An old daemon answers IPC_FRAME, and ash
  reports "raven-node too old for nearby". The Status field is optional (`serde(default)`).
- **Local files:**
  - `node_policy.nearby` is omitted while unset.
  - `outbox_routes.json` never stores Nearby routes. A lab `choice: "nearby"` makes older builds
    treat the file as unreadable; they fail narrow and plan LAN only.
  - New builds decode objects per entry and keep unknown entries.
- **Version bookkeeping:** a PROTOCOL_VERSIONS row (Draft), and `docs/PROTOCOL_FREEZE_HASHES_V1.md`
  regenerated.
