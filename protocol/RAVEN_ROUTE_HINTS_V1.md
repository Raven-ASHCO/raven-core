# RAVEN Route Hints V1 (RRH1, RLX1)

**Version:** 1 (`RRH1`, version byte `1`; `RLX1`, version byte `1`)
**Status:** Draft; **production disabled** (`ROUTE_HINTS_PRODUCTION_ENABLED = false`).
Lab only: debug builds with `RAVEN_LAB_ROUTE_HINTS=1`. Release builds ignore the
switch. Each carrier's own gate also applies (LAN direct, Internet direct, p2p).
Relay records (§11) are also held by the friend relay gate
(`FRIEND_RELAY_PRODUCTION_ENABLED = false`; debug builds: `RAVEN_LAB_FRIEND_RELAY=1`
with the p2p lab unlock `RAVEN_LAB_TEST_A=1`). Custody entries (§12) are also
held by the friend custody gates (`FRIEND_CUSTODY_PRODUCTION_ENABLED = false`,
`FRIEND_CUSTODY_WAN_ENABLED = false`; [`RAVEN_FRIEND_CUSTODY_V1.md`](RAVEN_FRIEND_CUSTODY_V1.md)).
The Phase 4 entry NAT_CLASS (§13) is also held by its own gate
(`NAT_CLASS_PRODUCTION_ENABLED = false`; debug builds: `RAVEN_LAB_NAT_CLASS=1`
with `RAVEN_LAB_TEST_A=1`), and so is PEER_SCHEDULE (§13.2:
`PEER_ROTATION_PRODUCTION_ENABLED = false`; debug builds:
`RAVEN_LAB_PEER_ROTATION=1` with `RAVEN_LAB_TEST_A=1`), and so is INET_DIRECT
(§13.3, auto-reach: `STUN_DISCOVERY_PRODUCTION_ENABLED = false`; debug builds:
`RAVEN_LAB_STUN_DISCOVERY=1` with `RAVEN_LAB_TEST_A=1`). The Phase 6b entry
PAIR_SEED (§14) is also held by its own gate (`PAIR_SEED_PRODUCTION_ENABLED =
false`; debug builds: `RAVEN_LAB_PAIR_SEED=1` with `RAVEN_LAB_TEST_A=1`).
Enabling it in production needs owner-signed Phase 2 amendments of the P2P relay
waiver (`docs/WAIVER_P2P_RELAY_DRAFT.md`, whose §6 lists route hints as a lapse
condition) and of the LAN-direct waiver (RLX1, RRH1 on LAN links).
**Audience:** re-implementers of the LAN / Internet / p2p direct links and of
the dial planner.
**Design:** the any-network reachability plan (an internal design document, not published)
(Phase 2 item 1, C5).

---

## 1. Purpose and properties

A contact tells another contact how to reach it: the relays it holds a
reservation on, its confirmed direct addresses, its LAN-direct port, whether it
holds sealed mail for its friends and, pair-blinded, the friends it collects its
own mail from (§12). Without it, a card or a `set-addr` is
the only way to learn a new route, so a contact whose relay or LAN port changes
cannot be reached until someone exchanges cards again.

- RRH1 is sent inside an authenticated Raven link, at most once each way,
  and only when the receiver is due one (§6.1): a change, or 30 minutes.
- It is **one-way**: never answered or acknowledged (§5.6).
- It is **never** wrapped in RVN1. It is never stored except by its receiver,
  and only to reach the sender. It is never forwarded or published (no DHT, no
  PeerRecord).
- It has **no signature**. The link (Noise transport plus the LAN bind or the
  RIH1 hello) authenticates it, so it stays deniable (design decision D8).

RRH1 changes nothing in `RavenEnvelopeV1`, RLB1, PairInit or the ATSAM endpoint
transaction. The RIH1 hello keeps its layout and gains one caps bit (§3.1). The
LAN Noise XX handshake keeps its pattern and its empty messages 1 and 2, and
gains an optional message-3 payload (§3.2).

## 2. Where it travels

- Only on endpoint-authenticated direct links, after both RLB1 offers:
  - LAN direct (no prologue);
  - Internet direct (prologue `raven/internet/v1`);
  - the p2p link inside `/raven/link/1.0.0` (prologue `raven/p2p-link/v1`).
- Never on custody, mesh, mailbox or bridge paths.
- At most one RRH1 per direction per link is expected. A receiver applies at
  most 2 per link. A third or later is consumed without effect; a dialer ends
  its reply wait as closed, and a listener counts it against its frame budget.

## 3. Negotiation

Rule: a peer sends RRH1 only when the other side advertised support **on this
connection**. A build that did not advertise it closes the link on RRH1, as on
any frame that is not RVN1 (§5.6).

### 3.1 Internet direct and p2p: RIH1 hello caps

- Hello caps bits 0-7 are node capabilities
  ([`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md) §2).
  Bits 8-31 are link features.
- `CAP_LINK_RRH1 = 0x00000100` (bit 8) means "I accept RRH1 on this link". With
  route hints on, a hello carries `CAP_INTERNET | CAP_LINK_RRH1 = 0x00000102`.
  With them off it carries `0x00000002`, byte-identical to earlier builds.
- `CAP_LINK_RRH1_ASK = 0x00000800` (bit 11) means "I hold none of your route
  hints: send me your RRH1 on this link" (§6.1). A side sets it only together
  with bit 8, on a link to a contact of which it holds no snapshot (none since
  it started, or it forgot them: `raven contact forget-address`, a new card,
  a removal). It is a request for this link, never a capability: a later
  hello without it is no downgrade. Today only a dialer sets it (it knows
  whom it dials before its hello).
- Receivers MUST ignore unknown bits. Every build already does: only
  `CAP_INTERNET` is required. A build before bit 11 ignores the request and
  tells as §6.1 says without it.
- The caps field is covered by the channel-bound hello signature, so it cannot
  be changed on the path or replayed onto another connection.

### 3.2 LAN direct: RLX1 in Noise XX message 3

- Messages 1 and 2 keep empty payloads unless RLK1 is in use
  ([`RAVEN_LINK_KNOCK_V1.md`](RAVEN_LINK_KNOCK_V1.md): a knock in message 1, a
  proof or random bytes in message 2). Message 2 goes to an initiator nobody
  has authenticated yet.
- The initiator (dialer) MAY carry an RLX1 payload in message 3:
  ```
  payload = "RLX1" || version 0x01 || entry*
  entry   = type u8 || len u8 || value[len]
  ```
- The whole payload is at most 64 bytes.
- Registered entry: `0x01 LINK_CAPS`, len 4, u32 big-endian, in the RIH1 caps
  bit namespace. Bit 8 = RRH1. Bit 9 = PAD1 link padding
  ([`RAVEN_LINK_PADDING_V1.md`](RAVEN_LINK_PADDING_V1.md) §3): the dialer
  pads once the listener's first RPD1 frame arrives. Bit 10 = RUP1 update
  exchange ([`RAVEN_UPDATE_EXCHANGE_V1.md`](RAVEN_UPDATE_EXCHANGE_V1.md) §2):
  the listener answers with its HAVE.
- Example (11 bytes): `524c5831 01 01 04 00000100`. With PAD1 too:
  `524c5831 01 01 04 00000300` (`link/rlx1_caps_002.json`); with RUP1 as well:
  `524c5831 01 01 04 00000700` (`update/rup1_frames_001.json`).
- Registered entry: `0x7E PAD`, any len, value ignored (zeros when sent). A
  knocking dialer adds one so message 3 has no fixed length
  ([`RAVEN_LINK_KNOCK_V1.md`](RAVEN_LINK_KNOCK_V1.md) §6): the payload is RLX1
  with `LINK_CAPS` (when it has caps) and `PAD`, at a random length up to 64
  bytes, also on a frame-less probe (caps then absent). Every RLX1 parser
  skips it as an unknown type, so the caps read as before
  (`link/rlk1_tags_001.json` `m3_payloads`).
- An empty payload means "no extensions". Every pre-RLX1 build sends it, and so
  does any build with route hints off.
- A dialer sends RLX1 only on dials that will read: dials that carry message
  frames, and announce links (§7). A frame-less probe, which closes right after
  the RLB1 offers, sends the empty payload. Otherwise the listener's RRH1 would
  arrive after the dialer closed, and the unread data would turn into a TCP
  reset.
- Bit 8 asks the listener for its RRH1 (§3.3). A dialer sets it only when
  route hints are due on that dial (§6.1): on an announce link, when it holds
  no RRH1 from the listener that it received within the refresh period (or
  no snapshot of the listener at all: it forgot them), or when the listener
  is due the dialer's own (only an asked listener's RRH1 lets the dialer
  send one). A dial that does not ask carries no RRH1 either
  way; its other bits (PAD1, RUP1) are offered as before. A LAN showing is
  never complete (`Seen`, Phase 6b P6.29): a dial without bit 8 is no
  downgrade.
- The receiver ignores the whole payload on any of:
  - magic is not `RLX1`;
  - version is not 1;
  - length below 5 or above 64;
  - a truncated entry;
  - a duplicate type;
  - `LINK_CAPS` with a len other than 4.
- Unknown types are skipped.
- RLX1 is parsed only after the contact gate. It never causes a close or a
  reply.
- Pre-RLX1 responders decrypt the m3 payload and discard it. With RLX1, m3
  grows from 64 to 75 bytes. The payload is mixed into the handshake hash but
  not into the chaining key, so the transport keys and both identity binds are
  unchanged (`lan/noise_xx_handshake_002.json`).

### 3.3 Order on the link

**Internet direct and p2p.** Both hellos are verified, then the RLB1 offers
travel as in [`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md) §3.
- The listener sends its RRH1 immediately after its RLB1 offer, if the dialer's
  verified hello has bit 8 and the dialer is due one (§6.1), or asked for it
  with bit 11.
- The dialer sends its RRH1 after verifying the listener's RLB1, before any
  other frame, if the listener's verified hello has bit 8 and the listener is
  due one (§6.1).
- Bit 8 stays in every hello while route hints are live: a hello is a complete
  showing of the sender's link features (Phase 6b P6.29). A frame-less dialer
  (an announce link) reads the listener's RRH1 for at most its reply wait
  (2 s), since one that is not due never comes.

**LAN direct.** The responder never signals in the handshake. Instead:
- The listener sends its RRH1 right after its RLB1 offer, if the dialer's
  LINK_CAPS has bit 8, whether or not the dialer is due one: that RRH1 also
  tells the dialer that the listener accepts RRH1, and the dialer asked
  because it wants it or has its own to tell (§3.2).
- The dialer sends its RRH1 only after receiving one on this link, and only
  when the listener is due one (§6.1). It does so at once, interleaved with
  its other frames.
- A dialer with no other frames (an announce link, §7) waits up to 2 s after the
  listener's RLB1 for that RRH1.

On every link RRH1 is consumed by the link layer. It is never handed to the
envelope dispatcher and never counts as a reply.

### 3.4 Version matrix

The same holds when "old" means "this build with route hints off".

| Dialer | Listener | Result |
|---|---|---|
| new | old | The old listener drops RLX1 (LAN) or ignores bit 8 (Internet, p2p) and never sends RRH1, so the new dialer never sends RRH1 either. Bytes after the handshake are identical to today; on LAN only m3 is longer. |
| old | new | Empty m3 / no bit 8, so the listener sends nothing. Identical to today. |
| new | new | At most one RRH1 each way, when due (§6.1). |

Since §6.1: a dialer of this revision always asks while it is due route
hints, so an older listener sends as it did; an older dialer always asks, so
a LAN listener of this revision answers it on every link (an Internet or p2p
one when the older dialer is due one).

## 4. Frame layout

Noise transport plaintext. All integers are big-endian.

```
 off len field
  0   4  magic       "RRH1"
  4   1  version     0x01
  5   8  generation  u64 >= 1
 13   4  ttl_s       u32 >= 60 (receivers clamp to <= 604800)
 17  ..  entries     type u8 || len u16 || value[len], until the end of the frame
```

- Frame length: 17 ..= 4096 bytes. This bound also bounds unregistered entries.
- Senders write entries in ascending type order, and the values of one type in
  their order of preference. Receivers accept any order.
- A frame with no entries is valid.

| type | name | len | value | max entries |
|---|---|---|---|---|
| 0x01 | P2P_ID | 38 | libp2p PeerId bytes of the sender: `00 24 08 01 12 20` \|\| ed25519_pub32 | 1 |
| 0x02 | RELAY | 1..=300 | ASCII multiaddr `/ip4\|ip6\|dns\|dns4\|dns6/<host>/(tcp/P \| udp/P/quic-v1)/p2p/<relay PeerId>`: an address of a relay the sender holds an active reservation on. Any port, including 443. | 4, naming at most 2 relays (§5.2) |
| 0x03 | DIRECT | 1..=120 | ASCII multiaddr `/ip4\|ip6/<literal>/(tcp/P \| udp/P/quic-v1)`, with no `/p2p`, no DNS and no circuit: a confirmed (UPnP-mapped, AutoNAT-confirmed, or reached by a contact from outside) address of the sender's libp2p host, then (auto-reach, §6) an address STUN discovery found for it that nothing confirmed yet, or, on LAN links only, a same-LAN listen address | 6 |
| 0x04 | LAN_PORT | 2 | u16 1..=65535: the sender's LAN-direct listener port. LAN links only. | 1 |
| 0x05 | CUSTODIAN | 32 | (Phase 2) Ed25519 device key of a friend the sender listed as custodian for this receiver ([`RAVEN_FRIEND_CUSTODY_V1.md`](RAVEN_FRIEND_CUSTODY_V1.md)). Receive-only since §12: senders MUST NOT emit it any more; receivers MAY still use it (§12.3). | 2 |
| 0x06 | CUSTODY_OFFER | 1 | flags u8. Bit 0 WAN: the sender serves RFC1 on Internet and p2p links. Bit 1 REACHABLE: the sender's libp2p endpoint is confirmed reachable (public or mapped). Bits 2-7 are sent as 0 and cleared on receipt. Its presence means "I hold sealed mail (RFC1) for my verified contacts" (§12). | 1 |
| 0x07 | CUSTODIAN_TAG | 33 | tag[32] \|\| flags u8. tag = SHA-256(`"raven/rrh1/custodian-tag/v1"` \|\| sender_ed25519[32] \|\| receiver_ed25519[32] \|\| custodian_ed25519[32]): a friend the sender collects its own mail from, or one it listed for this receiver (§12). The flags follow the custodian flags rule below. | 2 |
| 0x08 | PAIR_SEED | 40 (§14) | generation u32 \|\| seed[32] \|\| acked_generation u32: the pair's rotating seed (Phase 6b) | 1; checked on its own, never costing the frame (§14) |
| 0x20 | RELAY_OFFER | any (§11.1) | one relay offer record (§11): a relay the sender runs for its contacts, under the relay's own key | 2 kept, one per relay; checked one record at a time, never costing the frame (§11.2) |
| 0x21 | reserved | any | reserved, not used; skipped | - |
| 0x22 | NAT_CLASS | 5 (§13.1) | the sender's NAT mapping classes (Phase 4) | 1; checked on its own, never costing the frame (§13) |
| 0x23 | PEER_SCHEDULE | 14 + 40 n, n <= 8 (§13.2) | the sender's PeerId rotation schedule (Phase 4) | 1; checked on its own, never costing the frame (§13) |
| 0x24 | INET_DIRECT | 10..=48 (§13.3) | flags u8 \|\| ASCII `ip:port`: the public address of the sender's Internet direct listener (auto-reach) | 2; checked one at a time, never costing the frame (§13) |
| 0x25-0x2F | reserved for Phase 4 | any | not used yet; skipped | - |
| 0x30-0x3F | reserved for Phase 5 | any | not used yet; skipped | - |
| 0x40 | ONION | 104 (§15) | the sender's Tor onion binding ([`RAVEN_ONION_CARRIER_V1.md`](RAVEN_ONION_CARRIER_V1.md) §3): onion key, issued time, signature by the sender's Raven identity | 1; checked on its own, never costing the frame (§15) |
| 0x41-0x4F | reserved for the Tor onion carrier | any | not used yet; skipped | - |
| other | unregistered | any | skipped | - |

- Every RELAY and DIRECT byte is in 0x21..0x7e.
- RELAY entries that name the same relay PeerId are addresses of one
  reservation (for example TCP 7423 and TCP 443). They are fallbacks for each
  other.

**Type ranges.** 0x01-0x1F, 0x20 (RELAY_OFFER, §11) and the reserved 0x21 are
this document's (Phase 2 and later revisions of it). 0x22-0x2F are reserved for
the entries of Phase 4 (0x22 NAT_CLASS, 0x23 PEER_SCHEDULE and 0x24
INET_DIRECT are registered by §13) and 0x30-0x3F for
those of Phase 5; 0x40-0x4F are the Tor onion carrier's (0x40 ONION is
registered by §15); no other use may
take them. A type in them is registered only by a revision of this table.
Until then a receiver skips it (§5.1), and a receiver built before that
revision keeps skipping it, so an entry in these ranges is always optional: a
frame that carries it gives an older receiver the same hints.

**Custodian entries carry flags.** A custodian entry type added after 0x05
(0x07 CUSTODIAN_TAG, §12) ends its value with a flags u8:

| bit | name | meaning |
|---|---|---|
| 0 | HANDOFF_INBOX | Phase 5 (custody handoff between two custodians): the sender takes handoffs at this custodian; it registered its store tags there and the custodian answered OK within the last 24 h ([`RAVEN_CUSTODY_HANDOFF_V1.md`](RAVEN_CUSTODY_HANDOFF_V1.md) §3.5, §3.6) |
| 1 | LETTER_INBOX | reserved for Phase 5 |
| 2-7 | - | reserved |

Senders write 0 in every bit their revision does not define. Receivers ignore
(clear) the bits they do not know; an unknown bit never drops the entry or the
frame. 0x05 CUSTODIAN keeps its 32 bytes and carries no flags. This revision
defines bit 0 HANDOFF_INBOX (Phase 5): its senders set no other bit (§6) and its
receivers keep only that one (§5.2). A receiver built before it (Phase 3, which
defined no flag) clears every bit and keeps the entry, so a flagged tag still
names the custodian for it; it just never forwards.

Example (LAN scope, 22 bytes): `52524831 01 <generation u64> 0003f480 04 0002 1d6b`
(ttl_s 259200, LAN_PORT 7531).

## 5. Receiver rules

### 5.1 Structural: ignore the whole frame

The receiver ignores the whole frame (no state change, no close, no reply; a
counts-only log line, `RRH1_MALFORMED` in
[`RAVEN_ERROR_CODES_V1.md`](RAVEN_ERROR_CODES_V1.md)) on any of:
- a length outside 17 ..= 4096;
- bad magic;
- version is not 1;
- generation is 0;
- ttl_s below 60;
- a truncated entry (type, length or value);
- a registered type with a length out of range;
- more entries of one registered type than its max (RELAY: 4);
- LAN_PORT = 0;
- a RELAY or DIRECT byte outside 0x21..0x7e;
- a CUSTODY_OFFER whose length is not 1, or more than one CUSTODY_OFFER;
- a CUSTODIAN_TAG whose length is not 33, or more than 2 CUSTODIAN_TAGs.

These rules cover the types 0x01-0x07. A RELAY_OFFER record never makes the
frame ignored: it is checked on its own, and a bad one is dropped (§11.2).
Neither does a Phase 4 entry (NAT_CLASS, PEER_SCHEDULE, INET_DIRECT): a bad
one is dropped alone (§13). Nor does a PAIR_SEED (0x08, Phase 6b): a bad one is dropped alone
(§14).
A CUSTODY_OFFER value and a CUSTODIAN_TAG flags byte are never a reason to
ignore the frame: unknown bits are cleared (§5.2).

Unregistered types, including the reserved 0x21 and the reserved ranges
0x25-0x2F and 0x30-0x3F (§4), are skipped whatever their length and however
many there are. The frame bound limits them. A receiver built before §11 skips
0x20 the same way, so a frame that carries relay offers stays valid for it and
gives it the same hints. A receiver built before §12 skips 0x06 and 0x07 the
same way, and one built before §14 skips 0x08.

### 5.2 Semantic: drop the entry, keep the rest

- **Unpinned sender:** keep only LAN_PORT, and only if the frame arrived on a
  LAN link from a local-network address. CUSTODY_OFFER and CUSTODIAN_TAG are
  dropped on every link.
- **LAN_PORT:** kept only from a frame that arrived on a LAN link. From a pinned
  sender it is kept whatever the link's peer IP.
- **P2P_ID:** it must be an Ed25519 PeerId. On p2p links it must equal the
  libp2p PeerId of the connection. It must equal the PeerId in the receiver's
  contact book when the book has one, except (Phase 4, only while the
  receiver's PeerId rotation gate is live) when the same frame's PEER_SCHEDULE
  says the sender is rotating or postponed and names it (§13.2). A
  PEER_SCHEDULE naming a PeerId the receiver knows as another peer's (another
  contact's or a relay's) is ignored whole first, so it vouches for nothing
  (`RAVEN_P2P_PEER_ROTATION_V1.md` §8). Otherwise drop P2P_ID, every RELAY and
  every DIRECT.
- **RELAY/DIRECT without a valid P2P_ID:** drop.
- **RELAY:** drop it if it fails the strict grammar, names the sender's PeerId,
  or is a circuit (`p2p-circuit`). Drop it too if its host is an IP literal that
  is not globally routable unicast, on any link: a contact never makes the
  receiver dial loopback or its local networks. The DIRECT rule for
  IPv4-mapped, NAT64 and 6to4 addresses applies. A DNS name is kept; what it
  resolves to is held to the same rule when a circuit through it is dialled.
  Keep at most 2 distinct relays and at most 2 addresses of each, in frame
  order. Drop the rest and duplicates. In debug builds,
  `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1` admits loopback and private relays, and a
  loopback relay is also admitted while route hints run under their debug switch
  `RAVEN_LAB_ROUTE_HINTS=1` (one-machine harnesses). A snapshot stored before
  this rule is held to it when read.
- **DIRECT:** append `/p2p/<P2P_ID>`; drop it if the result fails the grammar,
  carries a WSS suffix (`RAVEN_WSS_TRANSPORT_V1.md` §2.3: endpoints never listen
  on WSS) or its host is not an IP literal. Keep it if the IP is globally routable unicast,
  at most 4 such. An IPv4-mapped, NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`)
  address is global exactly when the IPv4 address inside it is. A non-global
  entry is kept only when all of these hold:
  - the frame arrived on a LAN link;
  - the IP is a local-network address;
  - it shares the /24 (IPv4) or /64 (IPv6) with the link's peer IP.

  At most 2 such same-LAN entries are kept. In debug builds,
  `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1` admits loopback and private addresses as if
  they were global.
- **CUSTODIAN:** drop all-zero keys, the receiver's own key, the sender's key
  and duplicates.
- **CUSTODY_OFFER:** clear the unknown bits (keep `flags & 0x03`). An offer
  left with no bit set is still an offer.
- **CUSTODIAN_TAG:** drop all-zero tags. Clear the flag bits this revision does
  not define (keep `flags & 0x01`, HANDOFF_INBOX; a Phase 3 receiver kept
  `flags & 0x00`). A repeated tag is kept once, at its first position, with
  the flags of its copies OR-ed.
- **NAT_CLASS** (§13.1): kept only from a pinned sender whose P2P_ID passed.
  **PEER_SCHEDULE** (§13.2): kept only from a pinned sender, whatever its
  P2P_ID.
- **PAIR_SEED** (§14): kept only from a pinned sender, on any link; it is not
  part of either snapshot part (§5.3) and follows its own rules (§14.3).

`route_hints/rrh1_validated_001.json` has one case per rule, and
`route_hints/rrh1_validated_relay_002.json` one per case of the RELAY address
rule.

### 5.3 Generation

The receiver keeps one snapshot per sender, in two parts:
- the **global part**: P2P_ID, RELAY, global DIRECT, CUSTODIAN, CUSTODY_OFFER,
  CUSTODIAN_TAG and RELAY_OFFER (§11.3). CUSTODY_OFFER and CUSTODIAN_TAG follow
  the snapshot like every global entry: withdrawn when a newer generation lacks
  them, never used once the snapshot expired (the record a receiver keeps of an
  expired snapshot holds neither), and dropped when the sender is removed or
  blocked;
- the **per-link LAN part**: LAN_PORT, same-LAN DIRECT and the LAN IP.

The global part follows every frame, from any link:
- **generation higher than stored, or the stored snapshot expired:** replace
  the whole global part. Entries missing from the new frame are withdrawn;
- **equal generation:** extend the expiry;
- **lower generation:** ignore.

The LAN part follows only frames that arrived on a LAN link:
- such a frame replaces the whole LAN part when its generation is >= the LAN
  part's, or the LAN part expired;
- except that a frame of the LAN part's own generation that came from another
  peer IP and adds nothing to it (no LAN_PORT other than its port, no
  same-LAN DIRECT it lacks; its network the same) leaves the LAN part as it is,
  and does not extend its expiry either. A sender reached at two addresses
  (IPv4 and IPv6, a cable and Wi-Fi) tells one snapshot over both, and a
  receiver keeps fewer same-LAN DIRECT entries from one link than from the
  other (§5.2): replacing the part on every link made the stored view
  alternate (field E2: about 240 times an hour per contact, each a retry);
- the LAN IP is the link's peer IP. It is never taken from frame content;
- a frame that arrived on an Internet or p2p link never changes or withdraws the
  LAN part.

### 5.4 Expiry

`expires_at = received_at + clamp(ttl_s, 60, 604800)` seconds, by the receiver's
clock. An expired snapshot is not used, and the next frame from the sender
replaces it whatever its generation.

### 5.5 Use

- Only to reach the sender. A CUSTODY_OFFER is also used to leave mail for
  other contacts with its sender (§12.2).
- Never re-sent, and never put into the receiver's own RRH1, card or any frame.
- Not exposed except to the local user.

### 5.6 Never a reply

A receiver writes nothing in response to RRH1. A build with route hints off
treats RRH1 like any frame that is not RVN1 and closes the link. Senders
therefore MUST NOT send RRH1 without the §3 signal.

## 6. Sender rules

**Who gets what**
- The full snapshot goes only to a verified (pinned), unblocked contact.
- An unverified contact admitted on LAN under the local-network rule gets only
  LAN_PORT, and only on a LAN link.
- An RRH1 with no entries is still sent. It is the LAN capability answer (§3.3)
  and a withdrawal.

**Generation and TTL**
- The generation strictly increases per identity: `max(previous + 1, unix_ms)`.
- It changes exactly when an input of some snapshot changes. So for a given
  receiver an equal generation means identical content, except the per-link LAN
  part (LAN_PORT and same-LAN DIRECT), which is outside the generation digest;
  the local-network listen addresses those DIRECT entries are chosen from are
  an input (§6.1: a contact is told again only when the generation moves), and
  so is the LAN listener's address (and, for a wildcard one, this computer's
  networks).
- The default `ttl_s` is 259200 (72 h).

**Entries**
- P2P_ID only while the p2p host runs.
- RELAY: active reservations only, at most 2 relays and at most 2 addresses of
  each.
- DIRECT:
  - confirmed global addresses first, QUIC first, IPv6 before IPv4; then,
    while STUN discovery is live (auto-reach,
    [`docs/design/2026-10-auto-reach.md`](../docs/design/2026-10-auto-reach.md)
    §4.1), the public addresses it found for the host's listeners that no
    contact has reached from outside yet (the p2p QUIC endpoint first, then
    the public IP with the TCP listen port); at most 4 global ones in all.
    A receiver cannot tell the two apart and needs not: it dials them in
    frame order, and one that does not answer fails like any stale address;
  - same-LAN listen addresses only on LAN links, at most 2, in listen order:
    local-network listen addresses in the /24 (IPv4) or /64 (IPv6) of the
    link's peer IP, or of an address of the sender's interface on the peer's
    network (an interface with an address in the peer IP's /24 or /64; for an
    IPv6 link-local peer the interface of its zone, whose own link-local
    addresses name no network). A link over the contact's IPv6 address so
    carries what one over its IPv4 address does, whichever side dialled;
  - none at all when the user hides its IP from this receiver (globally or for
    this contact).
- LAN_PORT, on LAN links only, in both roles:
  - the listener always sends its own listener port;
  - the dialer sends it only when its LAN listener is bound to the link's local
    IP or to the unspecified address of that family.
- CUSTODIAN (0x05): never (receive-only since §12).
- CUSTODY_OFFER: only with the full snapshot, while the friend custody gate is
  live, `NodePolicy.custody` is on and some carrier can serve custody now (the
  LAN carrier is open, or the WAN custody gate is live with the Internet or
  p2p carrier open): an offer the node cannot serve, under `raven lan off`
  with WAN custody held, would keep a friend's automatic choice on a mail
  friend that holds nothing. The WAN bit is set exactly when the WAN
  custody gate and the p2p carrier gate are both live; the REACHABLE bit
  exactly when the node's reach class is public or mapped. Bits 2-7 are 0.
- CUSTODIAN_TAG: only with the full snapshot, while the friend custody gate is
  live. One tag for each custodian of these two sets, together at most 2:
  - the sender's home custodians (the friends it collects its own mail from),
    only while its friend-mailbox consent is on;
  - the custodians it listed for this receiver.

  A custodian is never the receiver or the sender. The tag is computed with
  sender = self and receiver = this contact. The flags byte is 0x01
  (HANDOFF_INBOX) exactly when the custody handoff gate is live and that
  custodian answered the sender's TAGS REGISTER with OK within the last 24 h
  ([`RAVEN_CUSTODY_HANDOFF_V1.md`](RAVEN_CUSTODY_HANDOFF_V1.md) §3.6), and
  0x00 otherwise (always 0x00 with the gate closed).
- Both custody entries are inputs of the generation: the offer and the home
  set are global, the tags per contact, each tag with its flags (a
  HANDOFF_INBOX that comes or goes moves that contact's generation).
- RELAY_OFFER: only as §11.4 says.
- Nothing learned from others, ever.

### 6.1 Telling again

A node keeps, in memory, what it last told each contact and when, and when it
last received (and used) each contact's RRH1. A contact is **due** an RRH1
on a link when any of these holds:
- it was not told one since the node started;
- the generation, or the PAIR_SEED entry (§14), differs from the last one told;
- the last telling is `REFRESH` = 30 minutes old;
- on a LAN link: the frame's LAN part adds a LAN_PORT or a DIRECT entry to the
  one last told over LAN, or none was, or that is 30 minutes old. A LAN part
  that only lacks something told before is not news (§5.3).

Otherwise the frame is not sent (§3.3; a LAN listener answers an ask all the
same, and so does every side whose peer's hello has bit 11, §3.1). A LAN dialer asks (§3.2) when the listener is due its RRH1, when its
own copy of the listener's is 30 minutes old (none at all after a start), or
when the LAN part it holds is older than the snapshot (a newer one came over
an Internet or p2p link, which never changes the LAN part, §5.3); a leader
that told a pair seed proposal asks on its next dial for the ack. The
generation is read for that before the dial's handshake (the same digests,
§6), so a change is never held back by a dial that did not ask.

A node that holds no snapshot of a contact (it forgot them, or none came
since its start) asks on its next dial whichever carrier it takes: RLX1 bit
8 on LAN, hello bit 11 on Internet direct, p2p, nearby and the onion link
(field test E3: after `raven contact forget-address` a friend at home was
not told again for as long as every link went over Tor, so the two never
went back to the LAN).

30 minutes is far inside the snapshot's TTL (72 h, §5.4), so a contact's
snapshot never expires while the two link at all. A link is never opened, or
kept open, only to tell again: announce links (§7) go only for a change. The
field run that made this rule (E2 night, three computers on one network,
friend custody both ways) told each friend its routes about 4 times a minute
and learned theirs twice, with nothing changing all night.

## 7. Announce links

When its snapshot changes, a node MAY open a link that carries only RRH1 to
recently active RRH1 contacts (contacts that sent it an RRH1 that has not
expired). A node that holds friend custody objects
([`RAVEN_FRIEND_CUSTODY_V1.md`](RAVEN_FRIEND_CUSTODY_V1.md)) MAY also open one,
ahead of those, to each verified, unblocked contact it holds unreleased,
unexpired objects for, newest deposit first, so a custodian that came back on
another address is fetched from there; only to a contact whose Noise static
key it recorded on an earlier authenticated link, since every attempt is an
identity-bearing dial. Both kinds share these limits:
- changes are coalesced over 10 s;
- at most 64 contacts;
- at most once per contact per minute;
- retried after 1, 10 and 60 minutes;
- a contact is done once any link carried the new generation.

An announce link is an ordinary authenticated link with no message frames, and
§3 applies to it. On LAN it carries RLX1 and waits for the listener's RRH1
(§3.3).

## 8. Security and privacy

**Exposure before authentication**
- LAN: the RLX1 caps in message 3 reach the responder before the responder has
  authenticated itself. The dialer's own identity bind follows on the same link
  anyway.
- Internet direct and p2p: the dialer's hello caps, including bit 8, reach the
  listener before the listener is authenticated, because the dialer's hello is
  sent first and the listener's contact gate runs before it answers. This is
  the same exposure as `CAP_INTERNET` today.
- RRH1 itself never reaches a stranger: the contact gate runs before RLB1, and
  RRH1 follows RLB1.
- Logs carry counts only.

**What a contact can do**
- A contact can steer only dials toward itself, through relays or global
  addresses it names (a relay's IP address must be global too, §5.2). This is
  bounded by the plan size (2 relays, 4 global addresses) and by a dial
  concurrency of 2.
- A contact can offer the receiver at most 2 relays (§11), each at up to 4
  global addresses. The receiver's own relay choice decides whether it ever
  reserves on one; an offer is never re-sent or forwarded.
- A learned PeerId is admitted by the receiver's peer gate only as a hidden
  contact (links only: no DCUtR, no Identify) until a p2p link proves it.
- A contact can record what it was told. Hints are deniable, not secret from
  their receiver.

**Hide my IP**
- No DIRECT entries are sent.
- Dials to that contact use circuits only, and only through a relay the
  contact names that the node itself also reserves on (set by hand or picked
  from an offer). A relay only the contact names is never dialled: the contact
  may run it, and it would see the node's IP. Such a circuit names the relay
  at the node's own addresses for it, never at an address the contact gives
  for it: while no connection to the relay is up, a circuit makes the node
  dial that address, which could be the contact's own host. The contact
  reaches the node through the node's own relays (its RELAY entries), and a
  link it opens is used both ways.
- No DCUtR and no Identify with that contact.
- No Internet-direct dials to that contact, by any planner or request.
- LAN links are not affected.
- An address sent before stays usable to its receiver until the snapshot
  expires (72 h by default, at most 7 days) or the next frame withdraws it.

## 9. Card v3 (informative; ash)

```
raven-card/3 address=<rvn1> pub_hex=<64 hex> fingerprint=<fp> p2p=<PeerId> [relay=<multiaddr>]{0,4}
```

- `p2p` is required.
- At most 4 `relay` fields, counting every one a reader drops. A reader drops a
  `relay` that fails the via grammar (a transport it does not know, a circuit)
  and keeps the card and its other relays: a later revision may name a relay
  by a transport an older reader cannot parse. Each relay it keeps must name a
  PeerId that is not the card's `p2p` and appear once, and the kept ones name
  at most 2 relays; otherwise the card is refused. Writers write only relays
  that pass the via grammar.
- `p2pn=<PeerId>` is the PeerId of the owner's next libp2p key (Phase 4 key
  rotation, [`RAVEN_P2P_PEER_ROTATION_V1.md`](RAVEN_P2P_PEER_ROTATION_V1.md)
  §5): written only while the owner's rotation is on, right after `p2p`. A
  reader accepts it at most once, only with `p2p` (which a /3 card needs
  anyway), and checks it like `p2p`: a canonical Ed25519 PeerId, not the
  card's `p2p` and not a kept relay's, else the card is refused. The contact
  book keeps it with `p2p` (`p2p_next`); a reader with the PeerId rotation
  gate live admits it with `p2p`. It is a /3 field: a /1 or /2 card that holds
  it is refused (unknown field).
- A /3 line is at most 1530 characters: the fields above at their longest (an
  address of 64 characters, a fingerprint of 16, four relays of 300) plus
  ` p2pn=` and a 52-character PeerId. /1 and /2 lines keep their own limit.
  Readers of the Tor onion carrier (lab, §15) add 146 to both limits for
  ` onion=` and its 139-character binding, which any card version may carry
  ([`RAVEN_ONION_CARRIER_V1.md`](RAVEN_ONION_CARRIER_V1.md) §7): 1676 for /3.
- `inet=`, `lan=` and `via=` are refused: a /3 card carries no address of its
  owner.
- Readers accept /1, /2 and /3.
- `raven whoami --card` prints /3 only when route hints are live and the card
  would hold relays only. `--compat` prints /1 or /2.
- A card never names a relay picked from a contact's offer (§11.3): a card goes
  to anyone, and that relay is a friend's, often at the friend's home IP.
- Auto-reach ([`docs/design/2026-10-auto-reach.md`](../docs/design/2026-10-auto-reach.md)
  §4.3): a card never names an address STUN discovery found. A card is
  copied around in plain text; a public address goes only inside RRH1 on an
  authenticated, encrypted link to a verified contact (DIRECT, INET_DIRECT).
  Readers are unchanged: a `raven-card/2` naming a direct `via=` or an
  `inet=` is read as before (in lab builds; a release reader takes no
  unsigned route from any card, §9.1).
- Pre-v3 readers refuse /3 with "card version … is not supported (update
  raven)". /3 readers built before the `p2pn` and dropped-`relay` rules
  (2026-10-21) refuse a card with either; /3 readers of 2026-10-21 until the
  `p2pn` check (2026-10-22) accept any `p2pn` value and ignore it. No release
  build prints /3 (route hints are production disabled), and no release build
  writes `p2pn` (PeerId rotation is production disabled).

### 9.1 Unsigned card routes (release builds, October 2026)

No key signs a card's route fields, and comparing security words checks the
key only, so anyone who handles a card on its way could name their own host
in them. Once Internet direct and p2p were switched on in release builds, an
address in a card could steer a dial (and the dialler's signed identity and
IP address) to that host. From October 2026:

- **Writers.** A release build never writes `inet=`, `p2p=`, `via=`,
  `p2pn=` or `relay=` into a card it creates. `raven whoami --card` refuses
  `--inet` and `--via` with the reason; the p2p route of `raven node p2p on`
  is not added. A card carries the identity (`address`, `pub_hex`,
  `fingerprint`), the signed `onion=` binding while the Tor carrier has one
  ([`RAVEN_ONION_CARRIER_V1.md`](RAVEN_ONION_CARRIER_V1.md) §7), and `lan=`
  only when the user puts one in (`--lan`). With no p2p route a card is a
  `raven-card/1`.
- **Readers.** A release build reads a card with those fields as before
  (version, known fields, each once, length limits), but never parses or
  keeps their values: no Internet route, PeerId, `p2pn` or relay comes from a
  card, so none is ever dialled. The reader prints one line naming the fields
  it left out. `lan=` is kept under the local-network rule (a card's LAN
  route is dialled only at a loopback, private, link-local or unique-local
  address, even for a verified contact); `onion=` is kept only when it
  verifies against the card's own key.
- **Where addresses travel instead.** A verified friend's public, LAN and
  relay addresses and PeerId reach the other side only in RRH1 (this spec),
  over an authenticated, encrypted link; the first link can be made over Tor
  with the card's signed `onion=`, or on the local network.
- **Lab.** A debug build with the lab unlock (`RAVEN_LAB_TEST_A=1`) still
  writes and reads the fields as described above, for the lab harnesses.
- A relay operator who allows a friend (`raven-relay allow`) takes the
  friend's PeerId from `raven whoami --peer-id`, since a card no longer
  carries it.

## 10. Vectors

All of them are written by Rust tests (`raven_core::route_hints`,
`raven_core::lan_vectors`) under `RAVEN_REGEN_RRH1_VECTORS=1`, and asserted
equal otherwise. Fuzz target: `rrh1_frame` (`node/fuzz`), which also runs the
RELAY_OFFER record decoder on its input and checks that custody entries
re-encode byte for byte. The Python reference
(`protocol/reference/tests/test_route_hints_custody.py`) recomputes the
custody tags and re-reads the custody frames and cases.

In [`shared-vectors/rvn1/route_hints/`](../shared-vectors/rvn1/route_hints/):
- `rrh1_full_001.json`: every entry type of the first draft (0x01-0x05); relay
  R1 at two addresses, relay R2 at one.
- `rrh1_custody_001.json`: LAN_PORT, CUSTODY_OFFER 0x03 and two
  CUSTODIAN_TAGs, the second with flags 0x03; the decoded view (flags as sent)
  and what a receiver keeps (bit 0 HANDOFF_INBOX kept, bit 1 cleared) (§12).
- `rrh1_custody_handoff_inbox_001.json` (Phase 5): two CUSTODIAN_TAGs, the
  first with flags 0x01 (HANDOFF_INBOX), the second with 0xfe (every bit this
  revision does not define); the decoded view, what this revision's receiver
  keeps (0x01 and 0x00) and what a receiver built before it keeps
  (`phase3_kept_flags`: both tags, every bit cleared) (§4).
- `rrh1_custodian_tag_001.json`: three key triples and their tags (§12).
- `rrh1_phase2_decoder_skips_custody_001.json`: frames with custody entries,
  as a receiver built before §12 decodes them (the same hints without the
  custody entries) and as a §12 receiver does.
- `rrh1_lan_port_001.json`: the LAN-scope frame, 22 bytes.
- `rrh1_ignored_001.json`: frames a receiver ignores whole (§5.1), each with
  the rule it breaks; since §12 also a CUSTODY_OFFER of length 0 or 2, two
  CUSTODY_OFFERs, a CUSTODIAN_TAG of length 32 or 34 and three
  CUSTODIAN_TAGs.
- `rrh1_validated_001.json`: a frame, its link and what §5.2 keeps, one case per
  rule, including a 600-byte entry of type 0x20 that is skipped (written when
  0x20 was reserved; it is a RELAY_OFFER record of an unknown version, which
  §11.2 ignores too). Since §12 also: an unpinned sender's custody entries
  dropped, CUSTODY_OFFER 0xff kept as 0x03, an all-zero CUSTODIAN_TAG dropped,
  CUSTODIAN_TAG unknown flag bits cleared with HANDOFF_INBOX kept, and a
  repeated CUSTODIAN_TAG merged; these cases also show the kept custody
  entries.
- `rrh1_validated_relay_002.json`: the §5.2 RELAY address rule, one case each:
  loopback, private, unique-local, CGNAT, documentation, and NAT64 or 6to4 of a
  private IPv4 address dropped on Internet, p2p and LAN links; global and DNS
  relays kept; the two debug lab flags (`lab_local`, `lab_loopback`).
- `rlx1_caps_001.json`: RLX1 encodings, and the LINK_CAPS a responder reads
  from each payload (§3.2).
- `rih1_hello_rrh1_001.json`: a hello with caps `0x00000102`: signing bytes,
  signature and wire.
- `rrh1_relay_offer_001.json`: a RELAY_OFFER record (§11) for an IPv4 relay on
  TCP and QUIC, flags CONFIRMED | AUTONAT, and a frame that carries it.
- `rrh1_relay_offer_dns_002.json`: a record for a DNS-named relay with TCP 443,
  flags AUTONAT | PORT_443, and a frame with two records (the most a frame
  carries).
- `negative/rrh1_relay_offer_{no_addr,five_addrs,circuit,p2p_suffix,trailing,noncanonical,bad_point}.json`:
  records that break one §11.2 rule each. Each is malformed; in a frame it is
  dropped and the frame kept.
- `rrh1_nat_class_001.json` (§13.1): `rrh1_full_001.json`'s frame with a
  NAT_CLASS entry appended (IPv4 TCP varies, IPv4 QUIC stable_shifted, IPv6
  TCP stable_kept, IPv6 QUIC unknown, global IPv6), and the Phase 2 frame it
  extends.
- `negative/rrh1_nat_class_short_001.json`: a NAT_CLASS of 4 bytes after a
  P2P_ID. The entry is dropped, the frame and its P2P_ID kept.
- `rrh1_peer_schedule_001.json` (§13.2): `rrh1_full_001.json`'s frame with a
  PEER_SCHEDULE of 8 entries appended (the sender seed's rotation on in epoch
  23: epochs 22-29 and their keys), and the Phase 2 frame it extends.
- `rrh1_peer_schedule_capability_only_001.json`: the same with a
  PEER_SCHEDULE of no entries (capable, rotation off, 28-day epochs).
- `negative/rrh1_peer_schedule_{nonmonotonic,too_many,bad_key}_001.json`: a
  PEER_SCHEDULE after a P2P_ID whose epochs are not strictly increasing, that
  holds 9 entries, or whose fifth key is of small order. The entry is dropped,
  the frame and its P2P_ID kept.

- `rrh1_pair_seed_001.json` (§14): `rrh1_full_001.json`'s frame with a
  PAIR_SEED (generation 3, acked 2) in ascending type order, and the Phase 2
  frame it extends.
- `negative/rrh1_pair_seed_short_001.json`: a PAIR_SEED of 39 bytes after a
  P2P_ID. The entry is dropped, the frame and its P2P_ID kept.

In [`shared-vectors/rvn1/pair_seed/`](../shared-vectors/rvn1/pair_seed/)
(written by `raven_core::pair_seed` under `RAVEN_REGEN_SECURITY_VECTORS=1`;
the Python reference `protocol/reference/tests/test_pair_seed.py` recomputes
it and re-reads the PAIR_SEED frames):
- `kdf_001.json` (§14.2): the alice/bob pair of the beacon vectors, two seeds,
  `K_pair` of each and the three medium keys made from it, and the leader.

Fuzz target `rrh1_phase4_tlvs` (`node/fuzz`) puts arbitrary Phase 4 entries
(NAT_CLASS and PEER_SCHEDULE among them) into valid frames: none ever costs
the frame or another entry. The `rrh1_frame` target reaches PAIR_SEED too.

In [`shared-vectors/rvn1/lan/`](../shared-vectors/rvn1/lan/):
- `noise_xx_handshake_002.json`: the `noise_xx_handshake_001` handshake with
  the RLX1 m3 payload. m1 and m2 equal 001 and m3 is 75 bytes. The handshake
  hash differs from 001, while both binds and the first application ciphertext
  equal 001. The responder reads exactly the 11 RLX1 bytes.
- `noise_xx_handshake_001.json` is unchanged. It pins the empty-payload
  handshake that every build sends with route hints off.

## 11. Relay records

A node that runs a friend relay offers it, inside RRH1, to the contacts that
are its relay members. The friend relay is a standard Circuit Relay v2 server
in the node. It runs under its own relay key, never the profile PeerId, and
admits only those members. Entry type 0x20 carries one RELAY_OFFER record.
Type 0x21 stays reserved.

- A record has no signature: the link authenticates it with the rest of the
  frame (§1).
- A record has no TTL of its own: an offer lives exactly as long as the
  snapshot that carried it (§5.3, §5.4).
- No libp2p protocol changes. HOP, STOP, AutoNAT, Identify and DCUtR stay as
  they are.

### 11.1 RELAY_OFFER layout

Record version 1. All integers are big-endian.

```
 off len field
  0   1  version    0x01
  1   1  flags      bit0 CONFIRMED, bit1 AUTONAT, bit2 PORT_443
  2  32  relay_pub  Ed25519 public key of the relay's libp2p key
 34   1  n_addrs    1..=4
 35  ..  addrs      n_addrs x (len u8 8..=120 || ASCII host+transport)
```

- **flags.** Writers set only these three bits. Readers ignore the others.
  - CONFIRMED: a member reserved on the relay from a globally routable IP
    within the last 24 hours, or UPnP mapped the relay's port.
  - AUTONAT: the relay answers AutoNAT v2.
  - PORT_443: one of the addresses is `/tcp/443`.
- **relay_pub** must be a valid Ed25519 point (it decompresses). The relay's
  PeerId is the libp2p Ed25519 PeerId of this key (`00 24 08 01 12 20 ||
  relay_pub`, base58: `12D3KooW…`). A member dials `<addr>/p2p/<PeerId>`.
- **addrs.** Each address is `/ip4|ip6|dns|dns4|dns6/<host>/(tcp/P |
  udp/P/quic-v1)`: a host and a transport only, with no `/p2p` and never a
  circuit. It must be canonical: `raven_core::p2p_route::parse_host_transport`
  returns it unchanged. That means:
  - IPv4 in dotted decimal, IPv6 in RFC 5952 form (lowercase, zeros
    compressed), DNS names in lowercase;
  - a port of 1..=65535 without leading zeros;
  - no unspecified, multicast or broadcast address.

  No two addresses of a record are equal.
- Nothing follows the last address. The longest record is 519 bytes.

### 11.2 Decoding

A receiver decodes each 0x20 entry on its own. Whatever a record holds, the
frame is kept and its other entries are used.

- **Unsupported:** the first byte is not 1. The record is ignored, without a
  log, whatever its length.
- **Malformed:** the record is dropped, with a counts-only `RRH1_MALFORMED`
  debug log, on any of:
  - an empty record, or one cut short;
  - relay_pub is not a valid Ed25519 point;
  - n_addrs is 0 or above 4;
  - an address length outside 8..=120;
  - an address that is not canonical host and transport text (§11.1),
    including one that goes on with `/p2p/…` or `/p2p-circuit`;
  - a repeated address;
  - bytes after the last address.
- **Per frame:** a receiver keeps the first 2 records it accepts, in frame
  order, at most one per relay_pub. A later record, or one that names the
  relay of a kept record, is dropped like a malformed one. An unsupported
  record takes no place.

### 11.3 Receiver rules

These come on top of §5.2.

- Offers are kept only from a pinned, unblocked sender (an unpinned sender's
  frame keeps only LAN_PORT, §5.2).
- An offer is dropped when relay_pub is:
  - the sender's own libp2p key: the key in its P2P_ID, or in the PeerId the
    receiver's contact book holds for it (that would be a relay under the
    sender's profile PeerId);
  - the receiver's own libp2p key;
  - the key of the receiver's own friend relay.
- Addresses: an IP address is kept only when it is globally routable unicast,
  by the §5.2 rule (IPv4-mapped, NAT64 and 6to4 addresses follow the IPv4
  address inside). DNS names are kept. In debug builds
  `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1` admits loopback and private addresses. An
  offer left with no address is dropped.
- Snapshot semantics: offers belong to the global part (§5.3). A frame with a
  higher generation replaces the sender's offers, so an offer missing from it
  is withdrawn and a frame without RELAY_OFFER withdraws them all. Offers
  expire with the snapshot (§5.4).
- A receiver stores at most 2 offers per sender and 32 in all. It may keep
  using a relay it holds a reservation on after the offer expired, until that
  reservation is lost.
- Use: the receiver's own relay choice may reserve on an offered relay. An
  offer is never re-sent, forwarded, or put into the receiver's own frames or
  card. Once the receiver holds a reservation there, the relay is one of its
  own relays like any other (RELAY, §6): its RRH1 names the relay's address to
  its own verified contacts, so members reach each other through it. The
  operator's consent covers this: members' contacts learn the relay's address,
  the operator's IP for a relay at home, including a contact the operator hides
  its IP from that a member also knows (such a contact is no member, §11.4, so
  the relay turns it away). The receiver's card never names it (§9).

### 11.4 Sender rules

A sender adds RELAY_OFFER only when all of these hold:
- the friend relay is live: its gate (or debug switch) and route hints;
- the frame is a full snapshot (§6) for a member of the relay. Members are the
  verified, unblocked contacts with a PeerId that the sender may show its IP
  to (hide my IP, §8, off for them), plus the relay's manual allow list, minus
  its deny list and minus blocked contacts;
- the sender may show its IP to that receiver: hide my IP (§8) is off globally
  and for this contact;
- the relay is up and has an address worth offering: the sender's reach class
  is public or mapped, or the relay is CONFIRMED, or the operator declared the
  relay's external addresses, or (auto-reach) STUN discovery found the
  sender's public address, which the relay then names with its own ports.
  Without CONFIRMED such an offer is a guess (a forward of the relay's port
  makes it right); members rank it below confirmed offers (relay selection)
  and its first reservation from a globally routable IP confirms it.

The sender writes canonical records only: at most 2 per frame, one per relay,
known flag bits only. The encoded records are inputs of the per-contact
generation digest (§6). A relay that comes up, goes down, or changes an
address or a flag therefore moves the generation, and announce links (§7)
carry the change.

### 11.5 Old peers

- A receiver built before this section skips type 0x20 (§4). A frame with
  offers stays valid for it and gives it the same hints.
- RRH1 goes only to peers that asked for it on the link (§3), so a build
  without route hints never sees an offer.
- Such peers can still use a friend relay through a static `via=` relay line:
  it is a standard Circuit Relay v2 server that admits members only.

## 12. Custody entries

CUSTODY_OFFER (0x06) and CUSTODIAN_TAG (0x07) let a node find friends who hold
sealed mail (RFC1, [`RAVEN_FRIEND_CUSTODY_V1.md`](RAVEN_FRIEND_CUSTODY_V1.md))
for a contact without naming them: an offer says "I hold mail for my verified
contacts", and a tag names a friend only to a receiver that already knows that
friend. Both are sent only to verified contacts (§6) and kept only from them
(§5.2).

### 12.1 Matching

A receiver R of a frame from sender S computes `T = tag(S, R, C)` (§4) for each
of its own pinned, unblocked contacts C, with C ≠ S and C ≠ R. A kept
CUSTODIAN_TAG equal to T means "S collects mail at C". R learns nothing about
a custodian it does not already know, except the number of entries.

### 12.2 Use

R may RFC1-DEPOSIT objects addressed to S at a matched C only when all of these
hold:
- R's friend-mailbox consent is on;
- C's own live snapshot at R carries CUSTODY_OFFER;
- when every route R has to C is an Internet or p2p route, that offer's WAN bit
  is set.

Tags and offers are never re-sent, never put in a card or in another RRH1, and
never logged except as counts (§5.5).

### 12.3 Legacy 0x05

A 0x05 CUSTODIAN from a Phase 2 sender counts as a match when it equals one of
R's pinned, unblocked contacts (other than S and R); §12.2 applies to it
unchanged. Senders of this revision never write 0x05.

### 12.4 Privacy

- A tag is deterministic per ordered pair and custodian, and links nothing
  across pairs: the same custodian has an unrelated tag in every other pair and
  in the other direction.
- Brute force is limited to keys R already holds: Ed25519 device keys are not
  guessable, so a tag reveals only a custodian R knows.
- CUSTODY_OFFER tells every verified contact that the node holds mail.
- No store tag, mailbox tag or `K_route` material ever appears in RRH1
  (`RAVEN_PRIVATE_RENDEZVOUS_V1.md` §3.2).
- A CUSTODIAN_TAG flags byte carries no secret. Bit 0 HANDOFF_INBOX (§4,
  Phase 5) tells the receiver only that the sender registered store tags with
  that custodian (which it collects mail from anyway); bit 1 stays reserved
  for letters.

### 12.5 Old peers

- A receiver built before this section skips 0x06 and 0x07 at any length (§4,
  §5.1) and keeps reading 0x05 only; a Phase 3 sender's frame gives it the
  same hints minus the custody entries
  (`rrh1_phase2_decoder_skips_custody_001.json`). Its friends fall back to the
  static custodian lists of RFC1 §2 (b).
- Such a sender's 0x05 is still used (§12.3).
- A Phase 3 receiver clears HANDOFF_INBOX (it defined no flag) and keeps the
  tag: it deposits there as before and never forwards
  (`rrh1_custody_handoff_inbox_001.json`). A Phase 3 sender sends 0x00, which a
  Phase 5 receiver reads as "no handoff inbox".

## 13. Phase 4 extensions

Phase 4 (`docs/roadmap/plans/phase45-design.json`, PortMap design) adds entries
in the range §4 reserved for it. Each is optional and checked on its own: a
malformed Phase 4 entry is dropped alone, with an `RRH1_MALFORMED` debug log,
and never makes the frame ignored or drops another entry. A receiver built
before this section skips them (§5.1) and gets the same hints. Each is sent
only while its own gate is live, so with the Phase 4 gates closed a sender's
RRH1 is byte for byte the frame of §4-§12 (`rrh1_full_001.json` is
unchanged).

### 13.1 NAT_CLASS (0x22)

```
 off len field
  0   1  v4_tcp   class code
  1   1  v4_quic  class code
  2   1  v6_tcp   class code
  3   1  v6_quic  class code
  4   1  flags
```

- Length exactly 5; any other length drops the entry. At most one per frame:
  a second is dropped and the first kept.
- Class codes: 0 unknown, 1 no_nat, 2 stable_kept, 3 stable_shifted,
  4 varies. A code above 4 reads as 0 (unknown), for forward compatibility;
  the entry is kept.
- Flags: bit 0 the sender has a globally routable IPv6 address; bit 1 an
  IPv6 pinhole (or an open IPv6 firewall) is confirmed for it. Senders write
  0 in bits 2-7; receivers clear them.
- What the classes mean: how the sender's NAT maps an outbound connection
  from its libp2p listen port, as seen by its own relays and contacts on at
  least two different networks (/24 or /48) at the same time. `stable_kept`:
  one outside address on the listen port for every destination;
  `stable_shifted`: one outside address on another port; `varies`: the
  outside address depends on the destination; `no_nat`: its own address;
  `unknown`: not enough evidence. No address or port is ever sent.
- **Sender.** Only while `NAT_CLASS_PRODUCTION_ENABLED` or its lab switch
  `RAVEN_LAB_NAT_CLASS=1` (with `RAVEN_LAB_TEST_A=1`, debug builds) is on,
  only in the full snapshot (§6) and only to a contact this node shows its IP
  (it serves hole punching, which needs the address too: none when DIRECT is
  withheld for hide-IP). It is part of the generation's inputs.
- **Receiver.** Kept only from a pinned sender whose P2P_ID passed (§5.2); it
  describes that libp2p host. It is part of the global part (§5.3): it
  inherits the snapshot's expiry, is replaced or withdrawn with it, and never
  survives in a tombstone. A receiver with the gate closed stores none.
- **Use.** Only by the receiver's hole-punch policy: a punch with the sender
  is skipped while both sides' IPv4 mappings vary (the best known of TCP and
  QUIC) and the two do not both have a global IPv6 address. Never re-sent.

Vectors: `rrh1_nat_class_001.json`,
`negative/rrh1_nat_class_short_001.json` (§10).

### 13.2 PEER_SCHEDULE (0x23)

```
 off      len  field
  0        1   flags         bit 0 capable, bit 1 rotating, bit 2 postponed
  1        4   epoch_len_s   u32 >= 1
  5        8   active_epoch  u64
 13        1   n             0..=8
 14 + 40i  8   epoch         u64        (i = 0 .. n-1)
 22 + 40i 32   key           Ed25519 public key of that epoch
```

The sender's PeerId rotation schedule
([`RAVEN_P2P_PEER_ROTATION_V1.md`](RAVEN_P2P_PEER_ROTATION_V1.md) §4): the
libp2p keys of its coming epochs, so a contact can admit and dial it after its
PeerId changes. Each key `K` names the PeerId `base58btc(00 24 08 01 12 20 ||
K)`.

- Length exactly `14 + 40 n` with `n <= 8`; any other length, or one that
  does not match `n`, drops the entry. At most one per frame: a second is
  dropped and the first kept.
- Flags: bit 0 (capable) must be set, else the entry is dropped. Senders write
  0 in bits 3-7; receivers clear them. `rotating`: the sender's rotation is on
  and `active_epoch` is the epoch it uses. `postponed`: its relays refused the
  next ID, so it went back to `active_epoch` until it retries.
- `epoch_len_s` 0 drops the entry.
- Entries: epochs strictly increasing and each within `active_epoch - 1 ..=
  active_epoch + 6` (no `- 1` below epoch 0); each key decodes as a point, is
  canonically encoded and is not of small order (the ed25519_strict rules).
  One entry that breaks a rule drops the whole PEER_SCHEDULE (never the frame).
- `n = 0` is a capability announcement: the sender can rotate but does not
  (its rotation is off). Its `active_epoch` is then 0 and says nothing.
- **Sender.** Only while `PEER_ROTATION_PRODUCTION_ENABLED` or its lab switch
  `RAVEN_LAB_PEER_ROTATION=1` (with `RAVEN_LAB_TEST_A=1`, debug builds) is on,
  and only in the full snapshot (§6), to every verified contact whatever
  hide-IP says (it holds PeerIds, no address): the capable flag always, the
  entries (the previous epoch, the active one and 6 ahead) only while the
  sender's rotation is on, or in the epoch before its first switch (entries
  without `rotating`, so its contacts admit the coming PeerIds before it uses
  them: `RAVEN_P2P_PEER_ROTATION_V1.md` §9.1). It is part of the generation's
  inputs.
- **Receiver.** Kept only from a pinned sender (§5.2), whatever its P2P_ID,
  and only while the receiver's own gate is live. It is stored in the
  receiver's `peer_schedules.json` under the link's authenticated Raven key,
  never under a PeerId, and is not part of the learned routes (§5.3). A
  newer snapshot from that contact without a PEER_SCHEDULE forgets it (its
  gate closed, or an older raven). An older generation changes nothing.
- **Use.** Only by the receiver's p2p peer gate, its friend relay's
  allow-list and its dialler (`RAVEN_P2P_PEER_ROTATION_V1.md` §9), and by the
  receiver's own rotation, which waits until every pinned contact with a p2p
  route said `capable`. Never re-sent.
- **P2P_ID of a rotating sender.** A rotating sender's P2P_ID names the PeerId
  of its current epoch, which its receiver's book (the card's `p2p=`) may not
  hold. While the receiver's own PeerId rotation gate is live, a P2P_ID that
  differs from the book's passes §5.2 when this frame's PEER_SCHEDULE is valid,
  says `rotating` or `postponed`, and has an entry whose key names that PeerId;
  on a p2p link it must still be the connection's PeerId. A capability-only
  PEER_SCHEDULE, or none, leaves the §5.2 rule as it was, and so does a closed
  gate.

Vectors: `rrh1_peer_schedule_001.json`,
`rrh1_peer_schedule_capability_only_001.json`,
`negative/rrh1_peer_schedule_{nonmonotonic,too_many,bad_key}_001.json` (§10).

### 13.3 INET_DIRECT (0x24, auto-reach)

```
 off len field
  0   1  flags   bit 0 CONFIRMED
  1  ..  addr    ASCII ip:port, 9..=47 bytes
```

- `addr` is an IPv4 address in dotted decimal or an IPv6 address in RFC 5952
  form in brackets, a colon and a port of 1..=65535 without leading zeros:
  `203.0.113.7:7422`, `[2001:db8::7]:7422`. It must read back to itself
  (canonical). The value is 10..=48 bytes.
- Flags: bit 0 CONFIRMED, a contact reached that listener from a globally
  routable IP that is not the sender's own within the last 24 hours. Senders
  write 0 in bits 1-7; receivers clear them.
- At most 2 per frame. A value that breaks a rule is dropped alone with an
  `RRH1_MALFORMED` debug log, and so is a third one or a repeated address;
  the frame and its other entries are kept.
- What it is: the public address of the sender's Internet direct listener
  (RIH1 over TCP, `INTERNET_DIRECT_PRODUCTION_ENABLED`), the public IP STUN
  discovery found with the listener's port. TCP cannot be probed by a UDP
  STUN query, so the address is a guess until a contact confirms it: a
  forward of the port makes it right.
- **Sender.** Only while STUN discovery is live
  (`STUN_DISCOVERY_PRODUCTION_ENABLED` or its lab switch
  `RAVEN_LAB_STUN_DISCOVERY=1` with `RAVEN_LAB_TEST_A=1`), the Internet
  direct listener listens, the full snapshot goes (§6) and this node shows
  the receiver its IP (hide my IP off globally and for this contact). It is
  part of the generation's inputs.
- **Receiver.** Kept only from a pinned sender, and only when the IP is
  globally routable (the §5.2 rule; `RAVEN_LAB_P2P_LOCAL_CANDIDATES=1` admits
  loopback and private ones in debug builds). Part of the global part (§5.3):
  replaced, withdrawn and expired with the snapshot, never in a tombstone.
  A receiver with the gate closed stores none.
- **Use.** Only to reach the sender over Internet direct: the dial planner
  adds it after the contact's saved Internet route, confirmed entries
  first. Never re-sent, never put into a card by the receiver.

Vectors: `rrh1_inet_direct_001.json`,
`negative/rrh1_inet_direct_bad_001.json` (§10).

### 13.4 Old peers

- A receiver built before this section skips 0x22, 0x23 and 0x24 like any
  reserved type; one built before §13.2 (with §13.1 only) skips 0x23, and one
  built before §13.3 skips 0x24.
- A sender with a gate closed never writes that gate's entry, so an older
  receiver and a newer one with the gates closed see the same bytes as before.

## 14. Pair seeds (Phase 6b)

Design B §5 and W-B4 of `docs/roadmap/plans/phase6-design.json` (owner
decision OD6b-12). The LAN beacon ([`RAVEN_LAN_BEACON_V1.md`](RAVEN_LAN_BEACON_V1.md)),
the link knock ([`RAVEN_LINK_KNOCK_V1.md`](RAVEN_LINK_KNOCK_V1.md)) and the
Bluetooth LE tokens and knock ([`RAVEN_NEARBY_LINK_V1.md`](RAVEN_NEARBY_LINK_V1.md))
take their keys from the R2 pairwise root
([`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](RAVEN_PRIVATE_RENDEZVOUS_V1.md) §5.3a),
which anyone who later gets one of the two identity keys can compute again,
and with it every beacon, knock and token recorded before. Two contacts
therefore also share a random seed that they replace every 7 days over an
authenticated link, and take those keys from it. Held by
`PAIR_SEED_PRODUCTION_ENABLED = false` (debug: `RAVEN_LAB_PAIR_SEED=1` with
`RAVEN_LAB_TEST_A=1`), which needs route hints live. With the gate closed no
entry is sent, none received is kept, and every key comes from the root.

### 14.1 PAIR_SEED (0x08)

```
 off len field
  0   4  generation        u32 >= 1
  4  32  seed              32 random bytes, not all zero
 36   4  acked_generation  u32
```

- Length exactly 40; any other length, generation 0 or an all-zero seed drops
  the entry (an `RRH1_MALFORMED` debug log), never the frame or another entry.
  At most one per frame: a second is dropped and the first kept.
- The **leader** of a pair is the contact whose Ed25519 identity key is
  numerically smaller (the 32 bytes compared as a big-endian number); the
  other is the **follower**.
- A leader's entry offers its outstanding proposal, or else its current seed;
  `acked_generation` is the generation it uses now (its current one, 0 when
  it has none). A follower's entry echoes its current seed;
  `acked_generation` equals `generation`. A follower without a seed sends no
  entry.
- **Sender.** Only while the gate is live, only in the full snapshot (§6),
  that is to a verified contact, on any link that carries RRH1. It is not
  part of the generation's inputs: it never moves the generation or opens an
  announce link (§7).
- **Receiver.** Kept only from a pinned sender (§5.2) and only while the
  receiver's own gate is live; stored in the receiver's `pair_seeds.json`
  under the link's authenticated key (sealed at rest, never sent to anyone
  else), whatever the frame's generation. A frame from a pinned sender
  without the entry means the sender has no seed now (§14.3).

### 14.2 Keys

```
K_pair   = HKDF-SHA256(salt = K_root, IKM = seed, info = "rvn1/pair-seed/v1", L = 32)
K_medium = HKDF-Expand-SHA256(PRK = K_pair, info = "medium" || medium, 32)
```

`K_root` is the pair's R2 root and `K_medium` the medium key of R2 §5.3a with
`K_pair` in the root's place: medium 0x01 Bluetooth LE (RNB1 tokens and the
RNK1 knock), 0x02 the LAN beacon, 0x03 the link knock. Everything below the
medium key (directional keys, epochs, tags) is unchanged. Vector:
`pair_seed/kdf_001.json`.

### 14.3 Rotation

Each side keeps, per contact: `current` (the seed it sends with), `previous`
(the one before, with the time it goes) and, a leader only, `proposed` (its
offer not yet acked).

1. **Propose.** A leader proposes generation g+1 (one above every generation
   it keeps) with a fresh seed when it has no seed, or when its seed is 7 days
   old and no previous one is kept. It stores the proposal before the RRH1
   that carries it is sent, and offers the same proposal in every RRH1 until
   it is acked (never a second one).
2. **Adopt.** A follower that receives an offer other than its current seed
   stores it as current (the old current becomes previous, kept with no end
   yet) before its next RRH1 is made, and acks it there. A follower thus
   follows the leader whatever the generation, so a leader restored from an
   old copy, or one that lost its seeds and proposed again, is followed too.
3. **Switch.** A leader whose proposal is acked (`generation` and `seed`
   equal its proposal's and `acked_generation = generation`) makes it current;
   the old current becomes previous and goes 2 days later.
4. **Retire.** A follower's previous seed goes 2 days after it receives an
   entry whose `acked_generation` equals its current generation (the leader
   uses the new seed). A retirement more than 2 days ahead of the clock is
   brought back to 2 days.
5. **No seed.** A pinned contact's RRH1 without the entry (its gate closed,
   an older build, or its seeds lost or unreadable): the receiver's current
   seed becomes previous for 2 days and it sends with the root. A leader then
   proposes again (it has no seed); its outstanding proposal stays.
6. **Removed.** Removing a contact forgets its seeds; one added again starts
   from the root.

**Use.** A side sends (beacon queries, knocks, advertised tokens) with its
current seed's `K_pair`, or the root while it has none, and accepts, in this
order, its current seed's, a leader's proposal's (the follower may use it
already), its previous seed's and always the root's; at most three key sets
per contact. An answer, a knock's proof and a pipe's knock use the key set
that matched. A match with the root while the receiver expects the contact's
seed (a leader with an acked seed; a follower that saw the leader use one) is
the local Notice `SEC_PAIR_SEED_ROOT` (`docs/SECURITY_EVENTS.md` code 35);
nothing is refused. A dialer whose knock made with a seed gets no proof
knocks once more, on a new connection, with the root before it stops
(`RAVEN_LINK_KNOCK_V1.md` §4). So a lost seed never locks two friends out: it
costs forward secrecy until the next rotation. Until the next authenticated
link tells the other side (the RRH1 without an entry, step 5), its beacon
queries and Bluetooth tokens made with the seed go unrecognised by the side
that lost it; that side still finds the other with the root (which the other
accepts), and dials in both directions go through. No ordering of sends, losses,
crashes between a store and a send, and clock steps leaves the key one side
sends with outside what the other accepts (`raven_core::pair_seed` tests,
`no_lockout_in_any_crash_ordering`).

**Honest limit.** Forward secrecy needs the old seed really gone: the seeds
live in a file sealed under the privacy pack's metadata key, and an old copy
of it stays readable while that key exists. The gain is against someone who
later gets only an identity key (a seed-phrase backup, a keychain export), not
a full disk image with its keystore.

### 14.4 Old peers

- A receiver built before this section skips 0x08 like any unregistered type
  of this document's range (§5.1) and gets the same hints; it never sends the
  entry, so its contact keeps using the root with it.
- A sender with the gate closed never writes the entry: an older receiver and
  a newer one with the gate closed see the same bytes as before.

## 15. The Tor onion carrier's entry (lab)

Held by the onion gate as well as the route hints gate
(`ONION_PRODUCTION_ENABLED = false`; debug builds: `RAVEN_LAB_TOR=1` with
`RAVEN_LAB_TEST_A=1`). Carrier: [`RAVEN_ONION_CARRIER_V1.md`](RAVEN_ONION_CARRIER_V1.md).

### 15.1 ONION (0x40)

Value: exactly the 104-byte onion binding of the sender (carrier spec §3):
`hs_id[32] || issued_s u64 BE || sig[64]`.

- **Decode:** a value that is not 104 bytes, or a second ONION entry, is dropped
  alone; the frame is kept (`RRH1_MALFORMED`, counts only).
- **Receiver:** kept only from a pinned sender, on any link (LAN, Internet, p2p,
  nearby, onion), and only when the binding verifies against the link's
  authenticated sender key (carrier spec §3: strict Ed25519 over the signing
  input with `raven_pub` = that key; a usable onion key; `issued_s` at most a day
  ahead). Never an unsigned onion address, never one signed by anyone else.
- **Kept** in the sender's contact book row (`onion`, sealed with the book) when
  it is newer (higher `issued_s`) than the one there, or there is none; it goes
  with the contact. It is not part of the snapshot of §5.3 (no generation or
  expiry): an onion address is long-lived, and a newer binding replaces it.
- **Sender:** a node whose onion service runs tells its binding to every verified
  contact, whatever "hide my IP" says (an onion address carries no IP). The
  binding is an input of the global part's digest, so a new onion key moves the
  generation and is told to everyone (§6.1).
- **Use:** only to plan the onion route to its sender (carrier spec §4, §9).

### 15.2 Old peers

A receiver built before §15 skips 0x40 like any unregistered type (§5.1), so a
frame that carries it gives it the same hints.

