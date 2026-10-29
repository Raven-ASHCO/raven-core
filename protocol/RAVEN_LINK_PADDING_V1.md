# RAVEN Link Padding V1 (PAD1)

**Version:** 1 (`RPD1`, version byte `1`)
**Status:** Draft; **production disabled** (`LINK_PADDING_PRODUCTION_ENABLED = false`).
Lab only: debug builds with `RAVEN_LAB_LINK_PADDING=1` and `RAVEN_LAB_TEST_A=1`
(`raven-core/src/security_gate.rs`). Release builds ignore the switch. With the
gate shut no link offers or sends PAD1 and every byte on the wire is as before.
**Audience:** re-implementers of the LAN, Internet direct, p2p and nearby Raven
links.
**Design:** `docs/roadmap/plans/phase6-design.json`, design B §2 and wire spec
W-B1; bucket sizes per owner decision OD6b-8.

---

## 1. Purpose

Every frame on a Raven link travels as one Noise transport message, whose
length is the frame's length plus 16. Someone on the path (the LAN, the Wi-Fi,
an ISP, a relay) sees that length, and frame lengths say what is going on: an
ACK is 293 bytes, a PairInit 2,788, a text roughly its length.

PAD1 pads every link frame to one of four sizes, so the path sees four size
classes instead. ACKs and short texts share the smallest; PairInit, RLB1
offers and medium texts share the next, so "a new session started" does not
stand out.

PAD1 does **not** hide: how many frames travel, when, in which direction, or
for how long a link stays open; the Noise handshake's sizes (the link knock
jitters them, [`RAVEN_LINK_KNOCK_V1.md`](RAVEN_LINK_KNOCK_V1.md) §6); the size
class of each frame; that two addresses talk at all.

## 2. Frame

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `RPD1` (`52 50 44 31`) |
| 4 | 1 | version `0x01` |
| 5 | 1 | reserved `0x00` |
| 6 | 2 | `inner_len`, u16 big-endian, 1..=65,511 |
| 8 | `inner_len` | the inner frame: exactly one link frame |
| 8 + `inner_len` | rest | padding, every byte `0x00` |

- The frame's total length `T` is the **smallest** bucket in
  {512, 4,096, 16,384, 65,519} with `T >= 8 + inner_len`.
- 65,519 is the largest Noise transport plaintext (65,535 less the 16-byte
  tag), so a padded frame is still one Noise transport message, and the
  longest inner frame is 65,511 bytes.
- The inner frame is one link frame as it would travel without PAD1: a LAN
  bind, RLB1, RRH1, RVN1, RFC1, RSR1 or PairInit. One RPD1 frame carries one
  inner frame; frames are never merged or split.
- Bucket edges: inner frames of 1-504 bytes take 512; 505-4,088 take 4,096;
  4,089-16,376 take 16,384; 16,377-65,511 take 65,519.
- Example: the 293-byte sealed ACK gives the header `52504431 01 00 0125`,
  the ACK, and 211 zero bytes (`shared-vectors/rvn1/link/pad1_ack_512_001.json`).

## 3. Negotiation

PAD1 is a link feature in the RIH1 caps namespace
([`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md) §2):

- `CAP_LINK_PAD1 = 0x00000200` (bit 9) means "on this link I pad what I send
  with PAD1 and read padded frames".
- **Internet direct, p2p and nearby:** in the signed RIH1 hello. A hello with
  route hints and padding carries `0x00000302`
  (`link/rih1_hello_pad1_001.json`); with padding alone `0x00000202`.
- **LAN direct:** in the dialer's RLX1 `LINK_CAPS` entry, Noise XX message 3
  ([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §3.2; with route hints
  and padding `524c5831 01 01 04 00000300`, `link/rlx1_caps_002.json`). The
  listener does not signal in the handshake: its first RPD1 frame is its
  answer. As for RRH1, a dialer offers PAD1 only on dials that will read; a
  frame-less probe sends the empty payload.
- A third party cannot strip the bit: the hello signature covers the caps and
  the handshake hash, and RLX1 is encrypted in message 3 and mixed into the
  handshake hash.
- A side offers PAD1 only while link padding is live. With it off, the hello
  and RLX1 are byte for byte what earlier builds send.
- Receivers ignore caps bits they do not know (unchanged rule; only
  `CAP_INTERNET` is required), so a peer built before PAD1 never pads and is
  never sent RPD1.

## 4. Order on the link

- **Internet direct, p2p and nearby.** When both verified hellos carry bit 9,
  each side wraps every frame it sends after the hellos. The hellos are never
  wrapped. When either lacks the bit, neither side pads.
- **LAN direct.** The dialer's bind comes first, as before.
  - The listener wraps every frame it sends from its own bind on when the
    dialer's `LINK_CAPS` carries bit 9 and the listener offers PAD1 itself.
  - The dialer reads RPD1 frames from the start (it asked for them). It wraps
    every frame it sends after it received the listener's first RPD1 frame.
    Before that its frames are bare; its bind (96 bytes) has a fixed size
    anyway. A listener without PAD1 never sends RPD1, so the dialer never
    pads to it.
- **Nearby (Bluetooth LE).** The Raven link inside the RNP1 pipe is the
  Internet-direct link ([`RAVEN_NEARBY_LINK_V1.md`](RAVEN_NEARBY_LINK_V1.md)
  §7), so it follows the Internet-direct rule; RNP1 fragments the padded
  frame like any other.

## 5. Sender rules

- A sender MUST use the smallest bucket that holds the inner frame, write the
  version `0x01` and the reserved byte `0x00`, and fill the padding with
  `0x00` (the Noise encryption hides it; zeros keep the frame deterministic
  and leave nothing to leak).
- A sender MUST NOT wrap an RPD1 frame (no nesting) and MUST NOT wrap an
  empty frame.
- Once a side wraps, it wraps every frame it sends on that link. A frame it
  cannot wrap (longer than 65,511 bytes) MUST NOT be sent bare: the peer
  would close the link. Today's links carry frames up to 65,519 bytes (an
  RFC1 frame with the largest RSO1, an RHW1 HANDOFF): on a padded link their
  senders use 65,511 as the limit.

## 6. Receiver rules

A side that offered PAD1 on a link reads every frame that starts with `RPD1`
as a PAD1 frame and refuses it on the first rule it breaks, in this order:

| Order | Rule | Error |
|---:|---|---|
| 1 | the frame starts with `RPD1` (otherwise it is a bare frame, below) | `BAD_MAGIC` |
| 2 | the frame's length is one of the four buckets | `BAD_BUCKET` |
| 3 | version is `0x01` | `BAD_VERSION` |
| 4 | the reserved byte is `0x00` | `BAD_RESERVED` |
| 5 | `inner_len` is 1..=`T - 8` | `BAD_LENGTH` |
| 6 | every padding byte is `0x00` | `NONZERO_PADDING` |
| 7 | the inner frame does not start with `RPD1` | `NESTED` |

- A receiver does **not** refuse a frame whose bucket is larger than the
  smallest that fits (a later revision may pad up).
- **Bare frames.** Before the peer's first RPD1 frame on this link, a frame
  that does not start with `RPD1` is read as it is (the peer may not pad yet:
  the LAN dialer's bind, or a frame sent before both hellos were checked).
  After it, a bare frame is refused: `UNPADDED`.
- Every refusal closes the link (raven-node notes it as
  `SEC_CONTACT_MALFORMED` about the contact).
- A side that did not offer PAD1 does not read RPD1: an RPD1 frame reaches its
  link as any frame it does not know, which closes the link (as for RRH1,
  [`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §3).
- The inner frame is then handled exactly as the same frame without PAD1.

## 7. Old peers

The same holds when "old" means "this build with link padding off".

| Dialer | Listener | Result |
|---|---|---|
| new | old | Internet, p2p, nearby: the old hello lacks bit 9, so nobody pads. LAN: the old listener ignores bit 9 (it reads only the bits it knows) and never sends RPD1, so the dialer never pads. Every byte after the handshake is as before. |
| old | new | No bit 9 from the dialer: the listener does not pad. As before. |
| new | new | Every frame after the hellos (Internet, p2p, nearby) or after the dialer's bind (LAN) is padded both ways. |

## 8. Sizes on the wire and cost

- A padded frame is a Noise transport message of `T + 16` bytes; on TCP it is
  framed as `u32_be(len) || message`, so a link frame costs `4 + T + 16`
  bytes on the wire: 532, 4,116, 16,404 or 65,539.
- ACKs and short texts grow to 512 bytes, medium texts and PairInit to 4 KiB.
  Negligible on Wi-Fi and cable; on Bluetooth LE a 4 KiB frame costs a
  fraction of a second.

## 9. Vectors

Written by Rust (`RAVEN_REGEN_SECURITY_VECTORS=1 cargo test -p raven-core
link_padding`), checked by the Python reference
(`protocol/reference/raven_protocol/link_padding.py`,
`tests/test_link_padding.py`). Under `shared-vectors/rvn1/link/`:

- `pad1_ack_512_001.json`: the sealed ACK of
  `atsam/indexed_session_v1_sealed_ack_001.json` (293 bytes) in 512.
- `pad1_pairinit_4096_001.json`: the PairInit of `atsam/pair_init_v1_001.json`
  (2,788 bytes) in 4,096.
- `pad1_max_001.json`: a 65,511-byte inner frame in 65,519 (by digest), the
  bucket edges, and the lengths a sender cannot pad.
- `rlx1_caps_002.json`: `LINK_CAPS` `0x00000300` and `0x00000200`.
- `rih1_hello_pad1_001.json`: a hello with caps `0x00000302` (same signer and
  binding as `route_hints/rih1_hello_rrh1_001.json`).
- `negative/`: `pad1_nonzero_padding_001`, `pad1_bad_bucket_001`,
  `pad1_nested_001`, `pad1_len_overflow_001`, `pad1_zero_len_001`,
  `pad1_bad_version_001`, `pad1_reserved_001` (one broken rule each), and
  `pad1_unpadded_after_pad1_001` (a bare frame after the peer's first RPD1
  frame).

## 10. Implementation status

- The codec and one side's state on a link: `raven-core/src/link_padding.rs`
  (`wrap`, `unwrap`, `PadState`); caps bit `CAP_LINK_PAD1` and the
  `LinkFeatures` set in `raven-core/src/internet.rs`; fuzz target
  `pad1_frame` (`node/fuzz`).
- The links (P6.34, behind the gate above): `raven-node/src/link.rs`
  (`LinkCipher`: the Noise transport and the link's `PadState`; every frame
  after the handshake is sealed and opened there). LAN direct
  (`lan_direct.rs`) offers bit 9 in the dialer's RLX1 on the dials that
  read, as for RRH1; the listener pads from its bind when the dialer offered
  it; the dialer pads after the listener's first RPD1 frame and records it
  in the listener's capability floor as seen. Internet direct
  (`internet_direct.rs`) offers it in the hello; p2p and nearby run that
  same link. A refusal ends the link; once the link knows its contact (past
  the listener's contact gate, or on a dial after the peer's bind or hello
  verified) it is `SEC_CONTACT_MALFORMED` about the contact.
- A frame longer than 65,511 bytes on a link that pads is not sent (the
  link write fails; spec §5). The RFC1 and RHW1 senders do not cap their
  frames at 65,511 on such a link yet, so an RSO1 within 8 bytes of
  `MAX_RFC1_RSO1` cannot cross a padded link.
- Tests: raven-node's duplex tests (each order, the bytes on the wire),
  carrier_matrix C86 part 1 and fault matrix s115 (against an older build
  with `RAVEN_FAULT_PADDING_OLD_BIN`).
