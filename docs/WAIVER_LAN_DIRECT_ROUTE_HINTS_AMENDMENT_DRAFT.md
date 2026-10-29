# DRAFT (unsigned): amendment to `WAIVER-LAN-DIRECT-2026-10-07` for route hints on LAN links

| | |
|---|---|
| **Status** | **DRAFT, not signed.** Nothing here is in force until the owner signs it. Until then `ROUTE_HINTS_PRODUCTION_ENABLED` stays `false` and route hints run only in debug builds with `RAVEN_LAB_ROUTE_HINTS=1`; with it off the LAN wire is byte-identical to today. |
| **Amends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md), its [P2a amendment](WAIVER_LAN_DIRECT_P2A_AMENDMENT_DRAFT.md) and its [session reset amendment](WAIVER_LAN_DIRECT_SESSION_RESET_AMENDMENT_DRAFT.md) (none is edited) |
| **Companion** | The Phase 2 amendment of [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) (§9: route hints on p2p links, friend relays). Both are signed before `ROUTE_HINTS_PRODUCTION_ENABLED` is flipped (one gate for every link, owner decision "gate shape") |
| **Design** | the any-network reachability plan (not published) §3, Phase 2 item 1 (C5) |
| **Wire** | [`protocol/RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md) §3.2 (RLX1), §4-§8 (RRH1); vector `shared-vectors/rvn1/lan/noise_xx_handshake_002.json` |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-17 |
| **Review by** | Same date as the LAN waiver (2027-01-07) |

## 1. Why an amendment

A contact whose LAN listener comes back on another port cannot be reached
until someone types its new address or exchanges cards again (fault matrix
s04). Route hints close that gap: each side tells the other, inside the
authenticated link, how to reach it. On LAN this changes two things on the
live slice: the Noise XX handshake's third message may carry a small payload,
and a new control frame travels after RLB1. The LAN waiver §6 makes "extending
the slice beyond §2 without a new waiver" a lapse condition, so the change is
written down here.

## 2. What changes on the covered slice

The carrier (LAN direct TCP, Noise XX bound to the Raven identity, the RLB1
offer), the session profile, the objects and the admission rules of the waiver
§2 are unchanged.

1. **RLX1 in Noise XX message 3** (spec §3.2). The dialer may put
   `"RLX1" || 0x01 || entries` into the payload of message 3. The one entry
   registered is `LINK_CAPS` (4 bytes, bit 8 = "I accept RRH1 on this link"),
   so with route hints on message 3 grows from **64 to 75 bytes**. The payload
   is mixed into the handshake hash but not into the chaining key: the
   transport keys and both identity binds are unchanged
   (`lan/noise_xx_handshake_002.json`). Messages 1 and 2 keep their empty
   payloads. A dialer sends RLX1 only on dials that will read (dials that
   carry message frames, and announce links, item 4); a frame-less probe sends
   the empty payload. A responder parses RLX1 only after its contact gate and
   never closes or answers because of it; a pre-RLX1 responder decrypts and
   discards it.
2. **RRH1 on LAN links** (spec §3.3-§6). One unsigned, one-way frame each way
   after both RLB1 offers, only when the dialer's LINK_CAPS has bit 8: the
   listener sends its frame right after its RLB1 offer, and the dialer
   answers with its own only after it received one. It is consumed by the
   link layer, never handed to the dispatcher, never wrapped in RVN1, never a
   reply. To a verified (pinned), unblocked contact it carries the full
   snapshot (PeerId, relays, confirmed global addresses, custodians while
   friend custody is live, relay offers while friend relays are live) plus
   the LAN part: the LAN listener port (`LAN_PORT`) and at most 2 same-LAN
   listen addresses in the link's /24 or /64. The receiver keeps the LAN part
   per contact (its IP is the link's peer IP, never an address the frame
   names), uses it only to reach the sender, and `raven send` saves a learned
   port back into the contact's LAN route. Old peers: a listener without
   RLX1 never sends RRH1, so a new dialer never sends one either (spec §3.4).
3. **LAN_PORT to unverified local contacts** (owner decision "route hints to
   unverified LAN contacts"). An unverified contact admitted on LAN under the
   waiver's local-network rule gets an RRH1 with `LAN_PORT` only, only on a LAN
   link: the same information as the card's `lan=`. A receiver keeps nothing
   else from an unpinned sender, and keeps `LAN_PORT` only from a frame that
   arrived on a LAN link from a local-network address. This is what closes
   s04 as the harness runs it (it pairs unverified contacts).
4. **Announce dials** (spec §7). When a node's snapshot changes (its LAN port,
   its relays, its addresses), it may open links that carry only RRH1 to the
   contacts that sent it an RRH1 that has not expired: changes are coalesced
   over 10 s, at most 64 contacts, at most once per contact per minute,
   retried after 1, 10 and 60 minutes, and a contact is done once any link
   carried the new generation. On LAN such a link carries RLX1, sends no
   message frame and waits up to 2 s after the listener's RLB1 for its RRH1.

## 3. What does not change

- No new carrier, no new port, no change to the Noise XX pattern, RLB1,
  `RavenEnvelopeV1`, PairInit, the indexed-session profile or the ATSAM
  endpoint transaction.
- Who is admitted is unchanged: RRH1 follows RLB1, which follows the contact
  gate, so RRH1 never reaches a stranger.
- Nothing learned is forwarded, re-sent or put into the receiver's own frame
  or card. `learned_routes.json` holds public keys, addresses and times only,
  written by raven-node alone, bounded, and forgotten with the contact
  (`raven contact remove`, `set-addr`, block).
- Logs carry counts only; a malformed frame is ignored whole or entry by entry
  (`RRH1_MALFORMED`, debug log), never a close.
- With the gate off, message 3 and every byte after the handshake are
  identical to the build before RLX1.

## 4. Residual risks added (on top of waiver §4)

1. **The caps bit before authentication.** RLX1 reaches the responder before
   the responder has authenticated itself (spec §8); the dialer's own identity
   bind follows on the same link anyway. A LAN impostor learns only that the
   dialer runs a build with route hints on.
2. **A local contact learns the LAN port**, unverified or not, and can record
   it; it is what the card's `lan=` already tells. Hints are deniable, not
   secret from their receiver.
3. **Same-LAN steering.** A contact can make this node dial at most 2 same-LAN
   addresses it names, inside the /24 or /64 of the link it arrived on.
4. **Announce dials add connections** and tell recent contacts, by their
   timing, that this node's snapshot changed (for example that it moved to
   another network).
5. **A stale port** stays usable to its receiver until the snapshot's TTL ends
   (72 h by default, at most 7 days) or the next frame replaces it. Its LAN
   IP and port stay dialable longer, for 30 days after they were learned
   (Phase 3 P3.C1, for friends who meet weekly): after the saved route, and
   never on a network this computer can tell is another one. Until then a
   dial may reach whoever holds that address by now, as with a stale saved
   address.

## 5. Preconditions for signing

- s04, s04b, s04c and s04p (`scripts/lan_fault_matrix.py` with
  `RAVEN_FAULT_HINTS=1`) green 5x on macOS and on Linux, with the locked-file
  backends.
- The full fault matrix and `cargo test` green with the switch on and off
  (`RAVEN_LAB_ROUTE_HINTS=1` and unset), and carrier_matrix C17 (LAN port
  change and old peers) green on ubuntu, macOS and Windows.
- One manual s04c row against a real pre-RLX1 build
  (`RAVEN_FAULT_OLD_BIN=<dir with the old ash and raven-node>`), both ways
  round: every message once, no dispatcher refusal, nothing learned.
- The real row R16 (a LAN listen-port change between two Macs,
  an unpublished test checklist).
- Before any LAN flip, the Swift/iOS LAN code, which is not in this tree, is
  checked against `lan/noise_xx_handshake_002.json`: it must accept a 75-byte
  message 3 and derive the same transport keys.

## 6. Signature

Not signed.
