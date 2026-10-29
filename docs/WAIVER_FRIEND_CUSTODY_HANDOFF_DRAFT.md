# DRAFT owner waiver: custody handoff ("two friends in a row") on the local network

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `CUSTODY_HANDOFF_PRODUCTION_ENABLED`
> (`node/crates/raven-core/src/custody_gate.rs`) stays `false` until the owner
> signs a final copy (renamed to `docs/WAIVER_FRIEND_CUSTODY_HANDOFF_<date>.md`),
> its preconditions (§7) are met, and the flip is applied as its own reviewed
> commit. Debug builds open handoff with `RAVEN_LAB_CUSTODY_HANDOFF=1` and the
> lab unlock `RAVEN_LAB_TEST_A=1`, only while friend custody is live; release
> builds never read either.

| | |
|---|---|
| **Waiver ID** | `WAIVER-FRIEND-CUSTODY-HANDOFF-<date>` (to be assigned on signature) |
| **Extends** | the friend custody record [`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md) (its §2 lists multi-hop delivery and `RHW1` as not covered), which extends [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) |
| **Not covered** | Handoff over the internet: the p2p record [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) (§2 and its Phase 3 amendment, §10) and [`WAIVER_INTERNET_DIRECT_DRAFT.md`](WAIVER_INTERNET_DIRECT_DRAFT.md) keep mesh custody, `RHW1` and "custody beyond RFC1 V1" out of scope, and they must be amended to name custody handoff first (§7) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-23 |
| **Decision** | Enable custody handoff (RFC1 ops 0x07 HANDOFF and 0x08 TAGS, the `RHW1` record) between verified friends' nodes on the local network in default and release builds, under this waiver instead of waiting for an independent review (owner decisions P5-MH-1, P5-MH-3, P5-MH-4 and P5-MH-5, recommended options) |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set `CUSTODY_HANDOFF_PRODUCTION_ENABLED = false` in `node/crates/raven-core/src/custody_gate.rs` |
| **Design** | [`design/2026-10-friend-custody.md`](design/2026-10-friend-custody.md) §20; the Phase 5 multi-hop design (`docs/roadmap/plans/phase45-design.json`, part "multi-hop delivery") |
| **Wire** | [`protocol/RAVEN_CUSTODY_HANDOFF_V1.md`](../protocol/RAVEN_CUSTODY_HANDOFF_V1.md) (RHW1 inside RFC1 version byte 1, codes 14-16); [`protocol/RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md) §4 (CUSTODIAN_TAG flag bit 0 `HANDOFF_INBOX`); vectors `shared-vectors/rvn1/custody/rhw1_*_001.json`, `rfc1_tags_*_001.json`, `rfc1_handoff_replies_001.json`, `custody/negative/`, `route_hints/rrh1_custody_handoff_inbox_001.json` |
| **User docs** | [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) §9; `raven node custody handoff on|off` prints its disclosure |
| **Real rows** | an unpublished test checklist: R28 (LAN mule) for this record; R29 (WAN chain) for the internet amendment |

## 1. Why a waiver is needed

[`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](../protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md)
§9.1 forbids a release flag for store-and-forward delivery until all of its
holds pass, and the friend custody record covers one custodian per copy
only. Custody handoff lets Alice leave a sealed message with her friend Fred,
who passes it on to Bob's friend Gina, from whom Bob collects it: Alice and
Bob need no friend in common, and neither friend learns both ends. Bob's ACK
comes back the mirrored way. It needs its own record.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- **RFC1 ops 0x07 HANDOFF** (an `RHW1` record: FORWARD from the origin to the
  first custodian, naming the final custodian's key; DELIVER from the first
  custodian to the final one) **and 0x08 TAGS** (REGISTER and WITHDRAW of the
  recipient's own store tags), with their replies 0x87 and 0x88, between the
  `raven-node` services of mutual **pinned** (verified) contacts, over **LAN
  links from a local-network source**, once `FRIEND_CUSTODY_PRODUCTION_ENABLED`
  and `CUSTODY_HANDOFF_PRODUCTION_ENABLED` are both set.
- **Objects:** the same as friend custody: RVNA1 `0x03` sealed messages and
  sealed ACKs only, staged under a confirmed session, with canonical hop
  fields; never pairing material and never a letter (RAL1).
- **Path:** at most two custodians. FORWARD is accepted only from the
  envelope's outer signer and DELIVER never creates a forward row, so a path
  is structurally A -> F1 -> F2 -> B; there is no hop budget to trust.
- **Discovery:** the recipient announces a custodian with the RRH1
  CUSTODIAN_TAG flag `HANDOFF_INBOX` only after that custodian accepted its
  tag registration; announcements ride authenticated links to verified
  contacts only, never cards. The sender names a next hop only among its own
  pinned contacts (the tags are pair-blinded).
- **Consent:** one node policy flag, `custody_handoff` (`raven node custody
  handoff on|off`), off by default and never set by AUTO, covering both
  custodian roles; it works only together with `raven node custody on`, and
  `on` prints what each role learns. The sender's and recipient's consent is
  their custodian lists (friend custody's).

Not covered (all remain held): handoff over Internet direct or p2p links
(WAN), more than two custodians, spray or blind forwarding (the transports
design's `RHW1` budgets, §4.2 and §4.6 there, are superseded and not built),
custodian-initiated delivery to the recipient, letters through a handoff, a
relay mailbox (owner decision P5-MH-2), Bluetooth handoff inboxes, and Swift /
iOS.

## 3. Holds of umbrella §9.1 waived for this scope

| Hold | Status | Waived? |
|---|---|---|
| 1. Automated gates | Unit tests, RHW1 and TAGS vectors, the RRH1 `HANDOFF_INBOX` vector, fuzz target `rfc1_frame` (RHW1, HANDOFF and TAGS seeds), carrier_matrix C54 and C55, fault matrix s68-s71, s97b and the s30 regression green on macOS | Not waived |
| 2. All companions APPROVED | Custody Handoff V1 and RRH1 are drafts | **Waived for this slice** |
| 3. Independent security review | Not done; the internal adversarial reviews are not independent | **Waived** |
| 4. Physical rows | Open: R28 | Not waived: the flip waits for it (§7) |
| 5. Store-and-forward paths stay lab-gated | Custody handoff becomes live | **Waived for this slice only** |

## 4. Residual risks accepted

1. **Who learns what** (spec §5). F1 (the sender's friend) learns the sender
   (link peer and signer), F2's key, the pair's opaque daily store tag, the
   message id, size and times, but not the recipient: there is no recipient
   field and the tag is opaque. F2 (the recipient's friend) learns F1, the
   recipient (through its tag registration, which its fetches show anyway),
   the tag, the message id, size and times, but not the sender, unless F2
   already holds the sender's public key and tests the outer Ed25519
   signature against it. ACKs mirror this with the roles swapped. Logs carry
   counts only.
2. **F1 and F2 colluding** learn the full sender-recipient link (by digest),
   never the content. The two friends of a pair often know each other.
3. **Timing correlation.** There is no mixing or delay: a network observer of
   the A-F1, F1-F2 and F2-B links, or the two friends together, can match one
   message's hops by time and size.
4. **Ciphertext at two custodians until it expires.** F1 keeps its copy after
   F2 answered STORED (TTL-only, owner decision P5-MH-4, errata rule 9): the
   signed envelope, proof of who wrote to whom to anyone who holds the
   sender's key, sits at two friends for up to 24 h (plus the 5 min skew
   allowance) unless RELEASE deletes F2's copy first.
5. **Tag squatting.** A node that already sees a pair's tag (a custodian of
   that pair, or a fetcher of the same custodian it colludes with) can
   register it first at a custodian: both registrations then lose the tag
   (conflicted until it expires) and handoffs to that recipient there fail
   for the day. It never redirects an object: a DELIVER needs a live,
   unconflicted registration, and only the registrant can FETCH it.
6. **Availability only.** Either friend can drop, withhold or delay; the
   sender keeps retrying directly, F1 keeps retrying F2 (TAG_UNKNOWN 60 s
   doubling to 10 min) until the object expires, and only a verified ACK
   delivers.
7. **The 24-hour limit.** Two hops spend part of the envelope's 24 h; the
   sender forwards only an object with at least 2 h left, and an object that
   runs out anywhere on the path is simply gone (s97b).
8. **No independent review** of RHW1, the TAGS rules or the handoff store,
   and Swift parity is not verified in this tree.

## 5. Compensating controls in place

- Everything of friend custody's §5 (link admission before identity, pinned
  contacts only, refuse never evict, at-rest sealing, counts-only logs).
- FORWARD only from the outer signer (`HOP_REFUSED` otherwise), DELIVER
  terminal, `next_hop` never the depositor or the custodian and always a
  pinned, unblocked contact (`NEXT_HOP_UNKNOWN`): the hop limit is checked by
  every honest custodian on its own.
- A DELIVER is stored only for a live, unconflicted registration whose
  registrant is a pinned contact other than the forwarder and the custodian
  (`TAG_UNKNOWN`, `CONFLICT`, `RECIPIENT_NOT_ACCEPTED`); RFC1 FETCH still binds
  the recipient to the link peer.
- Bounded custodians: the forward table 1,024 rows / 32 MiB per node, 128 rows
  / 8 MiB per depositor, 64 per (depositor, next hop), 2 next hops per digest;
  tags 512 per recipient and 8,192 per node, at most 72 h, 30 TAGS frames a
  minute; the attempt window shared with DEPOSIT; DELIVER under all RFC1 caps.
- The forwarder re-checks the depositor and the next hop before each pass and
  drops rows of a party no longer pinned; the handoff store is sealed at rest
  and purged with `raven node custody off --purge`.
- Old and closed custodians: a listener with the gate closed or built before
  the ops answers `UNSUPPORTED` and the sender parks handoff only (plain custody
  there stays usable); `HOLD` and `POLICY_DENIED` park handoff for an hour
  (C55, s71).

## 6. Conditions

This waiver lapses, and `CUSTODY_HANDOFF_PRODUCTION_ENABLED` MUST be set back
to `false`, if:

- a critical or high finding on the covered path is confirmed and not fixed;
- a path can hold more than two custodians, a FORWARD is accepted from anyone
  but the outer signer, or a DELIVER creates a forward row;
- a custodian evicts instead of refusing, admits an unpinned or blocked peer,
  or stores a DELIVER without a live registration;
- `HANDOFF_INBOX` or a custodian tag travels outside authenticated links or to
  unverified contacts, or appears in cards;
- handoff works without the `custody_handoff` consent, or with friend custody
  off;
- the friend custody record or the LAN waiver lapses or is withdrawn;
- C54, C55, s68-s71, s97b or the s30 regression is disabled or fails on any of
  its runners for more than one release;
- the review-by date passes without renewal.

## 7. Preconditions and flip order

Before signature:

- the friend custody record signed and `FRIEND_CUSTODY_PRODUCTION_ENABLED`
  live (owner decision P5-MH-5);
- carrier_matrix C54 (two-hop chain, message and ACK, with the byte scan) and
  C55 (refusals) green on ubuntu, macOS and Windows;
- lan_fault_matrix s68, s69, s70, s71, s97b and s30 (all with
  `RAVEN_FAULT_HANDOFF=1`, s30 also with `RAVEN_FAULT_CUSTODY=1`, with and
  without `RAVEN_FAULT_HINTS=1`) green 5 times on macOS and Linux;
- the RHW1, TAGS and handoff reply vectors green in Rust and
  [`PROTOCOL_FREEZE_HASHES_V1.md`](PROTOCOL_FREEZE_HASHES_V1.md) checked;
- real row **R28** (LAN mule: Alice and Fred on one Wi-Fi, Fred's laptop
  carried to the Wi-Fi of Gina and Bob, exactly once with no internet).

Flip order, each in its own reviewed commit, after signature (owner actions):

1. `CUSTODY_HANDOFF_PRODUCTION_ENABLED` (LAN only) after R28.
2. Handoff over the internet is not part of this record: it needs
   `FRIEND_CUSTODY_WAN_ENABLED`, real row **R29** (WAN chain), and amendments
   of the p2p and Internet direct records that name custody handoff and
   `RHW1`.

At the flip, the status line of `RAVEN_CUSTODY_HANDOFF_V1.md`, its row of
[`protocol/PROTOCOL_VERSIONS.md`](../protocol/PROTOCOL_VERSIONS.md) and the
freeze hashes are updated in the same commit.

## 8. Signature

Not signed.
