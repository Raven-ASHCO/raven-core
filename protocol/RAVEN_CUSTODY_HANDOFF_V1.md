# RAVEN Custody Handoff V1 (RHW1)

**Version:** 1 (`RHW1` record version byte `1`, inside RFC1 version byte `1`)
**Status:** Draft; **production disabled** (`CUSTODY_HANDOFF_PRODUCTION_ENABLED = false`,
which also needs `FRIEND_CUSTODY_PRODUCTION_ENABLED`). Lab only: debug builds with
`RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_CUSTODY_HANDOFF=1` while friend custody is live
(see `raven_core::custody_gate::handoff_live`). Release builds ignore the switches.
The per-link rule of friend custody (`custody_link_allowed`) still applies: LAN only
from local-network sources while `FRIEND_CUSTODY_WAN_ENABLED` is off.
**Audience:** re-implementers of the custodian, the forwarder and the requester.
**Companion:** [`RAVEN_FRIEND_CUSTODY_V1.md`](RAVEN_FRIEND_CUSTODY_V1.md) (RFC1). This
spec owns RFC1 ops 0x07 HANDOFF and 0x08 TAGS and replies 0x87 HANDOFF_RESULT and
0x88 TAGS_RESULT in the RFC1 op registry (RFC1 §4), and RFC1 codes 14-16 (RFC1 §5).
**Reference code:** `raven_core::custody_handoff` (the RHW1 record),
`raven_core::friend_custody` (the RFC1 frames). There is no Python reference: Rust
writes the vectors (§8).

---

## 0. Shape

Store-and-forward over at most two friend custodians: A -> F1 -> F2 -> B.

Preconditions:

- A and B have a confirmed, unexpired session (RFC1 §2 unchanged).
- A-F1, F1-F2 and F2-B are mutual pinned contacts.
- F1 is listed by A for B. F2 is listed by B for A.
- B announces F2 to A in RRH1 (the custodian entry of
  [`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §12) with flag bit0
  `HANDOFF_INBOX`.
- F1 and F2 run with custody and custody handoff on in their policy.

What stays unchanged:

- B fetches from F2, and A fetches ACKs from F1, with RFC1 FETCH/RELEASE.
- Ingest is unchanged (RFC1 §7).
- The ACK goes back B -> F2 -> F1 -> A by the same rules, with the roles mirrored.

No new port, handshake, crypto, envelope byte, RSO1 byte, or RFC1 header or version
byte.

## 1. Frames (inside RFC1)

The RFC1 header is unchanged: `"RFC1" | 0x01 | op | req_id[8]` (14 bytes). Integers
are big-endian. One frame is one Noise transport plaintext (at most 65,519 bytes).

```text
requests
  0x07 HANDOFF  rhw1_record                                       frame = 58 + rso1_len,
                                                                  rso1_len in [145, 65,461]
  0x08 TAGS     action u8 (1 REGISTER, 2 WITHDRAW) || count u8 (1..=32)
                || ( store_tag[16] || expires_at_ms u64 ) x count frame = 16 + 24 count

replies (exactly one terminal reply per request)
  0x87 HANDOFF_RESULT  code u8 || custody_digest[32]              47 B, terminal (digest zero if unparsable)
  0x88 TAGS_RESULT     code u8 || accepted u8 || conflicts u8     17 B, terminal
```

TAGS rules:

- REGISTER: every `expires_at_ms` is non-zero. WITHDRAW: every `expires_at_ms` is zero.
- Repeated tags merge to their latest expiry; the decoded entries are sorted by tag.
  Merging is a fixed point: re-encoding the decoded request and decoding it again gives
  the same request.

RHW1 record ("Raven Hop Wrapper" v1, carried only in op 0x07):

```text
off  len  field
0    4    "RHW1"
4    1    version = 0x01
5    1    kind: 0x01 FORWARD (origin -> first custodian), 0x02 DELIVER (first -> final custodian)
6    1    flags = 0x00
7    1    reserved = 0x00
8    32   next_hop: FORWARD = Ed25519 contact key of the final custodian (non-zero);
          DELIVER = 32 zero bytes
40   4    rso1_len u32
44   n    rso1
```

RHW1 constants:

- `RHW1_FIXED_LEN = 44`.
- `MAX_RHW1_RSO1 = 65,519 - 14 - 44 = 65,461` (the largest HANDOFF frame is exactly one
  transport plaintext).
- `MAX_RHW1_ENVELOPE = 65,461 - 59 = 65,402`. The largest LAN send (49,344 bytes: the
  text cap plus sealed overhead, the RVN1 prefix and the signature) always fits.

RSO1 rules: as RFC1 §4 (no custody signature, flags 0, `created_at_ms` and
`expires_at_ms` equal to the envelope's), and the envelope must fit
`MAX_RHW1_ENVELOPE`.

Digests:

- `custody_digest = SHA-256(packed envelope)`.
- `page_token` = the Mailbox V1 page token (unchanged).

The record carries **no** recipient key, **no** path and **no** hop counter.

**Decoding.** A HANDOFF whose record breaks any rule above (short input, another magic,
a version other than 1, a kind other than 1 or 2, non-zero flags or reserved byte, a
FORWARD with an all-zero `next_hop`, a DELIVER with a non-zero one, `rso1_len` outside
[145, 65,461], or a total length other than `44 + rso1_len`) gets HANDOFF_RESULT with
`MALFORMED`. A TAGS with a count outside 1..=32, a frame length other than
`16 + 24 count`, an action other than 1 or 2, a REGISTER entry with a zero expiry or a
WITHDRAW entry with a non-zero one gets TAGS_RESULT with `MALFORMED`. A reply op sent as
a request gets `UNSUPPORTED` (RFC1 §4). A future RHW2 uses a **new** RFC1 op, so v1
listeners answer it `UNSUPPORTED` rather than `MALFORMED`.

**Gates.** A listener whose handoff gate is closed, or one built before this spec,
answers 0x07 and 0x08 `UNSUPPORTED` (`max_version` 1, echoing `req_id`), whether or not
the frame is well formed, exactly as for any unknown op (RFC1 §4); so does a debug lab
listener with `RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1`. A listener that serves the ops
answers each refusal before the op's own work (the link gate `HOLD`, a link peer that is
not a pinned contact `NOT_VERIFIED`, `MALFORMED`) in that op's own terminal reply:
HANDOFF_RESULT with a zero digest, or TAGS_RESULT with zero counts. A refusal never comes
back as another op's reply.

## 2. Codes

RFC1 codes 0-13 keep their meaning. Unknown codes are still `PERSISTENCE`.

| Code | Name | Registry string | When / requester action |
|---:|---|---|---|
| 14 | NEXT_HOP_UNKNOWN | `CUSTODY_NEXT_HOP_UNKNOWN` | FORWARD: the next hop is not a pinned, unblocked contact of this custodian, or it is the depositor or the custodian itself. Park (custodian, next hop) for 24 h. |
| 15 | TAG_UNKNOWN | `CUSTODY_TAG_UNKNOWN` | DELIVER: the RSO1 store tag has no live registration. The forwarder retries (60 s doubling to 10 min) until the object expires. |
| 16 | HOP_REFUSED | `CUSTODY_HOP_REFUSED` | FORWARD from a link peer that is not the envelope's outer signer. Never again at this custodian. |

Reused codes:

- `HOLD` (3): the link gate is closed for this link. Park the custodian for handoff 1 h.
- `POLICY_DENIED` (2): custody or custody handoff is off in the custodian's policy. Park
  the custodian for handoff 1 h.
- `UNSUPPORTED` (0xFE reply): the listener does not serve the handoff ops (built before
  them, or its handoff gate is closed). Park handoff at that custodian for 24 h. Plain
  RFC1 custody there is unaffected.

Local-only registry strings: `CUSTODY_HANDOFF_UNSUPPORTED`, `CUSTODY_TAG_CONFLICT`.

## 3. Rules

### 3.1 Custodian receiving HANDOFF/FORWARD (F1; D = link peer)

Checks, in order:

1. The handoff gate (`UNSUPPORTED` while closed, §1), then the link gate (`HOLD`).
2. D is a pinned contact (`NOT_VERIFIED`).
3. Custody and custody handoff are on (`POLICY_DENIED`).
4. The per-depositor attempt window, 120 per minute, shared with DEPOSIT
   (`RATE_LIMITED`).
5. Strict decode and the RSO1 rules (`MALFORMED`).
6. Custody admission of the envelope (`EXPIRED` / `REFUSED_OBJECT`).
7. Canonical outbound hop fields: flags 0, hint 0, hop 8, budget 2, empty ratchet
   header (`REFUSED_OBJECT`).
8. The envelope's outer signature verifies under D, else `HOP_REFUSED`.
9. `next_hop` is not D, not the custodian, and is a pinned, unblocked contact
   (`NEXT_HOP_UNKNOWN`).

Then one IMMEDIATE transaction in the custodian's handoff store:

- the same (digest, next_hop) with the same tag gives `DUPLICATE`;
- the same digest with another tag gives `CONFLICT`;
- 2 next hops already held for this digest gives `QUOTA`;
- the caps (§6) give `STORE_FULL`, `QUOTA` or `RATE_LIMITED`;
- otherwise the row is inserted.

`STORED` is sent only after commit.

### 3.2 Forwarder (F1)

- Pending rows are grouped by next hop H.
- Before sending, the depositor is re-checked as a pinned, unblocked contact.
- H's routes are the custodian routes of friend custody, gate-filtered and LAN-localized
  while WAN custody is off.
- At most 16 HANDOFF/DELIVER frames per dial and 4 dials per H per pass.
- Triggers: a base interval of 60 s, H seen, a kick, a network change, and an inbound
  FORWARD.

How each answer is handled:

- `STORED` or `DUPLICATE`: the row is marked handed and is never re-sent; a later
  FORWARD of the same object gets `DUPLICATE`.
- `TAG_UNKNOWN`: back off.
- Terminal codes (`REFUSED_OBJECT`, `EXPIRED`, `MALFORMED`, `CONFLICT`,
  `RECIPIENT_NOT_ACCEPTED`, `HOP_REFUSED`): the row is marked refused.
- `HOLD` or `POLICY_DENIED`: park H for 1 h.
- `NOT_VERIFIED`: park H for 24 h.
- `UNSUPPORTED`: park H for 24 h.
- The link closed by the peer: a handoff strike; 3 strikes within 1 h park handoff at H
  for 1 h.

Retention: rows (payload included) stay until the envelope's `expires_at`, TTL-only
(errata rule 9).

### 3.3 Custodian receiving HANDOFF/DELIVER (F2; D = link peer)

Checks 1-7 as in 3.1. There is no signer check: the recipient's ingest checks the outer
signature against its own session peer before any protected load.

Then:

- R = the live, unconflicted registration of the RSO1 `store_tag`. None gives
  `TAG_UNKNOWN` (and creates no store); a conflicted tag gives `CONFLICT`.
- R must not be D or the custodian, and must be a pinned contact
  (`RECIPIENT_NOT_ACCEPTED`).
- The object is stored exactly as an RFC1 DEPOSIT, with recipient = R and depositor = D.
  All RFC1 caps apply (node, per depositor, per (depositor, recipient) 128).

Answers: `STORED`, `DUPLICATE`, `CONFLICT`, `QUOTA`, `STORE_FULL`, `RATE_LIMITED`. R
then FETCHes the object with RFC1 FETCH, unchanged.

### 3.4 Custodian receiving TAGS (registrant R = link peer)

Checks: the gates, R pinned, the policy, 30 TAGS frames per minute.

REGISTER:

- each expiry is clamped to now + 72 h, and entries already expired are skipped (a
  frame whose entries are all past answers `OK` with zero counts and creates no store);
- a free tag is registered to R;
- R's own tag is extended to the later expiry;
- a tag held by another recipient is marked conflicted until the later of both
  expiries (both lose), and `conflicts` is incremented; registering a tag that is
  already conflicted counts as a conflict too;
- caps: 512 live tags per recipient and 8,192 per node. An entry past a cap is refused
  alone: the frame answers `QUOTA`, and the entries before and after it are still
  registered. Nothing is ever evicted.

TAGS_RESULT for REGISTER: `accepted` = the entries registered or extended, `conflicts`
= the entries that met another recipient's tag or a conflicted one.

WITHDRAW deletes only R's own unconflicted tags and answers `OK` with `accepted` = the
tags withdrawn (0 when the custodian holds no handoff store) and `conflicts` = 0.

### 3.5 Requester (sender worker; also the recipient's owed ACKs)

The RFC1 custody eligibility rules are unchanged. For each listed custodian C (at
most 2):

- no fresh RRH1 announcement from the peer: RFC1 DEPOSIT (Phase 3 behaviour);
- C is in the peer's announced set: RFC1 DEPOSIT;
- otherwise, if the handoff gate is live and the peer announced H with `HANDOFF_INBOX`
  (H not C, not self, not the peer, and (C, H) not parked): HANDOFF/FORWARD with
  `next_hop = H` at C. One next hop per C;
- otherwise (the handoff gate closed, handoff parked at C or for every (C, H), or no H
  announced with `HANDOFF_INBOX`): RFC1 DEPOSIT at C, as in Phase 3 (a plain park of
  (C, peer) still blocks it). With the handoff gate closed the plan is exactly Phase
  3's.

H is matched against the requester's own pinned, unblocked contacts: an RRH1 custodian
tag is pair-blinded (`RAVEN_ROUTE_HINTS_V1.md` §12.1), so a custodian the requester
does not pin itself is never named as a next hop. Pinning it by key alone (no route)
is enough; the requester never dials it (it fetches from a custodian the peer
announced only when that custodian offers custody to the requester itself, §3.6).

The recipient's owed ACKs take the mirrored path: they are FORWARDed only when the
recipient pins a custodian the sender announced with `HANDOFF_INBOX`. For a message and
its ACK both to pass through two friends, each person pins the other's custodian;
otherwise the message can arrive while its ACK has no custody path back, and the
sender's view of an expired message held through a FORWARD says that its delivery was
not confirmed (not that the recipient did not collect it).

At a FORWARD step each object is checked on its own: only one with at least 2 h of
validity left whose envelope fits `MAX_RHW1_ENVELOPE` is forwarded. Any other object
gets the plain RFC1 DEPOSIT at C instead (the same fallback).

`STORED` or `DUPLICATE` count as "held by C" (forwarded, never delivered). Only a
verified ACK delivers. Other answers to a FORWARD:

- `NEXT_HOP_UNKNOWN`: park (C, H) for 24 h; the next attempt tries the next announced H;
- `HOLD` or `POLICY_DENIED`: park handoff at C for 1 h;
- `UNSUPPORTED`: park handoff at C for 24 h; plain custody at C is unaffected;
- any other code: the RFC1 rules.

A dial carrying FORWARDs only that C closed is a handoff strike (3 within 1 h park
handoff at C for 1 h); a dial that also carried DEPOSITs counts as plain custody's
strike. A plain park of the whole custodian (`HOLD`, `NOT_VERIFIED`, plain strikes,
`STORE_FULL` and the other RFC1 parks) also holds handoffs there; a plain park of
(C, peer) (`RECIPIENT_NOT_ACCEPTED`) blocks DEPOSITs only: while the handoff gate is
live the requester still fetches the peer's mail at C and registers its tags there (C
may hold that mail as a DELIVER from the peer's custodian). Since a closed link gate
answers every op `HOLD`, a custodian behind one is usually parked whole by the
requester's own fetch first.

### 3.6 Recipient tag registration

- For every custodian C it fetches from for contact P (the custodians it lists for P,
  and with learned custody its home custodians and those P announced that offer
  custody to it), the recipient REGISTERs the inbound store tags of each live session
  with P for the days [today - 1, today + 1] within the session's days.
- Expiry = the end of that day + the custody validity bound, clamped to now + 72 h by
  the recipient too.
- Registration rides the fetch dial (at most 2 TAGS frames, before RELEASE/FETCH). A
  tag is registered once for all its days and sent again when less than 24 h is left
  and a later expiry is wanted (a tag's expiry is fixed by its day), and in any case
  once C's last `OK` for it is 6 h old: C says nothing when it lost the registrations
  (custody turned off and on with its store purged, a damaged store set aside), since
  FETCH works by tag whatever is registered, and registering one's own tag again only
  extends it (§3.4). A round in which C answers TAGS or FETCH `POLICY_DENIED`, `HOLD`
  or `NOT_VERIFIED`, or TAGS `UNSUPPORTED`, forgets every registration at C: all of
  them are sent again once C takes the recipient.
- The recipient announces C with `HANDOFF_INBOX` only while C is fresh: C answered TAGS
  with `OK` within 24 h (with the 6 h refresh, several times a day while C is
  reached). The recipient's own record of what it registered does not keep C fresh,
  and a round C refuses as above ends it at once.
- C answering TAGS `UNSUPPORTED` parks handoff there for 24 h, `POLICY_DENIED` or
  `HOLD` for 1 h; either way C is no longer announced with `HANDOFF_INBOX`, and the
  fetch itself goes on. Conflicts are logged as counts only
  (`CUSTODY_TAG_CONFLICT`).

## 4. Hop limit and loops

- FORWARD is accepted only from the outer signer, and DELIVER is terminal (it never
  creates a forward row). Any path therefore has at most 2 custodians.
- Every honest custodian enforces this with a check it can make itself: locally
  policy-bounded forwarding (errata rule 8), with no unauthenticated budget.
- A Byzantine F1 cannot make an honest F2 forward again, because F2 sees signer != F1
  and refuses with `HOP_REFUSED`.
- `next_hop` is never the depositor or the custodian.
- Each node deduplicates by SHA-256 of the exact bytes; the same digest under another
  tag gives `CONFLICT`.
- Copies: at most 2 first-level custodians, times 1 next hop each, gives at most 2
  second-level holds (deduplicated when they share F2).
- Byzantine copying of ciphertext is always possible and is bounded only by quotas.

## 5. Who learns what

| Party | Learns | Does not learn |
|---|---|---|
| F1 (sender's friend) | A (link peer and signer); F2's key; the A-B daily store tag (opaque); message_id; size; created/expiry; timing | B: there is no recipient field, `dest_device_hint` is 0, and the tag is opaque. Exception: collusion with F2, or holding A-B session state |
| F2 (recipient's friend) | F1 (link peer); B (through B's tag registration, which B's FETCH shows anyway); the tag; message_id; size; timing; B's fetch and release timing | A, unless F2 already holds A's public key and tests the outer Ed25519 signature (disclosed in the waiver) |
| F1 and F2 colluding | The full A-B link, by digest | Content |
| A | B's announced custodians (Phase 3) and whether they accept handoffs | — |
| B | Same as RFC1 | — |
| Network observer | IPs and timing of A-F1, F1-F2 and B-F2; timing correlation is possible because there is no mixing | Content; identities inside Noise |

One-hop custody, by comparison, shows both ends to its custodian. Logs stay counts-only.
ACKs mirror the table with A and B swapped.

## 6. Limits (initial values; tuned with the harness)

| Scope | Limit |
|---|---|
| Forward table, node | 1,024 rows / 32 MiB |
| Forward table, per depositor | 128 rows / 8 MiB |
| Forward table, per (depositor, next hop) | 64 rows |
| Forward table, bytes per depositor | 2 MiB per minute |
| Forward table, next hops per digest | 2 |
| Attempt window | 120 frames per minute, shared with DEPOSIT |
| DELIVER at F2 | All RFC1 caps, with depositor = the forwarder (node 4,096 rows / 64 MiB, per forwarder 512 / 16 MiB, per (forwarder, recipient) 128, 2 MiB/min) |
| Tags | 512 per recipient, 8,192 per node, TTL at most 72 h, 30 TAGS frames per minute |
| Dials | at most 16 HANDOFF frames each; reply budgets as RFC1 |

Every refusal refuses; nothing is evicted.

## 7. Compatibility and old peers

- Listeners built before this spec, and listeners with the handoff gate closed, answer
  ops 0x07/0x08 `UNSUPPORTED` (RFC1 §4). Requesters then park handoff only.
- Pre-custody listeners are never sent RFC1 beyond the RFC1 rules. A closed link there
  on a dial of FORWARDs only is a handoff strike, separate from plain-custody strikes
  (§3.5).
- Older requesters never send ops 0x07/0x08.
- RRH1 receivers ignore unknown custodian flag bits.
- IPC dials refuse any RFC1 frame outside the lab (unchanged).
- The friend custody store keeps its schema; handoff state lives in a separate store
  that older builds ignore (its rows expire only once a newer build maintains it).
- No existing byte changes: ops 0x01-0x06, replies 0x81-0x86 and 0xFE, and every
  existing RFC1 vector are unchanged.

## 8. Vectors

[`shared-vectors/rvn1/custody/`](../shared-vectors/rvn1/custody/), written by Rust
(`raven_core::friend_custody` tests, `RAVEN_REGEN_RHW1_VECTORS=1`):

Positive:

- `rhw1_forward_001.json`, `rhw1_deliver_001.json` (the HANDOFF frame and the RHW1
  record of the RSO1 of `rfc1_deposit_001.json`);
- `rfc1_tags_register_001.json`, `rfc1_tags_withdraw_001.json`;
- `rfc1_handoff_replies_001.json` (frame lengths 47, 47 and 17).

Negative (`custody/negative/`; each gives the frame, its decode and the reply a listener
serving the handoff ops sends once its link gate and contact rule passed):

- `rhw1_neg_deliver_next_hop_001`, `rhw1_neg_forward_zero_hop_001`,
  `rhw1_neg_kind3_001`, `rhw1_neg_version2_001`, `rhw1_neg_flags_001`,
  `rhw1_neg_len_mismatch_001` (HANDOFF_RESULT `MALFORMED`);
- `rfc1_neg_tags_count0_001`, `rfc1_neg_tags_withdraw_expiry_001` (TAGS_RESULT
  `MALFORMED`);
- `rfc1_neg_handoff_result_as_request_001` (`UNSUPPORTED`).

## 9. Relay mailbox (not specified in v1)

TAGS REGISTER is the recipient-issued deposit right, scoped to depositors who are the
registering custodian's friends.

A mailbox that takes deposits from strangers would need all of the following, and is
deferred (owner decision P5-MH-2):

- a capability signed by B;
- capability-checked admission before identity is revealed;
- a peer-gate exception;
- Sybil limits per capability;
- its own gate and waiver.
