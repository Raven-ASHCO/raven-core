# RAVEN Friend Custody V1 (RFC1)

**Version:** 1 (`RFC1`, version byte `1`)
**Status:** Draft; **production disabled** (`FRIEND_CUSTODY_PRODUCTION_ENABLED = false`,
`FRIEND_CUSTODY_WAN_ENABLED = false`). Lab only: debug builds with
`RAVEN_LAB_TEST_A=1` (WAN custody also needs `RAVEN_LAB_CUSTODY_WAN=1`).
The letter ops (§10) also need the letter gate (`ASYNC_LETTER_PRODUCTION_ENABLED
= false`; lab `RAVEN_LAB_HORIZON=1` and `RAVEN_LAB_LETTER=1`).
Enabling it needs an owner-signed custody waiver.
**Audience:** re-implementers of the custodian, the sender's outbox and the
recipient's fetcher.
**Design:** [`docs/design/2026-10-friend-custody.md`](../docs/design/2026-10-friend-custody.md)
(revision 2).

---

## 1. Purpose

Alice can leave a message for Bob with Carol, a friend both of them verified,
when Bob cannot be reached directly. Carol holds the **exact sealed envelope**
(she cannot read it) until Bob fetches it, or until it expires. Bob's
acknowledgement travels back the same way. No new crypto, port or handshake:
custody frames ride the existing authenticated Raven link.

Custody works only inside an existing session: a first contact through a
friend is out of scope (design §13). The exception is a **letter** (§10): an
RAL1 letter carries its own PairInit V1 to a pinned contact, so it needs no
live session; the custodian holds it as opaquely as an object.

## 2. Who may do what

- Alice↔Carol and Bob↔Carol are mutual **pinned** contacts; Alice↔Bob are
  mutual pinned contacts with a confirmed, unexpired session.
- Carol serves custody only with `NodePolicy.custody = true` (default false;
  AUTO never sets it). With it off she refuses deposits but still serves fetch
  and release until held objects expire.
- Alice deposits objects for Bob at Carol when either holds:
  - (a) **announced:** Bob announced Carol to Alice (a CUSTODIAN_TAG Alice
    matched, [`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §12, or a
    Phase 2 0x05 entry), Carol offers custody to Alice (her CUSTODY_OFFER, with
    the WAN bit when Alice reaches her only over the Internet or p2p), and
    Alice's friend-mailbox consent is on; or
  - (b) **static:** both Alice and Bob list Carol as a custodian for each other
    (unchanged).
- Bob fetches from his home custodians (the friends he collects his own mail
  from, announced through RRH1 §12), from a former home custodian for about
  97 h after it is dropped, and from the custodians he listed. The drain is
  the RRH1 TTL Bob announces (72 h: a sender that never heard a newer
  announcement may still deposit there until the old one expires) plus the
  custody validity limit (24 h plus 5 min skew: what it left there lives at
  most that long) plus an hour, so every object a sender may still leave
  there has expired by then.

## 3. Addressing

Frozen derivations from the indexed-session profile (§6 of
[`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md)):

```text
day_epoch      = floor(unix_ms / 86_400_000)
mailbox_tag[d] = HMAC-SHA256(K_route[d], "rvn1/mailbox" || u64_be(day_epoch) || u64_be(d))[:16]
store_tag[d]   = SHA-256("raven/relay-tag/v1" || mailbox_tag[d])[:16]
```

- **Deposit tag:** the sender's outbound direction of the session the object
  was sealed under, and `day(envelope.created_at)` (deterministic per object).
- **Fetch tags:** the recipient's inbound direction, for every day in
  `[day(now − MAX_CUSTODY_VALIDITY_MS), day(now + 5 min)]` within the session's
  own days (at most 3). Toward a home custodian (§2 (a)): the inbound
  direction of every live session with a pinned contact, since any of them may
  have left mail there. Toward a static custodian (§2 (b)): the sessions of the
  contacts that listed it, unchanged.
- Every DEPOSIT also names the `recipient` key. Only that recipient,
  authenticated on the link, can fetch or release the object.

## 4. Frames

Each RFC1 frame is exactly one Noise transport plaintext (≤ 65,519 bytes), sent
on an authenticated Raven link after RLB1. All integers are big-endian.

```text
header (14 bytes, same layout in every version):
  magic "RFC1" (4) | version u8 = 0x01 | op u8 (requests < 0x80, replies >= 0x80) | req_id [u8; 8]

requests
  0x01 DEPOSIT  recipient[32] || rso1_len u32 || rso1           frame = 50 + rso1_len, rso1_len in [145, 65,469]
  0x02 FETCH    tag_count u8 (1..=32) || store_tag[16] x n || has_after u8 (0|1)
                || after_token[32] (all zero iff has_after = 0) || max_items u8 (1..=16)
                                                                 frame = 49 + 16 n
  0x03 RELEASE  count u8 (1..=32) || custody_digest[32] x count  frame = 15 + 32 count

replies (one terminal reply per request)
  0x81 DEPOSIT_RESULT  code u8 || custody_digest[32]                              47 B, terminal
  0x82 FETCH_ITEM      rso1_len u32 || rso1                                         non-terminal
  0x83 FETCH_END       code u8 || returned u8 || has_next u8 || next_token[32]     49 B, terminal
  0x84 RELEASE_RESULT  code u8 || released u8                                      16 B, terminal
  0xFE UNSUPPORTED     max_version u8                                              15 B, terminal
```

- `custody_digest = SHA-256(packed envelope)`.
- `page_token = SHA-256("raven/offline-mailbox/page-token/v1" || rso1)`
  ([`RAVEN_MAILBOX_TRANSPORT_V1.md`](RAVEN_MAILBOX_TRANSPORT_V1.md) §2).
- **RSO1 inside RFC1** ([`RAVEN_STORE_OBJECT_V1.md`](RAVEN_STORE_OBJECT_V1.md))
  is stricter: no custody signature (`flags == 0`), `created_at_ms` and
  `expires_at_ms` equal the envelope's, envelope ≤ 65,410 bytes. The RSO1
  `store_tag` is the custody tag.

**Op registry.** RFC1 has one op registry, under version byte 1. New
operations are added as new ops under that byte (an unknown op already gets
`UNSUPPORTED`, see Decoding); there is no RFC1 version 2, and the version byte
stays 1 for every op below. The letter ops 0x04-0x06 and their replies
0x85-0x86 are defined in §10. The handoff ops 0x07-0x08 and their replies
0x87-0x88 are defined by their owning spec,
[`RAVEN_CUSTODY_HANDOFF_V1.md`](RAVEN_CUSTODY_HANDOFF_V1.md) (multi-hop custody;
0x07 carries an RHW1 record). A listener serves them only while its handoff gate
is open, and a requester sends them only then.

| Op | Name | Direction | Answered by / kind | Owner |
|---:|---|---|---|---|
| 0x01 | DEPOSIT | request | DEPOSIT_RESULT 0x81 | this spec |
| 0x02 | FETCH | request | FETCH_ITEM 0x82 x n, then FETCH_END 0x83 | this spec |
| 0x03 | RELEASE | request | RELEASE_RESULT 0x84 | this spec |
| 0x04 | DEPOSIT_LETTER | request (§10) | DEPOSIT_RESULT 0x81 | this spec; the letter is [`RAVEN_ASYNC_LETTER_V1`](RAVEN_ASYNC_LETTER_V1.md) |
| 0x05 | FETCH_LETTERS | request (§10) | LETTER_ITEM 0x85 x n, then FETCH_END 0x83 | this spec |
| 0x06 | WITHDRAW_LETTERS | request (§10) | WITHDRAW_RESULT 0x86 | this spec |
| 0x07 | HANDOFF | request (handoff spec §1) | HANDOFF_RESULT 0x87 | [`RAVEN_CUSTODY_HANDOFF_V1`](RAVEN_CUSTODY_HANDOFF_V1.md) |
| 0x08 | TAGS | request (handoff spec §1) | TAGS_RESULT 0x88 | [`RAVEN_CUSTODY_HANDOFF_V1`](RAVEN_CUSTODY_HANDOFF_V1.md) |
| 0x81-0x84 | as above | reply | terminal except FETCH_ITEM | this spec |
| 0x85 | LETTER_ITEM | reply (§10) | non-terminal | this spec |
| 0x86 | WITHDRAW_RESULT | reply (§10) | terminal | this spec |
| 0x87 | HANDOFF_RESULT | reply (handoff spec §1) | terminal | [`RAVEN_CUSTODY_HANDOFF_V1`](RAVEN_CUSTODY_HANDOFF_V1.md) |
| 0x88 | TAGS_RESULT | reply (handoff spec §1) | terminal | [`RAVEN_CUSTODY_HANDOFF_V1`](RAVEN_CUSTODY_HANDOFF_V1.md) |
| 0xFE | UNSUPPORTED | reply | terminal | this spec |

- Requests 0x09-0x7F and replies 0x89-0xFD are unassigned; a later op takes
  the next free number in this table.
- Ops 0x01-0x03 and replies 0x81-0x84 keep their bodies whatever later op
  is added. DEPOSIT_RESULT and FETCH_END keep their layouts when they answer
  DEPOSIT_LETTER and FETCH_LETTERS.
- A listener without an op of 0x04-0x08 (a build from before it, or one whose
  gate for that op family is closed) answers `UNSUPPORTED` (`max_version` 1),
  echoing `req_id`, exactly as for any unknown op, whether or not the frame
  is well formed.
- A listener that serves the op answers its terminal reply with `HOLD` when
  the custody gate is closed for the link (§6), and with `POLICY_DENIED` when
  custody, or for 0x07-0x08 custody handoff, is off in its policy.
- A dial classifier must not end a request on LETTER_ITEM (non-terminal);
  0x86-0x88 end it like the other terminal replies.

**Decoding.** A frame shorter than 14 bytes or with another magic closes the
link. An unknown version, an unknown op, or a reply op sent as a request gets
`UNSUPPORTED` (echoing `req_id`). A wrong length, a count out of range,
`has_after ∉ {0,1}`, a non-zero `after_token` without `has_after`, or an RSO1
that breaks the rules gets the op's terminal reply with `MALFORMED`. Repeated
tags or digests are deduplicated.

## 5. Codes

| Code | Name | Meaning / requester action |
|---:|---|---|
| 0 | STORED | held by this custodian (`IN_CUSTODY`) |
| 1 | DUPLICATE | same as STORED |
| 2 | POLICY_DENIED | custody off: park the custodian 1 h |
| 3 | HOLD | gate closed for this link: park 1 h |
| 4 | NOT_VERIFIED | link peer is not a pinned contact |
| 5 | REFUSED_OBJECT | admission, canonical fields or signer check failed: never again for this object here |
| 6 | EXPIRED | never again for this object |
| 7 | STORE_FULL | node cap: back off |
| 8 | QUOTA | depositor or pair cap: back off |
| 9 | RATE_LIMITED | back off |
| 10 | PERSISTENCE | back off (also any unknown code) |
| 11 | MALFORMED | never again for these bytes |
| 12 | RECIPIENT_NOT_ACCEPTED | park (custodian, recipient) 1 h |
| 13 | CONFLICT | digest held under another tag or recipient: never again |
| 14 | NEXT_HOP_UNKNOWN | HANDOFF_RESULT only: the FORWARD's next hop is not usable here; park (custodian, next hop) 24 h (handoff spec §2) |
| 15 | TAG_UNKNOWN | HANDOFF_RESULT only: the DELIVER's store tag has no live registration; retry with back-off (handoff spec §2) |
| 16 | HOP_REFUSED | HANDOFF_RESULT only: a FORWARD from a link peer that is not the outer signer; never again here (handoff spec §2) |

The letter ops (§10) use codes 0-13 as the base ops do. Codes 14-16 appear
only in HANDOFF_RESULT, the reply to the handoff op 0x07 (§4); a requester
that never sends the handoff ops reads them, like any other unknown code, as
`PERSISTENCE`.

## 6. Custodian rules

A DEPOSIT is stored only if, in order: the gate allows the link (LAN from a
local-network source while WAN custody is off; an Internet or p2p link only
while `FRIEND_CUSTODY_WAN_ENABLED` is set, in debug builds also
`RAVEN_LAB_CUSTODY_WAN=1`, otherwise `HOLD`), the link peer is a pinned
contact, custody is on, the depositor's rate window allows it, the RSO1 obeys
§4, custody admission accepts the envelope (sealed indexed message or ACK
shape, TTL, no pairing material), its hop fields are the canonical outbound
values (`flags 0`, `hint 0`, `hop 8`, `budget 2`, empty ratchet header), the
**depositor is the envelope's outer signer**, the recipient is a pinned contact
other than the depositor and the custodian, and the node, depositor
(512 rows / 16 MiB), pair (128 rows) and byte-rate (2 MiB/min) caps allow it.
Over a cap the deposit is refused; nothing is ever evicted. `STORED` is replied
only after commit.

FETCH returns, in page-token order, the link peer's unreleased, unexpired
objects under the presented tags, after the cursor: at most `max_items` (≤ 16)
and 128 KiB, at least one if any matches. RELEASE hides the named objects from
that recipient; the payload is deleted only at TTL.

## 7. Recipient rules

Each fetched object is accepted under exactly the one session its tag names,
in this order: strict RSO1 decode and tag match → custody admission (expired:
release; from the future: keep) → canonical fields → the sender is a pinned
contact → the sender's outer signature (before any protected load) → room to
owe the ACK → the session-bound certificate → the normal endpoint accept →
history → the ACK, durably owed. Only then is the object released. Store
errors that may clear (clock, forward jump, busy lane) keep the object at the
custodian. An object whose outer signature is not the sender's (someone else
signed it and left it under the tag: a custodian checks only that its depositor
signed what it holds, never whose tag it was left under) is released and blames
nobody: it is no misbehaviour of the custodian (no security event, no strike),
and the recipient logs only how many it released. Page-token order says nothing
about when objects were written: a
recipient takes a page's objects in order of their creation time, each at its
own receive time, so they reach its inbox in the order they were written.

## 8. Compatibility

An older listener closes on RFC1 like any frame that is not RVN1; the requester
counts that as a strike (3 within 1 h park the custodian for 1 h). Older
requesters never send RFC1. No existing frame, envelope, PairInit, RLB1, RSO1
or IPC byte changes.

| Peer | What happens |
|---|---|
| A Phase 2 peer (no RRH1 §12) | It neither sends nor reads CUSTODY_OFFER or CUSTODIAN_TAG; custody with it falls back to the static lists (§2 (b)). Its 0x05 entries still count as announcements (RRH1 §12.3). |
| A custodian built before RFC1 | It closes the link on RFC1: a strike each time, and after 3 strikes within 1 h it is parked for 1 h. |
| A custodian that offers without the WAN bit | It is never dialled for custody over the Internet or p2p; only its LAN routes are used. |
| A custodian without an op of 0x04-0x08 (§4) | It answers that op `UNSUPPORTED`: the op is absent there (for the letter ops the requester caches that for 24 h, §10.5; for the handoff ops it parks handoff at that custodian for 24 h, handoff spec §2), not a strike. Ops 0x01-0x03 at that custodian are unaffected. |
| A custodian with the letter ops, and a recipient without them | The recipient never sends FETCH_LETTERS; its letters expire at the custodian (§10.5). |
| A custodian with the handoff ops, and a requester without them | The requester never sends HANDOFF or TAGS; its plain RFC1 custody there is unchanged (handoff spec §7). |

## 9. Vectors

[`shared-vectors/rvn1/custody/`](../shared-vectors/rvn1/custody/):
`rfc1_deposit_001.json`, `rfc1_fetch_001.json`, `rfc1_fetch_nocursor_001.json`,
`rfc1_release_001.json`, `rfc1_replies_001.json`; for the letter ops (§10)
`rfc1_letter_deposit_001.json` (the REPLY letter of
`letter/ral1_reply_001.json`), `rfc1_letter_fetch_001.json`,
`rfc1_letter_withdraw_001.json`, `rfc1_letter_replies_001.json` and
`rfc1_letter_on_base_listener_001.json` (a listener without the letter ops
answers `UNSUPPORTED`). Rust writes them (`raven_core::friend_custody` tests,
`RAVEN_REGEN_RFC1_VECTORS=1`). The handoff ops' vectors (`rhw1_*`,
`rfc1_tags_*`, `rfc1_handoff_replies_001.json` and `negative/`) are listed in
the handoff spec §8.

## 10. Letters

An RAL1 letter ([`RAVEN_ASYNC_LETTER_V1.md`](RAVEN_ASYNC_LETTER_V1.md)) is a
signed, wrapped PairInit V1 plus the first sealed messages of its session
(LETTER), or the PairResponse plus ACKs that answer it (REPLY). A custodian
holds the exact letter bytes for their recipient, opaquely, as it holds
objects; the ops below are the only place a letter appears on the wire.

### 10.1 Frames

All under version byte 1 (§4); integers big-endian.

```text
requests
  0x04 DEPOSIT_LETTER    recipient[32] || letter_len u32 || letter     frame = 50 + letter_len,
                                                                       letter_len in [776, 65,288]
  0x05 FETCH_LETTERS     has_after u8 (0|1) || after_token[32] (all zero iff has_after = 0)
                         || max_items u8 (1..=16)                      frame = 48
  0x06 WITHDRAW_LETTERS  count u8 (1..=32) || letter_digest[32] x count frame = 15 + 32 count

replies
  0x81 DEPOSIT_RESULT    code u8 || letter_digest[32]                  47 B, terminal (layout of §4)
  0x85 LETTER_ITEM       letter_len u32 || letter                      non-terminal
  0x83 FETCH_END         code u8 || returned u8 || has_next u8 || next_token[32]
                                                                       49 B, terminal (layout of §4)
  0x86 WITHDRAW_RESULT   code u8 || withdrawn u8                       16 B, terminal
```

- `letter_digest = SHA-256(letter)`; `page_token = SHA-256("raven/custody-letter/page-token/v1"
  || letter)` (RAL1 §3). A RELEASE (0x03) may name a letter digest (§10.3).
- Decoding is §4's: a wrong length, a count or `letter_len` out of range,
  `has_after ∉ {0,1}`, a non-zero `after_token` without `has_after` or a
  `max_items` out of range gets the op's terminal reply with `MALFORMED`;
  repeated digests are deduplicated. The letter's own structure is checked
  by admission (§10.2), not by the frame decoder.
- A DEPOSIT_LETTER frame and the LETTER_ITEM that serves it each fit one
  transport message (65,338 and 65,306 bytes at most).

### 10.2 Custodian rules

The letter ops are served only while the custodian's letter gate is open;
otherwise each is answered `UNSUPPORTED` before anything else (§4), as by a
listener built before them. A served letter op first passes §6's link gate
(`HOLD`) and pinned-contact rule (`NOT_VERIFIED`).

A DEPOSIT_LETTER is stored only if, in order:

1. custody is on (`POLICY_DENIED`) and the depositor's rate window allows it
   (`RATE_LIMITED`; the window DEPOSIT uses);
2. **admission, header only:** the strict RAL1 header decode (magic,
   version 1, kind 1 or 2, flags 0, the field rules, `ct_len` against the
   exact length; RAL1 §3), else `MALFORMED`; `created_at <= now + 5 min`;
   `now < expires_at` (else `EXPIRED`); `expires_at <= now + 7 d + 5 min`
   and `expires_at - created_at <= 7 d`. A time refusal other than
   `EXPIRED` is `REFUSED_OBJECT`. The ciphertext is never read;
3. `sender_device` is the depositor (the link peer) and the Ed25519
   signature (RAL1 §3) verifies under it, else `REFUSED_OBJECT`;
4. `recipient_device` equals the DEPOSIT's `recipient`, else
   `REFUSED_OBJECT`; that recipient is a pinned contact other than the
   depositor and the custodian, else `RECIPIENT_NOT_ACCEPTED`;
5. the caps, in the same transaction as the store: letters count toward the
   node (4,096 rows / 64 MiB), depositor (512 rows / 16 MiB) and byte-rate
   (2 MiB/min) caps together with the objects, and at most **32 letters per
   (depositor, recipient)** (`MAX_PAIR_LETTERS`; `QUOTA`); objects keep their
   own 128-row pair cap. Over a cap the letter is refused; nothing is
   evicted.

`STORED` (with the letter digest) is replied only after commit. The same
letter again, held or released, is `DUPLICATE`.

FETCH_LETTERS returns, in page-token order after the cursor, the unexpired
letters held for the link peer (as recipient): at most `max_items` and
128 KiB of letters, at least one if any exists, then FETCH_END. It is served,
like FETCH, while custody is off.

WITHDRAW_LETTERS deletes the named letters **the link peer deposited**;
another party's digest, an unknown or a released one changes nothing.
WITHDRAW_RESULT counts the letters deleted. Nothing of a withdrawn letter is
kept (its depositor signed it, so nobody else can leave it again).

### 10.3 Release and expiry

- RELEASE (0x03) by the authenticated recipient also releases letters by
  digest, exactly as objects: the letter is deleted and only its digest is
  kept, with the hour it would have expired in, so a replay is `DUPLICATE`
  until then. The recipient releases a letter only after its intake
  committed, or when the letter can never succeed (RAL1 §6).
- Expired letters, and letters of a party that is no longer a pinned
  contact, are deleted by the custodian's maintenance, as objects (§6).
- At rest the letters follow the objects' rules
  ([`docs/design/2026-10-at-rest-metadata.md`](../docs/design/2026-10-at-rest-metadata.md)
  section 7.4): in a sealed profile the digest and both parties are keyed
  lookups and the letter is sealed whole.

### 10.4 Requester rules

- A requester sends the letter ops only while its own letter gate is open.
- A depositor leaves the same letter bytes at every custodian it uses and
  withdraws them once every message they carry is settled.
- A recipient asks its home custodians for its letters, runs the RAL1 intake
  (RAL1 §6) on each, and releases each letter only after commit, or at
  once when the letter's code says it can never succeed.

### 10.5 Compatibility

| Peer | What happens |
|---|---|
| A custodian without the letter ops (built before them, letter gate closed, or lab `RAVEN_LAB_CUSTODY_BASE_OPS_ONLY=1`) | `UNSUPPORTED` (`max_version` 1) for each letter op. The requester marks that custodian as without letters for 24 h, moves no message into a letter and uses the base DEPOSIT of the direct copy. Ops 0x01-0x03 are unaffected. |
| A recipient without the letter ops | It never sends FETCH_LETTERS; its letters expire at the custodian. Delivery then happens when both contacts are online (RAL1 §9). |
| Older senders | They never send the letter ops; nothing changes for them. |

## 11. Requester budgets (informative)

Requester-local limits; nothing on the wire depends on them.
- At most 16 DEPOSIT frames and at most 512 KiB of RSO1 per dial. A single
  larger object goes in a dial of its own.
- At most 4 FETCH pages per trigger while the custodian's last path was
  relayed, and 8 otherwise. This keeps a fetch inside a friend relay's
  per-circuit budget.
- When the fetch tags fill more than one FETCH (32 tags each), each trigger
  starts where the previous one stopped, so every tag is visited in turn.
