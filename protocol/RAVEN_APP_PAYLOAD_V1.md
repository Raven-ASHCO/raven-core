# RAVEN App Payload V1 (`RVNAPP/1`)

**Status:** Draft; **on in release builds since October 2026**
(`APP_CHANNEL_PRODUCTION_ENABLED = true`; on macOS
`APP_CHANNEL_MACOS_UID_ONLY_ACCEPTED = true`, the owner's decision on UID-only
IPC, recorded in `docs/THREAT_MODEL.md` §3.16), not independently reviewed. A
debug build closes it with `RAVEN_LAB_TEST_A=0`. The receive-side rules of §3
are always on (they make a receiver app-safe), and the guard of §3.1 decides
which app payloads a node takes.
**Design:** [`docs/design/2026-10-rdap-app-channel.md`](../docs/design/2026-10-rdap-app-channel.md)
(revision 2).
**Not a wire change:** an app payload is the AEAD plaintext of an ordinary
indexed-session Message. Envelope, route and mailbox tags, StoreObjectV1,
carriers and link admission are unchanged.

---

## 1. Frame

```text
APP_FRAME    = MAGIC SP CONTENT_TYPE SP APP_ID LF BODY
MAGIC        = "RVNAPP/1"
CONTENT_TYPE = LOWER *30( LOWER / DIGIT / "." / "+" / "-" ) "/" NZDIGIT *2DIGIT   ; <= 36 chars
APP_ID       = 32 LOWHEX                ; 16 random bytes, fixed per sender object
BODY         = UTF-8; every char is TAB, LF, CR, or >= U+0020 and != U+007F; may be empty
```

| Limit | Value |
|---|---|
| Header (up to LF) | at most 128 bytes |
| Body | at most 49,024 bytes |
| Whole frame | at most 49,152 bytes (the LAN endpoint text limit) |

## 2. Content types (compiled registry)

| Type | Use | Accepted |
|---|---|---|
| `a2a-request/1` | RDAP task: A2A JSON-RPC `SendMessage` with `raven.*` delegation metadata | gate live |
| `a2a-response/1` | RDAP answer: A2A JSON-RPC response with a `Task` | gate live |
| `test/1` | lab and vectors | lab unlock only |

A sender refuses an unregistered type (`APP_BAD_CONTENT_TYPE`).

## 3. Receiver rules (always on)

Each opened plaintext is classified before commit
([`ATSAM_ENDPOINT_TRANSACTION_V1.md`](ATSAM_ENDPOINT_TRANSACTION_V1.md) §1
step 7):

| Plaintext | Class | Effect |
|---|---|---|
| does not start with `RVNAPP/` | chat | unchanged |
| starts with `RVNAPP/1 ` and parses strictly | app | gate live, type registered and inbox room: committed and stored in the app inbox (never chat history, never a chat UI), then ACKed. Otherwise deferred. |
| any other `RVNAPP/` text | reserved | deferred |

A **deferred** object commits nothing (no receipt, inbox row, ACK intent or
ratchet change) and is accepted later as a fresh object from the same bytes.
The link stays open and other frames in the same dial are unaffected.

### 3.1 The guard: who, what, how big, how often

A receiver takes an app payload (commits it, stores it in the app inbox,
ACKs it) only when every rule below holds; otherwise it defers it as above
(nothing committed; the sender's retries are fresh tries). Chat is never
judged by these rules.

| Rule | Value | Deferred as |
|---|---|---|
| **Who:** the sender (the session-bound certificate's identity key) is a current, unblocked contact whose key this user verified (security words or code checked) | an unverified contact, a stranger, a blocked contact, an unreadable contact book | `app_sender_not_verified` |
| **What:** the content type is registered (§2) | `a2a-request/1`, `a2a-response/1`; `test/1` under the lab unlock only | `app_type_unregistered` |
| **How big:** the frame parses strictly (§1) | body at most 49,024 bytes, header at most 128, frame at most 49,152 | `app_reserved_invalid` |
| **How often:** new payloads of one content type in the last 60 s | at most 30 from one sender device, at most 120 from all senders together (each type counted on its own) | `app_sender_rate` |
| **How many waiting:** the app inbox has room (§3, below) | 16 per sender and type, 128 items and 4 MiB in total | `app_inbox_full` |

A copy of a payload the inbox holds or already handled (the same sender and
message id, or the same sender and app id) is taken without counting against
the rate, so a resend after a lost ACK always settles. The rate windows live
in the receiving process's memory (a restart starts them empty).

The sending node applies the same "who" rule first: `AppSubmit` to a contact
who is not verified is refused with `CONTACT_NOT_VERIFIED` before any dial,
and `AgentSign` signs a delegation only for a verified contact
(`AGENT_SIGN_RECIPIENT_NOT_CONTACT` otherwise). A sender also refuses an
unregistered type (`APP_BAD_CONTENT_TYPE`) and a body over the limit
(`APP_PAYLOAD_TOO_LARGE`), and keeps its own limits: 16 app payloads in flight
per contact (`APP_QUEUE_FULL`), the automatic pairing budget
(`APP_PAIR_BUDGET`) and the AgentSign rate windows (60 tasks a minute; 30
answers a minute per recipient and 120 in total; `AGENT_SIGN_RATE`).

Because a deferred object leaves the receiver's message lane behind, a sender
seals no new app payload on a session while 128 or more of its messages there
follow the newest one the peer acknowledged (half the receiver's
`MAX_FORWARD_JUMP` of 256; chat keeps the other half). It answers
`APP_PEER_BACKLOG` (retryable) instead; any later ACK on the session clears it.

The app inbox deduplicates on `(sender device, message id)` and on
`(sender device, app id)`; tombstones block re-adds for 8 days. An item is
served only to the node's one bound consumer, and is re-checked when served
(contact, block, lineage revocation from the stored session-bound
certificate).

## 4. Compatibility

- A receiver older than this spec shows an app frame as chat text starting
  `RVNAPP/1`. RDAP limits that with an explicit opt-in (`rdap trust … --via
  raven`); there is no signed capability negotiation yet.
- Chat text that starts with `RVNAPP/` is refused by the composer (`NOT SENT`)
  and, from a sender older than this spec, deferred and never ACKed at a
  receiver implementing it.
- `RVNAPP/2` and later are reserved (deferred by v1 receivers).

## 5. AgentSign (identity bridge)

RDAP bound to a node signs its `raven.a2a.delegation.v2` statements through
the IPC op `AgentSign`. The node builds RDAP's canonical bytes
`lp(ctx) ‖ lp(sender) ‖ lp(recipient) ‖ lp(task_id) ‖ lp(kind) ‖
lp(dec(issued_at)) ‖ lp(dec(expires_at)) ‖ lp(sha256(text)) ‖ lp(nonce16)`
(`lp` = 2-byte big-endian length). Every such input starts with
`00 17 "raven.a2a.delegation.v2"`; Raven verifiers refuse that prefix and
Raven signers never produce it, so a delegation signature can never verify as
a Raven object and vice versa. Vector:
[`shared-vectors/rdap/agent_sign/delegation_v2_001.json`](../shared-vectors/rdap/agent_sign/delegation_v2_001.json).

## 6. Error codes

See [`RAVEN_ERROR_CODES_V1.md`](RAVEN_ERROR_CODES_V1.md) §2 (`APP_*`,
`AGENT_SIGN_*`).
