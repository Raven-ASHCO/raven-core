# RAVEN Group V1 (`RVNGRP/1`)

**Status:** Draft; **production disabled** (`GROUPS_PRODUCTION_ENABLED = false`,
which also needs `LONG_HORIZON_PRODUCTION_ENABLED`). Lab unlock: debug builds
with `RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_HORIZON=1` and `RAVEN_LAB_GROUPS=1`
(`raven_core::group::group_live_enabled`). Release builds ignore the switches.
**Design:** [`docs/design/2026-10-groups.md`](../docs/design/2026-10-groups.md).
**Reference code:** `raven_core::group` (Rust).
**Not a wire change:** a group frame is the AEAD plaintext of an ordinary
indexed-session Message between two friends. Envelope, route and mailbox
tags, StoreObjectV1, carriers, link admission, custody and the ACK are
unchanged.

---

## 1. Frame

```text
GROUP_FRAME = MAGIC SP KIND LF JSON
MAGIC       = "RVNGRP/1"
KIND        = "state" / "msg" / "receipt" / "leave" / "sync"
JSON        = one JSON object (RFC 8259, UTF-8), exactly the fields of §2 for KIND
```

| Limit | Value |
|---|---|
| Header (up to LF) | at most 16 bytes |
| Whole frame | at most 49,152 bytes (the LAN endpoint text limit) |
| Members | 1 to 16 (the admin included) |
| Body (`msg`) | 1 to 8,192 bytes |
| Name | 1 to 64 characters; label 0 to 64 |

Binary values are lowercase hex: a group id or message id is 32 hex
characters (16 bytes), a key 64 (an Ed25519 identity key), a signature 128.
Integers are JSON numbers (`epoch` 1 to 2³²−1; times in Unix milliseconds,
at most 2⁵³−1). A receiver refuses unknown fields, missing fields, uppercase
hex and duplicate keys in `members` or `relay`.

A group's id is bound to its admin: `group = SHA-256(lp("rvn1/group-id") ||
admin[32] || salt[16])[..16]`, where `salt` is 16 random bytes the admin
chose when it created the group and every `state` carries. A `state` whose
`group` is not that of its `admin` and `salt` is not well formed: nobody but
the admin can sign a roster for its group's id (2026-10-29: a member could
claim a group's id at a friend before the real admin and have the real
roster refused for good).

Text: `name` and `label` hold no control character (nothing below U+0020,
no U+007F) and no leading or trailing space; `body` follows the endpoint
text rule (TAB, LF, CR or any character at or above U+0020 except U+007F)
and is not only white space.

## 2. Kinds

| Kind | Fields | Sent by, to |
|---|---|---|
| `state` | `group`, `salt`, `epoch`, `name`, `admin`, `issued_ms`, `members` (`[{"key","label"}]`, admin first), `sig` | the admin, to every member (and to members it removed) |
| `msg` | `group`, `id`, `epoch`, `from`, `sent_ms`, `body`, `sig`, `relay` (keys) | the author to members who are its friends; a forwarder to one member |
| `receipt` | `group`, `of` (a message id), `epoch`, `from` (the receiver), `to` (the author), `at_ms`, `sig`, `relay` (keys) | a member that got a forwarded copy, to its forwarder |
| `leave` | `group`, `epoch`, `from`, `at_ms`, `sig` | a member, to the admin |
| `sync` | `group`, `epoch` (the roster epoch the sender holds) | a member, to the admin |

`relay` is not signed: it is an instruction from the frame's signer to the
one friend it sealed that copy to, authenticated by their pairwise session.

## 3. Signatures

Ed25519 by the named identity key over the bytes below (strict verification,
as every Raven signature). `lp(x)` is a 2-byte big-endian length then `x`;
`be16`, `be32`, `be64` are big-endian integers.

### 3.1 `state`, by `admin`

```text
lp("rvn1/group-state") || group[16] || salt[16] || be32(epoch) || admin[32] || be64(issued_ms)
  || lp(name) || be16(n) || n × ( key[32] || lp(label) )
```

### 3.2 `msg`, by `from`

```text
lp("rvn1/group-msg") || group[16] || id[16] || be32(epoch) || from[32]
  || be64(sent_ms) || SHA-256(body)[32]
```

### 3.3 `receipt`, by `from`

```text
lp("rvn1/group-receipt") || group[16] || of[16] || be32(epoch) || from[32]
  || to[32] || be64(at_ms)
```

### 3.4 `leave`, by `from`

```text
lp("rvn1/group-leave") || group[16] || be32(epoch) || from[32] || be64(at_ms)
```

Every input starts with `00 10`, `00 0e` or `00 12` and an `rvn1/group-`
string, so none can carry the AgentSign prefix
(`RAVEN_APP_PAYLOAD_V1.md` §5) or another Raven format's domain.

## 4. Receiver

### 4.1 Before commit (always on)

Each opened plaintext is classified before commit
([`ATSAM_ENDPOINT_TRANSACTION_V1.md`](ATSAM_ENDPOINT_TRANSACTION_V1.md) §1
step 7), next to the app frame rules of
[`RAVEN_APP_PAYLOAD_V1.md`](RAVEN_APP_PAYLOAD_V1.md) §3:

| Plaintext | Class | Effect |
|---|---|---|
| starts with `RVNGRP/1 ` and parses strictly (§1, §2) | group | gate live: committed, then §4.2, then ACKed. Gate closed: deferred |
| any other `RVNGRP/` text | reserved | deferred |

Deferred: nothing is committed (no receipt, inbox row, ACK intent or
ratchet change); the link stays open and the sender may retry the same
bytes. A committed group frame never reaches chat history or a chat view.

### 4.2 After commit

The *carrier peer* `P` is the identity of the session-bound certificate of
the session the copy arrived on. Ingest is idempotent: a frame seen again
changes nothing and is still ACKed. An invalid frame (a bad signature, a
stranger, a removed member) is ACKed and dropped, never shown.

**`state`**: verified under `admin`, with `group` the id of `admin` and
`salt` (§1). For an unknown group it is accepted
only when `P` is `admin` and the receiver is in `members`. For a known group
`admin` must equal the group's admin and `epoch` must be newer than the
roster held; then it replaces it. A receiver not in the new `members` stops
taking and sending messages for the group. An equal epoch with other bytes
is ignored.

**`msg`**: accepted when the group is known and active, `from` is in the
roster held, the signature verifies under `from` and the pair (`from`,
`id`) is new for the group (a message is known by its author and its id:
another author's message with the same `id` is a different message), and
`sent_ms` is within the last 7 days (the message horizon) and at most one
day ahead of the receiver's clock. A receiver keeps the (`from`, `id`) of
every message it took until its `sent_ms` is 7 days old (at most 8,192 per
group; a group at that many takes no new message until some expire), so a
message cannot be replayed as new. When `from` is not in the roster but `epoch` is newer than the
roster, the frame is held (§4.3). A frame for an unknown group is held too.

- **Forward** (only when `P` = `from`): for each key `T` in `relay` that is
  in the roster, is not the receiver and is one of the receiver's friends,
  the receiver seals the same frame with `relay` = `[]` to `T`, once per
  `(from, id, T)`. At most 16 forwards of one author's messages wait per
  group; more are not taken on. Every copy a receiver parks (forwards,
  receipts and rosters too) counts against its group share of the
  outbound stage, and an own copy dropped from its pending work fails its
  line.
- **Receipt** (when `P` ≠ `from`): the receiver signs a `receipt` with
  `of` = `id`, `to` = `from`, and seals it to `P` with `relay` = `[from]`.
- A copy that did not come straight from its author is never forwarded.

**`receipt`**: when `to` is the receiver: verified under `from` (a member),
it marks `from` as having message `of`. Otherwise, only when `P` = `from`
and `to` is in `relay`, the roster and the receiver's friends: forwarded to
`to` with `relay` = `[]`, once per `(to, of, from)`.

**`leave`**: taken by the admin only, from a current member, verified under
`from`; the admin then sends the next roster without `from`.

**`sync`**: taken by the admin only, from `P` a current or removed member;
the admin answers with its roster, at most once per member and group every
10 minutes.

### 4.3 Held frames

A held frame waits for a newer roster: at most 64 per group and 32 for
groups not known yet, each for at most 7 days. A receiver holding one asks
the admin with `sync` (at most once per group per hour). Every newer roster
stored retries the held frames.

## 5. Sender

- The author seals a `msg` only to members who are its own friends; it puts
  the others in `relay` in the copy to the admin when the admin is one of
  those friends, else in every copy.
- Only the admin sends `state`; it adds only its own friends.
- Every copy is an ordinary indexed-session Message with the 7-day message
  horizon; the pairwise ACK of a copy is that member's delivery receipt.

## 6. Compatibility

- A receiver older than this spec shows a group frame as chat text starting
  `RVNGRP/1`. Groups are lab-only.
- Chat text that starts with `RVNGRP/` is refused by the composers.
- `RVNGRP/2` and later are reserved (deferred by v1 receivers).

## 7. Error codes

See [`RAVEN_ERROR_CODES_V1.md`](RAVEN_ERROR_CODES_V1.md) §2 (`GROUP_*`).
