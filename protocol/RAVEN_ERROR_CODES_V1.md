# RAVEN Error Codes V1

**Version:** 1 (`rvn1`)  
**Status:** Binding for IPC, CLI, and transport-mapped failures  
**Companions:** [`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md), `raven_core::ipc`

## 1. Rules

- Codes are **stable ASCII identifiers** (`SCREAMING_SNAKE`), not free-form English alone.  
- Messages MUST NOT include seeds, private keys, plaintext bodies, or recovery material.  
- Unknown codes → treat as `INTERNAL` at UI layer; do not crash.

## 2. Code registry

| Code | Class | Meaning |
|------|-------|---------|
| `OK` | success | operation completed |
| `IPC_VERSION` | ipc | peer IPC version mismatch |
| `IPC_AUTH` | ipc | peer-cred / socket auth failed |
| `IPC_FRAME` | ipc | malformed / oversized IPC frame |
| `IPC_FORBIDDEN_FIELD` | ipc | request contained prohibited secret field name |
| `POLICY_DENIED` | policy | local policy forbids bridge/store/relay action |
| `ENVELOPE_MALFORMED` | parse | not a valid RavenEnvelopeV1 |
| `ENVELOPE_BAD_SIG` | crypto | sender_authentication failed |
| `ENVELOPE_EXPIRED` | ttl | expires_at reached |
| `ENVELOPE_REPLAY` | replay | message_id already seen |
| `ENVELOPE_HOP` | routing | hop_limit exhausted |
| `ACK_BAD_SIG` | crypto | ACK signature failed |
| `PEER_UNREACHABLE` | net | dial / send failed |
| `PEER_HELLO` | net | internet hello auth failed |
| `STORE_FULL` | store | capacity / rate limit |
| `STORE_NOT_FOUND` | store | no objects for tag |
| `STORE_FORBIDDEN` | store | retrieval auth failed |
| `PREKEY_EXPIRED` | crypto | prekey bundle expired |
| `PREKEY_BAD_SIG` | crypto | prekey signature failed |
| `BLE_REASSEMBLY` | ble | chunk timeout / missing |
| `RATE_LIMITED` | abuse | per-peer rate exceeded |
| `INTERNAL` | other | unexpected local error (no secrets in message) |
| `PEER_RESET` | session reset | the contact lost the session; a re-seal is pending (outbox, transitional) |
| `PEER_RESET_CONFIRM` | session reset | held: no local-network route for automatic re-seal; needs `raven outbox resend` |
| `PEER_RESET_LOOP` | session reset | held: 3 automatic reset rounds in 24 h |
| `PEER_IDENTITY_FORK` | session reset | held: the contact's identity may be in use on two computers |
| `PEER_RESET_UNREACHABLE` | session reset | not sent: every session with the contact was retired and it cannot be reached |
| `PEER_RESET_NO_BODY` | session reset | failed: a body-less (RDAP-sealed) row in a retired session |
| `RESEAL_CAP` | session reset | failed: per-message re-seal cap reached |
| `IN_CUSTODY` | custody | status: a sealed copy is held by a friend (custodian); not delivered yet |
| `CUSTODY_HOLD` | custody | friend custody is gated off for this link |
| `CUSTODY_REFUSED` | custody | the custodian refused the object (admission, canonical fields, signer) |
| `CUSTODY_QUOTA` | custody | depositor or pair cap at the custodian |
| `CUSTODY_UNAVAILABLE` | custody | custodian persistence error (transient) |
| `CUSTODY_MALFORMED` | custody | malformed RFC1 frame or RSO1 |
| `CUSTODY_RECIPIENT_REFUSED` | custody | the custodian does not accept the recipient |
| `CUSTODY_CONFLICT` | custody | the object is held under another tag or recipient |
| `CUSTODY_NEXT_HOP_UNKNOWN` | custody handoff | RFC1 code 14: the FORWARD's next hop is not a pinned, unblocked contact of the first custodian, or it is the depositor or that custodian ([`RAVEN_CUSTODY_HANDOFF_V1.md`](RAVEN_CUSTODY_HANDOFF_V1.md) §2) |
| `CUSTODY_TAG_UNKNOWN` | custody handoff | RFC1 code 15: the DELIVER's store tag has no live registration at the final custodian (retried with back-off) |
| `CUSTODY_HOP_REFUSED` | custody handoff | RFC1 code 16: a FORWARD from a link peer that is not the envelope's outer signer |
| `CUSTODY_HANDOFF_UNSUPPORTED`, `CUSTODY_TAG_CONFLICT` | custody handoff | local: the custodian does not serve the handoff ops (parked 24 h; plain custody unaffected); a store tag registered by two recipients at one custodian (both lose it until it expires) |
| `CUSTODY_UNSUPPORTED`, `CUSTODIAN_NOT_USABLE`, `OWED_ACK_FULL`, `CUSTODY_IPC_REFUSED` | custody | local: old custodian; custodian not a usable pinned contact; owed-ACK back-pressure; RFC1 over IPC dials refused |
| `CUSTODIAN_NOT_OFFERING`, `NO_SHARED_CUSTODIAN`, `MAILBOX_OFF` | custody | local, status only (never a failure): the friend the contact announced does not offer custody to you, or not over the Internet ([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §12.2); the contact collects mail only from friends you have not verified; friend mailboxes are off (`raven custody use on`) |
| `WAITING_FOR_CARRIER`, `CARRIER_FULL`, `NO_SHARED_CARRIER` | letters | local, status only (never a failure): a message moved into a sealed letter ([`RAVEN_ASYNC_LETTER_V1.md`](RAVEN_ASYNC_LETTER_V1.md)) that no friend holds yet: placement is retried (1 h doubling to 24 h, at once after a RELEASE or a fresh capability answer); every custodian refused it for space (QUOTA, STORE_FULL); no custodian is listed by both sides (it goes when the contact is reachable) |
| `APP_CHANNEL_HOLD` | app channel | the app channel (or AgentSign) is not enabled in this build ([`RAVEN_APP_PAYLOAD_V1.md`](RAVEN_APP_PAYLOAD_V1.md)) |
| `APP_BAD_IDENTITY`, `APP_BAD_CONTENT_TYPE`, `APP_BAD_CLIENT_REF`, `APP_BAD_TTL`, `APP_BAD_CURSOR`, `APP_BAD_CONSUMER`, `APP_BAD_DISPOSITION`, `APP_BAD_ACK` | app channel | request syntax, or a type not registered on this node |
| `APP_PAYLOAD_TOO_LARGE`, `APP_PAYLOAD_INVALID` | app channel | body over 49,024 bytes, or bad characters |
| `APP_CLIENT_REF_CONFLICT` | app channel | the same `(peer, client_ref)` was used for another body or type |
| `APP_QUEUE_FULL`, `APP_LANE_BUSY`, `SEND_IN_PROGRESS` | app channel | retry later: 16 in flight to the peer, an earlier message must go first, or another send holds the peer |
| `APP_PEER_BACKLOG` | app channel | retry later: the peer has not acknowledged 128 or more messages on the session; sealing more could put it past the forward-jump limit |
| `APP_PEER_UNREACHABLE`, `APP_PAIR_BUDGET` | app channel | retry later: no usable session and the peer did not answer (nothing sealed), or the automatic pairing budget (4 per peer per 24 h, 60 s apart) is used up |
| `APP_STORE`, `APP_CONSUMER_BUSY` | app channel | app store I/O (transient); another consumer is bound (use takeover) |
| `GROUP_HOLD` | groups | groups are not enabled in this build ([`RAVEN_GROUP_V1.md`](RAVEN_GROUP_V1.md)) |
| `GROUP_NOT_FOUND`, `GROUP_AMBIGUOUS` | groups | local: no group by that name or id, or several match (use more of its id) |
| `GROUP_NOT_ADMIN`, `GROUP_ADMIN_CANNOT_LEAVE`, `GROUP_NOT_MEMBER` | groups | local: only the admin adds and removes; the admin cannot leave; this profile left or was removed |
| `GROUP_TOO_LARGE`, `GROUP_NOT_A_FRIEND`, `GROUP_ALREADY_MEMBER`, `GROUP_BAD_NAME`, `GROUP_BAD_BODY` | groups | local: more than 16 members (or 64 groups); a member to add is no current, unblocked friend; already in; a name of 1-64 characters; a body of 1-8,192 bytes of chat text |
| `GROUP_QUEUE_FULL`, `GROUP_NO_ROUTE` | groups | retry later: group copies would pass the groups' 128 stage entries or a friend's 32 waiting messages; none of the other members is this profile's friend |
| `GROUP_NO_IDENTITY`, `GROUP_STORE` | groups | local: no identity yet; `groups.json` cannot be read or written (nothing is written over a file that cannot be read) |
| `AGENT_SIGN_FIELDS`, `AGENT_SIGN_SENDER`, `AGENT_SIGN_RECIPIENT_NOT_CONTACT`, `AGENT_SIGN_TIME`, `AGENT_SIGN_RATE` | AgentSign | the delegation statement was refused (fields, sender is not this node, recipient not a contact, time window), or the rate window is full |
| `RSR1_MALFORMED`, `RSR1_WRONG_SIGNER`, `RSR1_WRONG_SUBJECT`, `RSR1_BAD_SIGNATURE` | session reset | an RSR1 frame was refused ([`RAVEN_SESSION_RESET_V1.md`](RAVEN_SESSION_RESET_V1.md) §4); debug log only |
| `RRH1_MALFORMED` | route hints | an RRH1 frame was ignored whole ([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §5.1), or one RELAY_OFFER record in a kept frame was dropped (§11.2); debug log only, never a close or a reply |
| `LAN_OFF` | lan | local: `raven lan off` is in effect (no LAN listener, LAN dial or beacon) |
| `LAN_VERIFIED_ONLY` | lan | local: `raven lan verified-only on` is in effect and the contact is not verified (pinned): its LAN link is refused before this node's identity is sent, and no LAN dial to it is made |
| `SUITE_BROKEN`, `SUITE_HELD` | security notices | local: a security notice from the Raven project ([`RAVEN_SECURITY_ADVISORY_V1.md`](RAVEN_SECURITY_ADVISORY_V1.md) §8) marks a suite BROKEN: a link suite (no link is made or taken until Raven is updated) or PairInit version 1 (no new session is made or taken; sessions already open go on); `SUITE_HELD`: the session profile, and the session is held (nothing sealed or taken, nothing changed) |
| `RENEW_RESET_PENDING`, `RENEW_WAIT_PEER`, `RENEW_BACKOFF`, `RENEW_DAILY_CAP`, `REPAIR_COOLDOWN`, `RENEW_NO_ROUTE` | session renewal | local, raven-node's log only (`raven_core::session_renewal::code`): the session reset step owns the contact; after a lapse the contact's smaller key goes first; failed rounds back off; the day's re-pair budget is used up; the last re-pair round was less than a minute ago; no planned route may carry a PairInit (or LAN is off) |

### 2.1 Reasons attached to P2P_UNREACHABLE (local IPC, any-network plan C10)

When a p2p dial fails, raven-node may say why, as a reason block that ash reads to explain the failure
and name a fix (`raven_core::reach_diag`).

- The message of an `IpcResponse::Error` with code `P2P_DIAL` may end in
  `; reach: why=<reason>( <key>=<value>)*` (at most 120 bytes, ASCII).
- The same block (without the leading `; `) may appear in `OutboxItem.why` and in
  `Status.unreachable[].reason`.
- Keys: `why` (a reason below), `me` (a reachability class word: `public`, `mapped`, `relayed`,
  `unreachable` or `unknown`), `relay` (`mine1` or `mine2`: one of this node's own relay slots),
  `heard` and `asof` (an age: `<n>s`, `<n>m`, `<n>h` or `<n>d`, rounded down), `stale` (`1`),
  `src` (`card`).
- The block ends at `;`, `)`, a line end or the end of the text. Clients take the LAST block in a
  text (a multi-route failure joins several texts with `; `).
- The block never carries an address, PeerId, key or name.
- Clients ignore unknown keys and values a key does not take, and treat an unknown reason as no
  reason (they show the text they would show without a block).
- The reasons use local facts only; nothing is probed to find them.
- It is not a peer wire format: nothing is sent to contacts, relays or custodians.
- `lan_off` and `lan_no_answer` (Phase 3) come from raven-node's outbox, not from a p2p dial: they
  appear in `OutboxItem.why` and `Status.unreachable[].reason` only, for a contact no other carrier
  has a route to, and never in a `P2P_DIAL` error.

| Reason | Meaning |
|--------|---------|
| `contact_offline` | the contact's relay answered NO_RESERVATION or CONNECTION_FAILED |
| `relay_asleep` | none of its relays answered |
| `relay_refused` | a relay refused us, or closed our connection within 2 s |
| `relay_off` | the hop protocol is unsupported |
| `relay_busy` | RESOURCE_LIMIT_EXCEEDED |
| `not_admitted` | the contact's node closed our connection within 2 s |
| `both_nat` | no direct address and no relay for the contact, and this node is not reachable either |
| `no_relay` | the same, but this node is reachable |
| `direct_failed` | announced direct addresses did not answer, and there is no relay |
| `no_route` | this computer has no default route: only peers on its own networks can be reached |
| `lan_off` | local: `raven lan off` is in effect (`LAN_OFF`), and the contact has no route on another carrier |
| `lan_no_answer` | the LAN beacon looked for the contact (a message waits for it) and its last 2 rounds got no answer, though the contact was on this network in the last 7 days; no other carrier has a route |

## 3. IPC mapping

`IpcResponse::Error { code, message }` uses codes from this registry. Example: oversized frame → `IPC_FRAME`.
A `P2P_DIAL` error's message may end in a reason block (§2.1).

## 4. Vectors

Negative envelope fixtures under `shared-vectors/rvn1/negative/` map to `ENVELOPE_*`. Rust IPC tests cover `IPC_FORBIDDEN_FIELD` behavior (decode error).
