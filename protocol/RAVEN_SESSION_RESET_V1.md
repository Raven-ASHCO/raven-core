# RAVEN Session Reset V1 (RSR1)

**Version:** 1 (`RSR1`, version byte `1`)
**Status:** Draft; **production disabled** (`SESSION_RESET_PRODUCTION_ENABLED = false`,
`SESSION_RESET_RESTORE_PRODUCTION_ENABLED = false`). Lab only: debug builds with
`RAVEN_LAB_SESSION_RESET=1` (kinds 1 and 2) or `=2` (all kinds). Release builds
ignore the switch. Enabling it in production needs the owner-signed waiver
amendment (`docs/WAIVER_LAN_DIRECT_SESSION_RESET_AMENDMENT_DRAFT.md`).
**Audience:** re-implementers of the LAN / Internet / p2p direct dispatcher and
of the sealer's outbox.
**Design:** [`docs/design/2026-10-lost-state-recovery.md`](../docs/design/2026-10-lost-state-recovery.md)
(revision 2), §5-§9 and §14.3.

---

## 1. Purpose

A contact that lost its Raven state (reinstall, wiped data, restore from an
older backup) no longer holds the ATSAM indexed sessions its peers seal under.
Today such a contact closes the link on every message sealed under a lost
session, and the sealer cannot tell this from any other refusal. RSR1 lets the
sealer ask, on an authenticated link, whether the contact still holds the
session of one of the sealer's outstanding objects, and get a signed answer.

RSR1 changes nothing in `RavenEnvelopeV1`, PairInit, the prekey bundle or the
ATSAM endpoint transaction. The receiver's envelope path is untouched
([`ATSAM_ENDPOINT_TRANSACTION_V1.md`](ATSAM_ENDPOINT_TRANSACTION_V1.md) is
unchanged): an envelope for a lost session is refused exactly as before.

## 2. Where RSR1 may appear

- RSR1 is a raw Noise-transport plaintext frame, like RLB1. It is valid **only**
  on an endpoint-authenticated Raven link: LAN direct, Internet direct (RIH1) or
  the p2p direct link.
- It is **never** wrapped in RVN1, stored, queued or forwarded. Custody
  admission refuses it (it is not RVN1).
- Request kinds (1, 3) travel **only alone**, in a dedicated dial. Reply kinds
  (2, 4) travel **only** as the reply to a request on the same link.
- A build with the switch off treats an RSR1 frame like any other frame that is
  not RVN1: `lan frame is not RavenEnvelopeV1`, and the link closes.

## 3. Wire format

All integers are big-endian.

```
Header (78 bytes)
  0   4  magic           "RSR1"
  4   1  version         1
  5   1  kind            1 SESSION_QUERY  2 SESSION_STATUS  3 PREKEY_STALE  4 PREKEY_STATUS
  6  32  signer_device   Ed25519 device key of the frame's author
 38  32  subject_device  Ed25519 device key of the intended recipient
 70   8  created_at_ms   signer's clock: signed, for logs only, never a validity check
Body (kind-specific)
Trailer
 end-64 64 signature     Ed25519(signer, "rvn1/session-reset/v1\0" || bytes[0 .. end-64])
```

| Kind | Name | Direction | Body | Frame length |
|---|---|---|---|---|
| 1 | SESSION_QUERY | sealer → receiver | `envelope_len` u32 (86 ..= 65 373), then `envelope`: the exact packed RVN1 Message or Ack the signer sent the subject | 146 + n |
| 2 | SESSION_STATUS | receiver → sealer (reply) | `status` u8, `echoed_env_type` u8 (1 or 2), `echoed_object` 32, `echoed_mid` 16 | 192 |
| 3 | PREKEY_STALE | initiator → contact (2b) | `offered_bundle_hash` 32, `pinned_len` u32 (1 ..= 8192), `pinned_bundle` (PrekeyBundle JSON signed by the subject) | 178 + n |
| 4 | PREKEY_STATUS | reply (2b) | `result` u8, `echoed_pinned` 32, `current_id` u32 | 179 |

`status`: 1 PRESENT, 2 NO_SESSION, 3 SENDER_STATE_STALE (2b), 4 RECEIVER_STATE_STALE (2b).
`result`: 1 RENEWED, 2 NO_CHANGE_NEEDED, 3 GENERATION_CAP, 4 CLOCK_BEHIND, 5 STALE_OFFER, 6 INVALID_PROOF.

- `RSR1_MAX_FRAME` is the Noise transport plaintext limit (65 519 bytes).
- `echoed_object` is `authenticated_object_digest` of the queried envelope
  ([`RAVEN_BRIDGE_V1.md`](RAVEN_BRIDGE_V1.md)); `echoed_mid` its outer
  `message_id`.
- The signing domain `rvn1/session-reset/v1\0` is not a prefix of any other
  Raven signing domain, and none of them is a prefix of it.

Vectors: [`shared-vectors/rvn1/session_reset/`](../shared-vectors/rvn1/session_reset/)
(`rsr1_session_query_001.json`, `rsr1_session_status_001.json`).

## 4. Decoding and verification

**Decode** (strict):
- fewer than 4 bytes, or another magic → not RSR1;
- `version != 1` or an unknown `kind` → *unsupported*: the listener drops the
  frame without a reply and without closing;
- a wrong length, trailing bytes, a `status` or `result` outside the table, an
  `echoed_env_type` other than 1 or 2, an out-of-range `envelope_len` or
  `pinned_len`, or invalid JSON → `RSR1_MALFORMED` (listener: close; dialer: no
  answer).

**Verify**, in this order, with fixed codes:
1. `signer_device` equals the link's authenticated peer key → else `RSR1_WRONG_SIGNER`;
2. `subject_device` equals the local device key → else `RSR1_WRONG_SUBJECT`;
3. the signature verifies → else `RSR1_BAD_SIGNATURE`.

There is no time-window check. Replies are bound to the dial's Noise channel
and echo an object that is still outstanding at the sealer; requests cause only
read-only work (kind 1) or proof-gated, idempotent work (kind 3).

## 5. Receiver (SESSION_QUERY)

1. The link's peer must be a local contact, else the link closes.
2. Decode and verify (§4).
3. The queried envelope must be RVN1 Message or Ack, carry the asking contact's
   valid outer signature, and a `dest_device_hint` of 0 or the local device's
   hint; otherwise the link closes.
4. The receiver opens its session store. Any store-wide error closes the link;
   it never answers NO_SESSION on an error.
5. **Read-only** session match: for each confirmed, unexpired session with the
   contact, newest first, derive the inbound route tag exactly as the accept
   path does. No receive state, inbox, ACK intent or history changes. A
   session that no longer takes new objects from the contact (the receiver
   closed it after an early security re-key, see the note below) matches
   nothing.
6. Reply one SESSION_STATUS: NO_SESSION when nothing matches, else PRESENT.

**Note (Phase 6b, the early security re-key; behaviour only, no wire
change).** With the security responses and session renewal switches on (lab
only, debug builds), a receiver that met a security event about a contact
renews early and retires the older sessions with that contact for sending
(only while this switch is on too); they take the contact's objects for 10
more minutes, then none. A query about an object sealed in such a session is
answered NO_SESSION once that time is over, so the sealer retires the session
(§6) and re-seals what waited in it instead of keeping a copy that is never
taken. A sealer counts traffic on a session it retired this way as evidence
of a second instance of the contact only when that traffic was made (its
`created_at`) at least the accepted clock skew (5 minutes) after the
retirement: the receiver's earlier ACKs and messages in that session may
still arrive late, through a friend's custody.

## 6. Sealer

- A query is sent only when a dial that carried a Message was closed by the
  contact without a reply beyond its offer. It carries the first such Message,
  alone, in its own dial on the same route. At most one query per user send;
  the background outbox backs off per (peer, session): at once, then 1, 4, 16
  and 60 minutes.
- An answer counts only if it decodes, verifies (§4) and echoes the queried
  object exactly, and that object is still outstanding (not delivered).
- PRESENT changes nothing. NO_SESSION retires the session **for sending
  Messages** — except that a session where the sealer is the responder and that
  was confirmed less than 60 s ago is treated as transient.
- A retired session still accepts inbound messages and ACKs and still sends
  ACKs. Its undelivered Messages are sealed again, under the same logical
  `message_id`, into a newer session the sealer initiated over a local-network
  route, or, after the user confirms (`raven outbox resend`), over any route.
  The receiver deduplicates by `(peer, "in", message_id)`.

**Note (Phase 5a, the long message horizon; informative, no wire change).**
With `LONG_HORIZON_PRODUCTION_ENABLED` (false; lab only, debug builds with
`RAVEN_LAB_HORIZON=1`) a Message whose envelope ran out before its deadline
(7 days after it was written) is parked, and the sealer seals it again, under
the same logical `message_id`, into a newer session once the contact can be
reached ([`docs/design/2026-10-beyond-24h.md`](../docs/design/2026-10-beyond-24h.md)).
Those horizon re-seals share this section's machinery: one re-seal ledger per
message (its copy count, kept until the deadline), the same crash repair, the
re-pair budget per contact, and the receiver's deduplication by
`(peer, "in", message_id)`, which a receiver with either gate open also keeps
outside the chat history's size cap (the inbound-seen table, until the
deadline plus 1 day). RSR1 frames and their rules above are unchanged.

## 7. Compatibility

| Sealer | Receiver | Result |
|---|---|---|
| new | new | automatic recovery |
| new | old / switch off | the receiver closes on the query as on any unknown frame; the sealer keeps today's behaviour |
| old | new | byte-identical to today on the wire (the receiver never sends RSR1 unasked) |
| old | old | unchanged |

## 8. Phase 2b

Kinds 3 and 4, statuses 3 and 4 and stale-ACK retirement are specified in the
design (§14) and stay disabled until their own gate and waiver amendment.
