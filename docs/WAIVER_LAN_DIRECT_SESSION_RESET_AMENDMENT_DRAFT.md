# DRAFT (unsigned): amendment to `WAIVER-LAN-DIRECT-2026-10-07` for session reset (phase 2a)

| | |
|---|---|
| **Status** | **DRAFT, not signed.** Nothing here is in force until the owner signs it. Until then `SESSION_RESET_PRODUCTION_ENABLED` stays `false` and the feature runs only in debug builds with `RAVEN_LAB_SESSION_RESET=1`. |
| **Amends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) and its [P2a amendment](WAIVER_LAN_DIRECT_P2A_AMENDMENT_DRAFT.md) (neither is edited) |
| **Design** | [`design/2026-10-lost-state-recovery.md`](design/2026-10-lost-state-recovery.md) (revision 2), phase 2a: §5-§13, §15, §16 |
| **Wire** | [`protocol/RAVEN_SESSION_RESET_V1.md`](../protocol/RAVEN_SESSION_RESET_V1.md) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-15 |
| **Review by** | Same date as the LAN waiver (2027-01-07) |

## 1. Why an amendment

When a contact loses its Raven state (reinstall, wiped data, restored backup),
messages already sealed to it under the lost session can never be accepted.
Today they wait until they expire and are then given up as superseded or
expired, and the next send to that contact fails with `PEER_PREKEY_RESET` for
up to 30 days unless the user removes and re-adds the contact.

Phase 1 (time-floored prekey ids and the rotation fallback) needs no amendment:
it changes no wire format and no policy and is recorded in the LAN waiver change
log. Phase 2a changes what the covered slice does, so it is written down here.

## 2. What changes on the covered slice

The carrier, the session profile and the peers of the waiver are unchanged.

1. **RSR1 kinds 1 and 2 on LAN links, in dedicated dials only.** A sealer whose
   Message the contact closed the link on may send one signed SESSION_QUERY,
   alone, on the same authenticated link. The contact answers with one signed
   SESSION_STATUS (PRESENT or NO_SESSION). The receiver side is read-only. RSR1
   is never RVN1, never stored and never forwarded.
2. **Automatic re-seal of undelivered plaintext into a new session.** This
   deviates from the P2a amendment's "exact staged bytes, no new seal". It is
   allowed only:
   - on evidence that the old session is dead: a signed NO_SESSION answer to a
     query (E1), or the contact's own valid certificate on a Noise-bound offer
     that differs from the one bound into the session (E2);
   - into a session **this node initiated over a local-network route** (P2),
     unless the user confirmed with `raven outbox resend --contact X`;
   - under the same logical `message_id`, never extending the message's
     original deadline.
3. **PairInit started by the worker.** raven-node's outbox worker may set up a
   new session (PairInit over the contact's local-network LAN route) to re-seal
   into, at most 3 automatic rounds per contact per 24 h, at least 60 s apart.
4. **Seed-compromise trade-off (I3).** An attacker who holds the contact's
   identity seed and sits on the same local network can receive the undelivered
   backlog by answering NO_SESSION. The same attacker already receives every
   future message, so the backlog adds no new class of exposure; outside the
   local network it gets nothing without the user's confirmation. A contact that
   keeps using a session it said it lost is recorded as fork evidence
   (`PEER_IDENTITY_FORK`) and holds automatic handling for 24 h.
5. **Caps** (design §20): 3 automatic rounds per contact per 24 h; 3 re-seals per
   message (at most 4 copies ever exist); query backoff 0 / 1 / 4 / 16 / 60 min
   per (contact, session); 60 s responder young-session grace; 10 min minimum
   remaining lifetime of a re-seal target.

## 3. What does not change

- No new carrier. Internet direct and p2p stay under their own HOLD gates; when
  they open, automatic re-seal stays local-network-only (§2.2).
- No change to `RavenEnvelopeV1`, PairInit, the prekey bundle, the ATSAM
  endpoint transaction or custody admission.
- A retired session still accepts inbound messages and ACKs and still sends
  ACKs; nothing is deleted from the store except the outbox row of a copy that
  was sealed again (its outstanding row stays, so a late ACK still settles it).
- With the gate off the wire is byte-identical to today.

## 4. Preconditions for signing

- The design §21.3 matrix, phase 2a rows, green 5× on macOS and Linux with the
  locked-file backends.
- One manual Keychain run of s05 and s05d on macOS.
- `cargo test`, clippy (1.98 and 1.99) and the fault matrix green with the lab
  switch on and off.
- Owner decisions on the design's open questions (automatic re-seal policy,
  caps, fork handling).

## 5. Signature

Not signed.
