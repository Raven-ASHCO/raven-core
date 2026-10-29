# DRAFT (unsigned): amendment to `WAIVER-LAN-DIRECT-2026-10-07` for the long message horizon (Phase 5a)

| | |
|---|---|
| **Status** | **DRAFT, not signed.** Nothing here is in force until the owner signs it. Until the flip commit, `LONG_HORIZON_PRODUCTION_ENABLED` (`node/crates/raven-core/src/horizon.rs`) stays `false`; debug builds open it with the Lab Test A unlock and `RAVEN_LAB_HORIZON=1`, release builds never read that variable. |
| **Amends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) §2 and §4 item 1 ("24 hours"), and the [P2a amendment](WAIVER_LAN_DIRECT_P2A_AMENDMENT_DRAFT.md) §2 item 1 (design Q4, "no automatic re-seal after expiry"), next to the [session reset](WAIVER_LAN_DIRECT_SESSION_RESET_AMENDMENT_DRAFT.md), [route hints](WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md), [cutoff](WAIVER_LAN_DIRECT_CUTOFF_AMENDMENT_DRAFT.md) and [Phase 3](WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md) amendments (none is edited) |
| **Not covered** | Sealed letters (Phase 5b, `ASYNC_LETTER_PRODUCTION_ENABLED`) and any custody change: their own spec (RAL1), review and the custody waiver's letters section. §2.2 below records the letter-session rule only, for that later flip. |
| **Decision** | Reachability plan D9 as refined by owner decision O5-1 (5a, then 5b; the ratchet stays its own program); O5-2 (deadline 7 days); O5-3 (automatic re-seal under the same message id until the deadline, with receiver deduplication; a rare visible duplicate on old receivers accepted; re-pair on any carrier the contact may use). O5-1 still needs the owner's explicit OK. |
| **Design** | [`design/2026-10-beyond-24h.md`](design/2026-10-beyond-24h.md) §3; plan `docs/roadmap/plans/phase45-design.json` |
| **Wire** | None. Only PairInit V1 exchanges and RVN1 messages and ACKs as today; [`RAVEN_SESSION_RESET_V1.md`](../protocol/RAVEN_SESSION_RESET_V1.md) §6 carries an informative note |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-22 |
| **Review by** | Same date as the LAN waiver (2027-01-07) |
| **Withdrawal** | Set `LONG_HORIZON_PRODUCTION_ENABLED` back to `false` (§6) |

## 1. Why an amendment

Today a message whose envelope ran out is given up, and a send to a contact
with no session left who cannot be reached is NOT SENT, so a contact away for
more than a day gets nothing. Phase 5a keeps such a message until a deadline
of its own and seals it again, automatically and under the same message id,
into a new session once the contact is back. That reverses the P2a rule "no
automatic re-seal after expiry" (design Q4), and lets a message wait 7 days
instead of about one. The LAN waiver §6 makes "extending the slice beyond §2
without a new waiver" a lapse condition, so the change is written down here.

## 2. What changes on the covered slice (§2 amended)

The carrier (Noise XX bound to the identity, the RLB1 offer), the session
profile (`ATSAM/indexed-session/v1`, RVNA1 `0x03` messages and sealed ACKs),
PairInit V1 and the contact gate are unchanged.

### 2.1 Park and re-pair (`LONG_HORIZON_PRODUCTION_ENABLED`)

1. **A deadline per message.** `MESSAGE_HORIZON_MS = 7 days` after the
   message was written, set once and never extended (a clock stepped back
   does not move it). Sessions and envelopes keep their lifetimes: a session
   this node starts lasts 24 hours and an envelope at most `min(session end,
   now + 24 h)`.
2. **Parked, not given up.** A message whose envelope ran out before its
   deadline is parked: a row (recipient, message id, original time, deadline,
   send order) in the session store, the body in the protected outbound
   stage, the history `queued`. The outbox row goes; the outstanding row
   stays, so a late ACK of an earlier copy still settles it. The expired
   session's `K_root` is pruned on time, as today.
3. **A send with no session and no route parks too.** For a current,
   unblocked contact `raven send` parks the message at once and says it is
   queued and until when it can wait; anyone else keeps NOT SENT.
4. **Automatic re-seal under the same message id (Q4 amended).** When the
   contact can be reached again, raven-node seals the parked messages again
   into a usable session (sendable, not letter-class, at least 10 minutes
   left), or first sets up one with an ordinary synchronous PairInit V1, in
   the original send order. Each copy is valid until `min(deadline, session
   end, now + 24 h)`. At most 8 copies of one message, the first included,
   counted in the session-reset re-seal ledger, kept until the deadline.
5. **Re-pair budget.** One per contact, shared with Phase 3's renewal: 4
   rounds per 24 h, 60 s apart, counted only after a verified offer
   answered; held by fork evidence or a reset loop; never a dial while the
   send lock is held. The routes are those the contact may use (owner
   decision O5-3): unverified contacts stay on the local network.
6. **Receiver deduplication.** A receiver with the reset or the horizon gate
   open keeps the first body and stamp of a message id, and records each
   accepted message (keyed, sealed in a sealed profile) until receive time +
   8 days, so a copy whose first instance left the history is marked
   "received again", not shown twice.
7. **The deadline ends it.** Past its deadline a message is given up
   (`expired`) without a dial, and its view says time ran out (with "it never
   left this computer" when no carrier wrote it and no friend held a copy).
   A revoked identity's parked messages are given up (`failed`).

### 2.2 Letter sessions (§4 item 1 amended; in force only with 5b)

Waiver §4 item 1 says this implementation initiates sessions that last 24
hours. That stays true for every session that carries chat. Phase 5b (not
covered here, its own flip) adds **letter sessions**: initiated by this
implementation through a signed-prekey PairInit V1 of up to 7 days (never
beyond the bundle's or the certificate's expiry), carrying at most 16
messages, and **ACK-only at both ends**: no new message is ever sealed into
a letter session, and a peer-initiated session longer than 24 hours is never
a target for chat. Until `ASYNC_LETTER_PRODUCTION_ENABLED` flips under its own
waiver, no such session exists.

## 3. What does not change

- No new carrier, port, frame, TLV or vector; no change to Noise XX, RLB1,
  RRH1, `RavenEnvelopeV1`, PairInit V1, the indexed-session profile or the
  ATSAM endpoint transaction.
- Old peers: a re-sealed copy is an ordinary message under an ordinary
  session. A new receiver drops it if it took the message already; an old
  one may show it twice (see §4 item 3).
- With the gate closed a release build behaves exactly as before: an expired
  message is given up (`expired`), and a send with no session and no route is
  NOT SENT with CP.6's text.
- Logs carry counts only (`horizon: parked=N resealed=M expired=K`): no
  address, key, name or message id.

## 4. Residual risks added (on top of waiver §4)

1. **Messages wait longer on the sender's disk.** A message body may stay in
   the protected outbound stage for up to 7 days instead of about one, so
   whoever obtains the sender's device state in that time reads it. The body
   was always there while queued; only the time grows.
2. **More PairInits.** A contact who comes and goes costs up to 4 re-pairs a
   day (the budget shared with renewal), each one responder claim, far below
   the 32-per-initiator cap.
3. **A visible duplicate on old receivers.** When the first copy arrived but
   its ACK was lost, an old receiver shows the re-sealed copy again (owner
   decision O5-3 accepts this). New receivers drop it.
4. **Late messages.** A message may arrive days after it was written, with
   its original timestamp; the sender's terminal said until when it could
   wait.
5. **Message-id metadata kept longer.** The receiver keeps the ids of
   accepted messages (keyed and sealed in a sealed profile) for 8 days.
6. **Clocks.** The deadline follows this computer's clock; a clock far ahead
   gives a message up early, a clock behind keeps the deadline set when the
   message was written.

## 5. What stays held

- Sealed letters (5b), letter sessions and any custody change.
- Multi-hop delivery and Bluetooth nearby (Phase 5, their own records).
- Friend custody, route hints, Internet direct and p2p under their own
  records; the horizon uses those carriers only while their own gates are
  open.

## 6. Conditions and rollback (§6 amended)

On top of waiver §6 this amendment lapses, and the gate MUST be set back to
`false`, if:

- a deadline is ever extended, or a message is sealed after its deadline;
- a message is sealed more than 8 times, or under a different message id;
- a horizon re-pair exceeds the shared re-pair budget, or holds a send lock
  across a dial;
- a session that carries chat lasts beyond 24 hours, or a letter-class
  session becomes a chat target;
- any of s60, s60b, s60c or s94 is disabled, or fails on any of its runners
  for more than one release.

Rollback is the const set back to `false` in its own commit. Parked messages
then stay where they are and nothing seals them again (they are not given up
by themselves); the receiver keeps deduplicating only while the reset gate is
open. A follow-up commit may give parked messages up as `expired`.

## 7. Evidence before signature (all open until recorded)

- **Unit and store tests** (`raven-core`, `raven-node`, `ash`; the lab clock
  per thread): parking and its crash points, send order, the copy cap, the
  shared budget, revocation, the deadline sweep, a clock stepped back, the
  receiver's inbound-seen table, the gate-closed paths byte-identical.
- **lan_fault_matrix** (`scripts/lan_fault_matrix.py`, macOS and Linux,
  `RAVEN_FAULT_HORIZON=1`) green 5 times: s60 (away 3 days, the sender's node
  up: all 3 once, in order, within 60 s), s60b (past the deadline: expired,
  nothing sent, no PairInit), s60c (clock back then ahead: deadline unchanged,
  one copy), s94 (both away 25 h, gate closed and open); and the regression
  runs: s01-s14 and s30 with every new gate off and with the horizon on, and
  the RSR1 scenarios s05b, s05d and s22 with reset and horizon on.
- **Release inertness:** the release-mode CI step (`inert`, `production_flag`)
  green; `RAVEN_LAB_HORIZON` and `RAVEN_LAB_CLOCK_FILE` ignored.
- **A real row** with two computers, one away for at least three days: to be
  defined in the Phase 5 real-row checklist (none is assigned yet).

## 8. Signature

Not signed.
