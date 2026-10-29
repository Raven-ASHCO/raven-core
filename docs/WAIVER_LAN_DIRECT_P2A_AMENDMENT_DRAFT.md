# DRAFT (unsigned): narrowing amendment to `WAIVER-LAN-DIRECT-2026-10-07` for P2a

| | |
|---|---|
| **Status** | **DRAFT, not signed.** Nothing here is in force until the owner signs it. |
| **Amends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) (the signed LAN waiver, not edited) |
| **Phase** | P2a, background outbox worker ([transports design](design/2026-10-transports-internet-mesh-bridge.md) §2.4, §5 row "P2a outbox worker", §7.3) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-08 |
| **Review by** | Same date as the LAN waiver (2027-01-07) |

## 1. Why an amendment

Design §5 says P2a adds no carrier but changes retry timing and envelope
validity (F2), and asks for that to be recorded in the LAN waiver as a
narrowing amendment. The LAN waiver §6 makes "extending the slice beyond §2
without a new waiver" a lapse condition, so the change is written down here.

## 2. What changes on the covered slice

The carrier, the session profile, the objects and the peers of waiver §2 are
unchanged: LAN direct Noise XX + RLB1, PairInit V1, `ATSAM/indexed-session/v1`
RVNA1 `0x03` messages and sealed ACKs, local contacts only.

1. **Envelope validity: 1 h becomes `min(session end, now + 24 h)`.** One named
   constant, `raven_core::outbox::ENVELOPE_VALIDITY_MS`, used by `raven send`
   (messages) and the daemon (ACKs, `SealUnderSession`). Sessions this node
   initiates last 24 h, so in practice a message stays deliverable until its
   session ends. No automatic re-seal after expiry (design Q4): an expired
   message is abandoned and shown as `expired` (not delivered).
2. **Background retry.** `raven-node service` runs a sixth supervised task, the
   outbox worker. It re-sends the exact staged bytes of the session store's
   outbox (no new seal, no new key, no second queue) until the first verified
   ACK or expiry: backoff 5 s doubling to 10 min, ±50 % jitter (never above
   10 min, never below 5 s), scheduled on the monotonic clock (a wall-clock
   step moves only the expiry check), plus immediate tries on `raven send`'s
   kick, on listener start, when an authenticated contact connects (at most
   one such dial-back per contact per 60 s), and when this machine's own
   addresses change (IPv4 addresses or IPv6 prefixes, loopback and link-local
   ignored; acted on after 2 s of quiet, at most once per 10 s, the gap
   doubling to 5 min while changes keep coming; each contact due within 5 s).
   The backoff count starts over at 0 (the next wait is 5-7.5 s again, not up
   to 10 min) for a contact's queued messages and owed ACKs on a user kick
   (`raven send`, `raven outbox retry`/`cancel`, a reset step), on a verified
   ACK from that contact on the worker's own dial, and on that contact's
   authenticated inbound link (at most once per 10 min per contact); such a
   change of this machine's addresses starts it over for every queued object
   and owed ACK. A write without an ACK never starts it over, and a restart
   changes nothing else (attempts, refusal counts, blocked routes, the
   once-only reset retry). On a retry, the route that took a message without
   an ACK coming back goes last among that message's LAN routes (order only:
   no route is added or dropped and each is still dialled at most once per
   attempt; in memory, back to plan order on a restart or a change of this
   machine's addresses). It takes `raven send`'s per-peer lock for its store
   work only, never across a dial, and runs the same ACK verification
   (including "the ACK names this message"). A message the store
   refuses only because the clock moved is kept, not expired; a row this node
   holds no message body for (sealed by `SealUnderSession`) is held, never
   deleted; a message on an older session is given up as superseded only after
   3 consecutive refusals spread over at least 2 minutes. A wake from sleep
   (between two checks due 5 s apart, the wall clock ran at least 30 s further
   than the monotonic clock, or the monotonic clock itself ran at least 30 s
   past the 5 s) counts as a change of this machine's addresses everywhere in
   this item, even when no address moved, and is not held by the 10 s to
   5 min gap.
3. **ACKs we owe (F8).** An ACK whose reply could not be written on the inbound
   link is pushed to the sender over the sender's contact routes, exact bytes,
   in the same dial as that contact's due messages and only after the same
   contact, block and revocation checks. An ACK that arrives on an inbound link
   now also settles the outbox row and updates the chat history, and the
   history never goes back from `delivered` to `queued`.
4. **Fail closed.** A contact that is removed or blocked gets nothing (its
   messages are held, then expire); a revoked lineage has its undelivered
   messages abandoned (history `failed`). Nothing is ever sent to a key that is
   not a current, unblocked contact.
5. **Unverified contacts stay on the local network.** A contact whose
   fingerprint is not pinned is dialled, by `raven send` and by the worker
   through one core function, only when every address its LAN route resolves to
   is loopback, private (10/8, 172.16/12, 192.168/16), link-local (169.254/16,
   fe80::/10) or unique-local (fc00::/7); CGNAT (100.64/10) and public addresses
   are refused before anything is dialled. The LAN listener treats an unverified
   contact connecting from outside those ranges exactly like a stranger. Pinned
   contacts are unrestricted.

Outside this waiver's scope, for context only: the worker retries Internet
direct only when `INTERNET_DIRECT_PRODUCTION_ENABLED` (still `false`) or the
debug lab unlock allows it, and only for a verified (pinned) contact (owner
decision 2026-10-08).

## 3. Why this narrows rather than widens

- Same carrier, link class, objects and peers as waiver §2.
- Every retry carries byte-identical objects; the receiver deduplicates them
  (an exact duplicate gets the same ACK back, errata rule 5), so a retry can
  neither create a second message nor burn a ratchet index.
- The frozen protocol already allows the longer validity: the endpoint
  transaction requires only `expires_at <= session expires_at_ms`
  ([`ATSAM_ENDPOINT_TRANSACTION_V1.md`](../protocol/ATSAM_ENDPOINT_TRANSACTION_V1.md),
  processing step 4) and the store caps any envelope at 7 days
  (`MAX_ENDPOINT_ENVELOPE_LIFETIME_MS`). No frozen protocol file fixes the old
  1 h value (checked: `protocol/*.md`, `docs/PROTOCOL_FREEZE_HASHES_V1.md`), so
  no frozen file and no freeze hash changes.

## 4. Residual risks added (on top of waiver §4)

1. **A sealed envelope stays acceptable longer** (up to its session's end,
   about 24 h, instead of 1 h). On LAN direct it only ever travels inside Noise,
   and the receiver accepts each object once (store dedup and replay checks), so
   a leaked copy (a disk image of the sender's outbox, say) can at most deliver
   the same message once, later. The in-session no-FS risk (waiver §4.1) is
   unchanged.
2. **More connection attempts, and the dialer names itself first.** While a
   contact is offline, the daemon dials its saved LAN address on the backoff
   schedule for up to a day. A LAN observer learns that this node has something
   for that address. Whoever answers at that address, the contact or a
   different host, receives the dialer's signed bind (its RAVEN key and Noise
   static key) before the dialer has verified the responder: the responder is
   contact-gated, so one side has to name itself first, and this amendment does
   not change the protocol. A different host at a stale or spoofed address
   therefore learns which RAVEN identity is trying to reach that address, from
   which source address and how often. It receives no frame (no message, no
   ACK): frames are sent only after the responder's bind proves the expected
   key. To bound the repetition, after `WRONG_IDENTITY` (another key answered)
   or `LINK_NOT_ACCEPTED` (the responder closed before identifying itself) the
   worker stops retrying that object on that route; with no route left the
   object is held with that code, which `raven outbox status` shows, until
   `raven outbox retry`, a changed contact address or a service restart clears
   it. A message queued later, and an owed ACK, may still try that route. The
   backoff restarts of §2 item 2 add dials only after a user action, a
   delivery, the contact itself connecting, or a change of this machine's own
   addresses. For a contact that dials in every minute while our dial-backs
   fail (NAT, a port we do not know), that is about 15 dials per 10 min
   instead of about 11. A change of this machine's addresses brings the next
   attempt forward (within 5 s) and restarts its backoff, so a flapping link
   can raise the dial rate to a contact with queued messages to at most about
   7 rounds per 5 min; a wake from sleep does the same once per sleep of
   30 s or more; nothing else about what is dialled or sent changes.
3. **A message may arrive late** (hours after it was typed), with its original
   timestamp. The terminal says so when it is queued ("raven-node keeps trying
   until HH:MM UTC").
4. **Background work while the user is away.** The worker reads the same session
   store and chat history the daemon already reads on receive (no new secret,
   no new code identity, no new macOS Keychain item; design §6.3).

## 5. Compensating controls

- Contacts only, checked again before every attempt, fail closed on an unreadable
  contact book or block list.
- The same lock and the same ACK check as `raven send`; no network I/O inside a
  session-store transaction.
- Logs carry counts and fixed codes only (no key, address or message id).
- `raven outbox list|status|retry|cancel` shows and controls every queued object;
  IPC carries identifiers, states and counts only, never content.

## 6. Evidence

- Unit tests (`raven-node` `outbox::tests`, `raven-core` `outbox::tests`):
  backoff bounds and the 5 s floor, monotonic scheduling, rebuild after
  restart, cancel on ACK (including an ACK that arrived on another link),
  expiry and clock steps, rows with no local body, removed / blocked / revoked
  contact, shared lock not held across dials, owed ACKs in one dial, route
  blocking after `WRONG_IDENTITY` / `LINK_NOT_ACCEPTED`, dial-back rate limit,
  IPC without plaintext, both gates, the verified-contact rule and the
  local-network rule; backoff restarts: on a user kick only (not a custody or
  app kick), during an attempt in flight, on a verified ACK (not on a write
  without one, nor on an ACK that came another way), on an inbound link at
  most once per 10 min, with refusals, blocked routes and attempts untouched;
  on a network change, every backoff restarted with each contact due within
  5 s (its objects in one dial), an attempt in flight included, blocks and
  refusals kept, and nothing without a running worker; the silent-route
  rotation: only a write without an ACK moves it, it never adds or drops a
  route, one route is dialled as before, a second LAN address is tried next,
  a lost ACK comes back on the next route as a duplicate (one inbox row), and
  a network change returns plan order.
- Network change (`raven-node` `netwatch::tests`, `custody::tests`): the first
  view is a baseline; loopback, link-local and multicast churn never counts;
  an IPv6 privacy rotation inside its prefix is no change; a burst is one
  decision (2 s quiet, at most 10 s); changes are spaced 10 s doubling to
  5 min and back after 10 min of calm; losing every network retries nothing; a
  reopened watcher is compared with the kept baseline; a failed watcher is
  never polled again and is reopened with backoff; the lab event file is
  inert in release builds; custodians become due with their parks kept; a
  wake from sleep is one change even when no address moved, merges with the
  address burst after it and is not held by the gap; the wake check sees
  both clock kinds (a stopped monotonic clock, a jumped one), ignores a wall
  clock stepped back and is seeded again after a reopen backoff.
- Harness C4 (`node/crates/raven-node/tests/carrier_matrix.rs`), run by the CI
  jobs on ubuntu, macOS and Windows: A's service killed after staging, B down a
  few seconds, both restarted; delivered with no new `send`, exactly once.
- Harness C11 (same file, same three CI jobs): A's netwatch fed by the debug
  lab event file, B's on the real OS watcher (which must start on each OS);
  with B down, one change on A gives exactly one `network changed` line and an
  immediate retry on a fresh backoff, and the message is delivered exactly once
  when B is back. `scripts/lan_fault_matrix.py` s33 (`RAVEN_FAULT_NETWATCH=1`)
  runs the same flow with real `ash` and `raven-node` processes; s34 switches
  the network while 5 messages to 2 contacts wait (all delivered within 30 s,
  exactly once, in order), then repeats it for a wake from sleep, and s34c is
  the same switch without the change (the backoff alone).
- Still to record (owner): the stage-12 slice for LAN on physical machines
  (kill/relaunch, loss, duplicate, expiry), design §5 row P2a.

## 7. Withdrawal

Revert to the pre-P2a behaviour: set `ENVELOPE_VALIDITY_MS` back to
`60 * 60 * 1_000` and remove the `outbox` supervisor from `Commands::Service`
(`node/crates/raven-node/src/main.rs`). `raven send` then retries queued
messages only on the next send, as before.

The LAN waiver's own withdrawal (`LAN_DIRECT_PRODUCTION_ENABLED = false`) stops
all LAN direct traffic, the worker's included: the worker reads
`lan_direct_live_enabled()` before every attempt and then plans no LAN route,
and with the Internet gate also off it dials nothing at all. It does not by
itself undo this amendment: the 24 h validity constant stays, the worker keeps
its local bookkeeping (expiry, cancel, history), and a debug build with the lab
unlock (`RAVEN_LAB_TEST_A=1`) still dials LAN. A complete withdrawal is both
steps.

## 8. Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Protocol owner | | | **unsigned** |
