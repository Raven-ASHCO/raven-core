# DRAFT owner waiver amendment: attack sensing and responses (Phase 6b design A)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `SECURITY_EVENTS_PRODUCTION_ENABLED`,
> `SECURITY_RESPONSES_PRODUCTION_ENABLED` and `SUITE_FLOOR_PRODUCTION_ENABLED`
> (`node/crates/raven-core/src/security_gate.rs`) stay `false` until the owner
> signs a final copy for that gate (renamed to
> `docs/WAIVER_SECURITY_SENSING_<date>.md`), the preconditions in §7 are met,
> and the flip is applied as its own reviewed commit. Debug builds open them
> with `RAVEN_LAB_SECURITY_EVENTS=1`, `RAVEN_LAB_SECURITY_RESPONSES=1` and
> `RAVEN_LAB_SUITE_FLOOR=1`, each with `RAVEN_LAB_TEST_A=1`; release builds
> never read them.

| | |
|---|---|
| **Waiver ID** | `WAIVER-SECURITY-SENSING-<date>` (to be assigned on signature) |
| **Gates** | `SECURITY_EVENTS_PRODUCTION_ENABLED = false`; `SECURITY_RESPONSES_PRODUCTION_ENABLED = false` (sits on events); `SUITE_FLOOR_PRODUCTION_ENABLED = false` (sits on events). Each is flipped and signed on its own (§8) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) for what the gates change on the live LAN slice (a sealed ledger file, what the listener refuses, when a session renews, which path is tried first, which learned address is kept). That record is not edited. On a carrier that is held (Internet direct, p2p and friend relays, friend custody, letters, handoff, nearby), the same sensing starts only when that carrier's own gate is live, under its own record |
| **Not covered** | P6.32's attack harness (tampering proxy modes, C80-C85, s110-s114: set aside by the owner, not built); any automatic block, unpin or removal of a contact (never: OD6b-6); sharing events with anyone (never: no telemetry); the padding and knock events beyond those named here ([`WAIVER_TRAFFIC_ANALYSIS_DRAFT.md`](WAIVER_TRAFFIC_ANALYSIS_DRAFT.md)) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-24 |
| **Decision proposed** | Turn on, one gate at a time, local attack sensing (the `SEC_*` events, the sealed security ledger, `raven security`, the app's SEC overlay), then the automatic responses R1-R8, then the session-profile floor once a second profile exists (owner decisions OD6b-1 to OD6b-7, recommended options) |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set the gate's const back to `false`. Nothing is noted, written or answered any more and every refusal is as before the flip; a `security_events.sqlite` and `capability_floor.json` already written stay sealed and unread, and `raven erase` still deletes them |
| **Design** | `docs/roadmap/plans/phase6-design.json`, design P6b-A (sensing points, responses R1-R9, UX); the code registry [`SECURITY_EVENTS.md`](SECURITY_EVENTS.md) |
| **Wire** | None: the codes are local and never sent; no frame, field, error code, vector or freeze hash changes (R7 answers with the existing `RATE_LIMITED`) |
| **Threat model** | [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.3, §3.5, §3.10, §3.11, §3.14, §3.15 |
| **User docs** | `raven security --help`; [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) section 10 |
| **Real rows** | an unpublished test checklist: R30 (waits for P6.32) |

## 1. Why a waiver is needed

LAN direct is live in release builds under `WAIVER-LAN-DIRECT-2026-10-07`,
whose §6 makes "the slice is extended beyond the scope in §2 without a new
waiver or review" a lapse condition. Once these gates are live, the covered
listener refuses sources it refused nothing to before (R1), sessions renew
earlier than their schedule (R2, R3), the planner orders a contact's routes
differently for a while (R4), a learned address is forgotten (R5), and a new
sealed file appears in every sealed profile (the ledger). None of it adds a
carrier, a port or a byte on the wire, but each changes what the live slice
does, so it is written down before any flip.

## 2. Scope (exactly what each gate turns on)

### 2.1 `SECURITY_EVENTS_PRODUCTION_ENABLED`

1. **Sensing.** raven-node (`raven-node/src/security.rs`), raven-core
   (`security_sense.rs` and the modules it names) and ash note the kinds of
   the registry ([`SECURITY_EVENTS.md`](SECURITY_EVENTS.md)): link-layer
   failures and refusals (1-11), a contact's refused objects, keys and
   capabilities (20-35), carriers' misbehaviour (40-49), this computer's own
   rollback and failed unlocks (60, 61), and the update checks (70-77). Every
   classifier matches every error variant without a wildcard, so a new error
   does not build until someone decides whether it is an event.
2. **The ledger.** `security_events.sqlite`, keyed and sealed from its first
   version (at-rest design §7.7), only in a sealed profile: at most one write
   per kind and subject a minute; network sources only as a count per kind
   and day; subjects are contact, custodian or relay keys only; no IP
   address, port, message id, plaintext or stranger key, ever; counts and
   resolved alerts kept 30 days. The capability high-water marks
   (`capability_floor.json`, sealed, at-rest kind 11) are recorded under this
   gate too (R9's recording half).
3. **What the person sees.** `raven security` (list, `explain`, `resolve`,
   `clear`, `--json`), a SECURITY section in `raven status` while an alert or
   warning is open, a `security` row in `raven doctor`, one note on `raven
   send` to a contact with an open Alert (the send goes ahead), and in the
   full-screen app the header chip, the friend badge and banner, SEC, NET's
   Security group and the friend page's row. English only; the harmless
   explanation first; never an accusation; every Alert ends with one concrete,
   reversible action; "compare security words", never a digits-only code.
   A match in `raven contact verify` resolves that contact's rows.
4. **Nothing leaves the computer.** No event, count or ledger row reaches a
   frame encoder, an IPC answer other than the local `Status`, or a log line
   with a key or an address.

### 2.2 `SECURITY_RESPONSES_PRODUCTION_ENABLED` (on top of events)

Each response is bounded, ends by itself and writes its alert's action code;
none blocks, unpins or removes a contact (a source scan checks it).

| Response | Trigger | What it does | Bound |
|---|---|---|---|
| R1 penalty box | strikes from a network source at the LAN and Internet listeners, the p2p peer gate's inbound refusals, the beacon answerer | 16 strikes in a minute ban the source for 60 s, doubling up to 1 h; the listeners keep one probation connection per 10 s, and a contact that authenticates on it clears the source | memory only, one per process, at most 4,096 sources; loopback never banned; keys (the p2p responder's, nearby pipes') never struck |
| R2 early re-key | 20 or 22 about a contact, or its third 23 within an hour | the next live link renews the session early; older sessions retire for sending (cause 7) and take the contact's objects for 10 more minutes | one per contact per 6 h, inside the re-pair budget of 4 a day; `node_policy.security_auto_rekey` (default on) |
| R3 rollback recovery | 60 (this disk's session state rolled back, or sealed bytes that fail) | rotates this computer's prekey and asks an early re-key of every contact with a live session | once per 6 h |
| R4 path demotion | 1 at Suspicious | that contact's routes over that carrier go last on this network, behind friend custody when custody may carry the message | 10 minutes, memory only |
| R5 forget an address | 29 at Suspicious | forgets the learned LAN address another key answered at (`lan_seen` and the learned LAN route) | the address saved in the contact book stays |
| R6 park a custodian | the third of 40, 41 or a custodian's 47 within a day | the custodian is not used for a day; `raven outbox retry` lifts it | one day |
| R7 throttle a depositor | the tenth refused object (44) from one depositor within an hour | the custodian answers `RATE_LIMITED` to its deposits | one hour, memory only |
| R8 relay demotion | 45 above half of a relay's last 10 relayed dials, or 46 at Suspicious | the relay goes last in circuit order, never out | one hour, memory only |

### 2.3 `SUITE_FLOOR_PRODUCTION_ENABLED` (on top of events)

R9's refusing half: a session profile offered below a contact's floor is
refused (`require_profile`). Profile 1 (`ATSAM/indexed-session/v1`) is the
only profile today, so nothing is refused yet; the gate matters only once the
next profile program ships a second one ([`design/2026-10-suite-retirement.md`](design/2026-10-suite-retirement.md)).
Only `raven contact verify`, after a security-words match and a typed
`accept`, lowers a floor; removing the contact forgets it.

## 3. Holds

- P6.32 (the attack harness) is set aside by the owner (2026-10-23): no
  tampering proxy, no misbehaving-node lab switch, no C80-C85 or s110-s114.
- The false-positive budget (OD6b-2: zero Alerts and no ban of a contact over
  the whole default fault matrix and carrier matrix with these gates on) has
  not been run as one measured pass; P6.26 left the harness runs with the
  responses gate on to P6.32.
- "Pause sending" (the app's P) is the person's own choice, never automatic;
  it is read whatever the gates.

## 4. Residual risks accepted

1. **Bugs look like attacks.** Detection cannot tell malice from a bug, so
   every automatic answer must be safe when the event was a bug: nothing is
   deleted, no contact is blocked, and alert texts say "this can happen when
   ...". A false Alert still worries a person; the budget in §3 is unmeasured.
2. **What cannot be detected:** purely passive listening (a recording sends
   nothing), drop-only attackers (they look like a bad network: Raven says
   "could not reach", not "attack"), a fully compromised contact device (it
   behaves exactly like the contact), and anything on a held carrier.
3. **The penalty box is local and forgetful.** A flood from many addresses
   (each its own source; IPv6 grouped by /64) is not one source; bans live in
   memory and end at a restart; a stranger under 16 strikes a minute is never
   banned. A contact behind a banned shared address waits for the probation
   connection (one per 10 s).
4. **The ledger is a record.** Sealed, keyed and counts-only for strangers,
   but someone who can open the profile (the keystore key, §3.7a T3b of the
   threat model) learns which friends had security problems and when (to the
   hour). `raven security clear` and `raven erase` delete it.
5. **Early re-keys cost sessions.** R2 and R3 use the shared re-pair budget;
   a contact's own signed misbehaviour can spend it (no third party can:
   only a contact's signature or this disk raises those kinds).
6. **Local only.** No friend learns of an event; each computer decides alone.

## 5. Evidence

Recorded in `docs/roadmap/PROGRESS_LOG.md` (lane 6b, P6.21-P6.31, and the
sub-lane merge entry).

- **Local, macOS (this tree, gates held, lab switches on where named):** the
  unit and in-process tests of P6.21-P6.31: classifier exhaustiveness, the
  threshold table, the penalty box with an injected clock, the ledger (schema,
  rate limit, retention, resolve and clear, a byte scan that no fed IP or
  message id was stored), duplex Noise pairs with a flipped byte, the R2/R3
  two-profile fixtures, the never-block source scans, the CLI and app texts
  (a snapshot of every kind's words); `cargo test -p raven-core -p ash -p
  raven-node` 6089 passed with no switch and again with every Phase 6b switch
  set (merge gates on `6b524a5`); carrier_matrix C1-C16 with the events and
  responses switches (P6.26).
- **CI, open:** GitHub Actions is not running (org billing); CI's release
  "lab switches inert" block does not yet set `RAVEN_LAB_SECURITY_EVENTS`,
  `RAVEN_LAB_SECURITY_RESPONSES`, `RAVEN_LAB_SUITE_FLOOR` or
  `RAVEN_LAB_SEC_PENALTY_LOOPBACK` (unit tests cover their inertness).
- **Harness, open:** P6.32's rows and the false-positive budget run (§3).
- **Hardware, open:** R30 (waits for P6.32).
- **Review:** the Phase 6 exit's adversarial review (P6.53), every confirmed
  finding fixed or accepted with a recorded residual.

## 6. Rollback

Set the const back to `false` (responses or the floor alone may go back
while events stay on; events never goes back while one that sits on it is
on: a const assert refuses that build). No stored state needs a migration:
with the gate shut the ledger and the floor are not read or written, and
every listener, renewer and planner behaves as before the flip.

## 7. Preconditions and flip order

- Events first, then responses; the suite floor only when a second session
  profile exists (the next-profile program; decision D5 of the ratchet design
  is open).
- P6.32 built and green, or the owner records that it stays set aside and
  accepts sensing without it.
- The false-positive budget (§3) run once and recorded.
- CI green, its release "lab switches inert" block setting the sensing
  switches, and the release inertness tests run there.
- Real row R30 when P6.32 exists.
- The Phase 6 adversarial review done and its fixes clean.
- [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) updated in the flip commit: its
  section 10 paragraph and section 12 rows marked
  `SECURITY_EVENTS_PRODUCTION_ENABLED` / `SECURITY_RESPONSES_PRODUCTION_ENABLED`
  (`scripts/check_offline_guide.sh` fails until they match the code).

## 8. Signature

- `SECURITY_EVENTS_PRODUCTION_ENABLED`: not signed.
- `SECURITY_RESPONSES_PRODUCTION_ENABLED`: not signed.
- `SUITE_FLOOR_PRODUCTION_ENABLED`: not signed.
