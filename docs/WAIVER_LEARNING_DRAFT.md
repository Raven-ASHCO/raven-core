# DRAFT owner waiver: learning connectivity (Phase 6a)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `LEARNING_PRODUCTION_ENABLED` (`node/crates/raven-core/src/learning.rs`)
> stays `false` until the owner signs a final copy (renamed to
> `docs/WAIVER_LEARNING_<date>.md`), the preconditions in §7 are met, and the
> flip is applied as its own reviewed commit (owner decision OD6a-12). Debug
> builds open learning with `RAVEN_LAB_LEARNING=1`; release builds never read
> it.

| | |
|---|---|
| **Waiver ID** | `WAIVER-LEARNING-<date>` (to be assigned on signature) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) for the LAN behaviour learning changes on the live slice (shorter connect and reply waits, frame-less LAN probes, a learned carrier order); that record's §2 scope (carrier, handshake, session profile, objects, admission) is unchanged and it is not edited |
| **Not covered** | Any carrier that is held: learning orders only what the static planner allows in a given build. Internet direct, p2p, friend relays, friend custody, letters, handoff and nearby keep their own records and gates; learning's effect on each of them starts only when that carrier's own gate is live |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-23 |
| **Decision** | Enable learning connectivity (order-only route and carrier choice, adaptive waits never above today's, bounded exploration, a bounded relay term, carry choice with today's copy cap) in default and release builds under this waiver, on by default with `raven learning off` (owner decisions OD6a-4 and OD6a-12, recommended options) |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set `LEARNING_PRODUCTION_ENABLED = false` in `node/crates/raven-core/src/learning.rs`. Every plan, wait, log line and file is then as before the flip (carrier_matrix C72); a `learning.bin` already written stays sealed and unread, and `raven learning reset`, `raven learning off --forget` and `raven erase` still delete it |
| **Design** | [`design/2026-10-learning-connectivity.md`](design/2026-10-learning-connectivity.md); the Phase 6 plan `docs/roadmap/plans/phase6-design.json`, design "Phase 6a" (owner decisions OD6a-1 to OD6a-15) |
| **Wire** | None: no frame, card field, route hint entry, error code, vector or freeze hash changes |
| **Threat model** | [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.7b |
| **User docs** | `raven learning --help`; [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md) §6 |
| **Evidence** | The P6.8 simulator thresholds (`node/crates/raven-core/tests/learning_sim.rs`), carrier_matrix C70-C74, lan_fault_matrix s100-s106 and real rows L1-L4; each with its bar in §7 |
| **Real rows** | [`P6A_REAL_ROWS_CHECKLIST.md`](P6A_REAL_ROWS_CHECKLIST.md): L1-L4 |

## 1. Why a waiver is needed

LAN direct is live in release builds. Once `LEARNING_PRODUCTION_ENABLED` is
set, release LAN behaviour changes even though nothing on the wire does: a
contact's LAN route can move behind its Internet route on a network where
the LAN fails, the TCP connect per address and the first-reply wait can be
shorter than today's, and the node makes frame-less authenticated LAN links
of its own (probes) that no user action started. The LAN waiver's §6 makes
extending the slice without a new record a lapse condition, and the other
carriers' records describe today's static order and waits. This record
writes the change down, with its own gate, instead of amending each of them
(OD6a-12).

## 2. Scope (exactly what is covered)

Covered, and only in this combination, while the user's switch
(`node_policy.learning`) is not off:

- **Order-only learning.** For each contact the static planner already
  serves, the learned order of the carriers it
  already plans (LAN, Internet, p2p) on this network, from this computer's
  own dial outcomes. The learned plan must be a permutation of the static
  plan's candidates before the route cap (checked at run time; a plan that
  is not falls back to static and pins that contact-network to static for an
  hour). Nearby keeps its static place; G3's silent-route rotation and an
  open connection still go first; a forced carrier or typed peer is never
  reordered. Route memory (G2) is superseded while learning is on (OD6a-10).
- **Waits clamped to [floor, today].** The TCP connect per address (5 s
  today; floor 1.5 s LAN, 2.5 s Internet), the p2p connect (20 s; floor 8 s)
  and the first-reply wait (30 s; floor 6 s), learned per (contact, network,
  carrier) by RFC 6298 with a safety factor 2, used only after 4 samples of
  at most 24 h, doubled on each expiry (at most x8). Never changed: the 20 s
  connect budget, the 40 s dial deadlines, the worker's 45 s, the idle reply
  wait, IO, resolve and inbound limits (OD6a-6).
- **Probes** (OD6a-5). Frame-less authenticated dials (the probe API takes
  no frames) and owed-ACK-only batches, never a user message:
  - **budget:** 6 per hour for the whole node, burst 2, one in flight,
    none within 2 min of a network change;
  - **eligibility:** verified, unblocked contacts written to within 7 days;
    only carriers the contact's current plan holds, never its top carrier,
    never nearby; an arm at most every 60 min (15 min while it recovers);
  - **LAN bind exposure rule:** a LAN or Internet arm is probed only after
    it delivered a receipt on this network within 7 days, because a LAN
    dialer sends its identity bind before the responder proves who it is
    (cutoff code report, finding 10). A p2p arm is PeerId-pinned.
- **The relay term bound.** A learned term of at most ±150 added to relay
  selection's score (probation -1000 and cooldown -400 always win) and used
  to order a contact dial's circuits (a demoted circuit stays last). It never
  starts a relay change and never makes a relay eligible.
- **Carry cap 2.** While friend custody is live and in use, the at most 2
  friends who hold a contact's mail are picked from the existing candidates
  by this computer's own encounters with them times their own delivery
  record; never more than `MAX_CUSTODIANS_PER_CONTACT = 2` copies (equal to
  the envelope's replication budget), the same deposit timing, and no
  encounter recorded unless custody is in use (OD6a-7, OD6a-9, OD6a-14).
- **The store and its key.** `learning.bin`, an RMS1 sealed file of at-rest
  kind 22 under the profile's at-rest keys (wrapped by the profile's
  keystore key K_hist; OD6a-1 resolved to the privacy pack's keys).
  Contacts, networks and relays as HMAC keys under a secret kept only inside
  the sealed file; times rounded down to the hour; no time-of-day field;
  rows dropped after 30 days without an update (OD6a-8); at most 512 KiB.
  Without the key, learning is memory-only and nothing is written.

Not covered (all remain held): sharing anything learned with another
computer (encounter history, route outcomes, relay scores), any schedule or
time-of-day feature, a wait longer than today's, a route, address, peer or
carrier the static planner does not hold, more than 2 custody copies, a
probe that carries a frame, probes to an unverified, blocked or inactive
contact, and Swift / iOS.

## 3. Holds

| Hold | Status at signature (to fill) | Waived? |
|---|---|---|
| Automated gates (§7 list) green on their runners | Built: the simulator gate (the same numbers in debug and release), C70-C74 and s100-s106 ran green on macOS in the build lane. Pending: the Linux and Windows runs (GitHub Actions does not run at present), a CI job that sets `RAVEN_FAULT_LEARNING=1` (none does yet), and a Linux run of the advisory netns case (checked statically only) | Not waived |
| Independent review | Not done; the internal adversarial reviews are not independent | **Waived for this scope**: learning adds no wire surface, and every effect is bounded by today's static plan and waits |
| Real rows | L1-L4 pending, owner-run | **Not waived** |

## 4. Residual risks accepted

1. **Wrong attribution.** A contact who is simply away makes routes look
   bad. Mitigated by the soft weight for "not listening" and "contact
   offline", the evidence cap, the bias back to static and exploration; a
   contact asleep behind a network that drops connects still looks like "LAN
   no answer". The cost is order only.
2. **Duplicates from shorter waits.** A slow responder (a first keychain
   unlock, a full disk) can make a shortened first-reply wait end a dial
   whose message then also goes over another route. The receiver
   deduplicates and the ACK comes back as an owed ACK; the cost is traffic
   (s100 counts duplicates).
3. **Oscillation** under an adaptive attacker or a flapping link: one wasted
   dial per flip, bounded by the 25 % margin away from static and the
   evidence cap.
4. **Probe visibility.** Each probe is an authenticated link the contact
   (and, for p2p, a relay) sees, it triggers the contact's dial-back, and it
   costs a few kilobytes on a metered network: at most 6 per hour for the
   whole node.
5. **Carry choice cannot see who meets the recipient** (histories are never
   shared, OD6a-9): a friend met often who never meets the recipient wins
   until receipts fail. Simulated worst seed -0.10 (24 h) and -0.12 (7 d),
   p05 -0.03 and -0.01, against average gains of +0.13 and +0.06. A
   custodian that moved is never fetched from (a Phase 3 address problem) and
   can be unfairly demoted.
6. **A never-delivered LAN route is not re-tested** while the Internet
   works (the bind exposure rule): after a reset, an unreadable file or a
   contact away when learning started, a contact can stay on the slower
   Internet route after its LAN heals (simulator `lan_recovery_cold`).
7. **The network key is coarse:** offline networks share one bucket and two
   networks that hand out the same private address collide; a wrong order
   for 2-3 observations.
8. **Meeting and failure history on the laptop** (people report asset A4,
   adversary T3): sealed while the laptop is off or locked; readable through
   the keystore by anyone logged in as the user (T3b), as the rest of the
   profile. No places, addresses or times of day are kept.
9. **Store availability on macOS:** an unsigned build reading the keystore
   from raven-node may prompt; a denial keeps learning in memory only,
   restarting empty at each start.
10. **Sim-to-reality gap:** the simulator and prototype idealise links; the
    real rows are required, and the thresholds are never relaxed silently.

## 5. Compensating controls in place

- The runtime reorder-only check with a static fallback, and a seeded
  property test over 10 000 plans; the simulator checks every learned plan.
- Waits clamped in raven-core (the first-reply and p2p connect waits are
  capped again at today's values in raven-node, and the TCP connect stays
  inside its 20 s budget); a raven-node test pins the static values to the
  node's constants.
- The source-boundary check `node/scripts/learning_boundary_check.sh` (CI):
  the learning code never writes the user's settings, the contact book,
  relay offers or custody consent, never opens a gate, and never calls the
  RRH1, RLB1 or RFC1 encoders.
- Data faults fail safe: a corrupt or tampered file gives static plans and
  is replaced; a newer file is never overwritten; a missing key gives
  memory-only learning.
- Counts-only logs; `raven doctor` carries tokens and counts with no names;
  IPC reports are local.
- The user's controls: `raven learning status` explains every order in plain
  words; `raven learning reset [--contact NAME]` forgets; `raven learning
  off [--forget]` stops (and deletes); removing a contact forgets it.

## 6. Conditions

This waiver lapses, and `LEARNING_PRODUCTION_ENABLED` MUST be set back to
`false`, if:

- a critical or high finding on the covered behaviour is confirmed and not
  fixed;
- any change **adds a route**, address, peer or carrier to a plan, or lets a
  learned plan differ from a permutation of the static one;
- any change **lengthens a wait** or a deadline beyond today's value;
- any change **shares learned data** with another computer (a frame, a card,
  a route hint, a custody op, an IPC field that leaves the computer, a log
  line with an address, key, PeerId, network tag or name);
- any change **adds a schedule feature** (time of day, weekday, an hour
  histogram) or a timer-driven wake for users;
- any change **raises the copy cap** above 2, the probe budget above 6 per
  hour, or the relay term above ±150, or lets a probe carry a frame or reach
  an unverified, blocked or inactive contact, or a LAN or Internet arm
  without a receipt on that network;
- the store is written in clear or under a key other than the profile's
  at-rest keys;
- the LAN waiver lapses or is withdrawn;
- the simulator gate, C70-C74 or s100-s106 is disabled or fails on any of
  its runners for more than one release;
- the review-by date passes without renewal.

## 7. Preconditions and flip order

Before signature (none of the software runs replaces the real rows):

- **Simulator gate** (`node/crates/raven-core/tests/learning_sim.rs`, debug
  and release, Linux, macOS and Windows): every P6.8 threshold, unchanged.
  The route families: flaky Wi-Fi mean at most 0.60x static and p95 at most
  0.50x; network switch mean and p95 at most 0.50x; relay death mean at most
  0.40x and dials per message at most 0.50x; adaptive attacker mean at most
  0.85x and p95 at most static; LAN recovery mean at most 0.80x and its last
  quarter within 1.10x static + 50 ms; stable control mean within 1.05x +
  50 ms, p95 within 1.10x + 100 ms and dials within 1.02x; every seed within
  1.10x static + 100 ms; at most 6 probes per hour (8 in any hour); no probe
  with a frame. The cutoff families: 24 h gain at least +0.05 and worst seed
  at least -0.15, 7 d gain at least +0.02 and worst seed at least -0.20, p05
  at least -0.05, at most 2 copies.
- **carrier_matrix** C70-C74 (`--ignored`) green on ubuntu, macOS and
  Windows (C74 with the p2p lab), and C72 (learning off) equal to its
  baseline.
- **lan_fault_matrix** s100-s106 (`RAVEN_FAULT_LEARNING=1`; s105 also with
  `RAVEN_FAULT_CUSTODY=1`) and s30 with learning on, green 5 times on macOS
  and Linux; netns `learn-flaky` with its green streak (advisory until then).
- The release inert test (`cargo test --release -p raven-core --lib
  lan_gate::`) and `learning_boundary_check.sh` green.
- **Real rows** ([`P6A_REAL_ROWS_CHECKLIST.md`](P6A_REAL_ROWS_CHECKLIST.md)):
  **L1** (a café or guest Wi-Fi with an unreliable LAN path), **L2** (home and
  office, per-network order), **L3** (a friend relay switched off mid-day),
  **L4** (two Macs and a carrier laptop with no internet over 2 days; only
  needed for carry choice, which stays off until friend custody is live).
- **Owner decisions** recorded at signature (the recommended options are the
  ones built): OD6a-1 to OD6a-15, and the open item of the simulator's
  `lan_recovery_cold` (accept the limit of §4.6, or allow one probe of a
  never-delivered route per 6 h before the flip).

Flip order, after signature (owner action): `LEARNING_PRODUCTION_ENABLED`
alone, in its own reviewed commit, with the design document's status line.
Learning's effect on a held carrier (Internet direct, p2p, relays, custody,
nearby) begins only with that carrier's own flip under its own record.

## 8. Signature

Not signed.
