# Learning connectivity: local, bounded, explainable route and carrier choice (Phase 6a)

| | |
|---|---|
| **Status** | Built behind its gate (lab only, steps P6.2-P6.18). Nothing here is enabled in a release build. |
| **Gate** | `LEARNING_PRODUCTION_ENABLED = false` in `node/crates/raven-core/src/learning.rs`, const-asserted with the other holds in `lan_gate::tests::global_production_flags_stay_false`. Debug builds open it per process with `RAVEN_LAB_LEARNING=1`; release builds never read the variable (`lan_gate::tests::learning_lab_switches_are_inert_without_debug_assertions`). |
| **User switch** | `node_policy.learning` (`raven learning on|off`): unset is on while the gate is live (owner decision OD6a-4), `false` is off, and a policy that fails closed keeps it off. |
| **Decisions** | Owner decisions OD6a-1 to OD6a-15, recommended options; OD6a-1 resolved to option (c): the store is sealed by the privacy pack's `at_rest` (kind 22). |
| **Paperwork** | [`WAIVER_LEARNING_DRAFT.md`](../WAIVER_LEARNING_DRAFT.md) (unsigned, OD6a-12); real rows L1-L4 in an unpublished test checklist; threat model [`THREAT_MODEL.md`](../THREAT_MODEL.md) §3.7b. |
| **Wire** | None. No frame, card field, route hint entry or error code changes; `protocol/`, `shared-vectors/` and the freeze hashes are untouched. |
| **Plan** | `docs/roadmap/plans/phase6-design.json`, design "Phase 6a" and steps P6.2-P6.20 (the Phase 6 merged numbering). |
| **Date** | 2026-10-23 |

## 1. Summary

Raven learns only from its own delivery outcomes, on this computer, inside
fixed bounds. It never sends what it learned anywhere and never rewrites
code. Learning changes the **order** of what today's static planner already
allows, and a few **waits**, only ever shorter than today's. It adds no
carrier, no route, no peer, no wire format and no crate.

What it adds, each behind the gate and the user's switch:

1. **Observation per dial** at the three carrier chokepoints
   (`lan_direct::dial` and `dial_announce`, `internet_direct::dial`,
   `p2p::dial_with_path`), next to `delivery_paths::note`.
2. **A carrier order per (contact, network)** from a decayed success
   estimate and an expected cost per carrier (LAN, Internet, p2p), with a
   bias back toward the static order.
3. **Adaptive per-route waits** (RFC 6298) for the TCP connect per address,
   the p2p connect and the first-reply wait, clamped between a floor and
   today's value.
4. **Background exploration** with frame-less probes and owed-ACK dials
   only, never a user message, under a global budget of 6 per hour.
5. **A bounded relay term** (±150) added to relay selection's score and to
   the circuit order of a contact dial.
6. **Carry choice**: which (at most 2) friends hold a contact's mail, from
   this computer's own encounters with them times their own delivery record.
7. **Explanations**: a local reason grammar, `raven learning
   status|reset|on|off`, a LEARNING section in `raven status`, `learning:`
   lines in `raven doctor`.

With the gate shut or the switch off, every plan, wait, log line and file
is as before: no `learning.bin` is made, IPC `Status` carries no `learning`
report (gate shut) or an `off` one, and no log line names learning
(carrier_matrix C72).

## 2. Where it sits

```
 raven-core (pure; no I/O except store.rs)
   learning.rs           gate, user switch, lab switches
   learning/estimate.rs  decay, decayed Beta, RTT, encounter (fixed point)
   learning/observe.rs   Observation, Evidence, FrameKind, failure weights
   learning/rank.rs      carrier order p/cost + asymmetric hysteresis
   learning/wait.rs      connect / first-reply waits (RFC 6298, clamped)
   learning/relay.rs     bounded relay term
   learning/carry.rs     own encounters x own receipts -> at most 2 carriers
   learning/model.rs     Model: arms, relay, encounter and carry rows, caps
   learning/explain.rs   reason grammar (local IPC)
   learning/store.rs     LRN1 learning.bin, sealed (at_rest kind 22)
   outbox.rs             plan_object_routes_ranked (order before the cap)
        ^ observations (bounded channel, 256)     | order, waits, terms, picks
 raven-node learning.rs  the service: switch poll 2 s, load once, save every
                         60 s when changed and at shutdown, explorer tick 60 s,
                         hooks in the carriers, worker, p2p host and custody
        ^ IPC (local only): Status.learning, LearningPlan, LearningReset
 ash                     raven learning ...; raven status / doctor rows;
                         raven send's probe order and "Left with ... first"
```

The arithmetic under `raven_core::learning` is integer or fixed point
(`#![deny(clippy::float_arithmetic)]`), so the simulator and every OS give
the same numbers. Wall time is `raven_core::clock::now_ms()`, which the
Phase 5 lab clock moves in harness runs.

### 2.1 One send

1. The shared resolver (`outbox::peer_plan`: the worker, `AppSubmit`, the
   route-hints announcer and session renewal) asks `learning::plan(contact,
   static carriers)` while learning is on. Route memory (G2, lab) is then
   neither read nor taught (OD6a-10).
2. Per object, `plan_object_routes_ranked` runs the same filters as today
   (the carrier choice, gates, hide-IP and the verified-contact rule), then
   a stable sort by carrier rank **before** `truncate(MAX_ROUTES_PER_OBJECT)`.
   The result must be a permutation of the static plan's candidates
   (`rank::same_set_as_static`); if not, the static plan is used, the
   contradiction counted and that contact-network pinned to the static
   order for an hour (`CONTRADICTION_PIN_MS`).
3. Then, unchanged: blocked routes dropped, `localize_lan_route`, G3's
   silent-route rotation (`rotate_past`) and `connected_first`. A silent
   route and an open connection still beat the learned order; nearby keeps
   its static place.
4. Each dial takes its waits from `learning::waits(contact, carrier)` and
   posts one observation on return, Ok or Err.
5. The worker checks the ACKs (`accept_sealed_ack`); a dial whose every ACK
   was refused is retracted. After an attempt that reached the contact the
   worker remembers the applied order (the hysteresis start).
6. `raven send` dials through IPC into the same carrier dials, so it is
   observed with no new op; its probe order comes from IPC `LearningPlan`
   (asked within 2 s, only while ash's own gate is live).

A forced carrier (`--carrier`) or a typed `--peer` is a single-carrier
choice: there is nothing to reorder.

## 3. Algorithms and constants

### 3.1 Observations and evidence (`learning/observe.rs`)

An observation is (contact, network tag at dial start, carrier, path and
relay for p2p, frame kind, evidence, timings, Karn flag, time). It lives in
memory only and is never persisted raw.

| Evidence | Meaning | Weight (milli) |
|---|---|---|
| E1 Receipt | message frames and an ACK reply on the link the dial authenticated to that contact | +1000 |
| E2 Link | an authenticated link with no message frame (probe, owed-ACK push, announce, custody or app dial) | +500 (`PROBE_W_M`, OD6a-2 (a)) |
| E3 Silent | message frames written, no ACK before the reply wait | -500 |
| E4 Fail, soft | `NOT_LISTENING`, `Why::ContactOffline`, `lan_no_answer` (the contact may simply be away) | -250 |
| E4 Fail | `CLOSED_EARLY`, `PEER_REFUSED`, `Why::RelayBusy` | -500 |
| E4 Fail, full | `NOT_REACHABLE`, `DIAL_FAILED`, timeouts, `WRONG_IDENTITY`, `LINK_NOT_ACCEPTED`, the p2p reasons that blame the path, `no_route`; any unknown code | -1000 |
| E0 None | gates and holds, `CONTACT_BLOCKED`, this node's own state (lock, store, clock), the object's fate, a network change mid-dial, nearby, a dial that never began connecting, a dial whose link was tampered with (Phase 6b's `SEC_LINK_TAG_FAIL`: dropped and counted, so breaking some links cannot steer the order) | 0 (not evidence) |

The table is `FAIL_WEIGHTS` and `NOT_EVIDENCE`; a raven-node test fails
when a new stable dial code has no row. Success needs an ACK on the Noise
link authenticated to the contact; the worker's `accept_sealed_ack` can only
retract a success, never create one. An inbound link is not route evidence:
it records an encounter (§3.7), adds relay evidence when it came over our
own reservation (§3.6), and a contact back on the local network from a new
address halves that arm's LAN doubt (`Model::halve_doubt`).

### 3.2 Decay and the arm estimate (`learning/estimate.rs`, `model.rs`)

- Decay is `decay_q16(dt, half) = 2^(-dt/half)` from a 64-entry Q16 table,
  `dt` clamped to `[0, MAX_DT_MS = 30 d]`: a clock that steps back extends
  nothing, a forward jump only forgets.
- An **arm** is (contact, network, carrier), carrier in {LAN, Internet,
  p2p}. Its success estimate is a decayed Beta in milli-observations:
  half-life `HALF_LIFE_MS = 1 d`, evidence capped at `N_CAP_M = 8000` (about
  8 observations), prior `PRIOR_M = (1000, 1000)`, a recovery streak (a
  second success in a row halves the failure count). Mean
  `p = (a + A0) / (a + b + A0 + B0)`, floored at `P_FLOOR_PPM = 2 %` in the
  index (OD6a-3 (a)).
- Costs: `ok_ms` and `fail_ms` are EWMAs (alpha 1/4) of successful and
  failed dial times. Priors: LAN 300, Internet 1500, p2p 3000 ms; failure =
  today's connect wait of that carrier. On each success `fail_ms` relaxes
  1/8 of the way back to it.
- The arm also keeps its last 8 tries as bits (the reason's `k/n`) and the
  times of its last observation, receipt and probe.

### 3.3 Carrier order (`learning/rank.rs`)

- Expected time of trying arm i: `c_i = p_i * ok_i + (1 - p_i) * fail_i`.
  Sorting on `p_i / c_i` descending minimises the expected time to the
  first success over sequential tries; in integers
  `index = p_ppm * 10^6 / max(c_ms, 1)`.
- Groups are the distinct carriers of the static plan in static order
  (nearby excluded; it keeps its static slot).
- Below `N_MIN_M = 1500` milli of aged evidence over those arms: the static
  order (`why=cold`).
- Otherwise start from the last applied order (memory only), then bubble
  passes (at most n^2): swap neighbours when
  `index(lo) * 100 > index(hi) * (100 + m)`, with `m = 0` when the swap moves
  toward the static order and `MARGIN_PCT = 25` when it moves away. Ties
  keep the current order. This asymmetry is the main "never worse than
  static" rail: the order returns to static as soon as the evidence allows.
- `why` is `kept` (static), `failing` (a static carrier above failed some
  of its last tries: `fail=` never says 0), `faster` (a lower one answers
  sooner, or more often while the one above failed none of its last
  tries), or `recovering` (the pass moved back toward static).

### 3.4 Adaptive waits (`learning/wait.rs`, OD6a-6 (a))

Per arm two RTT estimators: connect (dial start to the peer's offer read,
that is, an authenticated link) and reply (frames written to the first
terminal reply). RFC 6298 with a safety factor 2:

- first sample `srtt = R, rttvar = R/2`; then
  `rttvar = (3 rttvar + |srtt - R|)/4`, `srtt = (7 srtt + R)/8`;
- `RTO = srtt + max(200 ms, 4 rttvar)`;
  `W = clamp((2 RTO) << backoff, MIN, STATIC)`;
- each expiry with no later sample in the same dial doubles the wait
  (`Model::rtt_expired`, at most x8); a fresh sample clears the backoff;
- used only while learning is on, the arm has `WARM_SAMPLES = 4` samples and
  the last is at most `FRESH_MS = 24 h` old; otherwise today's value;
- Karn: a dial that carries an object which went silent before
  (`Entry.unacked_route`) gives no reply sample.

| Wait | Today (static) | Floor |
|---|---|---|
| TCP connect per address (LAN) | 5 s (`netutil::CONNECT_TIMEOUT`) | 1.5 s |
| TCP connect per address (Internet) | 5 s | 2.5 s |
| p2p connect | 20 s (`p2p::CONNECT_DEADLINE`) | 8 s |
| first reply | 30 s (`PRODUCTION_REPLY_WAITS.first`) | 6 s |

A raven-node test pins the static column to the node's constants. Never
changed: the 20 s connect budget over several addresses, the 40 s carrier
dial deadlines, the worker's 45 s, the 2 s idle reply wait, IO and resolve
timeouts, and the inbound handshake deadline and lifetime. A learned p2p
connect wait shows tenths of a second in its error text (`after 8.4s`);
today's prints as before (`after 20s`).

Why a shorter wait is safe: a shortened first-reply wait ends that dial as
sent but not yet confirmed (`NO_ACK_YET`). The receiver deduplicates, an ACK
that comes later reaches the sender as an owed ACK, and G3 rotates the next
attempt. Nothing is lost or sealed again; the worst case is a duplicate
copy on another route, which the harness counts (s100).

### 3.5 Exploration (raven-node `learning.rs`, OD6a-5 (a))

A carrier that lost its place is tried again only by dials that carry no
user message, so a route that healed comes back without a message waiting
on it.

- **Who:** verified, unblocked contacts written to within `ACTIVE_MS = 7 d`
  (a message dial this run, or after a restart a receipt over any of the
  contact's arms on this network within 7 d), never one whose sending the
  user paused (Phase 6b P6.31's hold: nothing is planned or dialled to it,
  a probe included).
- **Which arm:** a carrier the contact's current plan holds (gates and
  hide-IP apply), never its top carrier and never nearby. A LAN or Internet
  arm only after a receipt **on this network** within `RECEIPT_WITHIN_MS =
  7 d`: a LAN dialer sends its identity bind before the responder proves who
  it is (code-report finding 10), so a stale address is never probed. The
  rule is per arm (contact, network, carrier): a newly learned LAN address
  of a verified contact whose LAN arm delivered here may be probed, still
  under the LAN Noise pin. A p2p arm qualifies whenever p2p is live (the
  dial is PeerId-pinned).
- **When:** due after `RECOVER_GAP_MS = 15 min` when the arm sits below its
  static place with a success streak, else after `PROBE_ARM_GAP_MS = 60 min`,
  and only when nothing else observed it within the shorter of its gap and
  30 min. The stalest due arm goes first.
- **Budget (global):** a token bucket of `PROBES_PER_HOUR = 6` with a burst
  of `PROBE_BURST = 2`, one probe in flight, nothing within `SETTLE_MS =
  2 min` of a network change, nothing while the file is kept in memory
  because a newer Raven wrote it.
- **A probe** is a frame-less dial (`Dialer::probe_within` takes no frames
  at all) over the first planned route of that carrier, localized as the
  worker does, within that carrier's connect wait plus 5 s. The carrier dial
  keeps that bound itself (`DialMeta::within`; the worker's own is 5 s
  later), so its link or failure, a probe that ran out of time included,
  reaches the model through the carrier hook like any dial.
- **ACK-only exploration:** a worker batch of owed ACKs with no message may
  put the stalest due arm first when that arm's failures are cheap
  (`fail_ms <= 10 s`), for a verified contact only. It spends the same
  budget. A batch with any message keeps the exploit order.
- `Status.learning.probes_24h` counts both kinds (the budget's spend).
- The design's 6 h floor (`FLOOR_MS`) was not built: the hourly gap already
  re-tests every eligible arm within the budget.

Side effects: a probe is an authenticated link the contact sees (and, over
p2p, the relay); it makes the contact's node run `peer_seen` (at most one
dial-back per 60 s); on a metered hotspot it costs a few kilobytes. Logs
carry counts only, never a line per probe. The explorer's own notes (whom
this node wrote to, which arm it tried when) live in memory only.

### 3.6 Relay term (`learning/relay.rs`)

- A relay row is a decayed Beta: a receipt over a relayed path through R
  +1000; per-circuit outcomes of a failed p2p dial (Phase 2's reason facts)
  `NoAnswer`, `Refused`, `NotARelay` -1000, `Busy` -500, `NotOnRelay` no
  change (the contact is offline); an authenticated inbound link that came
  over **our own reservation** on R +500; a Phase 6b security event about R
  (`SEC_RELAY_LINK_BROKEN`, about the relays the broken link went through,
  never the rest of the contact's dial set; a Suspicious
  `SEC_RELAY_NO_RECEIPT`; the responses gate) -1000, negative only, in place
  of 6b's "last for an hour" (R8 keeps that for profiles that do not
  learn).
- `term(R) = 0` below 3000 milli of evidence, else
  `clamp((p_ppm - 500 000) * 300 / 10^6, -150, +150)`
  (`RELAY_TERM_MAX = 150`).
- `relay_select`'s score adds the term, clamped again to ±150 whatever the
  caller passes. Its other terms are probation -1000, cooldown -400,
  last_ok +300, confirmed +100, availability 0..200, diversity +50+50. The
  term is read only when a slot is filled or a replacement was already due
  (`best_standby`): it never starts a change, never makes a relay eligible,
  and cannot beat probation or cooldown.
- A contact dial's circuits are stable-sorted by term, highest first, after
  Phase 2's not-member filter and DEMOTED partition: a demoted circuit stays
  last, and each relay's first circuit stays before any relay's fallback.
  The 8-address cap is applied before, so no address is added or dropped.
- Terms are computed in memory from the model and never logged.

### 3.7 Carry choice (`learning/carry.rs`, OD6a-7 (a), OD6a-9 (a), OD6a-14 (a))

Live only while learning is on, friend custody is live, and custody is in
use (`raven custody use on`, or a custodian listed for a verified contact
who is one too). Otherwise the worker keeps today's `deposit_custodians`
exactly, and no encounter is recorded at all.

- **Encounters**, this computer's own only: an authenticated link with a
  verified, unblocked contact in either direction (the trusted inbound
  links, a beacon answer and new route hints through `custody::peer_seen`;
  an outbound dial that linked) and a nearby pipe up (`custody::encounter`).
  Links within `ENC_GAP_MS = 30 min` of the last one merge. PRoPHET-style
  aging without transitivity: `p <- p * decay(dt, 3 d)`, then
  `p <- p + (1 - p) * 0.5`; `predict(F, now) = p * decay(now - at, 3 d)`.
- **Carry Beta per (custodian F, recipient B):** prior 0.7 (1400, 600) when
  B announced F, 0.4 (800, 1200) when F is only sender-listed; half-life 7 d.
  A message friends held that the worker finds delivered credits each holder
  `+1000/|H|`; one that expired or was parked by the horizon debits each
  `-1000/|H|`; a message never left with a friend, or given up for another
  reason, is no evidence.
- **Pick:** `U(F) = predict(F) * carry_mean(F, B)` over Phase 3's
  `custodian_candidates` (announced matches, then sender-listed, usable,
  at most 8 by bound, in static order); stable sort by U; the top
  `CARRY_CAP = MAX_CUSTODIANS_PER_CONTACT = 2`, which a test pins equal to
  the envelope's `OUTBOUND_REPLICATION_BUDGET`. With no encounter and no
  carry evidence for B: static (`carry=cold`). An object is never left with
  more than 2 candidates, so a changed pick never makes a third copy.
- **Spray and wait:** the source sprays to its 2 best; custodians only hold
  until the recipient fetches. Deposit timing is unchanged (no earlier than
  `CUSTODY_AFTER_MS = 60 s` and the failed direct try), as are parks,
  strikes and chunks.
- Letters use the same picks and order; the handoff plan gets `listed` in
  this order (order only); a forwarder visits its next hops in its own order
  of meeting them (`forward_order`, order only).
- IPC `LearningPlan.carry` names the pick to local ash, which words it in
  the queued text of `raven send`: "Left with Carol first (you meet often;
  delivered 3 of 4 before)." Custody log lines end with `carry=cold` or
  `carry=ranked` while carry choice is live.

### 3.8 Network key (OD6a-13 (a))

The network is `HMAC(store secret, "n" || egress tag)[..8]`. The tag is
route memory's egress tag (the private source address and the IPv6 /64 of
the default route), or `RAVEN_LAB_NET_TAG` in a debug lab run, read through a
learning-gated `route_memory::network_tag_for_learning()` and cached until
netwatch reports a change. A dial whose end finds the tag read then (a UDP
connect, nothing sent) other than the cached one is a network change
mid-dial (E0): a move netwatch has not acted on yet (its debounce, its gap,
a default route its next poll finds moved) teaches neither network. No
default route maps to the one bucket `none`,
so offline networks share it, and two networks that hand out the same
private address collide. Both cost a wrong order for 2-3 observations, never
a route. The tag itself is never stored.

## 4. Safety rails (each with a test)

1. **Gate and switches.** The const stays `false`; `RAVEN_LAB_LEARNING`,
   `RAVEN_LAB_LEARNING_TUNE` (`<probe_gap_s>,<recover_gap_s>,<half_life_s>`,
   each 1-604800) and `RAVEN_LAB_LEARNING_SEALER=unavailable` are read only
   under `cfg!(debug_assertions)`; a release test proves them inert. The
   fault matrix and carrier matrix strip all three unless a case asks.
2. **Reorder only.** The input is the gated, filtered static plan; the
   output must be a permutation of it or the static plan is used (contradiction,
   1 h pin). A seeded property test (10 000 plans) and the simulator check
   every learned plan.
3. **No gated carrier, no stranger, no settings.** Probes plan through the
   resolver for admitted, verified contacts only. Learning has no code path
   to the user's settings, the contact book file, relay offers, custody
   consent or any gate: `node/scripts/learning_boundary_check.sh` (CI job
   harness-integrity; `--self-test` proves each rule fires) refuses
   `save_policy`, `set_hide_ip`, `relay_offer`, `relay_allow`, a
   `custody_use` assignment, `contacts.json`, a `PRODUCTION_ENABLED = true`,
   and the RRH1, RLB1 and RFC1 encoders in the learning sources.
4. **Waits** are clamped to [floor, today]; no deadline is ever extended.
5. **Relay term** bounded to ±150; it never starts a change.
6. **Carry** draws from the same candidates, at most today's 2 copies, with
   today's timing.
7. **Data faults.** A corrupt or tampered file (AEAD) gives an empty model
   and static plans, and is replaced by the next save; a missing key gives
   memory-only learning until the key is here (then the file is read; a
   save the key refuses is tried again, and one contact cannot be forgotten
   in a file not read: an error, never "cleared 0"); a file a newer build
   wrote gives memory-only and is never overwritten; out-of-range rows are
   clamped or dropped on load; `raven privacy unseal` deletes the file.
8. **Nothing leaves the computer.** No learned value goes into a frame,
   a card or a route hint: the learning sources never call the RRH1, RLB1 or
   RFC1 encoders (rail 3's check). IPC is local; logs carry counts and fixed
   words only.

## 5. Storage and privacy

- **The file.** `learning.bin`: an RMS1 sealed file of at-rest kind 22
  under the profile's at-rest keys (which K_hist wraps), plaintext
  `RVNLRN01` plus compact JSON v1 (`raven_core::learning::store`). Writer:
  raven-node (every 60 s when changed, once at shutdown, IPC reset), and
  ash's `raven learning reset` / `off --forget` only while no learning
  raven-node answers. Lock `.learning.lock.sqlite`; owner-only (0600); at most
  512 KiB; a symlink, a second link or another mode is refused and started
  over. Registered in `at_rest::FILES` and in
  [`2026-10-at-rest-metadata.md`](2026-10-at-rest-metadata.md) §6.1; erase
  removes it.
- **A model, not a history.** Raw observations live in memory only (the
  channel and 24 h counters). The file holds decayed aggregates; every time
  is rounded down to the hour; there is no time-of-day, weekday or hour
  histogram anywhere (`carry::tests::no_time_of_day_feature` pins the
  stored fields; owner default "no online schedules learned"). A store test
  scans a saved model's plaintext for the contacts' keys, the network tag, an
  address and a PeerId, and finds none.
- **Keyed ids.** Contacts, relays and networks are HMAC keys under a secret
  that exists only inside the sealed file. A decrypted file names nobody
  without the contact book and that secret; a full reset changes the secret.
- **Bounds.** 64 contacts with arms, 8 networks per contact, 3 ranked
  carriers, 32 relays, 64 encounters, 128 carry rows (oldest by last update
  evicted). A row not updated for 30 d (OD6a-8) or with under 50 milli of
  evidence is dropped.
- **Memory only, never written or logged:** observations, the last applied
  order and contradiction pins, the explorer's notes, the carry facts the
  2 s poll caches (verified contact keys and the custody consent bit), and
  the holders of each queued object.
- **Encounters only while custody is in use** (OD6a-14): without custody
  nothing about meetings is kept.
- **Never shared** (owner default): encounter history and every other
  learned value stay on this computer; no PRoPHET transitivity exists.
- **Names.** IPC `Status.learning` rows and `LearningPlan.carry` carry contact
  keys for local ash only; `raven status` and `raven learning status` print
  petnames from the contact book (rows of keys the book does not hold are
  skipped). `raven doctor`, which people paste for help, carries counts and
  reason tokens only (`learning_row_<n>`), never a name or key.
- **Reset.** `raven learning reset [--contact NAME]` forgets rows (and the
  route memory, OD6a-10); `raven learning off --forget` deletes the file;
  removing a contact forgets its rows.

## 6. Security: who can do what

People-report adversaries ([`cutoff-people-report.md`](../roadmap/studies/cutoff-people-report.md)
§1.3) and the bounded-impact argument. The threat model's version is
[`THREAT_MODEL.md`](../THREAT_MODEL.md) §3.7b.

- **T1/T2, on-path network attacker** (guest Wi-Fi, router, hotspot host).
  It can drop, delay or reset traffic, so cause failures and slower samples.
  It cannot create a success: that needs an ACK on the Noise link
  authenticated to the contact. Effect: the routes it disrupts are demoted,
  and traffic moves to other routes the static plan already allows, which
  static would have reached anyway after its fixed waits. Slower samples
  lengthen waits only up to today's values. **Bound:** for every message the
  learned worst case is at most the static worst case (the same route set,
  waits at most today's), and the order returns to static as soon as the
  evidence allows. The simulator's adaptive attacker (it black-holes the
  direct route that carried the last receipt, every 20 min) gives 0.33x the
  static mean.
- **A malicious contact or custodian (T4).** It can make routes to itself
  look good or bad (its own delivery only). As a custodian it cannot forge
  the recipient's sealed ACK, so it gains carry score only by delivering. A
  custodian colluding with the recipient can steer the sender's copies to
  itself, which the recipient already announced; the bound is the existing
  announcement plus the cap of 2. Carry choice never adds a custodian, so it
  never adds a friend who learns who writes to whom.
- **A malicious relay operator.** It gains score only by relaying for real;
  refusing or dropping lowers its own. The term is bounded and Phase 2's
  hysteresis still governs.
- **T3, the laptop taken.** Off or locked (T3a): the file is sealed with
  the rest of the profile. Logged in (T3b): the model shows "this laptop met
  friend X often recently" and "LAN to Y fails here" for keyed ids the
  contact book names. It holds no places, no addresses, no times of day and
  no message metadata beyond what the outbox already holds. Local malware
  is out of scope (THREAT_MODEL §3.16).
- **Resource exhaustion.** The channel holds 256 (more are dropped and
  counted), every map has a cap, the file at most 512 KiB, the probe bucket
  6 per hour, ranking is O(n^2) with n at most 3. The model lock is never
  held across I/O.

What learning does not trust: the diagnosis text (tokens only), inbound
traffic as route evidence (see §3.1), and route hint contents (they feed the
static plan, not the model).

## 7. The reason grammar and what the user sees

```text
learn: state=<s> order=<c>,<c>[,<c>] why=<w>[ fail=<c>:<k>/<n>][ ok=<c>:<k>/<n>][ wait=<c>:<n>s][ age=<n><s|m|h|d>]
```

- `s` in {on, shadow, off, memory_only, reset_after_unreadable};
- `c` in {lan, internet, p2p} (nearby is never ranked);
- `w` in {cold, kept, faster, failing, recovering, contradiction, unreadable,
  off, held, shadow};
- `k/n`: failed or successful tries of the last `n` (at most 8);
- ASCII, at most 120 bytes; never an address, key, PeerId, network tag or
  name. It is local IPC, not an error code: `RAVEN_ERROR_CODES_V1` and the
  freeze hashes are untouched. `Reason::find` reads the last block and skips
  what it does not know, so a newer node's reason still gives text.

The user's surface (ash):

- `raven learning status [--json]`: the state, the counts (contacts,
  networks, relays, mail-friend records; tries, probes, dropped and orders
  set aside in 24 h), the save age, and one sentence per contact, for
  example "Bob: Internet first on this network: LAN did not answer 3 of the
  last 4 tries (2 h ago)". Without a report it says "held in this build",
  "off (raven learning on)" or "needs raven-node running"; `--json` then
  prints a status whose `state` is `held`, `off` or `not_running`.
- `raven learning reset [--contact NAME] [--yes]`: asks first on a terminal;
  IPC `LearningReset` first, else the sealed file with the same sealer.
- `raven learning on|off [--forget]`: writes `node_policy.learning`, never
  over an unreadable policy. `off --forget` waits (at most 5 s) until the
  running node read the switch (every 2 s), then forgets everything.
- `raven status`: a LEARNING section (at most 8 rows) while the node reports
  learning and it is not off. `raven doctor`: `learning: state=...
  contacts=... observations_24h=... probes_24h=... saved_age=...` and up to 8
  `learning_row_<n>: order=internet,lan why=failing fail=lan:3/4 ...` lines.
- The production gate table in `raven doctor` lists the learning gate and
  `raven learning held (LEARNING_HOLD)`.

## 8. Evidence

### 8.1 Prototype

A standard-library Python prototype of the same algorithms
([`learnsim_final3.py`](../roadmap/research/prototypes/learning-simulator/learnsim_final3.py),
results in `final_results.txt` next to it; 32 seeds; ratios are learned over
static):

| Family | Mean | p95 | Worst seed | Dials per message, static to learned | Probes/h |
|---|---|---|---|---|---|
| stable_control | 1.00 | 1.00 | 1.01 | 1.00 to 1.00 | 2.0 |
| flaky_wifi | 0.27 | 0.07 | 0.51 | 1.27 to 1.10 | 2.3 |
| network_switch | 0.17 | 0.15 | 0.23 | 1.40 to 1.00 | 2.1 |
| relay_death | 0.14 | 0.15 | 0.14 | 3.90 to 1.02 | 2.9 |
| adaptive_attacker | 0.38 | 0.49 | 0.44 | 1.51 to 1.29 | 1.1 |
| lan_recovery | 0.28 | 0.15 | 0.35 | 1.30 to 1.00 | 2.7 |

Cutoff, expected delivery over 128 seeds: 24 h 0.345 to 0.471 (oracle
0.504), worst seed -0.061, p05 -0.025; 7 d 0.907 to 0.958 (oracle 0.979),
worst -0.148, p05 -0.026. Variants tried and rejected: symmetric 25 %
hysteresis (stuck on the Internet after the LAN recovered), a 3 d half-life
with cap 12 (slow recovery), "anchor the static first custodian" (worse mean
and worst case), a stronger announced prior (no change).

### 8.2 Simulator gate (P6.8)

`node/crates/raven-core/tests/learning_sim.rs` drives the real code (the
static and ranked planners, `rank::order`, `wait`, `Model::observe` through
`observe::evidence` over real message and ACK envelopes, the relay terms,
`carry_pick` and `carry_outcome`, `retry_delay`) in a modelled world, worker
and explorer. 24 seeds per route family, 96 per cutoff family; the same
numbers in debug and release. Results on this tree (2026-10-23), ratios
learned over static:

| Family | Mean | p95 | Worst seed | Dials per message, static to learned | Probes/h | Threshold (asserted) |
|---|---|---|---|---|---|---|
| stable_control | 1.00 | 1.00 | 1.00 | 1.00 to 1.00 | 1.03 | mean <= 1.05x + 50 ms, p95 <= 1.10x + 100 ms, dials <= 1.02x |
| flaky_wifi | 0.27 | 0.07 | 0.46 | 1.30 to 1.11 | 2.16 | mean <= 0.60x, p95 <= 0.50x, rate not lower, dials not more |
| network_switch | 0.17 | 0.15 | 0.19 | 1.40 to 1.00 | 1.04 | mean <= 0.50x, p95 <= 0.50x |
| relay_death | 0.17 | 0.15 | 0.21 | 3.90 to 1.08 | 0.02 | mean <= 0.40x, dials <= 0.50x |
| adaptive_attacker | 0.33 | 0.46 | 0.36 | 1.51 to 1.29 | 1.04 | mean <= 0.85x, p95 <= 1.00x |
| lan_recovery | 0.25 | 0.15 | 0.29 | 1.31 to 1.00 | 2.43 | mean <= 0.80x, last quarter <= 1.10x + 50 ms (155/155 ms) |
| lan_recovery_cold | 0.41 | 0.15 | 0.50 | 1.31 to 1.00 | 1.03 | mean <= 0.80x; last quarter reported only (155/749 ms, §10) |

Every route family also asserts: every seed's mean within 1.10x static +
100 ms, at most 6 probes per hour on average and 8 in any hour, no probe with
a frame, and every learned plan a pure reorder of the static one.

Cutoff families (carry choice, expected delivery of the custodians chosen):

| Family | Static | Learned | Gain | Worst seed | p05 | Threshold |
|---|---|---|---|---|---|---|
| cutoff_meetings_24h | 0.364 | 0.499 | +0.134 | -0.100 | -0.026 | gain >= +0.05, worst >= -0.15, p05 >= -0.05, copies <= 2 |
| cutoff_meetings_7d | 0.901 | 0.964 | +0.063 | -0.123 | -0.012 | gain >= +0.02, worst >= -0.20, p05 >= -0.05, copies <= 2 |

The thresholds are never relaxed without the owner's OK. The CI workflow
runs the gate in debug and release next to `network_sim_1000`.

### 8.3 Harness (P6.18)

- **carrier_matrix** (`--ignored`, all three OSes; C74 needs the p2p lab):
  C70 a black-holed LAN is learned (Internet first from the third message in
  under 2 s, `raven learning status` says "LAN did not answer", reset brings
  LAN first back); C71 a stalled reply is left after the learned wait (under
  10 s, not 30 s) and delivered once by the retry; C72 learning off follows a
  recorded baseline, with no learning log line, file or report; C73 a
  corrupted store starts over and a missing key is memory-only with the file
  untouched; C74 relay rows feed the circuit order with no relay change
  started.
- **lan_fault_matrix** (`RAVEN_FAULT_LEARNING=1`, macOS and Linux): s100
  flaky LAN (total send time at most 0.6x of off, fewer sends that pay the
  LAN wait, each message once, at most 2 duplicates), s101 per-network
  order (home and office), s102 reset, off and `off --forget`, s103 probes
  revive a healed LAN within the budget (no framed link; a run can take up
  to 24 min of its 35 min window), s104 rows age out over a lab-clock jump
  (the send comes before the explorer's first tick, so no probe has run;
  a long tuned probe gap alone would not rule probes out, §10 item 3), s105
  carry choice by encounters (with `RAVEN_FAULT_CUSTODY=1`), s106 no probe
  to a stranger, an unverified or a blocked contact. s30 runs with learning
  on under the same flag.
- **netns** `learn-flaky` (Linux root, advisory): loss bursts on a shared
  bridge, p95 with learning at most half of p95 without, and no packet from
  A to a stranger's node behind a stale LAN address.

Where they have run (P6.18, macOS, the build lane): C70-C74 5/5 in one
run; s30 and s100-s106 8/8 with `RAVEN_FAULT_LEARNING=1` and
`RAVEN_FAULT_CUSTODY=1`. Not yet: the learning scenarios are opt-in and no
CI workflow sets `RAVEN_FAULT_LEARNING`; `learn-flaky` needs Linux root and
has been checked statically only (`bash -n`, shellcheck); and the CI rows
(C70-C74 on ubuntu and Windows, the simulator in CI, the netns advisory
run) wait for GitHub Actions, which does not run at present (the
organisation's billing).

The owner's real rows L1-L4 (an unpublished test checklist)
are required before any flip; the software runs do not replace them.

## 9. Non-goals: what learning does not solve

Learning orders routes and friends this computer already has. The
cutoff code report ([`cutoff-code-report.md`](../roadmap/studies/cutoff-code-report.md))
names limits it leaves where they are:

- **Addresses** (finding 2, and the hotspot host of finding 6): learning
  finds no address. Discovery is the Phase 3 beacon, route hints and the
  report's fixes F1-F8. A never-delivered LAN or Internet address is never
  probed (finding 10).
- **The 24 h ceilings** (findings 3 and 9): sessions, envelopes, custody
  objects and handoff keep their 24 h, and letters and the horizon their
  7 d. Learning lengthens no lifetime and no deadline.
- **Moved custodians** (finding 5, w1/w2): a custodian that came back up on a
  new address is not found by learning; F8 and the beacon join round are
  Phase 3's. Such a custodian's failed carries can unfairly lower its carry
  score until it delivers again.
- **No schedules:** no time-of-day or weekday feature, and no timer-driven
  wake for users. Reactions to contacts appearing stay event-driven
  (`peer_seen`, beacon answers, netwatch).
- **No settings:** learning never changes privacy settings, gates, contacts,
  relay offers or custody consent.

For the people report's assets: learning adds rows to A4 "meeting history"
(the encounter rows, only while custody is in use) and a new "route failure
history" (the arms), both sealed (T3a) and keyed; T4's view of who writes to
whom is unchanged in size (the cap stays 2).

## 10. Known limits and open items

1. **A never-delivered LAN route is not re-tested** (P6.8, the simulator's
   `lan_recovery_cold`): after `raven learning reset`, an unreadable file, the
   30-day retention, or a contact who was away when learning started, a
   contact can stay on the slower Internet route while its LAN works again,
   until the Internet fails or a user message falls through. Owner item:
   accept, or allow one probe of such a route per 6 h.
2. `RAVEN_LAB_LEARNING_TUNE`'s half-life field is parsed but not yet applied
   by the model (harness runs use the 1 d half-life); its gaps are applied.
3. A long tuned probe gap cannot stop the first exploration of an arm never
   explored once it has gone 30 min unobserved (s104 rules out probes by
   timing instead).
4. Status-only readers still name the static custodians, not carry choice's
   pick: ash `coverage_from_files` (`raven doctor`, `contact show`) and the
   queued-text fallback, raven-node `custody_status`, `reach_diag` and the
   letters "shared" flag. The queued text of `raven send` names the pick when
   raven-node gives one.
5. Carry debits for an object held when raven-node restarts before it expires
   are lost (the holders live in memory); credits still come from the route
   record.
6. On macOS an unsigned build may prompt when raven-node first reads the
   keystore; a denial keeps learning in memory only, restarting empty at each
   start.
7. The model and simulator idealise links (independent outcomes, one address
   per carrier, no libp2p dial concurrency); real rows L1-L4 close that gap.
8. The nearby encounter goes through `custody::encounter`, which a nearby
   pipe coming up calls; Phase 5's encounter wiring (P5.33) must keep
   calling it.
9. The C72 baseline is this build's: a deliberate change of today's order
   (route memory, the static plan) must update it.
10. No CI workflow runs s100-s106 yet (`RAVEN_FAULT_LEARNING=1` is opt-in),
    `learn-flaky` has not run on Linux, and the CI evidence of every
    learning row waits for GitHub Actions (§8.3). Meanwhile the 6a
    checkpoint (P6.20) is to run the fault scenarios on macOS.

## 11. Before any flip

- The learning waiver ([`WAIVER_LEARNING_DRAFT.md`](../WAIVER_LEARNING_DRAFT.md))
  signed by the Protocol owner after real rows L1-L4. LAN direct is live in
  release, so the flip changes release LAN behaviour (shorter waits, LAN
  probes) even though nothing on the wire changes (OD6a-12).
- The simulator gate, C70-C74 on their runners, s100-s106 and the netns
  advisory case green; the release inert test green.
- `LEARNING_PRODUCTION_ENABLED` flipped alone, in its own reviewed commit,
  with this document's status line updated.
