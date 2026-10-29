# Phase 6a real rows (operator checklist): learning connectivity

**Status:** owner-run, **open**. The checklist for the Phase 6a rows L1-L4;
results go to `node/proof_artifacts/p6a-<ROW>-<UTC>/` (git-ignored) with
public IPs redacted, and are attached to the signature record of
[`WAIVER_LEARNING_DRAFT.md`](WAIVER_LEARNING_DRAFT.md) (§7 there). The rows
come from the Phase 6a design
([`design/2026-10-learning-connectivity.md`](design/2026-10-learning-connectivity.md)
§8; `docs/roadmap/plans/phase6-design.json`, design "Phase 6a", testing
"Owner real rows").

| Row | What | Section |
|---|---|---|
| L1 | A cafe or guest Wi-Fi with an unreliable LAN path: 20 sends with learning on against 20 with it off | 3 |
| L2 | The same contact from home and from the office for 2 days: a different order on each network | 4 |
| L3 | A friend relay switched off at midday: the circuits through the other relay go first | 5 |
| L4 | Two Macs and a carrier laptop with no internet for 2 days (custody lab): mail left with the friend you meet | 6 |

## 0. Purpose and honest claim

- Real networks and real machines. Every `*_PRODUCTION_ENABLED` gate stays
  `false`, `LEARNING_PRODUCTION_ENABLED` included: the rows run debug builds
  of this tree with lab switches, exported in the shell on every machine
  before every command:
  - every row: `RAVEN_LAB_LEARNING=1` (the "off" runs use `raven learning
    off`, never a different build) and `RAVEN_LAB_AT_REST=1`, so the test
    profile is sealed and `learning.bin` is saved (in a plain profile learning
    stays in memory only and starts empty at each node start);
  - L1 and L2: `RAVEN_LAB_TEST_A=1` (the lab unlock that lets the contact be
    reached over the internet as well: Internet direct, or p2p through a
    relay as in [`P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md`](P1_REAL_ROWS_R3_R5_R9_R14_CHECKLIST.md));
  - L3: the friend relay switches of
    [`P2_REAL_ROWS_CHECKLIST.md`](P2_REAL_ROWS_CHECKLIST.md) section 5
    (`RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_ROUTE_HINTS=1`,
    `RAVEN_LAB_FRIEND_RELAY=1`);
  - L4: the custody switches of
    [`P3_REAL_ROWS_CHECKLIST.md`](P3_REAL_ROWS_CHECKLIST.md) section 0
    (`RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_ROUTE_HINTS=1`) plus
    `RAVEN_LAB_LAN_BEACON=1` (nearby search, no address typed).
  Never `RAVEN_LAB_LEARNING_TUNE`: the rows run the real gaps, budget and
  half-life. Release builds never read these switches. Nothing here flips a
  gate.
- Software stand-ins do not replace these rows: the simulator gate
  (`node/crates/raven-core/tests/learning_sim.rs`), carrier_matrix C70-C74,
  lan_fault_matrix s100-s106 (`RAVEN_FAULT_LEARNING=1`) and the netns case
  `learn-flaky` run on one computer or one kernel.
- **Test homes only** (a `--data-dir` you created for the row, or
  `RAVEN_WAN_HOME`, default `~/raven-wan-test`), never `~/.raven`, a live
  profile or a profile an older binary still uses: with `RAVEN_LAB_AT_REST=1`
  a build of this tree seals the profile at its first start, and older builds
  then refuse it. On a machine that runs another Raven node, give the test
  node free ports and record them.

## 1. Gear

- L1: two laptops (A and B) and a cafe, hotel or guest Wi-Fi where the LAN
  path between two guests is unreliable (client isolation that comes and
  goes, a weak access point, a busy evening), plus a route from A to B over
  the internet that does not use the guest LAN: p2p through a relay (the P1
  checklist's relay R).
- L2: laptop A that goes between home and an office (two networks with
  different private addresses), and B, a computer that stays at home and is
  reachable from the office over the internet (Internet direct to a forwarded
  port, or p2p through a relay).
- L3: A, B behind a NAT holding two friend relays (R1 and R2, two operators
  as in the P2 checklist's R13), all on different networks.
- L4: two Macs (Alice and Bob) and a carrier laptop (Fay), and two Wi-Fi
  networks with no internet (routers with their WAN unplugged, as row R11a),
  far enough apart that no laptop sees both. A fourth test profile (Gus) on a
  machine that stays off or out of reach during the row.

## 2. Record for every row

`node/proof_artifacts/p6a-<ROW>-<UTC>/` holds:

- `row.txt`: the row, the date, the commit under test, who ran it, the OS of
  each machine, each network by kind only (home Wi-Fi, office Wi-Fi, cafe
  Wi-Fi, phone hotspot, router with its WAN unplugged), the switches exported;
- for every send: the time, `raven send`'s outcome with `RAVEN_VERBOSE=1`
  (the `carrier=` and `path=` it ends with, and any `lan_dial ... did not
  answer; trying ...` line), its duration in seconds, with every address,
  PeerId and key replaced (`<lan-b>`, `<peer-1>`);
- `raven learning status` (names are the test profiles' petnames) and
  `raven doctor`'s `learning:` and `learning_row_<n>` lines after each block
  of sends (they carry no name, key or address; check that they do not);
- the receiver's `raven inbox` (message texts only) to count each message
  exactly once, and `raven outbox list` / `raven outbox status <id>` of any
  message that waited;
- **the three numbers every row reports**, for each run:
  - **duration**: the total and the slowest send time;
  - **duplicates**: messages whose frames went out on a second route after a
    first route carried them without an answer (a `NO_ACK_YET` attempt in
    `raven outbox status`, or two dial lines with frames in the verbose
    output); the receiver still shows each message once;
  - **probes per hour**: the change of `probes_24h` (`raven learning status
    --json`) over the run, divided by its hours; at most 6, never a frame
    (a probe is never a send of yours);
- the pass or fail against the bar below, and anything that surprised you.

## 3. L1: a cafe or guest Wi-Fi with an unreliable LAN path

- A and B on the same guest Wi-Fi; A pins B (verified) with B's LAN address
  on that Wi-Fi and an internet route (as in section 1). One message each way
  first, so the session is up.
- 40 numbered messages A to B, one every 30 s, in 8 blocks of 5: off, on,
  off, on, ... (`raven learning off` / `raven learning on` on A between
  blocks), so both runs see the same Wi-Fi. Before each send of an off block
  run `raven learning reset --yes` on A: it also clears the lab route memory,
  so the off run is today's static order (as fault scenario s100 does).
- If no off-block send paid a LAN wait (the LAN path never failed), the row
  is void: repeat it on another network or at a busier hour.
- **Pass:**
  - each of the 40 messages arrives exactly once;
  - the on blocks' total send time is at most 0.6 times the off blocks', and
    their slowest send is no slower than the off blocks' slowest;
  - fewer on-block sends than off-block sends pay a LAN wait;
  - at most 2 duplicates in each run;
  - at most 6 probes per hour, none with a frame;
  - `raven learning status` gives B a sentence naming the LAN that did not
    answer (or "the usual order" after the LAN worked again).

## 4. L2: home and office, the same contact, for 2 days

- B stays at home on the home Wi-Fi. A pins B with B's LAN address at home
  and its internet route. One message each way first, at home.
- For 2 days A goes between home and the office (morning there, evening
  back). On each arrival A sends 5 numbered messages to B, one a minute.
- At the office B's LAN address does not answer (it is the home network's),
  so learning should put the internet route first there; at home the LAN
  stays first.
- After each block: `raven learning status`, `raven learning status
  --json` (the row of B: `order`, `why`; replace B's key with `<peer-1>`) and
  `raven doctor`'s learning lines.
- **Pass:**
  - from the second visit to each network on, the first send there goes by
    that network's own first carrier without paying the other's wait: at the
    office no LAN wait (Internet or p2p first), at home LAN first and
    delivered over the LAN;
  - B's row reads differently on the two networks (internet first at the
    office, the usual order at home), and stays so across the days;
  - each message exactly once; duplicates and probes per hour recorded (at
    most 6 probes per hour, none with a frame);
  - no line of either node, and no `raven doctor` line, names an address,
    a network or a key.
- If home and office hand A the same private address, the two networks share
  one learning bucket (OD6a-13): record it and repeat with a network that
  hands out another address.

## 5. L3: a friend relay switched off at midday

- B behind a NAT holds R1 and R2 as friend relays (P2 checklist section 5);
  A (no relay of its own) pins B and reaches B only over relayed circuits
  (record `path=relayed`). Morning: one message A to B every 15 minutes for
  2 hours (both relays up).
- At midday R1's operator stops R1's node (or closes the lid) and leaves it
  off for the afternoon. One message A to B every 15 minutes for 3 hours.
- Next day, the same with `raven learning off` on A (learning reset first),
  for the comparison.
- The order of circuits inside one dial is not visible from outside (libp2p
  tries two addresses at once; carrier_matrix C74 checks the order in a unit
  test): the row measures the time to receipt and the path.
- **Pass:**
  - every message arrives exactly once, `path=relayed`;
  - from the third afternoon send on, the send time is within 1.5 times the
    morning's median and no slower than the learning-off afternoon's median;
  - learning starts no relay change: B logs no `relay replaced` beyond Phase
    2's own replacement of R1 after its loss timer (at most one), and A's log
    has no `relay chosen` or `relay replaced` line at all;
  - `raven learning status` on A counts at least 2 relays; at most 6 probes
    per hour, none with a frame; duplicates recorded.

## 6. L4: two Macs and a carrier laptop, no internet, 2 days (custody lab)

- **Who:** Alice and Bob (the two Macs) never share a network during the
  row. Fay (the carrier laptop) and Gus are friends of both, verified by
  everyone. Gus's machine stays off or out of reach for the whole row.
- **Consents** (the setup of fault scenario s105): Fay and Gus `raven node
  custody on`; Alice `raven custody use on` and `raven custody home @fay`
  (she collects her own mail from Fay), and lists Fay for Bob (`raven contact
  set-addr --tag bob --custodian @fay`); Bob lists Gus for Alice (`raven
  contact set-addr --tag alice --custodian @gus`), so his route hints
  announce Gus to her. Alice's candidates for Bob are then Gus (announced)
  before Fay (listed), the static order. Before the row, all four meet once
  on one network: Alice sends one message to Gus, to Fay and to Bob, and Bob
  one to Alice.
- **Off part (half a day):** `raven learning off` on Alice. Alice on Wi-Fi 1
  with Fay; Bob on Wi-Fi 2. Alice sends 3 messages to Bob: the queued text
  names Gus then Fay, and Fay takes the copy (Gus is away).
- **On part (2 days):** `raven learning on` on Alice (reset first). Each
  morning Fay is on Wi-Fi 1 with Alice (Alice fetches and sends while they
  meet); each evening Fay is carried to Wi-Fi 2, where Bob fetches from her
  and his ACKs go back through her. Alice sends 3 messages each morning.
- **Pass:**
  - from the second morning on, Alice's queued text says "Left with Fay
    first (you meet often" and names at most 2 friends; the deposit goes to
    Fay first;
  - each message reaches Bob exactly once, through Fay, and Alice's outbox
    says delivered for each, only after the ACK came back;
  - no internet at any time (record the routers' WAN unplugged), no address
    typed after the first meeting;
  - at most 6 probes per hour on Alice, none with a frame; duplicates
    recorded; Alice's `raven learning status` counts at least one
    mail-friend record;
  - no line of any node names an address, key or name.
- Offline networks share one learning bucket (`none`, OD6a-13): record
  whether Alice's order learned on Wi-Fi 1 looked wrong on another offline
  network. If it did, owner decision OD6a-13 option (b) (a fingerprint of the
  local subnets) is the follow-up.
