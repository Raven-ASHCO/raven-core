# Phase 5 real rows (operator checklist): custody handoff

**Status:** owner-run, **open**. The checklist for the Phase 5 rows of
multi-hop custody (custody handoff, "two friends in a row"); results go to
`node/proof_artifacts/p5-<ROW>-<UTC>/` (git-ignored) with public IPs redacted,
and are attached to the signature record of the waiver draft that names the
row. The rows come from the Phase 5 multi-hop design
(`docs/roadmap/plans/phase45-design.json`), which calls them "R18" and "R19"
(its earliest draft "R15" and "R16"); Phase 2 holds R15-R20 and Phase 4 R25-R27,
so they are R28 and R29 here. The Bluetooth rows N1-N12 have their own runbook.

| Row | What | Waiver draft | Section |
|---|---|---|---|
| R28 | LAN mule: a friend's laptop carries a message between two offline Wi-Fis (the plan's R18) | [`WAIVER_FRIEND_CUSTODY_HANDOFF_DRAFT.md`](WAIVER_FRIEND_CUSTODY_HANDOFF_DRAFT.md) §7 | 3 |
| R29 | WAN chain: two laptops on phone hotspots, never online together (the plan's R19) | the internet amendment the same draft asks for (§7 there) | 4 |

## 0. Purpose and honest claim

- Real networks and real machines. Every `*_PRODUCTION_ENABLED` gate stays
  `false`, `CUSTODY_HANDOFF_PRODUCTION_ENABLED` included: the rows run debug
  builds of this tree with the lab switches, exported in the shell on every
  machine before every command:
  - `RAVEN_LAB_TEST_A=1` (friend custody's lab unlock), `RAVEN_LAB_ROUTE_HINTS=1`
    (the friends ride route hints) and `RAVEN_LAB_CUSTODY_HANDOFF=1`;
  - R28 only: `RAVEN_LAB_LAN_BEACON=1` (nearby search, no address typed);
  - R29 only: `RAVEN_LAB_CUSTODY_WAN=1` and the p2p switches of the friend
    custody rows ([`P3_REAL_ROWS_CHECKLIST.md`](P3_REAL_ROWS_CHECKLIST.md)
    section 5, R10).
  Release builds never read these switches. Nothing here flips a gate.
- Software stand-ins do not replace these rows: carrier_matrix C54 and C55 and
  lan_fault_matrix s68-s71 and s97b (`RAVEN_FAULT_HANDOFF=1`) run every node
  on one computer's loopback.
- **Test homes only** (a `--data-dir` you created for the row, or
  `RAVEN_WAN_HOME`, default `~/raven-wan-test`), never `~/.raven`, a live
  profile or a profile an older binary still uses: a build of this tree seals
  a profile at its first start (a debug build only with `RAVEN_LAB_AT_REST=1`),
  and older builds then refuse it. On a machine that runs another Raven node,
  give the test node a free LAN port and record it.

## 1. Who is who

- **Alice** (A) and **Bob** (B): the two ends. They never pin a common friend
  as custodian.
- **Fred** (F1): Alice's friend. Pins Alice and Gina, never Bob.
- **Gina** (F2): Bob's friend. Pins Bob and Fred, never Alice.
- Alice pins Gina and Bob pins Fred **by key only** (verified, no address):
  a custodian tag in route hints is pair-blinded, so Alice can read Bob's
  announced Gina only as one of her own contacts. Nobody dials a friend it
  pinned by key only.
- Consents: on Fred and Gina `raven node custody on` and `raven node custody
  handoff on`; Alice `raven contact set-addr --tag bob --custodian @fred`, Bob
  `raven contact set-addr --tag alice --custodian @gina`.
- Before the row: Alice and Bob exchange one message each way while all four
  are up (their session; each registers its tags at its own friend:
  `raven node custody status` on Gina shows `registered tags: N` with N >= 1,
  and Bob's route hints then carry Gina with HANDOFF_INBOX to Alice).

## 2. Record for every row

`node/proof_artifacts/p5-<ROW>-<UTC>/` holds:

- `row.txt`: the row, the date, the commit under test, who ran it, the OS of
  each machine, each network by kind only (home Wi-Fi with its WAN unplugged,
  phone hotspot, VPS provider), the switches exported;
- `raven node custody status` of Fred and Gina after each step (counts only:
  `passing on: N waiting, N handed on, N refused`), `raven outbox status` of
  Alice's message, `raven inbox` of Bob (the message text only);
- the counts-only daemon lines the row names (`left 1 with a friend to pass
  on`, `handed on 1 kept 0 refused 0 dropped 0`, `fetched messages=1`,
  `fetched messages=0 acks=1`), with every PeerId, label and public IP
  replaced;
- `raven doctor` of Alice and Bob: the `offline_delivery:` line counts the
  other under `two_friends=`;
- the pass or fail against the bar below, and anything that surprised you.

## 3. R28: LAN mule (no internet)

- Two Wi-Fis with no internet (routers with their WAN unplugged, as R11a), far
  enough apart that no laptop sees both. Wi-Fi 1: Alice and Fred (a laptop).
  Wi-Fi 2: Gina and Bob.
- With Bob's laptop closed (or his node stopped), Alice sends 10 messages:
  each is `held by 1 friend`; Fred's status shows `passing on: 10 waiting`
  (Gina is not reachable from Wi-Fi 1).
- Alice leaves. Fred's laptop is carried to Wi-Fi 2: Fred's node finds Gina
  (nearby search) and hands the 10 on (`handed on 10`); Gina holds them.
- Bob comes back on Wi-Fi 2 and fetches them from Gina. His ACKs go back
  through Gina to Fred (Gina's status `handed on 10`), Fred's laptop goes back
  to Wi-Fi 1, and Alice, back, fetches the ACKs from Fred.
- Pass: Bob has each message exactly once, 10/10; Alice's outbox says
  delivered for each, only after the ACKs; no address was typed; neither
  laptop of Alice or Bob was ever on Wi-Fi 2 or Wi-Fi 1 respectively; no line
  of any daemon names an address, key or name.

## 4. R29: WAN chain (two hotspots, never online together)

Needs friend custody over the internet (`FRIEND_CUSTODY_WAN_ENABLED`'s lab
switch) and is evidence for the internet amendment only.

- Fred: an always-on computer at home (the D15 Mac Studio); Gina: a VPS
  custodian (a Raven node with an identity, not the relay kit). Alice and Bob:
  two laptops on two different phone hotspots, each reaching its own friend
  over p2p (a relay or direct).
- Alice sends 10 messages while Bob's laptop is off, then turns hers off.
  Fred hands them on to Gina within a few minutes (`handed on 10`).
- Bob turns his laptop on (Alice still off): he fetches the 10 from Gina; his
  ACKs go back through Gina to Fred. He turns his laptop off; Alice turns hers
  on and fetches the ACKs from Fred.
- Pass: 10/10 exactly once; Alice's outbox says delivered for each; Alice and
  Bob were never online at the same time (record both laptops' on and off
  times); the friends' logs name no address, PeerId or key.
