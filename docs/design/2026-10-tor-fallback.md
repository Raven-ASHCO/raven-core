# Tor onion services as Raven's universal internet baseline (lab)

| | |
|---|---|
| **Status** | Designed and built behind its gate, lab only. Nothing here is enabled in a release build. |
| **Gate** | `ONION_PRODUCTION_ENABLED = false` (`node/crates/raven-core/src/onion_gate.rs`). Debug builds open it per process with the Lab Test A unlock (`RAVEN_LAB_TEST_A=1`) plus `RAVEN_LAB_TOR=1`; release builds never read either variable. |
| **Build** | The Tor helper (`raven-tor-helper`, Arti inside) is built only with the cargo feature `tor` of `raven-node`. Without it the carrier still builds and is tested against a loopback helper. |
| **Decision** | Owner approval 2026-10-28 (Tor onion services, new dependency Arti, lab first), changed the same day from "last resort" to "universal baseline, always on, raced against the direct paths". |
| **Related** | the any-network reachability plan (not published) (D1: no project-run servers), [`RAVEN_ONION_CARRIER_V1.md`](../../protocol/RAVEN_ONION_CARRIER_V1.md) (wire and rules), [`RAVEN_ROUTE_HINTS_V1.md`](../../protocol/RAVEN_ROUTE_HINTS_V1.md) §15 (ONION entry), [`RAVEN_CARRIER_CONFORMANCE_V1.md`](../../protocol/RAVEN_CARRIER_CONFORMANCE_V1.md) §11.9 (onion profile), research: `reports/Raven serverless internet reachability research - part 2.md` §3 (outside the repository). |
| **Date** | 2026-10-28 |

## 1. The problem

The market is desktops only (macOS, Windows, Linux). Two friends in two
different places must be able to message with zero setup, whatever the two
networks are: Wi-Fi to Wi-Fi, Wi-Fi to a phone hotspot, hotspot to hotspot.

Field measurement RX0 (2026-10-28) on a phone hotspot: carrier NAT that is
endpoint dependent (symmetric), no port preservation, no IPv6. Two peers
behind such NATs can never connect directly or by hole punching without a
third machine both can reach. Raven runs no servers (D1), and a friend's
reachable machine (friend relay, custody) exists only in some circles.

Tor onion services are a third party that already exists, needs no Raven
server and no account: both sides only make outbound connections to Tor
relays, so any NAT works.

## 2. Decision

**Every raven-node runs one onion service and a Tor client, all the time**
(lab gate open). Its onion address is signed by the node's Raven identity
and travels in every card and every route hint, so every friend can always
reach every friend over Tor.

**Tor is a pipe, never a trust root.** The onion stream carries the same
Raven Noise link as Internet direct (same code: RIH1 identity bind, contact
gate, RLB1 offers, ATSAM sessions, PairInit, sealed ACKs). Only its Noise
prologue differs (`raven/onion-link/v1`) so a transcript made over Tor can
never complete against the TCP listener or the reverse, and its Noise
static: a key of the onion link's own (`RAVEN_ONION_CARRIER_V1` §5.1), so
what anyone holding a card reads from message 2 over Tor matches no LAN or
Internet listener. Tor authenticates
nothing for Raven; the Raven handshake authenticates the friend.

**Every send races the paths** ("happy eyeballs"):

1. The direct paths start at once, in plan order: LAN and Bluetooth nearby,
   IPv6 and IPv4 direct, hole punching, a friend relay (whatever the plan
   holds for this contact; the automatic public-address discovery and
   hole punching of branch `feature/auto-reach` only add routes to it).
2. The Tor path starts after a head start of 1.5 s for the direct ones, or
   at once when every direct route has already failed.
3. Whichever path first completes the Raven handshake (the friend's RLB1
   offer read and verified) claims the attempt and writes the frames. The
   other one closes without writing a frame.
4. Custody (a friend holds the mail) and waiting come after both, as today.

**A card's LAN name races too** (N3, security and speed report 2026-11-05;
`raven send`). A LAN name from a friend's card keeps the local-network
rule, so it must be resolved before it is dialled. While the send has a
route on another carrier (Tor, for a verified friend), the name is not
resolved before the race (that took up to 5 s, one name after the other):
its own probe in the race resolves it within
`raven_core::outbox::LOCALIZE_RACE_TIMEOUT` (1.5 s, as long as Tor's head
start) and dials the resolved local address, for the probe and then the
message. A name that does not answer in time fails that route alone, as a
name not found. A card's LAN address that may not be dialled (off the local
network, or not a usable `host:port`) fails that route alone too, never
dialled; before, both cases ended the whole send as NOT SENT though Tor
could carry it. With no other carrier (an unverified contact, or LAN only)
the send is as before: names resolved first, within 5 s, and a refusal is
the send's.

**Moving off Tor.** Raven links are per dial (a dial connects, sends,
collects the receipts and closes). Every send runs the race again with the
head start for the direct paths, so as soon as a direct path works it wins,
and the delivery line says so: `direct (moved off Tor)`.

## 3. Architecture

### 3.1 Process split: Arti runs in `raven-tor-helper`

Arti (the Rust Tor implementation) runs in its own process, started and
supervised by raven-node. raven-node never links Arti.

Why a process boundary:

- **`exit(1)` inside the library.** arti-client 0.47 calls
  `std::process::exit(1)` when a consensus marks its protocol version as
  required-but-missing (`client.rs`, `enforce_protocol_recommendations`,
  Arti issue #1932). There is no option to turn it off. In-process it would
  end raven-node; in a helper it ends the helper, and raven-node says
  "Tor: blocked (this Tor version is too old for the network)".
- **Hangs that spin.** Arti issue #2726: Windows bootstrap stuck at 15 %
  with one core at 100 %. A task that never yields cannot be cancelled from
  inside the process; a helper can be killed.
- **Panics and memory.** A panic or a runaway allocation in Arti stays in
  the helper.
- **Build cost.** Arti adds about 240 crates. raven-node, ash and their
  tests compile exactly as before unless the `tor` feature is asked for.

The local protocol (spec §6) is small:

- **Control: stdin and stdout, JSON lines.** raven-node writes one config
  line (state directory, a random 32-byte token, its forward address, the
  onion virtual port). The helper answers with events: `progress` (bootstrap
  percent and Arti's "blocked" text), `ready` plus its connect address,
  `onion` (the service's public key, once), `service` (Arti's reachability
  state), `error`. It exits when stdin closes, so a killed raven-node never
  leaves a helper behind.
- **Outbound: loopback TCP with the token.** raven-node connects to the
  helper's `127.0.0.1:<ephemeral>` port, sends the token and the target
  (onion key and port), and gets one status byte; then the bytes flow.
- **Inbound: loopback TCP with the token.** For every accepted onion stream
  the helper connects to raven-node's forward port (`127.0.0.1:<ephemeral>`),
  sends the token, then the bytes flow into the Raven link listener for the
  onion carrier. A local process without the token is closed before any
  Raven byte.

Only ephemeral loopback ports are bound; no Raven port, no public port.

### 3.2 The onion service key and its binding to the Raven identity

- Arti generates the onion service key on first start and keeps it in its
  keystore under `<profile>/tor/` (nickname `raven`). The address is stable
  for the profile.
- At rest (security review 2026-11, KS-1 and TOR-7): the keystore
  (`tor/state/keystore/`) holds that key and the intro points' keys in
  clear, in Arti's own files (owner only). The at-rest registry calls each
  file there an unsealed key, and `raven erase` writes zeros over it before
  it deletes the helper's folder at every depth. Keeping the key sealed and
  handing it to the helper only in memory is the owner's decision (OD-T3);
  until then the exposure is listed in THREAT_MODEL §3.7a (T3a).
- raven-node signs a **binding** with its Raven identity key:
  `"RAVEN-ONION-BIND-V1" || 0x00 || hs_id_pub[32] || raven_ed_pub[32] ||
  issued_s u64`. The binding on the wire is `hs_id_pub[32] || issued_s u64
  || sig[64]` (104 bytes; base64url without padding in a card).
- A friend uses an onion address **only** with a binding that verifies
  against that friend's pinned key (strict Ed25519). An unsigned address,
  or one signed by anyone else, is dropped. It is checked when learned and
  again whenever a route is planned from it.
- A newer binding (higher `issued_s`) replaces an older one; an older one
  never replaces a newer one. A new key (a lost Tor state directory)
  gets a fresh binding, told to friends by route hints on the next link.
- Not derived from the identity seed: supplying our own key to Arti needs
  its `experimental-api` feature, which has no stability promise. Owner
  decision OD-T3 lists the trade-off (a restored profile gets a new onion
  address).
- **The onion link pin** (protocol §5.1). The binding names the onion
  service key, not the onion link's Noise static, and Tor authenticates only
  that key. So whoever copies the key (it is in `<profile>/tor/`) could answer
  at the address and read the dialer's static and signed hello before the
  dialer reads the listener's hello. Each node therefore pins each contact's
  onion link static after the first verified onion link (either side
  dialled), as a keyed digest in its Noise pin store (sealed in a sealed
  profile), and a dial that meets another static stops after Noise message 2
  (`NOISE_PIN_MISMATCH`). It is pinned again by the contact's own verified
  onion link, by a newer binding naming another onion key (a fresh card, or
  route hints on any link), and by removing the contact. The static comes from
  the identity seed, so a friend restored from its seed (new onion address,
  same static) is never stopped. No wire change.

### 3.3 Where friends learn it

- **Card.** `raven whoami --card` adds `onion=<binding base64url>` to a
  `raven-card/2` or `raven-card/3` while the gate is open and the service
  key exists. `raven contact add --card` checks the signature against the
  card's own `pub_hex` (a card whose binding does not verify is refused) and
  keeps it in the contact book row. Readers built before this field refuse
  such a card ("unknown field"); `raven whoami --card --compat` leaves it out.
- **Route hints.** RRH1 entry `0x40 ONION` carries the same 104 bytes on
  every authenticated link (LAN, Internet, p2p, nearby, onion). Kept only
  from a verified contact and only when the signature verifies against the
  link's authenticated key, in the same contact book row (`onion`) when it
  is newer than the one there: sealed with the book at rest, gone with the
  contact. One place for both sources; no new file or at-rest kind.
- The planner reads the row's binding and checks its signature again.
- `raven send --carrier onion` (lab: refused with ONION_HOLD unless the gate is open, so a
  debug build with the Tor switch; a verified contact with `--contact` only) plans the onion
  route alone and records the choice `onion` (an outbox record value an older build leaves
  as it is): the outbox retries it over Tor only. Field tests can so test Tor between two
  computers on one LAN.
- `raven send` and the desktop app's send plan the onion route too (an
  IPC `OnionDial`, so a send can pair and deliver over Tor itself). Their
  route probes race: the direct routes 300 ms apart (each at once when the
  ones before it failed), Tor's probe after the 1.5 s head start (at once
  when the direct ones all failed), the first that answers carries the
  message (probes carry no message, so two at once never send twice; field
  test S15: a stale LAN address cost 8 s per send before). E2 r9: the head
  start only for a friend raven-node had a LAN link with in the last 10
  minutes, or a remembered p2p or Internet route first (IPC
  `ContactReach`); a send whose every route failed in the last 2 minutes,
  with no sign of the friend since, queues at once. E2 r40: a Tor failure
  leaves Tor out only while the friend's Raven is known stopped (its
  computer refused the LAN dial here); each route's failure goes with its
  own answer, Tor's also with any Tor link to the friend or our own
  self-check; a LAN sighting counts only at an address on our networks now
  and goes when the friend tells new routes over another carrier; the
  outbox starts Tor at once after the direct routes failed for a send; a
  message dial over Tor that fails right after Tor answered the probe is
  tried once more. A send that can queue waits for Tor's probe 25 s, not
  Tor's 75 s, and leaves Tor out while the outbox already carries a message
  to that friend and Tor did not reach it lately (the user never waits
  twice). When the send cannot
  finish, the outbox keeps racing, with Tor's dial deadline (80 s, not the
  45 s of a direct dial). A first message to a contact with no session needs the long
  horizon lab switch (`RAVEN_LAB_HORIZON=1`) to wait for pairing instead of
  "meet first".

### 3.4 Route plan and the race

The onion route is derived live for each plan (`onion:<64 hex of the onion
key>`) like the nearby route, never stored in `outbox_routes.json`, never
cut by the per-object route cap, and planned last (after nearby). It needs:
the gate open, a verified contact (as for Internet direct and p2p), a
binding that verifies, and a running helper. "Hide my IP" (D4) does not drop
it: Tor hides the IP.

The worker (`node/crates/raven-node/src/outbox.rs`) runs the race inside
one attempt:

- With an onion route and at least one other route, the onion dial runs on
  its own thread; the direct routes are dialled one after the other on the
  worker thread, as before.
- The claim (`crate::onion::race`) is taken in `ReplyCollector::begin`,
  the one point every Raven link passes when the friend's offer was read
  and verified, right before the first frame. A dial that loses closes with
  `RACE_LOST` and writes nothing. A lost dial is not a route failure: no
  failure count, no learning sample, no "contact did not answer".
- When the onion side wins, the direct dial still in flight is cut at once.
  When a direct side wins, the onion dial is cut (if Tor is still building
  the circuit, Arti finishes or drops it on its own).
- Frames a direct route could not carry (a send limited to LAN, say) still
  go over Tor after the race, as a plain dial.

Duplicates: the race makes them rare (only one side writes), but even two
writes of the same object are harmless: the bytes are exact, the receiver
deduplicates by object, and conformance §10.3 allows small direct hedging.

### 3.5 Timeouts sized for Tor

| Wait | Direct (today) | Onion |
|---|---|---|
| Head start of the direct paths | - | 1.5 s (`ONION_HEAD_START`) |
| Connect (Tor circuit to the service, rendezvous) | 5 s per address, 20 s per dial | 45 s (`ONION_CONNECT_BUDGET`); first contact is typically 10-30 s. Within it the helper tries once more, at once after a timeout (once Arti has the rendezvous circuit, it waits 6 s for the stream's CONNECTED, not its default 10 s) and 2 s after any other failure (no descriptor, not running, introduction or rendezvous failed), with 12 s or more left for it, in a new isolation group (fresh descriptor, fresh circuits): field test round 8, the first sends to a friend whose node had just restarted failed on the client's cached view of the old service. A fresh try that works makes its group the friend's for the connects that follow in that helper life, and a first try that timed out is never made in its group again (audit T6: Arti hands every connect of one group the same rendezvous circuit while it looks open, a dead one too, so each dial paid the timeout, the pause and a new rendezvous); a friend unused for 10 min is back in the default group. With the hedge gate open (§3.6, lab only) a first try with no stream after 2 s gets the fresh try beside it, and after a failed link the first try goes in a new group |
| Whole dial | 40-45 s | 75 s (`ONION_DIAL_DEADLINE`) |
| Frame I/O | 30 s | 30 s |
| First reply / idle reply | 30 s / 2 s | 30 s / 5 s |
| Inbound handshake deadline | 10 s | 30 s (a Tor RTT is 0.3-0.7 s; three handshake messages plus RLB1 over a fresh circuit) |
| Bootstrap watchdogs | - | no new progress for 120 s up to 15 % (the consensus download reports nothing until done) or 60 s after; 5 min cap; then "blocked on this network" or "could not start on this computer" (§3.7) |

### 3.6 Cost when idle

- The onion service stays published: intro circuits and a descriptor upload
  every 1-2 hours. That is the "always reachable" part.
- No client circuit is opened without something to send. Tor dials come
  from outbox attempts that carry a message or an owed receipt (and `raven
  send`), and from friend custody: a deposit or a hand-on carries mail, so
  it may always go over Tor; a fetch poll at a mail friend goes over Tor
  only when the last round there brought mail, the friend just linked to
  this node, this node's Tor has just become usable (a new helper life's
  first ready, Tor relays answering after a ready from Tor's cache, or our
  own Tor working again after a failed self-check: every mail friend is
  asked then, once), or no fetch there went over Tor for 30 minutes
  (`ONION_FETCH_EVERY`). A pass that finds no route to a mail friend at
  all (Tor not ready yet, or this rule) counts as no round there, so it
  does not stretch the friend's poll interval. The route-hints announcer,
  session renewal, the learning prober and the update exchange never plan
  the onion route, so they cannot keep circuits busy.
- After a delivery Arti keeps the rendezvous circuit for 10 minutes after
  its last use (`tor-hsclient`, `RETAIN_CIRCUIT_AFTER_LAST_USE`): a chat
  burst reuses one warm circuit (one Tor round trip per dial instead of a
  new rendezvous), and an idle friend costs nothing after that.
- Channel padding is set to `reduced` (laptops on battery; research §3.4:
  padding is most of Tor's idle cost on 4G).
- **W1, kept links** (Tor speed Stage A, security and speed report
  2026-11-05 §7, speed design M1; gate `ONION_WARM_PRODUCTION_ENABLED =
  false`, lab only, §4). With the warm gate open, a program's send over Tor
  (`raven send`, an app's engine, over IPC) keeps its link open after a
  batch that got every reply it waited for, for the next batch to the same
  friend: within 20 s of the last batch (`WARM_IDLE`, below the listener's
  30 s read deadline), 120 s of the link's dial (`WARM_AGE`, below the onion
  listener's 180 s lifetime) and 56 frames (`WARM_FRAMES`, below its 64); 4
  links at most, 2 on the embedded node, one per friend. The message then
  rides its check's link (a first send costs 4 round trips instead of 7),
  and a send within 20 s costs one, its check answered from the kept link
  with the friend's offer and no traffic. Nothing is opened with nothing to
  send. A kept link is written and read by a task of its own, so no wait
  stops part way through a frame, and a link whose wait ran out is never
  kept. Up to 3 batches ride one kept link at once (pipelining, speed design
  M8, `PIPELINE_DEPTH`): the task writes each batch's frames behind those
  of the batches before it and hands the replies out first in, first out
  (the listener answers frame after frame, each reply before it reads the
  next frame), so a burst of k messages costs about one round trip each
  from its own write, not k round trips for the last. A batch that ends any
  other way (its wait ran out, the link closed, its dial was cut) closes the
  link, and the batches behind it go again on a fresh link: a reply is
  never taken for another batch's, and an ACK is only ever counted for the
  message it names. The dial's
  checks run again before every batch; a keeper closes the link of a friend
  blocked, removed or no longer verified within a second, and all of them
  once the gate is shut (a hold); a lock, a network change, the end of a
  Tor helper's life and the embedded node's pause close them all. The
  listener is unchanged (`raven-node/src/onion/warm.rs`).
- **Hedge and fresh first** (speed design M5; gate
  `ONION_HEDGE_PRODUCTION_ENABLED = false`, lab only, §4). With the hedge
  gate open the dialer asks the helper for flags with each connect (the
  local helper protocol's version 3, `RAVEN_ONION_CARRIER_V1.md` §6): a
  hedge, so a first try in the friend's isolation group that has no stream
  after 2 s (`CONNECT_HEDGE_AFTER`; a healthy BEGIN takes one round trip)
  gets a fresh try in a new group beside it, the first stream winning and
  the other try dropped; and fresh first, after a link to that friend failed
  where the helper cannot see it (no link came up, a batch got no reply in
  its wait, a kept link died before any reply) within 10 minutes: the first
  try then goes in a new group at once. On the loopback model (one round
  trip r, a rendezvous R, Arti's 6 s wait for CONNECTED on a dead circuit)
  a send past a dead circuit costs 2 s + R + 4r with W1 instead of
  6 s + R + 7r, and R + 4r after a failed link. With the warm gate open
  too, a batch on a kept link with no reply within the longer of 2 s
  (`BATCH_HEDGE_FLOOR`) and 3 times that link's last round trip (the batch
  hedge) closes the link and goes again on a fresh one, fresh first; the
  friend answers the copy of a message it holds as the same message, with
  the same ACK. On the loopback model a message on a kept link whose
  circuit died with no word then costs 3r + R + 4r (with a 1r trip) instead
  of its whole reply wait and no ACK. The price: one more introduction (and
  maybe a descriptor fetch) at the friend's service when a hedge fires.

### 3.7 Robustness around Arti's known gaps

| Gap (research part 2 §3.2) | What Raven does |
|---|---|
| `exit(1)` on an obsolete version (#1932) | Process boundary (§3.1). raven-node restarts the helper with backoff and says so in the status line. |
| Windows bootstrap hang at 15 % (#2726) | Fixed at the source: `saturating-time` 0.5.0 (used by `tor-netdoc` while it checks the consensus) searches for the `SystemTime` limits and never ends on Windows (100 ns clock ticks). Raven builds a patched copy (`node/third_party/saturating-time-0.5.0-raven`, `[patch.crates-io]`); CI runs its termination tests on Windows. Kept as a backstop: the progress watchdog (no new progress for 120 s up to 15 %, 60 s after) and a ping during bootstrap (no answer for 60 s: the helper hung). Field test S15 found the old 45 s window also cut slow consensus downloads. |
| No sleep or network-change handling (#2705, #594) | raven-node's network watcher (`netwatch.rs`) already detects a wake from sleep, an address change and a moved default route. Each one restarts the helper. Arti's cached directory makes that a warm start (seconds). A network gone with nothing in its place (no network added, the default route not seen moving) restarts it only if it stays gone 30 s: a short address blip restarted healthy helpers, and their next lives started with no descriptor or circuit (Tor messaging audit 2026-11, T12). |
| Guard state that can poison itself (#2534) | After 3 bootstraps in a row that end stuck, the helper is started once with a fresh `state` subdirectory (guards only; keys and cache are kept). |
| Minutes until a new service is reachable | The service starts with the node, not with the first message. The status line says "starting" until Arti reports the service reachable. |
| Panics | Process boundary. |
| Hang | A helper that stops answering the control channel's pings for 60 s (from its start, not only once ready) is killed and restarted. |
| Slow first publish on slow links (field test round 8: win-c, Wi-Fi with double NAT, 7-9 min from ready to reachable; Macs 13-72 s) | Nothing safe to tune in Arti 0.47. Intro points are published after at most about twice the fastest one's set-up time (`ipt_mgr.rs`), so they are not the delay. The descriptor goes to every HSDir of both time-period rings (8 + 8) with retries up to 5 min each (`OVERALL_UPLOAD_TIMEOUT`, not configurable), and Arti reports "bootstrapping" until every upload of a ring has finished: one slow HSDir holds "reachable" back for up to 5 min although the descriptor can already be fetched from the others. Fewer intro points (`num_intro_points`, default 3) would not publish faster and would make the service less robust. Vanguards: see the next row. |
| "degraded_unreachable, descriptor upload timed out" while idle (field test round 9: win-c 12 times in 433 min, 88 min in all; mac-b 4 times in 457 min; mac-a never) | What Arti 0.47 means by it (`tor-hsservice` publish/reactor.rs): the service uploads a descriptor only to the HSDirs of each time-period ring that need one ("dirty": new in the ring after an hourly consensus, or whose last upload failed, or all of them when the descriptor changed or every 60-120 min), and each round's results replace that ring's. `upload_result_state` says `degraded_unreachable` when one ring's latest round had no success at all (or fewer than two rings are known). So a round of one new HSDir that timed out (5 min, `OVERALL_UPLOAD_TIMEOUT`) is enough, while the other HSDirs of that ring still hold the earlier descriptor: a descriptor lives 3 h (its lifetime is the intro point set's, `IPT_PUBLISH_UNCERTAIN`), and Arti keeps every intro point until the last descriptor naming it expired (`ipt_mgr.rs`). Friends try several HSDirs of the ring (Arti: up to 6 fetch attempts) and find one with it. It is a real loss only when most of a ring missed the current rounds for hours or the intro points failed (`recovering`). Raven measures instead of trusting the word: self-checks and friends' links (next rows); and it logs every round's counts, "descriptor upload round: N of M HSDirs took it", so a field reader sees rounds that failed from this uplink (counts only, never which relays). Bridges and pluggable transports are out of scope by decision. |
| Measuring reachability (round 9) | Self-check: the helper's own Tor client reaches our service as a friend would (a new isolation group each time: fresh descriptor, new circuits) on virtual port 9, which the service refuses with END: that answer proves descriptor, intro point and rendezvous; nothing reaches raven-node. 3 min after launch (or 45 s after the first upload round HSDirs took, if sooner: E2 r40, after a network change `raven status` learnt it 3 min late), then every 30 min while it reaches the service (two an hour), every 10 min while it fails, and 30 s after Arti reports trouble but not within 10 min of the last (six an hour at most). The latest self-check or friend's authenticated incoming Tor link younger than 10 min says whether friends can reach us, whatever Arti says; Arti saying reachable is newer news. Privacy: lite vanguards on both sides; the HSDirs and intro points see one more fetch and introduction of our own key, as from any friend; logs say only reached / not reached and a fixed reason. |
| Outage history (round 9) | `raven status` keeps the onion service's outages since raven-node started, across helper restarts: while one goes on, "unreachable for N min (why; onion service outages since start: K)"; afterwards, "Tor: ready (onion service outages since start: K, the last lasted N min and ended M min ago)". |
| Guard discovery against the onion service (an attacker who makes the service build many circuits learns its guard) | Owner decision 2026-10-29: the helper is built with Arti's `vanguards` feature, as Arti's own `arti` program is (privacy first, a slower publish accepted). The mode is Arti's default, `auto`, which is **lite** in Arti 0.47: a small long-lived set of second-hop relays (layer 2) for every onion circuit, client and service, with the same circuit lengths (`G -> L2 -> M`), as C Tor does for every onion service. The consensus parameter `vanguards-hs-service` asks for full vanguards (a fourth hop) for services, but Arti 0.47 does not read it yet (Arti #1382); with `auto` the helper follows Arti when it does. No new crate (Cargo.lock unchanged); the feature is pure Rust, no platform code. |

Bootstrap is bounded (watchdogs above). A start that ended is blamed on
one side, from the helper's last words (a fixed stage word with each
progress event, Tor's blockage word, `local` on helper errors):

- **the network** when no Tor relay answered a handshake, or Tor says
  `offline`, `filtered`, `cant_reach_tor` or `directory`: "Tor: blocked on
  this network", retried with backoff (30 s doubling to 10 min);
- **this computer** when the helper crashed (a panic on its stderr), hung
  (no pong), said a local error (its folder, damaged files, another Tor on
  the folder, configuration, internal), Tor's clock check failed, or the
  start got stuck after Tor relays answered (#2726's shape): "Tor: could
  not start on this computer (<short reason>)", retried with backoff (5 s
  doubling to 10 min).

Each ended helper leaves one log line of last words (percent, stage, Tor's
word, the helper's error tag, pings answered); each new stage during a
start is one log line. Raven does not try to get around a block: no
bridges, no pluggable transports, Arti's defaults only (plus Arti's
vanguards, lite, see the table above).

**Status line** (`raven status`, the node log, the terminal app):

- `Tor: off` (gate closed) or `Tor: not built in this raven` (no helper);
- `Tor: starting (45 %)`;
- `Tor: ready` (onion service published and reachable), `Tor: ready (onion service
  publishing)` until it first is, `Tor: ready, onion service unreachable (Arti: <state>,
  <reason>)` after a loss that held 60 s. Arti says `bootstrapping` for every descriptor
  republish and intro point change (field test r34: about 20 times an hour on one Wi-Fi with
  double NAT, once in 85 minutes on Ethernet) while the published descriptor still works: the
  node logs and shows only settled changes (first reachable at once, any later change once it
  held 60 s), and nothing (no send, no inbound link) waits on our own service's state. A
  friend's authenticated incoming Tor link proves the service reachable at once, whatever Arti
  says yet (field test round 8: Arti reported win-c "bootstrapping" for minutes while it
  finished uploads), until Arti agrees or 10 minutes pass without another such link;
- `Tor: blocked on this network (no Tor relay answered; retrying in 2 min)`;
- `Tor: could not start on this computer (stuck at 15 % after Tor relays answered; retrying in 20 s)`;
- `Tor: restarting (network changed)`.

**Logs** carry states and counts only: never a friend's onion address,
never our own (the card carries ours). The helper does not forward Arti's
own log lines.

- **A ready helper whose onion service stays unreachable is started again.**
  None of the watchdogs above ends a ready helper that answers its pings, so
  a service whose introduction points went stale or whose uploads kept
  failing stayed unreachable until the next network change, and friends fell
  back to custody or waited. raven-node now starts Tor again ("Tor: restarting
  (our onion service stayed unreachable)": no backoff, no failure, guard
  state kept) when the helper has been ready 12 min or more, its last 2
  self-checks in a row failed or went unanswered, the service does not read
  reachable, no friend reached it over Tor within 10 min, and this device has
  a network (the app's report or netwatch); at most once per 30 min and 4
  times per 6 hours. A service stuck from the start is restarted about 12-14
  min after ready; a later loss about 10 min after the first failed
  self-check.
  The new life publishes again on fresh circuits, from Arti's cache (seconds
  to a minute); Tor streams in flight are dropped. The same rules hold in the
  iPhone app while it is in front; a paused node runs no helper.

### 3.8 What the user is told (privacy wording)

Shown by `raven status --explain tor` and in the docs:

> **Connecting through Tor.** When your computer and your friend's cannot
> reach each other directly, Raven sends your messages through the Tor
> network instead. Your friend does not see your IP address on that path,
> and you do not see theirs. Tor relays carry only encrypted bytes; they
> cannot read your messages, and your messages stay end-to-end encrypted
> between you and your friend as on every other path. The first Tor relay
> your computer uses sees your IP address and that you use Tor, but not who
> you talk to. Anyone who has your card can tell when your computer is
> online over Tor.
>
> **What it costs.** Tor is slower: the first message to a friend can take
> 10 to 30 seconds, later ones about a second. Raven keeps a small amount
> of Tor traffic going while it runs, so that friends can reach you. Some
> networks block Tor; Raven then says "Tor: blocked on this network" and
> uses the other paths.

## 4. Gates, switches and builds

| Item | Value |
|---|---|
| Production gate | `ONION_PRODUCTION_ENABLED = false`; feature `feature/onion` in the suite registry (a security notice can hold it). |
| Lab switch | `RAVEN_LAB_TOR=1` with `RAVEN_LAB_TEST_A=1`, debug builds only. Closed under `RAVEN_LAB_NEARBY_ONLY=1`. |
| Cargo feature | `tor` (raven-node): builds `raven-tor-helper`. |
| Helper path | Next to `raven-node`; debug builds may override it with `RAVEN_TOR_HELPER=<path>`. |
| Loopback helper (tests) | Debug builds only: `RAVEN_LAB_TOR_LOOPBACK=<directory>` makes raven-node run `raven-node tor-loopback-helper` instead: the same local protocol, with "onion services" that are loopback TCP ports registered in that directory. No Tor network. Its warm circuit model, for the dry mode of the D1 harness (`scripts/tor_d1_harness.py`, below; read only with `RAVEN_LAB_TEST_A=1`): `RAVEN_LAB_TOR_LOOPBACK_RENDEZVOUS_MS=<ms>` adds a fresh rendezvous (R) to the first connect per isolation group and onion key, and `RAVEN_LAB_TOR_LOOPBACK_KEPT_MS=<ms>` drops a circuit no connect was handed for that long, so the next connect pays R again (Arti keeps one for 10 minutes after its last use). |
| Head start | `RAVEN_LAB_TOR_HEAD_START_MS` (debug only, tests) overrides 1.5 s. |
| Stage record | Debug builds only (speed groundwork for the D1 measurement, security and speed report 2026-11-05 §7): every onion dial's step times in memory, as durations only (`prep`, `connect` with its `circuit` and `begin` parts, `noise`, `hello`, `write`, `receipt`, `total`; never a key, an onion id, an address or a message). `RAVEN_LAB_TOR_STAGES=<absolute path>` with `RAVEN_LAB_TEST_A=1` appends one JSON line per dial (0600); the D1 harness reads the lines each send adds. Arti gets the circuit and opens the stream in one call, so `circuit` and `begin` split the helper's connect by the one round trip rule (BEGIN to CONNECTED takes as long as the Noise round trip that follows on the same circuit). Release builds keep nothing. |
| D1 harness | `scripts/tor_d1_harness.py` (security and speed report 2026-11-05 §7): two fresh locked-file debug profiles in a new lab folder, a sender and a friend, each with its own raven-node and Tor helper on random free 127.0.0.1 ports, friends over Tor only (cards with `onion=` alone, verified both ways; route hints, friend relays, STUN, port mapping, the NAT class, punching, nearby, the LAN beacon and WAN custody closed with their lab switches). It times sends through the engine for the cases WL, WC, PW, CN, CI and ER and the A/A run, base against patched in ABAB blocks (the patched arm sets Stage A lab switches on the sender only; every gate stays false), and writes one JSON line per run with durations, counts and fixed words only (`d1-runs.jsonl`). `analyze` prints the median and p90 per case with their 95% rank intervals and applies the claim rule. Its dry mode (the default) runs over the loopback helper with simulated r and R and checks that every socket of its processes stays on loopback; its real mode refuses to start without `--real-tor` and `RAVEN_D1_OWNER_OK=1`. `--self-test` (CI) needs no build, no process and no network. |
| Tor speed, Stage A | Five more gates, every one false, each open only while the onion carrier is, with its lab switch (with `RAVEN_LAB_TEST_A=1`, debug builds only) and a hold of its own in the suite registry: `ONION_WARM_PRODUCTION_ENABLED` (`RAVEN_LAB_TOR_WARM`, `feature/onion-warm`: W1 kept links and their pipelining, §3.6), `ONION_HEDGE_PRODUCTION_ENABLED` (`RAVEN_LAB_TOR_HEDGE`, `feature/onion-hedge`: the connect hedge, fresh first and, with the warm gate, the batch hedge, §3.6), `ONION_EARLY_PRODUCTION_ENABLED` (`RAVEN_LAB_TOR_EARLY`, `feature/onion-early`), `ONION_OPTIMISTIC_PRODUCTION_ENABLED` (`RAVEN_LAB_TOR_OPTIMISTIC`, `feature/onion-optimistic`) and `ONION_WARM_LINK_PRODUCTION_ENABLED` (`RAVEN_LAB_TOR_WARM_LINK`, `feature/onion-warm-link`: W2, a wire change). Only W1 with its pipelining, the connect hedge with fresh first and the batch hedge (§3.6) act yet. |

## 5. Tests

Automated tests never touch the real Tor network.

- Unit: binding encode, decode, sign and verify (wrong key, tampered,
  unsigned, older binding), card field, RRH1 entry, planner (onion last,
  above the cap, kept under hide-IP, verified contacts only, gate), race
  claim, timeouts, helper protocol, supervisor (bootstrap budget, progress
  watchdog, exit and restart backoff, network change).
- In-process: two profiles exchange a sealed message and its receipt over
  the onion link through the loopback engine.
- Process: two `raven-node service` processes with the loopback helper and
  no other route deliver both ways; the delivery line says `via Tor`.

The real-network check is the field test (§7).

## 6. Not in this step

- Restricted discovery (client authorization): only friends could even
  reach the descriptor. Needs Arti's experimental API (OD-T2).
- The onion route for the route-hints announcer, renewal and the learning
  prober.
- Proof-of-work DoS defence (LGPL code, experimental in Arti).
- Bridges and pluggable transports: not designed, by decision.
- Phones.

## 7. Field test (three machines, real Tor)

Machines: **M** = a laptop on a phone hotspot (symmetric carrier NAT), **W** =
a laptop behind two routers (double NAT), **S** = a third computer as an
observer only (it is not a contact of either, so no friend relay or custody
can help). No port forwards. Fresh test profiles; never `~/.raven`.

1. Build on M and W from `feature/tor-fallback`:
   `cargo build -p raven-node -p ash --features raven-node/tor` (Windows:
   `set CARGO_INCREMENTAL=0` first, as in `node/WINDOWS.md`).
2. Environment on both, every shell:
   `RAVEN_LAB_TEST_A=1 RAVEN_LAB_TOR=1 RAVEN_LAB_ROUTE_HINTS=1
   RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file
   RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file
   RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1 RAVEN_DATA_DIR=<test profile>`.
3. Start the service with test ports (for example `--lan-listen
   0.0.0.0:17520`, no Internet listener, no p2p). Note the time.
4. `raven status` every 10 s until `Tor: ready`. Record the bootstrap time
   (start to `ready`) and the time to "service reachable".
5. Exchange cards (`raven whoami --card`; the card carries `onion=`), add
   each other with the 10 security words read aloud.
6. M sends 10 messages to W, one every 30 s; then W sends 10 to M. Record
   for each: time to "delivered", the path shown (`via Tor` expected), and
   the first message's time separately (first connection).
7. Both sleep the laptop for 5 minutes, wake, send 2 messages each way:
   record the restart line and the time to delivery.
8. Move M from the hotspot to Wi-Fi and back once while W sends: record the
   restart line and delivery.
9. Put M and W on the same Wi-Fi: send 2 messages each way; expected path
   `direct (moved off Tor)` on the first, `direct` after.
10. Collect from each node log: `Tor:` state lines, restarts, counts. No
    onion address may appear in either log (`grep -c onion` on addresses).

Pass: 20/20 delivered over Tor in step 6, the first within 60 s, later ones
within 10 s each; steps 7-9 deliver without a manual restart.

## 8. Risks

- **Reachability is not guaranteed.** Peer-to-peer users of onion services
  report minutes before a new service is reachable, and stuck services
  (research §3.3). The field test measures it on these networks.
- **Blocked networks.** OONI shows 13-16 % Tor-test anomalies on the home
  ISP's network (heuristic, not confirmed blocking). Raven then has no
  serverless path between two such networks.
- **Arti's stability.** Monthly releases with breaking changes; the minimum
  Rust version moves; no dedicated audit of Arti; its onion service code is
  younger than C Tor's. Versions are pinned exactly; an upgrade is a
  reviewed step.
- **Presence.** Anyone holding a card can tell when its owner is online
  (descriptor and intro point answers). Same class as an Internet direct
  address today, without the IP.
- **A copy of the onion service key.** It is kept in the clear under
  `<profile>/tor/` (sealing it waits on OD-T3). With the onion link pin
  (§3.2) a copy answers no pinned dial; still open: the first onion dial
  to a contact before any verified onion link, and the first after a binding
  naming another onion key, can be answered by a copy holder, who then reads
  the dialer's identity (a binding that also names the static would close
  this; it changes the wire).
- **Resource use.** One published service keeps intro circuits up; desktop
  CPU and memory for this are unmeasured (field test step 10 adds them).
- **Duplicates.** Possible only when both paths complete the handshake at
  the same moment and the claim is lost to a crash; harmless (exact bytes).

## 9. Owner decisions

- **OD-T1 Process split.** Arti runs in `raven-tor-helper`, supervised by
  raven-node (recommended; the only way to contain Arti's `exit(1)` and
  spinning hangs). Alternative: in-process, with those risks.
- **OD-T2 Restricted discovery.** Turn on client authorization (only
  friends can reach the descriptor), which needs Arti's experimental API
  and a per-friend key exchange in cards and hints. Recommended later,
  after the field test.
- **OD-T3 Key from the identity seed.** Derive the onion key from the
  Raven identity so a restored profile keeps its onion address. Needs
  Arti's experimental API. Recommended: no for now.
- **OD-T4 Card field.** `onion=` makes older readers refuse a card; a new
  card version (`raven-card/4`) would make the break explicit. Recommended:
  keep the field (lab only) and decide the card version before release.
- **OD-T5 Production.** A waiver, an external review of the carrier and the
  helper, and the field test before `ONION_PRODUCTION_ENABLED` can flip.
