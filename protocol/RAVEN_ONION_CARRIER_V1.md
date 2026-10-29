# RAVEN Onion Carrier V1: Tor onion services as a Raven carrier

**Version:** 1. Parts: the onion binding (§3), the onion route name (§4), the Raven link
with the Noise prologue `raven/onion-link/v1` (§5), the local helper protocol (§6), the
card field (§7), the RRH1 entry (§8), the outbox race (§9).

**Status:** Draft. Production is disabled (`ONION_PRODUCTION_ENABLED = false`, raven-core
`onion_gate.rs`). Lab only: debug builds with `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_TOR=1`;
release builds read neither variable. A security notice can hold `feature/onion`.

**Design:** [`docs/design/2026-10-tor-fallback.md`](../docs/design/2026-10-tor-fallback.md)
(owner approval 2026-10-28: Tor as the universal baseline, raced against the direct paths).

**Companions:** [`RAVEN_CARRIER_CONFORMANCE_V1.md`](RAVEN_CARRIER_CONFORMANCE_V1.md) §3.2 and
§11.9; [`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §4 and §15.

**Audience:** re-implementers of the onion carrier.
**Reference:** Rust `raven_core::onion` (binding, route name), `raven_core::onion_gate`,
raven-node `src/onion/` (helper protocol, supervisor, race), `src/bin/raven-tor-helper/`
(Arti), and the vector `shared-vectors/rvn1/onion/binding_001.json` (§11).

---

## §0 Scope and layering

```
Tor: v3 onion service of the receiver, Tor client of the sender (both outbound only)
  -> one Tor stream to the service's virtual port 7422
  -> Raven link: Noise_XX_25519_ChaChaPoly_BLAKE2s, prologue "raven/onion-link/v1",
     RIH1 hello, contact gate, RLB1, dispatch frames
     (byte-identical to Internet direct except the prologue)
  -> unchanged sealed endpoint objects and ACKs
```

- Tor is a pipe. Its link class is `OPAQUE_CIRCUIT` (Conformance §3.2): the two Raven
  devices terminate the Raven link; Tor relays carry Tor cells around Raven-Noise ciphertext
  and are no participant.
- Nothing above the Raven link changes: no envelope, session, PairInit or ACK byte.

## §1 Gate

- `ONION_PRODUCTION_ENABLED = false`. Lab: `RAVEN_LAB_TOR=1` with the Lab Test A unlock, debug
  builds only. `RAVEN_LAB_TEST_A=1` alone never opens it.
- With the gate closed a node starts no Tor helper, publishes no onion service, makes no onion
  dial, prints no `onion=` card field and sends no RRH1 ONION entry. Its plans are exactly those
  of a build without the carrier.

## §2 Roles

- **Service:** every node with the gate open publishes one v3 onion service (nickname `raven`)
  and accepts streams on virtual port **7422** only (a number in the onion service's own address
  space; nothing binds it on any computer). Other ports and non-BEGIN requests get `END` with
  reason `DONE`.
- **Client:** every node dials its verified contacts' onion services over Tor.
- Both stay up while the node runs (the "universal baseline"); client circuits exist only while
  there is something to send (§10).

## §3 The onion binding

A node binds its onion service key to its Raven identity:

```
signing_input = "RAVEN-ONION-BIND-V1" || 0x00 || hs_id[32] || raven_pub[32] || issued_s (u64 BE)
binding       = hs_id[32] || issued_s (u64 BE) || sig[64]        (104 bytes)
sig           = Ed25519(raven identity secret, signing_input)
```

- `hs_id` is the onion service's Ed25519 identity public key (`KP_hs_id`, the 32 bytes a
  `.onion` address encodes). `raven_pub` is the node's Raven identity key (the key its contacts
  pin). `issued_s` is Unix seconds when it was signed.
- **Verification** (receiver, against the contact's pinned key `P`): `hs_id` is a valid,
  non-small-order Ed25519 point; `issued_s <= now + 86400`; the signature verifies strictly
  (RFC 8032 with the strict rules of every Raven signature: no weak key, canonical `s`) over
  `signing_input` with `raven_pub = P`.
- **Never trust an unsigned onion address.** A binding that does not verify is dropped, wherever
  it came from. It is verified when it is learned and again when a route is planned from it.
- **Newest wins.** Of two bindings that verify for one contact, the one with the higher
  `issued_s` is used; an older one never replaces a newer one.
- The binding is public: it says "this Raven identity runs this onion service" and nothing about
  where either is (an onion address carries no IP).
- The signing input never starts with the AgentSign delegation prefix (`0x00 0x17 ...`).

## §4 The onion route

The outbox names an onion route `onion:<64 lowercase hex of hs_id>` (carrier `onion_dial`).
Parsers accept exactly that prefix and 64 lowercase hex digits naming a usable key. The route
is derived live for each plan from a verified binding (§3) and never stored in
`outbox_routes.json`; only the helper (§6) turns a key into a `.onion` address.

## §5 The onion link

- One Tor stream per link, to virtual port 7422.
- The Raven link of Internet direct with the Noise prologue **`raven/onion-link/v1`**:
  `Noise_XX_25519_ChaChaPoly_BLAKE2s`, the RIH1 hello (caps as Internet direct), the contact gate
  (verified, unblocked contacts only, stranger timing parity), RLB1 both ways, then frames. The
  distinct prologue means no TCP, libp2p, nearby or onion transcript completes against another.
- No RLK1 knock (it is about a TCP source address; an onion stream has none).
- Route hints (RRH1, caps bit 8), link padding (PAD1) and the update exchange (RUP1) are offered
  as on Internet direct.
- Inbound limits: 16 links; each rendezvous circuit (the helper's circuit number, §6) counts as
  one source (Tor hides who dialled): at most 4 links per circuit, 2 of them before
  authentication. A full listener closes the oldest pre-authentication link of the circuit holding
  the most to admit a link of a less busy one. The helper's token is checked before any of these
  slots is taken. Noise message 1 must start within 10 s of the stream; handshake deadline 30 s;
  lifetime 180 s; 64 frames.
- The helper tears down a rendezvous circuit that opens more than 8 streams at once, and asks
  its introduction points to pass on at most 5 introductions per second (burst 20; the
  EST_INTRO DoS extension).
- Dial waits: connect (the Tor circuit to the service) 45 s; whole dial 75 s; frame I/O 30 s;
  first reply 30 s; idle reply 5 s.

## §6 The local helper protocol

Tor runs in a helper process (`raven-tor-helper`, Arti), never in the node. The node starts it
and talks to it over three channels:

1. **Control (stdin/stdout, one JSON object per line, at most 4096 bytes).**
   - Node to helper, first line: `{"v":2,"state_dir":"<profile>/tor","token":"<64 hex>",
     "forward":"127.0.0.1:<port>","port":7422,"fresh_state":false}`.
   - Node to helper, later: `{"cmd":"ping","n":N}`, `{"cmd":"self_check","n":N}`,
     `{"cmd":"stop"}`.
   - Helper to node: `{"ev":"progress","pct":0-100[,"blocked":"<word>"][,"stage":"<word>"]}`,
     `{"ev":"ready","connect":"127.0.0.1:<port>"}`, `{"ev":"onion","hs_id":"<64 hex>"}` (once),
     `{"ev":"service","state":"shutdown|bootstrapping|degraded_reachable|degraded_unreachable|
     running|recovering|broken"[,"reason":"<phrase>"]}`, `{"ev":"pong","n":N}`,
     `{"ev":"error","what":"<fixed text>"[,"local":true]}`.
   - `blocked` is one of `offline`, `filtered`, `clock_skewed`, `cant_reach_tor`, `directory`,
     `disabled`, `other` (never Arti's free text).
   - `stage` is one of `connecting`, `no_internet`, `handshaking`, `no_handshake` (no Tor relay
     has answered a handshake yet), `waiting`, `consensus`, `certificates`, `microdescriptors`,
     `usable` (relays answered; the directory is loading), `stuck`, `other`. A node reads an
     unknown word as `other`; a line without `stage` is an older helper.
   - `reason` is Arti's current service problem as one fixed phrase: `descriptor upload
     failed`, `descriptor upload timed out`, `descriptor upload retries ran out`, `intro point
     failed`, `intro point stopped answering`, `intro point left the directory`, `service
     error` (a node reads anything else as `other problem`; never Arti's text).
   - The node settles service states before it logs or shows them: the first reachable state
     (running, degraded_reachable) at once; after that, while reachable, `bootstrapping` is a
     descriptor republish (the published descriptor still works) and not a loss; a change of
     reachability counts once it held 60 s. A friend's authenticated incoming onion link proves
     the service reachable at once (until the helper's own state says reachable, or 10 minutes
     without another such link). The service state gates no send.
   - `local: true`: the error's cause is on this computer (its folder, its clock, the helper
     itself), not the network. Absent means false.
   - The helper answers `ping` from its start, not only once ready.
   - `self_check`: the helper's own Tor client reaches its own onion service as a friend would
     (a new isolation group for each try: a fresh descriptor, new circuits; within one 44 s
     connect wait and its second try) on virtual port 9, which the service refuses with END
     (DONE); that answer proves the descriptor, an introduction point and a rendezvous worked,
     and nothing reaches the node. It answers `{"ev":"self_check","n":N,"reached":true|false
     [,"reason":"<connect reason>"]}` (reasons as the connect reply's: `no descriptor`,
     `service not running`, `rendezvous failed`, `tor timeout`, `no circuit in time`, `not
     bootstrapped`, `tor connect failed`).
   - `{"ev":"uploads","ok":N,"of":M}`: one descriptor upload round ended, N of the M HSDirs that
     needed the descriptor took it (counts only, read from Arti's own debug line; never which
     relays).
   - The node's evidence rule: the latest self-check or friend's authenticated incoming onion
     link younger than 10 minutes says whether the service is reachable, whatever the service
     state says; the service state saying reachable is newer news. Self-checks: 3 minutes after
     the service was launched, or 45 s after the first upload round that HSDirs took if that
     comes sooner (each helper run, so also after a network change), then every 30 minutes
     while they reach it, every 10 minutes while they fail, and 30 s after the state reports
     trouble (not within 10 minutes of the last).
   - The helper exits when its stdin closes.
2. **Outbound (loopback TCP to `connect`).** The node writes `token[32] || hs_id[32] ||
   port (u16 BE)`; the helper answers `status u8 || reason_len u8 || reason` (status 0 open,
   1 not ready, 2 unreachable, 3 timeout, 4 failed; reason printable ASCII, at most 120 bytes,
   never an address), then the stream carries the bytes. A wrong token is closed without a byte.
3. **Inbound (loopback TCP to `forward`).** For every accepted onion stream the helper connects
   to the node's forward listener and writes `token[32] || circuit (u64 BE)`; then the stream
   carries the bytes. `circuit` is an opaque number the helper gives each rendezvous circuit of
   its service: the same for every stream on that circuit, never reused within one helper life,
   and it says nothing about who dialled. The node reads this header before it takes any
   admission slot (at most 32 connections may wait for it; one more closes the oldest), and
   closes a connection without the token within 10 s, before any Raven byte.
   (Version 2 of this local protocol; version 1 sent `token[32]` alone. Node and helper ship
   together and refuse each other's other version.)

The token is 32 random bytes per helper life. Only ephemeral loopback ports are used.

## §7 The card field

`raven whoami --card` adds `onion=<binding>` (§3, base64url without padding, 139 characters) to
a `raven-card/2` or `raven-card/3` while the gate is open and the node's binding exists. A reader
of this version accepts the field once, on `/2` and `/3`, and refuses the card when the binding
does not verify against the card's own `pub_hex`. Readers built before this field refuse such a
card (an unknown field); `raven whoami --card --compat` leaves it out. The contact book keeps it
in the contact's row (`onion`).

## §8 The RRH1 entry

RRH1 entry type `0x40 ONION` carries the 104-byte binding (§3);
[`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §15 has the rules.

## §9 Plan order and the race

- Plan order: LAN and Bluetooth nearby, IPv6 and IPv4 direct, hole punching, a friend relay (the
  p2p carrier), **Tor**, then custody and waiting. The onion route is planned last (after
  nearby), above the per-object route cap, only for a verified contact, only while the gate is
  open and the helper is ready. "Hide my IP" does not drop it.
- **Race.** An outbox attempt with an onion route and any other route dials the direct routes
  at once, one after the other, and the onion route on its own after a head start of 1.5 s (at
  once when every direct route already failed, or failed for a send within the last 2 minutes).
  Each dial claims the attempt when the contact's
  RLB1 offer was read and verified, right before its first frame; a dial whose other side
  already claimed it writes nothing and ends `RACE_LOST`, which is neither a route failure nor
  learning evidence. A losing dial still in flight is cut.
- Frames a direct route could not carry (a send limited to one carrier) go over Tor after the
  race, unraced.
- **Moving off Tor.** Links are per dial; every attempt races again with the direct paths' head
  start, so a direct path wins as soon as it works.
- **A send's probes** (`raven send`, the desktop app) race every route: the frame-less RLB1
  probes of the direct routes start 300 ms apart in plan order (each at once when every one
  before it failed), Tor's after the head start or at once when every direct one failed; the
  first that answers carries the message. The head start applies only while a direct route is
  likely to answer: the contact had an authenticated LAN link with this node in the last 10
  minutes from an address on one of this computer's networks now, and has told no new routes
  over another carrier since; or the plan puts a remembered p2p or Internet route first;
  otherwise Tor's probe starts with the others. A probe carries no frame, so two at once never
  send twice. A send of a message that can be queued leaves out of its race the routes that
  failed within the last 2 minutes (each route forgotten when it answers, Tor's also when any
  Tor link with the contact works or this computer's own onion service self-check succeeds),
  and is queued at once without probing when every route did. Tor's failure counts only while
  the contact's Raven is known stopped (its computer refused the LAN dial at an address on this
  computer's network), or while the node's outbox already carries a message to the contact
  and Tor did not reach it in the last 2 minutes (or still dials it): anywhere else Tor stays in
  the race. Such a send waits for Tor's probe at most 25 s (a first message, which needs the
  answer, Tor's full wait); past it the message is queued and the outbox tries Tor first, at
  once, with Tor's full wait.
- **The message after the probe.** The message goes on a connection of its own, over the route
  whose probe answered. Over Tor, one that fails within 30 s is tried once more at once (the
  same sealed envelope: a copy that arrived twice is answered as a duplicate); a slower failure
  is left to the outbox.
- **A second connect.** Within one connect request (44 s) the helper tries once more after a
  failure worth it (no descriptor, service not running, introduction or rendezvous failed, Tor
  timed out) when at least 14 s are left: 2 s later, in a new isolation group, so the client
  fetches the descriptor again and builds new circuits instead of using what it cached of the
  service before the friend's node restarted. Nothing else differs (same guards, same
  anonymity).
- **Deadlines.** An onion dial of the outbox or of friend custody ends at
  `ONION_DIAL_DEADLINE` (75 s) plus 5 s, not at a direct dial's 45 s.
- **Friend custody** (WAN custody only, `RAVEN_FRIEND_CUSTODY_V1.md`): a mail friend's onion
  route is planned last for a deposit, a hand-on (custody handoff) and a fetch; a LAN-only
  custody offer drops it, as it drops Internet and p2p routes.

## §10 Cost when idle

- The service stays published (introduction circuits, descriptor uploads).
- Client circuits come only from outbox attempts that carry a message or an owed ACK, custody
  deposits and hand-ons (they carry mail), and custody fetches that are likely to find mail: the
  last round at that mail friend brought some, the friend just linked to this node, or no fetch
  there went over Tor for 30 minutes. The route-hints announcer, session renewal's own probes,
  the learning prober and the update exchange plan no onion route.
- A rendezvous circuit is kept by Arti for 10 minutes after its last use, then closed.
- Channel padding `reduced`.

## §11 Vectors

`shared-vectors/rvn1/onion/binding_001.json`: the RFC 8032 test-1 identity ("alice") binds the
onion key of RFC 8032 test 2's public key at `issued_s = 1792756800`; the signing input, the
104-byte binding and its card text. Written by Rust under `RAVEN_REGEN_SECURITY_VECTORS=1`
(`raven_core::onion` tests).

## §12 Privacy and what users are told

- Neither friend learns the other's IP on this path. The first Tor relay (guard) of each side
  sees that side's IP and that it uses Tor, not who it talks to.
- Anyone who holds a card can tell when its owner's onion service is online.
- Logs carry states and counts only: never a friend's onion address, never the node's own, and
  never Arti's own text.
- The user text is design §3.8.

## §13 Not in V1

Restricted discovery (client authorization), the onion route for the other background dials
(announcer, renewal, learning prober), proof-of-work, bridges and pluggable transports (not
designed, by decision), phones.
