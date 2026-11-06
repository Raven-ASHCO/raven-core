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
`raven_core::lan_noise::derive_onion_noise_static` (the link's static, §5.1), raven-node
`src/onion/` (helper protocol, supervisor, race), `src/bin/raven-tor-helper/` (Arti), and the
vectors `shared-vectors/rvn1/onion/binding_001.json` and `noise_static_001.json` (§11).

---

## §0 Scope and layering

```
Tor: v3 onion service of the receiver, Tor client of the sender (both outbound only)
  -> one Tor stream to the service's virtual port 7422
  -> Raven link: Noise_XX_25519_ChaChaPoly_BLAKE2s, prologue "raven/onion-link/v1",
     the onion link's own Noise static (§5.1), RIH1 hello, contact gate, RLB1,
     dispatch frames (byte-identical to Internet direct except the prologue
     and the static)
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
- The Tor speed Stage A gates (`onion_gate::ONION_WARM_PRODUCTION_ENABLED` and four more, all
  false; lab switches `RAVEN_LAB_TOR_WARM` and so on with the Lab Test A unlock, debug builds
  only; a hold each) open only while this one is. Only W1 with its pipelining (§10), the connect
  hedge with fresh first and the batch hedge (§6, §9) act yet; none changes a frame.

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
- Both ends use the onion link's own Noise static (§5.1), never the device static.
- No RLK1 knock (it is about a TCP source address; an onion stream has none).
- Route hints (RRH1, caps bit 8), link padding (PAD1) and the update exchange (RUP1) are offered
  as on Internet direct.
- Inbound limits: 16 links; each rendezvous circuit (the helper's circuit number, §6) counts as
  one source (Tor hides who dialled): at most 4 links per circuit, 2 of them before
  authentication. A full listener closes the oldest pre-authentication link of the circuit holding
  the most to admit a link of a less busy one, however young that link is. A circuit that lost a
  pre-authentication link (closed for a newcomer, or ended before it authenticated) gets no slot
  in a full listener, and so closes no link, for the rest of the helper's life; the node forgets
  these circuits at each new token (§6), and keeps at most 4096 of them, the oldest forgotten
  first. A contact holds at most 4 authenticated links: a newer one that authenticates closes
  that contact's oldest (TOR-2). The helper's hello (§6) is checked before any of these slots is
  taken. Noise message 1 must start within 10 s of the stream; handshake deadline 30 s; lifetime
  180 s; 64 frames.
- **What the inbound limits defend, and what they do not.** Anyone who holds the card can open
  streams to the service. Defended: such a stranger cannot keep a friend out with silent or
  stalled streams, however young: a friend's link on a circuit new to the listener closes the
  oldest pre-authentication link of the busiest circuit. Streams the stranger opens on circuits it
  holds, or held and lost a link on, close no friend's link before it authenticates (a lone
  pre-authentication link on its circuit), and an authenticated link is never closed for a
  stranger's. One contact, or whoever holds its key, holds at most 4 of the 16 slots with
  authenticated links, so those cannot keep another friend out (TOR-2); its links before they
  authenticate are a stranger's. Not defended (TOR-1 is only partly closed): each circuit the
  stranger never used in this helper life closes one pre-authentication link of a full listener
  (the busiest circuit's oldest), so a stranger who opens enough of them (at most 16) while a
  friend's handshake runs (about three Tor round trips) closes the friend's link; each one costs
  it an introduction (5 per second per introduction point, burst 20, shared with friends). A
  friend whose link was closed, or ended before it authenticated (a dial the race cut, §9), is
  refused on that circuit while the listener is full. Closing these needs a proof that the dialer
  is a friend before a slot is given (a change to the link's first message) or restricted
  discovery (§13): owner decisions, not in V1.
- The helper tears down a rendezvous circuit that opens more than 8 streams at once, and asks
  its introduction points to pass on at most 5 introductions per second (burst 20; the
  EST_INTRO DoS extension).
- The helper keeps at most 64 rendezvous circuits (TOR-5): a newcomer closes the circuit that
  has gone longest without a stream, and is refused while every circuit carries a stream (no link
  in use is cut for it). A rendezvous circuit that has carried no stream for 10 minutes is closed
  (a client keeps its own that long after its last use, §10). Not defended: a stranger who keeps
  introducing (within the introduction rate limit) closes the quiet circuits of friends, whose
  next dial then needs a new introduction; and while every circuit carries a stream (the node
  holds at most 16 links, so the others are streams being closed) a newcomer is refused, a
  friend's included.
- Dial waits: connect (the Tor circuit to the service) 45 s; whole dial 75 s; frame I/O 30 s;
  first reply 30 s; idle reply 5 s.

## §6 The local helper protocol

Tor runs in a helper process (`raven-tor-helper`, Arti), never in the node. The node starts it
and talks to it over three channels:

1. **Control (stdin/stdout, one JSON object per line, at most 4096 bytes).**
   - Node to helper, first line: `{"v":4,"state_dir":"<profile>/tor","token":"<64 hex>",
     "forward":"<forward>","port":7422,"fresh_state":false}`.
   - Node to helper, later: `{"cmd":"ping","n":N}`, `{"cmd":"self_check","n":N}`,
     `{"cmd":"stop"}`.
   - Helper to node: `{"ev":"progress","pct":0-100[,"blocked":"<word>"][,"stage":"<word>"]}`,
     `{"ev":"ready","connect":"<connect>"}`, `{"ev":"onion","hs_id":"<64 hex>"}` (once),
     `{"ev":"service","state":"shutdown|bootstrapping|degraded_reachable|degraded_unreachable|
     running|recovering|broken"[,"reason":"<phrase>"]}`, `{"ev":"pong","n":N}`,
     `{"ev":"error","what":"<fixed text>"[,"local":true]}`.
   - `<forward>` and `<connect>` say where the streams of items 2 and 3 go (the helper channel,
     below). `<forward>` is `fd:<n>` (macOS, Linux: the end of the channel this helper process
     inherited, descriptor n), `conduit` (a helper in the node's process, handed its end) or
     `127.0.0.1:<port>` (Windows: the node's forward listener). `<connect>` is `conduit` on the
     channel, else `127.0.0.1:<port>` (the helper's connect port).
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
2. **Outbound (a stream to `connect`).** After the hello the node writes `proof[32] || hs_id[32] ||
   port (u16 BE) || flags u8`; the helper answers `status u8 || reason_len u8 || reason`
   (status 0 open, 1 not ready, 2 unreachable, 3 timeout, 4 failed; reason printable ASCII, at
   most 120 bytes, never an address), then the stream carries the bytes. A wrong proof is
   closed without a byte.
   - `flags`: bit 0 *fresh first*: the first try goes in a new isolation group, not the
     contact's (the node's last link to that contact failed where the helper cannot see it,
     §9); bit 3 *hedge*: a first try with no stream after 2 s gets a fresh try in a new group
     beside it, the first stream wins and the other try is dropped (a stream it opened is
     ended); with both, fresh first alone. Bits 1 and 2 are reserved (the keep-warm probe and
     optimistic data). A helper answers a request with a bit it does not know with status 4,
     `unknown connect flags`, and never serves it as if the bit were clear.
   - A node sets flags only while `onion_gate::ONION_HEDGE_PRODUCTION_ENABLED` is open (false;
     lab switch `RAVEN_LAB_TOR_HEDGE` with the Lab Test A unlock, debug builds only, hold
     `feature/onion-hedge`); otherwise 0, which asks what version 2 asked.
3. **Inbound (a stream to `forward`).** For every accepted onion stream the helper opens a stream
   to the node and writes `proof[32] || circuit (u64 BE)` in its hello (below); then the stream
   carries the bytes. `circuit` is an opaque number the helper gives each rendezvous circuit of
   its service: the same for every stream on that circuit, never reused within one helper life,
   and it says nothing about who dialled. The node reads this header before it takes any
   admission slot (at most 32 connections may wait for it; one more closes the oldest), and
   closes a stream without the helper's proof within 2 s, before any Raven byte.
   (Version 4 of this local protocol: version 3 sent the token itself, with no hello, on
   loopback TCP everywhere. Version 2 had no flags byte in a connect request (item
   2), and version 1 sent `token[32]` alone here. Node and helper ship together and refuse
   each other's other version.)

The token is 32 random bytes per helper life. Only the config line carries it; no stream does.

**The helper channel (version 4; security review 2026-11, TOR-4).** On macOS and Linux the
streams of items 2 and 3 ride one socket pair per helper life, with no port and no name: a
helper process inherits its end (`fd:<n>`, above stderr; the node keeps it closed on exec, so no
other program it starts holds it), and a helper in the node's process (the iOS app) is handed it
(`conduit`). Each stream is a fresh socket pair whose one end crosses the channel (SCM_RIGHTS)
with one kind byte: `c` for a connect stream (node to helper), `f` for a forward stream (helper
to node); a message of the other kind or without a socket is dropped. On Windows the streams
stay on loopback TCP (ephemeral loopback ports only: the node's forward listener and the
helper's connect port), and each of the two holds at most 32 connections that still owe their
hello; one more closes the oldest.

**The hello, on every stream.** The node sends `challenge[32]` (random); the helper answers
`nonce[32] || proof_h[32]`, on a forward stream with `circuit (u64 BE)` after it (item 3); the
node checks `proof_h` and only then sends `proof_n[32]`, on a connect stream as the request's
`proof` (item 2), which the helper checks before it reads the rest of the request or carries a
byte. With HMAC-SHA256, `L` = `raven/onion-helper-channel/v4` and `t` = `/connect` or
`/forward`: `k_h = HMAC(token, L || "/helper")`, `k_n = HMAC(token, L || "/node")`,
`proof_h = HMAC(k_h, L || t || "/helper" || challenge || nonce)` and
`proof_n = HMAC(k_n, L || t || "/node" || nonce || challenge)`, compared in constant time. A
program in the helper's place learns a random challenge and nothing else; a copied hello fails
against the next stream's fresh challenge, and no proof stands for the other side's or for the
other kind of stream. Each side waits at most 2 s for each step, then closes the stream without
a word. A helper answers a config line of another version with
`{"ev":"error","what":"unknown protocol version","local":true}`; the node shows "the Tor helper
is from another version of Raven; install Raven again" and starts it again with its usual
backoff.

## §7 The card field

`raven whoami --card` adds `onion=<binding>` (§3, base64url without padding, 139 characters) to
the card, of any version, while the gate is open and the node's binding exists. A reader of this
version accepts the field once, on any version, and refuses the card when the binding does not
verify against the card's own `pub_hex`. It is the one route a release build puts into a card, and
the one it reads from a card besides a local-network `lan=`: the other route fields are not signed
([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §9.1). Readers built before this field refuse such a
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
- **Hedge and fresh first** (Tor speed Stage A; gate
  `onion_gate::ONION_HEDGE_PRODUCTION_ENABLED = false`, lab switch `RAVEN_LAB_TOR_HEDGE`, §6
  item 2 flags). A first try with no stream after 2 s gets the fresh try beside it, in a new
  isolation group, when 12 s or more are left; the first stream wins and the other try is
  ended. A first try in the contact's group on a dead rendezvous circuit then costs 2 s instead
  of Arti's 6 s wait for CONNECTED, at the price of one more introduction (and maybe one more
  descriptor fetch) at the contact's service when the hedge fires. Once a node's link to a
  contact failed where the helper cannot see it (no link came up, a batch got no reply within
  its wait, or a kept link died before any reply), the next connect to that contact within
  10 minutes goes fresh first: its first try in a new isolation group, none in the contact's;
  a link that works ends that. With W1's gate open too (§10), a batch on a kept link with no
  reply within the longer of 2 s and 3 times that link's last round trip (the batch hedge)
  closes the link and goes again on a fresh one, fresh first: the contact answers a copy of a
  message it holds as the same message, with the same ACK. With the gate shut the node sends
  no flags, keeps no such record and hedges no batch.
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
- A rendezvous circuit is kept by Arti for 10 minutes after its last use, then closed; the
  helper closes a rendezvous circuit of its service after 10 minutes without a stream (§5).
- Channel padding `reduced`.
- W1, kept links (Tor speed Stage A; gate `onion_gate::ONION_WARM_PRODUCTION_ENABLED = false`,
  lab switch `RAVEN_LAB_TOR_WARM` with the Lab Test A unlock, debug builds only, hold
  `feature/onion-warm`; open only while §1's gate is): a program's send keeps the dialer's link
  after a batch that got every reply it waited for, for the next batch to the same contact,
  within 20 s of that batch, 120 s of the link's dial and 56 frames, at most 4 links (2 on the
  embedded node) and one per contact. No link is opened for it with nothing to send, and no
  frame changes: the listener reads one frame after another on a link, as before, within its
  own limits (§5). Up to 3 batches ride one kept link at once (pipelining): each batch's frames
  are written behind those of the batches before it, and the replies are taken first in, first
  out, as the listener answers frame after frame, each reply before it reads the next frame. A
  batch whose wait runs out, whose link closes or whose dial is cut closes the link; the batches
  behind it see it closed and go again on a fresh link, so no reply is taken for another
  batch's. A frame that comes with no batch on the link closes it too.

### §5.1 The onion link's Noise static

Anyone who holds a card can open an onion link and read the responder's static from Noise
message 2, before the contact gate runs; the dialer's static goes to the onion service only. A
static that LAN or Internet direct listeners also answer with would let that person match a
listener's IP address to the card's identity. So both ends of an onion link use a static of
their own:

```
onion_static = HKDF-SHA256(salt = "rvn1/onion-noise/v1", IKM = identity seed,
                           info = "static-x25519", L = 32)        (an X25519 private key)
```

- It is never the device static (`salt = "rvn1/lan-noise/v1"`, same info) that LAN, Internet
  direct, p2p and nearby links use. It is stable, and names nothing beyond the onion address
  the card already shows.
- The RIH1 hello signs the static with the handshake hash (as on Internet direct), so a contact
  still authenticates it, but the dialer reads the listener's hello only after its own message 3
  and its own signed hello. Tor authenticates only the onion service key, which the identity
  signs (§3); the binding does not name this static. So whoever holds a copy of that key but not
  the identity seed could answer at the onion address and read the dialer's static and signed
  hello. The onion link pin (next) stops that after the first verified onion link.
- **The onion link pin.** Each node pins each contact's onion link static, trust on first use,
  and checks it as a Noise pin (M0) is checked:
  - The pin is HMAC-SHA256 under the node's pin key (M0: HKDF of its identity seed), over the
    domain `rvn1/onion-link-pin/v1`, the contact's identity key and the static; never the static
    itself. It is kept with the node's Noise pins (`lan_noise_pins.json`; the sealed
    `lan_noise_pins.rms` in a sealed profile) under a row of its own:
    SHA-256(`rvn1/onion-link-pin-row/v1` || the contact's identity key).
  - Recorded after each verified onion link with the contact, whichever side dialled (the
    contact's hello signed the static). A new static replaces the pin.
  - Checked by the dialer after message 2: another static ends the dial with
    `NOISE_PIN_MISMATCH` before message 3, so that responder never sees the dialer's static or
    hello. A pin store that exists but cannot be read dials nothing over Tor
    (`NOISE_PIN_UNAVAILABLE`).
  - Pinned again: the contact's own verified onion link to this node records its current
    static; a newer binding (§3, from a fresh card or an RRH1 entry over any carrier) naming
    another `hs_id` forgets the pin, so the next verified onion link pins again; removing the
    contact forgets it. A binding of the same `hs_id` signed again keeps it. A contact restored
    from its seed answers with the same static (it is derived from the seed), so it needs none of
    these.
  - Always on with the carrier (no gate of its own). Nothing new is sent: no wire change.
  - The first onion dial before any verified onion link with that contact is still trust on
    first use, as is the first after a binding naming another `hs_id`.
- Noise pins (M0) of the device static are neither checked nor recorded on onion links.
- Nodes from before this rule answered onion links with the device static. The carrier has
  never been on in a release build, so no deployed node does.

## §11 Vectors

`shared-vectors/rvn1/onion/binding_001.json`: the RFC 8032 test-1 identity ("alice") binds the
onion key of RFC 8032 test 2's public key at `issued_s = 1792756800`; the signing input, the
104-byte binding and its card text. `shared-vectors/rvn1/onion/noise_static_001.json`: alice's
onion link static (§5.1) next to her device static. Both are written by Rust under
`RAVEN_REGEN_SECURITY_VECTORS=1` (`raven_core::onion` tests); the Python reference checks the
static (`protocol/reference/tests/test_onion_link.py`).

## §12 Privacy and what users are told

- Neither friend learns the other's IP on this path. The first Tor relay (guard) of each side
  sees that side's IP and that it uses Tor, not who it talks to.
- Anyone who holds a card can tell when its owner's onion service is online, and can read the
  onion link's static (§5.1), which matches no LAN or Internet listener.
- Logs carry states and counts only: never a friend's onion address, never the node's own, and
  never Arti's own text.
- The user text is design §3.8.

## §13 Not in V1

Restricted discovery (client authorization), the onion route for the other background dials
(announcer, renewal, learning prober), proof-of-work, bridges and pluggable transports (not
designed, by decision), phones.
