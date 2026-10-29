# RAVEN LAN Beacon V1: contact-only, solicited local discovery

**Version:** 1 (`rvn1`). The datagrams carry no version byte. The version is fixed by the key
derivation (the R2 pairwise root `rvn1/r2-pair/v1` and the LAN medium byte `0x02`, §2) and by the
two datagram length ranges (§3).

**Status:** Draft. Production is disabled (`LAN_BEACON_PRODUCTION_ENABLED = false`). The lab switch
`RAVEN_LAB_LAN_BEACON=1` works in debug builds only.

**Amended before the production flip (Phase 6b, 2026-10-23; people study M13):** random tails on
queries and answers (§3: 160..=191 and 48..=63 bytes on the wire, receivers read the first 160 or
48), a random delay of 0-500 ms before a datagram's first copy and 100-400 ms before its second
(§3), and the join round only on need (§8, already so since owner decision OD-C7). No node with the
gate open in production existed, so there is no old peer; after a flip, a change like this one
needs a new version (§10).

**Implements:** Private Rendezvous R2 under its revision-4 terminal-node profile
([`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](RAVEN_PRIVATE_RENDEZVOUS_V1.md) §5.3a).

**Discovery only.** A beacon result is an untrusted LAN dial candidate that lasts a short time. It
is never trust, presence, contact evidence or authentication. Noise XX, the RLB1 identity bind and
the contact gate decide everything.

**Audience:** re-implementers of the LAN carrier.
**Reference:** Rust `raven_core::lan_beacon` (the keys, the datagrams and their matching), the
Python reference `protocol/reference/raven_protocol/lan_beacon.py`, and the vectors in
`shared-vectors/rvn1/lan_beacon/` (§12).

---

## §0 LAN listener exposure (Phase 3 item 1, context)

**`--lan-listen auto`** (the new default):
- With `LAN_AUTO_LISTEN_PRODUCTION_ENABLED` (or the debug switch `RAVEN_LAB_LAN_AUTO`), it binds
  TCP `0.0.0.0:7420` and `[::]:7420` (IPV6_V6ONLY).
- A connection from a non-local source is closed before any byte is sent. Local means loopback,
  10/8, 172.16/12, 192.168/16, 169.254/16, fe80::/10 (with scope), fc00::/7, or an address inside
  a prefix of one of this host's interfaces. 100.64/10 (CGNAT, Tailscale) is not local.
- With the gate closed, `auto` is `0.0.0.0:7420` (any source), as before Phase 3.
- An explicit `IP:PORT` keeps its earlier behaviour (any source).

**What the contact gate already does on every LAN link** (raven-node `lan_direct` `handle_inbound`;
raven-core `lan_dispatch` `link_admission`):
1. Pre-authentication slots per IP, and a handshake deadline.
2. Noise XX. The responder's static key travels in m2, encrypted under ee. A passive observer does
   not see it. Anyone who connects does, and it is stable per identity (the D7 residual).
3. The dialer's signed bind comes first.
4. `link_admission`: the dialer must be a current, unblocked contact, and an unverified contact must
   come from a local source.
5. Only then are the responder's bind and RLB1 (identity, certificate, prekey bundle) sent.
6. Strangers get a close and nothing identifying. Logs are key-free.

**`raven lan off`** (node_policy `lan_off`, applied live): no LAN listener, no LAN dial and no
beacon, until `raven lan on`. `raven lan on --for <time>` (meeting mode) turns LAN off again when
the time is up. `raven lan verified-only on` (node_policy `lan_verified_only`) limits LAN links,
and the beacon (§6), to verified (pinned) contacts.

**IPv6 link-local addresses keep their zone everywhere a LAN address is stored or dialled:**
`[fe80::1%en0]:7420` on Unix (interface name); the numeric index on Windows.

## §1 Properties

- It finds the current LAN address and listener port of a contact who is in both contact books. No
  address is typed. It works on any shared IP link: Wi-Fi, a hotspot, a cable, or Wi-Fi with no
  uplink. A find is kept only at a local-network address (private IPv4, link-local, unique-local
  IPv6), the addresses a LAN plan dials a find at (§9): on a link numbered with public IPv4
  addresses only its IPv6 link-local finds count.
- **Solicited.** A node sends a query only for contacts it is about to reach (§8). It never
  advertises its presence or its contact list. A node with nothing to do sends nothing: its join
  round (at most 8 recent contacts per network change) goes only while it has a need (§8).
- **Jittered.** Neither a datagram's length nor its moment is fixed: a random tail and a random
  delay on each (§3), so length does not tell one sender's datagrams from another's, and the time
  between a trigger (a network change, a query) and the datagram it causes varies.
- A query names up to 8 contacts in fixed-size, indistinguishable slots. Only the named contact can
  recognise its slot. Nobody can count the real slots.
- No datagram contains any of these: a constant byte, an identity, a Raven address, a PeerId, a
  fingerprint, a certificate, a service name, a clear-text port, a timestamp or a counter. Every
  byte is either a fresh random value or the output of a pseudorandom function.
- Answers come only from a node whose contact gate admits the querier.

## §2 Keys

Integers are big-endian, `||` is concatenation, HMAC means HMAC-SHA256, labels are ASCII strings
with no terminator, and a key named by a person (A, B, X, Y) is that identity's 32-byte Ed25519
public key.

### 2.1 Pairwise secret

This is static-static with the collapsed device tier: the device key equals the identity key
([`WAIVER-LAN-DIRECT-2026-10-07`](../docs/WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) §4
item 3). It needs nothing but the contact's identity key, so it works from a contact card alone.

- `a = SHA-512(seed_A)[0..32]`. These are A's Ed25519 secret scalar bytes; X25519 clamps them.
- `u_B` = the Montgomery u-coordinate of B's Ed25519 public key: `u = (1+y)/(1-y) mod 2^255-19`.
- `Z = X25519(a, u_B)`, which equals `X25519(b, u_A)`.

**Contact-key checks.** A node derives no beacon keys for a contact key B, and that contact takes
no part in its beacon, unless all of these hold:
1. B decodes as an Ed25519 point;
2. B is canonically encoded: re-compressing the decoded point gives the same 32 bytes (this
   refuses y ≥ p, and x = 0 with the sign bit set);
3. B is not of small order (none of the 8 points of order 1, 2, 4 or 8);
4. B is not the node's own key;
5. Z is not all zero (contributory). A key that passes checks 1-3 never gives an all-zero Z; the
   check stays as a second line.

### 2.2 R2 pairwise root and medium keys

- `(lo, hi)` = A and B sorted bytewise.
- `K_root = HKDF-SHA256(salt = "rvn1/r2-pair/v1", ikm = Z, info = "root" || lo || hi, L = 32)`.
  This is the R2 pairwise root (R2 §5.3a item 2): one per pair, shared by every medium.
- `K_medium(m) = HKDF-Expand-SHA256(PRK = K_root, info = "medium" || u8(m), L = 32)`.
- `K_lan = K_medium(0x02)`.
- **Pair seeds** (Phase 6b, gated by `PAIR_SEED_PRODUCTION_ENABLED = false`;
  [`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §14): two verified
  contacts that share a pair seed take `K_medium` from `K_pair` in `K_root`'s
  place. A querier names a contact with the key set of its current seed (the
  root's while it has none); a receiver tries every key set it accepts for
  that contact (its current seed's, a leader's proposal's or its previous
  seed's, and always the root's) and answers with the one that matched. The
  datagrams are unchanged.

**Medium registry:**

| Byte | Medium | Status |
|---|---|---|
| `0x01` | Bluetooth LE nearby ([`RAVEN_NEARBY_LINK_V1.md`](RAVEN_NEARBY_LINK_V1.md) §2) | Draft |
| `0x02` | LAN beacon (this document) | Draft |

Other values are unassigned. Every medium takes its own byte, so the keys of one medium never
verify on another.

### 2.3 Directional keys

The querier is X and the answerer is Y.
- `K_q(X→Y) = HMAC(K_lan, "query" || X || Y)`
- `K_r(Y→X) = HMAC(K_lan, "reply" || Y || X)`

### 2.4 Epoch key

- `e = floor(unix_seconds / 600)`
- `K_q,e(X→Y) = HMAC(K_q(X→Y), "epoch" || u64(e))`

### 2.5 How the keys are used

- They are only for beacon tags.
- They are never a message, session, route, mailbox or ACK key.
- They live in memory only, are zeroized, and are recomputed when the contact book or block list
  changes.
- A contact book holds at most 1024 pair keys.

### 2.6 Address encoding

`ip16(ip)`: IPv4 is encoded as `::ffff:a.b.c.d`. IPv6 is its 16 bytes, without the zone. An
IPv4-mapped IPv6 address therefore gives the same 16 bytes as its IPv4 address.

## §3 Transport

- **UDP, destination port 7420.**
- **IPv4:** to `239.255.74.20` (IPv4 Local Scope, RFC 2365) with TTL 1, AND to the interface's
  subnet broadcast address.
- **IPv6:** to `ff02::8000:7420` (link-local scope; a dynamic group ID per RFC 3307) with hop
  limit 1.
- Nothing is routed beyond the link.

**Eligible interfaces:**
- up, multicast-capable, not loopback and not point-to-point;
- not Apple AWDL/LLW (`awdl*`, `llw*`);
- at most 8.

**Sending:** from a socket bound to that interface's primary IPv4 address or its IPv6 link-local
address, so the sender knows its own source address.

**Receiving:**
- Receivers bind `0.0.0.0:7420` and `[::]:7420` (V6ONLY).
- They set SO_REUSEADDR, and also SO_REUSEPORT on macOS/BSD, so that several profiles on one host
  each receive every datagram.
- They join both groups on every eligible interface.
- Linux sets IP_MULTICAST_ALL = 0.

**Datagram type by length:** 160..=191 bytes is a query and 48..=63 bytes is an answer. A receiver
reads the first 160 (48) bytes as §4 (§5) describes and ignores the rest. Any other length is
dropped with no effect.

**Tails (senders):** a sender puts 0..=31 fresh random bytes after a query's 160 and 0..=15 after an
answer's 48, the number drawn uniformly for each datagram. The tail is not covered by any tag and
carries nothing; it only spreads the lengths.

**Answers go to the group** (and to the subnet broadcast address for IPv4) on the interface where
the query arrived, never unicast. This has three effects:
- one inbound firewall rule (UDP 7420) covers both directions, including on stateful Linux
  firewalls that drop a unicast reply to a multicast;
- several profiles on one host work;
- an observer can tell which query an answer belongs to only by timing.

**Timing (senders):** a datagram's first copy goes out a random 0-500 ms after it was made (a round
of §8, or the query §6 answers), drawn uniformly for each datagram (each interface and family of a
round draws its own). A receiver's answer window (§7) starts when the query actually goes out.

**Repeats:** each query and each answer MAY be sent twice, the second copy byte for byte the first,
a random 100-400 ms after it, because Wi-Fi multicast is not acknowledged. Receivers deduplicate.
Nothing made while LAN was on goes out after it turned off (§0).

## §4 Query (160 bytes, then a tail of 0-31)

```
nonce[16] || slot[8],   slot = tag[16] || port_x[2]
```

For each target Y (at most 8, each named once), with `e` = the sender's current epoch and `src` =
the bound source address:

```
h    = HMAC(K_q,e(X→Y), nonce || ip16(src))
slot = h[0..16] || (u16(P_X) XOR h[16..18])
```

- `P_X` is the querier's LAN TCP listener port that a connection of this address family on this
  interface reaches, or 0 if there is none (§6: one rule per address family).
- Unused slots are 18 fresh random bytes.
- Slot order is a uniformly random permutation.
- The nonce is fresh for every round on every interface.

## §5 Answer (48 bytes, then a tail of 0-15)

```
r_nonce[16] || port_x[2] || tag[30]
h      = HMAC(K_r(Y→X), q_nonce || r_nonce || ip16(src_Y) || ip16(dst_X))
port_x = u16(P_Y) XOR h[0..2];   tag = h[2..32]
```

- `src_Y` is the answerer's bound source address on the interface where the query arrived.
- `dst_X` is the query's source address.
- `P_Y` is never 0: a node with no reachable listener sends no answer, and a receiver refuses an
  answer whose port is 0.
- `port_x` is not covered by the tag. An attacker on the path who flips it causes one dial to
  another port on the same IP, which the Noise bind refuses.

## §6 Receiving a query (answerer Y)

Drop the query silently (no answer, a counter only) unless all of these hold:
1. **Length and source.** The length is 160..=191 (the first 160 bytes are read) and the source
   is local (§0 rule).
2. **Rate.** At most 1 query per 2 s per source address (burst 4), and at most 10/s in total
   (burst 20).
3. **Replay.** The nonce is not in the matched-nonce cache (30 min, up to 4096 entries).
4. **Echo.** It is not Y's own query. An echo is recorded as "multicast works on this interface".

**The book.** Y's book holds the pair keys of every current contact that is not blocked, whether
pinned or not (at most 1024). While LAN is limited to verified contacts (`lan_verified_only`, §0),
it holds the pinned ones only: an unpinned contact is then neither named in Y's queries nor
answered.

**Matching.** For each contact C in the book and each `e' ∈ {e-1, e, e+1}` by Y's clock (within
0 to 2^64-1, never wrapping):
- compute `h` with `K_q,e'(C→Y)` and the observed source;
- a slot whose first 16 bytes equal `h[0..16]` matches (constant-time compare);
- at most one match per contact.

**For a match from C:**
- **Admission:** the same check as the LAN link gate (`link_admission`, carrier LAN, source). If
  it fails, send nothing and record nothing.
- **C's port:** `P_C = slot[16..18] XOR h[16..18]`. If `P_C ≠ 0`, record the candidate (C, source
  address with zone, `P_C`) unless the address is not a local-network one (§9). If deliveries to C are waiting, make them due now: at most once per
  5 s per contact, and backoff restarts at most once per 10 min.
- **Answer (§5)**, unless:
  - LAN is off;
  - Y's TCP listener does not accept connections of the query's address family on this interface
    (off, loopback-only, of the other family only, or bound to an address other than the
    unspecified one or the address Y's beacon speaks from there: the interface's IPv4 address or
    its IPv6 link-local one, which is where C dials. A second IPv4 address, or a global or
    unique-local IPv6 address of the same interface, counts as another address);
  - or Y answered C in the last 2 s.

**Clock hint (local, informative).** The epoch `e'` at which C's slot matched bounds how far C's
clock is from Y's. A match at `e+1` received `p` seconds into Y's epoch `e` shows that C's clock
is more than `600 - p` seconds ahead of Y's; a match at `e-1` shows that it is more than `p`
seconds behind (less the delivery time). A skew of a few seconds matches at `e+1` (or `e-1`) near
the end (or start) of every epoch, so the epoch alone says nothing. Y notes C's clock as too far
off only when three rounds in a row matched only at `e+1` (or only at `e-1`) and one of them shows
more than Raven's 5-minute limit (a match in the other half of Y's epoch), and then says only the
bound shown ("about N minutes or more"). One 2 epochs or more off is never matched. Y may tell its
own user so. Nothing is sent, stored or logged for it, and no rule above changes.

**One rule per address family.** A node answers, and puts a non-zero port in its query slots, only
on an address family its TCP listener accepts. With the `auto` gate closed the listener is a single
`0.0.0.0:7420` socket: it answers IPv4 queries only, and its IPv6 query slots carry port 0. An
IPv6 answer would otherwise make the querier dial a candidate this listener cannot accept.

Query processing writes no file and logs no address, key or name.

## §7 Receiving an answer (querier X)

Accept an answer only when all of these hold:
- it arrives within 3 s of one of X's query rounds on the same link: the interface it came in on
  for an IPv6 link-local source (its zone), else any of X's interfaces on whose network the IPv4
  source is (two interfaces on one subnet, Wi-Fi and a cable at a dock, each send their own query,
  and Y answers only one of them);
- its length is 48..=63 (the first 48 bytes are read) and its source is local;
- for one target Y of that query, `h` recomputed with `dst_X` = X's bound address on that query's
  interface makes the tag verify (constant-time). An IPv6 answer that reaches X on two links is
  checked once on each;
- the port it carries is not 0.

Then:
- `P_Y = port_x XOR h[0..2]`.
- The candidate is (Y, source address with zone, `P_Y`).
- It is valid for 10 minutes, while its interface exists, until the next network or interface
  change (the address may be another host's on the new network, even one numbered the same) and
  until a dial to it fails, a custody fetch or deposit dial included.
- It makes Y's waiting deliveries due now.

## §8 When a node queries (triggers and limits)

**Want sources:**
- an outbox attempt for Y in which some due object may use LAN;
- an ACK owed to Y;
- custody with Y (while custody is live);
- a user send (local IPC LanLocate, which waits at most 2 s: one find under §3's send shape,
  a query's first copy lost included);
- after an interface-set change or a network change, every contact with waiting deliveries (at
  most 64).

**Join round:** one round per service start and per network or interface change, only while the
node has a need: deliveries or ACKs wait for a contact, custody rows wait for their recipients, or
meeting mode (`raven lan on --for`) is on. Without one, joining a network sends nothing (owner
decision OD-C7: arriving must not announce "a Raven node just arrived"). It names at most 8
contacts from the authenticated inbound LAN sightings of the last 7 days (lan_seen, newest first),
plus, on a custodian with custody live, the recipients it holds custody rows for (targets beyond
one round's 8 slots go to the next round, as below). Its slots carry the listener port, so a
contact waiting to reach this node learns the new address at once. This covers DHCP moves and both
people moving while the moved side has something waiting; a moved node with nothing waiting is
found by the other side's own want-driven query (up to its per-contact interval).

**Skipped:** when Y has a candidate younger than 2 min on a current interface.

**Per contact:** queries at least 15 s apart, doubling while unanswered up to 10 min. The interval
resets on a network or interface change and on any authenticated link with Y. User sends: at least
2 s apart.

**Global:**
- a token bucket of 4 rounds, refilled 1 per 3 s;
- wants within 300 ms share a round (at most 8 targets; extra targets wait for the next round,
  oldest first).

**Never** while LAN is off, or while the LAN gate or the beacon gate is closed, and never for a
contact that is not in the book (§6). Interfaces are polled every 15 s while deliveries wait,
otherwise every 60 s. This polling also catches cable and link-local-only links, which netwatch
ignores.

## §9 Using a candidate

- A candidate is used only for LAN-direct dials to that contact.
- It goes first among that contact's LAN routes, at most 2 (IPv4 first).
- While a candidate exists, learned LAN routes from lan_seen and RRH1 are not added. The saved LAN
  route stays after the candidates.
- The dial runs Noise XX and the RLB1 bind with the contact's expected key. A different key fails
  like any wrong route.
- A candidate is never written to the contact book, lan_seen.json or learned_routes.json. It is
  never put in RRH1, a card or any frame, and never forwarded or published.
- A candidate for an unverified contact is local by construction.
- A candidate is kept only at a local-network address (private IPv4, IPv4 link-local, IPv6
  link-local with its zone, unique-local IPv6), the rule the LAN plan dials finds by. An answer or
  query from a public IPv4 address on the link (a public-numbered campus LAN) still counts as heard
  and is answered, but leaves no candidate, so it holds back no query.

## §10 Versions and old peers

- **No version byte.** A future version MUST derive its keys under another domain (a new medium
  byte in §2.2, or a new R2 pairwise-root salt) and use datagram lengths outside 48..=63 and
  160..=191, so v1 nodes drop its datagrams by length or by tag mismatch.
- **The Phase 6b amendment** (tails, timing, join round on need) was made before the production
  flip: every v1 node reads 160..=191 and 48..=63. Lab builds from before it read only 160 and 48
  and drop most amended datagrams; none ever had the gate open in production.
- When per-device keys land, the certified device X25519 keys and both certificate digests replace
  the identity keys of §2.1 under a new domain (R2 §5.3a item 2). That is a new version.
- **Pre-beacon nodes and nodes with the gate off** bind no UDP 7420 socket. They neither query nor
  answer. Queries to them go unanswered and the querier falls back to its other routes.
- Hosts do not send ICMP errors for multicast or broadcast traffic.
- No TCP, Noise, RLB1 or RRH1 byte changes. LAN Noise message 1-3 payloads are unchanged.
- Zoned addresses in lan_seen.json and learned_routes.json do not parse in old binaries, which skip
  them.

## §11 Privacy analysis

**Passive observer on the Wi-Fi.**
- It learns:
  - that a device runs Raven: the fixed group and port, sizes in two ranges (160-191 and 48-63),
    and TCP flows to its listener port;
  - when the device has waiting deliveries, custody rows or a meeting, or sends: rounds follow
    §8 (joining a network with none of these sends nothing);
  - roughly how many contacts it seeks at once, in steps of 8: wants that come together (after a
    network change, every contact with waiting deliveries, at most 64, plus a join round) go out
    as back-to-back rounds of at most 8 targets each, so the number of rounds in such a burst is
    the number of wanted contacts divided by 8, rounded up. Which contacts they are stays hidden;
  - which devices are probably contacts: an answer from B within about a second of A's query, and
    then their TCP connection. The random delays (§3) blur which query an answer belongs to when
    several devices query at once, but do not hide a lone query and its answer.
- It does not learn:
  - identities, addresses, PeerIds, fingerprints or the Noise static key (m2 is encrypted);
  - how many contacts a node has, or which contacts it seeks (only the burst size above);
  - listener ports from the beacon (they are encrypted).
- **Linkability across epochs:** none from content. Every query and answer uses a fresh 16-byte
  nonce under a PRF keyed per pair, so two datagrams cannot be linked even within one epoch, and
  still less across epochs. The epoch only bounds replay. Linking comes only from the MAC address,
  IP and timing, which the OS controls (macOS, iOS and Windows use a randomised MAC per network).

**Active attacker on the Wi-Fi.**
- **Probing TCP 7420** reveals the stable Noise static key, which is a tracking handle across
  networks (D7). Mitigations:
  - `raven lan off`;
  - on Windows, firewall rules limited to the Private profile;
  - optionally, LAN static rotation (owner decision 10).
- **Replaying a query** is limited by:
  - the ±1 epoch window (10-20 min);
  - the matched-nonce cache;
  - source-IP binding: on another network the attacker must spoof the original IP and receive a
    multicast answer.

  The residual is that a replay at the right place and time reveals that some device there answers
  the original querier.
- **Forging a query or an answer** is impossible without `K_lan` (or the root it comes from). A
  flipped port causes one refused dial.
- **Flooding** is limited by the token buckets (bounded CPU: at most 3 × 1024 HMACs per accepted
  query).

**Contacts.**
- A contact holding the pair's keys can recognise queries meant for itself and can confirm the
  other's presence on a shared LAN. R2 accepts this explicitly.
- A removed or blocked contact can still compute the static root. It never appears in our slots,
  and its queries get no answer (admission check), so it learns nothing more than any observer.

**Compromise.** No forward secrecy: compromising an identity key makes recorded beacons
attributable after the fact (metadata only). Static bootstrap must be reviewed independently (R2
§14 item 4).

**Software fingerprint.** The fixed UDP group, port and sizes identify beacon traffic to anyone who
knows this spec. The payload carries no marker. Hiding queries inside mDNS (port 5353) is deferred
(R2 §5.3 needs a reviewed Bonjour profile).

## §12 Vectors

`shared-vectors/rvn1/lan_beacon/`:
- `lbcn_pair_keys_001.json`: each person's X25519 scalar and Montgomery u; for alice's pairs with
  bob, carol and dave, Z both ways, `K_root`, `K_lan`, the four directional keys and the epoch keys.
- `lbcn_query_001.json`: alice's query naming bob (slot 5) and carol (slot 2) from 192.168.1.20
  with port 7420, a fixed nonce and fixed padding; whom each person's book finds (bob and carol
  find alice and 7420, dave nobody, alice nobody in her own query); bob at the epochs e-2 to e+2
  (e±1 accepted, e±2 refused); other sources refused (the IPv4-mapped form of the same address is
  the same source).
- `lbcn_answer_001.json`: bob's answer (48 bytes) from 192.168.1.30 to that query; alice opens it
  and gets 7420; another q_nonce, source or destination, swapped addresses or other keys open
  nothing.
- `lbcn_negative_001.json`: contact keys refused by §2.1 (the 8 small-order points, the identity
  point among them; non-canonical encodings, including y = p + 3; a non-point; the own key; 31 and
  33 bytes), u-coordinates whose Z is all zero, and datagrams dropped for their length (0, 47, 64,
  159 and 192 bytes: one byte short of each range, or one byte over its longest tail) or refused
  for port 0.
- `lbcn_query_padded_001.json`: the query of `lbcn_query_001.json` with tails of 1, 16 and 31
  bytes (191 in all); every book finds in it what it finds in the query alone.
- `lbcn_answer_padded_001.json`: the answer of `lbcn_answer_001.json` with tails of 1, 8 and 15
  bytes (63 in all); alice opens each to 7420, and with another query's nonce to nothing.

The people are alice and bob of `shared-vectors/v1/identities.json` (RFC 8032 §7.1 tests 1 and 2),
carol (RFC 8032 test 3, inline) and dave (32 bytes of 0x44, inline; not the dave of
identities.json). `epoch_seconds` is 1700000000, so `e = 2833333`.

Rust writes the files only under `RAVEN_REGEN_LAN_BEACON_VECTORS=1` (raven-core test
`lan_beacon::tests::lan_beacon_known_answer_vectors`) and otherwise checks them. The Python
reference (`protocol/reference/raven_protocol/lan_beacon.py`, test `tests/test_lan_beacon.py`)
recomputes every vector from its inputs; `generate_rvn1.py` does not write them. Swift is pending
and is needed before any flip. Fuzz target: `lan_beacon_datagram` (`node/fuzz`).

## §13 Gates

- `LAN_BEACON_PRODUCTION_ENABLED = false`
- `LAN_AUTO_LISTEN_PRODUCTION_ENABLED = false`

Both appear in `lan_gate::global_production_flags_stay_false`. `raven lan off|on` and the zone fix
are not gated: they only reduce exposure or fix correctness.

Flip order (owner):
1. Sign the LAN Phase 3 amendment (hold B12), then flip AUTO_LISTEN.
2. Approve R2 revision 4, complete the crypto review and check Swift, then flip BEACON.

## Appendix: RAVEN_PRIVATE_RENDEZVOUS_V1 revision 4, §5.3a (summary)

- **Terminal nodes:** "foreground" becomes "solicited for an exact contact by a pending delivery,
  an owed ACK, custody or a user send, plus, while one of these needs or meeting mode exists, one
  join round per network change naming at most 8 recent contacts". Advertising presence or all
  contacts stays forbidden.
- **Pairwise root with the collapsed device tier:** the Montgomery forms of both identity keys,
  one root per pair shared across media by a medium byte. When per-device keys land, the certified
  device X25519 keys and both certificate digests replace them under a new domain.
- **Fixed group and port** are allowed transport identifiers. The payload carries no marker.
- **Traffic shape:** the number of back-to-back rounds in a burst of wants shows an observer on the
  link roughly how many contacts the node seeks at once, in steps of 8 (§11); no contact count
  beyond that.
- **Unverified contacts** may use the LAN lane, on the local network only.
- **Vectors:** Rust and the Python reference; Swift before any flip.
