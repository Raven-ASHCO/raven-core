# RAVEN Link Knock V1 (RLK1)

**Version:** 1 (`rlk1/m1`, `rlk1/m2`)
**Status:** Draft; **production disabled** (`LINK_KNOCK_PRODUCTION_ENABLED = false`).
Lab only: debug builds with `RAVEN_LAB_LINK_KNOCK=1` and `RAVEN_LAB_TEST_A=1`
(`raven-core/src/security_gate.rs`). Release builds ignore the switch. With the
gate shut no dial knocks, no listener reads a knock, and every handshake is
byte for byte what earlier builds send (`lan/noise_xx_handshake_001.json`,
`noise_xx_handshake_002.json`). The gate is never live in release without the
LAN noise pins (M0, `LAN_NOISE_PIN_PRODUCTION_ENABLED`): a compile-time check.
**Audience:** re-implementers of the LAN direct and Internet direct Raven links.
**Design:** `docs/roadmap/plans/phase6-design.json`, design B §3 and wire spec
W-B2; owner decision OD6b-9 (RLK1 on top of M0, per-connection statics,
legacy to strict automatically, silent to strangers as a setting).

---

## 1. Purpose

A Raven listener answers Noise XX with its static key in message 2, and a
dialer sends its own in message 3. Both statics used to be derived from the
identity (`lan/noise_static_001.json`): the same key on every connection, for
anyone who asked. That key does not name the Raven ID, but it is a lifelong
handle: a scanner can recognise the same laptop on every network, and an
impostor at a friend's address learns the dialer's static.

M0 (the cutoff pack's noise pins) lets a dialer refuse to send message 3 to a
key it has not pinned for that contact, but it needs the static to stay the
same. RLK1 removes that need:

- a dialer that knows its contact **knocks** in message 1 (a tag only the
  contact can check);
- the listener answers a knock with the **proof** in message 2 (a tag only the
  dialer can check), and both sides then use **fresh statics** for this
  connection only;
- a dialer without a proof falls back to the M0 pin, and stops before message
  3 at a contact that has knocked before;
- a listener can answer strangers with a fresh static (strict) or not at all
  (silent).

RLK1 applies to LAN direct (no prologue) and Internet direct (prologue
`raven/internet/v1`). The Noise pattern, prologue and framing are unchanged;
only the payloads of messages 1 and 2, the statics and message 3's payload
change. Not to the p2p link (the peer gate refuses strangers before it, and
its PeerId is Phase 4's) and not to nearby (an RNK1 knock opens the pipe).

## 2. Keys

```
K_link   = medium_key(K_root, 0x03)
           = HKDF-Expand-SHA256(PRK K_root, info "medium" || 0x03, 32 bytes)
kq_X->Y  = HMAC-SHA256(K_link, "knock-q" || X || Y)
kr_X->Y  = HMAC-SHA256(K_link, "knock-r" || X || Y)
```

- `K_root` is the R2 pairwise root of the two Ed25519 identity keys
  ([`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](RAVEN_PRIVATE_RENDEZVOUS_V1.md) §5.3a,
  `lan_beacon/lbcn_pair_keys_001.json`); medium byte `0x03` is the link knock
  (`0x01` Bluetooth LE, `0x02` LAN beacon). While pair seeds are live
  ([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §14, Phase 6b, gated)
  `K_pair` of the pair's current seed replaces `K_root` here as for the other
  media: a dialer knocks with it (the root while it has none), and a listener
  tries every key set it accepts for each contact (its current seed's, a
  leader's proposal's or its previous seed's, the root's: at most three per
  contact, 3,072 in all) and proves with the one that matched. A dialer whose
  seeded knock gets no proof does not stop yet (§4): it knocks once more with
  the root on a new connection, which a contact that lost its seed (or runs
  without seeds) proves; only that knock's outcome decides (the pin, the
  floor and the impostor decision). It does so when the step of §4's table
  stops, and whenever the contact's floor shows the knock, whatever the step:
  a friend that lost its seed answers in legacy mode with its derived
  static, which an M0 pin kept from before the knock matches, and going on
  then would carry no knock (a false downgrade, §4). With a floor that lacks
  the knock a matching pin goes on as before, on one connection. A seeded
  knock whose listener closes the connection before message 2 on every
  attempt (a listener silent to strangers that lost the seed answers
  nothing else) is followed by one root knock on a new connection too.
- X and Y are 32-byte Ed25519 identity keys. `kq_A->B` makes A's knocks to B,
  `kr_B->A` B's proofs to A. Each side holds its own two and the mirrored
  two of each contact.
- The keys exist only in memory, are wiped on drop, and make nothing but
  knock tags and proofs. A key the beacon cannot use (not a canonical point,
  weak, or one's own) has no knock keys: dials to it do not knock.

## 3. Messages 1 and 2

A is the dialer, B the listener. `e_A` is A's 32-byte XX ephemeral, `s_B`
the static B uses on this connection.

```
message 1 payload = nonce16 || tag16 || pad(0..31)
  tag16   = HMAC-SHA256(kq_A->B, "rlk1/m1" || day_u32_be || nonce16 || e_A)[0..16]
  day     = floor(unix_ms / 86,400,000)
message 2 payload = proof16 || pad(0..31)
  proof16 = HMAC-SHA256(kr_B->A, "rlk1/m2" || nonce16 || e_A || s_B)[0..16]
            (16 random bytes when message 1 matched no contact)
```

- XX message 1 is `e_A || payload` with no encryption yet, so a listener reads
  the knock before it builds its responder. Message 2's payload is encrypted
  by XX (after `ee, s, es`).
- `nonce16` and `pad` are fresh random bytes from a CSPRNG; `pad` is 0-31
  bytes of uniformly random length. A dialer draws its ephemeral itself (the
  tag covers it) and gives it to its Noise state; it MUST be fresh for every
  connection.
- The proof covers `s_B`, so it also binds the fresh static the listener
  chose.

## 4. Listener and dialer

**Listener.** On every inbound connection while the knock is live:

1. Read message 1 (`e || payload`) before building the Noise responder.
2. A payload of 32-63 bytes is a knock candidate. Try every contact's
   `kq_peer->me` on the listener's day and the days before and after it,
   comparing each tag in constant time, every contact and day whatever
   matched already. At most 1,024 contacts are tried (the LAN beacon's book:
   every contact that is not blocked, pinned ones only under `raven lan
   verified-only`, pinned ones first), and of them only those the
   listener's contact gate takes on this connection: on Internet direct, and
   on LAN from a source beyond the local network (or an unknown one), the
   pinned (verified) contacts alone (owner decision 2026-10-08). An
   unverified contact's knock there gets a stranger's answer, never the
   proof that would tell it whose address this is before the gate refuses
   it. Exactly one match is a match; none or two is no match.
3. A matched nonce seen before (a cache of 4,096 matched nonces, each kept 3
   days: a knock is accepted on the listener's day and the days next to it,
   so one first matched early on day D-1 still matches until day D+1 ends)
   is a **replay**: `SEC_KNOCK_REPLAY` about the source (penalty-box strike
   4), answered as no match. Every listener of the process shares the cache,
   and the process keeps it in the profile (`knock_replays.bin`, sealed in a
   sealed profile, written before message 2 goes out), so a restart forgets
   nothing.
4. Choose the static:
   - a match: a fresh random static (X25519 from the OS CSPRNG) and the proof;
   - no match, legacy mode: the derived static and 16-47 random bytes;
   - no match, strict mode: a fresh random static and 16-47 random bytes;
   - no match, silent mode: close the connection without message 2.
5. Build the responder with that static and continue XX. Message 2's payload
   is always 16-47 bytes while the knock is live, so its length never says
   whether the knock matched.
6. A dialer whose knock matched uses a fresh static of its own: the listener
   does not pin it (M0). Any other dialer's static is pinned as before.

**Dialer.** On every LAN or Internet direct dial to a contact while the knock
is live:

1. Draw `e_A`, a nonce and pad; send message 1 with the knock. The Noise state
   that writes it holds the derived static.
2. Read message 2 and the listener's static `s_B`. The payload verifies when
   it is 16-47 bytes and its first 16 bytes equal the proof (constant time).
3. Decide (design B §3):

   | Proof | M0 pin for this contact | Contact's floor shows the knock | Step |
   |---|---|---|---|
   | valid | any | any | go on with a **fresh static** |
   | none | matches `s_B` | any | go on with the derived static (a listener without the knock) |
   | none | another key | any | stop before message 3 (M0) |
   | none | none | yes | stop before message 3 |
   | none | none | no | go on with the derived static (today's handshake) |

   "Stop" sends nothing more (not message 3, not the bind or hello) and is
   `SEC_ADDRESS_IMPOSTOR` about the contact, with M0's text. A knock with a
   pair seed (§2) without a proof leaves the decision to the root's knock
   instead when the step stops, and whenever the contact's floor shows the
   knock.
4. Going on with a fresh static: build the same handshake again with the fresh
   static and the same ephemeral, write message 1 again (the same bytes) and
   read message 2 again. XX sends the initiator's static only in message 3,
   so messages 1 and 2 are the same for both states; then write message 3.
5. A listener that proved itself used a static for this link only: the dialer
   does not pin it. Pins kept before stay the fallback for listeners without
   the knock.

**Statics.** A responder or initiator MAY use any X25519 static. The LAN bind
(`rvn1/lan-noise/v1` over the static) and the RIH1 hello (over the handshake
hash and the static) bind it to the identity, so nothing else changes
([`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md) §3).
`lan/noise_static_001.json` stays the KAT of the derived static, which
listeners without the knock, legacy mode and dialers without a proof use.

**Capability floor.** A LAN or Internet direct link always shows whether it
carried the knock (the listener: its match; the dialer: the proof). The
contact's capability high-water mark keeps the knock once seen; a later link
without it is a Suspicious `SEC_CAPABILITY_DOWNGRADE` (the link goes on).

## 5. Modes

`security_silent_to_strangers` in the node policy:

| Setting | Mode |
|---|---|
| Automatic (default) | **strict** once every contact the connection's book holds (§4 step 2) has the knock in its capability floor (an empty book included), **legacy** until then |
| On ("Silent to strangers") | **silent** |
| Off | **legacy** |

- A contact's build that pins statics but has no knock (M0 only) cannot reach
  a strict or silent listener: its pin of the derived static no longer
  matches. That is why automatic mode waits for every contact's knock
  high-water mark. A contact without M0 and without the knock still reaches a
  strict listener (with a fresh static).
- Silent mode closes before message 2 for anyone who did not knock: a scanner
  sees a TCP port that closes after message 1. It also shuts out contacts
  without the knock; the user turns it on knowing that.

## 6. Handshake shape

| Message | Without RLK1 | With RLK1 |
|---|---|---|
| 1 | 32 bytes | 64-95 bytes (`e` + 32-63) |
| 2 | 96 bytes | 112-143 bytes (`e`, encrypted static, encrypted 16-47 payload) |
| 3 | 64 bytes, LAN with RLX1 75 | 64 + RLX1 payload of up to 64 bytes |

While knocking, the dialer's message 3 payload is RLX1 with its `LINK_CAPS`
(when it has caps to send) and one `PAD` entry, type `0x7E`, whose value is
zeros, bringing the payload to a random length between its minimum (7 bytes
without caps, 13 with) and 64 bytes. Every RLX1 parser skips the unknown type
([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §3.2), so the caps read
as before; an Internet direct listener discards message 3's payload.

## 7. Old peers and the gate

- **Old listeners** (any build without RLK1, or the gate shut) drop message 1's
  payload (it is read and ignored), answer with the derived static and an
  empty message 2 payload: no proof, so the dialer's table decides. With an
  M0 pin or without the knock in the floor the link completes as before.
- **Old dialers** send an empty message 1 payload: no match, answered by the
  mode; they ignore message 2's payload.
- No build rejects a non-empty payload in message 1 or 2. RAVEN_ROUTE_HINTS
  §3.2's rule "messages 1 and 2 keep empty payloads" holds unless RLK1 is in
  use.
- With the gate shut a node never knocks, never reads a knock, and sends
  empty payloads and its derived static: byte for byte the earlier handshake.

## 8. Security considerations

- **Hides:** from a scanner or an impostor at a friend's address, the
  listener's lasting static (strict, silent) and the dialer's static (it
  stops before message 3); from anyone, that two connections came from the
  same laptop through its static.
- **Does not hide:** IP addresses, ports, timing, connection counts and
  durations; that Noise XX runs (the pattern stays recognisable to a prober
  that gets message 2); a contact's identity from that contact.
- **Replays:** a recorded message 1 matches again while it is in its
  window (three days at most); the cache, which covers that window and is
  kept in the profile across restarts, turns the second match into no match
  (and an event). Without the ephemeral's secret the replayer cannot read
  message 2 or complete the handshake anyway.
- **Clock:** a knock is accepted on the listener's day and the days next to
  it, so clocks up to a day apart still match.
- **Cost:** three HMACs per contact per inbound connection (about a
  millisecond at 1,024 contacts); bounded by the penalty box and the
  listener's admission caps.
- **Forward secrecy** of the knock keys is the pair seed's
  ([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §14): with seeds live
  a later thief of an identity key recomputes only knocks made with the root:
  before the first seed, after one was lost, and every fallback knock (§2).
  A seeded knock that got no proof, or whose connection closed before
  message 2, is followed by a root knock, so whatever answers at a friend's
  address without the proof (a stale address, another node, an impostor)
  draws one root-keyed knock per dial. Without seeds, every recorded knock.
- **Security notices:** a hold on the knock (`FEATURE_HOLD` BROKEN on
  `feature/link-knock`, or a BROKEN `rlk1/1`) stops this node's knocks and
  keeps its capability floors from noting the knock, while its listener
  still proves itself to a contact that knocks: a contact whose notice has
  not come yet would otherwise stop at it as at an impostor
  ([`docs/design/2026-10-suite-retirement.md`](../docs/design/2026-10-suite-retirement.md) §6.4).

## 9. Vectors

Rust writes them under `RAVEN_REGEN_SECURITY_VECTORS=1` and compares them
otherwise; the Python reference `protocol/reference/raven_protocol/link_knock.py`
(`tests/test_link_knock.py`) checks every one.

- `shared-vectors/rvn1/link/rlk1_tags_001.json`: Alice (RFC 8032 test 1) dials
  Bob (test 2): `K_link`, the four directional keys, the day of
  2026-10-23, the tag, the raw message 1, Bob's match in a book of
  (Carol, Alice), the proof over a fixed static, message 2's payload and three
  padded RLX1 message 3 payloads.
- Negatives in `link/negative/`: `rlk1_wrong_day_001` (the listener two days
  off), `rlk1_wrong_pair_001` (a knock for another contact, and the other
  direction's key), `rlk1_replay_001` (the same message 1 twice),
  `rlk1_unmatched_m2_random_001` (random bytes are no proof).
- `shared-vectors/rvn1/lan/noise_xx_handshake_003.json`: the whole LAN
  handshake with the same seeds and fixed ephemerals as
  `noise_xx_handshake_001`, the knock of `rlk1_tags_001`, fresh statics on
  both ends (scalars of 0x33 and 0x44 bytes), the dialer's state rebuilt
  after message 2, a 40-byte padded RLX1 in message 3, both binds and the
  first transport message.

## 10. Implementation status

- raven-core `link_knock.rs` (keys, tags, proofs, the replay cache, both
  decision tables, `hear` for the listener, `Dialing` for the dialer, the
  padded message 3) and `lan_noise.rs` (builders that take an explicit
  static, and the dialer's own ephemeral); fuzz target `rlk1_m1`.
- raven-node `link_knock.rs` wires it into `lan_direct` and `internet_direct`
  (P6.35): the listener's book and mode for the connection's carrier and
  source (made again when the contact book, block list, policy or capability
  floors change), the shared replay cache and its file,
  the dialer's steps, the pins left out for knocked links, and the knock in
  each link's capability-floor showing.
- Pair seeds (§2, P6.38): the listener's book and the dialer take their key
  sets from them while they are live; a root match while a seed was expected
  is `SEC_PAIR_SEED_ROOT`.
- Not yet: a command to set `security_silent_to_strangers` (the policy field
  exists), and the attack harness rows that drive an
  impostor through a tampering proxy (they wait for P6.32).
