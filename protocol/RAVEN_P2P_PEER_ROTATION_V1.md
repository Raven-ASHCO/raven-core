# RAVEN P2P PeerId Rotation V1

**Version:** 1
**Status:** Draft; **production disabled** (`PEER_ROTATION_PRODUCTION_ENABLED = false`). Lab only:
debug builds with `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_PEER_ROTATION=1` (a lab epoch length with
`RAVEN_LAB_PEER_EPOCH_S`, 10..=86400 s). Release builds read no switch. Even after a gate flip
rotation stays an opt-in privacy setting, off by default (owner decision O4-13). Enabling it in
production needs the owner-signed amendment of the p2p relay waiver (§11 of
`docs/WAIVER_P2P_RELAY_DRAFT.md`; real row R27, the Phase 4 plan's R17).
**Audience:** re-implementers of the p2p endpoint, its relays and its contact cards.
**Code:** `node/crates/raven-core/src/peer_rotation.rs` (derivation, schedules, relay schedule
text), `p2p_route.rs` (`active_peer_id`), `portmap_gate.rs` (gate),
`node/crates/raven-swarm/src/kad_node.rs` (`libp2p_keypair_for_epoch`),
`node/crates/raven-node/src/p2p.rs` (`RotationState`, the re-home and the rollback, the dial).
**Reference:** `protocol/reference/raven_protocol/peer_rotation.py`.
**Vectors:** `shared-vectors/rvn1/p2p/epoch_peer_id_001.json`, `epoch_phase_001.json`,
`relay_schedule_text_001.json`, `card_p2pn_001.json`
(`protocol/reference/generate_peer_rotation.py`).

---

## 1. Scope

A Raven node's libp2p PeerId has so far been fixed per profile: whoever learned it once (from an
old card, or by scanning a mapped or pinholed port) can recognise the node for as long as the
profile lives. With rotation on, the libp2p key changes every epoch (28 days by default). Contacts
running a capable raven follow automatically (they learn the coming PeerIds from route hints),
relays that are contacts follow with them, and other relays take a pasted schedule.

A PeerId names a libp2p key only, never a Raven identity: every p2p link still runs the Raven
Noise link with the pinned contact key inside the libp2p stream. Rotation changes which PeerIds
are admitted and dialled, never whom a node trusts.

Not rotated: the Raven identity and address, the device keys, and a relay's own key
(`relay_key.ed25519`).

## 2. Keys

All integers are big-endian; `seed` is the 32-byte Raven identity seed.

| Key | Libp2p Ed25519 secret seed |
|---|---|
| Legacy (rotation off) | `SHA-256("raven/libp2p-peer-key/v1" \|\| seed)` (unchanged) |
| Epoch `e` (`e` a u64) | `SHA-256("raven/libp2p-epoch-key/v1" \|\| be64(e) \|\| seed)` |

- The 32-byte digest is the Ed25519 secret seed (RFC 8032); its public key `K` gives the PeerId
  `base58btc(00 24 08 01 12 20 || K)` (an identity multihash of the libp2p protobuf public key),
  52 characters starting `12D3KooW`.
- Whenever rotation is off the legacy key is used, so a node that never turns rotation on keeps
  its PeerId forever; no epoch key equals it.
- `active_peer_id(None)` is the legacy PeerId, `active_peer_id(Some(e))` epoch `e`'s. Everything
  that names the node's own PeerId (cards, status, the libp2p host) goes through it.

## 3. Epochs and phase

```
phase    = be64(SHA-256("raven/libp2p-epoch-phase/v1" || seed)[0..8]) mod L
epoch(t) = (t + phase) div L                      t in Unix seconds
boundary = (epoch(t) + 1) * L - phase             the start of the next epoch
```

- `L` = 2 419 200 s (28 days). A debug lab build may shorten it (§1); `L` = 0 is read as 1.
- The phase is secret (it comes from the seed), so outsiders cannot tell when a node's ID
  changes, and two nodes do not change at the same moment.
- An implementation saturates `t + phase` at 2^64 - 1.

## 4. The announced schedule

While epoch `a` is in use, a node announces `a - 1, a, a + 1, …, a + 6` (8 entries; 7 at
`a` = 0), each with its Ed25519 public key: about 6 months of PeerIds. Contacts receive it in the
route hint entry PEER_SCHEDULE (type 0x23, `RAVEN_ROUTE_HINTS_V1.md` §13.2, which holds its
byte layout and rules), which also carries the flags `capable` (always set), `rotating` and
`postponed`, the epoch length and `a`. A receiver checks every key (it decodes as a point, is
canonically encoded and is not of small order) and stores the schedule under the link's
authenticated contact key, never under a PeerId (§8).

While the gate (§10) is live a node announces at least that it is `capable`: with its rotation
off, a PEER_SCHEDULE of no entries, its own epoch length and `a` = 0 (a clock epoch would narrow
its secret phase). Its rotation being on adds the entries and `rotating`; in the epoch before its
first switch (`starting`, §9.1) it announces the entries without `rotating`.

A node turns rotation on only when every pinned contact with a p2p route has announced
`capable`. If every relay it used before a rotation refuses the new ID, it rolls back to the
previous epoch and says `postponed` until it retries (§9.1); a rollback to the legacy key (the
first switch refused) announces as in `starting` instead (§9.1).

## 5. Card field `p2pn=`

`p2pn=<PeerId>`: the PeerId of `epoch(now) + 1`, written only while rotation is on, right after
`p2p=` (the PeerId of `epoch(now)`). It is a field of `raven-card/3`
(`RAVEN_ROUTE_HINTS_V1.md` §9, which bounds the line at 1530 characters, room included); readers
accept the fields in any order. A reader checks it like `p2p=`: a canonical Ed25519 PeerId, not
the card's `p2p=` and not a relay's, else it refuses the card. `raven contact add --card` keeps it
in the contact book next to `p2p=` (`p2p_next`; a card without it, or a new `p2p=`, clears it),
and the PeerIds admitted for the contact include it (§9). A card without rotation carries no
`p2pn=` and stays the bytes of today. `card_p2pn_001.json` is a card with it.

## 6. Relay schedule text

A dedicated relay is not a contact and never receives route hints. Its operator pastes a schedule
instead (`raven relay schedule` prints it; `raven relay allow --schedule` reads it):

```
raven-relay-schedule/1 <epoch>:<PeerId> [<epoch>:<PeerId>]…
```

A reader:

1. trims surrounding white space; the rest must be one line of at most 984 characters, each
   0x20..0x7E (else `not_one_line`);
2. splits on spaces (runs of spaces are one separator);
3. needs the first token to be `raven-relay-schedule/1` (another `raven-relay-schedule/…` is
   `version`, refused with "update raven"; anything else is `prefix`);
4. reads 1 to 13 entries (none is `empty`, a 14th is `too_many`), each `<epoch>:<PeerId>`
   (no colon is `entry`):
   - the epoch in canonical decimal: digits only, no leading zero except `0` itself, at most
     2^64 - 1 (else `epoch`);
   - the PeerId in its canonical Ed25519 form (else `peer_id`);
   - epochs strictly increasing (else `order`); each PeerId once (else `duplicate`).

984 = 22 + 13 × (1 + 20 + 1 + 52): the prefix and 13 entries of the longest epoch. A writer
writes single spaces and consecutive epochs from the active one (13 at most: about a year).
Error codes are those of the reference; implementations report them in their own words.

## 7. Relay allow-list expiry

Entries of `relay_allow.json` gain an optional `expires_ms` (Unix milliseconds); `version` stays
1. A schedule's entry for epoch `e` expires 7 days after `e` ends. A relay knows no friend's
phase, so it takes the latest end `e` can have, `(e + 1) × len` seconds (a phase only moves the
end earlier, by less than one epoch), with its own epoch length `len`: an entry never expires
early, and at most one epoch late. A relay that knows the field skips entries whose
`expires_ms` is below the current time (the entry is still checked, and a bad one still makes
the list unusable); an older relay ignores the field and keeps admitting them (harmless: expiry
is the only thing it misses). Writing a schedule again keeps the later expiry of an entry
already there, never adds one to an entry allowed without it, writes no entry already expired,
and drops expired entries from the list.

## 8. Contacts' schedules (local)

Not a wire format. A node keeps the schedules its contacts announced in `peer_schedules.json`:

- written by the node when a pinned contact's route hint carries PEER_SCHEDULE while the gate is
  live; a newer route hint of that contact without one forgets it;
- keyed by the contact's authenticated key (64 hex), never by a PeerId; only epochs and public
  keys, flags, the epoch length, the active epoch and when it was received;
- sealed at rest (RMS1 kind 66 in a sealed profile, `docs/design/2026-10-at-rest-metadata.md`),
  owner only, written under its own lock, never written over when it could not be read;
- at most 8 entries per contact and 1024 contacts (the least recently heard go first); entries
  behind the contact's clock (§9) go whenever the file is written and in each prune pass (the
  30-day address forget pass), while the `capable` flag stays; a contact removed, blocked or
  given new addresses has its schedule forgotten, as its learned routes are (a new card whose
  `p2p=` the contact is already known by, its old `p2p=` or an epoch its schedule names, keeps
  the schedule);
- a schedule is announced without proof that the sender holds its keys, so one whose entries
  name a PeerId the receiver knows as another peer's (another contact's card `p2p=` or `p2pn=`,
  a PeerId another contact's route hints named, an entry of another contact's schedule, or a
  relay's) is ignored whole: it neither vouches for a P2P_ID (§9) nor is kept, and the frame
  counts as one without a schedule. Only the PeerIds a contact's card gave or a p2p link proved
  are taken as that contact's when its routes are forgotten (a friend relay's manual entries are
  told whose they are).

## 9. Admitting and dialling a contact (local)

A contact's phase is secret too, so a schedule received at time `r` with active epoch `a` says
only that, `k = (t - r) div L` epochs later, the contact is in epoch `a + k` or `a + k + 1`; the
second is likelier when at least half an epoch passed after the `k`th (`guess`). A clock before
`r` counts as `r`. A schedule is used only while it says `capable` and `rotating` (or
`postponed`).

- **Admitted** (the peer gate and a friend relay's allow-list): the card's `p2p=` and `p2pn=`,
  then the schedule's entries for epochs `a + k - 1 ..= a + k + 2` (so a boundary between the two
  candidates is covered) and for `a` (where a postponed contact stays). A schedule that names
  entries without `rotating` (a contact about to rotate, §9.1) is admitted the same way. Only while the gate is
  live; each in the contact's own class (hidden from hole punching when it is), and a block or a
  deny takes every one of them (a friend relay's deny entry names the contact, so it holds over
  the epochs to come too).
- **Dialled**, at most 2 PeerIds, in order: `guess`, then `a` when the contact said `postponed`
  (and `a` is not `guess`), else the other candidate; each only when the schedule holds its key. When the schedule holds
  neither (or there is no usable schedule): the card's `p2p=`, then `p2pn=`; a contact about to
  rotate (entries without `rotating`): the card's `p2p=`, then the entry of `max(guess, a + 1)`
  (the epoch it may have switched to). A second PeerId is
  tried only after the first failed as unreachable, within the same dial deadline, and the peer
  gate admits the PeerId actually dialled. The contact's relays (its card's `via=` and the
  relays its route hints named) serve either PeerId; a direct address ends in a PeerId, so only
  the ones named under the PeerId dialled are used. An explicit address or circuit names its
  PeerId and is dialled as given.
- **Route hints of a rotating contact** (receiver side, only while the gate is live): its
  P2P_ID names the PeerId of its current epoch, not the one its card gave. A P2P_ID the book does
  not hold is still the sender's when the same frame's PEER_SCHEDULE says `rotating` (or
  `postponed`) and names it (`RAVEN_ROUTE_HINTS_V1.md` §13.2); on a p2p link it must also be the
  connection's PeerId, as always. The relays such hints name are the contact's relays (the peer
  gate, the dial) like those of hints naming the card's PeerId. With the gate closed the Phase 2
  rule stands: the book's PeerId wins.

### 9.1 The rotating node (local)

Not a wire format. A node whose setting is on (`raven node p2p rotate on`, node_policy.json
`peer_rotation`, off by default) is in one of these states, evaluated whenever its p2p endpoint
is built and again whenever its contact book, block list, schedules file or policy changes or
an epoch boundary passes:

| State | When | Key |
|---|---|---|
| `off` | the gate is closed or the setting is off | the legacy key |
| `waiting` | before the first switch: a pinned, unblocked contact with a usable `p2p=` has no stored schedule with `capable` | the legacy key |
| `starting` | every such contact is capable, and the clock is not yet past the epoch that holds `ready + L/2` (`ready`: when that became so) | the legacy key; route hints announce the schedule of the clock's epoch without `rotating` |
| `on` | otherwise | the key of the clock's epoch (§3) |
| `postponed` | a rollback holds (below) | the key used before the refused epoch |

- `starting` exists so that contacts learn the coming PeerIds while the legacy key is still in
  use: a receiver admits the keys of a schedule that names them without `rotating`, and dials
  the card's `p2p=` first and the epoch the sender may have switched to second (§9). The first
  boundary at least half an epoch after `ready` switches the key, so contacts get that long to
  hear the coming PeerIds. A contact that hears none of it (offline throughout) cannot admit
  the new PeerId over p2p; it follows once a route hint reaches it another way (LAN, Internet
  direct) or a new card is exchanged. `ready` (a time) is kept across restarts in
  `peer_rotation_state.json` (sealed, RMS1 kind 67; set while the setting is on and every
  contact is capable, cleared when the setting is off or, before the first switch, a contact
  cannot follow), so a restart does not fall back to the legacy key.
- Once the key has switched, a contact that cannot follow (one added later, or one whose
  schedule a new card forgot) no longer moves the node back to the legacy key: contacts that
  hold its epoch card admit no other PeerId, and nothing could tell them the legacy one. Such a
  contact follows once a route hint reaches it or a new card is exchanged.
- At each epoch boundary (and whenever the state changes the key) the endpoint is rebuilt with
  the new key (a re-home: listeners, reservations and AutoNAT start over); the outbox is kicked.
- **Rollback.** For 60 s after a rotation the node watches the relays it held a reservation on
  before it. When every one of them turns the new ID away (its peer gate closes the connection at
  once) and none accepts a reservation, the node rebuilds with the previous key and announces
  `postponed` with that epoch active, until the clock leaves the refused epoch or 6 hours pass,
  whichever comes first; then it rotates again. When the previous key is the legacy one (the
  first switch was refused) it announces the refused epoch's schedule without `rotating`, as in
  `starting`, never `postponed` (which would have contacts dial an epoch key first): contacts
  keep admitting the PeerId the retry uses while they dial the legacy one. A relay that is not a contact needs the relay
  schedule text (§6) to admit the new ID.
- IPC status names the PeerId of the key in use, the state, the count of contacts it waits on,
  the epoch in use and the seconds to the next change; never another PeerId. Logs say only that
  the ID rotated, was postponed or waits on a count of contacts.
- Which key is in use and a rollback are kept in memory only: a restart evaluates the state again
  (a rollback is forgotten, and the node tries the clock's epoch at once); only `ready` is
  written.

## 10. Gates and activation

| Gate | What it opens | Lab unlock (debug builds) |
|---|---|---|
| `PEER_ROTATION_PRODUCTION_ENABLED` | rotation, PEER_SCHEDULE in route hints, `p2pn=` in cards, `raven relay schedule` | `RAVEN_LAB_TEST_A=1 RAVEN_LAB_PEER_ROTATION=1` |

The gate sits on the p2p carrier (`P2P_PRODUCTION_ENABLED`). With it closed a node uses the
legacy key, sends no PEER_SCHEDULE and prints no `p2pn=`: its bytes are those of today. Reading a
schedule, a relay schedule text or a `p2pn=` is harmless with the gate closed.

## 11. Old peers

| Peer | What happens |
|---|---|
| A raven without rotation | Skips PEER_SCHEDULE (an unknown route hint entry); never sees a rotating node's new ID, which is why rotation waits until every p2p contact is capable. |
| A card reader before the `p2pn` rule (2026-10-21) | Refuses a card with `p2pn=` ("update raven"). |
| A relay before `expires_ms` | Ignores the field and keeps admitting the scheduled PeerIds. |
| A relay that is not a contact | Admits only what its allow-list names: without a pasted schedule it refuses the new ID after a boundary, and the node rolls back (§4). |

## 12. Vectors

All under `shared-vectors/rvn1/p2p/`, written by `generate_peer_rotation.py` (`--check` compares),
replayed by Rust (`peer_rotation` tests in raven-core, the card in ash) and by the reference's
tests:

| File | What it fixes |
|---|---|
| `epoch_peer_id_001.json` | seed 0x51 × 32: the epoch seeds, keys and PeerIds of epochs 0, 1, 2, 23, 2^40 and 2^64 - 1; the legacy PeerId; the schedule announced at 23 and at 0 |
| `epoch_phase_001.json` | two seeds at L = 28 days, 600 s and 1 s: the phase, and the epoch and next boundary at 0, a fixed time, the second before the next boundary, the boundary and one epoch later |
| `relay_schedule_text_001.json` | formatted texts (n clamped to 1..=13), accepted texts with their entries, refused texts with their error codes |
| `card_p2pn_001.json` | a `raven-card/3` with `p2p=` and `p2pn=` at a fixed time |

The fuzz target `relay_schedule_text` (`node/fuzz`) reads arbitrary text with the §6 parse.
