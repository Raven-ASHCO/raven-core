# RAVEN Update Exchange V1 (RUP1)

**Version:** 1 (`RUP1`, version byte `1`)
**Status:** Draft; **production disabled** (`MESH_UPDATE_PRODUCTION_ENABLED =
false`, which also needs `RELEASE_BUNDLE_PRODUCTION_ENABLED` and
`ADVISORY_PRODUCTION_ENABLED`; `raven-core/src/security_gate.rs`). Lab only:
debug builds with `RAVEN_LAB_MESH_UPDATE=1`, `RAVEN_LAB_RELEASE_BUNDLE=1`,
`RAVEN_LAB_ADVISORY=1` and `RAVEN_LAB_TEST_A=1`; release builds ignore the
switches. This revision defines the frames, their decode rules, the dial
classifier and the listener's answers (raven-core `update_exchange.rs`), and
raven-node runs the exchange (§7, §11) while the gate is live; with the gate
shut (every release build) no build sets caps bit 10 or sends a RUP1 frame.
**Audience:** re-implementers of the Raven links and of the update exchange.
**Design:** `docs/roadmap/plans/phase6-design.json`, design D §6 and wire
spec W-D4; owner decisions OD6b-23 (no built-in fetching from the internet:
files and friends only) and OD6b-24 (pinned contacts only; advisories and
logs automatic; a download approval and a separate install approval for
bundles; never over Bluetooth or custody for bundles).

---

## 1. Purpose

A Raven without an uplink still needs security advisories, the transparency
log and new releases. RUP1 lets friends pass them to each other over the
Raven links they already have: a HAVE frame says what one side holds, and
the other side asks for what is newer. Nothing a friend sends is trusted for
being sent by a friend: every advisory, log snapshot, manifest and chunk is
verified against the release keys and the log
([`RAVEN_SECURITY_ADVISORY_V1.md`](RAVEN_SECURITY_ADVISORY_V1.md),
[`RAVEN_TRANSPARENCY_LOG_V1.md`](RAVEN_TRANSPARENCY_LOG_V1.md),
[`RAVEN_RELEASE_BUNDLE_V1.md`](RAVEN_RELEASE_BUNDLE_V1.md)) before it is
kept, applied or passed on. A friend can withhold an update or send garbage;
it cannot make a Raven accept anything the release keys did not sign and the
log does not list.

All integers are big-endian.

## 2. Where RUP1 runs

### 2.1 Links and negotiation

RUP1 frames are raw Noise-transport frames on authenticated direct links
(LAN direct, Internet direct, p2p, nearby) after RLB1 and RRH1, like RSR1 and
RFC1: never inside RVN1, never stored for others, never forwarded as frames.
On a padded link each RUP1 frame is the inner frame of one RPD1 frame
([`RAVEN_LINK_PADDING_V1.md`](RAVEN_LINK_PADDING_V1.md) §2); every RUP1 frame
fits one (§8).

RUP1 is a link feature in the RIH1 caps namespace
([`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md) §2):

- **Bit 10**, `CAP_LINK_RUP1 = 0x00000400`: this side speaks RUP1 on this
  link. A node sets it while the exchange is live; frames go only to pinned
  contacts (§7).
- Internet direct, p2p and nearby: the bit is in the signed RIH1 hello. With
  RRH1 and PAD1 too the hello caps are `0x00000702`
  (`update/rup1_frames_001.json`, `link_caps`).
- LAN direct: the dialer puts the bit in its RLX1 `LINK_CAPS`
  ([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md) §3.2; with RRH1 and
  PAD1: `524c5831 01 01 04 00000700`), only on dials that read (the RRH1
  rule). The listener tells the dialer by sending its HAVE.

### 2.2 Order on the link

- **Internet direct, p2p, nearby.** The listener sends its HAVE right after
  its RLB1 offer (and its RRH1, if any), when the dialer's verified hello has
  bit 10. The dialer sends its HAVE after verifying the listener's RLB1 (and
  after its own RRH1, if any), when the listener's verified hello has bit 10.
- **LAN direct.** The listener sends its HAVE right after its RLB1 offer
  (and RRH1), when the dialer's `LINK_CAPS` has bit 10. The dialer sends its
  HAVE only after the listener's HAVE has arrived on this link.
- One HAVE each way per link. Only the **dialer** sends requests, and only
  after the listener's HAVE arrived on this link; the **listener** answers
  them (the RFC1 pattern). A listener never sends a request, and a dialer
  never answers one.

### 2.3 What RUP1 never does

- It never goes to a peer that did not set bit 10 on this link: old peers
  never receive RUP1 (§9).
- It never travels through custody, letters or a relay's store: only on a
  direct link between the two friends.
- It never carries a bundle over Bluetooth: on a nearby link a HAVE carries
  no offers and GET_MANIFEST and GET_CHUNKS are answered ERROR
  POLICY_DENIED. Advisories and logs are small enough for it.
- A HAVE is an unsigned claim. It never changes the update state by itself;
  it only decides what to fetch.

## 3. Frames

```
header = "RUP1" || version 0x01 || op u8 || req_id[4]            (10 bytes)
```

Every frame is at most **65,511 bytes** (`MAX_FRAME_LEN`, PAD1's inner
limit).

| Op | Name | Sent by | Body | Answered by / kind |
|---:|---|---|---|---|
| `0x01` | HAVE | both | §3.1 | one-way: never answered |
| `0x02` | GET_ADVISORY | dialer | empty | ADVISORY or ERROR |
| `0x03` | GET_LOG | dialer | empty | LOG or ERROR |
| `0x04` | GET_MANIFEST | dialer | `manifest_digest[32]` | MANIFEST or ERROR |
| `0x05` | GET_CHUNKS | dialer | §3.3 | CHUNK x n, then CHUNKS_END; or ERROR |
| `0x06` | GET_ROTATION | dialer | `key_set_digest[32]` | ADVISORY or ERROR |
| `0x82` | ADVISORY | listener | `rad1_len u16 (1..=32,768) \|\| RAD1 \|\| RTL1 snapshot` | terminal |
| `0x83` | LOG | listener | `RTL1 snapshot` | terminal |
| `0x84` | MANIFEST | listener | `manifest_len u16 (1..=5,198) \|\| RRB1 manifest \|\| RTL1 snapshot` | terminal |
| `0x85` | CHUNK | listener | §3.3 | non-terminal |
| `0x86` | CHUNKS_END | listener | `code u8 \|\| sent u8 (0..=8)` | terminal |
| `0xFF` | ERROR | listener | `code u8 (1..=255)` | terminal |

- `req_id`: four bytes the dialer chooses for each request (distinct within
  a dial); every reply to a request carries that request's `req_id`. A HAVE,
  which is never answered, carries `00000000`.
- **Op registry.** RUP1 has one op registry under version byte 1. New
  operations are new ops under that byte: requests take `0x06`-`0x7F`
  (`0x06` GET_ROTATION was added by the Phase 6 review, §9), replies
  `0x87`-`0xFE`. `0x00` and `0x80`-`0x81` are reserved.
- The snapshot in ADVISORY, LOG and MANIFEST is the rest of the frame
  (1..=58,023 bytes). The artifacts (RAD1, RTL1, RRB1) are only bounded by
  this frame; their own codecs read them when the update state verifies them.

### 3.1 HAVE

```
HAVE   = adv_serial u64 || adv_digest[32] || log_size u32 || log_root[32]
      || n u8 (0..=4) || offer x n                          (77 + offers)
offer  = build_serial u64 || target_len u8 (1..=64) || target
      || manifest_digest[32] || payload_len u64             (49 + target)
```

- `adv_serial`, `adv_digest`: the newest advisory this side accepted (its
  serial and `advisory_digest`). `0` and 32 zero bytes: none. A serial
  without a digest, or a digest without a serial, is refused.
- `log_size`, `log_root`: the log this side stored (its tree size and root).
  `0` and 32 zero bytes: none. At most 1,400 (the version 1 log's cap).
- `offers`: the bundles this side serves, each named by its manifest digest
  (at most once). `build_serial >= 1`; `target` is a target triple as in
  RRB1 (`[a-z0-9_.-]`, at least two non-empty `-` segments); `payload_len`
  is 1..=67,108,864.
- The longest HAVE (four offers with 64-byte targets) is 539 bytes. The test
  release's HAVE: `update/rup1_have_001.json`.

### 3.2 Advisories, logs and manifests

- **GET_ADVISORY -> ADVISORY**: the newest advisory the listener accepted
  and the log snapshot that lists it. The dialer hands both to its update
  state (`accept_advisory`, RAD1 §6).
- **GET_LOG -> LOG**: the listener's stored log snapshot (`accept_log`).
- **GET_MANIFEST -> MANIFEST**: the manifest with that digest and the log
  snapshot that lists it; verified before any chunk is asked for (RRB1 §7).
- **GET_ROTATION -> ADVISORY** (`key_set_digest[32]`, the dialer's current
  release key set; a 42-byte frame): the advisory whose `KEY_SET` entry
  rotated the listener away from that key set, signed by it, and the log
  snapshot the listener accepted it with (signed by it too). A dialer that
  missed a rotation can check both (RAD1 §6.2) and then the listener's
  newest advisory.
- A listener that does not hold what is asked for answers ERROR NOT_FOUND.

### 3.3 Chunks

```
GET_CHUNKS = manifest_digest[32] || first u32 || count u8 (1..=8)       (47-byte frame)
CHUNK      = index u32 || len u32 (1..=61,440) || chunk
          || path_len u8 (0..=11) || path[32] x path_len
CHUNKS_END = code u8 || sent u8
```

- GET_CHUNKS asks for chunks `first .. first + count` of the payload of the
  manifest with that digest; `first + count` is at most 1,093 (the chunks of
  a 64 MiB payload).
- The listener answers with one CHUNK per chunk it sends, in order, then one
  CHUNKS_END. `sent` is how many CHUNK frames it sent for this request;
  `code` is `0` when it sent every chunk asked for, otherwise an ERROR code
  saying why it stopped early (NOT_FOUND: past the payload's last chunk;
  BUSY; RATE_LIMITED).
- A CHUNK is chunk `index` of the payload (61,440 bytes, the last one what is
  left) with its RFC 6962 audit path to the manifest's chunk root, from the
  leaf's sibling up (RRB1 §5). A version 1 payload has at most 1,093 chunks,
  so a path has at most 11 hashes.
- The fetcher checks every chunk before writing it: its length is the
  chunk's and its path leads to the manifest's chunk root (RRB1
  `check_chunk`). A chunk that fails is discarded and fetched again,
  preferably from another friend (`update/negative/rup1_oversize_chunk_001.json`,
  `forged`).

### 3.4 ERROR codes

| Code | Name | Meaning |
|---:|---|---|
| 1 | `UNSUPPORTED` | an op or version the listener does not serve |
| 2 | `NOT_FOUND` | the listener does not hold it (or it does not fit one frame, §8) |
| 3 | `BUSY` | the listener serves as many requests as it will right now |
| 4 | `RATE_LIMITED` | this friend asked too often or fetched too much today |
| 5 | `POLICY_DENIED` | not served to this friend, on this link, or this artifact |
| 6 | `MALFORMED` | a known request whose body breaks a rule of §4 |
| 7-255 | (unknown) | kept; a failure all the same |

Code `0` is not an error: an ERROR with code 0 is refused (`BAD_CODE`); in
CHUNKS_END it means "every chunk was sent".

## 4. Decode rules

A frame is read in this order; the first rule broken refuses it with the
code shown (`update/negative/rup1_decode_rules_001.json`,
`rup1_oversize_chunk_001.json`):

1. The magic is `RUP1` (`NOT_RUP1`).
2. The frame is at least 10 bytes (`TRUNCATED`) and at most 65,511
   (`TOO_LONG`).
3. The version is `1` (`BAD_VERSION`).
4. The op is one of §3 (`UNKNOWN_OP`).
5. The op's fields in order, each with its cap, before anything is copied:
   - HAVE: `req_id` is zero (`NONZERO_REQ_ID`); the advisory pair
     (`BAD_ADVISORY_REF`); the log pair and its cap (`BAD_LOG_REF`); `n <= 4`
     (`TOO_MANY_OFFERS`); per offer `build_serial >= 1` (`BAD_SERIAL`), the
     target's length and bytes (`BAD_TARGET`), `payload_len`
     (`BAD_PAYLOAD_LEN`), a digest seen before (`DUPLICATE_OFFER`).
   - GET_MANIFEST, GET_ROTATION: the 32-byte digest.
   - GET_CHUNKS: `count` (`BAD_COUNT`), then `first + count <= 1,093`
     (`BAD_INDEX`).
   - ADVISORY: `rad1_len` (`BAD_RAD1_LEN`); MANIFEST: `manifest_len`
     (`BAD_MANIFEST_LEN`); then the snapshot's length (`BAD_SNAPSHOT_LEN`).
   - LOG: the snapshot's length (`BAD_SNAPSHOT_LEN`).
   - CHUNK: `index < 1,093` (`BAD_INDEX`), `len` (`BAD_CHUNK_LEN`), the
     chunk, `path_len <= 11` (`BAD_PATH_LEN`), the path.
   - CHUNKS_END: `sent <= 8` (`BAD_COUNT`). ERROR: `code != 0` (`BAD_CODE`).
   - A field cut short is `TRUNCATED`.
6. Nothing follows the last field (`TRAILING_BYTES`).

Every length is checked against its cap and against the bytes present before
it is used: decoding never allocates more than the caps allow plus the
frame's own payload bytes, and a refused frame allocates nothing
(`raven-core/tests/rup1_alloc.rs`). An accepted frame is canonical: it
re-encodes byte for byte, and an encoder refuses exactly what a decoder
refuses.

## 5. Requests, replies and dials

| Request | Replies that answer it |
|---|---|
| GET_ADVISORY | ADVISORY, ERROR |
| GET_LOG | LOG, ERROR |
| GET_MANIFEST | MANIFEST, ERROR |
| GET_CHUNKS | CHUNK (an index asked for), CHUNKS_END (`sent <= count`), ERROR |
| GET_ROTATION | ADVISORY, ERROR |

- Each request gets exactly one terminal reply (ADVISORY, LOG, MANIFEST,
  CHUNKS_END or ERROR); CHUNK never ends a request. raven-node's dial
  classifier counts a version 1 request as expecting a reply and a terminal
  reply as ending one (`frame_expects_reply`, `frame_is_terminal_reply`), so
  a dial ends once every request has its terminal reply. HAVE neither
  expects nor ends anything.
- A reply that cannot answer an outstanding request (another op, another
  `req_id`, a chunk not asked for) is ignored, and the request counts as
  failed.
- A fetcher asks for at most 8 chunks per request and 16 per dial.

## 6. Listener and dialer rules

What a listener does with a frame from its dialer
(`update_exchange::decode_for_listener`; the `listener` field of every
vector case):

| Frame | The listener |
|---|---|
| a request that passes §4 | serves it (§7), or answers ERROR BUSY, RATE_LIMITED, POLICY_DENIED or NOT_FOUND |
| a HAVE that passes §4 | takes it (one per link) |
| a request op whose body breaks §4 | answers ERROR MALFORMED with its `req_id` |
| another version, or an op below `0x80` it does not know | answers ERROR UNSUPPORTED with its `req_id` |
| a reply op (`0x80` and up), a HAVE that breaks §4, or no complete header | answers nothing |

A listener never answers a reply or a HAVE, and a dialer never answers
anything, so two nodes can never answer each other forever. A dialer that
receives a HAVE that breaks §4 ignores it; a reply that breaks §4 fails its
request.

## 7. Node rules

These are the rules raven-node follows (`raven-node/src/update_exchange.rs`,
P6.49; the numbers are `raven-core/src/update_exchange.rs` and
`raven-core/src/update_downloads.rs` constants). The exchange runs while the
gate is live and the build has release keys to check with; otherwise no
hello or RLX1 sets bit 10 and nothing below happens. A security notice's
hold on release bundles (`feature/release-bundle` BROKEN, or a BROKEN module
suite of that gate) stops only bundles: no offers in a HAVE, GET_MANIFEST
and GET_CHUNKS answered ERROR POLICY_DENIED, no download fetched, while
notices and logs still pass (a node without an uplink gets the notice that
lifts the hold only this way). A hold on `feature/mesh-update`, or a BROKEN
`rup1/1`, stops the whole exchange (RAD1 §8).

- **Pinned contacts only** (OD6b-24). On a link with anyone else a node
  sends no HAVE and answers any request ERROR POLICY_DENIED.
- **Advisories and logs: automatic.** When a pinned contact's HAVE names a
  newer advisory than the stored one, or a log that is longer (or as long
  with another root), a follow-up dial fetches it (GET_ADVISORY, GET_LOG);
  the update state verifies it and applies it, freezing on equivocation or
  a split view; the node then offers it onward in its own HAVE.
- **Bundles: approved.** An offer for this build's target with a newer
  build serial raises a download approval that names the friend, the
  version and the size. After approval the fetcher asks for the manifest
  first and verifies it, then for chunks from every friend offering the same
  manifest digest, resumably (`updates/incoming/<digest>/`), each chunk
  checked before it is written (§3.3). The complete payload is verified as a
  whole (RRB1 §7) and staged; installing is a separate approval, in the CLI
  or the terminal app only, never in raven-node.
- **Serving.** Verified bundles for this platform (other platforms' only
  with "Carry updates for friends" on), to pinned contacts: at most 6
  requests a minute and 128 MiB a day per friend (otherwise RATE_LIMITED),
  2 requests at a time overall (otherwise BUSY).
- **Storage.** `updates/incoming/`: at most 256 MiB, removed after 7 idle
  days. `updates/staged/`: 2 builds. `updates/quarantine/`: what failed
  verification, at most 64 MiB for 7 days, counted, never run or shown.

### 7.1 How raven-node does it

- **One HAVE each way per link.** A link's later HAVEs are ignored. A HAVE is
  taken only from a pinned contact; it is kept in memory (at most 256
  friends) for the exchange task.
- **Follow-up dials.** A HAVE that names newer notices, or an approved
  download it offers, wakes the exchange task, which dials that friend over
  the routes the outbox worker plans for it (Bluetooth skipped for a
  release). A dialer writes RUP1 requests only after the listener's HAVE
  arrived on that link (on LAN it waits for it after RLB1, as for RRH1); a
  listener that sends none gets no request and the dial ends with
  `UPDATE_EXCHANGE_NOT_OFFERED`. Such a dial's replies are not an IPC
  response, so its reply budget is 2 MiB (16 CHUNK frames fit), not the IPC
  frame's.
- **Notices.** GET_ADVISORY when the HAVE's advisory serial is higher than
  the newest known, or equal with another digest (equivocation when the
  signed bodies differ: the update state freezes); else GET_LOG when its log
  is longer, or as long with another root (a split view: it freezes). While
  frozen nothing is asked for: no advisory lifts a freeze (RAD1 §6.1). The
  same claims of a friend are asked for at most every 10 minutes; a friend
  whose notice or log failed its check is not asked again for 24 hours, and
  what it sent goes to quarantine.
- **Key rotations.** A node keeps the last 4 `KEY_SET` rotations it applied,
  each with the log it was accepted with, and answers GET_ROTATION from them.
  An advisory or log under a key set the node never trusted cannot be
  checked yet (RAD1 §6.1, `UNKNOWN_KEY_SET`): nothing goes to quarantine,
  the friend is not held back and no event is raised, while a catch-up is
  still possible. The node then asks that friend, in one more dial,
  GET_ROTATION with its own current key set and the same notice again;
  after each rotation taken it asks again, at most 6 dials per friend a
  pass and at most 4 GET_ROTATION dials per friend a day. When that dial
  brings no rotation (NOT_FOUND, another error but BUSY or RATE_LIMITED, a
  listener built before GET_ROTATION that answers UNSUPPORTED, or an answer
  that is no rotation) and the notice is still under a key set the node
  never trusted, or when
  the day's 4 are spent and that friend brought no rotation that day, the
  notice counts as forged: it goes to quarantine, SEC_ADVISORY_FORGED is
  noted about the friend who passed it on and that friend is not asked for
  notices for 24 hours (the node cannot tell such a notice from one under a
  key set the friend made up). A friend that brings rotations is not
  blamed: the rest follows the next day. A node more rotations behind than
  its friends keep, or whose friends never took the rotation themselves (a
  build that ships the new key set), is caught up by a file import of the
  rotation or a new build.
- **Releases.** An offer for this computer's target with a build serial
  above the installed one becomes a row of `updates/downloads` (the digest,
  serial, target, size and up to 8 friends that offered it; at most 16
  rows). Nothing is fetched until the row is approved (`raven update
  download`, or Y in the terminal app's UPDATES; IPC `UpdateKick` wakes the
  task). An approved row is fetched from the friends that offered it, the
  one that offered it last first, in turn: GET_MANIFEST first, verified as
  RRB1 §7 down to the payload (its log taken first, so a split view freezes
  before anything else), then GET_CHUNKS for the first missing chunks (two
  requests of 8 a dial), each chunk checked by its audit path before it is
  written at its offset in `updates/incoming/<digest>/payload` and marked in
  its bitmap (`chunks`): a dropped link or a restart resumes from the
  bitmap. A forged chunk goes to quarantine and that friend is not asked for
  that release for 24 hours; the others go on. NOT_FOUND or POLICY_DENIED
  from a friend does the same without quarantine; BUSY and RATE_LIMITED
  make that friend wait a minute. The manifest is checked against the log
  the friend sent with it when that lists it, else against the stored log
  when that does; a refusal that depends on that log (unlogged, a log that
  does not check, a split view, a manifest under another key set that no
  log lists) is that friend's bad copy, handled like a forged chunk, while
  another friend that offered the release is still to be asked (its log may
  list it). With none left, the release is not used now and that friend's
  copy is held back the same way, but nothing of the release itself goes to
  quarantine and the row fails as `NOT_LOGGED`: no log the node has lists
  it, which is no proof against the release (its log may be newer than any
  seen here). Such a row is approved again by itself once the stored log
  lists it (a notice brought a newer one) or a friend that offered it may be
  asked again (another friend's offer, or a day after the friend whose log
  did not list it). A release whose
  manifest itself is refused (a bad signature, a downgrade, below the
  release floor, another target) fails as a whole, since every friend's
  copy has the same bytes. Once the manifest verified, the row
  shows its build serial and size, not the HAVE's claims. Complete, the
  whole release is verified again, against the stored log when it lists it,
  else the one kept with it; then the row is `complete` and the folder holds
  `verified`. A download whose chunks are all in but whose check did not
  finish (raven-node stopped in between) is checked at the next pass with no
  dial; one whose kept log no longer checks (a key rotation since) gets a
  fresh manifest and log from a friend, its chunks kept, and nothing is
  raised about the friend. A row that cannot be fetched for lack of room in
  `updates/incoming/` fails with `NO_ROOM`, and one the CLI or the terminal
  app could not stage on this computer with `NOT_STAGED`: neither is said
  to be the friend's. A complete download whose folder went (7 idle days)
  is offered again, unless its build was staged. The CLI or the terminal
  app stage it (verified in full again, like an imported file) before the
  install approval; raven-node stages and installs nothing.
- **Serving.** The stored advisory with the stored log, the stored log, the
  kept rotations (GET_ROTATION), and the releases held for this platform:
  staged builds (their files back to back) and complete downloads. A held release's chunk tree is built from
  the disk and must match the manifest's chunk root; every chunk served is
  checked against it. The day's byte quota counts chunk bytes; a request
  that runs into it ends with CHUNKS_END `RATE_LIMITED` after the chunks
  that fit.
- **IPC** (IPC_VERSION stays 1): `UpdateKick { v }` (answered `Accepted`,
  or `UPDATE_EXCHANGE_OFF` while the exchange is not running; an older
  daemon answers `IPC_FRAME`); `Status.updates` (`UpdateStatus`: the newest
  advisory serial and its age in days, the log size, offers waiting for
  approval, downloads under way, complete downloads, staged builds, frozen,
  and what quarantine holds; counts only, absent while the exchange is not
  running).

## 8. Sizes

| Frame | Largest |
|---|---:|
| HAVE | 539 bytes (four offers, 64-byte targets) |
| GET_ADVISORY, GET_LOG | 10 bytes |
| GET_MANIFEST, GET_ROTATION | 42 bytes |
| GET_CHUNKS | 47 bytes |
| ADVISORY | 65,511 bytes (the frame limit) |
| LOG | 58,033 bytes (the longest snapshot) |
| MANIFEST | 63,233 bytes (10 + 2 + 5,198 + 58,023) |
| CHUNK | 61,811 bytes (10 + 8 + 61,440 + 1 + 32 x 11) |
| CHUNKS_END | 12 bytes |
| ERROR | 11 bytes |

- Every frame fits one PAD1 inner frame (65,511 bytes); the longest CHUNK
  pads into the 65,519-byte bucket (`update/rup1_chunk_path_001.json`).
- **ADVISORY.** An advisory may be 32,768 bytes and a snapshot 58,023, which
  together do not fit one frame. An advisory of at most **7,476 bytes**
  (`ADVISORY_ALWAYS_FITS`) fits beside any version 1 snapshot, and the
  release ceremony keeps advisories under that. A listener whose advisory
  and snapshot do not fit one frame answers ERROR NOT_FOUND; the advisory
  then travels as a file (`raven update import`).
- The design's table gave CHUNK's `path_len` as "<= 17"; version 1 caps it
  at 11, the deepest tree a 64 MiB payload has, which the frame-size sum
  above already assumed.

## 9. Old peers and later versions

- A build without RUP1 never sets bit 10, and a node sends RUP1 only to a
  peer that set it on this link, so old peers never receive a RUP1 frame.
  The hello and RLX1 payloads without bit 10 are byte for byte as before.
- A new op is added under version 1 (§3, op registry): a listener built
  before it answers ERROR UNSUPPORTED, and a dialer ignores a reply op it
  does not know. GET_ROTATION (`0x06`) is the first such op (Phase 6 review,
  2026-10-24): a dialer sends it only after a friend's notice came under a
  key set it never trusted, so an older friend sees it only then and
  answers UNSUPPORTED (that notice then counts as forged, §7.1); an older
  dialer never sends it.
- A change to an existing frame's layout or rule is version `0x02` with a
  new spec; a version 1 listener answers it ERROR UNSUPPORTED.

## 10. Vectors

Written by Rust (`RAVEN_REGEN_SECURITY_VECTORS=1 cargo test -p raven-core
update_exchange`), checked by the Python reference
(`protocol/reference/raven_protocol/update_exchange.py`,
`tests/test_update_exchange.py`), which builds every frame again byte for
byte, checks that the frames carry the test release, computes every chunk's
audit path on its own, and replays every refusal and listener decision.
Large frames are given by their head, a pattern fill (byte j = `(start + j)
mod 251`) and their tail, with their length and SHA-256.

- `update/rup1_frames_001.json`: one frame of every op carrying the test
  release of `update/rrbc_small_001.json` (its advisory, log, manifest and
  one-chunk payload), CHUNKS_END with and without a code, ERROR with each
  code and an unknown one; roles, the dial classifier, the listener, which
  reply answers which request, and the link caps with bit 10.
- `update/rup1_have_001.json`: HAVE holding nothing, the test release, four
  offers, and the longest (539 bytes).
- `update/rup1_chunk_path_001.json`: the CHUNK frames of the payloads of
  `update/rrb1_chunk_tree_001.json`: the small one's five chunks answering
  GET_CHUNKS first 0 count 5, and chunks 0 and 1,092 of the 64 MiB payload
  (chunk 0: an 11-hash path and the longest CHUNK frame).
- `update/negative/rup1_oversize_chunk_001.json`: CHUNK lengths, indexes and
  paths over their caps, cut and grown frames, a frame over the limit; and
  forged chunks that decode but fail their check.
- `update/negative/rup1_decode_rules_001.json`: every rule of §4 for every
  op, the accepted edges, and what a listener does with each (`0x07`: an op
  this version does not define).

## 11. Implementation status

- raven-core `update_exchange.rs` (P6.48): the frames, `encode`, `decode`,
  `decode_for_listener`, `frame_expects_reply`, `frame_is_terminal_reply`,
  `Rup1Msg::answered_by`, `Chunk::of_payload` and `Chunk::check`, the error
  codes, the limits and node constants of §7, `live()` (the gate and its
  advisory holds: bundles) and `notices_live()` (the same apart from a hold
  on release bundles: notices); `internet::LinkFeatures::RUP1`. Fuzz target `rup1_frame`;
  the allocation test `raven-core/tests/rup1_alloc.rs`.
- raven-node `update_exchange.rs` (P6.49): §7 and §7.1, on LAN direct and
  on the Internet direct link code that p2p and nearby run; the exchange
  task in `raven-node service`; IPC `UpdateKick` and `Status.updates`.
  raven-core `update_downloads.rs`: the offers and approvals file (sealed,
  at-rest kind 120), the incoming folder's names and the storage caps, and
  the debug lab switch `RAVEN_LAB_UPDATE_AUTO_APPROVE=1` (with Lab Test A:
  every offer approved as it comes, and `raven update install` without the
  typed word, for the update harness; a release build never reads it).
  ash: `raven update download [OFFER]` and the terminal app's Y in UPDATES;
  a complete download is staged by `raven update install` and by UPDATES.
- The update harness (P6.51): carrier_matrix C88 (notices over RUP1: a
  notice passed A -> B -> C by itself; a rolled-back, a forged and an
  equivocating notice refused by their event kinds; a split view between two
  friends' logs freezes) and C89 (unsigned, forged and unlogged releases
  refused from files and over RUP1 after each approval; a good release
  passed A -> B -> C only after each approval and installed from a temp
  prefix with the old raven-node kept; a downgrade refused), and the fault
  matrix's s118 (a notice A -> B -> C over LAN) and s119 (a release resumed
  from a second friend after the first link dropped). The debug lab switch
  `RAVEN_LAB_UPDATE_CLAIM_NEWER=1` (raven-node, with Lab Test A; a release
  build never reads it) makes a node's HAVE claim one advisory serial more
  than it holds, with the digest of the one it holds: a friend that answers
  GET_ADVISORY with an older notice than it claimed, which an honest node
  never does (C88's rollback). `node/scripts/update_mesh_test.sh` is the
  kit of real row R31 (three laptops, no uplink) with a loopback dry run.
- Not yet: carrying other platforms' releases for friends ("Carry updates
  for friends"): a node fetches releases for its own target only.
