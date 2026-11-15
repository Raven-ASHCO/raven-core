# RAVEN Attachment V1 (RVNATT/1 and RAX1)

| | |
|---|---|
| **Status** | Draft. Production disabled: `ATTACHMENTS_PRODUCTION_ENABLED = false`. Lab switch `RAVEN_LAB_ATTACHMENTS=1` with `RAVEN_LAB_TEST_A=1`, debug builds only. Phase 1a (§9) has no gate. |
| **Design** | `docs/design/2026-11-attachments.md`; profile pictures: `docs/design/2026-11-profile-pictures.md` |
| **Code** | `node/crates/raven-core/src/attachment/` (`blob.rs`, `offer.rs`, `shown.rs`, `store.rs`, `flow.rs`, `link.rs`, `exchange.rs`, `peers.rs`), `node/crates/raven-node/src/attachments.rs` |
| **Feature id** | `feature/attachments` (a security notice can hold it; close only) |
| **Not frozen** | Not in a release with the gate open. No test vectors yet (§11). |

A photo, a voice note or a file is one sealed message, the **offer**, and a
**blob** of sealed chunks that never travel as messages. This document says
what goes on the wire and what a node must check. It does not say how an app
shows anything.

## 1. Words

- **Attachment key** `K`: 32 random bytes, new for every attachment, never
  derived from the content.
- **Handle**: 16 bytes derived from `K`. The name of the attachment on links
  and on disk. It says nothing about `K` or the content.
- **Root** `R`: the root of the tree over the sealed chunks.
- **Offer**: the text that travels as a chat message (or a group message
  body). It holds `K` and `R`.
- **Stored form** (`ref`): the offer without `K`, `R` and the pad. What a
  history row keeps. It is never sent.

## 2. The blob

```text
padded     = bytes || zeros, Padmé(len) bytes in all
segment i  = padded[i * 61,424 ..][.. 61,424]            (the last: what is left)
chunk key  = HKDF-SHA256(K, info "rvnatt/1 chunk key")[32]
handle     = HKDF-SHA256(K, info "rvnatt/1 handle")[16]
custody id = HKDF-SHA256(K, info "rvnatt/1 custody id" || i u16 BE)[16]
nonce i    = i u64 BE || 16 zero bytes
aad i      = "rvnatt/1" || padded_len u64 BE || chunk_count u32 BE || i u32 BE
chunk i    = XChaCha20-Poly1305(chunk key, nonce i, aad i, segment i)
leaf i     = SHA-256(0x00 || chunk i);  R = the RFC 6962 root over the leaves
```

- HKDF has no salt. Integers are big endian.
- **Padmé.** For `len < 2` the padded length is `len`. Otherwise, with
  `e = floor(log2(len))` and `s = floor(log2(e)) + 1`, the last `e - s` bits
  of `len` are rounded up to zero. The padding is at most about 12 %.
- A segment is 61,424 bytes and a chunk 61,440 bytes (the segment and the
  16-byte tag); the last of each may be shorter. An attachment has at most
  1,059 chunks: 64,000,000 bytes, 65,011,712 padded.
- A chunk cannot move to another place (its index is in the nonce and in
  the additional data), and the attachment cannot be cut short (the count
  and the padded length are in the additional data of every chunk).
- The tree is the one of the release bundles (`RAVEN_RELEASE_BUNDLE_V1.md`):
  an audit path has at most 11 hashes.
- **Profile pictures** use one chunk whose segment is always 61,424 bytes,
  whatever the picture's size (at most 60,000 bytes), so the chunk's size
  says nothing.

## 3. Frames of text

A frame is text: a head line, a line feed, then one JSON object.

| Head | Meaning | Size |
|---|---|---|
| `RVNATT/1 offer` | an offer | exactly 8,192 bytes |
| `RVNATT/1 gone` | the author deleted the attachment before the friend had all of it; the object holds `v` and `handle` | small |
| `RVNATT/1 ref` | the stored form; never sent, and never accepted from a link | under 8,192 bytes |

Every text that starts with `RVNATT/` is reserved: it is never chat, and no
composer sends it (§9).

### 3.1 The offer

Members, in this order, each present or absent by the kind:
`v`, `handle`, `kind`, `seq`, `held`, `chunks`, `padded_len`, `true_len`,
`mime`, `name`, `caption`, `width`, `height`, `duration_ms`, `levels`,
`preview`, `key`, `root`, `pad`.

| Kind | Members between `kind` and `key` |
|---|---|
| `photo` | `chunks`, `padded_len`, `true_len`, `mime` (`image/jpeg`), `caption`, `width`, `height`, `preview` |
| `voice` | `chunks`, `padded_len`, `true_len`, `mime` (`audio/ogg`), `caption`, `duration_ms`, `levels` |
| `file` | `chunks`, `padded_len`, `true_len`, `mime`, `name`, `caption` |
| `profile` | `seq`, `held`, `chunks` (1), `padded_len` (61,424), `true_len`, `mime` (`image/jpeg`), `width`, `height` (equal), `preview` |
| `profile`, the empty form (No picture) | `seq`, `held`, `chunks` (0); no `key`, no `root` |

- `v` is 1. `handle`, `key` and `root` are lower case hex. `preview` and
  `levels` are standard base64. `pad` is a string of the character `0`,
  as long as it takes to make the whole frame 8,192 bytes.
- Limits: `caption` at most 2,000 bytes; `name` at most 255 bytes, cleaned
  (no path, no control characters); `mime` at most 127 bytes of
  `a-z 0-9 . + - _` around one `/`; `preview` at most 1,536 bytes before
  base64; `levels` exactly 64 bytes; `width` and `height` 1 to 16,384;
  `duration_ms` 1 to 900,000; a profile picture's side 64 to 512; `seq` and
  `held` at most 2^53 − 1.
- `padded_len` and `chunks` must be what §2 gives for `true_len`.
- `handle` must be the handle of `key` (the empty profile form has 16
  random bytes).
- **One size.** Every offer is 8,192 bytes, so its length says nothing
  about its kind. `key` and `root` come after every other field and the pad
  comes last, so no beginning of an offer holds the key.
- **One byte form.** An offer is accepted only as the bytes the encoder
  writes for what was read: white space, another member order, another
  escape, a pad that is not zeros, or a handle that is not the key's are
  refused.

### 3.2 The stored form

The same object without `key`, `root` and `pad` (a profile picture's also
without `preview`), under the head `RVNATT/1 ref`. A node writes it; a text
with this head that arrives on a link is not an offer: it is taken (ACKed)
and dropped.

## 4. Sending and receiving an offer

- The offer is sealed and sent like a chat message. The staged copy for a
  re-send holds the offer; the history row holds the stored form from its
  first write. A history row never holds `K`.
- The sender keeps a row for the attachment: handle, message id, friend,
  `K`, `R`, the SHA-256 of the offer as it travels, the stored form, the
  state. The offer can be made again from that row, byte for byte.
- **Receiving, attachments live.** An offer of a photo, a voice note or a
  file is accepted and ACKed like chat. Its history row holds the stored
  form. When the sender is a verified friend, the node also keeps a row
  (with `K` and `R`), so the chunks can come. From anyone else no row is
  kept: the attachment can never be fetched.
- A copy of the same offer that comes again (a re-send after a lost ACK) is
  compared with the kept row's SHA-256, and by what a reader shows: only
  another offer under the same message id marks the row as a conflict.
- Offers a phase 1a build kept as they came (§9) take the stored form when
  a build with attachments live first starts; a verified friend's gets its
  row then.
- An offer whose handle already belongs to another attachment keeps the
  first: nothing is replaced.

## 5. Chunks on links: RAX1

RAX1 frames are raw frames on the authenticated link between two nodes,
after RLB1 (and RRH1, and RUP1's HAVE), sorted by their magic like RUP1's.
Never inside an envelope, never through the IPC, never stored for others.

```text
frame  = "RAX1" || 0x01 || op || req_id[4] || body          (at most 65,511 B)

0x01 HAVE        dialer, answered by LACK     n u8 (1..=8), then n times: handle[16] || chunks u16
0x02 WANT        dialer, answered by CHUNKs   handle[16] || first u16 || count u8 (1..=16)
0x03 DONE        dialer, no answer            handle[16]
0x04 PUSH        dialer, no answer            a chunk (below)
0x81 CHUNK       answer to WANT, not final    a chunk (below)
0x82 CHUNKS_END  answer to WANT, final        code u8 || sent u8
0x83 LACK        answer to HAVE, final        n u8 (1..=8), then n times: handle[16] || status u8
                                              || chunks u16 || wanted[ceil(chunks / 8)]
0xFF ERROR       answer, final                code u8

chunk  = handle[16] || index u16 || length u32 (1..=61,440) || bytes
         || path_len u8 (0..=11) || path_len * hash[32]
```

- Integers are big endian. `chunks` in a HAVE is 1 to 1,059. A WANT asks
  for chunks `first .. first + count`, all below 1,059.
- **LACK.** `status` 0: "send the chunks whose bits are set" (bit `i % 8` of
  byte `i / 8`; at least one bit set; no bit past the last chunk). Status 1
  complete, 2 later, 3 declined, 4 not known: then `chunks` is 0 and no
  bitmap follows.
- **CHUNKS_END.** `code` 0 when every chunk asked for was sent, else an
  ERROR code; `sent` counts the CHUNK frames before it (at most 16).
- **ERROR codes.** 1 UNSUPPORTED, 2 NOT_FOUND, 3 BUSY, 4 RATE_LIMITED,
  5 POLICY_DENIED, 6 MALFORMED, 7 GONE.
- The longest frame is a chunk of 61,440 bytes with a path of 11 hashes:
  61,825 bytes.
- **A listener never speaks first.** The dialer sends HAVE, WANT, DONE and
  PUSH; the listener sends only CHUNK, CHUNKS_END, LACK and ERROR. A side
  that gets an op the other side never sends refuses the frame.

### 5.1 Decode rules

A fixed order; every count and length is checked before a byte is copied;
nothing follows the last field; an accepted frame re-encodes byte for byte.
A request with a body that does not read is answered with ERROR MALFORMED
under its request id (so the dialer is not left waiting); a PUSH or a DONE
that does not read is dropped.

### 5.2 Negotiation: link caps bit 12

`CAP_LINK_ATT1 = 0x00001000`: "this node takes `RVNATT/1` offers and RAX1
frames inside ordinary link limits". It rides the signed RIH1 hello and, on
LAN, the RLX1 `LINK_CAPS` of the dialer's Noise message 3 (only on a dial
that reads), like bits 8 to 11. It is never set on a Bluetooth link. No
build sets it while the gate is shut; old nodes ignore it.

- A node keeps, per verified friend, whether an authenticated link showed
  the bit. The bit writes the record; caps without the bit clear it; a link
  that showed no caps (a LAN listener sends none) changes nothing.
- A node sends RAX1 frames only to a friend with a record. On a link whose
  hello showed caps without the bit, a dial carries no RAX1 frame.
- A listener takes RAX1 frames only from a verified friend whose caps on
  this link showed the bit. Anyone else gets ERROR POLICY_DENIED for a HAVE
  or a WANT, and nothing for a PUSH or a DONE.
- With the gate shut a RAX1 frame is an unknown frame, as in every earlier
  build.

## 6. The exchange

- **Push** (the sender's node dials). It says HAVE for the attachment. The
  friend's node answers what it lacks. The next dial pushes those chunks
  (at most 40) and says HAVE again, until the LACK says complete: then the
  attachment is delivered. A friend that answers "not known" (the offer is
  still on its way) is asked again, first after 2 s, then twice as long
  each time, up to 5 minutes. After a cut the sender asks first again.
- **Pull** (the receiver's node dials). When no chunk landed for 15 s it
  asks the holder with WANT, at most 16 chunks a dial, and says DONE when
  it has them all. An attachment the user asked for is pulled at once.
- **What a receiver takes.** A chunk only for a row it keeps (§4), from the
  friend who sent that offer, in a state that still lacks chunks, and only
  when the chunk proves its place under `R` with its audit path. Then it is
  written at its place, synced, and marked in the bitmap, in that order.
  Three chunks from one source that do not prove their place end that
  source for that attachment (LACK declined).
- **The last check.** When every chunk is here, every chunk must open
  under the offer's key and everything after the attachment's last byte
  must be zeros. Otherwise the attachment is failed and never shown.
- **What a holder serves.** Only an attachment it offered to the friend who
  asks. At most 256 MiB of chunks to one friend a day (RATE_LIMITED).
- **What comes by itself.** Photos and voice notes up to 1 MiB. A file
  waits until the user asks (LACK later). Phase 1 sends nothing bigger
  than 1 MiB.
- **Delivered.** The sender marks an attachment delivered on a LACK of
  status complete or on a DONE from the friend it was offered to.

## 7. At rest

- `attachment_rows/<handle>.row`: the row (with `K` and `R`), sealed with
  the profile like every sealed file.
- `attachments/<handle>/blob`: the sealed chunks as they travel (ciphertext
  under `K`), and `have`: one bit per chunk that is here.
- `attachment_peers.json`: which friends' nodes showed bit 12, sealed.
- `attachments_staging/`: a file an app wrote to be sent; sealed into a
  blob and deleted at once.
- Removing an attachment removes its row first: without `K`, what a disk
  keeps of the blob cannot be read.

## 8. Limits

| Limit | Value |
|---|---|
| One attachment | 64,000,000 bytes (1,059 chunks); 1,048,576 in phase 1 |
| Offer | exactly 8,192 bytes |
| Rows a profile keeps | 4,096 |
| Chunks pushed per dial | 40 |
| Chunks asked per dial | 16, in at most 4 WANT requests |
| Entries in a HAVE or a LACK | 8 |
| Served to one friend | 256 MiB a day |

## 9. Older builds (phase 1a, no gate)

Every build knows the prefix, in chats and in group message bodies:

- An offer of a photo, a voice note or a file is accepted, ACKed and kept
  as it came, so a later build can open it. Every reader shows a line of
  words in its place ("{name} sent a photo. Update Raven to see it."),
  never the offer as text.
- A `profile` offer is ACKed and kept silently: one hidden row per friend,
  the newest `seq` only. It is never shown, listed, counted or announced.
- Any other `RVNATT/` text is ACKed and dropped. None is ever deferred.
- No composer sends text that starts with `RVNATT/`.

## 10. Not in this version

Transfer links for items over 1 MiB (link caps bit 13), chunks held by mail
friends, attachments in groups beyond the offer itself, the `gone` frame's
sending side, quotas by size, deletion with the chat and retention. The
design lists them.

## 11. Vectors and status

No shared vectors yet. Unit tests: `attachment::blob`, `attachment::offer`,
`attachment::link`, `attachment::store`, `attachment::flow`,
`attachment::exchange` (two profiles exchanging frames by hand),
`attachment::peers` in raven-core; `lan_direct` in raven-node
(`a_verified_friends_chunks_are_taken_on_a_lan_link`: a photo over a real
Noise link, and the refusals).
