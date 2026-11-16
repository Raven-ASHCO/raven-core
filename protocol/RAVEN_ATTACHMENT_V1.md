# RAVEN Attachment V1 (RVNATT/1 and RAX1)

| | |
|---|---|
| **Status** | Draft. Production disabled: `ATTACHMENTS_PRODUCTION_ENABLED = false`. Lab switch `RAVEN_LAB_ATTACHMENTS=1` with `RAVEN_LAB_TEST_A=1`, debug builds only. Phase 1a (§9) has no gate. |
| **Design** | `docs/design/2026-11-attachments.md`; profile pictures: `docs/design/2026-11-profile-pictures.md` |
| **Code** | `node/crates/raven-core/src/attachment/` (`blob.rs`, `offer.rs`, `shown.rs`, `store.rs`, `flow.rs`, `link.rs`, `exchange.rs`, `peers.rs`; profile pictures: `jpeg.rs`, `picture.rs`), `node/crates/raven-node/src/attachments.rs` |
| **Feature id** | `feature/attachments`; profile pictures (§10): `feature/profile-pictures`, gate `PROFILE_PICTURES_PRODUCTION_ENABLED = false` (a security notice can hold either; close only) |
| **Not frozen** | Not in a release with the gate open. No test vectors yet (§12). |

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
- **Room.** One friend's offers keep rows for at most 1,024 attachments, a
  quarter of the store. An offer that finds no room (that share is used up,
  or the store is full) is kept as it came, as in §9, and gets its row when
  a later start finds room: it is never reduced to the stored form, which
  holds no key and could not be fetched.
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
  or a WANT, and nothing for a PUSH or a DONE. Whether the peer is a
  verified friend that is not blocked is asked for every frame: one blocked
  while its link is open is refused from its next frame on.
- RAX1 frames are said only by the node's own task. A program on the
  node's IPC cannot make a dial carry one (`ATTACHMENT_IPC_REFUSED`).
- With the gate shut a RAX1 frame is an unknown frame, as in every earlier
  build.

## 6. The exchange

- **Push** (the sender's node). The chunks ride the link that carried the
  offer: right behind the offer's answer (its ACK: the friend's node kept
  the offer's row before it answered) the dialer writes every chunk (at
  most 40) and HAVE on that same link, and the listener answers with a
  LACK that says complete. Then the attachment is delivered. No dial of
  its own, which over Tor is most of a small photo's time. This holds for
  a link's own stream and for a Tor link kept from an earlier send, and
  only within the time the dial has left (at most 20 s); otherwise, and
  after a cut, the node dials: when the offer's delivery is written it
  pushes every chunk and says HAVE, and whenever it does not know what the
  friend has it says HAVE first, pushes what the LACK names and says HAVE
  again, until the LACK says complete. While a send of the offer is under
  way nothing is asked beside it. An offer whose delivery the node did not
  see is asked for with HAVE, after 5 s and then ever less often (up to 6
  hours apart, for at most 8 days). A friend that answers "not known" (the
  offer is not there yet) is asked again later.
- **How much, and how often.** The chunks of one attachment are pushed at
  most 8 times over in a day, whatever the friend's answers ask for; then
  the attachment waits for the next day and asks first. A try that failed
  waits before the next one, longer each time: up to 5 minutes for about
  the first hour, then 30 minutes for about a day, then 6 hours. A friend
  that was not reached is not dialled for its other attachments meanwhile.
  A link with the friend coming up ends these waits at once; it does not
  end a wait the friend's own answer set (later, declined, busy), or the
  day's limit. An attachment 30 days old is no longer dialled for by
  itself, mine or a friend's: the friend's own dial still moves it, and one
  the user asks for is fetched whatever its age. The dials of one look go
  to different friends and run side by side.
- **Pull** (the receiver's node dials). When no chunk landed for 15 s it
  asks the holder with WANT, at most 16 chunks a dial, and says DONE when
  it has them all. An attachment the user asked for is pulled at once. An
  answer of GONE turns only an attachment that still lacks chunks into "no
  longer available"; one that is whole stays. When every chunk is here and
  the last check did not run (the process stopped in between), the check
  runs at the next look and the holder is told with DONE.
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
  asks. At most 256 MiB of chunks to one friend a day (RATE_LIMITED); once
  the day is used up a request is refused before anything is read.
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
  blob and deleted at once. It is the attachment as the app wrote it, not
  sealed: one that was never sent (the app ended in between) is removed
  when the engine next stages a file, and by the node's sweep after 10
  minutes.
- Removing an attachment removes its row first: without `K`, what a disk
  keeps of the blob cannot be read.
- In memory, the hex copies of `K` in a row and in an offer's fields are
  wiped when they are dropped.
- **Open before the gate opens** (design §27): in a profile that is not
  sealed a row is a plain file, as that profile's other files are, while
  its chat history is protected by the platform's key; and the row and the
  blob folder are named by the handle, the same on the sender's disk and on
  the receiver's.

## 8. Limits

| Limit | Value |
|---|---|
| One attachment | 64,000,000 bytes (1,059 chunks); 1,048,576 in phase 1 |
| Offer | exactly 8,192 bytes |
| Rows a profile keeps | 4,096 |
| Rows one friend's offers keep | 1,024 |
| One attachment's chunks pushed | 8 times over a day |
| Dialled for by itself | for 30 days |
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

## 10. Profile pictures

Version 1: one picture a person sets, sent to each friend they verified, and
shown by a friend's Raven only while that friend has verified them. Behind
`PROFILE_PICTURES_PRODUCTION_ENABLED` (false; never open while the
attachments gate is shut), feature id `feature/profile-pictures`, lab switch
`RAVEN_LAB_PROFILE_PICTURES` beside the attachments switches. Design:
`docs/design/2026-11-profile-pictures.md`; its §28 says what of it is built.

### 10.1 The picture

- A baseline JPEG, square, 64 to 512 pixels a side (apps send 384), at most
  60,000 bytes. Its preview: the same rules, 16 to 64 pixels, at most 1,536
  bytes.
- **The file's form** (`attachment::jpeg::check`). In this order and nothing
  else:
  1. SOI;
  2. one JFIF APP0 of 16 bytes: version 1, a known unit, densities that are
     not 0, no thumbnail;
  3. the quantization tables (DQT): 8 bit, at most 4, no number twice, no
     value 0;
  4. one SOF0: 8 bit samples; 1 or 3 components, none twice; width equal to
     height; the first of three components sampled 1 or 2 each way and every
     other component 1; each names a quantization table that is there;
  5. the Huffman tables (DHT): classes 0 and 1, numbers 0 and 1, none twice;
     counts that make a prefix code with no code of all ones; DC symbols 0 to
     11; AC symbols with a size of 1 to 10, or 0x00, or 0xF0; no symbol
     twice; every table a component names is there;
  6. at most one DRI, never 0;
  7. one SOS with every component in the frame's order, Ss 0, Se 63, Ah and
     Al 0;
  8. the scan's data, in which 0xFF is followed only by 0x00, by a restart
     marker, or by EOI. The restart markers RST0 to RST7 come in their order
     and exactly as many as the interval and the picture's size ask for; a
     scan shorter than two bits a block is refused;
  9. EOI, and no byte after it.
- Refused with everything else: SOF1 to SOF15, DAC, DNL, DHP, EXP, every
  other APP segment, COM, any other marker, fill bytes between segments, a
  length that runs past the file.
- **Made so by the sender** (`attachment::jpeg::clean`). What an encoder
  wrote is written again in that order under a plain JFIF header: one DQT
  segment a table, lower numbers first; SOF0; one DHT segment a table, DC
  before AC; a DRI only when its interval is not 0; the scan as it is.
  Segments that hold no pixel are left out. A file whose Adobe segment says
  that its three components are not YCbCr, or whose three components are
  named R, G and B with no JFIF header, is refused: leaving the segment out
  would change its colours. So what leaves a device is exactly what every
  receiver takes.
- A receiver checks the bytes again before anything decodes them, and the
  side against the offer's `width`. Neither check decodes anything. A
  picture that fails goes at once.

### 10.2 The offer and its chunk

- **A key for each friend.** Every offer has a new random `K`, so the copies
  two friends get share no handle, no key and no byte. The picture is padded
  with zeros to one segment of 61,424 bytes and sealed as chunk 0 of 1 (§2);
  `R` is its leaf.
- The offer is §3.1's `profile` kind. `seq` orders a sender's profile
  offers: its clock in milliseconds, and at least the last `seq` it used
  plus one, one count for all friends. `held` is the `seq` of the
  receiver's newest profile offer that the sender holds; 0 for none.
- The empty form (`chunks` 0) says that the sender has no picture (any
  more).
- The offer travels as a message to that friend, and is never a chat
  message on either side. The sender's history row holds its stored form
  (no key, no root, no preview), and no reader shows, lists or counts it.
- The chunk travels as every attachment's does (§5, §6): pushed on the link
  that carried the offer, or pulled. A profile picture comes by itself, like
  a photo.

### 10.3 Who gets one, and when

A sender looks at its contact book and its own records, not at events:

- Only a contact that is verified and not blocked, and whose node showed
  link caps bit 12, is offered a picture.
- A friend is due an offer when it has none of the sender's newest choice (a
  picture, or none): after a change, after being verified, after its node
  first showed bit 12.
- **The first look of a store** (a new one, or one made again after the old
  was lost) only notes the friends verified by then. While the sender has
  never chosen, those friends are offered nothing, so a lost store never
  tells them that there is no picture. A friend verified after that look is
  due an offer like any other: the empty form when there is no picture. It
  carries `held`, and so lets that friend send its own picture again when
  the sender holds none of it.
- **Repair.** A friend whose profile offer came after the sender's was made,
  and carries a `held` lower than the `seq` it took, has lost the sender's
  picture: it is offered again, at most once a day.
- At most 4 offers for one friend in a day, and 3 changes of the picture in
  a day.
- An offer whose message never left, or ended without arriving, is made
  again, with a new key and `seq`.
- When the friend's node has the chunk, the sender removes the offer's row:
  the key goes with it, and a later request for that handle finds nothing.
- A contact that is no longer a verified friend is forgotten at the next
  look: what was sent to it, what it sent, and the rows of both.

### 10.4 What a receiver keeps

- With the gate shut, or from a contact the receiver has not verified: §9,
  the hidden row, the newest `seq` only. Once pictures are live and the
  words match, the kept offer is taken up and its row leaves the history;
  its chunk is then pulled.
- From a verified friend the newest `seq` wins. An offer with a higher `seq`
  replaces what is held at once: row, chunk and preview. The same offer
  again changes nothing. A lower or equal `seq` is ACKed and dropped. The
  empty form removes the picture. More than 8 offers from one friend in a
  day are ACKed and dropped.
- Nothing is decrypted or decoded when the offer or the chunk arrives. An
  app asks the engine, which opens the chunk in memory, checks it (§10.1)
  and hands over the bytes. Whether a picture shows is worked out at that
  moment from the contact book and is never stored: a contact that is not
  verified, or is blocked, shows none.
- Three pictures from one friend that fail the check in a day: none of that
  friend's is opened until the next day.
- A picture belongs to the contact, not to a chat. Clearing or deleting the
  chat, and the sweep of attachments whose message is gone, leave it alone.
  A picture's row that no record names is the sweep's to remove.

### 10.5 At rest

- `pictures_mine.json`: the picture as it travels, its preview, the number
  of the newest choice and the last `seq`.
- `pictures_sent.json`: for each friend, which choice went, its `seq`, the
  handle of its row and how far it is.
- `pictures_theirs.json`: for each friend, the newest `seq`, the digest of
  its offer, the handle of its row, its preview and the `held` it carried.

All three are sealed files of kind `attachments`, under a writer lock of
their own. A friend's chunk lies in the attachment store under its handle
(§7), ciphertext under the `K` of its row.

### 10.6 Not in this version of profile pictures

More than one picture (a face for each circle), a picture taken when
friends meet, the chunk held by mail friends, the chunk of an offer taken
before the receiver verified the sender (only the offer is kept until
then), a setting that hides every picture, offers spread over an hour
after a change (they go at once, as messages do), and raven-node sending
by itself: an offer is made by an app's engine while it runs, or by the
terminal's lab command.

## 11. Not in this version

Transfer links for items over 1 MiB (link caps bit 13), chunks held by mail
friends, attachments in groups beyond the offer itself, the `gone` frame's
sending side, quotas by size, deletion with the chat and retention. The
design lists them.

## 12. Vectors and status

No shared vectors yet. Unit tests: `attachment::blob`, `attachment::offer`,
`attachment::link`, `attachment::store`, `attachment::flow`,
`attachment::exchange` (two profiles exchanging frames by hand, what a
friend's node cannot make this node do, and a profile picture travelling
between two verified friends),
`attachment::peers`, `attachment::sweep`, `attachment::jpeg` (the form of a
picture's file, every refused marker, every cut of a file, and the rewrite
of an encoder's file) and `attachment::picture` (who is due an offer, the
newest `seq`, verified friends only, repair, the limits) in raven-core; in raven-node
`lan_direct` (`a_verified_friends_chunks_are_taken_on_a_lan_link`: a photo
over a real Noise link, and the refusals) and `internet_direct`
(`a_photo_crosses_an_internet_direct_link_in_one_dial`: the real dial, bit
12 in both hellos, and nothing sent with the gate shut); in raven-client,
two engines with their raven-node: `tests/attachments.rs` (loopback LAN)
and `tests/net_tor.rs` (`tor_a_photo_rides_the_link_that_carried_its_message`:
friends reached over the onion carrier alone).
