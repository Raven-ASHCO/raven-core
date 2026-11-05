# Attachments over every carrier: photos, voice notes and files (v1)

| | |
|---|---|
| **Status** | Architecture, third draft. The owner confirmed all ten decisions of §23 on 2026-11-05. Nothing is built yet. Not normative: the wire spec and the custody amendment it calls for (§22) do not exist yet. It changes no frozen byte. |
| **Review** | Two independent reads of the code on 2026-11-05. The first found 17 problems in the first draft (chunks sent as messages, mail friends, groups, link limits, storage, several numbers); the second found 13 in the second draft. This draft fixes all 30; §25 lists each one. |
| **Requested** | By the owner, 2026-11-05: photos, voice notes and files, over Tor, and fast. "Only the architecture." |
| **Gates (new)** | `ATTACHMENTS_PRODUCTION_ENABLED = false` (offers and live chunks up to 1 MiB, §9); `ATTACHMENT_CUSTODY_PRODUCTION_ENABLED = false` (mail friends hold chunks, §12; asserts the first and `FRIEND_CUSTODY_PRODUCTION_ENABLED` at compile time); `ATTACHMENT_EXCHANGE_PRODUCTION_ENABLED = false` (transfer links up to 64 MB, §10; asserts the first). Lab switches `RAVEN_LAB_ATTACHMENTS=1`, `RAVEN_LAB_ATTACHMENT_CUSTODY=1` and `RAVEN_LAB_ATTACHMENT_EXCHANGE=1` with `RAVEN_LAB_TEST_A=1`, debug builds only. |
| **Wire (to write)** | `protocol/RAVEN_ATTACHMENT_V1.md`: the blob, the `RVNATT/1` offer and its stored form, the `RAX1` link frames, link caps bits 12 and 13. An amendment to `protocol/RAVEN_FRIEND_CUSTODY_V1.md`: RFC1 ops 0x09 to 0x0B for chunk objects, under its existing op registry. |
| **Builds on** | RRB1's chunk tree and audit paths, RUP1's frame rules and download order, `RVNGRP/1` messages exactly as they are, RFC1 friend custody (mail friends), the outbox and the long horizon. |
| **Owner constraints** | No Raven server (D1). Everything private and encrypted: nothing a third party can read, no address in anything copied around. No new crate or package without approval. Plain words in the apps. |
| **Tree read** | raven-core `tor-speed/integration` 9187bbf (main plus the Tor speed work); raven-macos `ui/macos-integration`; raven-ios; raven-core-ios `feature/ios-embedded`; raven-windows; raven-linux. |
| **Date** | 2026-11-05 |

Path shorthand: `core/` = `node/crates/raven-core/src/`, `rn/` =
`node/crates/raven-node/src/`, `cl/` = `node/crates/raven-client/src/`,
`ash/` = `node/crates/ash/src/`, `sw/` = `node/crates/raven-swarm/src/`,
`proto/` = `protocol/`.

Sizes: 1 MiB is 1,048,576 bytes; 64 MB is 64,000,000 bytes.

---

## 0. Decisions on one page

1. **The apps prepare media; raven-node never parses it.** A photo is
   shrunk to 1,600 pixels on its long side and saved as JPEG with no
   metadata (no location, no device). A voice note is Opus at 24 kbit/s. A
   file goes as it is. Each app uses its system's own image and audio code;
   raven-node sees bytes, a size and a kind.
2. **Encrypt once, check every piece.** raven-node pads the bytes to a size
   class (Padmé, §7.2), seals them in 61,440-byte chunks with a random key
   used for this attachment only, and builds the RFC 6962 tree that release
   bundles already use. Every chunk travels with its audit path, so the
   receiver checks each one the moment it lands, whoever passed it on.
3. **The offer is the only message.** An `RVNATT/1 offer` carries the key,
   the root, the sizes, the kind and a tiny preview, padded to exactly 8,192
   bytes so its length says nothing about the kind. In a chat it is an
   ordinary sealed message. In a group it is the body of an ordinary signed
   group message, so the author's signature covers it and no group byte
   changes. It goes everywhere text goes, and the friend sees a blurred
   preview as soon as it lands.
4. **The bytes never travel as messages.** Chunks move as `RAX1` frames on a
   link between two nodes, outside the message keys, the queue, the
   outbound stage and the history. An attachment costs one message key and
   one queue slot, whatever its size. (The first draft sent chunks as
   messages; §25 says why that could not work.)
5. **Three ways for the chunks.**
   - **Live, up to 1 MiB** (phase 1): a photo's or voice note's chunks
     follow the offer on the same link, inside today's link limits; the
     friend's node can also pull them.
   - **Mail friends, up to 1 MiB** (phase 1, chats only): chunk objects
     through three new custody ops. A mail friend on an older build answers
     UNSUPPORTED and is skipped.
   - **Transfer links, up to 64 MB** (phase 2): longer links with a window,
     push and pull, resume, two Tor links for big files, and a move to LAN
     or direct mid transfer.
6. **Fast on Tor** (§11). Small items follow their offer on the link that is
   already open; the preview shows first; the window matches Tor's flow
   control; LAN and direct paths win when they exist; a cut costs nothing
   already checked. Arti's congestion control was a separate owner decision
   (§11.4).
7. **No friend gets what it cannot read.** First, every build learns to show
   an offer as "{name} sent a photo. Update Raven to see it." instead of text
   (phase 1a). Then a node announces attachments with link caps bit 12 (and
   bit 13 for transfer links), and a sender sends offers and chunks only to
   friends whose node announced it.
8. **Storage.** A new `attachments.sqlite` with sealed rows and secure
   delete, registered for key rotation like `friend_custody.sqlite`, and a
   folder of ciphertext blobs. History rows never hold the key, so the
   history format does not change.
9. **Privacy** (§18). Content, kind, names, captions and previews are end to
   end; sizes are rounded; every offer has the same size; photos lose their
   metadata; mail friends and the network learn counts, size classes and
   times, never content.
10. **iPhone** (§17). Transfers run while Raven is open, finish in the
    existing 15 s of grace when it leaves the screen, and resume on the next
    open. No background Tor.
11. **Limits** (§23, confirmed 2026-11-05): 64 MB per attachment, 16 MB in groups,
    1 MiB through mail friends, captions up to 2,000 bytes; photos and voice
    notes download by themselves, files on a tap.

---

## 1. What users get

- **Photo.** Pick or take a photo. The friend sees a blurred preview at once
  and the sharp photo a few seconds later.
- **Voice message.** Hold the microphone, speak, let go. The friend sees the
  length and a wave, and plays it at 1x, 1.5x or 2x.
- **File.** Any file up to the limit. The friend sees the name, size and
  type, downloads it with a tap, then opens or saves it.
- Each is end to end encrypted like a text message, works on every way
  Raven reaches a friend, and survives a cut connection.
- Several photos at once are several messages.

## 2. What exists today (verified in this tree)

Every number below comes from the code at 9187bbf. Several specs and design
docs still call Tor, mail friends, groups and Bluetooth "off"; the code has
them on, and this design follows the code.

| Fact | Value | Where |
|---|---|---|
| One link frame | Noise message ≤ 65,535 B, content ≤ 65,519 B | `core/lan_noise.rs:29-31` |
| One message | text ≤ 49,152 B (`MAX_LAN_ENDPOINT_TEXT`); UTF-8 with no C0 control character but tab, LF and CR, and no DEL (C1 controls pass) | `core/lan_noise.rs:33`, `core/indexed_session_store.rs:194-207` |
| Message keys | a receiver keeps at most 256 skipped keys and takes a jump of at most 256 | `core/indexed_session_store.rs:116-117` |
| Envelope | text + 192 B; no padding inside | `core/envelope.rs`, `core/atsam_indexed_session.rs:43-46` |
| Media | "MUST use a separately versioned bounded/chunked transport" | `proto/RAVEN_ENVELOPE_V1.md:105-125` |
| Reserved prefixes | `RVNAPP/` and `RVNGRP/`; any other text is chat and is shown | `core/app_channel.rs:138, 229` |
| Receiving a message | the policy runs inside the session store transaction, on metadata only; history, the app inbox and the group store are written after the commit, and the ACK waits for them | `core/app_channel.rs:330-352, 403`, `core/lan_dispatch.rs:2529-2547` |
| Sending a message | every seal writes a queued history row holding the exact body, and the outbound stage keeps the exact text for re-send: 256 entries in all, 192 entries and 3 MiB for friends who are away, 32 waiting per friend | `core/lan_dispatch.rs:381-421`, `core/horizon.rs:903`, `core/chat_history.rs:2812-2850`, `ash/pair_init_lab.rs:68-75` |
| History | one encrypted file: 2,000 rows, 4 MiB, rewritten on every change; unknown fields refused; each row has a short `preview` and the exact `body` | `core/chat_history.rs:52-88, 257-268` |
| One dial | ≤ 16 frames from the outbox; an app's own send ≤ 160 KiB per link | `rn/outbox.rs:152`, `ash/pair_init_lab.rs:4376-4381` |
| Dial replies | at most 64, sized for one IPC answer; raven-node's own dials get a bigger byte budget (RUP1 uses it for 16 chunks) | `rn/lib.rs:735-797` |
| Incoming link | 64 frames; 120 s (LAN, Internet direct, p2p), 180 s (Tor), 300 s (Bluetooth); 30 s per frame. The life is a timeout fixed when the link is accepted | `rn/lib.rs:1179-1217, 1673-1676`, `rn/onion/mod.rs:1608`, `rn/p2p.rs:3289`, `rn/internet_direct.rs:91` |
| Link caps | carried by the signed RIH1 hello and by RLX1 in the dialer's Noise message 3; a LAN listener sends none. Bits 8 to 11 in use; unknown bits ignored | `core/internet.rs:61-85`, `core/route_hints.rs:153` |
| Warm link | none: every dial is a new connection and handshake; Tor opens a new stream per dial on a circuit kept 10 min | `rn/lan_direct.rs:1927-2091`, `rn/onion/proto.rs:294` |
| Onion service | stream open 6 s; ≤ 8 open streams per rendezvous circuit; ≤ 4 incoming links per circuit, 16 in all | `rn/onion/arti.rs:49-62`, `proto/RAVEN_ONION_CARRIER_V1.md:103-104` |
| Tor flow control | Arti 0.47 without its experimental `hsc-`/`hss-negotiate-extensions` features: no congestion control on onion circuits, so a 500-cell stream window (about 249 KB in flight per stream) | `node/crates/raven-node/Cargo.toml:138-145`; Arti 0.47 source `tor-proto/src/stream.rs:48`, `tor-hsclient/src/caps.rs:40-55` |
| Bluetooth | macOS only; frames ≤ 512 B; perhaps 5-30 KB/s, not measured; a dial must finish in 40 s | `core/nearby_link.rs:45-52`, `docs/WAIVER_NEARBY_DRAFT.md:133`, `rn/nearby/mod.rs:99` |
| Friend relay | 2 MiB per circuit, 5 min | `sw/host.rs:197-213` |
| Link padding PAD1 | off in release: exact sizes are visible on the wire | `core/security_gate.rs:57` |
| Mail friends | on. An object is RSO1 around one RVN1 envelope (≤ 65,410 B), checked strictly by the keeper; life ≤ 24 h + 5 min. Sender: 16 deposits and 512 KiB per dial. Fetch: 16 items and 128 KiB per page, 8 pages a trigger (4 on a relayed path). Keeper: 16 MiB and 512 rows per depositor, 128 objects per pair, 2 MiB a minute, 64 MiB in all. An unknown RFC1 op gets UNSUPPORTED | `proto/RAVEN_FRIEND_CUSTODY_V1.md:103-114`, `core/custody_client.rs:54-63`, `core/friend_custody.rs:111-148, 809-818`, `core/carrier_admission.rs:54` |
| Groups | on. ≤ 16 members; a message body is 1 to 8,192 B of text, the frame ≤ 49,152 B; the author signs SHA-256 of the body; the wire form refuses unknown fields; one sealed copy per member; one forwarding hop that passes the author's frame as it is; messages kept in `groups.json` | `core/group.rs:46, 93-101, 280-292, 532-541, 702-708`, `core/group/store.rs:130` |
| Storage | bundled SQLite; SQLCipher is refused in release builds. Stores seal their rows (`at_rest::seal_row`) and turn on `secure_delete` | `node/Cargo.toml:41`, `node/crates/raven-core/build.rs:19-21`, `core/friend_custody.rs:1194`, `core/paths.rs:554-562` |
| Chunk exchange | RUP1 (off): 61,440-byte chunks, ≤ 8 per request, ≤ 16 per dial, RFC 6962 tree, audit path ≤ 11 hashes, resumable (the payload synced, then the bitmap), 128 MiB a day per friend | `core/update_exchange.rs`, `core/release_bundle.rs:76-82, 897`, `rn/update_exchange.rs:2070-2080` |
| iPhone | the background mail check runs without Tor (LAN and Internet direct only); Tor in the foreground only; 15 s of grace when Raven leaves the screen | `rn/lib.rs:5151-5154`; raven-ios `Raven/App/Background.swift`, `Raven/State/AppModel+Actions.swift:238-286` |
| Apps | no image, audio or file code in any of the four; no media crate in the node | |

**Speed today.** The October field test measured 11 to 28 s per Tor message,
each on its own connection (`docs/FIELD_TEST_2026_10.md:68-81`). The Tor
speed work since then removed round trips but has no new measurement. For
throughput, Tor Metrics (August to October 2026, C Tor clients with
congestion control, downloads from onion services) gives medians of 1.8 s
for 50 KiB, 4.6 s for 1 MiB and 13.4 s for 5 MiB: from 1 to 5 MiB, about
475 KB/s.

## 3. Goals and non-goals

Goals:
- Photos, voice notes and files between friends and in groups.
- End to end: nobody but the people in the chat can read the content, its
  kind, its name or its preview.
- Every way Raven reaches a friend, Tor included, and mail friends for small
  items.
- Fast: the preview at message speed, a photo a few seconds later.
- Resumable: a cut never makes a checked chunk travel twice.
- Bounded: every size, count and rate has a cap; a friend cannot fill a disk
  or a link.
- One message per attachment: the bytes never use message keys, queue slots,
  stage entries or history rows.
- No new carrier, no server, no new crate in the node.

Non-goals in v1: video transcoding (a video goes as a file); calls
(`proto/RAVEN_PRIVATE_REALTIME_MEDIA_V1.md` keeps them separate and says a
voice note is not a call); delete for everyone; the same attachments on the
user's other devices; anything public.

## 4. The design in one picture

```text
 Sender app         Sender raven-node                          Friend raven-node            Friend app
 ----------         -----------------                          -----------------            ----------
 pick, record --->  pad, seal with key K,
 shrink, strip      chunks and tree root R,
 tiny preview       blob store and row
                       |
                       |-- OFFER (K, R, sizes, preview): 8,192 B, one sealed message ---> row ---> blurred preview
                       |     any carrier, mail friends, groups (as the signed body)
                       |
                       |== RAX1 CHUNKs, each with its audit path ========================> blob store
                       |     live link: LAN, Internet direct, hole punching, Tor;
                       |     Bluetooth and friend relays up to 1 MiB
                       |
                       '-- friend away, up to 1 MiB: chunk objects at mail friends -----> blob store
                                                        (every chunk checked against R as it lands)
                                                                          |
                                                               complete --'--> opened in memory --> photo, play, save
```

## 5. Options considered

| Option | For | Against |
|---|---|---|
| A. Chunks as sealed messages (the first draft) | Would ride every carrier, mail friends, groups and the horizon as they are | Each piece takes a message key (from a window of 256), a queue and stage slot and a history row holding its exact body, plus a third more for base64. A friend who is away could get only 16 pieces through mail friends, and a group multiplies all of it by the members. The review showed it does not fit (§25) |
| B. Chunks on live links only | Fastest; raw bytes; few round trips | Two phones rarely open at the same time would rarely get a photo |
| **C. Chunks on links, and at mail friends for small items (chosen)** | One message per attachment; raw bytes everywhere; small items reach friends who are away; chunks can be checked one by one, so anyone holding them can pass them on | A new link frame and three new custody ops |

Option C also gives a clean order of work: phase 1 moves small items inside
today's link limits; phase 2 changes the link limits for big files.

## 6. Preparing media in the apps

The apps do all media work with their system's own code. raven-node gets a
file in its staging folder (§15) and never decodes an image or a sound.
This keeps media parsers, a classic attack surface, out of the node, and
needs no new crate.

### 6.1 Photos
- Long side 1,600 px; JPEG quality 0.8: typically 150 to 400 KB. An
  "original" choice sends the untouched file as a File instead.
- All metadata dropped (location, device, time, edits); the orientation is
  applied to the pixels first.
- HEIC, PNG, WebP and the rest become JPEG. An animated image goes as a File.
- Tools: macOS and iOS ImageIO, with PHPicker on iOS (it needs no photo
  library permission); Windows `BitmapDecoder` and `BitmapEncoder`; Linux
  gdk-pixbuf, already in the app through GTK.
- Preview: the same photo at 32 px on its long side, JPEG quality 0.4, at
  most 1,536 B. The friend's app shows it scaled and blurred.

### 6.2 Voice notes
- Mono, Opus at 24 kbit/s in an Ogg file (RFC 7845): about 180 KB a minute.
  At most 5 minutes in phase 1 (which carries up to 1 MiB), 15 minutes from
  phase 2.
- Preview: the length and 64 loudness levels of one byte each, drawn as the
  wave.
- Tools: macOS and iOS AudioToolbox (Opus since iOS 11 and macOS 10.13, to
  be proven in the first build; the Ogg pages are a few hundred lines of
  Swift). Windows has no system Opus encoder and needs one small library;
  Linux needs GStreamer. Both are new packages and need the owner's approval
  (§23, decision 2). The other choice, AAC, is built into Apple and Windows,
  is about a third bigger for the same voice, and still needs GStreamer on
  Linux.
- Permissions: the microphone usage text on iOS; on macOS the usage text and
  the audio input entitlement of the hardened runtime.

### 6.3 Files
- Sent as they are, with the name (at most 255 bytes, cleaned, §18.3), the
  MIME type the system gives (at most 127 bytes), and the size.
- No preview in v1: the app shows an icon by type.

### 6.4 What an app hands raven-node
`attachments.send` (§15) with: the staged file, the kind (photo, voice,
file), the MIME type, the name (files), a caption (at most 2,000 bytes), the
preview, width and height (photos), and the length and levels (voice).

## 7. The blob: one encryption for every path

### 7.1 Keys and names
- `K`: 32 random bytes, new for every attachment. Never derived from the
  content, so two copies of one photo are unrelated (no convergent
  encryption, which `proto/RAVEN_USER_OWNED_ARCHIVE_V1.md` also forbids).
- Chunk key: HKDF-SHA256 of K with the label "rvnatt/1 chunk key".
- Handle: the first 16 bytes of HKDF-SHA256 of K with the label
  "rvnatt/1 handle". It names the attachment on links and on disk, so the
  root never appears outside sealed messages.
- Custody id of chunk i: the first 16 bytes of HKDF-SHA256 of K with the
  label "rvnatt/1 custody id" and i as a big endian u16. A mail friend sees
  only these (§12), so it cannot tell from the ids which chunks belong
  together.

### 7.2 Padding
The bytes are padded with zeros to Padmé(length), the padding of the PURBs
paper: a size keeps only about log log n bits and grows by at most 12 %;
between 150 KB and 64 MB the growth is 0 to 3.1 % (a 1,048,577-byte file
becomes 1,081,344 bytes; a 409,600-byte one stays as it is). The true length
is in the offer. Every chunk but the last has the same size, so a carrier or
a mail friend learns a count and a size class, not a size.

### 7.3 Chunks and tree
- The padded bytes are cut into segments of 61,424 bytes, each sealed with
  XChaCha20-Poly1305 (the AEAD the node already uses at rest, crate
  `chacha20poly1305`) into a chunk of 61,440 bytes; the last may be shorter.
- Nonce: the chunk index as a big endian u64, then 16 zero bytes. The key
  serves one attachment only, so a counter is safe.
- Additional data: "rvnatt/1", the padded length, the chunk count and the
  index. A chunk cannot move and the file cannot be cut short.
- The tree is RFC 6962 as in RRB1 (`core/release_bundle.rs`): leaf
  SHA-256(0x00 || chunk), node SHA-256(0x01 || left || right). Its root R is
  in the offer.
- Limits: an original of at most 64,000,000 bytes pads to at most 65,011,712
  bytes, in at most 1,059 chunks, 65,028,656 bytes once sealed. That stays
  under RRB1's `MAX_PAYLOAD_LEN` of 67,108,864 (`core/release_bundle.rs:78`),
  so its tree code and audit paths (at most 11 hashes) are reused as they
  are. A full 64 MiB would not fit: its 1,093 tags add 17,488 bytes.
- Every chunk travels with its audit path and is checked against R with
  RRB1's `verify_chunk_path` (`core/release_bundle.rs:897`) the moment it
  lands, whoever sent it: the author, a group member, a mail friend or a
  second link.

## 8. The offer

### 8.1 Frames
Like `RVNGRP/1`, a frame is text: `RVNATT/1 <kind>`, a line feed, then strict
JSON with unknown fields refused.

| Kind | Carries | Size |
|---|---|---|
| `offer` | version, handle, kind (photo, voice, file), chunk count, padded and true length, MIME type, name (files), caption, preview, width and height or length and levels, then key K and root R, and last a `pad` member of zeros | exactly 8,192 B |
| `gone` | handle: the author deleted the attachment before the friend had all of it | small |
| `ref` | stored only, never sent: the offer without K and R (handle, kind, sizes, MIME type, name, caption, preview, levels) | under 8,192 B |

- **One size.** Without the pad, an offer with a preview would be bigger
  than one with levels, and a mail friend would learn the kind. The field
  limits keep the worst case (a caption of 2,000 bytes, which JSON escaping
  can double; a name of 255 bytes; a MIME type of 127; the preview of 1,536
  bytes as 2,048 base64 characters; 64 levels; the fixed fields) near 7,200
  bytes, so the pad always has room.
- **Field order.** K and R come after every other field and the pad comes
  last, so no beginning of an offer holds the key, and a store can drop the
  pad and put it back byte for byte (§13).
- **Why 8,192.** It is the group body limit (`core/group.rs:97`), so the same
  offer is a group message as it is (§13).

### 8.2 Sending an offer
The offer is sealed like a chat message, and the outbound stage keeps its
exact text for re-send (`core/lan_dispatch.rs:381-421`, `core/horizon.rs:903`,
`core/chat_history.rs:2848-2850`). The history row never holds K. Every
history write goes through `persist_lan_chat_history`
(`core/lan_dispatch.rs:232-255`), including the paths that write a staged
body back: delivery (`core/outbox.rs:498-509, 567-571, 857-891`), failure,
expiry and cancel (`core/outbox.rs:603-632`), and the start-up reconcile
(`core/lan_dispatch.rs:498`). So that function turns any `RVNATT/` body into
its `ref` form and sets the row's `preview`, today the first 120 characters
of the body (`core/lan_dispatch.rs:245`), to "Photo", "Voice message 0:42"
or the file name. Rows that a phase 1a build kept as they came are
converted the same way when the attachment build first opens the history.

### 8.3 Receiving an offer
The policy accepts an offer from a verified friend on metadata only, inside
the session store transaction, as it does chat (`core/app_channel.rs:330-352`).
After the commit raven-node writes the attachment row (with K and R) and a
history row whose body is the `ref` form, and only then ACKs
(`core/lan_dispatch.rs:2529-2547`). The branch is new in five places:
`classify`, `inbound_policy`, `deliver_committed`, `ingest_pending_committed`
and `archive_inbox_row` (`core/app_channel.rs:138, 339, 403, 543, 602`); the
archived inbox row keeps the `ref` form too.

A copy of the same offer can come again (a re-send after a lost ACK). Today
such a copy is compared with the stored body, and any difference marks the
row `id_conflict` (`core/app_channel.rs:414-434`,
`core/chat_history.rs:512-520`); a stored `ref` would never match. So the
attachment row keeps the SHA-256 of the offer as it came, and a copy is
compared with that: only a different offer under the same id is a conflict.

### 8.4 Older builds
- **Phase 1a, first and alone.** Every build learns `RVNATT/`, in chats and
  in group message bodies: an offer is accepted, ACKed and kept as it came,
  so a later build can open it, and shows (also as the chat list preview) as
  "{name} sent a photo. Update
  Raven to see it." (or a voice message, or a file). It is never shown as
  text and never deferred. Any other `RVNATT/` kind is ACKed and dropped.
  Without this step, today's builds would show an offer as text.
- **Then bit 12.** A sender sends offers and chunks only to friends whose
  node announced bit 12 (§10.1).
- **Groups** cannot rely on bit 12 for every member (§13); there the
  placeholder of phase 1a is what an older member sees.

## 9. Way 1: live chunks (phase 1, up to 1 MiB)

1. `attachments.send` writes the blob and the row, then puts the offer in the
   outbox like a chat message.
2. **Push.** When the offer's ACK comes back on a link the sender's node
   dialed, the node keeps that link open and pushes the chunks of a photo or
   a voice note on it as `RAX1 PUSH` frames (§10.2); a file waits for the
   friend's tap. This changes every dial function: it hands the open link to
   the attachment pump from inside its own deadline
   (`rn/nearby/mod.rs:884-899` is one). Per link:
   - at most 40 chunks, so that with up to 16 outbox frames and the dialer's
     other frames a listener sees at most 60 of its 64;
   - on a friend relay, under 1.9 MiB in all, the dial's own frames
     included, inside the relay's 2 MiB per circuit (`sw/host.rs:206`), as
     custody's relayed fetches stay inside it (`core/custody_client.rs:58-63`);
   - on Bluetooth at most 2 per dial, which keeps the dial inside its 40 s
     even at 5 KB/s.

   Pushed chunks need no answer. On a later link the node says HAVE first
   and pushes only what the friend's node asks for.
3. **Pull.** A friend's node that lacks chunks dials the holder and asks with
   `RAX1 WANT`, up to 16 chunks per dial, with raven-node's own reply budget
   as RUP1's follow-up dials use it (`rn/lib.rs:743-749`). This is how a
   download on a tap works, how an iPhone gets a photo when it opens, and how
   a cut resumes.
4. **Checking.** Each chunk is checked against R with its audit path at once,
   then written in RUP1's order: the chunk at its offset, a sync, then the
   bitmap (`rn/update_exchange.rs:2070-2080`). A chunk that fails is dropped;
   a source that sends three bad ones is not asked again for that attachment.
5. **Friend away.** If no link to the friend comes up within 60 s while the
   sender's node runs, the chunks of an item up to 1 MiB go to the friend's
   mail friends (§12). Otherwise they wait on the sender, which keeps the
   blob, until a link comes. An iPhone that leaves the screen first keeps
   them for its next open (§17).
6. **Delivered.** When the receiver's node has every chunk it says
   `RAX1 DONE` on its next dial to the sender, or answers the sender's next
   HAVE with a LACK whose status is complete; the sender's bubble then turns
   Delivered.
7. **Capability.** A node sends RAX1 only to a friend whose record shows bit
   12; a listener takes RAX1 only from a dialer whose hello on this link
   showed bit 12. On LAN a listener sends no caps (`core/route_hints.rs:153`),
   so the dialer goes by its record, which the friend's own dials keep fresh.

Speed: on Tor the chunks start as soon as the offer's ACK is back, on a link
that is already open. A 300 KB photo (5 chunks) lands about 1 to 4 s after
the offer; a 1 MiB item (18 chunks) about 3 to 10 s. Phase 0 measures these
(§21).

Why it stops at 1 MiB: today's link limits (64 frames, 120 to 180 s, 16
chunks per pull dial). Bigger items need the link changes of phase 2.

## 10. Way 2: transfer links (`RAX1`, phase 2, up to 64 MB)

### 10.1 Capabilities
- Link caps bit 12, `CAP_LINK_ATT1 = 0x00001000`: "this node takes
  `RVNATT/1` offers and RAX1 frames inside ordinary link limits" (phase 1).
  Bit 13, `CAP_LINK_RAX1 = 0x00002000`: "this node stretches its limits for a
  transfer link" (phase 2). Both ride the signed RIH1 hello and RLX1
  `LINK_CAPS` in the dialer's Noise message 3, like bits 8 to 11; old nodes
  ignore them.
- raven-node remembers, per verified friend, the last time it saw bits 12
  and 13 on an authenticated link. Senders and apps read that record; the
  release capability floor stays as it is. A friend whose node fails a RAX1
  exchange loses its record until it announces the bit again.
- A friend not reached since it updated has no record yet. The app says so
  in plain words and sends once the record exists.

### 10.2 Frames
RAX1 frames are raw Noise transport frames on the authenticated link, after
RLB1 and RRH1, sorted by their magic like RUP1's; never inside RVN1 and never
through the IPC. Header: `"RAX1" || 0x01 || op || req_id[4]`. Every frame
≤ 65,511 B (PAD1's inner limit).

Unlike RUP1, whose listener sends its HAVE first (`rn/lan_direct.rs:1494-1498`),
a RAX1 listener never speaks first: the dialer sends and the listener only
answers.

| Op | Sent by | Body |
|---|---|---|
| `0x01` HAVE | the dialer; answered by LACK | up to 8 entries: handle[16], chunk count u16 |
| `0x02` WANT | the dialer; answered by CHUNKs | handle[16], first chunk u16, count u8 (1 to 16) |
| `0x03` DONE | the dialer, no answer | handle[16]: "I have all of it" |
| `0x04` PUSH | the dialer, no answer | one chunk, laid out as in `0x81` |
| `0x81` CHUNK | answer to WANT, not final | handle[16], index u16, length u32 (1 to 61,440), chunk, path length u8 (0 to 11), path of 32-byte hashes (≤ 61,825 B in all) |
| `0x82` CHUNKS_END | answer to WANT, final | code u8, sent u8 |
| `0x83` LACK | answer to HAVE, final | per entry: handle[16], status u8 (0 wants the chunks its bits name, 1 complete, 2 later, 3 declined), then one bit for each chunk it still wants (≤ 133 B) |
| `0xFF` ERROR | answer, final | UNSUPPORTED, NOT_FOUND, BUSY, RATE_LIMITED, POLICY_DENIED, MALFORMED, GONE |

Decode rules follow RUP1's: a fixed order, every length checked before a byte
is copied, an accepted frame re-encodes byte for byte.

### 10.3 Push and pull
- **Push** (the sender's node dials). Right after the offer it pushes the
  chunks of a photo or a voice note; on a later link it says HAVE first and
  pushes only what the LACK answer asks for, which follows the friend's
  download rules (§16). A file waits for a pull or for a LACK that asks for
  it. This is the usual case: a phone or a desktop sending while it is open.
- **Pull** (the receiver's node dials). The receiver dials the holder and
  says WANT. This is how a file downloads on a tap, how an iPhone gets a big
  photo when it opens, and how any cut resumes.
- RUP1 only pulls. Here either node may start the link: a phone that sends
  must push, and a phone that receives must pull. Each node serves only what
  it holds and offered to that friend, or got in a group the friend is in
  (§18.2).
- When the receiver has everything it says DONE on its next dial to the
  sender, or answers the sender's next HAVE with a LACK of status complete,
  and the sender's bubble turns Delivered. Status later or declined leaves
  it at Sent.

### 10.4 The window
The receiver keeps W chunks asked for and not yet in: W = 4 at the start
(246 KB, about one Tor stream window of 500 cells), up to 8 on Internet
direct and 16 on LAN, set from the rate it sees. On today's Arti, more than
one stream window in flight only fills buffers and makes a cut cost more.

### 10.5 What raven-node must change for a transfer link
Today's links cannot be stretched for one transfer:
- The life of an incoming link is a timeout fixed when it is accepted,
  before any hello (`rn/lib.rs:1673-1676`, `rn/onion/mod.rs:1608`,
  `rn/p2p.rs:3289`), and the read loops check it again
  (`rn/lan_direct.rs:1502, 1519`, `rn/internet_direct.rs:829, 849`). It
  becomes a deadline the link can extend once a verified friend whose hello
  showed bit 13 sends its first RAX1 frame.
- The 64-frame budget becomes extendable the same way.
- A dialer collects replies in memory and stops at 64
  (`rn/lib.rs:738-741, 784`). For RAX1 the replies go straight to the blob
  store as they arrive.

The limits that replace them, for a transfer link only:

| Limit | Ordinary link | Transfer link |
|---|---|---|
| Frames | 64 | 4,096 |
| Life | 120 to 300 s | 20 min, ended by 30 s with no frame either way |
| Bytes | | what was offered to this friend, plus 1 MiB |
| At once | ≤ 4 per Tor circuit, 16 in all | 2 per friend and 4 in all, counted inside the same totals |
| Serving | | 256 MiB a day per friend; 2 requests at once per link |

### 10.6 Which carrier, and moving mid transfer
- A transfer link takes the outbox route plan: LAN, Internet direct, hole
  punching, then Tor. Bluetooth (40 s dials) and friend relays (2 MiB per
  circuit, `sw/host.rs:206`) never carry transfer links; they carry phase 1
  chunks only.
- During a Tor transfer the receiver tries the direct routes every 60 s; when
  one answers, the remaining chunks move there and the Tor link closes. A
  chunk is the same wherever it comes from.
- A file over 4 MB on Tor uses two transfer links, each asking for chunks the
  other has not asked for. Each stream has its own 500-cell window and the
  circuit allows 1,000 cells, so two links can roughly double the rate.

### 10.7 Resume
- Per attachment the receiver keeps a pre-sized file, a bitmap (one bit per
  chunk) and a "verified" mark, written in RUP1's order
  (`rn/update_exchange.rs:2070-2080`).
- A cut, a Raven restart, a carrier change or an iPhone pause loses at most
  the chunks in flight.

## 11. Speed over Tor

### 11.1 Where the time goes
- **The offer** costs what a text message costs today: the probe (2 round
  trips) and the message link (3 round trips) on a warm circuit, more on a
  cold one. The preview is in the offer, so the friend sees something then.
- **The chunks** then move at the circuit's rate. On today's Arti one stream
  carries at most 249 KB per round trip: about 250 KB/s at a 1 s round trip,
  500 KB/s at 0.5 s. Busy relays often allow less.

### 11.2 Estimates (phase 0 replaces them with measurements)

| Item | On the wire | Way | After the offer, over Tor | Same LAN |
|---|---|---|---|---|
| Voice message, 1 min | about 185 KB | live link | 1 to 3 s | under 1 s |
| Photo, standard | about 305 KB | live link | 1 to 4 s | under 1 s |
| Photo or file, 1 MiB | about 1.05 MB | live link | 3 to 10 s | about 1 s |
| File, 10 MB | about 10.3 MB | 2 transfer links | 20 to 60 s | 1 to 3 s |
| File, 64 MB | about 65.4 MB | 2 transfer links | 2 to 7 min | 5 to 20 s |

### 11.3 What makes it fast
1. Small items follow their offer on the link that is already open: no extra
   connection.
2. Raw bytes on every path: no base64.
3. The preview is in the offer: the friend sees the photo's shape at message
   speed.
4. Photos are shrunk and voice is Opus before anything travels.
5. The window matches Tor's flow control (§10.4).
6. Two links for big files (§10.6).
7. LAN and direct paths win, even mid transfer (§10.6).
8. Resume from the last checked chunk (§10.7).
9. Chat never waits behind a file: chunks are not messages, and chat frames
   go first on any link.

### 11.4 Arti's congestion control (owner decision 2026-11-05: measure first)
Arti 0.47 can negotiate Tor's congestion control (proposal 324) on onion
circuits, but only with its experimental features `hsc-negotiate-extensions`
and `hss-negotiate-extensions`, which Raven does not turn on. With it a
stream is no longer held to 500 cells per round trip; C Tor clients have it,
which is part of why they reach about 475 KB/s (§2). Both friends need it.
Because it is experimental in Arti, the proposal is to measure it in the lab
in phase 0 and decide with the numbers.

### 11.5 Later
Several circuits for one file (phase 3): faster for big files, more load on
Tor, more circuits to watch. Not before measurement.

## 12. Friends who are away, and mail friends (phase 1, chats only)

- **The offer** is a message, so a friend who is away gets it from a mail
  friend like text, and sees the preview.
- **The chunks** of an item up to 1 MiB go to the same mail friends as chunk
  objects, through three new ops under RFC1's op registry: no new version
  byte, and an unknown op already gets UNSUPPORTED
  (`proto/RAVEN_FRIEND_CUSTODY_V1.md:108-114`).

| Op | Body | Answer |
|---|---|---|
| `0x09` DEPOSIT_CHUNK | recipient[32] (the friend), custody id[16] (§7.1), expiry u64, chunk length u32, the sealed chunk, path length u8, path | DEPOSIT_RESULT `0x81`: a code and the SHA-256 of the record |
| `0x0A` FETCH_CHUNKS | 1 to 32 custody ids | CHUNK_ITEM `0x89` for each, then FETCH_END `0x83` |
| `0x0B` RELEASE_CHUNKS | 1 to 32 custody ids | RELEASE_RESULT `0x84` |

- **Who may deposit and fetch.** The rules of DEPOSIT and FETCH: a keeper
  takes a chunk object only for a recipient who is its own pinned contact
  (`core/friend_custody.rs:3716-3720`), counts it per depositor and recipient
  (`:811-813`), and serves and releases it only to that recipient, signed in
  on the link (`:1577-1590`). A chunk object is at most about 61,870 B,
  inside one RFC1 frame.
- **Older mail friends** answer UNSUPPORTED; the sender skips them for chunks
  for a day. The offer still goes to them.
- **Caps.** A deposit dial carries at most 8 chunk objects (the 512 KiB of
  `core/custody_client.rs:54-57`); a fetch page of 128 KiB holds 2
  (`core/friend_custody.rs:148`). Chunk pages have their own budget per
  fetch trigger: 9 on a direct path (one 1 MiB item), 4 when the path is
  relayed or not known yet, custody's own relayed limit
  (`core/custody_client.rs:58-63`, `rn/custody.rs:1083-1094`). On the keeper,
  chunk objects count against the depositor's 16 MiB and 512 rows, the
  node's 64 MiB and 4,096 rows and the 2 MiB a minute, with their own cap of
  64 per pair (about 4 MB, three items of 1 MiB), so they never push text
  out of the 128 objects a pair may hold.
- **One 1 MiB item** is the offer plus 18 chunk objects: 3 deposit dials per
  mail friend. The offer comes in one fetch trigger, and its 9 chunk pages in
  the next on a direct path, or in 3 more on a relayed one. An iPhone in the
  background checks mail on direct paths only, so there it takes two checks.
  A friend has at most 2 mail friends, so this can double the sender's
  upload.
- **Lifetime.** Chunk objects live as long as any object at a mail friend:
  24 h + 5 min at most (`core/carrier_admission.rs:54`). After that the rest
  waits on the sender until a live link; the offer itself can wait up to 7
  days on the long horizon.
- **The receiver** fetches its objects as today. For an offer whose chunks
  are at a mail friend, it derives the custody ids from K, asks
  FETCH_CHUNKS, checks each chunk against R, writes it, and sends
  RELEASE_CHUNKS.
- **Bigger items.** For an item over 1 MiB the offer still goes to mail
  friends, so the friend sees the preview and "Downloads when {name} is
  online"; the chunks wait for a live link.
- **What a mail friend learns:** what it learns for text (who to whom, when,
  how big), plus a set of chunk objects of one size with unrelated ids,
  which by their timing look like an attachment. Never the kind, the name,
  the caption, the preview or the content, and not from the ids which chunks
  belong together.
- **Groups:** no chunk objects at mail friends in v1, since every member
  would need its own copies (§13).
- **iPhone:** the background mail check runs without Tor, so in the
  background offers and chunks come only from a mail friend on the same
  network or on Internet direct (§17).

## 13. Groups

- **The offer is the message.** The body of an ordinary `RVNGRP/1 msg` is the
  8,192-byte offer text: exactly the group body limit (`core/group.rs:97`),
  well inside the 49,152-byte frame. The author signs SHA-256 of the body as
  today (`core/group.rs:280-292`), so K, R and every field are signed;
  forwarders pass the frame as it is; the group wire form (`MsgWire`, which
  refuses unknown fields) does not change, and no frozen byte does.
- **A member's node** sees after the commit that the body is an offer,
  writes the attachment row and shows the bubble.
- **The chunks** come live through RAX1 from the author, or from any member
  who is the receiver's friend and holds them, the forwarder first. Every
  chunk is checked against the signed R, so a member passing chunks on
  cannot change them.
- **Older members.** The author knows the build only of members who are its
  friends, and a forwarder cannot change the signed body for anyone. So a
  member on a build with phase 1a sees the placeholder line, and a member on
  a build from before phase 1a would see the offer as text. That is why
  phase 1b waits until phase 1a has spread (§22).
- **Limits.** 1 MiB per group attachment in phase 1; 16 MB in phase 2, since
  each member is its own upload.
- **The group store.** It keeps each message's body and signature as signed
  (`core/group/store.rs:130`), within 8 MiB for all groups
  (`core/group/store.rs:23-24, 320-337`). For an offer it keeps the body
  without its pad and puts the pad back, byte for byte, to check the
  signature, so an offer costs the store what its fields cost (under 3 KB
  before its caption), not 8,192 bytes.
- **Where K stays.** So in groups K also stays in `groups.json`, sealed with
  the profile, until retention or deletion removes the message. The author's
  per-member copies are queued history rows that hold the whole frame, and
  they are deleted once final (`core/group/park.rs:355-367`). Left for the
  spec: whether deleting a group attachment may rewrite the stored body
  (every reader of `StoredMsg.sig` must be checked).

## 14. Storage, retention and deletion

- **`attachments.sqlite`.** Bundled SQLite like every store (SQLCipher is
  refused in release, `node/crates/raven-core/build.rs:19-21`), handled like
  `friend_custody.sqlite`: registered in `at_rest::FILES` as a keyed store
  (`core/at_rest/registry.rs:447`; an unregistered file is refused,
  `core/at_rest.rs:1882-1885`), re-sealed by the key rotation pass
  (`core/privacy.rs:2092-2128`), rows sealed with `at_rest::seal_row`
  (`core/friend_custody.rs:1194`), `secure_delete` on
  (`core/paths.rs:554-562`), and a WAL checkpoint after deletes. As in every
  store, rows are sealed in a sealed profile (`core/privacy.rs:434-454`) and
  plain after `raven privacy unseal`. One row per attachment: handle, message
  id, friend or group, direction, kind, key K, root R, the SHA-256 of the
  offer, sizes, MIME type, name, caption, preview, state, chunks done,
  sources, custody ids still out, and times. Progress changes this file,
  never the history file.
- **Blob folder** `attachments/<handle>/`: `blob` (the sealed chunks as they
  travel, pre-sized), `have` (the bitmap), `verified`. Folder names are
  handles, not roots. The blob is ciphertext and needs no second
  encryption; the folder is registered in `at_rest::FILES` too, so the
  privacy tools know it.
- **History rows.** No new field, so the history format does not change.
  On both sides the body is the `ref` form from the first write, and the
  row's `preview` is the chat list text: "Photo", "Voice message 0:42", or
  the file name (§8.2).
- **Where K lives.** In the sealed offer while it travels or waits at a mail
  friend (24 h + 5 min at most there); in the sender's stage entry until the
  ACK; in the receiver's sealed inbox row until it is archived in the `ref`
  form; in the attachment row; in groups, also in the group store and in
  the author's copy rows until they are final (§13).
- **Retention** (7, 30 or 90 days, or always): an attachment goes with its
  message. **Clear history** and **Delete chat** remove blobs and rows.
  Deleting a message of yours removes its blob at once.
- **Deleting.** The row goes with `secure_delete` and a checkpoint, and the
  blob file with it. Without K, any blob bytes a flash disk keeps cannot be
  read; old flash blocks hold only sealed rows and ciphertext.
- **Quotas.** 2 GiB in all and 1 GiB per friend by default. When full, the
  oldest downloaded media of chats that are not pinned goes first; its offer
  and preview stay, with "Download again" while the sender still has it.
- **iPhone.** Inside the profile folder, already excluded from backups, with
  the same default file protection as the rest of the profile.

## 15. The app API

New ops: rows in `desktop/api/API.md`, arms in the `cl/engine.rs` dispatch
table, rows in `raven-client/STATUS.md`. They answer `NOT_AVAILABLE_YET`
while the gate is shut.

| Op | Args | Result |
|---|---|---|
| `attachments.stage` | `{name?}` | `{path}`: a new file in the profile's staging folder for the app to write |
| `attachments.send` | `{address or group, path, kind, mime, name?, caption?, preview?, width?, height?, duration_ms?, levels?}` | `{message, attachment}` at once; the node seals and sends |
| `attachments.get` | `{id}` | `{attachment}`: state, bytes done and in all, the way, the preview |
| `attachments.download` | `{id}` | starts or resumes a pull |
| `attachments.cancel` | `{id}` | stops a send or a download |
| `attachments.read` | `{id, offset, length ≤ 512 KiB}` | `{bytes_b64}`: plaintext of a photo or a voice note, decrypted in memory by the engine itself |
| `attachments.export` | `{id, to_path}` | writes the plaintext where the user chose |
| `attachments.can_send` | `{address or group}` | `{photos, files, max_bytes, why?}` from bits 12 and 13 |
| `settings.attachments` | `{auto_photos, auto_voice, auto_files_max}` | |

- **Events.** A new `attachment` event with id, message id, state and
  progress, at most 4 a second per attachment, so the 512-event queue holds.
- **Errors.** `ATTACHMENT_TOO_BIG`, `FRIEND_NEEDS_NEWER_RAVEN`,
  `STORAGE_FULL`, `ATTACHMENT_GONE`, `ATTACHMENT_BAD` (a check failed).
- **No big bytes in JSON.** An API call is at most 1 MiB. An app sends by
  path, reads photos and voice notes in pieces of at most 512 KiB, and gets a
  file out only through `export`. `attachments.read` is served by the engine
  itself, which reads the attachment row and the blob as it already reads
  history (`cl/engine.rs:646`): a piece never crosses raven-node's IPC, whose
  answers are at most 256 KiB (`core/ipc.rs:9`).
- **iPhone.** The same ops; the engine and the node share the app container,
  so the path is a file inside it.

## 16. The apps

The same behaviour on all four, each in its system's style.

- **Composer.** An attach button (Photo, Take photo on iPhone, File) and a
  microphone: hold to record, slide to cancel, and on iPhone tap to lock.
  Drag and drop and paste on macOS, Windows and Linux.
- **Photo bubble.** The blurred preview at once, a ring while it comes, then
  the photo; tap for full screen; Save.
- **Voice bubble.** Play and pause, the wave with the played part filled, the
  length, 1x, 1.5x and 2x.
- **File bubble.** Icon, name and size; Download, then Open and Save.
- **Download rules** (Settings). Photos and voice notes download by
  themselves; files on a tap; an option to download files up to a size by
  themselves on a home network.
- **Saving.** macOS sets the quarantine mark on a saved file and Windows the
  Mark of the Web, so the system checks a file before it runs it. Raven never
  opens a file by itself.
- **Words.** Plain, in the apps' voice, with no hyphens, dashes or
  apostrophes: "Photo", "Voice message", "Waiting for {name} to come online",
  "Downloads when {name} is online", "{name} needs a newer Raven for photos",
  and on builds from phase 1a "{name} sent a photo. Update Raven to see it."
- **The waiting card.** An attachment that waits shows the same perched raven
  as a message that waits.
- **Access.** Screen readers say "Photo from {name}", "Voice message, 42
  seconds", or the file name and size; controls are at least 44 points; with
  Reduce Motion the ring does not spin.

## 17. iPhone

- **Sending** happens while Raven is open. When it leaves the screen, an
  unfinished push counts as an activity, so the short finish (up to 15 s)
  covers it (raven-ios `Raven/State/AppModel+Actions.swift:228-268`). The
  hand-off then gives undelivered offers to a mail friend
  (`messages.handoff`, 5 s, `:274`), but not chunks: chunks still unsent
  wait for the next open, and the bubble says so. The offer waits in the
  outbox, the chunks in the blob store, and links resume from the bitmap.
- **Receiving** happens while Raven is open. In the background the mail check
  (no Tor) can bring offers and chunks from a mail friend on LAN or Internet
  direct, and the local notification "New message in Raven" shows as today.
- **Later, if wanted**: a `BGProcessingTask` (the Info.plist already declares
  the mode) could finish big transfers while the phone charges. Not in v1.
- **Permissions.** Microphone (a new usage text); camera (exists, for the QR
  card); "add to Photos" only when the user saves. PHPicker needs no photo
  library permission.

## 18. Privacy and security

### 18.1 Who learns what

| Who | Learns | Never learns |
|---|---|---|
| The friend or group member | everything in the attachment | |
| A mail friend | sender and receiver, times, offers of the one fixed size, chunk objects of one size with unrelated ids | kind, name, caption, preview, content; from the ids, which chunks belong together |
| A group member passing chunks on | it is a member, so everything, like any member | |
| Tor relays | as for text: a guard sees the volume and timing of one side | who talks to whom, anything inside |
| The local network | volume and timing of a LAN transfer (exact frame sizes while PAD1 is off) | anything inside |
| An iPhone backup | nothing: the profile is excluded | |

### 18.2 Threats and answers
- **A friend fetches what it was not sent.** A node serves a handle only to
  a friend it offered it to, or to a member of the group it came in; the
  handle comes from the key, which only an offer carries. A mail friend
  serves chunk objects only to the recipient they were deposited for.
- **A forged or changed chunk.** Every chunk is checked against R with its
  audit path before it is written, whoever sent it; R comes sealed (chats) or
  signed and sealed (groups) from the author.
- **A huge or endless transfer.** Caps on size, count, links, life and a
  daily serving budget (§10.5, §19). Files download only on a tap by
  default.
- **A poisoned image or sound.** Decoded only by the system's own decoders,
  in the app, never in the node. Only JPEG and Ogg Opus show inline; anything
  else is a File and opens only by the user's choice.
- **A file that pretends to be another type.** Names are cleaned (§18.3);
  saved files carry the system's quarantine mark or Mark of the Web.
- **Disk theft.** In a sealed profile rows are sealed and blobs are
  ciphertext; K lives only in sealed rows and goes with secure delete (§14).
  After `raven privacy unseal`, rows are plain like every other store's.

### 18.3 Names and text
File names lose path separators, control characters and direction override
characters (so a name with U+202E cannot pretend that an `.exe` is a `.png`),
and are cut at 255 bytes. Captions follow the chat text rules, at most 2,000
bytes.

### 18.4 What stays visible
Padmé hides exact sizes (§7.2), and every offer has the same size. While PAD1
is off, frames show their exact length on the wire. A transfer is a stream of
nearly equal frames, so someone watching a LAN or a Tor guard can tell a
transfer from chat by its volume. Raven sends no cover traffic, by owner
decision.

## 19. Limits and abuse controls (proposed)

| Limit | Value |
|---|---|
| One attachment, chat | 64 MB (at most 1,059 chunks); 1 MiB in phase 1 |
| One attachment, group | 16 MB from phase 2; 1 MiB in phase 1 |
| Mail friends | chats only; items up to 1 MiB; 64 chunk objects per pair; 8 per deposit dial; chunk pages 9 a trigger direct, 4 relayed |
| Offer | exactly 8,192 B; caption ≤ 2,000 B; preview ≤ 1,536 B; name ≤ 255 B; MIME type ≤ 127 B |
| Voice note | ≤ 5 min in phase 1, ≤ 15 min from phase 2 |
| Live chunks (phase 1) | ≤ 40 per link, under 1.9 MiB in all on a friend relay; ≤ 16 per pull dial; ≤ 2 per Bluetooth dial; files never pushed unasked |
| Transfers at once | 2 per friend, 4 in all |
| Served per friend | 256 MiB a day |
| Storage | 2 GiB in all, 1 GiB per friend (§14) |
| Downloads by themselves | photos and voice notes up to 1 MiB; files on a tap |

## 20. What the user sees

Sender: Preparing, Sending 40 %, Sent (the offer arrived; a file the friend
has not downloaded yet stays here), Delivered (the friend's node has every
chunk), Waiting for {name} (with the waiting card), Not sent (with Try
again).

Receiver: the preview with Downloading 40 %, then the photo or the player; a
file shows Download, then Open and Save; "No longer available" when the
author deleted it first. A friend on an older build sees "{name} sent a
photo. Update Raven to see it."

Nothing goes back when a friend opens or plays an attachment: Raven sends no
read receipts.

## 21. Tests and measurements

- **Phase 0, measure before building.** Two lab profiles over real Tor: offer
  time; transfer rate for 100 KB, 1 MB, 5 MB and 64 MB with one and two
  links; with and without Arti's congestion control (lab only); LAN; the mail
  friend path. The numbers replace §11.2.
- **raven-core.** Blob round trip, Padmé, the tree against RRB1's vectors,
  offer padding and field limits, a `ref` form that never holds K, the
  `RVNATT/1` and `RAX1` codecs with strict decode rules, the RFC1 chunk ops,
  allocation tests.
- **Vectors and Python reference** in `shared-vectors/rvn1/attachment/` and
  `protocol/reference/raven_protocol/attachment.py`; fuzz targets
  `rvnatt_frame`, `rax1_frame` and `rfc1_chunk_ops`.
- **raven-node.** Push on the offer's link; pull in dials of 16; Bluetooth
  dials under 40 s; resume after a cut; moving from Tor to LAN mid transfer;
  two links; the mail friend path, with an older mail friend that answers
  UNSUPPORTED; group fan out, and a member getting chunks from another
  member; quotas; a friend asking for a handle it was not offered gets
  NOT_FOUND; a forged chunk from a member or a mail friend is refused; no
  history row or preview ever holds K, on every write path; a re-sent offer
  is not an id conflict; a relayed push stays under 2 MiB; LACK's statuses
  keep a file at Sent; `attachments.sqlite` goes through the key rotation
  pass; an iPhone leaving the screen mid push; a phase 1a build shows the
  placeholder and never defers.
- **Carrier matrix and fault matrix** rows for each carrier, and a three
  machine field run.
- **Apps.** UI tests (send a photo, record and play a voice message, save a
  file), stills in light and dark, screen reader labels, an iPhone leaving
  the screen mid send.

## 22. Gates, specs and phases

The process is the one friend custody went through: the spec and the custody
amendment, a row in `proto/PROTOCOL_VERSIONS.md` and the freeze hashes, suite
ids `rvnatt/1` and `rax1/1`, feature ids `feature/attachments`,
`feature/attachment-custody` and `feature/attachment-exchange` in
`core/suite_registry.rs`, evidence rows, then the owner's own flip of each
gate.

| Phase | What | Gate |
|---|---|---|
| 0 | Measure Tor and LAN (§21). No product change. | none |
| 1a | Every build learns `RVNATT/`: offers are kept and shown as a placeholder, never as text, never deferred. Ships alone, first. | none: it only stops a frame from showing as text |
| 1b | Offers and live chunks up to 1 MiB: photos and voice notes, chats and groups, bit 12. macOS and iPhone first, Windows and Linux next. Waits until 1a has spread. | `ATTACHMENTS_PRODUCTION_ENABLED` |
| 1c | Mail friends hold chunks: RFC1 ops 0x09 to 0x0B, chats only, up to 1 MiB. | `ATTACHMENT_CUSTODY_PRODUCTION_ENABLED` |
| 2 | Transfer links: the link changes of §10.5; files and big photos up to 64 MB (16 MB in groups); two links; moving to LAN mid transfer; bit 13. | `ATTACHMENT_EXCHANGE_PRODUCTION_ENABLED` |
| 3 | Only if the numbers say so: Arti's congestion control, several circuits, `BGProcessingTask` on iPhone. | separate decisions |

## 23. Decisions

The owner confirmed all ten on 2026-11-05, each as recommended: Opus in Ogg
for voice notes (with its two new packages, one small library on Windows
and GStreamer on Linux, approved with it), Arti's congestion control
measured in the lab first, and phase 1a first and alone.

1. **Limits.** 64 MB per attachment, 16 MB in groups, 1 MiB through mail
   friends (chats only), and captions up to 2,000 bytes so that every offer
   fits one size. Recommended.
2. **Voice format.** Opus in Ogg (recommended: about 180 KB a minute; needs
   one small library on Windows and GStreamer on Linux, both new packages),
   or AAC (built into Apple and Windows, about a third bigger, still
   GStreamer on Linux).
3. **Photo size.** 1,600 px by default; "original" sends a File.
   Recommended.
4. **Downloads by themselves.** Photos and voice notes yes, files on a tap.
   Recommended.
5. **Mail friends hold small attachments** (up to 1 MiB, chats only): three
   new custody ops, and up to twice the upload for a friend who is away.
   Recommended.
6. **Arti's congestion control.** Measure in the lab only, decide with the
   numbers. Recommended.
7. **Two Tor links per big file.** Yes. Several circuits: later.
8. **Storage.** 2 GiB in all; the oldest media of chats that are not pinned
   goes first.
9. **Order of the apps.** macOS and iPhone first, then Windows and Linux.
10. **Phase 1a first and alone**, and phase 1b only once it has spread.
    Recommended.

## 24. Not in v1

Video as video (it goes as a file), albums (several photos are several
messages), editing, stickers and GIF search, view once, delete for everyone,
the same attachments on the user's other devices, chunks of group
attachments at mail friends, Android, and link previews (a link preview
fetches a web page, which leaks).

## 25. What the reviews changed

### 25.1 First check: 17 findings in the first draft

| # | Found in the first draft | Now |
|---|---|---|
| 1 | Mail friends could hold only 16 pieces of an item (the per friend window), and more would run into the 256 message keys a receiver keeps | Chunks are not messages; mail friends hold chunk objects through new custody ops (§12) |
| 2 | Every piece would have written a queued history row and a stage entry with its exact body; one group item needed 240 stage entries | The only message is the offer (§8.2) |
| 3 | A group message cannot carry a new `att` field: unknown fields are refused, the signature covers only the body, an empty body is refused, and group messages live in `groups.json` | The offer is the group message body, signed as it is (§13) |
| 4 | A listener cannot stretch its limits for one link: the life is fixed at accept, a LAN listener sends no caps, and a dialer stops at 64 replies | Phase 1 stays inside today's limits; §10.5 lists the changes phase 2 needs |
| 5 | Pieces could not be checked one by one: a chunk needs its audit path | Every chunk carries its audit path (§7.3) |
| 6 | 16 pieces on Bluetooth take 22 to 133 s, past the 40 s dial | At most 2 chunks per Bluetooth dial (§9) |
| 7 | An offer is not handled in one transaction, and five places need a branch | §8.3 follows the real order and names them |
| 8 | K also stayed in history, the stage and the inbox, and the offer's length showed its kind | The `ref` form on every history write; one offer size (§8, §14) |
| 9 | `attachments.sqlite` cannot be SQLCipher, and the key rotation does not cover it | Sealed rows, secure delete, and registered for key rotation like `friend_custody.sqlite` (§14) |
| 10 | Two code locations were wrong | Fixed (§2) |
| 11 | C1 control characters pass the text check | Fixed (§2) |
| 12 | Padmé growth was given as 0.7 to 2.4 % | 0 to 3.1 % (§7.2) |
| 13 | 64 MiB padded does not fit RRB1's limit once the tags are added | Originals up to 64,000,000 B, at most 1,059 chunks (§7.3) |
| 14 | Mail friend counts were wrong (36 objects with the offer; 12 per dial; 3 per fetch page) | Recomputed for chunk objects (§12) |
| 15 | An offer could pass 8,192 B in the worst case | Field limits and one fixed size (§8.1) |
| 16 | 15 minute voice notes did not fit phase 1's 1 MiB | 5 minutes in phase 1 (§6.2) |
| 17 | Friend relays were both excluded and included | Relays and Bluetooth carry phase 1 chunks only (§10.6) |

### 25.2 Second check: 13 findings in the second draft

| # | Found in the second draft | Now |
|---|---|---|
| 1 | DEPOSIT_CHUNK had no recipient, so the keeper's contact check, per pair caps and fetch rule could not run | `recipient[32]` first, the rules of DEPOSIT and FETCH, and a digest in the result (§12) |
| 2 | K stayed in history: several write paths put the staged offer back, and the preview kept the first 120 characters | The `ref` form and the preview are set in `persist_lan_chat_history` on every write; K and R come last (§8.1, §8.2) |
| 3 | A stored `ref` would turn every re-sent offer into an id conflict | Copies are compared with the offer's SHA-256 (§8.3) |
| 4 | 40 pushed chunks pass a friend relay's 2 MiB per circuit | Under 1.9 MiB in all on a relay (§9) |
| 5 | The fetch count ignored the pages one trigger may take | Chunk pages have their own budget; triggers counted (§12) |
| 6 | An iPhone's short finish and hand-off did not cover chunks | A push counts as an activity; unsent chunks wait for the next open (§17) |
| 7 | 8,192-byte offers would fill the 8 MiB group store | The store drops the pad and puts it back to check the signature (§13) |
| 8 | Key rotation still did not cover `attachments.sqlite`, and rows are plain after unseal | Registered and re-sealed; §14 and §18.2 say when rows are sealed |
| 9 | An empty LACK meant both complete and declined, and files were pushed unasked | LACK has a status; files wait for a tap (§9, §10.2, §10.3) |
| 10 | RUP1's listener does speak first | Corrected (§10.2) |
| 11 | The group body limit is at `core/group.rs:97`, not `:96` | Fixed (§8.1, §13) |
| 12 | A 512 KiB read cannot cross the node's 256 KiB IPC | The engine serves `attachments.read` itself (§15) |
| 13 | A 300 KB photo is 5 chunks, not 6; the Tor rate is about 475 KB/s, not 450 | Fixed (§2, §9, §11) |
