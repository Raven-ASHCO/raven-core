# Profile pictures between verified friends (v1)

| | |
|---|---|
| **Status** | Design, first draft, built on the owner's five decisions of 2026-11-06 (§24.1). Version 1, one picture, is built in the core and the terminal's lab commands behind its gate (§28, 2026-11-16); the rest is design. Not normative: the wire text belongs in `protocol/RAVEN_ATTACHMENT_V1.md`, which is not written yet. It changes no frozen byte. |
| **Review** | On 2026-11-06: checked against the code while writing (14 findings), then a skeptical read of the whole draft and of the attachments doc (16 more). §27 lists each finding and its fix. |
| **Requested** | By the owner, 2026-11-06: profile pictures that only verified friends see, a face for each circle, and a picture taken when friends meet. Design only. |
| **Gate (new)** | `PROFILE_PICTURES_PRODUCTION_ENABLED = false`. It asserts `ATTACHMENTS_PRODUCTION_ENABLED` at compile time. Lab switch `RAVEN_LAB_PROFILE_PICTURES=1` with `RAVEN_LAB_TEST_A=1`, debug builds only. |
| **Wire (to write)** | A section of `protocol/RAVEN_ATTACHMENT_V1.md`: the `profile` kind of `RVNATT/1 offer`, its empty form, the `seq` and `held` fields, and the picture as one chunk. No new frame, link frame, caps bit or custody op. |
| **Builds on** | `docs/design/2026-11-attachments.md`, which the owner approved on 2026-11-05: the offer, the blob, RAX1, mail friends, `attachments.sqlite` and phases 1a to 1c. The outbox, the group copy rules and the chat controls, as they are. |
| **Owner constraints** | No Raven server. Only verified friends. Never in a card, on the Lock Screen, in a notice or in an iPhone backup. No new crate or package. Plain words in the apps. |
| **Tree read** | raven-core `security/review-2026-11` 18f98ef; raven-ios `ui/ios-integration` c09d44c; raven-macos `ui/macos-integration` 79f5a47. |
| **Date** | 2026-11-06 |

Path shorthand, as in the attachments doc: `core/` = `node/crates/raven-core/src/`,
`rn/` = `node/crates/raven-node/src/`, `cl/` = `node/crates/raven-client/src/`,
`ash/` = `node/crates/ash/src/`, `proto/` = `protocol/`. "Attachments §n" is a
section of `docs/design/2026-11-attachments.md`.

Lines are from 18f98ef. The attachments doc cites the older 9187bbf, so some
of its lines have moved (for example, the group body limit is now
`core/group.rs:115`).

Sizes: 1 KB is 1,000 bytes; 1 MiB is 1,048,576 bytes.

---

## 0. Decisions on one page

1. **Only verified friends.** Raven sends my picture only to friends I have
   verified. It shows a friend's picture only after I verified them.
   Everyone else gets the seal: today's avatar, a calm circle with the first
   letter in the friend's colour.
2. **A face for each circle.** Up to 3 faces, for example Family, Work and
   Everyone else. Each verified friend is given exactly one face, and gets
   only that one (or No picture, §25 question 1). The other faces never
   leave the device. Face names never leave it either.
3. **One small picture.** Square, 384 px, baseline JPEG, no metadata, at
   most 60,000 bytes. It is padded so it is always exactly one chunk of
   61,440 bytes.
4. **The attachments machinery, as it is.** A picture is an `RVNATT/1 offer`
   of kind `profile`. It is 8,192 bytes like every offer, with a 32 px
   preview inside. Its one chunk follows on the link (RAX1), or through mail
   friends from phase 1c. Only three things are new on the wire: the fields
   `seq` and `held`, and an empty form that means No picture. No new frame,
   caps bit, custody op or crate.
5. **Chats only.** A picture is never a group message, because each friend
   gets their own face. Beside a group message, a verified friend shows the
   face they gave me in our own chat. Anyone else shows the seal, and a
   member who is not my friend also shows "not your friend".
6. **No history.** No bubble, no chat row, no notice. Each friend's newest
   picture replaces the one before it, and the old one goes with secure
   delete.
7. **The sender keeps track, from ACKs.** It sends when a face changes, when
   a friend is moved, and when a friend is verified. It sends again to a
   friend who missed one. `held` tells a friend which of their pictures I
   hold, so a lost one comes back. No link or hello change.
8. **Met in person.** Right after the words match face to face, Raven offers
   to take a picture of the friend. The picture never leaves this device, and
   it wins over their own picture here. Both phones send their faces at once,
   over LAN on the same network, else Tor. No Bluetooth.
9. **Decoding safety.** Only verified friends' pictures are ever decoded, and
   only JPEG. The engine checks every marker in Rust before the system
   decoder sees a byte. The decoder is pinned to JPEG. At most 512 px.
10. **Never outside Raven.** Not in a card, a notice, the Lock Screen, a Live
    Activity or an iPhone backup. Sealed at rest like attachment rows. On
    iPhone, faces and met pictures cannot be read while the phone is locked.
11. **Phases.** Attachments phase 1a learns the `profile` kind now and keeps
    it silently. Pictures show with phase 1b, macOS and iPhone first.

---

## 1. What users get

- **Your picture, for the people you trust.** You make up to three faces and
  choose which verified friend sees which. Nobody else ever gets them: not a
  friend you have not verified, not a group, and not a Raven server (there
  is none).
- **Their pictures, once you have verified them.** In the chat list, the
  chat, the friend card and beside their group messages. A blurred preview
  shows first, then the sharp picture.
- **A picture when you meet.** After you compare the words in person, you can
  take a picture of your friend. It stays on your device.
- **Calm.** A changed picture just appears. No message, no badge, no history
  of old pictures.
- **Take it back.** You can give anyone No picture at any time, and their
  copy of your picture goes.

## 2. What exists today (verified in this tree)

| Fact | Value | Where |
|---|---|---|
| The avatar | the first letter in one of 5 colours; index = the sum of the address bytes mod 5, the API's `avatar_index` | `cl/identity.rs:46`, `cl/contacts.rs:352`; raven-ios `Raven/Views/Components/Controls.swift:5`; raven-macos `Sources/RavenUI/Components/Presence.swift:18, 50` |
| Verified | the contact's pin (`pinned`), the API's `verified`; `verify.check_words` pins on a match | `ash/cli.rs:2181`, `cl/contacts.rs:335, 589, 610` |
| Chat controls | block, unblock and unverify are local: the other person is never told | `cl/chats.rs:1-4, 104-134`; `desktop/api/API.md` "Chat controls" |
| Real erase | per contact state may keep only current, unblocked contacts | `core/outbox.rs:2809` (`admitted_contact_keys`) |
| Verified and unblocked | one read of the book and the block list | `core/outbox.rs:2846` (`pinned_unblocked_contacts`) |
| Inbound policy | chat from a session is accepted; an `RVNAPP/` frame needs a verified sender and rate windows (30 per sender and type, 120 per type, a minute); past them, Defer | `core/app_channel.rs:241-259, 311-330, 339-384` |
| Reserved text | the composer guard refuses only `RVNAPP/` and `RVNGRP/`; a group body is checked only by `body_ok` | `core/app_channel.rs:229`, `core/group.rs:722` |
| Group copies | hidden queued rows, dropped from chat views, deleted once final; parked only while the whole stage holds fewer than 128 entries; 32 waiting per friend | `core/chat_history.rs:114, 1050`, `cl/engine.rs:649`, `core/group/park.rs:27-29, 62-130, 394, 441` |
| Outbound stage | 256 entries; offline queueing stops at 192 entries and 3 MiB; 32 queued per friend | `core/chat_history.rs:2812`, `ash/pair_init_lab.rs:68-73` |
| History writes | every row with a body goes through `persist_lan_chat_history`, the queued rows of group copies too | `core/lan_dispatch.rs:232-260, 381-474` |
| Horizon | 7 days | `core/horizon.rs:168` |
| Group authors | `from_friend` is true for you and for an unblocked contact; anyone else is shown with "not your friend" in a neutral colour | `cl/groups.rs:196-201, 343-348`; API.md "Groups", "Authors" |
| The apps' group models | `GroupMessage` has no `from_friend` yet; the iPhone colours an author it cannot find with colour 0, and the Mac colours every author from the address, members who are not friends too | raven-ios `Raven/Engine/Models.swift:521`, `Raven/Views/Chat/ChatView.swift:538-548`; raven-macos `Sources/RavenUI/Engine/Models.swift`, `Sources/RavenUI/Views/GroupViews.swift:197, 205` |
| Group body | 1 to 8,192 B; times at most 2^53 − 1 ms | `core/group.rs:115, 122, 722` |
| One leaf tree | `verify_chunk_path` with count 1 and no path checks that the leaf hash is the root | `core/release_bundle.rs:897-926` |
| Link caps | bits 0 to 4 and 8 to 11 in use; 12 and 13 planned by the attachments doc | `core/internet.rs:62-85` |
| A dial with no frames | the app channel's probe | `rn/app_channel.rs:669-700` |
| Outbox kick | IPC `OutboxKick`; `kick` in raven-node | `core/ipc.rs:127`, `rn/outbox.rs:703` |
| API limits | a request ≤ 1 MiB; an IPC answer ≤ 256 KiB; field names must not hold seed, private_key, secret, plaintext or recovery | `cl/envelope.rs:11`, `core/ipc.rs:9`, `cl/safety.rs:9` |
| Stores | keyed SQLite rules, sealed rows, secure delete, re-sealed on key rotation | `core/at_rest/registry.rs:103, 471-473`, `core/at_rest.rs:1627`, `core/paths.rs:678`, `core/privacy.rs:2092` |
| The old public profile | `RavenProfileRecordV1`, at a DHT key from the Raven ID, with `profile_image_digest` | `core/profile_record.rs`, `proto/RAVEN_PROFILE_RECORD_V1.md` |
| Strangers | a contact request needs an authenticated ATSAM root; it carries a name and aliases, no picture | `core/contact_request.rs:1-30` |
| Two devices | no fan out: a message reaches the one device the carrier reaches | `docs/design/2026-10-per-device-keys.md` §0 |
| iPhone profile | excluded from backups; default file protection (until first unlock), so the background mail check can read it | raven-ios `Raven/Engine/Engines.swift:42-60` |
| iPhone notices | only "New message in Raven" | raven-ios `Raven/App/Background.swift:22`, `Raven/Support/Copy.swift:703` |
| Live Activity | no message text; iOS keeps its data outside Raven while it lives | raven-ios `Shared/RavenActivityAttributes.swift:12-16` |
| App switcher | the picture iOS takes is blurred | raven-ios `Raven/Views/Components/LockCover.swift` |
| Camera text | "Raven uses the camera only to scan the card of a friend you add." | raven-ios `Config/Raven-Info.plist:84-85` |
| Words on a call | phone only; the words step knows when it is on | raven-ios `Raven/Views/AddFriend/WordsStep.swift:24, 43`, `Raven/State/AppModel+Actions.swift:723` |
| Mac | hardened runtime, no camera text, no system notices; the menu bar shows a presence dot | raven-macos `scripts/make-app.sh:292`, `Sources/RavenUI/Views/MenuBar.swift:66` |

## 3. Goals and non-goals

Goals:
- A picture for each friend, chosen by the sender, seen only between
  verified friends.
- End to end, on every way Raven reaches a friend, with no server.
- Nothing new on the wire but one offer kind: the offer, chunk, link frames
  and custody ops are those of the attachments design.
- Bounded: every count, size and rate has a cap. A friend cannot fill a
  disk, a stage or a link with pictures.
- Safe to show: a picture from a verified friend passes a strict check
  before any decoder, and nothing from anyone else is decoded.
- Calm: no history, no notices, no "changed" marks.

Non-goals in v1: a ring drawn from the key, temporary pictures, the same
faces on the user's other devices, pictures of groups, animated pictures,
and any public profile.

### 3.1 Not the old public profile record

raven-core has `RavenProfileRecordV1` (`core/profile_record.rs`,
`proto/RAVEN_PROFILE_RECORD_V1.md`, Discovery V1). It is a signed public
record at the DHT key `H("raven/profile/v1" || raven_id)`, with a display
name, public aliases and a content addressed `profile_image_digest`. Anyone
who knows the Raven ID can fetch it. A content address also lets anyone tell
that two people use the same picture. That is the opposite of this design,
so profile pictures never write or read that record and never fill
`profile_image_digest`. No picture is ever named by its content: every copy
has its own random key, handle and root.

## 4. The design in one picture

```text
 Sender app          Sender raven-node                                 Friend raven-node            Friend app
 ----------          -----------------                                 -----------------            ----------
 crop, 384 px  --->  faces: up to 3, sealed at rest
 JPEG <= 60 KB       face_of: each verified friend -> one face
                     profile pass: for each verified friend whose
                     face changed, a new key K, one sealed chunk
                        |
                        |-- OFFER, kind profile (K, R, seq, held, preview): 8,192 B --> pictures row --> blurred preview
                        |     one sealed chat message, never a group message;            (shown only if
                        |     a hidden queued row, like a group copy                      verified)
                        |
                        |== one RAX1 CHUNK, 61,440 B, one leaf and no path ============> checked against R
                        |     pushed after the ACK, or pulled with WANT                         |
                        |                                                                       '--> engine checks the JPEG
                        '-- friend away, from phase 1c: one chunk object                             markers, then the system
                              at the friend's mail friends ------------------------------>            decoder shows it
```

## 5. What others do

| Messenger | Who sees the picture | How it travels |
|---|---|---|
| Briar | every contact | sent to each contact: a 1,000 px JPEG of at most 32,668 B (briar-api `AvatarManager`, `MediaConstants`) |
| SimpleX | every contact; an incognito profile hides it | a data URI of at most 12,500 characters (about 9 KB) inside the profile message (`x.info`) to each contact |
| Delta Chat | the people you write to | the `Chat-User-Avatar` header, 512 px or 60,000 B, sent again every 14 days |
| Signal | whoever holds your profile key | encrypted with the profile key, stored on the Signal servers |
| Threema, Session | contacts | encrypted, on a media or file server |
| WhatsApp | everyone, by default | on its servers |
| Telegram | a public photo, and a personal photo for chosen contacts; others can browse old photos | on its servers |
| KakaoTalk Multi-Profile, LINE subprofiles | different profiles for chosen friends | on their servers |
| Cwtch | custom pictures only for accepted contacts | peer to peer over Tor |
| Raven, this design | only friends you verified, one face of three each | a sealed offer and one chunk, peer to peer; no Raven server |

No messenger found in this research shows a picture only after the keys were
verified. The faces follow KakaoTalk and LINE in spirit, without the server.

## 6. Faces

### 6.1 What a face is
- At most 3. Each has a picture and a local name, such as "Family". The name
  is for the user only and never leaves the device.
- One face is "for new friends", or No picture is. A friend verified later
  gets that.
- Each verified friend has exactly one choice: face 1, 2 or 3, or No picture.
- When there is no face yet, a new face is offered to every verified friend
  and becomes the face for new friends. Before it goes, Raven shows the
  count ("Your 14 verified friends will see this picture."), and the user can
  pick friends instead.
- Changing a face's picture sends the new picture to the friends who have
  that face, and to nobody else.
- Removing a face asks where its friends go (another face or No picture),
  shows the count, and sends once.

### 6.2 Moving a friend
- Moving a friend to another face sends them the new one. Their device
  replaces the old one at once, with secure delete.
- Moving a friend to No picture sends the empty form (§9.3), which deletes
  my picture on their device.
- A friend may be moved at most 2 times a day (§21), so a picture never
  flickers.

### 6.3 The group shortcut
- In a group, "Give a face to this group" sets the face of each member who
  is my verified, unblocked friend. It does this once, now. Members who are
  not friends, or not verified, are left out, and the screen says how many.
- It is a shortcut, not a rule. A friend who joins the group later is not
  changed. A friend in two groups keeps the last choice made.
- Each friend moved this way counts against their 2 moves a day.

### 6.4 The social side
A friend may notice a new picture and guess that they were moved, for
example from Family to Everyone else. Raven keeps this calm:
- Nothing is announced: no chat line, no badge, no "updated" mark, no notice,
  no history. The picture just changes.
- The friend never learns face names, how many faces exist, or who else
  shares one. Every friend's offer has the same size and its own key.
- Before a move, the sender sees one plain line: "Max will see this picture
  from now on. Raven does not tell Max, but Max may notice."
- Friends who compare their screens can still see that they got different
  pictures. That is the nature of faces, and the reason they exist.

## 7. Only verified friends

- **Verified** means the contact's pin (`pinned` in `Contact`,
  `ash/cli.rs:2181`). The API shows it as `verified` (`cl/contacts.rs:335`),
  and `verify.check_words` sets it on a match (`cl/contacts.rs:589, 610`).
  Each person verifies the other on their own device, so one side can be
  verified first.
- **Sending.** Only to friends who are verified and not blocked
  (`pinned_unblocked_contacts`, `core/outbox.rs:2846`), and whose node
  announced link caps bit 12 (attachments §10.1).
- **Showing.** A friend's picture shows only while I have them verified and
  not blocked. Whether it shows is worked out each time it is read, never
  stored, so no path can leave a picture showing for a friend who is not
  verified.
- **Before I verify them.** A friend who verified me may send first. Their
  offer and its chunk are taken and kept hidden: checked against R, but
  never decrypted and never decoded, for at most 7 days (§11.4). When my
  words match, the picture shows at once. After 7 days the hidden copy goes;
  then my own first offer after I verify them carries `held` 0, which makes
  them send theirs again (§9.4).
- **Removing verification** (`contacts.unverify`). Their picture is deleted
  at once with secure delete. The engine does it inside the same op, and
  raven-node's pass deletes anything left. My offer still waiting for them
  is stopped. Nothing is sent, as with every chat control
  (`cl/chats.rs:1-4`). My choice for them stays, for the day I verify them
  again.
- **The seal.** Today's avatar is the seal: the first letter in one of 5
  colours, chosen by the sum of the address bytes mod 5 (`avatar_index`,
  `cl/identity.rs:46`). A friend who is not verified, blocked, without a
  picture, or seen with Show pictures off gets the seal, with no extra mark.
  The "Not verified" text stays where it is today.

## 8. The picture

### 8.1 Made in the app
- **Sources:** Photos (PHPicker on iPhone, which needs no library
  permission), the camera, or a file on the Mac.
- **Shape:** the user moves and zooms a square. The orientation is applied
  to the pixels, the colours become sRGB, and the square is scaled to
  384 × 384 px.
- **Format:** baseline JPEG (not progressive), with no metadata: no
  location, device, time or colour profile.
- **Size:** quality 0.7 first. While the file is over 60,000 bytes, the
  quality drops by 0.05, down to 0.4. After that, the side shrinks by 32 px
  at a time, never below 256.
  - Measured on a Mac with ImageIO at quality 0.7: 384 px gave 16 to 63 KB,
    so most pictures fit at once and the largest need a step or two.
  - 256 px gave 10 to 29 KB, so the loop always ends.
- **JPEG, not HEIC:** HEIC is 40 to 50 % smaller, but Linux and Windows
  cannot all decode it. An animated image is refused.
- **Preview:** the same square at 32 × 32 px, quality 0.4, at most 1,536
  bytes, as for a photo (attachments §6.1).
- **Tools,** as in attachments §6.1: ImageIO on Apple, `BitmapEncoder` on
  Windows, gdk-pixbuf on Linux.

### 8.2 Checked and cleaned by the engine
`faces.set` (§17) runs the receiver's check (§16) on the picture and on the
preview, and refuses what fails. It then writes the file again, without
decoding anything:
- only the allowed markers, in one fixed order: SOI, one JFIF APP0, the DQT
  segments, SOF0, the DHT segments, at most one DRI, SOS and its data, EOI;
- any other APP or COM segment an encoder added is dropped, but an Adobe
  APP14 that says the colours are not YCbCr makes it refuse the picture,
  since dropping it would change the colours.

Moving table segments in front of SOS changes no pixel. So what leaves the
device is exactly what every receiver accepts, in the order every receiver
asks for.

### 8.3 Sealed as one chunk
- **Padding.** Zeros up to exactly 61,424 bytes, one full segment, so the
  sealed chunk is always 61,440 bytes.
  - Not Padmé (attachments §7.2). Padmé(60,000) is 61,440, which is more
    than one segment, so a picture near the limit would take two chunks.
    With Padmé, only pictures up to 59,392 bytes would fit in one.
  - A fixed length also gives every profile picture the same size on the
    wire.
- **Key.** A new random K for each friend and for each send. The handle, the
  chunk key and the custody id come from K as in attachments §7.1. The nonce
  and the additional data are as in attachments §7.3, with a padded length
  of 61,424 and a chunk count of 1.
- **Tree.** One leaf: R is SHA-256(0x00 || chunk), and the audit path is
  empty. RRB1's `verify_chunk_path` already accepts this: with a count of 1,
  index 0 and no path, the leaf must equal the root
  (`core/release_bundle.rs:897-926`).
- **Why a key for each friend.** With one K for all friends, every copy would
  have the same handle on links and the same custody ids at mail friends. A
  mail friend shared by two friends could then tell that both got the same
  picture, and a friend who has K could ask for another friend's copy. With
  a key each, the copies are unrelated.
- **Only K is kept per friend.** The sender keeps each face once. A friend's
  chunk is sealed again from the face and that friend's K whenever it is
  needed: the same key, nonce and data give the same bytes. K goes once the
  friend has the chunk, or once a newer offer replaces it.
- **No old versions.** When a face's picture changes, the old version goes
  at once with secure delete, so there is no picture history on the sender
  either. An offer for the old version that still waits is stopped; one the
  friend already holds can no longer be served, and a pull for it gets GONE
  (§11.3).

## 9. The profile offer

### 9.1 The frame
An offer frame as in attachments §8.1: `RVNATT/1 offer`, a line feed, then
strict JSON with unknown fields refused. It is exactly 8,192 bytes. K and R
come after every other field, and the pad comes last.

| Field | Value |
|---|---|
| `v` | 1 |
| `handle` | 16 bytes in hex, from K (attachments §7.1); random in the empty form |
| `kind` | `profile` |
| `seq` | the order of this sender's profile offers (§9.4) |
| `held` | the `seq` of the newest offer from the receiver that the sender holds; 0 for none (§9.4) |
| `chunks` | 1, or 0 in the empty form |
| `padded_len` | 61,424 |
| `true_len` | 1 to 60,000 |
| `mime` | `image/jpeg` |
| `width`, `height` | equal, 64 to 512 (today's apps send 384) |
| `preview` | the 32 px JPEG in base64: at most 1,536 bytes, 2,048 characters |
| `key` | K |
| `root` | R |
| `pad` | zeros, up to exactly 8,192 bytes |

- **Not in it:** no name, no caption, no face name or number, and no time
  other than `seq`. The friend learns the picture, and nothing about the
  circle.
- **Size.** Without the pad, the largest offer is under 2,500 bytes, 2,048
  of them for the preview. So the pad always has room, and a mail friend or
  the network cannot tell this offer from a photo's.
- **Names.** The spec fixes the final field names; the fields shared with a
  photo follow the attachments §8.1 list.

### 9.2 The stored form
The `ref` form (attachments §8.1) of a profile offer drops K and R, and also
the preview. It is stored in one place only, the sender's hidden queued row
(§10.2), and nothing shows that row.

### 9.3 The empty form: No picture
The empty form has exactly these fields, padded to 8,192 bytes: `v`,
`handle` (16 random bytes), `kind` = `profile`, `seq`, `held`, `chunks` = 0
and `pad`.
- No other field may appear. An offer with `chunks` 0 and any picture field
  is refused.
- It has no chunk.
- The receiver deletes the picture it holds from that friend, with secure
  delete. It keeps the `seq` and shows the seal.

### 9.4 `seq` and `held`
- **`seq`** is the sender's clock in milliseconds, but at least the last
  `seq` it used plus one. It is at most 9,007,199,254,740,991 (2^53 − 1, so a
  JSON number stays exact, like `MAX_TIME_MS` in `core/group.rs:122`). One
  counter serves all of a sender's profile offers.
  - Why the clock and not a plain counter: a counter would tell each friend
    how many offers went to others between two of theirs, and so roughly
    how many friends the sender has.
- **The receiver keeps the highest `seq`** from each friend. An offer with a
  lower one is ACKed and dropped (§11.2).
- **`held`** is the `seq` of the newest offer from the receiver that the
  sender holds now, hidden or shown, a picture or the empty form. It is 0
  when the sender holds none: it never had one, removed the receiver's
  verification, blocked them, lost its store, deleted a bad picture, or got
  GONE for it.
- **Repair.** Each sender remembers, per friend, the `seq` of its own last
  offer that the friend took (the ACK came). When an offer from that friend
  carries a `held` lower than that, the friend has lost my picture, and I
  send it again, at most once a day per friend. Nothing else on the wire is
  needed: no link frame and no hello change.

### 9.5 Older builds
- **Phase 1a builds** (attachments §8.4, amended) know the `profile` kind.
  Such an offer is ACKed and kept silently, one per friend, a newer `seq`
  replacing the older, so a later build can open it.
  - It is never shown as text, never as a placeholder bubble, and never in
    the chat list, an unread count or a notice.
  - It is never deferred.
  - It is kept in a hidden history row, so the move to the profile store
    (§15) happens when the 1b build first opens the history, as attachments
    §8.2 does for photos. If retention removes the row first, the picture
    comes back when that friend changes it, or after my next offer to them,
    which then carries a lower `held` (§9.4).
  - A 1a build announces no bit 12, so it gets such an offer only from a
    stale record (§14). The usual holder is a build with bit 12 whose
    profile gate is still shut, which follows the same rule.
- **Builds before 1a** would show an offer as text. Senders never send to
  them, because they announce no bit 12 (§10.1). Pictures come with 1b,
  which brings bit 12 and the chunk, and which waits until 1a has spread
  (attachments §22).
- **In a group body,** a profile offer is never valid. Every build from 1a
  ACKs that group message and drops it as invalid (§13).

## 10. Sending

### 10.1 The profile pass
A pass in raven-node. It runs on each outbox scan, next to the groups'
`run_pending` (`core/group/park.rs:455`), and whenever the engine kicks it.
It works from state, not from events, so every way of verifying (the words,
the old code, the CLI) and every restart is covered:
1. Read the verified, unblocked friends (`pinned_unblocked_contacts`), their
   bit 12 records (attachments §10.1), `face_of` and `face_sends` (§15).
2. Bring `face_of` up to date:
   - A verified friend with no row is new. The row gets the face for new
     friends, or No picture.
   - A friend verified again keeps the choice in their row, and is due an
     offer even if they hold my picture already, so that `held` reaches
     them.
   - When the store is new (the first run with the gate live, or a lost
     store), each friend already verified gets a row with no choice yet.
     Nothing goes to them until the user gives them a face or No picture
     (§6.1). So a new store never sends No picture to everyone, which would
     take the user's picture off every friend's device.
3. For each friend whose choice (a face at its version, or No picture)
   differs from the newest offer made for them (unless that one was missed),
   who is due an offer, or who needs a repair, build an offer: a new K, the
   next `seq`, and `held` from `pictures`. No offer made yet counts as
   different; no choice yet builds nothing.
4. Park it like a group copy (§10.2), within the caps of §21.
5. Apply §14 to friends who are no longer verified (their row is marked so,
   their picture goes, my choice for them stays) or no longer current
   contacts (everything goes).

A friend with no bit 12 record is skipped until one exists. "First sight of
bit 12" is then a trigger (§10.5). A hello on an authenticated link that
carries caps without bit 12 clears the record (attachments §10.1, amended),
so a friend who goes back to an older build gets nothing it would show as
text.

### 10.2 Like a group copy
- **Parking.** The offer is parked as `park_copy` parks a group copy
  (`core/group/park.rs:62-130`): the contact admission, the revocation
  check, the friend's queue (32 waiting, `MAX_WAITING_PER_FRIEND`), the
  sentinel binding, a queued history row and the route record. The offer
  then rides any carrier, and mail friends hold it like any message.
- **A hidden row.** The queued history row holds the `ref` form (§9.2),
  because `persist_lan_chat_history` turns any `RVNATT/` body into it
  (attachments §8.2), with an empty `preview`.
  - Chat views drop it, as they drop group copies (`is_group_copy`,
    `without_group_copies`: `core/chat_history.rs:114, 1050`;
    `cl/engine.rs:649`).
  - It goes once its delivery is final, as `refresh_deliveries` does for
    group copies (`core/group/park.rs:394, 441`).
- **One offer per friend.** A newer offer stops the one still waiting,
  through the same stop as `messages.stop`. If the older one already left,
  both may arrive, and the friend keeps the higher `seq`.
- **The stage share.** An offer is parked only while fewer than 32 profile
  offers are staged and the whole stage holds fewer than 128 entries. Group
  copies follow the same 128 rule (`GROUP_STAGE_BUDGET`,
  `core/group/park.rs:27, 96`).
  - So 1:1 chat always keeps half of the stage's 256 entries
    (`core/chat_history.rs:2812`).
  - Pictures never fill the offline queue's 192 entries and 3 MiB
    (`ash/pair_init_lab.rs:68-73`): 32 offers are 256 KiB.
- **Order.** Friends in touch (`presence: in_touch`) go first. Friends who
  are away are parked at random times within an hour, so a change to a face
  shared with many friends is not one burst a watcher can count.

### 10.3 The chunk
- **Push.** When the offer's ACK comes back on a link the sender dialed, the
  sender pushes the one chunk on that link, as attachments §9 step 2 pushes
  a photo's. It is one `RAX1 PUSH` of 61,473 bytes: the 10 byte header, the
  handle, index and length, the 61,440 byte chunk and a path length of 0.
  That is inside the 65,511 byte frame limit.
- **Pull.** A friend's node that has the offer but not the chunk asks with
  `RAX1 WANT` (attachments §9 step 3).
- **A friend who is away.** In phase 1b the offer reaches them through a
  mail friend like any message, so they see the blurred preview, and the
  chunk waits for a live link. From phase 1c, one chunk object also goes to
  each of their mail friends (attachments §12), counted in the same caps.
- **Served only to that friend,** and only for the newest offer to them. An
  older handle answers GONE. At most 8 times a day per friend.
- **Delivered.** When the friend says DONE, or answers HAVE with a LACK of
  status complete, the sender forgets K for that friend.

### 10.4 What the sender records
For each friend, `face_sends` (§15) records:
- the face and version sent, or No picture;
- the `seq` and handle, and K until the friend has the chunk;
- the state: waiting, sent, taken or missed;
- the times, and the day's counts.

"Taken" means that the offer's ACK came, so the friend's node stored it (an
ACK waits for storage, attachments §2). The friend card shows from this
whether a friend has my picture (§18.4).

### 10.5 Triggers

| What happened | Who gets an offer |
|---|---|
| A face's picture changed | the verified friends who have that face |
| A friend was moved, alone or by the group shortcut | that friend |
| A face was removed | its friends, with the choice the user picked for them |
| A friend was verified, the first time or again | that friend, even with No picture, so that `held` reaches them |
| A verified friend was unblocked | that friend; their choice was erased by the block (§14), so they get the face for new friends |
| Bit 12 from a verified friend, seen for the first time | that friend |
| An offer ran out (7 days) or failed for good | that friend, when they are next in touch |
| A friend's `held` is lower than the `seq` they took (§9.4) | that friend, at most once a day |

A friend with no choice yet (§10.1) gets nothing from any of these.

### 10.6 Cost
- Per friend: the offer (8,192 bytes, 8,384 once sealed) and the chunk
  (61,440 bytes), about 70 KB.
- A face shared with 100 friends is about 7 MB of upload, spread over up to
  an hour for the friends who are away.
- Through mail friends (phase 1c) it can be up to twice that for friends who
  are away, since a friend has at most 2 mail friends.

## 11. Receiving

### 11.1 The policy
The policy runs inside the session store transaction, on metadata only
(attachments §8.3, `core/app_channel.rs:339`):
- A profile offer is accepted from a current, unblocked contact, verified or
  not, because that friend may have verified me first.
- Only when the gate is live and the offer decodes by the strict rules.
- Only while that friend is under 8 profile offers a day, counted in a window
  kept in memory like the app channel's (`take_rate_slot`,
  `core/app_channel.rs:311`). Past it, Defer: nothing is committed, and the
  sender retries the same bytes later. An honest sender never gets there,
  since it sends at most 4 a day to one friend (§21).
- With the gate shut, the phase 1a rule applies: kept silently, never
  deferred.
- A profile offer that does not decode is ACKed and dropped, like any other
  bad `RVNATT/` frame (attachments §8.4), and counted.

### 11.2 After the commit
raven-node opens the profile store, applies the rules below and writes the
`pictures` row, and only then ACKs. When the store cannot be written,
`deliver_committed` returns `Ok(false)`, so no ACK goes and the sender
retries (`core/app_channel.rs:403`). There is no history row, no chat row,
no notice and no unread count. The profile branch sits in the same five
places as an attachment offer's (attachments §8.3).

| The offer | What happens |
|---|---|
| Same SHA-256 as the one held | a copy, such as a re-send after a lost ACK: ACK, nothing changes |
| Same `seq`, another SHA-256 | ACK, drop it, keep the first, and count it |
| A lower `seq` | ACK and drop it |
| A higher `seq` | it replaces the held one at once; the old row and file go with secure delete |
| The empty form, with a higher `seq` | the picture goes with secure delete; the seal shows |

### 11.3 The chunk
- The chunk is pushed or pulled, checked against R (one leaf, empty path)
  the moment it lands, and written to `attachments/pictures/` as it came.
- Nothing is decrypted yet. When the app asks (§17), the engine decrypts it
  in memory, checks the JPEG (§16) and hands the bytes to the app. The app
  decodes them with the system decoder.
- A push from a contact I have not verified is taken for an offer I hold
  from them: RAX1 asks only for bit 12 on that link (attachments §9 step 7).
- A pull that gets GONE means the sender changed that face or sent a newer
  offer. The receiver deletes the offer it holds and shows the seal until
  the newer one lands. Its `held` is then 0, so a lost newer offer is
  repaired too (§9.4).

### 11.4 Not verified yet
- The row is marked hidden.
- The chunk is still taken, checked against R and kept as ciphertext.
  Nothing is decrypted or decoded.
- The hidden row goes after 7 days, or when a newer offer replaces it.
- Such an offer comes only on a live link: mail friends carry messages only
  between friends who verified each other (API.md "Chat controls").
- A friend I blocked sends nothing that arrives: a block drops their
  messages (API.md "Chat controls").

### 11.5 Strangers
A stranger has no session, so no offer of theirs ever reaches the policy. A
contact request carries a name and aliases, never a picture
(`core/contact_request.rs`).

## 12. Met in person

### 12.1 The flow
1. Two friends meet, scan each other's card and compare the words.
2. On the result card after a match, Raven offers "Take a picture of Max"
   and "Not now" (raven-ios `Raven/Views/AddFriend/WordsStep.swift`;
   raven-macos `Sources/RavenUI/Views/CheckWordsSheet.swift`).
   - It does not offer this when the words were read on a call (the words
     step's `onCall` mode, phone only: `canReadWordsOnCall`,
     `Raven/State/AppModel+Actions.swift:723`), because the friend is not
     there.
3. The camera opens inside Raven, and the picture never goes to Photos. It
   is made and checked like a face (§8.1, §8.2) and kept sealed in
   `attachments/met/` (§15).
4. Later, the friend card of any verified friend offers "Take a picture of
   Max" too, and "Remove your picture of Max".

### 12.2 What it is
- It never travels: not in an offer, a card, a group, an iPhone backup or
  anything synced.
- On this device it wins over the friend's own picture. When their picture
  is held too, the friend card offers "See the picture Max chose".
- It shows only while the friend is verified (§7). When verification is
  removed, it is kept hidden (§25 question 3). A block or a removal deletes
  it (§14).

### 12.3 Both faces cross at once
- Right after the match, the engine kicks the profile pass for that friend,
  through the outbox kick (IPC `OutboxKick`, `core/ipc.rs:127`;
  `rn/outbox.rs:703`). The pass parks my offer for the friend, and the
  outbox dials at once on its route plan: LAN first when both are on the
  same network, then the direct routes, then Tor.
- The sender needs the friend's bit 12 record (attachments §10.1), and right
  after the match there may be none: the record is kept only for verified
  friends, and a LAN listener sends no caps. So when it is missing, the pass
  first makes one dial with no frames, as the app channel's `probe` does
  (`rn/app_channel.rs:669-700`).
  - On Tor and Internet direct, the signed hellos of that dial give this
    node the friend's caps at once, and the offer follows.
  - On LAN, only the friend learns this node's caps from that dial, and
    keeps them only if it has verified this node already. Once both phones
    have matched, the second phone's dial gives the first its record, the
    first phone's offer gives the second its record, and both offers go.
  - So both pictures cross once both phones have matched, whichever matched
    first.
- On the same network both pictures cross in seconds. Over Tor each takes
  about as long as a message (the October field test measured 11 to 28 s
  per Tor message, attachments §2).
- Bluetooth is never needed: it is off on iPhone by owner decision. Between
  two Macs it may carry the one chunk, like any phase 1 chunk
  (attachments §9).

### 12.4 Permissions
- **iPhone.** The camera usage text says the camera is used only to scan
  cards (raven-ios `Config/Raven-Info.plist:84-85`). It must change, for
  example to "Raven uses the camera to scan the card of a friend you add,
  and to take pictures for your faces and of friends you meet. A picture you
  take of a friend stays on this device."
- **Mac.** The app has no camera text today and is signed with the hardened
  runtime (raven-macos `scripts/make-app.sh:292`). Met pictures need
  `NSCameraUsageDescription` and the camera entitlement
  (`com.apple.security.device.camera`), unless the Mac takes them from a
  file only (§25 question 8).

## 13. Groups

- **Never in a group.** A face is chosen per friend, but a group message
  goes to every member, friends or not, verified or not. So:
  - the engine never puts a profile offer in a group;
  - `groups.send` refuses any text that starts with `RVNATT/` and was not
    built by `attachments.send` (the composer guard, attachments §8.4,
    amended);
  - from phase 1a, a member's node drops a group message whose body is a
    profile offer as invalid: it is ACKed and never shown, by the path that
    already drops invalid group messages (`core/group.rs:1026-1036`,
    `ingest`).
- **Authors.** Beside a group message, the app shows the author's picture
  only when `from_friend` is true and the author, found by `from_address`,
  is a verified friend whose picture it holds. That picture is the face the
  author gave me in our own chat.
  - Anyone else gets the seal.
  - A member who is not my friend keeps the neutral colour and "not your
    friend" (APP-02; `cl/groups.rs:343-348`; API.md "Groups", "Authors").
- **The apps need `from_friend` first.** The iPhone and Mac `GroupMessage`
  models do not decode it yet (raven-ios `Raven/Engine/Models.swift:521`;
  raven-macos `Sources/RavenUI/Engine/Models.swift`). Neither app uses the
  neutral colour beside a message: the iPhone colours an author it cannot
  find with colour 0 (`Raven/Views/Chat/ChatView.swift:538-548`), and the
  Mac colours every author from the address
  (`Sources/RavenUI/Views/GroupViews.swift:197, 205`), which API.md
  "Authors" forbids for members who are not friends. Phase 1b fixes both
  before any picture shows beside a group message.
- **The group's own avatar** (the grid of letters, `GroupAvatar`) keeps its
  letters. It mixes friends with members who are not, and stays even.
- **The group shortcut** (§6.3) only sets faces. It sends nothing to the
  group.

## 14. Hard cases

| Case | What happens |
|---|---|
| **A friend is blocked** | Their picture, my met picture of them and my choice for them all go at once, with secure delete: per contact state keeps only current, unblocked contacts ("real erase", `admitted_contact_keys`, `core/outbox.rs:2809`). Nothing goes to them, and offers from them are dropped. Unblocking gives them the face for new friends and sends it with `held` 0, so they send theirs again. |
| **A friend is removed** | Everything about them goes: the choice, the sends, their picture and the met picture. My picture stays on their device: Raven cannot take back what was sent, as with a message. Before removing, Raven says so (§18.5). |
| **Unverify or block, silently** | Chat controls send nothing (`cl/chats.rs:1-4`), so my picture stays on the friend's device. The confirmation says how to take it back first (§18.5, §25 question 2). |
| **A friend on an old build** | Before 1a: never sent, since there is no bit 12. On 1a, or on a later build whose attachments gate is shut: no bit 12, so nothing is sent; an offer that arrives anyway (a stale record) is kept silently. On a build with bit 12 but the profile gate shut: kept silently, and shown once that gate opens. |
| **The offer comes before I verify** | Kept hidden with its chunk, never decrypted or decoded, for at most 7 days. It shows the moment the words match (§11.4). |
| **A face changes while a send is in flight** | The old version is deleted at once on the sender (§8.3), and the newer offer stops the waiting one. If the old one already left, both may arrive in any order, and the receiver keeps the higher `seq`. If the old one arrived without its chunk, a pull gets GONE: the receiver deletes it and shows the seal until the newer one lands (§11.3). |
| **A lost ACK** | The outbox sends the same bytes again. The receiver sees the same SHA-256 and ACKs. The sender's state stays "sent" until then. |
| **An offer runs out** | After 7 days on the horizon (`MESSAGE_HORIZON_MS`, `core/horizon.rs:168`) it is marked missed. It goes again when the friend is next in touch. |
| **Two devices** | Raven has no fan out yet: a message reaches the one device the carrier reaches (`docs/design/2026-10-per-device-keys.md` §0), and so does a picture. The other device shows the seal until an offer reaches it. Faces are kept per device in v1. Repair is at most once a day per friend, so two devices that hold different pictures cost at most one extra send a day, never a loop. |
| **A lost or old store** | Faces and pictures are gone, or old. A new store gives each friend already verified no choice yet (§10.1), so Raven never sends No picture to them by itself, and they keep my old picture until I choose again. Their pictures come back when they change theirs, or after my next offer to them, which carries `held` 0 (§9.4, §25 question 10). The iPhone profile is not in backups. A Mac restore brings back sealed rows, and the clock based `seq` stays above what friends hold. |
| **A bad picture** | It fails the check (§16) or the decoder. It is deleted and counted, and the seal shows. After 3 in a day from one friend, that friend's pictures are not decoded until the next day. |
| **The iPhone is locked** | Faces and met pictures cannot be read (§15.3), so a send waits for the next open. A new picture can still be written by the background mail check (phase 1c). |
| **A new key** | Key rotation re-seals `attachments.sqlite` (attachments §14). Files need no rewrite, because their keys live in sealed rows. |
| **No faces at all** | Friends verified before the store was made have no choice yet and get nothing. A newly verified friend gets No picture, and the empty form goes, which carries `held`. Nothing else is sent. |
| **Show pictures off** | The app shows seals for everyone and decodes nothing. Pictures are still kept, so turning it on shows them. |
| **The clock goes back** | `seq` is at least the last plus one, so it still rises. |

## 15. Storage and deletion

### 15.1 Tables
The tables are new tables in `attachments.sqlite` (attachments §14):
- a keyed store in `at_rest::FILES` (`core/at_rest/registry.rs:103`);
- rows sealed with `seal_row` (`core/at_rest.rs:1627`);
- `secure_delete` on (`harden_sqlite`, `core/paths.rs:678`), and a WAL
  checkpoint after deletes;
- re-sealed by the key rotation pass (`reseal_everything`,
  `core/privacy.rs:2092`).

| Table | One row per | Holds |
|---|---|---|
| `faces` | face (1 to 3) | the local name, the key of its file, the sizes, the preview, the version, whether it is for new friends, the changes today |
| `face_of` | friend the pass has seen verified | the face (1 to 3, 0 for No picture, or none yet, §10.1), whether the friend is verified now, whether an offer is due, when it was set, the moves today |
| `face_sends` | friend | the last send: face and version, `seq`, handle, K, state, times, offers and serves today, the last repair |
| `pictures` | friend | the newest offer from them without its pad (with K and R), the SHA-256 of the offer as it came, the `seq`, hidden or not, whether the chunk is in, the bad pictures today |
| `met` | friend | the key of the met picture's file, the sizes, when it was taken |

Rows name a friend by their key and nothing else.

### 15.2 Files
- `attachments/faces/<random>`: each face, encrypted with its own key, which
  lives in its `faces` row.
- `attachments/pictures/<handle>`: each friend's chunk as it came, which is
  ciphertext under the K in their offer.
- `attachments/met/<random>`: each met picture, encrypted with its own key,
  which lives in its `met` row.

Every file is ciphertext, and every key lives only in a sealed row. So
deleting the row with secure delete makes any old copy left on flash
unreadable. File names are random or handles, never a friend's key or name.
The folders are registered in `at_rest::FILES`, with the blob folder.

- **Not attachments.** Pictures are not in the 2 GiB quota, and chat
  retention, Clear history and Delete chat do not touch them: a picture
  belongs to the contact, not to a chat. Removing the contact removes it.
- **No staging file.** A picture is at most 60,000 bytes, or 80,000
  characters in base64, so it goes inside the API call (`faces.set`,
  `pictures.met_set`). That is well under the 1 MiB request limit
  (`cl/envelope.rs:11`).
- **At most:** 3 faces, and per friend one picture from them (about 64 KB:
  the 61,440 byte chunk and a row of under 3 KB) and one met picture.

### 15.3 iPhone
- **Backups.** The profile folder is excluded from backups (`ProfileFolder`,
  raven-ios `Raven/Engine/Engines.swift:42-60`), so faces and pictures never
  reach iCloud or a computer.
- **File protection.**
  - `NSFileProtectionComplete` on `attachments/faces/` and
    `attachments/met/`. They are needed only while the user is in Raven,
    and become unreadable shortly after the phone locks.
  - `NSFileProtectionCompleteUnlessOpen` on `attachments/pictures/`. The
    background mail check can still write a new picture while the phone is
    locked, but nothing can read one back until it is unlocked.
  - The rest of the profile keeps its default (until first unlock), which
    the background mail check needs.
- **A test on a device.** The app sets the class on the folders when it
  makes them, and the files Rust creates there should inherit it. A test on
  a real iPhone checks the class of each file
  (`URLResourceValues.fileProtection`), since the simulator does not enforce
  it.
- **Mac.** A Time Machine backup holds sealed rows and ciphertext, like
  every store.

## 16. Decoding safety

### 16.1 Why
A friend's picture is decoded with no click. Image decoders have been the
way in for attacks that needed nothing from the victim:

| Attack | What carried it | What stops it here |
|---|---|---|
| FORCEDENTRY, CVE-2021-30860 (Citizen Lab; Google Project Zero) | a PDF named `.gif` with JBIG2 data inside, sent by iMessage and decoded by CoreGraphics | JPEG only; the type is pinned (§16.2 rule 5); the marker check refuses anything that is not a baseline JPEG |
| BLASTPASS, CVE-2023-41064 (Citizen Lab) | an image in a PassKit attachment sent by iMessage, reaching a flaw in ImageIO (public analyses tie it to the WebP flaw CVE-2023-4863) | JPEG only; no picture is opened by the type it claims |
| WhatsApp CVE-2025-55177, chained with Apple CVE-2025-43300 | linked device sync messages that could make a device fetch and process content from any URL, then an out of bounds write in ImageIO (public analyses place it in lossless JPEG data inside DNG files) | nothing is fetched by URL; only sealed offers from verified friends; lossless JPEG (SOF3), DNG and every other format refused |
| MS05-009 | a flaw in PNG decoding, reached through MSN Messenger display pictures | the same kind of feature, which is why: verified friends only, JPEG only, and checked first |

### 16.2 The rules
1. **Only verified friends.** A picture or preview is decrypted for showing,
   checked and decoded only while its sender is verified. Nothing from
   anyone else is ever decoded.
2. **JPEG only:** baseline, no animation.
3. **Checked in Rust before any decoder.** The engine walks the markers and
   lengths. It decodes nothing.
   - **Allowed, in the order the sender's engine writes them (§8.2):** SOI;
     one APP0, which must be JFIF; DQT (8 bit tables, at most 4); SOF0 (8
     bit samples, 1 or 3 components, sampling factors 1 or 2, width equal
     to height and both equal to the offer's, 64 to 512); DHT (at most 2
     per class, as baseline allows, with code counts that fit); at most one
     DRI; exactly one SOS with every component; RST0 to RST7 inside the
     scan, in order; EOI.
   - **Refused:** SOF1 to SOF15 (extended, progressive, lossless,
     hierarchical and arithmetic), DAC, DNL, DHP, EXP, every other APP
     segment (EXIF, XMP, ICC, MPF), COM, the JPG extensions, any unknown
     marker, a length that runs past the file, any byte after EOI, and a
     file whose length is not `true_len`.
   - **The preview:** the same rules, square, 16 to 64 px.
4. **At most 512 px.** This leaves room to send a bigger size later without
   a new spec. And 512 × 512 decodes to only 1 MiB (4 bytes a pixel), so a
   decoder never allocates for a size the check did not see.
5. **The system decoder, pinned to JPEG.**
   - Apple: `CGImageSourceCreateWithData` with the type hint `public.jpeg`;
     refused unless `CGImageSourceGetType` is `public.jpeg`;
     `kCGImageSourceShouldCache` false; decoded with
     `CGImageSourceCreateThumbnailAtIndex` at the size shown.
   - Windows: the WIC JPEG decoder made by its class id
     (`CLSID_WICJpegDecoder`), never one chosen by sniffing.
   - Linux: `gdk_pixbuf_loader_new_with_type("jpeg", &error)`, never the
     loader that sniffs.
6. **In memory only.** Decoded pixels are never written to disk or to a
   thumbnail cache.
7. **A failure** deletes the picture, counts it and shows the seal (§14).
8. **Never in raven-node.** The node never decodes a picture (attachments
   §18.2). The check is the engine's code. On iPhone the engine runs inside
   the app (raven-core-ios `feature/ios-embedded`), next to the decoder.

## 17. The app API

New ops get rows in `desktop/api/API.md`, arms in the `cl/engine.rs`
dispatch table (`:193`) and rows in `raven-client/STATUS.md`. They answer
`NOT_AVAILABLE_YET` while the gate is shut. The engine serves them itself
from `attachments.sqlite` and the folders, as it serves `attachments.read`
(attachments §15). Picture bytes never cross raven-node's IPC.

| Op | Args | Result |
|---|---|---|
| `faces.list` | – | `{faces: [Face], for_new: 0..3}` |
| `faces.set` | `{face?: 1..3, name, jpeg_b64, preview_b64}` | `{face: Face}`. Without `face` it makes a new face. The engine checks and cleans the picture (§8.2), and the pass sends it to that face's friends |
| `faces.clear` | `{face, move_to: 0..3}` | `{moved}`: the face goes, and its friends get `move_to`, as does the choice for new friends if it was this face |
| `faces.read` | `{face}` | `{jpeg_b64}` |
| `faces.assign` | `{address, face: 0..3}`, or `{group, face}`, or `{for_new: 0..3}` | `{changed, left_out}`: one friend, each verified friend in a group (§6.3), or the face for new friends |
| `pictures.read` | `{address, which?: "theirs" or "met"}` | `{jpeg_b64}`, decrypted in memory and checked (§16); `NOT_VERIFIED` for a friend who is not verified |
| `pictures.met_set` | `{address, jpeg_b64}` | `{contact}` |
| `pictures.met_clear` | `{address}` | `{contact}` |
| `settings.set` | `{show_pictures: bool}` | `Settings`; true by default |

- **Face:** `{id: 1..3, name, friends, for_new, changed_ms, changes_left}`.
  `friends` is a count.
- **Contact, new fields:**
  - `picture: "theirs" | "met" | null`: what to show. Null shows the seal,
    and it is null unless the friend is verified and not blocked. With Show
    pictures off the fields stay as they are, and the app shows seals.
  - `picture_seq`: changes whenever the shown picture changes. The app keeps
    decoded pixels in memory by it.
  - `has_theirs`, `has_met`.
  - `face: 0..3`: what this friend gets; null when no choice was made yet
    (§10.1), and then the face picker marks none and nothing goes.
  - `face_state: "taken" | "sending" | "needs_newer_raven" | "not_verified"`,
    or null with no choice yet.
- **Events:** `picture {address}` when a friend's `picture` or
  `picture_seq` changes; `faces` when faces, choices or a send state
  change. At most 4 a second, like the `attachment` event.
- **Errors:** `PICTURE_TOO_BIG` (over 60,000 bytes, or a side over 512),
  `PICTURE_BAD` (the check failed), `FACES_FULL` (3 already),
  `CHANGE_LIMIT` (a face or a friend changed too often today, §21),
  `NOT_VERIFIED`.
- **Only verified friends** can be given a face: `faces.assign` for a
  friend who is not verified is `NOT_VERIFIED`.
- **Field names.** None holds a token the API refuses (`cl/safety.rs:9`:
  seed, private_key, secret, plaintext, recovery).

## 18. What each app shows

### 18.1 Surfaces
iPhone paths are in raven-ios `Raven/Views/`; Mac paths in raven-macos
`Sources/RavenUI/`.

| Place | iPhone today | Mac today | Shows |
|---|---|---|---|
| Chat list row | 48 pt (`Chats/ChatsList.swift:329`) | `Avatar` | picture or seal |
| Chat header | 40 pt, 36 at large text sizes (`Chat/ChatView.swift:153, 205`) | `Avatar` | picture or seal |
| Friends list, friend card | 40 pt (`Settings/FriendsView.swift:99`) | `Avatar` | picture or seal; on the card, what the friend sees (§18.4) |
| Beside a group message | 28 pt (`Chat/ChatView.swift:548`) | 21 to 26 pt (`Views/GroupViews.swift`) | a verified friend's picture, else the seal (§13) |
| Banner inside the app | 40 pt (`RootView.swift:135`) | | picture or seal |
| My own avatar | 32, 38 and 52 pt (`Chats/ChatsList.swift:55`, `MainView.swift:267`, `Settings/SettingsView.swift:41`) | | the face for new friends, else my seal |
| A group's avatar | the 48 pt grid (`GroupAvatar`) | | letters, always |
| Menu bar | | presence dot (`Views/MenuBar.swift:66`) | nothing new |
| Notices | "New message in Raven" (raven-ios `Raven/App/Background.swift:22`) | none posted | never a picture |
| Lock Screen, Live Activity, StandBy | raven-ios `Shared/RavenActivityAttributes.swift` | | never a picture: iOS keeps an activity's data outside Raven |
| App switcher | blurred (`Components/LockCover.swift`) | | blurred, as today |
| Card, QR code | | | never a picture |

### 18.2 The seal
The seal is today's `Avatar` on both, unchanged: the first letter in the
friend's colour, by `avatar_index` (raven-ios
`Raven/Views/Components/Controls.swift:5`; raven-macos
`Sources/RavenUI/Components/Presence.swift:18, 50`). A picture takes the same
circle and the same presence dot, so nothing moves when a picture comes or
goes.

### 18.3 Blurred, then sharp
When an offer lands from a verified friend, its preview shows at once,
scaled up and blurred. When the chunk is in and checked, the picture fades
in sharp, with no fade under Reduce Motion. If the chunk never comes, the
blurred preview stays: it is still the picture that friend chose.

### 18.4 Screens
- **Settings, Faces.** Up to three faces in a row, each with its name and
  its count ("14 friends"). Add a face; for each face, Change picture,
  Rename and Remove; the choice for new friends; Show pictures. Under them,
  one line (§18.5).
- **The friend card.** For a verified friend: their picture; "See the
  picture Max chose" when a met picture wins; what Max sees (a face or No
  picture) and whether Max has it. For a friend who is not verified: the
  seal and "Compare security words with Max to share pictures."
- **The face picker.** The three faces and No picture, with the move line
  of §6.4.
- **The group shortcut.** In the group's info: "Give a face to this group",
  then the count of verified friends it changes and the count left out.
- **The words result card.** "Take a picture of Max" and "Not now" (§12).

### 18.5 Words
Plain words, in the apps' voice, with no hyphens, dashes or apostrophes.

| Where | Text |
|---|---|
| Settings section | "Faces" |
| Settings line | "Only friends you verified see your faces. Each picture goes straight to that friend, end to end encrypted. No Raven server." |
| The first face | "Your 14 verified friends will see this picture." |
| Moving a friend | "Max will see this picture from now on. Raven does not tell Max, but Max may notice." |
| No picture | "No picture" and "Max will see your letter instead." |
| For new friends | "For new friends" |
| Group shortcut | "Give a face to this group" and "5 verified friends get Family. 3 others are not verified." |
| A friend not verified | "Compare security words with Max to share pictures." |
| Waiting | "Max gets it next time Max is online." |
| An old build | "Max needs a newer Raven to see pictures." |
| Met in person | "Take a picture of Max", "Not now" and "This picture stays on this device. Max never gets it." |
| Friend card | "See the picture Max chose" and "Remove your picture of Max" |
| Unverify, block, remove | "Max keeps your picture. To take it back, choose No picture for Max first." |
| Show pictures | "Show pictures" and "Off shows letters for everyone." |
| Errors | "This picture is too big.", "Raven could not use this picture.", "You can change a face 3 times a day." and "You can move Max 2 times a day." |

### 18.6 Access
- Screen readers say "Picture of Max" for their picture, "Your picture of
  Max" for a met picture, and "Max" for a seal. The presence is said as
  today.
- The face picker reads each face by its name and its count: "Family, 5
  friends".
- Controls are at least 44 points. With Reduce Motion nothing fades.
- A picture is never the only way to tell friends apart: the name is always
  beside it.

## 19. Privacy

### 19.1 Who learns what

| Who | Learns | Never learns |
|---|---|---|
| A verified friend | the face I gave them, and when it changes | the other faces, face names, who else has which |
| A friend I have not verified | nothing new: my sends wait until I verify them | any picture of mine |
| A group member | only what our own chat gives, if we are verified friends | anything through the group |
| A mail friend (phase 1c) | that an offer and a chunk went from me to a friend, and when | the picture; whether two friends got the same face |
| Tor relays, the local network | volume and timing, as for any message | anything inside |
| An iPhone backup | nothing: the profile is excluded | |
| Lock Screen, notices, Live Activities | nothing: never a picture | |
| Someone holding a locked iPhone | sealed rows; faces and met pictures under Complete protection | the pictures, until it is unlocked |

### 19.2 What stays visible
- **The shape of the chunk.** Every offer has one size, but a profile picture
  is always one chunk of exactly 61,440 bytes, and no attachment is: Padmé
  makes a one chunk attachment shorter, and a longer one has more chunks. So
  a mail friend, or someone watching a LAN while PAD1 is off (attachments
  §18.4), can tell "a picture went from Lily to Max" from "a photo" by the
  count and size of the chunks after an offer. They never learn the
  picture, the face or who else got it.
- **Timing.** A face change sends to that face's friends. Friends who are
  away get theirs at random times within an hour, but someone watching many
  links could still see a cluster.
- **Socially,** friends who compare screens see whether they got the same
  face (§6.4).

## 20. Threats and answers

| Threat | Answer |
|---|---|
| A zero click attack through a picture | §16: verified friends only, JPEG only, the marker check in Rust, a pinned system decoder, at most 512 px, in memory only. What is left: a flaw in a baseline JPEG decoder, reached by a friend I verified |
| A stranger sends a picture | A stranger has no session, so nothing reaches the policy; contact requests carry no picture (§11.5) |
| A friend I have not verified sends a crafted picture | Taken and checked against R, never decrypted or decoded; gone after 7 days |
| A friend floods offers | 8 a day taken, then Defer; one picture per friend, the newest replacing the older |
| A friend pulls a chunk again and again | Served only to that friend, only the newest offer, at most 8 times a day |
| A friend asks for another friend's copy | A handle is served only to the friend it was offered to, and every copy has its own K, handle and custody id |
| Someone forges a friend's picture | The offer comes sealed in that friend's session, and the chunk is checked against the R inside it |
| An old picture comes back | The receiver keeps the highest `seq`, and the session layer refuses replays |
| A friend learns my circles | Face names and counts never leave the device; every offer has one size and its own key |
| A picture links me across friends | No content address (§3.1); every copy is sealed under its own key |
| A face reaches the wrong person in a group | Pictures never travel in groups (§13) |
| Pasted text poses as an offer | The composer guard refuses chat and group text that starts with `RVNATT/` (attachments §8.4, amended); otherwise a pasted profile offer could put its preview on a friend's screen as the sender's picture |
| A lost or stolen device | Sealed rows, ciphertext files, iPhone file protection (§15.3); the app switcher picture is blurred |
| A picture leaks outside Raven | Never in a notice, the Lock Screen, a Live Activity, a card or an iPhone backup |
| A public listing of my picture | There is no public record (§3.1) and no Raven server |
| A friend keeps my picture after I unverify or block them | By design, as with a message: chat controls are silent. The confirmation says how to take it back first |
| A friend copies or screenshots my picture | Raven cannot stop it, as with any message |

## 21. Limits

| Limit | Value |
|---|---|
| Faces | at most 3 |
| A picture | 384 px sent, 64 to 512 px taken, at most 60,000 bytes; preview at most 1,536 bytes, 16 to 64 px |
| Changing a face | 3 times a day per face |
| Moving a friend | 2 times a day per friend; the group shortcut counts |
| Offers sent to one friend | 4 a day, every trigger counted; past that, the newest state goes the next day |
| Offers taken from one friend | 8 a day, then Defer |
| Repair | once a day per friend |
| Profile offers in the stage | 32 at once, and only while the whole stage holds fewer than 128 entries |
| Serving a chunk | only to its friend, only the newest offer, 8 times a day per friend |
| Chunks taken from one friend | 8 a day |
| A hidden offer from a friend I have not verified | 7 days |
| Bad pictures | 3 a day from one friend, then no decoding until the next day |
| Kept per friend | one picture from them (about 64 KB with its row) and one met picture |
| Upload | about 70 KB per friend per change; about 7 MB for a face shared with 100 friends |

## 22. Tests

- **raven-core.**
  - The profile offer and its empty form: exactly 8,192 bytes, the field
    order, K and R last, unknown fields refused, picture fields refused when
    `chunks` is 0, the bounds of `seq` and `held`.
  - The one segment padding, and the one leaf tree with
    `verify_chunk_path`.
  - The JPEG marker check against a corpus: each refused marker,
    truncations, lengths past the end, data after EOI, sizes that do not
    match, progressive, lossless, arithmetic, 16 bit tables. A fuzz target
    `jpeg_check`, and allocation tests.
  - The `ref` form without K, R or preview; the composer guard for
    `RVNATT/`.
- **Vectors** in `shared-vectors/rvn1/attachment/profile/`, and the Python
  reference in `protocol/reference/raven_protocol/attachment.py`.
- **raven-node.**
  - Sends go to verified friends only, never to a friend without bit 12; a
    hello without bit 12 clears the record.
  - The stage share (32, and 128 for the whole stage), with 1:1 chat still
    sent.
  - A newer offer stops the waiting one; both orders of two offers in
    flight; a lost ACK; an offer that runs out and goes again; repair by
    `held`, at most once a day.
  - The policy's 8 a day and Defer; the same `seq` with another digest; the
    empty form.
  - An offer before verification: hidden, never decrypted, gone after 7
    days, shown at once when the words match.
  - Unverify, block, unblock and remove, each with the rows and files that
    must go (secure delete and checkpoint).
  - A profile offer in a group body is dropped and ACKed; `groups.send`
    refuses `RVNATT/` text.
  - Serving only to the friend, only the newest offer, 8 a day.
  - `attachments.sqlite` goes through the key rotation pass with the new
    tables.
  - A 1a build keeps a profile offer silently, one per friend, never in a
    chat view, the chat list, an unread count or a notice.
  - The met flow's dial with no frames, on LAN and on Tor.
  - A new store sends nothing to friends already verified; a friend
    verified for the first time, or again, gets one offer.
- **Apps.**
  - The picture pipeline: the sizes, the quality loop, and no metadata left
    (checked with `CGImageSourceCopyPropertiesAtIndex`).
  - The pinned decoders refuse a PNG, a GIF, a HEIC and a PDF renamed to
    `.jpg`.
  - The seal in every case of §7; blurred, then sharp; the met flow after a
    match in person and not on a call; screen reader labels; stills in
    light and dark.
  - On a real iPhone, the file protection class of every file in the three
    folders.
- **Field run.** Two iPhones and a Mac meet, verify and swap faces on the
  same network and over Tor; one goes away and comes back; a face shared
  with many friends.

## 23. Gates, specs and phases

The process is the attachments one (attachments §22):
- the wire text in `protocol/RAVEN_ATTACHMENT_V1.md`, as a section for the
  `profile` kind;
- a row in `proto/PROTOCOL_VERSIONS.md`, and the freeze hashes with it;
- the feature id `feature/profile-pictures` in `core/suite_registry.rs`;
- evidence rows;
- then the owner's own flip of the gate.

| Phase | What | Gate |
|---|---|---|
| Attachments 1a | Every build also learns the `profile` kind: ACKed, kept silently, never shown. Ships inside 1a, alone and first. | none |
| 1b | Faces, sending and showing pictures, met in person, group authors and the decoding rules. macOS and iPhone first. Waits until 1a has spread, like attachments 1b. | `PROFILE_PICTURES_PRODUCTION_ENABLED` (asserts `ATTACHMENTS_PRODUCTION_ENABLED`) |
| 1c | The chunk through mail friends, for friends who are away. | `ATTACHMENT_CUSTODY_PRODUCTION_ENABLED` |
| Next | Windows and Linux, with the pinned decoders of §16.2. | the same gate |
| Later | §26 | separate decisions |

## 24. Decisions

### 24.1 The owner's decisions (2026-11-06)
1. **Only verified friends see a picture.** I send my picture only to
   friends I have verified, and I show a friend's picture only after I have
   verified them. Before that, the seal: a calm circle with the first letter
   in the friend's colour. Removing verification hides and deletes their
   picture on my side, and stops sending mine to them (§7).
2. **A face for each circle, in v1.** Up to 3 pictures. Each friend is given
   exactly one face and receives only that one; the others never leave the
   device. Assigning by group is a shortcut that sets the face of each
   verified friend in that group. Moving a friend sends the new face and
   replaces the old one on their device (§6).
3. **Met in person, in v1.** Right after the words match, Raven offers to
   take a picture of the friend that stays only on this device. It never
   travels, and it wins over their own picture on this device, with a way to
   see theirs. Both phones send their faces at once over whatever way is
   open. Bluetooth is off on iPhone and is not required (§12).
4. **Not in v1:** a ring drawn from the key around the picture, and
   temporary pictures with an end date (§26).
5. **The profile offer kind goes into attachments phase 1a now;** showing
   pictures comes with phase 1b (§23).

### 24.2 Choices made in this design

| Choice | Why |
|---|---|
| One full segment, not Padmé | always one chunk, and every picture one size (§8.3) |
| A new K for each friend and each send | unrelated copies, and serving per friend (§8.3) |
| `seq` from the clock | a counter would show how many offers went to others (§9.4) |
| `held` for repair, no resend on a timer | no link or hello change, and no traffic while nothing changes (§9.4, §25 question 10) |
| No new caps bit | bit 12, with the silent keeping of 1a, covers every build (§9.5) |
| Accept offers from friends not verified yet, hidden | verification is one sided, and the picture shows the moment the words match (§11.4) |
| Take up to 512 px, send 384 | room for later, and at most 1 MiB decoded (§16.2) |
| A marker check in Rust and pinned decoders | the attacks of §16.1 came through format confusion and rarely used features |
| Hidden queued rows with a share of the stage | the group copy rules, already tested (§10.2) |
| The group shortcut acts once and is not a rule | a friend in two groups would be ambiguous (§6.3) |
| A block erases my choice too | the real erase rule (§14) |
| Face names stay on the device | a name says more than a picture (§6.1) |
| Pictures inside API calls | at most 80,000 characters, and no staging file to clean up (§15.2) |
| iPhone file protection per folder | faces and met pictures are needed only while Raven is open (§15.3) |
| No choice yet for friends verified before the store | a new or lost store must never take the user's picture off every friend's device (§10.1) |

## 25. Open questions for the owner

1. **No picture.** Your decision gives each friend exactly one face. May a
   friend also be given No picture, and may No picture be the choice for new
   friends? Recommended: yes to both. It is the only way to take a picture
   back.
2. **Taking a picture back on unverify or block.** Recommended: stay silent
   like every chat control, with one line in the confirmation ("Max keeps
   your picture..."). The other way, sending No picture first, tells the
   friend that something changed.
3. **The met picture when verification is removed.** Recommended: keep it
   hidden, and show it again if the words match again. Or delete it.
4. **A met picture later, and from Photos.** The friend card offers it any
   time for a verified friend, not only right after the match, and from
   Photos as well as the camera. Recommended: yes to both. It still never
   travels.
5. **An offer from a friend you have not verified yet.** Recommended: keep
   it hidden for 7 days, so it shows the moment the words match. Or drop it,
   and let `held` bring it after you verify, one round trip later.
6. **The size taken.** Recommended: accept 64 to 512 px and send 384, so a
   later build can send 512 without breaking older ones. Or exactly 384.
7. **iPhone file protection.** Recommended: Complete for faces and met
   pictures, CompleteUnlessOpen for friends' pictures. And should attachment
   photos follow the same rule? Today the attachments doc keeps the profile
   default for them.
8. **The Mac camera.** Recommended: yes, with its usage text and its
   entitlement, for met pictures and faces. Or files only on the Mac.
9. **The limits of §21,** as written.
10. **Pictures after a lost store.** Recommended: wait for the next offer
    either way, since every trigger carries `held`. Or send every verified
    friend their face again every 30 days, as Delta Chat does every 14:
    about 70 KB per friend each time.

## 26. Not in v1, and later

- A ring drawn from the key around the picture (owner decision 4).
- Temporary pictures with an end date (owner decision 4).
- The same faces on the user's other devices. This waits for fan out (P5 of
  `docs/design/2026-10-per-device-keys.md`).
- A picture for a group.
- HEIC or AVIF pictures, and a bigger default size (receivers already take
  512 px).
- The same marker check for attachment photos, which today rely on the
  system decoder alone (attachments §18.2).
- Never: animated pictures; a picture in the card or in any public record; a
  picture on the Lock Screen or in a notice; a note that a picture changed.

## 27. What the review changed

### 27.1 Found while checking the draft against the code

| # | Found | Now |
|---|---|---|
| 1 | The composer guard reserves only `RVNAPP/` and `RVNGRP/`, and `groups.send` checks only `body_ok`, so pasted text that starts with `RVNATT/` would become an offer on a 1a build; a pasted profile offer would put its preview on a friend's screen as the sender's picture | The guard refuses `RVNATT/` in chat and group text from phase 1a (attachments §8.4, amended; §13, §20 here) |
| 2 | Phase 1a did not know the `profile` kind: nothing kept such an offer for a later build, and nothing kept it out of chat views | One hidden row per friend, the newer `seq` replacing the older, never shown anywhere (attachments §8.4, §21, §22, amended; §9.5 here) |
| 3 | The caps record was never cleared, so a friend who went back to a build before 1a would still get offers it shows as text | A hello that carries caps without bit 12 clears it (attachments §10.1, amended; §10.1 here) |
| 4 | Attachments §8.3 accepts an offer only from a verified friend, but verification is one sided, so a friend's picture could never be waiting when the words match | A profile offer is accepted from any current, unblocked contact and kept hidden until verified (attachments §8.1 and §8.3, amended; §7, §11 here) |
| 5 | Padmé would make a 60,000 byte picture two chunks | Padded to one full segment instead (§8.3) |
| 6 | One K for all friends would give every copy the same handle and custody ids, linking friends at a shared mail friend | A new K for each friend and each send (§8.3) |
| 7 | A counter for `seq` would tell each friend how many offers went to others | `seq` from the clock, kept rising (§9.4) |
| 8 | The claim that nobody can tell a profile picture from a photo holds for the offer only: one chunk of exactly 61,440 bytes is found only in profile pictures | Said plainly in §19.2 |
| 9 | Blocking kept my choice for the friend, which the real erase rule forbids | A block erases it; unblocking gives the face for new friends (§14) |
| 10 | Profile offers could have taken the half of the stage kept for 1:1 chat, and a first face for 100 friends was one burst | Their own share of 32 and the group copies' 128 rule; friends in touch first, the others spread over an hour (§10.2) |
| 11 | The iPhone and Mac group models lack `from_friend` | Phase 1b adds it before pictures show beside group messages (§13) |
| 12 | The iPhone camera text says the camera is used only to scan cards, and the Mac has no camera text or entitlement | Both are listed for change (§12.4) |
| 13 | A "start" pass that sent to every friend after a lost store would have sent No picture, removing the user's picture everywhere | Dropped: Raven never sends No picture by itself (§14, §25 question 10) |
| 14 | Attachments §8.2 lists the paths that write a staged body back, but misses the session reset's `settle_history` | Checked at 18f98ef: it also goes through `persist_lan_chat_history`, so the rule holds; the path is added (attachments §8.2, amended) |

### 27.2 Found in the skeptical read of the whole draft

| # | Found | Now |
|---|---|---|
| 1 | Sealing a chunk again from the face would no longer match R once the face changed; keeping old versions to serve them would be a picture history on the sender | The old version goes at once; its offers are stopped or answer GONE, and the receiver deletes on GONE (§8.3, §11.3, §14) |
| 2 | `held` was 0 after an empty form, so every offer from that friend would have set off a repair | `held` counts the empty form, and hidden offers (§9.4) |
| 3 | The pass compared a friend's choice with the last offer taken, so it would build a second offer while one was still in flight | It compares with the newest offer made, unless that one was missed (§10.1) |
| 4 | The pass deleted all profile state on unverify, against §7 (my choice stays, the met picture is kept hidden) | Its last step now follows §14 (§10.1) |
| 5 | Met in person said the second phone finds the record ready, but the record is kept only for verified friends, so on LAN the first dial teaches nothing until both have matched | Rewritten step by step; both cross once both have matched (§12.3) |
| 6 | Baseline JPEG allows 2 Huffman tables per class, not 4 | Fixed (§16.2) |
| 7 | A strict marker order would refuse layouts that valid encoders write | The sender's engine writes one fixed order, which receivers require; an Adobe APP14 that is not YCbCr is refused rather than dropped (§8.2, §16.2) |
| 8 | The `pictures` row held the offer with its pad, about 8 KB more per friend than needed | Stored without the pad, with the SHA-256 of the offer as it came; about 64 KB per friend (§15.1, §15.2, §21) |
| 9 | The Mac colours every group author from the address, members who are not friends too, against API.md "Authors"; the iPhone uses colour 0 | Both are listed for phase 1b, before any picture shows there (§2, §13) |
| 10 | "1b with the gate shut" did not say which of the two gates | Split by gate (§14) |
| 11 | Attachments §9 step 2 pushes only photos and voice notes | A profile picture is pushed the same way (§10.3) |
| 12 | In phase 1b, nothing said what a friend who is away gets | The offer through a mail friend and the blurred preview; the chunk waits for a live link until 1c (§10.3) |
| 13 | An offer from a friend not verified yet cannot come through mail friends, which need both sides verified | Said in §11.4 |
| 14 | "The first face made" also covered a new face after all faces were removed, which would send to everyone again | Only when there is no face; the count first, and the user can pick friends instead (§6.1) |
| 15 | The pass did not say what a verified friend without a `face_of` row gets, so after a lost store every friend would have looked new and got No picture; and a friend verified again whose choice matched the last offer got nothing, so `held` never reached them | New friends get the choice for new friends; a new store gives friends already verified no choice yet, and nothing goes to them; a friend verified again is due an offer (§10.1, §14, §15.1, §17) |
| 16 | §9.5 said a 1a row removed by retention comes back at the next first sight of bit 12, but a build with bit 12 and the profile gate shut never shows bit 12 for the first time again | It comes back by `held` with my next offer, or when the friend changes it (§9.5) |

## 28. What is built (version 1: one picture)

The owner's wish of 2026-11-15: simple, as on the messengers people know. A
person picks one photo from their own gallery for their profile, and the
friends they verified see it. So version 1 is this design with one face and
without the two extras of §24.1. Built on 2026-11-16 in raven-core
(`attachment::jpeg`, `attachment::picture`), in the engine the apps call
(raven-client `src/pictures.rs`) and as lab commands of the terminal app
(`raven lab picture-set`, `picture-clear`, `picture-send`, `pictures`,
`picture-save`), behind `PROFILE_PICTURES_PRODUCTION_ENABLED` (false). The
wire text is `protocol/RAVEN_ATTACHMENT_V1.md` §10.

| This design | Version 1 |
|---|---|
| Up to three faces, one for each circle (§6) | One picture. Every verified friend gets it. The wire has no notion of a face, so circles can come later with no change on it |
| Met in person (§12) | Not built |
| Only verified friends (§7) | As written: offered only to verified friends, shown only for verified friends, worked out at each read and never stored |
| The picture: a square JPEG, 384 px, at most 60,000 bytes, checked and written again by the engine (§8, §16) | `attachment::jpeg` (`check`, `clean`). Stricter than §16.2 in three places: the first of three components may be sampled twice as finely as the others and nothing else is taken; a scan holds at least two bits a block; and it holds exactly the restart markers its interval and its size ask for |
| The offer, `seq`, `held`, the empty form (§9) | As written (the codec is phase 1a's) |
| The profile pass in raven-node, on each outbox scan (§10.1) | The same look, `attachment::picture::pass`, taken by whoever sends: an app's engine while it runs, or `raven lab picture-send`. raven-node makes no offer by itself, so a friend verified while no app runs gets the picture when one next runs |
| A friend already verified when the store is new gets nothing before a choice; one verified later gets an offer, the empty form too (§10.1 step 2) | As written: the store's first look notes who is verified, and a later friend is due an offer that carries `held` |
| Parked like a group copy, friends who are away at random times within an hour (§10.2) | Sent as a message of the user's is, at once. A change is one burst of messages that a watcher of the network could count; §19.2 leaned on the spread. Open before the gate opens |
| A newer offer stops the one still waiting (§10.2) | Both may arrive, and the higher `seq` wins. The older one's row is gone, so its chunk is never served |
| Repair by `held` (§9.4) | As written, and only for an offer of the friend's that came after mine was made: what a friend held before it had my newest asks for nothing. Found in the first run between two nodes, where an older offer made a picture go twice |
| An offer before the receiver verified the sender: kept hidden with its chunk for 7 days (§11.4) | The offer is kept as phase 1a keeps it (one hidden history row, the newest). It is taken up, and its chunk pulled, once the words match. So nothing but that one message is taken from a contact that is not verified |
| The policy: 8 offers a day, then Defer (§11.1) | 8 a day, then ACKed and dropped |
| The chunk served 8 times a day, only for the newest offer (§10.3) | The attachment exchange's limits (attachments §27). Only the newest offer has a row to serve from |
| New tables in `attachments.sqlite` (§15) | Three sealed files (`pictures_mine.json`, `pictures_sent.json`, `pictures_theirs.json`) and the rows of the attachment store, which is one sealed file a row (attachments §26) |
| A picture is not an attachment of a chat (§15.2) | As written: a cleared or deleted chat and the sweep leave a picture's row alone while a picture file names it |
| A bad picture, 3 a day (§14) | As written |
| Show pictures (§17) | Not built |
| The app API `faces.*`, `pictures.*` (§17) | `picture.mine`, `picture.set`, `picture.clear`, `picture.read`, the members `picture` and `my_picture` of a friend's row and the events `picture` and `picture_mine` (`desktop/api/API.md`, "Your picture"; raven-client `src/pictures.rs`) |
| Changing a face 3 times a day, 4 offers a friend a day (§21) | A picture can be set 3 times a day. Removing it is never refused and uses up none: taking a picture away must always work (the builder of the iPhone screens pointed at this). So a friend may be offered 7 in a day |
| Group authors (§13) | Follows from the contact row: an app shows a verified friend's picture beside their group message |

Tried between two nodes on one computer (throwaway profiles, the same
network way): a picture an encoder wrote with an Exif block arrived as the
9,144 bytes the sender kept, with the same SHA-256 on both sides, and the
system's decoder opens it as a 384 px JPEG; a newer picture replaced it; a
file of 72,796 bytes and a PNG were refused; removing the verification made
the friend's picture unreadable at once and removed it at the next look;
removing the picture told the friend.
