# Raven desktop API (contract v1)

The three native apps (macOS SwiftUI, Windows WinUI 3, Linux GTK 4) do not reimplement any of Raven's
logic. They call one engine, **`raven-client`** (`node/crates/raven-client`), a Rust library built from
the same code the CLI and the terminal app use (identity, contacts, verification, sending, history,
outbox, node control). The engine runs inside the app process; message delivery itself stays in the
background `raven-node`, as today. How to build and link it on each OS: the crate's `README.md`; what
is done and what is not verified: its `STATUS.md`.

## Boundary: one C function, JSON in and out

```c
/* raven_client.h */
char *raven_call(const char *request_json);   /* returns a JSON response; never NULL */
void  raven_free(char *response);             /* frees a string returned by raven_call */
```

- Swift calls it through a module map over the static library; C# through `[DllImport]`; the GTK app
  is written in Rust and calls `raven_client::call()` directly.
- Requests and responses are NUL-terminated UTF-8. A NULL or non-UTF-8 request is answered with
  `BAD_REQUEST`; a failure inside the engine with `INTERNAL`. Every returned string goes to
  `raven_free` exactly once (never to the app's own allocator).
- One function keeps the boundary small, versioned and identical on every OS. There are no callbacks
  across the boundary: events are pulled with `events.poll` (cheap; the apps poll every 500 ms while a
  window is open and every 5 s in the menu bar or tray), or waited for with `events.wait`, which
  answers as soon as an event comes (no app uses it yet).
- Secrets never cross the boundary. The engine refuses to put fields named like `seed`,
  `private_key`, `secret`, `plaintext` or `recovery` in a response (the same rule as raven-node's IPC).
- All text returned for display is already sanitised (control characters, bidi overrides and
  zero-width characters removed), so a friend's name or message cannot draw over the UI.
- `raven_call` is thread-safe and may block (`node.start` can take a few seconds), so apps call it
  off the UI thread and post the result back. `events.poll` never blocks; `events.wait` blocks the
  calling thread up to its `timeout_ms` (25 s at most), never the engine's other calls.

## Profile and raven-node

- **Profile folder:** `RAVEN_DATA_DIR`, else `ASH_DATA_DIR`, else `~/.raven` (the CLI's lookup), so the
  app, `raven` and `ash` share one identity and one contact list. The CLI's secret-store variables
  (`RAVEN_IDENTITY_BACKEND` and friends) apply unchanged. The profile folder is read once, on the
  first call in the process. Tests and smoke runs always set a throwaway `RAVEN_DATA_DIR` with the
  file-backed stores (`locked-file`) and `RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1` before that call, and use
  the engine's **debug** build: a release engine refuses the file-backed stores (`profile.state` is
  then `unreadable`, `detail` "... forbidden in Release builds") and never falls back to them.
- **raven-node:** the engine starts it (on `node.start`, or for a send when nothing runs) as the user's
  background process. The program is `RAVEN_NODE_BIN` when set, else `raven-node` next to the app's
  executable (macOS: `Raven.app/Contents/MacOS/raven-node`; Windows: `raven-node.exe` beside the app),
  else the CLI's own lookup. Each app ships raven-node in that place.
- **Opening the profile:** before every operation that touches the profile the engine does what the
  CLI does before every command. A profile whose erase or key change (`raven privacy rotate-meta`)
  did not finish is refused (`PROFILE_UNREADABLE`; its `detail` names the command that finishes
  it, the message none) and nothing is written. The profile's at-rest key is loaded (a sealed profile can't be read
  without it; raven-node seals a release build's profile at its start) and what is still plain is
  sealed where the build seals. Without the key, reading the friends list, the history or the
  settings fails with `KEYCHAIN_DENIED`.
- **Settings** are written once the identity exists; before that (during setup) they are kept in
  memory and written with the identity: `desktop_settings.json` (nothing in it names anyone), the
  user's name in `desktop_private.rms` (encrypted once the profile is), and the chat-keeping time as
  the privacy pack's own setting (what `raven chats keep` sets).

## Envelope

Request: `{"v": 1, "op": "<operation>", "args": { ... }}`

Response, success: `{"v": 1, "ok": true, "result": { ... }}`
Response, failure: `{"v": 1, "ok": false, "error": {"code": "<CODE>", "message": "<plain English, one next step>", "detail": "<technical text, shown only under Details>"}}`

Unknown fields must be ignored by both sides (forward compatibility). `v` increases only for breaking
changes. Fields marked `?` may be missing.

## Operations

| op | args | result |
|---|---|---|
| `app.info` | – | `{version, build: "release" \| "dev", platform, api: 1}` |
| `profile.state` | – | `{state: "new" \| "ready" \| "locked" \| "unreadable", reason?, detail?, lock_v2?: true}` (`locked`: `raven lock` stopped Raven, or with `lock_v2: true` Lock v2 holds it: `lock.unlock` opens it, see "Security, Lock and updates"; `unreadable` also while an erase or key change is unfinished, or while the keychain does not give the key of an encrypted profile) |
| `identity.create` | `{display_name?}` | `{address, words: [10], old_code, note?}` (`note`: a problem that did not stop setup, e.g. the first prekey) |
| `identity.me` | – | `{display_name?, address, words: [10], old_code, card, invite}` |
| `card.make` | `{include_address: bool}` | `{card, invite, address_included?: "ip:port", address_missing?: "not_receiving" \| "this_computer_only" \| "no_network"}` |
| `card.parse` | `{text}` | `{short_address, has_address, routes: [{kind, label, preview: bool}], address, already_saved: bool, already_verified: bool, ignored_routes: [kind], note: string\|null}` (never returns the friend's security words or old code). `ignored_routes`: the route kinds (`internet`, `p2p`) the card named that were left out, because no key signs a card's addresses and release builds never read them; `note` is the one line to show about it, `null` when nothing was left out |
| `contacts.list` | – | `{contacts: [Contact]}` |
| `contacts.add` | `{text, name}` | `{contact: Contact}` (saved as not verified) |
| `contacts.rename` | `{address, name}` | `{contact}` |
| `contacts.remove` | `{address}` | `{}` |
| `contacts.set_address` | `{address, lan: "ip:port"}` | `{contact}` |
| `contacts.block` | `{address}` | `{contact}` with `blocked: true` (see "Chat controls") |
| `contacts.unblock` | `{address}` | `{contact}` |
| `contacts.unverify` | `{address}` | `{contact}` with `verified: false` (see "Chat controls") |
| `verify.check_words` | `{address, words: [10]}` | `{result: "match" \| "typo" \| "mismatch", contact?, reason?, position?, mismatches?}` (see below) |
| `verify.check_old_code` | `{address, code}` | `{result: "match" \| "mismatch", contact?, case_only?: bool, mismatches?}` (see below) |
| `verify.word_hint` | `{prefix}` | `{word?, known: bool}` (completes after 3 letters from Raven's word list; says nothing about the friend's words) |
| `messages.history` | `{address, before?: id, limit}` | `{messages: [Message]}` (`limit` default 100, at most 1000) |
| `messages.send` | `{address, text}` | `{message: Message}` (returns at once with `sending`; the engine sends in the background) |
| `messages.retry` | `{id}` | `{message, changed: bool, replaces?: id, may_arrive_twice?: bool}` (see below) |
| `messages.stop` | `{id}` | `{message, changed: bool, may_have_arrived?: bool}` |
| `messages.delete` | `{id}` | `{id, deleted: true}` (an ended message of yours: see below) |
| `messages.details` | `{id}` | `{message, status_text, why_text, action_text, detail, technical}` (`detail`: plain lines, such as the stored message ID, the way it went and what the last try said; `technical`: the developer fields, shown only under "Technical details") |
| `messages.mark_read` | `{address, id?}` | `{address, unread, note?}` (the chat is read up to `id`, default its newest message; see "Read and unread") |
| `messages.clear` | `{address, include_pending?: bool}` | `{cleared, pending_kept}` (this device's history of that chat; see "Chat controls") |
| `messages.handoff` | `{budget_ms?}` | `{handed, left, delivered, holders: [name], custody: "on" \| "off", completed, elapsed_ms}` (before the app goes to the background: what waits goes to friends who hold mail now; see "Hand-off") |
| `node.status` | – | `NodeStatus` |
| `node.start` | – | `NodeStatus` |
| `node.stop` | – | `NodeStatus` + `{stop, note?}` (see below) |
| `node.pause` | `{nearby?: "keep" \| "stop"}` | `NodeStatus` + `{was_running, nearby: "kept" \| "stopped", note?}` (embedded node only: the app went to the background; `nearby: "keep"` keeps Bluetooth nearby in a small background node; see "Embedded node") |
| `node.resume` | – | `NodeStatus` (embedded node only: the app is open again) |
| `mail.check` | `{budget_ms?}` | `{custody: "on" \| "off", started_node, completed, new_messages, elapsed_ms, names: [name]}` (embedded node only: one bounded fetch from friends, for iOS background refresh; `names`: the friends it asked, by your names for them) |
| `network.path` | `{type: "wifi" \| "wired" \| "cellular" \| "other" \| "offline" \| "unknown"}` | `{path, changed}` (embedded node only: the kind of network the device uses, from the iOS app's `NWPathMonitor`; with `tor_wifi_only` on, Tor stays off on `cellular`) |
| `settings.get` | – | `Settings` |
| `settings.set` | `{...partial Settings}` | `Settings` |
| `events.poll` | `{after_seq}` | `{seq, events: [Event], reset: bool, locked?: true}` (see Events) |
| `events.wait` | `{after_seq, timeout_ms?}` | as `events.poll`; with nothing new it waits up to `timeout_ms` (at most and by default 25000) and answers as soon as an event comes (see Events) |
| `contacts.warm` | `{address, why: "open" \| "typing"}` | `{warming: bool, why?}` (lab, the warm gate: warms the Tor path to a verified friend before a send, when a chat with it opens or the user types in it; nothing is sent early; see "Warm-ups") |
| `privacy.state` | – | `{available: bool, encrypted: bool, locked: bool}` (`encrypted`: the privacy pack encrypts this profile; `locked`: `raven lock` stopped Raven; `available` is false until the apps offer the privacy actions, which they then show with the Preview label) |
| `privacy.lock` / `privacy.unlock` | – | `{state}` (`unlock` clears a `raven lock` and answers as `profile.state`) |
| `privacy.encrypt` | – | `{state}` (encrypts everything Raven stores on this computer) |
| `privacy.erase` | `{confirm: "erase"}` | `{}` (removes Raven's data from this computer; afterwards `profile.state` is `new`) |
| `network.status` | – | `NetworkStatus` (every way to reach friends; see Network) |
| `network.set` | `{...settings, agreed?}` | `{changes: [Change], restart_needed: bool, status: NetworkStatus}` |
| `network.check` | `{router?: bool}` | `{summary: [{key, label, value}], next_step, rows: [CheckRow], router?: [CheckRow], technical: [line]}` |
| `nearby.status` | – | `NearbyStatus` (Bluetooth nearby now; see "Bluetooth nearby") |
| `nearby.contact` | `{address, advertise: bool, for_min?: 30..1440}` | `{address, advertising, until_ms?, status: NearbyStatus}` (`raven nearby on <friend> [--for]` / `off <friend>`; verified friends only) |
| `nearby.stop_all` | – | `{status: NearbyStatus}` (`raven nearby off`: advertising stops for every friend) |
| `nearby.permission` | – | `{permission: "not_determined" \| "restricted" \| "denied" \| "allowed"}` (iPhone and iPad only: read without a prompt) |
| `contacts.routes` | `{address}` | `ContactRoutes` |
| `contacts.set_routes` | `{address, internet?, p2p?, via?: [..], clear?: [..], custodians?: [address], hide_ip?}` | `{contact: Contact, routes: ContactRoutes}` |
| `security.status` | – | `SecurityStatus` (`raven security`, read-only) |
| `lock.state` | – | `LockState` |
| `lock.now` | – | `LockState` (Lock v2: raven-node keeps running and forgets its keys; the app's own node stopped or paused: the lock is held in the process and its next start is locked) |
| `lock.unlock` | `{passphrase?}` | `LockState` + `{note?}` |
| `lock.passphrase_state` | – | `PassphraseState` (`raven passphrase`, read-only) |
| `lock.set_passphrase` | `{new, old?}` | `PassphraseState` + `{note}` (without `old`: sets one, `raven passphrase set`; with `old`: changes it, `raven passphrase change`) |
| `lock.remove_passphrase` | `{old}` | `PassphraseState` + `{note}` (`raven passphrase remove`: the keys go back into the login keychain) |
| `updates.status` | – | `UpdatesStatus` (`raven update status`, read-only; installing stays in the CLI) |
| `groups.list` | – | `{available: bool, groups: [Group]}` (see Groups) |
| `groups.get` | `{group}` | `{group: Group, members: [GroupMember]}` |
| `groups.create` | `{name, members: [address]}` | `{group: Group, members: [GroupMember]}` (you are its admin) |
| `groups.add` | `{group, members: [address]}` | `{group, members}` (admin only) |
| `groups.remove` | `{group, member: address}` | `{group, members}` (admin only) |
| `groups.leave` | `{group}` | `{group}` (not the admin) |
| `groups.forget` | `{group}` | `{group, forgotten: true}` (a group you left or were removed from; see Groups) |
| `groups.history` | `{group, before?: id, limit?}` | `{messages: [GroupMessage]}` (oldest first; `limit` default 100, at most 500) |
| `groups.send` | `{group, text}` | `{message: GroupMessage, note?}` (returns at once; raven-node delivers each copy, started first when none runs; `note`: why it could not be asked to now, the copies wait) |
| `groups.mark_read` | `{group}` | `{group: id, unread: 0}` |
| `groups.clear` | `{group, include_pending?: bool}` | `{cleared, pending_kept}` (see "Chat controls") |
| `chats.list` | – | `{chats: [Chat]}` (pinned first, then the newest message first; see "Chat controls") |
| `chats.delete` | `{address}` or `{group}` | `{deleted: true, cleared, pending_kept}` |
| `chats.pin` | `{address \| group, pinned: bool}` | `{pinned}` |

Until the apps offer them, `privacy.lock`, `privacy.encrypt` and `privacy.erase` return the error
`NOT_AVAILABLE_YET` (its `detail` names the CLI command: `raven lock`, `raven privacy seal-now`,
`raven erase`; the message names none, as no app installs a `raven` command) and change nothing.
`privacy.unlock` is the Locked screen's Unlock: it clears the lock as `raven unlock` first does, and
never touches Raven's login item.

### Checking words and the old code

- `verify.check_words` takes the 10 typed words as a list (one string with the words is accepted
  too). It never returns or marks the friend's words:
  - `match`: the friend is pinned as verified; `contact` is the updated contact.
  - `typo`: the check word does not fit (a misheard, swapped or mistyped word), or a word is not on
    Raven's list, or has letters that are not English. `reason` is `bad_check`, `unknown` or
    `non_latin`, and `position` (1-based) names the word when the problem is in one word. Both come
    from the typed text alone.
  - `mismatch`: do not verify; `mismatches` counts this friend's mismatches (words and old code
    together) in this run of the app, so the app can stop offering Check after three.
  - Nothing typed, not exactly 10 words, or a word typed with too few letters to be sure (fewer than
    3, or a prefix several words share) is not a result but the error `WORDS_INCOMPLETE` (`detail`
    says which word or how many were typed).
- `verify.check_old_code`: the old letters-and-digits code, for friends with an older Raven, compared
  as the CLI compares it. Spaces and separators such as `-` are ignored, letter case matters,
  Persian and Arabic-Indic digits are folded. `match` pins the friend as verified (`contact`);
  `mismatch` carries `mismatches` (shared with the words) and `case_only: true` when only the
  letters' case differs. An entry of 4 or more words is security words, and gets the answer of
  `verify.check_words`.

### Messages

- **Ids.** A message sent while the app runs gets the id `pending-N` at once and keeps it after its
  history row appears; other messages use their history id. Treat ids as opaque strings.
- **Incoming messages** have the state `delivered`.
- **`messages.retry`** depends on where the message stands:
  - `waiting`: raven-node tries it again now; the same message comes back (`changed: true`).
  - a send of this run that never got written anywhere and has no history row: sent again under the
    same id (`changed: true`). Such a send normally has one: see "Not sent" below.
  - ended (`failed`, `time_ran_out`, `not_sent_meet_first`): the same text is sent again as a **new
    message with a new id**; `replaces` holds the old id. Show the new message in place of the old
    one: from then on (this run of the engine) `messages.history` leaves the old one out, so the chat
    keeps one bubble for the text. `may_arrive_twice: true` means the first one may have
    reached the friend's computer, so the text may arrive twice.
  - `sending`, `sent`, `delivered`, or an incoming message: unchanged (`changed: false`).
- **Not sent.** A send that queued and wrote nothing (`not_sent_meet_first`, or `failed` because the
  background program could not be used or it was stopped before it ran) is kept in the chat history
  as `failed`, as a message raven-node gave up on: after a restart it is still in the chat, as
  `failed`, with Send again and Delete (in this run it keeps `not_sent_meet_first`). The terminal app
  lists it as not delivered.
- **`messages.delete`** takes an ended message of yours (`failed`, `time_ran_out`,
  `not_sent_meet_first`) out of the chat for good: a send of this run with no history row is
  forgotten; one Raven's history keeps is left out of `messages.history` from then on, in this run
  and the next, and out of the terminal app's chats (its id goes to `desktop_hidden.json`, ids only,
  which the terminal app reads too; the history row itself goes when the chat-keeping time ends).
  The message Send again replaces (`replaces`) is left out the same way. Anything else is
  `BAD_REQUEST` (stop a waiting message first).
- **`messages.stop`** ends a `waiting` or `sent` message (and drops a send still queued);
  `may_have_arrived: true` when it was already written to the friend's computer. Anything else comes
  back unchanged (`changed: false`).

### Read and unread

- One read marker per friend, kept in the profile and shared with the terminal app (the newest
  message read on this computer, in either app): a chat read in one app counts as read in the other,
  and the counts survive a restart. Local only: no read receipt is ever sent.
- `Contact.unread` counts the friend's messages after their marker (all of theirs before any is read).
  Messages of yours are never unread.
- **`messages.mark_read`** moves the marker to the newest message with a history row up to `id`
  (default the chat's newest), and never moves it back (a later marker saved by the terminal app
  stays). Apps call it while the open chat is on screen, with the newest message they show, so a
  message that arrived after it stays unread. `unread` is the count afterwards; `note` says why the
  marker could not be saved (it then counts for this run of the engine only). An `id` not in the chat
  is `BAD_REQUEST`.
- An `unread` event comes whenever a friend's count changes: a message came, or the chat was read in
  this app or in the terminal app (the engine looks at the marker's file about once a second).

### Groups

Group chats (`docs/design/2026-10-groups.md`, `protocol/RAVEN_GROUP_V1.md`). A group message is sealed
once for each member who is your friend and sent by raven-node like any message (every way, friend
custody, the 7-day wait); members who are not your friends get it passed on by another member. On
in release builds since 2026-10-29 (commit b783524, not independently reviewed): `groups.list` says
`available: true` there. Only while the gate is closed does `groups.list` say `available: false`
(the apps then show no Groups section) and every other `groups.*` op answer `NOT_AVAILABLE_YET`: a
debug build with `RAVEN_LAB_GROUPS=0` or `RAVEN_LAB_HORIZON=0` (for the engine and for raven-node),
or a security notice that holds `feature/groups` or `feature/long-horizon`.

- **Ids.** `group` is the group's id (32 hex characters, opaque to the apps); a message `id` is its
  group message id. Members are named by their Raven `address`.
- **Members.** A group has at most 16 members, you included, and one admin (its creator) who alone
  adds and removes; the admin can't leave. Only your friends (`contacts.list`, not blocked) can be
  added. Joining is automatic: a group a friend adds you to appears in `groups.list` (with a
  `group_changed` event); you can leave it. You keep at most 8 groups of one admin and 64 groups
  in all, left and removed ones counted until you forget them (`groups.forget`): an invitation
  past either waits on the admin's side and joins when it comes again once there is room; other
  admins' invitations are not affected. A group you were removed from that adds you back takes
  no new room.
- **Names.** `GroupMember.name` is your name for a member who is your friend, else the name the
  admin gave them (`label`); `friend: false` members are shown as "not your friend" and are never
  added to your friends by the group. You are `me: true` (name: your display name, else "You").
- **Authors.** A message's `from_name` is named the same way. A label is any text its admin chose,
  the name of one of your friends too, so `GroupMessage.from_friend` says whether `from_name` is a
  name you chose: true for yours and for a friend's, false for anyone else (the admin's label, or
  "a former member (1a2b3c4d)"); `Group.last_from_friend` says the same of `last_from`. An author
  with `from_friend: false` is never shown as a friend: wherever its name is shown (the message, a
  list preview, a notification) it goes with "not your friend", in a neutral colour (never one
  derived from the address). `raven group show`, `raven inbox` and the terminal app do so too, and
  show the start of the key instead of a label that is, or only looks like, the name of one of
  your friends or "you"; they name the members of a delivery list (a `receipts` entry's `name`)
  the same way, so an app shows a `receipts` name of a member who is not your friend with "not
  your friend" too.
- **Receipts.** Each message of yours lists one `receipts` entry per member it was for:
  `waiting` (still on this computer, or passed on by another member and not confirmed yet), `sent`
  (left this computer, no receipt yet), `delivered` (that member's Raven confirmed it: a signed
  receipt) or `failed` (given up). `delivered`/`total` give "Delivered to 3 of 5". `via: "relay"`
  marks a member reached through another member. A member you blocked is sent nothing, not even
  through another member: its entry is `failed` from the start, and its receipts are ignored. A
  member's Raven takes an author's share of a group's messages within 7 days: 8,192 over the
  group's members, at least 512 (4,096 in a group of two, 512 in a group of 16). Yours sends no
  message past your own share: `groups.send` is `GROUP_QUEUE_FULL` until your oldest of them is 7
  days old, because every member would refuse it and each copy would wait in your queue for that
  friend (the 32 messages a friend may have waiting, 1:1 messages included) for 7 days. A copy a
  member's Raven refuses anyway (its roster is newer than yours, with more members) is not
  confirmed: it stays `sent`, is sent again until it is taken or its 7 days pass, and counts in
  your queue for that friend meanwhile. A copy another member passed on for you past that member's
  share is dropped there (so it never waits in that member's queue), and that entry stays
  `waiting`.
- **Leaving and removal.** `status` is `left` after `groups.leave` and `removed` when the admin
  removed you: the history stays, `groups.send` is `GROUP_NOT_MEMBER`. `groups.leave` on a group
  you left whose admin has not taken your leave yet (no roster without you came; the copy may
  have been given up after 7 days) sends the leave again, one at a time; once a roster without you
  came, it is `GROUP_NOT_MEMBER`.
- **Forget** (`groups.forget`): a group you left or were removed from (or one with no other
  member) goes from this computer: it leaves `groups.list`, its messages go, and its place is free
  for another group; every op on it is then `GROUP_NOT_FOUND`. A group you are still in is
  `GROUP_STILL_MEMBER` (leave it first). Its old messages and rosters do not bring it back; a newer
  roster from its admin that adds you again is a new invitation. The other members are not told.
  `raven group forget GROUP`.
- **Read and unread.** `Group.unread` counts others' messages received after the group was last read
  on this computer (`groups.mark_read`, or `raven group show`). Local only.

### Chat controls

Block, remove verification, clear history, delete a chat and pin one (0.1.1). Everything is local to
this device: the other person is never told, and nothing about it is sent. Every UI on the device
(the apps, the terminal app, `raven`) shares the same state.

- **Block** (`contacts.block`): the friend's 1:1 messages, contact requests and group messages are
  dropped silently and nothing goes to them (no receipt, no route hints, no friend custody for them
  or with them): raven-node refuses a blocked key on every way. Their saved routes and their choice
  as a mail friend are forgotten; the contact stays (`blocked: true`) and `contacts.unblock` undoes
  it. The CLI: `raven contact block NAME`, `raven contact unblock NAME`.
- **Remove verification** (`contacts.unverify`): `verified: false`; the contact, the chat and the
  routes stay. What needs both of you verified (friend mailboxes, the LAN address shared over Tor)
  stops until `verify.check_words` matches again. `raven contact unverify NAME`.
- **Clear history** (`messages.clear`, `groups.clear`): this device's messages of that chat go for
  good (received copies leave a tombstone, so neither the archive nor a copy that comes again
  brings them back; the privacy pack's delete-chat). Messages of yours still waiting to be sent stay
  (`pending_kept`) and show again once sent, unless `include_pending: true`, which stops them first.
  `raven chats clear NAME`, `raven group clear GROUP`.
- **Delete chat** (`chats.delete`): clear history, and the chat leaves `chats.list` (and
  `hidden: true` on its Contact or Group) until a new message comes. The contact and the group
  membership stay. `raven chats delete NAME` or `--group GROUP`.
- **Pin** (`chats.pin`): pinned chats come first in `chats.list`, the newest pin first.
  `raven chats pin|unpin NAME` or `--group GROUP`.

Pins and deleted chats are kept in `chat_prefs.json` in the profile, encrypted with the rest when
the privacy pack encrypts the profile.

### Node

- `node.start` is refused before the identity exists, and with `PROFILE_LOCKED` while `raven lock`
  holds the profile (Lock now v1; on every system, before raven-node is looked for or probed).
  raven-node listens on the network while the
  setting `receive` is on, where the CLI would start it for this profile (`RAVEN_SERVICE_LAN_LISTEN`
  when set, else every interface on the profile's own port: the one it picked when the random
  listen port is live, else `7420`), and on `127.0.0.1` (a free port) while it is off.
  `identity.create` makes the profile as `raven init` does, so a new profile picks its own port
  while that gate is live.
- `node.stop` never stops a login service (launchd, systemd, the scheduled task); on Windows it stops
  only a raven-node this app started. `stop` says what happened: `stopped`, `still_running`, `advice`
  (`note` says how to stop it by hand), `managed` (a login service runs it; left running),
  `not_running` or `failed` (`note` has the reason).

### Hand-off

`messages.handoff` is for the moment an app goes to the background (the iOS app does it before
`node.pause`; a desktop app may do it when it quits). It is `raven outbox hand-off` for every friend:
raven-node tries what waits once more and leaves sealed copies of what it could not deliver with
friends who hold mail now, instead of after the minute it otherwise waits (the kick keeps that so for
ten minutes). The engine then looks at raven-node's outbox until each message is held by a friend,
delivered, or has nobody who could take it (no friend the recipient told about or you listed for
them), or `budget_ms` is up (default 5000, from 500 to 20000; it looks at least 1.5 s, so a message
stored a moment before, such as a group copy just parked, counts too).

- A message counts when it waits on this device (queued, held back or parked) and no friend holds a
  copy of it yet. One already written to the friend's computer (`sent`) does not: it is there.
  Group copies count like any message. Which friends may take a copy is raven-node's rule, as always:
  the friends the recipient told about, or listed by hand for the recipient, verified and unblocked.
- `handed`: messages a friend took; `holders`: those friends, by your names for them; `left`: still
  only on this device (also those nobody could take); `delivered`: delivered meanwhile;
  `completed`: nothing is left.
- `custody: "off"` (friend custody held in this build): nothing is handed, `left` counts what waits.
  Without a running raven-node (or a paused one) the answer is `NODE_NOT_RUNNING`.
- Each message a friend took then reads `path_kind: "friend"` (or `"handoff"`) with `via_name`, and a
  `state` event tells the app.

### Embedded node (iOS)

On iOS (and on macOS or Linux with the engine's `embedded-node` feature and
`RAVEN_NODE_MODE=embedded`) raven-node runs inside the app's own process:
`node.start` and a send start it in process, its IPC is a socket pair per
connection instead of the socket file, and `node.stop` stops it in process.
`NodeStatus` then has `embedded: true`, `paused`, and `state` may be `paused`,
`mail_check` or `background`. `node.pause` stops it cleanly and holds it stopped (a
`node.start` meanwhile is refused, its detail starting with `PAUSED`) until `node.resume`. A send
whose turn comes meanwhile, or while Lock v2 holds the profile, is held back: it stays `sending`
with nothing dialled or written, and goes once `node.resume` (or the unlock) lets it. With `nearby: "keep"` (an app built with the
`bluetooth-central` and `bluetooth-peripheral` background modes) it then starts a small
background node (`state: background`, `paused: true`): IPC, the outbox, collecting from and
passing on for friends, and Bluetooth nearby, scanning only for the friends it names (iOS requires
that in the background); no listener, p2p or Tor. A `node.start` or a send meanwhile reaches that
node (no full node starts). The answer says `nearby: "kept"`, or `"stopped"` with a
`note` when that node did not start (the pause holds all the same). `node.resume` replaces it
with the full node. `mail.check` collects what friends hold for
this profile within `budget_ms` (default 25000, at most 28000), starting a
small node for it when none runs and stopping it again. On a running full
node (the app in the front) only its wait is bounded: the node's fetch goes
on, and what it brings later shows through `events.poll`. It is refused with
`PROFILE_LOCKED` while the profile is locked. Without the embedded node the
three answer `NOT_AVAILABLE_YET`, as does `network.path`: the app reports the kind of network
the device uses (`NWPathMonitor`), and with the setting `tor_wifi_only` on (`network.set`; off by
default, so Tor runs on mobile data too) the node keeps Tor off on mobile data
(`NetworkStatus.tor.phase` `off_mobile_data`). When the Tor network requires a protocol this Tor
lacks, Tor turns off until Raven is updated (`tor.phase` `too_old`, the words "Tor off: this
version is too old for the Tor network; update Raven"); the node and the app keep running.
Architecture, lifecycle and limits:
[`docs/IOS.md`](../../docs/IOS.md).

### Warm-ups (Tor, lab)

`contacts.warm` warms the Tor path to a verified friend before the user sends (speed design M3;
only while the warm gate is open, which no release build does): `why: "open"` when a chat with the
friend opens, `why: "typing"` when the user starts typing in it. A chat open probes the friend's
rendezvous circuit (the friend's Tor refuses the probe and its raven-node sees nothing); typing
opens an onion link with no message on it, which the send then rides. Nothing is sent early: the
message goes when the user sends it. The answer is `{warming: true}` once raven-node started the
warm-up, else `{warming: false, why}`, `why` one of `off` (the gate is shut), `soon` (the same
warm-up ran for that friend within its limit: a chat open once per 6 minutes, typing once per 20
seconds), `not_verified`, `blocked`, `paused` (`node.pause`), `mobile_data` (typing on mobile data
while the setting `typing_warm_on_mobile_data` is off, or Tor on Wi-Fi only), `tor_not_ready` (a
warm-up never waits for Tor or starts it), `no_tor_route` (no Tor address is known for the
friend), `node_off` (no raven-node answers, or on the iPhone only a mail check's node runs),
`old_node`, `locked` or `other`. It is refused with `PROFILE_LOCKED` while Lock v2 holds the
profile. The app needs to do nothing with the answer. Keeping a conversation's circuit warm for up
to an hour, and warming the chats going on after a resume, are raven-node's own (nothing to call).
A typing warm-up tells the friend's raven-node that you are online and probably writing to it
([`docs/THREAT_MODEL.md`](../../docs/THREAT_MODEL.md)).

### Network

Every way a Raven node reaches friends or helps them, as the terminal Raven has it
(`NETWORK_PARITY.md` lists them with the CLI commands and screens). The engine runs the CLI's own
commands on the same `node_policy.json` (and its sealed sidecar) the CLI reads, so a change made in
the app is what `raven status`, `raven doctor` and the terminal app show, and the other way round.

- **States.** Each way in `NetworkStatus.carriers` and `protections` has a `state`:
  - `on`: released and switched on;
  - `off`: available, switched off (`setting: false`);
  - `preview`: held in this build (its `*_PRODUCTION_ENABLED` gate is false). Show it with the
    Preview label; it can't be turned on;
  - `lab`: on only because a developer build's lab switch opened its gate (`lab: true`; a way that
    is off in a lab build reads `off` with `lab: true`);
  - `not_on_this_os`: this computer can't have it (Bluetooth nearby without a radio backend for
    this OS, or no Bluetooth LE).
  `reason` is one plain sentence; `detail`, where the CLI has a row for the way, is that row.
  `running` (when raven-node answers) says whether it uses the way now. A way the running
  raven-node uses while its saved `setting` is off (it was started with settings of its own) reads
  `on` (or `lab`), not `off`, and its `reason` says the saved setting differs. For Bluetooth nearby that
  is raven-node's own rule: switched on, the radio powered on, and an address that is not the
  adapter's fixed public one (a debug build's `RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR` allows that, as
  it does in raven-node). Windows reports its address as public (row N7w), so nearby there reads
  not running even with the radio on.
- **The Tor way** (`tor`; on in release builds since 2026-10, `ONION_PRODUCTION_ENABLED`; a debug
  build closes it with `RAVEN_LAB_TOR=0`, in the engine's process and in raven-node's). It has no switch
  (`can_set: false`, no `setting`): raven-node runs Tor by itself while its gate is open. Its state
  comes from raven-node's Status line (`Tor: starting (45 %)`, `Tor: ready`, `Tor: blocked on this
  network (why; retrying in 2 min)`, `Tor: could not start on this computer (why)`, `Tor: ready,
  onion service unreachable for 5 min (why; outage history)`), the same line `raven status` and the
  terminal app's Network screen show. While raven-node has that line: `running` is true once Tor is
  ready (`ready`, `publishing`, `unreachable`), `detail` is the line after `Tor: `, `reason` says
  the state in a plain sentence (with the gate open), and `NetworkStatus.tor` has its parts:
  `phase`, `words` (the line after `Tor: `), `percent` (how far Tor's start is, while `starting`,
  in release and debug engines alike), `why`, `retry` and `outages` (the
  onion service's outage history since raven-node started, when it had any). States only: the line
  holds no address, onion or IP, and the engine adds none. Without that line (gate closed, an
  older raven-node, none running) nothing is said of Tor's state: no `running`, no `detail`, no
  `tor`. Apps show it as a way card in the Tor path colour, with the phase (`network.tor.phase.*`),
  the why and the outage history (`network.tor.why`, `network.tor.outages`).
- **Gates, both directions.** A release engine reads no lab switch: every way whose gate is closed
  in the build is `preview`, `network.set` refuses to turn one on with `NOT_AVAILABLE_YET` (nothing is changed;
  `detail` names the gate) and `lab`, `lab_switches` are empty. A debug engine honours the
  `RAVEN_LAB_*` switches in its environment; the raven-node it starts inherits them and reads them
  again itself (a release raven-node ignores them). `NetworkStatus.lab_switches` and
  `NodeStatus.lab_switches` list the switches the engine sees (names only); `NodeStatus.lab` the
  ways they opened.
- **`network.set`** takes any of these (at least one), checks them all first, then applies them in
  this order with the CLI's commands:

  | setting | value | the CLI's command | applies |
  |---|---|---|---|
  | `lan` (+ `lan_for`: `30m`, `1h`, ... up to `24h`) | bool | `raven lan on [--for]` / `off` | now |
  | `internet` (+ `internet_listen`, default the saved one, else `0.0.0.0:7422`) | bool | `raven node internet on --listen` / `off` | restart |
  | `p2p` (+ `p2p_listen`, default the saved one, else `7423`; `relays`: multiaddrs or friends' names) | bool | `raven node p2p on --listen --relay` / `off` | restart |
  | `port_mapping` | bool | `raven node upnp on\|off` | restart |
  | `proxy` | `"auto"`, `"off"` or `"http://host:port"` (never a user name or password) | `raven node proxy` | restart |
  | `nearby` | bool | `raven nearby enable\|disable` | now |
  | `nearby_background_mail` | bool | `raven nearby background-mail on --yes` / `off` (never turns `nearby` itself on) | now |
  | `carry_for_friends` | bool | `raven node custody on --yes` / `off` | now |
  | `friends_carry_mine` | bool | `raven custody use on --yes` / `off` | now |
  | `handoff` | bool | `raven node custody handoff on\|off` | now |
  | `relay_for_friends` | bool | `raven relay offer on\|off` | now |
  | `bridge`, `store`, `relay` | bool | `raven node bridge\|store\|relay on\|off` (AUTO off) | now |
  | `hide_ip` | bool | `raven node hide-ip on\|off` | now |
  | `tor_wifi_only` | bool (default false: Tor on mobile data too) | none (the phone app's setting; `node_policy.json`) | now |

  Tor on mobile data has this one name: `tor_wifi_only: true` keeps Tor off while the app says the
  device is on mobile data (`network.path`), `false` (the default) runs it on Wi-Fi and mobile data
  alike. An app that sends the opposite spelling `tor_on_cellular` gets `BAD_REQUEST` (its detail
  names `tor_wifi_only`) and nothing changes. `NetworkStatus.tor_wifi_only` is the saved choice.

  Turning a held way on is `NOT_AVAILABLE_YET`; turning anything off is always allowed.
  `carry_for_friends`, `friends_carry_mine`, `handoff` and `nearby_background_mail` turned on need
  the person's yes to what they mean: show `NetworkStatus.texts.<setting>` first and pass
  `agreed: true`, else the answer is `CONSENT_NEEDED`. Each `Change` says in plain words what it
  does (`effect`); `restart_needed` is
  true when a running raven-node applies a change only when it starts again (the app may offer
  `node.stop` then `node.start`). A failure after some changes names them in `detail`.
- **One consent rule in all three apps.** A consent sheet comes before exactly the settings the
  engine answers with `CONSENT_NEEDED` without `agreed: true`: `carry_for_friends`,
  `friends_carry_mine`, `handoff` and `nearby_background_mail`, turned on. The sheet says what it
  does, what it costs (bandwidth, disk, being online), what others can see and what they can't
  (`network.consent.<setting>.*` in `strings.en.json`) and shows the engine's own words
  (`texts.<setting>`); `agreed: true` is sent only after the person confirms, and "Not now" sends
  nothing. No other setting gets a sheet: lending friends a relay (`relay_for_friends`) shows its
  cost beside its switch (`network.relayForFriends.effect`), and `bridge`, `store` and `relay` show
  their `help.effects` beside theirs, since those flags do little or nothing in today's raven-node
  (below). A `CONSENT_NEEDED` for a setting the app sent without a sheet (a newer engine) opens a
  sheet with the engine's words.
- **What the help-friends flags do** (`help.effects`, the honest words): `bridge` lets raven-node
  pass on sealed envelopes other devices hand it on its bridge listeners (the older mesh envelope
  path; a node the CLI or the app starts listens for them on this computer only); messages to
  friends don't use it. `store` and `relay` change nothing in this version of raven-node. Lending
  friends a relay is `relay_for_friends`; holding their mail is `carry_for_friends`.
- **`network.check`** is `raven doctor`'s summary (its rows in its order, already plain words) and
  its network lines as `CheckRow`s (`key`, `value`, and `plain` where Raven has a sentence for it);
  an indented line keeps the key of the line above it. `summary` and `next_step` are the app's
  words: no command, key or switch to type (the next step is said once, not again as a summary
  row); the CLI's own summary and next step are `technical`. Apps show the rows' `plain`
  sentences, and the rows' keys and values with `technical` only under "Technical details". `router: true` also runs `raven doctor
  --router`: a read-only question to this computer's router (PCP, NAT-PMP, UPnP) that maps nothing
  and stores nothing; it takes up to about 4 s. On macOS it may need the Local Network permission.
- **Contacts.** `contacts.routes` shows a friend's saved routes (LAN, Internet, p2p with its
  relays, and nearby for a verified friend), what the friend told this computer about reaching it
  (route hints: counts and its PeerId), whether this computer's IP is hidden from it, and who
  carries its mail: the mail friends it told about (`told`, with `takes_handoffs`), those you
  listed (`listed`, with `usable`), its offline delivery class (`coverage`), how long a message could
  wait for it (`away`) and where it is reached on the local network now (`lan_now`). Never the friend's
  security words or old code. `contacts.set_routes` sets an Internet or p2p route (`via`: its
  relays), clears routes (`clear`: `lan`, `internet`, `p2p`), lists mail friends by their address
  (`custodians`, at most two verified friends; `[]` clears them) and hides this computer's IP from
  one friend (`hide_ip`); every value is checked before anything is saved.
- **Security, Lock and updates.** `security.status` is `raven security` as the terminal app's SEC
  screen reads it (never creates the ledger). A notice's `id` is its own number, the one `raven
  security` shows and `raven security explain N` / `resolve N` take (its ledger row: it stays the
  same while the notice is open, whatever else is noted or resolved). `lock.*` is Lock v2 where the running raven-node
  serves it: `lock.now` keeps raven-node running without its keys, `lock.unlock` opens it (with the
  Raven passphrase when the profile has one; the passphrase goes only to raven-node). Where the node
  does not serve it (no node, an older one, the gate shut) both answer `NOT_AVAILABLE_YET`, their
  `detail` naming `raven lock` / `raven unlock`. The one exception is the app's own node
  (embedded, docs/IOS.md) while it is stopped or paused, with the gate live: `lock.now` then holds the lock in the process
  (the engine and the node load no key), and the next `node.start` or `node.resume` starts the node
  locked, a keychain profile too: the iPhone app's launch while it says asleep calls `lock.now`
  first. `lock.unlock` with that node still stopped or paused ends the pause and starts it
  (locked) first, then opens it, so the wake after Face ID needs no `node.start` of its own.
  `updates.status` is `raven update status`; installing stays in the
  CLI (`raven update install`), and `install_text` says that the app doesn't install, without the
  command.
- **While Lock v2 holds the profile** the engine holds no key either. It learns of a lock from
  `lock.now`, `lock.state`, `profile.state` and the node's own status (the watcher's beat, a
  `node.*` op), so a lock made elsewhere (`raven lock`, the terminal app, a wake from sleep) counts
  too, and the same for an unlock. At the lock it lets go of the identity, the keys this process
  loaded (a sealed profile's at-rest key, a vault's derived key), its cached history, contacts and
  read markers, and every event not read yet. Until the unlock: `profile.state` is `locked` with
  `lock_v2: true` and loads nothing; `events.poll` answers `{seq, events: [], reset: false, locked:
  true}` and nothing is queued (no message text waits in the engine); `lock.state`, `lock.now`,
  `lock.unlock`, `lock.passphrase_state`, `node.status`, `node.start`, `node.stop`, `node.pause` and
  `node.resume` run (a node started then follows raven-node's rule: a passphrase profile's starts
  locked, an embedded node stays locked across a pause and after a `lock.now` made while it was
  stopped, a keychain profile's new raven-node process starts unlocked); every other op that reads the profile, `lock.set_passphrase` and
  `lock.remove_passphrase` included, is `PROFILE_LOCKED`. After the unlock the identity loads again
  and the first `events.poll` says `reset: true`: reload what the window shows. A profile with a
  Raven passphrase whose keys this engine's process cannot open yet (no passphrase file, and no
  unlock with the passphrase in this process) counts as locked the same way, whatever raven-node
  says: `lock.unlock {passphrase}` opens it, and for a raven-node program it also checks the
  passphrase against the vault in the engine's own process (`PASSPHRASE_NEEDED` without one,
  `PASSPHRASE_WRONG` for a wrong one). With the gate shut (every release build so far) none of this
  happens.
- **The Raven passphrase.** `lock.passphrase_state` says what `raven passphrase` offers this
  profile (it answers with the gate shut too: `available: false`, `offer: "none"`).
  `lock.set_passphrase {new}` sets one (macOS and iOS: the keys move from the keychain, the login
  keychain on macOS and the app's data-protection keychain on iOS, into a passphrase vault; it also
  finishes a switch that stopped halfway, with the passphrase that switch was started with),
  `lock.set_passphrase {new, old}` changes it (macOS, iOS, and GNU/Linux vault profiles),
  `lock.remove_passphrase {old}` removes it (macOS and iOS: the keys go back into the keychain). raven-node is held locked while the keys move and unlocked after; a node that already
  runs locked is refused (`PROFILE_LOCKED`: unlock first). The passphrases go in these fields only,
  are checked by raven-core's own rules (the CLI's), are never returned, logged or kept, and are
  wiped once used. Refusals: the gate shut is `NOT_AVAILABLE_YET` naming `raven passphrase` (as
  `lock.now` names `raven lock`); a system or profile where a Raven passphrase does not apply
  (Windows, a desktop-keyring profile, the lab's file backends) is
  `NOT_ON_THIS_SYSTEM` with raven-core's words; a wrong `old` is `PASSPHRASE_WRONG`; a `new` that
  breaks a rule, or an op this profile does not offer now (a set where one is set, a remove without
  one), is `BAD_REQUEST` with the reason in `message`. A forgotten Raven passphrase cannot be
  recovered: the apps say so before a set.

### Bluetooth nearby

The terminal Raven's `raven nearby` in the app (Task 2; `docs/NEARBY.md`). `network.set {nearby}`
turns it on or off and `network.set {nearby_background_mail}` (its own consent) lets it advertise
while mail waits; `network.status.nearby` keeps its summary. The nearby ops:

- **`nearby.status`**: `NearbyStatus`, what `raven nearby status` shows, read from the running
  raven-node (counts and states only), with the texts the app shows.
- **`nearby.contact {address, advertise, for_min?}`**: advertise for one verified friend now
  (`raven nearby on <friend> [--for 30m]`), for `for_min` minutes (30 to 1440) or until asked to stop
  (or raven-node restarts); `advertise: false` stops it (`raven nearby off <friend>`). A friend who
  is not verified is `NEARBY_BAD_REQUEST`; an unknown address `NOT_A_CONTACT`. A send already
  tells raven-node that you work with that friend (and with the friends who could carry their
  mail): no op is needed for that.
- **`nearby.stop_all`**: `raven nearby off` with no friend.
- **`nearby.permission`** (iPhone and iPad): the app's Bluetooth permission, read without a
  prompt, so the app can explain before iOS asks (iOS asks once, after `network.set {nearby:
  true}`); elsewhere, and in an app build without `NSBluetoothAlwaysUsageDescription` (nothing is
  read then), `NOT_ON_THIS_SYSTEM`.

While this build holds nearby (`network.status` way `nearby` `preview`) `nearby.contact` and
`nearby.stop_all` answer `NOT_AVAILABLE_YET` and change nothing; `nearby.status` says `held`.
Without a running raven-node they answer `NODE_NOT_RUNNING`; raven-node's own refusals keep its
codes: `NEARBY_NOT_RUNNING` (nearby is off, or has no radio), `NEARBY_BAD_REQUEST`,
`NEARBY_POLICY` (its setting could not be saved). On iOS the radio runs in the app's own process
(no helper): an app without `NSBluetoothAlwaysUsageDescription` reads radio
`helper_unavailable` and never crashes; the iOS Simulator has no Bluetooth (`unsupported`).

### Types

```text
Contact   { address, name, short_address, verified: bool, blocked: bool, pinned: bool, hidden: bool,
            presence: "in_touch" | "waiting" | "none" | "no_address",
            last_contact_ms?, waiting: {count, until_ms}?, avatar_index: 0..4, lan?: "ip:port",
            unread }
            waiting.until_ms is 0 when not known (raven-node not running).
            last_contact_ms: the newest message from the friend or of yours they confirmed (the
            history counts, also from before the app started); in_touch while that, or a message or
            receipt this run saw, is under 15 minutes old.
            unread: the friend's messages after the one last read here or in the terminal app
            (see "Read and unread").
            pinned: the chat is pinned (chat controls); hidden: the chat was deleted from the
            chat list and no message came since. A Group has both too.
Chat      { kind: "contact" | "group", address? (kind contact), group? (kind group), name,
            pinned: bool, last_ms (0 without a message), unread }
Message   { id, address, direction: "in" | "out", text, at_ms,
            state: "sending" | "sent" | "delivered" | "waiting" | "time_ran_out" | "not_sent_meet_first" | "failed",
            until_ms?, path?, path_kind?, via_name?, delivered_at_ms?, attempts? }
            path_kind and its path words (every label raven-node can report):
              lan "LAN direct" · internet "Internet direct" · p2p "p2p" (path not known) ·
              p2p_direct "p2p · direct" · p2p_reversed "p2p · reversed" · p2p_relayed "p2p · relayed" ·
              p2p_hole_punched "p2p · hole punched" ·
              websocket "p2p · relayed over WebSocket" (relayed while every relay in use runs over
                WebSocket/TLS) ·
              nearby "Bluetooth nearby" ·
              onion "via Tor" (the friend's Tor onion service; on in release builds since 2026-10-29) ·
              friend "Held by a friend" (friend custody; said while it waits too) ·
              handoff "Passed on between friends" (multi-hop custody) ·
              letter "Sealed letter with a friend".
            via_name: a message of yours a friend holds (path_kind friend or handoff): that friend,
            by your name for them (the first of them when several hold it). raven-node's outbox
            lists such a message as written (it left this device), so its state is `sent` while
            the friend holds it, not `waiting`. The name is kept with the message for the rest of
            the run, so its delivery still says it; it is never written down: after a restart a
            delivered message says only "Held by a friend" (which friends held a message is not
            kept once it is done).
            A delivery raven-node's outbox made takes raven-node's last path to the friend. The path
            of each delivered message of yours is kept in `desktop_private.rms` (by history id), so
            it comes back after a restart.
            until_ms (waiting): when it runs out for good, the time raven-node's outbox applies: its
            envelope's expiry, or, while the long message horizon is live (on in release builds), 7 days
            after it was written (an envelope that runs out first only parks it).
            delivered_at_ms: when its receipt came, only for a delivery more than a minute after it
            was written (the apps then say "Delivered 15:10"); kept with the path.
NodeStatus{ running: bool, started_by_app: bool, pid?, listening?: "0.0.0.0:7420" | "127.0.0.1:...",
            receive: bool, address?: "ip", last_ok_ms, build: "release" | "dev",
            state: "listening" | "local_only" | "send_only" | "not_running" | "not_answering" | "starting",
            not_receiving?: "addr_not_here" | "port_in_use" | "lan_off",
            lab: [way id ...], lab_switches: ["RAVEN_LAB_..." ...],
            carriers: { lan: "on", internet: "preview" | "on", p2p: "preview" | "on", custody: "preview" | "on",
                        nearby: "preview" | "on" } }
            started_by_app: only for the raven-node process this engine started.
            not_receiving: why a running raven-node does not receive (send_only), when Raven can
            tell: its address is no longer on this computer, another program has its port, or
            `raven lan off`.
            lab: the ways (NetworkStatus ids) a developer build's lab switch turned on, and
            lab_switches the RAVEN_LAB_* variables this engine sees (both always empty in a release).
            carriers: whether each is released in this build (NetworkStatus has the full state).
Settings  { display_name?, receive: bool, reduced_motion: bool, when_quit: "keep" | "stop_if_started" | "ask",
            keep_chats_days?: 7 | 30 | 90 | null, forget_addresses: bool, lock_on_sleep: bool,
            typing_warm_on_mobile_data: bool }
            typing_warm_on_mobile_data: may a typing warm-up (contacts.warm) use mobile data; until
            set, true on the desktop and false on the iPhone (the iOS app reports the network with
            network.path).
            keep_chats_days is the privacy pack's chat-keeping time, which it enforces.
            forget_addresses is always true: Raven forgets a friend's address after 30 days without
            contact (setting it false is NOT_AVAILABLE_YET). lock_on_sleep is stored and reported;
            it takes effect when the apps offer Lock.
NetworkStatus { build: "release" | "dev", node: "running" | "not_running",
            carriers: [Carrier], protections: [Carrier],
            listening: ["ip:port" ...], port, internet_listen?, p2p_listen?, p2p_addresses?: [multiaddr],
            (port: the port the running raven-node's LAN listener uses; while none answers, the
             profile's own port),
            lan_until_ms?, policy_unreadable?: true,
            port_mapping: { setting: "on" | "off" | "unset", router: raven-node's word ("off", "mapped 7423",
                            "failed", ...), nat_pmp_pcp: "on" | "lab" | "preview", v4?, v4_port?, v6? },
            relays: [{ relay, state, source: "manual" | "offer", friend_address? }],
            proxy: { setting: "auto" | "off" | "http://host:port", in_use, lines: [..] },
            nearby: { state: "held" | "node_held" | "not_running" | "live", saved, on_this_os,
                      enabled?, radio?, address_privacy?, in_range?, connected?, rows: [{label, value}] },
            carry: { friends_carry_mine: { setting: "on" | "off" | "not_decided", mail_friends,
                                           names: [name], chosen_by_hand, offering,
                                           offering_over_internet, offering_reachable,
                                           listed_by_hand },
                     carry_for_friends: { on, held_messages, held_bytes, handoff, handoff_lines },
                     letters_left: [..], relay_for_friends: { setting, offering, offered_to } },
            help: { bridge, store, relay, automatic, effects: { bridge, store, relay } },
            hide_ip, tor_wifi_only, path?: "wifi" | "wired" | "cellular" | "other" | "offline",
            (carry.friends_carry_mine.names: every friend a mail check asks for your mail, by your
             names for them: your mail friends, friends you listed for a contact, and friends a
             contact said it leaves your mail with; mail_friends counts only your mail friends.
             tor_wifi_only: see network.set; path: what the phone app last reported)
            lab_switches: [..],
            texts: { carry_for_friends, friends_carry_mine, handoff, nearby_background_mail },
            tor?: { phase: "ready" | "publishing" | "unreachable" | "starting" | "restarting" | "blocked"
                           | "could_not_start" | "not_built" | "off" | "too_old" | "off_mobile_data"
                           | "unknown",
                    words, percent?, why?, retry?, outages? } }
            (tor: raven-node's Tor line, read into its parts; only while raven-node's Status has
             that line: see "The Tor way")
            Carrier ids: lan, lan_beacon, internet, port_mapping, p2p, friend_relay, websocket, proxy,
            custody, letters, handoff, route_hints, nearby, tor. Protection ids: random_port,
            link_knock, link_padding, lock_v2, security_events, updates_from_friends.
NearbyStatus { state: "held" | "node_held" | "not_running" | "live", enabled, background_mail,
            radio: "powered_on" | "off" | "unauthorized" | "unsupported" | "no_backend"
                   | "helper_unavailable" | "service_down" | "local_state",
            permission?: "not_determined" | "restricted" | "denied" | "allowed",
            roles: ["central", "peripheral"], address_privacy: "random" | "public" | "unknown",
            advertising: bool, rotating: 0..2, in_range, connected,
            frames_tx, frames_rx, bytes_tx, bytes_rx, knock_silenced,
            background: "foreground_only" | "background",
            advertising_for: [{ address, name, until_ms? }],
            rows: [{ label, value }],
            texts: { nearby, nearby_background_mail, background?, after_swipe? } }
            (state as NetworkStatus.nearby; the counts and states are raven-node's, never a key,
             token or Bluetooth address. permission: iPhone and iPad only. background: whether
             nearby keeps working while the app is in the background: always on a desktop, on
             iOS only after node.pause {nearby: "keep"}. advertising_for: only the friends this
             app asked nearby.contact to advertise for, by your names for them, while their time
             runs (raven-node forgets them when it restarts); a friend's advert chosen by the
             outbox or background mail is not listed. rows: `raven nearby status`'s rows; on
             iOS in the iPhone's words (this iPhone, iOS's Settings, no command). texts: the
             consent shown before network.set {nearby: true} and before nearby_background_mail
             (on iOS both in the iPhone's words; neither names a `raven` command, and
             NetworkStatus.texts.nearby_background_mail is the same text); on iOS the
             background row and the words after the app was swiped away)
Carrier   { id, name, state: "on" | "off" | "preview" | "lab" | "not_on_this_os", reason,
            lab: bool, gate: "<NAME>_PRODUCTION_ENABLED", lab_switches: ["RAVEN_LAB_..."],
            can_set: bool, setting?: bool, running?: bool, detail? }
Change    { setting, value, effect, applies: "now" | "restart", detail: [the CLI's lines] }
CheckRow  { key, value, plain? }
ContactRoutes { address, verified, hide_ip,
            routes: [{ kind: "lan" | "internet" | "p2p" | "nearby", label, value, via?, next?,
                       state: "on" | "off" | "preview" | "lab" | "not_on_this_os" }],
            (a route's state is its way's state in network.status, so every screen says the same)
            learned?: { relays, direct, mail_friends, peer_id?, peer_id_proven, lan_port?, expires_at_ms },
            lan_now?: { addr: "ip:port", at_ms, saved_stale: bool },
            carriers: { hints: "on" | "off" | "preview" | "lab",
                        told: [{ address, name?, takes_handoffs }], told_unknown,
                        listed: [{ address, name?, usable }],
                        coverage?: { kind: "direct" | "mutual_friend" | "two_friends" | "none", name, until },
                        away?: { until_ms } | { meet_first: true, first_message?: true },
                        receipts_stranded } }
            lan_now: where Raven reaches the friend on the local network now, and when that was seen:
            this run's last delivery there, or where the friend last reached this computer from
            (raven-node's sighting, on the saved address's port), whichever came later.
            saved_stale: the saved LAN address is another one; `contacts.set_address` with `addr`
            replaces it.
            away: how long a message written now could wait while the friend is away, by the rule
            `raven contact list` and the terminal app use (until_ms; with the long message horizon
            live 7 days from now), or that none can (meet_first). first_message: none can because
            Raven hasn't connected with the friend yet, so a first message needs you both online
            (apps say that, as the terminal app does, not meet first); without it the last secure
            connection ended (meet first). meet_first stays set with first_message, so an app that
            knows only meet_first keeps its line. Absent for a blocked friend.
            coverage: how friends can carry it (the CLI's words); apps show it for mutual_friend and
            two_friends, beside `away`.
SecurityStatus { available, lab, kept: "off" | "unsealed" | "live", counted,
            notices: [{ id, level: "alert" | "warning", address?, name, headline, what_raven_did,
                        what_to_do, when, details: [{label, value}] }],
            node?: { strangers_refused_1h, failed_handshakes_1h, bans_active,
                     link_tag_failures_24h, alerts_open } }
LockState { available (this build has Lock v2), lab, supported (the running raven-node serves it),
            locked, has_passphrase? }
            locked: raven-node is locked, or this engine is (a passphrase profile whose keys it
            cannot open yet: "While Lock v2 holds the profile").
PassphraseState { available (this build has Lock v2), lab,
            offer: "set" | "change_or_remove" | "change" | "none",
            why?: "not_in_this_version" | "not_on_this_system" | "keyring_profile" | "lab_files",
            unfinished: bool, has_passphrase?, lines: [..] }
            offer: what this profile can do (change: a GNU/Linux vault profile, which keeps its
            passphrase); why: with offer none. unfinished: a switch of the keys to or from the vault
            stopped halfway (offer change_or_remove; a set with the passphrase it was started with,
            or a remove, finishes it). lines: what the profile has and can do, in plain words.
            Never a passphrase.
UpdatesStatus { available, bundles, from_friends, lab, lines: [..], summary?, offer?: [..],
            install: "cli_only", install_text }
Group     { id, name, short_id, status: "active" | "left" | "removed", admin: bool (you are the admin),
            admin_address, admin_name, members: n, unread, last_ms?, last_text?, last_from?,
            last_from_friend? }
            last_from: the newest message's author (a name; "You" for yours); last_text its text;
            last_from_friend: whether last_from is a name you chose (yours, a friend's); false: the
            admin's label, shown with "not your friend" (see Groups, Authors).
GroupMember { address, short_address, name, label, friend: bool, admin: bool, me: bool }
GroupMessage { id, group, from_address, from_name, from_friend: bool, mine: bool, text, at_ms,
            via_name? (the member that passed it on, when it was not its author),
            path_kind?, path? (a member's message: how the copy that brought it came, the kinds and
                               words of Message.path_kind; friend when a friend held it),
            delivered: n, total: n,
            receipts: [{ address, name, state: "waiting" | "sent" | "delivered" | "failed",
                         via: "direct" | "relay", held_by? }] }   (receipts only on yours)
            from_friend: true for yours and a friend's; false: from_name is the admin's label (or
            "a former member (1a2b3c4d)"), shown with "not your friend" (see Groups, Authors).
            held_by: the friend that holds the copy for that member while the member is away, by
            your name for them, until it is delivered or given up (its state is then `waiting` or
            `sent`, as raven-node's outbox lists it).
```

### Events

`events.poll {after_seq}` returns the events after `after_seq` and the newest `seq` (pass it as the
next `after_seq`; start with 0). The engine keeps a bounded queue (512 events; heartbeats replace each
other). **`reset: true`** means events after `after_seq` were lost (dropped for room, or `after_seq` is
from before this engine started): reload what the window shows (contacts, the open chat, node status)
instead of trusting the events, then keep polling from the returned `seq`. The engine watches
raven-node from the first poll on (about once a second) and stops watching after 30 s without a poll;
its first look only notes what is there, so old messages do not arrive as `incoming`. While Lock v2
holds the profile the queue is empty and nothing is added: a poll answers no events and `locked:
true`, and the first poll after the unlock says `reset: true` ("Security, Lock and updates").

`events.wait {after_seq, timeout_ms?}` answers exactly as `events.poll`, but while there is nothing
new after `after_seq` it waits for the next event, lock or unlock, up to `timeout_ms` (at most 25000,
the default; more is refused with `BAD_REQUEST`), and answers within a few milliseconds of it: a
receipt shows at once instead of at the next poll. With nothing in that time it answers no events,
as a poll would have. Events already there, `reset` and `locked` are answered at once, so an app
that waits in a loop goes back to its poll pace while `locked` holds. It keeps the watcher running,
as a poll does (a wait again right after its answer is soon enough). Only the calling thread waits:
call it off the UI thread.

```text
Event     { seq, kind, at_ms, ... } kinds:
            "status_ok"            heartbeat: a successful status check            -> heartbeat pulse
            "send_started"  {id}    a send attempt began                           -> packet travels out
            "receipt"       {id, address?, path, path_kind, ms, delivered_at_ms?, via_name?}  signed receipt arrived
                                       -> receipt travels back, Delivered (delivered_at_ms as on Message)
            "incoming"      {message}                                              -> packet travels in, bubble slides in
            "outgoing"      {message}  yours, sent by another program on this profile (the
                                       terminal app, the CLI) after the first look  -> bubble appears
                                       in the open chat (its path once delivered; a receipt follows)
            "retry"         {id, address, attempts}                                -> retry ring on the friend's dot
            "presence"      {address, presence}                                    -> dot changes (blink)
            "state"         {id, address?, state, until_ms?, path?, path_kind?, via_name?}  -> tick text changes
                            (also sent when a waiting message's until_ms becomes known or changes,
                             and when a friend takes a copy of it: via_name)
            "node"          {status}                                               -> header/menu-bar chip changes
            "unread"        {address, unread}  the friend's count changed (a message came, or the
                                       chat was read here or in the terminal app) -> badge follows
            "group_message" {group, message: GroupMessage}  a member's message came (after the
                                       first look)                                -> bubble in the group chat
            "group_changed" {group}  the group's members, status, unread count or a receipt changed
                                       (also a group that appeared, and one forgotten: groups.get is
                                       then GROUP_NOT_FOUND, drop it)             -> reload it (groups.get,
                                       and groups.history when it is open)
```

A `receipt` comes only after Raven verified the friend's signed receipt, and always before the
`state: delivered` of the same message. Animations are driven by these events only (see
`../design/DESIGN.md`, "Honest motion"). An app may never animate delivery before a `receipt` event.

## Error codes (first set)

`NOT_INITIALIZED`, `PROFILE_UNREADABLE`, `PROFILE_LOCKED`, `KEYCHAIN_DENIED`, `NODE_NOT_RUNNING`,
`NOT_A_CONTACT`, `CONTACT_BLOCKED`, `NAME_CLASH`, `CARD_INVALID`, `WORDS_INCOMPLETE`, `MESSAGE_TOO_LONG`,
`NOT_AVAILABLE_YET`, `BAD_REQUEST` (unknown op or bad arguments), `INTERNAL`, and for the network ops
`CONSENT_NEEDED` (`network.set` needs `agreed: true`), `PASSPHRASE_WRONG`, `PASSPHRASE_NEEDED` and
`UNLOCK_WAIT` (`lock.unlock`; `PASSPHRASE_WRONG` also for a wrong `old` of the passphrase ops), and
`NOT_ON_THIS_SYSTEM` (`lock.set_passphrase` / `lock.remove_passphrase` where a Raven passphrase does
not apply, and `nearby.permission` outside iOS), and for the nearby ops `NEARBY_NOT_RUNNING`,
`NEARBY_BAD_REQUEST` and `NEARBY_POLICY` (see "Bluetooth nearby"). Each comes with a
plain-English `message` that names one next step, never a terminal command (no app installs
`raven`); the technical text, with the CLI's command where one helps, goes in `detail`.

Groups add `GROUP_NOT_FOUND`, `GROUP_NOT_ADMIN` (only the admin adds and removes),
`GROUP_NOT_MEMBER` (you left or were removed), `GROUP_TOO_LARGE` (more than 16 members, or 64
groups: forget one you left), `GROUP_STILL_MEMBER` (only a group you left or were removed from can
be forgotten), `GROUP_ADMIN_CANNOT_LEAVE`, `GROUP_ALREADY_MEMBER`, `GROUP_BAD_NAME`, `GROUP_QUEUE_FULL` (too many group
copies still wait; try again once some are delivered; or you sent your share of a group's messages
within 7 days, see Receipts) and `GROUP_NO_ROUTE` (none of the other members
is your friend); a member who is not a friend is `NOT_A_CONTACT`, a message over 8,192 bytes
`MESSAGE_TOO_LONG`.

- "Not sent, meet first" and "time ran out" are message states (`not_sent_meet_first`,
  `time_ran_out`), not errors: no operation returns them as error codes.
- `CONTACT_BLOCKED`: the message says to unblock the friend first (`contacts.unblock`).
- `NAME_CLASH` also covers a name that only looks like a verified friend's name.

## Mocks

Every app also has a `MockRaven` that implements this contract in memory with the demo friends Ali
(verified, in touch), Mina (one waiting message) and Rena (not verified), and replays the demo events
of the design mockups. The mocks have no groups and no `nearby.*` ops yet (no app has group or
nearby screens yet; a mock that adds them follows "Groups" and "Bluetooth nearby" above). Its network answers are a release build's from before 2026-10-29: LAN direct on, every other way
`preview` (Bluetooth nearby `not_on_this_os` where the OS has no backend), `network.set` refusing to
turn a held way on with `NOT_AVAILABLE_YET` and keeping the bridge/store/relay flags, LAN and hide
IP it was given; Ali's routes are a LAN address, Mina's none; no security notice; Lock v2 and
updates not in this version. Mocks are for demos, snapshots and tests: they are compiled only into debug
builds (or a demo build), and an app runs on its mock only when a demo switch asks for it. A release
build always uses `raven-client`. Each app's README names its switch.
