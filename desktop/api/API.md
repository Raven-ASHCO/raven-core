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
  window is open and every 5 s in the menu bar or tray).
- Secrets never cross the boundary. The engine refuses to put fields named like `seed`,
  `private_key`, `secret`, `plaintext` or `recovery` in a response (the same rule as raven-node's IPC).
- All text returned for display is already sanitised (control characters, bidi overrides and
  zero-width characters removed), so a friend's name or message cannot draw over the UI.
- `raven_call` is thread-safe and may block (`node.start` can take a few seconds), so apps call it
  off the UI thread and post the result back. `events.poll` never blocks.

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
  did not finish is refused (`PROFILE_UNREADABLE`, the message names the command that finishes it)
  and nothing is written. The profile's at-rest key is loaded (a sealed profile can't be read
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
| `profile.state` | – | `{state: "new" \| "ready" \| "locked" \| "unreadable", reason?, detail?}` (`locked`: `raven lock` stopped Raven; `unreadable` also while an erase or key change is unfinished, or while the keychain does not give the key of an encrypted profile) |
| `identity.create` | `{display_name?}` | `{address, words: [10], old_code, note?}` (`note`: a problem that did not stop setup, e.g. the first prekey) |
| `identity.me` | – | `{display_name?, address, words: [10], old_code, card, invite}` |
| `card.make` | `{include_address: bool}` | `{card, invite, address_included?: "ip:port", address_missing?: "not_receiving" \| "this_computer_only" \| "no_network"}` |
| `card.parse` | `{text}` | `{short_address, has_address, routes: [{kind, label, preview: bool}], address, already_saved: bool, already_verified: bool, ignored_routes: [kind], note: string\|null}` (never returns the friend's security words or old code). `ignored_routes`: the route kinds (`internet`, `p2p`) the card named that were left out, because no key signs a card's addresses and release builds never read them; `note` is the one line to show about it, `null` when nothing was left out |
| `contacts.list` | – | `{contacts: [Contact]}` |
| `contacts.add` | `{text, name}` | `{contact: Contact}` (saved as not verified) |
| `contacts.rename` | `{address, name}` | `{contact}` |
| `contacts.remove` | `{address}` | `{}` |
| `contacts.set_address` | `{address, lan: "ip:port"}` | `{contact}` |
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
| `node.status` | – | `NodeStatus` |
| `node.start` | – | `NodeStatus` |
| `node.stop` | – | `NodeStatus` + `{stop, note?}` (see below) |
| `settings.get` | – | `Settings` |
| `settings.set` | `{...partial Settings}` | `Settings` |
| `events.poll` | `{after_seq}` | `{seq, events: [Event], reset: bool}` (see Events) |
| `privacy.state` | – | `{available: bool, encrypted: bool, locked: bool}` (`encrypted`: the privacy pack encrypts this profile; `locked`: `raven lock` stopped Raven; `available` is false until the apps offer the privacy actions, which they then show with the Preview label) |
| `privacy.lock` / `privacy.unlock` | – | `{state}` (`unlock` clears a `raven lock` and answers as `profile.state`) |
| `privacy.encrypt` | – | `{state}` (encrypts everything Raven stores on this computer) |
| `privacy.erase` | `{confirm: "erase"}` | `{}` (removes Raven's data from this computer; afterwards `profile.state` is `new`) |
| `network.status` | – | `NetworkStatus` (every way to reach friends; see Network) |
| `network.set` | `{...settings, agreed?}` | `{changes: [Change], restart_needed: bool, status: NetworkStatus}` |
| `network.check` | `{router?: bool}` | `{summary: [{key, label, value}], next_step, rows: [CheckRow], router?: [CheckRow], technical: [line]}` |
| `contacts.routes` | `{address}` | `ContactRoutes` |
| `contacts.set_routes` | `{address, internet?, p2p?, via?: [..], clear?: [..], custodians?: [address], hide_ip?}` | `{contact: Contact, routes: ContactRoutes}` |
| `security.status` | – | `SecurityStatus` (`raven security`, read-only) |
| `lock.state` | – | `LockState` |
| `lock.now` | – | `LockState` (Lock v2: raven-node keeps running and forgets its keys) |
| `lock.unlock` | `{passphrase?}` | `LockState` + `{note?}` |
| `updates.status` | – | `UpdatesStatus` (`raven update status`, read-only; installing stays in the CLI) |
| `groups.list` | – | `{available: bool, groups: [Group]}` (see Groups) |
| `groups.get` | `{group}` | `{group: Group, members: [GroupMember]}` |
| `groups.create` | `{name, members: [address]}` | `{group: Group, members: [GroupMember]}` (you are its admin) |
| `groups.add` | `{group, members: [address]}` | `{group, members}` (admin only) |
| `groups.remove` | `{group, member: address}` | `{group, members}` (admin only) |
| `groups.leave` | `{group}` | `{group}` (not the admin) |
| `groups.history` | `{group, before?: id, limit?}` | `{messages: [GroupMessage]}` (oldest first; `limit` default 100, at most 500) |
| `groups.send` | `{group, text}` | `{message: GroupMessage, note?}` (returns at once; raven-node delivers each copy, started first when none runs; `note`: why it could not be asked to now, the copies wait) |
| `groups.mark_read` | `{group}` | `{group: id, unread: 0}` |

Until the apps offer them, `privacy.lock`, `privacy.encrypt` and `privacy.erase` return the error
`NOT_AVAILABLE_YET` (the message names the CLI command: `raven lock`, `raven privacy seal-now`,
`raven erase`) and change nothing. `privacy.unlock` is the Locked screen's Unlock: it clears the lock
as `raven unlock` first does, and never touches Raven's login item.

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
custody, the 7-day wait); members who are not your friends get it passed on by another member. Lab
only: `groups.list` says `available: false` in a release build (the apps then show no Groups
section), and every other `groups.*` op is `NOT_AVAILABLE_YET` there; in a debug build the switches
`RAVEN_LAB_TEST_A=1 RAVEN_LAB_HORIZON=1 RAVEN_LAB_GROUPS=1` turn it on (for the engine and for
raven-node).

- **Ids.** `group` is the group's id (32 hex characters, opaque to the apps); a message `id` is its
  group message id. Members are named by their Raven `address`.
- **Members.** A group has at most 16 members, you included, and one admin (its creator) who alone
  adds and removes; the admin can't leave. Only your friends (`contacts.list`, not blocked) can be
  added. Joining is automatic: a group a friend adds you to appears in `groups.list` (with a
  `group_changed` event); you can leave it.
- **Names.** `GroupMember.name` is your name for a member who is your friend, else the name the
  admin gave them (`label`); `friend: false` members are shown as "not your friend" and are never
  added to your friends by the group. You are `me: true` (name: your display name, else "You").
- **Receipts.** Each message of yours lists one `receipts` entry per member it was for:
  `waiting` (still on this computer, or passed on by another member and not confirmed yet), `sent`
  (left this computer, no receipt yet), `delivered` (that member's Raven confirmed it: a signed
  receipt) or `failed` (given up). `delivered`/`total` give "Delivered to 3 of 5". `via: "relay"`
  marks a member reached through another member.
- **Leaving and removal.** `status` is `left` after `groups.leave` and `removed` when the admin
  removed you: the history stays, `groups.send` is `GROUP_NOT_MEMBER`.
- **Read and unread.** `Group.unread` counts others' messages received after the group was last read
  on this computer (`groups.mark_read`, or `raven group show`). Local only.

### Node

- `node.start` is refused before the identity exists. raven-node listens on the network while the
  setting `receive` is on, where the CLI would start it for this profile (`RAVEN_SERVICE_LAN_LISTEN`
  when set, else every interface on the profile's own port: the one it picked when the random
  listen port is live, else `7420`), and on `127.0.0.1` (a free port) while it is off.
  `identity.create` makes the profile as `raven init` does, so a new profile picks its own port
  while that gate is live.
- `node.stop` never stops a login service (launchd, systemd, the scheduled task); on Windows it stops
  only a raven-node this app started. `stop` says what happened: `stopped`, `still_running`, `advice`
  (`note` says how to stop it by hand), `managed` (a login service runs it; left running),
  `not_running` or `failed` (`note` has the reason).

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
- **The Tor way** (`tor`, lab: `ONION_PRODUCTION_ENABLED` is false; a debug build opens it with
  `RAVEN_LAB_TEST_A=1 RAVEN_LAB_TOR=1`, in the engine's process and in raven-node's). It has no switch
  (`can_set: false`, no `setting`): raven-node runs Tor by itself while its gate is open. Its state
  comes from raven-node's Status line (`Tor: starting (45 %)`, `Tor: ready`, `Tor: blocked on this
  network (why; retrying in 2 min)`, `Tor: could not start on this computer (why)`, `Tor: ready,
  onion service unreachable for 5 min (why; outage history)`), the same line `raven status` and the
  terminal app's Network screen show. While raven-node has that line: `running` is true once Tor is
  ready (`ready`, `publishing`, `unreachable`), `detail` is the line after `Tor: `, `reason` says
  the state in a plain sentence (with the gate open), and `NetworkStatus.tor` has its parts:
  `phase`, `words` (the line after `Tor: `), `percent` (starting), `why`, `retry` and `outages` (the
  onion service's outage history since raven-node started, when it had any). States only: the line
  holds no address, onion or IP, and the engine adds none. Without that line (gate closed, an
  older raven-node, none running) nothing is said of Tor's state: no `running`, no `detail`, no
  `tor`. Apps show it as a way card in the Tor path colour, with the phase (`network.tor.phase.*`),
  the why and the outage history (`network.tor.why`, `network.tor.outages`).
- **Gates, both directions.** A release engine reads no lab switch: every way but LAN direct is
  `preview`, `network.set` refuses to turn one on with `NOT_AVAILABLE_YET` (nothing is changed;
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
  | `carry_for_friends` | bool | `raven node custody on --yes` / `off` | now |
  | `friends_carry_mine` | bool | `raven custody use on --yes` / `off` | now |
  | `handoff` | bool | `raven node custody handoff on\|off` | now |
  | `relay_for_friends` | bool | `raven relay offer on\|off` | now |
  | `bridge`, `store`, `relay` | bool | `raven node bridge\|store\|relay on\|off` (AUTO off) | now |
  | `hide_ip` | bool | `raven node hide-ip on\|off` | now |

  Turning a held way on is `NOT_AVAILABLE_YET`; turning anything off is always allowed.
  `carry_for_friends`, `friends_carry_mine` and `handoff` turned on need the person's yes to what
  they mean: show `NetworkStatus.texts.<setting>` first and pass `agreed: true`, else the answer is
  `CONSENT_NEEDED`. Each `Change` says in plain words what it does (`effect`); `restart_needed` is
  true when a running raven-node applies a change only when it starts again (the app may offer
  `node.stop` then `node.start`). A failure after some changes names them in `detail`.
- **One consent rule in all three apps.** A consent sheet comes before exactly the settings the
  engine answers with `CONSENT_NEEDED` without `agreed: true`: `carry_for_friends`,
  `friends_carry_mine` and `handoff`, turned on. The sheet says what it does, what it costs
  (bandwidth, disk, being online), what others can see and what they can't
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
  does not serve it (no node, an older one, the gate shut) both answer `NOT_AVAILABLE_YET` naming
  `raven lock` / `raven unlock`. `updates.status` is `raven update status`; installing stays in the
  CLI (`raven update install`).

### Types

```text
Contact   { address, name, short_address, verified: bool, blocked: bool,
            presence: "in_touch" | "waiting" | "none" | "no_address",
            last_contact_ms?, waiting: {count, until_ms}?, avatar_index: 0..4, lan?: "ip:port",
            unread }
            waiting.until_ms is 0 when not known (raven-node not running).
            last_contact_ms: the newest message from the friend or of yours they confirmed (the
            history counts, also from before the app started); in_touch while that, or a message or
            receipt this run saw, is under 15 minutes old.
            unread: the friend's messages after the one last read here or in the terminal app
            (see "Read and unread").
Message   { id, address, direction: "in" | "out", text, at_ms,
            state: "sending" | "sent" | "delivered" | "waiting" | "time_ran_out" | "not_sent_meet_first" | "failed",
            until_ms?, path?, path_kind?, delivered_at_ms?, attempts? }
            path_kind and its path words (every label raven-node can report):
              lan "LAN direct" · internet "Internet direct" · p2p "p2p" (path not known) ·
              p2p_direct "p2p · direct" · p2p_reversed "p2p · reversed" · p2p_relayed "p2p · relayed" ·
              p2p_hole_punched "p2p · hole punched" ·
              websocket "p2p · relayed over WebSocket" (relayed while every relay in use runs over
                WebSocket/TLS) ·
              nearby "Bluetooth nearby" ·
              onion "via Tor" (the friend's Tor onion service; lab, RAVEN_LAB_TOR) ·
              friend "Held by a friend" (friend custody; said while it waits too) ·
              handoff "Passed on between friends" (multi-hop custody) ·
              letter "Sealed letter with a friend".
            A delivery raven-node's outbox made takes raven-node's last path to the friend. The path
            of each delivered message of yours is kept in `desktop_private.rms` (by history id), so
            it comes back after a restart.
            until_ms (waiting): when it runs out for good, the time raven-node's outbox applies: its
            envelope's expiry, or, while the long message horizon is live (a lab switch), 7 days
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
            keep_chats_days?: 7 | 30 | 90 | null, forget_addresses: bool, lock_on_sleep: bool }
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
                                           chosen_by_hand, offering, offering_over_internet,
                                           offering_reachable, listed_by_hand },
                     carry_for_friends: { on, held_messages, held_bytes, handoff, handoff_lines },
                     letters_left: [..], relay_for_friends: { setting, offering, offered_to } },
            help: { bridge, store, relay, automatic, effects: { bridge, store, relay } },
            hide_ip, lab_switches: [..],
            texts: { carry_for_friends, friends_carry_mine, handoff },
            tor?: { phase: "ready" | "publishing" | "unreachable" | "starting" | "restarting" | "blocked"
                           | "could_not_start" | "not_built" | "off" | "unknown",
                    words, percent?, why?, retry?, outages? } }
            (tor: raven-node's Tor line, read into its parts; only while raven-node's Status has
             that line: see "The Tor way")
            Carrier ids: lan, lan_beacon, internet, port_mapping, p2p, friend_relay, websocket, proxy,
            custody, letters, handoff, route_hints, nearby, tor. Protection ids: random_port,
            link_knock, link_padding, lock_v2, security_events, updates_from_friends.
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
UpdatesStatus { available, bundles, from_friends, lab, lines: [..], summary?, offer?: [..],
            install: "cli_only", install_text }
Group     { id, name, short_id, status: "active" | "left" | "removed", admin: bool (you are the admin),
            admin_address, admin_name, members: n, unread, last_ms?, last_text?, last_from? }
            last_from: the newest message's author (a name; "You" for yours); last_text its text.
GroupMember { address, short_address, name, label, friend: bool, admin: bool, me: bool }
GroupMessage { id, group, from_address, from_name, mine: bool, text, at_ms,
            via_name? (the member that passed it on, when it was not its author),
            delivered: n, total: n,
            receipts: [{ address, name, state: "waiting" | "sent" | "delivered" | "failed",
                         via: "direct" | "relay" }] }   (receipts only on yours)
```

### Events

`events.poll {after_seq}` returns the events after `after_seq` and the newest `seq` (pass it as the
next `after_seq`; start with 0). The engine keeps a bounded queue (512 events; heartbeats replace each
other). **`reset: true`** means events after `after_seq` were lost (dropped for room, or `after_seq` is
from before this engine started): reload what the window shows (contacts, the open chat, node status)
instead of trusting the events, then keep polling from the returned `seq`. The engine watches
raven-node from the first poll on (about once a second) and stops watching after 30 s without a poll;
its first look only notes what is there, so old messages do not arrive as `incoming`.

```text
Event     { seq, kind, at_ms, ... } kinds:
            "status_ok"            heartbeat: a successful status check            -> heartbeat pulse
            "send_started"  {id}    a send attempt began                           -> packet travels out
            "receipt"       {id, address?, path, path_kind, ms, delivered_at_ms?}  signed receipt arrived
                                       -> receipt travels back, Delivered (delivered_at_ms as on Message)
            "incoming"      {message}                                              -> packet travels in, bubble slides in
            "outgoing"      {message}  yours, sent by another program on this profile (the
                                       terminal app, the CLI) after the first look  -> bubble appears
                                       in the open chat (its path once delivered; a receipt follows)
            "retry"         {id, address, attempts}                                -> retry ring on the friend's dot
            "presence"      {address, presence}                                    -> dot changes (blink)
            "state"         {id, address?, state, until_ms?}                       -> tick text changes
                            (also sent when a waiting message's until_ms becomes known or changes)
            "node"          {status}                                               -> header/menu-bar chip changes
            "unread"        {address, unread}  the friend's count changed (a message came, or the
                                       chat was read here or in the terminal app) -> badge follows
            "group_message" {group, message: GroupMessage}  a member's message came (after the
                                       first look)                                -> bubble in the group chat
            "group_changed" {group}  the group's members, status, unread count or a receipt changed
                                       (also a group that appeared)               -> reload it (groups.get,
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
`UNLOCK_WAIT` (`lock.unlock`). Each comes with a plain-English `message` that names one next step;
the technical text goes in `detail`.

Groups add `GROUP_NOT_FOUND`, `GROUP_NOT_ADMIN` (only the admin adds and removes),
`GROUP_NOT_MEMBER` (you left or were removed), `GROUP_TOO_LARGE` (more than 16 members),
`GROUP_ADMIN_CANNOT_LEAVE`, `GROUP_ALREADY_MEMBER`, `GROUP_BAD_NAME`, `GROUP_QUEUE_FULL` (too many group
copies still wait; try again once some are delivered) and `GROUP_NO_ROUTE` (none of the other members
is your friend); a member who is not a friend is `NOT_A_CONTACT`, a message over 8,192 bytes
`MESSAGE_TOO_LONG`.

- "Not sent, meet first" and "time ran out" are message states (`not_sent_meet_first`,
  `time_ran_out`), not errors: no operation returns them as error codes.
- `CONTACT_BLOCKED`: v1 has no unblock operation; the message names the CLI's `raven contact unblock`.
- `NAME_CLASH` also covers a name that only looks like a verified friend's name.

## Mocks

Every app also has a `MockRaven` that implements this contract in memory with the demo friends Ali
(verified, in touch), Mina (one waiting message) and Rena (not verified), and replays the demo events
of the design mockups. The mocks have no groups yet (no app has group screens yet; a mock
that adds them follows "Groups" above). Its network answers are a release build's: LAN direct on, every other way
`preview` (Bluetooth nearby `not_on_this_os` where the OS has no backend), `network.set` refusing to
turn a held way on with `NOT_AVAILABLE_YET` and keeping the bridge/store/relay flags, LAN and hide
IP it was given; Ali's routes are a LAN address, Mina's none; no security notice; Lock v2 and
updates not in this version. Mocks are for demos, snapshots and tests: they are compiled only into debug
builds (or a demo build), and an app runs on its mock only when a demo switch asks for it. A release
build always uses `raven-client`. Each app's README names its switch.
