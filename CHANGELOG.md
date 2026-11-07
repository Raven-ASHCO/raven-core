# Changelog

What changed in each version of Raven core, for the people who use it. Raven is a pre-release:
nothing here has had an independent security review, and there are no downloads yet. The
[README](README.md) says what release builds have and what stays in the lab.

## Next version (not released yet)

Most of the changes below come from our own security review of November 2026. It is not an
independent review.

### Privacy on this computer

- In a sealed profile, the app channel's queue and its pairing records are now sealed like the rest
  of the profile: a copy of the disk no longer shows which friend's device an app record or a pairing
  attempt was for.
- `raven erase` now overwrites the Tor helper's onion service keys and its introduction point keys,
  and removes the helper's whole folder. It also removes the friend relay's lock, so the profile
  folder goes too. On Linux it names the system journal among the places it cannot reach.
- The Linux user service writes its lines to the profile's capped log, which erase removes, not to
  the system journal.
- Raven refuses a profile folder that another account owns.
- The node's log writes control characters as escapes, so a text from a peer cannot start a line
  that looks like Raven wrote it, or change your terminal.

### Other accounts on the same computer

- The node's local control endpoint can no longer be taken first by another account. For a long
  data folder it now lives in a folder of your user alone (on macOS your own temporary folder, on
  Linux `$XDG_RUNTIME_DIR`), and on Windows the pipe's name holds a random token of the profile.
- raven-node and its Tor helper now prove themselves to each other on every stream. On macOS and
  Linux they share a private socket pair that no other program gets. On Windows the helper's port
  holds a bounded number of connections.
- A release build no longer seals text for another program of your user (the SealUnderSession
  request is lab only).
- On a Mac, raven-node starts the Bluetooth helper only when its signature checks out as Raven's
  nearby helper. The helper runs with the hardened runtime and an empty environment, and what it may
  report is bounded.
- The Windows installers give the program folder an access list of its own. The Linux relay
  installer checks the relay folder as the relay account and refuses a planted SQLite journal.

### The network and Tor

- Raven tells your contacts a public address only after a contact or a relay saw you there. STUN
  and router answers alone no longer decide it, so someone on your network cannot make your friends
  dial an address of their choosing.
- UPnP: Raven takes the gateway answer from your default router only, bounds what it reads from it,
  and uses a mapping only at a public address a contact or relay saw.
- A stranger who has your card can no longer keep your friends out by filling your onion service
  with silent connections, and one contact cannot hold every place. The Tor helper keeps at most 64
  rendezvous circuits and closes idle ones.
- Raven remembers each contact's onion link key the first time they connect, and stops a Tor
  connection that shows another key before it sends anything about you.
- On the local network, one IPv6 host can no longer use up the places of its neighbours.

### Groups

- A blocked contact no longer takes part in your groups.
- The group store is bounded in size and shared fairly between admins and authors, and a group can
  be forgotten.
- A member who is not your friend is marked as such.

### For the apps and for people who build Raven

- Next to the name of the friend who holds a message of yours, or of the group member who passed a
  message on, the engine now says whether that is a friend you verified and have not blocked
  (`via_friend`), so the apps never show anyone else as a friend.
- Release builds refuse debug assertions, which would open lab switches. Every build uses the locked
  dependency list, and our copies of outside libraries are checked against their published releases.

### Tor and mail friends

- When Tor becomes usable (Raven started, the network changed, the computer woke, the iPhone app
  opened), Raven asks your mail friends for held mail at once. Before, mail held by a friend that
  only Tor reaches could wait a minute, or up to 30 minutes after the last check there.
- On the iPhone, the short mail check when the app opens no longer cuts the node's own fetch: mail
  that needs a new Tor connection arrives when that fetch ends, not a minute or more later.
- The iPhone's background refresh asks every mail friend, also one that had nothing just before the
  app went to the background.
- A message to a friend whose Tor connection died without notice gets a new connection after 6
  seconds instead of 12.
- A message sent the moment Raven starts (the iPhone app opening, for one) waits a few seconds for
  Tor and goes, instead of showing Waiting until the next try.
- When Raven's own onion service stays unreachable while Tor still answers (two failed self-checks
  in a row, at least 12 minutes after Tor was ready, and no friend linked in for 10 minutes), Raven
  starts Tor again: at most once in 30 minutes and four times in 6 hours. Before, it stayed
  unreachable until the network changed.
- On the iPhone, a local network connection the system refuses right after the app starts no longer
  holds a send or a mail check for up to 30 seconds. The wait stays on macOS, where a new program is
  let onto the local network only after a few seconds.

## 0.1.1 (October 2026)

Fixes from our own testing after 0.1.0, the engine for the iPhone app, and a Linux package.

### Chats and contacts

- New chat controls, on this device only (the other person is never told): block a contact, remove a
  contact's verification, clear a chat's history, delete a chat from your chat list (it comes back
  when a new message arrives) and pin a chat to the top. A blocked contact's messages, contact
  requests and group messages are dropped, and nothing goes to them, until you unblock; the contact
  stays. In the terminal: `raven contact block|unblock|unverify NAME`, `raven chats
  clear|delete|pin|unpin NAME` (or `--group`), `raven group clear GROUP`; for the apps, the engine
  ops in `desktop/api/API.md` ("Chat controls").

### Sending

- A message to a verified friend no longer gets lost when the secure connection with them has to be
  set up again and that first step gets no answer over Tor. It now waits and goes as soon as the
  friend can be reached. A refusal from the friend still says "not sent".
- A quick "unreachable" from Tor is checked once more before a message is queued, and it no longer
  makes Raven skip Tor for the next message.
- When a message is queued at once because Raven is already trying to reach the friend over Tor with
  an earlier one, Raven says that, instead of "couldn't be reached".
- After `raven nearby disable`, sending no longer tries Bluetooth. With peer-to-peer off on this
  computer, sending no longer tries an old peer-to-peer address, and the message no longer advises
  turning peer-to-peer on.

### Finding friends again

- Verified friends tell each other their local network address inside their encrypted links on every
  kind of link, not only on the local network. Two friends who only reached each other over Tor move
  to the faster direct way once they share a network. Raven uses an address it was told only for a
  verified friend, and only while that address is on one of your own networks.
- After `raven contact forget-address`, the next connection with the friend asks for their routes
  again, so the friend is not left reachable over Tor alone.
- `raven contact forget-address` now forgets every saved route of the friend (local network,
  Internet, peer-to-peer and its relays). The friend's Tor address, their verification and the mail
  friends they told you about stay, so mail for them still finds its way.
- Adding a friend's newer card replaces the routes an older card had saved, and says which went.

### What Raven tells you

- `raven status` no longer prints your 10 security words. People paste status into bug reports and
  screenshots. The words are shown only when you ask: `raven whoami --words`.
- `raven status` says plainly how friends are reached ("friends on this network directly, and friends
  elsewhere over Tor"). Rows only a developer needs moved behind `raven status --verbose`.
- `raven contact list` and `raven contact show` name the ways Raven has to reach each friend, never
  with a public address. A way Raven does not use now says why: off on this computer, not until you
  verify the friend, or not while you hide your IP address from them.
- The custody settings say what each one does and how to turn it on. The node settings say what to do
  for the background program that is actually running.
- The background program's log notes every delivery with the friend's short tag (never an address).

### The terminal app

- Every message says when it came and how (for example "via Tor" or "from a keeper").
- The unread count reads as a badge, a send shows "Connecting" before "Sending", and pressing Enter
  right after typing fast sends the message.

### Tor

- When the Tor network requires a newer Tor than this Raven has, Tor turns off with "this version is
  too old for the Tor network; update Raven" instead of ending the program. Raven carries a small,
  documented change to the Tor client it uses (Arti 0.47.0) for this.

### iPhone and iPad (the app is in development)

- Raven's background program can now run inside an app, with Tor inside it too, because iOS lets an
  app start no other program. The keys go to the iOS Keychain, for this device only (never iCloud,
  never a backup restored elsewhere). It builds for iPhone and the iOS Simulator and has run there in
  tests; it has not run on a phone yet.
- New engine operations for the app: pause and resume as it leaves and comes back to the screen; a
  mail check for iOS background refresh, which says which friends it asked; handing waiting messages
  to a friend who holds mail before the app goes to sleep; and a setting to use Tor on Wi-Fi only.
- There is no push server: a phone receives while Raven is open, and otherwise collects what friends
  hold for it when it opens or iOS lets it check in the background.

### For the desktop and phone apps

- A message a friend holds names that friend ("Held by Max"), and so does each member's copy of a
  group message of yours. A member's group message says how it came. Tor's start percentage is
  reported in release builds too.

### Packaging

- A script makes a Linux package (`raven-linux-<arch>-0.1.1.tar.gz`) with an installer that sets
  Raven up for one user as a systemd user service, and a SHA-256 checksum file. It has not been
  tested on every distribution yet.

## 0.1.0 (October 2026)

The first version with the features of the October 2026 field test switched on in release builds.
Three computers, one person: a phone hotspot and a home network reached each other over Tor in every
direction, a computer that was off for five minutes got its messages afterwards, and a Bluetooth chain
carried messages both ways. A small test is evidence, not proof.

- **Messages between two computers on the same local network**, end to end encrypted, with friends
  verified by comparing 10 security words.
- **Friends on other networks:** Internet direct, peer-to-peer with hole punching and relays run by
  friends, router port mapping (UPnP, NAT-PMP, PCP), routes friends tell each other inside their
  encrypted links, finding this computer's public address with STUN (Cloudflare and Google only), and
  Tor onion services, raced against the direct ways. Listening for Internet direct and peer-to-peer,
  port mapping, relaying for friends and keeping mail for friends each stay off until you turn them on.
- **A friend who is away:** friends keep sealed mail for each other (they cannot read it), and a
  message keeps trying for up to 7 days.
- **Groups** of up to 16 people; the creator is the only admin.
- **Bluetooth nearby** between Macs with no network at all (macOS only).
- **The app channel** for RDAP, Raven's companion for software agents: only from verified friends,
  only of known types, within size and rate limits.
- **Contact cards carry no unsigned route.** A card holds your key, your Tor onion address signed by
  your key and, only if you add one, a local network address. Release builds never put an Internet
  address, a peer-to-peer network ID or a relay into a card, and ignore them in a card they read.
- **Fixes from an internal review** (October 2026), among them: a new key under a verified friend's
  name is refused as a key change; the terminal app shows a friend's code only once they are
  verified; a new profile is encrypted by the program that creates its identity; Tor links use a key
  of their own. One fix was taken back: removing a contact keeps its sessions until they expire.
- Not independently reviewed. Nothing is packaged, signed or notarised.
