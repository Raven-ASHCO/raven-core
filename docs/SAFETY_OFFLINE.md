# Raven when the internet is cut off: a safety guide

Version 3. This guide describes what this version of Raven does. Anything
that is still being built or reviewed is marked **not in this version**.
Where this guide already says what such a part will do, it is marked **when
on in your build**: `raven lan status` and `raven status` say what your build
does. Section 12 lists them.

## 0. What this guide is for

Raven can carry messages between laptops on the same local network with no
internet at all: a home router whose internet is down, a laptop hotspot, or a
cable between two laptops. This guide says what that protects, what it does
not, and a few habits that help. Raven is not a tool for getting around
blocking or for reaching the outside internet, and nothing here helps with
that. How to set up the link itself (the same Wi-Fi, a hotspot or a cable,
and the firewall on each system) is in [OFFLINE_GUIDE.md](OFFLINE_GUIDE.md).

## 1. What Raven protects, and what it does not

| Raven protects | Raven does not protect |
|---|---|
| What you write: a message is end-to-end encrypted, and only the friend you wrote to can read it. | That two laptops are talking, when, and how much. Anyone on the same network can see that. |
| Who you are, from strangers who connect to your laptop: Raven tells them nothing about your identity unless they prove they hold the key of someone you added. | That Raven is installed. It listens on TCP port 7420, which anyone on the network can find. <!-- gate: LISTEN_PORT_RANDOM_PRODUCTION_ENABLED=false --> |
| Messages from people you did not add: Raven refuses them. | That your laptop can be recognised on the next network: Raven's listener answers every connection with the same key. <!-- gate: LINK_KNOCK_PRODUCTION_ENABLED=false --> |
| What Raven keeps about your friends on this computer (section 5): their nicknames, keys and addresses, when they last connected, who has messages waiting, and your message records are encrypted with a key that your keychain keeps. | Your chats, on a laptop someone takes while you are logged in. |
| | Your identity, when your laptop tries a friend at an old address (below). |
| | Whether someone is quietly listening on the network. Nobody can notice that, Raven included (section 4). |

<!-- gate: LAN_NOISE_PIN_PRODUCTION_ENABLED=false: the paragraph below is its pre-flip form; replace it when the gate flips. -->
**One gap in this version.** When your laptop tries a friend at an old
address, whatever answers there learns your Raven identity. Raven sends it
before it checks who answered. On a new network, the address your friend had
last time may now belong to someone else's computer, and Raven tries it again
for every message that is still waiting. So turn the local network off on
networks you don't trust (`raven lan off`, section 4), and let waiting
messages go out on networks you trust.

## 2. Before a cutoff

Do these on a calm day.

- **Add the people you need while you are together**, and compare security
  words out loud, face to face. Words or a code sent in a message prove
  nothing. Each of you runs:

  ```sh
  raven contact verify Sam
  ```

- **Use nicknames**, not full names. A nickname stays on this computer, but
  also in your shell history if you type it into a command.
- **Turn on disk encryption** (FileVault on macOS, BitLocker on Windows, LUKS
  on Linux) and use a strong login password. Raven encrypts what it keeps
  about your friends (section 5), and your login password is what protects
  Raven's key. Disk encryption also covers what Raven cannot: pieces of old
  files left in free disk space, Raven's settings, and other programs' files.
- **Save addresses as numbers**, not computer names: `10.42.0.1:7420`, not
  `sam-laptop.local:7420`. A computer name is looked up by asking the network
  out loud, again at every retry, so everyone there hears the name of your
  friend's computer.

  ```sh
  raven contact set-dial --petname Sam --lan-dial 10.42.0.1:7420
  ```

  `raven listen` shows the addresses of this computer that a friend can type.
- **Outside Raven**: your system, not Raven, sends two things that let
  people on a network recognise your laptop.
  - **Its Wi-Fi address** (the MAC address). Turn on your system's private
    Wi-Fi address, so that networks see a made-up one: on recent macOS,
    System Settings > Wi-Fi > Details next to the network > Private Wi-Fi
    address (where it offers Rotating, that hides more than Fixed); on
    Windows 10 and 11, Settings > Network & internet > Wi-Fi > Random
    hardware addresses, or the same setting in one network's properties
    ("Change daily" hides more); on Linux with NetworkManager, set the
    connection's cloned MAC address to `random` or `stable`. An address kept
    for one network still shows when you come back to that network.
  - **Its name.** Many systems announce the computer's name on every network
    they join, and use it as the Bluetooth name too. A plain name ("laptop")
    gives away less: on macOS, System Settings > General > About > Name, and
    General > Sharing > Local hostname; on Windows, Settings > System >
    About > Rename this PC; on Linux, `hostnamectl set-hostname laptop`.
- **Try a meeting once** with a friend (section 3), so the steps are familiar.

## 3. Meeting to exchange messages

- **A message waits about a day at most.** Raven can hold a message for a
  friend only until your secure connection with that friend ends, and each
  one lasts a day from when it is set up. After that it cannot queue new
  messages for them: write them at the next meeting. `raven contact list`
  shows it for each friend, in this computer's local time, for example
  "Messages to Sam can wait until tomorrow 14:05 (in about 19 h)." or "To
  write to Sam, meet first". `raven outbox list` says when the time ran out
  for a message that never left this computer.
- **Bring the laptop on, with Raven running.** A closed lid or a sleeping
  laptop receives nothing.
- **One of you makes the network**: a hotspot with a long password, or a
  cable. The other joins it. Whether a hotspot starts at all without an
  internet connection depends on the system (not tested for every system
  yet). A Bluetooth network between two computers (Bluetooth PAN) is an
  ordinary network for Raven, with typed addresses (UNVERIFIED: not tested on
  every system yet).
- **The laptop that receives must listen on the network.** Run this and keep
  the window open (Ctrl+C stops it):

  ```sh
  raven listen
  ```

  `raven status` says in its `receiving` row whether friends can reach you. A
  login service set up by the install scripts listens on this computer only
  (127.0.0.1:7420), unless it was installed to listen on an address of your
  network (`RAVEN_LAN_LISTEN`, or `-LanListen` on Windows: see your install
  guide).
- **Type the address your friend reads out** from their `raven listen`
  (`raven contact set-dial`, above). The laptop that joins a hotspot types the
  hotspot laptop's address. The hotspot laptop can reach the other one only
  after the other one has connected to it once, and only if it has some
  address saved for it: when a friend connects to you, Raven sends what is
  waiting for them to the address they came from, on the port you saved
  (an old saved address is enough).
- **Wait until it says delivered.** A send ends with `status delivered`, and
  `raven outbox list` shows what is still waiting.
- **Afterwards**, turn the hotspot off and stop listening (Ctrl+C in `raven
  listen`, or stop the background program, section 5).

## 4. On a shared or unknown network

<!-- gate: LINK_PADDING_PRODUCTION_ENABLED=false: the box below says each message's size shows; update it when the gate flips. -->
<!-- gate: LINK_KNOCK_PRODUCTION_ENABLED=false: the box below says the listener gives everyone the same key; update it when the gate flips. -->
<!-- gate: LISTEN_PORT_RANDOM_PRODUCTION_ENABLED=false: the box below names port 7420; update it when the gate flips. -->
> **What people near you can see**
>
> Anyone on the same network (the Wi-Fi, the hotspot or the cable) can
> record what goes over it without sending anything. Nobody can notice
> that, and Raven cannot warn you about it: assume someone may be listening.
>
> - **Anyone who listens** sees that your computer talks to another one,
>   when, for how long, and roughly how much. In this version they see
>   exactly how much: each message's size shows. They also see your
>   computer's Wi-Fi address and often its name; your system sends those,
>   not Raven.
> - **Anyone who connects** to your laptop while Raven listens on the
>   network also learns that it probably runs Raven (it answers on port
>   7420), and gets the same key from it on every network, so they can
>   recognise your laptop on the next network.
> - **Nobody** can read what you write, and listening alone does not tell
>   them who you or your friends are. (The gap in section 1 is about a
>   computer that answers your laptop, not about listeners.)
>
> Three habits help: turn on your system's **private Wi-Fi address** and
> give the computer a **plain name** (section 2 says where), and use
> **meeting mode** so that Raven listens only while you meet (below).

- **The gap in section 1**: a message waiting for a friend is tried at their
  old address, and whatever answers there learns who you are.
- **Turn the local network off** on a network you don't trust (a cafe, a
  hotel). Raven then stops listening on the local network, stops answering
  and sending nearby searches, and tries no friend at a local address, so
  the gap above stays closed there. Messages wait (or go over the internet
  where your build has that). Turn it on again on a network you trust; `raven
  lan status` says which it is:

  ```sh
  raven lan off
  raven lan on
  raven lan status
  ```

- **Meeting mode**: turn the local network on only for a meeting. It turns
  off by itself when the time is up (30m, 1h, 3h, or any number of minutes or
  hours up to 24h), even if the laptop's clock is set back meanwhile. While it
  is on, only your friends can connect, but others on the network can still
  see that your laptop waits for connections. If Raven says "for this computer
  only", no friend can connect yet: re-run the installer as it says:

  ```sh
  raven lan on --for 1h
  ```

- **Verified friends only**: a contact you have not verified (you did not
  compare security words in person) cannot connect to your laptop on the
  local network, and your laptop does not connect to them there. Your
  messages to them wait. Anyone on the network can still see that Raven
  listens:

  ```sh
  raven lan verified-only on
  raven lan verified-only off
  ```

<!-- gate: LISTEN_PORT_RANDOM_PRODUCTION_ENABLED=false: the item below describes the random port before its flip; update it when the gate flips. -->
- **A port of its own, when on in your build** (not in this version:
  section 12). Raven waits for friends on TCP port 7420, so anyone on the
  network who looks for that port can guess that your laptop runs Raven.
  With this on, a new profile picks a random port instead. A profile you
  already have keeps 7420 until you move it, from Raven's next start:

  ```sh
  raven lan port random
  ```

  Friends whose Raven learns your addresses by itself find the new port;
  friends who only saved your old address need your new card. Someone who
  connects to the port can still tell what answers there, and the port stays
  the same on every network, so it can still recognise your laptop.
<!-- gate: LINK_PADDING_PRODUCTION_ENABLED=false: the item below describes hidden message sizes before the flip; update it when the gate flips. -->
- **Hiding message sizes, when on in your build** (not in this version:
  section 12). Raven pads every message between two laptops to one of four
  sizes (half a kilobyte, 4, 16 or 64 kilobytes), so a listener sees which
  of the four it was, not how long your message is. Both laptops need a
  Raven that has it; with a friend whose Raven is older, nothing is padded.
  It does not hide how many messages go, when, in which direction, or how
  long two laptops stay connected.
<!-- gate: LINK_KNOCK_PRODUCTION_ENABLED=false: the item below describes the knock and per-connection keys before the flip; update it when the gate flips. -->
- **A new key for every connection, when on in your build** (not in this
  version: section 12). Your laptop and a friend's prove to each other that
  they are friends, and then use keys made for that connection only, so
  nobody can use your laptop's key to recognise it on the next network. A
  stranger who connects still gets your laptop's lasting key while some of
  your friends have a Raven without this; once all of them have it, a
  stranger gets a new random key each time. A setting that
  gives strangers no answer at all ("Silent to strangers") is not in this
  version either; with it on, friends with an older Raven could not connect
  to you. Someone who connects can still tell that something answers on
  the port, and listeners still see everything in the box above.
<!-- gate: LAN_BEACON_PRODUCTION_ENABLED=false: the item below describes nearby search before its flip; update it when the gate flips. -->
- **Nearby search, when on in your build** (not in this version: section
  12). Your laptop asks the network for your friends, so that no address
  needs typing, and answers your friends' questions. Everyone on the network
  can see that a Raven node is here (the searches use a fixed port and sizes
  in two narrow ranges), and when your laptop asks and when another laptop
  answers it: a question and a quick answer, followed by a connection,
  suggest that two laptops belong to friends. The searches carry no names, no keys and no
  addresses, and they do not show how many friends you have or which ones
  your laptop looks for. Your laptop asks only while it has something to do
  (messages waiting, mail held for a friend, or a meeting), answers only your
  contacts (with verified friends only: only verified friends), and stops
  both with `raven lan off`.
- **Guest and hotel networks** often keep devices apart, so friends cannot
  reach each other there. Use a hotspot or a cable instead.
- **When you don't need to receive**, stop Raven's background program
  (section 5).

## 5. If someone takes your laptop

- **What Raven encrypts.** Your friends list (nicknames, keys and saved
  addresses), the addresses Raven learned and when each friend last
  connected, who has messages waiting, and Raven's message records (secure
  connections, receipts and your chats) are kept in encrypted files. The key
  that opens them is kept by your login keychain on macOS, by the Secret
  Service keyring or your Raven passphrase on Linux, and by your Windows
  login on Windows. The first time this version starts on a profile, it
  encrypts the profile and says so once. To see what is encrypted:

  ```sh
  raven privacy status
  ```

- **What Raven does not encrypt.** Its settings (`node_policy.json` and
  `privacy.json`: for example the address Raven listens on and how long
  chats are kept) and its logs (counts and codes only, each line with its
  UTC time; the other side of a connection is a short tag that changes when
  Raven restarts, never its address). The names, sizes and
  times of Raven's files. Inside one profile, the records about the same
  friend can be matched to each other (not to who that friend is), and the
  files show to the hour when each secure connection began and in what order
  messages arrived. Your shell history and terminal scrollback. Copies of
  Raven's folder in backups (Time Machine, disk snapshots), and pieces of old
  files in free disk space: what Raven wrote before this version encrypted
  it, and what it deleted since.
- **Someone who can log in as you**, or who has the disk and your login
  password, can open everything, your chats too: your keychain opens Raven's
  key for them.
- **Someone who only has the disk**, without your password, cannot read your
  friends list, their addresses or your chats. With disk encryption off they
  can see what Raven does not encrypt (above), pieces of old files included.
  With disk encryption on and the laptop off, none of it.
- **Lock Raven, then lock the screen or log out**, before you hand the laptop
  over or leave it. `raven lock` stops Raven and keeps it stopped: friends
  can't reach you, and sending does not start Raven again, until you run
  `raven unlock`. Opening the full-screen app (`raven`) asks first whether
  to start Raven again, and keeps it stopped unless you say so. When Raven's
  own login service runs this profile, `raven lock` also asks whether to
  keep Raven stopped after your next login.

  ```sh
  raven lock
  raven unlock
  ```

  With a keychain (macOS, Windows, and Linux with a keyring), Lock only stops
  Raven: anyone who can log in as you can still open your chats, so lock the
  screen or log out too. With a Raven passphrase (Linux without a keyring),
  Lock really locks: your chats can't be opened again without the
  passphrase. If a service Raven didn't install runs Raven, `raven lock` says
  it can't stop it and how to stop it. In the full-screen app (run `ash`),
  press L on your friends list (or Q, then L): the app locks the same way,
  and sending does not start Raven again until you open the app again.
  When Raven's own login service runs this profile, the app stops Raven only
  until your next login; to keep it stopped after that, use `raven lock`.
<!-- gate: LOCAL_PROTECTION_PRODUCTION_ENABLED=false: the item below describes Lock v2, locking on sleep and the Raven passphrase before their flip; update it when the gate flips. -->
- **A lock that keeps Raven running, when on in your build** (not in this
  version: section 12). `raven lock` then keeps Raven running but makes it
  forget its keys: friends can't reach you, your messages wait here, and
  nothing is sent until `raven unlock`. With a Raven passphrase, `raven
  unlock` asks for it, and each wrong one makes you wait longer (up to a
  minute). Without one, it opens at once and says again that anyone who can
  log in as you can open your keys: lock the screen too.
  - **Locking when the laptop sleeps:** in the full-screen app, Settings,
    "Lock Raven when the computer sleeps". It is on by default with a Raven
    passphrase and off otherwise, and off by default too when Raven reads
    its passphrase from a file (a computer that runs Raven unattended: nobody
    would be there to unlock it). "Lock Raven when this app is idle" locks
    after the minutes you choose (off by default).
  - **A Raven passphrase on a Mac:** `raven passphrase set` moves Raven's
    keys from your login keychain into a vault that only the passphrase
    opens. Raven then starts locked after every restart, and your login alone
    no longer opens your chats. There is no way to recover a forgotten
    passphrase: your friends would have to add you again. `raven passphrase
    remove` moves the keys back to the keychain. On Linux with a Raven
    passphrase you can change it; on Windows, and on Linux with a keyring,
    Raven says a passphrase is not available yet.

  ```sh
  raven passphrase
  raven passphrase set
  raven passphrase change
  raven passphrase remove
  ```

- **If your keychain is locked or refuses Raven**, Raven can't open your
  friends list: nobody can connect to you and nothing is sent until it can
  (the full-screen app says "Locked out of your friends list").
  On a Mac, Raven may ask once for access to your keychain when it starts:
  choose Always Allow so Raven can receive messages while you are away.
  If the key is gone from the keychain (a new login keychain after a password
  reset, a profile copied to another computer, or another Windows account),
  `raven status` says so: put that keychain or the backup the profile came
  from back, or run `raven erase` and set Raven up again.
- **If you think someone copied Raven's keys** (not only the disk: a program
  that ran as you, say), `raven privacy rotate-meta` changes all of this
  profile's encryption keys. It does not help against someone who can also
  use your keychain: they can still open older copies of Raven's key file
  (section 6).
- **Shell history**: the commands you type stay in your shell history. Raven
  never takes a message from the command line: type it after the command and
  finish with Ctrl-D (on Windows: Ctrl-Z, then Enter). Nicknames and addresses
  you type into a command do stay in the history; the full-screen app (`ash`)
  keeps them out of it.

  ```sh
  raven send --contact Sam
  ```

- **Never use a test profile for real messages.** A test build may print
  "This profile keeps its keys unencrypted (lab file backend): use it for
  tests only, never for real messages." Such a profile has no protection at
  all. Release builds refuse it.

## 6. Deleting chats

- **Old chats are deleted from this computer automatically**, after 30 days
  unless you choose 7 days, 90 days, or always (until you delete them):

  ```sh
  raven chats keep 90d
  raven chats status
  ```

  The days count from when this computer stored a message. A message stored
  before this version counts from when it was written, and a received one is
  never deleted before it has been on this computer for the whole time. On a
  profile that already had chats, the first deletion waits 7 days, and Raven
  says once when it comes. Messages still waiting to be sent are never
  deleted, and your friends' copies are not touched. Raven deletes while it
  runs, or the next time you use a `raven` command. In the full-screen app
  (run `ash`): Settings, "Keep chats for".
- **Delete one chat now.** You are asked to type `delete`. Messages to Sam
  that are still waiting to be sent stay, and show in the chat again once
  they are sent. In a live chat (`raven send --contact Sam --chat`),
  `/clear-local-history` does the same; in the full-screen app, C on Sam's
  page ("Delete chat with Sam").

  ```sh
  raven chats delete --petname Sam
  ```

- **Addresses are forgotten too.** Raven forgets the addresses it learned for
  a friend, and where they last connected from, after 30 days without
  contact. An address you saved stays until you forget it (in the full-screen
  app: F on Sam's page); Raven can then reach Sam only after Sam connects to
  you, or after you save a new address:

  ```sh
  raven contact forget-address --petname Sam
  ```

- **When deleted data becomes unreadable.** A deletion removes the records
  from Raven's files. A copy of the files made before (a backup, a copied
  folder) still holds them, encrypted. After a deletion Raven changes the key
  of its files and keeps the old key for about a day, so 1-2 days after you
  delete a chat (or Raven forgets an address) such a copy no longer opens
  with this computer's keys. Raven does this while it runs, or the next time
  you use a `raven` command. `raven privacy status` says when the key last
  changed.
- **What that does not cover.** Raven's keys are kept, encrypted, under one
  key in your keychain that never changes while the profile exists. Someone
  who has an old copy of Raven's key file (from a backup, or recovered from
  free disk space) and can also use your keychain (your login password; on
  Windows, your Windows login; on Linux without a keyring, your Raven
  passphrase) can still open old copies. Pieces of deleted records can also
  stay in free disk space until they are overwritten. Only erasing Raven
  (section 7) and disk encryption cover these.

## 7. Erasing Raven

`raven erase` erases Raven from this computer: your Raven identity, friends,
chats and waiting messages, and their keys. It runs only in a terminal,
after you type `erase`. It can't be undone, and your friends will need to add
you again.

```sh
raven erase
```

In the full-screen app (run `ash`): Settings, "Erase Raven from this computer"
(the last row). It asks the same question, lists what goes, and also wants
`erase` typed; afterwards it clears the terminal and prints the same result.

- It stops Raven first, and changes nothing if Raven keeps running. It turns
  off and removes Raven's own login service for this profile.
- It deletes the keys first. The key that opens all of Raven's encrypted
  files goes before anything else, so a copy of the encrypted files made
  earlier no longer opens on this computer either (except a copy that holds
  that key itself: see below). Then it deletes Raven's own files. Files
  Raven didn't create stay, and it says how many.
- If it stops part-way, it says what is left: run `raven erase` again to
  finish. Until then, other Raven commands refuse to run on this profile.
- **What it can't erase**: your shell history and terminal scrollback; Time
  Machine backups, disk snapshots and Windows restore points, and any copy of
  the folder made elsewhere; a passphrase file you made; pieces of old files
  in free disk space (disk encryption covers them); your friends' copies of
  your chats and their entry for you. On Windows, and on Linux with a Raven
  passphrase, the key that opens Raven's files is kept in Raven's folder,
  protected by your Windows login or your passphrase: a copy of the whole
  folder made before the erase still opens for anyone who can use your
  Windows login or knows the passphrase.

## 8. Going back to an older Raven

Raven versions from before this encryption can't open an encrypted profile:
they stop with an error about the friends list (`contacts.json`), send
nothing and let nobody connect. They do not delete your records. If one
wrote a few small files unencrypted meanwhile, this version encrypts them
again and says so once.

To go back, first run this with the version you have now (you are asked to
type `unseal`):

```sh
raven privacy unseal
```

It stops Raven and writes this profile's records unencrypted, so an older
version can open them. Anyone who reads this disk can then see your friends
list and who you wrote to. This version doesn't encrypt the profile again by
itself, and every command reminds you. To encrypt it again:

```sh
raven privacy seal-now
```

- Never run an older version and this one on the same profile at the same
  time. While an older Raven still runs a profile, this version encrypts
  nothing there and asks you to restart Raven.
- What was encrypted before `unseal` stays, encrypted, in free disk space;
  what Raven writes after it is not encrypted until `seal-now`.

## 9. Friends who carry or hold messages

<!-- gate: FRIEND_CUSTODY_PRODUCTION_ENABLED=false: this section describes friends who hold mail before its flip; update it when the gate flips. -->
**Friends who hold mail, when on in your build** (not in this version:
section 12). A friend's laptop can keep a sealed copy of your message for a
contact who is away, until that contact's Raven collects it. It does this
only for two people who are both its owner's verified contacts.

- **What the friend who holds it learns.** Their laptop cannot read your
  message. It does learn, for every message it holds, who wrote it and who it
  is for (both Raven identities), when, how big it is, and when it was
  collected; over the internet, also the IP address each of you connects
  from. The messages are signed, so while their laptop holds one, it holds
  proof of who wrote to whom, when, and how much.
- **How long.** A message stays until the recipient's Raven confirms it
  collected it, or until it expires (at most 24 hours). A friend's laptop
  holds at most 128 messages for one pair of people, 64 MiB in all.
- **Nothing happens without a yes.** Holding mail for your friends, and
  leaving your mail with friends (and collecting your own from them), are two
  separate choices, and each is off until you agree. Each command first shows
  what the friend learns and asks; only `y` turns it on, and anything else
  changes nothing. A script that adds `--yes` agrees without the question:

  ```sh
  raven node custody on
  raven custody use on
  ```

  Both of you must agree: your friend for their laptop, you for your mail.
  To stop:

  ```sh
  raven node custody off
  raven custody use off
  ```

- **Turn it on only with friends you both trust.** A friend who holds mail
  learns who you write to, even though they cannot read it.

<!-- gate: CUSTODY_HANDOFF_PRODUCTION_ENABLED=false: this part describes two friends in a row before its flip; update it when the gate flips. -->
**Two friends in a row, when on in your build** (not in this version:
section 12). When you and a contact have no friend in common, your friend's
laptop can pass a sealed message on to your contact's friend, who holds it
until your contact's Raven collects it. Your contact's reply confirmation
comes back the same way, once each of you has verified the other's friend
(below). Neither friend can read the message.

- **What each friend learns.** The friend who passes it on learns who wrote
  it and which friend it goes to, never who it is for. The friend who holds
  it learns who it is for and which friend brought it, not who wrote it,
  unless they already have your Raven identity and check the message's
  signature. If the two friends compare notes, they learn who wrote to whom.
- **How long.** As above: at most 24 hours, and both friends keep their
  sealed copy until then.
- **Each of you verifies the other's friend.** Your laptop passes a message
  on only to a friend of your contact's that you verified yourself, and your
  contact's laptop sends its reply confirmation back only through a friend of
  yours that they verified. Verify that friend by its key alone, with no
  address to dial (`raven contact add` with `--verify-fp` and no
  `--lan-dial`); your laptop does not connect to it for this. If only one of
  you did, a message can arrive while its confirmation cannot come back: when
  time runs out, your outbox then says that delivery was not confirmed (your
  contact may have it), and `raven contact show` with the contact's name, on
  the side that is missing the friend, says so.
- **Nothing happens without a yes.** Passing messages on, and holding
  messages another friend passes on, are one more choice, off until the
  laptop's owner turns it on; it works only while holding mail is on too:

  ```sh
  raven node custody handoff on
  raven node custody handoff off
  ```

  `raven doctor` counts your contacts each way can reach (`offline_delivery`),
  and `raven contact show` with a contact's name says which way that contact
  can be reached while away.

Friends who pass messages on over the internet (relays): not in this
version.

## 10. Signs something is wrong

<!-- gate: SECURITY_EVENTS_PRODUCTION_ENABLED=false: the item below describes Raven's security notices before their flip; update it when the gate flips. -->
- **Raven's security notices, when on in your build** (not in this version:
  section 12). Raven notes when something looks wrong on a connection or with
  a friend's messages: another computer answering at a friend's address,
  messages that fail their checks, a stranger who keeps trying to connect.
  `raven security` lists the ones that need you, each with what happened,
  what Raven did and what you can do; `raven status` shows them too, and the
  full-screen app puts a mark next to the friend (press W to see them).

  ```sh
  raven security
  raven security explain 1
  raven security resolve 1
  ```

  The harmless explanation comes first: most of these are a bad network or a
  friend's reinstall, not an attack. Raven never blocks a friend by itself;
  to stop sending to someone until you have checked, press P on them in the
  full-screen app. Comparing security words with that friend again closes the
  notices about them. Raven keeps the notices on this computer only,
  encrypted, and tells nobody. It cannot notice someone who only listens.

<!-- gate: RELEASE_BUNDLE_PRODUCTION_ENABLED=false: the item below describes Raven updates before their flip; update it when the gate flips. -->
- **Someone hands you "a new Raven"**: never run a program someone gives you.
  When Raven updates are on in your build (not in this version: section 12),
  `raven update import` checks a Raven release file (signed by the Raven
  project's keys and listed in its public release log) before it keeps it,
  and installs nothing until you type `install`:

  ```sh
  raven update import <release file>
  raven update install
  ```

  Until then, update Raven the way you installed it (the install guide for
  your system).

- **The security words do not match**: do not mark the friend verified. Meet
  and compare them again.
- **A send says the computer that answered is not your friend** ("its key is
  not the one you saved"): someone else's computer may have your friend's old
  address, or your friend reinstalled Raven. Ask them in person.
- **A friend you never added appears**, or a friend's key changes when you
  did not expect it: remove them and add them again in person.

  ```sh
  raven contact remove --petname Sam
  ```

## 11. Quick card

Five habits:

1. Compare security words in person.
2. Use nicknames.
3. Turn on disk encryption and use a login password.
4. Run `raven lock` and lock the screen when you leave the laptop.
5. Turn the local network off on networks you don't trust (`raven lan off`).

Three meeting steps:

1. Make the network (hotspot or cable) and join it.
2. The receiver runs `raven listen`; the sender types the address it shows.
3. Wait for "delivered", then stop listening.

## 12. What is in this version

Each row marked "not in this version" is held off in release builds by a
switch in the code; `scripts/check_offline_guide.sh` fails when a switch
named here changes, so this table is updated with it.

| Feature | This version |
|---|---|
| Messages over a local network (router, hotspot, cable) with typed addresses <!-- gate: LAN_DIRECT_PRODUCTION_ENABLED=true --> | Yes |
| Stop before telling another computer at a friend's old address who you are <!-- gate: LAN_NOISE_PIN_PRODUCTION_ENABLED=false --> | Not in this version (being reviewed) |
| Keep a message for a friend whose computer name is not found; retry waiting friends at once when one answers; notice a cable network at once; reach a friend added without an address at the address they last connected from <!-- gate: OFFLINE_LAN_PRODUCTION_ENABLED=false --> | Not in this version (being reviewed) |
| Learn a friend's new address or port automatically <!-- gate: ROUTE_HINTS_PRODUCTION_ENABLED=false --> | Not in this version |
| Turning the local network off, on only for a meeting, or on for verified friends only (section 4) | Yes |
| A random local-network port instead of 7420 (section 4) <!-- gate: LISTEN_PORT_RANDOM_PRODUCTION_ENABLED=false --> | Not in this version |
| Hiding message sizes on the network (section 4) <!-- gate: LINK_PADDING_PRODUCTION_ENABLED=false --> | Not in this version |
| A new key for every connection with a friend; a new key, or no answer, for strangers (section 4) <!-- gate: LINK_KNOCK_PRODUCTION_ENABLED=false --> | Not in this version |
| Friends who hold messages for you (section 9) <!-- gate: FRIEND_CUSTODY_PRODUCTION_ENABLED=false --> | Not in this version |
| Two friends in a row: one passes a message on to the other (section 9) <!-- gate: CUSTODY_HANDOFF_PRODUCTION_ENABLED=false --> | Not in this version |
| Messages over the internet or through relays <!-- gate: INTERNET_DIRECT_PRODUCTION_ENABLED=false --> <!-- gate: P2P_PRODUCTION_ENABLED=false --> | Not in this version |
| Finding friends on a new network without typing an address (nearby search, section 4) <!-- gate: LAN_BEACON_PRODUCTION_ENABLED=false --> | Not in this version |
| Raven over Bluetooth (`raven nearby`) <!-- gate: NEARBY_PRODUCTION_ENABLED=false --> | Not in this version |
| Messages that wait longer than a day | Not in this version |
| Encrypting what Raven keeps about your friends on this computer (section 5) | Yes |
| Deleting old chats automatically, deleting one chat, forgetting learned addresses (section 6) | Yes |
| `raven lock`: stop Raven and keep it stopped (section 5) | Yes; it really locks only a profile with a Raven passphrase |
| Erasing Raven's data (section 7) | Yes |
| A lock that keeps Raven running but makes it forget its keys, locking when the laptop sleeps, a Raven passphrase on a Mac (section 5) <!-- gate: LOCAL_PROTECTION_PRODUCTION_ENABLED=false --> | Not in this version |
| Security notices: what Raven noticed and what it did (`raven security`, section 10) <!-- gate: SECURITY_EVENTS_PRODUCTION_ENABLED=false --> | Not in this version |
| Raven answering by itself: making a stranger who floods your laptop wait, a new secure connection after a suspicious message, trying another way to a friend first (section 10) <!-- gate: SECURITY_RESPONSES_PRODUCTION_ENABLED=false --> | Not in this version |
| Security notices from the Raven project, and Raven updates checked by its keys, from a file or passed on by friends (section 10) <!-- gate: ADVISORY_PRODUCTION_ENABLED=false --> <!-- gate: RELEASE_BUNDLE_PRODUCTION_ENABLED=false --> <!-- gate: MESH_UPDATE_PRODUCTION_ENABLED=false --> | Not in this version |
| Keys for nearby search and the knock that you and each friend change every week <!-- gate: PAIR_SEED_PRODUCTION_ENABLED=false --> | Not in this version |
