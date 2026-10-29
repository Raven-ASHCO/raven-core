# Privacy pack real row R34 (operator checklist)

**Status:** owner-run, **open**. Owner equipment only: a Mac, a Linux desktop
and a Windows PC. The pack itself is described in
[`design/2026-10-at-rest-metadata.md`](design/2026-10-at-rest-metadata.md);
what users are told is [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) sections 5-8;
the threat rows are [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.7a.

## 0. Purpose and honest claim

- These rows check what only real keystores, real login items and real
  backups can show: the macOS keychain (its dialogs, which follow the
  binary's signature), the Secret Service keyring, the Linux passphrase
  vault, Windows DPAPI, launchd / systemd / Task Scheduler, and Time Machine,
  APFS snapshots and Windows restore points. Every other part of the pack is
  covered by unit tests, carrier_matrix C87, C90 and C91 and fault scenarios
  s117 and s120-s125, all with lab key backends and fake login-item tools.
- **Release builds only.** A debug build seals a profile only with the lab
  switch `RAVEN_LAB_AT_REST=1`, refuses `raven erase` outside
  `RAVEN_LAB_ERASE_ROOT`, and never reads or runs a real login item, so it
  cannot run these rows (by design: a debug binary pointed at a real profile
  changes nothing).
- Nothing here flips a gate. The results go to the pack's exit record and its
  review (section 6).

## 1. Safety first

- **A separate OS user account** made for this test on each machine. It has
  its own keychain or keyring and its own login items. Raven's login item is
  one per OS user (`com.raven.raven-node`, `raven-node.service`,
  `RavenNodeBridge`): installing it for a test profile in your own account
  replaces the one that runs your real Raven.
- **Test profiles only**, made for this test under `~/raven-r34/` in that
  account. Never `~/.raven`, never a profile in use, and never a profile an
  older Raven binary still runs: the new build seals it at its first start,
  and older builds then refuse it.
- **Ports.** A Raven node of any account that already listens on 7420 (or
  7421, 7422, 7423, 7427) holds that port for the whole machine. 7421 is
  where every `raven-node service` runs its local Bluetooth stand-in unless
  told otherwise (`--ble-listen`), and Raven's own login item uses it too:
  two nodes started without `--ble-listen` take it from each other (and from
  your real Raven's node). Give the test nodes other ports: `--lan-listen`
  7441 for A, 7442 for B, 7443 for C, 7444 for D and 7445 for E below, and
  `--ble-listen 127.0.0.1:0` (any free port) on every one.
- **Windows:** the IPC pipe is per user, not per profile, so only one test
  profile per user account can run a node there. Run the friends B and E on
  another computer or in another user account.
- Stop every node you start by its process id; end with section 7.

## 2. Builds

Two release builds, side by side, outside the repository:

```bash
git clone https://github.com/Raven-ASHCO/RAVEN-v2.git ~/raven-r34/src-new
git -C ~/raven-r34/src-new checkout <the commit under test>
git clone https://github.com/Raven-ASHCO/RAVEN-v2.git ~/raven-r34/src-old
git -C ~/raven-r34/src-old checkout d0e4fd3        # the last commit before the pack
(cd ~/raven-r34/src-new/node && CARGO_TARGET_DIR=~/raven-r34/target-new cargo build --locked --release -p ash -p raven-node)
(cd ~/raven-r34/src-old/node && CARGO_TARGET_DIR=~/raven-r34/target-old cargo build --locked --release -p ash -p raven-node)
NEW=~/raven-r34/target-new/release; OLD=~/raven-r34/target-old/release
A=~/raven-r34/a; B=~/raven-r34/b; C=~/raven-r34/c; E=~/raven-r34/e
```

On Windows the same in PowerShell (`$NEW\raven.exe`). For the macOS keychain
row (R34.4) also keep a second unsigned build of the same commit (touch one
source file and build again: the new binary has another ad-hoc signature),
and, if one exists, a signed release (see
[`SIGNING_NOTARIZATION_CHECKLIST.md`](SIGNING_NOTARIZATION_CHECKLIST.md)).

## 3. Profiles to cover

| System | Keystore | How the profile gets it |
|---|---|---|
| macOS | login keychain | the default |
| macOS | a passphrase vault | **not in this build**: the vault is Linux-only (macOS keeps keys in the keychain, Windows in DPAPI); a Raven passphrase on macOS is Phase 6. Record "n/a". |
| Linux | Secret Service | a desktop session with an unlocked keyring (the default when one answers) |
| Linux | passphrase vault | `RAVEN_KEYSTORE_BACKEND=vault` for `init`, with the passphrase typed or in `RAVEN_KEYSTORE_PASSPHRASE_FILE` |
| Windows | DPAPI | the default |

Use distinctive names, so a search cannot match by chance: A calls B
`BobR34`, B calls A `AliceR34`.

## 4. The rows

### R34.1 Seal an existing profile

1. With the older build, make A and B, start both nodes, add each other, and
   exchange two messages each way:

   ```bash
   $OLD/raven --data-dir $A init; $OLD/raven --data-dir $B init
   $OLD/raven-node service --data-dir $A --lan-listen 127.0.0.1:7441 --ble-listen 127.0.0.1:0 > ~/raven-r34/a.log 2>&1 & A_PID=$!
   $OLD/raven-node service --data-dir $B --lan-listen 127.0.0.1:7442 --ble-listen 127.0.0.1:0 > ~/raven-r34/b.log 2>&1 & B_PID=$!
   $OLD/raven --data-dir $B whoami        # B's address, pub_hex and fingerprint
   $OLD/raven --data-dir $A contact add --address <B address> --pub-hex <B pub_hex> --petname BobR34 --tag bobr34 --lan-dial 127.0.0.1:7442 --verify-fp <B fingerprint>
   # the same on B for A (AliceR34, 127.0.0.1:7441), then:
   $OLD/raven --data-dir $A send --contact BobR34      # type the text, Ctrl-D
   ```

   Then a friend A removes before the upgrade: make E with the older build
   (`--lan-listen 127.0.0.1:7445 --ble-listen 127.0.0.1:0`), add each other
   (A calls E `EveR34`), send E one message from A, then remove her and stop
   her node:

   ```bash
   $OLD/raven --data-dir $A contact remove --petname EveR34 --yes
   ```

   Write down E's pub_hex (`E_PUB`). The older build named its per-friend
   send locks by the friend's key, and removing a friend leaves hers:
   `ls -a $A | grep -i "$E_PUB"` prints `.send_<E_PUB>.lock.sqlite`.
   Windows, the upgrade window (review A-keys-format-2): while A's and B's
   older nodes still run, send B one message with the new build
   (`$NEW\raven.exe --data-dir $A send --contact BobR34`). **Pass:** it says
   "Raven was updated. Restart Raven so it can finish the update: ...",
   nothing is sealed (`$NEW\raven.exe --data-dir $A privacy status`), no
   `chat_history_key.dpapi` appears in A, and A's older node still records
   and acknowledges B's next message (it shows in `$OLD\raven.exe --data-dir
   $A inbox`, and B sees it delivered).
2. Stop B (`kill $B_PID`), send one more message from A (it waits), stop A.
   Write down B's pub_hex and address (`B_PUB`, `B_ADDR`).
3. Start A's node with the new build and, before anything else, look for
   file names that hold a friend's key; then B's node:

   ```bash
   $NEW/raven-node service --data-dir $A --lan-listen 127.0.0.1:7441 --ble-listen 127.0.0.1:0 > ~/raven-r34/a-new.log 2>&1 & A_PID=$!
   # once a-new.log says `raven-node at_rest: sealed`:
   find $A -iname "*$B_PUB*" -o -iname "*$E_PUB*"
   $NEW/raven --data-dir $A status
   $NEW/raven --data-dir $A privacy status
   find $A -iname "*$B_PUB*" -o -iname "*$E_PUB*"
   ```

**Pass:** the first `find` prints nothing for E (A's waiting message to B
may hold B's lock for a moment, so it may print B's once), and the second
prints nothing at all (review E-harness-docs-ci-1: no send to E and no
`raven contact remove` of her would ever delete hers; on Windows
`Get-ChildItem -Force $A | Where-Object Name -match "$B_PUB|$E_PUB"`); A's
log says `raven-node at_rest: sealed N file(s)` and then `raven-node at_rest:
sealed`; the first `raven status` prints the sealing
notice once ("Raven now encrypts your friends list, ...") and on macOS the
keychain line; `raven privacy status` says "Encrypted on this computer:
friends list, addresses, message records (N files, M databases)"; once B's
node runs the new build too, the waiting message arrives once and both ways
deliver. Record whether a keychain dialog appeared at A's start (macOS).

### R34.2 No friend data readable on disk

Stop both nodes. Open A's `contacts.json`, `lan_seen.json`,
`learned_routes.json` and `chat_history.json` in the file browser's preview
(Finder Quick Look, the Linux file manager, Explorer): no readable names or
addresses. Then:

```bash
find $A -iname "*$B_PUB*" -o -iname "*$E_PUB*"
find $A -type f -exec sh -c 'strings -n 5 "$1" | grep -qi -e bobr34 -e ever34 -e "$2" -e "$3" -e "$4" -e 127.0.0.1 && echo "$1"' _ {} "$B_PUB" "$B_ADDR" "$E_PUB" \;
```

**Pass:** both print nothing. Record any file they print, with its rule from
the design's section 6. On Windows use `Select-String -Path <file> -Pattern
...` over every file.

To cover the full-screen app too, first open it on A once (`$NEW/raven
--data-dir $A`), set Settings > Your name to `AliceR34`, open the chat with
BobR34 so a message is marked read, and quit (stop A's node again if the app
started it); then run the commands above with `-e alicer34` added to the
second. **Pass:** still nothing: `tui_state.json` holds neither B's key nor
the name (since PP.24 they are in the sealed `tui_private.rms`), and the next
start of the app shows the name and the chat as read.

Without the app saving first (review D-lock-tui-1): on a profile whose
`tui_state.json` an app before PP.24 wrote (a name set, a chat read), seal it
with the new build by a command only (`$NEW/raven --data-dir <dir> privacy
status`), never opening the app. **Pass:** the second command above (with the
name and the friend's key added) prints nothing, `privacy status` shows no
"Not encrypted yet" line, and the app opened afterwards shows the name and the
chat as read.

### R34.3 `raven lock` with Raven's own login item

Install Raven's own login item for A in the test account (it builds from the
tree it runs in, so run it from `~/raven-r34/src-new`):

```bash
RAVEN_DATA_DIR=$A RAVEN_LAN_LISTEN=127.0.0.1:7441 RAVEN_BLE_LISTEN=127.0.0.1:0 RAVEN_BIN_DIR=~/raven-r34/bin bash node/scripts/install/macos_launchd.sh
# Linux: node/scripts/install/linux_systemd_user.sh with the same variables
# Windows: node\scripts\install\windows_service.ps1 -DataDir <A> -LanListen 127.0.0.1:7441 -BleListen 127.0.0.1:0 -BinDir <dir>
```

1. `$NEW/raven --data-dir $A lock`, and answer **no** to "Keep Raven stopped
   until you start it yourself?". **Pass:** "Raven is stopped until you log in
   again."; for a full minute no `raven-node service --data-dir <A>` runs
   (`pgrep -fl raven-node`), so launchd (or systemd, or the task's restart
   count) did **not** start it again; after a log-out and log-in it runs
   again.
2. `$NEW/raven --data-dir $A lock` again, answer **yes**. **Pass:** "Raven is
   stopped."; it stays stopped across a log-out and log-in (wait two minutes);
   `$NEW/raven --data-dir $A doctor` shows `lock: locked_by_user=1` with
   `login_item=disabled`.
3. While locked: `$NEW/raven --data-dir $A send --contact BobR34`. **Pass:**
   `NOT SENT, nothing queued: Raven is locked. Run `raven unlock` to start it
   again.`, and no raven-node starts.
4. `$NEW/raven --data-dir $A unlock`. **Pass:** "Raven is running. Friends
   can reach you."; the login item is on again (`launchctl print
   gui/$(id -u)/com.raven.raven-node`, `systemctl --user status raven-node`,
   or the task in Task Scheduler) and B's next message arrives.
5. Linux vault profile: the lock question says "Lock Raven now? ... Your
   chats can't be opened again without your passphrase."; after `raven
   unlock` the node opens the vault only with the passphrase (its file), and
   without it Raven says it can't open your friends list.
6. The full-screen app (PP.23): with the item on and Raven running, open
   `RAVEN_UI=tui $NEW/raven --data-dir $A` and press L on the friends list.
   **Pass:** the question ends with "Raven starts again when you log in. To
   keep it stopped, run `raven lock` in a terminal."; Enter leaves "Raven is
   stopped until you log in again." on a cleared terminal; for a full minute
   no `raven-node service --data-dir <A>` runs; `$NEW/raven --data-dir $A
   doctor` shows `lock: locked_by_user=1` with `login_item=unloaded`; the
   item is still on (not listed by `launchctl print-disabled gui/$(id -u)`,
   `systemctl --user is-enabled raven-node` says enabled, the task is
   Ready); after a log-out and log-in it runs again.
7. `$NEW/raven --data-dir $A lock`, answer **yes** (the item turned off),
   then open the app again (with B saved and receiving on). **Pass:** the
   app asks "Raven is locked ... Start Raven again now?" before anything
   starts (review E-harness-docs-ci-3); **Esc** keeps it stopped: for a full
   minute no `raven-node service --data-dir <A>` runs and `raven doctor`
   (in another terminal) still shows `locked_by_user=1`. Quit, open the app
   again and press **Enter**: `raven doctor` shows `locked_by_user=0` with
   `login_item=disabled`; the app starts Raven and says "Raven is running
   again. Raven's login item stays off until you run `raven unlock`."; the
   item stays off until `$NEW/raven --data-dir $A unlock`.
8. Right after step 7 (before `raven unlock`), press L in the app (review
   D-lock-tui-7). **Pass:** LOCK says "Raven's login item stays off until you
   run `raven unlock`." and not "Raven starts again when you log in"; Enter
   leaves "Raven is stopped." ("Raven is locked." on a vault profile); after a
   log-out and log-in Raven does not run.
9. Linux vault profile installed with a passphrase file the shell does not
   name (review D-lock-tui-2, -3): run `linux_systemd_user.sh` with
   `RAVEN_KEYSTORE_PASSPHRASE_FILE=<a custom path>`, once more with
   `RAVEN_SYSTEMD_LOAD_CREDENTIAL=1`, then, in a shell without that variable,
   `$NEW/raven --data-dir $A lock` and the app's L. **Pass:** both questions
   say "Your passphrase is saved in a file on this computer (<the custom
   path>). Anyone who can read your files can unlock Raven with it. ...".
10. Windows, a `raven lock` that cannot stop Raven (review D-lock-tui-4):
    with the task installed, end its node (`schtasks /End /TN
    RavenNodeBridge`), start A's node from another terminal (`$NEW/raven
    --data-dir $A listen`), then `$NEW/raven --data-dir $A lock` and answer
    **yes**.
    **Pass:** "Raven is still running, so it isn't locked. ..."; the task is
    still Ready (not Disabled) in Task Scheduler, and at the next log-in it
    starts Raven.

### R34.4 raven-node's start and the keychain dialog (macOS)

The sealed profile's node reads the chat-history key when it starts (before
the pack it did so at the first received chat).

1. After the second unsigned build of the same commit: start A's node with
   it. Record whether a keychain dialog appears at start. Choose **Deny**.
   **Pass:** the node keeps running and admits nobody; `raven status` says
   "Raven can't open your friends list: it needs your keychain ..."; over 10
   minutes at most one dialog per retry step (record each dialog's time),
   also while the terminal app (`raven` with no command) stays open: its
   status poll never asks for a try (review B-sealed-stores-6). `raven
   status` retries at once (one dialog): choose Always Allow, and B's next
   message arrives.
2. With a signed release, if there is one: record whether an update between
   two signed builds shows a dialog.
3. Linux: with the keyring locked the same "can't open" text, and receiving
   resumes after unlocking it. Windows: no dialog (record).

### R34.5 Delete a chat, change the data key, and an old copy

```bash
cp $A/chat_history.json ~/raven-r34/history-copy.bin
$NEW/raven --data-dir $A privacy status --verify-copy ~/raven-r34/history-copy.bin
$NEW/raven --data-dir $A chats delete --petname BobR34
$NEW/raven --data-dir $A privacy rotate-now --drop-now
$NEW/raven --data-dir $A privacy status --verify-copy ~/raven-r34/history-copy.bin
```

(`rotate-now` and `--verify-copy` are hidden commands for this row; type
`delete` and `rotate` when asked.) Before: count the `app.raven.node.*` items
in Keychain Access (Seahorse on Linux; nothing to count on Windows).

**Pass:** the first check says "This file opens with this profile's current
keys.", `rotate-now` says "The old key is gone: copies of deleted data no
longer open with this computer's keys.", the second check says "This file
does not open with this profile's current keys."; no keychain dialog
appeared and the item count is unchanged.

Then `$NEW/raven --data-dir $A privacy rotate-meta` (type `rotate`; it stops
Raven first). **Pass:** afterwards `raven contact list` and `raven inbox` read
as before, both ways deliver once the node runs again, no new keychain item,
no dialog.

### R34.6 Erase a second profile

1. Make C with the new build (port 7443), add B, exchange a message, and let
   the backups you use run once (Time Machine, or note the APFS local
   snapshots: `tmutil listlocalsnapshots /`; Windows restore points in System
   Protection; Linux file-system snapshots, if any).
2. Count the `app.raven.node.*` items again, then in a terminal:

   ```bash
   $NEW/raven --data-dir $C erase      # type erase
   ```

**Pass:** "Erased: identity, friends, chats, waiting messages and N keys. Not
erased: ..."; C's folder is gone (or holds only files Raven didn't create,
listed); C's keychain items are gone and A's stay (the count is back to what
it was before C); A's login item is untouched; A and B still exchange.
Record whether deleting the items showed a keychain dialog (macOS), and
**what the backups and snapshots taken while C existed still hold** (C's
folder, the keychain with C's chat-history key): Raven cannot erase them.

3. macOS, an erase that fails part-way (review C-deletion-erase-1): make a
   profile D like C (port 7444), exchange a message with B so D holds a
   conversation key, and count the `app.raven.node.atsam-indexed-session`
   items in Keychain Access. Lock the login keychain (`security
   lock-keychain`), run `$NEW/raven --data-dir $D erase` and cancel the
   password dialog (or answer **Deny** to an access dialog). **Pass:**
   "Erase stopped: ... a conversation key (the keychain) could not be
   deleted ... Still on this computer: ..., indexed_sessions.sqlite. Run
   `raven erase` again to finish."; D's folder still holds
   `indexed_sessions.sqlite` and `erase_in_progress`. Unlock the keychain and
   run `$NEW/raven --data-dir $D erase` again. **Pass:** "Erased: ..."; none
   of D's session items is left (the count is back to what it was before D)
   and A's stay. Record every dialog of both runs: the search for D's items
   reads attributes only and should show none.
4. Windows, the app's erase after its LOCK (review D-lock-tui-5): a profile
   E with Raven's own task installed (`windows_service.ps1 -DataDir <E>`,
   port 7445). Open the app on E, press L and Enter (the task's node ends),
   open the app again (it starts its own raven-node.exe), then Settings >
   Erase Raven from this computer, type erase. **Pass:** "Erased: ..." (the
   app ended its own node); not "Raven is still running, so erase can't
   continue".

### R34.7 The way back: `raven privacy unseal` and the older build

1. Before unsealing, the older build on the sealed profile:
   `$OLD/raven --data-dir $A contact list`. **Pass:** an error naming
   `contacts.json`; afterwards `$NEW/raven --data-dir $A privacy status` is as
   before.
2. `$NEW/raven --data-dir $A privacy unseal` (type `unseal`; it stops Raven
   first). **Pass:** "Done. You can now start the older Raven version.";
   `$OLD/raven --data-dir $A contact list` lists BobR34; A's node on the older
   build and B exchange both ways; every new-build command on A prints "This
   profile is not encrypted (you ran `raven privacy unseal`). ...".
3. Stop the older node, then `$NEW/raven --data-dir $A privacy seal-now`.
   **Pass:** sealed again (`raven privacy status`), both ways deliver.
4. Record any keychain dialog during unseal or seal-now (macOS), and on
   Windows that the older build reads the chat history after the unseal.

### R34.8 A key that is gone from the keystore

Review A-keys-format-4: a sealed profile whose chat-history key is no longer
in the keystore (a new login keychain, a profile copied to another account)
must say so, not "answer the keychain dialog". Nothing here deletes a
keychain item: copy a sealed test profile into the second test account.

1. Stop A's node, copy A's folder into the other test account (or another
   computer), and there run `$NEW/raven --data-dir <copy> status`. **Pass:**
   the `at_rest` row says "LOCKED — Raven can't open your friends list: its
   key is gone", followed by "Raven can't open your friends list: the key
   that encrypts this profile is no longer in your keychain ..."; no keychain
   dialog (macOS) and no keychain item created; nothing in the copy changes
   (compare file sizes and times before and after).
2. Start a node on the copy (port 7445, `--ble-listen 127.0.0.1:0`). **Pass:**
   `raven doctor` says `at_rest: state=key_lost`; the node log says "its key
   is gone" once, and the node tries again at most every 15 minutes (and at
   once on `raven status`).
3. Windows: the same in another Windows account (DPAPI no longer unwraps
   `chat_history_key.dpapi`). Linux: the same with another user's keyring.
   Stop the node by its process id and delete the copy.

## 5. What these rows cannot show

- Pieces of old files in free disk space (what a profile held before it was
  sealed, deleted records, the old frames of a SQLite log): that needs
  forensic tools, and only full-disk encryption covers it.
- Anyone who can log in as the test user opens everything (T3b): not a row.

## 6. Record (each row, each system and keystore)

- Pass or fail, and the exact texts seen.
- Keychain or keyring dialogs: how many, when, and the answer given.
- For R34.6: what each backup or snapshot still holds.
- The commit hashes (new and old builds), signed or unsigned, the OS version,
  the date (UTC) and the operator's role.

## 7. Clean up

Erase A and B with the new build (`raven erase`), remove Raven's login item
for A if it is still there (the installer's uninstall step, or `raven erase`
removes it), delete `~/raven-r34`, and delete the test user account.
