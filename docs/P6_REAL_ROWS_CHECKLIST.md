# Phase 6b real rows (operator checklist): attack sensing, traffic analysis, Lock v2 and updates

**Status:** owner-run, **open**. Owner equipment only. The checklist for the
Phase 6b rows of the merged Phase 6 plan (`docs/roadmap/plans/phase6-design.json`,
designs P6b-A to P6b-D, step P6.52). Results go to
`node/proof_artifacts/p6b-<ROW>-<UTC>/` (git-ignored) with public IPs, MAC
addresses, computer names and network names left out, and are attached to the
signature record of the waiver draft that names the row. Nothing here is
signed and no gate is flipped.

| Row | What | Waiver draft | Section | Runs now |
|---|---|---|---|---|
| R30 | Tamper and flood on a hotspot the owner controls (a third laptop as the router, running the tampering proxy) | [`WAIVER_SECURITY_SENSING_DRAFT.md`](WAIVER_SECURITY_SENSING_DRAFT.md) §7 | 3 | **No: waits for P6.32** (its proxy modes are set aside by the owner, 2026-10-23) |
| R31 | Three laptops with no uplink pass a security notice and a release | [`WAIVER_SECURITY_UPDATES_DRAFT.md`](WAIVER_SECURITY_UPDATES_DRAFT.md) §7 | 4 | Yes (`node/scripts/update_mesh_test.sh`) |
| R32 | Key-ceremony dry run with keys made for it, on an offline machine | [`WAIVER_SECURITY_UPDATES_DRAFT.md`](WAIVER_SECURITY_UPDATES_DRAFT.md) §7; [`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md) §8 | 5 | Yes |
| R33 | Reproducible build on two machines | [`WAIVER_SECURITY_UPDATES_DRAFT.md`](WAIVER_SECURITY_UPDATES_DRAFT.md) §7 | 6 | Yes |
| R35 | A meeting on a hotspot the owner controls, captured with tcpdump: sizes in the four classes, handshake shapes, silent mode | [`WAIVER_TRAFFIC_ANALYSIS_DRAFT.md`](WAIVER_TRAFFIC_ANALYSIS_DRAFT.md) §7 | 7 | Yes, except the statics (a capture cannot show them: section 7) |
| R37 | Lock v2, auto-lock on sleep and the Raven passphrase on macOS (keychain and passphrase), Linux (vault) and Windows (DPAPI) | [`WAIVER_LOCAL_PROTECTION_DRAFT.md`](WAIVER_LOCAL_PROTECTION_DRAFT.md) §7 | 8 | Yes |

Listed here, run elsewhere:

- **R34** (sealing, `raven lock` v1 and `raven erase` on real keystores)
  belongs to the privacy pack:
  [`PRIVACY_PACK_REAL_ROWS_R34_CHECKLIST.md`](PRIVACY_PACK_REAL_ROWS_R34_CHECKLIST.md).
- **R36** (alert texts in another language) is dropped: Raven is English only
  (owner rule, 2026-10-16).
- **L1-L4**, the Phase 6a learning rows (step P6.19), come with 6a's documents:
  the design record
  [`design/2026-10-learning-connectivity.md`](design/2026-10-learning-connectivity.md),
  the unsigned [`WAIVER_LEARNING_DRAFT.md`](WAIVER_LEARNING_DRAFT.md) and the
  checklist [`P6A_REAL_ROWS_CHECKLIST.md`](P6A_REAL_ROWS_CHECKLIST.md).

## 0. Purpose and honest claim

- Real networks, real machines and real keystores. Every
  `*_PRODUCTION_ENABLED` gate stays `false`: the rows run **debug builds** of
  this tree with lab switches, exported in the shell on every machine before
  every command (each row lists its set, always with `RAVEN_LAB_TEST_A=1`).
  Release builds never read these switches. R32 and R33 build release
  programs to sign or compare them; R37 is the one row that also runs a
  release build, to show that the gate keeps it shut (section 8, R37.7).
- Software stand-ins do not replace these rows: carrier_matrix C86, C88 and
  C89 (C87 is the privacy pack's, also run with every Phase 6 switch on),
  fault matrix s04r, s115, s116, s118 and s119, the dry run of
  `node/scripts/update_mesh_test.sh` and the unit tests of P6.21-P6.51 run
  every node on one computer's loopback.
- **Test homes only:** a `--data-dir` made for the row (or the R31 kit's
  test home), never `~/.raven`, a profile in use, or a profile an older Raven
  binary still runs: this tree seals a profile at its first start (a debug
  build with `RAVEN_LAB_AT_REST=1`) and older builds then refuse it.
- **Ports:** never 7420-7427, which a Raven node of any account on the machine
  may hold. The test nodes below listen on 7451, 7452 and 7453 (the R31 kit
  on 47431) and run their local Bluetooth stand-in on any free port
  (`--ble-listen 127.0.0.1:0`). On a machine that runs another Raven node,
  check that the port is free and record it.
- Stop every node you start by its process id (`kill <pid>`), never by name.
- **Passive listening cannot be detected.** No row tries to show that Raven
  notices someone who only listens; R35 records what such a listener sees.

## 1. The Phase 6b gates and their state

Every gate below is `false` in this tree (`node/crates/raven-core/src/security_gate.rs`).
A debug build opens one with its lab switch and `RAVEN_LAB_TEST_A=1`; a gate
that sits on another is live only while that one is. `scripts/check_doc_pointers.sh`
fails when a gate's state in the code and in this table differ.

| Gate | Lab switch | Sits on | Holds | Waiver draft | Rows |
|---|---|---|---|---|---|
| `SECURITY_EVENTS_PRODUCTION_ENABLED = false` | `RAVEN_LAB_SECURITY_EVENTS` | | the `SEC_*` events, the security ledger, `raven security`, the app's SEC overlay | [`WAIVER_SECURITY_SENSING_DRAFT.md`](WAIVER_SECURITY_SENSING_DRAFT.md) | R30 |
| `SECURITY_RESPONSES_PRODUCTION_ENABLED = false` | `RAVEN_LAB_SECURITY_RESPONSES` | events | the automatic responses R1-R8 (the penalty box, early re-key, path, address, custodian, depositor and relay answers) | the same | R30 |
| `SUITE_FLOOR_PRODUCTION_ENABLED = false` | `RAVEN_LAB_SUITE_FLOOR` | events | refusing a session profile below a contact's floor (R9) | the same | none (one session profile exists) |
| `LINK_PADDING_PRODUCTION_ENABLED = false` | `RAVEN_LAB_LINK_PADDING` | | PAD1 link padding | [`WAIVER_TRAFFIC_ANALYSIS_DRAFT.md`](WAIVER_TRAFFIC_ANALYSIS_DRAFT.md) | R35 |
| `LINK_KNOCK_PRODUCTION_ENABLED = false` | `RAVEN_LAB_LINK_KNOCK` | (release: M0) | the RLK1 knock, per-connection Noise statics, silent mode | the same | R35 |
| `LISTEN_PORT_RANDOM_PRODUCTION_ENABLED = false` | `RAVEN_LAB_RANDOM_PORT` | | a random LAN port for new profiles | the same | none (s04r in software) |
| `PAIR_SEED_PRODUCTION_ENABLED = false` | `RAVEN_LAB_PAIR_SEED` | route hints | pair-seed rotation | the same | none defined |
| `LOCAL_PROTECTION_PRODUCTION_ENABLED = false` | `RAVEN_LAB_LOCAL_PROTECTION` | | Lock v2, auto-lock on sleep, the Raven passphrase | [`WAIVER_LOCAL_PROTECTION_DRAFT.md`](WAIVER_LOCAL_PROTECTION_DRAFT.md) | R37 |
| `ADVISORY_PRODUCTION_ENABLED = false` | `RAVEN_LAB_ADVISORY` | | security notices (RAD1) and the release log (RTL1) | [`WAIVER_SECURITY_UPDATES_DRAFT.md`](WAIVER_SECURITY_UPDATES_DRAFT.md) | R31, R32 |
| `RELEASE_BUNDLE_PRODUCTION_ENABLED = false` | `RAVEN_LAB_RELEASE_BUNDLE` | advisory | release bundles (RRB1), `raven update` import, install, rollback | the same | R31, R32, R33 |
| `MESH_UPDATE_PRODUCTION_ENABLED = false` | `RAVEN_LAB_MESH_UPDATE` | bundle | passing notices and releases between friends (RUP1) | the same | R31 |

Gates of earlier phases these rows touch, also `false`: M0
(`LAN_NOISE_PIN_PRODUCTION_ENABLED`; a release build never has the knock
without it) and route hints (`ROUTE_HINTS_PRODUCTION_ENABLED`; pair seeds sit
on it). No build of this tree has the Raven project's release keys
(`RELEASE_KEY_SET_V1 = None`): until the key ceremony, every update artifact
is refused even with the update gates open, except in a debug build given a
key set file with `RAVEN_LAB_RELEASE_KEYS_FILE` (R31, R32).

**Flip order proposed** (OD6b-1, as decided): events, then responses, padding,
the knock, local protection (Lock v2), advisory, bundle, mesh update; the
random port, pair seeds and the suite floor when what they sit on is live.
Each flip needs the owner's own approval and its own signed waiver; nothing
here approves one.

## 2. Record for every row

`node/proof_artifacts/p6b-<ROW>-<UTC>/` holds:

- `row.txt`: the row, the date, the commit under test, who ran it, the OS
  and CPU of each machine, each network by kind only (a travel router with
  its WAN port unplugged, a laptop's own hotspot), the lab switches exported,
  the ports used;
- what each step below says to keep (command output, `raven status`,
  `raven security --json`, `raven update status`, a capture's summary);
- the pass or fail against each bar, and anything that surprised you.

Never put in it a passphrase, a key file, a private key, a public IP, a MAC
address, a computer name or a network name. Captures (R35) stay on the
capturing laptop; only their summary goes in the record.

## 3. R30: tamper and flood on an owner-controlled hotspot (waits for P6.32)

**Cannot run yet.** The row needs P6.32's attack harness: the tampering proxy
modes (`flip`, `replay`, `inject`, `flood`) on a third laptop that is the
hotspot and the router, the debug switches that make a node misbehave on
purpose (`RAVEN_LAB_SEC_DESYNC`, `RAVEN_LAB_SEC_DROP_CAPS`,
`RAVEN_LAB_SEC_BAD_CUSTODIAN`) and the harness rows C80-C85 and s110-s114.
None of them is built: the owner set P6.32 aside on 2026-10-23. Nothing in
this tree tampers with a live link on purpose, so the steps are written when
P6.32 lands.

What the row will show then (design A, testing):

- every tampered frame fails its Noise tag: the link closes and
  `SEC_LINK_TAG_FAIL` is noted against the contact's path on that network
  (R4 puts that path last for 10 minutes at Suspicious);
- replayed handshakes, knocks and objects are refused (`SEC_KNOCK_REPLAY`,
  `SEC_OBJECT_REPLAY`; R2's early re-key for an object replay);
- a stranger's flood is banned by the penalty box (`SEC_PREAUTH_FLOOD`, R1)
  while the contacts keep their links;
- the honest contact still gets every message exactly once;
- with no attack, zero Alerts and no ban of a contact over the whole run (the
  false-positive budget of OD6b-2).

Covered meanwhile in software only: the unit and in-process tests of
P6.24-P6.29 (duplex Noise pairs with a flipped byte, scripted stranger
handshakes, the penalty box with an injected clock, the R2/R3 two-profile
fixtures) and carrier_matrix C86, whose proxy records and never tampers.

## 4. R31: three laptops with no uplink pass a notice and a release

**Gear:** three laptops A, B and C (macOS or Linux; the kit is a bash script
and runs with bash 3.2 too), one Wi-Fi network with no uplink: a travel
router with its WAN port unplugged, checked by hand (never by contacting the
internet). Each laptop has a checkout of the commit under test and its
toolchain. The kit uses the locked-file test backends, the published **test**
release keys (anyone can sign with them, so only these test profiles trust
them) and port 47431; it copies the programs into its test home and runs
everything from there.

Before the row, on any one computer:

```bash
node/scripts/update_mesh_test.sh dry-run
```

**Pass:** `PASS` (A, B and C on loopback with the lab approval; not an R31
claim).

Then:

1. On each laptop: `node/scripts/update_mesh_test.sh setup A <its IP on this
   network>` (B and C likewise). Each prints its line for `add`.
2. Add verified contacts in a chain, comparing each fingerprint with the other
   laptop's screen: on A `add B ...`, on B `add A ...` and `add C ...`, on C
   `add B ...`. A and C never know each other.
3. On A: `node/scripts/update_mesh_test.sh publish` (test notice #1 and test
   release 5, listed in a test release log, imported on A).
4. On B: `link A`, wait a minute, `status`, then `approve` (lists the offer)
   and `approve <CODE>` (answer `y`), wait, `status`.
5. On C: `link B` once B says the release is downloaded and checked, wait a
   minute, `status`, `approve`, `approve <CODE>`, wait, `status`.
6. On each: `report R31`, then `stop`.

**Pass:**

- B's `status` names security notice #1 within a minute of its `link`, and
  C's within a minute of its own, with no command on either;
- each offer is listed before its approval and nothing of the release is
  fetched until the person answers `y`;
- after each approval `status` says "Raven 1.5.0 (build 5) from <friend> is
  downloaded and checked";
- nothing is installed (installing is `raven update install`, a separate
  typed approval; carrier_matrix C89 runs it in a temp prefix);
- `raven security` on B and C (in the report) lists notice #1 as applied
  (an informational alert) and no other alert or warning.

Keep the three reports.

## 5. R32: key-ceremony dry run on an offline machine

The procedure is [`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md)
sections 2-5, run as its section 8 dry run: the real offline machine, real
removable media and paper, with **keys made for the dry run**. Never the
production keys (they do not exist yet: OD6b-20), and never the published
test keys on the offline machine.

1. Build the tool twice (the build machine and a second one) and compare the
   SHA-256 (section 2 there). Record both hashes.
2. Offline machine: Wi-Fi and Bluetooth off, no cable, before, during and
   after. Record how that was checked.
3. Section 3: three keys labelled `release-a`, `release-b`, `release-c` on
   three dry-run media, their paper backups, and a restore test of one key
   from its paper copy.
4. On the build machine: `scripts/release/build_reproducible.sh` of the commit
   under test, then `scripts/release/make_bundle.sh draft ... --dry-run-serial 1`
   (a development build has serial 0).
5. Both signing rounds and the log steps of section 5 (sign, combine, log
   append, tree head, snapshot), then pack and check:
   `raven-release verify` and `scripts/release/check_log.py --key-set`.
6. Refusals: a wrong passphrase is refused; `combine` with two signatures by
   one key is refused; `sign` with the passphrase piped in (not typed) is
   refused.
7. A debug `raven` on a throwaway profile made with the test backends
   (`RAVEN_IDENTITY_BACKEND`, `RAVEN_SESSION_BACKEND`, `RAVEN_PREKEY_BACKEND`
   and `RAVEN_CHAT_HISTORY_BACKEND` set to `locked-file`, so no keychain is
   touched), with `RAVEN_LAB_TEST_A=1 RAVEN_LAB_ADVISORY=1
   RAVEN_LAB_RELEASE_BUNDLE=1 RAVEN_LAB_RELEASE_KEYS_FILE=<the dry-run key
   set file>`, runs `raven update verify <the bundle>` on a computer of the
   bundle's target.
8. Destroy the dry-run keys, media contents and folders.

**Pass:** every step as written, with the timing of each; the summaries the
tool shows before each passphrase match the drafts' signing hashes written
down on the build machine; every refusal in step 6; `raven update verify`
passes; nothing but drafts and signatures crossed the transfer medium. Keep
the ceremony record (dates, signing hashes, log size and root), never a
passphrase or a key file.

## 6. R33: reproducible build on two machines

**Gear:** two machines of the same OS and CPU (two Linux x86_64 PCs first;
then two Macs of one CPU kind, best effort), with different user names and
the checkout in different folders. `scripts/release/build_reproducible.sh`
uses rustc 1.98.0 (the PATH one when it is that version, else through rustup)
and builds in `/tmp/raven-reproducible` (one build per machine at a time).

1. On machine 1, from a clean checkout of the commit under test:
   `scripts/release/build_reproducible.sh --out <new folder>`.
2. On machine 2 the same, or `scripts/release/reproduce_check.sh <bundle>` for
   a bundle made from machine 1's build (R32's dry-run bundle will do).
3. Compare the two `SHA256SUMS` and `BUILDINFO` files (`diff`).

**Pass:** on Linux both files are identical (or `reproduce_check.sh` prints
`REPRODUCED`). On macOS identical, or every differing file recorded with
what differs (best effort: these are the bytes before platform signing).
Windows: not covered by the script; record "n/a". The CI job "reproducible
build (advisory)" has not run yet (GitHub Actions is off), so this row is the
only two-machine evidence for now.

## 7. R35: a meeting on a hotspot the owner controls, captured

**Gear:** laptops A and B, and a third laptop H that makes the hotspot and
captures on it (no uplink needed). Debug builds of the commit under test on
A and B, with:

```bash
export RAVEN_LAB_TEST_A=1 RAVEN_LAB_NOISE_PIN=1 RAVEN_LAB_LINK_PADDING=1 \
       RAVEN_LAB_LINK_KNOCK=1 RAVEN_LAB_SECURITY_EVENTS=1 RAVEN_LAB_AT_REST=1
# the row is about the wire: test backends, so no keychain is touched
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_SESSION_BACKEND=locked-file \
       RAVEN_PREKEY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file
```

Test profiles `$A` and `$B`, made with `raven --data-dir ... init`, each
node started with `raven-node service --data-dir <profile> --lan-listen
0.0.0.0:<7451 on A, 7452 on B> --ble-listen 127.0.0.1:0`; A and B add each
other (`raven contact add ... --lan-dial <other's IP>:<port>`) and compare
security words (`raven contact verify`) both ways. Send one message each way
before the capture, so each side's capability mark shows padding and the
knock.

1. On H: `sudo tcpdump -i <the hotspot interface> -w r35.pcap tcp port 7451
   or tcp port 7452`.
2. A sends B three texts of about 1, 400 and 3,000 characters; B sends the same
   back. Wait until each is delivered.
3. From H, probe B as a stranger, twice:
   `{ printf '\000\000\000\040'; head -c 32 /dev/urandom; sleep 3; } | nc -w 5 <B's IP> 7452 | wc -c`
   (a 4-byte length and a 32-byte Noise message 1 without a knock).
4. Stop B's node (by its pid), add the field `"security_silent_to_strangers":
   "on"` to `$B/node_policy.json` (or create the file as
   `{"security_silent_to_strangers": "on"}`; no command sets it yet), start
   it again, probe twice more as in step 3, and send B one more text from A.
5. Stop the capture and both nodes. Keep `raven security --json` of A and B.

**Read the capture** (Wireshark: Statistics, Conversations; then Follow, TCP
Stream, shown as raw): each Raven frame on the wire is a 4-byte big-endian
length and that many bytes.

**Pass:**

- After the handshake, every frame between A and B is 528, 4,112, 16,400 or
  65,535 bytes long (a PAD1 class plus the 16-byte Noise tag) on every
  connection that carries messages, except the dialer's first frames on a
  LAN link: its bind (96 bytes, a fixed size anyway) and anything it sends
  before it has read the listener's first padded frame
  ([`RAVEN_LINK_PADDING_V1.md`](../protocol/RAVEN_LINK_PADDING_V1.md) §4). A
  frame-less probe connection (a dial that reads nothing) is not padded:
  record how many there were.
- Knocked handshakes: message 1 is 64-95 bytes and message 2 112-143 bytes
  ([`RAVEN_LINK_KNOCK_V1.md`](../protocol/RAVEN_LINK_KNOCK_V1.md) §6), and the
  lengths differ between connections.
- Step 3's probes print a number from 116 to 147 (B answered a dialer
  without a knock with a 112-143-byte message 2 and its length, as a strict
  listener does: while the knock is live message 2 has the same length range
  whether a knock matched or not) and step 4's print `0` (silent: B closed
  without a byte). A still reaches B in silent mode.
- `raven security` on A and B lists no alert or warning (the probes are
  network events, only counted).

**Not shown by a capture: the statics.** Noise XX encrypts each side's
static key (messages 2 and 3), so tcpdump cannot show that they change per
connection. carrier_matrix C86 checks it in software (two stranger probes of
a strict listener see two statics; knocked links use statics made for that
connection). This tree has no stranger probe tool for real hardware; record
"not shown" rather than a pass.

Also record what the capture shows anyway, as expected: the two addresses,
connection times and counts, and which side sent each frame
([`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) section 4, "What people near you
can see").

## 8. R37: Lock v2, auto-lock on sleep and the Raven passphrase

**Safety first:** a **separate OS user account** made for this row on each
machine, with its own keychain or keyring and its own login items; test
profiles under `~/raven-r37/` in that account only. This row uses the real
keystore, so **never** set the `RAVEN_*_BACKEND=locked-file` variables here (a
profile with them is refused a Raven passphrase: "This profile keeps its keys
in the lab's files"). Windows: the IPC pipe is per user, so run the friend B
on another computer or account.

**Builds:** a debug build of the commit under test in that account
(`cargo build --locked -p ash -p raven-node`) with:

```bash
export RAVEN_LAB_TEST_A=1 RAVEN_LAB_LOCAL_PROTECTION=1 RAVEN_LAB_SECURITY_EVENTS=1 RAVEN_LAB_AT_REST=1
```

and, for R37.7, a release build of the same commit (`--release`).

| System | Keystore | How the profile gets it | Passphrase commands |
|---|---|---|---|
| macOS | login keychain | the default | `set` (moves the keys into a vault) |
| macOS | Raven passphrase | `raven passphrase set` on a keychain profile | `change`, `remove` (back to the keychain) |
| Linux | passphrase vault | `RAVEN_KEYSTORE_BACKEND=vault` at `init` | `change` |
| Linux | Secret Service | the default with an unlocked keyring | refused (record the text) |
| Windows | DPAPI | the default | refused (record the text) |

Each profile A has a friend B (another profile, `--lan-listen` 7452) that
sends to it during the row.

**R37.1 Lock and unlock.** With A's node running:
`raven --data-dir $A lock`. **Pass:** the question says that Raven keeps
running but forgets its keys, and on a profile without a Raven passphrase
that anyone who can log in as you can open them; after `y` it says "Raven is
locked. Friends can't reach you; your messages wait here."; `raven status`
says Raven is locked first; A's raven-node is still running (by its pid);
B's sends wait and B cannot link to A; `raven --data-dir $A send ...` says
"NOT SENT, nothing queued: Raven is locked."; on macOS no keychain dialog
appears while locked. `raven --data-dir $A unlock`: a passphrase profile asks
for the passphrase (not echoed); a keychain, DPAPI or keyring profile opens at
once and says again what a lock does not protect. **Pass:** "Raven is
unlocked. Friends can reach you again."; every message B sent meanwhile
arrives once.

**R37.2 Wrong passphrases** (passphrase profiles). Lock, then `raven unlock`
with a wrong passphrase three times. **Pass:** each is refused, each wait is
longer (1 s, doubling, at most 60 s); the right one opens and says how many
wrong tries there were; `raven security` afterwards counts them.

**R37.3 Auto-lock on sleep.** A passphrase profile (on by default): put the
computer to sleep for at least a minute (close the lid, or suspend), wake it.
**Pass:** within about ten seconds `raven status` says Raven is locked. A
keychain, DPAPI or keyring profile (off by default): stays unlocked; turn on
"Lock Raven when the computer sleeps" in the full-screen app's Settings and
repeat: locked.

**R37.4 The Raven passphrase on macOS.** On the keychain profile:
`raven passphrase set` (typed twice, not echoed). **Pass:** it says what moved;
Keychain Access (in the test account) shows no `app.raven.node.*` item for
this profile any more; after a node restart Raven starts locked and opens
only with the passphrase. Then `raven passphrase change`, and
`raven passphrase remove` (**Pass:** the items are back in the keychain; the
first use may show the keychain dialog, answer Always Allow). Never delete a
keychain item by hand.

**R37.5 The other systems.** Linux vault: `raven passphrase change`, then a
restart: Raven starts locked unless its passphrase comes from a file. With a
passphrase file (the headless service): `change` names the file and says to
put the new passphrase there; do so, restart: Raven starts unlocked; and a
wake from sleep (or a clock step of a minute) leaves it unlocked unless
"Lock Raven when the computer sleeps" is turned on. Linux
with a keyring and Windows: `raven passphrase set` is refused; record its
text.

**R37.6 The full-screen app.** In `raven` (or `ash`): the LOCKED screen with
a masked field on a passphrase profile and the honest keychain text on the
others; L on the friends list locks through Lock v2; the Settings rows
"Lock Raven when the computer sleeps", "Lock Raven when this app is idle"
(off by default; set a short time and wait) and "Raven passphrase".

**R37.7 The gate shut.** The same profile kinds with the release build (no lab
switch is read). **Pass:** `raven lock` is Lock now v1 (it stops Raven and
keeps it stopped until `raven unlock`, as in R34.3), and `raven passphrase`
says "A Raven passphrase is not part of this version of Raven."

Keep each command's output; stop every node by its pid; remove the test
account afterwards.
