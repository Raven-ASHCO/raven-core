# DRAFT owner waiver amendment: Lock v2, auto-lock on sleep and the Raven passphrase (Phase 6, P6.40)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `LOCAL_PROTECTION_PRODUCTION_ENABLED`
> (`node/crates/raven-core/src/security_gate.rs`) stays `false` until the owner
> signs a final copy (renamed to `docs/WAIVER_LOCAL_PROTECTION_<date>.md`), the
> preconditions in §7 are met, and the flip is applied as its own reviewed
> commit. Debug builds open it with `RAVEN_LAB_LOCAL_PROTECTION=1` and
> `RAVEN_LAB_TEST_A=1`; release builds never read them. With the gate shut,
> `raven lock` is the privacy pack's Lock now v1 (it stops Raven and keeps it
> stopped) and `raven passphrase` says "A Raven passphrase is not part of
> this version of Raven."

| | |
|---|---|
| **Waiver ID** | `WAIVER-LOCAL-PROTECTION-<date>` (to be assigned on signature) |
| **Gate** | `LOCAL_PROTECTION_PRODUCTION_ENABLED = false` |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md): a locked node keeps running but closes the live LAN listener, ends its links and refuses every key load, so the slice is unreachable while locked; that record is not edited. The privacy pack's Lock now v1 (shipped ungated, [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.7a row T3b) stays what `raven lock` does whenever the node does not serve v2 |
| **Not covered** | Daemon-owned secrets (`design/2026-10-daemon-owned-secrets.md`: an `ash` process started later still reads the keystore itself); a Raven passphrase on Windows and on GNU/Linux desktop-keyring profiles (not built: refused with what to do); local malware (THREAT_MODEL §3.16) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-24 |
| **Decision proposed** | Turn on Lock v2 (raven-node keeps running and forgets every key while locked), auto-lock on wake from sleep (on by default only for a profile with a Raven passphrase) and the Raven passphrase on macOS (owner decision OD6b-18, option 1) |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set the const back to `false`: `raven lock` is Lock now v1 again. A macOS profile already moved to a Raven passphrase keeps its keys in the vault (its marker says so); how a build with the gate shut opens such a profile without Lock v2's unlock is not tested, so move those profiles back first with `raven passphrase remove` (in a build with the gate live) |
| **Design** | Plan `docs/roadmap/plans/phase6-design.json`, design P6b-C (remainder), step P6.40 |
| **Wire** | None on the network. Local IPC only: `Lock`, `Unlock { passphrase_b64 }` and `Status.locked` (`IPC_VERSION` stays 1) on the per-user socket or pipe; the passphrase field is redacted in `Debug`, never in a decode error, and wiped with the request frame |
| **Threat model** | [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.7a row T3b |
| **User docs** | `raven lock --help`, `raven passphrase --help`; [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) section 5 |
| **Real rows** | [`P6_REAL_ROWS_CHECKLIST.md`](P6_REAL_ROWS_CHECKLIST.md): R37 |

## 1. Why a waiver is needed

The gate changes how the live slice's daemon behaves for hours at a time: a
locked raven-node closes the LAN listener and refuses links and key loads
while it keeps running, and a profile with a Raven passphrase starts locked
after every restart. A person who locks and forgets can miss messages
until they unlock (their friends' messages wait on their friends' side).

## 2. Scope (exactly what the flip turns on)

1. **Lock v2.** `raven lock` (and the full-screen app's lock) sends IPC
   `Lock` to a node that serves it: the node drops the LAN listener's
   identity, the at-rest keys, the decrypted contact book and block list, the
   vault's derived key and learning connectivity's model with its secret
   (saved first; it loads again at the unlock), refuses every key load of the
   profile meanwhile
   (raven-core `local_lock`), stops every network task and ends their links;
   while locked its IPC serves only `Ping`, `Status`, `Lock` and `Unlock`, and
   `raven send` says "NOT SENT, nothing queued: Raven is locked." An older
   node or one with the gate shut gets Lock now v1. `raven update install`
   and `rollback` refuse while it is locked ("run raven unlock first"):
   the lock lives in the process, so an update's restart would start a
   keychain profile's node unlocked, and on the default address where no
   login item starts it (a locked node reports no listen address; review
   lock-updates-local-6).
2. **Unlock.** A passphrase profile's `raven unlock` checks the passphrase
   against the vault (typed without echo; a wrong one waits 1 s, doubling up
   to 60 s; each is `SEC_UNLOCK_FAILED` while events are live). A keychain,
   DPAPI or desktop-keyring profile opens at once and says what a lock does
   not protect. Queued messages go out at once after an unlock.
3. **Auto-lock.** On wake from sleep (raven-node's wake clock: a sleep of 30 s
   or more), per `node_policy.auto_lock_on_sleep`: unset means on for a
   profile with a Raven passphrase and off for the others (OD6b-18), and off
   too where raven-node reads the passphrase from a file or a systemd
   credential (a headless node, which starts unlocked for the same reason:
   nobody is there to unlock it, and the file on the same disk leaves the
   lock nothing to protect; review lock-updates-local-3); set in the app's
   Settings ("Lock Raven when the computer sleeps"). The app's own idle lock
   ("Lock Raven when this app is idle") is off by default.
4. **The Raven passphrase.** macOS: `raven passphrase set` moves the
   identity seed, the history key, every session secret and the prekey state
   from the login keychain into a vault only the passphrase opens (copy, read
   back, markers, then the old items go; an interruption between the markers
   leaves the identity in the vault, so the profile counts as one with a
   passphrase, and either command finishes it); `change`; `remove` moves them
   back. Such a profile starts locked. GNU/Linux vault profiles: `change`
   only; where the service reads the passphrase from a file, `change` names
   that file and says to put the new passphrase there before Raven's next
   start (it is never rewritten for the person). A wrong current passphrase
   is refused before raven-node is held, so a typo leaves it running and is
   never counted as a wrong unlock. Windows and GNU/Linux keyring profiles:
   refused with the reason.

## 3. Holds

- Daemon-owned secrets are not built: the refusal of key loads
  (`raven-core/src/local_lock.rs`) is raven-node's own, in its process. An
  `ash` or `raven` command started while a keychain, DPAPI or keyring profile
  is locked still reads its own keys, as before Lock v2 (`raven send` stops
  because the node says it is locked, not because the keys are closed).
- The full-screen app's idle lock counts the app's own idle time only.

## 4. Residual risks accepted

1. **Keychain, DPAPI and keyring profiles stay open to the user's login.**
   Lock v2 makes the running node forget its keys, but anyone who can log in
   as the user can open them again. Every lock text says so; only a Raven
   passphrase changes it, and only on macOS and GNU/Linux vault profiles.
2. **A forgotten passphrase is a lost identity.** There is no recovery; the
   person's friends add them again.
3. **A passphrase crosses local IPC.** It travels on the per-user socket (or
   the per-user pipe on Windows), base64 in a frame that is wiped after use;
   another process of the same user could read it (local malware).
4. **Locked means unreachable.** Messages to a locked person wait on the
   sender's side; a long lock can outlast their deadlines.
5. **A sleep shorter than 30 s is not seen**, and a profile without a Raven
   passphrase does not lock on sleep unless the person turns it on; nor does
   a headless node that reads its passphrase from a file. The wake clock
   compares the wall clock with the monotonic one, so a forward clock step of
   30 s or more (an NTP fix after boot, a VM resumed) reads as a wake.

## 5. Evidence

- **Local, macOS (this tree, gate held, lab switch on where named):** the
  P6.40 unit tests (IPC redaction and wiping, the per-store refusals, the
  back-off, the passphrase moves and their interruption, the app's LOCKED
  screen and Settings rows), fault matrix s116 (`RAVEN_FAULT_LOCK_V2=1`: three
  queued messages, a friend dialing during the lock refused, all delivered
  once after the unlock), s121 (Lock now v1), the release inertness test
  `lock_v2_lab_switch_is_inert_in_release`; full suites with the switch.
- **Not run here:** Windows and the Secret Service code paths (no Windows
  target on this Mac; Secret Service is not built here).
- **CI, open:** GitHub Actions is not running (org billing).
- **Hardware, open:** R37 on macOS (keychain and passphrase), GNU/Linux
  (vault) and Windows (DPAPI).
- **Review:** the Phase 6 exit's adversarial review (P6.53).

## 6. Rollback

Set the const back to `false` (see Withdrawal above: macOS passphrase
profiles go back to the keychain first). Nothing else needs a migration;
`node_policy.auto_lock_on_sleep` is then not read.

## 7. Preconditions and flip order

- Order (OD6b-1, as decided): after the knock, before the update gates.
  (OD6b-1's original recommendation put the laptop-protection gates first as
  soon as their real rows pass; the decision recorded keeps them in this
  place because the at-rest part shipped ungated in the privacy pack.)
- R37 passed on the three systems.
- CI green, with its release inertness step run.
- The Phase 6 adversarial review done and its fixes clean.
- [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) updated in the flip commit: its
  section 5 paragraph and section 12 row marked
  `LOCAL_PROTECTION_PRODUCTION_ENABLED` (`scripts/check_offline_guide.sh`
  fails until they match the code).

## 8. Signature

- `LOCAL_PROTECTION_PRODUCTION_ENABLED`: not signed.
