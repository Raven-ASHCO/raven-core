# DRAFT amendment: Bluetooth nearby on iPhones (gate 27 for phones)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `NEARBY_PRODUCTION_ENABLED` stays `cfg!(target_os = "macos")` and the
> iPhone app's release Info.plist declares no Bluetooth background mode until
> the owner signs a final copy (renamed to
> `docs/WAIVER_NEARBY_PHONES_<date>.md`), an outside review of the scope in
> [`REVIEW_SCOPE_NEARBY_PHONES.md`](REVIEW_SCOPE_NEARBY_PHONES.md) is recorded,
> and the flip in §8 lands in its own reviewed commit.
>
> **Owner decisions recorded (2026-11-02):**
> - **Per-gate OK for gate 27 on iPhone: given.** The owner said to open gate 27, in the
>   coordinating session's chat (mac-b).
> - **Order: the outside review comes before the flip.** Asked whether to flip right after
>   signing, the owner chose to keep the rule: gate 27 flips only after the owner signs this
>   waiver and an outside review is in. Everything else is made ready meanwhile.

| | |
|---|---|
| **Amends** | [`WAIVER_NEARBY_DRAFT.md`](WAIVER_NEARBY_DRAFT.md), which excludes phones (its §2, "Not covered") |
| **Waiver ID** | `WAIVER-NEARBY-PHONES-<date>` (to be assigned on signature) |
| **Scope** | Bluetooth LE nearby inside the iPhone app's own process, its background modes, and the custody pickup advert (§2) |
| **Approver** | Protocol owner (per-gate OK given 2026-11-02; signature pending) |
| **Date drafted** | 2026-11-02 |
| **Review by** | 3 months after signature |
| **Withdrawal** | Set `NEARBY_PRODUCTION_ENABLED` back to `cfg!(target_os = "macos")` in `node/crates/raven-core/src/nearby_gate.rs` and remove the two background modes from the app's release Info.plist. A phone then creates no radio object, never advertises, scans, knocks or dials over Bluetooth, and its pause is the plain pause of 0.1.1 |
| **Spec** | [`RAVEN_NEARBY_LINK_V1.md`](../protocol/RAVEN_NEARBY_LINK_V1.md), with §3 (c) as of 2026-11-02 |
| **Evidence** | The iPhone app's `HANDOFF-IOS.md`, "Mesh relay on the iPhone": device rows R0 to R8 of 2026-11-02 on an iPhone 16 Pro Max and an iPhone 12 Pro, lab builds |

## 1. Why an amendment is needed

The nearby waiver covers laptops only. On a phone the radio runs inside the
app (iOS starts no helper process), iOS decides when the app runs at all, and
the app needs Apple's Bluetooth background modes to keep the radio while it is
not in front. A phone is also carried everywhere, so what it advertises is
seen in more places than a laptop's adverts.

## 2. Scope (exactly what is covered)

Everything the nearby waiver covers (the wire, admission, the advertising
policy, scanning, consent, carrier order), and in addition, only in this
combination:

- **The iOS backend:** CoreBluetooth inside the app's process
  (`raven-node` `nearby/apple/inproc.rs`, with the macOS helper's machine and
  CoreBluetooth glue, `machine.rs` and `cb.rs`, on one serial queue). It
  holds the pair keys in the engine's memory as the macOS raven-node does;
  nothing about a Bluetooth peer is stored. The engine's managers set no
  state-restoration identifier: iOS never relaunches Raven for a Bluetooth
  event.
- **Consent:** off by default; the app's Settings switch "Bluetooth nearby"
  asks first, and iOS asks for the Bluetooth permission once
  (`NSBluetoothAlwaysUsageDescription`). "Bluetooth for waiting mail" (OD-C8)
  is its own switch, shown only while nearby is on, and asks first too.
- **The background modes:** `bluetooth-central` and `bluetooth-peripheral` in
  the release Info.plist. They are used for one thing: when Raven leaves the
  front with nearby on, the pause becomes `node.pause {nearby: "keep"}`, which
  keeps a small background node (outbox, custody, nearby; no listener, no
  p2p, no Tor) and its radio until iOS suspends Raven. A Raven asleep behind
  its own lock holds no keys and keeps nothing.
- **The custody pickup advert** (RNL1 §3 (c), last reason): with background
  mail on and friend custody live, a node also advertises for the friends
  that hold mail for it, so the keeper's scan finds it (row R8).
- **Builds:** the iOS release engine with features `tor-embedded
  nearby-embedded`, as 0.1.1 already ships it with the gate closed.

Not covered (each needs its own record): Android; Bluetooth Classic, Wi-Fi
Aware or Multipeer Connectivity; CoreBluetooth state restoration (a relaunch
after iOS ended Raven); any background mode besides the two above; multi-hop
custody handoff ("chains"), which stays behind
`CUSTODY_HANDOFF_PRODUCTION_ENABLED`; mail kept longer than the session
allows, which waits for session renewal or letters.

## 3. Holds

| Hold | Status at signature (to fill) | Waived? |
|---|---|---|
| The owner's per-gate OK for gate 27 on iPhone | Given 2026-11-02 | Recorded |
| The nearby waiver itself (laptops) signed | Draft | **Not waived**: this amendment cannot stand alone |
| Outside review of [`REVIEW_SCOPE_NEARBY_PHONES.md`](REVIEW_SCOPE_NEARBY_PHONES.md) | Not started; before the flip (owner, 2026-11-02) | **Not waived** |
| Privacy capture on iPhone (row P7): what an iPhone adverts in front and in the background, its address type, and the GAP name a connecting device reads | Not run | **Not waived** |
| App Review accepts the two background modes for this use | Not asked | Not waived: a rejection means the modes and the keep pause wait |
| Rows R0 to R8 (lab builds, 2026-11-02) | R0, R1, R2, R3, R5, R7a, R8 passed; R4 as expected; R6 and R7b show the background limits of §4 | Recorded, not waived |
| One unexplained end of Raven on the 16 Pro Max during a send (no crash report) | Open | Not waived: needs a repeat run with memory notes |

## 4. Residual risks accepted

1. **iOS suspends Raven.** A few seconds after Raven leaves the front, iOS
   suspends it, modes or not; a radio event wakes it for about 10 seconds. A
   locked phone in a pocket delivered nothing in rows R6 and R7b. The pocket
   relay works sometimes, never on a promise, and the app says so ("When you
   leave Raven" on the Network page).
2. **No relaunch.** After the person swipes Raven away, or iOS ends it for
   memory, nothing runs until it is opened again.
3. **Background adverts.** In the background iOS moves the service UUID to
   the overflow area, which only an iOS device scanning for that UUID sees,
   and scans name at most 32 friends with longer intervals. A Mac does not
   find a backgrounded iPhone.
4. **A phone is carried.** The same linkability as the laptop waiver's risk
   2, in more places: sightings within one 15-minute epoch can be linked to
   one advertising phone.
5. **The device name.** A device that connects can read the GAP name; on an
   iPhone what it reads is to be recorded in row P7.
6. **The pickup advert.** With background mail on, a phone that a friend
   keeps mail for advertises for that friend with no send of its own: an
   observer sees that the phone advertises, never for whom.
7. **Battery** of scanning in front and of the background node (not measured).

## 5. Compensating controls in place

- Everything in the nearby waiver's §5: verified contacts only, the knock
  first, one random-looking UUID per slot, RNP1 refusals, keys in memory
  only, counts-only logs.
- iOS advertises from a resolvable private address (row P7 records it); the
  engine stays off the air where the backend reports a public address
  (`nearby/engine.rs` `address_private`).
- The keep pause runs only when the build declares both modes, nearby is on,
  the engine offers nearby and Raven does not sleep; a refused keep falls
  back to the plain pause (`MeshRelayTests`).
- The background task waits at most 5 seconds for the background radio and 1
  more for its first advert, then ends before iOS's deadline.
- Background mail and its pickup advert are off until the person turns them
  on, with their own consent text.

## 6. Conditions

This amendment lapses, and the flip in §8 MUST be undone, if any of these
happens before it is renewed:

- anything that lapses the nearby waiver (its §6);
- another background mode, or a use of these two for anything but the keep
  pause;
- CoreBluetooth state restoration added without a new record;
- a reason to advertise beyond RNL1 §3 (a) to (c);
- the background node gaining a listener, p2p or Tor without a new record.

## 7. Exit conditions before signature

- The nearby waiver signed, with OD-C8 recorded.
- The outside review of [`REVIEW_SCOPE_NEARBY_PHONES.md`](REVIEW_SCOPE_NEARBY_PHONES.md)
  recorded, its findings fixed or accepted here.
- Row P7, the privacy capture on iPhone, in front and in the background.
- Rows R1 to R8 again on a release build with the flip applied locally (not
  shipped), with Auto-Lock, Low Power Mode and the lock noted.
- A repeat of the send that ended Raven once, with memory noted.
- App Review asked about the two background modes (a TestFlight build).

## 8. The flip (written down, not applied)

1. `node/crates/raven-core/src/nearby_gate.rs`:

   ```rust
   pub const NEARBY_PRODUCTION_ENABLED: bool = cfg!(any(target_os = "macos", target_os = "ios"));
   ```

   with its doc comment and `NEARBY_HOLD` text updated in the same commit.
2. The iPhone app's `Config/Raven-Info.plist`, `UIBackgroundModes`, after
   `fetch` and `processing`:

   ```xml
   <string>bluetooth-central</string>
   <string>bluetooth-peripheral</string>
   ```

   (`Config/Raven-Lab-Info.plist` already has them; `MeshRelayTests` checks
   that the two files differ in nothing else, so it changes with the flip.)
3. A release engine built from the flipped commit, the app archived with it,
   and RNL1's status line and `docs/PROTOCOL_FREEZE_HASHES_V1.md` updated.

## 9. Signature

Not signed. To sign, the owner fills this in, renames the file to
`docs/WAIVER_NEARBY_PHONES_<date>.md`, and commits it alone. Signing does not
flip the gate: the flip in §8 follows the outside review (owner decision of
2026-11-02).

| | |
|---|---|
| **Signed by** | |
| **Date** | |
| **Waiver ID** | `WAIVER-NEARBY-PHONES-<date>` |
| **Nearby waiver (laptops) it amends** | `WAIVER_NEARBY_<date>.md`, signed on: |
| **OD-C8 (background mail, its pickup advert included)** | recorded: yes / no |
| **Holds of §3 at signature** | (fill each row's status) |
| **Outside review** | reviewer, date, findings and how each was settled: |
