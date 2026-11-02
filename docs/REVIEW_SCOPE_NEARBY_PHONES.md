# Outside review scope: Bluetooth nearby on iPhones (gate 27 for phones)

For the reviewer the draft amendment
[`WAIVER_NEARBY_PHONES_AMENDMENT_DRAFT.md`](WAIVER_NEARBY_PHONES_AMENDMENT_DRAFT.md)
asks for. The general review package is
[`SECURITY_REVIEW_SCOPE.md`](SECURITY_REVIEW_SCOPE.md); this covers what a phone
adds to Bluetooth nearby. Branch `release/raven-core-0.1.2` of raven-core, and `release/ios-0.1.2`
of the iPhone app.

## Read

raven-core (`node/crates/`):

- `raven-core/src/nearby_gate.rs`: the gate and its hold text.
- `raven-node/src/nearby/apple/inproc.rs`, `cb.rs`, `machine.rs`: CoreBluetooth
  inside the app's process, its serial queue and its lifetimes.
- `raven-node/src/nearby/engine.rs`: `rotation`, `update_air`, `pipe_for`,
  `address_private`, the caps of RNL1 §8.
- `raven-node/src/nearby/mod.rs`: `dial_on` (when a contact is wanted),
  `work_for` and `keepers_for_me` (background mail, RNL1 §3 (c)), `Host::pipe_up`.
- `raven-node/src/outbox.rs` `late_pipe`, and `raven-node/src/custody.rs` (the
  fetch pass, `encounter`): a pipe that comes up while Tor is tried.
- `raven-client/src/node.rs` `node_pause` and `raven-client/src/embedded.rs`:
  the background node the keep pause starts.
- `protocol/RAVEN_NEARBY_LINK_V1.md` §3 and §8.

The iPhone app:

- `Raven/State/AppModel+Custody.swift`: when the keep pause runs, the
  background radio wait, the consent before each switch.
- `Raven/State/AppModel+Actions.swift` `enteredBackground`: the order of the
  short finish, the hand-off to a friend, the pause.
- `Config/Raven-Info.plist` and `Config/Raven-Lab-Info.plist`: the background
  modes the flip adds.

## Check

1. **Admission.** Only verified contacts with a cached certificate get a
   token, on iOS as on macOS; nothing on the phone admits anyone else.
2. **The advert.** One 128-bit service UUID and nothing Raven chooses, in
   front and in the background; no local name set by the app.
3. **Who it advertises for.** The code's reasons match RNL1 §3 (a) to (c) and
   nothing more; the custody pickup reason only with background mail on and
   friend custody live.
4. **Keys on the phone.** Pair keys and session keys stay in memory and are
   wiped; nothing about a Bluetooth peer is written to disk; logs carry counts
   and states only.
5. **The background node.** It has no listener, p2p or Tor; it stops when
   Raven comes back or sleeps; a Raven that sleeps behind its lock holds no
   keys and keeps no radio.
6. **Concurrency.** CoreBluetooth calls stay on their queue; no wait on the
   main thread; an earlier radio life's callbacks are dropped.
7. **Strangers.** A stranger in range learns nothing beyond what the
   amendment's §4 accepts, and cannot exhaust more than the caps of RNL1 §8.
8. **Apple's rules.** The two background modes are used only for the keep
   pause, and the app says what iOS does not allow (the Network page's "When
   you leave Raven").

## Out of scope

The Noise and Raven link handshakes (frozen, reviewed with the laptop
carrier), Tor, LAN and p2p, and friend custody's own sealing (its own waiver).
