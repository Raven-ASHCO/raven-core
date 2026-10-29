# DRAFT (unsigned): amendment to `WAIVER-LAN-DIRECT-2026-10-07` for the cutoff pack's two LAN gates

| | |
|---|---|
| **Status** | **DRAFT, not signed.** Nothing here is in force until the owner signs it. Until the flip commit, `LAN_NOISE_PIN_PRODUCTION_ENABLED` and `OFFLINE_LAN_PRODUCTION_ENABLED` stay `false` in `node/crates/raven-core/src/lan_gate.rs`; debug builds open them with `RAVEN_LAB_NOISE_PIN=1` and `RAVEN_LAB_OFFLINE=1`, release builds never read those variables. |
| **Amends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md), its [P2a amendment](WAIVER_LAN_DIRECT_P2A_AMENDMENT_DRAFT.md) and its [session reset amendment](WAIVER_LAN_DIRECT_SESSION_RESET_AMENDMENT_DRAFT.md) (none is edited) |
| **Not covered** | The [route hints amendment](WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md) and everything in §3 below: those stay held under their own records |
| **Decision** | The owner approved (2026-10-16) setting exactly these two gates `true` in release once the cutoff pack is green and its adversarial review and fixes are clean, with this one amendment. No other gate is approved |
| **Plan** | `docs/roadmap/plans/cutoff-pack-plan.json` (CP.0-CP.15; the flip is CP.16); user guide [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) |
| **Wire** | No change: no new frame, field, carrier or port; message 3 of Noise XX is unchanged when it is sent |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-18 |
| **Review by** | Same date as the LAN waiver (2027-01-07) |
| **Withdrawal** | Set both consts back to `false` (§6) |

## 1. Why an amendment

The LAN waiver §6 makes "extending the slice beyond §2 without a new waiver"
a lapse condition. The two gates change how the covered LAN dialer behaves:
M0 makes it stop earlier, and the offline set makes it keep, retry and dial
in situations where it refused or waited before. Neither adds a carrier, a
port or a byte on the wire, but both change when and where the live slice
dials, so they are written down here before the flip.

## 2. What the flip turns on (and nothing else)

### 2.1 M0: `LAN_NOISE_PIN_PRODUCTION_ENABLED`

1. **Pins, as digests.** After every authenticated link with a contact (a
   LAN dial once the responder's identity bind verified; an inbound LAN link
   in its trusted branch, after the contact gate), the contact's Noise static
   key is recorded as `HMAC-SHA256(K, "rvn1/lan-noise-pin/v1" || contact
   Ed25519 key || Noise static)` in `lan_noise_pins.json` (version 2, no
   times, at most 4,096 entries, the oldest goes first, 0600, its own lock
   file). `K` is HKDF-SHA256 of this computer's identity seed (salt
   `rvn1/lan-noise-pin-key/v1`), which is not in the data dir, so a copy of
   the data dir cannot test the static that any listener shows in Noise
   message 2 against the pins. The friend's Noise static itself is never
   stored. A version 1 file (unkeyed, lab builds only) reads as no pins and is
   replaced. `raven contact remove` forgets the pin; an address change keeps
   it.
2. **The stop before message 3.** A dial to a contact with a pin reads Noise
   message 2, compares the responder's static with the pin and, when another
   key answers, ends the handshake **before message 3**: the dialer's own
   Noise static and its signed identity bind never leave the computer. The
   error `lan noise pin mismatch` maps to the existing outbox code
   `WRONG_IDENTITY`; `ash` says that something else answered at the friend's
   address and that Raven stopped before telling it who you are, and that if
   the friend reinstalled Raven (a new key, which no wait reaches) the way on
   is the friend's new invite.
3. **The block is per message and short.** A pin mismatch blocks that route
   for the message that found it (`pin_blocked`, in memory), not the
   contact: the block ends at a network change, at the contact's own inbound
   link or route change, and at any explicit outbox kick for that contact:
   `raven outbox retry`, and also every new send to it or app submit (each
   sends one). A new message to the contact starts with no block, so its
   first attempt dials that route again. Each such dial still stops at Noise
   message 2: whatever answers there sees Noise message 1 (an ephemeral key)
   again, never the identity bind. A mismatch that an attempt still in
   flight found before a network change or the contact's own link is not
   recorded when that attempt ends. A bind-mismatch `WRONG_IDENTITY` keeps
   today's rule.
4. **The Err path fails closed.** A pin store that exists but cannot be
   opened, and one a newer Raven wrote (a version above 2, after a rollback:
   never read as no pins and never overwritten), ends the dial before it
   connects (`lan noise pin unavailable: lan_noise_pins.json: <why>`):
   nothing is sent. The outbox holds it as `PIN_STORE_UNREADABLE`, and `ash`,
   the terminal app and `ash doctor` name the file and the fix (its owner or
   permissions, or moving it aside). A file that opens but does not parse is
   not this path: see §4 item 7.
5. **Scope of the dials.** Every identity-bearing LAN dial goes through it:
   the outbox worker, the app channel, the custody fetcher, `raven send`'s
   probe and the route hints announcer. The Internet direct and p2p inner
   links carry the same check, but stay inactive in release while their own
   gates are held.

### 2.2 The offline set: `OFFLINE_LAN_PRODUCTION_ENABLED` (F1, F5, F6, F7)

A const assert keeps this gate from being `true` without M0. Each item below
keeps the waiver's local-only rule: an unverified contact is still dialled
only at local-network addresses (loopback, private, link-local, unique-local
IPv6).

1. **F1, a friend's name that does not resolve** (CP.9). An unverified
   contact whose saved LAN route is a computer name that does not resolve now
   is queued as away (`NOT_REACHABLE`, "could not be found on this network")
   instead of refused as `CONTACT_NOT_VERIFIED`. The worker still resolves
   the name at each attempt and dials an unverified contact at the first
   local-network address it resolves to, as that literal; a name that also
   resolves outside the local network (mDNS gives a computer's global IPv6
   address too on a network with an IPv6 prefix) is no longer refused for
   it. This narrows the P2a amendment's item 5 ("only when every address its
   LAN route resolves to" is local) to the address dialled: an unverified
   contact is still never dialled outside the local network. A malformed
   address, and a name that resolves to no local address, are still
   refused.
2. **F5, wake waiting contacts when the network proves itself** (CP.12).
   When a contact answers on the local network (a LAN delivery to a
   local-network IP address other than loopback, or an inbound LAN link from
   a local address), the other contacts waiting there are
   retried within 5 s. Only contacts whose last attempt planned a LAN route
   and found a noise pin, with objects or owed ACKs waiting and no attempt in
   flight. At most one wake a minute in all; each contact's backoff restarts
   at most once per 10 minutes. Internet and p2p deliveries wake nobody, and
   a route blocked by a pin mismatch is not cleared by a wake. A lone contact
   that comes back without sending anything still waits for its backoff (up
   to about 4 minutes after 150 s away, fault matrix s91); that needs the
   Phase 3 beacon.
3. **F6, a cable counts as a network** (CP.10). When nothing else counts as a
   network, netwatch counts an IPv4 link-local address (169.254/16) as one,
   so a cable between two laptops brings waiting messages forward like any
   other network change. Never `fe80::/10` (every interface carries one).
4. **F7, a friend with no saved address** (CP.11). A contact with no LAN
   route at all (one added from an invite line) and a noise pin is dialled
   at the address it last connected from (a sighting within 30 days), on the
   default LAN port 7420. Never at a loopback sighting or one at any of this
   computer's own addresses (a contact on this computer that connected
   through its LAN address: a guess at 7420 there would dial this computer's
   own node), never at a scope-less `fe80`
   sighting, and for an unverified contact only at a local-network address.
   The route is saved only after a delivery through it succeeded.

## 3. What stays held

The flip touches the two consts and nothing else. These stay `false` under
their own records:

- `ROUTE_HINTS_PRODUCTION_ENABLED` (RRH1 and its announce dials:
  [route hints amendment](WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md)),
  including the cutoff pack's held-recipient announce (CP.14: a custodian
  that moved tells the verified, noise-pinned contacts it holds mail for),
  which needs route hints, friend custody and M0 together.
- `FRIEND_CUSTODY_PRODUCTION_ENABLED` and `FRIEND_CUSTODY_WAN_ENABLED`.
- F4, the default-gateway candidate for hotspot clients: not built (owner
  decision OD-C5, plan default "skip"). A client still needs the hotspot
  host's address saved.
- The Phase 3 contact-only LAN beacon, listening on every interface, and
  session renewal: not built yet; each comes with its own gate and record.
- `P2P_PRODUCTION_ENABLED`, `FRIEND_RELAY_PRODUCTION_ENABLED`,
  `INTERNET_DIRECT_PRODUCTION_ENABLED` and every other held gate.
- The installers keep binding `127.0.0.1:7420` unless `RAVEN_LAN_LISTEN` is
  set.

## 4. Residual risks added (on top of waiver §4)

1. **The first dial is not covered.** Before a pin exists (the first dial to
   a friend, or a friend last linked before the flip) the dialer still sends
   its identity bind before it knows who answered. A card that carries a
   Noise digest would close it (owner decision OD-C13, Phase 6b).
2. **The pin file is plaintext** until the privacy pack seals it (PP.5): it
   holds contact public keys and digests; `contacts.json` already holds the
   keys in plaintext. The digests are keyed (§2.1 item 1): without the
   identity seed they do not link a computer met on a network to a contact.
3. **More dials.** F5 and F7 dial sooner and at more addresses. Each is an
   identity-bearing dial checked against a pin, so whatever answers at a
   guessed address receives Noise message 1 only; F5 is bounded by the
   cooldowns above.
4. **Name lookups.** With F1, a queued message to a contact saved under a
   computer name repeats the system's name lookup at every attempt; for a
   `.local` name that asks the whole network. The safety guide tells people
   to save numbers.
5. **F6 churn.** On a Mac that keeps a 169.254 address (Thunderbolt Bridge),
   every Wi-Fi drop becomes a network change instead of "no network"; the
   netwatch backoff bounds the retries (accepted in the plan).
6. **What M0 does not hide.** The listener still answers any dialer with the
   node's Noise static in message 2 (a tracking handle across networks), and
   TCP 7420 with Raven's handshake shape still tells an observer that Raven
   runs.
7. **A pin file that does not parse fails open.** A row that does not parse
   is skipped (that contact has no pin); a file that does not parse at all
   (or an unkeyed version 1 file) reads as no pins. Those contacts are dialled
   as before M0 (item 1: the identity bind goes out before Raven knows who
   answered) until their next authenticated link pins them again. The next
   pin written moves the file aside to `lan_noise_pins.json.corrupt` (0600)
   first, so nothing in it is lost; the rows that parsed are kept.
8. **A pin block does not outlast a send.** Each new message to a contact,
   and each send or app submit to it, dials a route where another key
   answered once more (§2.1 item 3); every such dial stops at message 2.

## 5. Evidence

Recorded in `docs/roadmap/PROGRESS_LOG.md` (the cutoff pack's exit entry).

- **Local, macOS (this tree, gates held, lab switches on where named):**
  carrier_matrix C36 (F7: a hotspot host learns a client with no saved
  address), C38 (F5: a sibling's link wakes the queue), C39 (M0: a stranger
  at a friend's address learns nothing; gate-closed and gate-open rounds);
  fault matrix s90p (M0 against another node at a friend's old address),
  s91b (F5), s92 (F1), s98 (F6, gate closed and open), with s93b and s99;
  the release job's inertness tests with every lab switch set; the unit
  tests with no switch, with `RAVEN_LAB_TEST_A=1`, with
  `RAVEN_LAB_OFFLINE=1 RAVEN_LAB_NOISE_PIN=1` and with
  `RAVEN_LAB_ROUTE_HINTS=1`. The logs stay with the step reports, outside the
  repository.
- **CI, open until the owner pushes and the runs are green:** carrier_matrix
  C36-C39 on ubuntu and Windows; the Linux and Windows code of the interface
  and local-time readers; the advisory netns job `node/scripts/netns_offline.sh`
  (lan-noprovider, router-dead-uplink, hotspot-ap, cable-linklocal,
  three-rooms); shellcheck on the new scripts; `scripts/check_safety_offline.sh`
  on all three systems.
- **Hardware, open:** real row R11j (another Raven laptop at a friend's old
  DHCP address, with a packet capture) to confirm M0 on real hardware; its
  steps are in [`P3_REAL_ROWS_CHECKLIST.md`](P3_REAL_ROWS_CHECKLIST.md)
  section 7.
- **Review:** the cutoff pack's adversarial review, with every confirmed
  finding fixed or accepted with a recorded residual.

## 6. Rollback

Set `OFFLINE_LAN_PRODUCTION_ENABLED` back to `false`, or both consts (the
const assert allows the offline set off with M0 on, never the reverse). No
stored state needs a migration: with M0 off the pin file is simply not read
or written, and queued messages follow the rules of the build before the
flip.

## 7. Preconditions for signing

- The cutoff pack's gates green on macOS (§5) and the CI rows of §5 green.
- The pack's adversarial review done and its fixes clean.
- `docs/SAFETY_OFFLINE.md` updated in the flip commit: its pre-flip
  paragraph about old addresses and its "not in this version" rows for the
  two gates (`scripts/check_safety_offline.sh` fails until they match).

## 8. Signature

Not signed.
