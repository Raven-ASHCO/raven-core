# DRAFT owner waiver: Bluetooth nearby between laptops (RNL1, Phase 5)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file (the doc comment of `nearby_gate.rs` only names "a nearby waiver").
> `NEARBY_PRODUCTION_ENABLED` stays `false` until the owner signs a final copy
> (renamed to `docs/WAIVER_NEARBY_<date>.md`), the hardware rows N1-N12 and
> the other exit conditions in §7 are met, and the gate is flipped on its
> own, in its own reviewed commit (owner decisions O5-13 and O11). Nothing in
> Phase 5 flips a gate.

| | |
|---|---|
| **Waiver ID** | `WAIVER-NEARBY-<date>` (to be assigned on signature) |
| **Scope** | The Bluetooth LE nearby carrier between terminal nodes (laptops), §2 |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-23 |
| **Review by** | 3 months after signature; the owner reviews it then and renews, amends or withdraws it |
| **Withdrawal** | Set `NEARBY_PRODUCTION_ENABLED = false` in `node/crates/raven-core/src/nearby_gate.rs`. The service then creates no radio object, never advertises, scans, knocks or dials over Bluetooth, and every planner plans exactly what it planned before the carrier existed (raven-core test `outbox::tests::release_plan_is_unchanged_when_the_nearby_gate_is_closed`) |
| **Spec** | [`RAVEN_NEARBY_LINK_V1.md`](../protocol/RAVEN_NEARBY_LINK_V1.md) (RNB1 tokens, RNK1 knock, RNP1 pipe, prologue `raven/nearby-link/v1`); vectors `shared-vectors/rvn1/nearby/` |
| **Depends on** | The R2 amendment for its Bluetooth LE profile ([`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](../protocol/RAVEN_PRIVATE_RENDEZVOUS_V1.md) §5.3b, revision 5, for owner approval). Custody over nearby also needs [`WAIVER_FRIEND_CUSTODY_DRAFT.md`](WAIVER_FRIEND_CUSTODY_DRAFT.md) |
| **Design** | `docs/roadmap/plans/phase45-design.json`, `.designs[3]` (the Nearby design) and owner decisions O5-10 to O5-13 (`.review.owner_decisions`) |
| **User docs** | [`NEARBY.md`](NEARBY.md); the install guides' "Bluetooth nearby" sections; the threat model's §1.1 ([`THREAT_MODEL.md`](THREAT_MODEL.md)) |
| **Real rows** | an unpublished test checklist: N1-N12 |

## 1. Why a waiver is needed

Every other Raven carrier needs a shared network. Bluetooth nearby puts a
radio signal into the room that anyone can receive, exposes the operating
system's GATT data (the computer's Bluetooth name and, on macOS, its model)
to any device that connects, and depends on three operating-system Bluetooth
stacks whose behaviour CI cannot reproduce. R2 already allows local pairwise
discovery under rules this profile has to meet. The record names what is
accepted, under which conditions, and what must be proven on hardware first.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- **The wire:** RNL1 exactly as frozen (`docs/PROTOCOL_FREEZE_HASHES_V1.md`):
  pairwise RNB1 tokens from the R2 pairwise root (medium byte `0x01`), 15-minute
  epochs, a scanner accepting epoch ±1; the RNK1 knock before any Noise byte;
  RNP1 framing with credits and the caps of RNL1 §8; the Raven link with the
  prologue `raven/nearby-link/v1`, otherwise byte-identical to Internet direct.
  GATT only (Write Command / Notification); one hop.
- **Admission:** verified (pinned) contacts only, with a valid, non-revoked
  device certificate cached from an earlier authenticated link on another
  carrier (owner decision O5-12). No first contact over Bluetooth; blocked and
  revoked contacts get no token.
- **Advertising policy** (O5-12): a node advertises a contact's token only
  while user-initiated work for that contact exists within the 15-minute
  foreground TTL and work still waits, or after an explicit `raven nearby on`;
  at most 1 token on the air and 2 contacts rotating in 5 s slots; one 128-bit
  service UUID and nothing else Raven chooses; only from a random (private)
  address: a node that would advertise from a public address does not
  advertise.
- **Scanning:** passive where the OS allows, also in the background, for
  eligible contacts only. A match permits one bounded connect and a knock; it
  is never trust, presence or contact evidence.
- **Consent:** off by default; asked once (`raven nearby enable`), with the
  consent naming this computer's Bluetooth name; `raven nearby disable` stops
  all Bluetooth work. No installer turns it on.
- **Carrier order** (O5-13): nearby is planned last; first only while a pipe
  to that contact is up. Nearby routes are derived live and never stored.
- **Platforms:**
  - macOS: CoreBluetooth in the separate helper RavenNearby.app
    (`org.raven.nearby`, objc2 crates approved by O5-10), signed ad hoc or with
    a Developer ID; it holds no keys; raven-node never links CoreBluetooth and
    is never re-signed for it;
  - Linux: BlueZ over zbus 1.9.3 (glibc builds), advertising and connecting
    only with `Privacy = device` (review nearby-1: a connect shows the
    initiator's address as an advert shows the advertiser's);
  - Windows: WinRT (windows 0.62.2 features), inactive (no advert, no
    connect) until a hardware row shows that its adverts and its connects use
    a random address (§3).
- **Builds:** release builds with feature `nearby-radio` (and on macOS the
  signed helper) are part of the flip; until then the feature is built in lab
  and CI builds only.

Not covered (each needs a new record or an amendment): admission of
unpinned or unverified contacts; any change to RNB1, RNK1 or RNP1, or a new
version of them; more tokens on the air, a longer foreground TTL, any
constant, name, manufacturer data or other field in the advert, or
advertising from a public address; **background mail** (advertising for
every contact with waiting mail, cutoff addendum F11d; owner decision OD-C8
was approved on 2026-10-28 as a separate consent, `raven nearby
background-mail on`, default off) unless OD-C8 is recorded at signature;
the L2CAP fast path (design step 5.13, only
if row N6 shows the need, owner decision O12); multi-hop or spray over
Bluetooth, Wi-Fi Direct, Bluetooth Classic, and any reuse of the legacy iOS
MeshEnvelope GATT profile; phones.

## 3. Holds

| Hold | Status at signature (to fill) | Waived? |
|---|---|---|
| Hardware rows N1-N12 | Not run | **Not waived** |
| The R2 amendment (§5.3b, revision 5) approved | Draft, for owner approval | **Not waived**: this record cannot stand without it |
| Automated gates (§7 list) green on their runners | Built (P5.24-P5.32); CI's first macOS, Windows and btvirt runs pending | Not waived |
| macOS Bluetooth permission under launchd (row N8): the prompt names RavenNearby and no SIGABRT | Unverified (helper spawned as a plain child of raven-node) | **Not waived**: if N8 fails, the spawn changes first |
| Windows advert and connect addresses (row N7w) | Unknown: Windows is treated as public, so it neither advertises nor connects | **Not waived**: needed before Windows uses nearby at all |
| Custody over nearby | Under the friend custody gates and waiver | Covered there, not here |

## 4. Residual risks accepted

1. **The computer's name and model.** Connectable advertising exposes the
   OS's GATT data to any device that connects: the GAP Device Name on every
   OS and Device Information (model) on macOS. Raven cannot suppress it; it
   discloses it in the consent (with the actual name) and the threat model,
   and suggests renaming the computer (O5-12).
2. **Linkability.** Token epochs (15 minutes) and the OS's address rotation
   are not synchronized: sightings within an epoch, and across a change of
   one but not the other, can be linked to one advertising laptop.
3. **The BlueZ broadcast.** A BlueZ peripheral notifies every subscriber of a
   characteristic: a stranger that subscribes to one pair's service sees that
   pipe's ciphertext, sizes and timing (RNL1 §9), never a plaintext byte.
4. **Connection slots.** Strangers can hold GATT connections that macOS and
   Windows peripherals cannot drop. The caps (8 knocking connections, 4
   pipes) and the silence bound this to slot exhaustion, a denial of service
   no worse than jamming the radio.
4a. **A replayed beacon.** A token is a public UUID: someone who recorded one
   near a contact can play it back elsewhere while it still matches (up to
   about 30 minutes) and learn that the laptop it was meant for is in range,
   because that laptop connects to it. Each recorded token gets at most two
   connects (review nearby-4); the replayer learns no identity or key.
5. **macOS permission.** Which process macOS holds responsible for the
   Bluetooth permission of a helper started by a launchd agent is unverified;
   a refusal stops the helper only (SIGABRT), and raven-node backs off (1
   minute doubling to 1 hour).
6. **Cross-stack behaviour.** MTU timing, write-command flow control and
   silent drops, Windows GATT caching and supervision timeouts are found on
   hardware only; CI has no radio, and the fake radio and btvirt cannot show
   stack quirks.
7. **Throughput.** Possibly below 5-30 KB/s; each dial is a new Raven link
   (about 7.5 KB, plus 2.8 KB for PairInit). Several seconds per message on a
   poor link.
8. **Reach.** A contact who never linked before cannot be found; clocks more
   than about 15 minutes apart break discovery silently; two central-only
   computers can never reach each other, and a Windows PC uses nearby only
   after row N7w (today it is inactive).
9. **Battery and CPU** of continuous scanning (row N9 notes it).
10. **Downgrade of a lab file.** A lab `--carrier nearby` object makes
    `outbox_routes.json` unreadable to already-shipped builds, which then
    plan LAN only (narrow, but custodians-held bookkeeping is lost).

## 5. Compensating controls in place

- Off by default, asked once, and only for verified contacts with a cached,
  valid, non-revoked certificate; no setting admits anyone else.
- The knock comes first: a stranger never learns the stable Noise static key,
  and a node stays silent to any HELLO whose tag does not verify or whose
  nonce was seen (replay cache over two epochs, at least 256 entries per
  token); tags are compared in constant time.
- The advert carries one random-looking UUID with the version-4 bits set (off
  the Bluetooth Base UUID), only while there is work, from a random address.
- RNP1 refuses anything out of order (sequence gaps, credit overflow, wrong
  channel owner, oversize frames) and never retransmits: a broken pipe fails
  the dial and the outbox sends the exact bytes again; Noise AEAD fails
  closed underneath.
- RNB1 keys live in memory only and are wiped on drop; nothing about a
  Bluetooth peer is stored; logs, IPC and `raven status` carry counts and
  states only, never a token, address, device name or contact key.
- The macOS helper holds no keys and sees only tokens, characteristic UUIDs,
  device handles and frames; raven-node's code signature and Keychain access
  are untouched (the installer checks raven-node's signature before and
  after installing the helper).
- The gate is asserted false in `nearby_gate.rs`, `p2p_gate.rs` and
  `lan_gate.rs`; release builds read no lab switch.

## 6. Conditions

This waiver lapses, and `NEARBY_PRODUCTION_ENABLED` MUST be set back to
`false`, if any of these happens before it is renewed:

- any change to RNB1, RNK1 or RNP1 (wire, keys, labels, sizes, timers or
  caps), or to the Raven link prologue, without a new record;
- any change to the advertising policy: more tokens or contacts, a longer
  TTL, advertising without user-initiated work or `nearby on` (background
  mail without OD-C8), any added advert field, or advertising from a public
  address;
- admission of unpinned, unverified, blocked or revoked contacts, or first
  contact over Bluetooth;
- the macOS helper gaining access to a key, raven-node linking CoreBluetooth,
  or an installer re-signing raven-node;
- a log line, IPC field or stored file carrying a token, a Bluetooth address,
  a device name or a contact key from the nearby carrier;
- carrier_matrix C50-C53 or fault scenarios s63-s67 disabled, or failing on
  any of their runners for more than one release;
- the R2 amendment withdrawn;
- the review-by date passes without renewal.

## 7. Exit conditions before signature

All open until recorded; none of the software runs replaces the hardware
rows.

- **Unit and vector tests** on every OS job: raven-core `nearby_`
  (gate, RNL1 link, KATs regenerated unchanged), raven-node `nearby::` with
  the lab switch, the Python reference `test_nearby_vectors.py`, and the
  macOS helper's no-radio tests (`--bin raven-nearby-helper --test
  nearby_helper`).
- **carrier_matrix** (`--ignored`, ubuntu, macOS and Windows): C50 both ways
  with nearby the only path; C51 a stranger in range learns nothing; C52
  adverts rotate, carry no constant, name or manufacturer data, and unpinned
  contacts are never advertised; C53 a mid-message drop, then exactly one
  delivery; C56 the Bluetooth-only island.
- **lan_fault_matrix** (`RAVEN_FAULT_NEARBY=1`, macOS and Linux): s63-s66 and
  s72-s74; s67 with `RAVEN_FAULT_CUSTODY=1`.
- **Fuzzing:** `rnp1_frame` in the fuzz smoke.
- **Backends:** CI's first native runs of the WinRT backend and the macOS
  helper; the advisory `nearby-btvirt` job (BlueZ on emulated controllers)
  green, or its runner limitation recorded.
- **Installer:** `node/scripts/install/nearby_helper_selftest.sh` (the macOS
  helper install leaves raven-node's code signature unchanged).
- **Hardware rows** (an unpublished test checklist):
  N1-N4 10/10 each way per OS pair the owner can test (N4's central-only
  result recorded; Windows rows in a lab run with the public-address
  allowance until N7w); N5 the range curve; N6 the throughput (decides 5b);
  N7 the privacy capture per OS (flags plus one rotating UUID from a random
  address, no name, silence to strangers, a central's connect from a random
  address and none from a public one; the GAP name and model exposure
  recorded); N8 the background service per OS (on macOS the prompt
  names RavenNearby and no SIGABRT); N9 recovery with no user action; N10 the
  mule over nearby (with the custody waiver); N11 the carrier order; N12
  coexistence with Wi-Fi.
- **Owner decisions** recorded at signature (the recommended options are the
  ones built): O5-10 (the macOS crates and the helper), O5-11 (Linux and
  Windows libraries; Windows central-only rather than a sparse package),
  O5-12 (privacy and admission), O5-13 (gate, packaging and scope); OD-C8
  (background mail) if it is to be covered.

## 8. Frozen specs and files at the flip

1. [`protocol/RAVEN_NEARBY_LINK_V1.md`](../protocol/RAVEN_NEARBY_LINK_V1.md):
   its status line; its row in
   [`protocol/PROTOCOL_VERSIONS.md`](../protocol/PROTOCOL_VERSIONS.md).
2. [`RAVEN_PRIVATE_RENDEZVOUS_V1.md`](../protocol/RAVEN_PRIVATE_RENDEZVOUS_V1.md)
   §5.3b and its revision entry.
3. The user texts that say "held": [`NEARBY.md`](NEARBY.md),
   [`OFFLINE_GUIDE.md`](OFFLINE_GUIDE.md), [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md)
   (their `gate:` markers), the install guides and the README.
4. `docs/PROTOCOL_FREEZE_HASHES_V1.md` regenerated with
   `scripts/freeze_protocol_hashes.sh` in the same commit.

## 9. Signature

Not signed.
