# DRAFT owner waiver amendment: link padding, the link knock, a random port and pair seeds (Phase 6b design B)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `LINK_PADDING_PRODUCTION_ENABLED`, `LINK_KNOCK_PRODUCTION_ENABLED`,
> `LISTEN_PORT_RANDOM_PRODUCTION_ENABLED` and `PAIR_SEED_PRODUCTION_ENABLED`
> (`node/crates/raven-core/src/security_gate.rs`) stay `false` until the owner
> signs a final copy for that gate (renamed to
> `docs/WAIVER_TRAFFIC_ANALYSIS_<date>.md`), the preconditions in §7 are met,
> and the flip is applied as its own reviewed commit. Debug builds open them
> with `RAVEN_LAB_LINK_PADDING=1`, `RAVEN_LAB_LINK_KNOCK=1`,
> `RAVEN_LAB_RANDOM_PORT=1` and `RAVEN_LAB_PAIR_SEED=1`, each with
> `RAVEN_LAB_TEST_A=1`; release builds never read them.

| | |
|---|---|
| **Waiver ID** | `WAIVER-TRAFFIC-ANALYSIS-<date>` (to be assigned on signature) |
| **Gates** | `LINK_PADDING_PRODUCTION_ENABLED = false`; `LINK_KNOCK_PRODUCTION_ENABLED = false` (a compile-time check keeps it shut in release while M0, `LAN_NOISE_PIN_PRODUCTION_ENABLED`, is); `LISTEN_PORT_RANDOM_PRODUCTION_ENABLED = false`; `PAIR_SEED_PRODUCTION_ENABLED = false` (sits on route hints, `ROUTE_HINTS_PRODUCTION_ENABLED`, also `false`). Each is flipped and signed on its own (§8) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) (§2's carrier: what the live LAN link puts on the wire), next to its [cutoff amendment](WAIVER_LAN_DIRECT_CUTOFF_AMENDMENT_DRAFT.md) (M0, which the knock builds on) and its [route hints amendment](WAIVER_LAN_DIRECT_ROUTE_HINTS_AMENDMENT_DRAFT.md) (RRH1, which carries the pair seeds). None is edited. On Internet direct, p2p and Bluetooth the same features start only when that carrier's own gate is live ([`WAIVER_INTERNET_DIRECT_DRAFT.md`](WAIVER_INTERNET_DIRECT_DRAFT.md), [`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md); nearby's record after the main-line merge) |
| **Not covered** | The LAN beacon's length and timing jitter and its join round on need (Phase 3's `LAN_BEACON_PRODUCTION_ENABLED`, amended before its flip in [`WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md`](WAIVER_LAN_DIRECT_PHASE3_AMENDMENT_DRAFT.md) §4); cover traffic (not planned: OD6b-13); a post-quantum link handshake (Phase 6c); P6.32's tampering proxy rows (set aside) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-24 |
| **Decision proposed** | Turn on, one gate at a time, four frame-size classes on every link, the identity-hiding knock with per-connection Noise statics, a random port for new profiles and rotating pair seeds (owner decisions OD6b-8 to OD6b-12, recommended options) |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set the gate's const back to `false`; links, ports and keys are then as before the flip (§6) |
| **Design** | [`design/2026-10-traffic-analysis.md`](design/2026-10-traffic-analysis.md); plan `docs/roadmap/plans/phase6-design.json`, design P6b-B |
| **Wire** | [`RAVEN_LINK_PADDING_V1.md`](../protocol/RAVEN_LINK_PADDING_V1.md) (PAD1, caps bit 9), [`RAVEN_LINK_KNOCK_V1.md`](../protocol/RAVEN_LINK_KNOCK_V1.md) (RLK1, RLX1 entry `0x7E PAD`, rendezvous medium `0x03`), [`RAVEN_ROUTE_HINTS_V1.md`](../protocol/RAVEN_ROUTE_HINTS_V1.md) §14 (the `PAIR_SEED` entry); vectors under `shared-vectors/rvn1/link/`, `pair_seed/`, `lan/noise_xx_handshake_003.json`; `PROTOCOL_VERSIONS.md` rows and freeze records. A peer without a feature never sees it: every one is negotiated |
| **Threat model** | [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.4, §3.14, §3.17 |
| **User docs** | [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) sections 1, 4 and 12; `raven lan port --help` |
| **Real rows** | an unpublished test checklist: R35 |

## 1. Why a waiver is needed

Each gate changes what the live LAN slice of `WAIVER-LAN-DIRECT-2026-10-07`
puts on the wire or where it listens: padded frames (PAD1), knocked
handshakes with statics made for one connection (RLK1), another port for new
profiles, and pair keys from rotating seeds. The LAN waiver's §6 makes an
extension of its §2 scope without a new waiver a lapse condition.

## 2. Scope (exactly what each gate turns on)

### 2.1 `LINK_PADDING_PRODUCTION_ENABLED`

Both sides of a LAN, Internet direct, p2p or Bluetooth link that offered PAD1
pad every frame to 512, 4,096, 16,384 or 65,519 bytes (one Noise transport
message each; inner frames up to 65,511 bytes). A contact's frame that
breaks PAD1 on a link that agreed it closes the link (`SEC_CONTACT_MALFORMED`
while events are live). With the gate shut the hello, RLX1 and every frame
are byte for byte what earlier builds send.

### 2.2 `LINK_KNOCK_PRODUCTION_ENABLED`

On LAN and Internet direct: the dialer's Noise message 1 carries a 16-byte
tag only the contact can make; the listener answers a match with a static
made for that connection and a proof, and the dialer then uses a fresh static
of its own. Strangers get the derived static (legacy mode, until every
contact's capability mark shows the knock), a fresh one (strict) or no
message 2 at all (silent, `node_policy.security_silent_to_strangers = on`; no
command sets it yet). A dialer stops before message 3 when a contact whose
mark shows the knock answers without a proof (`SEC_ADDRESS_IMPOSTOR`, M0's
text). Knocked links write no M0 pins. A replayed knock is `SEC_KNOCK_REPLAY`
and answered as no match. Handshake sizes become ranges (message 1 64-95,
message 2 112-143, message 3 up to 128 bytes).

### 2.3 `LISTEN_PORT_RANDOM_PRODUCTION_ENABLED`

A profile made from then on picks a LAN port between 20,001 and 49,151 (a
short list of well-known ports skipped) and keeps it; existing profiles keep
7420 until `raven lan port random`. Cards, route hints and beacon answers
already carry the port.

### 2.4 `PAIR_SEED_PRODUCTION_ENABLED` (with route hints live)

Two verified friends agree a pair seed over RRH1 (the smaller identity key
proposes, at most every 7 days; the follower acks; the previous seed goes 2
days after the switch); beacon, knock and Bluetooth token keys come from the
seed, and the static-static root stays the fallback (`SEC_PAIR_SEED_ROOT`, a
Notice, when the root matched where a seed was expected). Stored sealed in
`pair_seeds.json` (at-rest kind 12); `raven contact remove` forgets it.

## 3. Holds

- P6.32's rows that need a tampering proxy or a fake listener at a friend's
  address (s113, C83) are not built (set aside by the owner, 2026-10-23); the
  knock's impostor stop is shown in-process only (LAN and Internet tests).
- Silent mode has no command and no Settings row yet; design B's "Hide
  message sizes" and "Silent to strangers" rows are not built.
- No real row for pair seeds is defined by the plan.

## 4. Residual risks accepted

1. **Passive listening stays undetectable, and the shape stays visible.**
   With every gate live an observer still sees addresses, times, durations,
   the number, direction and size class of frames, that Noise XX runs and
   that something accepts TCP connections on the port
   ([`design/2026-10-traffic-analysis.md`](design/2026-10-traffic-analysis.md)
   §4). A link to a peer without PAD1 is not padded.
2. **A random port that stays the same is a handle** across networks; it
   hides "this is Raven" only from someone who looks for 7420.
3. **The classical link layer.** A recording kept for a future quantum
   computer opens identities, route hints, pair seeds and the real sizes
   inside PAD1 (THREAT_MODEL §3.4); pair-seed forward secrecy does not hold
   against that break.
4. **Padding costs bandwidth:** a 293-byte ACK becomes 528 bytes on the wire,
   a PairInit 4,112.
5. **The knock can shut friends out:** an M0-only friend cannot reach a
   strict or silent listener (automatic mode waits for every contact's mark
   for that reason); a listener whose contact book cannot be read (a locked
   profile, the at-rest key still loading) answers its contacts as strangers;
   a friend who goes back to a build without the knock after knocking stops
   at the dial until `raven contact verify` and a typed `accept` lower its
   mark. The knock's replay cache keeps each matched nonce for the 3 days a
   knock can match, in the profile across restarts (sealed); a knock
   recorded and replayed within that window is seen (it still cannot finish
   the handshake).
6. **Pair seeds fall back to the root** for periods without a seed (before
   the first, after one is lost) and for the one root knock that follows any
   seeded knock that got no proof (whatever answers at a friend's address
   without the proof draws it), and do not help against a full disk image
   plus the keystore.

## 5. Evidence

- **Local, macOS (this tree, gates held, lab switches on where named):** PAD1
  and RLK1 codecs with every negative vector (Rust writes, the Python
  reference checks byte for byte, `noise_xx_handshake_003` whole), fuzz
  targets `pad1_frame` and `rlk1_m1`; carrier_matrix C86 part 1 (padding over
  LAN and Internet direct, mixed pairs), part 2 (knocked handshakes in their
  ranges, two stranger probes see two statics in strict mode, no message 2 in
  silent mode, an M0-only peer still reaches a knocking node) and part 3 (pair
  seeds agreed, knocked with, lost and agreed again); fault matrix s115
  (`RAVEN_FAULT_PADDING=1` against the pre-6b build `e28e03e`: an older build
  carries exactly the same message lengths as this one with the gate shut;
  `RAVEN_FAULT_KNOCK=1`, without an older build), s04r
  (`RAVEN_FAULT_RANDOM_PORT=1`); the pair-seed property test (400 runs x 300
  steps); full suites with each switch (P6.34-P6.38) and with every Phase 6b
  switch together (merge gates on `6b524a5`).
- **CI, open:** GitHub Actions is not running (org billing); the release
  inertness block sets these switches, but has not run there.
- **Hardware, open:** R35.
- **Review:** the Phase 6 exit's adversarial review (P6.53) and the external
  review of the new wire formats (design D's risk list: PAD1 and RLK1 among
  them) before any flip.

## 6. Rollback

Set the const back to `false`. Padding: no link offers bit 9 any more and
frames are bare again. Knock: listeners answer every dialer with the derived
static again and dialers send message 1 without a knock (M0's rules where M0
is live); the capability marks keep the knock, but nothing reads them for the
knock while its gate is shut. Random port: a profile that picked a port keeps
it in `node_policy.json`, which is read only while the gate is live, so a node
started with a bare `auto` (or by `raven` itself) listens on 7420 again and
friends need the address again; a login service whose settings name the
picked port keeps it until it is installed again. Pair seeds: every key is
the root's again; `pair_seeds.json` stays sealed and unread.

## 7. Preconditions and flip order

- Order (OD6b-1, as decided): padding after the sensing gates, then the knock
  (only with M0 live in release: its own approved cutoff flip); the random
  port and pair seeds when what they sit on is live (pair seeds need route
  hints).
- Padding: frames over 65,511 bytes (an RFC1 with an RSO1 within 8 bytes of
  its cap, an RHW1 HANDOFF at its cap) cannot cross a padded link; their
  senders must cap at 65,511 first (P6.34 open item).
- Knock: s115's mixed phases run once against a real pre-6b build
  (`RAVEN_FAULT_PADDING_OLD_BIN`); a command or Settings row for silent mode,
  or the owner's choice to keep it file-only.
- Random port: the Windows installer runs no `raven init` before it asks for
  the LAN default (P6.36), so with `auto` held a new Windows profile's task
  listens on 127.0.0.1:7420 until the installer runs again; fix it before the
  flip.
- R35 on test equipment; CI green; the external review of PAD1 and RLK1.
- [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) updated in the flip commit: its
  section 1, 4 and 12 markers for the flipped gate
  (`scripts/check_offline_guide.sh` fails until they match the code).

## 8. Signature

- `LINK_PADDING_PRODUCTION_ENABLED`: not signed.
- `LINK_KNOCK_PRODUCTION_ENABLED`: not signed.
- `LISTEN_PORT_RANDOM_PRODUCTION_ENABLED`: not signed.
- `PAIR_SEED_PRODUCTION_ENABLED`: not signed.
