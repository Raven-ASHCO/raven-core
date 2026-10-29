# Suite retirement and the next session profile (crypto agility)

| | |
|---|---|
| **Status** | Procedure and contract (Phase 6 step P6.50). Every gate it uses stays `false`: `SUITE_FLOOR_PRODUCTION_ENABLED` (on `SECURITY_EVENTS_PRODUCTION_ENABLED`) and `ADVISORY_PRODUCTION_ENABLED`. No next profile is built; nothing on the wire changes. |
| **Date** | 2026-10-24 |
| **Design** | `docs/roadmap/plans/phase6-design.json`, design D §7 and §8; design A R9. Owner decisions OD6b-7 (downgrade policy), OD6b-21 (what advisories may do), OD6b-29 (crypto agility and suite retirement). The ratchet design (`docs/design/2026-10-ratchet-fs-pcs.md`) §5.13 and its open decision D5. |
| **Code** | `node/crates/raven-core/src/capability_floor.rs` (`NextProfile`, `bundle_verified`, `session_confirmed`, `choose_profile`, the floor store), `suite_policy.rs` (`Policy::profile_status`, `Policy::profile_refusal`, `v1_sessions`), `suite_registry.rs` (the ids). |
| **Specs** | [`RAVEN_SECURITY_ADVISORY_V1.md`](../../protocol/RAVEN_SECURITY_ADVISORY_V1.md) §2 (key sets), §4 (registry), §8 (applying); [`ATSAM_HYBRID_RATCHET_V2.md`](../../protocol/ATSAM_HYBRID_RATCHET_V2.md) §15; [`PROTOCOL_VERSIONS.md`](../../protocol/PROTOCOL_VERSIONS.md), Negotiation. |

How Raven moves from its one session profile today (ATSAM indexed session V1) to the next one, how it
keeps a contact from being talked back down, and how an old suite is retired without cutting friends
off from each other. Raven ships the floor store, the enforcement API and a contract tested with a mock
profile; the next profile (HR v2 or HR3) is a separate program that plugs in.

## 1. Where Raven stands

- **One suite per layer, nothing to downgrade inside it.** PairInit V1 carries one suite byte
  (`pair_init::SUITE`) and refuses any other; ML-KEM-768 is mandatory in it; the Internet hello's caps
  are signed (`internet::hello_signing_bytes`) and the LAN dialer's RLX1 rides inside the Noise
  handshake hash. An attacker on the path has no choice to strip.
- **The registry** (`suite_registry`, RAD1 §4) names every negotiable suite and protocol version. A
  security notice (RAD1, signed by 2 of the 3 release keys) marks one INFO, DEPRECATED or BROKEN, and
  `suite_policy` applies it at its consult point (P6.45).
- **The floor** (`capability_floor`, P6.29) keeps, per contact, the best that contact's Raven ever
  showed. For session profiles it waits for a second profile: with only profile 1, nothing can be below
  the floor.

## 2. Session profiles

| Profile id | Profile | Bit in a bundle's signed `profile_set` | In this build |
|---:|---|---:|---|
| 1 | `atsam/indexed-session/v1` (made by `pairinit/1/1`, sealed as `rvna1/3`) | 0 | the only profile |
| 2 | HR v2 lab (`ATSAM_HYBRID_RATCHET_V2.md`) | 1 | no; lab only, always 0 in production bundles |
| 3 | HR3, `ATSAM/hybrid-ratchet/v3` (ratchet design §5) | 2 | no; the recommended next profile |

A profile's id is its bit plus one. Old peers keep getting V1 bundles (RLB1) until the sunset (§6).

## 3. How the next profile plugs in

The program implements `capability_floor::NextProfile`:

| Method | What it answers |
|---|---|
| `profile_id()` | its id (above 1) |
| `advertised(bundle)` | the profiles a verified PrekeyBundleV2's signed `profile_set` lists |
| `confirmed(session)` | whether the contact answered under one of its sessions |

and makes four calls:

| When | Call | Effect |
|---|---|---|
| it verified a contact's bundle (signature, lineage, rollback pin) | `bundle_verified` | the floor rises to the best profile both builds speak (`SetBy::Bundle`); a V1-only bundle raises nothing |
| the contact answered under a new session | `session_confirmed` | the floor rises to the next profile (`SetBy::Session`) |
| before any new session is made or taken, V1 included | `choose_profile` | the profile to use, or why none (§4) |
| whenever the applied notice may have changed | `suite_policy::v1_sessions(Some(id))` | what becomes of the V1 sessions already open (§6.2) |

The program also adds what only it can: its registry ids (`suite_registry`, `suite_policy::profile_ids`,
RAD1 §4.1, its `PROTOCOL_VERSIONS` row), RLB2 with the V2 bundle, the calls in V1's own PairInit paths
(`lan_dispatch`'s `create_initiator_pair_init` and `handle_pair_init`, where today's build needs none:
with one profile there is nothing to choose), its texts, and the re-seal target of §6.2.

## 4. Choosing a profile

`choose_profile(data_dir, peer, next, offered, via)` works the same both ways: `offered` is the verified
bundle's profile set when this node starts a session, and the profile of the contact's PairInit when it
takes one.

1. **The highest profile in common** of this build's set and `offered`. There is no negotiation
   message, so the choice is deterministic and there is nothing to strip. Nothing in common:
   `Refusal::Floor(Downgrade::NoCommonProfile)` (no security event: a newer build may have retired a
   profile).
2. **The applied notice.** A profile with an id marked BROKEN is left out (profile 1: any of
   `pairinit/1/1`, `atsam/indexed-session/v1`, `rvna1/3`). When nothing in common is left:
   `Refusal::Broken` with the `SUITE_BROKEN` text, either way.
3. **The floor** (`require_profile`): a profile below the contact's floor is an Alert
   (`SEC_CAPABILITY_DOWNGRADE`, once a day per contact) and is refused while `SUITE_FLOOR` is live. A
   notice never lowers a floor: if a notice ever marked the profile at the floor BROKEN, that contact
   gets nothing lower either until the person lowers it (§5).
4. **A retiring profile** (DEPRECATED) is used when the contact offers nothing newer, and `Choice.warn`
   asks the caller to tell the person, once per contact and notice in the process:
   "Sara's Raven still uses an older security method that is being retired. Ask Sara to update Raven."
   (`suite_policy::retiring_contact_text`). A contact that offers the newer profile gets it without a
   word.

With the advisory and events gates shut (every release build today) the choice is the highest profile
in common, exactly as before.

## 5. The sticky floor

- **Raised** by a verified bundle that lists the next profile or by a confirmed session under it; kept
  per contact identity key in `capability_floor.json` (sealed, RMS1 kind 11). Only profiles this build
  speaks are kept.
- **Enforced:** afterwards V1 is refused to and from that contact while `SUITE_FLOOR` is live (a
  replayed V1-only bundle when starting, a PairInit V1 when taking). Sessions already open are not
  touched.
- **Lowered only by the person**, after comparing the 10 security words with the contact
  (`CodeMatch::check`; the old code is not enough) and typing `accept` (`raven contact verify`, the
  terminal app's "Check again"). No network event, no notice and no other code path can lower it (a
  source scan keeps those two the only callers). Removing the contact forgets its floor.
- **Fails closed:** while `SUITE_FLOOR` is live, a floor file that cannot be read refuses anything
  below this build's highest profile.
- **Residual window** (ratchet design §5.13): the first contact between two new builds over a replayed,
  still valid V1-only bundle, before any floor exists. On LAN the bundle comes from the peer over Noise
  XX, so the attack needs the peer's key. A consistent rollback of the whole profile folder rolls the
  floor back too.

## 6. Retiring a suite

| Stage | Who decides, how it ships | What a build does |
|---|---|---|
| ALLOWED | (nothing) | uses it |
| DEPRECATED | a notice (`SUITE_STATUS` DEPRECATED, 2 of 3 keys), once the newer profile has shipped | refuses nothing: shows it (`raven status`, the terminal app's SEC, `raven doctor`), prefers the newer profile, warns once per contact that offers nothing newer (§4) |
| sunset | a release: the date is set per release (owner decision D5 of the ratchet design, not taken yet) | the release that sets it stops starting V1 sessions at the date; the ratchet design (§5.13 item 5, phase P7) also has it refuse PairInit V1 and stop publishing V1 bundles after the date, which D5 settles; older releases are unaffected |
| BROKEN | a notice (`SUITE_STATUS` BROKEN), **only for a practical break**, never as a schedule | refuses it both ways (no new V1 session made or taken); a BROKEN session profile also stops the V1 sessions already open (§6.2); no local override (OD6b-21); nothing expires by time |

V1 is never retired automatically when the next profile ships (OD6b-29): friends who cannot update
during a cutoff would lose each other. A notice can never lower a floor, open a gate, or choose a profile
the contact does not offer.

### 6.1 Which id to mark

| To retire | Mark | Effect on the sessions open |
|---|---|---|
| starting new V1 sessions | `pairinit/1/1` | none: they go on |
| the V1 session itself | `atsam/indexed-session/v1` (and `rvna1/3` for its sealed body) | §6.2 |

### 6.2 V1 sessions under a BROKEN session profile

`suite_policy::v1_sessions(next)`:

- **`Go`**: nothing BROKEN at the session layer (DEPRECATED and a BROKEN `pairinit/1/1` included).
- **`Held`** (this build, no next profile): every V1 session seals and takes nothing (`SUITE_HELD`);
  what waits in them stays until Raven is updated.
- **`Retire { into }`** (a build with the next profile): each V1 session is retired for sending; Phase
  2a re-seals what waited in it under a session of `into` with that contact, chosen by
  `choose_profile`; a contact that does not speak `into` yet keeps it waiting; the V1 session takes
  nothing more (still `SUITE_HELD`).

The program brings the re-seal target and a retire cause for it. The store's `retire_cause` column is
checked `BETWEEN 1 AND 7`, and builds since P6.27 rebuild a reset table whose check differs from theirs
(`widen_retire_causes`), so a new cause needs a rule that keeps older builds working on a profile a
newer one wrote; this step adds none.

### 6.3 The lab dry run

raven-node's update exchange fixture (`a_deprecated_pairinit_notice_only_warns_at_every_hop`): a notice
signed by the published test keys marks `pairinit/1/1` DEPRECATED and goes A -> B -> C over RUP1, each
hop fetching it from the friend before. Every profile shows "an older security method is being retired
(pairinit/1/1)", and nothing else changes: no link, PairInit, session or feature refused, no release
floor or text, the contact book as it was, no floor written, V1 still the session profile.

### 6.4 Holds on link features (knock, padding)

A `FEATURE_HOLD` (or a BROKEN wire module) closes a feature on each node when that node applies the
notice, and nodes apply it at different times. For most features that is close-only safe. For the
two a contact's capability floor tracks it is not, so they are handled apart (Phase 6 review
traffic-4):

- **Floors.** While this node holds `feature/link-padding` (or `pad1/1`) or `feature/link-knock`
  (or `rlk1/1`), its capability floors leave that feature out (`capability_floor::observe_link`,
  `observe_link_seen`): a showing without it is no `SEC_CAPABILITY_DOWNGRADE`, and one with it
  raises nothing. Its own links lack the feature, and so do those of every contact that applied
  the notice.
- **The knock's listener.** A hold on the knock stops this node's knocks (no dial knocks), but its
  listener still reads message 1 and proves itself to a contact that knocks
  (`security_gate::live_despite_own_hold`). A contact whose notice has not come yet, whose floor
  shows the knock and that holds no pin (pairs that met with the knock have none) would otherwise
  get no proof and stop at this node's address as at an impostor (`SEC_ADDRESS_IMPOSTOR`, and R5
  forgets the address), on every retry, until the notice reached it. So a knock hold closes the
  dialing half only; a break that needs the listener half closed too needs a release.
- **What remains.** Until a contact applies the notice, the held node's own links show it no
  padding and no knock, so that contact notes one Suspicious `SEC_CAPABILITY_DOWNGRADE` a day about
  the held node, which stays open until the person lowers it (`raven contact verify`). Issue these
  holds knowing that; they reach friends over RUP1 on the links that still work (the held node's
  own dials, p2p, nearby).

## 7. Release key sets: algorithm agility

- A key set starts with an algorithm byte (RAD1 §2.1): `0x01` = Ed25519, the only one. A later
  `0x02` (Ed25519 together with ML-DSA-65, both required) would protect updates against a future
  quantum forger. It needs a new crate, so it is a later owner decision (`docs/roadmap/README.md` section 2, rule 6).
- Decoders refuse an unknown algorithm before they look at its length (`UNSUPPORTED_ALG`), so an alg-2
  set in a `KEY_SET` entry is `BAD_ENTRY` for a build that knows only alg 1, and the whole advisory is
  invalid there (RAD1 §5). The move therefore goes:
  1. a release that verifies alg 2 ships first, still trusting the alg-1 set;
  2. the newest alg-1 advisory carries a `RELEASE_FLOOR` at that release, so older builds warn;
  3. the rotation travels where older builds can skip it (a new entry kind, which keeps an advisory
     valid for them (RAD1 §3.2), or a RAD1 version 2), never as an alg-2 `KEY_SET`;
  4. after it, older builds cannot check newer notices and keep what they applied (nothing expires).
- The ceremony is the same, with new keys: 2 of 3 offline keys (`docs/RELEASE_KEY_CEREMONY.md`).

## 8. Tests

- `capability_floor` (a mock HR3, notices applied on the test's thread): the highest profile in common
  whatever the order of the offer; the floor raised by a verified bundle or a confirmed session (not by
  a V1-only bundle or an unconfirmed session); V1 refused both ways while `SUITE_FLOOR` is live, noted
  only while it is shut, a contact without a floor unaffected; lowered only with that contact's own
  words; DEPRECATED V1 warns once per contact and notice and prefers HR3; BROKEN V1 refused both ways,
  its sessions retired into HR3 by the mock program's sweep (a V1-only contact's left waiting), and
  `Held` without a next profile; with the gates shut, the highest profile in common and nothing
  written.
- `suite_policy`: profile 1 takes the worst status of its ids, the refusal text names every BROKEN
  one, `v1_sessions` for each id and severity, an unregistered profile never refused.
- raven-node: the dry run of §6.3.

## 9. Open

- The next profile itself (HR v2 or HR3), a separate program.
- D5: the sunset date and whether the sunset also refuses inbound PairInit V1 at once.
- Alg 2 for release key sets (a new crate).
- The retire cause and re-seal target of §6.2, and the calls in V1's PairInit paths (§3).
