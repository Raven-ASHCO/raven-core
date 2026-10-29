# DRAFT owner waiver amendment: security notices, release bundles and mesh updates (Phase 6b design D)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `ADVISORY_PRODUCTION_ENABLED`, `RELEASE_BUNDLE_PRODUCTION_ENABLED` and
> `MESH_UPDATE_PRODUCTION_ENABLED` (`node/crates/raven-core/src/security_gate.rs`)
> stay `false` until the owner signs a final copy for that gate (renamed to
> `docs/WAIVER_SECURITY_UPDATES_<date>.md`), the preconditions in §7 are met,
> and the flip is applied as its own reviewed commit. Debug builds open them
> with `RAVEN_LAB_ADVISORY=1`, `RAVEN_LAB_RELEASE_BUNDLE=1` and
> `RAVEN_LAB_MESH_UPDATE=1`, each with `RAVEN_LAB_TEST_A=1`; release builds
> never read them. **No build has the Raven project's release keys yet**
> (`RELEASE_KEY_SET_V1 = None` in `node/crates/raven-core/src/update_state.rs`):
> until the key ceremony and its one-line key set commit, every update
> artifact is refused even with the gates open ("This build has no Raven
> release keys; it can't check updates.").

| | |
|---|---|
| **Waiver ID** | `WAIVER-SECURITY-UPDATES-<date>` (to be assigned on signature) |
| **Gates** | `ADVISORY_PRODUCTION_ENABLED = false`; `RELEASE_BUNDLE_PRODUCTION_ENABLED = false` (sits on advisory); `MESH_UPDATE_PRODUCTION_ENABLED = false` (sits on bundle). Each is flipped and signed on its own (§8) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md): an advisory can refuse a link, PairInit or session suite of the live slice, and RUP1 rides its links (caps bit 10 in the dialer's RLX1). That record is not edited. On a held carrier RUP1 starts only when that carrier's own gate is live |
| **Not covered** | Built-in fetching from the internet (none: OD6b-23); installing by raven-node (never: only `raven` and the full-screen app install, after a typed word); running any file from a bundle (never); carrying releases for friends' other platforms (`node_policy.update_carry_for_friends`: not built); a hybrid or post-quantum release key set (algorithm 2 needs a new crate: a separate owner decision) |
| **Approver** | Protocol owner (signature pending) |
| **Date drafted** | 2026-10-24 |
| **Decision proposed** | Turn on, one gate at a time, threshold-signed security notices with a public release log, verified release bundles that a person imports and installs with a typed approval, and passing notices and releases between pinned friends (owner decisions OD6b-20 to OD6b-29, recommended options) |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set the gate's const back to `false` (§6) |
| **Design** | Plan `docs/roadmap/plans/phase6-design.json`, design P6b-D; [`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md); [`design/2026-10-suite-retirement.md`](design/2026-10-suite-retirement.md) |
| **Wire** | [`RAVEN_SECURITY_ADVISORY_V1.md`](../protocol/RAVEN_SECURITY_ADVISORY_V1.md) (RAD1, the suite registry), [`RAVEN_TRANSPARENCY_LOG_V1.md`](../protocol/RAVEN_TRANSPARENCY_LOG_V1.md) (RTL1), [`RAVEN_RELEASE_BUNDLE_V1.md`](../protocol/RAVEN_RELEASE_BUNDLE_V1.md) (RRB1 and RRBC), [`RAVEN_UPDATE_EXCHANGE_V1.md`](../protocol/RAVEN_UPDATE_EXCHANGE_V1.md) (RUP1, caps bit 10); vectors under `shared-vectors/rvn1/update/`; `PROTOCOL_VERSIONS.md` rows and freeze records. An old peer never sets bit 10 and never gets a RUP1 frame |
| **Threat model** | [`THREAT_MODEL.md`](THREAT_MODEL.md) §3.5, §3.10, §3.14 |
| **User docs** | `raven update --help`; the "Updating Raven" sections of [`INSTALL_macOS.md`](INSTALL_macOS.md), [`INSTALL_Linux.md`](INSTALL_Linux.md) and [`INSTALL_Windows.md`](INSTALL_Windows.md); [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) section 10 |
| **Real rows** | an unpublished test checklist: R31, R32, R33 |

## 1. Why a waiver is needed

These gates add a trust root that can change the live slice: an advisory
signed by two of the three release keys can make every Raven that accepts it
refuse a link, PairInit or session suite, close a feature, or warn that the
running release is vulnerable; a release bundle replaces Raven's own
programs; RUP1 adds a frame type to the live LAN links. The LAN waiver's §6
makes an extension of its scope without a new waiver a lapse condition, and
nothing of this kind existed when it was signed.

## 2. Scope (exactly what each gate turns on)

### 2.1 `ADVISORY_PRODUCTION_ENABLED`

1. **What a notice may do** (OD6b-21): `SUITE_STATUS` DEPRECATED (a warning)
   or BROKEN (refuses exactly that registered suite at its consult point: a
   link suite before every link handshake, `pairinit/1/1` when a PairInit is
   made or taken, the session profile at every seal and accept, the sessions
   then held; a wire module's id turns its feature off); `FEATURE_HOLD`
   BROKEN (closes a feature and what sits on it, never opens one; a hold on
   advisories themselves is shown, never enforced); `RELEASE_FLOOR` (a
   warning that this release is vulnerable); `NOTICE` (text shown with
   escape and bidirectional controls removed); `KEY_SET` (the next key set).
   Unknown ids and kinds are never enforced. There is no local override of
   BROKEN.
2. **Checks, in order** (RAD1 §6.1): the release keys, the threshold
   signatures (strict Ed25519, weak keys refused), the serial against the
   newest known one and the build's compiled floor (lower: a rollback,
   ignored), the chain (two signed notices with one serial, or a broken
   chain: equivocation, which freezes the update state with both kept as
   evidence; the same notice with a signature dropped is not), and the
   release log snapshot that must list it and be consistent with the stored
   log (two signed logs that are not prefixes of each other: a split view,
   which freezes too). Only a higher installed build serial clears a freeze:
   no notice does, since the key set that froze signed two histories. A
   notice under a key set the node never trusted (a rotation it missed)
   cannot be checked yet and is ignored without an event; a friend that
   took the rotation passes it on (RUP1 GET_ROTATION, at most 4 asks per
   friend a day). A friend asked for the rotation that gives none has that
   notice counted as forged (quarantine, `SEC_ADVISORY_FORGED` "passed on
   by" it, not asked for notices for 24 hours): a node cannot tell it from
   one under a key set made up. A friend on a build that ships the new key
   set and never took the rotation itself is counted so too, once a day
   (Phase 6 review re-verify).
3. **Stored** sealed in `updates/state` (at-rest kind 23); every refusal is
   its `SEC_*` event (70-76) "passed on by" whoever handed it over, never
   blamed; each stored notice is `SEC_ADVISORY_APPLIED`.
4. **Where notices come from:** `raven update import` of a file the person
   has (`.rad1` with its log snapshot), and, with mesh updates live, friends.

### 2.2 `RELEASE_BUNDLE_PRODUCTION_ENABLED` (on top of advisory)

1. `raven update import FILE.rrb` checks the whole bundle (the manifest's
   2-of-3 signatures or a rotated set the log vouches for, the log entry, this
   computer's target, a newer build serial, every chunk and file hash, the
   paths) and stages its files in `updates/staged/<serial>/` (0700; files
   0600, never executable). `raven update verify` checks and keeps nothing.
2. `raven update install` shows the version, size, signers, the log entry and
   the notes ("Raven never installs anything without asking you.") and goes
   on only after the person types `install` (`downgrade` and
   `--allow-downgrade` for an older build, never below the release floor:
   OD6b-26). It swaps programs only in the running program's folder, when that
   folder is writable, holds raven-node as a file, none of the release's
   programs there is a link, and no package manager keeps it; else it prints
   the manual steps and changes nothing. The old programs stay as
   `<name>.prev`; the new node must answer within 20 s or every program goes
   back by itself. `raven update rollback` swaps them back (typed
   `rollback`). Never `sudo`, never a script (OD6b-25). Neither runs while
   Raven is locked, by `raven lock` stopping it (Lock now v1) or by Lock v2
   holding the node: "Raven is locked: run raven unlock first", asked before
   the typed word and again just before the node is stopped, with nothing
   changed. The lock lives in the node's process, so a restart would start a
   keychain profile's node unlocked, and a locked node reports no listen
   address, so a node started again where no login item starts it would
   listen on the default address instead of its own (review
   lock-updates-local-6). A passphrase profile's node starts locked again
   after an update, as after any start.

### 2.3 `MESH_UPDATE_PRODUCTION_ENABLED` (on top of bundle)

RUP1 between pinned contacts only: each link's HAVE names the newest notice,
log and releases a node holds; a newer notice or longer log is fetched with
no command (a forged one goes to quarantine and that friend is not asked for
a day); a release for this computer's target is listed as an offer and
fetched only after `raven update download` (or the app's [Y]), manifest
first, then chunks from every friend offering it, each checked by its audit
path, resumable; complete, it is checked again and waits for the install
approval. Serving: pinned contacts only, at most 6 requests a minute and
128 MiB a day per friend, 2 at once; incoming at most 256 MiB (idle
downloads go after 7 days), quarantine at most 64 MiB for 7 days, never run.
Bluetooth carries notices and logs only. Never through custody, letters or a
relay's store. raven-node stages and installs nothing. A notice's hold on
release bundles stops bundles between friends, not notices; a hold on the
exchange itself (`feature/mesh-update`, `rup1/1` BROKEN) stops both, so only
a new build or a file import lifts it, and `raven-release advisory` asks for
such an entry to be marked as meant.

## 3. Holds

- The production key set (OD6b-20): the owner's key ceremony and the
  signed-off key set commit. Until then nothing can be checked.
- `SEC_UPDATE_FLOOD` (78) is registered but not raised: RUP1's quotas answer
  `RATE_LIMITED` or `BUSY` without an event.
- Decision D5 of the ratchet design (the V1 sunset) is open, and the next
  session profile does not exist: a BROKEN `atsam/indexed-session/v1` today
  holds every session until an update ([`design/2026-10-suite-retirement.md`](design/2026-10-suite-retirement.md)).

## 4. Residual risks accepted

1. **Two keys sign anything.** Theft or coercion of two keys (all three are
   held by the Protocol owner) can sign a malicious release; the person's
   typed approval, the public log and reproducible builds checked by others
   are the mitigations. Independent key holders can be added later by a
   `KEY_SET` rotation.
2. **A BROKEN notice for the only suite stops Raven** for everyone who
   accepts it, until they update: issue BROKEN only for a practical break,
   with a fixed release already in the log.
3. **Freezing in a cutoff.** Someone can withhold newer notices; Raven shows
   how old its newest one is. An isolated group that never meets anyone with
   a newer log can be shown a consistent false history (it still needs the
   keys).
4. **Ed25519 is not post-quantum.** A key set's algorithm byte allows a
   hybrid set later (a new crate: a separate owner decision).
5. **Limits of v1.** The log snapshot holds at most 1,400 entries (RTL2 with
   proofs must come before then); a RAD1 notice over 7,476 bytes may not fit
   beside a full log in one RUP1 frame (it then travels as a file); bundles
   cross LAN, Internet direct and p2p, not Bluetooth; the macOS arm64 payload
   is 57.6 MB of the 64 MiB RRB1 cap (raven-swarm may have to leave the
   bundle, or the cap grow, before the programs grow much more).
6. **Self-update is fiddly.** The swap is tested in a temp prefix on macOS and
   with a mock file system that follows Windows' rules; it has not run on a
   real Windows or Linux install, nor with a platform-signed macOS release
   (Gatekeeper, the firewall prompt, the keychain dialog a new signature
   brings). Raven's own installers lay the programs out differently from a
   release (macOS and Linux: `raven` with `ash` as a link to it, or no `ash`;
   Windows: `raven.exe` and `ash.exe` as two copies): the swap maps the
   release's `bin/ash` onto them (`raven` and each copy replaced, a link
   left as it is), which is tested on the mock file system in each layout,
   not yet on a real install. The "Updating Raven" sections of the install
   guides say so.
7. **Reproducibility** is checked on one Mac (two clones) only; Linux
   determinism is expected and macOS and Windows are best effort (platform
   signing changes the shipped bytes; `rebuild_sha256` covers the bytes
   before it).

## 5. Evidence

- **Local, macOS (this tree, gates held, lab switches on where named):** the
  RAD1, RTL1, RRB1/RRBC and RUP1 codecs with every rule's vector (Rust writes,
  the Python reference checks byte for byte), fuzz targets `rad1_decode`,
  `rtl1_snapshot`, `rrb1_manifest`, `rrbc_container`, `rup1_frame`; the update
  state, suite policy (a property test that no notice opens a closed gate),
  install and download tests; carrier_matrix C88 (a notice A -> B -> C;
  rollback, forged, equivocating notices and a split view, each refused by its
  event) and C89 (unsigned, forged, unlogged and downgraded releases refused;
  a good one passed A -> B -> C with approvals and installed in a temp
  prefix, `.prev` kept), C87 with every Phase 6 switch on; fault matrix s118
  and s119 (`RAVEN_FAULT_UPDATES=1`); `node/scripts/update_mesh_test.sh
  dry-run`; the release tool's tests and a full ceremony dry run with the
  published test keys; `node/scripts/release_tool_feature_audit.sh
  --release-build` (no release build holds the tool); a reproducible rebuild
  from a second clone in another folder (every file matched).
- **CI, open:** GitHub Actions is not running (org billing): the
  "reproducible build (advisory)" job (advisory until 10 greens), the
  vector drift step and the release inertness block have not run there.
- **Hardware, open:** R31, R32, R33.
- **Review:** the Phase 6 exit's adversarial review (P6.53) and the external
  review of the new wire formats before any flip.

## 6. Rollback

Set the const back to `false`. Advisory: no notice is read, applied or
checked, every consult point allows, and `updates/state` stays sealed and
unread. Bundle: `raven update` says "Raven updates are not part of this
version."; staged files stay until `raven erase` (programs an install
already swapped stay, with their `.prev`). Mesh update: no bit 10, no HAVE, no
RUP1 frame taken; `updates/downloads`, `incoming/` and `quarantine/` stay
unread.

## 7. Preconditions and flip order

- The key ceremony and the key set commit (OD6b-20,
  [`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md)), after R32 (its dry
  run).
- Order (OD6b-1, as decided): advisory, then bundle, then mesh update, after
  the local-protection gate.
- R33 and the CI reproducible job green; R31 for mesh updates.
- Bundle: a real swap on each system in the installers' layouts (the mapping
  of a release's `bin/ash` onto the installed `raven` is built and tested on
  the mock file system; see §4 item 6), including a platform-signed macOS
  release.
- The external review of RAD1, RTL1, RRB1/RRBC and RUP1; the Phase 6
  adversarial review done and its fixes clean.
- The install guides' "Updating Raven" sections and
  [`SAFETY_OFFLINE.md`](SAFETY_OFFLINE.md) (section 10 and the section 12
  rows marked with these gates) updated in the flip commit
  (`scripts/check_offline_guide.sh` fails until the markers match the code).

## 8. Signature

- `ADVISORY_PRODUCTION_ENABLED`: not signed.
- `RELEASE_BUNDLE_PRODUCTION_ENABLED`: not signed.
- `MESH_UPDATE_PRODUCTION_ENABLED`: not signed.
