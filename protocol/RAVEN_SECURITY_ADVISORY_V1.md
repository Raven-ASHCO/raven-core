# RAVEN Security Advisory V1 (RAD1)

**Version:** 1 (`RAD1`, version byte `1`); release key sets V1 (algorithm byte `1`)
**Status:** Draft; **production disabled** (`ADVISORY_PRODUCTION_ENABLED = false`).
Lab only: debug builds with `RAVEN_LAB_ADVISORY=1` and `RAVEN_LAB_TEST_A=1`
(`raven-core/src/security_gate.rs`). Release builds ignore the switch. This
revision defines the format, the key sets, the registry and the checks; the
update state (`raven-core/src/update_state.rs`, behind the same gate) checks
and stores advisories, and no build applies one yet. Until the owner's key
ceremony puts the public release key set into the source, release builds
have **no** release keys and refuse every advisory (`NO_RELEASE_KEYS`); a
debug build with `RAVEN_LAB_TEST_A=1` may load a test key set from the file
`RAVEN_LAB_RELEASE_KEYS_FILE` names.
**Audience:** re-implementers; operators of the offline release tool.
**Design:** `docs/roadmap/plans/phase6-design.json`, design D §1, §2, §7, §8
and wire specs W-D1 and W-D6; owner decisions OD6b-20 (2-of-3 offline keys),
OD6b-21 (what advisories may do), OD6b-29 (crypto agility).

---

## 1. Purpose

Nothing tells a running Raven today that a crypto suite or a protocol version
is broken, or that its own release has a known security problem; in a
cutoff, a friend cannot pass such a notice on in a form the receiver can
check.

A **security advisory** is a numbered, signed list of such notices. The
Raven project holds three offline Ed25519 release keys; an advisory counts
only when **2 of the 3** signed it. Each advisory is the **whole current
list** (cumulative): advisory #6 replaces #5. Serials only grow, and each
advisory names the digest of the one before it, so an old advisory cannot be
passed off as current, and two different advisories with one serial are
evidence that the signers issued two histories.

An advisory can:

- mark a registered suite or protocol version (§4) INFO, DEPRECATED (warn)
  or BROKEN (refuse; no local override);
- name the oldest safe release (a warning; Raven keeps working);
- put a close-only hold on a gated feature;
- carry a short text;
- name the next release key set.

An advisory can **never**: open a gate, turn a feature on, change a contact,
a key pin, a block list, a route or a message, run or download anything, or
refer to a person. Nothing in it expires by time: a cutoff must not un-break
a suite.

The transparency log every artifact is entered in (RTL1,
[`RAVEN_TRANSPARENCY_LOG_V1.md`](RAVEN_TRANSPARENCY_LOG_V1.md)), release bundles
(RRB1, [`RAVEN_RELEASE_BUNDLE_V1.md`](RAVEN_RELEASE_BUNDLE_V1.md)), passing
advisories between friends (RUP1) and storing and applying them are separate
drafts and steps; this document is the advisory format, the key sets every
signed update artifact uses (§2) and the registry (§4).

## 2. Release key sets and signature blocks

All integers are big-endian.

### 2.1 Key set

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 1 | `alg`: `0x01` = Ed25519 |
| 1 | 1 | `threshold`: how many keys must sign, 1..=`n` |
| 2 | 1 | `n`: number of keys, 1..=8 |
| 3 | 32 * `n` | the public keys; key index `i` is the `i`-th |

`key_set_digest = SHA-256("rvn1/release-keys/v1\0" || KeySet)`. Every signed
artifact names the key set that signs it by this digest.

A decoder refuses key set bytes on the first rule they break, in this order:

| Order | Rule | Error |
|---:|---|---|
| 1 | at least 3 bytes | `BAD_LENGTH` |
| 2 | `alg` is `0x01` | `UNSUPPORTED_ALG` |
| 3 | `n` is 1..=8 | `BAD_COUNT` |
| 4 | exactly `3 + 32 * n` bytes | `BAD_LENGTH` |
| 5 | `threshold` is 1..=`n` | `BAD_THRESHOLD` |
| 6 | each key, in order: the canonical encoding of a point on the curve (it decodes, and encodes back to the same 32 bytes: no `y >= p`, no sign bit on `x = 0`) that does not have small order | `WEAK_KEY` |
| 7 | each key, in order: not equal to an earlier key | `DUPLICATE_KEY` |

Rules 6 and 7 are checked key by key (key 0's rules, then key 1's, ...).
Canonical, distinct keys mean one key holder can never count twice toward
the threshold. An unknown `alg` is refused before its length is checked, so
a later algorithm (`0x02`: Ed25519 together with a post-quantum signature,
both required; design D §8, a later owner decision) may use other key
lengths.

The production key set is 2 of 3 (OD6b-20). The key set a build trusts is
compiled in (`RELEASE_KEY_SET_V1`, `None` until the key ceremony) and changes
only by rotation (§6.2).

### 2.2 Signature block

```
block = sig_count u8 || (key_index u8 || signature[64]) * sig_count
```

The block ends the artifact: exactly `1 + 65 * sig_count` bytes follow the
signed bytes, nothing after them. Each `signature` is Ed25519 over the
artifact's signing input (RAD1: §3.4) by the key at `key_index`.

### 2.3 Checking a signature block

Against a key set, in this order; the first failure refuses the artifact
(the artifact is forged: `SEC_ADVISORY_FORGED` for an advisory):

| Order | Rule | Error |
|---:|---|---|
| 1 | the artifact's `key_set_digest` is this key set's digest | `WRONG_KEY_SET` |
| 2 | the block is exactly `1 + 65 * sig_count` bytes (for RAD1 a decode rule, §5: `BAD_SIG_BLOCK`) | `MALFORMED` |
| 3 | key indexes strictly increasing (one key listed twice fails here) | `KEY_INDEX_ORDER` |
| 4 | every key index below `n` | `UNKNOWN_KEY_INDEX` |
| 5 | `sig_count >= threshold` | `BELOW_THRESHOLD` |
| 6 | **every** listed signature verifies, strictly | `BAD_SIGNATURE` |

- Rules 3 and 4 give `threshold <= sig_count <= n` together with rule 5.
- Rule 6 holds for each signature, even when the others already meet the
  threshold: one bad signature fails the artifact
  (`negative/rad1_bad_sig_among_good_001.json`).
- Strict Ed25519 (as `Identity::verify` in raven-core and
  `raven_protocol.ed25519_strict` in the Python reference): the public key
  and the signature's `R` must not be small-order encodings, and `s` must be
  canonical (`s < L`).

### 2.4 Test keys

The published test keys are the Ed25519 keys of the seeds `0x11 x 32`,
`0x22 x 32` and `0x33 x 32` (key indexes 0, 1, 2), in a 2-of-3 key set
(`update/keyset_001.json`, digest `d84b699b...c332`). Anyone can sign with
them: they exist in test and debug builds only (`release_keys::test_keys`),
and a production key set must never contain one.

## 3. Advisory (RAD1)

### 3.1 Layout

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `RAD1` (`52 41 44 31`) |
| 4 | 1 | version `0x01` |
| 5 | 1 | flags `0x00` |
| 6 | 2 | `entry_count`, 0..=64 |
| 8 | 8 | `serial`, >= 1 |
| 16 | 8 | `issued_at_ms` (Unix time, milliseconds; shown, never enforced) |
| 24 | 32 | `key_set_digest` (§2.1) |
| 56 | 32 | `prev_digest`: the `advisory_digest` of advisory `serial - 1`; all zero exactly when `serial` is 1 |
| 88 | ... | `entry_count` entries (§3.2) |
| ... | ... | signature block (§2.2) |

An advisory is at most `MAX_RAD1_LEN = 32,768` bytes, signature block
included.

### 3.2 Entries

```
entry = kind u8 || severity u8 || target_len u8 || target
     || arg_len u16 || arg || text_id u16
```

- `target`: 1..=64 bytes of `[a-z0-9._/-]`, `/`-separated segments, none
  empty (no leading, trailing or double `/`).
- `arg`: 0..=1,024 bytes.
- `text_id`: the build's own text for this entry (0: none). A build that
  does not have the text shows its kind's generic text. Texts are never
  carried in an entry except a NOTICE's.

| Kind | Name | Target | Argument | Meaning |
|---:|---|---|---|---|
| `0x00` | (reserved) | | | refused: `BAD_KIND` |
| `0x01` | `SUITE_STATUS` | a suite id (§4.1): contains `/`, does not start with `feature/` | empty | the suite or protocol version is INFO, DEPRECATED or BROKEN |
| `0x02` | `RELEASE_FLOOR` | `raven` | `min_safe_build_serial` u64, >= 1 | builds with a lower serial have a known security problem: warn, never stop Raven |
| `0x03` | `FEATURE_HOLD` | `feature/<gate>` (§4.2): exactly two segments | empty | BROKEN closes the gated feature, DEPRECATED warns, INFO says nothing; never opens it |
| `0x04` | `NOTICE` | `notice` | 1..=1,024 bytes of UTF-8 | a text, shown sanitized (escape sequences and bidirectional controls removed) |
| `0x05` | `KEY_SET` | `keys` | a key set (§2.1) | the next release key set (§6.2) |
| `0x06`-`0xFF` | (unknown) | any target | any argument | valid; shown as "a notice this version doesn't understand: update Raven"; never enforced |

- Two entries with the same kind and the same target refuse the whole
  advisory (so there is at most one `RELEASE_FLOOR`, one `NOTICE` and one
  `KEY_SET`). The same target under two kinds is allowed.
- Entries are in no particular order.

### 3.3 Severity

| Value | Name | Allowed for |
|---:|---|---|
| 0 | `INFO` | every kind |
| 1 | `DEPRECATED` | every kind |
| 2 | `BROKEN` | `SUITE_STATUS`, `FEATURE_HOLD` and unknown kinds only |
| 3-255 | | refused: `BAD_SEVERITY` |

### 3.4 Signing input and digest

- Signing input: `"rvn1/advisory/v1\0" || bytes[0 .. start of the signature block]`.
- `advisory_digest = SHA-256("rvn1/advisory/digest/v1\0" || all bytes)`,
  signature block included. The next advisory's `prev_digest`, the
  transparency log and RUP1 name an advisory by it.

## 4. Suite and protocol-version registry

Every negotiable suite and protocol version has an id, and every gated
feature has a hold id. Ids are RAD1 targets (§3.2) and never change meaning:
a new version of a suite gets a new id. The registry in code is
`raven-core/src/suite_registry.rs`; a test there keeps it equal to the
tables below, and another fails when raven-core gains a gate without a
feature id here.

### 4.1 Suites (`SUITE_STATUS`)

| Id | What | Consulted | BROKEN means |
|---|---|---|---|
| `noise/xx-25519-chachapoly-blake2s` | the Noise handshake of every Raven link (`Noise_XX_25519_ChaChaPoly_BLAKE2s`) | before every link handshake (LAN direct, Internet direct, p2p, nearby) | no link: no contact can be reached until Raven is updated, and the text says so |
| `rih1/1` | the signed Internet hello, version 1 ([`RAVEN_TRANSPORT_INTERFACE_V1.md`](RAVEN_TRANSPORT_INTERFACE_V1.md)) | before every link handshake | no link |
| `rlb1/1` | the LAN bind and offer, version 1 | before every link handshake | no link |
| `pairinit/1/1` | PairInit version 1 with suite 1 (X25519 + ML-KEM-768) | creating and accepting a PairInit | no new session of version 1, either way |
| `atsam/indexed-session/v1` | the ATSAM indexed session V1 ([`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](ATSAM_INDEXED_SESSION_PROFILE_V1.md)) | sealing and accepting on a session | existing V1 sessions retired: re-sealed under the next profile when there is one, otherwise held with an explanation |
| `rvna1/3` | the RVNA1 sealed body, header version 3 | sealing and accepting on a session | as `atsam/indexed-session/v1` |
| `rrh1/1` | route hints ([`RAVEN_ROUTE_HINTS_V1.md`](RAVEN_ROUTE_HINTS_V1.md)) | the feature's live check | route hints off (`ROUTE_HINTS_PRODUCTION_ENABLED`'s feature) |
| `rfc1/1` | friend custody ([`RAVEN_FRIEND_CUSTODY_V1.md`](RAVEN_FRIEND_CUSTODY_V1.md)) | the feature's live check | friend custody off |
| `rsr1/1` | session reset ([`RAVEN_SESSION_RESET_V1.md`](RAVEN_SESSION_RESET_V1.md)) | the feature's live check | session reset off |
| `ral1/1` | async letters ([`RAVEN_ASYNC_LETTER_V1.md`](RAVEN_ASYNC_LETTER_V1.md)) | the feature's live check | letters off |
| `rhw1/1` | custody handoff ([`RAVEN_CUSTODY_HANDOFF_V1.md`](RAVEN_CUSTODY_HANDOFF_V1.md)) | the feature's live check | handoff off |
| `rnl1/1` | the Bluetooth LE nearby link ([`RAVEN_NEARBY_LINK_V1.md`](RAVEN_NEARBY_LINK_V1.md)) | the feature's live check | nearby off |
| `pad1/1` | link padding ([`RAVEN_LINK_PADDING_V1.md`](RAVEN_LINK_PADDING_V1.md)) | the feature's live check | link padding off |
| `rlk1/1` | the link knock ([`RAVEN_LINK_KNOCK_V1.md`](RAVEN_LINK_KNOCK_V1.md)) | the feature's live check | the knock off |
| `rup1/1` | the update exchange between friends ([`RAVEN_UPDATE_EXCHANGE_V1.md`](RAVEN_UPDATE_EXCHANGE_V1.md)) | the feature's live check | the exchange off |

DEPRECATED never refuses: it warns once per contact ("Sara still uses an
older security method; ask her to update"), and where two versions are
possible the newer is preferred.

### 4.2 Feature holds (`FEATURE_HOLD`)

`feature/<gate>`: the gate constant's name without `_PRODUCTION_ENABLED`, in
lower case, `_` written `-`. A hold is consulted inside the feature's live
check **after** its own gate, so it can only close.

| Id | Gate (raven-core) |
|---|---|
| `feature/advisory` | `security_gate::ADVISORY_PRODUCTION_ENABLED` (not holdable, §4.3) |
| `feature/app-channel` | `app_channel::APP_CHANNEL_PRODUCTION_ENABLED` |
| `feature/async-letter` | `horizon::ASYNC_LETTER_PRODUCTION_ENABLED` |
| `feature/custody-handoff` | `custody_gate::CUSTODY_HANDOFF_PRODUCTION_ENABLED` |
| `feature/friend-custody` | `custody_gate::FRIEND_CUSTODY_PRODUCTION_ENABLED` |
| `feature/friend-relay` | `p2p_gate::FRIEND_RELAY_PRODUCTION_ENABLED` |
| `feature/groups` | `group::GROUPS_PRODUCTION_ENABLED` |
| `feature/indexed-session-store` | `indexed_session_store::INDEXED_SESSION_STORE_PRODUCTION_ENABLED` |
| `feature/internet-direct` | `internet_gate::INTERNET_DIRECT_PRODUCTION_ENABLED` |
| `feature/lan-auto-listen` | `lan_gate::LAN_AUTO_LISTEN_PRODUCTION_ENABLED` |
| `feature/lan-beacon` | `lan_beacon::LAN_BEACON_PRODUCTION_ENABLED` |
| `feature/lan-direct` | `lan_gate::LAN_DIRECT_PRODUCTION_ENABLED` |
| `feature/lan-noise-pin` | `lan_gate::LAN_NOISE_PIN_PRODUCTION_ENABLED` |
| `feature/learning` | `learning::LEARNING_PRODUCTION_ENABLED` |
| `feature/link-knock` | `security_gate::LINK_KNOCK_PRODUCTION_ENABLED` |
| `feature/link-padding` | `security_gate::LINK_PADDING_PRODUCTION_ENABLED` |
| `feature/listen-port-random` | `security_gate::LISTEN_PORT_RANDOM_PRODUCTION_ENABLED` |
| `feature/local-protection` | `security_gate::LOCAL_PROTECTION_PRODUCTION_ENABLED` |
| `feature/long-horizon` | `horizon::LONG_HORIZON_PRODUCTION_ENABLED` |
| `feature/mesh-update` | `security_gate::MESH_UPDATE_PRODUCTION_ENABLED` |
| `feature/nat-class` | `portmap_gate::NAT_CLASS_PRODUCTION_ENABLED` |
| `feature/nearby` | `nearby_gate::NEARBY_PRODUCTION_ENABLED` |
| `feature/offline-lan` | `lan_gate::OFFLINE_LAN_PRODUCTION_ENABLED` |
| `feature/onion` | `onion_gate::ONION_PRODUCTION_ENABLED` |
| `feature/p2p` | `p2p_gate::P2P_PRODUCTION_ENABLED` |
| `feature/pair-seed` | `security_gate::PAIR_SEED_PRODUCTION_ENABLED` |
| `feature/peer-rotation` | `portmap_gate::PEER_ROTATION_PRODUCTION_ENABLED` |
| `feature/port-map` | `portmap_gate::PORT_MAP_PRODUCTION_ENABLED` |
| `feature/prekey-lifecycle` | `prekey_lifecycle::PREKEY_LIFECYCLE_PRODUCTION_ENABLED` |
| `feature/release-bundle` | `security_gate::RELEASE_BUNDLE_PRODUCTION_ENABLED` |
| `feature/route-hints` | `route_hints::ROUTE_HINTS_PRODUCTION_ENABLED` |
| `feature/security-events` | `security_gate::SECURITY_EVENTS_PRODUCTION_ENABLED` |
| `feature/security-responses` | `security_gate::SECURITY_RESPONSES_PRODUCTION_ENABLED` |
| `feature/serverless-punch` | `portmap_gate::SERVERLESS_PUNCH_PRODUCTION_ENABLED` |
| `feature/session-renewal` | `session_renewal::SESSION_RENEWAL_PRODUCTION_ENABLED` |
| `feature/session-reset` | `session_reset::SESSION_RESET_PRODUCTION_ENABLED` |
| `feature/session-reset-restore` | `session_reset::SESSION_RESET_RESTORE_PRODUCTION_ENABLED` |
| `feature/stun-discovery` | `portmap_gate::STUN_DISCOVERY_PRODUCTION_ENABLED` |
| `feature/suite-floor` | `security_gate::SUITE_FLOOR_PRODUCTION_ENABLED` |
| `feature/v6-pinhole` | `portmap_gate::V6_PINHOLE_PRODUCTION_ENABLED` |
| `feature/wss` | `wss_gate::WSS_PRODUCTION_ENABLED` |
| `feature/wss-proxy` | `wss_gate::WSS_PROXY_PRODUCTION_ENABLED` |

### 4.3 Registry rules

- An id this build does not have (a suite or gate added later) keeps the
  advisory valid and is not enforced: this build has nothing to refuse or
  close. Advisories are cumulative, so later ids always travel with the
  older ones.
- `feature/advisory` is not holdable: a hold on advisories would also stop
  the advisory that lifts it. Such an entry is shown and never enforced.
- `raven`, `notice` and `keys` are the fixed targets of `RELEASE_FLOOR`,
  `NOTICE` and `KEY_SET`; they are not registry ids.
- A new id needs a row here, in `suite_registry.rs` and in
  `PROTOCOL_VERSIONS.md`'s draft table entry of its protocol.

## 5. Decode rules

A decoder refuses advisory bytes on the first rule they break, in this
order. A field that runs past the end of the bytes, wherever it is, is
`TRUNCATED`; each field is checked as it is read.

| Order | Rule | Error |
|---:|---|---|
| 1 | at most 32,768 bytes | `TOO_LONG` |
| 2 | magic `RAD1` | `BAD_MAGIC` |
| 3 | version `0x01` | `BAD_VERSION` |
| 4 | flags `0x00` | `BAD_FLAGS` |
| 5 | `entry_count` <= 64 | `TOO_MANY_ENTRIES` |
| 6 | `serial` >= 1 | `BAD_SERIAL` |
| 7 | `prev_digest` all zero exactly when `serial` is 1 (read after `issued_at_ms` and `key_set_digest`) | `BAD_PREV` |
| 8 | each entry, in order, rules 8a-8g | |
| 8a | `kind` is not `0x00` | `BAD_KIND` |
| 8b | `severity` <= 2 | `BAD_SEVERITY` |
| 8c | `target_len` is 1..=64; then the target is `[a-z0-9._/-]` with no empty segment | `BAD_TARGET` |
| 8d | `arg_len` <= 1,024 (then the argument and `text_id` are read) | `BAD_ARG` |
| 8e | not `BROKEN` on `RELEASE_FLOOR`, `NOTICE` or `KEY_SET` | `BAD_SEVERITY` |
| 8f | a known kind's target and argument rule (§3.2) | `BAD_ENTRY` |
| 8g | no earlier entry with the same kind and target | `DUPLICATE_ENTRY` |
| 9 | the rest is exactly one signature block (§2.2) | `BAD_SIG_BLOCK` |

Every refusal makes the whole advisory invalid; nothing of it is shown or
applied. `negative/rad1_decode_rules_001.json` has a case for each.

## 6. Verification

### 6.1 Order

1. Decode (§5).
2. The advisory names the current key set (`key_set_digest`), and its
   signature block passes §2.3 against it.
3. Succession (§7) against the newest advisory known.
4. The log snapshot it came with: it decodes and checks against the current
   key set (RTL1 §6.1; a refusal makes the advisory forged), it lists the
   advisory (`SEC_UPDATE_UNLOGGED` otherwise), and it is consistent with the
   stored log (RTL1 §6.3; a split view freezes, `SEC_LOG_SPLIT_VIEW`).
5. Stored, with the log when that is longer, and rotated to the key set a
   `KEY_SET` entry names (§6.2). Applying the entries (§8) is a later step.

A refusal at 1 or 2 is a forged advisory (`SEC_ADVISORY_FORGED`): ignored,
kept in quarantine for 7 days, and the friend who passed it on is told that
it failed its check, without blame. One exception: an advisory (or a log
snapshot) whose `key_set_digest` names a key set this node never trusted
(not the current set nor one rotated out before it: most often a rotation
this node has not taken yet, §6.2) cannot be checked yet. It is ignored
with no event, nothing quarantined and nobody blamed (`UNKNOWN_KEY_SET`);
one naming a set rotated out since is still forged. Without a release key
set every advisory is refused before step 1 (`NO_RELEASE_KEYS`), with no
event.

While the update state is frozen (§7), steps 1 and 2 still run (a forged
advisory is still noted) and nothing new is stored. No advisory lifts a
freeze, a rotation included: the key set that froze signed two histories,
so nothing it signs can be trusted to end it. Only a release installed by
hand (a higher build serial than the one that froze) clears it; with two
keys exposed that release carries a new key set people check by hand
(§6.2).

### 6.2 Key rotation

A `KEY_SET` entry in an advisory signed by the current set names the next
set. Once that advisory is applied, artifacts are checked against the next
set; an artifact naming the old set is `WRONG_KEY_SET`
(`update/rad1_key_rotation_001.json`: advisory #3 rotates key `0x11` out,
advisory #4 is signed by the new set). Losing one key: rotate with the other
two. Losing or exposing two: there is no in-band recovery; a new key set
ships in a release that people check by hand (design D §9).

A node keeps the last 4 rotations it applied, each with the log snapshot it
was accepted with (both under the set it rotated away from), and passes
them on: a friend that missed a rotation finds everything newer under a key
set it never trusted (`UNKNOWN_KEY_SET`, §6.1) and asks for the rotation
away from its own set (RUP1 `GET_ROTATION`,
[`RAVEN_UPDATE_EXCHANGE_V1.md`](RAVEN_UPDATE_EXCHANGE_V1.md) §7.1), then for
the newest advisory again. "Cannot be checked yet" lasts only while such a
catch-up is possible: when the friend that passed it on gives no rotation,
or the day's catch-ups with it are spent and it brought none, the exchange
counts the advisory as forged (`SEC_ADVISORY_FORGED`, §7.1 there), since a
node cannot tell it from one under a key set the friend made up.

## 7. Succession

How a verified advisory relates to the stored one (`stored serial`,
`stored digest`):

| Case | Result | What happens |
|---|---|---|
| nothing stored | `FIRST` | applied |
| same serial, same digest | `SAME` | nothing |
| serial = stored + 1 and `prev_digest` = stored digest | `NEXT` | applied |
| serial > stored + 1 | `GAP` | applied (the chain across the gap is not checked) |
| serial < stored | `ROLLBACK` | ignored, the stored one kept; offered back to that friend (`SEC_ADVISORY_ROLLBACK`) |
| same serial, other digest | `EQUIVOCATION` | both kept as evidence; update state frozen: no new advisory applied, no install (`SEC_ADVISORY_EQUIVOCATION`) |
| serial = stored + 1 and `prev_digest` names another advisory | `EQUIVOCATION` | as above |

A build's compiled floor (the newest advisory known when it was built,
`(serial, digest)`) is the lowest stored serial it accepts: while nothing
newer is stored it is the newest advisory known, so an older one is
`ROLLBACK`, the floor's own advisory is stored when it arrives (`SAME`, its
bytes were not stored), and another with its serial is `EQUIVOCATION`. On
equal serials the stored advisory counts.

The digest covers the signature block, and anyone can drop a signature from
a block above the threshold (§2.3 accepts more), which makes another digest
without any key. Equivocation therefore needs two signed bodies: an
advisory with the stored one's serial and the same bytes before the
signature block is the same advisory, never `EQUIVOCATION` (nothing is
stored; a copy whose log does not list it is `SEC_UPDATE_UNLOGGED`). For
the compiled floor, whose bytes a node does not hold, another digest under
its serial is `EQUIVOCATION` only when the log snapshot it came with checks
and lists it (otherwise `SEC_UPDATE_UNLOGGED`). The release tool combines
exactly `threshold` signatures, so every copy of what it signs has the same
bytes.

## 8. Applying (summary)

Behind the gate (P6.45, raven-core `suite_policy.rs`): `SUITE_STATUS`
BROKEN refuses exactly the registered suite at its consult point (§4.1): a
link suite before every link handshake, either way (local code
`SUITE_BROKEN`); `pairinit/1/1` when a PairInit is made or taken, on a link
or in a letter, sessions already open going on (`SUITE_BROKEN`); the
session profile at every seal and accept, the sessions held until an
update (`SUITE_HELD`; a build with a next profile re-seals under it
instead); a wire module's id turns its feature off. DEPRECATED and INFO
only show. A `FEATURE_HOLD` BROKEN closes a feature whose gate is open, and
every feature that sits on it, and can never make a closed gate live (it
is consulted inside the feature's live check after its own gate). Two
link features a contact's capability floor tracks are closed in part,
since nodes apply a notice at different times
([`docs/design/2026-10-suite-retirement.md`](../docs/design/2026-10-suite-retirement.md)
§6.4): a hold on the knock (`feature/link-knock`, or a BROKEN `rlk1/1`)
stops this node's knocks while its listener still proves itself to a
contact that knocks (a contact without the notice would otherwise stop at
it as at an impostor); and while this node holds link padding or the knock,
its capability floors leave that feature out (no downgrade, nothing
raised). The update exchange (RUP1) is closed in part as well: a hold on
`feature/release-bundle` stops bundles between friends but not notices
(advisories and logs), since a node without an uplink gets the notice that
lifts the hold only that way; a hold on `feature/mesh-update`, or a BROKEN
`rup1/1`, stops the whole exchange, notices included, so only a new build
or a file import lifts it (the release tool asks for such an entry to be
marked as meant).
`RELEASE_FLOOR` warns when this build's serial is lower ("This Raven
version has a known security problem. Raven keeps working."); `NOTICE` text
is shown sanitized (escape sequences and bidirectional controls removed);
`KEY_SET` rotates (§6.2). Each advisory stored raises
`SEC_ADVISORY_APPLIED` (an informational alert). The policy is read from
the stored advisory, kept in memory and read again when the state file
changes; a freeze keeps it. There is no local override of BROKEN
(OD6b-21): an override would let an attacker talk people into a broken
method.

## 9. Old builds and later versions

- A build without advisory support never reads RAD1; nothing on the wire
  changes for it (advisories travel in RUP1, which old peers never
  negotiate, or as files).
- Unknown kinds, ids and text ids keep an advisory valid and are never
  enforced (§3.2, §4.3).
- A change to the layout or to an existing rule is version `0x02` with a
  new spec; builds refuse versions they do not know (`BAD_VERSION`), so an
  advisory meant for older builds too stays version 1.

## 10. Vectors

Written by Rust (`RAVEN_REGEN_SECURITY_VECTORS=1 cargo test -p raven-core
advisory`), checked by the Python reference
(`protocol/reference/raven_protocol/advisory.py`, `tests/test_advisory.py`),
which also builds every signed advisory again byte for byte (Ed25519
signatures are deterministic). Under `shared-vectors/rvn1/update/`:

- `keyset_001.json`: the test key set (§2.4).
- `rad1_two_of_three_001.json`: advisory #1, signed by keys 0 and 2.
- `rad1_three_of_three_001.json`: advisory #2 (after #1), signed by all three
  keys, with every kind, including the unknown kind `0x7F`.
- `rad1_key_rotation_001.json`: advisory #3 naming the next key set, and #4
  signed by it.
- `negative/`: `rad1_one_sig_001` (`BELOW_THRESHOLD`),
  `rad1_dup_key_index_001` (`KEY_INDEX_ORDER`),
  `rad1_bad_sig_among_good_001` (`BAD_SIGNATURE`), `rad1_wrong_keyset_001`
  (`WRONG_KEY_SET`), `rad1_rollback_pair_001` (`ROLLBACK`),
  `rad1_equivocation_pair_001` and `rad1_broken_chain_pair_001`
  (`EQUIVOCATION`), `rad1_decode_rules_001` (every rule of §5),
  `keyset_rules_001` (every rule of §2.1).

## 11. Implementation status

- raven-core `release_keys.rs`: `KeySet` (decode, encode, digest,
  `verify_block`, `verify_sigs`), `SigBlock`, the test keys
  (`release_keys::test_keys`, test and debug builds only).
- raven-core `advisory.rs`: `Advisory` (decode, `signing_input`, `digest`,
  `verify`), `AdvisoryDraft` (encode and sign), `succession`.
- raven-core `suite_registry.rs`: the registry of §4 (`SUITES`, `FEATURES`).
- Fuzz target `rad1_decode` (`node/fuzz`).
- raven-core `update_state.rs` (P6.44): the compiled key set
  (`RELEASE_KEY_SET_V1`, `None` until the key ceremony; a compile-time check
  refuses a set with a test key or a threshold below 2), the debug lab key
  file, the build serial and compiled floor, `accept_advisory` in the order
  of §6.1, `accept_log`, rotation, the freeze and its evidence; the state
  file `updates/state`, sealed at rest.
- raven-core `suite_policy.rs` (P6.45): the policy of the stored
  advisory (§8) and its consult points: every gate's live check
  (`hold_allows`, after its own gate), PairInit made and taken
  (`lan_dispatch`), sealing and accepting on indexed sessions, and
  raven-node's link handshakes (LAN direct, Internet direct, p2p, nearby);
  `raven status`, `raven doctor` and the terminal app's SEC show it. While
  the gate is shut every check allows.
- The RUP1 frames that carry advisories between friends (P6.48,
  [`RAVEN_UPDATE_EXCHANGE_V1.md`](RAVEN_UPDATE_EXCHANGE_V1.md)): an
  advisory of at most 7,476 bytes fits one ADVISORY reply beside any version
  1 log snapshot.
- Not yet: raven-node passing advisories between friends (staging and
  installing bundles and the release tool exist since P6.47 and P6.46). No
  build sends an advisory to anyone, and no release build can accept one
  before the key ceremony.
