# RAVEN Transparency Log V1 (RTL1)

**Version:** 1 (`RTL1`, version byte `1`)
**Status:** Draft; **production disabled**. The log is read only by
features that are gated off: advisories (`ADVISORY_PRODUCTION_ENABLED =
false`) and release bundles (`RELEASE_BUNDLE_PRODUCTION_ENABLED = false`),
`raven-core/src/security_gate.rs`. This revision defines the entries, the
hashing, the signed tree head, the snapshot and the checks; the update state
(`raven-core/src/update_state.rs`, behind the advisory gate) checks and
stores logs and freezes on a split view. It adds no lab switch.
**Audience:** re-implementers; operators of the offline release tool and of
the public log repository.
**Design:** `docs/roadmap/plans/phase6-design.json`, design D §3 and wire
spec W-D2; owner decision OD6b-22 (a public log, tree heads signed 2 of 3 in
the same ceremony as the artifacts, whole snapshots in version 1).

---

## 1. Purpose

Two of the three release keys can sign anything, including a special build
or advisory meant for one group only. The transparency log makes such an
artifact visible: every manifest, advisory and key set the Raven project
signs is an entry in one public, append-only list, and a Raven accepts an
artifact only when a log signed by the release keys lists it.

Version 1 carries **whole snapshots** instead of audit proofs: an artifact
travels with every entry of the log and the signed tree head (STH). A
verifier recomputes the root, checks that the entries it stored and the new
ones are prefixes of each other (in either direction), and keeps the longer
list. Two validly signed lists that are not prefixes of each other are a
**split view**: the signers showed two histories, which is evidence of key
misuse that anyone holding both can show.

The cap of 1,400 entries keeps a snapshot under 58 KB; at the expected
cadence (a few advisories and releases a year, one manifest per platform)
that lasts decades. A version 2 with audit proofs comes before the log
reaches it (§8).

All integers are big-endian. Key sets and signature blocks are those of
[`RAVEN_SECURITY_ADVISORY_V1.md`](RAVEN_SECURITY_ADVISORY_V1.md) §2.

## 2. Entries

```
entry = type u8 || digest[32] || logged_at_ms u64          (41 bytes)
```

| Type | Name | `digest` |
|---:|---|---|
| `0` | (reserved) | refused: `BAD_ENTRY_TYPE` |
| `1` | `MANIFEST` | a release manifest's `manifest_digest` (RRB1, [`RAVEN_RELEASE_BUNDLE_V1.md`](RAVEN_RELEASE_BUNDLE_V1.md) §3.4) |
| `2` | `ADVISORY` | an advisory's `advisory_digest` ([`RAVEN_SECURITY_ADVISORY_V1.md`](RAVEN_SECURITY_ADVISORY_V1.md) §3.4) |
| `3` | `KEY_SET` | a release key set's `key_set_digest` (same document, §2.1) |
| `4`-`255` | (unknown) | kept and hashed like any entry; never matched |

- `logged_at_ms`: when the signers logged the artifact (Unix time,
  milliseconds). Shown, never enforced: a cutoff must not invalidate a log.
- Entries are in log order, oldest first. Nothing else is required of them:
  times need not grow, and an artifact may be logged twice.
- An artifact is **in the log** when an entry has its type and its digest
  (`contains`); the time does not matter.

## 3. Hashing

As RFC 6962 §2.1, over the 41 entry bytes:

```
leaf(entry)    = SHA-256(0x00 || entry)
node(l, r)     = SHA-256(0x01 || l || r)
MTH(D[1])      = leaf(D[0])
MTH(D[n > 1])  = node(MTH(D[0 .. k]), MTH(D[k .. n]))   k = the largest power of two < n
```

(`MTH` of no entries is `SHA-256("")`; a log always has at least one.) The
same hashing over arbitrary leaves gives the RFC 6962 reference roots
(`update/rtl1_mth_001.json` carries both: the roots of the first 1..=17
entries of the test log and the reference roots of 0..=8 leaves).

## 4. Signed tree head (STH)

### 4.1 Layout

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `RTL1` (`52 54 4c 31`) |
| 4 | 1 | version `0x01` |
| 5 | 1 | kind `0x01` (STH) |
| 6 | 2 | reserved, `0` |
| 8 | 8 | `tree_size`, >= 1 |
| 16 | 32 | `root_hash`: `MTH` of the first `tree_size` entries |
| 48 | 8 | `timestamp_ms` (Unix time, milliseconds; shown, never enforced) |
| 56 | 32 | `key_set_digest`: the key set that signs it |
| 88 | ... | signature block (release key sets §2.2) |

- Signing input: `"rvn1/tlog/sth/v1\0" || bytes[0 .. 88]`. The domain
  differs from every other artifact's, so no other signature counts as a
  tree head's (`negative/rtl1_check_rules_001.json`, `advisory_domain`).
- An STH is at most `MAX_STH_LEN = 609` bytes: 88 and a block of 8
  signatures (no key set has more keys, and key indexes never repeat).
- The tree heads are signed 2 of 3 in the same offline ceremony as the
  artifacts they list (OD6b-22); there is no online log key.

### 4.2 Decode rules

A decoder refuses STH bytes on the first rule they break, in this order. A
field that runs past the end of the bytes is `TRUNCATED`; each field is
checked as it is read.

| Order | Rule | Error |
|---:|---|---|
| 1 | at most 609 bytes | `TOO_LONG` |
| 2 | magic `RTL1` | `BAD_MAGIC` |
| 3 | version `0x01` | `BAD_VERSION` |
| 4 | kind `0x01` | `BAD_KIND` |
| 5 | reserved `0` | `BAD_RESERVED` |
| 6 | `tree_size` >= 1 (then the root, the time and the key set digest are read) | `BAD_TREE_SIZE` |
| 7 | the rest is exactly one signature block | `BAD_SIG_BLOCK` |

`tree_size` has no upper bound in the STH itself: a version 1 verifier
checks only tree heads that come in a snapshot (§5), whose entry count is
capped.

## 5. Snapshot

### 5.1 Layout

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `RTL1` |
| 4 | 1 | version `0x01` |
| 5 | 1 | kind `0x02` (snapshot) |
| 6 | 2 | reserved, `0` |
| 8 | 4 | `entry_count`, 1..=1,400; equal to the STH's `tree_size` |
| 12 | 41 * `entry_count` | the entries (§2), oldest first |
| ... | 2 | `sth_len` |
| ... | `sth_len` | the STH (§4) |

Nothing follows the STH. A snapshot is at most `MAX_SNAPSHOT_LEN = 58,023`
bytes (1,400 entries and the longest STH); one of 1,400 entries with a
2-signature STH is 57,633 bytes.

### 5.2 Decode rules

In this order; a field past the end is `TRUNCATED`:

| Order | Rule | Error |
|---:|---|---|
| 1 | at most 58,023 bytes | `TOO_LONG` |
| 2 | magic `RTL1` | `BAD_MAGIC` |
| 3 | version `0x01` | `BAD_VERSION` |
| 4 | kind `0x02` (an STH given as a snapshot fails here) | `BAD_KIND` |
| 5 | reserved `0` | `BAD_RESERVED` |
| 6 | `entry_count` >= 1 | `BAD_TREE_SIZE` |
| 7 | `entry_count` <= 1,400 (checked before any entry is read) | `TOO_MANY_ENTRIES` |
| 8 | each entry, in order: its type is not `0` | `BAD_ENTRY_TYPE` |
| 9 | `sth_len`, then `sth_len` bytes, then nothing | `TRAILING_BYTES` |
| 10 | the STH, by §4.2 (its own errors) | |
| 11 | `entry_count` equals the STH's `tree_size` | `SIZE_MISMATCH` |

Every refusal makes the whole snapshot invalid, and with it the artifact it
came with. `negative/rtl1_decode_rules_001.json` has a case for every rule
of §4.2 and §5.2.

## 6. Checking

### 6.1 A snapshot

Against the current release key set, in this order:

| Order | Rule | Error |
|---:|---|---|
| 1 | the STH names this key set and its signature block passes release key sets §2.3 | that section's errors (`WRONG_KEY_SET`, `KEY_INDEX_ORDER`, `UNKNOWN_KEY_INDEX`, `BELOW_THRESHOLD`, `BAD_SIGNATURE`) |
| 2 | `MTH(entries)` equals the STH's `root_hash` | `BAD_ROOT` |

A refused snapshot is forged: the artifact it came with is refused too, and
nothing of the snapshot is stored (`negative/rtl1_check_rules_001.json`,
`negative/rtl1_bad_root_001.json`: a manifest substituted after signing).

### 6.2 Inclusion

An artifact counts only when the checked snapshot it came with lists it:
an entry with its type and digest (§2). An artifact the log does not list
is refused (`SEC_UPDATE_UNLOGGED`). Artifacts are verified against the
current key set; an older manifest, signed by a key set since rotated out,
is accepted when the current set's log lists its digest (design D §1).

### 6.3 Prefix consistency

How a checked snapshot's entries (`new`) relate to the entries stored from
earlier checked snapshots (`stored`; nothing stored is the empty list):

| Case | Result | What happens |
|---|---|---|
| `stored` is a prefix of the longer `new` | `EXTENDS` | the new entries and STH are stored |
| the same entries | `SAME` | nothing (the newer STH may be kept) |
| `new` is a prefix of the longer `stored` | `OLDER` | the stored log is kept; the sender is behind and can be offered it |
| neither is a prefix of the other | `SPLIT` | split view (`SEC_LOG_SPLIT_VIEW`, an Alert): both STHs kept as evidence; update state frozen (no new advisory applied, no install) |

Entries are compared whole (type, digest and time): a log that differs from
the stored one in any entry before the shorter one ends is a split view,
even when it is longer (`negative/rtl1_split_view_pair_001.json`).
`update/rtl1_consistency_001.json` shows `EXTENDS`, `OLDER` and `SAME`.

Only snapshots that passed §6.1 under the same key set are compared; an
unsigned claim (a friend's log size and root in an RUP1 `HAVE`) only makes
a node fetch that friend's snapshot.

### 6.4 What the log does not do

- A group that never meets anyone with a newer log can be shown a
  consistent fake history until it does; this still needs two stolen keys.
  Friends gossip the log size and root in every update exchange (RUP1), and
  the public repository lets anyone compare.
- Nothing in RTL1 expires by time; a far-future time is only shown.

## 7. Hosting (summary; OD6b-22)

The log is published in a public repository of the `Raven-ASHCO`
organisation (`raven-release-log`: `entries.bin`, the concatenated entries;
`sth/<size>.rtl1`, every STH; every advisory and manifest) and mirrored on
the website; anyone can audit it with `scripts/release/check_log.py` (later
step). Every RAD1 advisory and every RRB1 bundle carries the snapshot of the
log at the time it was signed.

## 8. Limits and later versions

- Version 1 holds at most 1,400 entries. Before the log reaches that, a
  version 2 with RFC 6962 audit and consistency proofs replaces whole
  snapshots; it gets a new version byte and a new spec. Builds refuse
  versions they do not know (`BAD_VERSION`).
- Entry types this version does not know keep a log valid (§2), so a later
  artifact type can be logged without breaking version 1 verifiers.
- A build without RTL1 support never reads it: nothing on the wire or on
  disk changes for old peers (snapshots travel only in advisories, bundles
  and RUP1, which they never negotiate).

## 9. Vectors

Written by Rust (`RAVEN_REGEN_SECURITY_VECTORS=1 cargo test -p raven-core
tlog`), checked by the Python reference
(`protocol/reference/raven_protocol/tlog.py`, `tests/test_tlog.py`), which
computes every root on its own and builds every signed tree head and
snapshot again byte for byte. The test log: entry 0 is the test key set
(`update/keyset_001.json`), then advisories and manifests with synthetic
digests, one a day. Under `shared-vectors/rvn1/update/`:

- `rtl1_mth_001.json`: the 17 test entries, their bytes and leaf hashes, the
  roots of the first 1..=17 (17 entries: `0e80cdff...755a`), and the RFC 6962
  reference roots of 0..=8 leaves.
- `rtl1_sth_001.json`: the STH of the first 5 entries (root
  `2c198d16...54a7`), signed by keys 0 and 1 of the test key set.
- `rtl1_snapshot_5_001.json`: the snapshot of those 5 entries with that STH
  (438 bytes); it checks; which artifacts it contains.
- `rtl1_consistency_001.json`: the 5- and 8-entry snapshots; `EXTENDS`,
  `OLDER`, `SAME`.
- `negative/`: `rtl1_split_view_pair_001` (`SPLIT` both ways),
  `rtl1_bad_root_001` (`BAD_ROOT`), `rtl1_check_rules_001` (every rule of
  §6.1), `rtl1_decode_rules_001` (every rule of §4.2 and §5.2).

## 10. Implementation status

- raven-core `tlog.rs`: `LogEntry`, `leaf_hash`, `node_hash`,
  `root_of_leaf_hashes`, `mth`, `contains`, `consistency`, `Sth` (decode,
  `signing_input`, `verify`), `SthDraft` (encode and sign), `Snapshot`
  (decode, encode, `check`), `Checked`.
- Fuzz target `rtl1_snapshot` (`node/fuzz`).
- raven-core `update_state.rs` (P6.44): the stored log (the longest
  checked snapshot), `accept_log`, every advisory required to come with a
  checked snapshot that lists it, and the freeze on a split view with both
  tree heads kept.
- Not yet: requiring the log of every bundle (staging, P6.47), the exchange
  between friends, the release tool's `log append` and `sth`, the public
  repository and its checker.
