# RAVEN Release Bundle V1 (RRB1 manifest, RRBC container)

**Version:** 1 (`RRB1` manifest and `RRBC` container, version byte `1` each)
**Status:** Draft; **production disabled** (`RELEASE_BUNDLE_PRODUCTION_ENABLED =
false`, `raven-core/src/security_gate.rs`). Lab only: debug builds with
`RAVEN_LAB_RELEASE_BUNDLE=1`, `RAVEN_LAB_ADVISORY=1` (the gate it sits on) and
`RAVEN_LAB_TEST_A=1`; release builds ignore the switches. This revision
defines the manifest, the chunk tree, the container and the verification
order; the CLI and the terminal app stage and install a verified bundle
(§8), raven-node never does. Until the owner's key
ceremony puts the public release key set into the source, release builds
have **no** release keys and refuse every bundle (`NO_RELEASE_KEYS`).
**Audience:** re-implementers; operators of the offline release tool.
**Design:** `docs/roadmap/plans/phase6-design.json`, design D §1, §4, §5, §9
and wire spec W-D3; owner decisions OD6b-25 (installing), OD6b-26 (release
downgrades), OD6b-27 (reproducible builds).

---

## 1. Purpose

Raven updates must reach people who have no server to download from: a USB
stick, a website mirror, or a friend who already has the new version (RUP1,
a later draft). Whoever carries it, the receiver must be able to check, on
its own and offline, that a release is exactly what the Raven project signed
and published.

A **release bundle** is one Raven release for one target triple: a signed
**manifest** (RRB1) that lists the release's files with their hashes, and a
**payload**, the files back to back. The **container** (`.rrb` file, RRBC)
packs the manifest, the transparency log snapshot that lists it
([`RAVEN_TRANSPARENCY_LOG_V1.md`](RAVEN_TRANSPARENCY_LOG_V1.md)), the newest
advisory ([`RAVEN_SECURITY_ADVISORY_V1.md`](RAVEN_SECURITY_ADVISORY_V1.md)),
and the payload into one file. Over RUP1 the same pieces travel separately,
the payload in 61,440-byte chunks that are each checked before they are
written.

A bundle counts only when **2 of the 3** release keys signed its manifest
and the public log lists it. A bundle never runs anything: it carries only
Raven's own binaries and documents, under `bin/` and `docs/`; no script, no
installer, no file from it is ever executed before Raven's own swap of its
own verified binaries (design D §5, a later step), and only after a person
typed `install`.

All integers are big-endian. Key sets and signature blocks are those of
[`RAVEN_SECURITY_ADVISORY_V1.md`](RAVEN_SECURITY_ADVISORY_V1.md) §2.

## 2. Limits

| Name | Value | Why |
|---|---:|---|
| `MAX_FILES` | 16 | binaries and documents of one platform |
| `CHUNK_SIZE` | 61,440 | a chunk and its RUP1 frame fit one PAD1 inner frame |
| `MAX_PAYLOAD_LEN` | 67,108,864 (64 MiB) | |
| `MAX_CHUNKS` | 1,093 | 64 MiB in 61,440-byte chunks |
| `MAX_CHUNK_PATH_LEN` | 11 | a tree of 1,093 chunks is 11 levels deep |
| `MAX_MANIFEST_LEN` | 5,198 | every field at its maximum and 8 signatures |
| `MAX_CONTAINER_LEN` | 67,204,873 | the header, three lengths, the longest manifest, snapshot (58,023) and advisory (32,768), and 64 MiB |

## 3. Manifest (RRB1)

### 3.1 Layout

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `RRB1` (`52 52 42 31`) |
| 4 | 1 | version `0x01` |
| 5 | 1 | kind `0x01` (release manifest) |
| 6 | 1 | `file_count`, 1..=16 |
| 7 | 1 | reserved, `0` |
| 8 | 8 | `build_serial`, >= 1 |
| 16 | 8 | `created_at_ms` (Unix time, milliseconds; shown, never enforced) |
| 24 | 32 | `key_set_digest`: the key set that signs it |
| 56 | 1 + n | `version_len` (1..=32) and the release version |
| ... | 1 + n | `target_len` (1..=64) and the target triple |
| ... | 20 | `source_commit`: the git commit (SHA-1 object id) it was built from |
| ... | 1 + n | `toolchain_len` (1..=32) and the Rust toolchain |
| ... | 8 | `min_advisory_serial` |
| ... | 4 | `chunk_size`, exactly 61,440 |
| ... | 8 | `payload_len`, 1..=67,108,864 |
| ... | 32 | `payload_chunk_root` (§5) |
| ... | 32 | `payload_sha256`: SHA-256 of the whole payload |
| ... | ... | `file_count` files (§3.3) |
| ... | 2 + n | `notes_len` (0..=2,048) and the release notes, UTF-8 |
| ... | ... | signature block (release key sets §2.2) |

### 3.2 Release fields

- `build_serial` grows with every release (the release script sets it;
  development builds have 0). It is what verification compares with the
  installed build (§7); the version is only shown.
- `version`: three dot-separated runs of ASCII digits, then nothing or a
  suffix that starts with `-` or `+` and has at least one more byte of
  `[0-9A-Za-z.+-]` (`1.5.0`, `1.5.0-rc.1`, `1.5.0+build.7`).
- `target`: 1..=64 bytes of `[a-z0-9_.-]` with at least two `-`-separated
  segments, none empty (`aarch64-apple-darwin`, `x86_64-pc-windows-msvc`).
  A build installs only bundles for the triple it was compiled for.
- `toolchain`: 1..=32 bytes of `[0-9A-Za-z._+-]` (`1.98.0`).
- `source_commit` and each file's `rebuild_sha256` are the
  reproducible-build hooks (OD6b-27): anyone can rebuild the commit and
  compare (`scripts/release/reproduce_check.sh`, a later step).
- `min_advisory_serial`: the newest advisory serial when the release was
  made (0: none). The release compiles that advisory in as its floor (design
  D §1); a verifier shows it and does not enforce it.
- `notes`: shown only after the bundle verified, sanitized like every
  displayed text.

### 3.3 Files

```
file = path_len u8 (1..=64) || path || mode u8 || offset u64 || size u64
    || sha256[32] || rebuild_sha256[32]
```

- `mode`: `0` = `0644` (a document), `1` = `0755` (a program).
- `sha256`: SHA-256 of the file's bytes in the payload; `rebuild_sha256`:
  of the file before platform signing (the same for unsigned files).
- **Paths.** 1..=64 bytes; 2 or 3 segments separated by `/`; the first
  segment exactly `bin` or `docs`; every segment non-empty, only
  `[A-Za-z0-9._-]`, not ending in `.` (so never `.` or `..`, and never a name
  Windows shortens), and not a Windows device name (the part before the
  first `.` is not `CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9` or
  `LPT0`-`LPT9`, in any case). No absolute path, no `\`, no drive, no stream
  (`:`): a path joined under any directory stays inside it
  (`negative/rrb1_path_traversal_001.json`).
- **Collisions.** No two paths may be equal ignoring ASCII case (they would
  be one file on macOS and Windows), and no path may be a directory of
  another (`bin/raven` and `bin/raven/x`, again ignoring case):
  `DUPLICATE_PATH`.
- **Tiling.** The files are the payload in order: the first starts at 0,
  each next one where the previous one ends (`offset` smaller: `OVERLAP`;
  larger: `GAP`), none runs past `payload_len`, and the last one ends exactly
  at it (`BAD_COVERAGE`). A file may be empty
  (`negative/rrb1_overlap_001.json`).

### 3.4 Signing input and digest

- Signing input: `"rvn1/release-manifest/v1\0" || bytes[0 .. start of the
  signature block]`. The domain differs from every other artifact's, so no
  advisory or tree head signature counts as a manifest's.
- `manifest_digest = SHA-256("rvn1/release-manifest/digest/v1\0" || all
  manifest bytes)`, signature block included: the log entry (type `1`) and
  RUP1 name the manifest by it. A manifest signed again by other keys is
  another manifest and must be logged again.

## 4. Decode rules

A decoder refuses manifest bytes on the first rule they break, in this
order. A field that runs past the end of the bytes is `TRUNCATED`; each
field is checked as it is read, a length before the bytes it counts.

| Order | Rule | Error |
|---:|---|---|
| 1 | at most 5,198 bytes | `TOO_LONG` |
| 2 | magic `RRB1` | `BAD_MAGIC` |
| 3 | version `0x01` | `BAD_VERSION` |
| 4 | kind `0x01` | `BAD_KIND` |
| 5 | `file_count` 1..=16 | `BAD_FILE_COUNT` |
| 6 | reserved `0` | `BAD_RESERVED` |
| 7 | `build_serial` >= 1 (then `created_at_ms` and `key_set_digest` are read) | `BAD_SERIAL` |
| 8 | `version_len` 1..=32, then the version (§3.2) | `BAD_RELEASE_VERSION` |
| 9 | `target_len` 1..=64, then the target (§3.2; then `source_commit` is read) | `BAD_TARGET` |
| 10 | `toolchain_len` 1..=32, then the toolchain (§3.2; then `min_advisory_serial` is read) | `BAD_TOOLCHAIN` |
| 11 | `chunk_size` is 61,440 | `BAD_CHUNK_SIZE` |
| 12 | `payload_len` 1..=67,108,864 (then both payload hashes are read) | `BAD_PAYLOAD_LEN` |
| 13 | each file, in order, rules 13a-13f | |
| 13a | `path_len` 1..=64, then the path (§3.3) | `BAD_PATH` |
| 13b | the path collides with no earlier one (§3.3) | `DUPLICATE_PATH` |
| 13c | `mode` <= 1 | `BAD_MODE` |
| 13d | `offset` is not before the previous file's end (0 for the first) | `OVERLAP` |
| 13e | `offset` is not after it | `GAP` |
| 13f | `offset + size` <= `payload_len` (then both hashes are read) | `BAD_COVERAGE` |
| 14 | the last file ends at `payload_len` | `BAD_COVERAGE` |
| 15 | `notes_len` <= 2,048, then the notes are UTF-8 | `BAD_NOTES` |
| 16 | the rest is exactly one signature block (release key sets §2.2) | `BAD_SIG_BLOCK` |

Every refusal makes the whole manifest invalid, and the bundle with it.
`negative/rrb1_decode_rules_001.json` has a case for each rule.

## 5. Chunks

The payload is cut into chunks of `chunk_size` bytes, the last one what is
left (`ceil(payload_len / 61,440)` chunks). The chunk tree is RFC 6962 §2.1
over the chunks, exactly like the log's tree over entries:

```
leaf(chunk)  = SHA-256(0x00 || chunk)
node(l, r)   = SHA-256(0x01 || l || r)
MTH          = split at the largest power of two below the size
payload_chunk_root = MTH(chunks)
```

- **Audit path** of chunk `i`: RFC 6962 §2.1.1 `PATH(i, chunks)`, from the
  leaf's sibling up; at most 11 hashes for 1,093 chunks. A friend serving a
  bundle sends each chunk with its path (RUP1).
- **Checking a chunk** (before it is written): its index is below the chunk
  count, its length is the chunk's (61,440, or what is left for the last
  one), its path has at most 11 hashes, and the path proves it under
  `payload_chunk_root` by RFC 9162 §2.1.3.2 (a path one hash too long or too
  short fails).
- `update/rrb1_chunk_tree_001.json`: a 5-chunk payload (every leaf, the root
  `a288c9fb...8db9`, every path) and the 64 MiB payload (1,093 chunks, root
  `6c3fb6a6...ad57`, paths of 11, 8, 5 and 3 hashes). Computing the chunk
  root of 64 MiB takes well under a second in a release build.

## 6. Container (RRBC, `.rrb`)

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic `RRBC` (`52 52 42 43`) |
| 4 | 1 | version `0x01` |
| 5 | 3 | reserved, `0` |
| 8 | 4 | `manifest_len`, 1..=5,198 |
| 12 | `manifest_len` | the manifest (§3) |
| ... | 4 | `snapshot_len`, 1..=58,023 |
| ... | `snapshot_len` | the RTL1 snapshot that lists the manifest |
| ... | 4 | `advisory_len`, 0..=32,768 (0: no advisory) |
| ... | `advisory_len` | a RAD1 advisory |
| ... | `payload_len` | the payload: exactly the manifest's `payload_len` bytes |

Nothing follows the payload. A reader opens a container in this order; each
length is checked against its cap **before** anything is allocated, and a
part is read into exactly its declared length (so a container that lies
about a length costs at most that capped length):

| Order | Rule | Error |
|---:|---|---|
| 1 | magic `RRBC` | `BAD_MAGIC` |
| 2 | version `0x01` | `BAD_VERSION` |
| 3 | reserved `0` | `BAD_RESERVED` |
| 4 | `manifest_len` 1..=5,198 | `BAD_MANIFEST_LEN` |
| 5 | the manifest decodes (§4) | `MANIFEST` (inner: its §4 error) |
| 6 | `snapshot_len` 1..=58,023 | `BAD_SNAPSHOT_LEN` |
| 7 | the snapshot decodes (RTL1 §5.2) | `SNAPSHOT` (inner: its error) |
| 8 | `advisory_len` <= 32,768 | `BAD_ADVISORY_LEN` |
| 9 | when `advisory_len` > 0, the advisory decodes (RAD1 §5) | `ADVISORY` (inner: its error) |
| 10 | then `payload_len` bytes | |
| 11 | then the end of the input | `TRAILING_BYTES` |

An input that ends early anywhere is `TRUNCATED`; a reader that fails is
`IO`. Opening checks structure only; nothing is trusted until §7.
`negative/rrbc_decode_rules_001.json` has a case for each rule.

## 7. Verification

### 7.1 Order

A bundle (from a container, or its pieces from RUP1) is checked against the
**verification context**: the build's release key set, the log entries it
stored from earlier checked snapshots, the installed build serial, the
build's target triple, the stored release floor, and whether the person
asked for a downgrade. In this order; the first failure refuses the bundle:

| Order | Rule | Error |
|---:|---|---|
| 1 | the build has a release key set | `NO_RELEASE_KEYS` |
| 2 | the manifest names the current key set and its block passes release key sets §2.3 (see §7.3 for a manifest of an earlier set) | `MANIFEST_SIG` (inner: `WRONG_KEY_SET`, `KEY_INDEX_ORDER`, `UNKNOWN_KEY_INDEX`, `BELOW_THRESHOLD`, `BAD_SIGNATURE`) |
| 3 | the snapshot checks (RTL1 §6.1: its tree head signed by the current set, the entries hash to its root) | `LOG` (inner: its error) |
| 4 | the log lists the manifest (type `1`, `manifest_digest`) | `UNLOGGED` |
| 5 | the log and the stored log are prefixes of each other (RTL1 §6.3) | `SPLIT_VIEW` |
| 6 | when there is an advisory: it names the current key set and is signed by it (RAD1 §6) | `ADVISORY_SIG` (inner) |
| 7 | when there is an advisory: the log lists it (type `2`); its `RELEASE_FLOOR` raises the stored floor (never lowers it) | `ADVISORY_UNLOGGED` |
| 8 | `target` is the build's target triple | `WRONG_TARGET` |
| 9 | `build_serial` is greater than the installed build's, unless the person asked for a downgrade (`--allow-downgrade` and a typed confirmation, OD6b-26) | `DOWNGRADE` |
| 10 | `build_serial` is not below the release floor, even for an explicit downgrade | `BELOW_FLOOR` |
| 11 | the payload is `payload_len` bytes (pieces from RUP1) | `PAYLOAD_LENGTH` |
| 12 | the payload's chunks hash to `payload_chunk_root` (§5) | `BAD_CHUNK_ROOT` |
| 13 | the payload hashes to `payload_sha256` | `BAD_PAYLOAD_HASH` |
| 14 | each file's bytes hash to its `sha256`, in order | `BAD_FILE_HASH` (with the file's index) |

Then (a later step) the files are staged and checked again, and nothing more
happens until a person types `install` in the CLI or the terminal app.

- Signatures before the log, the log before anything that could be
  expensive or local: a forged bundle costs a few signature checks, never a
  64 MiB hash.
- The same serial as the installed build is not newer (`DOWNGRADE`); an
  explicit downgrade allows it, as it allows an older one.
- A verified bundle reports what vouches for its manifest (`SIGNED`, or
  `LOGGED`, §7.3), how its log relates to the stored one (`EXTENDS`: the
  update state stores it; `SAME`; `OLDER`) and the release floor it was
  checked against.
- `negative/rrbc_verify_rules_001.json` has a case for each rule, the
  accepted variants (no advisory, nothing stored, the same and an older
  log, an explicit downgrade, a rotated key set) and a case where several
  rules break and the first one wins.

### 7.2 What a refusal means

| Error | Security event (`docs/SECURITY_EVENTS.md`) | What happens |
|---|---|---|
| `NO_RELEASE_KEYS` | none | "This build has no Raven release keys; it can't check updates." |
| `MANIFEST_SIG`, `LOG`, `PAYLOAD_LENGTH`, `BAD_CHUNK_ROOT`, `BAD_PAYLOAD_HASH`, `BAD_FILE_HASH` | `SEC_BUNDLE_FORGED` (Suspicious) | refused; the files kept in quarantine, never run or shown |
| `ADVISORY_SIG` | `SEC_ADVISORY_FORGED` | refused |
| `UNLOGGED`, `ADVISORY_UNLOGGED` | `SEC_UPDATE_UNLOGGED` | refused |
| `SPLIT_VIEW` | `SEC_LOG_SPLIT_VIEW` (Alert) | refused; both tree heads kept as evidence; update state frozen |
| `DOWNGRADE`, `BELOW_FLOOR` | `SEC_BUNDLE_DOWNGRADE` (Notice) | refused (a friend carrying an old build) |
| `WRONG_TARGET` | none | not for this computer; it may still be carried for friends |

### 7.3 Key rotation

Artifacts are checked against the **current** key set. A manifest that
names an earlier set (rotated out by a `KEY_SET` advisory since) is accepted
when the log the current set signed lists its digest: the log vouches for
every byte of it, signatures included. Its own signatures are then not
checked against any set, and the verified bundle reports `LOGGED`. A
manifest of another set that the log does not list is refused as
`MANIFEST_SIG` / `WRONG_KEY_SET`. Advisories are not accepted this way: an
advisory in a container must be signed by the current set (RAD1 §6.2).

## 8. Staging and installing (summary)

Behind the gate. Only the user-run CLI (`raven update import`, `install`,
`rollback`) or the terminal app (its Updates overlay) stages and installs;
raven-node never writes a program and, from a later draft (RUP1), only
downloads and verifies into `updates/incoming/`.

- **Staging:** a bundle's log goes to the update state first (a split view
  freezes there), then the bundle is verified in full (§7) and its files
  are extracted by offset into `<data_dir>/updates/staged/<build_serial>/`
  (owner only; each file `<index>-<last path segment>`, never executable;
  with the manifest, the snapshot and the advisory) and hashed again from
  the disk. At most two builds stay staged.
- **Installing:** the newest staged build newer than the installed one is
  verified again in full against the update state as it is then (a freeze
  refuses it), and shown (version, size, signers, its place in the log,
  the notes sanitized); it goes on only after the person types `install`
  (`downgrade` for an explicit downgrade, OD6b-26). Raven swaps only the
  `bin/<name>` programs, and only when the running program's folder is
  writable, holds raven-node and none of the release's programs as a link,
  and no package manager keeps it: each new program is copied beside the old
  one and synced, the node stops, each old program is renamed to
  `<name>.prev`, each new one renamed into place, the node starts and must
  answer `Ping` within 20 s, else the old programs go back and start again.
  Windows renames a running program (allowed) and never replaces or deletes
  one. Otherwise Raven prints the manual steps and changes nothing.
- **Rollback:** `<name>` and `<name>.prev` trade places after a typed
  `rollback`, with a warning when the build it goes back to is below the
  release floor, and the same health check.

Never `sudo`, never a script, never a file from the bundle run before the
swap (OD6b-25).

## 9. Old builds and later versions

- A build without bundle support never reads RRB1 or RRBC: nothing on the
  wire or on disk changes for it (bundles travel as files or in RUP1, which
  old peers never negotiate).
- A change to the layout or to an existing rule is version `0x02` with a new
  spec; builds refuse versions they do not know (`BAD_VERSION`).
- RUP1 ([`RAVEN_UPDATE_EXCHANGE_V1.md`](RAVEN_UPDATE_EXCHANGE_V1.md)) sends
  the manifest with its snapshot in one reply: at most 10 + 2 + 5,198 +
  58,023 = 63,233 bytes, inside PAD1's 65,511-byte inner frame; a chunk with
  an 11-hash path is at most 61,811 bytes.

## 10. Vectors

Written by Rust (`RAVEN_REGEN_SECURITY_VECTORS=1 cargo test -p raven-core
release_bundle`), checked by the Python reference
(`protocol/reference/raven_protocol/release_bundle.py`,
`tests/test_release_bundle.py`), which builds every signed manifest and
container again byte for byte, computes every chunk root and audit path by
the RFC 6962 definitions, and runs every verification case. The test
release: build 5, version `1.5.0` for `aarch64-apple-darwin`, three files
(`bin/raven`, `bin/raven-node`, `docs/README.txt`), signed by keys 0 and 1
of the test key set (`update/keyset_001.json`), with an advisory (serial 1,
`RELEASE_FLOOR` 3, a notice) and a log of the key set, the advisory and the
manifest. Under `shared-vectors/rvn1/update/`:

- `rrb1_manifest_001.json`: the manifest (666 bytes, digest
  `ea58c35c...628f`), its signing input, the payload (2,170 bytes) and its
  chunk root and hash.
- `rrbc_small_001.json`: the container (3,529 bytes) with its advisory and
  log, verified: `OK`, `SIGNED`, `EXTENDS`, release floor 3.
- `rrb1_chunk_tree_001.json`: chunk roots and audit paths (§5).
- `negative/`: `rrb1_path_traversal_001` (`BAD_PATH`, `DUPLICATE_PATH`),
  `rrb1_overlap_001` (`OVERLAP`, `GAP`, `BAD_COVERAGE`),
  `rrb1_decode_rules_001` (every rule of §4), `rrbc_decode_rules_001` (every
  rule of §6), `rrb1_unlogged_001` (`UNLOGGED`), `rrb1_wrong_target_001`
  (`WRONG_TARGET`), `rrbc_chunk_tamper_001` (one payload bit:
  `BAD_CHUNK_ROOT`), `rrbc_verify_rules_001` (every rule of §7).

## 11. Implementation status

- raven-core `release_bundle.rs`: `Manifest` (decode, `signing_input`,
  `digest`, `verify`, `check_chunk`), `ManifestDraft` (encode, sign,
  `fill_payload`), the field rules, `chunk_root`, `ChunkTree`
  (`chunk_path`), `verify_chunk_path`, `Container::open` and `Parts`
  (encode), `verify_bundle` with `VerifyCtx` and `VerifiedBundle`, and each
  refusal's security event (`BundleError::sec_kind`).
- Fuzz targets `rrb1_manifest` (with the path-traversal and overlap
  properties) and `rrbc_container` (`node/fuzz`).
- raven-core `update_state.rs` (P6.44): what a bundle is checked against
  (`UpdateState::verify_ctx`: the current key set, the stored log, the
  installed build serial, this build's target, the stored advisory's
  release floor), `accept_log` for a bundle's log before the bundle (a
  split view freezes there), and `note_bundle_refusal` for a refusal's
  event.
- The offline release tool `raven-release` (`manifest`, `pack`, `verify`)
  and the reproducible-build scripts (P6.46, `docs/RELEASE_KEY_CEREMONY.md`).
- ash `update_install.rs` (P6.47): `raven update status | import | verify |
  install | rollback` and the terminal app's Updates overlay (§8); the
  installed build and what the swap replaced are kept in the update state
  (`InstallRecord`).
- raven-core `update_exchange.rs` (P6.48): the RUP1 frames that carry a
  bundle's manifest and chunks between friends
  ([`RAVEN_UPDATE_EXCHANGE_V1.md`](RAVEN_UPDATE_EXCHANGE_V1.md));
  `Chunk::check` is `Manifest::check_chunk`.
- Not yet: raven-node passing bundles between friends (RUP1).
