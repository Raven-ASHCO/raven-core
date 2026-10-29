# Raven release key ceremony

How the Raven project makes, keeps and uses its release keys: the three
offline keys that sign security advisories (RAD1), release manifests (RRB1)
and the tree heads of the public release log (RTL1). Design D §1, §3, §9 of
the Phase 6 plan (`docs/roadmap/plans/phase6-design.json`); owner decisions
OD6b-20 (2 of 3 offline keys), OD6b-22 (the public log), OD6b-27
(reproducible builds), OD6b-28 (the tool).

**Status.** The tool, the scripts and this procedure are in the source
(Phase 6 P6.46). The production key set is **not** made yet: the Protocol
owner runs this ceremony, then commits the public key set as a separate,
signed-off commit (section 4). Until then every Raven build has no release
keys (`RELEASE_KEY_SET_V1 = None`) and refuses every update artifact
("This build has no Raven release keys; it can't check updates."), and the
advisory, bundle and mesh-update gates stay off.

## 1. What the keys can and cannot do

- **Can:** sign an advisory (suites marked DEPRECATED or BROKEN, a release
  floor, a feature hold that can only close a feature, a short notice, the
  next key set), sign a release manifest (the files of one release for one
  platform), sign a tree head of the release log.
- **Cannot:** open a gate, change a contact, a key pin, a block list, a route
  or a message, run or download anything, or name a person. Every install
  still needs the person's typed approval, and every artifact must be listed
  in the public log, where anyone can see it.
- **The biggest risk** of any update system: someone holding two keys (by
  theft or coercion) can sign a malicious release. Two of three keys held
  by one person protects against losing a key and against one stolen key,
  not against coercion of that person. The public log, reproducible builds
  checked by others, and the person's approval are the mitigations;
  independent key holders can be added later by a key rotation.

## 2. What you need

- **An offline machine.** A laptop that is never connected to a network:
  Wi-Fi and Bluetooth off (better: removed), no cable, before, during and
  after. A fresh operating system installed from verified media. It is used
  for nothing else. macOS or Linux (the tool reads passphrases from the
  terminal; Windows is not supported for the ceremony).
- **Three key media**, one per key: removable media of different makes,
  labelled only `release-a`, `release-b`, `release-c`.
- **A transfer medium** for drafts in and signed files out. Never a key
  medium.
- **Paper** for the backups and the ceremony record, and three
  tamper-evident bags.
- **Three places**, far enough apart that one event (fire, theft, a search)
  reaches only one of them. Each place keeps one key medium and one paper
  backup of a *different* key, so one place never holds two keys.
- **The tool,** built from the release commit on the build machine, in its
  own target folder so the feature never touches shipped binaries:

  ```sh
  cd node
  CARGO_TARGET_DIR=target/release-tool \
    cargo build --locked --release -p ash --features release-tool --bin raven-release
  shasum -a 256 target/release-tool/release/raven-release
  ```

  Build it on a second machine too and compare the hash before it goes to
  the offline machine on the transfer medium. A release build of the tool
  refuses the published test keys and the weak test parameters
  (`--test-key`, `--test-kdf` work only in debug builds, for tests).

**Never** put a person's name in a key label, a file name, a commit
message or the log: labels are `release-a`, `release-b`, `release-c` (and
`release-d`... after a rotation). Passphrases are typed at the terminal
only: the tool never reads one from an argument, the environment, a file or
a pipe.

## 3. Making the keys (once)

On the offline machine, for each key, with only that key's medium inserted:

```sh
raven-release keygen --label release-a --out /media/release-a/release-a.rrk
```

- The passphrase: six or more random words (dice), different for each key,
  at least 12 characters (the tool refuses less). Write it down on paper
  that is stored in a different place from the key medium.
- The key file holds the public key and the label in the clear and the
  Ed25519 seed sealed with XChaCha20-Poly1305 under an Argon2id key (256
  MiB, 3 passes) from the passphrase. `keygen` writes `<file>.pub` (the
  public key in hex) next to it, reads the file back and opens it with the
  passphrase before it says it is done.
- **Paper backup** of the sealed key file (useless without the
  passphrase):

  ```sh
  xxd -p /media/release-a/release-a.rrk          # copy these lines onto paper
  shasum -a 256 /media/release-a/release-a.rrk   # and this hash
  ```

  To restore: type the lines into a file, `xxd -r -p typed.txt > release-a.rrk`,
  and check the hash. Restore once now, on the offline machine, to prove
  the paper is right.

Then the key set (public keys only, no passphrase):

```sh
raven-release keyset --threshold 2 --out release-keys.keyset \
  /media/release-a/release-a.rrk.pub /media/release-b/release-b.rrk.pub \
  /media/release-c/release-c.rrk.pub
```

It prints the key set digest and the one line the owner's commit puts in
`node/crates/raven-core/src/update_state.rs`. Write the digest into the
ceremony record. Start the release log folder with the key set as its first
entry:

```sh
mkdir release-log
raven-release log append --log release-log --key-set release-keys.keyset \
  --next-key-set release-keys.keyset
```

## 4. The key set commit

A separate commit, signed off by the Protocol owner, that changes exactly
one line:

```rust
pub const RELEASE_KEY_SET_V1: Option<&[u8]> = Some(&hex_bytes::<99>("0102..."));
```

The build refuses a set that holds a published test key or lets fewer than
two keys sign. Publish the key set digest on the website, in the log
repository's README and in the release notes, so people can compare it by
hand.

## 5. Every release

On the build machine, from a clean checkout of the release commit (the
commit sets `BUILD_SERIAL` and `BUILD_ADVISORY_FLOOR` in
`node/crates/raven-core/src/update_state/release_build.rs`: the release's
serial, and the serial and digest of the newest advisory):

1. Build each platform: `scripts/release/build_reproducible.sh --out out/<target>`
   (toolchain 1.98.0, built at the fixed path `/tmp/raven-reproducible`
   with its own cargo home, paths remapped, SOURCE_DATE_EPOCH from the
   commit).
   Have someone else rebuild it (`scripts/release/reproduce_check.sh`, the
   CI job "reproducible build (advisory)") and compare.
2. Sign the binaries for the platform (notarization, Authenticode) where
   needed, into a separate folder.
3. Draft each manifest: `scripts/release/make_bundle.sh draft --build out/<target>
   --signed <signed folder> --key-set release-keys.keyset --out bundle/<target>`.
   Draft the advisory, if there is one (section 6).
4. Copy the drafts to the transfer medium. Write down each draft's
   *signing hash* (printed by `make_bundle.sh` and `raven-release`).

On the offline machine:

5. **Signing round 1**, one key per run, each key's medium inserted alone:

   ```sh
   raven-release sign --key-set release-keys.keyset --key /media/release-a/release-a.rrk \
     manifest-*.draft advisory-7.draft
   ```

   Read every line it shows (version, target, serial, files and hashes,
   advisory entries) and compare the signing hashes with the ones written
   down, then type the passphrase. Repeat with a second key. Each run writes
   `<draft>.sig-<key index>`.
6. Combine: `raven-release combine --key-set release-keys.keyset --draft <draft>
   --out <signed> <sig files>` (the manifest as
   `bundle/<target>/manifest-<target>.rrb1`, the advisory as
   `advisory-7.rad1`). It checks every signature and takes exactly the
   threshold (two): a third signature would let anyone make another copy
   of the artifact, with another digest, by dropping one.
7. List them in the log: `raven-release log append --log release-log --key-set
   release-keys.keyset advisory-7.rad1 bundle/*/manifest-*.rrb1`.
8. **Signing round 2**: `raven-release sth --log release-log --key-set
   release-keys.keyset` drafts the tree head (`tree-head-<size>.draft`);
   sign it with two keys as in step 5; `raven-release combine --key-set ...
   --draft tree-head-<size>.draft --log release-log <sig files>` keeps it in
   the log as `sth/<size>.rtl1`; `raven-release log snapshot --log
   release-log --key-set ...` writes `snapshot.rtl1`.
9. Copy the log folder and the signed files to the transfer medium. Key
   media back into their bags.

On the build machine:

10. Put each signed manifest back as `bundle/<target>/manifest-<target>.rrb1`
    and pack each platform: `scripts/release/make_bundle.sh pack --out bundle/<target>
    --key-set release-keys.keyset --log release-log [--advisory advisory-7.rad1]`.
    The tool verifies each bundle as a Raven build would before writing it.
11. Check: `raven-release verify --key-set release-keys.keyset <bundle>` and
    `python3 scripts/release/check_log.py release-log --key-set release-keys.keyset`
    (with the Python reference's `cryptography` package installed).
12. Publish: the log folder is the public `raven-release-log` repository of
    the Raven-ASHCO organisation (`entries.bin`, `sth/`, `advisories/`,
    `manifests/`, `keysets/`, `snapshot.rtl1`), mirrored on the website;
    the bundles and their `.sha256` files on the download page. Never
    rewrite the log repository's history: it only grows.

The ceremony record (date, what was signed, the signing hashes, the log
size and root after it) is kept on paper and published with the log.

## 6. Advisories

An advisory is the **whole current list** (cumulative), numbered: a new one
repeats every entry still in force. Describe it in JSON:

```json
{"serial": 7, "issued_at_ms": 1792800000000, "entries": [
  {"kind": "SUITE_STATUS", "target": "pairinit/1/1", "severity": "DEPRECATED"},
  {"kind": "RELEASE_FLOOR", "min_build_serial": 12},
  {"kind": "FEATURE_HOLD", "target": "feature/link-knock", "severity": "BROKEN"},
  {"kind": "NOTICE", "text": "Update Raven when you can."}
]}
```

```sh
raven-release advisory --key-set release-keys.keyset --spec advisory-7.json \
  --previous release-log/advisories/6.rad1 --out advisory-7.draft
```

The tool refuses a suite or feature this build would not enforce (a typo
would otherwise do nothing), a serial that does not follow the previous
advisory, and anything the RAD1 rules refuse. It also refuses an entry that
closes the update exchange between friends (`FEATURE_HOLD`
`feature/mesh-update` BROKEN, or `SUITE_STATUS` `rup1/1` BROKEN) unless the
entry says `"stops_notices": true`: from then on no notice passes between
friends, the one that would lift the hold included, so only a new release or
a file import (`raven update import`) reaches people without an uplink. A
hold on `feature/release-bundle` stops only releases between friends, never
notices. No notice lifts a freeze (section 7): a release does. Advisories
travel on their own too: a person imports `advisories/<n>.rad1` with the log
snapshot, and friends pass them on.

## 7. Rotation and loss

- **Planned rotation** (a new key holder, an old medium): make the new key
  (section 3), build the new key set, and issue an advisory with a
  `KEY_SET` entry (`{"kind": "KEY_SET", "key_set_hex": "<the new set>"}`)
  signed by the current set; list it and the new set in the log
  (`log append ... advisory-8.rad1 --next-key-set new-keys.keyset`). Raven
  accepts artifacts under the new set from then on; the next release also
  compiles it in (section 4).
- **One key lost, stolen or exposed:** rotate at once with the other two to
  a new set (the two that remain and a new third key, or three new keys).
  An exposed key counts as stolen.
- **Two keys lost or exposed:** there is no recovery inside Raven: whoever
  holds two keys can sign anything, including a rotation. Say so publicly
  everywhere the project speaks, make a completely new key set, and ship it
  in a new release whose key set digest people must check by hand (the
  digest compared in person, read out by people who checked it, printed
  where it cannot be changed quietly). Old releases cannot check the new
  set; they keep working, but update artifacts under the old keys must no
  longer be trusted.
- **A passphrase forgotten:** the key is lost (the paper backup is sealed
  with the same passphrase): rotate as for a lost key.

## 8. Dry run

Before the first real ceremony, and after any change to the tool, do a full
dry run (the real-world row R32): the same machine and steps, with keys
made for the dry run (`keygen` into a scratch folder) and a scratch log
folder; `make_bundle.sh draft --dry-run-serial 1` accepts a development
build. Destroy the dry-run keys and folders afterwards. A debug build of
the tool can instead sign with the published test keys (`--test-key 0`):
for tests only, never on the offline machine.

## 9. The files

Integers are big-endian. These files never leave the ceremony; no Raven
peer reads them.

```text
key file (.rrk) = "RVNRKY01" || version 0x01 || kdf 0x01 (Argon2id v0x13)
               || aead 0x01 (XChaCha20-Poly1305) || label_len u8 (1..=32)
               || m_kib u32 || t u32 || p u32 || salt[16] || nonce[24]
               || public_key[32] || label || sealed seed[32 + 16]
               (associated data: every byte before the sealed seed)
signature (.sig-<i>) = "RVNRSG01" || version 0x01 || kind u8 (1 manifest,
               2 advisory, 3 tree head) || key_index u8 || reserved 0
               || SHA-256(signing input)[32] || public_key[32] || signature[64]
draft          = the artifact (RRB1, RAD1, RTL1 tree head) with an empty
                 signature block
```

Drafts and signed artifacts are the formats of
`protocol/RAVEN_RELEASE_BUNDLE_V1.md`, `protocol/RAVEN_SECURITY_ADVISORY_V1.md`
and `protocol/RAVEN_TRANSPARENCY_LOG_V1.md`. The code is
`node/crates/raven-core/src/release_sign.rs` (tested against raven-core's
own verifiers) and `node/crates/ash/src/bin/raven-release.rs`;
`node/scripts/release_tool_feature_audit.sh` checks that no release build
contains the tool.
