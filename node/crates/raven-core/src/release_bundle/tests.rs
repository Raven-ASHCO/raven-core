//! RRB1 release manifests and RRBC containers (RAVEN_RELEASE_BUNDLE_V1)
//! and the vectors in `shared-vectors/rvn1/update` (`rrb1_*`, `rrbc_*`).
//! The vectors are written only under `RAVEN_REGEN_SECURITY_VECTORS=1` (a
//! deliberate wire change) and otherwise compared with the committed files;
//! the Python reference (`protocol/reference/raven_protocol/release_bundle.py`)
//! checks every one, builds every signed manifest and container again byte
//! for byte, computes every chunk root and audit path on its own and runs
//! every verification case.

use std::io::Read;
use std::time::{Duration, Instant};

use super::*;
use crate::advisory::{AdvisoryDraft, Entry, EntryKind, Severity};
use crate::release_keys::test_keys::{key_set, key_set_of, signer};
use crate::tlog::{Sth, SthDraft};
use serde_json::{json, Value};

const REGEN: &str = "RAVEN_REGEN_SECURITY_VECTORS";
/// 2026-10-23T00:00:00Z: the release is made then; log entry `i` is logged
/// `i` days later.
const CREATED_AT_MS: u64 = 1_792_713_600_000;
const DAY_MS: u64 = 86_400_000;
/// The test key set's seed bytes, by key index.
const CURRENT: [u8; 3] = [0x11, 0x22, 0x33];
/// Another key set: rotated out, or simply not this build's.
const OLD: [u8; 3] = [0x44, 0x55, 0x66];
/// The test release's target and another one.
const TARGET: &str = "aarch64-apple-darwin";
const OTHER_TARGET: &str = "x86_64-unknown-linux-gnu";
/// The test release's build serial; the installed build is one older.
const SERIAL: u64 = 5;
const INSTALLED: u64 = 4;
/// The release floor the test advisory names.
const ADVISORY_FLOOR: u64 = 3;
const REBUILD_DOMAIN: &[u8] = b"rvn1/rrb1/test-rebuild\0";
const COMMIT_DOMAIN: &[u8] = b"rvn1/rrb1/test-commit\0";
const NOTES: &str = "Raven 1.5.0 (test vectors only): fixes a test problem.\n";
const README: &[u8] = b"Raven 1.5.0 test release.\nThese bytes exist only in the test vectors.\n";

fn rvn1_dir() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors/rvn1")
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn set_of(seeds: &[u8; 3]) -> KeySet {
    key_set_of(2, seeds)
}

/// The keys at `indexes` of the set with these seed bytes, as signers.
fn ids(seeds: &[u8; 3], indexes: &[u8]) -> Vec<(u8, Identity)> {
    indexes
        .iter()
        .map(|i| (*i, signer(seeds[usize::from(*i)])))
        .collect()
}

fn sign_input(input: &[u8], seeds: &[u8; 3], indexes: &[u8]) -> SigBlock {
    let ids = ids(seeds, indexes);
    let signers: Vec<(u8, &Identity)> = ids.iter().map(|(i, id)| (*i, id)).collect();
    SigBlock::sign(input, &signers)
}

/// `len` bytes, byte `j` = `(j * 31 + salt) mod 251`.
fn pattern(len: usize, salt: usize) -> Vec<u8> {
    (0..len).map(|j| ((j * 31 + salt) % 251) as u8).collect()
}

/// The synthetic chunk-tree payload: byte `j` = `j mod 251`.
fn chunk_payload(len: usize) -> Vec<u8> {
    (0..len).map(|j| (j % 251) as u8).collect()
}

/// The chunk leaf hashes of [`chunk_payload`] of `len` bytes, each distinct
/// chunk hashed once (the payload repeats every 251 bytes, so the 1,093
/// chunks of 64 MiB are 251 distinct ones and the last).
fn chunk_payload_leaves(len: usize) -> Vec<[u8; 32]> {
    let size = CHUNK_SIZE as usize;
    let mut seen = std::collections::HashMap::new();
    (0..len.div_ceil(size))
        .map(|k| {
            let (start, n) = (k * size, size.min(len - k * size));
            *seen.entry((start % 251, n)).or_insert_with(|| {
                leaf_hash(
                    &(start..start + n)
                        .map(|j| (j % 251) as u8)
                        .collect::<Vec<_>>(),
                )
            })
        })
        .collect()
}

/// The three files of the test release: two programs and a document.
fn test_files() -> Vec<(&'static str, FileMode, Vec<u8>, [u8; 32])> {
    let program = |path: &'static str, len: usize, salt: usize| {
        let rebuild = sha(&[REBUILD_DOMAIN, path.as_bytes()]);
        (path, FileMode::Executable, pattern(len, salt), rebuild)
    };
    vec![
        program("bin/raven", 1_200, 3),
        program("bin/raven-node", 900, 7),
        (
            "docs/README.txt",
            FileMode::Regular,
            README.to_vec(),
            sha(&[README]),
        ),
    ]
}

fn pack<'a>(files: &'a [(&'a str, FileMode, Vec<u8>, [u8; 32])]) -> Vec<PackFile<'a>> {
    files
        .iter()
        .map(|(path, mode, bytes, rebuild)| PackFile {
            path,
            mode: *mode,
            bytes: bytes.as_slice(),
            rebuild_sha256: *rebuild,
        })
        .collect()
}

/// The test release's manifest fields, for the set with these seed bytes;
/// returns the draft and the payload.
fn draft_of(seeds: &[u8; 3]) -> (ManifestDraft, Vec<u8>) {
    let mut d = ManifestDraft {
        build_serial: SERIAL,
        created_at_ms: CREATED_AT_MS,
        key_set_digest: set_of(seeds).digest(),
        version: "1.5.0".into(),
        target: TARGET.into(),
        source_commit: sha(&[COMMIT_DOMAIN])[..SOURCE_COMMIT_LEN]
            .try_into()
            .unwrap(),
        toolchain: "1.98.0".into(),
        min_advisory_serial: 1,
        chunk_size: 0,
        payload_len: 0,
        payload_chunk_root: [0; 32],
        payload_sha256: [0; 32],
        files: Vec::new(),
        notes: NOTES.into(),
    };
    let payload = d.fill_payload(&pack(&test_files()));
    (d, payload)
}

fn signed(d: &ManifestDraft, seeds: &[u8; 3], indexes: &[u8]) -> Manifest {
    d.assemble(&sign_input(&d.signing_input().unwrap(), seeds, indexes))
        .unwrap()
}

/// The test release, signed by keys 0 and 1 of the test key set.
fn good_manifest() -> (Manifest, Vec<u8>) {
    let (d, payload) = draft_of(&CURRENT);
    (signed(&d, &CURRENT, &[0, 1]), payload)
}

/// The advisory that travels with the test release: serial 1, a release
/// floor and a notice, signed by keys at `indexes` of the set `seeds`.
fn advisory_of(floor: u64, seeds: &[u8; 3], indexes: &[u8]) -> Advisory {
    let d = AdvisoryDraft {
        serial: 1,
        issued_at_ms: CREATED_AT_MS,
        key_set_digest: set_of(seeds).digest(),
        prev_digest: [0; 32],
        entries: vec![
            Entry {
                kind: EntryKind::ReleaseFloor,
                severity: Severity::Deprecated,
                target: "raven".into(),
                arg: floor.to_be_bytes().to_vec(),
                text_id: 0,
            },
            Entry {
                kind: EntryKind::Notice,
                severity: Severity::Info,
                target: "notice".into(),
                arg: b"Raven 1.5.0 fixes a test problem. Update when a friend offers it.".to_vec(),
                text_id: 0,
            },
        ],
    };
    d.assemble(&sign_input(&d.signing_input().unwrap(), seeds, indexes))
        .unwrap()
}

fn good_advisory() -> Advisory {
    advisory_of(ADVISORY_FLOOR, &CURRENT, &[0, 2])
}

/// A log of these artifacts after the test key set (entry 0); entry `i`
/// logged `i` days after the release.
fn log_of(artifacts: &[(EntryType, [u8; 32])]) -> Vec<LogEntry> {
    std::iter::once((EntryType::KeySet, key_set().digest()))
        .chain(artifacts.iter().copied())
        .enumerate()
        .map(|(i, (kind, digest))| LogEntry {
            kind,
            digest,
            logged_at_ms: CREATED_AT_MS + i as u64 * DAY_MS,
        })
        .collect()
}

/// The tree head of `entries`, signed the day after the last entry by the
/// keys at `indexes` of the set `seeds`.
fn sth_of(entries: &[LogEntry], seeds: &[u8; 3], indexes: &[u8]) -> Sth {
    let d = SthDraft::of_entries(
        entries,
        CREATED_AT_MS + entries.len() as u64 * DAY_MS,
        set_of(seeds).digest(),
    );
    d.assemble(&sign_input(&d.signing_input().unwrap(), seeds, indexes))
        .unwrap()
}

/// A snapshot of `entries`, its head signed by keys 0 and 1 of the test set.
fn snapshot_of(entries: Vec<LogEntry>) -> Snapshot {
    let sth = sth_of(&entries, &CURRENT, &[0, 1]);
    Snapshot::new(entries, sth).unwrap()
}

/// Parts whose log lists the key set, the advisory (when there is one) and
/// the manifest, in that order.
fn parts_of(manifest: Manifest, advisory: Option<Advisory>, payload: Vec<u8>) -> Parts {
    let mut artifacts = Vec::new();
    if let Some(a) = &advisory {
        artifacts.push((EntryType::Advisory, a.digest()));
    }
    artifacts.push((EntryType::Manifest, manifest.digest()));
    Parts {
        manifest,
        snapshot: snapshot_of(log_of(&artifacts)),
        advisory,
        payload,
    }
}

/// The test release with its advisory: `rrbc_small_001`.
fn good_parts() -> Parts {
    let (manifest, payload) = good_manifest();
    parts_of(manifest, Some(good_advisory()), payload)
}

/// What the test release is verified against, owned.
#[derive(Clone)]
struct Ctx {
    key_set: Option<KeySet>,
    stored_log: Vec<LogEntry>,
    installed_serial: u64,
    target: String,
    release_floor: u64,
    allow_downgrade: bool,
}

impl Ctx {
    /// The test key set, the log up to the advisory stored, build 4 for
    /// the release's target, no floor of its own.
    fn good() -> Self {
        Self {
            key_set: Some(key_set()),
            stored_log: log_of(&[(EntryType::Advisory, good_advisory().digest())]),
            installed_serial: INSTALLED,
            target: TARGET.into(),
            release_floor: 0,
            allow_downgrade: false,
        }
    }

    fn view(&self) -> VerifyCtx<'_> {
        VerifyCtx {
            key_set: self.key_set.as_ref(),
            stored_log: &self.stored_log,
            installed_serial: self.installed_serial,
            target: &self.target,
            release_floor: self.release_floor,
            allow_downgrade: self.allow_downgrade,
        }
    }

    fn with(&self, f: impl FnOnce(&mut Self)) -> Self {
        let mut c = self.clone();
        f(&mut c);
        c
    }
}

// ── Constants and well-formed fields (spec §3) ──────────────────────

#[test]
fn constants() {
    assert_eq!(MANIFEST_FIXED_LEN, 165);
    assert_eq!(FILE_FIXED_LEN, 82);
    assert_eq!(MAX_MANIFEST_LEN, 5_198);
    assert_eq!(MAX_CHUNKS, 1_093);
    assert_eq!(MAX_CONTAINER_LEN, 67_204_873);
    assert_eq!(
        MAX_CONTAINER_LEN,
        8 + 12 + 5_198 + 58_023 + 32_768 + 67_108_864
    );
    // 1,093 chunks: 2^10 < 1,093 <= 2^11.
    assert_eq!(
        64 - (MAX_CHUNKS - 1).leading_zeros(),
        MAX_CHUNK_PATH_LEN as u32
    );
    assert!(target_well_formed(THIS_TARGET), "{THIS_TARGET}");
}

#[test]
fn field_rules() {
    for v in [
        "1.5.0",
        "0.0.0",
        "10.20.30",
        "1.5.0-rc.1",
        "1.5.0+build.7",
        "1.5.0-rc.1+b-2",
    ] {
        assert!(version_well_formed(v), "{v}");
    }
    for v in [
        "",
        "1.5",
        "1.5.0.1",
        "v1.5.0",
        "1.5.0-",
        "1.5.0+",
        "1..0",
        "1.5.0 beta",
        "1.5.0-r_c",
        "1.5.x",
        "\u{661}.5.0",
    ] {
        assert!(!version_well_formed(v), "{v}");
    }
    assert!(version_well_formed(&format!("1.5.0-{}", "a".repeat(26))));
    assert!(!version_well_formed(&format!("1.5.0-{}", "a".repeat(27))));
    for t in [
        TARGET,
        OTHER_TARGET,
        "x86_64-pc-windows-msvc",
        "wasm32-wasip1",
        "armv7-unknown-linux-gnueabihf",
    ] {
        assert!(target_well_formed(t), "{t}");
    }
    for t in [
        "",
        "aarch64",
        "Aarch64-apple-darwin",
        "aarch64--darwin",
        "-apple",
        "aarch64-",
        "a b-c",
        "aarch64/apple-darwin",
    ] {
        assert!(!target_well_formed(t), "{t}");
    }
    assert!(target_well_formed(&format!("a-{}", "b".repeat(62))));
    assert!(!target_well_formed(&format!("a-{}", "b".repeat(63))));
    for t in ["1.98.0", "nightly-2026-10-01", "1.98.0+local", "stable_1"] {
        assert!(toolchain_well_formed(t), "{t}");
    }
    for t in ["", "1.98.0 stable", "rustc/1.98", &"1".repeat(33)] {
        assert!(!toolchain_well_formed(t), "{t}");
    }
}

/// Paths the spec allows and refuses (spec §3.3), among them every path of
/// `negative/rrb1_path_traversal_001.json`.
fn bad_paths() -> Vec<(&'static str, Vec<u8>)> {
    let s = |p: &str| p.as_bytes().to_vec();
    vec![
        ("parent_first", s("../bin/raven")),
        ("parent_inside", s("bin/../../etc/passwd")),
        ("parent_last", s("bin/..")),
        ("dot_segment", s("bin/./raven")),
        ("dot_last", s("bin/.")),
        ("absolute", s("/bin/raven")),
        ("empty_segment", s("bin//raven")),
        ("trailing_slash", s("bin/raven/")),
        ("backslash", s("bin\\raven")),
        ("backslash_parent", s("bin/..\\..\\raven")),
        ("drive_letter", s("C:/bin/raven")),
        ("colon_stream", s("bin/raven:evil")),
        ("other_root", s("etc/passwd")),
        ("lib_root", s("lib/raven")),
        ("upper_root", s("BIN/raven")),
        ("root_only", s("bin")),
        ("four_segments", s("bin/a/b/raven")),
        ("trailing_dot", s("bin/raven.")),
        ("space", s("bin/ra ven")),
        ("trailing_space", s("bin/raven ")),
        ("nul_byte", s("bin/raven\0")),
        ("tilde_home", s("bin/~/raven")),
        ("non_ascii", s("bin/r\u{e4}ven")),
        ("invalid_utf8", vec![b'b', b'i', b'n', b'/', 0xff]),
        ("device_con", s("docs/CON")),
        ("device_nul_ext", s("docs/nul.txt")),
        ("device_com1", s("docs/com1.log")),
        ("device_lpt9", s("bin/LPT9")),
        ("device_aux_dir", s("docs/aux/readme")),
        ("too_long", s(&format!("bin/{}", "a".repeat(61)))),
        ("empty", Vec::new()),
    ]
}

#[test]
fn path_rules() {
    for p in [
        "bin/raven",
        "bin/raven-node",
        "bin/raven.exe",
        "docs/README.txt",
        "docs/man/raven.1",
        "bin/.raven",
        "docs/console",
        "docs/com10",
        "docs/lpt",
        &format!("bin/{}", "a".repeat(60)),
    ] {
        assert!(path_well_formed(p), "{p}");
    }
    for (name, p) in bad_paths() {
        let ok = std::str::from_utf8(&p).is_ok_and(path_well_formed);
        assert!(!ok, "{name}");
    }
    assert!(paths_collide("bin/raven", "bin/raven"));
    assert!(paths_collide("bin/Raven", "bin/raven"));
    assert!(paths_collide("bin/raven", "bin/raven/x"));
    assert!(paths_collide("docs/A/x", "docs/a"));
    assert!(!paths_collide("bin/raven", "bin/raven-node"));
    assert!(!paths_collide("bin/raven", "bin/ravenx/y"));
    assert!(!paths_collide("bin/a", "docs/a"));
}

/// Is `p` safe to join under a staging directory, by `std::path` alone (the
/// traversal property): every component a normal name of portable bytes,
/// under `bin` or `docs`, 2 or 3 of them, and the join stays inside.
fn independently_safe(p: &str) -> bool {
    use std::path::{Component, Path};
    let comps: Vec<Component> = Path::new(p).components().collect();
    let base = Path::new("staged");
    (2..=3).contains(&comps.len())
        && comps.iter().all(|c| matches!(c, Component::Normal(_)))
        && matches!(comps[0], Component::Normal(n) if n == "bin" || n == "docs")
        && !p.contains(['\\', ':', '\0', ' '])
        && p.split('/').count() == comps.len()
        && base.join(p).starts_with(base)
        && base.join(p).components().count() == comps.len() + 1
}

/// A path-traversal property over random paths: every path the rule
/// accepts is safe by `std::path`, and many random ones are accepted.
#[test]
fn path_traversal_property() {
    let alphabet: &[&str] = &[
        "a", "B", "0", "-", "_", ".", "..", "/", "\\", ":", " ", "~", "\u{e4}", "con", "x.",
    ];
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut accepted = 0;
    for _ in 0..20_000 {
        let mut p = match next() % 4 {
            0 => String::from("bin/"),
            1 => String::from("docs/"),
            2 => String::from("bin/x/"),
            _ => String::new(),
        };
        for _ in 0..next() % 8 {
            p.push_str(alphabet[(next() % alphabet.len() as u64) as usize]);
        }
        if path_well_formed(&p) {
            accepted += 1;
            assert!(independently_safe(&p), "{p:?}");
        }
    }
    assert!(accepted > 1_000, "only {accepted} accepted");
}

// ── Raw manifests (every field settable) ────────────────────────────

#[derive(Clone)]
struct RawFile {
    path: Vec<u8>,
    mode: u8,
    offset: u64,
    size: u64,
    sha256: [u8; 32],
    rebuild: [u8; 32],
}

/// A manifest's fields, the test release's unless one is changed; signed
/// with a valid 2-of-3 block over whatever the body is.
#[derive(Clone)]
struct RawManifest {
    magic: [u8; 4],
    version_byte: u8,
    kind: u8,
    file_count: Option<u8>,
    reserved: u8,
    build_serial: u64,
    version: Vec<u8>,
    target: Vec<u8>,
    toolchain: Vec<u8>,
    chunk_size: u32,
    payload_len: u64,
    files: Vec<RawFile>,
    notes: Vec<u8>,
    /// The test release's draft: the fields no case changes.
    fixed: ManifestDraft,
}

impl RawManifest {
    fn new() -> Self {
        let (d, _) = draft_of(&CURRENT);
        let fixed = d.clone();
        Self {
            magic: *RRB1_MAGIC,
            version_byte: RRB1_VERSION,
            kind: KIND_MANIFEST,
            file_count: None,
            reserved: 0,
            build_serial: d.build_serial,
            version: d.version.into_bytes(),
            target: d.target.into_bytes(),
            toolchain: d.toolchain.into_bytes(),
            chunk_size: d.chunk_size,
            payload_len: d.payload_len,
            files: d
                .files
                .iter()
                .map(|f| RawFile {
                    path: f.path.clone().into_bytes(),
                    mode: f.mode.byte(),
                    offset: f.offset,
                    size: f.size,
                    sha256: f.sha256,
                    rebuild: f.rebuild_sha256,
                })
                .collect(),
            notes: d.notes.into_bytes(),
            fixed,
        }
    }

    fn body(&self) -> Vec<u8> {
        let d = &self.fixed;
        let mut b = self.magic.to_vec();
        b.extend([
            self.version_byte,
            self.kind,
            self.file_count.unwrap_or(self.files.len() as u8),
            self.reserved,
        ]);
        b.extend(self.build_serial.to_be_bytes());
        b.extend(d.created_at_ms.to_be_bytes());
        b.extend(d.key_set_digest);
        for s in [&self.version, &self.target] {
            b.push(s.len() as u8);
            b.extend_from_slice(s);
        }
        b.extend(d.source_commit);
        b.push(self.toolchain.len() as u8);
        b.extend_from_slice(&self.toolchain);
        b.extend(d.min_advisory_serial.to_be_bytes());
        b.extend(self.chunk_size.to_be_bytes());
        b.extend(self.payload_len.to_be_bytes());
        b.extend(d.payload_chunk_root);
        b.extend(d.payload_sha256);
        for f in &self.files {
            b.push(f.path.len() as u8);
            b.extend_from_slice(&f.path);
            b.push(f.mode);
            b.extend(f.offset.to_be_bytes());
            b.extend(f.size.to_be_bytes());
            b.extend(f.sha256);
            b.extend(f.rebuild);
        }
        b.extend((self.notes.len() as u16).to_be_bytes());
        b.extend_from_slice(&self.notes);
        b
    }

    /// The body and a valid 2-of-3 block over it.
    fn signed(&self) -> Vec<u8> {
        let body = self.body();
        let block = sign_input(&[SIGNING_DOMAIN, &body].concat(), &CURRENT, &[0, 1]);
        [body, block.encode()].concat()
    }

    /// The body and an empty signature block: decodes like
    /// [`RawManifest::signed`] (decoding never checks signatures), cheaply.
    fn unsigned(&self) -> Vec<u8> {
        [self.body(), vec![0]].concat()
    }

    fn with(&self, f: impl FnOnce(&mut Self)) -> Vec<u8> {
        let mut m = self.clone();
        f(&mut m);
        m.signed()
    }
}

#[test]
fn raw_manifest_is_the_test_release() {
    let (m, _) = good_manifest();
    assert_eq!(RawManifest::new().signed(), m.bytes());
}

#[test]
fn manifest_round_trip_and_verify() {
    let (m, payload) = good_manifest();
    let again = Manifest::decode(m.bytes()).unwrap();
    assert_eq!(again, m);
    assert_eq!(m.draft().assemble(m.sigs()).unwrap().bytes(), m.bytes());
    assert_eq!(
        m.signing_input(),
        [SIGNING_DOMAIN, &m.bytes()[..m.signed_len()]].concat()
    );
    assert_eq!(m.digest(), sha(&[DIGEST_DOMAIN, m.bytes()]));
    assert_eq!(m.verify(&key_set()), Ok(()));
    assert_eq!(m.verify(&set_of(&OLD)), Err(SigError::WrongKeySet));
    assert_eq!(m.payload_len, payload.len() as u64);
    assert_eq!(m.files.len(), 3);
    for (f, (path, mode, bytes, rebuild)) in m.files.iter().zip(test_files()) {
        assert_eq!(
            (f.path.as_str(), f.mode, f.rebuild_sha256),
            (path, mode, rebuild)
        );
        assert_eq!(&payload[f.range()], &bytes[..]);
        assert_eq!(f.sha256, sha(&[&bytes]));
    }
    assert_eq!(FileMode::Executable.unix_mode(), 0o755);
    assert_eq!(FileMode::Regular.unix_mode(), 0o644);
}

/// A manifest with every field at its maximum and 8 signatures is exactly
/// `MAX_MANIFEST_LEN` bytes and decodes; one byte more is `TOO_LONG`.
#[test]
fn the_longest_manifest() {
    let eight: Vec<u8> = (0x11..=0x18).collect();
    let set = key_set_of(8, &eight);
    let files: Vec<(String, Vec<u8>)> = (0..MAX_FILES)
        .map(|i| (format!("docs/{}{i:02}", "n".repeat(57)), vec![i as u8; 3]))
        .collect();
    let packs: Vec<PackFile> = files
        .iter()
        .map(|(p, b)| PackFile {
            path: p,
            mode: FileMode::Regular,
            bytes: b,
            rebuild_sha256: [7; 32],
        })
        .collect();
    let mut d = draft_of(&CURRENT).0;
    d.key_set_digest = set.digest();
    d.version = format!("1.5.0-{}", "r".repeat(26));
    d.target = format!("a-{}", "b".repeat(62));
    d.toolchain = "t".repeat(32);
    d.notes = "\u{1F426}".repeat(512);
    d.fill_payload(&packs);
    let input = d.signing_input().unwrap();
    let signers: Vec<Identity> = eight.iter().map(|b| signer(*b)).collect();
    let pairs: Vec<(u8, &Identity)> = signers
        .iter()
        .enumerate()
        .map(|(i, s)| (i as u8, s))
        .collect();
    let m = d.sign(&pairs).unwrap();
    assert_eq!(m.bytes().len(), MAX_MANIFEST_LEN);
    assert_eq!(m.verify(&set), Ok(()));
    let mut over = m.bytes().to_vec();
    over.push(0);
    assert_eq!(Manifest::decode(&over), Err(Rrb1Error::TooLong));
    assert_eq!(SigBlock::sign(&input, &pairs).encode().len(), 1 + 8 * 65);
}

/// Every refusal of spec §4, each the first rule its bytes break.
fn decode_cases() -> Vec<(&'static str, Vec<u8>, Rrb1Error)> {
    use Rrb1Error::*;
    let raw = RawManifest::new();
    let ok = raw.signed();
    let file = |i: usize, f: &dyn Fn(&mut RawFile)| raw.with(|m| f(&mut m.files[i]));
    let mut padded = ok.clone();
    padded.resize(MAX_MANIFEST_LEN + 1, 0);
    let body = raw.body();
    let one_sig = sign_input(&[SIGNING_DOMAIN, &body].concat(), &CURRENT, &[0]).encode();
    vec![
        ("too_long", padded, TooLong),
        ("truncated_header", ok[..6].to_vec(), Truncated),
        ("truncated_in_files", ok[..300].to_vec(), Truncated),
        (
            "truncated_in_notes",
            body[..body.len() - 1].to_vec(),
            Truncated,
        ),
        ("bad_magic", raw.with(|m| m.magic = *b"RRB2"), BadMagic),
        (
            "container_magic",
            raw.with(|m| m.magic = *b"RRBC"),
            BadMagic,
        ),
        ("bad_version", raw.with(|m| m.version_byte = 2), BadVersion),
        ("bad_kind", raw.with(|m| m.kind = 2), BadKind),
        (
            "no_files",
            raw.with(|m| m.file_count = Some(0)),
            BadFileCount,
        ),
        (
            "seventeen_files",
            raw.with(|m| m.file_count = Some(17)),
            BadFileCount,
        ),
        ("bad_reserved", raw.with(|m| m.reserved = 1), BadReserved),
        ("serial_zero", raw.with(|m| m.build_serial = 0), BadSerial),
        (
            "version_empty",
            raw.with(|m| m.version.clear()),
            BadReleaseVersion,
        ),
        (
            "version_33_bytes",
            raw.with(|m| m.version = format!("1.5.0-{}", "a".repeat(27)).into_bytes()),
            BadReleaseVersion,
        ),
        (
            "version_two_parts",
            raw.with(|m| m.version = b"1.5".to_vec()),
            BadReleaseVersion,
        ),
        (
            "version_prefix",
            raw.with(|m| m.version = b"v1.5.0".to_vec()),
            BadReleaseVersion,
        ),
        (
            "version_space",
            raw.with(|m| m.version = b"1.5.0 beta".to_vec()),
            BadReleaseVersion,
        ),
        ("target_empty", raw.with(|m| m.target.clear()), BadTarget),
        (
            "target_one_segment",
            raw.with(|m| m.target = b"aarch64".to_vec()),
            BadTarget,
        ),
        (
            "target_upper_case",
            raw.with(|m| m.target = b"Aarch64-apple-darwin".to_vec()),
            BadTarget,
        ),
        (
            "target_empty_segment",
            raw.with(|m| m.target = b"aarch64--darwin".to_vec()),
            BadTarget,
        ),
        (
            "target_65_bytes",
            raw.with(|m| m.target = format!("a-{}", "b".repeat(63)).into_bytes()),
            BadTarget,
        ),
        (
            "toolchain_empty",
            raw.with(|m| m.toolchain.clear()),
            BadToolchain,
        ),
        (
            "toolchain_space",
            raw.with(|m| m.toolchain = b"1.98.0 stable".to_vec()),
            BadToolchain,
        ),
        (
            "chunk_size_64k",
            raw.with(|m| m.chunk_size = 65_536),
            BadChunkSize,
        ),
        (
            "payload_empty",
            raw.with(|m| m.payload_len = 0),
            BadPayloadLen,
        ),
        (
            "payload_over_64_mib",
            raw.with(|m| m.payload_len = MAX_PAYLOAD_LEN + 1),
            BadPayloadLen,
        ),
        ("path_empty", file(1, &|f| f.path.clear()), BadPath),
        (
            "path_65_bytes",
            file(1, &|f| {
                f.path = format!("bin/{}", "a".repeat(61)).into_bytes()
            }),
            BadPath,
        ),
        (
            "path_parent",
            file(1, &|f| f.path = b"bin/../raven".to_vec()),
            BadPath,
        ),
        (
            "path_twice",
            file(1, &|f| f.path = b"bin/raven".to_vec()),
            DuplicatePath,
        ),
        ("bad_mode", file(2, &|f| f.mode = 2), BadMode),
        ("overlap", file(1, &|f| f.offset -= 1), Overlap),
        ("gap", file(1, &|f| f.offset += 1), Gap),
        ("first_not_at_zero", file(0, &|f| f.offset = 1), Gap),
        ("past_the_payload", file(2, &|f| f.size += 1), BadCoverage),
        (
            "size_overflow",
            file(0, &|f| f.size = u64::MAX),
            BadCoverage,
        ),
        (
            "short_of_the_payload",
            file(2, &|f| f.size -= 1),
            BadCoverage,
        ),
        (
            "notes_2049_bytes",
            raw.with(|m| m.notes = vec![b'n'; 2_049]),
            BadNotes,
        ),
        (
            "notes_not_utf8",
            raw.with(|m| m.notes = vec![b'n', 0xff]),
            BadNotes,
        ),
        ("no_sig_block", body.clone(), BadSigBlock),
        (
            "sig_count_too_high",
            [&body[..], &[2], &one_sig[1..]].concat(),
            BadSigBlock,
        ),
        (
            "sig_block_extra_byte",
            [&ok[..], &[0]].concat(),
            BadSigBlock,
        ),
    ]
}

#[test]
fn decode_acceptance_table() {
    assert!(Manifest::decode(&RawManifest::new().signed()).is_ok());
    let mut names = Vec::new();
    for (name, bytes, want) in decode_cases() {
        assert_eq!(Manifest::decode(&bytes).err(), Some(want), "{name}");
        names.push(name);
    }
    let mut codes: Vec<&str> = decode_cases().iter().map(|c| c.2.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 21, "every refusal has a case");
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), decode_cases().len());
}

/// The path cases of `negative/rrb1_path_traversal_001.json`: each bad path
/// as file 1 (BAD_PATH), and pairs that collide (DUPLICATE_PATH).
fn path_cases() -> Vec<(String, Vec<u8>, Vec<u8>, Rrb1Error)> {
    let raw = RawManifest::new();
    let mut cases: Vec<(String, Vec<u8>, Vec<u8>, Rrb1Error)> = bad_paths()
        .into_iter()
        .map(|(name, path)| {
            let bytes = raw.with(|m| m.files[1].path = path.clone());
            (name.to_string(), path, bytes, Rrb1Error::BadPath)
        })
        .collect();
    for (name, first, second) in [
        ("same_path", "bin/raven", "bin/raven"),
        ("case_only", "bin/raven", "bin/RAVEN"),
        ("file_then_dir", "bin/raven", "bin/raven/node"),
        ("dir_then_file", "docs/man/raven.1", "docs/MAN"),
    ] {
        let bytes = raw.with(|m| {
            m.files[0].path = first.as_bytes().to_vec();
            m.files[1].path = second.as_bytes().to_vec();
        });
        cases.push((
            name.to_string(),
            second.as_bytes().to_vec(),
            bytes,
            Rrb1Error::DuplicatePath,
        ));
    }
    cases
}

#[test]
fn path_traversal_cases() {
    for (name, _, bytes, want) in path_cases() {
        assert_eq!(Manifest::decode(&bytes).err(), Some(want), "{name}");
    }
}

/// The layouts of `negative/rrb1_overlap_001.json`: `(offset, size)` of the
/// three files and `payload_len`.
/// A layout case: name, `(offset, size)` of the three files, `payload_len`
/// and the refusal.
type OverlapCase = (&'static str, [(u64, u64); 3], u64, Rrb1Error);

fn overlap_cases() -> Vec<OverlapCase> {
    use Rrb1Error::*;
    let raw = RawManifest::new();
    let [a, b, c] = [0, 1, 2].map(|i| raw.files[i].size);
    let n = raw.payload_len;
    vec![
        (
            "overlap_by_one",
            [(0, a), (a - 1, b), (a + b, c)],
            n,
            Overlap,
        ),
        (
            "second_inside_first",
            [(0, a), (10, 20), (a + b, c)],
            n,
            Overlap,
        ),
        ("same_offset", [(0, a), (0, b), (a + b, c)], n, Overlap),
        ("gap_of_one", [(0, a), (a + 1, b), (a + b, c)], n, Gap),
        ("first_at_one", [(1, a), (a + 1, b), (a + b + 1, c)], n, Gap),
        ("out_of_order", [(a, b), (0, a), (a + b, c)], n, Gap),
        (
            "last_past_payload",
            [(0, a), (a, b), (a + b, c + 1)],
            n,
            BadCoverage,
        ),
        (
            "size_wraps",
            [(0, a), (a, u64::MAX - a + 1), (a + b, c)],
            n,
            BadCoverage,
        ),
        (
            "short_coverage",
            [(0, a), (a, b), (a + b, c - 1)],
            n,
            BadCoverage,
        ),
        (
            "payload_longer",
            [(0, a), (a, b), (a + b, c)],
            n + 1,
            BadCoverage,
        ),
    ]
}

fn with_layout(layout: &[(u64, u64)], payload_len: u64) -> Vec<u8> {
    RawManifest::new().with(|m| set_layout(m, layout, payload_len))
}

fn set_layout(m: &mut RawManifest, layout: &[(u64, u64)], payload_len: u64) {
    m.payload_len = payload_len;
    for (f, (offset, size)) in m.files.iter_mut().zip(layout) {
        f.offset = *offset;
        f.size = *size;
    }
}

/// [`with_layout`] with an empty signature block (for the property).
fn unsigned(base: &RawManifest, layout: &[(u64, u64)], payload_len: u64) -> Vec<u8> {
    let mut m = base.clone();
    set_layout(&mut m, layout, payload_len);
    m.unsigned()
}

#[test]
fn overlap_cases_refused() {
    for (name, layout, payload_len, want) in overlap_cases() {
        assert_eq!(
            Manifest::decode(&with_layout(&layout, payload_len)).err(),
            Some(want),
            "{name}"
        );
    }
}

/// An overlap and coverage property over random layouts: a manifest is
/// accepted exactly when its files tile the payload in order, and then
/// every payload byte belongs to exactly one file.
#[test]
fn overlap_property() {
    let base = RawManifest::new();
    let mut rng = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut accepted = 0;
    for _ in 0..3_000 {
        let payload_len = 1 + next() % 24;
        let layout: Vec<(u64, u64)> = (0..3).map(|_| (next() % 26, next() % 12)).collect();
        let tiles = layout[0].0 == 0
            && layout.windows(2).all(|w| w[0].0 + w[0].1 == w[1].0)
            && layout[2].0 + layout[2].1 == payload_len;
        let decoded = Manifest::decode(&unsigned(&base, &layout, payload_len));
        assert_eq!(decoded.is_ok(), tiles, "{layout:?} {payload_len}");
        if let Ok(m) = decoded {
            accepted += 1;
            let mut owners = vec![0u8; payload_len as usize];
            for f in &m.files {
                for o in &mut owners[f.range()] {
                    *o += 1;
                }
            }
            assert!(owners.iter().all(|o| *o == 1), "{layout:?}");
        }
    }
    // Tiling layouts are rare at random: build some on purpose too.
    for _ in 0..300 {
        let sizes: Vec<u64> = (0..3).map(|_| next() % 9).collect();
        let total: u64 = sizes.iter().sum();
        if total == 0 {
            continue;
        }
        let layout = [
            (0, sizes[0]),
            (sizes[0], sizes[1]),
            (sizes[0] + sizes[1], sizes[2]),
        ];
        assert!(
            Manifest::decode(&unsigned(&base, &layout, total)).is_ok(),
            "{layout:?}"
        );
        accepted += 1;
    }
    assert!(accepted > 100);
}

// ── Chunks (spec §5) ────────────────────────────────────────────────

/// RFC 6962 §2.1.1 `PATH(m, D[n])`, by the definition.
fn rfc_path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = 1 << (n - 1).ilog2();
    if m < k {
        let mut p = rfc_path(m, &leaves[..k]);
        p.push(root_of_leaf_hashes(&leaves[k..]));
        p
    } else {
        let mut p = rfc_path(m - k, &leaves[k..]);
        p.push(root_of_leaf_hashes(&leaves[..k]));
        p
    }
}

#[test]
fn chunk_tree_is_rfc6962() {
    for n in (0..=70).chain([127, 128, 129, 255, 256, 257]) {
        let leaves: Vec<[u8; 32]> = (0..n as u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        let tree = ChunkTree::of_leaf_hashes(leaves.clone());
        assert_eq!(tree.len(), n);
        assert_eq!(tree.root(), root_of_leaf_hashes(&leaves), "{n}");
        assert_eq!(tree.chunk_path(n), None);
        // Every chunk of the small trees; the ends and the middle of the
        // larger ones.
        let ms: Vec<usize> = match n {
            0..=70 => (0..n).collect(),
            _ => vec![0, 1, n / 2, n - 2, n - 1],
        };
        for m in ms {
            let path = tree.chunk_path(m).unwrap();
            assert_eq!(path, rfc_path(m, &leaves), "{n} {m}");
            let (count, index) = (n as u64, m as u64);
            assert!(verify_chunk_path(
                &tree.root(),
                count,
                index,
                &leaves[m],
                &path
            ));
            if n > 1 {
                // Another leaf, another index, another size, a changed,
                // shortened or lengthened path: refused.
                assert!(!verify_chunk_path(
                    &tree.root(),
                    count,
                    index,
                    &leaves[(m + 1) % n],
                    &path
                ));
                assert!(!verify_chunk_path(
                    &tree.root(),
                    count,
                    (index + 1) % count,
                    &leaves[m],
                    &path
                ));
                let mut bad = path.clone();
                bad[0][0] ^= 1;
                assert!(!verify_chunk_path(
                    &tree.root(),
                    count,
                    index,
                    &leaves[m],
                    &bad
                ));
                assert!(!verify_chunk_path(
                    &tree.root(),
                    count,
                    index,
                    &leaves[m],
                    &path[..path.len() - 1]
                ));
            }
            let longer = [&path[..], &[[0u8; 32]][..]].concat();
            assert!(!verify_chunk_path(
                &tree.root(),
                count,
                index,
                &leaves[m],
                &longer
            ));
            assert!(!verify_chunk_path(
                &tree.root(),
                count,
                count,
                &leaves[m],
                &path
            ));
        }
    }
    let empty = ChunkTree::new(&[], CHUNK_SIZE);
    assert!(empty.is_empty());
    assert_eq!(empty.root(), sha(&[]));
    assert_eq!(chunk_root(&[], CHUNK_SIZE), sha(&[]));
}

#[test]
fn chunks_of_a_payload() {
    let len = 4 * CHUNK_SIZE as usize + 1_000;
    let payload = chunk_payload(len);
    let tree = ChunkTree::new(&payload, CHUNK_SIZE);
    assert_eq!(tree.len(), 5);
    assert_eq!(chunk_count(len as u64, CHUNK_SIZE), 5);
    assert_eq!(chunk_count(4 * u64::from(CHUNK_SIZE), CHUNK_SIZE), 4);
    assert_eq!(tree.root(), chunk_root(&payload, CHUNK_SIZE));
    let chunks: Vec<&[u8]> = payload.chunks(CHUNK_SIZE as usize).collect();
    assert_eq!(chunks[4].len(), 1_000);
    for (i, c) in chunks.iter().enumerate() {
        assert_eq!(tree.leaf(i), Some(leaf_hash(c)));
    }
    // A manifest for this payload checks each chunk by its path.
    let mut d = draft_of(&CURRENT).0;
    let files = [PackFile {
        path: "bin/raven",
        mode: FileMode::Executable,
        bytes: &payload,
        rebuild_sha256: [0; 32],
    }];
    d.fill_payload(&files);
    let m = signed(&d, &CURRENT, &[0, 1]);
    assert_eq!(m.chunk_count(), 5);
    assert_eq!(m.payload_chunk_root, tree.root());
    for (i, c) in chunks.iter().enumerate() {
        let path = tree.chunk_path(i).unwrap();
        let i = i as u64;
        assert_eq!(m.chunk_len(i), Some(c.len() as u64));
        assert!(m.check_chunk(i, c, &path));
        let mut tampered = c.to_vec();
        tampered[0] ^= 1;
        assert!(!m.check_chunk(i, &tampered, &path));
        assert!(!m.check_chunk(i, &c[..c.len() - 1], &path));
        assert!(!m.check_chunk((i + 1) % 5, c, &path));
    }
    assert_eq!(m.chunk_len(5), None);
    assert!(!m.check_chunk(5, chunks[4], &tree.chunk_path(4).unwrap()));
    // A path longer than any real tree needs is refused before hashing.
    let long = vec![[0u8; 32]; MAX_CHUNK_PATH_LEN + 1];
    assert!(!m.check_chunk(0, chunks[0], &long));
}

/// The chunk root of the largest payload (64 MiB, 1,093 chunks): under a
/// second in a release build (P6.43's performance check; a debug build
/// only checks the result).
#[test]
fn chunk_root_64_mib() {
    let payload = chunk_payload(MAX_PAYLOAD_LEN as usize);
    let start = Instant::now();
    let root = chunk_root(&payload, CHUNK_SIZE);
    let took = start.elapsed();
    let tree = ChunkTree::of_leaf_hashes(chunk_payload_leaves(payload.len()));
    assert_eq!(tree.len() as u64, MAX_CHUNKS);
    assert_eq!(tree.root(), root);
    let longest = (0..tree.len())
        .map(|i| tree.chunk_path(i).unwrap().len())
        .max();
    assert_eq!(longest, Some(MAX_CHUNK_PATH_LEN));
    if !cfg!(debug_assertions) {
        assert!(
            took < Duration::from_secs(1),
            "64 MiB chunk root took {took:?}"
        );
    }
    eprintln!("chunk root of 64 MiB: {took:?}");
}

// ── Containers (spec §6) ────────────────────────────────────────────

/// A reader that hands out at most `step` bytes per read and counts them.
struct Trickle<'a> {
    data: &'a [u8],
    at: usize,
    step: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.step).min(self.data.len() - self.at);
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

#[test]
fn container_round_trip() {
    let parts = good_parts();
    let bytes = parts.encode();
    assert_eq!(Container::encode(&parts), bytes);
    assert_eq!(Container::open(&bytes[..]).as_ref(), Ok(&parts));
    for step in [1, 7, 4_096] {
        let mut r = Trickle {
            data: &bytes,
            at: 0,
            step,
        };
        assert_eq!(Container::open(&mut r).as_ref(), Ok(&parts), "{step}");
        assert_eq!(r.at, bytes.len());
    }
    let none = Parts {
        advisory: None,
        ..good_parts()
    };
    let bytes = none.encode();
    assert_eq!(Container::open(&bytes[..]), Ok(none));
}

fn be32(n: usize) -> [u8; 4] {
    (n as u32).to_be_bytes()
}

/// Every refusal of spec §6, each the first rule its bytes break.
fn container_cases() -> Vec<(&'static str, Vec<u8>, RrbcError)> {
    use RrbcError::*;
    let parts = good_parts();
    let ok = parts.encode();
    let m = parts.manifest.bytes().to_vec();
    let s = parts.snapshot.encode();
    let a = parts.advisory.as_ref().unwrap().bytes().to_vec();
    let head = |reserved: [u8; 4]| [&RRBC_MAGIC[..], &reserved].concat();
    let h = head([1, 0, 0, 0]);
    let with_m = [&h[..], &be32(m.len()), &m].concat();
    let with_s = [&with_m[..], &be32(s.len()), &s].concat();
    let with_a = [&with_s[..], &be32(a.len()), &a].concat();
    let mut bad_m = m.clone();
    bad_m[0] = b'X';
    let sth = parts.snapshot.sth().bytes().to_vec();
    let mut bad_a = a.clone();
    bad_a[0] = b'X';
    vec![
        ("empty", Vec::new(), Truncated),
        ("short_magic", b"RRB".to_vec(), Truncated),
        ("bad_magic", [&b"RRBX"[..], &ok[4..]].concat(), BadMagic),
        (
            "manifest_magic",
            [&b"RRB1"[..], &ok[4..]].concat(),
            BadMagic,
        ),
        (
            "bad_version",
            [&head([2, 0, 0, 0])[..], &ok[8..]].concat(),
            BadVersion,
        ),
        (
            "bad_reserved",
            [&head([1, 0, 1, 0])[..], &ok[8..]].concat(),
            BadReserved,
        ),
        (
            "short_manifest_len",
            h[..].iter().chain(&[0, 0]).copied().collect(),
            Truncated,
        ),
        (
            "manifest_len_zero",
            [&h[..], &be32(0)].concat(),
            BadManifestLen,
        ),
        (
            "manifest_len_over_cap",
            [&h[..], &be32(MAX_MANIFEST_LEN + 1)].concat(),
            BadManifestLen,
        ),
        (
            "truncated_manifest",
            with_m[..with_m.len() - 1].to_vec(),
            Truncated,
        ),
        (
            "manifest_refused",
            [&h[..], &be32(m.len()), &bad_m].concat(),
            Manifest(Rrb1Error::BadMagic),
        ),
        (
            "snapshot_len_zero",
            [&with_m[..], &be32(0)].concat(),
            BadSnapshotLen,
        ),
        (
            "snapshot_len_over_cap",
            [&with_m[..], &be32(MAX_SNAPSHOT_LEN + 1)].concat(),
            BadSnapshotLen,
        ),
        (
            "truncated_snapshot",
            with_s[..with_s.len() - 1].to_vec(),
            Truncated,
        ),
        (
            "sth_as_snapshot",
            [&with_m[..], &be32(sth.len()), &sth].concat(),
            Snapshot(Rtl1Error::BadKind),
        ),
        (
            "advisory_len_over_cap",
            [&with_s[..], &be32(MAX_RAD1_LEN + 1)].concat(),
            BadAdvisoryLen,
        ),
        (
            "truncated_advisory",
            with_a[..with_a.len() - 1].to_vec(),
            Truncated,
        ),
        (
            "advisory_refused",
            [&with_s[..], &be32(a.len()), &bad_a].concat(),
            Advisory(Rad1Error::BadMagic),
        ),
        ("no_payload", with_a.clone(), Truncated),
        ("truncated_payload", ok[..ok.len() - 1].to_vec(), Truncated),
        ("trailing_bytes", [&ok[..], &[0]].concat(), TrailingBytes),
    ]
}

#[test]
fn container_rules() {
    let mut codes = Vec::new();
    for (name, bytes, want) in container_cases() {
        assert_eq!(Container::open(&bytes[..]).err(), Some(want), "{name}");
        codes.push(want.code());
    }
    codes.sort_unstable();
    codes.dedup();
    // Every refusal except IO has a case (IO: `container_io_error`).
    assert_eq!(codes.len(), 11);
}

/// Bounded reads: a refused length stops the read at once, a part is read
/// into exactly its length, and an endless input after a good container
/// is one byte too many.
#[test]
fn container_bounded_reads() {
    let parts = good_parts();
    let ok = parts.encode();
    let over = [&ok[..8], &be32(MAX_MANIFEST_LEN + 1)[..], &[0; 64]].concat();
    let mut r = Trickle {
        data: &over,
        at: 0,
        step: 4_096,
    };
    assert_eq!(
        Container::open(&mut r).err(),
        Some(RrbcError::BadManifestLen)
    );
    assert_eq!(r.at, 12);
    let endless = (&ok[..]).chain(std::io::repeat(0));
    assert_eq!(
        Container::open(endless).err(),
        Some(RrbcError::TrailingBytes)
    );
    // A manifest that declares 64 MiB of payload, but the input ends.
    let mut d = parts.manifest.draft();
    d.payload_len = MAX_PAYLOAD_LEN;
    d.files.last_mut().unwrap().size += MAX_PAYLOAD_LEN - parts.payload.len() as u64;
    let big = signed(&d, &CURRENT, &[0, 1]);
    let short = Parts {
        manifest: big,
        ..good_parts()
    }
    .encode();
    assert_eq!(
        Container::open(&short[..]).err(),
        Some(RrbcError::Truncated)
    );
    assert_eq!(read_part(&mut &[1u8, 2, 3][..], 3).unwrap().capacity(), 3);
}

#[test]
fn container_io_error() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("unplugged"))
        }
    }
    let err = Container::open(Broken).unwrap_err();
    assert_eq!(err, RrbcError::Io(ErrorKind::Other));
    assert_eq!((err.code(), err.inner_code()), ("IO", None));
    let bytes = good_parts().encode();
    let after_header = (&bytes[..20]).chain(Broken);
    assert_eq!(
        Container::open(after_header).err(),
        Some(RrbcError::Io(ErrorKind::Other))
    );
}

// ── Verification (spec §7) ──────────────────────────────────────────

/// The test release with another manifest (signed and listed in its log).
fn parts_with_manifest(d: &ManifestDraft, seeds: &[u8; 3], indexes: &[u8]) -> Parts {
    let (_, payload) = good_manifest();
    parts_of(signed(d, seeds, indexes), Some(good_advisory()), payload)
}

/// The test release with another manifest signature block, listed in its log.
fn parts_with_block(sigs: Vec<(u8, [u8; 64])>) -> Parts {
    let (d, payload) = draft_of(&CURRENT);
    let m = d.assemble(&SigBlock::new(sigs)).unwrap();
    parts_of(m, Some(good_advisory()), payload)
}

/// One verification case: the parts, the context and the result.
type VerifyCase = (&'static str, Parts, Ctx, Result<(), BundleError>);

/// Every rule of spec §7 and the accepted variants.
fn verify_cases() -> Vec<VerifyCase> {
    use BundleError::*;
    use SigError::*;
    let good = good_parts();
    let ctx = Ctx::good();
    let (d, payload) = draft_of(&CURRENT);
    let input = d.signing_input().unwrap();
    let [k0, k1, k2] = crate::release_keys::test_keys::signers();
    let adv_input = [
        crate::advisory::SIGNING_DOMAIN,
        &input[SIGNING_DOMAIN.len()..],
    ]
    .concat();
    let manifest = good.manifest.clone();
    let advisory = good_advisory();
    let snap = |entries: Vec<LogEntry>, sth: Sth| Snapshot::new(entries, sth).unwrap();
    let full_log = good.snapshot.entries().to_vec();
    let with_snapshot = |s: Snapshot| Parts {
        snapshot: s,
        ..good.clone()
    };
    let mut wrong_root = full_log.clone();
    wrong_root[2].digest = [9; 32];
    let mut tampered = payload.clone();
    tampered[1_500] ^= 0x01;
    let mut wrong_sha = d.clone();
    wrong_sha.payload_sha256 = [0xee; 32];
    let mut wrong_file = d.clone();
    wrong_file.files[1].sha256 = [0xee; 32];
    let mut d_old = d.clone();
    d_old.key_set_digest = set_of(&OLD).digest();
    let mut split = full_log[..1].to_vec();
    split.extend(
        log_of(&[(EntryType::Advisory, [7; 32])])
            .into_iter()
            .skip(1),
    );
    let mut longer = full_log.clone();
    longer.extend(
        log_of(&[
            (EntryType::Advisory, [1; 32]),
            (EntryType::Advisory, [2; 32]),
            (EntryType::Advisory, [3; 32]),
        ])
        .into_iter()
        .skip(3),
    );
    let ok = Ok(());
    vec![
        ("ok", good.clone(), ctx.clone(), ok),
        (
            "ok_no_advisory",
            Parts {
                advisory: None,
                ..good.clone()
            },
            ctx.clone(),
            ok,
        ),
        (
            "ok_nothing_stored",
            good.clone(),
            ctx.with(|c| c.stored_log.clear()),
            ok,
        ),
        (
            "ok_same_log",
            good.clone(),
            ctx.with(|c| c.stored_log = full_log.clone()),
            ok,
        ),
        (
            "ok_older_log",
            good.clone(),
            ctx.with(|c| c.stored_log = longer.clone()),
            ok,
        ),
        (
            "ok_explicit_downgrade",
            good.clone(),
            ctx.with(|c| {
                c.installed_serial = 6;
                c.allow_downgrade = true;
            }),
            ok,
        ),
        (
            "ok_rotated_key_set",
            parts_with_manifest(&d_old, &OLD, &[0, 1]),
            ctx.clone(),
            ok,
        ),
        (
            "no_release_keys",
            good.clone(),
            ctx.with(|c| c.key_set = None),
            Err(NoReleaseKeys),
        ),
        (
            "manifest_one_signature",
            parts_with_manifest(&d, &CURRENT, &[2]),
            ctx.clone(),
            Err(ManifestSig(BelowThreshold)),
        ),
        (
            "manifest_key_index_order",
            parts_with_block(vec![(1, k1.sign(&input)), (0, k0.sign(&input))]),
            ctx.clone(),
            Err(ManifestSig(KeyIndexOrder)),
        ),
        (
            "manifest_unknown_key_index",
            parts_with_block(vec![(0, k0.sign(&input)), (3, k2.sign(&input))]),
            ctx.clone(),
            Err(ManifestSig(UnknownKeyIndex)),
        ),
        (
            "manifest_bad_signature_among_good",
            parts_with_block(vec![
                (0, k0.sign(&input)),
                (1, k1.sign(&adv_input)),
                (2, k2.sign(&input)),
            ]),
            ctx.clone(),
            Err(ManifestSig(BadSignature)),
        ),
        (
            "manifest_advisory_domain",
            parts_with_block(vec![(0, k0.sign(&adv_input)), (1, k1.sign(&adv_input))]),
            ctx.clone(),
            Err(ManifestSig(BadSignature)),
        ),
        (
            "manifest_other_key_set_unlogged",
            Parts {
                manifest: signed(&d_old, &OLD, &[0, 1]),
                ..good.clone()
            },
            ctx.clone(),
            Err(ManifestSig(WrongKeySet)),
        ),
        (
            "log_one_signature",
            with_snapshot(snap(full_log.clone(), sth_of(&full_log, &CURRENT, &[1]))),
            ctx.clone(),
            Err(Log(LogCheckError::Sig(BelowThreshold))),
        ),
        (
            "log_other_key_set",
            with_snapshot(snap(full_log.clone(), sth_of(&full_log, &OLD, &[0, 1]))),
            ctx.clone(),
            Err(Log(LogCheckError::Sig(WrongKeySet))),
        ),
        (
            "log_bad_root",
            with_snapshot(snap(
                full_log.clone(),
                sth_of(&wrong_root, &CURRENT, &[0, 1]),
            )),
            ctx.clone(),
            Err(Log(LogCheckError::BadRoot)),
        ),
        (
            "unlogged",
            with_snapshot(snapshot_of(full_log[..2].to_vec())),
            ctx.with(|c| c.stored_log.truncate(1)),
            Err(Unlogged),
        ),
        (
            "split_view",
            good.clone(),
            ctx.with(|c| c.stored_log = split.clone()),
            Err(SplitView),
        ),
        (
            "advisory_one_signature",
            parts_of(
                manifest.clone(),
                Some(advisory_of(ADVISORY_FLOOR, &CURRENT, &[1])),
                payload.clone(),
            ),
            ctx.with(|c| c.stored_log.truncate(1)),
            Err(AdvisorySig(BelowThreshold)),
        ),
        (
            "advisory_other_key_set",
            parts_of(
                manifest.clone(),
                Some(advisory_of(ADVISORY_FLOOR, &OLD, &[0, 1])),
                payload.clone(),
            ),
            ctx.with(|c| c.stored_log.truncate(1)),
            Err(AdvisorySig(WrongKeySet)),
        ),
        (
            "advisory_unlogged",
            Parts {
                advisory: Some(advisory.clone()),
                ..parts_of(manifest.clone(), None, payload.clone())
            },
            ctx.with(|c| c.stored_log.truncate(1)),
            Err(AdvisoryUnlogged),
        ),
        (
            "wrong_target",
            good.clone(),
            ctx.with(|c| c.target = OTHER_TARGET.into()),
            Err(WrongTarget),
        ),
        (
            "downgrade",
            good.clone(),
            ctx.with(|c| c.installed_serial = 6),
            Err(Downgrade),
        ),
        (
            "same_build",
            good.clone(),
            ctx.with(|c| c.installed_serial = SERIAL),
            Err(Downgrade),
        ),
        (
            "below_stored_floor",
            good.clone(),
            ctx.with(|c| c.release_floor = 6),
            Err(BelowFloor),
        ),
        (
            "below_advisory_floor",
            parts_of(
                manifest.clone(),
                Some(advisory_of(6, &CURRENT, &[0, 2])),
                payload.clone(),
            ),
            ctx.with(|c| c.stored_log.truncate(1)),
            Err(BelowFloor),
        ),
        (
            "explicit_downgrade_below_floor",
            good.clone(),
            ctx.with(|c| {
                c.installed_serial = 6;
                c.allow_downgrade = true;
                c.release_floor = 6;
            }),
            Err(BelowFloor),
        ),
        (
            "payload_one_byte_short",
            Parts {
                payload: payload[..payload.len() - 1].to_vec(),
                ..good.clone()
            },
            ctx.clone(),
            Err(PayloadLength),
        ),
        (
            "bad_chunk_root",
            Parts {
                payload: tampered.clone(),
                ..good.clone()
            },
            ctx.clone(),
            Err(BadChunkRoot),
        ),
        (
            "bad_payload_hash",
            parts_with_manifest(&wrong_sha, &CURRENT, &[0, 1]),
            ctx.clone(),
            Err(BadPayloadHash),
        ),
        (
            "bad_file_hash",
            parts_with_manifest(&wrong_file, &CURRENT, &[0, 1]),
            ctx.clone(),
            Err(BadFileHash(1)),
        ),
        (
            "first_rule_wins",
            Parts {
                payload: tampered,
                ..parts_with_manifest(&d, &CURRENT, &[2])
            },
            ctx.with(|c| c.target = OTHER_TARGET.into()),
            Err(ManifestSig(BelowThreshold)),
        ),
    ]
}

#[test]
fn verify_rules() {
    let mut codes = Vec::new();
    for (name, parts, ctx, want) in verify_cases() {
        let got = verify_bundle(&parts, &ctx.view());
        assert_eq!(got.as_ref().map(drop).map_err(|e| *e), want, "{name}");
        // Each case is a well-formed bundle: it travels in a container.
        if parts.payload.len() as u64 == parts.manifest.payload_len {
            assert_eq!(
                Container::open(&parts.encode()[..]).as_ref(),
                Ok(&parts),
                "{name}"
            );
        }
        if let Err(e) = want {
            codes.push(e.code());
        }
    }
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 14, "every refusal has a case");
}

#[test]
fn verified_bundle() {
    let parts = good_parts();
    let ctx = Ctx::good();
    let v = verify_bundle(&parts, &ctx.view()).unwrap();
    assert_eq!(v.manifest(), &parts.manifest);
    assert_eq!(v.advisory(), parts.advisory.as_ref());
    assert_eq!(v.authority(), Authority::Signed);
    assert_eq!(v.consistency(), Consistency::Extends);
    assert_eq!(v.release_floor(), ADVISORY_FLOOR);
    assert_eq!(v.log().entries(), parts.snapshot.entries());
    assert_eq!(v.payload(), &parts.payload[..]);
    let files: Vec<(&str, Vec<u8>)> = v
        .files()
        .map(|(f, b)| (f.path.as_str(), b.to_vec()))
        .collect();
    let want: Vec<(&str, Vec<u8>)> = test_files()
        .into_iter()
        .map(|(p, _, b, _)| (p, b))
        .collect();
    assert_eq!(files, want);
    let none = Parts {
        advisory: None,
        ..good_parts()
    };
    let v = verify_bundle(&none, &ctx.with(|c| c.release_floor = 2).view()).unwrap();
    assert_eq!(v.release_floor(), 2);
    let (_, rotated, ..) = verify_cases()
        .into_iter()
        .find(|c| c.0 == "ok_rotated_key_set")
        .unwrap();
    let v = verify_bundle(&rotated, &ctx.view()).unwrap();
    assert_eq!(v.authority(), Authority::Logged);
}

#[test]
fn security_events() {
    use BundleError::*;
    let sig = SigError::BadSignature;
    for (e, want) in [
        (NoReleaseKeys, None),
        (WrongTarget, None),
        (ManifestSig(sig), Some(SecKind::BundleForged)),
        (Log(LogCheckError::BadRoot), Some(SecKind::BundleForged)),
        (PayloadLength, Some(SecKind::BundleForged)),
        (BadChunkRoot, Some(SecKind::BundleForged)),
        (BadPayloadHash, Some(SecKind::BundleForged)),
        (BadFileHash(0), Some(SecKind::BundleForged)),
        (AdvisorySig(sig), Some(SecKind::AdvisoryForged)),
        (Unlogged, Some(SecKind::UpdateUnlogged)),
        (AdvisoryUnlogged, Some(SecKind::UpdateUnlogged)),
        (SplitView, Some(SecKind::LogSplitView)),
        (Downgrade, Some(SecKind::BundleDowngrade)),
        (BelowFloor, Some(SecKind::BundleDowngrade)),
    ] {
        assert_eq!(e.sec_kind(), want, "{e:?}");
    }
    assert_eq!(ManifestSig(sig).inner_code(), Some("BAD_SIGNATURE"));
    assert_eq!(Log(LogCheckError::BadRoot).inner_code(), Some("BAD_ROOT"));
    assert_eq!(Unlogged.inner_code(), None);
}

/// Any single-bit change of the good container outside the payload makes
/// it fail to open or to verify; in the payload, the chunk root catches it
/// (every 17th byte, every bit position over the run).
#[test]
fn any_single_byte_change_fails() {
    let ctx = Ctx::good();
    let bytes = good_parts().encode();
    let fails = |b: &[u8]| match Container::open(b) {
        Err(_) => true,
        Ok(p) => verify_bundle(&p, &ctx.view()).is_err(),
    };
    assert!(!fails(&bytes));
    let payload_at = bytes.len() - good_parts().payload.len();
    for i in (0..payload_at).chain((payload_at..bytes.len()).step_by(17)) {
        let mut m = bytes.clone();
        m[i] ^= 1 << (i % 8);
        assert!(fails(&m), "byte {i} still verifies");
    }
}

// ── Vectors (spec §9) ───────────────────────────────────────────────

fn vector(name: &str, description: &str, inputs: Value, expected: Value) -> Value {
    json!({
        "name": name,
        "protocol_version": "rvn1",
        "deterministic": true,
        "description": description,
        "inputs": inputs,
        "expected": expected,
    })
}

/// Assert that the committed vector `file` (under shared-vectors/rvn1/update)
/// equals `expected`; write it first under `RAVEN_REGEN_SECURITY_VECTORS=1`.
fn assert_vector(file: &str, expected: &Value) {
    let path = rvn1_dir().join("update").join(file);
    if std::env::var(REGEN).as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(expected).unwrap() + "\n",
        )
        .unwrap();
    }
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
    let stored: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(&stored, expected, "{file}");
}

fn key_set_json(seeds: &[u8; 3]) -> Value {
    let set = set_of(seeds);
    json!({
        "threshold": set.threshold(),
        "seeds_hex": seeds.iter().map(|b| hex::encode([*b; 32])).collect::<Vec<_>>(),
        "public_keys_hex": set.keys().iter().map(hex::encode).collect::<Vec<_>>(),
        "key_set_hex": hex::encode(set.encode()),
        "key_set_digest_hex": hex::encode(set.digest()),
    })
}

fn entries_json(entries: &[LogEntry]) -> Value {
    json!(entries
        .iter()
        .map(|e| json!({
            "type": e.kind.byte(),
            "digest_hex": hex::encode(e.digest),
            "logged_at_ms": e.logged_at_ms,
        }))
        .collect::<Vec<_>>())
}

/// What a signer builds: the manifest's fields, its files and who signs.
fn manifest_inputs(m: &Manifest, payload: &[u8]) -> Value {
    json!({
        "build_serial": m.build_serial,
        "created_at_ms": m.created_at_ms,
        "key_set_digest_hex": hex::encode(m.key_set_digest),
        "version": m.version,
        "target": m.target,
        "source_commit_hex": hex::encode(m.source_commit),
        "toolchain": m.toolchain,
        "min_advisory_serial": m.min_advisory_serial,
        "files": m.files.iter().map(|f| json!({
            "path": f.path,
            "mode": f.mode.byte(),
            "hex": hex::encode(&payload[f.range()]),
            "rebuild_sha256_hex": hex::encode(f.rebuild_sha256),
        })).collect::<Vec<_>>(),
        "notes": m.notes,
        "signers": m.sigs().sigs().iter().map(|(i, _)| *i).collect::<Vec<_>>(),
    })
}

fn manifest_expected(m: &Manifest) -> Value {
    json!({
        "manifest_hex": hex::encode(m.bytes()),
        "signing_input_hex": hex::encode(m.signing_input()),
        "digest_hex": hex::encode(m.digest()),
        "chunk_size": m.chunk_size,
        "payload_len": m.payload_len,
        "payload_chunk_root_hex": hex::encode(m.payload_chunk_root),
        "payload_sha256_hex": hex::encode(m.payload_sha256),
        "files": m.files.iter().map(|f| json!({
            "path": f.path,
            "offset": f.offset,
            "size": f.size,
            "sha256_hex": hex::encode(f.sha256),
        })).collect::<Vec<_>>(),
        "verify": m.verify(&key_set()).err().map_or("OK", SigError::code),
    })
}

fn ctx_json(c: &Ctx) -> Value {
    json!({
        "key_set": c.key_set.as_ref().map(|k| hex::encode(k.encode())),
        "stored_log": entries_json(&c.stored_log),
        "installed_serial": c.installed_serial,
        "target": c.target,
        "release_floor": c.release_floor,
        "allow_downgrade": c.allow_downgrade,
    })
}

fn verify_json(parts: &Parts, c: &Ctx) -> Value {
    match verify_bundle(parts, &c.view()) {
        Ok(v) => json!({
            "result": "OK",
            "authority": v.authority().name(),
            "consistency": v.consistency().name(),
            "release_floor": v.release_floor(),
        }),
        Err(e) => {
            let mut out = json!({ "result": e.code(), "inner": e.inner_code() });
            if let BundleError::BadFileHash(i) = e {
                out["file_index"] = json!(i);
            }
            out
        }
    }
}

fn parts_json(p: &Parts, good_payload: &[u8]) -> Value {
    json!({
        "manifest_hex": hex::encode(p.manifest.bytes()),
        "snapshot_hex": hex::encode(p.snapshot.encode()),
        "advisory_hex": p.advisory.as_ref().map(|a| hex::encode(a.bytes())),
        "payload_hex": (p.payload != good_payload).then(|| hex::encode(&p.payload)),
    })
}

const LAYOUT: &str = "manifest = \"RRB1\" | 0x01 | kind 0x01 | file_count u8 | reserved 0 | \
                      build_serial u64 | created_at_ms u64 | key_set_digest[32] | version_len \
                      u8 | version | target_len u8 | target | source_commit[20] | toolchain_len \
                      u8 | toolchain | min_advisory_serial u64 | chunk_size u32 | payload_len \
                      u64 | payload_chunk_root[32] | payload_sha256[32] | files (path_len u8 | \
                      path | mode u8 | offset u64 | size u64 | sha256[32] | rebuild_sha256[32]) \
                      | notes_len u16 | notes | signature block over \
                      \"rvn1/release-manifest/v1\\0\" || bytes before it; manifest_digest = \
                      SHA-256(\"rvn1/release-manifest/digest/v1\\0\" || manifest); container = \
                      \"RRBC\" | 0x01 | reserved[3] | manifest_len u32 | manifest | snapshot_len \
                      u32 | RTL1 snapshot | advisory_len u32 | RAD1 (0: none) | payload; chunk \
                      root = RFC 6962 over 61,440-byte chunks (RAVEN_RELEASE_BUNDLE_V1 §3-§6)";

const TEST_RELEASE: &str = "The test release: build 5, version 1.5.0 for aarch64-apple-darwin, \
                            three files (bin/raven 1,200 bytes and bin/raven-node 900 bytes, \
                            byte j = (j * 31 + 3 or 7) mod 251, mode 1; docs/README.txt, mode \
                            0), signed by keys 0 and 1 of the test key set (keyset_001). Its \
                            advisory: serial 1, RELEASE_FLOOR 3 and a NOTICE, signed by keys 0 \
                            and 2. Its log: the test key set, the advisory, the manifest, entry \
                            i logged at 1792713600000 + i days, the tree head signed by keys 0 \
                            and 1 the day after the last entry";

#[test]
fn update_vectors_rrb1() {
    let parts = good_parts();
    let (m, payload) = good_manifest();
    let ctx = Ctx::good();
    assert_vector(
        "rrb1_manifest_001.json",
        &vector(
            "rrb1_manifest_001",
            &format!(
                "{LAYOUT}. {TEST_RELEASE}. The manifest alone: its bytes, signing input and \
                 digest, the payload the files make and its chunk root (one chunk) and hash"
            ),
            json!({ "key_set": key_set_json(&CURRENT), "manifest": manifest_inputs(&m, &payload) }),
            json!({ "manifest": manifest_expected(&m), "payload_hex": hex::encode(&payload) }),
        ),
    );
    let advisory = parts.advisory.as_ref().unwrap();
    let sth = parts.snapshot.sth();
    assert_vector(
        "rrbc_small_001.json",
        &vector(
            "rrbc_small_001",
            &format!(
                "{LAYOUT}. {TEST_RELEASE}. The container of the test release with its \
                 advisory and log, verified (RAVEN_RELEASE_BUNDLE_V1 §7) against the test key \
                 set with the log up to the advisory stored (EXTENDS), installed build 4 for \
                 the same target and no stored floor: the advisory raises the floor to 3"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "manifest": manifest_inputs(&m, &payload),
                "advisory_hex": hex::encode(advisory.bytes()),
                "log": {
                    "entries": entries_json(parts.snapshot.entries()),
                    "sth": {
                        "timestamp_ms": sth.timestamp_ms,
                        "signers": sth.sigs().sigs().iter().map(|(i, _)| *i).collect::<Vec<_>>(),
                    },
                },
                "ctx": ctx_json(&ctx),
            }),
            json!({
                "container_hex": hex::encode(parts.encode()),
                "manifest_len": m.bytes().len(),
                "snapshot_len": parts.snapshot.encode().len(),
                "advisory_len": advisory.bytes().len(),
                "payload_len": payload.len(),
                "manifest_digest_hex": hex::encode(m.digest()),
                "advisory_digest_hex": hex::encode(advisory.digest()),
                "snapshot_hex": hex::encode(parts.snapshot.encode()),
                "verify": verify_json(&parts, &ctx),
            }),
        ),
    );
    let five = chunk_payload(4 * CHUNK_SIZE as usize + 1_000);
    let tree = ChunkTree::new(&five, CHUNK_SIZE);
    let max = ChunkTree::of_leaf_hashes(chunk_payload_leaves(MAX_PAYLOAD_LEN as usize));
    let path_hex = |t: &ChunkTree, i: usize| {
        t.chunk_path(i)
            .unwrap()
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
    };
    assert_vector(
        "rrb1_chunk_tree_001.json",
        &vector(
            "rrb1_chunk_tree_001",
            "Chunk roots and audit paths (RAVEN_RELEASE_BUNDLE_V1 §5): a payload of payload_len \
             bytes with byte j = j mod 251, cut in 61,440-byte chunks (the last one what is \
             left); leaf = SHA-256(0x00 || chunk), nodes and the split as RFC 6962 §2.1, the \
             audit path of chunk i as RFC 6962 §2.1.1 (from the leaf's sibling up), checked as \
             RFC 9162 §2.1.3.2. small: 4 full chunks and 1,000 bytes; max: 64 MiB, 1,093 \
             chunks, paths of up to 11 hashes",
            json!({
                "chunk_size": CHUNK_SIZE,
                "small_payload_len": five.len(),
                "max_payload_len": MAX_PAYLOAD_LEN,
                "max_path_indexes": [0, 1, 1_023, 1_024, 1_091, 1_092],
            }),
            json!({
                "small": {
                    "chunk_count": tree.len(),
                    "leaf_hashes_hex": (0..tree.len()).map(|i| hex::encode(tree.leaf(i).unwrap())).collect::<Vec<_>>(),
                    "root_hex": hex::encode(tree.root()),
                    "paths": (0..tree.len()).map(|i| json!({ "index": i, "path_hex": path_hex(&tree, i) })).collect::<Vec<_>>(),
                },
                "max": {
                    "chunk_count": max.len(),
                    "root_hex": hex::encode(max.root()),
                    "paths": ([0, 1, 1_023, 1_024, 1_091, 1_092].map(|i: usize| json!({ "index": i, "path_hex": path_hex(&max, i) }))),
                },
            }),
        ),
    );

    // Negatives.
    assert_vector(
        "negative/rrb1_path_traversal_001.json",
        &vector(
            "rrb1_path_traversal_001",
            &format!(
                "{LAYOUT}. Paths that could leave the staging directory or name another file \
                 than they seem (RAVEN_RELEASE_BUNDLE_V1 §3.3): the test release's manifest with \
                 file 1's path replaced (BAD_PATH), and pairs that collide on a \
                 case-insensitive file system or make a file a directory (DUPLICATE_PATH: files \
                 0 and 1). Each manifest carries a valid 2-of-3 block of the test keys over its \
                 own bytes; only the path rule breaks"
            ),
            json!({
                "cases": path_cases().iter().map(|(name, path, bytes, _)| json!({
                    "name": name,
                    "path_hex": hex::encode(path),
                    "manifest_hex": hex::encode(bytes),
                })).collect::<Vec<_>>(),
            }),
            json!({
                "errors": path_cases().iter().map(|(name, _, _, e)| json!({ "name": name, "error": e.code() })).collect::<Vec<_>>(),
            }),
        ),
    );
    assert_vector(
        "negative/rrb1_overlap_001.json",
        &vector(
            "rrb1_overlap_001",
            &format!(
                "{LAYOUT}. File layouts that do not tile the payload (RAVEN_RELEASE_BUNDLE_V1 \
                 §3.3): the test release's manifest with these (offset, size) for its three \
                 files and this payload_len; files must start at 0, follow each other without \
                 gap or overlap, and end exactly at payload_len. Each manifest validly signed"
            ),
            json!({
                "cases": overlap_cases().iter().map(|(name, layout, len, _)| json!({
                    "name": name,
                    "layout": layout.iter().map(|(o, s)| json!({ "offset": o, "size": s })).collect::<Vec<_>>(),
                    "payload_len": len,
                    "manifest_hex": hex::encode(with_layout(layout, *len)),
                })).collect::<Vec<_>>(),
            }),
            json!({
                "errors": overlap_cases().iter().map(|(name, _, _, e)| json!({ "name": name, "error": e.code() })).collect::<Vec<_>>(),
            }),
        ),
    );
    assert_vector(
        "negative/rrb1_decode_rules_001.json",
        &vector(
            "rrb1_decode_rules_001",
            &format!(
                "{LAYOUT}. Every structural refusal of RAVEN_RELEASE_BUNDLE_V1 §4, each case \
                 breaking one rule of the test release's manifest (the first it meets; a \
                 signature block, where present, is a valid 2-of-3 block of the test keys over \
                 the case's body). too_long: hex followed by zero bytes up to zero_pad_to bytes"
            ),
            json!({
                "cases": decode_cases().iter().map(|(name, bytes, _)| {
                    if *name == "too_long" {
                        json!({ "name": name, "hex": hex::encode(m.bytes()), "zero_pad_to": bytes.len() })
                    } else {
                        json!({ "name": name, "hex": hex::encode(bytes) })
                    }
                }).collect::<Vec<_>>(),
            }),
            json!({
                "errors": decode_cases().iter().map(|(name, _, e)| json!({ "name": name, "error": e.code() })).collect::<Vec<_>>(),
            }),
        ),
    );
    assert_vector(
        "negative/rrbc_decode_rules_001.json",
        &vector(
            "rrbc_decode_rules_001",
            &format!(
                "{LAYOUT}. {TEST_RELEASE}. Every refusal of RAVEN_RELEASE_BUNDLE_V1 §6 when \
                 a container is opened, each case breaking one rule of the test release's \
                 container (the first it meets); a refused part carries its own code as inner"
            ),
            json!({
                "cases": container_cases().iter().map(|(name, bytes, _)| json!({ "name": name, "hex": hex::encode(bytes) })).collect::<Vec<_>>(),
            }),
            json!({
                "errors": container_cases().iter().map(|(name, _, e)| json!({ "name": name, "error": e.code(), "inner": e.inner_code() })).collect::<Vec<_>>(),
            }),
        ),
    );
    let (_, unlogged, unlogged_ctx, _) = verify_cases()
        .into_iter()
        .find(|c| c.0 == "unlogged")
        .unwrap();
    assert_vector(
        "negative/rrb1_unlogged_001.json",
        &vector(
            "rrb1_unlogged_001",
            &format!(
                "{LAYOUT}. {TEST_RELEASE}. The test release in a container whose log (validly \
                 signed) lists the key set and the advisory but not the manifest: it opens, its \
                 manifest and log verify, but the release is not in the public log. UNLOGGED, \
                 refused (SEC_UPDATE_UNLOGGED)"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "container_hex": hex::encode(unlogged.encode()),
                "ctx": ctx_json(&unlogged_ctx),
            }),
            json!({
                "open": "OK",
                "manifest_verify": unlogged.manifest.verify(&key_set()).err().map_or("OK", SigError::code),
                "log_check": unlogged.snapshot.check(&key_set()).err().map_or("OK", LogCheckError::code),
                "manifest_digest_hex": hex::encode(unlogged.manifest.digest()),
                "verify": verify_json(&unlogged, &unlogged_ctx),
            }),
        ),
    );
    let linux = ctx.with(|c| c.target = OTHER_TARGET.into());
    assert_vector(
        "negative/rrb1_wrong_target_001.json",
        &vector(
            "rrb1_wrong_target_001",
            &format!(
                "{LAYOUT}. {TEST_RELEASE}. The good container (rrbc_small_001) verified by a \
                 build for x86_64-unknown-linux-gnu: signed and logged, but for another \
                 computer. WRONG_TARGET, refused without a security event"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "container_hex": hex::encode(parts.encode()),
                "ctx": ctx_json(&linux),
            }),
            json!({ "verify": verify_json(&parts, &linux) }),
        ),
    );
    let (_, tampered, tampered_ctx, _) = verify_cases()
        .into_iter()
        .find(|c| c.0 == "bad_chunk_root")
        .unwrap();
    assert_vector(
        "negative/rrbc_chunk_tamper_001.json",
        &vector(
            "rrbc_chunk_tamper_001",
            &format!(
                "{LAYOUT}. {TEST_RELEASE}. The good container with payload byte 1,500 (in \
                 bin/raven-node) changed by one bit: it opens and every signature and the log \
                 check, but the payload's chunk no longer hashes to the chunk root. \
                 BAD_CHUNK_ROOT, refused (SEC_BUNDLE_FORGED); the chunk alone fails its path \
                 check too (RUP1 checks every chunk before writing it)"
            ),
            json!({
                "key_set": key_set_json(&CURRENT),
                "container_hex": hex::encode(tampered.encode()),
                "ctx": ctx_json(&tampered_ctx),
            }),
            json!({
                "open": "OK",
                "chunk_root_hex": hex::encode(chunk_root(&tampered.payload, CHUNK_SIZE)),
                "manifest_chunk_root_hex": hex::encode(tampered.manifest.payload_chunk_root),
                "check_chunk_0": tampered.manifest.check_chunk(0, &tampered.payload, &[]),
                "verify": verify_json(&tampered, &tampered_ctx),
            }),
        ),
    );
    let mut rules = vector(
        "rrbc_verify_rules_001",
        &format!(
            "{LAYOUT}. {TEST_RELEASE}. Every rule of RAVEN_RELEASE_BUNDLE_V1 §7 in order, and \
             the accepted variants: each case is a bundle's parts (payload_hex null: the test \
             release's payload, good_payload_hex) and a verification context (key_set null: \
             no release keys; stored_log: the entries stored before). A changed manifest or \
             advisory is listed in its case's log, so only the case's rule breaks. Old key \
             set: seeds 0x44, 0x55, 0x66 x 32 (other_key_set); ok_rotated_key_set is a \
             manifest it signed, accepted because the current set's log lists it"
        ),
        json!({
            "key_set": key_set_json(&CURRENT),
            "good_payload_hex": hex::encode(&payload),
            "cases": verify_cases().iter().map(|(name, p, c, _)| json!({
                "name": name,
                "parts": parts_json(p, &payload),
                "ctx": ctx_json(c),
            })).collect::<Vec<_>>(),
        }),
        json!({
            "results": verify_cases().iter().map(|(name, p, c, want)| {
                let got = verify_json(p, c);
                assert_eq!(got["result"] == "OK", want.is_ok(), "{name}");
                let mut out = json!({ "name": name });
                out.as_object_mut().unwrap().extend(got.as_object().unwrap().clone());
                out
            }).collect::<Vec<_>>(),
        }),
    );
    rules["inputs"]["other_key_set"] = key_set_json(&OLD);
    assert_vector("negative/rrbc_verify_rules_001.json", &rules);
}

/// The committed `rrb1_*` and `rrbc_*` files are exactly the ones
/// [`update_vectors_rrb1`] writes.
#[test]
fn rrb1_vector_files() {
    if std::env::var(REGEN).as_deref() == Ok("1") {
        return; // being written right now
    }
    let names = |dir: &str| {
        let mut names: Vec<String> = std::fs::read_dir(rvn1_dir().join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| (n.starts_with("rrb1_") || n.starts_with("rrbc_")) && n.ends_with(".json"))
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        names("update"),
        [
            "rrb1_chunk_tree_001.json",
            "rrb1_manifest_001.json",
            "rrbc_small_001.json",
        ]
    );
    assert_eq!(
        names("update/negative"),
        [
            "rrb1_decode_rules_001.json",
            "rrb1_overlap_001.json",
            "rrb1_path_traversal_001.json",
            "rrb1_unlogged_001.json",
            "rrb1_wrong_target_001.json",
            "rrbc_chunk_tamper_001.json",
            "rrbc_decode_rules_001.json",
            "rrbc_verify_rules_001.json",
        ]
    );
}
