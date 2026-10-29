//! The offline release signing helpers (P6.46): key files, drafts,
//! detached signatures, the log kit and packing, each checked against
//! raven-core's own verifiers (the advisory, log and bundle checks a Raven
//! build runs on what the ceremony publishes).

use super::*;
use crate::advisory::{succession, Succession};
use crate::release_bundle::{BundleError, THIS_TARGET};
use crate::release_keys::test_keys::{key_set, key_set_of, signer, SEEDS};
use crate::tlog::Consistency;

const PASS: &[u8] = b"correct horse battery staple";
const OTHER_PASS: &[u8] = b"correct horse battery stapler";
/// 2026-10-24T00:00:00Z.
const AT_MS: u64 = 1_792_800_000_000;
const TARGET: &str = "x86_64-unknown-linux-gnu";

/// The published test seed of key index `i`, sealed in a key file with the
/// weak test parameters.
fn key_file(i: usize) -> KeyFile {
    KeyFile::seal_with(
        &format!("test-key-{i}"),
        &SEEDS[i],
        PASS,
        TEST_KDF,
        &TEST_BOUNDS,
    )
    .expect("seal")
}

/// Key index `i` signs `draft` through its key file.
fn sign_with_file(draft: &Artifact, i: usize) -> DetachedSig {
    let id = key_file(i).unlock(PASS).expect("unlock");
    sign_detached(draft, &key_set(), &id).expect("sign")
}

fn release_files() -> Vec<ReleaseFile> {
    let file = |path: &str, bytes: Vec<u8>| ReleaseFile {
        path: path.into(),
        rebuild_sha256: Sha256::digest(&bytes).into(),
        bytes,
    };
    vec![
        file("bin/ash", (0..70_000u32).map(|i| (i % 251) as u8).collect()),
        file(
            "bin/raven-node",
            (0..50_000u32).map(|i| (i % 241) as u8).collect(),
        ),
        file(
            "docs/INSTALL_Linux.md",
            b"# Install\nCopy bin/ to a folder.\n".to_vec(),
        ),
    ]
}

fn manifest_spec() -> ManifestSpec {
    ManifestSpec {
        build_serial: 7,
        created_at_ms: AT_MS,
        version: "0.1.0".into(),
        target: TARGET.into(),
        source_commit: [0xab; SOURCE_COMMIT_LEN],
        toolchain: "1.98.0".into(),
        min_advisory_serial: 0,
        notes: "Raven 0.1.0 (test): first signed release.\n".into(),
        files: release_files(),
    }
}

fn advisory_json(serial: u64) -> Vec<u8> {
    serde_json::json!({
        "serial": serial,
        "issued_at_ms": AT_MS,
        "entries": [
            {"kind": "SUITE_STATUS", "target": "pairinit/1/1", "severity": "DEPRECATED"},
            {"kind": "RELEASE_FLOOR", "min_build_serial": 5},
            {"kind": "FEATURE_HOLD", "target": "feature/link-knock", "severity": "BROKEN", "text_id": 3},
            {"kind": "NOTICE", "text": "Update Raven when you can."}
        ]
    })
    .to_string()
    .into_bytes()
}

fn signed_manifest() -> Manifest {
    let draft = manifest_draft(&manifest_spec(), &key_set()).expect("draft");
    let sigs = [sign_with_file(&draft, 0), sign_with_file(&draft, 2)];
    match combine(&draft, &key_set(), &sigs).expect("combine") {
        Artifact::Manifest(m) => m,
        other => panic!("not a manifest: {other:?}"),
    }
}

fn signed_advisory(serial: u64, previous: Previous<'_>) -> Advisory {
    let draft = advisory_draft(&advisory_json(serial), &key_set(), previous).expect("draft");
    let sigs = [sign_with_file(&draft, 1), sign_with_file(&draft, 0)];
    match combine(&draft, &key_set(), &sigs).expect("combine") {
        Artifact::Advisory(a) => a,
        other => panic!("not an advisory: {other:?}"),
    }
}

/// A log folder holding `artifacts`, with a signed tree head of the whole
/// log stored in it.
fn log_with(dir: &Path, artifacts: &[Artifact]) -> ReleaseLog {
    let mut log = ReleaseLog::open(dir).expect("open");
    for (i, a) in artifacts.iter().enumerate() {
        log.append_artifact(a, &key_set(), AT_MS + i as u64)
            .expect("append");
    }
    let draft = log.tree_head_draft(&key_set(), AT_MS + 100).expect("sth");
    let sigs = [sign_with_file(&draft, 1), sign_with_file(&draft, 2)];
    let Artifact::TreeHead(sth) = combine(&draft, &key_set(), &sigs).expect("combine") else {
        panic!("not a tree head");
    };
    log.store_tree_head(&sth, &key_set()).expect("store");
    log
}

// ── Key files ───────────────────────────────────────────────────────

#[test]
fn key_file_round_trips_and_a_wrong_passphrase_fails() {
    let file = KeyFile::generate_with("release-a", PASS, TEST_KDF, &TEST_BOUNDS).expect("generate");
    let bytes = file.encode();
    assert_eq!(
        bytes.len(),
        KEY_FILE_HEADER_LEN + "release-a".len() + 32 + 16
    );
    assert!(bytes.starts_with(KEY_FILE_MAGIC));
    let back = KeyFile::decode_with(&bytes, &TEST_BOUNDS).expect("decode");
    assert_eq!(back, file);
    assert_eq!(back.label(), "release-a");
    let id = back.unlock(PASS).expect("the right passphrase opens it");
    assert_eq!(id.public_key_bytes(), file.public_key());
    assert!(matches!(
        back.unlock(OTHER_PASS),
        Err(SignError::WrongPassphrase)
    ));
    assert!(matches!(back.unlock(b""), Err(SignError::WrongPassphrase)));
    // Two files of one seed and passphrase differ (fresh salt and nonce).
    assert_ne!(key_file(0).encode(), key_file(0).encode());
    assert_eq!(
        key_file(0).unlock(PASS).expect("unlock").public_key_bytes(),
        signer(0x11).public_key_bytes()
    );
}

#[test]
fn a_changed_key_file_byte_never_opens() {
    let bytes = key_file(1).encode();
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 0x01;
        let opened = KeyFile::decode_with(&changed, &TEST_BOUNDS).and_then(|f| f.unlock(PASS));
        assert!(
            opened.is_err(),
            "byte {at} changed and the key still opened"
        );
    }
}

#[test]
fn key_files_refuse_bad_labels_short_passphrases_and_unsafe_costs() {
    for label in [
        "",
        "Release",
        "alice smith",
        "-a",
        "a-",
        "a_b",
        &"k".repeat(33),
    ] {
        assert!(
            matches!(
                KeyFile::seal_with(label, &SEEDS[0], PASS, TEST_KDF, &TEST_BOUNDS),
                Err(SignError::BadLabel)
            ),
            "label {label:?}"
        );
    }
    assert!(label_well_formed("release-key-3"));
    assert!(matches!(
        KeyFile::seal_with("k", &SEEDS[0], b"eleven char", TEST_KDF, &TEST_BOUNDS),
        Err(SignError::BadPassphrase(_))
    ));
    assert!(check_new_passphrase("twelve chars".as_bytes()).is_ok());
    assert!(check_new_passphrase(&[b'a'; 1025]).is_err());
    // A planted header asking for 8 GiB, or 100 passes, is refused before
    // Argon2id runs.
    for (at, value) in [(12, 8 * 1024 * 1024u32), (16, 100), (20, 0)] {
        let mut bytes = key_file(0).encode();
        bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
        assert!(
            matches!(
                KeyFile::decode_with(&bytes, &TEST_BOUNDS),
                Err(SignError::UnsafeKdf { .. })
            ),
            "offset {at}"
        );
    }
    let mut bytes = key_file(0).encode();
    bytes.push(0);
    assert!(matches!(
        KeyFile::decode_with(&bytes, &TEST_BOUNDS),
        Err(SignError::BadKeyFile(_))
    ));
    assert!(matches!(
        KeyFile::decode_with(b"RVNRKY01", &TEST_BOUNDS),
        Err(SignError::BadKeyFile(_))
    ));
}

#[test]
fn the_production_cost_is_strong_and_the_test_cost_is_refused_by_it() {
    assert!(KEY_FILE_BOUNDS.check(KEY_FILE_KDF).is_ok());
    const { assert!(KEY_FILE_KDF.m_kib >= 256 * 1024) };
    assert!(KEY_FILE_BOUNDS.check(TEST_KDF).is_err());
    assert!(TEST_BOUNDS.check(TEST_KDF).is_ok());
}

/// Release builds of raven-release refuse the weak test parameters and the
/// published test keys, and read key files with the production bounds only
/// (run in release by the CI "inert" step).
#[test]
fn test_kdf_and_test_keys_are_inert_without_debug_assertions() {
    if cfg!(debug_assertions) {
        assert_eq!(keygen_params(true).expect("debug"), TEST_KDF);
        assert_eq!(key_file_bounds(), TEST_BOUNDS);
        assert_eq!(
            test_signer(2).expect("debug").public_key_bytes(),
            signer(0x33).public_key_bytes()
        );
        assert!(test_signer(3).is_err());
    } else {
        assert!(matches!(keygen_params(true), Err(SignError::TestOnly(_))));
        assert_eq!(key_file_bounds(), KEY_FILE_BOUNDS);
        assert!(matches!(test_signer(0), Err(SignError::TestOnly(_))));
    }
    assert_eq!(keygen_params(false).expect("production"), KEY_FILE_KDF);
    assert!(matches!(
        keygen_params_for(true, false),
        Err(SignError::TestOnly(_))
    ));
    assert_eq!(keygen_params_for(true, true).expect("debug"), TEST_KDF);
    assert_eq!(key_file_bounds_for(false), KEY_FILE_BOUNDS);
    assert_eq!(key_file_bounds_for(true), TEST_BOUNDS);
    // A release build reads no key file with the weak test cost.
    let weak = key_file(0).encode();
    assert!(matches!(
        KeyFile::decode_with(&weak, &key_file_bounds_for(false)),
        Err(SignError::UnsafeKdf { .. })
    ));
    for seed in SEEDS {
        assert!(is_test_key(&Identity::from_seed(&seed).public_key_bytes()));
    }
    assert!(!is_test_key(&signer(0x44).public_key_bytes()));
}

#[test]
fn public_keys_come_from_key_files_pub_files_or_hex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = key_file(2);
    let key_path = dir.path().join("k.rrk");
    fs::write(&key_path, file.encode()).expect("write");
    let pub_path = dir.path().join("k.rrk.pub");
    fs::write(
        &pub_path,
        format!("{}  test-key-2\n", to_hex(&file.public_key())),
    )
    .expect("write");
    let want = signer(0x33).public_key_bytes();
    // A key file with the weak test cost is read by debug builds only.
    let from_file = read_public_key(key_path.to_str().unwrap());
    if cfg!(debug_assertions) {
        assert_eq!(from_file.unwrap(), want);
    } else {
        assert!(matches!(from_file, Err(SignError::UnsafeKdf { .. })));
    }
    assert_eq!(read_public_key(pub_path.to_str().unwrap()).unwrap(), want);
    assert_eq!(read_public_key(&to_hex(&want)).unwrap(), want);
    assert!(read_public_key("not-a-file").is_err());
}

// ── Signing and combining ───────────────────────────────────────────

/// The step's acceptance test: the tool's helpers sign a manifest and an
/// advisory with the test keys (through key files), and raven-core's own
/// verifiers accept them.
#[test]
fn signs_a_manifest_and_an_advisory_that_raven_core_verifies() {
    let manifest = signed_manifest();
    let decoded = Manifest::decode(manifest.bytes()).expect("decode");
    decoded
        .verify(&key_set())
        .expect("raven-core verifies the manifest");
    assert_eq!(decoded.sigs().sigs().len(), 2);
    assert_eq!(decoded.sigs().sigs()[0].0, 0);
    assert_eq!(decoded.sigs().sigs()[1].0, 2);
    assert_eq!(decoded.files.len(), 3);
    assert_eq!(decoded.files[0].mode, FileMode::Executable);
    assert_eq!(decoded.files[2].mode, FileMode::Regular);

    let first = signed_advisory(1, Previous::None);
    let decoded = Advisory::decode(first.bytes()).expect("decode");
    decoded
        .verify(&key_set())
        .expect("raven-core verifies the advisory");
    assert_eq!(decoded.prev_digest, [0; 32]);
    assert_eq!(decoded.entries.len(), 4);
    assert_eq!(succession(None, &decoded), Succession::First);

    let second = signed_advisory(2, Previous::Advisory(&first));
    second.verify(&key_set()).expect("verifies");
    assert_eq!(
        succession(Some((first.serial, first.digest())), &second),
        Succession::Next
    );
    let by_digest = advisory_draft(
        &advisory_json(2),
        &key_set(),
        Previous::Digest(first.digest()),
    )
    .expect("draft");
    assert_eq!(
        by_digest,
        second
            .draft()
            .assemble(&SigBlock::default())
            .map(Artifact::Advisory)
            .unwrap()
    );
}

#[test]
fn drafts_decode_as_artifacts_and_show_what_is_signed() {
    let draft = manifest_draft(&manifest_spec(), &key_set()).expect("draft");
    assert!(draft.is_draft());
    let back = Artifact::decode(draft.bytes()).expect("decode");
    assert_eq!(back, draft);
    assert_eq!(back.kind(), ArtifactKind::Manifest);
    let summary = back.summary().join("\n");
    assert!(summary.contains("build serial 7"), "{summary}");
    assert!(summary.contains("bin/raven-node"), "{summary}");
    assert!(summary.contains("(draft)"), "{summary}");
    let advisory = advisory_draft(&advisory_json(1), &key_set(), Previous::None).unwrap();
    let summary = advisory.summary().join("\n");
    assert!(
        summary.contains("FEATURE_HOLD BROKEN feature/link-knock"),
        "{summary}"
    );
    assert!(
        summary.contains("RELEASE_FLOOR INFO builds below 5"),
        "{summary}"
    );
    // A snapshot is not signed itself, and other bytes are no artifact.
    let dir = tempfile::tempdir().expect("tempdir");
    let log = log_with(dir.path(), &[Artifact::Manifest(signed_manifest())]);
    let snapshot = log.snapshot(&key_set()).expect("snapshot").encode();
    assert!(matches!(
        Artifact::decode(&snapshot),
        Err(SignError::NotAnArtifact(_))
    ));
    assert!(matches!(
        Artifact::decode(b"RVNRKY01"),
        Err(SignError::NotAnArtifact(_))
    ));
    assert!(matches!(
        Artifact::decode(b"RAD1\x02"),
        Err(SignError::Artifact(_))
    ));
}

#[test]
fn detached_signatures_round_trip_and_decode_strictly() {
    let draft = advisory_draft(&advisory_json(1), &key_set(), Previous::None).unwrap();
    let sig = sign_with_file(&draft, 2);
    assert_eq!(sig.key_index, 2);
    assert_eq!(sig.kind, ArtifactKind::Advisory);
    assert_eq!(sig.signed_hash, draft.signing_hash());
    let bytes = sig.encode();
    assert_eq!(bytes.len(), SIG_FILE_LEN);
    assert_eq!(DetachedSig::decode(&bytes).expect("decode"), sig);
    for (at, value) in [(0, b'X'), (8, 2), (9, 4), (11, 1)] {
        let mut bad = bytes.clone();
        bad[at] = value;
        assert!(DetachedSig::decode(&bad).is_err(), "byte {at}");
    }
    assert!(DetachedSig::decode(&bytes[..139]).is_err());
}

#[test]
fn combine_refuses_what_would_not_verify() {
    let ks = key_set();
    let draft = manifest_draft(&manifest_spec(), &ks).expect("draft");
    let s0 = sign_with_file(&draft, 0);
    let s1 = sign_with_file(&draft, 1);

    // One signature is below the threshold of 2.
    let err = combine(&draft, &ks, std::slice::from_ref(&s0)).unwrap_err();
    assert!(matches!(err, SignError::Combine(_)), "{err}");
    // The same key twice.
    let err = combine(&draft, &ks, &[s0.clone(), s0.clone()]).unwrap_err();
    assert!(matches!(err, SignError::Combine(_)), "{err}");
    // A signature of another draft.
    let mut other_spec = manifest_spec();
    other_spec.build_serial = 8;
    let other = manifest_draft(&other_spec, &ks).expect("draft");
    let err = combine(&draft, &ks, &[s0.clone(), sign_with_file(&other, 1)]).unwrap_err();
    assert!(matches!(err, SignError::Signature(_)), "{err}");
    // A signature of another kind.
    let advisory = advisory_draft(&advisory_json(1), &ks, Previous::None).unwrap();
    let err = combine(&draft, &ks, &[s0.clone(), sign_with_file(&advisory, 1)]).unwrap_err();
    assert!(matches!(err, SignError::Signature(_)), "{err}");
    // A changed signature byte, or a signature under the wrong index.
    let mut bad = s1.clone();
    bad.signature[5] ^= 1;
    let err = combine(&draft, &ks, &[s0.clone(), bad]).unwrap_err();
    assert!(matches!(err, SignError::Signature(_)), "{err}");
    let mut moved = s1.clone();
    moved.key_index = 2;
    let err = combine(&draft, &ks, &[s0.clone(), moved]).unwrap_err();
    assert!(matches!(err, SignError::Signature(_)), "{err}");
    // A key outside the set cannot sign; a draft of another set is refused.
    let err = sign_detached(&draft, &ks, &signer(0x44)).unwrap_err();
    assert!(matches!(err, SignError::KeyNotInSet(_)), "{err}");
    let other_set = key_set_of(2, &[0x44, 0x55, 0x66]);
    let err = sign_detached(&draft, &other_set, &signer(0x44)).unwrap_err();
    assert!(matches!(err, SignError::WrongKeySet { .. }), "{err}");
    let err = combine(&draft, &other_set, &[]).unwrap_err();
    assert!(matches!(err, SignError::WrongKeySet { .. }), "{err}");

    // The order of the files does not matter.
    let signed = combine(&draft, &ks, &[s1.clone(), s0.clone()]).expect("combine");
    assert_eq!(
        signed,
        combine(&draft, &ks, &[s0.clone(), s1.clone()]).unwrap()
    );
    assert_eq!(signed.sigs().sigs().len(), 2);
    assert_eq!(signed.unsigned().unwrap(), draft);
    // More than the threshold is refused (Phase 6 review updates-protocol-1):
    // anyone could drop the extra one and make a copy with other bytes.
    let s2 = sign_with_file(&draft, 2);
    let err = combine(&signed, &ks, std::slice::from_ref(&s2)).unwrap_err();
    assert!(
        matches!(&err, SignError::Combine(m) if m.contains("exactly 2")),
        "{err}"
    );
    let err = combine(&draft, &ks, &[s0.clone(), s1.clone(), s2]).unwrap_err();
    assert!(matches!(err, SignError::Combine(_)), "{err}");
}

// ── Advisory descriptions ───────────────────────────────────────────

#[test]
fn advisory_descriptions_follow_the_chain_and_name_only_real_targets() {
    let ks = key_set();
    let draft = |json: serde_json::Value, previous| {
        advisory_draft(json.to_string().as_bytes(), &ks, previous)
    };
    let spec = |serial: u64, entries: serde_json::Value| serde_json::json!({"serial": serial, "issued_at_ms": AT_MS, "entries": entries});
    // The chain: 1 follows nothing, every other serial the one before.
    assert!(draft(spec(0, serde_json::json!([])), Previous::None).is_err());
    assert!(draft(spec(1, serde_json::json!([])), Previous::None).is_ok());
    assert!(draft(spec(2, serde_json::json!([])), Previous::None).is_err());
    assert!(draft(spec(1, serde_json::json!([])), Previous::Digest([1; 32])).is_err());
    assert!(draft(spec(3, serde_json::json!([])), Previous::Digest([0; 32])).is_err());
    let first = signed_advisory(1, Previous::None);
    assert!(draft(spec(3, serde_json::json!([])), Previous::Advisory(&first)).is_err());
    let unsigned = first.draft().assemble(&SigBlock::default()).unwrap();
    assert!(draft(
        spec(2, serde_json::json!([])),
        Previous::Advisory(&unsigned)
    )
    .is_err());
    // Only targets this build would enforce.
    for entry in [
        serde_json::json!({"kind": "SUITE_STATUS", "target": "pairinit/9/9", "severity": "BROKEN"}),
        serde_json::json!({"kind": "FEATURE_HOLD", "target": "feature/no-such-gate", "severity": "BROKEN"}),
        serde_json::json!({"kind": "FEATURE_HOLD", "target": "feature/advisory", "severity": "BROKEN"}),
        serde_json::json!({"kind": "NOTICE", "text": "x", "severity": "BROKEN"}),
        serde_json::json!({"kind": "NOTICE", "text": ""}),
        serde_json::json!({"kind": "RELEASE_FLOOR", "min_build_serial": 0}),
        serde_json::json!({"kind": "KEY_SET", "key_set_hex": "0102"}),
        serde_json::json!({"kind": "SUITE_STATUS", "target": "pairinit/1/1"}),
        serde_json::json!({"kind": "NOTICE", "text": "x", "person": "a name"}),
        serde_json::json!({"kind": "UNHEARD_OF"}),
    ] {
        let err = draft(spec(1, serde_json::json!([entry.clone()])), Previous::None).unwrap_err();
        assert!(matches!(err, SignError::Spec(_)), "{entry}: {err}");
    }
    // A key rotation names the next set.
    let next = key_set_of(2, &[0x44, 0x55, 0x66]);
    let rotate = draft(
        spec(
            1,
            serde_json::json!([{"kind": "KEY_SET", "key_set_hex": to_hex(&next.encode())}]),
        ),
        Previous::None,
    )
    .expect("rotation");
    let Artifact::Advisory(a) = rotate else {
        panic!("not an advisory")
    };
    assert_eq!(a.entries[0].key_set(), Some(next));
    assert!(serde_json::from_slice::<AdvisorySpec>(b"{\"serial\":1}").is_err());
}

/// Phase 6 review updates-protocol-4: an entry that closes the update
/// exchange (a hold on `feature/mesh-update`, `rup1/1` BROKEN) stops every
/// later notice between friends too, so the tool asks for it to be said;
/// a hold on release bundles leaves notices passing and needs nothing.
#[test]
fn an_entry_that_stops_notices_between_friends_must_say_so() {
    let ks = key_set();
    let draft = |entry: serde_json::Value| {
        let spec = serde_json::json!({"serial": 1, "issued_at_ms": AT_MS, "entries": [entry]});
        advisory_draft(spec.to_string().as_bytes(), &ks, Previous::None)
    };
    for entry in [
        serde_json::json!({"kind": "FEATURE_HOLD", "target": "feature/mesh-update", "severity": "BROKEN"}),
        serde_json::json!({"kind": "SUITE_STATUS", "target": "rup1/1", "severity": "BROKEN"}),
    ] {
        let err = draft(entry.clone()).unwrap_err();
        assert!(
            matches!(&err, SignError::Spec(m) if m.contains("stops_notices")),
            "{entry}: {err}"
        );
        let mut said = entry.clone();
        said["stops_notices"] = serde_json::json!(true);
        assert!(draft(said).is_ok(), "{entry}");
    }
    for entry in [
        serde_json::json!({"kind": "FEATURE_HOLD", "target": "feature/release-bundle", "severity": "BROKEN"}),
        serde_json::json!({"kind": "FEATURE_HOLD", "target": "feature/mesh-update", "severity": "DEPRECATED"}),
        serde_json::json!({"kind": "SUITE_STATUS", "target": "rup1/1", "severity": "DEPRECATED"}),
    ] {
        assert!(draft(entry.clone()).is_ok(), "{entry}");
    }
    assert!(closes_notices(
        EntryKind::FeatureHold,
        "feature/mesh-update"
    ));
    assert!(!closes_notices(
        EntryKind::FeatureHold,
        "feature/release-bundle"
    ));
    assert!(!closes_notices(EntryKind::Notice, "notice"));
}

// ── The log kit ─────────────────────────────────────────────────────

#[test]
fn the_log_kit_appends_signs_tree_heads_and_writes_snapshots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ks = key_set();
    let manifest = Artifact::Manifest(signed_manifest());
    let advisory = Artifact::Advisory(signed_advisory(1, Previous::None));
    let mut log = ReleaseLog::open(dir.path()).expect("open");
    assert!(log.entries().is_empty());
    assert!(
        log.tree_head_draft(&ks, AT_MS).is_err(),
        "an empty log has no head"
    );

    // Drafts and tree heads are not listed; signed artifacts are, once.
    let draft = manifest.unsigned().unwrap();
    assert!(log.append_artifact(&draft, &ks, AT_MS).is_err());
    let (entry, published) = log.append_artifact(&manifest, &ks, AT_MS).expect("append");
    assert_eq!(entry.kind, EntryType::Manifest);
    assert_eq!(
        published,
        dir.path()
            .join("manifests")
            .join(format!("7-{TARGET}.rrb1"))
    );
    assert_eq!(fs::read(&published).unwrap(), manifest.bytes());
    assert!(
        log.append_artifact(&manifest, &ks, AT_MS + 1).is_err(),
        "listed twice"
    );
    assert!(
        log.append_artifact(&advisory, &ks, AT_MS - 1).is_err(),
        "logged in the past"
    );
    assert!(
        !dir.path().join("advisories").exists(),
        "a refused entry publishes nothing"
    );
    let other_set = key_set_of(2, &[0x44, 0x55, 0x66]);
    assert!(log
        .append_artifact(&advisory, &other_set, AT_MS + 1)
        .is_err());
    log.append_artifact(&advisory, &ks, AT_MS + 1)
        .expect("append");
    let next = key_set_of(2, &[0x44, 0x55, 0x66]);
    let (entry, published) = log.append_key_set(&next, AT_MS + 2).expect("key set");
    assert_eq!(entry.digest, next.digest());
    assert_eq!(fs::read(published).unwrap(), next.encode());
    assert!(dir.path().join("advisories/1.rad1").is_file());

    // entries.bin is the entries back to back, read again on open.
    let bytes = fs::read(dir.path().join(LOG_ENTRIES)).unwrap();
    assert_eq!(bytes.len(), 3 * ENTRY_LEN);
    let reopened = ReleaseLog::open(dir.path()).expect("reopen");
    assert_eq!(reopened.entries(), log.entries());
    assert!(reopened.snapshot(&ks).is_err(), "no tree head yet");

    // The tree head: drafted, signed by two keys, kept as sth/3.rtl1.
    let head = log.tree_head_draft(&ks, AT_MS + 10).expect("draft");
    let Artifact::TreeHead(draft_head) = &head else {
        panic!("not a tree head")
    };
    assert_eq!(draft_head.tree_size, 3);
    let sigs = [sign_with_file(&head, 0), sign_with_file(&head, 1)];
    let Artifact::TreeHead(sth) = combine(&head, &ks, &sigs).unwrap() else {
        panic!("not a tree head")
    };
    assert!(log.store_tree_head(&sth, &other_set).is_err());
    let path = log.store_tree_head(&sth, &ks).expect("store");
    assert_eq!(path, dir.path().join("sth/3.rtl1"));
    let snapshot_path = log.write_snapshot(&ks).expect("snapshot");
    let snapshot = Snapshot::decode(&fs::read(snapshot_path).unwrap()).expect("decode");
    let checked = snapshot.check(&ks).expect("raven-core checks the snapshot");
    assert!(checked.contains(EntryType::Manifest, &signed_manifest().digest()));
    assert_eq!(
        checked.consistency(&log.entries()[..2]),
        Consistency::Extends
    );

    // A tree head whose root is not the log's is refused; a broken
    // entries.bin is refused on open.
    let mut entries = log.entries().to_vec();
    entries[0].logged_at_ms += 1;
    let wrong = SthDraft::of_entries(&entries, AT_MS, ks.digest())
        .sign(&[(0, &signer(0x11)), (1, &signer(0x22))])
        .unwrap();
    assert!(log.store_tree_head(&wrong, &ks).is_err());
    fs::write(dir.path().join(LOG_ENTRIES), &bytes[..40]).unwrap();
    assert!(ReleaseLog::open(dir.path()).is_err());
    assert!(decode_entries(&vec![0u8; ENTRY_LEN * (MAX_LOG_ENTRIES + 1)]).is_err());
}

// ── Packing ─────────────────────────────────────────────────────────

#[test]
fn pack_is_deterministic_and_raven_core_verifies_the_bundle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ks = key_set();
    let manifest = signed_manifest();
    let advisory = signed_advisory(1, Previous::None);
    let log = log_with(
        dir.path(),
        &[
            Artifact::Advisory(advisory.clone()),
            Artifact::Manifest(manifest.clone()),
        ],
    );
    let snapshot = log.snapshot(&ks).expect("snapshot");
    let files = tempfile::tempdir().expect("tempdir");
    for f in release_files() {
        let path = files.path().join(&f.path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, &f.bytes).unwrap();
    }
    let payload = read_payload(&manifest, files.path()).expect("payload");
    let one = pack(&ks, &manifest, &snapshot, Some(&advisory), payload.clone()).expect("pack");
    let two = pack(&ks, &manifest, &snapshot, Some(&advisory), payload.clone()).expect("pack");
    assert_eq!(one, two, "the same pieces pack to the same bytes");

    // What a Raven build of that target checks on import.
    let parts = Container::open(&one[..]).expect("open");
    let verified = verify_bundle(
        &parts,
        &VerifyCtx {
            key_set: Some(&ks),
            stored_log: &[],
            installed_serial: 6,
            target: TARGET,
            release_floor: 0,
            allow_downgrade: false,
        },
    )
    .expect("raven-core verifies the bundle");
    assert_eq!(verified.manifest().build_serial, 7);
    assert_eq!(verified.release_floor(), 5);
    assert_eq!(verified.files().count(), 3);
    if THIS_TARGET != TARGET {
        let ctx = VerifyCtx {
            key_set: Some(&ks),
            stored_log: &[],
            installed_serial: 0,
            target: THIS_TARGET,
            release_floor: 0,
            allow_downgrade: false,
        };
        assert_eq!(
            verify_bundle(&parts, &ctx).err(),
            Some(BundleError::WrongTarget)
        );
    }

    // A changed file (same size) or a manifest the log does not list is
    // refused before anything is written.
    let mut bad = payload.clone();
    bad[10] ^= 1;
    let err = pack(&ks, &manifest, &snapshot, None, bad).unwrap_err();
    assert!(matches!(err, SignError::Bundle(_)), "{err}");
    let other_dir = tempfile::tempdir().expect("tempdir");
    let unlisted = log_with(other_dir.path(), &[Artifact::Advisory(advisory.clone())]);
    let err = pack(
        &ks,
        &manifest,
        &unlisted.snapshot(&ks).unwrap(),
        None,
        payload,
    )
    .unwrap_err();
    assert!(err.to_string().contains("UNLOGGED"), "{err}");

    // A file of another size, or a link, is not read.
    fs::write(files.path().join("docs/INSTALL_Linux.md"), b"shorter").unwrap();
    assert!(read_payload(&manifest, files.path()).is_err());
    #[cfg(unix)]
    {
        let target = files.path().join("bin/raven-node");
        let moved = files.path().join("elsewhere");
        fs::rename(&target, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &target).unwrap();
        fs::write(
            files.path().join("docs/INSTALL_Linux.md"),
            &release_files()[2].bytes,
        )
        .unwrap();
        let err = read_payload(&manifest, files.path()).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }
}

#[test]
fn new_files_are_never_written_over() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("a.sig");
    write_new(&path, b"one").expect("new");
    write_new(&path, b"one").expect("the same bytes again");
    assert!(write_new(&path, b"two").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"one");
}

#[test]
fn key_set_files_are_bytes_or_hex() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ks = key_set();
    let raw = dir.path().join("raw.keyset");
    fs::write(&raw, ks.encode()).unwrap();
    let hex = dir.path().join("hex.keyset");
    fs::write(&hex, format!("{}\n", to_hex(&ks.encode()))).unwrap();
    assert_eq!(read_key_set(&raw).unwrap(), ks);
    assert_eq!(read_key_set(&hex).unwrap(), ks);
    fs::write(&raw, b"nope").unwrap();
    assert!(read_key_set(&raw).is_err());
}
