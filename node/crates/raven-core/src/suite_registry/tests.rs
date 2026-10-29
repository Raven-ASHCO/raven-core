//! The registry against the code and the spec: every gate of raven-core has
//! a feature id, every gated wire module of design D §7 has a suite id,
//! every id is a RAD1 target of its kind, and RAVEN_SECURITY_ADVISORY_V1 §4
//! lists exactly these ids.

use super::*;
use crate::advisory::{AdvisoryDraft, Entry, EntryKind, Severity, MAX_ENTRIES};
use crate::release_keys::test_keys::{key_set, signers};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `const <NAME>_PRODUCTION_ENABLED: bool` under raven-core's `src/`.
fn gates_in_source() -> BTreeSet<String> {
    fn walk(dir: &Path, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|x| x == "rs") {
                for line in std::fs::read_to_string(&path).unwrap().lines() {
                    let Some((_, rest)) = line.split_once("const ") else {
                        continue;
                    };
                    let Some((name, _)) = rest.split_once(": bool") else {
                        continue;
                    };
                    if name.ends_with("_PRODUCTION_ENABLED")
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                    {
                        out.insert(name.to_owned());
                    }
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(&crate_dir().join("src"), &mut out);
    out
}

/// The feature id of a gate name: `feature/` and the name without
/// `_PRODUCTION_ENABLED`, lower case, `_` written `-`.
fn derived_id(gate: &str) -> String {
    let base = gate.strip_suffix("_PRODUCTION_ENABLED").unwrap();
    format!("feature/{}", base.to_ascii_lowercase().replace('_', "-"))
}

#[test]
fn every_gate_has_a_feature_id() {
    let gates = gates_in_source();
    assert!(gates.len() >= 38, "the scan found only {gates:?}");
    let registered: BTreeSet<String> = FEATURES.iter().map(|f| f.gate.to_owned()).collect();
    assert_eq!(
        registered, gates,
        "every *_PRODUCTION_ENABLED gate needs a feature id here (and RAVEN_SECURITY_ADVISORY_V1 §4.2)"
    );
    for f in FEATURES {
        assert_eq!(f.id, derived_id(f.gate), "{}", f.gate);
        assert_eq!(feature(f.id), Some(f));
        assert_eq!(feature_for_gate(f.gate), Some(f));
    }
    // The values are the gates' own (the table names the constants).
    assert!(feature(FEATURE_LAN_DIRECT).unwrap().production);
    assert!(!feature(FEATURE_ADVISORY).unwrap().production);
    assert_eq!(
        feature(FEATURE_MESH_UPDATE).unwrap().production,
        crate::security_gate::MESH_UPDATE_PRODUCTION_ENABLED
    );
}

#[test]
fn every_gated_wire_module_has_a_suite_id() {
    let modules: Vec<&Suite> = SUITES.iter().filter(|s| s.layer == Layer::Module).collect();
    let ids: Vec<&str> = modules.iter().map(|s| s.id).collect();
    assert_eq!(
        ids,
        [RRH1_V1, RFC1_V1, RSR1_V1, RAL1_V1, RHW1_V1, RNL1_V1, PAD1_V1, RLK1_V1, RUP1_V1]
    );
    for s in SUITES {
        match s.layer {
            Layer::Module => {
                let gate = s.gate.expect("a module suite names its gate");
                assert!(feature_for_gate(gate).is_some(), "{}: {gate}", s.id);
            }
            _ => assert_eq!(s.gate, None, "{}", s.id),
        }
        assert_eq!(suite(s.id), Some(s));
    }
    // Each gated module once.
    let gates: BTreeSet<_> = modules.iter().map(|s| s.gate).collect();
    assert_eq!(gates.len(), modules.len());
    assert_eq!(
        SUITES.iter().filter(|s| s.layer == Layer::Link).count(),
        3,
        "noise, rih1, rlb1"
    );
    // The link suite names the Noise pattern raven-core runs.
    assert_eq!(
        crate::lan_noise::NOISE_PATTERN
            .to_ascii_lowercase()
            .replace('_', "-"),
        format!(
            "noise-{}",
            NOISE_XX_25519_CHACHAPOLY_BLAKE2S.trim_start_matches("noise/")
        )
    );
}

#[test]
fn ids_are_unique_and_well_formed() {
    let mut seen = BTreeSet::new();
    for id in SUITES
        .iter()
        .map(|s| s.id)
        .chain(FEATURES.iter().map(|f| f.id))
    {
        assert!(seen.insert(id), "{id} twice");
        assert!(crate::advisory::target_well_formed(id), "{id}");
    }
    assert_eq!(suite("pairinit/1/2"), None);
    assert_eq!(feature("feature/nothing"), None);
    assert_eq!(feature_for_gate("NOTHING_PRODUCTION_ENABLED"), None);
    // Only the advisory gate itself cannot be held.
    let unholdable: Vec<&str> = FEATURES
        .iter()
        .filter(|f| !f.holdable())
        .map(|f| f.id)
        .collect();
    assert_eq!(unholdable, [FEATURE_ADVISORY]);
}

/// An advisory naming every suite (SUITE_STATUS) and every feature
/// (FEATURE_HOLD) decodes and verifies: each id is a target of its kind.
#[test]
fn an_advisory_can_name_every_id() {
    let mut entries: Vec<Entry> = SUITES
        .iter()
        .map(|s| Entry {
            kind: EntryKind::SuiteStatus,
            severity: Severity::Broken,
            target: s.id.to_owned(),
            arg: Vec::new(),
            text_id: 0,
        })
        .collect();
    entries.extend(FEATURES.iter().map(|f| Entry {
        kind: EntryKind::FeatureHold,
        severity: Severity::Broken,
        target: f.id.to_owned(),
        arg: Vec::new(),
        text_id: 0,
    }));
    assert!(entries.len() <= MAX_ENTRIES, "{} ids", entries.len());
    let set = key_set();
    let [a, _, c] = signers();
    let advisory = AdvisoryDraft {
        serial: 1,
        issued_at_ms: 0,
        key_set_digest: set.digest(),
        prev_digest: [0; 32],
        entries,
    }
    .sign(&[(0, &a), (2, &c)])
    .unwrap();
    assert_eq!(advisory.verify(&set), Ok(()));
}

/// RAVEN_SECURITY_ADVISORY_V1 §4 lists exactly the registry: the first
/// column of its tables.
#[test]
fn the_spec_lists_every_id() {
    let mut spec = crate_dir();
    spec.pop();
    spec.pop();
    spec.pop();
    let text =
        std::fs::read_to_string(spec.join("protocol/RAVEN_SECURITY_ADVISORY_V1.md")).unwrap();
    let section = text
        .split("\n## 4. ")
        .nth(1)
        .and_then(|s| s.split("\n## 5. ").next())
        .expect("a section 4");
    let listed: BTreeSet<&str> = section
        .lines()
        .filter_map(|l| l.strip_prefix("| `"))
        .filter_map(|l| l.split_once('`').map(|(id, _)| id))
        .collect();
    let registry: BTreeSet<&str> = SUITES
        .iter()
        .map(|s| s.id)
        .chain(FEATURES.iter().map(|f| f.id))
        .collect();
    assert_eq!(listed, registry);
}
