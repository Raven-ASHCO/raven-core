//! P6.9 tests: [`TestSealer`] (identity, or each error injected) for the
//! store's own rules; the real [`PlatformSealer`] in a sealed temp profile
//! (the cfg(test) lab K_hist, never a keychain item) for RMS1 kind 22.

use super::*;
use crate::at_rest::SEALED_OVERHEAD;
use crate::learning::estimate::{DAY_MS, N_CAP_M};
use crate::learning::model::{ArmKey, MAX_CARRY_ROWS, MAX_CONTACTS, MAX_ENCOUNTERS};
use crate::learning::model::{MAX_NETS_PER_CONTACT, MAX_RELAYS, RETAIN_MS};
use crate::learning::observe::{DialTiming, Evidence, FrameKind, Observation};
use crate::outbox::DeliveryPath;
use crate::reach_diag::CircuitOutcome;

/// 20 min 34.567 s past an hour.
const NOW: u64 = 1_800_000_000_000 + 1_234_567;
const BOB: [u8; 32] = [0xB0; 32];
const CAROL: [u8; 32] = [0xC0; 32];
const NET: &str = "lan:192.168.1.0/24 home-wifi";
const RELAY: &[u8] = b"12D3KooWRelayPeerOne";

/// Identity, or the error given for each direction.
#[derive(Default)]
struct TestSealer {
    protect: Option<SealError>,
    unprotect: Option<SealError>,
}

impl Sealer for TestSealer {
    fn protect(&self, _dd: &Path, pt: &[u8]) -> Result<Vec<u8>, SealError> {
        self.protect.clone().map_or_else(|| Ok(pt.to_vec()), Err)
    }

    fn unprotect(&self, _dd: &Path, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        self.unprotect
            .clone()
            .map_or_else(|| Ok(Zeroizing::new(ct.to_vec())), Err)
    }
}

const ID: TestSealer = TestSealer {
    protect: None,
    unprotect: None,
};

fn failing(e: SealError) -> TestSealer {
    TestSealer {
        protect: Some(e.clone()),
        unprotect: Some(e),
    }
}

fn opening_fails(e: SealError) -> TestSealer {
    TestSealer {
        protect: None,
        unprotect: Some(e),
    }
}

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn bytes(dd: &Path) -> Vec<u8> {
    std::fs::read(path(dd)).unwrap()
}

/// Writes `raw` as the file, 0600 (what a save writes).
fn put(dd: &Path, raw: &[u8]) {
    crate::paths::atomic_write_private(&path(dd), raw).unwrap();
}

/// A plaintext as `file` gives it (no save: nothing pruned or rounded).
fn craft(dd: &Path, file: &LearningFile) {
    let mut raw = MAGIC.to_vec();
    serde_json::to_writer(&mut raw, file).unwrap();
    put(dd, &raw);
}

fn obs(carrier: OutboxCarrier, evidence: Evidence, path: Option<DeliveryPath>) -> Observation {
    Observation {
        contact: BOB,
        net: Some(NET.into()),
        net_changed: false,
        carrier,
        path,
        relay: (path == Some(DeliveryPath::Relayed)).then(|| RELAY.to_vec()),
        kind: FrameKind::Message,
        evidence,
        timing: DialTiming {
            connect_ms: Some(40),
            reply_ms: Some(90),
            total_ms: 250,
        },
        karn_exclude: false,
        at_ms: NOW,
    }
}

fn key(carrier: OutboxCarrier) -> ArmKey {
    ArmKey {
        contact: BOB,
        net: Some(NET.into()),
        carrier,
    }
}

/// Arms on three carriers (one relayed receipt), a relay row from that
/// receipt and one from a busy circuit, an encounter and a carry row.
fn sample() -> Model {
    let mut m = Model::new_empty([7; 32]);
    let hour_ago = NOW - HOUR_MS;
    m.observe(
        &obs(
            OutboxCarrier::Lan,
            Evidence::Receipt,
            Some(DeliveryPath::Direct),
        ),
        hour_ago - 2 * HOUR_MS,
    );
    m.observe(
        &obs(
            OutboxCarrier::Internet,
            Evidence::Fail {
                code: "NOT_REACHABLE",
                weight_milli: 1_000,
            },
            None,
        ),
        hour_ago - HOUR_MS,
    );
    m.observe(
        &obs(
            OutboxCarrier::P2p,
            Evidence::Receipt,
            Some(DeliveryPath::Relayed),
        ),
        hour_ago,
    );
    m.relay_circuit(b"12D3KooWRelayPeerTwo", CircuitOutcome::Busy, NOW);
    assert!(m.encounter(&CAROL, NOW - 5 * HOUR_MS));
    assert!(m.encounter(&CAROL, NOW - HOUR_MS));
    m.carry_outcome(&BOB, &[CAROL], true, NOW - HOUR_MS);
    m
}

fn round_beta(b: Beta) -> Beta {
    Beta {
        at_ms: hour(b.at_ms),
        ..b
    }
}

fn round_rtt(r: Rtt) -> Rtt {
    Rtt {
        at_ms: hour(r.at_ms),
        ..r
    }
}

/// `a` as a save and a load give it back.
fn round_arm(a: Arm) -> Arm {
    Arm {
        beta: round_beta(a.beta),
        connect: round_rtt(a.connect),
        reply: round_rtt(a.reply),
        last_obs_ms: hour(a.last_obs_ms),
        last_receipt_ms: hour(a.last_receipt_ms),
        last_probe_ms: hour(a.last_probe_ms),
        ..a
    }
}

/// Every row of `a` equals `b`'s as a save and a load give it back.
fn assert_round_tripped(loaded: &Model, saved: &Model) {
    for carrier in [
        OutboxCarrier::Lan,
        OutboxCarrier::Internet,
        OutboxCarrier::P2p,
    ] {
        let want = round_arm(*saved.arm(&key(carrier)).unwrap());
        assert_eq!(loaded.arm(&key(carrier)), Some(&want), "{carrier:?}");
    }
    for relay in [RELAY, b"12D3KooWRelayPeerTwo"] {
        let row = saved.relay(relay).unwrap();
        let want = RelayRow {
            beta: round_beta(row.beta),
            ..*row
        };
        assert_eq!(loaded.relay(relay), Some(&want));
    }
    let e = saved.encounter_of(&CAROL).unwrap();
    let want = Encounter {
        at_ms: hour(e.at_ms),
        last_ms: hour(e.last_ms),
        ..*e
    };
    assert_eq!(loaded.encounter_of(&CAROL), Some(&want));
    let row = saved.carry_of(&CAROL, &BOB).unwrap();
    assert_eq!(
        loaded.carry_of(&CAROL, &BOB).map(|r| r.beta),
        Some(round_beta(row.beta))
    );
    assert_eq!(
        (
            loaded.arms.len(),
            loaded.relays.len(),
            loaded.encounters.len(),
            loaded.carry.len()
        ),
        (3, 2, 1, 1)
    );
}

fn json_of(raw: &[u8]) -> serde_json::Value {
    serde_json::from_slice(raw.strip_prefix(MAGIC.as_slice()).expect("magic")).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A profile sealed as raven-node's start seals it, its keys loaded.
fn sealed_profile() -> tempfile::TempDir {
    let dir = crate::contact_book::tests::profile();
    crate::contact_book::tests::seal(dir.path());
    dir
}

#[test]
fn round_trip() {
    let dir = dir();
    let dd = dir.path();
    let m = sample();
    save(dd, &ID, &m, NOW).unwrap();
    let raw = bytes(dd);
    assert!(raw.starts_with(MAGIC));
    assert_eq!(json_of(&raw)["v"], 1);
    assert_eq!(json_of(&raw)["secret"], hex::encode([7u8; 32]));
    let (loaded, state) = load(dd, &ID, NOW);
    assert_eq!(state, StoreState::On);
    assert_eq!(loaded.state, State::On);
    // The same secret: the same keys find the same rows.
    assert_eq!(*loaded.secret, [7; 32]);
    assert_round_tripped(&loaded, &m);
    // The memory-only parts start over.
    assert_eq!(loaded.counters().observations, 0);
    // A second save of the loaded model writes the same plaintext.
    save(dd, &ID, &loaded, NOW).unwrap();
    assert_eq!(bytes(dd), raw);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path(dd)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn missing_is_empty_on() {
    let dir = dir();
    let dd = dir.path();
    let (m, state) = load(dd, &ID, NOW);
    assert_eq!(state, StoreState::On);
    assert_eq!(m.state, State::On);
    assert_eq!(
        (
            m.arms.len(),
            m.relays.len(),
            m.encounters.len(),
            m.carry.len()
        ),
        (0, 0, 0, 0)
    );
    // A new secret from the OS for each empty model, first written by its
    // first save; no file and no lock file before.
    let (other, _) = load(dd, &ID, NOW);
    assert_ne!(*m.secret, *other.secret);
    assert_ne!(*m.secret, [0; 32]);
    assert!(std::fs::read_dir(dd).unwrap().next().is_none());
    save(dd, &ID, &m, NOW).unwrap();
    assert_eq!(json_of(&bytes(dd))["secret"], hex::encode(*m.secret));
}

#[test]
fn unavailable_is_memory_only_and_file_untouched() {
    let dir = dir();
    let dd = dir.path();
    save(dd, &ID, &sample(), NOW).unwrap();
    let before = bytes(dd);
    let locked = failing(SealError::Unavailable);
    let (m, state) = load(dd, &locked, NOW);
    assert_eq!(state, StoreState::MemoryOnly("keystore"));
    assert_eq!(m.state, State::MemoryOnly);
    assert!(m.arms.is_empty());
    // Refused, whatever the sealer could do now.
    assert!(save(dd, &locked, &m, NOW).is_err());
    assert!(save(dd, &ID, &m, NOW).is_err());
    assert_eq!(bytes(dd), before);
    // A save that cannot seal writes nothing either.
    assert!(save(dd, &locked, &sample(), NOW).is_err());
    assert_eq!(bytes(dd), before);
    // No file to open: the sealer is asked, and the model is memory-only.
    let empty = self::dir();
    let (m, state) = load(empty.path(), &locked, NOW);
    assert_eq!(state, StoreState::MemoryOnly("keystore"));
    assert_eq!(m.state, State::MemoryOnly);
    assert!(save(empty.path(), &ID, &m, NOW).is_err());
    assert!(!path(empty.path()).exists());
    // An I/O failure of the sealer is memory-only too.
    let (_, state) = load(dd, &failing(SealError::Other("disk".into())), NOW);
    assert_eq!(state, StoreState::MemoryOnly("io"));
    assert_eq!(bytes(dd), before);
}

#[test]
fn corrupt_and_tampered_reset_and_overwrite() {
    let garbage = b"not a learning file".to_vec();
    let mut plain = MAGIC.to_vec();
    plain.extend_from_slice(b"{\"v\":1,\"secret\":\"00\"}");
    let mut zero = MAGIC.to_vec();
    zero.extend_from_slice(b"{\"v\":0,\"secret\":\"00\"}");
    let mut bad_rows = MAGIC.to_vec();
    bad_rows.extend_from_slice(b"{\"v\":1,\"secret\":\"");
    bad_rows.extend_from_slice(hex::encode([1u8; 32]).as_bytes());
    bad_rows.extend_from_slice(b"\",\"arms\":[[1,2]]}");
    let cases: [(&[u8], TestSealer); 7] = [
        (garbage.as_slice(), ID),
        (b"RVNLRN01", ID),
        (plain.as_slice(), ID),
        (zero.as_slice(), ID),
        (bad_rows.as_slice(), ID),
        (b"sealed", opening_fails(SealError::Corrupt)),
        (b"sealed", opening_fails(SealError::AuthFailed)),
    ];
    for (n, (raw, sealer)) in cases.iter().enumerate() {
        let dir = dir();
        let dd = dir.path();
        put(dd, raw);
        let (m, state) = load(dd, sealer, NOW);
        assert_eq!(state, StoreState::ResetAfterUnreadable, "case {n}");
        assert_eq!(m.state, State::ResetAfterUnreadable, "case {n}");
        assert!(m.arms.is_empty(), "case {n}");
        // Overwritten on the next save, and read back on.
        save(dd, sealer, &m, NOW).unwrap();
        assert_ne!(bytes(dd), *raw, "case {n}");
        let (_, state) = load(dd, &ID, NOW);
        assert_eq!(state, StoreState::On, "case {n}");
    }
}

#[test]
fn newer_version_is_never_overwritten() {
    let mut newer = MAGIC.to_vec();
    newer.extend_from_slice(b"{\"v\":2,\"rows\":\"another layout\"}");
    for (raw, sealer) in [
        (newer, ID),
        (b"sealed".to_vec(), opening_fails(SealError::Newer)),
    ] {
        let dir = dir();
        let dd = dir.path();
        put(dd, &raw);
        let (m, state) = load(dd, &sealer, NOW);
        assert_eq!(state, StoreState::MemoryOnly("newer"));
        assert_eq!(m.state, State::MemoryOnly);
        assert!(save(dd, &sealer, &m, NOW).is_err());
        assert_eq!(bytes(dd), raw);
    }
}

#[cfg(unix)]
#[test]
fn symlink_hardlink_and_oversize_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let good = |dd: &Path| {
        save(dd, &ID, &sample(), NOW).unwrap();
        bytes(dd)
    };
    // A symlink to a good file elsewhere: refused, and the save replaces the
    // link itself, never its target.
    let dir = dir();
    let dd = dir.path();
    let outside = self::dir();
    let raw = good(outside.path());
    std::os::unix::fs::symlink(path(outside.path()), path(dd)).unwrap();
    let (m, state) = load(dd, &ID, NOW);
    assert_eq!(state, StoreState::ResetAfterUnreadable);
    save(dd, &ID, &m, NOW).unwrap();
    assert!(!std::fs::symlink_metadata(path(dd))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(bytes(outside.path()), raw);
    // A second link.
    let dir = self::dir();
    let dd = dir.path();
    good(dd);
    std::fs::hard_link(path(dd), dd.join("learning.copy")).unwrap();
    assert_eq!(load(dd, &ID, NOW).1, StoreState::ResetAfterUnreadable);
    std::fs::remove_file(dd.join("learning.copy")).unwrap();
    assert_eq!(load(dd, &ID, NOW).1, StoreState::On);
    // Not 0600.
    for mode in [0o644, 0o640, 0o400, 0o700] {
        std::fs::set_permissions(path(dd), std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            load(dd, &ID, NOW).1,
            StoreState::ResetAfterUnreadable,
            "{mode:o}"
        );
    }
    std::fs::set_permissions(path(dd), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(load(dd, &ID, NOW).1, StoreState::On);
    // A directory in its place.
    let dir = self::dir();
    std::fs::create_dir(path(dir.path())).unwrap();
    assert_eq!(
        load(dir.path(), &ID, NOW).1,
        StoreState::ResetAfterUnreadable
    );
    // Over the size limit (one byte over; a sealer is never asked to open it).
    let dir = self::dir();
    let dd = dir.path();
    put(dd, &vec![b' '; MAX_FILE as usize + 1]);
    let refuses = opening_fails(SealError::Other("opened".into()));
    assert_eq!(load(dd, &refuses, NOW).1, StoreState::ResetAfterUnreadable);
    // A refused file with no key is memory-only and stays as it is.
    let before = bytes(dd);
    let (_, state) = load(dd, &failing(SealError::Unavailable), NOW);
    assert_eq!(state, StoreState::MemoryOnly("keystore"));
    assert_eq!(bytes(dd), before);
}

#[cfg(not(unix))]
#[test]
fn symlink_hardlink_and_oversize_are_refused() {
    let dir = dir();
    let dd = dir.path();
    put(dd, &vec![b' '; MAX_FILE as usize + 1]);
    assert_eq!(load(dd, &ID, NOW).1, StoreState::ResetAfterUnreadable);
    let dir = self::dir();
    std::fs::create_dir(path(dir.path())).unwrap();
    assert_eq!(
        load(dir.path(), &ID, NOW).1,
        StoreState::ResetAfterUnreadable
    );
}

/// Worst-case values in every row, every map at its cap.
fn full_model() -> Model {
    let mut m = Model::new_empty([9; 32]);
    let beta = Beta {
        a_m: N_CAP_M / 2,
        b_m: N_CAP_M / 2,
        at_ms: NOW,
        streak: u8::MAX,
    };
    let rtt = Rtt {
        srtt_ms: u32::MAX,
        rttvar_ms: u32::MAX,
        n: u16::MAX,
        backoff: MAX_BACKOFF,
        at_ms: NOW,
    };
    let arm = Arm {
        beta,
        ok_ms: u32::MAX,
        fail_ms: u32::MAX,
        connect: rtt,
        reply: rtt,
        paths: [u16::MAX; 4],
        last_obs_ms: NOW,
        last_receipt_ms: NOW,
        last_probe_ms: NOW,
        recent: u8::MAX,
        recent_n: RECENT_MAX,
    };
    let k16 = |tag: u8, i: usize| {
        let mut k = [tag; 16];
        k[..8].copy_from_slice(&(i as u64).to_be_bytes());
        k
    };
    for c in 0..MAX_CONTACTS {
        for n in 0..MAX_NETS_PER_CONTACT {
            for k in 0..3 {
                m.arms.insert((k16(0xC0, c), [n as u8; 8], k), arm);
            }
        }
    }
    for r in 0..MAX_RELAYS {
        let row = RelayRow {
            beta,
            ok_ms: u32::MAX,
        };
        m.relays.insert(k16(0xA0, r), row);
    }
    for c in 0..MAX_ENCOUNTERS {
        let e = Encounter {
            p_q16: Q16_ONE,
            at_ms: NOW,
            last_ms: NOW,
        };
        m.encounters.insert(k16(0xE0, c), e);
    }
    for i in 0..MAX_CARRY_ROWS {
        m.carry
            .insert((k16(0xF0, i), k16(0xF1, i)), CarryRow { beta });
    }
    m
}

fn counts(m: &Model) -> (usize, usize, usize, usize) {
    (
        m.arms.len(),
        m.relays.len(),
        m.encounters.len(),
        m.carry.len(),
    )
}

#[test]
fn caps_and_retention() {
    let full = (
        MAX_CONTACTS * MAX_NETS_PER_CONTACT * 3,
        MAX_RELAYS,
        MAX_ENCOUNTERS,
        MAX_CARRY_ROWS,
    );
    // A model at every cap, with the widest values, fits the limit even
    // sealed (RMS1 adds its overhead).
    let dir = dir();
    let dd = dir.path();
    let m = full_model();
    assert_eq!(counts(&m), full);
    save(dd, &ID, &m, NOW).unwrap();
    let len = bytes(dd).len() as u64;
    assert!(len + SEALED_OVERHEAD <= MAX_FILE, "{len} bytes");
    let (loaded, state) = load(dd, &ID, NOW);
    assert_eq!(state, StoreState::On);
    assert_eq!(counts(&loaded), full);

    // A file over the caps (another writer, a hand edit): the caps are kept
    // on load, the oldest rows go.
    let mut file = LearningFile {
        v: VERSION,
        secret: hex::encode([9u8; 32]),
        arms: Vec::new(),
        relays: Vec::new(),
        enc: Vec::new(),
        carry: Vec::new(),
    };
    let beta = |at: u64| BetaRow(1_000, 0, at, 1);
    let rtt = || RttRow(0, 0, 0, 0, 0);
    let arm = |c: u8, n: u8, at: u64| {
        ArmRow(
            hex::encode([c; 16]),
            hex::encode([n; 8]),
            0,
            beta(at),
            300,
            5_000,
            rtt(),
            rtt(),
            [0; 4],
            at,
            at,
            0,
            1,
            1,
        )
    };
    let old = NOW - DAY_MS;
    // 65 contacts (the first one oldest), and contact 1 on 9 networks.
    for c in 0..=MAX_CONTACTS as u8 {
        file.arms.push(arm(c, 0, if c == 0 { old } else { NOW }));
    }
    for n in 1..=MAX_NETS_PER_CONTACT as u8 {
        file.arms
            .push(arm(1, n, if n == 1 { old } else { NOW - HOUR_MS }));
    }
    for r in 0..=MAX_RELAYS as u8 {
        let at = if r == 0 { old } else { NOW };
        file.relays
            .push(RelayFileRow(hex::encode([r; 16]), beta(at), 3_000));
    }
    for c in 0..=MAX_ENCOUNTERS as u8 {
        let at = if c == 0 { old } else { NOW };
        file.enc.push(EncRow(hex::encode([c; 16]), 30_000, at, at));
    }
    for i in 0..=MAX_CARRY_ROWS as u8 {
        let at = if i == 0 { old } else { NOW };
        file.carry.push(CarryFileRow(
            hex::encode([i; 16]),
            hex::encode([0xBB; 16]),
            beta(at),
        ));
    }
    craft(dd, &file);
    let (m, state) = load(dd, &ID, NOW);
    assert_eq!(state, StoreState::On);
    let contacts: std::collections::BTreeSet<[u8; 16]> = m.arms.keys().map(|k| k.0).collect();
    assert_eq!(contacts.len(), MAX_CONTACTS);
    assert!(!contacts.contains(&[0; 16]), "the oldest contact went");
    let nets = m.arms.keys().filter(|k| k.0 == [1; 16]).count();
    assert_eq!(nets, MAX_NETS_PER_CONTACT);
    assert!(
        !m.arms.contains_key(&([1; 16], [1; 8], 0)),
        "its oldest network went"
    );
    assert_eq!(m.relays.len(), MAX_RELAYS);
    assert!(!m.relays.contains_key(&[0; 16]));
    assert_eq!(m.encounters.len(), MAX_ENCOUNTERS);
    assert!(!m.encounters.contains_key(&[0; 16]));
    assert_eq!(m.carry.len(), MAX_CARRY_ROWS);
    assert!(!m.carry.contains_key(&([0; 16], [0xBB; 16])));

    // Retention: a row not updated for 30 days goes, and so does one with
    // less than 50 milli of evidence (on load, and before a save writes).
    let mut file = LearningFile {
        v: VERSION,
        secret: hex::encode([9u8; 32]),
        arms: vec![
            arm(1, 0, NOW),
            arm(2, 0, NOW - RETAIN_MS - HOUR_MS),
            ArmRow(
                hex::encode([3u8; 16]),
                hex::encode([0u8; 8]),
                0,
                BetaRow(20, 20, NOW, 0),
                300,
                5_000,
                rtt(),
                rtt(),
                [0; 4],
                NOW,
                NOW,
                0,
                0,
                0,
            ),
        ],
        relays: vec![RelayFileRow(
            hex::encode([1u8; 16]),
            beta(NOW - RETAIN_MS - HOUR_MS),
            3_000,
        )],
        enc: vec![EncRow(
            hex::encode([1u8; 16]),
            30_000,
            NOW,
            NOW - RETAIN_MS - HOUR_MS,
        )],
        carry: vec![CarryFileRow(
            hex::encode([1u8; 16]),
            hex::encode([2u8; 16]),
            beta(NOW - RETAIN_MS - HOUR_MS),
        )],
    };
    craft(dd, &file);
    let (m, _) = load(dd, &ID, NOW);
    assert_eq!(counts(&m), (1, 0, 0, 0));
    assert!(m.arms.contains_key(&([1; 16], [0; 8], 0)));
    file.arms.truncate(1);
    craft(dd, &file);
    // 31 days later nothing is left, and a save writes no stale row.
    let later = NOW + RETAIN_MS + DAY_MS;
    let (m, _) = load(dd, &ID, later);
    assert_eq!(counts(&m), (0, 0, 0, 0));
    let (m, _) = load(dd, &ID, NOW);
    assert_eq!(counts(&m), (1, 0, 0, 0));
    save(dd, &ID, &m, later).unwrap();
    assert_eq!(json_of(&bytes(dd))["arms"], serde_json::json!([]));
}

#[test]
fn load_clamps_and_drops_bad_rows() {
    let dir = dir();
    let dd = dir.path();
    let future = NOW + 10 * DAY_MS;
    let row = |c: &str, n: &str, k: u8| {
        ArmRow(
            c.into(),
            n.into(),
            k,
            BetaRow(N_CAP_M * 2, N_CAP_M * 2, future, 2),
            300,
            5_000,
            RttRow(100, 50, 5, 9, future),
            RttRow(100, 50, 5, 1, NOW),
            [1, 0, 0, 0],
            future,
            future,
            future,
            0b1111_1111,
            200,
        )
    };
    let good_c = hex::encode([1u8; 16]);
    let good_n = hex::encode([2u8; 8]);
    let file = LearningFile {
        v: VERSION,
        secret: hex::encode([5u8; 32]),
        arms: vec![
            row(&good_c, &good_n, 1),
            // Nearby is never ranked; 9 is no carrier.
            row(&good_c, &good_n, 3),
            row(&good_c, &good_n, 9),
            // Keys of the wrong length or not hex.
            row(&hex::encode([1u8; 15]), &good_n, 0),
            row(&good_c, &hex::encode([2u8; 9]), 0),
            row("zz", &good_n, 0),
        ],
        relays: vec![RelayFileRow("12".into(), BetaRow(1_000, 0, NOW, 1), 0)],
        enc: vec![
            EncRow(good_c.clone(), Q16_ONE * 3, future, future),
            EncRow(hex::encode([2u8; 16]), 0, NOW, NOW),
        ],
        carry: vec![CarryFileRow(
            good_c.clone(),
            "nothex".into(),
            BetaRow(1_000, 0, NOW, 1),
        )],
    };
    craft(dd, &file);
    let (m, state) = load(dd, &ID, NOW);
    assert_eq!(state, StoreState::On);
    assert_eq!(counts(&m), (1, 0, 1, 0));
    let arm = m.arms[&([1; 16], [2; 8], 1)];
    // Counts scaled back to the cap, the ratio kept; no time after now.
    assert_eq!(arm.beta.a_m + arm.beta.b_m, N_CAP_M);
    assert_eq!(arm.beta.a_m, arm.beta.b_m);
    assert_eq!(arm.beta.at_ms, NOW);
    assert_eq!((arm.connect.backoff, arm.connect.at_ms), (MAX_BACKOFF, NOW));
    assert_eq!(
        (arm.last_obs_ms, arm.last_receipt_ms, arm.last_probe_ms),
        (NOW, NOW, NOW)
    );
    assert_eq!(arm.recent_n, RECENT_MAX);
    let e = m.encounters[&[1; 16]];
    assert_eq!((e.p_q16, e.at_ms, e.last_ms), (Q16_ONE, NOW, NOW));
    // A secret that is not 32 bytes of hex is no file at all.
    let mut file = file;
    file.secret = hex::encode([5u8; 31]);
    craft(dd, &file);
    assert_eq!(load(dd, &ID, NOW).1, StoreState::ResetAfterUnreadable);
}

#[test]
fn times_round_to_the_hour() {
    let dir = dir();
    let dd = dir.path();
    let m = sample();
    // Times off the hour before the save.
    let arm = m.arm(&key(OutboxCarrier::P2p)).unwrap();
    assert_ne!(arm.last_obs_ms % HOUR_MS, 0);
    save(dd, &ID, &m, NOW).unwrap();
    // Every number in the file that is a time is on the hour.
    fn times(v: &serde_json::Value, out: &mut Vec<u64>) {
        match v {
            serde_json::Value::Number(n) => {
                if let Some(t) = n.as_u64().filter(|t| *t >= 1_000_000_000_000) {
                    out.push(t);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|i| times(i, out)),
            serde_json::Value::Object(map) => map.values().for_each(|i| times(i, out)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    times(&json_of(&bytes(dd)), &mut found);
    // 14 in the arms (no receipt on the failed one), 2 relays, the
    // encounter's 2 and the carry row's 1.
    assert_eq!(found.len(), 19);
    assert!(found.iter().all(|t| t % HOUR_MS == 0), "{found:?}");
    let (loaded, _) = load(dd, &ID, NOW);
    let arm = loaded.arm(&key(OutboxCarrier::P2p)).unwrap();
    for t in [
        arm.beta.at_ms,
        arm.connect.at_ms,
        arm.reply.at_ms,
        arm.last_obs_ms,
        arm.last_receipt_ms,
    ] {
        assert_eq!(t % HOUR_MS, 0);
    }
    // No field names a time of day.
    let text = String::from_utf8(bytes(dd)).unwrap();
    for word in ["hour", "day", "time", "clock", "weekday", "tod"] {
        assert!(!text.contains(word), "{word}");
    }
}

#[test]
fn file_contains_no_pub_hex_no_tag_no_address() {
    let dir = dir();
    let dd = dir.path();
    let m = sample();
    save(dd, &ID, &m, NOW).unwrap();
    let plain = bytes(dd);
    let lower = String::from_utf8(plain.clone()).unwrap().to_lowercase();
    for person in [BOB, CAROL] {
        assert!(!lower.contains(&hex::encode(person)));
        assert!(!lower.contains(&hex::encode(&person[..8])));
        assert!(!contains(&plain, &person));
    }
    for needle in [
        NET.as_bytes(),
        b"192.168",
        b"home",
        b"wifi",
        RELAY,
        b"12D3KooW",
        hex::encode(RELAY).as_bytes(),
    ] {
        assert!(
            !contains(lower.as_bytes(), &needle.to_ascii_lowercase()),
            "{}",
            String::from_utf8_lossy(needle)
        );
    }
}

#[test]
fn delete_under_lock() {
    let dir = dir();
    let dd = dir.path();
    save(dd, &ID, &sample(), NOW).unwrap();
    {
        // Another writer holds the lock: nothing is read, written or removed.
        let _held = DataDirLock::acquire(dd, LEARNING_LOCK).unwrap();
        assert!(delete(dd).is_err());
        assert!(path(dd).exists());
        assert_eq!(load(dd, &ID, NOW).1, StoreState::MemoryOnly("io"));
    }
    delete(dd).unwrap();
    assert!(!path(dd).exists());
    // No file is not an error.
    delete(dd).unwrap();
    assert_eq!(load(dd, &ID, NOW).1, StoreState::On);
}

#[test]
fn windows_and_unix_paths_compile() {
    let dir = dir();
    let dd = dir.path();
    assert_eq!(path(dd), dd.join("learning.bin"));
    assert_eq!(LEARNING_FILE, "learning.bin");
    save(dd, &ID, &sample(), NOW).unwrap();
    let meta = std::fs::symlink_metadata(path(dd)).unwrap();
    assert!(acceptable(&meta));
    assert!(same_file(&meta, &std::fs::metadata(path(dd)).unwrap()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
    #[cfg(windows)]
    assert!(!meta.file_type().is_symlink());
}

#[test]
fn store_state_names_the_explain_state() {
    for (s, want) in [
        (StoreState::On, State::On),
        (StoreState::MemoryOnly("keystore"), State::MemoryOnly),
        (
            StoreState::ResetAfterUnreadable,
            State::ResetAfterUnreadable,
        ),
        (StoreState::Shadow, State::Shadow),
    ] {
        assert_eq!(s.state(), want);
    }
    // Every at-rest failure has its place.
    let map = SealError::from;
    assert_eq!(
        map(AtRestError::KeyUnavailable("x".into())),
        SealError::Unavailable
    );
    assert_eq!(
        map(AtRestError::KeyLost("x".into())),
        SealError::Unavailable
    );
    assert_eq!(map(AtRestError::NoIdentity), SealError::Unavailable);
    assert_eq!(map(AtRestError::NotSealedMode), SealError::Unavailable);
    assert_eq!(
        map(AtRestError::StaleKeys { epoch: 2 }),
        SealError::Unavailable
    );
    assert_eq!(
        map(AtRestError::Tampered { kind: 22 }),
        SealError::AuthFailed
    );
    assert_eq!(
        map(AtRestError::WrongKind { want: 22, got: 1 }),
        SealError::AuthFailed
    );
    assert_eq!(map(AtRestError::Truncated), SealError::Corrupt);
    assert_eq!(map(AtRestError::NewerFormat(2)), SealError::Newer);
    assert_eq!(
        map(AtRestError::Io("disk".into())),
        SealError::Other("disk".into())
    );
}

// ── The real sealer (RMS1 kind 22 under K_meta) ──

#[test]
fn platform_sealer_round_trip_in_a_sealed_profile() {
    let dir = sealed_profile();
    let dd = dir.path();
    let m = sample();
    save(dd, &PlatformSealer, &m, NOW).unwrap();
    let raw = bytes(dd);
    assert!(at_rest::is_sealed_as(Kind::LearningStore, &raw));
    assert_eq!(raw[5], 22);
    assert!(!contains(&raw, MAGIC));
    assert!(!contains(&raw, hex::encode([7u8; 32]).as_bytes()));
    let (loaded, state) = load(dd, &PlatformSealer, NOW);
    assert_eq!(state, StoreState::On);
    assert_round_tripped(&loaded, &m);
    // The registry knows it: its writer lock, and the rotation's re-seal.
    assert!(at_rest::lock_file(dd, &path(dd), Kind::LearningStore).is_ok());
    assert_eq!(
        at_rest::reseal_file(dd, &path(dd), Kind::LearningStore).unwrap(),
        at_rest::Resealed::Current
    );
    // A changed byte, and a sealed file of another kind: reset, and the
    // next save writes a file that opens.
    for raw in [
        {
            let mut changed = raw.clone();
            *changed.last_mut().unwrap() ^= 1;
            changed
        },
        at_rest::seal(
            &at_rest::keys_cached(dd).unwrap(),
            Kind::Contacts,
            &encode(&m, NOW).unwrap(),
        ),
    ] {
        put(dd, &raw);
        let (fresh, state) = load(dd, &PlatformSealer, NOW);
        assert_eq!(state, StoreState::ResetAfterUnreadable);
        save(dd, &PlatformSealer, &fresh, NOW).unwrap();
        assert_eq!(load(dd, &PlatformSealer, NOW).1, StoreState::On);
    }
    // A newer RMS1 format: memory-only, never overwritten.
    let mut newer = raw.clone();
    newer[4] = 2;
    put(dd, &newer);
    let (m2, state) = load(dd, &PlatformSealer, NOW);
    assert_eq!(state, StoreState::MemoryOnly("newer"));
    assert!(save(dd, &PlatformSealer, &m2, NOW).is_err());
    assert_eq!(bytes(dd), newer);
    // The keys gone from this process: memory-only, file untouched.
    put(dd, &raw);
    at_rest::forget_cached_keys(dd);
    let (m3, state) = load(dd, &PlatformSealer, NOW);
    assert_eq!(state, StoreState::MemoryOnly("keystore"));
    assert!(save(dd, &PlatformSealer, &m, NOW).is_err());
    assert!(save(dd, &PlatformSealer, &m3, NOW).is_err());
    assert_eq!(bytes(dd), raw);
}

#[test]
fn platform_sealer_never_writes_in_a_plain_profile() {
    let dir = crate::contact_book::tests::profile();
    let dd = dir.path();
    assert_eq!(crate::privacy::mode(dd), Mode::Plain);
    // No file: memory-only at once, and a save writes nothing.
    let (m, state) = load(dd, &PlatformSealer, NOW);
    assert_eq!(state, StoreState::MemoryOnly("keystore"));
    assert!(save(dd, &PlatformSealer, &sample(), NOW).is_err());
    assert!(save(dd, &PlatformSealer, &m, NOW).is_err());
    assert!(!path(dd).exists());
    // A plaintext left by `raven privacy unseal`: never read, never written.
    save(dd, &ID, &sample(), NOW).unwrap();
    let before = bytes(dd);
    assert_eq!(
        load(dd, &PlatformSealer, NOW).1,
        StoreState::MemoryOnly("keystore")
    );
    assert_eq!(bytes(dd), before);
}

#[test]
fn lab_fault_makes_the_platform_sealer_unavailable() {
    let dir = sealed_profile();
    let dd = dir.path();
    assert!(PlatformSealer::keys(dd, false).is_ok());
    assert_eq!(
        PlatformSealer::keys(dd, true).err(),
        Some(SealError::Unavailable)
    );
}
