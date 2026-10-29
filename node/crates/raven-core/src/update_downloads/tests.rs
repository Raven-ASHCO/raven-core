//! The download rows (step P6.49): offers, approvals, bounds, the file and
//! the lab auto-approval's switch.

use super::*;

const T0: u64 = 1_792_800_000_000;

fn offer(serial: u64, digest_byte: u8) -> Offer {
    Offer {
        build_serial: serial,
        target: THIS_TARGET.to_owned(),
        manifest_digest: [digest_byte; 32],
        payload_len: 34_000_000,
    }
}

/// The mesh update gate (and what it sits on) open for this thread.
struct Gates;

impl Gates {
    fn open() -> Gates {
        for g in [
            SecGate::Advisory,
            SecGate::ReleaseBundle,
            SecGate::MeshUpdate,
        ] {
            security_gate::set_lab_for_this_thread(g, Some(true));
        }
        Gates
    }
}

impl Drop for Gates {
    fn drop(&mut self) {
        for g in [
            SecGate::Advisory,
            SecGate::ReleaseBundle,
            SecGate::MeshUpdate,
        ] {
            security_gate::set_lab_for_this_thread(g, None);
        }
    }
}

/// The person approves on this thread (the lab auto-approval off, whatever
/// the variables say); back to the variables when dropped.
struct Manual;

impl Manual {
    fn set() -> Manual {
        set_lab_auto_approve_for_this_thread(Some(false));
        Manual
    }
}

impl Drop for Manual {
    fn drop(&mut self) {
        set_lab_auto_approve_for_this_thread(None);
    }
}

#[test]
fn an_offer_for_this_computer_is_newer_and_for_its_target() {
    assert!(for_this_computer(&offer(5, 1), 4));
    assert!(!for_this_computer(&offer(4, 1), 4), "not newer");
    let mut other = offer(9, 1);
    other.target = if THIS_TARGET == "x86_64-pc-windows-msvc" {
        "aarch64-apple-darwin".into()
    } else {
        "x86_64-pc-windows-msvc".into()
    };
    assert!(!for_this_computer(&other, 0), "another platform's");
}

#[test]
fn offers_become_rows_and_friends_join_them() {
    let _manual = Manual::set();
    let (sara, rena) = ([0x5A; 32], [0x7E; 32]);
    let mut rows = Downloads::default();
    assert!(rows.note_offer(&sara, &offer(5, 1), T0));
    assert_eq!(rows.rows.len(), 1);
    let row = &rows.rows[0];
    assert_eq!(row.state, RowState::Offered, "nothing is fetched unasked");
    assert_eq!((row.build_serial, row.from.clone()), (5, vec![sara]));
    // The same friend again the same day: nothing to write.
    assert!(!rows.note_offer(&sara, &offer(5, 1), T0 + 60_000));
    // Another friend offering the same release goes first.
    assert!(rows.note_offer(&rena, &offer(5, 1), T0 + 120_000));
    assert_eq!(rows.rows[0].from, vec![rena, sara]);
    assert_eq!(rows.rows[0].offered_by(), Some(&rena));
    // A day later the sighting counts again.
    assert!(rows.note_offer(&rena, &offer(5, 1), T0 + DAY_MS));
    for i in 0..20u8 {
        rows.note_offer(&[i; 32], &offer(5, 1), T0 + DAY_MS);
    }
    assert_eq!(rows.rows[0].from.len(), MAX_FROM);
}

#[test]
fn approving_takes_a_unique_prefix_once() {
    let _manual = Manual::set();
    let mut rows = Downloads::default();
    rows.note_offer(&[1; 32], &offer(5, 0xAB), T0);
    rows.note_offer(&[1; 32], &offer(6, 0xAC), T0);
    assert_eq!(rows.approve("a", T0), Err(ApproveError::Ambiguous));
    assert_eq!(rows.approve("ff", T0), Err(ApproveError::Unknown));
    assert_eq!(rows.approve("", T0), Err(ApproveError::Unknown));
    let row = rows.approve("ABAB", T0 + 5).unwrap().clone();
    assert_eq!(
        (row.state, row.approved_ms),
        (RowState::Approved, Some(T0 + 5))
    );
    assert!(row.wanted());
    assert_eq!(
        rows.approve(&hex::encode([0xAB; 32]), T0),
        Err(ApproveError::Already(RowState::Approved))
    );
    // A failed download can be approved again.
    let failed = rows.row_mut(&[0xAC; 32]).unwrap();
    failed.state = RowState::Failed;
    failed.failed = Some("BAD_CHUNK_ROOT".into());
    let again = rows.approve("ac", T0).unwrap();
    assert_eq!(
        (again.state, again.failed.clone()),
        (RowState::Approved, None)
    );
}

#[test]
fn rows_are_bounded_and_forgotten_once_installed() {
    let _manual = Manual::set();
    let mut rows = Downloads::default();
    rows.note_offer(&[1; 32], &offer(5, 0), T0);
    rows.approve(&hex::encode([0; 32]), T0).unwrap();
    for i in 1..=(MAX_ROWS as u8 + 3) {
        rows.note_offer(&[1; 32], &offer(5 + u64::from(i), i), T0 + u64::from(i));
    }
    assert_eq!(rows.rows.len(), MAX_ROWS);
    assert!(
        rows.row(&[0; 32]).is_some(),
        "an approved row outlives offers not approved"
    );
    assert!(rows.row(&[1; 32]).is_none(), "the oldest offer went first");
    // Build 10 installed: offers up to it go, a complete one stays (it is
    // served to friends while its folder lasts).
    assert!(rows.row(&[4; 32]).is_none(), "the four oldest offers went");
    rows.row_mut(&[5; 32]).unwrap().state = RowState::Complete;
    assert!(rows.forget_installed(10));
    assert!(rows
        .rows
        .iter()
        .all(|r| r.build_serial > 10 || r.digest == [5; 32]));
    assert!(!rows.forget_installed(10));
}

#[test]
fn the_bitmap_counts_chunks_from_the_high_bit() {
    let mut bitmap = vec![0u8; bitmap_len(1_093)];
    assert_eq!(bitmap.len(), 137);
    for i in [0, 7, 8, 1_092] {
        assert!(!chunk_written(&bitmap, i));
        mark_chunk(&mut bitmap, i);
        assert!(chunk_written(&bitmap, i));
    }
    assert_eq!(bitmap[0], 0x81);
    assert_eq!(bitmap[1], 0x80);
    assert_eq!(bitmap[136], 0x08);
    // Past the end: never written, and marking it changes nothing.
    assert!(!chunk_written(&bitmap, 2_000));
    mark_chunk(&mut bitmap, 2_000);
    assert_eq!(bitmap.iter().map(|b| b.count_ones()).sum::<u32>(), 4);
    assert_eq!(bitmap_len(0), 0);
    assert_eq!(bitmap_len(8), 1);
    assert_eq!(bitmap_len(9), 2);
}

#[test]
fn the_file_round_trips_under_the_gate_and_is_shut_without_it() {
    let _manual = Manual::set();
    // Shut for this thread whatever the variables say (`Gates::open` opens
    // it below, and its drop goes back to the variables).
    security_gate::set_lab_for_this_thread(SecGate::MeshUpdate, Some(false));
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        load(dir.path()).unwrap(),
        Downloads::default(),
        "gate shut: empty"
    );
    assert!(change(dir.path(), |_| ()).is_err(), "gate shut: no write");
    let _gates = Gates::open();
    if !security_gate::live(SecGate::MeshUpdate) {
        return; // a release build: the overrides are ignored
    }
    assert_eq!(load(dir.path()).unwrap(), Downloads::default());
    let sara = [0x5A; 32];
    assert!(change(dir.path(), |rows| rows.note_offer(&sara, &offer(5, 9), T0)).unwrap());
    // A plain profile: plain JSON (a sealed one seals it, kind 120).
    let raw = std::fs::read_to_string(dir.path().join(DOWNLOADS_FILE)).unwrap();
    assert!(raw.contains(&hex::encode([9u8; 32])) && raw.contains("\"offered\""));
    let row = approve(dir.path(), "0909", T0 + 1).unwrap().unwrap();
    assert_eq!(row.state, RowState::Approved);
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded.v, DOWNLOADS_VERSION);
    assert_eq!(loaded.rows, vec![row]);
    // Nothing changed: nothing written.
    let before = std::fs::metadata(dir.path().join(DOWNLOADS_FILE))
        .unwrap()
        .modified()
        .unwrap();
    change(dir.path(), |rows| rows.rows.len()).unwrap();
    let after = std::fs::metadata(dir.path().join(DOWNLOADS_FILE))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(before, after);
    // A later format is refused, never written over.
    std::fs::write(dir.path().join(DOWNLOADS_FILE), br#"{"v":99,"rows":[]}"#).unwrap();
    assert!(load(dir.path()).is_err());
    assert!(change(dir.path(), |rows| rows.rows.clear()).is_err());
    assert_eq!(
        incoming_dir(dir.path(), &[0xAB; 32]),
        dir.path().join(INCOMING_DIR).join("ab".repeat(32))
    );
}

/// Phase 6 review updates-protocol-8: a friend's offer seen again on the
/// same day (every link with it) leaves the file as it is; a new friend or
/// a new day writes it.
#[test]
fn an_offer_seen_again_the_same_day_writes_nothing() {
    let _manual = Manual::set();
    let _gates = Gates::open();
    if !security_gate::live(SecGate::MeshUpdate) {
        return; // a release build: the overrides are ignored
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(DOWNLOADS_FILE);
    let (sara, rena) = ([0x5A; 32], [0x7E; 32]);
    assert!(change(dir.path(), |rows| rows.note_offer(&sara, &offer(5, 9), T0)).unwrap());
    let first = std::fs::read(&file).unwrap();
    for later in [60_000, 3_600_000] {
        let wrote = change(dir.path(), |rows| {
            rows.note_offer(&sara, &offer(5, 9), T0 + later)
        });
        assert_eq!(wrote, Ok(false));
        assert_eq!(std::fs::read(&file).unwrap(), first, "{later} ms later");
    }
    assert_eq!(load(dir.path()).unwrap().rows[0].last_seen_ms, T0);
    // Another friend, or the next day: written.
    assert!(change(dir.path(), |rows| rows.note_offer(
        &rena,
        &offer(5, 9),
        T0 + 7
    ))
    .unwrap());
    assert_ne!(std::fs::read(&file).unwrap(), first);
    let row = load(dir.path()).unwrap().rows[0].clone();
    assert_eq!((row.from, row.last_seen_ms), (vec![rena, sara], T0 + 7));
    assert!(change(dir.path(), |rows| rows.note_offer(
        &rena,
        &offer(5, 9),
        T0 + DAY_MS
    ))
    .unwrap());
    assert_eq!(load(dir.path()).unwrap().rows[0].last_seen_ms, T0 + DAY_MS);
}

/// Runs in both builds: the release test job sets Lab Test A and the
/// switch, and a release build still never approves anything by itself.
#[test]
fn auto_approve_is_inert_without_debug_assertions() {
    assert!(!lab_auto_approve_from(
        false,
        || panic!("read"),
        || panic!("read")
    ));
    assert!(!lab_auto_approve_from(true, || false, || Some("1".into())));
    assert!(!lab_auto_approve_from(true, || true, || Some("yes".into())));
    assert!(lab_auto_approve_from(true, || true, || Some("1".into())));
    if !cfg!(debug_assertions) {
        // Edition 2021: plain calls. No other release test reads these.
        std::env::set_var("RAVEN_LAB_TEST_A", "1");
        std::env::set_var(LAB_UPDATE_AUTO_APPROVE, "1");
        set_lab_auto_approve_for_this_thread(Some(true));
        assert!(!lab_auto_approve());
        let mut rows = Downloads::default();
        rows.note_offer(&[1; 32], &offer(5, 1), T0);
        assert_eq!(rows.rows[0].state, RowState::Offered);
        set_lab_auto_approve_for_this_thread(None);
        return;
    }
    // A debug build: this thread's override approves a new row at once.
    set_lab_auto_approve_for_this_thread(Some(true));
    let mut rows = Downloads::default();
    rows.note_offer(&[1; 32], &offer(5, 1), T0);
    assert_eq!(
        (rows.rows[0].state, rows.rows[0].approved_ms),
        (RowState::Approved, Some(T0))
    );
    set_lab_auto_approve_for_this_thread(Some(false));
    rows.note_offer(&[1; 32], &offer(6, 2), T0);
    assert_eq!(rows.rows[1].state, RowState::Offered);
    set_lab_auto_approve_for_this_thread(None);
}
