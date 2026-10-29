//! PP.4 tests of the at-rest loader: the backoff and the Status retry, the
//! hold while the key loads, the key-fault switch, `Status.at_rest`. The
//! profiles here are temp folders sealed with the debug lab K_hist
//! (`RAVEN_CHAT_HISTORY_BACKEND=locked-file`): never a keychain item; the
//! tests skip without it.

use super::*;
use raven_core::outbox::{contact_admission, ContactAdmission};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Every raven-node test that loads an at-rest key takes this: one of them
/// sets `RAVEN_LAB_AT_REST_KEY_FAULT`, which every key load in the process
/// reads.
pub(crate) fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The lab K_hist is what a key load gets here: a debug build with the
/// locked-file backend. Without it a key load would ask the real keystore,
/// so the tests that seal skip.
pub(crate) fn lab_hist_key() -> bool {
    let lab = ["RAVEN_CHAT_HISTORY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
        .iter()
        .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
    // Windows: the key is DPAPI-wrapped for this user, never a prompt.
    if !(cfg!(windows) || (cfg!(debug_assertions) && lab)) {
        eprintln!("skipped: needs a debug build and RAVEN_CHAT_HISTORY_BACKEND=locked-file");
        return false;
    }
    true
}

/// A temp profile with an identity on record (its backend marker only) and
/// `contacts` as its plain book.
pub(crate) fn profile_with(contacts: &[[u8; 32]]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(raven_core::BACKEND_MARKER_NAME),
        b"locked-file\n",
    )
    .unwrap();
    write_book(dir.path(), contacts);
    dir
}

/// The book (through its writer: sealed in a sealed profile).
pub(crate) fn write_book(dd: &Path, contacts: &[[u8; 32]]) {
    let rows: Vec<serde_json::Value> = contacts
        .iter()
        .map(|k| {
            serde_json::json!({
                "petname": "friend",
                "address": raven_core::encode_address(k),
                "pub_hex": hex::encode(k),
                "pinned": true,
            })
        })
        .collect();
    contact_book::write_rows(dd, &rows).unwrap();
}

/// Seal `dd` as a node of this build would at its start.
pub(crate) fn seal(dd: &Path) {
    let report = privacy::migrate_all(dd, crate::now_ms(), MigratePolicy::Allow).unwrap();
    assert_eq!(report.outcome, MigrateOutcome::Sealed);
}

const FAST: Timing = Timing {
    retry: [
        Duration::from_millis(150),
        Duration::from_millis(300),
        Duration::from_millis(600),
        Duration::from_millis(1200),
        Duration::from_millis(2400),
        Duration::from_millis(4800),
    ],
    status_retry: Duration::from_millis(100),
    space_retry: Duration::from_secs(3600),
};

fn phase_of(dd: &Path) -> Option<Phase> {
    boots().get(dd).map(|b| b.phase)
}

/// Wait (bounded) until `dd`'s loader settles in `want`.
fn wait_phase(dd: &Path, want: Phase) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while phase_of(dd) != Some(want) || boots().get(dd).is_some_and(|b| b.trying) {
        assert!(
            Instant::now() < deadline,
            "phase {:?}, wanted {want:?}",
            phase_of(dd)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn admitted(dd: &Path, key: &[u8; 32]) -> bool {
    matches!(contact_admission(dd, key), ContactAdmission::Allowed(_))
}

/// The loader at `dd`'s start (a plain profile this build seals) waiting for
/// the keychain dialog nobody answered yet: the book is held, and the key
/// load runs ([`key_loading`]) until the returned sender sends (or drops);
/// then the book opens. Other modules' tests of a book held at start or
/// after an Unlock (E1).
pub(crate) fn key_loading_until_answered(dd: &Path) -> std::sync::mpsc::Sender<()> {
    let (answer, keychain) = std::sync::mpsc::channel::<()>();
    start_with(dd, MigratePolicy::Allow, FAST, move |_: &Path| {
        let _ = keychain.recv();
        Ok(MigrateReport {
            outcome: MigrateOutcome::NotAllowed,
            sealed: 0,
            leftovers: 0,
        })
    });
    assert!(contact_book::is_held(dd) && key_loading(dd));
    answer
}

/// [`key_loading_until_answered`] answered: wait (bounded) for its book to
/// open.
pub(crate) fn answered(dd: &Path, answer: std::sync::mpsc::Sender<()>) {
    let _ = answer.send(());
    wait_phase(dd, Phase::Plain);
    assert!(!contact_book::is_held(dd) && !key_loading(dd));
}

#[test]
fn backoff_steps_cap_at_fifteen_minutes() {
    let t = Timing::REAL;
    let secs: Vec<u64> = (1..=9).map(|n| t.backoff(n).as_secs()).collect();
    assert_eq!(secs, [30, 60, 120, 240, 480, 900, 900, 900, 900]);
    assert_eq!(t.backoff(0), Duration::from_secs(30));
    assert_eq!(t.status_retry, Duration::from_secs(30));
}

/// Review R14: failed tries back off (30 s, 1, 2, 4, 8, 15 min in
/// production; scaled down here); the user's Status (`raven status`) while
/// the key is unavailable and the last try ended 30 s ago or more asks for
/// one try at once, and only one try is ever outstanding.
#[test]
fn keychain_retry_backs_off_and_status_triggers_one_retry() {
    let dir = profile_with(&[]);
    let dd = dir.path().to_path_buf();
    let tries = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let running = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let attempt = {
        let (tries, running, most) = (tries.clone(), running.clone(), most.clone());
        move |_: &Path| -> Result<MigrateReport, AtRestError> {
            let now_running = running.fetch_add(1, Ordering::SeqCst) + 1;
            most.fetch_max(now_running, Ordering::SeqCst);
            tries.lock().unwrap().push(Instant::now());
            std::thread::sleep(Duration::from_millis(20));
            running.fetch_sub(1, Ordering::SeqCst);
            Err(AtRestError::KeyUnavailable(
                "the test's keystore says no".into(),
            ))
        }
    };
    start_with(&dd, MigratePolicy::Allow, FAST, attempt);
    // Four tries: at once, then after 150, 300 and 600 ms.
    let deadline = Instant::now() + Duration::from_secs(10);
    while tries.lock().unwrap().len() < 4 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let gaps: Vec<Duration> = tries
        .lock()
        .unwrap()
        .windows(2)
        .map(|w| w[1] - w[0])
        .collect();
    for (gap, step) in gaps.iter().zip(FAST.retry) {
        assert!(*gap >= step, "{gaps:?}");
    }
    assert!(gaps[2] > gaps[0], "the waits grow: {gaps:?}");
    // Waiting out the next step (1200 ms): a Status asks for a try now.
    wait_phase(&dd, Phase::KeyUnavailable);
    std::thread::sleep(FAST.status_retry + Duration::from_millis(20));
    let before = tries.lock().unwrap().len();
    let asked_at = Instant::now();
    assert_eq!(status(&dd, true).state, privacy::STATE_KEY_UNAVAILABLE);
    // A burst of Status requests asks for that one try only.
    for _ in 0..20 {
        let _ = status(&dd, true);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while tries.lock().unwrap().len() == before {
        assert!(
            Instant::now() < deadline,
            "the Status did not ask for a try"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        tries.lock().unwrap()[before] - asked_at < Duration::from_millis(500),
        "the try came at once"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(tries.lock().unwrap().len(), before + 1, "one try per ask");
    assert_eq!(most.load(Ordering::SeqCst), 1, "at most one try at a time");
    // The book stays held throughout.
    assert!(contact_book::read_plain(&dd).unwrap_err().is_locked());
}

/// Review B-sealed-stores-6: the terminal app asks for a Status every 2 s
/// (here every 10 ms, against FAST's 100 ms `status_retry`); that poll never
/// asks for a try, so the tries keep their backoff while the app is open
/// (it used to start one 30 s after each try began: a keychain dialog every
/// 30 s). The user's `raven status` still asks for exactly one try at once.
#[test]
fn the_apps_status_poll_keeps_the_backoff() {
    let dir = profile_with(&[]);
    let dd = dir.path().to_path_buf();
    let tries = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let attempt = {
        let tries = tries.clone();
        move |_: &Path| -> Result<MigrateReport, AtRestError> {
            tries.lock().unwrap().push(Instant::now());
            std::thread::sleep(Duration::from_millis(20));
            Err(AtRestError::KeyUnavailable("the user pressed Deny".into()))
        }
    };
    start_with(&dd, MigratePolicy::Allow, FAST, attempt);
    let polled_until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < polled_until {
        let _ = status(&dd, false);
        std::thread::sleep(Duration::from_millis(10));
    }
    let gaps: Vec<Duration> = tries
        .lock()
        .unwrap()
        .windows(2)
        .map(|w| w[1] - w[0])
        .collect();
    // The backoff alone: at once, then 150, 300 and 600 ms later (the next,
    // 1200 ms later, is past the 2 s); a load can only make them later.
    assert!(gaps.len() <= 3, "the poll started tries: gaps {gaps:?}");
    for (gap, step) in gaps.iter().zip(FAST.retry) {
        assert!(*gap >= step, "{gaps:?}");
    }
    // `raven status`: one try at once.
    wait_phase(&dd, Phase::KeyUnavailable);
    let before = tries.lock().unwrap().len();
    let asked_at = Instant::now();
    let _ = status(&dd, true);
    let deadline = Instant::now() + Duration::from_secs(5);
    while tries.lock().unwrap().len() == before {
        assert!(Instant::now() < deadline, "raven status did not ask");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        tries.lock().unwrap()[before] - asked_at < Duration::from_millis(500),
        "the try came at once"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(tries.lock().unwrap().len(), before + 1, "one try per ask");
}

/// Review B-sealed-stores-6: a slow answer (a keychain dialog left open
/// longer than `status_retry`, then Deny) counts from its end: `raven
/// status` right after it starts no try at once (it used to: the last try
/// had *started* long enough ago), the next one comes later.
#[test]
fn a_slow_answer_counts_from_its_end() {
    let timing = Timing {
        status_retry: Duration::from_millis(1000),
        retry: [Duration::from_millis(1500); 6],
        ..FAST
    };
    let dir = profile_with(&[]);
    let dd = dir.path().to_path_buf();
    // (start, end) of each try.
    let tries = Arc::new(Mutex::new(Vec::<(Instant, Instant)>::new()));
    let attempt = {
        let tries = tries.clone();
        move |_: &Path| -> Result<MigrateReport, AtRestError> {
            let started = Instant::now();
            std::thread::sleep(Duration::from_millis(1200));
            tries.lock().unwrap().push((started, Instant::now()));
            Err(AtRestError::KeyUnavailable("the user pressed Deny".into()))
        }
    };
    start_with(&dd, MigratePolicy::Allow, timing, attempt);
    wait_phase(&dd, Phase::KeyUnavailable);
    let _ = status(&dd, true);
    let deadline = Instant::now() + Duration::from_secs(10);
    while tries.lock().unwrap().len() < 2 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    let tries = tries.lock().unwrap();
    let after_end = tries[1].0 - tries[0].1;
    assert!(
        after_end >= timing.status_retry,
        "the next try came {after_end:?} after the slow one ended"
    );
}

/// Review R14: the listeners start at once while the key loads (the start
/// returns before the keystore answers) and admit nobody until it is here.
#[test]
fn listeners_start_while_waiting_for_keychain() {
    let bob = [0xb0; 32];
    let dir = profile_with(&[bob]);
    let dd = dir.path().to_path_buf();
    assert!(
        admitted(&dd, &bob),
        "the control: a contact before the start"
    );
    let (answer, keychain) = std::sync::mpsc::channel::<()>();
    let attempt = move |_: &Path| -> Result<MigrateReport, AtRestError> {
        // The keychain dialog: nobody has answered it yet.
        let _ = keychain.recv();
        Ok(MigrateReport {
            outcome: MigrateOutcome::NotAllowed,
            sealed: 0,
            leftovers: 0,
        })
    };
    let started = Instant::now();
    start_with(&dd, MigratePolicy::Allow, FAST, attempt);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "start waited"
    );
    assert_eq!(
        status(&dd, false).state,
        privacy::STATE_WAITING_FOR_KEYCHAIN
    );
    assert!(!admitted(&dd, &bob), "admitted while the key loads");
    assert!(key_loading(&dd), "a link waits for it a moment (E1)");
    assert_eq!(contact_admission(&dd, &bob), ContactAdmission::Unreadable);
    // Not a stranger's refusal: the held book judges nobody (E1).
    assert_eq!(
        raven_core::lan_dispatch::link_admission(
            &dd,
            &bob,
            raven_core::outbox::OutboxCarrier::Lan,
            None
        ),
        Err(raven_core::lan_dispatch::LINK_REFUSED_NOT_READY)
    );
    answer.send(()).unwrap();
    wait_phase(&dd, Phase::Plain);
    assert!(admitted(&dd, &bob));
    assert!(!key_loading(&dd));
}

/// Review A-keys-format-4: a key that is gone from the keystore while the
/// key file is there (`KeyLost`) is `key_lost`, not `key_unavailable`: no
/// dialog is waiting, so the loader tries again only at the slowest step
/// (here 4.8 s) and when the user's `raven status` asks. It admits nobody
/// meanwhile, and a key put back is loaded on the next try.
#[test]
fn a_lost_key_is_key_lost_and_tried_again_only_slowly() {
    let bob = [0xb2; 32];
    let dir = profile_with(&[bob]);
    let dd = dir.path().to_path_buf();
    let tries = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let back = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let attempt = {
        let (tries, back) = (tries.clone(), back.clone());
        move |_: &Path| -> Result<MigrateReport, AtRestError> {
            tries.lock().unwrap().push(Instant::now());
            if back.load(Ordering::SeqCst) {
                return Ok(MigrateReport {
                    outcome: MigrateOutcome::NotAllowed,
                    sealed: 0,
                    leftovers: 0,
                });
            }
            Err(AtRestError::KeyLost(
                "protected chat-history key is missing".into(),
            ))
        }
    };
    start_with(&dd, MigratePolicy::Allow, FAST, attempt);
    wait_phase(&dd, Phase::KeyLost);
    assert_eq!(status(&dd, false).state, privacy::STATE_KEY_LOST);
    assert!(!admitted(&dd, &bob));
    assert!(contact_book::read_plain(&dd).unwrap_err().is_locked());
    // The backoff of an unavailable key would have tried again after 150
    // and 300 ms; a lost one waits for the slowest step.
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(tries.lock().unwrap().len(), 1, "tried again before 4.8 s");
    // `raven status` asks: one try at once (long before the slow step).
    let asked_at = Instant::now();
    let _ = status(&dd, true);
    let deadline = asked_at + Duration::from_secs(3);
    while tries.lock().unwrap().len() < 2 {
        assert!(Instant::now() < deadline, "raven status did not ask");
        std::thread::sleep(Duration::from_millis(2));
    }
    wait_phase(&dd, Phase::KeyLost);
    // The key is put back: the next try (asked for again) loads it.
    back.store(true, Ordering::SeqCst);
    std::thread::sleep(FAST.status_retry + Duration::from_millis(20));
    let _ = status(&dd, true);
    wait_phase(&dd, Phase::Plain);
    assert!(admitted(&dd, &bob));
    assert_eq!(tries.lock().unwrap().len(), 3);
}

/// The lab switch `RAVEN_LAB_AT_REST_KEY_FAULT=unavailable` makes the
/// keystore fail: a sealed profile's node admits nobody and says so, and
/// recovers on the next try once the switch is cleared.
#[test]
fn key_unavailable_admits_nobody_reports_and_recovers() {
    if !lab_hist_key() {
        return;
    }
    let _serial = serial();
    let bob = [0xb1; 32];
    let dir = profile_with(&[bob]);
    let dd = dir.path().to_path_buf();
    seal(&dd);
    // A fresh node: nothing loaded yet in its process.
    raven_core::at_rest::forget_cached_keys(&dd);
    std::env::set_var(raven_core::lan_gate::LAB_AT_REST_KEY_FAULT, "unavailable");
    start_with(&dd, MigratePolicy::Allow, FAST, |dd: &Path| {
        privacy::migrate_all(dd, crate::now_ms(), MigratePolicy::Allow)
    });
    wait_phase(&dd, Phase::KeyUnavailable);
    let st = status(&dd, false);
    assert_eq!(
        (st.state.as_str(), st.sealed_files),
        (privacy::STATE_KEY_UNAVAILABLE, 1)
    );
    assert!(!admitted(&dd, &bob));
    assert!(contact_book::read_plain(&dd).unwrap_err().is_locked());
    // Still unavailable on the next try.
    std::thread::sleep(FAST.retry[0] + Duration::from_millis(50));
    wait_phase(&dd, Phase::KeyUnavailable);
    assert!(!admitted(&dd, &bob));
    // The keystore answers again: `raven status` asks, the next try loads it.
    std::env::remove_var(raven_core::lan_gate::LAB_AT_REST_KEY_FAULT);
    std::thread::sleep(FAST.status_retry);
    let _ = status(&dd, true);
    wait_phase(&dd, Phase::Sealed);
    assert_eq!(status(&dd, false).state, privacy::STATE_SEALED);
    assert!(admitted(&dd, &bob));
}

/// `Status.at_rest` both ways through the codec; an older daemon's Status
/// (no `at_rest`) still decodes, and is what ash takes for an older node.
#[test]
fn status_at_rest_round_trip_and_old_json() {
    use raven_core::ipc::{decode_response, encode_response, IpcResponse};
    let view = raven_core::ipc::AtRestStatus {
        state: privacy::STATE_KEY_UNAVAILABLE.into(),
        sealed_files: 1,
        plain_files: 0,
        notes: vec![privacy::NOTE_OLDER_BUILD_WROTE_PLAIN.into()],
    };
    let response = IpcResponse::Status {
        v: 1,
        bridge: false,
        store: false,
        relay: false,
        forward_pending: 0,
        capabilities: vec!["ipc".into()],
        p2p: None,
        pid: Some(7),
        lan_listen: None,
        last_paths: Vec::new(),
        route_hints: None,
        unreachable: Vec::new(),
        egress: None,
        lan_listen_wanted: None,
        lan_bind_error: None,
        clock_skew: Vec::new(),
        unanswered: Vec::new(),
        at_rest: Some(view.clone()),
        lan: None,
        security: None,
        nearby: None,
        tor: None,
        learning: None,
        locked: None,
        updates: None,
    };
    let frame = encode_response(&response).unwrap();
    let back = decode_response(&frame).unwrap();
    assert_eq!(back, response);
    let json = serde_json::to_string(&response).unwrap();
    assert!(
        json.contains(
            r#""at_rest":{"state":"key_unavailable","sealed_files":1,"plain_files":0,"notes":["older_build_wrote_plain"]}"#
        ),
        "{json}"
    );
    assert!(!privacy::node_is_older(&back));
    // An older daemon's Status: no at_rest.
    let old: IpcResponse = serde_json::from_str(
        r#"{"ok":"status","v":1,"bridge":true,"store":false,"relay":false,"forward_pending":0,"capabilities":["ipc"],"pid":9}"#,
    )
    .unwrap();
    let IpcResponse::Status { at_rest, .. } = &old else {
        panic!("{old:?}");
    };
    assert_eq!(*at_rest, None);
    assert!(privacy::node_is_older(&old));
    // A newer one's extra fields inside at_rest are ignored.
    let newer: IpcResponse = serde_json::from_str(
        r#"{"ok":"status","v":1,"bridge":true,"store":false,"relay":false,"forward_pending":0,"capabilities":["ipc"],"at_rest":{"state":"sealed","sealed_files":3,"plain_files":0,"rotation_day":12}}"#,
    )
    .unwrap();
    let IpcResponse::Status { at_rest, .. } = &newer else {
        panic!("{newer:?}");
    };
    assert_eq!(at_rest.as_ref().map(|a| a.sealed_files), Some(3));
    // No loader in this process (`raven-node ipc` before its start, a test):
    // the state the profile's files say.
    let dir = profile_with(&[]);
    assert_eq!(status(dir.path(), false).state, privacy::STATE_PLAIN);
}
