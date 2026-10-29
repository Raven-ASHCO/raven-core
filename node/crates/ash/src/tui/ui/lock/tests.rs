//! LOCKED, PASS, SET's lock rows and the idle lock (Lock now v2, P6.40):
//! what they draw, the jobs they ask for, and that nothing of them shows
//! while the local-protection gate is shut.

use std::time::Duration;

use crossterm::event::KeyCode;
use raven_core::security_gate::{set_lab_for_this_thread, SecGate};

use super::*;

/// The local-protection gate open on this thread while it lives.
struct Gate;

impl Gate {
    fn open() -> Gate {
        set_lab_for_this_thread(SecGate::LocalProtection, Some(true));
        Gate
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        set_lab_for_this_thread(SecGate::LocalProtection, None);
    }
}

/// raven-node 4242 answering Status, its lock `locked`.
fn node(app: &mut App, locked: Option<bool>) -> Vec<Cmd> {
    let mut probe = testkit::status(4242, "0.0.0.0:7420");
    probe.locked = locked;
    testkit::send(app, Msg::Poll(workers::PollUpdate::Status(probe)))
}

fn settings_read(app: &mut App, offer: bridge::PassOffer, sleep_lock: bool) -> Vec<Cmd> {
    testkit::send(
        app,
        Msg::Job(JobResult::LockSettings(LockSettingsView {
            offer,
            sleep_lock,
        })),
    )
}

fn typing(app: &mut App, text: &str) {
    for c in text.chars() {
        testkit::press(app, KeyCode::Char(c));
    }
}

fn node_jobs(cmds: &[Cmd]) -> Vec<NodeJob> {
    cmds.iter()
        .filter_map(|cmd| match cmd {
            Cmd::Node(job) => Some(job.clone()),
            _ => None,
        })
        .collect()
}

fn locked_view(app: &App) -> &LockedView {
    match app.overlays() {
        [Overlay::Locked(view), ..] => view,
        other => panic!("no LOCKED: {other:?}"),
    }
}

/// A profile with a Raven passphrase: LOCKED covers everything once the
/// node says it is locked; the passphrase shows as marks only, Enter sends
/// it (never in a Debug of the job), a wrong one is said, and the unlock
/// closes it with the node's words.
#[test]
fn locked_takes_the_passphrase_as_marks_and_unlocks() {
    let _gate = Gate::open();
    let mut app = testkit::settled_app((80, 24), Receive::On, 2);
    settings_read(&mut app, bridge::PassOffer::ChangeOrRemove, true);
    node(&mut app, Some(false));
    assert!(app.overlays().is_empty());
    node(&mut app, Some(true));
    assert!(locked_view(&app).passphrase);
    let text = testkit::render_text(&app);
    assert!(text.contains(bridge::LOCKED_SCREEN), "{text}");
    assert!(
        text.contains("Type your Raven passphrase to unlock: > _"),
        "{text}"
    );
    assert!(
        !text.contains("Friend 1"),
        "nothing of the profile shows: {text}"
    );
    typing(&mut app, "hunter22");
    let text = testkit::render_text(&app);
    assert!(text.contains("> ********_"), "{text}");
    assert!(!text.contains("hunter22"));
    let jobs = node_jobs(&testkit::press(&mut app, KeyCode::Enter));
    assert!(
        matches!(&jobs[..], [NodeJob::UnlockV2(Some(typed))] if typed.chars() == 8),
        "{jobs:?}"
    );
    assert!(!format!("{jobs:?}").contains("hunter22"), "{jobs:?}");
    assert!(locked_view(&app).unlocking && locked_view(&app).typed.is_empty());
    // Enter again while it runs asks nothing.
    assert!(node_jobs(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
    testkit::send(
        &mut app,
        Msg::Job(JobResult::UnlockedV2(bridge::UnlockAnswer::Wrong(
            "That passphrase is not right.".into(),
        ))),
    );
    assert!(testkit::render_text(&app).contains("That passphrase is not right."));
    typing(&mut app, "right one");
    testkit::press(&mut app, KeyCode::Enter);
    let opened = testkit::send(
        &mut app,
        Msg::Job(JobResult::UnlockedV2(bridge::UnlockAnswer::Opened(vec![
            "Raven is unlocked. Friends can reach you again.".into(),
        ]))),
    );
    assert!(app.overlays().is_empty());
    assert!(node_jobs(&opened).contains(&NodeJob::Probe));
    assert_eq!(
        app.toast().map(|t| t.text.as_str()),
        Some("Raven is unlocked. Friends can reach you again.")
    );
}

/// A keychain profile: LOCKED says plainly what the lock does not protect,
/// and Enter resumes with no passphrase; an unlock elsewhere (or no node)
/// closes it.
#[test]
fn a_keychain_profile_s_locked_says_what_it_does_not_protect() {
    let _gate = Gate::open();
    let mut app = testkit::settled_app((80, 24), Receive::On, 1);
    settings_read(&mut app, bridge::PassOffer::Set, false);
    node(&mut app, Some(true));
    assert!(!locked_view(&app).passphrase);
    let text = testkit::render_text(&app);
    assert!(text.contains(bridge::LOCKED_SCREEN), "{text}");
    assert!(
        text.contains("Anyone who can log in as you can open them"),
        "{text}"
    );
    assert!(!text.contains("Type your Raven passphrase"), "{text}");
    typing(&mut app, "abc");
    assert!(locked_view(&app).typed.is_empty(), "nothing is typed here");
    let jobs = node_jobs(&testkit::press(&mut app, KeyCode::Enter));
    assert_eq!(jobs, [NodeJob::UnlockV2(None)]);
    node(&mut app, Some(false));
    assert!(app.overlays().is_empty(), "unlocked elsewhere");
    node(&mut app, Some(true));
    node(&mut app, None);
    assert!(app.overlays().is_empty(), "no node: no lock");
    // Ctrl+C still opens QUIT over it.
    node(&mut app, Some(true));
    testkit::ctrl(&mut app, 'c');
    assert!(matches!(
        app.overlays(),
        [Overlay::Locked(_), Overlay::Quit]
    ));
}

/// LOCK's Enter locks a node that serves Lock v2 (it keeps running), and
/// LOCKED opens once it answered. The idle lock does the same after the
/// minutes SET says, and never while the app is used.
#[test]
fn lock_now_and_the_idle_lock_use_lock_v2() {
    let _gate = Gate::open();
    let mut app = testkit::settled_app((80, 24), Receive::On, 1);
    node(&mut app, Some(false));
    testkit::press(&mut app, KeyCode::Char('s'));
    let read = node_jobs(&testkit::press(&mut app, KeyCode::Esc));
    assert!(read.is_empty());
    testkit::press(&mut app, KeyCode::Char('s'));
    settings_read(&mut app, bridge::PassOffer::Set, false);
    while !matches!(app.screen(), Screen::Settings(set) if set.row == SetRow::LockNow) {
        testkit::press(&mut app, KeyCode::Down);
    }
    testkit::press(&mut app, KeyCode::Enter);
    let text = testkit::render_text(&app);
    assert!(
        text.contains("Raven keeps running but forgets its keys"),
        "{text}"
    );
    assert!(
        text.contains("Anyone who can log in as you can open them"),
        "{text}"
    );
    let jobs = node_jobs(&testkit::press(&mut app, KeyCode::Enter));
    assert_eq!(jobs, [NodeJob::LockV2], "no stop: Lock v2");
    testkit::send(&mut app, Msg::Job(JobResult::LockedV2(Ok(true))));
    assert!(matches!(app.overlays(), [Overlay::Locked(_)]));
    node(&mut app, Some(false));
    assert!(app.overlays().is_empty());

    // 'Lock Raven when this app is idle': after 5 minutes.
    while !matches!(app.screen(), Screen::Settings(set) if set.row == SetRow::IdleLock) {
        testkit::press(&mut app, KeyCode::Down);
    }
    testkit::press(&mut app, KeyCode::Enter);
    assert_eq!(app.settings().idle_lock_minutes, 5);
    assert!(
        testkit::render_text(&app).contains("Lock Raven when this app is idle < After 5 minutes >")
    );
    assert!(node_jobs(&testkit::tick(&mut app, Duration::from_secs(4 * 60))).is_empty());
    testkit::press(&mut app, KeyCode::Up);
    testkit::press(&mut app, KeyCode::Down);
    assert!(
        node_jobs(&testkit::tick(&mut app, Duration::from_secs(4 * 60))).is_empty(),
        "a key started the minutes over"
    );
    let jobs = node_jobs(&testkit::tick(&mut app, Duration::from_secs(61)));
    assert_eq!(jobs, [NodeJob::LockV2]);
    // A node without Lock v2 is left alone by the idle lock (no stop).
    let none = testkit::send(&mut app, Msg::Job(JobResult::LockedV2(Ok(false))));
    assert!(app.overlays().is_empty());
    assert!(node_jobs(&none)
        .iter()
        .all(|job| !matches!(job, NodeJob::Lock { .. })));
}

/// SET's lock rows show once the lock settings were read (never with the
/// gate shut); the sleep lock saves raven-node's policy, and PASS sets a
/// passphrase: too short is said, two that differ start over, the change
/// goes with both typed the same.
#[test]
fn set_s_lock_rows_and_pass() {
    let _gate = Gate::open();
    let mut app = testkit::settled_app((80, 40), Receive::On, 1);
    let opened = testkit::press(&mut app, KeyCode::Char('s'));
    assert_eq!(node_jobs(&opened), [NodeJob::LockSettings]);
    assert!(!testkit::render_text(&app).contains("Raven passphrase"));
    settings_read(&mut app, bridge::PassOffer::Set, false);
    let text = testkit::render_text(&app);
    for row in [
        "Lock Raven when the computer sleeps Off",
        "Lock Raven when this app is idle Off",
        "Raven passphrase Set",
    ] {
        assert!(text.contains(row), "{row}: {text}");
    }
    while !matches!(app.screen(), Screen::Settings(set) if set.row == SetRow::SleepLock) {
        testkit::press(&mut app, KeyCode::Down);
    }
    assert!(testkit::render_text(&app).contains("When this computer wakes from sleep"));
    let saved = node_jobs(&testkit::press(&mut app, KeyCode::Enter));
    assert_eq!(saved, [NodeJob::SetSleepLock(true)]);
    let reread = testkit::send(&mut app, Msg::Job(JobResult::SleepLockSaved(Ok(()))));
    assert_eq!(node_jobs(&reread), [NodeJob::LockSettings]);
    settings_read(&mut app, bridge::PassOffer::Set, true);
    assert!(testkit::render_text(&app).contains("Lock Raven when the computer sleeps < On >"));

    testkit::press(&mut app, KeyCode::Down);
    testkit::press(&mut app, KeyCode::Down);
    assert!(testkit::render_text(&app).contains("Anyone who can log in as you can open them"));
    testkit::press(&mut app, KeyCode::Enter);
    assert!(matches!(app.overlays(), [Overlay::Passphrase(_)]));
    let text = testkit::render_text(&app);
    assert!(text.contains("Set a Raven passphrase"), "{text}");
    assert!(text.contains("no way to recover a forgotten one"), "{text}");
    typing(&mut app, "short");
    testkit::press(&mut app, KeyCode::Enter);
    assert!(testkit::render_text(&app).contains("Use at least 8 characters."));
    typing(&mut app, "long enough");
    testkit::press(&mut app, KeyCode::Enter);
    typing(&mut app, "long enougH");
    testkit::press(&mut app, KeyCode::Enter);
    assert!(testkit::render_text(&app).contains(bridge::PASSPHRASES_DIFFER));
    typing(&mut app, "long enough");
    testkit::press(&mut app, KeyCode::Enter);
    typing(&mut app, "long enough");
    let text = testkit::render_text(&app);
    assert!(text.contains("> ***********_"), "{text}");
    assert!(!text.contains("long enough"));
    let jobs = node_jobs(&testkit::press(&mut app, KeyCode::Enter));
    assert!(
        matches!(
            &jobs[..],
            [NodeJob::Passphrase { op: bridge::PassOp::Set, current: None, new: Some(new) }]
                if new.chars() == 11
        ),
        "{jobs:?}"
    );
    assert!(!format!("{jobs:?}").contains("long enough"));
    // Esc does nothing while it runs; the node, locked meanwhile, opens no
    // LOCKED.
    testkit::press(&mut app, KeyCode::Esc);
    node(&mut app, Some(true));
    assert!(matches!(app.overlays(), [Overlay::Passphrase(_)]));
    testkit::send(
        &mut app,
        Msg::Job(JobResult::PassphraseChanged(Ok(vec![
            "Your Raven passphrase is set.".into(),
        ]))),
    );
    node(&mut app, Some(false));
    assert!(app.overlays().is_empty());
    assert_eq!(
        app.toast().map(|t| t.text.as_str()),
        Some("Your Raven passphrase is set.")
    );
}

/// With the gate shut: no lock rows, no lock settings read, LOCK's Enter is
/// Lock now v1, and a node's Status has no lock to follow.
#[test]
fn with_the_gate_shut_nothing_of_lock_v2_shows() {
    set_lab_for_this_thread(SecGate::LocalProtection, Some(false));
    let mut app = testkit::settled_app((80, 40), Receive::On, 1);
    node(&mut app, Some(false));
    let opened = testkit::press(&mut app, KeyCode::Char('s'));
    assert!(node_jobs(&opened).is_empty());
    let text = testkit::render_text(&app);
    assert!(!text.contains("Raven passphrase") && !text.contains("computer sleeps"));
    while !matches!(app.screen(), Screen::Settings(set) if set.row == SetRow::LockNow) {
        testkit::press(&mut app, KeyCode::Down);
    }
    testkit::press(&mut app, KeyCode::Enter);
    assert!(!testkit::render_text(&app).contains("forgets its keys"));
    let jobs = node_jobs(&testkit::press(&mut app, KeyCode::Enter));
    assert!(!jobs.contains(&NodeJob::LockV2), "{jobs:?}");
    set_lab_for_this_thread(SecGate::LocalProtection, None);
}

/// LOCKED as drawn at 80x24 in the simple mono look, a passphrase profile
/// with three characters typed and a wrong one said.
#[test]
fn locked_renders_over_the_whole_screen() {
    let _gate = Gate::open();
    let mut app = testkit::settled_app((80, 24), Receive::On, 2);
    settings_read(&mut app, bridge::PassOffer::ChangeOrRemove, true);
    node(&mut app, Some(true));
    typing(&mut app, "abc");
    testkit::press(&mut app, KeyCode::Enter);
    testkit::send(
        &mut app,
        Msg::Job(JobResult::UnlockedV2(bridge::UnlockAnswer::Wrong(
            "That passphrase is not right.".into(),
        ))),
    );
    typing(&mut app, "xyz");
    testkit::assert_rows(
        &testkit::render(&app, 80, 24),
        &[
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "        ┌──────────────────────────────────────────────────────────────┐        ",
            "        │ Raven is locked. Friends can't reach you; your messages wait │        ",
            "        │ here.                                                        │        ",
            "        │                                                              │        ",
            "        │ Type your Raven passphrase to unlock:                        │        ",
            "        │ > ***_                                                       │        ",
            "        │                                                              │        ",
            "        │ That passphrase is not right.                                │        ",
            "        │                                                              │        ",
            "        │ [Enter] Unlock   [Ctrl+C] Quit                               │        ",
            "        └──────────────────────────────────────────────────────────────┘        ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
            "                                                                                ",
        ],
    );
}
