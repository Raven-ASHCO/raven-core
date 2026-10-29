//! The nearby CLI (P5.28): the consent, the rows, the doctor lines, an
//! older raven-node, and `--for`.

use super::*;

fn info(radio: &str, roles: &[&str], address: &str) -> Box<NearbyStatusInfo> {
    Box::new(NearbyStatusInfo {
        enabled: true,
        gate_live: true,
        radio: radio.into(),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        address_privacy: address.into(),
        ..NearbyStatusInfo::default()
    })
}

fn rows(view: &NearbyView) -> Vec<String> {
    status_rows(view)
        .into_iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect()
}

/// The consent (owner decision O5-12) says what nearby devices see, that a
/// device that connects reads this computer's Bluetooth name (as given,
/// made safe for the terminal) and model, and who may use it.
#[test]
fn the_consent_names_the_bluetooth_name_and_what_is_seen() {
    let text = consent_text("Studio\u{1b}[31m Mac");
    assert!(text.contains("a random Bluetooth ID"), "{text}");
    assert!(text.contains("changes every 15 minutes"), "{text}");
    assert!(
        text.contains("can read its Bluetooth name 'Studio Mac' and its model"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(text.contains("only your verified contacts"), "{text}");
    assert!(text.contains("end-to-end encrypted"), "{text}");
    // Review nearby-4: the connect, and what a replayed ID tells.
    assert!(
        text.contains("connects, from a random Bluetooth address, to a contact whose ID it sees"),
        "{text}"
    );
    assert!(
        text.contains("recorded that contact's ID in the last 30 minutes can play it back"),
        "{text}"
    );
    assert!(text.contains("raven nearby disable"), "{text}");
    let name = bluetooth_name();
    assert!(!name.is_empty() && name.chars().count() <= 64, "{name}");
    assert!(!name.contains('\n'), "{name}");
}

#[test]
fn the_linux_name_is_the_pretty_host_name() {
    assert_eq!(
        pretty_hostname("CHASSIS=laptop\nPRETTY_HOSTNAME=\"Ada's laptop\"\n"),
        Some("Ada's laptop".into())
    );
    assert_eq!(
        pretty_hostname("PRETTY_HOSTNAME='lab one'"),
        Some("lab one".into())
    );
    assert_eq!(
        pretty_hostname("PRETTY_HOSTNAME=plain"),
        Some("plain".into())
    );
    assert_eq!(pretty_hostname("PRETTY_HOSTNAME=\"\"\nCHASSIS=x"), None);
    assert_eq!(pretty_hostname(""), None);
}

#[test]
fn for_takes_minutes_or_hours_as_lan_on_for_does() {
    assert_eq!(parse_for("30m"), Ok(1800));
    assert_eq!(parse_for(" 2H "), Ok(7200));
    assert_eq!(parse_for("24h"), Ok(86_400));
    for bad in ["0m", "25h", "90s", "x", "", "-5m"] {
        assert!(parse_for(bad).is_err(), "{bad}");
    }
}

/// Where the view comes from: this build's gate first (held: the saved
/// choice only), then the running node's Status (`nearby` present: live;
/// absent: an older node or its gate closed), else not running.
#[test]
fn the_view_follows_this_builds_gate_then_the_node() {
    let status = |nearby: Option<Box<NearbyStatusInfo>>| -> Result<IpcResponse, String> {
        Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p: None,
            pid: None,
            lan_listen: None,
            last_paths: Vec::new(),
            route_hints: None,
            unreachable: Vec::new(),
            egress: None,
            lan_listen_wanted: None,
            lan_bind_error: None,
            clock_skew: Vec::new(),
            unanswered: Vec::new(),
            at_rest: None,
            lan: None,
            security: None,
            nearby,
            tor: None,
            learning: None,
            locked: None,
            updates: None,
        })
    };
    let live = info("powered_on", &["central", "peripheral"], "random");
    assert_eq!(
        view_with(false, Some(true), &status(Some(live.clone()))),
        NearbyView::Held { saved: Some(true) }
    );
    assert_eq!(
        view_with(true, None, &status(Some(live.clone()))),
        NearbyView::Live(live)
    );
    assert_eq!(
        view_with(true, Some(false), &status(None)),
        NearbyView::NodeHeld { saved: Some(false) }
    );
    assert_eq!(
        view_with(true, Some(true), &Err("not running".into())),
        NearbyView::NotRunning { saved: Some(true) }
    );
}

/// The `address` row of a radio that would use its fixed public address:
/// nearby is inactive there (no advert, no connect; review nearby-1).
fn public_row() -> String {
    if cfg!(windows) {
        "address: nearby inactive: Windows may use this PC's fixed Bluetooth address, so it \
         neither advertises nor connects until that is ruled out (row N7w)"
            .into()
    } else {
        "address: nearby inactive: the adapter would use its fixed public address, so this \
         computer neither advertises nor connects; set Privacy = device in \
         /etc/bluetooth/main.conf (admin)"
            .into()
    }
}

/// The ux snapshots of the NEARBY rows (design step 5.7): held, off, the
/// radio not allowed, a public address (nearby inactive), a central-only
/// radio, and a working one. Counts and states only.
#[test]
fn nearby_rows_for_held_off_unauthorized_public_and_central_only() {
    assert!(
        rows(&NearbyView::Held { saved: None }).is_empty(),
        "release"
    );
    assert_eq!(
        rows(&NearbyView::Held { saved: Some(true) }),
        [format!(
            "state: held in this build: {HELD_WHY} (your choice is kept)"
        )]
    );
    let mut off = info("off", &[], "unknown");
    off.enabled = false;
    assert_eq!(
        rows(&NearbyView::Live(off)),
        ["state: off (turn on: raven nearby enable; verified contacts only)"]
    );
    assert_eq!(
        rows(&NearbyView::NotRunning { saved: None }),
        ["state: off (turn on: raven nearby enable; verified contacts only)"]
    );
    assert_eq!(
        rows(&NearbyView::NotRunning { saved: Some(true) })[0],
        "state: on; raven-node is not running: nearby needs it (it starts when you send, or \
         run `raven listen`)"
    );
    assert_eq!(
        rows(&NearbyView::NodeHeld { saved: Some(true) }),
        ["state: raven-node does not run nearby (held there, or too old: update it)"]
    );
    assert_eq!(
        rows(&NearbyView::Live(info("unauthorized", &[], "unknown"))),
        [
            "state: on (verified contacts only)",
            "radio: not allowed: allow Bluetooth for Raven in this computer's privacy \
             settings (on macOS: RavenNearby), then restart raven-node"
        ]
    );
    assert_eq!(
        rows(&NearbyView::Live(info("off", &[], "unknown"))),
        [
            "state: on (verified contacts only)",
            "radio: off: turn Bluetooth on in this computer's settings"
        ]
    );
    assert_eq!(
        rows(&NearbyView::Live(info(
            "powered_on",
            &["central", "peripheral"],
            "public"
        ))),
        [
            "state: on (verified contacts only)".to_string(),
            "radio: on".into(),
            public_row(),
            "in range: 0 contacts in range now, 0 connected".into()
        ]
    );
    // A central-only radio with a public address (Windows today) does
    // not connect either (review nearby-1).
    assert_eq!(
        rows(&NearbyView::Live(info(
            "powered_on",
            &["central"],
            "public"
        ))),
        [
            "state: on (verified contacts only)".to_string(),
            "radio: on, central only: this computer can only connect to contacts that \
             advertise"
                .into(),
            public_row(),
            "in range: 0 contacts in range now, 0 connected".into()
        ]
    );
    assert_eq!(
        rows(&NearbyView::Live(info(
            "powered_on",
            &["central"],
            "random"
        ))),
        [
            "state: on (verified contacts only)",
            "radio: on, central only: this computer can only connect to contacts that \
             advertise",
            "in range: 0 contacts in range now, 0 connected"
        ]
    );
    let mut busy = info("powered_on", &["central", "peripheral"], "random");
    busy.in_range = 1;
    busy.pipes = 1;
    busy.advertising = 1;
    busy.rotating = 2;
    assert_eq!(
        rows(&NearbyView::Live(busy)),
        [
            "state: on (verified contacts only)",
            "radio: on",
            "address: random, changing (nothing fixed is advertised)",
            "in range: 1 contact in range now, 1 connected; advertising for 2 (only while you \
             have something to send)"
        ]
    );
    assert_eq!(
        rows(&NearbyView::Live(info("no_backend", &[], "unknown")))[1],
        "radio: no Bluetooth support in this build of raven-node"
    );
}

/// Review nearby-3: a radio raven-node could not start because the
/// Bluetooth software is missing or not running (the macOS helper, BlueZ),
/// or because this profile's own state is not ready, says that and its fix
/// in the row and in doctor's fix line: never "no Bluetooth LE" or "turn
/// Bluetooth on".
#[test]
fn a_radio_that_did_not_start_names_the_real_fix() {
    for (state, fix) in [
        (
            "helper_unavailable",
            "RAVEN_INSTALL_NEARBY_HELPER=1 bash scripts/install/macos_launchd.sh",
        ),
        ("service_down", "sudo systemctl enable --now bluetooth"),
        ("local_state", "see the other lines of raven doctor"),
    ] {
        assert!(
            raven_core::ipc::NEARBY_RADIO_STATES.contains(&state),
            "{state}"
        );
        let row = &rows(&NearbyView::Live(info(state, &[], "unknown")))[1];
        let doctor = doctor_lines(&NearbyView::Live(info(state, &[], "unknown")));
        for text in [row.as_str(), doctor[1].as_str()] {
            assert!(text.contains(fix), "{state}: {text}");
            assert!(!text.contains("no Bluetooth LE"), "{state}: {text}");
            assert!(!text.contains("turn Bluetooth on"), "{state}: {text}");
        }
        assert!(doctor[0].contains(&format!("radio={state} ")), "{doctor:?}");
    }
}

/// `raven doctor`: one keyed line, and the fix when the radio needs the
/// user (held: the flag named).
#[test]
fn doctor_lines_key_the_state_and_name_the_fix() {
    assert_eq!(
        doctor_lines(&NearbyView::Held { saved: None }),
        [format!("bluetooth_nearby: held ({HELD_DOCTOR})")]
    );
    assert_eq!(
        doctor_lines(&NearbyView::NotRunning { saved: Some(true) }),
        ["bluetooth_nearby: node=not_running enabled=yes"]
    );
    assert_eq!(
        doctor_lines(&NearbyView::NodeHeld { saved: None }),
        ["bluetooth_nearby: node=held_or_old enabled=unset"]
    );
    let lines = doctor_lines(&NearbyView::Live(info("unauthorized", &[], "unknown")));
    assert_eq!(
        lines[0],
        "bluetooth_nearby: enabled=yes radio=unauthorized roles= address=unknown advertising=0 \
         rotating=0 in_range=0 pipes=0 knock_silenced=0 background_mail=no"
    );
    let mut background = info("unauthorized", &[], "unknown");
    background.background_mail = true;
    assert!(
        doctor_lines(&NearbyView::Live(background))[0].ends_with(" background_mail=yes"),
        "OD-C8"
    );
    assert!(
        lines[1].starts_with("bluetooth_nearby_fix: not allowed"),
        "{lines:?}"
    );
    for roles in [&["central", "peripheral"][..], &["central"]] {
        let public = doctor_lines(&NearbyView::Live(info("powered_on", roles, "public")));
        assert_eq!(public.len(), 2, "{public:?}");
        assert_eq!(
            format!(
                "bluetooth_nearby_fix: {}",
                public_row().trim_start_matches("address: ")
            ),
            public[1],
            "{roles:?}"
        );
        assert!(
            public[1].contains("neither advertises nor connects"),
            "{public:?}"
        );
        if !cfg!(windows) {
            assert!(
                public[1].contains("set Privacy = device in /etc/bluetooth/main.conf"),
                "{public:?}"
            );
        }
    }
    let central = doctor_lines(&NearbyView::Live(info(
        "powered_on",
        &["central"],
        "random",
    )));
    assert!(
        central[1].contains("can only connect to contacts that advertise"),
        "{central:?}"
    );
    assert_eq!(
        doctor_lines(&NearbyView::Live(info(
            "powered_on",
            &["central", "peripheral"],
            "random"
        )))
        .len(),
        1
    );
}

/// An older raven-node answers a nearby request with `IPC_FRAME`: "too old
/// for nearby", never a raw code; a node holding nearby, or without its
/// engine, says so in words.
#[test]
fn an_old_node_is_too_old_for_nearby() {
    let err = |code: &str| {
        Ok(IpcResponse::Error {
            v: IPC_VERSION,
            code: code.into(),
            message: "x".into(),
        })
    };
    assert_eq!(
        expect_done(control_answer(err("IPC_FRAME"))).unwrap_err(),
        "raven-node is too old for nearby: update it"
    );
    assert!(expect_done(control_answer(err("NEARBY_HOLD")))
        .unwrap_err()
        .starts_with("raven-node holds nearby in its build"));
    assert!(expect_done(control_answer(err("NEARBY_NOT_RUNNING")))
        .unwrap_err()
        .contains("raven nearby enable"));
    let gone = Err(ipc_client::ipc_request_timeout(
        Path::new("/nonexistent/raven-test-profile"),
        &IpcRequest::status(),
        Duration::from_millis(200),
    )
    .unwrap_err());
    assert_eq!(
        expect_done(control_answer(gone)).unwrap_err(),
        NOT_RUNNING,
        "no raven-node"
    );
    let done = Ok(IpcResponse::NearbyControlResult {
        v: IPC_VERSION,
        status: info("powered_on", &["central"], "random"),
    });
    assert!(expect_done(control_answer(done)).is_ok());
}

/// `raven nearby enable` with no raven-node running: the consent comes
/// first, once (nothing saved yet), then the choice is saved for the next
/// start; again (or after `disable`): no consent.
#[test]
fn the_consent_is_shown_once_and_the_choice_is_saved() {
    let dir = tempfile::tempdir().unwrap();
    let first = enable(dir.path(), true).unwrap();
    assert!(first[0].starts_with("Nearby (Bluetooth) lets"), "{first:?}");
    assert!(
        first.iter().any(|l| l.contains("Bluetooth name '")),
        "{first:?}"
    );
    assert_eq!(
        first.last().unwrap(),
        "ok nearby=on saved: raven-node turns it on when it starts"
    );
    assert_eq!(saved(dir.path()), Some(true));
    let again = enable(dir.path(), true).unwrap();
    assert_eq!(
        again,
        ["ok nearby=on saved: raven-node turns it on when it starts"]
    );
    assert_eq!(enable(dir.path(), false).unwrap(), ["ok nearby=off saved"]);
    assert_eq!(saved(dir.path()), Some(false));
    let back = enable(dir.path(), true).unwrap();
    assert!(
        !back.iter().any(|l| l.contains("Bluetooth name")),
        "{back:?}"
    );
}

/// With this build holding nearby (no lab switches here), every command
/// but `status` refuses with the hold and changes nothing.
#[test]
fn a_held_build_refuses_and_changes_nothing() {
    if raven_core::nearby_live_enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for arg in [
        NearbyArg::Enable,
        NearbyArg::Disable,
        NearbyArg::On {
            contact: "@bob".into(),
            ttl: None,
        },
        NearbyArg::Off { contact: None },
    ] {
        let err = cmd_nearby(dir.path(), arg.clone()).unwrap_err();
        assert!(err.contains("NEARBY_HOLD"), "{arg:?}: {err}");
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    let status = cmd_nearby(dir.path(), NearbyArg::Status).unwrap();
    assert!(status[1].starts_with("held in this build"), "{status:?}");
    foreground(dir.path(), &"ab".repeat(32));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// Owner decision OD-C8: the background-mail consent says what a radio
/// neighbour sees without any send (an advert while mail waits, and so
/// that this computer keeps or waits with mail for someone, for how long),
/// who can use it, the replay a recorded ID allows, the battery, that it
/// needs nearby on, and how to turn it off; lines fit a terminal.
#[test]
fn the_background_mail_consent_says_what_it_reveals() {
    let text = BACKGROUND_MAIL_CONSENT;
    assert!(text.lines().next().unwrap().ends_with('?'), "{text}");
    for needle in [
        "keeps sealed mail for a verified contact",
        "a random Bluetooth ID, which changes every 15 minutes",
        "for as long as such mail waits (at most 2 contacts at a time)",
        "cannot\n  tell whom it is for",
        "keeps or waits with mail for someone, and for how long",
        "Only your verified contacts can",
        "end-to-end\n  encrypted",
        "play it back\n  to learn that this computer is in range",
        "more battery",
        "raven nearby enable",
        "raven nearby background-mail off",
    ] {
        assert!(text.contains(needle), "{needle}: {text}");
    }
    for line in text.lines() {
        assert!(line.chars().count() <= 80, "{line}");
    }
    assert!(BACKGROUND_NEEDS_YES.contains("--yes"));
}

/// OD-C8: a BLUETOOTH NEARBY row while background mail is on (none while off), and
/// the advertising count says mail waiting counts too.
#[test]
fn background_mail_shows_in_the_nearby_rows() {
    let mut on = info("powered_on", &["central", "peripheral"], "random");
    on.advertising = 1;
    on.rotating = 1;
    let off_rows = rows(&NearbyView::Live(on.clone()));
    assert!(
        !off_rows.iter().any(|r| r.starts_with("background:")),
        "{off_rows:?}"
    );
    on.background_mail = true;
    let on_rows = rows(&NearbyView::Live(on));
    assert!(
        on_rows.contains(&format!("background: {BACKGROUND_ON_ROW}")),
        "{on_rows:?}"
    );
    assert!(
        on_rows
            .iter()
            .any(|r| r.ends_with("(only while you have something to send or mail waits)")),
        "{on_rows:?}"
    );
}

/// OD-C8, as the custody consents ask: off a terminal it needs `--yes`
/// (exit 2) and changes nothing; on one only a yes turns it on, after the
/// consent; a second `on` says it is on already; `--yes` prints the consent
/// as what was agreed to; `off` saves off. With no raven-node running the
/// choice is saved for its next start, and nearby itself is never turned
/// on (a note says it waits for it).
#[test]
fn background_mail_asks_like_the_custody_consents() {
    let dir = tempfile::tempdir().unwrap();
    let saved = || saved_background(dir.path());
    let on = BackgroundArg::On { yes: false };
    let err = background_set(dir.path(), on, false, |_| panic!("not asked")).unwrap_err();
    assert_eq!((err.code, err.text.as_str()), (2, BACKGROUND_NEEDS_YES));
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "nothing written"
    );
    let mut asked = String::new();
    let no = background_set(dir.path(), on, true, |q| {
        asked = q.to_string();
        Some("n".into())
    })
    .unwrap();
    assert!(asked.starts_with(BACKGROUND_MAIL_CONSENT), "{asked}");
    assert!(asked.ends_with("Turn on? [y/N] "), "{asked}");
    assert_eq!(no, ["nothing changed: background mail stays off"]);
    assert_eq!(saved(), None);
    let yes = background_set(dir.path(), on, true, |_| Some("yes".into())).unwrap();
    assert_eq!(
        yes,
        [
            "ok background mail on saved: raven-node applies it when it starts",
            "note: nearby itself is off: background mail starts once you turn it on (raven \
             nearby enable)"
        ]
    );
    assert_eq!(saved(), Some(true));
    let policy = try_load_policy(dir.path()).unwrap();
    assert_eq!(policy.nearby, None, "nearby itself stays as it was");
    assert_eq!(
        background_set(dir.path(), on, true, |_| panic!("not asked again")).unwrap(),
        ["background mail is on already (raven nearby background-mail off stops it)"]
    );
    let scripted = background_set(dir.path(), BackgroundArg::On { yes: true }, false, |_| {
        panic!("--yes asks nothing")
    })
    .unwrap();
    assert!(
        scripted
            .iter()
            .any(|l| l.contains("for as long as such mail waits")),
        "the consent as agreed to: {scripted:?}"
    );
    assert!(background_status(dir.path())[0].starts_with("background mail: on:"));
    assert_eq!(
        background_set(dir.path(), BackgroundArg::Off, false, |_| panic!(
            "off asks nothing"
        ))
        .unwrap(),
        ["ok background mail off saved"]
    );
    assert_eq!(saved(), Some(false));
    assert!(background_status(dir.path())[0].starts_with("background mail: off:"));
    // Status never changes it.
    background_set(dir.path(), BackgroundArg::Status, false, |_| {
        panic!("status")
    })
    .unwrap();
    assert_eq!(saved(), Some(false));
}

/// With this build holding nearby, `on` and `off` refuse with the hold and
/// write nothing; `status` answers.
#[test]
fn background_mail_in_a_held_build_changes_nothing() {
    if raven_core::nearby_live_enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for arg in [BackgroundArg::On { yes: true }, BackgroundArg::Off] {
        let err = background_mail_with(dir.path(), arg, true, |_| Some("y".into())).unwrap_err();
        assert!(err.text.contains("NEARBY_HOLD"), "{arg:?}: {}", err.text);
        assert_eq!(err.code, 1);
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    let status = background_mail_with(dir.path(), BackgroundArg::Status, false, |_| None).unwrap();
    assert!(status[0].starts_with("background mail: off"), "{status:?}");
    assert!(status[1].starts_with("held in this build"), "{status:?}");
}
