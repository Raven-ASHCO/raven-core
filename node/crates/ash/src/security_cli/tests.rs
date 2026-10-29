use super::*;
use raven_core::security_events::{Attribution, SecEvent, Via};
use raven_core::security_gate::{self, SecGate};
use raven_core::security_ledger::AlertId;

/// 2026-10-20 (a Tuesday), 15:00 UTC.
const NOW: u64 = 20_746 * DAY_MS + 15 * HOUR_MS;
const NOW_HOUR: u64 = NOW / HOUR_MS;

fn clock() -> Clock {
    Clock {
        now_ms: NOW,
        fixed: Some(Some(0)),
    }
}

fn contact(seed: u8, petname: &str, pinned: bool) -> Contact {
    let id = raven_core::Identity::from_seed(&[seed; 32]);
    Contact {
        petname: petname.into(),
        public_tag: petname.to_ascii_lowercase(),
        alias: String::new(),
        address: id.address(),
        pub_hex: hex::encode(id.public_key_bytes()),
        pinned,
        lan_dial: String::new(),
        internet_dial: String::new(),
        p2p: String::new(),
        p2p_next: String::new(),
        p2p_via: Vec::new(),
        custodians: Vec::new(),
        hide_ip: false,
        onion: String::new(),
    }
}

fn key(c: &Contact) -> [u8; 32] {
    super::super::parse_pub_hex(&c.pub_hex).unwrap()
}

fn alert(id: i64, kind: SecKind, subject: Option<LedgerSubject>, severity: Severity) -> Alert {
    Alert {
        id: AlertId(id),
        kind,
        subject,
        first_hour: NOW_HOUR - 5,
        last_hour: NOW_HOUR - 5,
        n: 1,
        severity,
        state: AlertState::New,
        action: None,
    }
}

/// Sara (verified) and Rena (not verified), and the ledger's open rows in
/// its order: a refused key change about Sara (an alert), Rena's mailbox
/// serving bad mail twice, parked (a warning), and a notice.
fn scene() -> (Book, Vec<Alert>, Contact, Contact) {
    let sara = contact(0x5a, "Sara", true);
    let rena = contact(0x7e, "Rena", false);
    let key_change = alert(
        1,
        SecKind::KeyChangeAttempt,
        Some(LedgerSubject::Contact(key(&sara))),
        Severity::Alert,
    );
    let mut mailbox = alert(
        2,
        SecKind::CustodianBadObject,
        Some(LedgerSubject::Carrier {
            key: key(&rena),
            role: CarrierRole::Custodian,
        }),
        Severity::Suspicious,
    );
    mailbox.n = 2;
    mailbox.first_hour = NOW_HOUR - 30;
    mailbox.last_hour = NOW_HOUR - 1;
    mailbox.action = Some("CUSTODIAN_PARKED".into());
    let notice = alert(
        3,
        SecKind::IndexJump,
        Some(LedgerSubject::Contact(key(&sara))),
        Severity::Notice,
    );
    let book = Book::of(&[sara.clone(), rena.clone()]);
    (book, vec![key_change, mailbox, notice], sara, rena)
}

/// `raven security`: alerts and warnings numbered with what Raven did, what
/// to do and its command; notices only counted; the strangers count from
/// raven-node; where to go next.
#[test]
fn the_list_shows_alerts_and_warnings_and_only_counts_notices() {
    let (book, alerts, ..) = scene();
    let view = View::of(alerts, &book);
    assert_eq!(view.shown.len(), 2);
    assert_eq!(view.counted, 1);
    assert_eq!(
        list_lines(&view, Some(37), &clock()),
        vec![
            "1. ! An invite had a different key from the Sara you verified (this morning)",
            "     Raven kept the old key.",
            "     If Sara really has a new key (a new computer or a reinstall), compare security \
             words with Sara before you add it. If not, ignore that invite.",
            "       raven contact verify --petname Sara",
            "2. - Mail that came through Rena's computer failed Raven's checks (2 times, latest \
             this afternoon)",
            "     Raven didn't show it. It stopped using Rena as a mailbox for a day.",
            "     Tell Rena in person: Rena may not know. Raven tries Rena's mailbox again after a \
             day; you can also do it now.",
            "       raven outbox retry ID   (any waiting message; `raven outbox` lists them)",
            "Also 1 smaller notice, only counted.",
            "Strangers refused in the last hour: 37 (they learned nothing about you)",
            text::LIST_FOOTER,
        ]
    );
    // Nothing open: says so, and counts what is only counted.
    let quiet = View::of(
        vec![alert(9, SecKind::IndexJump, None, Severity::Notice)],
        &book,
    );
    assert_eq!(
        list_lines(&quiet, Some(0), &clock()),
        vec![text::NOTHING_OPEN, "Also 1 smaller notice, only counted."]
    );
}

/// `raven security explain N`: when, what Raven did, what to do, then whom
/// it is about (a key prefix only for a verified friend), the counts per
/// day, how serious and the technical code.
#[test]
fn explain_adds_counts_whom_and_the_code() {
    let (book, alerts, sara, _) = scene();
    let view = View::of(alerts, &book);
    let lines = explain_lines(&view.shown[0], &[(0, 1), (2, 3)], &clock());
    let prefix = &sara.pub_hex[..8];
    assert_eq!(
        lines,
        vec![
            "! An invite had a different key from the Sara you verified".to_string(),
            "  When            this morning".into(),
            "  What Raven did  Raven kept the old key.".into(),
            "  What you can do If Sara really has a new key (a new computer or a reinstall), \
             compare security words with Sara before you add it. If not, ignore that invite."
                .into(),
            "                    raven contact verify --petname Sara".into(),
            "Details".into(),
            format!("  About           Sara (verified friend, key {prefix})"),
            "  Per day         today 1, 2 days ago 3".into(),
            "  How serious     alert".into(),
            "  Code            SEC_KEY_CHANGE_ATTEMPT (27)".into(),
        ]
    );
    let lines = explain_lines(&view.shown[1], &[], &clock()).join("\n");
    assert!(
        lines.contains("  When            2 times, first yesterday, latest this afternoon"),
        "{lines}"
    );
    assert!(
        lines.contains("  About           Rena, as a mailbox for you (not verified)\n"),
        "{lines}"
    );
    assert!(lines.contains("  How serious     warning"), "{lines}");
    assert!(
        lines.contains("  Raven's action  CUSTODIAN_PARKED"),
        "{lines}"
    );
    assert!(
        !lines.contains(&book.contacts[1].pub_hex[..8]),
        "no key of an unverified one"
    );
}

/// `--json` (v1): each alert's kind, code, severity, state, times, count,
/// whom (a name; a key prefix only for a verified friend), the action and
/// its words; never a whole key or an address.
#[test]
fn json_is_versioned_and_names_no_whole_key() {
    let (book, alerts, sara, rena) = scene();
    let view = View::of(alerts, &book);
    let one = view.shown[0].json();
    assert_eq!(one["n"], 1);
    assert_eq!(one["kind"], "SEC_KEY_CHANGE_ATTEMPT");
    assert_eq!(one["code"], 27);
    assert_eq!(one["severity"], "alert");
    assert_eq!(one["state"], "new");
    assert_eq!(one["count"], 1);
    assert_eq!(one["first_at_ms"], (NOW_HOUR - 5) * HOUR_MS);
    assert_eq!(one["last_at_ms"], (NOW_HOUR - 5) * HOUR_MS);
    assert_eq!(one["about"]["role"], "contact");
    assert_eq!(one["about"]["name"], "Sara");
    assert_eq!(one["about"]["verified"], true);
    assert_eq!(one["about"]["key_prefix"], &sara.pub_hex[..8]);
    assert_eq!(one["action"], Value::Null);
    assert_eq!(one["act"], "compare_words");
    assert_eq!(
        one["headline"],
        "An invite had a different key from the Sara you verified"
    );
    for key in ["did", "todo"] {
        assert!(one[key].as_str().is_some_and(|t| t.ends_with('.')), "{key}");
    }
    let two = view.shown[1].json();
    assert_eq!(two["severity"], "suspicious");
    assert_eq!(two["about"]["role"], "mailbox");
    assert_eq!(two["about"]["verified"], false);
    assert!(two["about"].get("key_prefix").is_none());
    assert_eq!(two["action"], "CUSTODIAN_PARKED");
    assert_eq!(two["act"], "mailbox_retry");
    let all = format!("{one}{two}");
    for whole in [&sara.pub_hex, &rena.pub_hex, &sara.address, &rena.address] {
        assert!(!all.contains(whole.as_str()), "{whole} in {all}");
    }
    assert!(!all.contains(&rena.pub_hex[..8]));
    // Nothing to read: the same shape, `available` false and why.
    for why in ["not_in_this_version", "not_encrypted"] {
        let off = unavailable_json(why);
        assert_eq!(off["v"], 1);
        assert_eq!(off["available"], false);
        assert_eq!(off["why"], why);
        assert_eq!(off["alerts"], json!([]));
        assert_eq!(off["counted"], 0);
    }
}

/// A relay, this computer, an update and a removed contact are named
/// without a key; an update names who passed it on.
#[test]
fn whom_a_notice_is_about_without_a_key() {
    let (book, ..) = scene();
    let relay = alert(
        4,
        SecKind::RelayLinkBroken,
        Some(LedgerSubject::Carrier {
            key: [0xEE; 32],
            role: CarrierRole::Relay,
        }),
        Severity::Suspicious,
    );
    let shown = Shown::of(relay, &book);
    assert_eq!(shown.json()["about"], json!({ "role": "relay" }));
    assert_eq!(
        shown.text.headline,
        "A relay broke a connection to a friend"
    );
    assert!(!explain_lines(&shown, &[], &clock())
        .join("\n")
        .contains(&hex::encode([0xEE; 32])[..8]));
    let rollback = Shown::of(
        alert(5, SecKind::LocalRollback, None, Severity::Alert),
        &book,
    );
    assert_eq!(rollback.json()["about"], json!({ "role": "this_computer" }));
    assert_eq!(
        rollback.hint().as_deref(),
        Some("raven contact verify NAME")
    );
    let gone = Shown::of(
        alert(
            6,
            SecKind::ObjectAuthFail,
            Some(LedgerSubject::Contact([0x11; 32])),
            Severity::Alert,
        ),
        &book,
    );
    assert_eq!(
        gone.text.headline,
        "Messages from someone not in your contacts failed Raven's security check"
    );
    assert_eq!(gone.json()["about"]["verified"], false);
    assert!(gone.json()["about"].get("key_prefix").is_none());
    let update = Shown::of(
        alert(
            7,
            SecKind::AdvisoryForged,
            Some(LedgerSubject::PassedBy(key(&book.contacts[0]))),
            Severity::Suspicious,
        ),
        &book,
    );
    assert_eq!(
        update.text.headline,
        "A security update passed on by Sara failed Raven's checks"
    );
    let unread = Book {
        contacts: Vec::new(),
        read: false,
    };
    let unknown = Shown::of(
        alert(
            8,
            SecKind::ObjectAuthFail,
            Some(LedgerSubject::Contact([0x11; 32])),
            Severity::Alert,
        ),
        &unread,
    );
    assert_eq!(unknown.who.name, "a contact");
}

/// `raven status`: a SECURITY section only while an alert or a warning is
/// open (at most three in full, then how many more), with the strangers
/// count and where the details are; otherwise only the strangers row, and
/// nothing at all while no stranger was refused.
#[test]
fn status_has_a_section_only_while_something_is_open() {
    let (book, alerts, ..) = scene();
    let none = status_rows_of(None, Some(0), &clock());
    assert!(none.section.is_empty() && none.strangers.is_none());
    let row = status_rows_of(None, Some(37), &clock());
    assert!(row.section.is_empty());
    assert_eq!(
        row.strangers.as_deref(),
        Some("Strangers refused in the last hour: 37 (they learned nothing about you)")
    );
    let notices_only = View::of(alerts[2..].to_vec(), &book);
    assert!(status_rows_of(Some(&notices_only), None, &clock())
        .section
        .is_empty());
    let view = View::of(alerts.clone(), &book);
    let rows = status_rows_of(Some(&view), Some(37), &clock());
    assert_eq!(rows.strangers, None, "inside the section");
    assert_eq!(
        rows.section,
        vec![
            "! An invite had a different key from the Sara you verified (this morning)",
            "  Raven kept the old key.",
            "  If Sara really has a new key (a new computer or a reinstall), compare security \
             words with Sara before you add it. If not, ignore that invite.",
            "    raven contact verify --petname Sara",
            "- Mail that came through Rena's computer failed Raven's checks (2 times, latest this \
             afternoon)",
            "  Raven didn't show it. It stopped using Rena as a mailbox for a day.",
            "  Tell Rena in person: Rena may not know. Raven tries Rena's mailbox again after a \
             day; you can also do it now.",
            "    raven outbox retry ID   (any waiting message; `raven outbox` lists them)",
            "Strangers refused in the last hour: 37 (they learned nothing about you)",
            "Details: raven security",
        ]
    );
    let many: Vec<Alert> = (0..5)
        .map(|i| alert(i, SecKind::BindingMismatch, None, Severity::Alert))
        .collect();
    let rows = status_rows_of(Some(&View::of(many, &book)), None, &clock());
    assert_eq!(
        rows.section.iter().filter(|l| l.starts_with("! ")).count(),
        STATUS_SHOWN
    );
    assert!(rows.section.contains(&"2 more: raven security".to_string()));
}

/// `raven doctor`: one row with how many are open, then what to do about
/// the first and its command; nothing while none is.
#[test]
fn doctor_counts_the_open_alerts_and_says_what_to_do() {
    let (book, alerts, ..) = scene();
    assert!(doctor_rows_of(None).is_empty());
    assert!(doctor_rows_of(Some(&View::of(alerts[2..].to_vec(), &book))).is_empty());
    let view = View::of(alerts, &book);
    assert_eq!(
        doctor_rows_of(Some(&view)),
        vec![
            ("security", "2 open alerts (raven security)".to_string()),
            (
                "",
                "If Sara really has a new key (a new computer or a reinstall), compare security \
                 words with Sara before you add it. If not, ignore that invite."
                    .into()
            ),
            ("", "  raven contact verify --petname Sara".into()),
        ]
    );
}

/// `raven send`: one note for a contact with an open alert, none for a
/// warning or a notice, none for another contact.
#[test]
fn send_notes_only_an_open_alert_about_that_contact() {
    let (book, alerts, sara, rena) = scene();
    let view = View::of(alerts, &book);
    assert_eq!(
        send_note_of(&view, &key(&sara), &clock()).as_deref(),
        Some(
            "Note: An invite had a different key from the Sara you verified (this morning). \
             Your message is still protected and is sent anyway. Compare security words with \
             Sara when you can (raven security)."
        )
    );
    assert_eq!(
        send_note_of(&view, &key(&rena), &clock()),
        None,
        "a warning"
    );
    let other = contact(0x33, "Omid", true);
    assert_eq!(send_note_of(&view, &key(&other), &clock()), None);
}

#[test]
fn verify_names_the_contact_as_one_shell_word() {
    let mut c = contact(0x5a, "Sara", true);
    assert_eq!(verify_arg(&c).as_deref(), Some("--petname Sara"));
    c.petname = "Sara K. (work)".into();
    assert_eq!(
        verify_arg(&c).as_deref(),
        Some("--petname \"Sara K. (work)\"")
    );
    c.petname = "a\"b$c`d".into();
    assert_eq!(verify_arg(&c).as_deref(), Some("--petname \"abcd\""));
    c.petname = String::new();
    assert_eq!(verify_arg(&c).as_deref(), Some("@sara"));
    c.public_tag = String::new();
    assert_eq!(verify_arg(&c), None);
    assert_eq!(display_name(&c), "an unnamed contact");
}

/// A temporary sealed profile (a debug build with the lab file backend),
/// as the ledger needs one; `None` where this machine cannot make one.
fn sealed_profile() -> Option<tempfile::TempDir> {
    let lab = std::env::var("RAVEN_CHAT_HISTORY_BACKEND").is_ok_and(|v| v == "locked-file");
    if !(cfg!(windows) || (cfg!(debug_assertions) && lab)) {
        eprintln!("skipped: needs a debug build and RAVEN_CHAT_HISTORY_BACKEND=locked-file");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    std::fs::write(dd.join(raven_core::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
    let report =
        raven_core::privacy::migrate_all(dd, now_ms(), raven_core::at_rest::MigratePolicy::Allow)
            .unwrap();
    assert_eq!(report.outcome, raven_core::privacy::MigrateOutcome::Sealed);
    Some(dir)
}

/// The events gate for this thread, shut again when it drops.
struct Gate;

impl Gate {
    fn open() -> Option<Self> {
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        if raven_core::security_sense::live() {
            Some(Gate)
        } else {
            security_gate::set_lab_for_this_thread(SecGate::Events, None);
            None
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
    }
}

/// With a real ledger: reading never creates it; a match in `contact
/// verify` reads whether a downgrade alert was open, then resolves every
/// notice about that contact (and only it); `send` notes the other's;
/// `resolve` and `clear` empty it; with the gate shut nothing is read.
#[test]
fn a_match_resolves_that_contacts_notices_and_reads_the_floor_alert() {
    let Some(dir) = sealed_profile() else {
        return;
    };
    let dd = dir.path();
    {
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
        assert!(matches!(open_ledger(dd), Ok(Opened::Off)));
        assert_eq!(resolve_on_match(dd, &[1; 32]), Ok(Verified::default()));
        cmd_list(dd, false).unwrap();
        cmd_explain(dd, 1, true).unwrap();
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
    }
    let Some(_gate) = Gate::open() else {
        return;
    };
    let sara = contact(0x5a, "Sara", true);
    let rena = contact(0x7e, "Rena", true);
    super::super::save_contacts(dd, &[sara.clone(), rena.clone()]).unwrap();
    // Nothing noted yet: nothing read, no file made.
    assert!(matches!(open_ledger(dd), Ok(Opened::Nothing)));
    assert_eq!(send_note(dd, &sara.pub_hex), None);
    cmd_list(dd, false).unwrap();
    assert!(!ledger_path(dd).exists());
    let now = now_ms();
    let mut ledger = SecurityLedger::open(dd).unwrap();
    let mut note = |kind, peer, severity| {
        let ev = SecEvent::new(kind, Attribution::Contact { peer }, Via::Local, now);
        ledger.record(&ev, severity, now).unwrap();
    };
    note(
        SecKind::CapabilityDowngrade,
        key(&sara),
        Severity::Suspicious,
    );
    note(SecKind::KeyChangeAttempt, key(&sara), Severity::Alert);
    note(SecKind::KeyChangeAttempt, key(&rena), Severity::Alert);
    ledger.flush(now).unwrap();
    drop(ledger);
    let open = || {
        SecurityLedger::open(dd)
            .unwrap()
            .open_alerts()
            .unwrap()
            .len()
    };
    assert_eq!(open(), 3);
    assert!(send_note(dd, &sara.pub_hex)
        .unwrap()
        .starts_with("Note: An invite had a different key from the Sara you verified ("));
    assert_eq!(
        doctor_rows(dd, &[sara.clone(), rena.clone()])[0],
        ("security", "3 open alerts (raven security)".to_string())
    );
    assert!(open_about(dd, &sara.pub_hex), "checked again at a terminal");
    assert!(!open_about(dd, &contact(0x33, "Omid", true).pub_hex));
    let verified = resolve_on_match(dd, &key(&sara)).unwrap();
    assert_eq!(
        verified,
        Verified {
            floor_alert: true,
            resolved: 2
        }
    );
    assert_eq!(
        resolved_line("Sara", &verified).unwrap(),
        format!("{C_DIM}Resolved 2 security notices about Sara.{C_RESET}")
    );
    assert_eq!(open(), 1, "only Rena's is left");
    assert_eq!(send_note(dd, &sara.pub_hex), None);
    assert!(!open_about(dd, &sara.pub_hex));
    assert!(send_note(dd, &rena.pub_hex).is_some());
    // Again: nothing open about Sara now.
    assert_eq!(resolve_on_match(dd, &key(&sara)), Ok(Verified::default()));
    // Rena's keeps its own number; Sara's numbers name nothing open now.
    let left = view_of(&open_ledger(dd).unwrap(), &Book::read(dd)).unwrap();
    let rena_n = usize::try_from(left.shown[0].number()).unwrap();
    let gone = (1..=3).find(|n| *n != rena_n).unwrap();
    cmd_explain(dd, rena_n, false).unwrap();
    assert_eq!(
        cmd_explain(dd, gone, false),
        Err(text::no_such_notice(gone))
    );
    cmd_resolve(dd, rena_n, false).unwrap();
    assert_eq!(open(), 0);
    assert_eq!(
        cmd_resolve(dd, rena_n, true),
        Err(text::no_such_notice(rena_n))
    );
    // `clear --yes` (the typed word is the black-box test's): everything goes.
    let mut ledger = SecurityLedger::open(dd).unwrap();
    let ev = SecEvent::new(
        SecKind::BindingMismatch,
        Attribution::Contact { peer: key(&rena) },
        Via::Local,
        now,
    );
    ledger.record(&ev, Severity::Alert, now).unwrap();
    ledger.flush(now).unwrap();
    drop(ledger);
    assert_eq!(open(), 1);
    cmd_clear(dd, true, true).unwrap();
    assert_eq!(open(), 0);
    let ledger = SecurityLedger::open(dd).unwrap();
    assert!(ledger.counts(0).unwrap().is_empty());
}

/// The terminal app (P6.31) reads the same alerts and warnings in the same
/// words, with whom each is about (a mailbox's friend too, never a relay),
/// coarse times, the details (a key prefix only for a verified friend) and
/// the counts of the last 7 days.
#[test]
fn the_terminal_app_reads_the_same_notices() {
    let (book, mut alerts, sara, rena) = scene();
    alerts.push(alert(
        4,
        SecKind::RelayLinkBroken,
        Some(LedgerSubject::Carrier {
            key: [0xEE; 32],
            role: CarrierRole::Relay,
        }),
        Severity::Suspicious,
    ));
    let week = vec![(sara.pub_hex.clone(), 3)];
    let read = app_read_of(View::of(alerts, &book), week.clone(), &clock());
    assert_eq!(read.kept, Kept::Live);
    assert_eq!(read.counted, 1);
    assert_eq!(read.week, week);
    assert_eq!(read.notices.len(), 3);
    let one = &read.notices[0];
    assert_eq!((one.id, one.alert), (1, true));
    assert_eq!(one.peer.as_deref(), Some(sara.pub_hex.as_str()));
    assert_eq!(
        (one.name.as_str(), one.when.as_str()),
        ("Sara", "this morning")
    );
    assert_eq!(
        one.text.headline,
        "An invite had a different key from the Sara you verified"
    );
    assert_eq!(one.text.act, text::Act::CompareWords);
    assert_eq!(
        one.details,
        vec![
            (
                "About",
                format!("Sara (verified friend, key {})", &sara.pub_hex[..8])
            ),
            ("How serious", "alert".to_string()),
            ("Code", "SEC_KEY_CHANGE_ATTEMPT (27)".to_string()),
        ]
    );
    let two = &read.notices[1];
    assert_eq!((two.id, two.alert), (2, false));
    assert_eq!(
        two.peer.as_deref(),
        Some(rena.pub_hex.as_str()),
        "a mailbox"
    );
    assert_eq!(two.when, "2 times, latest this afternoon");
    assert!(two
        .details
        .contains(&("Raven's action", "CUSTODIAN_PARKED".to_string())));
    assert!(!format!("{:?}", two.details).contains(&rena.pub_hex[..8]));
    let relay = &read.notices[2];
    assert_eq!(relay.peer, None, "a relay is nobody's friend");
}

/// With a real ledger: the app's read never creates it, says whether
/// notices are kept, counts the week per contact, and resolves one by its
/// id.
#[test]
fn the_terminal_app_reads_and_resolves_a_real_ledger() {
    let Some(dir) = sealed_profile() else {
        return;
    };
    let dd = dir.path();
    security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
    assert_eq!(app_read(dd).unwrap(), AppRead::default());
    assert_eq!(app_resolve(dd, 1), Ok(false));
    security_gate::set_lab_for_this_thread(SecGate::Events, None);
    let Some(_gate) = Gate::open() else {
        return;
    };
    let sara = contact(0x5a, "Sara", true);
    super::super::save_contacts(dd, std::slice::from_ref(&sara)).unwrap();
    let nothing = app_read(dd).unwrap();
    assert_eq!(nothing.kept, Kept::Live);
    assert!(nothing.notices.is_empty() && nothing.week.is_empty());
    assert!(!ledger_path(dd).exists(), "reading never creates it");
    let now = now_ms();
    let mut ledger = SecurityLedger::open(dd).unwrap();
    let ev = SecEvent::new(
        SecKind::ObjectAuthFail,
        Attribution::Contact { peer: key(&sara) },
        Via::Local,
        now,
    );
    ledger.record(&ev, Severity::Alert, now).unwrap();
    ledger.flush(now).unwrap();
    drop(ledger);
    let read = app_read(dd).unwrap();
    assert_eq!(read.notices.len(), 1);
    assert_eq!(read.notices[0].peer.as_deref(), Some(sara.pub_hex.as_str()));
    assert_eq!(
        read.notices[0].text.headline,
        "Messages from Sara failed Raven's security check"
    );
    assert_eq!(read.week, vec![(sara.pub_hex.clone(), 1)]);
    assert_eq!(app_resolve(dd, read.notices[0].id), Ok(true));
    assert_eq!(app_resolve(dd, read.notices[0].id), Ok(false), "once");
    let after = app_read(dd).unwrap();
    assert!(after.notices.is_empty());
    assert_eq!(after.week, read.week, "the counts stay");
}

/// Phase 6 review (sensing-6): a notice keeps its number while it is open,
/// so `resolve N` closes the notice the person listed even when a more
/// severe one about someone else was noted in between (and now sorts above
/// it); a number no open notice has is refused, never another notice.
#[test]
fn resolve_closes_the_listed_notice_whatever_was_noted_since() {
    let Some(dir) = sealed_profile() else {
        return;
    };
    let dd = dir.path();
    let Some(_gate) = Gate::open() else {
        return;
    };
    let sara = contact(0x5a, "Sara", true);
    let rena = contact(0x7e, "Rena", true);
    let omid = contact(0x33, "Omid", true);
    super::super::save_contacts(dd, &[sara.clone(), rena.clone(), omid.clone()]).unwrap();
    let now = now_ms();
    let note = |who: &Contact, kind, severity| {
        let mut ledger = SecurityLedger::open(dd).unwrap();
        let peer = key(who);
        let ev = SecEvent::new(kind, Attribution::Contact { peer }, Via::Local, now);
        ledger.record(&ev, severity, now).unwrap();
        ledger.flush(now).unwrap();
    };
    let view = || view_of(&open_ledger(dd).unwrap(), &Book::read(dd)).unwrap();
    let about = |s: &Shown| s.alert.subject;
    note(&sara, SecKind::KeyChangeAttempt, Severity::Alert);
    note(&rena, SecKind::CapabilityDowngrade, Severity::Suspicious);
    // `raven security`: Sara's alert, then Rena's warning, each numbered.
    let listed = view();
    let rena_n = listed.shown[1].number();
    assert_eq!(
        about(&listed.shown[1]),
        Some(LedgerSubject::Contact(key(&rena)))
    );
    let lines = list_lines(&listed, None, &clock());
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with(&format!("{rena_n}. - "))),
        "{lines:?}"
    );
    cmd_list(dd, false).unwrap();
    // Before the person types `resolve`, an alert about Omid arrives and
    // sorts above Rena's warning.
    note(&omid, SecKind::KeyChangeAttempt, Severity::Alert);
    let moved = view();
    assert_eq!(moved.shown.len(), 3);
    assert_eq!(moved.shown[2].number(), rena_n, "Rena's moved down");
    assert!(cmd_resolve(dd, 99, false).is_err(), "no such notice");
    cmd_resolve(dd, usize::try_from(rena_n).unwrap(), false).unwrap();
    let open: Vec<_> = view().shown.iter().map(about).collect();
    assert_eq!(open.len(), 2, "only Rena's was resolved: {open:?}");
    assert!(!open.contains(&Some(LedgerSubject::Contact(key(&rena)))));
    for who in [&sara, &omid] {
        assert!(open.contains(&Some(LedgerSubject::Contact(key(who)))));
    }
}
