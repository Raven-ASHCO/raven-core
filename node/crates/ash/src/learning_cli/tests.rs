//! The learning CLI (P6.17): status rows and sentences, reset over IPC or
//! the file, the switch, and `off --forget`.

use super::*;
use raven_core::ipc::IPC_VERSION;
use raven_core::learning::explain::{Detail, Tally, WaitNote};
use raven_core::learning::model::{ArmKey, Model};
use raven_core::learning::observe::{DialTiming, Evidence, FrameKind, Observation};
use raven_core::learning::rank::Order;
use raven_core::learning::store::{SealError, Zeroizing};
use raven_core::outbox::{DeliveryPath, OutboxRoute};

const BOB: [u8; 32] = [0xB0; 32];
const CAROL: [u8; 32] = [0xC0; 32];
const STRANGER: [u8; 32] = [0xEE; 32];
const NET: &str = "lab-net";

fn contact(petname: &str, key: &[u8; 32]) -> Contact {
    Contact {
        petname: petname.into(),
        public_tag: String::new(),
        alias: String::new(),
        address: format!("rvn1{}", hex::encode(&key[..4])),
        pub_hex: hex::encode(key),
        pinned: true,
        lan_dial: "192.168.1.20:7420".into(),
        internet_dial: String::new(),
        p2p: String::new(),
        p2p_via: Vec::new(),
        p2p_next: String::new(),
        custodians: Vec::new(),
        hide_ip: false,
        onion: String::new(),
        lan_dial_trusted: false,
    }
}

fn row(key: &[u8; 32], order: &[&str], why: &str) -> LearningRow {
    LearningRow {
        peer_pub_hex: hex::encode(key),
        order: order.iter().map(|s| s.to_string()).collect(),
        why: why.into(),
    }
}

fn learning(state: &str, rows: Vec<LearningRow>) -> LearningStatus {
    LearningStatus {
        state: state.into(),
        contacts: 3,
        networks: 2,
        relays: 1,
        carriers: 2,
        observations_24h: 41,
        probes_24h: 5,
        dropped_24h: 0,
        contradictions: 0,
        would_reorder_24h: 7,
        saved_age_s: Some(12),
        rows,
    }
}

fn status(learning: Option<LearningStatus>) -> Result<IpcResponse, String> {
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
        nearby: None,
        tor: None,
        learning: learning.map(Box::new),
        locked: None,
        updates: None,
    })
}

const FAILING: &str =
    "learn: state=on order=internet,lan why=failing fail=lan:3/4 ok=internet:4/4 \
     age=2h";

/// The rows name contacts as this book does (any case of the key), skip
/// keys it does not hold, and say each reason as a sentence; the state, the
/// counts and the save age come first. Every other state and the views
/// without a report say one line; `--json` is the report itself.
#[test]
fn learning_status_names_contacts_and_skips_unknown_keys() {
    let book = vec![contact("Bob", &BOB), contact("Carol", &CAROL)];
    let mut carol = row(
        &CAROL,
        &["lan_dial", "internet_dial"],
        "learn: state=on order=lan,internet why=kept age=5m",
    );
    carol.peer_pub_hex = carol.peer_pub_hex.to_uppercase();
    let report = learning(
        "on",
        vec![
            row(&BOB, &["internet_dial", "lan_dial"], FAILING),
            row(
                &STRANGER,
                &["lan_dial"],
                "learn: state=on order=lan why=cold",
            ),
            carol,
        ],
    );
    let daemon = status(Some(report.clone()));
    let v = view(&daemon, true, false);
    assert_eq!(v, LearningView::Live(&report));
    let lines = status_lines(&v, &book);
    assert_eq!(
        lines,
        vec![
            "learning: on",
            "  remembers 3 contacts on 2 networks, 1 relay and 2 mail-friend records",
            "  last 24 hours: 41 tries watched, 5 probes, 0 dropped, 0 learned orders set aside",
            "  saved 12 s ago",
            "  Bob: Internet first on this network: LAN did not answer 3 of the last 4 tries \
             (2 h ago)",
            "  Carol: the usual order: it works best here (5 min ago)",
        ]
    );
    let all = lines.join("\n");
    assert!(!all.contains(&hex::encode(STRANGER)), "{all}");
    assert!(!all.to_lowercase().contains(&hex::encode(BOB)), "{all}");
    assert!(!all.contains("192.168"), "{all}");

    // `raven status`: the same rows, at most 8 and then `(+N more)`; no
    // section while off or without a report.
    let many: Vec<LearningRow> = (0..11u8)
        .map(|i| {
            row(
                &[i; 32],
                &["lan_dial"],
                "learn: state=on order=lan why=cold",
            )
        })
        .collect();
    let crowd: Vec<Contact> = (0..11u8)
        .map(|i| contact(&format!("Friend {i}"), &[i; 32]))
        .collect();
    let (note, shown) = status_section(&status(Some(learning("on", many))), &crowd).unwrap();
    assert_eq!(note, "(Raven tries first what worked on this network)");
    assert_eq!(shown.len(), SHOWN_ROWS + 1);
    assert_eq!(shown[0].0, "Friend 0");
    assert_eq!(
        shown[0].1,
        "the usual order: too few tries to learn from yet"
    );
    assert_eq!(shown[SHOWN_ROWS], (String::new(), "(+3 more)".to_string()));
    let (note, shown) =
        status_section(&status(Some(learning("memory_only", Vec::new()))), &book).unwrap();
    assert_eq!(
        note,
        "learning is on, in memory only (this profile's key is not available here: nothing is \
         saved)"
    );
    assert!(shown.is_empty());
    assert_eq!(
        status_section(&status(Some(learning("off", Vec::new()))), &book),
        None
    );
    assert_eq!(status_section(&status(None), &book), None);
    assert_eq!(status_section(&Err("down".into()), &book), None);

    // No rows this book names.
    let lines = status_lines(&LearningView::Live(&learning("on", Vec::new())), &book);
    assert_eq!(
        lines.last().unwrap(),
        "  (nothing learned about your contacts on this network yet)"
    );
    // The switch off: one line.
    assert_eq!(
        status_lines(&LearningView::Live(&learning("off", Vec::new())), &book),
        vec!["learning: off (raven learning on)"]
    );
    let lines = status_lines(
        &LearningView::Live(&LearningStatus {
            saved_age_s: None,
            ..learning("reset_after_unreadable", Vec::new())
        }),
        &book,
    );
    assert_eq!(
        lines[0],
        "learning: on, started over (what was learned could not be read)"
    );
    assert!(lines.contains(&"  not saved yet".to_string()), "{lines:?}");

    // Without a report: an old raven-node or the hold, this build's hold,
    // the switch off, no raven-node.
    let down: Result<IpcResponse, String> = Err("raven-node is not running".into());
    for (daemon, live, off, want) in [
        (status(None), true, false, "learning: held in this build"),
        (down.clone(), false, false, "learning: held in this build"),
        (down.clone(), false, true, "learning: held in this build"),
        (
            down.clone(),
            true,
            true,
            "learning: off (raven learning on)",
        ),
        (
            down.clone(),
            true,
            false,
            "learning: needs raven-node running",
        ),
    ] {
        assert_eq!(status_lines(&view(&daemon, live, off), &book), vec![want]);
    }
    // `--json`: the report as raven-node gave it, else a state alone.
    let json = status_json(&LearningView::Live(&report));
    let back: LearningStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
    for (v, state) in [
        (LearningView::Held, "held"),
        (LearningView::Off, "off"),
        (LearningView::NeedsNode, "not_running"),
    ] {
        let back: LearningStatus = serde_json::from_str(&status_json(&v)).unwrap();
        assert_eq!(
            back,
            LearningStatus {
                state: state.into(),
                ..LearningStatus::default()
            }
        );
    }
}

/// Every reason token reads as its own plain sentence, with the counts and
/// the age the block carries and none of its tokens; a block this build
/// cannot read says the order alone.
#[test]
fn learning_status_explains_each_reason_token() {
    let detail = Detail {
        state: State::On,
        fail: Some(Tally {
            carrier: OutboxCarrier::Lan,
            k: 3,
            n: 4,
        }),
        ok: Some(Tally {
            carrier: OutboxCarrier::P2p,
            k: 2,
            n: 2,
        }),
        wait: Some(WaitNote {
            carrier: OutboxCarrier::Internet,
            secs: 4,
        }),
        age_s: Some(90),
    };
    let mut seen = std::collections::BTreeSet::new();
    for why in Why::ALL {
        let order = Order {
            carriers: vec![OutboxCarrier::P2p, OutboxCarrier::Lan],
            why,
            detail,
        };
        let raw = order.render();
        let text = reason_text(&raw).unwrap_or_else(|| panic!("{raw}"));
        assert!(seen.insert(text.clone()), "{why:?} repeats {text}");
        assert!(text.ends_with(" (1 min ago)"), "{text}");
        for token in [
            "learn:", "why=", "order=", "fail=", "ok=", "state=", "_dial",
        ] {
            assert!(!text.contains(token), "{why:?}: {text}");
        }
        let want = match why {
            Why::Cold => "too few tries",
            Why::Kept => "it works best here",
            Why::Faster => "p2p first on this network: it answered sooner (2 of the last 2 tries",
            Why::Failing => "p2p first on this network: LAN did not answer 3 of the last 4 tries",
            Why::Recovering => "p2p moves back up on this network: it worked 2 of the last 2",
            Why::Contradiction => "did not fit",
            Why::Unreadable => "could not be read",
            Why::Off => "learning is off",
            Why::Held => "held in this build",
            Why::Shadow => "only watches",
        };
        assert!(text.contains(want), "{why:?}: {text}");
        // A row's text is the sentence.
        assert_eq!(row_text(&row(&BOB, &["p2p_dial", "lan_dial"], &raw)), text);
    }
    // Without the optional fields: still a sentence.
    assert_eq!(
        reason_text("learn: state=on order=internet,lan why=failing").as_deref(),
        Some("Internet first on this network: the usual first did not answer")
    );
    assert_eq!(
        reason_text("learn: state=on order=lan why=recovering").as_deref(),
        Some("back toward the usual order on this network")
    );
    // A one-try tally reads "1 of the last 1 try".
    assert_eq!(
        reason_text("learn: state=on order=internet,lan why=failing fail=lan:1/1").as_deref(),
        Some("Internet first on this network: LAN did not answer 1 of the last 1 try")
    );
    // A newer raven-node's reason (or none): the order alone.
    for raw in [
        "learn: state=on order=internet,lan why=telepathy",
        "",
        "junk",
    ] {
        assert_eq!(reason_text(raw), None, "{raw}");
        assert_eq!(
            row_text(&row(&BOB, &["internet_dial", "lan_dial"], raw)),
            "Internet, then LAN"
        );
    }
    assert_eq!(
        row_text(&row(&BOB, &["mesh_\u{1b}[2J"], "")),
        "mesh_",
        "an unknown label is made safe for the terminal"
    );
    assert_eq!(row_text(&row(&BOB, &[], "")), "a learned order");
}

/// Identity, or the error given for opening (`unavailable`).
#[derive(Default)]
struct TestSealer {
    unavailable: bool,
}

impl Sealer for TestSealer {
    fn protect(&self, _dd: &Path, pt: &[u8]) -> Result<Vec<u8>, SealError> {
        Ok(pt.to_vec())
    }

    fn unprotect(&self, _dd: &Path, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        if self.unavailable {
            return Err(SealError::Unavailable);
        }
        Ok(Zeroizing::new(ct.to_vec()))
    }
}

fn receipt(contact: [u8; 32], now: u64) -> Observation {
    Observation {
        contact,
        net: Some(NET.into()),
        net_changed: false,
        carrier: OutboxCarrier::Lan,
        path: Some(DeliveryPath::Direct),
        relay: None,
        kind: FrameKind::Message,
        evidence: Evidence::Receipt,
        timing: DialTiming {
            connect_ms: Some(40),
            reply_ms: Some(90),
            total_ms: 250,
        },
        karn_exclude: false,
        at_ms: now,
    }
}

/// A saved model with rows for Bob and Carol.
fn plant(dd: &Path, now: u64) {
    let mut m = Model::new_empty([7; 32]);
    m.observe(&receipt(BOB, now), now);
    m.observe(&receipt(CAROL, now), now);
    store::save(dd, &TestSealer::default(), &m, now).unwrap();
}

fn has_rows(dd: &Path, who: &[u8; 32], now: u64) -> bool {
    let (m, state) = store::load(dd, &TestSealer::default(), now);
    assert_eq!(state, StoreState::On);
    m.arm(&ArmKey {
        contact: *who,
        net: Some(NET.into()),
        carrier: OutboxCarrier::Lan,
    })
    .is_some()
}

fn file(dd: &Path) -> std::path::PathBuf {
    dd.join(store::LEARNING_FILE)
}

/// `reset` asks on a terminal (`y`/`yes`; anything else, Enter or EOF
/// cancels) and needs `--yes` without one. A running raven-node does the
/// work (IPC; nothing here touches the file); with none running, one that
/// holds learning or an older one, the file is changed here with the same
/// sealer; a raven-node that cannot forget changes nothing. Route memory
/// goes with it, for the contact or for everyone.
#[test]
fn reset_asks_on_a_tty_and_uses_ipc_or_the_file() {
    // The question and the decision.
    assert_eq!(
        reset_question(Some("Bob")),
        "Forget what Raven learned about delivery for Bob? [y/N] "
    );
    assert_eq!(
        reset_question(None),
        "Forget what Raven learned about delivery for everyone? [y/N] "
    );
    assert_eq!(
        confirmed(true, false, || panic!("--yes asks nothing")),
        Ok(())
    );
    let err = confirmed(false, false, || panic!("no terminal: no question")).unwrap_err();
    assert!(err.contains("--yes"), "{err}");
    for (answer, go) in [
        (Some("y"), true),
        (Some(" YES "), true),
        (Some(""), false),
        (Some("n"), false),
        (Some("yes please"), false),
        (None, false),
    ] {
        let got = confirmed(false, true, || answer.map(str::to_owned));
        assert_eq!(got.is_ok(), go, "{answer:?}");
        if !go {
            assert!(got.unwrap_err().contains("nothing forgotten"));
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let now = now_ms();
    let id = TestSealer::default();
    // No file and no node: nothing, and no lock file made.
    let down = ipc_client::learning_reset(dd, None).unwrap_err();
    assert!(ipc_client::error_means_not_running(&down), "{down}");
    assert_eq!(
        forget_learned(dd, None, |_| Err(down.clone()), &id, now),
        Ok(0)
    );
    assert!(!dd.join(store::LEARNING_LOCK).exists());

    // A running raven-node: asked for exactly this contact; the file is its
    // to change.
    plant(dd, now);
    let before = std::fs::read(file(dd)).unwrap();
    let asked = std::cell::RefCell::new(Vec::new());
    let by_node = forget_learned(
        dd,
        Some(&BOB),
        |hex| {
            asked.borrow_mut().push(hex.map(str::to_owned));
            Ok(Some(1))
        },
        &id,
        now,
    );
    assert_eq!(by_node, Ok(1));
    assert_eq!(*asked.borrow(), vec![Some(hex::encode(BOB))]);
    assert_eq!(std::fs::read(file(dd)).unwrap(), before);
    // One that cannot forget (or does not answer): an error, the file kept.
    for e in [
        "LEARNING_RESET: the learning file could not be changed; try again",
        "IPC_VERSION: x",
    ] {
        let err = forget_learned(dd, None, |_| Err(e.to_string()), &id, now).unwrap_err();
        assert!(err.contains("nothing changed"), "{err}");
        assert_eq!(std::fs::read(file(dd)).unwrap(), before);
    }

    // None running: one contact's rows leave the file, the others stay.
    assert_eq!(
        forget_learned(dd, Some(&BOB), |_| Err(down.clone()), &id, now),
        Ok(1)
    );
    assert!(!has_rows(dd, &BOB, now) && has_rows(dd, &CAROL, now));
    assert_eq!(
        forget_learned(dd, Some(&BOB), |_| Err(down.clone()), &id, now),
        Ok(0),
        "nothing left to forget"
    );
    // The hold or an older raven-node (`Ok(None)`): the file, for everyone.
    assert_eq!(forget_learned(dd, None, |_| Ok(None), &id, now), Ok(1));
    assert!(!file(dd).exists());

    // A file that does not open here: one contact cannot be taken out (an
    // error, kept); everyone's goes.
    plant(dd, now);
    let closed = TestSealer { unavailable: true };
    let err = forget_in_file(dd, Some(&BOB), &closed, now).unwrap_err();
    assert!(err.contains("for everyone deletes it"), "{err}");
    assert!(file(dd).exists());
    assert_eq!(forget_in_file(dd, None, &closed, now), Ok(0));
    assert!(!file(dd).exists());
    // One that could not be read at all: nothing to forget, kept for the
    // next save to replace.
    raven_core::paths::atomic_write_private(&file(dd), b"not sealed").unwrap();
    assert_eq!(forget_in_file(dd, Some(&BOB), &id, now), Ok(0));
    assert!(file(dd).exists());

    // Route memory: the contact's, then everyone's (OD6a-10).
    let route = OutboxRoute {
        carrier: OutboxCarrier::Internet,
        dial: "203.0.113.7:7422".into(),
    };
    let above = OutboxRoute {
        carrier: OutboxCarrier::Lan,
        dial: "192.168.1.250:7420".into(),
    };
    for peer in [BOB, CAROL] {
        raven_core::route_memory::learn(
            dd,
            &peer,
            &[above.clone(), route.clone()],
            None,
            &[(above.clone(), false), (route.clone(), true)],
            Some("n1"),
            now,
            now,
        )
        .unwrap();
    }
    let remembered =
        |peer: &[u8; 32]| raven_core::route_memory::preferred_route(dd, peer, Some("n1"), now);
    assert_eq!(forget_route_memory(dd, Some(&BOB)), None);
    assert_eq!((remembered(&BOB), remembered(&CAROL)), (None, Some(route)));
    assert_eq!(forget_route_memory(dd, None), None);
    assert_eq!(remembered(&CAROL), None);

    // What it says.
    assert_eq!(
        reset_line(Some("Bob"), 1),
        "Forgot what Raven learned about delivery for Bob (1 contact cleared)."
    );
    assert_eq!(
        reset_line(None, 3),
        "Forgot what Raven learned about delivery for everyone (3 contacts cleared)."
    );
    assert_eq!(
        reset_line(None, 0),
        "Nothing was learned about delivery for everyone yet: nothing to forget (cleared 0)."
    );
}

/// `on`/`off` save `node_policy.learning` and keep every other setting;
/// over an unreadable policy they change nothing.
#[test]
fn off_refuses_an_unreadable_policy() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let path = raven_core::node_policy::policy_path(dd);
    std::fs::write(&path, b"{ not json").unwrap();
    for (on, forget) in [(false, false), (false, true), (true, false)] {
        let err = switch(dd, on, forget).unwrap_err();
        assert!(err.contains("node_policy.json is unreadable"), "{err}");
        assert!(err.contains("nothing changed"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json");
    }

    std::fs::remove_file(&path).unwrap();
    raven_core::node_policy::update_policy(dd, |p| p.hide_ip = true).unwrap();
    let lines = switch(dd, false, false).unwrap();
    assert!(lines[0].starts_with("ok learning: off"), "{lines:?}");
    let saved = raven_core::node_policy::load_policy(dd);
    assert_eq!((saved.learning, saved.hide_ip), (Some(false), true));
    assert!(switch_off(dd));
    let lines = switch(dd, true, false).unwrap();
    assert!(lines[0].starts_with("ok learning: on"), "{lines:?}");
    let saved = raven_core::node_policy::load_policy(dd);
    assert_eq!((saved.learning, saved.hide_ip), (Some(true), true));
    assert!(!switch_off(dd));
    // While held, it says the choice waits for the release.
    assert_eq!(
        lines.iter().any(|l| l.contains("held in this build")),
        !raven_core::learning::learning_live(),
        "{lines:?}"
    );
}

/// `off --forget` saves the switch off and deletes the learning file (no
/// raven-node here: the file is removed whatever opens); `off` alone keeps
/// it.
#[test]
fn off_forget_deletes_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let dd = dir.path();
    let now = now_ms();
    plant(dd, now);
    switch(dd, false, false).unwrap();
    assert!(file(dd).exists(), "off alone keeps what was learned");
    let lines = switch(dd, false, true).unwrap();
    assert!(!file(dd).exists());
    assert_eq!(
        raven_core::node_policy::load_policy(dd).learning,
        Some(false)
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("  forgot what was learned (")),
        "{lines:?}"
    );
    // Again: nothing there, still fine.
    assert!(switch(dd, false, true).is_ok());
    assert!(!file(dd).exists());

    // `wait_until_off` stops at once without a report or once it is off,
    // and waits no longer than it is told.
    let asked = std::cell::Cell::new(0);
    wait_until_off(
        || {
            asked.set(asked.get() + 1);
            status(None)
        },
        Duration::from_secs(5),
    );
    assert_eq!(asked.get(), 1);
    let asked = std::cell::Cell::new(0);
    wait_until_off(
        || {
            asked.set(asked.get() + 1);
            status(Some(learning(
                if asked.get() < 3 { "on" } else { "off" },
                Vec::new(),
            )))
        },
        Duration::from_secs(5),
    );
    assert_eq!(asked.get(), 3);
    let started = Instant::now();
    wait_until_off(
        || status(Some(learning("on", Vec::new()))),
        Duration::from_millis(300),
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}
