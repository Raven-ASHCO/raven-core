use super::*;
use raven_core::custody_gate::{
    set_custody_gates_for_this_thread, set_custody_hints_for_this_thread,
};
use raven_core::node_policy::{load_policy, save_policy};

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn never(_: &str) -> Option<String> {
    panic!("must not ask")
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
    key_of(c).unwrap()
}

/// What a contact told this node: (who, custody offer, custodian tags).
type Told<'a> = (&'a Contact, Option<u8>, Vec<[u8; 32]>);

/// learned_routes.json: each [`Told`] is a live snapshot with that custody
/// offer and those custodian tags.
fn learned(dir: &Path, told: &[Told<'_>]) {
    let now = now_ms();
    let rows: Vec<serde_json::Value> = told
        .iter()
        .map(|(c, offer, tags)| {
            let mut row = serde_json::json!({
                "pub_hex": c.pub_hex,
                "generation": 1,
                "received_at_ms": now,
                "expires_at_ms": now + 3_600_000,
                "via": "lan",
            });
            if let Some(o) = offer {
                row["custody_offer"] = serde_json::json!(o);
            }
            if !tags.is_empty() {
                row["custodian_tags"] =
                    serde_json::json!(tags.iter().map(hex::encode).collect::<Vec<_>>());
                row["custodian_tag_flags"] = serde_json::json!(vec![0u8; tags.len()]);
            }
            row
        })
        .collect();
    std::fs::write(
        dir.join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
        serde_json::Value::Array(rows).to_string(),
    )
    .unwrap();
}

fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Off a terminal without --yes: exit 2, "add --yes", nothing saved. On a
/// terminal the consent is asked; Enter, EOF or anything but y/yes changes
/// nothing; AUTO is kept either way.
#[test]
fn node_custody_on_off_a_tty_without_yes_refuses_and_changes_nothing() {
    let dir = tmp();
    save_policy(
        dir.path(),
        &NodePolicy {
            auto_policy: true,
            ..NodePolicy::default()
        },
    )
    .unwrap();
    let before = std::fs::read(raven_core::policy_path(dir.path())).unwrap();
    let err = custody_on_with(dir.path(), false, false, never).unwrap_err();
    assert_eq!(err.code, 2);
    assert!(err.text.contains("add --yes"), "{}", err.text);
    assert!(err.text.contains("nothing changed"), "{}", err.text);
    assert_eq!(
        std::fs::read(raven_core::policy_path(dir.path())).unwrap(),
        before
    );
    for answer in [None, Some(""), Some("n"), Some("sure"), Some("yess")] {
        let mut question = String::new();
        let lines = custody_on_with(dir.path(), false, true, |q| {
            question = q.to_string();
            answer.map(String::from)
        })
        .unwrap();
        assert_eq!(question, format!("{CUSTODIAN_CONSENT}\n{TURN_ON}"));
        assert_eq!(
            lines,
            ["nothing changed: friend custody stays off"],
            "{answer:?}"
        );
        assert!(!load_policy(dir.path()).custody);
    }
    for answer in ["y", " YES "] {
        let dir = tmp();
        let lines = custody_on_with(dir.path(), false, true, |_| Some(answer.into())).unwrap();
        assert_eq!(lines[0], "ok friend custody on");
        // Seen on the terminal already: not printed again.
        assert!(
            !lines.iter().any(|l| l.contains("Raven identities")),
            "{lines:?}"
        );
        assert!(load_policy(dir.path()).custody);
    }
}

/// --yes saves without a question, keeps AUTO and prints the consent: the
/// custodian learns who sent each message and who it is for (both Raven
/// identities), when, how big, collection time and IP addresses.
#[test]
fn node_custody_on_with_yes_saves_and_text_names_both_identities() {
    let dir = tmp();
    save_policy(
        dir.path(),
        &NodePolicy {
            auto_policy: true,
            ..NodePolicy::default()
        },
    )
    .unwrap();
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: true,
        wan: false,
    }));
    let lines = custody_on_with(dir.path(), true, false, never).unwrap();
    set_custody_gates_for_this_thread(None);
    let policy = load_policy(dir.path());
    assert!(policy.custody && policy.auto_policy);
    assert_eq!(lines[0], "ok friend custody on");
    let text = flat(&lines[1..].join("\n"));
    for words in [
        "who sent it and who it is for",
        "(both Raven identities)",
        "when, how big, and when it was collected",
        "the IP address each friend connects from",
        "At most 128 messages per pair at a time, 64 MiB in all",
    ] {
        assert!(text.contains(words), "{words}: {text}");
    }
    assert!(!text.contains("Turn on?"), "{text}");
    assert!(
        !lines.iter().any(|l| l.contains("CUSTODY_HOLD")),
        "{lines:?}"
    );
    // While the gate holds it says so.
    let dir = tmp();
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: false,
        wan: false,
    }));
    let lines = custody_on_with(dir.path(), true, false, never).unwrap();
    set_custody_gates_for_this_thread(None);
    assert_eq!(lines.last().unwrap(), &format!("note: {CUSTODY_HOLD}"));
}

/// A copy of the UPnP decision: a flag decides, a saved answer is kept, no
/// terminal asks nothing (unset), otherwise one question: y / yes is on,
/// Enter, EOF or anything else is off.
#[test]
fn custody_use_decision_table() {
    let unasked = || -> Option<String> { panic!("must not ask") };
    for (saved, flag, tty, want) in [
        (None, Some(true), true, Some(true)),
        (None, Some(false), true, Some(false)),
        (Some(false), Some(true), false, Some(true)),
        (Some(true), None, true, Some(true)),
        (Some(false), None, true, Some(false)),
        (None, None, false, None),
    ] {
        assert_eq!(
            custody_use_decision(saved, flag, tty, unasked),
            (want, false),
            "{saved:?} {flag:?} tty={tty}"
        );
    }
    for (answer, want) in [
        (Some("y"), true),
        (Some(" Yes "), true),
        (Some(""), false),
        (None, false),
        (Some("no"), false),
        (Some("sure"), false),
    ] {
        let mut asked = 0;
        let got = custody_use_decision(None, None, true, || {
            asked += 1;
            answer.map(String::from)
        });
        assert_eq!(got, (Some(want), true), "{answer:?}");
        assert_eq!(asked, 1);
    }
    // The commands: `on` off a terminal needs --yes (exit 2), `off` needs
    // nothing and says how long mail is still collected.
    let dir = tmp();
    let err = custody_use_with(dir.path(), UseArg::On { yes: false }, false, never).unwrap_err();
    assert_eq!(err.code, 2);
    assert!(err.text.contains("add --yes"), "{}", err.text);
    assert_eq!(load_policy(dir.path()).custody_use, None);
    let mut question = String::new();
    custody_use_with(dir.path(), UseArg::On { yes: false }, true, |q| {
        question = q.to_string();
        Some("y".into())
    })
    .unwrap();
    assert_eq!(question, MAILBOX_QUESTION);
    assert_eq!(load_policy(dir.path()).custody_use, Some(true));
    let lines = custody_use_with(dir.path(), UseArg::Off, false, never).unwrap();
    assert!(
        lines[0].contains("mail already left for you is still collected for up to 97 h"),
        "{lines:?}"
    );
    assert_eq!(load_policy(dir.path()).custody_use, Some(false));
    custody_use_with(dir.path(), UseArg::On { yes: true }, false, never).unwrap();
    assert_eq!(load_policy(dir.path()).custody_use, Some(true));
    assert!(flat(MAILBOX_QUESTION).contains(
        "but it learns that you wrote to someone, to whom, and when. It also sees both Raven \
         identities and how big each message is"
    ));
}

/// `raven custody home`: verified, unblocked contacts other than you, at
/// most 2; `auto` alone clears the list; a refusal changes nothing; a
/// friend that offers nothing is named in a note.
#[test]
fn custody_home_validation() {
    let dir = tmp();
    let (carol, dan, erin) = (
        contact(0x31, "Carol", true),
        contact(0x32, "Dan", true),
        contact(0x33, "Erin", true),
    );
    let (unpinned, me, blocked) = (
        contact(0x34, "Ulla", false),
        contact(0x35, "Me", true),
        contact(0x36, "Bo", true),
    );
    super::super::save_contacts(
        dir.path(),
        &[
            carol.clone(),
            dan.clone(),
            erin.clone(),
            unpinned,
            me.clone(),
            blocked.clone(),
        ],
    )
    .unwrap();
    let mut blocks = raven_core::chat_history::BlockList::load_checked(dir.path()).unwrap();
    blocks.block(&blocked.pub_hex);
    blocks.save(dir.path()).unwrap();
    learned(dir.path(), &[(&carol, Some(OFFER_REACHABLE), Vec::new())]);
    let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let home = || load_policy(dir.path()).custody_home;
    for (who, says) in [
        (&["@ulla"][..], "is not verified"),
        (&["@me"][..], "you cannot be your own mail friend"),
        (&["@bo"][..], "is blocked"),
        (
            &["@carol", "@dan", "@erin"][..],
            "at most 2 mail friends (got 3",
        ),
        (&["@carol", "auto"][..], "`auto` stands alone"),
        (&["@nobody"][..], ""),
    ] {
        let err = custody_home_with(dir.path(), &me.pub_hex, &words(who)).unwrap_err();
        assert!(err.contains(says), "{who:?}: {err}");
        assert!(home().is_empty(), "{who:?}");
    }
    let lines = custody_home_with(
        dir.path(),
        &me.pub_hex,
        &words(&["@carol", "@dan", "@carol"]),
    )
    .unwrap();
    assert_eq!(lines[0], "ok mail friends: Carol, Dan");
    assert_eq!(
        home(),
        [
            carol.pub_hex.to_ascii_lowercase(),
            dan.pub_hex.to_ascii_lowercase()
        ]
    );
    // Dan offers nothing; mailboxes are off.
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("note: Dan does not offer")),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("note: Carol")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("`raven custody use on`")),
        "{lines:?}"
    );
    let lines = custody_home_with(dir.path(), &me.pub_hex, &words(&["auto"])).unwrap();
    assert!(
        lines[0].starts_with("ok mail friends: automatic"),
        "{lines:?}"
    );
    assert!(home().is_empty());
}

/// `raven custody status`: counts only, never a name, key or address.
#[test]
fn custody_status_rows_counts_only() {
    let rows = custody_status_rows(&CustodyFacts {
        consent: Some(true),
        home: 2,
        manual: false,
        draining: 1,
        offering: 3,
        offering_wan: 1,
        offering_reachable: 2,
        holding_on: true,
        held_rows: 4,
        held_bytes: 9000,
        hints_live: true,
        listed: 0,
    });
    assert_eq!(
        rows,
        [
            "friend mailboxes   on",
            "mail friends       2 (picked automatically), 1 more still collected from (up to 97 h)",
            "offering friends   3 verified friends offer to hold mail (1 over the internet, 2 \
             reachable)",
            "holding for others on: 4 sealed messages, 9000 bytes",
        ]
    );
    // From a profile: the friends are counted, never named.
    let dir = tmp();
    let (carol, dan) = (contact(0x31, "Carol", true), contact(0x32, "Dan", true));
    super::super::save_contacts(dir.path(), &[carol.clone(), dan.clone()]).unwrap();
    learned(
        dir.path(),
        &[
            (&carol, Some(OFFER_WAN | OFFER_REACHABLE), Vec::new()),
            (&dan, Some(0), Vec::new()),
        ],
    );
    save_policy(
        dir.path(),
        &NodePolicy {
            custody_home: vec![carol.pub_hex.clone()],
            ..NodePolicy::default()
        },
    )
    .unwrap();
    set_custody_hints_for_this_thread(Some(false));
    let facts = gather_facts(dir.path());
    set_custody_hints_for_this_thread(None);
    assert_eq!(
        (
            facts.consent,
            facts.offering,
            facts.offering_wan,
            facts.offering_reachable
        ),
        (None, 2, 1, 1)
    );
    assert!(facts.manual);
    let rows = custody_status_rows(&facts);
    assert!(rows[0].contains("not decided yet"), "{rows:?}");
    assert!(rows
        .last()
        .unwrap()
        .starts_with("note: friend mailboxes are lab-only"));
    for row in &rows {
        for c in [&carol, &dan] {
            assert!(
                !row.contains(&c.petname) && !row.contains(&c.pub_hex[..16]),
                "{row}"
            );
            assert!(!row.contains(&c.address[..12]), "{row}");
        }
    }
}

/// The mailbox question at the end of `raven status`: only while never
/// answered, learned custody is live and a verified friend offers; a
/// saved answer is never asked again.
#[test]
fn mailbox_prompt_needs_an_offering_friend_and_is_asked_once() {
    let dir = tmp();
    let carol = contact(0x31, "Carol", true);
    super::super::save_contacts(dir.path(), std::slice::from_ref(&carol)).unwrap();
    let mut policy = NodePolicy::default();
    set_custody_hints_for_this_thread(Some(true));
    // Nobody offers yet.
    assert_eq!(
        mailbox_prompt(dir.path(), &mut policy, true, never),
        Ok(None)
    );
    learned(dir.path(), &[(&carol, Some(0), Vec::new())]);
    // Not a terminal: nothing.
    assert_eq!(
        mailbox_prompt(dir.path(), &mut policy, false, never),
        Ok(None)
    );
    let lines = mailbox_prompt(dir.path(), &mut policy, true, |q| {
        assert_eq!(q, MAILBOX_QUESTION);
        Some("".into())
    })
    .unwrap()
    .unwrap();
    assert!(
        lines[0].starts_with("ok: friend mailboxes stay off"),
        "{lines:?}"
    );
    assert_eq!(load_policy(dir.path()).custody_use, Some(false));
    assert_eq!(
        mailbox_prompt(dir.path(), &mut policy, true, never),
        Ok(None)
    );
    // Held in this build: never asked.
    let dir = tmp();
    super::super::save_contacts(dir.path(), std::slice::from_ref(&carol)).unwrap();
    learned(dir.path(), &[(&carol, Some(0), Vec::new())]);
    set_custody_hints_for_this_thread(Some(false));
    let mut policy = NodePolicy::default();
    assert_eq!(
        mailbox_prompt(dir.path(), &mut policy, true, never),
        Ok(None)
    );
    set_custody_hints_for_this_thread(None);
}

/// A queued send asks about mailboxes only when the contact announced a
/// mail friend this node also has as a verified contact.
#[test]
fn mailbox_match_needs_a_shared_verified_friend() {
    let dir = tmp();
    let local = [0x52; 32];
    let (bob, carol, dan) = (
        contact(0x41, "Bob", true),
        contact(0x31, "Carol", true),
        contact(0x32, "Dan", false),
    );
    super::super::save_contacts(dir.path(), &[bob.clone(), carol.clone(), dan.clone()]).unwrap();
    let tag = |c: &Contact| raven_core::route_hints::custodian_tag(&key(&bob), &local, &key(c));
    assert!(!mailbox_match(dir.path(), &local, &key(&bob)));
    // Dan is not verified here: no match.
    learned(dir.path(), &[(&bob, None, vec![tag(&dan)])]);
    assert!(!mailbox_match(dir.path(), &local, &key(&bob)));
    learned(dir.path(), &[(&bob, None, vec![tag(&dan), tag(&carol)])]);
    assert!(mailbox_match(dir.path(), &local, &key(&bob)));
    // A tag made for another receiver matches nothing here.
    let other = raven_core::route_hints::custodian_tag(&key(&bob), &[0x99; 32], &key(&carol));
    learned(dir.path(), &[(&bob, None, vec![other])]);
    assert!(!mailbox_match(dir.path(), &local, &key(&bob)));
}

/// Review D-6: each consent question saves only its own answer on top of
/// the policy as it is when the answer comes. A `raven lan off` (or any
/// other change) made while the question waited stays.
#[test]
fn a_consent_answer_keeps_what_changed_while_it_was_asked() {
    let lan_off_meanwhile = |dir: &Path| {
        let mut p = try_load_policy(dir).unwrap();
        p.lan_off = true;
        p.hide_ip = true;
        save_policy(dir, &p).unwrap();
    };
    // `raven node custody on`.
    let dir = tmp();
    custody_on_with(dir.path(), false, true, |_| {
        lan_off_meanwhile(dir.path());
        Some("y".into())
    })
    .unwrap();
    let p = load_policy(dir.path());
    assert_eq!((p.custody, p.lan_off, p.hide_ip), (true, true, true));
    // `raven custody use on`.
    let dir = tmp();
    custody_use_with(dir.path(), UseArg::On { yes: false }, true, |_| {
        lan_off_meanwhile(dir.path());
        Some("y".into())
    })
    .unwrap();
    let p = load_policy(dir.path());
    assert_eq!(
        (p.custody_use, p.lan_off, p.hide_ip),
        (Some(true), true, true)
    );
    // The mailbox question at the end of `raven status`, answered no.
    let dir = tmp();
    let carol = contact(0x31, "Carol", true);
    super::super::save_contacts(dir.path(), std::slice::from_ref(&carol)).unwrap();
    learned(dir.path(), &[(&carol, Some(0), Vec::new())]);
    set_custody_hints_for_this_thread(Some(true));
    let mut policy = try_load_policy(dir.path()).unwrap();
    let asked = mailbox_prompt(dir.path(), &mut policy, true, |_| {
        lan_off_meanwhile(dir.path());
        Some("n".into())
    });
    set_custody_hints_for_this_thread(None);
    assert!(asked.unwrap().is_some());
    let p = load_policy(dir.path());
    assert_eq!(
        (p.custody_use, p.lan_off, p.hide_ip),
        (Some(false), true, true)
    );
    assert_eq!(policy, p, "the caller's copy is what was saved");
    // The custody follow-up after a yes to the relay offer.
    let dir = tmp();
    set_custody_gates_for_this_thread(Some(CustodyGates {
        live: true,
        wan: false,
    }));
    let mut policy = try_load_policy(dir.path()).unwrap();
    let said = relay_custody_follow_up(dir.path(), &mut policy, |_| {
        lan_off_meanwhile(dir.path());
        Some("yes".into())
    });
    set_custody_gates_for_this_thread(None);
    assert!(said.unwrap().is_some());
    let p = load_policy(dir.path());
    assert_eq!((p.custody, p.lan_off, p.hide_ip), (true, true, true));
}

/// Review D-4: the custody follow-up to the relay offer turns on what
/// `raven node custody on` turns on, so it asks with the same consent text.
#[test]
fn relay_follow_up_asks_with_the_custodian_consent() {
    let q = relay_custody_follow_up_question();
    for line in CUSTODIAN_CONSENT.lines().skip(1) {
        assert!(q.contains(line), "{line:?} in {q}");
    }
    assert!(q.ends_with("Turn that on too? [y/N] "), "{q}");
    assert!(!flat(&q).contains("not what"), "{q}");
}

/// Review D-5: `raven custody use off` (and `raven custody status`) say
/// when friends listed by hand for a contact are still used, and only then.
#[test]
fn custody_use_off_mentions_listed_custodians() {
    let dir = tmp();
    let (mut bob, carol, dan) = (
        contact(0x41, "Bob", true),
        contact(0x42, "Carol", true),
        contact(0x43, "Dan", true),
    );
    super::super::save_contacts(dir.path(), &[bob.clone(), carol.clone(), dan.clone()]).unwrap();
    let lines = custody_use_with(dir.path(), UseArg::Off, false, never).unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("nothing new is left with your mail friends"),
        "{lines:?}"
    );
    assert_eq!(gather_facts(dir.path()).listed, 0);
    // Carol listed for Bob by hand.
    bob.custodians = vec![carol.pub_hex.clone()];
    super::super::save_contacts(dir.path(), &[bob, carol, dan]).unwrap();
    let lines = custody_use_with(dir.path(), UseArg::Off, false, never).unwrap();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(
        flat(&lines[1]),
        "note: 1 contact still uses the friends you listed for it by hand: messages are left \
         with them and mail is collected from them (`raven contact set-addr --custodian` \
         changes that)."
    );
    let facts = gather_facts(dir.path());
    assert_eq!(facts.listed, 1);
    let rows = custody_status_rows(&facts);
    assert!(rows.contains(&lines[1]), "{rows:?}");
}

// ── Phase 5 P5.22: handoff CLI, offline delivery coverage ──────────────────

/// Custody, hints and handoff gates for this thread (`None`: as built).
fn gates(custody: Option<bool>, hints: Option<bool>, handoff: Option<bool>) {
    set_custody_gates_for_this_thread(custody.map(|live| CustodyGates { live, wan: false }));
    set_custody_hints_for_this_thread(hints);
    raven_core::custody_gate::set_handoff_gate_for_this_thread(handoff);
}

/// `raven node custody handoff on|off` saves only `custody_handoff`: AUTO,
/// bridge, store, relay and custody stay as they are on disk. `on` prints
/// the disclosure, notes custody off and the closed gate; `off` says what
/// happens to what is held. An unreadable policy changes nothing. The
/// clap command reaches the same setter.
#[test]
fn handoff_on_off_keeps_the_other_policy_fields() {
    use clap::Parser as _;
    let dir = tmp();
    let before = NodePolicy {
        auto_policy: true,
        bridge: true,
        store: true,
        relay: true,
        custody: true,
        ..NodePolicy::default()
    };
    save_policy(dir.path(), &before).unwrap();
    gates(Some(true), None, Some(true));
    let lines = handoff_switch(dir.path(), true).unwrap();
    assert_eq!(lines[0], "ok custody handoff on");
    let text = flat(&lines[1..].join("\n"));
    assert_eq!(text, flat(HANDOFF_DISCLOSURE), "{lines:?}");
    for words in [
        "pass sealed messages on from a verified contact to another verified contact",
        "You cannot read them.",
        "When passing on you see who sent it and which friend it goes to, never the final \
         recipient",
        "when holding you see the recipient and the friend who brought it, not the sender",
    ] {
        assert!(text.contains(words), "{words}: {text}");
    }
    assert_eq!(
        load_policy(dir.path()),
        NodePolicy {
            custody_handoff: true,
            ..before.clone()
        }
    );
    let lines = handoff_switch(dir.path(), false).unwrap();
    assert_eq!(lines, ["ok custody handoff off", HANDOFF_OFF_TEXT]);
    assert_eq!(load_policy(dir.path()), before);
    // Custody off and the gate closed: both said, still saved.
    save_policy(
        dir.path(),
        &NodePolicy {
            custody: false,
            ..before.clone()
        },
    )
    .unwrap();
    gates(Some(true), None, Some(false));
    let lines = handoff_switch(dir.path(), true).unwrap();
    assert_eq!(
        lines[lines.len() - 2..],
        [
            HANDOFF_NEEDS_CUSTODY.to_string(),
            format!("note: {HANDOFF_HOLD}")
        ]
    );
    let saved = load_policy(dir.path());
    assert!(saved.custody_handoff && !saved.custody && saved.auto_policy && saved.bridge);
    // The command line: `raven node custody handoff off` through clap.
    let cli =
        super::super::Cli::try_parse_from(["raven", "node", "custody", "handoff", "off"]).unwrap();
    let Some(super::super::Commands::Node {
        cmd: super::super::NodeCommands::Custody { state },
    }) = cli.cmd
    else {
        panic!("not a node custody command");
    };
    super::super::cmd_node_custody(dir.path(), state).unwrap();
    let saved = load_policy(dir.path());
    assert!(!saved.custody_handoff && saved.auto_policy && saved.store && saved.relay);
    assert!(
        super::super::Cli::try_parse_from(["raven", "node", "custody", "handoff", "maybe"])
            .is_err()
    );
    // An unreadable policy: refused, nothing written.
    std::fs::write(raven_core::policy_path(dir.path()), b"{not json").unwrap();
    let err = handoff_switch(dir.path(), true).unwrap_err();
    assert!(err.contains("unreadable"), "{err}");
    assert_eq!(
        std::fs::read(raven_core::policy_path(dir.path())).unwrap(),
        b"{not json"
    );
    gates(None, None, None);
}

/// Three forward rows (one waiting, one handed on, one refused) and two
/// registered tags in custody_handoff.sqlite.
fn handoff_rows(dir: &Path) -> HandoffUsage {
    use raven_core::friend_custody::CustodyCode;
    let now = now_ms();
    let mut store = HandoffStore::open_or_create(dir).unwrap();
    let (hop, depositor) = ([0x61; 32], [0x62; 32]);
    for (i, size) in [100usize, 200, 300].into_iter().enumerate() {
        let digest = [0x70 + i as u8; 32];
        let code = store
            .forward(
                &digest,
                &hop,
                &depositor,
                &[0x80 + i as u8; 16],
                &vec![0xAB; size],
                now + 3_600_000,
                now,
            )
            .unwrap();
        assert_eq!(code, CustodyCode::Ok);
    }
    assert!(store
        .mark_handed(&[0x71; 32], &hop, CustodyCode::Ok)
        .unwrap());
    assert!(store
        .mark_refused(&[0x72; 32], &hop, CustodyCode::Expired)
        .unwrap());
    let tags = store
        .register(
            &[0x63; 32],
            &[([0x90; 16], now + 3_600_000), ([0x91; 16], now + 3_600_000)],
            now,
        )
        .unwrap();
    assert_eq!(tags.accepted, 2);
    store.usage().unwrap()
}

/// `raven node custody status`: the handoff counts from
/// custody_handoff.sqlite (counts only), nothing while handoff is off,
/// held and the store empty; the gate's hold while on and held. No store
/// is created by reading it.
#[test]
fn custody_status_counts_handoff_rows_and_tags() {
    let dir = tmp();
    gates(Some(true), None, Some(false));
    assert!(handoff_status_lines(dir.path()).is_empty());
    assert!(!raven_core::custody_handoff::handoff_db_path(dir.path()).exists());
    // The gate open: shown, all zero.
    gates(Some(true), None, Some(true));
    assert_eq!(
        handoff_status_lines(dir.path()),
        [
            "handoff off  passing on: 0 waiting, 0 handed on, 0 refused, 0 bytes; registered \
          tags: 0"
        ]
    );
    assert!(!raven_core::custody_handoff::handoff_db_path(dir.path()).exists());
    let usage = handoff_rows(dir.path());
    assert_eq!((usage.pending, usage.handed, usage.refused), (1, 1, 1));
    gates(Some(true), None, Some(false));
    let lines = handoff_status_lines(dir.path());
    assert_eq!(
        lines,
        [format!(
            "handoff off  passing on: 1 waiting, 1 handed on, 1 refused, {} bytes; registered \
             tags: 2",
            usage.bytes
        )]
    );
    assert!(usage.bytes >= 600, "{usage:?}");
    // On while the gate holds it: the hold follows the counts.
    save_policy(
        dir.path(),
        &NodePolicy {
            custody: true,
            custody_handoff: true,
            ..NodePolicy::default()
        },
    )
    .unwrap();
    let lines = handoff_status_lines(dir.path());
    assert!(
        lines[0].starts_with("handoff on  passing on: 1 waiting"),
        "{lines:?}"
    );
    assert_eq!(lines[1], HANDOFF_HOLD);
    for line in &lines {
        assert!(!line.contains(&hex::encode([0x61u8; 32])), "{line}");
    }
    gates(None, None, None);
}

/// `raven node custody off --purge` empties both files: the custody store
/// and the handoff store (forward rows and tags); without `--purge` both
/// keep what they hold. Either way custody is saved off and the handoff
/// flag is left as it was.
#[test]
fn custody_off_purge_purges_both_files() {
    use super::super::CustodyState;
    use raven_core::friend_custody::CustodyCode;
    let fill = |dir: &Path| {
        let now = now_ms();
        let mut store = CustodyStore::open_or_create(dir).unwrap();
        let code = store
            .deposit(
                &[0x21; 32],
                &[0x22; 32],
                &[0x23; 32],
                &[0x24; 16],
                &[0xCD; 64],
                now + 3_600_000,
                now,
            )
            .unwrap();
        assert_eq!(code, CustodyCode::Ok);
        handoff_rows(dir);
    };
    let held = |dir: &Path| {
        (
            CustodyStore::open_existing(dir)
                .unwrap()
                .unwrap()
                .usage()
                .unwrap()
                .0,
            HandoffStore::open_existing(dir)
                .unwrap()
                .unwrap()
                .usage()
                .unwrap(),
        )
    };
    let policy = NodePolicy {
        custody: true,
        custody_handoff: true,
        auto_policy: true,
        ..NodePolicy::default()
    };
    // Without --purge: both kept.
    let dir = tmp();
    save_policy(dir.path(), &policy).unwrap();
    fill(dir.path());
    super::super::cmd_node_custody(dir.path(), CustodyState::Off { purge: false }).unwrap();
    let (objects, handoff) = held(dir.path());
    assert_eq!(
        (
            objects,
            handoff.pending + handoff.handed + handoff.refused,
            handoff.tags
        ),
        (1, 3, 2)
    );
    // With --purge: both emptied.
    let dir = tmp();
    save_policy(dir.path(), &policy).unwrap();
    fill(dir.path());
    super::super::cmd_node_custody(dir.path(), CustodyState::Off { purge: true }).unwrap();
    let (objects, handoff) = held(dir.path());
    assert_eq!(objects, 0);
    assert_eq!(handoff, HandoffUsage::default());
    let saved = load_policy(dir.path());
    assert!(!saved.custody && saved.custody_handoff && saved.auto_policy);
    // No handoff store: none is created, nothing to report.
    let dir = tmp();
    assert_eq!(purge_handoff(dir.path()), Ok(None));
    assert!(!raven_core::custody_handoff::handoff_db_path(dir.path()).exists());
}

/// What a contact told this node with flags: (who, custodian tags with
/// each one's flags byte).
type ToldFlags<'a> = (&'a Contact, Vec<([u8; 32], u8)>);

/// learned_routes.json: each [`ToldFlags`] is a live snapshot with those
/// custodian tags and flags.
fn learned_flags(dir: &Path, told: &[ToldFlags<'_>]) {
    let now = now_ms();
    let rows: Vec<serde_json::Value> = told
        .iter()
        .map(|(c, tags)| {
            serde_json::json!({
                "pub_hex": c.pub_hex,
                "generation": 1,
                "received_at_ms": now,
                "expires_at_ms": now + 3_600_000,
                "via": "lan",
                "custodian_tags": tags.iter().map(|(t, _)| hex::encode(t)).collect::<Vec<_>>(),
                "custodian_tag_flags": tags.iter().map(|(_, f)| *f).collect::<Vec<_>>(),
            })
        })
        .collect();
    std::fs::write(
        dir.join(raven_core::learned_routes::LEARNED_ROUTES_FILE),
        serde_json::Value::Array(rows).to_string(),
    )
    .unwrap();
}

/// The coverage world: this node (`LOCAL`) has verified Carol and Erin
/// (friends), Bob and Dan (both list Carol as their mail friend here),
/// Gina and Hal; Frank is not verified (Carol listed for him too), and Hal
/// lists Frank. Bob announced Carol (a mail friend they share), plus a
/// friend this node does not know; Dan announced Erin, who takes mail
/// another friend passes on for him (HANDOFF_INBOX). Carol and Gina were
/// reached directly within 24 h, Hal 25 h ago.
const LOCAL: [u8; 32] = [0x52; 32];

struct World {
    dir: tempfile::TempDir,
    carol: Contact,
    erin: Contact,
    bob: Contact,
    dan: Contact,
    gina: Contact,
    hal: Contact,
}

fn coverage_world() -> World {
    use raven_core::route_hints::{custodian_tag, CUSTODIAN_FLAG_HANDOFF_INBOX};
    let dir = tmp();
    let carol = contact(0x31, "Carol", true);
    let erin = contact(0x33, "Erin", true);
    let mut bob = contact(0x41, "Bob", true);
    let mut dan = contact(0x42, "Dan", true);
    let gina = contact(0x43, "Gina", true);
    let mut hal = contact(0x44, "Hal", true);
    let mut frank = contact(0x45, "Frank", false);
    for c in [&mut bob, &mut dan, &mut frank] {
        c.custodians = vec![carol.pub_hex.clone()];
    }
    hal.custodians = vec![frank.pub_hex.clone()];
    super::super::save_contacts(
        dir.path(),
        &[
            carol.clone(),
            erin.clone(),
            bob.clone(),
            dan.clone(),
            gina.clone(),
            hal.clone(),
            frank,
        ],
    )
    .unwrap();
    let tag = |peer: &Contact, c: &[u8; 32]| custodian_tag(&key(peer), &LOCAL, c);
    learned_flags(
        dir.path(),
        &[
            (
                &bob,
                vec![(tag(&bob, &key(&carol)), 0), (tag(&bob, &[0x99; 32]), 0)],
            ),
            (
                &dan,
                vec![(tag(&dan, &key(&erin)), CUSTODIAN_FLAG_HANDOFF_INBOX)],
            ),
        ],
    );
    World {
        dir,
        carol,
        erin,
        bob,
        dan,
        gina,
        hal,
    }
}

/// A raven-node status with these last paths (contact, seconds ago).
fn status_with_paths(paths: &[(&Contact, u64)]) -> Result<IpcResponse, String> {
    let paths: Vec<serde_json::Value> = paths
        .iter()
        .map(|(c, age)| {
            serde_json::json!({"peer_pub_hex": c.pub_hex, "carrier": "lan_dial", "age_s": age})
        })
        .collect();
    Ok(serde_json::from_value(serde_json::json!({
        "ok": "status", "v": 1, "bridge": false, "store": false, "relay": false,
        "forward_pending": 0, "capabilities": ["ipc"], "last_paths": paths,
    }))
    .unwrap())
}

/// `raven doctor`'s offline delivery coverage from the fixture's
/// contacts.json, announcements and last paths, under the worker's
/// handoff parks: one class per verified contact (best way first), counts
/// only, each class with its ceiling, the next step for `none`.
#[test]
fn doctor_coverage_classes_from_contacts_announcements_and_parks() {
    let w = coverage_world();
    let dir = w.dir.path();
    let status = status_with_paths(&[(&w.carol, 0), (&w.gina, 3_600), (&w.hal, 25 * 3_600)]);
    let none = |_: &[u8; 32], _: Option<&[u8; 32]>| false;
    gates(Some(true), Some(true), Some(true));
    let lines = doctor_offline_lines_with(dir, &LOCAL, &status, &none);
    assert_eq!(
        lines,
        [
            "offline_delivery: verified_contacts=6 direct=2 mutual_friend=1 two_friends=1 \
             none=2 (raven contact show NAME says which way)",
            "  Raven keeps it until you're both online (2 contacts): for up to a day after you \
             were last connected",
            "  a mail friend you share (1 contact): the friend holds a sealed copy until it \
             expires, up to a day (7 days as a letter)",
            "  two friends in a row (1 contact): up to a day",
            "  nobody can carry it (2 contacts): it goes when you meet",
            "  next step: ask a friend you both trust to hold mail (raven node custody on), or \
             pin an always-on friend node as custodian",
        ]
    );
    // Counts only: never a name or a key.
    for line in &lines {
        for c in [&w.carol, &w.erin, &w.bob, &w.dan, &w.gina, &w.hal] {
            assert!(
                !line.contains(&c.petname) && !line.contains(&c.pub_hex),
                "{line}"
            );
        }
    }
    let counts = |parked: &HandoffParked<'_>| {
        doctor_offline_lines_with(dir, &LOCAL, &status, parked)
            .remove(0)
            .split(" (")
            .next()
            .unwrap()
            .to_string()
    };
    // Every handoff parked at Carol, or the pair (Carol, Erin): Dan has none.
    let carol = key(&w.carol);
    let erin = key(&w.erin);
    let two_none = "offline_delivery: verified_contacts=6 direct=2 mutual_friend=1 \
                    two_friends=0 none=3";
    assert_eq!(counts(&|c, hop| *c == carol && hop.is_none()), two_none);
    assert_eq!(
        counts(&|c, hop| *c == carol && hop == Some(&erin)),
        two_none
    );
    // A park of another pair changes nothing.
    assert_eq!(
        counts(&|c, hop| *c == carol && hop == Some(&[0x99; 32])),
        "offline_delivery: verified_contacts=6 direct=2 mutual_friend=1 two_friends=1 none=2"
    );
    // The handoff gate closed: no two friends.
    gates(Some(true), Some(true), Some(false));
    assert_eq!(counts(&none), two_none);
    // Learned custody held: no announcement, so no mutual friend either.
    gates(Some(true), Some(false), Some(true));
    assert_eq!(
        counts(&none),
        "offline_delivery: verified_contacts=6 direct=2 mutual_friend=0 two_friends=0 none=4"
    );
    // raven-node not answering: no last paths, so nobody is direct.
    gates(Some(true), Some(true), Some(true));
    let quiet = doctor_offline_lines_with(dir, &LOCAL, &Err("down".into()), &none);
    assert!(
        quiet[0].starts_with(
            "offline_delivery: verified_contacts=6 direct=0 mutual_friend=1 two_friends=1 none=4"
        ),
        "{quiet:?}"
    );
    // Friend custody held in this build: the next step says so.
    gates(Some(false), Some(false), Some(false));
    let held = doctor_offline_lines_with(dir, &LOCAL, &status, &none);
    assert_eq!(
        held.last().unwrap(),
        &format!("  next step: {OFFLINE_HELD_STEP}")
    );
    // Nothing to count, and a book that cannot be read.
    let empty = tmp();
    assert_eq!(
        doctor_offline_lines_with(empty.path(), &LOCAL, &status, &none),
        [
            "offline_delivery: verified_contacts=0 direct=0 mutual_friend=0 two_friends=0 none=0 \
          (raven contact show NAME says which way)"
        ]
    );
    std::fs::write(
        empty.path().join(raven_core::contact_book::CONTACTS_FILE),
        b"[not json",
    )
    .unwrap();
    assert_eq!(
        doctor_offline_lines_with(empty.path(), &LOCAL, &status, &none),
        ["offline_delivery: unknown (contacts.json cannot be read)"]
    );
    gates(None, None, None);
}

/// The pure rule: a DEPOSIT at an announced custodian beats a FORWARD,
/// which beats a direct delivery; a listed custodian the contact did not
/// announce is no mutual friend.
#[test]
fn coverage_prefers_a_shared_friend_then_two_friends_then_direct() {
    let (peer, c, h) = ([0x41; 32], [0x31; 32], [0x33; 32]);
    let none = |_: &[u8; 32], _: Option<&[u8; 32]>| false;
    let ann = |key, handoff_inbox| Announced { key, handoff_inbox };
    let of = |listed: &[[u8; 32]], announced: Option<&[Announced]>, direct| {
        coverage_of(&peer, &LOCAL, listed, announced, true, &none, direct)
    };
    assert_eq!(
        of(&[c], Some(&[ann(c, false), ann(h, true)]), true),
        Coverage::MutualFriend
    );
    assert_eq!(of(&[c], Some(&[ann(h, true)]), true), Coverage::TwoFriends);
    assert_eq!(of(&[c], Some(&[ann(h, false)]), true), Coverage::Direct);
    assert_eq!(of(&[c], None, false), Coverage::Nobody);
    assert_eq!(of(&[], Some(&[ann(h, true)]), false), Coverage::Nobody);
    // The next hop is never the contact itself or this node.
    assert_eq!(
        of(&[c], Some(&[ann(peer, true), ann(LOCAL, true)]), false),
        Coverage::Nobody
    );
}

/// Review handoff-3: Bob collects mail that friends pass on
/// (HANDOFF_INBOX) only at a friend this node has not verified, and no
/// mail friend you share carries mail from this node to him: this node's
/// receipts for Bob's messages (which may still reach it through two
/// friends) cannot go back that way. `raven contact show` says so and how
/// to fix it; `raven doctor` counts such contacts, never naming one.
/// Neither for a contact with such a friend this node verified (two
/// friends in a row), one with a mail friend you share, one that announced
/// no such friend, or while the handoff gate is closed.
#[test]
fn contact_show_and_doctor_say_when_receipts_cannot_go_back() {
    use raven_core::route_hints::{custodian_tag, CUSTODIAN_FLAG_HANDOFF_INBOX as INBOX};
    let w = coverage_world();
    let dir = w.dir.path();
    let now = now_ms();
    let tag = |peer: &Contact, c: &[u8; 32]| custodian_tag(&key(peer), &LOCAL, c);
    let unknown = [0x99; 32];
    // Bob (you list Carol for him) announced only a friend you do not know,
    // with HANDOFF_INBOX; Dan announced Erin (verified here) with it.
    let told = |bob: Vec<([u8; 32], u8)>| {
        learned_flags(
            dir,
            &[
                (&w.bob, bob),
                (&w.dan, vec![(tag(&w.dan, &key(&w.erin)), INBOX)]),
            ],
        )
    };
    told(vec![(tag(&w.bob, &unknown), INBOX)]);
    let show = |who: &str| contact_show_lines(dir, who, &LOCAL, &[], now).unwrap();
    let receipts = |lines: &[String]| {
        lines
            .iter()
            .filter(|l| l.starts_with("  receipts: "))
            .cloned()
            .collect::<Vec<_>>()
    };
    let status = status_with_paths(&[]);
    let none = |_: &[u8; 32], _: Option<&[u8; 32]>| false;
    gates(Some(true), Some(true), Some(true));
    let bob = show("Bob");
    assert_eq!(
        receipts(&bob),
        [
            "  receipts: Bob collects mail that friends pass on only at a friend you have not \
             verified, so your receipts for Bob's messages cannot go back through friends. Ask \
             Bob which friend that is and verify it by its key alone, with no address to dial \
             (raven contact add with --verify-fp and no --lan-dial)"
        ],
        "{bob:?}"
    );
    for who in ["@dan", "@hal", "@gina"] {
        assert!(receipts(&show(who)).is_empty(), "{who}");
    }
    let doctor = doctor_offline_lines_with(dir, &LOCAL, &status, &none);
    assert_eq!(
        receipts(&doctor),
        [
            "  receipts: 1 contact collects mail that friends pass on only at friends you have \
             not verified: your receipts cannot go back to it through friends (raven contact \
             show NAME)"
        ]
    );
    for line in &doctor {
        assert!(
            !line.contains(&w.bob.petname) && !line.contains(&w.bob.pub_hex),
            "{line}"
        );
    }
    assert_eq!(
        receipts_stranded_count_line(2).unwrap(),
        "  receipts: 2 contacts collect mail that friends pass on only at friends you have not \
         verified: your receipts cannot go back to them through friends (raven contact show \
         NAME)"
    );
    assert_eq!(receipts_stranded_count_line(0), None);
    // Carol, the mail friend you share, announced as well: she carries them.
    told(vec![
        (tag(&w.bob, &key(&w.carol)), 0),
        (tag(&w.bob, &unknown), INBOX),
    ]);
    assert!(receipts(&show("Bob")).is_empty());
    // Erin (verified here) takes them for Bob: two friends in a row.
    told(vec![
        (tag(&w.bob, &key(&w.erin)), INBOX),
        (tag(&w.bob, &unknown), INBOX),
    ]);
    assert!(receipts(&show("Bob")).is_empty());
    // An unknown friend without HANDOFF_INBOX: nothing passed on to say.
    told(vec![(tag(&w.bob, &unknown), 0)]);
    assert!(receipts(&show("Bob")).is_empty());
    // The handoff gate closed: nothing is passed on anyway.
    told(vec![(tag(&w.bob, &unknown), INBOX)]);
    gates(Some(true), Some(true), Some(false));
    assert!(receipts(&show("Bob")).is_empty());
    assert!(receipts(&doctor_offline_lines_with(dir, &LOCAL, &status, &none)).is_empty());
    gates(None, None, None);
}

/// `raven contact show NAME`: the mail friends the contact announced (by
/// your own names, with whether each takes mail another friend passes on;
/// unknown ones counted), the ones you listed (an unusable one flagged),
/// and its offline delivery class with its ceiling.
#[test]
fn contact_show_lists_announced_mail_friends_and_handoff() {
    let w = coverage_world();
    let dir = w.dir.path();
    let now = now_ms();
    gates(Some(true), Some(true), Some(true));
    let show = |who: &str, direct: &[[u8; 32]]| contact_show_lines(dir, who, &LOCAL, direct, now);
    let dan = show("@dan", &[]).unwrap();
    assert!(dan[0].starts_with("Dan  @dan  verified"), "{dan:?}");
    assert!(dan[1].starts_with("  fp "), "{dan:?}");
    assert_eq!(
        dan[2..],
        [
            "  mail friends Dan told you about: Erin (also takes mail another friend passes on)",
            "  mail friends you listed for Dan: Carol",
            "  offline delivery (two friends in a row): up to a day",
        ]
    );
    let bob = show("Bob", &[]).unwrap();
    assert_eq!(
        bob[2..],
        [
            "  mail friends Bob told you about: Carol; 1 more that is not your verified contact",
            "  mail friends you listed for Bob: Carol",
            "  offline delivery (a mail friend you share): the friend holds a sealed copy until \
             it expires, up to a day (7 days as a letter)",
        ]
    );
    let hal = show("@hal", &[]).unwrap();
    assert_eq!(
        hal[2..],
        [
            "  mail friends Hal told you about: none",
            "  mail friends you listed for Hal: Frank (not used: not a verified, unblocked \
             contact)",
            "  offline delivery (nobody can carry it): it goes when you meet",
            "  next step: ask a friend you both trust to hold mail (raven node custody on), or \
             pin an always-on friend node as custodian",
        ]
    );
    let gina = show("@gina", &[key(&w.gina)]).unwrap();
    assert_eq!(
        gina.last().unwrap(),
        "  offline delivery (Raven keeps it until you're both online): for up to a day after \
         you were last connected"
    );
    let frank = show("@frank", &[]).unwrap();
    assert!(frank[0].ends_with("not verified"), "{frank:?}");
    assert_eq!(
        frank.last().unwrap(),
        "  offline delivery: friends carry mail for verified contacts only (raven contact \
         verify @frank)"
    );
    // Learned custody held in this build: nothing announced is read.
    gates(Some(true), Some(false), Some(true));
    let dan = show("@dan", &[]).unwrap();
    assert_eq!(
        dan[2],
        "  mail friends Dan told you about: not in this build (friend mailboxes are lab-only)"
    );
    assert_eq!(
        dan[4],
        "  offline delivery (nobody can carry it): it goes when you meet"
    );
    assert!(show("@nobody", &[]).is_err());
    gates(None, None, None);
}
