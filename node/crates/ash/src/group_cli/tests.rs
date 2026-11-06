//! `raven group` on lab profiles: create, list, show (members, delivery
//! lines), the inbox section, and the refusals.

use super::*;
use raven_core::group::{GroupFrame, GroupMsg};
use raven_core::identity::Identity;

struct Lab;

impl Lab {
    fn on() -> Lab {
        group::set_lab_groups_for_this_thread(Some(true));
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
        Lab
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        group::set_lab_groups_for_this_thread(None);
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
    }
}

fn friend(name: &str, id: &Identity) -> super::super::Contact {
    super::super::Contact {
        petname: name.into(),
        public_tag: String::new(),
        alias: String::new(),
        address: id.address(),
        pub_hex: hex::encode(id.public_key_bytes()),
        pinned: true,
        lan_dial: String::new(),
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

/// A profile with an identity and `friends` in its book.
fn profile(friends: &[(&str, &Identity)]) -> (tempfile::TempDir, Identity) {
    let dir = tempfile::tempdir().unwrap();
    let (me, _) = raven_core::load_or_create_profile_identity(dir.path()).unwrap();
    raven_core::device_cert::ensure_local_device_certificate(
        dir.path(),
        &me,
        raven_core::paths::PRIMARY_DEVICE_ID,
    )
    .unwrap();
    let book: Vec<_> = friends.iter().map(|(n, id)| friend(n, id)).collect();
    super::super::save_contacts(dir.path(), &book).unwrap();
    (dir, me)
}

fn plain(lines: &[String]) -> String {
    let joined = lines.join("\n");
    raven_core::sanitize::sanitize_terminal_text(&joined).replace(['\u{1b}'], "")
}

#[test]
fn create_list_show_and_send_on_a_lab_profile() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let bea = Identity::from_seed(&[0xBE; 32]);
    let cy = Identity::from_seed(&[0xC7; 32]);
    let (dir, me) = profile(&[("Bea", &bea), ("Cy", &cy)]);
    let d = dir.path();
    let out = cmd_group(
        d,
        GroupArg::Create {
            name: "  Book club ".into(),
            members: vec!["bea".into(), "Cy".into(), "Bea".into()],
        },
    )
    .unwrap();
    assert!(
        out[0].starts_with("ok group Book club created (3 members"),
        "{out:?}"
    );
    let listed = plain(&cmd_group(d, GroupArg::List).unwrap());
    assert!(listed.contains("Book club"), "{listed}");
    assert!(listed.contains("3 members"), "{listed}");
    assert!(listed.contains("you are the admin"), "{listed}");
    let id = group::find(d, "book CLUB").unwrap();
    group::send(d, &me, &id, "first meeting on Monday", now_ms()).unwrap();
    let shown = plain(
        &cmd_group(
            d,
            GroupArg::Show {
                group: "book club".into(),
                all: false,
            },
        )
        .unwrap(),
    );
    assert!(shown.contains("members (3):"), "{shown}");
    assert!(shown.contains("Bea"), "{shown}");
    assert!(shown.contains("your friend"), "{shown}");
    assert!(shown.contains("you: first meeting on Monday"), "{shown}");
    assert!(shown.contains("delivered to 0 of 2"), "{shown}");
    // Only the admin changes the roster; strangers are refused.
    let err = cmd_group(
        d,
        GroupArg::Add {
            group: "book club".into(),
            members: vec!["nobody".into()],
        },
    )
    .unwrap_err();
    assert!(err.contains("no contact for nobody"), "{err}");
    let removed = cmd_group(
        d,
        GroupArg::Remove {
            group: "book club".into(),
            members: vec!["cy".into()],
        },
    )
    .unwrap();
    assert!(
        removed[0].starts_with("ok removed 1 from Book club (2 members now)"),
        "{removed:?}"
    );
    let err = cmd_group(
        d,
        GroupArg::Leave {
            group: "book club".into(),
            yes: true,
        },
    )
    .unwrap_err();
    assert!(err.contains("GROUP_ADMIN_CANNOT_LEAVE"), "{err}");
    assert!(cmd_group(
        d,
        GroupArg::Show {
            group: "nothing".into(),
            all: false,
        }
    )
    .unwrap_err()
    .contains("GROUP_NOT_FOUND"));
}

/// The salt of the inbox test's group.
const SALT_33: [u8; 16] = [0x33; 16];

#[test]
fn the_inbox_lists_received_group_messages_by_group_and_author() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let admin = Identity::from_seed(&[0xA1; 32]);
    let other = Identity::from_seed(&[0x0E; 32]);
    let (dir, me) = profile(&[("Ana", &admin)]);
    let d = dir.path();
    assert!(inbox_lines(d).is_empty());
    let mut state = group::GroupState {
        group: group::group_id_for(&admin.public_key_bytes(), &SALT_33),
        salt: SALT_33,
        epoch: 1,
        name: "Hikers".into(),
        admin: admin.public_key_bytes(),
        issued_ms: now_ms(),
        members: vec![
            group::Member {
                key: admin.public_key_bytes(),
                label: String::new(),
            },
            group::Member {
                key: me.public_key_bytes(),
                label: "Me".into(),
            },
            group::Member {
                key: other.public_key_bytes(),
                label: "Ola".into(),
            },
        ],
        sig: [0; 64],
    };
    state.sign(&admin);
    let a = admin.public_key_bytes();
    group::ingest(d, &a, &GroupFrame::State(state), now_ms()).unwrap();
    let mut m = GroupMsg {
        group: group::group_id_for(&admin.public_key_bytes(), &SALT_33),
        id: [0x44; 16],
        epoch: 1,
        from: [0; 32],
        sent_ms: now_ms(),
        body: "summit at noon".into(),
        sig: [0; 64],
        relay: Vec::new(),
    };
    m.sign(&other);
    group::ingest(d, &a, &GroupFrame::Msg(m), now_ms()).unwrap();
    let lines = plain(&inbox_lines(d));
    assert!(lines.contains("[Hikers] Ola: summit at noon"), "{lines}");
    let shown = plain(
        &cmd_group(
            d,
            GroupArg::Show {
                group: "hikers".into(),
                all: false,
            },
        )
        .unwrap(),
    );
    assert!(shown.contains("passed on by Ana"), "{shown}");
    assert!(
        shown.contains("not your friend; named by the admin"),
        "{shown}"
    );
}

#[test]
fn group_commands_say_the_hold_when_the_gate_is_closed() {
    group::set_lab_groups_for_this_thread(Some(false));
    let bea = Identity::from_seed(&[0xBE; 32]);
    let (dir, _) = profile(&[("Bea", &bea)]);
    let err = cmd_group(
        dir.path(),
        GroupArg::Create {
            name: "x".into(),
            members: vec!["bea".into()],
        },
    )
    .unwrap_err();
    assert!(err.contains("GROUP_HOLD"), "{err}");
    let listed = plain(&cmd_group(dir.path(), GroupArg::List).unwrap());
    assert!(listed.contains("not part of this build"), "{listed}");
    assert!(listed.contains("no groups yet"), "{listed}");
    group::set_lab_groups_for_this_thread(None);
}

/// E2 r9 #15: each message says how and when it came: for a member's, how
/// its copy came, who passed it on, and when it arrived; for yours, when
/// you sent it.
#[test]
fn every_message_says_how_and_when_it_came() {
    use raven_core::arrivals::ArrivedVia;
    let view = |mine: bool, path: Option<ArrivedVia>, via: Option<Key>| MessageView {
        id: [1; 16],
        from: [2; 32],
        mine,
        body: "hi".into(),
        sent_ms: 1_000,
        received_ms: 2_000,
        via,
        lines: Vec::new(),
        copies: Vec::new(),
        delivered: 0,
        total: 0,
        path,
    };
    let name = |k: &Key| format!("member {}", k[0]);
    let when = |at: u64| format!("at {at} (UTC+1)");
    assert_eq!(
        how_it_came(&view(false, Some(ArrivedVia::Tor), None), name, when),
        ["via Tor", "arrived at 2000 (UTC+1)"]
    );
    assert_eq!(
        how_it_came(
            &view(false, Some(ArrivedVia::Lan), Some([9; 32])),
            name,
            when
        ),
        [
            "via LAN",
            "passed on by member 9",
            "arrived at 2000 (UTC+1)"
        ]
    );
    assert_eq!(
        how_it_came(&view(false, Some(ArrivedVia::Keeper), None), name, when),
        ["from a keeper", "arrived at 2000 (UTC+1)"]
    );
    assert_eq!(
        how_it_came(&view(false, None, None), name, when),
        ["arrived at 2000 (UTC+1)"]
    );
    assert_eq!(
        how_it_came(&view(true, None, None), name, when),
        ["sent at 1000 (UTC+1)"]
    );
}

/// E2 r9 #16: "messages (newest 15)" gave no hint that older ones exist.
/// The hint names the group by its whole id (ASH-1).
#[test]
fn the_messages_header_says_how_many_are_older_and_how_to_see_them() {
    let id: GroupId = [0x5a; 16];
    let whole = "5a".repeat(16);
    assert_eq!(messages_header(3, 3, &id), "messages (3):");
    assert_eq!(
        messages_header(20, 45, &id),
        format!("messages (newest 20 of 45; 25 older: `raven group show {whole} --all`):")
    );
    assert_eq!(
        messages_header(20, 21, &id),
        format!("messages (newest 20 of 21; 1 older: `raven group show {whole} --all`):")
    );
}

/// A group a friend made and signed as its admin, naming me in its roster:
/// its id.
fn admin_group(d: &Path, admin: &Identity, me: &Identity, salt: [u8; 16], name: &str) -> GroupId {
    let id = group::group_id_for(&admin.public_key_bytes(), &salt);
    let mut state = group::GroupState {
        group: id,
        salt,
        epoch: 1,
        name: name.into(),
        admin: admin.public_key_bytes(),
        issued_ms: now_ms(),
        members: vec![
            group::Member {
                key: admin.public_key_bytes(),
                label: String::new(),
            },
            group::Member {
                key: me.public_key_bytes(),
                label: String::new(),
            },
        ],
        sig: [0; 64],
    };
    state.sign(admin);
    let a = admin.public_key_bytes();
    group::ingest(d, &a, &GroupFrame::State(state), now_ms()).unwrap();
    id
}

/// `n` messages the admin wrote in group `id`, their ids starting with
/// `tag`.
fn admin_says(d: &Path, admin: &Identity, id: &GroupId, tag: u8, n: u8) {
    let a = admin.public_key_bytes();
    for i in 0..n {
        let mut mid = [tag; 16];
        mid[15] = i;
        let mut m = GroupMsg {
            group: *id,
            id: mid,
            epoch: 1,
            from: [0; 32],
            sent_ms: now_ms(),
            body: format!("note {i}"),
            sig: [0; 64],
            relay: Vec::new(),
        };
        m.sign(admin);
        group::ingest(d, &a, &GroupFrame::Msg(m), now_ms()).unwrap();
    }
}

/// The messages header `raven group show` printed.
fn header_of(shown: &str) -> &str {
    shown
        .lines()
        .find(|l| l.starts_with("messages ("))
        .unwrap_or_else(|| panic!("no messages header in {shown}"))
}

/// ASH-1: the hint to the older messages names the group by its whole id,
/// never by the name its admin chose. A name may hold what a shell runs
/// once the command is pasted, quotes that end the word, or text a command
/// reads as an option; a plain name gets the same hint.
#[test]
fn the_older_messages_hint_names_the_group_by_its_whole_id() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let admin = Identity::from_seed(&[0xA1; 32]);
    let (dir, me) = profile(&[("Ana", &admin)]);
    let d = dir.path();
    let names = [
        "Book club $(touch pwned)",
        "a`id`b",
        "q\" ; id ; \"",
        "it's 'quoted'",
        "x;id",
        "x|id",
        "x&calc",
        "x>out <in",
        "!!",
        "%PATH%",
        "\u{201c}curly\u{201d}; calc",
        "--all",
        "-rf",
        "Hikers",
    ];
    for (n, name) in names.into_iter().enumerate() {
        let tag = n as u8 + 1;
        let id = admin_group(d, &admin, &me, [tag; 16], name);
        admin_says(d, &admin, &id, tag, 21);
        let shown = plain(
            &cmd_group(
                d,
                GroupArg::Show {
                    group: hex::encode(id),
                    all: false,
                },
            )
            .unwrap(),
        );
        assert_eq!(
            header_of(&shown),
            format!(
                "messages (newest 20 of 21; 1 older: `raven group show {} --all`):",
                hex::encode(id)
            ),
            "{name}"
        );
    }
}

/// ASH-1 end to end: the command in the hint pastes as five plain words
/// and its id finds the same group, also next to groups their admins named
/// with its whole id and with its first 8 hex characters. Run as given, it
/// lists every message.
#[test]
fn the_older_messages_hint_pastes_safely_and_finds_the_same_group() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let admin = Identity::from_seed(&[0xA1; 32]);
    let (dir, me) = profile(&[("Ana", &admin)]);
    let d = dir.path();
    let id = admin_group(d, &admin, &me, [0x51; 16], "Book club $(touch pwned)");
    admin_says(d, &admin, &id, 0x51, 21);
    let whole = hex::encode(id);
    admin_group(d, &admin, &me, [0x52; 16], &whole);
    admin_group(d, &admin, &me, [0x53; 16], &whole[..8]);
    let shown = plain(
        &cmd_group(
            d,
            GroupArg::Show {
                group: "book club $(touch pwned)".into(),
                all: false,
            },
        )
        .unwrap(),
    );
    let header = header_of(&shown);
    let command = header.split('`').nth(1).unwrap_or_default();
    assert!(
        !command.contains(|c| "$`\"';|&<>(){}[]%!*?~#\\".contains(c)),
        "{command}"
    );
    let words: Vec<&str> = command.split_whitespace().collect();
    assert_eq!(words.len(), 5, "{command}");
    assert_eq!(words[..3], ["raven", "group", "show"], "{command}");
    assert_eq!(words[4], "--all", "{command}");
    assert_eq!(group::find(d, words[3]), Ok(id), "{command}");
    let every = plain(
        &cmd_group(
            d,
            GroupArg::Show {
                group: words[3].into(),
                all: true,
            },
        )
        .unwrap(),
    );
    assert_eq!(header_of(&every), "messages (21):", "{every}");
}

/// `--all` lists every message the group keeps; without it the newest 20
/// and the header's hint.
#[test]
fn show_all_lists_every_message() {
    if !cfg!(debug_assertions) {
        return;
    }
    let _lab = Lab::on();
    let bea = Identity::from_seed(&[0xBE; 32]);
    let (dir, me) = profile(&[("Bea", &bea)]);
    let d = dir.path();
    cmd_group(
        d,
        GroupArg::Create {
            name: "Walkers".into(),
            members: vec!["bea".into()],
        },
    )
    .unwrap();
    let id = group::find(d, "walkers").unwrap();
    for n in 0..23 {
        group::send(d, &me, &id, &format!("walk {n}"), now_ms() + n).unwrap();
    }
    let show = |all: bool| {
        plain(
            &cmd_group(
                d,
                GroupArg::Show {
                    group: "walkers".into(),
                    all,
                },
            )
            .unwrap(),
        )
    };
    let some = show(false);
    assert!(
        some.contains(&format!(
            "messages (newest 20 of 23; 3 older: `raven group show {} --all`):",
            hex::encode(id)
        )),
        "{some}"
    );
    assert!(!some.contains("walk 2 "), "{some}");
    assert!(some.contains("you: walk 22 (sent "), "{some}");
    let every = show(true);
    assert!(every.contains("messages (23):"), "{every}");
    assert!(every.contains("you: walk 0 (sent "), "{every}");
}
