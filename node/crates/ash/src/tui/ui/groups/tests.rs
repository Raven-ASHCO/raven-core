//! Groups on Home (lab): the list's GROUPS section, a group's chat with
//! its delivery line, NEW GROUP, MEMBERS, live reads, and that nothing of
//! it exists while the gate is closed. The last test builds its groups with
//! raven-core's API on a profile of its own and reads them through the
//! controller, as the store and send workers do.

use std::collections::VecDeque;
use std::path::Path;

use crossterm::event::KeyCode;
use raven_core::group::{self as core_group, GroupId, GroupView, Key, MemberView};
use raven_core::identity::Identity;

use super::*;
use controller::{
    Controller, GroupChange, GroupChat, GroupDone, GroupMessage, GroupsRead, MemberLine, Verify,
};
use workers::{FileStamp, PollUpdate, Watched};

/// The groups' lab switches for this thread (debug builds), shut again
/// when dropped. `on`: open, or explicitly closed.
struct Lab;

impl Lab {
    fn set(on: bool) -> Option<Lab> {
        if !cfg!(debug_assertions) {
            return None;
        }
        core_group::set_lab_groups_for_this_thread(Some(on));
        raven_core::horizon::set_lab_horizon_for_this_thread(Some(on));
        Some(Lab)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        core_group::set_lab_groups_for_this_thread(None);
        raven_core::horizon::set_lab_horizon_for_this_thread(None);
    }
}

/// testkit's friend `n` has the key `n` repeated.
fn key(n: u8) -> Key {
    [n; 32]
}

/// This profile's key in these views.
const ME: Key = [0x70; 32];

fn gid(n: u8) -> GroupId {
    [n; 16]
}

fn summary(n: u8, name: &str, members: usize, unread: usize, status: &str) -> GroupSummary {
    GroupSummary {
        id: gid(n),
        name: name.into(),
        admin: if n == 1 { ME } else { key(1) },
        i_am_admin: n == 1,
        status: status.into(),
        epoch: 1,
        members,
        unread,
        last_ms: 0,
        last: None,
    }
}

fn member(key: Key, label: &str, friend: Option<&str>, admin: bool) -> MemberView {
    MemberView {
        key,
        label: label.into(),
        friend_name: friend.map(str::to_owned),
        admin,
        me: key == ME,
    }
}

/// Book club (group 1, this profile its admin), Hikers (group 2, Friend
/// 1's) and Old crew (group 3, left).
fn three_groups(unread: usize) -> Vec<GroupSummary> {
    vec![
        summary(1, "Book club", 3, unread, core_group::store::STATUS_ACTIVE),
        summary(2, "Hikers", 2, 0, core_group::store::STATUS_ACTIVE),
        summary(3, "Old crew", 4, 0, core_group::store::STATUS_LEFT),
    ]
}

/// Book club's chat at `now_ms`: Friend 1's message, Ola's (not a friend)
/// passed on by Friend 1, and one of yours delivered to Friend 1 of the
/// two.
fn book_club(now_ms: u64, unread: usize) -> GroupChat {
    let minutes = |n: u64| now_ms - n * 60_000;
    GroupChat {
        view: GroupView {
            summary: three_groups(unread).remove(0),
            members: vec![
                member(ME, "", None, true),
                member(key(1), "Bea", Some("Friend 1"), false),
                member(key(9), "Ola", None, false),
            ],
        },
        messages: vec![
            GroupMessage {
                id: [0x11; 16],
                mine: false,
                author: "Friend 1".into(),
                via: None,
                body: "Hello club!".into(),
                at_ms: minutes(30),
                sent_ms: minutes(31),
                path: None,
                lines: Vec::new(),
                delivered: 0,
                total: 0,
            },
            GroupMessage {
                id: [0x12; 16],
                mine: false,
                author: "Ola".into(),
                via: Some("Friend 1".into()),
                body: "Count me in.".into(),
                at_ms: minutes(20),
                sent_ms: minutes(21),
                path: None,
                lines: Vec::new(),
                delivered: 0,
                total: 0,
            },
            mine([0x13; 16], "See you on Monday.", minutes(5), 1),
        ],
    }
}

/// A message of yours to Friend 1 and Ola, delivered to `delivered` of
/// them (Friend 1 first).
fn mine(id: [u8; 16], body: &str, at_ms: u64, delivered: usize) -> GroupMessage {
    let state = |i: usize| {
        if i < delivered {
            core_group::store::LINE_DELIVERED
        } else {
            core_group::store::LINE_WAITING
        }
    };
    GroupMessage {
        id,
        mine: true,
        author: "you".into(),
        via: None,
        body: body.into(),
        at_ms,
        sent_ms: at_ms,
        path: None,
        lines: vec![
            MemberLine {
                name: "Friend 1".into(),
                state: state(0).into(),
                relayed: false,
            },
            MemberLine {
                name: "Ola".into(),
                state: state(1).into(),
                relayed: true,
            },
        ],
        delivered,
        total: 2,
    }
}

/// Home with friends 1 and 2 and the groups live, its first groups read
/// answered with `groups`.
fn live_home(size: (u16, u16), groups: Vec<GroupSummary>) -> App {
    let mut app = testkit::home_app(
        size,
        state_file::Receive::Off,
        vec![testkit::friend(1), testkit::friend(2)],
        controller::Conversations::new(),
    );
    assert!(app.groups_live(), "the lab switches are on");
    settle(&mut app, &groups);
    app
}

/// Reads answered with `groups` until no more is asked for: the first
/// one, and those asked for meanwhile (the friends' and the history's
/// loads ask too).
fn settle(app: &mut App, groups: &[GroupSummary]) {
    while !loads(&read(app, groups.to_vec(), None)).is_empty() {}
}

/// A groups read answered: `groups`, and `chat` for the open group.
fn read(app: &mut App, groups: Vec<GroupSummary>, chat: Option<GroupChat>) -> Vec<Cmd> {
    let open = chat.map(|chat| (chat.view.summary.id, Ok(chat)));
    testkit::send(
        app,
        Msg::Job(JobResult::Groups(GroupsRead {
            groups: Ok(groups),
            open,
            stamp: FileStamp::default(),
        })),
    )
}

fn loads(cmds: &[Cmd]) -> Vec<(Option<GroupId>, bool)> {
    cmds.iter()
        .filter_map(|cmd| match cmd {
            Cmd::Store(StoreJob::LoadGroups { open, refresh }) => Some((*open, *refresh)),
            _ => None,
        })
        .collect()
}

fn changes(cmds: &[Cmd]) -> Vec<&GroupChange> {
    cmds.iter()
        .filter_map(|cmd| match cmd {
            Cmd::Send(SendJob::GroupChange(change)) => Some(change),
            _ => None,
        })
        .collect()
}

fn press_all(app: &mut App, keys: &[KeyCode]) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    for &key in keys {
        cmds.extend(testkit::press(app, key));
    }
    cmds
}

fn type_text(app: &mut App, text: &str) -> Vec<Cmd> {
    let keys: Vec<KeyCode> = text.chars().map(KeyCode::Char).collect();
    press_all(app, &keys)
}

fn top(app: &App) -> Option<&GroupOverlay> {
    match app.overlays().last() {
        Some(Overlay::Group(group)) => Some(group),
        _ => None,
    }
}

/// Book club open (Down twice from Friend 1, Enter), its chat read.
fn book_club_open(size: (u16, u16), unread: usize) -> (App, Vec<Cmd>) {
    let mut app = live_home(size, three_groups(unread));
    let mut cmds = press_all(&mut app, &[KeyCode::Down, KeyCode::Down, KeyCode::Enter]);
    let chat = book_club(app.now_ms(), unread);
    cmds.extend(read(&mut app, three_groups(unread), Some(chat)));
    (app, cmds)
}

#[test]
fn the_list_has_a_groups_section_under_the_friends() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((80, 24), three_groups(2));
    press_all(&mut app, &[KeyCode::Down, KeyCode::Down]);
    testkit::assert_rows(
        &testkit::render(&app, 80, 24),
        &[
            "R A V E N                                                     o Receiving is off",
            "┌ Chats ─────────────┐┌────────────────────────────────────────────────────────┐",
            "│  x Friend 1       !││                                                        │",
            "│  x Friend 2       !││                                                        │",
            "│ Groups             ││                                                        │",
            "│> # Book club      2││                                                        │",
            "│  # Hikers          ││                                                        │",
            "│  # Old crew    left││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││ ────────────────────────────────────────────────────── │",
            "│ A  Add a friend    ││ Pick a friend on the left and press Enter to start     │",
            "│ C  New group       ││ writing.                                               │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "2 friends - all quiet                          activity ........................",
            "? Help  Q Quit  Up/Down Choose  Enter Open  A Add  C New group  V Verify        ",
        ],
    );
    // One pane has room for the member count.
    testkit::resize(&mut app, 60, 16);
    let rows = testkit::render(&app, 60, 16);
    assert!(
        rows.iter().any(|row| row.contains("# Hikers  2 members")),
        "{rows:#?}"
    );
    assert!(
        rows.iter().any(|row| row.contains("C  New group")),
        "{rows:#?}"
    );
}

#[test]
fn the_highlight_stays_on_its_group_as_the_list_reorders() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((80, 24), three_groups(0));
    // Down past the friends to Hikers.
    press_all(&mut app, &[KeyCode::Down, KeyCode::Down, KeyCode::Down]);
    assert_eq!(app.highlighted_group_at(), Some(1));
    // Hikers had news: it comes first now.
    let mut reordered = three_groups(0);
    reordered.swap(0, 1);
    read(&mut app, reordered, None);
    assert_eq!(app.highlighted_group_at(), Some(0));
    // A friend more: the highlight moves down with Hikers.
    testkit::send(
        &mut app,
        Msg::Job(JobResult::Contacts {
            contacts: Ok(vec![
                testkit::friend(1),
                testkit::friend(2),
                testkit::friend(3),
            ]),
            stamp: FileStamp::default(),
        }),
    );
    assert_eq!(app.highlight(), 3);
    assert_eq!(app.highlighted_group_at(), Some(0));
    // The last row is the last group.
    press_all(&mut app, &[KeyCode::Down; 5]);
    assert_eq!(app.highlight(), 5);
}

/// E2 r9 #15: with this computer's offset known, a member's message says
/// how its copy came and when it arrived, and yours when you sent it; the
/// way shows without the offset too.
#[test]
fn a_group_chat_says_how_and_when_each_message_came() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((100, 24), three_groups(0));
    press_all(&mut app, &[KeyCode::Down, KeyCode::Down, KeyCode::Enter]);
    let mut chat = book_club(app.now_ms(), 0);
    chat.messages[0].path = Some(raven_core::arrivals::ArrivedVia::Tor);
    chat.messages[1].path = Some(raven_core::arrivals::ArrivedVia::Keeper);
    read(&mut app, three_groups(0), Some(chat));
    let plain = testkit::render_text(&app);
    assert!(plain.contains("Friend 1 - 30 min ago - via Tor"), "{plain}");
    assert!(
        plain.contains("Ola - 20 min ago - from a keeper - passed on by Friend 1"),
        "{plain}"
    );
    assert!(
        !plain.contains("arrived"),
        "no clock without the offset: {plain}"
    );
    let zoned = bridge::with_local_offset(Some(3_600), || testkit::render_text(&app));
    assert!(
        zoned.contains("arrived today at") || zoned.contains("arrived yesterday at"),
        "{zoned}"
    );
    assert!(zoned.contains("(UTC+1)"), "{zoned}");
    assert!(
        zoned.contains("sent today at") || zoned.contains("sent yesterday at"),
        "{zoned}"
    );
}

#[test]
fn a_group_chat_says_who_wrote_who_passed_it_on_and_how_many_have_it() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((80, 24), three_groups(0));
    let cmds = press_all(&mut app, &[KeyCode::Down, KeyCode::Down, KeyCode::Enter]);
    // Opening it reads it with a refresh; the composer has the keys.
    assert_eq!(loads(&cmds), [(Some(gid(1)), true)]);
    assert_eq!(app.open_group(), Some(gid(1)));
    assert_eq!(app.open_friend(), None);
    assert_eq!(app.focus(), Focus::Composer);
    let rows = testkit::render(&app, 80, 24);
    assert!(testkit::screen_text(&rows).contains("Loading messages..."));
    let chat = book_club(app.now_ms(), 0);
    read(&mut app, three_groups(0), Some(chat));
    testkit::assert_rows(
        &testkit::render(&app, 80, 24),
        &[
            "R A V E N                                                     o Receiving is off",
            "┌ Chats ─────────────┐┌────────────────────────────────────────────────────────┐",
            "│  x Friend 1       !││ Book club  3 members - you are the admin               │",
            "│  x Friend 2       !││                                                        │",
            "│ Groups             ││                                                        │",
            "│> # Book club       ││                                                        │",
            "│  # Hikers          ││                                                        │",
            "│  # Old crew    left││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││                                                        │",
            "│                    ││ Friend 1 - 30 min ago                                  │",
            "│                    ││   Hello club!                                          │",
            "│                    ││ Ola - 20 min ago - passed on by Friend 1               │",
            "│                    ││   Count me in.                                         │",
            "│                    ││ You - 5 min ago  v Delivered to 1 of 2                 │",
            "│                    ││   Ola waiting: another member passes it on             │",
            "│                    ││   See you on Monday.                                   │",
            "│ A  Add a friend    ││ ────────────────────────────────────────────────────── │",
            "│ C  New group       ││ To Book club: write here  (Enter sends  Ctrl+J new lin │",
            "└────────────────────┘└────────────────────────────────────────────────────────┘",
            "2 friends - 1 message waiting for Book club    activity ........................",
            "? Help  Esc Friends  Enter Send  Ctrl+J New line  Tab Messages  PgUp/PgDn Scroll",
        ],
    );
    // Messages focus: the newest is chosen; Enter shows who has it.
    let cmds = press_all(&mut app, &[KeyCode::Tab, KeyCode::Enter]);
    assert!(cmds.is_empty(), "{cmds:?}");
    assert_eq!(
        top(&app),
        Some(&GroupOverlay::Delivery {
            group: gid(1),
            message: [0x13; 16],
        })
    );
    let text = testkit::render_text(&app);
    assert!(text.contains("Who has it"), "{text}");
    assert!(text.contains("Delivered to 1 of 2."), "{text}");
    assert!(text.contains("Friend 1 delivered"), "{text}");
    assert!(
        text.contains("Ola waiting: another member passes it on"),
        "{text}"
    );
    testkit::press(&mut app, KeyCode::Esc);
    assert!(app.overlays().is_empty());
    // A member's message has no delivery list.
    press_all(&mut app, &[KeyCode::Up, KeyCode::Char('d'), KeyCode::Enter]);
    assert!(app.overlays().is_empty());
    // Esc goes back to the composer, then the list.
    press_all(&mut app, &[KeyCode::Esc, KeyCode::Esc]);
    assert_eq!(app.focus(), Focus::Friends);
}

#[test]
fn an_open_group_with_unread_messages_is_marked_read_once() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let (mut app, cmds) = book_club_open((80, 24), 2);
    let marks = |cmds: &[Cmd]| {
        cmds.iter()
            .filter(|cmd| matches!(cmd, Cmd::Store(StoreJob::MarkGroupRead { group }) if *group == gid(1)))
            .count()
    };
    assert_eq!(marks(&cmds), 1, "{cmds:?}");
    // Not again while it runs, nor for the same count after.
    assert_eq!(marks(&testkit::press(&mut app, KeyCode::Up)), 0);
    let cmds = testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupMarked {
            group: gid(1),
            result: Ok(()),
        }),
    );
    assert_eq!(loads(&cmds), [(Some(gid(1)), false)], "read again");
    assert_eq!(marks(&cmds), 0);
    // A new message while it shows: marked again.
    let chat = book_club(app.now_ms(), 3);
    let cmds = read(&mut app, three_groups(3), Some(chat));
    assert_eq!(marks(&cmds), 1);
}

#[test]
fn the_composer_sends_as_a_send_job_and_a_refusal_comes_back_into_it() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let (mut app, _) = book_club_open((80, 24), 0);
    let mut cmds = type_text(&mut app, "Who brings snacks?");
    cmds.extend(testkit::press(&mut app, KeyCode::Enter));
    let sends: Vec<_> = cmds
        .iter()
        .filter_map(|cmd| match cmd {
            Cmd::Send(SendJob::GroupSend {
                local_id,
                group,
                text,
            }) => Some((*local_id, *group, text.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(sends, [(1, gid(1), "Who brings snacks?".to_owned())]);
    assert!(app.group_composer().is_some_and(|c| c.is_empty()));
    let text = testkit::render_text(&app);
    assert!(text.contains("You - just now ~ Sending..."), "{text}");
    // It went: shown until a read has it.
    let done = GroupDone {
        result: Ok([0x14; 16]),
        kicked: true,
    };
    let cmds = testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupSent { local_id: 1, done }),
    );
    assert_eq!(loads(&cmds), [(Some(gid(1)), false)]);
    assert!(testkit::render_text(&app).contains("Sending..."));
    let mut chat = book_club(app.now_ms(), 0);
    chat.messages
        .push(mine([0x14; 16], "Who brings snacks?", app.now_ms(), 0));
    read(&mut app, three_groups(0), Some(chat));
    let text = testkit::render_text(&app);
    assert!(!text.contains("Sending..."), "{text}");
    assert!(
        text.contains(
            "You - just now ~ Delivered to 0 of 2 2 waiting (1 passed on by other members) \
             Who brings snacks?"
        ),
        "{text}"
    );
    // Refused: the text comes back, and a toast says why.
    type_text(&mut app, "again");
    testkit::press(&mut app, KeyCode::Enter);
    let why = core_group::GroupError::QueueFull.sentence();
    testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupSent {
            local_id: 2,
            done: GroupDone {
                result: Err(why.clone()),
                kicked: false,
            },
        }),
    );
    assert_eq!(app.group_composer().map(|c| c.text()), Some("again"));
    assert_eq!(
        app.toast().map(|t| t.text.clone()),
        Some(format!("Not sent: {why}"))
    );
    // No background program took the copies of one that went: a toast.
    let cmds = testkit::press(&mut app, KeyCode::Enter);
    assert_eq!(cmds.len(), 1, "{cmds:?}");
    testkit::tick(&mut app, std::time::Duration::from_secs(5));
    testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupSent {
            local_id: 3,
            done: GroupDone {
                result: Ok([0x15; 16]),
                kicked: false,
            },
        }),
    );
    assert_eq!(app.toast().map(|t| t.text.as_str()), Some(app::GROUP_WAITS));
}

#[test]
fn new_group_asks_a_name_then_friends_and_opens_it() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((80, 24), Vec::new());
    let blocked = bridge::ContactView {
        blocked: true,
        ..testkit::friend(3)
    };
    testkit::send(
        &mut app,
        Msg::Job(JobResult::Contacts {
            contacts: Ok(vec![testkit::friend(1), testkit::friend(2), blocked]),
            stamp: FileStamp::default(),
        }),
    );
    settle(&mut app, &[]);
    testkit::press(&mut app, KeyCode::Char('c'));
    assert!(matches!(top(&app), Some(GroupOverlay::Name { .. })));
    // An empty name is refused; letters are text, never shortcuts.
    testkit::press(&mut app, KeyCode::Enter);
    let text = testkit::render_text(&app);
    assert!(text.contains(app::GROUP_NAME_EMPTY), "{text}");
    type_text(&mut app, "Book club");
    testkit::assert_rows(
        &testkit::render(&app, 80, 24)[8..16],
        &[
            "│         ┌ New group ───────────────────────────────────────────────┐         │",
            "│         │ Its name. Everyone in the group sees it.                 │         │",
            "│         │                                                          │         │",
            "│         │ > Book club                                              │         │",
            "│         │                                                          │         │",
            "│         │ [Enter] Next   [Esc] Cancel                              │         │",
            "│         └──────────────────────────────────────────────────────────┘         │",
            "│                    ││                                                        │",
        ],
    );
    testkit::press(&mut app, KeyCode::Enter);
    // The picker: unblocked friends only.
    let Some(GroupOverlay::Pick(pick)) = top(&app) else {
        panic!("{:?}", app.overlays());
    };
    assert_eq!(
        app.pick_candidates(&pick.purpose)
            .iter()
            .map(|c| c.label.as_str())
            .collect::<Vec<_>>(),
        ["Friend 1", "Friend 2"]
    );
    // Enter with nobody picked says what to do.
    testkit::press(&mut app, KeyCode::Enter);
    assert!(testkit::render_text(&app).contains(app::GROUP_PICK_NONE));
    press_all(
        &mut app,
        &[KeyCode::Char(' '), KeyCode::Down, KeyCode::Char(' ')],
    );
    let text = testkit::render_text(&app);
    assert!(text.contains("New group: Book club"), "{text}");
    assert!(text.contains("[x] Friend 1"), "{text}");
    assert!(text.contains("> [x] Friend 2"), "{text}");
    assert!(text.contains("2 picked"), "{text}");
    let cmds = testkit::press(&mut app, KeyCode::Enter);
    let change = GroupChange::Create {
        name: "Book club".into(),
        members: vec![
            (key(1), "Friend 1".to_owned()),
            (key(2), "Friend 2".to_owned()),
        ],
    };
    assert_eq!(changes(&cmds), [&change]);
    // While it runs, keys wait.
    assert!(changes(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
    assert!(testkit::render_text(&app).contains("Creating the group..."));
    let cmds = testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupChanged {
            change,
            done: GroupDone {
                result: Ok(gid(5)),
                kicked: true,
            },
        }),
    );
    assert!(app.overlays().is_empty());
    assert_eq!(app.open_group(), Some(gid(5)));
    assert_eq!(app.focus(), Focus::Composer);
    assert_eq!(
        app.toast().map(|t| t.text.as_str()),
        Some("Created Book club. You are its admin.")
    );
    assert!(loads(&cmds).contains(&(Some(gid(5)), true)), "{cmds:?}");
    // The read that lists it gives it the highlight.
    let mut created = summary(5, "Book club", 3, 0, core_group::store::STATUS_ACTIVE);
    created.i_am_admin = true;
    read(&mut app, vec![created], None);
    assert_eq!(app.highlighted_group_at(), Some(0));
}

#[test]
fn the_picker_takes_15_friends_at_most() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((80, 24), Vec::new());
    testkit::send(
        &mut app,
        Msg::Job(JobResult::Contacts {
            contacts: Ok((1..=16).map(testkit::friend).collect()),
            stamp: FileStamp::default(),
        }),
    );
    testkit::press(&mut app, KeyCode::Char('c'));
    type_text(&mut app, "Everyone");
    testkit::press(&mut app, KeyCode::Enter);
    for _ in 0..16 {
        press_all(&mut app, &[KeyCode::Char(' '), KeyCode::Down]);
    }
    let Some(GroupOverlay::Pick(pick)) = top(&app) else {
        panic!("{:?}", app.overlays());
    };
    assert_eq!(pick.picked.len(), 15);
    assert_eq!(
        pick.problem.as_deref(),
        Some(core_group::GroupError::TooMany.sentence().as_str())
    );
    // Esc goes back to the name, as typed.
    testkit::press(&mut app, KeyCode::Esc);
    assert_eq!(
        top(&app),
        Some(&GroupOverlay::Name {
            typed: "Everyone".into(),
            problem: None,
        })
    );
}

#[test]
fn members_lets_the_admin_add_and_remove_after_a_yes() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let (mut app, _) = book_club_open((80, 24), 0);
    press_all(&mut app, &[KeyCode::Tab, KeyCode::Char('m')]);
    assert!(matches!(top(&app), Some(GroupOverlay::Members(_))));
    testkit::assert_rows(
        &testkit::render(&app, 80, 24)[6..17],
        &[
            "│  # Hikers          ││                                                        │",
            "│  # Old crew    left││                                                        │",
            "│         ┌ Book club - 3 members ───────────────────────────────────┐         │",
            "│         │ > You - admin                                            │         │",
            "│         │   Friend 1 - your friend                                 │         │",
            "│         │   Ola - not your friend                                  │         │",
            "│         │                                                          │         │",
            "│         │ [A] Add   [X] Remove   [Esc] Close                       │         │",
            "│         └──────────────────────────────────────────────────────────┘         │",
            "│                    ││   Count me in.                                         │",
            "│                    ││ > You - 5 min ago  v Delivered to 1 of 2               │",
        ],
    );
    // X on yourself does nothing; on Friend 1 it asks first.
    assert!(changes(&testkit::press(&mut app, KeyCode::Char('x'))).is_empty());
    assert!(matches!(top(&app), Some(GroupOverlay::Members(m)) if m.ask.is_none()));
    press_all(&mut app, &[KeyCode::Down, KeyCode::Char('x')]);
    let text = testkit::render_text(&app);
    assert!(
        text.contains("Remove Friend 1 from Book club? They keep what they already received."),
        "{text}"
    );
    testkit::press(&mut app, KeyCode::Char('n'));
    assert!(matches!(top(&app), Some(GroupOverlay::Members(m)) if m.ask.is_none()));
    testkit::press(&mut app, KeyCode::Char('x'));
    let cmds = testkit::press(&mut app, KeyCode::Char('y'));
    let change = GroupChange::Remove {
        group: gid(1),
        member: key(1),
        name: "Friend 1".into(),
    };
    assert_eq!(changes(&cmds), [&change]);
    testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupChanged {
            change,
            done: GroupDone {
                result: Ok(gid(1)),
                kicked: true,
            },
        }),
    );
    assert!(matches!(top(&app), Some(GroupOverlay::Members(m)) if !m.busy && m.ask.is_none()));
    assert_eq!(
        app.toast().map(|t| t.text.as_str()),
        Some("Removed Friend 1 from Book club. They keep what they already received.")
    );
    // A adds friends who are not in it yet: the same picker.
    testkit::press(&mut app, KeyCode::Char('a'));
    let Some(GroupOverlay::Pick(pick)) = top(&app) else {
        panic!("{:?}", app.overlays());
    };
    let offered: Vec<String> = app
        .pick_candidates(&pick.purpose)
        .iter()
        .map(|c| c.label.clone())
        .collect();
    assert_eq!(offered, ["Friend 2"]);
    let cmds = press_all(&mut app, &[KeyCode::Char(' '), KeyCode::Enter]);
    assert_eq!(
        changes(&cmds),
        [&GroupChange::Add {
            group: gid(1),
            members: vec![(key(2), "Friend 2".to_owned())],
        }]
    );
    // Refused: the picker says why and takes keys again.
    let why = core_group::GroupError::NotAFriend(key(2)).sentence();
    testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupChanged {
            change: GroupChange::Add {
                group: gid(1),
                members: vec![(key(2), "Friend 2".to_owned())],
            },
            done: GroupDone {
                result: Err(why.clone()),
                kicked: false,
            },
        }),
    );
    assert!(
        matches!(top(&app), Some(GroupOverlay::Pick(p)) if !p.busy && p.problem.as_deref() == Some(why.as_str()))
    );
    // Esc back to MEMBERS, Esc closes.
    press_all(&mut app, &[KeyCode::Esc]);
    assert!(matches!(top(&app), Some(GroupOverlay::Members(_))));
    press_all(&mut app, &[KeyCode::Esc]);
    assert!(app.overlays().is_empty());
}

#[test]
fn a_member_may_leave_after_a_yes_and_a_left_group_has_no_composer() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((80, 24), three_groups(0));
    // Hikers, a member's group: E on the list shows its members.
    press_all(&mut app, &[KeyCode::Down, KeyCode::Down, KeyCode::Down]);
    let cmds = testkit::press(&mut app, KeyCode::Char('e'));
    assert_eq!(loads(&cmds), [(Some(gid(2)), true)]);
    assert!(matches!(top(&app), Some(GroupOverlay::Members(_))));
    assert!(testkit::render_text(&app).contains("Reading the group..."));
    let hikers = GroupChat {
        view: GroupView {
            summary: three_groups(0).remove(1),
            members: vec![
                member(key(1), "", Some("Friend 1"), true),
                member(ME, "Me", None, false),
            ],
        },
        messages: Vec::new(),
    };
    read(&mut app, three_groups(0), Some(hikers.clone()));
    let text = testkit::render_text(&app);
    assert!(text.contains("Friend 1 - admin, your friend"), "{text}");
    assert!(text.contains("[L] Leave the group"), "{text}");
    // A member removes nobody.
    press_all(&mut app, &[KeyCode::Down, KeyCode::Char('x')]);
    assert!(matches!(top(&app), Some(GroupOverlay::Members(m)) if m.ask.is_none()));
    testkit::press(&mut app, KeyCode::Char('l'));
    assert!(matches!(
        top(&app),
        Some(GroupOverlay::Members(MembersState {
            ask: Some(MemberAsk::Leave),
            ..
        }))
    ));
    let cmds = testkit::press(&mut app, KeyCode::Char('y'));
    let change = GroupChange::Leave { group: gid(2) };
    assert_eq!(changes(&cmds), [&change]);
    testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupChanged {
            change,
            done: GroupDone {
                result: Ok(gid(2)),
                kicked: true,
            },
        }),
    );
    assert!(app.overlays().is_empty());
    assert_eq!(
        app.toast().map(|t| t.text.as_str()),
        Some("You left Hikers. What you received stays here.")
    );
    // The read after it: Hikers is left, and its chat has no composer.
    let mut groups = three_groups(0);
    groups[1].status = core_group::store::STATUS_LEFT.into();
    let mut left = hikers;
    left.view.summary.status = core_group::store::STATUS_LEFT.into();
    read(&mut app, groups, Some(left));
    assert!(app.group_composer().is_none());
    let text = testkit::render_text(&app);
    assert!(text.contains("Hikers 2 members - you left"), "{text}");
    assert!(text.contains("You left this group."), "{text}");
    assert!(text.contains("# Hikers left"), "{text}");
    // Letters type nothing; Tab skips the composer.
    type_text(&mut app, "hi");
    assert!(app.group_composer().is_none());
    testkit::press(&mut app, KeyCode::Esc);
    assert_eq!(app.focus(), Focus::Friends);
    testkit::press(&mut app, KeyCode::Tab);
    assert_eq!(app.focus(), Focus::Messages);
}

#[test]
fn groups_json_changing_reads_the_groups_again() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((80, 24), three_groups(0));
    let changed = |n: u64| {
        let dir = testkit::short_dir();
        let path = dir.path().join("groups.json");
        std::fs::write(&path, "x".repeat(usize::try_from(n).unwrap())).unwrap();
        FileStamp::of(&path)
    };
    let (one, two) = (changed(1), changed(2));
    let poll = |app: &mut App, stamp| {
        testkit::send(
            app,
            Msg::Poll(PollUpdate::File {
                watched: Watched::Groups,
                stamp,
            }),
        )
    };
    assert_eq!(loads(&poll(&mut app, one)), [(None, false)]);
    // Again while it is read: once it answers.
    assert!(loads(&poll(&mut app, two)).is_empty());
    let cmds = testkit::send(
        &mut app,
        Msg::Job(JobResult::Groups(GroupsRead {
            groups: Ok(three_groups(1)),
            open: None,
            stamp: one,
        })),
    );
    assert_eq!(loads(&cmds), [(None, false)]);
    let cmds = testkit::send(
        &mut app,
        Msg::Job(JobResult::Groups(GroupsRead {
            groups: Ok(three_groups(1)),
            open: None,
            stamp: two,
        })),
    );
    assert!(loads(&cmds).is_empty(), "settled: {cmds:?}");
    assert!(poll(&mut app, two).is_empty());
    // Once a minute, and after the history changed: with a refresh.
    assert_eq!(
        loads(&testkit::send(&mut app, Msg::Poll(PollUpdate::HorizonsDue))),
        [(None, true)]
    );
    testkit::send(
        &mut app,
        Msg::Job(JobResult::Groups(GroupsRead {
            groups: Ok(three_groups(0)),
            open: None,
            stamp: two,
        })),
    );
    let cmds = testkit::reload_rows(&mut app, &[]);
    assert_eq!(loads(&cmds), [(None, true)]);
}

#[test]
fn nothing_of_groups_shows_while_the_gate_is_closed() {
    let Some(_lab) = Lab::set(false) else {
        return;
    };
    let mut app = testkit::app((80, 24));
    let cmds = app.start(testkit::session(state_file::Receive::Off));
    assert!(loads(&cmds).is_empty(), "{cmds:?}");
    let mut app = testkit::home_app(
        (80, 24),
        state_file::Receive::Off,
        vec![testkit::friend(1)],
        controller::Conversations::new(),
    );
    assert!(!app.groups_live());
    let before = testkit::render(&app, 80, 24);
    // C opens nothing; a read or a file change (were one to come) shows
    // nothing and asks for nothing.
    assert!(testkit::press(&mut app, KeyCode::Char('c')).is_empty());
    assert!(app.overlays().is_empty());
    read(&mut app, three_groups(2), None);
    let cmds = testkit::send(
        &mut app,
        Msg::Poll(PollUpdate::File {
            watched: Watched::Groups,
            stamp: FileStamp::default(),
        }),
    );
    assert!(cmds.is_empty(), "{cmds:?}");
    assert!(loads(&testkit::send(&mut app, Msg::Poll(PollUpdate::HorizonsDue))).is_empty());
    assert!(app.group_list().is_empty());
    assert_eq!(testkit::render(&app, 80, 24), before);
    let text = testkit::screen_text(&before);
    assert!(
        !text.contains("Groups") && !text.contains("New group"),
        "{text}"
    );
    // The highlight stays on the friends.
    press_all(&mut app, &[KeyCode::Down, KeyCode::Down, KeyCode::Enter]);
    assert_eq!(app.open_group(), None);
    assert_eq!(app.open_friend(), Some(testkit::friend(1).pub_hex.as_str()));
}

// ── Through the controller, on a profile ────────────────────────────────────

/// Raven-node never starts in these tests.
fn no_node(_: &Path) -> Result<(), String> {
    Err("no raven-node in tests".into())
}

/// A profile whose identity the controller made, with Bea and Cy saved as
/// friends the way the App saves them.
fn profile() -> (tempfile::TempDir, Controller, [Key; 2]) {
    testkit::lab_backends();
    let dir = testkit::short_dir();
    let controller = Controller::with_ensure(dir.path(), no_node);
    controller.create_identity().result.expect("an identity");
    let me = controller.me().expect("an identity").pub_hex;
    let mut keys = [[0; 32]; 2];
    for (i, (seed, name)) in [(0xBE, "Bea"), (0xC7, "Cy")].into_iter().enumerate() {
        let id = Identity::from_seed(&[seed; 32]);
        let card = bridge::format_card_with(&id, "", "", None).expect("a card");
        let friend = controller::parse_friend_paste(&card, &me).expect("a friend's card");
        controller
            .save_friend(&friend, name, &Verify::Unpinned)
            .result
            .expect("saved");
        keys[i] = id.public_key_bytes();
    }
    (dir, controller, keys)
}

/// Runs the store and send jobs among `cmds` as the workers run them, and
/// the jobs their answers ask for in turn; the rest is dropped.
fn run_jobs(app: &mut App, controller: &Controller, cmds: Vec<Cmd>) {
    let mut queue: VecDeque<Cmd> = cmds.into();
    while let Some(cmd) = queue.pop_front() {
        let result = match cmd {
            Cmd::Store(job) => workers::store_job(controller, job),
            Cmd::Send(job) => workers::send_job(controller, job),
            _ => continue,
        };
        queue.extend(testkit::send(app, Msg::Job(result)));
    }
}

#[test]
fn a_group_made_and_written_to_on_a_profile_shows_delivered_to_1_of_2() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let (dir, controller, [bea, _cy]) = profile();
    let mut app = testkit::app((80, 24));
    let cmds = app.start(testkit::session(state_file::Receive::Off));
    assert!(loads(&cmds).contains(&(None, true)), "{cmds:?}");
    run_jobs(&mut app, &controller, cmds);
    assert!(app.group_list().is_empty());
    // C, a name, both friends, Enter: created on the profile, then open.
    let mut cmds = testkit::press(&mut app, KeyCode::Char('C'));
    cmds.extend(type_text(&mut app, "Book club"));
    cmds.extend(testkit::press(&mut app, KeyCode::Enter));
    cmds.extend(press_all(
        &mut app,
        &[
            KeyCode::Char(' '),
            KeyCode::Down,
            KeyCode::Char(' '),
            KeyCode::Enter,
        ],
    ));
    run_jobs(&mut app, &controller, cmds);
    assert_eq!(
        app.toast().map(|t| t.text.as_str()),
        Some("Created Book club. You are its admin.")
    );
    let id = core_group::find(dir.path(), "book club").expect("the group");
    assert_eq!(app.open_group(), Some(id));
    assert_eq!(app.group_list().len(), 1);
    // A message, sent as the send worker sends it.
    let mut cmds = type_text(&mut app, "First meeting on Monday");
    cmds.extend(testkit::press(&mut app, KeyCode::Enter));
    run_jobs(&mut app, &controller, cmds);
    let text = testkit::render_text(&app);
    assert!(
        text.contains("Delivered to 0 of 2 First meeting on Monday"),
        "{text}"
    );
    // Bea's Raven confirmed her copies: the history says so, and a read
    // with a refresh (as after the history changed) takes it in.
    let history = raven_core::ChatHistory::load(dir.path()).expect("the history");
    let bea_hex = hex::encode(bea);
    let rows: Vec<String> = history
        .entries
        .iter()
        .filter(|e| e.direction == "out" && e.peer_pub_hex.eq_ignore_ascii_case(&bea_hex))
        .map(|e| e.message_id_hex.clone())
        .collect();
    assert!(!rows.is_empty(), "Bea's copies were parked");
    for mid in &rows {
        raven_core::ChatHistory::set_delivery_persisted(
            dir.path(),
            &bea_hex,
            "out",
            mid,
            "delivered",
        )
        .expect("delivered");
    }
    let cmds = testkit::reload_rows(&mut app, &[]);
    run_jobs(&mut app, &controller, cmds);
    let chat = app.group_chat().expect("the chat");
    let m = chat.messages.last().expect("the message");
    assert_eq!((m.delivered, m.total), (1, 2));
    let text = testkit::render_text(&app);
    assert!(
        // Who still waits, by name, as raven-node reports each copy (Calm).
        text.contains("You - just now v Delivered to 1 of 2 - Cy waiting First meeting on Monday"),
        "{text}"
    );
    assert!(
        text.contains("Book club 3 members - you are the admin"),
        "{text}"
    );
    // WHO HAS IT names them by the names this profile gave them.
    press_all(&mut app, &[KeyCode::Tab, KeyCode::Char('d')]);
    let text = testkit::render_text(&app);
    assert!(text.contains("Bea delivered"), "{text}");
    assert!(text.contains("Cy waiting"), "{text}");
}

#[test]
fn help_lists_the_group_keys_while_groups_are_live() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let mut app = live_home((80, 24), three_groups(0));
    testkit::press(&mut app, KeyCode::Char('?'));
    let text = testkit::render_text(&app);
    assert!(
        text.contains(
            "Groups C New group (on the list) M Members of the open group Enter, D Who has it: a \
             message of yours, member by member Space Pick a friend for the group"
        ),
        "{text}"
    );
    // The gate shut: HELP lists none of them.
    drop(_lab);
    let Some(_closed) = Lab::set(false) else {
        return;
    };
    let mut app = testkit::home_app(
        (80, 24),
        state_file::Receive::Off,
        vec![testkit::friend(1)],
        controller::Conversations::new(),
    );
    testkit::press(&mut app, KeyCode::Char('?'));
    let text = testkit::render_text(&app);
    assert!(!text.contains("New group"), "{text}");
}

#[test]
fn a_group_chat_in_the_calm_palette() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let look = app::Look {
        glyphs: theme::Glyphs::fancy(),
        theme: theme::Theme::calm(&theme::DARK, theme::Depth::True),
        ..testkit::simple_mono()
    };
    let (mut app, _) = book_club_open((80, 24), 0);
    app.set_look_for_tests(look);
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 24)).expect("a terminal");
    terminal
        .draw(|f| render_frame(f, &app, app.now()))
        .expect("a draw");
    let buf = terminal.backend().buffer().clone();
    let rows = testkit::buffer_lines(&buf);
    let t = &look.theme;
    // Your message: the bar in front of its lines, 'Delivered to 1 of 2'
    // in the colour of things that went (not all of them did: the sent
    // mark), and who still waits in the warning's colour.
    let y = rows
        .iter()
        .position(|row| row.contains("Delivered to 1 of 2"))
        .expect("your message");
    let x = rows[y]
        .find("Ola waiting")
        .map(|at| rows[y][..at].chars().count());
    if let Some(x) = x {
        let x = u16::try_from(x).expect("a column");
        assert_eq!(
            buf[(x, u16::try_from(y).expect("a row"))].fg,
            t.warn.fg.expect("a colour")
        );
    }
    let body = &rows[y + 1 + usize::from(x.is_none())];
    assert!(body.contains("│ See you on Monday."), "{rows:#?}");
}

#[test]
fn a_run_of_group_messages_from_one_member_has_one_sender_line() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let (mut app, _) = book_club_open((80, 24), 0);
    let now = app.now_ms();
    let mut chat = book_club(now, 0);
    // Friend 1 again, a minute after the first: no sender line.
    chat.messages.insert(
        1,
        GroupMessage {
            id: [0x21; 16],
            body: "Bring snacks.".into(),
            at_ms: now - 29 * 60_000,
            ..chat.messages[0].clone()
        },
    );
    read(&mut app, three_groups(0), Some(chat));
    let text = testkit::render_text(&app);
    assert!(
        text.contains("Friend 1 - 30 min ago Hello club! Bring snacks. Ola - 20 min ago"),
        "{text}"
    );
    assert_eq!(text.matches("Friend 1 - ").count(), 1, "{text}");
}

#[test]
fn the_ticker_never_says_all_quiet_while_group_messages_go() {
    let Some(_lab) = Lab::set(true) else {
        return;
    };
    let (mut app, _) = book_club_open((80, 24), 0);
    // Delivered to every member: all quiet.
    let mut chat = book_club(app.now_ms(), 0);
    chat.messages.pop();
    read(&mut app, three_groups(0), Some(chat.clone()));
    let ticker = |app: &App| testkit::render(app, 80, 24)[22].clone();
    assert!(ticker(&app).contains("all quiet"), "{}", ticker(&app));
    // A send running: it says so.
    type_text(&mut app, "On my way");
    testkit::press(&mut app, KeyCode::Enter);
    assert!(
        ticker(&app).starts_with("Sending to Book club..."),
        "{}",
        ticker(&app)
    );
    // Its job answered, no read has it yet: one waiting, not all quiet.
    let done = GroupDone {
        result: Ok([0x31; 16]),
        kicked: true,
    };
    testkit::send(
        &mut app,
        Msg::Job(JobResult::GroupSent { local_id: 1, done }),
    );
    assert!(
        ticker(&app).contains("1 message waiting for Book club"),
        "{}",
        ticker(&app)
    );
    // Read, with a member's copy still waiting: still not quiet.
    chat.messages
        .push(mine([0x31; 16], "On my way", app.now_ms(), 1));
    read(&mut app, three_groups(0), Some(chat));
    assert!(
        ticker(&app).contains("1 message waiting for Book club"),
        "{}",
        ticker(&app)
    );
}
