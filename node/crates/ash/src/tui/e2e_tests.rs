//! The end-to-end test: two real profiles, Alice's and Bob's, each driven
//! through its App and its Controller as the full screen drives them, but
//! with no terminal and none of the workers' threads.
//!
//! Each profile has a fake raven-node on its own IPC socket (testkit's
//! `FakeNode`), bound before anything else: both report a listener on every
//! address at port 7420, and Alice's carries her dials to Bob's real
//! dispatcher on his profile, as his raven-node would. Nothing listens on a
//! TCP port and no raven-node is ever started.
//!
//! The driver plays the UI thread and the workers. Each store and send job an
//! update asks for runs at once through that side's controller, as the
//! workers run them (`workers::run_job` around `store_job` and `send_job`),
//! and its result goes back as `Msg::Job`. Node jobs are recorded and never
//! run: the app waits on two of them before it shows a card with an address,
//! so those two get the answers the node worker would give with the fake
//! already answering (no vault; the start finds the node running), and the
//! others get none. The poller is played by [`Side::poll_files`]: a file the
//! app last loaded at another size or time is loaded again.
//!
//! The app's clock is the real one, moved on by [`Side::later`] where the
//! paste guard or a draw-in would otherwise need a sleep.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use raven_core::identity::Identity;

use super::app::{
    App, Cmd, IdentityStart, JobResult, Key, ListenOverride, Look, LookEnv, Msg, NodeJob, PasteVia,
    Screen, Session, STOPPED_TOAST,
};
use super::bridge::{self, IdentityLoad, MeView};
use super::controller::{Controller, SendResult};
use super::delivery::{Actions, Tick, Waiting, WriteEvidence};
use super::node::{Ensured, Program, Vault};
use super::presence::{self, Presence};
use super::state_file::{Receive, TuiState};
use super::testkit::{self, DialPeer, FakeNode, FakeStatus};
use super::theme::Glyphs;
use super::workers::{self, FileStamp, PollUpdate, Watched};

/// The listener both fake nodes report: every address, Raven's port.
const LISTEN: &str = "0.0.0.0:7420";

/// The address on both cards: that port at the address injected below.
const CARD_LAN: &str = "127.0.0.1:7420";

/// The terminal both apps draw in: two panes.
const COLS: u16 = 100;
const ROWS: u16 = 30;

/// This computer's address, as both controllers are told it (nothing asks
/// the network).
fn loopback() -> Option<Ipv4Addr> {
    Some(Ipv4Addr::LOCALHOST)
}

/// One profile: its controller, its app, and what the driver noted.
struct Side {
    name: &'static str,
    controller: Controller,
    app: App,
    /// How far the app's clock is ahead of the real one.
    skew: Duration,
    /// Every node job the app asked for, in order. None of them ran.
    node_jobs: Vec<NodeJob>,
    /// How each send job ended, in order.
    sent: Vec<SendResult>,
    /// A friend's security code no frame may show, nor any group of 4 of
    /// it: checked on a fresh frame after every update while set.
    hidden: Option<String>,
}

impl Side {
    /// The identity made in `dir` through the controller (locked-file), and
    /// the app started on Home with receiving on, its first jobs carried
    /// out. Only the fake node's socket is in the profile before: the device
    /// certificate and the first prekey are the controller's to make.
    fn new(name: &'static str, dir: &Path) -> Side {
        let controller = Controller::with_egress(dir, loopback);
        let created = controller.create_identity().result.expect("create");
        assert_eq!(created.prekey_warning, None, "{name}");
        let mut app = App::new(
            testkit::simple_mono(),
            (COLS, ROWS),
            Instant::now(),
            bridge::now_ms(),
        );
        app.set_mac_for_tests(false);
        app.set_windows_for_tests(false);
        let mut side = Side {
            name,
            controller,
            app,
            skew: Duration::ZERO,
            node_jobs: Vec::new(),
            sent: Vec::new(),
            hidden: None,
        };
        let cmds = side.app.start(Session {
            identity: IdentityStart::Ready(created.me),
            data_dir: dir.to_path_buf(),
            // The notes shown once (UXF.9) were seen: their own tests show
            // them.
            settings: testkit::notes_seen(TuiState {
                receive: Receive::On,
                ..TuiState::default()
            }),
            program: Program::of_this_process(),
            listen: ListenOverride::None,
            over_ssh: false,
            gates: testkit::release_gates(),
            look_env: LookEnv::default(),
            locked: false,
        });
        side.carry_out(cmds);
        side
    }

    fn dir(&self) -> &Path {
        self.controller.data_dir()
    }

    fn me(&self) -> MeView {
        self.app.me().expect("an identity").clone()
    }

    /// The identity again, from the profile, for the fake node.
    fn identity(&self) -> Arc<Identity> {
        match bridge::load_identity(self.dir()) {
            IdentityLoad::Ready(id) => id,
            _ => panic!("{}: the identity can't be read back", self.name),
        }
    }

    /// `msg`, at the app's clock: what it asks for, not carried out yet.
    fn update(&mut self, msg: Msg) -> Vec<Cmd> {
        let skew_ms = u64::try_from(self.skew.as_millis()).unwrap_or(u64::MAX);
        let cmds = self.app.update(
            msg,
            Instant::now() + self.skew,
            bridge::now_ms().saturating_add(skew_ms),
        );
        if let Some(code) = &self.hidden {
            assert_no_code(&self.frame(), code, self.name);
        }
        cmds
    }

    /// `msg`, and everything it asks for carried out.
    fn feed(&mut self, msg: Msg) {
        let cmds = self.update(msg);
        self.carry_out(cmds);
    }

    /// Carries out `cmds` in order, as the UI thread and the workers would,
    /// each result going back to the app before the next command.
    fn carry_out(&mut self, cmds: Vec<Cmd>) {
        let mut queue = VecDeque::from(cmds);
        while let Some(cmd) = queue.pop_front() {
            let result = match cmd {
                Cmd::Store(job) => {
                    workers::run_job(job.name(), || workers::store_job(&self.controller, job))
                }
                Cmd::Send(job) => {
                    workers::run_job(job.name(), || workers::send_job(&self.controller, job))
                }
                Cmd::Node(job) => {
                    self.node_jobs.push(job.clone());
                    match self.node_answer(job) {
                        Some(result) => result,
                        None => continue,
                    }
                }
                // No poller and no screen: the driver looks at the files
                // itself, and draws on demand.
                Cmd::Poll(_) | Cmd::Redraw => continue,
                other => panic!("{}: the app asked for {other:?}", self.name),
            };
            if let JobResult::Sent { outcome, .. } = &result {
                self.sent.push(outcome.result.clone());
            }
            queue.extend(self.update(Msg::Job(result)));
        }
    }

    /// What the node worker would answer `job` with, for the two jobs the
    /// app waits on; None for the rest, which go unanswered. Nothing runs.
    fn node_answer(&self, job: NodeJob) -> Option<JobResult> {
        match job {
            // The keys are in lab files: no vault waits for a passphrase.
            NodeJob::VaultCheck => Some(JobResult::Vault(Vault::default())),
            // The fake answers already, so a start would find it and start
            // nothing: what `Controller::ensure_node` reports then.
            NodeJob::Ensure => Some(JobResult::Ensured(Ensured {
                result: Ok(()),
                after: self.controller.probe_node(),
                started_by_app: None,
                captured: String::new(),
                ring: 0..0,
            })),
            NodeJob::Probe | NodeJob::DetectManaged => None,
            other => panic!("{}: the app asked for node job {other:?}", self.name),
        }
    }

    /// The poller's look at the profile's files: one the app last loaded at
    /// another size or time is loaded again.
    fn poll_files(&mut self) {
        let dir = self.dir().to_path_buf();
        for (watched, path) in [
            (Watched::Contacts, bridge::contacts_path(&dir)),
            (Watched::History, bridge::history_path(&dir)),
        ] {
            let stamp = FileStamp::of(&path);
            self.feed(Msg::Poll(PollUpdate::File { watched, stamp }));
        }
    }

    /// `code` pressed: what it asks for, not carried out yet.
    fn key(&mut self, code: KeyCode) -> Vec<Cmd> {
        self.update(Msg::Key(Key::Event(KeyEvent::new(
            code,
            KeyModifiers::NONE,
        ))))
    }

    /// `code` pressed, and what it asks for carried out.
    fn press(&mut self, code: KeyCode) {
        let cmds = self.key(code);
        self.carry_out(cmds);
    }

    /// Ctrl+`c` pressed, and what it asks for carried out.
    fn ctrl(&mut self, c: char) {
        let cmds = self.update(Msg::Key(Key::Event(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::CONTROL,
        ))));
        self.carry_out(cmds);
    }

    fn type_text(&mut self, text: &str) {
        for c in text.chars() {
            self.press(KeyCode::Char(c));
        }
    }

    /// `text` pasted (bracketed), then the paste guard waited out.
    fn paste(&mut self, text: &str) {
        self.feed(Msg::Paste {
            text: text.to_owned(),
            via: PasteVia::Bracketed,
        });
        self.later(Duration::from_millis(300));
    }

    /// The app's clock moved on by `by`, as the UI thread's tick.
    fn later(&mut self, by: Duration) {
        self.skew += by;
        self.feed(Msg::Tick);
    }

    /// The frame the app draws now.
    fn frame(&self) -> Vec<String> {
        testkit::render_at(&self.app, COLS, ROWS, self.app.now())
    }

    /// The frame drawn with `glyphs` instead of the app's own.
    fn frame_with(&self, glyphs: Glyphs) -> Vec<String> {
        let mut app = self.app.clone();
        app.set_look_for_tests(Look {
            glyphs,
            ..*self.app.look()
        });
        testkit::render_at(&app, COLS, ROWS, app.now())
    }

    /// The newest message of mine with `body` to `peer`: its tick, its
    /// write evidence and what R, C and S may do.
    fn tick(&self, peer: &str, body: &str) -> (Tick, WriteEvidence, Actions) {
        let bubbles = self.app.bubbles(peer);
        let bubble = bubbles
            .iter()
            .rev()
            .find(|bubble| bubble.outgoing() && bubble.body() == body)
            .copied()
            .unwrap_or_else(|| panic!("{}: no message '{body}'", self.name));
        let view = self.app.tick_view(bubble).expect("a tick");
        (view.tick, view.evidence, view.actions)
    }

    /// The history's delivery state of my message `body` to `peer`.
    fn history(&self, peer: &str, body: &str) -> String {
        let history = self.controller.load_history().expect("history");
        history
            .get(peer)
            .and_then(|rows| rows.iter().rev().find(|r| r.outgoing && r.body == body))
            .map(|row| row.delivery.clone())
            .unwrap_or_else(|| panic!("{}: no history row '{body}'", self.name))
    }

    /// The friend `pub_hex` as contacts.json has them.
    fn saved(&self, pub_hex: &str) -> Option<bridge::ContactView> {
        self.controller
            .load_contacts()
            .expect("contacts")
            .into_iter()
            .find(|c| c.pub_hex == pub_hex)
    }

    /// On AF-1: `card` pasted, then `name` given on AF-2; VF opens.
    fn paste_and_name(&mut self, card: &str, name: &str) {
        self.paste(card);
        self.press(KeyCode::Enter);
        self.type_text(name);
        self.press(KeyCode::Enter);
        assert!(
            matches!(self.app.screen(), Screen::Verify(_)),
            "{}: {:?}",
            self.name,
            self.app.screen()
        );
    }

    /// VF's confirmation code typed as shown, then Enter: the friend saved.
    fn confirm(&mut self) {
        let code = self
            .app
            .verify_code_for_tests()
            .unwrap_or_else(|| panic!("{}: no confirmation code", self.name))
            .to_owned();
        self.type_text(&code);
        self.press(KeyCode::Enter);
    }

    /// The composer's text sent with Enter: the send job asked for, not
    /// carried out yet (its message is on screen, Sending).
    fn compose(&mut self, text: &str) -> Vec<Cmd> {
        self.type_text(text);
        let cmds = self.key(KeyCode::Enter);
        assert!(
            testkit::send_job(&cmds).is_some_and(|(_, sent)| sent == text),
            "{}: no send of '{text}' in {cmds:?}",
            self.name
        );
        cmds
    }
}

/// Neither `code` nor any of its groups of 4 on `rows`.
fn assert_no_code(rows: &[String], code: &str, who: &str) {
    let text = rows.join("\n");
    assert!(!text.contains(code), "{who}: {code} on screen:\n{text}");
    for group in code.split('-').filter(|group| group.len() == 4) {
        assert!(
            !text.contains(group),
            "{who}: {group} of {code} on screen:\n{text}"
        );
    }
}

/// `code` typed as read aloud, but with its first letter in the other case.
fn wrong_case(code: &str) -> String {
    let at = code
        .find(|c: char| c.is_ascii_alphabetic())
        .expect("a letter in the code");
    let mut wrong = code.to_owned();
    let flipped = match code.as_bytes()[at] {
        c if c.is_ascii_lowercase() => c.to_ascii_uppercase(),
        c => c.to_ascii_lowercase(),
    };
    wrong.replace_range(at..=at, &char::from(flipped).to_string());
    wrong
}

/// Whether a row of `rows` holds `text`.
fn shows(rows: &[String], text: &str) -> bool {
    rows.iter().any(|row| row.contains(text))
}

#[test]
fn two_profiles_add_verify_and_message_each_other() {
    testkit::lab_backends();
    // 1. The fake nodes answer before anything else touches the profiles.
    let (a_dir, b_dir) = (testkit::short_dir(), testkit::short_dir());
    let a_node = FakeNode::start(a_dir.path(), FakeStatus::listening(4242, LISTEN));
    let b_node = FakeNode::start(b_dir.path(), FakeStatus::listening(4343, LISTEN));

    // 2. Both identities, through the controller.
    let mut alice = Side::new("Alice", a_dir.path());
    let mut bob = Side::new("Bob", b_dir.path());
    let (a_me, b_me) = (alice.me(), bob.me());
    a_node.answer_dials_as(DialPeer {
        dir: b_dir.path().to_path_buf(),
        id: bob.identity(),
        from_dir: a_dir.path().to_path_buf(),
        from_id: alice.identity(),
    });
    // Alice's frames never show Bob's code before it matched; Bob never
    // checks Alice's, so his never show hers.
    alice.hidden = Some(b_me.fingerprint.clone());
    bob.hidden = Some(a_me.fingerprint.clone());

    // 3. Both open Add a friend: the start is asked for (and not run), and
    // each card has this computer's address at the node's port.
    for side in [&mut alice, &mut bob] {
        side.press(KeyCode::Char('a'));
        assert_eq!(
            side.node_jobs
                .iter()
                .filter(|job| **job == NodeJob::Ensure)
                .count(),
            1,
            "{}: {:?}",
            side.name,
            side.node_jobs
        );
        let card = side.app.share_view().and_then(|view| view.line);
        assert!(
            card.as_deref()
                .is_some_and(|card| card.contains(&format!("lan={CARD_LAN}"))),
            "{}: {card:?}",
            side.name
        );
    }
    let a_card = alice.app.share_view().and_then(|v| v.line).expect("card");
    let b_card = bob.app.share_view().and_then(|v| v.line).expect("card");

    // 4. Alice pastes Bob's card, names him, and checks him: his old code
    // first (Ctrl+O), one letter in the wrong case (the case hint, nothing
    // saved); then, back to the words, his security words as he reads them,
    // and the confirmation code.
    alice.paste_and_name(&b_card, "Bob");
    // What she types is hers to see; Bob's code itself stays hidden.
    alice.hidden = None;
    alice.ctrl('o');
    let wrong = wrong_case(&b_me.fingerprint);
    alice.type_text(&wrong);
    alice.press(KeyCode::Enter);
    let view = alice.app.verify_view().expect("VF");
    assert_eq!((view.theirs, view.theirs_words), (None, None));
    assert!(
        testkit::screen_text(&alice.frame()).contains("Upper and lower case differ"),
        "{:?}",
        alice.frame()
    );
    assert_eq!(alice.saved(&b_me.pub_hex), None);
    alice.ctrl('o');
    alice.type_text(&b_me.words.join(" "));
    assert!(alice
        .app
        .verify_view()
        .is_some_and(|view| view.theirs_words.is_none()));
    alice.press(KeyCode::Enter);
    assert!(alice
        .app
        .verify_view()
        .is_some_and(|view| view.theirs.is_some() && view.theirs_words.is_some()));
    assert!(
        testkit::screen_text(&alice.frame()).contains("They match"),
        "{:?}",
        alice.frame()
    );
    alice.confirm();
    assert!(matches!(alice.app.screen(), Screen::Added(added) if added.verified));
    let row = alice.saved(&b_me.pub_hex).expect("Bob saved");
    assert!(row.pinned);
    assert_eq!(
        (row.label.as_str(), row.lan_dial.as_str()),
        ("Bob", CARD_LAN)
    );

    // 5. Bob adds Alice as not verified (Later), after the confirmation code.
    bob.paste_and_name(&a_card, "Alice");
    bob.press(KeyCode::Tab);
    bob.confirm();
    assert!(matches!(bob.app.screen(), Screen::Added(added) if !added.verified));
    let row = bob.saved(&a_me.pub_hex).expect("Alice saved");
    assert!(!row.pinned);
    assert_eq!(row.label, "Alice");
    bob.press(KeyCode::Esc);
    assert_eq!(bob.app.screen(), &Screen::Home);

    // 6. Alice opens the chat and sends: Connecting, then Delivered.
    alice.press(KeyCode::Enter);
    assert_eq!(alice.app.open_friend(), Some(b_me.pub_hex.as_str()));
    let cmds = alice.compose("hello bob");
    let bob_key = b_me.pub_hex.as_str();
    assert_eq!(alice.tick(bob_key, "hello bob").0, Tick::Connecting);
    alice.carry_out(cmds);
    assert_eq!(alice.tick(bob_key, "hello bob").0, Tick::Delivered);
    let sent = &alice.app.sends()[0];
    assert!(sent.captured.contains("confirmed"), "{}", sent.captured);
    let dials = a_node.dials();
    assert!(
        !dials.is_empty() && dials.iter().all(|dial| dial == CARD_LAN),
        "{dials:?}"
    );
    alice.later(Duration::from_secs(1));
    assert!(
        shows(&alice.frame(), "You - just now  vv Delivered"),
        "{:?}",
        alice.frame()
    );
    let fancy = alice.frame_with(Glyphs::fancy());
    assert!(shows(&fancy, "You · just now  ✓✓ Delivered"), "{fancy:?}");
    assert_eq!(alice.history(bob_key, "hello bob"), "delivered");
    alice.poll_files();
    assert_eq!(alice.tick(bob_key, "hello bob").0, Tick::Delivered);

    // 7. Bob's history has it: one unread, and Alice in touch (the row came
    // after his first load).
    bob.poll_files();
    let alice_key = a_me.pub_hex.as_str();
    let rows = bob.app.rows(alice_key);
    assert!(
        rows.iter()
            .any(|row| !row.view.outgoing && row.view.body == "hello bob"),
        "{rows:?}"
    );
    assert_eq!(bob.app.unread(alice_key), 1);
    let friend = bob.app.friend(alice_key).expect("Alice listed").clone();
    let now = (bob.app.now(), bob.app.now_ms());
    assert!(matches!(
        presence::presence(&friend, bob.app.rows(alice_key), now.0, now.1),
        Presence::Recent { .. }
    ));
    // Her row in the list: highlighted, the in-touch mark, the unread badge.
    let dot = bob.app.look().glyphs.dot_recent;
    let in_list: Vec<String> = bob
        .frame()
        .iter()
        .map(|row| row.chars().skip(1).take(20).collect())
        .collect();
    assert!(
        in_list
            .iter()
            .any(|row| row.starts_with(&format!("> {dot} Alice "))
                && row.trim_end().ends_with(" 1 new")),
        "{in_list:?}"
    );

    // 8. Bob's Raven stops answering: the next message waits for the one
    // after it, and never left this computer.
    let refused = format!(
        "lan connect: cannot connect to {CARD_LAN} ({CARD_LAN}: Connection refused (os error 61))"
    );
    a_node.refuse_dials(&refused);
    let cmds = alice.compose("second");
    alice.carry_out(cmds);
    let outcome = alice.sent.last().expect("the send of 'second' ended");
    assert!(
        matches!(outcome, SendResult::Failed(text) if text.starts_with(bridge::QUEUED_PREFIX)),
        "{outcome:?}"
    );
    let (tick, evidence, _) = alice.tick(bob_key, "second");
    assert_eq!(tick, Tick::Waiting(Waiting::NextSend), "{outcome:?}");
    assert_eq!(evidence, WriteEvidence::NeverWritten);
    assert!(
        shows(
            &alice.frame(),
            // In the run of yours: no sender line of its own.
            "  ~ Waiting: goes out with your next message"
        ),
        "{:?}",
        alice.frame()
    );
    assert_eq!(alice.history(bob_key, "second"), "queued");

    // 9. Back again: the next message goes, and takes the waiting one along.
    a_node.accept_dials();
    let cmds = alice.compose("third");
    alice.carry_out(cmds);
    assert_eq!(alice.tick(bob_key, "third").0, Tick::Delivered);
    alice.poll_files();
    assert_eq!(alice.history(bob_key, "second"), "delivered");
    assert_eq!(alice.tick(bob_key, "second").0, Tick::Delivered);

    // 10. Refused again: one more waits, and C stops it (after a yes). It
    // never left this computer, so R sends it again.
    a_node.refuse_dials(&refused);
    let cmds = alice.compose("fourth");
    alice.carry_out(cmds);
    alice.poll_files();
    assert!(alice.tick(bob_key, "fourth").2.stop, "its id is known");
    alice.press(KeyCode::Tab);
    alice.press(KeyCode::Char('c'));
    alice.press(KeyCode::Char('y'));
    assert!(
        alice.app.toasts_for_tests().contains(&STOPPED_TOAST),
        "{:?}",
        alice.app.toasts_for_tests()
    );
    alice.poll_files();
    assert_eq!(alice.history(bob_key, "fourth"), "cancelled");
    let (tick, evidence, actions) = alice.tick(bob_key, "fourth");
    assert_eq!(
        (tick, evidence),
        (Tick::Ended { expired: false }, WriteEvidence::NeverWritten)
    );
    assert!(actions.send_again && !actions.send_again_anyway);
    assert!(
        testkit::screen_text(&alice.frame()).contains("Not delivered: it never left this computer"),
        "{:?}",
        alice.frame()
    );
    let cmds = alice.key(KeyCode::Char('r'));
    assert_eq!(
        testkit::send_job(&cmds).map(|(_, text)| text),
        Some("fourth".to_owned())
    );
    a_node.accept_dials();
    alice.carry_out(cmds);
    assert!(
        matches!(alice.sent.last(), Some(SendResult::Delivered(to)) if to.dial.as_deref() == Some(CARD_LAN)),
        "{:?}",
        alice.sent
    );

    // 11. No node was ever started (no service log in either profile; no
    // node job ran, and none but the four above was asked for), and every
    // dial went through Alice's fake, at the card's address.
    for side in [&alice, &bob] {
        assert!(
            !bridge::service_log_path(side.dir()).exists(),
            "{}: a raven-node ran",
            side.name
        );
    }
    assert!(a_node.dials().iter().all(|dial| dial == CARD_LAN));
    assert!(b_node.dials().is_empty());
}
