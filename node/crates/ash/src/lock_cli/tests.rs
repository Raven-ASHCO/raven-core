//! Lock now v2's and the Raven passphrase's command-line flows (P6.40),
//! against answers a test writes: the v1 fallback, the unlock's retries and
//! back-off, and a change of the passphrase with raven-node held.

use std::cell::RefCell;

use super::*;

fn error(code: &str, message: &str) -> Result<IpcResponse, String> {
    Ok(IpcResponse::Error {
        v: IPC_VERSION,
        code: code.into(),
        message: message.into(),
    })
}

fn lock_state(locked: bool, passphrase: bool, failed_unlocks: u32) -> Result<IpcResponse, String> {
    Ok(IpcResponse::LockState {
        v: IPC_VERSION,
        locked,
        passphrase,
        failed_unlocks,
    })
}

fn secret(text: &str) -> SecretBytes {
    SecretBytes::new(text.as_bytes().to_vec())
}

/// The passphrase an `Unlock` carries, decoded.
fn carried(req: &IpcRequest) -> Option<Vec<u8>> {
    match req {
        IpcRequest::Unlock { passphrase_b64, .. } => passphrase_b64
            .as_ref()
            .map(|p| p.decode_b64().expect("base64").to_vec()),
        other => panic!("not an unlock: {other:?}"),
    }
}

/// An older raven-node answers `IPC_FRAME` to `Lock` and one whose gate is
/// shut `LOCK_V2_HELD`: `raven lock` falls back to Lock now v1 (stop it).
#[test]
fn an_older_daemon_answers_ipc_frame_and_raven_lock_falls_back_to_v1() {
    for code in ["IPC_FRAME", raven_core::ipc::LOCK_V2_HELD] {
        let sent = RefCell::new(Vec::new());
        let v1 = lock_v2_with(|req| {
            sent.borrow_mut().push(req.clone());
            error(code, "unknown variant `lock`")
        })
        .unwrap();
        assert_eq!(v1, None, "{code}");
        assert_eq!(sent.into_inner(), [IpcRequest::Lock { v: IPC_VERSION }]);
    }
    assert_eq!(
        lock_v2_with(|_| lock_state(true, false, 0)).unwrap(),
        Some(lock_v2_lines(false))
    );
    assert!(lock_v2_with(|_| error("INTERNAL", "it broke")).is_err());
    assert!(lock_v2_with(|_| Err("no answer".into())).is_err());
}

/// The keychain profile's lock and unlock say plainly what a lock does not
/// protect; a passphrase profile's do not need to.
#[test]
fn a_keychain_lock_says_what_it_does_not_protect() {
    let honest = raven_core::privacy::keys_open_to_login_text();
    assert!(honest.contains("Anyone who can log in as you can open them"));
    assert!(lock_v2_question(false).contains(honest));
    assert!(!lock_v2_question(true).contains(honest));
    assert!(lock_v2_question(true).contains("Your Raven passphrase opens it again"));
    assert_eq!(
        lock_v2_lines(false).last().map(String::as_str),
        Some(honest)
    );
    assert!(!lock_v2_lines(true).iter().any(|l| l == honest));
    assert_eq!(
        lock_v2_lines(true)[0],
        "Raven is locked. Friends can't reach you; your messages wait here."
    );
    assert_eq!(unlocked_lines(false, 0), [UNLOCKED_LINE, honest]);
    assert_eq!(unlocked_lines(true, 0), [UNLOCKED_LINE]);
}

/// A passphrase profile: a wrong passphrase is asked again, the node's
/// back-off is sat out with the same passphrase, and the unlock says how
/// many wrong ones came. The passphrase travels only in its field.
#[test]
fn unlock_asks_again_after_a_wrong_passphrase_and_waits_out_the_back_off() {
    let typed = RefCell::new(vec![secret("right one"), secret("wrong one")]);
    let mut read = || Ok(typed.borrow_mut().pop().unwrap());
    let answers = RefCell::new(vec![
        lock_state(false, true, 1),
        error(
            raven_core::ipc::UNLOCK_WAIT,
            "Wait 2 s before you try again.",
        ),
        error(
            raven_core::ipc::UNLOCK_WRONG_PASSPHRASE,
            "That passphrase is not right.",
        ),
    ]);
    let sent = RefCell::new(Vec::new());
    let mut send = |req: &IpcRequest| {
        sent.borrow_mut().push(carried(req));
        answers.borrow_mut().pop().unwrap()
    };
    let slept = RefCell::new(Vec::new());
    let mut sleep = |d: Duration| slept.borrow_mut().push(d);
    let said = RefCell::new(Vec::new());
    let mut say = |line: &str| said.borrow_mut().push(line.to_owned());
    let lines = unlock_v2_with(true, &mut read, &mut send, &mut sleep, &mut say).unwrap();
    assert_eq!(
        lines,
        [
            UNLOCKED_LINE.to_owned(),
            "Someone typed a wrong Raven passphrase 1 time while Raven was locked.".to_owned()
        ]
    );
    assert_eq!(
        sent.into_inner(),
        [
            Some(b"wrong one".to_vec()),
            Some(b"right one".to_vec()),
            Some(b"right one".to_vec())
        ]
    );
    assert_eq!(slept.into_inner(), [Duration::from_secs(2)]);
    assert_eq!(said.into_inner().len(), 2);
    assert_eq!(wait_of("Wait 600 s"), UNLOCK_MAX_WAIT);
    assert_eq!(wait_of("Wait a moment"), Duration::from_secs(1));
}

/// A keychain profile resumes with no passphrase read; a node that asks
/// for one gets it; three wrong ones end it, still locked.
#[test]
fn unlock_reads_a_passphrase_only_when_one_is_needed() {
    let mut never = || -> Result<SecretBytes, String> { panic!("no passphrase is read") };
    let mut send = |req: &IpcRequest| {
        assert_eq!(carried(req), None);
        lock_state(false, false, 0)
    };
    let lines = unlock_v2_with(false, &mut never, &mut send, &mut |_| {}, &mut |_| {}).unwrap();
    assert_eq!(lines[0], UNLOCKED_LINE);

    let reads = RefCell::new(0);
    let mut read = || {
        *reads.borrow_mut() += 1;
        Ok(secret("asked for"))
    };
    let mut send = |req: &IpcRequest| match carried(req) {
        None => error(
            raven_core::ipc::UNLOCK_PASSPHRASE_REQUIRED,
            "This profile has a Raven passphrase.",
        ),
        Some(_) => lock_state(false, true, 0),
    };
    unlock_v2_with(false, &mut read, &mut send, &mut |_| {}, &mut |_| {}).unwrap();
    assert_eq!(reads.into_inner(), 1);

    let mut read = || Ok(secret("always wrong"));
    let mut send = |_: &IpcRequest| error(raven_core::ipc::UNLOCK_WRONG_PASSPHRASE, "No.");
    let refused = unlock_v2_with(true, &mut read, &mut send, &mut |_| {}, &mut |_| {});
    assert_eq!(
        refused,
        Err(format!(
            "Raven stays locked: no right passphrase in {UNLOCK_TRIES} tries."
        ))
    );
}

fn typed(current: Option<&str>, new: Option<&str>) -> Typed {
    Typed {
        current: current.map(secret),
        new: new.map(secret),
    }
}

/// raven-node as `run_op_with` meets it: it locks, and unlocks only with
/// the passphrase that opens the profile (`opens`; `None`: a keychain
/// profile, no passphrase needed), counting each wrong one as raven-node
/// does (`SEC_UNLOCK_FAILED`, said at the next unlock).
struct FakeNode {
    opens: RefCell<Option<Vec<u8>>>,
    locked: RefCell<bool>,
    wrong: RefCell<u32>,
    order: RefCell<Vec<String>>,
}

impl FakeNode {
    fn new(opens: Option<&str>) -> Self {
        FakeNode {
            opens: RefCell::new(opens.map(|p| p.as_bytes().to_vec())),
            locked: RefCell::new(false),
            wrong: RefCell::new(0),
            order: RefCell::new(Vec::new()),
        }
    }

    fn answer(&self, req: &IpcRequest) -> Result<IpcResponse, String> {
        match req {
            IpcRequest::Lock { .. } => {
                self.order.borrow_mut().push("lock".to_owned());
                *self.locked.borrow_mut() = true;
                lock_state(true, self.opens.borrow().is_some(), 0)
            }
            IpcRequest::Unlock { .. } => {
                self.order.borrow_mut().push("unlock".to_owned());
                let opens = self.opens.borrow().clone();
                match (opens, carried(req)) {
                    (None, _) => {}
                    (Some(_), None) => {
                        return error(
                            raven_core::ipc::UNLOCK_PASSPHRASE_REQUIRED,
                            "This profile has a Raven passphrase.",
                        )
                    }
                    (Some(right), Some(given)) if right == given => {}
                    (Some(_), Some(_)) => {
                        *self.wrong.borrow_mut() += 1;
                        return error(
                            raven_core::ipc::UNLOCK_WRONG_PASSPHRASE,
                            "That passphrase is not right.",
                        );
                    }
                }
                *self.locked.borrow_mut() = false;
                lock_state(false, self.opens.borrow().is_some(), 0)
            }
            other => panic!("{other:?}"),
        }
    }
}

/// A node that runs unlocked is locked before the change and unlocked
/// after with what opens the profile then; a change that failed (not for
/// a wrong passphrase) unlocks with what opened it before.
#[test]
fn a_change_of_the_passphrase_holds_the_node_locked_meanwhile() {
    for (op, ok, before, after) in [
        (PassOp::Set, true, None, Some("new passphrase")),
        (PassOp::Set, false, None, None),
        (
            PassOp::Change,
            true,
            Some("old passphrase"),
            Some("new passphrase"),
        ),
        (
            PassOp::Change,
            false,
            Some("old passphrase"),
            Some("old passphrase"),
        ),
        (PassOp::Remove, true, Some("old passphrase"), None),
        (
            PassOp::Remove,
            false,
            Some("old passphrase"),
            Some("old passphrase"),
        ),
    ] {
        let typed = typed(
            op.needs_current().then_some("old passphrase"),
            op.needs_new().then_some("new passphrase"),
        );
        let node = FakeNode::new(before);
        let mut check = || Ok(());
        let mut send = |req: &IpcRequest| node.answer(req);
        let mut apply = || {
            node.order.borrow_mut().push("change".to_owned());
            if ok {
                *node.opens.borrow_mut() = after.map(|p| p.as_bytes().to_vec());
                Ok(Moved::default())
            } else {
                Err(PassError::Failed("the disk is full".into()))
            }
        };
        let done = run_op_with(
            op,
            &typed,
            NodeHold::Unlocked,
            &mut check,
            &mut send,
            &mut apply,
            None,
        );
        assert_eq!(
            node.order.borrow().as_slice(),
            ["lock", "change", "unlock"],
            "{op:?}"
        );
        assert_eq!(done.is_ok(), ok, "{op:?}");
        assert!(!*node.locked.borrow(), "{op:?} {ok}: unlocked again");
        assert_eq!(*node.wrong.borrow(), 0, "{op:?} {ok}");
        if !ok {
            assert_eq!(done.unwrap_err(), "the disk is full");
        }
    }
}

/// A typo in the current passphrase of a change or a remove (review
/// lock-updates-local-1): checked before raven-node is held, it changes
/// nothing and raven-node keeps running unlocked; it never reaches
/// raven-node as a wrong unlock (which would leave it locked and say "Someone
/// typed a wrong Raven passphrase" at the next unlock). Should the change
/// itself still find it wrong, that passphrase is not sent: raven-node
/// stays locked and says nothing false.
#[test]
fn a_wrong_current_passphrase_never_reaches_raven_node() {
    for op in [PassOp::Change, PassOp::Remove] {
        let typed = typed(Some("a typo"), op.needs_new().then_some("new passphrase"));
        let node = FakeNode::new(Some("old passphrase"));
        let mut check = || Err(PassError::Wrong);
        let mut send = |req: &IpcRequest| node.answer(req);
        let mut never = || -> Result<Moved, PassError> { panic!("nothing changes") };
        let done = run_op_with(
            op,
            &typed,
            NodeHold::Unlocked,
            &mut check,
            &mut send,
            &mut never,
            None,
        );
        assert_eq!(done, Err(raven_passphrase::WRONG.to_owned()), "{op:?}");
        assert!(node.order.borrow().is_empty(), "{op:?}: no IPC at all");
        assert!(!*node.locked.borrow());

        // The check passed, the change found it wrong after all (the vault
        // changed meanwhile): no unlock with it.
        let node = FakeNode::new(Some("old passphrase"));
        let mut check = || Ok(());
        let mut send = |req: &IpcRequest| node.answer(req);
        let mut wrong = || Err(PassError::Wrong);
        let done = run_op_with(
            op,
            &typed,
            NodeHold::Unlocked,
            &mut check,
            &mut send,
            &mut wrong,
            None,
        );
        assert_eq!(
            done,
            Err(format!("{}\n{STAYS_LOCKED}", raven_passphrase::WRONG)),
            "{op:?}"
        );
        assert_eq!(node.order.borrow().as_slice(), ["lock"], "{op:?}");
        assert_eq!(*node.wrong.borrow(), 0, "{op:?}: no wrong unlock counted");
    }
    // No node to hold: nothing is checked first (the change itself says).
    let typed = typed(Some("a typo"), Some("new passphrase"));
    let mut no_check = || -> Result<(), PassError> { panic!("not held: no check") };
    let mut no_ipc = |req: &IpcRequest| -> Result<IpcResponse, String> { panic!("{req:?}") };
    let mut wrong = || Err(PassError::Wrong);
    assert_eq!(
        run_op_with(
            PassOp::Change,
            &typed,
            NodeHold::Absent,
            &mut no_check,
            &mut no_ipc,
            &mut wrong,
            None,
        ),
        Err(raven_passphrase::WRONG.to_owned())
    );
}

/// A change on a profile whose passphrase this computer keeps in a file
/// (the headless GNU/Linux service's, review lock-updates-local-2) says
/// that file is stale and names it; without one, the lines are as before.
/// Set and remove never mention it.
#[test]
fn a_change_names_the_saved_passphrase_file_it_leaves_stale() {
    let file = std::path::Path::new("/srv/raven/keystore-passphrase");
    let lines = done_lines(PassOp::Change, &Moved::default(), Some(file));
    assert_eq!(lines[0], "Your Raven passphrase is changed.");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[1].contains("/srv/raven/keystore-passphrase"),
        "{lines:?}"
    );
    assert!(lines[1].contains("put the new passphrase in that file now"));
    assert!(lines[1].contains("Raven will not start next time"));
    assert_eq!(
        done_lines(PassOp::Change, &Moved::default(), None),
        ["Your Raven passphrase is changed."]
    );
    for op in [PassOp::Set, PassOp::Remove] {
        assert_eq!(
            done_lines(op, &Moved::default(), Some(file)),
            done_lines(op, &Moved::default(), None)
        );
    }
    // Through the change itself, before raven-node's unlock note.
    let typed = typed(Some("old passphrase"), Some("new passphrase"));
    let mut check = || Ok(());
    let mut no_ipc = |req: &IpcRequest| -> Result<IpcResponse, String> { panic!("{req:?}") };
    let mut apply = || Ok(Moved::default());
    let lines = run_op_with(
        PassOp::Change,
        &typed,
        NodeHold::Locked,
        &mut check,
        &mut no_ipc,
        &mut apply,
        Some(file),
    )
    .unwrap();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[1].contains("/srv/raven/keystore-passphrase"));
    assert_eq!(lines[2], STAYS_LOCKED);
    // A name with escape sequences is shown inert.
    let odd = std::path::Path::new("/tmp/a\x1b[2Jb");
    assert!(!saved_file_line(odd, true).contains('\x1b'));
    assert!(saved_file_line(odd, false).contains("after this change"));
}

/// No node: no IPC. A locked node stays locked (and says so). A node that
/// cannot be held is refused before anything changes.
#[test]
fn a_change_without_a_node_or_with_a_locked_one_sends_nothing() {
    let typed = typed(None, Some("new passphrase"));
    let mut check = || Ok(());
    let mut no_ipc = |req: &IpcRequest| -> Result<IpcResponse, String> { panic!("{req:?}") };
    let mut apply = || {
        Ok(Moved {
            keys: 4,
            left: vec!["a conversation key (the keychain said no)".into()],
        })
    };
    let lines = run_op_with(
        PassOp::Set,
        &typed,
        NodeHold::Absent,
        &mut check,
        &mut no_ipc,
        &mut apply,
        None,
    )
    .unwrap();
    assert!(lines[0].starts_with("Your Raven passphrase is set."));
    assert!(lines.last().unwrap().contains("a conversation key"));
    let lines = run_op_with(
        PassOp::Set,
        &typed,
        NodeHold::Locked,
        &mut check,
        &mut no_ipc,
        &mut apply,
        None,
    )
    .unwrap();
    assert_eq!(lines.last().map(String::as_str), Some(STAYS_LOCKED));
    let mut never = || -> Result<Moved, PassError> { panic!("nothing changes") };
    assert_eq!(
        run_op_with(
            PassOp::Set,
            &typed,
            NodeHold::Unheld,
            &mut check,
            &mut no_ipc,
            &mut never,
            None,
        ),
        Err(NODE_UNHELD.to_owned())
    );
}

/// What each profile is offered, and the words for what it is not.
#[test]
fn the_ops_follow_what_the_profile_offers() {
    assert!(PassOp::Set.offered(&Offer::Set));
    assert!(!PassOp::Change.offered(&Offer::Set));
    assert!(PassOp::Change.offered(&Offer::ChangeOrRemove));
    assert!(PassOp::Remove.offered(&Offer::ChangeOrRemove));
    assert!(PassOp::Change.offered(&Offer::Change));
    assert!(!PassOp::Remove.offered(&Offer::Change));
    assert!(!PassOp::Set.offered(&Offer::No("x")));
    // A switch that stopped halfway is offered change or remove, and set
    // finishes it too (review lock-updates-local-4).
    assert!(allowed(PassOp::Remove, &Offer::ChangeOrRemove, true));
    assert!(allowed(PassOp::Set, &Offer::ChangeOrRemove, true));
    assert!(!allowed(PassOp::Set, &Offer::ChangeOrRemove, false));
    assert!(!allowed(PassOp::Set, &Offer::No("x"), true));
    assert!(!allowed(PassOp::Set, &Offer::Change, true));
    assert!(allowed(PassOp::Set, &Offer::Set, false));
    assert_eq!(refusal(PassOp::Set, &Offer::No("not here")), "not here");
    assert_eq!(
        refusal(PassOp::Change, &Offer::Set),
        raven_passphrase::NONE_SET
    );
    assert_eq!(
        refusal(PassOp::Set, &Offer::ChangeOrRemove),
        raven_passphrase::ALREADY_SET
    );
    assert_eq!(status_lines(&Offer::No("why")), ["why"]);
    assert!(status_lines(&Offer::Set)
        .iter()
        .any(|l| l == raven_core::privacy::keys_open_to_login_text()));
}
