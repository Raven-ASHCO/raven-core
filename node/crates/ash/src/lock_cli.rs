//! Lock now v2 and the Raven passphrase on the command line (Phase 6 P6.40,
//! gate `LOCAL_PROTECTION`; design C §6, OD6b-18).
//!
//! `raven lock` / `raven unlock` lock and unlock a running raven-node that
//! serves Lock v2 (IPC `Lock` / `Unlock`: it keeps running and holds no
//! key), and fall back to Lock now v1 (PP.15: stop it) when it does not (an
//! older one answers `IPC_FRAME`, one whose gate is shut `LOCK_V2_HELD`).
//! `raven passphrase` sets, changes or removes the Raven passphrase
//! ([`raven_core::raven_passphrase`]) with raven-node held locked
//! meanwhile. Passphrases come from the terminal without echo, never argv
//! or the environment, and are wiped when dropped. The terminal app reaches
//! the same flows through `tui::bridge`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use raven_core::ipc::{IpcRequest, IpcResponse, IpcSecret, SecretBytes, IPC_VERSION};
use raven_core::raven_passphrase::{self, Moved, Offer, PassError};
use raven_core::sanitize::sanitize_terminal_line;
use raven_core::security_gate::{self, SecGate};

use super::ipc_client;

/// How long `raven lock` and `raven unlock` wait for raven-node's answer (a
/// lock says goodbye to the relays first; an unlock checks a passphrase
/// with Argon2id).
const LOCK_V2_WAIT: Duration = Duration::from_secs(20);
/// How many passphrases `raven unlock` asks for before it gives up.
const UNLOCK_TRIES: usize = 3;
/// The longest wait `raven unlock` sits out after a wrong passphrase.
const UNLOCK_MAX_WAIT: Duration = Duration::from_secs(60);
/// What `raven unlock` asks (never echoed).
const UNLOCK_PROMPT: &str = "Raven passphrase: ";
/// What `raven unlock` says when it opened.
pub(super) const UNLOCKED_LINE: &str = "Raven is unlocked. Friends can reach you again.";

/// Lock v2 is offered: its gate is live in this build and this profile's
/// raven-node answers with `Status.locked` (it serves v2, and its gate is
/// live too): whether it is locked. `None`: Lock now v1 (no node, an older
/// one, or a gate shut).
pub(super) fn node_lock_v2(data_dir: &Path) -> Option<bool> {
    if !security_gate::live(SecGate::LocalProtection) {
        return None;
    }
    match ipc_client::ipc_request_timeout(data_dir, &IpcRequest::status(), Duration::from_secs(3)) {
        Ok(IpcResponse::Status { locked, .. }) => locked,
        _ => None,
    }
}

/// `raven lock`'s v2 question (UX copy): what a lock does, and on a profile
/// without a Raven passphrase what it does not protect.
pub(super) fn lock_v2_question(passphrase: bool) -> String {
    let what = "Lock Raven now? Raven keeps running but forgets its keys: friends can't reach \
                you, and your messages wait here.";
    if passphrase {
        format!("{what} Your Raven passphrase opens it again. [y/N] ")
    } else {
        format!(
            "{what}\n{}\n[y/N] ",
            raven_core::privacy::keys_open_to_login_text()
        )
    }
}

/// What `raven lock` says once raven-node is locked (v2).
pub(super) fn lock_v2_lines(passphrase: bool) -> Vec<String> {
    let mut lines = vec![
        raven_core::privacy::LOCKED_V2_SCREEN.to_owned(),
        "Run `raven unlock` to open it again.".to_owned(),
    ];
    if !passphrase {
        lines.push(raven_core::privacy::keys_open_to_login_text().to_owned());
    }
    lines
}

/// `raven lock` v2 once the node serves it: the question (unless `--yes`),
/// then IPC `Lock`. `Ok(None)`: the node did not take it, so Lock now v1
/// follows.
pub(super) fn lock_v2(data_dir: &Path, yes: bool) -> Result<Option<Vec<String>>, String> {
    if !yes {
        let passphrase = raven_core::keystore_select::has_passphrase(data_dir).unwrap_or(false);
        print!("{}", lock_v2_question(passphrase));
        let _ = io::stdout().flush();
        if !super::read_decision_line().is_some_and(|answer| super::answer_is_yes(&answer)) {
            return Err("cancelled — Raven keeps running".into());
        }
    }
    lock_v2_with(|req| ipc_client::ipc_request_timeout(data_dir, req, LOCK_V2_WAIT))
}

/// IPC `Lock` through `send`: the lines to print, or `None` when the node
/// does not take it (an older one answers `IPC_FRAME`; one whose gate is
/// shut `LOCK_V2_HELD`): Lock now v1 then.
pub(super) fn lock_v2_with(
    send: impl FnOnce(&IpcRequest) -> Result<IpcResponse, String>,
) -> Result<Option<Vec<String>>, String> {
    match send(&IpcRequest::Lock { v: IPC_VERSION }) {
        Ok(IpcResponse::LockState {
            locked: true,
            passphrase,
            ..
        }) => Ok(Some(lock_v2_lines(passphrase))),
        Ok(IpcResponse::Error { code, .. })
            if code == "IPC_FRAME" || code == raven_core::ipc::LOCK_V2_HELD =>
        {
            Ok(None)
        }
        Ok(IpcResponse::Error { message, .. }) => Err(sanitize_terminal_line(&message)),
        Ok(_) => Err("raven-node gave an unexpected answer to the lock".into()),
        Err(e) => Err(format!(
            "raven-node did not lock: {}",
            sanitize_terminal_line(&e)
        )),
    }
}

/// `raven unlock` v2: a profile with a Raven passphrase asks for it on the
/// terminal (never echoed, never argv or the environment).
pub(super) fn unlock_v2(data_dir: &Path) -> Result<Vec<String>, String> {
    let passphrase = raven_core::keystore_select::has_passphrase(data_dir).unwrap_or(true);
    let mut read = || read_hidden(UNLOCK_PROMPT);
    let mut send = |req: &IpcRequest| ipc_client::ipc_request_timeout(data_dir, req, LOCK_V2_WAIT);
    let mut say = |line: &str| eprintln!("{line}");
    unlock_v2_with(
        passphrase,
        &mut read,
        &mut send,
        &mut std::thread::sleep,
        &mut say,
    )
}

/// One passphrase from the terminal, without echo.
fn read_hidden(prompt: &str) -> Result<SecretBytes, String> {
    if !super::stdin_is_tty() {
        return Err(
            "Raven needs a terminal to read your Raven passphrase (it is never taken from \
             arguments or the environment)"
                .into(),
        );
    }
    raven_core::keystore_vault::read_hidden_passphrase(prompt).map_err(|e| e.to_string())
}

/// The unlock: `Unlock` with the passphrase `read` gives (only when the
/// profile has one, or the node asks for it), at most [`UNLOCK_TRIES`]
/// passphrases. After a wrong one the node's back-off is sat out (`sleep`)
/// and the same passphrase goes again; `say` gets the notes. The lines to
/// print once unlocked.
pub(super) fn unlock_v2_with(
    passphrase_profile: bool,
    read: &mut dyn FnMut() -> Result<SecretBytes, String>,
    send: &mut dyn FnMut(&IpcRequest) -> Result<IpcResponse, String>,
    sleep: &mut dyn FnMut(Duration),
    say: &mut dyn FnMut(&str),
) -> Result<Vec<String>, String> {
    let mut wants = passphrase_profile;
    let mut passphrase: Option<SecretBytes> = None;
    let mut typed = 0usize;
    loop {
        if wants && passphrase.is_none() {
            if typed == UNLOCK_TRIES {
                return Err(format!(
                    "Raven stays locked: no right passphrase in {UNLOCK_TRIES} tries."
                ));
            }
            typed += 1;
            passphrase = Some(read()?);
        }
        match send(&unlock_request(passphrase.as_deref().map(|p| &p[..]))) {
            Ok(IpcResponse::LockState {
                locked: false,
                passphrase: had,
                failed_unlocks,
                ..
            }) => return Ok(unlocked_lines(had, failed_unlocks)),
            Ok(IpcResponse::Error { code, message, .. }) => {
                let message = sanitize_terminal_line(&message);
                match code.as_str() {
                    raven_core::ipc::UNLOCK_PASSPHRASE_REQUIRED if !wants => wants = true,
                    raven_core::ipc::UNLOCK_WRONG_PASSPHRASE => {
                        say(&message);
                        passphrase = None;
                    }
                    raven_core::ipc::UNLOCK_WAIT => {
                        say(&message);
                        sleep(wait_of(&message));
                    }
                    _ => return Err(message),
                }
            }
            Ok(_) => return Err("raven-node gave an unexpected answer to the unlock".into()),
            Err(e) => {
                return Err(format!(
                    "raven-node did not unlock: {}",
                    sanitize_terminal_line(&e)
                ))
            }
        }
    }
}

/// What one `Unlock` came to (the terminal app's LOCKED screen asks once
/// per Enter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum UnlockAnswer {
    /// Unlocked: the lines to say.
    Opened(Vec<String>),
    /// That passphrase is not right (the node's words).
    Wrong(String),
    /// The back-off after a wrong one: how long to wait (its words).
    Wait(String),
    /// This profile has a Raven passphrase and none came.
    NeedsPassphrase(String),
    /// Anything else (its words).
    Failed(String),
}

/// One `Unlock` of this profile's raven-node with `passphrase`.
pub(super) fn unlock_once(data_dir: &Path, passphrase: Option<&[u8]>) -> UnlockAnswer {
    answer_of(ipc_client::ipc_request_timeout(
        data_dir,
        &unlock_request(passphrase),
        LOCK_V2_WAIT,
    ))
}

/// What raven-node's answer to one `Unlock` says.
pub(super) fn answer_of(answer: Result<IpcResponse, String>) -> UnlockAnswer {
    match answer {
        Ok(IpcResponse::LockState {
            locked: false,
            passphrase,
            failed_unlocks,
            ..
        }) => UnlockAnswer::Opened(unlocked_lines(passphrase, failed_unlocks)),
        Ok(IpcResponse::Error { code, message, .. }) => {
            let message = sanitize_terminal_line(&message);
            match code.as_str() {
                raven_core::ipc::UNLOCK_WRONG_PASSPHRASE => UnlockAnswer::Wrong(message),
                raven_core::ipc::UNLOCK_WAIT => UnlockAnswer::Wait(message),
                raven_core::ipc::UNLOCK_PASSPHRASE_REQUIRED => {
                    UnlockAnswer::NeedsPassphrase(message)
                }
                _ => UnlockAnswer::Failed(message),
            }
        }
        Ok(_) => UnlockAnswer::Failed("raven-node gave an unexpected answer to the unlock".into()),
        Err(e) => UnlockAnswer::Failed(format!(
            "raven-node did not unlock: {}",
            sanitize_terminal_line(&e)
        )),
    }
}

/// IPC `Lock` of this profile's raven-node: `Ok(true)` locked, `Ok(false)`
/// it does not serve Lock v2 (Lock now v1 then).
pub(super) fn lock_once(data_dir: &Path) -> Result<bool, String> {
    lock_v2_with(|req| ipc_client::ipc_request_timeout(data_dir, req, LOCK_V2_WAIT))
        .map(|lines| lines.is_some())
}

/// IPC `Unlock` with `passphrase` (base64 in a field that is never logged
/// and wiped when dropped).
pub(super) fn unlock_request(passphrase: Option<&[u8]>) -> IpcRequest {
    IpcRequest::Unlock {
        v: IPC_VERSION,
        passphrase_b64: passphrase.map(IpcSecret::of_bytes),
    }
}

/// The seconds an `UNLOCK_WAIT` message names (1 when it names none), at
/// most [`UNLOCK_MAX_WAIT`].
pub(super) fn wait_of(message: &str) -> Duration {
    let secs = message
        .split_whitespace()
        .find_map(|word| word.parse::<u64>().ok())
        .unwrap_or(1);
    Duration::from_secs(secs).min(UNLOCK_MAX_WAIT)
}

/// What an unlock says: that it opened, how many wrong passphrases came
/// while it was locked, and on a profile without a Raven passphrase what a
/// lock does not protect.
pub(super) fn unlocked_lines(passphrase: bool, failed_unlocks: u32) -> Vec<String> {
    let mut lines = vec![UNLOCKED_LINE.to_owned()];
    if failed_unlocks > 0 {
        lines.push(format!(
            "Someone typed a wrong Raven passphrase {failed_unlocks} time{} while Raven was \
             locked.",
            if failed_unlocks == 1 { "" } else { "s" }
        ));
    }
    if !passphrase {
        lines.push(raven_core::privacy::keys_open_to_login_text().to_owned());
    }
    lines
}

// ── The Raven passphrase ────────────────────────────────────────────────────

/// What `raven passphrase` (or the app's Settings) changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PassOp {
    Set,
    Change,
    Remove,
}

impl PassOp {
    /// The op this profile offers.
    pub(super) fn offered(self, offer: &Offer) -> bool {
        match self {
            PassOp::Set => *offer == Offer::Set,
            PassOp::Change => offer.has_passphrase(),
            PassOp::Remove => *offer == Offer::ChangeOrRemove,
        }
    }

    /// It needs the passphrase the profile has now.
    pub(super) fn needs_current(self) -> bool {
        self != PassOp::Set
    }

    /// It needs a new passphrase (typed twice).
    pub(super) fn needs_new(self) -> bool {
        self != PassOp::Remove
    }
}

/// The passphrases one op takes, wiped when dropped.
#[derive(Default)]
pub(super) struct Typed {
    pub(super) current: Option<SecretBytes>,
    pub(super) new: Option<SecretBytes>,
}

/// Where this profile's raven-node stands for a change of the passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NodeHold {
    /// None runs: nothing to hold.
    Absent,
    /// It runs unlocked and serves Lock v2: locked first, unlocked after.
    Unlocked,
    /// It runs locked: it stays so.
    Locked,
    /// It runs and does not serve Lock v2 (or did not answer): refused.
    Unheld,
}

/// This profile's raven-node, asked once.
pub(super) fn node_hold(data_dir: &Path) -> NodeHold {
    match ipc_client::ipc_request_timeout(data_dir, &IpcRequest::status(), Duration::from_secs(3)) {
        Ok(IpcResponse::Status {
            locked: Some(locked),
            ..
        }) if security_gate::live(SecGate::LocalProtection) => {
            if locked {
                NodeHold::Locked
            } else {
                NodeHold::Unlocked
            }
        }
        Err(e) if ipc_client::error_means_not_running(&e) => NodeHold::Absent,
        _ => NodeHold::Unheld,
    }
}

/// What a raven-node that does not serve Lock v2 needs first.
pub(super) const NODE_UNHELD: &str = "Raven is running and can't be locked while your keys \
     move. Stop it first (in the app: N, then X), then try again.";

/// 'Lock Raven when the computer sleeps' as it applies to this profile
/// (`node_policy.auto_lock_on_sleep`; unset: on for a profile with a Raven
/// passphrase that raven-node cannot read by itself, OD6b-18 and review
/// lock-updates-local-3, as raven-node decides it).
pub(super) fn sleep_lock(data_dir: &Path) -> bool {
    let passphrase = raven_core::keystore_select::has_passphrase(data_dir).unwrap_or(false)
        || raven_passphrase::unfinished(data_dir).unwrap_or(false);
    let unset = raven_core::node_policy::NodePolicy::auto_lock_on_sleep_default(
        passphrase,
        passphrase && node_reads_passphrase(data_dir),
    );
    raven_core::node_policy::try_load_policy(data_dir)
        .map(|policy| policy.auto_lock_on_sleep.unwrap_or(unset))
        .unwrap_or(unset)
}

/// raven-node reads this profile's passphrase by itself, as far as this
/// process can tell: its environment hands raven-node a passphrase file or
/// a systemd credential, or Raven's own login item for this profile names
/// one (node_control's `item_passphrase_file`). Reads only.
fn node_reads_passphrase(data_dir: &Path) -> bool {
    raven_core::keystore_vault::passphrase_file_configured()
        || super::node_control::LoginEnv::current()
            .ok()
            .and_then(|env| super::node_control::own_login_item(&env, data_dir))
            .and_then(|item| super::node_control::item_passphrase_file(&item))
            .is_some()
}

/// The passphrase file this computer keeps for this profile, if one is
/// there (cli.rs's lookup for `raven lock`: the one
/// `RAVEN_KEYSTORE_PASSPHRASE_FILE` names, the systemd credential, the one
/// Raven's own login item hands raven-node, PASSFILE's default). Reads
/// only.
fn saved_passphrase_file(data_dir: &Path) -> Option<PathBuf> {
    let login = super::node_control::LoginEnv::current().ok();
    super::profile_passphrase_file(data_dir, login.as_ref(), &|name| std::env::var_os(name))
}

/// Saves 'Lock Raven when the computer sleeps' (raven-node reads it at the
/// next wake).
pub(super) fn set_sleep_lock(data_dir: &Path, on: bool) -> Result<(), String> {
    raven_core::node_policy::update_policy(data_dir, |policy| {
        policy.auto_lock_on_sleep = Some(on);
    })
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// `raven passphrase` with no op: what this profile has and can do.
pub(super) fn status_lines(offer: &Offer) -> Vec<String> {
    match offer {
        Offer::Set => vec![
            "This profile has no Raven passphrase.".into(),
            raven_core::privacy::keys_open_to_login_text().into(),
            "Run `raven passphrase set` to set one.".into(),
        ],
        Offer::ChangeOrRemove => vec![
            "This profile has a Raven passphrase: Raven's keys on this computer open only \
             with it."
                .into(),
            "Run `raven passphrase change` or `raven passphrase remove`.".into(),
        ],
        Offer::Change => vec![
            "This profile has a Raven passphrase: Raven's keys on this computer open only \
             with it."
                .into(),
            "Run `raven passphrase change` to change it.".into(),
        ],
        Offer::No(why) => vec![(*why).into()],
    }
}

/// `raven passphrase [set|change|remove]`.
pub(super) fn cmd_passphrase(data_dir: &Path, op: Option<PassOp>) -> Result<(), String> {
    let offer = raven_passphrase::offer(data_dir);
    let unfinished = raven_passphrase::unfinished(data_dir).unwrap_or(false);
    let Some(op) = op else {
        for line in status_lines(&offer) {
            println!("{line}");
        }
        if unfinished && offer == Offer::ChangeOrRemove {
            println!("{UNFINISHED}");
        }
        return Ok(());
    };
    if !allowed(op, &offer, unfinished) {
        return Err(refusal(op, &offer));
    }
    if op == PassOp::Change {
        if let Some(file) = saved_passphrase_file(data_dir) {
            println!("{}", saved_file_line(&file, false));
        }
    }
    let typed = read_typed(op)?;
    let lines = run_op(data_dir, op, &typed)?;
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

/// `op` may run on a profile `offer` describes. A switch that stopped
/// halfway (`unfinished`, offered change or remove) is finished by `set`
/// too, with the passphrase it was started with (review
/// lock-updates-local-4).
pub(super) fn allowed(op: PassOp, offer: &Offer, unfinished: bool) -> bool {
    op.offered(offer) || (op == PassOp::Set && unfinished && *offer == Offer::ChangeOrRemove)
}

/// A switch of the keys to or from the vault stopped halfway
/// ([`raven_passphrase::unfinished`]).
pub(super) const UNFINISHED: &str = "Moving your Raven keys stopped halfway. Run `raven \
     passphrase set` with the passphrase you chose, or `raven passphrase remove`, to finish it.";

/// Why `op` is not offered here.
pub(super) fn refusal(op: PassOp, offer: &Offer) -> String {
    match offer {
        Offer::No(why) => (*why).into(),
        Offer::Set => raven_passphrase::NONE_SET.into(),
        Offer::ChangeOrRemove if op == PassOp::Set => raven_passphrase::ALREADY_SET.into(),
        _ => raven_passphrase::KEYRING_PROFILE.into(),
    }
}

/// The passphrases `op` needs, from the terminal: the current one, a new
/// one twice (they must match and follow the rules).
fn read_typed(op: PassOp) -> Result<Typed, String> {
    let mut typed = Typed::default();
    if op.needs_current() {
        typed.current = Some(read_hidden("Current Raven passphrase: ")?);
    }
    if op.needs_new() {
        let new = read_hidden("New Raven passphrase: ")?;
        raven_passphrase::check_new(&new).map_err(|e| e.to_string())?;
        let again = read_hidden("Type it again: ")?;
        if *again != *new {
            return Err(DIFFER.into());
        }
        typed.new = Some(new);
    }
    Ok(typed)
}

/// The two new passphrases differ.
pub(super) const DIFFER: &str = "The two passphrases differ. Nothing changed.";

/// `op` with raven-node held (production).
pub(super) fn run_op(data_dir: &Path, op: PassOp, typed: &Typed) -> Result<Vec<String>, String> {
    let mut check = || check_typed(data_dir, op, typed);
    let mut send = |req: &IpcRequest| ipc_client::ipc_request_timeout(data_dir, req, LOCK_V2_WAIT);
    let mut apply = || apply_op(data_dir, op, typed);
    // A change leaves a saved copy of the passphrase stale (review
    // lock-updates-local-2).
    let saved = (op == PassOp::Change)
        .then(|| saved_passphrase_file(data_dir))
        .flatten();
    run_op_with(
        op,
        typed,
        node_hold(data_dir),
        &mut check,
        &mut send,
        &mut apply,
        saved.as_deref(),
    )
}

/// Before raven-node is held for `op` (review lock-updates-local-1): the
/// passphrase that must open the vault does. The current one for a change
/// or a remove; for a set that finishes a switch that stopped halfway, the
/// one it was started with. A set from the keychain opens nothing yet.
fn check_typed(data_dir: &Path, op: PassOp, typed: &Typed) -> Result<(), PassError> {
    let opens = match op {
        PassOp::Change | PassOp::Remove => typed.current.as_deref(),
        PassOp::Set if raven_passphrase::unfinished(data_dir).unwrap_or(false) => {
            typed.new.as_deref()
        }
        PassOp::Set => None,
    };
    match opens {
        Some(passphrase) => raven_passphrase::check_opens(data_dir, passphrase),
        None => Ok(()),
    }
}

/// The change itself ([`raven_passphrase`]).
fn apply_op(data_dir: &Path, op: PassOp, typed: &Typed) -> Result<Moved, PassError> {
    let missing = || PassError::Refused("a passphrase is missing".into());
    match op {
        PassOp::Set => raven_passphrase::set(data_dir, typed.new.as_deref().ok_or_else(missing)?),
        PassOp::Change => raven_passphrase::change(
            data_dir,
            typed.current.as_deref().ok_or_else(missing)?,
            typed.new.as_deref().ok_or_else(missing)?,
        )
        .map(|()| Moved::default()),
        PassOp::Remove => {
            raven_passphrase::remove(data_dir, typed.current.as_deref().ok_or_else(missing)?)
        }
    }
}

/// [`run_op`] with the node's state, the check of the typed passphrase, its
/// IPC, the change and the saved passphrase file (`saved`) passed in. A
/// node that runs unlocked is locked first (it then holds no key and writes
/// none), once `check` says the typed passphrase opens the vault (a wrong
/// one changes nothing and leaves it running: review
/// lock-updates-local-1), and unlocked after with what opens the profile
/// then: the new passphrase, the one it had (the change failed, or it was
/// removed: none). A passphrase that turned out wrong is never sent: the
/// node would count it as a wrong unlock, so it stays locked. One that runs
/// locked stays so; one that cannot be held is refused.
pub(super) fn run_op_with(
    op: PassOp,
    typed: &Typed,
    node: NodeHold,
    check: &mut dyn FnMut() -> Result<(), PassError>,
    send: &mut dyn FnMut(&IpcRequest) -> Result<IpcResponse, String>,
    apply: &mut dyn FnMut() -> Result<Moved, PassError>,
    saved: Option<&Path>,
) -> Result<Vec<String>, String> {
    let held = match node {
        NodeHold::Unheld => return Err(NODE_UNHELD.into()),
        NodeHold::Absent | NodeHold::Locked => false,
        NodeHold::Unlocked => {
            check().map_err(|e| e.to_string())?;
            match send(&IpcRequest::Lock { v: IPC_VERSION }) {
                Ok(IpcResponse::LockState { locked: true, .. }) => {}
                Ok(IpcResponse::Error { message, .. }) => {
                    return Err(sanitize_terminal_line(&message))
                }
                Ok(_) => return Err("raven-node gave an unexpected answer to the lock".into()),
                Err(e) => {
                    return Err(format!(
                        "raven-node did not lock: {}",
                        sanitize_terminal_line(&e)
                    ))
                }
            }
            true
        }
    };
    let done = apply();
    // What opens the profile now; `None`: nothing the user typed does.
    let opens = match (&done, op) {
        (Ok(_), PassOp::Set | PassOp::Change) => Some(typed.new.as_deref()),
        (Ok(_), PassOp::Remove) | (Err(_), PassOp::Set) => Some(None),
        (Err(PassError::Wrong), PassOp::Change | PassOp::Remove) => None,
        (Err(_), PassOp::Change | PassOp::Remove) => Some(typed.current.as_deref()),
    };
    let mut lines = match &done {
        Ok(moved) => done_lines(op, moved, saved),
        Err(_) => Vec::new(),
    };
    if held {
        match opens.map(|opens| send(&unlock_request(opens.map(|p| &p[..])))) {
            Some(Ok(IpcResponse::LockState { locked: false, .. })) => {}
            _ => lines.push(STAYS_LOCKED.into()),
        }
    } else if node == NodeHold::Locked {
        lines.push(STAYS_LOCKED.into());
    }
    match done {
        Ok(_) => Ok(lines),
        Err(e) => {
            let mut text = e.to_string();
            for line in lines {
                text.push('\n');
                text.push_str(&line);
            }
            Err(text)
        }
    }
}

/// raven-node stays locked after the change.
pub(super) const STAYS_LOCKED: &str = "Raven stays locked: run `raven unlock` to open it.";

/// The paragraph about a passphrase file this computer keeps (review
/// lock-updates-local-2): before a change (`done` false), and after it.
pub(super) fn saved_file_line(file: &Path, done: bool) -> String {
    let file = sanitize_terminal_line(&file.display().to_string());
    if done {
        format!(
            "Your old passphrase is still saved in a file on this computer ({file}), and Raven \
             reads it when it starts: put the new passphrase in that file now, or Raven will not \
             start next time."
        )
    } else {
        format!(
            "Your passphrase is saved in a file on this computer ({file}), and Raven reads it \
             when it starts: after this change, put the new passphrase in that file."
        )
    }
}

/// What a change that went through says; `saved`: the passphrase file this
/// computer keeps, now stale after a change.
pub(super) fn done_lines(op: PassOp, moved: &Moved, saved: Option<&Path>) -> Vec<String> {
    let mut lines = match op {
        PassOp::Set => vec![
            "Your Raven passphrase is set. Raven's keys on this computer open only with it."
                .to_owned(),
            "Raven can't open them without it: there is no way to recover a forgotten one."
                .to_owned(),
        ],
        PassOp::Change => {
            let mut lines = vec!["Your Raven passphrase is changed.".to_owned()];
            lines.extend(saved.map(|file| saved_file_line(file, true)));
            lines
        }
        PassOp::Remove => vec![
            "Your Raven passphrase is removed. Your Raven keys are in your login keychain again."
                .to_owned(),
            raven_core::privacy::keys_open_to_login_text().to_owned(),
        ],
    };
    if !moved.left.is_empty() {
        lines.push(format!(
            "These could not be removed from where they were: {}.",
            moved.left.join("; ")
        ));
    }
    lines
}

#[cfg(test)]
mod tests;
