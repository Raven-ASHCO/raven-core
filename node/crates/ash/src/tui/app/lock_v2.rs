//! Lock now v2 in the terminal app (Phase 6 P6.40, gate `LOCAL_PROTECTION`;
//! design C §6, OD6b-18).
//!
//! - LOCKED covers everything while this profile's raven-node runs locked
//!   (its Status says `locked`): the Raven passphrase is typed there, or on
//!   a keychain profile Enter resumes, and the screen says plainly what such
//!   a lock does not protect.
//! - LOCK's Enter locks a node that serves Lock v2 (it keeps running and
//!   holds no key) instead of stopping it (Lock now v1, which stays as it
//!   was for every other node).
//! - The app locks Raven after it was idle (no key, no paste) for the
//!   minutes SET's 'Lock Raven when this app is idle' says (off by default).
//! - SET's 'Lock Raven when the computer sleeps' (raven-node's
//!   `auto_lock_on_sleep`) and 'Raven passphrase' with PASS, which sets,
//!   changes or removes it with the node held locked meanwhile.
//!
//! Nothing here shows while the gate is shut: a node's Status then has no
//! `locked`, and SET reads no lock settings. A passphrase is typed into a
//! [`Masked`] field: never drawn (one mark per character), never in
//! `Debug`, wiped when it drops; it leaves the app only in IPC `Unlock`'s
//! field or the change itself.

use std::fmt;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};
use zeroize::Zeroizing;

use super::bridge::{self, PassOffer, PassOp, Typed, UnlockAnswer};
use super::{
    has_ctrl_or_alt, is_ctrl, plain_char, App, Cmd, JobName, NodeJob, Overlay, Screen, SetRow,
};

/// 'Lock Raven when this app is idle': off, or these minutes.
pub(in super::super) const IDLE_LOCK_STEPS: [u16; 5] = [0, 5, 15, 30, 60];
/// The longest passphrase a field takes, in bytes (raven-core's limit).
const MAX_TYPED: usize = 1024;

/// A passphrase being typed: never drawn, never in `Debug`, wiped when it
/// drops.
#[derive(Clone, Default, PartialEq, Eq)]
pub(in super::super) struct Masked(Zeroizing<String>);

impl Masked {
    /// Characters typed (each drawn as one mark).
    pub(in super::super) fn chars(&self) -> usize {
        self.0.chars().count()
    }

    pub(in super::super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn push(&mut self, c: char) {
        if self.0.len() + c.len_utf8() <= MAX_TYPED && !c.is_control() {
            self.0.push(c);
        }
    }

    fn pop(&mut self) {
        self.0.pop();
    }

    fn clear(&mut self) {
        // Zeroizing wipes what it held as it is replaced.
        self.0 = Zeroizing::new(String::new());
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Its bytes, for a job (wiped when dropped).
    pub(in super::super) fn secret(&self) -> raven_core::ipc::SecretBytes {
        raven_core::ipc::SecretBytes::new(self.0.as_bytes().to_vec())
    }
}

impl fmt::Debug for Masked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Masked(..)")
    }
}

/// LOCKED: this profile's raven-node runs locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct LockedView {
    /// The profile has a Raven passphrase: it is typed here. Without one
    /// Enter resumes.
    pub(in super::super) passphrase: bool,
    pub(in super::super) typed: Masked,
    /// What the last try said (its words).
    pub(in super::super) note: Option<String>,
    /// An unlock is out.
    pub(in super::super) unlocking: bool,
}

/// PASS's steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) enum PassStep {
    /// C (change) or R (remove).
    Choose,
    /// The passphrase it has now.
    Current,
    /// A new one.
    New,
    /// The new one again.
    Again,
    /// The change runs.
    Changing,
}

/// PASS: SET's 'Raven passphrase'.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct PassState {
    /// What it changes; None while choosing.
    pub(in super::super) op: Option<PassOp>,
    pub(in super::super) step: PassStep,
    pub(in super::super) current: Masked,
    pub(in super::super) new: Masked,
    pub(in super::super) again: Masked,
    /// Why the last step went back (its words).
    pub(in super::super) note: Option<String>,
}

impl PassState {
    fn of(offer: &PassOffer) -> Option<PassState> {
        let (op, step) = match offer {
            PassOffer::Set => (Some(PassOp::Set), PassStep::New),
            PassOffer::Change => (Some(PassOp::Change), PassStep::Current),
            PassOffer::ChangeOrRemove => (None, PassStep::Choose),
            PassOffer::No(_) => return None,
        };
        Some(PassState {
            op,
            step,
            current: Masked::default(),
            new: Masked::default(),
            again: Masked::default(),
            note: None,
        })
    }

    /// The field typed into now.
    fn field(&mut self) -> Option<&mut Masked> {
        match self.step {
            PassStep::Current => Some(&mut self.current),
            PassStep::New => Some(&mut self.new),
            PassStep::Again => Some(&mut self.again),
            PassStep::Choose | PassStep::Changing => None,
        }
    }

    /// The first step that types (after a failed change: from the start).
    fn restart(&mut self, note: String) {
        self.current.clear();
        self.new.clear();
        self.again.clear();
        self.step = match self.op {
            Some(PassOp::Set) => PassStep::New,
            _ => PassStep::Current,
        };
        self.note = Some(note);
    }
}

/// The lock settings as read (SET's rows show once they are).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct LockSettingsView {
    pub(in super::super) offer: PassOffer,
    /// 'Lock Raven when the computer sleeps' as it applies.
    pub(in super::super) sleep_lock: bool,
}

/// Why the app asked for a lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) enum LockWhy {
    /// LOCK's Enter: a node without Lock v2 is stopped instead (v1).
    User,
    /// The idle lock: a node without Lock v2 is left alone.
    Idle,
}

/// Lock v2's part of the App.
#[derive(Debug, Clone, Default)]
pub(in super::super) struct LockV2State {
    /// The lock settings, once read.
    pub(in super::super) settings: Option<LockSettingsView>,
    /// A lock is out, and why.
    locking: Option<LockWhy>,
    /// The last key or paste (the idle lock counts from it).
    last_input: Option<Instant>,
}

/// LOCKED's toast after an unlock, when the node said nothing more.
const UNLOCKED_TOAST: &str = "Raven is unlocked. Friends can reach you again.";
/// A lock the node did not take.
const NOT_LOCKED_TOAST: &str = "Raven couldn't lock. Try again, or run `raven lock`.";
/// 'Lock Raven when the computer sleeps' was not saved.
const SLEEP_LOCK_NOT_SAVED: &str = "Raven couldn't save that setting. Try again.";

impl App {
    /// Lock v2 is offered now: its gate is live here and this profile's node
    /// runs unlocked and serves it.
    pub(in super::super) fn lock_v2_offered(&self) -> bool {
        bridge::lock_v2_live() && self.node.locked == Some(false)
    }

    /// The lock settings (SET's rows show once they are read).
    pub(in super::super) fn lock_settings(&self) -> Option<&LockSettingsView> {
        self.lock_v2.settings.as_ref()
    }

    /// A key or a paste came: the idle lock counts from now.
    pub(super) fn lock_v2_input(&mut self) {
        self.lock_v2.last_input = Some(self.now);
    }

    /// Reads the lock settings, while the gate is live.
    pub(super) fn load_lock_settings(&mut self) {
        if bridge::lock_v2_live() {
            self.job(Cmd::Node(NodeJob::LockSettings));
        }
    }

    pub(super) fn lock_settings_read(&mut self, view: LockSettingsView) {
        let passphrase = view.offer.has_passphrase();
        self.lock_v2.settings = Some(view);
        if let Some(Overlay::Locked(locked)) = self.locked_overlay_mut() {
            locked.passphrase = passphrase;
        }
        self.dirty = true;
    }

    fn locked_overlay_mut(&mut self) -> Option<&mut Overlay> {
        self.overlays
            .iter_mut()
            .find(|overlay| matches!(overlay, Overlay::Locked(_)))
    }

    /// The node's lock as its Status says it now (`before`: as it said it
    /// before): LOCKED opens over everything while it runs locked, and
    /// closes once it does not (an unlock elsewhere, or no node).
    pub(super) fn lock_v2_follow(&mut self, before: Option<bool>) {
        let open = self
            .overlays
            .iter()
            .any(|overlay| matches!(overlay, Overlay::Locked(_)));
        // PASS's change holds the node locked while it runs: no LOCKED.
        let changing = self.overlays.iter().any(|overlay| {
            matches!(overlay, Overlay::Passphrase(pass) if pass.step == PassStep::Changing)
        });
        match self.node.locked {
            Some(true) if !open && !changing => {
                let passphrase = self
                    .lock_v2
                    .settings
                    .as_ref()
                    .is_none_or(|read| read.offer.has_passphrase());
                // Nothing of the profile shows over it; QUIT may still open
                // over it.
                self.overlays.retain(|overlay| *overlay == Overlay::Quit);
                self.overlays.insert(
                    0,
                    Overlay::Locked(LockedView {
                        passphrase,
                        typed: Masked::default(),
                        note: None,
                        unlocking: false,
                    }),
                );
                self.dirty = true;
                if self.lock_v2.settings.is_none() {
                    self.load_lock_settings();
                }
            }
            Some(true) => {}
            _ if open => {
                self.overlays
                    .retain(|overlay| !matches!(overlay, Overlay::Locked(_)));
                self.dirty = true;
            }
            _ => {}
        }
        if before != self.node.locked {
            self.dirty = true;
        }
    }

    /// LOCKED: printable keys type the passphrase (one mark each),
    /// Backspace takes one back, Esc clears it, Enter unlocks; Ctrl+C opens
    /// QUIT over it. Nothing else.
    pub(super) fn on_locked_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let Some(Overlay::Locked(view)) = self.overlays.last_mut() else {
            return;
        };
        match key.code {
            KeyCode::Enter if !view.unlocking => {
                if view.passphrase && view.typed.is_empty() {
                    return;
                }
                view.unlocking = true;
                view.note = None;
                let typed = view.passphrase.then(|| view.typed.clone());
                view.typed.clear();
                self.job(Cmd::Node(NodeJob::UnlockV2(typed)));
            }
            KeyCode::Esc => view.typed.clear(),
            KeyCode::Backspace => view.typed.pop(),
            KeyCode::Char(c) if view.passphrase && !has_ctrl_or_alt(key) => view.typed.push(c),
            _ => return,
        }
        self.dirty = true;
    }

    /// LOCKED's Enter answered.
    pub(super) fn unlocked_v2(&mut self, answer: UnlockAnswer) {
        let Some(Overlay::Locked(view)) = self.locked_overlay_mut() else {
            return;
        };
        view.unlocking = false;
        match answer {
            UnlockAnswer::Opened(lines) => {
                self.overlays
                    .retain(|overlay| !matches!(overlay, Overlay::Locked(_)));
                self.node.locked = Some(false);
                let text = lines.join(" ");
                self.push_toast(if text.is_empty() {
                    UNLOCKED_TOAST
                } else {
                    &text
                });
                self.lock_v2.last_input = Some(self.now);
                self.job(Cmd::Node(NodeJob::Probe));
            }
            UnlockAnswer::NeedsPassphrase(note) => {
                view.passphrase = true;
                view.note = Some(note);
            }
            UnlockAnswer::Wrong(note) | UnlockAnswer::Wait(note) | UnlockAnswer::Failed(note) => {
                view.note = Some(note)
            }
        }
        self.dirty = true;
    }

    /// Asks raven-node to lock (unless a lock is out).
    pub(super) fn lock_v2_now(&mut self, why: LockWhy) {
        if self.lock_v2.locking.is_none() {
            self.lock_v2.locking = Some(why);
            self.job(Cmd::Node(NodeJob::LockV2));
        }
    }

    /// The lock answered: LOCKED opens at once (the next Status agrees). A
    /// node without Lock v2 is stopped instead when the user asked (v1);
    /// the idle lock leaves it alone.
    pub(super) fn locked_v2(&mut self, result: Result<bool, String>) {
        let why = self.lock_v2.locking.take();
        match result {
            Ok(true) => {
                let before = self.node.locked;
                self.node.locked = Some(true);
                self.lock_v2_follow(before);
                self.job(Cmd::Node(NodeJob::Probe));
            }
            Ok(false) if why == Some(LockWhy::User) => {
                self.open_lock();
                self.lock_now();
            }
            Ok(false) => {}
            Err(_) => self.push_toast(NOT_LOCKED_TOAST),
        }
    }

    /// A lock or unlock job ended without an answer (it failed).
    pub(super) fn lock_v2_job_failed(&mut self, job: JobName) {
        match job {
            JobName::NodeLockV2 => self.lock_v2.locking = None,
            JobName::NodeUnlockV2 => {
                if let Some(Overlay::Locked(view)) = self.locked_overlay_mut() {
                    view.unlocking = false;
                }
            }
            JobName::NodePassphrase => {
                if let Some(Overlay::Passphrase(pass)) = self.overlays.last_mut() {
                    pass.restart(NOT_LOCKED_TOAST.into());
                }
            }
            _ => {}
        }
        self.dirty = true;
    }

    /// Every update: the idle lock, once the app has had no key and no
    /// paste for the minutes SET says, while the node runs unlocked with
    /// Lock v2.
    pub(super) fn lock_v2_upkeep(&mut self) {
        let minutes = self.settings.idle_lock_minutes;
        if minutes == 0 || !self.lock_v2_offered() || self.lock_v2.locking.is_some() {
            return;
        }
        let last = *self.lock_v2.last_input.get_or_insert(self.now);
        let idle = self.now.saturating_duration_since(last);
        if idle >= Duration::from_secs(u64::from(minutes) * 60) {
            self.lock_v2.last_input = Some(self.now);
            self.lock_v2_now(LockWhy::Idle);
        }
    }

    /// SET's rows of Lock v2, shown once the lock settings were read.
    pub(super) fn lock_v2_row_shown(&self, row: SetRow) -> bool {
        !matches!(
            row,
            SetRow::SleepLock | SetRow::IdleLock | SetRow::Passphrase
        ) || self.lock_v2.settings.is_some()
    }

    /// Enter, Right or Left on one of Lock v2's rows: the sleep lock turns
    /// on or off (raven-node's policy), the idle lock steps through its
    /// minutes (this app's settings), the passphrase row opens PASS.
    pub(super) fn change_lock_setting(&mut self, row: SetRow, forward: bool) {
        let Some(read) = self.lock_v2.settings.clone() else {
            return;
        };
        match row {
            SetRow::SleepLock => self.job(Cmd::Node(NodeJob::SetSleepLock(!read.sleep_lock))),
            SetRow::IdleLock => {
                self.settings.idle_lock_minutes = super::state_file::step(
                    &IDLE_LOCK_STEPS,
                    self.settings.idle_lock_minutes,
                    forward,
                );
                self.lock_v2.last_input = Some(self.now);
                self.save_settings();
            }
            SetRow::Passphrase => {
                if let Some(pass) = PassState::of(&read.offer) {
                    self.open_overlay(Overlay::Passphrase(pass));
                }
            }
            _ => return,
        }
        self.dirty = true;
    }

    /// The sleep lock's save answered: the settings are read again.
    pub(super) fn sleep_lock_saved(&mut self, result: Result<(), String>) {
        if result.is_err() {
            self.push_toast(SLEEP_LOCK_NOT_SAVED);
        }
        self.load_lock_settings();
    }

    /// PASS: C or R chooses; printable keys type into the step's field,
    /// Backspace takes one back; Enter goes on (a new passphrase is checked,
    /// then typed again; the last step changes it); Esc closes, except
    /// while the change runs. Ctrl+C opens QUIT over it.
    pub(super) fn on_passphrase_key(&mut self, key: KeyEvent) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        let Some(Overlay::Passphrase(pass)) = self.overlays.last_mut() else {
            return;
        };
        if pass.step == PassStep::Changing {
            return;
        }
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => {
                self.close_overlay();
                return;
            }
            (_, Some('c' | 'C')) if pass.step == PassStep::Choose => {
                pass.op = Some(PassOp::Change);
                pass.step = PassStep::Current;
            }
            (_, Some('r' | 'R')) if pass.step == PassStep::Choose => {
                pass.op = Some(PassOp::Remove);
                pass.step = PassStep::Current;
            }
            (KeyCode::Enter, _) => {
                let submit = next_step(pass);
                if submit {
                    let (Some(op), current, new) = (pass.op, &pass.current, &pass.new) else {
                        return;
                    };
                    let current = op.needs_current().then(|| current.clone());
                    let new = op.needs_new().then(|| new.clone());
                    pass.step = PassStep::Changing;
                    pass.note = None;
                    self.job(Cmd::Node(NodeJob::Passphrase { op, current, new }));
                }
            }
            (KeyCode::Backspace, _) => {
                if let Some(field) = pass.field() {
                    field.pop();
                }
            }
            (KeyCode::Char(c), _) if !has_ctrl_or_alt(key) => {
                if let Some(field) = pass.field() {
                    field.push(c);
                }
            }
            _ => return,
        }
        self.dirty = true;
    }

    /// A paste into LOCKED's or PASS's field (one line; a line break ends
    /// it): `true` when one took it.
    pub(super) fn lock_v2_paste(&mut self, text: &str) -> bool {
        let line = text.lines().next().unwrap_or("");
        let field = match self.overlays.last_mut() {
            Some(Overlay::Locked(view)) if view.passphrase && !view.unlocking => {
                Some(&mut view.typed)
            }
            Some(Overlay::Passphrase(pass)) => pass.field(),
            Some(Overlay::Locked(_)) => None,
            _ => return false,
        };
        if let Some(field) = field {
            line.chars().for_each(|c| field.push(c));
            self.dirty = true;
        }
        true
    }

    /// PASS's change answered: done (its first line as a toast, and the
    /// settings read again), or why not (from its first step again).
    pub(super) fn passphrase_changed(&mut self, result: Result<Vec<String>, String>) {
        match result {
            Ok(lines) => {
                if matches!(self.overlays.last(), Some(Overlay::Passphrase(_))) {
                    self.close_overlay();
                }
                if let Some(first) = lines.first() {
                    self.push_toast(first);
                }
                self.load_lock_settings();
                self.job(Cmd::Node(NodeJob::Probe));
            }
            Err(why) => {
                if let Some(Overlay::Passphrase(pass)) = self.overlays.last_mut() {
                    pass.restart(why.lines().next().unwrap_or_default().to_owned());
                }
            }
        }
        self.dirty = true;
    }

    /// SET opened: the lock settings are read again.
    pub(super) fn lock_v2_settings_opened(&mut self) {
        if matches!(self.screen, Screen::Settings(_)) {
            self.load_lock_settings();
        }
    }
}

/// Enter on PASS's typing step: the next step, or `true` when the change
/// goes now. A new passphrase must follow the rules and be typed the same
/// twice; an empty field goes nowhere.
fn next_step(pass: &mut PassState) -> bool {
    match pass.step {
        PassStep::Current if pass.current.is_empty() => false,
        PassStep::Current if pass.op == Some(PassOp::Remove) => true,
        PassStep::Current => {
            pass.step = PassStep::New;
            pass.note = None;
            false
        }
        PassStep::New => {
            match bridge::check_new_passphrase(pass.new.bytes()) {
                Ok(()) => {
                    pass.step = PassStep::Again;
                    pass.note = None;
                }
                Err(why) => {
                    pass.new.clear();
                    pass.note = Some(why);
                }
            }
            false
        }
        PassStep::Again if pass.again != pass.new => {
            pass.new.clear();
            pass.again.clear();
            pass.step = PassStep::New;
            pass.note = Some(bridge::PASSPHRASES_DIFFER.to_owned());
            false
        }
        PassStep::Again => true,
        PassStep::Choose | PassStep::Changing => false,
    }
}

/// What a passphrase job hands the worker: the op and its passphrases.
pub(in super::super) fn typed_of(current: Option<&Masked>, new: Option<&Masked>) -> Typed {
    Typed {
        current: current.map(Masked::secret),
        new: new.map(Masked::secret),
    }
}
