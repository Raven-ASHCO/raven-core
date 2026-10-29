//! Raven updates in the terminal app (Phase 6 P6.47, gate `RELEASE_BUNDLE`;
//! design D §5 and UX, OD6b-24, OD6b-25).
//!
//! - UPDATES (U on Home and on NET): what `raven update status` says, and
//!   when a checked release waits, what installing it shows (version,
//!   size, who signed it, its place in the public release log, the notes)
//!   with a field for the word: Enter installs once it is `install`. A
//!   download from a friend is a separate approval (P6.49); this is the
//!   install's. Where Raven can't replace its own programs, the manual
//!   steps instead, and no field.
//! - The install runs on the node worker (tui/node.rs): this profile's
//!   raven-node stops around the swap and starts again, and must answer
//!   within 20 s, else the old programs go back. UPDATES says how it ended;
//!   the app itself keeps running the version it started with.
//! - A release a friend offered (P6.49): its prompt, Y downloads it (raven-
//!   node fetches it and checks every part), N closes. Installing it is
//!   the install above, once it is complete.
//! - NET's row "Raven updates: 1.5.0 ready to install".
//!
//! Nothing here shows while the gate is shut: U does nothing and NET has
//! no row.

use crossterm::event::{KeyCode, KeyEvent};

use super::bridge::{self, UpdateView};
use super::{
    has_ctrl_or_alt, is_ctrl, plain_char, typed_word_is, App, Cmd, NodeJob, Overlay, Probe,
    LINE_FIELD_MAX,
};

/// UPDATES: the word as typed, and the install once it runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in super::super) struct UpdState {
    pub(in super::super) typed: String,
    pub(in super::super) step: UpdStep,
}

/// Where UPDATES is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in super::super) enum UpdStep {
    /// The view (`App::updates`) and, when a release waits, the field.
    #[default]
    Showing,
    /// The install of this build runs: only its answer ends this.
    Installing { version: String },
    /// How it ended: installed (`Ok`), or why not (the old programs back,
    /// or nothing changed).
    Ended(Result<Vec<String>, String>),
}

impl App {
    /// U: UPDATES over what is open, and a fresh read of what waits. Only
    /// while the gate is live.
    pub(super) fn open_updates(&mut self) {
        if !bridge::updates_offered() {
            return;
        }
        self.open_overlay(Overlay::Updates(UpdState::default()));
        self.load_updates();
    }

    /// Read what waits (NET's row, and with UPDATES open what installing it
    /// shows); nothing while the gate is shut.
    pub(super) fn load_updates(&mut self) {
        if bridge::updates_offered() {
            let full = self.updates_open();
            self.job(Cmd::Node(NodeJob::LoadUpdates { full }));
        }
    }

    fn updates_open(&self) -> bool {
        self.overlays
            .iter()
            .any(|overlay| matches!(overlay, Overlay::Updates(_)))
    }

    /// The read answered: it replaces the last one whole (a short read,
    /// NET's, keeps what UPDATES showed while it is open).
    pub(super) fn updates_read(&mut self, mut view: UpdateView) {
        if !view.full && self.updates_open() {
            if let Some(shown) = &self.updates {
                view.ready = shown.ready.clone();
                view.manual = shown.manual.clone();
            }
        }
        if self.updates.as_ref() != Some(&view) {
            self.updates = Some(view);
            self.dirty = true;
        }
    }

    /// What was read last; None before the first read.
    pub(in super::super) fn updates(&self) -> Option<&UpdateView> {
        self.updates.as_ref()
    }

    fn updates_mut(&mut self) -> Option<&mut UpdState> {
        match self.overlays.last_mut() {
            Some(Overlay::Updates(upd)) => Some(upd),
            _ => None,
        }
    }

    /// UPDATES' keys: Esc closes (not while it installs); letters type the
    /// word, Backspace takes one back; Enter (not right after a paste)
    /// installs the release shown once the word is right. Without a release
    /// to install, Y downloads a friend's offer and N closes. Ctrl+C opens
    /// QUIT.
    pub(super) fn on_updates_key(&mut self, key: KeyEvent, upd: &UpdState) {
        if is_ctrl(key, 'c') {
            self.open_overlay(Overlay::Quit);
            return;
        }
        if matches!(upd.step, UpdStep::Installing { .. }) {
            return;
        }
        let ready = self
            .updates
            .as_ref()
            .and_then(|view| view.ready.clone())
            .filter(|_| upd.step == UpdStep::Showing);
        match (key.code, plain_char(key)) {
            (KeyCode::Esc, _) => self.close_overlay(),
            (KeyCode::Backspace, _) if !has_ctrl_or_alt(key) => {
                if let Some(upd) = self.updates_mut() {
                    upd.typed.pop();
                }
                self.dirty = true;
            }
            (_, Some(c)) if ready.is_some() => {
                if let Some(upd) = self.updates_mut() {
                    if upd.typed.chars().count() < LINE_FIELD_MAX && !c.is_control() {
                        upd.typed.push(c);
                    }
                }
                self.dirty = true;
            }
            (_, Some('y' | 'Y')) if upd.step == UpdStep::Showing => {
                let offer = self.updates.as_ref().and_then(|view| view.offer.clone());
                if let Some(offer) = offer {
                    self.job(Cmd::Node(NodeJob::ApproveDownload {
                        digest: offer.digest,
                    }));
                }
            }
            (_, Some('u' | 'U' | 'n' | 'N')) => self.close_overlay(),
            _ => {
                let Some(ready) = ready else {
                    return;
                };
                if !self.confirms(key) || !typed_word_is(&upd.typed, ready.word) {
                    return;
                }
                if let Some(upd) = self.updates_mut() {
                    upd.step = UpdStep::Installing {
                        version: ready.version.clone(),
                    };
                    upd.typed.clear();
                }
                self.dirty = true;
                self.job(Cmd::Node(NodeJob::InstallUpdate {
                    serial: ready.serial,
                    started_by_app: self.node.started_by_app,
                }));
            }
        }
    }

    /// The install answered: UPDATES says how it ended, the node is shown
    /// as it is now (the one the install started from this app, `started`,
    /// is this app's own: QUIT's 'stop it if this app started it' and the
    /// stop rules follow it, review lock-updates-local-7), and what waits is
    /// read again.
    pub(super) fn update_installed(
        &mut self,
        result: Result<Vec<String>, String>,
        after: Probe,
        started: Option<u32>,
    ) {
        let open = self.overlays.iter_mut().find_map(|overlay| match overlay {
            Overlay::Updates(upd) => Some(upd),
            _ => None,
        });
        match open {
            Some(upd) => upd.step = UpdStep::Ended(result),
            None => self.push_toast(&match &result {
                Ok(lines) => lines.first().cloned().unwrap_or_default(),
                Err(why) => why.clone(),
            }),
        }
        self.apply_probe(&after);
        if started.is_some() && after.pid == started {
            self.node.started_by_app = started;
        }
        self.dirty = true;
        self.load_updates();
    }

    /// The install's job failed (it panicked): UPDATES says so.
    pub(super) fn update_install_failed(&mut self, why: String) {
        if let Some(upd) = self.overlays.iter_mut().find_map(|overlay| match overlay {
            Overlay::Updates(upd) => Some(upd),
            _ => None,
        }) {
            upd.step = UpdStep::Ended(Err(why));
        }
        self.dirty = true;
        self.load_updates();
    }

    /// A paste while UPDATES' field is on top: the word must be typed.
    pub(super) fn clear_update_word(&mut self) -> bool {
        match self.updates_mut() {
            Some(upd) if !upd.typed.is_empty() => {
                upd.typed.clear();
                self.dirty = true;
                true
            }
            _ => false,
        }
    }
}
