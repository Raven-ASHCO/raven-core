//! UPDATES (Phase 6 P6.47; design D UX): what `raven update status` says,
//! and when a checked release waits, what installing it shows and the field
//! for its word (Enter installs once it is `install`); where Raven can't
//! replace its own programs, the manual steps. While it installs, that it
//! does; then how it ended. Esc closes (not while it installs).
//!
//! Every text comes from update_install.rs through bridge.rs (the CLI's
//! words) and is shaped by display.rs before it is drawn: release notes are
//! untrusted.

use ratatui::layout::{Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::app::{App, UpdState, UpdStep};
#[cfg(test)]
use super::app::{Cmd, JobResult, Msg, NodeJob, Overlay, PasteVia};
#[cfg(test)]
use super::bridge::{OfferView, UpdateReady, UpdateView};
#[cfg(test)]
use super::node::Probe;
#[cfg(test)]
use super::testkit;
use super::{display, overlays, widgets, wrap};

const TITLE: &str = " Raven updates ";
/// UPDATES' largest size, in cells; smaller in a smaller terminal.
const WIDTH: u16 = 76;
const HEIGHT: u16 = 24;

/// Before the first read answered.
const READING: &str = "Reading what waits to be installed";
/// While the install runs.
const INSTALLING: &str = "Raven's background program stops, its programs are replaced, and \
                          it starts again. This takes a few seconds.";

/// Draws UPDATES over the screen, its keys on the bottom border and the
/// cursor in the field while there is one.
pub(super) fn render(f: &mut Frame, area: Rect, app: &App, upd: &UpdState) {
    let look = app.look();
    let rect = overlays::centered(area, WIDTH, HEIGHT);
    let mut bar = widgets::key_bar(look, &keys(app, upd), rect.width.saturating_sub(4));
    bar.spans.insert(0, Span::raw(" "));
    bar.spans.push(Span::raw(" "));
    let block = overlays::overlay_block(look)
        .title(Span::styled(TITLE, look.theme.title))
        .title_bottom(bar);
    let inner = block.inner(rect);
    let (rows, field) = lines(app, upd, inner.width);
    // The field stays in view: the rows above it go first.
    let height = usize::from(inner.height);
    let top = field.map_or(0, |row| (row + 1).saturating_sub(height));
    widgets::clear(f, rect, look);
    f.render_widget(
        Paragraph::new(rows.clone())
            .block(block)
            .scroll((u16::try_from(top).unwrap_or(u16::MAX), 0)),
        rect,
    );
    if let Some(row) = field {
        let Some(y) = u16::try_from(row - top).ok().filter(|y| *y < inner.height) else {
            return;
        };
        let x = u16::try_from(rows[row].width()).unwrap_or(u16::MAX);
        let x = inner.x.saturating_add(x.min(inner.width.saturating_sub(1)));
        f.set_cursor_position(Position::new(x, inner.y + y));
    }
}

/// UPDATES' keys now.
fn keys(app: &App, upd: &UpdState) -> Vec<(&'static str, &'static str)> {
    match upd.step {
        UpdStep::Installing { .. } => Vec::new(),
        UpdStep::Ended(_) => vec![("Esc", "Close")],
        UpdStep::Showing => {
            let mut keys = vec![("Esc", "Close")];
            if app.updates().is_some_and(|view| view.ready.is_some()) {
                keys.push(("Enter", "Install"));
            } else if app.updates().is_some_and(|view| view.offer.is_some()) {
                keys.push(("Y", "Download"));
                keys.push(("N", "Not now"));
            }
            keys
        }
    }
}

/// UPDATES' rows at `width` cells, and which one is the field (if any).
pub(super) fn lines(app: &App, upd: &UpdState, width: u16) -> (Vec<Line<'static>>, Option<usize>) {
    let look = app.look();
    let t = &look.theme;
    let mut rows = Vec::new();
    match &upd.step {
        UpdStep::Installing { version } => {
            rows.extend(plain(
                &format!("Installing Raven {version}{}", look.glyphs.ellipsis),
                width,
            ));
            rows.push(Line::default());
            rows.extend(styled(INSTALLING, width, t.secondary));
            return (rows, None);
        }
        UpdStep::Ended(Ok(lines)) => {
            for line in lines {
                rows.extend(plain(line, width));
            }
            return (rows, None);
        }
        UpdStep::Ended(Err(why)) => {
            rows.extend(styled(why, width, t.warn));
            return (rows, None);
        }
        UpdStep::Showing => {}
    }
    let Some(view) = app.updates() else {
        let text = format!("{READING}{}", look.glyphs.ellipsis);
        return (plain(&text, width), None);
    };
    for line in &view.lines {
        rows.extend(plain(line, width));
    }
    if let Some(ready) = &view.ready {
        rows.push(Line::default());
        for line in &ready.lines {
            rows.extend(plain(line, width));
        }
        rows.push(Line::default());
        rows.extend(plain(&format!("Type {} to continue:", ready.word), width));
        rows.push(Line::raw(format!(
            "> {}",
            display::one_line(&upd.typed, u16::MAX, "")
        )));
        let field = rows.len() - 1;
        return (rows, Some(field));
    }
    if let Some(offer) = &view.offer {
        rows.push(Line::default());
        for line in &offer.lines {
            rows.extend(plain(line, width));
        }
    }
    if !view.manual.is_empty() {
        rows.push(Line::default());
        for line in &view.manual {
            rows.push(Line::raw(display::one_line(
                line,
                width,
                look.glyphs.ellipsis,
            )));
        }
    }
    (rows, None)
}

/// `text` wrapped at `width` cells, plain.
fn plain(text: &str, width: u16) -> Vec<Line<'static>> {
    wrap(&shaped(text), width, 0)
        .into_iter()
        .map(Line::raw)
        .collect()
}

fn styled(text: &str, width: u16, style: ratatui::style::Style) -> Vec<Line<'static>> {
    wrap(&shaped(text), width, 0)
        .into_iter()
        .map(|row| Line::styled(row, style))
        .collect()
}

/// Untrusted text (release notes, file names) as one line of plain cells.
fn shaped(text: &str) -> String {
    display::one_line(text, u16::MAX, "")
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;
    use raven_core::security_gate::{self, SecGate};

    use super::*;

    /// The update gates open for this thread (debug builds), shut again
    /// when dropped.
    struct Gates;

    impl Gates {
        fn open() -> Option<Gates> {
            if !cfg!(debug_assertions) {
                return None;
            }
            security_gate::set_lab_for_this_thread(SecGate::Advisory, Some(true));
            security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, Some(true));
            Some(Gates)
        }
    }

    impl Drop for Gates {
        fn drop(&mut self) {
            security_gate::set_lab_for_this_thread(SecGate::Advisory, None);
            security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, None);
        }
    }

    fn ready_view() -> UpdateView {
        UpdateView {
            live: true,
            full: true,
            lines: vec![
                "Security notices from the Raven project: none yet.".to_owned(),
                "This Raven: Raven 1.4.2 (build 41).".to_owned(),
                "Updates: Raven 1.5.0 (build 42) is ready to install (raven update install)."
                    .to_owned(),
            ],
            ready: Some(UpdateReady {
                serial: 42,
                version: "1.5.0".to_owned(),
                lines: vec![
                    "Raven 1.5.0 (build 42) is ready to install (34.1 MB). It is signed by 2 of \
                     the 3 Raven project keys and listed in the public release log (entry 9 of \
                     9)."
                    .to_owned(),
                    "What's new: \u{1b}[2J faster.".to_owned(),
                ],
                word: "install",
            }),
            manual: Vec::new(),
            net_row: Some("1.5.0 ready to install".to_owned()),
            offer: None,
        }
    }

    /// A friend's offer and nothing to install (P6.49).
    fn offer_view() -> UpdateView {
        UpdateView {
            live: true,
            full: true,
            lines: vec!["Updates: none waiting.".to_owned()],
            ready: None,
            manual: Vec::new(),
            net_row: Some("none waiting".to_owned()),
            offer: Some(OfferView {
                digest: [0x3F; 32],
                lines: vec![
                    "Sara has a Raven update (build 5) for this computer (34.1 MB).".to_owned(),
                    "Download it from Sara?".to_owned(),
                ],
            }),
        }
    }

    /// The download is its own approval (P6.49): Y queues it for the offer
    /// shown, N closes, and nothing else does either.
    #[test]
    fn y_downloads_a_friends_offer_and_n_closes() {
        let Some(_gates) = Gates::open() else {
            return;
        };
        let mut app = testkit::app((80, 24));
        testkit::press(&mut app, KeyCode::Char('U'));
        testkit::send(&mut app, Msg::Job(JobResult::Updates(offer_view())));
        let Some(Overlay::Updates(upd)) = app.overlays().last().cloned() else {
            panic!()
        };
        let (rows, field) = lines(&app, &upd, 72);
        assert!(field.is_none(), "no word to type for a download");
        let text: Vec<String> = rows.iter().map(ToString::to_string).collect();
        assert!(
            text.iter().any(|row| row == "Download it from Sara?"),
            "{text:?}"
        );
        assert_eq!(
            keys(&app, &upd),
            vec![("Esc", "Close"), ("Y", "Download"), ("N", "Not now")]
        );
        assert!(!testkit::press(&mut app, KeyCode::Enter)
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Node(NodeJob::ApproveDownload { .. }))));
        let cmds = testkit::press(&mut app, KeyCode::Char('y'));
        assert!(
            cmds.iter().any(|cmd| matches!(
                cmd,
                Cmd::Node(NodeJob::ApproveDownload { digest }) if *digest == [0x3F; 32]
            )),
            "{cmds:?}"
        );
        testkit::press(&mut app, KeyCode::Char('n'));
        assert!(app.overlays().is_empty());
        // With a release to install the letters type its word instead.
        testkit::press(&mut app, KeyCode::Char('U'));
        let mut both = ready_view();
        both.offer = offer_view().offer;
        testkit::send(&mut app, Msg::Job(JobResult::Updates(both)));
        assert!(!testkit::press(&mut app, KeyCode::Char('y'))
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Node(NodeJob::ApproveDownload { .. }))));
    }

    fn installs(cmds: &[Cmd]) -> Vec<&NodeJob> {
        cmds.iter()
            .filter_map(|cmd| match cmd {
                Cmd::Node(job @ NodeJob::InstallUpdate { .. }) => Some(job),
                _ => None,
            })
            .collect()
    }

    fn type_word(app: &mut App, word: &str) -> Vec<Cmd> {
        let mut cmds = Vec::new();
        for c in word.chars() {
            cmds.extend(testkit::press(app, KeyCode::Char(c)));
        }
        cmds
    }

    #[test]
    fn u_does_nothing_while_the_gate_is_shut() {
        security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, Some(false));
        let mut app = testkit::app((80, 24));
        let cmds = testkit::press(&mut app, KeyCode::Char('u'));
        assert!(app.overlays().is_empty());
        assert!(!cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Node(NodeJob::LoadUpdates { .. }))));
        security_gate::set_lab_for_this_thread(SecGate::ReleaseBundle, None);
    }

    /// The install is its own approval: shown, the word typed, Enter; it
    /// runs as one node job with the build shown, and UPDATES says how it
    /// ended.
    #[test]
    fn the_word_typed_and_enter_install_the_build_shown() {
        let Some(_gates) = Gates::open() else {
            return;
        };
        let mut app = testkit::app((80, 24));
        let cmds = testkit::press(&mut app, KeyCode::Char('U'));
        assert!(matches!(app.overlays(), [Overlay::Updates(_)]));
        assert!(cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Node(NodeJob::LoadUpdates { full: true }))));
        // Before the read: nothing to type into.
        let Some(Overlay::Updates(upd)) = app.overlays().last().cloned() else {
            panic!()
        };
        let (rows, field) = lines(&app, &upd, 72);
        assert!(field.is_none());
        assert!(rows[0].to_string().starts_with(READING));
        testkit::send(&mut app, Msg::Job(JobResult::Updates(ready_view())));
        let Some(Overlay::Updates(upd)) = app.overlays().last().cloned() else {
            panic!()
        };
        let (rows, field) = lines(&app, &upd, 72);
        let text: Vec<String> = rows.iter().map(ToString::to_string).collect();
        assert!(
            text.iter().any(|row| row == "Type install to continue:"),
            "{text:?}"
        );
        assert!(text.iter().all(|row| !row.contains('\u{1b}')), "{text:?}");
        assert_eq!(field, Some(rows.len() - 1));
        // Enter with the wrong word installs nothing; 'u' types, not closes.
        let mut cmds = type_word(&mut app, "insta");
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert!(installs(&cmds).is_empty());
        assert!(matches!(app.overlays(), [Overlay::Updates(_)]));
        cmds = type_word(&mut app, "ll");
        cmds.extend(testkit::press(&mut app, KeyCode::Enter));
        assert_eq!(
            installs(&cmds),
            [&NodeJob::InstallUpdate {
                serial: 42,
                started_by_app: None
            }]
        );
        let Some(Overlay::Updates(upd)) = app.overlays().last().cloned() else {
            panic!()
        };
        assert_eq!(
            upd.step,
            UpdStep::Installing {
                version: "1.5.0".to_owned()
            }
        );
        // While it installs, Esc and Enter do nothing.
        assert!(installs(&testkit::press(&mut app, KeyCode::Enter)).is_empty());
        testkit::press(&mut app, KeyCode::Esc);
        assert!(matches!(app.overlays(), [Overlay::Updates(_)]));
        let done = vec!["Raven 1.5.0 (build 42) is installed and running.".to_owned()];
        let cmds = testkit::send(
            &mut app,
            Msg::Job(JobResult::UpdateInstalled {
                result: Ok(done.clone()),
                after: Probe::timed_out(),
                started: None,
            }),
        );
        let Some(Overlay::Updates(upd)) = app.overlays().last().cloned() else {
            panic!()
        };
        assert_eq!(upd.step, UpdStep::Ended(Ok(done)));
        // What waits is read again; Esc closes now.
        assert!(cmds
            .iter()
            .any(|cmd| matches!(cmd, Cmd::Node(NodeJob::LoadUpdates { full: true }))));
        testkit::press(&mut app, KeyCode::Esc);
        assert!(app.overlays().is_empty());
    }

    #[test]
    fn a_paste_clears_the_word_and_manual_steps_have_no_field() {
        let Some(_gates) = Gates::open() else {
            return;
        };
        let mut app = testkit::app((80, 24));
        testkit::press(&mut app, KeyCode::Char('u'));
        testkit::send(&mut app, Msg::Job(JobResult::Updates(ready_view())));
        type_word(&mut app, "install");
        testkit::paste(&mut app, "install", PasteVia::Bracketed);
        let Some(Overlay::Updates(upd)) = app.overlays().last().cloned() else {
            panic!()
        };
        assert_eq!(upd.typed, "");
        // A short read (NET's) while UPDATES is open keeps what it shows.
        let short = UpdateView {
            full: false,
            ready: None,
            ..ready_view()
        };
        testkit::send(&mut app, Msg::Job(JobResult::Updates(short)));
        assert!(app.updates().is_some_and(|view| view.ready.is_some()));
        // Where Raven can't swap its programs: the steps, no field, and U
        // closes.
        let manual = UpdateView {
            ready: None,
            manual: vec![
                "Raven can't replace its own programs in /usr/local/bin: this user can't change \
                 that folder. Install it the way you installed Raven:"
                    .to_owned(),
                "  3. Start Raven again: raven unlock".to_owned(),
            ],
            ..ready_view()
        };
        testkit::send(&mut app, Msg::Job(JobResult::Updates(manual)));
        let (rows, field) = lines(&app, &upd, 72);
        assert!(field.is_none());
        let text: Vec<String> = rows.iter().map(ToString::to_string).collect();
        assert!(
            text.iter()
                .any(|row| row.starts_with("  3. Start Raven again")),
            "{text:?}"
        );
        let cmds = testkit::press(&mut app, KeyCode::Enter);
        assert!(installs(&cmds).is_empty());
        testkit::press(&mut app, KeyCode::Char('u'));
        assert!(app.overlays().is_empty());
    }
}
