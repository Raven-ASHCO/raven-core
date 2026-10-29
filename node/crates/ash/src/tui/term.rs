//! The terminal while the full screen is up. [`TerminalGuard::enter`] puts it
//! into raw mode and the alternate screen; every way out puts it back:
//!
//! - the guard's Drop;
//! - the panic hook, for a panic on the UI thread
//!   ([`install_panic_hook_once`]);
//! - the signal thread, when the UI does not exit in time (workers.rs).
//!
//! The guard also owns SCREEN_ACTIVE (stdio.rs): set while the screen is up,
//! so stray `println!` output lands in the ring instead of on the frame, and
//! cleared before anything is printed on the plain terminal again.
//!
//! Never turned on: mouse capture (native selection keeps working), keyboard
//! enhancement flags, a window title.

use std::cell::Cell;
use std::io::{self, Stdout, Write};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

use crossterm::cursor;
#[cfg(not(windows))]
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use crossterm::queue;
use crossterm::terminal::{
    self, Clear, ClearType, DisableLineWrap, EnableLineWrap, EnterAlternateScreen,
    LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::Rect;
use ratatui::Terminal;

use super::stdio;
#[cfg(test)]
use super::testkit;
#[cfg(all(test, unix))]
use super::ui;

/// The terminal the app draws on.
pub(super) type Tty = Terminal<CrosstermBackend<Stdout>>;

/// The terminal is in raw mode with the screen's settings: what [`restore`]
/// undoes. Swapped to false by whoever undoes it, so it is undone once.
static ENTERED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Set on the UI thread: a panic there takes the screen down with it.
    static UI_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// The full screen, while it is up. Dropping it restores the terminal.
pub(super) struct TerminalGuard {
    _private: (),
}

impl TerminalGuard {
    /// Raw mode, the alternate screen, no line wrap and a hidden cursor; on
    /// Unix also bracketed paste and explicit BiDi. Then SCREEN_ACTIVE.
    ///
    /// With line wrap off, a glyph the terminal draws wider than ratatui
    /// counted is clipped at the edge instead of spilling into the next row.
    pub(super) fn enter() -> io::Result<(TerminalGuard, Tty)> {
        // Made first, so every early return below undoes what was done.
        let guard = TerminalGuard { _private: () };
        enter_screen()?;
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        stdio::set_screen_active(true);
        Ok((guard, terminal))
    }

    /// Leaves the screen entirely, raw mode included, for a prompt on the
    /// plain terminal (the vault passphrase while a vault profile's identity
    /// is made). SCREEN_ACTIVE is cleared first, so everything printed from
    /// here on reaches the terminal.
    pub(super) fn suspend_full(&mut self) {
        stdio::set_screen_active(false);
        leave_screen();
    }

    /// Back from [`TerminalGuard::suspend_full`]. SCREEN_ACTIVE is set first,
    /// so nothing printed from here on reaches the screen; every cell is
    /// redrawn at the next draw. On an error the guard's Drop still restores
    /// whatever was done. (It needs a real terminal, so no test calls it.)
    pub(super) fn resume_full(&mut self, terminal: &mut Tty) -> io::Result<()> {
        stdio::set_screen_active(true);
        enter_screen()?;
        terminal.clear()
    }
}

/// COPY's two halves, carried out by the UI thread (`Cmd::Peek` and
/// `Cmd::Unpeek`). On Windows crossterm may carry these out through the
/// console API instead of escape sequences, on whatever console the tests run
/// in, so only Unix tests call them.
impl TerminalGuard {
    /// COPY: leaves the alternate screen to show `lines` on the plain
    /// terminal, where they can be selected, each ended with CR LF. Raw mode
    /// stays and the input thread keeps reading: any key returns, through
    /// [`TerminalGuard::unpeek`]. SCREEN_ACTIVE stays set, and the lines go
    /// straight to the terminal.
    pub(super) fn peek(&mut self, lines: &[&str]) -> io::Result<()> {
        let mut out = io::stdout().lock();
        Self::queue_peek(&mut out, lines)?;
        out.flush()
    }

    /// Back from [`TerminalGuard::peek`]: the screen again, every cell
    /// redrawn at the next draw.
    pub(super) fn unpeek<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        let mut out = io::stdout();
        Self::queue_unpeek(&mut out)?;
        out.flush()?;
        redraw_all(terminal)
    }

    fn queue_peek(out: &mut impl Write, lines: &[&str]) -> io::Result<()> {
        queue!(out, LeaveAlternateScreen, EnableLineWrap, cursor::Show)?;
        for line in lines {
            out.write_all(line.as_bytes())?;
            out.write_all(b"\r\n")?;
        }
        Ok(())
    }

    fn queue_unpeek(out: &mut impl Write) -> io::Result<()> {
        queue!(out, EnterAlternateScreen, DisableLineWrap, cursor::Hide)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

/// Clears the screen and forgets ratatui's last frame, so the next draw
/// draws every cell. Through a resize to the size there is, not
/// `Terminal::clear`: that asks the terminal where its cursor is (`CSI 6n`)
/// and fails when no answer comes.
fn redraw_all<B: Backend>(terminal: &mut Terminal<B>) -> io::Result<()> {
    let other = |e: B::Error| io::Error::other(e.to_string());
    let size = terminal.size().map_err(other)?;
    terminal
        .resize(Rect::new(0, 0, size.width, size.height))
        .map_err(other)
}

/// Puts the terminal back as it was before [`TerminalGuard::enter`] if it
/// is still in the screen, and clears SCREEN_ACTIVE. The guard's Drop, the
/// panic hook and the signal thread all call it; only the first undoes.
pub(super) fn restore() {
    leave_screen();
    stdio::set_screen_active(false);
}

/// LOCK's way out (UXF.7), once the screen is left: the plain terminal is
/// cleared (`CSI 2 J`), so is its scrollback where the terminal supports it
/// (`CSI 3 J`; others ignore it), and the cursor goes to the top left, where
/// the exit line follows. Errors are ignored, as for any exit line.
pub(super) fn clear_plain(out: &mut impl Write) {
    let _ = queue_clear(out);
    let _ = out.flush();
}

fn queue_clear(out: &mut impl Write) -> io::Result<()> {
    queue!(
        out,
        cursor::MoveTo(0, 0),
        Clear(ClearType::All),
        Clear(ClearType::Purge)
    )
}

/// Marks the calling thread as the UI thread, for the panic hook.
pub(super) fn mark_ui_thread() {
    UI_THREAD.with(|ui| ui.set(true));
}

/// Installs, once per process, a panic hook that restores the terminal and
/// stderr before the panic message is printed, then hands over to the hook
/// that was there before. Only for a panic on the UI thread: the workers
/// catch their own panics, and the screen stays up for them.
pub(super) fn install_panic_hook_once() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if UI_THREAD.try_with(Cell::get).unwrap_or(false) {
                restore();
                let _ = stdio::restore_stderr();
            }
            previous(info);
        }));
    });
}

/// Raw mode, then the screen's settings.
fn enter_screen() -> io::Result<()> {
    terminal::enable_raw_mode()?;
    ENTERED.store(true, Ordering::Release);
    let mut out = io::stdout();
    queue_enter(&mut out)?;
    out.flush()
}

/// Undoes [`enter_screen`] if it is in effect: the settings, then raw mode.
/// Errors are ignored: the terminal may be gone (a hang-up), and each step is
/// tried anyway.
fn leave_screen() {
    if ENTERED.swap(false, Ordering::AcqRel) {
        queue_leave(&mut io::stdout());
        let _ = terminal::disable_raw_mode();
    }
}

fn queue_enter(out: &mut impl Write) -> io::Result<()> {
    queue!(out, EnterAlternateScreen, DisableLineWrap, cursor::Hide)?;
    #[cfg(not(windows))]
    {
        // A terminal without either ignores it; a paste then arrives as
        // keystrokes, which the input thread joins up.
        let _ = queue!(out, EnableBracketedPaste, ExplicitBidi(true));
    }
    Ok(())
}

/// Everything [`queue_enter`] turned on, turned off in reverse order, then
/// flushed. Each on its own, so one that fails cannot hold back the rest.
fn queue_leave(out: &mut impl Write) {
    #[cfg(not(windows))]
    {
        let _ = queue!(out, ExplicitBidi(false));
        let _ = queue!(out, DisableBracketedPaste);
    }
    let _ = queue!(out, EnableLineWrap);
    let _ = queue!(out, LeaveAlternateScreen);
    let _ = queue!(out, cursor::Show);
    let _ = out.flush();
}

/// ECMA-48 BDSM, `CSI 8 h` (explicit) and `CSI 8 l`: VTE then lays out
/// every row left to right as sent, so right-to-left text in one pane cannot
/// reorder the other pane. Terminals without BiDi ignore it.
#[cfg(not(windows))]
struct ExplicitBidi(bool);

#[cfg(not(windows))]
impl crossterm::Command for ExplicitBidi {
    fn write_ansi(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        f.write_str(if self.0 { "\x1b[8h" } else { "\x1b[8l" })
    }
}

#[cfg(test)]
impl TerminalGuard {
    /// A guard that marks the screen up as `enter` does, without touching the
    /// terminal: tests have none, and must never put the one they run in into
    /// raw mode.
    fn screen_only() -> TerminalGuard {
        stdio::set_screen_active(true);
        TerminalGuard { _private: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use ratatui::backend::TestBackend;

    /// The bytes `queue` writes.
    #[cfg(unix)]
    fn queued(queue: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut out = Vec::new();
        queue(&mut out);
        String::from_utf8(out).expect("escape sequences are ASCII")
    }

    /// Enter and leave, in order: leave undoes enter in reverse.
    #[cfg(unix)]
    #[test]
    fn entering_and_leaving_queue_the_commands_in_order() {
        let enter = queued(|out| queue_enter(out).expect("queue"));
        assert_eq!(
            enter,
            concat!(
                "\x1b[?1049h", // alternate screen
                "\x1b[?7l",    // line wrap off
                "\x1b[?25l",   // cursor hidden
                "\x1b[?2004h", // bracketed paste
                "\x1b[8h",     // explicit BiDi
            )
        );
        let leave = queued(queue_leave);
        assert_eq!(
            leave,
            concat!(
                "\x1b[8l",
                "\x1b[?2004l",
                "\x1b[?7h",
                "\x1b[?1049l",
                "\x1b[?25h",
            )
        );
    }

    /// LOCK's way out: the cursor to the top left, the screen cleared, then
    /// the scrollback, and nothing else.
    #[cfg(unix)]
    #[test]
    fn lock_clears_the_plain_terminal_and_its_scrollback() {
        let clear = queued(clear_plain);
        assert_eq!(clear, "\x1b[1;1H\x1b[2J\x1b[3J");
    }

    #[cfg(unix)]
    #[test]
    fn peek_shows_lines_on_the_plain_terminal() {
        let peek = queued(|out| {
            TerminalGuard::queue_peek(out, &["Copy your invite:", "", "raven-card/abc", ""])
                .expect("queue")
        });
        assert_eq!(
            peek,
            concat!(
                "\x1b[?1049l\x1b[?7h\x1b[?25h",
                "Copy your invite:\r\n\r\nraven-card/abc\r\n\r\n",
            )
        );
        let back = queued(|out| TerminalGuard::queue_unpeek(out).expect("queue"));
        assert_eq!(back, "\x1b[?1049h\x1b[?7l\x1b[?25l");
    }

    /// COPY as the UI thread carries it out: my invite alone between its
    /// heading and footer, each line ended with CR LF (raw mode stays).
    #[cfg(unix)]
    #[test]
    fn copy_writes_my_invite_alone_on_the_plain_terminal() {
        let card = testkit::card(7, "192.168.1.20:7420");
        let lines = ui::add_friend::copy_lines(&card, false, false);
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        let peek = queued(|out| TerminalGuard::queue_peek(out, &lines).expect("queue"));
        assert_eq!(
            peek,
            format!(
                "\x1b[?1049l\x1b[?7h\x1b[?25hYour Raven invite. Select the line below and copy \
                 it with your terminal:\r\n\r\n{card}\r\n\r\nIt holds only public \
                 information. Press any key to go back to Raven.\r\n"
            )
        );
        assert!(!card.contains('\x1b'));
    }

    /// A terminal that never answers where its cursor is (a pipe, a dumb
    /// pseudo-terminal), drawing into a test buffer.
    struct Mute(ratatui::backend::TestBackend);

    /// A test backend's answer: it never fails.
    fn sure<T>(answer: Result<T, std::convert::Infallible>) -> io::Result<T> {
        answer.map_err(|never| match never {})
    }

    impl Backend for Mute {
        type Error = io::Error;

        fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
        where
            I: Iterator<Item = (u16, u16, &'a ratatui::buffer::Cell)>,
        {
            sure(self.0.draw(content))
        }

        fn hide_cursor(&mut self) -> io::Result<()> {
            sure(self.0.hide_cursor())
        }

        fn show_cursor(&mut self) -> io::Result<()> {
            sure(self.0.show_cursor())
        }

        fn get_cursor_position(&mut self) -> io::Result<ratatui::layout::Position> {
            Err(io::Error::other("the terminal never answered CSI 6n"))
        }

        fn set_cursor_position<P: Into<ratatui::layout::Position>>(
            &mut self,
            position: P,
        ) -> io::Result<()> {
            sure(self.0.set_cursor_position(position))
        }

        fn clear(&mut self) -> io::Result<()> {
            sure(self.0.clear())
        }

        fn clear_region(&mut self, clear_type: ratatui::backend::ClearType) -> io::Result<()> {
            sure(self.0.clear_region(clear_type))
        }

        fn size(&self) -> io::Result<ratatui::layout::Size> {
            sure(self.0.size())
        }

        fn window_size(&mut self) -> io::Result<ratatui::backend::WindowSize> {
            sure(self.0.window_size())
        }

        fn flush(&mut self) -> io::Result<()> {
            sure(Backend::flush(&mut self.0))
        }
    }

    /// Back from COPY every cell is drawn again, and the terminal is asked
    /// nothing: ratatui's own clear asks where the cursor is, and a terminal
    /// that never answers would end the app.
    #[test]
    fn a_full_redraw_asks_the_terminal_nothing() {
        use ratatui::widgets::Paragraph;
        let mut terminal =
            Terminal::new(Mute(ratatui::backend::TestBackend::new(12, 2))).expect("a terminal");
        let draw = |terminal: &mut Terminal<Mute>| {
            terminal
                .draw(|f| f.render_widget(Paragraph::new("Raven"), f.area()))
                .map(|_| ())
        };
        let shown =
            |terminal: &Terminal<Mute>| testkit::buffer_lines(terminal.backend().0.buffer());
        draw(&mut terminal).expect("a frame");
        assert!(terminal.clear().is_err(), "ratatui's clear asks the cursor");
        redraw_all(&mut terminal).expect("nothing asked");
        assert_eq!(shown(&terminal), ["            ", "            "]);
        // The same frame again: drawn whole, since the last one is forgotten.
        draw(&mut terminal).expect("the frame again");
        assert_eq!(shown(&terminal), ["Raven       ", "            "]);
    }

    /// Runs this module's test `name` alone in a child process (see
    /// testkit::run_in_child): Some in the parent, None in the child.
    fn in_child(name: &str) -> Option<String> {
        testkit::run_in_child(&format!("{}::{name}", module_path!()))
    }

    #[test]
    fn screen_active_follows_the_guard() {
        if let Some(out) = in_child("screen_active_follows_the_guard") {
            if cfg!(unix) {
                assert!(
                    out.contains(concat!(
                        "\x1b[?1049l\x1b[?7h\x1b[?25hline one\r\nline two\r\n",
                        "\x1b[?1049h\x1b[?7l\x1b[?25l",
                    )),
                    "peek and unpeek write to the terminal directly:\n{out:?}"
                );
            }
            return;
        }
        assert!(!stdio::divert_stdout(format_args!("before\n")));
        let mut guard = TerminalGuard::screen_only();
        assert!(stdio::divert_stdout(format_args!("while up\n")));
        // COPY keeps the screen marked up: its lines go to the terminal
        // directly, and stray output still goes to the ring.
        #[cfg(unix)]
        {
            guard.peek(&["line one", "line two"]).expect("peek");
            assert!(stdio::divert_stdout(format_args!("while peeking\n")));
            let mut terminal = Terminal::new(TestBackend::new(20, 4)).expect("test terminal");
            guard.unpeek(&mut terminal).expect("unpeek");
        }
        // A plain-terminal prompt: cleared before anything is printed.
        guard.suspend_full();
        assert!(!stdio::divert_stdout(format_args!("prompt\n")));
        drop(guard);
        assert!(!stdio::divert_stdout(format_args!("after the screen\n")));
        // A second guard, dropped: restoring twice is harmless.
        drop(TerminalGuard::screen_only());
        restore();
        assert!(!stdio::divert_stdout(format_args!("after the second\n")));
    }

    #[test]
    fn the_panic_hook_restores_only_for_the_ui_thread() {
        if in_child("the_panic_hook_restores_only_for_the_ui_thread").is_some() {
            return;
        }
        install_panic_hook_once();
        install_panic_hook_once();
        // Only the hook may take the screen down here.
        std::mem::forget(TerminalGuard::screen_only());
        let worker = std::thread::spawn(|| panic!("a worker panics (expected in this test)"));
        assert!(worker.join().is_err());
        assert!(
            stdio::divert_stdout(format_args!("still up\n")),
            "a worker's panic leaves the screen up"
        );
        mark_ui_thread();
        let ui = panic::catch_unwind(|| panic!("the UI thread panics (expected in this test)"));
        assert!(ui.is_err());
        assert!(
            !stdio::divert_stdout(format_args!("after\n")),
            "a UI-thread panic takes the screen down"
        );
    }
}
