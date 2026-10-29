//! Full-screen terminal app (see docs/design/2026-10-terminal-app.md).
//!
//! Only `bridge.rs` may name items of cli.rs and its sibling modules; every
//! other file here goes through `bridge::…`. A source scan in `testkit.rs`
//! enforces this, so this file never names a `super` path: here `super` is
//! cli.rs itself.

mod anim;
mod app;
mod background;
mod bridge;
mod controller;
mod delivery;
mod display;
#[cfg(all(test, unix))]
mod e2e_tests;
mod errors;
pub(super) use errors::outbox_code_headline;
mod gate;
// Messages deleted in a desktop app: the desktop engine writes the file
// (engine_bridge.rs), and the chats of both apps leave them out.
pub(super) mod hidden;
mod keys_fa;
// A typed confirmation word on a Persian keyboard layout reads as the Latin
// letters on the same keys (`raven chats delete`).
pub(super) use keys_fa::latin as latin_on_same_key;
mod live;
mod logo;
mod node;
// The login service Raven's installer set up: `ash status` and `ash listen`
// word their advice by it.
pub(super) use node::{login_service_for, Managed};
mod presence;
#[cfg(test)]
mod screens;
// The read markers, which the desktop engine shares (engine_bridge.rs).
pub(super) mod read_marks;
mod state_file;
// The read markers and the name a sealed profile's tui_state.json still
// holds move into tui_private.rms at the top of every command (review
// D-lock-tui-1); `raven privacy status` counts what is left.
pub(super) use state_file::{move_private_now, private_files_in_plain};
pub(super) mod stdio;
mod term;
#[cfg(test)]
mod testkit;
mod theme;
mod ui;
mod workers;

use std::collections::VecDeque;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use app::{
    App, Cmd, ExitPlan, IdentityStart, JobResult, ListenOverride, Look, LookEnv, Msg, Session,
    SuspendJob,
};
use controller::{Controller, IdentityState};
use gate::{GateInput, UiChoice};
use state_file::{Receive, TuiState};
use stdio::StderrRedirect;
use term::{TerminalGuard, Tty};
use theme::TermEnv;
use workers::{Hub, InputHandle, SignalMode};

/// Printed on the plain terminal before the full screen opens: the way back
/// to the classic menu, in case the screen is no use to this person.
const OPENING: &str = "Opening Raven in full-screen mode. For the plain menu: \
                       Settings > Classic menu, or start Raven with RAVEN_UI=classic.\n";

/// On Windows, after the exit line, when this process is alone in its
/// console (started by a double-click): the window closes when Raven exits.
const PRESS_ENTER: &str = "Press Enter to close this window.\n";

/// The longest the UI thread waits for a message when nothing on screen
/// moves: then it ticks the clock, and draws only if something is due.
const IDLE_WAKE: Duration = Duration::from_secs(30);

/// Printed on the plain terminal just before a passphrase-vault profile's
/// first passphrase prompt (WZ-4).
const VAULT_NOTE: &str = "Raven needs a passphrase to protect your keys on this computer. You \
                          will type it each time you open Raven. The full-screen app comes back \
                          afterwards.\n";
/// Why the identity was not made when the input thread did not let go of
/// the keyboard for the passphrase prompt.
const KEYBOARD_BUSY: &str = "the keyboard could not be handed to the passphrase prompt";

/// How long the exit waits for a job still writing the identity or
/// contacts.json (a Keychain dialog may hold it up).
const CRITICAL_WAIT: Duration = Duration::from_secs(30);

/// What `raven` and `ash` run with no arguments: the full screen when the
/// gate allows it (tui/gate.rs), otherwise the classic line menu.
pub(super) fn run_or_classic(data_dir: &Path) {
    let saved = state_file::peek(data_dir);
    match gate::decide(&gate_input(&saved)) {
        UiChoice::Tui => run_full_screen(data_dir, &saved),
        UiChoice::Classic => bridge::interactive(data_dir),
    }
}

/// The gate's inputs for this process. Only reads: tui_state.json was
/// peeked, never created, and the Windows console is left in the mode it was
/// in.
fn gate_input(saved: &TuiState) -> GateInput {
    GateInput {
        stdin_tty: io::stdin().is_terminal(),
        stdout_tty: io::stdout().is_terminal(),
        term: std::env::var("TERM").ok(),
        ui_env: std::env::var("RAVEN_UI").ok(),
        saved_classic: saved.always_classic,
        windows_console_ok: stdio::windows_console_ok(),
        screen_reader: stdio::screen_reader_running(),
        default_on: gate::DEFAULT_ON,
    }
}

/// The full screen, start to exit. Returns only for exit code 0; when the
/// screen cannot start, the classic menu runs instead.
fn run_full_screen(data_dir: &Path, saved: &TuiState) {
    write_plain(&mut io::stdout().lock(), OPENING);
    // Now, while no other thread exists to read the environment.
    let listen = if bridge::service_lan_listen_env().is_some() {
        ListenOverride::User
    } else if saved.receive == Receive::Off {
        bridge::set_listen_loopback_env();
        ListenOverride::Loopback
    } else {
        ListenOverride::None
    };
    // On the plain terminal, before any other thread: the vault passphrase
    // prompt, Keychain dialogs and the identity-lock notice all work here.
    // The controller keeps it for the whole session.
    let controller = Arc::new(Controller::new(data_dir));
    let mut locked = false;
    let identity = match controller.load_identity() {
        IdentityState::Ready { me, .. } => {
            // Opening the app is its way to start Raven again after its own
            // Lock (PP.23): that lock is cleared before anything could start
            // Raven. One `raven lock` set stays, and UNLOCK asks first
            // (review E-harness-docs-ci-3).
            locked = controller.reopen_after_lock();
            IdentityStart::Ready(me)
        }
        IdentityState::Missing => IdentityStart::Missing,
        IdentityState::Unavailable(why) => IdentityStart::Unavailable(why),
    };
    // Once, while no other thread exists to read the environment.
    let mut look_env = look_env();
    // The gate read tui_state.json alone; the session also gets the read
    // markers and the name a sealed profile keeps in tui_private.rms
    // (privacy pack PP.24), opened with the keys this process loaded first.
    let mut session = Session {
        identity,
        data_dir: data_dir.to_path_buf(),
        settings: state_file::load(data_dir).0,
        program: node::Program::of_this_process(),
        listen,
        over_ssh: look_env.term.ssh,
        gates: node::GatesView::of_this_build(),
        look_env: look_env.clone(),
        locked,
    };

    let (tx, rx) = mpsc::channel();
    if let Err(e) = workers::start_signal_thread(tx.clone()) {
        return open_classic_instead(data_dir, None, &e);
    }
    // Before any thread that could start a process exists.
    let redirect = match workers::capture_stderr(tx.clone()) {
        Ok(redirect) => redirect,
        Err(e) => return open_classic_instead(data_dir, None, &e),
    };
    term::install_panic_hook_once();
    term::mark_ui_thread();
    let (guard, mut terminal) = match TerminalGuard::enter() {
        Ok(entered) => entered,
        Err(e) => return open_classic_instead(data_dir, Some(redirect), &e),
    };
    // Colors > Automatic: the terminal's background as it says it, asked
    // once (OSC 11), in raw mode, before the first frame and before the
    // input thread reads the keys (background.rs).
    let ttys = io::stdin().is_terminal() && io::stdout().is_terminal();
    if background::should_ask(saved, &look_env.term, ttys) {
        let wait = background::wait(&look_env.term);
        let answered = background::ask(&mut io::stdout(), &mut stdio::KeysIn, wait);
        look_env.term.answered_background = answered;
        session.look_env.term.answered_background = answered;
    }
    let now = Instant::now();
    let look = Look::of(saved, &look_env);
    let mut app = App::new(look, terminal_size(&terminal), now, bridge::now_ms());
    // Its first jobs wait until the workers are there; the first frame is
    // already the session's screen (the wizard, ERR-ID or Home).
    let first = app.start(session);
    // Only the first draw falls back to the classic menu: after it, the
    // screen has worked, and a failure means the terminal has gone.
    if let Err(e) = terminal.draw(|f| ui::render(f, &app, now)) {
        drop((terminal, guard));
        return open_classic_instead(data_dir, Some(redirect), &e);
    }
    app.take_dirty();
    app.mark_drawn(now);
    // The workers and the poller first: no job runs until the app asks.
    let hub = match Hub::start(Arc::clone(&controller), &tx) {
        Ok(hub) => hub,
        Err(e) => {
            drop((terminal, guard));
            return open_classic_instead(data_dir, Some(redirect), &e);
        }
    };
    let input = match workers::spawn_input(tx, app.size()) {
        Ok(input) => input,
        Err(e) => {
            drop((terminal, guard));
            return open_classic_instead(data_dir, Some(redirect), &e);
        }
    };
    let mut running = Running {
        terminal,
        guard,
        redirect,
        input,
        hub,
        controller,
    };
    let end = match carry_out(first, &mut app, &mut running) {
        Some(end) => end,
        None => event_loop(&mut running, &mut app, &rx),
    };
    let Running {
        terminal,
        guard,
        redirect,
        input,
        hub,
        ..
    } = running;
    match end {
        // The process ends: a job still running ends with it, once nothing
        // writes the identity or contacts.json any more.
        End::Exit(plan) => finish(*plan, &input, terminal, guard, redirect),
        End::Classic => {
            hub.shut_down();
            switch_to_classic(data_dir, &input, terminal, guard, redirect);
        }
    }
}

/// The full screen could not start: the terminal back as it was, one line
/// on stderr saying why, then the classic menu.
fn open_classic_instead(data_dir: &Path, redirect: Option<StderrRedirect>, why: &io::Error) {
    if let Some(redirect) = redirect {
        let _ = redirect.disarm();
    }
    workers::set_signal_mode(SignalMode::Classic);
    write_plain(
        &mut io::stderr().lock(),
        &format!(
            "Raven couldn't open the full screen ({why}), so the classic menu opens instead.\n"
        ),
    );
    bridge::interactive(data_dir);
}

/// How the event loop ended.
enum End {
    /// Boxed: an exit plan carries the settings to save (a large `Err` for
    /// `create_on_plain_terminal`).
    Exit(Box<ExitPlan>),
    /// The user chose the classic menu.
    Classic,
}

/// What the UI thread works with while the screen is up.
struct Running {
    terminal: Tty,
    guard: TerminalGuard,
    redirect: StderrRedirect,
    input: InputHandle,
    hub: Hub,
    /// For the jobs the UI thread runs itself (`Cmd::Suspend`).
    controller: Arc<Controller>,
}

/// The UI thread's loop: a draw whenever something visible changed or an
/// animation frame is due, then one message at a time, through
/// `App::update`. With nothing moving it sleeps until a message comes (or
/// [`IDLE_WAKE`]), so an idle app draws nothing.
fn event_loop(running: &mut Running, app: &mut App, rx: &Receiver<Msg>) -> End {
    loop {
        let now = Instant::now();
        let due = anim::frame_due(app, now);
        // During COPY the plain terminal shows its lines: nothing is drawn.
        if !app.peeking() && (app.take_dirty() || due) {
            if running.terminal.draw(|f| ui::render(f, app, now)).is_err() {
                return End::Exit(Box::new(ExitPlan::draw_failed(workers::received_signal())));
            }
            app.mark_drawn(now);
        }
        let wait = anim::next_wait(app, Instant::now()).unwrap_or(IDLE_WAKE);
        let msg = match rx.recv_timeout(wait) {
            Ok(msg) => msg,
            Err(RecvTimeoutError::Timeout) => Msg::Tick,
            // Every sender is gone, the signal thread's too: no key and no
            // signal can reach the app any more.
            Err(RecvTimeoutError::Disconnected) => {
                return End::Exit(Box::new(ExitPlan::part_failed()))
            }
        };
        let now = Instant::now();
        if let Some(end) = carry_out(app.update(msg, now, bridge::now_ms()), app, running) {
            return end;
        }
    }
}

/// Carries out what `update` asked, in order: jobs to their workers, the
/// UI thread's own commands here. A job the UI thread runs itself hands its
/// result straight back to `update`, and what that asks comes next. Some(end)
/// when the loop must end.
fn carry_out(cmds: Vec<Cmd>, app: &mut App, running: &mut Running) -> Option<End> {
    let mut queue = VecDeque::from(cmds);
    while let Some(cmd) = queue.pop_front() {
        match cmd {
            Cmd::Redraw => {
                if running.terminal.clear().is_err() {
                    return Some(End::Exit(Box::new(ExitPlan::draw_failed(
                        workers::received_signal(),
                    ))));
                }
            }
            Cmd::Suspend(SuspendJob::CreateIdentity) => {
                let result = match create_on_plain_terminal(running) {
                    Ok(result) => result,
                    Err(end) => return Some(end),
                };
                queue.extend(app.update(Msg::Job(result), Instant::now(), bridge::now_ms()));
            }
            // The App asks only while no job runs: no worker reads the
            // environment now.
            Cmd::ApplyListenLoopback => {
                if bridge::service_lan_listen_env().is_none() {
                    bridge::set_listen_loopback_env();
                }
            }
            // COPY: raw mode stays and the keys keep coming; a failure
            // means the terminal has gone.
            Cmd::Peek(lines) => {
                let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
                if running.guard.peek(&lines).is_err() {
                    return Some(End::Exit(Box::new(ExitPlan::draw_failed(
                        workers::received_signal(),
                    ))));
                }
            }
            Cmd::Unpeek => {
                if running.guard.unpeek(&mut running.terminal).is_err() {
                    return Some(End::Exit(Box::new(ExitPlan::draw_failed(
                        workers::received_signal(),
                    ))));
                }
            }
            Cmd::SwitchToClassic => return Some(End::Classic),
            // A note shown once on the plain terminal is remembered first: a
            // failure only means it shows again next time.
            Cmd::Exit(plan) => {
                if let Some(state) = &plan.save {
                    let _ = running.controller.save_read_marks(state);
                }
                return Some(End::Exit(Box::new(plan)));
            }
            job => running.hub.dispatch(job),
        }
    }
    None
}

/// WZ-4 on a passphrase-vault profile. The vault asks for the new passphrase
/// twice on the terminal itself, so the screen steps aside: the keyboard is
/// handed over, the screen and raw mode are left (SCREEN_ACTIVE off),
/// stderr reaches the terminal again, and a signal waits until the identity
/// is made, here on the UI thread. Then everything comes back as it was.
/// Err when the screen can't come back: the terminal has gone.
fn create_on_plain_terminal(running: &mut Running) -> Result<JobResult, End> {
    if !running.input.pause() {
        running.input.resume();
        return Ok(JobResult::Created {
            result: Err(KEYBOARD_BUSY.to_owned()),
            captured: String::new(),
        });
    }
    workers::set_signal_mode(SignalMode::Suspended);
    running.guard.suspend_full();
    running.redirect.set_passthrough(true);
    write_plain(&mut io::stdout().lock(), VAULT_NOTE);
    // Not caught: a panic on the UI thread ends Raven, the panic hook putting
    // the terminal and stderr back first, as anywhere else on this thread.
    let result = workers::created(running.controller.create_identity());
    running.redirect.set_passthrough(false);
    let resumed = running.guard.resume_full(&mut running.terminal);
    workers::set_signal_mode(SignalMode::Tui);
    running.input.resume();
    match resumed {
        Ok(()) => Ok(result),
        Err(_) => Err(End::Exit(Box::new(ExitPlan::draw_failed(
            workers::received_signal(),
        )))),
    }
}

/// Leaves the screen for the classic line menu in this terminal: the
/// keyboard, the terminal and stderr go back first, and a signal then ends
/// the process at once. The menu's own way out ends Raven as it always has.
fn switch_to_classic(
    data_dir: &Path,
    input: &InputHandle,
    terminal: Tty,
    guard: TerminalGuard,
    redirect: StderrRedirect,
) {
    // The menu reads the keyboard now.
    input.pause();
    drop(terminal);
    drop(guard);
    let _ = redirect.disarm();
    workers::set_signal_mode(SignalMode::Classic);
    bridge::interactive(data_dir);
}

/// Leaves the screen and ends as `plan` says: the terminal and stderr back,
/// then the exit line (after LOCK and ERASE, on a cleared terminal), and on
/// Windows the wait for Enter in a console of its own. After a hang-up
/// nothing is printed, and a failure exits as the hang-up did. Returns only
/// for exit code 0.
fn finish(
    plan: ExitPlan,
    input: &InputHandle,
    terminal: Tty,
    guard: TerminalGuard,
    redirect: StderrRedirect,
) {
    // The keyboard goes back to the shell, or to the wait below.
    input.pause();
    // ratatui shows the cursor when dropped and reports a failure on stderr:
    // done while stderr still goes into the pipe.
    drop(terminal);
    drop(guard);
    let _ = redirect.disarm();
    // A job still writing the identity or contacts.json finishes first: the
    // process must not end in the middle of it.
    workers::wait_for_critical(CRITICAL_WAIT);
    let hang_up = workers::received_signal().filter(|signal| signal.hung_up());
    let code = match hang_up {
        Some(signal) if plan.code != 0 => signal.exit_code(),
        _ => plan.code,
    };
    if !plan.quiet && hang_up.is_none() {
        // LOCK, ERASE: nothing of the session stays on the terminal above
        // its lines.
        if plan.clear {
            term::clear_plain(&mut io::stdout().lock());
        }
        if let Some(line) = plan.line {
            let line = format!("{line}\n");
            if code == 0 {
                write_plain(&mut io::stdout().lock(), &line);
            } else {
                write_plain(&mut io::stderr().lock(), &line);
            }
        }
        if stdio::console_process_count() == Some(1) {
            write_plain(&mut io::stdout().lock(), PRESS_ENTER);
            let _ = io::stdin().read_line(&mut String::new());
        }
    }
    if code != 0 {
        std::process::exit(code);
    }
}

/// Writes the app's own text on the plain terminal straight to `out`, never
/// through `println!`: that panics on any error but a closed pipe, and a
/// hung-up terminal gives EIO. Errors are ignored.
fn write_plain(out: &mut impl Write, text: &str) {
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

/// What the screens' look follows besides Settings, in this process.
fn look_env() -> LookEnv {
    LookEnv {
        term: TermEnv::from_process(),
        code_page: stdio::output_code_page(),
        screen_reader: stdio::screen_reader_running(),
    }
}

/// The terminal's size in cells; 80 by 24 if it cannot be read (the next
/// draw then fails, or the size poll corrects it).
fn terminal_size(terminal: &Tty) -> (u16, u16) {
    terminal
        .size()
        .map_or((80, 24), |size| (size.width, size.height))
}
