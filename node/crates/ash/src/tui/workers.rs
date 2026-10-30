//! The threads beside the UI thread, and what they send it:
//!
//! - input: keys, pastes and size changes through crossterm. Keystroke bursts
//!   become one paste ([`coalesce`]), so pasted text never fires a shortcut;
//! - stderr reader: drains the pipe that `StderrRedirect` points stderr into,
//!   so no writer ever blocks on it and nothing lands on the frame. It notes
//!   sync sentinels ([`sync_stderr`]) and passes the rest on;
//! - signal: SIGTERM and SIGHUP (Windows: the console closing, Ctrl+Break),
//!   for the whole process;
//! - the store, send and node workers ([`Hub`]): each runs its jobs one at a
//!   time, in order, inside `catch_unwind` and a `JobCapture`. Every write to
//!   contacts.json is a store job, so the app never races itself on it;
//! - the poller: watches the profile's files and asks raven-node for its
//!   Status and outbox ([`Cadence`]). It never sends OutboxKick. It also
//!   tells the App when to read the friends' horizons again (the store
//!   worker reads them), and, with each Status, whether this computer is on
//!   any network when that changed.
//!
//! Each holds a [`ThreadGuard`], so the UI hears when one ends that should
//! have kept running.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use raven_core::ipc::{IpcRequest, IpcResponse, OutboxItem};

use super::app::{
    self, Cmd, FriendChange, JobName, JobResult, Key, LockSettingsView, Masked, Msg, NewIdentity,
    NodeJob, PasteVia, SendJob, StoreJob,
};
use super::controller::{Captured, Controller, Created};
#[cfg(all(test, unix))]
use super::controller::{SendResult, NO_IDENTITY};
use super::node::{self, Probe};
use super::stdio::{self, JobCapture, StderrRedirect};
#[cfg(test)]
use super::testkit;
use super::{bridge, errors, hidden, read_marks, term};

/// Thread names in [`Msg::ThreadDied`].
pub(super) const INPUT_THREAD: &str = "input";
pub(super) const SIGNAL_THREAD: &str = "signal";
pub(super) const STDERR_THREAD: &str = "stderr reader";
pub(super) const STORE_THREAD: &str = "store worker";
pub(super) const SEND_THREAD: &str = "send worker";
pub(super) const NODE_THREAD: &str = "node worker";
pub(super) const POLL_THREAD: &str = "poller";

/// How long the input thread waits for an event before it checks the
/// terminal size and the pause flag again.
const INPUT_POLL: Duration = Duration::from_millis(100);
/// Text keys closer together than this belong to one burst: nobody types
/// that fast, but a paste arrives that way.
const BURST_GAP: Duration = Duration::from_millis(10);
/// A burst of this many text keys is a paste.
const BURST_MIN_KEYS: usize = 3;
/// An Enter this soon after another text key is a pasted line break.
const PASTED_ENTER_GAP: Duration = Duration::from_millis(30);
/// Events read into one burst at most; a longer paste goes on in the next.
const MAX_BURST_EVENTS: usize = 4096;
/// A Windows key release this long after every press is an Alt+numpad code.
const ALT_CODE_WINDOW: Duration = Duration::from_secs(1);
/// How long `InputHandle::pause` waits for the thread to stop reading.
const PAUSE_WAIT: Duration = Duration::from_secs(1);
/// Bytes of one stderr line that are kept; the rest of the line is dropped.
const STDERR_LINE_CAP: usize = 4 * 1024;
/// How long the UI has to leave the screen itself after a signal, before
/// the signal thread restores the terminal and exits.
const SIGNAL_GRACE: Duration = Duration::from_secs(1);
/// How often a deferred signal looks at the mode again.
const SIGNAL_RECHECK: Duration = Duration::from_millis(50);
/// How long `start_signal_thread` waits for the handlers to be in place.
const SIGNAL_READY_WAIT: Duration = Duration::from_secs(2);
/// The start of a sync sentinel line on stderr: the stderr reader notes it
/// and drops it.
const SYNC_PREFIX: &str = "RAVEN_TUI_SYNC ";
/// The words of a Keychain wait on stderr: raven-core's watchdog in this
/// process (macos_keychain.rs), and ext.rs's note that raven-node waits
/// (`keychain_wait_notice`). testkit checks both files still say them.
pub(super) const WATCHDOG_MARK: &str = "still waiting for macOS Keychain access (";
pub(super) const SERVICE_WAIT_MARK: &str = "is waiting for macOS Keychain access to ";

// ── thread guard ─────────────────────────────────────────────────────────────

/// Held by every thread beside the UI thread. Dropped without
/// [`ThreadGuard::finish`] (the thread unwound, or returned when it should
/// not have), it sends `Msg::ThreadDied` with the thread's name.
pub(super) struct ThreadGuard {
    name: &'static str,
    tx: Sender<Msg>,
    finished: bool,
}

impl ThreadGuard {
    pub(super) fn new(name: &'static str, tx: Sender<Msg>) -> ThreadGuard {
        ThreadGuard {
            name,
            tx,
            finished: false,
        }
    }

    /// The thread ends as planned: the UI is told nothing.
    pub(super) fn finish(mut self) {
        self.finished = true;
    }
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        if !self.finished {
            // The UI may be gone already; then nobody needs telling.
            let _ = self.tx.send(Msg::ThreadDied(self.name));
        }
    }
}

/// Locks `mutex`, carrying on after a panic elsewhere: the flags it guards
/// are valid after any partial update.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ── input ────────────────────────────────────────────────────────────────────

/// The UI thread's hold on the input thread.
pub(super) struct InputHandle {
    gate: Arc<InputGate>,
}

impl InputHandle {
    /// Stops the input thread from reading the terminal, so something else
    /// can (a plain-terminal prompt, the shell after exit). True once the
    /// thread has said it stopped, or has ended; false if it did not answer
    /// within a second.
    pub(super) fn pause(&self) -> bool {
        let mut state = lock(&self.gate.state);
        state.paused = true;
        state.acked = false;
        self.gate.changed.notify_all();
        let (state, _) = self
            .gate
            .changed
            .wait_timeout_while(state, PAUSE_WAIT, |s| !s.acked && !s.stopped)
            .unwrap_or_else(PoisonError::into_inner);
        state.acked || state.stopped
    }

    /// Lets the input thread read again after [`InputHandle::pause`].
    pub(super) fn resume(&self) {
        let mut state = lock(&self.gate.state);
        state.paused = false;
        state.acked = false;
        self.gate.changed.notify_all();
    }
}

/// The pause flag, its acknowledgement and whether the thread has ended.
#[derive(Default)]
struct InputGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    paused: bool,
    /// The input thread has seen `paused` and stopped reading.
    acked: bool,
    /// The input thread has ended: it will never acknowledge.
    stopped: bool,
}

impl InputGate {
    /// Called by the input thread between reads: while paused, it says so
    /// and waits to be resumed.
    fn wait_while_paused(&self) {
        let mut state = lock(&self.state);
        while state.paused {
            if !state.acked {
                state.acked = true;
                self.changed.notify_all();
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// Marks the input thread ended when dropped, however it ends.
struct MarkStopped(Arc<InputGate>);

impl Drop for MarkStopped {
    fn drop(&mut self) {
        lock(&self.0.state).stopped = true;
        self.0.changed.notify_all();
    }
}

/// Starts the input thread. `size` is the terminal size the app starts with,
/// so the size poll reports only changes.
pub(super) fn spawn_input(tx: Sender<Msg>, size: (u16, u16)) -> io::Result<InputHandle> {
    let gate = Arc::new(InputGate::default());
    let thread_gate = Arc::clone(&gate);
    thread::Builder::new()
        .name("raven-tui-input".into())
        .spawn(move || {
            let _stopped = MarkStopped(Arc::clone(&thread_gate));
            let died = ThreadGuard::new(INPUT_THREAD, tx.clone());
            // A read error ends the thread without `finish`: with no keys
            // coming, the UI restores the terminal and exits.
            if read_input(&thread_gate, &tx, size).is_ok() {
                died.finish();
            }
        })?;
    Ok(InputHandle { gate })
}

/// The input loop. Ok when the UI has gone (its receiver dropped).
fn read_input(gate: &InputGate, tx: &Sender<Msg>, size: (u16, u16)) -> io::Result<()> {
    let mut keys = KeyFilter::new(cfg!(windows));
    let mut burst = Burst::default();
    let mut last_size = Some(size);
    loop {
        gate.wait_while_paused();
        if !event::poll(INPUT_POLL)? {
            // Windows reports no resize without mouse capture, which the app
            // never turns on: look at the size on every idle poll instead.
            if let Some((cols, rows)) = size_change(&mut last_size, crossterm::terminal::size()) {
                if tx.send(Msg::Resize { cols, rows }).is_err() {
                    return Ok(());
                }
            }
            continue;
        }
        let mut batch = Vec::new();
        push_event(&mut batch, &mut keys, event::read()?);
        // A text key starts a burst when more input is already waiting, or
        // when it follows the last text key closely.
        let starts_burst = match batch.last() {
            Some((at, ev)) if is_text(ev) => event::poll(Duration::ZERO)? || burst.continues(*at),
            _ => false,
        };
        if starts_burst {
            while batch.len() < MAX_BURST_EVENTS && event::poll(BURST_GAP)? {
                push_event(&mut batch, &mut keys, event::read()?);
            }
        }
        // An Enter right after text keys is a pasted line break only when
        // more text follows it: wait out the gap a pasted Enter keeps. With
        // nothing after it, it is the user's Enter (field test E3: Enter
        // sent right after fast text, as tmux sends it, did not send).
        let mut settled = false;
        while batch.len() < MAX_BURST_EVENTS && ends_in_quick_enter(&batch, &burst) {
            let left = batch.last().map_or(Duration::ZERO, |(at, _)| {
                PASTED_ENTER_GAP.saturating_sub(at.elapsed())
            });
            if !event::poll(left)? {
                settled = true;
                break;
            }
            push_event(&mut batch, &mut keys, event::read()?);
            while batch.len() < MAX_BURST_EVENTS && event::poll(BURST_GAP)? {
                push_event(&mut batch, &mut keys, event::read()?);
            }
        }
        for msg in coalesce_settled(&batch, &mut burst, settled) {
            if let Msg::Resize { cols, rows } = msg {
                last_size = Some((cols, rows));
            }
            if tx.send(msg).is_err() {
                return Ok(());
            }
        }
    }
}

/// Adds `event` to `batch`, stamped now, if the key filter keeps it.
fn push_event(batch: &mut Vec<(Instant, Event)>, keys: &mut KeyFilter, event: Event) {
    let at = Instant::now();
    if let Some(event) = keys.keep(event, at) {
        batch.push((at, event));
    }
}

/// The new size when `now` differs from the last one seen. A failed read
/// changes nothing.
pub(super) fn size_change(
    last: &mut Option<(u16, u16)>,
    now: io::Result<(u16, u16)>,
) -> Option<(u16, u16)> {
    let now = now.ok()?;
    if *last == Some(now) {
        return None;
    }
    *last = Some(now);
    Some(now)
}

/// Which key events reach the app, and in what form:
///
/// - presses only. On Windows a release of a character key is kept too when
///   every character key pressed within the last second has been released
///   already: Alt+numpad codes arrive only as the Alt key's release, with no
///   press (crossterm windows/parse.rs). It becomes a press of that character;
/// - a character typed with Ctrl+Alt that is not an ASCII letter is AltGr
///   (`@`, `{`, `€` on many layouts): plain text, never a shortcut.
pub(super) struct KeyFilter {
    windows: bool,
    /// When each character key that has not been released yet was pressed.
    held: VecDeque<Instant>,
}

impl KeyFilter {
    pub(super) fn new(windows: bool) -> KeyFilter {
        KeyFilter {
            windows,
            held: VecDeque::new(),
        }
    }

    /// `event` as the app should see it, or None to drop it.
    pub(super) fn keep(&mut self, event: Event, at: Instant) -> Option<Event> {
        let Event::Key(key) = event else {
            return Some(event);
        };
        let char_key = matches!(key.code, KeyCode::Char(_));
        match key.kind {
            KeyEventKind::Press => {
                if self.windows && char_key {
                    self.held.push_back(at);
                }
                Some(Event::Key(altgr_as_text(key)))
            }
            KeyEventKind::Release if self.windows && char_key => {
                while self.held.front().is_some_and(|pressed| {
                    at.saturating_duration_since(*pressed) >= ALT_CODE_WINDOW
                }) {
                    self.held.pop_front();
                }
                // Counted, not matched by character: Shift or AltGr let go
                // first changes the character the release reports.
                if self.held.pop_front().is_some() {
                    return None;
                }
                let mut code = key;
                code.kind = KeyEventKind::Press;
                code.modifiers
                    .remove(KeyModifiers::CONTROL | KeyModifiers::ALT);
                Some(Event::Key(code))
            }
            KeyEventKind::Release | KeyEventKind::Repeat => None,
        }
    }
}

/// `key` with Ctrl and Alt taken off when they are AltGr.
fn altgr_as_text(mut key: KeyEvent) -> KeyEvent {
    let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
    if let KeyCode::Char(c) = key.code {
        if key.modifiers.contains(altgr) && !c.is_ascii_alphabetic() {
            key.modifiers.remove(altgr);
        }
    }
    key
}

/// Text keys: characters without Ctrl or Alt, Enter and Tab. Only these
/// join a burst; arrows, Esc and Ctrl or Alt keys never do, so a mouse wheel
/// the terminal turns into arrow keys stays arrows.
fn is_text(event: &Event) -> bool {
    let Event::Key(key) = event else {
        return false;
    };
    !key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char(_) | KeyCode::Enter | KeyCode::Tab)
}

/// The text a text key stands for in a paste: Enter is a line break and Tab
/// a space.
fn text_char(event: &Event) -> Option<char> {
    match event {
        Event::Key(key) => match key.code {
            KeyCode::Char(c) => Some(c),
            KeyCode::Enter => Some('\n'),
            KeyCode::Tab => Some(' '),
            _ => None,
        },
        _ => None,
    }
}

/// What [`coalesce`] carries from one batch to the next.
#[derive(Debug, Default)]
pub(super) struct Burst {
    /// When the last text key arrived.
    last_text: Option<Instant>,
    /// Text keys in the burst that key belongs to.
    keys: usize,
}

impl Burst {
    /// Whether a text key arriving `at` continues the last burst.
    fn continues(&self, at: Instant) -> bool {
        self.last_text
            .is_some_and(|last| at.saturating_duration_since(last) < BURST_GAP)
    }
}

/// Whether `batch` ends in an Enter that came less than
/// [`PASTED_ENTER_GAP`] after another text key (in the batch, or the one
/// `burst` ended with): a pasted line break if more text follows, the
/// user's Enter if nothing does.
fn ends_in_quick_enter(batch: &[(Instant, Event)], burst: &Burst) -> bool {
    let Some(((at, last), before)) = batch.split_last() else {
        return false;
    };
    if !is_enter(last) {
        return false;
    }
    let previous = before
        .iter()
        .rev()
        .find(|(_, event)| is_text(event))
        .map(|(at, _)| *at)
        .or(burst.last_text);
    previous.is_some_and(|previous| at.saturating_duration_since(previous) < PASTED_ENTER_GAP)
}

/// An Enter that is a text key (no Ctrl or Alt).
fn is_enter(event: &Event) -> bool {
    is_text(event) && matches!(event, Event::Key(key) if key.code == KeyCode::Enter)
}

/// [`coalesce_settled`] for a batch that is not known to end in silence.
#[cfg(test)]
pub(super) fn coalesce(events: &[(Instant, Event)], burst: &mut Burst) -> Vec<Msg> {
    coalesce_settled(events, burst, false)
}

/// [`coalesce_inner`], except that when `settled` (nothing came for
/// [`PASTED_ENTER_GAP`] after it) a final Enter is the user's Enter: it
/// sends or confirms, after the text before it, however fast that came.
pub(super) fn coalesce_settled(
    events: &[(Instant, Event)],
    burst: &mut Burst,
    settled: bool,
) -> Vec<Msg> {
    match events.split_last() {
        Some(((at, last @ Event::Key(key)), before)) if settled && is_enter(last) => {
            let mut out = coalesce_inner(before, burst);
            out.push(Msg::Key(Key::Event(*key)));
            burst.last_text = Some(*at);
            burst.keys = 0;
            out
        }
        _ => coalesce_inner(events, burst),
    }
}

/// Turns a batch of events, each stamped with when it was read, into
/// messages:
///
/// - text keys less than [`BURST_GAP`] apart form a burst. A burst of
///   [`BURST_MIN_KEYS`] or more, counting keys the previous batch ended
///   with, is a paste: each stretch of its text keys becomes one
///   `Msg::Paste { via: Keystrokes }`, Enter a line break and Tab a space;
/// - other keys pass one by one, in order; an Enter less than
///   [`PASTED_ENTER_GAP`] after another text key becomes `Key::PastedEnter`;
/// - a bracketed paste becomes `Msg::Paste { via: Bracketed }` and a resize
///   `Msg::Resize`. Focus and mouse events are never turned on, and dropped.
fn coalesce_inner(events: &[(Instant, Event)], burst: &mut Burst) -> Vec<Msg> {
    // First the bursts: which one each text key belongs to, and their sizes.
    // Burst 0 is the one the previous batch ended in.
    let mut sizes = vec![burst.keys];
    let mut current = 0;
    let mut last = burst.last_text;
    let member: Vec<Option<usize>> = events
        .iter()
        .map(|(at, event)| {
            if !is_text(event) {
                return None;
            }
            let joins = last.is_some_and(|last| at.saturating_duration_since(last) < BURST_GAP);
            if !joins {
                sizes.push(0);
                current = sizes.len() - 1;
            }
            sizes[current] += 1;
            last = Some(*at);
            Some(current)
        })
        .collect();

    let mut out = Vec::new();
    let mut pasted = String::new();
    let mut previous_text = burst.last_text;
    for ((at, event), member) in events.iter().zip(&member) {
        match member {
            Some(b) if sizes[*b] >= BURST_MIN_KEYS => pasted.extend(text_char(event)),
            _ => {
                flush_paste(&mut pasted, &mut out);
                let msg = match event {
                    Event::Key(key)
                        if member.is_some()
                            && key.code == KeyCode::Enter
                            && previous_text.is_some_and(|before| {
                                at.saturating_duration_since(before) < PASTED_ENTER_GAP
                            }) =>
                    {
                        Msg::Key(Key::PastedEnter)
                    }
                    Event::Key(key) => Msg::Key(Key::Event(*key)),
                    Event::Paste(text) => Msg::Paste {
                        text: text.clone(),
                        via: PasteVia::Bracketed,
                    },
                    Event::Resize(cols, rows) => Msg::Resize {
                        cols: *cols,
                        rows: *rows,
                    },
                    Event::FocusGained | Event::FocusLost | Event::Mouse(_) => continue,
                };
                out.push(msg);
            }
        }
        if member.is_some() {
            previous_text = Some(*at);
        }
    }
    flush_paste(&mut pasted, &mut out);
    burst.last_text = last;
    burst.keys = sizes[current];
    out
}

fn flush_paste(pasted: &mut String, out: &mut Vec<Msg>) {
    if !pasted.is_empty() {
        out.push(Msg::Paste {
            text: std::mem::take(pasted),
            via: PasteVia::Keystrokes,
        });
    }
}

// ── stderr reader ────────────────────────────────────────────────────────────

/// Points stderr into a pipe and starts the thread that drains it: from here
/// until the redirect is disarmed, stderr lines go to the ring and to the UI
/// as `Msg::Stderr`.
pub(super) fn capture_stderr(tx: Sender<Msg>) -> io::Result<StderrRedirect> {
    let (redirect, pipe) = StderrRedirect::arm()?;
    READER_RUNNING.store(true, Ordering::Release);
    let spawned = thread::Builder::new()
        .name("raven-tui-stderr".into())
        .spawn(move || {
            let died = ThreadGuard::new(STDERR_THREAD, tx.clone());
            let drained = drain_stderr(pipe, &tx);
            READER_RUNNING.store(false, Ordering::Release);
            if drained {
                died.finish();
            }
        });
    if let Err(e) = spawned {
        READER_RUNNING.store(false, Ordering::Release);
        // Nobody would read the pipe: put stderr back before it fills.
        let _ = redirect.disarm();
        return Err(e);
    }
    Ok(redirect)
}

/// Reads `pipe` to its end: true when its write end closed (the redirect was
/// disarmed). On a read error it points stderr at the null device first, so
/// no writer ever blocks on a full pipe, and returns false.
///
/// Each chunk is handled inside `catch_unwind`: one bad chunk loses its own
/// lines, never the reader. A sync sentinel is noted ([`sync_stderr`]) and
/// kept out of the ring.
fn drain_stderr(mut pipe: impl Read, tx: &Sender<Msg>) -> bool {
    let mut lines = LineSplitter::default();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match pipe.read(&mut chunk) {
            Ok(0) => return true,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = stdio::quiet_stderr();
                return false;
            }
        };
        let bytes = &chunk[..n];
        let handled = panic::catch_unwind(AssertUnwindSafe(|| {
            stdio::pass_through(bytes);
            for line in lines.push(bytes) {
                if let Some(n) = sync_number(&line) {
                    note_sync(n, stdio::ring_next_seq());
                    continue;
                }
                stdio::ring_push_line(&line);
                // The UI may be gone; the pipe is still drained.
                let _ = tx.send(Msg::Stderr(line));
            }
        }));
        if handled.is_err() {
            lines = LineSplitter::default();
        }
    }
}

/// Cuts stderr bytes into lines. A line longer than [`STDERR_LINE_CAP`]
/// keeps its start; a CR before the LF is dropped.
#[derive(Default)]
struct LineSplitter {
    partial: Vec<u8>,
}

impl LineSplitter {
    /// The lines that `bytes` completes.
    fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut lines = Vec::new();
        for &byte in bytes {
            if byte == b'\n' {
                if self.partial.last() == Some(&b'\r') {
                    self.partial.pop();
                }
                lines.push(String::from_utf8_lossy(&self.partial).into_owned());
                self.partial.clear();
            } else if self.partial.len() < STDERR_LINE_CAP {
                self.partial.push(byte);
            }
        }
        lines
    }
}

/// The stderr reader runs: a sync sentinel written now will be seen.
static READER_RUNNING: AtomicBool = AtomicBool::new(false);
/// The number of the next sync sentinel.
static NEXT_SYNC: AtomicU64 = AtomicU64::new(1);
/// The last sentinel the reader reached, and the ring's next sequence number
/// at that moment.
static SYNCED: Mutex<(u64, u64)> = Mutex::new((0, 0));
static SYNCED_CHANGED: Condvar = Condvar::new();

/// Writes a sync sentinel to stderr, then waits up to `timeout` for the
/// stderr reader to reach it. Some(the ring's next sequence number when it
/// did): every line written to stderr before this call is in the ring below
/// it. None when no reader runs, or it took too long.
pub(super) fn sync_stderr(timeout: Duration) -> Option<u64> {
    if !READER_RUNNING.load(Ordering::Acquire) {
        return None;
    }
    let n = NEXT_SYNC.fetch_add(1, Ordering::Relaxed);
    // One write: the line can't be split by another thread's.
    let _ = io::stderr().write_all(format!("{SYNC_PREFIX}{n}\n").as_bytes());
    wait_for_sync(n, timeout)
}

/// Waits until the reader has reached sentinel `n`.
fn wait_for_sync(n: u64, timeout: Duration) -> Option<u64> {
    let synced = lock(&SYNCED);
    let (synced, _) = SYNCED_CHANGED
        .wait_timeout_while(synced, timeout, |(last, _)| *last < n)
        .unwrap_or_else(PoisonError::into_inner);
    (synced.0 >= n).then_some(synced.1)
}

/// The reader reached sentinel `n` with the ring at `ring_seq`.
fn note_sync(n: u64, ring_seq: u64) {
    let mut synced = lock(&SYNCED);
    if n > synced.0 {
        *synced = (n, ring_seq);
    }
    SYNCED_CHANGED.notify_all();
}

/// The number of a sync sentinel line.
fn sync_number(line: &str) -> Option<u64> {
    line.strip_prefix(SYNC_PREFIX)?.trim().parse().ok()
}

/// A Keychain wait seen on stderr: KC explains it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KeychainWait {
    /// What is being read, in raven-core's plain words.
    pub(super) item: &'static str,
    /// raven-node waits, not this process.
    pub(super) service: bool,
}

/// The Keychain wait a stderr line reports: raven-core's watchdog line
/// (`still waiting for macOS Keychain access (<item>) after 3s.`) or ext.rs's
/// note that raven-node waits (`… is waiting for macOS Keychain access to
/// <item>.`). Only the items raven-core names are shown; anything else in
/// that place is 'a saved secret'.
pub(super) fn keychain_wait(line: &str) -> Option<KeychainWait> {
    let known = |text: &str| {
        bridge::KEYCHAIN_ITEMS
            .iter()
            .find(|item| **item == text.trim())
            .copied()
            .unwrap_or(bridge::UNKNOWN_KEYCHAIN_ITEM)
    };
    if let Some(at) = line.find(WATCHDOG_MARK) {
        let rest = &line[at + WATCHDOG_MARK.len()..];
        let item = rest.split(')').next().unwrap_or_default();
        return Some(KeychainWait {
            item: known(item),
            service: false,
        });
    }
    let at = line.find(SERVICE_WAIT_MARK)?;
    let rest = line[at + SERVICE_WAIT_MARK.len()..].trim_end();
    Some(KeychainWait {
        item: known(rest.strip_suffix('.').unwrap_or(rest)),
        service: true,
    })
}

// ── signals ──────────────────────────────────────────────────────────────────

/// What the signal thread does with a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignalMode {
    /// The full screen is up: the UI leaves it, or the signal thread does.
    Tui,
    /// A plain-terminal prompt runs (the vault passphrase while the identity
    /// is created): wait until it is done.
    Suspended,
    /// The classic menu runs in cooked mode: there is nothing to restore.
    Classic,
}

impl SignalMode {
    const fn to_u8(self) -> u8 {
        match self {
            SignalMode::Tui => 0,
            SignalMode::Suspended => 1,
            SignalMode::Classic => 2,
        }
    }

    const fn from_u8(value: u8) -> SignalMode {
        match value {
            1 => SignalMode::Suspended,
            2 => SignalMode::Classic,
            _ => SignalMode::Tui,
        }
    }
}

static SIGNAL_MODE: AtomicU8 = AtomicU8::new(SignalMode::Tui.to_u8());
/// Open [`Critical`] sections: while any is open no signal ends the process.
static CRITICAL: AtomicUsize = AtomicUsize::new(0);
/// The first signal received, as [`OsSignal::to_u8`]; 0 before any.
static RECEIVED: AtomicU8 = AtomicU8::new(0);

pub(super) fn set_signal_mode(mode: SignalMode) {
    SIGNAL_MODE.store(mode.to_u8(), Ordering::Release);
}

fn signal_mode() -> SignalMode {
    SignalMode::from_u8(SIGNAL_MODE.load(Ordering::Acquire))
}

/// The first signal this process received, if any: a failed draw after a
/// hang-up exits with 129 and prints nothing.
pub(super) fn received_signal() -> Option<OsSignal> {
    OsSignal::from_u8(RECEIVED.load(Ordering::Acquire))
}

/// Held while identity creation or a contacts save runs: a signal then
/// waits, so a profile is never left half-written.
#[must_use = "the section ends when this is dropped"]
pub(super) struct Critical(());

impl Critical {
    pub(super) fn enter() -> Critical {
        CRITICAL.fetch_add(1, Ordering::AcqRel);
        Critical(())
    }
}

impl Drop for Critical {
    fn drop(&mut self) {
        CRITICAL.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Waits until no [`Critical`] section is open, or `limit` has passed: true
/// when none is. The UI thread calls it before the process ends, so a job
/// still writing the identity or contacts.json finishes first.
pub(super) fn wait_for_critical(limit: Duration) -> bool {
    let until = Instant::now() + limit;
    while CRITICAL.load(Ordering::Acquire) > 0 {
        if Instant::now() >= until {
            return false;
        }
        thread::sleep(SIGNAL_RECHECK);
    }
    true
}

/// The signals the app handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OsSignal {
    /// SIGTERM.
    Terminate,
    /// SIGHUP: the terminal has gone.
    HangUp,
    /// Windows: the console window is closing.
    ConsoleClosed,
    /// Windows: Ctrl+Break.
    Break,
}

impl OsSignal {
    /// 128 + the signal's number on Unix, as a shell reports a process the
    /// signal ended; 1 on Windows.
    pub(super) fn exit_code(self) -> i32 {
        match self {
            OsSignal::Terminate => 128 + 15,
            OsSignal::HangUp => 128 + 1,
            OsSignal::ConsoleClosed | OsSignal::Break => 1,
        }
    }

    /// The terminal has gone: nothing more can be printed or asked there.
    pub(super) fn hung_up(self) -> bool {
        matches!(self, OsSignal::HangUp | OsSignal::ConsoleClosed)
    }

    const fn to_u8(self) -> u8 {
        match self {
            OsSignal::Terminate => 1,
            OsSignal::HangUp => 2,
            OsSignal::ConsoleClosed => 3,
            OsSignal::Break => 4,
        }
    }

    const fn from_u8(value: u8) -> Option<OsSignal> {
        match value {
            1 => Some(OsSignal::Terminate),
            2 => Some(OsSignal::HangUp),
            3 => Some(OsSignal::ConsoleClosed),
            4 => Some(OsSignal::Break),
            _ => None,
        }
    }
}

/// The signal thread's next step for a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignalStep {
    /// Send `Msg::OsSignal`: the UI leaves the screen and exits itself.
    TellUi,
    /// Look again shortly.
    Wait,
    /// The UI did not exit in time: restore the terminal and exit here.
    RestoreAndExit,
    /// Exit at once: the terminal is in cooked mode already.
    Exit,
}

/// The decision table, by mode:
///
/// - Classic: exit at once with 128 + n;
/// - Suspended: wait until the prompt is done (the vault's hidden input
///   restores the tty itself only if it finishes);
/// - Tui: tell the UI; if the process still runs a second later and no
///   critical section is open, restore the terminal and exit.
///
/// `told_ui`: how long ago the UI was told, None before.
pub(super) fn signal_step(
    mode: SignalMode,
    critical: usize,
    told_ui: Option<Duration>,
) -> SignalStep {
    match (mode, told_ui) {
        (SignalMode::Classic, _) => SignalStep::Exit,
        (SignalMode::Suspended, _) => SignalStep::Wait,
        (SignalMode::Tui, None) => SignalStep::TellUi,
        (SignalMode::Tui, Some(waited)) if waited < SIGNAL_GRACE || critical > 0 => {
            SignalStep::Wait
        }
        (SignalMode::Tui, Some(_)) => SignalStep::RestoreAndExit,
    }
}

/// Starts the signal thread, which lives as long as the process: tokio never
/// takes a signal handler back out (tokio signal/unix.rs), so once it is in,
/// only this thread can end the process on a signal. Returns once the
/// handlers are in place.
pub(super) fn start_signal_thread(tx: Sender<Msg>) -> io::Result<()> {
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::Builder::new()
        .name("raven-tui-signal".into())
        .spawn(move || {
            let _died = ThreadGuard::new(SIGNAL_THREAD, tx.clone());
            if let Err(e) = watch_signals(&tx, &ready_tx) {
                let _ = ready_tx.send(Err(e));
            }
        })?;
    match ready_rx.recv_timeout(SIGNAL_READY_WAIT) {
        Ok(ready) => ready,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the signal handlers did not start",
        )),
    }
}

/// Runs the signal loop; returns only when the handlers cannot be set up.
fn watch_signals(tx: &Sender<Msg>, ready: &Sender<io::Result<()>>) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut signals = Signals::new()?;
        let _ = ready.send(Ok(()));
        loop {
            let Some(signal) = signals.next().await else {
                return Err(io::Error::other("the signal streams ended"));
            };
            let _ =
                RECEIVED.compare_exchange(0, signal.to_u8(), Ordering::AcqRel, Ordering::Acquire);
            handle_signal(signal, tx).await;
        }
    })
}

/// Carries out the decision table for `signal` until the process ends.
async fn handle_signal(signal: OsSignal, tx: &Sender<Msg>) {
    let mut told: Option<Instant> = None;
    // The UI's receiver is gone: nobody else will exit, so no grace period.
    let mut ui_gone = false;
    loop {
        let waited = if ui_gone {
            Some(SIGNAL_GRACE)
        } else {
            told.map(|at| at.elapsed())
        };
        match signal_step(signal_mode(), CRITICAL.load(Ordering::Acquire), waited) {
            SignalStep::TellUi => {
                ui_gone = tx.send(Msg::OsSignal(signal)).is_err();
                told = Some(Instant::now());
            }
            SignalStep::Wait => tokio::time::sleep(SIGNAL_RECHECK).await,
            SignalStep::RestoreAndExit => {
                term::restore();
                let _ = stdio::restore_stderr();
                std::process::exit(signal.exit_code());
            }
            SignalStep::Exit => std::process::exit(signal.exit_code()),
        }
    }
}

/// SIGTERM and SIGHUP.
#[cfg(unix)]
struct Signals {
    terminate: tokio::signal::unix::Signal,
    hang_up: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl Signals {
    fn new() -> io::Result<Signals> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Signals {
            terminate: signal(SignalKind::terminate())?,
            hang_up: signal(SignalKind::hangup())?,
        })
    }

    /// The next signal; None once both streams have ended.
    async fn next(&mut self) -> Option<OsSignal> {
        tokio::select! {
            Some(()) = self.terminate.recv() => Some(OsSignal::Terminate),
            Some(()) = self.hang_up.recv() => Some(OsSignal::HangUp),
            else => None,
        }
    }
}

/// The console closing, and Ctrl+Break. Ctrl+C is a key in raw mode.
#[cfg(windows)]
struct Signals {
    close: tokio::signal::windows::CtrlClose,
    brk: tokio::signal::windows::CtrlBreak,
}

#[cfg(windows)]
impl Signals {
    fn new() -> io::Result<Signals> {
        Ok(Signals {
            close: tokio::signal::windows::ctrl_close()?,
            brk: tokio::signal::windows::ctrl_break()?,
        })
    }

    /// The next signal; None once both streams have ended.
    async fn next(&mut self) -> Option<OsSignal> {
        tokio::select! {
            Some(()) = self.close.recv() => Some(OsSignal::ConsoleClosed),
            Some(()) = self.brk.recv() => Some(OsSignal::Break),
            else => None,
        }
    }
}

// ── workers ──────────────────────────────────────────────────────────────────

/// One job, and the name its result goes by if it panics.
type Job = (JobName, Box<dyn FnOnce() -> JobResult + Send>);

/// A thread that runs jobs one at a time, first in first out, each through
/// [`run_job`]; every result goes to the UI as `Msg::Job`.
pub(super) struct Worker {
    jobs: Sender<Job>,
    thread: JoinHandle<()>,
}

impl Worker {
    pub(super) fn spawn(name: &'static str, tx: Sender<Msg>) -> io::Result<Worker> {
        let (jobs, queue) = mpsc::channel::<Job>();
        let thread = thread::Builder::new()
            .name(format!("raven-tui-{}", name.replace(' ', "-")))
            .spawn(move || {
                let died = ThreadGuard::new(name, tx.clone());
                for (job_name, job) in queue {
                    if tx.send(Msg::Job(run_job(job_name, job))).is_err() {
                        // The UI has gone: nobody wants the rest.
                        break;
                    }
                }
                died.finish();
            })?;
        Ok(Worker { jobs, thread })
    }

    /// Queues `job`: it runs after every job queued before it.
    pub(super) fn submit(&self, name: JobName, job: impl FnOnce() -> JobResult + Send + 'static) {
        // The thread ends only once the UI has: then nobody needs the result.
        let _ = self.jobs.send((name, Box::new(job)));
    }

    /// Takes no more jobs, and waits until the queued ones are done.
    pub(super) fn join(self) {
        drop(self.jobs);
        let _ = self.thread.join();
    }
}

/// Runs one job inside `catch_unwind`, so a panic becomes a failure the UI
/// can show, and with a `JobCapture`, so nothing it prints reaches the
/// screen. What it printed is kept only for a panic's Details: a job that
/// keeps its output captures it itself.
pub(super) fn run_job(name: JobName, job: impl FnOnce() -> JobResult) -> JobResult {
    let capture = JobCapture::start();
    let ran = panic::catch_unwind(AssertUnwindSafe(job));
    let captured = capture.finish();
    ran.unwrap_or_else(|panic| JobResult::Failed {
        job: name,
        plain: errors::explain_panic(&panic_text(&*panic), &captured),
    })
}

/// A panic's message.
fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic without a message".to_owned())
}

/// The workers and the poller, and the jobs the UI thread hands them.
pub(super) struct Hub {
    controller: Arc<Controller>,
    /// Identity, contacts and settings: every write to contacts.json.
    store: Worker,
    /// Sends, retries and cancels.
    send: Worker,
    /// Starting, checking and stopping raven-node.
    node: Worker,
    poller: Poller,
}

impl Hub {
    /// The workers and the poller, idle. The poller waits for
    /// `PollCtl::Start`, which the App sends once the identity exists.
    pub(super) fn start(controller: Arc<Controller>, tx: &Sender<Msg>) -> io::Result<Hub> {
        Ok(Hub {
            store: Worker::spawn(STORE_THREAD, tx.clone())?,
            send: Worker::spawn(SEND_THREAD, tx.clone())?,
            node: Worker::spawn(NODE_THREAD, tx.clone())?,
            poller: Poller::spawn(controller.data_dir().to_path_buf(), tx.clone())?,
            controller,
        })
    }

    /// Hands a job to its worker, or a word to the poller. The UI thread's
    /// own commands are not for here.
    pub(super) fn dispatch(&self, cmd: Cmd) {
        let controller = Arc::clone(&self.controller);
        match cmd {
            Cmd::Store(job) => self
                .store
                .submit(job.name(), move || store_job(&controller, job)),
            Cmd::Send(job) => self
                .send
                .submit(job.name(), move || send_job(&controller, job)),
            Cmd::Node(job) => self
                .node
                .submit(job.name(), move || node_job(&controller, job)),
            Cmd::Poll(ctl) => self.poller.tell(ctl),
            Cmd::Redraw
            | Cmd::Suspend(_)
            | Cmd::ApplyListenLoopback
            | Cmd::SwitchToClassic
            | Cmd::Peek(_)
            | Cmd::Unpeek
            | Cmd::Exit(_) => {}
        }
    }

    /// Stops the poller and waits until the workers have done what they
    /// were given: before the classic menu takes over the terminal.
    pub(super) fn shut_down(self) {
        self.poller.stop();
        for worker in [self.store, self.send, self.node] {
            worker.join();
        }
    }
}

/// A store job, run (tests run the App's jobs through it too).
pub(super) fn store_job(controller: &Controller, job: StoreJob) -> JobResult {
    match job {
        StoreJob::LoadContacts => {
            let (contacts, stamp) = controller.load_contacts_stamped();
            JobResult::Contacts { contacts, stamp }
        }
        StoreJob::LoadHistory => {
            let (history, stamp) = controller.load_history_stamped();
            JobResult::History { history, stamp }
        }
        StoreJob::LoadHorizons { peers } => JobResult::Horizons(controller.horizons(&peers)),
        StoreJob::SaveSettings(state) => JobResult::SettingsSaved(controller.save_settings(&state)),
        StoreJob::SaveReadMarks(state) => {
            JobResult::ReadMarksSaved(controller.save_read_marks(&state))
        }
        StoreJob::LoadReadMarks => JobResult::ReadMarks(controller.load_read_marks()),
        StoreJob::CheckVault => JobResult::VaultChecked {
            prompts: controller.creation_prompts(),
        },
        StoreJob::CreateIdentity => created(controller.create_identity()),
        StoreJob::SaveLearnedDial { pub_hex, dial } => {
            JobResult::LearnedDialSaved(controller.save_learned_dial(&pub_hex, &dial).result)
        }
        StoreJob::ShareCard { listen } => JobResult::Shared {
            share: controller.share(listen.as_deref()),
            listen,
        },
        StoreJob::UpdateAddresses(friend) => JobResult::AddressesUpdated {
            result: controller.update_addresses(&friend).result,
            pub_hex: friend.pub_hex,
        },
        StoreJob::SaveFriend {
            friend,
            name,
            verify,
        } => changed(
            FriendChange::Add,
            &friend.pub_hex,
            controller.save_friend(&friend, &name, &verify),
        ),
        StoreJob::VerifyExisting { pub_hex, typed_fp } => {
            // Verified: every open security notice about them is resolved
            // too (P6.31, as `raven contact verify` does), and the note says
            // how many.
            let done = controller.verify_existing(&pub_hex, &typed_fp);
            let notes = match done.result {
                Ok(()) => controller.resolved_notes(&pub_hex, &typed_fp),
                Err(_) => Vec::new(),
            };
            JobResult::FriendChanged {
                change: FriendChange::Verify,
                pub_hex,
                result: done.result,
                notes,
            }
        }
        StoreJob::RenameFriend { pub_hex, name } => changed(
            FriendChange::Rename,
            &pub_hex,
            controller.rename(&pub_hex, &name),
        ),
        StoreJob::SetFriendAddress { pub_hex, address } => changed(
            FriendChange::Address,
            &pub_hex,
            controller.set_lan_address(&pub_hex, &address),
        ),
        StoreJob::RemoveFriend { pub_hex } => {
            changed(FriendChange::Remove, &pub_hex, controller.remove(&pub_hex))
        }
        StoreJob::UnblockFriend { pub_hex } => changed(
            FriendChange::Unblock,
            &pub_hex,
            controller.unblock(&pub_hex),
        ),
        StoreJob::LoadPrivacy => JobResult::Privacy(controller.read_privacy()),
        StoreJob::SetChatKeep(keep) => JobResult::ChatKeepSaved {
            keep,
            result: controller.set_chat_keep(keep),
        },
        StoreJob::MarkNoticeShown(notice) => {
            controller.mark_notice_shown(notice);
            JobResult::NoticeMarked(notice)
        }
        StoreJob::DeleteChat { pub_hex } => JobResult::ChatDeleted {
            result: controller.delete_chat(&pub_hex).result,
            pub_hex,
        },
        StoreJob::ForgetAddress { pub_hex } => {
            // What could not be forgotten comes along (review D-lock-tui-8).
            let done = controller.forget_address(&pub_hex);
            let (result, notes) = match done.result {
                Ok(notes) => (Ok(()), notes),
                Err(why) => (Err(why), Vec::new()),
            };
            JobResult::FriendChanged {
                change: FriendChange::ForgetAddress,
                pub_hex,
                result,
                notes,
            }
        }
        StoreJob::ErasePlan => JobResult::ErasePlan(controller.erase_plan()),
        StoreJob::Erase => JobResult::Erased(controller.erase()),
        StoreJob::LoadSecurity => JobResult::Security(controller.read_security()),
        StoreJob::ResolveNotice { id } => JobResult::NoticeResolved(controller.resolve_notice(id)),
        StoreJob::SetSendHold { pub_hex, on } => JobResult::SendHoldSet {
            result: controller.set_send_hold(&pub_hex, on),
            pub_hex,
            on,
        },
        StoreJob::Recheck { pub_hex, typed } => JobResult::Rechecked {
            result: controller.resolve_on_match(&pub_hex, &typed),
            pub_hex,
        },
        StoreJob::AcceptOlderMethod { pub_hex, typed } => JobResult::OlderMethodAccepted {
            result: controller.accept_older_method(&pub_hex, &typed),
            pub_hex,
        },
        StoreJob::LoadGroups { open, refresh } => {
            JobResult::Groups(controller.groups_read(open, refresh))
        }
        StoreJob::MarkGroupRead { group } => JobResult::GroupMarked {
            result: controller.group_mark_read(&group),
            group,
        },
    }
}

/// A change to a friend's answer for the App. What it printed stays here:
/// the App says what happened in its own words.
fn changed(change: FriendChange, pub_hex: &str, done: Captured<()>) -> JobResult {
    JobResult::FriendChanged {
        change,
        pub_hex: pub_hex.to_owned(),
        result: done.result,
        notes: Vec::new(),
    }
}

/// A send worker job, run (the e2e test runs the App's sends through it too).
pub(super) fn send_job(controller: &Controller, job: SendJob) -> JobResult {
    match job {
        SendJob::Send {
            local_id,
            pub_hex,
            text,
        } => JobResult::Sent {
            local_id,
            outcome: controller.send(&pub_hex, &text),
        },
        SendJob::Retry { mid, peer } => {
            let done = controller.retry(&mid);
            JobResult::Retried {
                mid,
                peer,
                result: done.result,
                captured: done.captured,
            }
        }
        SendJob::Cancel { mid, peer } => {
            let done = controller.cancel(&mid);
            JobResult::Cancelled {
                mid,
                peer,
                result: done.result,
                captured: done.captured,
            }
        }
        SendJob::GroupSend {
            local_id,
            group,
            text,
        } => JobResult::GroupSent {
            local_id,
            done: controller.group_send(&group, &text),
        },
        SendJob::GroupChange(change) => JobResult::GroupChanged {
            done: controller.group_change(&change),
            change,
        },
    }
}

/// A creation's answer for the App: the identity's public half and the
/// prekey warning, or why it failed. The App saves its settings through the
/// controller, which holds the identity.
pub(super) fn created(created: Captured<Created>) -> JobResult {
    JobResult::Created {
        result: created.result.map(|created| NewIdentity {
            me: created.me,
            prekey_warning: created.prekey_warning,
        }),
        captured: created.captured,
    }
}

/// A node job, run.
fn node_job(controller: &Controller, job: NodeJob) -> JobResult {
    match job {
        NodeJob::Probe => JobResult::Probed(controller.probe_node()),
        NodeJob::Ensure => JobResult::Ensured(controller.ensure_node()),
        NodeJob::Stop {
            started_by_app,
            managed,
        } => JobResult::Stopped(controller.stop_node(started_by_app, managed)),
        NodeJob::Lock {
            started_by_app,
            own_item,
            managed,
        } => JobResult::Stopped(controller.lock_node(started_by_app, own_item, managed)),
        // Raven's own login item for this profile (PP.23); where this build
        // reads no login items, UXF.7's check.
        NodeJob::DetectManaged => match controller.login_item() {
            Ok(item) => JobResult::LoginItem(item),
            Err(_) => JobResult::Managed(node::login_service_for(controller.data_dir())),
        },
        NodeJob::VaultCheck => JobResult::Vault(controller.vault_check()),
        NodeJob::Unlock => JobResult::Unlocked(controller.unlock()),
        NodeJob::LanAddresses => JobResult::LanAddresses(bridge::lan_addresses_for_friends()),
        NodeJob::ServiceLog => JobResult::ServiceLog(controller.service_log_tail()),
        // Lock now v2 and the Raven passphrase (P6.40).
        NodeJob::LockV2 => JobResult::LockedV2(bridge::lock_node_v2(controller.data_dir())),
        NodeJob::UnlockV2(typed) => {
            let passphrase = typed.as_ref().map(Masked::secret);
            JobResult::UnlockedV2(bridge::unlock_node_v2(
                controller.data_dir(),
                passphrase.as_deref().map(|p| &p[..]),
            ))
        }
        NodeJob::Passphrase { op, current, new } => {
            let typed = app::typed_of(current.as_ref(), new.as_ref());
            JobResult::PassphraseChanged(bridge::change_passphrase(
                controller.data_dir(),
                op,
                &typed,
            ))
        }
        NodeJob::LockSettings => JobResult::LockSettings(LockSettingsView {
            offer: bridge::passphrase_offer(controller.data_dir()),
            sleep_lock: bridge::sleep_lock(controller.data_dir()),
        }),
        NodeJob::SetSleepLock(on) => {
            JobResult::SleepLockSaved(bridge::set_sleep_lock(controller.data_dir(), on))
        }
        // Raven updates (P6.47).
        NodeJob::LoadUpdates { full } => {
            JobResult::Updates(bridge::update_view(controller.data_dir(), full))
        }
        NodeJob::ApproveDownload { digest } => {
            JobResult::Updates(bridge::approve_download(controller.data_dir(), &digest))
        }
        NodeJob::InstallUpdate {
            serial,
            started_by_app,
        } => {
            let (result, after, started) =
                node::install_update(controller.data_dir(), serial, started_by_app);
            JobResult::UpdateInstalled {
                result,
                after,
                started,
            }
        }
    }
}

// ── poller ───────────────────────────────────────────────────────────────────

/// How often the profile's files are looked at (their size and time only).
pub(super) const FILES_EVERY: Duration = Duration::from_millis(500);
/// How often raven-node is asked for its Status, and while this app starts
/// it.
pub(super) const STATUS_EVERY: Duration = Duration::from_secs(2);
pub(super) const STATUS_STARTING_EVERY: Duration = Duration::from_secs(1);
/// How often its outbox is listed while a message is waiting, held or sent,
/// and otherwise.
pub(super) const OUTBOX_LIVE_EVERY: Duration = Duration::from_secs(5);
pub(super) const OUTBOX_IDLE_EVERY: Duration = Duration::from_secs(30);
/// How often the App is told to read again how long a message to each
/// friend could wait (the store worker reads it; the poller reads nothing).
pub(super) const HORIZONS_EVERY: Duration = Duration::from_secs(60);
/// When one friend's outbox is listed again after a send ended Waiting or
/// Sent.
pub(super) const BURST_AFTER: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(3)];
/// Windows: unanswered Status requests in a row before the poller stops.
pub(super) const MAX_TIMEOUTS: u32 = 3;
/// How long the poller sleeps before it is started.
const UNSTARTED_WAIT: Duration = Duration::from_secs(3600);
/// How long a Windows request may run in its own thread before it is given
/// up on (its own wait is [`node::PROBE_TIMEOUT`]).
const LANE_HOLD: Duration = Duration::from_secs(24 * 3600);

/// What the UI tells the poller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PollCtl {
    /// The identity exists: start watching and asking.
    Start,
    Hints(PollHints),
    /// A send to `peer` (hex) ended Waiting or Sent: list that friend's
    /// outbox at +1 s and +3 s.
    Burst {
        peer: String,
    },
    /// Ask for Status again after Windows' stop (R on NET).
    CheckAgain,
}

/// What the screen needs often or rarely.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PollHints {
    /// This app is starting raven-node: Status every second.
    pub(super) starting: bool,
    /// A message is waiting, held or sent and not confirmed: the outbox
    /// every 5 s.
    pub(super) live: bool,
    /// The service log is read: the node is starting, KC is up, the log
    /// view is open, or it runs without receiving (to tell why).
    pub(super) read_log: bool,
}

/// What the poller found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PollUpdate {
    Status(Probe),
    /// Windows: [`MAX_TIMEOUTS`] Status requests in a row went unanswered,
    /// so none is asked until `PollCtl::CheckAgain`.
    StatusStopped,
    /// The outbox, every friend's (`peer` None) or one friend's.
    Outbox {
        peer: Option<String>,
        items: Vec<OutboxItem>,
    },
    /// A watched file changed (or was seen for the first time).
    File {
        watched: Watched,
        stamp: FileStamp,
    },
    /// The service log written since the poller began reading it.
    ServiceLog(String),
    /// Time to read again how long a message to each friend could wait: the
    /// App hands the read to the store worker.
    HorizonsDue,
    /// Whether this computer is on any network changed
    /// (`bridge::on_any_network`; None: it can't be told).
    Network(Option<bool>),
    /// Windows: whose folder the running process `pid` serves, read once
    /// per process.
    NodeFolder {
        pid: u32,
        folder: node::NodeFolder,
    },
    /// How messages came and went, as raven-node remembers (asked when the
    /// chat history changed).
    Paths(node::Paths),
}

/// The files the poller watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Watched {
    Contacts,
    History,
    /// tui_state.json or tui_private.rms: the desktop app may have read a
    /// chat (read_marks.rs).
    ReadMarks,
    /// desktop_hidden.json: the desktop app deleted a message (hidden.rs).
    Hidden,
    /// groups.json (lab): a group message, a receipt or a roster came, or
    /// raven-node parked a copy. Watched only while groups are live.
    Groups,
}

/// A file's size and time of last change, or that it is missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct FileStamp(Option<(u64, SystemTime)>);

impl FileStamp {
    pub(super) fn of(path: &Path) -> FileStamp {
        FileStamp(std::fs::metadata(path).ok().map(|meta| {
            (
                meta.len(),
                meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            )
        }))
    }
}

/// Something the poller does now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PollTask {
    Files,
    Status,
    Horizons,
    Outbox(Option<String>),
}

/// How a Status went, for [`Cadence::status_seen`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StatusSeen {
    /// A node answered.
    Answered,
    /// No node, or one that answered nonsense.
    NoNode,
    /// The request was taken and not answered in time (or, on Windows, one
    /// is still out).
    TimedOut,
}

/// When the poller does what (pure: the time comes in):
///
/// - the files every 500 ms;
/// - Status every 2 s, every second while this app starts the node. On
///   Windows, after [`MAX_TIMEOUTS`] unanswered in a row, none until
///   [`Cadence::check_again`];
/// - the horizons at once, then every [`HORIZONS_EVERY`] (a word to the
///   App, whose store worker reads them);
/// - the outbox only while a node answers: at once when one does, then every
///   5 s while something is live and every 30 s otherwise; a friend's at +1 s
///   and +3 s after a send ([`Cadence::burst`]).
pub(super) struct Cadence {
    windows: bool,
    hints: PollHints,
    next_files: Instant,
    next_status: Instant,
    next_horizons: Instant,
    /// None while no node answers.
    next_outbox: Option<Instant>,
    bursts: Vec<(Instant, String)>,
    timeouts: u32,
    stopped: bool,
}

impl Cadence {
    /// Files, Status and the horizons are due at once.
    pub(super) fn new(windows: bool, now: Instant) -> Cadence {
        Cadence {
            windows,
            hints: PollHints::default(),
            next_files: now,
            next_status: now,
            next_horizons: now,
            next_outbox: None,
            bursts: Vec::new(),
            timeouts: 0,
            stopped: false,
        }
    }

    pub(super) fn set_hints(&mut self, hints: PollHints, now: Instant) {
        if hints.starting && !self.hints.starting {
            self.next_status = self.next_status.min(now + STATUS_STARTING_EVERY);
        }
        if hints.live && !self.hints.live {
            if let Some(next) = &mut self.next_outbox {
                *next = (*next).min(now + OUTBOX_LIVE_EVERY);
            }
        }
        self.hints = hints;
    }

    pub(super) fn burst(&mut self, peer: &str, now: Instant) {
        for after in BURST_AFTER {
            self.bursts.push((now + after, peer.to_owned()));
        }
    }

    pub(super) fn check_again(&mut self, now: Instant) {
        self.stopped = false;
        self.timeouts = 0;
        self.next_status = now;
    }

    /// Whether Windows' stop is in effect.
    #[cfg(test)]
    pub(super) fn stopped(&self) -> bool {
        self.stopped
    }

    /// What is due at `now`, each scheduled again. A friend's outbox due
    /// while no node answers is dropped.
    pub(super) fn due(&mut self, now: Instant) -> Vec<PollTask> {
        let mut tasks = Vec::new();
        if self.next_files <= now {
            tasks.push(PollTask::Files);
            self.next_files = now + FILES_EVERY;
        }
        if !self.stopped && self.next_status <= now {
            tasks.push(PollTask::Status);
            self.next_status = now + self.status_every();
        }
        if self.next_horizons <= now {
            tasks.push(PollTask::Horizons);
            self.next_horizons = now + HORIZONS_EVERY;
        }
        if self.next_outbox.is_some_and(|next| next <= now) {
            tasks.push(PollTask::Outbox(None));
            self.next_outbox = Some(now + self.outbox_every());
        }
        let answering = self.next_outbox.is_some();
        let (due, later): (Vec<_>, Vec<_>) = self.bursts.drain(..).partition(|(at, _)| *at <= now);
        self.bursts = later;
        if answering {
            tasks.extend(
                due.into_iter()
                    .map(|(_, peer)| PollTask::Outbox(Some(peer))),
            );
        }
        tasks
    }

    /// The next moment something is due.
    pub(super) fn next_due(&self) -> Instant {
        let mut next = self.next_files.min(self.next_horizons);
        if !self.stopped {
            next = next.min(self.next_status);
        }
        for at in self
            .next_outbox
            .iter()
            .chain(self.bursts.iter().map(|(at, _)| at))
        {
            next = next.min(*at);
        }
        next
    }

    /// How the last Status went. True when it made Windows' stop begin.
    pub(super) fn status_seen(&mut self, seen: StatusSeen, now: Instant) -> bool {
        match seen {
            StatusSeen::Answered => {
                self.timeouts = 0;
                self.next_outbox.get_or_insert(now);
            }
            StatusSeen::NoNode => {
                self.timeouts = 0;
                self.next_outbox = None;
            }
            StatusSeen::TimedOut => {
                self.next_outbox = None;
                self.timeouts += 1;
                if self.windows && self.timeouts >= MAX_TIMEOUTS && !self.stopped {
                    self.stopped = true;
                    return true;
                }
            }
        }
        false
    }

    fn status_every(&self) -> Duration {
        if self.hints.starting {
            STATUS_STARTING_EVERY
        } else {
            STATUS_EVERY
        }
    }

    fn outbox_every(&self) -> Duration {
        if self.hints.live {
            OUTBOX_LIVE_EVERY
        } else {
            OUTBOX_IDLE_EVERY
        }
    }
}

/// The poller thread, and how the UI talks to it.
pub(super) struct Poller {
    ctl: Sender<PollCtl>,
    thread: JoinHandle<()>,
}

impl Poller {
    /// Starts the thread, idle until `PollCtl::Start`.
    pub(super) fn spawn(data_dir: PathBuf, tx: Sender<Msg>) -> io::Result<Poller> {
        let (ctl, words) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("raven-tui-poller".into())
            .spawn(move || {
                let died = ThreadGuard::new(POLL_THREAD, tx.clone());
                poll(&data_dir, &words, &tx);
                died.finish();
            })?;
        Ok(Poller { ctl, thread })
    }

    pub(super) fn tell(&self, ctl: PollCtl) {
        // The thread ends only when the UI does.
        let _ = self.ctl.send(ctl);
    }

    /// Stops the thread and waits for it (a request in flight ends first).
    pub(super) fn stop(self) {
        drop(self.ctl);
        let _ = self.thread.join();
    }
}

/// The poller's loop: until the UI drops its end, or stops taking updates.
fn poll(data_dir: &Path, words: &Receiver<PollCtl>, tx: &Sender<Msg>) {
    let mut cadence: Option<Cadence> = None;
    let mut hints = PollHints::default();
    let mut files = FileWatch::default();
    let mut networks = NetWatch::default();
    let lanes = Lanes::default();
    // Windows: the process whose folder was read last (`node::folder_of`).
    let mut folder_read: Option<u32> = None;
    loop {
        let wait = cadence.as_ref().map_or(UNSTARTED_WAIT, |c| {
            c.next_due().saturating_duration_since(Instant::now())
        });
        match words.recv_timeout(wait) {
            Ok(word) => {
                if let PollCtl::Hints(new) = word {
                    files.read_log(new.read_log, data_dir);
                }
                hear(word, &mut cadence, &mut hints, Instant::now());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let Some(c) = cadence.as_mut() else {
            continue;
        };
        for task in c.due(Instant::now()) {
            let mut updates = Vec::new();
            match task {
                PollTask::Files => {
                    updates = files.look(data_dir);
                    // The history changed: how its new messages came or
                    // went (field test E3: the chat showed it for a few of
                    // yours only).
                    let history = updates.iter().any(|update| {
                        matches!(
                            update,
                            PollUpdate::File {
                                watched: Watched::History,
                                ..
                            }
                        )
                    });
                    if let Some(paths) = history.then(|| lanes.paths(data_dir)).flatten() {
                        updates.push(PollUpdate::Paths(paths));
                    }
                }
                PollTask::Status => {
                    let (probe, friends_here) = lanes.status(data_dir);
                    let seen = if probe.timed_out {
                        StatusSeen::TimedOut
                    } else if probe.running() {
                        StatusSeen::Answered
                    } else {
                        StatusSeen::NoNode
                    };
                    let stopped = c.status_seen(seen, Instant::now());
                    let pid = probe.pid.filter(|_| cfg!(windows) && probe.running());
                    updates.push(PollUpdate::Status(probe));
                    if let Some(pid) = pid.filter(|&pid| folder_read != Some(pid)) {
                        folder_read = Some(pid);
                        updates.push(PollUpdate::NodeFolder {
                            pid,
                            folder: node::folder_of(pid, data_dir),
                        });
                    }
                    if stopped {
                        updates.push(PollUpdate::StatusStopped);
                    }
                    let friends_here = networks.friends_here(friends_here);
                    updates.extend(networks.look(bridge::on_any_network(friends_here)));
                }
                PollTask::Horizons => updates.push(PollUpdate::HorizonsDue),
                PollTask::Outbox(peer) => {
                    if let Some(mut items) = lanes.outbox(data_dir, peer.clone()) {
                        bridge::with_message_deadlines(data_dir, &mut items);
                        updates.push(PollUpdate::Outbox { peer, items });
                    }
                }
            }
            for update in updates {
                if tx.send(Msg::Poll(update)).is_err() {
                    return;
                }
            }
        }
    }
}

/// A word from the UI, at `now`: Start begins the cadence with the hints
/// heard so far (once); the others reach the cadence once it runs.
fn hear(word: PollCtl, cadence: &mut Option<Cadence>, hints: &mut PollHints, now: Instant) {
    match word {
        PollCtl::Start => {
            cadence.get_or_insert_with(|| {
                let mut started = Cadence::new(cfg!(windows), now);
                started.set_hints(*hints, now);
                started
            });
        }
        PollCtl::Hints(new) => {
            *hints = new;
            if let Some(c) = cadence {
                c.set_hints(new, now);
            }
        }
        PollCtl::Burst { peer } => {
            if let Some(c) = cadence {
                c.burst(&peer, now);
            }
        }
        PollCtl::CheckAgain => {
            if let Some(c) = cadence {
                c.check_again(now);
            }
        }
    }
}

/// What the poller last saw of the profile's files.
#[derive(Default)]
struct FileWatch {
    contacts: Option<FileStamp>,
    history: Option<FileStamp>,
    /// tui_state.json's and tui_private.rms's.
    marks: [Option<FileStamp>; 2],
    /// desktop_hidden.json's.
    hidden: Option<FileStamp>,
    /// Whether groups are live, read at the first look (the App reads it
    /// once too), and groups.json's stamp while they are.
    groups_live: Option<bool>,
    groups: Option<FileStamp>,
    /// Where the service log is read from, while it is read: its length
    /// when reading began, so an old run's lines never count.
    log_from: Option<u64>,
    log: Option<FileStamp>,
}

impl FileWatch {
    fn read_log(&mut self, on: bool, data_dir: &Path) {
        match (on, self.log_from) {
            (true, None) => {
                self.log_from = Some(node::service_log_len(data_dir));
                self.log = Some(FileStamp::of(&bridge::service_log_path(data_dir)));
            }
            (false, Some(_)) => {
                self.log_from = None;
                self.log = None;
            }
            _ => {}
        }
    }

    /// What changed since the last look; at the first look, every file.
    fn look(&mut self, data_dir: &Path) -> Vec<PollUpdate> {
        let mut updates = Vec::new();
        let [settings, private] = read_marks::files(data_dir);
        let [marks, sealed_marks] = &mut self.marks;
        let watched = [
            (
                Watched::Contacts,
                bridge::contacts_path(data_dir),
                &mut self.contacts,
            ),
            (
                Watched::History,
                bridge::history_path(data_dir),
                &mut self.history,
            ),
            (Watched::ReadMarks, settings, marks),
            (Watched::ReadMarks, private, sealed_marks),
            (Watched::Hidden, hidden::path(data_dir), &mut self.hidden),
        ];
        for (watched, path, last) in watched {
            let stamp = FileStamp::of(&path);
            if *last != Some(stamp) {
                *last = Some(stamp);
                updates.push(PollUpdate::File { watched, stamp });
            }
        }
        if *self
            .groups_live
            .get_or_insert_with(raven_core::group::group_live_enabled)
        {
            let stamp = FileStamp::of(&raven_core::group::store::groups_path(data_dir));
            if self.groups != Some(stamp) {
                self.groups = Some(stamp);
                updates.push(PollUpdate::File {
                    watched: Watched::Groups,
                    stamp,
                });
            }
        }
        if let Some(from) = self.log_from {
            let stamp = FileStamp::of(&bridge::service_log_path(data_dir));
            if self.log != Some(stamp) {
                self.log = Some(stamp);
                if let Ok((text, _)) = node::service_log_from(data_dir, from) {
                    if !text.is_empty() {
                        updates.push(PollUpdate::ServiceLog(text));
                    }
                }
            }
        }
        updates
    }
}

/// What the poller last saw of this computer's networks. It starts as not
/// known, as the App does, so the App hears only a change.
#[derive(Default)]
struct NetWatch {
    on_any: Option<bool>,
    /// The friends the node last said it saw here lately: a Status that
    /// timed out (a busy node) keeps it.
    friends_here: Option<u32>,
}

impl NetWatch {
    /// The friends the running node saw here lately, for
    /// [`bridge::on_any_network`]: `answered` (None: Status timed out, the
    /// last answer stands).
    fn friends_here(&mut self, answered: Option<Option<u32>>) -> Option<u32> {
        if let Some(now) = answered {
            self.friends_here = now;
        }
        self.friends_here
    }

    /// `now` (a read of [`bridge::on_any_network`]) for the App, when it is
    /// news.
    fn look(&mut self, now: Option<bool>) -> Option<PollUpdate> {
        (std::mem::replace(&mut self.on_any, now) != now).then_some(PollUpdate::Network(now))
    }
}

/// The poller's requests to raven-node: Status and OutboxList, nothing
/// else. On Windows one request of each kind is out at a time: a pipe
/// request that times out leaves its thread behind (ipc_client.rs), so a
/// kind still out is not asked again until it ends.
#[derive(Default)]
struct Lanes {
    status: Lane,
    outbox: Lane,
    paths: Lane,
}

impl Lanes {
    /// The Status answer as the app reads it, with the friends the node saw
    /// here lately (`bridge::friends_here_10m`; outer None: not answered in
    /// time).
    fn status(&self, data_dir: &Path) -> (Probe, Option<Option<u32>>) {
        match ask(&self.status, data_dir, node::status_request()) {
            Some(answer) => (
                Probe::read(&answer),
                Some(bridge::friends_here_10m(&answer)),
            ),
            None => (Probe::timed_out(), None),
        }
    }

    fn outbox(&self, data_dir: &Path, peer: Option<String>) -> Option<Vec<OutboxItem>> {
        ask(&self.outbox, data_dir, node::outbox_request(peer)).and_then(node::outbox_items)
    }

    fn paths(&self, data_dir: &Path) -> Option<node::Paths> {
        ask(&self.paths, data_dir, node::arrivals_request()).and_then(node::paths_of)
    }
}

/// `req`'s answer, or None when it was not answered in time (Windows: or one
/// of its kind is still out).
fn ask(lane: &Lane, data_dir: &Path, req: IpcRequest) -> Option<Result<IpcResponse, String>> {
    if !cfg!(windows) {
        // A socket has its own timeouts: nothing is left behind.
        return Some(bridge::ipc_request_timeout(
            data_dir,
            &req,
            node::PROBE_TIMEOUT,
        ));
    }
    let data_dir = data_dir.to_path_buf();
    lane.ask(node::PROBE_TIMEOUT, move || {
        bridge::ipc_request_timeout(&data_dir, &req, LANE_HOLD)
    })
    .answered()
}

/// One request at a time, each on a thread of its own that the asker waits
/// for only so long.
#[derive(Default)]
pub(super) struct Lane {
    busy: Arc<AtomicBool>,
}

/// How a [`Lane::ask`] went.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LaneAnswer<T> {
    Answered(T),
    /// Still running: it goes on alone, and the lane stays busy until then.
    TimedOut,
    /// The one before is still running.
    Busy,
}

impl<T> LaneAnswer<T> {
    fn answered(self) -> Option<T> {
        match self {
            LaneAnswer::Answered(answer) => Some(answer),
            LaneAnswer::TimedOut | LaneAnswer::Busy => None,
        }
    }
}

/// Marks the lane free when its request ends, however it ends.
struct Freed(Arc<AtomicBool>);

impl Drop for Freed {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Lane {
    /// Runs `request` on its own thread and waits up to `wait` for it,
    /// unless the one before still runs.
    pub(super) fn ask<T: Send + 'static>(
        &self,
        wait: Duration,
        request: impl FnOnce() -> T + Send + 'static,
    ) -> LaneAnswer<T> {
        if self.busy.swap(true, Ordering::AcqRel) {
            return LaneAnswer::Busy;
        }
        let (tx, rx) = mpsc::channel();
        let freed = Freed(Arc::clone(&self.busy));
        let spawned = thread::Builder::new()
            .name("raven-tui-ipc".into())
            .spawn(move || {
                let answer = request();
                drop(freed);
                let _ = tx.send(answer);
            });
        if spawned.is_err() {
            // `freed` went with the closure that never ran.
            return LaneAnswer::TimedOut;
        }
        match rx.recv_timeout(wait) {
            Ok(answer) => LaneAnswer::Answered(answer),
            Err(_) => LaneAnswer::TimedOut,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const NONE: KeyModifiers = KeyModifiers::NONE;

    fn key_event(code: KeyCode, modifiers: KeyModifiers) -> Event {
        Event::Key(KeyEvent::new(code, modifiers))
    }

    fn release(code: KeyCode, modifiers: KeyModifiers) -> Event {
        Event::Key(KeyEvent::new_with_kind(
            code,
            modifiers,
            KeyEventKind::Release,
        ))
    }

    /// `events` stamped at `gaps_ms` milliseconds apart, from `t0`.
    fn timed(t0: Instant, gap_ms: u64, events: Vec<Event>) -> Vec<(Instant, Event)> {
        (0u64..)
            .zip(events)
            .map(|(i, event)| (t0 + Duration::from_millis(i * gap_ms), event))
            .collect()
    }

    fn chars(text: &str) -> Vec<Event> {
        text.chars()
            .map(|c| match c {
                '\n' => key_event(KeyCode::Enter, NONE),
                '\t' => key_event(KeyCode::Tab, NONE),
                c => key_event(KeyCode::Char(c), NONE),
            })
            .collect()
    }

    fn typed(c: char) -> Msg {
        Msg::Key(Key::Event(KeyEvent::new(KeyCode::Char(c), NONE)))
    }

    fn pasted(text: &str) -> Msg {
        Msg::Paste {
            text: text.to_owned(),
            via: PasteVia::Keystrokes,
        }
    }

    #[test]
    fn a_fast_burst_of_text_keys_is_one_paste() {
        let t0 = Instant::now();
        let mut burst = Burst::default();
        let msgs = coalesce(&timed(t0, 1, chars("Hi Bob\nA\tV")), &mut burst);
        assert_eq!(msgs, [pasted("Hi Bob\nA V")]);

        // Three keys are enough; two are not.
        let mut burst = Burst::default();
        assert_eq!(
            coalesce(&timed(t0, 2, chars("avq")), &mut burst),
            [pasted("avq")]
        );
        let mut burst = Burst::default();
        assert_eq!(
            coalesce(&timed(t0, 2, chars("av")), &mut burst),
            [typed('a'), typed('v')]
        );
    }

    #[test]
    fn typing_stays_single_keys() {
        let t0 = Instant::now();
        let mut burst = Burst::default();
        let mut msgs = Vec::new();
        // One key per batch, 60 ms apart, as the input thread reads typing.
        for (i, event) in (0u64..).zip(chars("aq?\n")) {
            let at = t0 + Duration::from_millis(60 * i);
            msgs.extend(coalesce(&[(at, event)], &mut burst));
        }
        assert_eq!(
            msgs,
            [
                typed('a'),
                typed('q'),
                typed('?'),
                Msg::Key(Key::Event(KeyEvent::new(KeyCode::Enter, NONE)))
            ]
        );
    }

    #[test]
    fn an_enter_right_after_a_key_is_a_pasted_enter() {
        let t0 = Instant::now();
        let mut burst = Burst::default();
        assert_eq!(
            coalesce(&[(t0, chars("x").remove(0))], &mut burst),
            [typed('x')]
        );
        let enter = (
            t0 + Duration::from_millis(20),
            key_event(KeyCode::Enter, NONE),
        );
        assert_eq!(coalesce(&[enter], &mut burst), [Msg::Key(Key::PastedEnter)]);
        // 40 ms later it is a real Enter.
        let enter = (
            t0 + Duration::from_millis(60),
            key_event(KeyCode::Enter, NONE),
        );
        assert_eq!(
            coalesce(&[enter], &mut burst),
            [Msg::Key(Key::Event(KeyEvent::new(KeyCode::Enter, NONE)))]
        );
    }

    /// Field test E3: text sent fast (tmux `send-keys -l`, a text expander,
    /// a paste without bracketed paste) and an Enter right after it, then
    /// nothing: the Enter sends, after the text. A line break inside the
    /// burst stays text; an Enter more text follows stays a line break.
    #[test]
    fn an_enter_after_fast_text_and_then_nothing_is_the_users_enter() {
        let t0 = Instant::now();
        let enter = || Msg::Key(Key::Event(KeyEvent::new(KeyCode::Enter, NONE)));
        // In the same batch as the burst.
        let mut burst = Burst::default();
        let batch = timed(t0, 1, chars("hello bob\n"));
        assert!(ends_in_quick_enter(&batch, &burst));
        assert_eq!(
            coalesce_settled(&batch, &mut burst, true),
            [pasted("hello bob"), enter()]
        );
        // Not settled (more text came): a line break, as before.
        let mut burst = Burst::default();
        assert_eq!(
            coalesce_settled(&batch, &mut burst, false),
            [pasted("hello bob\n")]
        );
        // A line break inside, the Enter at the end.
        let mut burst = Burst::default();
        assert_eq!(
            coalesce_settled(&timed(t0, 1, chars("one\ntwo\n")), &mut burst, true),
            [pasted("one\ntwo"), enter()]
        );
        // In a batch of its own, 20 ms after the text: the user's Enter
        // once nothing followed, a pasted Enter while it is not known.
        let mut burst = Burst::default();
        assert_eq!(
            coalesce_settled(&timed(t0, 1, chars("hey")), &mut burst, false),
            [pasted("hey")]
        );
        let late = [(
            t0 + Duration::from_millis(22),
            key_event(KeyCode::Enter, NONE),
        )];
        assert!(ends_in_quick_enter(&late, &burst));
        let mut unsettled = Burst {
            last_text: burst.last_text,
            keys: burst.keys,
        };
        assert_eq!(
            coalesce_settled(&late, &mut unsettled, false),
            [Msg::Key(Key::PastedEnter)]
        );
        assert_eq!(coalesce_settled(&late, &mut burst, true), [enter()]);
        // Typing (an Enter long after the last key) waits for nothing.
        let slow = [(
            t0 + Duration::from_millis(500),
            key_event(KeyCode::Enter, NONE),
        )];
        assert!(!ends_in_quick_enter(&slow, &burst));
        // An Enter with Ctrl is no text key.
        let ctrl = [(t0, key_event(KeyCode::Enter, KeyModifiers::CONTROL))];
        assert!(!ends_in_quick_enter(&ctrl, &Burst::default()));
    }

    #[test]
    fn arrows_esc_and_shortcuts_are_never_joined() {
        let t0 = Instant::now();
        let mut burst = Burst::default();
        let wheel = vec![key_event(KeyCode::Down, NONE); 6];
        let msgs = coalesce(&timed(t0, 1, wheel), &mut burst);
        assert_eq!(
            msgs,
            vec![Msg::Key(Key::Event(KeyEvent::new(KeyCode::Down, NONE))); 6]
        );
        let ctrl = KeyModifiers::CONTROL;
        let keys = vec![
            key_event(KeyCode::Char('c'), ctrl),
            key_event(KeyCode::Esc, NONE),
            key_event(KeyCode::Char('c'), ctrl),
        ];
        assert_eq!(coalesce(&timed(t0, 1, keys), &mut burst).len(), 3);

        // Inside a paste such a key stays a key, between two pastes.
        let mut burst = Burst::default();
        let mut events = chars("abc");
        events.push(key_event(KeyCode::Char('j'), ctrl));
        events.extend(chars("de"));
        let msgs = coalesce(&timed(t0, 1, events), &mut burst);
        assert_eq!(
            msgs,
            [
                pasted("abc"),
                Msg::Key(Key::Event(KeyEvent::new(KeyCode::Char('j'), ctrl))),
                pasted("de")
            ]
        );
    }

    #[test]
    fn a_burst_goes_on_into_the_next_batch() {
        let t0 = Instant::now();
        let mut burst = Burst::default();
        assert_eq!(
            coalesce(&timed(t0, 1, chars("abcd")), &mut burst),
            [pasted("abcd")]
        );
        // The next batch starts 2 ms after the last key: the same paste, even
        // for one key.
        let next = t0 + Duration::from_millis(5);
        assert!(burst.continues(next));
        assert_eq!(
            coalesce(&timed(next, 1, chars("q")), &mut burst),
            [pasted("q")]
        );
        // Long after, a key is a key again.
        let later = t0 + Duration::from_secs(1);
        assert!(!burst.continues(later));
        assert_eq!(
            coalesce(&timed(later, 1, chars("q")), &mut burst),
            [typed('q')]
        );
    }

    #[test]
    fn bracketed_pastes_and_resizes_pass_through() {
        let t0 = Instant::now();
        let mut burst = Burst::default();
        let events = vec![
            (t0, Event::Paste("raven-card/x\nsecond".into())),
            (t0, Event::Resize(100, 30)),
            (t0, Event::FocusGained),
        ];
        assert_eq!(
            coalesce(&events, &mut burst),
            [
                Msg::Paste {
                    text: "raven-card/x\nsecond".into(),
                    via: PasteVia::Bracketed
                },
                Msg::Resize {
                    cols: 100,
                    rows: 30
                }
            ]
        );
    }

    #[test]
    fn altgr_characters_are_text() {
        let t0 = Instant::now();
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        for windows in [false, true] {
            let mut keys = KeyFilter::new(windows);
            let at = keys.keep(key_event(KeyCode::Char('@'), altgr), t0);
            assert_eq!(at, Some(key_event(KeyCode::Char('@'), NONE)));
            let euro = keys.keep(
                key_event(KeyCode::Char('€'), altgr | KeyModifiers::SHIFT),
                t0,
            );
            assert_eq!(
                euro,
                Some(key_event(KeyCode::Char('€'), KeyModifiers::SHIFT))
            );
            // Ctrl+Alt+letter stays a shortcut.
            let letter = keys.keep(key_event(KeyCode::Char('q'), altgr), t0);
            assert_eq!(letter, Some(key_event(KeyCode::Char('q'), altgr)));
        }
        // An AltGr '@' among typed text joins a paste like any character.
        let mut keys = KeyFilter::new(true);
        let mut batch = Vec::new();
        for (i, event) in (0u64..).zip([
            key_event(KeyCode::Char('a'), NONE),
            key_event(KeyCode::Char('@'), altgr),
            key_event(KeyCode::Char('b'), NONE),
        ]) {
            let at = t0 + Duration::from_millis(i);
            batch.extend(keys.keep(event, at).map(|event| (at, event)));
        }
        assert_eq!(coalesce(&batch, &mut Burst::default()), [pasted("a@b")]);
    }

    #[test]
    fn only_presses_pass_and_windows_alt_codes_are_text() {
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        let mut unix = KeyFilter::new(false);
        assert_eq!(unix.keep(release(KeyCode::Char('é'), NONE), ms(0)), None);
        let repeat = KeyEvent::new_with_kind(KeyCode::Down, NONE, KeyEventKind::Repeat);
        assert_eq!(unix.keep(Event::Key(repeat), ms(0)), None);
        assert_eq!(
            unix.keep(Event::Resize(1, 1), ms(0)),
            Some(Event::Resize(1, 1))
        );

        let mut windows = KeyFilter::new(true);
        // Typing: each release follows its press, and is dropped.
        assert!(windows
            .keep(key_event(KeyCode::Char('a'), NONE), ms(0))
            .is_some());
        assert_eq!(
            windows.keep(release(KeyCode::Char('a'), NONE), ms(80)),
            None
        );
        // Shift let go first: the release reports another character.
        assert!(windows
            .keep(key_event(KeyCode::Char('A'), KeyModifiers::SHIFT), ms(200))
            .is_some());
        assert_eq!(
            windows.keep(release(KeyCode::Char('a'), NONE), ms(260)),
            None
        );
        assert_eq!(windows.keep(release(KeyCode::Enter, NONE), ms(270)), None);
        // Alt+0233: only a release, with no press before it.
        assert_eq!(
            windows.keep(release(KeyCode::Char('é'), KeyModifiers::ALT), ms(400)),
            Some(key_event(KeyCode::Char('é'), NONE))
        );
        // A press held over a second ago no longer hides an Alt code.
        assert!(windows
            .keep(key_event(KeyCode::Char('x'), NONE), ms(500))
            .is_some());
        assert_eq!(
            windows.keep(release(KeyCode::Char('ß'), NONE), ms(1600)),
            Some(key_event(KeyCode::Char('ß'), NONE))
        );
    }

    #[test]
    fn the_size_poll_reports_changes_only() {
        let mut last = Some((80, 24));
        assert_eq!(size_change(&mut last, Ok((80, 24))), None);
        assert_eq!(size_change(&mut last, Ok((100, 30))), Some((100, 30)));
        assert_eq!(size_change(&mut last, Ok((100, 30))), None);
        assert_eq!(
            size_change(&mut last, Err(io::ErrorKind::Other.into())),
            None
        );
        assert_eq!(last, Some((100, 30)));
        let mut unknown = None;
        assert_eq!(size_change(&mut unknown, Ok((80, 24))), Some((80, 24)));
    }

    #[test]
    fn signal_decision_table() {
        use SignalMode::{Classic, Suspended, Tui};
        use SignalStep::{Exit, RestoreAndExit, TellUi, Wait};
        let ms = Duration::from_millis;
        let table = [
            // mode, critical sections, told the UI this long ago -> step
            (Classic, 0, None, Exit),
            (Classic, 1, None, Exit),
            (Classic, 0, Some(ms(0)), Exit),
            (Suspended, 0, None, Wait),
            (Suspended, 1, None, Wait),
            (Suspended, 0, Some(ms(5000)), Wait),
            (Tui, 0, None, TellUi),
            (Tui, 1, None, TellUi),
            (Tui, 0, Some(ms(999)), Wait),
            (Tui, 0, Some(ms(1000)), RestoreAndExit),
            (Tui, 0, Some(ms(5000)), RestoreAndExit),
            (Tui, 1, Some(ms(5000)), Wait),
            (Tui, 2, Some(ms(1)), Wait),
        ];
        for (mode, critical, told, step) in table {
            assert_eq!(
                signal_step(mode, critical, told),
                step,
                "{mode:?}, {critical} critical, told {told:?}"
            );
        }
    }

    #[test]
    fn signals_have_shell_exit_codes() {
        let all = [
            (OsSignal::Terminate, 143, false),
            (OsSignal::HangUp, 129, true),
            (OsSignal::ConsoleClosed, 1, true),
            (OsSignal::Break, 1, false),
        ];
        for (signal, code, hung_up) in all {
            assert_eq!((signal.exit_code(), signal.hung_up()), (code, hung_up));
            assert_eq!(OsSignal::from_u8(signal.to_u8()), Some(signal));
        }
        assert_eq!(OsSignal::from_u8(0), None);
        for mode in [SignalMode::Tui, SignalMode::Suspended, SignalMode::Classic] {
            assert_eq!(SignalMode::from_u8(mode.to_u8()), mode);
        }
    }

    #[test]
    fn critical_sections_count_until_dropped() {
        // Other tests may hold one at the same time: compare against before.
        let before = CRITICAL.load(Ordering::Acquire);
        let outer = Critical::enter();
        let inner = Critical::enter();
        assert!(CRITICAL.load(Ordering::Acquire) >= before + 2);
        drop(inner);
        drop(outer);
        assert!(CRITICAL.load(Ordering::Acquire) <= before + 2);
    }

    #[test]
    fn the_exit_waits_for_a_critical_section() {
        // Alone in a child: other tests open sections of their own.
        let name = format!("{}::the_exit_waits_for_a_critical_section", module_path!());
        if testkit::run_in_child(&name).is_some() {
            return;
        }
        assert!(wait_for_critical(Duration::ZERO), "none open");
        let held = Critical::enter();
        let started = Instant::now();
        assert!(!wait_for_critical(ms(120)), "still open");
        assert!(started.elapsed() >= ms(120));
        let writer = thread::spawn(move || {
            thread::sleep(ms(150));
            drop(held);
        });
        let started = Instant::now();
        assert!(wait_for_critical(Duration::from_secs(10)));
        assert!(started.elapsed() >= ms(100), "{:?}", started.elapsed());
        writer.join().expect("the writer");
    }

    #[test]
    fn a_thread_guard_reports_only_an_unplanned_end() {
        let (tx, rx) = mpsc::channel();
        ThreadGuard::new(INPUT_THREAD, tx.clone()).finish();
        assert!(rx.try_recv().is_err(), "a planned end says nothing");
        drop(ThreadGuard::new(INPUT_THREAD, tx.clone()));
        assert_eq!(rx.try_recv(), Ok(Msg::ThreadDied(INPUT_THREAD)));
        let thread_tx = tx.clone();
        let joined = thread::spawn(move || {
            let _guard = ThreadGuard::new(SIGNAL_THREAD, thread_tx);
            panic!("a dying thread (expected in this test)");
        })
        .join();
        assert!(joined.is_err());
        assert_eq!(rx.try_recv(), Ok(Msg::ThreadDied(SIGNAL_THREAD)));
        // The UI is gone: the guard still drops quietly.
        drop(rx);
        drop(ThreadGuard::new(INPUT_THREAD, tx));
    }

    #[test]
    fn pause_waits_for_the_input_thread_to_stop_reading() {
        let gate = Arc::new(InputGate::default());
        let handle = InputHandle {
            gate: Arc::clone(&gate),
        };
        let (reads_tx, reads) = mpsc::channel();
        let reader_gate = Arc::clone(&gate);
        let reader = thread::spawn(move || {
            let _stopped = MarkStopped(Arc::clone(&reader_gate));
            for _ in 0..200 {
                reader_gate.wait_while_paused();
                if reads_tx.send(()).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });
        reads.recv().expect("the reader runs");
        assert!(handle.pause(), "the reader acknowledged");
        while reads.try_recv().is_ok() {}
        thread::sleep(Duration::from_millis(50));
        assert!(reads.try_recv().is_err(), "no read while paused");
        handle.resume();
        reads
            .recv_timeout(Duration::from_secs(5))
            .expect("reading again after resume");
        drop(reads);
        reader.join().expect("the reader ends");
        // An ended thread never acknowledges: pause does not wait for it.
        let started = Instant::now();
        assert!(handle.pause());
        assert!(started.elapsed() < PAUSE_WAIT);
    }

    #[test]
    fn stderr_is_cut_into_lines() {
        let mut lines = LineSplitter::default();
        assert!(lines.push(b"raven: still wait").is_empty());
        assert_eq!(
            lines.push(b"ing\r\nsecond\n\nthird"),
            ["raven: still waiting", "second", ""]
        );
        assert_eq!(lines.push(b"\xff\n"), ["third\u{fffd}"]);
        let long = vec![b'x'; STDERR_LINE_CAP + 10];
        let mut got = lines.push(&long);
        got.extend(lines.push(b"\n"));
        assert_eq!(got, ["x".repeat(STDERR_LINE_CAP)]);
    }

    #[test]
    fn the_stderr_reader_sends_whole_lines_until_the_pipe_ends() {
        let (tx, rx) = mpsc::channel();
        let pipe = Cursor::new(b"one\ntwo\npartial".to_vec());
        assert!(
            drain_stderr(pipe, &tx),
            "end of file: the redirect was disarmed"
        );
        let got: Vec<String> = rx
            .try_iter()
            .map(|msg| match msg {
                Msg::Stderr(line) => line,
                other => panic!("not a stderr line: {other:?}"),
            })
            .collect();
        assert_eq!(got, ["one", "two"]);
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn keychain_lines_name_raven_cores_items() {
        let lines = [
            (
                "raven: still waiting for macOS Keychain access (your chat history) after 3s.",
                Some(("your chat history", false)),
            ),
            (
                "raven: still waiting for macOS Keychain access (your Raven identity) after 33s - \
                 answer the macOS dialog (\"Always Allow\"), or press Ctrl-C to give up.",
                Some(("your Raven identity", false)),
            ),
            // ext.rs's note, coloured as on a terminal.
            (
                "\x1b[1;35mnote\x1b[0m: raven-node (the background service) is waiting for macOS \
                 Keychain access to key-exchange data.",
                Some(("key-exchange data", true)),
            ),
            // Words raven-core never uses are not shown.
            (
                "raven: still waiting for macOS Keychain access (\x1b]0;pwned) after 3s.",
                Some(("a saved secret", false)),
            ),
            // The service log's marker is read from the log, never stderr.
            (
                "raven-node: BLOCKED_ON_KEYCHAIN what=identity waited=3s",
                None,
            ),
            ("notice: started raven-node (process 42)", None),
            ("", None),
        ];
        for (line, want) in lines {
            let got = keychain_wait(line).map(|wait| (wait.item, wait.service));
            assert_eq!(got, want, "{line:?}");
        }
    }

    #[test]
    fn the_reader_notes_sync_sentinels_and_keeps_them_out_of_the_ring() {
        let (tx, rx) = mpsc::channel();
        let n = NEXT_SYNC.fetch_add(1, Ordering::Relaxed);
        let first = stdio::ring_next_seq();
        let text = format!(
            "\x1b[1;35mnotice\x1b[0m: started raven-node (process 4242), RAVEN's background \
             service for this profile. It keeps running after ash exits.\n\
             \x1b[2mstop only this one with: kill 4242\x1b[0m\n\
             {SYNC_PREFIX}{n}\n\
             after the sentinel\n"
        );
        assert!(drain_stderr(Cursor::new(text.into_bytes()), &tx));
        let end = wait_for_sync(n, Duration::ZERO).expect("the reader reached the sentinel");
        let lines: Vec<String> = stdio::ring_lines(first..end)
            .into_iter()
            .map(|(_, line)| line)
            .collect();
        assert!(
            lines.iter().all(|line| !line.contains(SYNC_PREFIX)),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|line| line == "after the sentinel"),
            "{lines:?}"
        );
        assert_eq!(
            node::notice_pid(lines.iter().map(String::as_str)),
            Some(4242)
        );
        let sent: Vec<String> = rx
            .try_iter()
            .map(|msg| match msg {
                Msg::Stderr(line) => line,
                other => panic!("not a stderr line: {other:?}"),
            })
            .collect();
        assert_eq!(sent.len(), 3, "{sent:?}");
        assert_eq!(sent[2], "after the sentinel");
        assert_eq!(sync_number(&format!("{SYNC_PREFIX}{n}")), Some(n));
        assert_eq!(sync_number("RAVEN_TUI_SYNC x"), None);
        // One never reached times out; with no reader, none is even written.
        assert_eq!(wait_for_sync(u64::MAX, ms(10)), None);
        let started = Instant::now();
        assert_eq!(sync_stderr(Duration::from_secs(5)), None);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_worker_runs_its_jobs_in_order_and_outlives_a_panic() {
        let (tx, rx) = mpsc::channel();
        let worker = Worker::spawn(NODE_THREAD, tx).expect("a worker");
        let order = Arc::new(Mutex::new(Vec::new()));
        for i in 0..3u64 {
            let order = Arc::clone(&order);
            worker.submit(JobName::NodeProbe, move || {
                // The first sleeps longest: a worker still keeps the order.
                thread::sleep(ms(10 * (3 - i)));
                lock(&order).push(i);
                JobResult::Managed(None)
            });
        }
        worker.submit(JobName::NodeEnsure, || {
            println!("printed by the job");
            panic!("a job panics (expected in this test)")
        });
        worker.submit(JobName::NodeVault, || {
            JobResult::Vault(node::Vault::default())
        });
        worker.join();
        assert_eq!(*lock(&order), [0, 1, 2]);
        let results: Vec<Msg> = rx.try_iter().collect();
        assert_eq!(results.len(), 5, "{results:?}");
        match &results[3] {
            Msg::Job(JobResult::Failed {
                job: JobName::NodeEnsure,
                plain,
            }) => {
                assert_eq!(plain.headline, "Something went wrong inside Raven.");
                assert!(plain.technical.contains("a job panics"), "{plain:?}");
                assert!(plain.technical.contains("printed by the job"), "{plain:?}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            results[4],
            Msg::Job(JobResult::Vault(node::Vault::default()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_hub_hands_each_job_to_its_worker() {
        testkit::lab_backends();
        let dir = testkit::short_dir();
        // No identity: the jobs refuse, and the profile stays empty.
        let controller = Arc::new(Controller::new(dir.path()));
        let (tx, rx) = mpsc::channel();
        let hub = Hub::start(controller, &tx).expect("the workers");
        hub.dispatch(Cmd::Store(StoreJob::LoadContacts));
        hub.dispatch(Cmd::Node(NodeJob::Ensure));
        hub.dispatch(Cmd::Send(SendJob::Send {
            local_id: 1,
            pub_hex: "b0".repeat(32),
            text: "hi".into(),
        }));
        hub.dispatch(Cmd::Redraw);
        hub.shut_down();
        let results: Vec<Msg> = rx.try_iter().collect();
        assert_eq!(results.len(), 3, "{results:?}");
        assert!(results.iter().any(|msg| matches!(
            msg,
            Msg::Job(JobResult::Sent { local_id: 1, outcome })
                if outcome.result == SendResult::Failed(NO_IDENTITY.to_owned())
        )));
        let no_identity = Err(NO_IDENTITY.to_owned());
        assert!(results.iter().any(|msg| matches!(
            msg,
            Msg::Job(JobResult::Contacts { contacts, .. }) if *contacts == no_identity
        )));
        assert!(results.iter().any(|msg| matches!(
            msg,
            Msg::Job(JobResult::Ensured(ensured)) if ensured.result == Err(NO_IDENTITY.to_owned())
        )));
        assert!(!bridge::service_log_path(dir.path()).exists());
    }

    #[test]
    fn the_poller_watches_files_and_asks_status_on_its_cadence() {
        use PollTask::{Files, Horizons, Status};
        let t0 = Instant::now();
        let mut c = Cadence::new(false, t0);
        assert_eq!(c.due(t0), [Files, Status, Horizons]);
        assert_eq!(c.next_due(), t0 + FILES_EVERY);
        assert!(c.due(t0 + ms(499)).is_empty());
        assert_eq!(c.due(t0 + ms(500)), [Files]);
        assert_eq!(c.due(t0 + ms(1000)), [Files]);
        assert_eq!(c.due(t0 + ms(2000)), [Files, Status]);
        // No node answers: no outbox is ever asked for.
        c.status_seen(StatusSeen::NoNode, t0 + ms(2000));
        for at in (2500..40_000).step_by(500) {
            assert!(!c
                .due(t0 + ms(at))
                .iter()
                .any(|t| matches!(t, PollTask::Outbox(_))));
        }
        // While this app starts the node: Status every second.
        let mut c = Cadence::new(false, t0);
        c.due(t0);
        c.set_hints(
            PollHints {
                starting: true,
                read_log: true,
                ..PollHints::default()
            },
            t0 + ms(100),
        );
        assert_eq!(c.next_due(), t0 + ms(500));
        assert_eq!(c.due(t0 + ms(1100)), [Files, Status]);
        assert_eq!(c.due(t0 + ms(2100)), [Files, Status]);
    }

    #[test]
    fn the_outbox_is_listed_only_while_a_node_answers() {
        use PollTask::{Files, Horizons, Outbox, Status};
        let t0 = Instant::now();
        // Idle: at once when a node answers, then every 30 s.
        let mut c = Cadence::new(false, t0);
        assert_eq!(c.due(t0), [Files, Status, Horizons]);
        assert!(!c.status_seen(StatusSeen::Answered, t0));
        assert_eq!(c.next_due(), t0);
        assert_eq!(c.due(t0), [Outbox(None)]);
        assert!(!c.due(t0 + ms(29_999)).contains(&Outbox(None)));
        assert!(c.due(t0 + ms(30_000)).contains(&Outbox(None)));
        // Live items: every 5 s, and sooner as soon as one is live.
        c.set_hints(
            PollHints {
                live: true,
                ..PollHints::default()
            },
            t0 + ms(30_100),
        );
        assert!(!c.due(t0 + ms(35_000)).contains(&Outbox(None)));
        assert!(c.due(t0 + ms(35_100)).contains(&Outbox(None)));
        assert!(!c.due(t0 + ms(40_000)).contains(&Outbox(None)));
        assert!(c.due(t0 + ms(40_100)).contains(&Outbox(None)));
        // The node went: no more lists until it answers again.
        c.status_seen(StatusSeen::NoNode, t0 + ms(40_200));
        assert!(!c.due(t0 + ms(46_000)).contains(&Outbox(None)));
        c.status_seen(StatusSeen::Answered, t0 + ms(46_000));
        assert!(c.due(t0 + ms(46_000)).contains(&Outbox(None)));
        assert!(!c.due(t0 + ms(46_500)).contains(&Outbox(None)));
        assert!(c.due(t0 + ms(51_000)).contains(&Outbox(None)));
    }

    #[test]
    fn the_horizons_are_due_at_once_then_every_minute() {
        let t0 = Instant::now();
        for windows in [false, true] {
            let mut c = Cadence::new(windows, t0);
            let horizons = |c: &mut Cadence, at: Duration| {
                c.due(t0 + at)
                    .iter()
                    .filter(|t| **t == PollTask::Horizons)
                    .count()
            };
            assert_eq!(horizons(&mut c, ms(0)), 1);
            assert_eq!(c.next_due(), t0 + FILES_EVERY);
            // Whatever raven-node does: they are the App's to read.
            for _ in 0..MAX_TIMEOUTS {
                c.status_seen(StatusSeen::TimedOut, t0);
            }
            let mut asked = 0;
            for at in (500..=120_000).step_by(500) {
                asked += horizons(&mut c, ms(at));
            }
            assert_eq!(asked, 2, "at 60 s and 120 s");
            // Nothing else due: the next is a minute after the last.
            let mut idle = Cadence::new(windows, t0);
            idle.due(t0);
            idle.next_files = t0 + HORIZONS_EVERY * 2;
            idle.next_status = t0 + HORIZONS_EVERY * 2;
            assert_eq!(idle.next_due(), t0 + HORIZONS_EVERY);
        }
    }

    #[test]
    fn a_send_lists_its_friends_outbox_at_one_and_three_seconds() {
        use PollTask::Outbox;
        let t0 = Instant::now();
        let bob = "b0".repeat(32);
        let mut c = Cadence::new(false, t0);
        c.due(t0);
        c.status_seen(StatusSeen::Answered, t0);
        c.due(t0);
        c.burst(&bob, t0 + ms(100));
        assert_eq!(c.next_due(), t0 + ms(500));
        let lists = |c: &mut Cadence, at: u64| -> Vec<PollTask> {
            c.due(t0 + ms(at))
                .into_iter()
                .filter(|t| matches!(t, Outbox(Some(_))))
                .collect()
        };
        assert!(lists(&mut c, 1000).is_empty());
        assert_eq!(lists(&mut c, 1100), [Outbox(Some(bob.clone()))]);
        assert!(lists(&mut c, 2000).is_empty());
        assert_eq!(lists(&mut c, 3100), [Outbox(Some(bob.clone()))]);
        assert!(lists(&mut c, 10_000).is_empty());
        // Due while no node answers: dropped, never asked later.
        c.burst(&bob, t0 + ms(10_000));
        c.status_seen(StatusSeen::NoNode, t0 + ms(10_000));
        assert!(lists(&mut c, 11_000).is_empty());
        assert!(lists(&mut c, 13_000).is_empty());
        c.status_seen(StatusSeen::Answered, t0 + ms(13_500));
        assert!(lists(&mut c, 14_000).is_empty());
    }

    #[test]
    fn windows_stops_asking_after_three_unanswered_status_requests() {
        let t0 = Instant::now();
        for windows in [false, true] {
            let mut c = Cadence::new(windows, t0);
            let mut at = t0;
            let mut stopped_at = None;
            for round in 0..5 {
                assert_eq!(c.due(at).contains(&PollTask::Status), !c.stopped());
                if c.status_seen(StatusSeen::TimedOut, at) {
                    stopped_at = Some(round);
                }
                at += STATUS_EVERY;
            }
            if windows {
                assert_eq!(stopped_at, Some(2), "the third timeout stops it");
                assert!(c.stopped());
                assert!(!c
                    .due(at + Duration::from_secs(60))
                    .contains(&PollTask::Status));
                // The files are still watched; R asks again at once.
                c.check_again(at);
                assert!(!c.stopped());
                assert!(c.due(at).contains(&PollTask::Status));
                // An answer in between starts the count again.
                c.status_seen(StatusSeen::TimedOut, at);
                c.status_seen(StatusSeen::TimedOut, at);
                c.status_seen(StatusSeen::Answered, at);
                assert!(!c.status_seen(StatusSeen::TimedOut, at));
                assert!(!c.stopped());
            } else {
                assert_eq!(stopped_at, None, "a socket leaves nothing behind");
            }
        }
    }

    #[test]
    fn the_poller_hears_the_ui_only_once_started() {
        use PollTask::{Files, Horizons, Outbox, Status};
        let t0 = Instant::now();
        let mut cadence = None;
        let mut hints = PollHints::default();
        let live = PollHints {
            live: true,
            starting: true,
            ..PollHints::default()
        };
        // Before Start: only the hints are kept, for when it starts.
        hear(PollCtl::Hints(live), &mut cadence, &mut hints, t0);
        hear(
            PollCtl::Burst {
                peer: "b0".repeat(32),
            },
            &mut cadence,
            &mut hints,
            t0,
        );
        hear(PollCtl::CheckAgain, &mut cadence, &mut hints, t0);
        assert!(cadence.is_none());
        assert_eq!(hints, live);
        hear(PollCtl::Start, &mut cadence, &mut hints, t0);
        let c = cadence.as_mut().expect("started");
        assert_eq!(c.due(t0), [Files, Status, Horizons]);
        // Started with those hints: Status every second.
        assert!(c.due(t0 + ms(1000)).contains(&Status));
        // A second Start changes nothing; a burst now reaches it.
        hear(PollCtl::Start, &mut cadence, &mut hints, t0 + ms(1000));
        let c = cadence.as_mut().expect("started");
        c.status_seen(StatusSeen::Answered, t0 + ms(1000));
        c.due(t0 + ms(1000));
        hear(
            PollCtl::Burst {
                peer: "b0".repeat(32),
            },
            &mut cadence,
            &mut hints,
            t0 + ms(1000),
        );
        let c = cadence.as_mut().expect("started");
        assert!(c
            .due(t0 + ms(2000))
            .contains(&Outbox(Some("b0".repeat(32)))));
        // Check again after Windows' stop asks at once.
        let mut stopped = Some(Cadence::new(true, t0));
        let c = stopped.as_mut().expect("a cadence");
        for _ in 0..MAX_TIMEOUTS {
            c.status_seen(StatusSeen::TimedOut, t0);
        }
        assert!(c.stopped());
        hear(PollCtl::CheckAgain, &mut stopped, &mut hints, t0 + ms(10));
        assert!(stopped
            .as_mut()
            .expect("a cadence")
            .due(t0 + ms(10))
            .contains(&Status));
    }

    #[test]
    fn a_lane_asks_one_request_at_a_time() {
        let lane = Lane::default();
        let wait = Duration::from_secs(5);
        assert_eq!(lane.ask(wait, || 7), LaneAnswer::Answered(7));
        let (release, released) = mpsc::channel::<()>();
        let slow = lane.ask(ms(20), move || {
            let _ = released.recv();
            8
        });
        assert_eq!(slow, LaneAnswer::TimedOut);
        assert_eq!(lane.ask(wait, || 9), LaneAnswer::Busy);
        release.send(()).expect("the slow request still runs");
        let free = |lane: &Lane| {
            let until = Instant::now() + wait;
            while lane.busy.load(Ordering::Acquire) && Instant::now() < until {
                thread::sleep(ms(5));
            }
        };
        free(&lane);
        assert_eq!(lane.ask(wait, || 10), LaneAnswer::Answered(10));
        // A request that panics frees the lane too.
        let died = lane.ask(wait, || -> u8 {
            panic!("a request panics (expected in this test)")
        });
        assert_eq!(died, LaneAnswer::TimedOut);
        free(&lane);
        assert_eq!(lane.ask(wait, || 11), LaneAnswer::Answered(11));
        assert_eq!(LaneAnswer::Answered(1).answered(), Some(1));
        assert_eq!(LaneAnswer::<u8>::Busy.answered(), None);
    }

    #[test]
    fn the_file_watch_reports_changes_and_new_service_log_lines() {
        // Groups (on in release builds since 2026-10) add their own file:
        // off on this thread here; the groups' watch has its own test below.
        raven_core::group::set_lab_groups_for_this_thread(Some(false));
        let dir = testkit::short_dir();
        let mut files = FileWatch::default();
        // First look: every file, missing or not.
        assert_eq!(
            files.look(dir.path()),
            [
                PollUpdate::File {
                    watched: Watched::Contacts,
                    stamp: FileStamp::default()
                },
                PollUpdate::File {
                    watched: Watched::History,
                    stamp: FileStamp::default()
                },
                PollUpdate::File {
                    watched: Watched::ReadMarks,
                    stamp: FileStamp::default()
                },
                PollUpdate::File {
                    watched: Watched::ReadMarks,
                    stamp: FileStamp::default()
                },
                PollUpdate::File {
                    watched: Watched::Hidden,
                    stamp: FileStamp::default()
                },
            ]
        );
        assert!(files.look(dir.path()).is_empty());
        // A message deleted in the desktop app (desktop_hidden.json).
        let deleted = hidden::path(dir.path());
        std::fs::write(&deleted, r#"{"messages":[]}"#).unwrap();
        assert_eq!(
            files.look(dir.path()),
            [PollUpdate::File {
                watched: Watched::Hidden,
                stamp: FileStamp::of(&deleted)
            }]
        );
        // The read markers: tui_state.json, and tui_private.rms in a sealed
        // profile (the desktop app may have read a chat).
        for file in read_marks::files(dir.path()) {
            std::fs::write(&file, "{}").unwrap();
            assert_eq!(
                files.look(dir.path()),
                [PollUpdate::File {
                    watched: Watched::ReadMarks,
                    stamp: FileStamp::of(&file)
                }]
            );
        }
        let contacts = bridge::contacts_path(dir.path());
        std::fs::write(&contacts, "[]").unwrap();
        let stamp = FileStamp::of(&contacts);
        assert_ne!(stamp, FileStamp::default());
        assert_eq!(
            files.look(dir.path()),
            [PollUpdate::File {
                watched: Watched::Contacts,
                stamp
            }]
        );
        // The service log: only while asked for, and only what came after.
        let log = bridge::service_log_path(dir.path());
        std::fs::write(
            &log,
            "raven-node: BLOCKED_ON_KEYCHAIN what=identity waited=9s\n",
        )
        .unwrap();
        assert!(files.look(dir.path()).is_empty(), "not read unless asked");
        files.read_log(true, dir.path());
        assert!(
            files.look(dir.path()).is_empty(),
            "an old run's lines don't count"
        );
        let mut text = std::fs::read_to_string(&log).unwrap();
        text.push_str("--- ash: starting raven-node service ---\n");
        std::fs::write(&log, &text).unwrap();
        assert_eq!(
            files.look(dir.path()),
            [PollUpdate::ServiceLog(
                "--- ash: starting raven-node service ---\n".into()
            )]
        );
        assert!(files.look(dir.path()).is_empty());
        files.read_log(false, dir.path());
        text.push_str("more\n");
        std::fs::write(&log, &text).unwrap();
        assert!(files.look(dir.path()).is_empty());
    }

    #[test]
    fn the_file_watch_reports_groups_json_only_while_groups_are_live() {
        let dir = testkit::short_dir();
        let path = raven_core::group::store::groups_path(dir.path());
        let groups = |updates: &[PollUpdate]| {
            updates
                .iter()
                .filter(|u| {
                    matches!(
                        u,
                        PollUpdate::File {
                            watched: Watched::Groups,
                            ..
                        }
                    )
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        // Not live: never looked at, whatever changes.
        raven_core::group::set_lab_groups_for_this_thread(Some(false));
        let mut files = FileWatch::default();
        assert!(groups(&files.look(dir.path())).is_empty());
        std::fs::write(&path, "{}").unwrap();
        assert!(files.look(dir.path()).is_empty());
        // Live (the lab switches, debug builds): the first look, then each
        // change.
        if cfg!(debug_assertions) {
            raven_core::group::set_lab_groups_for_this_thread(Some(true));
            raven_core::horizon::set_lab_horizon_for_this_thread(Some(true));
            let mut files = FileWatch::default();
            let seen = |path: &Path| PollUpdate::File {
                watched: Watched::Groups,
                stamp: FileStamp::of(path),
            };
            assert_eq!(groups(&files.look(dir.path())), [seen(&path)]);
            assert!(files.look(dir.path()).is_empty());
            std::fs::write(&path, r#"{"v":1}"#).unwrap();
            assert_eq!(files.look(dir.path()), [seen(&path)]);
            raven_core::horizon::set_lab_horizon_for_this_thread(None);
        }
        raven_core::group::set_lab_groups_for_this_thread(None);
    }

    #[test]
    fn the_network_watch_reports_only_a_change() {
        let mut networks = NetWatch::default();
        // Not known is what the App starts with: nothing to say.
        assert_eq!(networks.look(None), None);
        assert_eq!(
            networks.look(Some(false)),
            Some(PollUpdate::Network(Some(false)))
        );
        assert_eq!(networks.look(Some(false)), None);
        assert_eq!(
            networks.look(Some(true)),
            Some(PollUpdate::Network(Some(true)))
        );
        assert_eq!(networks.look(None), Some(PollUpdate::Network(None)));
        // raven-core reads this computer's interfaces (CP.4): the first read
        // is news for the App.
        let now = bridge::on_any_network(None);
        assert!(now.is_some());
        assert_eq!(
            NetWatch::default().look(now),
            Some(PollUpdate::Network(now))
        );
    }

    /// Phase 3 review E-1: the friends the node saw here lately (a cable
    /// with only fe80:: counts as a network once one is seen) come from
    /// each Status answer; one that timed out keeps the last answer, and no
    /// node (an answer without it) forgets it.
    #[test]
    fn the_network_watch_keeps_the_friends_seen_through_a_timeout() {
        let mut networks = NetWatch::default();
        assert_eq!(networks.friends_here(None), None);
        assert_eq!(networks.friends_here(Some(Some(2))), Some(2));
        assert_eq!(networks.friends_here(None), Some(2));
        assert_eq!(networks.friends_here(Some(None)), None);
        assert_eq!(networks.friends_here(None), None);
        let mut lan = raven_core::ipc::LanStatus {
            friends_here_10m: Some(4),
            ..Default::default()
        };
        let status = |lan: &raven_core::ipc::LanStatus| -> Result<IpcResponse, String> {
            Ok(IpcResponse::Status {
                v: raven_core::ipc::IPC_VERSION,
                bridge: false,
                store: false,
                relay: false,
                forward_pending: 0,
                capabilities: vec!["ipc".into(), "lan_direct".into()],
                p2p: None,
                pid: Some(4242),
                lan_listen: Some("0.0.0.0:7420".into()),
                last_paths: Vec::new(),
                route_hints: None,
                unreachable: Vec::new(),
                egress: None,
                lan_listen_wanted: None,
                lan_bind_error: None,
                clock_skew: Vec::new(),
                unanswered: Vec::new(),
                at_rest: None,
                lan: Some(lan.clone()),
                security: None,
                nearby: None,
                tor: None,
                learning: None,
                locked: None,
                updates: None,
            })
        };
        assert_eq!(bridge::friends_here_10m(&status(&lan)), Some(4));
        lan.friends_here_10m = None;
        assert_eq!(bridge::friends_here_10m(&status(&lan)), None);
        assert_eq!(bridge::friends_here_10m(&Err("not running".into())), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_poller_asks_only_status_outbox_list_and_arrivals_never_a_kick() {
        let dir = testkit::short_dir();
        let fake = testkit::FakeNode::start(
            dir.path(),
            testkit::FakeStatus::listening(4242, "127.0.0.1:7420"),
        );
        let bob = "b0".repeat(32);
        fake.set_outbox(vec![OutboxItem {
            message_id_hex: "a1".repeat(16),
            peer_pub_hex: bob.clone(),
            kind: "message".into(),
            state: "queued".into(),
            ..OutboxItem::default()
        }]);
        let (tx, rx) = mpsc::channel();
        let poller = Poller::spawn(dir.path().to_path_buf(), tx).expect("the poller");
        // Idle until the identity exists.
        thread::sleep(ms(300));
        assert!(fake.ops().is_empty());
        poller.tell(PollCtl::Start);
        poller.tell(PollCtl::Hints(PollHints {
            live: true,
            ..PollHints::default()
        }));
        poller.tell(PollCtl::Burst { peer: bob });
        poller.tell(PollCtl::CheckAgain);
        let msgs = testkit::collect_msgs(&rx, ms(5200));
        poller.stop();
        let ops = fake.ops();
        assert!(!ops.iter().any(|op| op == "outbox_kick"), "{ops:?}");
        // Arrivals (how messages came and went, field test E3) only when
        // the chat history changed: here at the first look.
        assert!(
            ops.iter()
                .all(|op| op == "status" || op == "outbox_list" || op == "arrivals"),
            "{ops:?}"
        );
        let count = |name: &str| ops.iter().filter(|op| *op == name).count();
        assert!(count("arrivals") <= 1, "{ops:?}");
        assert!(count("status") >= 3, "{ops:?}");
        // At once, then at +1 s and +3 s for Bob (and every 5 s).
        assert!(count("outbox_list") >= 3, "{ops:?}");
        let polled = |found: &dyn Fn(&PollUpdate) -> bool| {
            msgs.iter()
                .any(|msg| matches!(msg, Msg::Poll(update) if found(update)))
        };
        assert!(polled(&|u| matches!(
            u,
            PollUpdate::Status(probe) if probe.reach == node::Reach::LocalOnly && probe.pid == Some(4242)
        )));
        assert!(polled(&|u| matches!(
            u,
            PollUpdate::Outbox { peer: None, items } if items.len() == 1
        )));
        assert!(polled(&|u| matches!(
            u,
            PollUpdate::Outbox { peer: Some(_), .. }
        )));
        assert!(polled(&|u| matches!(
            u,
            PollUpdate::File {
                watched: Watched::Contacts,
                ..
            }
        )));
        // The horizons: only a word to the App, whose store worker reads.
        assert!(polled(&|u| *u == PollUpdate::HorizonsDue));
    }

    #[cfg(unix)]
    #[test]
    fn a_stop_signals_only_the_pid_this_profile_reports() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;
        let dir = testkit::short_dir();
        let mut sleeper = Command::new("sleep").arg("30").spawn().expect("sleep");
        let pid = sleeper.id();
        let fake = Arc::new(testkit::FakeNode::start(
            dir.path(),
            testkit::FakeStatus::listening(pid, "0.0.0.0:7420"),
        ));
        let controller = Controller::new(dir.path());
        // A login service is never stopped: nothing is signalled.
        let managed = NodeJob::Stop {
            started_by_app: Some(pid),
            managed: true,
        };
        match node_job(&controller, managed) {
            JobResult::Stopped(stopped) => {
                assert_eq!(stopped.outcome, node::StopOutcome::Managed);
            }
            other => panic!("{other:?}"),
        }
        assert!(sleeper.try_wait().expect("poll").is_none(), "still running");
        // The fake stops answering once its 'process' has ended.
        let answering = Arc::clone(&fake);
        let watcher = thread::spawn(move || {
            let status = sleeper.wait();
            answering.stop();
            status
        });
        let stop = NodeJob::Stop {
            started_by_app: None,
            managed: false,
        };
        match node_job(&controller, stop.clone()) {
            JobResult::Stopped(stopped) => {
                assert_eq!(stopped.outcome, node::StopOutcome::Stopped);
                assert_eq!(stopped.after.reach, node::Reach::NotRunning);
            }
            other => panic!("{other:?}"),
        }
        let status = watcher.join().expect("watcher").expect("wait");
        assert_eq!(status.signal(), Some(15));
        // Nothing runs any more: nothing to stop.
        match node_job(&controller, stop) {
            JobResult::Stopped(stopped) => {
                assert_eq!(stopped.outcome, node::StopOutcome::NotRunning);
            }
            other => panic!("{other:?}"),
        }
    }

    /// LOCK's job once the login item read answered (PP.23): the lock is
    /// recorded, Raven's own login item unloaded for this login session
    /// (never turned off), Raven stopped; and where Raven still runs after
    /// the stop, the lock is taken back. Lab login items and fake tools
    /// only.
    #[cfg(unix)]
    #[test]
    fn lock_records_the_lock_unloads_the_login_item_and_stops_raven() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;
        testkit::lab_backends();
        let root = testkit::short_dir();
        let (a, b) = (root.path().join("a"), root.path().join("b"));
        for dd in [&a, &b] {
            std::fs::create_dir_all(dd).expect("the profile");
            bridge::load_or_create_identity(dd).expect("an identity");
        }
        // Raven's one login item runs `a`.
        let log = bridge::lab_login_item_for_tests(&a, &a);
        let ours = Controller::with_lab_login_item(&a);
        let other = Controller::with_lab_login_item(&b);
        ours.load_identity();
        other.load_identity();
        assert!(matches!(
            node_job(&ours, NodeJob::DetectManaged),
            JobResult::LoginItem(Some(_))
        ));
        // The second profile: the item runs another, so it is not Managed.
        assert!(matches!(
            node_job(&other, NodeJob::DetectManaged),
            JobResult::LoginItem(None)
        ));

        let mut sleeper = Command::new("sleep").arg("30").spawn().expect("sleep");
        let pid = sleeper.id();
        let fake = Arc::new(testkit::FakeNode::start(
            &a,
            testkit::FakeStatus::listening(pid, "0.0.0.0:7420"),
        ));
        let answering = Arc::clone(&fake);
        let watcher = thread::spawn(move || {
            let status = sleeper.wait();
            answering.stop();
            status
        });
        let lock = NodeJob::Lock {
            started_by_app: None,
            own_item: true,
            managed: false,
        };
        match node_job(&ours, lock) {
            JobResult::Stopped(stopped) => {
                assert_eq!(stopped.outcome, node::StopOutcome::Stopped);
                assert!(stopped.gone(), "{stopped:?}");
            }
            other => panic!("{other:?}"),
        }
        let status = watcher.join().expect("watcher").expect("wait");
        assert_eq!(status.signal(), Some(15));
        // Unloaded for this login session once, and nothing else ran.
        let runs = bridge::lab_tool_runs(&log);
        assert_eq!(runs.len(), 1, "{runs:?}");
        assert!(
            runs[0].contains("bootout") || runs[0].contains("--user stop"),
            "{runs:?}"
        );
        assert_eq!(
            bridge::lock_state_for_tests(&a),
            (true, Some("unloaded")),
            "a send starts no Raven now, and `raven unlock` loads the item again"
        );

        // `b`: Raven still answers after the stop, so the lock is taken
        // back; no login item of Raven's, so no tool runs.
        let mut sleeper = Command::new("sleep").arg("30").spawn().expect("sleep");
        let _still = testkit::FakeNode::start(
            &b,
            testkit::FakeStatus::listening(sleeper.id(), "0.0.0.0:7420"),
        );
        let lock = NodeJob::Lock {
            started_by_app: None,
            own_item: false,
            managed: false,
        };
        match node_job(&other, lock) {
            JobResult::Stopped(stopped) => {
                assert_eq!(stopped.outcome, node::StopOutcome::StillRunning);
                assert!(!stopped.gone());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(bridge::lock_state_for_tests(&b), (false, None));
        assert_eq!(bridge::lab_tool_runs(&log).len(), 1);
        let _ = sleeper.kill();
        let _ = sleeper.wait();
    }

    /// Runs this module's test `name` alone in a child process (see
    /// testkit::run_in_child): Some in the parent, None in the child.
    #[cfg(unix)]
    fn in_child(name: &str) -> Option<String> {
        testkit::run_in_child(&format!("{}::{name}", module_path!()))
    }

    #[cfg(unix)]
    fn in_child_exiting(name: &str, code: i32) -> Option<String> {
        testkit::run_in_child_exiting(&format!("{}::{name}", module_path!()), code)
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_reaches_the_ui_and_waits_for_a_critical_section() {
        if in_child("sigterm_reaches_the_ui_and_waits_for_a_critical_section").is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let critical = Critical::enter();
        start_signal_thread(tx).expect("signal handlers");
        bridge::kill_term(std::process::id()).expect("SIGTERM to this process");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(Msg::OsSignal(OsSignal::Terminate))
        );
        assert_eq!(received_signal(), Some(OsSignal::Terminate));
        // Past the grace period: the open section keeps the process alive.
        thread::sleep(SIGNAL_GRACE + Duration::from_millis(300));
        // Kept open, so the test's own end cannot race a forced exit.
        std::mem::forget(critical);
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_ends_the_process_when_the_ui_does_not() {
        if in_child_exiting("sigterm_ends_the_process_when_the_ui_does_not", 143).is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        start_signal_thread(tx).expect("signal handlers");
        bridge::kill_term(std::process::id()).expect("SIGTERM to this process");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(Msg::OsSignal(OsSignal::Terminate))
        );
        // The UI never answers: the signal thread restores and exits.
        thread::sleep(Duration::from_secs(10));
        panic!("still running 10 s after SIGTERM");
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_in_the_classic_menu_exits_at_once() {
        if in_child_exiting("sigterm_in_the_classic_menu_exits_at_once", 143).is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        set_signal_mode(SignalMode::Classic);
        start_signal_thread(tx).expect("signal handlers");
        bridge::kill_term(std::process::id()).expect("SIGTERM to this process");
        // Well within the grace period the Tui mode would give.
        thread::sleep(Duration::from_millis(800));
        panic!(
            "still running after SIGTERM in the classic menu ({:?})",
            rx.try_recv()
        );
    }
}
