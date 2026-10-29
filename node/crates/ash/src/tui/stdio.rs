//! Output capture and platform probes for the full screen.
//!
//! While the screen is up, nothing the existing code prints may reach the
//! terminal, or it would land on top of the frame:
//!
//! - stdout: every `print!` / `println!` in cli.rs and its child modules goes
//!   through `print_stdout`, which asks [`divert_stdout`] first. A job's output
//!   lands in its [`JobCapture`]; anything else printed while the screen is up
//!   lands in the ring.
//! - stderr: `eprintln!` and raven-core's direct writes go to fd 2 (Unix) or
//!   STD_ERROR_HANDLE (Windows), which [`StderrRedirect`] points into a pipe
//!   that the stderr reader drains into the ring.
//!
//! Also here: [`quiet_stderr`], the Windows console probes (stopping
//! raven-node is node_control.rs's, outside the app: privacy pack PP.15),
//! and [`KeysIn`], where background.rs reads the terminal's answer to OSC
//! 11 before the input thread starts.
//! This is the only non-test tui file with `unsafe` (a testkit scan enforces
//! it): every FFI call says why it is sound and checks what it returns.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::background;

#[cfg(test)]
use super::testkit;

/// Most text one [`JobCapture`] keeps; the rest of the job's output is dropped.
const JOB_CAP: usize = 64 * 1024;
/// Lines the ring keeps; older ones are dropped.
const RING_LINES: usize = 256;
/// Most bytes one ring line keeps; the rest of the line is dropped.
const RING_LINE_CAP: usize = 4 * 1024;

// ── stdout ───────────────────────────────────────────────────────────────────

/// Set while the full screen is up. Owned by `TerminalGuard`, which sets it on
/// entering the screen and clears it before any plain-terminal output.
static SCREEN_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Stray output while the screen is up: stdout lines and the stderr reader's.
static RING: Mutex<CaptureRing> = Mutex::new(CaptureRing::new());

/// Numbers every [`JobCapture`], so one closed out of order never closes
/// another that happens to sit where it did.
static NEXT_JOB: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// This thread's open job captures as (number, text), innermost last.
    static JOBS: RefCell<Vec<(u64, String)>> = const { RefCell::new(Vec::new()) };
}

/// The hook at the top of `print_stdout`; true when it took the text:
///
/// 1. this thread has a [`JobCapture`]: the text goes there;
/// 2. otherwise, while the screen is up, it goes to the ring;
/// 3. otherwise false, and `print_stdout` writes to stdout as before.
pub(crate) fn divert_stdout(args: fmt::Arguments<'_>) -> bool {
    // The text is formatted before any borrow or lock is taken: a Display
    // impl may print too.
    if job_capture_open() {
        let text = fmt::format(args);
        with_jobs(|jobs| {
            if let Some((_, buf)) = jobs.last_mut() {
                push_capped(buf, &text, JOB_CAP);
            }
        });
        return true;
    }
    if SCREEN_ACTIVE.load(Ordering::Acquire) {
        let text = fmt::format(args);
        lock(&RING).push_text(&text);
        return true;
    }
    false
}

/// Called only by `TerminalGuard`: true from entering the screen until it
/// leaves it, or suspends it for a plain-terminal prompt.
pub(super) fn set_screen_active(on: bool) {
    SCREEN_ACTIVE.store(on, Ordering::Release);
}

/// The sequence number the next ring line gets. A job notes it before it
/// starts, so its Details can show the lines written while it ran.
pub(super) fn ring_next_seq() -> u64 {
    lock(&RING).next_seq()
}

/// Adds one whole line (the stderr reader's) and returns its sequence number.
pub(super) fn ring_push_line(line: &str) -> u64 {
    lock(&RING).push_line(line)
}

/// The ring lines still kept whose sequence numbers fall in `range`, oldest
/// first.
pub(super) fn ring_lines(range: Range<u64>) -> Vec<(u64, String)> {
    lock(&RING).lines(range)
}

/// The last [`RING_LINES`] lines of stray output, each cut at
/// [`RING_LINE_CAP`] bytes and numbered in the order they arrived.
pub(super) struct CaptureRing {
    lines: VecDeque<String>,
    /// The sequence number of `lines[0]`, or of the next line when empty.
    first_seq: u64,
    /// A stdout line whose newline has not been printed yet.
    partial: String,
}

impl CaptureRing {
    pub(super) const fn new() -> Self {
        CaptureRing {
            lines: VecDeque::new(),
            first_seq: 0,
            partial: String::new(),
        }
    }

    pub(super) fn next_seq(&self) -> u64 {
        self.first_seq + self.lines.len() as u64
    }

    /// Adds one whole line, dropping the oldest when full; returns its number.
    pub(super) fn push_line(&mut self, line: &str) -> u64 {
        let seq = self.next_seq();
        if self.lines.len() == RING_LINES {
            self.lines.pop_front();
            self.first_seq += 1;
        }
        self.lines.push_back(capped(line, RING_LINE_CAP).to_owned());
        seq
    }

    /// Adds stdout text: each newline ends a ring line, and the text after
    /// the last one waits for the rest of its line.
    pub(super) fn push_text(&mut self, text: &str) {
        let mut rest = text;
        while let Some(end) = rest.find('\n') {
            push_capped(&mut self.partial, &rest[..end], RING_LINE_CAP);
            let line = std::mem::take(&mut self.partial);
            self.push_line(&line);
            rest = &rest[end + 1..];
        }
        push_capped(&mut self.partial, rest, RING_LINE_CAP);
    }

    /// The kept lines whose sequence numbers fall in `range`, oldest first.
    pub(super) fn lines(&self, range: Range<u64>) -> Vec<(u64, String)> {
        let start = range.start.max(self.first_seq);
        let end = range.end.min(self.next_seq());
        (start..end)
            .map(|seq| (seq, self.lines[(seq - self.first_seq) as usize].clone()))
            .collect()
    }
}

/// Collects what `print!` / `println!` write on this thread, from `start` to
/// `finish`, instead of the terminal or the ring ([`JOB_CAP`] bytes at most).
///
/// Captures nest: when an inner one finishes, its text also lands in the one
/// around it, so each capture holds everything its thread printed while it
/// was open. A capture dropped without `finish` does the same, and its text
/// is otherwise discarded.
#[must_use = "a capture collects output only until it is finished or dropped"]
pub(super) struct JobCapture {
    /// This capture's number in JOBS; None once closed, or when this thread's
    /// locals were already gone when it started.
    id: Option<u64>,
    /// Captures are per thread, so one must never move to another thread.
    _this_thread: PhantomData<*const ()>,
}

impl JobCapture {
    pub(super) fn start() -> JobCapture {
        let id = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
        let id = with_jobs(|jobs| {
            jobs.push((id, String::new()));
            id
        });
        JobCapture {
            id,
            _this_thread: PhantomData,
        }
    }

    /// Stops capturing and returns what this thread printed meanwhile.
    pub(super) fn finish(mut self) -> String {
        self.close()
    }

    fn close(&mut self) -> String {
        let Some(id) = self.id.take() else {
            return String::new();
        };
        with_jobs(|jobs| {
            // Gone when a capture around this one closed first: its text went
            // along with that one's.
            let Some(at) = jobs.iter().position(|(open, _)| *open == id) else {
                return String::new();
            };
            // Captures opened inside this one and never closed end with it.
            let mut text = String::new();
            for (_, inner) in jobs.split_off(at) {
                push_capped(&mut text, &inner, JOB_CAP);
            }
            if let Some((_, outer)) = jobs.last_mut() {
                push_capped(outer, &text, JOB_CAP);
            }
            text
        })
        .unwrap_or_default()
    }
}

impl Drop for JobCapture {
    fn drop(&mut self) {
        self.close();
    }
}

fn job_capture_open() -> bool {
    JOBS.try_with(|jobs| jobs.try_borrow().is_ok_and(|jobs| !jobs.is_empty()))
        .unwrap_or(false)
}

/// Runs `f` on this thread's open captures; None once the thread's locals
/// are being torn down.
fn with_jobs<R>(f: impl FnOnce(&mut Vec<(u64, String)>) -> R) -> Option<R> {
    JOBS.try_with(|jobs| jobs.try_borrow_mut().ok().map(|mut jobs| f(&mut jobs)))
        .ok()
        .flatten()
}

/// The longest start of `text` that fits in `cap` bytes, cut between chars.
fn capped(text: &str, cap: usize) -> &str {
    let mut end = cap.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Appends as much of `text` as keeps `buf` within `cap` bytes.
fn push_capped(buf: &mut String, text: &str, cap: usize) {
    buf.push_str(capped(text, cap.saturating_sub(buf.len())));
}

/// Locks `mutex`, carrying on after a panic elsewhere: what it guards (text,
/// or the saved stderr) is valid after any partial update, and losing the
/// terminal's stderr over a poisoned lock would be worse.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ── stderr ───────────────────────────────────────────────────────────────────

/// The terminal's own stderr while the redirect is armed; None before `arm`
/// and after `disarm`. Taking it out is what makes disarming idempotent, and
/// the lock keeps [`pass_through`] from writing to a descriptor that disarm
/// has closed.
static ORIGINAL: Mutex<Option<os::Original>> = Mutex::new(None);

/// Set by the first `arm`: the redirect is armed at most once per process
/// (`suspend_full` switches to passthrough instead).
static ARMED_ONCE: AtomicBool = AtomicBool::new(false);

/// Set while a plain-terminal prompt is up and stderr must reach it.
static PASSTHROUGH: AtomicBool = AtomicBool::new(false);

/// stderr pointed into a pipe while the full screen is up, so `eprintln!` and
/// raven-core's direct writes reach the stderr reader instead of the frame.
/// Dropping it disarms.
pub(super) struct StderrRedirect {
    _private: (),
}

impl StderrRedirect {
    /// Points stderr into a new pipe and returns the pipe's read end. Called
    /// once per session, before any thread that can spawn a process exists.
    ///
    /// Unix: both pipe ends and the saved fd 2 are close-on-exec, so a child
    /// (the detached raven-node, the vault's `stty`) inherits none of them;
    /// fd 2 itself stays inheritable, as dup2 leaves it. Windows: the pipe
    /// handles are not inheritable.
    pub(super) fn arm() -> io::Result<(StderrRedirect, File)> {
        let mut original = lock(&ORIGINAL);
        if ARMED_ONCE.swap(true, Ordering::AcqRel) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "stderr was already redirected once in this process",
            ));
        }
        match os::arm() {
            Ok((saved, reader)) => {
                *original = Some(saved);
                Ok((StderrRedirect { _private: () }, reader))
            }
            Err(e) => {
                ARMED_ONCE.store(false, Ordering::Release);
                Err(e)
            }
        }
    }

    /// While on, the stderr reader also copies what it reads to the
    /// terminal's own stderr ([`pass_through`]): the vault's plain-terminal
    /// prompt shows its errors there.
    pub(super) fn set_passthrough(&self, on: bool) {
        PASSTHROUGH.store(on, Ordering::Release);
    }

    /// Puts the terminal's own stderr back ([`restore_stderr`]).
    pub(super) fn disarm(&self) -> io::Result<()> {
        restore_stderr()
    }
}

impl Drop for StderrRedirect {
    fn drop(&mut self) {
        // Nowhere is left to report a failure: stderr is what failed.
        let _ = restore_stderr();
    }
}

/// Puts the terminal's own stderr back if the redirect is armed, and does
/// nothing otherwise, so `disarm`, Drop and the panic hook can all call it.
/// The pipe's write end closes with it, so the reader sees end-of-file.
pub(super) fn restore_stderr() -> io::Result<()> {
    let Some(original) = lock(&ORIGINAL).take() else {
        return Ok(());
    };
    PASSTHROUGH.store(false, Ordering::Release);
    os::restore(original)
}

/// The stderr reader hands each chunk it reads here; while passthrough is on,
/// the chunk also goes to the terminal's own stderr. Errors are ignored:
/// nowhere is left to report them.
pub(super) fn pass_through(bytes: &[u8]) {
    if !PASSTHROUGH.load(Ordering::Acquire) {
        return;
    }
    if let Some(original) = lock(&ORIGINAL).as_ref() {
        let _ = original.write_all(bytes);
    }
}

/// Points stderr at /dev/null (Windows: NUL) for the rest of the process, so
/// writers never block on a pipe nobody reads. The stderr reader calls it
/// when it cannot go on.
pub(super) fn quiet_stderr() -> io::Result<()> {
    os::quiet_stderr()
}

// ── Windows probes ───────────────────────────────────────────────────────────

/// Whether this console can show the full screen: stdin and stdout are both
/// console handles and stdout accepts VT sequences (Windows 10 and later, not
/// the legacy console). TERM is not consulted: Git Bash sets it over a pipe
/// that is no console. The console is left in the mode it was found in.
/// Always true off Windows.
pub(super) fn windows_console_ok() -> bool {
    os::console_ok()
}

/// The console's output code page (GetConsoleOutputCP); None off Windows or
/// without a console.
pub(super) fn output_code_page() -> Option<u32> {
    os::output_code_page()
}

/// Whether Windows reports a running screen reader (SPI_GETSCREENREADER).
/// Always false off Windows.
pub(super) fn screen_reader_running() -> bool {
    os::screen_reader_running()
}

/// The terminal's keys (stdin, in raw mode), read directly for the answers
/// to background.rs's questions at start, before the input thread exists.
/// On Unix only: on Windows nothing is ever readable, so nothing is read.
pub(super) struct KeysIn;

impl background::Answers for KeysIn {
    fn readable(&mut self, within: Duration) -> bool {
        os::keys_readable(within)
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        os::keys_read(buf)
    }

    fn discard(&mut self) {
        os::keys_discard();
    }
}

/// How many processes share this console (GetConsoleProcessList); 1 means
/// Raven was started by a double-click and its window closes when it exits.
/// None off Windows or without a console.
pub(super) fn console_process_count() -> Option<u32> {
    os::console_process_count()
}

#[cfg(unix)]
mod os {
    use std::ffi::{c_int, c_short, c_void};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;

    extern "C" {
        fn pipe(fds: *mut c_int) -> c_int;
        fn dup(fd: c_int) -> c_int;
        fn dup2(from: c_int, to: c_int) -> c_int;
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        fn poll(fds: *mut PollFd, nfds: NFds, timeout: c_int) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        fn tcflush(fd: c_int, queue: c_int) -> c_int;
    }

    /// poll(2)'s `struct pollfd`: the same layout on Linux, macOS and the
    /// BSDs.
    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }

    /// `nfds_t`: unsigned long on Linux, unsigned int on macOS and the BSDs.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    type NFds = std::ffi::c_ulong;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    type NFds = std::ffi::c_uint;

    const POLLIN: c_short = 1;
    /// tcflush's input queue: 0 on Linux, 1 on macOS and the BSDs.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TCIFLUSH: c_int = 0;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const TCIFLUSH: c_int = 1;
    const STDIN: c_int = 0;

    /// Whether stdin has something to read within `within`. An error (a
    /// signal in between, too) is nothing to read.
    pub(super) fn keys_readable(within: Duration) -> bool {
        let timeout = c_int::try_from(within.as_millis()).unwrap_or(c_int::MAX);
        let mut fd = PollFd {
            fd: STDIN,
            events: POLLIN,
            revents: 0,
        };
        // Sound: one pollfd that lives across the call, nfds 1.
        let ready = unsafe { poll(&mut fd, 1, timeout) };
        ready == 1 && fd.revents & POLLIN != 0
    }

    /// What stdin has now, into `buf` (poll said it has some, so it does not
    /// block): how much; 0 at its end or on an error.
    pub(super) fn keys_read(buf: &mut [u8]) -> usize {
        // Sound: `buf` is valid for `buf.len()` bytes and written only up to
        // what read returns.
        let n = unsafe { read(STDIN, buf.as_mut_ptr().cast(), buf.len()) };
        usize::try_from(n).unwrap_or(0)
    }

    /// Drops what the terminal sent and nobody read: an answer that came
    /// late never reaches the input thread as keys.
    pub(super) fn keys_discard() {
        // Sound: a plain call on fd 0; an error (not a terminal) leaves it.
        let _ = unsafe { tcflush(STDIN, TCIFLUSH) };
    }

    // The same values on Linux, macOS and the BSDs.
    const F_SETFD: c_int = 2;
    const FD_CLOEXEC: c_int = 1;
    const STDERR: c_int = 2;

    /// The terminal's own stderr: the close-on-exec copy of fd 2 that `arm`
    /// took. Closed when dropped.
    pub(super) struct Original {
        saved: File,
    }

    impl Original {
        pub(super) fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
            (&self.saved).write_all(bytes)
        }
    }

    pub(super) fn arm() -> io::Result<(Original, File)> {
        let mut fds: [c_int; 2] = [-1; 2];
        // SAFETY: pipe(2) writes two descriptors into the array it is given,
        // and `fds` is a live, writable [c_int; 2].
        if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe(2) succeeded, so both are open descriptors that nothing
        // else owns; from here on they close on every early return.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        set_cloexec(read.as_raw_fd())?;
        set_cloexec(write.as_raw_fd())?;
        // SAFETY: dup(2) takes a plain descriptor number and reports a closed
        // fd 2 as -1.
        let saved = unsafe { dup(STDERR) };
        if saved < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: dup(2) succeeded, so `saved` is an open descriptor that
        // nothing else owns.
        let saved = unsafe { OwnedFd::from_raw_fd(saved) };
        set_cloexec(saved.as_raw_fd())?;
        point_at(write.as_raw_fd(), STDERR)?;
        // close(write): fd 2 is now the pipe's only write end, so the reader
        // sees end-of-file once fd 2 is restored.
        drop(write);
        Ok((
            Original {
                saved: File::from(saved),
            },
            File::from(read),
        ))
    }

    pub(super) fn restore(original: Original) -> io::Result<()> {
        // `saved` closes when `original` drops here; fd 2 keeps its own copy.
        point_at(original.saved.as_raw_fd(), STDERR)
    }

    pub(super) fn quiet_stderr() -> io::Result<()> {
        let null = OpenOptions::new().write(true).open("/dev/null")?;
        point_at(null.as_raw_fd(), STDERR)
    }

    pub(super) fn console_ok() -> bool {
        true
    }

    pub(super) fn output_code_page() -> Option<u32> {
        None
    }

    pub(super) fn screen_reader_running() -> bool {
        false
    }

    pub(super) fn console_process_count() -> Option<u32> {
        None
    }

    fn set_cloexec(fd: c_int) -> io::Result<()> {
        // SAFETY: F_SETFD takes one int argument and changes only the flags of
        // `fd`, an open descriptor that the caller owns.
        if unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// dup2(from, to), tried again when a signal interrupts it.
    fn point_at(from: c_int, to: c_int) -> io::Result<()> {
        loop {
            // SAFETY: dup2(2) takes plain descriptor numbers; `from` is open
            // (the caller holds it), and replacing `to` is the point.
            if unsafe { dup2(from, to) } == to {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}

#[cfg(windows)]
mod os {
    use std::ffi::c_void;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::mem::ManuallyDrop;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
    use std::ptr::null_mut;

    /// Never asked on Windows (background.rs): nothing to read.
    pub(super) fn keys_readable(_within: std::time::Duration) -> bool {
        false
    }

    pub(super) fn keys_read(_buf: &mut [u8]) -> usize {
        0
    }

    pub(super) fn keys_discard() {}

    type Bool = i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreatePipe(
            read: *mut RawHandle,
            write: *mut RawHandle,
            attributes: *mut c_void,
            size: u32,
        ) -> Bool;
        fn GetStdHandle(which: u32) -> RawHandle;
        fn SetStdHandle(which: u32, handle: RawHandle) -> Bool;
        fn GetConsoleMode(console: RawHandle, mode: *mut u32) -> Bool;
        fn SetConsoleMode(console: RawHandle, mode: u32) -> Bool;
        fn GetConsoleOutputCP() -> u32;
        fn GetConsoleProcessList(ids: *mut u32, count: u32) -> u32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn SystemParametersInfoW(action: u32, param: u32, value: *mut c_void, ini: u32) -> Bool;
    }

    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    const SPI_GETSCREENREADER: u32 = 0x0046;
    /// INVALID_HANDLE_VALUE, which GetStdHandle returns on failure.
    const INVALID_HANDLE: isize = -1;

    /// The stderr handle the process had before `arm` (not ours: never
    /// closed here) and the pipe's write end (ours: closed when dropped).
    pub(super) struct Original {
        /// Kept as an integer so the static holding it can be shared.
        saved: usize,
        write: OwnedHandle,
    }

    impl Original {
        pub(super) fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
            let handle = self.saved as RawHandle;
            if handle.is_null() || handle as isize == INVALID_HANDLE {
                // The process started without a stderr: nowhere to copy to.
                return Ok(());
            }
            // SAFETY: `handle` is the process's stderr from before `arm`,
            // still open (nothing here closes it), and ManuallyDrop keeps this
            // File from closing it.
            let file = ManuallyDrop::new(unsafe { File::from_raw_handle(handle) });
            (&*file).write_all(bytes)
        }
    }

    pub(super) fn arm() -> io::Result<(Original, File)> {
        let mut read: RawHandle = null_mut();
        let mut write: RawHandle = null_mut();
        // SAFETY: CreatePipe writes one handle through each pointer, both live
        // locals. Null security attributes: neither handle is inheritable.
        if unsafe { CreatePipe(&mut read, &mut write, null_mut(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreatePipe succeeded, so both are open handles that nothing
        // else owns; from here on they close on every early return.
        let (read, write) = unsafe {
            (
                File::from_raw_handle(read),
                OwnedHandle::from_raw_handle(write),
            )
        };
        // SAFETY: GetStdHandle only reads this process's handle table.
        let saved = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        if saved as isize == INVALID_HANDLE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: SetStdHandle stores the handle value; `write` stays open
        // until `restore` has put `saved` back. std looks the handle up on
        // every write to stderr.
        if unsafe { SetStdHandle(STD_ERROR_HANDLE, write.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            Original {
                saved: saved as usize,
                write,
            },
            read,
        ))
    }

    pub(super) fn restore(original: Original) -> io::Result<()> {
        // SAFETY: SetStdHandle stores the handle value; `saved` is the handle
        // the process had before `arm`, which nothing has closed.
        if unsafe { SetStdHandle(STD_ERROR_HANDLE, original.saved as RawHandle) } == 0 {
            let e = io::Error::last_os_error();
            // stderr still names the pipe's write end: leave it open, so no
            // write ever reaches a reused handle value.
            let _still_stderr = original.write.into_raw_handle();
            return Err(e);
        }
        // Dropping `original` closes the write end, so the reader sees
        // end-of-file.
        Ok(())
    }

    pub(super) fn quiet_stderr() -> io::Result<()> {
        let nul = OpenOptions::new().write(true).open("NUL")?;
        // SAFETY: SetStdHandle stores the handle value; `nul` is never closed
        // (into_raw_handle below), so it stays valid for the whole process.
        if unsafe { SetStdHandle(STD_ERROR_HANDLE, nul.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _stays_open = nul.into_raw_handle();
        Ok(())
    }

    pub(super) fn console_ok() -> bool {
        // SAFETY: GetStdHandle only reads this process's handle table.
        let (input, output) = unsafe {
            (
                GetStdHandle(STD_INPUT_HANDLE),
                GetStdHandle(STD_OUTPUT_HANDLE),
            )
        };
        let (mut in_mode, mut out_mode) = (0u32, 0u32);
        // SAFETY: GetConsoleMode writes one u32 through the pointer, a live
        // local, and fails for any handle that is not a console (null and
        // INVALID_HANDLE_VALUE included).
        let consoles = unsafe {
            GetConsoleMode(input, &mut in_mode) != 0 && GetConsoleMode(output, &mut out_mode) != 0
        };
        if !consoles {
            return false;
        }
        if out_mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        // SAFETY: SetConsoleMode takes plain values, and `output` is a console
        // handle (GetConsoleMode accepted it).
        if unsafe { SetConsoleMode(output, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) } == 0 {
            // The legacy console refuses VT sequences.
            return false;
        }
        // Put the mode back, so the classic menu runs exactly as before;
        // crossterm turns VT on again itself when the full screen starts.
        // SAFETY: as above, with the mode the console just reported. Should it
        // fail, VT stays on, which is harmless.
        let _restored = unsafe { SetConsoleMode(output, out_mode) };
        true
    }

    pub(super) fn output_code_page() -> Option<u32> {
        // SAFETY: GetConsoleOutputCP takes no arguments; it returns 0 when the
        // process has no console.
        let page = unsafe { GetConsoleOutputCP() };
        (page != 0).then_some(page)
    }

    pub(super) fn screen_reader_running() -> bool {
        let mut running: Bool = 0;
        // SAFETY: SPI_GETSCREENREADER writes one BOOL through `value`, which
        // points at a live local; the other two arguments must be 0.
        let ok = unsafe {
            SystemParametersInfoW(
                SPI_GETSCREENREADER,
                0,
                (&mut running as *mut Bool).cast(),
                0,
            )
        };
        ok != 0 && running != 0
    }

    pub(super) fn console_process_count() -> Option<u32> {
        let mut ids = [0u32; 4];
        // SAFETY: GetConsoleProcessList writes at most `ids.len()` ids into
        // the live array, and returns the total count (0 on failure) even
        // when the array is too small to hold them all.
        let count = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) };
        (count != 0).then_some(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::process::{Command, Stdio};

    /// What a stderr test prints once fd 2 is back; its parent looks for it.
    #[cfg(unix)]
    const RESTORED: &str = "stderr-is-back-on-the-terminal";

    #[cfg(unix)]
    const KEYCHAIN_LINE: &str =
        "raven: still waiting for macOS Keychain access (your Raven identity)\n";

    /// Runs this module's test `name` alone in a child process: Some(output)
    /// in the parent, None in the child (see testkit::run_in_child).
    fn in_child(name: &str) -> Option<String> {
        testkit::run_in_child(&format!("{}::{name}", module_path!()))
    }

    #[test]
    fn job_capture_keeps_only_its_own_threads_output() {
        let capture = JobCapture::start();
        println!("from the job");
        print!("no newline");
        std::thread::spawn(|| println!("from another thread"))
            .join()
            .unwrap();
        assert_eq!(capture.finish(), "from the job\nno newline");
        // No test in this process puts the screen up, so nothing takes it now.
        assert!(!divert_stdout(format_args!("after the job\n")));
    }

    #[test]
    fn job_captures_nest_and_stop_at_64_kib() {
        let outer = JobCapture::start();
        println!("a");
        let inner = JobCapture::start();
        println!("b");
        assert_eq!(inner.finish(), "b\n");
        let dropped = JobCapture::start();
        println!("c");
        drop(dropped);
        assert_eq!(outer.finish(), "a\nb\nc\n");

        // An inner capture that outlives the one around it closes nothing else.
        let outer = JobCapture::start();
        let stale = JobCapture::start();
        assert_eq!(outer.finish(), "");
        let first = JobCapture::start();
        let second = JobCapture::start();
        drop(stale);
        println!("d");
        assert_eq!(second.finish(), "d\n");
        assert_eq!(first.finish(), "d\n");

        let capture = JobCapture::start();
        // 3-byte chars: the cap falls inside one, which is dropped whole.
        let chunk = "€".repeat(1000);
        for _ in 0..30 {
            print!("{chunk}");
        }
        let text = capture.finish();
        assert_eq!(text.len(), JOB_CAP - JOB_CAP % 3);
        assert!(text.chars().all(|c| c == '€'));
    }

    #[test]
    fn ring_is_bounded_and_numbered() {
        let mut ring = CaptureRing::new();
        assert_eq!(ring.next_seq(), 0);
        for n in 0..300 {
            assert_eq!(ring.push_line(&format!("line {n}")), n);
        }
        assert_eq!(ring.next_seq(), 300);
        let kept = ring.lines(0..u64::MAX);
        assert_eq!(kept.len(), RING_LINES);
        assert_eq!(kept[0], (44, "line 44".to_owned()));
        assert_eq!(kept[RING_LINES - 1], (299, "line 299".to_owned()));
        assert!(kept.windows(2).all(|pair| pair[1].0 == pair[0].0 + 1));
        assert!(ring.lines(0..44).is_empty(), "dropped lines are gone");
        assert_eq!(ring.lines(298..400).len(), 2);

        // stdout text becomes lines at its newlines; long lines stop at 4 KiB.
        let seq = ring.next_seq();
        ring.push_text("half a ");
        ring.push_text("line\nsecond\nthird, ");
        ring.push_text(&"x".repeat(5000));
        ring.push_text("\n");
        ring.push_line(&"y".repeat(5000));
        let lines: Vec<String> = ring
            .lines(seq..ring.next_seq())
            .into_iter()
            .map(|(_, line)| line)
            .collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "half a line");
        assert_eq!(lines[1], "second");
        assert_eq!(lines[2].len(), RING_LINE_CAP);
        assert!(lines[2].starts_with("third, xxx"));
        assert_eq!(lines[3], "y".repeat(RING_LINE_CAP));
    }

    #[test]
    fn screen_active_sends_stray_output_to_the_ring_until_cleared() {
        if in_child("screen_active_sends_stray_output_to_the_ring_until_cleared").is_some() {
            return;
        }
        let seq = ring_next_seq();
        assert!(!divert_stdout(format_args!("before the screen\n")));
        set_screen_active(true);
        assert!(divert_stdout(format_args!("direct\n")));
        println!("through println");
        let reader_seq = ring_push_line("from the stderr reader");
        assert_eq!(reader_seq, seq + 2);
        let job = JobCapture::start();
        println!("a job's own output");
        assert_eq!(
            job.finish(),
            "a job's own output\n",
            "a job capture comes before the ring"
        );
        set_screen_active(false);
        assert!(!divert_stdout(format_args!("after the screen\n")));
        let lines: Vec<String> = ring_lines(seq..ring_next_seq())
            .into_iter()
            .map(|(_, line)| line)
            .collect();
        assert_eq!(
            lines,
            ["direct", "through println", "from the stderr reader"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn redirect_captures_stderr_and_restores_fd_2() {
        if let Some(out) = in_child("redirect_captures_stderr_and_restores_fd_2") {
            assert!(out.contains(RESTORED), "fd 2 was not restored:\n{out}");
            assert!(
                !out.contains("still waiting"),
                "the redirected line reached the terminal:\n{out}"
            );
            return;
        }
        let (redirect, mut reader) = StderrRedirect::arm().expect("arm");
        io::stderr()
            .write_all(KEYCHAIN_LINE.as_bytes())
            .expect("write into the pipe");
        redirect.disarm().expect("disarm");
        let mut got = String::new();
        // fd 2 was the pipe's only write end, so this ends.
        reader.read_to_string(&mut got).expect("read the pipe");
        assert_eq!(got, KEYCHAIN_LINE);
        eprintln!("{RESTORED}");
    }

    /// The descriptors from 3 to 9 that a freshly spawned shell holds.
    #[cfg(unix)]
    fn descriptors_a_child_inherits() -> Vec<u32> {
        let out = Command::new("/bin/sh")
            .args([
                "-c",
                "for f in 3 4 5 6 7 8 9; do [ -e /dev/fd/$f ] && echo $f; done; true",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("run /bin/sh");
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .map(|fd| fd.parse().expect("a descriptor number"))
            .collect()
    }

    /// The descriptors from 3 to 9 open in this process.
    #[cfg(unix)]
    fn own_descriptors() -> Vec<u32> {
        (3..=9)
            .filter(|fd| std::path::Path::new(&format!("/dev/fd/{fd}")).exists())
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn armed_redirect_leaks_no_descriptor_to_a_child() {
        if in_child("armed_redirect_leaks_no_descriptor_to_a_child").is_some() {
            return;
        }
        // Whatever the test runner itself passes down shows up in both lists.
        let before = descriptors_a_child_inherits();
        let mine = own_descriptors();
        let (redirect, reader) = StderrRedirect::arm().expect("arm");
        let opened: Vec<u32> = own_descriptors()
            .into_iter()
            .filter(|fd| !mine.contains(fd))
            .collect();
        let armed = descriptors_a_child_inherits();
        redirect.disarm().expect("disarm");
        drop(reader);
        // The pipe's read end and the saved fd 2; the write end is fd 2 itself.
        assert_eq!(
            opened.len(),
            2,
            "the check must cover the redirect's own descriptors, got {opened:?}"
        );
        assert_eq!(
            armed, before,
            "a child spawned while armed inherited the pipe or the saved fd 2 {opened:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn disarm_twice_is_harmless_and_arm_is_once_per_process() {
        if let Some(out) = in_child("disarm_twice_is_harmless_and_arm_is_once_per_process") {
            assert!(out.contains(RESTORED), "fd 2 was not restored:\n{out}");
            return;
        }
        let (redirect, reader) = StderrRedirect::arm().expect("arm");
        redirect.disarm().expect("first disarm");
        redirect.disarm().expect("second disarm");
        restore_stderr().expect("the panic hook's call, after disarm");
        drop(redirect);
        drop(reader);
        let again = StderrRedirect::arm().map(|_| ()).map_err(|e| e.kind());
        assert_eq!(again, Err(io::ErrorKind::AlreadyExists));
        eprintln!("{RESTORED}");
    }

    #[cfg(unix)]
    #[test]
    fn quiet_stderr_keeps_writes_working_with_no_reader() {
        if let Some(out) = in_child("quiet_stderr_keeps_writes_working_with_no_reader") {
            assert!(out.contains(RESTORED), "fd 2 was not restored:\n{out}");
            assert!(!out.contains("nobody reads"), "{out}");
            return;
        }
        let (redirect, reader) = StderrRedirect::arm().expect("arm");
        drop(reader);
        let refused = io::stderr()
            .write_all(b"nobody reads this\n")
            .map_err(|e| e.kind());
        assert_eq!(refused, Err(io::ErrorKind::BrokenPipe));
        quiet_stderr().expect("quiet_stderr");
        // Far more than any pipe holds: /dev/null takes it all.
        io::stderr()
            .write_all(&vec![b'x'; 1 << 20])
            .expect("write after quiet_stderr");
        redirect.disarm().expect("disarm");
        eprintln!("{RESTORED}");
    }

    #[cfg(unix)]
    #[test]
    fn passthrough_copies_to_the_terminal_stderr() {
        if let Some(out) = in_child("passthrough_copies_to_the_terminal_stderr") {
            assert!(out.contains("shown while suspended"), "{out}");
            assert!(!out.contains("kept off the terminal"), "{out}");
            return;
        }
        let (redirect, _reader) = StderrRedirect::arm().expect("arm");
        pass_through(b"kept off the terminal\n");
        redirect.set_passthrough(true);
        pass_through(b"shown while suspended\n");
        redirect.disarm().expect("disarm");
        pass_through(b"kept off the terminal after disarm\n");
    }

    #[cfg(not(windows))]
    #[test]
    fn probes_report_a_plain_terminal_off_windows() {
        assert!(windows_console_ok());
        assert_eq!(output_code_page(), None);
        assert!(!screen_reader_running());
        assert_eq!(console_process_count(), None);
    }

    #[cfg(windows)]
    #[test]
    fn probes_answer_on_windows() {
        // Whatever console the test runner has, often none: they just answer.
        let _ = (
            windows_console_ok(),
            output_code_page(),
            screen_reader_running(),
            console_process_count(),
        );
    }
}
