//! SIGPIPE in an app whose `main` is not Rust.
//!
//! A write to a socket or pipe whose other end is closed raises SIGPIPE,
//! and the signal's default action ends the process at once: no panic, no
//! error to handle, no crash report. A Rust program never meets it: the
//! runtime sets the action to "ignore" before `main`, and the write is then
//! the error `BrokenPipe`, which Raven handles wherever it writes (a program
//! that hangs up before its answer, a friend that closes a link).
//!
//! A node that runs inside an app in another language has had no such start
//! (an iPhone app's `main` is Swift). There the first such write ended the
//! app: on two iPhones, 2026-11-14, "App terminated due to signal 13" 25 s
//! after a send to a friend Tor did not reach, when the node answered the
//! in-process connection the send had closed by then (T3 a).
//!
//! So the embedded node does at its start what a Rust program's start does
//! ([`ignore_if_default`]), and its in-process connections raise no SIGPIPE
//! where the system can say so per socket ([`crate::ipc::inproc`]). Only
//! the default action is replaced: a handler the app installed is the app's
//! decision and stays.

/// Sets SIGPIPE's action to "ignore" if it is still the default. `true`
/// when this call changed it.
#[cfg(unix)]
pub fn ignore_if_default() -> bool {
    // SAFETY: with no new action, sigaction only fills `now` (plain data,
    // zeroed first); signal() then sets one action, as the Rust runtime
    // does before `main`.
    unsafe {
        let mut now: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut now) != 0
            || now.sa_sigaction != libc::SIG_DFL
        {
            return false;
        }
        libc::signal(libc::SIGPIPE, libc::SIG_IGN) != libc::SIG_ERR
    }
}

/// No SIGPIPE on this system.
#[cfg(not(unix))]
pub fn ignore_if_default() -> bool {
    false
}

/// For tests of what a process does with SIGPIPE's default action: a Rust
/// test program ignores the signal, and giving the default back would end
/// the whole program on another test's broken pipe. So such a test runs
/// again in a process of its own.
#[cfg(all(test, unix))]
pub(crate) mod testing {
    /// Names the test a child process runs ([`run_child`]).
    const CHILD_ENV: &str = "RAVEN_TEST_SIGPIPE_CHILD";

    /// `module_path!()` and a test's name as the test program names it.
    fn path(module: &str, test: &str) -> String {
        let module = module.split_once("::").map_or(module, |(_, rest)| rest);
        format!("{module}::{test}")
    }

    /// SIGPIPE's action now.
    pub(crate) fn action() -> libc::sighandler_t {
        // SAFETY: with no new action, sigaction only fills `now`.
        unsafe {
            let mut now: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut now),
                0
            );
            now.sa_sigaction
        }
    }

    /// Runs the test `test` of `module` alone in a new process and expects
    /// it to pass there; a signal that ended it is named.
    pub(crate) fn run_child(module: &str, test: &str) {
        let name = path(module, test);
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, &name)
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{name} failed ({}):\n{said}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        // `--exact` on a renamed test would run nothing and pass.
        assert!(said.contains("1 passed"), "{name} did not run:\n{said}");
    }

    /// Whether this process is the child that runs `test` of `module`
    /// ([`run_child`]). The child then has SIGPIPE's default action, as an
    /// app whose `main` is not Rust starts with it.
    pub(crate) fn child_with_default(module: &str, test: &str) -> bool {
        if !std::env::var(CHILD_ENV).is_ok_and(|v| v == path(module, test)) {
            return false;
        }
        // SAFETY: sets one signal's action in a process that runs one test.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
        assert_eq!(action(), libc::SIG_DFL);
        true
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    extern "C" fn the_apps_own(_signal: libc::c_int) {}

    /// The default action becomes "ignore", once; a handler the app
    /// installed stays as it is.
    #[test]
    fn the_default_becomes_ignore_and_an_apps_handler_stays() {
        testing::run_child(module_path!(), "default_and_handler_child");
    }

    #[test]
    fn default_and_handler_child() {
        if !testing::child_with_default(module_path!(), "default_and_handler_child") {
            return;
        }
        assert!(ignore_if_default());
        assert_eq!(testing::action(), libc::SIG_IGN);
        assert!(!ignore_if_default(), "nothing left to change");
        assert_eq!(testing::action(), libc::SIG_IGN);

        let handler = the_apps_own as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: installs a handler that does nothing, in a process that
        // runs this test only.
        unsafe {
            libc::signal(libc::SIGPIPE, handler);
        }
        assert!(!ignore_if_default(), "the app's handler is its decision");
        assert_eq!(testing::action(), handler);
    }

    /// A Rust program (this test program) ignores SIGPIPE from its start:
    /// nothing to change.
    #[test]
    fn a_rust_program_has_nothing_to_change() {
        assert_eq!(testing::action(), libc::SIG_IGN);
        assert!(!ignore_if_default());
    }
}
