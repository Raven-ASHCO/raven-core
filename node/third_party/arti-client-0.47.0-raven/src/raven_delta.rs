//! Raven's delta over arti-client 0.47.0 (`RAVEN_DELTA.md`).
//!
//! When a fresh consensus lists a Tor subprotocol as *required* and this
//! Arti lacks it, upstream writes a message on stderr and calls
//! `std::process::exit(1)` five seconds later (arti#1932). A program that
//! runs Tor inside a process it must not lose (Raven's iOS app runs the node
//! and Tor in the app's own process) can ask to be told instead:
//! [`on_unsupported_software`]. It must then stop using every [`TorClient`]
//! of the process (drop them and their runtime): an obsolete client may
//! harm the Tor network, which is why upstream exits.
//!
//! Without a hook nothing changes: the message, the wait, the exit.
//!
//! [`TorClient`]: crate::TorClient

use std::sync::OnceLock;
use std::time::Duration;

use tor_rtcompat::SleepProvider;

/// What runs instead of the exit.
type Hook = Box<dyn Fn() + Send + Sync>;

/// The process's hook, set at most once.
static UNSUPPORTED_SOFTWARE: OnceLock<Hook> = OnceLock::new();

/// Run `hook` instead of `std::process::exit(1)` when a fresh consensus
/// requires a Tor subprotocol this Arti lacks. Set once per process: `false`
/// when a hook was set already (the first one stays). The program must then
/// stop using every `TorClient` of the process.
pub fn on_unsupported_software(hook: Box<dyn Fn() + Send + Sync>) -> bool {
    UNSUPPORTED_SOFTWARE.set(hook).is_ok()
}

/// What the client does once such a consensus came (the protocol status
/// monitor's fatal path): the hook when one is set; else upstream's message
/// on stderr (`report`, then `hint`), a five-second wait for the logs, and
/// the exit.
#[allow(clippy::print_stderr)]
pub(crate) async fn unsupported_software<R: SleepProvider>(
    runtime: &R,
    report: String,
    hint: Option<String>,
) {
    if let Some(hook) = UNSUPPORTED_SOFTWARE.get() {
        hook();
        return;
    }
    eprintln!(
        "Shutting down because of unsupported software version.\nError was:\n{}",
        report
    );
    if let Some(hint) = hint {
        eprintln!("{}", hint);
    }
    // Give the tracing module a while to flush everything, since it has no
    // built-in flush function.
    runtime.sleep(Duration::new(5, 0)).await;
    std::process::exit(1);
}

/// For an embedding program's tests: the fatal path a consensus requiring a
/// missing subprotocol takes, with a made-up report. Without a hook it ends
/// the process, as the real one does.
#[doc(hidden)]
pub async fn simulate_unsupported_software<R: SleepProvider>(runtime: &R) {
    unsupported_software(
        runtime,
        "a subprotocol the Tor network requires is missing (simulated)".into(),
        None,
    )
    .await;
}
