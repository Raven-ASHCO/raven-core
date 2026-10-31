//! The engine's embedded node mode (docs/IOS.md): raven-node runs inside
//! the app's own process (raven-node's `embedded` host) instead of as a
//! program the engine starts.
//!
//! - **Chosen** at build time for iOS (the feature `embedded-node` is
//!   required there: an app may start no helper process) and at run time
//!   elsewhere with `RAVEN_NODE_MODE=embedded` (tests, and an app that wants
//!   it). Without the feature the engine starts the program, as before.
//! - **The same code paths.** The CLI's own start (ash's ext.rs, reached by
//!   `node.start`, a send, a retry) is pointed at the embedded node once
//!   ([`install`]), and every IPC request of this process goes to it in
//!   process (a socket pair: raven-core's `ipc::inproc`), so Status, the
//!   outbox, sends and the network ops read and do exactly what they do
//!   with the program.
//! - **What differs** is only what a process has and an app does not:
//!   `node.stop` stops the node in process (never a signal: its pid is the
//!   app's own), and the lifecycle ops `node.pause` (with `nearby: "keep"`,
//!   the background node that keeps Bluetooth nearby), `node.resume` and
//!   `mail.check`.

use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use ash_engine::engine as bridge;
use raven_node::embedded::{self as node, NodeConfig};

/// `RAVEN_NODE_MODE`: `embedded` runs the node in this process (any OS with
/// the feature), `process` or unset starts the program (not on iOS).
pub const NODE_MODE_ENV: &str = "RAVEN_NODE_MODE";

/// Whether this engine runs its node embedded: always on iOS, else when
/// [`NODE_MODE_ENV`] says `embedded`. Read once per process.
pub(crate) fn mode_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        cfg!(target_os = "ios")
            || std::env::var(NODE_MODE_ENV).is_ok_and(|v| v.trim() == "embedded")
    })
}

/// The hook the CLI's start calls in this process.
struct Embedded;

impl bridge::EmbeddedNode for Embedded {
    fn running(&self, data_dir: &Path) -> bool {
        node::running_for(data_dir)
    }

    fn start(&self, data_dir: &Path, listen: &str) -> Result<(), String> {
        node::start(&NodeConfig::new(data_dir, listen))
    }
}

static EMBEDDED: Embedded = Embedded;

/// Points this process at the embedded node, once: the CLI's starts go to
/// it, and IPC connects in process only (no socket file is ever tried).
pub(crate) fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        raven_core::ipc::inproc::set_embedded_only();
        bridge::set_embedded_node(&EMBEDDED);
    });
}

/// The node for `data_dir`, listening on `listen`.
pub(crate) fn config(data_dir: &Path, listen: &str) -> NodeConfig {
    NodeConfig::new(data_dir, listen)
}

/// `node.stop` in process: `true` when one was running.
pub(crate) fn stop() -> bool {
    node::stop(Duration::from_secs(8))
}

pub(crate) fn pause(data_dir: &Path) -> bool {
    KEPT_NEARBY.store(false, std::sync::atomic::Ordering::Relaxed);
    node::pause(data_dir)
}

/// The last pause kept Bluetooth nearby running (`node.pause {nearby:
/// "keep"}`, Task 2 Phase B).
static KEPT_NEARBY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `node.pause {nearby: "keep"}`: the full node stops and the background
/// node (Bluetooth nearby kept) starts; `Ok(was_running)`.
pub(crate) fn pause_keeping_nearby(data_dir: &Path, listen: &str) -> Result<bool, String> {
    let kept = node::pause_keeping_nearby(&config(data_dir, listen));
    KEPT_NEARBY.store(kept.is_ok(), std::sync::atomic::Ordering::Relaxed);
    kept
}

/// Whether the last `node.pause` kept Bluetooth nearby.
pub(crate) fn kept_nearby() -> bool {
    KEPT_NEARBY.load(std::sync::atomic::Ordering::Relaxed)
}

/// The app's Bluetooth permission (iOS), read without a prompt.
pub(crate) fn nearby_permission() -> Option<&'static str> {
    node::nearby_permission()
}

/// The pause ends; the caller starts the node (through the CLI's start).
/// The background node (Bluetooth kept) stops first, so that start is the
/// full node's.
pub(crate) fn end_pause() {
    if node::status().state == node::State::Background {
        node::stop(Duration::from_secs(8));
    }
    node::end_pause()
}

/// `lock.now` with no node running here (Lock v2): the lock is held in this
/// process and the next start is locked. `Ok(false)`: the gate is shut.
pub(crate) fn lock_while_stopped(data_dir: &Path) -> Result<bool, String> {
    node::lock_while_stopped(data_dir)
}

/// Lock v2 as this process holds it while no node runs for `data_dir`
/// (`None`: a node runs, it says itself, or the gate is shut).
pub(crate) fn held_while_stopped(data_dir: &Path) -> Option<bool> {
    if node::running_for(data_dir) {
        return None;
    }
    node::held_locked(data_dir)
}

pub(crate) fn state_word() -> &'static str {
    node::status().state.word()
}

pub(crate) fn check_mail(
    data_dir: &Path,
    listen: &str,
    budget: Duration,
) -> Result<node::MailCheck, String> {
    node::check_mail(&config(data_dir, listen), budget)
}

pub(crate) use node::MAIL_CHECK_MAX_BUDGET;
