//! The debug lab network audit (Phase 5 P5.28, carrier_matrix C56: the
//! cutoff study's Bluetooth-only island). With `RAVEN_LAB_NET_AUDIT=<file>`
//! in a debug build with the Lab Test A unlock, every system name lookup
//! and every outbound TCP connect of this process appends one word to that
//! file: `dns`, `connect_loopback` or `connect_other`. Counts only: never a
//! name, an address or a port. The file is the harness's own (outside any
//! profile) and a release build never reads the variable, so nothing here
//! ever runs there.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// The lab switch naming the audit file.
pub const LAB_NET_AUDIT: &str = "RAVEN_LAB_NET_AUDIT";

/// The audit file of this process, read once: `None` in a release build,
/// without the Lab Test A unlock, or with the switch unset.
fn audit_file() -> Option<&'static Mutex<PathBuf>> {
    static FILE: OnceLock<Option<Mutex<PathBuf>>> = OnceLock::new();
    FILE.get_or_init(|| {
        crate::pair_init::lab_test_a_enabled()
            .then(|| crate::p2p_gate::lab_switch(LAB_NET_AUDIT))
            .flatten()
            .map(|p| Mutex::new(PathBuf::from(p.trim())))
    })
    .as_ref()
}

/// One audited event (`dns`, `connect_loopback`, `connect_other`). Best
/// effort: an audit that cannot be written is lost, never an error.
pub fn note(what: &'static str) {
    if !cfg!(debug_assertions) {
        return;
    }
    let Some(file) = audit_file() else {
        return;
    };
    let path = file
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&*path)
    {
        let _ = writeln!(f, "{what}");
    }
}

/// A system name lookup is about to run.
pub fn dns() {
    note("dns");
}

/// An outbound TCP connect to `addr` is about to run.
pub fn connect(addr: &SocketAddr) {
    note(connect_word(addr));
}

/// The word [`connect`] writes: whether `addr` stays on this computer.
pub fn connect_word(addr: &SocketAddr) -> &'static str {
    if addr.ip().is_loopback() {
        "connect_loopback"
    } else {
        "connect_other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connects_are_told_apart_by_loopback_only() {
        for (addr, word) in [
            ("127.0.0.1:7", "connect_loopback"),
            ("[::1]:7", "connect_loopback"),
            ("192.168.1.2:7420", "connect_other"),
            ("[fe80::1]:7", "connect_other"),
        ] {
            assert_eq!(connect_word(&addr.parse().unwrap()), word, "{addr}");
        }
        // Without the switch, and in a release build whatever the
        // environment says, nothing is ever written.
        if std::env::var(LAB_NET_AUDIT).is_err() || !cfg!(debug_assertions) {
            assert!(audit_file().is_none());
            note("dns");
        }
    }
}
