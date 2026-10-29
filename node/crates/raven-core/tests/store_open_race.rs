//! Concurrent first opens of a fresh indexed-session store (the listener's
//! preflight and the outbox worker's first scan race at service start).
use std::sync::{Arc, Barrier};

#[test]
fn concurrent_first_opens_of_a_fresh_store_all_succeed() {
    for key in [
        "RAVEN_SESSION_BACKEND",
        "RAVEN_PREKEY_BACKEND",
        "RAVEN_IDENTITY_BACKEND",
    ] {
        // SAFETY: set before any thread starts; test-only lab backends.
        unsafe { std::env::set_var(key, "locked-file") };
    }
    let mut failures = Vec::new();
    for round in 0..25 {
        let dir = tempfile::tempdir().unwrap();
        let barrier = Arc::new(Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (dir, barrier) = (dir.path().to_path_buf(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    raven_core::IndexedSessionStore::open(&dir).map(|_| ())
                })
            })
            .collect();
        for h in handles {
            if let Err(e) = h.join().unwrap() {
                failures.push(format!("round {round}: {}", e.redacted_display()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failed opens: {:?}",
        failures.len(),
        &failures[..failures.len().min(3)]
    );
}
