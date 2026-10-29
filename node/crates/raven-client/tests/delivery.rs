//! A message from profile A to profile B through two real raven-node
//! processes on 127.0.0.1, on plain profiles (common/flow.rs; tests/privacy.rs
//! runs the same flow on sealed ones).
//!
//! Needs the raven-node that `cargo build` puts next to the test binaries'
//! folder; without it the test says so and passes.

mod common;

#[test]
fn delivered_only_after_a_signed_receipt() {
    common::lab_env();
    common::flow::delivered_only_after_a_signed_receipt(|dir, _| {
        // No lab switch: a debug build leaves the profiles plain.
        let book = std::fs::read(dir.join("contacts.json")).unwrap();
        assert!(!book.starts_with(b"RMS1"));
    });
}
