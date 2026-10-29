//! raven-nearby-helper: the macOS nearby radio (P5.31; Nearby design step
//! 5.10; owner decision O5-10). raven-node (`nearby/apple.rs`) starts it
//! from RavenNearby.app and speaks the line protocol of
//! `nearby/apple/proto.rs` with it over stdin and stdout. It runs
//! CoreBluetooth and nothing else: it holds no keys, reads no profile and
//! writes no file. Its stderr is raven-node's log; nothing it logs names a
//! device.
//!
//! `--check` answers `hello`, or why it cannot run, and exits without
//! touching Bluetooth (the installers' and the tests' check).
//!
//! On other systems it only says it is unsupported.

// The state machine runs on macOS only; its tests run everywhere.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
mod cb;
mod machine;
// Shared with raven-node; the helper does not use every item.
#[allow(dead_code)]
#[path = "../../nearby/apple/proto.rs"]
mod proto;
#[cfg(test)]
mod tests;

/// What the helper says on a system without CoreBluetooth.
#[cfg(not(target_os = "macos"))]
const UNSUPPORTED: &str = "raven-nearby-helper runs on macOS only";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let check_only = match args.as_slice() {
        [] => false,
        [a] if a == "--check" => true,
        _ => {
            eprintln!("usage: raven-nearby-helper [--check]");
            std::process::exit(2);
        }
    };
    std::process::exit(run(check_only));
}

#[cfg(target_os = "macos")]
fn run(check_only: bool) -> i32 {
    cb::run(check_only)
}

#[cfg(not(target_os = "macos"))]
fn run(_check_only: bool) -> i32 {
    use std::io::Write as _;
    let line = proto::line(&proto::FromHelper::State {
        state: proto::Power::Unsupported,
        detail: UNSUPPORTED.to_owned(),
    });
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes()).and_then(|()| out.flush());
    0
}
