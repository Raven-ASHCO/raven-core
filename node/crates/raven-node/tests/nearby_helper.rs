//! P5.31: raven-nearby-helper, the macOS nearby radio, with no radio
//! (feature `nearby-radio`). Run outside RavenNearby.app it has no
//! Bluetooth usage description, so it says `unauthorized` and exits cleanly
//! before any CoreBluetooth call (the macOS CI runner has no Bluetooth
//! permission either). In a bundle made from the repository's Info.plist,
//! `--check` finds the description and says `hello`; it, too, creates no
//! CoreBluetooth manager. On other systems the helper says it is
//! unsupported.

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

fn helper() -> Command {
    Command::new(env!("CARGO_BIN_EXE_raven-nearby-helper"))
}

/// The helper's lines, as JSON.
fn lines(out: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l:?}: {e}")))
        .collect()
}

/// Exited by itself with code 0: no crash, no signal.
fn clean(out: &Output) {
    assert_eq!(
        out.status.code(),
        Some(0),
        "{:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Its one line: it cannot run here, and why.
fn says_it_cannot_run(out: &Output) {
    clean(out);
    let said = lines(out);
    assert_eq!(said.len(), 1, "{said:?}");
    assert_eq!(said[0]["ev"], "state");
    let detail = said[0]["detail"].as_str().unwrap();
    if cfg!(target_os = "macos") {
        assert_eq!(said[0]["state"], "unauthorized");
        assert!(detail.starts_with("no usage description"), "{detail}");
        assert!(
            detail.contains("NSBluetoothAlwaysUsageDescription"),
            "{detail}"
        );
    } else {
        assert_eq!(said[0]["state"], "unsupported");
        assert!(detail.contains("macOS only"), "{detail}");
    }
}

/// Started as raven-node starts it (stdin and stdout piped) but outside its
/// bundle: Unauthorized, and it exits 0 even with its input still open.
#[test]
fn nearby_helper_outside_its_bundle_is_unauthorized_and_does_not_crash() {
    let mut child = helper()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // A command it never gets to: it stops before reading any.
    let _ = stdin.write_all(b"{\"cmd\":\"scan\",\"on\":true}\n");
    let out = child.wait_with_output().unwrap();
    drop(stdin);
    says_it_cannot_run(&out);
}

/// `--check` answers the same without reading stdin; anything else is a
/// usage error.
#[test]
fn nearby_helper_check_reads_only_its_bundle() {
    let out = helper()
        .arg("--check")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    says_it_cannot_run(&out);
    let out = helper().arg("--radio").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
}

/// In RavenNearby.app (the repository's Info.plist next to a copy of the
/// helper) `--check` finds the usage description: `hello` with protocol 1.
/// Only `--check`: started without it, the helper would open CoreBluetooth.
#[cfg(target_os = "macos")]
#[test]
fn nearby_helper_in_its_bundle_finds_its_usage_description() {
    let plist = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("macos/RavenNearby.app/Contents/Info.plist");
    let text = std::fs::read_to_string(&plist).unwrap();
    for needle in [
        "<key>NSBluetoothAlwaysUsageDescription</key>",
        "<string>org.raven.nearby</string>",
        "<string>raven-nearby-helper</string>",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    let dir = tempfile::tempdir().unwrap();
    let contents = dir.path().join("RavenNearby.app/Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    std::fs::copy(&plist, contents.join("Info.plist")).unwrap();
    let exe = contents.join("MacOS/raven-nearby-helper");
    std::fs::copy(env!("CARGO_BIN_EXE_raven-nearby-helper"), &exe).unwrap();
    let out = Command::new(&exe)
        .arg("--check")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    clean(&out);
    let said = lines(&out);
    assert_eq!(said, vec![serde_json::json!({"ev": "hello", "v": 1})]);
}
