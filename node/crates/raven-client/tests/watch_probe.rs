//! `raven_watch_probe` through the C ABI (Keep watch lab, src/watch_probe.rs).
//!
//! It opens no profile and no engine: this binary sets no data folder.

use std::ffi::{c_char, CStr, CString};

use raven_client::{raven_free, raven_watch_probe};
use serde_json::Value;

/// One call through the C ABI; the answer is freed here.
fn probe(request: Option<&[u8]>) -> Value {
    let owned = request.map(|bytes| CString::new(bytes).unwrap());
    let ptr: *const c_char = owned.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: NULL or a NUL-terminated string alive for the call.
    let out = unsafe { raven_watch_probe(ptr) };
    assert!(!out.is_null(), "raven_watch_probe returned NULL");
    // SAFETY: raven_watch_probe returns a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_owned();
    // SAFETY: returned by raven_watch_probe, freed once.
    unsafe { raven_free(out) };
    let answer: Value = serde_json::from_str(&text).unwrap();
    assert!(answer.is_object(), "{text}");
    answer
}

#[test]
fn a_null_or_broken_request_is_an_error_never_null() {
    assert_eq!(probe(None)["error"], "the request is NULL");
    assert_eq!(
        probe(Some(b"\xff\xfe not utf-8"))["error"],
        "the request is not UTF-8"
    );
}

/// A build without the lab probe (every release build, and every build
/// without Tor in process) says so to every request, and starts nothing.
#[cfg(not(all(feature = "tor-embedded", debug_assertions)))]
#[test]
fn a_build_without_the_probe_says_so() {
    for request in [
        &br#"{"op":"status"}"#[..],
        br#"{"op":"start","state_dir":"/nonexistent/raven-watch-probe"}"#,
        br#"{"op":"stop"}"#,
        b"not json",
    ] {
        let answer = probe(Some(request));
        assert_eq!(answer["error"], "not in this build", "{answer}");
        assert_eq!(answer.as_object().unwrap().len(), 1, "{answer}");
    }
    assert!(!std::path::Path::new("/nonexistent/raven-watch-probe").exists());
}

/// The lab build, with the loopback helper in place of Tor: bad requests
/// are refused in words, a start brings the helper up alone, the status
/// says so in counts and short words, and a stop ends it.
#[cfg(all(feature = "tor-embedded", debug_assertions))]
#[test]
fn the_probe_starts_says_what_it_saw_and_stops() {
    use std::time::{Duration, Instant};

    let registry = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    // This binary's only test that starts anything: the loopback helper in
    // this process, not Tor.
    std::env::set_var("RAVEN_LAB_TOR_LOOPBACK", registry.path());
    let state_dir = state.path().join("tor");

    for (request, error) in [
        ("not json".to_string(), "the request is not a JSON object"),
        ("[1,2]".to_string(), "the request is not a JSON object"),
        ("{}".to_string(), "unknown op"),
        (r#"{"op":"node.start"}"#.to_string(), "unknown op"),
        (
            r#"{"op":"start"}"#.to_string(),
            "state_dir is not an absolute path",
        ),
        (
            r#"{"op":"start","state_dir":"tor"}"#.to_string(),
            "state_dir is not an absolute path",
        ),
        (
            serde_json::json!({"op": "start", "state_dir": state_dir, "check_every_s": "often"})
                .to_string(),
            "check_every_s is not a count of seconds",
        ),
    ] {
        assert_eq!(probe(Some(request.as_bytes()))["error"], error, "{request}");
    }
    assert_eq!(probe(Some(br#"{"op":"status"}"#))["phase"], "off");
    assert!(!state_dir.exists(), "a refused start made the folder");

    let start = serde_json::json!({"op": "start", "state_dir": state_dir, "check_every_s": 60});
    let started = probe(Some(start.to_string().as_bytes()));
    assert!(started.get("error").is_none(), "{started}");
    assert!(state_dir.is_dir());

    let wait_for = |phase: &str| {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let seen = probe(Some(br#"{"op":"status"}"#));
            if seen["phase"] == phase {
                return seen;
            }
            assert!(Instant::now() < deadline, "no {phase}: {seen}");
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let seen = wait_for("ready");
    assert_eq!(seen["lives"], 1, "{seen}");
    assert_eq!(seen["pct"], 100, "{seen}");
    assert!(seen["ready_after_ms"].as_i64() >= Some(0), "{seen}");
    // Counts and short words: nothing as long as an onion key.
    let text = seen.to_string();
    assert!(!text.split('"').any(|part| part.len() >= 40), "{text}");

    let stopped = probe(Some(br#"{"op":"stop"}"#));
    assert!(stopped.get("error").is_none(), "{stopped}");
    wait_for("off");
    std::env::remove_var("RAVEN_LAB_TOR_LOOPBACK");
}
