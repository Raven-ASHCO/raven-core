//! The C ABI and the envelope, on the process's own engine (`raven_call`).
//!
//! This binary points `RAVEN_DATA_DIR` at a throwaway folder before the
//! first call, so the global engine never sees a real profile.

mod common;

use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::sync::OnceLock;

use raven_client::{raven_call, raven_free};
use serde_json::Value;

/// The throwaway profile of this binary, set before any engine exists.
fn profile() -> &'static PathBuf {
    static DIR: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &DIR.get_or_init(|| {
        common::lab_env();
        let dir = common::short_dir();
        let path = dir.path().join("profile");
        std::env::set_var("RAVEN_DATA_DIR", &path);
        std::env::remove_var("ASH_DATA_DIR");
        (dir, path)
    })
    .1
}

/// One call through the C ABI; the response is freed here.
fn c_call(request: Option<&[u8]>) -> Value {
    profile();
    let owned = request.map(|bytes| CString::new(bytes).unwrap());
    let ptr = owned.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    // SAFETY: NULL or a NUL-terminated string alive for the call.
    let out = unsafe { raven_call(ptr) };
    assert!(!out.is_null(), "raven_call returned NULL");
    // SAFETY: raven_call returns a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_owned();
    // SAFETY: returned by raven_call, freed once.
    unsafe { raven_free(out) };
    serde_json::from_str(&text).unwrap()
}

fn code(v: &Value) -> &str {
    assert_eq!(v["v"], 1, "{v}");
    assert_eq!(v["ok"], false, "{v}");
    v["error"]["code"].as_str().unwrap()
}

#[test]
fn null_and_broken_requests_are_bad_requests_never_null() {
    assert_eq!(code(&c_call(None)), "BAD_REQUEST");
    assert_eq!(code(&c_call(Some(b"\xff\xfe not utf-8"))), "BAD_REQUEST");
    for bad in [
        &b""[..],
        b"not json",
        b"[1,2]",
        br#"{"op":"app.info"}"#,
        br#"{"v":9,"op":"app.info"}"#,
        br#"{"v":1,"op":"no.such.op"}"#,
        br#"{"v":1,"op":"contacts.add","args":"text"}"#,
    ] {
        let v = c_call(Some(bad));
        assert_eq!(code(&v), "BAD_REQUEST", "{}", String::from_utf8_lossy(bad));
        assert!(!v["error"]["message"].as_str().unwrap().is_empty());
    }
    // Freeing NULL is fine.
    // SAFETY: NULL is ignored.
    unsafe { raven_free(std::ptr::null_mut::<c_char>()) };
}

#[test]
fn app_info_and_a_new_profile() {
    let info = c_call(Some(br#"{"v":1,"op":"app.info","unknown":true}"#));
    assert_eq!(info["ok"], true, "{info}");
    let r = &info["result"];
    assert!(["dev", "release"].contains(&r["build"].as_str().unwrap()));
    assert!(
        ["macos", "windows", "linux"].contains(&r["platform"].as_str().unwrap())
            || r["platform"].is_string()
    );
    assert!(r["version"].is_string());
    let state = c_call(Some(br#"{"v":1,"op":"profile.state"}"#));
    assert_eq!(state["result"]["state"], "new", "{state}");
    // Nothing that needs an identity works before one exists.
    for op in ["identity.me", "contacts.list", "card.make"] {
        let v = c_call(Some(format!(r#"{{"v":1,"op":"{op}"}}"#).as_bytes()));
        assert_eq!(code(&v), "NOT_INITIALIZED", "{op}");
    }
    // The profile folder holds nothing the first identity would trip on.
    let leftovers: Vec<_> = std::fs::read_dir(profile())
        .map(|d| d.filter_map(Result::ok).map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(
        !leftovers
            .iter()
            .any(|n| n == "desktop_settings.json" || n == "contacts.json"),
        "{leftovers:?}"
    );
}

#[test]
fn the_privacy_pack_state_and_actions() {
    // A plain profile (a debug build without the lab switch), not locked;
    // the pack's actions are not offered in the app yet.
    let state = c_call(Some(br#"{"v":1,"op":"privacy.state"}"#));
    assert_eq!(
        state["result"],
        serde_json::json!({"available": false, "encrypted": false, "locked": false})
    );
    for op in ["privacy.lock", "privacy.encrypt", "privacy.erase"] {
        let req = format!(r#"{{"v":1,"op":"{op}","args":{{"confirm":"erase"}}}}"#);
        assert_eq!(
            code(&c_call(Some(req.as_bytes()))),
            "NOT_AVAILABLE_YET",
            "{op}"
        );
    }
    // Unlock clears a lock (none here) and answers as profile.state.
    let unlock = c_call(Some(br#"{"v":1,"op":"privacy.unlock"}"#));
    assert_eq!(unlock["ok"], true, "{unlock}");
    assert!(unlock["result"]["state"].is_string(), "{unlock}");
}

#[test]
fn calls_from_many_threads_at_once() {
    let threads: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                for _ in 0..20 {
                    let req = if i % 2 == 0 {
                        &br#"{"v":1,"op":"app.info"}"#[..]
                    } else {
                        &br#"{"v":1,"op":"events.poll","args":{"after_seq":0}}"#[..]
                    };
                    assert_eq!(c_call(Some(req))["ok"], true);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    // The Rust entry point answers the same.
    let v: Value = serde_json::from_str(&raven_client::call(r#"{"v":1,"op":"app.info"}"#)).unwrap();
    assert_eq!(v["ok"], true);
}
