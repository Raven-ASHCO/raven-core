//! Keep watch lab: the Tor helper alone in the calling process
//! (`raven_watch_probe`, ffi.rs; raven-node `onion/watch_probe.rs`).
//!
//! The iPhone app's tunnel extension links the engine's library and calls
//! this one function, and nothing else of the engine: no profile is opened,
//! no key is read, no node starts. It exists in debug builds with the
//! feature `tor-embedded`; every other build answers that it is not there.
//!
//! One JSON object in, one out:
//!
//! - `{"op":"start","state_dir":"<absolute path>","check_every_s":300}`
//!   starts it with Tor's state in that folder (`check_every_s` may be left
//!   out; raven-node sets its least);
//! - `{"op":"status"}` says what it saw;
//! - `{"op":"stop"}` ends it.
//!
//! Each answers with the probe's status (raven-node's words: counts, times
//! and the Tor helper's fixed words, never an address), or with
//! `{"error":"<what>"}`.

/// A failed request's answer.
pub(crate) fn failure(what: &str) -> String {
    serde_json::json!({ "error": what }).to_string()
}

/// One request, one answer (the module's words).
#[cfg(all(feature = "tor-embedded", debug_assertions))]
pub(crate) fn call(request: &str) -> String {
    use raven_node::watch_probe as probe;
    use serde_json::Value;

    let Ok(Value::Object(request)) = serde_json::from_str::<Value>(request) else {
        return failure("the request is not a JSON object");
    };
    match request.get("op").and_then(Value::as_str) {
        Some("start") => {
            let dir = request
                .get("state_dir")
                .and_then(Value::as_str)
                .map(std::path::Path::new)
                .filter(|dir| dir.is_absolute());
            let Some(dir) = dir else {
                return failure("state_dir is not an absolute path");
            };
            let every = match request.get("check_every_s") {
                None => DEFAULT_CHECK_EVERY_S,
                Some(seconds) => match seconds.as_u64() {
                    Some(seconds) => seconds,
                    None => return failure("check_every_s is not a count of seconds"),
                },
            };
            match probe::start(dir, std::time::Duration::from_secs(every)) {
                Ok(()) => probe::status(),
                Err(what) => failure(&what),
            }
        }
        Some("status") => probe::status(),
        Some("stop") => {
            probe::stop();
            probe::status()
        }
        _ => failure("unknown op"),
    }
}

/// A check every five minutes of the wall clock when the caller names no
/// other time.
#[cfg(all(feature = "tor-embedded", debug_assertions))]
const DEFAULT_CHECK_EVERY_S: u64 = 300;

/// Not in this build (a release build, or one without Tor in process).
#[cfg(not(all(feature = "tor-embedded", debug_assertions)))]
pub(crate) fn call(_request: &str) -> String {
    failure("not in this build")
}
