//! `raven-client`: the engine of Raven's desktop apps (desktop/api/API.md).
//!
//! One function, JSON in and out: [`call`] in Rust (the Linux app), and the C
//! ABI `raven_call` / `raven_free` (include/raven_client.h) for the macOS
//! (static library) and Windows (DLL) apps. Every operation runs the same
//! code the CLI runs (crates/ash, through its engine bridge) on the same
//! profile the CLI uses (`RAVEN_DATA_DIR`, else `ASH_DATA_DIR`, else
//! `~/.raven`), so the app, `raven` and `ash` see one identity and one
//! contact list. Message delivery itself stays in the background raven-node.
//!
//! Safety in every response: no field named like a secret (`seed`,
//! `private_key`, `secret`, `plaintext`, `recovery`), all display text
//! sanitised, no panic across the boundary (it becomes `INTERNAL`).

mod contacts;
mod engine;
mod envelope;
mod events;
mod explain;
mod ffi;
mod groups;
mod identity;
mod messages;
mod network;
mod node;
mod profile;
mod safety;
mod settings;

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

pub use envelope::code;
pub use ffi::{raven_call, raven_free};
pub use node::NODE_PROGRAM_ENV;

/// The answer when even building an error response failed.
const LAST_RESORT: &str = r#"{"v":1,"ok":false,"error":{"code":"INTERNAL","message":"Something went wrong inside Raven. Try again; if it keeps happening, open Details.","detail":"the response could not be built"}}"#;

/// One engine for one profile. Cheap to clone; thread-safe.
#[derive(Clone)]
pub struct Client(Arc<engine::Inner>);

impl Client {
    /// The engine for the profile the CLI uses without `--data-dir`.
    pub fn new() -> Client {
        Client(engine::Inner::new(ash_engine::engine::default_data_dir()))
    }

    /// The engine for the profile in `data_dir` (tests, and apps that keep
    /// their own folder).
    pub fn with_data_dir(data_dir: impl Into<PathBuf>) -> Client {
        Client(engine::Inner::new(Ok(data_dir.into())))
    }

    /// One request envelope in, one response envelope out (API.md). Never
    /// panics; a panic inside becomes an `INTERNAL` error.
    pub fn call(&self, request_json: &str) -> String {
        let response = std::panic::catch_unwind(AssertUnwindSafe(|| self.0.handle(request_json)))
            .unwrap_or_else(|panic| {
                let what = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "a panic".to_owned());
                let mut v = envelope::failure(&envelope::ApiError::internal(format!(
                    "panic inside the engine: {what}"
                )));
                safety::sanitize_strings(&mut v);
                v
            });
        serde_json::to_string(&response).unwrap_or_else(|_| LAST_RESORT.to_owned())
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

static GLOBAL: OnceLock<Client> = OnceLock::new();

/// The process's engine (the profile the CLI uses), made on first use.
pub fn global() -> &'static Client {
    GLOBAL.get_or_init(Client::new)
}

/// `raven_call` for Rust: one request envelope in, one response out, on the
/// process's engine. Thread-safe; it may block (a start of raven-node takes
/// a few seconds), except `events.poll`, which never does.
pub fn call(request_json: &str) -> String {
    global().call(request_json)
}
