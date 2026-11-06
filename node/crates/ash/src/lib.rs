//! ash as a library, for one user only: the desktop engine (`raven-client`,
//! node/crates/raven-client), behind the `engine` feature.
//!
//! The `ash` and `raven` binaries include cli.rs themselves (src/bin/*.rs).
//! With `engine` on, this library compiles that same file once more and
//! exposes nothing of it but [`engine`] (cli.rs's `engine_bridge` module, the
//! one place that names the CLI's items for the engine). Without the feature
//! it holds only the release check below, so building ash costs nothing
//! extra.

// The lab commands and switches of the CLI (cli.rs) are compiled only with
// `debug_assertions`, and a release profile can switch that on. Such a build
// stops here: this library is built with every program of the package
// (security review 2026-11, DEP-3; raven-core checks the same for itself).
const _: () = assert!(
    !(cfg!(debug_assertions) && matches!(raven_core::BUILD_PROFILE.as_bytes(), b"release")),
    "debug assertions in a release build open the lab gates"
);

#[cfg(feature = "engine")]
#[path = "cli.rs"]
// Most of the CLI is unused by the engine: the binaries are its users.
#[allow(dead_code)]
mod ash_cli;

#[cfg(feature = "engine")]
pub use ash_cli::engine_bridge as engine;
