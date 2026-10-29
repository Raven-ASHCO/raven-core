//! ash as a library, for one user only: the desktop engine (`raven-client`,
//! node/crates/raven-client), behind the `engine` feature.
//!
//! The `ash` and `raven` binaries include cli.rs themselves (src/bin/*.rs).
//! With `engine` on, this library compiles that same file once more and
//! exposes nothing of it but [`engine`] (cli.rs's `engine_bridge` module, the
//! one place that names the CLI's items for the engine). Without the feature
//! it is empty, so building ash costs nothing extra.

#[cfg(feature = "engine")]
#[path = "cli.rs"]
// Most of the CLI is unused by the engine: the binaries are its users.
#[allow(dead_code)]
mod ash_cli;

#[cfg(feature = "engine")]
pub use ash_cli::engine_bridge as engine;
