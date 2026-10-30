//! raven-tor-helper: Arti (the Rust Tor implementation) for one raven-node,
//! in its own process (lab; `protocol/RAVEN_ONION_CARRIER_V1.md` §6, design
//! `docs/design/2026-10-tor-fallback.md` §3.1). The helper's code is
//! src/onion/arti.rs, shared with the in-process helper (feature
//! `tor-embedded`, the iOS app); this program runs it on its stdin and
//! stdout.
//!
//! raven-node starts it, writes one config line on its stdin and reads its
//! events on stdout. It exits when its stdin closes (raven-node is gone) or
//! on `stop`. If Arti panics or calls `exit(1)` (an obsolete protocol
//! version, Arti #1932), only this process ends; raven-node restarts it with
//! backoff.

#[path = "../../onion/proto.rs"]
#[allow(dead_code)]
mod proto;

#[path = "../../onion/arti.rs"]
mod arti;

use std::time::Duration;

fn main() {
    // Two workers: Tor in its own small pool, never the node's.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => std::process::exit(3),
    };
    let code = runtime.block_on(arti::serve(tokio::io::stdin(), tokio::io::stdout()));
    // Do not wait for Arti's background tasks: raven-node is gone or asked.
    runtime.shutdown_timeout(Duration::from_secs(1));
    std::process::exit(code);
}
