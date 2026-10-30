//! raven-tor-helper: Arti (the Rust Tor implementation) for one raven-node,
//! in its own process (lab; `protocol/RAVEN_ONION_CARRIER_V1.md` §6, design
//! `docs/design/2026-10-tor-fallback.md` §3.1). The helper's code is
//! src/onion/arti.rs, shared with the in-process helper (feature
//! `tor-embedded`, the iOS app); this program runs it on its stdin and
//! stdout.
//!
//! raven-node starts it, writes one config line on its stdin and reads its
//! events on stdout. It exits when its stdin closes (raven-node is gone) or
//! on `stop`. If Arti panics, only this process ends; raven-node restarts
//! it with backoff. When the Tor network requires a protocol this Arti
//! lacks (Arti #1932), it says so on stderr and exits with 1 (Raven's
//! arti-client patch tells it instead of exiting itself), and raven-node
//! keeps Tor off.

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
    // Too old for the Tor network: say so where raven-node reads it (as
    // Arti's own exit used to), and end as it did.
    let code = if code == arti::EXIT_OBSOLETE {
        eprintln!("{}", arti::OBSOLETE_WORDS);
        1
    } else {
        code
    };
    // Do not wait for Arti's background tasks: raven-node is gone or asked.
    runtime.shutdown_timeout(Duration::from_secs(1));
    std::process::exit(code);
}
