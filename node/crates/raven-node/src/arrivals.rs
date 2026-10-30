//! What raven-node says about mail it receives and hands over (field test E2
//! r9): one log line per received message, written when it arrives, "received a message from
//! contact #ab12 via Tor" (#12; before, an incoming message over the onion
//! left no line at all), and a keeper's own line when it hands sealed mail
//! over, "custody: handed over 3 sealed messages to contact #ab12" (#13;
//! before, only the count changed). Counts, carrier words and short tags
//! only: never an address, key or onion address. The arrivals themselves
//! are kept by `raven_core::arrivals` (in memory); IPC `Arrivals` serves
//! them to `raven inbox`.

use std::time::Duration;

use raven_core::arrivals::{Arrival, ArrivedVia};
use raven_core::ipc::{ArrivalRow, IpcResponse};

use crate::netutil;

/// Install the log hooks (once, at the service's start).
pub(crate) fn install() {
    raven_core::arrivals::set_hook(log_arrival);
    raven_core::friend_custody::set_handover_hook(log_handover);
}

/// "received a message from contact #ab12 via Tor", "received a group
/// message from contact #ab12 from a keeper".
pub(crate) fn arrival_line(tag: &str, via: ArrivedVia, group: bool) -> String {
    format!(
        "received a {}message from contact {tag} {}",
        if group { "group " } else { "" },
        via.phrase()
    )
}

/// "handed over 3 sealed messages to contact #ab12 (deleted here)".
pub(crate) fn handover_line(tag: &str, n: usize) -> String {
    format!(
        "handed over {n} sealed message{} to contact {tag} (deleted here)",
        if n == 1 { "" } else { "s" }
    )
}

/// One line per received message, written when it arrives (E2 r38: a
/// sender's arrivals were folded per 30 s window, and the count of the
/// folded ones came only with that sender's next line, if any).
fn log_arrival(a: &Arrival) {
    // A message over Tor from the friend: Tor to it works (E2 r40).
    if a.via == ArrivedVia::Tor {
        crate::delivery_paths::carrier_worked(&a.sender, raven_core::OutboxCarrier::Onion);
    }
    let tag = netutil::link_tag(&a.sender);
    eprintln!("raven-node inbox: {}", arrival_line(&tag, a.via, a.group));
}

/// One line per hand-over (each is one RELEASE: a batch already).
fn log_handover(to: &[u8; 32], n: usize) {
    eprintln!(
        "raven-node custody: {}",
        handover_line(&netutil::link_tag(to), n)
    );
}

/// IPC `Arrivals`: how the messages received since raven-node started came,
/// and how our own ones a receipt confirmed went, newest last (message id,
/// carrier token, age).
pub(crate) fn ipc_rows(v: u16) -> IpcResponse {
    let now = raven_core::clock::now_ms();
    let row = |message_id: [u8; 16], via: ArrivedVia, at_ms: u64| ArrivalRow {
        message_id_hex: hex::encode(message_id),
        via: via.token().into(),
        age_s: Duration::from_millis(now.saturating_sub(at_ms)).as_secs(),
    };
    IpcResponse::Arrivals {
        v,
        rows: raven_core::arrivals::recent()
            .into_iter()
            .map(|a| row(a.message_id, a.via, a.at_ms))
            .collect(),
        delivered: crate::delivery_paths::delivered_messages()
            .into_iter()
            .map(|(id, via, at_ms)| row(id, via, at_ms))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E2 r9 #12/#13: the lines name the way and a short tag, never an
    /// address or a key.
    #[test]
    fn arrival_and_handover_lines_name_the_way_and_a_tag_only() {
        assert_eq!(
            arrival_line("#ab12", ArrivedVia::Tor, false),
            "received a message from contact #ab12 via Tor"
        );
        assert_eq!(
            arrival_line("#ab12", ArrivedVia::Keeper, true),
            "received a group message from contact #ab12 from a keeper"
        );
        assert_eq!(
            arrival_line("#ab12", ArrivedVia::Lan, false),
            "received a message from contact #ab12 via LAN"
        );
        assert_eq!(
            handover_line("#ab12", 3),
            "handed over 3 sealed messages to contact #ab12 (deleted here)"
        );
        assert_eq!(
            handover_line("#ab12", 1),
            "handed over 1 sealed message to contact #ab12 (deleted here)"
        );
        let key = [0x5A; 32];
        let tag = netutil::link_tag(&key);
        let line = arrival_line(&tag, ArrivedVia::P2p, false);
        assert!(!line.contains(&hex::encode(key)[..8]), "{line}");
    }

    #[test]
    fn ipc_rows_carry_the_carrier_token_and_age() {
        let id = [0xC3; 16];
        raven_core::arrivals::note(Arrival {
            sender: [1; 32],
            message_id: id,
            via: ArrivedVia::Nearby,
            at_ms: raven_core::clock::now_ms().saturating_sub(5_000),
            group: false,
        });
        let IpcResponse::Arrivals { rows, .. } = ipc_rows(raven_core::ipc::IPC_VERSION) else {
            panic!("not Arrivals");
        };
        let row = rows
            .iter()
            .rev()
            .find(|r| r.message_id_hex == hex::encode(id))
            .expect("kept");
        assert_eq!(row.via, "nearby");
        assert!((4..=60).contains(&row.age_s), "{row:?}");
    }
}
