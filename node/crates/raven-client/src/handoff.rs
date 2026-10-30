//! `messages.handoff`: before the app goes to the background (the iOS app,
//! docs/IOS.md §3), the messages of yours that wait are left as sealed
//! copies with friends who hold mail (friend custody) now, within a time
//! the app gives, instead of after the minute raven-node otherwise waits.
//! It is `raven outbox hand-off` for every friend, and then a look at
//! raven-node's outbox until each message is held, delivered, or the time
//! is up.
//!
//! A message counts when it waits on this computer: queued, held back or
//! parked (`queued`, `held`, `waiting` in raven-node's outbox), with no
//! friend holding a copy yet and no sealed letter for it. One already
//! written to the friend's computer (`sent`) is not: it is there. raven-node
//! decides as always where a copy may go (the friends the recipient told
//! about, or listed by hand, verified and unblocked); a direct try comes
//! first, so a friend who answers now gets the message itself.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use ash_engine::engine as bridge;
use raven_core::ipc::OutboxItem;
use serde_json::{json, Value};

use crate::engine::{Inner, OutboxSnap};
use crate::envelope::{code, ApiError, Args, OpResult};
use crate::messages::holder_name;

/// The time `messages.handoff` takes when the app names none.
pub(crate) const HANDOFF_DEFAULT: Duration = Duration::from_secs(5);
/// The longest it takes: the app also needs time to pause the node inside
/// the background time iOS gives it (about 30 s).
pub(crate) const HANDOFF_MAX: Duration = Duration::from_secs(20);
/// The shortest.
const HANDOFF_MIN: Duration = Duration::from_millis(500);
/// How often the outbox is read while it waits.
const LOOK_EVERY: Duration = Duration::from_millis(250);
/// How long a hand-off looks at least, so what raven-node lists only after
/// the kick (a message stored a moment ago) is counted.
const SETTLE: Duration = Duration::from_millis(1500);

/// Waits on this computer and nobody holds a copy: what a hand-off is for.
pub(crate) fn waits_here(item: &OutboxItem, snap: &OutboxSnap) -> bool {
    item.kind == "message"
        && matches!(item.state.as_str(), "queued" | "held" | "waiting")
        && item.in_custody == 0
        && !snap
            .letters
            .contains(&item.message_id_hex.to_ascii_lowercase())
}

/// Where each message of a hand-off ended.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    /// A friend holds a copy.
    pub handed: Vec<String>,
    /// Delivered meanwhile.
    pub delivered: usize,
    /// Still only on this computer (the unlisted ones among them).
    pub left: usize,
    /// Not listed by raven-node at this look: between two of its scans (a
    /// copy sealed again is listed anew at the next one), or finished.
    pub unlisted: Vec<String>,
}

/// Where the messages `asked` (ids in lower case) stand in `snap`.
pub(crate) fn tally(asked: &[String], snap: &OutboxSnap) -> Tally {
    let mut t = Tally::default();
    for mid in asked {
        match snap.items.get(mid) {
            Some(i) if i.state == "delivered" => t.delivered += 1,
            Some(i) if i.in_custody > 0 || snap.letters.contains(mid) => t.handed.push(mid.clone()),
            // Waiting still, or given up (expired, failed, cancelled).
            Some(_) => t.left += 1,
            // Not known now: still waiting, until the chat history says
            // otherwise (`settle_unlisted`).
            None => {
                t.left += 1;
                t.unlisted.push(mid.clone());
            }
        }
    }
    t
}

/// The unlisted messages of a finished hand-off whose history row says
/// delivered count as delivered, not left behind.
fn settle_unlisted(t: &mut Tally, delivered: &dyn Fn(&str) -> bool) {
    for mid in std::mem::take(&mut t.unlisted) {
        if delivered(&mid) {
            t.left = t.left.saturating_sub(1);
            t.delivered += 1;
        }
    }
}

impl Inner {
    /// `messages.handoff {budget_ms?}`: `{handed, left, delivered, holders,
    /// custody, completed, elapsed_ms}` (API.md).
    pub(crate) fn messages_handoff(&self, args: &Args) -> OpResult {
        let budget = args
            .opt_u64("budget_ms")?
            .map_or(HANDOFF_DEFAULT, Duration::from_millis)
            .clamp(HANDOFF_MIN, HANDOFF_MAX);
        self.identity()?;
        let dir = self.data_dir()?.to_path_buf();
        let started = Instant::now();
        let custody = raven_core::custody_gate::CustodyGates::current().live;
        self.invalidate_outbox();
        let snap = self.outbox(Duration::ZERO);
        if !snap.answered {
            return Err(ApiError::new(
                code::NODE_NOT_RUNNING,
                "Raven isn't running, so no friend can take your messages now. They wait on \
                 this device and go when Raven runs again.",
                "messages.handoff: no raven-node answered",
            ));
        }
        // What friends held before: not this hand-off's.
        let held_before: HashSet<String> = snap
            .items
            .iter()
            .filter(|(mid, i)| i.in_custody > 0 || snap.letters.contains(*mid))
            .map(|(mid, _)| mid.clone())
            .collect();
        let mut asked: Vec<String> = snap
            .items
            .values()
            .filter(|i| waits_here(i, &snap))
            .map(|i| i.message_id_hex.to_ascii_lowercase())
            .collect();
        let result = |t: &Tally, holders: Vec<String>, completed: bool| -> Value {
            json!({
                "handed": t.handed.len(),
                "left": t.left,
                "delivered": t.delivered,
                "holders": holders,
                "custody": if custody { "on" } else { "off" },
                "completed": completed,
                "elapsed_ms": started.elapsed().as_millis() as u64,
            })
        };
        if !custody {
            // Friends hold no mail in this build: nothing to hand on (what
            // waits stays in the outbox).
            let t = Tally {
                left: asked.len(),
                ..Tally::default()
            };
            return Ok(result(&t, Vec::new(), true));
        }
        if !bridge::outbox_hand_off(&dir) {
            return Err(ApiError::new(
                code::NODE_NOT_RUNNING,
                "Raven's background program isn't sending right now, so no friend can take your \
                 messages. They wait on this device.",
                "messages.handoff: raven-node took no hand-off (no outbox worker)",
            ));
        }
        // The kick makes raven-node read its queue again: a message stored a
        // moment ago (a group copy just parked) is listed only then, so for
        // a short while what shows up waiting, or newly held, counts too.
        let settle = SETTLE.min(budget);
        let mut t;
        loop {
            self.invalidate_outbox();
            let now = self.outbox(Duration::ZERO);
            for (mid, i) in &now.items {
                let new_here = waits_here(i, &now)
                    || (i.kind == "message" && (i.in_custody > 0 || now.letters.contains(mid)));
                if new_here && !held_before.contains(mid) && !asked.contains(mid) {
                    asked.push(mid.clone());
                }
            }
            t = tally(&asked, &now);
            let elapsed = started.elapsed();
            if (t.left == 0 && elapsed >= settle) || elapsed >= budget {
                break;
            }
            std::thread::sleep(LOOK_EVERY.min(budget.saturating_sub(elapsed)));
        }
        if !t.unlisted.is_empty() {
            let rows = raven_core::chat_history::ChatHistory::load(&dir)
                .map(|h| h.entries)
                .unwrap_or_default();
            settle_unlisted(&mut t, &|mid| {
                rows.iter().any(|e| {
                    e.message_id_hex.eq_ignore_ascii_case(mid)
                        && matches!(e.delivery.as_str(), "delivered" | "read")
                })
            });
        }
        let completed = t.left == 0;
        // Who took them, by name (each named once).
        let holders = {
            let held = crate::engine::copy_holders(&dir);
            let contacts = self.contacts()?;
            let mut seen = HashSet::new();
            t.handed
                .iter()
                .filter_map(|mid| holder_name(held.get(mid), &contacts))
                .filter(|name| seen.insert(name.clone()))
                .collect()
        };
        // The chats show it at once (the watcher would at its next beat).
        let _ = self.refresh(Duration::ZERO);
        Ok(result(&t, holders, completed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(mid: &str, state: &str, in_custody: u8) -> OutboxItem {
        OutboxItem {
            message_id_hex: mid.into(),
            kind: "message".into(),
            state: state.into(),
            in_custody,
            ..Default::default()
        }
    }

    fn snap(items: &[OutboxItem]) -> OutboxSnap {
        OutboxSnap {
            answered: true,
            worker_running: true,
            items: items
                .iter()
                .map(|i| (i.message_id_hex.clone(), i.clone()))
                .collect(),
            ..OutboxSnap::default()
        }
    }

    #[test]
    fn only_what_waits_here_with_nobody_holding_it_is_handed() {
        let mut s = snap(&[]);
        assert!(waits_here(&item("a", "queued", 0), &s));
        assert!(waits_here(&item("a", "held", 0), &s));
        assert!(waits_here(&item("a", "waiting", 0), &s));
        // Written to the friend's computer already, or a friend holds it.
        assert!(!waits_here(&item("a", "sent", 0), &s));
        assert!(!waits_here(&item("a", "queued", 1), &s));
        for done in ["delivered", "expired", "failed", "cancelled"] {
            assert!(!waits_here(&item("a", done, 0), &s), "{done}");
        }
        let mut ack = item("a", "queued", 0);
        ack.kind = "ack".into();
        assert!(!waits_here(&ack, &s));
        // A sealed letter with a friend holds it too.
        s.letters.insert("a".into());
        assert!(!waits_here(&item("a", "queued", 0), &s));
    }

    #[test]
    fn a_tally_counts_held_delivered_and_left() {
        let asked: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| (*s).into())
            .collect();
        let mut s = snap(&[
            item("a", "sent", 1),
            item("b", "delivered", 0),
            item("c", "queued", 0),
            item("d", "expired", 0),
        ]);
        let mut t = tally(&asked, &s);
        assert_eq!(t.handed, ["a"]);
        assert_eq!(t.delivered, 1);
        // "e" is not listed now: waiting, until its row says delivered.
        assert_eq!(
            (t.left, t.unlisted.as_slice()),
            (3, ["e".to_owned()].as_slice())
        );
        settle_unlisted(&mut t, &|mid| mid == "e");
        assert_eq!((t.left, t.delivered), (2, 2));
        let mut t = tally(&asked, &s);
        settle_unlisted(&mut t, &|_| false);
        assert_eq!((t.left, t.delivered), (3, 1));
        s.letters.insert("c".into());
        assert_eq!(tally(&asked, &s).handed, ["a", "c"]);
    }
}
