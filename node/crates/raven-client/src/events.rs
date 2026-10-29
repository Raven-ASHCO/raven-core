//! The event queue `events.poll` reads: every event gets the next `seq`; a
//! poll returns what came after the caller's `after_seq`.
//!
//! The buffer is bounded. Heartbeats (`status_ok`) replace each other, so a
//! window that polls rarely still finds the other events. When events the
//! caller has not seen were dropped for room (or the caller's `after_seq` is
//! from before this engine started), the poll says `reset: true`: the app
//! then reloads what it shows instead of trusting the events alone (an
//! addition to the contract: an extra field, which API.md allows).

use std::collections::VecDeque;
use std::sync::Mutex;

use serde_json::{Map, Value};

/// Events kept at most.
pub const CAPACITY: usize = 512;

#[derive(Default)]
struct Queue {
    seq: u64,
    events: VecDeque<(u64, Value)>,
    /// The highest seq dropped for room (0: none).
    dropped_through: u64,
}

/// One poll's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Batch {
    /// The newest seq so far (also when nothing new came).
    pub seq: u64,
    pub events: Vec<Value>,
    /// Events after `after_seq` were lost: reload.
    pub reset: bool,
}

#[derive(Default)]
pub struct EventHub {
    queue: Mutex<Queue>,
}

impl EventHub {
    pub fn new() -> EventHub {
        EventHub::default()
    }

    /// Adds one event of `kind` with `fields`, at `at_ms`; returns its seq.
    pub fn emit(&self, kind: &str, fields: Map<String, Value>, at_ms: u64) -> u64 {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        q.seq += 1;
        let seq = q.seq;
        let mut event = Map::new();
        event.insert("seq".into(), seq.into());
        event.insert("kind".into(), kind.into());
        event.insert("at_ms".into(), at_ms.into());
        for (k, v) in fields {
            event.entry(k).or_insert(v);
        }
        if kind == "status_ok" {
            q.events
                .retain(|(_, e)| e.get("kind").and_then(Value::as_str) != Some("status_ok"));
        }
        q.events.push_back((seq, Value::Object(event)));
        while q.events.len() > CAPACITY {
            if let Some((dropped, _)) = q.events.pop_front() {
                q.dropped_through = dropped;
            }
        }
        seq
    }

    /// What came after `after_seq`. Never blocks beyond the queue's lock.
    pub fn poll(&self, after_seq: u64) -> Batch {
        let q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        // A seq from before this engine (the app outlived an engine restart)
        // or one whose followers were dropped: everything kept, and reset.
        let ahead = after_seq > q.seq;
        let reset = ahead || after_seq < q.dropped_through;
        let from = if ahead { 0 } else { after_seq };
        Batch {
            seq: q.seq,
            events: q
                .events
                .iter()
                .filter(|(seq, _)| *seq > from)
                .map(|(_, e)| e.clone())
                .collect(),
            reset,
        }
    }

    /// The newest seq so far.
    #[cfg(test)]
    pub fn seq(&self) -> u64 {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fields(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn polls_return_what_came_after() {
        let hub = EventHub::new();
        assert_eq!(hub.poll(0).seq, 0);
        let a = hub.emit("send_started", fields(json!({"id": "x"})), 10);
        let b = hub.emit("receipt", fields(json!({"id": "x", "seq": 99})), 11);
        assert_eq!((a, b), (1, 2));
        let all = hub.poll(0);
        assert_eq!(all.events.len(), 2);
        assert!(!all.reset);
        // The engine's own seq wins over a field of the same name.
        assert_eq!(all.events[1]["seq"], 2);
        assert_eq!(all.events[1]["kind"], "receipt");
        assert_eq!(all.events[1]["at_ms"], 11);
        let after = hub.poll(1);
        assert_eq!((after.seq, after.events.len()), (2, 1));
        assert!(hub.poll(2).events.is_empty());
    }

    #[test]
    fn heartbeats_replace_each_other() {
        let hub = EventHub::new();
        hub.emit("status_ok", Map::new(), 1);
        hub.emit("presence", Map::new(), 2);
        hub.emit("status_ok", Map::new(), 3);
        let batch = hub.poll(0);
        let kinds: Vec<&str> = batch
            .events
            .iter()
            .map(|e| e["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["presence", "status_ok"]);
        assert!(!batch.reset, "a replaced heartbeat is no loss");
    }

    #[test]
    fn a_full_buffer_and_a_seq_from_the_future_say_reset() {
        let hub = EventHub::new();
        for i in 0..(CAPACITY as u64 + 10) {
            hub.emit("state", Map::new(), i);
        }
        let old = hub.poll(3);
        assert!(old.reset);
        assert_eq!(old.events.len(), CAPACITY);
        assert!(!hub.poll(hub.seq() - 1).reset);
        let future = hub.poll(hub.seq() + 100);
        assert!(future.reset);
        assert_eq!(future.events.len(), CAPACITY);
    }
}
