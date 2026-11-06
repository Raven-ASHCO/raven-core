//! The event queue `events.poll` reads: every event gets the next `seq`; a
//! poll returns what came after the caller's `after_seq`.
//!
//! The buffer is bounded. Heartbeats (`status_ok`) replace each other, so a
//! window that polls rarely still finds the other events. When events the
//! caller has not seen were dropped for room (or the caller's `after_seq` is
//! from before this engine started), the poll says `reset: true`: the app
//! then reloads what it shows instead of trusting the events alone (an
//! addition to the contract: an extra field, which API.md allows).
//!
//! While Lock v2 holds the profile ([`EventHub::set_locked`]) the queue is
//! empty and stays so: what was not read yet goes at the lock (an
//! `incoming` event carries a message's text), every event meanwhile is
//! dropped, and a poll says `locked: true` with no events. The first poll
//! after the unlock says `reset: true`.
//!
//! `events.wait` ([`EventHub::wait`], speed design M9) answers as a poll,
//! but while there is nothing to say it waits for the next event, a lock
//! or an unlock, up to its timeout.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

/// Events kept at most.
pub const CAPACITY: usize = 512;

#[derive(Default)]
struct Queue {
    seq: u64,
    events: VecDeque<(u64, Value)>,
    /// The highest seq dropped for room, or at a lock or an unlock (0:
    /// none).
    dropped_through: u64,
    /// Lock v2 holds the profile: nothing is queued.
    locked: bool,
}

/// One poll's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Batch {
    /// The newest seq so far (also when nothing new came).
    pub seq: u64,
    pub events: Vec<Value>,
    /// Events after `after_seq` were lost: reload.
    pub reset: bool,
    /// Lock v2 holds the profile: no events until the unlock.
    pub locked: bool,
}

#[derive(Default)]
pub struct EventHub {
    queue: Mutex<Queue>,
    /// Woken at every event, lock and unlock ([`Self::wait`]).
    news: Condvar,
}

impl EventHub {
    pub fn new() -> EventHub {
        EventHub::default()
    }

    /// Adds one event of `kind` with `fields`, at `at_ms`; returns its seq.
    /// While locked nothing is added (the newest seq so far is returned).
    pub fn emit(&self, kind: &str, fields: Map<String, Value>, at_ms: u64) -> u64 {
        let mut q = self.lock();
        if q.locked {
            return q.seq;
        }
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
        self.news.notify_all();
        seq
    }

    /// Lock v2 locked (`true`) or unlocked the profile. A lock empties the
    /// queue; an unlock takes a seq of its own and counts it as dropped, so
    /// every poll from before it says `reset: true` (what the app showed
    /// before the lock is reloaded). No change: nothing happens.
    pub fn set_locked(&self, locked: bool) {
        let mut q = self.lock();
        if q.locked == locked {
            return;
        }
        q.locked = locked;
        if locked {
            q.events.clear();
        } else {
            q.seq += 1;
        }
        q.dropped_through = q.seq;
        self.news.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What came after `after_seq`. Never blocks beyond the queue's lock.
    /// While locked: no events, `locked`.
    pub fn poll(&self, after_seq: u64) -> Batch {
        Self::batch(&self.lock(), after_seq)
    }

    /// [`Self::poll`], but while it would say nothing (no event after
    /// `after_seq`, no reset, not locked) it waits up to `timeout` for the
    /// next event, lock or unlock, and answers as soon as one comes. Only
    /// the calling thread waits: the queue's lock is let go meanwhile.
    pub fn wait(&self, after_seq: u64, timeout: Duration) -> Batch {
        let deadline = Instant::now() + timeout;
        let mut q = self.lock();
        loop {
            let batch = Self::batch(&q, after_seq);
            let left = deadline.saturating_duration_since(Instant::now());
            if !batch.events.is_empty() || batch.reset || batch.locked || left.is_zero() {
                return batch;
            }
            q = self
                .news
                .wait_timeout(q, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// What `q` holds after `after_seq`.
    fn batch(q: &Queue, after_seq: u64) -> Batch {
        if q.locked {
            return Batch {
                seq: q.seq,
                events: Vec::new(),
                reset: false,
                locked: true,
            };
        }
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
            locked: false,
        }
    }

    /// The newest seq so far.
    #[cfg(test)]
    pub fn seq(&self) -> u64 {
        self.lock().seq
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

    /// Lock v2: the lock empties the queue (a message's text goes with
    /// its `incoming` event), nothing is queued while locked and a poll
    /// says so; the first poll after the unlock says reset, then events
    /// flow again.
    #[test]
    fn a_lock_empties_the_queue_and_keeps_it_empty_until_the_unlock() {
        let hub = EventHub::new();
        hub.emit("incoming", fields(json!({"message": {"text": "hello"}})), 1);
        hub.emit("status_ok", Map::new(), 2);
        let before = hub.poll(0);
        assert_eq!(before.events.len(), 2);
        assert!(!before.locked);
        hub.set_locked(true);
        let locked = hub.poll(0);
        assert!(locked.locked);
        assert!(locked.events.is_empty());
        assert!(!locked.reset);
        assert_eq!(locked.seq, 2);
        // Nothing is queued meanwhile, whatever comes.
        assert_eq!(
            hub.emit("incoming", fields(json!({"message": {"text": "x"}})), 3),
            2
        );
        hub.emit("node", Map::new(), 4);
        assert!(hub.poll(0).events.is_empty());
        assert!(!format!("{:?}", hub.poll(0)).contains("hello"));
        hub.set_locked(true);
        assert_eq!(hub.seq(), 2, "locked already: no change");
        hub.set_locked(false);
        let after = hub.poll(locked.seq);
        assert!(!after.locked);
        assert!(after.reset, "what was shown before the lock is reloaded");
        assert!(after.events.is_empty());
        let seq = hub.emit("incoming", fields(json!({"message": {"text": "new"}})), 5);
        let next = hub.poll(after.seq);
        assert!(!next.reset);
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0]["seq"], seq);
        assert!(!format!("{:?}", hub.poll(0)).contains("hello"));
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
