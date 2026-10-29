//! The deterministic simulation kernel shared by raven-core's simulators
//! (`network_sim_1000`, `learning_sim`): a SplitMix64 generator and a
//! time-ordered event queue that keeps FIFO order among events at the same
//! time. Moved out of `network_sim_1000.rs` unchanged (its numbers stay
//! byte-identical to the baseline-freeze artifact); the queue is generic
//! over the event kind.
//!
//! Each simulator includes it with `#[path = "sim/mod.rs"] mod sim;`, so
//! every test binary compiles its own copy and uses a different part.
#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// One event at simulated time `at`; `sequence` orders events at the same
/// time first in, first out.
#[derive(Clone, Debug)]
pub struct ScheduledEvent<K> {
    pub at: u64,
    pub sequence: u64,
    pub kind: K,
}

impl<K> PartialEq for ScheduledEvent<K> {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.sequence == other.sequence
    }
}

impl<K> Eq for ScheduledEvent<K> {}

impl<K> PartialOrd for ScheduledEvent<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K> Ord for ScheduledEvent<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap; reverse time and sequence for stable FIFO.
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// A [`BinaryHeap`] of [`ScheduledEvent`]s that numbers what it is given:
/// earliest first, FIFO at the same time.
#[derive(Debug)]
pub struct EventQueue<K> {
    events: BinaryHeap<ScheduledEvent<K>>,
    next_sequence: u64,
}

impl<K> Default for EventQueue<K> {
    fn default() -> Self {
        Self {
            events: BinaryHeap::new(),
            next_sequence: 0,
        }
    }
}

impl<K> EventQueue<K> {
    pub fn push(&mut self, at: u64, kind: K) {
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).expect("event sequence bound");
        self.events.push(ScheduledEvent { at, sequence, kind });
    }

    pub fn pop(&mut self) -> Option<ScheduledEvent<K>> {
        self.events.pop()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// SplitMix64: the same stream on every platform and in both builds.
#[derive(Clone, Copy, Debug)]
pub struct DeterministicRng(u64);

impl DeterministicRng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn index(&mut self, upper_exclusive: usize) -> usize {
        assert!(upper_exclusive > 0);
        (self.next_u64() % upper_exclusive as u64) as usize
    }

    pub fn draw_per_10k(&mut self, rate: u16) -> bool {
        rate != 0 && self.next_u64() % 10_000 < u64::from(rate)
    }

    /// A uniform integer in `lo..=hi`.
    pub fn between(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(lo <= hi);
        lo + self.next_u64() % (hi - lo + 1)
    }

    /// A uniform sample from `[0, 1)` (53 bits).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// An exponential sample with mean `mean` (inverse transform).
    pub fn exponential(&mut self, mean: f64) -> f64 {
        -(1.0 - self.unit()).ln() * mean
    }
}
