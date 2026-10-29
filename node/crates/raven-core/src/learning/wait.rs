//! Adaptive waits (design "Phase 6a", algorithms §4: RFC 6298 with a
//! safety factor 2): an arm's connect and first-reply [`Rtt`]s may shorten
//! today's fixed waits, never lengthen them.
//!
//! - `W = clamp((2·RTO) << backoff, MIN, STATIC)` with
//!   `RTO = srtt + max(RTO_G_MS, 4·rttvar)` ([`Rtt::rto_ms`]) and the
//!   expiry backoff at most ×8 ([`MAX_BACKOFF`]; a larger stored value
//!   counts as the cap).
//! - A wait is learned only once its `Rtt` holds [`WARM_SAMPLES`] samples
//!   and the last one is at most [`FRESH_MS`] old; otherwise it is today's
//!   value ([`statics`]). A sample dated after `now_ms` (the clock stepped
//!   back, or a damaged row) is not fresh either: static is the safe side.
//! - `connect` is the TCP connect timeout per address for LAN and Internet
//!   (the 20 s connect budget of a dial stays) and the p2p connect deadline
//!   (direct, then circuits) for p2p.
//! - Nearby always keeps today's waits: it is never learned.
//! - Unchanged: the idle 2 s reply wait, the connect budget, the carriers'
//!   40 s dial deadlines, the worker's 45 s, the inbound handshake limits,
//!   the write and name-resolution timeouts.
//! - The Karn rule is [`super::model::Model::observe`]'s: a dial that
//!   resent an object which went silent before gives no reply sample.
//! - Whether learning is on is the caller's check (raven-node); this
//!   module only turns an arm into waits.
//!
//! Pure: no I/O and no clock read (`now_ms` comes from `raven_core::clock`
//! at the caller), integers only. raven-node's
//! `learning_static_waits_equal_the_node_constants` keeps the `STATIC_*`
//! values equal to the node's own constants.

use std::time::Duration;

use super::estimate::{Rtt, DAY_MS};
pub use super::estimate::{MAX_BACKOFF, RTO_G_MS};
use super::model::Arm;
use crate::outbox::OutboxCarrier;

/// Today's TCP connect timeout per address, LAN and Internet (raven-node
/// `netutil::CONNECT_TIMEOUT`).
pub const STATIC_CONNECT_PER_ADDR: Duration = Duration::from_secs(5);
/// Today's p2p connect deadline (raven-node `p2p::CONNECT_DEADLINE`).
pub const STATIC_P2P_CONNECT: Duration = Duration::from_secs(20);
/// Today's wait for a nearby pipe (raven-node `nearby::CONNECT_BUDGET`).
pub const STATIC_NEARBY_CONNECT: Duration = Duration::from_secs(12);
/// The onion carrier's connect wait: a Tor rendezvous with the friend's
/// onion service ([`crate::onion::ONION_CONNECT_BUDGET`]). Onion is never
/// ranked or learned.
pub const STATIC_ONION_CONNECT: Duration = crate::onion::ONION_CONNECT_BUDGET;
/// Today's first-reply wait, every carrier (raven-node
/// `netutil::PRODUCTION_REPLY_WAITS.first`).
pub const STATIC_REPLY_FIRST: Duration = Duration::from_secs(30);
/// The shortest learned connect wait per LAN address.
pub const MIN_CONNECT_LAN: Duration = Duration::from_millis(1_500);
/// The shortest learned connect wait per Internet address.
pub const MIN_CONNECT_INTERNET: Duration = Duration::from_millis(2_500);
/// The shortest learned p2p connect deadline.
pub const MIN_P2P_CONNECT: Duration = Duration::from_secs(8);
/// The shortest learned first-reply wait: a slow responder (a first
/// Keychain unlock, a full disk) still gets this long.
pub const MIN_REPLY_FIRST: Duration = Duration::from_secs(6);
/// Samples an [`Rtt`] needs before its wait is learned.
pub const WARM_SAMPLES: u16 = 4;
/// The oldest last sample a learned wait may rest on.
pub const FRESH_MS: u64 = DAY_MS;

/// The waits of one dial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Waits {
    /// Per address (LAN, Internet), or the p2p connect deadline.
    pub connect: Duration,
    /// Frames written → first terminal reply.
    pub reply_first: Duration,
    /// At least one of the two came from the arm.
    pub learned: bool,
}

/// One of an arm's two waits (its `Rtt`):
/// [`super::model::Model::rtt_expired`] names the one that ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitKind {
    /// The connect wait ([`Waits::connect`], the arm's `connect` Rtt).
    Connect,
    /// The first-reply wait ([`Waits::reply_first`], the arm's `reply` Rtt).
    Reply,
}

/// Today's waits on `carrier`, `learned = false`.
pub fn statics(carrier: OutboxCarrier) -> Waits {
    let connect = match carrier {
        OutboxCarrier::Lan | OutboxCarrier::Internet => STATIC_CONNECT_PER_ADDR,
        OutboxCarrier::P2p => STATIC_P2P_CONNECT,
        OutboxCarrier::Nearby => STATIC_NEARBY_CONNECT,
        OutboxCarrier::Onion => STATIC_ONION_CONNECT,
    };
    Waits {
        connect,
        reply_first: STATIC_REPLY_FIRST,
        learned: false,
    }
}

/// The floor of a learned connect wait; `None` for nearby (never learned).
fn min_connect(carrier: OutboxCarrier) -> Option<Duration> {
    match carrier {
        OutboxCarrier::Lan => Some(MIN_CONNECT_LAN),
        OutboxCarrier::Internet => Some(MIN_CONNECT_INTERNET),
        OutboxCarrier::P2p => Some(MIN_P2P_CONNECT),
        OutboxCarrier::Nearby | OutboxCarrier::Onion => None,
    }
}

/// The waits for a dial on `carrier` whose arm is `arm` (module doc):
/// each wait learned when its `Rtt` is warm and fresh, otherwise today's.
/// Never above [`statics`].
pub fn waits(arm: Option<&Arm>, carrier: OutboxCarrier, now_ms: u64) -> Waits {
    let base = statics(carrier);
    let (Some(arm), Some(min_connect)) = (arm, min_connect(carrier)) else {
        return base;
    };
    let connect = adapted(&arm.connect, now_ms, min_connect, base.connect);
    let reply_first = adapted(&arm.reply, now_ms, MIN_REPLY_FIRST, base.reply_first);
    Waits {
        connect: connect.unwrap_or(base.connect),
        reply_first: reply_first.unwrap_or(base.reply_first),
        learned: connect.is_some() || reply_first.is_some(),
    }
}

/// `(2·RTO) << backoff` held to `[min, max]` (never above `max`), when
/// `rtt` is warm and fresh at `now_ms`.
fn adapted(rtt: &Rtt, now_ms: u64, min: Duration, max: Duration) -> Option<Duration> {
    let fresh = now_ms
        .checked_sub(rtt.at_ms)
        .is_some_and(|age| age <= FRESH_MS);
    if rtt.n < WARM_SAMPLES || !fresh {
        return None;
    }
    // At most 2·(2³² − 1) << 3: no overflow.
    let w_ms = (2 * u64::from(rtt.rto_ms())) << rtt.backoff.min(MAX_BACKOFF);
    Some(Duration::from_millis(w_ms).max(min).min(max))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::model::{ArmKey, Model};
    use crate::learning::observe::{DialTiming, Evidence, FrameKind, Observation};
    use OutboxCarrier::{Internet, Lan, Nearby, P2p};

    const NOW: u64 = 1_800_000_000_000;
    const ALL: [OutboxCarrier; 4] = [Lan, Internet, P2p, Nearby];

    fn rtt(samples: &[u32], at_ms: u64) -> Rtt {
        let mut r = Rtt::default();
        for s in samples {
            r.sample(*s, at_ms);
        }
        r
    }

    /// An arm whose connect and reply waits saw these samples at `at_ms`.
    fn arm(carrier: OutboxCarrier, connect: &[u32], reply: &[u32], at_ms: u64) -> Arm {
        let mut a = Arm::new(carrier);
        a.connect = rtt(connect, at_ms);
        a.reply = rtt(reply, at_ms);
        a
    }

    #[test]
    fn cold_or_stale_is_static() {
        assert_eq!(statics(Lan).connect, STATIC_CONNECT_PER_ADDR);
        assert_eq!(statics(Internet).connect, STATIC_CONNECT_PER_ADDR);
        assert_eq!(statics(P2p).connect, STATIC_P2P_CONNECT);
        assert_eq!(statics(Nearby).connect, STATIC_NEARBY_CONNECT);
        for carrier in ALL {
            let s = statics(carrier);
            assert_eq!((s.reply_first, s.learned), (STATIC_REPLY_FIRST, false));
            assert_eq!(waits(None, carrier, NOW), s, "{carrier:?}: no arm");
            // Three samples are not warm.
            let a = arm(carrier, &[20; 3], &[50; 3], NOW);
            assert_eq!(waits(Some(&a), carrier, NOW), s, "{carrier:?}: cold");
            // Warm, but the last samples are a day and 1 ms old.
            let a = arm(carrier, &[20; 4], &[50; 4], NOW - FRESH_MS - 1);
            assert_eq!(waits(Some(&a), carrier, NOW), s, "{carrier:?}: stale");
            // Dated after now: the clock stepped back, or a damaged row.
            let a = arm(carrier, &[20; 4], &[50; 4], NOW + 1);
            assert_eq!(waits(Some(&a), carrier, NOW), s, "{carrier:?}: future");
        }
        // Exactly FRESH_MS old is still fresh, and one learned wait is
        // enough for `learned`.
        let a = arm(Lan, &[20; 4], &[50; 3], NOW - FRESH_MS);
        assert_eq!(
            waits(Some(&a), Lan, NOW),
            Waits {
                connect: MIN_CONNECT_LAN,
                reply_first: STATIC_REPLY_FIRST,
                learned: true,
            }
        );
    }

    #[test]
    fn warm_lan_connect_floors_at_1500ms() {
        // RTO = 20 + max(200, 4·3) = 220 ms; 2·RTO = 440 ms is under the
        // floor.
        let a = arm(Lan, &[20; 4], &[], NOW);
        assert_eq!(a.connect.rto_ms(), 220);
        let w = waits(Some(&a), Lan, NOW);
        assert_eq!(w.connect, Duration::from_millis(1_500));
        assert_eq!((w.reply_first, w.learned), (STATIC_REPLY_FIRST, true));
        // The other carriers' floors.
        let a = arm(Internet, &[20; 4], &[], NOW);
        assert_eq!(
            waits(Some(&a), Internet, NOW).connect,
            Duration::from_millis(2_500)
        );
        let a = arm(P2p, &[20; 4], &[], NOW);
        assert_eq!(waits(Some(&a), P2p, NOW).connect, Duration::from_secs(8));
        // Between the floor and today's value the wait is 2·RTO itself:
        // rttvar 500 → 375 → 281 → 210, RTO = 1000 + 840 ms.
        let a = arm(Lan, &[1_000; 4], &[], NOW);
        assert_eq!(a.connect.rto_ms(), 1_840);
        assert_eq!(
            waits(Some(&a), Lan, NOW).connect,
            Duration::from_millis(3_680)
        );
    }

    /// xorshift64*: the property's seeded arms are the same on every run
    /// and platform.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn rtt(&mut self) -> Rtt {
            Rtt {
                srtt_ms: (self.next() as u32) >> (self.next() % 32),
                rttvar_ms: (self.next() as u32) >> (self.next() % 32),
                n: (self.next() % 8) as u16,
                backoff: self.next() as u8,
                at_ms: NOW + 1_000 - self.next() % (2 * FRESH_MS),
            }
        }
    }

    #[test]
    fn slow_samples_never_exceed_static() {
        // Samples above today's values give exactly today's values.
        for carrier in [Lan, Internet, P2p] {
            let a = arm(carrier, &[60_000; 4], &[90_000; 4], NOW);
            let w = waits(Some(&a), carrier, NOW);
            assert_eq!(
                (w.connect, w.reply_first, w.learned),
                (statics(carrier).connect, STATIC_REPLY_FIRST, true)
            );
        }
        // Seeded arms of any shape (huge, zero, a damaged backoff, any
        // age): never above today's value, never below the floor.
        let mut rng = XorShift(0x5EED_6A05);
        for _ in 0..5_000 {
            let carrier = ALL[(rng.next() % 4) as usize];
            let mut a = Arm::new(carrier);
            a.connect = rng.rtt();
            a.reply = rng.rtt();
            let s = statics(carrier);
            let w = waits(Some(&a), carrier, NOW);
            assert!(w.connect <= s.connect && w.reply_first <= s.reply_first);
            assert!(w.connect >= min_connect(carrier).unwrap_or(s.connect));
            assert!(w.reply_first >= MIN_REPLY_FIRST);
            if carrier == Nearby {
                assert_eq!(w, s);
            }
        }
    }

    #[test]
    fn backoff_doubles_then_caps() {
        // Replies of 2 s: rttvar 1000 → 750 → 562 → 421, RTO = 2000 + 1684
        // ms, 2·RTO = 7368 ms.
        let mut a = arm(Lan, &[], &[2_000; 4], NOW);
        assert_eq!(a.reply.rto_ms(), 3_684);
        let reply = |a: &Arm| waits(Some(a), Lan, NOW).reply_first;
        assert_eq!(reply(&a), Duration::from_millis(7_368));
        a.reply.expired();
        assert_eq!(reply(&a), Duration::from_millis(14_736));
        a.reply.expired();
        assert_eq!(reply(&a), Duration::from_millis(29_472));
        // ×8 would be 58.9 s: held at today's 30 s.
        a.reply.expired();
        assert_eq!((reply(&a), a.reply.backoff), (STATIC_REPLY_FIRST, 3));
        // The backoff itself stops at ×8.
        a.reply.expired();
        assert_eq!(
            (reply(&a), a.reply.backoff),
            (STATIC_REPLY_FIRST, MAX_BACKOFF)
        );
        // A damaged stored backoff counts as the cap (no shift overflow).
        a.reply.backoff = u8::MAX;
        assert_eq!(reply(&a), STATIC_REPLY_FIRST);
        // The next sample clears it: rttvar (3·421)/4 = 315, RTO = 3260 ms.
        a.reply.sample(2_000, NOW);
        assert_eq!(reply(&a), Duration::from_millis(6_520));
        // The connect wait backs off the same way, capped at today's 20 s.
        let mut a = arm(P2p, &[4_000; 4], &[], NOW);
        let connect = |a: &Arm| waits(Some(a), P2p, NOW).connect;
        // rttvar 2000 → 1500 → 1125 → 843, RTO = 4000 + 3372 ms.
        assert_eq!(a.connect.rto_ms(), 7_372);
        assert_eq!(connect(&a), Duration::from_millis(14_744));
        a.connect.expired();
        assert_eq!(connect(&a), STATIC_P2P_CONNECT);
    }

    #[test]
    fn reply_floor_6s() {
        // RTO = 50 + max(200, 4·9) = 250 ms; 2·RTO = 500 ms.
        for carrier in [Lan, Internet, P2p] {
            let a = arm(carrier, &[], &[50; 4], NOW);
            assert_eq!(a.reply.rto_ms(), 250);
            let w = waits(Some(&a), carrier, NOW);
            assert_eq!(w.reply_first, Duration::from_secs(6), "{carrier:?}");
            assert_eq!(w.connect, statics(carrier).connect);
        }
    }

    #[test]
    fn nearby_is_always_static() {
        let mut a = arm(Nearby, &[20; 8], &[50; 8], NOW);
        assert_eq!(waits(Some(&a), Nearby, NOW), statics(Nearby));
        a.reply.expired();
        assert_eq!(waits(Some(&a), Nearby, NOW), statics(Nearby));
        // Even another carrier's warm arm, asked for nearby.
        let lan = arm(Lan, &[20; 8], &[50; 8], NOW);
        assert!(waits(Some(&lan), Lan, NOW).learned);
        assert_eq!(waits(Some(&lan), Nearby, NOW), statics(Nearby));
    }

    #[test]
    fn karn_excluded_samples_do_not_move_reply() {
        let mut m = Model::new_empty([7; 32]);
        let key = ArmKey {
            contact: [0xB0; 32],
            net: Some("home".into()),
            carrier: Lan,
        };
        let mut o = Observation {
            contact: key.contact,
            net: key.net.clone(),
            net_changed: false,
            carrier: Lan,
            path: None,
            relay: None,
            kind: FrameKind::Message,
            evidence: Evidence::Receipt,
            timing: DialTiming {
                connect_ms: Some(20),
                reply_ms: Some(50),
                total_ms: 100,
            },
            karn_exclude: true,
            at_ms: NOW,
        };
        for _ in 0..WARM_SAMPLES {
            m.observe(&o, NOW);
        }
        let a = m.arm(&key).unwrap();
        assert_eq!((a.connect.n, a.reply.n), (WARM_SAMPLES, 0));
        // The connect wait is learned; the reply wait stays today's.
        assert_eq!(
            waits(Some(a), Lan, NOW),
            Waits {
                connect: MIN_CONNECT_LAN,
                reply_first: STATIC_REPLY_FIRST,
                learned: true,
            }
        );
        // Warm from plain dials, a Karn-excluded slow reply still moves
        // nothing ...
        o.karn_exclude = false;
        for _ in 0..WARM_SAMPLES {
            m.observe(&o, NOW);
        }
        let before = waits(m.arm(&key), Lan, NOW);
        assert_eq!(before.reply_first, MIN_REPLY_FIRST);
        o.karn_exclude = true;
        o.timing.reply_ms = Some(29_000);
        m.observe(&o, NOW);
        assert_eq!(waits(m.arm(&key), Lan, NOW), before);
        // ... while the same reply without the exclusion lengthens it.
        o.karn_exclude = false;
        m.observe(&o, NOW);
        assert!(waits(m.arm(&key), Lan, NOW).reply_first > before.reply_first);
    }
}
