//! Phase 6a acceptance gate (P6.8; design "Phase 6a", testing "Simulator
//! gate"): the learning core against today's static planner on the eight
//! scenario families of the plan, before anything is wired into raven-node.
//!
//! It drives the real code: `outbox::plan_object_routes` (static) and
//! `outbox::plan_object_routes_ranked` with `learning::rank::order`
//! (learned) over one saved contact (LAN, Internet and p2p routes),
//! `learning::wait` (statics and adaptive waits), `Model::observe` through
//! `learning::observe::evidence` (real message and ACK frames), the relay
//! terms for the circuit order (`Model::relay_terms`, `relay_circuit`), and
//! `Model::encounter`, `carry_pick` and `carry_outcome` for the carry choice.
//! Only three things are modelled here:
//! - the world: what a route or relay circuit does at a time
//!   ([`World::state`]);
//! - the worker as raven-node runs it today: the planned routes one after
//!   another, a silent dial (frames written, no ACK) ends the attempt, the
//!   next attempt starts past the silent route (G3), `outbox::retry_delay`
//!   between attempts, no reply sample after an object went silent (Karn);
//! - the explorer of design §5 (raven-node gets it in P6.14): a tick each
//!   minute, a token bucket of 6 per hour with a burst of 2, one probe in
//!   flight, none in the 2 min after a network change, not the top carrier,
//!   LAN and Internet only after a receipt on this network in 7 d, gaps of
//!   60 min (15 min for a demoted arm that just succeeded; these are the
//!   values `learning::Tune` replaces in a lab run), the stalest arm first;
//!   a probe is a frame-less dial.
//!
//! Route families report time to receipt (mean, p95, last quarter), the
//! delivery rate, dials per delivered message (each relay circuit tried
//! counts as one dial) and probes per hour; cutoff families report the
//! expected delivery probability of the custodians chosen (the
//! hypoexponential CDF of the world's true meeting rates, so sampling luck
//! does not decide a seed). The thresholds are the plan's (P6.8) and are
//! never relaxed without the owner's OK. Also asserted: every seed of every
//! route family within 1.10 × static + 100 ms on the mean, at most 6 probes
//! per hour on average and no more than the bucket allows (6 + 2) in any
//! hour, no probe with a frame, every learned plan a pure reorder of the
//! static one (`rank::same_set_as_static`), at most `CARRY_CAP` copies.
//!
//! The families follow the Python prototype
//! (docs/roadmap/research/prototypes/learning-simulator/learnsim_final3.py),
//! with two choices it left open: the adaptive attacker black-holes the
//! direct route that carried the last receipt (chosen again every 20 min),
//! and `lan_recovery`'s LAN route delivered on this network before the
//! outage (as a recovering route did; OD6a-5 probes no other).
//! `lan_recovery_cold` runs it with an empty model: it is reported, and its
//! last quarter stays on the Internet by OD6a-5 (not asserted; an owner
//! item).
//!
//! Known gap: the model has no expiry hook yet (`Model::rtt_expired` comes
//! with P6.13), so an expired learned wait does not back off here.
//!
//! Deterministic: SplitMix64 streams per seed (`sim/mod.rs`) and integer
//! times in ms; the same numbers in debug and release on one platform.

#[path = "sim/mod.rs"]
mod sim;

use std::cmp::Reverse;
use std::time::Duration;

use raven_core::envelope::{EnvType, Envelope};
use raven_core::learning::carry::{Candidate, CARRY_CAP};
use raven_core::learning::model::{ArmKey, Model};
use raven_core::learning::observe::{evidence, DialTiming, Evidence, FrameKind, Observation};
use raven_core::learning::{rank, wait};
use raven_core::outbox::{
    plan_object_routes, plan_object_routes_ranked, retry_delay, CarrierChoice, CarrierGates,
    ContactRoutes, DeliveryPath, ObjectRoutes, OutboxCarrier, OutboxRoute,
};
use raven_core::reach_diag::CircuitOutcome;
use sim::{DeterministicRng, EventQueue};

const S: u64 = 1_000;
const MIN: u64 = 60 * S;
const HOUR: u64 = 60 * MIN;
const DAY: u64 = 24 * HOUR;
/// Simulated time 0 on the model's clock: well after 0, so a time the model
/// never recorded (0) is long ago.
const EPOCH_MS: u64 = 1_800_000_000_000;

const ROUTE_SEEDS: u64 = 24;
const CUTOFF_SEEDS: u64 = 96;
/// Messages per route-family run, and their mean gap (exponential).
const MESSAGES: usize = 300;
const MESSAGE_GAP_MS: f64 = 2.0 * 60_000.0;
/// A message not confirmed this long after it was written counts as not
/// delivered.
const HORIZON_MS: u64 = 6 * HOUR;
/// One relay circuit's share of the p2p connect deadline.
const CIRCUIT_MS: u64 = 10 * S;
/// What a refused connection costs.
const REFUSED_MS: u64 = 50;

/// The explorer (design §5).
const TICK_MS: u64 = MIN;
const PROBES_PER_HOUR: u64 = 6;
const PROBE_BURST: u64 = 2;
const PROBE_ARM_GAP_MS: u64 = 60 * MIN;
const RECOVER_GAP_MS: u64 = 15 * MIN;
const STALE_MS: u64 = 30 * MIN;
const RECEIPT_WINDOW_MS: u64 = 7 * DAY;
const ACTIVE_MS: u64 = 7 * DAY;
const SETTLE_MS: u64 = 2 * MIN;

/// The stable dial codes the worker records (raven-node `dial_error_code`).
const NOT_REACHABLE: &str = "NOT_REACHABLE";
const NOT_LISTENING: &str = "NOT_LISTENING";

const BOB: [u8; 32] = [0xB0; 32];
const MODEL_SECRET: [u8; 32] = [0x5E; 32];
/// The contact's relays, in book order.
const RELAYS: [&[u8]; 2] = [b"relay-r1", b"relay-r2"];
const GATES: CarrierGates = CarrierGates {
    lan: true,
    internet: true,
    p2p: true,
    nearby: false,
    onion: false,
};

// ── The world ────────────────────────────────────────────────────────────────

/// Where a dial goes: a direct route or one relay circuit of the p2p dial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Lan,
    Internet,
    Circuit(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Connects and answers.
    Ok,
    /// Nothing answers: the connect wait runs out.
    Blackhole,
    /// The connection is refused at once.
    Refused,
    /// Connects, then never replies.
    Stall,
    /// Nobody is there: refused once the connect time has passed.
    Offline,
}

/// The mode of a target at a time, and the connect and first-reply times
/// it takes when it answers (ms).
type State = (Mode, u64, u64);

trait World {
    /// The network tag at `t`.
    fn net_at(&self, _t: u64) -> &'static str {
        "n0"
    }

    fn state(&mut self, net: &str, target: Target, t: u64) -> State;

    /// A receipt came back over `carrier` at `t` (the adaptive attacker
    /// watches).
    fn delivered(&mut self, _carrier: OutboxCarrier, _t: u64) {}
}

fn ok(rng: &mut DeterministicRng, connect: (u64, u64), reply: (u64, u64)) -> State {
    (
        Mode::Ok,
        rng.between(connect.0, connect.1),
        rng.between(reply.0, reply.1),
    )
}

/// Everything works.
struct StableControl {
    rng: DeterministicRng,
}

impl World for StableControl {
    fn state(&mut self, _net: &str, target: Target, _t: u64) -> State {
        match target {
            Target::Lan => ok(&mut self.rng, (20, 50), (80, 140)),
            Target::Internet => ok(&mut self.rng, (150, 250), (300, 500)),
            Target::Circuit(_) => ok(&mut self.rng, (800, 1_400), (900, 1_500)),
        }
    }
}

/// The LAN flaps: up about 10 min, down about 4 min (a black hole 60 %, a
/// stall 25 %, refused 15 %); the Internet route black-holes 2 % of dials.
struct FlakyWifi {
    rng: DeterministicRng,
    /// (end, LAN mode until then), in time order.
    periods: Vec<(u64, Mode)>,
}

impl FlakyWifi {
    fn new(seed: u64) -> Self {
        let mut rng = DeterministicRng::new(seed ^ 0x666c_616b_7900);
        let mut periods = Vec::new();
        let (mut t, mut up) = (0, true);
        while t < 4 * DAY {
            let mean = if up { 10.0 } else { 4.0 } * 60_000.0;
            let end = t + rng.exponential(mean) as u64;
            let mode = if up {
                Mode::Ok
            } else {
                match rng.index(100) {
                    0..60 => Mode::Blackhole,
                    60..85 => Mode::Stall,
                    _ => Mode::Refused,
                }
            };
            periods.push((end, mode));
            (t, up) = (end, !up);
        }
        Self {
            rng: DeterministicRng::new(seed),
            periods,
        }
    }

    fn lan_mode(&self, t: u64) -> Mode {
        let i = self.periods.partition_point(|(end, _)| *end <= t);
        self.periods.get(i).map_or(Mode::Ok, |p| p.1)
    }
}

impl World for FlakyWifi {
    fn state(&mut self, _net: &str, target: Target, t: u64) -> State {
        match target {
            Target::Lan => {
                let (_, c, r) = ok(&mut self.rng, (20, 60), (100, 180));
                (self.lan_mode(t), c, r)
            }
            Target::Internet if self.rng.draw_per_10k(200) => (Mode::Blackhole, 0, 0),
            Target::Internet => ok(&mut self.rng, (200, 350), (350, 600)),
            Target::Circuit(_) => ok(&mut self.rng, (900, 1_500), (900, 1_600)),
        }
    }
}

/// Home and office alternate every 3 h; at the office the saved LAN address
/// black-holes.
struct NetworkSwitch {
    rng: DeterministicRng,
}

impl World for NetworkSwitch {
    fn net_at(&self, t: u64) -> &'static str {
        if (t / (3 * HOUR)).is_multiple_of(2) {
            "home"
        } else {
            "office"
        }
    }

    fn state(&mut self, net: &str, target: Target, _t: u64) -> State {
        match target {
            Target::Lan if net == "office" => (Mode::Blackhole, 0, 0),
            Target::Lan => ok(&mut self.rng, (20, 50), (90, 150)),
            Target::Internet => ok(&mut self.rng, (200, 350), (350, 600)),
            Target::Circuit(_) => ok(&mut self.rng, (900, 1_500), (900, 1_600)),
        }
    }
}

/// A remote contact: LAN and Internet black-hole, p2p goes through relay r1
/// or r2 (book order), and r1 dies at 1 h.
struct RelayDeath {
    rng: DeterministicRng,
}

impl World for RelayDeath {
    fn state(&mut self, _net: &str, target: Target, t: u64) -> State {
        match target {
            Target::Lan | Target::Internet => (Mode::Blackhole, 0, 0),
            Target::Circuit(0) if t >= HOUR => (Mode::Blackhole, 0, 0),
            Target::Circuit(_) => ok(&mut self.rng, (1_200, 2_000), (900, 1_600)),
        }
    }
}

/// An on-path attacker black-holes the direct route (LAN or Internet) that
/// carried the last receipt, choosing again every 20 min. It can only cause
/// failures.
struct AdaptiveAttacker {
    rng: DeterministicRng,
    window: u64,
    target: OutboxCarrier,
    used_last: OutboxCarrier,
}

impl World for AdaptiveAttacker {
    fn state(&mut self, _net: &str, target: Target, t: u64) -> State {
        let window = t / (20 * MIN);
        if window > self.window {
            self.window = window;
            self.target = self.used_last;
        }
        match target {
            Target::Lan if self.target == OutboxCarrier::Lan => (Mode::Blackhole, 0, 0),
            Target::Internet if self.target == OutboxCarrier::Internet => (Mode::Blackhole, 0, 0),
            Target::Lan => ok(&mut self.rng, (20, 60), (100, 180)),
            Target::Internet => ok(&mut self.rng, (200, 350), (350, 600)),
            Target::Circuit(_) => ok(&mut self.rng, (900, 1_500), (900, 1_600)),
        }
    }

    fn delivered(&mut self, carrier: OutboxCarrier, _t: u64) {
        if matches!(carrier, OutboxCarrier::Lan | OutboxCarrier::Internet) {
            self.used_last = carrier;
        }
    }
}

/// The LAN is dead for 3 h, then perfect. In `lan_recovery` the LAN route
/// had delivered on this network before the outage ([`lan_history`]); in
/// `lan_recovery_cold` the model starts empty.
struct LanRecovery {
    rng: DeterministicRng,
}

impl World for LanRecovery {
    fn state(&mut self, _net: &str, target: Target, t: u64) -> State {
        match target {
            Target::Lan if t < 3 * HOUR => (Mode::Blackhole, 0, 0),
            Target::Lan => ok(&mut self.rng, (20, 50), (90, 150)),
            Target::Internet => ok(&mut self.rng, (200, 350), (350, 600)),
            Target::Circuit(_) => ok(&mut self.rng, (900, 1_500), (900, 1_600)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RouteFamily {
    StableControl,
    FlakyWifi,
    NetworkSwitch,
    RelayDeath,
    AdaptiveAttacker,
    LanRecovery,
    /// `lan_recovery` with an empty model: reported, and every bound but
    /// the last-quarter one asserted (see [`route_thresholds`]).
    LanRecoveryCold,
}

impl RouteFamily {
    const ALL: [Self; 7] = [
        Self::StableControl,
        Self::FlakyWifi,
        Self::NetworkSwitch,
        Self::RelayDeath,
        Self::AdaptiveAttacker,
        Self::LanRecovery,
        Self::LanRecoveryCold,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::StableControl => "stable_control",
            Self::FlakyWifi => "flaky_wifi",
            Self::NetworkSwitch => "network_switch",
            Self::RelayDeath => "relay_death",
            Self::AdaptiveAttacker => "adaptive_attacker",
            Self::LanRecovery => "lan_recovery",
            Self::LanRecoveryCold => "lan_recovery_cold",
        }
    }

    fn world(self, seed: u64) -> Box<dyn World> {
        let rng = DeterministicRng::new(seed);
        match self {
            Self::StableControl => Box::new(StableControl { rng }),
            Self::FlakyWifi => Box::new(FlakyWifi::new(seed)),
            Self::NetworkSwitch => Box::new(NetworkSwitch { rng }),
            Self::RelayDeath => Box::new(RelayDeath { rng }),
            Self::AdaptiveAttacker => Box::new(AdaptiveAttacker {
                rng,
                window: 0,
                target: OutboxCarrier::Lan,
                used_last: OutboxCarrier::Lan,
            }),
            Self::LanRecovery | Self::LanRecoveryCold => Box::new(LanRecovery { rng }),
        }
    }
}

/// `lan_recovery`'s history: the LAN route delivered on this network an
/// hour before the run, as a stored model remembers (arms are kept 30 d).
/// A recovering LAN route is one that worked here before; without such a
/// receipt OD6a-5 never lets the explorer probe it (`lan_recovery_cold`).
fn lan_history(model: &mut Model) {
    let at = EPOCH_MS - HOUR;
    let kind = FrameKind::of(&[frame(EnvType::Message)]);
    let ev = evidence(kind, Some(&[frame(EnvType::Ack)]), true, None, false);
    assert_eq!(ev, Evidence::Receipt);
    let o = Observation {
        contact: BOB,
        net: Some("n0".into()),
        net_changed: false,
        carrier: OutboxCarrier::Lan,
        path: Some(DeliveryPath::Direct),
        relay: None,
        kind,
        evidence: ev,
        timing: DialTiming {
            connect_ms: Some(35),
            reply_ms: Some(120),
            total_ms: 155,
        },
        karn_exclude: false,
        at_ms: at,
    };
    model.observe(&o, at);
}

// ── The worker and the planners ──────────────────────────────────────────────

/// One saved contact with a LAN, an Internet and a p2p route (book order).
fn contact() -> ContactRoutes {
    let peer = raven_core::p2p_route::peer_id_from_ed25519_public(&[0x5A; 32]);
    let route = |carrier, dial: String| OutboxRoute { carrier, dial };
    ContactRoutes {
        routes: vec![
            route(OutboxCarrier::Lan, "10.0.0.2:7420".into()),
            route(OutboxCarrier::Internet, "203.0.113.7:7420".into()),
            route(OutboxCarrier::P2p, format!("/p2p/{peer}")),
        ],
        pinned: true,
        ..ContactRoutes::default()
    }
}

/// A send that did not force a carrier.
fn record() -> ObjectRoutes {
    ObjectRoutes {
        peer_pub_hex: hex::encode(BOB),
        choice: CarrierChoice::Auto,
        routes: Vec::new(),
        expires_at_ms: u64::MAX,
        unsent: false,
        written: false,
        custodians_held: Vec::new(),
        custody: false,
        custody_forwarded: false,
    }
}

fn frame(env_type: EnvType) -> Vec<u8> {
    Envelope {
        env_type: env_type as u8,
        flags: 0,
        message_id: [0x11; 16],
        routing_tag: [0x22; 16],
        dest_device_hint: 0,
        created_at: 1,
        expires_at: 2,
        hop_limit: 4,
        replication_budget: 1,
        anti_replay_nonce: [0x33; 12],
        ratchet_header_ciphertext: vec![],
        message_ciphertext: vec![0x44; 32],
        sender_authentication: vec![0; 64],
    }
    .pack()
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn ms32(ms: u64) -> u32 {
    u32::try_from(ms).unwrap_or(u32::MAX)
}

/// What one dial did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Res {
    Receipt,
    Silent,
    Link,
    Fail(&'static str),
}

#[derive(Clone, Debug)]
struct DialOut {
    route: OutboxRoute,
    net: &'static str,
    res: Res,
    took: u64,
    connect_ms: Option<u64>,
    reply_ms: Option<u64>,
    /// The relay circuit that carried a p2p dial.
    via: Option<usize>,
    /// Circuits that failed, and when.
    circuits: Vec<(usize, CircuitOutcome, u64)>,
    /// Connection attempts (a route, or each relay circuit tried).
    dials: u64,
    /// Frames written on the link (none for a probe).
    frames_written: usize,
}

struct Msg {
    t0: u64,
    failures: u32,
    /// The route of the last silent dial (G3 starts the next attempt past it).
    silent_route: Option<OutboxRoute>,
    /// It went silent once: no more reply samples (Karn).
    went_silent: bool,
    plan: Vec<OutboxRoute>,
    next: usize,
    pending: Option<DialOut>,
    dials: u64,
    /// `Some(time to receipt)` once delivered.
    done: Option<u64>,
}

/// The learning side: the model and the explorer's state.
struct Learner {
    model: Model,
    relays: Vec<Vec<u8>>,
    tokens_milli: u64,
    tokens_at: u64,
    net: Option<&'static str>,
    settle_until: u64,
    last_message_dial: Option<u64>,
    probe_busy: bool,
    probe: Option<DialOut>,
    probe_times: Vec<u64>,
    probes_with_frames: u64,
    plans: u64,
}

#[derive(Clone, Copy, Debug)]
enum Ev {
    Attempt(usize),
    DialEnd(usize),
    Tick,
    ProbeEnd,
}

struct Runner {
    world: Box<dyn World>,
    learner: Option<Learner>,
    queue: EventQueue<Ev>,
    jitter: DeterministicRng,
    msgs: Vec<Msg>,
    contact: ContactRoutes,
    record: ObjectRoutes,
    message: Vec<Vec<u8>>,
    ack: Vec<Vec<u8>>,
    unsettled: usize,
    end: u64,
}

/// One run of one family, seed and planner.
#[derive(Clone, Debug, PartialEq)]
struct RunStats {
    /// Times to receipt of the delivered messages, in message order.
    times: Vec<u64>,
    messages: usize,
    dials: u64,
    probe_times: Vec<u64>,
    probes_with_frames: u64,
    plans_checked: u64,
    end_ms: u64,
}

impl RunStats {
    fn mean(&self) -> f64 {
        mean(&self.times)
    }
}

impl Runner {
    fn new(world: Box<dyn World>, learn: bool, seed: u64) -> Self {
        let learner = learn.then(|| Learner {
            model: Model::new_empty(MODEL_SECRET),
            relays: RELAYS.iter().map(|r| r.to_vec()).collect(),
            tokens_milli: PROBE_BURST * 1_000,
            tokens_at: 0,
            net: None,
            settle_until: 0,
            last_message_dial: None,
            probe_busy: false,
            probe: None,
            probe_times: Vec::new(),
            probes_with_frames: 0,
            plans: 0,
        });
        Self {
            world,
            learner,
            queue: EventQueue::default(),
            jitter: DeterministicRng::new(seed ^ 0x6a69_7474_6572),
            msgs: Vec::new(),
            contact: contact(),
            record: record(),
            message: vec![frame(EnvType::Message)],
            ack: vec![frame(EnvType::Ack)],
            unsettled: 0,
            end: 0,
        }
    }

    fn run(mut self, arrivals: &[u64]) -> RunStats {
        assert_eq!(FrameKind::of(&self.message), FrameKind::Message);
        for (m, t0) in arrivals.iter().enumerate() {
            self.msgs.push(Msg {
                t0: *t0,
                failures: 0,
                silent_route: None,
                went_silent: false,
                plan: Vec::new(),
                next: 0,
                pending: None,
                dials: 0,
                done: None,
            });
            self.queue.push(*t0, Ev::Attempt(m));
        }
        self.unsettled = arrivals.len();
        if self.learner.is_some() {
            self.queue.push(0, Ev::Tick);
        }
        while let Some(ev) = self.queue.pop() {
            let t = ev.at;
            self.end = self.end.max(t);
            match ev.kind {
                Ev::Attempt(m) => self.attempt(m, t),
                Ev::DialEnd(m) => self.dial_end(m, t),
                Ev::Tick => self.tick(t),
                Ev::ProbeEnd => self.probe_end(t),
            }
        }
        assert_eq!(self.unsettled, 0);
        let learner = self.learner.as_ref();
        RunStats {
            times: self.msgs.iter().filter_map(|m| m.done).collect(),
            messages: self.msgs.len(),
            dials: self.msgs.iter().map(|m| m.dials).sum(),
            probe_times: learner.map(|l| l.probe_times.clone()).unwrap_or_default(),
            probes_with_frames: learner.map_or(0, |l| l.probes_with_frames),
            plans_checked: learner.map_or(0, |l| l.plans),
            end_ms: self.end,
        }
    }

    /// The routes of one attempt on `net`: the static plan, or the learned
    /// order applied by the real planner (always a pure reorder).
    fn plan(&mut self, net: &'static str, now: u64) -> Vec<OutboxRoute> {
        let fixed = plan_object_routes(Some(&self.record), &self.contact, GATES);
        let Some(l) = self.learner.as_mut() else {
            return fixed.routes;
        };
        let carriers = rank::carriers_of(&fixed.routes);
        let order = rank::order(&l.model, &BOB, Some(net), &carriers, None, now);
        let ranked =
            plan_object_routes_ranked(Some(&self.record), &self.contact, GATES, Some(&order));
        assert!(!ranked.learning_contradiction, "{order:?}");
        assert!(
            rank::same_set_as_static(&ranked.routes, &fixed.routes, fixed.routes.len()),
            "{:?} vs {:?}",
            ranked.routes,
            fixed.routes
        );
        l.model.remember_order(&BOB, Some(net), &order);
        l.plans += 1;
        ranked.routes
    }

    fn waits(&self, carrier: OutboxCarrier, net: &str, now: u64) -> wait::Waits {
        let fixed = wait::statics(carrier);
        let Some(l) = &self.learner else {
            return fixed;
        };
        let key = ArmKey {
            contact: BOB,
            net: Some(net.to_owned()),
            carrier,
        };
        let w = wait::waits(l.model.arm(&key), carrier, now);
        assert!(w.connect <= fixed.connect && w.reply_first <= fixed.reply_first);
        w
    }

    /// The circuits of a p2p dial: book order, or stable by relay term.
    fn circuits(&self, now: u64) -> Vec<usize> {
        let mut order: Vec<usize> = (0..RELAYS.len()).collect();
        if let Some(l) = &self.learner {
            let terms = l.model.relay_terms(&l.relays, now);
            order.sort_by_key(|r| Reverse(terms[*r]));
        }
        order
    }

    /// One dial of `route` at `t` that writes `frames` once linked (none:
    /// a probe).
    fn dial(
        &mut self,
        route: &OutboxRoute,
        net: &'static str,
        t: u64,
        frames: &[Vec<u8>],
    ) -> DialOut {
        let now = EPOCH_MS + t;
        let waits = self.waits(route.carrier, net, now);
        let (connect_wait, reply_wait) = (millis(waits.connect), millis(waits.reply_first));
        let mut out = DialOut {
            route: route.clone(),
            net,
            res: Res::Fail(NOT_REACHABLE),
            took: 0,
            connect_ms: None,
            reply_ms: None,
            via: None,
            circuits: Vec::new(),
            dials: 0,
            frames_written: 0,
        };
        let connected = match route.carrier {
            OutboxCarrier::Lan | OutboxCarrier::Internet => {
                out.dials = 1;
                let target = if route.carrier == OutboxCarrier::Lan {
                    Target::Lan
                } else {
                    Target::Internet
                };
                match self.world.state(net, target, t) {
                    (Mode::Refused, _, _) => {
                        (out.took, out.res) = (REFUSED_MS, Res::Fail(NOT_LISTENING));
                        None
                    }
                    (Mode::Offline, c, _) => {
                        (out.took, out.res) = (c.min(connect_wait), Res::Fail(NOT_LISTENING));
                        None
                    }
                    (Mode::Blackhole, _, _) => {
                        out.took = connect_wait;
                        None
                    }
                    (_, c, _) if c > connect_wait => {
                        out.took = connect_wait;
                        None
                    }
                    (mode, c, r) => Some((c, r, mode)),
                }
            }
            OutboxCarrier::P2p => {
                let mut elapsed = 0;
                let mut got = None;
                for r in self.circuits(now) {
                    let share = CIRCUIT_MS.min(connect_wait.saturating_sub(elapsed));
                    if share == 0 {
                        break;
                    }
                    out.dials += 1;
                    let failed = match self.world.state(net, Target::Circuit(r), t + elapsed) {
                        (Mode::Refused, _, _) => {
                            elapsed += REFUSED_MS;
                            CircuitOutcome::Refused
                        }
                        (Mode::Offline, _, _) => {
                            elapsed += share;
                            CircuitOutcome::NotOnRelay
                        }
                        (Mode::Blackhole, _, _) => {
                            elapsed += share;
                            CircuitOutcome::NoAnswer
                        }
                        (_, c, _) if c > share => {
                            elapsed += share;
                            CircuitOutcome::NoAnswer
                        }
                        (mode, c, rr) => {
                            got = Some((elapsed + c, rr, mode));
                            out.via = Some(r);
                            break;
                        }
                    };
                    out.circuits.push((r, failed, t + elapsed));
                }
                if got.is_none() {
                    out.took = elapsed;
                }
                got
            }
            OutboxCarrier::Nearby | OutboxCarrier::Onion => {
                unreachable!("nearby and onion are not planned here")
            }
        };
        if let Some((c, r, mode)) = connected {
            out.connect_ms = Some(c);
            out.frames_written = frames.len();
            if frames.is_empty() {
                (out.took, out.res) = (c, Res::Link);
            } else if mode == Mode::Stall || r > reply_wait {
                (out.took, out.res) = (c + reply_wait, Res::Silent);
            } else {
                (out.took, out.res, out.reply_ms) = (c + r, Res::Receipt, Some(r));
            }
        }
        out
    }

    /// What the dial `out` that ended at `t` teaches the model, through the
    /// real classifier.
    fn learn(&mut self, out: &DialOut, kind: FrameKind, karn: bool, t: u64) {
        let net_changed = self.world.net_at(t) != out.net;
        let Some(l) = self.learner.as_mut() else {
            return;
        };
        let none: &[Vec<u8>] = &[];
        let ev = match out.res {
            Res::Receipt => evidence(kind, Some(&self.ack), true, None, net_changed),
            Res::Silent => evidence(kind, Some(none), true, None, net_changed),
            Res::Link => evidence(kind, Some(none), false, None, net_changed),
            Res::Fail(code) => evidence(kind, None, false, Some(code), net_changed),
        };
        let want = match out.res {
            _ if net_changed => Evidence::None,
            Res::Receipt => Evidence::Receipt,
            Res::Silent => Evidence::Silent,
            Res::Link => Evidence::Link,
            Res::Fail(code) => Evidence::Fail {
                code,
                weight_milli: raven_core::learning::observe::weight_m(code).unwrap(),
            },
        };
        assert_eq!(ev, want, "{:?}", out.res);
        let path = match (out.connect_ms, out.via) {
            (None, _) => None,
            (Some(_), Some(_)) => Some(DeliveryPath::Relayed),
            (Some(_), None) => Some(DeliveryPath::Direct),
        };
        let now = EPOCH_MS + t;
        let o = Observation {
            contact: BOB,
            net: Some(out.net.to_owned()),
            net_changed,
            carrier: out.route.carrier,
            path,
            relay: out.via.map(|r| l.relays[r].clone()),
            kind,
            evidence: ev,
            timing: DialTiming {
                connect_ms: out.connect_ms.map(ms32),
                reply_ms: out.reply_ms.map(ms32),
                total_ms: ms32(out.took),
            },
            karn_exclude: karn,
            at_ms: now,
        };
        l.model.observe(&o, now);
        for (r, outcome, at) in &out.circuits {
            l.model
                .relay_circuit(&l.relays[*r], *outcome, EPOCH_MS + *at);
        }
    }

    fn attempt(&mut self, m: usize, t: u64) {
        if t - self.msgs[m].t0 >= HORIZON_MS {
            self.unsettled -= 1;
            return;
        }
        let net = self.world.net_at(t);
        let mut plan = self.plan(net, EPOCH_MS + t);
        let msg = &mut self.msgs[m];
        if let Some(i) = msg
            .silent_route
            .as_ref()
            .and_then(|s| plan.iter().position(|r| r == s))
        {
            plan.rotate_left(i + 1);
        }
        assert!(!plan.is_empty());
        (msg.plan, msg.next) = (plan, 0);
        self.dial_next(m, t);
    }

    fn dial_next(&mut self, m: usize, t: u64) {
        let route = self.msgs[m].plan[self.msgs[m].next].clone();
        self.msgs[m].next += 1;
        let net = self.world.net_at(t);
        let frames = self.message.clone();
        let out = self.dial(&route, net, t, &frames);
        if let Some(l) = self.learner.as_mut() {
            l.last_message_dial = Some(t);
        }
        let end = t + out.took;
        self.msgs[m].dials += out.dials;
        self.msgs[m].pending = Some(out);
        self.queue.push(end, Ev::DialEnd(m));
    }

    fn dial_end(&mut self, m: usize, t: u64) {
        let out = self.msgs[m].pending.take().expect("a dial in flight");
        let kind = FrameKind::of(&self.message);
        self.learn(&out, kind, self.msgs[m].went_silent, t);
        match out.res {
            Res::Receipt => {
                self.world.delivered(out.route.carrier, t);
                self.msgs[m].done = Some(t - self.msgs[m].t0);
                self.unsettled -= 1;
            }
            Res::Silent => {
                let msg = &mut self.msgs[m];
                (msg.silent_route, msg.went_silent) = (Some(out.route), true);
                self.retry(m, t);
            }
            Res::Fail(_) if self.msgs[m].next < self.msgs[m].plan.len() => self.dial_next(m, t),
            Res::Fail(_) => self.retry(m, t),
            Res::Link => unreachable!("a message dial writes frames"),
        }
    }

    fn retry(&mut self, m: usize, t: u64) {
        let msg = &mut self.msgs[m];
        let delay = millis(retry_delay(msg.failures, self.jitter.unit()));
        msg.failures += 1;
        self.queue.push(t + delay, Ev::Attempt(m));
    }

    /// The explorer's tick (design §5).
    fn tick(&mut self, t: u64) {
        if self.unsettled > 0 {
            self.queue.push(t + TICK_MS, Ev::Tick);
        }
        let net = self.world.net_at(t);
        let fixed = plan_object_routes(Some(&self.record), &self.contact, GATES);
        let l = self.learner.as_mut().expect("ticks are the learner's");
        let refill = (t - l.tokens_at) * PROBES_PER_HOUR * 1_000 / HOUR;
        l.tokens_milli = (l.tokens_milli + refill).min(PROBE_BURST * 1_000);
        l.tokens_at = t;
        if l.net.is_some_and(|n| n != net) {
            l.settle_until = t + SETTLE_MS;
        }
        l.net = Some(net);
        let active = l.last_message_dial.is_some_and(|d| t - d <= ACTIVE_MS);
        if l.probe_busy || t < l.settle_until || l.tokens_milli < 1_000 || !active {
            return;
        }
        let now = EPOCH_MS + t;
        let carriers = rank::carriers_of(&fixed.routes);
        let order = rank::order(&l.model, &BOB, Some(net), &carriers, None, now);
        let top = order.carriers.first().copied();
        let mut best: Option<(u64, OutboxCarrier)> = None;
        for (pos, c) in carriers.iter().enumerate() {
            if Some(*c) == top {
                continue;
            }
            let arm = l.model.arm(&ArmKey {
                contact: BOB,
                net: Some(net.to_owned()),
                carrier: *c,
            });
            let delivered_here = arm.is_some_and(|a| {
                a.last_receipt_ms > 0 && now.saturating_sub(a.last_receipt_ms) <= RECEIPT_WINDOW_MS
            });
            if *c != OutboxCarrier::P2p && !delivered_here {
                continue;
            }
            let demoted = order
                .carriers
                .iter()
                .position(|o| o == c)
                .is_some_and(|p| p > pos);
            let streak = arm.map_or(0, |a| a.beta.streak);
            let gap = if demoted && streak >= 1 {
                RECOVER_GAP_MS
            } else {
                PROBE_ARM_GAP_MS
            };
            let last_obs = arm.map_or(0, |a| a.last_obs_ms);
            let last_probe = arm.map_or(0, |a| a.last_probe_ms);
            if now.saturating_sub(last_obs) < gap.min(STALE_MS)
                || now.saturating_sub(last_probe) < gap
            {
                continue;
            }
            if best.is_none_or(|(o, _)| last_obs < o) {
                best = Some((last_obs, *c));
            }
        }
        let Some((_, carrier)) = best else {
            return;
        };
        l.tokens_milli -= 1_000;
        l.probe_busy = true;
        l.probe_times.push(t);
        let route = fixed
            .routes
            .iter()
            .find(|r| r.carrier == carrier)
            .expect("the arm is in the static plan")
            .clone();
        let out = self.dial(&route, net, t, &[]);
        self.queue.push(t + out.took, Ev::ProbeEnd);
        self.learner.as_mut().expect("learner").probe = Some(out);
    }

    fn probe_end(&mut self, t: u64) {
        let l = self.learner.as_mut().expect("probes are the learner's");
        let out = l.probe.take().expect("a probe in flight");
        l.probe_busy = false;
        if out.frames_written > 0 {
            l.probes_with_frames += 1;
        }
        self.learn(&out, FrameKind::of(&[]), false, t);
    }
}

/// The message times of one seed (the same for both planners).
fn arrivals(seed: u64) -> Vec<u64> {
    let mut rng = DeterministicRng::new(seed ^ 0x6172_7269_7665);
    let mut t = 0;
    (0..MESSAGES)
        .map(|_| {
            t += rng.exponential(MESSAGE_GAP_MS) as u64;
            t
        })
        .collect()
}

fn run_route(family: RouteFamily, seed: u64, learn: bool) -> RunStats {
    let mut runner = Runner::new(family.world(seed), learn, seed);
    if let (RouteFamily::LanRecovery, Some(l)) = (family, runner.learner.as_mut()) {
        lan_history(&mut l.model);
    }
    runner.run(&arrivals(seed))
}

// ── Statistics ───────────────────────────────────────────────────────────────

fn mean(xs: &[u64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    xs.iter().map(|x| *x as f64).sum::<f64>() / xs.len() as f64
}

/// The prototype's percentile: the value at rank ⌈q·n⌉.
fn pct(xs: &[u64], q: f64) -> u64 {
    let mut xs = xs.to_vec();
    xs.sort_unstable();
    let i = ((q * xs.len() as f64).ceil() as usize).clamp(1, xs.len()) - 1;
    xs[i]
}

/// One planner over every seed of a family.
#[derive(Debug)]
struct Pooled {
    rate: f64,
    mean_ms: f64,
    p95_ms: u64,
    last_quarter_ms: f64,
    dials_per_msg: f64,
    probes_per_hour: f64,
    /// The most probes in any hour (sliding).
    max_probes_hour: usize,
    probes_with_frames: u64,
    plans_checked: u64,
}

fn pooled(runs: &[RunStats]) -> Pooled {
    let all: Vec<u64> = runs.iter().flat_map(|r| r.times.iter().copied()).collect();
    let last: Vec<u64> = runs
        .iter()
        .flat_map(|r| r.times[r.times.len() - r.times.len() / 4..].iter().copied())
        .collect();
    let delivered: usize = runs.iter().map(|r| r.times.len()).sum();
    let probes: usize = runs.iter().map(|r| r.probe_times.len()).sum();
    let hours: f64 = runs.iter().map(|r| r.end_ms as f64 / HOUR as f64).sum();
    let max_probes_hour = runs
        .iter()
        .flat_map(|r| {
            r.probe_times.iter().enumerate().map(|(i, t)| {
                r.probe_times[i..]
                    .iter()
                    .take_while(|u| **u < t + HOUR)
                    .count()
            })
        })
        .max()
        .unwrap_or(0);
    Pooled {
        rate: runs
            .iter()
            .map(|r| r.times.len() as f64 / r.messages as f64)
            .sum::<f64>()
            / runs.len() as f64,
        mean_ms: mean(&all),
        p95_ms: pct(&all, 0.95),
        last_quarter_ms: mean(&last),
        dials_per_msg: runs.iter().map(|r| r.dials).sum::<u64>() as f64 / delivered.max(1) as f64,
        probes_per_hour: probes as f64 / hours,
        max_probes_hour,
        probes_with_frames: runs.iter().map(|r| r.probes_with_frames).sum(),
        plans_checked: runs.iter().map(|r| r.plans_checked).sum(),
    }
}

struct RouteResult {
    family: RouteFamily,
    fixed: Pooled,
    learned: Pooled,
    /// The largest per-seed `learned mean / static mean`, and by how much a
    /// seed's learned mean exceeds `1.10 × static + 100 ms` at most.
    worst_ratio: f64,
    worst_excess_ms: f64,
    max_seed_probes_per_hour: f64,
}

fn route_family(family: RouteFamily) -> RouteResult {
    let mut fixed = Vec::new();
    let mut learned = Vec::new();
    for seed in 1..=ROUTE_SEEDS {
        fixed.push(run_route(family, seed, false));
        learned.push(run_route(family, seed, true));
    }
    let mut worst_ratio = 0.0_f64;
    let mut worst_excess_ms = f64::NEG_INFINITY;
    for (s, l) in fixed.iter().zip(&learned) {
        worst_ratio = worst_ratio.max(l.mean() / s.mean());
        worst_excess_ms = worst_excess_ms.max(l.mean() - (1.10 * s.mean() + 100.0));
    }
    let max_seed_probes_per_hour = learned
        .iter()
        .map(|r| r.probe_times.len() as f64 / (r.end_ms as f64 / HOUR as f64))
        .fold(0.0, f64::max);
    RouteResult {
        family,
        fixed: pooled(&fixed),
        learned: pooled(&learned),
        worst_ratio,
        worst_excess_ms,
        max_seed_probes_per_hour,
    }
}

/// `value ≤ bound`, or a line saying it is not.
fn at_most(fails: &mut Vec<String>, what: String, value: f64, bound: f64) {
    if value.is_nan() || value > bound {
        fails.push(format!("{what}: {value:.3} > {bound:.3}"));
    }
}

/// `value ≥ bound`, or a line saying it is not.
fn at_least(fails: &mut Vec<String>, what: String, value: f64, bound: f64) {
    if value.is_nan() || value < bound {
        fails.push(format!("{what}: {value:.3} < {bound:.3}"));
    }
}

/// The plan's thresholds for one route family, and the bounds every family
/// shares.
fn route_thresholds(r: &RouteResult, fails: &mut Vec<String>) {
    let (s, l) = (&r.fixed, &r.learned);
    let name = r.family.name();
    let mut le = |what: &str, value: f64, bound: f64| {
        at_most(fails, format!("{name} {what}"), value, bound);
    };
    match r.family {
        RouteFamily::FlakyWifi => {
            le("mean", l.mean_ms, 0.60 * s.mean_ms);
            le("p95", l.p95_ms as f64, 0.50 * s.p95_ms as f64);
            le("rate (static minus learned)", s.rate - l.rate, 0.0);
            le("dials/msg", l.dials_per_msg, s.dials_per_msg);
        }
        RouteFamily::NetworkSwitch => {
            le("mean", l.mean_ms, 0.50 * s.mean_ms);
            le("p95", l.p95_ms as f64, 0.50 * s.p95_ms as f64);
        }
        RouteFamily::RelayDeath => {
            le("mean", l.mean_ms, 0.40 * s.mean_ms);
            le("dials/msg", l.dials_per_msg, 0.50 * s.dials_per_msg);
        }
        RouteFamily::AdaptiveAttacker => {
            le("mean", l.mean_ms, 0.85 * s.mean_ms);
            le("p95", l.p95_ms as f64, s.p95_ms as f64);
        }
        RouteFamily::LanRecovery => {
            le("mean", l.mean_ms, 0.80 * s.mean_ms);
            le(
                "last-quarter mean",
                l.last_quarter_ms,
                1.10 * s.last_quarter_ms + 50.0,
            );
        }
        // Reported, not asserted: with an empty model the LAN route never
        // delivered on this network, so OD6a-5 never lets the explorer
        // probe it and the order stays on the Internet after the LAN heals
        // (an owner item of P6.8).
        RouteFamily::LanRecoveryCold => le("mean", l.mean_ms, 0.80 * s.mean_ms),
        RouteFamily::StableControl => {
            le("mean", l.mean_ms, 1.05 * s.mean_ms + 50.0);
            le("p95", l.p95_ms as f64, 1.10 * s.p95_ms as f64 + 100.0);
            le("dials/msg", l.dials_per_msg, 1.02 * s.dials_per_msg);
        }
    }
    le(
        "worst seed mean over 1.10 x static + 100 ms",
        r.worst_excess_ms,
        0.0,
    );
    le(
        "probes/h (worst seed)",
        r.max_seed_probes_per_hour,
        PROBES_PER_HOUR as f64,
    );
    le(
        "probes in one hour",
        l.max_probes_hour as f64,
        (PROBES_PER_HOUR + PROBE_BURST) as f64,
    );
    le("probes with frames", l.probes_with_frames as f64, 0.0);
    if l.plans_checked == 0 {
        fails.push(format!("{name}: no learned plan was checked"));
    }
}

fn route_row(r: &RouteResult) -> String {
    let (s, l) = (&r.fixed, &r.learned);
    format!(
        "{:<18} {:>6.3} {:>8.0} {:>8} {:>5.2} | {:>6.3} {:>8.0} {:>8} {:>5.2} {:>5.2} | {:>5.2} {:>5.2} {:>5.2} | last quarter {:.0}/{:.0} ms, probes in 1 h <= {}",
        r.family.name(),
        s.rate,
        s.mean_ms,
        s.p95_ms,
        s.dials_per_msg,
        l.rate,
        l.mean_ms,
        l.p95_ms,
        l.dials_per_msg,
        l.probes_per_hour,
        l.mean_ms / s.mean_ms,
        l.p95_ms as f64 / s.p95_ms as f64,
        r.worst_ratio,
        s.last_quarter_ms,
        l.last_quarter_ms,
        l.max_probes_hour,
    )
}

// ── Total cutoff: the carry choice ───────────────────────────────────────────

const CARRIERS: usize = 4;
const CUTOFF_DAYS: u64 = 21;
const WARM_DAYS: u64 = 4;
const RATES_PER_DAY: [f64; 4] = [0.1, 0.3, 1.0, 3.0];
const AB_RATE_PER_DAY: f64 = 0.05;
const MESSAGES_PER_DAY: f64 = 3.0;

struct CutoffCarrier {
    /// A meets it, it meets B (per day).
    la: f64,
    lb: f64,
    /// B announced it (else only A listed it).
    announced: bool,
    a_meet: Vec<u64>,
    b_meet: Vec<u64>,
}

struct CutoffWorld {
    carriers: Vec<CutoffCarrier>,
    /// A meets B directly.
    ab: Vec<u64>,
    /// The book order of the carriers.
    book: Vec<usize>,
}

fn poisson(rng: &mut DeterministicRng, per_day: f64, end: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut t = 0.0;
    loop {
        t += rng.exponential(DAY as f64 / per_day);
        if t >= end as f64 {
            return out;
        }
        out.push(t as u64);
    }
}

fn cutoff_world(seed: u64) -> CutoffWorld {
    let mut rng = DeterministicRng::new(seed ^ 0x6375_746f_6666);
    let end = CUTOFF_DAYS * DAY;
    let carriers = (0..CARRIERS)
        .map(|_| {
            let la = RATES_PER_DAY[rng.index(RATES_PER_DAY.len())];
            let lb = RATES_PER_DAY[rng.index(RATES_PER_DAY.len())];
            let announced = rng.index(2) == 0;
            let a_meet = poisson(&mut rng, la, end);
            let b_meet = poisson(&mut rng, lb, end);
            CutoffCarrier {
                la,
                lb,
                announced,
                a_meet,
                b_meet,
            }
        })
        .collect();
    let ab = poisson(&mut rng, AB_RATE_PER_DAY, end);
    let mut book: Vec<usize> = (0..CARRIERS).collect();
    for i in (1..book.len()).rev() {
        book.swap(i, rng.index(i + 1));
    }
    CutoffWorld { carriers, ab, book }
}

fn carrier_key(i: usize) -> [u8; 32] {
    [0x40 + i as u8; 32]
}

/// `P(Exp(la) + Exp(lb) ≤ d)`, rates per day and `d` in days.
fn hypo(la: f64, lb: f64, d: f64) -> f64 {
    if (la - lb).abs() < 1e-12 {
        1.0 - (-la * d).exp() * (1.0 + la * d)
    } else {
        1.0 - (lb * (-la * d).exp() - la * (-lb * d).exp()) / (lb - la)
    }
}

/// The expected delivery probability within `deadline` of leaving copies
/// with `chosen` (plus the rare direct meeting).
fn expected(w: &CutoffWorld, chosen: &[usize], deadline: u64) -> f64 {
    let d = deadline as f64 / DAY as f64;
    let miss = chosen
        .iter()
        .map(|c| 1.0 - hypo(w.carriers[*c].la, w.carriers[*c].lb, d))
        .product::<f64>();
    1.0 - (-AB_RATE_PER_DAY * d).exp() * miss
}

fn next_after(times: &[u64], t: u64) -> Option<u64> {
    times.get(times.partition_point(|x| *x <= t)).copied()
}

/// When the object left at `t0` with `chosen` reaches B (by a holder or
/// directly), if within `deadline`.
fn realized(w: &CutoffWorld, chosen: &[usize], t0: u64, deadline: u64) -> Option<u64> {
    let by = t0 + deadline;
    let via = chosen.iter().filter_map(|c| {
        let c = &w.carriers[*c];
        let ta = next_after(&c.a_meet, t0).filter(|t| *t <= by)?;
        next_after(&c.b_meet, ta).filter(|t| *t <= by)
    });
    via.chain(next_after(&w.ab, t0).filter(|t| *t <= by)).min()
}

#[derive(Clone, Copy, Debug)]
enum CutoffEv {
    MeetCarrier(usize),
    MeetB,
    Message,
    Outcome {
        holders: [Option<usize>; CARRY_CAP],
        delivered: bool,
    },
}

/// One seed: (static, learned) mean expected delivery, and the most copies
/// one message got.
fn run_cutoff(seed: u64, deadline: u64) -> (f64, f64, usize) {
    const B: [u8; 32] = [0xB0; 32];
    let w = cutoff_world(seed);
    let end = CUTOFF_DAYS * DAY;
    let mut rng = DeterministicRng::new(seed ^ 0x6d73_6773);
    let msgs: Vec<u64> = poisson(&mut rng, MESSAGES_PER_DAY, end - deadline)
        .into_iter()
        .filter(|t| *t >= WARM_DAYS * DAY)
        .collect();
    // Today's choice (custody_client `deposit_custodians`): the announced
    // custodians in book order, then the listed ones, at most CARRY_CAP.
    let cands: Vec<usize> = (w.book.iter().filter(|c| w.carriers[**c].announced))
        .chain(w.book.iter().filter(|c| !w.carriers[**c].announced))
        .copied()
        .collect();
    let candidates: Vec<Candidate> = cands
        .iter()
        .map(|c| Candidate {
            key: carrier_key(*c),
            announced: w.carriers[*c].announced,
        })
        .collect();
    let fixed: Vec<usize> = cands.iter().copied().take(CARRY_CAP).collect();
    let mut copies = fixed.len();
    let fixed_mean = expected(&w, &fixed, deadline);

    let mut model = Model::new_empty(MODEL_SECRET);
    let mut queue: EventQueue<CutoffEv> = EventQueue::default();
    for (i, c) in w.carriers.iter().enumerate() {
        for t in &c.a_meet {
            queue.push(*t, CutoffEv::MeetCarrier(i));
        }
    }
    for t in &w.ab {
        queue.push(*t, CutoffEv::MeetB);
    }
    for t in &msgs {
        queue.push(*t, CutoffEv::Message);
    }
    let mut learned = Vec::with_capacity(msgs.len());
    while let Some(ev) = queue.pop() {
        let (t, now) = (ev.at, EPOCH_MS + ev.at);
        match ev.kind {
            CutoffEv::MeetCarrier(c) => {
                model.encounter(&carrier_key(c), now);
            }
            CutoffEv::MeetB => {
                model.encounter(&B, now);
            }
            CutoffEv::Message => {
                let (pick, _why) = model.carry_pick(&B, &candidates, CARRY_CAP, now);
                assert!(pick.len() <= CARRY_CAP);
                let chosen: Vec<usize> = pick
                    .iter()
                    .map(|k| {
                        (0..CARRIERS)
                            .find(|c| carrier_key(*c) == *k)
                            .expect("a pick is one of the candidates")
                    })
                    .collect();
                copies = copies.max(chosen.len());
                learned.push(expected(&w, &chosen, deadline));
                let got = realized(&w, &chosen, t, deadline);
                let mut holders = [None; CARRY_CAP];
                for (slot, c) in holders.iter_mut().zip(&chosen) {
                    *slot = Some(*c);
                }
                // The receipt is known when it arrives, an expiry at the
                // deadline.
                queue.push(
                    got.unwrap_or(t + deadline),
                    CutoffEv::Outcome {
                        holders,
                        delivered: got.is_some(),
                    },
                );
            }
            CutoffEv::Outcome { holders, delivered } => {
                let keys: Vec<[u8; 32]> =
                    holders.iter().flatten().map(|c| carrier_key(*c)).collect();
                model.carry_outcome(&B, &keys, delivered, now);
            }
        }
    }
    let learned_mean = learned.iter().sum::<f64>() / learned.len().max(1) as f64;
    (fixed_mean, learned_mean, copies)
}

struct CutoffResult {
    name: &'static str,
    fixed: f64,
    learned: f64,
    worst: f64,
    p05: f64,
    copies: usize,
}

fn cutoff_family(name: &'static str, deadline: u64) -> CutoffResult {
    let runs: Vec<(f64, f64, usize)> = (1..=CUTOFF_SEEDS)
        .map(|seed| run_cutoff(seed, deadline))
        .collect();
    let n = runs.len() as f64;
    let mut diffs: Vec<f64> = runs.iter().map(|(s, l, _)| l - s).collect();
    diffs.sort_by(f64::total_cmp);
    CutoffResult {
        name,
        fixed: runs.iter().map(|r| r.0).sum::<f64>() / n,
        learned: runs.iter().map(|r| r.1).sum::<f64>() / n,
        worst: diffs[0],
        p05: diffs[diffs.len() / 20],
        copies: runs.iter().map(|r| r.2).max().unwrap_or(0),
    }
}

fn cutoff_thresholds(r: &CutoffResult, gain: f64, worst: f64, fails: &mut Vec<String>) {
    let name = r.name;
    at_least(fails, format!("{name} gain"), r.learned - r.fixed, gain);
    at_least(fails, format!("{name} per-seed p05"), r.p05, -0.05);
    at_least(fails, format!("{name} worst seed"), r.worst, worst);
    at_most(
        fails,
        format!("{name} copies per message"),
        r.copies as f64,
        CARRY_CAP as f64,
    );
}

// ── The gate ─────────────────────────────────────────────────────────────────

/// Every family, its table, and the plan's thresholds (P6.8).
#[test]
fn learning_beats_static_on_every_family() {
    let (routes, cutoffs) = std::thread::scope(|scope| {
        let routes: Vec<_> = RouteFamily::ALL
            .into_iter()
            .map(|f| scope.spawn(move || route_family(f)))
            .collect();
        let day = scope.spawn(|| cutoff_family("cutoff_meetings_24h", DAY));
        let week = scope.spawn(|| cutoff_family("cutoff_meetings_7d", 7 * DAY));
        (
            routes
                .into_iter()
                .map(|h| h.join().expect("route family"))
                .collect::<Vec<_>>(),
            [
                day.join().expect("cutoff 24h"),
                week.join().expect("cutoff 7d"),
            ],
        )
    });
    println!(
        "learning_sim: {ROUTE_SEEDS} seeds per route family, {CUTOFF_SEEDS} per cutoff family"
    );
    println!(
        "{:<18} {:>6} {:>8} {:>8} {:>5} | {:>6} {:>8} {:>8} {:>5} {:>5} | {:>5} {:>5} {:>5}",
        "family",
        "rate",
        "mean_ms",
        "p95_ms",
        "d/msg",
        "rate",
        "mean_ms",
        "p95_ms",
        "d/msg",
        "pr/h",
        "mean",
        "p95",
        "worst"
    );
    println!(
        "{:<18} {:-^37} | {:-^43} | {:-^17}",
        "", " static ", " learned ", " learn/static "
    );
    let mut fails = Vec::new();
    for r in &routes {
        println!("{}", route_row(r));
        route_thresholds(r, &mut fails);
    }
    for (r, gain, worst) in [(&cutoffs[0], 0.05, -0.15), (&cutoffs[1], 0.02, -0.20)] {
        println!(
            "{:<20} expected delivery static {:.3} learned {:.3} (gain {:+.3}) per-seed worst {:+.3} p05 {:+.3} copies<={}",
            r.name,
            r.fixed,
            r.learned,
            r.learned - r.fixed,
            r.worst,
            r.p05,
            r.copies
        );
        cutoff_thresholds(r, gain, worst, &mut fails);
    }
    assert!(fails.is_empty(), "thresholds failed:\n{}", fails.join("\n"));
}

/// The same seed gives the same run, in both planners.
#[test]
fn a_run_is_deterministic() {
    for learn in [false, true] {
        let a = run_route(RouteFamily::FlakyWifi, 7, learn);
        let b = run_route(RouteFamily::FlakyWifi, 7, learn);
        assert_eq!(a, b);
        assert_eq!(a.messages, MESSAGES);
    }
    assert_eq!(run_cutoff(7, DAY), run_cutoff(7, DAY));
}

/// The worker model's dial outcomes, mode by mode, with today's waits.
#[test]
fn the_dial_model_follows_the_static_waits() {
    struct Fixed(State);
    impl World for Fixed {
        fn state(&mut self, _net: &str, _target: Target, _t: u64) -> State {
            self.0
        }
    }
    let lan = contact().routes[0].clone();
    let p2p = contact().routes[2].clone();
    let fixed = wait::statics(OutboxCarrier::Lan);
    let (connect, reply) = (millis(fixed.connect), millis(fixed.reply_first));
    let message = vec![frame(EnvType::Message)];
    for (state, frames, res, took) in [
        ((Mode::Ok, 30, 100), true, Res::Receipt, 130),
        ((Mode::Ok, 30, 100), false, Res::Link, 30),
        (
            (Mode::Ok, connect + 1, 100),
            true,
            Res::Fail(NOT_REACHABLE),
            connect,
        ),
        ((Mode::Ok, 30, reply + 1), true, Res::Silent, 30 + reply),
        ((Mode::Stall, 30, 100), true, Res::Silent, 30 + reply),
        ((Mode::Stall, 30, 100), false, Res::Link, 30),
        (
            (Mode::Blackhole, 0, 0),
            true,
            Res::Fail(NOT_REACHABLE),
            connect,
        ),
        (
            (Mode::Refused, 0, 0),
            true,
            Res::Fail(NOT_LISTENING),
            REFUSED_MS,
        ),
        ((Mode::Offline, 700, 0), true, Res::Fail(NOT_LISTENING), 700),
    ] {
        let mut r = Runner::new(Box::new(Fixed(state)), false, 1);
        let frames: &[Vec<u8>] = if frames { &message } else { &[] };
        let out = r.dial(&lan, "n0", 0, frames);
        assert_eq!((out.res, out.took, out.dials), (res, took, 1), "{state:?}");
        // Frames go out only on a link, and a probe writes none.
        let linked = out.connect_ms.is_some();
        assert_eq!(out.frames_written, if linked { frames.len() } else { 0 });
    }
    // p2p: each dead circuit takes its 10 s share of the 20 s deadline.
    let mut r = Runner::new(Box::new(Fixed((Mode::Blackhole, 0, 0))), false, 1);
    let out = r.dial(&p2p, "n0", 0, &message);
    assert_eq!(
        (out.res, out.took, out.dials),
        (Res::Fail(NOT_REACHABLE), 2 * CIRCUIT_MS, 2)
    );
    assert_eq!(
        out.circuits,
        vec![
            (0, CircuitOutcome::NoAnswer, CIRCUIT_MS),
            (1, CircuitOutcome::NoAnswer, 2 * CIRCUIT_MS)
        ]
    );
    let mut r = Runner::new(Box::new(Fixed((Mode::Ok, 1_000, 900))), false, 1);
    let out = r.dial(&p2p, "n0", 0, &message);
    assert_eq!((out.res, out.took, out.via), (Res::Receipt, 1_900, Some(0)));
}
