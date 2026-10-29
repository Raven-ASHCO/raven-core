//! The reason grammar of a learned carrier order (design "Phase 6a", reason
//! grammar): a local, ASCII line of fixed words and small numbers that
//! raven-node hands to ash over IPC and ash words for the user.
//!
//! ```text
//! learn: state=<s> order=<c>,<c>[,<c>] why=<w>[ fail=<c>:<k>/<n>][ ok=<c>:<k>/<n>][ wait=<c>:<n>s][ age=<n><s|m|h|d>]
//! ```
//!
//! - `s` ∈ {on, shadow, off, memory_only, reset_after_unreadable}
//!   ([`State`]);
//! - `c` ∈ {lan, internet, p2p} (nearby keeps its static place and is never
//!   ranked);
//! - `w` ∈ {cold, kept, faster, failing, recovering, contradiction,
//!   unreadable, off, held, shadow} ([`Why`]);
//! - `fail` / `ok`: `k` failed or successful tries of the last `n` on that
//!   carrier (at most 8, [`super::model::RECENT_MAX`]);
//! - `wait`: the adaptive wait of that carrier in whole seconds;
//! - `age`: since the newest observation behind the order, rounded down
//!   (the same units as Phase 2's `reach:` block).
//!
//! [`Order::render`] writes at most [`MAX_RENDERED`] bytes: the three fixed
//! fields always fit, an optional one that would not fit is left out.
//! [`Reason::find`] reads it back with the rules of Phase 2's
//! `reach_diag::Diag::find`: the last block in the text, up to ';', ')', a
//! line end or [`MAX_RENDERED`] bytes; unknown keys and values skipped; an
//! unknown or missing `why` is `None`, so a newer daemon's reason gives
//! today's text. It never holds an address, key, PeerId, network tag or
//! name, and it is not an error code (`RAVEN_ERROR_CODES_V1` is untouched).

use super::rank::Order;
use crate::outbox::OutboxCarrier;
use crate::reach_diag::{parse_age, write_age};

/// What starts a reason block.
pub const LEARN_TAG: &str = "learn: ";
/// A reason block is at most this long, and [`Reason::find`] reads no
/// further.
pub const MAX_RENDERED: usize = 120;

/// Why the order is what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Why {
    /// Too little evidence yet: the static order.
    Cold,
    /// Enough evidence, and the static order is still the best.
    Kept,
    /// A carrier moved ahead of the static one because it answers sooner
    /// (or more often, while the static one failed none of its last tries).
    Faster,
    /// A carrier moved ahead of the static one because that one failed some
    /// of its last tries (`fail=` says how many, never 0).
    Failing,
    /// A demoted carrier moved back toward its static place.
    Recovering,
    /// A learned order failed the plan's invariant: static, pinned a while.
    Contradiction,
    /// The learning file could not be read and was started over.
    Unreadable,
    /// The user turned learning off.
    Off,
    /// The gate is shut (`LEARNING_HOLD`).
    Held,
    /// Learning watches without changing the order.
    Shadow,
}

impl Why {
    pub const ALL: [Self; 10] = [
        Self::Cold,
        Self::Kept,
        Self::Faster,
        Self::Failing,
        Self::Recovering,
        Self::Contradiction,
        Self::Unreadable,
        Self::Off,
        Self::Held,
        Self::Shadow,
    ];

    pub fn token(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::Kept => "kept",
            Self::Faster => "faster",
            Self::Failing => "failing",
            Self::Recovering => "recovering",
            Self::Contradiction => "contradiction",
            Self::Unreadable => "unreadable",
            Self::Off => "off",
            Self::Held => "held",
            Self::Shadow => "shadow",
        }
    }

    /// The exact token only.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|w| w.token() == s)
    }
}

/// The learning store's state as the reason and `raven learning status`
/// name it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum State {
    #[default]
    On,
    Shadow,
    Off,
    /// The keystore is unavailable or the file is newer: nothing is written.
    MemoryOnly,
    /// The file could not be read: started over, overwritten on the next
    /// save.
    ResetAfterUnreadable,
}

impl State {
    pub const ALL: [Self; 5] = [
        Self::On,
        Self::Shadow,
        Self::Off,
        Self::MemoryOnly,
        Self::ResetAfterUnreadable,
    ];

    pub fn token(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Shadow => "shadow",
            Self::Off => "off",
            Self::MemoryOnly => "memory_only",
            Self::ResetAfterUnreadable => "reset_after_unreadable",
        }
    }

    /// The exact token only.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|w| w.token() == s)
    }
}

/// `lan` | `internet` | `p2p`; nearby and onion are never ranked, so they
/// have none.
pub fn carrier_token(carrier: OutboxCarrier) -> Option<&'static str> {
    match carrier {
        OutboxCarrier::Lan => Some("lan"),
        OutboxCarrier::Internet => Some("internet"),
        OutboxCarrier::P2p => Some("p2p"),
        OutboxCarrier::Nearby | OutboxCarrier::Onion => None,
    }
}

/// The exact carrier token only.
pub fn parse_carrier(s: &str) -> Option<OutboxCarrier> {
    [
        OutboxCarrier::Lan,
        OutboxCarrier::Internet,
        OutboxCarrier::P2p,
    ]
    .into_iter()
    .find(|c| carrier_token(*c) == Some(s))
}

/// `k` of the last `n` tries on `carrier` (failed ones for `fail=`,
/// successful ones for `ok=`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tally {
    pub carrier: OutboxCarrier,
    pub k: u8,
    pub n: u8,
}

/// The adaptive wait of `carrier`, in whole seconds (P6.6 / P6.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitNote {
    pub carrier: OutboxCarrier,
    pub secs: u32,
}

/// The facts an [`Order`]'s reason prints besides the order and `why`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Detail {
    pub state: State,
    /// The carrier that lost its static place, and how it fared.
    pub fail: Option<Tally>,
    /// The carrier that took a place, and how it fared.
    pub ok: Option<Tally>,
    pub wait: Option<WaitNote>,
    /// Seconds since the newest observation behind the order.
    pub age_s: Option<u64>,
}

/// A reason block read back ([`Reason::find`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    /// `None`: missing or a state this build does not know.
    pub state: Option<State>,
    /// The carriers in order; unknown tokens skipped.
    pub order: Vec<OutboxCarrier>,
    pub why: Why,
    pub fail: Option<Tally>,
    pub ok: Option<Tally>,
    pub wait: Option<WaitNote>,
    /// Seconds, rounded down to the unit the block was written in.
    pub age_s: Option<u64>,
}

/// `<c>:<k>/<n>`, or nothing for a carrier with no token.
fn tally_text(t: &Tally) -> Option<String> {
    carrier_token(t.carrier).map(|c| format!("{c}:{}/{}", t.k, t.n))
}

/// `<c>:<k>/<n>` with `k ≤ n`.
fn parse_tally(v: &str) -> Option<Tally> {
    let (c, counts) = v.split_once(':')?;
    let (k, n) = counts.split_once('/')?;
    let (k, n) = (small_number(k)?, small_number(n)?);
    let k = u8::try_from(k).ok()?;
    let n = u8::try_from(n).ok()?;
    (k <= n).then_some(Tally {
        carrier: parse_carrier(c)?,
        k,
        n,
    })
}

/// `<c>:<n>s`.
fn parse_wait(v: &str) -> Option<WaitNote> {
    let (c, secs) = v.split_once(':')?;
    let secs = small_number(secs.strip_suffix('s')?)?;
    Some(WaitNote {
        carrier: parse_carrier(c)?,
        secs,
    })
}

/// 1 to 10 ASCII digits that fit a `u32`.
fn small_number(v: &str) -> Option<u32> {
    if v.is_empty() || v.len() > 10 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

impl Order {
    /// The reason block (module doc): fixed words and small numbers only,
    /// at most [`MAX_RENDERED`] bytes. A carrier without a token (nearby,
    /// which an order never holds) is left out.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(MAX_RENDERED);
        out.push_str(LEARN_TAG);
        out.push_str("state=");
        out.push_str(self.detail.state.token());
        out.push_str(" order=");
        let tokens: Vec<&str> = self
            .carriers
            .iter()
            .filter_map(|c| carrier_token(*c))
            .collect();
        out.push_str(&tokens.join(","));
        out.push_str(" why=");
        out.push_str(self.why.token());
        let mut optional = Vec::with_capacity(4);
        if let Some(t) = self.detail.fail.as_ref().and_then(tally_text) {
            optional.push(format!(" fail={t}"));
        }
        if let Some(t) = self.detail.ok.as_ref().and_then(tally_text) {
            optional.push(format!(" ok={t}"));
        }
        if let Some(w) = self.detail.wait {
            if let Some(c) = carrier_token(w.carrier) {
                optional.push(format!(" wait={c}:{}s", w.secs));
            }
        }
        if let Some(secs) = self.detail.age_s {
            let mut age = String::from(" age=");
            write_age(&mut age, secs);
            optional.push(age);
        }
        for field in optional {
            if out.len() + field.len() <= MAX_RENDERED {
                out.push_str(&field);
            }
        }
        out
    }
}

impl Reason {
    /// The LAST block in `raw` (module doc). `None` when there is none or
    /// its `why` is missing or unknown.
    pub fn find(raw: &str) -> Option<Self> {
        let start = raw.rfind(LEARN_TAG)?;
        let tail = &raw[start..];
        let mut end = tail.len().min(MAX_RENDERED);
        while !tail.is_char_boundary(end) {
            end -= 1;
        }
        let block = tail[..end]
            .split([';', ')', '\n', '\r'])
            .next()
            .unwrap_or_default();
        let mut why = None;
        let mut r = Reason {
            state: None,
            order: Vec::new(),
            why: Why::Cold,
            fail: None,
            ok: None,
            wait: None,
            age_s: None,
        };
        for (key, value) in block
            .get(LEARN_TAG.len()..)?
            .split(' ')
            .filter_map(|w| w.split_once('='))
        {
            match key {
                "state" => r.state = State::parse(value).or(r.state),
                "order" => {
                    r.order.clear();
                    for c in value.split(',').filter_map(parse_carrier) {
                        if !r.order.contains(&c) {
                            r.order.push(c);
                        }
                    }
                }
                "why" => why = Some(Why::parse(value)?),
                "fail" => r.fail = parse_tally(value).or(r.fail),
                "ok" => r.ok = parse_tally(value).or(r.ok),
                "wait" => r.wait = parse_wait(value).or(r.wait),
                "age" => r.age_s = parse_age(value).or(r.age_s),
                _ => {}
            }
        }
        r.why = why?;
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::model::{Model, RECENT_MAX};
    use crate::learning::observe::{DialTiming, Evidence, FrameKind, Observation};
    use crate::learning::rank;
    use crate::outbox::OutboxRoute;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const CARRIERS: [OutboxCarrier; 4] = [
        OutboxCarrier::Lan,
        OutboxCarrier::Internet,
        OutboxCarrier::P2p,
        OutboxCarrier::Nearby,
    ];

    fn random_tally(rng: &mut StdRng) -> Option<Tally> {
        rng.gen_bool(0.6).then(|| {
            let n = rng.gen_range(0..=RECENT_MAX);
            Tally {
                carrier: CARRIERS[rng.gen_range(0..3)],
                k: rng.gen_range(0..=n),
                n,
            }
        })
    }

    /// An optional field read back: exactly what was rendered, or left out
    /// (it did not fit). `true`: read back exactly.
    fn read_back<T: PartialEq + std::fmt::Debug>(
        got: Option<T>,
        want: Option<T>,
        text: &str,
    ) -> bool {
        assert!(got.is_none() || got == want, "{got:?} {want:?} {text}");
        got == want
    }

    /// An age as the block can carry it (rounded down to its unit).
    fn rounded(secs: u64) -> u64 {
        let mut s = String::new();
        write_age(&mut s, secs);
        parse_age(&s).unwrap()
    }

    #[test]
    fn tokens_round_trip_and_reject_junk() {
        for w in Why::ALL {
            assert_eq!(Why::parse(w.token()), Some(w));
        }
        for s in State::ALL {
            assert_eq!(State::parse(s.token()), Some(s));
        }
        for c in &CARRIERS[..3] {
            assert_eq!(parse_carrier(carrier_token(*c).unwrap()), Some(*c));
        }
        assert_eq!(carrier_token(OutboxCarrier::Nearby), None);
        for junk in ["", "Cold", "nearby", "lan_dial", " lan", "on "] {
            assert_eq!(Why::parse(junk), None);
            assert_eq!(State::parse(junk), None);
            assert_eq!(parse_carrier(junk), None);
        }
        assert_eq!(
            Order::fixed(
                &[OutboxCarrier::Lan, OutboxCarrier::Internet],
                Why::Cold,
                State::On
            )
            .render(),
            "learn: state=on order=lan,internet why=cold"
        );
    }

    /// Every order renders within the bound, its fixed fields always read
    /// back, and an optional field reads back exactly (age rounded) or is
    /// left out only when it did not fit.
    #[test]
    fn render_find_round_trip_and_bounds() {
        let mut rng = StdRng::seed_from_u64(0x6a_5e);
        let mut full = 0;
        for _ in 0..10_000 {
            let mut carriers = CARRIERS[..3].to_vec();
            for i in (1..carriers.len()).rev() {
                carriers.swap(i, rng.gen_range(0..=i));
            }
            carriers.truncate(rng.gen_range(0..=3));
            let order = Order {
                carriers: carriers.clone(),
                why: Why::ALL[rng.gen_range(0..Why::ALL.len())],
                detail: Detail {
                    state: State::ALL[rng.gen_range(0..State::ALL.len())],
                    fail: random_tally(&mut rng),
                    ok: random_tally(&mut rng),
                    wait: rng.gen_bool(0.5).then(|| WaitNote {
                        carrier: CARRIERS[rng.gen_range(0..3)],
                        secs: rng.gen_range(0..=u32::MAX),
                    }),
                    age_s: rng
                        .gen_bool(0.7)
                        .then(|| rng.gen_range(0..=u64::MAX / 1_000)),
                },
            };
            let text = order.render();
            assert!(text.len() <= MAX_RENDERED, "{text}");
            assert!(text.is_ascii());
            let back = Reason::find(&text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(back.state, Some(order.detail.state));
            assert_eq!(back.order, carriers);
            assert_eq!(back.why, order.why);
            let all = [
                read_back(back.fail, order.detail.fail, &text),
                read_back(back.ok, order.detail.ok, &text),
                read_back(back.wait, order.detail.wait, &text),
                read_back(back.age_s, order.detail.age_s.map(rounded), &text),
            ];
            full += usize::from(all.iter().all(|same| *same));
            // The same block inside a longer text, after another one.
            let joined = format!("lan: refused; learn: state=on order=p2p why=kept; {text})x");
            assert_eq!(Reason::find(&joined), Some(back));
        }
        // Most random orders fit whole.
        assert!(full > 5_000, "{full}");
        // A real order with every field fits whole.
        let order = Order {
            carriers: vec![
                OutboxCarrier::Internet,
                OutboxCarrier::P2p,
                OutboxCarrier::Lan,
            ],
            why: Why::Failing,
            detail: Detail {
                state: State::On,
                fail: Some(Tally {
                    carrier: OutboxCarrier::Lan,
                    k: 3,
                    n: 4,
                }),
                ok: Some(Tally {
                    carrier: OutboxCarrier::Internet,
                    k: 2,
                    n: 2,
                }),
                wait: Some(WaitNote {
                    carrier: OutboxCarrier::Internet,
                    secs: 4,
                }),
                age_s: Some(7_300),
            },
        };
        assert_eq!(
            order.render(),
            "learn: state=on order=internet,p2p,lan why=failing fail=lan:3/4 ok=internet:2/2 \
             wait=internet:4s age=2h"
        );
    }

    /// Tolerant reading: unknown keys and bad values are skipped; a missing
    /// or unknown `why` gives `None`.
    #[test]
    fn find_is_tolerant() {
        let r = Reason::find(
            "x learn: state=later order=lan,ble,lan,p2p why=kept new=1 fail=lan:5/4 ok=p2p:1/1 \
             wait=lan:9 age=3x",
        )
        .unwrap();
        assert_eq!(r.state, None);
        assert_eq!(r.order, vec![OutboxCarrier::Lan, OutboxCarrier::P2p]);
        assert_eq!(r.why, Why::Kept);
        assert_eq!(r.fail, None);
        assert_eq!(
            r.ok,
            Some(Tally {
                carrier: OutboxCarrier::P2p,
                k: 1,
                n: 1
            })
        );
        assert_eq!((r.wait, r.age_s), (None, None));
        assert_eq!(Reason::find("learn: state=on order=lan"), None);
        assert_eq!(Reason::find("learn: state=on order=lan why=later"), None);
        assert_eq!(Reason::find("reach: why=no_relay"), None);
        // Past the bound: not read.
        let far = format!(
            "learn: state=on order=lan{} why=kept",
            " ".repeat(MAX_RENDERED)
        );
        assert_eq!(Reason::find(&far), None);
    }

    /// Whatever the routes, tags and outcomes, a reason holds no address:
    /// no '.', no brackets or slashes, nothing but carrier tokens in
    /// `order=`, and every ':' after the tag sits between a carrier token
    /// and a number.
    #[test]
    fn reason_never_contains_digits_of_an_address() {
        let mut rng = StdRng::seed_from_u64(0xadd2);
        for round in 0..3_000u64 {
            let mut model = Model::new_empty(rng.gen());
            let peer: [u8; 32] = rng.gen();
            let net = format!("192.168.{}.{}", rng.gen_range(0..255), round % 255);
            let routes: Vec<OutboxRoute> = (0..rng.gen_range(1..8))
                .map(|_| {
                    let carrier = CARRIERS[rng.gen_range(0..4)];
                    let dial = match carrier {
                        OutboxCarrier::Lan => format!("10.0.{}.{}:7420", rng.gen::<u8>(), round),
                        OutboxCarrier::Internet => format!("[2001:db8::{round:x}]:7422"),
                        OutboxCarrier::P2p => format!("/p2p/12D3KooW{round}"),
                        OutboxCarrier::Nearby => format!("nearby:{}", hex::encode(peer)),
                        OutboxCarrier::Onion => crate::onion::dial_for(&peer),
                    };
                    OutboxRoute { carrier, dial }
                })
                .collect();
            let mut now = 1_800_000_000_000 + round;
            for _ in 0..rng.gen_range(0..12) {
                let evidence = match rng.gen_range(0..4) {
                    0 => Evidence::Receipt,
                    1 => Evidence::Link,
                    2 => Evidence::Silent,
                    _ => Evidence::Fail {
                        code: "NOT_REACHABLE",
                        weight_milli: 1_000,
                    },
                };
                model.observe(
                    &Observation {
                        contact: peer,
                        net: Some(net.clone()),
                        net_changed: false,
                        carrier: CARRIERS[rng.gen_range(0..4)],
                        path: None,
                        relay: None,
                        kind: FrameKind::Message,
                        evidence,
                        timing: DialTiming {
                            connect_ms: Some(rng.gen_range(1..9_000)),
                            reply_ms: Some(rng.gen_range(1..30_000)),
                            total_ms: rng.gen_range(1..40_000),
                        },
                        karn_exclude: false,
                        at_ms: now,
                    },
                    now,
                );
                now += rng.gen_range(0..7_200_000);
            }
            let order = rank::order(
                &model,
                &peer,
                Some(&net),
                &rank::carriers_of(&routes),
                None,
                now,
            );
            let text = order.render();
            assert!(text.starts_with(LEARN_TAG), "{text}");
            assert!(!text.contains(['.', '[', ']']), "{text}");
            assert!(!text.contains(&net) && !text.contains(&hex::encode(peer)));
            for r in &routes {
                assert!(!text.contains(&r.dial), "{text}");
            }
            let body = &text[LEARN_TAG.len()..];
            for word in body.split(' ') {
                let (key, value) = word.split_once('=').unwrap();
                if key == "order" {
                    assert!(value
                        .split(',')
                        .all(|c| parse_carrier(c).is_some() || c.is_empty()));
                }
                if let Some((c, rest)) = value.split_once(':') {
                    assert!(parse_carrier(c).is_some(), "{text}");
                    assert!(
                        rest.bytes()
                            .all(|b| b.is_ascii_digit() || b == b'/' || b == b's'),
                        "{text}"
                    );
                }
            }
            assert!(Reason::find(&text).is_some());
        }
    }
}
