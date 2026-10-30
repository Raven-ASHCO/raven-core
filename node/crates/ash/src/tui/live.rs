//! The live feel (UXF.10): what moves on Home, each motion started by
//! something Raven really did, and the words the footer's ticker gives it.
//!
//! - The heartbeat: a Status poll the background program answered. The
//!   heart is bright from that poll to the next whole second on the clock,
//!   and 'node ok · 3 s ago' counts from it.
//! - The route line: your message travels out while its send runs, the
//!   signed receipt travels back once it came, a friend's message travels
//!   in before it shows. How the last delivery went is what the send
//!   answered (its carrier and address) or what raven-node's outbox
//!   recorded (its carrier and p2p path); nothing else is guessed.
//! - The retry ring: raven-node's outbox lists more attempts for a waiting
//!   message than before.
//! - A friend's row blinks when a message from them arrived or one of yours
//!   was delivered.
//! - The activity line: your messages and theirs per two minutes over the
//!   last 48 minutes, counted from the chat history on this computer. It is
//!   never sent anywhere.
//!
//! Honest motion: no motion starts without one of these (the Welcome mark's
//! reveal is the one exception), nothing types, nothing says anyone is
//! online, and nothing says delivered before the receipt. Under reduced
//! motion only text changes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::app::Touch;
use super::bridge;
use super::theme::{Glyphs, Motion, PathKind};

/// How long a message takes along the route line, either way.
pub(super) const ROUTE_TIME: Duration = Duration::from_millis(800);
/// The steps of one trip: the scheduler wakes for each (within the frame
/// budget).
pub(super) const ROUTE_STEPS: u32 = 16;
/// A friend's row blinks: on, off, on.
pub(super) const NEWS_FRAMES: u32 = 3;
pub(super) const NEWS_TIME: Duration = Duration::from_millis(600);
/// The retry ring: its four frames (◌ ◎ ◉ ◎), then the waiting mark again.
pub(super) const RING_FRAMES: u32 = 4;
pub(super) const RING_TIME: Duration = Duration::from_millis(900);
/// How long the ticker names an event before it says how things stand.
pub(super) const TICKER_FOR: Duration = Duration::from_secs(30);
/// The heart stays bright at least this long after a poll, to the next
/// whole second.
const PULSE_MIN_MS: u64 = 200;
/// The activity line: 24 buckets of two minutes, the newest the current
/// two minutes on the clock.
pub(super) const BUCKETS: usize = 24;
pub(super) const BUCKET_MS: u64 = 2 * 60_000;

/// A carrier a message of yours went over (the outbox's `lan_dial`,
/// `internet_dial`, `p2p_dial`, `nearby_dial`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Carrier {
    Lan,
    Internet,
    P2p,
    /// Bluetooth nearby (Phase 5).
    Nearby,
    /// The Tor onion carrier (lab).
    Onion,
}

impl Carrier {
    /// The outbox's word for a carrier; None for one this app doesn't know.
    pub(super) fn of_label(label: &str) -> Option<Carrier> {
        match label {
            "lan_dial" => Some(Carrier::Lan),
            "internet_dial" => Some(Carrier::Internet),
            "p2p_dial" => Some(Carrier::P2p),
            "nearby_dial" => Some(Carrier::Nearby),
            "onion_dial" => Some(Carrier::Onion),
            _ => None,
        }
    }

    /// The carrier a send planned (bridge.rs's dial routes).
    pub(super) fn of_dial(carrier: bridge::DialCarrier) -> Carrier {
        match carrier {
            bridge::DialCarrier::Lan => Carrier::Lan,
            bridge::DialCarrier::Internet => Carrier::Internet,
            bridge::DialCarrier::P2p => Carrier::P2p,
            bridge::DialCarrier::Nearby => Carrier::Nearby,
            bridge::DialCarrier::Onion => Carrier::Onion,
        }
    }
}

/// How one delivery travelled, as far as Raven knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Route {
    pub(super) carrier: Carrier,
    /// Where a send of this app went (`192.168.1.30:7420`); raw, drawn
    /// through display.rs. None when raven-node delivered it.
    pub(super) dial: Option<String>,
    /// How a p2p write travelled, as raven-node recorded it (`direct`,
    /// `relayed`, `hole_punched`, `reversed`); empty when not known.
    pub(super) path: String,
}

impl Route {
    /// The p2p path in words; None when not known (a word this app doesn't
    /// know is not shown).
    fn path_words(&self) -> Option<&'static str> {
        match (self.carrier, self.path.as_str()) {
            (Carrier::P2p, "direct") => Some("direct"),
            (Carrier::P2p, "relayed") => Some("relayed"),
            (Carrier::P2p, "hole_punched") => Some("hole punched"),
            (Carrier::P2p, "reversed") => Some("reversed"),
            _ => None,
        }
    }

    /// The kind of path, for its colour (tokens: `color.pathRule`): a hole
    /// punched is the internet's own, other p2p paths the relays'.
    pub(super) fn kind(&self) -> PathKind {
        match (self.carrier, self.path.as_str()) {
            (Carrier::Lan, _) => PathKind::Lan,
            (Carrier::Nearby, _) => PathKind::Nearby,
            (Carrier::Internet, _) | (Carrier::P2p, "hole_punched") => PathKind::Direct,
            (Carrier::P2p, _) => PathKind::Relay,
            (Carrier::Onion, _) => PathKind::Tor,
        }
    }

    /// How a message came or went as raven-node says it (IPC `Arrivals`);
    /// None for one a keeper held (no carrier: widgets.rs's
    /// `arrived_tag` says it).
    pub(super) fn of_arrived(via: raven_core::arrivals::ArrivedVia) -> Option<Route> {
        use raven_core::arrivals::ArrivedVia;
        let (carrier, path) = match via {
            ArrivedVia::Lan => (Carrier::Lan, ""),
            ArrivedVia::Internet => (Carrier::Internet, ""),
            ArrivedVia::P2p => (Carrier::P2p, ""),
            ArrivedVia::Relayed => (Carrier::P2p, "relayed"),
            ArrivedVia::Tor => (Carrier::Onion, ""),
            ArrivedVia::Nearby => (Carrier::Nearby, ""),
            ArrivedVia::Keeper => return None,
        };
        Some(Route {
            carrier,
            dial: None,
            path: path.into(),
        })
    }

    /// How a delivery went, as raven-node's outbox recorded it (its
    /// carrier and p2p path); None for a carrier this app doesn't know.
    pub(super) fn of_outbox(item: &raven_core::ipc::OutboxItem) -> Option<Route> {
        Some(Route {
            carrier: Carrier::of_label(&item.carrier)?,
            dial: None,
            path: item.path.clone(),
        })
    }

    /// The carrier in words: 'LAN direct'.
    pub(super) fn carrier_words(&self) -> &'static str {
        match self.carrier {
            Carrier::Lan => "LAN direct",
            Carrier::Internet => "Internet direct",
            Carrier::P2p => "p2p",
            Carrier::Nearby => "Bluetooth nearby",
            Carrier::Onion => "via Tor",
        }
    }

    /// The way it went, for a sentence: 'LAN direct', 'p2p (relayed)'.
    pub(super) fn words(&self) -> String {
        match self.path_words() {
            Some(path) => format!("{} ({path})", self.carrier_words()),
            None => self.carrier_words().to_owned(),
        }
    }

    /// The route line's label, its parts `sep` apart: 'LAN direct ·
    /// 192.168.1.30:7420', 'p2p · relayed'. The address is raw.
    pub(super) fn label(&self, sep: &str) -> String {
        let mut label = self.carrier_words().to_owned();
        let more = match (self.carrier, &self.dial) {
            (Carrier::Lan | Carrier::Internet, Some(dial)) => Some(dial.as_str()),
            _ => self.path_words(),
        };
        if let Some(more) = more {
            label.push_str(sep);
            label.push_str(more);
        }
        label
    }
}

/// Something Raven did that the ticker names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Event {
    /// A message of yours was delivered: the friend's Raven signed its
    /// receipt. `took`: from Enter to the receipt, for a send of this
    /// session that brought it back itself.
    Delivered {
        peer: String,
        route: Option<Route>,
        took: Option<Duration>,
    },
    /// One of yours left this computer; no receipt yet.
    Sent { peer: String },
    /// raven-node tried a waiting message again (its attempts grew).
    /// `unreachable`: the try found nobody there. `until_ms`: when it stops
    /// trying (0: not known).
    TriedAgain {
        peer: String,
        unreachable: bool,
        until_ms: u64,
    },
    /// `count` messages from the friend arrived.
    Received { peer: String, count: usize },
}

impl Event {
    /// The friend it is about (a key, lower case).
    pub(super) fn peer(&self) -> &str {
        match self {
            Event::Delivered { peer, .. }
            | Event::Sent { peer }
            | Event::TriedAgain { peer, .. }
            | Event::Received { peer, .. } => peer,
        }
    }

    /// The event in words, `name` the friend as drawn, parts `sep` apart:
    /// the whole sentence first, then shorter ones for a narrow row, each
    /// keeping what matters most (who, and whether the receipt came).
    pub(super) fn texts(&self, name: &str, sep: &str, now_ms: u64) -> Vec<String> {
        let mut texts = match self {
            Event::Delivered { route, took, .. } => {
                let via = route
                    .as_ref()
                    .map(|route| format!(" via {}", route.words()))
                    .unwrap_or_default();
                let took = took
                    .map(|took| format!(" in {}", took_words(took)))
                    .unwrap_or_default();
                let receipt = format!("{sep}receipt signed by {name}");
                vec![
                    format!("Delivered to {name}{via}{took}{receipt}"),
                    format!("Delivered to {name}{took}{receipt}"),
                    format!("Delivered to {name}{receipt}"),
                ]
            }
            Event::Sent { .. } => vec![format!("Sent to {name}{sep}not confirmed yet")],
            Event::TriedAgain {
                unreachable,
                until_ms,
                ..
            } => {
                let found = if *unreachable {
                    "not reachable yet"
                } else {
                    "not delivered yet"
                };
                let until = if *until_ms > now_ms {
                    format!(
                        "keeps trying until {}",
                        bridge::deadline_text(*until_ms, now_ms).short
                    )
                } else {
                    "keeps trying".to_owned()
                };
                vec![
                    format!("Tried {name} again{sep}{found}{sep}{until}"),
                    format!("Tried {name} again{sep}{until}"),
                    format!("Tried {name} again{sep}keeps trying"),
                ]
            }
            Event::Received { count: 1, .. } => vec![format!("New message from {name}")],
            Event::Received { count, .. } => vec![format!("{count} new messages from {name}")],
        };
        texts.dedup();
        texts
    }
}

/// How long a send took, as the ticker says it: '1.4 s', '12 s', '2 min'.
fn took_words(took: Duration) -> String {
    let ms = took.as_millis();
    match ms {
        0..=9_949 => format!("{}.{} s", (ms + 50) / 1000, (ms + 50) % 1000 / 100),
        9_950..=59_499 => format!("{} s", (ms + 500) / 1000),
        _ => format!("{} min", (ms + 30_000) / 60_000),
    }
}

/// The ticker when nothing new happened: whether Raven listens here, how
/// many friends, and what waits (`waiting`: each friend's name and their
/// messages still waiting), `sep` apart. The whole line first, then without
/// the count of friends, then what waits alone, for a narrow row.
pub(super) fn idle_texts(
    listening: bool,
    friends: usize,
    waiting: &[(String, usize)],
    sep: &str,
) -> Vec<String> {
    let listening = listening.then(|| "Listening on your network".to_owned());
    let friends = match friends {
        0 => "No friends yet".to_owned(),
        1 => "1 friend".to_owned(),
        n => format!("{n} friends"),
    };
    let total: usize = waiting.iter().map(|(_, n)| n).sum();
    let waits = match waiting {
        _ if total == 0 => "all quiet".to_owned(),
        [(name, 1)] => format!("1 message waiting for {name}"),
        [(name, n)] => format!("{n} messages waiting for {name}"),
        _ => format!("{total} messages waiting"),
    };
    let join = |parts: &[Option<&String>]| -> String {
        parts
            .iter()
            .flatten()
            .map(|part| part.as_str())
            .collect::<Vec<_>>()
            .join(sep)
    };
    let mut texts = vec![
        join(&[listening.as_ref(), Some(&friends), Some(&waits)]),
        join(&[listening.as_ref(), Some(&waits)]),
        waits.clone(),
    ];
    texts.dedup();
    texts
}

/// What the live feel follows, besides the rows and ticks the App keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Live {
    /// The last Status poll a background program answered.
    pub(super) beat: Option<Touch>,
    /// How the last delivery to each friend went, by key (lower case).
    pub(super) routes: HashMap<String, Route>,
    /// When raven-node last tried each friend's waiting messages again.
    pub(super) rings: HashMap<String, Instant>,
    /// The latest event, and when this app saw it.
    pub(super) event: Option<(Event, Instant)>,
}

impl Live {
    /// The ticker's event at `now`, while it is still news.
    pub(super) fn news(&self, now: Instant) -> Option<&Event> {
        self.event
            .as_ref()
            .filter(|(_, at)| now.saturating_duration_since(*at) < TICKER_FOR)
            .map(|(event, _)| event)
    }

    /// When the ticker's event stops being news.
    pub(super) fn news_until(&self) -> Option<Instant> {
        self.event.as_ref().map(|(_, at)| *at + TICKER_FOR)
    }
}

/// How long ago `then_ms` was at `now_ms`, to the second while it is under
/// a minute: 'just now' (under 5 s), '12 s ago', then as `ash messages`
/// says it ('5 min ago').
pub(super) fn live_age(now_ms: u64, then_ms: u64) -> String {
    let ms = now_ms.saturating_sub(then_ms);
    match ms {
        0..=4_999 => "just now".to_owned(),
        5_000..=59_999 => format!("{} s ago", ms / 1000),
        _ => bridge::short_age(now_ms, then_ms),
    }
}

/// Whether the heart is bright at `now_ms` for a poll answered at
/// `beat_ms`: from the poll to the first whole second at least 200 ms
/// later, so it goes dim with the clock's own redraw. Never under reduced
/// motion.
pub(super) fn pulse_on(beat_ms: u64, now_ms: u64, motion: Motion) -> bool {
    let until = (beat_ms + PULSE_MIN_MS).div_ceil(1000) * 1000;
    motion == Motion::Full && (beat_ms..until).contains(&now_ms)
}

/// Messages per bucket, oldest first, from their times (`times_ms`, on the
/// wall clock): the last bucket is the two minutes `now_ms` is in. Times
/// ahead of `now_ms` (a sender's clock ahead of this one) count as now.
pub(super) fn activity(times_ms: impl IntoIterator<Item = u64>, now_ms: u64) -> [u32; BUCKETS] {
    let current = now_ms / BUCKET_MS;
    let mut buckets = [0u32; BUCKETS];
    for at in times_ms {
        let back = current.saturating_sub(at.min(now_ms) / BUCKET_MS);
        if let Some(i) = usize::try_from(back)
            .ok()
            .filter(|back| *back < BUCKETS)
            .map(|back| BUCKETS - 1 - back)
        {
            buckets[i] = buckets[i].saturating_add(1);
        }
    }
    buckets
}

/// The activity line: a bar for each bucket, the lowest for none, the
/// highest for six or more.
pub(super) fn sparkline(buckets: &[u32], glyphs: &Glyphs) -> String {
    let top = glyphs.bars.len() - 1;
    buckets
        .iter()
        .map(|n| glyphs.bars[usize::try_from(*n).map_or(top, |n| n.min(top))])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 1_760_000_000_000;

    #[test]
    fn activity_counts_per_two_minutes_on_the_clock() {
        let bucket_start = NOW_MS / BUCKET_MS * BUCKET_MS;
        let times = [
            // The current two minutes: from its start to now, and a sender
            // ahead of this clock.
            bucket_start,
            NOW_MS,
            NOW_MS + 3_600_000,
            // The two minutes before, at both ends.
            bucket_start - 1,
            bucket_start - BUCKET_MS,
            // The oldest bucket, 46 to 48 minutes back.
            bucket_start - 23 * BUCKET_MS,
            // Older than 48 minutes: not counted.
            bucket_start - 23 * BUCKET_MS - 1,
            0,
        ];
        let buckets = activity(times, NOW_MS);
        assert_eq!(buckets[BUCKETS - 1], 3);
        assert_eq!(buckets[BUCKETS - 2], 2);
        assert_eq!(buckets[0], 1);
        assert_eq!(buckets.iter().sum::<u32>(), 6);
        assert_eq!(activity([], NOW_MS), [0; BUCKETS]);
        // A new bucket starts on the clock's even minutes, not when the app
        // opened.
        let later = activity([NOW_MS], bucket_start + BUCKET_MS);
        assert_eq!((later[BUCKETS - 1], later[BUCKETS - 2]), (0, 1));
    }

    #[test]
    fn the_activity_line_rises_to_six() {
        let counts: Vec<u32> = (0..9).collect();
        assert_eq!(sparkline(&counts, &Glyphs::fancy()), "⣀⣠⣤⣴⣶⣾⣿⣿⣿");
        assert_eq!(sparkline(&counts, &Glyphs::simple()), ".:-=+*###");
        assert_eq!(sparkline(&counts, &Glyphs::ascii()), ".:-=+*###");
        assert_eq!(sparkline(&[u32::MAX], &Glyphs::ascii()), "#");
        assert_eq!(
            sparkline(&activity([], NOW_MS), &Glyphs::fancy()),
            "⣀".repeat(BUCKETS)
        );
    }

    #[test]
    fn ages_count_by_the_second_under_a_minute() {
        assert_eq!(live_age(NOW_MS, NOW_MS), "just now");
        assert_eq!(live_age(NOW_MS, NOW_MS - 4_999), "just now");
        assert_eq!(live_age(NOW_MS, NOW_MS - 5_000), "5 s ago");
        assert_eq!(live_age(NOW_MS, NOW_MS - 59_999), "59 s ago");
        assert_eq!(live_age(NOW_MS, NOW_MS - 60_000), "1 min ago");
        assert_eq!(live_age(NOW_MS, NOW_MS - 7_200_000), "2 h ago");
        // A time ahead of this clock is now.
        assert_eq!(live_age(NOW_MS, NOW_MS + 9_000), "just now");
    }

    #[test]
    fn the_heart_is_bright_to_the_next_whole_second() {
        let beat = NOW_MS + 300;
        assert!(pulse_on(beat, beat, Motion::Full));
        assert!(pulse_on(beat, NOW_MS + 999, Motion::Full));
        assert!(!pulse_on(beat, NOW_MS + 1000, Motion::Full));
        assert!(!pulse_on(beat, beat - 1, Motion::Full));
        // At least 200 ms: a poll late in a second stays bright into the next.
        let late = NOW_MS + 900;
        assert!(pulse_on(late, NOW_MS + 1050, Motion::Full));
        assert!(!pulse_on(late, NOW_MS + 2000, Motion::Full));
        // Never under reduced motion.
        assert!(!pulse_on(beat, beat, Motion::Reduced));
    }

    #[test]
    fn each_route_has_its_path_kind() {
        let route = |carrier, path: &str| Route {
            carrier,
            dial: None,
            path: path.into(),
        };
        assert_eq!(route(Carrier::Lan, "").kind(), PathKind::Lan);
        assert_eq!(route(Carrier::Nearby, "").kind(), PathKind::Nearby);
        assert_eq!(route(Carrier::Internet, "").kind(), PathKind::Direct);
        assert_eq!(route(Carrier::P2p, "hole_punched").kind(), PathKind::Direct);
        assert_eq!(route(Carrier::Onion, "").kind(), PathKind::Tor);
        assert_eq!(route(Carrier::Onion, "").words(), "via Tor");
        assert_eq!(route(Carrier::Onion, "").label(" · "), "via Tor");
        let onion = raven_core::ipc::OutboxItem {
            carrier: "onion_dial".into(),
            ..raven_core::ipc::OutboxItem::default()
        };
        assert_eq!(Route::of_outbox(&onion), Some(route(Carrier::Onion, "")));
        for path in ["relayed", "direct", "reversed", ""] {
            assert_eq!(route(Carrier::P2p, path).kind(), PathKind::Relay, "{path}");
        }
        let item = raven_core::ipc::OutboxItem {
            carrier: "p2p_dial".into(),
            path: "relayed".into(),
            ..raven_core::ipc::OutboxItem::default()
        };
        assert_eq!(
            Route::of_outbox(&item),
            Some(route(Carrier::P2p, "relayed"))
        );
        let unknown = raven_core::ipc::OutboxItem {
            carrier: "pigeon".into(),
            ..item
        };
        assert_eq!(Route::of_outbox(&unknown), None);
    }

    #[test]
    fn routes_say_what_raven_knows() {
        let lan = Route {
            carrier: Carrier::Lan,
            dial: Some("192.168.1.30:7420".into()),
            path: String::new(),
        };
        assert_eq!(lan.label(" · "), "LAN direct · 192.168.1.30:7420");
        assert_eq!(lan.words(), "LAN direct");
        let background = Route { dial: None, ..lan };
        assert_eq!(background.label(" · "), "LAN direct");
        let relayed = Route {
            carrier: Carrier::P2p,
            dial: Some("/p2p/12D3KooW".into()),
            path: "relayed".into(),
        };
        assert_eq!(relayed.label(" · "), "p2p · relayed");
        assert_eq!(relayed.words(), "p2p (relayed)");
        let punched = Route {
            path: "hole_punched".into(),
            ..relayed.clone()
        };
        assert_eq!(punched.label(" - "), "p2p - hole punched");
        // A path this app doesn't know is not shown.
        let unknown = Route {
            path: "wss".into(),
            ..relayed
        };
        assert_eq!(unknown.label(" · "), "p2p");
        let internet = Route {
            carrier: Carrier::Internet,
            dial: Some("203.0.113.5:7420".into()),
            path: String::new(),
        };
        assert_eq!(internet.label(" · "), "Internet direct · 203.0.113.5:7420");
        assert_eq!(Carrier::of_label("lan_dial"), Some(Carrier::Lan));
        assert_eq!(Carrier::of_label("internet_dial"), Some(Carrier::Internet));
        assert_eq!(Carrier::of_label("p2p_dial"), Some(Carrier::P2p));
        assert_eq!(Carrier::of_label("nearby_dial"), Some(Carrier::Nearby));
        assert_eq!(Carrier::of_label(""), None);
        assert_eq!(Carrier::of_label("ble"), None);
    }

    #[test]
    fn the_ticker_names_real_events() {
        let sep = " · ";
        let lan = Route {
            carrier: Carrier::Lan,
            dial: Some("192.168.1.30:7420".into()),
            path: String::new(),
        };
        let delivered = Event::Delivered {
            peer: "aa".into(),
            route: Some(lan),
            took: Some(Duration::from_millis(1_400)),
        };
        assert_eq!(
            delivered.texts("Ali", sep, NOW_MS),
            [
                "Delivered to Ali via LAN direct in 1.4 s · receipt signed by Ali",
                "Delivered to Ali in 1.4 s · receipt signed by Ali",
                "Delivered to Ali · receipt signed by Ali",
            ]
        );
        let background = Event::Delivered {
            peer: "aa".into(),
            route: None,
            took: None,
        };
        assert_eq!(
            background.texts("Ali", sep, NOW_MS),
            ["Delivered to Ali · receipt signed by Ali"]
        );
        assert_eq!(
            Event::Sent { peer: "aa".into() }.texts("Ali", sep, NOW_MS),
            ["Sent to Ali · not confirmed yet"]
        );
        let tried = Event::TriedAgain {
            peer: "bb".into(),
            unreachable: true,
            until_ms: NOW_MS + 22 * 3_600_000,
        };
        // This computer's time zone isn't known under test: how long is left.
        assert_eq!(
            tried.texts("Mina", sep, NOW_MS)[0],
            "Tried Mina again · not reachable yet · keeps trying until about 22 h from now"
        );
        let local = bridge::with_local_offset(Some(0), || tried.texts("Mina", sep, NOW_MS));
        assert_eq!(
            local,
            [
                "Tried Mina again · not reachable yet · keeps trying until tomorrow 06:53",
                "Tried Mina again · keeps trying until tomorrow 06:53",
                "Tried Mina again · keeps trying",
            ]
        );
        let unknown = Event::TriedAgain {
            peer: "bb".into(),
            unreachable: false,
            until_ms: 0,
        };
        assert_eq!(
            unknown.texts("Mina", " - ", NOW_MS),
            [
                "Tried Mina again - not delivered yet - keeps trying",
                "Tried Mina again - keeps trying",
            ]
        );
        let one = Event::Received {
            peer: "aa".into(),
            count: 1,
        };
        assert_eq!(one.texts("Ali", sep, NOW_MS), ["New message from Ali"]);
        let three = Event::Received {
            peer: "aa".into(),
            count: 3,
        };
        assert_eq!(three.texts("Ali", sep, NOW_MS), ["3 new messages from Ali"]);
        assert_eq!(three.peer(), "aa");
        // How long a send took.
        let took = |ms| took_words(Duration::from_millis(ms));
        assert_eq!(
            [
                took(0),
                took(1_400),
                took(9_949),
                took(9_950),
                took(59_499),
                took(59_500),
                took(125_000)
            ],
            ["0.0 s", "1.4 s", "9.9 s", "10 s", "59 s", "1 min", "2 min"]
        );
    }

    #[test]
    fn the_quiet_ticker_says_how_things_stand() {
        let sep = " · ";
        assert_eq!(
            idle_texts(true, 3, &[], sep),
            [
                "Listening on your network · 3 friends · all quiet",
                "Listening on your network · all quiet",
                "all quiet",
            ]
        );
        assert_eq!(
            idle_texts(true, 3, &[("Mina".into(), 1)], sep)[0],
            "Listening on your network · 3 friends · 1 message waiting for Mina"
        );
        assert_eq!(
            idle_texts(false, 1, &[("Mina".into(), 2)], " - "),
            [
                "1 friend - 2 messages waiting for Mina",
                "2 messages waiting for Mina"
            ]
        );
        assert_eq!(
            idle_texts(true, 2, &[("Mina".into(), 2), ("Rena".into(), 1)], sep)[0],
            "Listening on your network · 2 friends · 3 messages waiting"
        );
        assert_eq!(
            idle_texts(false, 0, &[], sep),
            ["No friends yet · all quiet", "all quiet"]
        );
    }

    #[test]
    fn news_lasts_30_seconds() {
        let t0 = Instant::now();
        let mut live = Live::default();
        assert_eq!(live.news(t0), None);
        assert_eq!(live.news_until(), None);
        let event = Event::Sent { peer: "aa".into() };
        live.event = Some((event.clone(), t0));
        assert_eq!(live.news(t0 + Duration::from_secs(29)), Some(&event));
        assert_eq!(live.news(t0 + TICKER_FOR), None);
        assert_eq!(live.news_until(), Some(t0 + TICKER_FOR));
    }
}
