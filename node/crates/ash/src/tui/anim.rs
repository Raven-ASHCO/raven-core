//! The frame scheduler: when the UI thread must wake to draw something that
//! changes with time alone (a spinner, a transition, a toast going away,
//! the clock), and whether a frame is due now.
//!
//! Every animation is a pure function of when it started and the time now,
//! so a frame drawn late is still the right frame, and a frame is drawn only
//! when the picture would differ from the last one. When nothing moves,
//! [`next_wait`] is None: an idle app wakes for nothing and draws nothing.
//! Home's clock and the ages that count up change once a second
//! ([`Moving::Clock`]): an idle Home draws at most once a second.
//!
//! The frame budget: frames are never closer than the spinner's interval,
//! 80 ms (160 ms over SSH), whatever an animation asks.
//!
//! Every motion starts here, from what the screens list in their `moving`
//! (testkit's scan: no render code reads the clock or waits by itself).
//! Each one is started by something Raven did (live.rs), but WZ-1's reveal.
//!
//! Reduced motion (theme.rs): no spinner frames (a still '…') and no
//! transitions; only text changes (the clock, the ages).

use std::time::{Duration, Instant};

#[cfg(test)]
use super::app::Msg;
use super::app::{App, Look, Screen, Toast};
#[cfg(test)]
use super::controller::Conversations;
#[cfg(test)]
use super::live;
#[cfg(test)]
use super::state_file::Receive;
#[cfg(test)]
use super::testkit;
#[cfg(test)]
use super::theme::Glyphs;
use super::theme::Motion;
use super::ui::widgets::Chip;
use super::ui::{add_friend, home, network, overlays, verify, wizard};

/// Half a pulse: KC's icon is bright, then dim, once a second.
pub(super) const PULSE_STEP: Duration = Duration::from_millis(500);

/// Something on screen that changes with time alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Moving {
    /// A spinner turning since `since`: a frame every `Look::spinner_interval`.
    Spinner { since: Instant },
    /// `frames` frames spread evenly over `length` from `start`, then still:
    /// a draw-in, an emphasis that fades, a blink.
    Transition {
        start: Instant,
        frames: u32,
        length: Duration,
    },
    /// One change at a known time: a toast going away.
    Deadline(Instant),
    /// A change every `every` from `since`, for as long as it shows: a
    /// pulse. Still under reduced motion.
    Steps { since: Instant, every: Duration },
    /// Text that changes on each whole second of the wall clock: Home's
    /// clock and the ages that count up. `at_ms` is `at` on the wall clock.
    /// Under reduced motion too: it is text, not motion.
    Clock { at: Instant, at_ms: u64 },
}

/// What moves on the screen `app` shows now. Each animated widget adds its
/// source here in the change that draws it. Behind SMALL nothing turns, and
/// during COPY nothing is drawn at all.
pub(super) fn moving(app: &App) -> Vec<Moving> {
    if app.peeking() {
        return Vec::new();
    }
    let mut moving: Vec<Moving> = app
        .toast()
        .and_then(Toast::until)
        .map(Moving::Deadline)
        .into_iter()
        .collect();
    if !app.too_small() {
        // The header's chip while the background program starts.
        if let Some(Chip::Starting { since }) = app.chip() {
            moving.push(Moving::Spinner { since });
        }
        if let Some(since) = app.keychain_pulse() {
            moving.push(Moving::Steps {
                since,
                every: PULSE_STEP,
            });
        }
        // WZ-1's mark and letters, WZ-4's spinner, WZ-5's words.
        if let Screen::Wizard(step) = app.screen() {
            moving.extend(wizard::moving(
                step,
                app.me().map(|me| me.words.as_slice()),
                app.look(),
                app.size(),
            ));
        }
        // Home's delivery ticks (spinners, draw-ins, blinks) and its live
        // feel: the clock and ages, the route line, the friends' blinks and
        // retry rings, the ticker's news going.
        moving.extend(home::moving(app));
        // AF-1's spinner while Raven starts, and a paste's summary fading.
        moving.extend(add_friend::moving(app));
        // VF's marks and match drawing in, AF-3's check mark.
        moving.extend(verify::moving(app));
        // NET's Starting row.
        moving.extend(network::moving(app));
        // QUIT's spinner while a chosen quit waits for a send or a stop.
        moving.extend(overlays::moving(app));
    }
    moving
}

/// The frame a transition of `frames` frames over `length` from `start`
/// shows at `now`: 0 at its start, `frames` once it rests, and `frames` at
/// once under reduced motion. Its frames change where [`next_change`] says.
pub(super) fn transition_frame(
    start: Instant,
    now: Instant,
    frames: u32,
    length: Duration,
    motion: Motion,
) -> u32 {
    if motion == Motion::Reduced || length.is_zero() {
        return frames;
    }
    let into = now.saturating_duration_since(start).as_nanos();
    let frame = into.saturating_mul(u128::from(frames)) / length.as_nanos();
    u32::try_from(frame).map_or(frames, |frame| frame.min(frames))
}

/// Whether a pulse that started at `since` is bright at `now`: always under
/// reduced motion.
pub(super) fn pulse_on(since: Instant, now: Instant, motion: Motion) -> bool {
    motion == Motion::Reduced || spinner_frame(since, now, PULSE_STEP).is_multiple_of(2)
}

/// How long the UI thread may wait for a message before the picture changes
/// by itself, or the read markers are due to be saved (the tick that follows
/// saves them); None when nothing moves and nothing is due.
pub(super) fn next_wait(app: &App, now: Instant) -> Option<Duration> {
    let after = app.drawn_at().unwrap_or(now);
    let change = next_change(&moving(app), app.look(), after).map(|at| budget(app, at));
    [change, app.marks_due()]
        .into_iter()
        .flatten()
        .min()
        .map(|at| at.saturating_duration_since(now))
}

/// Whether something moved on since the last frame was drawn, and the frame
/// budget allows one. Before the first frame the app is dirty anyway.
pub(super) fn frame_due(app: &App, now: Instant) -> bool {
    app.drawn_at().is_some_and(|drawn| {
        next_change(&moving(app), app.look(), drawn).is_some_and(|at| budget(app, at) <= now)
    })
}

/// The frame for a change at `at`, no sooner than the frame budget allows
/// after the last frame: 12 frames a second, 6 over SSH.
fn budget(app: &App, at: Instant) -> Instant {
    app.drawn_at()
        .and_then(|drawn| drawn.checked_add(app.look().spinner_interval))
        .map_or(at, |earliest| at.max(earliest))
}

/// The first moment after `after` when one of `moving` looks different.
pub(super) fn next_change(moving: &[Moving], look: &Look, after: Instant) -> Option<Instant> {
    moving
        .iter()
        .filter_map(|m| change_after(*m, look, after))
        .min()
}

/// The first moment after `after` when `m` looks different, if it ever does.
fn change_after(m: Moving, look: &Look, after: Instant) -> Option<Instant> {
    match (m, look.motion) {
        (Moving::Spinner { since }, Motion::Full) => {
            let next = spinner_frame(since, after, look.spinner_interval).checked_add(1)?;
            since.checked_add(times(look.spinner_interval, next)?)
        }
        (
            Moving::Transition {
                start,
                frames,
                length,
            },
            Motion::Full,
        ) => {
            // Frame i shows from start + length * i / frames; the last
            // boundary (i = frames) is where it comes to rest.
            let frames = u128::from(frames.max(1));
            let into = after.saturating_duration_since(start).as_nanos();
            let next = into.checked_mul(frames)? / length.as_nanos().max(1) + 1;
            if next > frames {
                return None;
            }
            let offset = length.as_nanos().checked_mul(next)? / frames;
            start.checked_add(Duration::from_nanos(u64::try_from(offset).ok()?))
        }
        (Moving::Deadline(at), _) => (at > after).then_some(at),
        (Moving::Steps { since, every }, Motion::Full) => {
            let next = spinner_frame(since, after, every).checked_add(1)?;
            since.checked_add(times(every, next)?)
        }
        (Moving::Clock { at, at_ms }, _) => {
            // The wall clock at `after` (before or after `at`), in ns, and
            // the next whole second after it.
            const SECOND: i128 = 1_000_000_000;
            let anchor = i128::from(at_ms) * 1_000_000;
            let wall = if after >= at {
                anchor + i128::try_from(after.duration_since(at).as_nanos()).ok()?
            } else {
                anchor - i128::try_from(at.duration_since(after).as_nanos()).ok()?
            };
            let offset = (wall.div_euclid(SECOND) + 1) * SECOND - anchor;
            let shift = Duration::from_nanos(u64::try_from(offset.unsigned_abs()).ok()?);
            if offset >= 0 {
                at.checked_add(shift)
            } else {
                at.checked_sub(shift)
            }
        }
        (
            Moving::Spinner { .. } | Moving::Transition { .. } | Moving::Steps { .. },
            Motion::Reduced,
        ) => None,
    }
}

/// The spinner frame to draw at `now` for one turning since `since`.
pub(super) fn spinner_frame(since: Instant, now: Instant, interval: Duration) -> u64 {
    let frame = now.saturating_duration_since(since).as_nanos() / interval.as_nanos().max(1);
    u64::try_from(frame).unwrap_or(u64::MAX)
}

/// `step` times `n`, if that fits in a Duration.
fn times(step: Duration, n: impl TryInto<u32>) -> Option<Duration> {
    step.checked_mul(n.try_into().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn full() -> Look {
        testkit::simple_mono()
    }

    fn reduced() -> Look {
        Look {
            motion: Motion::Reduced,
            ..full()
        }
    }

    fn over_ssh() -> Look {
        Look {
            spinner_interval: ms(160),
            ..full()
        }
    }

    #[test]
    fn an_idle_app_never_wakes() {
        let mut app = testkit::app((80, 24));
        let t0 = app.now();
        assert_eq!(next_wait(&app, t0), None);
        assert!(!frame_due(&app, t0), "nothing drawn yet: the app is dirty");
        app.mark_drawn(t0);
        assert_eq!(next_wait(&app, t0 + Duration::from_secs(3600)), None);
        assert!(!frame_due(&app, t0 + Duration::from_secs(3600)));
        // Keys that change nothing on screen add no wake-up either.
        testkit::press(&mut app, KeyCode::Up);
        testkit::tick(&mut app, Duration::from_secs(60));
        assert!(moving(&app).is_empty());
        assert_eq!(next_wait(&app, app.now()), None);
    }

    #[test]
    fn a_visible_spinner_wakes_within_80_ms() {
        let t0 = Instant::now();
        let spinner = [Moving::Spinner { since: t0 }];
        assert_eq!(next_change(&spinner, &full(), t0), Some(t0 + ms(80)));
        assert_eq!(
            next_change(&spinner, &full(), t0 + ms(50)),
            Some(t0 + ms(80))
        );
        assert_eq!(
            next_change(&spinner, &full(), t0 + ms(80)),
            Some(t0 + ms(160))
        );
        // Drawn before it started: its first change is a frame later.
        let later = [Moving::Spinner {
            since: t0 + ms(500),
        }];
        assert_eq!(next_change(&later, &full(), t0), Some(t0 + ms(580)));
        // Over SSH, half as many frames.
        assert_eq!(next_change(&spinner, &over_ssh(), t0), Some(t0 + ms(160)));
        // The frame number follows the clock alone.
        assert_eq!(spinner_frame(t0, t0, ms(83)), 0);
        assert_eq!(spinner_frame(t0, t0 + ms(82), ms(83)), 0);
        assert_eq!(spinner_frame(t0, t0 + ms(83), ms(83)), 1);
        assert_eq!(spinner_frame(t0, t0 + ms(170), ms(83)), 2);
        assert_eq!(spinner_frame(t0 + ms(10), t0, ms(83)), 0);
        assert_eq!(spinner_frame(t0, t0 + ms(5), Duration::ZERO), 5_000_000);
    }

    #[test]
    fn reduced_motion_schedules_no_spinner_frames() {
        let t0 = Instant::now();
        let still = [
            Moving::Spinner { since: t0 },
            Moving::Transition {
                start: t0,
                frames: 5,
                length: ms(400),
            },
        ];
        assert_eq!(next_change(&still, &reduced(), t0), None);
        assert!(next_change(&still, &full(), t0).is_some());
        // A toast still goes away on time.
        let toast = [still[0], Moving::Deadline(t0 + ms(4000))];
        assert_eq!(next_change(&toast, &reduced(), t0), Some(t0 + ms(4000)));
    }

    #[test]
    fn the_clock_changes_on_whole_seconds() {
        let t0 = Instant::now() + Duration::from_secs(1);
        let clock = [Moving::Clock {
            at: t0,
            at_ms: 1_760_000_000_250,
        }];
        assert_eq!(next_change(&clock, &full(), t0), Some(t0 + ms(750)));
        assert_eq!(
            next_change(&clock, &full(), t0 + ms(750)),
            Some(t0 + ms(1750))
        );
        // Drawn before its anchor: the second that passed in between.
        assert_eq!(
            next_change(&clock, &full(), t0 - ms(400)),
            Some(t0 - ms(250))
        );
        // Text, not motion: under reduced motion too.
        assert_eq!(next_change(&clock, &reduced(), t0), Some(t0 + ms(750)));
    }

    #[test]
    fn a_transition_steps_through_its_frames_then_rests() {
        let t0 = Instant::now();
        let draw_in = [Moving::Transition {
            start: t0,
            frames: 5,
            length: ms(400),
        }];
        let mut at = t0;
        let mut changes = Vec::new();
        while let Some(next) = next_change(&draw_in, &full(), at) {
            changes.push(next.duration_since(t0).as_millis());
            at = next;
        }
        assert_eq!(changes, [80, 160, 240, 320, 400]);
        assert_eq!(next_change(&draw_in, &full(), t0 + ms(1000)), None);
    }

    #[test]
    fn the_soonest_change_wins() {
        let t0 = Instant::now();
        let both = [
            Moving::Deadline(t0 + ms(4000)),
            Moving::Spinner { since: t0 },
            Moving::Deadline(t0 + ms(20)),
        ];
        assert_eq!(next_change(&both, &full(), t0), Some(t0 + ms(20)));
        assert_eq!(next_change(&both, &full(), t0 + ms(20)), Some(t0 + ms(80)));
        assert_eq!(next_change(&[], &full(), t0), None);
        // A deadline already passed changes nothing more.
        assert_eq!(next_change(&both[..1], &full(), t0 + ms(4000)), None);
    }

    #[test]
    fn a_toast_wakes_the_app_once_when_it_goes() {
        let mut app = testkit::app((80, 24));
        let t0 = app.now();
        app.mark_drawn(t0);
        testkit::ctrl(&mut app, 'z');
        assert!(app.take_dirty(), "the toast shows at once");
        app.mark_drawn(t0);
        let until = app.toast().and_then(Toast::until).expect("a toast on show");
        assert_eq!(next_wait(&app, t0), Some(until - t0));
        assert_eq!(next_wait(&app, t0 + ms(1000)), Some(until - t0 - ms(1000)));
        assert!(!frame_due(&app, until - ms(1)));
        assert!(frame_due(&app, until));
        // Late is fine: still due, and no wait.
        assert_eq!(next_wait(&app, until + ms(30)), Some(Duration::ZERO));

        // The UI thread's tick at that moment takes it away and draws once.
        app.update(Msg::Tick, until, 0);
        assert!(app.toast().is_none());
        assert!(app.take_dirty());
        app.mark_drawn(until);
        assert_eq!(next_wait(&app, until), None);
        assert!(!frame_due(&app, until + Duration::from_secs(60)));
    }

    /// Home at 80x24 in `look` with friend 1 (an address) open, a
    /// background program this app started listening, and no other news.
    fn live_home(look: Look) -> App {
        let mut app = testkit::home_app_in(
            look,
            (80, 24),
            Receive::On,
            vec![testkit::reachable(1)],
            Conversations::new(),
        );
        testkit::press(&mut app, KeyCode::Enter);
        testkit::started_here(&mut app, 4242);
        app
    }

    /// Every change `app` asks to be woken for from `from` to `until`, in
    /// ms after `from`.
    fn changes(app: &App, from: Instant, until: Duration) -> Vec<u64> {
        let moving = moving(app);
        let mut at = from;
        let mut out = Vec::new();
        while let Some(next) = next_change(&moving, app.look(), at) {
            if next > from + until {
                break;
            }
            out.push(u64::try_from(next.duration_since(from).as_millis()).expect("ms"));
            at = next;
        }
        out
    }

    /// The UI thread's loop for `app` over `span`, drawing whenever a frame
    /// is due: the time of each frame after the first, in ms.
    fn frames_over(app: &mut App, span: Duration) -> Vec<u64> {
        let t0 = app.now();
        app.mark_drawn(t0);
        let mut frames = Vec::new();
        while let Some(wait) = next_wait(app, app.now()) {
            if app.now() + wait > t0 + span {
                break;
            }
            testkit::tick(app, wait);
            if frame_due(app, app.now()) {
                app.mark_drawn(app.now());
                frames.push(u64::try_from((app.now() - t0).as_millis()).expect("ms"));
            }
        }
        frames
    }

    #[test]
    fn nothing_moves_without_a_real_event() {
        // A quiet Home: only its clock's text, once a second.
        let mut app = live_home(full());
        assert_eq!(
            moving(&app),
            [Moving::Clock {
                at: app.now(),
                at_ms: app.now_ms()
            }]
        );
        // A Status poll answered: the heart is bright to the next second,
        // which the clock redraws anyway. Nothing more wakes the app.
        testkit::tick(&mut app, ms(300));
        testkit::send(&mut app, testkit::node_up());
        assert_eq!(moving(&app).len(), 1);
        // A send: the route line and its spinner, while it runs.
        testkit::type_and_send(&mut app, "hi").expect("a send");
        assert!(moving(&app)
            .iter()
            .any(|m| matches!(m, Moving::Steps { every, .. } if *every == live::ROUTE_TIME / live::ROUTE_STEPS)));
        // The Welcome mark's reveal is the one motion no event starts.
        let wizard = testkit::wizard_app((80, 24));
        assert!(!moving(&wizard).is_empty());
    }

    #[test]
    fn reduced_motion_requests_no_animation_frames() {
        let reduced = Look {
            glyphs: Glyphs::fancy(),
            ..reduced()
        };
        let mut app = live_home(reduced);
        let wall_s = app.now_ms() / 1000;
        assert_eq!(app.now_ms(), wall_s * 1000, "the test clock is on a second");
        // Everything that moves under full motion at once: a send running,
        // a ring, news in the list, the heartbeat.
        testkit::type_and_send(&mut app, "hi").expect("a send");
        let mut item = testkit::outbox_item(1, 1, "queued");
        testkit::send(&mut app, testkit::outbox(vec![item.clone()]));
        item.attempts = 1;
        testkit::send(&mut app, testkit::outbox(vec![item]));
        testkit::reload_rows(&mut app, &[(1, testkit::row(2, false, "", 0, "hello"))]);
        testkit::send(&mut app, testkit::node_up());
        let full_look = Look {
            motion: Motion::Full,
            ..*app.look()
        };
        let mut moving_full = app.clone();
        moving_full.set_look_for_tests(full_look);
        assert!(
            changes(&moving_full, app.now(), ms(1000)).len() > 5,
            "under full motion all of it moves"
        );
        // Reduced: the clock's whole seconds, and the ticker's news going
        // after 30 s; no frame between.
        let news = app.live().news_until().expect("news");
        let t0 = app.now();
        for at in changes(&app, t0, Duration::from_secs(40)) {
            let on_a_second = at % 1000 == 0;
            assert!(
                on_a_second || t0 + ms(at) == news,
                "a frame at {at} ms under reduced motion"
            );
        }
    }

    #[test]
    fn an_idle_home_draws_at_most_once_a_second() {
        let mut app = live_home(full());
        let frames = frames_over(&mut app, Duration::from_secs(10));
        assert_eq!(frames, (1..=10).map(|s| s * 1000).collect::<Vec<u64>>());
        // A Status poll every 2 s is an event of its own: still no frame
        // between the seconds.
        let mut app = live_home(full());
        let t0 = app.now();
        let mut drawn = Vec::new();
        app.mark_drawn(t0);
        for _ in 0..5 {
            for _ in 0..2 {
                let wait = next_wait(&app, app.now()).expect("the clock");
                assert!(wait <= Duration::from_secs(1));
                testkit::tick(&mut app, wait);
                if frame_due(&app, app.now()) {
                    app.mark_drawn(app.now());
                    drawn.push(app.now() - t0);
                }
            }
            testkit::send(&mut app, testkit::node_up());
        }
        assert!(drawn
            .windows(2)
            .all(|w| w[1] - w[0] >= Duration::from_secs(1)));
    }

    #[test]
    fn animation_keeps_the_frame_budget() {
        // A send running: its spinner (every 80 ms) and the route line
        // (a step every 50 ms) ask for more than the budget gives.
        for (look, budget) in [(full(), 80), (over_ssh(), 160)] {
            let mut app = live_home(look);
            testkit::type_and_send(&mut app, "hi").expect("a send");
            let frames = frames_over(&mut app, Duration::from_secs(2));
            assert!(frames.len() >= 10, "{frames:?}");
            let mut last = 0;
            for at in frames {
                assert!(
                    at - last >= budget,
                    "{at} ms after {last} ms: {budget} ms budget"
                );
                last = at;
            }
        }
    }
}
