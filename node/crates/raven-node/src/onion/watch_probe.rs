//! Keep watch, groundwork for step (c): the Tor helper alone, inside the
//! calling process, with no raven-node around it (lab: debug builds with
//! the feature `tor-embedded`).
//!
//! The iPhone app's tunnel extension (the VPN slot of "Keep watch") calls it
//! to learn two things before the node moves in there: how much memory Tor
//! takes against the slot's limit of 50 MiB, and whether Tor lives through
//! the short sleeps and wakes iOS gives that slot (a first night on an
//! iPhone 16 Pro Max, 2026-11-17: awake about 15% of the time, a few
//! seconds about 45 times an hour).
//!
//! It runs the same in-process helper the iPhone app's node runs
//! ([`super::InProcess`]: Arti with one onion service), on a state folder of
//! its own. That onion service is a throwaway: its key is made in that
//! folder, nobody is told its address, and no Raven identity, contact or
//! message is anywhere near it. Its inbound streams would go to a loopback
//! listener that takes them and closes; none come but the helper's own
//! check, which the service refuses by itself (that answer proves the
//! descriptor, an introduction point and a rendezvous all worked).
//!
//! The probe asks for that check by the wall clock, which goes on while the
//! device sleeps: a first one soon after the service's descriptor went out,
//! then one every [`start`]'s `check_every`, asked the first second this
//! process runs after it is due. So off the charger a check is mostly asked
//! right after a wake, and its two durations (the time this process ran,
//! the time on the wall clock) say what a sleep in the middle of it cost.
//!
//! It keeps Tor alive in the plainest way, and counts every time it had
//! to: a life that is not ready in [`READY_WAIT`] of running time, or whose
//! checks missed [`MISSES_END_A_LIFE`] times in a row (a check with no
//! answer in [`CHECK_WAIT`] is a miss), is ended and another started
//! (without the circuit times the old one learned), after a pause that
//! doubles while nothing is reached.
//!
//! [`status`] gives the counts as one JSON object: numbers and the helper's
//! fixed words only, never the onion address.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use raven_core::clock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::proto::{self, Command, Event};
use super::{InProcess, LineReader, Proc, Spawn};

/// A life that is not ready after this much running time is ended.
const READY_WAIT: Duration = Duration::from_secs(180);
/// This many checks in a row that did not reach the service end a life.
const MISSES_END_A_LIFE: u32 = 4;
/// A check the helper has not answered in this much running time is given
/// up, and counts as one that did not reach (the helper's own tries end
/// well within it).
const CHECK_WAIT: Duration = Duration::from_secs(120);
/// The pause before the next life: this, doubled after every life that
/// reached nothing, up to [`LONGEST_PAUSE`].
const FIRST_PAUSE: Duration = Duration::from_secs(5);
const LONGEST_PAUSE: Duration = Duration::from_secs(300);
/// The shortest time between two checks [`start`] takes: a check builds
/// new circuits, and the Tor network is not ours to load.
pub const CHECK_EVERY_MIN: Duration = Duration::from_secs(60);

/// When checks are asked, by the wall clock.
#[derive(Clone, Copy, Debug)]
struct Pace {
    /// The first check of a life, after it is ready (raven-node's own
    /// first check waits as long).
    first: Duration,
    /// ... or this long after its descriptor first reached an HSDir.
    after_upload: Duration,
    /// Between an answer and the next check.
    every: Duration,
}

/// What the probe saw since its start.
#[derive(Clone, Debug, Default)]
struct Seen {
    /// "off", "starting", "bootstrapping", "ready", "ended", "too_old".
    phase: &'static str,
    /// Bootstrap progress of the life that runs, 0 to 100, and Tor's word
    /// for what blocks it, if it says so.
    pct: u8,
    blocked: String,
    /// The onion service's state as the helper words it.
    service: String,
    /// Helper lives started; those ended for not being ready in time, and
    /// for checks that missed; panics of the helper.
    lives: u32,
    slow_starts: u32,
    unreached_ends: u32,
    panics: u32,
    /// When the life that runs began, and how long it took to be ready
    /// (running time).
    life_began: Option<Instant>,
    ready_after_ms: Option<u64>,
    /// Checks asked and answered, and how many answers reached the service.
    asked: u32,
    checks: u32,
    reached: u32,
    last_reached: Option<Instant>,
    /// The last answered check: whether it reached, how long it took in
    /// running time and on the wall clock, and the helper's fixed reason
    /// if it did not reach.
    last_check_reached: bool,
    last_check_ms: u64,
    last_check_wall_ms: u64,
    last_reason: String,
    /// Descriptor upload rounds, and over them the HSDirs that took it of
    /// those asked.
    upload_rounds: u32,
    uploads_ok: u32,
    uploads_of: u32,
    /// Error events of the helper, and the last one's fixed words.
    errors: u32,
    last_error: String,
}

/// Where a probe keeps what it saw (the process's one: [`book`]).
type Book = Mutex<Seen>;

fn book() -> &'static Book {
    static BOOK: OnceLock<Book> = OnceLock::new();
    BOOK.get_or_init(|| {
        Mutex::new(Seen {
            phase: "off",
            ..Seen::default()
        })
    })
}

fn note(book: &Book, change: impl FnOnce(&mut Seen)) {
    change(&mut book.lock().unwrap_or_else(PoisonError::into_inner));
}

fn read<T>(book: &Book, what: impl FnOnce(&Seen) -> T) -> T {
    what(&book.lock().unwrap_or_else(PoisonError::into_inner))
}

/// The process's one probe: how to stop it, and whether its thread lives
/// (it ends a moment after a stop).
#[derive(Default)]
struct Run {
    stop: Option<oneshot::Sender<()>>,
    running: bool,
}

fn run() -> std::sync::MutexGuard<'static, Run> {
    static RUN: OnceLock<Mutex<Run>> = OnceLock::new();
    RUN.get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Starts the probe with Tor's state under `state_dir` (made if it is not
/// there, for this user only) and a check every `check_every` of the wall
/// clock (at least [`CHECK_EVERY_MIN`]). A start while it runs does
/// nothing; one right after a [`stop`] is refused until the old life is
/// gone.
pub fn start(state_dir: &Path, check_every: Duration) -> Result<(), String> {
    let pace = Pace {
        first: super::watch::SELF_CHECK_FIRST,
        after_upload: super::watch::SELF_CHECK_AFTER_UPLOAD,
        every: check_every.max(CHECK_EVERY_MIN),
    };
    start_with(state_dir, pace, InProcess::find())
}

fn start_with(state_dir: &Path, pace: Pace, helper: InProcess) -> Result<(), String> {
    let mut run = run();
    if run.stop.is_some() {
        return Ok(());
    }
    if run.running {
        return Err("the probe is still stopping".into());
    }
    std::fs::create_dir_all(state_dir).map_err(|e| format!("the state folder ({})", e.kind()))?;
    super::restrict_dir(state_dir);
    let (stop, stopped) = oneshot::channel();
    let dir = state_dir.to_path_buf();
    note(book(), |s| {
        *s = Seen {
            phase: "starting",
            ..Seen::default()
        }
    });
    std::thread::Builder::new()
        .name("raven-watch-probe".into())
        .spawn(move || {
            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                runtime.block_on(supervise(dir, pace, helper, stopped, book()));
            }
            note(book(), |s| {
                if s.phase != "too_old" {
                    s.phase = "off";
                }
            });
            let mut run = self::run();
            run.running = false;
            run.stop = None;
        })
        .map_err(|e| {
            note(book(), |s| s.phase = "off");
            format!("the probe's thread ({})", e.kind())
        })?;
    run.stop = Some(stop);
    run.running = true;
    Ok(())
}

/// Stops the probe: the helper's life ends, and with it every circuit.
pub fn stop() {
    let stop = run().stop.take();
    if let Some(stop) = stop {
        let _ = stop.send(());
    }
}

/// What the probe saw, as one JSON object (the module's words). Times are
/// in ms; -1: not yet.
pub fn status() -> String {
    words(&read(book(), Seen::clone))
}

fn words(seen: &Seen) -> String {
    let ago = |at: Option<Instant>| at.map_or(-1, |t| t.elapsed().as_millis() as i64);
    serde_json::json!({
        "phase": seen.phase,
        "pct": seen.pct,
        "blocked": &seen.blocked,
        "service": &seen.service,
        "lives": seen.lives,
        "slow_starts": seen.slow_starts,
        "unreached_ends": seen.unreached_ends,
        "panics": seen.panics,
        "life_ms": ago(seen.life_began),
        "ready_after_ms": seen.ready_after_ms.map_or(-1, |v| v as i64),
        "asked": seen.asked,
        "checks": seen.checks,
        "reached": seen.reached,
        "last_reached_ms_ago": ago(seen.last_reached),
        "last_check_reached": seen.last_check_reached,
        "last_check_ms": seen.last_check_ms,
        "last_check_wall_ms": seen.last_check_wall_ms,
        "last_reason": &seen.last_reason,
        "upload_rounds": seen.upload_rounds,
        "uploads_ok": seen.uploads_ok,
        "uploads_of": seen.uploads_of,
        "errors": seen.errors,
        "last_error": &seen.last_error,
    })
    .to_string()
}

/// How a helper life ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// [`stop`].
    Stopped,
    /// By itself (Tor gave up, a panic).
    Gone,
    /// Not ready in [`READY_WAIT`].
    SlowStart,
    /// [`MISSES_END_A_LIFE`] checks in a row missed.
    Unreached,
    /// The Tor network takes this Arti no more: no further life.
    TooOld,
}

/// One helper life after the other until `stopped`.
async fn supervise(
    state_dir: PathBuf,
    pace: Pace,
    helper: InProcess,
    mut stopped: oneshot::Receiver<()>,
    book: &Book,
) {
    // The stand-in for raven-node's forward listener.
    let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await else {
        return note(book, |s| s.errors += 1);
    };
    let Ok(forward) = listener.local_addr() else {
        return note(book, |s| s.errors += 1);
    };
    tokio::spawn(async move {
        loop {
            // Taken and closed: nothing is served here.
            if listener.accept().await.is_err() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    });
    let mut pause = FIRST_PAUSE;
    let mut fresh_timeouts = false;
    loop {
        note(book, |s| {
            s.lives += 1;
            s.phase = "starting";
            s.pct = 0;
            s.blocked.clear();
            s.service.clear();
            s.life_began = Some(Instant::now());
            s.ready_after_ms = None;
        });
        let reached_before = read(book, |s| s.reached);
        let config = proto::Config {
            v: proto::PROTO_VERSION,
            state_dir: state_dir.to_string_lossy().into_owned(),
            token: hex::encode(rand::random::<[u8; proto::TOKEN_LEN]>()),
            forward: forward.to_string(),
            port: raven_core::onion::ONION_VIRTUAL_PORT,
            fresh_state: false,
            fresh_timeouts,
        };
        let ended = match helper.spawn() {
            Ok(proc) => life(proc, &config, pace, &mut stopped, book).await,
            Err(_) => {
                note(book, |s| s.errors += 1);
                Ended::Gone
            }
        };
        match ended {
            Ended::Stopped => return note(book, |s| s.phase = "ended"),
            Ended::TooOld => return note(book, |s| s.phase = "too_old"),
            Ended::SlowStart => note(book, |s| s.slow_starts += 1),
            Ended::Unreached => note(book, |s| s.unreached_ends += 1),
            Ended::Gone => {}
        }
        note(book, |s| s.phase = "ended");
        // What the old life learned about circuit times may be what kept
        // it from its relays or its service (raven-node does the same).
        fresh_timeouts = matches!(ended, Ended::SlowStart | Ended::Unreached);
        if read(book, |s| s.reached) > reached_before {
            pause = FIRST_PAUSE;
        }
        tokio::select! {
            _ = &mut stopped => return,
            () = tokio::time::sleep(pause) => {}
        }
        pause = (pause * 2).min(LONGEST_PAUSE);
    }
}

/// A check that is out: its number, and when it was asked in running time
/// and on the wall clock.
#[derive(Clone, Copy)]
struct Asked {
    n: u64,
    at: tokio::time::Instant,
    wall: SystemTime,
}

/// A check's time has come: `due` is reached, or lies further ahead than a
/// pace ever sets it (the wall clock was set back).
fn is_due(due: Option<SystemTime>, now: SystemTime, pace: Pace) -> bool {
    due.is_some_and(|at| match at.duration_since(now) {
        Ok(ahead) => ahead.is_zero() || ahead > pace.every.max(pace.first),
        Err(_) => true,
    })
}

/// A check ended: answered (`reached`, else with the helper's `reason`) or
/// given up.
fn checked(book: &Book, open: Asked, reached: bool, reason: String) {
    let ran = open.at.elapsed().as_millis() as u64;
    let wall = clock::now()
        .duration_since(open.wall)
        .map_or(0, |d| d.as_millis() as u64);
    note(book, |s| {
        s.checks += 1;
        s.last_check_reached = reached;
        s.last_check_ms = ran;
        s.last_check_wall_ms = wall;
        if reached {
            s.reached += 1;
            s.last_reached = Some(Instant::now());
            s.last_reason.clear();
        } else {
            s.last_reason = reason;
        }
    });
}

/// One life of the helper: its config line, its events, its checks.
async fn life(
    proc: Proc,
    config: &proto::Config,
    pace: Pace,
    stopped: &mut oneshot::Receiver<()>,
    book: &Book,
) -> Ended {
    let Proc {
        mut stdin,
        stdout,
        stderr,
        done,
        kill,
    } = proc;
    if stdin
        .write_all(proto::line(config).as_bytes())
        .await
        .is_err()
    {
        note(book, |s| s.errors += 1);
        return Ended::Gone;
    }
    // Running time, on the runtime's clock (the tests' stands still).
    let began = tokio::time::Instant::now();
    let mut events = LineReader::new(stdout);
    let mut second = tokio::time::interval(Duration::from_secs(1));
    second.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let slow = tokio::time::sleep(READY_WAIT);
    tokio::pin!(slow);
    let mut ready = false;
    // The checks asked in this life, the one that is out, the next one's
    // time on the wall clock, and the misses in a row.
    let mut asked = 0u64;
    let mut out: Option<Asked> = None;
    let mut due: Option<SystemTime> = None;
    let mut uploaded = false;
    let mut misses = 0u32;
    let ended = loop {
        tokio::select! {
            _ = &mut *stopped => break Ended::Stopped,
            () = &mut slow, if !ready => break Ended::SlowStart,
            line = events.next_line() => {
                let Some(line) = line else {
                    break Ended::Gone;
                };
                let Ok(event) = serde_json::from_str::<Event>(&line) else {
                    continue;
                };
                match event {
                    Event::Progress { pct, blocked, .. } => note(book, |s| {
                        s.pct = pct;
                        s.blocked = blocked.unwrap_or_default();
                        if !ready {
                            s.phase = "bootstrapping";
                        }
                    }),
                    Event::Ready { .. } => {
                        ready = true;
                        due = Some(clock::now() + pace.first);
                        note(book, |s| {
                            s.phase = "ready";
                            s.ready_after_ms = Some(began.elapsed().as_millis() as u64);
                        });
                    }
                    // The address stays in the helper.
                    Event::Onion { .. } | Event::Pong { .. } => {}
                    Event::Service { state, .. } => note(book, |s| s.service = state),
                    Event::Uploads { ok, of } => {
                        // The descriptor is out: the first check comes soon.
                        if ok > 0 && !uploaded && asked == 0 {
                            uploaded = true;
                            let soon = clock::now() + pace.after_upload;
                            due = Some(due.map_or(soon, |at| at.min(soon)));
                        }
                        note(book, |s| {
                            s.upload_rounds += 1;
                            s.uploads_ok += ok;
                            s.uploads_of += of;
                        });
                    }
                    Event::SelfCheck { n, reached, reason } => {
                        // Only the check that is out: not one given up, not
                        // one never asked.
                        let Some(open) = out.filter(|open| open.n == n) else {
                            continue;
                        };
                        out = None;
                        due = Some(clock::now() + pace.every);
                        misses = if reached { 0 } else { misses + 1 };
                        checked(book, open, reached, reason.unwrap_or_default());
                        if misses >= MISSES_END_A_LIFE {
                            break Ended::Unreached;
                        }
                    }
                    Event::Error { what, .. } => note(book, |s| {
                        s.errors += 1;
                        s.last_error = what;
                    }),
                }
            }
            // One check at a time, asked the first second this process runs
            // after it is due.
            _ = second.tick(), if ready => {
                let now = clock::now();
                match out {
                    Some(open) if open.at.elapsed() < CHECK_WAIT => {}
                    Some(open) => {
                        out = None;
                        due = Some(now + pace.every);
                        misses += 1;
                        checked(book, open, false, "no answer".into());
                        if misses >= MISSES_END_A_LIFE {
                            break Ended::Unreached;
                        }
                    }
                    None if is_due(due, now, pace) => {
                        asked += 1;
                        out = Some(Asked {
                            n: asked,
                            at: tokio::time::Instant::now(),
                            wall: now,
                        });
                        note(book, |s| s.asked += 1);
                        let cmd = proto::line(&Command::SelfCheck { n: asked });
                        if stdin.write_all(cmd.as_bytes()).await.is_err() {
                            break Ended::Gone;
                        }
                    }
                    None => {}
                }
            }
        }
    };
    // The helper's end: asked, then made, and waited for a moment (its
    // thread drops Tor's runtime, and with it every circuit and socket).
    let _ = stdin
        .write_all(proto::line(&Command::Stop).as_bytes())
        .await;
    if let Some(kill) = kill {
        let _ = kill.send(());
    }
    let _ = tokio::time::timeout(Duration::from_secs(3), done).await;
    if ended != Ended::Gone {
        return ended;
    }
    // What a life that went by itself left on its stderr.
    let mut words = String::new();
    if let Some(mut stderr) = stderr {
        let _ =
            tokio::time::timeout(Duration::from_secs(1), stderr.read_to_string(&mut words)).await;
    }
    if words.contains(super::arti::OBSOLETE_WORDS) {
        return Ended::TooOld;
    }
    if words.contains("panicked") {
        note(book, |s| s.panics += 1);
    }
    Ended::Gone
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen() -> serde_json::Value {
        serde_json::from_str(&status()).unwrap()
    }

    fn wait_for(what: &str, within: Duration, done: impl Fn(&serde_json::Value) -> bool) {
        let deadline = Instant::now() + within;
        while !done(&seen()) {
            assert!(Instant::now() < deadline, "{what}: {}", status());
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The probe with the lab's loopback helper in place of Tor: it comes
    /// ready, asks its checks one after the other by its pace, counts those
    /// that reached, and its status holds counts and fixed words and no
    /// address. A stop ends it, and it starts anew with its counts at zero.
    #[test]
    fn the_probe_runs_the_helper_alone_and_counts_its_checks() {
        let registry = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let helper = || InProcess::Loopback(registry.path().to_path_buf());
        let pace = Pace {
            first: Duration::from_millis(100),
            after_upload: Duration::from_millis(100),
            every: Duration::from_millis(300),
        };
        assert_eq!(seen()["phase"], "off");
        start_with(state.path(), pace, helper()).unwrap();
        // A second start while it runs changes nothing.
        start_with(state.path(), pace, helper()).unwrap();
        wait_for("two checks reached", Duration::from_secs(60), |s| {
            s["reached"].as_u64() >= Some(2)
        });
        let s = seen();
        let text = status();
        assert_eq!(s["phase"], "ready", "{text}");
        assert_eq!(s["lives"], 1, "{text}");
        assert_eq!(s["service"], "running", "{text}");
        assert!(s["ready_after_ms"].as_i64() >= Some(0), "{text}");
        assert_eq!(s["last_check_reached"], true, "{text}");
        assert!(s["last_reached_ms_ago"].as_i64() >= Some(0), "{text}");
        assert_eq!(s["checks"], s["reached"], "{text}");
        // Numbers and fixed words only: nothing as long as an onion key.
        assert!(!text.split('"').any(|part| part.len() >= 40), "{text}");
        // The loopback helper kept its "service" in the registry while it ran.
        assert_eq!(std::fs::read_dir(registry.path()).unwrap().count(), 1);

        stop();
        wait_for("off after a stop", Duration::from_secs(20), |s| {
            s["phase"] == "off"
        });
        assert_eq!(std::fs::read_dir(registry.path()).unwrap().count(), 0);

        start_with(state.path(), pace, helper()).unwrap();
        assert_eq!(seen()["checks"], 0);
        wait_for(
            "a check of the second start",
            Duration::from_secs(60),
            |s| s["reached"].as_u64() >= Some(1),
        );
        assert_eq!(seen()["lives"], 1);
        stop();
        wait_for("off after the second stop", Duration::from_secs(20), |s| {
            s["phase"] == "off"
        });
    }

    /// A helper as a test plays it: what the probe writes to it, and its
    /// own lines, stderr and end.
    struct Played {
        lines: LineReader,
        events: Pin<Box<dyn tokio::io::AsyncWrite + Send>>,
        stderr: tokio::io::DuplexStream,
        ended: oneshot::Sender<()>,
        killed: oneshot::Receiver<()>,
    }

    use std::pin::Pin;

    fn played() -> (Proc, Played) {
        let (probe_end, helper_end) = tokio::io::duplex(64 * 1024);
        let (probe_out, probe_in) = tokio::io::split(probe_end);
        let (helper_in, helper_out) = tokio::io::split(helper_end);
        let (stderr_probe, stderr_helper) = tokio::io::duplex(1024);
        let (kill, killed) = oneshot::channel();
        let (ended, done) = oneshot::channel::<()>();
        let proc = Proc {
            stdin: Box::pin(probe_in),
            stdout: Box::pin(probe_out),
            stderr: Some(Box::pin(stderr_probe)),
            done: Box::pin(async move {
                let _ = done.await;
            }),
            kill: Some(kill),
        };
        let played = Played {
            lines: LineReader::new(Box::pin(helper_in)),
            events: Box::pin(helper_out),
            stderr: stderr_helper,
            ended,
            killed,
        };
        (proc, played)
    }

    impl Played {
        async fn say(&mut self, event: &Event) {
            self.events
                .write_all(proto::line(event).as_bytes())
                .await
                .unwrap();
        }

        /// The probe's next line as a command.
        async fn command(&mut self) -> Command {
            let line = self.lines.next_line().await.expect("a line of the probe");
            serde_json::from_str(&line).expect("a command")
        }

        /// The config line read, and "ready" said.
        async fn ready(&mut self) -> proto::Config {
            let line = self.lines.next_line().await.expect("the config line");
            let config: proto::Config = serde_json::from_str(&line).expect("a config line");
            self.say(&Event::Ready {
                connect: "127.0.0.1:9".into(),
            })
            .await;
            config
        }
    }

    fn config() -> proto::Config {
        proto::Config {
            v: proto::PROTO_VERSION,
            state_dir: "/nonexistent/raven-watch-probe".into(),
            token: hex::encode([7u8; proto::TOKEN_LEN]),
            forward: "127.0.0.1:9".into(),
            port: raven_core::onion::ONION_VIRTUAL_PORT,
            fresh_state: false,
            fresh_timeouts: false,
        }
    }

    /// Checks at once and one right after the other.
    const AT_ONCE: Pace = Pace {
        first: Duration::ZERO,
        after_upload: Duration::ZERO,
        every: Duration::ZERO,
    };

    /// One life against a played helper: how it ended, and what the probe
    /// noted.
    async fn one_life<F, Fut>(pace: Pace, play: F) -> (Ended, Seen)
    where
        F: FnOnce(Played) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (proc, played) = played();
        let playing = tokio::spawn(play(played));
        let book = Book::default();
        let (_stop, mut stopped) = oneshot::channel();
        let ended = life(proc, &config(), pace, &mut stopped, &book).await;
        playing.await.expect("the played helper");
        (ended, read(&book, Seen::clone))
    }

    /// The helper's end as a played helper sees it: "stop" on its input,
    /// then the kill; and it goes.
    async fn goes_when_ended(mut played: Played) {
        assert_eq!(played.command().await, Command::Stop);
        played.killed.await.expect("the kill");
        let _ = played.ended.send(());
    }

    /// A helper that says nothing after its first progress is ended after
    /// [`READY_WAIT`] of running time, and asked no check.
    #[tokio::test(start_paused = true)]
    async fn a_life_that_is_not_ready_in_time_is_ended() {
        let began = tokio::time::Instant::now();
        let (ended, seen) = one_life(AT_ONCE, |mut played| async move {
            let line = played.lines.next_line().await.expect("the config line");
            let got: proto::Config = serde_json::from_str(&line).expect("a config line");
            assert_eq!(got, config());
            played
                .say(&Event::Progress {
                    pct: 10,
                    blocked: Some("no relays".into()),
                    stage: None,
                })
                .await;
            goes_when_ended(played).await;
        })
        .await;
        assert_eq!(ended, Ended::SlowStart);
        assert!(began.elapsed() >= READY_WAIT);
        assert_eq!(
            (seen.phase, seen.pct, seen.blocked.as_str()),
            ("bootstrapping", 10, "no relays")
        );
        assert_eq!((seen.asked, seen.checks), (0, 0));
    }

    /// Checks go one at a time; an answer that is not the open check's is
    /// not counted; [`MISSES_END_A_LIFE`] misses in a row end the life, and
    /// a check that reached in between starts the count anew.
    #[tokio::test(start_paused = true)]
    async fn checks_that_miss_in_a_row_end_a_life() {
        let (ended, seen) = one_life(AT_ONCE, |mut played| async move {
            played.ready().await;
            let answer = |n, reached: bool| Event::SelfCheck {
                n,
                reached,
                reason: (!reached).then(|| "no descriptor".to_string()),
            };
            let mut n = 0;
            // Two misses, one reached, then the misses that end it.
            for reached in [false, false, true, false, false, false, false] {
                n += 1;
                assert_eq!(played.command().await, Command::SelfCheck { n });
                // Not this check's answers: an old one, and one never asked.
                played.say(&answer(n - 1, true)).await;
                played.say(&answer(n + 5, true)).await;
                // No second check while this one is open.
                let more = tokio::time::timeout(Duration::from_secs(30), played.command()).await;
                assert!(more.is_err(), "a check beside check {n}");
                played.say(&answer(n, reached)).await;
            }
            goes_when_ended(played).await;
        })
        .await;
        assert_eq!(ended, Ended::Unreached);
        assert_eq!((seen.asked, seen.checks, seen.reached), (7, 7, 1));
        assert!(!seen.last_check_reached);
        assert_eq!(seen.last_reason, "no descriptor");
        // Each check was open for the 30 s the played helper waited.
        assert_eq!(seen.last_check_ms, 30_000);
    }

    /// A check the helper does not answer is given up after [`CHECK_WAIT`]
    /// of running time and counts as a miss; its late answer counts for
    /// nothing, and the next check is asked.
    #[tokio::test(start_paused = true)]
    async fn a_check_with_no_answer_is_given_up() {
        let (ended, seen) = one_life(AT_ONCE, |mut played| async move {
            played.ready().await;
            let began = tokio::time::Instant::now();
            assert_eq!(played.command().await, Command::SelfCheck { n: 1 });
            // No answer: the next check comes once the first is given up.
            assert_eq!(played.command().await, Command::SelfCheck { n: 2 });
            assert!(began.elapsed() >= CHECK_WAIT, "{:?}", began.elapsed());
            // The first one's answer, late.
            played
                .say(&Event::SelfCheck {
                    n: 1,
                    reached: true,
                    reason: None,
                })
                .await;
            played
                .say(&Event::SelfCheck {
                    n: 2,
                    reached: true,
                    reason: None,
                })
                .await;
            assert_eq!(played.command().await, Command::SelfCheck { n: 3 });
            let _ = played.ended.send(());
        })
        .await;
        assert_eq!(ended, Ended::Gone);
        // Check 1 given up, check 2 reached, check 3 still out.
        assert_eq!((seen.asked, seen.checks, seen.reached), (3, 2, 1));
        assert!(seen.last_check_reached);

        // Every check unanswered: the life ends as unreached.
        let (ended, seen) = one_life(AT_ONCE, |mut played| async move {
            played.ready().await;
            for n in 1..=u64::from(MISSES_END_A_LIFE) {
                assert_eq!(played.command().await, Command::SelfCheck { n });
            }
            goes_when_ended(played).await;
        })
        .await;
        assert_eq!(ended, Ended::Unreached);
        assert_eq!((seen.checks, seen.reached), (MISSES_END_A_LIFE, 0));
        assert_eq!(seen.last_reason, "no answer");
        assert_eq!(seen.last_check_ms, CHECK_WAIT.as_millis() as u64);
    }

    /// When a check is due by the wall clock.
    #[test]
    fn a_check_is_due_at_its_time_or_when_the_clock_was_set_back() {
        let pace = Pace {
            first: Duration::from_secs(180),
            after_upload: Duration::from_secs(45),
            every: Duration::from_secs(300),
        };
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert!(!is_due(None, now, pace));
        assert!(is_due(Some(now), now, pace));
        assert!(is_due(Some(now - Duration::from_secs(1)), now, pace));
        assert!(!is_due(Some(now + Duration::from_secs(1)), now, pace));
        assert!(!is_due(Some(now + pace.every), now, pace));
        // Further ahead than any pace sets it: the clock went back.
        assert!(is_due(
            Some(now + pace.every + Duration::from_secs(1)),
            now,
            pace
        ));
    }

    /// The first check waits for the pace's first time, or comes soon after
    /// the descriptor first reached an HSDir; upload rounds are counted.
    #[tokio::test(start_paused = true)]
    async fn the_first_check_comes_soon_after_the_descriptor_went_out() {
        let pace = Pace {
            first: Duration::from_secs(3600),
            after_upload: Duration::ZERO,
            every: Duration::from_secs(3600),
        };
        let (ended, seen) = one_life(pace, |mut played| async move {
            played.ready().await;
            // A round that reached no HSDir brings no check.
            played.say(&Event::Uploads { ok: 0, of: 8 }).await;
            let none = tokio::time::timeout(Duration::from_secs(120), played.command()).await;
            assert!(none.is_err(), "a check before the descriptor went out");
            played.say(&Event::Uploads { ok: 6, of: 8 }).await;
            assert_eq!(played.command().await, Command::SelfCheck { n: 1 });
            played
                .say(&Event::SelfCheck {
                    n: 1,
                    reached: true,
                    reason: None,
                })
                .await;
            // The next is an hour of the wall clock away: none comes.
            let none = tokio::time::timeout(Duration::from_secs(120), played.command()).await;
            assert!(none.is_err(), "a second check within the hour");
            // The helper goes by itself, with nothing on its stderr.
            let _ = played.ended.send(());
        })
        .await;
        assert_eq!(ended, Ended::Gone);
        assert_eq!((seen.asked, seen.checks, seen.reached), (1, 1, 1));
        assert_eq!(
            (seen.upload_rounds, seen.uploads_ok, seen.uploads_of),
            (2, 6, 16)
        );
        assert_eq!(seen.panics, 0);
    }

    /// What a helper that went by itself left on its stderr: a panic is
    /// counted, and "too old for the Tor network" ends the probe for good.
    #[tokio::test(start_paused = true)]
    async fn a_helper_that_goes_by_itself_says_why() {
        // No check is due in these lives.
        let pace = Pace {
            first: Duration::from_secs(3600),
            after_upload: Duration::from_secs(3600),
            every: Duration::from_secs(3600),
        };
        let (ended, seen) = one_life(pace, |mut played| async move {
            played.ready().await;
            played
                .say(&Event::Error {
                    what: "onion service ended".into(),
                    local: false,
                })
                .await;
            played
                .stderr
                .write_all(b"thread 'raven-tor' panicked at the in-process Tor helper\n")
                .await
                .unwrap();
            let _ = played.ended.send(());
        })
        .await;
        assert_eq!(ended, Ended::Gone);
        assert_eq!((seen.panics, seen.errors), (1, 1));
        assert_eq!(seen.last_error, "onion service ended");

        let (ended, seen) = one_life(pace, |mut played| async move {
            played.ready().await;
            let words = format!("{}\n", super::super::arti::OBSOLETE_WORDS);
            played.stderr.write_all(words.as_bytes()).await.unwrap();
            let _ = played.ended.send(());
        })
        .await;
        assert_eq!(ended, Ended::TooOld);
        assert_eq!(seen.panics, 0);
    }

    /// The status: every field a number, a yes or no, or a short word.
    #[test]
    fn the_status_is_counts_and_short_words() {
        let seen = Seen {
            phase: "ready",
            pct: 100,
            service: "running".into(),
            lives: 2,
            life_began: Some(Instant::now()),
            ready_after_ms: Some(4200),
            asked: 3,
            checks: 3,
            reached: 2,
            last_reached: Some(Instant::now()),
            last_check_ms: 5100,
            last_check_wall_ms: 61_000,
            last_reason: "tor timeout".into(),
            upload_rounds: 1,
            uploads_ok: 6,
            uploads_of: 8,
            ..Seen::default()
        };
        let got: serde_json::Value = serde_json::from_str(&words(&seen)).unwrap();
        let fields = got.as_object().unwrap();
        assert_eq!(fields.len(), 23);
        assert_eq!(got["phase"], "ready");
        assert_eq!(got["ready_after_ms"], 4200);
        assert_eq!(got["last_check_wall_ms"], 61_000);
        assert_eq!(got["last_reason"], "tor timeout");
        assert!(got["life_ms"].as_i64() >= Some(0));
        // Not yet: -1.
        let nothing: serde_json::Value = serde_json::from_str(&words(&Seen::default())).unwrap();
        assert_eq!(nothing["life_ms"], -1);
        assert_eq!(nothing["ready_after_ms"], -1);
        assert_eq!(nothing["last_reached_ms_ago"], -1);
    }
}
