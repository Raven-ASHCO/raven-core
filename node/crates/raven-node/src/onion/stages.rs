//! The stage record of onion dials (speed groundwork for the D1
//! measurement, design `docs/design/2026-10-tor-fallback.md` §3.9): for
//! each onion dial, how long each of its steps took. Durations only: never
//! a key, an onion id, an address or a message, so a record says how slow
//! a dial was and nothing about whom it reached or what it carried.
//!
//! **Debug builds only.** A release build marks nothing and keeps nothing
//! ([`timed`] runs the dial alone), so it behaves exactly as before.
//!
//! **The steps,** as the dialer sees them ([`Record`]):
//! - `prep`: from the dial's start until its connect request goes to the
//!   Tor helper (the contact checks, waiting for a ready Tor, this node's
//!   identity and offer loaded);
//! - `connect`: the helper's connect, until its reply: Tor gets a circuit
//!   to the friend's onion service (a rendezvous when none is kept), then
//!   opens the stream on it (BEGIN, then CONNECTED);
//! - `circuit` and `begin`: `connect` in two. Arti does both inside one
//!   call (`TorClient::connect_with_prefs`) and tells neither apart, so the
//!   split follows the one round trip rule: BEGIN to CONNECTED is one round
//!   trip on the circuit, as long as the Noise round trip right after it on
//!   the same circuit (`begin = min(noise, connect)`), and the rest of
//!   `connect` is getting the circuit. A measured split needs a timing hook
//!   inside Arti (a change to its fork).
//! - `noise`: Noise message 1 written, message 2 read (one round trip);
//! - `hello`: message 3 and our hello written, the friend's hello verified
//!   (one round trip; its RLB1 offer comes in the same flight);
//! - `write`: from the friend's hello until our frames are written (the
//!   offers, their checks, the writes: local work);
//! - `receipt`: from the frames written until the first terminal reply,
//!   the friend's signed ACK (one round trip).
//!
//! **Where it is read:** [`recent`] (this process's last [`KEPT`] records),
//! and, in a debug build with `RAVEN_LAB_TEST_A=1`, the lab file
//! [`STAGES_ENV`] (an absolute path): one JSON line per dial, appended
//! (0600). The D1 harness `scripts/tor_d1_harness.py` sets it for the
//! sender of its two lab profiles and takes the lines each send adds as
//! that send's stage times, next to its D1 (its dry mode runs over the
//! loopback helper's warm circuit model; its real mode starts only with the
//! owner's OK). A test sees its own dials' records through `caught`.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
use tokio::time::Instant;

/// Debug builds with `RAVEN_LAB_TEST_A=1`: append every record to this
/// file (an absolute path), one JSON line each.
pub(crate) const STAGES_ENV: &str = "RAVEN_LAB_TOR_STAGES";
/// How many records [`recent`] keeps.
const KEPT: usize = 64;

/// The end of one step of a dial ([`mark`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The connect request is about to go to the helper (a new attempt:
    /// everything marked before it is from an attempt given up).
    Asked,
    /// The helper said the Tor stream is open.
    Connected,
    /// Noise message 2 was read.
    Noise,
    /// The friend's hello was verified.
    Hello,
    /// Our frames were written.
    Written,
    /// The first terminal reply was read.
    Receipt,
}

/// When each step of the running dial ended.
#[derive(Clone, Copy, Debug, Default)]
struct Marks {
    asked: Option<Instant>,
    connected: Option<Instant>,
    noise: Option<Instant>,
    hello: Option<Instant>,
    written: Option<Instant>,
    receipt: Option<Instant>,
}

tokio::task_local! {
    /// The marks of the onion dial this task runs ([`timed`]).
    static MARKS: Arc<Mutex<Marks>>;
}

/// `step` ended now, in the onion dial this task runs ([`timed`]); nothing
/// anywhere else (the other carriers share the code that marks) and
/// nothing in a release build.
pub(crate) fn mark(step: Step) {
    if !cfg!(debug_assertions) {
        return;
    }
    let _ = MARKS.try_with(|marks| {
        let now = Instant::now();
        let mut m = marks.lock().unwrap_or_else(PoisonError::into_inner);
        match step {
            // A handshake retried on a fresh stream starts over.
            Step::Asked => {
                *m = Marks {
                    asked: Some(now),
                    ..Marks::default()
                }
            }
            Step::Connected => m.connected = Some(now),
            Step::Noise => m.noise = Some(now),
            Step::Hello => m.hello = Some(now),
            Step::Written => m.written = Some(now),
            Step::Receipt => {
                m.receipt.get_or_insert(now);
            }
        }
    });
}

/// What an onion dial was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Purpose {
    /// A send's check: no frames, asked over IPC.
    Check,
    /// The outbox's dial in its race.
    Outbox,
    /// Any other dial (a send's message dial is one, with frames).
    Dial,
}

/// One onion dial's stage times, in ms (see the module doc). A step the
/// dial never reached is `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Record {
    pub(crate) purpose: Purpose,
    /// How many frames it carried (a count).
    pub(crate) frames: u32,
    /// It ended without an error.
    pub(crate) ok: bool,
    pub(crate) prep_ms: Option<u32>,
    pub(crate) connect_ms: Option<u32>,
    pub(crate) circuit_ms: Option<u32>,
    pub(crate) begin_ms: Option<u32>,
    pub(crate) noise_ms: Option<u32>,
    pub(crate) hello_ms: Option<u32>,
    pub(crate) write_ms: Option<u32>,
    pub(crate) receipt_ms: Option<u32>,
    pub(crate) total_ms: u32,
}

fn ms(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

impl Record {
    /// The record of a dial that began at `began` and ended at `ended`.
    fn new(
        purpose: Purpose,
        frames: usize,
        ok: bool,
        began: Instant,
        m: &Marks,
        ended: Instant,
    ) -> Self {
        let span = |from: Option<Instant>, to: Option<Instant>| {
            Some(ms(to?.saturating_duration_since(from?)))
        };
        let connect = span(m.asked, m.connected);
        let noise = span(m.connected, m.noise);
        let begin = connect.zip(noise).map(|(c, n)| c.min(n));
        Self {
            purpose,
            frames: u32::try_from(frames).unwrap_or(u32::MAX),
            ok,
            prep_ms: span(Some(began), m.asked),
            connect_ms: connect,
            circuit_ms: connect.zip(begin).map(|(c, b)| c - b),
            begin_ms: begin,
            noise_ms: noise,
            hello_ms: span(m.noise, m.hello),
            write_ms: span(m.hello, m.written),
            receipt_ms: span(m.written, m.receipt),
            total_ms: ms(ended.saturating_duration_since(began)),
        }
    }
}

/// The records kept ([`KEPT`] at most, oldest first).
static RECENT: Mutex<VecDeque<Record>> = Mutex::new(VecDeque::new());

/// Runs the onion dial `dial` with its steps marked ([`mark`]) and keeps
/// its record ([`recent`], the lab file). A release build runs `dial`
/// alone.
pub(crate) async fn timed<T, F>(purpose: Purpose, frames: usize, dial: F) -> Result<T, String>
where
    F: Future<Output = Result<T, String>>,
{
    if !cfg!(debug_assertions) {
        return dial.await;
    }
    let began = Instant::now();
    let marks = Arc::new(Mutex::new(Marks::default()));
    let out = MARKS.scope(Arc::clone(&marks), dial).await;
    let m = *marks.lock().unwrap_or_else(PoisonError::into_inner);
    keep(Record::new(
        purpose,
        frames,
        out.is_ok(),
        began,
        &m,
        Instant::now(),
    ));
    out
}

fn keep(record: Record) {
    #[cfg(test)]
    let _ = CAUGHT.try_with(|caught| {
        caught
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record.clone());
    });
    if let Some(path) = lab_file() {
        append(&path, &record);
    }
    let mut recent = RECENT.lock().unwrap_or_else(PoisonError::into_inner);
    if recent.len() == KEPT {
        recent.pop_front();
    }
    recent.push_back(record);
}

/// The lab file ([`STAGES_ENV`]): a debug build with `RAVEN_LAB_TEST_A=1`
/// and an absolute path only.
fn lab_file() -> Option<PathBuf> {
    lab_file_with(raven_core::pair_init::lab_test_a_enabled, || {
        std::env::var_os(STAGES_ENV)
    })
}

/// [`lab_file`]'s rule: the variable (`value`) is read only when
/// `lab_test_a` (false in every release build), and only an absolute path
/// counts.
fn lab_file_with(
    lab_test_a: impl FnOnce() -> bool,
    value: impl FnOnce() -> Option<OsString>,
) -> Option<PathBuf> {
    if !lab_test_a() {
        return None;
    }
    let path = PathBuf::from(value()?);
    path.is_absolute().then_some(path)
}

/// `record` as one JSON line at the end of `path` (made private to this
/// user); a failure loses the line, never the dial.
fn append(path: &Path, record: &Record) {
    use std::io::Write;
    let Ok(mut line) = serde_json::to_vec(record) else {
        return;
    };
    line.push(b'\n');
    let mut open = std::fs::OpenOptions::new();
    open.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut open, 0o600);
    if let Ok(mut file) = open.open(path) {
        let _ = file.write_all(&line);
    }
}

/// This process's last records, oldest first (empty in a release build).
/// Only tests read them so far; a debug reader may come later.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn recent() -> Vec<Record> {
    RECENT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .cloned()
        .collect()
}

#[cfg(test)]
tokio::task_local! {
    /// A test's own records ([`caught`]).
    static CAUGHT: Arc<Mutex<Vec<Record>>>;
}

/// Runs `work` and returns, beside its output, the records of the onion
/// dials it ran itself (never those of a test running beside it).
#[cfg(test)]
pub(crate) async fn caught<F: Future>(work: F) -> (F::Output, Vec<Record>) {
    let records = Arc::new(Mutex::new(Vec::new()));
    let out = CAUGHT.scope(Arc::clone(&records), work).await;
    let records = std::mem::take(&mut *records.lock().unwrap_or_else(PoisonError::into_inner));
    (out, records)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The split of a dial's connect follows the one round trip rule, every
    /// span runs from the step before, and a step never reached is `None`.
    #[test]
    fn a_record_splits_connect_by_the_noise_round_trip() {
        let t = Instant::now();
        let at = |ms: u64| Some(t + Duration::from_millis(ms));
        let m = Marks {
            asked: at(20),
            connected: at(3_420),
            noise: at(3_820),
            hello: at(4_230),
            written: at(4_260),
            receipt: at(4_660),
        };
        let r = Record::new(
            Purpose::Dial,
            1,
            true,
            t,
            &m,
            t + Duration::from_millis(4_700),
        );
        assert_eq!(r.prep_ms, Some(20));
        assert_eq!(r.connect_ms, Some(3_400));
        assert_eq!(r.noise_ms, Some(400));
        assert_eq!((r.circuit_ms, r.begin_ms), (Some(3_000), Some(400)));
        assert_eq!(r.hello_ms, Some(410));
        assert_eq!(r.write_ms, Some(30));
        assert_eq!(r.receipt_ms, Some(400));
        assert_eq!(r.total_ms, 4_700);
        // A warm circuit: connect is one round trip, nothing to build.
        let warm = Marks {
            connected: at(420),
            noise: at(830),
            ..m
        };
        let r = Record::new(
            Purpose::Check,
            0,
            true,
            t,
            &warm,
            t + Duration::from_millis(900),
        );
        assert_eq!((r.circuit_ms, r.begin_ms), (Some(0), Some(400)));
        // A dial that never got a stream: no step after prep.
        let failed = Marks {
            asked: at(5),
            ..Marks::default()
        };
        let r = Record::new(
            Purpose::Outbox,
            2,
            false,
            t,
            &failed,
            t + Duration::from_millis(9),
        );
        assert_eq!(r.prep_ms, Some(5));
        assert_eq!(
            (
                r.connect_ms,
                r.circuit_ms,
                r.begin_ms,
                r.noise_ms,
                r.receipt_ms
            ),
            (None, None, None, None, None)
        );
    }

    /// Durations only: a record's JSON line has numbers, a purpose word and
    /// a flag, nothing else.
    #[test]
    fn a_record_line_holds_durations_only() {
        let t = Instant::now();
        let r = Record::new(Purpose::Check, 0, true, t, &Marks::default(), t);
        let v: serde_json::Value = serde_json::to_value(&r).unwrap();
        let obj = v.as_object().unwrap();
        for (k, v) in obj {
            match k.as_str() {
                "purpose" => assert_eq!(v, "check"),
                "ok" => assert!(v.is_boolean()),
                _ => assert!(v.is_null() || v.is_u64(), "{k}: {v}"),
            }
        }
    }

    /// A mark outside an onion dial's scope reaches no record; the dial's
    /// own marks make its record. Runs in both builds: a release build marks
    /// nothing and keeps nothing (the dial runs alone).
    #[tokio::test]
    async fn marks_outside_a_timed_dial_are_ignored_and_release_keeps_none() {
        let (out, kept) = caught(async {
            mark(Step::Noise);
            let out: Result<u8, String> = timed(Purpose::Dial, 1, async {
                mark(Step::Asked);
                mark(Step::Connected);
                Ok(7)
            })
            .await;
            mark(Step::Hello);
            out
        })
        .await;
        assert_eq!(out, Ok(7));
        if !cfg!(debug_assertions) {
            assert_eq!(kept, Vec::new(), "a release build keeps nothing");
            return;
        }
        assert_eq!(kept.len(), 1, "{kept:?}");
        let ours = &kept[0];
        assert!(ours.ok && ours.connect_ms.is_some(), "{ours:?}");
        assert_eq!((ours.noise_ms, ours.hello_ms), (None, None), "{ours:?}");
        assert!(recent().contains(ours), "kept for this process too");
    }

    /// The lab file: read only in a lab run and only as an absolute path;
    /// each record is one JSON line appended, the file private to this user.
    #[test]
    fn the_lab_file_takes_one_private_line_per_record() {
        let never = || -> Option<OsString> { panic!("read outside a lab run") };
        assert_eq!(lab_file_with(|| false, never), None);
        assert_eq!(lab_file_with(|| true, || None), None);
        assert_eq!(lab_file_with(|| true, || Some("stages.jsonl".into())), None);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stages.jsonl");
        let value = path.clone().into_os_string();
        assert_eq!(lab_file_with(|| true, || Some(value)), Some(path.clone()));
        let t = Instant::now();
        let r = Record::new(Purpose::Outbox, 2, false, t, &Marks::default(), t);
        append(&path, &r);
        append(&path, &r);
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines, vec![serde_json::to_value(&r).unwrap(); 2]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
