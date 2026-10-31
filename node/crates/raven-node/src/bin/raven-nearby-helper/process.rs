//! raven-nearby-helper's process (macOS): `hello`, raven-node's commands
//! from stdin, the half-second tick, the lines to stdout, and the exit. The
//! CoreBluetooth side and the state machine are raven-node's own
//! (`nearby/apple/cb.rs` and `machine.rs`, included with `#[path]`), shared
//! with the iOS app's in-process radio.

use std::io::{self, Write};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use objc2::rc::autoreleasepool;

use crate::cb;
use crate::machine::Machine;
use crate::proto::{self, FromHelper, Power, ToHelper};

/// How often the machine's deadlines are checked.
const TICK: Duration = Duration::from_millis(500);
/// The exit code after a panic (raven-node reports the helper ended).
const PANICKED: i32 = 70;

/// Write lines to raven-node. A closed stdout means raven-node is gone.
fn say_all(lines: &[FromHelper]) {
    if lines.is_empty() {
        return;
    }
    let mut out = io::stdout().lock();
    let wrote = lines
        .iter()
        .try_for_each(|l| out.write_all(proto::line(l).as_bytes()))
        .and_then(|()| out.flush());
    if wrote.is_err() {
        std::process::exit(0);
    }
}

fn say(line: &FromHelper) {
    say_all(std::slice::from_ref(line));
}

/// After a panic the helper stops, as it always did.
fn exit_panicked() {
    eprintln!("raven-nearby-helper: internal error; stopping");
    std::process::exit(PANICKED);
}

/// The helper's life: its lines go to stdout.
struct Stdout;

impl cb::Sink for Stdout {
    fn say(&self, lines: Vec<FromHelper>) {
        say_all(&lines);
    }

    fn panicked(&self) {
        exit_panicked();
    }
}

/// The helper (see the module doc). Returns the exit code.
pub(crate) fn run(check_only: bool) -> i32 {
    if !cb::has_usage_description() {
        say(&FromHelper::State {
            state: Power::Unauthorized,
            detail: cb::NO_USAGE.to_owned(),
        });
        return 0;
    }
    say(&FromHelper::Hello { v: proto::VERSION });
    if check_only {
        return 0;
    }
    let Some(queue) = cb::queue(exit_panicked) else {
        eprintln!("raven-nearby-helper: no dispatch queue");
        return 1;
    };
    // The managers are made on the queue, and the life is in place before
    // their first callbacks (queued there) run.
    cb::run_sync(Box::new(move || {
        let os = cb::make(queue, cb::Options::default());
        *cb::STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(cb::Life {
            m: Machine::new(os),
            sink: Arc::new(Stdout),
            id: 0,
        });
    }));
    let _ = std::thread::Builder::new()
        .name("tick".into())
        .spawn(|| loop {
            std::thread::sleep(TICK);
            cb::post(Box::new(|| {
                cb::deliver(&cb::STATE, |life, now| {
                    autoreleasepool(|_| life.m.tick(now));
                });
            }));
        });
    let stdin = io::stdin();
    let mut r = stdin.lock();
    let mut buf = Vec::new();
    while let Ok(true) = proto::read_line(&mut r, &mut buf) {
        if let Some(cmd) = proto::parse::<ToHelper>(&buf) {
            cb::post(Box::new(move || {
                cb::deliver(&cb::STATE, move |life, now| {
                    autoreleasepool(|_| life.m.command(cmd, now));
                });
            }));
        }
    }
    // raven-node is gone or let go of the radio.
    cb::run_sync(Box::new(|| {
        cb::deliver(&cb::STATE, |life, _| autoreleasepool(|_| life.m.stop()));
    }));
    0
}
