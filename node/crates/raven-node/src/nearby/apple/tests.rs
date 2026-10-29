//! The macOS backend's raven-node side with no radio: the helper protocol,
//! finding the helper, the back-off, and the radio over a scripted helper
//! (pipes; on Unix also small shell helpers and, when it was built, the real
//! raven-nearby-helper outside its bundle, which never creates a
//! CoreBluetooth manager).

use std::io::{BufReader, PipeReader, PipeWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use raven_core::nearby_link::{char_uuid, Role};
use tokio::sync::mpsc;

use super::proto::{self, FromHelper, Gatt, Power, Side, ToHelper};
use super::*;
use crate::nearby::radio::{Privacy, Radio, RadioAddr, RadioEvent, RadioState, Sent, EVENT_QUEUE};

/// RNL1 vector token (rnb1_tokens_001.json, alice).
const T: [u8; 16] = [
    0x06, 0x2a, 0x8a, 0xc6, 0x9e, 0x02, 0x4a, 0xbb, 0xab, 0x83, 0xf9, 0xea, 0xbb, 0x5e, 0x8d, 0x99,
];
/// A helper device handle (placeholder).
const DEV: &str = "00112233445566778899aabbccddeeff";
const WAIT: Duration = Duration::from_secs(5);

// ── The protocol ────────────────────────────────────────────────────────────

/// Every message survives a line each way, under the names the helper and
/// raven-node agree on (the helper compiles this same file).
#[test]
fn the_helper_protocol_round_trips() {
    let to = [
        ToHelper::Services {
            services: vec![Gatt {
                service: proto::uuid_hex(&T),
                characteristic: proto::uuid_hex(&char_uuid(&T)),
            }],
            advertise: Some(proto::uuid_hex(&T)),
        },
        ToHelper::Services {
            services: vec![],
            advertise: None,
        },
        ToHelper::Scan { on: true },
        ToHelper::Connect {
            conn: 1,
            dev: DEV.into(),
            service: proto::uuid_hex(&T),
            characteristic: proto::uuid_hex(&char_uuid(&T)),
        },
        ToHelper::Send {
            conn: 3,
            b64: proto::b64_of(&[0x11, 0, 1]),
        },
        ToHelper::Disconnect { conn: 2 },
    ];
    for m in to {
        let l = proto::line(&m);
        assert!(l.ends_with('\n') && !l[..l.len() - 1].contains('\n'), "{l}");
        assert_eq!(proto::parse::<ToHelper>(l.as_bytes()), Some(m));
    }
    let from = [
        FromHelper::Hello { v: proto::VERSION },
        FromHelper::State {
            state: Power::Unauthorized,
            detail: "why".into(),
        },
        FromHelper::State {
            state: Power::On,
            detail: String::new(),
        },
        FromHelper::Seen {
            dev: DEV.into(),
            uuids: vec![proto::uuid_hex(&T)],
            rssi: -61,
        },
        FromHelper::Connected {
            conn: 2,
            role: Side::Peripheral,
            service: proto::uuid_hex(&T),
            max_tx: 182,
            max_rx: 182,
        },
        FromHelper::Frame {
            conn: 1,
            b64: proto::b64_of(&[0x12]),
        },
        FromHelper::Sent { conn: 1 },
        FromHelper::Disconnected { conn: 1 },
    ];
    for m in from {
        assert_eq!(
            proto::parse::<FromHelper>(proto::line(&m).as_bytes()),
            Some(m)
        );
    }
    // The wire's names.
    assert_eq!(
        proto::line(&ToHelper::Scan { on: false }),
        "{\"cmd\":\"scan\",\"on\":false}\n"
    );
    assert_eq!(
        proto::parse::<FromHelper>(br#"{"ev":"state","state":"off"}"#),
        Some(FromHelper::State {
            state: Power::Off,
            detail: String::new()
        })
    );
    assert_eq!(
        proto::parse::<FromHelper>(br#"{"ev":"connected","conn":1,"role":"central","service":"00","max_tx":20,"max_rx":20}"#),
        Some(FromHelper::Connected {
            conn: 1,
            role: Side::Central,
            service: "00".into(),
            max_tx: 20,
            max_rx: 20
        })
    );
    assert_eq!(
        proto::parse::<FromHelper>(br#"{"ev":"state","state":"maybe"}"#),
        None
    );
    assert_eq!(proto::parse::<ToHelper>(b"not json"), None);
}

/// UUIDs are exactly 32 hex digits in RNL1 byte order (§2); frames are 1
/// to 512 bytes of base64.
#[test]
fn uuids_and_frames_on_the_wire() {
    assert_eq!(proto::uuid_hex(&T), "062a8ac69e024abbab83f9eabb5e8d99");
    assert_eq!(
        proto::uuid_from("062a8ac69e024abbab83f9eabb5e8d99"),
        Some(T)
    );
    assert_eq!(
        proto::uuid_from("062A8AC69E024ABBAB83F9EABB5E8D99"),
        Some(T)
    );
    assert_eq!(
        proto::uuid_from("062a8ac6-9e02-4abb-ab83-f9eabb5e8d99"),
        None
    );
    assert_eq!(proto::uuid_from("062a"), None);
    let max = vec![7u8; proto::MAX_FRAME];
    assert_eq!(proto::frame_from(&proto::b64_of(&max)), Some(max));
    assert_eq!(
        proto::frame_from(&proto::b64_of(&[7; proto::MAX_FRAME + 1])),
        None
    );
    assert_eq!(proto::frame_from(""), None);
    assert_eq!(proto::frame_from("!!"), None);
}

/// A line over MAX_LINE is skipped whole; the next one reads.
#[test]
fn an_overlong_line_is_skipped() {
    let mut input = vec![b'x'; proto::MAX_LINE + 10];
    input.push(b'\n');
    input.extend_from_slice(b"{\"cmd\":\"scan\",\"on\":true}\n");
    let mut r = BufReader::with_capacity(64, &input[..]);
    let mut buf = Vec::new();
    assert!(proto::read_line(&mut r, &mut buf).unwrap());
    assert_eq!(proto::parse::<ToHelper>(&buf), None);
    assert!(proto::read_line(&mut r, &mut buf).unwrap());
    assert_eq!(
        proto::parse::<ToHelper>(&buf),
        Some(ToHelper::Scan { on: true })
    );
    assert!(!proto::read_line(&mut r, &mut buf).unwrap());
}

#[test]
fn the_radio_is_both_roles_from_a_random_address() {
    assert_eq!(
        caps(),
        RadioCaps {
            central: true,
            peripheral: true,
            l2cap: false,
            address_privacy: Privacy::Random,
            per_central_notify: true,
        }
    );
}

// ── Finding the helper and the back-off ─────────────────────────────────────

#[test]
fn the_helper_is_found_by_its_setting_beside_raven_node_or_installed() {
    let home = PathBuf::from("/x/home");
    let bin = PathBuf::from("/opt/raven/bin");
    let beside = bin.join("RavenNearby.app/Contents/MacOS/raven-nearby-helper");
    let installed = home.join(
        "Library/Application Support/Raven/RavenNearby.app/Contents/MacOS/raven-nearby-helper",
    );
    let all = |_: &Path| true;
    assert_eq!(
        find_helper(None, Some(bin.clone()), Some(home.clone()), all),
        Some(beside.clone())
    );
    let only = |want: PathBuf| move |p: &Path| p == want;
    assert_eq!(
        find_helper(
            None,
            Some(bin.clone()),
            Some(home.clone()),
            only(installed.clone())
        ),
        Some(installed)
    );
    assert_eq!(
        find_helper(None, Some(bin.clone()), Some(home.clone()), |_: &Path| {
            false
        }),
        None
    );
    // The setting alone, when set: the helper or its bundle, absolute only. The temp folder is
    // absolute on every OS ("/x/..." has no drive letter, so it is not absolute on Windows).
    let abs = std::env::temp_dir().join("x");
    let set = abs.join("RavenNearby.app");
    assert_eq!(
        find_helper(
            Some(set.clone()),
            Some(bin.clone()),
            Some(home.clone()),
            all
        ),
        Some(executable_in(&set))
    );
    let exe = abs.join("raven-nearby-helper");
    assert_eq!(
        find_helper(Some(exe.clone()), None, None, all),
        Some(exe.clone())
    );
    assert_eq!(
        find_helper(Some(exe), Some(bin.clone()), None, only(beside)),
        None,
        "nothing else is tried"
    );
    assert_eq!(
        find_helper(Some(PathBuf::from("rel/helper")), Some(bin), None, all),
        None
    );
    assert_eq!(helper_path(), None, "a test build never looks");
}

/// Each failure doubles the wait (up to the cap), during which the open
/// answers the last failure without starting anything; a radio that came
/// up resets it.
#[test]
fn the_back_off_doubles_and_resets() {
    let now = Instant::now();
    let mut b = Backoff::default();
    assert_eq!(b.check(now), Ok(()));
    let why = RadioState::Unauthorized("no".into());
    b.failed(now, why.clone());
    assert_eq!(
        b.check(now + BACKOFF_FIRST - Duration::from_secs(1)),
        Err(why.clone())
    );
    assert_eq!(b.check(now + BACKOFF_FIRST), Ok(()));
    b.failed(now, why.clone());
    assert_eq!(
        b.check(now + BACKOFF_FIRST * 2 - Duration::from_secs(1)),
        Err(why.clone())
    );
    for _ in 0..40 {
        b.failed(now, why.clone());
    }
    assert_eq!(b.check(now + BACKOFF_MAX), Ok(()), "capped");
    b.healthy();
    assert_eq!(b.check(now), Ok(()));
}

/// What a helper that ended means: SIGABRT (macOS refusing Bluetooth) is
/// Unauthorized and says where to allow it; anything else is Unsupported.
#[test]
fn a_helper_that_ended_says_why() {
    assert_eq!(
        ended_state(None),
        RadioState::Unsupported("the nearby helper ended".into())
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::ExitStatus;
        match ended_state(Some(ExitStatus::from_raw(libc::SIGABRT))) {
            RadioState::Unauthorized(why) => {
                assert!(why.contains("Privacy & Security > Bluetooth"), "{why}")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            ended_state(Some(ExitStatus::from_raw(libc::SIGKILL))),
            RadioState::Unsupported(format!(
                "the nearby helper was stopped by signal {}",
                libc::SIGKILL
            ))
        );
        assert_eq!(
            ended_state(Some(ExitStatus::from_raw(3 << 8))),
            RadioState::Unsupported("the nearby helper ended (exit 3)".into())
        );
    }
}

// ── The radio over a scripted helper ────────────────────────────────────────

/// The helper's ends of the two pipes.
struct FakeHelper {
    heard: std::sync::mpsc::Receiver<Option<ToHelper>>,
    to_node: Option<PipeWriter>,
}

impl FakeHelper {
    fn new(from_node: PipeReader, to_node: PipeWriter) -> Self {
        let (tx, heard) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut r = BufReader::new(from_node);
            let mut buf = Vec::new();
            while let Ok(true) = proto::read_line(&mut r, &mut buf) {
                if tx.send(proto::parse::<ToHelper>(&buf)).is_err() {
                    return;
                }
            }
        });
        Self {
            heard,
            to_node: Some(to_node),
        }
    }

    fn raw(&mut self, l: &str) {
        let w = self.to_node.as_mut().unwrap();
        w.write_all(l.as_bytes()).unwrap();
        w.flush().unwrap();
    }

    fn say(&mut self, m: &FromHelper) {
        self.raw(&proto::line(m));
    }

    /// The next line raven-node wrote.
    fn heard(&self) -> ToHelper {
        self.heard
            .recv_timeout(WAIT)
            .expect("a line from raven-node")
            .expect("a line that parses")
    }

    /// raven-node closed the helper's stdin.
    fn input_closed(&self) -> bool {
        matches!(
            self.heard.recv_timeout(WAIT),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        )
    }
}

fn pipes(
    hello: Option<&str>,
    queue: usize,
) -> (
    FakeHelper,
    Result<HelperRadio, RadioState>,
    mpsc::Receiver<RadioEvent>,
    Arc<Mutex<Backoff>>,
) {
    let (from_node, node_w) = std::io::pipe().unwrap();
    let (node_r, to_node) = std::io::pipe().unwrap();
    let mut helper = FakeHelper::new(from_node, to_node);
    if let Some(l) = hello {
        helper.raw(l);
    }
    let (tx, rx) = mpsc::channel(queue);
    let backoff = Arc::new(Mutex::new(Backoff::default()));
    let radio = start(
        node_w,
        node_r,
        None,
        tx,
        Some(Arc::clone(&backoff)),
        Duration::from_millis(500),
    );
    (helper, radio, rx, backoff)
}

fn hello() -> String {
    proto::line(&FromHelper::Hello { v: proto::VERSION })
}

fn next(rx: &mut mpsc::Receiver<RadioEvent>) -> RadioEvent {
    let until = Instant::now() + WAIT;
    loop {
        match rx.try_recv() {
            Ok(ev) => return ev,
            Err(mpsc::error::TryRecvError::Empty) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) => panic!("no event: {e:?}"),
        }
    }
}

/// The queue closed: no sender is left.
fn closed(rx: &mut mpsc::Receiver<RadioEvent>) -> bool {
    let until = Instant::now() + WAIT;
    loop {
        match rx.try_recv() {
            Err(mpsc::error::TryRecvError::Disconnected) => return true,
            Err(mpsc::error::TryRecvError::Empty) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(5))
            }
            _ => return false,
        }
    }
}

/// A connected central link: (conn, its wire number).
fn central_link(
    radio: &mut HelperRadio,
    helper: &mut FakeHelper,
    rx: &mut mpsc::Receiver<RadioEvent>,
    max_tx: usize,
) -> ConnId {
    let conn = radio.connect(&RadioAddr(DEV.into()), T).unwrap();
    assert!(matches!(helper.heard(), ToHelper::Connect { .. }));
    helper.say(&FromHelper::Connected {
        conn: conn & WIRE_MASK,
        role: Side::Central,
        service: proto::uuid_hex(&T),
        max_tx,
        max_rx: max_tx,
    });
    assert!(matches!(next(rx), RadioEvent::Connected { .. }));
    conn
}

/// The radio speaks the protocol: services carry their characteristic
/// (raven-node derives it), connects are odd, and the helper's lines become
/// the radio's events.
#[test]
fn a_helper_that_says_hello_is_a_radio() {
    let (mut helper, radio, mut rx, _) = pipes(Some(&hello()), EVENT_QUEUE);
    let mut radio = radio.unwrap();
    radio.set_services(&[T], Some(T)).unwrap();
    assert_eq!(
        helper.heard(),
        ToHelper::Services {
            services: vec![Gatt {
                service: proto::uuid_hex(&T),
                characteristic: proto::uuid_hex(&char_uuid(&T)),
            }],
            advertise: Some(proto::uuid_hex(&T)),
        }
    );
    assert!(
        radio.set_services(&[], Some(T)).is_err(),
        "advertised, not published"
    );
    radio.set_scanning(true).unwrap();
    assert_eq!(helper.heard(), ToHelper::Scan { on: true });
    helper.say(&FromHelper::State {
        state: Power::On,
        detail: String::new(),
    });
    assert_eq!(next(&mut rx), RadioEvent::State(RadioState::PoweredOn));
    helper.say(&FromHelper::Seen {
        dev: DEV.into(),
        uuids: vec![proto::uuid_hex(&T)],
        rssi: -55,
    });
    assert_eq!(
        next(&mut rx),
        RadioEvent::Seen {
            addr: RadioAddr(DEV.into()),
            uuids: vec![T],
            rssi: -55,
        }
    );
    let c1 = radio.connect(&RadioAddr(DEV.into()), T).unwrap();
    let c3 = radio.connect(&RadioAddr(DEV.into()), T).unwrap();
    assert_eq!((c1 & WIRE_MASK, c3 & WIRE_MASK), (1, 3));
    assert_eq!(c1 >> 32, c3 >> 32);
    assert_eq!(
        helper.heard(),
        ToHelper::Connect {
            conn: 1,
            dev: DEV.into(),
            service: proto::uuid_hex(&T),
            characteristic: proto::uuid_hex(&char_uuid(&T)),
        }
    );
    helper.heard();
    assert!(radio.send(c1, &[1]).is_err(), "not connected yet");
    helper.say(&FromHelper::Connected {
        conn: 1,
        role: Side::Central,
        service: proto::uuid_hex(&T),
        max_tx: 182,
        max_rx: 182,
    });
    assert_eq!(
        next(&mut rx),
        RadioEvent::Connected {
            conn: c1,
            role: Role::Central,
            service: T,
            max_tx: 182,
            max_rx: 182,
        }
    );
    helper.say(&FromHelper::Frame {
        conn: 1,
        b64: proto::b64_of(&[0x11, 0]),
    });
    assert_eq!(
        next(&mut rx),
        RadioEvent::Frame {
            conn: c1,
            bytes: vec![0x11, 0]
        }
    );
    // A central opened to this side: even, numbered by the helper.
    helper.say(&FromHelper::Connected {
        conn: 2,
        role: Side::Peripheral,
        service: proto::uuid_hex(&T),
        max_tx: 100,
        max_rx: 100,
    });
    let c2 = match next(&mut rx) {
        RadioEvent::Connected {
            conn,
            role: Role::Peripheral,
            ..
        } => conn,
        other => panic!("{other:?}"),
    };
    assert_eq!(c2 & WIRE_MASK, 2);
    assert_eq!(radio.send(c2, &[9; 10]), Ok(Sent::Queued));
    assert_eq!(
        helper.heard(),
        ToHelper::Send {
            conn: 2,
            b64: proto::b64_of(&[9; 10])
        }
    );
    radio.disconnect(c3);
    assert_eq!(helper.heard(), ToHelper::Disconnect { conn: 3 });
    helper.say(&FromHelper::Disconnected { conn: 3 });
    assert_eq!(next(&mut rx), RadioEvent::Disconnected { conn: c3 });
    helper.say(&FromHelper::Disconnected { conn: 3 });
    helper.say(&FromHelper::Disconnected { conn: 2 });
    assert_eq!(
        next(&mut rx),
        RadioEvent::Disconnected { conn: c2 },
        "once each"
    );
    assert_eq!(radio.overflows(), 0);
}

/// Lines that do not fit what raven-node knows are dropped, and a link the
/// helper got wrong is ended.
#[test]
fn lines_that_do_not_fit_are_dropped() {
    let (mut helper, radio, mut rx, _) = pipes(Some(&hello()), EVENT_QUEUE);
    let mut radio = radio.unwrap();
    helper.raw("garbage\n");
    helper.say(&FromHelper::Seen {
        dev: String::new(),
        uuids: vec![proto::uuid_hex(&T)],
        rssi: -1,
    });
    helper.say(&FromHelper::Seen {
        dev: DEV.into(),
        uuids: vec!["xyz".into()],
        rssi: -1,
    });
    helper.say(&FromHelper::Frame {
        conn: 1,
        b64: proto::b64_of(&[1]),
    });
    // A central link raven-node never opened, an odd "peripheral" one and
    // a frame size out of range: the helper is told to end each.
    for (conn, role, max_tx) in [
        (5, Side::Central, 100),
        (7, Side::Peripheral, 100),
        (4, Side::Peripheral, 600),
    ] {
        helper.say(&FromHelper::Connected {
            conn,
            role,
            service: proto::uuid_hex(&T),
            max_tx,
            max_rx: max_tx,
        });
        assert_eq!(helper.heard(), ToHelper::Disconnect { conn });
    }
    // A frame that is not base64 ends its link.
    let c1 = central_link(&mut radio, &mut helper, &mut rx, 100);
    helper.say(&FromHelper::Frame {
        conn: 1,
        b64: "!!".into(),
    });
    assert_eq!(helper.heard(), ToHelper::Disconnect { conn: 1 });
    helper.say(&FromHelper::Disconnected { conn: 1 });
    assert_eq!(next(&mut rx), RadioEvent::Disconnected { conn: c1 });
    assert!(rx.try_recv().is_err(), "nothing else came through");
}

/// RNL1 §8: at most SEND_WINDOW frames per connection are on their way;
/// one more is WouldBlock, and the `sent` that makes room gives one
/// Writable. A frame over max_tx is refused.
#[test]
fn the_send_window_blocks_and_one_sent_makes_room() {
    let (mut helper, radio, mut rx, _) = pipes(Some(&hello()), EVENT_QUEUE);
    let mut radio = radio.unwrap();
    let c1 = central_link(&mut radio, &mut helper, &mut rx, 64);
    assert!(radio.send(c1, &[0; 65]).is_err());
    assert!(radio.send(c1, &[]).is_err());
    for _ in 0..SEND_WINDOW {
        assert_eq!(radio.send(c1, &[1; 64]), Ok(Sent::Queued));
        assert!(matches!(helper.heard(), ToHelper::Send { conn: 1, .. }));
    }
    assert_eq!(radio.send(c1, &[1]), Ok(Sent::WouldBlock));
    helper.say(&FromHelper::Sent { conn: 1 });
    assert_eq!(next(&mut rx), RadioEvent::Writable { conn: c1 });
    helper.say(&FromHelper::Sent { conn: 1 });
    // A frame through the queue after it: no second Writable before it.
    helper.say(&FromHelper::Frame {
        conn: 1,
        b64: proto::b64_of(&[2]),
    });
    assert_eq!(
        next(&mut rx),
        RadioEvent::Frame {
            conn: c1,
            bytes: vec![2]
        },
        "one Writable per WouldBlock"
    );
    assert_eq!(radio.send(c1, &[1]), Ok(Sent::Queued));
}

/// RNL1 §8: a connection whose event the full queue lost is ended at the
/// helper; its `Disconnected` comes once there is room.
#[test]
fn a_lost_event_ends_its_connection_at_the_helper() {
    let (mut helper, radio, mut rx, _) = pipes(Some(&hello()), 2);
    let mut radio = radio.unwrap();
    let c1 = central_link(&mut radio, &mut helper, &mut rx, 100);
    for _ in 0..3 {
        helper.say(&FromHelper::Frame {
            conn: 1,
            b64: proto::b64_of(&[1]),
        });
    }
    assert_eq!(helper.heard(), ToHelper::Disconnect { conn: 1 });
    helper.say(&FromHelper::Disconnected { conn: 1 });
    assert!(matches!(next(&mut rx), RadioEvent::Frame { .. }));
    assert!(matches!(next(&mut rx), RadioEvent::Frame { .. }));
    // The next line delivers the owed end first.
    helper.say(&FromHelper::Seen {
        dev: DEV.into(),
        uuids: vec![],
        rssi: 0,
    });
    assert_eq!(next(&mut rx), RadioEvent::Disconnected { conn: c1 });
    assert!(radio.overflows() >= 1);
}

/// A helper that ends on its own ends every connection, says why, and
/// closes the queue (the engine then ends); it counts for the back-off.
#[test]
fn a_helper_that_ends_on_its_own_closes_the_radio() {
    let (mut helper, radio, mut rx, backoff) = pipes(Some(&hello()), EVENT_QUEUE);
    let mut radio = radio.unwrap();
    let c1 = central_link(&mut radio, &mut helper, &mut rx, 100);
    helper.say(&FromHelper::State {
        state: Power::On,
        detail: String::new(),
    });
    assert_eq!(next(&mut rx), RadioEvent::State(RadioState::PoweredOn));
    helper.to_node.take();
    assert_eq!(next(&mut rx), RadioEvent::Disconnected { conn: c1 });
    assert_eq!(
        next(&mut rx),
        RadioEvent::State(RadioState::Unsupported("the nearby helper ended".into()))
    );
    assert!(closed(&mut rx));
    assert!(lock(&backoff).check(Instant::now()).is_err());
    assert!(radio.set_scanning(true).is_err(), "gone");
    assert!(helper.input_closed());
}

/// raven-node letting go of the radio closes the helper's input (the
/// helper then stops everything and exits).
#[test]
fn dropping_the_radio_closes_the_helpers_input() {
    let (helper, radio, _rx, backoff) = pipes(Some(&hello()), EVENT_QUEUE);
    drop(radio.unwrap());
    assert!(helper.input_closed());
    assert!(
        lock(&backoff).check(Instant::now()).is_ok(),
        "not a failure"
    );
}

/// A helper that cannot run, speaks another version, says something else
/// first, or says nothing: no radio.
#[test]
fn a_helper_that_does_not_say_hello_is_no_radio() {
    let no_usage = proto::line(&FromHelper::State {
        state: Power::Unauthorized,
        detail: "no usage description".into(),
    });
    let (_h, radio, _rx, _) = pipes(Some(&no_usage), EVENT_QUEUE);
    assert_eq!(
        radio.err(),
        Some(RadioState::Unauthorized("no usage description".into()))
    );
    let other = proto::line(&FromHelper::Hello {
        v: proto::VERSION + 1,
    });
    let (_h, radio, _rx, _) = pipes(Some(&other), EVENT_QUEUE);
    assert!(matches!(radio.err(), Some(RadioState::Unsupported(why)) if why.contains("protocol")));
    let on = proto::line(&FromHelper::State {
        state: Power::On,
        detail: String::new(),
    });
    let (_h, radio, _rx, _) = pipes(Some(&on), EVENT_QUEUE);
    assert!(matches!(radio.err(), Some(RadioState::Unsupported(_))));
    let (_h, radio, _rx, _) = pipes(None, EVENT_QUEUE);
    assert_eq!(
        radio.err(),
        Some(RadioState::Unsupported(
            "the nearby helper did not answer".into()
        ))
    );
}

// ── Helper processes (Unix) ─────────────────────────────────────────────────

#[cfg(unix)]
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// The process side: a helper that cannot run fails the open; one that
/// exits after its hello ends the radio with its exit code; a missing one
/// does not start.
#[cfg(unix)]
#[test]
fn helper_processes_start_and_end() {
    let dir = tempfile::tempdir().unwrap();
    let refusing = script(
        dir.path(),
        "refusing",
        r#"printf '%s\n' '{"ev":"state","state":"unauthorized","detail":"no usage description"}'"#,
    );
    let (tx, _rx) = mpsc::channel(EVENT_QUEUE);
    assert_eq!(
        open_at(&refusing, tx, None, WAIT).err(),
        Some(RadioState::Unauthorized("no usage description".into()))
    );
    let quitting = script(
        dir.path(),
        "quitting",
        &format!("printf '%s\\n' '{}'\nread line\nexit 3", hello().trim_end()),
    );
    let (tx, mut rx) = mpsc::channel(EVENT_QUEUE);
    let backoff = Arc::new(Mutex::new(Backoff::default()));
    let mut radio = open_at(&quitting, tx, Some(Arc::clone(&backoff)), WAIT).unwrap();
    radio.set_scanning(true).unwrap();
    assert_eq!(
        next(&mut rx),
        RadioEvent::State(RadioState::Unsupported(
            "the nearby helper ended (exit 3)".into()
        ))
    );
    assert!(closed(&mut rx));
    assert!(lock(&backoff).check(Instant::now()).is_err());
    let (tx, _rx) = mpsc::channel(EVENT_QUEUE);
    assert!(matches!(
        open_at(&dir.path().join("missing"), tx, None, WAIT).err(),
        Some(RadioState::Unsupported(why)) if why.starts_with("the nearby helper did not start")
    ));
}

/// The real raven-nearby-helper (built with feature `nearby-radio`), run
/// outside its bundle: no usage description, so Unauthorized from the open
/// and no crash (it creates no CoreBluetooth manager: no radio). Elsewhere
/// it is unsupported.
#[test]
fn the_real_helper_outside_its_bundle_is_no_radio() {
    let Some(exe) = std::env::current_exe()
        .ok()
        .and_then(|p| {
            let name = format!("{EXECUTABLE}{}", std::env::consts::EXE_SUFFIX);
            Some(p.parent()?.parent()?.join(name))
        })
        .filter(|p| p.is_file())
    else {
        eprintln!("raven-nearby-helper is not built (feature nearby-radio): skipped");
        return;
    };
    let (tx, _rx) = mpsc::channel(EVENT_QUEUE);
    match open_at(&exe, tx, None, WAIT).err() {
        Some(RadioState::Unauthorized(why)) if cfg!(target_os = "macos") => {
            assert!(why.starts_with("no usage description"), "{why}")
        }
        Some(RadioState::Unsupported(why)) if !cfg!(target_os = "macos") => {
            assert!(why.contains("macOS only"), "{why}")
        }
        other => panic!("{:?}", other),
    }
}
