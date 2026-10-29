//! The in-process ether (paused time), and a pipe over it.

use std::sync::{Arc, Mutex};

use raven_core::nearby_link::{Role, MAX_FRAME};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, timeout, Duration, Instant};

use super::*;
use crate::nearby::pipe::{Pipe, PipeEnd};
use crate::nearby::radio::{ConnSink, SharedRadio, EVENT_QUEUE};

const T1: [u8; 16] = [0x11; 16];
const T2: [u8; 16] = [0x22; 16];

fn radio(ether: &Ether, name: &str) -> (FakeRadio, mpsc::Receiver<RadioEvent>) {
    let (tx, rx) = mpsc::channel(EVENT_QUEUE);
    (ether.radio(name, tx), rx)
}

/// The next event `keep` accepts (others are skipped), within 10 s.
async fn next(
    rx: &mut mpsc::Receiver<RadioEvent>,
    keep: impl Fn(&RadioEvent) -> bool,
) -> RadioEvent {
    timeout(Duration::from_secs(10), async {
        loop {
            let ev = rx.recv().await.expect("an event");
            if keep(&ev) {
                return ev;
            }
        }
    })
    .await
    .expect("in time")
}

fn is_link(ev: &RadioEvent) -> bool {
    ev.conn().is_some()
}

/// Everything queued now.
fn drain(rx: &mut mpsc::Receiver<RadioEvent>) -> Vec<RadioEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// Central `b` connects to peripheral `a` on `t`: (central conn,
/// peripheral conn).
async fn link(
    a: &mut FakeRadio,
    a_rx: &mut mpsc::Receiver<RadioEvent>,
    b: &mut FakeRadio,
    b_rx: &mut mpsc::Receiver<RadioEvent>,
    t: [u8; 16],
) -> (ConnId, ConnId) {
    a.set_services(&[t], Some(t)).unwrap();
    let c = b.connect(&a.addr(), t).unwrap();
    let RadioEvent::Connected { conn: p, .. } = next(a_rx, is_link).await else {
        panic!("connected")
    };
    assert!(matches!(next(b_rx, is_link).await, RadioEvent::Connected { conn, .. } if conn == c));
    (c, p)
}

/// Adverts: a scanner sees each other radio's one token (only while it
/// scans, never its own), and every token that goes on air is recorded
/// once.
#[tokio::test(start_paused = true)]
async fn a_scanner_sees_each_advert_and_the_ether_records_it() {
    let ether = Ether::new(EtherParams::default());
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (_c, mut c_rx) = radio(&ether, "c");
    a.set_services(&[T1], Some(T1)).unwrap();
    a.set_scanning(true).unwrap();
    b.set_scanning(true).unwrap();
    sleep(ADVERT_EVERY * 3).await;
    let seen: Vec<_> = drain(&mut b_rx)
        .into_iter()
        .filter(|e| matches!(e, RadioEvent::Seen { .. }))
        .collect();
    assert!(seen.len() >= 2, "{} adverts seen", seen.len());
    for ev in &seen {
        assert_eq!(
            ev,
            &RadioEvent::Seen {
                addr: a.addr(),
                uuids: vec![T1],
                rssi: RSSI
            }
        );
    }
    let own = drain(&mut a_rx);
    assert!(
        !own.iter().any(|e| matches!(e, RadioEvent::Seen { .. })),
        "not its own"
    );
    assert_eq!(
        drain(&mut c_rx),
        vec![RadioEvent::State(RadioState::PoweredOn)],
        "not scanning"
    );
    a.set_services(&[T1, T2], Some(T1)).unwrap();
    a.set_services(&[T1, T2], Some(T2)).unwrap();
    a.set_services(&[T1, T2], None).unwrap();
    sleep(ADVERT_EVERY * 2).await;
    b.set_scanning(false).unwrap();
    drain(&mut b_rx);
    sleep(ADVERT_EVERY * 2).await;
    assert!(drain(&mut b_rx).is_empty(), "nothing on air, scan off");
    let record = |uuids| AdvertRecord {
        radio: "a".into(),
        uuids,
    };
    assert_eq!(ether.adverts(), vec![record(vec![T1]), record(vec![T2])]);
    assert!(
        a.set_services(&[T1], Some(T2)).is_err(),
        "advertise what is published"
    );
}

/// A link: both sides `Connected` with their roles and frame limits (each
/// way from its own MTU), frames in order both ways, a frame over the
/// limit refused.
#[tokio::test(start_paused = true)]
async fn a_link_carries_frames_both_ways_with_each_sides_limit() {
    let ether = Ether::new(EtherParams {
        mtu_c2p: 185,
        mtu_p2c: 100,
        latency: Duration::from_millis(5),
        ..EtherParams::default()
    });
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    a.set_services(&[T1], Some(T1)).unwrap();
    let c = b.connect(&a.addr(), T1).unwrap();
    let up_a = next(&mut a_rx, is_link).await;
    let up_b = next(&mut b_rx, is_link).await;
    let RadioEvent::Connected { conn: p, .. } = up_a else {
        panic!("{up_a:?}")
    };
    assert_eq!(
        up_a,
        RadioEvent::Connected {
            conn: p,
            role: Role::Peripheral,
            service: T1,
            max_tx: 97,
            max_rx: 182
        }
    );
    assert_eq!(
        up_b,
        RadioEvent::Connected {
            conn: c,
            role: Role::Central,
            service: T1,
            max_tx: 182,
            max_rx: 97
        }
    );
    for i in 0..5u8 {
        assert_eq!(b.send(c, &[i; 182]).unwrap(), Sent::Queued);
        assert_eq!(a.send(p, &[i; 97]).unwrap(), Sent::Queued);
    }
    for i in 0..5u8 {
        assert_eq!(
            next(&mut a_rx, is_link).await,
            RadioEvent::Frame {
                conn: p,
                bytes: vec![i; 182]
            }
        );
        assert_eq!(
            next(&mut b_rx, is_link).await,
            RadioEvent::Frame {
                conn: c,
                bytes: vec![i; 97]
            }
        );
    }
    assert!(b.send(c, &[0; 183]).is_err());
    assert!(a.send(p, &[0; 98]).is_err());
    assert!(a.send(p, &[]).is_err());
    assert!(a.send(c, &[1]).is_err(), "the other side's connection");
    assert!(b.send(999, &[1]).is_err());
    assert_eq!(ether.crossed(), 10);
    assert_eq!(EtherParams::max_tx(23), 20);
    assert_eq!(EtherParams::max_tx(517), MAX_FRAME);
}

/// A connect to a radio that does not publish the service (or to nothing)
/// completes as `Disconnected`.
#[tokio::test(start_paused = true)]
async fn a_connect_to_an_unpublished_service_ends_in_disconnected() {
    let ether = Ether::new(EtherParams::default());
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    a.set_services(&[T1], None).unwrap();
    let c = b.connect(&a.addr(), T2).unwrap();
    assert_eq!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    let c = b.connect(&RadioAddr("ether-999".into()), T1).unwrap();
    assert_eq!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    let c = b.connect(&b.addr(), T1).unwrap();
    assert_eq!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    sleep(Duration::from_secs(1)).await;
    assert!(!drain(&mut a_rx).iter().any(is_link));
    assert_eq!(ether.links(), 0);
}

/// A full link direction answers WouldBlock; the sender gets exactly one
/// Writable once a frame left, and nothing is lost.
#[tokio::test(start_paused = true)]
async fn would_block_then_one_writable() {
    let ether = Ether::new(EtherParams {
        latency: Duration::from_millis(10),
        ..EtherParams::default()
    });
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    for i in 0..LINK_QUEUE {
        assert_eq!(b.send(c, &[i as u8]).unwrap(), Sent::Queued);
    }
    assert_eq!(b.send(c, &[99]).unwrap(), Sent::WouldBlock);
    assert_eq!(b.send(c, &[99]).unwrap(), Sent::WouldBlock);
    assert_eq!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Writable { conn: c }
    );
    assert_eq!(b.send(c, &[LINK_QUEUE as u8]).unwrap(), Sent::Queued);
    for i in 0..=LINK_QUEUE {
        assert_eq!(
            next(&mut a_rx, is_link).await,
            RadioEvent::Frame {
                conn: p,
                bytes: vec![i as u8]
            }
        );
    }
    sleep(Duration::from_secs(1)).await;
    assert!(drain(&mut b_rx).iter().all(|e| !is_link(e)), "one Writable");
}

/// `disconnect` (either side), a withdrawn service and a dropped radio
/// each cut the link: both sides get `Disconnected`, once.
#[tokio::test(start_paused = true)]
async fn disconnect_withdrawal_and_drop_cut_the_link_on_both_sides() {
    let ether = Ether::new(EtherParams::default());
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let down = |conn| RadioEvent::Disconnected { conn };

    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    b.disconnect(c);
    assert_eq!(next(&mut a_rx, is_link).await, down(p));
    assert_eq!(next(&mut b_rx, is_link).await, down(c));
    assert!(b.send(c, &[1]).is_err());

    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    a.disconnect(p);
    assert_eq!(next(&mut a_rx, is_link).await, down(p));
    assert_eq!(next(&mut b_rx, is_link).await, down(c));

    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    a.set_services(&[T2], Some(T2)).unwrap();
    assert_eq!(next(&mut a_rx, is_link).await, down(p));
    assert_eq!(next(&mut b_rx, is_link).await, down(c));

    let (c, _) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T2).await;
    drop(a);
    assert_eq!(next(&mut b_rx, is_link).await, down(c));
    assert_eq!(ether.links(), 0);
    sleep(Duration::from_secs(1)).await;
    assert!(!drain(&mut b_rx).iter().any(is_link), "once");
}

/// Fault injection, counting every frame that crossed: the frame after
/// `drop_after_frames` is lost, once; the link carrying the frame after
/// `disconnect_after_frames` is cut, once.
#[tokio::test(start_paused = true)]
async fn faults_lose_one_frame_and_cut_one_link_once() {
    let ether = Ether::new(EtherParams {
        drop_after_frames: Some(3),
        ..EtherParams::default()
    });
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (c, _) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    for i in 0..6u8 {
        b.send(c, &[i]).unwrap();
    }
    sleep(Duration::from_secs(1)).await;
    let got: Vec<u8> = drain(&mut a_rx)
        .into_iter()
        .filter_map(|e| match e {
            RadioEvent::Frame { bytes, .. } => Some(bytes[0]),
            _ => None,
        })
        .collect();
    assert_eq!(got, vec![0, 1, 2, 4, 5], "the fourth is lost");
    for i in 6..9u8 {
        b.send(c, &[i]).unwrap();
    }
    sleep(Duration::from_secs(1)).await;
    assert_eq!(drain(&mut a_rx).len(), 3, "once");

    let ether = Ether::new(EtherParams {
        disconnect_after_frames: Some(2),
        ..EtherParams::default()
    });
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    for i in 0..3u8 {
        b.send(c, &[i]).unwrap();
    }
    sleep(Duration::from_secs(1)).await;
    assert_eq!(
        drain(&mut a_rx),
        vec![
            RadioEvent::Frame {
                conn: p,
                bytes: vec![0]
            },
            RadioEvent::Frame {
                conn: p,
                bytes: vec![1]
            },
            RadioEvent::Disconnected { conn: p }
        ]
    );
    assert_eq!(drain(&mut b_rx), vec![RadioEvent::Disconnected { conn: c }]);
    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    b.send(c, &[7]).unwrap();
    assert_eq!(
        next(&mut a_rx, is_link).await,
        RadioEvent::Frame {
            conn: p,
            bytes: vec![7]
        },
        "a new link is not cut"
    );
}

/// Power (the user's Bluetooth switch, P5.28): off cuts the radio's links,
/// says `PoweredOff`, hides its advert and its scan, and refuses connects
/// both ways; on says `PoweredOn` and everything comes back.
#[tokio::test(start_paused = true)]
async fn power_off_cuts_links_and_hides_the_radio_until_on() {
    let ether = Ether::new(EtherParams::default());
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    assert_eq!(ether.set_power("nobody", false), 0);
    assert_eq!(ether.set_power("a", false), 1);
    let off = drain(&mut a_rx);
    assert!(
        off.contains(&RadioEvent::Disconnected { conn: p }),
        "{off:?}"
    );
    assert!(
        off.contains(&RadioEvent::State(RadioState::PoweredOff)),
        "{off:?}"
    );
    assert_eq!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    assert_eq!(
        ether.radios(),
        vec![("a".to_string(), false), ("b".to_string(), true)]
    );
    // Off: its advert is not seen, it sees nothing, and no connect works.
    a.set_scanning(true).unwrap();
    b.set_scanning(true).unwrap();
    b.set_services(&[T2], Some(T2)).unwrap();
    sleep(ADVERT_EVERY * 3).await;
    assert!(!drain(&mut b_rx)
        .iter()
        .any(|e| matches!(e, RadioEvent::Seen { .. })));
    assert!(!drain(&mut a_rx)
        .iter()
        .any(|e| matches!(e, RadioEvent::Seen { .. })));
    let c = b.connect(&a.addr(), T1).unwrap();
    assert_eq!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    let c = a.connect(&b.addr(), T2).unwrap();
    assert_eq!(
        next(&mut a_rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    // A token published while off goes on air (and is recorded) once on.
    a.set_services(&[T1], Some(T1)).unwrap();
    assert_eq!(ether.adverts().len(), 2, "T1 (before), T2 (b)");
    assert_eq!(ether.set_power("a", false), 1, "off again is no change");
    assert!(drain(&mut a_rx).is_empty());
    ether.set_power("a", true);
    assert_eq!(
        next(&mut a_rx, |_| true).await,
        RadioEvent::State(RadioState::PoweredOn)
    );
    let RadioEvent::Seen { uuids, .. } =
        next(&mut b_rx, |e| matches!(e, RadioEvent::Seen { .. })).await
    else {
        unreachable!()
    };
    assert_eq!(uuids, vec![T1]);
    link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
}

/// Faults armed later count from then (P5.28: the harness arms a lost
/// frame mid-message), once each; `None` disarms.
#[tokio::test(start_paused = true)]
async fn armed_faults_count_from_when_they_are_armed() {
    let ether = Ether::new(EtherParams::default());
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (c, _) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    let frames = |rx: &mut mpsc::Receiver<RadioEvent>| -> Vec<u8> {
        drain(rx)
            .into_iter()
            .filter_map(|e| match e {
                RadioEvent::Frame { bytes, .. } => Some(bytes[0]),
                _ => None,
            })
            .collect()
    };
    for i in 0..5u8 {
        b.send(c, &[i]).unwrap();
    }
    sleep(Duration::from_secs(1)).await;
    assert_eq!(frames(&mut a_rx), vec![0, 1, 2, 3, 4]);
    ether.arm_faults(Some(2), None);
    for i in 5..10u8 {
        b.send(c, &[i]).unwrap();
    }
    sleep(Duration::from_secs(1)).await;
    assert_eq!(
        frames(&mut a_rx),
        vec![5, 6, 8, 9],
        "the third after arming"
    );
    ether.arm_faults(None, Some(1));
    for i in 10..13u8 {
        b.send(c, &[i]).unwrap();
    }
    sleep(Duration::from_secs(1)).await;
    let got = drain(&mut a_rx);
    assert!(
        got.iter()
            .any(|e| matches!(e, RadioEvent::Frame { bytes, .. } if bytes[0] == 10)),
        "{got:?}"
    );
    assert!(got
        .iter()
        .any(|e| matches!(e, RadioEvent::Disconnected { .. })));
    assert!(drain(&mut b_rx)
        .iter()
        .any(|e| matches!(e, RadioEvent::Disconnected { .. })));
    let (c, _) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    ether.arm_faults(None, None);
    for i in 20..24u8 {
        b.send(c, &[i]).unwrap();
    }
    sleep(Duration::from_secs(1)).await;
    assert_eq!(frames(&mut a_rx), vec![20, 21, 22, 23], "disarmed");
}

/// What a radio observer captures: the central's knock HELLOs (35 bytes,
/// kind 0x01) with the service they were written to; nothing else.
#[tokio::test(start_paused = true)]
async fn the_ether_keeps_the_knock_hellos_a_sniffer_would_see() {
    use raven_core::nearby_link::{HELLO_LEN, KIND_HELLO};
    let ether = Ether::new(EtherParams::default());
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    let mut hello = vec![KIND_HELLO; HELLO_LEN];
    hello[5] = 0x77;
    b.send(c, &hello).unwrap();
    b.send(c, &[KIND_HELLO; 20]).unwrap();
    a.send(p, &[KIND_HELLO; HELLO_LEN]).unwrap();
    sleep(Duration::from_secs(1)).await;
    assert_eq!(ether.hellos(), vec![(T1, hello)]);
}

/// Latency delays each frame; the rate paces a burst.
#[tokio::test(start_paused = true)]
async fn latency_and_rate_pace_the_air() {
    let ether = Ether::new(EtherParams {
        latency: Duration::from_millis(50),
        bytes_per_sec: 10_000,
        ..EtherParams::default()
    });
    let (mut a, mut a_rx) = radio(&ether, "a");
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (c, _) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    let start = Instant::now();
    for _ in 0..LINK_QUEUE {
        assert_eq!(b.send(c, &[0; 100]).unwrap(), Sent::Queued);
    }
    next(&mut a_rx, is_link).await;
    let first = start.elapsed();
    assert!(first >= Duration::from_millis(50), "{first:?}");
    for _ in 1..LINK_QUEUE {
        next(&mut a_rx, is_link).await;
    }
    // 8 x 100 B at 10 kB/s: 80 ms of air.
    let last = start.elapsed();
    assert!(last >= Duration::from_millis(80), "{last:?}");
    assert!(last < Duration::from_millis(200), "{last:?}");
}

/// RNL1 §8: a radio whose event queue is full loses the connection, not a
/// frame: the link is cut, the other side is told at once, and this side
/// gets its `Disconnected` once there is room.
#[tokio::test(start_paused = true)]
async fn a_full_event_queue_cuts_the_link() {
    let ether = Ether::new(EtherParams::default());
    let (tx, mut a_rx) = mpsc::channel(4);
    let mut a = ether.radio("a", tx);
    let (mut b, mut b_rx) = radio(&ether, "b");
    let (c, p) = link(&mut a, &mut a_rx, &mut b, &mut b_rx, T1).await;
    for i in 0..6u8 {
        assert_eq!(b.send(c, &[i]).unwrap(), Sent::Queued);
    }
    assert_eq!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    assert!(a.overflows() > 0);
    let got = drain(&mut a_rx);
    assert_eq!(got.len(), 4);
    assert!(got
        .iter()
        .all(|e| matches!(e, RadioEvent::Frame { conn, .. } if *conn == p)));
    sleep(ADVERT_EVERY * 2).await;
    assert_eq!(drain(&mut a_rx), vec![RadioEvent::Disconnected { conn: p }]);
}

/// A central-only radio publishes nothing; a public address shows in its
/// caps.
#[tokio::test(start_paused = true)]
async fn central_only_and_public_address_radios() {
    let ether = Ether::new(EtherParams::default());
    let (tx, _rx) = mpsc::channel(8);
    let opts = FakeOpts {
        central_only: true,
        public_address: true,
    };
    let mut r = ether.radio_with("w", tx, opts);
    let caps = r.caps();
    assert!(caps.central && !caps.peripheral && !caps.l2cap);
    assert_eq!(caps.address_privacy, Privacy::Public);
    assert!(r.set_services(&[T1], Some(T1)).is_err());
    assert!(r.set_services(&[], None).is_ok());
    let (a, _rx) = radio(&ether, "a");
    assert_eq!(a.caps().address_privacy, Privacy::Random);
    assert!(a.caps().peripheral);
    assert!(EtherParams::default().check().is_ok());
    for mtu in [22, 518] {
        let p = EtherParams {
            mtu_p2c: mtu,
            ..EtherParams::default()
        };
        assert!(p.check().is_err(), "{mtu}");
    }
}

/// One side of a pipe over a fake radio: its events drive the pipe as the
/// engine will (frames, Writable, Disconnected).
async fn pipe_side(
    radio: FakeRadio,
    mut rx: mpsc::Receiver<RadioEvent>,
    up: oneshot::Sender<Pipe>,
    inbound: mpsc::UnboundedSender<tokio::io::DuplexStream>,
) -> Option<PipeEnd> {
    let shared: SharedRadio = Arc::new(Mutex::new(Box::new(radio) as Box<dyn Radio>));
    let mut up = Some(up);
    let mut pipe = None;
    let mut task = None;
    while let Some(ev) = rx.recv().await {
        match ev {
            RadioEvent::Connected {
                conn,
                role,
                max_tx,
                max_rx,
                ..
            } => {
                let sink = Box::new(ConnSink::new(shared.clone(), conn));
                let inbound = inbound.clone();
                let on_inbound = Box::new(move |_: u8, s: tokio::io::DuplexStream| {
                    let _ = inbound.send(s);
                });
                let (p, t) = Pipe::start([0; 32], role, max_tx, max_rx, sink, on_inbound).unwrap();
                if let Some(up) = up.take() {
                    let _ = up.send(p.clone());
                }
                pipe = Some(p);
                task = Some(t);
            }
            RadioEvent::Frame { bytes, .. } => {
                if let Some(p) = &pipe {
                    let _ = p.rx(bytes);
                }
            }
            RadioEvent::Writable { .. } => {
                if let Some(p) = &pipe {
                    p.writable();
                }
            }
            RadioEvent::Disconnected { .. } => {
                if let Some(p) = &pipe {
                    p.down();
                }
                break;
            }
            RadioEvent::State(_) | RadioEvent::Seen { .. } => {}
        }
    }
    drop(pipe);
    match task {
        Some(t) => t.await.ok(),
        None => None,
    }
}

/// The seam end to end: a pipe on each side of a fake link (ATT MTU 185,
/// 2 ms latency, 20 kB/s, the radio's WouldBlock under the pipe's credit)
/// carries a 64 KiB link message each way; the central's disconnect ends
/// both.
#[tokio::test(start_paused = true)]
async fn a_pipe_runs_over_the_ether() {
    let ether = Ether::new(EtherParams {
        mtu_c2p: 185,
        mtu_p2c: 185,
        latency: Duration::from_millis(2),
        bytes_per_sec: 20_000,
        ..EtherParams::default()
    });
    let (mut a, a_rx) = radio(&ether, "a");
    let (mut b, b_rx) = radio(&ether, "b");
    a.set_services(&[T1], Some(T1)).unwrap();
    b.set_scanning(true).unwrap();
    let c = b.connect(&a.addr(), T1).unwrap();
    let (a_up, a_pipe) = oneshot::channel();
    let (b_up, b_pipe) = oneshot::channel();
    let (a_in, mut a_inbound) = mpsc::unbounded_channel();
    let (b_in, _b_inbound) = mpsc::unbounded_channel();
    let peripheral = tokio::spawn(pipe_side(a, a_rx, a_up, a_in));
    let central = tokio::spawn(pipe_side(b, b_rx, b_up, b_in));
    let (_pa, pb) = (a_pipe.await.unwrap(), b_pipe.await.unwrap());
    assert!(c > 0);
    let mut dial = pb.open_channel().await.unwrap();
    let mut serve = a_inbound.recv().await.unwrap();
    let mut msg = (65535u32).to_be_bytes().to_vec();
    msg.extend((0..65535u32).map(|i| (i % 251) as u8));
    let m = msg.clone();
    let writer = tokio::spawn(async move {
        dial.write_all(&m).await.unwrap();
        let mut back = vec![0; m.len()];
        dial.read_exact(&mut back).await.unwrap();
        (dial, back)
    });
    let mut got = vec![0; msg.len()];
    serve.read_exact(&mut got).await.unwrap();
    assert!(got == msg, "request intact");
    serve.write_all(&got).await.unwrap();
    let (_dial, back) = writer.await.unwrap();
    assert!(back == msg, "reply intact");
    assert!(ether.crossed() > 2 * 65539 / 181);
    pb.reset(raven_core::nearby_link::PipeError::Shutdown);
    let ends = (central.await.unwrap(), peripheral.await.unwrap());
    assert_eq!(
        ends.0,
        Some(PipeEnd::ResetSent(
            raven_core::nearby_link::PipeError::Shutdown
        ))
    );
    assert!(
        matches!(ends.1, Some(PipeEnd::ResetReceived(4) | PipeEnd::Down)),
        "{:?}",
        ends.1
    );
    assert_eq!(ether.links(), 0, "the central disconnected");
}
