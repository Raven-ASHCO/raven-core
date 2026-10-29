//! The hub over real loopback TCP: two [`HubRadio`]s in separate tasks
//! meet on one ether.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use super::*;

const T1: [u8; 16] = [0x5a; 16];

async fn hub(params: EtherParams) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = serve(listener, params).await;
    });
    (addr, task)
}

fn client(addr: SocketAddr, name: &str) -> (HubRadio, mpsc::Receiver<RadioEvent>) {
    let (tx, rx) = mpsc::channel(EVENT_QUEUE);
    (
        HubRadio::connect(addr, name, FakeOpts::default(), tx).unwrap(),
        rx,
    )
}

/// The next event `keep` accepts (others skipped), within 10 s.
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

/// The design's hub test: discovery, connect, frames both ways in order
/// (past the client window: WouldBlock, then Writable), and the ends of a
/// link (a disconnect, a client that goes away) reach both radios.
#[tokio::test]
async fn hub_round_trip_between_two_radios_over_tcp() {
    let (addr, server) = hub(EtherParams {
        mtu_c2p: 185,
        mtu_p2c: 247,
        ..EtherParams::default()
    })
    .await;
    let (mut a, mut a_rx) = client(addr, "a");
    let (mut b, mut b_rx) = client(addr, "b");
    assert_eq!(
        next(&mut a_rx, |_| true).await,
        RadioEvent::State(RadioState::PoweredOn)
    );
    a.set_services(&[T1], Some(T1)).unwrap();
    b.set_scanning(true).unwrap();
    let RadioEvent::Seen {
        addr: at, uuids, ..
    } = next(&mut b_rx, |e| matches!(e, RadioEvent::Seen { .. })).await
    else {
        unreachable!()
    };
    assert_eq!(uuids, vec![T1]);
    b.set_scanning(false).unwrap();

    let c = b.connect(&at, T1).unwrap();
    assert_eq!(c % 2, 1, "the client's own odd number");
    let up_b = next(&mut b_rx, is_link).await;
    assert_eq!(
        up_b,
        RadioEvent::Connected {
            conn: c,
            role: Role::Central,
            service: T1,
            max_tx: 182,
            max_rx: 244
        }
    );
    let RadioEvent::Connected {
        conn: p,
        role,
        max_tx,
        max_rx,
        ..
    } = next(&mut a_rx, is_link).await
    else {
        panic!("connected")
    };
    assert_eq!(
        (p % 2, role, max_tx, max_rx),
        (0, Role::Peripheral, 244, 182)
    );

    // Past the window without yielding: WouldBlock, then one Writable.
    let mut sent = 0u8;
    let mut blocked = false;
    while sent < 40 {
        match b.send(c, &[sent; 182]).unwrap() {
            Sent::Queued => sent += 1,
            Sent::WouldBlock => {
                blocked = true;
                assert_eq!(sent as usize, HUB_WINDOW);
                assert_eq!(
                    next(&mut b_rx, is_link).await,
                    RadioEvent::Writable { conn: c }
                );
                break;
            }
        }
    }
    assert!(blocked);
    while sent < 40 {
        if b.send(c, &[sent; 182]).unwrap() == Sent::WouldBlock {
            next(&mut b_rx, is_link).await;
            continue;
        }
        sent += 1;
    }
    for i in 0..40u8 {
        assert_eq!(
            next(&mut a_rx, is_link).await,
            RadioEvent::Frame {
                conn: p,
                bytes: vec![i; 182]
            }
        );
    }
    assert_eq!(a.send(p, &[9; 244]).unwrap(), Sent::Queued);
    assert_eq!(
        next(&mut b_rx, |e| matches!(e, RadioEvent::Frame { .. })).await,
        RadioEvent::Frame {
            conn: c,
            bytes: vec![9; 244]
        }
    );
    assert!(b.send(c, &[0; 183]).is_err(), "over max_tx");
    assert!(b.send(c + 2, &[0]).is_err(), "not connected");

    b.disconnect(c);
    let down = |conn| RadioEvent::Disconnected { conn };
    assert_eq!(next(&mut b_rx, is_link).await, down(c));
    assert_eq!(next(&mut a_rx, is_link).await, down(p));

    // A client that goes away cuts its links.
    let c = b.connect(&at, T1).unwrap();
    assert!(matches!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Connected { .. }
    ));
    let RadioEvent::Connected { conn: p, .. } = next(&mut a_rx, is_link).await else {
        panic!("connected")
    };
    drop(b);
    assert_eq!(next(&mut a_rx, is_link).await, down(p));
    assert!(c > 1);
    assert_eq!(a.overflows(), 0);
    server.abort();
}

/// A client refuses locally what the hub would refuse, and a connect to an
/// address nobody has ends in `Disconnected`.
#[tokio::test]
async fn a_client_refuses_what_the_hub_would() {
    let (addr, server) = hub(EtherParams::default()).await;
    let (tx, mut rx) = mpsc::channel(EVENT_QUEUE);
    let opts = FakeOpts {
        central_only: true,
        public_address: true,
    };
    let mut w = HubRadio::connect(addr, "w", opts, tx).unwrap();
    assert!(!w.caps().peripheral);
    assert_eq!(w.caps().address_privacy, Privacy::Public);
    assert!(w.set_services(&[T1], Some(T1)).is_err());
    let (mut a, _a_rx) = client(addr, "a");
    assert!(a.set_services(&[T1], Some([0; 16])).is_err());
    let c = w.connect(&RadioAddr("ether-424242".into()), T1).unwrap();
    assert_eq!(
        next(&mut rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    assert!(w.send(c, &[1]).is_err());
    let not_loopback: SocketAddr = "192.0.2.1:9".parse().unwrap();
    let (tx, _rx) = mpsc::channel(1);
    assert!(HubRadio::connect(not_loopback, "x", FakeOpts::default(), tx).is_err());
    server.abort();
}

/// The hub going away ends every connection and turns the radio off.
#[tokio::test]
async fn the_hub_going_away_ends_every_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fake_hub = tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let (r, mut w) = s.into_split();
        let mut r = BufReader::new(r);
        let mut hello = String::new();
        r.read_line(&mut hello).await.unwrap();
        assert!(hello.contains("\"op\":\"hello\""), "{hello}");
        let up = FromHub::Connected {
            conn: 2,
            role: "peripheral".into(),
            service: uuid_hex(&T1),
            max_tx: 100,
            max_rx: 100,
        };
        w.write_all(line(&up).as_bytes()).await.unwrap();
    });
    let (_r, mut rx) = client(addr, "a");
    assert!(matches!(
        next(&mut rx, is_link).await,
        RadioEvent::Connected { conn: 2, .. }
    ));
    fake_hub.await.unwrap();
    assert_eq!(
        next(&mut rx, is_link).await,
        RadioEvent::Disconnected { conn: 2 }
    );
    assert_eq!(
        next(&mut rx, |_| true).await,
        RadioEvent::State(RadioState::PoweredOff)
    );
}

/// The lines: the shapes the harness may write, the length cap, and the
/// loopback-only lab address.
#[tokio::test]
async fn lines_and_the_lab_address() {
    let hello = r#"{"op":"hello","name":"n"}"#;
    assert_eq!(
        serde_json::from_str::<ToHub>(hello).unwrap(),
        ToHub::Hello {
            name: "n".into(),
            central_only: false,
            public_address: false
        }
    );
    let sent = line(&FromHub::Sent { conn: 3 });
    assert_eq!(sent, "{\"ev\":\"sent\",\"conn\":3}\n");
    let mut long = vec![b'x'; MAX_LINE + 10];
    long.push(b'\n');
    let mut r = BufReader::new(&long[..]);
    let mut buf = Vec::new();
    assert!(read_msg::<_, ToHub>(&mut r, &mut buf).await.is_err());
    let mut r = BufReader::new(&b"{\"op\":\"scan\",\"on\":true}\n"[..]);
    assert_eq!(
        read_msg::<_, ToHub>(&mut r, &mut buf).await.unwrap(),
        Some(ToHub::Scan { on: true })
    );
    assert_eq!(read_msg::<_, ToHub>(&mut r, &mut buf).await.unwrap(), None);
    assert!(uuid_from("00").is_err());
    assert_eq!(uuid_from(&uuid_hex(&T1)).unwrap(), T1);

    for ok in ["127.0.0.1:40000", "[::1]:5", " 127.0.0.2:9 "] {
        assert!(parse_loopback(ok).is_ok(), "{ok}");
    }
    for bad in ["0.0.0.0:1", "127.0.0.1:0", "198.51.100.2:3", "x", ""] {
        assert!(parse_loopback(bad).is_err(), "{bad}");
    }
    if std::env::var(LAB_ETHER).is_err() {
        assert_eq!(lab_ether(), Ok(None));
    }
}

/// `raven-node nearby-ether` is lab-only: without the nearby lab switch it
/// refuses before listening (exit 3); with it, a non-loopback address or
/// a bad MTU is refused (exit 2).
#[tokio::test]
async fn the_hub_command_is_lab_only_and_loopback_only() {
    let anywhere: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let lab = raven_core::pair_init::lab_switch(raven_core::nearby_gate::LAB_NEARBY);
    if !lab {
        assert_eq!(run_cli(anywhere, false, EtherParams::default()).await, 3);
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert_eq!(run_cli(local, false, EtherParams::default()).await, 3);
        return;
    }
    assert_eq!(run_cli(anywhere, false, EtherParams::default()).await, 2);
    let tiny = EtherParams {
        mtu_c2p: 5,
        ..EtherParams::default()
    };
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    assert_eq!(run_cli(local, false, tiny).await, 2);
}

/// One control request and its answer.
async fn ask(
    w: &mut OwnedWriteHalf,
    r: &mut BufReader<OwnedReadHalf>,
    req: &str,
) -> serde_json::Value {
    w.write_all(format!("{req}\n").as_bytes()).await.unwrap();
    let mut answer = String::new();
    timeout(Duration::from_secs(10), r.read_line(&mut answer))
        .await
        .expect("an answer in time")
        .unwrap();
    serde_json::from_str(&answer).unwrap()
}

/// A control session (P5.28, the harness's side of the hub): it lists the
/// radios, switches one off and on (its links end, it hears `PoweredOff`,
/// then `PoweredOn`), arms a fault, and reads the air: every token that
/// went on air and the knock HELLOs a radio observer captured. A radio
/// session gets an error for a control request, and an unknown radio is
/// an error.
#[tokio::test]
async fn a_control_session_switches_a_radio_and_reads_the_air() {
    use raven_core::nearby_link::{HELLO_LEN, KIND_HELLO};
    let (addr, server) = hub(EtherParams::default()).await;
    let (mut a, mut a_rx) = client(addr, "a");
    let (mut b, mut b_rx) = client(addr, "b");
    let stream = TcpStream::connect(addr).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    w.write_all(b"{\"op\":\"control\"}\n").await.unwrap();
    let mut radios = serde_json::Value::Null;
    for _ in 0..100 {
        radios = ask(&mut w, &mut r, r#"{"op":"radios"}"#).await;
        if radios["radios"].as_array().is_some_and(|r| r.len() == 2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        radios,
        serde_json::json!({"ev": "radios", "radios": [
            {"name": "a", "on": true}, {"name": "b", "on": true}]})
    );

    a.set_services(&[T1], Some(T1)).unwrap();
    b.set_scanning(true).unwrap();
    let RadioEvent::Seen { addr: at, .. } =
        next(&mut b_rx, |e| matches!(e, RadioEvent::Seen { .. })).await
    else {
        unreachable!()
    };
    assert_eq!(
        ask(&mut w, &mut r, r#"{"op":"adverts"}"#).await,
        serde_json::json!({"ev": "adverts", "records": [
            {"radio": "a", "uuids": [uuid_hex(&T1)]}]})
    );
    let c = b.connect(&at, T1).unwrap();
    assert!(matches!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Connected { .. }
    ));
    let RadioEvent::Connected { conn: p, .. } = next(&mut a_rx, is_link).await else {
        panic!("connected")
    };
    let hello = [KIND_HELLO; HELLO_LEN];
    b.send(c, &hello).unwrap();
    assert!(matches!(
        next(&mut a_rx, is_link).await,
        RadioEvent::Frame { .. }
    ));
    assert_eq!(
        ask(&mut w, &mut r, r#"{"op":"hellos"}"#).await,
        serde_json::json!({"ev": "hellos", "hellos": [
            {"service": uuid_hex(&T1), "b64": b64().encode(hello)}]})
    );

    let ok = serde_json::json!({"ev": "ok"});
    assert_eq!(
        ask(&mut w, &mut r, r#"{"op":"power","name":"a","on":false}"#).await,
        ok
    );
    assert_eq!(
        next(&mut a_rx, |_| true).await,
        RadioEvent::Disconnected { conn: p }
    );
    assert_eq!(
        next(&mut a_rx, |_| true).await,
        RadioEvent::State(RadioState::PoweredOff)
    );
    assert_eq!(
        next(&mut b_rx, is_link).await,
        RadioEvent::Disconnected { conn: c }
    );
    assert_eq!(
        ask(&mut w, &mut r, r#"{"op":"power","name":"a","on":true}"#).await,
        ok
    );
    assert_eq!(
        next(&mut a_rx, |_| true).await,
        RadioEvent::State(RadioState::PoweredOn)
    );
    assert_eq!(
        ask(&mut w, &mut r, r#"{"op":"fault","drop_after":3}"#).await,
        ok
    );
    let stats = ask(&mut w, &mut r, r#"{"op":"stats"}"#).await;
    assert_eq!(
        (
            stats["ev"].as_str(),
            stats["crossed"].as_u64(),
            stats["dropped"].as_bool()
        ),
        (Some("stats"), Some(1), Some(false)),
        "{stats}"
    );
    let unknown = ask(&mut w, &mut r, r#"{"op":"power","name":"zed","on":true}"#).await;
    assert_eq!(unknown["ev"], "error", "{unknown}");
    let wrong = ask(&mut w, &mut r, r#"{"op":"scan","on":true}"#).await;
    assert_eq!(wrong["ev"], "error", "{wrong}");

    // A radio session asking for the air is refused.
    let raw = TcpStream::connect(addr).await.unwrap();
    let (rr, mut rw) = raw.into_split();
    let mut rr = BufReader::new(rr);
    rw.write_all(b"{\"op\":\"hello\",\"name\":\"s\"}\n{\"op\":\"adverts\"}\n")
        .await
        .unwrap();
    let mut got = String::new();
    loop {
        got.clear();
        timeout(Duration::from_secs(10), rr.read_line(&mut got))
            .await
            .expect("in time")
            .unwrap();
        if !got.contains("\"ev\":\"state\"") {
            break;
        }
    }
    assert!(got.contains("\"ev\":\"error\""), "{got}");
    server.abort();
}
