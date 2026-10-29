//! The WinRT backend's pure part (no WinRT, no radio): GUIDs and addresses,
//! the capabilities, the state machine over scripted inputs, and the send
//! table.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use raven_core::nearby_link::{char_uuid, Role};
use tokio::sync::mpsc;

use super::*;
use crate::nearby::radio::{EventTx, Privacy, RadioAddr, RadioEvent, EVENT_QUEUE};

const A: [u8; 16] = [
    0x06, 0x2a, 0x8a, 0xc6, 0x9e, 0x02, 0x4a, 0xbb, 0xab, 0x83, 0xf9, 0xea, 0xbb, 0x5e, 0x8d, 0x99,
];
const B: [u8; 16] = [0x22; 16];
/// WinRT device ids (documentation-only placeholders).
const DEV: &str = "BluetoothLE#dev-1";
const DEV2: &str = "BluetoothLE#dev-2";
/// Battery Service, written long.
const SIG: [u8; 16] = [
    0x00, 0x00, 0x18, 0x0f, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
];

/// What [`Core`] asked of WinRT, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Create([u8; 16]),
    Advertise([u8; 16], bool),
    Withdraw([u8; 16]),
    Scan(bool),
    Connect(ConnId, [u8; 16]),
    CentralUp(ConnId, usize),
    PeripheralUp(ConnId, [u8; 16], String, usize),
    Ended(ConnId),
}

#[derive(Default)]
struct FakeOs {
    calls: Vec<Call>,
}

impl Os for FakeOs {
    fn create(&mut self, t: [u8; 16]) {
        self.calls.push(Call::Create(t));
    }

    fn advertise(&mut self, t: [u8; 16], on_air: bool) {
        self.calls.push(Call::Advertise(t, on_air));
    }

    fn withdraw(&mut self, t: [u8; 16]) {
        self.calls.push(Call::Withdraw(t));
    }

    fn scan(&mut self, on: bool) {
        self.calls.push(Call::Scan(on));
    }

    fn connect(&mut self, conn: ConnId, _addr: Addr, t: [u8; 16]) {
        self.calls.push(Call::Connect(conn, t));
    }

    fn central_up(&mut self, conn: ConnId, max_tx: usize) {
        self.calls.push(Call::CentralUp(conn, max_tx));
    }

    fn peripheral_up(&mut self, conn: ConnId, t: [u8; 16], device: &str, max_tx: usize) {
        self.calls
            .push(Call::PeripheralUp(conn, t, device.to_owned(), max_tx));
    }

    fn ended(&mut self, conn: ConnId) {
        self.calls.push(Call::Ended(conn));
    }
}

fn full_caps() -> RadioCaps {
    caps(
        Adapter {
            low_energy: true,
            central: true,
            peripheral: true,
        },
        &Server::Works,
    )
    .unwrap()
}

fn core_with(
    caps: RadioCaps,
    powered: bool,
    queue: usize,
) -> (Core<FakeOs>, mpsc::Receiver<RadioEvent>) {
    let (tx, rx) = mpsc::channel(queue);
    let mut core = Core::new(FakeOs::default(), EventTx::new(tx), caps, powered);
    core.start();
    (core, rx)
}

/// A powered core with both roles; its first `State` already taken.
fn new_core() -> (Core<FakeOs>, mpsc::Receiver<RadioEvent>) {
    let (core, mut rx) = core_with(full_caps(), true, EVENT_QUEUE);
    assert_eq!(drain(&mut rx), [RadioEvent::State(RadioState::PoweredOn)]);
    (core, rx)
}

/// Everything queued now.
fn drain(rx: &mut mpsc::Receiver<RadioEvent>) -> Vec<RadioEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

fn calls(core: &mut Core<FakeOs>) -> Vec<Call> {
    std::mem::take(&mut core.os.calls)
}

fn sub(device: &str, max_tx: usize, max_rx: usize) -> Subscriber {
    Subscriber {
        device: device.to_owned(),
        max_tx,
        max_rx,
    }
}

/// `t` published and its provider ready (nothing advertised).
fn serve(core: &mut Core<FakeOs>, t: [u8; 16], now: Instant) {
    core.command(Cmd::Services(vec![t], None), now);
    assert_eq!(calls(core), [Call::Create(t)]);
    core.created(t, Ok(()), now);
    assert_eq!(calls(core), [Call::Advertise(t, false)]);
}

fn addr(n: u64) -> Addr {
    Addr::new(0x0000_5e00_5300 + n, AddrKind::Random)
}

/// RNL1 §2/§10: WinRT's GUID for a token is `GUID::from_u128` of its bytes
/// read big-endian, and back again; the characteristic's too.
#[test]
fn guid_round_trip_matches_the_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../shared-vectors/rvn1/nearby/rnb1_tokens_001.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let tokens = v["expected"]["tokens"].as_array().unwrap();
    assert!(tokens.len() >= 4);
    for tok in tokens {
        let t: [u8; 16] = hex::decode(tok["token_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let want = tok["windows_guid_u128_hex"].as_str().unwrap();
        assert_eq!(format!("{:032x}", guid_u128(&t)), want);
        assert_eq!(uuid_of(u128::from_str_radix(want, 16).unwrap()), t);
        let c = char_uuid(&t);
        assert_eq!(uuid_of(guid_u128(&c)), c);
        assert_eq!(
            format!("{:032x}", guid_u128(&c)),
            tok["char_uuid_hex"].as_str().unwrap()
        );
        assert!(!is_sig_uuid(&t) && !is_sig_uuid(&c));
    }
    assert_eq!(
        A,
        hex::decode("062a8ac69e024abbab83f9eabb5e8d99").unwrap()[..]
    );
    assert!(is_sig_uuid(&SIG));
    // An advert's candidates: no SIG UUID, each once, in order, bounded.
    assert_eq!(candidates([SIG, A, B, A]), [A, B]);
    let many: Vec<[u8; 16]> = (0..20u8).map(|i| [i; 16]).collect();
    assert_eq!(candidates(many).len(), MAX_ADVERT_UUIDS);
}

/// The engine's handle names the address and its type, round-trips, and
/// never shows in `Debug`.
#[test]
fn addresses_round_trip_and_never_show() {
    let a = Addr::new(0xffff_0000_5e00_5301, AddrKind::Random);
    assert_eq!(a.raw, 0x0000_5e00_5301, "48 bits");
    assert_eq!(a.radio_addr(), RadioAddr("00005e005301/r".into()));
    assert_eq!(Addr::parse(&a.radio_addr()), Some(a));
    for kind in [AddrKind::Public, AddrKind::Random, AddrKind::Unspecified] {
        let a = Addr::new(0x0000_5e00_53ff, kind);
        assert_eq!(Addr::parse(&a.radio_addr()), Some(a));
    }
    assert_eq!(format!("{a:?}"), "Addr(..)");
    for bad in [
        "00005e005301",
        "00005e005301/x",
        "00005e00530/r",
        "00005e0053011/r",
        "00005e00530g/r",
        "/org/bluez/hci0/dev_00_00_5E_00_53_01",
    ] {
        assert_eq!(Addr::parse(&RadioAddr(bad.into())), None, "{bad}");
    }
}

/// RNL1 §4: `min(ATT_MTU - 3, 512)` each way; ATT's default when WinRT
/// reports less.
#[test]
fn frame_sizes_follow_the_att_mtu() {
    assert_eq!(frame_limit(0), 20);
    assert_eq!(frame_limit(23), 20);
    assert_eq!(frame_limit(247), 244);
    assert_eq!(frame_limit(517), 512);
    assert_eq!(frame_limit(u16::MAX), 512);
    assert_eq!(notify_limit(0), 20);
    assert_eq!(notify_limit(182), 182);
    assert_eq!(notify_limit(600), 512);
}

/// The caps mapping: the adapter's roles, the GATT server probe (a refusal
/// is central-only, O5-11), per-central notifications, and an address that
/// counts as public (RNL1 §3).
#[test]
fn caps_follow_the_adapter_and_the_server_probe() {
    let all = Adapter {
        low_energy: true,
        central: true,
        peripheral: true,
    };
    let c = caps(all, &Server::Works).unwrap();
    assert!(c.central && c.peripheral && !c.l2cap && c.per_central_notify);
    assert_eq!(c.address_privacy, Privacy::Public);

    let refused = Server::Refused("DisabledByPolicy".into());
    let c = caps(all, &refused).unwrap();
    assert!(c.central && !c.peripheral, "central-only");

    let central_only = Adapter {
        peripheral: false,
        ..all
    };
    let c = caps(central_only, &Server::NotTried).unwrap();
    assert!(c.central && !c.peripheral);

    let peripheral_only = Adapter {
        central: false,
        ..all
    };
    let c = caps(peripheral_only, &Server::Works).unwrap();
    assert!(!c.central && c.peripheral);
    match caps(peripheral_only, &refused) {
        Err(RadioState::Unsupported(why)) => assert!(why.contains("DisabledByPolicy"), "{why}"),
        other => panic!("{other:?}"),
    }

    let no_le = Adapter {
        low_energy: false,
        ..all
    };
    assert!(matches!(
        caps(no_le, &Server::Works),
        Err(RadioState::Unsupported(_))
    ));
    let neither = Adapter {
        low_energy: true,
        central: false,
        peripheral: false,
    };
    assert!(matches!(
        caps(neither, &Server::NotTried),
        Err(RadioState::Unsupported(_))
    ));
}

/// A failed setup call: no adapter, refused, or another HRESULT (named by
/// code only).
#[test]
fn setup_errors_map_to_radio_states() {
    match setup_failed("BluetoothAdapter", 0) {
        RadioState::Unsupported(why) => assert!(why.contains("no Bluetooth adapter"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        setup_failed("BluetoothAdapter", E_ACCESSDENIED),
        RadioState::Unauthorized(_)
    ));
    match setup_failed("Radio", 0x8007_048f) {
        RadioState::Unsupported(why) => assert_eq!(why, "Radio: HRESULT 0x8007048F"),
        other => panic!("{other:?}"),
    }
    assert_eq!(bt_error_name(0), "Success");
    assert_eq!(bt_error_name(5), "DisabledByPolicy");
    assert_eq!(bt_error_name(8), "ConsentRequired");
    assert_eq!(bt_error_name(42), "BluetoothError(unknown)");
}

/// RNL1 §3: at most one token on air. Every published service is started;
/// only the advertised one is discoverable, and a change takes the old one
/// off the air before the new one goes on.
#[test]
fn at_most_one_token_is_ever_on_air() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    core.command(Cmd::Services(vec![B, A], Some(A)), now);
    assert_eq!(calls(&mut core), [Call::Create(A), Call::Create(B)]);
    core.created(B, Ok(()), now);
    assert_eq!(calls(&mut core), [Call::Advertise(B, false)]);
    core.created(A, Ok(()), now);
    assert_eq!(calls(&mut core), [Call::Advertise(A, true)]);

    core.command(Cmd::Services(vec![A, B], Some(B)), now);
    assert_eq!(
        calls(&mut core),
        [Call::Advertise(A, false), Call::Advertise(B, true)],
        "off the air first"
    );
    // The same again: nothing restarts.
    core.command(Cmd::Services(vec![A, B], Some(B)), now);
    assert!(calls(&mut core).is_empty());

    core.command(Cmd::Services(vec![B], None), now);
    assert_eq!(
        calls(&mut core),
        [Call::Withdraw(A), Call::Advertise(B, false)]
    );
    // An advert that is not published is not advertised.
    core.command(Cmd::Services(vec![B], Some(A)), now);
    assert!(calls(&mut core).is_empty());
    assert!(drain(&mut rx).is_empty());
}

/// A service withdrawn while its provider is being made is turned down when
/// it is ready; asked for again meanwhile, that one creation is kept.
#[test]
fn a_creation_under_way_is_never_doubled() {
    let now = Instant::now();
    let (mut core, _rx) = new_core();
    core.command(Cmd::Services(vec![A], None), now);
    assert_eq!(calls(&mut core), [Call::Create(A)]);
    assert!(core.creating(&A));
    core.command(Cmd::Services(vec![], None), now);
    assert!(calls(&mut core).is_empty(), "nothing to drop yet");
    core.created(A, Ok(()), now);
    assert_eq!(calls(&mut core), [Call::Withdraw(A)], "turned down");
    assert!(!core.creating(&A) && !core.serving(&A));

    core.command(Cmd::Services(vec![A], None), now);
    core.command(Cmd::Services(vec![], None), now);
    core.command(Cmd::Services(vec![A], None), now);
    assert_eq!(calls(&mut core), [Call::Create(A)], "one creation");
    core.created(A, Ok(()), now);
    assert_eq!(calls(&mut core), [Call::Advertise(A, false)]);
    assert!(core.serving(&A));
    // A late duplicate result changes nothing.
    core.created(A, Ok(()), now);
    assert!(calls(&mut core).is_empty());
}

/// A refused provider (an unpackaged process, policy) or an aborted advert is
/// made again after RETRY; the aborted one's connections end first.
#[test]
fn refused_providers_and_aborted_adverts_are_tried_again() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    core.command(Cmd::Services(vec![A], Some(A)), now);
    assert_eq!(calls(&mut core), [Call::Create(A)]);
    core.created(A, Err("DisabledByPolicy".into()), now);
    assert_eq!(calls(&mut core), [Call::Withdraw(A)]);
    core.tick(now + Duration::from_secs(5));
    assert!(calls(&mut core).is_empty());
    core.tick(now + RETRY);
    assert_eq!(calls(&mut core), [Call::Create(A)]);
    let later = now + RETRY;
    core.created(A, Ok(()), later);
    assert_eq!(calls(&mut core), [Call::Advertise(A, true)]);

    core.subscribers(A, vec![sub(DEV, 182, 244)], later);
    assert_eq!(
        calls(&mut core),
        [Call::PeripheralUp(2, A, DEV.into(), 182)]
    );
    drain(&mut rx);
    core.aborted(A, "RadioNotAvailable", later);
    assert_eq!(calls(&mut core), [Call::Ended(2), Call::Withdraw(A)]);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 2 }]);
    core.tick(later + RETRY);
    assert_eq!(calls(&mut core), [Call::Create(A)]);
}

/// A central subscribed to a published service is one peripheral
/// connection: the send route, then `Connected`, its writes as frames, and
/// one `Disconnected` when it unsubscribes.
#[test]
fn a_subscribed_central_is_one_peripheral_connection() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    serve(&mut core, A, now);
    core.subscribers(A, vec![sub(DEV, 182, 244)], now);
    assert_eq!(
        calls(&mut core),
        [Call::PeripheralUp(2, A, DEV.into(), 182)]
    );
    assert_eq!(
        drain(&mut rx),
        [RadioEvent::Connected {
            conn: 2,
            role: Role::Peripheral,
            service: A,
            max_tx: 182,
            max_rx: 244,
        }]
    );
    core.written(A, DEV.into(), vec![0x01, 0x02], now);
    assert_eq!(
        drain(&mut rx),
        [RadioEvent::Frame {
            conn: 2,
            bytes: vec![0x01, 0x02],
        }]
    );
    // A second central on the same service is its own connection.
    core.subscribers(A, vec![sub(DEV, 182, 244), sub(DEV2, 20, 20)], now);
    assert_eq!(
        calls(&mut core),
        [Call::PeripheralUp(4, A, DEV2.into(), 20)]
    );
    drain(&mut rx);
    core.subscribers(A, vec![sub(DEV2, 20, 20)], now);
    assert_eq!(calls(&mut core), [Call::Ended(2)]);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 2 }]);
    // Withdrawing the service ends the rest, once.
    core.command(Cmd::Services(vec![], None), now);
    assert_eq!(calls(&mut core), [Call::Ended(4), Call::Withdraw(A)]);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 4 }]);
    core.subscribers(A, vec![sub(DEV2, 20, 20)], now);
    assert!(drain(&mut rx).is_empty(), "not served any more");
}

/// A write that arrives before its central's subscription waits for it (up
/// to EARLY_WAIT); a stranger that never subscribes gets nothing.
#[test]
fn an_early_write_waits_for_its_subscription() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    serve(&mut core, A, now);
    core.written(A, DEV.into(), vec![0x01], now);
    core.written(A, DEV.into(), vec![0x02], now);
    assert!(drain(&mut rx).is_empty());
    core.subscribers(A, vec![sub(DEV, 100, 100)], now);
    let evs = drain(&mut rx);
    assert!(matches!(evs[0], RadioEvent::Connected { conn: 2, .. }));
    assert_eq!(
        evs[1..],
        [
            RadioEvent::Frame {
                conn: 2,
                bytes: vec![0x01],
            },
            RadioEvent::Frame {
                conn: 2,
                bytes: vec![0x02],
            },
        ]
    );
    // A stranger's writes expire.
    core.written(A, DEV2.into(), vec![0x09], now);
    core.tick(now + EARLY_WAIT);
    core.subscribers(
        A,
        vec![sub(DEV, 100, 100), sub(DEV2, 100, 100)],
        now + EARLY_WAIT,
    );
    let evs = drain(&mut rx);
    assert_eq!(evs.len(), 1, "{evs:?}");
    assert!(matches!(evs[0], RadioEvent::Connected { conn: 4, .. }));
}

/// A Windows peripheral cannot drop a central: a connection ended here
/// silences that central for SILENCE, unless it unsubscribes first; after
/// that its next write is a new connection.
#[test]
fn a_peripheral_disconnect_silences_that_central() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    serve(&mut core, A, now);
    core.subscribers(A, vec![sub(DEV, 100, 100)], now);
    calls(&mut core);
    drain(&mut rx);
    core.command(Cmd::Disconnect(2), now);
    assert_eq!(calls(&mut core), [Call::Ended(2)]);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 2 }]);
    core.command(Cmd::Disconnect(2), now);
    assert!(drain(&mut rx).is_empty(), "one Disconnected");
    core.written(A, DEV.into(), vec![0x01], now + Duration::from_secs(1));
    core.subscribers(A, vec![sub(DEV, 100, 100)], now + Duration::from_secs(1));
    assert!(drain(&mut rx).is_empty(), "silenced");
    let later = now + SILENCE;
    core.tick(later);
    core.written(A, DEV.into(), vec![0x02], later);
    assert_eq!(
        calls(&mut core),
        [Call::PeripheralUp(4, A, DEV.into(), 100)]
    );
    let evs = drain(&mut rx);
    assert!(matches!(evs[0], RadioEvent::Connected { conn: 4, .. }));
    assert_eq!(
        evs[1],
        RadioEvent::Frame {
            conn: 4,
            bytes: vec![0x02],
        }
    );
    // Unsubscribing lifts a silence at once.
    core.command(Cmd::Disconnect(4), later);
    core.subscribers(A, vec![], later);
    core.subscribers(A, vec![sub(DEV, 100, 100)], later);
    let evs = drain(&mut rx);
    assert!(
        matches!(evs.last(), Some(RadioEvent::Connected { conn: 6, .. })),
        "{evs:?}"
    );
}

/// A central connect: the send route, then `Connected`, then notifications
/// that came first; one `Disconnected` when the link goes.
#[test]
fn a_central_connect_comes_up_in_order() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    core.command(
        Cmd::Connect {
            conn: 1,
            addr: addr(1),
            service: A,
        },
        now,
    );
    assert_eq!(calls(&mut core), [Call::Connect(1, A)]);
    assert!(core.connecting(1));
    core.frame(1, vec![0x02], now);
    assert!(drain(&mut rx).is_empty(), "nothing before Connected");
    core.central_up(1, 244, 244, now);
    assert_eq!(calls(&mut core), [Call::CentralUp(1, 244)]);
    assert_eq!(
        drain(&mut rx),
        [
            RadioEvent::Connected {
                conn: 1,
                role: Role::Central,
                service: A,
                max_tx: 244,
                max_rx: 244,
            },
            RadioEvent::Frame {
                conn: 1,
                bytes: vec![0x02],
            },
        ]
    );
    core.frame(1, vec![0x03], now);
    assert_eq!(
        drain(&mut rx),
        [RadioEvent::Frame {
            conn: 1,
            bytes: vec![0x03],
        }]
    );
    core.writable(1, now);
    assert_eq!(drain(&mut rx), [RadioEvent::Writable { conn: 1 }]);
    core.lost(1, now);
    core.lost(1, now);
    assert_eq!(calls(&mut core), [Call::Ended(1)]);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 1 }]);
    core.writable(1, now);
    core.frame(1, vec![0x04], now);
    assert!(drain(&mut rx).is_empty(), "nothing after Disconnected");
}

/// A connect that ended meanwhile (the engine's disconnect, its deadline, a
/// failure) drops the link it made; too many early notifications end it.
#[test]
fn a_connect_that_ended_meanwhile_drops_its_link() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    let connect = |core: &mut Core<FakeOs>, conn| {
        core.command(
            Cmd::Connect {
                conn,
                addr: addr(conn),
                service: A,
            },
            now,
        );
    };
    connect(&mut core, 1);
    core.command(Cmd::Disconnect(1), now);
    core.central_up(1, 100, 100, now);
    assert_eq!(
        calls(&mut core),
        [Call::Connect(1, A), Call::Ended(1), Call::Ended(1)]
    );
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 1 }]);

    connect(&mut core, 3);
    core.tick(now + CONNECT_BUDGET - Duration::from_millis(1));
    assert!(drain(&mut rx).is_empty());
    core.tick(now + CONNECT_BUDGET);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 3 }]);

    connect(&mut core, 5);
    core.central_failed(5, "no such service", now);
    core.central_failed(5, "no such service", now);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 5 }]);

    connect(&mut core, 7);
    for i in 0..=EARLY_FRAMES {
        core.frame(7, vec![i as u8], now);
    }
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 7 }]);
    calls(&mut core);

    // The same id twice is one connect; powered off, it ends at once.
    connect(&mut core, 9);
    connect(&mut core, 9);
    assert_eq!(calls(&mut core), [Call::Connect(9, A)]);
    assert!(drain(&mut rx).is_empty());
    let (mut off, mut off_rx) = core_with(full_caps(), false, EVENT_QUEUE);
    connect(&mut off, 1);
    assert!(calls(&mut off).is_empty());
    assert_eq!(
        drain(&mut off_rx),
        [
            RadioEvent::State(RadioState::PoweredOff),
            RadioEvent::Disconnected { conn: 1 },
        ]
    );
}

/// Sightings: connectable adverts with a candidate token only, while
/// scanning, at most once a second per address unless its UUIDs change.
#[test]
fn sightings_are_throttled_and_tokens_only() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    core.advert(addr(1), vec![A], -40, true, now);
    assert!(drain(&mut rx).is_empty(), "not scanning");
    core.command(Cmd::Scan(true), now);
    assert_eq!(calls(&mut core), [Call::Scan(true)]);
    core.advert(addr(1), vec![SIG], -40, true, now);
    core.advert(addr(1), vec![A], -40, false, now);
    assert!(drain(&mut rx).is_empty(), "no token, or not connectable");
    core.advert(addr(1), vec![SIG, A], -41, true, now);
    assert_eq!(
        drain(&mut rx),
        [RadioEvent::Seen {
            addr: addr(1).radio_addr(),
            uuids: vec![A],
            rssi: -41,
        }]
    );
    core.advert(
        addr(1),
        vec![A],
        -42,
        true,
        now + Duration::from_millis(500),
    );
    assert!(drain(&mut rx).is_empty(), "throttled");
    core.advert(
        addr(1),
        vec![B],
        -42,
        true,
        now + Duration::from_millis(600),
    );
    core.advert(
        addr(2),
        vec![A],
        -50,
        true,
        now + Duration::from_millis(600),
    );
    core.advert(
        addr(1),
        vec![B],
        -43,
        true,
        now + Duration::from_millis(1600),
    );
    let seen: Vec<(RadioAddr, Vec<[u8; 16]>)> = drain(&mut rx)
        .into_iter()
        .map(|e| match e {
            RadioEvent::Seen { addr, uuids, .. } => (addr, uuids),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        seen,
        [
            (addr(1).radio_addr(), vec![B]),
            (addr(2).radio_addr(), vec![A]),
            (addr(1).radio_addr(), vec![B]),
        ]
    );
    core.command(Cmd::Scan(false), now);
    assert_eq!(calls(&mut core), [Call::Scan(false)]);
    core.advert(addr(3), vec![A], -40, true, now + Duration::from_secs(3));
    assert!(drain(&mut rx).is_empty());
}

/// A watcher that stops by itself is started again after RETRY; a
/// central-less radio never scans.
#[test]
fn a_stopped_scan_is_tried_again() {
    let now = Instant::now();
    let (mut core, _rx) = new_core();
    core.command(Cmd::Scan(true), now);
    assert_eq!(calls(&mut core), [Call::Scan(true)]);
    core.scan_stopped("RadioNotAvailable", now);
    core.tick(now + Duration::from_secs(1));
    assert!(calls(&mut core).is_empty());
    core.tick(now + RETRY);
    assert_eq!(calls(&mut core), [Call::Scan(true)]);

    let no_central = RadioCaps {
        central: false,
        ..full_caps()
    };
    let (mut core, _rx) = core_with(no_central, true, EVENT_QUEUE);
    core.command(Cmd::Scan(true), now);
    assert!(calls(&mut core).is_empty());
}

/// Power off ends every connection and the scan; power on starts the
/// providers and the scan again.
#[test]
fn a_power_cycle_ends_connections_and_starts_again() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    core.command(Cmd::Services(vec![A], Some(A)), now);
    core.created(A, Ok(()), now);
    core.command(Cmd::Scan(true), now);
    core.subscribers(A, vec![sub(DEV, 100, 100)], now);
    core.command(
        Cmd::Connect {
            conn: 1,
            addr: addr(1),
            service: B,
        },
        now,
    );
    calls(&mut core);
    drain(&mut rx);
    core.power(false, now);
    let mut evs = drain(&mut rx);
    assert_eq!(evs.remove(0), RadioEvent::State(RadioState::PoweredOff));
    evs.sort_by_key(|e| e.conn());
    assert_eq!(
        evs,
        [
            RadioEvent::Disconnected { conn: 1 },
            RadioEvent::Disconnected { conn: 2 },
        ]
    );
    let mut ended = calls(&mut core);
    assert_eq!(ended.pop(), Some(Call::Scan(false)));
    ended.sort_by_key(|c| format!("{c:?}"));
    assert_eq!(ended, [Call::Ended(1), Call::Ended(2)]);
    core.power(false, now);
    assert!(drain(&mut rx).is_empty());
    core.power(true, now);
    assert_eq!(drain(&mut rx), [RadioEvent::State(RadioState::PoweredOn)]);
    assert_eq!(
        calls(&mut core),
        [Call::Advertise(A, true), Call::Scan(true)]
    );
}

/// A wanted service is created only while the radio is on.
#[test]
fn services_wait_for_power() {
    let now = Instant::now();
    let (mut core, mut rx) = core_with(full_caps(), false, EVENT_QUEUE);
    core.command(Cmd::Services(vec![A], Some(A)), now);
    core.command(Cmd::Scan(true), now);
    assert!(calls(&mut core).is_empty());
    core.power(true, now);
    assert_eq!(calls(&mut core), [Call::Create(A), Call::Scan(true)]);
    assert_eq!(
        drain(&mut rx),
        [
            RadioEvent::State(RadioState::PoweredOff),
            RadioEvent::State(RadioState::PoweredOn),
        ]
    );
}

/// Stop: every connection ends once, every provider and the watcher stop,
/// and nothing happens after.
#[test]
fn stop_ends_everything_once() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core();
    serve(&mut core, A, now);
    core.command(Cmd::Scan(true), now);
    core.subscribers(A, vec![sub(DEV, 100, 100)], now);
    calls(&mut core);
    drain(&mut rx);
    core.command(Cmd::Stop, now);
    assert!(!core.alive());
    assert_eq!(
        calls(&mut core),
        [Call::Ended(2), Call::Withdraw(A), Call::Scan(false)]
    );
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 2 }]);
    core.command(Cmd::Services(vec![B], Some(B)), now);
    core.command(Cmd::Scan(true), now);
    core.power(false, now);
    core.tick(now + RETRY);
    assert!(calls(&mut core).is_empty());
    assert!(drain(&mut rx).is_empty());
}

/// RNL1 §8: a connection whose event the full queue lost is ended (its
/// `Disconnected` owed by the queue).
#[test]
fn a_lost_event_ends_its_connection() {
    let now = Instant::now();
    let (mut core, mut rx) = core_with(full_caps(), true, 2);
    serve(&mut core, A, now);
    core.subscribers(A, vec![sub(DEV, 100, 100)], now);
    calls(&mut core);
    // State + Connected fill the queue; the frame is lost.
    core.written(A, DEV.into(), vec![0x01], now);
    assert_eq!(calls(&mut core), [Call::Ended(2)]);
    assert_eq!(core.dropped(), 1);
    drain(&mut rx);
    core.tick(now);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 2 }]);
}

/// A writer that records frames.
#[derive(Clone, Default)]
struct Rec(Arc<Mutex<Vec<Vec<u8>>>>, bool);

impl Push for Rec {
    fn push(&self, frame: Vec<u8>) -> bool {
        self.0.lock().unwrap().push(frame);
        !self.1
    }
}

/// The send table: frames within max_tx go to the connection's writer, at
/// most SEND_WINDOW queued, then WouldBlock and exactly one Writable owed.
#[test]
fn the_send_table_windows_frames() {
    let mut table: Table<Rec> = Table::default();
    assert_eq!(table.send(1, &[0x11]), Err("not connected".into()));
    let rec = Rec::default();
    table.add(1, rec.clone(), 64);
    assert!(table.send(1, &[]).is_err());
    assert!(table.send(1, &[0; 65]).is_err());
    for i in 0..SEND_WINDOW {
        assert_eq!(table.send(1, &[i as u8; 64]), Ok(Sent::Queued));
    }
    assert_eq!(table.send(1, &[0x11]), Ok(Sent::WouldBlock));
    assert_eq!(table.send(1, &[0x11]), Ok(Sent::WouldBlock));
    assert_eq!(rec.0.lock().unwrap().len(), SEND_WINDOW);
    assert!(table.sent(1), "one Writable owed");
    assert!(!table.sent(1), "once");
    assert_eq!(table.send(1, &[0x12]), Ok(Sent::Queued));
    assert!(!table.sent(2), "unknown connection");
    let gone = Rec(Arc::default(), true);
    table.add(3, gone, 64);
    assert_eq!(table.send(3, &[0x11]), Err("not connected".into()));
    table.remove(1);
    assert!(table.send(1, &[0x11]).is_err());
    // The writer tasks' own channel.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut table = Table::default();
    table.add(5, tx, 20);
    assert_eq!(table.send(5, &[0x11, 0]), Ok(Sent::Queued));
    assert_eq!(rx.try_recv().unwrap(), vec![0x11, 0]);
    drop(rx);
    assert_eq!(table.send(5, &[0x11]), Err("not connected".into()));
}
