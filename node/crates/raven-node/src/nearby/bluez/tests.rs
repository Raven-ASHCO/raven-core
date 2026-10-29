//! The BlueZ backend's pure part (no bus, no radio): UUID forms, the objects
//! served to BlueZ, and the state machine over scripted message sequences.

use std::time::{Duration, Instant};

use raven_core::nearby_link::{char_uuid, uuid_string, Role};
use tokio::sync::mpsc;

use super::*;
use crate::nearby::radio::{EventTx, Privacy, RadioAddr, RadioCaps, RadioEvent, EVENT_QUEUE};

const ADAPTER_PATH: &str = "/org/bluez/hci0";
/// BlueZ's unique name on the bus.
const BLUEZ_NAME: &str = ":1.7";
/// Device objects (documentation-only addresses).
const DEV: &str = "/org/bluez/hci0/dev_00_00_5E_00_53_01";
const DEV2: &str = "/org/bluez/hci0/dev_00_00_5E_00_53_02";
const T: [u8; 16] = [
    0x06, 0x2a, 0x8a, 0xc6, 0x9e, 0x02, 0x4a, 0xbb, 0xab, 0x83, 0xf9, 0xea, 0xbb, 0x5e, 0x8d, 0x99,
];
const T2: [u8; 16] = [0x22; 16];

/// Records what [`Core`] asks of the bus; serials count up from 1.
#[derive(Default)]
struct FakeBus {
    serial: u32,
    calls: Vec<(u32, Call)>,
    notified: Vec<(ConnId, String, Vec<u8>)>,
    central: Vec<(ConnId, i32, i32, usize, usize)>,
    reading: Vec<ConnId>,
    peripheral: Vec<(ConnId, usize)>,
    ended: Vec<ConnId>,
    broken: bool,
}

impl Bus for FakeBus {
    type Fd = i32;

    fn call(&mut self, call: Call) -> Result<u32, String> {
        if self.broken {
            return Err("org.freedesktop.DBus.Error.Disconnected".to_owned());
        }
        self.serial += 1;
        self.calls.push((self.serial, call));
        Ok(self.serial)
    }

    fn notify(&mut self, conn: ConnId, chr: &str, value: &[u8]) {
        self.notified.push((conn, chr.to_owned(), value.to_vec()));
    }

    fn central_up(&mut self, conn: ConnId, notify: i32, write: i32, max_tx: usize, max_rx: usize) {
        self.central.push((conn, notify, write, max_tx, max_rx));
    }

    fn start_reading(&mut self, conn: ConnId) {
        self.reading.push(conn);
    }

    fn peripheral_up(&mut self, conn: ConnId, max_tx: usize) {
        self.peripheral.push((conn, max_tx));
    }

    fn ended(&mut self, conn: ConnId) {
        self.ended.push(conn);
    }
}

impl FakeBus {
    /// The calls since the last look, as (serial, member, path).
    fn take(&mut self) -> Vec<(u32, &'static str, String)> {
        std::mem::take(&mut self.calls)
            .into_iter()
            .map(|(serial, c)| (serial, c.member, c.path))
            .collect()
    }
}

fn caps() -> RadioCaps {
    RadioCaps {
        central: true,
        peripheral: true,
        l2cap: false,
        address_privacy: Privacy::Random,
        per_central_notify: false,
    }
}

fn core_with(caps: RadioCaps, now: Instant) -> (Core<FakeBus>, mpsc::Receiver<RadioEvent>) {
    let (tx, rx) = mpsc::channel(EVENT_QUEUE);
    let start = Start {
        adapter: ADAPTER_PATH.to_owned(),
        bluez: BLUEZ_NAME.to_owned(),
        caps,
        powered: true,
        devices: vec![(
            DEV.to_owned(),
            DeviceProps {
                connected: Some(false),
                ..DeviceProps::default()
            },
        )],
    };
    let mut core = Core::new(FakeBus::default(), EventTx::new(tx), start, now);
    core.start();
    (core, rx)
}

fn new_core(now: Instant) -> (Core<FakeBus>, mpsc::Receiver<RadioEvent>) {
    core_with(caps(), now)
}

/// Everything queued now.
fn drain(rx: &mut mpsc::Receiver<RadioEvent>) -> Vec<RadioEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

fn device(props: DeviceProps) -> Signal {
    Signal::Device {
        path: DEV.to_owned(),
        props,
    }
}

fn bluez() -> Option<&'static str> {
    Some(BLUEZ_NAME)
}

/// The services and the advert as registered by the replies to every
/// registration call so far.
fn register_all(core: &mut Core<FakeBus>, now: Instant) -> Vec<(u32, &'static str, String)> {
    let mut seen = Vec::new();
    loop {
        let calls = core.bus.take();
        if calls.is_empty() {
            return seen;
        }
        for (serial, member, path) in calls {
            core.reply(serial, Reply::Done, now);
            seen.push((serial, member, path));
        }
    }
}

// ── UUIDs and paths ─────────────────────────────────────────────────────────

/// P5.29: the UUID text forms BlueZ uses parse to the bytes of the shared
/// vectors (token and characteristic), and SIG UUIDs are never tokens.
#[test]
fn uuid_strings_match_the_vectors() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../shared-vectors/rvn1/nearby/rnb1_tokens_001.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let tokens = v["expected"]["tokens"].as_array().unwrap();
    assert!(tokens.len() >= 4);
    for tok in tokens {
        let hex16 = |k: &str| -> [u8; 16] {
            hex::decode(tok[k].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let (t, c) = (hex16("token_hex"), hex16("char_uuid_hex"));
        let (ts, cs) = (
            tok["uuid_string"].as_str().unwrap(),
            tok["char_uuid_string"].as_str().unwrap(),
        );
        assert_eq!(uuid_parse(ts), Some(t));
        assert_eq!(uuid_parse(&ts.to_uppercase()), Some(t), "either case");
        assert_eq!(uuid_string(&t), ts);
        assert_eq!(char_uuid(&t), c);
        assert_eq!(uuid_parse(cs), Some(c));
        assert!(!is_sig_uuid(&t) && !is_sig_uuid(&c));
    }
    assert_eq!(
        T,
        hex::decode("062a8ac69e024abbab83f9eabb5e8d99").unwrap()[..]
    );
    // 16-bit UUIDs written long (Battery, Device Information).
    for sig in [
        "0000180f-0000-1000-8000-00805f9b34fb",
        "0000180A-0000-1000-8000-00805F9B34FB",
    ] {
        assert!(is_sig_uuid(&uuid_parse(sig).unwrap()), "{sig}");
    }
    for bad in [
        "062a8ac69e024abbab83f9eabb5e8d99",
        "062a8ac6-9e02-4abb-ab83-f9eabb5e8d9",
        "062a8ac6-9e02-4abb-ab83-f9eabb5e8d99a",
        "062a8ac6-9e02-4abb-ab83f-9eabb5e8d99",
        "062a8ac6-9e02-4abb-ab83-f9eabb5e8d9g",
        "",
    ] {
        assert_eq!(uuid_parse(bad), None, "{bad}");
    }
}

#[test]
fn object_paths_name_this_process_objects_only() {
    assert_eq!(object_of("/org/raven/nearby/app0"), Some(Obj::App(0)));
    assert_eq!(
        object_of("/org/raven/nearby/app12/svc0"),
        Some(Obj::Service(12))
    );
    assert_eq!(
        object_of("/org/raven/nearby/app3/svc0/chr0"),
        Some(Obj::Char(3))
    );
    assert_eq!(object_of("/org/raven/nearby/adv7"), Some(Obj::Adv(7)));
    for other in [
        "/org/raven/nearby",
        "/org/raven/nearby/app",
        "/org/raven/nearby/app01",
        "/org/raven/nearby/app1/svc1",
        "/org/raven/nearby/app1/svc0/chr0/desc0",
        "/org/raven/nearbyx/app1",
        "/org/bluez/hci0",
    ] {
        assert_eq!(object_of(other), None, "{other}");
    }
    assert_eq!(char_path(2), "/org/raven/nearby/app2/svc0/chr0");
    assert_eq!(frame_limit(23), 20);
    assert_eq!(frame_limit(0), 20, "never under ATT's default");
    assert_eq!(frame_limit(185), 182);
    assert_eq!(frame_limit(517), 512);
    assert_eq!(frame_limit(u16::MAX), 512);
}

// ── The objects served to BlueZ ─────────────────────────────────────────────

/// The golden GetManagedObjects of the application serving the vectors'
/// alice token, and its advert's properties (D-Bus signatures as keys).
const GOLDEN: &str = r#"{
  "/org/raven/nearby/app0/svc0": {
    "org.bluez.GattService1": {
      "Primary": { "b": true },
      "UUID": { "s": "062a8ac6-9e02-4abb-ab83-f9eabb5e8d99" }
    }
  },
  "/org/raven/nearby/app0/svc0/chr0": {
    "org.bluez.GattCharacteristic1": {
      "Flags": { "as": ["write-without-response", "write", "notify"] },
      "Service": { "o": "/org/raven/nearby/app0/svc0" },
      "UUID": { "s": "482a83ca-d420-4a92-9f9b-6573385a6b05" }
    }
  }
}"#;

const GOLDEN_ADV: &str = r#"{
  "ServiceUUIDs": { "as": ["062a8ac6-9e02-4abb-ab83-f9eabb5e8d99"] },
  "Type": { "s": "peripheral" }
}"#;

fn json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap()
}

/// P5.29: GetManagedObjects of a published service matches the golden map
/// (one primary service, one characteristic with WwR | W | N and no read);
/// the advert carries only the token (no Includes, no LocalName); every
/// object answers GetAll and Get on its own interface only.
#[test]
fn managed_objects_match_the_golden_map() {
    let now = Instant::now();
    let (mut core, _rx) = new_core(now);
    assert_eq!(
        serde_json::to_value(app_objects(0, &T)).unwrap(),
        json(GOLDEN)
    );
    core.command(Cmd::Services(vec![T], Some(T)), now);
    // BlueZ asks while RegisterApplication is in flight.
    let answer = core.call(
        bluez(),
        "/org/raven/nearby/app0",
        Incoming::ManagedObjects,
        now,
    );
    let Answer::Objects(objects) = answer else {
        panic!("{answer:?}");
    };
    assert_eq!(serde_json::to_value(objects).unwrap(), json(GOLDEN));
    register_all(&mut core, now);
    let adv = core.call(
        bluez(),
        "/org/raven/nearby/adv0",
        Incoming::GetAll(ADVERTISEMENT.to_owned()),
        now,
    );
    let Answer::Props(props) = adv else {
        panic!("{adv:?}");
    };
    assert_eq!(serde_json::to_value(props).unwrap(), json(GOLDEN_ADV));
    let get = |core: &mut Core<FakeBus>, path: &str, iface: &str, prop: &str| {
        core.call(
            bluez(),
            path,
            Incoming::Get(iface.to_owned(), prop.to_owned()),
            now,
        )
    };
    assert_eq!(
        get(
            &mut core,
            "/org/raven/nearby/app0/svc0",
            GATT_SERVICE,
            "Primary"
        ),
        Answer::Prop(Prop::Bool(true))
    );
    assert_eq!(
        get(
            &mut core,
            "/org/raven/nearby/app0/svc0/chr0",
            GATT_CHAR,
            "Value"
        ),
        Answer::Error(UNKNOWN_PROPERTY),
        "no readable value"
    );
    assert_eq!(
        get(&mut core, "/org/raven/nearby/app0/svc0", GATT_CHAR, "UUID"),
        Answer::Error(UNKNOWN_INTERFACE)
    );
    assert_eq!(
        core.call(
            bluez(),
            "/org/raven/nearby/app0/svc0/chr0",
            Incoming::Read,
            now
        ),
        Answer::Error(NOT_SUPPORTED)
    );
    assert_eq!(
        core.call(
            bluez(),
            "/org/raven/nearby/app1",
            Incoming::ManagedObjects,
            now
        ),
        Answer::Error(UNKNOWN_OBJECT),
        "nothing published there"
    );
    assert_eq!(
        core.call(
            bluez(),
            "/org/raven/nearby/adv1",
            Incoming::GetAll(ADVERTISEMENT.into()),
            now
        ),
        Answer::Error(UNKNOWN_OBJECT)
    );
}

/// Only BlueZ calls this process's objects or moves its state: a call or a
/// unicast signal from any other name is refused or ignored.
#[test]
fn only_bluez_calls_or_signals() {
    let now = Instant::now();
    let (mut core, mut rx) = new_core(now);
    core.command(Cmd::Services(vec![T], None), now);
    for sender in [None, Some(":1.99"), Some(BUS_DAEMON)] {
        assert_eq!(
            core.call(
                sender,
                "/org/raven/nearby/app0",
                Incoming::ManagedObjects,
                now
            ),
            Answer::Error(ACCESS_DENIED)
        );
    }
    drain(&mut rx);
    // A stranger's "adapter off" and "BlueZ stopped" change nothing.
    core.signal(
        Some(":1.99"),
        Signal::Adapter {
            path: ADAPTER_PATH.to_owned(),
            powered: Some(false),
        },
        now,
    );
    core.signal(Some(BLUEZ_NAME), Signal::Owner(None), now);
    assert!(drain(&mut rx).is_empty());
    assert!(core.alive());
    // The bus daemon's NameOwnerChanged is the real one.
    core.signal(Some(BUS_DAEMON), Signal::Owner(None), now);
    assert!(!core.alive());
    assert_eq!(
        drain(&mut rx),
        [RadioEvent::State(RadioState::Unsupported(
            "BlueZ stopped".into()
        ))]
    );
}

// ── Calls and replies ───────────────────────────────────────────────────────

/// P5.29, the reply-serial matcher: a central connect over a scripted
/// sequence. Every call is matched by its reply's serial only; a stranger's
/// reply, a duplicate and a late one match nothing; BlueZ's signals and
/// calls interleave freely; the sockets' replies come in either order.
#[test]
fn reply_serial_matcher_over_a_scripted_sequence() {
    let t0 = Instant::now();
    let (mut core, mut rx) = new_core(t0);
    assert_eq!(drain(&mut rx), [RadioEvent::State(RadioState::PoweredOn)]);

    // Scan: the filter, then StartDiscovery after its reply.
    core.command(Cmd::Scan(true), t0);
    let calls = core.bus.take();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        (calls[0].1, calls[0].2.as_str()),
        ("SetDiscoveryFilter", ADAPTER_PATH)
    );
    assert_eq!(core.expects(calls[0].0), Some(Expect::Nothing));
    // A reply to a serial nobody sent is nothing.
    assert_eq!(core.expects(999), None);
    core.reply(999, Reply::Done, t0);
    assert!(core.bus.take().is_empty());
    core.reply(
        calls[0].0,
        Reply::Failed("org.bluez.Error.NotSupported".into()),
        t0,
    );
    let start = core.bus.take();
    assert_eq!(start[0].1, "StartDiscovery");
    core.reply(
        start[0].0,
        Reply::Failed("org.bluez.Error.InProgress".into()),
        t0,
    );
    assert_eq!(core.pending_calls(), 0);

    // A sighting: tokens only (no SIG UUID), with the RSSI.
    let battery = uuid_parse("0000180f-0000-1000-8000-00805f9b34fb").unwrap();
    core.signal(
        bluez(),
        device(DeviceProps {
            uuids: Some(vec![battery, T]),
            rssi: Some(-52),
            ..DeviceProps::default()
        }),
        t0,
    );
    assert_eq!(
        drain(&mut rx),
        [RadioEvent::Seen {
            addr: RadioAddr(DEV.to_owned()),
            uuids: vec![T],
            rssi: -52,
        }]
    );

    // Connect: Device1.Connect.
    core.command(
        Cmd::Connect {
            conn: 1,
            device: DEV.to_owned(),
            service: T,
        },
        t0,
    );
    let connect = core.bus.take();
    assert_eq!((connect[0].1, connect[0].2.as_str()), ("Connect", DEV));
    // ServicesResolved arrives before Connect's reply (BlueZ's order for LE).
    core.signal(
        bluez(),
        device(DeviceProps {
            connected: Some(true),
            resolved: Some(true),
            ..DeviceProps::default()
        }),
        t0,
    );
    assert!(core.bus.take().is_empty(), "nothing before Connect's reply");
    // BlueZ calls in between: answered at once, no serial consumed.
    assert_eq!(
        core.call(
            bluez(),
            "/org/raven/nearby/app0",
            Incoming::ManagedObjects,
            t0
        ),
        Answer::Error(UNKNOWN_OBJECT)
    );
    core.reply(connect[0].0, Reply::Done, t0);
    let find = core.bus.take();
    assert_eq!((find[0].1, find[0].2.as_str()), ("GetManagedObjects", "/"));
    assert_eq!(core.expects(find[0].0), Some(Expect::Objects));
    // The service on this device and its characteristic, among others: a
    // same-UUID service on another device and a wrong characteristic.
    let svc = format!("{DEV}/service0010");
    let objects = vec![
        Remote::Service {
            path: format!("{DEV2}/service0010"),
            uuid: T,
            device: DEV2.to_owned(),
        },
        Remote::Char {
            path: format!("{svc}/char0011"),
            uuid: T,
            service: svc.clone(),
        },
        Remote::Service {
            path: svc.clone(),
            uuid: T,
            device: DEV.to_owned(),
        },
        Remote::Char {
            path: format!("{svc}/char0013"),
            uuid: char_uuid(&T),
            service: svc.clone(),
        },
    ];
    core.reply(find[0].0, Reply::Objects(objects), t0);
    let acquire = core.bus.take();
    let chr = format!("{svc}/char0013");
    assert_eq!(
        acquire
            .iter()
            .map(|(_, m, p)| (*m, p.as_str()))
            .collect::<Vec<_>>(),
        [
            ("AcquireNotify", chr.as_str()),
            ("AcquireWrite", chr.as_str())
        ]
    );
    assert_eq!(core.expects(acquire[0].0), Some(Expect::Socket));
    // The write socket first, then the notify socket; then a duplicate.
    core.reply(acquire[1].0, Reply::Socket { fd: 41, mtu: 185 }, t0);
    assert!(drain(&mut rx).is_empty(), "not up with one socket");
    core.reply(acquire[0].0, Reply::Socket { fd: 40, mtu: 247 }, t0);
    core.reply(acquire[0].0, Reply::Socket { fd: 42, mtu: 247 }, t0);
    assert_eq!(core.bus.central, [(1, 40, 41, 182, 244)]);
    assert_eq!(core.bus.reading, [1]);
    assert_eq!(
        drain(&mut rx),
        [RadioEvent::Connected {
            conn: 1,
            role: Role::Central,
            service: T,
            max_tx: 182,
            max_rx: 244,
        }]
    );
    assert_eq!(core.pending_calls(), 0);

    // The engine ends it: one Disconnected, the I/O stops, the link drops.
    core.command(Cmd::Disconnect(1), t0);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 1 }]);
    assert_eq!(core.bus.ended, [1]);
    let disconnect = core.bus.take();
    assert_eq!(
        (disconnect[0].1, disconnect[0].2.as_str()),
        ("Disconnect", DEV)
    );
    core.command(Cmd::Disconnect(1), t0);
    assert!(drain(&mut rx).is_empty(), "exactly one Disconnected");
}

/// A connect that fails anywhere ends in exactly one `Disconnected`: a
/// refused Connect, no such service (a token BlueZ remembers but the device
/// no longer serves), a refused socket, a deadline; a late reply after the
/// end matches nothing.
#[test]
fn a_failed_connect_ends_once() {
    let t0 = Instant::now();
    let (mut core, mut rx) = new_core(t0);
    drain(&mut rx);
    let connect = |core: &mut Core<FakeBus>, conn: ConnId| {
        core.command(
            Cmd::Connect {
                conn,
                device: DEV.to_owned(),
                service: T,
            },
            t0,
        );
        core.bus.take()[0].0
    };
    // Refused.
    let s = connect(&mut core, 1);
    core.reply(s, Reply::Failed("org.bluez.Error.Failed".into()), t0);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 1 }]);
    assert!(
        core.bus.take().is_empty(),
        "nothing came up: no Disconnect call"
    );

    // Connected, but the service is not there.
    let s = connect(&mut core, 3);
    core.signal(
        bluez(),
        device(DeviceProps {
            connected: Some(true),
            resolved: Some(true),
            ..DeviceProps::default()
        }),
        t0,
    );
    core.reply(
        s,
        Reply::Failed("org.bluez.Error.AlreadyConnected".into()),
        t0,
    );
    let find = core.bus.take()[0].0;
    core.reply(find, Reply::Objects(Vec::new()), t0);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 3 }]);
    assert_eq!(core.bus.take()[0].1, "Disconnect");

    // A refused socket ends it; the other socket's late reply is dropped.
    let s = connect(&mut core, 5);
    core.reply(s, Reply::Done, t0);
    let find = core.bus.take()[0].0;
    let svc = format!("{DEV}/service0010");
    core.reply(
        find,
        Reply::Objects(vec![
            Remote::Service {
                path: svc.clone(),
                uuid: T,
                device: DEV.to_owned(),
            },
            Remote::Char {
                path: format!("{svc}/char0011"),
                uuid: char_uuid(&T),
                service: svc,
            },
        ]),
        t0,
    );
    let acquire = core.bus.take();
    core.reply(
        acquire[0].0,
        Reply::Failed("org.bluez.Error.NotPermitted".into()),
        t0,
    );
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 5 }]);
    core.reply(acquire[1].0, Reply::Socket { fd: 9, mtu: 185 }, t0);
    assert!(drain(&mut rx).is_empty());
    assert!(core.bus.central.is_empty());

    // No reply in time: the connect budget ends it (and drops the link);
    // every call expires CALL_DEADLINE after it went out.
    connect(&mut core, 7);
    core.tick(t0 + CONNECT_BUDGET);
    assert!(drain(&mut rx).contains(&RadioEvent::Disconnected { conn: 7 }));
    core.tick(t0 + CALL_DEADLINE);
    assert_eq!(core.pending_calls(), 1, "the Disconnect sent at the budget");
    core.tick(t0 + CONNECT_BUDGET + CALL_DEADLINE);
    assert_eq!(core.pending_calls(), 0);
    assert!(
        drain(&mut rx).is_empty(),
        "a late failure ends nothing twice"
    );

    // A device that is not under this adapter, or the adapter off.
    core.command(
        Cmd::Connect {
            conn: 9,
            device: "/org/bluez/hci1/dev_00_00_5E_00_53_01".to_owned(),
            service: T,
        },
        t0,
    );
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 9 }]);
    assert!(core.bus.take().iter().all(|(_, m, _)| *m != "Connect"));
}

// ── Publishing ──────────────────────────────────────────────────────────────

/// P5.29, the deadlock case: BlueZ calls GetManagedObjects back before it
/// answers RegisterApplication, and gets the application's objects. One
/// application per service: withdrawing one never touches another; the
/// advert follows its application, one registration at a time, a new path
/// each time.
#[test]
fn register_application_is_answered_before_its_reply() {
    let t0 = Instant::now();
    let (mut core, _rx) = new_core(t0);
    core.command(Cmd::Services(vec![T, T2], Some(T)), t0);
    let calls = core.bus.take();
    assert_eq!(
        calls
            .iter()
            .map(|(_, m, p)| (*m, p.as_str()))
            .collect::<Vec<_>>(),
        [
            ("RegisterApplication", ADAPTER_PATH),
            ("RegisterApplication", ADAPTER_PATH)
        ],
        "no advert before its application is registered"
    );
    // BlueZ reads both applications before answering (the services are a
    // sorted set: T, 0x06.., takes slot 0 and T2 slot 1).
    for (slot, t) in [(0, T), (1, T2)] {
        assert_eq!(
            core.call(bluez(), &app_path(slot), Incoming::ManagedObjects, t0),
            Answer::Objects(app_objects(slot, &t)),
            "app{slot}"
        );
    }
    core.reply(calls[0].0, Reply::Done, t0);
    let adv = core.bus.take();
    assert_eq!(
        adv.iter().map(|(_, m, _)| *m).collect::<Vec<_>>(),
        ["RegisterAdvertisement"]
    );
    core.reply(
        calls[1].0,
        Reply::Failed("org.bluez.Error.AlreadyExists".into()),
        t0,
    );
    core.reply(adv[0].0, Reply::Done, t0);
    assert!(core.bus.take().is_empty());

    // The rotation moves the advert to T2: unregister, then register anew.
    core.command(Cmd::Services(vec![T, T2], Some(T2)), t0);
    let un = core.bus.take();
    assert_eq!(un[0].1, "UnregisterAdvertisement");
    core.command(Cmd::Services(vec![T, T2], Some(T)), t0);
    assert!(
        core.bus.take().is_empty(),
        "one advert call in flight at a time"
    );
    core.reply(un[0].0, Reply::Done, t0);
    let re = core.bus.take();
    assert_eq!(re[0].1, "RegisterAdvertisement");
    core.reply(re[0].0, Reply::Done, t0);
    let Answer::Props(props) = core.call(
        bluez(),
        &adv_path(1),
        Incoming::GetAll(ADVERTISEMENT.into()),
        t0,
    ) else {
        panic!("adv1")
    };
    assert_eq!(props["ServiceUUIDs"], Prop::Strs(vec![uuid_string(&T)]));

    // T2 withdrawn: only its application goes; T's stays (slot 0).
    core.command(Cmd::Services(vec![T], Some(T)), t0);
    let calls = core.bus.take();
    assert_eq!(
        calls
            .iter()
            .map(|(_, m, p)| (*m, p.as_str()))
            .collect::<Vec<_>>(),
        [("UnregisterApplication", ADAPTER_PATH)]
    );
    core.reply(calls[0].0, Reply::Done, t0);
    assert!(core.bus.take().is_empty());
    assert!(matches!(
        core.call(bluez(), &app_path(0), Incoming::ManagedObjects, t0),
        Answer::Objects(_)
    ));
    assert_eq!(
        core.call(bluez(), &app_path(1), Incoming::ManagedObjects, t0),
        Answer::Error(UNKNOWN_OBJECT)
    );

    // BlueZ releases the advert: registered again (a new path).
    assert_eq!(
        core.call(bluez(), &adv_path(1), Incoming::Release, t0),
        Answer::Unit
    );
    let again = core.bus.take();
    assert_eq!(again[0].1, "RegisterAdvertisement");

    // A refused registration is tried again after RETRY, not before.
    core.command(Cmd::Services(vec![T, T2], Some(T)), t0);
    let reg = core.bus.take();
    assert_eq!(reg[0].1, "RegisterApplication");
    core.reply(reg[0].0, Reply::Failed("org.bluez.Error.Failed".into()), t0);
    core.tick(t0 + RETRY / 2);
    assert!(core.bus.take().is_empty());
    core.tick(t0 + RETRY);
    assert_eq!(core.bus.take()[0].1, "RegisterApplication");
}

/// A radio without the peripheral role publishes nothing and never
/// advertises; with the adapter off no advert is registered.
#[test]
fn no_peripheral_role_publishes_nothing() {
    let t0 = Instant::now();
    let mut central_only = caps();
    central_only.peripheral = false;
    let (mut core, _rx) = core_with(central_only, t0);
    core.command(Cmd::Services(vec![T], Some(T)), t0);
    assert!(core.bus.take().is_empty());

    let (mut core, mut rx) = new_core(t0);
    core.signal(
        bluez(),
        Signal::Adapter {
            path: ADAPTER_PATH.to_owned(),
            powered: Some(false),
        },
        t0,
    );
    core.command(Cmd::Services(vec![T], Some(T)), t0);
    let reg = core.bus.take();
    assert_eq!(reg.len(), 1, "the application, not the advert");
    core.reply(reg[0].0, Reply::Done, t0);
    assert!(core.bus.take().is_empty());
    drain(&mut rx);
    core.signal(
        bluez(),
        Signal::Adapter {
            path: ADAPTER_PATH.to_owned(),
            powered: Some(true),
        },
        t0,
    );
    assert_eq!(drain(&mut rx), [RadioEvent::State(RadioState::PoweredOn)]);
    assert_eq!(core.bus.take()[0].1, "RegisterAdvertisement");
}

// ── Peripheral connections ──────────────────────────────────────────────────

/// P5.29: a central that subscribed and writes is one connection (its first
/// write opens it, with the MTU BlueZ names); its sends become
/// notifications on that characteristic (BlueZ broadcasts them: the radio
/// says per_central_notify = false). A connection this side ends silences
/// that central on that service for a while; StopNotify and a dropped link
/// end connections too, each with one Disconnected.
#[test]
fn a_subscribed_central_writing_is_one_peripheral_connection() {
    let t0 = Instant::now();
    let (mut core, mut rx) = new_core(t0);
    core.command(Cmd::Services(vec![T], None), t0);
    register_all(&mut core, t0);
    drain(&mut rx);
    let chr = "/org/raven/nearby/app0/svc0/chr0";
    let write = |core: &mut Core<FakeBus>, dev: &str, bytes: &[u8]| {
        core.call(
            bluez(),
            chr,
            Incoming::Write {
                value: bytes.to_vec(),
                device: Some(dev.to_owned()),
                mtu: Some(185),
            },
            t0,
        )
    };
    // No subscription yet: a write is no connection.
    assert_eq!(write(&mut core, DEV, b"hello"), Answer::Unit);
    assert!(drain(&mut rx).is_empty());
    assert_eq!(
        core.call(bluez(), chr, Incoming::StartNotify, t0),
        Answer::Unit
    );
    write(&mut core, DEV, b"hello");
    write(&mut core, DEV, b"again");
    write(&mut core, DEV2, b"other");
    assert_eq!(
        drain(&mut rx),
        [
            RadioEvent::Connected {
                conn: 2,
                role: Role::Peripheral,
                service: T,
                max_tx: 182,
                max_rx: 182,
            },
            RadioEvent::Frame {
                conn: 2,
                bytes: b"hello".to_vec()
            },
            RadioEvent::Frame {
                conn: 2,
                bytes: b"again".to_vec()
            },
            RadioEvent::Connected {
                conn: 4,
                role: Role::Peripheral,
                service: T,
                max_tx: 182,
                max_rx: 182,
            },
            RadioEvent::Frame {
                conn: 4,
                bytes: b"other".to_vec()
            },
        ]
    );
    assert_eq!(core.bus.peripheral, [(2, 182), (4, 182)]);
    // A send is a notification on that service's characteristic.
    core.command(
        Cmd::Notify {
            conn: 2,
            frame: b"answer".to_vec(),
        },
        t0,
    );
    assert_eq!(core.bus.notified, [(2, chr.to_owned(), b"answer".to_vec())]);

    // This side ends 4 (a stranger): its link drops, it is silenced.
    core.command(Cmd::Disconnect(4), t0);
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn: 4 }]);
    let calls = core.bus.take();
    assert_eq!((calls[0].1, calls[0].2.as_str()), ("Disconnect", DEV2));
    write(&mut core, DEV2, b"more");
    assert!(drain(&mut rx).is_empty(), "silenced");
    core.tick(t0 + SILENCE);
    let now = t0 + SILENCE;
    core.call(
        bluez(),
        chr,
        Incoming::Write {
            value: b"later".to_vec(),
            device: Some(DEV2.to_owned()),
            mtu: None,
        },
        now,
    );
    assert_eq!(
        drain(&mut rx)[0],
        RadioEvent::Connected {
            conn: 6,
            role: Role::Peripheral,
            service: T,
            max_tx: 20,
            max_rx: 20,
        },
        "after the silence; ATT's default MTU when BlueZ names none"
    );

    // The last subscriber left: every connection on the service ends.
    core.call(bluez(), chr, Incoming::StopNotify, now);
    let mut ended = drain(&mut rx);
    ended.sort_by_key(|e| e.conn());
    assert_eq!(
        ended,
        [
            RadioEvent::Disconnected { conn: 2 },
            RadioEvent::Disconnected { conn: 6 }
        ]
    );
    assert!(
        core.bus.take().is_empty(),
        "the central left: no Disconnect call"
    );

    // A dropped link ends that device's connections.
    core.call(bluez(), chr, Incoming::StartNotify, now);
    core.call(
        bluez(),
        chr,
        Incoming::Write {
            value: b"x".to_vec(),
            device: Some(DEV.to_owned()),
            mtu: Some(23),
        },
        now,
    );
    let conn = match drain(&mut rx)[0] {
        RadioEvent::Connected { conn, .. } => conn,
        ref other => panic!("{other:?}"),
    };
    core.signal(
        bluez(),
        device(DeviceProps {
            connected: Some(true),
            ..DeviceProps::default()
        }),
        now,
    );
    core.signal(
        bluez(),
        device(DeviceProps {
            connected: Some(false),
            ..DeviceProps::default()
        }),
        now,
    );
    assert_eq!(drain(&mut rx), [RadioEvent::Disconnected { conn }]);

    // The service withdrawn: its connections end.
    core.call(
        bluez(),
        chr,
        Incoming::Write {
            value: b"y".to_vec(),
            device: Some(DEV.to_owned()),
            mtu: Some(23),
        },
        now,
    );
    let conn = match drain(&mut rx)[0] {
        RadioEvent::Connected { conn, .. } => conn,
        ref other => panic!("{other:?}"),
    };
    core.command(Cmd::Services(Vec::new(), None), now);
    assert!(drain(&mut rx).contains(&RadioEvent::Disconnected { conn }));
    assert!(core.bus.ended.contains(&conn));
}

/// A device keeps advertising: `Seen` at most once per SEEN_EVERY, at once
/// when its tokens change; nothing for SIG UUIDs only or without an RSSI.
#[test]
fn sightings_are_throttled_and_tokens_only() {
    let t0 = Instant::now();
    let (mut core, mut rx) = new_core(t0);
    drain(&mut rx);
    let seen = |core: &mut Core<FakeBus>, props: DeviceProps, at: Instant| {
        core.signal(bluez(), device(props), at);
    };
    let battery = uuid_parse("0000180f-0000-1000-8000-00805f9b34fb").unwrap();
    seen(
        &mut core,
        DeviceProps {
            uuids: Some(vec![battery]),
            rssi: Some(-60),
            ..DeviceProps::default()
        },
        t0,
    );
    seen(
        &mut core,
        DeviceProps {
            uuids: Some(vec![battery, T]),
            ..DeviceProps::default()
        },
        t0,
    );
    assert!(drain(&mut rx).is_empty(), "SIG only, then no RSSI");
    for ms in [0, 300, 900] {
        seen(
            &mut core,
            DeviceProps {
                rssi: Some(-61),
                ..DeviceProps::default()
            },
            t0 + Duration::from_millis(ms),
        );
    }
    assert_eq!(drain(&mut rx).len(), 1, "once per second");
    seen(
        &mut core,
        DeviceProps {
            uuids: Some(vec![battery, T, T2]),
            rssi: Some(-62),
            ..DeviceProps::default()
        },
        t0 + Duration::from_millis(950),
    );
    seen(
        &mut core,
        DeviceProps {
            rssi: Some(-63),
            ..DeviceProps::default()
        },
        t0 + Duration::from_millis(1950),
    );
    assert_eq!(
        drain(&mut rx),
        [
            RadioEvent::Seen {
                addr: RadioAddr(DEV.to_owned()),
                uuids: vec![T, T2],
                rssi: -62,
            },
            RadioEvent::Seen {
                addr: RadioAddr(DEV.to_owned()),
                uuids: vec![T, T2],
                rssi: -63,
            }
        ]
    );
    // A device of another adapter is not ours.
    core.signal(
        bluez(),
        Signal::Device {
            path: "/org/bluez/hci1/dev_00_00_5E_00_53_01".into(),
            props: DeviceProps {
                uuids: Some(vec![T]),
                rssi: Some(-40),
                ..DeviceProps::default()
            },
        },
        t0 + Duration::from_secs(5),
    );
    assert!(drain(&mut rx).is_empty());
}

/// The adapter off ends every connection and the scan; on again, the scan
/// starts over. The adapter or BlueZ gone stops the backend; a bus that
/// cannot take a call stops it too.
#[test]
fn power_and_bluez_lifecycle() {
    let t0 = Instant::now();
    let (mut core, mut rx) = new_core(t0);
    core.command(Cmd::Scan(true), t0);
    let f = core.bus.take()[0].0;
    core.reply(f, Reply::Done, t0);
    let s = core.bus.take()[0].0;
    core.reply(s, Reply::Done, t0);
    core.command(
        Cmd::Connect {
            conn: 1,
            device: DEV.to_owned(),
            service: T,
        },
        t0,
    );
    core.bus.take();
    drain(&mut rx);
    core.signal(
        bluez(),
        Signal::Adapter {
            path: ADAPTER_PATH.to_owned(),
            powered: Some(false),
        },
        t0,
    );
    assert_eq!(
        drain(&mut rx),
        [
            RadioEvent::Disconnected { conn: 1 },
            RadioEvent::State(RadioState::PoweredOff)
        ]
    );
    assert!(core.bus.take().is_empty(), "no scan calls while off");
    core.signal(
        bluez(),
        Signal::Adapter {
            path: ADAPTER_PATH.to_owned(),
            powered: Some(true),
        },
        t0,
    );
    assert_eq!(core.bus.take()[0].1, "SetDiscoveryFilter");
    // Scanning off while it starts: stopped once it runs.
    core.command(Cmd::Scan(false), t0);
    assert!(core.bus.take().is_empty());

    // The adapter removed: the backend stops.
    core.signal(
        bluez(),
        Signal::Removed {
            path: ADAPTER_PATH.to_owned(),
            ifaces: vec![ADAPTER.to_owned()],
        },
        t0,
    );
    assert!(!core.alive());

    // A broken bus: the call fails, the backend stops.
    let (mut core, mut rx) = new_core(t0);
    core.bus.broken = true;
    core.command(
        Cmd::Connect {
            conn: 1,
            device: DEV.to_owned(),
            service: T,
        },
        t0,
    );
    assert!(drain(&mut rx).contains(&RadioEvent::Disconnected { conn: 1 }));
    assert!(!core.alive());
}

// ── The send table ──────────────────────────────────────────────────────────

/// A peripheral connection may have NOTIFY_WINDOW notifications queued; one
/// more is Full, and the one that makes room owes one Writable. A central
/// connection writes to its socket; an unknown connection or a frame over
/// max_tx is an error.
#[test]
fn the_send_table_windows_notifications() {
    let mut table: Table<&'static str> = Table::default();
    assert!(table.route(1, 10).is_err(), "not connected");
    table.central(1, Arc::new("socket"), 182);
    assert!(matches!(table.route(1, 182), Ok(Route::Write(w)) if *w == "socket"));
    assert!(table.route(1, 183).is_err());
    assert!(table.route(1, 0).is_err());
    table.peripheral(2, 20);
    for _ in 0..NOTIFY_WINDOW {
        assert!(matches!(table.route(2, 20), Ok(Route::Notify)));
    }
    assert!(matches!(table.route(2, 20), Ok(Route::Full)));
    assert!(table.notified(2), "room: the owed Writable");
    assert!(!table.notified(2), "owed once");
    assert!(matches!(table.route(2, 20), Ok(Route::Notify)));
    assert!(
        !table.notified(1),
        "a central connection is not windowed here"
    );
    table.remove(2);
    assert!(table.route(2, 20).is_err());
    assert!(!table.notified(2));
}

#[test]
fn pending_calls_expire_oldest_first() {
    let t0 = Instant::now();
    let mut p: Pending<u8> = Pending::new();
    p.insert(5, 50, t0 + Duration::from_secs(1));
    p.insert(3, 30, t0);
    p.insert(9, 90, t0 + Duration::from_secs(20));
    assert_eq!(p.peek(3), Some(30));
    assert_eq!(
        p.expire(t0 + Duration::from_secs(11), Duration::from_secs(10)),
        [30, 50]
    );
    assert_eq!(p.take(5), None);
    assert_eq!(p.take(9), Some(90));
    assert_eq!(p.take(9), None, "a reply matches once");
    assert_eq!(p.len(), 0);
}
