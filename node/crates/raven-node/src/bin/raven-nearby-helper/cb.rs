//! raven-nearby-helper's CoreBluetooth side (macOS; objc2-core-bluetooth
//! 0.3.2, owner decision O5-10).
//!
//! **Before any CoreBluetooth object.** The helper reads
//! `NSBluetoothAlwaysUsageDescription` from its bundle's Info.plist. Without
//! it macOS would kill the process at the first Bluetooth call, so the
//! helper says `unauthorized` ("no usage description") and exits instead.
//! `--check` stops after that answer: it never creates a manager, so it
//! never prompts and never touches the radio.
//!
//! **One serial queue.** Both managers deliver their callbacks on a private
//! serial dispatch queue (a few lines of libdispatch FFI instead of the
//! dispatch2 crate), and the [`Machine`] with every CoreBluetooth object
//! lives behind [`STATE`], touched on that queue only. stdin's commands and
//! a half-second tick are posted to the queue. Each callback becomes one
//! [`Input`]; the lines the machine queues go to stdout at once.
//!
//! **Central links.** Connect, find service `T` and characteristic `C`
//! (both by UUID, nothing else is discovered), check that `C` can take
//! Write Commands and notify, subscribe; the link is up once the
//! subscription is. `max_tx` is `maximumWriteValueLengthForType:` for Write
//! Commands. A frame is written only while `canSendWriteWithoutResponse`.
//!
//! **Errors** are logged by CoreBluetooth error code only, never with a
//! device's identifier, and each distinct one once in a row.

use std::collections::HashMap;
use std::ffi::{c_char, c_ulong, c_void};
use std::io::{self, Write};
use std::panic::AssertUnwindSafe;
use std::sync::{Mutex, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, Message};
use objc2_core_bluetooth::{
    CBATTError, CBATTRequest, CBAdvertisementDataIsConnectable, CBAdvertisementDataServiceUUIDsKey,
    CBAttributePermissions, CBCentral, CBCentralManager, CBCentralManagerDelegate,
    CBCentralManagerScanOptionAllowDuplicatesKey, CBCharacteristic, CBCharacteristicProperties,
    CBCharacteristicWriteType, CBMutableCharacteristic, CBMutableService, CBPeripheral,
    CBPeripheralDelegate, CBPeripheralManager, CBPeripheralManagerDelegate, CBService, CBUUID,
};
use objc2_foundation::{
    ns_string, NSArray, NSBundle, NSData, NSDictionary, NSError, NSNumber, NSObject,
    NSObjectProtocol, NSString,
};

use crate::machine::{CbState, Machine, Os};
use crate::proto::{self, FromHelper, Power, ToHelper};

/// The usage description macOS requires before any Bluetooth call.
const USAGE_KEY: &str = "NSBluetoothAlwaysUsageDescription";
/// What the helper says when its bundle lacks [`USAGE_KEY`].
pub(crate) const NO_USAGE: &str = "no usage description: raven-nearby-helper must run from \
     RavenNearby.app, whose Info.plist carries NSBluetoothAlwaysUsageDescription";
/// The queue's label.
const QUEUE_LABEL: &[u8] = b"org.raven.nearby\0";
/// How often the machine's deadlines are checked.
const TICK: Duration = Duration::from_millis(500);
/// The exit code after a panic (raven-node reports the helper ended).
const PANICKED: i32 = 70;

// ── libdispatch ─────────────────────────────────────────────────────────────

/// `dispatch_autorelease_frequency_t`: drain an autorelease pool around
/// every work item (CoreBluetooth's callbacks included).
const DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM: c_ulong = 1;

// libdispatch is part of libSystem. A `dispatch_queue_t` is an
// Objective-C object (`@`), so it can be handed to `initWithDelegate:queue:`.
extern "C" {
    fn dispatch_queue_attr_make_with_autorelease_frequency(
        attr: *mut AnyObject,
        frequency: c_ulong,
    ) -> *mut AnyObject;
    fn dispatch_queue_create(label: *const c_char, attr: *mut AnyObject) -> *mut AnyObject;
    fn dispatch_async_f(
        queue: *mut AnyObject,
        context: *mut c_void,
        work: extern "C" fn(*mut c_void),
    );
    fn dispatch_sync_f(
        queue: *mut AnyObject,
        context: *mut c_void,
        work: extern "C" fn(*mut c_void),
    );
}

/// The helper's serial queue (created once, never released).
#[derive(Clone, Copy)]
struct Queue(*mut AnyObject);

// SAFETY: a dispatch queue may be used from any thread.
unsafe impl Send for Queue {}
unsafe impl Sync for Queue {}

static QUEUE: std::sync::OnceLock<Queue> = std::sync::OnceLock::new();

type Work = Box<dyn FnOnce()>;

/// Run `f` on the queue later.
fn post(f: Work) {
    let Some(q) = QUEUE.get() else {
        return;
    };
    let ctx = Box::into_raw(Box::new(f)).cast::<c_void>();
    // SAFETY: `ctx` is a leaked `Box<Work>` that `trampoline` takes back
    // exactly once.
    unsafe { dispatch_async_f(q.0, ctx, trampoline) };
}

/// Run `f` on the queue and wait for it.
fn run_sync(f: Work) {
    let Some(q) = QUEUE.get() else {
        return;
    };
    let ctx = Box::into_raw(Box::new(f)).cast::<c_void>();
    // SAFETY: as in `post`.
    unsafe { dispatch_sync_f(q.0, ctx, trampoline) };
}

extern "C" fn trampoline(ctx: *mut c_void) {
    // SAFETY: `ctx` came from `post` or `run_sync`.
    let f = unsafe { Box::from_raw(ctx.cast::<Work>()) };
    if std::panic::catch_unwind(AssertUnwindSafe(f)).is_err() {
        eprintln!("raven-nearby-helper: internal error; stopping");
        std::process::exit(PANICKED);
    }
}

// ── The state on the queue ──────────────────────────────────────────────────

struct OnQueue(Machine<Cb>);

// SAFETY: the machine and the CoreBluetooth objects it holds are only ever
// touched on the helper's serial queue: `setup` creates them there, and
// every input reaches them through `deliver`, which runs there.
unsafe impl Send for OnQueue {}

static STATE: Mutex<Option<OnQueue>> = Mutex::new(None);

/// One thing that happened, for the machine.
enum Input {
    Cmd(ToHelper),
    Tick,
    Stop,
    CmState(isize),
    PmState(isize),
    Discovered {
        peripheral: Retained<CBPeripheral>,
        uuids: Vec<[u8; 16]>,
        connectable: Option<bool>,
        rssi: i16,
    },
    LinkUp(String),
    LinkDown(String),
    Services(String, bool),
    Characteristics(String, bool),
    Notifying(String, bool),
    Invalidated(String, Vec<[u8; 16]>),
    Value(String, Option<[u8; 16]>, Option<Vec<u8>>),
    CanWrite(String),
    Added([u8; 16], Option<isize>),
    Advertising(Option<isize>),
    Subscribed(Retained<CBCentral>, [u8; 16]),
    Unsubscribed(String, [u8; 16]),
    Written(Retained<NSArray<CBATTRequest>>),
    Read(Retained<CBATTRequest>),
    CanNotify,
}

/// Handle `input` on the queue (a callback that comes while the state is in
/// use is posted again).
fn deliver(input: Input) {
    let mut guard = match STATE.try_lock() {
        Ok(g) => g,
        Err(TryLockError::Poisoned(p)) => p.into_inner(),
        Err(TryLockError::WouldBlock) => {
            post(Box::new(move || deliver(input)));
            return;
        }
    };
    let Some(OnQueue(m)) = guard.as_mut() else {
        return;
    };
    let lines = match std::panic::catch_unwind(AssertUnwindSafe(|| {
        autoreleasepool(|_| handle(m, input, Instant::now()));
        m.take_out()
    })) {
        Ok(lines) => lines,
        Err(_) => {
            eprintln!("raven-nearby-helper: internal error; stopping");
            std::process::exit(PANICKED);
        }
    };
    drop(guard);
    say_all(&lines);
}

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

// ── Identifiers and UUIDs ───────────────────────────────────────────────────

/// A CoreBluetooth UUID from RNL1 bytes (the token's bytes in order).
pub(crate) fn cbuuid(u: &[u8; 16]) -> Retained<CBUUID> {
    // SAFETY: a 16-byte NSData is a valid 128-bit UUID.
    unsafe { CBUUID::UUIDWithData(&NSData::with_bytes(u)) }
}

/// The 16 bytes of a 128-bit CoreBluetooth UUID (`None` for a 16- or
/// 32-bit one).
pub(crate) fn uuid_bytes(u: &CBUUID) -> Option<[u8; 16]> {
    // SAFETY: `data` has no preconditions.
    let data = unsafe { u.data() };
    <[u8; 16]>::try_from(data.to_vec().as_slice()).ok()
}

/// A peer's handle: its identifier (macOS's, per app and device) as hex.
fn peer_id(identifier: &objc2_foundation::NSUUID) -> String {
    // The UUID string, not `getUUIDBytes:`: objc2's debug check of that
    // method's type encoding fails on current macOS ('*' against '[16C]')
    // and stopped the helper in the field (r41). The same 32 hex digits.
    identifier
        .UUIDString()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn peripheral_id(p: &CBPeripheral) -> String {
    // SAFETY: `identifier` has no preconditions.
    let id = unsafe { p.identifier() };
    peer_id(&id)
}

fn central_id(c: &CBCentral) -> String {
    // SAFETY: as above.
    let id = unsafe { c.identifier() };
    peer_id(&id)
}

/// The UUID of a service, characteristic or descriptor.
fn attribute_uuid(a: &objc2_core_bluetooth::CBAttribute) -> Option<[u8; 16]> {
    // SAFETY: `UUID` has no preconditions.
    let u = unsafe { a.UUID() };
    uuid_bytes(&u)
}

fn char_uuid_of(ch: &CBCharacteristic) -> Option<[u8; 16]> {
    attribute_uuid(ch)
}

/// The 128-bit service UUIDs an advert carries.
fn advert_uuids(data: &NSDictionary<NSString, AnyObject>) -> Vec<[u8; 16]> {
    // SAFETY: a CoreBluetooth constant.
    let key = unsafe { CBAdvertisementDataServiceUUIDsKey };
    let Some(Ok(list)) = data.objectForKey(key).map(|o| o.downcast::<NSArray>()) else {
        return Vec::new();
    };
    list.to_vec()
        .into_iter()
        .filter_map(|o| o.downcast::<CBUUID>().ok())
        .filter_map(|u| uuid_bytes(&u))
        .take(proto::MAX_UUIDS * 2)
        .collect()
}

/// Whether the advert says it is connectable (`None`: it does not say).
fn advert_connectable(data: &NSDictionary<NSString, AnyObject>) -> Option<bool> {
    // SAFETY: a CoreBluetooth constant.
    let key = unsafe { CBAdvertisementDataIsConnectable };
    data.objectForKey(key)
        .and_then(|o| o.downcast::<NSNumber>().ok())
        .map(|n| n.as_bool())
}

fn error_code(error: Option<&NSError>) -> Option<isize> {
    error.map(|e| e.code())
}

// ── The delegate ────────────────────────────────────────────────────────────

define_class!(
    // SAFETY: NSObject has no subclassing requirements, and `Delegate` has
    // no Drop and no state of its own.
    #[unsafe(super(NSObject))]
    #[name = "RavenNearbyHelperDelegate"]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl CBCentralManagerDelegate for Delegate {
        #[unsafe(method(centralManagerDidUpdateState:))]
        fn cm_state(&self, central: &CBCentralManager) {
            // SAFETY: `state` has no preconditions.
            deliver(Input::CmState(unsafe { central.state() }.0));
        }

        #[unsafe(method(centralManager:didDiscoverPeripheral:advertisementData:RSSI:))]
        fn discovered(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            data: &NSDictionary<NSString, AnyObject>,
            rssi: &NSNumber,
        ) {
            let uuids = advert_uuids(data);
            if uuids.is_empty() {
                return;
            }
            deliver(Input::Discovered {
                peripheral: peripheral.retain(),
                uuids,
                connectable: advert_connectable(data),
                rssi: i16::try_from(rssi.as_isize()).unwrap_or(i16::MIN),
            });
        }

        #[unsafe(method(centralManager:didConnectPeripheral:))]
        fn connected(&self, _central: &CBCentralManager, peripheral: &CBPeripheral) {
            deliver(Input::LinkUp(peripheral_id(peripheral)));
        }

        #[unsafe(method(centralManager:didFailToConnectPeripheral:error:))]
        fn connect_failed(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            _error: Option<&NSError>,
        ) {
            deliver(Input::LinkDown(peripheral_id(peripheral)));
        }

        #[unsafe(method(centralManager:didDisconnectPeripheral:error:))]
        fn disconnected(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            _error: Option<&NSError>,
        ) {
            deliver(Input::LinkDown(peripheral_id(peripheral)));
        }
    }

    unsafe impl CBPeripheralDelegate for Delegate {
        #[unsafe(method(peripheral:didDiscoverServices:))]
        fn services(&self, peripheral: &CBPeripheral, error: Option<&NSError>) {
            deliver(Input::Services(peripheral_id(peripheral), error.is_none()));
        }

        #[unsafe(method(peripheral:didDiscoverCharacteristicsForService:error:))]
        fn characteristics(
            &self,
            peripheral: &CBPeripheral,
            _service: &CBService,
            error: Option<&NSError>,
        ) {
            deliver(Input::Characteristics(
                peripheral_id(peripheral),
                error.is_none(),
            ));
        }

        #[unsafe(method(peripheral:didUpdateNotificationStateForCharacteristic:error:))]
        fn notifying(
            &self,
            peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            // SAFETY: `isNotifying` has no preconditions.
            let on = error.is_none() && unsafe { characteristic.isNotifying() };
            deliver(Input::Notifying(peripheral_id(peripheral), on));
        }

        #[unsafe(method(peripheral:didUpdateValueForCharacteristic:error:))]
        fn value(
            &self,
            peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            let bytes = if error.is_none() {
                // SAFETY: `value` has no preconditions.
                unsafe { characteristic.value() }.map(|d| d.to_vec())
            } else {
                None
            };
            deliver(Input::Value(
                peripheral_id(peripheral),
                char_uuid_of(characteristic),
                bytes,
            ));
        }

        #[unsafe(method(peripheralIsReadyToSendWriteWithoutResponse:))]
        fn can_write(&self, peripheral: &CBPeripheral) {
            deliver(Input::CanWrite(peripheral_id(peripheral)));
        }

        #[unsafe(method(peripheral:didModifyServices:))]
        fn modified(&self, peripheral: &CBPeripheral, invalidated: &NSArray<CBService>) {
            let gone = invalidated
                .to_vec()
                .iter()
                .filter_map(|s| attribute_uuid(s))
                .collect();
            deliver(Input::Invalidated(peripheral_id(peripheral), gone));
        }
    }

    unsafe impl CBPeripheralManagerDelegate for Delegate {
        #[unsafe(method(peripheralManagerDidUpdateState:))]
        fn pm_state(&self, peripheral: &CBPeripheralManager) {
            // SAFETY: `state` has no preconditions.
            deliver(Input::PmState(unsafe { peripheral.state() }.0));
        }

        #[unsafe(method(peripheralManagerDidStartAdvertising:error:))]
        fn advertising(&self, _peripheral: &CBPeripheralManager, error: Option<&NSError>) {
            deliver(Input::Advertising(error_code(error)));
        }

        #[unsafe(method(peripheralManager:didAddService:error:))]
        fn added(
            &self,
            _peripheral: &CBPeripheralManager,
            service: &CBService,
            error: Option<&NSError>,
        ) {
            if let Some(t) = attribute_uuid(service) {
                deliver(Input::Added(t, error_code(error)));
            }
        }

        #[unsafe(method(peripheralManager:central:didSubscribeToCharacteristic:))]
        fn subscribed(
            &self,
            _peripheral: &CBPeripheralManager,
            central: &CBCentral,
            characteristic: &CBCharacteristic,
        ) {
            if let Some(c) = char_uuid_of(characteristic) {
                deliver(Input::Subscribed(central.retain(), c));
            }
        }

        #[unsafe(method(peripheralManager:central:didUnsubscribeFromCharacteristic:))]
        fn unsubscribed(
            &self,
            _peripheral: &CBPeripheralManager,
            central: &CBCentral,
            characteristic: &CBCharacteristic,
        ) {
            if let Some(c) = char_uuid_of(characteristic) {
                deliver(Input::Unsubscribed(central_id(central), c));
            }
        }

        #[unsafe(method(peripheralManager:didReceiveWriteRequests:))]
        fn written(&self, _peripheral: &CBPeripheralManager, requests: &NSArray<CBATTRequest>) {
            deliver(Input::Written(requests.retain()));
        }

        #[unsafe(method(peripheralManager:didReceiveReadRequest:))]
        fn read(&self, _peripheral: &CBPeripheralManager, request: &CBATTRequest) {
            deliver(Input::Read(request.retain()));
        }

        #[unsafe(method(peripheralManagerIsReadyToUpdateSubscribers:))]
        fn can_notify(&self, _peripheral: &CBPeripheralManager) {
            deliver(Input::CanNotify);
        }
    }
);

impl Delegate {
    fn new() -> Retained<Self> {
        let this = Self::alloc().set_ivars(());
        // SAFETY: NSObject's `init`.
        unsafe { msg_send![super(this), init] }
    }
}

// ── CoreBluetooth as the machine's Os ───────────────────────────────────────

/// A central link being set up or up: its service, characteristic and,
/// once found, the characteristic object.
struct Link {
    t: [u8; 16],
    c: [u8; 16],
    ch: Option<Retained<CBCharacteristic>>,
}

struct Cb {
    cm: Retained<CBCentralManager>,
    pm: Retained<CBPeripheralManager>,
    delegate: Retained<Delegate>,
    services: HashMap<
        [u8; 16],
        (
            Retained<CBMutableService>,
            Retained<CBMutableCharacteristic>,
        ),
    >,
    devices: HashMap<String, Retained<CBPeripheral>>,
    links: HashMap<String, Link>,
    centrals: HashMap<String, Retained<CBCentral>>,
    logged: Option<String>,
}

impl Cb {
    /// Log a CoreBluetooth error once in a row (codes only).
    fn note(&mut self, what: &str, code: Option<isize>) {
        let line = match code {
            Some(code) => format!("{what}: CoreBluetooth error {code}"),
            None => what.to_owned(),
        };
        if self.logged.as_ref() != Some(&line) {
            eprintln!("raven-nearby-helper: {line}");
            self.logged = Some(line);
        }
    }

    /// The service `T` of `dev`'s link, among the services found on it.
    fn found_service(&self, dev: &str) -> Option<Retained<CBService>> {
        let t = self.links.get(dev)?.t;
        let p = self.devices.get(dev)?;
        // SAFETY: `services` has no preconditions.
        unsafe { p.services() }?
            .to_vec()
            .into_iter()
            .find(|s| attribute_uuid(s) == Some(t))
    }
}

impl Os for Cb {
    fn add(&mut self, t: [u8; 16], c: [u8; 16]) {
        let props = CBCharacteristicProperties::WriteWithoutResponse
            | CBCharacteristicProperties::Write
            | CBCharacteristicProperties::Notify;
        // SAFETY: a fresh characteristic and service with valid UUIDs, no
        // cached value (a notifying characteristic must have none), and
        // write permission only.
        let ch = unsafe {
            CBMutableCharacteristic::initWithType_properties_value_permissions(
                CBMutableCharacteristic::alloc(),
                &cbuuid(&c),
                props,
                None,
                CBAttributePermissions::Writeable,
            )
        };
        let svc = unsafe {
            CBMutableService::initWithType_primary(CBMutableService::alloc(), &cbuuid(&t), true)
        };
        let chars = NSArray::from_retained_slice(&[Retained::into_super(ch.clone())]);
        // SAFETY: the service is not published yet.
        unsafe {
            svc.setCharacteristics(Some(&chars));
            self.pm.addService(&svc);
        }
        self.services.insert(t, (svc, ch));
    }

    fn remove(&mut self, t: [u8; 16]) {
        if let Some((svc, _)) = self.services.remove(&t) {
            // SAFETY: a service this manager was asked to add.
            unsafe { self.pm.removeService(&svc) };
        }
    }

    fn advertise(&mut self, t: Option<[u8; 16]>) {
        // SAFETY: plain calls on the peripheral manager; the advert holds
        // only the service UUID key (no local name).
        unsafe {
            if self.pm.isAdvertising() {
                self.pm.stopAdvertising();
            }
            if let Some(t) = t {
                let list = NSArray::from_retained_slice(&[cbuuid(&t)]);
                let advert: Retained<NSDictionary<NSString, AnyObject>> =
                    NSDictionary::from_retained_objects(
                        &[CBAdvertisementDataServiceUUIDsKey],
                        &[list.into()],
                    );
                self.pm.startAdvertising(Some(&advert));
            }
        }
    }

    fn scan(&mut self, on: bool) {
        // SAFETY: plain calls on the central manager. Every advert is
        // reported (duplicates allowed), so a contact stays seen.
        unsafe {
            if on {
                let options: Retained<NSDictionary<NSString, AnyObject>> =
                    NSDictionary::from_retained_objects(
                        &[CBCentralManagerScanOptionAllowDuplicatesKey],
                        &[NSNumber::new_bool(true).into()],
                    );
                self.cm
                    .scanForPeripheralsWithServices_options(None, Some(&options));
            } else {
                self.cm.stopScan();
            }
        }
    }

    fn connect(&mut self, dev: &str, t: [u8; 16], c: [u8; 16]) -> bool {
        let Some(p) = self.devices.get(dev) else {
            return false;
        };
        // SAFETY: a peripheral this manager discovered; the delegate lives
        // as long as the helper.
        unsafe {
            p.setDelegate(Some(ProtocolObject::from_ref(&*self.delegate)));
            self.cm.connectPeripheral_options(p, None);
        }
        self.links.insert(dev.to_owned(), Link { t, c, ch: None });
        true
    }

    fn cancel(&mut self, dev: &str) {
        self.links.remove(dev);
        if let Some(p) = self.devices.get(dev) {
            // SAFETY: as in `connect`.
            unsafe { self.cm.cancelPeripheralConnection(p) };
        }
    }

    fn write(&mut self, dev: &str, frame: &[u8]) -> bool {
        let (Some(p), Some(Link { ch: Some(ch), .. })) =
            (self.devices.get(dev), self.links.get(dev))
        else {
            return false;
        };
        // SAFETY: a characteristic found on this peripheral that takes
        // Write Commands; the frame fits max_tx (the machine checked).
        unsafe {
            if !p.canSendWriteWithoutResponse() {
                return false;
            }
            p.writeValue_forCharacteristic_type(
                &NSData::with_bytes(frame),
                ch,
                CBCharacteristicWriteType::WithoutResponse,
            );
        }
        true
    }

    fn notify(&mut self, t: [u8; 16], central: &str, frame: &[u8]) -> bool {
        let (Some((_, ch)), Some(who)) = (self.services.get(&t), self.centrals.get(central)) else {
            // Gone: the frame is dropped (its connection is ending).
            return true;
        };
        let to = NSArray::from_retained_slice(std::slice::from_ref(who));
        // SAFETY: a published characteristic and a subscribed central.
        unsafe {
            self.pm.updateValue_forCharacteristic_onSubscribedCentrals(
                &NSData::with_bytes(frame),
                ch,
                Some(&to),
            )
        }
    }

    fn forget(&mut self, dev: &str) {
        self.devices.remove(dev);
        self.links.remove(dev);
    }

    fn forget_central(&mut self, central: &str) {
        self.centrals.remove(central);
    }

    fn reset(&mut self) {
        self.services.clear();
        self.devices.clear();
        self.links.clear();
        self.centrals.clear();
    }
}

// ── Inputs ──────────────────────────────────────────────────────────────────

/// `dev`'s link cannot be set up: end it.
fn fail(m: &mut Machine<Cb>, dev: &str, now: Instant) {
    m.os.cancel(dev);
    m.central_down(dev, now);
}

fn handle(m: &mut Machine<Cb>, input: Input, now: Instant) {
    match input {
        Input::Cmd(cmd) => m.command(cmd, now),
        Input::Tick => m.tick(now),
        Input::Stop => m.stop(),
        Input::CmState(raw) => m.cm_state(CbState::from_raw(raw), now),
        Input::PmState(raw) => m.pm_state(CbState::from_raw(raw), now),
        Input::Discovered {
            peripheral,
            uuids,
            connectable,
            rssi,
        } => {
            let dev = peripheral_id(&peripheral);
            if m.discovered(&dev, &uuids, connectable, rssi, now) {
                m.os.devices.entry(dev).or_insert(peripheral);
            }
        }
        Input::LinkUp(dev) => {
            let (Some(link), Some(p)) = (m.os.links.get(&dev), m.os.devices.get(&dev)) else {
                // Cancelled meanwhile.
                if let Some(p) = m.os.devices.get(&dev) {
                    // SAFETY: as in `Cb::connect`.
                    unsafe { m.os.cm.cancelPeripheralConnection(p) };
                }
                return;
            };
            let only = NSArray::from_retained_slice(&[cbuuid(&link.t)]);
            // SAFETY: a connected peripheral.
            unsafe { p.discoverServices(Some(&only)) };
        }
        Input::LinkDown(dev) => {
            m.os.links.remove(&dev);
            m.central_down(&dev, now);
        }
        Input::Services(dev, ok) => {
            let svc = if ok { m.os.found_service(&dev) } else { None };
            let (Some(svc), Some(link), Some(p)) =
                (svc, m.os.links.get(&dev), m.os.devices.get(&dev))
            else {
                return fail(m, &dev, now);
            };
            let only = NSArray::from_retained_slice(&[cbuuid(&link.c)]);
            // SAFETY: a service found on this connected peripheral.
            unsafe { p.discoverCharacteristics_forService(Some(&only), &svc) };
        }
        Input::Characteristics(dev, ok) => {
            let found = if ok { m.os.found_service(&dev) } else { None }.and_then(|svc| {
                let c = m.os.links.get(&dev)?.c;
                // SAFETY: `characteristics` has no preconditions.
                unsafe { svc.characteristics() }?
                    .to_vec()
                    .into_iter()
                    .find(|ch| char_uuid_of(ch) == Some(c))
            });
            let need = CBCharacteristicProperties::WriteWithoutResponse
                | CBCharacteristicProperties::Notify;
            // SAFETY: `properties` has no preconditions.
            let Some(ch) = found.filter(|ch| unsafe { ch.properties() }.contains(need)) else {
                return fail(m, &dev, now);
            };
            let (Some(link), Some(p)) = (m.os.links.get_mut(&dev), m.os.devices.get(&dev)) else {
                return fail(m, &dev, now);
            };
            // SAFETY: a characteristic found on this peripheral that can
            // notify.
            unsafe { p.setNotifyValue_forCharacteristic(true, &ch) };
            link.ch = Some(ch);
        }
        Input::Notifying(dev, on) => {
            let ready = on && m.os.links.get(&dev).is_some_and(|l| l.ch.is_some());
            let Some(p) = m.os.devices.get(&dev).filter(|_| ready) else {
                return fail(m, &dev, now);
            };
            // SAFETY: `maximumWriteValueLengthForType:` has no
            // preconditions.
            let max_tx = unsafe {
                p.maximumWriteValueLengthForType(CBCharacteristicWriteType::WithoutResponse)
            };
            m.central_up(&dev, max_tx);
        }
        Input::Invalidated(dev, gone) => {
            if m.os.links.get(&dev).is_some_and(|l| gone.contains(&l.t)) {
                fail(m, &dev, now);
            }
        }
        Input::Value(dev, c, bytes) => {
            // Only the link's own characteristic carries frames.
            let ours = m.os.links.get(&dev).is_some_and(|l| Some(l.c) == c);
            if let Some(bytes) = bytes.filter(|_| ours) {
                m.notified(&dev, bytes, now);
            }
        }
        Input::CanWrite(dev) => m.central_ready(&dev),
        Input::Added(t, error) => {
            if error.is_some() {
                m.os.note("a GATT service was refused", error);
            }
            m.added(t, error.is_none(), now);
        }
        Input::Advertising(error) => {
            if error.is_some() {
                m.os.note("advertising was refused", error);
            }
            m.advertising(error.is_none(), now);
        }
        Input::Subscribed(central, c) => {
            let Some(t) = m.service_of_char(&c) else {
                return;
            };
            let id = central_id(&central);
            // SAFETY: `maximumUpdateValueLength` has no preconditions.
            let max_tx = unsafe { central.maximumUpdateValueLength() };
            m.os.centrals.insert(id.clone(), central);
            m.subscribed(t, &id, max_tx, now);
            if !m.has_central(&id) {
                m.os.centrals.remove(&id);
            }
        }
        Input::Unsubscribed(id, c) => {
            if let Some(t) = m.service_of_char(&c) {
                m.unsubscribed(t, &id, now);
            }
        }
        Input::Written(requests) => {
            let requests = requests.to_vec();
            for r in &requests {
                // SAFETY: plain getters of a request CoreBluetooth made.
                let (central, ch, offset, value) =
                    unsafe { (r.central(), r.characteristic(), r.offset(), r.value()) };
                let (Some(c), Some(value)) = (char_uuid_of(&ch), value) else {
                    continue;
                };
                // A frame is one ATT PDU: a long (prepared) write is none.
                if offset != 0 {
                    continue;
                }
                if let Some(t) = m.service_of_char(&c) {
                    m.written(t, &central_id(&central), &value.to_vec());
                }
            }
            // One answer for the whole batch (ignored for Write Commands).
            if let Some(first) = requests.first() {
                // SAFETY: a request of this manager, answered once.
                unsafe {
                    m.os.pm
                        .respondToRequest_withResult(first, CBATTError::Success)
                };
            }
        }
        Input::Read(request) => {
            // SAFETY: as above. The characteristic has no Read property.
            unsafe {
                m.os.pm
                    .respondToRequest_withResult(&request, CBATTError::ReadNotPermitted)
            };
        }
        Input::CanNotify => m.peripheral_ready(),
    }
}

// ── The process ─────────────────────────────────────────────────────────────

/// Whether this process's bundle carries the Bluetooth usage description.
fn has_usage_description() -> bool {
    debug_assert_eq!(USAGE_KEY, "NSBluetoothAlwaysUsageDescription");
    autoreleasepool(|_| {
        NSBundle::mainBundle()
            .objectForInfoDictionaryKey(ns_string!("NSBluetoothAlwaysUsageDescription"))
            .is_some()
    })
}

/// Create the managers on the queue, so their first callbacks (queued on
/// it) find the machine in place.
fn setup(queue: Queue) {
    let delegate = Delegate::new();
    let none: Option<&NSDictionary<NSString, AnyObject>> = None;
    // SAFETY: `initWithDelegate:queue:options:` with a delegate that lives
    // as long as the helper, a valid serial queue (an Objective-C object)
    // and no options.
    let (cm, pm): (Retained<CBCentralManager>, Retained<CBPeripheralManager>) = unsafe {
        let cm_delegate: &ProtocolObject<dyn CBCentralManagerDelegate> =
            ProtocolObject::from_ref(&*delegate);
        let pm_delegate: &ProtocolObject<dyn CBPeripheralManagerDelegate> =
            ProtocolObject::from_ref(&*delegate);
        (
            msg_send![CBCentralManager::alloc(), initWithDelegate: cm_delegate, queue: queue.0, options: none],
            msg_send![CBPeripheralManager::alloc(), initWithDelegate: pm_delegate, queue: queue.0, options: none],
        )
    };
    let cb = Cb {
        cm,
        pm,
        delegate,
        services: HashMap::new(),
        devices: HashMap::new(),
        links: HashMap::new(),
        centrals: HashMap::new(),
        logged: None,
    };
    *STATE.lock().unwrap_or_else(PoisonError::into_inner) = Some(OnQueue(Machine::new(cb)));
}

/// The helper (see the module doc). Returns the exit code.
pub(crate) fn run(check_only: bool) -> i32 {
    if !has_usage_description() {
        say(&FromHelper::State {
            state: Power::Unauthorized,
            detail: NO_USAGE.to_owned(),
        });
        return 0;
    }
    say(&FromHelper::Hello { v: proto::VERSION });
    if check_only {
        return 0;
    }
    // SAFETY: a static label; the attribute is the serial one (NULL) with
    // an autorelease pool per work item.
    let queue = unsafe {
        let attr = dispatch_queue_attr_make_with_autorelease_frequency(
            std::ptr::null_mut(),
            DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM,
        );
        dispatch_queue_create(QUEUE_LABEL.as_ptr().cast(), attr)
    };
    if queue.is_null() {
        eprintln!("raven-nearby-helper: no dispatch queue");
        return 1;
    }
    let queue = Queue(queue);
    let _ = QUEUE.set(queue);
    run_sync(Box::new(move || setup(queue)));
    let _ = std::thread::Builder::new()
        .name("tick".into())
        .spawn(|| loop {
            std::thread::sleep(TICK);
            post(Box::new(|| deliver(Input::Tick)));
        });
    let stdin = io::stdin();
    let mut r = stdin.lock();
    let mut buf = Vec::new();
    while let Ok(true) = proto::read_line(&mut r, &mut buf) {
        if let Some(cmd) = proto::parse::<ToHelper>(&buf) {
            post(Box::new(move || deliver(Input::Cmd(cmd))));
        }
    }
    // raven-node is gone or let go of the radio.
    run_sync(Box::new(|| deliver(Input::Stop)));
    0
}

#[cfg(test)]
mod tests {
    use objc2::sel;

    use super::*;

    /// The delegate class registers and answers every callback the helper
    /// relies on, for all three protocols (a debug build also checks each
    /// method against the protocol's signature when the class registers).
    /// Making it touches no Bluetooth: no manager is created.
    #[test]
    fn the_delegate_answers_every_callback() {
        let d = Delegate::new();
        for sel in [
            sel!(centralManagerDidUpdateState:),
            sel!(centralManager:didDiscoverPeripheral:advertisementData:RSSI:),
            sel!(centralManager:didConnectPeripheral:),
            sel!(centralManager:didFailToConnectPeripheral:error:),
            sel!(centralManager:didDisconnectPeripheral:error:),
            sel!(peripheral:didDiscoverServices:),
            sel!(peripheral:didDiscoverCharacteristicsForService:error:),
            sel!(peripheral:didUpdateNotificationStateForCharacteristic:error:),
            sel!(peripheral:didUpdateValueForCharacteristic:error:),
            sel!(peripheralIsReadyToSendWriteWithoutResponse:),
            sel!(peripheral:didModifyServices:),
            sel!(peripheralManagerDidUpdateState:),
            sel!(peripheralManagerDidStartAdvertising:error:),
            sel!(peripheralManager:didAddService:error:),
            sel!(peripheralManager:central:didSubscribeToCharacteristic:),
            sel!(peripheralManager:central:didUnsubscribeFromCharacteristic:),
            sel!(peripheralManager:didReceiveWriteRequests:),
            sel!(peripheralManager:didReceiveReadRequest:),
            sel!(peripheralManagerIsReadyToUpdateSubscribers:),
        ] {
            assert!(d.respondsToSelector(sel), "{sel:?}");
        }
        assert!(!d.respondsToSelector(sel!(peripheral:didOpenL2CAPChannel:error:)));
        let _: &ProtocolObject<dyn CBCentralManagerDelegate> = ProtocolObject::from_ref(&*d);
        let _: &ProtocolObject<dyn CBPeripheralManagerDelegate> = ProtocolObject::from_ref(&*d);
        let _: &ProtocolObject<dyn CBPeripheralDelegate> = ProtocolObject::from_ref(&*d);
    }

    /// RNL1 §2: a CoreBluetooth UUID made from a token holds the token's
    /// bytes in order, and its text is the token's UUID text (CoreBluetooth
    /// writes it upper case); the same for the characteristic UUID. No
    /// manager is created: no radio.
    #[test]
    fn cbuuid_bytes_equal_the_vector_token_bytes() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/nearby/rnb1_tokens_001.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let tokens = v["expected"]["tokens"].as_array().unwrap();
        assert!(!tokens.is_empty());
        for tok in tokens {
            for (hex_key, text_key) in [
                ("token_hex", "uuid_string"),
                ("char_uuid_hex", "char_uuid_string"),
            ] {
                let bytes = proto::uuid_from(tok[hex_key].as_str().unwrap()).unwrap();
                let u = cbuuid(&bytes);
                assert_eq!(uuid_bytes(&u), Some(bytes), "{hex_key}");
                // SAFETY: `UUIDString` has no preconditions.
                let text = unsafe { u.UUIDString() }.to_string();
                assert_eq!(text.to_lowercase(), tok[text_key].as_str().unwrap());
                // And back from the text, as an advert's UUID would come.
                // SAFETY: a valid UUID string.
                let parsed = unsafe { CBUUID::UUIDWithString(&NSString::from_str(&text)) };
                assert_eq!(uuid_bytes(&parsed), Some(bytes));
            }
        }
        // A 16-bit SIG UUID is not 16 bytes long.
        // SAFETY: a valid 16-bit UUID string.
        let battery = unsafe { CBUUID::UUIDWithString(ns_string!("180F")) };
        assert_eq!(uuid_bytes(&battery), None);
    }
}
