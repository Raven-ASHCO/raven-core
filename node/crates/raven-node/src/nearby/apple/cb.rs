//! CoreBluetooth for the nearby radio (objc2-core-bluetooth 0.3.2, owner
//! decision O5-10), one source for two hosts: raven-nearby-helper on macOS,
//! its own process (`bin/raven-nearby-helper/process.rs` adds stdin, stdout
//! and the exit; the helper includes this file with `#[path]`), and the iOS
//! app's own process (`super::inproc`, Task 2 design §3), where an app may
//! start no helper.
//!
//! **Before any CoreBluetooth object.** [`has_usage_description`] reads
//! `NSBluetoothAlwaysUsageDescription` from the main bundle's Info.plist
//! (RavenNearby.app's, or the iOS app's own). Without it the system would
//! kill the process at the first Bluetooth call, so no manager is made then
//! ([`NO_USAGE`] says why). The helper's `--check` stops after that
//! answer: it never creates a manager, so it never prompts and never touches
//! the radio.
//!
//! **One serial queue** per process ([`queue`]; a few lines of libdispatch
//! FFI instead of the dispatch2 crate). Both managers deliver their
//! callbacks on it, and [`STATE`] holds the one [`Life`] at a time: the
//! [`Machine`] with every CoreBluetooth object, and the [`Sink`] its lines go
//! to, touched on that queue only. Commands and the tick are posted to the
//! queue ([`post`], [`post_after`]). Each callback becomes one [`Input`];
//! the lines the machine queues go to the sink once the state lock is
//! released ([`deliver`]). [`run_sync`] waits for the queue and so is never
//! called on it (a debug assertion: [`on_queue`]).
//!
//! **A life's callbacks only.** Each life has a [`Delegate`] of its own; a
//! callback from another life's managers (one queued before that life
//! ended) is dropped.
//!
//! **A panic** in this code is caught on the queue and in every delegate
//! method: it never unwinds into CoreBluetooth or libdispatch. It ends the
//! life ([`Sink::panicked`]): the helper exits, as it always did; in
//! process the radio is gone, and the app keeps running.
//!
//! **Central links.** Connect, find service `T` and characteristic `C`
//! (both by UUID, nothing else is discovered), check that `C` can take
//! Write Commands and notify, subscribe; the link is up once the
//! subscription is. `max_tx` is `maximumWriteValueLengthForType:` for Write
//! Commands. A frame is written only while `canSendWriteWithoutResponse`.
//!
//! **Scanning** reports every advert, duplicates allowed, so a contact
//! stays seen; on iOS a scan filter (the background scan, Task 2 design
//! §3.5) names the only service UUIDs to scan for, which iOS requires of an
//! app in the background. The macOS helper never filters.
//!
//! **Errors** are logged by CoreBluetooth error code only, never with a
//! device's identifier, and each distinct one once in a row.

// On macOS the library builds this only for its tests, and the helper uses
// what its process needs: the rest is the iOS app's.
#![cfg_attr(not(target_os = "ios"), allow(dead_code))]

use std::collections::HashMap;
use std::ffi::{c_char, c_ulong, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, Message};
use objc2_core_bluetooth::{
    CBATTError, CBATTRequest, CBAdvertisementDataIsConnectable, CBAdvertisementDataServiceUUIDsKey,
    CBAttributePermissions, CBCentral, CBCentralManager, CBCentralManagerDelegate,
    CBCentralManagerOptionShowPowerAlertKey, CBCentralManagerScanOptionAllowDuplicatesKey,
    CBCharacteristic, CBCharacteristicProperties, CBCharacteristicWriteType,
    CBMutableCharacteristic, CBMutableService, CBPeripheral, CBPeripheralDelegate,
    CBPeripheralManager, CBPeripheralManagerDelegate, CBPeripheralManagerOptionShowPowerAlertKey,
    CBService, CBUUID,
};
use objc2_foundation::{
    ns_string, NSArray, NSBundle, NSData, NSDictionary, NSError, NSNumber, NSObject,
    NSObjectProtocol, NSString,
};

use super::machine::{CbState, Machine, Os};
use super::proto::{self, FromHelper};

/// The usage description the system requires before any Bluetooth call.
const USAGE_KEY: &str = "NSBluetoothAlwaysUsageDescription";

/// What a bundle without [`USAGE_KEY`] means: on macOS the helper runs from
/// outside RavenNearby.app; on iOS the app was built without the key, a
/// build error (said as the in-process radio's own failure, which the
/// status classes as the software Raven needs, not as no Bluetooth LE).
pub(crate) const fn no_usage_text(ios: bool) -> &'static str {
    if ios {
        "the nearby radio cannot start: this app build lacks NSBluetoothAlwaysUsageDescription"
    } else {
        "no usage description: raven-nearby-helper must run from RavenNearby.app, whose \
         Info.plist carries NSBluetoothAlwaysUsageDescription"
    }
}

/// What this build says when its bundle lacks [`USAGE_KEY`].
pub(crate) const NO_USAGE: &str = no_usage_text(cfg!(target_os = "ios"));
/// The queue's label.
const QUEUE_LABEL: &[u8] = b"org.raven.nearby\0";

// ── libdispatch ─────────────────────────────────────────────────────────────

/// `dispatch_autorelease_frequency_t`: drain an autorelease pool around
/// every work item (CoreBluetooth's callbacks included).
const DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM: c_ulong = 1;
/// `DISPATCH_TIME_NOW`.
const DISPATCH_TIME_NOW: u64 = 0;

// libdispatch is part of libSystem (on iOS too). A `dispatch_queue_t` is an
// Objective-C object (`@`), so it can be handed to `initWithDelegate:queue:`.
extern "C" {
    fn dispatch_queue_attr_make_with_autorelease_frequency(
        attr: *mut AnyObject,
        frequency: c_ulong,
    ) -> *mut AnyObject;
    fn dispatch_queue_create(label: *const c_char, attr: *mut AnyObject) -> *mut AnyObject;
    fn dispatch_queue_set_specific(
        queue: *mut AnyObject,
        key: *const c_void,
        context: *mut c_void,
        destructor: Option<extern "C" fn(*mut c_void)>,
    );
    fn dispatch_get_specific(key: *const c_void) -> *mut c_void;
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
    fn dispatch_time(when: u64, delta: i64) -> u64;
    fn dispatch_after_f(
        when: u64,
        queue: *mut AnyObject,
        context: *mut c_void,
        work: extern "C" fn(*mut c_void),
    );
}

/// The process's serial queue (created once, never released).
#[derive(Clone, Copy)]
pub(super) struct Queue(*mut AnyObject);

// SAFETY: a dispatch queue may be used from any thread.
unsafe impl Send for Queue {}
unsafe impl Sync for Queue {}

static QUEUE: OnceLock<Option<Queue>> = OnceLock::new();
/// What a panic that reached a work item's own catch means (the queue's
/// maker says: the helper exits, the in-process radio logs it).
static ON_PANIC: OnceLock<fn()> = OnceLock::new();
/// The queue's mark: its address is the key of the queue-specific value
/// [`on_queue`] reads.
static MARK: u8 = 0;

/// The process's queue: serial, with an autorelease pool per work item,
/// made at the first call (`None` if libdispatch gives none). `on_panic` is
/// what a panic past every other catch on it means, set by the first call.
pub(super) fn queue(on_panic: fn()) -> Option<Queue> {
    *QUEUE.get_or_init(|| {
        let _ = ON_PANIC.set(on_panic);
        // SAFETY: a static label; the attribute is the serial one (NULL)
        // with an autorelease pool per work item. The mark is a static, so
        // the context outlives the queue.
        unsafe {
            let attr = dispatch_queue_attr_make_with_autorelease_frequency(
                std::ptr::null_mut(),
                DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM,
            );
            let q = dispatch_queue_create(QUEUE_LABEL.as_ptr().cast(), attr);
            if q.is_null() {
                return None;
            }
            let mark = std::ptr::addr_of!(MARK).cast::<c_void>();
            dispatch_queue_set_specific(q, mark, mark.cast_mut(), None);
            Some(Queue(q))
        }
    })
}

fn current() -> Option<Queue> {
    QUEUE.get().copied().flatten()
}

/// Running on the queue now (a work item of it, or a callback on it).
pub(super) fn on_queue() -> bool {
    // SAFETY: a plain read of the current queue's value for the mark's key.
    !unsafe { dispatch_get_specific(std::ptr::addr_of!(MARK).cast()) }.is_null()
}

pub(super) type Work = Box<dyn FnOnce()>;

/// Run `f` on the queue later.
pub(super) fn post(f: Work) {
    let Some(q) = current() else {
        return;
    };
    let ctx = Box::into_raw(Box::new(f)).cast::<c_void>();
    // SAFETY: `ctx` is a leaked `Box<Work>` that `trampoline` takes back
    // exactly once.
    unsafe { dispatch_async_f(q.0, ctx, trampoline) };
}

/// Run `f` on the queue after `delay`.
pub(super) fn post_after(delay: Duration, f: Work) {
    let Some(q) = current() else {
        return;
    };
    let nanos = i64::try_from(delay.as_nanos()).unwrap_or(i64::MAX);
    let ctx = Box::into_raw(Box::new(f)).cast::<c_void>();
    // SAFETY: as in `post`.
    unsafe {
        let when = dispatch_time(DISPATCH_TIME_NOW, nanos);
        dispatch_after_f(when, q.0, ctx, trampoline);
    }
}

/// Run `f` on the queue and wait for it. Never on the queue itself: it
/// would wait for itself.
pub(super) fn run_sync(f: Work) {
    debug_assert!(
        !on_queue(),
        "run_sync on the nearby radio's own queue never returns"
    );
    let Some(q) = current() else {
        return;
    };
    let ctx = Box::into_raw(Box::new(f)).cast::<c_void>();
    // SAFETY: as in `post`.
    unsafe { dispatch_sync_f(q.0, ctx, trampoline) };
}

extern "C" fn trampoline(ctx: *mut c_void) {
    // SAFETY: `ctx` came from `post`, `post_after` or `run_sync`.
    let f = unsafe { Box::from_raw(ctx.cast::<Work>()) };
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        if let Some(on_panic) = ON_PANIC.get() {
            on_panic();
        }
    }
}

// ── The state on the queue ──────────────────────────────────────────────────

/// Where a life's lines go, and what its end after a panic means.
pub(super) trait Sink: Send + Sync {
    /// The lines the machine queued, in order (on the queue, the state lock
    /// released).
    fn say(&self, lines: Vec<FromHelper>);
    /// The machine's tick ran (on the queue).
    fn ticked(&self) {}
    /// Code on the queue panicked: this life is over (it was taken out of
    /// its slot already).
    fn panicked(&self);
}

/// One life: a machine (with, for CoreBluetooth, both managers, the
/// delegate and every object kept), the sink its lines go to, and which
/// life it is (the in-process radio's generation; the helper has one).
pub(super) struct Life<O: Os> {
    pub(super) m: Machine<O>,
    pub(super) sink: Arc<dyn Sink>,
    pub(super) id: u64,
}

// SAFETY: a life and the CoreBluetooth objects its machine holds are only
// ever touched on the serial queue: `make` makes them in a `run_sync` work
// item, which the queue serialises, and every input reaches them through
// `deliver`, which runs there.
unsafe impl<O: Os> Send for Life<O> {}

/// The one life of a machine of `O` at a time.
pub(super) type Slot<O> = Mutex<Option<Life<O>>>;

/// CoreBluetooth's life (one queue per process, one life at a time).
pub(super) static STATE: Slot<Cb> = Mutex::new(None);

/// Run `f` with the life in `slot` on the queue (nothing without one), then
/// hand the lines its machine queued to the life's sink once the lock is
/// released. A callback that comes while the state is in use (a call into
/// CoreBluetooth that calls back at once) is posted again. A panic in `f`
/// or in the sink ends the life ([`end_after_panic`]).
pub(super) fn deliver<O: Os + 'static>(
    slot: &'static Slot<O>,
    f: impl FnOnce(&mut Life<O>, Instant) + 'static,
) {
    let mut guard = match slot.try_lock() {
        Ok(g) => g,
        Err(TryLockError::Poisoned(p)) => p.into_inner(),
        Err(TryLockError::WouldBlock) => {
            post(Box::new(move || deliver(slot, f)));
            return;
        }
    };
    let Some(life) = guard.as_mut() else {
        return;
    };
    let id = life.id;
    let handled = catch_unwind(AssertUnwindSafe(|| {
        f(life, Instant::now());
        (life.m.take_out(), Arc::clone(&life.sink))
    }));
    drop(guard);
    let said = match handled {
        Ok((lines, _)) if lines.is_empty() => true,
        Ok((lines, sink)) => catch_unwind(AssertUnwindSafe(|| sink.say(lines))).is_ok(),
        Err(_) => false,
    };
    if !said {
        end_after_panic(slot, id);
    }
}

/// Life `id` panicked: it leaves `slot`, its sink is told, and what the
/// machine still has on the air is withdrawn as far as it goes; then every
/// object of it is let go of, here on the queue.
pub(super) fn end_after_panic<O: Os>(slot: &Slot<O>, id: u64) {
    let ended = {
        let mut guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.as_ref().is_some_and(|l| l.id == id) {
            guard.take()
        } else {
            None
        }
    };
    if let Some(mut life) = ended {
        let _ = catch_unwind(AssertUnwindSafe(|| life.sink.panicked()));
        let _ = catch_unwind(AssertUnwindSafe(|| life.m.stop()));
    }
}

/// A callback of `from` for CoreBluetooth's life: dropped unless `from` is
/// that life's delegate.
fn deliver_cb(from: &Delegate, input: Input) {
    let from = from.retain();
    deliver(&STATE, move |life, now| {
        if std::ptr::eq(&*from, &*life.m.os.delegate) {
            autoreleasepool(|_| handle(&mut life.m, input, now));
        }
    });
}

/// A delegate method's body: a panic in it never unwinds into
/// CoreBluetooth; it ends the delegate's life (posted, so the state lock is
/// free).
fn guarded(from: &Delegate, body: impl FnOnce()) {
    if catch_unwind(AssertUnwindSafe(body)).is_err() {
        let from = from.retain();
        post(Box::new(move || {
            let id = STATE
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .filter(|l| std::ptr::eq(&*from, &*l.m.os.delegate))
                .map(|l| l.id);
            if let Some(id) = id {
                end_after_panic(&STATE, id);
            }
        }));
    }
}

/// One thing CoreBluetooth said, for the machine.
enum Input {
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
            guarded(self, || {
                // SAFETY: `state` has no preconditions.
                deliver_cb(self, Input::CmState(unsafe { central.state() }.0));
            });
        }

        #[unsafe(method(centralManager:didDiscoverPeripheral:advertisementData:RSSI:))]
        fn discovered(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            data: &NSDictionary<NSString, AnyObject>,
            rssi: &NSNumber,
        ) {
            guarded(self, || {
                let uuids = advert_uuids(data);
                if uuids.is_empty() {
                    return;
                }
                deliver_cb(
                    self,
                    Input::Discovered {
                        peripheral: peripheral.retain(),
                        uuids,
                        connectable: advert_connectable(data),
                        rssi: i16::try_from(rssi.as_isize()).unwrap_or(i16::MIN),
                    },
                );
            });
        }

        #[unsafe(method(centralManager:didConnectPeripheral:))]
        fn connected(&self, _central: &CBCentralManager, peripheral: &CBPeripheral) {
            guarded(self, || {
                deliver_cb(self, Input::LinkUp(peripheral_id(peripheral)))
            });
        }

        #[unsafe(method(centralManager:didFailToConnectPeripheral:error:))]
        fn connect_failed(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            _error: Option<&NSError>,
        ) {
            guarded(self, || {
                deliver_cb(self, Input::LinkDown(peripheral_id(peripheral)))
            });
        }

        #[unsafe(method(centralManager:didDisconnectPeripheral:error:))]
        fn disconnected(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            _error: Option<&NSError>,
        ) {
            guarded(self, || {
                deliver_cb(self, Input::LinkDown(peripheral_id(peripheral)))
            });
        }
    }

    unsafe impl CBPeripheralDelegate for Delegate {
        #[unsafe(method(peripheral:didDiscoverServices:))]
        fn services(&self, peripheral: &CBPeripheral, error: Option<&NSError>) {
            guarded(self, || {
                deliver_cb(
                    self,
                    Input::Services(peripheral_id(peripheral), error.is_none()),
                );
            });
        }

        #[unsafe(method(peripheral:didDiscoverCharacteristicsForService:error:))]
        fn characteristics(
            &self,
            peripheral: &CBPeripheral,
            _service: &CBService,
            error: Option<&NSError>,
        ) {
            guarded(self, || {
                deliver_cb(
                    self,
                    Input::Characteristics(peripheral_id(peripheral), error.is_none()),
                );
            });
        }

        #[unsafe(method(peripheral:didUpdateNotificationStateForCharacteristic:error:))]
        fn notifying(
            &self,
            peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            guarded(self, || {
                // SAFETY: `isNotifying` has no preconditions.
                let on = error.is_none() && unsafe { characteristic.isNotifying() };
                deliver_cb(self, Input::Notifying(peripheral_id(peripheral), on));
            });
        }

        #[unsafe(method(peripheral:didUpdateValueForCharacteristic:error:))]
        fn value(
            &self,
            peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            guarded(self, || {
                let bytes = if error.is_none() {
                    // SAFETY: `value` has no preconditions.
                    unsafe { characteristic.value() }.map(|d| d.to_vec())
                } else {
                    None
                };
                deliver_cb(
                    self,
                    Input::Value(
                        peripheral_id(peripheral),
                        char_uuid_of(characteristic),
                        bytes,
                    ),
                );
            });
        }

        #[unsafe(method(peripheralIsReadyToSendWriteWithoutResponse:))]
        fn can_write(&self, peripheral: &CBPeripheral) {
            guarded(self, || {
                deliver_cb(self, Input::CanWrite(peripheral_id(peripheral)))
            });
        }

        #[unsafe(method(peripheral:didModifyServices:))]
        fn modified(&self, peripheral: &CBPeripheral, invalidated: &NSArray<CBService>) {
            guarded(self, || {
                let gone = invalidated
                    .to_vec()
                    .iter()
                    .filter_map(|s| attribute_uuid(s))
                    .collect();
                deliver_cb(self, Input::Invalidated(peripheral_id(peripheral), gone));
            });
        }
    }

    unsafe impl CBPeripheralManagerDelegate for Delegate {
        #[unsafe(method(peripheralManagerDidUpdateState:))]
        fn pm_state(&self, peripheral: &CBPeripheralManager) {
            guarded(self, || {
                // SAFETY: `state` has no preconditions.
                deliver_cb(self, Input::PmState(unsafe { peripheral.state() }.0));
            });
        }

        #[unsafe(method(peripheralManagerDidStartAdvertising:error:))]
        fn advertising(&self, _peripheral: &CBPeripheralManager, error: Option<&NSError>) {
            guarded(self, || {
                deliver_cb(self, Input::Advertising(error_code(error)))
            });
        }

        #[unsafe(method(peripheralManager:didAddService:error:))]
        fn added(
            &self,
            _peripheral: &CBPeripheralManager,
            service: &CBService,
            error: Option<&NSError>,
        ) {
            guarded(self, || {
                if let Some(t) = attribute_uuid(service) {
                    deliver_cb(self, Input::Added(t, error_code(error)));
                }
            });
        }

        #[unsafe(method(peripheralManager:central:didSubscribeToCharacteristic:))]
        fn subscribed(
            &self,
            _peripheral: &CBPeripheralManager,
            central: &CBCentral,
            characteristic: &CBCharacteristic,
        ) {
            guarded(self, || {
                if let Some(c) = char_uuid_of(characteristic) {
                    deliver_cb(self, Input::Subscribed(central.retain(), c));
                }
            });
        }

        #[unsafe(method(peripheralManager:central:didUnsubscribeFromCharacteristic:))]
        fn unsubscribed(
            &self,
            _peripheral: &CBPeripheralManager,
            central: &CBCentral,
            characteristic: &CBCharacteristic,
        ) {
            guarded(self, || {
                if let Some(c) = char_uuid_of(characteristic) {
                    deliver_cb(self, Input::Unsubscribed(central_id(central), c));
                }
            });
        }

        #[unsafe(method(peripheralManager:didReceiveWriteRequests:))]
        fn written(&self, _peripheral: &CBPeripheralManager, requests: &NSArray<CBATTRequest>) {
            guarded(self, || deliver_cb(self, Input::Written(requests.retain())));
        }

        #[unsafe(method(peripheralManager:didReceiveReadRequest:))]
        fn read(&self, _peripheral: &CBPeripheralManager, request: &CBATTRequest) {
            guarded(self, || deliver_cb(self, Input::Read(request.retain())));
        }

        #[unsafe(method(peripheralManagerIsReadyToUpdateSubscribers:))]
        fn can_notify(&self, _peripheral: &CBPeripheralManager) {
            guarded(self, || deliver_cb(self, Input::CanNotify));
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

/// CoreBluetooth as the machine's [`Os`]: both managers, this life's
/// delegate, and every object kept for what the machine does.
pub(super) struct Cb {
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
    /// The scan under way (or none).
    scanning: bool,
    /// Honour scan filters (iOS); the macOS helper scans for every advert.
    filtered: bool,
    /// The only service UUIDs to scan for (empty: every advert).
    filter: Vec<[u8; 16]>,
}

impl Cb {
    /// Log a CoreBluetooth error once in a row (codes only).
    fn note(&mut self, what: &str, code: Option<isize>) {
        let line = match code {
            Some(code) => format!("{what}: CoreBluetooth error {code}"),
            None => what.to_owned(),
        };
        if self.logged.as_ref() != Some(&line) {
            eprintln!("{LOG_PREFIX}: {line}");
            self.logged = Some(line);
        }
    }

    /// Start (or restart with the filter now) the scan: every advert is
    /// reported (duplicates allowed), so a contact stays seen.
    fn start_scan(&self) {
        let only: Vec<Retained<CBUUID>> = self.filter.iter().map(cbuuid).collect();
        let services = (!only.is_empty()).then(|| NSArray::from_retained_slice(&only));
        // SAFETY: a plain call on the central manager; calling it again
        // while scanning replaces the scan's services.
        unsafe {
            let options: Retained<NSDictionary<NSString, AnyObject>> =
                NSDictionary::from_retained_objects(
                    &[CBCentralManagerScanOptionAllowDuplicatesKey],
                    &[NSNumber::new_bool(true).into()],
                );
            self.cm
                .scanForPeripheralsWithServices_options(services.as_deref(), Some(&options));
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
        self.scanning = on;
        if on {
            self.start_scan();
        } else {
            // SAFETY: a plain call on the central manager.
            unsafe { self.cm.stopScan() };
        }
    }

    fn scan_filter(&mut self, only: &[[u8; 16]]) {
        if !self.filtered || self.filter == only {
            return;
        }
        self.filter = only.to_vec();
        if self.scanning {
            self.start_scan();
        }
    }

    fn connect(&mut self, dev: &str, t: [u8; 16], c: [u8; 16]) -> bool {
        let Some(p) = self.devices.get(dev) else {
            return false;
        };
        // SAFETY: a peripheral this manager discovered; the delegate lives
        // as long as this life.
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
        self.scanning = false;
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

// ── A life's start ──────────────────────────────────────────────────────────

/// What the logs of this code start with.
const LOG_PREFIX: &str = if cfg!(target_os = "ios") {
    "raven-node nearby"
} else {
    "raven-nearby-helper"
};

/// Whether this process's main bundle carries the Bluetooth usage
/// description (RavenNearby.app's, or the iOS app's own Info.plist).
pub(crate) fn has_usage_description() -> bool {
    debug_assert_eq!(USAGE_KEY, "NSBluetoothAlwaysUsageDescription");
    autoreleasepool(|_| {
        NSBundle::mainBundle()
            .objectForInfoDictionaryKey(ns_string!("NSBluetoothAlwaysUsageDescription"))
            .is_some()
    })
}

/// What a life's managers are made with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Options {
    /// The system's own alert when Bluetooth is off and a manager is made:
    /// `None` leaves it to the system (the macOS helper); the iOS app says
    /// `Some(false)` and shows its own row.
    pub(super) power_alert: Option<bool>,
    /// Honour scan filters (the iOS app's background scan).
    pub(super) filtered_scan: bool,
}

/// A manager's options: none, or the power alert key.
fn manager_options(
    key: &NSString,
    power_alert: Option<bool>,
) -> Option<Retained<NSDictionary<NSString, AnyObject>>> {
    power_alert
        .map(|show| NSDictionary::from_retained_objects(&[key], &[NSNumber::new_bool(show).into()]))
}

/// Make a life's delegate and managers, on the queue: the caller puts the
/// life in [`STATE`] in the same work item, so their first callbacks
/// (queued on the queue) find it in place.
pub(super) fn make(queue: Queue, options: Options) -> Cb {
    let delegate = Delegate::new();
    // SAFETY: CoreBluetooth constants.
    let (cm_key, pm_key) = unsafe {
        (
            CBCentralManagerOptionShowPowerAlertKey,
            CBPeripheralManagerOptionShowPowerAlertKey,
        )
    };
    let cm_options = manager_options(cm_key, options.power_alert);
    let pm_options = manager_options(pm_key, options.power_alert);
    let (cm_options, pm_options) = (cm_options.as_deref(), pm_options.as_deref());
    // SAFETY: `initWithDelegate:queue:options:` with a delegate that lives
    // as long as this life, a valid serial queue (an Objective-C object)
    // and no options, or only the power alert's.
    let (cm, pm): (Retained<CBCentralManager>, Retained<CBPeripheralManager>) = unsafe {
        let cm_delegate: &ProtocolObject<dyn CBCentralManagerDelegate> =
            ProtocolObject::from_ref(&*delegate);
        let pm_delegate: &ProtocolObject<dyn CBPeripheralManagerDelegate> =
            ProtocolObject::from_ref(&*delegate);
        (
            msg_send![CBCentralManager::alloc(), initWithDelegate: cm_delegate, queue: queue.0, options: cm_options],
            msg_send![CBPeripheralManager::alloc(), initWithDelegate: pm_delegate, queue: queue.0, options: pm_options],
        )
    };
    Cb {
        cm,
        pm,
        delegate,
        services: HashMap::new(),
        devices: HashMap::new(),
        links: HashMap::new(),
        centrals: HashMap::new(),
        logged: None,
        scanning: false,
        filtered: options.filtered_scan,
        filter: Vec::new(),
    }
}

/// The app's Bluetooth permission (`CBManagerAuthorization`'s raw value) in
/// the words of the engine API (`nearby.permission`): `not_determined`,
/// `restricted`, `denied` or `allowed`; an unknown value is
/// `not_determined`.
pub(crate) fn permission_word(raw: isize) -> &'static str {
    match raw {
        1 => "restricted",
        2 => "denied",
        3 => "allowed",
        _ => "not_determined",
    }
}

/// The app's Bluetooth permission now (`CBManager.authorization`, iOS 13.1
/// and later), read without a manager, so without a prompt.
#[cfg(target_os = "ios")]
pub(crate) fn authorization_raw() -> isize {
    use objc2_core_bluetooth::CBManager;
    // SAFETY: a class property with no preconditions.
    unsafe { CBManager::authorization_class() }.0
}

#[cfg(test)]
mod tests {
    use objc2::sel;

    use super::*;

    /// The delegate class registers and answers every callback the radio
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

    /// The usage-description texts of each system (Task 2 design §2.2 item
    /// 8): the helper's says RavenNearby.app, as it always did; the iOS
    /// app's is the in-process radio's own failure (`helper_unavailable`,
    /// not "no Bluetooth LE"); the build's own is its system's.
    #[test]
    fn the_usage_texts_name_each_systems_bundle() {
        assert_eq!(
            no_usage_text(false),
            "no usage description: raven-nearby-helper must run from RavenNearby.app, whose \
             Info.plist carries NSBluetoothAlwaysUsageDescription"
        );
        assert!(no_usage_text(true).starts_with("the nearby radio"));
        assert!(no_usage_text(true).contains("NSBluetoothAlwaysUsageDescription"));
        assert_eq!(NO_USAGE, no_usage_text(cfg!(target_os = "ios")));
        for (raw, word) in [
            (0, "not_determined"),
            (1, "restricted"),
            (2, "denied"),
            (3, "allowed"),
            (9, "not_determined"),
        ] {
            assert_eq!(permission_word(raw), word);
        }
    }

    /// A manager's options are none unless a power alert choice is given
    /// (the macOS helper gives none, as before). No manager is created.
    #[test]
    fn manager_options_are_none_or_the_power_alert_only() {
        // SAFETY: a CoreBluetooth constant.
        let key = unsafe { CBCentralManagerOptionShowPowerAlertKey };
        assert!(manager_options(key, None).is_none());
        let off = manager_options(key, Some(false)).unwrap();
        assert_eq!(off.count(), 1);
        let value = off.objectForKey(key).unwrap();
        assert!(!value.downcast::<NSNumber>().unwrap().as_bool());
    }
}
