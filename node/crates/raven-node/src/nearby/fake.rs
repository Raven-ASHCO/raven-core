//! The no-hardware radio of the nearby carrier (Nearby design step 5.5):
//! an in-process [`Ether`] that [`FakeRadio`]s advertise, scan, connect and
//! send frames on, with the link faults the tests need. Compiled into tests
//! and debug builds only; [`super::ether_hub`] serves one ether to lab
//! raven-nodes (`raven-node nearby-ether`). It needs a tokio runtime.
//!
//! - **Adverts:** every [`ADVERT_EVERY`] each scanning radio sees every
//!   other radio's advertised token (`Seen` with that one UUID: a fake
//!   advert has no name and no manufacturer data). Every token that goes on
//!   air is recorded ([`Ether::adverts`]) for privacy assertions.
//! - **Links:** connecting to a radio that publishes the service gives both
//!   sides `Connected` after the latency, the peripheral's first (the
//!   central has subscribed); anything else ends in `Disconnected`. A side
//!   sends frames of at most `min(ATT_MTU - 3, 512)` bytes
//!   ([`EtherParams::mtu_c2p`], [`EtherParams::mtu_p2c`]).
//! - **Air:** each link direction carries its frames in order, each after
//!   [`EtherParams::latency`] and at [`EtherParams::bytes_per_sec`]. At most
//!   [`LINK_QUEUE`] frames wait per direction; one more is
//!   [`Sent::WouldBlock`], and the sender gets one `Writable` once there is
//!   room.
//! - **Faults**, counting every frame that crossed the ether: the one after
//!   [`EtherParams::drop_after_frames`] is lost (once); the link carrying
//!   the one after [`EtherParams::disconnect_after_frames`] is cut (once).
//!   [`Ether::arm_faults`] arms them again, counted from then.
//!   `disconnect`, a withdrawn service or a dropped radio cuts a link too:
//!   both sides get `Disconnected`.
//! - **Power** ([`Ether::set_power`]): a radio switched off gets
//!   `State(PoweredOff)` and loses its links; it neither sees adverts nor is
//!   seen, and connects to or from it fail, until it is switched on again
//!   (`State(PoweredOn)`).
//! - **A sniffer's view** ([`Ether::hellos`]): every knock HELLO that
//!   crossed, with the service it was written to (a radio observer can
//!   capture the cleartext knock and replay it).
//! - **Events** go through [`EventTx`]: a full event queue cuts the link of
//!   the connection that lost an event, as on a real backend.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use raven_core::nearby_link::{Role, HELLO_LEN, KIND_HELLO, MAX_FRAME};
use tokio::sync::{mpsc, Notify};
use tokio::time::{Instant, MissedTickBehavior};

use super::lock;
use super::radio::{
    ConnId, EventTx, Privacy, Radio, RadioAddr, RadioCaps, RadioEvent, RadioState, Sent,
};

/// How often a scanner sees each advert.
pub(crate) const ADVERT_EVERY: Duration = Duration::from_millis(100);
/// Frames waiting per link direction before [`Sent::WouldBlock`].
pub(crate) const LINK_QUEUE: usize = 8;
/// The largest ATT MTU (512 bytes a frame).
pub(crate) const MAX_ATT_MTU: usize = 517;
/// The smallest ATT MTU (20 bytes a frame: no knock starts).
pub(crate) const MIN_ATT_MTU: usize = 23;
/// The adverts the ether keeps.
const MAX_ADVERT_RECORDS: usize = 4096;
/// The knock HELLOs the ether keeps ([`Ether::hellos`]).
const MAX_HELLO_RECORDS: usize = 64;
const ATT_HEADER: usize = 3;
const RSSI: i16 = -50;
const ADDR_PREFIX: &str = "ether-";

/// The ether's air: one set for every link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EtherParams {
    /// ATT MTU of central-to-peripheral writes.
    pub(crate) mtu_c2p: usize,
    /// ATT MTU of peripheral-to-central notifications.
    pub(crate) mtu_p2c: usize,
    /// How long each frame takes to arrive (and a connect to complete).
    pub(crate) latency: Duration,
    /// Each link direction's rate; 0 is no limit.
    pub(crate) bytes_per_sec: u32,
    /// Lose the frame after this many crossed the ether (once).
    pub(crate) drop_after_frames: Option<u64>,
    /// Cut the link carrying the frame after this many crossed the ether
    /// (once).
    pub(crate) disconnect_after_frames: Option<u64>,
}

impl Default for EtherParams {
    fn default() -> Self {
        Self {
            mtu_c2p: MAX_ATT_MTU,
            mtu_p2c: MAX_ATT_MTU,
            latency: Duration::ZERO,
            bytes_per_sec: 0,
            drop_after_frames: None,
            disconnect_after_frames: None,
        }
    }
}

impl EtherParams {
    /// The frame limit of an ATT MTU: `min(mtu - 3, 512)`.
    pub(crate) fn max_tx(mtu: usize) -> usize {
        mtu.saturating_sub(ATT_HEADER).min(MAX_FRAME)
    }

    /// Both MTUs within [`MIN_ATT_MTU`]..=[`MAX_ATT_MTU`].
    pub(crate) fn check(&self) -> Result<(), String> {
        for mtu in [self.mtu_c2p, self.mtu_p2c] {
            if !(MIN_ATT_MTU..=MAX_ATT_MTU).contains(&mtu) {
                return Err(format!(
                    "ATT MTU {mtu} is outside {MIN_ATT_MTU}..={MAX_ATT_MTU}"
                ));
            }
        }
        Ok(())
    }
}

/// One fake radio's own traits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FakeOpts {
    /// No GATT server and no advertising (Windows without a working
    /// GattServiceProvider).
    pub(crate) central_only: bool,
    /// Reports a public advertising address.
    pub(crate) public_address: bool,
}

/// One token that went on air: what an advert carried, all of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdvertRecord {
    pub(crate) radio: String,
    pub(crate) uuids: Vec<[u8; 16]>,
}

/// The shared air of a set of fake radios.
#[derive(Clone)]
pub(crate) struct Ether {
    inner: Arc<Mutex<EtherState>>,
}

struct EtherState {
    params: EtherParams,
    next_id: u64,
    radios: HashMap<u64, Slot>,
    links: HashMap<u64, Link>,
    /// Connection: its link and end (0 central, 1 peripheral).
    conns: HashMap<ConnId, (u64, usize)>,
    /// Frames that crossed (delivered or lost).
    crossed: u64,
    dropped_once: bool,
    cut_once: bool,
    adverts: Vec<AdvertRecord>,
    /// Knock HELLOs that crossed: (service, frame).
    hellos: Vec<([u8; 16], Vec<u8>)>,
}

struct Slot {
    name: String,
    events: EventTx,
    scanning: bool,
    services: Vec<[u8; 16]>,
    advert: Option<[u8; 16]>,
    /// Switched on ([`Ether::set_power`]).
    powered: bool,
}

struct Link {
    service: [u8; 16],
    ends: [End; 2],
}

struct End {
    radio: u64,
    conn: ConnId,
    max_tx: usize,
    /// Frames this end sent that have not arrived yet.
    queue: VecDeque<(Vec<u8>, Instant)>,
    want_writable: bool,
    wake: Arc<Notify>,
}

impl EtherState {
    fn alloc(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// End `link`: both connections get `Disconnected`.
    fn cut(&mut self, link: u64) {
        let Some(l) = self.links.remove(&link) else {
            return;
        };
        for e in &l.ends {
            self.conns.remove(&e.conn);
            e.wake.notify_one();
            if let Some(s) = self.radios.get(&e.radio) {
                let _ = s.events.emit(RadioEvent::Disconnected { conn: e.conn });
            }
        }
    }

    /// Queue `ev` for radio `id`; a connection that lost an event has its
    /// link cut.
    fn emit(&mut self, id: u64, ev: RadioEvent) {
        let Some(s) = self.radios.get(&id) else {
            return;
        };
        if let Err(Some(conn)) = s.events.emit(ev) {
            if let Some(&(link, _)) = self.conns.get(&conn) {
                self.cut(link);
            }
        }
    }
}

impl Ether {
    /// A new ether; its advert ticker runs while any handle or radio of it
    /// lives.
    pub(crate) fn new(params: EtherParams) -> Self {
        let inner = Arc::new(Mutex::new(EtherState {
            params,
            next_id: 0,
            radios: HashMap::new(),
            links: HashMap::new(),
            conns: HashMap::new(),
            crossed: 0,
            dropped_once: false,
            cut_once: false,
            adverts: Vec::new(),
            hellos: Vec::new(),
        }));
        tokio::spawn(advertise(Arc::downgrade(&inner)));
        Self { inner }
    }

    /// A radio named `name` (for the advert records) on this ether, telling
    /// `tx` what happens.
    #[cfg(test)]
    pub(crate) fn radio(&self, name: &str, tx: mpsc::Sender<RadioEvent>) -> FakeRadio {
        self.radio_with(name, tx, FakeOpts::default())
    }

    pub(crate) fn radio_with(
        &self,
        name: &str,
        tx: mpsc::Sender<RadioEvent>,
        opts: FakeOpts,
    ) -> FakeRadio {
        let events = EventTx::new(tx);
        let _ = events.emit(RadioEvent::State(RadioState::PoweredOn));
        let mut st = lock(&self.inner);
        let id = st.alloc();
        st.radios.insert(
            id,
            Slot {
                name: name.to_owned(),
                events: events.clone(),
                scanning: false,
                services: Vec::new(),
                advert: None,
                powered: true,
            },
        );
        FakeRadio {
            ether: self.clone(),
            id,
            events,
            opts,
        }
    }

    /// Every token that went on air, in order.
    pub(crate) fn adverts(&self) -> Vec<AdvertRecord> {
        lock(&self.inner).adverts.clone()
    }

    /// Frames that crossed the ether (delivered or lost).
    #[cfg(test)]
    pub(crate) fn crossed(&self) -> u64 {
        lock(&self.inner).crossed
    }

    /// Links up now.
    #[cfg(test)]
    pub(crate) fn links(&self) -> usize {
        lock(&self.inner).links.len()
    }

    /// The knock HELLOs that crossed the ether, oldest first, with the
    /// service each was written to: what a radio observer captures.
    pub(crate) fn hellos(&self) -> Vec<([u8; 16], Vec<u8>)> {
        lock(&self.inner).hellos.clone()
    }

    /// The names of the radios on the ether, and whether each is on.
    pub(crate) fn radios(&self) -> Vec<(String, bool)> {
        let st = lock(&self.inner);
        let mut out: Vec<(String, bool)> = st
            .radios
            .values()
            .map(|s| (s.name.clone(), s.powered))
            .collect();
        out.sort();
        out
    }

    /// Switch the radios named `name` on or off (the user's Bluetooth
    /// switch). Off: `State(PoweredOff)`, every link of theirs cut, no
    /// advert seen either way and no connect, until on (`State(PoweredOn)`).
    /// How many radios have that name.
    pub(crate) fn set_power(&self, name: &str, on: bool) -> usize {
        let mut st = lock(&self.inner);
        let ids: Vec<u64> = st
            .radios
            .iter()
            .filter(|(_, s)| s.name == name)
            .map(|(&id, _)| id)
            .collect();
        for &id in &ids {
            let Some(slot) = st.radios.get_mut(&id) else {
                continue;
            };
            if slot.powered == on {
                continue;
            }
            slot.powered = on;
            if !on {
                let mine: Vec<u64> = st
                    .links
                    .iter()
                    .filter(|(_, l)| l.ends.iter().any(|e| e.radio == id))
                    .map(|(&link, _)| link)
                    .collect();
                for link in mine {
                    st.cut(link);
                }
            }
            let state = if on {
                RadioState::PoweredOn
            } else {
                RadioState::PoweredOff
            };
            st.emit(id, RadioEvent::State(state));
        }
        ids.len()
    }

    /// Frames that crossed the ether so far, and whether the armed lost
    /// frame and the armed cut happened.
    pub(crate) fn fault_stats(&self) -> (u64, bool, bool) {
        let st = lock(&self.inner);
        (st.crossed, st.dropped_once, st.cut_once)
    }

    /// Arm the faults again, counted from now: the frame after
    /// `drop_after` more frames crossed is lost (once), the link carrying
    /// the one after `disconnect_after` more is cut (once). `None` disarms.
    pub(crate) fn arm_faults(&self, drop_after: Option<u64>, disconnect_after: Option<u64>) {
        let mut st = lock(&self.inner);
        let now = st.crossed;
        st.params.drop_after_frames = drop_after.map(|n| now.saturating_add(n));
        st.params.disconnect_after_frames = disconnect_after.map(|n| now.saturating_add(n));
        st.dropped_once = false;
        st.cut_once = false;
    }
}

fn addr_of(id: u64) -> RadioAddr {
    RadioAddr(format!("{ADDR_PREFIX}{id}"))
}

fn id_of(addr: &RadioAddr) -> Option<u64> {
    addr.0.strip_prefix(ADDR_PREFIX)?.parse().ok()
}

/// Every [`ADVERT_EVERY`]: each scanner sees each other radio's advert, and
/// owed `Disconnected` events go out.
async fn advertise(ether: Weak<Mutex<EtherState>>) {
    let mut tick = tokio::time::interval(ADVERT_EVERY);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let Some(inner) = ether.upgrade() else {
            return;
        };
        let st = lock(&inner);
        for s in st.radios.values() {
            s.events.flush();
        }
        let adverts: Vec<(u64, [u8; 16])> = st
            .radios
            .iter()
            .filter(|(_, s)| s.powered)
            .filter_map(|(&id, s)| s.advert.map(|t| (id, t)))
            .collect();
        for (&id, s) in st.radios.iter().filter(|(_, s)| s.scanning && s.powered) {
            for &(from, t) in adverts.iter().filter(|(from, _)| *from != id) {
                let _ = s.events.emit(RadioEvent::Seen {
                    addr: addr_of(from),
                    uuids: vec![t],
                    rssi: RSSI,
                });
            }
        }
    }
}

/// One link direction: the frames end `from` sent, to the other end.
async fn carry(ether: Weak<Mutex<EtherState>>, link: u64, from: usize) {
    let mut next_free = Instant::now();
    loop {
        let (wake, due) = {
            let Some(inner) = ether.upgrade() else {
                return;
            };
            let st = lock(&inner);
            let Some(l) = st.links.get(&link) else {
                return;
            };
            let e = &l.ends[from];
            match e.queue.front() {
                None => (Some(e.wake.clone()), None),
                Some((f, at)) => {
                    // No rate (0) is no air time.
                    let air = (f.len() as u64 * 1_000_000)
                        .checked_div(u64::from(st.params.bytes_per_sec))
                        .map_or(Duration::ZERO, Duration::from_micros);
                    next_free = next_free.max(Instant::now()) + air;
                    (None, Some(next_free.max(*at + st.params.latency)))
                }
            }
        };
        if let Some(wake) = wake {
            wake.notified().await;
            continue;
        }
        if let Some(due) = due {
            tokio::time::sleep_until(due).await;
        }
        let Some(inner) = ether.upgrade() else {
            return;
        };
        let mut st = lock(&inner);
        let Some(l) = st.links.get_mut(&link) else {
            return;
        };
        let Some((frame, _)) = l.ends[from].queue.pop_front() else {
            continue;
        };
        let room = l.ends[from].queue.len() < LINK_QUEUE && l.ends[from].want_writable;
        if room {
            l.ends[from].want_writable = false;
        }
        let (src, src_conn) = (l.ends[from].radio, l.ends[from].conn);
        let (dst, dst_conn) = (l.ends[1 - from].radio, l.ends[1 - from].conn);
        let service = l.service;
        if from == 0
            && frame.len() == HELLO_LEN
            && frame.first() == Some(&KIND_HELLO)
            && st.hellos.len() < MAX_HELLO_RECORDS
        {
            st.hellos.push((service, frame.clone()));
        }
        st.crossed += 1;
        let n = st.crossed;
        if !st.cut_once
            && st
                .params
                .disconnect_after_frames
                .is_some_and(|k| n == k + 1)
        {
            st.cut_once = true;
            st.cut(link);
            return;
        }
        if !st.dropped_once && st.params.drop_after_frames.is_some_and(|k| n == k + 1) {
            st.dropped_once = true;
        } else {
            st.emit(
                dst,
                RadioEvent::Frame {
                    conn: dst_conn,
                    bytes: frame,
                },
            );
        }
        if room && st.links.contains_key(&link) {
            st.emit(src, RadioEvent::Writable { conn: src_conn });
        }
    }
}

/// A radio on an [`Ether`]. Dropping it cuts its links.
pub(crate) struct FakeRadio {
    ether: Ether,
    id: u64,
    events: EventTx,
    opts: FakeOpts,
}

impl FakeRadio {
    /// The address other radios see this one at.
    #[cfg(test)]
    pub(crate) fn addr(&self) -> RadioAddr {
        addr_of(self.id)
    }
}

impl Radio for FakeRadio {
    fn caps(&self) -> RadioCaps {
        RadioCaps {
            central: true,
            peripheral: !self.opts.central_only,
            l2cap: false,
            address_privacy: if self.opts.public_address {
                Privacy::Public
            } else {
                Privacy::Random
            },
            per_central_notify: true,
        }
    }

    fn set_services(
        &mut self,
        services: &[[u8; 16]],
        advertise: Option<[u8; 16]>,
    ) -> Result<(), String> {
        if self.opts.central_only && !services.is_empty() {
            return Err("this radio cannot be a peripheral".into());
        }
        if advertise.is_some_and(|t| !services.contains(&t)) {
            return Err("the advertised service is not published".into());
        }
        let mut st = lock(&self.ether.inner);
        let withdrawn: Vec<u64> = st
            .links
            .iter()
            .filter(|(_, l)| l.ends[1].radio == self.id && !services.contains(&l.service))
            .map(|(&id, _)| id)
            .collect();
        for link in withdrawn {
            st.cut(link);
        }
        let Some(slot) = st.radios.get_mut(&self.id) else {
            return Err("radio gone".into());
        };
        // Off, nothing goes on air (the token is recorded once it does).
        let fresh = advertise.filter(|t| slot.powered && slot.advert != Some(*t));
        slot.services = services.to_vec();
        slot.advert = advertise;
        let name = slot.name.clone();
        if let Some(t) = fresh {
            if st.adverts.len() < MAX_ADVERT_RECORDS {
                st.adverts.push(AdvertRecord {
                    radio: name,
                    uuids: vec![t],
                });
            }
        }
        Ok(())
    }

    fn set_scanning(&mut self, on: bool) -> Result<(), String> {
        let mut st = lock(&self.ether.inner);
        let slot = st.radios.get_mut(&self.id).ok_or("radio gone")?;
        slot.scanning = on;
        Ok(())
    }

    fn connect(&mut self, addr: &RadioAddr, service: [u8; 16]) -> Result<ConnId, String> {
        let weak = Arc::downgrade(&self.ether.inner);
        let mut st = lock(&self.ether.inner);
        let conn_c = st.alloc();
        let latency = st.params.latency;
        let powered = |id: &u64| st.radios.get(id).is_some_and(|s| s.powered);
        let peer = id_of(addr).filter(|p| {
            *p != self.id
                && powered(&self.id)
                && powered(p)
                && st
                    .radios
                    .get(p)
                    .is_some_and(|s| s.services.contains(&service))
        });
        let Some(peer) = peer else {
            let events = self.events.clone();
            tokio::spawn(async move {
                tokio::time::sleep(latency).await;
                let _ = events.emit(RadioEvent::Disconnected { conn: conn_c });
            });
            return Ok(conn_c);
        };
        let conn_p = st.alloc();
        let link = st.alloc();
        let max_c = EtherParams::max_tx(st.params.mtu_c2p);
        let max_p = EtherParams::max_tx(st.params.mtu_p2c);
        let end = |radio: u64, conn: ConnId, max_tx: usize| End {
            radio,
            conn,
            max_tx,
            queue: VecDeque::new(),
            want_writable: false,
            wake: Arc::new(Notify::new()),
        };
        st.links.insert(
            link,
            Link {
                service,
                ends: [end(self.id, conn_c, max_c), end(peer, conn_p, max_p)],
            },
        );
        st.conns.insert(conn_c, (link, 0));
        st.conns.insert(conn_p, (link, 1));
        tokio::spawn(carry(weak.clone(), link, 0));
        tokio::spawn(carry(weak.clone(), link, 1));
        let central = self.id;
        tokio::spawn(async move {
            tokio::time::sleep(latency).await;
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let mut st = lock(&inner);
            if !st.links.contains_key(&link) {
                return;
            }
            let up = |conn, role, max_tx, max_rx| RadioEvent::Connected {
                conn,
                role,
                service,
                max_tx,
                max_rx,
            };
            st.emit(peer, up(conn_p, Role::Peripheral, max_p, max_c));
            if st.links.contains_key(&link) {
                st.emit(central, up(conn_c, Role::Central, max_c, max_p));
            }
        });
        Ok(conn_c)
    }

    fn send(&mut self, conn: ConnId, frame: &[u8]) -> Result<Sent, String> {
        let mut st = lock(&self.ether.inner);
        let &(link, end) = st.conns.get(&conn).ok_or("not connected")?;
        let e = &mut st.links.get_mut(&link).ok_or("not connected")?.ends[end];
        if e.radio != self.id {
            return Err("not this radio's connection".into());
        }
        if frame.is_empty() || frame.len() > e.max_tx {
            return Err(format!(
                "a frame of {} bytes on a link of max_tx {}",
                frame.len(),
                e.max_tx
            ));
        }
        if e.queue.len() >= LINK_QUEUE {
            e.want_writable = true;
            return Ok(Sent::WouldBlock);
        }
        e.queue.push_back((frame.to_vec(), Instant::now()));
        e.wake.notify_one();
        Ok(Sent::Queued)
    }

    fn disconnect(&mut self, conn: ConnId) {
        let mut st = lock(&self.ether.inner);
        if let Some(&(link, end)) = st.conns.get(&conn) {
            if st
                .links
                .get(&link)
                .is_some_and(|l| l.ends[end].radio == self.id)
            {
                st.cut(link);
            }
        }
    }

    fn overflows(&self) -> u64 {
        self.events.dropped()
    }
}

impl Drop for FakeRadio {
    fn drop(&mut self) {
        let mut st = lock(&self.ether.inner);
        let mine: Vec<u64> = st
            .links
            .iter()
            .filter(|(_, l)| l.ends.iter().any(|e| e.radio == self.id))
            .map(|(&id, _)| id)
            .collect();
        for link in mine {
            st.cut(link);
        }
        st.radios.remove(&self.id);
    }
}

#[cfg(test)]
mod tests;
