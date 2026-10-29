//! Network-change detection (transports design 2026-10 §2.4, G1).
//!
//! Nothing else notices this machine's own addresses changing (Wi-Fi to a
//! hotspot, a new DHCP lease, a cable, a VPN), so a queued message would sit
//! out its backoff (up to 10 min) on a network where its contact may be
//! reachable now. This supervised task watches the OS's address-change channel
//! (if-watch: netlink on Linux, an SCDynamicStore thread on macOS,
//! `NotifyIpInterfaceChange` on Windows) and tells the outbox when the set of
//! usable networks changed.
//!
//! - **What counts:** IPv4 addresses and IPv6 prefixes (a temporary "privacy"
//!   address rotating inside its prefix is not a change). Loopback,
//!   link-local (169.254/16, fe80::/10), multicast, broadcast and unspecified
//!   addresses never count, so AWDL / utun / container veth churn does not
//!   even arm the timer. A container or VM bridge with a private address
//!   (Docker's 172.17.0.1/16, a VM host's 192.168.64.1/24) does count.
//! - **A cable alone (cutoff pack F6; the offline-LAN gate,
//!   [`raven_core::offline_lan_live`], read once at start):** while nothing
//!   above counts, IPv4 link-local addresses (169.254/16: two laptops on a
//!   cable with no DHCP server) count, each as itself ([`view_keys`]). Never
//!   fe80::/10: every up interface (awdl, utun, llw) carries one. "No
//!   network" to "link-local only", a move between link-local addresses and
//!   "link-local only" to a normal network are each a change (`link-local
//!   network only (a cable?)` while only those count); beside a counted
//!   network one never counts. Gate closed: never, as above. if-watch
//!   reports addresses, not interface states: a 169.254 address counts while
//!   the OS reports it, as every other address does.
//! - **Baseline:** every watcher first reports the addresses that already
//!   exist; the first settled view is the baseline (`watching (N networks)`),
//!   not a change.
//! - **Debounce:** a burst of events is one decision, [`QUIET`] after its last
//!   event and at most [`MAX_SETTLE`] after its first. A view equal to the last
//!   one acted on is nothing.
//! - **Gap:** changes are acted on at least [`GAP_MIN`] apart; the gap doubles
//!   up to [`GAP_MAX`] while they keep coming and is back to [`GAP_MIN`] after
//!   [`GAP_CALM`] without one.
//! - **No network:** losing every usable network is logged and retries
//!   nothing; the network coming back (with F6, a cable alone too) is a
//!   change.
//! - **Wake from sleep:** every [`WAKE_TICK`] the wall clock is compared with
//!   the monotonic clock. When it ran [`WAKE_SLACK`] or more ahead (macOS and
//!   Linux stop the monotonic clock while asleep), or the monotonic clock
//!   itself jumped that far past a check (Windows counts sleep; a stopped
//!   process), that is a change even if no address moved (`woke from
//!   sleep`), and the gap does not hold it. The clock is seeded again at
//!   every (re)open, so a reopen backoff is no sleep. Release builds too (P2a
//!   amendment draft §2 item 2).
//! - **Default route moved:** while a p2p host runs or route memory is live
//!   (lab), [`raven_core::route_memory::egress_tag`] (the source addresses
//!   the default routes use: a UDP `connect`, nothing sent) is read every
//!   [`EGRESS_POLL`] and right before each decision. A move with the same
//!   networks is a change (`default route moved`); the first reading only
//!   seeds. Release builds run neither, so they never read it. The last
//!   reading (a lab `egress` line included) is kept for [`last_egress`]: the
//!   "nobody reachable" diagnosis says `no_route` while there is none, and
//!   the `no_route` reasons go when one is back.
//! - **Every relay silent:** the p2p host [`hint`]s when every relay holding
//!   a reservation failed its pings within a minute and no other connection
//!   answered one (an open direct connection to anyone else is given one
//!   ping round to answer first). The default route is read again first:
//!   moved, that is a `default route moved` change; otherwise it is a path
//!   loss our addresses do not show (`every relay stopped answering`): the
//!   p2p host re-homes, custodians are due, the outbox keeps its backoff
//!   (the re-homed host kicks it). Debounced and held by the gap like a
//!   change.
//! - **Action:** p2p first. When the paths are stale (a network gone unless
//!   the default route was read and stayed, back from no network, the
//!   default route moved, a wake), [`crate::p2p::network_changed`] (a
//!   running libp2p host re-homes: a fresh endpoint on the same relays;
//!   nothing without one); when networks were only added (a container
//!   bridge, a second IPv6 prefix), or only gone beside a default route
//!   that was read and stayed (a bridge stopped, a second NIC unplugged),
//!   [`crate::p2p::nudge`] (idle relay slots retry at once). Then
//!   [`crate::outbox::network_changed`] (every queued object and owed ACK on
//!   a fresh backoff, each contact due within 5 s),
//!   [`crate::custody::network_changed`] (custodians due; nothing while the
//!   custody gate is closed), [`crate::renewal::network_changed`] (the
//!   session renewer forgets its per-contact rechecks and lapse marks;
//!   nothing while its gate is closed) and
//!   [`crate::lan_beacon::network_changed`] (the LAN beacon reads the
//!   interfaces again, drops what it found on gone ones, starts every
//!   contact's query interval over and sends a join round; nothing while its
//!   gate is closed). Losing every network tells the beacon
//!   too. One log line with counts only, never an address.
//! - **Current networks (lab):** each baseline, change and loss of every
//!   network leaves the networks it settled on for [`on_link`]. While route
//!   memory is live, the outbox skips a learned LAN address
//!   ([`raven_core::lan_seen`]) that is on none of them (it is from a network
//!   this computer left), unless a point-to-point network of its family is
//!   up (a VPN's /32 or /31, an IPv6 /127 or /128, which may route to it);
//!   saved addresses are always dialled.
//! - **Failure:** a watcher that cannot be opened, fails or ends is reopened
//!   after [`REOPEN_MIN`] doubling to [`REOPEN_MAX`] (logged once an hour at
//!   most); meanwhile the outbox keeps its own timers, as before this task. A
//!   failed watcher is never polled again (if-watch repeats its error on every
//!   poll). The baseline survives a reopen, so a change made while no watcher
//!   ran is still noticed.
//!
//! Not a carrier and not gated: it opens no port and sends nothing (the
//! default-route reading binds a UDP socket for a moment, beside a p2p host
//! or live route memory only); it only brings forward retries the outbox
//! would make anyway, through the same route plan, gates and contact checks.
//!
//! Debug builds only: `RAVEN_LAB_NETWATCH_EVENTS=<file>` replaces the OS
//! watcher, the wake clock and the default-route reading with lines appended
//! to that file (`up 192.0.2.10/24`, `down …`, `wake`, `egress <hex>`,
//! `egress none`), so the harnesses can change "the network" without root.
//! Release builds never read it.

use std::collections::{BTreeSet, VecDeque};
use std::convert::Infallible;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use futures::{Stream, StreamExt};
use if_watch::{IfEvent, IpNet};
use tokio::sync::Notify;
use tokio::time::{Instant, MissedTickBehavior};

use crate::netutil;

/// A burst of address events is decided this long after its last event…
const QUIET: Duration = Duration::from_secs(2);
/// …and at most this long after its first (an interface that never settles).
const MAX_SETTLE: Duration = Duration::from_secs(10);
/// Acted-on changes are at least this far apart…
const GAP_MIN: Duration = Duration::from_secs(10);
/// …the gap doubling up to this while changes keep coming (a flapping link)…
const GAP_MAX: Duration = Duration::from_secs(300);
/// …and back to [`GAP_MIN`] after this long without an acted-on change.
const GAP_CALM: Duration = Duration::from_secs(600);
/// A watcher that failed is reopened after this, doubling up to [`REOPEN_MAX`].
const REOPEN_MIN: Duration = Duration::from_secs(5);
const REOPEN_MAX: Duration = Duration::from_secs(300);
/// Addresses tracked at most (a host has a handful; this bounds a flood).
const MAX_ADDRS: usize = 1024;
/// How often the debug lab event file is read.
const LAB_POLL: Duration = Duration::from_millis(100);
/// The wall clock is compared with the monotonic clock this often…
const WAKE_TICK: Duration = Duration::from_secs(5);
/// …and running this far ahead of it (or the monotonic clock jumping this far
/// past a check) means this computer slept.
const WAKE_SLACK: Duration = Duration::from_secs(30);
/// How often the default routes' fingerprint is read while something needs
/// it (and right before each decision).
const EGRESS_POLL: Duration = Duration::from_secs(30);
/// A lab `egress` line carries 1 to this many lowercase hex digits.
const LAB_EGRESS_MAX: usize = 64;

/// A watcher that cannot be opened or failed: one line an hour at most.
static NETWATCH_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(3600));

/// The networks the service's task last settled on ([`on_link`]); `None`
/// before its first baseline.
static VIEW: Mutex<Option<Vec<IpNet>>> = Mutex::new(None);

/// Whether the last default-route reading of the service's task found one
/// ([`last_egress`]); `None` before its first reading.
static LAST_EGRESS: Mutex<Option<bool>> = Mutex::new(None);

/// What identifies a network for change detection; `None`: never counts.
fn key(net: &IpNet) -> Option<IpNet> {
    match net {
        IpNet::V4(n) => {
            let ip = n.addr();
            let skip = ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast();
            (!skip).then_some(*net)
        }
        IpNet::V6(n) => {
            let ip = n.addr();
            // fe80::/10, as raven_core::outbox::is_local_network_ip.
            let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || link_local {
                return None;
            }
            // The prefix: temporary (privacy) addresses rotate inside it.
            Some(IpNet::V6(n.trunc()))
        }
    }
}

/// F6: an IPv4 link-local address (169.254/16), what a cable between two
/// laptops with no DHCP server gives each of them. IPv6 link-local never
/// qualifies.
fn cable_link_local(net: &IpNet) -> bool {
    matches!(net, IpNet::V4(n) if n.addr().is_link_local())
}

/// Whether an address is tracked at all: one [`key`] counts, and with F6
/// open (`live`) an IPv4 link-local one too. Nothing else arms the timer.
fn tracked(net: &IpNet, live: bool) -> bool {
    key(net).is_some() || (live && cable_link_local(net))
}

/// The networks `addrs` count as (pure). Gate closed (`live` false): exactly
/// [`key`]'s. Open (F6): when [`key`] counts none, the IPv4 link-local
/// addresses, each as itself (as any IPv4 network); beside a counted one
/// they never count.
fn view_keys(addrs: &BTreeSet<IpNet>, live: bool) -> BTreeSet<IpNet> {
    let counted: BTreeSet<IpNet> = addrs.iter().filter_map(key).collect();
    if !counted.is_empty() || !live {
        return counted;
    }
    addrs
        .iter()
        .filter(|net| cable_link_local(net))
        .copied()
        .collect()
}

/// Why a change is acted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    /// The usable networks changed.
    Addresses,
    /// This computer woke from sleep ([`WakeClock`], or a lab `wake` line).
    Wake,
    /// The default routes moved while the networks stayed the same.
    Route,
}

/// A change to act on (counts only).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Change {
    added: usize,
    removed: usize,
    networks: usize,
    cause: Cause,
    /// Back from "no network": every path is new.
    from_offline: bool,
    /// The default routes' source fingerprint moved (only while it is read).
    egress_moved: bool,
    /// It was read, names a default route and did not move.
    egress_kept: bool,
    /// The networks now are IPv4 link-local addresses only (F6: a cable
    /// with no DHCP server); never while the gate is closed.
    link_local: bool,
}

impl Change {
    /// Connections, NAT mappings and reachability results made before this
    /// change cannot be trusted: the p2p host starts over. Networks only
    /// added (a container bridge, a second IPv6 prefix) keep them, and so do
    /// networks gone while the default route is known to have stayed (a
    /// container or VM bridge stopped, a second NIC unplugged): the paths
    /// out did not move, and a connection that did use a network gone fails
    /// its pings.
    fn paths_stale(&self) -> bool {
        (self.removed > 0 && !self.egress_kept)
            || self.from_offline
            || self.egress_moved
            || self.cause != Cause::Addresses
    }
}

/// What a settled burst means.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Settled {
    /// The first view after start: nothing to retry.
    Baseline { networks: usize },
    /// Something to act on: the networks changed, this computer woke, or
    /// the default route moved.
    Changed(Change),
    /// Every usable network is gone: nothing is retried until one is back.
    Offline,
    /// Every relay stopped answering and nothing here changed (p2p only).
    PathLoss,
}

/// What makes a burst a decision even when no network moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Forced {
    Wake,
    Route,
    PathLoss,
}

/// The debounce and gap rules over the address events (pure: the caller
/// passes the time).
struct NetState {
    /// Significant addresses as the events left them (raw, not keys).
    addrs: BTreeSet<IpNet>,
    /// The networks last acted on; `None` until the baseline.
    settled: Option<BTreeSet<IpNet>>,
    /// The current burst: its first and its latest event.
    dirty_since: Option<Instant>,
    last_event: Option<Instant>,
    /// The last change acted on, and the gap the next one keeps from it.
    last_fire: Option<Instant>,
    gap: Duration,
    /// Makes the current burst a change even if the networks stay the same.
    forced: Option<Forced>,
    /// The default routes' fingerprint as last read (`None`: never read)…
    egress_seen: Option<Option<String>>,
    /// …and as last acted on (`None`: not seeded by a first reading yet).
    egress_acted: Option<Option<String>>,
    /// F6 is open ([`view_keys`]): IPv4 link-local addresses are tracked
    /// and count while nothing else does.
    link_local: bool,
}

impl NetState {
    /// `link_local`: F6 is open (the offline-LAN gate, [`Probes::link_local`]).
    fn new(link_local: bool) -> Self {
        Self {
            addrs: BTreeSet::new(),
            settled: None,
            dirty_since: None,
            last_event: None,
            last_fire: None,
            gap: GAP_MIN,
            forced: None,
            egress_seen: None,
            egress_acted: None,
            link_local,
        }
    }

    fn keys(&self) -> BTreeSet<IpNet> {
        view_keys(&self.addrs, self.link_local)
    }

    /// Something to decide: the current burst starts, or goes on, now.
    fn arm(&mut self, now: Instant) {
        self.dirty_since.get_or_insert(now);
        self.last_event = Some(now);
    }

    fn apply(&mut self, ev: NetEvent, now: Instant) {
        match ev {
            NetEvent::If(ev) => self.event(ev, now),
            NetEvent::Wake => self.wake(now),
            NetEvent::Egress(tag) => self.egress(tag, now),
        }
    }

    /// One address event. Only an actual change of the significant set arms
    /// the timer.
    fn event(&mut self, ev: IfEvent, now: Instant) {
        let changed = match ev {
            IfEvent::Up(net) => {
                tracked(&net, self.link_local)
                    && self.addrs.len() < MAX_ADDRS
                    && self.addrs.insert(net)
            }
            IfEvent::Down(net) => self.addrs.remove(&net),
        };
        if changed {
            self.arm(now);
        }
    }

    /// This computer woke from sleep: every path is suspect, and the gap
    /// does not hold it (the monotonic clock it is kept on may have stood
    /// still while asleep).
    fn wake(&mut self, now: Instant) {
        self.forced = Some(Forced::Wake);
        self.last_fire = None;
        self.gap = GAP_MIN;
        self.arm(now);
    }

    /// The default routes' fingerprint was read. The first reading only
    /// seeds (a p2p host started after the baseline must not see a change
    /// in it); after the baseline, a move away from the one last acted on is
    /// a change.
    fn egress(&mut self, tag: Option<String>, now: Instant) {
        let tag = Some(tag);
        if self.egress_acted.is_none() {
            self.egress_seen = tag.clone();
            self.egress_acted = tag;
            return;
        }
        let moved = self.egress_seen != tag;
        self.egress_seen = tag;
        if moved && self.settled.is_some() && self.egress_acted != self.egress_seen {
            self.forced.get_or_insert(Forced::Route);
            self.arm(now);
        }
    }

    /// The p2p host's relays all went silent ([`hint`]). Before the baseline
    /// there is nothing to compare with; a wake already counts for more. It
    /// wins over a pending route move, which is classified by the readings
    /// at the decision anyway (one moved and back must not drop it).
    fn path_loss(&mut self, now: Instant) {
        if self.settled.is_none() {
            return;
        }
        if self.forced != Some(Forced::Wake) {
            self.forced = Some(Forced::PathLoss);
        }
        self.arm(now);
    }

    /// The networks last settled on (none before the baseline).
    fn view(&self) -> Vec<IpNet> {
        self.settled.iter().flatten().copied().collect()
    }

    /// A decision was made: later readings are compared with this one.
    fn egress_acted_on(&mut self) {
        if self.egress_seen.is_some() {
            self.egress_acted = self.egress_seen.clone();
        }
    }

    /// A watcher (re)opened: its first events rebuild the view from scratch,
    /// and that view is compared with the one last acted on.
    fn resync(&mut self, now: Instant) {
        self.addrs.clear();
        // From now: a burst the failed watcher left open must not settle
        // before the new watcher's first events are in.
        self.dirty_since = Some(now);
        self.last_event = Some(now);
    }

    /// A decision is acted on now: the next one keeps the gap from it.
    fn fire(&mut self, now: Instant) {
        self.gap = match self.last_fire {
            Some(t) if now.saturating_duration_since(t) < GAP_CALM => (self.gap * 2).min(GAP_MAX),
            _ => GAP_MIN,
        };
        self.last_fire = Some(now);
        self.egress_acted_on();
    }

    /// When the current burst is decided (`None`: nothing pending).
    fn due_at(&self) -> Option<Instant> {
        let first = self.dirty_since?;
        let settle = (self.last_event? + QUIET).min(first + MAX_SETTLE);
        Some(self.last_fire.map_or(settle, |t| settle.max(t + self.gap)))
    }

    /// Decide the burst if it is due.
    fn settle(&mut self, now: Instant) -> Option<Settled> {
        if self.due_at().is_none_or(|due| due > now) {
            return None;
        }
        self.dirty_since = None;
        self.last_event = None;
        let forced = self.forced.take();
        let egress_moved = self.egress_seen.is_some() && self.egress_acted != self.egress_seen;
        let egress_kept = matches!(self.egress_seen, Some(Some(_))) && !egress_moved;
        let keys = self.keys();
        let Some(prev) = self.settled.replace(keys.clone()) else {
            self.egress_acted_on();
            return Some(Settled::Baseline {
                networks: keys.len(),
            });
        };
        if keys.is_empty() {
            // Nothing to retry on (a wake, a route move or a path loss
            // included): neither a fire nor a gap step. Still no network is
            // nothing new.
            return (!prev.is_empty()).then_some(Settled::Offline);
        }
        let cause = if forced == Some(Forced::Wake) {
            Cause::Wake
        } else if egress_moved && prev == keys {
            Cause::Route
        } else {
            Cause::Addresses
        };
        if prev == keys && cause == Cause::Addresses {
            if forced != Some(Forced::PathLoss) {
                return None;
            }
            self.fire(now);
            return Some(Settled::PathLoss);
        }
        self.fire(now);
        Some(Settled::Changed(Change {
            added: keys.difference(&prev).count(),
            removed: prev.difference(&keys).count(),
            networks: keys.len(),
            cause,
            from_offline: prev.is_empty(),
            egress_moved,
            egress_kept,
            link_local: keys.iter().all(cable_link_local),
        }))
    }
}

/// Notices this computer sleeping: between two checks the wall clock ran
/// ahead of the monotonic clock (macOS and Linux stop it while asleep), or
/// the monotonic clock itself jumped (Windows counts sleep; a stopped
/// process). Pure: the caller passes both clocks.
struct WakeClock {
    mono: Instant,
    wall: SystemTime,
}

impl WakeClock {
    fn new(mono: Instant, wall: SystemTime) -> Self {
        Self { mono, wall }
    }

    /// `Some(gap)` when the time since the last check says this computer
    /// slept.
    fn check(&mut self, mono: Instant, wall: SystemTime) -> Option<Duration> {
        let m = mono.saturating_duration_since(self.mono);
        // A wall clock stepped back is no wake.
        let w = wall.duration_since(self.wall).unwrap_or(Duration::ZERO);
        (self.mono, self.wall) = (mono, wall);
        let gap = w.saturating_sub(m).max(m.saturating_sub(WAKE_TICK));
        (gap >= WAKE_SLACK).then_some(gap)
    }
}

/// What the driver reacts to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NetEvent {
    /// An address came or went.
    If(IfEvent),
    /// This computer woke from sleep (a lab `wake` line; otherwise the
    /// [`WakeClock`] notices it).
    Wake,
    /// The default routes' fingerprint (a lab `egress` line).
    Egress(Option<String>),
}

/// What the driver reads besides the events (fakes in tests).
struct Probes {
    /// Run the [`WakeClock`] (off with the lab file: its `wake` lines stand in).
    wake_clock: bool,
    /// The wall clock.
    wall: Box<dyn Fn() -> SystemTime + Send>,
    /// The default routes' fingerprint; `None` while nothing needs it.
    egress: Box<dyn FnMut() -> Option<Option<String>> + Send>,
    /// Told each default-route reading, the lab file's included: whether
    /// there is a default route ([`note_egress`] for the service).
    seen: Box<dyn FnMut(bool) + Send>,
    /// F6: IPv4 link-local addresses count while nothing else does
    /// ([`view_keys`]); the offline-LAN gate, read once at start.
    link_local: bool,
}

impl Probes {
    /// The service's. With the lab file only the file speaks. The wall clock
    /// is Raven's ([`raven_core::clock::now`]): a lab clock jump ahead reads
    /// as a wake from sleep. F6 follows the offline-LAN gate, lab file or not.
    fn real(lab: bool) -> Self {
        Self {
            wake_clock: !lab,
            wall: Box::new(raven_core::clock::now),
            egress: Box::new(move || {
                egress_needed(
                    lab,
                    crate::p2p::host_running(),
                    raven_core::route_memory::live() || raven_core::learning::learning_live(),
                )
                .then(raven_core::route_memory::egress_tag)
            }),
            seen: Box::new(note_egress),
            link_local: raven_core::offline_lan_live(),
        }
    }

    /// Read the default routes' fingerprint, when something needs it, into
    /// `state`.
    fn read_egress(&mut self, state: &mut NetState, now: Instant) {
        if let Some(tag) = (self.egress)() {
            (self.seen)(tag.is_some());
            state.egress(tag, now);
        }
    }
}

/// The service's task read the default route: `present` is whether there is
/// one (a lab `egress <hex>` line, or a real reading with a source address;
/// `egress none`, or none). When one is back, the `no_route` reasons go
/// ([`crate::delivery_paths::route_back`]).
fn note_egress(present: bool) {
    let before = LAST_EGRESS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .replace(present);
    if present && before != Some(true) {
        crate::delivery_paths::route_back();
    }
}

/// Whether this computer had a default route at the service task's last
/// reading: `Some(false)` none (only peers on its own networks can be
/// reached), `Some(true)` one, `None` not read yet (nothing needed it, or
/// not `raven-node service`). A local fact: nothing is probed.
pub(crate) fn last_egress() -> Option<bool> {
    *LAST_EGRESS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What another task tells netwatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hint {
    /// The p2p host: every relay holding a reservation stopped answering
    /// pings, and no other connection answered one since (an open direct
    /// connection to anyone else was given one ping round to answer first).
    RelayLoss,
}

/// The hints waiting for the driver.
struct Side {
    notify: Notify,
    relay_loss: AtomicBool,
}

impl Side {
    fn new() -> Self {
        Self {
            notify: Notify::new(),
            relay_loss: AtomicBool::new(false),
        }
    }

    fn hint(&self, h: Hint) {
        match h {
            Hint::RelayLoss => self.relay_loss.store(true, Ordering::SeqCst),
        }
        self.notify.notify_one();
    }
}

fn side() -> &'static Side {
    static SIDE: OnceLock<Side> = OnceLock::new();
    SIDE.get_or_init(Side::new)
}

/// Tell the running netwatch task (the service's). A hint given while its
/// watcher is reopened waits for it; hints before the baseline are nothing.
pub(crate) fn hint(h: Hint) {
    side().hint(h);
}

/// The default routes' fingerprint is read only while something acts on it:
/// a p2p host (it re-homes), or route memory or learning connectivity
/// (`keyed`: lab or gated, keyed by it). Release builds run none of them, so
/// they never read it; the lab file stands in for it.
fn egress_needed(lab: bool, p2p_host: bool, keyed: bool) -> bool {
    !lab && (p2p_host || keyed)
}

async fn sleep_until_or_never(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Feed `events` (and the [`Probes`] and `side`'s hints) into `state` and
/// report each decision, with the networks it leaves settled, to `on` until
/// the stream fails or ends: that error is returned and the stream is never
/// polled again (if-watch repeats a failure on every poll).
async fn watch_events<S>(
    events: &mut S,
    state: &mut NetState,
    side: &Side,
    probes: &mut Probes,
    on: &mut impl FnMut(Settled, &[IpNet]),
) -> io::Error
where
    S: Stream<Item = io::Result<NetEvent>> + Unpin,
{
    // Seeded at every open: the reopen backoff before it was no sleep.
    let mut wake = WakeClock::new(Instant::now(), (probes.wall)());
    let mut tick = tokio::time::interval(WAKE_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut egress_due = Instant::now();
    loop {
        let due = state.due_at();
        tokio::select! {
            ev = events.next() => match ev {
                Some(Ok(ev)) => {
                    if let NetEvent::Egress(tag) = &ev {
                        (probes.seen)(tag.is_some());
                    }
                    // Lock v2's auto-lock on sleep (P6.40).
                    if ev == NetEvent::Wake {
                        crate::lock::woke_from_sleep();
                    }
                    state.apply(ev, Instant::now());
                }
                Some(Err(e)) => return e,
                None => return io::Error::other("the watcher ended"),
            },
            () = sleep_until_or_never(due) => {
                let now = Instant::now();
                // A change that also moved the default route is classified
                // now, not at the next poll.
                probes.read_egress(state, now);
                if let Some(s) = state.settle(now) {
                    on(s, &state.view());
                }
            }
            () = side.notify.notified() => {
                if side.relay_loss.swap(false, Ordering::SeqCst) {
                    let now = Instant::now();
                    // A moved default route explains silent relays: that
                    // change is acted on, not a path loss.
                    probes.read_egress(state, now);
                    state.path_loss(now);
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                if probes.wake_clock && wake.check(now, (probes.wall)()).is_some() {
                    state.wake(now);
                    crate::lock::woke_from_sleep();
                }
                if now >= egress_due {
                    egress_due = now + EGRESS_POLL;
                    probes.read_egress(state, now);
                }
            }
        }
    }
}

/// Open a watcher with `open`, watch it, and reopen it with backoff when it
/// fails, for ever. The state (the baseline) outlives each watcher.
async fn run_with<S, F>(
    mut open: F,
    mut probes: Probes,
    side: &Side,
    mut on: impl FnMut(Settled, &[IpNet]),
) -> Infallible
where
    S: Stream<Item = io::Result<NetEvent>> + Unpin,
    F: FnMut() -> io::Result<S>,
{
    let mut state = NetState::new(probes.link_local);
    let mut reopen = REOPEN_MIN;
    loop {
        let opened = Instant::now();
        let err = match open() {
            Ok(mut events) => {
                state.resync(Instant::now());
                watch_events(&mut events, &mut state, side, &mut probes, &mut on).await
            }
            Err(e) => e,
        };
        if opened.elapsed() >= netutil::RESTART_STABLE {
            reopen = REOPEN_MIN;
        }
        netutil::log_limited(
            &NETWATCH_LOG,
            "raven-node netwatch: unavailable",
            format_args!(
                "{err}; queued messages keep their own retry timers; trying again in {}s",
                reopen.as_secs()
            ),
        );
        tokio::time::sleep(reopen).await;
        reopen = (reopen * 2).min(REOPEN_MAX);
    }
}

type Events = Pin<Box<dyn Stream<Item = io::Result<NetEvent>> + Send>>;

/// The OS watcher, or the debug lab file.
fn open_source() -> io::Result<Events> {
    if let Some(path) = lab_events_path() {
        eprintln!("raven-node netwatch: lab events (debug build)");
        return Ok(Box::pin(lab_events(path)));
    }
    // Inside the runtime: the Linux backend registers its socket with it.
    let watcher = if_watch::tokio::IfWatcher::new()?;
    Ok(Box::pin(watcher.map(|ev| ev.map(NetEvent::If))))
}

fn noun(networks: usize) -> &'static str {
    if networks == 1 {
        "network"
    } else {
        "networks"
    }
}

/// What the p2p host does about a change.
#[derive(Debug, PartialEq, Eq)]
enum P2pAction {
    /// Start the endpoint over ([`crate::p2p::network_changed`]).
    Rehome(crate::p2p::Rehome),
    /// Networks were only added: idle relay slots retry at once
    /// ([`crate::p2p::nudge`]).
    Nudge,
}

/// What the p2p host does about a change (pure).
fn p2p_action(c: &Change) -> P2pAction {
    use crate::p2p::Rehome;
    if !c.paths_stale() {
        return P2pAction::Nudge;
    }
    P2pAction::Rehome(match c.cause {
        Cause::Addresses => Rehome::Network,
        Cause::Wake => Rehome::Wake,
        Cause::Route => Rehome::Route,
    })
}

/// The only side effects: the p2p, friend relay, outbox, custody, delivery
/// paths, route hints and LAN beacon hooks, the view [`on_link`] reads and
/// one log line.
fn act(s: Settled, view: &[IpNet]) {
    match s {
        Settled::Baseline { networks } => {
            set_view(view);
            // Route hints compare a wildcard listener's networks with the
            // ones it last told (a restart on another network, cutoff F8):
            // look now that they are known, not a TICK later.
            crate::hints::own_changed();
            eprintln!("{}", baseline_line(networks));
        }
        Settled::Offline => {
            set_view(view);
            // Auto-reach: what STUN discovery found belonged to the network
            // that went away.
            crate::autoreach::network_changed();
            // The LAN beacon drops what it found on interfaces now gone.
            crate::lan_beacon::network_changed();
            // Learning connectivity keys what it learns by the network.
            crate::learning::network_changed();
            eprintln!("raven-node netwatch: no network; waiting for one")
        }
        Settled::Changed(c) => {
            // Before the outbox's retry round, so it plans on the new view.
            set_view(view);
            // Auto-reach: what STUN discovery found belonged to the old
            // network; the re-homed endpoint's anchor asks again.
            if c.paths_stale() {
                crate::autoreach::network_changed();
            }
            // The p2p endpoint first, so the outbox's retry round already
            // finds its dials queued for the fresh one.
            let rehoming = match p2p_action(&c) {
                P2pAction::Rehome(why) => crate::p2p::network_changed(why),
                P2pAction::Nudge => {
                    crate::p2p::nudge();
                    false
                }
            };
            // A running friend relay starts over on the new paths (a fresh
            // UPnP gateway search, fresh listeners, addresses from the new
            // external IP); networks only added leave it alone.
            if c.paths_stale() {
                crate::friend_relay::network_changed();
            }
            let waiting = crate::outbox::network_changed();
            crate::custody::network_changed();
            // Session renewal (Phase 3): the per-contact rechecks and lapse
            // marks were made on the old network.
            crate::renewal::network_changed();
            // Why a contact could not be reached was learned on the old
            // network.
            crate::delivery_paths::network_changed();
            // What route hints tell may have moved with the network (the
            // announcer looks after it settles).
            crate::hints::own_changed();
            // The LAN beacon (Phase 3): the interfaces read again, what it
            // found on gone ones dropped, every query interval started over,
            // and one join round.
            crate::lan_beacon::network_changed();
            // Learning connectivity (Phase 6a, gated): what it learns from
            // now on is this network's.
            crate::learning::network_changed();
            // The Tor helper (lab, gated): Arti handles neither a network
            // change nor a wake (#2705, #594), so it starts over on stale
            // paths; networks only added leave it alone.
            if c.paths_stale() {
                crate::onion::network_changed(c.cause == Cause::Wake);
            }
            eprintln!("{}", change_line(&c, waiting, rehoming));
        }
        Settled::PathLoss => {
            // No network change (the view stays): the outbox keeps its
            // backoff (the re-homed host kicks it). Nothing to do without a
            // host.
            if crate::p2p::network_changed(crate::p2p::Rehome::PathLoss) {
                crate::custody::network_changed();
                eprintln!("raven-node netwatch: every relay stopped answering; p2p re-homing");
            }
        }
    }
}

/// The log line of the first view (`node/scripts/netns_offline.sh` waits for
/// it with no network at all).
fn baseline_line(networks: usize) -> String {
    format!(
        "raven-node netwatch: watching ({networks} {})",
        noun(networks)
    )
}

/// The log line of an acted-on change (counts only, never an address):
/// `waiting` is what the outbox put on a fresh backoff (`None`: no outbox).
/// Only a change to IPv4 link-local networks alone (F6) says `link-local
/// network only (a cable?)`; every other line is as before it.
fn change_line(c: &Change, waiting: Option<usize>, rehoming: bool) -> String {
    let what = match c.cause {
        Cause::Addresses if c.link_local => "link-local network only (a cable?)",
        Cause::Addresses => "network changed",
        Cause::Wake => "woke from sleep",
        Cause::Route => "default route moved",
    };
    let head = format!(
        "raven-node netwatch: {what} ({} new, {} gone, {} now)",
        c.added, c.removed, c.networks
    );
    let p2p = if rehoming { ", p2p re-homing" } else { "" };
    match waiting {
        Some(n) => format!("{head}: retrying {n} waiting now, backoff restarted{p2p}"),
        None => format!("{head}: outbox not running{p2p}"),
    }
}

/// What [`on_link`] reads from now on.
fn set_view(view: &[IpNet]) {
    *VIEW.lock().unwrap_or_else(PoisonError::into_inner) = Some(view.to_vec());
}

/// A digest of the networks the service's task last settled on, for route
/// hints ([`crate::hints`]: friends reach a wildcard listener at whatever
/// address this computer has, so a move to another network is something to
/// tell them, cutoff F8). `None` before the first baseline and while there is
/// no network at all. A digest keyed with this computer's identity (`key`),
/// never the addresses: the route hints state that keeps it is a file, and a
/// plain digest of one IPv4 network is brute-forced from it (review FU-2).
pub(crate) fn view_digest(key: &raven_core::route_hints::NetworksKey) -> Option<String> {
    let view = VIEW.lock().unwrap_or_else(PoisonError::into_inner);
    view_digest_of(view.as_deref()?, key)
}

/// [`view_digest`] of `view` (pure): the same networks in any order give the
/// same digest.
pub(crate) fn view_digest_of(
    view: &[IpNet],
    key: &raven_core::route_hints::NetworksKey,
) -> Option<String> {
    let nets: BTreeSet<String> = view.iter().map(ToString::to_string).collect();
    if nets.is_empty() {
        return None;
    }
    let parts: Vec<&[u8]> = nets.iter().map(String::as_bytes).collect();
    Some(raven_core::route_hints::keyed_inputs_digest(key, &parts))
}

/// Is `ip` on one of the networks the service's task last settled on? `None`
/// when that is not known: no baseline yet (or no task: not `raven-node
/// service`), for an address [`key`] never counts (loopback, link-local: a
/// learned 169.254/16 address may be on a link it does not track, and F6
/// counts one only while nothing else does), and for one on none of them
/// while a point-to-point network of its family is up (a VPN's /32 or /31,
/// an IPv6 /127 or /128: it may route there). The outbox's lab filter for
/// learned LAN routes.
pub(crate) fn on_link(ip: IpAddr) -> Option<bool> {
    let view = VIEW.lock().unwrap_or_else(PoisonError::into_inner);
    on_link_in(view.as_deref()?, ip)
}

/// [`on_link`] against `view` (pure).
fn on_link_in(view: &[IpNet], ip: IpAddr) -> Option<bool> {
    let ip = ip.to_canonical();
    // An address `key` never counts is not known, also while F6 counts a
    // link-local network (such an address is dialled, never skipped).
    key(&IpNet::from(ip))?;
    if view.iter().any(|net| net.contains(&ip)) {
        return Some(true);
    }
    // A point-to-point link (a tunnel) has no subnet of its own: what it
    // routes is on none of our prefixes.
    let point_to_point = view.iter().any(|net| match (net, ip) {
        (IpNet::V4(n), IpAddr::V4(_)) => n.prefix_len() >= 31,
        (IpNet::V6(n), IpAddr::V6(_)) => n.prefix_len() >= 127,
        _ => false,
    });
    (!point_to_point).then_some(false)
}

/// The supervised task (`raven-node service`); it runs for the life of the
/// process.
pub(crate) async fn run() -> Result<(), String> {
    let lab = lab_events_path().is_some();
    match run_with(open_source, Probes::real(lab), side(), act).await {}
}

/// `RAVEN_LAB_NETWATCH_EVENTS`, debug builds only (independent of
/// `RAVEN_LAB_TEST_A`); release builds never read it.
fn lab_events_path() -> Option<PathBuf> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var_os("RAVEN_LAB_NETWATCH_EVENTS")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// One lab line: `up <ip>/<prefix>`, `down <ip>/<prefix>`, `wake`,
/// `egress <1-64 lowercase hex digits>` or `egress none`; anything else is
/// ignored.
fn parse_lab_line(line: &str) -> Option<NetEvent> {
    let mut words = line.split_whitespace();
    let (kind, arg) = (words.next()?, words.next());
    if words.next().is_some() {
        return None;
    }
    let net = |text: &str| text.parse::<IpNet>().ok();
    match (kind, arg) {
        ("up", Some(text)) => Some(NetEvent::If(IfEvent::Up(net(text)?))),
        ("down", Some(text)) => Some(NetEvent::If(IfEvent::Down(net(text)?))),
        ("wake", None) => Some(NetEvent::Wake),
        ("egress", Some("none")) => Some(NetEvent::Egress(None)),
        ("egress", Some(tag)) => {
            let hex = tag.len() <= LAB_EGRESS_MAX
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            hex.then(|| NetEvent::Egress(Some(tag.to_string())))
        }
        _ => None,
    }
}

/// The lab file as an event stream: read every [`LAB_POLL`] (a missing file
/// is empty), whole lines only (one still being written is read next time).
/// It never ends.
fn lab_events(path: PathBuf) -> impl Stream<Item = io::Result<NetEvent>> + Send {
    futures::stream::unfold(
        (path, 0usize, VecDeque::new()),
        |(path, mut offset, mut queue)| async move {
            loop {
                if let Some(ev) = queue.pop_front() {
                    return Some((Ok(ev), (path, offset, queue)));
                }
                tokio::time::sleep(LAB_POLL).await;
                let text = tokio::fs::read_to_string(&path).await.unwrap_or_default();
                // A file replaced by a shorter one is read from the start.
                let fresh = text.get(offset..).unwrap_or_else(|| {
                    offset = 0;
                    &text
                });
                let Some(end) = fresh.rfind('\n') else {
                    continue;
                };
                queue.extend(fresh[..end].lines().filter_map(parse_lab_line));
                offset += end + 1;
            }
        },
    )
}

/// Tests that read or set [`LAST_EGRESS`], or note `no_route` reasons, hold
/// this (the static is the process's).
#[cfg(test)]
pub(crate) async fn egress_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

/// Set [`last_egress`] as a reading would leave it (no reasons cleared).
#[cfg(test)]
pub(crate) fn set_last_egress(v: Option<bool>) {
    *LAST_EGRESS.lock().unwrap_or_else(PoisonError::into_inner) = v;
}

/// The service's driver on the lab file `path` (its readings reach
/// [`last_egress`]), without its actions.
#[cfg(test)]
pub(crate) fn lab_reader(path: PathBuf) -> tokio::task::JoinHandle<()> {
    let side: &'static Side = Box::leak(Box::new(Side::new()));
    tokio::spawn(async move {
        let open = move || -> io::Result<Events> { Ok(Box::pin(lab_events(path.clone()))) };
        match run_with(open, Probes::real(true), side, |_, _| {}).await {}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn up(s: &str) -> IfEvent {
        IfEvent::Up(net(s))
    }

    fn down(s: &str) -> IfEvent {
        IfEvent::Down(net(s))
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    const MS: Duration = Duration::from_millis(1);

    /// A change of the networks alone (no wake, no route move, not back
    /// from offline).
    fn addresses_change(added: usize, removed: usize, networks: usize) -> Change {
        Change {
            added,
            removed,
            networks,
            cause: Cause::Addresses,
            from_offline: false,
            egress_moved: false,
            egress_kept: false,
            link_local: false,
        }
    }

    fn addresses(added: usize, removed: usize, networks: usize) -> Settled {
        Settled::Changed(addresses_change(added, removed, networks))
    }

    /// Neither a wake clock nor a default-route reading.
    fn quiet() -> Probes {
        Probes {
            wake_clock: false,
            wall: Box::new(SystemTime::now),
            egress: Box::new(|| None),
            seen: Box::new(|_| {}),
            link_local: false,
        }
    }

    fn tag(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    /// A state whose baseline (`views`, opened at `t0`) is settled.
    fn baseline(t0: Instant, views: &[&str]) -> NetState {
        baseline_with(t0, views, false)
    }

    /// [`baseline`] with F6 (the offline-LAN gate) open or closed.
    fn baseline_with(t0: Instant, views: &[&str], live: bool) -> NetState {
        let mut st = NetState::new(live);
        st.resync(t0);
        for v in views {
            st.event(up(v), t0);
        }
        let due = st.due_at().unwrap();
        assert!(matches!(st.settle(due), Some(Settled::Baseline { .. })));
        st
    }

    /// Settle at the due time (just before it: nothing yet).
    fn settle_when_due(st: &mut NetState) -> (Instant, Option<Settled>) {
        let due = st.due_at().expect("a decision is pending");
        assert_eq!(st.settle(due - MS), None, "not before it is due");
        (due, st.settle(due))
    }

    #[test]
    fn first_view_after_start_is_a_baseline_not_a_change() {
        let t0 = Instant::now();
        let mut st = NetState::new(false);
        st.resync(t0);
        for v in ["192.168.0.16/24", "fe80::1/64", "127.0.0.1/8"] {
            st.event(up(v), t0);
        }
        assert_eq!(st.due_at(), Some(t0 + QUIET));
        assert_eq!(st.settle(t0 + QUIET - MS), None);
        assert_eq!(
            st.settle(t0 + QUIET),
            Some(Settled::Baseline { networks: 1 })
        );
        assert_eq!(st.due_at(), None, "nothing pending afterwards");

        // A watcher with no address at all still settles a baseline.
        let mut empty = NetState::new(false);
        empty.resync(t0);
        assert_eq!(
            empty.settle(t0 + QUIET),
            Some(Settled::Baseline { networks: 0 })
        );
    }

    /// E-custody-harness-docs-2 (netns cable-linklocal): a node started
    /// with no address at all says `watching (0 networks)` (a baseline,
    /// never "no network; waiting for one", which needs networks that went);
    /// its first 169.254 address is then the cable line with F6 open, and
    /// nothing with it closed.
    #[test]
    fn a_watcher_started_with_no_address_then_given_a_cable() {
        let t0 = Instant::now();
        for live in [true, false] {
            let mut st = NetState::new(live);
            st.resync(t0);
            let first = st.settle(t0 + QUIET);
            assert_eq!(first, Some(Settled::Baseline { networks: 0 }), "{live}");
            assert_eq!(
                baseline_line(0),
                "raven-node netwatch: watching (0 networks)"
            );
            let t = t0 + secs(30);
            st.event(up("169.254.10.1/16"), t);
            if !live {
                assert_eq!(st.due_at(), None, "gate closed: never armed");
                continue;
            }
            let (_, s) = settle_when_due(&mut st);
            let Some(Settled::Changed(c)) = s else {
                panic!("{s:?}");
            };
            assert!(c.link_local, "{c:?}");
            assert!(change_line(&c, Some(0), false)
                .starts_with("raven-node netwatch: link-local network only (a cable?) (1 new"));
        }
    }

    #[test]
    fn loopback_link_local_and_multicast_churn_never_arms_the_timer() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        let t1 = t0 + secs(60);
        for v in [
            "fe80::1/64",
            "fe80::aede:48ff:fe00:1122/64",
            "febf::1/64",
            "169.254.1.2/16",
            "::1/128",
            "127.0.0.2/8",
            "224.0.0.1/32",
            "ff02::1/16",
            "0.0.0.0/0",
            "255.255.255.255/32",
        ] {
            st.event(up(v), t1);
            st.event(down(v), t1);
            st.event(up(v), t1);
        }
        assert_eq!(st.due_at(), None);
        assert_eq!(st.settle(t1 + secs(60)), None);
    }

    #[test]
    fn ipv6_privacy_rotation_inside_one_prefix_is_not_a_change() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["2001:db8:1::a/64"]);
        let t1 = t0 + secs(60);
        st.event(up("2001:db8:1::b/64"), t1);
        st.event(down("2001:db8:1::a/64"), t1);
        assert_eq!(settle_when_due(&mut st).1, None, "same prefix");
        let t2 = t1 + secs(60);
        st.event(up("2001:db8:2::b/64"), t2);
        st.event(down("2001:db8:1::b/64"), t2);
        assert_eq!(settle_when_due(&mut st).1, Some(addresses(1, 1, 1)));
    }

    #[test]
    fn wifi_to_hotspot_is_one_change_after_the_burst_quiets() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        let t = t0 + secs(60);
        st.event(down("192.168.0.16/24"), t);
        st.event(up("172.20.10.2/28"), t + secs(1));
        assert_eq!(st.settle(t + QUIET), None, "the burst went on");
        assert_eq!(st.settle(t + secs(1) + QUIET - MS), None);
        assert_eq!(st.settle(t + secs(1) + QUIET), Some(addresses(1, 1, 1)));
        assert_eq!(st.due_at(), None, "exactly one");
    }

    #[test]
    fn a_burst_that_never_quiets_settles_at_max_settle() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        let t1 = t0 + secs(60);
        let mut first = None;
        for i in 0..30u64 {
            let at = t1 + secs(i);
            if let Some(due) = st.due_at().filter(|d| *d <= at) {
                let s = st.settle(due);
                assert!(matches!(s, Some(Settled::Changed(_))), "{s:?}");
                first.get_or_insert(due);
            }
            st.event(up(&format!("10.0.{i}.1/24")), at);
        }
        assert_eq!(first, Some(t1 + MAX_SETTLE));
    }

    #[test]
    fn down_and_up_of_the_same_address_within_quiet_is_nothing() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        let t = t0 + secs(60);
        st.event(down("192.168.0.16/24"), t);
        st.event(up("192.168.0.16/24"), t + secs(1));
        assert_eq!(settle_when_due(&mut st).1, None);
        assert_eq!((st.last_fire, st.gap), (None, GAP_MIN));
    }

    #[test]
    fn losing_every_network_is_remembered_and_coming_back_is_a_change() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24", "fe80::1/64"]);
        let t = t0 + secs(60);
        st.event(down("192.168.0.16/24"), t);
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Offline));
        assert_eq!((st.last_fire, st.gap), (None, GAP_MIN), "not a fire");
        // A wake while offline is nothing to retry on either.
        st.wake(t + secs(10));
        assert_eq!(settle_when_due(&mut st).1, None);
        st.event(up("192.168.0.16/24"), t + secs(30));
        let back = Change {
            from_offline: true,
            ..addresses_change(1, 0, 1)
        };
        assert!(back.paths_stale(), "every path is new");
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Changed(back)));
    }

    #[test]
    fn flapping_widens_the_gap_up_to_the_cap_and_calm_resets_it() {
        let t0 = Instant::now();
        let views = ["192.168.0.16/24", "172.20.10.2/28"];
        let mut st = baseline(t0, &views[..1]);
        let mut on = 0;
        let mut flip = |st: &mut NetState, at: Instant| {
            st.event(down(views[on]), at);
            on ^= 1;
            st.event(up(views[on]), at);
        };
        let changed = Some(addresses(1, 1, 1));
        // The first change is held by nothing.
        let t = t0 + secs(60);
        flip(&mut st, t);
        let (mut fired, s) = settle_when_due(&mut st);
        assert_eq!((fired, s), (t + QUIET, changed.clone()));
        for gap in [10, 20, 40, 80, 160, 300, 300] {
            flip(&mut st, fired + secs(1));
            let (at, s) = settle_when_due(&mut st);
            assert_eq!((at - fired, s), (secs(gap), changed.clone()));
            fired = at;
        }
        // Calm: the next change is held by nothing, the one after by GAP_MIN.
        let t = fired + GAP_CALM + secs(1);
        flip(&mut st, t);
        let (at, s) = settle_when_due(&mut st);
        assert_eq!((at, s), (t + QUIET, changed.clone()));
        flip(&mut st, at + secs(1));
        let (next, s) = settle_when_due(&mut st);
        assert_eq!((next - at, s), (GAP_MIN, changed));
    }

    #[test]
    fn reopening_a_watcher_detects_what_changed_while_it_was_down() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        let t = t0 + secs(60);
        st.resync(t);
        st.event(up("172.20.10.2/28"), t);
        assert_eq!(settle_when_due(&mut st).1, Some(addresses(1, 1, 1)));
        let t = t + secs(60);
        st.resync(t);
        st.event(up("172.20.10.2/28"), t);
        assert_eq!(settle_when_due(&mut st).1, None, "the same view");
    }

    #[test]
    fn address_cap_holds() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &[]);
        for i in 0..(MAX_ADDRS as u32 + 100) {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i);
            st.event(IfEvent::Up(IpNet::new(ip.into(), 32).unwrap()), t0);
        }
        assert_eq!(st.addrs.len(), MAX_ADDRS);
    }

    fn woke(added: usize, removed: usize, networks: usize) -> Settled {
        Settled::Changed(Change {
            cause: Cause::Wake,
            ..addresses_change(added, removed, networks)
        })
    }

    #[test]
    fn a_wake_is_one_change_even_when_no_address_moved() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        let t = t0 + secs(60);
        st.wake(t);
        let (at, s) = settle_when_due(&mut st);
        assert_eq!((at, s.clone()), (t + QUIET, Some(woke(0, 0, 1))));
        let Some(Settled::Changed(c)) = s else {
            unreachable!()
        };
        assert!(c.paths_stale());
        assert_eq!(st.due_at(), None, "exactly one");
    }

    #[test]
    fn a_wake_and_the_address_burst_after_it_are_one_change() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        let t = t0 + secs(60);
        st.wake(t);
        st.event(down("192.168.0.16/24"), t + secs(1));
        st.event(up("172.20.10.2/28"), t + secs(3));
        assert_eq!(st.settle(t + QUIET), None, "the burst went on");
        let (at, s) = settle_when_due(&mut st);
        assert_eq!((at, s), (t + secs(3) + QUIET, Some(woke(1, 1, 1))));
        assert_eq!(st.due_at(), None, "exactly one");
    }

    #[test]
    fn a_wake_is_not_held_by_the_flap_gap() {
        let t0 = Instant::now();
        let views = ["192.168.0.16/24", "172.20.10.2/28"];
        let mut st = baseline(t0, &views[..1]);
        let mut fired = t0 + secs(60);
        for i in 0..3 {
            st.event(down(views[i % 2]), fired + secs(1));
            st.event(up(views[(i + 1) % 2]), fired + secs(1));
            let (at, s) = settle_when_due(&mut st);
            assert_eq!(s, Some(addresses(1, 1, 1)));
            fired = at;
        }
        assert_eq!(st.gap, secs(40), "the flap gap escalated");
        let t = fired + secs(1);
        st.wake(t);
        assert_eq!(settle_when_due(&mut st), (t + QUIET, Some(woke(0, 0, 1))));
        // A change right after it keeps only the minimum gap from the wake.
        st.event(up("10.8.0.2/24"), t + QUIET + secs(1));
        let (at, s) = settle_when_due(&mut st);
        assert_eq!((at - (t + QUIET), s), (GAP_MIN, Some(addresses(1, 0, 2))));
    }

    #[test]
    fn an_egress_move_alone_is_a_route_change_once() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        st.egress(tag("aa"), t0 + secs(10));
        assert_eq!(st.due_at(), None, "the first reading only seeds");
        st.egress(tag("aa"), t0 + secs(40));
        assert_eq!(st.due_at(), None, "the same fingerprint is nothing");
        let t = t0 + secs(70);
        st.egress(tag("bb"), t);
        let route = Change {
            cause: Cause::Route,
            egress_moved: true,
            ..addresses_change(0, 0, 1)
        };
        assert!(route.paths_stale());
        assert_eq!(
            settle_when_due(&mut st),
            (t + QUIET, Some(Settled::Changed(route)))
        );
        st.egress(tag("bb"), t + secs(30));
        assert_eq!(st.due_at(), None, "acted on once");
        // Away and back before the decision: nothing.
        st.egress(tag("cc"), t + secs(60));
        st.egress(tag("bb"), t + secs(61));
        assert_eq!(settle_when_due(&mut st).1, None);
        // A move inside an address change: one change, by the addresses.
        st.event(up("10.8.0.2/24"), t + secs(120));
        st.egress(None, t + secs(121));
        let both = Change {
            egress_moved: true,
            ..addresses_change(1, 0, 2)
        };
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Changed(both)));
        st.egress(None, t + secs(150));
        assert_eq!(st.due_at(), None, "no route reading counts too");
    }

    /// Phase 0b: a p2p host that starts after the baseline reads the
    /// fingerprint for the first time; that seeds it, it is no change.
    #[test]
    fn the_first_egress_look_after_the_baseline_only_seeds() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        assert_eq!((&st.egress_seen, &st.egress_acted), (&None, &None));
        st.egress(tag("aa"), t0 + secs(30));
        assert_eq!(st.due_at(), None);
        assert_eq!(st.settle(t0 + secs(60)), None);
        // From then on a move is a change.
        st.egress(tag("bb"), t0 + secs(60));
        let (_, s) = settle_when_due(&mut st);
        assert!(
            matches!(&s, Some(Settled::Changed(c)) if c.cause == Cause::Route),
            "{s:?}"
        );
    }

    /// Phase 0b: every relay going silent while the networks and the
    /// default route stay the same is a path loss: debounced, held by the
    /// gap and widening it like a change. Before the baseline it is
    /// nothing; a wake counts for more.
    #[test]
    fn a_relay_loss_with_the_same_route_is_a_path_loss_held_by_the_gap() {
        let t0 = Instant::now();
        let mut early = NetState::new(false);
        early.resync(t0);
        early.event(up("192.168.0.16/24"), t0);
        early.path_loss(t0 + secs(1));
        assert_eq!(
            settle_when_due(&mut early),
            (t0 + QUIET, Some(Settled::Baseline { networks: 1 }))
        );
        assert_eq!(early.due_at(), None, "nothing left behind");

        let mut st = baseline(t0, &["192.168.0.16/24"]);
        st.egress(tag("aa"), t0 + secs(5));
        let t = t0 + secs(60);
        // The driver reads the fingerprint first: unchanged.
        st.egress(tag("aa"), t);
        st.path_loss(t);
        let (fired, s) = settle_when_due(&mut st);
        assert_eq!((fired, s), (t + QUIET, Some(Settled::PathLoss)));
        assert_eq!(st.due_at(), None, "exactly one");
        // The next one keeps the gap from it, and the gap widens.
        st.path_loss(fired + secs(1));
        let (at, s) = settle_when_due(&mut st);
        assert_eq!((at - fired, s), (GAP_MIN, Some(Settled::PathLoss)));
        st.path_loss(at + secs(1));
        let (next, s) = settle_when_due(&mut st);
        assert_eq!((next - at, s), (GAP_MIN * 2, Some(Settled::PathLoss)));
        // A wake counts for more: one change, by the wake.
        st.wake(next + secs(30));
        st.path_loss(next + secs(31));
        let wake = Change {
            cause: Cause::Wake,
            egress_kept: true,
            ..addresses_change(0, 0, 1)
        };
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Changed(wake)));
        // No network: nothing to re-home onto.
        let t = next + secs(120);
        st.event(down("192.168.0.16/24"), t);
        st.path_loss(t);
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Offline));
    }

    /// Phase 0b: silent relays after the default route moved are that move
    /// (one `default route moved` change), not a path loss. A route moved
    /// and back inside one burst does not drop the path loss.
    #[test]
    fn a_relay_loss_after_the_route_moved_is_a_route_change() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        st.egress(tag("aa"), t0 + secs(5));
        let t = t0 + secs(60);
        st.egress(tag("bb"), t);
        st.path_loss(t);
        let route = Change {
            cause: Cause::Route,
            egress_moved: true,
            ..addresses_change(0, 0, 1)
        };
        assert_eq!(
            settle_when_due(&mut st),
            (t + QUIET, Some(Settled::Changed(route)))
        );
        assert_eq!(st.due_at(), None, "exactly one");
        let t = t + secs(60);
        st.egress(tag("cc"), t);
        st.path_loss(t + secs(1));
        st.egress(tag("bb"), t + secs(2));
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::PathLoss));
    }

    #[test]
    fn added_networks_alone_keep_the_paths() {
        let base = addresses_change(1, 0, 2);
        assert!(!base.paths_stale(), "only added");
        for (stale, why) in [
            (
                Change {
                    removed: 1,
                    ..base.clone()
                },
                "a network gone",
            ),
            (
                Change {
                    from_offline: true,
                    ..base.clone()
                },
                "back from offline",
            ),
            (
                Change {
                    egress_moved: true,
                    ..base.clone()
                },
                "the default route moved",
            ),
            (
                Change {
                    cause: Cause::Wake,
                    ..base.clone()
                },
                "woke",
            ),
            (
                Change {
                    cause: Cause::Route,
                    ..base.clone()
                },
                "route",
            ),
        ] {
            assert!(stale.paths_stale(), "{why}");
        }
        let gone_beside_the_route = Change {
            removed: 1,
            egress_kept: true,
            ..base.clone()
        };
        assert!(!gone_beside_the_route.paths_stale());
        // A container bridge next to the Wi-Fi: networks only added.
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24"]);
        st.egress(tag("aa"), t0 + secs(5));
        st.event(up("172.17.0.1/16"), t0 + secs(60));
        st.egress(tag("aa"), t0 + secs(61));
        let (_, s) = settle_when_due(&mut st);
        let bridge = Change {
            egress_kept: true,
            ..addresses_change(1, 0, 2)
        };
        assert_eq!(s, Some(Settled::Changed(bridge)));
    }

    #[test]
    fn p2p_action_maps_changes_to_rehome_or_nudge() {
        use crate::p2p::Rehome;
        let with = |cause, removed, from_offline, egress_moved| Change {
            cause,
            removed,
            from_offline,
            egress_moved,
            ..addresses_change(1, 0, 2)
        };
        for (change, want) in [
            (
                with(Cause::Addresses, 1, false, false),
                P2pAction::Rehome(Rehome::Network),
            ),
            (
                with(Cause::Addresses, 0, true, false),
                P2pAction::Rehome(Rehome::Network),
            ),
            (
                with(Cause::Addresses, 0, false, true),
                P2pAction::Rehome(Rehome::Network),
            ),
            (
                with(Cause::Wake, 0, false, false),
                P2pAction::Rehome(Rehome::Wake),
            ),
            (
                with(Cause::Route, 0, false, true),
                P2pAction::Rehome(Rehome::Route),
            ),
            (with(Cause::Addresses, 0, false, false), P2pAction::Nudge),
            // A network gone beside a default route read and kept.
            (
                Change {
                    egress_kept: true,
                    ..with(Cause::Addresses, 1, false, false)
                },
                P2pAction::Nudge,
            ),
            (
                Change {
                    egress_kept: true,
                    ..with(Cause::Wake, 1, false, false)
                },
                P2pAction::Rehome(Rehome::Wake),
            ),
        ] {
            assert_eq!(p2p_action(&change), want, "{change:?}");
        }
    }

    /// A network gone with the default route read and still in place (a
    /// container or VM bridge stopped, a second NIC) leaves the p2p host's
    /// paths alone, as one added does; the default route moving with it, or
    /// never read, still re-homes.
    #[test]
    fn a_network_gone_beside_a_steady_default_route_only_nudges() {
        use crate::p2p::Rehome;
        let decide = |egress_after: Option<&str>, read: bool| {
            let t0 = Instant::now();
            let mut st = baseline(t0, &["192.168.0.16/24", "172.18.0.1/16"]);
            if read {
                st.egress(tag("aa"), t0 + secs(5));
            }
            let t = t0 + secs(60);
            st.event(down("172.18.0.1/16"), t);
            if read {
                st.egress(egress_after.map(str::to_string), t + secs(1));
            }
            match settle_when_due(&mut st).1 {
                Some(Settled::Changed(c)) => {
                    assert_eq!((c.added, c.removed, c.networks), (0, 1, 1), "{c:?}");
                    p2p_action(&c)
                }
                s => panic!("{s:?}"),
            }
        };
        assert_eq!(decide(Some("aa"), true), P2pAction::Nudge, "the bridge");
        assert_eq!(
            decide(Some("bb"), true),
            P2pAction::Rehome(Rehome::Network),
            "the default route moved with it"
        );
        assert_eq!(
            decide(None, true),
            P2pAction::Rehome(Rehome::Network),
            "no default route left"
        );
        assert_eq!(
            decide(None, false),
            P2pAction::Rehome(Rehome::Network),
            "never read (no p2p host)"
        );
    }

    /// Lab: a point-to-point network (a VPN's /32 or /31, an IPv6 /127 or
    /// /128) routes further addresses of its family that are on no network
    /// here, so whether one is on link is not known; without one it is not.
    #[test]
    fn a_point_to_point_network_makes_other_addresses_unknown() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let view = [net("10.99.0.5/32"), net("192.168.1.14/24")];
        for (addr, want) in [
            ("10.20.30.40", None),
            ("192.168.1.20", Some(true)),
            ("10.99.0.5", Some(true)),
            ("fd00::4", Some(false)),
        ] {
            assert_eq!(on_link_in(&view, ip(addr)), want, "{addr}");
        }
        assert_eq!(
            on_link_in(&[net("10.99.0.4/31")], ip("10.20.30.40")),
            None,
            "/31"
        );
        let v6 = [net("2001:db8:1::/64"), net("fd00:99::5/128")];
        assert_eq!(on_link_in(&v6, ip("fd00:20::4")), None);
        assert_eq!(on_link_in(&v6, ip("10.20.30.40")), Some(false));
        assert_eq!(
            on_link_in(&[net("192.168.1.14/24")], ip("10.20.30.40")),
            Some(false),
            "no point-to-point network"
        );
    }

    /// E-custody-harness-docs-1: route hints see a move to another network
    /// (another address, another prefix) as another digest, never the same
    /// networks in another order, and nothing while there is no network.
    #[test]
    fn the_view_digest_moves_with_the_networks_only() {
        let t0 = Instant::now();
        let home = baseline(t0, &["192.168.1.30/24", "2001:db8:1::a/64"]).view();
        let mut reversed = home.clone();
        reversed.reverse();
        let key = raven_core::route_hints::NetworksKey::derive(
            &raven_core::identity::Identity::from_seed(&[0x11; 32]),
        );
        let digest = view_digest_of(&home, &key).unwrap();
        assert_eq!(
            view_digest_of(&reversed, &key).as_deref(),
            Some(digest.as_str())
        );
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains("192.168"), "a digest, not the addresses");
        // A temporary IPv6 address in the same prefix is the same networks.
        let privacy = baseline(t0, &["192.168.1.30/24", "2001:db8:1::beef/64"]).view();
        assert_eq!(view_digest_of(&privacy, &key), Some(digest.clone()));
        for moved in [
            &["10.42.0.5/24", "2001:db8:1::a/64"][..],
            &["192.168.1.31/24", "2001:db8:1::a/64"],
            &["192.168.1.30/24", "2001:db8:2::a/64"],
            &["192.168.1.30/24"],
        ] {
            let view = baseline(t0, moved).view();
            assert_ne!(
                view_digest_of(&view, &key),
                Some(digest.clone()),
                "{moved:?}"
            );
        }
        assert_eq!(view_digest_of(&[], &key), None, "no network");
        // Another identity, the same networks: another digest (review FU-2).
        let other = raven_core::route_hints::NetworksKey::derive(
            &raven_core::identity::Identity::from_seed(&[0x12; 32]),
        );
        assert_ne!(view_digest_of(&home, &other), Some(digest));
    }

    /// Phase 0b (lab): an address is on link only inside a network last
    /// settled on; loopback and link-local addresses (netwatch never counts
    /// them) are not known.
    #[test]
    fn on_link_is_known_only_for_addresses_netwatch_counts() {
        let t0 = Instant::now();
        let st = baseline(
            t0,
            &[
                "192.168.0.16/24",
                "2001:db8:1::a/64",
                "fe80::1/64",
                "127.0.0.1/8",
            ],
        );
        let view = st.view();
        assert_eq!(view, [net("192.168.0.16/24"), net("2001:db8:1::/64")]);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for (addr, want) in [
            ("192.168.0.20", Some(true)),
            ("::ffff:192.168.0.20", Some(true)),
            ("2001:db8:1::99", Some(true)),
            ("192.168.1.20", Some(false)),
            ("10.0.0.5", Some(false)),
            ("fd00::4", Some(false)),
            ("127.0.0.1", None),
            ("169.254.3.4", None),
            ("fe80::1", None),
        ] {
            assert_eq!(on_link_in(&view, ip(addr)), want, "{addr}");
        }
        assert_eq!(
            on_link_in(&[], ip("192.168.0.20")),
            Some(false),
            "no network: nothing is on link"
        );
        assert!(
            NetState::new(false).view().is_empty(),
            "none before the baseline"
        );
    }

    fn nets(v: &[&str]) -> BTreeSet<IpNet> {
        v.iter().map(|s| net(s)).collect()
    }

    /// Cutoff F6, gate open: two laptops on a cable with no DHCP server.
    /// Wi-Fi gone is "no network"; a 169.254 address alone is then a
    /// network (a change back from offline: every path is new); a move to
    /// another link-local address is a change too, held by the gap; a
    /// normal network arriving is a change to it alone (the link-local one
    /// no longer counts beside it); it going leaves the cable again, and
    /// the cable unplugged is "no network". Gate closed: the same cable is
    /// nothing at all.
    #[test]
    fn a_link_local_only_cable_counts_when_nothing_else_does_under_the_switch() {
        let t0 = Instant::now();
        let mut st = baseline_with(t0, &["192.168.0.16/24", "fe80::1/64"], true);
        let t = t0 + secs(60);
        st.event(down("192.168.0.16/24"), t);
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Offline));
        assert_eq!((st.last_fire, st.gap), (None, GAP_MIN), "not a fire");
        // The OS self-assigns an address once DHCP gives up on the cable.
        let t = t + secs(30);
        st.event(up("169.254.10.2/16"), t);
        let cable = Change {
            from_offline: true,
            link_local: true,
            ..addresses_change(1, 0, 1)
        };
        assert!(cable.paths_stale(), "every path is new");
        let (fired, s) = settle_when_due(&mut st);
        assert_eq!((fired, s), (t + QUIET, Some(Settled::Changed(cable))));
        assert_eq!(st.view(), [net("169.254.10.2/16")]);
        // Another link-local address (a conflict moved it): a change.
        st.event(down("169.254.10.2/16"), fired + secs(1));
        st.event(up("169.254.20.3/16"), fired + secs(1));
        let moved = Change {
            link_local: true,
            ..addresses_change(1, 1, 1)
        };
        let (at, s) = settle_when_due(&mut st);
        assert_eq!(
            (at - fired, s),
            (GAP_MIN, Some(Settled::Changed(moved.clone())))
        );
        // A normal network beside it: the change is to that one alone.
        let t = at + secs(60);
        st.event(up("10.42.0.7/24"), t);
        assert_eq!(
            settle_when_due(&mut st),
            (t + QUIET, Some(addresses(1, 1, 1)))
        );
        assert_eq!(st.view(), [net("10.42.0.7/24")]);
        // It goes: the cable alone again.
        let t = t + secs(60);
        st.event(down("10.42.0.7/24"), t);
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Changed(moved)));
        assert_eq!(st.view(), [net("169.254.20.3/16")]);
        // Unplugged: no network.
        let t = t + secs(60);
        st.event(down("169.254.20.3/16"), t);
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Offline));
        assert!(st.view().is_empty());

        let mut closed = baseline(t0, &["192.168.0.16/24"]);
        closed.event(down("192.168.0.16/24"), t0 + secs(60));
        assert_eq!(settle_when_due(&mut closed).1, Some(Settled::Offline));
        closed.event(up("169.254.10.2/16"), t0 + secs(90));
        assert_eq!(closed.due_at(), None, "never armed");
        assert!(closed.view().is_empty());
    }

    /// F6's accepted cost: a Mac whose Thunderbolt Bridge keeps a 169.254
    /// address beside its Wi-Fi. Gate closed, Wi-Fi dropping is "no
    /// network" (no fire) and coming back a change; open, dropping is a
    /// change to the link-local network and coming back a change from it.
    /// Either way one decision per transition, so at most one more change
    /// each (every drop), and the same gap rules hold them: here a Wi-Fi
    /// flapping 1 s after each decision waits for the gap sooner.
    #[test]
    fn a_persistent_link_local_beside_wifi_adds_at_most_one_change_per_transition() {
        let wifi = "192.168.0.16/24";
        let run = |live: bool| -> Vec<(u64, Settled)> {
            let t0 = Instant::now();
            let mut st = baseline_with(t0, &[wifi, "169.254.7.7/16"], live);
            assert_eq!(st.view(), [net(wifi)], "beside Wi-Fi it never counts");
            let mut seen = Vec::new();
            let mut t = t0 + secs(60);
            for _ in 0..3 {
                for ev in [down(wifi), up(wifi)] {
                    st.event(ev, t);
                    let (at, s) = settle_when_due(&mut st);
                    seen.push(((at - t).as_secs(), s.expect("one decision per transition")));
                    assert_eq!(st.due_at(), None, "exactly one");
                    t = at + secs(1);
                }
            }
            seen
        };
        let back = Settled::Changed(Change {
            from_offline: true,
            ..addresses_change(1, 0, 1)
        });
        let offline = Settled::Offline;
        assert_eq!(
            run(false),
            [
                (2, offline.clone()),
                (2, back.clone()),
                (9, offline.clone()),
                (2, back.clone()),
                (19, offline),
                (2, back),
            ]
        );
        let to_cable = Settled::Changed(Change {
            link_local: true,
            ..addresses_change(1, 1, 1)
        });
        let from_cable = addresses(1, 1, 1);
        assert_eq!(
            run(true),
            [
                (2, to_cable.clone()),
                (9, from_cable.clone()),
                (19, to_cable.clone()),
                (39, from_cable.clone()),
                (79, to_cable),
                (159, from_cable),
            ]
        );
    }

    /// F6 counts IPv4 link-local only: fe80::/10 sits on every up interface
    /// (awdl, utun, llw) and never counts, gate open or closed; with only
    /// those, losing the Wi-Fi is still "no network".
    #[test]
    fn fe80_alone_never_counts() {
        for live in [false, true] {
            let t0 = Instant::now();
            let mut st = NetState::new(live);
            st.resync(t0);
            for v in ["fe80::1/64", "fe80::aede:48ff:fe00:1122/64", "febf::1/64"] {
                st.event(up(v), t0);
            }
            assert_eq!(
                settle_when_due(&mut st).1,
                Some(Settled::Baseline { networks: 0 }),
                "{live}"
            );
            let t = t0 + secs(60);
            st.event(up("fe80::2/64"), t);
            st.event(down("fe80::1/64"), t);
            assert_eq!(st.due_at(), None, "never armed ({live})");
            st.event(up("192.168.0.16/24"), t);
            let back = Change {
                from_offline: true,
                ..addresses_change(1, 0, 1)
            };
            assert_eq!(settle_when_due(&mut st).1, Some(Settled::Changed(back)));
            st.event(down("192.168.0.16/24"), t + secs(60));
            assert_eq!(settle_when_due(&mut st).1, Some(Settled::Offline), "{live}");
            assert!(!tracked(&net("fe80::1/64"), live));
            assert!(view_keys(&nets(&["fe80::1/64", "fe80::2/64"]), live).is_empty());
        }
    }

    /// F6 open: beside a counted network (IPv4 or IPv6) a 169.254 address
    /// never counts: the baseline counts the normal network only, and the
    /// link-local address coming, going or moving settles to nothing (no
    /// fire, no gap step).
    #[test]
    fn link_local_beside_a_normal_network_never_counts() {
        let t0 = Instant::now();
        let mut st = baseline_with(t0, &["192.168.0.16/24", "169.254.7.7/16"], true);
        assert_eq!(st.view(), [net("192.168.0.16/24")]);
        let t = t0 + secs(60);
        st.event(down("169.254.7.7/16"), t);
        st.event(up("169.254.9.9/16"), t + secs(1));
        assert_eq!(settle_when_due(&mut st).1, None);
        st.event(down("169.254.9.9/16"), t + secs(60));
        assert_eq!(settle_when_due(&mut st).1, None);
        assert_eq!((st.last_fire, st.gap), (None, GAP_MIN), "not a fire");
        assert_eq!(st.view(), [net("192.168.0.16/24")]);
        assert_eq!(
            view_keys(&nets(&["192.168.0.16/24", "169.254.7.7/16"]), true),
            nets(&["192.168.0.16/24"])
        );
        assert_eq!(
            view_keys(&nets(&["2001:db8:1::a/64", "169.254.7.7/16"]), true),
            nets(&["2001:db8:1::/64"]),
            "an IPv6 network counts as much"
        );
        assert_eq!(
            view_keys(
                &nets(&[
                    "169.254.7.7/16",
                    "169.254.9.9/16",
                    "127.0.0.1/8",
                    "fe80::1/64"
                ]),
                true
            ),
            nets(&["169.254.7.7/16", "169.254.9.9/16"]),
            "nothing else: the IPv4 link-local ones, each as itself"
        );
    }

    /// Gate closed (release until CP.16): today's view and lines. A
    /// 169.254 address is never tracked (it never arms the timer, and "no
    /// network" stays that with one up), and a change logs carrier_matrix
    /// C11's and s33's `raven-node netwatch: network changed (`; only a
    /// change to link-local networks alone (gate open) logs the cable's
    /// line, and a wake on the cable is still a wake.
    #[test]
    fn the_gate_closed_view_is_todays() {
        let t0 = Instant::now();
        let mut st = baseline(t0, &["192.168.0.16/24", "169.254.7.7/16"]);
        assert!(!st.addrs.contains(&net("169.254.7.7/16")), "not tracked");
        assert_eq!(st.view(), [net("192.168.0.16/24")]);
        let t = t0 + secs(60);
        st.event(down("192.168.0.16/24"), t);
        assert_eq!(settle_when_due(&mut st).1, Some(Settled::Offline));
        st.event(up("169.254.10.2/16"), t + secs(30));
        assert_eq!(st.due_at(), None);
        assert!(!tracked(&net("169.254.10.2/16"), false));
        assert!(tracked(&net("169.254.10.2/16"), true));
        assert!(view_keys(&nets(&["169.254.10.2/16"]), false).is_empty());
        assert_eq!(
            view_keys(&nets(&["192.168.0.16/24", "169.254.7.7/16"]), false),
            nets(&["192.168.0.16/24"])
        );

        let changed = addresses_change(1, 1, 1);
        assert_eq!(
            change_line(&changed, Some(2), false),
            "raven-node netwatch: network changed (1 new, 1 gone, 1 now): \
             retrying 2 waiting now, backoff restarted"
        );
        let woke = Change {
            cause: Cause::Wake,
            ..addresses_change(0, 0, 1)
        };
        assert_eq!(
            change_line(&woke, None, true),
            "raven-node netwatch: woke from sleep (0 new, 0 gone, 1 now): \
             outbox not running, p2p re-homing"
        );
        let route = Change {
            cause: Cause::Route,
            ..addresses_change(0, 0, 1)
        };
        assert!(change_line(&route, Some(0), false)
            .starts_with("raven-node netwatch: default route moved (0 new, 0 gone, 1 now)"));
        let cable = Change {
            from_offline: true,
            link_local: true,
            ..addresses_change(1, 0, 1)
        };
        assert_eq!(
            change_line(&cable, Some(1), false),
            "raven-node netwatch: link-local network only (a cable?) (1 new, 0 gone, 1 now): \
             retrying 1 waiting now, backoff restarted"
        );
        let cable_wake = Change {
            cause: Cause::Wake,
            ..cable
        };
        assert!(change_line(&cable_wake, Some(1), false)
            .starts_with("raven-node netwatch: woke from sleep ("));
    }

    /// Phase 3 (the LAN beacon, step 10): a change and the loss of every
    /// network both tell the beacon (what it found on gone interfaces goes,
    /// its query intervals start over); the first view does not. `act` has
    /// process-wide side effects that no test runs, so its arms are read
    /// from this file. The line carrier_matrix C11 and the fault matrix's
    /// s33 parse is unchanged.
    #[test]
    fn the_changed_and_offline_arms_tell_the_lan_beacon() {
        let source = include_str!("netwatch.rs");
        let act = &source[source.find("\nfn act(").expect("act")..];
        let act = &act[..act.find("\n}\n").expect("the end of act")];
        let arm = |head: &str| {
            let from = act.find(head).unwrap_or_else(|| panic!("{head}")) + head.len();
            let rest = &act[from..];
            rest[..rest.find("Settled::").unwrap_or(rest.len())].to_owned()
        };
        let beacon = "crate::lan_beacon::network_changed();";
        assert!(arm("Settled::Changed(c) =>").contains(beacon));
        assert!(arm("Settled::Offline =>").contains(beacon));
        assert!(!arm("Settled::Baseline { networks } =>").contains(beacon));
        assert!(!arm("Settled::PathLoss =>").contains(beacon));
        // Learning connectivity (Phase 6a) reads the network tag again on
        // the same two.
        let learning = "crate::learning::network_changed();";
        assert!(arm("Settled::Changed(c) =>").contains(learning));
        assert!(arm("Settled::Offline =>").contains(learning));
        assert!(!arm("Settled::Baseline { networks } =>").contains(learning));
        assert!(!arm("Settled::PathLoss =>").contains(learning));
        assert!(change_line(&addresses_change(1, 1, 2), Some(0), false)
            .starts_with("raven-node netwatch: network changed (1 new, 1 gone, 2 now): "));
    }

    /// The service's probes carry the offline-LAN gate (read once at
    /// start), and a release build follows the const alone: the lab switch
    /// is inert there (runs in a release test job; a debug build checks
    /// that the probes read the gate).
    #[test]
    fn the_link_local_rule_is_inert_in_release_and_follows_the_gate() {
        if !cfg!(debug_assertions) {
            // Edition 2021: a plain call. No release test reads it.
            std::env::set_var("RAVEN_LAB_OFFLINE", "1");
            assert_eq!(
                Probes::real(false).link_local,
                raven_core::lan_gate::OFFLINE_LAN_PRODUCTION_ENABLED
            );
            return;
        }
        assert_eq!(
            Probes::real(false).link_local,
            raven_core::offline_lan_live()
        );
        assert_eq!(
            Probes::real(true).link_local,
            raven_core::offline_lan_live()
        );
    }

    #[test]
    fn the_wake_clock_sees_sleep_on_both_clock_kinds() {
        let (m0, w0) = (Instant::now(), SystemTime::UNIX_EPOCH + secs(1_800_000_000));
        let hour = secs(3600);
        for (mono, wall, want) in [
            (secs(5), w0 + secs(5), None),
            // macOS / Linux: the monotonic clock stood still while asleep.
            (secs(5), w0 + 2 * hour, Some(2 * hour - secs(5))),
            // Windows QPC counts sleep; a stopped process.
            (2 * hour, w0 + 2 * hour, Some(2 * hour - WAKE_TICK)),
            // The wall clock stepped back: no wake.
            (secs(5), w0 - hour, None),
            (secs(5), w0 + secs(20), None),
            (secs(5), w0 + secs(40), Some(secs(35))),
        ] {
            let mut clock = WakeClock::new(m0, w0);
            assert_eq!(clock.check(m0 + mono, wall), want, "{mono:?} {wall:?}");
            // Each check is the reference for the next one.
            let next = wall + secs(5);
            assert_eq!(clock.check(m0 + mono + secs(5), next), None);
        }
    }

    #[test]
    fn lab_lines_parse_wake_and_egress() {
        assert_eq!(parse_lab_line("wake"), Some(NetEvent::Wake));
        assert_eq!(
            parse_lab_line(" egress 0a1b "),
            Some(NetEvent::Egress(tag("0a1b")))
        );
        assert_eq!(parse_lab_line("egress none"), Some(NetEvent::Egress(None)));
        let longest = "f".repeat(LAB_EGRESS_MAX);
        assert_eq!(
            parse_lab_line(&format!("egress {longest}")),
            Some(NetEvent::Egress(Some(longest)))
        );
        let too_long = format!("egress {}", "f".repeat(LAB_EGRESS_MAX + 1));
        for junk in [
            "wake now",
            "WAKE",
            "egress",
            "egress xyz",
            "egress 0A1B",
            "egress 0a1b extra",
            "egress -1",
            too_long.as_str(),
        ] {
            assert_eq!(parse_lab_line(junk), None, "{junk:?}");
        }
    }

    #[test]
    fn lab_lines_parse_and_garbage_is_ignored() {
        assert_eq!(
            parse_lab_line("up 192.0.2.10/24"),
            Some(NetEvent::If(up("192.0.2.10/24")))
        );
        assert_eq!(
            parse_lab_line("  down 2001:db8::1/64 "),
            Some(NetEvent::If(down("2001:db8::1/64")))
        );
        for junk in [
            "side 192.0.2.10/24",
            "",
            "up",
            "up 300.1.1.1/24",
            "up 192.0.2.10",
            "up 192.0.2.10/24 extra",
            "UP 192.0.2.10/24",
        ] {
            assert_eq!(parse_lab_line(junk), None, "{junk:?}");
        }
    }

    /// Release builds never read the lab variable (runs in a release test
    /// job; a debug build skips it).
    #[test]
    fn lab_events_are_inert_without_debug_assertions() {
        if cfg!(debug_assertions) {
            return;
        }
        // Edition 2021: a plain call. No other test reads this variable.
        std::env::set_var("RAVEN_LAB_NETWATCH_EVENTS", "raven-lab-netwatch.txt");
        assert_eq!(lab_events_path(), None);
    }

    async fn next_event<S>(events: &mut S) -> NetEvent
    where
        S: Stream<Item = io::Result<NetEvent>> + Unpin,
    {
        tokio::time::timeout(secs(10), events.next())
            .await
            .expect("an event within 10 s")
            .expect("the lab source never ends")
            .expect("the lab source never fails")
    }

    #[tokio::test]
    async fn the_lab_source_reads_whole_lines_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.txt");
        let mut events = Box::pin(lab_events(path.clone()));
        // A missing file is empty.
        let none = tokio::time::timeout(LAB_POLL * 3, events.next()).await;
        assert!(none.is_err(), "nothing yet");
        // Garbage is skipped; a line without its newline waits.
        std::fs::write(&path, "up 192.0.2.10/24\njunk\nup 198.51").unwrap();
        assert_eq!(
            next_event(&mut events).await,
            NetEvent::If(up("192.0.2.10/24"))
        );
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, b".100.7/24\ndown 192.0.2.10/24\n").unwrap();
        assert_eq!(
            next_event(&mut events).await,
            NetEvent::If(up("198.51.100.7/24"))
        );
        assert_eq!(
            next_event(&mut events).await,
            NetEvent::If(down("192.0.2.10/24"))
        );
    }

    type Recorded = Arc<Mutex<Vec<(Instant, Settled)>>>;

    fn recorder() -> (Recorded, impl FnMut(Settled, &[IpNet]) + Send + 'static) {
        let seen: Recorded = Arc::default();
        let log = Arc::clone(&seen);
        (seen, move |s, _| {
            log.lock().unwrap().push((Instant::now(), s))
        })
    }

    #[tokio::test(start_paused = true)]
    async fn the_driver_settles_after_quiet_and_reports_changes() {
        let t0 = Instant::now();
        let (tx, mut rx) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
        let (seen, mut record) = recorder();
        let views: Arc<Mutex<Vec<Vec<IpNet>>>> = Arc::default();
        let mut on = {
            let views = Arc::clone(&views);
            move |s, view: &[IpNet]| {
                views.lock().unwrap().push(view.to_vec());
                record(s, view)
            }
        };
        let task = tokio::spawn(async move {
            let mut state = NetState::new(false);
            state.resync(Instant::now());
            watch_events(&mut rx, &mut state, &Side::new(), &mut quiet(), &mut on).await
        });
        tx.unbounded_send(Ok(NetEvent::If(up("192.168.0.16/24"))))
            .unwrap();
        tx.unbounded_send(Ok(NetEvent::If(up("127.0.0.1/8"))))
            .unwrap();
        tokio::time::sleep_until(t0 + secs(5)).await;
        tx.unbounded_send(Ok(NetEvent::If(down("192.168.0.16/24"))))
            .unwrap();
        tx.unbounded_send(Ok(NetEvent::If(up("172.20.10.2/28"))))
            .unwrap();
        tokio::time::sleep_until(t0 + secs(30)).await;
        drop(tx);
        let err = task.await.unwrap();
        assert!(err.to_string().contains("ended"), "{err}");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![
                (t0 + QUIET, Settled::Baseline { networks: 1 }),
                (t0 + secs(5) + QUIET, addresses(1, 1, 1)),
            ]
        );
        // Each decision carries the networks it settled on (keys only).
        assert_eq!(
            views.lock().unwrap().clone(),
            [vec![net("192.168.0.16/24")], vec![net("172.20.10.2/28")]]
        );
    }

    /// The driver builds its state with F6 from its probes (the service's
    /// read the offline-LAN gate once): Wi-Fi traded for a cable is a change
    /// to the cable's network, with that view, while the gate is open, and
    /// "no network" while it is closed.
    #[tokio::test(start_paused = true)]
    async fn the_driver_takes_the_link_local_rule_from_its_probes() {
        type Seen = Arc<Mutex<Vec<(Settled, Vec<IpNet>)>>>;
        for live in [false, true] {
            let t0 = Instant::now();
            let (tx, rx) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
            let mut source = Some(rx);
            let open = move || source.take().ok_or_else(|| io::Error::other("no more"));
            let seen: Seen = Arc::default();
            let on = {
                let seen = Arc::clone(&seen);
                move |s: Settled, view: &[IpNet]| seen.lock().unwrap().push((s, view.to_vec()))
            };
            let probes = Probes {
                link_local: live,
                ..quiet()
            };
            let task = tokio::spawn(async move { run_with(open, probes, &Side::new(), on).await });
            tx.unbounded_send(Ok(NetEvent::If(up("192.0.2.10/24"))))
                .unwrap();
            tokio::time::sleep_until(t0 + secs(5)).await;
            for ev in [down("192.0.2.10/24"), up("169.254.10.2/16")] {
                tx.unbounded_send(Ok(NetEvent::If(ev))).unwrap();
            }
            tokio::time::sleep_until(t0 + secs(30)).await;
            task.abort();
            let after = if live {
                let cable = Change {
                    link_local: true,
                    ..addresses_change(1, 1, 1)
                };
                (Settled::Changed(cable), vec![net("169.254.10.2/16")])
            } else {
                (Settled::Offline, vec![])
            };
            assert_eq!(
                seen.lock().unwrap().clone(),
                [
                    (
                        Settled::Baseline { networks: 1 },
                        vec![net("192.0.2.10/24")]
                    ),
                    after
                ],
                "{live}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_or_ended_stream_is_returned_not_spun_on() {
        let polls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&polls);
        // Like if-watch after "Background task stopped" / "rtnetlink socket
        // closed": the same error on every poll.
        let mut failing = futures::stream::repeat_with(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("Background task stopped"))
        });
        let mut state = NetState::new(false);
        let side = Side::new();
        let err = watch_events(
            &mut failing,
            &mut state,
            &side,
            &mut quiet(),
            &mut |_, _| {},
        )
        .await;
        assert_eq!(err.to_string(), "Background task stopped");
        assert_eq!(polls.load(Ordering::SeqCst), 1, "never polled again");

        let (tx, mut rx) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
        drop(tx);
        let err = watch_events(&mut rx, &mut state, &side, &mut quiet(), &mut |_, _| {}).await;
        assert!(err.to_string().contains("ended"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_open_is_retried_with_backoff_and_the_baseline_survives_a_reopen() {
        let t0 = Instant::now();
        let (tx1, rx1) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
        let (tx2, rx2) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
        tx1.unbounded_send(Ok(NetEvent::If(up("192.168.0.16/24"))))
            .unwrap();
        tx2.unbounded_send(Ok(NetEvent::If(up("172.20.10.2/28"))))
            .unwrap();
        let mut sources = VecDeque::from([Err(io::Error::other("no store")), Ok(rx1), Ok(rx2)]);
        let opened: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let opens = Arc::clone(&opened);
        let open = move || {
            opens.lock().unwrap().push(Instant::now());
            sources
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::other("no more sources")))
        };
        let (seen, on) = recorder();
        let task = tokio::spawn(async move { run_with(open, quiet(), &Side::new(), on).await });
        // Open 1 fails at t0; open 2 at +REOPEN_MIN settles view A, then that
        // watcher fails; open 3 (the doubled wait later) sees view B.
        tokio::time::sleep_until(t0 + REOPEN_MIN + secs(3)).await;
        tx1.unbounded_send(Err(io::Error::other("rtnetlink socket closed")))
            .unwrap();
        tokio::time::sleep_until(t0 + secs(60)).await;
        task.abort();
        let reopened = t0 + REOPEN_MIN + secs(3) + REOPEN_MIN * 2;
        assert_eq!(
            opened.lock().unwrap().clone(),
            vec![t0, t0 + REOPEN_MIN, reopened]
        );
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![
                (t0 + REOPEN_MIN + QUIET, Settled::Baseline { networks: 1 }),
                (reopened + QUIET, addresses(1, 1, 1)),
            ]
        );
        drop(tx2);
    }

    /// Phase 0b: the wake clock runs only while a watcher is open and is
    /// seeded again at every open, so a long reopen backoff (300 s here) is
    /// no false wake; a real sleep after it is one.
    #[tokio::test(start_paused = true)]
    async fn the_wake_clock_is_reseeded_after_a_reopen() {
        let t0 = Instant::now();
        // The wall clock follows the paused monotonic clock, plus `slept` (a
        // sleep the monotonic clock did not see).
        let slept = Arc::new(Mutex::new(Duration::ZERO));
        let wall = {
            let slept = Arc::clone(&slept);
            let base = SystemTime::UNIX_EPOCH + secs(1_800_000_000);
            move || base + (Instant::now() - t0) + *slept.lock().unwrap()
        };
        let (tx1, rx1) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
        let (tx2, rx2) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
        tx1.unbounded_send(Ok(NetEvent::If(up("192.168.0.16/24"))))
            .unwrap();
        tx2.unbounded_send(Ok(NetEvent::If(up("192.168.0.16/24"))))
            .unwrap();
        // Watcher 1 fails at +3 s; six failed opens later (waits 5, 10, 20,
        // 40, 80, 160 s) the last wait is 300 s before watcher 2 opens.
        let mut sources = VecDeque::from([Ok(rx1)]);
        sources.extend((0..6).map(|_| Err(io::Error::other("no store"))));
        sources.push_back(Ok(rx2));
        let opened: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let opens = Arc::clone(&opened);
        let open = move || {
            opens.lock().unwrap().push(Instant::now());
            sources
                .pop_front()
                .unwrap_or_else(|| Err(io::Error::other("no more sources")))
        };
        let probes = Probes {
            wake_clock: true,
            wall: Box::new(wall),
            egress: Box::new(|| None),
            seen: Box::new(|_| {}),
            link_local: false,
        };
        let (seen, on) = recorder();
        let task = tokio::spawn(async move { run_with(open, probes, &Side::new(), on).await });
        tokio::time::sleep_until(t0 + secs(3)).await;
        tx1.unbounded_send(Err(io::Error::other("rtnetlink socket closed")))
            .unwrap();
        let second = t0 + secs(3 + 5 + 10 + 20 + 40 + 80 + 160 + 300);
        // Off the 5 s check grid, so the order of the two is certain.
        tokio::time::sleep_until(second + secs(82)).await;
        assert_eq!(opened.lock().unwrap().last(), Some(&second));
        // Asleep for an hour: the next check (at +85 s) sees it.
        *slept.lock().unwrap() = secs(3600);
        tokio::time::sleep_until(second + secs(200)).await;
        task.abort();
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![
                (t0 + QUIET, Settled::Baseline { networks: 1 }),
                (second + secs(85) + QUIET, woke(0, 0, 1)),
            ]
        );
        drop((tx1, tx2));
    }

    /// Phase 0b: the p2p host's hint reaches the driver, which reads the
    /// default routes' fingerprint first. Two hints in a row are one path
    /// loss; a hint before the baseline is nothing.
    #[tokio::test(start_paused = true)]
    async fn a_relay_hint_becomes_one_path_loss() {
        let t0 = Instant::now();
        let side = Arc::new(Side::new());
        let reads: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let egress = {
            let reads = Arc::clone(&reads);
            move || {
                reads.lock().unwrap().push(Instant::now());
                Some(tag("aa"))
            }
        };
        let mut probes = Probes {
            wake_clock: false,
            wall: Box::new(SystemTime::now),
            egress: Box::new(egress),
            seen: Box::new(|_| {}),
            link_local: false,
        };
        let (tx, mut rx) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
        let (seen, mut on) = recorder();
        let task = {
            let side = Arc::clone(&side);
            tokio::spawn(async move {
                let mut state = NetState::new(false);
                state.resync(Instant::now());
                watch_events(&mut rx, &mut state, &side, &mut probes, &mut on).await
            })
        };
        side.hint(Hint::RelayLoss);
        tx.unbounded_send(Ok(NetEvent::If(up("192.168.0.16/24"))))
            .unwrap();
        tokio::time::sleep_until(t0 + secs(20)).await;
        side.hint(Hint::RelayLoss);
        side.hint(Hint::RelayLoss);
        tokio::time::sleep_until(t0 + secs(60)).await;
        drop(tx);
        let err = task.await.unwrap();
        assert!(err.to_string().contains("ended"), "{err}");
        assert!(reads.lock().unwrap().contains(&(t0 + secs(20))));
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![
                (t0 + QUIET, Settled::Baseline { networks: 1 }),
                (t0 + secs(20) + QUIET, Settled::PathLoss),
            ]
        );
    }

    /// Phase 0b: the default routes' fingerprint is read only while a p2p
    /// host or route memory needs it, never with the lab file; when read, it
    /// is read at the open (seeding it), every 30 s and right before each
    /// decision.
    #[tokio::test(start_paused = true)]
    async fn the_egress_poll_runs_only_when_a_p2p_host_or_route_memory_needs_it() {
        for (lab, host, memory, want) in [
            (false, false, false, false),
            (false, true, false, true),
            (false, false, true, true),
            (false, true, true, true),
            (true, true, true, false),
            (true, false, false, false),
        ] {
            assert_eq!(
                egress_needed(lab, host, memory),
                want,
                "{lab} {host} {memory}"
            );
        }
        let mut lab = Probes::real(true);
        assert!(!lab.wake_clock, "the lab file's `wake` lines stand in");
        assert_eq!((lab.egress)(), None, "and its `egress` lines");
        assert!(Probes::real(false).wake_clock);

        let t0 = Instant::now();
        let needed = Arc::new(AtomicBool::new(true));
        let current = Arc::new(Mutex::new(tag("aa")));
        let reads: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let egress = {
            let (needed, current, reads) = (
                Arc::clone(&needed),
                Arc::clone(&current),
                Arc::clone(&reads),
            );
            move || {
                if !needed.load(Ordering::SeqCst) {
                    return None;
                }
                reads.lock().unwrap().push(Instant::now());
                Some(current.lock().unwrap().clone())
            }
        };
        let mut probes = Probes {
            wake_clock: false,
            wall: Box::new(SystemTime::now),
            egress: Box::new(egress),
            seen: Box::new(|_| {}),
            link_local: false,
        };
        let (tx, mut rx) = futures::channel::mpsc::unbounded::<io::Result<NetEvent>>();
        let (seen, mut on) = recorder();
        let task = tokio::spawn(async move {
            let mut state = NetState::new(false);
            state.resync(Instant::now());
            watch_events(&mut rx, &mut state, &Side::new(), &mut probes, &mut on).await
        });
        tx.unbounded_send(Ok(NetEvent::If(up("192.168.0.16/24"))))
            .unwrap();
        tokio::time::sleep_until(t0 + secs(40)).await;
        *current.lock().unwrap() = tag("bb");
        tokio::time::sleep_until(t0 + secs(70)).await;
        // Nothing needs it any more: never read again, a move goes unseen.
        needed.store(false, Ordering::SeqCst);
        *current.lock().unwrap() = tag("cc");
        tokio::time::sleep_until(t0 + secs(200)).await;
        drop(tx);
        let err = task.await.unwrap();
        assert!(err.to_string().contains("ended"), "{err}");
        assert_eq!(
            reads.lock().unwrap().clone(),
            vec![
                t0,
                t0 + QUIET,
                t0 + secs(30),
                t0 + secs(60),
                t0 + secs(60) + QUIET
            ]
        );
        let route = Change {
            cause: Cause::Route,
            egress_moved: true,
            ..addresses_change(0, 0, 1)
        };
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![
                (t0 + QUIET, Settled::Baseline { networks: 1 }),
                (t0 + secs(60) + QUIET, Settled::Changed(route)),
            ]
        );
    }

    /// Wait (up to 10 s) until `f` holds.
    async fn eventually(what: &str, f: impl Fn() -> bool) {
        let deadline = Instant::now() + secs(10);
        while !f() {
            assert!(Instant::now() < deadline, "{what}: not within 10 s");
            tokio::time::sleep(LAB_POLL).await;
        }
    }

    /// F9: every default-route reading reaches [`last_egress`], the lab
    /// file's `egress` lines included; a route coming back clears the
    /// `no_route` reasons, and only those. A reading that stays absent
    /// clears nothing.
    #[tokio::test]
    async fn a_route_coming_back_clears_no_route_reasons() {
        use raven_core::reach_diag::Why;
        let _lock = egress_test_lock().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.txt");
        std::fs::write(&path, "egress none\n").unwrap();
        set_last_egress(None);
        let task = lab_reader(path.clone());
        eventually("egress none read", || last_egress() == Some(false)).await;
        let (alice, bob) = ([0xA9; 32], [0xB9; 32]);
        let diag = crate::delivery_paths::tests::diag;
        crate::delivery_paths::note_unreachable(&alice, &diag(Why::NoRoute), None);
        crate::delivery_paths::note_unreachable(&bob, &diag(Why::BothNat), None);
        let why = |k: &[u8; 32]| crate::delivery_paths::why_for(k).map(|(d, _)| d.why);
        // Still none: nothing is cleared.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, b"egress none\n").unwrap();
        tokio::time::sleep(LAB_POLL * 4).await;
        assert_eq!(why(&alice), Some(Why::NoRoute));
        // Back: alice's no_route goes, bob's both_nat stays.
        std::io::Write::write_all(&mut file, b"egress 0a\n").unwrap();
        eventually("egress 0a read", || last_egress() == Some(true)).await;
        assert_eq!(why(&alice), None);
        assert_eq!(why(&bob), Some(Why::BothNat));
        task.abort();
        let _ = task.await;
        set_last_egress(None);
    }
}
