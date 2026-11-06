//! The Bluetooth LE nearby carrier in raven-node (RNL1,
//! `protocol/RAVEN_NEARBY_LINK_V1.md`; Nearby design steps 5.5 and 5.6).
//! Gated by [`raven_core::nearby_live_enabled`]
//! (`NEARBY_PRODUCTION_ENABLED`: true on macOS since 2026-10-29, false on
//! Windows and Linux).
//!
//! - [`radio`]: the seam every Bluetooth LE backend implements (BlueZ on
//!   linux-gnu, WinRT on Windows and CoreBluetooth on macOS and iOS, feature
//!   `nearby-radio`), and the one place that picks a backend.
//! - [`pipe`]: the RNP1 pipe driver: one task per pipe that came UP, two
//!   byte channels as `tokio::io::duplex` pairs with credit backpressure.
//! - [`engine`]: the one owner of the radio: pair keys, scanning,
//!   advertising, the RNK1 knock and the pipes.
//! - [`fake`] (tests and debug builds only): the no-hardware radio, an
//!   in-process ether; [`ether_hub`] serves one ether to lab raven-nodes over
//!   loopback TCP (`raven-node nearby-ether`, debug builds only).
//! - `bluez` and `bluez_mgmt` (glibc Linux with `nearby-radio`; their pure
//!   parts in every test build): the BlueZ backend over zbus 1.9.3, and the
//!   management socket's READ_INFO for the address-privacy bit.
//! - `winrt` (Windows with `nearby-radio`; its pure part in every test
//!   build): the WinRT backend over windows 0.62.2.
//! - `apple` (macOS and iOS with `nearby-radio`; its pure part in every
//!   test build): the CoreBluetooth backend, run in the `raven-nearby-helper`
//!   process of RavenNearby.app on macOS (objc2-core-bluetooth 0.3.2, owner
//!   decision O5-10) and the line protocol raven-node speaks with it, and on
//!   iOS the same machine and glue inside the app's own process
//!   (`apple::inproc`, Task 2).
//!
//! This module is the rest of the node's way in:
//! - [`run`], the service task (`raven-node service`). With the gate closed
//!   it idles for the life of the process and reads nothing. With it open it
//!   reads node_policy's `nearby` every [`POLICY_POLL`] (and at once after
//!   `raven nearby enable|disable`, [`policy_changed`]); only while that is
//!   on does it load the identity, create the radio ([`radio::platform_radio`])
//!   and run the engine, so a closed gate or a user who never said yes means
//!   no radio object and no operating-system Bluetooth prompt.
//! - [`dial`]: the carrier's dial (outbox, custody, route hints, IPC
//!   `NearbyDial`): verified contacts only, over a pipe that is up or comes
//!   up within [`CONNECT_BUDGET`]; otherwise [`NEARBY_NOT_IN_RANGE`] at once,
//!   and the contact is wanted ([`engine::EngineHandle::want`]).
//! - [`route_connected`] and [`available`] for the planners: a nearby route
//!   is planned only for a contact the engine holds a pair key for, last,
//!   and first only while its pipe is up.
//! - [`control`] and [`status`] for IPC `NearbyControl` and `Status`.
//!
//! The other side's channel on a pipe runs the Internet direct responder
//! ([`crate::internet_direct::serve_inbound_on`] with [`NEARBY_LINK`] and the
//! knocked contact as its expected key) under [`crate::netutil::NEARBY_INBOUND`].

use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use futures::future::BoxFuture;
use raven_core::identity::Identity;
use raven_core::ipc::NearbyStatusInfo;
use raven_core::nearby_link::PairKeys;
use raven_core::outbox::{nearby_dial_peer, DeliveryPath, OutboxCarrier, OutboxRoute};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use crate::internet_direct::{self, NEARBY_LINK};
use crate::netutil::{self, Admission, DialProgress, PRODUCTION_REPLY_WAITS};
use crate::pair_seed::KeyUse;
use engine::{EngineHandle, Host, KeyStamp};
use radio::RadioState;

#[cfg(any(
    test,
    all(any(target_os = "macos", target_os = "ios"), feature = "nearby-radio")
))]
pub(crate) mod apple;
#[cfg(any(
    test,
    all(target_os = "linux", target_env = "gnu", feature = "nearby-radio")
))]
pub(crate) mod bluez;
#[cfg(any(
    test,
    all(target_os = "linux", target_env = "gnu", feature = "nearby-radio")
))]
pub(crate) mod bluez_mgmt;
pub(crate) mod engine;
#[cfg(any(test, debug_assertions))]
pub(crate) mod ether_hub;
#[cfg(any(test, debug_assertions))]
pub(crate) mod fake;
pub(crate) mod pipe;
pub(crate) mod radio;
#[cfg(any(test, all(windows, feature = "nearby-radio")))]
pub(crate) mod winrt;

/// How long a dial waits for a pipe to come up (a contact seen, or a knock
/// under way).
pub(crate) const CONNECT_BUDGET: Duration = Duration::from_secs(12);
/// The whole dial, below the 45 s IPC cap (as Internet direct).
pub(crate) const DIAL_DEADLINE: Duration = Duration::from_secs(40);
/// User work (a send, an open chat) keeps a contact eligible this long
/// (RNL1 §3); [`foreground_ttl`] is what the node uses.
pub(crate) const FOREGROUND_TTL: Duration = Duration::from_secs(15 * 60);
/// The debug lab switch that shortens [`FOREGROUND_TTL`], in milliseconds
/// (carrier_matrix C56's variant and the fault matrix's s72: radios that
/// meet after the user's work ran out). Read only in a debug build with the
/// nearby lab switch on.
pub(crate) const LAB_FOREGROUND_MS: &str = "RAVEN_LAB_NEARBY_FOREGROUND_MS";
/// A sighting is fresh enough to connect to this long.
pub(crate) const SEEN_TTL: Duration = Duration::from_secs(30);
/// One token on air this long, then the next one in the rotation (RNL1 §3).
pub(crate) const ADV_SLOT: Duration = Duration::from_secs(5);
/// Each side of a knock (RNL1 §5).
pub(crate) const KNOCK_DEADLINE: Duration = Duration::from_secs(5);
/// The service reads node_policy's nearby settings this often.
pub(crate) const POLICY_POLL: Duration = Duration::from_secs(30);
/// How long a stopping engine may take to reset its pipes.
const STOP_WAIT: Duration = Duration::from_secs(2);

/// A nearby dial to a contact whose beacon is not seen now (stable code
/// `NEARBY_NOT_IN_RANGE`). Fails fast: other carriers are not held up, and
/// it is never route evidence.
pub(crate) const NEARBY_NOT_IN_RANGE: &str =
    "NEARBY_NOT_IN_RANGE: the contact's Bluetooth beacon is not seen now";
/// A nearby dial to a contact in range while the pipes are all taken, this
/// node's or the contact's (stable code `NEARBY_BUSY`). Fails fast like
/// [`NEARBY_NOT_IN_RANGE`], is never route evidence, and the outbox tries
/// again on its backoff.
pub(crate) const NEARBY_BUSY: &str =
    "NEARBY_BUSY: the contact is in Bluetooth range but every nearby link is in use now";
/// No nearby engine runs in this raven-node (stable code
/// `NEARBY_NOT_RUNNING`).
pub(crate) const NEARBY_NOT_RUNNING: &str =
    "NEARBY_NOT_RUNNING: nearby is not running in this raven-node (raven nearby enable turns it \
     on; it also needs a Bluetooth backend in this build)";

/// How long user work (and a dial that wanted the contact) keeps it
/// eligible: [`FOREGROUND_TTL`], or [`LAB_FOREGROUND_MS`] in a debug lab
/// run with the nearby lab switch on (read once).
pub(crate) fn foreground_ttl() -> Duration {
    static TTL: OnceLock<Duration> = OnceLock::new();
    *TTL.get_or_init(|| {
        foreground_ttl_from(
            raven_core::pair_init::lab_switch(raven_core::nearby_gate::LAB_NEARBY),
            raven_core::p2p_gate::lab_switch(LAB_FOREGROUND_MS).as_deref(),
        )
    })
}

/// [`foreground_ttl`] from its inputs: the lab value only with the nearby
/// lab switch on, and only a whole number of milliseconds from 1 up to
/// [`FOREGROUND_TTL`] (it can only shorten it).
fn foreground_ttl_from(lab: bool, value: Option<&str>) -> Duration {
    let max = u64::try_from(FOREGROUND_TTL.as_millis()).unwrap_or(u64::MAX);
    value
        .filter(|_| lab)
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| (1..=max).contains(ms))
        .map_or(FOREGROUND_TTL, Duration::from_millis)
}

/// A nearby mutex, poisoned or not: every critical section here leaves the
/// state whole.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ── The service ─────────────────────────────────────────────────────────────

/// The service task's state, shared with IPC.
#[derive(Default)]
struct Service {
    engine: Mutex<Option<EngineHandle>>,
    /// node_policy's nearby settings changed (`raven nearby enable|disable`).
    wake: Notify,
    status: Mutex<ServiceStatus>,
}

#[derive(Default)]
struct ServiceStatus {
    /// The service task runs past the gate in this process.
    running: bool,
    /// node_policy `nearby`, as last read.
    enabled: bool,
    /// node_policy `nearby_background_mail` (OD-C8), as last read.
    background: bool,
    /// Why the last start made no engine, if it did not
    /// ([`StartError::state_name`]).
    radio: Option<&'static str>,
}

fn service() -> &'static Service {
    static SERVICE: OnceLock<Service> = OnceLock::new();
    SERVICE.get_or_init(Service::default)
}

/// Radios the service task asked for ([`radio::platform_radio`]): the
/// proof that a closed gate or a user who never enabled nearby creates none.
static RADIO_STARTS: AtomicU64 = AtomicU64::new(0);

/// The running engine, if any.
pub(crate) fn current() -> Option<EngineHandle> {
    lock(&service().engine)
        .clone()
        .filter(EngineHandle::is_running)
}

/// node_policy's nearby settings changed: the service applies them now.
pub(crate) fn policy_changed() {
    service().wake.notify_one();
}

/// The engine the service runs now (`None`: none). raven-core's engine flag
/// ([`raven_core::nearby_gate::set_nearby_running`]) follows it, so the
/// nearby carrier counts for custody only while an engine runs that can go
/// on the air (review nearby-2; offline mesh carry research, Phase 0: an
/// engine whose radio would use the adapter's fixed public address carries
/// nothing, [`EngineHandle::may_go_on_air`]); when that changes, the
/// announcer looks again at this node's custody offer
/// ([`crate::hints::own_changed`]).
fn set_current(engine: Option<EngineHandle>) {
    let on = engine.as_ref().is_some_and(EngineHandle::may_go_on_air);
    *lock(&service().engine) = engine;
    if raven_core::nearby_gate::set_nearby_running(on) {
        crate::hints::own_changed();
    }
}

/// The engine the service runs, stopped when the service task ends.
#[derive(Default)]
struct Running {
    engine: Option<(EngineHandle, JoinHandle<()>)>,
}

impl Running {
    /// The engine's task ended (its radio went away); never, while none
    /// runs. The engine stays here: [`Self::stop`] ends it.
    async fn ended(&mut self) {
        match self.engine.as_mut() {
            Some((_, task)) => {
                let _ = task.await;
            }
            None => std::future::pending::<()>().await,
        }
    }

    async fn stop(&mut self) {
        let Some((handle, task)) = self.engine.take() else {
            return;
        };
        set_current(None);
        handle.stop();
        // An ended task has nothing to wait for, and [`Self::ended`] may
        // already have taken its result: polling it again panics.
        if task.is_finished() {
            return;
        }
        let abort = task.abort_handle();
        if tokio::time::timeout(STOP_WAIT, task).await.is_err() {
            abort.abort();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some((handle, task)) = self.engine.take() {
            set_current(None);
            // The task must not outlive the service. Ending it drops its
            // pipes (each driver then resets with SHUTDOWN) and the radio.
            handle.stop();
            task.abort();
        }
        lock(&service().status).running = false;
    }
}

/// The supervised service task (`raven-node service`; see the module doc).
/// `background_life`: the service of an iOS app's background node (Task 2
/// Phase B), whose engine is a background life (its scan filter,
/// [`engine::spawn`]).
pub(crate) async fn run(data_dir: PathBuf, background_life: bool) -> Result<(), String> {
    if !raven_core::nearby_live_enabled() {
        // Closed for the life of the process (lab switches are read at
        // start): nothing is read, no identity, no radio.
        std::future::pending::<()>().await;
    }
    let svc = service();
    lock(&svc.status).running = true;
    let mut running = Running::default();
    let admission = Admission::new(netutil::NEARBY_INBOUND);
    let mut identity: Option<Arc<Identity>> = None;
    let mut refused: Option<String> = None;
    loop {
        let dd = data_dir.clone();
        let (on, background_mail) =
            tokio::task::spawn_blocking(move || raven_core::node_policy::nearby_settings(&dd))
                .await
                .unwrap_or((false, false));
        {
            let mut status = lock(&svc.status);
            status.enabled = on;
            status.background = background_mail;
        }
        if running
            .engine
            .as_ref()
            .is_some_and(|(_, task)| task.is_finished())
        {
            // The radio went away: start again below while still on.
            running.stop().await;
        }
        match (&running.engine, on) {
            (Some((handle, _)), true) => handle.set_background_mail(background_mail),
            (Some(_), false) => {
                running.stop().await;
                eprintln!("raven-node nearby: stopped");
            }
            (None, true) => {
                match start(
                    &data_dir,
                    &mut identity,
                    &admission,
                    background_mail,
                    background_life,
                )
                .await
                {
                    Ok(started) => {
                        lock(&svc.status).radio = None;
                        refused = None;
                        eprintln!("raven-node nearby: started ({})", radio::backend_name());
                        running.engine = Some(started);
                    }
                    Err(why) => {
                        let line = why.to_string();
                        if refused.as_ref() != Some(&line) {
                            eprintln!("raven-node nearby: not started: {line}");
                            refused = Some(line);
                        }
                        lock(&svc.status).radio = Some(why.state_name());
                    }
                }
            }
            (None, false) => {}
        }
        tokio::select! {
            () = tokio::time::sleep(POLICY_POLL) => {}
            () = svc.wake.notified() => {}
            () = running.ended() => {}
        }
    }
}

/// Why the service made no engine.
enum StartError {
    /// The local state (identity, prekeys, sessions) is not ready.
    Local(String),
    /// No radio: the backend's answer.
    Radio(RadioState),
}

impl StartError {
    /// [`NearbyStatusInfo::radio`] for it: `local_state` for this profile's
    /// own state (never "Bluetooth off"), else the radio's state, whose
    /// reason class says whether Bluetooth LE is missing or only the
    /// software it needs (review nearby-3).
    fn state_name(&self) -> &'static str {
        match self {
            Self::Local(_) => "local_state",
            Self::Radio(state) => engine::state_name(state),
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(e) => write!(f, "local state: {e}"),
            // The backend's reason too (it names no device), so the log
            // keeps what the status row can only class.
            Self::Radio(state @ (RadioState::Unauthorized(why) | RadioState::Unsupported(why))) => {
                write!(f, "radio {} ({why})", engine::state_name(state))
            }
            Self::Radio(state) => write!(f, "radio {}", engine::state_name(state)),
        }
    }
}

/// The identity (loaded once, as the listeners do), the radio and the
/// engine (a background life when `background`).
async fn start(
    data_dir: &Path,
    identity: &mut Option<Arc<Identity>>,
    admission: &Arc<Admission>,
    background_mail: bool,
    background: bool,
) -> Result<(EngineHandle, JoinHandle<()>), StartError> {
    let id = match identity.clone() {
        Some(id) => id,
        None => {
            let dd = data_dir.to_path_buf();
            let loaded = internet_direct::blocking(move || {
                internet_direct::preflight_link_ready(NEARBY_LINK, &dd)
            })
            .await
            .map_err(StartError::Local)?;
            let id = Arc::new(loaded);
            *identity = Some(Arc::clone(&id));
            id
        }
    };
    let (tx, rx) = mpsc::channel(radio::EVENT_QUEUE);
    RADIO_STARTS.fetch_add(1, Ordering::Relaxed);
    let radio = tokio::task::spawn_blocking(move || radio::platform_radio(tx))
        .await
        .map_err(|e| StartError::Radio(RadioState::Unsupported(e.to_string())))?
        .map_err(StartError::Radio)?;
    let host = Arc::new(NodeHost {
        data_dir: data_dir.to_path_buf(),
        identity: Arc::clone(&id),
        admission: Arc::clone(admission),
    });
    let (handle, task) = engine::spawn(
        radio,
        rx,
        host,
        id.public_key_bytes(),
        background_mail,
        background,
    );
    set_current(Some(handle.clone()));
    Ok((handle, task))
}

// ── The engine's host in raven-node ─────────────────────────────────────────

/// Contacts a background scan filter remembers of each kind (Task 2 Q5).
const REMEMBERED: usize = engine::FILTER_CONTACTS;

/// What this process remembers for a background life's scan filter across
/// engines (the iOS app's full node stops before its background node
/// starts): the contacts whose pipe came up last, newest first, and those
/// `raven nearby on` named and `off` did not undo since. In memory only,
/// keys only, at most [`REMEMBERED`] of each.
#[derive(Default)]
struct Remembered {
    pipes: Vec<[u8; 32]>,
    on: Vec<[u8; 32]>,
}

impl Remembered {
    fn piped(&mut self, peer: [u8; 32]) {
        self.pipes.retain(|p| *p != peer);
        self.pipes.insert(0, peer);
        self.pipes.truncate(REMEMBERED);
    }

    fn on(&mut self, peer: [u8; 32], on: bool) {
        self.on.retain(|p| *p != peer);
        if on {
            self.on.insert(0, peer);
            self.on.truncate(REMEMBERED);
        }
    }
}

fn remembered() -> &'static Mutex<Remembered> {
    static MEMORY: OnceLock<Mutex<Remembered>> = OnceLock::new();
    MEMORY.get_or_init(Mutex::default)
}

/// `raven-node service`'s: its profile, the outbox, custody and the
/// Internet direct responder.
struct NodeHost {
    data_dir: PathBuf,
    identity: Arc<Identity>,
    admission: Arc<Admission>,
}

impl Host for NodeHost {
    fn now_ms(&self) -> u64 {
        raven_core::clock::now_ms()
    }

    fn stamp(&self) -> KeyStamp {
        key_stamp(&self.data_dir)
    }

    fn load_keys(&self) -> BoxFuture<'static, Result<Vec<(PairKeys, KeyUse)>, String>> {
        let (dd, id) = (self.data_dir.clone(), Arc::clone(&self.identity));
        let seeds = crate::pair_seed::live();
        Box::pin(internet_direct::blocking(move || {
            load_keys(&dd, &id, seeds)
        }))
    }

    fn has_work(&self) -> BoxFuture<'static, Vec<[u8; 32]>> {
        work_for(
            self.data_dir.clone(),
            self.identity.public_key_bytes(),
            crate::outbox::waiting_peers(engine::MAX_KEYS),
        )
    }

    /// Task 2 Q5: the work (outbox, held, mail friends, keepers), then the
    /// contacts with a recent pipe and those `raven nearby on` named, as this
    /// process remembers them across engines ([`Remembered`]: the full node's
    /// engine is gone when the background node starts).
    fn filter_contacts(&self) -> BoxFuture<'static, Vec<[u8; 32]>> {
        let work = self.has_work();
        Box::pin(async move {
            let (recent, on) = {
                let r = lock(remembered());
                (r.pipes.clone(), r.on.clone())
            };
            let mut out = work.await;
            for peer in recent.into_iter().chain(on) {
                if !out.contains(&peer) {
                    out.push(peer);
                }
            }
            out
        })
    }

    fn pipe_up(&self, peer: &[u8; 32]) {
        lock(remembered()).piped(*peer);
        // What waits for the contact goes now, over the pipe first
        // (`route_connected`); a custodian is fetched from at once, and
        // (P5.33) what waits for the contacts it may carry mail for goes
        // too (the blocking pool reads the book and the route hints).
        let _ = crate::outbox::kick(Some(peer), false, false);
        if crate::custody::encounter(peer) {
            let (dd, local, peer) = (
                self.data_dir.clone(),
                self.identity.public_key_bytes(),
                *peer,
            );
            tokio::spawn(internet_direct::blocking(move || {
                crate::custody::kick_carried(&dd, &local, &peer);
                Ok(())
            }));
        }
    }

    fn inbound(&self, peer: [u8; 32], stream: DuplexStream) {
        if NEARBY_LINK.require_live().is_err() {
            return;
        }
        serve_inbound(
            self.data_dir.clone(),
            Arc::clone(&self.identity),
            &self.admission,
            peer,
            stream,
        );
    }

    fn allow_public_address(&self) -> bool {
        raven_core::pair_init::lab_switch("RAVEN_LAB_NEARBY_ALLOW_PUBLIC_ADDR")
    }
}

/// What tells that the pair keys must be read again: the contact book, the
/// block list, the revocation store, the cached device certificates and the
/// pair seeds (Phase 6b), the contact book's reload generation (it moves
/// when the at-rest key arrives), and while pair seeds are live the hour (a
/// retired seed leaves the keys within it).
fn key_stamp(dd: &Path) -> KeyStamp {
    use crate::p2p::file_stamp;
    let (seeds, hour) = crate::pair_seed::stamp(dd);
    (
        vec![
            file_stamp(&dd.join(raven_core::contact_book::CONTACTS_FILE)),
            file_stamp(&raven_core::chat_history::blocked_path(dd)),
            file_stamp(&raven_core::device_sync::revocation_store_path(dd)),
            file_stamp(&raven_core::lan_dispatch::peer_cert_cache_path(dd)),
            seeds,
        ],
        raven_core::contact_book::reload_generation(dd),
        if crate::pair_seed::live() { hour } else { 0 },
    )
}

/// Blocking: the pair keys (RNL1 §0, §2) of every verified, unblocked
/// contact that has a valid cached device certificate whose lineage is not
/// revoked, at most [`engine::MAX_KEYS`] contacts. While pair seeds are live
/// (`seeds`, Phase 6b P6.38) a contact has up to three key sets (its
/// current seed's, a proposal's or its previous seed's, the root's), each
/// with what it is for; otherwise the root's alone. An unreadable book,
/// block list, certificate cache or revocation store is an error (nobody
/// then).
pub(crate) fn load_keys(
    dd: &Path,
    identity: &Identity,
    seeds: bool,
) -> Result<Vec<(PairKeys, KeyUse)>, String> {
    let seeds = crate::pair_seed::book(dd, seeds);
    let mut out = Vec::new();
    let mut contacts = 0;
    for peer in raven_core::outbox::pinned_unblocked_contacts(dd)? {
        if contacts == engine::MAX_KEYS {
            break;
        }
        let Some(cert) = raven_core::lan_dispatch::cached_peer_certificate(dd, &peer)? else {
            continue;
        };
        if raven_core::outbox::peer_lineage_denied(dd, &cert)? {
            continue;
        }
        // A key the R2 root refuses (§2) is left out.
        if let Ok(sets) = crate::pair_seed::key_sets(
            identity,
            &peer,
            &seeds,
            raven_core::nearby_link::pair_keys_from,
        ) {
            contacts += 1;
            out.extend(sets);
        }
    }
    Ok(out)
}

/// Blocking: whom this node holds mail for as a custodian (cutoff addendum
/// F11d): the recipients of its unreleased custody objects, then (`letters`:
/// it serves the letter ops) of its letters, newest deposit first each, then
/// the custody handoff next hops `hops`. An unreadable store adds nobody.
fn held_work(dd: &Path, letters: bool, hops: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let now = raven_core::clock::now_ms();
    let mut held = raven_core::friend_custody::held_recipients(dd, now).unwrap_or_default();
    if letters {
        held.extend(
            raven_core::friend_custody::held_letter_recipients(dd, now).unwrap_or_default(),
        );
    }
    held.extend(hops);
    held
}

/// [`NodeHost::has_work`] once the outbox named `waiting` (cutoff addendum
/// F11d, field finding S17): `waiting`, then while the custody gates are
/// live the recipients this node holds mail for ([`held_work`]), the mail
/// friends of `waiting` ([`mail_friends`]) and the friends this node
/// collects its own mail from ([`keepers_for_me`]), read with one book on
/// the blocking pool ([`work_set`]).
fn work_for(
    dd: PathBuf,
    local: [u8; 32],
    waiting: Vec<[u8; 32]>,
) -> BoxFuture<'static, Vec<[u8; 32]>> {
    Box::pin(async move {
        // The gates are read here, not in the blocking pool.
        if !raven_core::custody_gate::CustodyGates::current().live {
            return work_set(waiting, Vec::new(), Vec::new());
        }
        let letters = raven_core::friend_custody::letter_ops_served();
        let hops = crate::custody::forward_hops();
        let carry = crate::learning::carry_live();
        let asked = waiting.clone();
        let (held, friends) = internet_direct::blocking(move || {
            let now = raven_core::clock::now_ms();
            let mut friends = mail_friends(&dd, &local, &asked, carry, now);
            friends.extend(keepers_for_me(&dd, &local, now));
            Ok((held_work(&dd, letters, hops), friends))
        })
        .await
        .unwrap_or_default();
        work_set(waiting, held, friends)
    })
}

/// Blocking: the friends this node collects its own mail from, the custody
/// fetcher's targets ([`raven_core::custody_client::fetch_targets`]). The
/// fetcher's failed nearby dial only `want`s a keeper, which no user work
/// puts on air, so without this a recipient never advertised for the friend
/// holding mail for it (field test 2026-11-02, R7b: two open iPhones met only
/// once an unrelated send brought a link up). An unreadable book is nobody.
/// The caller checks the custody gates.
fn keepers_for_me(dd: &Path, local: &[u8; 32], now: u64) -> Vec<[u8; 32]> {
    raven_core::custody_client::fetch_targets(dd, local, now)
        .map(|targets| targets.into_iter().map(|(keeper, _)| keeper).collect())
        .unwrap_or_default()
}

/// Blocking: the mail friends of `waiting` (field finding S17): the deposit
/// custodians of each contact something waits for, the ones the outbox
/// would leave its mail with ([`raven_core::custody_client::deposit_custodians`],
/// or while carry choice is live, `carry`, every candidate it picks from,
/// as [`crate::custody::kick_carried`] reads them), from one read of the
/// book. A mail friend is a contact like any other here: advertising for it
/// lets the pipe come up on which the deposit goes (`Host::pipe_up`, then
/// `custody::kick_carried`). The caller checks the custody gates.
fn mail_friends(
    dd: &Path,
    local: &[u8; 32],
    waiting: &[[u8; 32]],
    carry: bool,
    now: u64,
) -> Vec<[u8; 32]> {
    let lists = if carry {
        raven_core::custody_client::custodian_candidates_for(dd, local, waiting, now)
    } else {
        raven_core::custody_client::deposit_custodians_for(dd, local, waiting, now)
    };
    friends_of(waiting, lists)
}

/// [`mail_friends`] from the custodian lists of `waiting` (in its order):
/// flattened, in order, each once, never a contact of `waiting` itself
/// (that one is work already).
fn friends_of(waiting: &[[u8; 32]], lists: Vec<Vec<([u8; 32], Option<u8>)>>) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    for (custodian, _) in lists.into_iter().flatten() {
        if !waiting.contains(&custodian) && !out.contains(&custodian) {
            out.push(custodian);
        }
    }
    out
}

/// The contacts something waits for (cutoff addendum F11d): the outbox's
/// (objects and owed ACKs, oldest first), then the recipients a custodian
/// holds mail for, then the mail friends of the outbox's contacts (S17:
/// [`mail_friends`]), each once, at most [`engine::MAX_KEYS`].
fn work_set(waiting: Vec<[u8; 32]>, held: Vec<[u8; 32]>, friends: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    for peer in waiting.into_iter().chain(held).chain(friends) {
        if out.len() == engine::MAX_KEYS {
            break;
        }
        if !out.contains(&peer) {
            out.push(peer);
        }
    }
    out
}

/// Admission key of a pipe's contact: a stable address in fd00::/8 (one /64
/// per contact) from its key, so the shared caps apply per contact (pattern
/// `p2p::admission_ip`). In memory only.
fn admission_ip(peer: &[u8; 32]) -> IpAddr {
    let mut o = [0u8; 16];
    o[0] = 0xfd;
    o[1..8].copy_from_slice(&peer[..7]);
    IpAddr::V6(Ipv6Addr::from(o))
}

static CAP_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(10));

/// Serve the Raven link the other side opened on the pipe knocked for
/// `peer` (RNL1 §7): the Internet direct responder with [`NEARBY_LINK`], the
/// contact gate, and `peer` as the only key it accepts, under
/// [`netutil::NEARBY_INBOUND`]. Over the caps the stream is dropped (its
/// channel FINs).
pub(crate) fn serve_inbound(
    data_dir: PathBuf,
    identity: Arc<Identity>,
    admission: &Arc<Admission>,
    peer: [u8; 32],
    stream: DuplexStream,
) {
    let limits = netutil::NEARBY_INBOUND;
    let Some(mut slot) = admission.try_admit(admission_ip(&peer)) else {
        netutil::log_limited(
            &CAP_LOG,
            "nearby",
            format_args!("link cap reached; refused a link"),
        );
        return;
    };
    let displaced = slot.displaced();
    let auth = slot.auth_flag();
    tokio::spawn(async move {
        let work = internet_direct::serve_inbound_on(
            NEARBY_LINK,
            data_dir,
            identity,
            stream,
            limits,
            &mut slot,
            None,
            Some(peer),
            None,
        );
        tokio::select! {
            done = tokio::time::timeout(limits.lifetime, work) => match done {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    // Before the link knew whom it served: about the pipe's
                    // radio source (Phase 6b S2, as the listeners do).
                    if !auth.load(Ordering::Relaxed) {
                        crate::security::inbound_refused(
                            admission_ip(&peer),
                            OutboxCarrier::Nearby,
                            &e,
                        );
                    }
                    netutil::log_inbound_failure("nearby inbound", e)
                }
                Err(_) => netutil::log_inbound_failure(
                    "nearby inbound",
                    "connection lifetime exceeded",
                ),
            },
            () = displaced.notified() => netutil::log_inbound_failure(
                "nearby inbound",
                displaced.why(),
            ),
        }
    });
}

// ── The carrier ─────────────────────────────────────────────────────────────

/// Dial a verified contact over nearby (`nearby_dial` is its route's dial
/// string, [`raven_core::outbox::nearby_dial_for`]), complete
/// Noise+RIH1+RLB1 on a pipe channel, send `frames`, collect the replies.
/// Nothing goes out for another contact, an unverified one, with the gate
/// closed or without an engine.
pub(crate) async fn dial(
    data_dir: &Path,
    nearby_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    dial_raced(data_dir, nearby_dial, expected_pub_hex, frames, None).await
}

/// [`dial`] as one of the outbox's direct paths in its Tor race
/// ([`crate::onion::race`]): with `race`, the link claims it before its
/// first frame, and one whose other side already won writes nothing.
pub(crate) async fn dial_raced(
    data_dir: &Path,
    nearby_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    race: Option<crate::onion::race::RaceTicket>,
) -> Result<Vec<Vec<u8>>, String> {
    NEARBY_LINK.require_live()?;
    let expected = internet_direct::parse_pub_hex(expected_pub_hex)?;
    if nearby_dial_peer(nearby_dial) != Some(expected) {
        return Err("nearby dial names another contact; nothing was sent".into());
    }
    let dd = data_dir.to_path_buf();
    let pinned =
        internet_direct::blocking(move || raven_core::contact_is_pinned(&dd, &expected)).await?;
    if !raven_core::carrier_allowed_for_contact(OutboxCarrier::Nearby, pinned) {
        return Err(format!(
            "{}: nearby delivery needs a verified contact; nothing was sent",
            raven_core::CONTACT_NOT_VERIFIED
        ));
    }
    let engine = current().ok_or_else(|| NEARBY_NOT_RUNNING.to_string())?;
    dial_on(&engine, data_dir, &expected, frames, race).await
}

/// [`dial_raced`] on `engine`, past the checks.
pub(crate) async fn dial_on(
    engine: &EngineHandle,
    data_dir: &Path,
    expected: &[u8; 32],
    frames: &[Vec<u8>],
    race: Option<crate::onion::race::RaceTicket>,
) -> Result<Vec<Vec<u8>>, String> {
    let pipe = match engine.pipe_for(*expected, CONNECT_BUDGET).await {
        Ok(pipe) => pipe,
        Err(e) => {
            // Something is queued that nearby could not carry now: the
            // contact may go into the advertising rotation (RNL1 §3). That
            // is this dial's frames, or what the outbox holds for the
            // contact (a horizon re-pair probes with no frames first; P5.28,
            // carrier_matrix C56). A route hints link with nothing waiting
            // carries nothing queued.
            if !frames.is_empty()
                || crate::outbox::waiting_peers(engine::MAX_KEYS).contains(expected)
            {
                engine.want(*expected);
            }
            return Err(e);
        }
    };
    let mut progress = DialProgress::new(NEARBY_LINK.wire, PRODUCTION_REPLY_WAITS);
    progress.collector.set_race(race);
    let outcome = tokio::time::timeout(
        DIAL_DEADLINE,
        internet_direct::dial_session_on(
            NEARBY_LINK,
            data_dir,
            move || {
                let pipe = pipe.clone();
                async move { pipe.open_channel().await }
            },
            expected,
            frames,
            None,
            &mut progress,
        ),
    )
    .await;
    let replies = match outcome {
        Ok(Ok(())) => Ok(progress.collector.into_replies()),
        Ok(Err(e)) => Err(e),
        Err(_) => progress.on_deadline("nearby", "the contact", DIAL_DEADLINE),
    };
    crate::clock_notes::dialled(expected, frames, &replies);
    let replies = replies?;
    crate::delivery_paths::note(
        expected,
        OutboxCarrier::Nearby,
        Some(DeliveryPath::Direct),
        frames,
        &replies,
    );
    Ok(replies)
}

/// The outbox's `AttemptCtx::connected` for nearby: a nearby route whose
/// contact has a pipe up now (it then goes first, plan §2.3 step 1). Only a
/// short lock; `false` without an engine and for other carriers.
pub(crate) fn route_connected(route: &OutboxRoute) -> bool {
    route.carrier == OutboxCarrier::Nearby
        && nearby_dial_peer(&route.dial)
            .is_some_and(|peer| current().is_some_and(|e| e.has_pipe(&peer)))
}

/// May the planners add `peer`'s nearby route
/// ([`raven_core::outbox::with_nearby_route`])? The engine runs (the gate is
/// open and the user enabled nearby), can go on the air (not from the
/// adapter's fixed public address, [`EngineHandle::may_go_on_air`]: a route
/// it cannot dial is never planned) and holds a pair key for the contact.
pub(crate) fn available(peer: &[u8; 32]) -> bool {
    current().is_some_and(|e| e.may_go_on_air() && e.has_keys(peer))
}

/// A custodian's nearby route for the custody planners (deposits and
/// fetches; owner decision O5-13: custody rides a nearby link, which is
/// local like LAN, under the existing custody gates), as `(planned,
/// dialled)`: when the engine holds a pair key for the custodian and the
/// custody and nearby gates admit it. Planned after the custodian's other
/// routes; `None` otherwise (and always while either gate is closed).
pub(crate) fn custodian_route(custodian: &[u8; 32]) -> Option<(OutboxRoute, OutboxRoute)> {
    use raven_core::custody_gate::{carrier_gates_now, custody_route_allowed, CustodyGates};
    if !available(custodian) {
        return None;
    }
    let route = OutboxRoute {
        carrier: OutboxCarrier::Nearby,
        dial: raven_core::outbox::nearby_dial_for(custodian),
    };
    custody_route_allowed(CustodyGates::current(), carrier_gates_now(), &route)
        .then(|| (route.clone(), route))
}

/// IPC `NearbyControl` (`raven nearby …`, a send's foreground): the nearby
/// status after the action, or a stable code and why. `enable` / `disable`
/// write node_policy's `nearby`, and `background_on` / `background_off` its
/// `nearby_background_mail` (`raven nearby background-mail`, owner decision
/// OD-C8; it never turns nearby itself on), the caller holding the policy
/// lock, and the service applies it at once; `on` / `off` / `foreground`
/// need the engine.
pub(crate) fn control(
    data_dir: &Path,
    action: &str,
    peer_pub_hex: Option<&str>,
    ttl_secs: Option<u32>,
) -> Result<NearbyStatusInfo, (&'static str, String)> {
    if !raven_core::nearby_live_enabled() {
        return Err(("NEARBY_HOLD", raven_core::NEARBY_HOLD.into()));
    }
    let peer = || {
        let hex = peer_pub_hex.ok_or((
            "NEARBY_BAD_REQUEST",
            format!("nearby {action} needs the contact's key"),
        ))?;
        internet_direct::parse_pub_hex(hex).map_err(|e| ("NEARBY_BAD_REQUEST", e))
    };
    let engine = || current().ok_or(("NEARBY_NOT_RUNNING", NEARBY_NOT_RUNNING.to_string()));
    match action {
        "enable" | "disable" => {
            let on = action == "enable";
            raven_core::node_policy::update_settings(data_dir, |p| p.nearby = Some(on))
                .map_err(|e| ("NEARBY_POLICY", e.to_string()))?;
            lock(&service().status).enabled = on;
            policy_changed();
        }
        "background_on" | "background_off" => {
            let on = action == "background_on";
            raven_core::node_policy::update_settings(data_dir, |p| {
                p.nearby_background_mail = Some(on);
            })
            .map_err(|e| ("NEARBY_POLICY", e.to_string()))?;
            lock(&service().status).background = on;
            if let Some(engine) = current() {
                engine.set_background_mail(on);
            }
            policy_changed();
        }
        "on" => {
            let (engine, peer) = (engine()?, peer()?);
            engine.on(peer, ttl_secs.map(|s| Duration::from_secs(u64::from(s))));
            lock(remembered()).on(peer, true);
        }
        "off" => {
            let (engine, peer) = (engine()?, peer()?);
            engine.off(peer);
            lock(remembered()).on(peer, false);
        }
        "foreground" => {
            let (engine, peer) = (engine()?, peer()?);
            let ttl = foreground_ttl();
            engine.foreground(peer, ttl);
            foreground_mail_friends(data_dir, &engine, peer, ttl);
        }
        "status" => {}
        _ => {
            return Err((
                "NEARBY_BAD_REQUEST",
                format!(
                    "unknown nearby action; one of {}",
                    raven_core::ipc::NEARBY_CONTROL_ACTIONS.join(", ")
                ),
            ))
        }
    }
    Ok(status_info(data_dir))
}

/// A send's foreground reaches the mail friends of `peer` too (field
/// finding S17): each gets the same foreground, so the rotation takes one
/// once the outbox's deposit with it over nearby failed (`want`, in
/// [`dial_on`]): RNL1 §3 (a), user work and still queued work, for the mail
/// friend. Without that a sender with Bluetooth only never advertises for
/// the friend that could carry its mail, and the friend, with no work for
/// the sender, never advertises for it. Only while the custody gates are
/// live (read here, not in the blocking pool); the book is read on the
/// blocking pool, so the IPC answer does not wait for it (the CLI's
/// foreground is best effort within 800 ms).
fn foreground_mail_friends(data_dir: &Path, engine: &EngineHandle, peer: [u8; 32], ttl: Duration) {
    if !raven_core::custody_gate::CustodyGates::current().live {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let carry = crate::learning::carry_live();
    let (dd, engine) = (data_dir.to_path_buf(), engine.clone());
    runtime.spawn_blocking(move || {
        let now = raven_core::clock::now_ms();
        for friend in mail_friends(&dd, &engine.me(), &[peer], carry, now) {
            engine.foreground(friend, ttl);
        }
    });
}

/// The nearby carrier for IPC `Status`: `None` while the gate is closed (a
/// release build's Status is what it was), else counts and states only.
pub(crate) fn status(data_dir: &Path) -> Option<NearbyStatusInfo> {
    raven_core::nearby_live_enabled().then(|| status_info(data_dir))
}

fn status_info(data_dir: &Path) -> NearbyStatusInfo {
    let (running, enabled, background, radio) = {
        let s = lock(&service().status);
        (s.running, s.enabled, s.background, s.radio)
    };
    // Without the service task (`raven-node ipc` alone) the file says.
    let (enabled, background_mail) = if running {
        (enabled, background)
    } else {
        raven_core::node_policy::nearby_settings(data_dir)
    };
    match current() {
        Some(engine) => NearbyStatusInfo {
            enabled,
            background_mail,
            ..engine.status()
        },
        None => NearbyStatusInfo {
            enabled,
            background_mail,
            gate_live: true,
            radio: radio.unwrap_or("off").into(),
            ..NearbyStatusInfo::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A service with the gate closed, or with nearby never enabled, creates
    /// no radio object (no Bluetooth prompt) and runs no engine. With the gate
    /// closed it reads nothing at all.
    #[tokio::test]
    async fn a_service_with_the_gate_closed_creates_no_radio() {
        let dir = tempfile::tempdir().unwrap();
        let before = RADIO_STARTS.load(Ordering::Relaxed);
        let task = tokio::spawn(run(dir.path().to_path_buf(), false));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "the service task never ends by itself");
        assert_eq!(RADIO_STARTS.load(Ordering::Relaxed), before, "no radio");
        assert!(current().is_none());
        task.abort();
        let _ = task.await;
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "nothing written"
        );
        if !raven_core::nearby_live_enabled() {
            assert_eq!(status(dir.path()), None, "Status as before the carrier");
            let err = dial(
                dir.path(),
                &raven_core::outbox::nearby_dial_for(&[7; 32]),
                &hex::encode([7u8; 32]),
                &[b"x".to_vec()],
            )
            .await
            .unwrap_err();
            assert_eq!(err, raven_core::NEARBY_HOLD);
            for action in raven_core::ipc::NEARBY_CONTROL_ACTIONS {
                let (code, why) = control(dir.path(), action, None, None).unwrap_err();
                assert_eq!(
                    (code, why.as_str()),
                    ("NEARBY_HOLD", raven_core::NEARBY_HOLD)
                );
            }
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }

    /// A radio that ends at once (the macOS helper that macOS stops with
    /// SIGABRT when Bluetooth is not allowed for RavenNearby, or the iOS
    /// in-process radio that stopped): its event queue closes, the engine
    /// ends, the service sees that ([`Running::ended`]) and stops the engine
    /// on its next turn. That stop must not poll the engine's task again:
    /// tokio panics with "JoinHandle polled after completion", which ended
    /// the whole service task on every radio that went away.
    #[tokio::test]
    async fn an_engine_whose_radio_ends_at_once_stops_without_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let ether = fake::Ether::new(fake::EtherParams::default());
        let (unused, _unused) = mpsc::channel(radio::EVENT_QUEUE);
        let radio = ether.radio("ends-at-once", unused);
        // The queue's only sender goes at once, as the helper's does.
        let (gone, events) = mpsc::channel(radio::EVENT_QUEUE);
        drop(gone);
        let identity = Arc::new(Identity::from_seed(&[0x5A; 32]));
        let host = Arc::new(NodeHost {
            data_dir: dir.path().to_path_buf(),
            identity: Arc::clone(&identity),
            admission: Admission::new(netutil::NEARBY_INBOUND),
        });
        let mut running = Running {
            engine: Some(engine::spawn(
                Box::new(radio),
                events,
                host,
                identity.public_key_bytes(),
                false,
                false,
            )),
        };
        tokio::time::timeout(Duration::from_secs(5), running.ended())
            .await
            .expect("the engine ends with its radio");
        assert!(
            running
                .engine
                .as_ref()
                .is_some_and(|(_, task)| task.is_finished()),
            "run's next turn stops it"
        );
        running.stop().await;
        assert!(running.engine.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), running.ended())
                .await
                .is_err(),
            "no engine: nothing ends"
        );
    }

    /// A nearby dial names exactly the contact it is for, and only a
    /// verified one: refused before any radio work (lab gate open only).
    #[tokio::test]
    async fn a_dial_for_another_or_unverified_contact_sends_nothing() {
        if !raven_core::nearby_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let bob = [0x42u8; 32];
        let err = dial(
            dir.path(),
            &raven_core::outbox::nearby_dial_for(&[0x43; 32]),
            &hex::encode(bob),
            &[],
        )
        .await
        .unwrap_err();
        assert!(err.contains("another contact"), "{err}");
        crate::outbox::test_rig::contacts(dir.path(), &bob, "", "", false);
        let err = dial(
            dir.path(),
            &raven_core::outbox::nearby_dial_for(&bob),
            &hex::encode(bob),
            &[],
        )
        .await
        .unwrap_err();
        assert!(err.starts_with(raven_core::CONTACT_NOT_VERIFIED), "{err}");
    }

    /// Review nearby-3: a radio that did not start because the Bluetooth
    /// software Raven needs is missing, outdated or not running (the macOS
    /// helper; BlueZ or the system bus) is not "no Bluetooth LE", and this
    /// profile's own state is not "Bluetooth off"; the log keeps the
    /// backend's reason. Every name is one IPC knows.
    #[test]
    fn start_errors_name_what_the_user_can_fix() {
        use radio::RadioState::{Unauthorized, Unsupported};
        let name = |s: RadioState| StartError::Radio(s).state_name();
        for why in [
            apple::NO_HELPER.to_string(),
            "the nearby helper did not start: No such file or directory (os error 2)".into(),
            "the nearby helper did not answer".into(),
            "the nearby helper speaks protocol 2, this raven-node 1: install the RavenNearby.app \
             of this release"
                .into(),
        ] {
            assert_eq!(
                name(Unsupported(why.clone())),
                "helper_unavailable",
                "{why}"
            );
        }
        assert_eq!(name(apple::ended_state(None)), "helper_unavailable");
        for why in [
            radio::BLUEZ_NOT_RUNNING.to_string(),
            radio::BLUEZ_STOPPED.into(),
            format!("{} (No such file or directory)", radio::NO_SYSTEM_BUS),
        ] {
            assert_eq!(name(Unsupported(why.clone())), "service_down", "{why}");
        }
        for why in [
            "the Bluetooth adapter has no Bluetooth LE",
            "no Bluetooth adapter",
            "this Mac has no Bluetooth LE",
            "BlueZ GetManagedObjects: org.freedesktop.DBus.Error.Failed",
        ] {
            assert_eq!(name(Unsupported(why.into())), "unsupported", "{why}");
        }
        assert_eq!(name(Unsupported(radio::NO_BACKEND.into())), "no_backend");
        assert_eq!(name(Unauthorized("refused".into())), "unauthorized");
        assert_eq!(name(RadioState::PoweredOff), "off");
        let local = StartError::Local("no identity".into());
        assert_eq!(local.state_name(), "local_state");
        assert_eq!(local.to_string(), "local state: no identity");
        assert_eq!(
            StartError::Radio(Unsupported(radio::BLUEZ_NOT_RUNNING.into())).to_string(),
            format!("radio service_down ({})", radio::BLUEZ_NOT_RUNNING)
        );
        for state in [
            "helper_unavailable",
            "service_down",
            "local_state",
            "unsupported",
            "no_backend",
            "unauthorized",
            "off",
            "powered_on",
        ] {
            assert!(
                raven_core::ipc::NEARBY_RADIO_STATES.contains(&state),
                "{state}"
            );
        }
    }

    /// F11d and S17: the outbox's contacts first, then the held ones, then
    /// the mail friends; each contact once, at most [`engine::MAX_KEYS`].
    #[test]
    fn work_set_keeps_the_outbox_first_and_each_contact_once() {
        let (a, b, c, d) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        assert_eq!(work_set(vec![b, a], vec![a, c], Vec::new()), vec![b, a, c]);
        assert_eq!(
            work_set(vec![b, a], vec![c], vec![d, a, c, d]),
            vec![b, a, c, d]
        );
        assert!(work_set(Vec::new(), Vec::new(), Vec::new()).is_empty());
        let many: Vec<[u8; 32]> = (0..engine::MAX_KEYS as u16 + 8)
            .map(|i| {
                let mut k = [0xF0u8; 32];
                k[..2].copy_from_slice(&i.to_be_bytes());
                k
            })
            .collect();
        let capped = work_set(vec![a], vec![b], many.clone());
        assert_eq!(capped.len(), engine::MAX_KEYS);
        assert_eq!(capped[..3], [a, b, many[0]]);
    }

    /// S17: the mail friends of the waiting contacts, in the order of the
    /// contacts and of each one's list, each once; never a contact that
    /// something waits for itself (it is work already), so a recipient is
    /// never listed as its own friend.
    #[test]
    fn mail_friends_follow_the_waiting_contacts_in_order() {
        let (a, b, c) = ([0xA1u8; 32], [0xB1u8; 32], [0xC1u8; 32]);
        let (f, g) = ([0xF1u8; 32], [0xF2u8; 32]);
        let lists = vec![
            vec![(f, None), (b, Some(1)), (a, None)],
            vec![(g, None), (f, None)],
            Vec::new(),
        ];
        assert_eq!(friends_of(&[a, b, c], lists), vec![f, g]);
        assert!(friends_of(&[a], vec![Vec::new()]).is_empty());
    }

    /// S17 with a profile: a waiting contact whose mail this node may leave
    /// with a friend it listed (the outbox's own custodian list) makes that
    /// friend work, after the contact; with the custody gates closed only
    /// the contact is.
    #[tokio::test]
    async fn a_waiting_contact_makes_its_mail_friend_work() {
        use raven_core::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
        let dir = tempfile::tempdir().unwrap();
        let (local, alice, bob, dave) = ([0xEE; 32], [0xA1; 32], [0xB1; 32], [0xD1; 32]);
        let row = |key: &[u8; 32], custodians: &[[u8; 32]]| {
            serde_json::json!({
                "pub_hex": hex::encode(key),
                "pinned": true,
                "custodians": custodians.iter().map(hex::encode).collect::<Vec<_>>(),
            })
        };
        let rows = vec![row(&alice, &[bob]), row(&bob, &[]), row(&dave, &[])];
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::Value::Array(rows).to_string(),
        )
        .unwrap();
        let work = |waiting: Vec<[u8; 32]>| work_for(dir.path().to_path_buf(), local, waiting);
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        let live = work(vec![alice]).await;
        let both = work(vec![dave, alice]).await;
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: false,
            wan: false,
        }));
        let closed = work(vec![alice]).await;
        set_custody_gates_for_this_thread(None);
        assert_eq!(live, [alice, bob]);
        assert_eq!(both, [dave, alice, bob]);
        assert_eq!(closed, [alice], "custody closed: no mail friend");
    }

    /// Field test 2026-11-02 (R7b): with nothing waiting and nothing held,
    /// the friend this node collects its own mail from is work too, so a
    /// recipient with background mail on advertises for its keeper and the
    /// keeper's scan finds it. Before, two open iPhones with mail held for
    /// one of them met only when an unrelated send brought a link up. With
    /// the custody gates closed nobody is.
    #[tokio::test]
    async fn a_friend_holding_mail_for_this_node_is_work() {
        use raven_core::custody_gate::{set_custody_gates_for_this_thread, CustodyGates};
        let dir = tempfile::tempdir().unwrap();
        let (local, alice, bob) = ([0xEE; 32], [0xA1; 32], [0xB1; 32]);
        let row = |key: &[u8; 32], custodians: &[[u8; 32]]| {
            serde_json::json!({
                "pub_hex": hex::encode(key),
                "pinned": true,
                "custodians": custodians.iter().map(hex::encode).collect::<Vec<_>>(),
            })
        };
        // Alice's mail for this node may wait with Bob.
        let rows = vec![row(&alice, &[bob]), row(&bob, &[])];
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::Value::Array(rows).to_string(),
        )
        .unwrap();
        let work = || work_for(dir.path().to_path_buf(), local, Vec::new());
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: true,
            wan: false,
        }));
        let live = work().await;
        set_custody_gates_for_this_thread(Some(CustodyGates {
            live: false,
            wan: false,
        }));
        let closed = work().await;
        set_custody_gates_for_this_thread(None);
        assert_eq!(live, [bob]);
        assert!(closed.is_empty(), "custody closed: no keeper");
    }

    /// Task 2 Q5: the contacts a background scan filter remembers across
    /// engines: pipes newest first, `raven nearby on` until `off`, each
    /// once and bounded.
    #[test]
    fn the_background_filter_remembers_recent_pipes_and_explicit_on() {
        let mut r = Remembered::default();
        let (a, b) = ([0xA1u8; 32], [0xB1u8; 32]);
        r.piped(a);
        r.piped(b);
        r.piped(a);
        assert_eq!(r.pipes, [a, b]);
        for i in 0..=REMEMBERED as u8 {
            r.piped([i; 32]);
        }
        assert_eq!(r.pipes.len(), REMEMBERED);
        assert_eq!(r.pipes[0], [REMEMBERED as u8; 32]);
        r.on(a, true);
        r.on(b, true);
        r.on(a, true);
        assert_eq!(r.on, [a, b]);
        r.on(a, false);
        assert_eq!(r.on, [b]);
    }

    /// F11d on a custodian (merge I.5): its custody objects' recipients,
    /// then its letters' (only while it serves the letter ops), then the
    /// handoff next hops; no store is nobody but the hops.
    #[test]
    fn held_work_counts_objects_letters_and_next_hops() {
        use raven_core::friend_custody::CustodyStore;
        let dir = tempfile::tempdir().unwrap();
        let (object_to, letter_to, hop) = ([0xB1; 32], [0xB2; 32], [0xB3; 32]);
        assert_eq!(held_work(dir.path(), true, vec![hop]), [hop]);
        let now = raven_core::clock::now_ms();
        let mut store = CustodyStore::open_or_create(dir.path()).unwrap();
        let depositor = [0xA1; 32];
        let expires = now + 3_600_000;
        store
            .deposit(
                &[1; 32], &object_to, &depositor, &[1; 16], &[0; 16], expires, now,
            )
            .unwrap();
        store
            .deposit_letter(&[2; 32], &letter_to, &depositor, &[2; 900], expires, now)
            .unwrap();
        drop(store);
        assert_eq!(
            held_work(dir.path(), true, vec![hop]),
            [object_to, letter_to, hop]
        );
        assert_eq!(held_work(dir.path(), false, Vec::new()), [object_to]);
    }

    /// The lab foreground TTL (P5.28) only shortens, only with the nearby
    /// lab switch, and a release build never reads it.
    #[test]
    fn the_lab_foreground_ttl_only_shortens_and_only_in_the_lab() {
        let five = Duration::from_millis(5_000);
        assert_eq!(foreground_ttl_from(true, Some("5000")), five);
        assert_eq!(foreground_ttl_from(true, Some(" 5000 ")), five);
        for v in [
            None,
            Some(""),
            Some("0"),
            Some("-1"),
            Some("x"),
            Some("900001"),
        ] {
            assert_eq!(foreground_ttl_from(true, v), FOREGROUND_TTL, "{v:?}");
        }
        assert_eq!(foreground_ttl_from(false, Some("5000")), FOREGROUND_TTL);
        if !cfg!(debug_assertions) || std::env::var(LAB_FOREGROUND_MS).is_err() {
            assert_eq!(foreground_ttl(), FOREGROUND_TTL);
        }
    }

    #[test]
    fn admission_ip_is_per_contact_and_local() {
        let a = admission_ip(&[1; 32]);
        assert_ne!(a, admission_ip(&[2; 32]));
        assert_eq!(netutil::admission_key(a), netutil::admission_key(a));
        assert_ne!(
            netutil::admission_key(a),
            netutil::admission_key(admission_ip(&[2; 32]))
        );
        let IpAddr::V6(v6) = a else { panic!("v6") };
        assert_eq!(v6.octets()[0], 0xfd);
    }
}
