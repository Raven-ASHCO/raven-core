//! Route hints (RRH1) on one Raven link: whether this side sends its own,
//! what it says, and what becomes of the peer's ([`raven_core::route_hints`],
//! `protocol/RAVEN_ROUTE_HINTS_V1.md`). Nothing happens unless route hints
//! are live on the link's carrier ([`live_on`]).
//!
//! - **Asked for on this connection (spec §3).** On Internet direct and the
//!   p2p link the peer's verified hello sets caps bit 8
//!   ([`raven_core::CAP_LINK_RRH1`]). On LAN the dialer's Noise XX message 3
//!   carries RLX1 with that bit, and only on a dial that will read (it has
//!   frames to send): a frame-less probe closes right after RLB1, and an RRH1
//!   it left unread could reset the link. It asks only when route hints are
//!   due on that dial ([`lan_asks`]). The LAN listener never signals in the
//!   handshake: its own RRH1 tells the dialer that it accepts one.
//! - **Telling again (spec §6.1).** A contact is told our RRH1 only when it
//!   was not told one since raven-node started, the generation or the pair
//!   seed entry moved, the LAN part adds something to what it was told over
//!   LAN, or [`REFRESH`] (30 min) went by ([`tell_due`]); an asked LAN
//!   listener answers all the same. E2 night: every custody poll and every
//!   incoming dial told and learned, about 4 times a minute per friend.
//! - **Order.** The listener sends its RRH1 right after its RLB1, before any
//!   reply. An Internet or p2p dialer sends its own before its frames, a LAN
//!   dialer as soon as the listener's arrives. One each way; a receiver
//!   applies at most [`MAX_RRH1_PER_LINK`], consumes later ones without
//!   effect, and a dialer ends its wait on a flood.
//! - **Never a reply, never dispatched.** [`LinkCtl::take`] consumes an RRH1
//!   only while route hints are live. With the gate off the frame reaches
//!   the dispatcher and closes the link, exactly as in older builds.
//! - **The snapshot (spec §6).** The full snapshot goes to a verified,
//!   unblocked contact; an unverified one on a LAN link from a local-network
//!   address gets only LAN_PORT (owner decision 1). LAN_PORT goes on LAN
//!   links only, and so do the same-LAN DIRECT entries, chosen by the
//!   contact's network, not by which of its addresses the link used
//!   ([`same_lan_listen`]). Hiding this node's IP (node policy or the contact's row)
//!   drops every DIRECT entry. While custody rides route hints
//!   ([`raven_core::custody_gate::custody_hints_live`], Phase 3, spec §12) a
//!   verified contact gets this node's CUSTODY_OFFER (`raven node custody`)
//!   and CUSTODIAN_TAGs naming its home custodians and the custodians listed
//!   for that contact, blinded for that contact; CUSTODIAN (0x05) is never
//!   sent.
//!   RELAY_OFFER (spec §11.4) names this node's friend relay to a contact it
//!   admits, while relay offers are live, the relay is up with an address
//!   worth offering and this node may show the contact its IP. Nothing
//!   learned from anyone is ever sent: `learned_routes.json` is read only
//!   for a contact's own PeerId that a p2p link proved (whether the friend
//!   relay admits it), never for what a snapshot says. NAT_CLASS (Phase 4,
//!   spec §13.1) names the p2p host's NAT mapping classes while the
//!   NAT_CLASS gate is live, to a contact this node shows its IP; with the
//!   gate closed the frame is byte for byte Phase 2's, and a NAT_CLASS
//!   received is not stored. PEER_SCHEDULE (Phase 4, spec §13.2) goes to
//!   every verified contact while the PeerId rotation gate is live: the
//!   capability always, the entries only while this node's rotation is on
//!   ([`own_schedule`]). A pinned contact's is kept in
//!   `peer_schedules.json` under the link's authenticated key, never under a
//!   PeerId; a snapshot of its without one forgets it. With the gate closed
//!   none is sent and none received is stored. PAIR_SEED (Phase 6b, spec
//!   §14, `crate::pair_seed`) goes to every verified contact while the
//!   pair-seed gate is live, and a verified contact's (or that its frame had
//!   none) feeds this pair's seeds; with the gate closed none is sent and
//!   nothing received is kept.
//! - **Generation.** [`GEN_STATE_FILE`] holds the generation, a digest of
//!   the inputs every verified contact shares and one digest per contact (at
//!   most [`MAX_TRACKED`], most recently used first). The generation moves,
//!   to `max(previous + 1, now_ms)`, exactly when a digest changes, and is
//!   saved before it is used. LAN_PORT and same-LAN DIRECT are per link and
//!   outside the digests: receivers replace their LAN part at an equal
//!   generation. The announcer also keeps the LAN listener's own address
//!   there: a listener that came back elsewhere moves the generation, so
//!   every contact is told its new port. The friend relay's offer is in
//!   both digests: the record in the shared one (a relay that comes up, goes
//!   down or moves is announced), the bytes a contact is sent in its own.
//! - **Announce links (spec §7).** When what every verified contact is told
//!   changes (the p2p host's relays or confirmed addresses, the LAN
//!   listener, a network change, hide-IP, custody, the friend relay's offer)
//!   or one contact's own inputs do, [`run_announcer`] opens links that
//!   carry only RRH1 to the contacts whose own RRH1 has not expired (they
//!   take one), and, while custody is live and M0 is on, first to the
//!   verified contacts with a noise pin it holds custody mail for (cutoff
//!   F8: a custodian that moved is fetched from at its new address):
//!   changes coalesced over [`SETTLE`], at most [`MAX_TARGETS`] contacts, one
//!   link per contact per [`PER_PEER_MIN`] at most, retried after 1, 10 and
//!   60 minutes; a contact is done once any link carried it the new
//!   generation. The debug `RAVEN_LAB_HINTS_NO_ANNOUNCE=1` keeps the
//!   announcer idle (links still carry RRH1), so a harness case can hold a
//!   contact's stale route until its next link ([`announcer_live`]).
//! - Logs carry counts only, at most one line of each kind per 30 s.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use futures::StreamExt;
use raven_core::custody_client::announced_custodian_keys;
use raven_core::ipc::RouteHintsStatus;
use raven_core::learned_routes::{self, Applied};
use raven_core::outbox::{
    contact_admission, is_local_network_ip, localize_lan_route, may_share_ip, ContactAdmission,
    ContactRoutes, OutboxRoute, LOCALIZE_RESOLVE_TIMEOUT,
};
use raven_core::p2p_route::{
    is_global_ip, libp2p_ed25519_public, normalize_peer_id, parse_via, peer_id_bytes, ViaAddr,
    PEER_ID_BYTES,
};
use raven_core::route_hints::{
    self, encode_offer, HintLink, NatClass, RelayOfferRecord, RouteHints, DIRECT_MAX_LEN,
    MAX_ADDRS_PER_RELAY, MAX_GLOBAL_DIRECT, MAX_LOCAL_DIRECT, MAX_RELAYS, MAX_RELAY_OFFERS,
    RRH1_DEFAULT_TTL_S,
};
use raven_core::security_events::Via;
use raven_core::{Identity, OutboxCarrier, CAP_LINK_PAD1, CAP_LINK_RRH1};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::netutil::{self, LogLimiter};
use crate::outbox::AttemptCtx;
use crate::p2p::OwnP2p;
use crate::security::LinkFeatures;

/// RRH1 frames a receiver applies per link; later ones are consumed without
/// effect (spec §2).
pub(crate) const MAX_RRH1_PER_LINK: u8 = 2;
/// The sender's generation state, in the data dir. Only raven-node writes it,
/// under its own lock: RMS1 kind 17 in a sealed profile (privacy pack PP.5;
/// it holds the LAN listener's address). An advisory file: unreadable reads
/// as no state, and is then never written over ([`load_gen`]).
pub(crate) const GEN_STATE_FILE: &str = raven_core::route_hints::ROUTE_HINTS_STATE_FILE;
/// Contacts whose digest and last sent generation are kept.
pub(crate) const MAX_TRACKED: usize = 256;

static TOLD_LOG: KeyedLog = KeyedLog::new();
static LEARNED_LOG: KeyedLog = KeyedLog::new();
static IGNORED_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(30));
static MALFORMED_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(30));
static SCHEDULE_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(30));
static ANNOUNCE_LOG: LogLimiter = LogLimiter::new(Duration::from_secs(30));

/// Since raven-node started: RRH1 frames sent, frames that changed what this
/// node plans for a contact, and frames not used (malformed, stale, or past
/// [`MAX_RRH1_PER_LINK`]).
static TOLD: AtomicU64 = AtomicU64::new(0);
static LEARNED: AtomicU64 = AtomicU64::new(0);
static IGNORED: AtomicU64 = AtomicU64::new(0);
/// The newest generation each contact was sent (the announcer's "done").
static SENT_GEN: Mutex<Option<HashMap<[u8; 32], u64>>> = Mutex::new(None);
/// [`GEN_STATE_FILE`] as last read or written, with its data dir.
static GEN: Mutex<Option<(PathBuf, GenState)>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
thread_local! {
    static LIVE_FOR_TEST: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    /// Kicks [`LinkCtl::take`] gave on this thread: a learned change that
    /// retried a contact's queue and woke its custody fetch at once.
    static KICKS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Route hints on `carrier` in this process
/// ([`route_hints::route_hints_live_on`]: the hints gate and the carrier's).
/// A test sets it for its own thread ([`LiveForTest`]).
pub(crate) fn live_on(carrier: OutboxCarrier) -> bool {
    #[cfg(test)]
    if let Some(live) = LIVE_FOR_TEST.with(std::cell::Cell::get) {
        return live;
    }
    route_hints::route_hints_live_on(carrier)
}

/// [`live_on`] for the current thread until dropped. A `#[tokio::test]`
/// runs its tasks on that thread, so both ends of a scripted link see it.
#[cfg(test)]
pub(crate) struct LiveForTest;

#[cfg(test)]
impl LiveForTest {
    pub(crate) fn set(live: bool) -> Self {
        LIVE_FOR_TEST.with(|c| c.set(Some(live)));
        Self
    }
}

#[cfg(test)]
impl Drop for LiveForTest {
    fn drop(&mut self) {
        LIVE_FOR_TEST.with(|c| c.set(None));
    }
}

/// The RLX1 payload of a LAN dialer's Noise XX message 3 (spec §3.2), only
/// on a dial that will read: RRH1 asked for while route hints are live on
/// LAN (`live`), PAD1 offered while link padding is (`pad`, Phase 6b
/// P6.34, `crate::link`). Empty otherwise, byte for byte what older builds
/// send. The link code calls [`lan_m3_payload_with`] (the tests this).
#[cfg(test)]
pub(crate) fn lan_m3_payload(live: bool, pad: bool, reads: bool) -> Vec<u8> {
    lan_m3_payload_with(live, pad, false, reads)
}

/// [`lan_m3_payload`] with the update exchange's bit 10 offered on a dial
/// that reads while it is active (`rup1`, Phase 6b P6.49,
/// `crate::update_exchange`).
pub(crate) fn lan_m3_payload_with(live: bool, pad: bool, rup1: bool, reads: bool) -> Vec<u8> {
    let mut caps = 0;
    if reads && live {
        caps |= CAP_LINK_RRH1;
    }
    if reads && pad {
        caps |= CAP_LINK_PAD1;
    }
    if reads && rup1 {
        caps |= raven_core::CAP_LINK_RUP1;
    }
    route_hints::rlx1_payload(caps)
}

/// Which end of the link this node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Dialer,
    Listener,
}

/// The link's two Raven identities: the peer's (authenticated by the link)
/// and ours, with our libp2p key (a relay offered to us under it is never
/// kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinkKeys {
    pub peer: [u8; 32],
    pub local: [u8; 32],
    pub local_p2p: [u8; 32],
}

impl LinkKeys {
    /// The keys of a link between `peer` and our `local` identity.
    pub(crate) fn new(peer: [u8; 32], local: &Identity) -> Self {
        Self {
            peer,
            local: local.public_key_bytes(),
            local_p2p: libp2p_ed25519_public(local),
        }
    }
}

/// Route hints on one link, built once both RLB1 offers are through. The link
/// code asks it for our RRH1 before it writes ([`Self::outgoing`]), says when
/// that was written ([`Self::written`]) and hands it every frame it reads
/// first ([`Self::take`]).
pub(crate) struct LinkCtl {
    data_dir: PathBuf,
    /// RRH1 on this link at all: route hints live on the carrier, and on a
    /// LAN dial, its message 3 asked for them.
    live: bool,
    carrier: OutboxCarrier,
    role: Role,
    /// Does the peer accept our RRH1? Known from its hello (Internet, p2p)
    /// or its message 3 (LAN listener); a LAN dialer learns it from the
    /// listener's RRH1.
    peer_accepts: Option<bool>,
    sent: bool,
    /// Our RRH1 went out on this link ([`Self::written`]).
    told_here: bool,
    received: u8,
    keys: LinkKeys,
    /// The peer's IP on a LAN link.
    peer_ip: Option<IpAddr>,
    /// The zone of an IPv6 link-local `peer_ip` ([`Self::with_peer_zone`]).
    peer_zone: Option<String>,
    /// Our end of a LAN dial's connection (is our listener reachable there?).
    local_addr: Option<SocketAddr>,
    /// p2p links: the connection's libp2p PeerId.
    link_peer_id: Option<String>,
    /// A dial that carries nothing but RRH1: it waits for the listener's.
    announce: bool,
    /// Our RRH1 as [`Self::outgoing`] built it, until the link code says it
    /// was written ([`Self::written`]): only then is the peer told.
    pending: Option<RouteHints>,
    /// The peer's link features this link showed, for its capability floor
    /// (Phase 6b P6.29, [`crate::security::link_features`]): read only
    /// while security events are live.
    features: Option<LinkFeatures>,
    /// A LAN dialer: the listener's features its frames showed so far (its
    /// RRH1, its first RPD1 frame: [`Self::pad_seen`]).
    seen: u32,
    /// Whether this link carried the RLK1 knock (Phase 6b P6.35,
    /// `crate::link_knock`), for the peer's capability floor: `None` when
    /// it cannot tell (p2p, nearby, the knock shut here).
    knock: Option<bool>,
    /// The update exchange on this link (RUP1, Phase 6b P6.49): off unless
    /// the link code gave it one ([`Self::with_update`]).
    update: crate::update_exchange::UpdateLink,
    /// What our dial carries ([`dial_purpose`]), for the log lines; `None`
    /// on a link the peer opened (its frames come after the route hints).
    purpose: Option<&'static str>,
}

impl LinkCtl {
    fn new(
        data_dir: &Path,
        carrier: OutboxCarrier,
        role: Role,
        keys: LinkKeys,
        live: bool,
    ) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            live,
            carrier,
            role,
            peer_accepts: None,
            sent: false,
            told_here: false,
            received: 0,
            keys,
            peer_ip: None,
            peer_zone: None,
            local_addr: None,
            link_peer_id: None,
            announce: false,
            pending: None,
            features: None,
            seen: 0,
            knock: None,
            update: crate::update_exchange::UpdateLink::off(),
            purpose: None,
        }
    }

    /// A LAN dial. `asked`: its message 3 asked for RRH1
    /// ([`lan_m3_payload`]); without that nothing is sent or consumed.
    pub(crate) fn lan_dialer(
        data_dir: &Path,
        keys: LinkKeys,
        local_addr: Option<SocketAddr>,
        peer_ip: Option<IpAddr>,
        asked: bool,
        announce: bool,
    ) -> Self {
        Self {
            peer_ip,
            local_addr,
            announce,
            ..Self::new(data_dir, OutboxCarrier::Lan, Role::Dialer, keys, asked)
        }
    }

    /// What this dial carries ([`dial_purpose`]): the hint log lines say it.
    pub(crate) fn with_purpose(mut self, purpose: &'static str) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// The LAN listener of a dialer at `source` whose message 3 payload was
    /// `m3`, parsed only now (after the contact gate).
    pub(crate) fn lan_listener(
        data_dir: &Path,
        keys: LinkKeys,
        source: Option<IpAddr>,
        m3: &[u8],
    ) -> Self {
        let live = live_on(OutboxCarrier::Lan);
        Self {
            peer_accepts: Some(live && route_hints::rlx1_caps(m3) & CAP_LINK_RRH1 != 0),
            peer_ip: source,
            features: crate::security::events_live()
                .then(|| LinkFeatures::Seen(route_hints::rlx1_caps(m3))),
            ..Self::new(data_dir, OutboxCarrier::Lan, Role::Listener, keys, live)
        }
    }

    /// Whether this link carried the RLK1 knock (`None`: it cannot tell),
    /// noted with the peer's link features ([`Self::note_features`]).
    pub(crate) fn with_knock(mut self, knock: Option<bool>) -> Self {
        self.knock = knock;
        self
    }

    /// A LAN dialer's link carried the knock or not (`knock`, the
    /// listener's proof; P6.35): noted at once, with what the listener
    /// showed so far, while security events are live. Nothing for `None`.
    pub(crate) fn knock_seen(&mut self, knock: Option<bool>) {
        self.knock = knock;
        if knock.is_some() {
            self.dialer_saw(0);
        }
    }

    /// The zone the LAN link's IPv6 link-local peer address came in on
    /// (`netutil::link_local_zone`): the LAN part learned on this link keeps
    /// it ([`HintLink::peer_zone`], Phase 3 P3.4).
    pub(crate) fn with_peer_zone(mut self, zone: Option<String>) -> Self {
        self.peer_zone = zone;
        self
    }

    /// The update exchange's part of this link (RUP1, Phase 6b P6.49): the
    /// link code reads and writes its frames through [`Self::update`].
    pub(crate) fn with_update(mut self, update: crate::update_exchange::UpdateLink) -> Self {
        self.update = update;
        self
    }

    /// The update exchange on this link.
    pub(crate) fn update(&mut self) -> &mut crate::update_exchange::UpdateLink {
        &mut self.update
    }

    /// Internet direct or the p2p link (`carrier`). `rrh1`: our hello set the
    /// RRH1 bit; `peer_caps`: the peer's verified hello caps.
    pub(crate) fn inet(
        data_dir: &Path,
        carrier: OutboxCarrier,
        role: Role,
        keys: LinkKeys,
        rrh1: bool,
        peer_caps: u32,
        link_peer_id: Option<String>,
    ) -> Self {
        Self {
            peer_accepts: Some(rrh1 && peer_caps & CAP_LINK_RRH1 != 0),
            link_peer_id,
            features: crate::security::events_live().then_some(LinkFeatures::Complete(peer_caps)),
            ..Self::new(data_dir, carrier, role, keys, rrh1)
        }
    }

    /// Our RRH1, once, when the peer said it accepts one (§3) and §6 gives
    /// this peer one. `None` otherwise. The link code writes it and then
    /// calls [`Self::written`]: the peer counts as told (the announcer's
    /// "done", spec §7) only once a link carried it.
    pub(crate) async fn outgoing(&mut self) -> Option<Vec<u8>> {
        if !self.live || self.sent || self.peer_accepts != Some(true) {
            return None;
        }
        self.sent = true;
        let (data_dir, ctx) = (self.data_dir.clone(), self.snap_ctx());
        let hints = tokio::task::spawn_blocking(move || snapshot_for(&data_dir, &ctx))
            .await
            .ok()
            .flatten()?;
        // A LAN listener answers every dialer that asked: its RRH1 is also
        // how that dialer learns it takes one (spec §3.3), and a dialer asks
        // only when it wants ours or has its own to tell ([`lan_asks`]).
        // Otherwise a contact is told only what it was not told lately
        // (spec §6, telling again).
        let answer = (self.role, self.carrier) == (Role::Listener, OutboxCarrier::Lan);
        let told = told_to(&self.data_dir, &self.keys.peer);
        if !answer && !tell_due(told.as_ref(), &hints, self.carrier, Instant::now()) {
            return None;
        }
        let frame = route_hints::encode(&hints);
        self.pending = Some(hints);
        Some(frame)
    }

    /// The RRH1 [`Self::outgoing`] returned was written on the link: the
    /// peer is told its generation. A write that failed never calls this,
    /// so the announcer tries that contact again.
    pub(crate) fn written(&mut self) {
        if let Some(hints) = self.pending.take() {
            self.told_here = true;
            note_told(
                &self.data_dir,
                &self.keys.peer,
                &hints,
                self.carrier,
                Instant::now(),
            );
            note_sent(&self.keys.peer, &hints, self.label());
        }
    }

    /// Who and how, for the log lines.
    fn label(&self) -> LinkLabel {
        LinkLabel {
            peer: self.keys.peer,
            carrier: self.carrier,
            role: self.role,
            purpose: self.purpose,
        }
    }

    /// `true`: `frame` is an RRH1 and was consumed here (stored when it is
    /// valid; never dispatched, never answered). When it changed what this
    /// node plans for the contact, what waits for it is retried now
    /// ([`crate::outbox::peer_routes_changed`]), and so is a fetch from it
    /// as a custodian ([`crate::custody::routes_changed`]); a changed custody
    /// offer retries what waits for anybody
    /// ([`crate::outbox::custodians_changed`]). Always `false` while
    /// route hints are off on this link.
    pub(crate) async fn take(&mut self, frame: &[u8]) -> bool {
        if !self.live || !route_hints::is_rrh1(frame) {
            return false;
        }
        self.received = self.received.saturating_add(1);
        // A LAN dialer: the listener spoke first, so it accepts ours.
        if self.peer_accepts.is_none() {
            self.peer_accepts = Some(true);
        }
        // A LAN dialer saw the listener's route hints: a feature its
        // capability floor keeps (Phase 6b P6.29).
        if self.received == 1 {
            self.dialer_saw(CAP_LINK_RRH1);
        }
        if self.received <= MAX_RRH1_PER_LINK {
            let (data_dir, frame, ctx) = (self.data_dir.clone(), frame.to_vec(), self.apply_ctx());
            let label = self.label();
            let applied = tokio::task::spawn_blocking(move || {
                apply_frame_as(&data_dir, &frame, &ctx, &label)
            })
            .await;
            if let Ok(Ok(Applied::Changed { .. } | Applied::Refreshed | Applied::Unchanged)) =
                applied
            {
                note_heard(&self.data_dir, &self.keys.peer, Instant::now());
            }
            // What we plan for the contact changed: retry what waits for it,
            // and fetch from it at once when it is a custodian of ours (one
            // that moved told us where it is now: cutoff F8).
            // At most once per contact per PER_PEER_MIN: a contact on two
            // addresses of one network changes its LAN part on every link,
            // and a kick per change opened the next link at once (E1).
            if let Ok(Ok(Applied::Changed { custody, .. })) = applied {
                // New routes told over another carrier than the LAN: the
                // contact moved, so its old LAN sighting gives the LAN no
                // head start over Tor any more (E2 r40).
                if self.carrier != OutboxCarrier::Lan {
                    crate::delivery_paths::forget_lan_sighting(&self.keys.peer);
                }
                if kick_due(&self.keys.peer, Instant::now()) {
                    #[cfg(test)]
                    KICKS.with(|k| k.set(k.get() + 1));
                    crate::outbox::peer_routes_changed(&self.keys.peer);
                    crate::custody::routes_changed(&self.keys.peer);
                    // A custody offer or announced custodians changed: the
                    // home custodians are chosen again, and a friend may
                    // now take what waits for anybody (Phase 3).
                    if custody {
                        crate::custody::offers_changed();
                        crate::outbox::custodians_changed();
                    }
                }
            }
        } else {
            IGNORED.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// A LAN dialer read the listener's first RPD1 frame (Phase 6b P6.34,
    /// `crate::link`): the listener pads, a feature its capability floor
    /// keeps (`Seen(CAP_LINK_PAD1)`, never a downgrade when missing).
    pub(crate) fn pad_seen(&mut self) {
        self.dialer_saw(CAP_LINK_PAD1);
    }

    /// A LAN dialer's link showed the listener's feature `cap`: noted with
    /// what it showed before, while security events are live.
    fn dialer_saw(&mut self, cap: u32) {
        if (self.role, self.carrier) != (Role::Dialer, OutboxCarrier::Lan)
            || !crate::security::events_live()
        {
            return;
        }
        self.seen |= cap;
        self.features = Some(LinkFeatures::Seen(self.seen));
        self.note_features();
    }

    /// More RRH1 frames came than a link carries: a dialer stops reading.
    pub(crate) fn flooded(&self) -> bool {
        self.received > MAX_RRH1_PER_LINK
    }

    /// The contact at the other end and the carrier: whose path a failed
    /// read on this link is about (Phase 6b, `crate::security`).
    pub(crate) fn link_of(&self) -> ([u8; 32], OutboxCarrier) {
        (self.keys.peer, self.carrier)
    }

    /// Should a dial without frames read the peer's RRH1 before it closes?
    /// An announce link does (LAN), and so does a dial whose peer's hello
    /// said it sends one (unread data at close can reset the connection).
    pub(crate) fn expects_peer_frame(&self) -> bool {
        self.live
            && self.received == 0
            && match (self.role, self.carrier) {
                (Role::Dialer, OutboxCarrier::Lan) => self.announce,
                (Role::Dialer, _) => self.peer_accepts == Some(true),
                (Role::Listener, _) => false,
            }
    }

    /// A p2p link: its libp2p PeerId carried the peer's Raven identity, so
    /// the PeerId the peer named over another link is proven
    /// ([`learned_routes::note_p2p_link`]).
    pub(crate) async fn note_link(&self) {
        if !self.live || self.carrier != OutboxCarrier::P2p {
            return;
        }
        let Some(link_peer_id) = self.link_peer_id.clone() else {
            return;
        };
        let (data_dir, peer) = (self.data_dir.clone(), self.keys.peer);
        let _ = tokio::task::spawn_blocking(move || {
            learned_routes::note_p2p_link(&data_dir, &peer, &link_peer_id, crate::now_ms())
        })
        .await;
    }

    /// The peer's link features this link showed go into its capability
    /// floor (Phase 6b P6.29, [`crate::security::link_features`]), on a
    /// blocking thread the link does not wait for (its timing stays as it
    /// was). The link code calls it once the peer is known to be a contact;
    /// a no-op while security events are shut.
    pub(crate) fn note_features(&self) {
        let Some(features) = self.features else {
            return;
        };
        let via = match self.role {
            Role::Dialer => Via::Dial(self.carrier),
            Role::Listener => Via::DirectLink(self.carrier),
        };
        let (data_dir, peer, knock) = (self.data_dir.clone(), self.keys.peer, self.knock);
        drop(tokio::task::spawn_blocking(move || {
            crate::security::link_features(&data_dir, &peer, features, knock, via)
        }));
    }

    fn snap_ctx(&self) -> SnapCtx {
        SnapCtx {
            carrier: self.carrier,
            role: self.role,
            keys: self.keys,
            peer_ip: self.peer_ip,
            peer_zone: self.peer_zone.clone(),
            local_ifs: if self.carrier == OutboxCarrier::Lan {
                raven_core::netifs::read().unwrap_or_default()
            } else {
                Vec::new()
            },
            local_addr: self.local_addr,
            listeners: if self.carrier == OutboxCarrier::Lan {
                crate::lan_direct::listener_addrs()
            } else {
                Vec::new()
            },
            own: crate::p2p::own_routes(),
            lab_local: raven_core::p2p_local_candidates_enabled(),
            custody_hints: raven_core::custody_gate::custody_hints_live(),
            reach_confirmed: crate::p2p::reach_confirmed(),
            offers_live: raven_core::relay_offers_live(),
            offer: crate::friend_relay::offer(&self.data_dir),
            nat_live: raven_core::nat_class_live_enabled(),
            schedule: own_schedule(),
            seeds_live: crate::pair_seed::live(),
            now_ms: crate::now_ms(),
        }
    }

    fn apply_ctx(&self) -> ApplyCtx {
        ApplyCtx {
            carrier: self.carrier,
            keys: self.keys,
            peer_ip: self.peer_ip,
            peer_zone: self.peer_zone.clone(),
            link_peer_id: self.link_peer_id.clone(),
            lab_local: raven_core::p2p_local_candidates_enabled(),
            offers_live: raven_core::relay_offers_live(),
            nat_live: raven_core::nat_class_live_enabled(),
            stun_live: raven_core::portmap_gate::stun_discovery_live_enabled(),
            rotation_live: raven_core::peer_rotation_live_enabled(),
            seeds_live: crate::pair_seed::live(),
            now_ms: crate::now_ms(),
        }
    }

    /// Whether our RRH1 went out and how many of the peer's came in.
    #[cfg(test)]
    pub(crate) fn counts(&self) -> (bool, u8) {
        (self.told_here, self.received)
    }
}

// ── Receiving (spec §5) ─────────────────────────────────────────────────────

/// The link an RRH1 came on.
struct ApplyCtx {
    carrier: OutboxCarrier,
    keys: LinkKeys,
    peer_ip: Option<IpAddr>,
    peer_zone: Option<String>,
    link_peer_id: Option<String>,
    lab_local: bool,
    /// [`raven_core::relay_offers_live`]: relay offers are kept.
    offers_live: bool,
    /// [`raven_core::nat_class_live_enabled`]: a NAT_CLASS is kept.
    nat_live: bool,
    /// [`raven_core::portmap_gate::stun_discovery_live_enabled`]: an
    /// INET_DIRECT address is kept (spec §13.3; security review 2026-10-29
    /// #9: kept while the gate was closed).
    stun_live: bool,
    /// [`raven_core::peer_rotation_live_enabled`]: a pinned contact's
    /// PEER_SCHEDULE is kept (and a snapshot without one forgets it).
    rotation_live: bool,
    /// [`crate::pair_seed::live`]: a pinned contact's PAIR_SEED (or that it
    /// had none) goes to its pair seeds (Phase 6b, spec §14).
    seeds_live: bool,
    now_ms: u64,
}

impl ApplyCtx {
    /// The link as [`route_hints::validate`] sees it. `local_relay`: our own
    /// friend relay's key ([`crate::friend_relay::own_relay_key`]).
    fn link<'a>(
        &'a self,
        contact: &'a ContactRoutes,
        local_relay: Option<[u8; 32]>,
    ) -> HintLink<'a> {
        HintLink {
            carrier: self.carrier,
            peer_ip: self.peer_ip,
            peer_zone: self.peer_zone.as_deref(),
            link_peer_id: self.link_peer_id.as_deref(),
            book_peer_id: contact.p2p.as_ref().map(|p| p.peer_id.as_str()),
            pinned: contact.pinned,
            sender: self.keys.peer,
            local: self.keys.local,
            local_p2p: self.keys.local_p2p,
            local_relay,
            lab_local: self.lab_local,
            lab_loopback: route_hints::lab_loopback_relays(),
        }
    }
}

/// [`apply_frame_as`] on a link the contact opened (tests).
#[cfg(test)]
fn apply_frame(data_dir: &Path, frame: &[u8], ctx: &ApplyCtx) -> Result<Applied, String> {
    let label = LinkLabel {
        peer: ctx.keys.peer,
        carrier: ctx.carrier,
        role: Role::Listener,
        purpose: None,
    };
    apply_frame_as(data_dir, frame, ctx, &label)
}

/// Blocking: check one RRH1 from a current, unblocked contact
/// ([`route_hints::decode`], [`route_hints::validate`]) and store what it
/// may keep ([`learned_routes::apply`]). Relay offers are kept only while
/// relay offers are live, and never one naming our own friend relay. The
/// "learned" log line names the link `label` describes.
fn apply_frame_as(
    data_dir: &Path,
    frame: &[u8],
    ctx: &ApplyCtx,
    label: &LinkLabel,
) -> Result<Applied, String> {
    let Some(mut hints) = route_hints::decode(frame) else {
        IGNORED.fetch_add(1, Ordering::Relaxed);
        netutil::log_limited(
            &IGNORED_LOG,
            "raven-node hints",
            "ignored a malformed route hint",
        );
        return Ok(Applied::Ignored);
    };
    if hints.dropped_phase4 > 0 {
        netutil::log_limited(
            &MALFORMED_LOG,
            "raven-node hints",
            format_args!(
                "RRH1_MALFORMED: dropped {} Phase 4 entr{} of a route hint",
                hints.dropped_phase4,
                if hints.dropped_phase4 == 1 {
                    "y"
                } else {
                    "ies"
                }
            ),
        );
    }
    if hints.dropped_pair_seed > 0 {
        netutil::log_limited(
            &MALFORMED_LOG,
            "raven-node hints",
            "RRH1_MALFORMED: dropped a pair seed entry of a route hint",
        );
    }
    if hints.dropped_onion > 0 {
        netutil::log_limited(
            &MALFORMED_LOG,
            "raven-node hints",
            "RRH1_MALFORMED: dropped an onion entry of a route hint",
        );
    }
    if hints.dropped_offers > 0 {
        netutil::log_limited(
            &MALFORMED_LOG,
            "raven-node hints",
            format_args!(
                "RRH1_MALFORMED: dropped {} relay offer record(s) of a route hint",
                hints.dropped_offers
            ),
        );
    }
    let ContactAdmission::Allowed(contact) = contact_admission(data_dir, &ctx.keys.peer) else {
        return Ok(Applied::Ignored);
    };
    if ctx.rotation_live {
        drop_foreign_schedule(data_dir, &ctx.keys.peer, &mut hints);
    }
    let local_relay = if hints.offers.is_empty() {
        None
    } else {
        crate::friend_relay::own_relay_key(data_dir)
    };
    let link = ctx.link(&contact, local_relay);
    let mut valid = route_hints::validate(&hints, &link);
    if !ctx.offers_live {
        valid.offers.clear();
    }
    // With the NAT_CLASS gate closed nothing of it is stored (Phase 2).
    if !ctx.nat_live {
        valid.nat_class = None;
    }
    // With the STUN discovery gate closed no INET_DIRECT address is stored
    // (spec §13.3).
    if !ctx.stun_live {
        valid.inet.clear();
    }
    // Not part of the learned routes: its own file (below).
    let schedule = valid.peer_schedule.take();
    // Phase 6b (spec §14): a verified contact's pair seed, or that it had
    // none, whatever the generation; its own file.
    if contact.pinned {
        crate::pair_seed::incoming(
            data_dir,
            ctx.seeds_live,
            &ctx.keys.local,
            &ctx.keys.peer,
            valid.pair_seed.take().as_ref(),
            ctx.now_ms,
        );
    }
    // The Tor onion carrier (§15): a verified contact's own binding, newest
    // kept in its book row (never an unsigned or foreign one: `validate`).
    if let Some(binding) = valid.onion.filter(|_| contact.pinned) {
        crate::onion::learn_binding(data_dir, &ctx.keys.peer, binding);
    }
    // The network a LAN part belongs to (its port and same-LAN addresses).
    let local_tag = if valid.local_direct.is_empty() && valid.lan_port.is_none() {
        None
    } else {
        raven_core::route_memory::egress_tag()
    };
    let applied = learned_routes::apply(
        data_dir,
        &ctx.keys.peer,
        &valid,
        &link,
        local_tag,
        ctx.now_ms,
    )?;
    if applied == Applied::Stale {
        IGNORED.fetch_add(1, Ordering::Relaxed);
    }
    if ctx.rotation_live && contact.pinned && !matches!(applied, Applied::Stale | Applied::Ignored)
    {
        note_schedule(data_dir, &ctx.keys.peer, schedule.as_ref(), ctx.now_ms);
    }
    if matches!(applied, Applied::Changed { .. }) {
        LEARNED.fetch_add(1, Ordering::Relaxed);
        LEARNED_LOG.log(
            label,
            format_args!(
                "learned a contact's routes (relays={}, direct={}, lan={}, custodians={}, \
                 offer={}, offers={})",
                relay_count(valid.relays.iter()),
                valid.direct.len() + valid.local_direct.len(),
                yes_no(valid.lan_port.is_some()),
                valid.custodians.len() + valid.custodian_tags.len(),
                yes_no(valid.custody_offer.is_some()),
                valid.offers.len()
            ),
        );
    }
    Ok(applied)
}

/// Review D-4: a PEER_SCHEDULE from the contact `peer` that names a PeerId
/// this node knows as another peer's (another contact's or a relay's,
/// [`raven_core::outbox::schedule_names_another_peer`]) is ignored whole:
/// its epoch keys come without proof, so it could not vouch for a P2P_ID
/// (the hints would be kept under that peer's PeerId) and it is not kept
/// (a later forget or block of `peer` would reach that peer). The frame
/// then counts as one without a schedule. `true` when it was dropped.
fn drop_foreign_schedule(data_dir: &Path, peer: &[u8; 32], hints: &mut RouteHints) -> bool {
    let foreign = hints.peer_schedule.as_ref().is_some_and(|s| {
        raven_core::outbox::schedule_names_another_peer(data_dir, &hex::encode(peer), s)
    });
    if foreign {
        hints.peer_schedule = None;
        netutil::log_limited(
            &SCHEDULE_LOG,
            "raven-node hints",
            "ignored a contact's PeerId schedule that names another peer's PeerId",
        );
    }
    foreign
}

/// Blocking: keep a pinned contact's PeerId schedule (RRH1 PEER_SCHEDULE,
/// Phase 4) under its authenticated key `peer`, never under a PeerId
/// ([`raven_core::peer_rotation::save_schedule`]); a snapshot without one
/// (its gate closed, or an older raven) forgets the one kept. Advisory: a
/// file that cannot be read or written is left, with a counts-only log.
fn note_schedule(
    data_dir: &Path,
    peer: &[u8; 32],
    schedule: Option<&route_hints::PeerSchedule>,
    now_ms: u64,
) {
    use raven_core::peer_rotation::{forget_schedule, save_schedule, ContactSchedule};
    let key = hex::encode(peer);
    let done = match schedule {
        Some(s) => save_schedule(data_dir, &key, &ContactSchedule::from_announced(s, now_ms)),
        None => forget_schedule(data_dir, &key),
    };
    if done.is_err() {
        netutil::log_limited(
            &SCHEDULE_LOG,
            "raven-node hints",
            "could not keep a contact's PeerId schedule",
        );
    }
}

// ── Sending (spec §6) ───────────────────────────────────────────────────────

/// What this node announces in PEER_SCHEDULE (Phase 4, spec §13.2) while
/// the PeerId rotation gate is live: that it can rotate and its epoch
/// length, and while the running p2p host uses epoch keys the epoch in use
/// and its schedule ([`crate::p2p::announced_schedule`]); with no host
/// running or the fixed key, the capability alone.
fn own_schedule() -> Option<route_hints::PeerSchedule> {
    raven_core::peer_rotation_live_enabled().then(|| {
        crate::p2p::announced_schedule().unwrap_or_else(|| {
            let len = raven_core::peer_rotation::epoch_len_s();
            route_hints::PeerSchedule::capability_only(u32::try_from(len).unwrap_or(u32::MAX))
        })
    })
}

/// What a snapshot depends on beyond the data dir, read when the link asks.
#[derive(Clone, Debug)]
struct SnapCtx {
    carrier: OutboxCarrier,
    role: Role,
    keys: LinkKeys,
    peer_ip: Option<IpAddr>,
    /// The zone of an IPv6 link-local `peer_ip`.
    peer_zone: Option<String>,
    /// This computer's interface addresses, on LAN links
    /// ([`same_lan_listen`]).
    local_ifs: Vec<raven_core::netifs::LocalAddr>,
    local_addr: Option<SocketAddr>,
    /// The LAN listener's addresses, IPv4 first (`auto` binds IPv4 and
    /// IPv6; [`crate::lan_direct::listener_addrs`]).
    listeners: Vec<SocketAddr>,
    /// The running p2p host's routes ([`crate::p2p::own_routes`]).
    own: Option<OwnP2p>,
    /// [`raven_core::p2p_local_candidates_enabled`]: loopback and private
    /// confirmed addresses count as global.
    lab_local: bool,
    /// Custody rides route hints
    /// ([`raven_core::custody_gate::custody_hints_live`]): CUSTODY_OFFER and
    /// CUSTODIAN_TAG entries.
    custody_hints: bool,
    /// This node's libp2p endpoint is confirmed reachable (reach class
    /// public or mapped, [`crate::p2p::reach_confirmed`]): the offer's
    /// REACHABLE bit.
    reach_confirmed: bool,
    /// [`raven_core::relay_offers_live`]: RELAY_OFFER entries.
    offers_live: bool,
    /// The friend relay's offer ([`crate::friend_relay::offer`]).
    offer: Option<crate::friend_relay::Offer>,
    /// [`raven_core::nat_class_live_enabled`]: the NAT_CLASS entry.
    nat_live: bool,
    /// [`own_schedule`]: the PEER_SCHEDULE entry (PeerId rotation gate).
    schedule: Option<route_hints::PeerSchedule>,
    /// [`crate::pair_seed::live`]: the PAIR_SEED entry (Phase 6b, spec §14).
    seeds_live: bool,
    now_ms: u64,
}

/// What one contact is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    /// A verified contact: everything.
    Full,
    /// An unverified contact on a LAN link from a local-network address:
    /// LAN_PORT only (owner decision 1).
    LanOnly,
}

/// Blocking: our RRH1 for the link `ctx` describes (spec §6), `None` when
/// this peer gets none (not a current, unblocked contact; unverified and not
/// on a local LAN link; the generation could not be saved). Reads the
/// contact book, the block list, the node policy and the generation state,
/// never what contacts told us (only, for the friend relay's offer, whether
/// a p2p link proved the PeerId the contact named: [`contact_peer_id`]).
fn snapshot_for(data_dir: &Path, ctx: &SnapCtx) -> Option<RouteHints> {
    let Plan {
        contact,
        scope,
        policy_hide,
        own,
        custody,
        tags,
        offers,
        onion,
        generation,
    } = plan_for(data_dir, ctx)?;
    let mut hints = RouteHints {
        generation,
        // A dropped home custodian is drained for as long as a contact may
        // still act on this TTL (`custody_home::DRAIN_MS` is built from it).
        ttl_s: RRH1_DEFAULT_TTL_S,
        lan_port: lan_port(ctx),
        ..RouteHints::default()
    };
    if scope == Scope::Full {
        if let Some(own) = own {
            hints.p2p_id = Some(own.id);
            hints.relays = own.relays;
            if !(policy_hide || contact.hide_ip) {
                // NAT_CLASS serves hole punching, which needs the IP too.
                hints.nat_class = own.nat;
                hints.direct = own.direct;
                // Auto-reach (spec §13.3): the Internet direct listener's
                // public address.
                hints.inet = own.inet;
                if ctx.carrier == OutboxCarrier::Lan {
                    let listen = ctx.own.as_ref().map_or(&[][..], |o| &o.listen[..]);
                    let link = LanLink {
                        peer_ip: ctx.peer_ip,
                        peer_zone: ctx.peer_zone.as_deref(),
                        local_ifs: &ctx.local_ifs,
                    };
                    for addr in same_lan_listen(listen, &own.peer_id, &link) {
                        if !hints.direct.contains(&addr) {
                            hints.direct.push(addr);
                        }
                    }
                }
            }
        }
        if let Some(custody) = &custody {
            hints.custody_offer = custody.offer;
            // Bit 0 HANDOFF_INBOX only; every other bit is sent as 0 (§4).
            hints.custodian_tags = tags;
        }
        hints.offers = offers;
        // PeerIds only, no address: whatever hide-IP says.
        hints.peer_schedule = ctx.schedule.clone();
        // The onion binding (§15): no IP either, so whatever hide-IP says.
        hints.onion = onion;
        // Phase 6b (spec §14): this pair's seed, a leader's proposal stored
        // before this frame goes.
        hints.pair_seed = crate::pair_seed::outgoing(
            data_dir,
            ctx.seeds_live,
            &ctx.keys.local,
            &ctx.keys.peer,
            ctx.now_ms,
        );
    }
    Some(hints)
}

/// What [`snapshot_for`] reads and decides before it writes a frame: who
/// the contact is and what it gets, and the generation of that (moved and
/// saved here when an input changed, [`generation_for`]). Nothing else is
/// stored: a LAN dial reads it before its handshake to tell whether this
/// contact has news coming ([`lan_asks`]).
struct Plan {
    contact: ContactRoutes,
    scope: Scope,
    policy_hide: bool,
    own: Option<OwnPart>,
    custody: Option<CustodyShared>,
    tags: Vec<([u8; 32], u8)>,
    offers: Vec<RelayOfferRecord>,
    /// This node's onion binding (§15), told to verified contacts.
    onion: Option<raven_core::onion::OnionBinding>,
    generation: u64,
}

/// Blocking: [`Plan`] for the link `ctx` describes; `None` as
/// [`snapshot_for`] says.
fn plan_for(data_dir: &Path, ctx: &SnapCtx) -> Option<Plan> {
    let ContactAdmission::Allowed(contact) = contact_admission(data_dir, &ctx.keys.peer) else {
        return None;
    };
    let scope = match (contact.pinned, ctx.carrier) {
        (true, _) => Scope::Full,
        (false, OutboxCarrier::Lan) if ctx.peer_ip.is_some_and(is_local_network_ip) => {
            Scope::LanOnly
        }
        _ => return None,
    };
    let policy_hide = raven_core::node_policy::load_policy(data_dir).hide_ip;
    let mut own = ctx.own.as_ref().and_then(|o| OwnPart::of(o, ctx.lab_local));
    if !ctx.nat_live {
        if let Some(own) = own.as_mut() {
            own.nat = None;
        }
    }
    // Custody (Phase 3): what every verified contact shares is read for
    // every snapshot (the shared digest must not depend on the scope); the
    // tags only for a verified contact.
    let custody = ctx
        .custody_hints
        .then(|| CustodyShared::read(data_dir, &ctx.keys.local, ctx.reach_confirmed, ctx.now_ms));
    // Each with its flags (§4): HANDOFF_INBOX (Phase 5) where this node's
    // store tags are registered (custody handoff spec §3.6).
    let tags: Vec<([u8; 32], u8)> = match &custody {
        Some(_) if scope == Scope::Full => {
            announced_custodian_keys(data_dir, &ctx.keys.local, &ctx.keys.peer, ctx.now_ms)
                .iter()
                .map(|c| {
                    (
                        route_hints::custodian_tag(&ctx.keys.local, &ctx.keys.peer, c),
                        custodian_flags(c),
                    )
                })
                .collect()
        }
        _ => Vec::new(),
    };
    let relay = ctx.offer.as_ref().filter(|_| ctx.offers_live);
    let offers = relay_offers(data_dir, ctx, &contact, scope, relay);
    // The Tor onion carrier (§15): this node's binding while its onion
    // service runs (shared by every verified contact).
    let onion = crate::onion::own_binding();
    let plain_tags: Vec<[u8; 32]> = tags.iter().map(|(t, _)| *t).collect();
    let own_tags = contact_tags(
        &plain_tags,
        custody.as_ref(),
        &ctx.keys.local,
        &ctx.keys.peer,
    );
    let generation = generation_for(
        data_dir,
        &global_digest(
            own.as_ref(),
            ctx.lab_local,
            ctx.custody_hints,
            policy_hide,
            relay.map(|r| &r.record),
            custody.as_ref(),
            ctx.schedule.as_ref(),
            onion.as_ref(),
        ),
        &ctx.keys.peer,
        &contact_digest(&contact, &own_tags, &tag_flags_input(&tags), scope, &offers),
        ctx.now_ms,
    )?;
    Some(Plan {
        contact,
        scope,
        policy_hide,
        own,
        custody,
        tags,
        offers,
        onion,
        generation,
    })
}

/// The custody inputs every verified contact's snapshot shares (Phase 3,
/// spec §12): this node's CUSTODY_OFFER, whether it uses friends as
/// mailboxes, and its home custodians (each contact's tags name them).
#[derive(Clone, Debug, PartialEq, Eq)]
struct CustodyShared {
    /// [`raven_core::custody_gate::offer_flags`] from `raven node custody`.
    offer: Option<u8>,
    /// [`raven_core::node_policy::NodePolicy::custody_use`].
    consent: Option<bool>,
    /// [`raven_core::custody_home::home`].
    home: Vec<[u8; 32]>,
}

impl CustodyShared {
    /// Blocking: read from the node policy and the home choice.
    fn read(data_dir: &Path, local: &[u8; 32], reach_confirmed: bool, now_ms: u64) -> Self {
        let policy = raven_core::node_policy::load_policy(data_dir);
        Self {
            offer: raven_core::custody_gate::offer_flags(policy.custody, reach_confirmed),
            consent: policy.custody_use,
            home: raven_core::custody_home::home(data_dir, local, now_ms),
        }
    }

    /// The digest bytes: the offer, the consent, then the home keys.
    fn bytes(&self) -> Vec<u8> {
        let option = |v: Option<u8>| v.map_or([0, 0], |v| [1, v]);
        let mut out = Vec::with_capacity(4 + 32 * self.home.len());
        out.extend(option(self.offer));
        out.extend(option(self.consent.map(u8::from)));
        for key in &self.home {
            out.extend(key);
        }
        out
    }
}

/// The tags in `tags` (sent to `peer`) that are this contact's own input:
/// those not naming a home custodian (the shared digest holds the home set,
/// so a new home custodian moves only that one, announced once to every
/// contact).
/// A CUSTODIAN_TAG's flags for custodian `c` (§4): HANDOFF_INBOX exactly
/// when the handoff gate is live and `c` answered this node's TAGS REGISTER
/// with OK within 24 h ([`crate::custody::handoff_inbox_ok`]); no other bit.
fn custodian_flags(c: &[u8; 32]) -> u8 {
    if crate::custody::handoff_inbox_ok(c) {
        route_hints::CUSTODIAN_FLAG_HANDOFF_INBOX
    } else {
        0
    }
}

/// The tag flags as a generation input: each flagged tag with its flags
/// (none flagged, always so before Phase 5: empty, so the digest is the
/// one an older build computed).
fn tag_flags_input(tags: &[([u8; 32], u8)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, flags) in tags.iter().filter(|(_, flags)| *flags != 0) {
        out.extend_from_slice(tag);
        out.push(*flags);
    }
    out
}

fn contact_tags(
    tags: &[[u8; 32]],
    custody: Option<&CustodyShared>,
    local: &[u8; 32],
    peer: &[u8; 32],
) -> Vec<[u8; 32]> {
    let home: Vec<[u8; 32]> = custody.map_or(Vec::new(), |c| {
        c.home
            .iter()
            .map(|h| route_hints::custodian_tag(local, peer, h))
            .collect()
    });
    tags.iter().filter(|t| !home.contains(t)).copied().collect()
}

/// RELAY_OFFER for this contact (spec §11.4): the friend relay's record
/// when relay offers are live and it offers one (`relay`), the contact gets
/// the full snapshot, this node may show it its IP
/// ([`raven_core::outbox::may_share_ip`]: hide my IP off for it and for
/// everyone) and the relay admits its PeerId ([`contact_peer_id`]). At most
/// [`MAX_RELAY_OFFERS`].
fn relay_offers(
    data_dir: &Path,
    ctx: &SnapCtx,
    contact: &ContactRoutes,
    scope: Scope,
    relay: Option<&crate::friend_relay::Offer>,
) -> Vec<RelayOfferRecord> {
    let Some(relay) = relay.filter(|_| scope == Scope::Full) else {
        return Vec::new();
    };
    if !may_share_ip(data_dir, &ctx.keys.peer) {
        return Vec::new();
    }
    contact_peer_id(data_dir, contact, &ctx.keys.peer, ctx.now_ms)
        .and_then(|peer_id| relay.offer_for(&peer_id))
        .into_iter()
        .take(MAX_RELAY_OFFERS)
        .collect()
}

/// The contact's libp2p PeerId as the friend relay's members know it: the
/// book's, or else the one its route hints named once a p2p link proved it
/// (the relay admits no other).
fn contact_peer_id(
    data_dir: &Path,
    contact: &ContactRoutes,
    peer: &[u8; 32],
    now_ms: u64,
) -> Option<String> {
    if let Some(p2p) = &contact.p2p {
        return Some(p2p.peer_id.clone());
    }
    learned_routes::learned(data_dir, peer, now_ms)?
        .p2p()
        .filter(|p| p.proven)
        .map(|p| p.peer_id)
}

/// LAN_PORT (LAN links only): the listener's own port, and on a dial only
/// when one of our listener's sockets answers on the address the dial left
/// from.
fn lan_port(ctx: &SnapCtx) -> Option<u16> {
    if ctx.carrier != OutboxCarrier::Lan {
        return None;
    }
    match ctx.role {
        Role::Listener => ctx.listeners.first().map(|l| l.port()).filter(|p| *p != 0),
        Role::Dialer => {
            let local = ctx.local_addr?;
            ctx.listeners
                .iter()
                .find_map(|listen| listen_port_for(*listen, local))
        }
    }
}

/// The LAN listener's port, when a connection that left from `local` shows
/// the peer an address the listener `listen` is bound to: the same IP, or
/// the unspecified address of the same family (a `[::]` listener on an IPv4
/// connection does not count: Windows sockets default to IPV6_V6ONLY). An
/// IPv4-mapped address counts as its IPv4 address.
fn listen_port_for(listen: SocketAddr, local: SocketAddr) -> Option<u16> {
    if listen.port() == 0 {
        return None;
    }
    let (bound, here) = (listen.ip().to_canonical(), local.ip().to_canonical());
    let reachable = if bound.is_unspecified() {
        bound.is_ipv4() == here.is_ipv4()
    } else {
        bound == here
    };
    reachable.then_some(listen.port())
}

/// The host's part of a snapshot, filtered as spec §6 says.
struct OwnPart {
    id: [u8; PEER_ID_BYTES],
    peer_id: String,
    /// At most [`MAX_RELAYS`] relays of [`MAX_ADDRS_PER_RELAY`] addresses.
    relays: Vec<String>,
    /// Confirmed global addresses (any, under `lab_local`), then the ones
    /// STUN discovery found (auto-reach): QUIC first, then IPv6 before IPv4
    /// within each, at most [`MAX_GLOBAL_DIRECT`] in all.
    direct: Vec<String>,
    /// The host's NAT mapping classes (NAT_CLASS, Phase 4), while the
    /// NAT_CLASS gate is live.
    nat: Option<NatClass>,
    /// Auto-reach: the Internet direct listener's public address
    /// (INET_DIRECT, spec §13.3), confirmed ones first.
    inet: Vec<route_hints::InetDirect>,
    /// Its listen addresses on the local network, the same-LAN DIRECT
    /// entries are chosen from ([`same_lan_listen`]): a generation input, so
    /// a host back on another port is told (spec §6.1: nobody is told again
    /// otherwise).
    listen_local: Vec<String>,
}

impl OwnPart {
    fn of(own: &OwnP2p, lab_local: bool) -> Option<Self> {
        let peer_id = normalize_peer_id(&own.peer_id).ok()?;
        let id = peer_id_bytes(&peer_id).ok()?;
        let mut relays: Vec<ViaAddr> = Vec::new();
        for text in &own.relays {
            let Ok(via) = parse_via(text) else {
                continue;
            };
            if via.peer_id == peer_id || relays.contains(&via) {
                continue;
            }
            let addrs = relays.iter().filter(|r| r.peer_id == via.peer_id).count();
            let full = if addrs == 0 {
                relay_count(relays.iter()) == MAX_RELAYS
            } else {
                addrs == MAX_ADDRS_PER_RELAY
            };
            if !full {
                relays.push(via);
            }
        }
        // Confirmed addresses first, then (auto-reach, spec §6) what STUN
        // discovery found that nobody confirmed yet; QUIC first and IPv6
        // before IPv4 within each.
        let mut direct: Vec<(bool, String, IpAddr)> = Vec::new();
        let found = own
            .confirmed
            .iter()
            .map(|t| (false, t))
            .chain(own.discovered.iter().map(|t| (true, t)));
        for (discovered, text) in found {
            let Some(ip) = direct_ip(text, &peer_id) else {
                continue;
            };
            if (lab_local || is_global_ip(ip)) && !direct.iter().any(|(_, t, _)| t == text) {
                direct.push((discovered, text.clone(), ip));
            }
        }
        direct.sort_by_key(|(discovered, text, ip)| {
            (*discovered, !text.contains("/quic-v1"), ip.is_ipv4())
        });
        direct.truncate(MAX_GLOBAL_DIRECT);
        let listen_local = own
            .listen
            .iter()
            .filter(|t| direct_ip(t, &peer_id).is_some_and(is_local_network_ip))
            .cloned()
            .collect();
        Some(Self {
            id,
            peer_id,
            relays: relays.into_iter().map(|v| v.text).collect(),
            direct: direct.into_iter().map(|(_, text, _)| text).collect(),
            nat: own.nat.map(NatClass::normalized),
            inet: {
                let mut inet: Vec<route_hints::InetDirect> = own
                    .inet
                    .iter()
                    .filter_map(|(text, confirmed)| {
                        let addr: SocketAddr = text.parse().ok()?;
                        (lab_local || is_global_ip(addr.ip())).then_some(route_hints::InetDirect {
                            flags: if *confirmed {
                                route_hints::INET_FLAG_CONFIRMED
                            } else {
                                0
                            },
                            addr,
                        })
                    })
                    .collect();
                inet.sort_by_key(|e| !e.confirmed());
                inet.truncate(route_hints::MAX_INET_DIRECT);
                inet
            },
            listen_local,
        })
    }
}

/// The IP of a DIRECT value a receiver accepts (spec §4): an IP literal and a
/// transport, no `/p2p`, so that with the sender's `/p2p` appended it passes
/// the `via=` grammar.
fn direct_ip(text: &str, peer_id: &str) -> Option<IpAddr> {
    if text.len() > DIRECT_MAX_LEN || !text.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    parse_via(&format!("{text}/p2p/{peer_id}")).ok()?;
    let mut parts = text.split('/').skip(1);
    match (parts.next(), parts.next()) {
        (Some("ip4" | "ip6"), Some(host)) => host.parse().ok(),
        _ => None,
    }
}

/// What a LAN link's same-LAN DIRECT entries are chosen by
/// ([`same_lan_listen`]).
struct LanLink<'a> {
    /// The contact's address on this link.
    peer_ip: Option<IpAddr>,
    /// The zone of an IPv6 link-local `peer_ip`: the interface it came in on.
    peer_zone: Option<&'a str>,
    /// This computer's interface addresses ([`raven_core::netifs::read`]).
    local_ifs: &'a [raven_core::netifs::LocalAddr],
}

/// Same /24 (IPv4) or /64 (IPv6), the receivers' same-LAN rule (spec §5.2).
fn same_net(a: IpAddr, b: IpAddr) -> bool {
    match (a.to_canonical(), b.to_canonical()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.segments()[..4] == b.segments()[..4],
        _ => false,
    }
}

/// Same-LAN DIRECT entries (LAN links only), at most [`MAX_LOCAL_DIRECT`]
/// in listen order: listen addresses on the local network in the /24
/// (IPv4) or /64 (IPv6) of the link's peer, or of an address of this
/// computer's interface on the contact's network (the one with an address
/// in the peer's /24 or /64; for an IPv6 link-local peer the interface of
/// its zone). A link to the contact's IPv6 address so carries what a link to
/// its IPv4 address does, whichever side dialled (E2 night: win-c told a
/// friend "direct=0" on its own custody dials and "direct=2" on the
/// friend's, all night). Receivers still keep only those in the link peer's
/// /24 or /64 (spec §5.2); their LAN part keeps the fuller set (§5.3).
fn same_lan_listen(listen: &[String], peer_id: &str, link: &LanLink<'_>) -> Vec<String> {
    let Some(peer) = link.peer_ip.map(|ip| ip.to_canonical()) else {
        return Vec::new();
    };
    let link_local = matches!(peer, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80);
    // The interfaces the contact is on.
    let on_its_net = |a: &raven_core::netifs::LocalAddr| {
        if link_local {
            link.peer_zone
                .is_some_and(|z| a.ifname == z || (a.index != 0 && z == a.index.to_string()))
        } else {
            same_net(a.ip, peer)
        }
    };
    let names: Vec<&str> = link
        .local_ifs
        .iter()
        .filter(|a| on_its_net(a))
        .map(|a| a.ifname.as_str())
        .collect();
    let mut nets = vec![peer];
    nets.extend(
        link.local_ifs
            .iter()
            .filter(|a| names.contains(&a.ifname.as_str()))
            // Every interface has its own fe80::/64: never a network by
            // itself.
            .filter(|a| !matches!(a.ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80))
            .map(|a| a.ip),
    );
    listen
        .iter()
        .filter(|text| {
            direct_ip(text, peer_id).is_some_and(|ip| {
                let ip = ip.to_canonical();
                is_local_network_ip(ip) && nets.iter().any(|n| same_net(*n, ip))
            })
        })
        .take(MAX_LOCAL_DIRECT)
        .cloned()
        .collect()
}

/// The inputs every verified contact's snapshot shares: the host's PeerId,
/// relays and confirmed addresses, `lab_local`, the node policy's hide-IP,
/// whether custody rides route hints and then its shared inputs (`custody`:
/// the custody offer, the mailbox consent, the home custodians), the friend
/// relay's offer record while relay offers are live (`offer`: what a member
/// is told; whether a contact is one is in its own digest), the host's
/// NAT_CLASS (Phase 4) while it is sent, this node's PEER_SCHEDULE
/// (Phase 4, `schedule`) while it is sent, and the host's listen addresses
/// on the local network (what same-LAN DIRECT entries are chosen from: a
/// contact is told again only when a generation moves, spec §6.1). Not the
/// LAN port or the listener's address (per link). With no offer, no
/// custody, no NAT_CLASS, no PEER_SCHEDULE and no local listen address the
/// digest is the one older builds made.
#[allow(clippy::too_many_arguments)]
fn global_digest(
    own: Option<&OwnPart>,
    lab_local: bool,
    custody_hints: bool,
    policy_hide: bool,
    offer: Option<&RelayOfferRecord>,
    custody: Option<&CustodyShared>,
    schedule: Option<&route_hints::PeerSchedule>,
    onion: Option<&raven_core::onion::OnionBinding>,
) -> String {
    let (peer_id, relays, direct) = own
        .map_or((String::new(), String::new(), String::new()), |o| {
            (o.peer_id.clone(), o.relays.join("\n"), o.direct.join("\n"))
        });
    let flags = [
        u8::from(lab_local),
        u8::from(policy_hide),
        u8::from(custody_hints),
    ];
    let offer = offer.map(encode_offer);
    let custody = custody.map(CustodyShared::bytes);
    let nat = own.and_then(|o| o.nat).map(|n| n.to_bytes());
    let mut parts: Vec<&[u8]> = vec![
        peer_id.as_bytes(),
        relays.as_bytes(),
        direct.as_bytes(),
        &flags,
    ];
    parts.extend(offer.as_deref());
    if let Some(custody) = &custody {
        // Tagged, so it never reads as a relay offer record.
        parts.push(b"custody");
        parts.push(custody);
    }
    // Tagged, so it never reads as an offer record.
    let nat_part = nat.map(|n| [&b"nat"[..], &n].concat());
    parts.extend(nat_part.as_deref());
    let schedule_part = schedule
        .and_then(route_hints::PeerSchedule::to_bytes)
        .map(|s| [&b"schedule"[..], &s].concat());
    parts.extend(schedule_part.as_deref());
    // Tagged, and only when there are any (the digest older builds made
    // otherwise): the local listen addresses a LAN link's same-LAN DIRECT
    // entries come from.
    let listen_part = own
        .filter(|o| !o.listen_local.is_empty())
        .map(|o| [&b"listen"[..], o.listen_local.join("\n").as_bytes()].concat());
    parts.extend(listen_part.as_deref());
    // Auto-reach, tagged and only when there is one: INET_DIRECT.
    let inet_part = own.filter(|o| !o.inet.is_empty()).map(|o| {
        let mut part = b"inet".to_vec();
        for e in &o.inet {
            part.extend_from_slice(&e.to_bytes());
            part.push(b'\n');
        }
        part
    });
    parts.extend(inet_part.as_deref());
    // Tagged, and only with one (the digest of before otherwise): this
    // node's onion binding (§15), so a new onion key is told to everyone.
    let onion_part = onion.map(|b| [&b"onion"[..], &b.to_bytes()].concat());
    parts.extend(onion_part.as_deref());
    route_hints::inputs_digest(&parts)
}

/// The inputs of one contact's snapshot: verified or not, its row's hide-IP,
/// the custodian tags that are its own ([`contact_tags`]: the custodians
/// listed for it), the scope, and the RELAY_OFFER records it is sent
/// (encoded; none leaves the digest as older builds made it).
fn contact_digest(
    contact: &ContactRoutes,
    custodians: &[[u8; 32]],
    tag_flags: &[u8],
    scope: Scope,
    offers: &[RelayOfferRecord],
) -> String {
    let flags = [
        u8::from(contact.pinned),
        u8::from(contact.hide_ip),
        u8::from(scope == Scope::Full),
    ];
    let custodians = custodians.concat();
    let offers: Vec<Vec<u8>> = offers.iter().map(encode_offer).collect();
    let mut parts: Vec<&[u8]> = vec![&flags, &custodians];
    parts.extend(offers.iter().map(Vec::as_slice));
    // A HANDOFF_INBOX flag that comes or goes moves the generation (only
    // when one is set: unchanged digests otherwise).
    if !tag_flags.is_empty() {
        parts.push(tag_flags);
    }
    route_hints::inputs_digest(&parts)
}

/// [`GEN_STATE_FILE`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct GenState {
    generation: u64,
    #[serde(default)]
    global: String,
    /// Most recently used first.
    #[serde(default)]
    contacts: Vec<ContactDigest>,
    /// The LAN listener's address when the announcer last looked
    /// ([`probe`]; empty: none), with a keyed digest of this computer's
    /// networks for a wildcard listener ([`lan_input`]). A plain digest an
    /// older build saved differs from the keyed one: one announce, once.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    lan: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ContactDigest {
    pub_hex: String,
    digest: String,
}

/// [`GEN_STATE_FILE`], sealed or plain: a missing file or plain bytes that
/// do not parse read as no state (and are replaced, as always); a sealed file
/// this process cannot open (the at-rest key not loaded yet, a changed byte)
/// is `Unreadable` and never replaced (the advisory-file rule: that would
/// destroy sealed data).
fn load_gen(data_dir: &Path) -> raven_core::at_rest::Advisory<GenState> {
    raven_core::at_rest::load_json_advisory(
        data_dir,
        &data_dir.join(GEN_STATE_FILE),
        raven_core::at_rest::Kind::RouteHintsState,
    )
}

/// Blocking: the generation of a snapshot made from `global` and `contact`
/// (digests) for `peer`. It moves to `max(previous + 1, now_ms)` when this
/// is the first one, the global digest changed, or `peer`'s recorded digest
/// changed (a contact seen for the first time is recorded as is), and the
/// state is saved before the generation is used. A global change is
/// announced to every contact that takes RRH1 ([`announce_all`]), a change
/// of `peer`'s own to it ([`announce_one`]). `None`: it could not be saved.
fn generation_for(
    data_dir: &Path,
    global: &str,
    peer: &[u8; 32],
    contact: &str,
    now_ms: u64,
) -> Option<u64> {
    let (generation, moved) =
        next_generation(data_dir, global, None, Some((peer, contact)), now_ms)?;
    match moved {
        Moved::Global => announce_all(generation),
        Moved::Contact => announce_one(*peer, generation),
        Moved::Nothing => {}
    }
    Some(generation)
}

/// What moved the generation ([`next_generation`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Moved {
    Nothing,
    /// An input every verified contact shares, the LAN listener's address
    /// (or the first generation).
    Global,
    /// Only the contact's own inputs.
    Contact,
}

/// Blocking: [`generation_for`]'s rule, for one contact's snapshot or (no
/// `contact`) for the announcer's look at the shared inputs alone
/// ([`probe`]), which also brings `lan`, the LAN listener's address and for
/// a wildcard one this computer's networks ([`lan_input`]): a change of it
/// moves the generation too ([`lan_moved`]). Announces nothing itself. The
/// digest of a contact that is no longer a current, unblocked contact
/// ([`raven_core::outbox::admitted_contact_keys`]) is dropped and the state
/// saved without it (storage rule: real erase); the announcer's look runs
/// at start and at least every [`TICK`].
fn next_generation(
    data_dir: &Path,
    global: &str,
    lan: Option<&str>,
    contact: Option<(&[u8; 32], &str)>,
    now_ms: u64,
) -> Option<(u64, Moved)> {
    let mut held = lock(&GEN);
    let state = match &mut *held {
        Some((dir, state)) if dir == data_dir => state,
        other => match load_gen(data_dir) {
            // Unreadable: not kept (it is read again next time, once the key
            // is loaded), and nothing is saved over it, so no generation
            // can be used.
            raven_core::at_rest::Advisory::Unreadable(why) => {
                raven_core::at_rest::note_skipped_write(data_dir, &why);
                return None;
            }
            read => {
                let state = read.into_loaded().unwrap_or_default();
                &mut other.insert((data_dir.to_path_buf(), state)).1
            }
        },
    };
    let mut next = state.clone();
    let lan_moved = lan.is_some_and(|lan| {
        let (moved, keep) = lan_moved(&next.lan, lan);
        next.lan = keep;
        moved
    });
    let global_moved = next.generation == 0 || next.global != global || lan_moved;
    next.global = global.to_string();
    let (mut contact_moved, mut known) = (false, true);
    if let Some((peer, digest)) = contact {
        let key = hex::encode(peer);
        let at = next.contacts.iter().position(|c| c.pub_hex == key);
        known = at.is_some();
        if let Some(i) = at {
            contact_moved = next.contacts.remove(i).digest != digest;
        }
        next.contacts.insert(
            0,
            ContactDigest {
                pub_hex: key,
                digest: digest.to_string(),
            },
        );
        next.contacts.truncate(MAX_TRACKED);
    }
    // A removed or blocked contact's key leaves the state. An unreadable
    // book keeps it as it is (no generation moves for that).
    let held = next.contacts.len();
    if let Ok(keys) = raven_core::outbox::admitted_contact_keys(data_dir) {
        next.contacts.retain(|c| keys.contains(&c.pub_hex));
    }
    let pruned = next.contacts.len() != held;
    let bump = global_moved || contact_moved;
    if bump {
        next.generation = next.generation.saturating_add(1).max(now_ms);
    }
    if bump || !known || pruned {
        raven_core::at_rest::store_json(
            data_dir,
            &data_dir.join(GEN_STATE_FILE),
            raven_core::at_rest::Kind::RouteHintsState,
            &next,
        )
        .ok()?;
    }
    *state = next;
    let moved = if global_moved {
        Moved::Global
    } else if contact_moved {
        Moved::Contact
    } else {
        Moved::Nothing
    };
    Some((state.generation, moved))
}

/// When a learned change last kicked each contact ([`kick_due`]).
static KICKED: Mutex<Option<HashMap<[u8; 32], Instant>>> = Mutex::new(None);

/// Whether a learned change may kick `peer` at `now` (retry what waits for
/// it, wake its custody fetch): not within [`PER_PEER_MIN`] of the last
/// kick, the spacing of announce links (spec §7). The routes are stored
/// from every frame all the same; the outbox and custody schedules still
/// run. `true` notes the kick.
fn kick_due(peer: &[u8; 32], now: Instant) -> bool {
    let mut kicked = lock(&KICKED);
    let kicked = kicked.get_or_insert_with(HashMap::new);
    if kicked
        .get(peer)
        .is_some_and(|at| now.saturating_duration_since(*at) < PER_PEER_MIN)
    {
        return false;
    }
    if kicked.len() >= MAX_TRACKED {
        kicked.retain(|_, at| now.saturating_duration_since(*at) < PER_PEER_MIN);
    }
    kicked.insert(*peer, now);
    true
}

// ── Telling again (spec §6) ─────────────────────────────────────────────────

/// A contact is told routes it already holds again at most this often, and
/// a LAN dialer asks a contact for its own again at most this often
/// ([`lan_asks`]): far inside the snapshot's TTL (72 h, spec §5.4), and
/// the receiver rewrites an unchanged snapshot at most hourly anyway
/// (`learned_routes`). E2 night: every link told and asked, about 4 times a
/// minute per friend with nothing changing all night.
pub(crate) const REFRESH: Duration = Duration::from_secs(30 * 60);

/// What one contact was last told ([`note_told`]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Told {
    generation: u64,
    at: Instant,
    /// The LAN part the last LAN link carried: LAN_PORT, the DIRECT
    /// entries, and when.
    lan: Option<(Option<u16>, Vec<String>, Instant)>,
    /// The PAIR_SEED entry (Phase 6b, spec §14), as told.
    seed: Option<raven_core::pair_seed::SeedEntry>,
}

/// Per data dir and contact (tests run many profiles in one process).
type PerContact<T> = Mutex<Option<HashMap<(PathBuf, [u8; 32]), T>>>;

/// What each contact was told last, since raven-node started.
static TOLD_TO: PerContact<Told> = Mutex::new(None);
/// When each contact's own route hints last came (a frame that was used).
static HEARD_FROM: PerContact<Instant> = Mutex::new(None);

fn told_to(data_dir: &Path, peer: &[u8; 32]) -> Option<Told> {
    lock(&TOLD_TO)
        .as_ref()?
        .get(&(data_dir.to_path_buf(), *peer))
        .cloned()
}

/// Keep `value` for (`data_dir`, `peer`), at most [`MAX_TRACKED`] (the
/// entry `age` says is oldest goes first).
fn keep<T>(
    map: &PerContact<T>,
    data_dir: &Path,
    peer: &[u8; 32],
    value: T,
    age: impl Fn(&T) -> Instant,
) {
    let mut held = lock(map);
    let held = held.get_or_insert_with(HashMap::new);
    let key = (data_dir.to_path_buf(), *peer);
    if !held.contains_key(&key) && held.len() >= MAX_TRACKED {
        if let Some(oldest) = held
            .iter()
            .min_by_key(|(_, v)| age(v))
            .map(|(k, _)| k.clone())
        {
            held.remove(&oldest);
        }
    }
    held.insert(key, value);
}

/// `peer` was told `hints` over `carrier` at `now`. A leader's outstanding
/// pair seed proposal in it (spec §14.3) wants the contact's ack: its own
/// RRH1 is asked for on the next LAN dial ([`lan_asks`]).
fn note_told(
    data_dir: &Path,
    peer: &[u8; 32],
    hints: &RouteHints,
    carrier: OutboxCarrier,
    now: Instant,
) {
    let lan = if carrier == OutboxCarrier::Lan {
        Some((hints.lan_port, hints.direct.clone(), now))
    } else {
        told_to(data_dir, peer).and_then(|t| t.lan)
    };
    let told = Told {
        generation: hints.generation,
        at: now,
        lan,
        seed: hints.pair_seed.clone(),
    };
    keep(&TOLD_TO, data_dir, peer, told, |t| t.at);
    if hints
        .pair_seed
        .as_ref()
        .is_some_and(|s| s.generation != s.acked)
    {
        if let Some(heard) = lock(&HEARD_FROM).as_mut() {
            heard.remove(&(data_dir.to_path_buf(), *peer));
        }
    }
}

/// `peer`'s route hints came at `now` and were used.
fn note_heard(data_dir: &Path, peer: &[u8; 32], now: Instant) {
    keep(&HEARD_FROM, data_dir, peer, now, |at| *at);
}

/// Tests: what `data_dir`'s contacts were told and when they were heard is
/// forgotten (a restart of its raven-node).
#[cfg(test)]
pub(crate) fn forget_told(data_dir: &Path) {
    if let Some(m) = lock(&TOLD_TO).as_mut() {
        m.retain(|(dir, _), _| dir != data_dir);
    }
    if let Some(m) = lock(&HEARD_FROM).as_mut() {
        m.retain(|(dir, _), _| dir != data_dir);
    }
}

/// Should a link over `carrier` carry `hints` to a contact that was last
/// told `told` (pure)? Yes when it never was, the generation or the pair
/// seed entry is another, the last telling is [`REFRESH`] old, or (LAN) the
/// LAN part adds a port or an address to the last one told over LAN, or
/// that one is [`REFRESH`] old. A LAN part that only lacks something told
/// before is not news: the receiver keeps the fuller one (spec §5.3).
fn tell_due(told: Option<&Told>, hints: &RouteHints, carrier: OutboxCarrier, now: Instant) -> bool {
    let Some(t) = told else {
        return true;
    };
    let stale = |at: Instant| now.saturating_duration_since(at) >= REFRESH;
    if t.generation != hints.generation || stale(t.at) || t.seed != hints.pair_seed {
        return true;
    }
    if carrier != OutboxCarrier::Lan {
        return false;
    }
    match &t.lan {
        None => true,
        Some((port, direct, at)) => {
            stale(*at)
                || hints.lan_port.is_some_and(|p| *port != Some(p))
                || hints.direct.iter().any(|d| !direct.contains(d))
        }
    }
}

/// Should a LAN dial to the contact `keys.peer` ask for route hints
/// (RLX1 bit 8 in its message 3, spec §3.2)? Only an asked listener sends
/// its RRH1, and only after it does may the dialer send its own (§3.3). So
/// it asks on an announce link (`announce`), when it holds no route hints
/// from the contact used in the last [`REFRESH`] (or its LAN part is older
/// than its snapshot: a newer one came over p2p), and when the contact has
/// news coming ([`tell_due`] before the link: the generation or the pair
/// seed entry moved since it was told, or that is [`REFRESH`] old). A dial
/// that does not ask carries no route hints either way: a custody fetch
/// every few minutes, a message, an ACK (E2 night). An unverified contact
/// is asked as before (its LAN_PORT depends on the link).
pub(crate) async fn lan_asks(data_dir: &Path, keys: LinkKeys, announce: bool) -> bool {
    if announce || !live_on(OutboxCarrier::Lan) {
        return announce;
    }
    let now = Instant::now();
    let stale = |at: Instant| now.saturating_duration_since(at) >= REFRESH;
    let heard = lock(&HEARD_FROM)
        .as_ref()
        .and_then(|m| m.get(&(data_dir.to_path_buf(), keys.peer)).copied());
    let Some(told) = told_to(data_dir, &keys.peer) else {
        return true;
    };
    if heard.is_none_or(stale) || stale(told.at) || told.lan.as_ref().is_none_or(|l| stale(l.2)) {
        return true;
    }
    // Its newest snapshot came over Internet or p2p: its LAN part (port,
    // same-LAN addresses) is older and only a LAN link renews it.
    let (dd, peer) = (data_dir.to_path_buf(), keys.peer);
    let behind = tokio::task::spawn_blocking(move || {
        learned_routes::lan_part_behind(&dd, &peer, crate::now_ms())
    })
    .await
    .unwrap_or(true);
    if behind {
        return true;
    }
    let ctx = SnapCtx {
        carrier: OutboxCarrier::Lan,
        role: Role::Dialer,
        keys,
        peer_ip: None,
        peer_zone: None,
        local_ifs: Vec::new(),
        local_addr: None,
        listeners: Vec::new(),
        own: crate::p2p::own_routes(),
        lab_local: raven_core::p2p_local_candidates_enabled(),
        custody_hints: raven_core::custody_gate::custody_hints_live(),
        reach_confirmed: crate::p2p::reach_confirmed(),
        offers_live: raven_core::relay_offers_live(),
        offer: crate::friend_relay::offer(data_dir),
        nat_live: raven_core::nat_class_live_enabled(),
        schedule: own_schedule(),
        seeds_live: crate::pair_seed::live(),
        now_ms: crate::now_ms(),
    };
    let dd = data_dir.to_path_buf();
    let news = tokio::task::spawn_blocking(move || {
        let plan = plan_for(&dd, &ctx)?;
        if plan.scope != Scope::Full {
            return None;
        }
        let (seed, propose) = crate::pair_seed::peek(
            &dd,
            ctx.seeds_live,
            &ctx.keys.local,
            &ctx.keys.peer,
            ctx.now_ms,
        );
        Some(plan.generation != told.generation || seed != told.seed || propose)
    })
    .await
    .ok()
    .flatten();
    // Not known (not a verified contact, the generation could not be
    // saved): asked, as before.
    news.unwrap_or(true)
}

fn note_sent(peer: &[u8; 32], hints: &RouteHints, label: LinkLabel) {
    TOLD.fetch_add(1, Ordering::Relaxed);
    {
        let mut sent = lock(&SENT_GEN);
        let sent = sent.get_or_insert_with(HashMap::new);
        if !sent.contains_key(peer) && sent.len() >= MAX_TRACKED {
            if let Some(oldest) = sent.iter().min_by_key(|(_, g)| **g).map(|(k, _)| *k) {
                sent.remove(&oldest);
            }
        }
        let newest = sent.entry(*peer).or_insert(0);
        *newest = (*newest).max(hints.generation);
    }
    TOLD_LOG.log(&label, format_args!("{}", told_line(hints)));
}

/// The counts-only line for routes we told a contact: what kinds went, never
/// an address or an onion key (`onion=yes`: our signed onion binding, RRH1
/// ONION, was in it).
fn told_line(hints: &RouteHints) -> String {
    let relays: Vec<ViaAddr> = hints
        .relays
        .iter()
        .filter_map(|r| parse_via(r).ok())
        .collect();
    format!(
        "told a contact our routes (relays={}, direct={}, lan={}, offers={}, onion={})",
        relay_count(relays.iter()),
        hints.direct.len(),
        yes_no(hints.lan_port.is_some()),
        hints.offers.len(),
        yes_no(hints.onion.is_some())
    )
}

/// Who a hint log line is about and how (E1: "told a contact our routes
/// ... (and 62 more like it in the last 30s)" named neither, so a burst
/// could not be traced): the contact's short tag (never its key or
/// address, [`netutil::link_tag`]), the carrier, which side opened the
/// link, and what our own dial carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinkLabel {
    peer: [u8; 32],
    carrier: OutboxCarrier,
    role: Role,
    purpose: Option<&'static str>,
}

impl LinkLabel {
    /// `contact #3d74, lan, we dialled (custody)` / `contact #3d74, p2p, it
    /// dialled`.
    fn words(&self) -> String {
        let carrier = match self.carrier {
            OutboxCarrier::Lan => "lan",
            OutboxCarrier::Internet => "internet",
            OutboxCarrier::P2p => "p2p",
            OutboxCarrier::Nearby => "nearby",
            OutboxCarrier::Onion => "onion",
        };
        let side = match (self.role, self.purpose) {
            (Role::Dialer, Some(purpose)) => format!("we dialled ({purpose})"),
            (Role::Dialer, None) => "we dialled".to_owned(),
            (Role::Listener, _) => "it dialled".to_owned(),
        };
        format!(
            "contact {}, {carrier}, {side}",
            netutil::link_tag(&self.peer)
        )
    }
}

/// What a dial of ours carries, in a word for the hint log lines: its
/// first frame's kind (a message, an ACK, custody, the update exchange),
/// `announce` for a LAN link that carries route hints alone, `no frames`
/// for any other dial without frames (an Internet or p2p announce link or
/// probe).
pub(crate) fn dial_purpose(frames: &[Vec<u8>], announce: bool) -> &'static str {
    let Some(first) = frames.first() else {
        return if announce { "announce" } else { "no frames" };
    };
    if raven_core::friend_custody::is_rfc1(first) {
        return "custody";
    }
    if first.starts_with(raven_core::update_exchange::RUP1_MAGIC) {
        return "update";
    }
    match raven_core::envelope::Envelope::unpack(first).map(|e| e.env_type) {
        Some(t) if t == raven_core::envelope::EnvType::Message as u8 => "message",
        Some(t) if t == raven_core::envelope::EnvType::Ack as u8 => "ack",
        Some(_) => "envelope",
        None => "other",
    }
}

/// One line per kind (told, learned) for each contact, carrier, side and
/// purpose ([`LinkLabel`]) per 30 s, with how many more like it came since
/// its last line; at most [`KEYED_LOG_MAX`] of them at a time (the rest
/// share one).
pub(crate) struct KeyedLog {
    state: Mutex<Option<HashMap<String, LabelCount>>>,
}

/// One label's: when its last line was written (`None`: never), and the
/// events since.
type LabelCount = (Option<Instant>, u64);

/// Labels a [`KeyedLog`] keeps apart at once.
const KEYED_LOG_MAX: usize = 64;
/// One line per label per this.
pub(crate) const KEYED_LOG_WINDOW: Duration = Duration::from_secs(30);

impl KeyedLog {
    pub(crate) const fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    fn log(&self, label: &LinkLabel, what: std::fmt::Arguments<'_>) {
        let words = label.words();
        if let Some(n) = self.hit(&words, Instant::now()) {
            let more = if n > 1 {
                format!(
                    " (and {} more like it in the last {}s)",
                    n - 1,
                    KEYED_LOG_WINDOW.as_secs()
                )
            } else {
                String::new()
            };
            eprintln!("raven-node hints: {what}; {words}{more}");
        }
    }

    /// Count one event for `key` at `now` (as [`LogLimiter`] does for one
    /// kind). `Some(n)`: write a line now; `n` events happened for it since
    /// its previous line (this one included).
    pub(crate) fn hit(&self, key: &str, now: Instant) -> Option<u64> {
        let mut state = lock(&self.state);
        let map = state.get_or_insert_with(HashMap::new);
        let mut key = key;
        if !map.contains_key(key) && map.len() >= KEYED_LOG_MAX {
            // Labels whose window ran out with nothing waiting go first.
            map.retain(|_, (at, n)| {
                *n > 0 || at.is_some_and(|at| now.saturating_duration_since(at) < KEYED_LOG_WINDOW)
            });
            if map.len() >= KEYED_LOG_MAX {
                key = "others";
            }
        }
        let (last, count) = map.entry(key.to_owned()).or_insert((None, 0));
        *count += 1;
        if last.is_some_and(|at| now.saturating_duration_since(at) < KEYED_LOG_WINDOW) {
            return None;
        }
        *last = Some(now);
        Some(std::mem::take(count))
    }
}

/// The newest generation `peer` was sent since raven-node started.
pub(crate) fn sent_generation(peer: &[u8; 32]) -> Option<u64> {
    lock(&SENT_GEN).as_ref()?.get(peer).copied()
}

/// Distinct relays among relay addresses.
fn relay_count<'a>(relays: impl Iterator<Item = &'a ViaAddr>) -> usize {
    let mut seen: Vec<&str> = Vec::new();
    for via in relays {
        if !seen.contains(&via.peer_id.as_str()) {
            seen.push(&via.peer_id);
        }
    }
    seen.len()
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// ── Announcing (spec §7) ────────────────────────────────────────────────────

/// Changes are coalesced over this (a re-reservation, a UPnP mapping, a
/// network change come in bursts).
const SETTLE: Duration = Duration::from_secs(10);
/// With no change the announcer looks again this often (its own inputs, the
/// retries, the gate).
const TICK: Duration = Duration::from_secs(30);
/// A contact not told yet is dialled again this long after it was first
/// due, then dropped.
const RETRY: [Duration; 3] = [
    Duration::from_secs(60),
    Duration::from_secs(600),
    Duration::from_secs(3600),
];
/// Contacts waiting to be told, at most (held recipients, then the newest
/// RRH1 senders, first).
const MAX_TARGETS: usize = 64;
/// One announce link per contact at most this often.
const PER_PEER_MIN: Duration = Duration::from_secs(60);
/// Announce links open at once at most.
const AT_ONCE: usize = 4;

/// Wakes the announcer: this node's own routes changed
/// ([`own_changed`]), or a link moved the generation.
fn changed() -> &'static Notify {
    static CHANGED: OnceLock<Notify> = OnceLock::new();
    CHANGED.get_or_init(Notify::new)
}

/// Something every verified contact is told may have changed: the p2p
/// host's relays or addresses, the LAN listener (bound or gone), this
/// machine's network, the friend relay's offer. The announcer looks after
/// [`SETTLE`].
pub(crate) fn own_changed() {
    changed().notify_one();
}

/// What [`generation_for`] asked the announcer to tell.
#[derive(Debug, Default)]
struct Pending {
    /// Every contact that takes RRH1: this generation (or a newer one).
    all: Option<u64>,
    /// These contacts: their own inputs changed at that generation.
    one: Vec<([u8; 32], u64)>,
}

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    /// What this thread asked the announcer to tell, in order: `None` for
    /// every contact, or one contact (tests; the announcer's own queue is
    /// process-wide).
    static ANNOUNCED: std::cell::RefCell<Vec<(Option<[u8; 32]>, u64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn announce_all(generation: u64) {
    #[cfg(test)]
    ANNOUNCED.with(|a| a.borrow_mut().push((None, generation)));
    {
        let mut pending = lock(&PENDING);
        let pending = pending.get_or_insert_with(Pending::default);
        pending.all = pending.all.max(Some(generation));
    }
    changed().notify_one();
}

fn announce_one(peer: [u8; 32], generation: u64) {
    #[cfg(test)]
    ANNOUNCED.with(|a| a.borrow_mut().push((Some(peer), generation)));
    {
        let mut pending = lock(&PENDING);
        let pending = pending.get_or_insert_with(Pending::default);
        pending.one.retain(|(p, _)| *p != peer);
        pending.one.insert(0, (peer, generation));
        pending.one.truncate(MAX_TARGETS);
    }
    changed().notify_one();
}

fn take_pending() -> Pending {
    lock(&PENDING).take().unwrap_or_default()
}

/// One contact still to be told.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    peer: [u8; 32],
    /// Done once a link carried it at least this generation.
    generation: u64,
    /// When it became due: its retries count from here.
    since: Instant,
    /// Announce links tried so far.
    tries: usize,
}

/// Who the announcer still has to tell, and when (pure: the loop feeds it
/// the time and what links sent).
#[derive(Debug, Default)]
struct Schedule {
    /// Newest first, at most [`MAX_TARGETS`].
    targets: Vec<Target>,
    /// When each contact last got an announce link (at most one per
    /// [`PER_PEER_MIN`]).
    last_dial: HashMap<[u8; 32], Instant>,
}

impl Schedule {
    /// Tell `peers` about `generation` from `now` on, ahead of the others.
    /// A contact already waiting starts over at the newer generation.
    fn add(&mut self, generation: u64, peers: &[[u8; 32]], now: Instant) {
        for peer in peers.iter().rev() {
            let generation = self
                .targets
                .iter()
                .find(|t| t.peer == *peer)
                .map_or(generation, |t| t.generation.max(generation));
            self.targets.retain(|t| t.peer != *peer);
            self.targets.insert(
                0,
                Target {
                    peer: *peer,
                    generation,
                    since: now,
                    tries: 0,
                },
            );
        }
        self.targets.truncate(MAX_TARGETS);
    }

    /// The contacts to open an announce link to now. A contact that `sent`
    /// says got its generation is done; one is due at once, then
    /// [`RETRY`] after that, never twice within [`PER_PEER_MIN`]; one whose
    /// last retry went by is dropped.
    fn due(&mut self, now: Instant, sent: impl Fn(&[u8; 32]) -> Option<u64>) -> Vec<[u8; 32]> {
        let Self { targets, last_dial } = self;
        targets
            .retain(|t| sent(&t.peer).is_none_or(|g| g < t.generation) && t.tries <= RETRY.len());
        let mut out = Vec::new();
        for t in targets.iter_mut() {
            let at = match t.tries {
                0 => t.since,
                n => t.since + RETRY[n - 1],
            };
            let spaced = last_dial
                .get(&t.peer)
                .is_none_or(|last| now.saturating_duration_since(*last) >= PER_PEER_MIN);
            if now >= at && spaced {
                t.tries += 1;
                last_dial.insert(t.peer, now);
                out.push(t.peer);
            }
        }
        // Bounded: forget links whose spacing is over.
        if last_dial.len() > MAX_TRACKED {
            last_dial.retain(|_, at| now.saturating_duration_since(*at) < PER_PEER_MIN);
        }
        out
    }
}

/// The service's announcer (supervised in `main`): idle while route hints
/// are off; else it looks at this node's own inputs at start and after
/// every change ([`own_changed`], coalesced over [`SETTLE`]) or
/// [`TICK`], and opens announce links to the contacts not told yet.
pub(crate) async fn run_announcer(data_dir: PathBuf) -> Result<(), String> {
    announce_loop(&data_dir, announcer_live, announce_link).await
}

/// Route hints are live and the debug lab switch does not hold the
/// announcer ([`lab_no_announce`]).
fn announcer_live() -> bool {
    announcer_runs(route_hints::route_hints_live(), lab_no_announce())
}

/// The announcer runs while route hints are live (`hints_live`), unless
/// the lab switch holds it (`held`).
fn announcer_runs(hints_live: bool, held: bool) -> bool {
    hints_live && !held
}

/// `RAVEN_LAB_HINTS_NO_ANNOUNCE=1` (debug builds only, exactly "1"): the
/// announcer opens no link, while every link still carries RRH1. A harness
/// case that needs a contact to keep a stale route until its next link
/// sets it (carrier_matrix C20: the recipient's own announcer would tell the
/// sender its new port before the case's first send). Release builds never
/// read the variable.
fn lab_no_announce() -> bool {
    cfg!(debug_assertions) && std::env::var("RAVEN_LAB_HINTS_NO_ANNOUNCE").as_deref() == Ok("1")
}

/// [`run_announcer`] with the gate and the announce link as arguments.
async fn announce_loop<F, Fut>(data_dir: &Path, live: fn() -> bool, link: F) -> Result<(), String>
where
    F: Fn(PathBuf, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut schedule = Schedule::default();
    let mut first = true;
    loop {
        if !live() {
            tokio::time::sleep(TICK).await;
            continue;
        }
        if !std::mem::take(&mut first) {
            tokio::select! {
                () = changed().notified() => {}
                () = tokio::time::sleep(TICK) => {}
            }
        }
        tokio::time::sleep(SETTLE).await;
        let dd = data_dir.to_path_buf();
        let fresh = tokio::task::spawn_blocking(move || {
            let probed = probe(&dd, crate::now_ms());
            // And what links found moved since the last look.
            let pending = take_pending();
            let all = probed
                .max(pending.all)
                .map(|g| (g, announce_targets(&dd, crate::now_ms(), HeldGates::now())));
            (all, pending.one)
        })
        .await
        .map_err(|e| format!("route hints blocking join: {e}"))?;
        let now = Instant::now();
        let (all, one) = fresh;
        let mut added = 0;
        if let Some((generation, peers)) = all {
            added += peers.len();
            schedule.add(generation, &peers, now);
        }
        for (peer, generation) in one {
            added += 1;
            schedule.add(generation, &[peer], now);
        }
        let due = schedule.due(now, sent_generation);
        if added > 0 && !due.is_empty() {
            netutil::log_limited(
                &ANNOUNCE_LOG,
                "raven-node hints",
                format_args!("routes changed; telling {} contacts", due.len()),
            );
        }
        futures::stream::iter(due)
            .for_each_concurrent(AT_ONCE, |peer| link(data_dir.to_path_buf(), peer))
            .await;
    }
}

/// Blocking: who a change every verified contact shares is announced to
/// ([`targets_from`]): the recipients this node holds custody mail for
/// ([`held_targets`] under `gates`), then the contacts whose RRH1 has not
/// expired.
fn announce_targets(data_dir: &Path, now_ms: u64, gates: HeldGates) -> Vec<[u8; 32]> {
    targets_from(
        &held_targets(data_dir, now_ms, gates),
        &learned_routes::live_contacts(data_dir, now_ms),
    )
}

/// `held` first, then `live`, each contact once, at most [`MAX_TARGETS`].
fn targets_from(held: &[[u8; 32]], live: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    for peer in held.iter().chain(live) {
        if out.len() == MAX_TARGETS {
            break;
        }
        if !out.contains(peer) {
            out.push(*peer);
        }
    }
    out
}

/// The gates [`held_targets`] reads.
#[derive(Clone, Copy, Debug)]
struct HeldGates {
    /// Friend custody ([`raven_core::custody_gate::CustodyGates`]).
    custody: bool,
    /// M0 ([`raven_core::lan_noise_pin_live`]).
    noise_pin: bool,
    /// This custodian serves the letter ops
    /// ([`raven_core::friend_custody::letter_ops_served`]).
    letters: bool,
}

impl HeldGates {
    fn now() -> Self {
        Self {
            custody: raven_core::custody_gate::CustodyGates::current().live,
            noise_pin: raven_core::lan_noise_pin_live(),
            letters: raven_core::friend_custody::letter_ops_served(),
        }
    }
}

/// Blocking (cutoff F8): the recipients this custodian holds unreleased
/// custody mail for, newest deposit first
/// ([`raven_core::friend_custody::held_recipients`]), then, while it serves
/// the letter ops, those it holds sealed letters for
/// ([`raven_core::friend_custody::held_letter_recipients`], review cross-2:
/// a letter waits up to 7 days, past the recipient's RRH1), each once: a
/// custodian that came back elsewhere tells them, so they fetch at its new
/// address, also one whose RRH1 it never got or that has expired. Only while
/// custody is live and M0 is on, and only verified, unblocked contacts with
/// a noise pin: every try of an announce link is an identity-bearing dial,
/// so it goes only where M0 checks who answers. An unreadable store holds
/// mail for nobody.
fn held_targets(data_dir: &Path, now_ms: u64, gates: HeldGates) -> Vec<[u8; 32]> {
    if !(gates.custody && gates.noise_pin) {
        return Vec::new();
    }
    let mut held =
        raven_core::friend_custody::held_recipients(data_dir, now_ms).unwrap_or_default();
    if gates.letters {
        for peer in
            raven_core::friend_custody::held_letter_recipients(data_dir, now_ms).unwrap_or_default()
        {
            if !held.contains(&peer) {
                held.push(peer);
            }
        }
    }
    held.into_iter()
        .filter(|peer| {
            matches!(
                contact_admission(data_dir, peer),
                ContactAdmission::Allowed(c) if c.pinned
            )
        })
        .filter(|peer| {
            matches!(
                raven_core::lan_noise_pin::load_pin(data_dir, peer),
                Ok(Some(_))
            )
        })
        .collect()
}

/// What [`probe`] compares for the LAN listener (pure): its address, and for
/// a wildcard one (0.0.0.0 or [::]: friends reach it at whatever address
/// this computer has) also `view`, a digest of the networks netwatch settled
/// on, keyed with this computer's identity ([`crate::netwatch::view_digest`]:
/// a copy of the state file cannot test guesses against it), as
/// `<address>|<digest>`. A move to another network with the same listener is
/// then a change too (cutoff F8: a custodian that moved tells the recipients
/// it holds mail for, also on the default 0.0.0.0:7420). Empty: no listener.
fn lan_input(listener: Option<SocketAddr>, view: Option<&str>) -> String {
    match (listener, view) {
        (Some(addr), Some(view)) if addr.ip().is_unspecified() => format!("{addr}|{view}"),
        (Some(addr), _) => addr.to_string(),
        (None, _) => String::new(),
    }
}

/// Whether the LAN listener's input moved from `saved` to `now`
/// ([`lan_input`]), and what to save (pure). Another address moves it, and
/// so do other networks under the same one, or networks where none were
/// saved (a build before this rule, or a first look before netwatch knew
/// them): one announce too many rather than a move nobody is told. Networks
/// not known now (before netwatch's first baseline, or no network at all)
/// are no move: the saved ones stay until they are known again.
fn lan_moved(saved: &str, now: &str) -> (bool, String) {
    let split = |lan: &str| match lan.split_once('|') {
        Some((addr, view)) => (addr.to_string(), Some(view.to_string())),
        None => (lan.to_string(), None),
    };
    let ((saved_addr, saved_view), (now_addr, now_view)) = (split(saved), split(now));
    if saved_addr != now_addr {
        return (true, now.to_string());
    }
    match now_view {
        Some(view) => (saved_view.as_ref() != Some(&view), now.to_string()),
        None => (false, saved.to_string()),
    }
}

/// Blocking: the announcer's look at the inputs every verified contact
/// shares (the p2p host's routes, `lab_local`, the node policy's hide-IP,
/// custody, the friend relay's offer) and at the LAN listener's address (a
/// listener back on another port, a restart included: receivers learn
/// LAN_PORT only from LAN links) and, for a wildcard listener, this
/// computer's networks ([`lan_input`]). A change moves the generation: that
/// generation is returned, for every contact to be told.
fn probe(data_dir: &Path, now_ms: u64) -> Option<u64> {
    let lab_local = raven_core::p2p_local_candidates_enabled();
    let own = crate::p2p::own_routes();
    let mut own = own.as_ref().and_then(|o| OwnPart::of(o, lab_local));
    if !raven_core::nat_class_live_enabled() {
        if let Some(own) = own.as_mut() {
            own.nat = None;
        }
    }
    let offer = crate::friend_relay::offer(data_dir).filter(|_| raven_core::relay_offers_live());
    // The networks' digest is keyed with this computer's identity, the one
    // the outbox worker loaded (review FU-2: the state is a file). No worker
    // yet: the networks are not known, which moves nothing (and nothing is
    // announced without it anyway); the next look has them.
    let ctx = crate::outbox::attempt_ctx();
    let custody_hints = raven_core::custody_gate::custody_hints_live();
    // The home custodians are this node's verified contacts other than
    // itself: its key comes from the worker, or from the LAN listener. With
    // neither yet no key is excluded (a profile never lists its own key, so
    // the set is the same one a snapshot reads).
    let custody = custody_hints.then(|| {
        let local = ctx
            .as_ref()
            .map(|c| c.identity.public_key_bytes())
            .or_else(|| crate::lan_direct::listener_identity().map(|i| i.public_key_bytes()))
            .unwrap_or([0; 32]);
        CustodyShared::read(data_dir, &local, crate::p2p::reach_confirmed(), now_ms)
    });
    let global = global_digest(
        own.as_ref(),
        lab_local,
        custody_hints,
        raven_core::node_policy::load_policy(data_dir).hide_ip,
        offer.as_ref().map(|o| &o.record),
        custody.as_ref(),
        own_schedule().as_ref(),
        crate::onion::own_binding().as_ref(),
    );
    let key = ctx.map(|ctx| route_hints::NetworksKey::derive(&ctx.identity));
    let lan = lan_input(
        crate::lan_direct::listener_addr(),
        key.as_ref()
            .and_then(crate::netwatch::view_digest)
            .as_deref(),
    );
    match next_generation(data_dir, &global, Some(&lan), None, now_ms)? {
        (generation, Moved::Global) => Some(generation),
        _ => None,
    }
}

/// The generation every verified contact would be told with the p2p host's
/// routes `own` alone (no LAN listener, no custody, no offer, no hide-IP):
/// [`probe`]'s rule for the host's part (other modules' tests).
#[cfg(test)]
pub(crate) fn own_generation(data_dir: &Path, own: &OwnP2p, now_ms: u64) -> Option<u64> {
    let own = OwnPart::of(own, false);
    let global = global_digest(own.as_ref(), false, false, false, None, None, None, None);
    next_generation(data_dir, &global, None, None, now_ms).map(|(generation, _)| generation)
}

/// One announce link to `peer`: its routes as the worker plans owed ACKs
/// ([`announce_routes`]), tried in dial order with no message frame until
/// one link completes. A failure is not reported: a contact not told is
/// retried. With no outbox worker there is no plan, so no dial this round:
/// the contact stays not told and its retries stand.
async fn announce_link(data_dir: PathBuf, peer: [u8; 32]) {
    let Some(ctx) = crate::outbox::attempt_ctx() else {
        return;
    };
    // Blocking: localization may resolve names.
    let Ok(routes) =
        tokio::task::spawn_blocking(move || announce_routes(&ctx, &peer, crate::now_ms())).await
    else {
        return;
    };
    let pub_hex = hex::encode(peer);
    for (_, route) in routes {
        let linked = match route.carrier {
            OutboxCarrier::Lan => {
                crate::lan_direct::dial_announce(&data_dir, &route.dial, &pub_hex).await
            }
            OutboxCarrier::Internet => {
                crate::internet_direct::dial(&data_dir, &route.dial, &pub_hex, &[])
                    .await
                    .map(drop)
            }
            OutboxCarrier::P2p => crate::p2p::dial(&data_dir, &route.dial, &pub_hex, &[])
                .await
                .map(drop),
            // A zero-frame link: never wants the contact (nothing queued).
            OutboxCarrier::Nearby => crate::nearby::dial(&data_dir, &route.dial, &pub_hex, &[])
                .await
                .map(drop),
            // The announcer plans no onion route (design §3.6); a plan that
            // held one would announce over Tor like any carrier.
            OutboxCarrier::Onion => crate::onion::dial_with_meta(
                &data_dir,
                &route.dial,
                &pub_hex,
                &[],
                crate::learning::DialMeta::default(),
            )
            .await
            .map(drop),
        };
        if linked.is_ok() {
            return;
        }
    }
}

/// Blocking: where one announce link to `peer` goes, in dial order, as
/// (planned, dialled): the worker's resolver ([`crate::outbox::peer_plan`]:
/// its gates, which route hints need too, the on-link filter, the route
/// memory, connected first, learned routes and hide-IP) for a current,
/// unblocked contact, a LAN route of an unverified one only on the local
/// network ([`localize_lan_route`]); nothing otherwise. The announcer never
/// teaches the route memory.
pub(crate) fn announce_routes(
    ctx: &AttemptCtx,
    peer: &[u8; 32],
    now: u64,
) -> Vec<(OutboxRoute, OutboxRoute)> {
    let ContactAdmission::Allowed(contact) = contact_admission(&ctx.data_dir, peer) else {
        return Vec::new();
    };
    crate::outbox::peer_plan(ctx, peer, contact, now).auto_dial(
        peer,
        ctx.connected,
        &mut |r, pinned| localize_lan_route(r, pinned, LOCALIZE_RESOLVE_TIMEOUT),
    )
}

// ── Status ──────────────────────────────────────────────────────────────────

/// IPC `Status` `route_hints` (counts only): `None` while route hints are
/// off, and while the contact book cannot be read. Blocking (reads the data
/// dir).
pub(crate) fn status(data_dir: &Path) -> Option<RouteHintsStatus> {
    if !route_hints::route_hints_live() {
        return None;
    }
    let now = crate::now_ms();
    let generation = {
        let held = lock(&GEN);
        match &*held {
            Some((dir, state)) if dir == data_dir => state.generation,
            _ => {
                load_gen(data_dir)
                    .into_loaded()
                    .unwrap_or_default()
                    .generation
            }
        }
    };
    let told = lock(&SENT_GEN).as_ref().map_or(0, HashMap::len);
    Some(RouteHintsStatus {
        live: true,
        told: u32::try_from(told).unwrap_or(u32::MAX),
        learned: u32::try_from(learned_routes::live_contacts(data_dir, now).len())
            .unwrap_or(u32::MAX),
        ignored: IGNORED.load(Ordering::Relaxed),
        generation_age_s: if generation == 0 {
            0
        } else {
            now.saturating_sub(generation) / 1000
        },
        hide_ip: raven_core::node_policy::load_policy(data_dir).hide_ip,
        hidden_contacts: hidden_contacts(data_dir).ok()?,
    })
}

/// Contacts this node hides its IP from one by one (`contacts.json` rows
/// with `hide_ip`, one per key). A book that cannot be read (sealed without
/// its key, corrupt) is an error, never "none": [`status`] then reports no
/// route hints row rather than a count it cannot know (privacy pack PP.4).
fn hidden_contacts(data_dir: &Path) -> Result<u32, raven_core::contact_book::BookError> {
    #[derive(Deserialize)]
    struct Row {
        #[serde(default)]
        pub_hex: String,
        #[serde(default)]
        hide_ip: bool,
    }
    let rows: Vec<Row> = raven_core::contact_book::read_rows(data_dir)?.unwrap_or_default();
    let keys: HashSet<String> = rows
        .into_iter()
        .filter(|r| r.hide_ip)
        .map(|r| r.pub_hex.trim().to_ascii_lowercase())
        .filter(|k| !k.is_empty())
        .collect();
    Ok(u32::try_from(keys.len()).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Qualified: a glob would clash with this module's own `lan` and `ctx`.
    use crate::outbox::test_rig as rig;
    use raven_core::identity::Identity;
    use raven_core::node_policy::{save_policy, NodePolicy};
    use raven_core::p2p_route::local_peer_id;
    use serde_json::json;

    /// P6.29: a link keeps the peer's features for its capability floor
    /// only while security events are live: a verified hello's caps are
    /// complete, a LAN dialer's message 3 only shows some; a dial without
    /// RLX1 shows nothing.
    #[test]
    fn a_link_reads_the_peers_features_only_while_security_events_are_live() {
        use raven_core::security_gate::{self, SecGate};
        let keys = LinkKeys::new([0x29; 32], &Identity::from_seed(&[0x30; 32]));
        let caps = raven_core::CAP_INTERNET | CAP_LINK_RRH1;
        let links = || {
            let inet = LinkCtl::inet(
                Path::new("unused"),
                OutboxCarrier::Internet,
                Role::Dialer,
                keys,
                false,
                caps,
                None,
            );
            let m3 = route_hints::rlx1_payload(CAP_LINK_RRH1);
            let lan = LinkCtl::lan_listener(Path::new("unused"), keys, None, &m3);
            let probe = LinkCtl::lan_listener(Path::new("unused"), keys, None, &[]);
            (inet.features, lan.features, probe.features)
        };
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
        assert_eq!(links(), (None, None, None));
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        if crate::security::events_live() {
            assert_eq!(
                links(),
                (
                    Some(LinkFeatures::Complete(caps)),
                    Some(LinkFeatures::Seen(CAP_LINK_RRH1)),
                    Some(LinkFeatures::Seen(0)),
                )
            );
        }
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
    }

    /// `RAVEN_LAB_HINTS_NO_ANNOUNCE=1` holds the announcer, exactly "1"
    /// and in a debug build only: a release build never reads it (the
    /// release test job runs this). Only this test reads or sets it.
    #[test]
    fn the_no_announce_lab_switch_holds_the_announcer_in_debug_builds_only() {
        std::env::set_var("RAVEN_LAB_HINTS_NO_ANNOUNCE", "0");
        assert!(!lab_no_announce());
        std::env::set_var("RAVEN_LAB_HINTS_NO_ANNOUNCE", "1");
        assert_eq!(lab_no_announce(), cfg!(debug_assertions));
        if cfg!(debug_assertions) {
            assert!(!announcer_live());
        } else {
            assert_eq!(announcer_live(), route_hints::route_hints_live());
        }
        // Held, it never runs; route hints off, neither.
        assert!(announcer_runs(true, false));
        assert!(!announcer_runs(true, true));
        assert!(!announcer_runs(false, false));
        std::env::remove_var("RAVEN_LAB_HINTS_NO_ANNOUNCE");
        assert!(!lab_no_announce());
        assert_eq!(announcer_live(), route_hints::route_hints_live());
    }

    const T0: u64 = 1_760_000_000_000;
    /// This node, the contact, a custodian it lists and a stranger.
    const LOCAL: u8 = 0x51;
    const PEER: u8 = 0x52;
    const CUSTODIAN: u8 = 0x53;
    const OTHER: u8 = 0x54;

    fn key(seed: u8) -> [u8; 32] {
        Identity::from_seed(&[seed; 32]).public_key_bytes()
    }

    fn pid(seed: u8) -> String {
        local_peer_id(&Identity::from_seed(&[seed; 32]))
    }

    fn relay(seed: u8, host: &str) -> String {
        format!("{host}/p2p/{}", pid(seed))
    }

    /// One contacts.json row: (seed, pinned, hide_ip, custodians).
    type Row<'a> = (u8, bool, bool, &'a [u8]);

    fn write_book(dir: &Path, rows: &[Row]) {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(seed, pinned, hide_ip, custodians)| {
                json!({
                    "pub_hex": hex::encode(key(*seed)),
                    "pinned": pinned,
                    "hide_ip": hide_ip,
                    "custodians": custodians.iter().map(|c| hex::encode(key(*c))).collect::<Vec<_>>(),
                })
            })
            .collect();
        std::fs::write(
            dir.join("contacts.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }

    /// The contact, verified or not, listing the custodian (a verified
    /// contact itself).
    fn book(dir: &Path, pinned: bool) {
        write_book(
            dir,
            &[
                (PEER, pinned, false, &[CUSTODIAN]),
                (CUSTODIAN, true, false, &[]),
            ],
        );
    }

    /// The host: two addresses of one relay and one of another, then a third
    /// relay and one naming ourselves (both dropped); global confirmed
    /// addresses among a private one, a duplicate, a DNS name and one with
    /// its own `/p2p`; listen addresses on two networks.
    fn own() -> OwnP2p {
        OwnP2p {
            peer_id: pid(LOCAL),
            relays: vec![
                relay(0x61, "/ip4/11.0.2.1/tcp/7423"),
                relay(0x61, "/ip4/11.0.2.1/tcp/443"),
                relay(0x62, "/dns4/relay.example.org/tcp/443"),
                relay(0x63, "/ip4/11.0.2.3/tcp/7423"),
                relay(LOCAL, "/ip4/11.0.2.9/tcp/7423"),
            ],
            confirmed: vec![
                "/ip4/11.0.3.5/tcp/7423".into(),
                "/ip6/2c0f:fff0:a::5/udp/7423/quic-v1".into(),
                "/ip4/192.168.7.5/tcp/7423".into(),
                "/ip4/11.0.3.5/udp/7423/quic-v1".into(),
                "/ip4/11.0.3.5/tcp/7423".into(),
                "/dns4/me.example.org/tcp/7423".into(),
                format!("/ip4/11.0.3.6/tcp/7423/p2p/{}", pid(LOCAL)),
            ],
            listen: vec![
                "/ip4/192.168.7.5/tcp/7423".into(),
                "/ip4/10.0.0.5/tcp/7423".into(),
                "/ip4/192.168.7.6/udp/7423/quic-v1".into(),
                "/ip4/192.168.7.7/tcp/7423".into(),
            ],
            nat: None,
            discovered: Vec::new(),
            inet: Vec::new(),
        }
    }

    fn ctx(carrier: OutboxCarrier, role: Role, peer_ip: &str) -> SnapCtx {
        SnapCtx {
            carrier,
            role,
            keys: LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32])),
            peer_ip: peer_ip.parse().ok(),
            peer_zone: None,
            local_ifs: Vec::new(),
            local_addr: Some("192.168.7.5:50000".parse().unwrap()),
            listeners: vec!["0.0.0.0:7531".parse().unwrap()],
            own: Some(own()),
            lab_local: false,
            custody_hints: true,
            reach_confirmed: false,
            offers_live: false,
            offer: None,
            nat_live: false,
            schedule: None,
            seeds_live: false,
            now_ms: T0,
        }
    }

    fn lan(role: Role) -> SnapCtx {
        ctx(OutboxCarrier::Lan, role, "192.168.7.20")
    }

    const GLOBAL_DIRECT: [&str; 3] = [
        "/ip6/2c0f:fff0:a::5/udp/7423/quic-v1",
        "/ip4/11.0.3.5/udp/7423/quic-v1",
        "/ip4/11.0.3.5/tcp/7423",
    ];

    fn frame(generation: u64, lan_port: Option<u16>) -> Vec<u8> {
        route_hints::encode(&RouteHints {
            generation,
            ttl_s: 3600,
            lan_port,
            ..RouteHints::default()
        })
    }

    #[test]
    fn listen_port_for_table() {
        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        for (listen, local, want) in [
            ("0.0.0.0:7420", "192.168.1.5:50000", Some(7420)),
            ("127.0.0.1:7420", "192.168.1.5:50000", None),
            ("192.168.1.5:7420", "192.168.1.5:50000", Some(7420)),
            ("[::]:7420", "192.168.1.5:50000", None),
            ("[::]:7420", "[fd00::5]:50000", Some(7420)),
            ("0.0.0.0:7420", "[fd00::5]:50000", None),
            ("[fd00::5]:7420", "[fd00::5]:50000", Some(7420)),
            ("[fd00::5]:7420", "[fd00::6]:50000", None),
            ("0.0.0.0:0", "192.168.1.5:50000", None),
            ("192.168.1.5:7420", "[::ffff:192.168.1.5]:50000", Some(7420)),
            ("[::ffff:192.168.1.5]:7420", "192.168.1.5:50000", Some(7420)),
            ("0.0.0.0:7420", "[::ffff:192.168.1.5]:50000", Some(7420)),
        ] {
            assert_eq!(
                listen_port_for(at(listen), at(local)),
                want,
                "{listen} {local}"
            );
        }
    }

    /// Phase 3 P3.5: an `auto` listener has a socket per family (`0.0.0.0`
    /// and `[::]`, IPv6 only). A dial tells LAN_PORT when either answers on
    /// the address it left from; a listener tells its port (both share it).
    #[test]
    fn lan_port_checks_every_listener_socket() {
        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        let mut dialer = lan(Role::Dialer);
        dialer.listeners = vec![at("0.0.0.0:7531"), at("[::]:7531")];
        for local in [
            "192.168.7.5:50000",
            "[::ffff:192.168.7.5]:50000",
            "[fd00::5]:50000",
        ] {
            dialer.local_addr = Some(at(local));
            assert_eq!(lan_port(&dialer), Some(7531), "{local}");
        }
        // IPv4 only (no IPv6 on this computer): an IPv6 dial does not.
        dialer.listeners.truncate(1);
        assert_eq!(lan_port(&dialer), None);
        let mut listener = lan(Role::Listener);
        listener.listeners = vec![at("0.0.0.0:7531"), at("[::]:7531")];
        assert_eq!(lan_port(&listener), Some(7531));
        listener.listeners.clear();
        assert_eq!(lan_port(&listener), None);
    }

    /// The LAN dialer's message 3 asks for RRH1 only while route hints are
    /// live and only on a dial that reads.
    #[test]
    fn lan_m3_payload_table() {
        for pad in [false, true] {
            assert!(lan_m3_payload(false, pad, false).is_empty());
            assert!(
                lan_m3_payload(true, pad, false).is_empty(),
                "a probe offers nothing"
            );
        }
        assert!(lan_m3_payload(false, false, true).is_empty());
        let asked = lan_m3_payload(true, false, true);
        assert_eq!(asked.len(), 11);
        assert_eq!(route_hints::rlx1_caps(&asked), CAP_LINK_RRH1);
        // Phase 6b P6.34: PAD1 alone and with RRH1
        // (`shared-vectors/rvn1/link/rlx1_caps_002.json`).
        let pad = lan_m3_payload(false, true, true);
        assert_eq!(hex::encode(&pad), "524c583101010400000200");
        let both = lan_m3_payload(true, true, true);
        assert_eq!(hex::encode(&both), "524c583101010400000300");
        assert_eq!(route_hints::rlx1_caps(&both), CAP_LINK_RRH1 | CAP_LINK_PAD1);
    }

    /// Phase 6b P6.34: a LAN dialer that read the listener's first RPD1
    /// frame keeps it for the listener's capability floor, with the RRH1 it
    /// saw, only while security events are live; no other link does.
    #[tokio::test]
    async fn a_lan_dialer_notes_the_listeners_padding_as_seen() {
        use raven_core::security_gate::{self, SecGate};
        let keys = LinkKeys::new([0x29; 32], &Identity::from_seed(&[0x30; 32]));
        let dir = tempfile::tempdir().unwrap();
        let _live = LiveForTest::set(true);
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(false));
        let mut quiet = LinkCtl::lan_dialer(dir.path(), keys, None, None, true, false);
        quiet.pad_seen();
        assert_eq!(quiet.features, None);
        security_gate::set_lab_for_this_thread(SecGate::Events, Some(true));
        if crate::security::events_live() {
            let mut dial = LinkCtl::lan_dialer(dir.path(), keys, None, None, true, false);
            dial.pad_seen();
            assert_eq!(dial.features, Some(LinkFeatures::Seen(CAP_LINK_PAD1)));
            assert!(dial.take(&frame(7, Some(7431))).await);
            assert_eq!(
                dial.features,
                Some(LinkFeatures::Seen(CAP_LINK_PAD1 | CAP_LINK_RRH1))
            );
            let mut inet = LinkCtl::inet(
                dir.path(),
                OutboxCarrier::Internet,
                Role::Dialer,
                keys,
                true,
                raven_core::CAP_INTERNET,
                None,
            );
            inet.pad_seen();
            assert_eq!(
                inet.features,
                Some(LinkFeatures::Complete(raven_core::CAP_INTERNET)),
                "a hello already said it all"
            );
        }
        security_gate::set_lab_for_this_thread(SecGate::Events, None);
    }

    /// Auto-reach (spec §6, §13.3): what STUN discovery found goes as DIRECT
    /// after the confirmed addresses (within the 4 global ones), the
    /// Internet direct address as INET_DIRECT, confirmed ones first; a
    /// change moves the generation; hide my IP removes both.
    #[test]
    fn discovered_addresses_follow_the_confirmed_ones_and_inet_rides_along() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        book(dd, true);
        let before = snapshot_for(dd, &ctx(OutboxCarrier::P2p, Role::Listener, "")).unwrap();
        let mut c = ctx(OutboxCarrier::P2p, Role::Listener, "");
        c.now_ms = T0 + 1;
        {
            let own = c.own.as_mut().unwrap();
            own.discovered = vec![
                "/ip4/11.0.3.7/tcp/17423".into(),
                "/ip4/11.0.3.7/udp/17423/quic-v1".into(),
                "/ip4/192.168.7.9/udp/17423/quic-v1".into(),
            ];
            own.inet = vec![
                ("11.0.3.7:17422".into(), false),
                ("[2c0f:fff0:a::7]:17422".into(), true),
                ("192.168.7.9:17422".into(), true),
            ];
        }
        let h = snapshot_for(dd, &c).unwrap();
        let mut direct: Vec<String> = GLOBAL_DIRECT.iter().map(|s| s.to_string()).collect();
        direct.push("/ip4/11.0.3.7/udp/17423/quic-v1".into());
        assert_eq!(
            h.direct, direct,
            "confirmed first, then the discovered QUIC one"
        );
        assert_eq!(
            h.inet,
            vec![
                route_hints::InetDirect {
                    flags: route_hints::INET_FLAG_CONFIRMED,
                    addr: "[2c0f:fff0:a::7]:17422".parse().unwrap(),
                },
                route_hints::InetDirect {
                    flags: 0,
                    addr: "11.0.3.7:17422".parse().unwrap(),
                },
            ]
        );
        assert!(h.generation > before.generation, "a change is told");
        let frame = route_hints::encode(&h);
        assert_eq!(route_hints::decode(&frame).unwrap().inet, h.inet);
        // Hide my IP for everyone: no DIRECT, no INET_DIRECT.
        save_policy(
            dd,
            &NodePolicy {
                hide_ip: true,
                ..NodePolicy::default()
            },
        )
        .unwrap();
        let hidden = snapshot_for(dd, &c).unwrap();
        assert!(hidden.direct.is_empty() && hidden.inet.is_empty());
    }

    #[test]
    fn snapshot_filters() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        book(dd, true);
        let r = |seed: u8, host: &str| relay(seed, host);
        let relays = vec![
            r(0x61, "/ip4/11.0.2.1/tcp/7423"),
            r(0x61, "/ip4/11.0.2.1/tcp/443"),
            r(0x62, "/dns4/relay.example.org/tcp/443"),
        ];
        let local_direct = [
            "/ip4/192.168.7.5/tcp/7423",
            "/ip4/192.168.7.6/udp/7423/quic-v1",
        ];
        let own_id = peer_id_bytes(&pid(LOCAL)).unwrap();

        // A verified contact on a LAN link: everything, LAN_PORT and the
        // same-LAN listen addresses included.
        let full = snapshot_for(dd, &lan(Role::Listener)).unwrap();
        assert!(full.generation >= T0);
        assert_eq!(full.ttl_s, RRH1_DEFAULT_TTL_S);
        assert_eq!(full.p2p_id, Some(own_id));
        assert_eq!(full.relays, relays);
        let mut direct: Vec<String> = GLOBAL_DIRECT.iter().map(|s| s.to_string()).collect();
        direct.extend(local_direct.iter().map(|s| s.to_string()));
        assert_eq!(full.direct, direct);
        assert_eq!(full.lan_port, Some(7531));
        // The listed custodian, blinded for this contact (Phase 3: never
        // CUSTODIAN 0x05, every tag flag 0).
        assert!(full.custodians.is_empty());
        assert_eq!(
            full.custodian_tags,
            vec![(
                route_hints::custodian_tag(&key(LOCAL), &key(PEER), &key(CUSTODIAN)),
                0
            )]
        );
        assert!(route_hints::decode(&route_hints::encode(&full)).is_some());

        // Internet and p2p links: no LAN_PORT, no same-LAN address, even
        // with a LAN listener up and a local peer address.
        for carrier in [OutboxCarrier::Internet, OutboxCarrier::P2p] {
            for ip in ["11.0.3.9", "192.168.7.20", ""] {
                let h = snapshot_for(dd, &ctx(carrier, Role::Listener, ip)).unwrap();
                assert_eq!(h.lan_port, None, "{carrier:?} {ip}");
                assert_eq!(h.direct, GLOBAL_DIRECT, "{carrier:?} {ip}");
                assert_eq!((h.p2p_id, &h.relays), (Some(own_id), &relays));
                assert_eq!(h.generation, full.generation, "same content");
            }
        }

        // A dialer tells its port only when its listener answers on the
        // address it left from.
        let mut dialer = lan(Role::Dialer);
        assert_eq!(snapshot_for(dd, &dialer).unwrap().lan_port, Some(7531));
        dialer.listeners = vec!["127.0.0.1:7531".parse().unwrap()];
        assert_eq!(snapshot_for(dd, &dialer).unwrap().lan_port, None);
        dialer.listeners.clear();
        assert_eq!(snapshot_for(dd, &dialer).unwrap().lan_port, None);

        // Custody off: no custody entry. A custodian that is no longer a
        // verified contact is never named.
        let mut no_custody = lan(Role::Listener);
        no_custody.custody_hints = false;
        let h = snapshot_for(dd, &no_custody).unwrap();
        assert!(h.custodians.is_empty() && h.custodian_tags.is_empty());
        assert_eq!(h.custody_offer, None);
        write_book(
            dd,
            &[
                (PEER, true, false, &[CUSTODIAN]),
                (CUSTODIAN, false, false, &[]),
            ],
        );
        assert!(snapshot_for(dd, &lan(Role::Listener))
            .unwrap()
            .custodian_tags
            .is_empty());

        // No host: no P2P_ID, relay or direct address.
        book(dd, true);
        let mut no_host = lan(Role::Listener);
        no_host.own = None;
        let h = snapshot_for(dd, &no_host).unwrap();
        assert_eq!((h.p2p_id, h.relays.len(), h.direct.len()), (None, 0, 0));
        assert_eq!(h.lan_port, Some(7531));

        // Hide my IP, for this contact or for everyone: no DIRECT at all
        // (relays stay).
        write_book(
            dd,
            &[
                (PEER, true, true, &[CUSTODIAN]),
                (CUSTODIAN, true, false, &[]),
            ],
        );
        let h = snapshot_for(dd, &lan(Role::Listener)).unwrap();
        assert!(h.direct.is_empty());
        assert_eq!(h.relays, relays);
        book(dd, true);
        save_policy(
            dd,
            &NodePolicy {
                hide_ip: true,
                ..NodePolicy::default()
            },
        )
        .unwrap();
        let h = snapshot_for(dd, &lan(Role::Listener)).unwrap();
        assert!(h.direct.is_empty());
        assert_eq!(h.relays, relays);
        save_policy(dd, &NodePolicy::default()).unwrap();

        // An unverified contact: LAN_PORT only, and only on a LAN link from
        // a local-network address.
        book(dd, false);
        let lan_only = snapshot_for(dd, &lan(Role::Listener)).unwrap();
        assert_eq!(
            lan_only,
            RouteHints {
                generation: lan_only.generation,
                ttl_s: RRH1_DEFAULT_TTL_S,
                lan_port: Some(7531),
                ..RouteHints::default()
            }
        );
        for (carrier, ip) in [
            (OutboxCarrier::Lan, "203.0.113.9"),
            (OutboxCarrier::Lan, "100.64.3.4"),
            (OutboxCarrier::Lan, ""),
            (OutboxCarrier::Internet, "192.168.7.20"),
            (OutboxCarrier::P2p, ""),
        ] {
            assert_eq!(
                snapshot_for(dd, &ctx(carrier, Role::Listener, ip)),
                None,
                "{carrier:?} {ip}"
            );
        }

        // Not a contact, a blocked one, an unreadable book: nothing.
        write_book(dd, &[(OTHER, true, false, &[])]);
        assert_eq!(snapshot_for(dd, &lan(Role::Listener)), None);
        book(dd, true);
        let mut blocks = raven_core::BlockList::default();
        blocks.block(&hex::encode(key(PEER)));
        blocks.save(dd).unwrap();
        assert_eq!(snapshot_for(dd, &lan(Role::Listener)), None);
        std::fs::write(dd.join("contacts.json"), "{not json").unwrap();
        assert_eq!(snapshot_for(dd, &lan(Role::Listener)), None);
    }

    /// The no-forwarding rule: what contacts told us never shapes what we
    /// tell anyone (a poisoned learned_routes.json changes nothing).
    #[test]
    fn snapshot_never_reads_learned_routes() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        book(dd, true);
        let before = snapshot_for(dd, &lan(Role::Listener)).unwrap();
        let poison = json!([{
            "pub_hex": hex::encode(key(LOCAL)),
            "generation": u64::MAX,
            "received_at_ms": T0,
            "expires_at_ms": u64::MAX,
            "via": "lan",
            "peer_id": pid(OTHER),
            "relays": [relay(0x70, "/ip4/11.9.9.9/tcp/7423")],
            "direct": [format!("/ip4/11.9.9.8/tcp/7423/p2p/{}", pid(OTHER))],
            "lan": {"generation": u64::MAX, "received_at_ms": T0, "expires_at_ms": u64::MAX,
                    "lan_port": 9999, "lan_ip": "192.168.7.99"},
        }]);
        std::fs::write(
            dd.join(learned_routes::LEARNED_ROUTES_FILE),
            serde_json::to_vec(&poison).unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot_for(dd, &lan(Role::Listener)).unwrap(), before);
        std::fs::write(dd.join(learned_routes::LEARNED_ROUTES_FILE), "{garbage").unwrap();
        assert_eq!(snapshot_for(dd, &lan(Role::Listener)).unwrap(), before);
        let text = format!("{before:?}");
        assert!(!text.contains("11.9.9") && !text.contains("9999"), "{text}");
    }

    /// Phase 3 (P3.20): custody entries ride the snapshot.
    mod custody {
        use super::*;
        use raven_core::custody_gate::{
            set_carrier_gates_for_this_thread, set_custody_gates_for_this_thread, CustodyGates,
            OFFER_REACHABLE,
        };

        /// Custody live (no WAN) and the LAN carrier open (custody can be
        /// served, whatever another test does with `raven lan off`) on this
        /// test thread; cleared on drop.
        struct Live;

        impl Live {
            fn on() -> Self {
                set_custody_gates_for_this_thread(Some(CustodyGates {
                    live: true,
                    wan: false,
                }));
                set_carrier_gates_for_this_thread(Some(raven_core::outbox::CarrierGates {
                    lan: true,
                    internet: false,
                    p2p: false,
                    nearby: false,
                    onion: false,
                }));
                Self
            }
        }

        impl Drop for Live {
            fn drop(&mut self) {
                set_custody_gates_for_this_thread(None);
                set_carrier_gates_for_this_thread(None);
            }
        }

        /// The node policy: custody offered (`raven node custody`), the
        /// mailbox consent and a manual home list.
        fn policy(dd: &Path, custody: bool, custody_use: Option<bool>, home: &[u8]) {
            save_policy(
                dd,
                &NodePolicy {
                    custody,
                    custody_use,
                    custody_home: home.iter().map(|h| hex::encode(key(*h))).collect(),
                    ..NodePolicy::default()
                },
            )
            .unwrap();
        }

        fn tag(custodian: u8) -> ([u8; 32], u8) {
            (
                route_hints::custodian_tag(&key(LOCAL), &key(PEER), &key(custodian)),
                0,
            )
        }

        #[test]
        fn snapshot_carries_offer_and_tags_only_in_full_scope_with_custody_hints_live() {
            let _live = Live::on();
            let dir = tempfile::tempdir().unwrap();
            let dd = dir.path();
            write_book(
                dd,
                &[
                    (PEER, true, false, &[CUSTODIAN]),
                    (CUSTODIAN, true, false, &[]),
                    (OTHER, true, false, &[]),
                ],
            );
            // Offering custody, using friends, OTHER picked as home.
            policy(dd, true, Some(true), &[OTHER]);
            let full = snapshot_for(dd, &lan(Role::Listener)).unwrap();
            if !cfg!(debug_assertions) {
                // A release build ignores the per-thread gate override (CI
                // runs `hints::` in release with every lab switch set):
                // since 2026-10 friend custody (WAN too) and route hints are
                // on there, so the offer goes out.
                assert!(full.custody_offer.is_some());
                return;
            }
            assert_eq!(full.custody_offer, Some(0), "no WAN, not reachable");
            assert_eq!(full.custodian_tags, vec![tag(OTHER), tag(CUSTODIAN)]);
            assert!(full.custodians.is_empty(), "0x05 is never sent");
            let wire = route_hints::encode(&full);
            let back = route_hints::decode(&wire).unwrap();
            assert_eq!(back.custodian_tags, full.custodian_tags);
            // No raw custodian key on the wire.
            for k in [key(CUSTODIAN), key(OTHER)] {
                assert!(!wire.windows(32).any(|w| w == k));
            }
            // Reachable: the REACHABLE bit.
            let mut reach = lan(Role::Listener);
            reach.reach_confirmed = true;
            let h = snapshot_for(dd, &reach).unwrap();
            assert_eq!(h.custody_offer, Some(OFFER_REACHABLE));
            // Not offering: no offer, the tags stay.
            policy(dd, false, Some(true), &[OTHER]);
            let h = snapshot_for(dd, &lan(Role::Listener)).unwrap();
            assert_eq!(h.custody_offer, None);
            assert_eq!(h.custodian_tags, vec![tag(OTHER), tag(CUSTODIAN)]);
            // Mailboxes off: the home pick is not announced, the listed
            // custodian still is.
            policy(dd, true, Some(false), &[OTHER]);
            let h = snapshot_for(dd, &lan(Role::Listener)).unwrap();
            assert_eq!(h.custodian_tags, vec![tag(CUSTODIAN)]);
            // Custody not riding route hints: neither entry.
            let mut off = lan(Role::Listener);
            off.custody_hints = false;
            let h = snapshot_for(dd, &off).unwrap();
            assert_eq!((h.custody_offer, h.custodian_tags.len()), (None, 0));
            // Every carrier of a verified contact gets them.
            for carrier in [OutboxCarrier::Internet, OutboxCarrier::P2p] {
                let h = snapshot_for(dd, &ctx(carrier, Role::Dialer, "")).unwrap();
                assert_eq!(h.custody_offer, Some(0), "{carrier:?}");
                assert_eq!(h.custodian_tags, vec![tag(CUSTODIAN)], "{carrier:?}");
            }
        }

        #[test]
        fn unpinned_contact_never_gets_custody_entries() {
            let _live = Live::on();
            let dir = tempfile::tempdir().unwrap();
            let dd = dir.path();
            write_book(
                dd,
                &[
                    (PEER, false, false, &[CUSTODIAN]),
                    (CUSTODIAN, true, false, &[]),
                ],
            );
            policy(dd, true, Some(true), &[CUSTODIAN]);
            let h = snapshot_for(dd, &lan(Role::Listener)).unwrap();
            assert_eq!(
                h,
                RouteHints {
                    generation: h.generation,
                    ttl_s: RRH1_DEFAULT_TTL_S,
                    lan_port: Some(7531),
                    ..RouteHints::default()
                },
                "LAN_PORT only"
            );
            for carrier in [OutboxCarrier::Internet, OutboxCarrier::P2p] {
                assert_eq!(snapshot_for(dd, &ctx(carrier, Role::Dialer, "")), None);
            }
        }

        /// A new home custodian is an input every verified contact shares:
        /// one announce to all, not one per contact, and the generation
        /// moves once.
        #[test]
        fn home_change_moves_the_global_digest_once() {
            let _live = Live::on();
            let dir = tempfile::tempdir().unwrap();
            let dd = dir.path();
            write_book(
                dd,
                &[
                    (PEER, true, false, &[]),
                    (OTHER, true, false, &[]),
                    (CUSTODIAN, true, false, &[]),
                ],
            );
            let mut other = lan(Role::Listener);
            other.keys.peer = key(OTHER);
            let first = snapshot_for(dd, &lan(Role::Listener)).unwrap().generation;
            assert_eq!(snapshot_for(dd, &other).unwrap().generation, first);
            take_announced();
            policy(dd, false, Some(true), &[CUSTODIAN]);
            let mut later = lan(Role::Listener);
            later.now_ms = T0 + 1_000;
            let g = snapshot_for(dd, &later).unwrap().generation;
            assert!(g > first);
            other.now_ms = T0 + 2_000;
            assert_eq!(snapshot_for(dd, &other).unwrap().generation, g);
            assert_eq!(take_announced(), vec![(None, g)], "announce_all once");
            // Its tag is in both snapshots, blinded per contact.
            let mine = snapshot_for(dd, &later).unwrap().custodian_tags;
            let theirs = snapshot_for(dd, &other).unwrap().custodian_tags;
            assert_eq!(mine, vec![tag(CUSTODIAN)]);
            assert_eq!(theirs.len(), 1);
            assert_ne!(mine, theirs);
            assert!(take_announced().is_empty());
        }

        /// Phase 5 (P5.21, custody handoff): a custodian's CUSTODIAN_TAG
        /// carries HANDOFF_INBOX (bit 0, no other bit) exactly while the
        /// handoff gate is live and that custodian answered this node's TAGS
        /// with OK within 24 h; the flag coming or going is the contact's
        /// own input (one announce to it). With the gate closed nothing
        /// changes: the digest is the one an older build computed.
        #[test]
        fn handoff_inbox_flag_follows_the_custodians_tags_answer() {
            if !cfg!(debug_assertions) {
                return;
            }
            // A custodian seed of this test's own: the inbox state is
            // process-wide.
            const INBOX: u8 = 0x5e;
            let _live = Live::on();
            let dir = tempfile::tempdir().unwrap();
            let dd = dir.path();
            write_book(
                dd,
                &[(PEER, true, false, &[INBOX]), (INBOX, true, false, &[])],
            );
            policy(dd, false, Some(true), &[]);
            let flagged = |flags: u8| vec![(tag(INBOX).0, flags)];
            raven_core::custody_gate::set_handoff_gate_for_this_thread(Some(true));
            let first = snapshot_for(dd, &lan(Role::Listener)).unwrap();
            assert_eq!(first.custodian_tags, flagged(0), "no TAGS answer yet");
            take_announced();
            crate::custody::set_inbox_ok_for_test(&key(INBOX), true);
            let mut later = lan(Role::Listener);
            later.now_ms = T0 + 1_000;
            let h = snapshot_for(dd, &later).unwrap();
            assert_eq!(
                h.custodian_tags,
                flagged(route_hints::CUSTODIAN_FLAG_HANDOFF_INBOX)
            );
            assert!(h.generation > first.generation);
            assert_eq!(take_announced(), vec![(Some(key(PEER)), h.generation)]);
            // On the wire: tag || 0x01, kept by a receiver of this revision.
            let wire = route_hints::encode(&h);
            assert_eq!(
                route_hints::decode(&wire).unwrap().custodian_tags,
                h.custodian_tags
            );
            // The gate closed: no flag (the digest moves back).
            raven_core::custody_gate::set_handoff_gate_for_this_thread(Some(false));
            later.now_ms = T0 + 2_000;
            let off = snapshot_for(dd, &later).unwrap();
            assert_eq!(off.custodian_tags, flagged(0));
            // The answer forgotten (UNSUPPORTED, POLICY_DENIED): no flag.
            raven_core::custody_gate::set_handoff_gate_for_this_thread(Some(true));
            crate::custody::set_inbox_ok_for_test(&key(INBOX), false);
            later.now_ms = T0 + 3_000;
            assert_eq!(snapshot_for(dd, &later).unwrap().custodian_tags, flagged(0));
            raven_core::custody_gate::set_handoff_gate_for_this_thread(None);
        }

        /// The custodians listed for one contact are that contact's own
        /// input: only it is announced to.
        #[test]
        fn per_contact_static_list_moves_the_contact_digest() {
            let _live = Live::on();
            let dir = tempfile::tempdir().unwrap();
            let dd = dir.path();
            let rows = |listed: &[u8]| {
                write_book(
                    dd,
                    &[
                        (PEER, true, false, listed),
                        (OTHER, true, false, &[]),
                        (CUSTODIAN, true, false, &[]),
                    ],
                )
            };
            rows(&[]);
            let mut other = lan(Role::Listener);
            other.keys.peer = key(OTHER);
            let first = snapshot_for(dd, &lan(Role::Listener)).unwrap().generation;
            snapshot_for(dd, &other).unwrap();
            take_announced();
            rows(&[CUSTODIAN]);
            let mut later = lan(Role::Listener);
            later.now_ms = T0 + 1_000;
            let h = snapshot_for(dd, &later).unwrap();
            assert!(h.generation > first);
            assert_eq!(h.custodian_tags, vec![tag(CUSTODIAN)]);
            assert_eq!(take_announced(), vec![(Some(key(PEER)), h.generation)]);
            other.now_ms = T0 + 2_000;
            let o = snapshot_for(dd, &other).unwrap();
            assert!(o.custodian_tags.is_empty());
            assert!(take_announced().is_empty(), "nobody else is told");
        }
    }

    /// contacts.json rows: (seed, pinned, hide_ip, the card's PeerId or "").
    fn write_p2p_book(dir: &Path, rows: &[(u8, bool, bool, &str)]) {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(seed, pinned, hide_ip, p2p)| {
                json!({
                    "pub_hex": hex::encode(key(*seed)),
                    "pinned": pinned,
                    "hide_ip": hide_ip,
                    "p2p": p2p,
                    "p2p_via": [],
                })
            })
            .collect();
        std::fs::write(
            dir.join("contacts.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }

    /// The record of a friend relay with the key of `seed` at 11.0.4.`n`.
    fn relay_record(seed: u8, n: u8, flags: u8) -> RelayOfferRecord {
        RelayOfferRecord {
            flags,
            relay_pub: raven_core::p2p_route::parse_peer_id(&pid(seed)).unwrap(),
            addrs: vec![
                format!("/ip4/11.0.4.{n}/tcp/7427"),
                format!("/ip4/11.0.4.{n}/udp/7427/quic-v1"),
            ],
        }
    }

    /// The friend relay's offer of `record` to the PeerIds of `members`.
    fn friend_offer(
        dir: &Path,
        record: RelayOfferRecord,
        members: &[u8],
    ) -> crate::friend_relay::Offer {
        let ids: Vec<String> = members.iter().map(|m| pid(*m)).collect();
        crate::friend_relay::Offer::of(dir, record, &ids)
    }

    /// `base` with relay offers live and the friend relay offering `offer`.
    fn offering(base: &SnapCtx, offer: Option<crate::friend_relay::Offer>) -> SnapCtx {
        SnapCtx {
            offers_live: true,
            offer,
            ..base.clone()
        }
    }

    /// What this thread asked the announcer to tell since the last call.
    fn take_announced() -> Vec<(Option<[u8; 32]>, u64)> {
        ANNOUNCED.with(|a| std::mem::take(&mut *a.borrow_mut()))
    }

    /// Spec §11.4: RELAY_OFFER only to a contact the friend relay admits,
    /// that gets the full snapshot and may see this node's IP, and only
    /// while the relay is up with an address worth offering (an offer to
    /// publish at all).
    #[test]
    fn offers_go_only_to_members_we_may_show_our_ip_and_only_while_the_relay_is_up_and_offering() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let record = relay_record(0x61, 1, route_hints::FLAG_AUTONAT);
        let to_peer = friend_offer(dd, record.clone(), &[PEER, OTHER]);
        let base = ctx(OutboxCarrier::P2p, Role::Listener, "");
        let with = |offer: &crate::friend_relay::Offer| {
            snapshot_for(dd, &offering(&base, Some(offer.clone())))
                .unwrap()
                .offers
        };
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        let h = snapshot_for(dd, &offering(&base, Some(to_peer.clone()))).unwrap();
        assert_eq!(h.offers, std::slice::from_ref(&record));
        // It travels as entry 0x20 and a receiver reads it back.
        let wire = route_hints::decode(&route_hints::encode(&h)).unwrap();
        assert_eq!(
            (wire.offers, wire.dropped_offers),
            (vec![record.clone()], 0)
        );
        // Not a member: nothing.
        assert!(with(&friend_offer(dd, record.clone(), &[OTHER])).is_empty());
        // The relay is down or names nothing worth offering: no offer.
        let no_relay = snapshot_for(dd, &offering(&base, None)).unwrap();
        assert!(no_relay.offers.is_empty());
        // Hide my IP from this contact, or from everyone: its address would
        // show this node's.
        write_p2p_book(dd, &[(PEER, true, true, &pid(PEER))]);
        assert!(with(&to_peer).is_empty(), "hidden from the contact");
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        let hide_all = NodePolicy {
            hide_ip: true,
            ..NodePolicy::default()
        };
        save_policy(dd, &hide_all).unwrap();
        assert!(with(&to_peer).is_empty(), "hidden from everyone");
        save_policy(dd, &NodePolicy::default()).unwrap();
        assert_eq!(with(&to_peer), std::slice::from_ref(&record));
        // An unverified contact gets LAN_PORT only.
        write_p2p_book(dd, &[(PEER, false, false, &pid(PEER))]);
        let lan_only = snapshot_for(dd, &offering(&lan(Role::Listener), Some(to_peer.clone())));
        let lan_only = lan_only.unwrap();
        assert!(lan_only.offers.is_empty() && lan_only.p2p_id.is_none());

        // No PeerId on its card: the one its route hints named, once a p2p
        // link proved it (the friend relay admits no other).
        write_p2p_book(dd, &[(PEER, true, false, "")]);
        assert!(with(&to_peer).is_empty(), "no PeerId known");
        let learned = |proven: bool| {
            json!([{
                "pub_hex": hex::encode(key(PEER)),
                "generation": 1,
                "received_at_ms": T0,
                "expires_at_ms": T0 + 3_600_000,
                "via": "lan",
                "peer_id": pid(PEER),
                "peer_id_proven": proven,
            }])
        };
        let file = dd.join(learned_routes::LEARNED_ROUTES_FILE);
        std::fs::write(&file, serde_json::to_vec(&learned(false)).unwrap()).unwrap();
        assert!(with(&to_peer).is_empty(), "not proven");
        std::fs::write(&file, serde_json::to_vec(&learned(true)).unwrap()).unwrap();
        assert_eq!(with(&to_peer), [record]);
    }

    /// Spec §11.4: the offer is an input of the generation. The record
    /// every member gets is in the shared digest: a relay that comes up,
    /// moves, changes a flag or goes down moves it and every contact is
    /// told. The bytes one contact is sent are in its own digest: a change
    /// of membership alone tells that contact.
    #[test]
    fn an_offer_change_bumps_the_generation_and_announces() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        let base = ctx(OutboxCarrier::P2p, Role::Listener, "");
        let snap = |offer: Option<crate::friend_relay::Offer>, at: u64| {
            let c = SnapCtx {
                now_ms: at,
                ..offering(&base, offer)
            };
            snapshot_for(dd, &c).unwrap()
        };
        let autonat = route_hints::FLAG_AUTONAT;
        let first = snap(None, T0).generation;
        take_announced();

        // The relay comes up offering to the contact.
        let up = friend_offer(dd, relay_record(0x61, 1, autonat), &[PEER]);
        let h = snap(Some(up.clone()), T0 + 1);
        assert!(h.generation > first);
        assert_eq!(h.offers.len(), 1);
        assert_eq!(take_announced(), [(None, h.generation)]);
        // Nothing new: nothing moves, nobody is told.
        assert_eq!(snap(Some(up), T0 + 2).generation, h.generation);
        assert!(take_announced().is_empty());
        // It moves (a new address), then a flag changes.
        let mut last = h.generation;
        for record in [
            relay_record(0x61, 2, autonat),
            relay_record(0x61, 2, autonat | route_hints::FLAG_CONFIRMED),
        ] {
            let g = snap(Some(friend_offer(dd, record.clone(), &[PEER])), T0 + 3);
            assert!(g.generation > last);
            assert_eq!(g.offers, [record]);
            assert_eq!(take_announced(), [(None, g.generation)]);
            last = g.generation;
        }
        // Membership alone: the contact's own digest moves, and only it is
        // told.
        let confirmed = relay_record(0x61, 2, autonat | route_hints::FLAG_CONFIRMED);
        let left = snap(Some(friend_offer(dd, confirmed.clone(), &[OTHER])), T0 + 4);
        assert!(left.generation > last && left.offers.is_empty());
        assert_eq!(take_announced(), [(Some(key(PEER)), left.generation)]);
        let back = snap(Some(friend_offer(dd, confirmed, &[PEER])), T0 + 5);
        assert!(back.generation > left.generation);
        assert_eq!(take_announced(), [(Some(key(PEER)), back.generation)]);
        // The relay goes down: every contact is told.
        let down = snap(None, T0 + 6);
        assert!(down.generation > back.generation && down.offers.is_empty());
        assert_eq!(take_announced(), [(None, down.generation)]);
    }

    /// The friend relay gate off (since 2026-10 only a debug build's
    /// `RAVEN_LAB_FRIEND_RELAY=0` closes it; a link reads it): no
    /// RELAY_OFFER is sent, neither digest sees the relay, and none is kept.
    #[test]
    fn no_offer_with_the_friend_relay_switch_off() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        let base = ctx(OutboxCarrier::P2p, Role::Listener, "");
        let without = snapshot_for(dd, &base).unwrap();
        take_announced();
        let off = SnapCtx {
            offer: Some(friend_offer(
                dd,
                relay_record(0x61, 1, route_hints::FLAG_AUTONAT),
                &[PEER],
            )),
            ..base.clone()
        };
        assert!(!off.offers_live);
        let h = snapshot_for(dd, &off).unwrap();
        assert!(h.offers.is_empty());
        assert_eq!(h.generation, without.generation, "the generation stays");
        assert!(take_announced().is_empty());
        // A link reads the switch; without it relay offers are off.
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        let both = raven_core::CAP_INTERNET | CAP_LINK_RRH1;
        let ctl = LinkCtl::inet(
            dd,
            OutboxCarrier::P2p,
            Role::Listener,
            keys,
            true,
            both,
            None,
        );
        let live = raven_core::relay_offers_live();
        assert_eq!(
            (ctl.snap_ctx().offers_live, ctl.apply_ctx().offers_live),
            (live, live)
        );
        // This process: on as in a release build, unless its environment
        // closes the friend relay or route hints (or p2p) in a debug build.
        if std::env::var("RAVEN_LAB_FRIEND_RELAY").as_deref() == Ok("0") {
            assert!(!live);
        }
        assert_eq!(
            live,
            raven_core::p2p_gate::friend_relay_live_enabled() && route_hints::route_hints_live()
        );
        // A receiver with the switch off keeps none (the cache is gated by
        // the route-hints switch, so this part needs it).
        if !route_hints::route_hints_live() {
            return;
        }
        let frame = route_hints::encode(&RouteHints {
            generation: 9,
            ttl_s: 3600,
            p2p_id: Some(peer_id_bytes(&pid(PEER)).unwrap()),
            offers: vec![relay_record(0x61, 1, route_hints::FLAG_AUTONAT)],
            ..RouteHints::default()
        });
        let apply = ApplyCtx {
            carrier: OutboxCarrier::P2p,
            keys,
            peer_ip: None,
            peer_zone: None,
            link_peer_id: Some(pid(PEER)),
            lab_local: false,
            offers_live: false,
            nat_live: false,
            stun_live: true,
            rotation_live: false,
            seeds_live: false,
            now_ms: T0,
        };
        apply_frame(dd, &frame, &apply).unwrap();
        assert!(learned_routes::learned(dd, &keys.peer, T0).is_some());
        assert!(learned_routes::offers(dd, T0).is_empty());
    }

    /// Phase 4 (P4.24): NAT_CLASS goes to a verified contact this node shows
    /// its IP, and only while the NAT_CLASS gate is live: with it closed the
    /// snapshot (bytes and generation) is Phase 2's. A class of its own
    /// moves the generation. A receiver with the gate closed keeps none.
    #[test]
    fn nat_class_is_sent_and_kept_only_while_its_gate_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        let class = NatClass {
            v4_tcp: 4,
            v4_quic: 4,
            ..NatClass::default()
        };
        let base = ctx(OutboxCarrier::P2p, Role::Listener, "");
        let with_nat = |live: bool| SnapCtx {
            own: Some(OwnP2p {
                nat: Some(class),
                ..own()
            }),
            nat_live: live,
            ..base.clone()
        };
        let without = snapshot_for(dd, &base).unwrap();
        let closed = snapshot_for(dd, &with_nat(false)).unwrap();
        assert_eq!(closed.nat_class, None);
        assert_eq!(route_hints::encode(&closed), route_hints::encode(&without));
        let open = snapshot_for(dd, &with_nat(true)).unwrap();
        assert_eq!(open.nat_class, Some(class));
        assert!(open.generation > without.generation, "a new input");
        let frame = route_hints::encode(&open);
        assert_eq!(route_hints::decode(&frame).unwrap().nat_class, Some(class));
        // Hidden from this contact: no NAT_CLASS either.
        write_p2p_book(dd, &[(PEER, true, true, &pid(PEER))]);
        assert_eq!(snapshot_for(dd, &with_nat(true)).unwrap().nat_class, None);
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        // Receiving (the cache itself is gated by the route-hints switch).
        if !route_hints::route_hints_live() {
            return;
        }
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        let peer_frame = route_hints::encode(&RouteHints {
            generation: 9,
            ttl_s: 3600,
            p2p_id: Some(peer_id_bytes(&pid(PEER)).unwrap()),
            nat_class: Some(class),
            inet: vec![route_hints::InetDirect {
                flags: 0,
                addr: "1.1.1.1:7422".parse().unwrap(),
            }],
            ..RouteHints::default()
        });
        // Security review 2026-10-29 #9: the STUN discovery gate (spec
        // §13.3) closed with the NAT_CLASS gate here: no INET_DIRECT kept.
        let apply = |nat_live: bool, now_ms: u64| ApplyCtx {
            carrier: OutboxCarrier::P2p,
            keys,
            peer_ip: None,
            peer_zone: None,
            link_peer_id: Some(pid(PEER)),
            lab_local: false,
            offers_live: false,
            nat_live,
            stun_live: nat_live,
            rotation_live: false,
            seeds_live: false,
            now_ms,
        };
        apply_frame(dd, &peer_frame, &apply(false, T0)).unwrap();
        let held = learned_routes::learned(dd, &keys.peer, T0).unwrap();
        assert_eq!(held.nat_class, None, "gate closed: not stored");
        assert!(held.inet.is_empty(), "STUN gate closed: no INET_DIRECT");
        let peer_frame = route_hints::encode(&RouteHints {
            generation: 10,
            ..route_hints::decode(&peer_frame).unwrap()
        });
        apply_frame(dd, &peer_frame, &apply(true, T0 + 1)).unwrap();
        let held = learned_routes::learned(dd, &keys.peer, T0 + 1).unwrap();
        assert_eq!(held.nat_class, Some(class));
        assert_eq!(held.inet.len(), 1, "STUN gate open: kept");
    }

    /// Phase 4 (P4.27): PEER_SCHEDULE goes to every verified contact while
    /// the PeerId rotation gate is live (hide-IP or not: PeerIds only), and
    /// moves the generation; with the gate closed the snapshot (bytes and
    /// generation) is Phase 2's. A pinned contact's is kept under the link's
    /// authenticated key, a snapshot without one forgets it, and a receiver
    /// with the gate closed keeps none.
    #[test]
    fn peer_schedule_is_sent_and_kept_by_the_link_key_only_while_its_gate_is_live() {
        use raven_core::peer_rotation::{load_schedules, PEER_SCHEDULES_FILE};
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        let capable = route_hints::PeerSchedule::capability_only(600);
        let base = ctx(OutboxCarrier::P2p, Role::Listener, "");
        let with = |schedule: Option<route_hints::PeerSchedule>| SnapCtx {
            schedule,
            ..base.clone()
        };
        let without = snapshot_for(dd, &base).unwrap();
        assert_eq!(without.peer_schedule, None);
        let open = snapshot_for(dd, &with(Some(capable.clone()))).unwrap();
        assert_eq!(open.peer_schedule, Some(capable.clone()));
        assert!(open.generation > without.generation, "a new input");
        let frame = route_hints::encode(&open);
        assert_eq!(
            route_hints::decode(&frame).unwrap().peer_schedule,
            Some(capable.clone())
        );
        // Hidden from this contact: still sent (no address in it).
        write_p2p_book(dd, &[(PEER, true, true, &pid(PEER))]);
        let hidden = snapshot_for(dd, &with(Some(capable.clone()))).unwrap();
        assert_eq!(hidden.peer_schedule, Some(capable.clone()));
        assert!(hidden.direct.is_empty());
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        // The gate in this build: closed unless the lab switch is on.
        assert_eq!(
            own_schedule().is_some(),
            raven_core::peer_rotation_live_enabled()
        );

        // Kept under the link's key, never a PeerId; forgotten by a
        // snapshot without one.
        let rotating = raven_core::peer_rotation::announced_schedule(
            &Identity::from_seed(&[PEER; 32]),
            Some((40, false)),
            600,
        );
        note_schedule(dd, &key(PEER), Some(&rotating), T0);
        let kept = load_schedules(dd).unwrap();
        assert_eq!(kept.keys().collect::<Vec<_>>(), [&hex::encode(key(PEER))]);
        let held = &kept[&hex::encode(key(PEER))];
        assert_eq!((held.active, held.entries.len()), (40, 8));
        let raw = std::fs::read_to_string(dd.join(PEER_SCHEDULES_FILE)).unwrap();
        assert!(!raw.contains("12D3KooW"), "{raw}");
        note_schedule(dd, &key(PEER), None, T0 + 1);
        assert!(load_schedules(dd).unwrap().is_empty());

        // Through apply_frame (the cache itself is gated by the route-hints
        // switch).
        if !route_hints::route_hints_live() {
            return;
        }
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        let peer_frame = |generation: u64, s: Option<route_hints::PeerSchedule>| {
            route_hints::encode(&RouteHints {
                generation,
                ttl_s: 3600,
                p2p_id: Some(peer_id_bytes(&pid(PEER)).unwrap()),
                peer_schedule: s,
                ..RouteHints::default()
            })
        };
        let apply = |rotation_live: bool, now_ms: u64| ApplyCtx {
            carrier: OutboxCarrier::P2p,
            keys,
            peer_ip: None,
            peer_zone: None,
            link_peer_id: Some(pid(PEER)),
            lab_local: false,
            offers_live: false,
            nat_live: false,
            stun_live: true,
            rotation_live,
            seeds_live: false,
            now_ms,
        };
        apply_frame(
            dd,
            &peer_frame(9, Some(rotating.clone())),
            &apply(false, T0),
        )
        .unwrap();
        assert!(load_schedules(dd).unwrap().is_empty(), "gate closed");
        apply_frame(
            dd,
            &peer_frame(10, Some(rotating.clone())),
            &apply(true, T0),
        )
        .unwrap();
        assert_eq!(load_schedules(dd).unwrap().len(), 1);
        // An older generation changes nothing; a newer one without it
        // forgets it.
        apply_frame(dd, &peer_frame(8, None), &apply(true, T0 + 1)).unwrap();
        assert_eq!(load_schedules(dd).unwrap().len(), 1);
        apply_frame(dd, &peer_frame(11, None), &apply(true, T0 + 2)).unwrap();
        assert!(load_schedules(dd).unwrap().is_empty());
    }

    /// Review D-4: a pinned contact's PEER_SCHEDULE naming another
    /// contact's PeerId (here the epoch its card names) is dropped from the
    /// frame before anything uses it (P2P_ID acceptance, the stored
    /// schedule); one naming its own epochs stays.
    #[test]
    fn a_schedule_naming_another_contacts_peer_id_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let other = Identity::from_seed(&[OTHER; 32]);
        let other_epoch = raven_core::peer_rotation::epoch_peer_id(&other, 40);
        write_p2p_book(
            dd,
            &[
                (PEER, true, false, &pid(PEER)),
                (OTHER, true, false, &other_epoch),
            ],
        );
        let frame = |s: route_hints::PeerSchedule| RouteHints {
            generation: 1,
            ttl_s: 3600,
            p2p_id: Some(peer_id_bytes(&other_epoch).unwrap()),
            peer_schedule: Some(s),
            ..RouteHints::default()
        };
        let claimed = raven_core::peer_rotation::announced_schedule(&other, Some((40, false)), 600);
        let mut hints = frame(claimed);
        assert!(drop_foreign_schedule(dd, &key(PEER), &mut hints));
        assert_eq!(hints.peer_schedule, None);
        let own = raven_core::peer_rotation::announced_schedule(
            &Identity::from_seed(&[PEER; 32]),
            Some((40, false)),
            600,
        );
        let mut hints = frame(own.clone());
        assert!(!drop_foreign_schedule(dd, &key(PEER), &mut hints));
        assert_eq!(hints.peer_schedule, Some(own));
    }

    /// The receiver's side (spec §11.3) as raven-node runs it: offers are
    /// kept while relay offers are live, never one of this node's own
    /// friend relay (the key its status names, also after it stopped).
    #[test]
    fn received_offers_are_kept_while_live_and_never_our_own_relay() {
        if !route_hints::route_hints_live() {
            eprintln!("skipped: route hints are off (RAVEN_LAB_ROUTE_HINTS=1, debug)");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        // Here PEER is the operator and LOCAL this node, which ran a friend
        // relay under the key of 0x62 once.
        book(dd, true);
        let relay_dir = raven_core::relay_allow::friend_relay_dir(dd);
        std::fs::create_dir_all(&relay_dir).unwrap();
        let status = raven_core::relay_allow::RelayStatusFile {
            version: 1,
            peer_id: pid(0x62),
            ..Default::default()
        };
        raven_core::relay_allow::write_relay_status(&relay_dir, &status).unwrap();
        assert_eq!(
            crate::friend_relay::own_relay_key(dd),
            raven_core::p2p_route::parse_peer_id(&pid(0x62)).ok()
        );
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        let theirs = relay_record(0x61, 1, route_hints::FLAG_AUTONAT);
        let frame = route_hints::encode(&RouteHints {
            generation: 9,
            ttl_s: 3600,
            p2p_id: Some(peer_id_bytes(&pid(PEER)).unwrap()),
            offers: vec![relay_record(0x62, 2, 0), theirs.clone()],
            ..RouteHints::default()
        });
        let apply = ApplyCtx {
            carrier: OutboxCarrier::P2p,
            keys,
            peer_ip: None,
            peer_zone: None,
            link_peer_id: Some(pid(PEER)),
            lab_local: false,
            offers_live: true,
            nat_live: false,
            stun_live: true,
            rotation_live: false,
            seeds_live: false,
            now_ms: T0,
        };
        apply_frame(dd, &frame, &apply).unwrap();
        let kept = learned_routes::offers(dd, T0);
        assert_eq!(kept.len(), 1, "{kept:?}");
        let (operator, operator_peer, offer, expires) = &kept[0];
        assert_eq!(
            (operator.as_str(), operator_peer.as_str()),
            (hex::encode(key(PEER)).as_str(), pid(PEER).as_str())
        );
        assert_eq!(offer.relay_peer_id, pid(0x61));
        assert_eq!(offer.addrs, theirs.addrs);
        assert_eq!(*expires, T0 + 3_600_000);
    }

    /// Spec §11.3 "never re-sent": relays contacts offered this node never
    /// reach what it tells anyone; only its own friend relay is offered.
    #[test]
    fn offers_learned_from_contacts_are_never_passed_on() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_p2p_book(
            dd,
            &[
                (PEER, true, false, &pid(PEER)),
                (OTHER, true, false, &pid(OTHER)),
            ],
        );
        let ours = relay_record(0x61, 1, route_hints::FLAG_AUTONAT);
        let to_peer = offering(
            &ctx(OutboxCarrier::P2p, Role::Listener, ""),
            Some(friend_offer(dd, ours.clone(), &[PEER])),
        );
        let before = snapshot_for(dd, &to_peer).unwrap();
        // OTHER, and PEER itself, offered this node relays of theirs.
        let entry = |seed: u8, relay: u8| {
            json!({
                "pub_hex": hex::encode(key(seed)),
                "generation": 1,
                "received_at_ms": T0,
                "expires_at_ms": T0 + 3_600_000,
                "via": "p2p",
                "peer_id": pid(seed),
                "peer_id_proven": true,
                "offers": [{
                    "relay_peer_id": pid(relay),
                    "addrs": [format!("/ip4/11.9.9.{relay}/tcp/7427")],
                    "flags": route_hints::FLAG_AUTONAT,
                }],
            })
        };
        let learned = json!([entry(OTHER, 0x70), entry(PEER, 0x71)]);
        std::fs::write(
            dd.join(learned_routes::LEARNED_ROUTES_FILE),
            serde_json::to_vec(&learned).unwrap(),
        )
        .unwrap();
        assert_eq!(learned_routes::offers(dd, T0).len(), 2);
        let after = snapshot_for(dd, &to_peer).unwrap();
        assert_eq!(after, before);
        assert_eq!(after.offers, [ours]);
        let wire = route_hints::encode(&after);
        assert!(!wire.windows(5).any(|w| w == b"11.9."), "a learned relay");
    }

    #[test]
    fn generation_is_time_floored_monotonic_and_moves_on_every_enumerated_input() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        book(dd, true);
        let mut now = T0;
        let last = std::cell::Cell::new(0);
        // Each step: a snapshot at a later time; `moves` says whether its
        // generation must move (to at least `at`) or stay.
        let step = |what: &str, c: &SnapCtx, at: u64, moves: bool| {
            let mut c = c.clone();
            c.now_ms = at;
            let g = snapshot_for(dd, &c).unwrap().generation;
            let prev = last.replace(g);
            if moves {
                assert!(g > prev && g >= at, "{what}: {g} after {prev} at {at}");
            } else {
                assert_eq!(g, prev, "{what}");
            }
        };
        let base = lan(Role::Listener);
        step("first snapshot", &base, now, true);
        assert_eq!(last.get(), T0, "floored to the clock");
        now += 1_000;
        step("nothing changed", &base, now, false);

        // Per link, outside the digests: the LAN port, the link's address,
        // the dialer role.
        let mut c = base.clone();
        c.listeners = vec!["0.0.0.0:7999".parse().unwrap()];
        step("LAN port", &c, now, false);
        c.peer_ip = "192.168.7.21".parse().ok();
        c.role = Role::Dialer;
        step("link address and role", &c, now, false);
        step(
            "another carrier",
            &ctx(OutboxCarrier::P2p, Role::Dialer, ""),
            now,
            false,
        );

        // Every input every verified contact shares.
        let mut c = base.clone();
        c.own.as_mut().unwrap().relays.truncate(1);
        now += 1;
        step("relays", &c, now, true);
        // The local listen addresses the same-LAN DIRECT entries come from
        // (E2: told again only when a generation moves).
        let listen = c.own.as_ref().unwrap().listen.clone();
        c.own
            .as_mut()
            .unwrap()
            .listen
            .retain(|l| !l.contains("192.168.7.7"));
        now += 1;
        step("local listen addresses", &c, now, true);
        c.own
            .as_mut()
            .unwrap()
            .listen
            .push("/ip4/203.0.113.5/tcp/7423".into());
        now += 1;
        step("a listen address off the local network", &c, now, false);
        c.own.as_mut().unwrap().listen = listen;
        now += 1;
        step("local listen addresses back", &c, now, true);
        c.own.as_mut().unwrap().confirmed.truncate(1);
        now += 1;
        step("confirmed addresses", &c, now, true);
        c.lab_local = true;
        now += 1;
        step("lab_local", &c, now, true);
        c.custody_hints = false;
        now += 1;
        step("custody gate", &c, now, true);
        c.own = None;
        now += 1;
        step("p2p host stopped", &c, now, true);
        save_policy(
            dd,
            &NodePolicy {
                hide_ip: true,
                ..NodePolicy::default()
            },
        )
        .unwrap();
        now += 1;
        step("hide my IP for everyone", &c, now, true);
        save_policy(dd, &NodePolicy::default()).unwrap();
        now += 1;
        step("hide my IP off again", &c, now, true);

        // Every input of this contact's snapshot.
        let c = base.clone();
        now += 1;
        step("back to the base inputs", &c, now, true);
        write_book(
            dd,
            &[
                (PEER, true, true, &[CUSTODIAN]),
                (CUSTODIAN, true, false, &[]),
            ],
        );
        now += 1;
        step("hide my IP from the contact", &c, now, true);
        write_book(
            dd,
            &[(PEER, true, false, &[]), (CUSTODIAN, true, false, &[])],
        );
        now += 1;
        step("custodians", &c, now, true);
        book(dd, false);
        now += 1;
        step("verified -> unverified (scope)", &c, now, true);
        book(dd, true);
        now += 1;
        step("verified again", &c, now, true);

        // Another contact's first snapshot does not move anyone's; its own
        // change does.
        write_book(
            dd,
            &[
                (PEER, true, false, &[CUSTODIAN]),
                (CUSTODIAN, true, false, &[]),
                (OTHER, true, false, &[]),
            ],
        );
        let mut other = base.clone();
        other.keys.peer = key(OTHER);
        now += 1;
        step("a new contact", &other, now, false);
        step("the first contact again", &c, now, false);
        write_book(
            dd,
            &[
                (PEER, true, false, &[CUSTODIAN]),
                (CUSTODIAN, true, false, &[]),
                (OTHER, true, true, &[]),
            ],
        );
        now += 1;
        step("the new contact's own change", &other, now, true);

        // The clock: a later one floors the next generation; one that went
        // back still moves it forward by one.
        let mut c = base.clone();
        c.lab_local = true;
        step("a clock far ahead", &c, now + 3_600_000, true);
        assert_eq!(last.get(), now + 3_600_000);
        c.lab_local = false;
        let before = last.get();
        step("a clock that went back", &c, T0, true);
        assert_eq!(last.get(), before + 1);

        // Saved before use: another data dir in between reloads it as is.
        let other_dir = tempfile::tempdir().unwrap();
        book(other_dir.path(), true);
        assert!(snapshot_for(other_dir.path(), &base).is_some());
        step("reloaded from the file", &c, T0, false);
        let state: GenState =
            serde_json::from_slice(&std::fs::read(dd.join(GEN_STATE_FILE)).unwrap()).unwrap();
        assert_eq!(state.generation, last.get());
        assert_eq!(state.contacts[0].pub_hex, hex::encode(key(PEER)));
    }

    /// Privacy pack PP.5: in a sealed profile the state is sealed (it holds
    /// this node's LAN listener address and every contact's digest), and a
    /// state this process cannot open is never written over (the
    /// advisory-file rule): no generation is used, and the skip is counted
    /// when the file itself does not open (not while the key is only late);
    /// once it reads again the state moves on, sealed.
    #[test]
    fn a_sealed_state_this_process_cannot_open_is_never_written_over() {
        use crate::at_rest_boot::tests::{lab_hist_key, profile_with, seal, serial};
        use raven_core::at_rest;
        if !lab_hist_key() {
            return;
        }
        let dir = profile_with(&[key(PEER)]);
        let dd = dir.path();
        {
            let _serial = serial();
            seal(dd);
        }
        let lan = Some("192.168.1.44:7420");
        let peer = key(PEER);
        let (first, _) = next_generation(dd, "g1", lan, Some((&peer, "d1")), T0).unwrap();
        let raw = std::fs::read(dd.join(GEN_STATE_FILE)).unwrap();
        assert!(at_rest::is_sealed(&raw));
        for needle in [&b"192.168.1.44"[..], hex::encode(peer).as_bytes()] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle));
        }
        // A restart that has not loaded the key yet: nothing used, nothing
        // written, and nothing to report (the key is only late).
        at_rest::forget_cached_keys(dd);
        *lock(&GEN) = None;
        assert_eq!(
            next_generation(dd, "g2", lan, Some((&peer, "d2")), T0 + 1),
            None
        );
        assert_eq!(std::fs::read(dd.join(GEN_STATE_FILE)).unwrap(), raw);
        assert_eq!(at_rest::skipped_writes(dd), 0);
        {
            let _serial = serial();
            at_rest::keys_load_with(dd, at_rest::MigratePolicy::Allow).unwrap();
        }
        // A changed byte: the same, and the kept file is counted.
        let mut changed = raw.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(dd.join(GEN_STATE_FILE), &changed).unwrap();
        assert_eq!(
            next_generation(dd, "g2", lan, Some((&peer, "d2")), T0 + 1),
            None
        );
        assert_eq!(std::fs::read(dd.join(GEN_STATE_FILE)).unwrap(), changed);
        assert_eq!(at_rest::skipped_writes(dd), 1);
        // The file as it was: the sealed state reads, moves on and is saved
        // sealed.
        std::fs::write(dd.join(GEN_STATE_FILE), &raw).unwrap();
        let (next, moved) = next_generation(dd, "g2", lan, Some((&peer, "d2")), T0 + 2).unwrap();
        assert!(next > first && moved == Moved::Global, "{next} {moved:?}");
        let again = std::fs::read(dd.join(GEN_STATE_FILE)).unwrap();
        assert!(at_rest::is_sealed(&again) && again != raw);
    }

    /// A contact removed from the book, or blocked, leaves
    /// route_hints_state.json at the next look at the state, whoever it is
    /// for, even when nothing else changed (storage rule: real erase).
    #[test]
    fn a_removed_or_blocked_contact_leaves_the_generation_state() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let for_whom = |seed: u8| SnapCtx {
            keys: LinkKeys::new(key(seed), &Identity::from_seed(&[LOCAL; 32])),
            ..ctx(OutboxCarrier::Internet, Role::Dialer, "11.0.3.9")
        };
        let saved = || std::fs::read_to_string(dd.join(GEN_STATE_FILE)).unwrap();
        let (peer, custodian) = (hex::encode(key(PEER)), hex::encode(key(CUSTODIAN)));
        book(dd, true);
        for seed in [PEER, CUSTODIAN, CUSTODIAN] {
            assert!(snapshot_for(dd, &for_whom(seed)).is_some());
        }
        assert!(saved().contains(&peer) && saved().contains(&custodian));
        let generation = saved_generation(dd);

        // Removed: the custodian's next snapshot (nothing of its own
        // changed) saves the state without it.
        write_book(dd, &[(CUSTODIAN, true, false, &[])]);
        assert!(snapshot_for(dd, &for_whom(CUSTODIAN)).is_some());
        assert!(!saved().contains(&peer), "{}", saved());
        assert!(saved().contains(&custodian));
        assert_eq!(saved_generation(dd), generation, "no generation moved");

        // Blocked: the same.
        book(dd, true);
        assert!(snapshot_for(dd, &for_whom(PEER)).is_some());
        assert!(saved().contains(&peer));
        let mut blocks = raven_core::BlockList::default();
        blocks.block(&peer);
        blocks.save(dd).unwrap();
        assert!(snapshot_for(dd, &for_whom(CUSTODIAN)).is_some());
        assert!(!saved().contains(&peer), "{}", saved());

        // An unreadable book keeps the state as it is.
        raven_core::BlockList::default().save(dd).unwrap();
        assert!(snapshot_for(dd, &for_whom(PEER)).is_some());
        std::fs::write(dd.join("contacts.json"), "{not json").unwrap();
        assert_eq!(
            next_generation(dd, "x", None, None, T0).map(|g| g.1),
            Some(Moved::Global)
        );
        assert!(saved().contains(&peer));
    }

    /// A contact is told a generation only once a link carried it (spec §7):
    /// an RRH1 built for a link whose write then failed (no
    /// [`LinkCtl::written`]) leaves the contact due again at the next retry;
    /// once one is written, it is done.
    #[tokio::test]
    async fn a_contact_is_told_only_once_the_rrh1_is_written() {
        // A contact of this test only: SENT_GEN is process-wide.
        const ONLY_HERE: u8 = 0x5e;
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[(ONLY_HERE, true, false, &[])]);
        let keys = LinkKeys::new(key(ONLY_HERE), &Identity::from_seed(&[LOCAL; 32]));
        let both = raven_core::CAP_INTERNET | CAP_LINK_RRH1;
        let link = || {
            LinkCtl::inet(
                dd,
                OutboxCarrier::Internet,
                Role::Dialer,
                keys,
                true,
                both,
                None,
            )
        };
        let mut failed = link();
        let frame = failed.outgoing().await.expect("our RRH1");
        let generation = route_hints::decode(&frame).unwrap().generation;
        drop(failed); // its write failed: never `written`
        assert_eq!(sent_generation(&keys.peer), None);
        let mut schedule = Schedule::default();
        let t0 = Instant::now();
        schedule.add(generation, &[keys.peer], t0);
        assert_eq!(schedule.due(t0, sent_generation), [keys.peer]);
        assert_eq!(
            schedule.due(t0 + RETRY[0], sent_generation),
            [keys.peer],
            "due again at the next retry"
        );
        // The next link writes it: done.
        let mut ok = link();
        let frame = ok.outgoing().await.expect("our RRH1");
        ok.written();
        assert_eq!(route_hints::decode(&frame).unwrap().generation, generation);
        assert_eq!(sent_generation(&keys.peer), Some(generation));
        assert!(schedule.due(t0 + RETRY[1], sent_generation).is_empty());
    }

    /// E1 (three machines): a contact on two addresses of one network (a Mac
    /// on cable and Wi-Fi) gives every LAN link another LAN part, so each of
    /// its RRH1 frames is a change. The retry and custody wake that a change
    /// gives open a link at once, which carried the next "change": links and
    /// RRH1 frames back to back for minutes. A change now kicks a contact at
    /// most once per [`PER_PEER_MIN`] (the announce links' own spacing); the
    /// routes are still stored from every frame.
    ///
    /// Since the E2 night fix (`learned_routes::merge`) the same snapshot
    /// over the other address adds nothing and leaves the held LAN part as
    /// it is (the cable one stays), so only a new snapshot moves it; field
    /// round 9 found this test still expecting every link to move it. Here
    /// each link brings a newer snapshot, so each is a change and the LAN
    /// part follows the link; the same snapshot again over the other address
    /// keeps it.
    #[tokio::test]
    async fn a_multi_homed_contact_is_kicked_at_most_once_a_minute() {
        if !route_hints::route_hints_live() {
            eprintln!("skipped: route hints are off (RAVEN_LAB_ROUTE_HINTS=1, debug)");
            return;
        }
        const HOMED: u8 = 0x7B;
        let _live = LiveForTest::set(true);
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[(HOMED, true, false, &[])]);
        let keys = LinkKeys::new(key(HOMED), &Identity::from_seed(&[LOCAL; 32]));
        let cable: Option<IpAddr> = "192.168.7.14".parse().ok();
        let wifi: Option<IpAddr> = "192.168.7.24".parse().ok();
        KICKS.with(|k| k.set(0));
        let mut generation = 7;
        for i in 0..20 {
            let ip = if i % 2 == 0 { cable } else { wifi };
            generation += 1;
            let mut link = LinkCtl::lan_dialer(dd, keys, None, ip, true, false);
            assert!(link.take(&frame(generation, Some(7431))).await);
            let stored = learned_routes::learned(dd, &keys.peer, crate::now_ms())
                .and_then(|l| l.lan)
                .and_then(|lan| lan.ip);
            assert_eq!(stored, ip, "link {i}");
        }
        // The same snapshot over the other address: the held part stays.
        let mut link = LinkCtl::lan_dialer(dd, keys, None, cable, true, false);
        assert!(link.take(&frame(generation, Some(7431))).await);
        let stored = learned_routes::learned(dd, &keys.peer, crate::now_ms())
            .and_then(|l| l.lan)
            .and_then(|lan| lan.ip);
        assert_eq!(stored, wifi, "the same snapshot keeps the held LAN part");
        assert_eq!(KICKS.with(std::cell::Cell::get), 1, "one kick per minute");
        let later = Instant::now() + PER_PEER_MIN;
        assert!(kick_due(&keys.peer, later), "a minute later: kicked again");
        assert!(!kick_due(&keys.peer, later + Duration::from_secs(1)));
    }

    /// E1 (three machines): "told a contact our routes ... (and 62 more like
    /// it in the last 30s)" named nobody and no carrier. Each line now names
    /// the contact by its short tag (never its key or address), the
    /// carrier, which side opened the link and what our own dial carried,
    /// one line per such label per 30 s, each folding its own repeats.
    #[test]
    fn hint_lines_name_the_contact_carrier_side_and_purpose() {
        let peer = key(0x3D);
        let label = |carrier, role, purpose| LinkLabel {
            peer,
            carrier,
            role,
            purpose,
        };
        let tag = netutil::link_tag(&peer);
        let fetch = label(OutboxCarrier::Lan, Role::Dialer, Some("custody"));
        let theirs = label(OutboxCarrier::P2p, Role::Listener, None);
        assert_eq!(
            fetch.words(),
            format!("contact {tag}, lan, we dialled (custody)")
        );
        assert_eq!(theirs.words(), format!("contact {tag}, p2p, it dialled"));
        for words in [fetch.words(), theirs.words()] {
            assert!(!words.contains(&hex::encode(peer)[..8]), "{words}");
        }
        // One line per label per window, each with its own count.
        let log = KeyedLog::new();
        let t0 = Instant::now();
        let (a, b) = (fetch.words(), theirs.words());
        assert_eq!(log.hit(&a, t0), Some(1));
        assert_eq!(log.hit(&b, t0), Some(1), "another label: a line of its own");
        for i in 1..=5 {
            assert_eq!(log.hit(&a, t0 + Duration::from_secs(i)), None);
        }
        assert_eq!(log.hit(&b, t0 + Duration::from_secs(2)), None);
        let later = t0 + KEYED_LOG_WINDOW;
        assert_eq!(log.hit(&a, later), Some(6), "the five folded, and this one");
        assert_eq!(log.hit(&b, later), Some(2));
        // Never more labels than KEYED_LOG_MAX at a time.
        for i in 0..2 * KEYED_LOG_MAX {
            log.hit(&format!("label {i}"), later);
        }
        assert!(lock(&log.state).as_ref().unwrap().len() <= KEYED_LOG_MAX + 1);
    }

    /// What our dial carries, in a word: its first frame's kind.
    #[test]
    fn a_dials_purpose_is_its_first_frames_kind() {
        use raven_core::envelope::{EnvType, Envelope};
        let envelope = |kind: EnvType| {
            Envelope {
                env_type: kind as u8,
                flags: 0,
                message_id: [1; 16],
                routing_tag: [2; 16],
                dest_device_hint: 0,
                created_at: 1,
                expires_at: u64::MAX / 2,
                hop_limit: 4,
                replication_budget: 1,
                anti_replay_nonce: [3; 12],
                ratchet_header_ciphertext: vec![],
                message_ciphertext: vec![4; 8],
                sender_authentication: vec![0; 64],
            }
            .pack()
        };
        assert_eq!(dial_purpose(&[], true), "announce");
        assert_eq!(dial_purpose(&[], false), "no frames");
        assert_eq!(
            dial_purpose(&[envelope(EnvType::Message)], false),
            "message"
        );
        assert_eq!(dial_purpose(&[envelope(EnvType::Ack)], false), "ack");
        let mut rfc1 = raven_core::friend_custody::RFC1_MAGIC.to_vec();
        rfc1.extend_from_slice(&[0; 8]);
        assert_eq!(dial_purpose(&[rfc1], false), "custody");
        let mut rup1 = raven_core::update_exchange::RUP1_MAGIC.to_vec();
        rup1.push(1);
        assert_eq!(dial_purpose(&[rup1], false), "update");
        assert_eq!(dial_purpose(&[b"something else".to_vec()], false), "other");
    }

    /// Phase 3 P3.4: the zone of a LAN link's IPv6 link-local peer reaches
    /// the link its route hints are stored for, on either end; no zone, none.
    #[test]
    fn a_lan_links_zone_reaches_the_hint_link() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        let fe80: Option<IpAddr> = "fe80::1".parse().ok();
        let contact = ContactRoutes::default();
        for zone in [Some("en0"), None] {
            for ctl in [
                LinkCtl::lan_listener(dd, keys, fe80, &[]),
                LinkCtl::lan_dialer(dd, keys, None, fe80, true, false),
            ] {
                let ctx = ctl.with_peer_zone(zone.map(String::from)).apply_ctx();
                let link = ctx.link(&contact, None);
                assert_eq!((link.peer_ip, link.peer_zone), (fe80, zone));
            }
        }
    }

    fn ifaddr(name: &str, ip: &str, index: u32) -> raven_core::netifs::LocalAddr {
        raven_core::netifs::LocalAddr {
            ifname: name.into(),
            ip: ip.parse().unwrap(),
            prefix: 0,
            up: true,
            loopback: false,
            point_to_point: false,
            virtual_net: false,
            scope_id: 0,
            index,
            multicast: true,
            broadcast: true,
        }
    }

    /// E2 night: win-c told one friend "direct=0" on its own custody dials
    /// and "direct=2" on the friend's dials, all night: the same-LAN DIRECT
    /// entries followed the link's peer address, and its dials went to the
    /// friend's IPv6 address. They now come from this computer's interface
    /// on the friend's network as well, so a dial to the friend's IPv6
    /// address (global, unique-local or link-local with its zone) and a link
    /// from its IPv4 one, either side dialling, tell one set; a network the
    /// friend is not on (a VPN's 10.0.0.5) is never named.
    #[test]
    fn a_dial_and_an_inbound_link_tell_one_route_set() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        book(dd, true);
        let ifs = vec![
            ifaddr("en0", "192.168.7.5", 4),
            ifaddr("en0", "192.168.7.6", 4),
            ifaddr("en0", "fd00:7::5", 4),
            ifaddr("en0", "2c0f:fff0:7::5", 4),
            ifaddr("en0", "fe80::5", 4),
            ifaddr("utun3", "10.0.0.5", 9),
            ifaddr("utun3", "fe80::9", 9),
        ];
        let told = |role: Role, peer: &str, zone: Option<&str>| {
            let snap = SnapCtx {
                peer_zone: zone.map(String::from),
                local_ifs: ifs.clone(),
                ..ctx(OutboxCarrier::Lan, role, peer)
            };
            let h = snapshot_for(dd, &snap).unwrap();
            (h.direct, h.lan_port, h.generation)
        };
        let inbound = told(Role::Listener, "192.168.7.20", None);
        let local = [
            "/ip4/192.168.7.5/tcp/7423",
            "/ip4/192.168.7.6/udp/7423/quic-v1",
        ];
        assert!(local.iter().all(|l| inbound.0.contains(&l.to_string())));
        assert!(!inbound.0.iter().any(|d| d.contains("10.0.0.5")));
        for (peer, zone) in [
            ("fd00:7::20", None),
            ("2c0f:fff0:7::20", None),
            ("fe80::20", Some("en0")),
            ("fe80::20", Some("4")),
            ("192.168.7.21", None),
        ] {
            for role in [Role::Dialer, Role::Listener] {
                assert_eq!(told(role, peer, zone), inbound, "{role:?} {peer} {zone:?}");
            }
        }
        // A link-local peer on another interface, or without its zone, is
        // on no network of en0's.
        for zone in [Some("utun3"), None] {
            let (direct, ..) = told(Role::Dialer, "fe80::20", zone);
            assert!(!direct.iter().any(|d| d.contains("192.168.7.")), "{zone:?}");
        }
        // No interface list: the peer's /24 alone, as before.
        let snap = ctx(OutboxCarrier::Lan, Role::Dialer, "fd00:7::20");
        let h = snapshot_for(dd, &snap).unwrap();
        assert!(!h.direct.iter().any(|d| d.contains("192.168.7.")));
    }

    /// E2 night (spec §6, telling again): a contact told a snapshot is told
    /// it again only when it changed, or [`REFRESH`] after it was told; a
    /// LAN part that only lacks what was told over LAN is not news.
    #[test]
    fn tell_due_table() {
        let t0 = Instant::now();
        let hints = |generation: u64, port: Option<u16>, direct: &[&str]| RouteHints {
            generation,
            lan_port: port,
            direct: direct.iter().map(|d| d.to_string()).collect(),
            ..RouteHints::default()
        };
        let lan = OutboxCarrier::Lan;
        let a = "/ip4/192.168.7.5/tcp/7423";
        let told = Told {
            generation: 7,
            at: t0,
            lan: Some((Some(7531), vec![a.into()], t0)),
            seed: None,
        };
        let soon = t0 + Duration::from_secs(60);
        assert!(
            tell_due(None, &hints(7, Some(7531), &[a]), lan, soon),
            "never told"
        );
        assert!(!tell_due(
            Some(&told),
            &hints(7, Some(7531), &[a]),
            lan,
            soon
        ));
        assert!(
            !tell_due(Some(&told), &hints(7, None, &[]), lan, soon),
            "less"
        );
        assert!(
            tell_due(Some(&told), &hints(8, Some(7531), &[a]), lan, soon),
            "newer"
        );
        assert!(
            tell_due(Some(&told), &hints(7, Some(7532), &[a]), lan, soon),
            "port"
        );
        let b = "/ip4/192.168.7.6/tcp/7423";
        assert!(
            tell_due(Some(&told), &hints(7, Some(7531), &[a, b]), lan, soon),
            "address"
        );
        assert!(tell_due(
            Some(&told),
            &hints(7, Some(7531), &[a]),
            lan,
            t0 + REFRESH
        ));
        for carrier in [OutboxCarrier::Internet, OutboxCarrier::P2p] {
            assert!(!tell_due(Some(&told), &hints(7, None, &[]), carrier, soon));
            assert!(tell_due(Some(&told), &hints(8, None, &[]), carrier, soon));
        }
        // Never told over LAN: the LAN part is news.
        let no_lan = Told {
            lan: None,
            ..told.clone()
        };
        assert!(tell_due(
            Some(&no_lan),
            &hints(7, Some(7531), &[a]),
            lan,
            soon
        ));
        assert!(!tell_due(
            Some(&no_lan),
            &hints(7, None, &[]),
            OutboxCarrier::P2p,
            soon
        ));
        // A pair seed entry that moved is news too (spec §14).
        let seed = raven_core::pair_seed::SeedEntry::new(2, [9; 32], 1);
        let mut with_seed = hints(7, Some(7531), &[a]);
        with_seed.pair_seed = Some(seed);
        assert!(tell_due(Some(&told), &with_seed, lan, soon));
    }

    /// A LAN dial asks for route hints only when it wants the contact's or
    /// has its own to tell (spec §3.2, E2): never told, never heard, a
    /// changed generation, [`REFRESH`] gone by, or an announce link.
    #[tokio::test]
    async fn a_lan_dial_asks_only_when_hints_are_due() {
        let _live = LiveForTest::set(true);
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        book(dd, true);
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        assert!(lan_asks(dd, keys, false).await, "never told");
        // The generation this contact's snapshot has now (a dial's own).
        let generation = plan_for(dd, &lan(Role::Dialer)).unwrap().generation;
        let now = Instant::now();
        let told = |generation: u64, at: Instant| Told {
            generation,
            at,
            lan: Some((Some(7531), Vec::new(), at)),
            seed: None,
        };
        keep(&TOLD_TO, dd, &keys.peer, told(generation, now), |t| t.at);
        assert!(lan_asks(dd, keys, false).await, "never heard");
        note_heard(dd, &keys.peer, now);
        // Own routes as `lan_asks` reads them: none from a p2p host in this
        // test, as `lan(..)` has; the generation moves if they differ.
        let g = plan_for(
            dd,
            &SnapCtx {
                own: crate::p2p::own_routes(),
                lab_local: raven_core::p2p_local_candidates_enabled(),
                custody_hints: raven_core::custody_gate::custody_hints_live(),
                ..lan(Role::Dialer)
            },
        )
        .unwrap()
        .generation;
        keep(&TOLD_TO, dd, &keys.peer, told(g, now), |t| t.at);
        assert!(!lan_asks(dd, keys, false).await, "told and heard lately");
        assert!(lan_asks(dd, keys, true).await, "an announce link asks");
        keep(&TOLD_TO, dd, &keys.peer, told(g - 1, now), |t| t.at);
        assert!(lan_asks(dd, keys, false).await, "a newer generation");
        // (A monotonic clock that started less than REFRESH ago has no
        // such time.)
        if let Some(old) = now.checked_sub(REFRESH) {
            keep(&TOLD_TO, dd, &keys.peer, told(g, old), |t| t.at);
            assert!(lan_asks(dd, keys, false).await, "told long ago");
            keep(&TOLD_TO, dd, &keys.peer, told(g, now), |t| t.at);
            note_heard(dd, &keys.peer, old);
            assert!(lan_asks(dd, keys, false).await, "heard long ago");
        }
        forget_told(dd);
    }

    /// Who sends, when, and what is consumed (spec §3, §5.6).
    #[tokio::test]
    async fn link_ctl_table() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        book(dd, true);
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        let asked = lan_m3_payload(true, false, true);
        let local_ip: Option<IpAddr> = "192.168.7.20".parse().ok();
        let rrh1 = frame(7, Some(7431));
        let envelope = b"RVN1 not a route hint".to_vec();
        let both = raven_core::CAP_INTERNET | CAP_LINK_RRH1;

        // A LAN listener sends only to a dialer whose message 3 asked, once,
        // and never with the gate off.
        {
            let _live = LiveForTest::set(true);
            let mut l = LinkCtl::lan_listener(dd, keys, local_ip, &asked);
            let ours = l.outgoing().await.expect("asked: our RRH1");
            assert!(route_hints::decode(&ours).is_some());
            l.written();
            assert_eq!(
                sent_generation(&keys.peer),
                Some(route_hints::decode(&ours).unwrap().generation)
            );
            assert_eq!(l.outgoing().await, None, "never twice");
            for m3 in [
                Vec::new(),
                route_hints::rlx1_payload(0x1),
                b"RLX2\x01\x01\x04\x00\x00\x01\x00".to_vec(),
            ] {
                let mut l = LinkCtl::lan_listener(dd, keys, local_ip, &m3);
                assert_eq!(l.outgoing().await, None, "{m3:02x?}");
                // A route hint it did not ask for is still consumed.
                assert!(l.take(&rrh1).await);
            }
        }
        {
            let _off = LiveForTest::set(false);
            let mut l = LinkCtl::lan_listener(dd, keys, local_ip, &asked);
            assert_eq!(l.outgoing().await, None);
            assert!(!l.take(&rrh1).await, "gate off: today's dispatch");
        }

        // A LAN dialer sends only after the listener's arrived (another
        // raven-node: nothing told yet).
        forget_told(dd);
        let mut d = LinkCtl::lan_dialer(dd, keys, None, local_ip, true, false);
        assert_eq!(d.outgoing().await, None, "the listener has not spoken");
        assert!(
            !d.expects_peer_frame(),
            "a message dial reads replies anyway"
        );
        assert!(!d.take(&envelope).await, "not RRH1: a reply");
        assert!(d.take(&rrh1).await);
        assert!(d.outgoing().await.is_some());
        d.written();
        assert_eq!(d.outgoing().await, None);
        assert_eq!(d.counts(), (true, 1));
        // Told just now (spec §6, E2): the next dial that asks gets the
        // listener's answer, and adds nothing the listener was told lately;
        // an asked LAN listener still answers.
        let mut d = LinkCtl::lan_dialer(dd, keys, None, local_ip, true, false);
        assert!(d.take(&rrh1).await);
        assert_eq!(d.outgoing().await, None, "told lately");
        assert_eq!(d.counts(), (false, 1));
        {
            let _live = LiveForTest::set(true);
            let mut l = LinkCtl::lan_listener(dd, keys, local_ip, &asked);
            assert!(l.outgoing().await.is_some(), "an asked listener answers");
        }
        // A dial that did not ask consumes nothing and sends nothing.
        let mut d = LinkCtl::lan_dialer(dd, keys, None, local_ip, false, false);
        assert!(!d.take(&rrh1).await);
        assert_eq!(d.outgoing().await, None);
        // An announce dial waits for the listener's.
        let d = LinkCtl::lan_dialer(dd, keys, None, local_ip, true, true);
        assert!(d.expects_peer_frame());

        // Internet and p2p: the dialer sends first when the listener's hello
        // set the bit, and reads the listener's before it closes.
        for carrier in [OutboxCarrier::Internet, OutboxCarrier::P2p] {
            forget_told(dd);
            let mut d = LinkCtl::inet(dd, carrier, Role::Dialer, keys, true, both, None);
            assert!(d.expects_peer_frame());
            assert!(d.outgoing().await.is_some(), "{carrier:?}");
            assert_eq!(d.outgoing().await, None);
            assert!(d.take(&rrh1).await);
            assert!(!d.expects_peer_frame(), "read it");
            let caps = raven_core::CAP_INTERNET | 0x8000_0000;
            let mut d = LinkCtl::inet(dd, carrier, Role::Dialer, keys, true, caps, None);
            assert_eq!(d.outgoing().await, None, "the listener did not ask");
            assert!(!d.expects_peer_frame());
            let mut d = LinkCtl::inet(dd, carrier, Role::Dialer, keys, false, both, None);
            assert_eq!(d.outgoing().await, None, "gate off");
            assert!(!d.take(&rrh1).await);
            let mut l = LinkCtl::inet(dd, carrier, Role::Listener, keys, true, both, None);
            assert!(!l.expects_peer_frame());
            assert!(l.outgoing().await.is_some());
            l.written();
            // Told lately: neither end tells again (spec §6, E2).
            let mut l = LinkCtl::inet(dd, carrier, Role::Listener, keys, true, both, None);
            assert_eq!(l.outgoing().await, None, "{carrier:?}: told lately");
            let mut d = LinkCtl::inet(dd, carrier, Role::Dialer, keys, true, both, None);
            assert_eq!(d.outgoing().await, None, "{carrier:?}: told lately");
        }

        // A third RRH1 floods; garbage with the magic is consumed too.
        let mut d = LinkCtl::inet(
            dd,
            OutboxCarrier::Internet,
            Role::Dialer,
            keys,
            true,
            both,
            None,
        );
        assert!(d.take(b"RRH1 garbage").await);
        assert!(d.take(&rrh1).await);
        assert!(!d.flooded());
        assert!(d.take(&rrh1).await);
        assert!(d.flooded());
    }

    /// P6.38: two profiles that verified each other run the pair-seed
    /// exchange through their RRH1 frames: the leader's carries its proposal
    /// (stored before the frame is made), the follower adopts it and acks it
    /// in its own, the leader switches on the ack, and both then make their
    /// beacon, knock and Bluetooth keys from the same seed. A profile whose
    /// gate is shut (as an older build) sends no entry and keeps none, and
    /// the other side then sends with the root; an unverified contact gets
    /// no entry.
    #[test]
    fn pair_seeds_propose_ack_switch_across_two_nodes() {
        use raven_core::pair_seed::{is_leader, state};
        let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
        let ids = [
            Identity::from_seed(&[LOCAL; 32]),
            Identity::from_seed(&[PEER; 32]),
        ];
        write_book(dirs[0].path(), &[(PEER, true, false, &[])]);
        write_book(dirs[1].path(), &[(LOCAL, true, false, &[])]);
        let (l, f) = if is_leader(&key(LOCAL), &key(PEER)) {
            (0, 1)
        } else {
            (1, 0)
        };
        // `from` makes its RRH1 for `to` on a LAN link and `to` applies it;
        // each side's gate as given.
        let link = |from: usize, to: usize, live: [bool; 2], now: u64| -> RouteHints {
            let snap = SnapCtx {
                keys: LinkKeys::new(ids[to].public_key_bytes(), &ids[from]),
                own: None,
                custody_hints: false,
                seeds_live: live[from],
                now_ms: now,
                ..lan(Role::Listener)
            };
            let hints = snapshot_for(dirs[from].path(), &snap).unwrap();
            let apply = ApplyCtx {
                carrier: OutboxCarrier::Lan,
                keys: LinkKeys::new(ids[from].public_key_bytes(), &ids[to]),
                peer_ip: "192.168.7.20".parse().ok(),
                peer_zone: None,
                link_peer_id: None,
                lab_local: false,
                offers_live: false,
                nat_live: false,
                stun_live: true,
                rotation_live: false,
                seeds_live: live[to],
                now_ms: now,
            };
            apply_frame(dirs[to].path(), &route_hints::encode(&hints), &apply).unwrap();
            hints
        };
        let send_key = |at: usize, of: usize| {
            let seeds = crate::pair_seed::book(dirs[at].path(), true);
            let roots = seeds.roots(&ids[at], &ids[of].public_key_bytes()).unwrap();
            (*roots.send_key(), roots.is_root(roots.send))
        };
        let live = [true, true];
        // The leader proposes generation 1.
        let offer = link(l, f, live, T0)
            .pair_seed
            .expect("the leader's proposal");
        assert_eq!((offer.generation, offer.acked), (1, 0));
        assert!(state(dirs[l].path(), &ids[f].public_key_bytes())
            .unwrap()
            .proposed
            .is_some());
        assert!(send_key(l, f).1, "the root until acked");
        assert!(
            !send_key(f, l).1,
            "the follower sends with the seed at once"
        );
        // The follower acks; the leader switches.
        let ack = link(f, l, live, T0 + 1)
            .pair_seed
            .expect("the follower's ack");
        assert_eq!((ack.generation, ack.acked), (1, 1));
        assert_eq!(*ack.seed, *offer.seed);
        assert_eq!(send_key(l, f), send_key(f, l));
        assert!(!send_key(l, f).1, "both send with K_pair now");
        // The next frame tells the follower the leader uses it.
        let again = link(l, f, live, T0 + 2).pair_seed.unwrap();
        assert_eq!((again.generation, again.acked), (1, 1));
        assert_eq!(
            state(dirs[f].path(), &ids[l].public_key_bytes())
                .unwrap()
                .peer_acked,
            1
        );

        // The follower's gate shut (an older build): no entry in its frame,
        // nothing kept from the leader's, and the leader falls back to the
        // root for it.
        let old = [l == 0, l == 1];
        assert!(link(f, l, old, T0 + 3).pair_seed.is_none());
        assert!(send_key(l, f).1, "the root for a peer without seeds");
        let before =
            std::fs::read(dirs[f].path().join(raven_core::pair_seed::PAIR_SEEDS_FILE)).unwrap();
        assert!(link(l, f, old, T0 + 4).pair_seed.is_some());
        let after =
            std::fs::read(dirs[f].path().join(raven_core::pair_seed::PAIR_SEEDS_FILE)).unwrap();
        assert_eq!(before, after, "a shut gate keeps nothing");

        // An unverified contact gets no entry (only LAN_PORT).
        write_book(
            dirs[l].path(),
            &[(if f == 1 { PEER } else { LOCAL }, false, false, &[])],
        );
        assert!(link(l, f, live, T0 + 5).pair_seed.is_none());
    }

    /// What a receiver stores (needs the route-hints switch: the cache is
    /// gated): an unverified contact's frame keeps only LAN_PORT, and a p2p
    /// link whose PeerId differs from the frame's drops the p2p part.
    #[tokio::test]
    async fn received_frames_follow_the_receiver_rules() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        // Here PEER is the sender and LOCAL the receiver.
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        let full = route_hints::encode(&RouteHints {
            generation: 9,
            ttl_s: 3600,
            p2p_id: Some(peer_id_bytes(&pid(PEER)).unwrap()),
            relays: vec![relay(0x61, "/ip4/11.0.2.1/tcp/7423")],
            direct: vec!["/ip4/11.0.3.5/tcp/7423".into()],
            lan_port: Some(7431),
            custodians: vec![key(CUSTODIAN)],
            ..RouteHints::default()
        });
        let apply = |carrier, peer_ip: &str, link_peer_id: Option<String>| ApplyCtx {
            carrier,
            keys,
            peer_ip: peer_ip.parse().ok(),
            peer_zone: None,
            link_peer_id,
            lab_local: false,
            offers_live: false,
            nat_live: false,
            stun_live: true,
            rotation_live: false,
            seeds_live: false,
            now_ms: T0,
        };
        let ctx = apply(OutboxCarrier::P2p, "", Some(pid(OTHER)));
        book(dd, true);
        let contact = match contact_admission(dd, &keys.peer) {
            ContactAdmission::Allowed(c) => c,
            other => panic!("{other:?}"),
        };
        let v = route_hints::validate(
            &route_hints::decode(&full).unwrap(),
            &ctx.link(&contact, None),
        );
        assert_eq!((v.peer_id, v.relays.len(), v.direct.len()), (None, 0, 0));
        assert_eq!(v.custodians, vec![key(CUSTODIAN)]);
        let ctx = apply(OutboxCarrier::P2p, "", Some(pid(PEER)));
        let v = route_hints::validate(
            &route_hints::decode(&full).unwrap(),
            &ctx.link(&contact, None),
        );
        assert_eq!(v.peer_id, Some(pid(PEER)));

        let applied = apply_frame(dd, &full, &apply(OutboxCarrier::P2p, "", Some(pid(OTHER))));
        if !route_hints::route_hints_live() {
            assert_eq!(applied, Ok(Applied::Ignored));
            assert!(!dd.join(learned_routes::LEARNED_ROUTES_FILE).exists());
            return;
        }
        let view = learned_routes::learned(dd, &keys.peer, T0).unwrap();
        assert_eq!((view.peer_id, view.relays.len()), (None, 0));

        // An unverified contact on a LAN link: LAN_PORT only.
        let lan_dir = tempfile::tempdir().unwrap();
        book(lan_dir.path(), false);
        apply_frame(
            lan_dir.path(),
            &full,
            &apply(OutboxCarrier::Lan, "192.168.7.20", None),
        )
        .unwrap();
        let view = learned_routes::learned(lan_dir.path(), &keys.peer, T0).unwrap();
        assert_eq!((view.peer_id, view.relays.len()), (None, 0));
        assert!(view.custodians.is_empty());
        assert_eq!(view.lan.unwrap().port, Some(7431));

        // Malformed: ignored whole, nothing stored, never an error.
        let bad = tempfile::tempdir().unwrap();
        book(bad.path(), true);
        assert_eq!(
            apply_frame(
                bad.path(),
                b"RRH1\x02",
                &apply(OutboxCarrier::Lan, "192.168.7.20", None)
            ),
            Ok(Applied::Ignored)
        );
        assert!(learned_routes::learned(bad.path(), &keys.peer, T0).is_none());
    }

    /// Spec §7: every target is dialled at once, then 1, 10 and 60 min
    /// after it became due, then dropped; a link that carried its
    /// generation ends it (a lower one does not); at most 64 wait; one
    /// contact is dialled at most once a minute, a new generation included.
    #[test]
    fn announce_targets_and_retry_schedule() {
        let t0 = Instant::now();
        let min = |m: u64| Duration::from_secs(60 * m);
        let peers: Vec<[u8; 32]> = (0..70u8).map(|i| [i; 32]).collect();
        let mut sched = Schedule::default();
        sched.add(5, &peers, t0);
        assert_eq!(sched.targets.len(), MAX_TARGETS, "newest 64 only");
        let sent: std::cell::RefCell<HashMap<[u8; 32], u64>> = Default::default();
        let told = |p: &[u8; 32]| sent.borrow().get(p).copied();
        let first = sched.due(t0, told);
        assert_eq!(
            first,
            peers[..MAX_TARGETS].to_vec(),
            "all at once, in order"
        );
        assert!(sched.due(t0 + Duration::from_secs(59), told).is_empty());

        // Contact 0 got generation 5 on some link, contact 1 an older one.
        sent.borrow_mut().insert(peers[0], 5);
        sent.borrow_mut().insert(peers[1], 4);
        let retry = sched.due(t0 + min(1), told);
        assert_eq!(retry.len(), MAX_TARGETS - 1);
        assert!(!retry.contains(&peers[0]) && retry.contains(&peers[1]));
        assert!(sched.due(t0 + min(9), told).is_empty());
        assert_eq!(sched.due(t0 + min(10), told).len(), MAX_TARGETS - 1);
        assert!(sched.due(t0 + min(59), told).is_empty());
        assert_eq!(sched.due(t0 + min(60), told).len(), MAX_TARGETS - 1);
        // Four links each: then dropped, whatever the time.
        assert!(sched.due(t0 + min(600), told).is_empty());
        assert!(sched.targets.is_empty());

        // A new generation for a contact dialled a moment ago waits out the
        // minute; it is due at once after that.
        let t1 = t0 + min(700);
        sched.add(6, &peers[1..2], t1);
        assert_eq!(sched.due(t1, told), vec![peers[1]]);
        sched.add(7, &peers[1..2], t1 + Duration::from_secs(10));
        assert!(sched.due(t1 + Duration::from_secs(10), told).is_empty());
        assert_eq!(sched.due(t1 + min(1), told), vec![peers[1]]);
        assert_eq!(sched.targets[0].generation, 7);
        sent.borrow_mut().insert(peers[1], 6);
        assert_eq!(
            sched.due(t1 + min(2), told),
            vec![peers[1]],
            "6 is not 7: retried"
        );
        sent.borrow_mut().insert(peers[1], 7);
        assert!(sched.due(t1 + min(11), told).is_empty());
        assert!(sched.targets.is_empty(), "told");
    }

    // ── Cutoff F8: who an announce round tells ──

    /// Custody live, M0 on, and the letter ops served.
    const HELD_LIVE: HeldGates = HeldGates {
        custody: true,
        noise_pin: true,
        letters: true,
    };

    /// This node holds custody mail from OTHER for each of `seeds`, the
    /// later ones deposited later (newest last).
    fn holds_for(dir: &Path, seeds: &[u8], now: u64) {
        let mut store = raven_core::friend_custody::CustodyStore::open_or_create(dir).unwrap();
        for (i, seed) in seeds.iter().enumerate() {
            let mut digest = [0u8; 32];
            digest[..2].copy_from_slice(&u16::try_from(i).unwrap().to_be_bytes());
            digest[2] = *seed;
            let at = now - 600_000 + 1_000 * u64::try_from(i).unwrap();
            let code = store
                .deposit(
                    &digest,
                    &key(*seed),
                    &key(OTHER),
                    &[1; 16],
                    &[0u8; 16],
                    now + 3_600_000,
                    at,
                )
                .unwrap();
            assert_eq!(code, raven_core::friend_custody::CustodyCode::Ok);
        }
    }

    /// This node holds a sealed letter from OTHER for each of `seeds`
    /// (and no custody object), the later ones deposited later.
    fn letters_for(dir: &Path, seeds: &[u8], now: u64) {
        let mut store = raven_core::friend_custody::CustodyStore::open_or_create(dir).unwrap();
        for (i, seed) in seeds.iter().enumerate() {
            let mut digest = [0xAAu8; 32];
            digest[..2].copy_from_slice(&u16::try_from(i).unwrap().to_be_bytes());
            digest[2] = *seed;
            let at = now - 600_000 + 1_000 * u64::try_from(i).unwrap();
            let code = store
                .deposit_letter(
                    &digest,
                    &key(*seed),
                    &key(OTHER),
                    &[*seed; 900],
                    now + 3_600_000,
                    at,
                )
                .unwrap();
            assert_eq!(code, raven_core::friend_custody::CustodyCode::Ok);
        }
    }

    /// Each of `seeds` sent this node an RRH1 that has not expired (the
    /// first one most recently).
    fn sent_us_rrh1(dir: &Path, seeds: &[u8], now: u64) {
        let entries: Vec<serde_json::Value> = seeds
            .iter()
            .enumerate()
            .map(|(i, seed)| {
                json!({
                    "pub_hex": hex::encode(key(*seed)),
                    "generation": 1,
                    "received_at_ms": now - 1_000 * u64::try_from(i).unwrap(),
                    "expires_at_ms": now + 3_600_000,
                    "via": "lan",
                })
            })
            .collect();
        std::fs::write(
            dir.join(learned_routes::LEARNED_ROUTES_FILE),
            serde_json::to_vec(&entries).unwrap(),
        )
        .unwrap();
    }

    /// M0 holds a noise pin for each of `seeds`.
    fn noise_pinned(dir: &Path, seeds: &[u8]) {
        let pin_key = raven_core::lan_noise_pin::PinKey::derive(&Identity::from_seed(&[0xC0; 32]));
        for seed in seeds {
            raven_core::lan_noise_pin::record(dir, &pin_key, &key(*seed), &[*seed; 32]).unwrap();
        }
    }

    /// A verified contact this node holds custody mail for is told first
    /// when its routes change, ahead of the RRH1 senders, but only while
    /// custody is live and M0 is on; an unverified one or a stranger never
    /// is.
    #[test]
    fn held_recipients_are_targets_only_while_custody_is_live() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        const STRANGER: u8 = 0x55;
        write_book(
            dd,
            &[
                (PEER, true, false, &[]),
                (CUSTODIAN, false, false, &[]),
                (OTHER, true, false, &[]),
            ],
        );
        holds_for(dd, &[STRANGER, CUSTODIAN, PEER], T0);
        noise_pinned(dd, &[PEER, CUSTODIAN, STRANGER]);
        sent_us_rrh1(dd, &[OTHER], T0);
        assert_eq!(
            announce_targets(dd, T0, HELD_LIVE),
            [key(PEER), key(OTHER)],
            "held verified first; unverified and stranger left out"
        );
        for gates in [
            HeldGates {
                custody: false,
                ..HELD_LIVE
            },
            HeldGates {
                noise_pin: false,
                ..HELD_LIVE
            },
        ] {
            assert_eq!(
                announce_targets(dd, T0, gates),
                [key(OTHER)],
                "{gates:?}: today's targets"
            );
        }
        // Expired mail is held for nobody.
        assert!(held_targets(dd, T0 + 3_600_000, HELD_LIVE).is_empty());
        // No store, an unreadable one: nobody.
        let none = tempfile::tempdir().unwrap();
        book(none.path(), true);
        assert!(held_targets(none.path(), T0, HELD_LIVE).is_empty());
        std::fs::write(
            raven_core::friend_custody::custody_db_path(none.path()),
            b"not a database",
        )
        .unwrap();
        assert!(held_targets(none.path(), T0, HELD_LIVE).is_empty());
    }

    /// Every try of an announce link is an identity-bearing dial: a held
    /// recipient without a noise pin (M0 never checked who answers at its
    /// address) is not a target until a link pins it.
    #[test]
    fn held_recipients_need_a_noise_pin() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[(PEER, true, false, &[]), (OTHER, true, false, &[])]);
        holds_for(dd, &[PEER, OTHER], T0);
        noise_pinned(dd, &[OTHER]);
        assert_eq!(held_targets(dd, T0, HELD_LIVE), [key(OTHER)]);
        noise_pinned(dd, &[PEER]);
        assert_eq!(
            held_targets(dd, T0, HELD_LIVE),
            [key(OTHER), key(PEER)],
            "newest deposit first"
        );
        // A pin store that cannot be read is no pin.
        std::fs::write(
            dd.join(raven_core::lan_noise_pin::NOISE_PIN_FILE),
            b"{not json",
        )
        .unwrap();
        assert!(held_targets(dd, T0, HELD_LIVE).is_empty());
    }

    /// Review cross-2: a custodian that holds only a sealed letter for a
    /// verified contact (no custody object; a letter waits up to 7 days,
    /// past the contact's RRH1) tells that contact when it moves, while it
    /// serves the letter ops; not with that gate closed, custody off or M0
    /// off. One it holds an object and a letter for is told once, and the
    /// noise pin and the book still decide.
    #[test]
    fn a_held_letters_recipient_is_a_target_while_letters_are_served() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        const STRANGER: u8 = 0x56;
        write_book(
            dd,
            &[
                (PEER, true, false, &[]),
                (CUSTODIAN, false, false, &[]),
                (OTHER, true, false, &[]),
            ],
        );
        letters_for(dd, &[STRANGER, CUSTODIAN, PEER], T0);
        noise_pinned(dd, &[PEER, CUSTODIAN, STRANGER]);
        assert_eq!(
            announce_targets(dd, T0, HELD_LIVE),
            [key(PEER)],
            "the letter's verified recipient; unverified and stranger left out"
        );
        for gates in [
            HeldGates {
                letters: false,
                ..HELD_LIVE
            },
            HeldGates {
                custody: false,
                ..HELD_LIVE
            },
            HeldGates {
                noise_pin: false,
                ..HELD_LIVE
            },
        ] {
            assert!(announce_targets(dd, T0, gates).is_empty(), "{gates:?}");
        }
        // A letter that ran out is held for nobody.
        assert!(held_targets(dd, T0 + 3_600_000, HELD_LIVE).is_empty());
        // Objects for OTHER and (newer) for PEER too: the objects' first,
        // newest first, and PEER once.
        holds_for(dd, &[OTHER, PEER], T0);
        noise_pinned(dd, &[OTHER]);
        assert_eq!(held_targets(dd, T0, HELD_LIVE), [key(PEER), key(OTHER)]);
    }

    /// E-custody-harness-docs-1 (pure): what [`probe`] compares for the
    /// LAN listener, and when it moved.
    #[test]
    fn a_wildcard_listener_input_carries_the_networks() {
        let at = |s: &str| Some(s.parse::<SocketAddr>().unwrap());
        assert_eq!(lan_input(at("0.0.0.0:7420"), Some("h")), "0.0.0.0:7420|h");
        assert_eq!(lan_input(at("[::]:7420"), Some("h")), "[::]:7420|h");
        assert_eq!(lan_input(at("0.0.0.0:7420"), None), "0.0.0.0:7420");
        assert_eq!(
            lan_input(at("192.168.1.30:7420"), Some("h")),
            "192.168.1.30:7420",
            "a listener on one address: the address alone, as before"
        );
        assert_eq!(lan_input(None, Some("h")), "");
        // (saved, now) -> (moved, saved next)
        let table = [
            ("0.0.0.0:7420|h", "0.0.0.0:7420|h", false, "0.0.0.0:7420|h"),
            ("0.0.0.0:7420|h", "0.0.0.0:7420|a", true, "0.0.0.0:7420|a"),
            ("0.0.0.0:7420|h", "0.0.0.0:7420", false, "0.0.0.0:7420|h"),
            ("0.0.0.0:7420", "0.0.0.0:7420|h", true, "0.0.0.0:7420|h"),
            ("0.0.0.0:7420|h", "0.0.0.0:7533", true, "0.0.0.0:7533"),
            ("0.0.0.0:7420|h", "", true, ""),
            ("", "0.0.0.0:7420", true, "0.0.0.0:7420"),
            ("10.0.0.2:7420", "10.0.0.2:7420", false, "10.0.0.2:7420"),
            ("10.0.0.2:7420", "10.0.0.3:7420", true, "10.0.0.3:7420"),
            ("", "", false, ""),
        ];
        for (saved, now, moved, keep) in table {
            assert_eq!(
                lan_moved(saved, now),
                (moved, keep.to_string()),
                "{saved:?} -> {now:?}"
            );
        }
    }

    /// E-custody-harness-docs-1: a custodian on the default 0.0.0.0:7420
    /// that moves to another network keeps its listener, so only its
    /// networks say it moved. That moves the generation, and the recipient
    /// it holds mail for is then due its announce; the same networks again,
    /// or none known yet, move nothing. Mail is a custody object, or (review
    /// cross-2) only a sealed letter.
    #[test]
    fn a_wildcard_listener_on_another_network_tells_its_held_recipients() {
        for letter_only in [false, true] {
            wildcard_listener_moves(letter_only);
        }
    }

    fn wildcard_listener_moves(letter_only: bool) {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        write_book(dd, &[(PEER, true, false, &[]), (OTHER, true, false, &[])]);
        if letter_only {
            letters_for(dd, &[PEER], T0);
        } else {
            holds_for(dd, &[PEER], T0);
        }
        noise_pinned(dd, &[PEER]);
        let wild = Some("0.0.0.0:7420".parse::<SocketAddr>().unwrap());
        let look = |view: Option<&str>, now_ms: u64| {
            next_generation(dd, "g", Some(&lan_input(wild, view)), None, now_ms)
                .map(|(_, moved)| moved)
        };
        assert_eq!(look(Some("home"), T0), Some(Moved::Global), "the first");
        assert_eq!(look(Some("home"), T0 + 1), Some(Moved::Nothing));
        assert_eq!(look(None, T0 + 2), Some(Moved::Nothing), "not known yet");
        let before = saved_generation(dd).unwrap();
        assert_eq!(look(Some("away"), T0 + 3), Some(Moved::Global), "moved");
        assert!(saved_generation(dd).unwrap() > before);
        assert_eq!(
            announce_targets(dd, T0, HELD_LIVE),
            [key(PEER)],
            "letter only: {letter_only}"
        );
        assert_eq!(look(Some("away"), T0 + 4), Some(Moved::Nothing));
        // A restart on that network (the state read back from the file).
        let other = tempfile::tempdir().unwrap();
        assert!(next_generation(other.path(), "g", None, None, T0).is_some());
        assert_eq!(look(None, T0 + 5), Some(Moved::Nothing));
        assert_eq!(look(Some("away"), T0 + 6), Some(Moved::Nothing));
        let saved = std::fs::read_to_string(dd.join(GEN_STATE_FILE)).unwrap();
        assert!(saved.contains("0.0.0.0:7420|away"), "{saved}");
    }

    /// Review FU-2: the state file keeps the wildcard listener's networks as
    /// a digest keyed with this computer's identity. A copy of the data dir
    /// cannot test a guess against it (one IPv4 network is a few million
    /// guesses over the private ranges), while the same identity on the same
    /// networks reads it back as no move, and other networks still move it.
    #[test]
    fn the_saved_networks_cannot_be_tested_from_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let wild = Some("0.0.0.0:7420".parse::<SocketAddr>().unwrap());
        let net = |s: &str| vec![s.parse::<if_watch::IpNet>().unwrap()];
        let me = route_hints::NetworksKey::derive(&Identity::from_seed(&[0x11; 32]));
        let look = |view: &[if_watch::IpNet], key: &route_hints::NetworksKey, now_ms: u64| {
            let digest = crate::netwatch::view_digest_of(view, key);
            next_generation(
                dd,
                "g",
                Some(&lan_input(wild, digest.as_deref())),
                None,
                now_ms,
            )
            .map(|(_, moved)| moved)
        };
        let home = net("192.168.1.30/24");
        assert_eq!(look(&home, &me, T0), Some(Moved::Global));
        let saved = std::fs::read_to_string(dd.join(GEN_STATE_FILE)).unwrap();
        // What a reader of the file alone computes for the right guess.
        let guess = route_hints::inputs_digest(&[b"192.168.1.30/24"]);
        assert!(!saved.contains(&guess), "{saved}");
        assert!(!saved.contains("192.168"), "{saved}");
        // A restart: the same identity derives the same key.
        let again = route_hints::NetworksKey::derive(&Identity::from_seed(&[0x11; 32]));
        assert_eq!(look(&home, &again, T0 + 1), Some(Moved::Nothing));
        assert_eq!(
            look(&net("10.42.0.5/24"), &again, T0 + 2),
            Some(Moved::Global),
            "another network still moves it"
        );
    }

    /// Held recipients, then RRH1 senders, each once, at most
    /// [`MAX_TARGETS`] in all.
    #[test]
    fn targets_are_capped_and_deduped() {
        let held: Vec<[u8; 32]> = (0..40u8).map(|i| [i; 32]).collect();
        let live: Vec<[u8; 32]> = (30..100u8).map(|i| [i; 32]).collect();
        let targets = targets_from(&held, &live);
        assert_eq!(targets.len(), MAX_TARGETS);
        let want: Vec<[u8; 32]> = (0..MAX_TARGETS)
            .map(|i| [u8::try_from(i).unwrap(); 32])
            .collect();
        assert_eq!(targets, want, "held first, a contact in both once");
        assert_eq!(targets_from(&[], &live[..3]), live[..3].to_vec());
        assert_eq!(
            targets_from(&[[7; 32], [7; 32]], &[[7; 32]]),
            [[7; 32]],
            "once"
        );
        // Through the store and the book: the same order and cap.
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let seeds: Vec<u8> = (0x60..0x60 + 70).collect();
        let rows: Vec<Row> = seeds.iter().map(|s| (*s, true, false, &[][..])).collect();
        write_book(dd, &rows);
        holds_for(dd, &seeds, T0);
        noise_pinned(dd, &seeds);
        sent_us_rrh1(dd, &[OTHER, seeds[69]], T0);
        let targets = announce_targets(dd, T0, HELD_LIVE);
        assert_eq!(targets.len(), MAX_TARGETS);
        let newest: Vec<[u8; 32]> = seeds
            .iter()
            .rev()
            .take(MAX_TARGETS)
            .map(|s| key(*s))
            .collect();
        assert_eq!(targets, newest, "newest held first; no room left for OTHER");
    }

    /// The step's review dropped "peers with a sendable session" as
    /// announce targets: a verified contact with a session and a noise pin,
    /// for whom this node holds no mail and who sent no RRH1, is not told.
    #[test]
    fn no_session_only_peer_is_a_target() {
        use raven_core::device_cert::ensure_local_device_certificate;
        use raven_core::lan_dispatch::{cache_peer_bundle, local_bundle};
        use raven_core::paths::PRIMARY_DEVICE_ID;
        if !rig::lab_backends() {
            return;
        }
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let alice = Identity::from_seed(&[LOCAL; 32]);
        let bob = Identity::from_seed(&[PEER; 32]);
        for (dir, id) in [(a.path(), &alice), (b.path(), &bob)] {
            ensure_local_device_certificate(dir, id, PRIMARY_DEVICE_ID).unwrap();
            raven_core::ensure_local_prekey(dir, id).unwrap();
        }
        rig::contacts(a.path(), &key(PEER), "127.0.0.1:9", "", true);
        rig::contacts(b.path(), &key(LOCAL), "", "", true);
        let a_bundle = local_bundle(a.path(), &alice).unwrap();
        let b_bundle = local_bundle(b.path(), &bob).unwrap();
        cache_peer_bundle(a.path(), &b_bundle).unwrap();
        rig::pair(a.path(), &alice, b.path(), &bob, &a_bundle, &b_bundle);
        let now = crate::now_ms();
        assert!(
            matches!(
                raven_core::outbox::queue_reach(a.path(), &key(PEER), now),
                Ok(raven_core::outbox::QueueReach::CanWait { .. })
            ),
            "a sendable session"
        );
        noise_pinned(a.path(), &[PEER]);
        assert!(announce_targets(a.path(), now, HELD_LIVE).is_empty());
        // Held mail for it makes it one.
        holds_for(a.path(), &[PEER], now);
        assert_eq!(announce_targets(a.path(), now, HELD_LIVE), [key(PEER)]);
    }

    /// An attempt context on `dir` (LAN only, as the rig's) that must not
    /// dial, and its dialer.
    fn announce_ctx(
        dir: &Path,
        on_link: fn(IpAddr) -> Option<bool>,
    ) -> (crate::outbox::AttemptCtx, std::sync::Arc<rig::NoDial>) {
        let nodial = std::sync::Arc::new(rig::NoDial::default());
        let ctx = crate::outbox::AttemptCtx {
            on_link,
            ..rig::test_ctx(
                dir,
                std::sync::Arc::new(Identity::from_seed(&[LOCAL; 32])),
                nodial.clone(),
            )
        };
        (ctx, nodial)
    }

    fn announced(ctx: &crate::outbox::AttemptCtx) -> Vec<OutboxRoute> {
        announce_routes(ctx, &key(PEER), crate::now_ms())
            .into_iter()
            .map(|(planned, _)| planned)
            .collect()
    }

    /// 6a: the announcer plans through the worker's resolver, so a learned
    /// LAN address on none of this computer's networks is not dialled (its
    /// signed bind would go to whoever holds that address now); on link it
    /// is, after the saved route.
    #[test]
    fn announce_routes_leave_out_an_off_link_learned_lan_route() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (saved, learned) = (rig::lan("10.0.0.5:7420"), rig::lan("192.168.1.20:7420"));
        rig::contacts_all(dd, &key(PEER), &saved.dial, "203.0.113.9:7422");
        let seen_at: IpAddr = "192.168.1.20".parse().unwrap();
        raven_core::lan_seen::record_contact_seen(dd, &key(PEER), seen_at, None, crate::now_ms())
            .unwrap();
        let (off, off_dials) = announce_ctx(dd, |_| Some(false));
        assert_eq!(announced(&off), std::slice::from_ref(&saved));
        let (on, on_dials) = announce_ctx(dd, |_| Some(true));
        assert_eq!(announced(&on), [saved, learned]);
        assert_eq!(off_dials.dials() + on_dials.dials(), 0);
    }

    /// Nobody to tell but a current, unblocked contact: a stranger, a
    /// blocked contact and an unreadable book get no route at all.
    #[test]
    fn announce_routes_are_empty_for_a_stranger_or_a_blocked_contact() {
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (ctx, nodial) = announce_ctx(dd, rig::unknown_link);
        rig::contacts(dd, &key(OTHER), "10.0.0.5:7420", "", true);
        assert!(announced(&ctx).is_empty(), "a stranger");
        rig::contacts(dd, &key(PEER), "10.0.0.5:7420", "", true);
        assert_eq!(announced(&ctx), [rig::lan("10.0.0.5:7420")], "the control");
        let mut blocks = raven_core::BlockList::default();
        blocks.block(&hex::encode(key(PEER)));
        blocks.save(dd).unwrap();
        assert!(announced(&ctx).is_empty(), "a blocked contact");
        raven_core::BlockList::default().save(dd).unwrap();
        std::fs::write(dd.join("contacts.json"), "{not json").unwrap();
        assert!(announced(&ctx).is_empty(), "an unreadable book");
        assert_eq!(nodial.dials(), 0);
    }

    /// What a probe of `dir` saved last: its generation.
    fn saved_generation(dir: &Path) -> Option<u64> {
        std::fs::read(dir.join(GEN_STATE_FILE))
            .ok()
            .and_then(|raw| serde_json::from_slice::<GenState>(&raw).ok())
            .map(|s| s.generation)
    }

    /// Wait (real time, the paused clock standing still) until `done`.
    async fn until(what: &str, done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(1));
            tokio::task::yield_now().await;
        }
    }

    fn always() -> bool {
        true
    }

    /// The announcer looks at this node's inputs once at start, SETTLE
    /// after it starts (not before), with no change asked for; then a LAN
    /// listener coming up wakes it, long before its TICK.
    #[test]
    fn the_first_probe_runs_at_start_and_a_lan_listener_bind_triggers_a_probe() {
        // The listener's address is process-wide: held for the whole test.
        let _state = crate::lan_direct::listener_state_test_lock();
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let dd = dir.path().to_path_buf();
            let announcer =
                tokio::spawn(async move { announce_loop(&dd, always, |_, _| async {}).await });
            tokio::time::sleep(SETTLE - Duration::from_secs(1)).await;
            assert_eq!(saved_generation(dir.path()), None, "not before SETTLE");
            tokio::time::sleep(Duration::from_secs(2)).await;
            until("the first probe", || saved_generation(dir.path()).is_some()).await;
            let first = saved_generation(dir.path()).unwrap();

            // The listener binds (a new port): probed SETTLE later, not a
            // TICK later, and its address moves the generation.
            let woken = Instant::now();
            let up = crate::lan_direct::listener_bound("0.0.0.0:7531".parse().unwrap());
            tokio::time::sleep(SETTLE + Duration::from_secs(1)).await;
            until("a probe after the bind", || {
                saved_generation(dir.path()).is_some_and(|g| g > first)
            })
            .await;
            assert!(Instant::now() < woken + TICK);
            let bound = saved_generation(dir.path()).unwrap();
            // Nothing new: the next look (a TICK later) keeps it.
            tokio::time::sleep(TICK + SETTLE + Duration::from_secs(1)).await;
            assert_eq!(saved_generation(dir.path()), Some(bound));
            // Gone: told again.
            drop(up);
            tokio::time::sleep(SETTLE + Duration::from_secs(1)).await;
            until("a probe after the unbind", || {
                saved_generation(dir.path()).is_some_and(|g| g > bound)
            })
            .await;
            announcer.abort();
        });
    }

    /// Privacy pack PP.4 (review R23): the count of contacts this node hides
    /// its IP from is an error for a book it cannot open (its key not
    /// loaded, a changed byte), never "none"; the route hints row of Status
    /// is then left out rather than wrong.
    #[test]
    fn quiet_readers_fail_their_operation_on_key_unavailable() {
        use crate::at_rest_boot::tests::{lab_hist_key, profile_with, seal, serial};
        if !lab_hist_key() {
            return;
        }
        let dir = profile_with(&[]);
        let dd = dir.path();
        let row = json!({ "pub_hex": hex::encode(key(PEER)), "pinned": true, "hide_ip": true });
        raven_core::contact_book::write_rows(dd, &[row]).unwrap();
        assert_eq!(hidden_contacts(dd), Ok(1));
        {
            let _serial = serial();
            seal(dd);
        }
        assert_eq!(hidden_contacts(dd), Ok(1));
        raven_core::at_rest::forget_cached_keys(dd);
        assert!(hidden_contacts(dd).unwrap_err().is_locked());
        // A changed byte in the sealed book.
        {
            let _serial = serial();
            raven_core::at_rest::keys_load_with(dd, raven_core::at_rest::MigratePolicy::Never)
                .unwrap();
        }
        let path = dd.join(raven_core::contact_book::CONTACTS_FILE);
        let mut sealed = std::fs::read(&path).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        std::fs::write(&path, &sealed).unwrap();
        assert!(matches!(
            hidden_contacts(dd),
            Err(raven_core::contact_book::BookError::Corrupt(_))
        ));
    }

    /// §15: a verified contact's ONION entry that its own key signed lands
    /// in its book row; an unsigned or foreign one, or one from an
    /// unverified contact, never does. Whatever the route-hints gate: the
    /// frame is applied here directly.
    #[test]
    fn an_onion_entry_is_kept_in_the_book_only_signed_by_a_verified_contact() {
        use raven_core::onion::{now_s, OnionBinding};
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let peer = Identity::from_seed(&[PEER; 32]);
        let hs_id = Identity::from_seed(&[0x61; 32]).public_key_bytes();
        let keys = LinkKeys::new(key(PEER), &Identity::from_seed(&[LOCAL; 32]));
        let apply = ApplyCtx {
            carrier: OutboxCarrier::Internet,
            keys,
            peer_ip: None,
            peer_zone: None,
            link_peer_id: None,
            lab_local: false,
            offers_live: false,
            nat_live: false,
            stun_live: true,
            rotation_live: false,
            seeds_live: false,
            now_ms: crate::now_ms(),
        };
        let frame = |generation: u64, onion: OnionBinding| {
            route_hints::encode(&RouteHints {
                generation,
                ttl_s: 3600,
                onion: Some(onion),
                ..RouteHints::default()
            })
        };
        let book_onion = || -> Option<OnionBinding> {
            raven_core::outbox::contact_routes(dd, &key(PEER))
                .unwrap()
                .and_then(|c| c.onion)
        };
        let signed = OnionBinding::sign(&peer, hs_id, now_s());
        // Unverified: nothing kept.
        write_p2p_book(dd, &[(PEER, false, false, &pid(PEER))]);
        apply_frame(dd, &frame(1, signed), &apply).unwrap();
        assert_eq!(book_onion(), None);
        // Verified: kept; a foreign or unsigned one never.
        write_p2p_book(dd, &[(PEER, true, false, &pid(PEER))]);
        let foreign = OnionBinding::sign(&Identity::from_seed(&[OTHER; 32]), hs_id, now_s());
        apply_frame(dd, &frame(2, foreign), &apply).unwrap();
        let unsigned = OnionBinding {
            sig: [0; 64],
            ..signed
        };
        apply_frame(dd, &frame(3, unsigned), &apply).unwrap();
        assert_eq!(book_onion(), None);
        apply_frame(dd, &frame(4, signed), &apply).unwrap();
        assert_eq!(book_onion(), Some(signed));
        // An older binding never replaces a newer one.
        let older = OnionBinding::sign(&peer, hs_id, now_s() - 60);
        apply_frame(dd, &frame(5, older), &apply).unwrap();
        assert_eq!(book_onion(), Some(signed));
    }

    /// The "told a contact our routes" line says whether our onion binding
    /// went (`onion=yes|no`), never the binding or an address.
    #[test]
    fn the_told_line_says_whether_the_onion_hint_went() {
        let me = Identity::from_seed(&[0x42; 32]);
        let hs_id = Identity::from_seed(&[0x43; 32]).public_key_bytes();
        let binding = raven_core::onion::OnionBinding::sign(&me, hs_id, 1_790_000_000);
        let mut hints = RouteHints {
            direct: vec!["198.51.100.7:7422".into()],
            lan_port: Some(7531),
            ..RouteHints::default()
        };
        assert_eq!(
            told_line(&hints),
            "told a contact our routes (relays=0, direct=1, lan=yes, offers=0, onion=no)"
        );
        hints.onion = Some(binding);
        let line = told_line(&hints);
        assert!(line.ends_with(", onion=yes)"), "{line}");
        assert!(!line.contains("198.51.100.7"), "{line}");
        assert!(!line.contains(&binding.to_text()), "{line}");
        assert!(!line.contains(&hex::encode(hs_id)), "{line}");
    }
}
