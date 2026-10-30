//! What contacts told this node about reaching them (RRH1 route hints).
//!
//! A contact's computer moves: its LAN listener comes back on another port,
//! it holds a reservation on another relay, its public address changes. Its
//! RRH1 frame ([`crate::route_hints`], `protocol/RAVEN_ROUTE_HINTS_V1.md`)
//! says where it is now. raven-node keeps here the last snapshot each contact
//! sent, and the planners (the outbox worker, `raven send`, the p2p dialler)
//! add those routes after the saved ones.
//!
//! - **Two parts per sender** (spec §5.3). The global part (PeerId, relays,
//!   global direct addresses, custodians, relay offers) follows the
//!   generation from any link: a higher one replaces it whole (snapshot
//!   semantics: what the new frame lacks is withdrawn), an equal one extends
//!   its expiry, a lower one is ignored. The LAN part (LAN port, same-LAN
//!   direct addresses, the LAN IP) changes only on frames that came over a
//!   LAN link, at a generation at least its own. Its IP is the link's peer
//!   IP (an IPv6 link-local one with the zone the link came in on, Phase 3
//!   P3.4: `fe80::b%en0`), never a host the frame names.
//! - **Expiring.** A part lives `ttl_s` by this node's clock (60 s .. 7 d).
//!   The next frame after that replaces it whatever its generation. An
//!   expired entry stays [`TOMBSTONE_MS`] as a tombstone (when the contact
//!   was last heard, no route but a kept LAN port, below) for the diagnosis
//!   ([`last_heard`]); it keeps the relays it offered, for a reservation
//!   there that outlives the offer ([`offers`]). Privacy pack PP.7
//!   ([`prune`], owner decision OD-C10): the tombstone of a contact this
//!   node has not heard from for [`FORGET_AFTER_MS`] keeps only its
//!   generation and its times to the day, and the file is written as its
//!   readers see it.
//! - **A LAN port kept for people who meet weekly** (Phase 3 P3.C1, cutoff
//!   F11c, owner decision OD-C10 (a)). A LAN part past its expiry (its own,
//!   or the whole entry's) keeps its LAN IP and port, and the network they
//!   belong to, until [`LAN_KEEP_MS`] after it was received: a friend whose
//!   listener moved is found again a week later with no typed address. Only
//!   the LAN planner dials it ([`learned_with_lan`], [`rrh1_lan_dials`]:
//!   after the saved route, inside the learned LAN budget). It is in no
//!   [`LearnedView`], names no PeerId and makes no announce target
//!   ([`live_contacts`]). A frame over another link keeps it (the LAN part
//!   follows LAN frames only); the next LAN frame replaces it whatever its
//!   generation. Nothing is added to the file: it is the stored LAN part
//!   without its same-LAN direct addresses (p2p routes).
//! - **Relay offers** (spec §11.3): the friend relays a contact offers this
//!   node, at most [`MAX_RELAY_OFFERS`] per contact and [`MAX_OFFERS`] in all
//!   (the newest senders' stay). This node's own relay choice may reserve on
//!   them.
//! - **Custody** (Phase 3 P3.18, spec §12): whether the sender offers to
//!   hold sealed mail for its verified contacts (CUSTODY_OFFER, its flags),
//!   and the tags of the custodians it collects from (CUSTODIAN_TAG, each
//!   with its flags byte, kept for Phase 5), part of the global snapshot. A
//!   tombstone keeps none. Phase 2's plain custodian keys (0x05) are still
//!   read ([`LearnedCustody::plain`]). The home-custodian choice reads the
//!   offers ([`crate::custody_home`]); the custody planners match the tags.
//! - **NAT classes** (Phase 4, spec §13.1): the sender's NAT_CLASS, part of
//!   the global snapshot, stored only while the NAT_CLASS gate is live
//!   (raven-node clears it otherwise) and never in a tombstone. Only this
//!   node's hole-punch policy reads it ([`nat_classes`]).
//! - **Used only to reach the sender** (and its offers only by this node's
//!   relay choice and custodian choice). Nothing here is ever re-sent or put
//!   into this node's own RRH1 or card.
//!
//! The file holds no secret: public keys, addresses and times. Only raven-node
//! writes it, for authenticated links and only while [`route_hints_live`];
//! `ash contact remove` / `set-addr` [`forget`] the contact's entry under the
//! same data-dir lock. Readers take no lock and do not check the gate: the
//! planners do. Bounded: [`MAX_ENTRIES`] contacts, tombstones included.
//!
//! Privacy pack PP.6: RMS1 kind 3 in a sealed profile ([`crate::at_rest`]),
//! today's JSON otherwise; readers accept both. An unreadable file reads as
//! empty, as before, but its writers never write over one they could not
//! read (a sealed file whose key is not loaded, a changed byte): that write
//! is skipped and counted. Plain bytes that do not parse are replaced.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, Kind};
use crate::lan_seen::ScopedIp;
use crate::outbox::OutboxCarrier;
use crate::p2p_route::{normalize_peer_id, parse_host_transport, parse_via, ViaAddr};
use crate::paths::DataDirLock;
use crate::route_hints::{
    route_hints_live, HintLink, NatClass, ValidHints, CUSTODY_OFFER_KNOWN, MAX_CUSTODIANS,
    MAX_GLOBAL_DIRECT, MAX_LOCAL_DIRECT, MAX_OFFER_ADDRS, MAX_RELAY_ENTRIES, MAX_RELAY_OFFERS,
    RRH1_MAX_TTL_S, RRH1_MIN_TTL_S,
};

/// The file in the data dir.
pub const LEARNED_ROUTES_FILE: &str = "learned_routes.json";
/// raven-node (every write) and ash ([`forget`]) take it; so does
/// [`crate::custody_home`] for its own file.
pub(crate) const LEARNED_ROUTES_LOCK: &str = ".learned_routes.lock.sqlite";
/// At most this many contacts are remembered, tombstones included (the
/// oldest frame goes first).
pub const MAX_ENTRIES: usize = 256;
/// Relay offers kept in all (spec §11.3), tombstones' included: the newest
/// senders' stay. One sender's are at most [`MAX_RELAY_OFFERS`].
pub const MAX_OFFERS: usize = 32;
/// Custody offers [`custody_offers`] lists at most (the newest senders').
pub const MAX_CUSTODY_OFFERS: usize = 32;
/// How long an expired entry stays as a tombstone (30 days past its expiry).
pub const TOMBSTONE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// A contact this node has not heard from for longer than this (no RRH1,
/// no authenticated LAN link) keeps a bare tombstone ([`prune`]; privacy
/// pack PP.7, owner decision OD-C10: 30 days).
pub const FORGET_AFTER_MS: u64 = crate::lan_seen::MAX_AGE_MS;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// How long a LAN part stays dialable after it was received, past its
/// expiry too (Phase 3 P3.C1, owner decision OD-C10 (a): 30 days): its LAN
/// IP and port only ([`learned_with_lan`]). Never longer than the tombstone
/// that holds it, nor than [`prune`] lets a contact's addresses live.
pub const LAN_KEEP_MS: u64 = 30 * DAY_MS;
const _: () = assert!(LAN_KEEP_MS <= TOMBSTONE_MS && LAN_KEEP_MS <= FORGET_AFTER_MS);
/// Learned LAN routes one contact's plan may hold: [`crate::lan_seen`]'s and
/// RRH1's together, so a p2p route is never truncated out of the plan.
pub const MAX_LEARNED_LAN_DIALS: usize = 2;
/// An unchanged snapshot is rewritten only when that extends its expiry by
/// this much (or by half its TTL, when that is shorter): every link carries
/// one RRH1 each way.
const REFRESH_WRITE_MS: u64 = 60 * 60 * 1000;
/// An entry stamped further than this in the future means the clock went
/// back: it is dropped (the contact's next frame fills it again).
const CLOCK_SLACK_MS: u64 = 5 * 60 * 1000;
/// A busy lock skips the frame (the contact's next link carries it again).
const LOCK_WAIT: Duration = Duration::from_secs(2);
const MAX_TTL_MS: u64 = RRH1_MAX_TTL_S as u64 * 1000;

/// A relay a contact offered this node (a RELAY_OFFER record, spec §11, as
/// [`crate::route_hints::validate`] kept it), dialled at
/// `<addr>/p2p/<relay_peer_id>`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StoredOffer {
    /// The relay's own PeerId (never its operator's).
    pub relay_peer_id: String,
    /// Host and transport only, the ones this node may dial: 1 to
    /// [`MAX_OFFER_ADDRS`].
    pub addrs: Vec<String>,
    /// [`crate::route_hints::FLAG_CONFIRMED`], `FLAG_AUTONAT`,
    /// `FLAG_PORT_443`, as received (unknown bits are ignored).
    pub flags: u8,
}

impl StoredOffer {
    /// Checked again on read (the file is advisory): a canonical relay
    /// PeerId and canonical, distinct addresses, at most
    /// [`MAX_OFFER_ADDRS`]; `None` when no address is left.
    fn checked(&self) -> Option<Self> {
        let relay_peer_id = normalize_peer_id(&self.relay_peer_id).ok()?;
        let mut addrs: Vec<String> = Vec::new();
        for addr in &self.addrs {
            if addrs.len() < MAX_OFFER_ADDRS
                && parse_host_transport(addr).ok().as_deref() == Some(addr.as_str())
                && !addrs.contains(addr)
            {
                addrs.push(addr.clone());
            }
        }
        (!addrs.is_empty()).then_some(Self {
            relay_peer_id,
            addrs,
            flags: self.flags,
        })
    }
}

/// One sender's snapshot. The top-level fields are the global part; a
/// tombstone keeps only the key, the generation, the times, the relays it
/// offered and a kept LAN part ([`LanPart::kept_part`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Learned {
    pub_hex: String,
    /// The global part's generation.
    generation: u64,
    /// The last frame from this sender that changed or refreshed something.
    received_at_ms: u64,
    /// The global part's (and the entry's) expiry.
    expires_at_ms: u64,
    /// The link that carried the global part last.
    via: OutboxCarrier,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    peer_id: String,
    /// A p2p link with that PeerId carried the contact's identity.
    #[serde(default, skip_serializing_if = "is_false")]
    peer_id_proven: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    relays: Vec<String>,
    /// Global direct addresses, each ending in `/p2p/<peer_id>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    direct: Vec<String>,
    /// Hex Ed25519 device keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    custodians: Vec<String>,
    /// Relays the sender offers this node (part of the global snapshot).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    offers: Vec<StoredOffer>,
    /// CUSTODIAN_TAG values in hex (Phase 3 P3.18), at most
    /// [`MAX_CUSTODIANS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    custodian_tags: Vec<String>,
    /// The flags byte of each of `custodian_tags` (same index; Phase 5).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    custodian_tag_flags: Vec<u8>,
    /// CUSTODY_OFFER: the sender holds sealed mail for its verified
    /// contacts; its flags ([`crate::custody_gate::OFFER_WAN`],
    /// [`crate::custody_gate::OFFER_REACHABLE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody_offer: Option<u8>,
    /// The sender's NAT mapping classes (RRH1 NAT_CLASS, Phase 4, spec
    /// §13.1), part of the global snapshot: stored only while the NAT_CLASS
    /// gate is live (raven-node clears it otherwise), never in a tombstone.
    /// Codes and flags, no address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nat_class: Option<NatClass>,
    /// Auto-reach (RRH1 INET_DIRECT, spec §13.3): the public address of the
    /// sender's Internet direct listener, part of the global snapshot,
    /// never in a tombstone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    inet: Vec<StoredInet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lan: Option<LanPart>,
}

/// One INET_DIRECT entry as stored: `ip:port` text and its CONFIRMED flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredInet {
    addr: String,
    #[serde(default, skip_serializing_if = "is_false")]
    confirmed: bool,
}

/// The LAN part: a LAN link's (its peer IP and the LAN port it was told),
/// or one the contact told over another link (LAN_ADDR, spec §16:
/// `told`). Only frames over a LAN link, or ones carrying LAN_ADDR, change
/// it (§5.3). Past its expiry it is kept for dialling
/// ([`LanPart::kept_part`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LanPart {
    generation: u64,
    received_at_ms: u64,
    /// Its own expiry: frames over other links never refresh it.
    expires_at_ms: u64,
    lan_port: Option<u16>,
    /// The peer IP of the LAN link that carried it, in [`ScopedIp`]'s text
    /// form: an IPv6 link-local one with its zone (`fe80::b%en0`), which an
    /// older build's `parse::<IpAddr>()` refuses (no route, never one
    /// without the zone).
    lan_ip: String,
    /// Same-LAN direct addresses, each ending in `/p2p/<peer_id>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    local_direct: Vec<String>,
    /// [`crate::route_memory::egress_tag`] when the part (its port or its
    /// same-LAN direct addresses) was learned: the network it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_tag: Option<String>,
    /// Learned from the contact's own word over another link (LAN_ADDR,
    /// spec §16), not from a LAN link's peer IP: `lan_ip` and `lan_port`
    /// are the address it told, dialled only while that is on one of this
    /// computer's own networks.
    #[serde(default, skip_serializing_if = "is_false")]
    told: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// What [`apply`] did with one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// Nothing stored: route hints are off.
    Ignored,
    /// An older generation (and, on a LAN link, older than the LAN part).
    Stale,
    /// The snapshot held; the file was not rewritten.
    Unchanged,
    /// The same routes, rewritten: the expiry moved, the generation did, or
    /// only the relays the sender offers changed (they are not routes to
    /// it: this node's relay choice reads them).
    Refreshed,
    /// What this node plans for the sender changed: `lan` the LAN part's
    /// routes, `p2p` the PeerId (or whether it is proven), relays or global
    /// direct addresses, `custody` its custodians (plain keys or tags) or
    /// its custody offer.
    Changed { lan: bool, p2p: bool, custody: bool },
}

/// What one contact's live snapshot says about custody
/// ([`learned_custody`]), checked again on read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LearnedCustody {
    /// CUSTODIAN_TAG values (never all-zero), at most [`MAX_CUSTODIANS`]:
    /// matched with [`crate::route_hints::custodian_tag`].
    pub tags: Vec<[u8; 32]>,
    /// The flags byte of each of `tags` (same index) as stored (0 for an
    /// entry stored without one; a repeated tag's flags OR-ed into the
    /// first). Readers test only the bits they know
    /// ([`crate::route_hints::CUSTODIAN_FLAG_HANDOFF_INBOX`]).
    pub tag_flags: Vec<u8>,
    /// Phase 2's plain custodian keys (0x05, receive-only).
    pub plain: Vec<[u8; 32]>,
    /// CUSTODY_OFFER with only the known bits
    /// ([`crate::route_hints::CUSTODY_OFFER_KNOWN`]); `None`: no offer.
    pub offer: Option<u8>,
    /// When that snapshot was stored.
    pub heard_ms: u64,
}

/// One contact's live snapshot ([`learned`]), checked again on read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnedView {
    pub generation: u64,
    pub received_at_ms: u64,
    pub expires_at_ms: u64,
    pub via: OutboxCarrier,
    pub peer_id: Option<String>,
    pub peer_id_proven: bool,
    /// Empty without a PeerId.
    pub relays: Vec<ViaAddr>,
    /// Global, each ending in `/p2p/<peer_id>`; empty without a PeerId.
    pub direct: Vec<ViaAddr>,
    pub custodians: Vec<[u8; 32]>,
    /// The sender's NAT mapping classes (Phase 4), with the snapshot's
    /// expiry; `None` without a PeerId.
    pub nat_class: Option<NatClass>,
    /// Auto-reach (spec §13.3): the public addresses of the sender's
    /// Internet direct listener and whether each is confirmed, at most
    /// [`crate::route_hints::MAX_INET_DIRECT`].
    pub inet: Vec<(std::net::SocketAddr, bool)>,
    /// `None` when no LAN link carried one or it expired (one kept past its
    /// expiry is for the LAN planner only: [`learned_with_lan`]).
    pub lan: Option<LearnedLan>,
}

/// The LAN part of a [`LearnedView`], or one kept past its expiry
/// ([`learned_with_lan`]: no same-LAN direct address then).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnedLan {
    pub port: Option<u16>,
    /// The peer IP of the LAN link that carried it.
    pub ip: Option<IpAddr>,
    /// The zone of an IPv6 link-local `ip`: the interface of this computer
    /// the link came in on ([`ScopedIp`]).
    pub zone: Option<String>,
    /// Same-LAN direct addresses of the current PeerId.
    pub local_direct: Vec<ViaAddr>,
    /// The network it was learned on ([`crate::route_memory::egress_tag`]).
    pub local_tag: Option<String>,
    /// The contact told this address over another link (LAN_ADDR, spec
    /// §16): its own word, from its authenticated link. A planner dials it
    /// only for a verified contact and only while it is on one of this
    /// computer's own networks ([`crate::netifs::on_our_networks`]).
    pub told: bool,
    pub received_at_ms: u64,
}

impl LearnedLan {
    /// Does this LAN part belong to the network `here` (this computer's
    /// [`crate::route_memory::egress_tag`] now)? Its port and peer IP are
    /// that network's: on another one they would reach whoever holds that
    /// address there. Unknown on either side (a part stored before tags, or
    /// no default route, as on a LAN without internet) counts as here.
    pub fn on_network(&self, here: Option<&str>) -> bool {
        match (self.local_tag.as_deref(), here) {
            (Some(learned), Some(here)) => learned == here,
            _ => true,
        }
    }
}

/// What the p2p dialler may use ([`LearnedView::p2p`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnedP2p {
    pub peer_id: String,
    pub relays: Vec<ViaAddr>,
    pub direct: Vec<ViaAddr>,
    /// Usable only on the network named by `local_tag`.
    pub local_direct: Vec<ViaAddr>,
    pub local_tag: Option<String>,
    pub proven: bool,
}

impl LearnedView {
    /// The contact's PeerId and the addresses it named, when it sent one.
    pub fn p2p(&self) -> Option<LearnedP2p> {
        let peer_id = self.peer_id.clone()?;
        let (local_direct, local_tag) = self.lan.as_ref().map_or((Vec::new(), None), |l| {
            (l.local_direct.clone(), l.local_tag.clone())
        });
        Some(LearnedP2p {
            peer_id,
            relays: self.relays.clone(),
            direct: self.direct.clone(),
            local_direct,
            local_tag,
            proven: self.peer_id_proven,
        })
    }
}

impl Learned {
    fn live(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms
    }

    /// Kept at all (live, or a tombstone within [`TOMBSTONE_MS`]). An entry
    /// stamped in the future, or with an expiry no frame could give it, is
    /// not.
    fn kept(&self, now_ms: u64) -> bool {
        self.received_at_ms <= now_ms.saturating_add(CLOCK_SLACK_MS)
            && self.expires_at_ms <= self.received_at_ms.saturating_add(MAX_TTL_MS)
            && now_ms < self.expires_at_ms.saturating_add(TOMBSTONE_MS)
    }

    fn tombstone(self) -> Self {
        Self {
            pub_hex: self.pub_hex,
            generation: self.generation,
            received_at_ms: self.received_at_ms,
            expires_at_ms: self.expires_at_ms,
            via: self.via,
            peer_id: String::new(),
            peer_id_proven: false,
            relays: Vec::new(),
            direct: Vec::new(),
            custodians: Vec::new(),
            // A reservation on an offered relay may outlive the offer.
            offers: self.offers,
            custodian_tags: Vec::new(),
            custodian_tag_flags: Vec::new(),
            custody_offer: None,
            nat_class: None,
            inet: Vec::new(),
            lan: None,
        }
    }

    /// As its readers see it at `now_ms` ([`tidy`]): past its expiry a
    /// tombstone. A LAN part past its own expiry, or in a tombstone, is kept
    /// for dialling ([`LanPart::kept_part`]) or goes.
    fn aged(mut self, now_ms: u64) -> Self {
        let live = self.live(now_ms);
        let lan = self.lan.take().and_then(|l| {
            if live && l.live(now_ms) {
                Some(l)
            } else {
                l.kept_part(now_ms)
            }
        });
        let mut entry = if live { self } else { self.tombstone() };
        entry.lan = lan;
        entry
    }

    /// The tombstone of a contact unheard for [`FORGET_AFTER_MS`] (OD-C10):
    /// its key, generation and carrier, and its times to the day (rounded
    /// down: the tombstone goes at most a day early); no address, port,
    /// relay, relay offer or custodian. The generation is the sender's clock
    /// in ms (spec §5.3: `max(previous + 1, unix_ms)`), so it is kept to the
    /// day too: no frame is ever compared with an expired entry's (any frame
    /// replaces it), and a lower one never holds a newer frame back.
    fn forgotten(self) -> Self {
        let day = |ms: u64| ms - ms % DAY_MS;
        let mut bare = self.tombstone();
        bare.generation = day(bare.generation).max(1);
        bare.received_at_ms = day(bare.received_at_ms);
        bare.expires_at_ms = day(bare.expires_at_ms);
        bare.offers = Vec::new();
        bare
    }

    /// A live entry's view at `now_ms`: its LAN part only while that is live
    /// too (one kept past its expiry is [`learned_with_lan`]'s alone).
    fn view(&self, now_ms: u64) -> LearnedView {
        let peer_id = normalize_peer_id(&self.peer_id).ok();
        let vias =
            |texts: &[String], max: usize, keep: &dyn Fn(&ViaAddr) -> bool| -> Vec<ViaAddr> {
                if peer_id.is_none() {
                    return Vec::new();
                }
                texts
                    .iter()
                    .filter_map(|t| parse_via(t).ok())
                    .filter(keep)
                    .take(max)
                    .collect()
            };
        let own = |v: &ViaAddr| peer_id.as_deref() == Some(v.peer_id.as_str());
        // The RELAY address rule (spec §5.2) again, for a snapshot stored
        // before it held.
        let (lab_local, lab_loopback) = (
            crate::p2p_local_candidates_enabled(),
            crate::route_hints::lab_loopback_relays(),
        );
        let usable_relay = |v: &ViaAddr| {
            !own(v) && crate::route_hints::relay_host_usable(v, lab_local, lab_loopback)
        };
        LearnedView {
            generation: self.generation,
            received_at_ms: self.received_at_ms,
            expires_at_ms: self.expires_at_ms,
            via: self.via,
            peer_id_proven: self.peer_id_proven && peer_id.is_some(),
            relays: vias(&self.relays, MAX_RELAY_ENTRIES, &usable_relay),
            direct: vias(&self.direct, MAX_GLOBAL_DIRECT, &own),
            custodians: self
                .custodians
                .iter()
                .filter_map(|h| <[u8; 32]>::try_from(hex::decode(h).ok()?).ok())
                .take(MAX_CUSTODIANS)
                .collect(),
            nat_class: self
                .nat_class
                .filter(|_| peer_id.is_some())
                .map(NatClass::normalized),
            // The receiver's rule again (spec §13.3), for a file edited by
            // hand: canonical, and globally routable unless in a lab.
            inet: self
                .inet
                .iter()
                .filter_map(|e| {
                    let addr: std::net::SocketAddr = e.addr.parse().ok()?;
                    (addr.to_string() == e.addr
                        && (crate::p2p_route::is_global_ip(addr.ip()) || lab_local))
                        .then_some((addr, e.confirmed))
                })
                .take(crate::route_hints::MAX_INET_DIRECT)
                .collect(),
            lan: self
                .lan
                .as_ref()
                .filter(|l| l.live(now_ms))
                .map(|l| l.view(vias(&l.local_direct, MAX_LOCAL_DIRECT, &own))),
            peer_id: peer_id.clone(),
        }
    }

    /// Its custody fields as a planner reads them ([`LearnedCustody`]).
    fn custody(&self) -> LearnedCustody {
        let key = |h: &String| <[u8; 32]>::try_from(hex::decode(h).ok()?).ok();
        let mut tags: Vec<[u8; 32]> = Vec::new();
        let mut tag_flags: Vec<u8> = Vec::new();
        for (i, raw) in self.custodian_tags.iter().enumerate() {
            let Some(tag) = key(raw) else {
                continue;
            };
            let flags = self.custodian_tag_flags.get(i).copied().unwrap_or(0);
            if let Some(j) = tags.iter().position(|t| *t == tag) {
                tag_flags[j] |= flags;
            } else if tags.len() < MAX_CUSTODIANS && tag != [0; 32] {
                tags.push(tag);
                tag_flags.push(flags);
            }
        }
        LearnedCustody {
            tags,
            tag_flags,
            plain: self
                .custodians
                .iter()
                .filter_map(key)
                .take(MAX_CUSTODIANS)
                .collect(),
            offer: self.custody_offer.map(|f| f & CUSTODY_OFFER_KNOWN),
            heard_ms: self.received_at_ms,
        }
    }

    /// The custody fields [`Applied::Changed`] compares.
    fn custody_fields(&self) -> (&[String], &[String], &[u8], Option<u8>) {
        (
            &self.custodians,
            &self.custodian_tags,
            &self.custodian_tag_flags,
            self.custody_offer,
        )
    }
}

impl LanPart {
    fn live(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms
    }

    /// What it keeps past its expiry (Phase 3 P3.C1): its LAN IP and port,
    /// and the network they belong to, until [`LAN_KEEP_MS`] after it was
    /// received; its same-LAN direct addresses go (p2p routes: the p2p
    /// dialler reads only a live LAN part). `None` once that time is up,
    /// without a port to dial, or when it is stamped in the future (the
    /// clock went back).
    fn kept_part(self, now_ms: u64) -> Option<Self> {
        let keep = self.lan_port.is_some_and(|p| p != 0)
            && self.received_at_ms <= now_ms.saturating_add(CLOCK_SLACK_MS)
            && now_ms < self.received_at_ms.saturating_add(LAN_KEEP_MS);
        keep.then(|| Self {
            local_direct: Vec::new(),
            ..self
        })
    }

    /// What a planner reads of it, with its same-LAN direct addresses as the
    /// caller checked them.
    fn view(&self, local_direct: Vec<ViaAddr>) -> LearnedLan {
        let ip = ScopedIp::parse(&self.lan_ip);
        LearnedLan {
            port: self.lan_port.filter(|p| *p != 0),
            ip: ip.as_ref().map(ScopedIp::ip),
            zone: ip.as_ref().and_then(|ip| ip.zone().map(str::to_owned)),
            local_direct,
            local_tag: self.local_tag.clone(),
            told: self.told,
            received_at_ms: self.received_at_ms,
        }
    }
}

#[cfg(test)]
thread_local! {
    static LOADS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// File reads [`load`] made on this thread (tests count a caller's reads).
#[cfg(test)]
pub(crate) fn loads_on_this_thread() -> usize {
    LOADS.with(std::cell::Cell::get)
}

fn load(data_dir: &Path) -> Vec<Learned> {
    #[cfg(test)]
    LOADS.with(|n| n.set(n.get() + 1));
    // Advisory state: a missing or unreadable file is an empty one.
    at_rest::load_json_advisory(
        data_dir,
        &data_dir.join(LEARNED_ROUTES_FILE),
        Kind::LearnedRoutes,
    )
    .into_loaded()
    .unwrap_or_default()
}

/// [`current`] for a writer that holds [`LEARNED_ROUTES_LOCK`]: `Err` when
/// the file could not be read and so must not be written over (counted).
fn current_for_write(data_dir: &Path, now_ms: u64) -> Result<Vec<Learned>, String> {
    at_rest::load_json_for_write(
        data_dir,
        &data_dir.join(LEARNED_ROUTES_FILE),
        Kind::LearnedRoutes,
    )
    .map(|all| tidy(all, now_ms))
    .map_err(|e| format!("{LEARNED_ROUTES_FILE}: {e}"))
}

/// The entries as of `now_ms`, newest first, one per sender: past their
/// expiry they are tombstones, past [`TOMBSTONE_MS`] (or stamped in the
/// future) gone, and an expired LAN part keeps only its IP and port, until
/// [`LAN_KEEP_MS`] after it was received ([`Learned::aged`]).
fn tidy(mut all: Vec<Learned>, now_ms: u64) -> Vec<Learned> {
    all.sort_by_key(|e| Reverse(e.received_at_ms));
    let mut seen = HashSet::new();
    all.into_iter()
        .filter(|e| e.kept(now_ms) && seen.insert(e.pub_hex.clone()))
        .map(|e| e.aged(now_ms))
        .collect()
}

fn current(data_dir: &Path, now_ms: u64) -> Vec<Learned> {
    tidy(load(data_dir), now_ms)
}

fn save(data_dir: &Path, mut all: Vec<Learned>) -> Result<(), String> {
    all.sort_by_key(|e| Reverse(e.received_at_ms));
    all.truncate(MAX_ENTRIES);
    // At most MAX_OFFERS relay offers in all: the newest senders' stay.
    let mut room = MAX_OFFERS;
    for e in &mut all {
        e.offers.truncate(room.min(MAX_RELAY_OFFERS));
        room -= e.offers.len();
    }
    let raw = serde_json::to_vec_pretty(&all).map_err(|e| e.to_string())?;
    // The caller holds LEARNED_ROUTES_LOCK: sealed in a sealed profile.
    at_rest::write_held(
        data_dir,
        &data_dir.join(LEARNED_ROUTES_FILE),
        Kind::LearnedRoutes,
        &raw,
    )
    .map_err(|e| e.to_string())
}

/// Store what `sender` (its device Ed25519 key) told this node in one RRH1,
/// already checked against `link` ([`crate::route_hints::validate`]).
/// `local_tag` is this computer's [`crate::route_memory::egress_tag`], kept
/// with the LAN part (a LAN port or same-LAN direct addresses).
/// [`Applied::Ignored`] (and no file) while route hints are off.
pub fn apply(
    data_dir: &Path,
    sender: &[u8; 32],
    v: &ValidHints,
    link: &HintLink<'_>,
    local_tag: Option<String>,
    now_ms: u64,
) -> Result<Applied, String> {
    if !route_hints_live() {
        return Ok(Applied::Ignored);
    }
    record(data_dir, sender, v, link, local_tag, now_ms)
}

/// [`apply`] with the gate open: other modules' tests seed the file with it.
#[cfg(test)]
pub(crate) fn apply_ungated(
    data_dir: &Path,
    sender: &[u8; 32],
    v: &ValidHints,
    link: &HintLink<'_>,
    local_tag: Option<String>,
    now_ms: u64,
) -> Result<Applied, String> {
    record(data_dir, sender, v, link, local_tag, now_ms)
}

/// [`apply`] without the gate.
fn record(
    data_dir: &Path,
    sender: &[u8; 32],
    v: &ValidHints,
    link: &HintLink<'_>,
    local_tag: Option<String>,
    now_ms: u64,
) -> Result<Applied, String> {
    if v.generation == 0 {
        return Ok(Applied::Ignored);
    }
    let key = hex::encode(sender);
    let step = |mut all: Vec<Learned>| {
        let old = all
            .iter()
            .position(|e| e.pub_hex == key)
            .map(|i| all.remove(i));
        let (entry, applied) = merge(old, &key, v, link, local_tag.clone(), now_ms);
        all.push(entry);
        (all, applied)
    };
    // Most frames repeat what is stored: no lock and no write for those.
    if let (_, applied @ (Applied::Stale | Applied::Unchanged)) = step(current(data_dir, now_ms)) {
        return Ok(applied);
    }
    let _lock = DataDirLock::acquire_within(data_dir, LEARNED_ROUTES_LOCK, LOCK_WAIT)?;
    // A file this process could not read is never written over: the frame
    // is not stored (the contact's next link carries it again).
    let Ok(all) = current_for_write(data_dir, now_ms) else {
        return Ok(Applied::Ignored);
    };
    let (all, applied) = step(all);
    if !matches!(applied, Applied::Stale | Applied::Unchanged) {
        save(data_dir, all)?;
    }
    Ok(applied)
}

/// One frame against the sender's entry (spec §5.3 and §5.4): the new entry
/// and what changed.
fn merge(
    old: Option<Learned>,
    pub_hex: &str,
    v: &ValidHints,
    link: &HintLink<'_>,
    local_tag: Option<String>,
    now_ms: u64,
) -> (Learned, Applied) {
    let ttl_ms = u64::from(v.ttl_s.clamp(RRH1_MIN_TTL_S, RRH1_MAX_TTL_S)) * 1000;
    let expires = now_ms.saturating_add(ttl_ms);
    let refresh_due =
        |old_expires: u64| expires.saturating_sub(old_expires) >= REFRESH_WRITE_MS.min(ttl_ms / 2);
    let peer_id = v.peer_id.clone().unwrap_or_default();
    let texts = |vias: &[ViaAddr]| vias.iter().map(|a| a.text.clone()).collect::<Vec<_>>();
    let local_direct = texts(&v.local_direct);
    let fresh = Learned {
        pub_hex: pub_hex.to_owned(),
        generation: v.generation,
        received_at_ms: now_ms,
        expires_at_ms: expires,
        via: link.carrier,
        peer_id_proven: link.carrier == OutboxCarrier::P2p
            && !peer_id.is_empty()
            && link
                .link_peer_id
                .and_then(|p| normalize_peer_id(p).ok())
                .is_some_and(|p| p == peer_id),
        peer_id,
        relays: texts(&v.relays),
        direct: texts(&v.direct),
        custodians: v.custodians.iter().map(hex::encode).collect(),
        custodian_tags: v.custodian_tags.iter().map(hex::encode).collect(),
        custodian_tag_flags: v.custodian_tag_flags.clone(),
        custody_offer: v.custody_offer,
        offers: v
            .offers
            .iter()
            .take(MAX_RELAY_OFFERS)
            .map(|o| StoredOffer {
                relay_peer_id: o.relay_peer_id(),
                addrs: o.addrs.clone(),
                flags: o.flags,
            })
            .collect(),
        nat_class: v.nat_class.filter(|_| v.peer_id.is_some()),
        inet: v
            .inet
            .iter()
            .map(|e| StoredInet {
                addr: e.addr.to_string(),
                confirmed: e.confirmed(),
            })
            .collect(),
        lan: (link.carrier == OutboxCarrier::Lan).then(|| LanPart {
            generation: v.generation,
            received_at_ms: now_ms,
            expires_at_ms: expires,
            lan_port: v.lan_port,
            // The link's peer IP (with the zone of a link-local one), never
            // a host the frame names.
            lan_ip: link
                .peer_ip
                .map(|ip| ScopedIp::new(ip, link.peer_zone).to_string())
                .unwrap_or_default(),
            local_tag: local_tag
                .clone()
                .filter(|_| !local_direct.is_empty() || v.lan_port.is_some()),
            local_direct,
            told: false,
        }),
    };
    // LAN_ADDR (spec §16): the LAN part a verified contact told over another
    // link, its first address (the caller kept only ones on this computer's
    // own networks). The address is the contact's word, so it is marked.
    let mut fresh = fresh;
    if link.carrier != OutboxCarrier::Lan {
        fresh.lan = v.lan_addrs.first().map(|e| LanPart {
            generation: v.generation,
            received_at_ms: now_ms,
            expires_at_ms: expires,
            lan_port: Some(e.addr.port()).filter(|p| *p != 0),
            lan_ip: e.addr.ip().to_canonical().to_string(),
            local_direct: Vec::new(),
            local_tag: local_tag.clone(),
            told: true,
        });
    }
    // A newer snapshot over another link without one withdraws a told LAN
    // part (the contact left that network, or hides its IP now); a LAN
    // link's part only a LAN link changes.
    let withdraws = |held: &LanPart| {
        fresh.lan.is_none()
            && link.carrier != OutboxCarrier::Lan
            && held.told
            && v.generation > held.generation
    };
    // No entry, or an expired one: any frame replaces it. The LAN part an
    // expired one kept (P3.C1) stays unless this frame came over a LAN link
    // or told a LAN address (§16), the only ones that change the LAN part,
    // or withdraws a told one.
    let old = match old {
        Some(old) if old.live(now_ms) => old,
        expired => {
            let kept = expired
                .as_ref()
                .and_then(|e| e.lan.clone())
                .filter(|l| !withdraws(l));
            let mut fresh = fresh;
            if fresh.lan.is_none() {
                fresh.lan = kept;
            }
            let applied = changed(expired.as_ref(), &fresh).unwrap_or(Applied::Refreshed);
            return (fresh, applied);
        }
    };

    let mut entry = old.clone();
    let mut wrote = false;
    let same_global = fresh.peer_id == old.peer_id
        && fresh.relays == old.relays
        && fresh.direct == old.direct
        && fresh.custody_fields() == old.custody_fields()
        && fresh.offers == old.offers
        && fresh.nat_class == old.nat_class
        && fresh.inet == old.inet;
    let global_stale = v.generation < old.generation;
    // E2 r9 #17: the same snapshot over two links right after the sender's
    // start, one told before its p2p listeners were up (no same-LAN
    // addresses: "direct=0"), one after ("direct=2"). When only the direct
    // addresses differ and the newer frame names fewer of the same ones
    // (a subset), the held set stays, so the view of the sender no longer
    // flips to the poorer set when it arrives last. Any other change (a
    // listener on a new port: carrier matrix C20) replaces it as before.
    let fewer_direct = !same_global
        && fresh.peer_id == old.peer_id
        && fresh.relays == old.relays
        && fresh.custody_fields() == old.custody_fields()
        && fresh.offers == old.offers
        && fresh.nat_class == old.nat_class
        && fresh.inet == old.inet
        && fresh.direct.iter().all(|d| old.direct.contains(d));
    if v.generation == old.generation && fewer_direct {
        entry.peer_id_proven |= fresh.peer_id_proven;
        entry.expires_at_ms = expires.max(old.expires_at_ms);
        if refresh_due(old.expires_at_ms) {
            entry.via = link.carrier;
            wrote = true;
        }
    } else if v.generation > old.generation || (v.generation == old.generation && !same_global) {
        // A newer snapshot replaces the global part whole. So does the same
        // generation when it checks out differently now (this node verified
        // the sender, or its book PeerId changed): the sender's content is
        // the same, this node's rules are newer.
        entry = Learned {
            expires_at_ms: if v.generation > old.generation {
                expires
            } else {
                expires.max(old.expires_at_ms)
            },
            peer_id_proven: fresh.peer_id_proven
                || (old.peer_id_proven && old.peer_id == fresh.peer_id),
            lan: old.lan.clone(),
            ..fresh.clone()
        };
        wrote = true;
    } else if !global_stale {
        entry.peer_id_proven |= fresh.peer_id_proven;
        entry.expires_at_ms = expires.max(old.expires_at_ms);
        if refresh_due(old.expires_at_ms) {
            entry.via = link.carrier;
            wrote = true;
        }
    }

    let mut lan_stale = true;
    if old.lan.as_ref().is_some_and(withdraws) {
        lan_stale = false;
        entry.lan = None;
        wrote = true;
    }
    if let Some(part) = fresh.lan {
        // A LAN part past its expiry (kept for dialling) is no generation to
        // hold: any LAN frame replaces it.
        match old.lan.as_ref().filter(|held| held.live(now_ms)) {
            Some(held) if v.generation < held.generation => {}
            // §16: a LAN link's part at least as new as the snapshot that
            // told an address over another link stays (the link's own peer
            // IP beats the contact's word); a LAN link's frame replaces a
            // told part of its generation or older.
            Some(held) if part.told && !held.told && v.generation == held.generation => {
                lan_stale = false;
            }
            Some(held) if !part.told && held.told => {
                lan_stale = false;
                entry.lan = Some(part);
                wrote = true;
            }
            // The same snapshot over a link to another of the sender's
            // addresses (its IPv6 one, its Wi-Fi beside its cable) that adds
            // nothing to the held part: that stays as it is (E2 night: a
            // friend's view of win-c flipped between "direct=0" and
            // "direct=2" all night, and every flip retried its queue and
            // woke custody).
            Some(held)
                if v.generation == held.generation
                    && part.lan_ip != held.lan_ip
                    && (part.local_tag.is_none() || part.local_tag == held.local_tag)
                    && !lan_adds(&part, held) =>
            {
                lan_stale = false;
            }
            Some(held) if v.generation == held.generation && same_lan(held, &part) => {
                lan_stale = false;
                if refresh_due(held.expires_at_ms) {
                    entry.lan = Some(LanPart {
                        received_at_ms: now_ms,
                        expires_at_ms: expires.max(held.expires_at_ms),
                        ..held.clone()
                    });
                    wrote = true;
                }
            }
            // E2 r9 #17: the same snapshot from the same address naming
            // fewer of the same same-LAN addresses (one told before the
            // sender's p2p listeners were up named none): the held part
            // stays. Other addresses (a new port) replace it below.
            Some(held)
                if v.generation == held.generation
                    && part.lan_ip == held.lan_ip
                    && part.lan_port == held.lan_port
                    && part.local_tag == held.local_tag
                    && part
                        .local_direct
                        .iter()
                        .all(|d| held.local_direct.contains(d)) =>
            {
                lan_stale = false;
                if refresh_due(held.expires_at_ms) {
                    entry.lan = Some(LanPart {
                        received_at_ms: now_ms,
                        expires_at_ms: expires.max(held.expires_at_ms),
                        ..held.clone()
                    });
                    wrote = true;
                }
            }
            // None (or expired), or at least its generation: replace it.
            _ => {
                lan_stale = false;
                entry.lan = Some(part);
                wrote = true;
            }
        }
    }

    let applied = match changed(Some(&old), &entry) {
        Some(changed) => changed,
        None if wrote => Applied::Refreshed,
        None if global_stale && lan_stale => Applied::Stale,
        None => Applied::Unchanged,
    };
    if !matches!(applied, Applied::Stale | Applied::Unchanged) {
        entry.received_at_ms = now_ms;
    }
    (entry, applied)
}

/// Does `part` add to `held` (spec §5.3): another LAN port, or a same-LAN
/// direct address `held` lacks?
fn lan_adds(part: &LanPart, held: &LanPart) -> bool {
    part.lan_port
        .is_some_and(|p| p != 0 && held.lan_port != Some(p))
        || part
            .local_direct
            .iter()
            .any(|d| !held.local_direct.contains(d))
}

fn same_lan(a: &LanPart, b: &LanPart) -> bool {
    a.lan_port == b.lan_port
        && a.lan_ip == b.lan_ip
        && a.local_direct == b.local_direct
        && a.local_tag == b.local_tag
        && a.told == b.told
}

/// [`Applied::Changed`] when what a planner reads differs between `old` (no
/// entry: nothing) and `new`.
fn changed(old: Option<&Learned>, new: &Learned) -> Option<Applied> {
    // The direct routes to it: its PeerId and what it names, and (auto-reach)
    // its Internet direct addresses.
    fn p2p(e: Option<&Learned>) -> (&str, bool, &[String], &[String], &[StoredInet]) {
        match e {
            Some(e) => (&e.peer_id, e.peer_id_proven, &e.relays, &e.direct, &e.inet),
            None => ("", false, &[], &[], &[]),
        }
    }
    fn lan(e: Option<&Learned>) -> Option<&LanPart> {
        // A LAN part with no route plans nothing.
        e.and_then(|e| e.lan.as_ref())
            .filter(|l| l.lan_port.is_some() || !l.local_direct.is_empty())
    }
    fn custody(e: Option<&Learned>) -> (&[String], &[String], &[u8], Option<u8>) {
        e.map_or((&[], &[], &[], None), Learned::custody_fields)
    }
    let new = Some(new);
    let p2p = p2p(old) != p2p(new);
    let lan = match (lan(old), lan(new)) {
        (Some(a), Some(b)) => !same_lan(a, b),
        (a, b) => a.is_some() != b.is_some(),
    };
    let custody = custody(old) != custody(new);
    (p2p || lan || custody).then_some(Applied::Changed { lan, p2p, custody })
}

/// `peer`'s live snapshot: `None` when it never sent one, it expired (a
/// tombstone) or it was forgotten. Its `lan` is the live LAN part only.
pub fn learned(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Option<LearnedView> {
    let key = hex::encode(peer);
    current(data_dir, now_ms)
        .into_iter()
        .find(|e| e.pub_hex == key && e.live(now_ms))
        .map(|e| e.view(now_ms))
}

/// [`learned`], and the LAN part the planners dial ([`rrh1_lan_dials`]),
/// from one read: the live snapshot's own, or else one kept past its expiry
/// (Phase 3 P3.C1): its LAN IP and port, [`LAN_KEEP_MS`] after it was
/// received, whether the rest of the snapshot is live or a tombstone. For
/// the delivery planners only: a kept part names no PeerId and is no
/// announce target ([`live_contacts`]).
pub fn learned_with_lan(
    data_dir: &Path,
    peer: &[u8; 32],
    now_ms: u64,
) -> (Option<LearnedView>, Option<LearnedLan>) {
    let key = hex::encode(peer);
    let Some(e) = current(data_dir, now_ms)
        .into_iter()
        .find(|e| e.pub_hex == key)
    else {
        return (None, None);
    };
    let view = e.live(now_ms).then(|| e.view(now_ms));
    let lan = match view.as_ref().and_then(|v| v.lan.clone()) {
        Some(live) => Some(live),
        // Read as `tidy` left it: a part kept past its expiry, if any.
        None => e.lan.as_ref().map(|l| l.view(Vec::new())),
    };
    (view, lan)
}

/// Whether `peer`'s live snapshot is newer than its LAN part (or it has no
/// live LAN part): a newer generation came over an Internet or p2p link,
/// which never changes the LAN part (spec §5.3), so its same-LAN addresses
/// and LAN port may be stale. A LAN dial then asks for route hints
/// (spec §3.2, §6.1). `false` without a live snapshot.
pub fn lan_part_behind(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> bool {
    let key = hex::encode(peer);
    current(data_dir, now_ms)
        .into_iter()
        .find(|e| e.pub_hex == key && e.live(now_ms))
        .is_some_and(|e| {
            e.lan
                .as_ref()
                .is_none_or(|l| !l.live(now_ms) || l.generation < e.generation)
        })
}

/// What `peer`'s live snapshot says about custody (Phase 3 P3.18): `None`
/// for an unknown, expired (a tombstone) or forgotten sender. No gate here:
/// the custody planners check [`crate::custody_gate::custody_hints_live`].
pub fn learned_custody(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Option<LearnedCustody> {
    let key = hex::encode(peer);
    current(data_dir, now_ms)
        .into_iter()
        .find(|e| e.pub_hex == key && e.live(now_ms))
        .map(|e| e.custody())
}

/// [`learned_custody`] for every live snapshot, from one read of the file:
/// for callers that loop over contacts.
pub fn learned_custody_all(data_dir: &Path, now_ms: u64) -> HashMap<[u8; 32], LearnedCustody> {
    current(data_dir, now_ms)
        .into_iter()
        .filter(|e| e.live(now_ms))
        .filter_map(|e| {
            let peer = <[u8; 32]>::try_from(hex::decode(&e.pub_hex).ok()?).ok()?;
            Some((peer, e.custody()))
        })
        .collect()
}

/// (sender, CUSTODY_OFFER flags, when that snapshot was stored) of every
/// live snapshot that carries an offer, newest first, at most
/// [`MAX_CUSTODY_OFFERS`]. A tombstone offers nothing.
pub fn custody_offers(data_dir: &Path, now_ms: u64) -> Vec<([u8; 32], u8, u64)> {
    current(data_dir, now_ms)
        .into_iter()
        .filter(|e| e.live(now_ms))
        .filter_map(|e| {
            let peer = <[u8; 32]>::try_from(hex::decode(&e.pub_hex).ok()?).ok()?;
            let c = e.custody();
            Some((peer, c.offer?, c.heard_ms))
        })
        .take(MAX_CUSTODY_OFFERS)
        .collect()
}

/// When `peer`'s last RRH1 was stored, and whether that snapshot has
/// expired since (a tombstone, kept [`TOMBSTONE_MS`]). For the diagnosis.
pub fn last_heard(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Option<(u64, bool)> {
    let key = hex::encode(peer);
    current(data_dir, now_ms)
        .into_iter()
        .find(|e| e.pub_hex == key)
        .map(|e| (e.received_at_ms, !e.live(now_ms)))
}

/// Contacts with a live learned PeerId, newest first: (device key hex,
/// PeerId, proven by a p2p link). For the p2p peer gate.
pub fn learned_peer_ids(data_dir: &Path, now_ms: u64) -> Vec<(String, String, bool)> {
    current(data_dir, now_ms)
        .into_iter()
        .filter(|e| e.live(now_ms))
        .filter_map(|e| {
            let view = e.view(now_ms);
            Some((e.pub_hex, view.peer_id?, view.peer_id_proven))
        })
        .collect()
}

/// The p2p part ([`LearnedView::p2p`]) of every live snapshot that names a
/// PeerId, newest first: (device key hex, what it named). For the p2p peer
/// gate.
pub fn learned_p2p(data_dir: &Path, now_ms: u64) -> Vec<(String, LearnedP2p)> {
    current(data_dir, now_ms)
        .into_iter()
        .filter(|e| e.live(now_ms))
        .filter_map(|e| {
            let p2p = e.view(now_ms).p2p()?;
            Some((e.pub_hex, p2p))
        })
        .collect()
}

/// The relays contacts' live route hints name (RELAY), each with when the
/// newest snapshot that names it was received (wall-clock ms). A relay that
/// turned this node away before then may admit it now (its operator may
/// have added this node since): raven-node tries it again.
pub fn relays_named_at(data_dir: &Path, now_ms: u64) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = Vec::new();
    for e in current(data_dir, now_ms)
        .into_iter()
        .filter(|e| e.live(now_ms))
    {
        let at = e.received_at_ms;
        for relay in e.view(now_ms).relays {
            match out.iter_mut().find(|(p, _)| *p == relay.peer_id) {
                Some(seen) => seen.1 = seen.1.max(at),
                None => out.push((relay.peer_id, at)),
            }
        }
    }
    out
}

/// The NAT mapping classes contacts' live snapshots name (Phase 4, RRH1
/// NAT_CLASS), newest first: (device key hex, the PeerId the snapshot
/// named, the classes, when the snapshot expires, wall-clock ms). For the
/// hole-punch policy (raven-node's peer gate load); no gate here.
pub fn nat_classes(data_dir: &Path, now_ms: u64) -> Vec<(String, String, NatClass, u64)> {
    current(data_dir, now_ms)
        .into_iter()
        .filter(|e| e.live(now_ms))
        .filter_map(|e| {
            let view = e.view(now_ms);
            Some((e.pub_hex, view.peer_id?, view.nat_class?, e.expires_at_ms))
        })
        .collect()
}

/// Contacts whose RRH1 has not expired, newest first. They accept RRH1, so
/// they are the announce targets. A LAN part kept past its expiry (P3.C1)
/// makes no contact one.
pub fn live_contacts(data_dir: &Path, now_ms: u64) -> Vec<[u8; 32]> {
    current(data_dir, now_ms)
        .into_iter()
        .filter(|e| e.live(now_ms))
        .filter_map(|e| <[u8; 32]>::try_from(hex::decode(&e.pub_hex).ok()?).ok())
        .collect()
}

/// The relays contacts offer this node (spec §11.3), newest sender first:
/// (the operator's device key hex, the PeerId its snapshot named (empty when
/// it named none, and for a tombstone), the offer, when that snapshot
/// expires). An expired snapshot's offers are still listed, with their past
/// expiry, while it is a tombstone: a reservation there may outlive the
/// offer. At most [`MAX_RELAY_OFFERS`] per operator and [`MAX_OFFERS`] in
/// all. No gate here: relay choice checks it.
pub fn offers(data_dir: &Path, now_ms: u64) -> Vec<(String, String, StoredOffer, u64)> {
    let mut out = Vec::new();
    for e in current(data_dir, now_ms) {
        let peer_id = normalize_peer_id(&e.peer_id).unwrap_or_default();
        let mut relays: Vec<String> = Vec::new();
        for offer in e.offers.iter().filter_map(StoredOffer::checked) {
            if out.len() == MAX_OFFERS {
                return out;
            }
            if relays.len() == MAX_RELAY_OFFERS || relays.contains(&offer.relay_peer_id) {
                continue;
            }
            relays.push(offer.relay_peer_id.clone());
            out.push((e.pub_hex.clone(), peer_id.clone(), offer, e.expires_at_ms));
        }
    }
    out
}

/// A p2p link whose libp2p PeerId is `link_peer_id` carried `peer`'s Raven
/// identity: the PeerId `peer` named is proven. `true` when that is news.
/// Nothing is written while route hints are off.
pub fn note_p2p_link(
    data_dir: &Path,
    peer: &[u8; 32],
    link_peer_id: &str,
    now_ms: u64,
) -> Result<bool, String> {
    if !route_hints_live() {
        return Ok(false);
    }
    prove(data_dir, peer, link_peer_id, now_ms)
}

/// [`note_p2p_link`] without the gate.
fn prove(
    data_dir: &Path,
    peer: &[u8; 32],
    link_peer_id: &str,
    now_ms: u64,
) -> Result<bool, String> {
    let Ok(link_peer_id) = normalize_peer_id(link_peer_id) else {
        return Ok(false);
    };
    let key = hex::encode(peer);
    let unproven = |all: &[Learned]| {
        all.iter().position(|e| {
            e.pub_hex == key && e.live(now_ms) && !e.peer_id_proven && e.peer_id == link_peer_id
        })
    };
    if unproven(&current(data_dir, now_ms)).is_none() {
        return Ok(false);
    }
    let _lock = DataDirLock::acquire_within(data_dir, LEARNED_ROUTES_LOCK, LOCK_WAIT)?;
    let Ok(mut all) = current_for_write(data_dir, now_ms) else {
        return Ok(false);
    };
    let Some(i) = unproven(&all) else {
        return Ok(false);
    };
    all[i].peer_id_proven = true;
    save(data_dir, all)?;
    Ok(true)
}

/// Forget what `peer` told this node, the relays it offered, its custody
/// fields and its tombstone included (its contact was removed or blocked,
/// or its address set by hand). Missing file or entry is fine.
pub fn forget(data_dir: &Path, peer: &[u8; 32]) -> Result<(), String> {
    let key = hex::encode(peer);
    let path = data_dir.join(LEARNED_ROUTES_FILE);
    // Lock-free first: nothing to forget, no lock (and no lock file).
    match at_rest::load_json_advisory::<Vec<Learned>>(data_dir, &path, Kind::LearnedRoutes) {
        at_rest::Advisory::Missing | at_rest::Advisory::CorruptPlain => return Ok(()),
        at_rest::Advisory::Loaded(all) if !all.iter().any(|e| e.pub_hex == key) => {
            return Ok(());
        }
        at_rest::Advisory::Loaded(_) | at_rest::Advisory::Unreadable(_) => {}
    }
    let _lock = DataDirLock::acquire(data_dir, LEARNED_ROUTES_LOCK)?;
    // A file that could not be read is kept as it is (an error).
    let mut all: Vec<Learned> = at_rest::load_json_for_write(data_dir, &path, Kind::LearnedRoutes)
        .map_err(|e| format!("{LEARNED_ROUTES_FILE}: {e}"))?;
    let before = all.len();
    all.retain(|e| e.pub_hex != key);
    if all.len() == before {
        return Ok(());
    }
    save(data_dir, all)
}

/// `raven contact forget-address` (field test E3 round 2): forget what
/// `peer`'s route hints said about reaching it (its PeerId, relays, direct
/// and Internet addresses, NAT classes, the relays it offered and its LAN
/// part) and keep what they said about its mail friends (custodian keys and
/// tags with their flags, its custody offer: no address in any of them).
/// The kept entry's generation goes to 0: the contact's next RRH1 replaces
/// it whatever its generation, and until one comes this node holds no
/// routes of it ([`holds_no_routes`]), so its next link asks for them. An
/// entry with no mail friend to keep goes whole ([`forget`]). Whether mail
/// friends were kept; a missing file or entry is fine.
pub fn forget_routes(data_dir: &Path, peer: &[u8; 32]) -> Result<bool, String> {
    let key = hex::encode(peer);
    let path = data_dir.join(LEARNED_ROUTES_FILE);
    match at_rest::load_json_advisory::<Vec<Learned>>(data_dir, &path, Kind::LearnedRoutes) {
        at_rest::Advisory::Missing | at_rest::Advisory::CorruptPlain => return Ok(false),
        at_rest::Advisory::Loaded(all) if !all.iter().any(|e| e.pub_hex == key) => {
            return Ok(false);
        }
        at_rest::Advisory::Loaded(_) | at_rest::Advisory::Unreadable(_) => {}
    }
    let _lock = DataDirLock::acquire(data_dir, LEARNED_ROUTES_LOCK)?;
    let mut all: Vec<Learned> = at_rest::load_json_for_write(data_dir, &path, Kind::LearnedRoutes)
        .map_err(|e| format!("{LEARNED_ROUTES_FILE}: {e}"))?;
    let Some(at) = all.iter().position(|e| e.pub_hex == key) else {
        return Ok(false);
    };
    let old = all.remove(at);
    let kept =
        !old.custodians.is_empty() || !old.custodian_tags.is_empty() || old.custody_offer.is_some();
    if kept {
        all.push(Learned {
            generation: 0,
            peer_id: String::new(),
            peer_id_proven: false,
            relays: Vec::new(),
            direct: Vec::new(),
            offers: Vec::new(),
            nat_class: None,
            inet: Vec::new(),
            lan: None,
            ..old
        });
    }
    save(data_dir, all)?;
    Ok(kept)
}

/// Whether this node holds no routes of `peer` from its route hints: no live
/// snapshot, or one whose routes `raven contact forget-address` forgot
/// ([`forget_routes`]: generation 0, its mail friends kept).
pub fn holds_no_routes(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> bool {
    learned(data_dir, peer, now_ms).is_none_or(|v| v.generation == 0)
}

/// Phase 6b R5 (design A, step P6.28): another key answered at `ip` when
/// this node dialled `peer` there often enough to be Suspicious. Forget the
/// LAN part `peer`'s RRH1 learned at that address (its port, its same-LAN
/// direct addresses); the global part, the relays and the custody fields
/// stay, and so does every address saved by hand (that is the contact
/// book's). The contact's next LAN link teaches its address again. Whether
/// anything was forgotten; a missing file or entry is fine, and a file that
/// could not be read is kept as it is (an error).
pub fn forget_lan_at(data_dir: &Path, peer: &[u8; 32], ip: IpAddr) -> Result<bool, String> {
    let key = hex::encode(peer);
    let ip = ScopedIp::new(ip, None).ip();
    let at = |e: &Learned| {
        e.pub_hex == key
            && e.lan
                .as_ref()
                .and_then(|l| ScopedIp::parse(&l.lan_ip))
                .is_some_and(|l| l.ip() == ip)
    };
    let path = data_dir.join(LEARNED_ROUTES_FILE);
    // Lock-free first: nothing at that address, no lock (and no lock file).
    match at_rest::load_json_advisory::<Vec<Learned>>(data_dir, &path, Kind::LearnedRoutes) {
        at_rest::Advisory::Missing | at_rest::Advisory::CorruptPlain => return Ok(false),
        at_rest::Advisory::Loaded(all) if !all.iter().any(at) => return Ok(false),
        at_rest::Advisory::Loaded(_) | at_rest::Advisory::Unreadable(_) => {}
    }
    let _lock = DataDirLock::acquire_within(data_dir, LEARNED_ROUTES_LOCK, LOCK_WAIT)?;
    let mut all: Vec<Learned> = at_rest::load_json_for_write(data_dir, &path, Kind::LearnedRoutes)
        .map_err(|e| format!("{LEARNED_ROUTES_FILE}: {e}"))?;
    let mut forgot = false;
    for e in &mut all {
        if at(e) {
            e.lan = None;
            forgot = true;
        }
    }
    if forgot {
        save(data_dir, all)?;
    }
    Ok(forgot)
}

/// Privacy pack PP.7: write the file as its readers see it ([`tidy`]: an
/// expired snapshot becomes a tombstone without its routes, an expired LAN
/// part keeps only its IP and port (Phase 3 P3.C1) and goes
/// [`LAN_KEEP_MS`] after it was received, a past tombstone and an entry
/// stamped in the future go; before, only a frame or a forget rewrote it),
/// and cut the tombstone of every contact unheard for [`FORGET_AFTER_MS`]
/// to [`Learned::forgotten`]: its relay offers go too. Heard is the newer
/// of its last stored RRH1 and its last authenticated LAN link
/// (`last_link`: device key hex -> ms, [`crate::lan_seen::sighting_times`];
/// `None` when those could not be read, and then no tombstone is cut). No
/// plan changes: the planners read only live snapshots and kept LAN parts
/// (a forgotten tombstone's LAN part was older than [`LAN_KEEP_MS`]
/// already). Under [`LEARNED_ROUTES_LOCK`] (a busy one skips this pass);
/// lock-free first. How many entries went or lost something.
pub fn prune(
    data_dir: &Path,
    now_ms: u64,
    last_link: Option<&HashMap<String, u64>>,
) -> Result<usize, String> {
    let unheard = |e: &Learned| {
        let Some(links) = last_link else {
            return false;
        };
        let link = links
            .get(&e.pub_hex.to_ascii_lowercase())
            .copied()
            .unwrap_or(0);
        !e.live(now_ms) && now_ms.saturating_sub(e.received_at_ms.max(link)) > FORGET_AFTER_MS
    };
    let pruned = |all: &[Learned]| {
        let kept: Vec<Learned> = tidy(all.to_vec(), now_ms)
            .into_iter()
            .map(|e| if unheard(&e) { e.forgotten() } else { e })
            .collect();
        let changed = all.iter().filter(|e| !kept.contains(e)).count();
        (kept, changed)
    };
    let path = data_dir.join(LEARNED_ROUTES_FILE);
    match at_rest::load_json_advisory::<Vec<Learned>>(data_dir, &path, Kind::LearnedRoutes) {
        at_rest::Advisory::Missing | at_rest::Advisory::CorruptPlain => return Ok(0),
        at_rest::Advisory::Unreadable(e) => return Err(format!("{LEARNED_ROUTES_FILE}: {e}")),
        at_rest::Advisory::Loaded(all) if pruned(&all).1 == 0 => return Ok(0),
        at_rest::Advisory::Loaded(_) => {}
    }
    let _lock = DataDirLock::acquire_within(data_dir, LEARNED_ROUTES_LOCK, LOCK_WAIT)?;
    let all: Vec<Learned> = at_rest::load_json_for_write(data_dir, &path, Kind::LearnedRoutes)
        .map_err(|e| format!("{LEARNED_ROUTES_FILE}: {e}"))?;
    let (kept, changed) = pruned(&all);
    if changed > 0 {
        save(data_dir, kept)?;
    }
    Ok(changed)
}

/// The LAN routes RRH1 adds for a contact, from its LAN part `lan` (the live
/// one, or one kept past its expiry: [`learned_with_lan`]): its announced
/// port on each saved host, then on the IP of the LAN link that carried it,
/// then on `seen` (where it last reached us,
/// [`crate::lan_seen::usable_sighting`]). Deduplicated, never equal to a `saved` route, at most `budget`
/// (what the lan_seen routes left of [`MAX_LEARNED_LAN_DIALS`]). An IPv6
/// link-local address is dialled with its zone (`[fe80::b%en0]:port`); one
/// without a zone cannot be dialled back and is skipped.
pub fn rrh1_lan_dials(
    lan: Option<&LearnedLan>,
    seen: Option<&ScopedIp>,
    saved: &[String],
    budget: usize,
) -> Vec<String> {
    let Some(lan) = lan else {
        return Vec::new();
    };
    let Some(port) = lan.port else {
        return Vec::new();
    };
    let on_addr = |addr: ScopedIp| addr.dialable().then(|| addr.dial(port));
    let on_host = |dial: &String| {
        let (host, _) = crate::lan_seen::split_host_port(dial.trim())?;
        match ScopedIp::parse(host) {
            Some(addr) => on_addr(addr),
            None if host.contains(':') => Some(format!("[{host}]:{port}")),
            None => Some(format!("{host}:{port}")),
        }
    };
    // The contact's saved host first: the port is the contact's own word
    // and the host the user's; the addresses it was only seen at (the
    // link's peer IP, a sighting) may be a router's in front of it (E2).
    let candidates = saved
        .iter()
        .filter_map(on_host)
        .chain(
            lan.ip
                .map(|ip| ScopedIp::new(ip, lan.zone.as_deref()))
                .and_then(on_addr),
        )
        .chain(seen.cloned().and_then(on_addr));
    let cap = budget.min(MAX_LEARNED_LAN_DIALS);
    let mut out: Vec<String> = Vec::new();
    for dial in candidates {
        if out.len() == cap {
            break;
        }
        if !saved.iter().chain(&out).any(|s| same_dial(s, &dial)) {
            out.push(dial);
        }
    }
    out
}

/// The same `host:port` (an IPv4-mapped IPv6 address is its IPv4 address).
fn same_dial(a: &str, b: &str) -> bool {
    match (
        a.trim().parse::<SocketAddr>(),
        b.trim().parse::<SocketAddr>(),
    ) {
        (Ok(a), Ok(b)) => a.ip().to_canonical() == b.ip().to_canonical() && a.port() == b.port(),
        _ => a.trim().eq_ignore_ascii_case(b.trim()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody_gate::{OFFER_REACHABLE, OFFER_WAN};
    use crate::identity::Identity;
    use crate::p2p_route::{libp2p_ed25519_public, local_peer_id, peer_id_bytes};
    use crate::route_hints::{
        validate, RelayOfferRecord, RouteHints, FLAG_AUTONAT, RRH1_DEFAULT_TTL_S,
    };
    use serde_json::json;

    const MIN: u64 = 60 * 1000;
    const DAY: u64 = 24 * 60 * MIN;
    const T0: u64 = 20_000 * DAY;
    const TTL_MS: u64 = RRH1_DEFAULT_TTL_S as u64 * 1000;
    const BOTH: Applied = Applied::Changed {
        lan: true,
        p2p: true,
        custody: false,
    };
    const LAN: Applied = Applied::Changed {
        lan: true,
        p2p: false,
        custody: false,
    };
    const P2P: Applied = Applied::Changed {
        lan: false,
        p2p: true,
        custody: false,
    };

    fn pid(seed: u8) -> String {
        local_peer_id(&Identity::from_seed(&[seed; 32]))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn scoped(s: &str) -> ScopedIp {
        ScopedIp::parse(s).unwrap()
    }

    fn relay(n: u8, seed: u8) -> String {
        format!("/ip4/11.0.2.{n}/tcp/7423/p2p/{}", pid(seed))
    }

    /// From the fixture sender (seed 0x51): its PeerId, relay R1 (seed 0x61),
    /// one global and one same-LAN direct address, LAN port 7531, one
    /// custodian.
    fn frame(generation: u64) -> RouteHints {
        RouteHints {
            generation,
            ttl_s: RRH1_DEFAULT_TTL_S,
            p2p_id: Some(peer_id_bytes(&pid(0x51)).unwrap()),
            relays: vec![relay(1, 0x61)],
            direct: vec![
                "/ip4/11.0.3.5/tcp/7423".into(),
                "/ip4/192.168.7.20/tcp/7423".into(),
            ],
            lan_port: Some(7531),
            custodians: vec![[0x77; 32]],
            ..Default::default()
        }
    }

    /// The fixture link from a verified sender (LAN: from 192.168.7.20).
    fn link(carrier: OutboxCarrier) -> HintLink<'static> {
        HintLink::fixture(carrier, true)
    }

    fn sender() -> [u8; 32] {
        link(OutboxCarrier::Lan).sender
    }

    fn put(dir: &Path, h: &RouteHints, link: &HintLink, now: u64) -> Applied {
        record(dir, &link.sender, &validate(h, link), link, None, now).unwrap()
    }

    fn view(dir: &Path, now: u64) -> LearnedView {
        learned(dir, &sender(), now).expect("a live snapshot")
    }

    fn texts(vias: &[ViaAddr]) -> Vec<String> {
        vias.iter().map(|v| v.text.clone()).collect()
    }

    fn read(dir: &Path) -> Vec<u8> {
        std::fs::read(dir.join(LEARNED_ROUTES_FILE)).unwrap()
    }

    /// The device key of the `i`-th other contact.
    fn peer(i: usize) -> [u8; 32] {
        let mut p = [0xaa; 32];
        p[..8].copy_from_slice(&(i as u64).to_be_bytes());
        p
    }

    /// A frame with no entries from contact `peer`.
    fn empty(dir: &Path, peer: &[u8; 32], ttl_s: u32, now: u64) {
        let v = ValidHints {
            generation: 1,
            ttl_s,
            ..Default::default()
        };
        record(dir, peer, &v, &link(OutboxCarrier::P2p), None, now).unwrap();
    }

    /// The public key of a relay's own key from `seed` (never a profile's).
    fn relay_key(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    /// An offer of the relay with key `key` at 11.0.4.`n`, TCP and QUIC.
    fn offer_of(key: [u8; 32], n: u8) -> RelayOfferRecord {
        RelayOfferRecord {
            flags: FLAG_AUTONAT,
            relay_pub: key,
            addrs: vec![
                format!("/ip4/11.0.4.{n}/tcp/7427"),
                format!("/ip4/11.0.4.{n}/udp/7427/quic-v1"),
            ],
        }
    }

    /// [`offer_of`] as it is stored.
    fn stored(key: [u8; 32], n: u8) -> StoredOffer {
        let r = offer_of(key, n);
        StoredOffer {
            relay_peer_id: r.relay_peer_id(),
            addrs: r.addrs,
            flags: r.flags,
        }
    }

    /// The fixture frame with these offers.
    fn with_offers(generation: u64, offers: &[RelayOfferRecord]) -> RouteHints {
        RouteHints {
            offers: offers.to_vec(),
            ..frame(generation)
        }
    }

    /// What [`offers`] lists for the fixture sender.
    fn offered(dir: &Path, now: u64) -> Vec<StoredOffer> {
        let s = hex::encode(sender());
        offers(dir, now)
            .into_iter()
            .filter(|(operator, ..)| *operator == s)
            .map(|(_, _, offer, _)| offer)
            .collect()
    }

    /// Offers stored in the file, every sender's.
    fn offers_on_disk(dir: &Path) -> usize {
        let raw: serde_json::Value = serde_json::from_slice(&read(dir)).unwrap();
        raw.as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e.get("offers"))
            .map(|o| o.as_array().unwrap().len())
            .sum()
    }

    #[test]
    fn apply_generation_table() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let lan = link(OutboxCarrier::Lan);
        let inet = link(OutboxCarrier::Internet);
        assert_eq!(put(d, &frame(5), &lan, T0), BOTH_C, "a first snapshot");
        let first = read(d);

        // Equal: the expiry extends, but the file is rewritten at most hourly.
        assert_eq!(put(d, &frame(5), &lan, T0 + 10 * MIN), Applied::Unchanged);
        assert_eq!(read(d), first);
        assert_eq!(put(d, &frame(5), &lan, T0 + 61 * MIN), Applied::Refreshed);
        let v = view(d, T0 + 61 * MIN);
        assert_eq!((v.generation, v.expires_at_ms), (5, T0 + 61 * MIN + TTL_MS));

        // Lower: ignored, whatever it says and wherever it came from.
        let mut older = frame(4);
        older.relays = vec![relay(9, 0x69)];
        older.lan_port = Some(7999);
        let held = read(d);
        assert_eq!(put(d, &older, &lan, T0 + 62 * MIN), Applied::Stale);
        assert_eq!(put(d, &older, &inet, T0 + 62 * MIN), Applied::Stale);
        assert_eq!(read(d), held);

        // Higher with the same routes: the generation moves, nothing to replan.
        assert_eq!(put(d, &frame(6), &lan, T0 + 63 * MIN), Applied::Refreshed);
        assert_eq!(view(d, T0 + 63 * MIN).generation, 6);

        // Higher with other routes, from another link: replaced.
        let mut newer = frame(7);
        newer.relays = vec![relay(2, 0x62)];
        assert_eq!(put(d, &newer, &inet, T0 + 64 * MIN), P2P);
        let v = view(d, T0 + 64 * MIN);
        assert_eq!((v.generation, v.via), (7, OutboxCarrier::Internet));
        assert_eq!(texts(&v.relays), [relay(2, 0x62)]);
        assert_eq!(v.lan.unwrap().port, Some(7531), "the LAN part stays");

        // Expired: not used, and any generation replaces it.
        let late = v.expires_at_ms;
        assert!(learned(d, &sender(), late - 1).is_some());
        assert!(learned(d, &sender(), late).is_none());
        assert_eq!(put(d, &older, &lan, late), BOTH_C);
        let v = view(d, late);
        assert_eq!(v.generation, 4);
        assert_eq!(texts(&v.relays), [relay(9, 0x69)]);
        assert_eq!(v.lan.unwrap().port, Some(7999));
    }

    #[test]
    fn snapshot_semantics_withdraw_missing_entries() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let p2p = link(OutboxCarrier::P2p);
        let mut full = frame(5);
        full.relays = vec![relay(1, 0x61), relay(2, 0x62)];
        assert_eq!(put(d, &full, &p2p, T0), P2P_C);
        let v = view(d, T0);
        assert_eq!(v.peer_id.as_deref(), Some(pid(0x51).as_str()));
        assert_eq!(texts(&v.relays), [relay(1, 0x61), relay(2, 0x62)]);
        assert_eq!(
            texts(&v.direct),
            [format!("/ip4/11.0.3.5/tcp/7423/p2p/{}", pid(0x51))]
        );
        assert_eq!(v.custodians, [[0x77; 32]]);
        assert_eq!(v.lan, None, "a p2p link carries no LAN part");

        // What the newer frame lacks is withdrawn.
        let mut fewer = frame(6);
        fewer.relays = vec![relay(2, 0x62)];
        fewer.direct.clear();
        fewer.custodians.clear();
        assert_eq!(put(d, &fewer, &p2p, T0 + 1), P2P_C);
        let v = view(d, T0 + 1);
        assert_eq!(texts(&v.relays), [relay(2, 0x62)]);
        assert!(v.direct.is_empty() && v.custodians.is_empty());

        // Without P2P_ID every relay and direct address goes too.
        let mut bare = frame(7);
        bare.p2p_id = None;
        assert_eq!(put(d, &bare, &p2p, T0 + 2), P2P_C);
        let v = view(d, T0 + 2);
        assert_eq!((v.peer_id.as_deref(), v.peer_id_proven), (None, false));
        assert!(v.relays.is_empty() && v.direct.is_empty() && v.p2p().is_none());
        assert_eq!(v.custodians, [[0x77; 32]]);

        // Custodians alone.
        bare.generation = 8;
        bare.custodians.clear();
        assert_eq!(
            put(d, &bare, &p2p, T0 + 3),
            Applied::Changed {
                lan: false,
                p2p: false,
                custody: true,
            }
        );
        assert!(view(d, T0 + 3).custodians.is_empty());
    }

    #[test]
    fn lan_ip_comes_from_the_link_never_from_the_frame() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let lan = link(OutboxCarrier::Lan);
        let mut h = frame(5);
        h.direct = vec![
            "/ip4/192.168.7.44/tcp/7423".into(),
            "/ip4/10.9.9.9/tcp/7423".into(),
        ];
        let tag = Some("net-a".to_string());
        let v = validate(&h, &lan);
        assert_eq!(
            record(d, &lan.sender, &v, &lan, tag.clone(), T0),
            Ok(BOTH_C)
        );
        let l = view(d, T0).lan.unwrap();
        assert_eq!(l.ip, Some(ip("192.168.7.20")), "the link's peer IP");
        assert_eq!(l.port, Some(7531));
        assert_eq!(
            texts(&l.local_direct),
            [format!("/ip4/192.168.7.44/tcp/7423/p2p/{}", pid(0x51))],
            "a same-LAN address is a dial target, never the LAN IP"
        );
        assert_eq!(l.local_tag, tag);
        let p2p = view(d, T0).p2p().unwrap();
        assert_eq!((p2p.local_direct, p2p.local_tag), (l.local_direct, tag));

        // The same frame from another address of that contact (v4-mapped)
        // adds nothing: the held part stays (E2, spec §5.3).
        let moved = HintLink {
            peer_ip: Some(ip("::ffff:192.168.7.33")),
            ..lan
        };
        let v = validate(&h, &moved);
        assert_eq!(
            record(d, &lan.sender, &v, &moved, Some("net-a".into()), T0 + 1),
            Ok(Applied::Unchanged)
        );
        assert_eq!(view(d, T0 + 1).lan.unwrap().ip, Some(ip("192.168.7.20")));
        // With another LAN port it does: the IP follows the link
        // (v4-mapped, as IPv4).
        h.lan_port = Some(7532);
        let v = validate(&h, &moved);
        assert_eq!(
            record(d, &lan.sender, &v, &moved, Some("net-a".into()), T0 + 1),
            Ok(LAN)
        );
        assert_eq!(view(d, T0 + 1).lan.unwrap().ip, Some(ip("192.168.7.33")));
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(raw.contains("\"lan_ip\": \"192.168.7.33\""), "{raw}");
        h.lan_port = Some(7531);

        // No same-LAN address: the LAN port is that network's too, so the
        // part keeps its tag, and it belongs to that network only.
        h.direct.clear();
        let v = validate(&h, &lan);
        record(d, &lan.sender, &v, &lan, Some("net-a".into()), T0 + 2).unwrap();
        let l = view(d, T0 + 2).lan.unwrap();
        assert_eq!(
            (l.port, l.local_tag.as_deref()),
            (Some(7531), Some("net-a"))
        );
        assert!(l.on_network(Some("net-a")) && !l.on_network(Some("net-b")));
        assert!(
            l.on_network(None),
            "no default route: a LAN without internet"
        );
        // Neither a port nor an address: no tag either.
        h.lan_port = None;
        let v = validate(&h, &lan);
        record(d, &lan.sender, &v, &lan, Some("net-a".into()), T0 + 3).unwrap();
        let l = view(d, T0 + 3).lan.unwrap();
        assert_eq!(l.local_tag, None);
        assert!(l.on_network(Some("net-b")), "an untagged part is anywhere");

        // Over Internet and p2p: never a LAN part.
        let other = tempfile::tempdir().unwrap();
        for carrier in [OutboxCarrier::Internet, OutboxCarrier::P2p] {
            put(other.path(), &frame(5), &link(carrier), T0);
            assert_eq!(view(other.path(), T0).lan, None, "{carrier:?}");
        }
    }

    #[test]
    fn bounded_expiring_and_corrupt_file_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let lan = link(OutboxCarrier::Lan);
        let s = sender();

        // Clock edges: a 60 s snapshot.
        let mut short = frame(5);
        short.ttl_s = 60;
        put(d, &short, &lan, T0);
        assert!(learned(d, &s, T0 + 60_000 - 1).is_some());
        assert!(learned(d, &s, T0 + 60_000).is_none());
        // At most 7 days, whatever the frame asks.
        let v = ValidHints {
            ttl_s: u32::MAX,
            ..validate(&frame(6), &lan)
        };
        record(d, &s, &v, &lan, None, T0 + 1).unwrap();
        assert_eq!(view(d, T0 + 1).expires_at_ms, T0 + 1 + 7 * DAY);

        // The clock went back: an entry stamped in the future is not used,
        // and the next frame replaces it whatever its generation.
        let back = T0 - CLOCK_SLACK_MS - 2;
        assert!(learned(d, &s, back).is_none());
        assert_eq!(last_heard(d, &s, back), None);
        assert_eq!(put(d, &frame(1), &lan, back), BOTH_C);
        assert_eq!(view(d, back).generation, 1);

        // Bounded: the newest MAX_ENTRIES stay.
        for i in 0..MAX_ENTRIES + 10 {
            empty(d, &peer(i), 600, T0 + i as u64);
        }
        let now = T0 + 1_000;
        assert_eq!(load(d).len(), MAX_ENTRIES);
        let live = live_contacts(d, now);
        assert_eq!(live.len(), MAX_ENTRIES);
        assert_eq!(live[0], peer(MAX_ENTRIES + 9), "newest first");
        assert_eq!(last_heard(d, &peer(9), now), None, "the oldest went");
        assert_eq!(last_heard(d, &s, now), None);

        // A corrupt file reads empty, and the next frame replaces it.
        std::fs::write(d.join(LEARNED_ROUTES_FILE), b"{not json").unwrap();
        assert!(learned(d, &peer(MAX_ENTRIES + 9), now).is_none());
        assert!(live_contacts(d, now).is_empty() && learned_peer_ids(d, now).is_empty());
        assert_eq!(put(d, &frame(5), &lan, now), BOTH_C);
        assert!(learned(d, &s, now).is_some());
    }

    #[test]
    fn forget_removes_one() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(d, &frame(5), &link(OutboxCarrier::Lan), T0);
        empty(d, &peer(1), 600, T0);
        forget(d, &sender()).unwrap();
        assert!(learned(d, &sender(), T0).is_none());
        assert_eq!(last_heard(d, &sender(), T0), None);
        assert_eq!(last_heard(d, &peer(1), T0), Some((T0, false)));
        forget(d, &sender()).unwrap();

        // Nothing to forget: no file, no lock file.
        let fresh = tempfile::tempdir().unwrap();
        forget(fresh.path(), &sender()).unwrap();
        assert_eq!(std::fs::read_dir(fresh.path()).unwrap().count(), 0);
    }

    #[test]
    fn note_p2p_link_proves_the_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let s = sender();
        let lan = link(OutboxCarrier::Lan);
        put(d, &frame(5), &lan, T0);
        let me = (hex::encode(s), pid(0x51));
        assert_eq!(
            learned_peer_ids(d, T0),
            [(me.0.clone(), me.1.clone(), false)]
        );
        assert!(!view(d, T0).p2p().unwrap().proven, "learned over LAN");

        assert!(!prove(d, &s, &pid(0x52), T0).unwrap(), "another PeerId");
        assert!(!prove(d, &s, "garbage", T0).unwrap());
        assert!(
            !prove(d, &peer(1), &pid(0x51), T0).unwrap(),
            "another contact"
        );
        assert!(!view(d, T0).peer_id_proven);
        assert!(prove(d, &s, &pid(0x51), T0).unwrap());
        assert!(!prove(d, &s, &pid(0x51), T0).unwrap(), "no news");
        assert_eq!(learned_peer_ids(d, T0), [(me.0.clone(), me.1, true)]);

        // The same PeerId in a newer snapshot stays proven.
        assert_eq!(put(d, &frame(6), &lan, T0 + 1), Applied::Refreshed);
        assert!(view(d, T0 + 1).peer_id_proven);

        // Another PeerId (the book has none) starts unproven ...
        let p53 = pid(0x53);
        let mut other = frame(7);
        other.p2p_id = Some(peer_id_bytes(&p53).unwrap());
        let unbooked = HintLink {
            book_peer_id: None,
            ..lan
        };
        assert_eq!(put(d, &other, &unbooked, T0 + 2), BOTH);
        let v = view(d, T0 + 2);
        assert_eq!(v.peer_id.as_deref(), Some(p53.as_str()));
        assert!(!v.peer_id_proven);
        assert!(
            !prove(d, &s, &p53, v.expires_at_ms).unwrap(),
            "an expired snapshot proves nothing"
        );
        // ... and a p2p link with that PeerId proves it by carrying it.
        let p2p = HintLink {
            book_peer_id: None,
            link_peer_id: Some(&p53),
            ..link(OutboxCarrier::P2p)
        };
        assert_eq!(put(d, &other, &p2p, T0 + 3), P2P);
        assert!(view(d, T0 + 3).peer_id_proven);
    }

    #[test]
    fn rrh1_lan_dials_order_dedup_and_budget() {
        let at = |port: Option<u16>, link_ip: &str| LearnedView {
            generation: 1,
            received_at_ms: T0,
            expires_at_ms: T0 + TTL_MS,
            via: OutboxCarrier::Lan,
            peer_id: None,
            peer_id_proven: false,
            relays: Vec::new(),
            direct: Vec::new(),
            custodians: Vec::new(),
            nat_class: None,
            inet: Vec::new(),
            lan: Some(LearnedLan {
                port,
                ip: link_ip.parse().ok(),
                zone: None,
                local_direct: Vec::new(),
                local_tag: None,
                told: false,
                received_at_ms: T0,
            }),
        };
        let strings = |s: &[&str]| s.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let saved = strings(&["192.168.7.20:7420", "bob-mac.local:7420"]);
        let v = at(Some(7531), "192.168.7.20");
        let seen = Some(scoped("192.168.7.33"));

        // The saved hosts, then the link IP, then the lan_seen IP: an
        // address the contact was only seen at goes last (E2).
        assert_eq!(
            rrh1_lan_dials(v.lan.as_ref(), seen.as_ref(), &saved, 2),
            ["192.168.7.20:7531", "bob-mac.local:7531"]
        );
        let one_saved = strings(&["192.168.7.20:7420"]);
        assert_eq!(
            rrh1_lan_dials(v.lan.as_ref(), seen.as_ref(), &one_saved, 2),
            ["192.168.7.20:7531", "192.168.7.33:7531"]
        );
        let elsewhere = at(Some(7531), "192.168.7.40");
        assert_eq!(
            rrh1_lan_dials(elsewhere.lan.as_ref(), seen.as_ref(), &one_saved, 2),
            ["192.168.7.20:7531", "192.168.7.40:7531"]
        );
        assert_eq!(
            rrh1_lan_dials(v.lan.as_ref(), seen.as_ref(), &saved, 1),
            ["192.168.7.20:7531"]
        );
        assert!(rrh1_lan_dials(v.lan.as_ref(), seen.as_ref(), &saved, 0).is_empty());
        assert_eq!(
            rrh1_lan_dials(v.lan.as_ref(), seen.as_ref(), &saved, 9).len(),
            MAX_LEARNED_LAN_DIALS
        );
        // Deduplicated (a v4-mapped sighting is its IPv4 address).
        assert_eq!(
            rrh1_lan_dials(
                v.lan.as_ref(),
                Some(&scoped("::ffff:192.168.7.20")),
                &saved,
                2
            ),
            ["192.168.7.20:7531", "bob-mac.local:7531"]
        );
        // Never a saved route.
        let current = strings(&["192.168.7.20:7531"]);
        assert!(rrh1_lan_dials(v.lan.as_ref(), None, &current, 2).is_empty());

        // IPv6: a scope-less link-local address is skipped, a scoped saved
        // host is kept.
        let v6 = at(Some(7531), "fe80::1");
        let saved6 = strings(&["[fe80::1]:7420", "[fe80::1%en0]:7420", "[fd00::4]:7420"]);
        assert_eq!(
            rrh1_lan_dials(v6.lan.as_ref(), Some(&scoped("fe80::2")), &saved6, 2),
            ["[fe80::1%en0]:7531", "[fd00::4]:7531"]
        );

        // No port, or no LAN part: nothing.
        assert!(rrh1_lan_dials(
            at(None, "192.168.7.20").lan.as_ref(),
            seen.as_ref(),
            &saved,
            2
        )
        .is_empty());
        let no_lan = LearnedView { lan: None, ..v };
        assert!(rrh1_lan_dials(no_lan.lan.as_ref(), seen.as_ref(), &saved, 2).is_empty());
    }

    /// Phase 3 P3.4: a LAN link from an IPv6 link-local address keeps its
    /// zone in the LAN part, and RRH1 dials it (and a zoned sighting) with
    /// that zone; without a zone neither is dialled. An older build's
    /// `parse::<IpAddr>()` refuses the zoned `lan_ip`: no route there at all.
    #[test]
    fn rrh1_lan_dials_accept_a_scoped_link_local_and_skip_a_scope_less_one() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let lan = HintLink {
            peer_ip: Some(ip("fe80::1")),
            peer_zone: Some("en0"),
            ..link(OutboxCarrier::Lan)
        };
        record(d, &lan.sender, &validate(&frame(5), &lan), &lan, None, T0).unwrap();
        let l = view(d, T0).lan.unwrap();
        assert_eq!(
            (l.ip, l.zone.as_deref(), l.port),
            (Some(ip("fe80::1")), Some("en0"), Some(7531))
        );
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(raw.contains("\"lan_ip\": \"fe80::1%en0\""), "{raw}");
        assert!("fe80::1%en0".parse::<IpAddr>().is_err(), "an older build");
        let saved = vec!["192.168.7.20:7420".to_string()];
        assert_eq!(
            rrh1_lan_dials(
                view(d, T0).lan.as_ref(),
                Some(&scoped("fe80::2%en1")),
                &saved,
                2
            ),
            ["192.168.7.20:7531", "[fe80::1%en0]:7531"]
        );
        assert_eq!(
            rrh1_lan_dials(
                view(d, T0).lan.as_ref(),
                Some(&scoped("fe80::2%en1")),
                &[],
                2
            ),
            ["[fe80::1%en0]:7531", "[fe80::2%en1]:7531"]
        );

        // The same link without its zone: the LAN part holds the bare
        // address and no dial goes there, nor to a scope-less sighting.
        let bare = HintLink {
            peer_zone: None,
            ..lan
        };
        record(
            d,
            &lan.sender,
            &validate(&frame(6), &bare),
            &bare,
            None,
            T0 + 1,
        )
        .unwrap();
        let l = view(d, T0 + 1).lan.unwrap();
        assert_eq!((l.ip, l.zone), (Some(ip("fe80::1")), None));
        assert_eq!(
            rrh1_lan_dials(
                view(d, T0 + 1).lan.as_ref(),
                Some(&scoped("fe80::2")),
                &saved,
                2
            ),
            ["192.168.7.20:7531"]
        );

        // A zone means nothing on any other address: not kept.
        let v4 = HintLink {
            peer_zone: Some("en0"),
            ..link(OutboxCarrier::Lan)
        };
        record(d, &lan.sender, &validate(&frame(7), &v4), &v4, None, T0 + 2).unwrap();
        let l = view(d, T0 + 2).lan.unwrap();
        assert_eq!((l.ip, l.zone), (Some(ip("192.168.7.20")), None));
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(raw.contains("\"lan_ip\": \"192.168.7.20\""), "{raw}");
    }

    #[test]
    fn no_file_is_written_while_the_gate_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let lan = link(OutboxCarrier::Lan);
        let applied = apply(d, &lan.sender, &validate(&frame(5), &lan), &lan, None, T0).unwrap();
        let proved = note_p2p_link(d, &lan.sender, &pid(0x51), T0).unwrap();
        if route_hints_live() {
            assert_eq!((applied, proved), (BOTH_C, true));
            assert!(d.join(LEARNED_ROUTES_FILE).exists());
        } else {
            assert_eq!((applied, proved), (Applied::Ignored, false));
            assert_eq!(
                std::fs::read_dir(d).unwrap().count(),
                0,
                "not even the lock file"
            );
        }
    }

    #[test]
    fn a_newer_p2p_frame_keeps_the_lan_part() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(put(d, &frame(5), &link(OutboxCarrier::Lan), T0), BOTH_C);
        let mut moved = frame(6);
        moved.relays = vec![relay(2, 0x62)];
        moved.lan_port = None;
        assert_eq!(put(d, &moved, &link(OutboxCarrier::P2p), T0 + MIN), P2P);
        let v = view(d, T0 + MIN);
        assert_eq!(texts(&v.relays), [relay(2, 0x62)]);
        let l = v.lan.unwrap();
        assert_eq!((l.port, l.ip), (Some(7531), Some(ip("192.168.7.20"))));
        assert_eq!(l.local_direct.len(), 1);
    }

    /// `frame(generation)` with the LAN_ADDR entry `addr` (spec §16).
    fn told_lan(generation: u64, addr: &str) -> RouteHints {
        RouteHints {
            lan_addrs: vec![crate::route_hints::InetDirect {
                flags: 0,
                addr: addr.parse().unwrap(),
            }],
            ..frame(generation)
        }
    }

    /// Route hints spec §16 (field test E3, owner decision 2026-10-30): a
    /// LAN address a verified contact told over Tor becomes its LAN part,
    /// marked as told. A LAN link's part of the same generation replaces it
    /// and is not replaced by it; a newer told one replaces that; a newer
    /// snapshot over another link without one withdraws a told part (never
    /// a LAN link's: `a_newer_p2p_frame_keeps_the_lan_part`); an older one
    /// touches nothing. On disk a LAN link's part carries no `told` key, as
    /// before.
    #[test]
    fn a_lan_address_told_over_tor_is_the_lan_part_until_a_lan_link_says_more() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (tor, lan) = (link(OutboxCarrier::Onion), link(OutboxCarrier::Lan));
        let part = |now: u64| view(d, now).lan.expect("a LAN part");
        let told = told_lan(5, "192.168.7.21:7421");
        assert_eq!(put(d, &told, &tor, T0), BOTH_C);
        let l = part(T0);
        assert_eq!(
            (l.ip, l.port, l.told, l.local_direct.len()),
            (Some(ip("192.168.7.21")), Some(7421), true, 0)
        );
        let on_disk = |d: &Path| -> serde_json::Value {
            serde_json::from_slice::<serde_json::Value>(&read(d)).unwrap()[0]["lan"]["told"].clone()
        };
        assert_eq!(on_disk(d), json!(true));
        assert_eq!(put(d, &told, &tor, T0 + MIN), Applied::Unchanged);
        // The LAN link's own part (its peer IP, its port) replaces it.
        assert_eq!(put(d, &frame(5), &lan, T0 + 2 * MIN), LAN);
        let l = part(T0 + 2 * MIN);
        assert_eq!(
            (l.ip, l.port, l.told),
            (Some(ip("192.168.7.20")), Some(7531), false)
        );
        assert_eq!(on_disk(d), serde_json::Value::Null, "no `told` key");
        // The same snapshot told over Tor again: the LAN link's part stays.
        assert_eq!(put(d, &told, &tor, T0 + 3 * MIN), Applied::Unchanged);
        assert!(!part(T0 + 3 * MIN).told);
        // A newer one (the contact's listener moved) replaces it.
        assert_eq!(
            put(d, &told_lan(6, "192.168.7.21:7422"), &tor, T0 + 4 * MIN),
            LAN
        );
        let l = part(T0 + 4 * MIN);
        assert_eq!((l.port, l.told), (Some(7422), true));
        // An older one touches nothing.
        assert_eq!(
            put(d, &told_lan(4, "192.168.7.22:7423"), &tor, T0 + 5 * MIN),
            Applied::Stale
        );
        assert_eq!(part(T0 + 5 * MIN).port, Some(7422));
        // A newer snapshot without one (the contact hides its IP now, or
        // left this network) withdraws it.
        assert_eq!(put(d, &frame(7), &tor, T0 + 6 * MIN), LAN);
        assert_eq!(view(d, T0 + 6 * MIN).lan, None);
        // Never on a LAN link: there the link's peer IP is the LAN part's.
        let on_lan = validate(&told_lan(8, "192.168.7.21:7421"), &lan);
        assert!(on_lan.lan_addrs.is_empty());
    }

    /// §16: a told LAN part kept past its expiry (P3.C1) is withdrawn by a
    /// newer snapshot without one too, and kept by one that has it.
    #[test]
    fn an_expired_told_lan_part_is_withdrawn_by_a_newer_snapshot_without_one() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let tor = link(OutboxCarrier::Onion);
        put(d, &told_lan(5, "192.168.7.21:7421"), &tor, T0);
        let later = T0 + TTL_MS + MIN;
        let kept = learned_with_lan(d, &sender(), later).1.expect("kept");
        assert!(kept.told);
        put(d, &told_lan(6, "192.168.7.21:7421"), &tor, later);
        assert!(learned_with_lan(d, &sender(), later).1.unwrap().told);
        let much_later = later + TTL_MS + MIN;
        put(d, &frame(7), &tor, much_later);
        assert_eq!(learned_with_lan(d, &sender(), much_later).1, None);
    }

    /// Field test E3 round 2: `raven contact forget-address` also forgot
    /// the mail friends the contact told about ("told you about: none",
    /// "nobody can carry it"). Its routes go; its custody entries stay, and
    /// the next frame, whatever its generation, brings the routes back.
    #[test]
    fn forgetting_routes_keeps_the_mail_friends_the_contact_told_about() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let tor = link(OutboxCarrier::Onion);
        let told = RouteHints {
            lan_addrs: vec![crate::route_hints::InetDirect {
                flags: 0,
                addr: "192.168.7.21:7421".parse().unwrap(),
            }],
            custody_offer: Some(OFFER_WAN),
            custodian_tags: vec![([0x44; 32], 1)],
            ..frame(5)
        };
        put(d, &told, &tor, T0);
        assert!(!holds_no_routes(d, &sender(), T0));
        assert_eq!(forget_routes(d, &sender()), Ok(true));
        assert!(holds_no_routes(d, &sender(), T0));
        let v = view(d, T0);
        assert_eq!(v.generation, 0);
        assert!(v.peer_id.is_none() && v.relays.is_empty() && v.direct.is_empty());
        assert!(v.lan.is_none() && v.inet.is_empty());
        assert_eq!((v.custodians.len(), v.custodians[0]), (1, [0x77; 32]));
        let custody = learned_custody(d, &sender(), T0).unwrap();
        assert_eq!(custody.tags, [[0x44; 32]]);
        assert_eq!(custody.offer, Some(OFFER_WAN));
        // No address is left in the file.
        let text = String::from_utf8(read(d)).unwrap();
        for gone in ["192.168", "11.0.", "/p2p/"] {
            assert!(!text.contains(gone), "{gone}: {text}");
        }
        // The next frame, an older generation even, brings the routes back.
        put(d, &frame(4), &tor, T0 + MIN);
        let v = view(d, T0 + MIN);
        assert_eq!(v.generation, 4);
        assert!(v.peer_id.is_some());
        assert!(!holds_no_routes(d, &sender(), T0 + MIN));
        // Nothing about mail friends: the entry goes whole.
        let other = tempfile::tempdir().unwrap();
        put(other.path(), &frame(5), &link(OutboxCarrier::P2p), T0);
        let plain = RouteHints {
            custodians: Vec::new(),
            ..frame(6)
        };
        put(other.path(), &plain, &link(OutboxCarrier::P2p), T0);
        assert_eq!(forget_routes(other.path(), &sender()), Ok(false));
        assert!(learned(other.path(), &sender(), T0).is_none());
        assert!(holds_no_routes(other.path(), &sender(), T0));
    }

    #[test]
    fn an_equal_generation_lan_frame_replaces_lan_port_and_lan_ip() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let lan = link(OutboxCarrier::Lan);
        put(d, &frame(5), &lan, T0);
        let before = view(d, T0);
        let mut h = frame(5);
        h.lan_port = Some(7532);
        let other = HintLink {
            peer_ip: Some(ip("192.168.7.21")),
            ..lan
        };
        assert_eq!(put(d, &h, &other, T0 + MIN), LAN);
        let v = view(d, T0 + MIN);
        let l = v.lan.clone().unwrap();
        assert_eq!((l.port, l.ip), (Some(7532), Some(ip("192.168.7.21"))));
        assert_eq!(v.generation, 5);
        assert_eq!((&v.relays, &v.direct), (&before.relays, &before.direct));
        assert!(v.expires_at_ms >= before.expires_at_ms);
    }

    /// E2 night: one friend told win-c the same snapshot over its IPv4
    /// address (a LAN port and its same-LAN address) and over its IPv6 one
    /// (the port only: the receiver keeps no IPv4 address from an IPv6
    /// link), link after link. Each frame replaced the LAN part (about 240
    /// "learned" an hour, each a queue retry and a custody wake). Now one
    /// from another address that adds nothing keeps the held part, whichever
    /// came first; one that adds an address, or a newer generation,
    /// replaces it.
    #[test]
    fn alternating_addresses_of_one_snapshot_do_not_flip_the_lan_part() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let v4 = link(OutboxCarrier::Lan);
        let v6 = HintLink {
            peer_ip: Some(ip("fd00::20")),
            ..v4
        };
        let full = (Some(7531), Some(ip("192.168.7.20")), 1);
        let lan_of = |now| {
            let l = view(d, now).lan.unwrap();
            (l.port, l.ip, l.local_direct.len())
        };
        assert_eq!(put(d, &frame(5), &v4, T0), BOTH_C);
        let mut changed = 0;
        for i in 1..=20u64 {
            let at = if i % 2 == 0 { &v4 } else { &v6 };
            if matches!(put(d, &frame(5), at, T0 + i * MIN), Applied::Changed { .. }) {
                changed += 1;
            }
            assert_eq!(lan_of(T0 + i * MIN), full, "link {i}");
        }
        assert_eq!(changed, 0, "no flip");

        // The IPv6 link first: its part (the port) is held until a frame
        // adds the same-LAN address, then that one stays.
        let dir2 = tempfile::tempdir().unwrap();
        let d2 = dir2.path();
        put(d2, &frame(5), &v6, T0);
        let l = learned(d2, &sender(), T0).unwrap().lan.unwrap();
        assert_eq!((l.ip, l.local_direct.len()), (Some(ip("fd00::20")), 0));
        assert_eq!(put(d2, &frame(5), &v4, T0 + MIN), LAN, "adds an address");
        assert_eq!(put(d2, &frame(5), &v6, T0 + 2 * MIN), Applied::Unchanged);
        let l = learned(d2, &sender(), T0 + 2 * MIN).unwrap().lan.unwrap();
        assert_eq!((l.ip, l.local_direct.len()), (Some(ip("192.168.7.20")), 1));

        // A newer snapshot from the other address replaces it.
        assert!(matches!(
            put(d, &frame(6), &v6, T0 + 30 * MIN),
            Applied::Changed { lan: true, .. }
        ));
        assert_eq!(lan_of(T0 + 30 * MIN), (Some(7531), Some(ip("fd00::20")), 0));
    }

    /// E2 (s40): a newer snapshot over p2p leaves the LAN part at its older
    /// generation; a LAN dial then asks for route hints until a LAN frame
    /// brings it up to date.
    #[test]
    fn a_lan_part_behind_its_snapshot_is_said() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(!lan_part_behind(d, &sender(), T0), "no snapshot");
        put(d, &frame(5), &link(OutboxCarrier::P2p), T0);
        assert!(lan_part_behind(d, &sender(), T0), "no LAN part");
        put(d, &frame(5), &link(OutboxCarrier::Lan), T0 + 1);
        assert!(!lan_part_behind(d, &sender(), T0 + 1));
        put(d, &frame(6), &link(OutboxCarrier::P2p), T0 + 2);
        assert!(
            lan_part_behind(d, &sender(), T0 + 2),
            "a newer one over p2p"
        );
        put(d, &frame(6), &link(OutboxCarrier::Lan), T0 + 3);
        assert!(!lan_part_behind(d, &sender(), T0 + 3));
    }

    #[test]
    fn an_older_lan_frame_does_not_touch_the_lan_part() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let lan = link(OutboxCarrier::Lan);
        put(d, &frame(6), &lan, T0);
        let held = read(d);
        let mut old = frame(5);
        old.lan_port = Some(7999);
        let other = HintLink {
            peer_ip: Some(ip("192.168.7.21")),
            ..lan
        };
        assert_eq!(put(d, &old, &other, T0 + MIN), Applied::Stale);
        assert_eq!(read(d), held);

        // A newer global part from p2p, then a LAN frame at the LAN part's
        // generation: the global part ignores it, the LAN part takes it.
        let mut p = frame(7);
        p.relays = vec![relay(2, 0x62)];
        assert_eq!(put(d, &p, &link(OutboxCarrier::P2p), T0 + 2 * MIN), P2P);
        let mut l = frame(6);
        l.lan_port = Some(7532);
        assert_eq!(put(d, &l, &lan, T0 + 3 * MIN), LAN);
        let v = view(d, T0 + 3 * MIN);
        assert_eq!(v.generation, 7);
        assert_eq!(texts(&v.relays), [relay(2, 0x62)]);
        assert_eq!(v.lan.unwrap().port, Some(7532));
    }

    #[test]
    fn an_expired_lan_part_is_not_used_and_any_lan_frame_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let lan = link(OutboxCarrier::Lan);
        let mut short = frame(5);
        short.ttl_s = 60;
        put(d, &short, &lan, T0);
        assert_eq!(
            put(d, &frame(6), &link(OutboxCarrier::P2p), T0 + 30_000),
            P2P
        );
        let v = view(d, T0 + 60_000);
        assert_eq!(v.lan, None, "the p2p frame did not refresh it");
        assert_eq!(v.generation, 6);
        let mut older = frame(4);
        older.lan_port = Some(7600);
        assert_eq!(put(d, &older, &lan, T0 + 61_000), LAN);
        let v = view(d, T0 + 61_000);
        assert_eq!((v.generation, v.lan.unwrap().port), (6, Some(7600)));
    }

    /// E2 r9 #17: right after a start the same snapshot came over two links,
    /// one told before the sender's listeners were up (fewer direct
    /// addresses), one after. Whatever their order, the richer set stays;
    /// other addresses (a listener's new port, C20) or a newer snapshot
    /// replace it.
    #[test]
    fn the_same_snapshot_with_fewer_direct_addresses_keeps_the_richer_set() {
        let p2p = link(OutboxCarrier::P2p);
        let with = |generation: u64, direct: &[&str]| RouteHints {
            direct: direct.iter().map(|d| (*d).to_string()).collect(),
            ..frame(generation)
        };
        let (a, b, c) = (
            "/ip4/11.0.3.5/tcp/7423",
            "/ip4/11.0.3.6/tcp/7423",
            "/ip4/11.0.3.6/tcp/7499",
        );
        let full = |d: &Path, now: u64| texts(&view(d, now).direct);
        let named = |addrs: &[&str]| -> Vec<String> {
            addrs
                .iter()
                .map(|x| format!("{x}/p2p/{}", pid(0x51)))
                .collect()
        };
        for first_rich in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path();
            let (first, second) = if first_rich {
                (with(5, &[a, b]), with(5, &[]))
            } else {
                (with(5, &[]), with(5, &[a, b]))
            };
            put(d, &first, &p2p, T0);
            put(d, &second, &p2p, T0 + 1);
            assert_eq!(full(d, T0 + 1), named(&[a, b]), "first rich: {first_rich}");
            // Fewer of the same: the held set stays.
            put(d, &with(5, &[b]), &p2p, T0 + 2);
            assert_eq!(full(d, T0 + 2), named(&[a, b]));
            // Another address (a new port): replaced, as before.
            put(d, &with(5, &[a, c]), &p2p, T0 + 3);
            assert_eq!(full(d, T0 + 3), named(&[a, c]));
            // A newer snapshot replaces it whole.
            assert_eq!(put(d, &with(6, &[a]), &p2p, T0 + 4), P2P);
            assert_eq!(full(d, T0 + 4), named(&[a]));
        }
        // Over the LAN (the field case): fewer of the same same-LAN
        // addresses from one address stay; another port replaces them.
        let lan = link(OutboxCarrier::Lan);
        let local = |d: &Path, now: u64| {
            view(d, now)
                .lan
                .map(|l| texts(&l.local_direct))
                .unwrap_or_default()
        };
        let (l1, l2, l3) = (
            "/ip4/192.168.7.20/tcp/7423",
            "/ip4/192.168.7.20/udp/7423/quic-v1",
            "/ip4/192.168.7.20/tcp/7499",
        );
        for first_rich in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path();
            let (first, second) = if first_rich {
                (with(5, &[l1, l2]), with(5, &[]))
            } else {
                (with(5, &[]), with(5, &[l1, l2]))
            };
            put(d, &first, &lan, T0);
            put(d, &second, &lan, T0 + 1);
            assert_eq!(local(d, T0 + 1).len(), 2, "first rich: {first_rich}");
            put(d, &with(5, &[l3]), &lan, T0 + 2);
            assert_eq!(local(d, T0 + 2).len(), 1, "a new port replaces them");
        }
    }

    #[test]
    fn an_equal_generation_checked_under_newer_rules_replaces_the_global_part() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let unverified = HintLink::fixture(OutboxCarrier::Lan, false);
        assert_eq!(put(d, &frame(5), &unverified, T0), LAN);
        let v = view(d, T0);
        assert_eq!(v.peer_id, None, "an unverified contact: LAN_PORT only");
        assert_eq!(v.lan.unwrap().port, Some(7531));
        // Verified since: the same generation now gives the rest.
        assert_eq!(
            put(d, &frame(5), &link(OutboxCarrier::Lan), T0 + MIN),
            BOTH_C
        );
        let v = view(d, T0 + MIN);
        assert_eq!(v.peer_id.as_deref(), Some(pid(0x51).as_str()));
        assert_eq!(texts(&v.relays), [relay(1, 0x61)]);
    }

    /// A snapshot stored before the RELAY address rule (spec §5.2) is held
    /// to it when read: a relay at a private or documentation address is
    /// never planned (route hints validate it away before storing now).
    #[test]
    fn a_stored_relay_at_a_local_address_is_not_used() {
        if crate::p2p_local_candidates_enabled() {
            return; // the debug lab keeps them
        }
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let at = |host: &str, seed: u8| parse_via(&format!("{host}/p2p/{}", pid(seed))).unwrap();
        let v = ValidHints {
            generation: 3,
            ttl_s: RRH1_DEFAULT_TTL_S,
            peer_id: Some(pid(0x51)),
            relays: vec![
                at("/ip4/192.168.1.1/tcp/80", 0x61),
                at("/ip4/198.51.100.1/tcp/7423", 0x62),
                parse_via(&relay(1, 0x63)).unwrap(),
            ],
            ..Default::default()
        };
        record(d, &sender(), &v, &link(OutboxCarrier::P2p), None, T0).unwrap();
        let got = view(d, T0);
        assert_eq!(texts(&got.relays), [relay(1, 0x63)]);
        assert_eq!(got.p2p().unwrap().relays, got.relays);
    }

    /// Each relay contacts' route hints name, with when the newest snapshot
    /// naming it came: a newer one moves it on, an expired one names none.
    #[test]
    fn relays_named_at_takes_the_newest_snapshot_naming_each_relay() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(relays_named_at(d, T0).is_empty());
        let naming = |generation: u64, seeds: &[u8]| ValidHints {
            generation,
            ttl_s: RRH1_DEFAULT_TTL_S,
            peer_id: Some(pid(0x51)),
            relays: seeds
                .iter()
                .map(|s| parse_via(&relay(1, *s)).unwrap())
                .collect(),
            ..Default::default()
        };
        let p2p = link(OutboxCarrier::P2p);
        record(d, &sender(), &naming(3, &[0x63, 0x64]), &p2p, None, T0).unwrap();
        record(d, &peer(1), &naming(1, &[0x64]), &p2p, None, T0 + 5).unwrap();
        let mut got = relays_named_at(d, T0 + 10);
        got.sort();
        let mut want = vec![(pid(0x63), T0), (pid(0x64), T0 + 5)];
        want.sort();
        assert_eq!(got, want);
        // The sender names one of them again later.
        record(d, &sender(), &naming(4, &[0x63]), &p2p, None, T0 + 20).unwrap();
        let mut got = relays_named_at(d, T0 + 30);
        got.sort();
        let mut want = vec![(pid(0x63), T0 + 20), (pid(0x64), T0 + 5)];
        want.sort();
        assert_eq!(got, want);
        // Expired snapshots name nothing.
        let later = T0 + 20 + u64::from(RRH1_DEFAULT_TTL_S) * 1000 + 1;
        assert!(relays_named_at(d, later).is_empty());
    }

    #[test]
    fn expired_entries_stay_as_tombstones_for_30_days() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let s = sender();
        let mut short = frame(5);
        short.ttl_s = 60;
        put(d, &short, &link(OutboxCarrier::Lan), T0);
        let expired = T0 + 60_000;
        assert_eq!(last_heard(d, &s, expired - 1), Some((T0, false)));
        assert!(learned(d, &s, expired).is_none());
        assert_eq!(last_heard(d, &s, expired), Some((T0, true)));
        assert!(live_contacts(d, expired).is_empty());
        assert!(learned_peer_ids(d, expired).is_empty());

        // The next write stores it as a tombstone: no route is left but its
        // LAN port (Phase 3 P3.C1, kept LAN_KEEP_MS).
        empty(d, &peer(1), 600, expired);
        let raw = String::from_utf8(read(d)).unwrap();
        for gone in [
            pid(0x51),
            "local_direct".into(),
            "relays".into(),
            "77777777".into(),
        ] {
            assert!(!raw.contains(&gone), "{gone}: {raw}");
        }
        assert!(raw.contains("\"lan_port\": 7531"), "{raw}");
        assert_eq!(last_heard(d, &s, expired), Some((T0, true)));

        // Gone 30 days after its expiry ...
        assert_eq!(
            last_heard(d, &s, expired + TOMBSTONE_MS - 1),
            Some((T0, true))
        );
        assert_eq!(last_heard(d, &s, expired + TOMBSTONE_MS), None);

        // ... or once MAX_ENTRIES newer contacts were heard.
        let other = tempfile::tempdir().unwrap();
        let o = other.path();
        put(o, &short, &link(OutboxCarrier::Lan), T0);
        for i in 0..MAX_ENTRIES - 1 {
            empty(o, &peer(i), 600, expired + i as u64);
        }
        let now = expired + MAX_ENTRIES as u64;
        assert_eq!(last_heard(o, &s, now), Some((T0, true)));
        empty(o, &peer(MAX_ENTRIES), 600, now);
        assert_eq!(last_heard(o, &s, now), None);
    }

    /// Phase 3 P3.C1 (people who meet weekly): past its expiry an entry's
    /// LAN part keeps its LAN IP and port, with the network it was learned
    /// on, until LAN_KEEP_MS after it was received, for the LAN planner only
    /// ([`learned_with_lan`]). The rest goes as before (the global part, the
    /// same-LAN direct addresses), the file gains no field, and the
    /// tombstone outlives the kept port.
    #[test]
    fn an_expired_hint_keeps_its_lan_port_for_30_days_and_drops_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let s = sender();
        let lan = link(OutboxCarrier::Lan);
        let tag = Some("net-a".to_string());
        record(d, &s, &validate(&frame(5), &lan), &lan, tag.clone(), T0).unwrap();
        let expired = T0 + TTL_MS;
        let with_lan = |now: u64| learned_with_lan(d, &s, now);

        // Live: the view's own LAN part, its same-LAN direct address too.
        let (live, part) = with_lan(expired - 1);
        assert_eq!(live.unwrap().lan, part);
        assert_eq!(part.unwrap().local_direct.len(), 1);

        // Expired: no snapshot, its LAN IP and port kept 30 days.
        assert!(learned(d, &s, expired).is_none());
        let (view, part) = with_lan(expired);
        assert_eq!(view, None);
        let part = part.expect("the kept LAN part");
        assert_eq!(
            part,
            LearnedLan {
                port: Some(7531),
                ip: Some(ip("192.168.7.20")),
                zone: None,
                local_direct: Vec::new(),
                local_tag: tag,
                told: false,
                received_at_ms: T0,
            }
        );
        assert_eq!(with_lan(T0 + LAN_KEEP_MS - 1).1, Some(part.clone()));
        assert_eq!(with_lan(T0 + LAN_KEEP_MS), (None, None), "30 days on");

        // On disk once written (the next frame from anyone): the tombstone
        // and the LAN part's own fields, nothing new; no PeerId, relay,
        // direct address or custodian.
        empty(d, &peer(1), 600, expired);
        let rows: serde_json::Value = serde_json::from_slice(&read(d)).unwrap();
        let row = rows
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["pub_hex"].as_str() == Some(hex::encode(s).as_str()))
            .unwrap();
        let keys = |v: &serde_json::Value| {
            let mut keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            keys.sort_unstable();
            keys
        };
        assert_eq!(
            keys(row),
            [
                "expires_at_ms",
                "generation",
                "lan",
                "pub_hex",
                "received_at_ms",
                "via"
            ]
        );
        assert_eq!(
            keys(&row["lan"]),
            [
                "expires_at_ms",
                "generation",
                "lan_ip",
                "lan_port",
                "local_tag",
                "received_at_ms"
            ]
        );
        assert_eq!(with_lan(expired).1, Some(part));

        // The first write past LAN_KEEP_MS drops it; the tombstone stays
        // (TOMBSTONE_MS past its expiry).
        empty(d, &peer(2), 600, T0 + LAN_KEEP_MS);
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(
            !raw.contains("lan_port") && !raw.contains("192.168.7.20"),
            "{raw}"
        );
        assert_eq!(last_heard(d, &s, T0 + LAN_KEEP_MS), Some((T0, true)));
    }

    /// P3.C1: a kept LAN part makes nobody an announce target (the announcer
    /// is unchanged); the p2p gate's lists and the relays named do not see
    /// its expired snapshot either.
    #[test]
    fn live_contacts_ignores_kept_lan_parts() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let s = sender();
        put(d, &frame(5), &link(OutboxCarrier::Lan), T0);
        empty(d, &peer(1), RRH1_MAX_TTL_S, T0 + 1);
        let expired = T0 + TTL_MS;
        assert_eq!(live_contacts(d, expired - 1), [peer(1), s]);
        assert_eq!(learned_peer_ids(d, expired - 1).len(), 1);
        assert_eq!(relays_named_at(d, expired - 1).len(), 1);

        let unseen = |d: &Path| {
            assert!(learned_with_lan(d, &s, expired).1.is_some(), "kept");
            assert_eq!(live_contacts(d, expired), [peer(1)]);
            assert!(learned_peer_ids(d, expired).is_empty());
            assert!(learned_p2p(d, expired).is_empty());
            assert!(relays_named_at(d, expired).is_empty());
        };
        unseen(d);
        // Written as a tombstone with its LAN port: the same.
        let other = tempfile::tempdir().unwrap();
        let o = other.path();
        put(o, &frame(5), &link(OutboxCarrier::Lan), T0);
        empty(o, &peer(1), RRH1_MAX_TTL_S, T0 + 1);
        empty(o, &peer(1), RRH1_MAX_TTL_S, expired);
        assert!(String::from_utf8(read(o)).unwrap().contains("\"lan_port\""));
        unseen(o);
    }

    /// P3.C1: frames over other links never touch a kept LAN part (the LAN
    /// part follows LAN frames only), whether they find the snapshot expired
    /// or live, and it stays out of the live view; the next LAN frame
    /// replaces it whatever its generation.
    #[test]
    fn a_kept_lan_port_survives_other_links_and_a_lan_frame_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let s = sender();
        let mut short = frame(5);
        short.ttl_s = 60;
        put(d, &short, &link(OutboxCarrier::Lan), T0);
        let kept = |now: u64| {
            let l = learned_with_lan(d, &s, now).1.expect("a kept LAN part");
            (l.port, l.ip, l.local_direct.len(), l.received_at_ms)
        };
        let want = (Some(7531), Some(ip("192.168.7.20")), 0, T0);

        // Expired: a p2p frame replaces the snapshot, not the LAN port.
        let day = T0 + DAY;
        assert_eq!(put(d, &frame(6), &link(OutboxCarrier::P2p), day), P2P_C);
        assert_eq!(view(d, day).lan, None, "not in the live view");
        assert_eq!(kept(day), want);
        // Live, its LAN part expired: an Internet frame keeps it too.
        let mut newer = frame(7);
        newer.relays = vec![relay(2, 0x62)];
        let inet = link(OutboxCarrier::Internet);
        assert_eq!(put(d, &newer, &inet, day + MIN), P2P);
        assert_eq!(kept(day + MIN), want);
        assert_eq!(view(d, day + MIN).lan, None);

        // An older LAN frame replaces it: a live LAN part again.
        let mut older = frame(4);
        older.lan_port = Some(7600);
        assert_eq!(
            put(d, &older, &link(OutboxCarrier::Lan), day + 2 * MIN),
            LAN
        );
        let v = view(d, day + 2 * MIN);
        assert_eq!((v.generation, v.lan.unwrap().port), (7, Some(7600)));
    }

    /// Spec §11.3: offers belong to the global snapshot. A newer frame
    /// replaces them (what it lacks is withdrawn, a frame without
    /// RELAY_OFFER withdraws them all), an older one is ignored. They are
    /// not routes to the sender: a change of offers alone is a rewrite, not
    /// a replan.
    #[test]
    fn offers_follow_snapshot_semantics_and_empty_withdraws() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let p2p = link(OutboxCarrier::P2p);
        let (r1, r2, r3) = (relay_key(0x71), relay_key(0x72), relay_key(0x73));
        let both = [offer_of(r1, 1), offer_of(r2, 2)];
        assert_eq!(put(d, &with_offers(5, &both), &p2p, T0), P2P_C);
        assert_eq!(
            offers(d, T0),
            [
                (hex::encode(sender()), pid(0x51), stored(r1, 1), T0 + TTL_MS),
                (hex::encode(sender()), pid(0x51), stored(r2, 2), T0 + TTL_MS),
            ]
        );
        // The same snapshot: nothing is written.
        let held = read(d);
        assert_eq!(
            put(d, &with_offers(5, &both), &p2p, T0 + MIN),
            Applied::Unchanged
        );
        assert_eq!(read(d), held);
        // An older one is ignored, whatever it offers.
        assert_eq!(
            put(d, &with_offers(4, &[offer_of(r3, 3)]), &p2p, T0 + 2 * MIN),
            Applied::Stale
        );
        assert_eq!(offered(d, T0 + 2 * MIN), [stored(r1, 1), stored(r2, 2)]);
        // A newer one with one offer (at a new address): the other is
        // withdrawn.
        assert_eq!(
            put(d, &with_offers(6, &[offer_of(r2, 9)]), &p2p, T0 + 3 * MIN),
            Applied::Refreshed
        );
        assert_eq!(offered(d, T0 + 3 * MIN), [stored(r2, 9)]);
        // A newer one without RELAY_OFFER withdraws them all.
        assert_eq!(put(d, &frame(7), &p2p, T0 + 4 * MIN), Applied::Refreshed);
        assert!(offered(d, T0 + 4 * MIN).is_empty());
        assert!(!String::from_utf8(read(d)).unwrap().contains("offers"));
        // Any link carries them (the global part), LAN too.
        let lan = link(OutboxCarrier::Lan);
        put(d, &with_offers(8, &[offer_of(r3, 3)]), &lan, T0 + 5 * MIN);
        assert_eq!(offered(d, T0 + 5 * MIN), [stored(r3, 3)]);
        // The same generation checked under newer rules (the relay became
        // this node's own) replaces them too.
        let own = HintLink {
            local_relay: Some(r3),
            ..lan
        };
        let v = validate(&with_offers(8, &[offer_of(r3, 3)]), &own);
        assert!(v.offers.is_empty());
        assert_eq!(
            record(d, &own.sender, &v, &own, None, T0 + 6 * MIN),
            Ok(Applied::Refreshed)
        );
        assert!(offered(d, T0 + 6 * MIN).is_empty());
    }

    /// Spec §11.3: never the sender's own libp2p key (a relay under its
    /// profile PeerId), known from its P2P_ID, the book's PeerId or the p2p
    /// link's; never this node's own key or its friend relay's.
    #[test]
    fn a_profile_key_own_key_or_own_relay_key_offer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let sender_p2p = libp2p_ed25519_public(&Identity::from_seed(&[0x51; 32]));
        let mine = relay_key(0x7e);
        let good = offer_of(relay_key(0x71), 1);
        let p2p = HintLink {
            local_relay: Some(mine),
            ..link(OutboxCarrier::P2p)
        };
        let baseline = validate(&frame(5), &p2p).dropped;
        for (what, refused) in [
            ("the sender's key", sender_p2p),
            ("our key", p2p.local_p2p),
            ("our friend relay's key", mine),
        ] {
            let v = validate(&with_offers(5, &[offer_of(refused, 2), good.clone()]), &p2p);
            assert_eq!(v.offers, std::slice::from_ref(&good), "{what}");
            assert_eq!(v.dropped, baseline + 1, "{what}: counted");
        }
        // Without P2P_ID the book's PeerId, or the p2p link's, is enough.
        let bare = RouteHints {
            p2p_id: None,
            ..with_offers(5, &[offer_of(sender_p2p, 2), good.clone()])
        };
        let inet = link(OutboxCarrier::Internet);
        assert_eq!(
            validate(&bare, &inet).offers,
            std::slice::from_ref(&good),
            "the book"
        );
        let unbooked_p2p = HintLink {
            book_peer_id: None,
            ..link(OutboxCarrier::P2p)
        };
        assert_eq!(
            validate(&bare, &unbooked_p2p).offers,
            std::slice::from_ref(&good),
            "the p2p link"
        );
        // Knowing none of them, that key is just another relay's.
        let unbooked = HintLink {
            book_peer_id: None,
            ..inet
        };
        assert_eq!(validate(&bare, &unbooked).offers.len(), 2);

        // What is stored: the other offer only.
        let h = with_offers(5, &[offer_of(mine, 3), offer_of(sender_p2p, 2), good]);
        assert_eq!(
            record(d, &p2p.sender, &validate(&h, &p2p), &p2p, None, T0),
            Ok(P2P_C)
        );
        assert_eq!(offered(d, T0), [stored(relay_key(0x71), 1)]);
    }

    /// Spec §11.3: at most two offers per sender and 32 in all, the newest
    /// senders' (on disk and when read), each checked again on read.
    #[test]
    fn offers_are_bounded_per_operator_and_total() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // One frame never gives more than two (validate keeps the first).
        let three: Vec<RelayOfferRecord> =
            (1..=3).map(|n| offer_of(relay_key(0x70 + n), n)).collect();
        put(d, &with_offers(5, &three), &link(OutboxCarrier::P2p), T0);
        assert_eq!(
            offered(d, T0),
            [stored(relay_key(0x71), 1), stored(relay_key(0x72), 2)]
        );
        // Twenty newer operators with two each: 42 offered, 32 kept.
        for i in 0..20u8 {
            let v = ValidHints {
                generation: 1,
                ttl_s: 600,
                offers: vec![
                    offer_of(relay_key(0x80 + 2 * i), 1),
                    offer_of(relay_key(0x81 + 2 * i), 2),
                ],
                ..Default::default()
            };
            let at = T0 + 1 + u64::from(i);
            record(
                d,
                &peer(usize::from(i)),
                &v,
                &link(OutboxCarrier::P2p),
                None,
                at,
            )
            .unwrap();
        }
        let now = T0 + 100;
        let all = offers(d, now);
        assert_eq!(all.len(), MAX_OFFERS);
        assert_eq!(offers_on_disk(d), MAX_OFFERS);
        assert_eq!(all[0].0, hex::encode(peer(19)), "newest first");
        assert_eq!(all[MAX_OFFERS - 1].0, hex::encode(peer(4)));
        assert!(offered(d, now).is_empty(), "the oldest sender's went");
        assert!(learned(d, &sender(), now).is_some(), "its routes did not");

        // A file edited by hand: still two per operator, one per relay, each
        // checked (a canonical PeerId, canonical addresses).
        let (r1, r2) = (stored(relay_key(0x71), 1), stored(relay_key(0x72), 2));
        let bad_peer = StoredOffer {
            relay_peer_id: "garbage".into(),
            ..r1.clone()
        };
        let bad_addr = StoredOffer {
            addrs: vec!["/ip4/11.0.4.4/tcp/07427".into()],
            ..stored(relay_key(0x74), 4)
        };
        let edited = json!([{
            "pub_hex": hex::encode(peer(1)),
            "generation": 1,
            "received_at_ms": T0,
            "expires_at_ms": T0 + 600_000,
            "via": "p2p",
            "offers": [r1, r1, bad_peer, bad_addr, r2, stored(relay_key(0x73), 3)],
        }]);
        std::fs::write(
            d.join(LEARNED_ROUTES_FILE),
            serde_json::to_vec(&edited).unwrap(),
        )
        .unwrap();
        let listed: Vec<StoredOffer> = offers(d, T0).into_iter().map(|(.., o, _)| o).collect();
        assert_eq!(listed, [r1, r2]);
    }

    /// Step 20's rule (a reservation on an offered relay outlives the
    /// offer): an expired snapshot's offers stay listed, with their past
    /// expiry, while it is a tombstone, and nothing else of it does.
    #[test]
    fn offers_survive_in_a_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let r1 = relay_key(0x71);
        let mut short = with_offers(5, &[offer_of(r1, 1)]);
        short.ttl_s = 60;
        put(d, &short, &link(OutboxCarrier::P2p), T0);
        let expired = T0 + 60_000;
        assert_eq!(
            offers(d, expired - 1),
            [(hex::encode(sender()), pid(0x51), stored(r1, 1), expired)]
        );
        assert!(learned(d, &sender(), expired).is_none());
        // The tombstone names no PeerId any more, but keeps the offer.
        assert_eq!(
            offers(d, expired),
            [(hex::encode(sender()), String::new(), stored(r1, 1), expired)]
        );
        // So does the file once it is written as one.
        empty(d, &peer(1), 600, expired);
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(raw.contains(&stored(r1, 1).relay_peer_id), "{raw}");
        for gone in [pid(0x51), "relays".into(), "lan_port".into()] {
            assert!(!raw.contains(&gone), "{gone}: {raw}");
        }
        assert_eq!(offered(d, expired + TOMBSTONE_MS - 1), [stored(r1, 1)]);
        assert!(offered(d, expired + TOMBSTONE_MS).is_empty());
        // The sender's next snapshot replaces it whole.
        assert_eq!(
            put(d, &frame(6), &link(OutboxCarrier::P2p), expired + 1),
            P2P_C
        );
        assert!(offered(d, expired + 1).is_empty());
    }

    #[test]
    fn forget_removes_offers() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(
            d,
            &with_offers(5, &[offer_of(relay_key(0x71), 1)]),
            &link(OutboxCarrier::P2p),
            T0,
        );
        let other = ValidHints {
            generation: 1,
            ttl_s: 600,
            offers: vec![offer_of(relay_key(0x72), 2)],
            ..Default::default()
        };
        record(d, &peer(1), &other, &link(OutboxCarrier::P2p), None, T0).unwrap();
        forget(d, &sender()).unwrap();
        assert!(offered(d, T0).is_empty());
        let left = offers(d, T0);
        assert_eq!(left.len(), 1);
        assert_eq!(
            (left[0].0.as_str(), &left[0].2),
            (hex::encode(peer(1)).as_str(), &stored(relay_key(0x72), 2))
        );
        // A tombstone's offers go with it.
        let expired = T0 + 600_000;
        assert_eq!(offers(d, expired).len(), 1);
        forget(d, &peer(1)).unwrap();
        assert!(offers(d, expired).is_empty());
    }

    const OFFER_BOTH: u8 = OFFER_WAN | OFFER_REACHABLE;
    /// [`BOTH`], [`LAN`] and [`P2P`] when the custodians changed too (the
    /// fixture frame names one: a first snapshot, or one after a tombstone).
    const BOTH_C: Applied = Applied::Changed {
        lan: true,
        p2p: true,
        custody: true,
    };
    const P2P_C: Applied = Applied::Changed {
        lan: false,
        p2p: true,
        custody: true,
    };
    const CUSTODY: Applied = Applied::Changed {
        lan: false,
        p2p: false,
        custody: true,
    };

    /// The fixture frame with a custody offer and two custodian tags.
    fn with_custody(generation: u64, offer: u8) -> RouteHints {
        RouteHints {
            custody_offer: Some(offer),
            custodian_tags: vec![([0x31; 32], 0), ([0x32; 32], 0)],
            ..frame(generation)
        }
    }

    fn custody_of(dir: &Path, now: u64) -> Option<LearnedCustody> {
        learned_custody(dir, &sender(), now)
    }

    #[test]
    fn custody_fields_follow_snapshot_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let p2p = link(OutboxCarrier::P2p);
        assert_eq!(
            put(d, &with_custody(5, OFFER_BOTH), &p2p, T0),
            Applied::Changed {
                lan: false,
                p2p: true,
                custody: true,
            }
        );
        let c = custody_of(d, T0).unwrap();
        assert_eq!(c.tags, [[0x31; 32], [0x32; 32]]);
        assert_eq!(c.plain, [[0x77; 32]], "0x05 is still read, as plain keys");
        assert_eq!((c.offer, c.heard_ms), (Some(OFFER_BOTH), T0));
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(raw.contains(&hex::encode([0x31; 32])), "{raw}");
        assert!(raw.contains("custody_offer"), "{raw}");
        // A newer snapshot without them withdraws them (the rest is equal).
        assert_eq!(put(d, &frame(6), &p2p, T0 + MIN), CUSTODY);
        let c = custody_of(d, T0 + MIN).unwrap();
        assert!(c.tags.is_empty() && c.offer.is_none());
        assert_eq!((c.plain.len(), c.heard_ms), (1, T0 + MIN));
        let raw = String::from_utf8(read(d)).unwrap();
        for gone in ["custody_offer", "custodian_tags", "custodian_tag_flags"] {
            assert!(!raw.contains(gone), "{gone}: {raw}");
        }
        // An older one changes nothing.
        assert_eq!(
            put(d, &with_custody(4, OFFER_BOTH), &p2p, T0 + 2 * MIN),
            Applied::Stale
        );
        assert!(custody_of(d, T0 + 2 * MIN).unwrap().offer.is_none());
        // An unverified sender's custody entries never reach the file.
        let unverified = HintLink::fixture(OutboxCarrier::P2p, false);
        put(d, &with_custody(7, OFFER_BOTH), &unverified, T0 + 3 * MIN);
        let c = custody_of(d, T0 + 3 * MIN).unwrap();
        assert!(c.tags.is_empty() && c.offer.is_none());
    }

    #[test]
    fn equal_generation_keeps_custody_fields() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let p2p = link(OutboxCarrier::P2p);
        put(d, &with_custody(5, OFFER_REACHABLE), &p2p, T0);
        let before = read(d);
        // The same frame again: nothing to write.
        assert_eq!(
            put(d, &with_custody(5, OFFER_REACHABLE), &p2p, T0 + MIN),
            Applied::Unchanged
        );
        assert_eq!(read(d), before);
        // Later, the same frame extends the expiry and keeps every field.
        let later = T0 + 3 * 60 * MIN;
        assert_eq!(
            put(d, &with_custody(5, OFFER_REACHABLE), &p2p, later),
            Applied::Refreshed
        );
        let c = custody_of(d, later).unwrap();
        assert_eq!(c.tags.len(), 2);
        assert_eq!(c.offer, Some(OFFER_REACHABLE));
        assert_eq!(custody_offers(d, later).len(), 1);
    }

    #[test]
    fn tombstones_carry_no_custody() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let short = RouteHints {
            ttl_s: 600,
            ..with_custody(5, OFFER_BOTH)
        };
        put(d, &short, &link(OutboxCarrier::P2p), T0);
        assert!(custody_of(d, T0).is_some());
        let expired = T0 + 600_000;
        assert_eq!(custody_of(d, expired), None);
        assert!(learned_custody_all(d, expired).is_empty());
        assert!(custody_offers(d, expired).is_empty());
        // Written as its readers see it: a tombstone without them.
        assert_eq!(prune(d, expired, None), Ok(1));
        let raw = String::from_utf8(read(d)).unwrap();
        for gone in [
            "custody_offer".to_owned(),
            "custodian_tags".to_owned(),
            hex::encode([0x31; 32]),
        ] {
            assert!(!raw.contains(&gone), "{gone}: {raw}");
        }
        assert!(last_heard(d, &sender(), expired).is_some(), "the tombstone");
    }

    #[test]
    fn forget_drops_custody() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        put(
            d,
            &with_custody(5, OFFER_BOTH),
            &link(OutboxCarrier::P2p),
            T0,
        );
        let other = ValidHints {
            generation: 1,
            ttl_s: 600,
            custody_offer: Some(0),
            ..Default::default()
        };
        record(d, &peer(1), &other, &link(OutboxCarrier::P2p), None, T0).unwrap();
        forget(d, &sender()).unwrap();
        assert_eq!(custody_of(d, T0), None);
        assert_eq!(custody_offers(d, T0), [(peer(1), 0, T0)]);
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(!raw.contains(&hex::encode([0x31; 32])), "{raw}");
        forget(d, &peer(1)).unwrap();
        assert!(custody_offers(d, T0).is_empty());
    }

    #[test]
    fn applied_changed_reports_custody_diff() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let p2p = link(OutboxCarrier::P2p);
        put(d, &with_custody(5, OFFER_BOTH), &p2p, T0);
        // The offer's flags alone.
        assert_eq!(
            put(d, &with_custody(6, OFFER_REACHABLE), &p2p, T0 + MIN),
            CUSTODY
        );
        // A tag's flags alone (a Phase 5 bit, kept once validate keeps it).
        let mut flagged = with_custody(7, OFFER_REACHABLE);
        flagged.custodian_tags[1] = ([0x32; 32], 0x01);
        let mut v = validate(&flagged, &p2p);
        v.custodian_tag_flags = vec![0, 0x01];
        assert_eq!(
            record(d, &p2p.sender, &v, &p2p, None, T0 + 2 * MIN),
            Ok(CUSTODY)
        );
        // ... and read back with its tag (Phase 5 P5.20).
        assert_eq!(custody_of(d, T0 + 2 * MIN).unwrap().tag_flags, [0, 0x01]);
        // One tag fewer.
        let mut fewer = with_custody(8, OFFER_REACHABLE);
        fewer.custodian_tags.pop();
        assert_eq!(put(d, &fewer, &p2p, T0 + 3 * MIN), CUSTODY);
        assert_eq!(custody_of(d, T0 + 3 * MIN).unwrap().tags, [[0x31; 32]]);
        // Routes alone: custody is false.
        let mut moved = with_custody(9, OFFER_REACHABLE);
        moved.custodian_tags.pop();
        moved.relays = vec![relay(2, 0x62)];
        assert_eq!(put(d, &moved, &p2p, T0 + 4 * MIN), P2P);
        // An offer that comes or goes.
        let mut gone = moved.clone();
        gone.generation = 10;
        gone.custody_offer = None;
        assert_eq!(put(d, &gone, &p2p, T0 + 5 * MIN), CUSTODY);
        assert_eq!(custody_of(d, T0 + 5 * MIN).unwrap().offer, None);
        assert!(custody_offers(d, T0 + 5 * MIN).is_empty());
    }

    #[test]
    fn custody_offers_newest_first_bounded_32() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let p2p = link(OutboxCarrier::P2p);
        let offer = |flags: Option<u8>| ValidHints {
            generation: 1,
            ttl_s: RRH1_DEFAULT_TTL_S,
            custody_offer: flags,
            ..Default::default()
        };
        for i in 0..40 {
            record(d, &peer(i), &offer(Some(0x03)), &p2p, None, T0 + i as u64).unwrap();
        }
        // No offer, and an expired one: not listed.
        record(d, &peer(100), &offer(None), &p2p, None, T0 + 100).unwrap();
        let short = ValidHints {
            ttl_s: 60,
            ..offer(Some(0x01))
        };
        record(d, &peer(101), &short, &p2p, None, T0 - 61_000).unwrap();
        let listed = custody_offers(d, T0 + 200);
        assert_eq!(listed.len(), MAX_CUSTODY_OFFERS);
        let want: Vec<([u8; 32], u8, u64)> = (8..40)
            .rev()
            .map(|i| (peer(i), 0x03, T0 + i as u64))
            .collect();
        assert_eq!(listed, want, "newest first");
        let all = learned_custody_all(d, T0 + 200);
        assert_eq!(all.len(), 41, "every live snapshot, offer or not");
        assert_eq!(all[&peer(100)].offer, None);
    }

    #[test]
    fn an_old_file_without_custody_fields_decodes() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let s = hex::encode(sender());
        let old = json!([{
            "pub_hex": s,
            "generation": 5,
            "received_at_ms": T0,
            "expires_at_ms": T0 + TTL_MS,
            "via": "p2p",
            "custodians": [hex::encode([0x77; 32])],
        }]);
        std::fs::write(d.join(LEARNED_ROUTES_FILE), old.to_string()).unwrap();
        let c = custody_of(d, T0).unwrap();
        assert_eq!(
            c,
            LearnedCustody {
                tags: Vec::new(),
                tag_flags: Vec::new(),
                plain: vec![[0x77; 32]],
                offer: None,
                heard_ms: T0,
            }
        );
        assert!(custody_offers(d, T0).is_empty());
        // Unknown offer bits and a bad tag in the file are dropped on read.
        let odd = json!([{
            "pub_hex": s,
            "generation": 5,
            "received_at_ms": T0,
            "expires_at_ms": T0 + TTL_MS,
            "via": "p2p",
            "custodian_tags": ["zz", hex::encode([0; 32]), hex::encode([0x31; 32])],
            "custody_offer": 0xff,
        }]);
        std::fs::write(d.join(LEARNED_ROUTES_FILE), odd.to_string()).unwrap();
        let c = custody_of(d, T0).unwrap();
        assert_eq!((c.tags, c.offer), (vec![[0x31; 32]], Some(0x03)));
        assert_eq!(c.tag_flags, [0], "no flags stored: 0");
        // Each tag keeps its own flags byte past a bad entry, and a repeated
        // tag's flags are OR-ed into the first (Phase 5 P5.20).
        let flagged = json!([{
            "pub_hex": s,
            "generation": 5,
            "received_at_ms": T0,
            "expires_at_ms": T0 + TTL_MS,
            "via": "p2p",
            "custodian_tags": [
                "zz",
                hex::encode([0x31; 32]),
                hex::encode([0x32; 32]),
                hex::encode([0x31; 32]),
            ],
            "custodian_tag_flags": [0x01, 0x00, 0x01, 0x02],
        }]);
        std::fs::write(d.join(LEARNED_ROUTES_FILE), flagged.to_string()).unwrap();
        let c = custody_of(d, T0).unwrap();
        assert_eq!(c.tags, [[0x31; 32], [0x32; 32]]);
        assert_eq!(c.tag_flags, [0x02, 0x01]);
    }

    /// Phase 4 (§13.1): a NAT_CLASS is part of the global snapshot: stored
    /// with it, listed with its PeerId and expiry, replaced (and withdrawn)
    /// by a newer frame, written again at an equal generation that carries
    /// another one (no plan changes: `Refreshed`), and gone from a
    /// tombstone. No address is in it.
    #[test]
    fn nat_class_follows_the_global_snapshot() {
        use crate::route_hints::NAT_FLAG_V6_GLOBAL;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let varies = NatClass {
            v4_tcp: 4,
            v4_quic: 4,
            flags: NAT_FLAG_V6_GLOBAL,
            ..NatClass::default()
        };
        let with = |generation: u64, c: Option<NatClass>| RouteHints {
            nat_class: c,
            ..frame(generation)
        };
        let p2p = link(OutboxCarrier::P2p);
        assert_eq!(put(d, &with(5, Some(varies)), &p2p, T0), P2P_C);
        assert_eq!(view(d, T0).nat_class, Some(varies));
        assert_eq!(
            nat_classes(d, T0),
            [(hex::encode(sender()), pid(0x51), varies, T0 + TTL_MS)]
        );
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(raw.contains("\"nat_class\""), "{raw}");
        // The same frame again: nothing to write.
        assert_eq!(
            put(d, &with(5, Some(varies)), &p2p, T0 + 1),
            Applied::Unchanged
        );
        // The same generation with another class (the sender cannot send
        // that, but a receiver's rules may read it so): written, no plan
        // change.
        let kept = NatClass {
            v4_tcp: 2,
            ..varies
        };
        assert_eq!(
            put(d, &with(5, Some(kept)), &p2p, T0 + 2),
            Applied::Refreshed
        );
        assert_eq!(view(d, T0 + 2).nat_class, Some(kept));
        // A newer frame without one withdraws it.
        put(d, &with(6, None), &p2p, T0 + 3);
        assert_eq!(view(d, T0 + 3).nat_class, None);
        assert!(nat_classes(d, T0 + 3).is_empty());
        // An unpinned sender's is never kept, nor one without a PeerId.
        let unpinned = HintLink::fixture(OutboxCarrier::P2p, false);
        let v = validate(&with(7, Some(varies)), &unpinned);
        assert_eq!(v.nat_class, None);
        // A tombstone keeps none.
        put(d, &with(8, Some(varies)), &p2p, T0 + 4);
        let expired = T0 + 4 + TTL_MS;
        assert!(nat_classes(d, expired).is_empty());
        empty(d, &peer(1), 600, expired);
        let raw = String::from_utf8(read(d)).unwrap();
        assert!(!raw.contains("nat_class"), "{raw}");
    }

    /// Phase 6b R5 (step P6.28): another key at the address a contact's LAN
    /// part was learned at forgets that LAN part (its port, its same-LAN
    /// direct addresses, a part kept past its expiry too); the PeerId, the
    /// relays and the custody fields stay. Another address, another contact
    /// and a missing file forget nothing and write nothing.
    #[test]
    fn an_impostor_at_the_learned_lan_address_forgets_only_that_lan_part() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(forget_lan_at(d, &sender(), ip("192.168.7.20")), Ok(false));
        assert!(!d.join(LEARNED_ROUTES_FILE).exists());
        assert_eq!(put(d, &frame(5), &link(OutboxCarrier::Lan), T0), BOTH_C);
        let before = view(d, T0);
        assert_eq!(
            before.lan.as_ref().and_then(|l| l.ip),
            Some(ip("192.168.7.20"))
        );
        let held = read(d);
        assert_eq!(forget_lan_at(d, &sender(), ip("192.168.7.21")), Ok(false));
        assert_eq!(forget_lan_at(d, &peer(1), ip("192.168.7.20")), Ok(false));
        assert_eq!(read(d), held);
        // A dual-stack listener's form of the same address.
        assert_eq!(
            forget_lan_at(d, &sender(), ip("::ffff:192.168.7.20")),
            Ok(true)
        );
        let after = view(d, T0);
        assert_eq!(after.lan, None);
        assert_eq!(learned_with_lan(d, &sender(), T0 + TTL_MS + 1).1, None);
        assert!(after.p2p().unwrap().local_direct.is_empty());
        assert_eq!(
            (after.peer_id, texts(&after.relays), after.custodians),
            (before.peer_id, texts(&before.relays), before.custodians)
        );
        assert_eq!(forget_lan_at(d, &sender(), ip("192.168.7.20")), Ok(false));
    }
}
