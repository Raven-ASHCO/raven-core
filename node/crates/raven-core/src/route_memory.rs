//! Which route last reached a contact after a route above it failed (G2).
//!
//! Every send and every outbox attempt starts at the top of its plan (saved
//! LAN, learned LAN, Internet, p2p). For a contact that only answers further
//! down, each of them first waits out the dead routes above. This file
//! remembers, per contact, the one route that reached it right after a route
//! ranked above it failed, so the next tries start there for a while.
//!
//! - **Order only.** A remembered route moves to the front of a plan that
//!   already holds it, after every other rule (carrier choice, gates, the
//!   verified-contact rule, plausibility, blocked routes, localization). It is
//!   never added: what may be dialled does not change (Carrier Conformance V1
//!   §10.1/§10.2: a score affects scheduling only).
//! - **Authenticated evidence only.** A route "reached" the contact when its
//!   dial completed the Raven Noise handshake with the expected key (the RLB1
//!   probe answered, or a worker dial returned with an ACK where it carried
//!   messages). Inbound links, discovery and custodian dials teach nothing.
//! - **A fixed lease, LAN first whenever it works.** An entry lives
//!   [`LEASE_MS`] from its grant and is never extended by use (privacy pack
//!   PP.7: [`prune`] takes it off the disk after that). Any LAN route
//!   reaching the contact ends a remote one, and so does the contact
//!   connecting to our LAN listener from a new local address.
//! - **Per network.** An entry holds a tag of the network it was learned on
//!   ([`network_tag`]); on another network, or with no tag at all, nothing is
//!   used or learned.
//!
//! **Lab only** ([`live`]): debug builds with `RAVEN_LAB_TEST_A=1`. Otherwise
//! [`network_tag`] is `None`, and without a tag [`preferred_route`] and
//! [`learn`] read and write nothing, so a release plan is exactly today's.
//!
//! The file holds contact keys, routes and times; no message id and no
//! address of ours (the tag is a hash). Owner-only. Writers (`raven send`,
//! the outbox worker, the LAN listener, `raven contact`) take its own
//! data-dir lock; readers take none. Bounded: [`MAX_ENTRIES`] contacts.
//! Privacy pack PP.6: RMS1 kind 13 in a sealed profile ([`crate::at_rest`]),
//! today's JSON otherwise; a file a writer could not read is never written
//! over (skipped and counted).

use std::cmp::Reverse;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::at_rest::{self, Kind};
use crate::outbox::{plausible_route, OutboxCarrier, OutboxRoute};
use crate::paths::DataDirLock;

/// The file in the data dir.
pub const ROUTE_MEMORY_FILE: &str = "route_memory.json";
const ROUTE_MEMORY_LOCK: &str = ".route_memory.lock.sqlite";
/// How long a remembered route goes first (30 min from its grant).
pub const LEASE_MS: u64 = 30 * 60 * 1000;
/// At most this many contacts are remembered (the oldest grant goes first).
pub const MAX_ENTRIES: usize = 256;
/// An entry stamped further than this in the future means the clock went
/// back: it is ignored.
const CLOCK_SLACK_MS: u64 = 5 * 60 * 1000;
/// A busy lock skips the lesson (one slower attempt later, never a wrong
/// route).
const LOCK_WAIT: Duration = Duration::from_secs(2);
const TAG_DOMAIN: &[u8] = b"raven/route-memory/net/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Remembered {
    pub_hex: String,
    route: OutboxRoute,
    at_ms: u64,
    net: String,
}

/// Is the route memory on? Debug builds with `RAVEN_LAB_TEST_A=1` only
/// (owner decision: lab-only until Internet and p2p go to production).
pub fn live() -> bool {
    cfg!(debug_assertions) && crate::lab_test_a_enabled()
}

fn load(data_dir: &Path) -> Vec<Remembered> {
    // Advisory state: a missing or unreadable file is an empty one.
    at_rest::load_json_advisory(
        data_dir,
        &data_dir.join(ROUTE_MEMORY_FILE),
        Kind::RouteMemory,
    )
    .into_loaded()
    .unwrap_or_default()
}

/// Within its lease and not stamped in the future.
fn fresh(e: &Remembered, now_ms: u64) -> bool {
    e.at_ms <= now_ms.saturating_add(CLOCK_SLACK_MS) && now_ms < e.at_ms.saturating_add(LEASE_MS)
}

/// Fresh, learned on network `net`, and still a route the carriers can dial.
fn usable(e: &Remembered, net: &str, now_ms: u64) -> bool {
    e.net == net && fresh(e, now_ms) && plausible_route(&e.route)
}

/// The route that goes first for `peer` on network `net`, if one was
/// remembered there within its lease. `None` without a tag (memory off, or
/// no default route): nothing is read then. Never a LAN address another
/// contact was seen at too (`crate::lan_seen::shared_with_another`: a
/// router's in front of both, E2: a dial there reached one friend through
/// the router once, and both friends' sends then began there).
pub fn preferred_route(
    data_dir: &Path,
    peer: &[u8; 32],
    net: Option<&str>,
    now_ms: u64,
) -> Option<OutboxRoute> {
    let net = net?;
    let key = hex::encode(peer);
    load(data_dir)
        .into_iter()
        .find(|e| e.pub_hex == key && usable(e, net, now_ms))
        .map(|e| e.route)
        .filter(|r| !shared_lan_address(data_dir, peer, r, now_ms))
}

/// A LAN route whose IP literal is an address another contact was seen at
/// too.
fn shared_lan_address(data_dir: &Path, peer: &[u8; 32], route: &OutboxRoute, now_ms: u64) -> bool {
    route.carrier == crate::outbox::OutboxCarrier::Lan
        && crate::lan_seen::split_host_port(route.dial.trim())
            .and_then(|(host, _)| crate::lan_seen::ScopedIp::parse(host))
            .is_some_and(|ip| {
                crate::lan_seen::shared_with_another(data_dir, Some(peer), ip.ip(), now_ms)
            })
}

/// The order to try `planned` in: plan order, with `preferred` first when
/// the plan holds it (indices into `planned`; nothing added or dropped).
pub fn probe_order(planned: &[OutboxRoute], preferred: Option<&OutboxRoute>) -> Vec<usize> {
    let mut order: Vec<usize> = (0..planned.len()).collect();
    if let Some(i) = preferred.and_then(|p| planned.iter().position(|r| r == p)) {
        order.remove(i);
        order.insert(0, i);
    }
    order
}

/// What one attempt's dials say about the route memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lesson {
    /// It reached the contact after a route ranked above it failed.
    Grant(OutboxRoute),
    /// The remembered route failed.
    Forget(OutboxRoute),
    /// A LAN route reached the contact: no remote route goes first.
    ForgetRemote,
    Keep,
}

/// The lesson of one attempt. `normal`: the contact's routes in their plain
/// plan order (the ranks); `preferred`: the route this attempt put first;
/// `dialled`: (route as planned, reached) in dial order. A route that both
/// failed and reached in one attempt counts as reached.
pub fn lesson(
    normal: &[OutboxRoute],
    preferred: Option<&OutboxRoute>,
    dialled: &[(OutboxRoute, bool)],
) -> Lesson {
    let reached = |r: &OutboxRoute| dialled.iter().any(|(d, ok)| *ok && d == r);
    let failed = |r: &OutboxRoute| dialled.iter().any(|(d, ok)| !*ok && d == r) && !reached(r);
    let rank = |r: &OutboxRoute| normal.iter().position(|n| n == r).unwrap_or(normal.len());
    let winner = dialled.iter().find(|(_, ok)| *ok).map(|(r, _)| r);
    if let Some(w) = winner {
        if dialled.iter().any(|(r, _)| failed(r) && rank(r) < rank(w)) {
            return Lesson::Grant(w.clone());
        }
    }
    if let Some(p) = preferred.filter(|p| failed(p)) {
        return Lesson::Forget(p.clone());
    }
    if winner.is_some_and(|w| w.carrier == OutboxCarrier::Lan) {
        return Lesson::ForgetRemote;
    }
    Lesson::Keep
}

/// Apply what one attempt to `peer` saw ([`lesson`]). `net`: this computer's
/// network tag; without one nothing is read or written. `started_ms`: when
/// the attempt began, so a forget never removes a grant another process
/// wrote meanwhile (compare-and-delete).
#[allow(clippy::too_many_arguments)]
pub fn learn(
    data_dir: &Path,
    peer: &[u8; 32],
    normal: &[OutboxRoute],
    preferred: Option<&OutboxRoute>,
    dialled: &[(OutboxRoute, bool)],
    net: Option<&str>,
    started_ms: u64,
    now_ms: u64,
) -> Result<(), String> {
    let Some(net) = net else {
        return Ok(());
    };
    match lesson(normal, preferred, dialled) {
        Lesson::Keep => Ok(()),
        Lesson::Grant(route) => {
            if !plausible_route(&route) {
                return Ok(());
            }
            let key = hex::encode(peer);
            let entry = Remembered {
                pub_hex: key.clone(),
                route: OutboxRoute {
                    carrier: route.carrier,
                    dial: route.dial.trim().to_string(),
                },
                at_ms: now_ms,
                net: net.to_string(),
            };
            edit(data_dir, now_ms, |all| {
                all.retain(|e| e.pub_hex != key);
                all.push(entry);
            })
            .map(|_| ())
        }
        Lesson::Forget(route) => {
            forget_where(data_dir, peer, started_ms, now_ms, |e| e.route == route)
        }
        Lesson::ForgetRemote => forget_where(data_dir, peer, started_ms, now_ms, |e| {
            e.route.carrier != OutboxCarrier::Lan
        }),
    }
}

/// Forget `peer`'s remembered route (its contact was removed or its
/// addresses changed). Missing file or entry is fine; nothing is created.
pub fn forget(data_dir: &Path, peer: &[u8; 32]) -> Result<(), String> {
    forget_where(data_dir, peer, u64::MAX, crate::clock::now_ms(), |_| true)
}

/// Forget every contact's remembered route (`raven learning reset` for
/// everyone, OD6a-10: learning supersedes the memory while it is on, and its
/// reset forgets it too). Lock-free first: no file or no entry, no lock and
/// no write; nothing is created. How many entries went. A file this process
/// could not read is kept as it is (an error).
pub fn forget_all(data_dir: &Path) -> Result<usize, String> {
    match at_rest::load_json_advisory::<Vec<Remembered>>(
        data_dir,
        &data_dir.join(ROUTE_MEMORY_FILE),
        Kind::RouteMemory,
    ) {
        at_rest::Advisory::Missing | at_rest::Advisory::CorruptPlain => return Ok(0),
        at_rest::Advisory::Loaded(all) if all.is_empty() => return Ok(0),
        at_rest::Advisory::Loaded(_) | at_rest::Advisory::Unreadable(_) => {}
    }
    edit(data_dir, crate::clock::now_ms(), Vec::clear)
}

/// Forget `peer`'s remembered Internet or p2p route granted before
/// `before_ms`: it connected to our LAN listener from a new local-network
/// address, so LAN goes first again.
pub fn forget_remote(data_dir: &Path, peer: &[u8; 32], before_ms: u64) -> Result<(), String> {
    forget_where(data_dir, peer, before_ms, crate::clock::now_ms(), |e| {
        e.route.carrier != OutboxCarrier::Lan
    })
}

/// Remove `peer`'s entries that match `pred` and were written at or before
/// `before_ms`. Lock-free first: no match, no lock and no write. A file this
/// process could not read is looked at under the lock, and kept (an error).
fn forget_where(
    data_dir: &Path,
    peer: &[u8; 32],
    before_ms: u64,
    now_ms: u64,
    pred: impl Fn(&Remembered) -> bool,
) -> Result<(), String> {
    let key = hex::encode(peer);
    let doomed = |e: &Remembered| e.pub_hex == key && e.at_ms <= before_ms && pred(e);
    match at_rest::load_json_advisory::<Vec<Remembered>>(
        data_dir,
        &data_dir.join(ROUTE_MEMORY_FILE),
        Kind::RouteMemory,
    ) {
        at_rest::Advisory::Missing | at_rest::Advisory::CorruptPlain => return Ok(()),
        at_rest::Advisory::Loaded(all) if !all.iter().any(doomed) => return Ok(()),
        at_rest::Advisory::Loaded(_) | at_rest::Advisory::Unreadable(_) => {}
    }
    edit(data_dir, now_ms, |all| all.retain(|e| !doomed(e))).map(|_| ())
}

/// Privacy pack PP.7: take the entries past their lease (or stamped in the
/// future) off the disk. No plan reads them ([`preferred_route`] needs a
/// fresh one); before, they stayed until the next lesson was written.
/// Lock-free first: none, no lock and no write. How many went. A file that
/// could not be read is kept as it is (an error).
pub fn prune(data_dir: &Path, now_ms: u64) -> Result<usize, String> {
    match at_rest::load_json_advisory::<Vec<Remembered>>(
        data_dir,
        &data_dir.join(ROUTE_MEMORY_FILE),
        Kind::RouteMemory,
    ) {
        at_rest::Advisory::Missing | at_rest::Advisory::CorruptPlain => return Ok(0),
        at_rest::Advisory::Unreadable(e) => return Err(format!("{ROUTE_MEMORY_FILE}: {e}")),
        at_rest::Advisory::Loaded(all) if all.iter().all(|e| fresh(e, now_ms)) => return Ok(0),
        at_rest::Advisory::Loaded(_) => {}
    }
    edit(data_dir, now_ms, |_| {})
}

/// Rewrite the file under its lock with `f`, dropping entries past their
/// lease or stamped in the future. Written only when the content changed; a
/// file that did not exist and stays empty is never created. Plain bytes
/// that do not parse are replaced (it holds hints only); a file this process
/// could not read (a sealed one whose key is not loaded, a changed byte) is
/// never written over: an error, counted. How many entries of the file are
/// not in what was written (none when nothing was).
fn edit(
    data_dir: &Path,
    now_ms: u64,
    f: impl FnOnce(&mut Vec<Remembered>),
) -> Result<usize, String> {
    let _lock = DataDirLock::acquire_within(data_dir, ROUTE_MEMORY_LOCK, LOCK_WAIT)?;
    let path = data_dir.join(ROUTE_MEMORY_FILE);
    let before: Vec<Remembered> = at_rest::load_json_for_write(data_dir, &path, Kind::RouteMemory)
        .map_err(|e| format!("{ROUTE_MEMORY_FILE}: {e}"))?;
    let mut all = before.clone();
    all.retain(|e| fresh(e, now_ms));
    f(&mut all);
    all.sort_by_key(|e| Reverse(e.at_ms));
    all.truncate(MAX_ENTRIES);
    if all == before {
        return Ok(0);
    }
    let raw = serde_json::to_vec_pretty(&all).map_err(|e| e.to_string())?;
    // Under ROUTE_MEMORY_LOCK: sealed in a sealed profile.
    at_rest::write_held(data_dir, &path, Kind::RouteMemory, &raw).map_err(|e| e.to_string())?;
    Ok(before.iter().filter(|e| !all.contains(e)).count())
}

/// This computer's network tag: a hash of the source IPv4 address and the
/// IPv6 /64 its default routes would use. `None` when the memory is off
/// ([`live`]) or there is no default route. Found with a UDP `connect` to a
/// documentation address (RFC 5737, RFC 3849), which sends no packet.
///
/// Debug builds only: `RAVEN_LAB_NET_TAG` replaces it (the lab harness).
pub fn network_tag() -> Option<String> {
    if !live() {
        return None;
    }
    if let Some(tag) = lab_net_tag() {
        return Some(tag);
    }
    egress_tag()
}

/// [`network_tag`] behind the learning gate instead of the route memory's
/// (Phase 6a, [`crate::learning::learning_live`]): the tag learning
/// connectivity keys its networks by (HMACed before it is kept). `None`
/// while the learning gate is shut or there is no default route; debug
/// builds take `RAVEN_LAB_NET_TAG` as [`network_tag`] does.
pub fn network_tag_for_learning() -> Option<String> {
    if !crate::learning::learning_live() {
        return None;
    }
    if let Some(tag) = lab_net_tag() {
        return Some(tag);
    }
    egress_tag()
}

/// [`tag_for`] the [`egress_addrs`]. No lab override and no [`live`] gate:
/// raven-node's netwatch reads it to notice the default route moving between
/// interfaces that keep their addresses.
pub fn egress_tag() -> Option<String> {
    let (v4, v6) = egress_addrs();
    tag_for(v4, v6)
}

/// The source addresses this computer's default routes would use (UDP
/// `connect` to 192.0.2.1:9 and [2001:db8::1]:9; nothing is sent). No lab
/// override and no [`live`] gate: raven-node's netwatch and the p2p
/// candidate book read it.
pub fn egress_addrs() -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let egress = |bind: SocketAddr, to: SocketAddr| -> Option<IpAddr> {
        let socket = UdpSocket::bind(bind).ok()?;
        socket.connect(to).ok()?;
        let ip = socket.local_addr().ok()?.ip();
        (!ip.is_unspecified()).then_some(ip)
    };
    let v4 = egress(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9)),
    );
    let v6 = egress(
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9)),
    );
    let v4 = match v4 {
        Some(IpAddr::V4(a)) => Some(a),
        _ => None,
    };
    let v6 = match v6 {
        Some(IpAddr::V6(a)) => Some(a),
        _ => None,
    };
    (v4, v6)
}

/// `RAVEN_LAB_NET_TAG`, debug builds only; release builds never read it.
fn lab_net_tag() -> Option<String> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var("RAVEN_LAB_NET_TAG")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The tag for these egress addresses: hex of the first 8 bytes of SHA-256
/// over a domain, the IPv4 address and the IPv6 /64 (so IPv6 privacy
/// addresses rotating within the prefix keep the tag). `None` for neither.
pub fn tag_for(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> Option<String> {
    if v4.is_none() && v6.is_none() {
        return None;
    }
    let v6_prefix = v6.map(|a| u128::from(a) >> 64);
    let mut h = Sha256::new();
    h.update(TAG_DOMAIN);
    h.update(format!("{v4:?}|{v6_prefix:?}").as_bytes());
    Some(hex::encode(&h.finalize()[..8]))
}

/// [`egress_tag`] as the 8 bytes a security event carries
/// ([`crate::security_events::SecEvent::network`]).
pub fn egress_tag_bytes() -> Option<[u8; 8]> {
    hex::decode(egress_tag()?).ok()?.try_into().ok()
}

// ---- Path interference (Phase 6b design A R4, step P6.28) ----

/// How long a contact's routes over one carrier go last on one network after
/// its links there were tampered with (design A R4).
pub const INTERFERENCE_MS: u64 = 10 * 60 * 1000;
/// Interference notes kept at most (the one ending first goes).
const MAX_INTERFERENCE: usize = 256;

/// One note: `peer`'s routes over `carrier` on the network `net` (an
/// [`egress_tag_bytes`]) go last until `until_ms`. In memory only: it lasts
/// minutes, and it is about a path, never about the contact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Interference {
    peer: [u8; 32],
    net: [u8; 8],
    carrier: OutboxCarrier,
    until_ms: u64,
}

static INTERFERENCE: std::sync::Mutex<Vec<Interference>> = std::sync::Mutex::new(Vec::new());

fn interference() -> std::sync::MutexGuard<'static, Vec<Interference>> {
    INTERFERENCE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Phase 6b R4: links to `peer` over `carrier` on the network `egress_tag`
/// failed their tags often enough to be Suspicious. Until `until_ms` the
/// outbox plans that contact's other routes first there
/// ([`interfered_carriers`]): order only, nothing is blocked. A later note
/// for the same path moves its end; nothing is noted while the responses
/// gate is shut.
pub fn note_interference(
    peer: &[u8; 32],
    egress_tag: [u8; 8],
    carrier: OutboxCarrier,
    until_ms: u64,
) {
    use crate::security_gate::{live, SecGate};
    if !live(SecGate::Responses) {
        return;
    }
    let mut held = interference();
    let same = |i: &Interference| i.peer == *peer && i.net == egress_tag && i.carrier == carrier;
    if let Some(i) = held.iter_mut().find(|i| same(i)) {
        i.until_ms = i.until_ms.max(until_ms);
        return;
    }
    if held.len() >= MAX_INTERFERENCE {
        if let Some(first) = (0..held.len()).min_by_key(|&i| held[i].until_ms) {
            held.swap_remove(first);
        }
    }
    held.push(Interference {
        peer: *peer,
        net: egress_tag,
        carrier,
        until_ms,
    });
}

/// Is any interference noted for `peer` at `now_ms` (on any network)? A
/// planner asks this before it reads the egress tag.
pub fn interference_noted(peer: &[u8; 32], now_ms: u64) -> bool {
    use crate::security_gate::{live, SecGate};
    live(SecGate::Responses)
        && interference()
            .iter()
            .any(|i| i.peer == *peer && now_ms < i.until_ms)
}

/// The carriers whose routes to `peer` go last on the network `egress_tag`
/// at `now_ms` (design A R4): none without a tag or while the responses
/// gate is shut. (Notes past their end are only ignored here; a full list
/// drops the one ending first.)
pub fn interfered_carriers(
    peer: &[u8; 32],
    egress_tag: Option<[u8; 8]>,
    now_ms: u64,
) -> Vec<OutboxCarrier> {
    use crate::security_gate::{live, SecGate};
    let Some(net) = egress_tag.filter(|_| live(SecGate::Responses)) else {
        return Vec::new();
    };
    let mut carriers: Vec<OutboxCarrier> = interference()
        .iter()
        .filter(|i| i.peer == *peer && i.net == net && now_ms < i.until_ms)
        .map(|i| i.carrier)
        .collect();
    carriers.sort_unstable();
    carriers.dedup();
    carriers
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_000 * 24 * 60 * 60 * 1000;
    const MIN: u64 = 60 * 1000;
    const BOB: [u8; 32] = [7; 32];

    fn lan(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: d.into(),
        }
    }

    fn inet(d: &str) -> OutboxRoute {
        OutboxRoute {
            carrier: OutboxCarrier::Internet,
            dial: d.into(),
        }
    }

    fn grant(dir: &Path, peer: &[u8; 32], route: &OutboxRoute, net: &str, at: u64) {
        let above = lan("192.168.1.250:7420");
        learn(
            dir,
            peer,
            &[above.clone(), route.clone()],
            None,
            &[(above, false), (route.clone(), true)],
            Some(net),
            at,
            at,
        )
        .unwrap();
        assert_eq!(
            preferred_route(dir, peer, Some(net), at).as_ref(),
            Some(route)
        );
    }

    #[test]
    fn a_route_reached_after_a_failed_one_goes_first_on_the_same_network() {
        let dir = tempfile::tempdir().unwrap();
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        learn(
            dir.path(),
            &BOB,
            &[l.clone(), i.clone()],
            None,
            &[(l.clone(), false), (i.clone(), true)],
            Some("n1"),
            T,
            T,
        )
        .unwrap();
        assert_eq!(preferred_route(dir.path(), &BOB, Some("n1"), T), Some(i));
        assert_eq!(preferred_route(dir.path(), &BOB, Some("n2"), T), None);
        assert_eq!(preferred_route(dir.path(), &BOB, None, T), None);
        assert_eq!(preferred_route(dir.path(), &[8; 32], Some("n1"), T), None);
        // Reached first time (nothing above failed): nothing to remember.
        let other = [9u8; 32];
        learn(
            dir.path(),
            &other,
            std::slice::from_ref(&l),
            None,
            &[(l.clone(), true)],
            Some("n1"),
            T,
            T,
        )
        .unwrap();
        assert_eq!(preferred_route(dir.path(), &other, Some("n1"), T), None);
    }

    #[test]
    fn the_lease_is_fixed_and_using_it_does_not_extend_it() {
        let dir = tempfile::tempdir().unwrap();
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        grant(dir.path(), &BOB, &i, "n1", T);
        // Used 10 min later, first and reached: Keep, the lease stays as it is.
        let later = T + 10 * MIN;
        let normal = [l.clone(), i.clone()];
        assert_eq!(
            lesson(&normal, Some(&i), &[(i.clone(), true)]),
            Lesson::Keep
        );
        learn(
            dir.path(),
            &BOB,
            &normal,
            Some(&i),
            &[(i.clone(), true)],
            Some("n1"),
            later,
            later,
        )
        .unwrap();
        assert_eq!(
            preferred_route(dir.path(), &BOB, Some("n1"), T + LEASE_MS - 1),
            Some(i.clone())
        );
        assert_eq!(
            preferred_route(dir.path(), &BOB, Some("n1"), T + LEASE_MS),
            None
        );
    }

    #[test]
    fn a_failed_remembered_route_is_forgotten_but_not_a_newer_grant() {
        let dir = tempfile::tempdir().unwrap();
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        let normal = [l.clone(), i.clone()];
        let failed = [(i.clone(), false)];
        grant(dir.path(), &BOB, &i, "n1", T);
        // An attempt that started before the grant (another process wrote it
        // meanwhile) leaves it.
        learn(
            dir.path(),
            &BOB,
            &normal,
            Some(&i),
            &failed,
            Some("n1"),
            T - 1,
            T + 1,
        )
        .unwrap();
        assert_eq!(
            preferred_route(dir.path(), &BOB, Some("n1"), T + 1),
            Some(i.clone())
        );
        // One that started at or after it removes it.
        learn(
            dir.path(),
            &BOB,
            &normal,
            Some(&i),
            &failed,
            Some("n1"),
            T,
            T + 1,
        )
        .unwrap();
        assert_eq!(preferred_route(dir.path(), &BOB, Some("n1"), T + 1), None);
        assert_eq!(load(dir.path()), Vec::new());
    }

    #[test]
    fn a_lan_route_that_reaches_the_contact_ends_a_remote_lease() {
        let dir = tempfile::tempdir().unwrap();
        let (saved, learned) = (lan("bob-mac.local:7420"), lan("192.168.1.37:7420"));
        let i = inet("203.0.113.7:7422");
        let normal = [saved.clone(), learned.clone(), i.clone()];
        grant(dir.path(), &BOB, &i, "n1", T);
        learn(
            dir.path(),
            &BOB,
            &normal,
            None,
            &[(saved.clone(), true)],
            Some("n1"),
            T + 1,
            T + 1,
        )
        .unwrap();
        assert_eq!(preferred_route(dir.path(), &BOB, Some("n1"), T + 1), None);
        // A LAN-over-LAN lease (the learned address before the saved one)
        // survives a saved-LAN success.
        grant(dir.path(), &BOB, &learned, "n1", T + 2);
        learn(
            dir.path(),
            &BOB,
            &normal,
            None,
            &[(saved.clone(), true)],
            Some("n1"),
            T + 3,
            T + 3,
        )
        .unwrap();
        assert_eq!(
            preferred_route(dir.path(), &BOB, Some("n1"), T + 3),
            Some(learned.clone())
        );
        // forget_remote drops only non-LAN entries written before its bound.
        forget_remote(dir.path(), &BOB, T + 10).unwrap();
        assert_eq!(
            preferred_route(dir.path(), &BOB, Some("n1"), T + 3),
            Some(learned)
        );
        let carol = [3u8; 32];
        grant(dir.path(), &carol, &i, "n1", T + 20);
        forget_remote(dir.path(), &carol, T + 19).unwrap();
        assert_eq!(
            preferred_route(dir.path(), &carol, Some("n1"), T + 20),
            Some(i.clone()),
            "granted after the sighting"
        );
        forget_remote(dir.path(), &carol, T + 20).unwrap();
        assert_eq!(
            preferred_route(dir.path(), &carol, Some("n1"), T + 20),
            None
        );
    }

    /// (preferred, dialled, the lesson).
    type Case<'a> = (Option<&'a OutboxRoute>, Vec<(OutboxRoute, bool)>, Lesson);

    #[test]
    fn lesson_table() {
        let (l1, l2) = (lan("192.168.1.20:7420"), lan("192.168.1.21:7420"));
        let i = inet("203.0.113.7:7422");
        let away = inet("198.51.100.9:7422");
        let normal = [l1.clone(), l2.clone(), i.clone()];
        let cases: [Case; 10] = [
            // No winner, nothing remembered.
            (
                None,
                vec![(l1.clone(), false), (i.clone(), false)],
                Lesson::Keep,
            ),
            // No winner: the remembered route failed.
            (
                Some(&i),
                vec![(i.clone(), false), (l1.clone(), false)],
                Lesson::Forget(i.clone()),
            ),
            // The first planned route won: LAN first again.
            (None, vec![(l1.clone(), true)], Lesson::ForgetRemote),
            // A winner the normal plan does not hold, after a planned failure.
            (
                None,
                vec![(l1.clone(), false), (away.clone(), true)],
                Lesson::Grant(away.clone()),
            ),
            // ... and on its own.
            (None, vec![(away.clone(), true)], Lesson::Keep),
            // Failed, then reached on the same route: neither.
            (
                Some(&i),
                vec![(i.clone(), false), (i.clone(), true)],
                Lesson::Keep,
            ),
            // The remembered route failed and a LAN route won.
            (
                Some(&i),
                vec![(i.clone(), false), (l1.clone(), true)],
                Lesson::Forget(i.clone()),
            ),
            // A grant overrides the forget.
            (
                Some(&l2),
                vec![(l2.clone(), false), (l1.clone(), false), (i.clone(), true)],
                Lesson::Grant(i.clone()),
            ),
            // A failure ranked below the winner grants nothing.
            (
                None,
                vec![(l2.clone(), true), (i.clone(), false)],
                Lesson::ForgetRemote,
            ),
            // The learned LAN address after the saved one failed.
            (
                None,
                vec![(l1.clone(), false), (l2.clone(), true)],
                Lesson::Grant(l2.clone()),
            ),
        ];
        for (preferred, dialled, want) in cases {
            assert_eq!(
                lesson(&normal, preferred, &dialled),
                want,
                "{preferred:?} {dialled:?}"
            );
        }
    }

    #[test]
    fn probe_order_moves_only_a_planned_route() {
        let planned = [
            lan("192.168.1.20:7420"),
            lan("192.168.1.37:7420"),
            inet("203.0.113.7:7422"),
        ];
        assert_eq!(probe_order(&planned, None), [0, 1, 2]);
        assert_eq!(
            probe_order(&planned, Some(&inet("198.51.100.9:7422"))),
            [0, 1, 2]
        );
        assert_eq!(probe_order(&planned, Some(&planned[2])), [2, 0, 1]);
        assert_eq!(probe_order(&planned, Some(&planned[1])), [1, 0, 2]);
        assert_eq!(probe_order(&planned, Some(&planned[0])), [0, 1, 2]);
        assert!(probe_order(&[], Some(&planned[0])).is_empty());
    }

    #[test]
    fn bounded_corrupt_and_clock_steps() {
        let i = inet("203.0.113.7:7422");
        // A fresh dir is never created by a read, a Keep or a no-op forget.
        let parent = tempfile::tempdir().unwrap();
        let fresh_dir = parent.path().join("profile");
        assert_eq!(preferred_route(&fresh_dir, &BOB, Some("n1"), T), None);
        learn(
            &fresh_dir,
            &BOB,
            std::slice::from_ref(&i),
            None,
            &[(i.clone(), true)],
            Some("n1"),
            T,
            T,
        )
        .unwrap();
        let l = lan("192.168.1.20:7420");
        learn(
            &fresh_dir,
            &BOB,
            std::slice::from_ref(&l),
            None,
            &[(l.clone(), true)],
            Some("n1"),
            T,
            T,
        )
        .unwrap();
        forget(&fresh_dir, &BOB).unwrap();
        forget_remote(&fresh_dir, &BOB, T).unwrap();
        assert!(!fresh_dir.exists());

        let dir = tempfile::tempdir().unwrap();
        for n in 0..(MAX_ENTRIES as u64 + 10) {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&n.to_be_bytes());
            grant(dir.path(), &peer, &i, "n1", T + n);
        }
        let all = load(dir.path());
        assert_eq!(all.len(), MAX_ENTRIES);
        assert!(
            all.iter().all(|e| e.at_ms >= T + 10),
            "the newest grants are kept"
        );
        // Corrupt: read as empty, and the next grant rewrites it.
        let path = dir.path().join(ROUTE_MEMORY_FILE);
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(preferred_route(dir.path(), &BOB, Some("n1"), T), None);
        forget(dir.path(), &BOB).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
        grant(dir.path(), &BOB, &i, "n1", T);
        assert_eq!(load(dir.path()).len(), 1);
        // Stamped more than 5 min ahead (the clock went back): ignored.
        let ahead = T + CLOCK_SLACK_MS + 1;
        grant(dir.path(), &[4; 32], &i, "n1", ahead);
        assert_eq!(preferred_route(dir.path(), &[4; 32], Some("n1"), T), None);
        assert_eq!(
            preferred_route(dir.path(), &[4; 32], Some("n1"), ahead - CLOCK_SLACK_MS),
            Some(i.clone())
        );
        // A route that no longer passes the dial rules is never used.
        let mut all = load(dir.path());
        all[0].route.dial = "local-listen".into();
        let peer_hex = all[0].pub_hex.clone();
        std::fs::write(&path, serde_json::to_vec(&all).unwrap()).unwrap();
        let peer: [u8; 32] = hex::decode(peer_hex).unwrap().try_into().unwrap();
        assert_eq!(preferred_route(dir.path(), &peer, Some("n1"), ahead), None);
        // The file holds keys, routes and times only, owner-only.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&hex::encode(BOB)), "{text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{mode:o}");
        }
    }

    /// `raven learning reset` for everyone (P6.17, OD6a-10): every contact's
    /// route goes; no file (or an empty one) is left as it is, nothing is
    /// created, and a corrupt plain file is kept.
    #[test]
    fn forget_all_clears_every_contact_and_creates_nothing() {
        let parent = tempfile::tempdir().unwrap();
        let fresh_dir = parent.path().join("profile");
        assert_eq!(forget_all(&fresh_dir), Ok(0));
        assert!(!fresh_dir.exists());

        let dir = tempfile::tempdir().unwrap();
        let now = crate::clock::now_ms();
        let i = inet("203.0.113.7:7422");
        for peer in [BOB, [8; 32], [9; 32]] {
            grant(dir.path(), &peer, &i, "n1", now);
        }
        assert_eq!(forget_all(dir.path()), Ok(3));
        for peer in [BOB, [8; 32], [9; 32]] {
            assert_eq!(preferred_route(dir.path(), &peer, Some("n1"), now), None);
        }
        assert!(load(dir.path()).is_empty());
        assert_eq!(forget_all(dir.path()), Ok(0));

        let path = dir.path().join(ROUTE_MEMORY_FILE);
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(forget_all(dir.path()), Ok(0));
        assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
    }

    #[test]
    fn no_grant_without_a_network_tag() {
        let dir = tempfile::tempdir().unwrap();
        let (l, i) = (lan("192.168.1.20:7420"), inet("203.0.113.7:7422"));
        learn(
            dir.path(),
            &BOB,
            &[l.clone(), i.clone()],
            None,
            &[(l, false), (i, true)],
            None,
            T,
            T,
        )
        .unwrap();
        assert!(!dir.path().join(ROUTE_MEMORY_FILE).exists());
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
        // Nor for a route the carriers would never dial.
        let junk = lan("local-listen");
        learn(
            dir.path(),
            &BOB,
            &[lan("192.168.1.20:7420"), junk.clone()],
            None,
            &[(lan("192.168.1.20:7420"), false), (junk, true)],
            Some("n1"),
            T,
            T,
        )
        .unwrap();
        assert!(!dir.path().join(ROUTE_MEMORY_FILE).exists());
    }

    #[test]
    fn network_tag_hashes_the_v4_address_and_the_v6_prefix() {
        let v4: Ipv4Addr = "192.168.1.37".parse().unwrap();
        let a: Ipv6Addr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:1:2:1111:2222:3333:4444".parse().unwrap();
        let other: Ipv6Addr = "2001:db8:1:3::1".parse().unwrap();
        let tag = tag_for(Some(v4), Some(a)).unwrap();
        assert_eq!(tag.len(), 16);
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(tag_for(Some(v4), Some(b)).as_deref(), Some(tag.as_str()));
        assert_ne!(tag_for(Some(v4), Some(other)), Some(tag.clone()));
        assert_ne!(
            tag_for(Some("192.168.1.38".parse().unwrap()), Some(a)),
            Some(tag.clone())
        );
        assert_ne!(tag_for(Some(v4), None), Some(tag.clone()));
        assert_ne!(tag_for(None, Some(a)), tag_for(Some(v4), None));
        assert_eq!(tag_for(None, None), None);
        for text in ["192.168.1.37", "2001:db8", "192", "c0a8"] {
            assert!(!tag.contains(text), "{tag} holds {text}");
        }
    }

    /// The ungated lookup is the same hash of the same addresses, whatever
    /// the lab switches say.
    #[test]
    fn egress_tag_is_tag_for_the_egress_addresses() {
        let (v4, v6) = egress_addrs();
        assert!(v4.is_none_or(|a| !a.is_unspecified()), "{v4:?}");
        assert!(v6.is_none_or(|a| !a.is_unspecified()), "{v6:?}");
        assert_eq!(egress_tag(), tag_for(v4, v6));
    }

    /// The release test job: off whatever the environment says. A debug
    /// build follows exactly the lab switch.
    #[test]
    fn live_is_off_without_debug_and_lab_test_a() {
        if !cfg!(debug_assertions) {
            assert!(!live());
            assert_eq!(network_tag(), None);
            return;
        }
        assert_eq!(live(), crate::lab_test_a_enabled());
        if !live() {
            assert_eq!(network_tag(), None);
        }
    }

    /// Learning's tag (Phase 6a) follows the learning gate, not the route
    /// memory's: none while it is shut (always in a release build), and
    /// otherwise the tag `network_tag` reads (the lab one, or the egress
    /// tag).
    #[test]
    fn the_learning_tag_follows_the_learning_gate() {
        if !crate::learning::learning_live() {
            assert_eq!(network_tag_for_learning(), None);
            return;
        }
        let want = lab_net_tag().or_else(egress_tag);
        assert_eq!(network_tag_for_learning(), want);
    }

    /// Release builds never read the lab variable (runs in a release test
    /// job; a debug build skips it).
    #[test]
    fn network_tag_lab_override_is_inert_in_release() {
        if cfg!(debug_assertions) {
            return;
        }
        // Edition 2021: a plain call. No other test reads this variable.
        std::env::set_var("RAVEN_LAB_NET_TAG", "lab-net");
        assert_eq!(lab_net_tag(), None);
        assert_eq!(network_tag(), None);
    }

    /// Phase 6b R4 (step P6.28): an interference note puts that contact's
    /// carrier last on that network until its end (a later note moves the
    /// end, never back), on no other network and for no other contact;
    /// nothing is noted or read while the responses gate is shut.
    #[test]
    fn interference_lasts_until_its_end_on_its_network_only() {
        use crate::security_sense::tests::{Responses, Shut};
        let (here, there) = ([0x11; 8], [0x22; 8]);
        let (alice, carol) = ([0x71; 32], [0x72; 32]);
        let end = T + INTERFERENCE_MS;
        {
            let _shut = Shut::start();
            note_interference(&alice, here, OutboxCarrier::Lan, end);
        }
        let Some(_on) = Responses::on() else {
            return;
        };
        assert!(!interference_noted(&alice, T), "nothing while shut");
        note_interference(&alice, here, OutboxCarrier::Lan, end);
        assert!(interference_noted(&alice, T));
        assert_eq!(
            interfered_carriers(&alice, Some(here), T + 9 * MIN),
            vec![OutboxCarrier::Lan]
        );
        assert!(interfered_carriers(&alice, Some(there), T).is_empty());
        assert!(interfered_carriers(&alice, None, T).is_empty());
        assert!(interfered_carriers(&carol, Some(here), T).is_empty());
        // An earlier end never shortens it; a later one moves it.
        note_interference(&alice, here, OutboxCarrier::Lan, end - MIN);
        assert!(interfered_carriers(&alice, Some(here), end).is_empty());
        note_interference(&alice, here, OutboxCarrier::Lan, end + 5 * MIN);
        note_interference(&alice, here, OutboxCarrier::P2p, end);
        assert_eq!(
            interfered_carriers(&alice, Some(here), end - 1),
            vec![OutboxCarrier::Lan, OutboxCarrier::P2p]
        );
        assert_eq!(
            interfered_carriers(&alice, Some(here), end),
            vec![OutboxCarrier::Lan]
        );
        assert!(interfered_carriers(&alice, Some(here), end + 5 * MIN).is_empty());
        assert!(!interference_noted(&alice, end + 5 * MIN));
    }
}
