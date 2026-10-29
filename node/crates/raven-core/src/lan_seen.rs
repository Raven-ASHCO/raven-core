//! Where verified-or-local contacts last reached this node on the LAN.
//!
//! A contact whose computer got a new DHCP address keeps its listening port, but
//! the `lan_dial` saved in the contact book still names the old address, so
//! every send to it fails until someone retypes it. When that contact connects
//! *to us* over an authenticated link (it sends us something, or its outbox
//! retries), raven-node records the source IP here. Senders then also try
//! `<seen ip>:<saved port>` as a second LAN route, and `raven send` saves it to
//! the contact once it has reached (and authenticated) that contact. Under the
//! cutoff pack's F7 a contact with no LAN route saved at all (one added from an
//! invite line) is tried at `<seen ip>:<default LAN port>`
//! ([`learned_lan_dial_default_port`]), only with a noise pin for it.
//!
//! An IPv6 link-local source (fe80::/10) is recorded with the zone it came in
//! on (Phase 3 P3.4, [`ScopedIp`]): `fe80::b%en0` inside the same `ip` string
//! (this computer's interface name, or its number), dialled back as
//! `[fe80::b%en0]:port`. One without a zone is still never recorded: it could
//! not be dialled back. An older build fails `parse::<IpAddr>()` on a zoned
//! entry and skips it, so no build ever dials a link-local address without its
//! zone; a file without zones is byte for byte what older builds write.
//! [`recent_lan_contacts`] lists who reached this node lately (the LAN
//! beacon's join round, P3.10).
//!
//! The file holds no secret: public keys, IP addresses and times only. Only the
//! listener writes it, for links whose Noise static key is a contact's key, and
//! `ash contact remove` / `set-addr` forget the contact's entry. A learned
//! address is offered for an unverified contact only when it is on the local
//! network (the same rule as its saved LAN address). Bounded: [`MAX_ENTRIES`]
//! contacts, each forgotten after [`MAX_AGE_MS`] (privacy pack PP.7: taken
//! off the disk by [`prune`] too, not only ignored).
//!
//! Privacy pack PP.6: RMS1 kind 2 in a sealed profile ([`crate::at_rest`]),
//! today's JSON otherwise; readers accept both. Writers take the
//! cross-process lock [`LAN_SEEN_LOCK`] (before, only a mutex inside one
//! process), and never write over a file they could not read (a sealed one
//! whose key is not loaded, a changed byte): that is skipped and counted.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, Advisory, Kind};

/// The file in the data dir.
pub const LAN_SEEN_FILE: &str = "lan_seen.json";
/// At most this many contacts are remembered (the oldest sighting goes first).
pub const MAX_ENTRIES: usize = 256;
/// A sighting older than this is not used (30 days).
pub const MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// The longest zone kept with an IPv6 link-local address: an interface name
/// (at most 15 bytes on Linux, macOS and the BSDs, 31 on illumos) or its
/// number (Windows zones are always numbers).
const MAX_ZONE_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Seen {
    pub_hex: String,
    /// [`ScopedIp`]'s text form.
    ip: String,
    seen_at_ms: u64,
    /// When a LAN dial to this address last reached the contact's key
    /// ([`note_reached`]): the address is the contact's own, not a router's
    /// in front of it. 0: never (or it was seen at another address since).
    #[serde(default, skip_serializing_if = "is_zero")]
    reached_at_ms: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// Two contacts seen at one address within this of each other share it
/// ([`shared_with_another`]): a router in front of both (E2: two friends
/// behind a second router reached mac-b from that router's address on mac-b's
/// network), not a friend's own address.
pub const SHARED_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// An address as a sighting keeps it, and a learned LAN part
/// ([`crate::learned_routes`]): an IPv6 link-local address (fe80::/10) with
/// the zone it is reached on, an interface of this computer (`fe80::b%en0`,
/// or its number `fe80::b%4`); any other address bare, an IPv4-mapped one as
/// IPv4. Written (`Display`) and read ([`ScopedIp::parse`]) in that text
/// form. `parse::<IpAddr>()` refuses it when it has a zone, so an older build
/// skips such an entry instead of dialling it without its zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedIp {
    ip: IpAddr,
    /// Only with an IPv6 link-local `ip`.
    zone: Option<String>,
}

impl ScopedIp {
    /// `ip` with `zone` when `ip` is an IPv6 link-local address and the zone
    /// is one a dial string carries and reads back (`zone_ok`); any other
    /// zone is dropped.
    pub fn new(ip: IpAddr, zone: Option<&str>) -> Self {
        let ip = canonical_ip(ip);
        let zone = zone
            .filter(|z| is_link_local_v6(ip) && zone_ok(z))
            .map(str::to_owned);
        Self { ip, zone }
    }

    /// The text form read back: `192.168.1.37`, `fd00::5`, `fe80::b%en0`.
    /// `None` for anything else, a zone on any but an IPv6 link-local address
    /// and a zone `zone_ok` refuses included.
    pub fn parse(text: &str) -> Option<Self> {
        match text.split_once('%') {
            None => text.parse::<IpAddr>().ok().map(|ip| Self::new(ip, None)),
            Some((ip, zone)) => {
                let ip: IpAddr = ip.parse().ok()?;
                (is_link_local_v6(ip) && zone_ok(zone)).then(|| Self {
                    ip,
                    zone: Some(zone.to_owned()),
                })
            }
        }
    }

    /// The address (an IPv4-mapped one as IPv4).
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The zone of an IPv6 link-local address; `None` for any other.
    pub fn zone(&self) -> Option<&str> {
        self.zone.as_deref()
    }

    /// Can be dialled back: not unspecified or multicast, and an IPv6
    /// link-local address only with its zone.
    pub fn dialable(&self) -> bool {
        !(self.ip.is_unspecified()
            || self.ip.is_multicast()
            || (is_link_local_v6(self.ip) && self.zone.is_none()))
    }

    /// The dial string on `port`: `192.168.1.37:7420`, `[fd00::5]:7420` or
    /// `[fe80::b%en0]:7420`.
    pub fn dial(&self, port: u16) -> String {
        match &self.zone {
            Some(zone) => format!("[{}%{zone}]:{port}", self.ip),
            None => SocketAddr::new(self.ip, port).to_string(),
        }
    }
}

impl std::fmt::Display for ScopedIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.zone {
            Some(zone) => write!(f, "{}%{zone}", self.ip),
            None => write!(f, "{}", self.ip),
        }
    }
}

fn is_link_local_v6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80)
}

/// A zone a dial string carries and reads back as the same interface (the
/// rule raven-node's `netutil::zone_for` writes them by): not empty, at most
/// [`MAX_ZONE_LEN`] bytes, no whitespace or control character, no `%` or
/// `]`, and not the number 0 (no zone at all).
fn zone_ok(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= MAX_ZONE_LEN
        && zone.parse::<u32>().ok() != Some(0)
        && !zone
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '%' | ']'))
}

/// Every writer takes it (the listener runs links concurrently, and `raven
/// contact remove` forgets in another process): the lock `at_rest::FILES`
/// names for [`LAN_SEEN_FILE`].
pub const LAN_SEEN_LOCK: &str = ".at_rest.lan_seen.lock.sqlite";

fn seen_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LAN_SEEN_FILE)
}

fn read(data_dir: &Path) -> Advisory<Vec<Seen>> {
    at_rest::load_json_advisory(data_dir, &seen_path(data_dir), Kind::LanSeen)
}

fn load(data_dir: &Path) -> Vec<Seen> {
    // Advisory state: a missing or unreadable file is an empty one.
    read(data_dir).into_loaded().unwrap_or_default()
}

/// The sighting of `key` at `ip` applied to `seen` as of `now_ms` (old ones
/// dropped, bounded): `None` when nothing is to be written (the same IP seen
/// within the hour), else whether the address is new.
fn apply_sighting(seen: &mut Vec<Seen>, key: &str, ip: &str, now_ms: u64) -> Option<bool> {
    seen.retain(|s| now_ms.saturating_sub(s.seen_at_ms) <= MAX_AGE_MS);
    let moved;
    if let Some(entry) = seen.iter_mut().find(|s| s.pub_hex == key) {
        moved = entry.ip != ip;
        if !moved && now_ms.saturating_sub(entry.seen_at_ms) < 60 * 60 * 1000 {
            return None;
        }
        if moved {
            entry.reached_at_ms = 0;
        }
        entry.ip = ip.to_string();
        entry.seen_at_ms = now_ms;
    } else {
        moved = true;
        seen.push(Seen {
            pub_hex: key.to_string(),
            ip: ip.to_string(),
            seen_at_ms: now_ms,
            reached_at_ms: 0,
        });
    }
    seen.sort_by_key(|s| std::cmp::Reverse(s.seen_at_ms));
    seen.truncate(MAX_ENTRIES);
    Some(moved)
}

/// Record that the contact `peer` (its device Ed25519 key) just reached this node
/// from `ip` over an authenticated link. Rewrites the file only when the address
/// changed or the last sighting is more than an hour old. `zone`: the zone an
/// IPv6 link-local `ip` came in on (`en0`, or its number), kept with it
/// ([`ScopedIp`]); ignored for any other address.
///
/// `true` when the address is new: the contact had no (recent) sighting, or
/// it came from another IP (or zone). The same IP, rewritten or not, and a
/// source that is not recorded (unspecified, multicast, IPv6 link-local
/// without a usable zone) are `false`.
pub fn record_contact_seen(
    data_dir: &Path,
    peer: &[u8; 32],
    ip: IpAddr,
    zone: Option<&str>,
    now_ms: u64,
) -> Result<bool, String> {
    let ip = ScopedIp::new(ip, zone);
    // A link-local source without its zone could not be dialled back; do not
    // let it replace a usable sighting.
    if !ip.dialable() {
        return Ok(false);
    }
    let key = hex::encode(peer);
    let ip = ip.to_string();
    // Most links repeat a recent sighting: no lock and no write for those.
    if apply_sighting(&mut load(data_dir), &key, &ip, now_ms).is_none() {
        return Ok(false);
    }
    let path = seen_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::LanSeen).map_err(|e| e.to_string())?;
    // Never written over when it could not be read (a sealed file whose key
    // is not loaded, a changed byte): nothing is recorded (counted).
    let Ok(mut seen) = at_rest::load_json_for_write::<Vec<Seen>>(data_dir, &path, Kind::LanSeen)
    else {
        return Ok(false);
    };
    let Some(moved) = apply_sighting(&mut seen, &key, &ip, now_ms) else {
        return Ok(false);
    };
    lock.store_json(&seen).map_err(|e| e.to_string())?;
    Ok(moved)
}

/// The address `peer` last reached us from, with the port of its saved
/// `lan_dial`, when that differs from the saved address: `ip:port`, or
/// `[fe80::b%en0]:port` for an IPv6 link-local sighting with its zone.
/// `None` when there is no recent sighting, the saved dial has no usable
/// port, it already names the seen address, the sighting cannot be dialled
/// back (a link-local address without a zone, in a file written by hand), or
/// the contact is not verified (`pinned`) and the seen address is not on the
/// local network.
pub fn learned_lan_dial(
    data_dir: &Path,
    peer: &[u8; 32],
    saved_dial: &str,
    pinned: bool,
    now_ms: u64,
) -> Option<String> {
    let (host, port) = split_host_port(saved_dial.trim())?;
    let seen = usable_sighting(data_dir, peer, now_ms)?;
    if !pinned && !crate::outbox::is_local_network_ip(seen.ip()) {
        return None;
    }
    if ScopedIp::parse(host).is_some_and(|saved| saved == seen) {
        return None;
    }
    Some(seen.dial(port))
}

/// `peer`'s sighting as a LAN dial may use it: within [`MAX_AGE_MS`],
/// dialable, and no other contact seen at that address within
/// [`SHARED_WINDOW_MS`] of it ([`shared_with_another`]: a router's
/// address, E2). The caller applies the contact's locality rule and its
/// own on-link filter.
pub fn usable_sighting(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Option<ScopedIp> {
    let all = load(data_dir);
    let key = hex::encode(peer);
    let mine = all
        .iter()
        .find(|s| s.pub_hex == key && now_ms.saturating_sub(s.seen_at_ms) <= MAX_AGE_MS)?;
    let addr = ScopedIp::parse(&mine.ip).filter(ScopedIp::dialable)?;
    (!shared_in(&all, mine, now_ms)).then_some(addr)
}

/// Whether another contact was seen at `mine`'s address within
/// [`SHARED_WINDOW_MS`] of `mine` (both within [`MAX_AGE_MS`]). Loopback
/// never is: contacts on this computer each listen on their own port.
fn shared_in(all: &[Seen], mine: &Seen, now_ms: u64) -> bool {
    let at = ScopedIp::parse(&mine.ip).map(|a| a.ip());
    if at.is_some_and(|ip| ip.is_loopback()) {
        return false;
    }
    all.iter().any(|s| {
        s.pub_hex != mine.pub_hex
            && now_ms.saturating_sub(s.seen_at_ms) <= MAX_AGE_MS
            && s.seen_at_ms.abs_diff(mine.seen_at_ms) <= SHARED_WINDOW_MS
            && ScopedIp::parse(&s.ip).map(|a| a.ip()) == at
    })
}

/// Whether a contact other than `peer` (`None`: any two contacts) was seen
/// at `ip` within [`SHARED_WINDOW_MS`] of `peer`'s own sighting there: the
/// address is a router's in front of several contacts, never one of them
/// (E2). The route memory and the route hints' LAN part ask too.
pub fn shared_with_another(
    data_dir: &Path,
    peer: Option<&[u8; 32]>,
    ip: IpAddr,
    now_ms: u64,
) -> bool {
    let ip = canonical_ip(ip);
    let all = load(data_dir);
    let at_ip: Vec<&Seen> = all
        .iter()
        .filter(|s| {
            now_ms.saturating_sub(s.seen_at_ms) <= MAX_AGE_MS
                && ScopedIp::parse(&s.ip).is_some_and(|a| a.ip() == ip)
        })
        .collect();
    if ip.is_loopback() {
        return false;
    }
    match peer {
        Some(peer) => {
            let key = hex::encode(peer);
            match at_ip.iter().find(|s| s.pub_hex == key) {
                Some(mine) => shared_in(&all, mine, now_ms),
                // Not seen there itself: any other contact seen there makes
                // it someone else's address.
                None => at_ip.iter().any(|s| s.pub_hex != key),
            }
        }
        None => at_ip.iter().any(|a| shared_in(&all, a, now_ms)),
    }
}

/// Whether `peer`'s sighting is at `ip` and a LAN dial there reached its
/// key ([`note_reached`]).
pub fn reached_at(data_dir: &Path, peer: &[u8; 32], ip: IpAddr, now_ms: u64) -> bool {
    let key = hex::encode(peer);
    let ip = canonical_ip(ip);
    load(data_dir).iter().any(|s| {
        s.pub_hex == key
            && s.reached_at_ms > 0
            && now_ms.saturating_sub(s.seen_at_ms) <= MAX_AGE_MS
            && ScopedIp::parse(&s.ip).is_some_and(|a| a.ip() == ip)
    })
}

/// A LAN dial to `ip` (with its zone) reached `peer`'s key at `now_ms`:
/// its sighting there, if it has one, is its own address
/// ([`reached_at`]). Rewritten at most hourly. Whether it was written; no
/// sighting there, or a file that cannot be read, writes nothing.
pub fn note_reached(
    data_dir: &Path,
    peer: &[u8; 32],
    ip: IpAddr,
    zone: Option<&str>,
    now_ms: u64,
) -> Result<bool, String> {
    let key = hex::encode(peer);
    let ip = ScopedIp::new(ip, zone).to_string();
    let due = |s: &Seen| {
        s.pub_hex == key && s.ip == ip && now_ms.saturating_sub(s.reached_at_ms) >= 60 * 60 * 1000
    };
    if !load(data_dir).iter().any(due) {
        return Ok(false);
    }
    let path = seen_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::LanSeen).map_err(|e| e.to_string())?;
    let Ok(mut seen) = at_rest::load_json_for_write::<Vec<Seen>>(data_dir, &path, Kind::LanSeen)
    else {
        return Ok(false);
    };
    let Some(entry) = seen.iter_mut().find(|s| due(s)) else {
        return Ok(false);
    };
    entry.reached_at_ms = now_ms;
    lock.store_json(&seen).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Cutoff F7: the address `peer` last reached us from, on the default LAN
/// port, for a contact with no LAN route at all (one added from an invite
/// line), whose port nothing else tells: the debug lab's
/// [`crate::lan_gate::lab_default_lan_port`], else
/// [`crate::paths::DEFAULT_LAN_PORT`]. The rules of [`learned_lan_dial`]
/// (a sighting within [`MAX_AGE_MS`]; a local-network address only for an
/// unverified contact; an IPv6 link-local sighting with its zone as
/// `[fe80::b%en0]:7420`), and never:
/// - a scope-less IPv6 link-local address (it cannot be dialled back);
/// - a loopback sighting, or one at any of this computer's own addresses
///   (a contact on this computer that reached the listener through its LAN
///   address), unless the lab port is set: a guess at 7420 there would dial
///   this computer's own node.
///
/// The caller checks the gates and the contact's noise pin
/// ([`crate::outbox::with_default_port_sighting`]).
pub fn learned_lan_dial_default_port(
    data_dir: &Path,
    peer: &[u8; 32],
    pinned: bool,
    now_ms: u64,
) -> Option<String> {
    default_port_dial(
        data_dir,
        peer,
        pinned,
        now_ms,
        crate::lan_gate::lab_default_lan_port(),
        on_this_computer,
    )
}

/// One of this computer's own addresses ([`crate::netifs`]). An interface
/// list that can't be read knows of none (loopback is checked anyway).
fn on_this_computer(ip: IpAddr) -> bool {
    crate::netifs::is_on_this_computer(ip) == Some(true)
}

/// [`learned_lan_dial_default_port`] with the lab port and the own-address
/// check passed in.
fn default_port_dial(
    data_dir: &Path,
    peer: &[u8; 32],
    pinned: bool,
    now_ms: u64,
    lab_port: Option<u16>,
    is_own: impl Fn(IpAddr) -> bool,
) -> Option<String> {
    let seen = usable_sighting(data_dir, peer, now_ms)?;
    let ip = seen.ip();
    if !pinned && !crate::outbox::is_local_network_ip(ip) {
        return None;
    }
    if lab_port.is_none() && (ip.is_loopback() || is_own(ip)) {
        return None;
    }
    Some(seen.dial(lab_port.unwrap_or(crate::paths::DEFAULT_LAN_PORT)))
}

/// Where `peer` last reached us from, when that was within [`MAX_AGE_MS`].
/// No locality rule: the caller applies the contact's. An IPv6 link-local
/// sighting keeps its zone, which an `IpAddr` cannot hold: `None` here,
/// [`seen_addr`] reads it.
pub fn seen_ip(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Option<IpAddr> {
    seen_text(data_dir, peer, now_ms)?.parse().ok()
}

/// [`seen_ip`] with the zone of an IPv6 link-local sighting ([`ScopedIp`]):
/// route hints try the contact's announced LAN port there too
/// ([`crate::learned_routes::rrh1_lan_dials`]). The caller checks
/// [`ScopedIp::dialable`] before it dials: a link-local address without a
/// zone (only in a file written by hand) is not.
pub fn seen_addr(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Option<ScopedIp> {
    ScopedIp::parse(&seen_text(data_dir, peer, now_ms)?)
}

/// The `ip` text of `peer`'s sighting within [`MAX_AGE_MS`].
fn seen_text(data_dir: &Path, peer: &[u8; 32], now_ms: u64) -> Option<String> {
    seen_text_within(data_dir, peer, MAX_AGE_MS, now_ms)
}

/// The `ip` text of `peer`'s sighting within `max_age_ms` (never beyond
/// [`MAX_AGE_MS`]).
fn seen_text_within(
    data_dir: &Path,
    peer: &[u8; 32],
    max_age_ms: u64,
    now_ms: u64,
) -> Option<String> {
    let max_age_ms = max_age_ms.min(MAX_AGE_MS);
    let key = hex::encode(peer);
    load(data_dir)
        .into_iter()
        .find(|s| s.pub_hex == key && now_ms.saturating_sub(s.seen_at_ms) <= max_age_ms)
        .map(|s| s.ip)
}

/// [`seen_addr`] for a sighting within `max_age_ms` only (never beyond
/// [`MAX_AGE_MS`]): the LAN beacon asks whether a contact that gives no
/// answer reached this node on this network lately (Phase 3 P3.C3: the
/// last 7 days). A missing or unreadable file knows of no one.
pub fn seen_within(
    data_dir: &Path,
    peer: &[u8; 32],
    max_age_ms: u64,
    now_ms: u64,
) -> Option<ScopedIp> {
    ScopedIp::parse(&seen_text_within(data_dir, peer, max_age_ms, now_ms)?)
}

/// The contacts (device keys) that reached this node over an authenticated
/// link within `max_age_ms` (never beyond [`MAX_AGE_MS`]), newest first, at
/// most `n`: the LAN beacon's join round looks for them (Phase 3 P3.10).
/// Whatever their address; an entry whose key is not 32 bytes of hex is
/// skipped. A missing or unreadable file knows of no one.
pub fn recent_lan_contacts(
    data_dir: &Path,
    n: usize,
    max_age_ms: u64,
    now_ms: u64,
) -> Vec<[u8; 32]> {
    let max_age_ms = max_age_ms.min(MAX_AGE_MS);
    let mut seen = load(data_dir);
    seen.retain(|s| now_ms.saturating_sub(s.seen_at_ms) <= max_age_ms);
    seen.sort_by_key(|s| std::cmp::Reverse(s.seen_at_ms));
    let mut out: Vec<[u8; 32]> = Vec::new();
    for s in seen {
        if out.len() == n {
            break;
        }
        let key = hex::decode(&s.pub_hex)
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k).ok());
        if let Some(key) = key.filter(|k| !out.contains(k)) {
            out.push(key);
        }
    }
    out
}

/// Forget where `peer` was seen (its contact was removed or its address was
/// set by hand), under [`LAN_SEEN_LOCK`]. Missing file or entry is fine; a
/// file that could not be read is kept as it is (an error).
pub fn forget(data_dir: &Path, peer: &[u8; 32]) -> Result<(), String> {
    let key = hex::encode(peer);
    // Lock-free first: nothing to forget, no lock (and no lock file).
    match read(data_dir) {
        Advisory::Missing | Advisory::CorruptPlain => return Ok(()),
        Advisory::Loaded(seen) if !seen.iter().any(|s| s.pub_hex == key) => return Ok(()),
        Advisory::Loaded(_) | Advisory::Unreadable(_) => {}
    }
    let path = seen_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::LanSeen).map_err(|e| e.to_string())?;
    let mut seen = at_rest::load_json_for_write::<Vec<Seen>>(data_dir, &path, Kind::LanSeen)
        .map_err(|e| format!("{LAN_SEEN_FILE}: {e}"))?;
    let before = seen.len();
    seen.retain(|s| s.pub_hex != key);
    if seen.len() == before {
        return Ok(());
    }
    lock.store_json(&seen).map_err(|e| e.to_string())
}

/// Phase 6b R5 (design A, step P6.28): forget where `peer` was seen when it
/// was at `ip` (another key answered there often enough to be Suspicious).
/// A sighting at another address stays, and so does the address saved in
/// the contact book (not this file's). Whether it was forgotten; a missing
/// file or entry is fine, and a file that could not be read is kept as it
/// is (an error).
pub fn forget_at(data_dir: &Path, peer: &[u8; 32], ip: IpAddr) -> Result<bool, String> {
    let key = hex::encode(peer);
    let ip = canonical_ip(ip);
    let at = |s: &Seen| s.pub_hex == key && ScopedIp::parse(&s.ip).is_some_and(|a| a.ip() == ip);
    // Lock-free first: nothing at that address, no lock (and no lock file).
    match read(data_dir) {
        Advisory::Missing | Advisory::CorruptPlain => return Ok(false),
        Advisory::Loaded(seen) if !seen.iter().any(at) => return Ok(false),
        Advisory::Loaded(_) | Advisory::Unreadable(_) => {}
    }
    let path = seen_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::LanSeen).map_err(|e| e.to_string())?;
    let mut seen = at_rest::load_json_for_write::<Vec<Seen>>(data_dir, &path, Kind::LanSeen)
        .map_err(|e| format!("{LAN_SEEN_FILE}: {e}"))?;
    let before = seen.len();
    seen.retain(|s| !at(s));
    if seen.len() == before {
        return Ok(false);
    }
    lock.store_json(&seen).map_err(|e| e.to_string())?;
    Ok(true)
}

/// When each contact (its device key, hex) last reached this node over an
/// authenticated link, whatever the age of the sighting. `None` when the
/// file could not be read (a sealed one whose key is not loaded, a changed
/// byte): then nothing is known either way. A missing file knows of no one.
pub fn sighting_times(data_dir: &Path) -> Option<HashMap<String, u64>> {
    let seen = match read(data_dir) {
        Advisory::Missing | Advisory::CorruptPlain => Vec::new(),
        Advisory::Loaded(seen) => seen,
        Advisory::Unreadable(_) => return None,
    };
    let mut times: HashMap<String, u64> = HashMap::new();
    for s in seen {
        let at = times.entry(s.pub_hex.to_ascii_lowercase()).or_default();
        *at = (*at).max(s.seen_at_ms);
    }
    Some(times)
}

/// Privacy pack PP.7: take the sightings older than [`MAX_AGE_MS`] off the
/// disk. No dial reads them ([`learned_lan_dial`], [`seen_ip`] and the
/// default-port guess skip them); before, they stayed until the next
/// sighting was written. Under [`LAN_SEEN_LOCK`]; lock-free first: none
/// that old, no lock and no write. How many went. A file that could not be
/// read is kept as it is (an error).
pub fn prune(data_dir: &Path, now_ms: u64) -> Result<usize, String> {
    let old = |s: &Seen| now_ms.saturating_sub(s.seen_at_ms) > MAX_AGE_MS;
    match read(data_dir) {
        Advisory::Missing | Advisory::CorruptPlain => return Ok(0),
        Advisory::Loaded(seen) if !seen.iter().any(old) => return Ok(0),
        Advisory::Unreadable(e) => return Err(format!("{LAN_SEEN_FILE}: {e}")),
        Advisory::Loaded(_) => {}
    }
    let path = seen_path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::LanSeen).map_err(|e| e.to_string())?;
    let mut seen = at_rest::load_json_for_write::<Vec<Seen>>(data_dir, &path, Kind::LanSeen)
        .map_err(|e| format!("{LAN_SEEN_FILE}: {e}"))?;
    let before = seen.len();
    seen.retain(|s| !old(s));
    let removed = before - seen.len();
    if removed > 0 {
        lock.store_json(&seen).map_err(|e| e.to_string())?;
    }
    Ok(removed)
}

/// Whether a saved `lan_dial` names its host by IP address. A name
/// (`bob-mac.local:7420`) already follows DHCP changes, so a learned address
/// may be tried but must never replace it.
pub fn saved_host_is_ip(dial: &str) -> bool {
    split_host_port(dial.trim()).is_some_and(|(host, _)| host.parse::<IpAddr>().is_ok())
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`, what a dual-stack listener reports) as IPv4.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// `host:port`, `[v6]:port` or `v4:port` → (host, port).
pub(crate) fn split_host_port(dial: &str) -> Option<(&str, u16)> {
    let (host, port) = if let Some(rest) = dial.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':')?)
    } else {
        dial.rsplit_once(':')?
    };
    if host.is_empty() || (host.contains(':') && !dial.starts_with('[')) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    (port != 0).then_some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60 * 1000;
    /// A verified contact: no locality rule.
    const PIN: bool = true;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// No address is this computer's own (the real check reads the
    /// interfaces).
    fn not_own(_: IpAddr) -> bool {
        false
    }

    /// E2: two friends behind one router are seen at its address; it is
    /// neither's (no learned dial, no default-port guess), while a sighting
    /// of one friend alone is. Sightings a day apart (a DHCP lease handed on)
    /// are no sharing. A dial that reached the friend at its sighting marks
    /// it; a sighting elsewhere clears that.
    #[test]
    fn an_address_two_contacts_are_seen_at_is_shared() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (a, b, c) = ([0xa1u8; 32], [0xb1u8; 32], [0xc1u8; 32]);
        let nat = ip("192.168.0.50");
        record_contact_seen(d, &a, nat, None, DAY).unwrap();
        assert!(usable_sighting(d, &a, DAY).is_some(), "alone there");
        record_contact_seen(d, &b, nat, None, DAY + 60_000).unwrap();
        for peer in [&a, &b] {
            assert_eq!(usable_sighting(d, peer, DAY + 60_000), None);
            assert_eq!(
                learned_lan_dial(d, peer, "192.168.1.20:17420", PIN, DAY + 60_000),
                None
            );
            assert_eq!(
                default_port_dial(d, peer, PIN, DAY + 60_000, None, not_own),
                None
            );
            assert!(shared_with_another(d, Some(peer), nat, DAY + 60_000));
        }
        assert!(shared_with_another(d, None, nat, DAY + 60_000));
        assert!(
            shared_with_another(d, Some(&c), nat, DAY + 60_000),
            "someone else's"
        );
        record_contact_seen(d, &c, ip("192.168.0.60"), None, DAY).unwrap();
        assert!(usable_sighting(d, &c, DAY).is_some());
        assert!(!shared_with_another(d, None, ip("192.168.0.60"), DAY));

        // A lease handed on: a's at .70 two days before b's.
        let dir2 = tempfile::tempdir().unwrap();
        let d2 = dir2.path();
        record_contact_seen(d2, &a, ip("192.168.0.70"), None, DAY).unwrap();
        record_contact_seen(d2, &b, ip("192.168.0.70"), None, 3 * DAY).unwrap();
        assert!(usable_sighting(d2, &b, 3 * DAY).is_some());
        assert!(!shared_with_another(
            d2,
            Some(&b),
            ip("192.168.0.70"),
            3 * DAY
        ));

        // Reached there, then seen elsewhere.
        assert!(!reached_at(d2, &b, ip("192.168.0.70"), 3 * DAY));
        assert!(!note_reached(d2, &b, ip("192.168.0.71"), None, 3 * DAY).unwrap());
        assert!(note_reached(d2, &b, ip("192.168.0.70"), None, 3 * DAY).unwrap());
        assert!(reached_at(d2, &b, ip("192.168.0.70"), 3 * DAY));
        assert!(!note_reached(d2, &b, ip("192.168.0.70"), None, 3 * DAY + 1).unwrap());
        record_contact_seen(d2, &b, ip("192.168.0.71"), None, 3 * DAY + 2).unwrap();
        assert!(!reached_at(d2, &b, ip("192.168.0.71"), 3 * DAY + 2));

        // Contacts on this computer each listen on their own port.
        let dir3 = tempfile::tempdir().unwrap();
        let d3 = dir3.path();
        for peer in [&a, &b] {
            record_contact_seen(d3, peer, ip("127.0.0.1"), None, DAY).unwrap();
        }
        assert!(usable_sighting(d3, &a, DAY).is_some());
        assert!(!shared_with_another(d3, Some(&a), ip("127.0.0.1"), DAY));
    }

    #[test]
    fn a_moved_contact_is_reached_at_its_new_ip_on_the_saved_port() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        let now = 10 * DAY;
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "192.168.1.20:7420", PIN, now),
            None
        );
        record_contact_seen(dir.path(), &bob, ip("192.168.1.37"), None, now).unwrap();
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "192.168.1.20:7420", PIN, now).as_deref(),
            Some("192.168.1.37:7420")
        );
        // Already the saved address: nothing new to try.
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "192.168.1.37:7420", PIN, now),
            None
        );
        // Another contact learns nothing from Bob's sighting.
        assert_eq!(
            learned_lan_dial(dir.path(), &[8u8; 32], "192.168.1.20:7420", PIN, now),
            None
        );
        // The bare sighting (route hints add their own port to it), until
        // it is too old.
        assert_eq!(seen_ip(dir.path(), &bob, now), Some(ip("192.168.1.37")));
        assert_eq!(seen_ip(dir.path(), &[8u8; 32], now), None);
        assert_eq!(
            seen_ip(dir.path(), &bob, now + MAX_AGE_MS),
            Some(ip("192.168.1.37"))
        );
        assert_eq!(seen_ip(dir.path(), &bob, now + MAX_AGE_MS + 1), None);
    }

    #[test]
    fn mapped_ipv6_ipv6_and_hostnames() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        record_contact_seen(dir.path(), &bob, ip("::ffff:10.0.0.9"), None, DAY).unwrap();
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "10.0.0.9:7420", PIN, DAY),
            None,
            "a v4-mapped sighting is the same v4 address"
        );
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "bob-mac.local:7420", PIN, DAY).as_deref(),
            Some("10.0.0.9:7420")
        );
        record_contact_seen(dir.path(), &bob, ip("fd00::5"), None, DAY).unwrap();
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "[fd00::4]:7420", PIN, DAY).as_deref(),
            Some("[fd00::5]:7420")
        );
        for bad in ["", "7420", "host:", "host:0", "host:99999", "fd00::4:7420"] {
            assert_eq!(
                learned_lan_dial(dir.path(), &bob, bad, PIN, DAY),
                None,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn sightings_expire_are_bounded_and_survive_a_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        record_contact_seen(dir.path(), &bob, ip("10.0.0.9"), None, DAY).unwrap();
        assert!(
            learned_lan_dial(dir.path(), &bob, "10.0.0.1:7420", PIN, DAY + MAX_AGE_MS).is_some()
        );
        assert!(
            learned_lan_dial(dir.path(), &bob, "10.0.0.1:7420", PIN, DAY + MAX_AGE_MS + 1)
                .is_none()
        );
        for i in 0..(MAX_ENTRIES as u64 + 10) {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&i.to_be_bytes());
            record_contact_seen(dir.path(), &peer, ip("10.0.0.2"), None, DAY + i).unwrap();
        }
        assert_eq!(load(dir.path()).len(), MAX_ENTRIES);
        std::fs::write(dir.path().join(LAN_SEEN_FILE), b"{not json").unwrap();
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "10.0.0.1:7420", PIN, DAY),
            None
        );
        record_contact_seen(dir.path(), &bob, ip("10.0.0.9"), None, DAY).unwrap();
        assert!(learned_lan_dial(dir.path(), &bob, "10.0.0.1:7420", PIN, DAY).is_some());
    }

    #[test]
    fn unspecified_and_multicast_sources_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        record_contact_seen(dir.path(), &bob, ip("0.0.0.0"), None, DAY).unwrap();
        record_contact_seen(dir.path(), &bob, ip("224.0.0.1"), None, DAY).unwrap();
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "10.0.0.1:7420", PIN, DAY),
            None
        );
    }

    #[test]
    fn an_unverified_contact_learns_only_local_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        record_contact_seen(dir.path(), &bob, ip("100.64.3.4"), None, DAY).unwrap();
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "192.168.1.20:7420", false, DAY),
            None,
            "CGNAT/Tailscale space is not the local network"
        );
        assert!(learned_lan_dial(dir.path(), &bob, "192.168.1.20:7420", true, DAY).is_some());
        record_contact_seen(dir.path(), &bob, ip("192.168.1.37"), None, DAY).unwrap();
        assert_eq!(
            learned_lan_dial(dir.path(), &bob, "192.168.1.20:7420", false, DAY).as_deref(),
            Some("192.168.1.37:7420")
        );
    }

    /// Phase 3 P3.4: an IPv6 link-local source is kept with the zone it came
    /// in on and dialled back with it; one without a zone never replaces a
    /// usable sighting.
    #[test]
    fn link_local_v6_sightings_keep_their_zone_and_forget_removes_one() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [7u8; 32];
        record_contact_seen(d, &bob, ip("192.168.1.37"), None, DAY).unwrap();
        assert!(!record_contact_seen(d, &bob, ip("fe80::1"), None, DAY + 1).unwrap());
        assert_eq!(
            learned_lan_dial(d, &bob, "192.168.1.20:7420", PIN, DAY + 1).as_deref(),
            Some("192.168.1.37:7420"),
            "a scope-less link-local source does not replace a usable sighting"
        );
        assert!(record_contact_seen(d, &bob, ip("fe80::1"), Some("en0"), DAY + 2).unwrap());
        assert_eq!(load(d)[0].ip, "fe80::1%en0", "inside the same ip string");
        let seen = seen_addr(d, &bob, DAY + 2).unwrap();
        assert_eq!((seen.ip(), seen.zone()), (ip("fe80::1"), Some("en0")));
        assert_eq!(seen_ip(d, &bob, DAY + 2), None, "an IpAddr has no zone");
        for pinned in [true, false] {
            assert_eq!(
                learned_lan_dial(d, &bob, "192.168.1.20:7420", pinned, DAY + 2).as_deref(),
                Some("[fe80::1%en0]:7420"),
                "link-local is the local network (pinned={pinned})"
            );
        }
        // The same zone within the hour is no news; another zone is.
        assert!(!record_contact_seen(d, &bob, ip("fe80::1"), Some("en0"), DAY + 3).unwrap());
        assert!(record_contact_seen(d, &bob, ip("fe80::1"), Some("en1"), DAY + 4).unwrap());
        forget(d, &bob).unwrap();
        assert_eq!(
            learned_lan_dial(d, &bob, "192.168.1.20:7420", PIN, DAY + 4),
            None
        );
        assert_eq!(seen_addr(d, &bob, DAY + 4), None);
        forget(d, &bob).unwrap();
    }

    /// A link-local IPv6 source without a usable zone is never recorded (not
    /// even a file is written); a zone on any other address is dropped.
    #[test]
    fn a_scope_less_link_local_sighting_is_never_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [7u8; 32];
        let too_long = "z".repeat(MAX_ZONE_LEN + 1);
        for zone in [
            None,
            Some(""),
            Some("0"),
            Some("en 0"),
            Some("en%0"),
            Some("en0]"),
            Some("en\u{7}0"),
            Some(too_long.as_str()),
        ] {
            assert!(
                !record_contact_seen(d, &bob, ip("fe80::1"), zone, DAY).unwrap(),
                "{zone:?}"
            );
            assert!(!d.join(LAN_SEEN_FILE).exists(), "{zone:?}");
        }
        for (n, (at, zone)) in [("192.168.1.37", "en0"), ("fd00::5", "en0"), ("::1", "lo0")]
            .into_iter()
            .enumerate()
        {
            assert!(record_contact_seen(d, &bob, ip(at), Some(zone), DAY + n as u64).unwrap());
            assert_eq!(load(d)[0].ip, at, "a zone only on a link-local address");
        }
        // The longest zone kept, and a number.
        let longest = "z".repeat(MAX_ZONE_LEN);
        for (n, zone) in [longest.as_str(), "4"].into_iter().enumerate() {
            let at = DAY + 10 + n as u64;
            assert!(record_contact_seen(d, &bob, ip("fe80::1"), Some(zone), at).unwrap());
            assert_eq!(load(d)[0].ip, format!("fe80::1%{zone}"));
        }
    }

    /// `[fe80::b%en0]:7420`: the saved port, or for a contact with no saved
    /// route the default LAN port (cutoff F7), on the zoned sighting; a
    /// numeric zone the same way, which std reads back as that scope id.
    #[test]
    fn learned_lan_dial_formats_a_scoped_link_local_address() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [7u8; 32];
        record_contact_seen(d, &bob, ip("fe80::b"), Some("en0"), DAY).unwrap();
        for pinned in [true, false] {
            assert_eq!(
                learned_lan_dial(d, &bob, "192.168.1.20:7420", pinned, DAY).as_deref(),
                Some("[fe80::b%en0]:7420")
            );
            assert_eq!(
                default_port_dial(d, &bob, pinned, DAY, None, not_own).as_deref(),
                Some("[fe80::b%en0]:7420")
            );
        }
        assert_eq!(
            default_port_dial(d, &bob, PIN, DAY, Some(47001), not_own).as_deref(),
            Some("[fe80::b%en0]:47001")
        );
        // Already the saved address (the same zone): nothing new to try.
        assert_eq!(
            learned_lan_dial(d, &bob, "[fe80::b%en0]:7420", PIN, DAY),
            None
        );
        assert_eq!(
            learned_lan_dial(d, &bob, "[fe80::b%en1]:7420", PIN, DAY).as_deref(),
            Some("[fe80::b%en0]:7420"),
            "another interface"
        );
        record_contact_seen(d, &bob, ip("fe80::b"), Some("4"), DAY + 1).unwrap();
        let dial = learned_lan_dial(d, &bob, "192.168.1.20:7531", PIN, DAY + 1).unwrap();
        assert_eq!(dial, "[fe80::b%4]:7531");
        assert!(matches!(
            dial.parse::<SocketAddr>(),
            Ok(SocketAddr::V6(v6)) if v6.scope_id() == 4 && v6.port() == 7531
        ));
        // A scope-less link-local entry (only ever in a file written by
        // hand) is never dialled.
        let raw = format!(
            r#"[{{"pub_hex":"{}","ip":"fe80::b","seen_at_ms":{DAY}}}]"#,
            hex::encode(bob)
        );
        std::fs::write(d.join(LAN_SEEN_FILE), raw).unwrap();
        assert_eq!(
            learned_lan_dial(d, &bob, "192.168.1.20:7420", PIN, DAY),
            None
        );
        assert_eq!(default_port_dial(d, &bob, PIN, DAY, None, not_own), None);
    }

    /// An older build reads each entry's `ip` with `parse::<IpAddr>()`: a
    /// zoned entry fails that and is skipped (never dialled without its
    /// zone), and the other entries of the same file still read.
    #[test]
    fn old_reader_skips_a_zoned_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        record_contact_seen(d, &[7u8; 32], ip("fe80::b"), Some("en0"), DAY).unwrap();
        record_contact_seen(d, &[8u8; 32], ip("fe80::c"), Some("4"), DAY).unwrap();
        record_contact_seen(d, &[9u8; 32], ip("192.168.1.37"), None, DAY).unwrap();
        // The older build's record type is this one (no field was added).
        let old: Vec<Seen> =
            serde_json::from_slice(&std::fs::read(d.join(LAN_SEEN_FILE)).unwrap()).unwrap();
        let usable: Vec<(String, IpAddr)> = old
            .iter()
            .filter_map(|s| Some((s.pub_hex.clone(), s.ip.parse::<IpAddr>().ok()?)))
            .collect();
        assert_eq!(old.len(), 3);
        assert_eq!(usable, [(hex::encode([9u8; 32]), ip("192.168.1.37"))]);
        // This build reads all three.
        for (key, want) in [(7u8, "fe80::b%en0"), (8, "fe80::c%4"), (9, "192.168.1.37")] {
            assert_eq!(
                seen_addr(d, &[key; 32], DAY)
                    .map(|a| a.to_string())
                    .as_deref(),
                Some(want)
            );
        }
    }

    /// Without a zone the file is byte for byte what older builds write: a
    /// zone given with any other address leaves no trace.
    #[test]
    fn a_file_without_zones_stays_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        record_contact_seen(d, &[7u8; 32], ip("192.168.1.37"), Some("en0"), DAY).unwrap();
        record_contact_seen(d, &[8u8; 32], ip("::ffff:10.0.0.9"), None, DAY + 1).unwrap();
        record_contact_seen(d, &[9u8; 32], ip("fd00::5"), Some("4"), DAY + 2).unwrap();
        let entry = |key: u8, ip: &str, at: u64| {
            format!(
                "  {{\n    \"pub_hex\": \"{}\",\n    \"ip\": \"{ip}\",\n    \"seen_at_ms\": {at}\n  }}",
                hex::encode([key; 32])
            )
        };
        let want = format!(
            "[\n{},\n{},\n{}\n]",
            entry(9, "fd00::5", DAY + 2),
            entry(8, "10.0.0.9", DAY + 1),
            entry(7, "192.168.1.37", DAY)
        );
        assert_eq!(
            std::fs::read_to_string(d.join(LAN_SEEN_FILE)).unwrap(),
            want
        );
    }

    /// The LAN beacon's join round (P3.10): who reached this node lately,
    /// newest first, at most `n`, none older than `max_age_ms` (nor than
    /// [`MAX_AGE_MS`]), whatever the address (a zoned one too).
    #[test]
    fn recent_lan_contacts_is_newest_first_bounded_and_ages_out() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let week = 7 * DAY;
        assert!(
            recent_lan_contacts(d, 8, week, 10 * DAY).is_empty(),
            "no file"
        );
        let key = |n: u8| [n; 32];
        record_contact_seen(d, &key(1), ip("192.168.1.31"), None, DAY).unwrap();
        record_contact_seen(d, &key(2), ip("fe80::2"), Some("en0"), 5 * DAY).unwrap();
        record_contact_seen(d, &key(3), ip("192.168.1.33"), None, 9 * DAY).unwrap();
        record_contact_seen(d, &key(4), ip("10.0.0.4"), None, 3 * DAY).unwrap();
        let now = 10 * DAY;
        assert_eq!(
            recent_lan_contacts(d, 8, week, now),
            [key(3), key(2), key(4)],
            "a week old exactly is still recent"
        );
        assert_eq!(recent_lan_contacts(d, 2, week, now), [key(3), key(2)]);
        assert!(recent_lan_contacts(d, 0, week, now).is_empty());
        assert_eq!(
            recent_lan_contacts(d, 8, 9 * DAY, now),
            [key(3), key(2), key(4), key(1)]
        );
        assert_eq!(recent_lan_contacts(d, 8, week, 12 * DAY), [key(3), key(2)]);
        assert_eq!(recent_lan_contacts(d, 8, week, 12 * DAY + 1), [key(3)]);
        // Never beyond MAX_AGE_MS, whatever is asked.
        assert_eq!(
            recent_lan_contacts(d, 8, u64::MAX, DAY + MAX_AGE_MS).len(),
            4
        );
        assert_eq!(
            recent_lan_contacts(d, 8, u64::MAX, DAY + MAX_AGE_MS + 1),
            [key(3), key(2), key(4)]
        );
        // A key that is not 32 bytes of hex is skipped; an unreadable file
        // knows of no one.
        let raw = serde_json::json!([
            {"pub_hex": "zz", "ip": "10.0.0.8", "seen_at_ms": now},
            {"pub_hex": "0707", "ip": "10.0.0.7", "seen_at_ms": now},
            {"pub_hex": hex::encode(key(9)), "ip": "10.0.0.9", "seen_at_ms": now},
        ]);
        std::fs::write(d.join(LAN_SEEN_FILE), raw.to_string()).unwrap();
        assert_eq!(recent_lan_contacts(d, 8, week, now), [key(9)]);
        std::fs::write(d.join(LAN_SEEN_FILE), b"{not json").unwrap();
        assert!(recent_lan_contacts(d, 8, week, now).is_empty());
    }

    /// Phase 3 P3.C3: a contact's sighting when it is young enough (a week
    /// old exactly still is), with the zone of a link-local one; none for
    /// an older one, a contact never seen, beyond MAX_AGE_MS whatever is
    /// asked, or an unreadable file.
    #[test]
    fn seen_within_is_the_sighting_when_young_enough() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let week = 7 * DAY;
        let key = |n: u8| [n; 32];
        assert_eq!(seen_within(d, &key(1), week, 10 * DAY), None, "no file");
        record_contact_seen(d, &key(1), ip("192.168.1.31"), None, DAY).unwrap();
        record_contact_seen(d, &key(2), ip("fe80::2"), Some("en0"), 3 * DAY).unwrap();
        let now = 10 * DAY;
        assert_eq!(seen_within(d, &key(1), week, now), None, "9 days old");
        assert_eq!(
            seen_within(d, &key(1), 9 * DAY, now),
            Some(ScopedIp::new(ip("192.168.1.31"), None))
        );
        let ll = seen_within(d, &key(2), week, now).unwrap();
        assert_eq!((ll.ip(), ll.zone()), (ip("fe80::2"), Some("en0")));
        assert_eq!(seen_within(d, &key(3), week, now), None);
        assert_eq!(
            seen_within(d, &key(1), u64::MAX, DAY + MAX_AGE_MS + 1),
            None
        );
        std::fs::write(d.join(LAN_SEEN_FILE), b"{not json").unwrap();
        assert_eq!(seen_within(d, &key(2), week, now), None);
    }

    /// G2: the listener forgets a remembered remote route only when the
    /// contact shows up from a new address.
    #[test]
    fn record_contact_seen_says_when_the_address_is_new() {
        let dir = tempfile::tempdir().unwrap();
        let bob = [7u8; 32];
        let hour = 60 * 60 * 1000;
        let seen =
            |at: &str, now: u64| record_contact_seen(dir.path(), &bob, ip(at), None, now).unwrap();
        assert!(seen("192.168.1.37", DAY), "first sighting");
        assert!(!seen("192.168.1.37", DAY + 1), "the same IP");
        assert!(
            !seen("::ffff:192.168.1.37", DAY + 2),
            "the same IP, v4-mapped"
        );
        assert!(seen("192.168.1.38", DAY + 3), "a changed IP");
        assert!(
            !seen("192.168.1.38", DAY + 3 + 2 * hour),
            "rewritten, not moved"
        );
        assert_eq!(
            load(dir.path())[0].seen_at_ms,
            DAY + 3 + 2 * hour,
            "it was rewritten"
        );
        for skipped in ["0.0.0.0", "224.0.0.1", "fe80::1"] {
            assert!(!seen(skipped, DAY + 4 + 2 * hour), "{skipped}");
        }
        assert!(
            seen("192.168.1.38", DAY + 4 + 2 * hour + MAX_AGE_MS),
            "the old one expired"
        );
    }

    /// F7: a contact with no LAN route at all gets its sighting on the
    /// default LAN port; one with a saved route keeps learning only the
    /// saved port ([`learned_lan_dial`]), and the outbox adds the guess only
    /// when no LAN route is left after the others.
    #[test]
    fn default_port_route_only_without_a_saved_route() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [7u8; 32];
        assert_eq!(default_port_dial(d, &bob, PIN, DAY, None, not_own), None);
        record_contact_seen(d, &bob, ip("::ffff:192.168.1.37"), None, DAY).unwrap();
        assert_eq!(
            default_port_dial(d, &bob, PIN, DAY, None, not_own).as_deref(),
            Some("192.168.1.37:7420")
        );
        assert_eq!(
            default_port_dial(d, &bob, PIN, DAY, Some(47001), not_own).as_deref(),
            Some("192.168.1.37:47001"),
            "the lab port replaces 7420"
        );
        assert_eq!(
            default_port_dial(d, &bob, PIN, DAY + MAX_AGE_MS + 1, None, not_own),
            None,
            "too old"
        );
        assert_eq!(
            default_port_dial(d, &[8u8; 32], PIN, DAY, None, not_own),
            None
        );
        // A saved route keeps its own port.
        assert_eq!(
            learned_lan_dial(d, &bob, "192.168.1.20:7531", PIN, DAY).as_deref(),
            Some("192.168.1.37:7531")
        );
        use crate::outbox::{
            with_default_port_sighting, ContactRoutes, OutboxCarrier, OutboxRoute,
        };
        crate::lan_noise_pin::record(d, &crate::lan_noise_pin::test_key(), &bob, &[0x51; 32])
            .unwrap();
        let lan = |dial: &str| OutboxRoute {
            carrier: OutboxCarrier::Lan,
            dial: dial.into(),
        };
        let saved = ContactRoutes {
            routes: vec![lan("192.168.1.20:7531")],
            pinned: PIN,
            ..ContactRoutes::default()
        };
        assert_eq!(
            with_default_port_sighting(d, &bob, saved.clone(), |_| true, true),
            saved
        );
        let none = ContactRoutes {
            pinned: PIN,
            ..ContactRoutes::default()
        };
        // The planner reads the clock: a sighting from now.
        let now = crate::clock::now_ms();
        record_contact_seen(d, &bob, ip("192.168.1.37"), None, now).unwrap();
        let guess = learned_lan_dial_default_port(d, &bob, PIN, now).unwrap();
        assert!(guess.starts_with("192.168.1.37:"), "{guess}");
        assert_eq!(
            with_default_port_sighting(d, &bob, none, |_| true, true).routes,
            [lan(&guess)]
        );
    }

    /// An unverified contact's guess is on the local network only, as its
    /// learned and saved addresses are.
    #[test]
    fn unverified_needs_a_local_ip() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [7u8; 32];
        record_contact_seen(d, &bob, ip("100.64.3.4"), None, DAY).unwrap();
        assert_eq!(default_port_dial(d, &bob, false, DAY, None, not_own), None);
        assert_eq!(
            default_port_dial(d, &bob, true, DAY, None, not_own).as_deref(),
            Some("100.64.3.4:7420")
        );
        record_contact_seen(d, &bob, ip("198.51.100.4"), None, DAY + 1).unwrap();
        assert_eq!(
            default_port_dial(d, &bob, false, DAY + 1, None, not_own),
            None
        );
        for local in ["10.1.2.3", "172.20.10.2", "169.254.7.9", "fd00::5"] {
            record_contact_seen(d, &bob, ip(local), None, DAY + 2).unwrap();
            let want = SocketAddr::new(ip(local), 7420).to_string();
            assert_eq!(
                default_port_dial(d, &bob, false, DAY + 2, None, not_own),
                Some(want),
                "{local}"
            );
        }
    }

    /// A loopback sighting (a contact on this very computer) is guessed only
    /// on the lab port: 127.0.0.1:7420 would be this computer's own node.
    #[test]
    fn a_loopback_sighting_needs_the_lab_port() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [7u8; 32];
        for (n, lo) in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"]
            .into_iter()
            .enumerate()
        {
            let at = DAY + n as u64;
            record_contact_seen(d, &bob, ip(lo), None, at).unwrap();
            for pinned in [true, false] {
                assert_eq!(
                    default_port_dial(d, &bob, pinned, at, None, not_own),
                    None,
                    "{lo}"
                );
                let dial = default_port_dial(d, &bob, pinned, at, Some(47001), not_own).unwrap();
                assert!(dial.ends_with(":47001"), "{lo}: {dial}");
                assert!(!dial.contains("7420"), "{dial}");
            }
        }
        // The same file never holds a link-local IPv6 sighting without its
        // zone; were one there, it would not be guessed either.
        let raw = format!(
            r#"[{{"pub_hex":"{}","ip":"fe80::1","seen_at_ms":{DAY}}}]"#,
            hex::encode(bob)
        );
        std::fs::write(d.join(LAN_SEEN_FILE), raw).unwrap();
        assert_eq!(seen_ip(d, &bob, DAY), Some(ip("fe80::1")));
        assert_eq!(
            default_port_dial(d, &bob, PIN, DAY, Some(47001), not_own),
            None
        );
    }

    /// A sighting at one of this computer's own addresses (a contact on
    /// this computer that reached the listener through its LAN address, which
    /// the listener sees as the source) is treated like loopback: guessed
    /// only on the lab port, else <own IP>:7420 would dial this computer's
    /// own node.
    #[test]
    fn a_sighting_at_an_own_address_needs_the_lab_port() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [7u8; 32];
        let own = |ip: IpAddr| ip == "192.168.0.16".parse::<IpAddr>().unwrap();
        for (n, seen) in ["192.168.0.16", "::ffff:192.168.0.16"]
            .into_iter()
            .enumerate()
        {
            let at = DAY + n as u64;
            record_contact_seen(d, &bob, ip(seen), None, at).unwrap();
            for pinned in [true, false] {
                assert_eq!(
                    default_port_dial(d, &bob, pinned, at, None, own),
                    None,
                    "{seen}"
                );
                assert_eq!(
                    default_port_dial(d, &bob, pinned, at, Some(47001), own).as_deref(),
                    Some("192.168.0.16:47001"),
                    "{seen}"
                );
            }
        }
        // Another computer on the same network is guessed as before.
        record_contact_seen(d, &bob, ip("192.168.1.44"), None, DAY + 5).unwrap();
        assert_eq!(
            default_port_dial(d, &bob, PIN, DAY + 5, None, own).as_deref(),
            Some("192.168.1.44:7420")
        );
    }

    /// The same through the real interface list: a sighting at this
    /// computer's own LAN address is never guessed on 7420.
    #[test]
    fn this_computers_own_address_is_never_guessed_on_7420() {
        let Ok(all) = crate::netifs::read() else {
            return;
        };
        let Some(own) = all.iter().map(|a| a.ip).find(|ip| {
            !ip.is_loopback()
                && crate::outbox::is_local_network_ip(*ip)
                && !matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80)
        }) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let bob = [7u8; 32];
        let now = crate::clock::now_ms();
        record_contact_seen(d, &bob, own, None, now).unwrap();
        let guess = learned_lan_dial_default_port(d, &bob, PIN, now);
        match crate::lan_gate::lab_default_lan_port() {
            Some(port) => assert_eq!(guess, Some(SocketAddr::new(own, port).to_string())),
            None => assert_eq!(guess, None, "{own} is this computer's own address"),
        }
    }

    /// The child processes of
    /// [`lan_seen_cross_process_writers_do_not_lose_updates`]: `<dir>|<n>`.
    const WRITER_CHILD_ENV: &str = "RAVEN_PP6_LAN_SEEN_WRITER";
    const PER_WRITER: u8 = 24;

    /// Privacy pack PP.6: writers take a lock across processes (before,
    /// only a mutex inside one process), so separate processes (the
    /// listener in raven-node, `raven contact remove`) that record at once
    /// lose no sighting. Four copies of this test binary each record their
    /// own contacts into one profile at the same time.
    #[test]
    fn lan_seen_cross_process_writers_do_not_lose_updates() {
        let dir = tempfile::tempdir().unwrap();
        let module = module_path!();
        let module = module.split_once("::").map_or(module, |(_, rest)| rest);
        let writers: Vec<_> = (0..4u8)
            .map(|n| {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        &format!("{module}::lan_seen_writer_child"),
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(WRITER_CHILD_ENV, format!("{}|{n}", dir.path().display()))
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for writer in writers {
            let out = writer.wait_with_output().unwrap();
            assert!(out.status.success(), "{out:?}");
            // `--exact` on a renamed helper would run nothing and pass.
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("running 1 test"),
                "{out:?}"
            );
        }
        let seen = load(dir.path());
        assert_eq!(seen.len(), 4 * usize::from(PER_WRITER), "a lost update");
        for n in 0..4u8 {
            for i in 0..PER_WRITER {
                let mut peer = [0u8; 32];
                peer[0] = n;
                peer[1] = i;
                assert_eq!(
                    seen_ip(dir.path(), &peer, DAY + 10),
                    Some(ip("10.0.0.2")),
                    "{n} {i}"
                );
            }
        }
    }

    #[test]
    fn lan_seen_writer_child() {
        let Ok(arg) = std::env::var(WRITER_CHILD_ENV) else {
            return;
        };
        let (dir, n) = arg.rsplit_once('|').unwrap();
        let n: u8 = n.parse().unwrap();
        for i in 0..PER_WRITER {
            let mut peer = [0u8; 32];
            peer[0] = n;
            peer[1] = i;
            assert!(record_contact_seen(Path::new(dir), &peer, ip("10.0.0.2"), None, DAY).unwrap());
        }
    }

    /// The cross-process lock is the one `at_rest::FILES` names, and a read
    /// takes none (nor makes its file).
    #[test]
    fn writers_take_the_registered_lock() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            crate::at_rest::rule_for(LAN_SEEN_FILE).and_then(|r| r.lock),
            Some(LAN_SEEN_LOCK)
        );
        assert_eq!(seen_ip(dir.path(), &[7u8; 32], DAY), None);
        forget(dir.path(), &[7u8; 32]).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        record_contact_seen(dir.path(), &[7u8; 32], ip("10.0.0.9"), None, DAY).unwrap();
        assert!(dir.path().join(LAN_SEEN_LOCK).exists());
    }

    /// Phase 6b R5 (step P6.28): an impostor at the address a contact was
    /// seen at forgets that sighting only. The saved address is the contact
    /// book's and still planned; a sighting at another address, another
    /// contact's and a missing file are left alone (nothing is written).
    #[test]
    fn an_impostor_at_the_seen_address_forgets_only_that_sighting() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let (bob, carol) = ([7u8; 32], [8u8; 32]);
        let now = 10 * DAY;
        assert_eq!(forget_at(d, &bob, ip("192.168.1.37")), Ok(false));
        assert_eq!(std::fs::read_dir(d).unwrap().count(), 0);
        record_contact_seen(d, &bob, ip("192.168.1.37"), None, now).unwrap();
        record_contact_seen(d, &carol, ip("192.168.1.37"), None, now).unwrap();
        let held = std::fs::read(d.join(LAN_SEEN_FILE)).unwrap();
        assert_eq!(forget_at(d, &bob, ip("192.168.1.38")), Ok(false));
        assert_eq!(std::fs::read(d.join(LAN_SEEN_FILE)).unwrap(), held);
        assert_eq!(forget_at(d, &bob, ip("::ffff:192.168.1.37")), Ok(true));
        assert_eq!(seen_ip(d, &bob, now), None);
        assert_eq!(
            learned_lan_dial(d, &bob, "192.168.1.20:7420", PIN, now),
            None,
            "only the saved address is left to plan"
        );
        assert_eq!(seen_ip(d, &carol, now), Some(ip("192.168.1.37")));
    }

    #[test]
    fn only_ip_literal_dials_count_as_replaceable() {
        assert!(saved_host_is_ip("192.168.1.20:7420"));
        assert!(saved_host_is_ip("[fd00::4]:7420"));
        assert!(!saved_host_is_ip("bob-mac.local:7420"));
        assert!(!saved_host_is_ip("garbage"));
    }
}
