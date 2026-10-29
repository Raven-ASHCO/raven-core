//! Home custodians (Phase 3 P3.18, `protocol/RAVEN_FRIEND_CUSTODY_V1.md`
//! §2, RAVEN_ROUTE_HINTS_V1 §12): the at most [`MAX_HOME`] verified friends
//! this node collects its own mail from.
//!
//! - **Manual wins.** `raven custody home @a [@b]` (the policy's
//!   [`crate::node_policy::NodePolicy::custody_home`]) is the list, as long
//!   as those friends are still usable.
//! - **Otherwise automatic**, among verified friends whose live RRH1 carries
//!   CUSTODY_OFFER ([`crate::learned_routes::learned_custody_all`]): picks
//!   are sticky while their owner still offers; a pick that is not
//!   REACHABLE yields to an unpicked REACHABLE offer; free slots go to WAN
//!   offers first (only while WAN custody is live), then REACHABLE ones,
//!   then the most recently heard, then the lower key ([`select`]).
//! - **Consent.** Nothing is picked unless the user said yes to friend
//!   mailboxes (`raven custody use on`,
//!   [`crate::node_policy::NodePolicy::custody_use`]).
//! - **Drain.** A pick that is dropped (no longer offered, replaced, or
//!   consent turned off) is still fetched from for [`DRAIN_MS`]
//!   ([`fetch_from`]): a sender that never heard of the change may still
//!   leave mail there for as long as this node's last announcement lives
//!   (the RRH1 TTL it sends), and every object left there has expired by
//!   then. A custodian that is no longer a verified, unblocked contact is
//!   dropped at once, with no drain ([`forget`] when it is removed or
//!   blocked).
//!
//! The choice is kept in [`CUSTODY_HOME_FILE`], written by raven-node
//! ([`refresh`]) and, to forget a removed or blocked contact, by ash
//! ([`forget`]), under the same data-dir lock as `learned_routes.json`. It
//! names friends, so it is RMS1 kind 33 in a sealed profile (the at-rest
//! rule, [`crate::at_rest`]) and today's JSON (0600) otherwise; readers
//! accept both. A corrupt or unreadable file reads as empty; its writer
//! never writes over a sealed file it could not open. No gate here: the
//! callers check [`crate::custody_gate::custody_hints_live`].

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, Kind};
use crate::custody_gate::{CustodyGates, OFFER_REACHABLE, OFFER_WAN};
use crate::paths::DataDirLock;

/// The file in the data dir.
pub const CUSTODY_HOME_FILE: &str = "custody_home.json";
/// Home custodians at most (manual or automatic).
pub const MAX_HOME: usize = 2;
/// How long a contact may still act on this node's last RRH1 announcement
/// after it was sent: the TTL this node announces (raven-node's hints
/// snapshot sends [`crate::route_hints::RRH1_DEFAULT_TTL_S`]).
const ANNOUNCED_TTL_MS: u64 = crate::route_hints::RRH1_DEFAULT_TTL_S as u64 * 1000;
/// A dropped home custodian is still fetched from this long (about 97 h): a
/// sender that never heard the newer announcement may deposit there until
/// the old one expires ([`ANNOUNCED_TTL_MS`]), and what it left lives up to
/// the custody validity limit; plus an hour.
pub const DRAIN_MS: u64 =
    ANNOUNCED_TTL_MS + crate::carrier_admission::MAX_CUSTODY_VALIDITY_MS + 3_600_000;
// A longer announced TTL must lengthen the drain with it.
const _: () =
    assert!(DRAIN_MS >= ANNOUNCED_TTL_MS + crate::carrier_admission::MAX_CUSTODY_VALIDITY_MS);
/// Dropped picks still drained at most: enough that every dropped pick
/// drains until its end. The list holds usable contacts only, one entry
/// each (a friend dropped again only moves its end), so it is never longer
/// than the different friends dropped within one drain (about 4 days).
/// More than this many is not a realistic churn; the cap bounds the fetch
/// work, and past it the drain that ends first goes. (8, the old cap, could
/// be reached within one drain: the Phase 3 re-verify's D-1 follow-on.)
pub const MAX_RETIRED: usize = 64;
/// A busy lock skips this pass (raven-node refreshes again later).
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// One custody offer as [`select`] weighs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfferView {
    /// The offering contact's device key.
    pub custodian: [u8; 32],
    /// Its CUSTODY_OFFER flags ([`OFFER_WAN`], [`OFFER_REACHABLE`]).
    pub flags: u8,
    /// When the snapshot that carries it was stored.
    pub heard_ms: u64,
}

impl OfferView {
    fn reachable(&self) -> bool {
        self.flags & OFFER_REACHABLE != 0
    }
}

/// The home custodians (pure). Nothing without `consent`. A non-empty
/// `manual` list wins (at most [`MAX_HOME`], in its order). Otherwise:
/// keep the `current` picks that still offer; a pick without REACHABLE
/// yields to an unpicked REACHABLE offer; fill free slots by (WAN when
/// `wan_live`, REACHABLE, newest heard, lower key). At most [`MAX_HOME`].
/// The caller passes only usable custodians (verified, unblocked contacts).
pub fn select(
    manual: &[[u8; 32]],
    consent: bool,
    offers: &[OfferView],
    current: &[[u8; 32]],
    wan_live: bool,
) -> Vec<[u8; 32]> {
    if !consent {
        return Vec::new();
    }
    if !manual.is_empty() {
        return distinct(manual.iter().copied());
    }
    // One offer per custodian: its newest.
    let mut newest: Vec<OfferView> = offers.to_vec();
    newest.sort_by_key(|o| Reverse(o.heard_ms));
    let mut seen = HashSet::new();
    newest.retain(|o| seen.insert(o.custodian));
    let mut ranked = newest;
    ranked.sort_by_key(|o| {
        (
            Reverse(wan_live && o.flags & OFFER_WAN != 0),
            Reverse(o.reachable()),
            Reverse(o.heard_ms),
            o.custodian,
        )
    });
    let offer_of = |c: &[u8; 32]| ranked.iter().find(|o| o.custodian == *c);
    // Sticky while offering.
    let mut picks = distinct(current.iter().copied().filter(|c| offer_of(c).is_some()));
    // A pick that is not reachable yields to the best unpicked reachable offer.
    for i in 0..picks.len() {
        if offer_of(&picks[i]).is_some_and(OfferView::reachable) {
            continue;
        }
        if let Some(better) = ranked
            .iter()
            .find(|o| o.reachable() && !picks.contains(&o.custodian))
        {
            picks[i] = better.custodian;
        }
    }
    for o in &ranked {
        if picks.len() == MAX_HOME {
            break;
        }
        if !picks.contains(&o.custodian) {
            picks.push(o.custodian);
        }
    }
    picks
}

/// The first [`MAX_HOME`] distinct keys, in order.
fn distinct(keys: impl Iterator<Item = [u8; 32]>) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    for key in keys {
        if out.len() == MAX_HOME {
            break;
        }
        if !out.contains(&key) {
            out.push(key);
        }
    }
    out
}

/// What [`CUSTODY_HOME_FILE`] holds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct HomeFile {
    /// The home custodians (device keys in hex), at most [`MAX_HOME`].
    #[serde(default)]
    picked: Vec<String>,
    /// Dropped picks still fetched from: (device key hex, until ms), at most
    /// [`MAX_RETIRED`].
    #[serde(default)]
    retired: Vec<(String, u64)>,
}

fn parse_key(hex_key: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut out).ok()?;
    Some(out)
}

fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(CUSTODY_HOME_FILE)
}

/// The saved choice; a missing, corrupt or unreadable file is empty.
fn load(data_dir: &Path) -> HomeFile {
    at_rest::load_json_advisory(data_dir, &path(data_dir), Kind::CustodyHome)
        .into_loaded()
        .unwrap_or_default()
}

/// The current, unblocked, verified contacts other than `local`: who may be
/// a home custodian. Several rows for one key (an old book) are verified
/// only if all are. An unreadable contact book or block list is an error.
fn usable_contacts(data_dir: &Path, local: &[u8; 32]) -> Result<HashSet<[u8; 32]>, String> {
    #[derive(Deserialize)]
    struct Row {
        #[serde(default)]
        pub_hex: String,
        #[serde(default)]
        pinned: bool,
    }
    let rows: Vec<Row> = crate::contact_book::read_rows(data_dir)
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let blocks = crate::chat_history::BlockList::load_checked(data_dir)?;
    let mut pinned: HashMap<[u8; 32], bool> = HashMap::new();
    for row in &rows {
        if let Some(key) = parse_key(&row.pub_hex) {
            *pinned.entry(key).or_insert(true) &= row.pinned;
        }
    }
    Ok(pinned
        .into_iter()
        .filter(|(key, pinned)| *pinned && key != local && !blocks.is_blocked(&hex::encode(key)))
        .map(|(key, _)| key)
        .collect())
}

/// The policy's manual list: usable keys only, at most [`MAX_HOME`].
fn manual_home(
    policy: &crate::node_policy::NodePolicy,
    usable: &HashSet<[u8; 32]>,
) -> Vec<[u8; 32]> {
    distinct(
        policy
            .custody_home
            .iter()
            .filter_map(|h| parse_key(h))
            .filter(|k| usable.contains(k)),
    )
}

/// raven-node only: choose again from the policy and the offers in
/// `learned_routes.json` (usable contacts only), retire the dropped picks
/// for [`DRAIN_MS`] (each until its drain ends, at most [`MAX_RETIRED`]; an
/// unusable one goes at once)
/// and write [`CUSTODY_HOME_FILE`] when anything in it changed. Returns
/// the home custodians and whether they changed. An unreadable policy,
/// contact book or block list, or a sealed file this process cannot open,
/// is an error and nothing is written.
pub fn refresh(
    data_dir: &Path,
    local: &[u8; 32],
    now_ms: u64,
) -> Result<(Vec<[u8; 32]>, bool), String> {
    let policy = crate::node_policy::try_load_policy(data_dir).map_err(|e| e.to_string())?;
    let usable = usable_contacts(data_dir, local)?;
    let consent = policy.custody_use == Some(true);
    let manual = manual_home(&policy, &usable);
    let offers: Vec<OfferView> = crate::learned_routes::learned_custody_all(data_dir, now_ms)
        .into_iter()
        .filter(|(custodian, _)| usable.contains(custodian))
        .filter_map(|(custodian, learned)| {
            Some(OfferView {
                custodian,
                flags: learned.offer?,
                heard_ms: learned.heard_ms,
            })
        })
        .collect();
    let wan_live = CustodyGates::current().wan && crate::p2p_live_enabled();

    let _lock = DataDirLock::acquire_within(
        data_dir,
        crate::learned_routes::LEARNED_ROUTES_LOCK,
        LOCK_WAIT,
    )?;
    let file = path(data_dir);
    let old: HomeFile = at_rest::load_json_for_write(data_dir, &file, Kind::CustodyHome)
        .map_err(|e| format!("{CUSTODY_HOME_FILE}: {e}"))?;
    let saved: Vec<[u8; 32]> = old.picked.iter().filter_map(|h| parse_key(h)).collect();
    // An unusable pick goes at once, with no drain.
    let current: Vec<[u8; 32]> = saved
        .iter()
        .copied()
        .filter(|c| usable.contains(c))
        .collect();
    let home = select(&manual, consent, &offers, &current, wan_live);

    let mut retired: Vec<([u8; 32], u64)> = Vec::new();
    let drain_end = now_ms.saturating_add(DRAIN_MS);
    let mut retire = |key: [u8; 32], until: u64| {
        // Never past a drain that starts now (a clock that went back).
        let until = until.min(drain_end);
        if home.contains(&key) || !usable.contains(&key) || until <= now_ms {
            return;
        }
        match retired.iter_mut().find(|(k, _)| *k == key) {
            Some(held) => held.1 = held.1.max(until),
            None => retired.push((key, until)),
        }
    };
    for (key, until) in &old.retired {
        if let Some(key) = parse_key(key) {
            retire(key, *until);
        }
    }
    for key in &current {
        retire(*key, drain_end);
    }
    retired.sort_by_key(|(key, until)| (Reverse(*until), *key));
    retired.truncate(MAX_RETIRED);

    let new = HomeFile {
        picked: home.iter().map(hex::encode).collect(),
        retired: retired
            .iter()
            .map(|(key, until)| (hex::encode(key), *until))
            .collect(),
    };
    if new != old {
        let raw = serde_json::to_vec_pretty(&new).map_err(|e| e.to_string())?;
        // The caller holds the learned routes' lock: the file's writer lock.
        at_rest::write_held(data_dir, &file, Kind::CustodyHome, &raw)
            .map_err(|e| format!("{CUSTODY_HOME_FILE}: {e}"))?;
    }
    Ok((home.clone(), saved != home))
}

/// The home custodians as saved (read-only: `raven status`, the hints
/// snapshot): none without consent; the manual list, else the saved
/// automatic picks; usable contacts only. An unreadable policy is no
/// consent; an unreadable contact book or block list is nobody.
pub fn home(data_dir: &Path, local: &[u8; 32], _now_ms: u64) -> Vec<[u8; 32]> {
    let policy = crate::node_policy::load_policy(data_dir);
    if policy.custody_use != Some(true) {
        return Vec::new();
    }
    let Ok(usable) = usable_contacts(data_dir, local) else {
        return Vec::new();
    };
    home_from(&policy, &usable, &load(data_dir))
}

fn home_from(
    policy: &crate::node_policy::NodePolicy,
    usable: &HashSet<[u8; 32]>,
    file: &HomeFile,
) -> Vec<[u8; 32]> {
    let manual = manual_home(policy, usable);
    if !manual.is_empty() {
        return manual;
    }
    distinct(
        file.picked
            .iter()
            .filter_map(|h| parse_key(h))
            .filter(|k| usable.contains(k)),
    )
}

/// Who this node fetches its own mail from: [`home`], then the retired
/// picks still draining (until [`DRAIN_MS`] after they were dropped, also
/// after consent was turned off), usable contacts only.
pub fn fetch_from(data_dir: &Path, local: &[u8; 32], now_ms: u64) -> Vec<[u8; 32]> {
    let Ok(usable) = usable_contacts(data_dir, local) else {
        return Vec::new();
    };
    let file = load(data_dir);
    let policy = crate::node_policy::load_policy(data_dir);
    let mut out = if policy.custody_use == Some(true) {
        home_from(&policy, &usable, &file)
    } else {
        Vec::new()
    };
    let drain_end = now_ms.saturating_add(DRAIN_MS);
    for (key, until) in file.retired.iter().take(MAX_RETIRED) {
        let Some(key) = parse_key(key) else {
            continue;
        };
        let draining = *until > now_ms && *until <= drain_end;
        if draining && usable.contains(&key) && !out.contains(&key) {
            out.push(key);
        }
    }
    out
}

/// ash, when a contact is removed or blocked: `key` is no longer a home
/// custodian, picked or draining, so a contact added and verified again
/// later is not silently picked back from this file. Lock-free first
/// (nothing to forget: no lock, no write); then under the learned routes'
/// lock, the file's writer lock. A file that could not be read is kept as
/// it is (an error).
pub fn forget(data_dir: &Path, key: &[u8; 32]) -> Result<(), String> {
    let file = path(data_dir);
    let names = |f: &HomeFile| {
        f.picked.iter().any(|h| parse_key(h) == Some(*key))
            || f.retired.iter().any(|(h, _)| parse_key(h) == Some(*key))
    };
    match at_rest::load_json_advisory::<HomeFile>(data_dir, &file, Kind::CustodyHome) {
        at_rest::Advisory::Missing | at_rest::Advisory::CorruptPlain => return Ok(()),
        at_rest::Advisory::Loaded(f) if !names(&f) => return Ok(()),
        at_rest::Advisory::Loaded(_) | at_rest::Advisory::Unreadable(_) => {}
    }
    let _lock = DataDirLock::acquire(data_dir, crate::learned_routes::LEARNED_ROUTES_LOCK)?;
    let mut held: HomeFile = at_rest::load_json_for_write(data_dir, &file, Kind::CustodyHome)
        .map_err(|e| format!("{CUSTODY_HOME_FILE}: {e}"))?;
    if !names(&held) {
        return Ok(());
    }
    held.picked.retain(|h| parse_key(h) != Some(*key));
    held.retired.retain(|(h, _)| parse_key(h) != Some(*key));
    let raw = serde_json::to_vec_pretty(&held).map_err(|e| e.to_string())?;
    // Held: the learned routes' lock is the file's writer lock.
    at_rest::write_held(data_dir, &file, Kind::CustodyHome, &raw)
        .map_err(|e| format!("{CUSTODY_HOME_FILE}: {e}"))
}

#[cfg(test)]
mod tests;
