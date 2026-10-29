//! Relay allow-list and status files (P3, transports design §3.5).
//!
//! A dedicated relay (`raven-node relay`) accepts reservations only from the
//! PeerIds in `relay_allow.json` in its data dir:
//! on by default, managed with `raven relay allow|deny`. A missing file admits
//! nobody; an unreadable or invalid one admits nobody either (fail closed),
//! and the relay says so in its counts. `relay_status.json` is what a relay
//! reports about itself for `raven relay status|card`: its own PeerId, its
//! listen addresses, the addresses it names for itself (`advertised`), its
//! UPnP state and counts only, never a client's PeerId or address.
//!
//! The folder belongs to the account the relay runs as: `allow` and `deny`
//! refuse a folder another account owns (an installed relay's, Unix), since
//! a file written there by someone else could be unreadable by the relay,
//! which would then admit nobody.
//!
//! A profile's own `relay_allow.json` also holds a deny list (`deny`) for
//! the friend relay (any-network plan C6), which admits the profile's
//! verified contacts by itself: a contact turned away goes on `deny`, so
//! that derived set cannot re-add them. A dedicated relay admits only
//! `peers` and never uses `deny`. The file stays version 1. An older
//! `raven relay allow|deny` keeps only `version` and `peers` when it rewrites
//! the file, so it drops `deny`, and the friend relay then admits those
//! contacts again until they are denied again.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ipc::RelayCounts;
use crate::p2p_route::normalize_peer_id;

pub const RELAY_ALLOW_FILE: &str = "relay_allow.json";
pub const RELAY_STATUS_FILE: &str = "relay_status.json";
/// The libp2p key of a dedicated relay (`raven-node relay`): a 32-byte
/// Ed25519 seed, owner-only. A relay holds no Raven identity at all.
pub const RELAY_KEY_FILE: &str = "relay_key.ed25519";
/// The allow-list's writer lock (the one `at_rest::FILES` names).
pub(crate) const RELAY_ALLOW_LOCK: &str = ".relay_allow.lock.sqlite";
/// Held by a running `raven-node relay` for its whole life: one relay per
/// folder, and `raven relay status` tells a stopped relay by it.
pub const RELAY_LOCK_FILE: &str = ".relay.lock.sqlite";
/// A running relay rewrites `relay_status.json` at least this often.
pub const RELAY_STATUS_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(10);
/// Older than this, the status file is a stopped (or stuck) relay's.
pub const RELAY_STATUS_STALE_MS: u64 = 35_000;
const ALLOW_VERSION: u32 = 1;
/// A relay schedule's entry for epoch `e` admits until this long after `e`
/// ends (peer rotation spec §7): a friend whose clock runs late still
/// reserves, and a postponed rotation keeps the previous PeerId.
pub const SCHEDULE_GRACE_MS: u64 = 7 * 86_400_000;
/// PeerIds one allow-list holds at most (the hard max of reservations).
pub const MAX_ALLOW_ENTRIES: usize = 1024;
const MAX_LABEL_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAllowEntry {
    pub peer_id: String,
    /// The operator's own note (a petname), never shown to the peer.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// A profile's friend relay only: the contact (its device key, lowercase
    /// hex) this PeerId belongs to, set by `raven relay allow @name` and when
    /// that contact's routes are forgotten ([`tag_contact`]). A block of
    /// that contact holds over the entry whatever this node still knows of
    /// its PeerIds (a learned PeerId is forgotten with the block). Omitted
    /// while empty; older readers ignore it and an older `raven relay
    /// allow|deny` drops it when it rewrites the file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub contact: String,
    /// When the entry stops admitting (Unix ms), for a PeerId of a rotating
    /// friend's relay schedule ([`relay_allow_schedule`], peer rotation spec
    /// §7); `None` (left out of the file): it never expires. The file stays
    /// version 1: an older relay ignores the field and keeps admitting the
    /// PeerId (expiry is the only thing it misses), and an older `raven
    /// relay allow|deny` drops it when it rewrites the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<u64>,
}

impl RelayAllowEntry {
    /// Has the entry expired at `now_ms` (`expires_ms < now_ms`)? A relay
    /// skips such an entry.
    pub fn expired(&self, now_ms: u64) -> bool {
        self.expires_ms.is_some_and(|at| at < now_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAllowList {
    pub version: u32,
    #[serde(default)]
    pub peers: Vec<RelayAllowEntry>,
    /// Peers the friend relay never admits, although they are the profile's
    /// contacts ([`relay_deny`] with `keep_denied`). Never also in `peers`.
    /// Omitted from the file while empty; an older reader ignores it, and an
    /// older `raven relay allow|deny` drops it when it rewrites the file
    /// (see the module doc).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<RelayAllowEntry>,
}

impl Default for RelayAllowList {
    fn default() -> Self {
        Self {
            version: ALLOW_VERSION,
            peers: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl RelayAllowList {
    pub fn contains(&self, peer_id: &str) -> bool {
        self.peers.iter().any(|e| e.peer_id == peer_id)
    }

    /// The contacts (device keys, lowercase hex) the deny list names
    /// ([`relay_deny_contact`]), once each: the friend relay turns away
    /// every PeerId each is known by, the ones of its coming epochs too.
    pub fn denied_contacts(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in &self.deny {
            let key = e.contact.trim().to_ascii_lowercase();
            if !key.is_empty() && !out.contains(&key) {
                out.push(key);
            }
        }
        out
    }

    /// Is `peer_id` on the deny list?
    pub fn is_denied(&self, peer_id: &str) -> bool {
        self.deny.iter().any(|e| e.peer_id == peer_id)
    }
}

pub fn relay_allow_path(dir: &Path) -> PathBuf {
    dir.join(RELAY_ALLOW_FILE)
}

/// The allow-list: `Ok(None)` when there is none (nobody may reserve), `Err`
/// when it exists but cannot be used (unreadable, not JSON, an unknown
/// version, an invalid or duplicate PeerId, too many entries, a peer both
/// allowed and denied): the relay then admits nobody. Never "repaired"
/// silently.
///
/// In a profile that is sealed (`raven-node service --relay`, the friend
/// relay's manual list) the file is RMS1 kind 21 (privacy pack PP.5), opened
/// with this process's at-rest key; a dedicated relay folder has no identity
/// and so no key, and its list stays plain.
pub fn load_relay_allow(dir: &Path) -> Result<Option<RelayAllowList>, String> {
    let path = relay_allow_path(dir);
    let raw = match crate::at_rest::load_bytes(dir, &path, crate::at_rest::Kind::RelayAllow) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(None),
        // Already "relay_allow.json: <why>".
        Err(crate::at_rest::AtRestError::Io(text)) => return Err(text),
        Err(e) => return Err(format!("{RELAY_ALLOW_FILE}: {e}")),
    };
    let list: RelayAllowList =
        serde_json::from_slice(&raw).map_err(|e| format!("{RELAY_ALLOW_FILE} corrupt: {e}"))?;
    if list.version != ALLOW_VERSION {
        return Err(format!(
            "{RELAY_ALLOW_FILE}: version {} is not supported",
            list.version
        ));
    }
    if list.peers.len() > MAX_ALLOW_ENTRIES || list.deny.len() > MAX_ALLOW_ENTRIES {
        return Err(format!(
            "{RELAY_ALLOW_FILE}: more than {MAX_ALLOW_ENTRIES} peers"
        ));
    }
    let canonical_set = |entries: &[RelayAllowEntry]| {
        let mut seen = std::collections::HashSet::with_capacity(entries.len());
        for entry in entries {
            let canonical = normalize_peer_id(&entry.peer_id)
                .map_err(|e| format!("{RELAY_ALLOW_FILE}: invalid peer_id: {e}"))?;
            if canonical != entry.peer_id || !seen.insert(canonical) {
                return Err(format!(
                    "{RELAY_ALLOW_FILE}: non-canonical or duplicate peer_id"
                ));
            }
        }
        Ok(seen)
    };
    // A peer both allowed and denied makes the file unusable: the relay
    // admits nobody (fail closed), never the allowed side.
    if !canonical_set(&list.peers)?.is_disjoint(&canonical_set(&list.deny)?) {
        return Err(format!(
            "{RELAY_ALLOW_FILE}: a peer_id is both allowed and denied"
        ));
    }
    Ok(Some(list))
}

fn clean_label(label: &str) -> String {
    crate::sanitize::sanitize_terminal_line(label)
        .chars()
        .take(MAX_LABEL_CHARS)
        .collect()
}

/// A relay folder another account owns is refused (Unix): the relay that
/// runs as its owner must stay able to read what is written there. A
/// missing folder is fine (it is created). On Windows the folder's
/// protected DACL already refuses another account.
fn refuse_foreign_owner(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(dir) {
            if meta.uid() != crate::ipc::current_euid() {
                return Err(
                    "this relay folder belongs to another account: change it as that \
                     account (sudo raven-relay allow …); a file written now would be unreadable \
                     by the relay, which would then admit nobody"
                        .into(),
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Edit the allow-list under its lock. A missing file starts empty; an
/// unreadable one is refused (fix or move it aside first), so a typo never
/// opens or empties the relay behind the operator's back.
fn edit_relay_allow<T>(
    dir: &Path,
    edit: impl FnOnce(&mut RelayAllowList) -> Result<T, String>,
) -> Result<T, String> {
    crate::paths::ensure_private_dir(dir)?;
    // RELAY_ALLOW_LOCK, the lock at_rest::FILES names for the file: sealed
    // in a sealed profile, plain in a dedicated relay folder (no key there).
    let lock = crate::at_rest::lock_file(
        dir,
        &relay_allow_path(dir),
        crate::at_rest::Kind::RelayAllow,
    )
    .map_err(|e| e.to_string())?;
    let mut list = load_relay_allow(dir)?.unwrap_or_default();
    let out = edit(&mut list)?;
    lock.store_json(&list).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Allow `peer_id` to reserve (and take it off the deny list). `Ok(false)`:
/// it already was (the label is updated when given).
pub fn relay_allow(dir: &Path, peer_id: &str, label: &str) -> Result<bool, String> {
    relay_allow_contact(dir, peer_id, label, "")
}

/// [`relay_allow`] for a PeerId that belongs to the contact `contact` (its
/// device key in hex; empty for none): the entry remembers it
/// ([`RelayAllowEntry::contact`]), so blocking that contact turns it away.
pub fn relay_allow_contact(
    dir: &Path,
    peer_id: &str,
    label: &str,
    contact: &str,
) -> Result<bool, String> {
    let contact = contact_key(contact)?;
    let added = allow_entries(dir, &[(peer_id.to_string(), label.to_string())], &contact)?;
    Ok(added.first().copied().unwrap_or(false))
}

/// Allow every `(peer_id, label)` in one edit (`raven relay allow --cards`):
/// all or nothing. Every PeerId, and the room left on the list, is checked
/// before anything is written. A denied peer leaves the deny list (keeping
/// its label unless a new one is given). Per entry, `true` when it was
/// added, `false` when it already was (or came earlier in `entries`; the
/// label is updated when given).
pub fn relay_allow_all(dir: &Path, entries: &[(String, String)]) -> Result<Vec<bool>, String> {
    allow_entries(dir, entries, "")
}

/// A contact's device key as [`RelayAllowEntry::contact`] keeps it: 64 hex
/// digits, lowercase (empty stays empty).
fn contact_key(contact: &str) -> Result<String, String> {
    let key = contact.trim().to_ascii_lowercase();
    if key.is_empty() || (key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())) {
        Ok(key)
    } else {
        Err("a contact's device key is 64 hex digits".into())
    }
}

/// [`relay_allow_all`], every entry for `contact` (empty: an entry keeps
/// the contact it names, if any).
fn allow_entries(
    dir: &Path,
    entries: &[(String, String)],
    contact: &str,
) -> Result<Vec<bool>, String> {
    refuse_foreign_owner(dir)?;
    let entries = entries
        .iter()
        .map(|(peer_id, label)| Ok((normalize_peer_id(peer_id)?, clean_label(label))))
        .collect::<Result<Vec<_>, String>>()?;
    edit_relay_allow(dir, |list| {
        let mut added = Vec::with_capacity(entries.len());
        for (peer_id, label) in entries {
            if let Some(entry) = list.peers.iter_mut().find(|e| e.peer_id == peer_id) {
                if !label.is_empty() {
                    entry.label = label;
                }
                if !contact.is_empty() {
                    entry.contact = contact.to_string();
                }
                // Allowed by hand: no longer only for a schedule's epoch.
                entry.expires_ms = None;
                added.push(false);
                continue;
            }
            if list.peers.len() >= MAX_ALLOW_ENTRIES {
                return Err(format!(
                    "{RELAY_ALLOW_FILE} is full ({MAX_ALLOW_ENTRIES} peers)"
                ));
            }
            let label = match list.deny.iter().position(|e| e.peer_id == peer_id) {
                Some(at) if label.is_empty() => list.deny.remove(at).label,
                Some(at) => {
                    list.deny.remove(at);
                    label
                }
                None => label,
            };
            list.peers.push(RelayAllowEntry {
                peer_id,
                label,
                contact: contact.to_string(),
                expires_ms: None,
            });
            added.push(true);
        }
        Ok(added)
    })
}

/// What [`relay_allow_schedule`] did with a schedule's entries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScheduleOutcome {
    /// Entries new on the allow-list.
    pub added: usize,
    /// Entries already there (their expiry moved later when the schedule's
    /// is later; one allowed by hand stays without expiry).
    pub already: usize,
    /// Entries whose expiry has passed already: not written.
    pub past: usize,
}

/// `raven relay allow --schedule`: allow each `(epoch, PeerId)` of a
/// rotating friend's relay schedule
/// ([`crate::peer_rotation::parse_relay_schedule`]) until
/// [`SCHEDULE_GRACE_MS`] after the end of its epoch (`epoch_end_ms`, Unix
/// ms; a relay knows no friend's phase, so it passes the latest end
/// possible, [`crate::peer_rotation::latest_epoch_end_ms`]). One edit, all or
/// nothing, like [`relay_allow_all`]. Idempotent: an entry already there
/// keeps the later expiry (and none when it was allowed by hand), and the
/// label is updated when given. Entries already expired are not written,
/// and expired entries are dropped from the list, so refreshing a schedule
/// every few months never fills it ([`MAX_ALLOW_ENTRIES`]). A denied PeerId
/// leaves the deny list, as with `allow`.
pub fn relay_allow_schedule(
    dir: &Path,
    label: &str,
    entries: &[(u64, String)],
    epoch_end_ms: impl Fn(u64) -> u64,
) -> Result<ScheduleOutcome, String> {
    refuse_foreign_owner(dir)?;
    let label = clean_label(label);
    let entries = entries
        .iter()
        .map(|(e, peer_id)| {
            let expires = epoch_end_ms(*e).saturating_add(SCHEDULE_GRACE_MS);
            Ok((normalize_peer_id(peer_id)?, expires))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let now = crate::clock::now_ms();
    edit_relay_allow(dir, |list| {
        list.peers.retain(|e| !e.expired(now));
        let mut out = ScheduleOutcome::default();
        for (peer_id, expires) in entries {
            if expires < now {
                out.past += 1;
                continue;
            }
            if let Some(entry) = list.peers.iter_mut().find(|e| e.peer_id == peer_id) {
                if !label.is_empty() {
                    entry.label = label.clone();
                }
                entry.expires_ms = entry.expires_ms.map(|at| at.max(expires));
                out.already += 1;
                continue;
            }
            if list.peers.len() >= MAX_ALLOW_ENTRIES {
                return Err(format!(
                    "{RELAY_ALLOW_FILE} is full ({MAX_ALLOW_ENTRIES} peers)"
                ));
            }
            let label = match list.deny.iter().position(|e| e.peer_id == peer_id) {
                Some(at) if label.is_empty() => list.deny.remove(at).label,
                Some(at) => {
                    list.deny.remove(at);
                    label.clone()
                }
                None => label.clone(),
            };
            list.peers.push(RelayAllowEntry {
                peer_id,
                label,
                contact: String::new(),
                expires_ms: Some(expires),
            });
            out.added += 1;
        }
        Ok(out)
    })
}

/// What [`relay_deny`] changed; both `false` when nothing did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DenyOutcome {
    /// It was on the allow-list (`peers`) and is not any more.
    pub removed: bool,
    /// It went on the deny list (`keep_denied`, and not denied already).
    pub denied: bool,
}

/// Stop allowing `peer_id`: it leaves the allow-list, and a running relay
/// drops its reservation at the next reload. `keep_denied` (set when the
/// peer is one of the profile's contacts, whom the friend relay admits by
/// itself) also puts it on the deny list, so that derived set cannot re-add
/// it. A dedicated relay folder never sets it: `deny` matters only for the
/// friend relay. A peer already denied stays denied.
pub fn relay_deny(dir: &Path, peer_id: &str, keep_denied: bool) -> Result<DenyOutcome, String> {
    deny_entry(dir, peer_id, keep_denied, "")
}

/// [`relay_deny`] (`keep_denied`) of the PeerId `peer_id` of the contact
/// `contact` (its device key): the deny entry names that contact
/// ([`RelayAllowEntry::contact`]), so the friend relay turns away every
/// PeerId the contact is known by, not only this one: a rotating contact's
/// card `p2pn=` and scheduled epochs too, now and after its next boundary
/// (peer rotation spec §9: a deny takes every one of them). An entry
/// denied already without a contact is told it.
pub fn relay_deny_contact(dir: &Path, peer_id: &str, contact: &str) -> Result<DenyOutcome, String> {
    let contact = contact_key(contact)?;
    deny_entry(dir, peer_id, true, &contact)
}

/// [`relay_deny`], the deny entry naming `contact` (empty: the one the
/// allow-list entry named, if any).
fn deny_entry(
    dir: &Path,
    peer_id: &str,
    keep_denied: bool,
    contact: &str,
) -> Result<DenyOutcome, String> {
    refuse_foreign_owner(dir)?;
    let peer_id = normalize_peer_id(peer_id)?;
    edit_relay_allow(dir, |list| {
        if keep_denied && !contact.is_empty() {
            for e in list.deny.iter_mut() {
                if e.peer_id == peer_id && e.contact.is_empty() {
                    e.contact = contact.to_string();
                }
            }
        }
        let was = list
            .peers
            .iter()
            .position(|e| e.peer_id == peer_id)
            .map(|at| list.peers.remove(at));
        let outcome = DenyOutcome {
            removed: was.is_some(),
            denied: keep_denied && !list.is_denied(&peer_id),
        };
        if outcome.denied {
            if list.deny.len() >= MAX_ALLOW_ENTRIES {
                return Err(format!(
                    "{RELAY_ALLOW_FILE}: the deny list is full ({MAX_ALLOW_ENTRIES} peers)"
                ));
            }
            let (label, was_contact) = was.map(|e| (e.label, e.contact)).unwrap_or_default();
            list.deny.push(RelayAllowEntry {
                peer_id,
                label,
                contact: if contact.is_empty() {
                    was_contact
                } else {
                    contact.to_string()
                },
                expires_ms: None,
            });
        }
        Ok(outcome)
    })
}

/// Remember on the manual allow-list that each entry naming one of
/// `peer_ids` belongs to the contact `contact` ([`RelayAllowEntry::contact`];
/// an entry that names a contact already keeps it). Called before a
/// contact's learned routes are forgotten (a block, a removal, new
/// addresses): a learned PeerId lives only there, so without this a block
/// could not find the entry `raven relay allow @name` made from it. Returns
/// how many entries it tagged; a missing list is left missing and an
/// unchanged one is not rewritten.
pub fn tag_contact(dir: &Path, contact: &str, peer_ids: &[String]) -> Result<usize, String> {
    let contact = contact_key(contact)?;
    let due = |list: &RelayAllowList| {
        list.peers
            .iter()
            .filter(|e| e.contact.is_empty() && peer_ids.contains(&e.peer_id))
            .count()
    };
    let Some(list) = load_relay_allow(dir)? else {
        return Ok(0);
    };
    if contact.is_empty() || due(&list) == 0 {
        return Ok(0);
    }
    edit_relay_allow(dir, |list| {
        let mut tagged = 0;
        for entry in list.peers.iter_mut() {
            if entry.contact.is_empty() && peer_ids.contains(&entry.peer_id) {
                entry.contact = contact.clone();
                tagged += 1;
            }
        }
        Ok(tagged)
    })
}

/// The folder of a profile's friend relay, inside the profile: its own relay
/// key ([`RELAY_KEY_FILE`]), status file and lock, never a Raven identity.
pub const FRIEND_RELAY_DIR: &str = "friend_relay";

/// [`FRIEND_RELAY_DIR`] of the profile in `profile`.
pub fn friend_relay_dir(profile: &Path) -> PathBuf {
    profile.join(FRIEND_RELAY_DIR)
}

/// The profile a friend relay folder belongs to: `Some` when `dir` is
/// [`FRIEND_RELAY_DIR`] of a folder with a Raven identity on record. Its
/// status file and key then follow the profile's at-rest mode (privacy pack
/// PP.6: RMS1 kinds 30 and 31 in a sealed profile, today's bytes otherwise),
/// under the writer locks `at_rest::FILES` names in the profile. `None` for a
/// dedicated relay folder (no identity, so no key root): plain, as before.
pub fn friend_relay_profile(dir: &Path) -> Option<&Path> {
    if dir.file_name()? != FRIEND_RELAY_DIR {
        return None;
    }
    let profile = dir.parent()?;
    crate::identity_store::identity_recorded(profile)
        .ok()?
        .then_some(profile)
}

/// What a relay process publishes about itself (`relay_status.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatusFile {
    pub version: u32,
    /// The relay's own PeerId (what friends put in `via=`).
    pub peer_id: String,
    /// Its own listen addresses (no `/p2p/` suffix).
    pub listen_addrs: Vec<String>,
    pub counts: RelayCounts,
    pub updated_at_ms: u64,
    /// The process that wrote it (a later start replaces the file).
    #[serde(default)]
    pub pid: u32,
    /// The relay's own named addresses: `swarm.external_addresses()` minus
    /// the loopback placeholder (explicit `--external` / `--public-host`,
    /// global listen addresses and UPnP-confirmed ones). Never a client's
    /// address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertised: Vec<String>,
    /// The relay's own UPnP-IGD state (`on`, `mapped <port>`, `failed`);
    /// empty when it does not use UPnP.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub upnp: String,
    /// The external addresses UPnP mapped for the relay's own ports, sorted
    /// (each is in `advertised` too); empty when it does not use UPnP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upnp_addrs: Vec<String>,
    /// When this relay was last seen to be reachable from the Internet (a
    /// member reserved from a globally routable IP, or UPnP mapped its
    /// port), in Unix ms; 0 when never.
    #[serde(default)]
    pub confirmed_at_ms: u64,
    /// The relay's `--also-tcp` ports that friends reach on another port: a
    /// router or firewall maps `public` to `local` (the kit's 7443:443).
    /// `raven relay card --host` names the public port. Empty when no port
    /// is mapped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_tcp: Vec<crate::p2p_route::ExtraTcp>,
}

pub fn relay_status_path(dir: &Path) -> PathBuf {
    dir.join(RELAY_STATUS_FILE)
}

/// Write the status file: in a profile's friend relay folder through the
/// profile's at-rest rules ([`friend_relay_profile`]), plain elsewhere.
pub fn write_relay_status(dir: &Path, status: &RelayStatusFile) -> Result<(), String> {
    let path = relay_status_path(dir);
    if let Some(profile) = friend_relay_profile(dir) {
        return crate::at_rest::store_json(
            profile,
            &path,
            crate::at_rest::Kind::FriendRelayStatus,
            status,
        )
        .map_err(|e| format!("{RELAY_STATUS_FILE}: {e}"));
    }
    let raw = serde_json::to_vec_pretty(status).map_err(|e| e.to_string())?;
    crate::paths::atomic_write_private(&path, &raw)
}

/// `Ok(None)` when no relay has run in `dir`. A profile's friend relay
/// status is opened with the profile's at-rest key when it is sealed.
pub fn load_relay_status(dir: &Path) -> Result<Option<RelayStatusFile>, String> {
    let path = relay_status_path(dir);
    let raw = match crate::at_rest::load_bytes(
        friend_relay_profile(dir).unwrap_or(dir),
        &path,
        crate::at_rest::Kind::FriendRelayStatus,
    ) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(None),
        // Already "relay_status.json: <why>".
        Err(crate::at_rest::AtRestError::Io(text)) => return Err(text),
        Err(e) if e.is_unavailable() => return Err(format!("{RELAY_STATUS_FILE}: {e}")),
        Err(e) => return Err(format!("{RELAY_STATUS_FILE} corrupt: {e}")),
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|e| format!("{RELAY_STATUS_FILE} corrupt: {e}"))
}

/// Is `dir` a dedicated relay folder (it holds a relay key, so no identity)?
pub fn is_relay_dir(dir: &Path) -> bool {
    dir.join(RELAY_KEY_FILE).is_file()
}

/// Does a relay run in `dir` right now? It holds [`RELAY_LOCK_FILE`] for
/// its whole life; taking it (and letting it go at once) means nobody does.
pub fn relay_is_running(dir: &Path) -> bool {
    if !dir.join(RELAY_LOCK_FILE).exists() {
        return false;
    }
    crate::paths::DataDirLock::acquire_within(dir, RELAY_LOCK_FILE, std::time::Duration::ZERO)
        .is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> String {
        crate::p2p_route::local_peer_id(&crate::Identity::from_seed(&[seed; 32]))
    }

    #[test]
    fn allow_and_deny_round_trip_and_stay_canonical() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_relay_allow(dir.path()).unwrap(), None);
        assert!(relay_allow(dir.path(), &peer(1), "bob").unwrap());
        assert!(!relay_allow(dir.path(), &format!(" {} ", peer(1)), "").unwrap());
        assert!(relay_allow(dir.path(), &peer(2), "carol\u{1b}[31m").unwrap());
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.peers.len(), 2);
        assert!(list.contains(&peer(1)) && list.contains(&peer(2)));
        assert_eq!(list.peers[0].label, "bob");
        assert!(!list.peers[1].label.contains('\u{1b}'));
        assert!(relay_deny(dir.path(), &peer(1), false).unwrap().removed);
        assert_eq!(
            relay_deny(dir.path(), &peer(1), false).unwrap(),
            DenyOutcome::default()
        );
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert!(!list.contains(&peer(1)) && list.contains(&peer(2)));
        assert!(list.deny.is_empty());
        assert!(relay_allow(dir.path(), "not-a-peer", "").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(relay_allow_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// `raven relay allow --cards`: one edit, all or nothing. A bad PeerId or
    /// a list without room for every new entry writes nothing.
    #[test]
    fn allow_all_is_all_or_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let entry = |p: String, l: &str| (p, l.to_string());
        assert!(relay_allow_all(
            dir.path(),
            &[entry(peer(1), "a"), entry("not-a-peer".into(), "")]
        )
        .is_err());
        assert_eq!(
            load_relay_allow(dir.path()).unwrap(),
            None,
            "nothing written"
        );
        assert_eq!(
            relay_allow_all(
                dir.path(),
                &[entry(peer(1), "a"), entry(peer(1), "b"), entry(peer(2), "")]
            )
            .unwrap(),
            [true, false, true]
        );
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.peers.len(), 2);
        assert_eq!(list.peers[0].label, "b", "a later label wins");

        // Fill the list to one short of full, then ask for two more.
        let many: Vec<(String, String)> = (0..MAX_ALLOW_ENTRIES - 3)
            .map(|i| {
                let mut seed = [7u8; 32];
                seed[..2].copy_from_slice(&(i as u16).to_be_bytes());
                let id = crate::Identity::from_seed(&seed);
                entry(crate::p2p_route::local_peer_id(&id), "")
            })
            .collect();
        relay_allow_all(dir.path(), &many).unwrap();
        let before = std::fs::read(relay_allow_path(dir.path())).unwrap();
        let e = relay_allow_all(dir.path(), &[entry(peer(3), ""), entry(peer(4), "")]).unwrap_err();
        assert!(e.contains("is full"), "{e}");
        assert_eq!(
            std::fs::read(relay_allow_path(dir.path())).unwrap(),
            before,
            "nothing written"
        );
        assert!(relay_allow(dir.path(), &peer(3), "").unwrap(), "one fits");
    }

    /// The allow-list as relays before P4.26 read it (version 1, no
    /// `expires_ms`; serde ignores unknown fields).
    #[derive(Debug, Deserialize)]
    struct OldEntryV1 {
        peer_id: String,
        #[serde(default)]
        label: String,
    }

    #[derive(Debug, Deserialize)]
    struct OldListV1 {
        version: u32,
        #[serde(default)]
        peers: Vec<OldEntryV1>,
    }

    /// `expires_ms` round-trips, is left out of the file while `None`, the
    /// file stays version 1, and an older reader ignores the field (it keeps
    /// admitting the PeerId: expiry is all it misses).
    #[test]
    fn relay_allow_expires_ms_round_trips_and_an_old_reader_ignores_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(relay_allow(dir.path(), &peer(1), "box").unwrap());
        let raw = std::fs::read_to_string(relay_allow_path(dir.path())).unwrap();
        assert!(!raw.contains("expires_ms"), "{raw}");
        let at = 1_900_000_000_000u64;
        let sched = [(5u64, peer(2))];
        relay_allow_schedule(dir.path(), "dana", &sched, |_| at).unwrap();
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.version, 1);
        assert_eq!(list.peers[0].expires_ms, None);
        assert_eq!(list.peers[1].expires_ms, Some(at + SCHEDULE_GRACE_MS));
        assert!(!list.peers[1].expired(at + SCHEDULE_GRACE_MS));
        assert!(list.peers[1].expired(at + SCHEDULE_GRACE_MS + 1));
        assert!(!list.peers[0].expired(u64::MAX));
        let raw = std::fs::read_to_string(relay_allow_path(dir.path())).unwrap();
        assert_eq!(raw.matches("expires_ms").count(), 1, "{raw}");
        let back: RelayAllowList = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, list);
        // A relay built before the field reads the same file and admits both.
        let old: OldListV1 = serde_json::from_str(&raw).unwrap();
        assert_eq!(old.version, 1);
        let old: Vec<_> = old
            .peers
            .iter()
            .map(|e| (e.peer_id.clone(), e.label.as_str()))
            .collect();
        assert_eq!(old, [(peer(1), "box"), (peer(2), "dana")]);
        // A file such a relay wrote (no field) reads as never expiring.
        let v1 = format!(r#"{{"version":1,"peers":[{{"peer_id":"{}"}}]}}"#, peer(3));
        std::fs::write(relay_allow_path(dir.path()), v1).unwrap();
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.peers[0].expires_ms, None);
    }

    /// `raven relay allow --schedule`: one entry per PeerId, expiring
    /// [`SCHEDULE_GRACE_MS`] after its epoch's end; the same schedule again
    /// changes nothing; a later one moves expiry later, never earlier; an
    /// entry allowed by hand stays without expiry; entries already expired
    /// are not written and expired ones leave the list; and a list without
    /// room for every new entry is left untouched.
    #[test]
    fn relay_allow_schedule_is_idempotent_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let now = crate::clock::now_ms();
        let day = 86_400_000u64;
        // Epoch e ends at now + e days.
        let end = |e: u64| now + e * day;
        let sched: Vec<(u64, String)> = (1..=3).map(|e| (e, peer(10 + e as u8))).collect();
        let out = relay_allow_schedule(dir.path(), "dana", &sched, end).unwrap();
        assert_eq!(
            out,
            ScheduleOutcome {
                added: 3,
                already: 0,
                past: 0
            }
        );
        let first = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(first.peers.len(), 3);
        for (entry, (e, p)) in first.peers.iter().zip(&sched) {
            assert_eq!(&entry.peer_id, p);
            assert_eq!(entry.label, "dana");
            assert!(entry.contact.is_empty());
            assert_eq!(entry.expires_ms, Some(end(*e) + SCHEDULE_GRACE_MS));
        }
        // Idempotent.
        let out = relay_allow_schedule(dir.path(), "", &sched, end).unwrap();
        assert_eq!((out.added, out.already), (0, 3));
        assert_eq!(load_relay_allow(dir.path()).unwrap().unwrap(), first);
        // An earlier end never shortens; a later one lengthens.
        relay_allow_schedule(dir.path(), "", &sched[..1], |_| now).unwrap();
        assert_eq!(load_relay_allow(dir.path()).unwrap().unwrap(), first);
        relay_allow_schedule(dir.path(), "", &sched[..1], |_| now + 30 * day).unwrap();
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(
            list.peers[0].expires_ms,
            Some(now + 30 * day + SCHEDULE_GRACE_MS)
        );
        // Allowed by hand: no expiry, and a schedule does not add one.
        relay_allow(dir.path(), &sched[1].1, "").unwrap();
        relay_allow_schedule(dir.path(), "", &sched, end).unwrap();
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.peers[1].expires_ms, None);
        // An entry long past is not written; an expired one is dropped.
        let stale = [(0u64, peer(20))];
        let out = relay_allow_schedule(dir.path(), "", &stale, |_| now - 8 * day).unwrap();
        assert_eq!(out.past, 1);
        assert!(!load_relay_allow(dir.path())
            .unwrap()
            .unwrap()
            .contains(&peer(20)));
        let mut list = load_relay_allow(dir.path()).unwrap().unwrap();
        list.peers[2].expires_ms = Some(now - 1);
        write_list(dir.path(), &list);
        relay_allow_schedule(dir.path(), "", &[], end).unwrap();
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.peers.len(), 2, "the expired entry left");
        // A denied PeerId leaves the deny list.
        relay_deny(dir.path(), &sched[0].1, true).unwrap();
        relay_allow_schedule(dir.path(), "", &sched[..1], end).unwrap();
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert!(list.contains(&sched[0].1) && !list.is_denied(&sched[0].1));
        // Capped: all or nothing.
        let mut full = RelayAllowList {
            peers: many(MAX_ALLOW_ENTRIES - 1, 9),
            ..Default::default()
        };
        full.peers[0].expires_ms = Some(now + day);
        let before = write_list(dir.path(), &full);
        let e = relay_allow_schedule(dir.path(), "", &sched[..2], end).unwrap_err();
        assert!(e.contains("is full"), "{e}");
        assert_eq!(std::fs::read(relay_allow_path(dir.path())).unwrap(), before);
        assert!(relay_allow_schedule(dir.path(), "x", &[(1, "nope".into())], end).is_err());
        assert_eq!(
            relay_allow_schedule(dir.path(), "", &sched[..1], end)
                .unwrap()
                .added,
            1
        );
    }

    /// An allow-list that cannot be used admits nobody and is never
    /// silently rewritten by `allow` / `deny`.
    #[test]
    fn an_unusable_allow_list_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        for raw in [
            "{not json".to_string(),
            r#"{"version":2,"peers":[]}"#.to_string(),
            r#"{"version":1,"peers":[{"peer_id":"12D3KooWnope"}]}"#.to_string(),
            format!(
                r#"{{"version":1,"peers":[{{"peer_id":"{p}"}},{{"peer_id":"{p}"}}]}}"#,
                p = peer(3)
            ),
        ] {
            std::fs::write(relay_allow_path(dir.path()), &raw).unwrap();
            assert!(load_relay_allow(dir.path()).is_err(), "{raw}");
            assert!(relay_allow(dir.path(), &peer(4), "").is_err(), "{raw}");
            assert!(relay_deny(dir.path(), &peer(3), false).is_err(), "{raw}");
            assert_eq!(
                std::fs::read_to_string(relay_allow_path(dir.path())).unwrap(),
                raw,
                "never repaired silently"
            );
        }
    }

    /// `n` distinct canonical PeerIds (no key derivation: any 32 bytes are
    /// an Ed25519 PeerId's text).
    fn many(n: usize, tag: u8) -> Vec<RelayAllowEntry> {
        (0..n)
            .map(|i| {
                let mut public = [tag; 32];
                public[..2].copy_from_slice(&(i as u16).to_be_bytes());
                RelayAllowEntry {
                    peer_id: crate::p2p_route::peer_id_from_ed25519_public(&public),
                    label: String::new(),
                    contact: String::new(),
                    expires_ms: None,
                }
            })
            .collect()
    }

    fn write_list(dir: &Path, list: &RelayAllowList) -> Vec<u8> {
        let raw = serde_json::to_vec_pretty(list).unwrap();
        std::fs::write(relay_allow_path(dir), &raw).unwrap();
        raw
    }

    /// An entry remembers the contact it was allowed for (`raven relay allow
    /// @name`), or is told it when that contact's routes are forgotten
    /// ([`tag_contact`]): only entries naming one of the PeerIds, never one
    /// that names a contact already. A missing list stays missing, an
    /// untouched one is not rewritten, and the field is left out while
    /// empty.
    #[test]
    fn an_entry_remembers_the_contact_it_belongs_to() {
        let dir = tempfile::tempdir().unwrap();
        let (dana, erin) = ("da".repeat(32), "EE".repeat(32));
        assert_eq!(tag_contact(dir.path(), &dana, &[peer(1)]).unwrap(), 0);
        assert_eq!(load_relay_allow(dir.path()).unwrap(), None);
        assert!(relay_allow_contact(dir.path(), &peer(1), "dana", &dana).unwrap());
        assert!(relay_allow(dir.path(), &peer(2), "box").unwrap());
        assert!(relay_allow(dir.path(), &peer(3), "").unwrap());
        assert!(relay_allow_contact(dir.path(), &peer(1), "x", "not hex").is_err());
        let contacts = |dir: &Path| -> Vec<String> {
            let list = load_relay_allow(dir).unwrap().unwrap();
            list.peers.iter().map(|e| e.contact.clone()).collect()
        };
        assert_eq!(
            contacts(dir.path()),
            [dana.clone(), String::new(), String::new()]
        );
        let raw = std::fs::read_to_string(relay_allow_path(dir.path())).unwrap();
        assert_eq!(raw.matches(r#""contact""#).count(), 1, "{raw}");
        // Erin's routes are forgotten: her PeerIds are 1 (already Dana's)
        // and 3.
        assert_eq!(
            tag_contact(dir.path(), &erin, &[peer(1), peer(3)]).unwrap(),
            1
        );
        let erin = erin.to_ascii_lowercase();
        assert_eq!(
            contacts(dir.path()),
            [dana.clone(), String::new(), erin.clone()]
        );
        // Nothing left to tag: the file is not rewritten.
        let before = std::fs::read(relay_allow_path(dir.path())).unwrap();
        assert_eq!(tag_contact(dir.path(), &erin, &[peer(3)]).unwrap(), 0);
        assert_eq!(std::fs::read(relay_allow_path(dir.path())).unwrap(), before);
        // Allowed again for a contact: that contact; without one: kept.
        assert!(!relay_allow_contact(dir.path(), &peer(2), "", &dana).unwrap());
        assert!(!relay_allow(dir.path(), &peer(1), "").unwrap());
        assert_eq!(contacts(dir.path()), [dana.clone(), dana.clone(), erin]);
        // Denied: it keeps the contact on the deny list.
        relay_deny(dir.path(), &peer(1), true).unwrap();
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert_eq!(list.deny[0].contact, dana);
    }

    /// The friend relay's deny list: with `keep_denied` a peer moves from
    /// the allow-list to `deny` (keeping its label), allowing it again takes
    /// it off, and the file stays version 1 with `deny` left out while empty.
    #[test]
    fn deny_list_round_trips_and_allow_removes_from_deny() {
        let dir = tempfile::tempdir().unwrap();
        let both = |removed, denied| DenyOutcome { removed, denied };
        assert!(relay_allow(dir.path(), &peer(1), "bob").unwrap());
        // A dedicated relay's deny: off the allow-list only.
        assert_eq!(
            relay_deny(dir.path(), &peer(1), false).unwrap(),
            both(true, false)
        );
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert!(!list.contains(&peer(1)) && !list.is_denied(&peer(1)));
        // A contact allowed by hand, then denied for good.
        assert!(relay_allow(dir.path(), &peer(1), "bob").unwrap());
        assert_eq!(
            relay_deny(dir.path(), &peer(1), true).unwrap(),
            both(true, true)
        );
        // A contact never allowed by hand goes on the deny list as well.
        assert_eq!(
            relay_deny(dir.path(), &format!(" {} ", peer(2)), true).unwrap(),
            both(false, true)
        );
        // Again: nothing changes, and a denied peer stays denied.
        for keep_denied in [true, false] {
            assert_eq!(
                relay_deny(dir.path(), &peer(2), keep_denied).unwrap(),
                DenyOutcome::default()
            );
        }
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert!(list.peers.is_empty());
        let denied: Vec<_> = list
            .deny
            .iter()
            .map(|e| (e.peer_id.clone(), e.label.as_str()))
            .collect();
        assert_eq!(denied, [(peer(1), "bob"), (peer(2), "")]);
        let raw = std::fs::read_to_string(relay_allow_path(dir.path())).unwrap();
        assert!(raw.contains(r#""deny": ["#), "{raw}");
        assert!(
            raw.contains(r#""version": 1"#),
            "the file stays version 1: {raw}"
        );
        // Allowing takes a peer off the deny list; its label stays unless a
        // new one is given.
        assert!(relay_allow(dir.path(), &peer(1), "").unwrap());
        assert_eq!(
            relay_allow_all(dir.path(), &[(peer(2), "carol".into())]).unwrap(),
            [true]
        );
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert!(list.deny.is_empty() && list.contains(&peer(1)) && list.contains(&peer(2)));
        let labels: Vec<_> = list.peers.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(labels, ["bob", "carol"]);
        // An empty deny list is not written at all.
        let raw = std::fs::read_to_string(relay_allow_path(dir.path())).unwrap();
        assert!(!raw.contains("deny"), "{raw}");

        // A full deny list takes no one more (nothing written), but a peer
        // already on it, or a deny without keep_denied, needs no room.
        let full = RelayAllowList {
            deny: many(MAX_ALLOW_ENTRIES, 0x31),
            ..RelayAllowList::default()
        };
        let before = write_list(dir.path(), &full);
        let e = relay_deny(dir.path(), &peer(3), true).unwrap_err();
        assert!(e.contains("deny list is full"), "{e}");
        assert_eq!(std::fs::read(relay_allow_path(dir.path())).unwrap(), before);
        let first = full.deny[0].peer_id.clone();
        assert_eq!(
            relay_deny(dir.path(), &first, true).unwrap(),
            DenyOutcome::default()
        );
        assert_eq!(
            relay_deny(dir.path(), &peer(3), false).unwrap(),
            DenyOutcome::default()
        );
        // Allowing one of them frees a place.
        assert!(relay_allow(dir.path(), &first, "").unwrap());
        assert!(relay_deny(dir.path(), &peer(3), true).unwrap().denied);
    }

    /// A peer on both lists (a hand edit) makes the file unusable: the relay
    /// admits nobody, and `allow` / `deny` refuse to touch it. The deny list
    /// is checked like the allow-list: canonical, unique, bounded.
    #[test]
    fn a_peer_in_both_lists_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let raw = format!(
            r#"{{"version":1,"peers":[{{"peer_id":"{p}"}},{{"peer_id":"{q}"}}],"deny":[{{"peer_id":"{p}"}}]}}"#,
            p = peer(1),
            q = peer(2)
        );
        std::fs::write(relay_allow_path(dir.path()), &raw).unwrap();
        let e = load_relay_allow(dir.path()).unwrap_err();
        assert!(e.contains("both allowed and denied"), "{e}");
        assert!(relay_allow(dir.path(), &peer(3), "").is_err());
        assert!(relay_deny(dir.path(), &peer(1), true).is_err());
        assert!(relay_deny(dir.path(), &peer(2), false).is_err());
        assert_eq!(
            std::fs::read_to_string(relay_allow_path(dir.path())).unwrap(),
            raw,
            "never repaired silently"
        );
        for deny in [
            r#"[{"peer_id":"12D3KooWnope"}]"#.to_string(),
            format!(r#"[{{"peer_id":"{p}"}},{{"peer_id":"{p}"}}]"#, p = peer(4)),
            format!(r#"[{{"peer_id":" {p}"}}]"#, p = peer(4)),
            r#"{"peer_id":"x"}"#.to_string(),
        ] {
            let raw = format!(r#"{{"version":1,"peers":[],"deny":{deny}}}"#);
            std::fs::write(relay_allow_path(dir.path()), &raw).unwrap();
            assert!(load_relay_allow(dir.path()).is_err(), "{raw}");
        }
        let over = RelayAllowList {
            deny: many(MAX_ALLOW_ENTRIES + 1, 0x32),
            ..RelayAllowList::default()
        };
        write_list(dir.path(), &over);
        let e = load_relay_allow(dir.path()).unwrap_err();
        assert!(e.contains("more than"), "{e}");
    }

    /// An older reader (`RelayAllowList` as it was: `version` and `peers`)
    /// reads a file with `deny` and ignores it. Rewriting the file the old
    /// way drops it, the downgrade the module doc discloses.
    #[test]
    fn an_old_reader_ignores_deny() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct OldAllowList {
            version: u32,
            #[serde(default)]
            peers: Vec<RelayAllowEntry>,
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(relay_allow(dir.path(), &peer(1), "bob").unwrap());
        assert!(relay_deny(dir.path(), &peer(2), true).unwrap().denied);
        let raw = std::fs::read(relay_allow_path(dir.path())).unwrap();
        let old: OldAllowList = serde_json::from_slice(&raw).unwrap();
        assert_eq!(old.version, 1);
        assert_eq!(old.peers.len(), 1);
        assert_eq!(old.peers[0].peer_id, peer(1));
        let rewritten = serde_json::to_vec_pretty(&old).unwrap();
        std::fs::write(relay_allow_path(dir.path()), rewritten).unwrap();
        let list = load_relay_allow(dir.path()).unwrap().unwrap();
        assert!(list.contains(&peer(1)) && list.deny.is_empty());
        // And a file an older build wrote reads with an empty deny list.
        let list: RelayAllowList = serde_json::from_str(r#"{"version":1,"peers":[]}"#).unwrap();
        assert_eq!(list, RelayAllowList::default());
    }

    #[test]
    fn the_friend_relay_folder_sits_inside_the_profile() {
        let profile = tempfile::tempdir().unwrap();
        let dir = friend_relay_dir(profile.path());
        assert_eq!(dir.parent(), Some(profile.path()));
        assert_eq!(dir.file_name().unwrap(), "friend_relay");
        assert_eq!(FRIEND_RELAY_DIR, "friend_relay");
    }

    #[test]
    fn status_file_round_trips_and_holds_counts_only() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_relay_status(dir.path()).unwrap(), None);
        let status = RelayStatusFile {
            version: 1,
            peer_id: peer(5),
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/7423".into()],
            counts: RelayCounts {
                allowed_peers: 2,
                reservations: 1,
                ..RelayCounts::default()
            },
            updated_at_ms: 1,
            pid: 7,
            advertised: vec!["/ip4/203.0.113.7/tcp/7423".into()],
            upnp: "mapped 7423".into(),
            upnp_addrs: vec!["/ip4/203.0.113.7/tcp/7423".into()],
            confirmed_at_ms: 3,
            extra_tcp: vec![crate::p2p_route::ExtraTcp {
                local: 7443,
                public: 443,
            }],
        };
        write_relay_status(dir.path(), &status).unwrap();
        assert_eq!(load_relay_status(dir.path()).unwrap(), Some(status));
        assert!(!is_relay_dir(dir.path()));
        std::fs::write(dir.path().join(RELAY_KEY_FILE), [0u8; 32]).unwrap();
        assert!(is_relay_dir(dir.path()));
    }

    /// `advertised`, `upnp`, `upnp_addrs` and `confirmed_at_ms` are new: a
    /// file an older relay wrote reads with them empty, and an empty one is
    /// not written (an older `raven` reads a newer file too: no
    /// unknown-field refusal).
    #[test]
    fn status_file_new_fields_are_optional_both_ways() {
        let old = r#"{"version":1,"peer_id":"p","listen_addrs":["/ip4/127.0.0.1/tcp/7423"],
            "counts":{"open":false,"allowed_peers":1,"reservations":0,"circuits":0,
            "reservations_refused":0,"circuits_refused":0},"updated_at_ms":9,"pid":4}"#;
        let read: RelayStatusFile = serde_json::from_str(old).unwrap();
        assert!(read.advertised.is_empty() && read.upnp.is_empty());
        assert!(read.upnp_addrs.is_empty());
        assert_eq!((read.confirmed_at_ms, read.pid), (0, 4));
        let unknown = old.replacen(r#""pid":4"#, r#""pid":4,"later_field":[1]"#, 1);
        assert_eq!(
            serde_json::from_str::<RelayStatusFile>(&unknown).unwrap(),
            read
        );
        assert!(read.extra_tcp.is_empty());
        let raw = serde_json::to_string(&read).unwrap();
        assert!(
            !raw.contains("advertised") && !raw.contains("upnp") && !raw.contains("extra_tcp"),
            "{raw}"
        );
        let mapped = RelayStatusFile {
            extra_tcp: vec![crate::p2p_route::ExtraTcp {
                local: 7443,
                public: 443,
            }],
            ..read.clone()
        };
        let raw = serde_json::to_string(&mapped).unwrap();
        assert!(
            raw.contains(r#""extra_tcp":[{"local":7443,"public":443}]"#),
            "{raw}"
        );
        assert_eq!(
            serde_json::from_str::<RelayStatusFile>(&raw).unwrap(),
            mapped
        );
        let named = RelayStatusFile {
            advertised: vec!["/dns/relay.example.org/tcp/443".into()],
            upnp: "failed".into(),
            upnp_addrs: vec!["/ip4/203.0.113.7/tcp/7427".into()],
            ..read
        };
        let raw = serde_json::to_string(&named).unwrap();
        assert!(raw.contains(r#""advertised":["/dns/relay.example.org/tcp/443"]"#));
        assert!(raw.contains(r#""upnp":"failed""#));
        assert!(raw.contains(r#""upnp_addrs":["/ip4/203.0.113.7/tcp/7427"]"#));
        assert_eq!(
            serde_json::from_str::<RelayStatusFile>(&raw).unwrap(),
            named
        );
    }

    /// A folder another account owns is refused before anything is read or
    /// written. Skipped as root (or as the owner of `/`).
    #[cfg(unix)]
    #[test]
    fn a_foreign_owned_relay_folder_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let euid = crate::ipc::current_euid();
        // "/" belongs to root.
        let foreign = std::path::Path::new("/");
        if euid == 0 || std::fs::metadata(foreign).unwrap().uid() == euid {
            eprintln!("running as the owner of /: skipped");
            return;
        }
        for result in [
            relay_allow(foreign, &peer(1), "bob").map(drop),
            relay_deny(foreign, &peer(1), true).map(drop),
        ] {
            let e = result.unwrap_err();
            assert!(e.contains("belongs to another account"), "{e}");
            assert!(e.contains("raven-relay"), "{e}");
        }
        // Checked first: even an invalid PeerId gets the folder's refusal.
        assert!(relay_allow(foreign, "not-a-peer", "")
            .unwrap_err()
            .contains("another account"));
        // Our own folder, and one not created yet, are fine.
        let dir = tempfile::tempdir().unwrap();
        assert!(relay_allow(dir.path(), &peer(1), "").unwrap());
        assert!(relay_allow(&dir.path().join("new"), &peer(1), "").unwrap());
        assert!(relay_deny(dir.path(), &peer(1), false).unwrap().removed);
    }

    /// Review item 13: a stopped relay is told from a running one by its
    /// lock, not only by the age of its last status.
    #[test]
    fn a_running_relay_is_told_by_its_lock() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!relay_is_running(dir.path()));
        let held = crate::paths::DataDirLock::acquire(dir.path(), RELAY_LOCK_FILE).unwrap();
        assert!(relay_is_running(dir.path()));
        drop(held);
        assert!(!relay_is_running(dir.path()));
        const {
            assert!(RELAY_STATUS_STALE_MS > 3 * RELAY_STATUS_HEARTBEAT.as_millis() as u64);
        }
    }
}
