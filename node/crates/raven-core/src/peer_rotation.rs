//! PeerId rotation (Phase 4 P4.25, `protocol/RAVEN_P2P_PEER_ROTATION_V1.md`):
//! the libp2p key of a profile per epoch, the schedule a node announces, the
//! schedules its contacts announced, and the relay schedule text an operator
//! pastes into a dedicated relay's allow-list.
//!
//! The key of epoch `e` is `SHA-256(EPOCH_KEY_DOMAIN || be64(e) || seed)`
//! used as an Ed25519 secret seed; an epoch is [`DEFAULT_EPOCH_S`] long and
//! starts at a per-profile phase ([`phase_s`]), so strangers cannot tell
//! when anyone's ID changes. The legacy, non-rotating key
//! ([`crate::p2p_route::libp2p_ed25519_seed`]) is untouched and stays the key
//! whenever rotation is off; the relay key never rotates.
//!
//! A PeerId names a libp2p key only (see [`crate::p2p_route`]): every p2p link
//! still runs the Raven Noise link with the pinned contact key inside, so a
//! schedule only says which PeerIds to admit and to dial, never whom to trust.
//!
//! Contacts' schedules live in [`PEER_SCHEDULES_FILE`]: keyed by the contact's
//! authenticated key (never by a PeerId), at most [`MAX_SCHEDULE`] entries per
//! contact and [`MAX_SCHEDULE_CONTACTS`] contacts, entries behind a contact's
//! clock dropped. An advisory file in the [`crate::lan_seen`] pattern: owner
//! only, RMS1 kind 66 in a sealed profile ([`crate::at_rest`]), written under
//! [`PEER_SCHEDULES_LOCK`], never written over when it could not be read.
//!
//! Everything here is pure or local: nothing is sent, and nothing rotates
//! unless `PEER_ROTATION_PRODUCTION_ENABLED` (false) or its lab switch is on
//! ([`crate::portmap_gate::peer_rotation_live_enabled`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::at_rest::{self, Advisory, Kind};
use crate::identity::Identity;
use crate::p2p_route::{normalize_peer_id, peer_id_from_ed25519_public};

/// Domain of an epoch's libp2p key seed.
pub const EPOCH_KEY_DOMAIN: &[u8] = b"raven/libp2p-epoch-key/v1";
/// Domain of the profile's epoch phase.
pub const EPOCH_PHASE_DOMAIN: &[u8] = b"raven/libp2p-epoch-phase/v1";
/// The epoch length: 28 days (owner decision O4-13).
pub const DEFAULT_EPOCH_S: u64 = 28 * 86_400;
/// Epochs a schedule announces after the active one (about 6 months).
pub const AHEAD: u64 = 6;
/// Entries of one schedule: the previous epoch, the active one and [`AHEAD`].
pub const MAX_SCHEDULE: usize = 8;
/// Contacts [`PEER_SCHEDULES_FILE`] remembers (the least recently heard go
/// first).
pub const MAX_SCHEDULE_CONTACTS: usize = 1024;
/// The prefix of the relay schedule text.
pub const RELAY_SCHEDULE_PREFIX: &str = "raven-relay-schedule/1";
/// Entries of one relay schedule text.
pub const MAX_RELAY_SCHEDULE: usize = 13;
/// The longest relay schedule text: the prefix and 13 entries of the
/// longest epoch (20 digits) and a 52-character PeerId.
pub const RELAY_SCHEDULE_MAX_LEN: usize =
    RELAY_SCHEDULE_PREFIX.len() + MAX_RELAY_SCHEDULE * (" ".len() + 20 + ":".len() + 52);
/// Contacts' schedules, in the data dir.
pub const PEER_SCHEDULES_FILE: &str = "peer_schedules.json";
/// Every writer of [`PEER_SCHEDULES_FILE`] takes it: the lock `at_rest::FILES`
/// names for it.
pub const PEER_SCHEDULES_LOCK: &str = ".at_rest.peer_schedules.lock.sqlite";
/// The same schedule heard again within this time is not written again.
const REWRITE_AFTER_MS: u64 = 60 * 60 * 1000;
/// This profile's own rotation progress ([`OwnRotation`]), in the data dir.
pub const ROTATION_STATE_FILE: &str = "peer_rotation_state.json";
/// Every writer of [`ROTATION_STATE_FILE`] takes it.
pub const ROTATION_STATE_LOCK: &str = ".at_rest.peer_rotation_state.lock.sqlite";

/// The epoch length in use: [`DEFAULT_EPOCH_S`], or the debug harness's
/// `RAVEN_LAB_PEER_EPOCH_S` ([`crate::portmap_gate::lab_peer_epoch_s`]).
pub fn epoch_len_s() -> u64 {
    crate::portmap_gate::lab_peer_epoch_s().unwrap_or(DEFAULT_EPOCH_S)
}

/// The libp2p Ed25519 secret seed of epoch `e`:
/// `SHA-256(EPOCH_KEY_DOMAIN || be64(e) || raven seed)`.
pub fn epoch_seed(id: &Identity, e: u64) -> Zeroizing<[u8; 32]> {
    let seed = id.seed_zeroizing();
    let mut h = Sha256::new();
    h.update(EPOCH_KEY_DOMAIN);
    h.update(e.to_be_bytes());
    h.update(seed.as_slice());
    Zeroizing::new(h.finalize().into())
}

/// Public half of [`epoch_seed`].
pub fn epoch_public(id: &Identity, e: u64) -> [u8; 32] {
    SigningKey::from_bytes(&epoch_seed(id, e))
        .verifying_key()
        .to_bytes()
}

/// The PeerId of epoch `e`.
pub fn epoch_peer_id(id: &Identity, e: u64) -> String {
    peer_id_from_ed25519_public(&epoch_public(id, e))
}

/// The profile's phase in an epoch of `len` seconds:
/// `be64(SHA-256(EPOCH_PHASE_DOMAIN || seed)[0..8]) mod len` (a `len` of 0
/// reads as 1).
pub fn phase_s(id: &Identity, len: u64) -> u64 {
    let seed = id.seed_zeroizing();
    let mut h = Sha256::new();
    h.update(EPOCH_PHASE_DOMAIN);
    h.update(seed.as_slice());
    let digest: [u8; 32] = h.finalize().into();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first) % len.max(1)
}

/// The epoch at `unix_s`: `(unix_s + phase) div len`.
pub fn epoch_at(id: &Identity, unix_s: u64, len: u64) -> u64 {
    unix_s.saturating_add(phase_s(id, len)) / len.max(1)
}

/// When the epoch after the one at `unix_s` starts (Unix seconds):
/// `(epoch_at + 1) * len - phase`.
pub fn next_boundary_unix(id: &Identity, unix_s: u64, len: u64) -> u64 {
    let len = len.max(1);
    (epoch_at(id, unix_s, len).saturating_add(1))
        .saturating_mul(len)
        .saturating_sub(phase_s(id, len))
}

/// The latest time epoch `e` of `len` seconds can end for any phase (Unix
/// ms): `(e + 1) * len` seconds, since a phase only moves the end earlier
/// (by less than `len`). A dedicated relay knows no friend's phase, so a
/// relay schedule's entry expires from here (spec §7). Saturating; a `len`
/// of 0 reads as 1.
pub fn latest_epoch_end_ms(e: u64, len: u64) -> u64 {
    e.saturating_add(1)
        .saturating_mul(len.max(1))
        .saturating_mul(1000)
}

/// The schedule this profile announces while epoch `active` is in use: the
/// previous epoch, `active` and [`AHEAD`] more, each with its public key.
pub fn own_schedule(id: &Identity, active: u64) -> Vec<(u64, [u8; 32])> {
    (active.saturating_sub(1)..=active.saturating_add(AHEAD))
        .map(|e| (e, epoch_public(id, e)))
        .collect()
}

/// What this profile announces in its route hints (RRH1 PEER_SCHEDULE,
/// spec §4): with its rotation off (`active` `None`) only that it is
/// capable, its epoch length (`len`, saturated to u32) and no entries;
/// with it on, the epoch in use, [`own_schedule`] and whether it rolled
/// back (`postponed`).
pub fn announced_schedule(
    id: &Identity,
    active: Option<(u64, bool)>,
    len: u64,
) -> crate::route_hints::PeerSchedule {
    use crate::route_hints::{PeerSchedule, SCHEDULE_FLAG_POSTPONED, SCHEDULE_FLAG_ROTATING};
    let len = u32::try_from(len.max(1)).unwrap_or(u32::MAX);
    match active {
        None => PeerSchedule::capability_only(len),
        Some((epoch, postponed)) => {
            let mut s = PeerSchedule::capability_only(len);
            s.flags |= SCHEDULE_FLAG_ROTATING;
            if postponed {
                s.flags |= SCHEDULE_FLAG_POSTPONED;
            }
            s.active_epoch = epoch;
            s.entries = own_schedule(id, epoch);
            s
        }
    }
}

// ── Contacts' schedules ──────────────────────────────────────────────────

/// One contact's schedule, as its last route hint announced it (RRH1
/// PEER_SCHEDULE) and when that was received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactSchedule {
    /// The contact runs a raven that can rotate (always set when announced).
    pub capable: bool,
    /// Its rotation is on.
    pub rotating: bool,
    /// It rolled back to an earlier epoch (its relays refused the next ID).
    pub postponed: bool,
    /// Its epoch length in seconds.
    pub len_s: u32,
    /// The epoch it used when it sent the schedule.
    pub active: u64,
    /// Epochs (strictly increasing, within `active - 1 ..= active + 6`) and
    /// their Ed25519 public keys.
    #[serde(with = "entries_hex")]
    pub entries: Vec<(u64, [u8; 32])>,
    /// When it was received (Unix milliseconds).
    pub received_ms: u64,
}

/// `entries` as `[[epoch, "<64 hex>"], …]`.
mod entries_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[(u64, [u8; 32])], s: S) -> Result<S::Ok, S::Error> {
        v.iter()
            .map(|(e, key)| (*e, hex::encode(key)))
            .collect::<Vec<_>>()
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(u64, [u8; 32])>, D::Error> {
        Vec::<(u64, String)>::deserialize(d)?
            .into_iter()
            .map(|(e, text)| {
                let mut key = [0u8; 32];
                hex::decode_to_slice(&text, &mut key)
                    .map_err(|_| serde::de::Error::custom("a schedule key is not 64 hex"))?;
                Ok((e, key))
            })
            .collect()
    }
}

impl ContactSchedule {
    /// A contact's announcement (RRH1 PEER_SCHEDULE, as
    /// [`crate::route_hints::validate`] kept it) received at `received_ms`.
    pub fn from_announced(s: &crate::route_hints::PeerSchedule, received_ms: u64) -> Self {
        Self {
            capable: s.capable(),
            rotating: s.rotating(),
            postponed: s.postponed(),
            len_s: s.epoch_len_s,
            active: s.active_epoch,
            entries: s.entries.clone(),
            received_ms,
        }
    }
}

/// An Ed25519 public key a schedule may carry: it decodes as a point, is
/// canonically encoded and is not of small order (the ed25519_strict rules).
pub fn schedule_key_ok(key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(key)
        .is_ok_and(|vk| vk.to_edwards().compress().to_bytes() == *key && !vk.is_weak())
}

impl ContactSchedule {
    /// Whether the contact reaches us under epoch keys (its rotation is on,
    /// or on but postponed), so the entries name its PeerIds.
    fn uses_epochs(&self) -> bool {
        self.capable && (self.rotating || self.postponed)
    }

    /// Whether the schedule names the contact's epoch keys: it uses them, or
    /// announced them before its first switch (entries without `rotating`,
    /// spec §9.1).
    fn names_keys(&self) -> bool {
        self.capable && !self.entries.is_empty()
    }

    /// The contact's clock epoch at `now_unix`, as far as the schedule tells:
    /// its phase is secret, so the epoch at `received_ms` was `active` and
    /// now is `active + k` or `active + k + 1` (`k` whole epochs later).
    /// Returns `(lower, guess)`: `guess` is the likelier of the two (the
    /// second when more than half of an epoch passed after the `k`th).
    fn clock(&self, now_unix: u64) -> (u64, u64) {
        let len = u64::from(self.len_s).max(1);
        let elapsed = now_unix.saturating_sub(self.received_ms / 1000);
        let lower = self.active.saturating_add(elapsed / len);
        let guess = if (elapsed % len).saturating_mul(2) >= len {
            lower.saturating_add(1)
        } else {
            lower
        };
        (lower, guess)
    }

    fn key_of(&self, e: u64) -> Option<String> {
        self.entries
            .iter()
            .find(|(epoch, _)| *epoch == e)
            .map(|(_, key)| peer_id_from_ed25519_public(key))
    }

    /// Checked and bounded: an error for a schedule no hint could carry
    /// (no capability, a zero length, an entry out of `active - 1 ..= active
    /// + 6`, epochs not strictly increasing, a bad key, more than
    /// [`MAX_SCHEDULE`]).
    fn check(&self) -> Result<(), String> {
        if !self.capable {
            return Err("a schedule always says it is capable".into());
        }
        if self.len_s == 0 {
            return Err("a schedule's epoch length is not 0".into());
        }
        if self.entries.len() > MAX_SCHEDULE {
            return Err(format!("a schedule holds at most {MAX_SCHEDULE} entries"));
        }
        let (lo, hi) = (
            self.active.saturating_sub(1),
            self.active.saturating_add(AHEAD),
        );
        if self.entries.iter().any(|(e, _)| *e < lo || *e > hi) {
            return Err("a schedule entry is outside the previous epoch .. 6 ahead".into());
        }
        if self.entries.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err("schedule epochs are not strictly increasing".into());
        }
        if !self.entries.iter().all(|(_, key)| schedule_key_ok(key)) {
            return Err("a schedule key is not a usable Ed25519 key".into());
        }
        Ok(())
    }

    /// Drop the entries behind the contact's clock at `now_ms` (older than
    /// one epoch before its lowest possible clock epoch). Whether any went.
    fn prune(&mut self, now_ms: u64) -> bool {
        let (lower, _) = self.clock(now_ms / 1000);
        let keep_from = lower.saturating_sub(1);
        let before = self.entries.len();
        self.entries.retain(|(e, _)| *e >= keep_from);
        self.entries.len() != before
    }

    /// The same announcement, whenever it was received.
    fn same_as(&self, other: &ContactSchedule) -> bool {
        ContactSchedule {
            received_ms: other.received_ms,
            ..self.clone()
        } == *other
    }
}

type Schedules = BTreeMap<String, ContactSchedule>;

fn schedules_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PEER_SCHEDULES_FILE)
}

fn read(data_dir: &Path) -> Advisory<Schedules> {
    at_rest::load_json_advisory(data_dir, &schedules_path(data_dir), Kind::PeerSchedules)
}

/// A contact's key as the file names it: 64 lower-case hex.
fn contact_key(pub_hex: &str) -> Result<String, String> {
    let key = pub_hex.trim().to_ascii_lowercase();
    if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("a contact key is 64 hex characters".into());
    }
    Ok(key)
}

/// Every contact's schedule (by its key, hex). A missing file, or plain
/// bytes that do not parse, hold none; a schedule that fails the checks
/// (hand-edited) is left out. An error when the file could not be read (a
/// sealed one whose key is not loaded, a changed byte).
pub fn load_schedules(data_dir: &Path) -> Result<Schedules, String> {
    match read(data_dir) {
        Advisory::Missing | Advisory::CorruptPlain => Ok(Schedules::new()),
        Advisory::Loaded(all) => Ok(all
            .into_iter()
            .filter(|(key, s)| contact_key(key).as_deref() == Ok(key) && s.check().is_ok())
            .collect()),
        Advisory::Unreadable(e) => Err(format!("{PEER_SCHEDULES_FILE}: {e}")),
    }
}

/// Remember `s` as the schedule of the contact `pub_hex` (its authenticated
/// key, never a PeerId), under [`PEER_SCHEDULES_LOCK`]. The entries behind
/// the contact's clock at `s.received_ms` go, and so do every other
/// contact's; past [`MAX_SCHEDULE_CONTACTS`] the least recently heard go.
/// The same schedule heard again within the hour is not written again. A
/// schedule that fails the checks, and a file that could not be read
/// (never written over), are errors.
pub fn save_schedule(data_dir: &Path, pub_hex: &str, s: &ContactSchedule) -> Result<(), String> {
    let key = contact_key(pub_hex)?;
    s.check()?;
    let mut s = s.clone();
    s.prune(s.received_ms);
    let fresh = |all: &Schedules| {
        all.get(&key).is_some_and(|old| {
            old.same_as(&s) && s.received_ms.saturating_sub(old.received_ms) < REWRITE_AFTER_MS
        })
    };
    // Most hints repeat the schedule: no lock and no write for those.
    if let Advisory::Loaded(all) = read(data_dir) {
        if fresh(&all) {
            return Ok(());
        }
    }
    let path = schedules_path(data_dir);
    let lock =
        at_rest::lock_file(data_dir, &path, Kind::PeerSchedules).map_err(|e| e.to_string())?;
    let mut all = at_rest::load_json_for_write::<Schedules>(data_dir, &path, Kind::PeerSchedules)
        .map_err(|e| format!("{PEER_SCHEDULES_FILE}: {e}"))?;
    if fresh(&all) {
        return Ok(());
    }
    let now_ms = s.received_ms;
    all.insert(key, s);
    for other in all.values_mut() {
        other.prune(now_ms);
    }
    if all.len() > MAX_SCHEDULE_CONTACTS {
        let mut by_age: Vec<(u64, String)> = all
            .iter()
            .map(|(k, v)| (v.received_ms, k.clone()))
            .collect();
        by_age.sort();
        for (_, k) in by_age.into_iter().take(all.len() - MAX_SCHEDULE_CONTACTS) {
            all.remove(&k);
        }
    }
    lock.store_json(&all).map_err(|e| e.to_string())
}

/// Forget the schedule of the contact `pub_hex` (it was removed), under
/// [`PEER_SCHEDULES_LOCK`]. A missing file or entry is fine; a file that
/// could not be read is kept as it is (an error).
pub fn forget_schedule(data_dir: &Path, pub_hex: &str) -> Result<(), String> {
    let key = contact_key(pub_hex)?;
    match read(data_dir) {
        Advisory::Missing | Advisory::CorruptPlain => return Ok(()),
        Advisory::Loaded(all) if !all.contains_key(&key) => return Ok(()),
        Advisory::Loaded(_) | Advisory::Unreadable(_) => {}
    }
    let path = schedules_path(data_dir);
    let lock =
        at_rest::lock_file(data_dir, &path, Kind::PeerSchedules).map_err(|e| e.to_string())?;
    let mut all = at_rest::load_json_for_write::<Schedules>(data_dir, &path, Kind::PeerSchedules)
        .map_err(|e| format!("{PEER_SCHEDULES_FILE}: {e}"))?;
    if all.remove(&key).is_none() {
        return Ok(());
    }
    lock.store_json(&all).map_err(|e| e.to_string())
}

/// Take the entries behind each contact's clock at `now_ms` off the disk
/// (the capability itself stays). Lock-free first: none, no lock and no
/// write. How many entries went. A file that could not be read is kept as
/// it is (an error).
pub fn prune_schedules(data_dir: &Path, now_ms: u64) -> Result<usize, String> {
    let stale = |all: &Schedules| -> usize {
        all.values()
            .map(|s| {
                let mut s = s.clone();
                let before = s.entries.len();
                s.prune(now_ms);
                before - s.entries.len()
            })
            .sum()
    };
    match read(data_dir) {
        Advisory::Missing | Advisory::CorruptPlain => return Ok(0),
        Advisory::Loaded(all) if stale(&all) == 0 => return Ok(0),
        Advisory::Unreadable(e) => return Err(format!("{PEER_SCHEDULES_FILE}: {e}")),
        Advisory::Loaded(_) => {}
    }
    let path = schedules_path(data_dir);
    let lock =
        at_rest::lock_file(data_dir, &path, Kind::PeerSchedules).map_err(|e| e.to_string())?;
    let mut all = at_rest::load_json_for_write::<Schedules>(data_dir, &path, Kind::PeerSchedules)
        .map_err(|e| format!("{PEER_SCHEDULES_FILE}: {e}"))?;
    let removed = stale(&all);
    if removed > 0 {
        for s in all.values_mut() {
            s.prune(now_ms);
        }
        lock.store_json(&all).map_err(|e| e.to_string())?;
    }
    Ok(removed)
}

// ── This profile's own rotation ──────────────────────────────────────────

/// Since when this profile announces its own coming PeerIds
/// ([`ROTATION_STATE_FILE`], spec §9.1): set when its rotation became ready
/// (setting on, every p2p contact capable) and its route hints began to
/// carry the schedule's entries; the first epoch boundary after `ready_ms`
/// switches its key, so contacts learn the coming PeerIds before the first
/// one is used. Kept across restarts (a restart would otherwise go back to
/// the fixed PeerId for an epoch); cleared while rotation is off or waits
/// on a contact. Sealed (RMS1 kind 67), owner only, written under
/// [`ROTATION_STATE_LOCK`]; only a time, no PeerId or key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnRotation {
    /// When the announcement began (Unix ms); `None`: not ready.
    #[serde(default)]
    pub ready_ms: Option<u64>,
}

fn rotation_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ROTATION_STATE_FILE)
}

/// This profile's [`OwnRotation`]: a missing file, or plain bytes that do not
/// parse, is the default (not ready). An error when the file could not be
/// read (a sealed one whose key is not loaded): the caller then keeps the
/// fixed PeerId and writes nothing.
pub fn load_own_rotation(data_dir: &Path) -> Result<OwnRotation, String> {
    match at_rest::load_json_advisory::<OwnRotation>(
        data_dir,
        &rotation_state_path(data_dir),
        Kind::PeerRotationState,
    ) {
        Advisory::Missing | Advisory::CorruptPlain => Ok(OwnRotation::default()),
        Advisory::Loaded(r) => Ok(r),
        Advisory::Unreadable(e) => Err(format!("{ROTATION_STATE_FILE}: {e}")),
    }
}

/// Write `r` as this profile's [`OwnRotation`] under [`ROTATION_STATE_LOCK`]
/// (only when it differs from what the file holds). A file that could not
/// be read is never written over (an error).
pub fn save_own_rotation(data_dir: &Path, r: OwnRotation) -> Result<(), String> {
    if load_own_rotation(data_dir)? == r {
        return Ok(());
    }
    let path = rotation_state_path(data_dir);
    let lock =
        at_rest::lock_file(data_dir, &path, Kind::PeerRotationState).map_err(|e| e.to_string())?;
    let held =
        at_rest::load_json_for_write::<OwnRotation>(data_dir, &path, Kind::PeerRotationState)
            .map_err(|e| format!("{ROTATION_STATE_FILE}: {e}"))?;
    if held == r {
        return Ok(());
    }
    lock.store_json(&r).map_err(|e| e.to_string())
}

// ── Which PeerIds a contact has ──────────────────────────────────────────

fn push_unique(out: &mut Vec<String>, peer: Option<String>) {
    if let Some(peer) = peer {
        if !out.contains(&peer) {
            out.push(peer);
        }
    }
}

fn card_peer(text: Option<&str>) -> Option<String> {
    text.and_then(|t| normalize_peer_id(t).ok())
}

/// The PeerIds the peer gate and the friend relay's allow-list admit for a
/// contact: its card's `p2p=` and `p2pn=`, then, while its schedule names
/// keys (it uses epoch keys, or is about to: spec §9.1), the epochs around
/// its clock (the one before the lower estimate up to the one after the
/// higher, so a boundary between the two is covered) and the epoch it
/// announced as active (where a postponed contact stays). Unparseable card
/// values are left out.
pub fn admitted_peer_ids(
    card_peer_id: Option<&str>,
    card_next: Option<&str>,
    s: Option<&ContactSchedule>,
    now_unix: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    push_unique(&mut out, card_peer(card_peer_id));
    push_unique(&mut out, card_peer(card_next));
    if let Some(s) = s.filter(|s| s.names_keys()) {
        let (lower, _) = s.clock(now_unix);
        let (lo, hi) = (lower.saturating_sub(1), lower.saturating_add(2));
        for (e, key) in &s.entries {
            if (lo..=hi).contains(e) || *e == s.active {
                push_unique(&mut out, Some(peer_id_from_ed25519_public(key)));
            }
        }
    }
    out
}

/// Every PeerId a contact's schedule names (whatever its clock): what a
/// block or a removal takes away with the contact.
pub fn schedule_peer_ids(s: &ContactSchedule) -> Vec<String> {
    let mut out = Vec::new();
    for (_, key) in &s.entries {
        push_unique(&mut out, Some(peer_id_from_ed25519_public(key)));
    }
    out
}

/// The PeerIds to dial a contact under, in order, at most 2: while its
/// schedule says it uses epoch keys, the likelier clock epoch, then the
/// epoch it announced as active when it says it postponed (and that is not
/// the likelier one), else the other side of the boundary the clock
/// estimate may straddle (each only when the
/// schedule holds its key); otherwise, or when the schedule holds neither,
/// the card's `p2p=` and `p2pn=`. A contact about to rotate (its schedule
/// names keys without saying it rotates, spec §9.1) still uses its fixed
/// PeerId: the card's `p2p=` first, then the epoch it may have switched to
/// since (the likelier clock epoch, never the one it announced from).
pub fn dial_peer_ids(
    card_peer_id: &str,
    card_next: Option<&str>,
    s: Option<&ContactSchedule>,
    now_unix: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(s) = s.filter(|s| s.uses_epochs()) {
        let (lower, guess) = s.clock(now_unix);
        let second = if s.postponed && s.active != guess {
            s.active
        } else if guess == lower {
            lower.saturating_add(1)
        } else {
            lower
        };
        push_unique(&mut out, s.key_of(guess));
        push_unique(&mut out, s.key_of(second));
    }
    if out.is_empty() {
        push_unique(&mut out, card_peer(Some(card_peer_id)));
        match s.filter(|s| s.names_keys() && !s.uses_epochs()) {
            Some(s) => {
                let (_, guess) = s.clock(now_unix);
                push_unique(&mut out, s.key_of(guess.max(s.active.saturating_add(1))));
            }
            None => push_unique(&mut out, card_peer(card_next)),
        }
    }
    out.truncate(2);
    out
}

// ── Relay schedule text ──────────────────────────────────────────────────

/// `raven-relay-schedule/1 <epoch>:<PeerId> …`: this profile's PeerIds of
/// `n` epochs from `from` (`n` clamped to 1 ..= [`MAX_RELAY_SCHEDULE`]),
/// what a dedicated relay's operator pastes into `raven relay allow
/// --schedule`.
pub fn format_relay_schedule(id: &Identity, from: u64, n: usize) -> String {
    let mut text = RELAY_SCHEDULE_PREFIX.to_string();
    for i in 0..n.clamp(1, MAX_RELAY_SCHEDULE) as u64 {
        let Some(e) = from.checked_add(i) else {
            break;
        };
        text.push_str(&format!(" {e}:{}", epoch_peer_id(id, e)));
    }
    text
}

/// A canonical decimal epoch: digits only, no leading zero (but `0`), at
/// most `u64::MAX`.
fn parse_epoch(text: &str) -> Option<u64> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

/// Strict parse of a relay schedule text (like a card): one line of at most
/// [`RELAY_SCHEDULE_MAX_LEN`] plain characters after trimming, the prefix,
/// then 1 ..= [`MAX_RELAY_SCHEDULE`] `<epoch>:<PeerId>` entries with
/// strictly increasing epochs and each PeerId once (the canonical Ed25519
/// form, [`crate::p2p_route::parse_peer_id`]). Returns the epochs and the
/// canonical PeerIds.
pub fn parse_relay_schedule(t: &str) -> Result<Vec<(u64, String)>, String> {
    let line = t.trim();
    if line.len() > RELAY_SCHEDULE_MAX_LEN
        || !line.chars().all(|c| c == ' ' || c.is_ascii_graphic())
    {
        return Err(format!(
            "not a relay schedule: one line of at most {RELAY_SCHEDULE_MAX_LEN} plain characters"
        ));
    }
    let mut tokens = line.split(' ').filter(|t| !t.is_empty());
    match tokens.next() {
        Some(RELAY_SCHEDULE_PREFIX) => {}
        Some(v) if v.starts_with("raven-relay-schedule/") => {
            return Err(format!(
                "relay schedule version \"{v}\" is not supported: this raven reads \
                 {RELAY_SCHEDULE_PREFIX} (update raven)"
            ))
        }
        _ => {
            return Err(format!(
                "not a relay schedule: it must start with {RELAY_SCHEDULE_PREFIX} (ask for the \
                 line `raven relay schedule` prints)"
            ))
        }
    }
    let mut out: Vec<(u64, String)> = Vec::new();
    for token in tokens {
        if out.len() == MAX_RELAY_SCHEDULE {
            return Err(format!(
                "a relay schedule holds at most {MAX_RELAY_SCHEDULE} entries"
            ));
        }
        let (epoch, peer) = token
            .split_once(':')
            .ok_or("a relay schedule entry is <epoch>:<PeerId>")?;
        let epoch = parse_epoch(epoch).ok_or("a relay schedule epoch is a decimal number")?;
        let peer = normalize_peer_id(peer)
            .ok()
            .filter(|p| p == peer)
            .ok_or("a relay schedule entry names no canonical PeerId")?;
        if out.last().is_some_and(|(last, _)| *last >= epoch) {
            return Err("relay schedule epochs are not strictly increasing".into());
        }
        if out.iter().any(|(_, p)| *p == peer) {
            return Err("a PeerId appears twice in the relay schedule".into());
        }
        out.push((epoch, peer));
    }
    if out.is_empty() {
        return Err("a relay schedule names at least one epoch".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
