//! Pair-seed rotation (`docs/roadmap/plans/phase6-design.json` step P6.38;
//! design B §5 and W-B4, owner decision OD6b-12): forward secrecy for the
//! keys of the LAN beacon, the RLK1 link knock and the Bluetooth LE tokens.
//!
//! Those keys come from the R2 pairwise root ([`crate::lan_beacon::pair_root`]),
//! which anyone who later gets an identity key can compute again, and with it
//! every recorded beacon, knock and token. Two contacts therefore also share a
//! random **pair seed** that they replace every 7 days over an authenticated
//! link (RRH1 entry `PAIR_SEED`, type 0x08, `RAVEN_ROUTE_HINTS_V1.md` §14), and
//! take the medium keys from `K_pair` instead of the root:
//!
//! ```text
//! K_pair = HKDF-SHA256(salt = pair_root, IKM = seed, info = "rvn1/pair-seed/v1", L = 32)
//! K_medium = medium_key(K_pair, medium)        (0x01 Bluetooth LE, 0x02 beacon, 0x03 knock)
//! ```
//!
//! - **Roles.** The contact with the numerically smaller identity key leads
//!   ([`is_leader`]). It proposes generation g+1 with a fresh seed at most
//!   every [`ROTATE_MS`] (and at once when the pair has none), stored before
//!   the RRH1 that carries it goes out; it offers the same proposal until it
//!   is acked. The follower stores what the leader offers (stored before its
//!   ack goes out) and acks it in its own RRH1; the leader switches to it on
//!   the ack.
//! - **Keys a side uses** ([`PairState::send_seed`], [`PairRoots`]): it sends
//!   (beacon queries, knocks, advertised tokens) with its current seed, or
//!   the root while it has none, and accepts its current seed, the leader's
//!   outstanding proposal (the follower may use it already) or its previous
//!   seed, and the static root, in that order. The previous seed goes
//!   [`RETIRE_MS`] after the switch: the leader's when it switches, the
//!   follower's once it sees the leader use the new one (`acked_generation`).
//!   A contact whose RRH1 carries no entry has no seed (its gate is shut, an
//!   older build, its seeds lost): this side keeps its seed as the previous
//!   one for [`RETIRE_MS`] and sends with the root. So a lost seed never
//!   locks friends out; it only loses forward secrecy until the next
//!   rotation. A match with the static root while this side expects the
//!   contact to use a seed is a Notice (`SEC_PAIR_SEED_ROOT`).
//! - **Stored** in [`PAIR_SEEDS_FILE`], keyed by the contact's identity key,
//!   under its own lock ([`PAIR_SEEDS_LOCK`]): RMS1 kind 12 in a sealed
//!   profile (`at_rest::FILES`, registered from its first version) and plain
//!   JSON (0600) in a plain one, sealed by the migration with the rest. An
//!   advisory file: one this process cannot read reads as no seeds (the root
//!   only) and is never written over. At most [`MAX_PAIRS`] contacts. A
//!   removed contact loses its seeds ([`forget`]).
//!
//! Live only while [`SecGate::PairSeed`] is (`PAIR_SEED_PRODUCTION_ENABLED =
//! false`; it sits on route hints): with the gate shut nothing is sent,
//! nothing received is kept, and every key comes from the root as before.
//! Honest limit (design B §5): forward secrecy needs the old seed really
//! gone; an old copy of the sealed file stays readable while the at-rest
//! key exists. The gain is against someone who later gets only the identity
//! key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::at_rest::{self, Advisory, Kind};
use crate::identity::Identity;
use crate::lan_beacon::{pair_root, BeaconError};
use crate::security_gate::{self, SecGate};

/// The file, in the profile folder.
pub const PAIR_SEEDS_FILE: &str = "pair_seeds.json";
/// Every writer of [`PAIR_SEEDS_FILE`] takes it (`at_rest::FILES`).
pub const PAIR_SEEDS_LOCK: &str = ".at_rest.pair_seeds.lock.sqlite";
/// The RRH1 PAIR_SEED value: `generation u32 || seed[32] || acked_generation
/// u32`.
pub const ENTRY_LEN: usize = 4 + 32 + 4;
/// The HKDF info of [`pair_key`].
pub const KDF_INFO: &[u8] = b"rvn1/pair-seed/v1";
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// The leader proposes a new seed at most this often.
pub const ROTATE_MS: u64 = 7 * DAY_MS;
/// A replaced seed is accepted this long after the switch.
pub const RETIRE_MS: u64 = 2 * DAY_MS;
/// Contacts with seeds at most: past it, the pair that switched longest ago
/// goes (it falls back to the root).
pub const MAX_PAIRS: usize = 4_096;

/// Pair seeds are live in this process ([`SecGate::PairSeed`], which needs
/// route hints live too).
pub fn live() -> bool {
    security_gate::live(SecGate::PairSeed)
}

/// Does `me` lead the pair with `peer` (the numerically smaller identity
/// key, bytes compared as a big-endian number)?
pub fn is_leader(me: &[u8; 32], peer: &[u8; 32]) -> bool {
    me < peer
}

/// `K_pair` of a seed: HKDF-SHA256(salt = the pair's R2 root, IKM = `seed`,
/// info = [`KDF_INFO`], 32 bytes). It takes the root's place in
/// [`crate::lan_beacon::medium_key`].
pub fn pair_key(root: &[u8; 32], seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(root), seed)
        .expand(KDF_INFO, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

// ── The RRH1 entry ──────────────────────────────────────────────────────────

/// One RRH1 PAIR_SEED entry (type 0x08, [`ENTRY_LEN`] bytes): the sender's
/// seed offer and what it adopted. A leader offers its outstanding proposal,
/// else its current seed, with `acked` its current generation (0: none); a
/// follower echoes its current seed, with `acked` its generation. `Debug`
/// shows no seed.
#[derive(Clone, PartialEq, Eq)]
pub struct SeedEntry {
    /// 1 or more.
    pub generation: u32,
    pub seed: Zeroizing<[u8; 32]>,
    pub acked: u32,
}

impl std::fmt::Debug for SeedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedEntry")
            .field("generation", &self.generation)
            .field("acked", &self.acked)
            .finish_non_exhaustive()
    }
}

impl SeedEntry {
    pub fn new(generation: u32, seed: [u8; 32], acked: u32) -> Self {
        Self {
            generation,
            seed: Zeroizing::new(seed),
            acked,
        }
    }

    /// `generation_be || seed || acked_be`.
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        let mut out = [0u8; ENTRY_LEN];
        out[..4].copy_from_slice(&self.generation.to_be_bytes());
        out[4..36].copy_from_slice(self.seed.as_slice());
        out[36..].copy_from_slice(&self.acked.to_be_bytes());
        out
    }

    /// An entry's value, or `None` (dropped alone, never the frame): a
    /// length other than 40, generation 0 or an all-zero seed.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let value: &[u8; ENTRY_LEN] = value.try_into().ok()?;
        let generation = u32::from_be_bytes(value[..4].try_into().ok()?);
        let seed: [u8; 32] = value[4..36].try_into().ok()?;
        let acked = u32::from_be_bytes(value[36..].try_into().ok()?);
        (generation != 0 && seed != [0; 32]).then(|| Self {
            generation,
            seed: Zeroizing::new(seed),
            acked,
        })
    }

    /// Does the value follow §14 (as [`Self::from_bytes`] reads it)?
    pub fn valid(&self) -> bool {
        self.generation != 0 && *self.seed != [0; 32]
    }
}

// ── The state machine (pure) ────────────────────────────────────────────────

/// One seed generation. Wiped on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Seed {
    pub generation: u32,
    #[serde(with = "hex_seed")]
    pub seed: [u8; 32],
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seed")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Seed {
    fn of(e: &SeedEntry) -> Self {
        Self {
            generation: e.generation,
            seed: *e.seed,
        }
    }

    fn is(&self, e: &SeedEntry) -> bool {
        self.generation == e.generation && self.seed == *e.seed
    }
}

/// One contact's seeds, seen from this node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairState {
    /// The seed this side sends with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Seed>,
    /// The seed before `current` (or one the contact dropped), still
    /// accepted ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Seed>,
    /// ... until then (Unix ms); `None`: a follower that has not yet seen
    /// the leader use `current`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retire_at_ms: Option<u64>,
    /// A leader's proposal, not yet acked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed: Option<Seed>,
    /// When `current` was adopted (a leader proposes again [`ROTATE_MS`]
    /// later).
    #[serde(default)]
    pub since_ms: u64,
    /// A follower: the generation the leader said it uses (its last entry's
    /// `acked`; 0: none).
    #[serde(default)]
    pub peer_acked: u32,
}

impl PairState {
    /// Nothing kept: the pair uses the root.
    pub fn is_empty(&self) -> bool {
        self.current.is_none() && self.previous.is_none() && self.proposed.is_none()
    }

    /// The previous seed goes once its time came; a retirement more than
    /// [`RETIRE_MS`] ahead (the clock went back) is brought back to that.
    pub fn prune(&mut self, now_ms: u64) {
        if let Some(at) = self.retire_at_ms {
            if now_ms >= at {
                self.previous = None;
                self.retire_at_ms = None;
            } else if at > now_ms.saturating_add(RETIRE_MS) {
                self.retire_at_ms = Some(now_ms.saturating_add(RETIRE_MS));
            }
        }
        if self.previous.is_none() {
            self.retire_at_ms = None;
        }
    }

    /// A leader's proposal is due: none is out, and the pair has no seed,
    /// or its seed is [`ROTATE_MS`] old and the one before it is gone (so a
    /// side never accepts more than three keys). A clock that went back by
    /// more than [`ROTATE_MS`] starts the wait over.
    fn proposal_due(&self, now_ms: u64) -> bool {
        self.proposed.is_none()
            && match &self.current {
                None => true,
                Some(_) => {
                    self.previous.is_none()
                        && (now_ms >= self.since_ms.saturating_add(ROTATE_MS)
                            || self.since_ms > now_ms.saturating_add(ROTATE_MS))
                }
            }
    }

    /// The next generation: one above every generation kept.
    fn next_generation(&self) -> u32 {
        [&self.current, &self.previous, &self.proposed]
            .into_iter()
            .flatten()
            .map(|s| s.generation)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(1)
    }

    /// The entry this side puts in its RRH1, without a new proposal.
    pub fn entry(&self, leader: bool) -> Option<SeedEntry> {
        let acked = self.current.as_ref().map_or(0, |s| s.generation);
        let offer = if leader {
            self.proposed.as_ref().or(self.current.as_ref())?
        } else {
            self.current.as_ref()?
        };
        Some(SeedEntry {
            generation: offer.generation,
            seed: Zeroizing::new(offer.seed),
            acked,
        })
    }

    /// A leader makes its proposal when one is due ([`Self::proposal_due`])
    /// with the 32 random bytes `fresh` gives: `true` when it did (store the
    /// state before the RRH1 that carries it goes out). A follower never
    /// proposes.
    pub fn propose(&mut self, leader: bool, now_ms: u64, fresh: impl FnOnce() -> [u8; 32]) -> bool {
        self.prune(now_ms);
        if !leader || !self.proposal_due(now_ms) {
            return false;
        }
        let mut seed = fresh();
        if seed == [0; 32] {
            seed[31] = 1;
        }
        self.proposed = Some(Seed {
            generation: self.next_generation(),
            seed,
        });
        true
    }

    /// The contact's RRH1 carried `entry` (`None`: none; it has no seed).
    /// A leader switches when it is the ack of its proposal; a follower
    /// adopts what the leader offers when it is not what it holds, and
    /// starts the previous seed's last [`RETIRE_MS`] once the leader says it
    /// uses the current one.
    pub fn incoming(&mut self, leader: bool, entry: Option<&SeedEntry>, now_ms: u64) {
        self.prune(now_ms);
        let Some(e) = entry.filter(|e| e.valid()) else {
            self.demote(now_ms);
            return;
        };
        if leader {
            let acks = self
                .proposed
                .as_ref()
                .is_some_and(|p| p.is(e) && e.acked == e.generation);
            if acks {
                let new = self.proposed.take().expect("checked above");
                if let Some(old) = self.current.replace(new) {
                    self.previous = Some(old);
                    self.retire_at_ms = Some(now_ms.saturating_add(RETIRE_MS));
                }
                self.since_ms = now_ms;
            }
            return;
        }
        self.proposed = None;
        if !self.current.as_ref().is_some_and(|c| c.is(e)) {
            // The seed it dropped comes back: it is the current one again.
            if self.previous.as_ref().is_some_and(|p| p.is(e)) {
                self.previous = None;
                self.retire_at_ms = None;
            }
            if let Some(old) = self.current.replace(Seed::of(e)) {
                self.previous = Some(old);
                self.retire_at_ms = None;
            }
            self.since_ms = now_ms;
        }
        self.peer_acked = e.acked;
        if e.acked == e.generation && self.previous.is_some() && self.retire_at_ms.is_none() {
            self.retire_at_ms = Some(now_ms.saturating_add(RETIRE_MS));
        }
    }

    /// The contact has no seed now: the current one becomes the previous
    /// one for [`RETIRE_MS`], and this side sends with the root. A leader's
    /// outstanding proposal stays (the contact may adopt it later).
    fn demote(&mut self, now_ms: u64) {
        if let Some(old) = self.current.take() {
            self.previous = Some(old);
            self.retire_at_ms = Some(now_ms.saturating_add(RETIRE_MS));
        }
        self.peer_acked = 0;
    }

    /// The seed this side sends with (`None`: the root).
    pub fn send_seed(&self) -> Option<&Seed> {
        self.current.as_ref()
    }

    /// The seeds a receiver tries before the root, in order: the current
    /// one, a leader's outstanding proposal, the previous one (at most
    /// three).
    pub fn accepted(&self, now_ms: u64) -> Vec<&Seed> {
        let previous = self
            .previous
            .as_ref()
            .filter(|_| self.retire_at_ms.is_none_or(|at| now_ms < at));
        let mut out: Vec<&Seed> = Vec::with_capacity(3);
        for s in [self.current.as_ref(), self.proposed.as_ref(), previous]
            .into_iter()
            .flatten()
        {
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }

    /// A match with the static root is a Notice: this side sends with a
    /// seed, and the contact is expected to as well (a leader's current seed
    /// was acked; a follower saw the leader say it uses one).
    pub fn root_is_notice(&self, leader: bool) -> bool {
        self.current.is_some() && (leader || self.peer_acked != 0)
    }
}

// ── Keys for the matchers ───────────────────────────────────────────────────

/// The keys R a contact's medium keys are made from
/// ([`crate::lan_beacon::medium_key`]), seen from this node: `accept` in the
/// order a receiver tries them (the current seed's `K_pair`, the leader's
/// proposal's or the previous seed's, the static root last), and the one it
/// sends with. Wiped on drop; `Debug` shows no key.
pub struct PairRoots {
    pub accept: Vec<Zeroizing<[u8; 32]>>,
    /// Which of `accept` this node sends with.
    pub send: usize,
    /// A match with the root (`accept`'s last) is a Notice
    /// ([`PairState::root_is_notice`]).
    pub root_notice: bool,
}

impl std::fmt::Debug for PairRoots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairRoots")
            .field("keys", &self.accept.len())
            .field("send", &self.send)
            .field("root_notice", &self.root_notice)
            .finish()
    }
}

impl PairRoots {
    /// The R this node sends with.
    pub fn send_key(&self) -> &[u8; 32] {
        &self.accept[self.send]
    }

    /// Is `index` of `accept` the static root?
    pub fn is_root(&self, index: usize) -> bool {
        index + 1 == self.accept.len()
    }

    /// A match at `index` of `accept` is the Notice of design B §5.
    pub fn notice_at(&self, index: usize) -> bool {
        self.root_notice && self.is_root(index)
    }
}

/// The [`PairRoots`] of `own` with `peer` from its state (`None`: no seed,
/// the root only), at `now_ms` (the checks and errors of [`pair_root`]).
pub fn roots(
    own: &Identity,
    peer: &[u8; 32],
    state: Option<&PairState>,
    now_ms: u64,
) -> Result<PairRoots, BeaconError> {
    let root = pair_root(own, peer)?;
    Ok(roots_from(
        &root,
        &own.public_key_bytes(),
        peer,
        state,
        now_ms,
    ))
}

/// [`roots`] from the pair's root.
pub fn roots_from(
    root: &[u8; 32],
    me: &[u8; 32],
    peer: &[u8; 32],
    state: Option<&PairState>,
    now_ms: u64,
) -> PairRoots {
    let Some(state) = state else {
        return PairRoots {
            accept: vec![Zeroizing::new(*root)],
            send: 0,
            root_notice: false,
        };
    };
    let seeds = state.accepted(now_ms);
    let mut accept: Vec<Zeroizing<[u8; 32]>> =
        seeds.iter().map(|s| pair_key(root, &s.seed)).collect();
    accept.push(Zeroizing::new(*root));
    // The current seed is always the first accepted one.
    let send = if state.send_seed().is_some() {
        0
    } else {
        accept.len() - 1
    };
    PairRoots {
        accept,
        send,
        root_notice: state.root_is_notice(is_leader(me, peer)),
    }
}

/// Every contact's seeds from one read of the file: empty while the gate is
/// shut or the file cannot be read (the root for everyone, as before).
#[derive(Debug, Default)]
pub struct SeedBook {
    pairs: BTreeMap<String, PairState>,
    now_ms: u64,
}

impl SeedBook {
    /// The book of `data_dir` at `now_ms` (`live`: the gate, which the
    /// caller reads, [`live`]).
    pub fn load(data_dir: &Path, live: bool, now_ms: u64) -> Self {
        let pairs = if live {
            read(data_dir).map(|f| f.pairs).unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        Self { pairs, now_ms }
    }

    /// `peer`'s state, if it has seeds.
    pub fn state(&self, peer: &[u8; 32]) -> Option<&PairState> {
        self.pairs.get(&key(peer))
    }

    /// The [`PairRoots`] of `own` with `peer`.
    pub fn roots(&self, own: &Identity, peer: &[u8; 32]) -> Result<PairRoots, BeaconError> {
        roots(own, peer, self.state(peer), self.now_ms)
    }
}

// ── The file ────────────────────────────────────────────────────────────────

/// The file's contents.
#[derive(Debug, Default, Serialize, Deserialize)]
struct SeedFile {
    /// States by the contact's identity key (lowercase hex).
    #[serde(default)]
    pairs: BTreeMap<String, PairState>,
}

impl SeedFile {
    /// Past [`MAX_PAIRS`], drop the pairs that switched longest ago (never
    /// `keep`).
    fn bound(&mut self, keep: &str) {
        while self.pairs.len() > MAX_PAIRS {
            let oldest = self
                .pairs
                .iter()
                .filter(|(k, _)| k.as_str() != keep)
                .min_by_key(|(k, s)| (s.since_ms, k.as_str()))
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => self.pairs.remove(&k),
                None => break,
            };
        }
    }
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(PAIR_SEEDS_FILE)
}

fn key(peer: &[u8; 32]) -> String {
    hex::encode(peer)
}

/// The seeds; empty for a missing file or plain bytes that do not parse, an
/// error for a file this process cannot read.
fn read(data_dir: &Path) -> Result<SeedFile, String> {
    match at_rest::load_json_advisory::<SeedFile>(data_dir, &path(data_dir), Kind::PairSeeds) {
        Advisory::Missing | Advisory::CorruptPlain => Ok(SeedFile::default()),
        Advisory::Loaded(file) => Ok(file),
        Advisory::Unreadable(e) => Err(format!("{PAIR_SEEDS_FILE}: {e}")),
    }
}

/// Change `peer`'s state under the file's lock: `edit` returns what the
/// caller gets, and the file is written only when the state changed (a
/// state left empty is removed).
fn change<R>(
    data_dir: &Path,
    peer: &[u8; 32],
    edit: impl FnOnce(&mut PairState) -> R,
) -> Result<R, String> {
    let k = key(peer);
    let path = path(data_dir);
    let lock = at_rest::lock_file(data_dir, &path, Kind::PairSeeds)
        .map_err(|e| format!("{PAIR_SEEDS_FILE}: {e}"))?;
    let mut file: SeedFile = at_rest::load_json_for_write(data_dir, &path, Kind::PairSeeds)
        .map_err(|e| format!("{PAIR_SEEDS_FILE}: {e}"))?;
    let before = file.pairs.get(&k).cloned();
    let mut state = before.clone().unwrap_or_default();
    let out = edit(&mut state);
    let after = (!state.is_empty()).then_some(state);
    if after == before {
        return Ok(out);
    }
    match after {
        Some(state) => {
            file.pairs.insert(k.clone(), state);
            file.bound(&k);
        }
        None => {
            file.pairs.remove(&k);
        }
    }
    lock.store_json(&file)
        .map_err(|e| format!("{PAIR_SEEDS_FILE}: {e}"))?;
    Ok(out)
}

/// The PAIR_SEED entry for this node's (`me`) RRH1 to `peer` at `now_ms`: a
/// leader makes its proposal first when one is due (32 bytes from `fresh`)
/// and stores it before it is offered. `None`: nothing to offer (a follower
/// without a seed). A proposal that cannot be stored is not made (the entry
/// offers what was there before); a file that cannot be read offers nothing
/// (the contact then uses the root, as this side does).
pub fn outgoing(
    data_dir: &Path,
    me: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
    fresh: impl FnOnce() -> [u8; 32],
) -> Option<SeedEntry> {
    let leader = is_leader(me, peer);
    let mut state = read(data_dir)
        .ok()?
        .pairs
        .remove(&key(peer))
        .unwrap_or_default();
    state.prune(now_ms);
    let before = state.entry(leader);
    if !state.clone().propose(leader, now_ms, || [1; 32]) {
        return before;
    }
    change(data_dir, peer, |s| {
        s.propose(leader, now_ms, fresh);
        s.entry(leader)
    })
    .unwrap_or(before)
}

/// `peer`'s RRH1 (from a verified contact, on an authenticated link) carried
/// `entry` (`None`: none) at `now_ms`; this node is `me`. Stored before it
/// returns.
pub fn incoming(
    data_dir: &Path,
    me: &[u8; 32],
    peer: &[u8; 32],
    entry: Option<&SeedEntry>,
    now_ms: u64,
) -> Result<(), String> {
    let leader = is_leader(me, peer);
    // Most links change nothing: a read without the lock first.
    let before = read(data_dir)?.pairs.remove(&key(peer));
    let mut state = before.clone().unwrap_or_default();
    state.incoming(leader, entry, now_ms);
    if (!state.is_empty()).then_some(state) == before {
        return Ok(());
    }
    change(data_dir, peer, |s| s.incoming(leader, entry, now_ms))
}

/// `peer`'s state, if it has seeds and the file can be read.
pub fn state(data_dir: &Path, peer: &[u8; 32]) -> Option<PairState> {
    read(data_dir).ok()?.pairs.remove(&key(peer))
}

/// The contact `peer` was removed: its seeds go (a contact added again
/// starts with the root). No write when the file does not name it; a file
/// that cannot be read is an error and stays as it is.
pub fn forget(data_dir: &Path, peer: &[u8; 32]) -> Result<(), String> {
    let k = key(peer);
    match at_rest::load_json_advisory::<SeedFile>(data_dir, &path(data_dir), Kind::PairSeeds) {
        Advisory::Missing | Advisory::CorruptPlain => return Ok(()),
        Advisory::Loaded(file) if !file.pairs.contains_key(&k) => return Ok(()),
        Advisory::Loaded(_) | Advisory::Unreadable(_) => {}
    }
    change(data_dir, peer, |s| *s = PairState::default())
}

mod hex_seed {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = zeroize::Zeroizing::new(String::deserialize(d)?);
        let v = zeroize::Zeroizing::new(hex::decode(s.as_str()).map_err(serde::de::Error::custom)?);
        v.as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

#[cfg(test)]
mod tests;
