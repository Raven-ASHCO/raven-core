//! RAVEN Link Knock V1 (RLK1, `protocol/RAVEN_LINK_KNOCK_V1.md`;
//! `docs/roadmap/plans/phase6-design.json` step P6.35, design B §3 and W-B2,
//! owner decision OD6b-9): a dialer that knows its contact proves it in Noise
//! XX message 1, and the listener proves itself in message 2, so both can use
//! a fresh Noise static on every connection and the dialer can tell whether
//! its friend answered before it sends message 3 (its own static) and its
//! signed identity.
//!
//! ```text
//! K_link     = medium_key(pair_root(A, B), 0x03)            (RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3a)
//! kq_X->Y    = HMAC-SHA256(K_link, "knock-q" || X || Y)
//! kr_X->Y    = HMAC-SHA256(K_link, "knock-r" || X || Y)
//! m1 payload = nonce16 || tag16 || pad(0..=31)
//!     tag16  = HMAC-SHA256(kq_A->B, "rlk1/m1" || day_u32_be || nonce16 || e_A)[0..16]
//! m2 payload = proof16 || pad(0..=31)
//!   proof16  = HMAC-SHA256(kr_B->A, "rlk1/m2" || nonce16 || e_A || s_B)[0..16]
//!              (16 random bytes when message 1 matched no contact)
//! ```
//!
//! A is the dialer, B the listener (32-byte Ed25519 identity keys), `e_A` the
//! dialer's XX ephemeral, `s_B` the static the listener uses on this
//! connection, `day = floor(unix_ms / 86,400,000)`; a listener accepts its
//! day and the days next to it.
//!
//! - **Listener** ([`hear`]: [`match_m1`], [`ReplayCache`],
//!   [`listener_mode`], [`answer`]): it reads message 1's raw bytes before
//!   it builds the Noise responder (XX message 1 is the ephemeral and a
//!   clear payload), tries every contact's key in constant time, and then
//!   picks its static: a fresh one for a contact that knocked; for anyone
//!   else the derived one in legacy mode (so pins of builds without the
//!   knock still match), a fresh one in strict mode, and no answer at all
//!   in silent mode. A nonce matched before is a replay and counts as no
//!   match.
//! - **Dialer** ([`Dialing`]: [`m1_payload`], [`check_m2`]; [`dialer_step`]):
//!   a valid proof lets it go on with a fresh static of its own; without
//!   one, an M0 pin that matches lets it go on with its derived static (a
//!   listener without the knock); a contact whose capability floor shows
//!   the knock and no pin stops before message 3; anyone else (a first
//!   contact) goes on as before.
//! - **Shape**: both payloads carry 0-31 random bytes, and message 3 carries
//!   an RLX1 `PAD` entry ([`m3_payload`]), so the three handshake messages
//!   have no fixed sizes.
//!
//! Pure: no I/O and no clock (callers pass the day and the time); the random
//! parts take a caller's RNG. The links use it only while
//! [`SecGate::LinkKnock`](crate::security_gate::SecGate::LinkKnock) is live
//! (`LINK_KNOCK_PRODUCTION_ENABLED = false`); with the gate shut every
//! handshake is byte for byte what earlier builds send. These keys only make
//! knock tags and proofs: never a message, session, route, mailbox or ACK
//! key. They live in memory, are wiped on drop and are never stored or
//! logged.

use std::collections::{HashSet, VecDeque};

use hmac::{Hmac, Mac};
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use snow::HandshakeState;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::identity::Identity;
use crate::lan_beacon::{medium_key, pair_root, BeaconError};
use crate::lan_noise::{
    build_initiator_with_static, derived_static_secret, get_remote_static, handshake_read,
    handshake_write, LanNoiseError,
};
use crate::node_policy::SilentMode;
use crate::route_hints::{rlx1_padded_min_len, rlx1_payload_padded, RLX1_MAX_LEN};

// The knock moves pins (M0) to a fallback for listeners without it; it is
// never live in release without them.
const _: () = assert!(
    !crate::security_gate::LINK_KNOCK_PRODUCTION_ENABLED
        || crate::lan_gate::LAN_NOISE_PIN_PRODUCTION_ENABLED
);

/// The medium byte of the link knock (RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3a
/// registry: `0x01` Bluetooth LE, `0x02` LAN beacon, `0x03` link knock).
pub const MEDIUM_LINK: u8 = 0x03;
/// The X25519 ephemeral at the start of XX message 1.
pub const E_LEN: usize = 32;
/// The knock's nonce.
pub const NONCE_LEN: usize = 16;
/// The knock's tag (a truncated HMAC-SHA256).
pub const TAG_LEN: usize = 16;
/// The listener's proof (a truncated HMAC-SHA256).
pub const PROOF_LEN: usize = 16;
/// Random bytes after a knock or a proof, at most.
pub const PAD_MAX: usize = 31;
/// The shortest knocked message 1 payload.
pub const M1_PAYLOAD_MIN: usize = NONCE_LEN + TAG_LEN;
/// The longest knocked message 1 payload.
pub const M1_PAYLOAD_MAX: usize = M1_PAYLOAD_MIN + PAD_MAX;
/// The shortest message 2 payload while the knock is on.
pub const M2_PAYLOAD_MIN: usize = PROOF_LEN;
/// The longest message 2 payload.
pub const M2_PAYLOAD_MAX: usize = PROOF_LEN + PAD_MAX;
/// Days are UTC days since the Unix epoch.
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// A listener tries at most this many contacts (the beacon's book bound).
pub const MAX_BOOK: usize = 1_024;
/// ... and at most this many key sets: a contact with pair seeds (Phase 6b,
/// [`crate::pair_seed`]) has up to three (the current seed's, the
/// proposal's or the previous seed's, the root's).
pub const MAX_BOOK_KEYS: usize = 3 * MAX_BOOK;
/// Matched nonces a listener remembers, at most.
pub const REPLAY_ENTRIES: usize = 4_096;
/// How long a matched nonce is remembered: a listener accepts a knock on
/// its own day and the days next to it, so one first matched early on day
/// D-1 (tagged D-1 or D) still matches until day D+1 ends, up to three days
/// later (Phase 6 review traffic-9; it was two).
pub const REPLAY_TTL_MS: u64 = 3 * DAY_MS;
/// The profile file a listener keeps its matched nonces in, so a knock
/// recorded before a restart is still a replay after it (raven-node; Phase 6
/// review traffic-9): [`ReplayCache::encode`]'s bytes, sealed in a sealed
/// profile (at-rest kind 112).
pub const KNOCK_REPLAYS_FILE: &str = "knock_replays.bin";
/// Its writer lock (`at_rest::FILES`).
pub const KNOCK_REPLAYS_LOCK: &str = ".at_rest.knock_replays.lock.sqlite";
/// The version byte [`ReplayCache::encode`] starts with.
const REPLAYS_VERSION: u8 = 1;
/// One remembered nonce in [`ReplayCache::encode`]'s bytes: when it matched
/// (u64 BE ms) and the nonce.
const REPLAY_RECORD: usize = 8 + NONCE_LEN;

const LABEL_Q: &[u8] = b"knock-q";
const LABEL_R: &[u8] = b"knock-r";
const LABEL_M1: &[u8] = b"rlk1/m1";
const LABEL_M2: &[u8] = b"rlk1/m2";

/// The day of a time: `floor(unix_ms / 86,400,000)` (saturating).
pub fn day_of(unix_ms: u64) -> u32 {
    u32::try_from(unix_ms / DAY_MS).unwrap_or(u32::MAX)
}

/// One contact's knock keys, from the pair's link medium key `K_link`, seen
/// from this node (`me`): `kq(me→peer)` for this node's knocks, `kq(peer→me)`
/// for the contact's, `kr(me→peer)` for this node's proofs and `kr(peer→me)`
/// for the contact's. Wiped on drop; `Debug` shows no key, not even the
/// contact's.
pub struct KnockKeys {
    /// The contact's Ed25519 identity key.
    pub peer: [u8; 32],
    q_out: Zeroizing<[u8; 32]>,
    q_in: Zeroizing<[u8; 32]>,
    r_out: Zeroizing<[u8; 32]>,
    r_in: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for KnockKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KnockKeys(..)")
    }
}

/// `K_link` of `own` and the contact key `peer` (the checks and errors of
/// [`pair_root`]).
pub fn link_key(own: &Identity, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, BeaconError> {
    let root = pair_root(own, peer)?;
    Ok(medium_key(&root, MEDIUM_LINK))
}

/// The [`KnockKeys`] of `own` with the contact key `peer` (the checks and
/// errors of [`pair_root`]).
pub fn knock_keys(own: &Identity, peer: &[u8; 32]) -> Result<KnockKeys, BeaconError> {
    let root = pair_root(own, peer)?;
    Ok(knock_keys_from(&own.public_key_bytes(), peer, &root))
}

/// The [`KnockKeys`] of this node (`me`) with `peer` from the key `r`
/// `K_link` comes from: the pair's root ([`pair_root`]), or `K_pair` of a
/// pair seed (Phase 6b, [`crate::pair_seed::pair_key`]).
pub fn knock_keys_from(me: &[u8; 32], peer: &[u8; 32], r: &[u8; 32]) -> KnockKeys {
    let k_link = medium_key(r, MEDIUM_LINK);
    let key = |label: &[u8], x: &[u8; 32], y: &[u8; 32]| {
        Zeroizing::new(hmac_sha256(&k_link, &[label, x.as_slice(), y.as_slice()]))
    };
    KnockKeys {
        peer: *peer,
        q_out: key(LABEL_Q, me, peer),
        q_in: key(LABEL_Q, peer, me),
        r_out: key(LABEL_R, me, peer),
        r_in: key(LABEL_R, peer, me),
    }
}

/// `tag16 = HMAC(kq, "rlk1/m1" || day_u32_be || nonce16 || e)[0..16]`.
pub fn m1_tag(kq: &[u8; 32], day: u32, nonce: &[u8; NONCE_LEN], e: &[u8; E_LEN]) -> [u8; TAG_LEN] {
    truncate(hmac_sha256(kq, &[LABEL_M1, &day.to_be_bytes(), nonce, e]))
}

/// `proof16 = HMAC(kr, "rlk1/m2" || nonce16 || e || s)[0..16]`.
pub fn m2_proof(
    kr: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    e: &[u8; E_LEN],
    s: &[u8; 32],
) -> [u8; PROOF_LEN] {
    truncate(hmac_sha256(kr, &[LABEL_M2, nonce, e, s]))
}

impl KnockKeys {
    /// The tag of this node's knock to the contact.
    pub fn tag_out(&self, day: u32, nonce: &[u8; NONCE_LEN], e: &[u8; E_LEN]) -> [u8; TAG_LEN] {
        m1_tag(&self.q_out, day, nonce, e)
    }

    /// The tag of the contact's knock to this node.
    pub fn tag_in(&self, day: u32, nonce: &[u8; NONCE_LEN], e: &[u8; E_LEN]) -> [u8; TAG_LEN] {
        m1_tag(&self.q_in, day, nonce, e)
    }

    /// This node's proof to the contact (this node listens with `s`).
    pub fn proof_out(
        &self,
        nonce: &[u8; NONCE_LEN],
        e: &[u8; E_LEN],
        s: &[u8; 32],
    ) -> [u8; PROOF_LEN] {
        m2_proof(&self.r_out, nonce, e, s)
    }

    /// The contact's proof to this node (the contact listens with `s`).
    pub fn proof_in(
        &self,
        nonce: &[u8; NONCE_LEN],
        e: &[u8; E_LEN],
        s: &[u8; 32],
    ) -> [u8; PROOF_LEN] {
        m2_proof(&self.r_in, nonce, e, s)
    }
}

/// The dialer's message 1 payload for the contact of `keys` on `day`, with
/// its XX ephemeral `e`: `nonce || tag || pad`, with a fresh nonce and 0-31
/// random bytes from `rng`. Also returns the nonce (for [`check_m2`]).
pub fn m1_payload<R: RngCore + CryptoRng>(
    keys: &KnockKeys,
    day: u32,
    e: &[u8; E_LEN],
    rng: &mut R,
) -> (Vec<u8>, [u8; NONCE_LEN]) {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let pad = random_pad(rng);
    (m1_payload_with(keys, day, e, &nonce, &pad), nonce)
}

/// [`m1_payload`] with the nonce and the trailing bytes given (vectors).
/// `pad` longer than [`PAD_MAX`] is cut.
pub fn m1_payload_with(
    keys: &KnockKeys,
    day: u32,
    e: &[u8; E_LEN],
    nonce: &[u8; NONCE_LEN],
    pad: &[u8],
) -> Vec<u8> {
    let pad = &pad[..pad.len().min(PAD_MAX)];
    let mut out = Vec::with_capacity(M1_PAYLOAD_MIN + pad.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&keys.tag_out(day, nonce, e));
    out.extend_from_slice(pad);
    out
}

/// What a listener found in a message 1 ([`match_m1`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct M1Match {
    /// Which contact of the book knocked (its index).
    pub index: usize,
    /// That contact's key.
    pub peer: [u8; 32],
    /// The knock's nonce (the replay cache, and the proof).
    pub nonce: [u8; NONCE_LEN],
    /// The dialer's ephemeral (the proof).
    pub e: [u8; E_LEN],
}

/// The contact of `book` whose knock is in the raw XX message 1 `raw_m1`
/// (`e || payload`), for the listener's `day` (its day and the days next to
/// it are accepted). Every contact and day is tried, whatever matched
/// already, and each tag is compared in constant time. `None`: a payload of
/// another length (an empty one is a dialer without the knock), no match, or
/// more than one (never for real keys). Only the first [`MAX_BOOK_KEYS`]
/// key sets are tried (at most [`MAX_BOOK`] contacts, up to three each).
pub fn match_m1(book: &[KnockKeys], raw_m1: &[u8], day: u32) -> Option<M1Match> {
    let (e, payload) = split_m1(raw_m1)?;
    if !(M1_PAYLOAD_MIN..=M1_PAYLOAD_MAX).contains(&payload.len()) {
        return None;
    }
    let nonce: [u8; NONCE_LEN] = payload[..NONCE_LEN].try_into().ok()?;
    let tag = &payload[NONCE_LEN..M1_PAYLOAD_MIN];
    let days = [day.saturating_sub(1), day, day.saturating_add(1)];
    let mut found: Option<usize> = None;
    let mut matches = 0u32;
    for (i, keys) in book.iter().take(MAX_BOOK_KEYS).enumerate() {
        let mut hit = false;
        for d in days {
            hit |= ct_eq(&keys.tag_in(d, &nonce, &e), tag);
        }
        if hit {
            matches += 1;
            found = Some(i);
        }
    }
    let index = found.filter(|_| matches == 1)?;
    Some(M1Match {
        index,
        peer: book[index].peer,
        nonce,
        e,
    })
}

/// `e` and the payload of a raw XX message 1 (at least the ephemeral).
pub fn split_m1(raw_m1: &[u8]) -> Option<([u8; E_LEN], &[u8])> {
    let e: [u8; E_LEN] = raw_m1.get(..E_LEN)?.try_into().ok()?;
    Some((e, &raw_m1[E_LEN..]))
}

/// The listener's message 2 payload for a dialer that knocked: `proof ||
/// pad` over the knock's nonce and ephemeral and the static `s` this
/// listener uses on this connection.
pub fn m2_payload<R: RngCore + CryptoRng>(
    keys: &KnockKeys,
    nonce: &[u8; NONCE_LEN],
    e: &[u8; E_LEN],
    s: &[u8; 32],
    rng: &mut R,
) -> Vec<u8> {
    let pad = random_pad(rng);
    m2_payload_with(keys, nonce, e, s, &pad)
}

/// [`m2_payload`] with the trailing bytes given (vectors). `pad` longer than
/// [`PAD_MAX`] is cut.
pub fn m2_payload_with(
    keys: &KnockKeys,
    nonce: &[u8; NONCE_LEN],
    e: &[u8; E_LEN],
    s: &[u8; 32],
    pad: &[u8],
) -> Vec<u8> {
    let pad = &pad[..pad.len().min(PAD_MAX)];
    let mut out = Vec::with_capacity(PROOF_LEN + pad.len());
    out.extend_from_slice(&keys.proof_out(nonce, e, s));
    out.extend_from_slice(pad);
    out
}

/// The listener's message 2 payload for a dialer that did not knock (or
/// whose knock was a replay): 16 random bytes and 0-31 more, so its length
/// says nothing about a match.
pub fn m2_payload_unmatched<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<u8> {
    let mut out = vec![0u8; PROOF_LEN + random_pad_len(rng)];
    rng.fill_bytes(&mut out);
    out
}

/// Does the listener's message 2 payload `payload` prove the contact of
/// `keys` (the dialer knocked with `nonce` and its ephemeral `e`; `s` is the
/// static message 2 carried)? Compared in constant time; any length outside
/// 16..=47 is no proof.
pub fn check_m2(
    keys: &KnockKeys,
    nonce: &[u8; NONCE_LEN],
    e: &[u8; E_LEN],
    s: &[u8; 32],
    payload: &[u8],
) -> bool {
    (M2_PAYLOAD_MIN..=M2_PAYLOAD_MAX).contains(&payload.len())
        && ct_eq(&keys.proof_in(nonce, e, s), &payload[..PROOF_LEN])
}

/// The dialer's message 3 payload while it knocks: RLX1 with `LINK_CAPS`
/// `caps` (none when 0) and a `PAD` entry that brings it to a random length
/// up to [`RLX1_MAX_LEN`] (route hints spec §3.2, entry `0x7E`).
pub fn m3_payload<R: RngCore>(caps: u32, rng: &mut R) -> Vec<u8> {
    let min = rlx1_padded_min_len(caps);
    let span = (RLX1_MAX_LEN - min + 1) as u32;
    let total = min + (rng.next_u32() % span) as usize;
    rlx1_payload_padded(caps, total)
}

/// Matched nonces a listener has seen (at most [`REPLAY_ENTRIES`], each for
/// [`REPLAY_TTL_MS`]). One cache serves every listener of a process, so a
/// knock recorded on one link is a replay on the other too, and raven-node
/// keeps it in the profile ([`KNOCK_REPLAYS_FILE`], [`Self::encode`],
/// [`Self::decode`]) so a restart forgets nothing.
#[derive(Debug, Default)]
pub struct ReplayCache {
    order: VecDeque<(u64, [u8; NONCE_LEN])>,
    seen: HashSet<[u8; NONCE_LEN]>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// A matched knock with `nonce` at `now_ms`: `true` when that nonce was
    /// matched before within [`REPLAY_TTL_MS`] (a replay: answer it as no
    /// match), otherwise it is remembered and `false`. Past
    /// [`REPLAY_ENTRIES`] the oldest goes.
    pub fn replayed(&mut self, nonce: &[u8; NONCE_LEN], now_ms: u64) -> bool {
        while let Some(&(at, old)) = self.order.front() {
            if now_ms.saturating_sub(at) < REPLAY_TTL_MS {
                break;
            }
            self.order.pop_front();
            self.seen.remove(&old);
        }
        if self.seen.contains(nonce) {
            return true;
        }
        if self.order.len() >= REPLAY_ENTRIES {
            if let Some((_, old)) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.order.push_back((now_ms, *nonce));
        self.seen.insert(*nonce);
        false
    }

    /// Nonces remembered now.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// The nonces remembered, with when each matched, oldest first.
    pub fn entries(&self) -> impl Iterator<Item = (u64, [u8; NONCE_LEN])> + '_ {
        self.order.iter().copied()
    }

    /// The cache as [`KNOCK_REPLAYS_FILE`] keeps it: a version byte, then
    /// each nonce remembered, oldest first, as when it matched (u64 BE ms)
    /// and the nonce.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.order.len() * REPLAY_RECORD);
        out.push(REPLAYS_VERSION);
        for (at, nonce) in &self.order {
            out.extend_from_slice(&at.to_be_bytes());
            out.extend_from_slice(nonce);
        }
        out
    }

    /// A cache from [`Self::encode`]'s bytes, at `now_ms`: a nonce
    /// remembered [`REPLAY_TTL_MS`] or longer is gone, as is each one past
    /// the newest [`REPLAY_ENTRIES`]; bytes of another version or length
    /// are an empty cache.
    pub fn decode(bytes: &[u8], now_ms: u64) -> Self {
        let mut cache = Self::new();
        let Some((&REPLAYS_VERSION, records)) = bytes.split_first() else {
            return cache;
        };
        let (records, rest) = records.as_chunks::<REPLAY_RECORD>();
        if !rest.is_empty() {
            return cache;
        }
        for record in records {
            let (at, nonce) = record.split_at(8);
            let at = u64::from_be_bytes(at.try_into().expect("8 bytes"));
            let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("16 bytes");
            if now_ms.saturating_sub(at) >= REPLAY_TTL_MS || !cache.seen.insert(nonce) {
                continue;
            }
            cache.order.push_back((at, nonce));
        }
        while cache.order.len() > REPLAY_ENTRIES {
            if let Some((_, old)) = cache.order.pop_front() {
                cache.seen.remove(&old);
            }
        }
        cache
    }
}

/// How a listener answers a dialer without a valid knock (design B §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerMode {
    /// With the derived static, which builds without the knock pin (M0).
    Legacy,
    /// With a fresh static: nobody but a knocking contact sees a static
    /// twice.
    Strict,
    /// Not at all: the connection closes before message 2.
    Silent,
}

/// The listener's mode from the user's setting and whether every contact's
/// capability floor shows the knock (`every_contact_knocks`; true for an
/// empty book): `On` is silent, `Off` legacy, `Automatic` strict once every
/// contact knocks and legacy until then.
pub fn listener_mode(setting: SilentMode, every_contact_knocks: bool) -> ListenerMode {
    match setting {
        SilentMode::On => ListenerMode::Silent,
        SilentMode::Off => ListenerMode::Legacy,
        SilentMode::Automatic if every_contact_knocks => ListenerMode::Strict,
        SilentMode::Automatic => ListenerMode::Legacy,
    }
}

/// What a listener does with one message 1 ([`answer`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Message 2 with a fresh static; `proof`: it carries the proof for the
    /// contact that knocked (otherwise random bytes of the same length).
    Fresh { proof: bool },
    /// Message 2 with the derived static and random bytes for a proof.
    Derived,
    /// No message 2: the connection closes.
    Close,
}

/// The decision table of design B §3: a contact that knocked gets a fresh
/// static and the proof whatever the mode; anyone else the derived static
/// (legacy), a fresh one (strict) or nothing (silent).
pub fn answer(mode: ListenerMode, matched: bool) -> Answer {
    match (matched, mode) {
        (true, _) => Answer::Fresh { proof: true },
        (false, ListenerMode::Legacy) => Answer::Derived,
        (false, ListenerMode::Strict) => Answer::Fresh { proof: false },
        (false, ListenerMode::Silent) => Answer::Close,
    }
}

/// The dialer's M0 pin for the contact it dials, against the static message
/// 2 carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinCheck {
    /// No pin (or pins are off).
    None,
    Match,
    Mismatch,
}

/// What a knocking dialer does after message 2 ([`dialer_step`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialerStep {
    /// The proof verified: go on with a fresh static of its own.
    Fresh,
    /// No proof, and the pin matched or there is nothing to hold the
    /// listener to: go on with the derived static, as before the knock.
    Derived,
    /// No proof and another static than the pinned one: stop before message
    /// 3 (M0).
    StopPin,
    /// No proof, no pin, and the contact's capability floor shows the knock:
    /// stop before message 3.
    StopKnock,
}

/// The dialer's decision table of design B §3: a valid proof, then the M0
/// pin, then the contact's capability floor (`floor_knock`: a link of the
/// contact's carried the knock before), then today's behaviour.
pub fn dialer_step(proof_ok: bool, pin: PinCheck, floor_knock: bool) -> DialerStep {
    match (proof_ok, pin) {
        (true, _) => DialerStep::Fresh,
        (false, PinCheck::Mismatch) => DialerStep::StopPin,
        (false, PinCheck::Match) => DialerStep::Derived,
        (false, PinCheck::None) if floor_knock => DialerStep::StopKnock,
        (false, PinCheck::None) => DialerStep::Derived,
    }
}

/// The static a listener answers one message 1 with and message 2's
/// payload ([`hear`]). The static is wiped on drop; `Debug` shows neither.
pub struct Reply {
    pub static_secret: StaticSecret,
    pub payload: Vec<u8>,
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reply(..)")
    }
}

/// What a listener made of one raw message 1 ([`hear`]).
#[derive(Debug)]
pub struct Heard {
    /// Message 2's static and payload; `None`: close without message 2
    /// (silent mode).
    pub reply: Option<Reply>,
    /// The contact whose knock matched (not a replay): it got a fresh
    /// static and the proof, and it uses a fresh static of its own.
    pub matched: Option<[u8; 32]>,
    /// The book entry that matched (a contact with pair seeds has several,
    /// Phase 6b: was it the static root's?).
    pub matched_index: Option<usize>,
    /// The knock matched a contact with a nonce matched before
    /// (SEC_KNOCK_REPLAY): answered as no match.
    pub replay: bool,
}

/// The listener's side of design B §3 for one raw XX message 1 `raw_m1`
/// (spec §4): [`match_m1`] against `book` on the day of `now_ms`, a match
/// checked against `replays`, then [`answer`] in `mode`, and the static and
/// message 2 payload it calls for: a fresh static and the proof for the
/// contact that knocked, the derived static of `identity` (legacy) or a
/// fresh one (strict) with 16-47 random bytes for anyone else, nothing in
/// silent mode. Fresh statics, pads and random payloads come from `rng`.
pub fn hear<R: RngCore + CryptoRng>(
    book: &[KnockKeys],
    mode: ListenerMode,
    identity: &Identity,
    raw_m1: &[u8],
    now_ms: u64,
    replays: &mut ReplayCache,
    rng: &mut R,
) -> Result<Heard, LanNoiseError> {
    let found = match_m1(book, raw_m1, day_of(now_ms));
    let replay = found.is_some_and(|m| replays.replayed(&m.nonce, now_ms));
    let found = found.filter(|_| !replay);
    let reply = match answer(mode, found.is_some()) {
        Answer::Close => None,
        Answer::Derived => Some(Reply {
            static_secret: derived_static_secret(identity)?,
            payload: m2_payload_unmatched(rng),
        }),
        Answer::Fresh { proof } => {
            let static_secret = StaticSecret::random_from_rng(&mut *rng);
            let s = PublicKey::from(&static_secret).to_bytes();
            let payload = match found.filter(|_| proof) {
                Some(m) => m2_payload(&book[m.index], &m.nonce, &m.e, &s, rng),
                None => m2_payload_unmatched(rng),
            };
            Some(Reply {
                static_secret,
                payload,
            })
        }
    };
    Ok(Heard {
        reply,
        matched: found.map(|m| m.peer),
        matched_index: found.map(|m| m.index),
        replay,
    })
}

/// A knocking dialer's Noise XX handshake (spec §4): it draws its own
/// ephemeral (the knock covers it, so it must be known before snow writes
/// message 1) and writes message 1 from a state that holds its derived
/// static; after message 2 it goes on with that state (a listener without
/// the knock pins the derived static, M0) or builds the same handshake
/// again with a fresh static and the same ephemeral ([`Self::finish`]):
/// XX sends the initiator's static only in message 3, so messages 1 and 2
/// are the same for both states. The ephemeral and a fresh static are
/// wiped on drop; `Debug` shows nothing.
pub struct Dialing {
    ephemeral: StaticSecret,
    e: [u8; E_LEN],
    nonce: [u8; NONCE_LEN],
    payload: Vec<u8>,
    m1: Vec<u8>,
    derived_pub: [u8; 32],
    prologue: Option<&'static [u8]>,
    hs: HandshakeState,
}

impl std::fmt::Debug for Dialing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dialing(..)")
    }
}

impl Dialing {
    /// Message 1 to the contact of `keys` on `day` with the carrier's
    /// `prologue` (`None` on LAN): a fresh ephemeral, nonce and 0-31
    /// trailing bytes from `rng`, written by a state that holds `identity`'s
    /// derived static.
    pub fn start<R: RngCore + CryptoRng>(
        identity: &Identity,
        keys: &KnockKeys,
        day: u32,
        prologue: Option<&'static [u8]>,
        rng: &mut R,
    ) -> Result<Self, LanNoiseError> {
        let ephemeral = StaticSecret::random_from_rng(&mut *rng);
        let e = PublicKey::from(&ephemeral).to_bytes();
        let (payload, nonce) = m1_payload(keys, day, &e, rng);
        let derived = derived_static_secret(identity)?;
        let derived_pub = PublicKey::from(&derived).to_bytes();
        let mut hs = build_initiator_with_static(&derived, &ephemeral, prologue)?;
        let m1 = handshake_write(&mut hs, &payload)?;
        Ok(Self {
            ephemeral,
            e,
            nonce,
            payload,
            m1,
            derived_pub,
            prologue,
            hs,
        })
    }

    /// Message 1 as it goes on the wire (`e || nonce || tag || pad`).
    pub fn m1(&self) -> &[u8] {
        &self.m1
    }

    /// Read message 2: the listener's static, and whether its payload is
    /// the proof of the contact of `keys` ([`check_m2`]).
    pub fn read_m2(
        &mut self,
        keys: &KnockKeys,
        m2: &[u8],
    ) -> Result<([u8; 32], bool), LanNoiseError> {
        let payload = handshake_read(&mut self.hs, m2)?;
        let s = get_remote_static(&self.hs)?;
        Ok((s, check_m2(keys, &self.nonce, &self.e, &s, &payload)))
    }

    /// The state that writes message 3 and the public key of the static it
    /// holds: with `fresh` (the proof verified) the handshake built again
    /// with a fresh static from `rng` (message 1 written and `m2`, the
    /// message 2 [`Self::read_m2`] read, read again), else the derived
    /// static's state as it is.
    pub fn finish<R: RngCore + CryptoRng>(
        self,
        fresh: bool,
        m2: &[u8],
        rng: &mut R,
    ) -> Result<(HandshakeState, [u8; 32]), LanNoiseError> {
        if !fresh {
            return Ok((self.hs, self.derived_pub));
        }
        let static_secret = StaticSecret::random_from_rng(&mut *rng);
        let mut hs = build_initiator_with_static(&static_secret, &self.ephemeral, self.prologue)?;
        if handshake_write(&mut hs, &self.payload)? != self.m1 {
            return Err(LanNoiseError::Handshake);
        }
        handshake_read(&mut hs, m2)?;
        Ok((hs, PublicKey::from(&static_secret).to_bytes()))
    }
}

/// 0-31 random bytes.
fn random_pad<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let mut pad = vec![0u8; random_pad_len(rng)];
    rng.fill_bytes(&mut pad);
    pad
}

/// A length in 0..=31, uniform.
fn random_pad_len<R: RngCore>(rng: &mut R) -> usize {
    (rng.next_u32() % (PAD_MAX as u32 + 1)) as usize
}

fn truncate(mac: [u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

/// HMAC-SHA256 of the concatenated `parts`.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac takes any key");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Constant-time equality: every byte pair is compared, wherever the first
/// difference is.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests;
