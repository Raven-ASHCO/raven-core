//! RAVEN_LAN_BEACON_V1 (Phase 3 item 2): the keys, datagram codec and
//! matching of the contact-only, solicited LAN beacon. Pure: no socket, no
//! clock, no file. raven-node's beacon task (P3.10) sends and receives the
//! datagrams, keeps the rate limits and holds the candidates.
//!
//! - **One R2 pairwise root per pair** ([`pair_root`]): X25519 between the
//!   Montgomery forms of the two pinned Ed25519 identity keys (the collapsed
//!   device tier: device key = identity key), so it works from a contact card
//!   alone. HKDF-SHA256 with salt [`R2_PAIR_SALT`] and info
//!   `"root" || lo || hi` (the two keys sorted bytewise) turns the secret into
//!   the root. Every medium takes its own key from it with a medium byte
//!   ([`medium_key`]): [`MEDIUM_LAN`] here, [`MEDIUM_BLE`] for Bluetooth LE
//!   nearby ([`crate::nearby_link`], RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3b).
//! - **Directional keys** ([`PairKeys`]): HMACs of the LAN medium key over
//!   `"query"` or `"reply"` and both keys in the direction's order, so a
//!   datagram of one direction never verifies in the other. A query key is
//!   narrowed to the epoch ([`EPOCH_SECS`]) before use; receivers accept the
//!   epochs next to theirs (a long-lived receiver keeps a book's narrowed
//!   keys per epoch, [`EpochKeys`]).
//! - **Datagrams** ([`QUERY_LEN`], [`ANSWER_LEN`]) hold a fresh nonce and PRF
//!   outputs only: no constant byte, identity, address, PeerId, fingerprint,
//!   clear-text port, timestamp or counter. A query names up to [`SLOTS`]
//!   contacts in fixed-size slots at random positions, and unused slots are
//!   random bytes, so only a named contact can tell its slot from padding and
//!   nobody can count the real slots. Both datagrams bind the sender's source
//!   address ([`ip16`]).
//! - **Length jitter** (Phase 6b, people study M13; the v1 amendment made
//!   before the beacon's production flip): a sender adds 0 to
//!   [`QUERY_TAIL_MAX`] (or [`ANSWER_TAIL_MAX`]) random bytes ([`with_tail`]),
//!   and a receiver reads the first [`QUERY_LEN`] (or [`ANSWER_LEN`]) bytes of
//!   any datagram of 160..=191 (or 48..=63) bytes and ignores the rest
//!   ([`kind_of`]). raven-node adds the timing jitter.
//! - **Discovery only.** A match is an untrusted LAN dial candidate: Noise
//!   XX, the RLB1 identity bind and the contact gate decide everything.
//!
//! These keys are only for beacon tags (never a message, session, route,
//! mailbox or ACK key). They live in memory, are wiped on drop and are never
//! stored or logged.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::identity::Identity;

/// Phase 3 item 2: the LAN beacon (UDP [`BEACON_PORT`]). false until the
/// owner approves RAVEN_PRIVATE_RENDEZVOUS_V1 revision 4, the independent
/// crypto review of the static bootstrap is done (R2 §14 item 4) and Swift
/// checks the vectors.
pub const LAN_BEACON_PRODUCTION_ENABLED: bool = false;

/// The beacon is live: [`LAN_BEACON_PRODUCTION_ENABLED`], or in a debug build
/// `RAVEN_LAB_LAN_BEACON=1` (a release build never reads it); unless a
/// security notice holds it (P6.45, close-only) or a debug lab run carries
/// over nearby alone ([`crate::nearby_gate::nearby_only`]).
pub fn lan_beacon_live() -> bool {
    crate::nearby_gate::unless_nearby_only(
        (LAN_BEACON_PRODUCTION_ENABLED
            || crate::p2p_gate::lab_flag(cfg!(debug_assertions), || {
                std::env::var("RAVEN_LAB_LAN_BEACON").ok()
            }))
            && crate::suite_policy::hold_allows(crate::suite_registry::FEATURE_LAN_BEACON),
    )
}

/// IPv4 group (IPv4 Local Scope, RFC 2365), sent with TTL 1 (and to the
/// interface's subnet broadcast address).
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 74, 20);
/// IPv6 group (link-local scope, a dynamic group ID per RFC 3307), sent with
/// hop limit 1.
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x8000, 0x7420);
/// UDP destination port of every beacon datagram: a fixed transport
/// identifier of the spec, not the LAN TCP listener's port.
pub const BEACON_PORT: u16 = 7420;
/// The most contacts one query names.
pub const SLOTS: usize = 8;
/// One slot: tag[16] || port_x[2].
const SLOT_LEN: usize = 18;
/// The nonce that starts a query (and an answer).
const NONCE_LEN: usize = 16;
/// A query: nonce[16] || slot[8] (160 bytes).
pub const QUERY_LEN: usize = NONCE_LEN + SLOTS * SLOT_LEN;
/// An answer: r_nonce[16] || port_x[2] || tag[30].
pub const ANSWER_LEN: usize = 48;
/// The most random bytes a sender puts after a query's [`QUERY_LEN`]
/// (Phase 6b W-B3): receivers read the first [`QUERY_LEN`] and ignore them.
pub const QUERY_TAIL_MAX: usize = 31;
/// The most random bytes a sender puts after an answer's [`ANSWER_LEN`].
pub const ANSWER_TAIL_MAX: usize = 15;
/// The longest query a receiver reads (191 bytes).
pub const QUERY_MAX_LEN: usize = QUERY_LEN + QUERY_TAIL_MAX;
/// The longest answer a receiver reads (63 bytes).
pub const ANSWER_MAX_LEN: usize = ANSWER_LEN + ANSWER_TAIL_MAX;
// A datagram's type is its length (anything else is dropped), so the two
// length ranges are part of the wire, and they must not meet.
const _: () = assert!(
    QUERY_LEN == 160
        && ANSWER_LEN == NONCE_LEN + 2 + 30
        && QUERY_MAX_LEN == 191
        && ANSWER_MAX_LEN == 63
        && ANSWER_MAX_LEN < QUERY_LEN
);
/// How long a user send (`raven send`, the terminal app) lets raven-node
/// look for a contact on the local network (IPC `LanLocate`'s `wait_ms`),
/// and the longest raven-node waits (§8). It outlasts one find under the
/// amended send shape (Phase 6b W-B3) when the query's first copy is lost:
/// the round gathers wants for 300 ms, the query's first copy goes up to
/// 500 ms later and its second up to 400 ms after that, and the answer's
/// first copy waits up to 500 ms: 1.7 s and the round trip (Phase 6 review
/// traffic-3; raven-node checks the sum at compile time).
pub const LOCATE_SEND_WAIT_MS: u32 = 2_000;
/// e = floor(unix_seconds / 600); a receiver accepts e-1..=e+1 of its own.
pub const EPOCH_SECS: u64 = 600;
/// HKDF-SHA256 salt of the R2 pairwise root (one root per pair for every
/// medium).
pub const R2_PAIR_SALT: &[u8] = b"rvn1/r2-pair/v1";
/// Medium byte of Bluetooth LE nearby ([`crate::nearby_link`],
/// RAVEN_NEARBY_LINK_V1 §2).
pub const MEDIUM_BLE: u8 = 0x01;
/// Medium byte of this beacon.
pub const MEDIUM_LAN: u8 = 0x02;

/// What a datagram is, by its length (§3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramKind {
    /// 160..=191 bytes: the first [`QUERY_LEN`] are the query.
    Query,
    /// 48..=63 bytes: the first [`ANSWER_LEN`] are the answer.
    Answer,
}

/// The kind of a datagram of `len` bytes; `None` (dropped with no effect)
/// for any length outside 160..=191 and 48..=63.
pub fn kind_of(len: usize) -> Option<DatagramKind> {
    match len {
        QUERY_LEN..=QUERY_MAX_LEN => Some(DatagramKind::Query),
        ANSWER_LEN..=ANSWER_MAX_LEN => Some(DatagramKind::Answer),
        _ => None,
    }
}

/// `datagram` (a query or an answer of its exact length) as a sender puts
/// it on the wire (Phase 6b W-B3): with 0..=[`QUERY_TAIL_MAX`] (a query) or
/// 0..=[`ANSWER_TAIL_MAX`] (an answer) fresh random bytes after it, the
/// number drawn uniformly. Receivers ignore them, so the length no longer
/// tells one sender's datagrams from another's.
///
/// # Panics
/// When `datagram` is neither [`QUERY_LEN`] nor [`ANSWER_LEN`] bytes long.
pub fn with_tail(rng: &mut dyn RngCore, datagram: &[u8]) -> Vec<u8> {
    let most = match datagram.len() {
        QUERY_LEN => QUERY_TAIL_MAX,
        ANSWER_LEN => ANSWER_TAIL_MAX,
        n => panic!("a query or an answer, not {n} bytes"),
    };
    let mut out = Vec::with_capacity(datagram.len() + most);
    out.extend_from_slice(datagram);
    let mut tail = [0u8; QUERY_TAIL_MAX];
    let tail = &mut tail[..rng.gen_range(0..=most)];
    rng.fill_bytes(tail);
    out.extend_from_slice(tail);
    out
}

/// Why a contact key gets no beacon keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BeaconError {
    /// The key does not decode as a point, is not canonically encoded, is
    /// weak (small order) or is this identity's own key.
    #[error("not a usable contact key for the LAN beacon")]
    BadKey,
    /// X25519 gave the all-zero secret.
    #[error("the pairwise secret is not contributory")]
    NonContributory,
}

/// R2 pairwise root (RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3a): shared by every medium.
///
/// `Z = X25519(own scalar, Montgomery(peer))`, which equals the peer's
/// `X25519(peer scalar, Montgomery(own))`; the root is
/// HKDF-SHA256(salt [`R2_PAIR_SALT`], ikm Z, info `"root" || lo || hi`, 32)
/// with `lo`, `hi` the two identity keys sorted bytewise, so both sides
/// derive the same root. [`BeaconError::BadKey`]: `peer` does not decode,
/// is not canonically encoded (re-compressing it gives other bytes), is
/// weak or is `own`'s key. [`BeaconError::NonContributory`]: Z is all zero.
pub fn pair_root(own: &Identity, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, BeaconError> {
    let vk = VerifyingKey::from_bytes(peer).map_err(|_| BeaconError::BadKey)?;
    if vk.to_edwards().compress().to_bytes() != *peer
        || vk.is_weak()
        || *peer == own.public_key_bytes()
    {
        return Err(BeaconError::BadKey);
    }
    root_from(
        &own.x25519_agreement_scalar(),
        vk.to_montgomery().to_bytes(),
        &own.public_key_bytes(),
        peer,
    )
}

/// [`pair_root`] after the key checks: X25519 with the peer's Montgomery
/// u-coordinate `peer_u`, the contributory check and the HKDF. A key that
/// passes those checks never gives an all-zero Z (only a small-order point
/// does), so the tests reach this check here.
fn root_from(
    scalar: &[u8; 32],
    peer_u: [u8; 32],
    me: &[u8; 32],
    peer: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, BeaconError> {
    let z = StaticSecret::from(*scalar).diffie_hellman(&PublicKey::from(peer_u));
    if !z.was_contributory() {
        return Err(BeaconError::NonContributory);
    }
    let (lo, hi) = if me <= peer { (me, peer) } else { (peer, me) };
    let mut root = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(R2_PAIR_SALT), z.as_bytes())
        .expand(
            &[b"root".as_slice(), lo.as_slice(), hi.as_slice()].concat(),
            root.as_mut_slice(),
        )
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(root)
}

/// One medium's key from the pairwise root: HKDF-Expand(PRK = root,
/// info = `"medium" || medium`, 32) ([`MEDIUM_LAN`], [`MEDIUM_BLE`]).
pub fn medium_key(root: &[u8; 32], medium: u8) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::from_prk(root)
        .expect("a 32-byte PRK is long enough")
        .expand(
            &[b"medium".as_slice(), &[medium]].concat(),
            key.as_mut_slice(),
        )
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// One contact's beacon keys, from the pair's LAN medium key `K_lan`:
/// `K_q(X→Y) = HMAC(K_lan, "query" || X || Y)` for X's queries to Y and
/// `K_r(Y→X) = HMAC(K_lan, "reply" || Y || X)` for Y's answers to X. Wiped
/// on drop; the beacon task rebuilds them when the contact book or block
/// list changes. `Debug` shows no key, not even the contact's.
pub struct PairKeys {
    /// The contact's Ed25519 identity key.
    pub peer: [u8; 32],
    /// K_q(me→peer): this node's queries naming the contact.
    q_out: Zeroizing<[u8; 32]>,
    /// K_q(peer→me): the contact's queries naming this node.
    q_in: Zeroizing<[u8; 32]>,
    /// K_r(me→peer): this node's answers to the contact.
    r_out: Zeroizing<[u8; 32]>,
    /// K_r(peer→me): the contact's answers to this node.
    r_in: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for PairKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairKeys(..)")
    }
}

/// The [`PairKeys`] of `own` with the contact key `peer` (the checks and
/// errors of [`pair_root`]).
pub fn pair_keys(own: &Identity, peer: &[u8; 32]) -> Result<PairKeys, BeaconError> {
    let root = pair_root(own, peer)?;
    Ok(pair_keys_from(&own.public_key_bytes(), peer, &root))
}

/// The [`PairKeys`] of this node (`me`) with `peer` from the key `r` the
/// medium keys come from: the pair's root ([`pair_root`]), or `K_pair` of a
/// pair seed (Phase 6b, [`crate::pair_seed::pair_key`], which takes the
/// root's place in [`medium_key`]).
pub fn pair_keys_from(me: &[u8; 32], peer: &[u8; 32], r: &[u8; 32]) -> PairKeys {
    let lan = medium_key(r, MEDIUM_LAN);
    let me = *me;
    let key = |label: &[u8], x: &[u8; 32], y: &[u8; 32]| {
        Zeroizing::new(hmac_sha256(&lan, &[label, x.as_slice(), y.as_slice()]))
    };
    PairKeys {
        peer: *peer,
        q_out: key(b"query", &me, peer),
        q_in: key(b"query", peer, &me),
        r_out: key(b"reply", &me, peer),
        r_in: key(b"reply", peer, &me),
    }
}

/// The beacon epoch of a time: `unix_secs / EPOCH_SECS`.
pub fn epoch_at(unix_secs: u64) -> u64 {
    unix_secs / EPOCH_SECS
}

/// The 16 address bytes a tag binds: IPv4 as `::ffff:a.b.c.d`, IPv6 as it
/// is. A zone is never part of it, and an IPv4-mapped IPv6 address gives the
/// same bytes as its IPv4 address.
pub fn ip16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// A query (160 bytes, before [`with_tail`]) from the bound address `src`
/// naming `targets`: a fresh nonce, each target's slot at a uniformly random
/// position and 18 fresh random bytes in every other slot. A repeated
/// contact gets one slot, and targets after the first [`SLOTS`] are left
/// out (the caller names them in its next round). `port` is this node's LAN
/// listener port that can be reached on this interface, 0 if there is none.
/// A real slot is
/// `h[0..16] || (port_be ^ h[16..18])` with
/// `h = HMAC(HMAC(K_q, "epoch" || e_be), nonce || ip16(src))`.
pub fn build_query(
    rng: &mut dyn RngCore,
    epoch: u64,
    src: IpAddr,
    port: u16,
    targets: &[&PairKeys],
) -> [u8; QUERY_LEN] {
    let mut named: Vec<&PairKeys> = Vec::with_capacity(SLOTS);
    for &k in targets {
        if named.len() < SLOTS && named.iter().all(|n| n.peer != k.peer) {
            named.push(k);
        }
    }
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let mut order: [usize; SLOTS] = std::array::from_fn(|i| i);
    order.shuffle(rng);
    let pads = SLOTS - named.len();
    let mut padding = [[0u8; SLOT_LEN]; SLOTS];
    for pad in &mut padding[..pads] {
        rng.fill_bytes(pad);
    }
    build_query_with(
        nonce,
        &order[..named.len()],
        &padding[..pads],
        epoch,
        src,
        port,
        &named,
    )
}

/// [`build_query`] with its random parts given, for the vectors and the
/// fuzz target (not test-only: node/fuzz builds outside `cfg(test)`):
/// `positions[i]` is the slot of `targets[i]`, and `padding` fills the other
/// slots in slot order. Nothing is skipped or capped here.
///
/// # Panics
/// When the positions are not distinct slots, one per target, or `padding`
/// does not fill exactly the other slots.
#[doc(hidden)]
pub fn build_query_with(
    nonce: [u8; 16],
    positions: &[usize],
    padding: &[[u8; 18]],
    epoch: u64,
    src: IpAddr,
    port: u16,
    targets: &[&PairKeys],
) -> [u8; QUERY_LEN] {
    assert!(
        positions.len() == targets.len() && targets.len() + padding.len() == SLOTS,
        "one position per target and one padding per other slot"
    );
    let mut q = [0u8; QUERY_LEN];
    q[..NONCE_LEN].copy_from_slice(&nonce);
    let mut used = [false; SLOTS];
    let port = port.to_be_bytes();
    for (k, &pos) in targets.iter().zip(positions) {
        assert!(pos < SLOTS && !used[pos], "positions are distinct slots");
        used[pos] = true;
        let h = query_tag(&k.q_out, epoch, &nonce, src);
        let slot = slot_mut(&mut q, pos);
        slot[..16].copy_from_slice(&h[..16]);
        slot[16] = port[0] ^ h[16];
        slot[17] = port[1] ^ h[17];
    }
    let free: Vec<usize> = (0..SLOTS).filter(|&p| !used[p]).collect();
    for (pos, pad) in free.into_iter().zip(padding) {
        slot_mut(&mut q, pos).copy_from_slice(pad);
    }
    q
}

/// The contacts of `book` that a query from `src` names: `(index in book,
/// the querier's port)` in book order, at most one per contact. Each
/// contact's query key is tried at the epochs `now_epoch - 1 ..= now_epoch +
/// 1` against every slot (constant-time compare). The port is 0 when the
/// querier has no listener there. A query of 161..=191 bytes is read as its
/// first [`QUERY_LEN`] (the tail is ignored); a datagram of any other length
/// names nobody. A match is not admission: the caller still runs the LAN
/// link gate.
pub fn match_query(q: &[u8], src: IpAddr, now_epoch: u64, book: &[PairKeys]) -> Vec<(usize, u16)> {
    if kind_of(q.len()) != Some(DatagramKind::Query) {
        return Vec::new();
    }
    match_query_with(q, src, &EpochKeys::new(book, now_epoch))
}

/// A book's query keys narrowed to the epochs a receiver at `now_epoch`
/// accepts (`now_epoch - 1 ..= now_epoch + 1`, within u64): what
/// [`match_query`] derives for every query. raven-node's beacon task keeps
/// one per epoch and book ([`match_query_epochs`]), so a query costs one
/// HMAC per contact and epoch. Wiped on drop; `Debug` shows no key.
pub struct EpochKeys {
    now_epoch: u64,
    /// The first epoch of the window (`now_epoch - 1`, or 0).
    first_epoch: u64,
    /// Per book entry, `HMAC(K_q(C→me), "epoch" || e)` for each accepted
    /// epoch `e`, in epoch order.
    keys: Vec<Vec<Zeroizing<[u8; 32]>>>,
}

impl std::fmt::Debug for EpochKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochKeys(..)")
    }
}

impl EpochKeys {
    /// The epoch keys of `book` (in its order) for a receiver at
    /// `now_epoch`.
    pub fn new(book: &[PairKeys], now_epoch: u64) -> Self {
        let first_epoch = now_epoch.saturating_sub(1);
        let epochs = first_epoch..=now_epoch.saturating_add(1);
        let keys = book
            .iter()
            .map(|k| epochs.clone().map(|e| epoch_key(&k.q_in, e)).collect())
            .collect();
        Self {
            now_epoch,
            first_epoch,
            keys,
        }
    }

    /// The receiver's epoch they were made for.
    pub fn epoch(&self) -> u64 {
        self.now_epoch
    }

    /// The offset from the receiver's epoch of the window's epoch at `at`.
    fn offset(&self, at: usize) -> i8 {
        let epoch = self.first_epoch + at as u64;
        match epoch.cmp(&self.now_epoch) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }
}

/// [`match_query`] with the book's [`EpochKeys`] made beforehand: the same
/// contacts and ports, in the same order.
pub fn match_query_with(q: &[u8], src: IpAddr, book: &EpochKeys) -> Vec<(usize, u16)> {
    match_query_epochs(q, src, book)
        .into_iter()
        .map(|m| (m.index, m.port))
        .collect()
}

/// One contact a query names ([`match_query_epochs`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryMatch {
    /// The contact's place in the book.
    pub index: usize,
    /// The querier's port; 0 when it has no listener there.
    pub port: u16,
    /// The epoch the slot was made for, less the receiver's own: -1, 0 or
    /// +1. It bounds the querier's clock by when the slot matched: at +1, `p`
    /// seconds into the receiver's epoch, it runs more than
    /// [`EPOCH_SECS`] - `p` ahead of the receiver's; at -1, more than `p`
    /// behind. A skew of seconds matches next door near every epoch's edge,
    /// so the offset alone is no measure. A local fact for the receiver: it
    /// changes no rule and nothing that is sent.
    pub offset: i8,
}

/// [`match_query_with`] that also says at which epoch each contact matched
/// ([`QueryMatch::offset`]): the same contacts and ports, in the same order.
pub fn match_query_epochs(q: &[u8], src: IpAddr, book: &EpochKeys) -> Vec<QueryMatch> {
    let mut found = Vec::new();
    if kind_of(q.len()) != Some(DatagramKind::Query) {
        return found;
    }
    let (nonce, slots) = q[..QUERY_LEN].split_at(NONCE_LEN);
    let slots = slots.as_chunks::<SLOT_LEN>().0;
    let src = ip16(src);
    for (i, epochs) in book.keys.iter().enumerate() {
        let mut hit = None;
        for (at, epoch_key) in epochs.iter().enumerate() {
            let h = hmac_sha256(epoch_key, &[nonce, &src]);
            for slot in slots {
                if ct_eq(&slot[..16], &h[..16]) && hit.is_none() {
                    let port = u16::from_be_bytes([slot[16] ^ h[16], slot[17] ^ h[17]]);
                    hit = Some((port, book.offset(at)));
                }
            }
        }
        if let Some((port, offset)) = hit {
            found.push(QueryMatch {
                index: i,
                port,
                offset,
            });
        }
    }
    found
}

/// An answer (48 bytes, before [`with_tail`]) to a query of `k.peer` with
/// nonce `q_nonce`: `src` is this node's bound address on the interface
/// where the query arrived, `dst` the query's source, and `port` this node's
/// LAN listener port there. It is `r_nonce || (port_be ^ h[0..2]) ||
/// h[2..32]` with
/// `h = HMAC(K_r, q_nonce || r_nonce || ip16(src) || ip16(dst))`. A node with
/// no listener that can be reached there sends no answer: [`open_answer`]
/// refuses port 0.
pub fn build_answer(
    rng: &mut dyn RngCore,
    k: &PairKeys,
    q_nonce: &[u8; 16],
    src: IpAddr,
    dst: IpAddr,
    port: u16,
) -> [u8; ANSWER_LEN] {
    let mut r_nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut r_nonce);
    answer_with(r_nonce, k, q_nonce, src, dst, port)
}

/// [`build_answer`] with its nonce given (the tests and the vectors).
fn answer_with(
    r_nonce: [u8; 16],
    k: &PairKeys,
    q_nonce: &[u8; 16],
    src: IpAddr,
    dst: IpAddr,
    port: u16,
) -> [u8; ANSWER_LEN] {
    let h = answer_tag(&k.r_out, q_nonce, &r_nonce, src, dst);
    let port = port.to_be_bytes();
    let mut a = [0u8; ANSWER_LEN];
    a[..NONCE_LEN].copy_from_slice(&r_nonce);
    a[NONCE_LEN] = port[0] ^ h[0];
    a[NONCE_LEN + 1] = port[1] ^ h[1];
    a[NONCE_LEN + 2..].copy_from_slice(&h[2..]);
    a
}

/// The port in an answer of `k.peer` to this node's query with nonce
/// `q_nonce`: `src` is the answer's source and `dst` this node's bound
/// address on that interface. An answer of 49..=63 bytes is read as its
/// first [`ANSWER_LEN`] (the tail is ignored). `None` for another length, a
/// tag that does not verify (constant-time compare) or port 0. The port is
/// not covered by the tag: a flipped port costs one dial that the Noise bind
/// refuses.
pub fn open_answer(
    a: &[u8],
    k: &PairKeys,
    q_nonce: &[u8; 16],
    src: IpAddr,
    dst: IpAddr,
) -> Option<u16> {
    if kind_of(a.len()) != Some(DatagramKind::Answer) {
        return None;
    }
    let (r_nonce, rest) = a[..ANSWER_LEN].split_at(NONCE_LEN);
    let h = answer_tag(&k.r_in, q_nonce, r_nonce, src, dst);
    if !ct_eq(&rest[2..], &h[2..]) {
        return None;
    }
    let port = u16::from_be_bytes([rest[0] ^ h[0], rest[1] ^ h[1]]);
    (port != 0).then_some(port)
}

/// HMAC-SHA256 of the concatenated `parts`.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac takes any key");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// `HMAC(K_q, "epoch" || e_be)`: a query key narrowed to one epoch.
fn epoch_key(query_key: &[u8; 32], epoch: u64) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hmac_sha256(query_key, &[b"epoch", &epoch.to_be_bytes()]))
}

/// A query slot's `h`: `HMAC(epoch_key(K_q, e), nonce || ip16(src))`.
fn query_tag(query_key: &[u8; 32], epoch: u64, nonce: &[u8], src: IpAddr) -> [u8; 32] {
    hmac_sha256(&epoch_key(query_key, epoch), &[nonce, &ip16(src)])
}

/// An answer's `h`: `HMAC(K_r, q_nonce || r_nonce || ip16(src) || ip16(dst))`.
fn answer_tag(
    reply_key: &[u8; 32],
    q_nonce: &[u8],
    r_nonce: &[u8],
    src: IpAddr,
    dst: IpAddr,
) -> [u8; 32] {
    hmac_sha256(reply_key, &[q_nonce, r_nonce, &ip16(src), &ip16(dst)])
}

/// Slot `pos` of a query.
fn slot_mut(q: &mut [u8; QUERY_LEN], pos: usize) -> &mut [u8] {
    &mut q[NONCE_LEN + pos * SLOT_LEN..NONCE_LEN + (pos + 1) * SLOT_LEN]
}

/// Constant-time equality, like `nearby`'s `constant_eq_ascii`: every byte
/// pair is compared, wherever the first difference is.
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
mod tests {
    use std::collections::HashSet;

    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use serde_json::{json, Value};

    use super::*;

    /// RFC 8032 section 7.1 tests 1-3 (the shared vectors' alice, bob and
    /// carol).
    const ALICE: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const BOB: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const CAROL: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    /// The vectors' dave: 32 bytes of 0x44.
    const DAVE: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    /// The vectors' time ([`E`] is its epoch).
    const NOW_S: u64 = 1_700_000_000;
    /// The vectors' epoch: `epoch_at(1_700_000_000)`.
    const E: u64 = 2_833_333;
    /// Alice's bound address here.
    const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    /// Bob's.
    const BOB_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30));

    /// The eight points of small order, each canonically encoded: the
    /// identity point (order 1), orders 2, 4, 4, and four of order 8.
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    /// Montgomery u-coordinates for which X25519 gives the all-zero secret
    /// whatever the scalar: 0, 1, two points of order 8, p - 1, and p and
    /// p + 1 (0 and 1 not reduced).
    const NON_CONTRIBUTORY_U: [&str; 7] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    fn bytes32(hex_text: &str) -> [u8; 32] {
        hex::decode(hex_text).unwrap().try_into().unwrap()
    }

    fn id(seed: &str) -> Identity {
        Identity::from_seed(&bytes32(seed))
    }

    /// The vectors' dave (32 bytes of 0x44).
    fn dave() -> Identity {
        Identity::from_seed(&[0x44; 32])
    }

    fn keys(own: &Identity, peer: &Identity) -> PairKeys {
        pair_keys(own, &peer.public_key_bytes()).unwrap()
    }

    fn slot(q: &[u8], pos: usize) -> &[u8] {
        &q[NONCE_LEN + pos * SLOT_LEN..NONCE_LEN + (pos + 1) * SLOT_LEN]
    }

    /// The slots of `q` holding the tag of `k`'s queries at epoch `e` from
    /// `src`.
    fn slots_of(q: &[u8], k: &PairKeys, e: u64, src: IpAddr) -> Vec<usize> {
        let h = query_tag(&k.q_out, e, &q[..NONCE_LEN], src);
        (0..SLOTS)
            .filter(|&p| slot(q, p)[..16] == h[..16])
            .collect()
    }

    fn mapped(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
            v6 => v6,
        }
    }

    #[test]
    fn root_is_symmetric_medium_keys_differ_and_directional_keys_differ() {
        let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
        let ab = pair_root(&a, &b.public_key_bytes()).unwrap();
        assert_eq!(*ab, *pair_root(&b, &a.public_key_bytes()).unwrap());
        assert_ne!(*ab, *pair_root(&a, &c.public_key_bytes()).unwrap());
        assert_ne!(*ab, *pair_root(&b, &c.public_key_bytes()).unwrap());
        // One key per medium byte, none of them the root itself.
        let mut media: Vec<[u8; 32]> = (0..=u8::MAX).map(|m| *medium_key(&ab, m)).collect();
        assert!(!media.contains(&*ab));
        media.sort_unstable();
        media.dedup();
        assert_eq!(media.len(), 256);
        let (lan, ble) = (medium_key(&ab, MEDIUM_LAN), medium_key(&ab, MEDIUM_BLE));
        assert_ne!(*lan, *ble);
        // Bob's keys for alice mirror alice's for bob ...
        let (at_a, at_b) = (keys(&a, &b), keys(&b, &a));
        assert_eq!(at_a.peer, b.public_key_bytes());
        assert_eq!(at_b.peer, a.public_key_bytes());
        assert_eq!(*at_a.q_out, *at_b.q_in);
        assert_eq!(*at_a.q_in, *at_b.q_out);
        assert_eq!(*at_a.r_out, *at_b.r_in);
        assert_eq!(*at_a.r_in, *at_b.r_out);
        // ... and a pair's four keys differ from each other, from both
        // medium keys and from the root.
        let four = [*at_a.q_out, *at_a.q_in, *at_a.r_out, *at_a.r_in];
        for (i, k) in four.iter().enumerate() {
            assert!(four[i + 1..].iter().all(|other| other != k), "key {i}");
            assert!(![*ab, *lan, *ble].contains(k), "key {i}");
        }
        // They are the LAN medium key's (§2.2), never the BLE one's.
        let (me, peer) = (a.public_key_bytes(), b.public_key_bytes());
        assert_eq!(*at_a.q_out, hmac_sha256(&lan, &[b"query", &me, &peer]));
        assert_eq!(*at_a.r_in, hmac_sha256(&lan, &[b"reply", &peer, &me]));
        assert_ne!(*at_a.q_out, hmac_sha256(&ble, &[b"query", &me, &peer]));
        // Another pair, other keys; Debug shows none.
        assert_ne!(*keys(&a, &c).q_out, *at_a.q_out);
        assert_eq!(format!("{at_a:?}"), "PairKeys(..)");
    }

    #[test]
    fn weak_small_order_noncanonical_and_self_keys_are_refused() {
        let a = id(ALICE);
        let refused = |key: &[u8; 32]| {
            let what = hex::encode(key);
            assert_eq!(
                pair_root(&a, key).unwrap_err(),
                BeaconError::BadKey,
                "{what}"
            );
            assert_eq!(
                pair_keys(&a, key).unwrap_err(),
                BeaconError::BadKey,
                "{what}"
            );
        };
        for point in SMALL_ORDER {
            let key = bytes32(point);
            // Real points, canonically encoded: the weak check refuses them.
            let vk = VerifyingKey::from_bytes(&key).unwrap();
            assert!(vk.is_weak(), "{point}");
            assert_eq!(vk.to_edwards().compress().to_bytes(), key, "{point}");
            refused(&key);
        }
        // y = p + 3 (with either sign bit) decodes to the point y = 3, which
        // is not weak; re-compressing it gives other bytes.
        for noncanonical in [
            "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            let key = bytes32(noncanonical);
            let vk = VerifyingKey::from_bytes(&key).unwrap();
            assert!(!vk.is_weak());
            assert_ne!(vk.to_edwards().compress().to_bytes(), key);
            refused(&key);
        }
        // Other encodings of small-order points: y = p + 1 (the identity) and
        // x = 0 with the sign bit set.
        for other in [
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0100000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            refused(&bytes32(other));
        }
        // Not a point (y = 2 is not on the curve).
        let mut two = [0u8; 32];
        two[0] = 2;
        assert!(VerifyingKey::from_bytes(&two).is_err());
        refused(&two);
        refused(&a.public_key_bytes());
        assert!(pair_root(&a, &id(BOB).public_key_bytes()).is_ok());
    }

    /// X25519 gives the all-zero secret for the small-order Montgomery
    /// u-coordinates (and their non-canonical forms) whatever the scalar. No
    /// key that passes `pair_root`'s checks maps to one of them, so this
    /// check is reached through `root_from`.
    #[test]
    fn non_contributory_shared_secret_is_refused() {
        let (a, b) = (id(ALICE), id(BOB));
        let (me, peer) = (a.public_key_bytes(), b.public_key_bytes());
        let scalar = a.x25519_agreement_scalar();
        for u in NON_CONTRIBUTORY_U {
            let u = bytes32(u);
            assert_eq!(x25519_dalek::x25519(*scalar, u), [0u8; 32]);
            assert_eq!(
                root_from(&scalar, u, &me, &peer).unwrap_err(),
                BeaconError::NonContributory
            );
        }
        // The same path with bob's real Montgomery form is pair_root's.
        let u = VerifyingKey::from_bytes(&peer)
            .unwrap()
            .to_montgomery()
            .to_bytes();
        assert_eq!(
            *root_from(&scalar, u, &me, &peer).unwrap(),
            *pair_root(&a, &peer).unwrap()
        );
    }

    #[test]
    fn query_matches_only_the_named_contact_and_returns_its_port() {
        let (a, b, c, d) = (id(ALICE), id(BOB), id(CAROL), dave());
        let (to_b, to_c) = (keys(&a, &b), keys(&a, &c));
        let mut rng = StdRng::seed_from_u64(1);
        let q = build_query(&mut rng, E, SRC, 7420, &[&to_b, &to_c]);
        // Bob and carol each find their slot; dave holds alice too but is
        // not named.
        let bob_book = [keys(&b, &d), keys(&b, &a), keys(&b, &c)];
        assert_eq!(match_query(&q, SRC, E, &bob_book), vec![(1, 7420)]);
        let carol_book = [keys(&c, &a)];
        assert_eq!(match_query(&q, SRC, E, &carol_book), vec![(0, 7420)]);
        let dave_book = [keys(&d, &a), keys(&d, &b), keys(&d, &c)];
        assert!(match_query(&q, SRC, E, &dave_book).is_empty());
        // Alice's own query (an echo) names nobody in her book.
        let alice_book = [keys(&a, &b), keys(&a, &c), keys(&a, &d)];
        assert!(match_query(&q, SRC, E, &alice_book).is_empty());
        // Each target carries the querier's port; 0 means no listener.
        let q = build_query(&mut rng, E, SRC, 51_234, &[&to_c, &to_b]);
        assert_eq!(match_query(&q, SRC, E, &bob_book), vec![(1, 51_234)]);
        let q = build_query(&mut rng, E, SRC, 0, &[&to_b]);
        assert_eq!(match_query(&q, SRC, E, &bob_book), vec![(1, 0)]);
        assert!(match_query(&q, SRC, E, &carol_book).is_empty());
        // A query naming nobody, and other lengths, name nobody. A tail of
        // up to 31 bytes is ignored (Phase 6b W-B3), a 32nd refuses it.
        let empty = build_query(&mut rng, E, SRC, 7420, &[]);
        assert!(match_query(&empty, SRC, E, &bob_book).is_empty());
        let q = build_query(&mut rng, E, SRC, 7420, &[&to_b]);
        assert!(match_query(&q[..QUERY_LEN - 1], SRC, E, &bob_book).is_empty());
        let mut long = q.to_vec();
        long.push(0);
        assert_eq!(match_query(&long, SRC, E, &bob_book), vec![(1, 7420)]);
        long.resize(QUERY_MAX_LEN + 1, 0);
        assert!(match_query(&long, SRC, E, &bob_book).is_empty());
        assert!(match_query(&q[..ANSWER_LEN], SRC, E, &bob_book).is_empty());
        assert!(match_query(&[], SRC, E, &bob_book).is_empty());
        assert!(match_query(&q, SRC, E, &[]).is_empty());
    }

    fn chi_square(counts: &[u64; 256]) -> f64 {
        let expected = counts.iter().sum::<u64>() as f64 / 256.0;
        counts
            .iter()
            .map(|&n| (n as f64 - expected).powi(2) / expected)
            .sum()
    }

    #[test]
    fn padding_and_real_slots_are_indistinguishable_and_positions_vary() {
        let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
        let (to_b, to_c) = (keys(&a, &b), keys(&a, &c));
        let mut rng = StdRng::seed_from_u64(2);
        let mut positions = [[0u32; SLOTS]; 2];
        let (mut real, mut padding) = ([0u64; 256], [0u64; 256]);
        // The bytes that carry the port (the same 7420 in every query).
        let mut port_bytes = [[0u32; 256]; 2];
        for _ in 0..1000 {
            let q = build_query(&mut rng, E, SRC, 7420, &[&to_b, &to_c]);
            let mut is_real = [false; SLOTS];
            for (t, k) in [&to_b, &to_c].into_iter().enumerate() {
                let at = slots_of(&q, k, E, SRC);
                assert_eq!(at.len(), 1);
                positions[t][at[0]] += 1;
                is_real[at[0]] = true;
            }
            for (pos, real_slot) in is_real.into_iter().enumerate() {
                let s = slot(&q, pos);
                let counts = if real_slot { &mut real } else { &mut padding };
                for &byte in s {
                    counts[usize::from(byte)] += 1;
                }
                if real_slot {
                    port_bytes[0][usize::from(s[16])] += 1;
                    port_bytes[1][usize::from(s[17])] += 1;
                }
            }
        }
        // Each target lands in every slot, about equally often (125 of 1000).
        for (t, per_slot) in positions.iter().enumerate() {
            assert!(
                per_slot.iter().all(|n| (60..=200).contains(n)),
                "target {t}: {per_slot:?}"
            );
        }
        // Real slots and padding both look uniform (chi-square over 256
        // values: mean 255, sd 22.6), and no port byte value stands out
        // (2000 real slots: 7.8 of each value expected).
        let (chi_real, chi_padding) = (chi_square(&real), chi_square(&padding));
        assert!(chi_real < 400.0, "real slots: {chi_real}");
        assert!(chi_padding < 400.0, "padding: {chi_padding}");
        for counts in port_bytes {
            assert!(counts.iter().all(|&n| n < 40), "{counts:?}");
        }
    }

    #[test]
    fn epoch_window_accepts_e_minus_1_to_e_plus_1_only() {
        assert_eq!(epoch_at(1_700_000_000), E);
        assert_eq!(epoch_at(0), 0);
        assert_eq!(epoch_at(EPOCH_SECS - 1), 0);
        assert_eq!(epoch_at(EPOCH_SECS), 1);
        let (a, b) = (id(ALICE), id(BOB));
        let to_b = keys(&a, &b);
        let book = [keys(&b, &a)];
        let mut rng = StdRng::seed_from_u64(3);
        let q = build_query(&mut rng, E, SRC, 7420, &[&to_b]);
        for (now, named) in [
            (E - 2, false),
            (E - 1, true),
            (E, true),
            (E + 1, true),
            (E + 2, false),
        ] {
            let found = match_query(&q, SRC, now, &book);
            assert_eq!(found == vec![(0, 7420)], named, "answerer at epoch {now}");
            assert!(named || found.is_empty(), "answerer at epoch {now}");
        }
        // The ends of the range do not wrap.
        let q = build_query(&mut rng, 0, SRC, 7420, &[&to_b]);
        assert_eq!(match_query(&q, SRC, 0, &book), vec![(0, 7420)]);
        assert_eq!(match_query(&q, SRC, 1, &book), vec![(0, 7420)]);
        assert!(match_query(&q, SRC, 2, &book).is_empty());
        assert!(match_query(&q, SRC, u64::MAX, &book).is_empty());
        let q = build_query(&mut rng, u64::MAX, SRC, 7420, &[&to_b]);
        assert_eq!(match_query(&q, SRC, u64::MAX, &book), vec![(0, 7420)]);
        assert_eq!(match_query(&q, SRC, u64::MAX - 1, &book), vec![(0, 7420)]);
        assert!(match_query(&q, SRC, 0, &book).is_empty());
    }

    /// Phase 3 P3.C3 (F11b): a match says at which of the receiver's three
    /// epochs it was made, as the querier's epoch less the receiver's (its
    /// clock ahead: +1, behind: -1), at the ends of the range too; the
    /// contacts and ports are [`match_query_with`]'s.
    #[test]
    fn a_match_says_the_queriers_epoch_offset() {
        let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
        let book = [keys(&b, &a), keys(&c, &a)];
        let (to_b, to_c) = (keys(&a, &b), keys(&a, &c));
        let mut rng = StdRng::seed_from_u64(12);
        let found = |q: &[u8], now: u64| -> Vec<(usize, u16, i8)> {
            match_query_epochs(q, SRC, &EpochKeys::new(&book, now))
                .into_iter()
                .map(|m| (m.index, m.port, m.offset))
                .collect()
        };
        for (sent, offset) in [(E - 1, Some(-1)), (E, Some(0)), (E + 1, Some(1))] {
            let q = build_query(&mut rng, sent, SRC, 7420, &[&to_b, &to_c]);
            let want: Vec<(usize, u16, i8)> =
                offset.map_or(Vec::new(), |o| vec![(0, 7420, o), (1, 7420, o)]);
            assert_eq!(found(&q, E), want, "sent at {sent}");
            let cached = EpochKeys::new(&book, E);
            assert_eq!(
                match_query_with(&q, SRC, &cached),
                vec![(0, 7420), (1, 7420)]
            );
        }
        for sent in [E - 2, E + 2] {
            let q = build_query(&mut rng, sent, SRC, 7420, &[&to_b]);
            assert!(found(&q, E).is_empty(), "sent at {sent}");
        }
        // The ends of the range: no wrap, and the offsets still say which.
        let q = build_query(&mut rng, 1, SRC, 0, &[&to_b]);
        assert_eq!(found(&q, 0), vec![(0, 0, 1)]);
        let q = build_query(&mut rng, 0, SRC, 0, &[&to_b]);
        assert_eq!(found(&q, 0), vec![(0, 0, 0)]);
        let q = build_query(&mut rng, u64::MAX - 1, SRC, 9, &[&to_c]);
        assert_eq!(found(&q, u64::MAX), vec![(1, 9, -1)]);
        assert!(found(&q[..QUERY_LEN - 1], u64::MAX).is_empty());
    }

    #[test]
    fn source_ip_is_bound() {
        assert_eq!(
            ip16(SRC),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 20]
        );
        assert_eq!(ip16(mapped(SRC)), ip16(SRC));
        let (a, b) = (id(ALICE), id(BOB));
        let to_b = keys(&a, &b);
        let book = [keys(&b, &a)];
        let mut rng = StdRng::seed_from_u64(4);
        let q = build_query(&mut rng, E, SRC, 7420, &[&to_b]);
        assert_eq!(match_query(&q, SRC, E, &book), vec![(0, 7420)]);
        // v4 and v4-mapped are the same source.
        assert_eq!(match_query(&q, mapped(SRC), E, &book), vec![(0, 7420)]);
        for other in [
            "192.168.1.21",
            "10.0.0.20",
            "::ffff:192.168.1.21",
            "::192.168.1.20",
            "fe80::1",
        ] {
            let other: IpAddr = other.parse().unwrap();
            assert!(match_query(&q, other, E, &book).is_empty(), "{other}");
        }
        // IPv6 binds its 16 bytes (a zone is not part of an IpAddr).
        let ll: IpAddr = "fe80::1234".parse().unwrap();
        assert_eq!(ip16(ll), "fe80::1234".parse::<Ipv6Addr>().unwrap().octets());
        let q = build_query(&mut rng, E, ll, 7420, &[&to_b]);
        assert_eq!(match_query(&q, ll, E, &book), vec![(0, 7420)]);
        for other in ["fe80::1235", "fd00::1234", "::ffff:192.168.1.20"] {
            let other: IpAddr = other.parse().unwrap();
            assert!(match_query(&q, other, E, &book).is_empty(), "{other}");
        }
    }

    #[test]
    fn at_most_one_match_per_contact() {
        let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
        let (to_b, to_c) = (keys(&a, &b), keys(&a, &c));
        let book = [keys(&b, &a)];
        let nonce = [7u8; 16];
        let pad = |n: usize| vec![[0x55u8; 18]; n];
        // Bob in two slots of one query (build_query never does this).
        let twice = build_query_with(nonce, &[1, 6], &pad(6), E, SRC, 7420, &[&to_b, &to_b]);
        assert_eq!(slots_of(&twice, &to_b, E, SRC), vec![1, 6]);
        assert_eq!(match_query(&twice, SRC, E, &book), vec![(0, 7420)]);
        // Bob's slots for two epochs in one query (e in slot 1, e + 1 in
        // slot 6, another port): still one match.
        let now = build_query_with(nonce, &[1], &pad(7), E, SRC, 7420, &[&to_b]);
        let next = build_query_with(nonce, &[6], &pad(7), E + 1, SRC, 4242, &[&to_b]);
        let mut spliced = now;
        let six = NONCE_LEN + 6 * SLOT_LEN..NONCE_LEN + 7 * SLOT_LEN;
        spliced[six.clone()].copy_from_slice(&next[six]);
        assert_eq!(slots_of(&spliced, &to_b, E + 1, SRC), vec![6]);
        let found = match_query(&spliced, SRC, E, &book);
        assert!(matches!(found.as_slice(), [(0, 7420 | 4242)]), "{found:?}");
        // Several contacts in one query: each finds its own slot once.
        let both = build_query_with(nonce, &[0, 7], &pad(6), E, SRC, 7420, &[&to_b, &to_c]);
        assert_eq!(match_query(&both, SRC, E, &book), vec![(0, 7420)]);
        assert_eq!(match_query(&both, SRC, E, &[keys(&c, &a)]), vec![(0, 7420)]);
        // The same contact twice in a book (not what the beacon task builds)
        // is two entries, each matched once.
        assert_eq!(
            match_query(&both, SRC, E, &[keys(&b, &a), keys(&b, &a)]),
            vec![(0, 7420), (1, 7420)]
        );
    }

    /// The beacon task's per-epoch keys (P3.10) find exactly what
    /// `match_query` finds: the same contacts, ports and order, at every
    /// epoch of the window and at the ends of u64.
    #[test]
    fn epoch_keys_match_exactly_like_match_query() {
        let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
        let book = [keys(&b, &a), keys(&c, &a), keys(&dave(), &a)];
        let (to_b, to_c) = (keys(&a, &b), keys(&a, &c));
        let mut rng = StdRng::seed_from_u64(9);
        for sent in [E, 0, 1, u64::MAX - 1, u64::MAX] {
            let queries = [
                build_query(&mut rng, sent, SRC, 7420, &[&to_b, &to_c]),
                build_query(&mut rng, sent, SRC, 0, &[&to_c]),
                build_query(&mut rng, sent, SRC, 7531, &[]),
            ];
            for now in [
                sent.saturating_sub(2),
                sent.saturating_sub(1),
                sent,
                sent.saturating_add(1),
                sent.saturating_add(2),
            ] {
                let cached = EpochKeys::new(&book, now);
                assert_eq!(cached.epoch(), now);
                for q in &queries {
                    for src in [SRC, mapped(SRC), BOB_IP] {
                        assert_eq!(
                            match_query_with(q, src, &cached),
                            match_query(q, src, now, &book),
                            "sent at {sent}, receiver at {now}"
                        );
                    }
                    assert!(match_query_with(&q[..QUERY_LEN - 1], SRC, &cached).is_empty());
                }
            }
        }
        let cached = EpochKeys::new(&book, E);
        let q = build_query(&mut rng, E, SRC, 7420, &[&to_b, &to_c]);
        assert_eq!(
            match_query_with(&q, SRC, &cached),
            vec![(0, 7420), (1, 7420)]
        );
        assert_eq!(format!("{cached:?}"), "EpochKeys(..)");
        assert!(match_query_with(&q, SRC, &EpochKeys::new(&[], E)).is_empty());
    }

    #[test]
    fn build_query_names_each_contact_once_and_at_most_eight() {
        let a = id(ALICE);
        let contacts: Vec<Identity> = (0..10u8)
            .map(|i| Identity::from_seed(&[0x60 + i; 32]))
            .collect();
        let to: Vec<PairKeys> = contacts.iter().map(|c| keys(&a, c)).collect();
        let mut rng = StdRng::seed_from_u64(5);
        // A repeated target gets one slot.
        let q = build_query(&mut rng, E, SRC, 7420, &[&to[0], &to[1], &to[0]]);
        assert_eq!(slots_of(&q, &to[0], E, SRC).len(), 1);
        assert_eq!(slots_of(&q, &to[1], E, SRC).len(), 1);
        // Ten targets: the first eight are named, one slot each.
        let all: Vec<&PairKeys> = to.iter().collect();
        let q = build_query(&mut rng, E, SRC, 7420, &all);
        let mut used = HashSet::new();
        for (i, (contact, k)) in contacts.iter().zip(&to).enumerate() {
            let at = slots_of(&q, k, E, SRC);
            let named = !match_query(&q, SRC, E, &[keys(contact, &a)]).is_empty();
            assert_eq!(named, i < SLOTS, "target {i}");
            assert_eq!(at.len(), usize::from(i < SLOTS), "target {i}");
            used.extend(at);
        }
        assert_eq!(used.len(), SLOTS);
    }

    #[test]
    fn answer_binds_q_nonce_src_and_dst() {
        let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
        let (a_b, b_a) = (keys(&a, &b), keys(&b, &a));
        let mut rng = StdRng::seed_from_u64(6);
        let q_nonce = [0x11u8; 16];
        // Bob answers alice's query from his address to hers.
        let ans = build_answer(&mut rng, &b_a, &q_nonce, BOB_IP, SRC, 51_000);
        assert_eq!(open_answer(&ans, &a_b, &q_nonce, BOB_IP, SRC), Some(51_000));
        assert_eq!(
            open_answer(&ans, &a_b, &q_nonce, mapped(BOB_IP), mapped(SRC)),
            Some(51_000)
        );
        // Another query's nonce, source or destination: nothing.
        let other: IpAddr = "192.168.1.31".parse().unwrap();
        assert_eq!(open_answer(&ans, &a_b, &[0x12; 16], BOB_IP, SRC), None);
        assert_eq!(open_answer(&ans, &a_b, &q_nonce, other, SRC), None);
        assert_eq!(open_answer(&ans, &a_b, &q_nonce, BOB_IP, other), None);
        assert_eq!(open_answer(&ans, &a_b, &q_nonce, SRC, BOB_IP), None);
        // Only alice's keys for bob open it: not carol's, not alice's for
        // carol, and not bob's own (directions do not mix).
        assert_eq!(
            open_answer(&ans, &keys(&c, &b), &q_nonce, BOB_IP, SRC),
            None
        );
        assert_eq!(
            open_answer(&ans, &keys(&a, &c), &q_nonce, BOB_IP, SRC),
            None
        );
        assert_eq!(open_answer(&ans, &b_a, &q_nonce, BOB_IP, SRC), None);
        // Any changed nonce or tag byte: nothing.
        for i in (0..NONCE_LEN).chain(NONCE_LEN + 2..ANSWER_LEN) {
            let mut bad = ans;
            bad[i] ^= 0x01;
            assert_eq!(
                open_answer(&bad, &a_b, &q_nonce, BOB_IP, SRC),
                None,
                "byte {i}"
            );
        }
        // The port is not covered by the tag (§5): a flipped bit gives
        // another port, which the Noise bind then refuses.
        let mut flipped = ans;
        flipped[NONCE_LEN + 1] ^= 0x01;
        assert_eq!(
            open_answer(&flipped, &a_b, &q_nonce, BOB_IP, SRC),
            Some(51_000 ^ 1)
        );
        // Other lengths.
        assert_eq!(
            open_answer(&ans[..ANSWER_LEN - 1], &a_b, &q_nonce, BOB_IP, SRC),
            None
        );
        // A tail of up to 15 bytes is ignored (Phase 6b W-B3), a 16th
        // refuses it.
        let mut long = ans.to_vec();
        long.push(0);
        assert_eq!(
            open_answer(&long, &a_b, &q_nonce, BOB_IP, SRC),
            Some(51_000)
        );
        long.resize(ANSWER_MAX_LEN + 1, 0);
        assert_eq!(open_answer(&long, &a_b, &q_nonce, BOB_IP, SRC), None);
        assert_eq!(open_answer(&[], &a_b, &q_nonce, BOB_IP, SRC), None);
        // A fresh nonce every time; IPv6 link-local addresses work the same.
        let again = build_answer(&mut rng, &b_a, &q_nonce, BOB_IP, SRC, 51_000);
        assert_ne!(again, ans);
        assert_eq!(
            open_answer(&again, &a_b, &q_nonce, BOB_IP, SRC),
            Some(51_000)
        );
        let (b6, a6): (IpAddr, IpAddr) = ("fe80::b".parse().unwrap(), "fe80::a".parse().unwrap());
        let ans6 = build_answer(&mut rng, &b_a, &q_nonce, b6, a6, 7420);
        assert_eq!(open_answer(&ans6, &a_b, &q_nonce, b6, a6), Some(7420));
        assert_eq!(open_answer(&ans6, &a_b, &q_nonce, a6, b6), None);
    }

    #[test]
    fn port_zero_answer_refused() {
        let (a, b) = (id(ALICE), id(BOB));
        let (a_b, b_a) = (keys(&a, &b), keys(&b, &a));
        let (q_nonce, r_nonce) = ([0x21u8; 16], [0x22u8; 16]);
        let zero = answer_with(r_nonce, &b_a, &q_nonce, BOB_IP, SRC, 0);
        assert_eq!(open_answer(&zero, &a_b, &q_nonce, BOB_IP, SRC), None);
        // The same answer with another port opens: only the port refused it.
        for port in [1, 7420, u16::MAX] {
            let ans = answer_with(r_nonce, &b_a, &q_nonce, BOB_IP, SRC, port);
            assert_eq!(ans[..NONCE_LEN], zero[..NONCE_LEN]);
            assert_eq!(ans[NONCE_LEN + 2..], zero[NONCE_LEN + 2..]);
            assert_eq!(open_answer(&ans, &a_b, &q_nonce, BOB_IP, SRC), Some(port));
        }
        let mut rng = StdRng::seed_from_u64(7);
        let zero = build_answer(&mut rng, &b_a, &q_nonce, BOB_IP, SRC, 0);
        assert_eq!(open_answer(&zero, &a_b, &q_nonce, BOB_IP, SRC), None);
    }

    /// Phase 6b W-B3 (people study M13): a query with any tail of 0..=31
    /// bytes names the same contacts with the same port as without it, and
    /// an answer with any tail of 0..=15 opens to the same port; the tail's
    /// bytes count for nothing. A 192-byte query and a 64-byte answer are
    /// refused, and the two length ranges never meet.
    #[test]
    fn padded_queries_and_answers_match_and_longer_ones_are_refused() {
        let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
        let (to_b, to_c, b_a) = (keys(&a, &b), keys(&a, &c), keys(&b, &a));
        let bob_book = [keys(&b, &c), keys(&b, &a)];
        let mut rng = StdRng::seed_from_u64(11);
        let q = build_query(&mut rng, E, SRC, 47_531, &[&to_b, &to_c]);
        let q_nonce: [u8; 16] = q[..NONCE_LEN].try_into().unwrap();
        let ans = build_answer(&mut rng, &b_a, &q_nonce, BOB_IP, SRC, 47_532);
        let a_b = keys(&a, &b);
        for tail in 0..=QUERY_TAIL_MAX {
            for fill in [0x00, 0xff] {
                let padded = [&q[..], &vec![fill; tail]].concat();
                assert_eq!(kind_of(padded.len()), Some(DatagramKind::Query));
                assert_eq!(
                    match_query(&padded, SRC, E, &bob_book),
                    vec![(1, 47_531)],
                    "tail {tail}"
                );
            }
        }
        for tail in 0..=ANSWER_TAIL_MAX {
            for fill in [0x00, 0xff] {
                let padded = [&ans[..], &vec![fill; tail]].concat();
                assert_eq!(kind_of(padded.len()), Some(DatagramKind::Answer));
                assert_eq!(
                    open_answer(&padded, &a_b, &q_nonce, BOB_IP, SRC),
                    Some(47_532),
                    "tail {tail}"
                );
            }
        }
        // One byte more than the most: refused, also as the other kind.
        let too_long = [&q[..], &[0u8; QUERY_TAIL_MAX + 1]].concat();
        assert_eq!(too_long.len(), 192);
        assert_eq!(kind_of(192), None);
        assert!(match_query(&too_long, SRC, E, &bob_book).is_empty());
        assert_eq!(open_answer(&too_long, &a_b, &q_nonce, BOB_IP, SRC), None);
        let too_long = [&ans[..], &[0u8; ANSWER_TAIL_MAX + 1]].concat();
        assert_eq!(too_long.len(), 64);
        assert!(match_query(&too_long, SRC, E, &bob_book).is_empty());
        assert_eq!(open_answer(&too_long, &a_b, &q_nonce, BOB_IP, SRC), None);
        let kinds: Vec<Option<DatagramKind>> = (0..=256).map(kind_of).collect();
        for (len, kind) in kinds.iter().enumerate() {
            let want = if (160..=191).contains(&len) {
                Some(DatagramKind::Query)
            } else if (48..=63).contains(&len) {
                Some(DatagramKind::Answer)
            } else {
                None
            };
            assert_eq!(*kind, want, "{len} bytes");
        }
        // The sender's tails: the datagram first, then fresh random bytes.
        let padded = with_tail(&mut rng, &q);
        assert_eq!(padded[..QUERY_LEN], q[..]);
        assert_eq!(match_query(&padded, SRC, E, &bob_book), vec![(1, 47_531)]);
        let padded = with_tail(&mut rng, &ans);
        assert_eq!(padded[..ANSWER_LEN], ans[..]);
        assert_eq!(
            open_answer(&padded, &a_b, &q_nonce, BOB_IP, SRC),
            Some(47_532)
        );
    }

    /// Phase 6b W-B3: over 1,000 queries the tails take every length from
    /// 0 to 31 (so the queries every length from 160 to 191), each about as
    /// often as the others, and over 1,000 answers every length from 48 to
    /// 63; the tail bytes themselves are random.
    #[test]
    fn tail_lengths_cover_the_whole_range_over_1000_datagrams() {
        let (a, b) = (id(ALICE), id(BOB));
        let (to_b, b_a) = (keys(&a, &b), keys(&b, &a));
        let mut rng = StdRng::seed_from_u64(12);
        let mut queries = [0u32; QUERY_TAIL_MAX + 1];
        let mut answers = [0u32; ANSWER_TAIL_MAX + 1];
        let mut tail_bytes = [0u64; 256];
        for _ in 0..1000 {
            let q = build_query(&mut rng, E, SRC, 7420, &[&to_b]);
            let q = with_tail(&mut rng, &q);
            assert!((QUERY_LEN..=QUERY_MAX_LEN).contains(&q.len()));
            queries[q.len() - QUERY_LEN] += 1;
            let q_nonce: [u8; 16] = q[..NONCE_LEN].try_into().unwrap();
            let ans = build_answer(&mut rng, &b_a, &q_nonce, BOB_IP, SRC, 7420);
            let ans = with_tail(&mut rng, &ans);
            assert!((ANSWER_LEN..=ANSWER_MAX_LEN).contains(&ans.len()));
            answers[ans.len() - ANSWER_LEN] += 1;
            for &byte in q[QUERY_LEN..].iter().chain(&ans[ANSWER_LEN..]) {
                tail_bytes[usize::from(byte)] += 1;
            }
        }
        // Expected 31.25 per query length and 62.5 per answer length.
        assert!(
            queries.iter().all(|&n| (10..=60).contains(&n)),
            "{queries:?}"
        );
        assert!(
            answers.iter().all(|&n| (30..=100).contains(&n)),
            "{answers:?}"
        );
        // About 23,000 tail bytes, uniform (chi-square over 256 values: mean
        // 255, sd 22.6).
        let chi = chi_square(&tail_bytes);
        assert!(chi < 400.0, "tail bytes: {chi}");
    }

    #[test]
    #[should_panic(expected = "a query or an answer")]
    fn a_tail_goes_only_after_a_whole_query_or_answer() {
        let _ = with_tail(&mut StdRng::seed_from_u64(13), &[0u8; QUERY_LEN + 1]);
    }

    #[test]
    fn no_constant_bytes_or_identity_in_64_datagrams() {
        let (a, b, c) = (id(ALICE), id(BOB), id(CAROL));
        let (to_b, to_c, b_a) = (keys(&a, &b), keys(&a, &c), keys(&b, &a));
        let mut rng = StdRng::seed_from_u64(8);
        // The same targets, port, addresses and epoch every time: whatever
        // repeats would show.
        let (mut queries, mut answers) = (Vec::new(), Vec::new());
        for _ in 0..64 {
            let q = build_query(&mut rng, E, SRC, 7420, &[&to_b, &to_c]);
            let q_nonce: [u8; 16] = q[..NONCE_LEN].try_into().unwrap();
            answers.push(build_answer(&mut rng, &b_a, &q_nonce, BOB_IP, SRC, 7420).to_vec());
            queries.push(q.to_vec());
        }
        for (what, set) in [("query", &queries), ("answer", &answers)] {
            for off in 0..=set[0].len() - 4 {
                let first = &set[0][off..off + 4];
                assert!(
                    set.iter().any(|d| d[off..off + 4] != *first),
                    "{what}: the same 4 bytes at offset {off} in all 64"
                );
            }
        }
        // No identity material: the identity keys and their Montgomery
        // forms, LAN Noise statics, PeerIds (binary and text), addresses,
        // fingerprints and the bound addresses (any 8 bytes of them).
        let mut needles: Vec<Vec<u8>> = vec![ip16(SRC).to_vec(), ip16(BOB_IP).to_vec()];
        for who in [&a, &b, &c] {
            let public = who.public_key_bytes();
            let noise = crate::lan_noise::derive_noise_static(who).unwrap();
            let peer_id = crate::p2p_route::local_peer_id(who);
            needles.extend([
                public.to_vec(),
                VerifyingKey::from_bytes(&public)
                    .unwrap()
                    .to_montgomery()
                    .to_bytes()
                    .to_vec(),
                crate::lan_noise::noise_static_public(&noise).to_vec(),
                crate::p2p_route::peer_id_bytes(&peer_id).unwrap().to_vec(),
                peer_id.into_bytes(),
                who.address().into_bytes(),
                crate::fingerprint::device_fingerprint_v1(&public).into_bytes(),
                crate::fingerprint::mesh_v1_hex_fingerprint(&public).into_bytes(),
            ]);
        }
        let forbidden: HashSet<&[u8]> = needles.iter().flat_map(|n| n.windows(8)).collect();
        for d in queries.iter().chain(&answers) {
            assert!(d.windows(8).all(|w| !forbidden.contains(w)));
            // Nor the address marker, in any case, nor an IPv4 address.
            assert!(!d.windows(4).any(|w| w.eq_ignore_ascii_case(b"rvn1")));
            assert!(!d
                .windows(4)
                .any(|w| w == [192, 168, 1, 20] || w == [192, 168, 1, 30]));
        }
    }

    // RAVEN_LAN_BEACON_V1 §12: the known-answer vectors in
    // shared-vectors/rvn1/lan_beacon. This test writes them only under
    // RAVEN_REGEN_LAN_BEACON_VECTORS=1 (a deliberate wire change) and
    // otherwise compares them with the committed files. The Python reference
    // (protocol/reference/raven_protocol/lan_beacon.py) recomputes them from
    // their inputs.

    /// The vectors' people: (name, seed, where the seed comes from).
    const PEOPLE: [(&str, &str, &str); 4] = [
        (
            "alice",
            ALICE,
            "shared-vectors/v1/identities.json alice (RFC 8032 section 7.1 test 1)",
        ),
        (
            "bob",
            BOB,
            "shared-vectors/v1/identities.json bob (RFC 8032 section 7.1 test 2)",
        ),
        ("carol", CAROL, "inline: RFC 8032 section 7.1 test 3"),
        (
            "dave",
            DAVE,
            "inline: 32 bytes of 0x44 (not the dave of shared-vectors/v1/identities.json)",
        ),
    ];

    /// One of [`PEOPLE`].
    fn person(name: &str) -> Identity {
        let (_, seed, _) = PEOPLE
            .iter()
            .find(|p| p.0 == name)
            .expect("one of the vectors' people");
        id(seed)
    }

    /// The Montgomery u-coordinate of an Ed25519 key (§2.1).
    fn montgomery(public: &[u8; 32]) -> [u8; 32] {
        VerifyingKey::from_bytes(public)
            .unwrap()
            .to_montgomery()
            .to_bytes()
    }

    /// 16 counting bytes from `first`: the vectors' nonces.
    fn counting(first: u8) -> [u8; 16] {
        std::array::from_fn(|i| first + i as u8)
    }

    /// The people `names` as a vector's inputs list them.
    fn people_json(names: &[&str]) -> Value {
        let mut map = serde_json::Map::new();
        for (name, seed, source) in PEOPLE {
            if names.contains(&name) {
                map.insert(
                    name.into(),
                    json!({
                        "seed_hex": seed,
                        "ed_public_hex": hex::encode(person(name).public_key_bytes()),
                        "source": source,
                    }),
                );
            }
        }
        Value::Object(map)
    }

    /// `owner`'s contact book in the vectors: the three others, in
    /// [`PEOPLE`] order (names, keys).
    fn book_of(owner: &str) -> (Vec<&'static str>, Vec<PairKeys>) {
        let me = person(owner);
        let names: Vec<&'static str> = PEOPLE.iter().map(|p| p.0).filter(|n| *n != owner).collect();
        let book = names.iter().map(|n| keys(&me, &person(n))).collect();
        (names, book)
    }

    /// Whom `owner`'s book finds in the query `q` from `src` when its clock
    /// is at epoch `now`: (contact, port).
    fn found_in(q: &[u8], owner: &str, src: IpAddr, now: u64) -> Vec<(&'static str, u16)> {
        let (names, book) = book_of(owner);
        match_query(q, src, now, &book)
            .into_iter()
            .map(|(i, port)| (names[i], port))
            .collect()
    }

    fn vectors_dir() -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors/rvn1/lan_beacon")
    }

    /// A vector file's JSON, in the layout of the other rvn1 vectors.
    fn vector(name: &str, description: &str, inputs: Value, expected: Value) -> Value {
        json!({
            "name": name,
            "protocol_version": "rvn1",
            "deterministic": true,
            "description": description,
            "inputs": inputs,
            "expected": expected,
        })
    }

    /// Assert that the committed vector `file` (in
    /// shared-vectors/rvn1/lan_beacon) equals `expected`; write it first
    /// under `RAVEN_REGEN_LAN_BEACON_VECTORS=1`.
    fn assert_vector(file: &str, expected: &Value) {
        let path = vectors_dir().join(file);
        if std::env::var("RAVEN_REGEN_LAN_BEACON_VECTORS").as_deref() == Ok("1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(expected).unwrap() + "\n",
            )
            .unwrap();
        }
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
        let stored: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(&stored, expected, "{file}");
    }

    /// lbcn_pair_keys_001.json (§2): every person's X25519 scalar and
    /// Montgomery u, and the keys of alice's pairs with bob, carol and dave.
    fn pair_keys_vector() -> Value {
        let names = ["alice", "bob", "carol", "dave"];
        let mut per_person = serde_json::Map::new();
        for name in names {
            let who = person(name);
            let u = montgomery(&who.public_key_bytes());
            // X25519's own public key of the scalar is the same u.
            assert_eq!(
                x25519_dalek::x25519(
                    *who.x25519_agreement_scalar(),
                    x25519_dalek::X25519_BASEPOINT_BYTES
                ),
                u
            );
            per_person.insert(
                name.into(),
                json!({
                    "x25519_scalar_hex": hex::encode(*who.x25519_agreement_scalar()),
                    "montgomery_u_hex": hex::encode(u),
                }),
            );
        }
        let pairs = [("alice", "bob"), ("alice", "carol"), ("alice", "dave")];
        let rows: Vec<Value> = pairs
            .iter()
            .map(|&(an, bn)| {
                let (a, b) = (person(an), person(bn));
                let (ap, bp) = (a.public_key_bytes(), b.public_key_bytes());
                let z_by_a = x25519_dalek::x25519(*a.x25519_agreement_scalar(), montgomery(&bp));
                let z_by_b = x25519_dalek::x25519(*b.x25519_agreement_scalar(), montgomery(&ap));
                assert_eq!(z_by_a, z_by_b, "{an} and {bn}");
                let root = pair_root(&a, &bp).unwrap();
                assert_eq!(*root, *pair_root(&b, &ap).unwrap());
                let lan = medium_key(&root, MEDIUM_LAN);
                let (lo, hi) = if ap <= bp { (an, bn) } else { (bn, an) };
                let k = keys(&a, &b);
                json!({
                    "a": an,
                    "b": bn,
                    "lo": lo,
                    "hi": hi,
                    "root_info_hex": hex::encode([b"root".as_slice(), &ap.min(bp), &ap.max(bp)].concat()),
                    "z_by_a_hex": hex::encode(z_by_a),
                    "z_by_b_hex": hex::encode(z_by_b),
                    "k_root_hex": hex::encode(*root),
                    "k_lan_hex": hex::encode(*lan),
                    "k_query_a_to_b_hex": hex::encode(*k.q_out),
                    "k_query_b_to_a_hex": hex::encode(*k.q_in),
                    "k_reply_a_to_b_hex": hex::encode(*k.r_out),
                    "k_reply_b_to_a_hex": hex::encode(*k.r_in),
                    "k_query_epoch_a_to_b_hex": hex::encode(*epoch_key(&k.q_out, E)),
                    "k_query_epoch_b_to_a_hex": hex::encode(*epoch_key(&k.q_in, E)),
                })
            })
            .collect();
        vector(
            "LAN beacon keys: R2 pairwise root, LAN medium key, directional and epoch keys",
            "RAVEN_LAN_BEACON_V1 §2. a = SHA-512(seed)[0..32] (X25519 clamps it); u = (1 + y) / \
             (1 - y) mod 2^255 - 19 is the Montgomery u-coordinate of an Ed25519 key; Z = \
             X25519(a_A, u_B) = X25519(a_B, u_A). K_root = HKDF-SHA256(salt 'rvn1/r2-pair/v1', \
             ikm Z, info 'root' || lo || hi, 32 bytes) with lo and hi the two Ed25519 keys sorted \
             bytewise: the R2 pairwise root, one per pair for every medium. K_lan = \
             HKDF-Expand-SHA256(PRK K_root, info 'medium' || 0x02, 32 bytes). With X and Y \
             Ed25519 keys, K_q(X->Y) = HMAC-SHA256(K_lan, 'query' || X || Y) and K_r(Y->X) = \
             HMAC-SHA256(K_lan, 'reply' || Y || X); the epoch key K_q,e = HMAC-SHA256(K_q, \
             'epoch' || e as u64 big-endian), e = floor(epoch_seconds / 600). Labels are ASCII \
             with no terminator. These keys only make beacon tags: never a message, session, \
             route, mailbox or ACK key",
            json!({
                "people": people_json(&names),
                "pairs": pairs.map(|(a, b)| [a, b]),
                "r2_pair_salt_ascii": std::str::from_utf8(R2_PAIR_SALT).unwrap(),
                "medium_lan": MEDIUM_LAN,
                "epoch_seconds": NOW_S,
                "epoch_len_s": EPOCH_SECS,
            }),
            json!({
                "epoch": E,
                "people": per_person,
                "pairs": rows,
            }),
        )
    }

    /// lbcn_query_001.json (§4, §6) and its query: alice names bob in slot
    /// 5 and carol in slot 2.
    fn query_vector() -> (Value, [u8; QUERY_LEN]) {
        let a = person("alice");
        let (to_b, to_c) = (keys(&a, &person("bob")), keys(&a, &person("carol")));
        let nonce = counting(0x00);
        let free = [0, 1, 3, 4, 6, 7];
        let padding: Vec<[u8; SLOT_LEN]> = (0..6u8).map(|j| [0xa0 + j; SLOT_LEN]).collect();
        let q = build_query_with(nonce, &[5, 2], &padding, E, SRC, 7420, &[&to_b, &to_c]);
        for (&pos, pad) in free.iter().zip(&padding) {
            assert_eq!(slot(&q, pos), pad);
        }
        let slots: Vec<Value> = [("carol", 2, &to_c), ("bob", 5, &to_b)]
            .into_iter()
            .map(|(target, pos, k)| {
                let h = query_tag(&k.q_out, E, &nonce, SRC);
                let s = slot(&q, pos);
                assert_eq!(s[..16], h[..16]);
                assert_eq!([s[16] ^ h[16], s[17] ^ h[17]], 7420u16.to_be_bytes());
                json!({
                    "slot": pos,
                    "target": target,
                    "h_hex": hex::encode(h),
                    "slot_hex": hex::encode(s),
                })
            })
            .collect();
        let matches: Vec<Value> = PEOPLE
            .iter()
            .map(|&(receiver, _, _)| {
                let found: Vec<Value> = found_in(&q, receiver, SRC, E)
                    .into_iter()
                    .map(|(contact, port)| json!({ "contact": contact, "port": port }))
                    .collect();
                json!({ "receiver": receiver, "found": found })
            })
            .collect();
        // Bob and carol find alice and her port; dave is not named, and
        // alice's own query (an echo) names nobody in her book.
        assert_eq!(found_in(&q, "bob", SRC, E), [("alice", 7420)]);
        assert_eq!(found_in(&q, "carol", SRC, E), [("alice", 7420)]);
        assert!(found_in(&q, "dave", SRC, E).is_empty());
        assert!(found_in(&q, "alice", SRC, E).is_empty());
        let bob_port = |src: IpAddr, now: u64| found_in(&q, "bob", src, now).first().map(|f| f.1);
        let window: Vec<Value> = (E - 2..=E + 2)
            .map(|now| {
                let port = bob_port(SRC, now);
                assert_eq!(port.is_some(), now.abs_diff(E) <= 1, "bob at epoch {now}");
                json!({ "receiver_epoch": now, "port": port })
            })
            .collect();
        let sources: Vec<Value> = [
            "192.168.1.21",
            "10.0.0.20",
            "::ffff:192.168.1.20",
            "::192.168.1.20",
            "fe80::1",
        ]
        .into_iter()
        .map(|src| {
            let port = bob_port(src.parse().unwrap(), E);
            // Only the same address binds, also in its IPv4-mapped form.
            assert_eq!(port.is_some(), src == "::ffff:192.168.1.20", "{src}");
            json!({ "src": src, "port": port })
        })
        .collect();
        let file = vector(
            "LAN beacon query: alice names bob (slot 5) and carol (slot 2)",
            "RAVEN_LAN_BEACON_V1 §4 and §6. A query is nonce[16] || 8 slots of 18 bytes. A named \
             target Y's slot is h[0..16] || (port as u16 big-endian XOR h[16..18]) with h = \
             HMAC-SHA256(K_q,e(alice->Y), nonce || ip16(src)); ip16 of an IPv4 address is \
             ::ffff:a.b.c.d, of an IPv6 address its 16 bytes (never a zone). The other slots \
             hold the given padding in slot order (fresh random bytes in a real query, whose \
             slot order is random too). A receiver tries each contact C's K_q(C->receiver) at \
             the epochs e'-1, e', e'+1 of its own clock against every slot (constant-time \
             compare), at most one match per contact; the port is slot[16..18] XOR h[16..18]. \
             books lists each person's contacts. Keys: lbcn_pair_keys_001.json",
            json!({
                "people": people_json(&["alice", "bob", "carol", "dave"]),
                "querier": "alice",
                "targets": [{ "name": "bob", "slot": 5 }, { "name": "carol", "slot": 2 }],
                "nonce_hex": hex::encode(nonce),
                "padding": free
                    .iter()
                    .zip(&padding)
                    .map(|(pos, pad)| json!({ "slot": pos, "hex": hex::encode(pad) }))
                    .collect::<Vec<_>>(),
                "epoch_seconds": NOW_S,
                "src": SRC.to_string(),
                "port": 7420,
                "books": PEOPLE
                    .iter()
                    .map(|p| (p.0.to_string(), json!(book_of(p.0).0)))
                    .collect::<serde_json::Map<_, _>>(),
            }),
            json!({
                "epoch": E,
                "src_ip16_hex": hex::encode(ip16(SRC)),
                "query_hex": hex::encode(q),
                "query_len": q.len(),
                "slots": slots,
                "matches": matches,
                "epoch_window_bob": window,
                "other_sources_bob": sources,
            }),
        );
        (file, q)
    }

    /// lbcn_answer_001.json (§5, §7) and its answer: bob answers alice's
    /// query of lbcn_query_001.json.
    fn answer_vector() -> (Value, [u8; ANSWER_LEN]) {
        let b_a = keys(&person("bob"), &person("alice"));
        let (q_nonce, r_nonce) = (counting(0x00), counting(0x10));
        let ans = answer_with(r_nonce, &b_a, &q_nonce, BOB_IP, SRC, 7420);
        let h = answer_tag(&b_a.r_out, &q_nonce, &r_nonce, BOB_IP, SRC);
        let mut other_nonce = q_nonce;
        other_nonce[15] ^= 0x01;
        let ip = |text: &str| -> IpAddr { text.parse().unwrap() };
        let rows = [
            (
                "alice opens it with her keys for bob",
                "alice",
                "bob",
                q_nonce,
                BOB_IP,
                SRC,
                Some(7420),
            ),
            (
                "the same with both addresses in their IPv4-mapped form",
                "alice",
                "bob",
                q_nonce,
                mapped(BOB_IP),
                mapped(SRC),
                Some(7420),
            ),
            (
                "another query's nonce",
                "alice",
                "bob",
                other_nonce,
                BOB_IP,
                SRC,
                None,
            ),
            (
                "another source",
                "alice",
                "bob",
                q_nonce,
                ip("192.168.1.31"),
                SRC,
                None,
            ),
            (
                "another destination",
                "alice",
                "bob",
                q_nonce,
                BOB_IP,
                ip("192.168.1.21"),
                None,
            ),
            (
                "source and destination swapped",
                "alice",
                "bob",
                q_nonce,
                SRC,
                BOB_IP,
                None,
            ),
            (
                "carol's keys for bob",
                "carol",
                "bob",
                q_nonce,
                BOB_IP,
                SRC,
                None,
            ),
            (
                "bob's own keys for alice (the other direction)",
                "bob",
                "alice",
                q_nonce,
                BOB_IP,
                SRC,
                None,
            ),
        ];
        let opens: Vec<Value> = rows
            .iter()
            .map(|&(what, opener, peer, n, src, dst, want)| {
                let port = open_answer(&ans, &keys(&person(opener), &person(peer)), &n, src, dst);
                assert_eq!(port, want, "{what}");
                json!({
                    "what": what,
                    "opener": opener,
                    "peer": peer,
                    "q_nonce_hex": hex::encode(n),
                    "src": src.to_string(),
                    "dst": dst.to_string(),
                    "port": port,
                })
            })
            .collect();
        let file = vector(
            "LAN beacon answer: bob answers alice's query",
            "RAVEN_LAN_BEACON_V1 §5 and §7. Bob answers alice's query of lbcn_query_001.json \
             (q_nonce is its nonce). An answer is r_nonce[16] || port_x[2] || tag[30] with h = \
             HMAC-SHA256(K_r(bob->alice), q_nonce || r_nonce || ip16(src) || ip16(dst)), port_x \
             = port as u16 big-endian XOR h[0..2] and tag = h[2..32]; src is the answerer's \
             bound address, dst the query's source. To open it, the querier recomputes h with \
             K_r(answerer->querier) for a target of that query and compares the tag in constant \
             time; port_x is not covered by the tag, and port 0 is refused. Each row of opens is \
             one open with the keys of opener for peer (port null: refused). Keys: \
             lbcn_pair_keys_001.json",
            json!({
                "people": people_json(&["alice", "bob", "carol"]),
                "answerer": "bob",
                "querier": "alice",
                "q_nonce_hex": hex::encode(q_nonce),
                "r_nonce_hex": hex::encode(r_nonce),
                "src": BOB_IP.to_string(),
                "dst": SRC.to_string(),
                "port": 7420,
            }),
            json!({
                "src_ip16_hex": hex::encode(ip16(BOB_IP)),
                "dst_ip16_hex": hex::encode(ip16(SRC)),
                "h_hex": hex::encode(h),
                "answer_hex": hex::encode(ans),
                "answer_len": ans.len(),
                "opens": opens,
            }),
        );
        (file, ans)
    }

    /// lbcn_negative_001.json (§2.1, §3), around the vectors' query `q` and
    /// answer `ans`.
    fn negative_vector(q: &[u8], ans: &[u8]) -> Value {
        let (a, b) = (person("alice"), person("bob"));
        let (me, bob_key) = (a.public_key_bytes(), b.public_key_bytes());
        let small_order = [
            "small order: the identity point (order 1)",
            "small order: order 2 (y = p - 1)",
            "small order: order 4 (y = 0)",
            "small order: order 4 (y = 0, sign bit set)",
            "small order: order 8",
            "small order: order 8 (sign bit set)",
            "small order: order 8, the other y",
            "small order: order 8, the other y (sign bit set)",
        ];
        let mut contact_keys: Vec<(&str, Vec<u8>)> = small_order
            .into_iter()
            .zip(SMALL_ORDER)
            .map(|(what, key)| (what, bytes32(key).to_vec()))
            .collect();
        let mut two = [0u8; 32];
        two[0] = 2;
        contact_keys.extend([
            (
                "not canonical: y = p + 3, which decodes to the point with y = 3 (not weak)",
                bytes32("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
                    .to_vec(),
            ),
            (
                "not canonical: y = p + 3 with the sign bit set",
                bytes32("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .to_vec(),
            ),
            (
                "not canonical: the identity point as y = p + 1",
                bytes32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
                    .to_vec(),
            ),
            (
                "not canonical: the identity point with the sign bit set (x = 0)",
                bytes32("0100000000000000000000000000000000000000000000000000000000000080")
                    .to_vec(),
            ),
            (
                "not canonical: the order-2 point with the sign bit set (x = 0)",
                bytes32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                    .to_vec(),
            ),
            ("not a point: y = 2", two.to_vec()),
            ("the own key (alice's)", me.to_vec()),
            (
                "31 bytes: bob's key without its last byte",
                bob_key[..31].to_vec(),
            ),
            (
                "33 bytes: bob's key and one more byte",
                [&bob_key[..], &[0u8][..]].concat(),
            ),
        ]);
        let contact_keys: Vec<Value> = contact_keys
            .iter()
            .map(|(what, key)| {
                match <[u8; 32]>::try_from(key.as_slice()) {
                    Ok(key) => {
                        assert_eq!(
                            pair_root(&a, &key).unwrap_err(),
                            BeaconError::BadKey,
                            "{what}"
                        );
                        assert_eq!(
                            pair_keys(&a, &key).unwrap_err(),
                            BeaconError::BadKey,
                            "{what}"
                        );
                    }
                    // Not even a key: the API takes exactly 32 bytes.
                    Err(_) => assert_ne!(key.len(), 32, "{what}"),
                }
                json!({
                    "what": what,
                    "peer_pub_hex": hex::encode(key),
                    "len": key.len(),
                    "result": "bad_key",
                })
            })
            .collect();
        let scalar = a.x25519_agreement_scalar();
        let shared_secrets: Vec<Value> = [
            "u = 0 (order 2)",
            "u = 1 (order 4)",
            "order 8",
            "order 8, the other u",
            "u = p - 1 (a small-order point of the twist)",
            "u = p (0, not reduced)",
            "u = p + 1 (1, not reduced)",
        ]
        .into_iter()
        .zip(NON_CONTRIBUTORY_U)
        .map(|(what, u)| {
            let u = bytes32(u);
            let z = x25519_dalek::x25519(*scalar, u);
            assert_eq!(z, [0u8; 32], "{what}");
            assert_eq!(
                root_from(&scalar, u, &me, &bob_key).unwrap_err(),
                BeaconError::NonContributory,
                "{what}"
            );
            json!({
                "what": what,
                "u_hex": hex::encode(u),
                "z_hex": hex::encode(z),
                "result": "non_contributory",
            })
        })
        .collect();
        let (q_nonce, r_nonce) = (counting(0x00), counting(0x10));
        let a_b = keys(&a, &b);
        // The whole query and answer are found and opened: below, only the
        // length or the port differs.
        assert_eq!(found_in(q, "bob", SRC, E), [("alice", 7420)]);
        assert_eq!(open_answer(ans, &a_b, &q_nonce, BOB_IP, SRC), Some(7420));
        let zero_port = answer_with(r_nonce, &keys(&b, &a), &q_nonce, BOB_IP, SRC, 0);
        let datagrams: Vec<Value> = [
            ("empty", Vec::new()),
            (
                "the query of lbcn_query_001.json cut to 159 bytes",
                q[..QUERY_LEN - 1].to_vec(),
            ),
            (
                "that query and a 32-byte tail (192 bytes: one more than a tail may have)",
                [q, &[0u8; QUERY_TAIL_MAX + 1][..]].concat(),
            ),
            (
                "the answer of lbcn_answer_001.json cut to 47 bytes",
                ans[..ANSWER_LEN - 1].to_vec(),
            ),
            (
                "that answer and a 16-byte tail (64 bytes: one more than a tail may have)",
                [ans, &[0u8; ANSWER_TAIL_MAX + 1][..]].concat(),
            ),
            (
                "that answer with port 0 (its tag verifies)",
                zero_port.to_vec(),
            ),
        ]
        .into_iter()
        .map(|(what, d)| {
            assert!(found_in(&d, "bob", SRC, E).is_empty(), "{what}");
            assert_eq!(open_answer(&d, &a_b, &q_nonce, BOB_IP, SRC), None, "{what}");
            json!({
                "what": what,
                "datagram_hex": hex::encode(&d),
                "len": d.len(),
                "bob_finds": [],
                "alice_opens": null,
            })
        })
        .collect();
        vector(
            "LAN beacon negatives: refused contact keys, non-contributory secrets, dropped datagrams",
            "RAVEN_LAN_BEACON_V1 §2.1 and §3. contact_keys: contact keys that get no beacon keys \
             (bad_key) for alice: one that does not decode as an Ed25519 point, is not \
             canonically encoded (re-compressing the decoded point gives other bytes), has small \
             order, is her own key, or is not 32 bytes. shared_secrets: Montgomery \
             u-coordinates for which X25519 with alice's scalar gives the all-zero Z, refused as \
             non-contributory (no key that passes the contact_keys checks maps to one). \
             datagrams: a datagram whose length is neither 160..=191 (a query: a tail of up \
             to 31 bytes after its 160 is ignored) nor 48..=63 (an answer: a tail of up to 15 \
             bytes after its 48) is dropped with no effect, and an answer with port 0 is \
             refused: bob's book (books) \
             finds nobody in it as a query from query_src at the vectors' epoch, and alice's \
             keys for bob open nothing in it as an answer to q_nonce from answer_src to \
             answer_dst",
            json!({
                "people": people_json(&["alice", "bob", "carol", "dave"]),
                "own": "alice",
                "epoch_seconds": NOW_S,
                "books": { "bob": book_of("bob").0 },
                "query_src": SRC.to_string(),
                "q_nonce_hex": hex::encode(q_nonce),
                "answer_src": BOB_IP.to_string(),
                "answer_dst": SRC.to_string(),
            }),
            json!({
                "contact_keys": contact_keys,
                "shared_secrets": shared_secrets,
                "datagrams": datagrams,
            }),
        )
    }

    /// `n` counting bytes from `first`: the vectors' tails.
    fn tail(first: u8, n: usize) -> Vec<u8> {
        (0..n).map(|i| first + i as u8).collect()
    }

    /// lbcn_query_padded_001.json (§3, §4, §6; Phase 6b W-B3): the query of
    /// lbcn_query_001.json with tails of 1, 16 and 31 bytes is found as
    /// without them.
    fn query_padded_vector(q: &[u8; QUERY_LEN]) -> Value {
        let tails = [1, 16, QUERY_TAIL_MAX];
        let padded: Vec<Value> = tails
            .iter()
            .map(|&n| {
                let d = [&q[..], &tail(0xc0, n)].concat();
                assert_eq!(kind_of(d.len()), Some(DatagramKind::Query));
                let matches: Vec<Value> = PEOPLE
                    .iter()
                    .map(|&(receiver, _, _)| {
                        let found = found_in(&d, receiver, SRC, E);
                        assert_eq!(found, found_in(q, receiver, SRC, E), "{receiver}");
                        let found: Vec<Value> = found
                            .into_iter()
                            .map(|(contact, port)| json!({ "contact": contact, "port": port }))
                            .collect();
                        json!({ "receiver": receiver, "found": found })
                    })
                    .collect();
                json!({
                    "tail_len": n,
                    "datagram_hex": hex::encode(&d),
                    "len": d.len(),
                    "matches": matches,
                })
            })
            .collect();
        vector(
            "LAN beacon query with a random tail: read as its first 160 bytes",
            "RAVEN_LAN_BEACON_V1 §3, §4 and §6 (the v1 amendment of Phase 6b, made before the \
             beacon's production flip). A sender puts 0..=31 fresh random bytes after a query's \
             160 (the number drawn uniformly); a receiver takes any datagram of 160..=191 bytes \
             as a query, reads its first 160 bytes as lbcn_query_001.json describes and ignores \
             the rest. Here the query of lbcn_query_001.json (query_hex) gets tails of 1, 16 \
             and 31 counting bytes from 0xc0 (random in a real query); each person's book \
             (books) finds in it exactly what it finds in the query alone. A 192-byte \
             datagram is dropped: lbcn_negative_001.json",
            json!({
                "people": people_json(&["alice", "bob", "carol", "dave"]),
                "query_vector": "lbcn_query_001.json",
                "query_hex": hex::encode(q),
                "tail_first_byte": 0xc0,
                "tail_lens": tails,
                "epoch_seconds": NOW_S,
                "src": SRC.to_string(),
                "books": PEOPLE
                    .iter()
                    .map(|p| (p.0.to_string(), json!(book_of(p.0).0)))
                    .collect::<serde_json::Map<_, _>>(),
            }),
            json!({
                "epoch": E,
                "max_len": QUERY_MAX_LEN,
                "padded": padded,
            }),
        )
    }

    /// lbcn_answer_padded_001.json (§3, §5, §7; Phase 6b W-B3): the answer
    /// of lbcn_answer_001.json with tails of 1, 8 and 15 bytes opens as
    /// without them.
    fn answer_padded_vector(ans: &[u8; ANSWER_LEN]) -> Value {
        let a_b = keys(&person("alice"), &person("bob"));
        let q_nonce = counting(0x00);
        let mut other_nonce = q_nonce;
        other_nonce[15] ^= 0x01;
        let tails = [1, 8, ANSWER_TAIL_MAX];
        let padded: Vec<Value> = tails
            .iter()
            .map(|&n| {
                let d = [&ans[..], &tail(0xe0, n)].concat();
                assert_eq!(kind_of(d.len()), Some(DatagramKind::Answer));
                let opens = open_answer(&d, &a_b, &q_nonce, BOB_IP, SRC);
                assert_eq!(opens, Some(7420));
                let other = open_answer(&d, &a_b, &other_nonce, BOB_IP, SRC);
                assert_eq!(other, None);
                json!({
                    "tail_len": n,
                    "datagram_hex": hex::encode(&d),
                    "len": d.len(),
                    "alice_opens": opens,
                    "alice_opens_with_another_q_nonce": other,
                })
            })
            .collect();
        vector(
            "LAN beacon answer with a random tail: read as its first 48 bytes",
            "RAVEN_LAN_BEACON_V1 §3, §5 and §7 (the v1 amendment of Phase 6b, made before the \
             beacon's production flip). A sender puts 0..=15 fresh random bytes after an \
             answer's 48 (the number drawn uniformly); a receiver takes any datagram of 48..=63 \
             bytes as an answer, reads its first 48 bytes as lbcn_answer_001.json describes and \
             ignores the rest. Here the answer of lbcn_answer_001.json (answer_hex) gets tails \
             of 1, 8 and 15 counting bytes from 0xe0 (random in a real answer); alice opens \
             each with her keys for bob to bob's port as she opens the answer alone, and with \
             another query's nonce to nothing. A 64-byte datagram is dropped: \
             lbcn_negative_001.json",
            json!({
                "people": people_json(&["alice", "bob"]),
                "answer_vector": "lbcn_answer_001.json",
                "answer_hex": hex::encode(ans),
                "tail_first_byte": 0xe0,
                "tail_lens": tails,
                "opener": "alice",
                "peer": "bob",
                "q_nonce_hex": hex::encode(q_nonce),
                "other_q_nonce_hex": hex::encode(other_nonce),
                "src": BOB_IP.to_string(),
                "dst": SRC.to_string(),
            }),
            json!({
                "max_len": ANSWER_MAX_LEN,
                "padded": padded,
            }),
        )
    }

    #[test]
    fn lan_beacon_known_answer_vectors() {
        assert_eq!(epoch_at(NOW_S), E);
        assert_vector("lbcn_pair_keys_001.json", &pair_keys_vector());
        let (query, q) = query_vector();
        assert_vector("lbcn_query_001.json", &query);
        let (answer, ans) = answer_vector();
        assert_vector("lbcn_answer_001.json", &answer);
        assert_vector("lbcn_negative_001.json", &negative_vector(&q, &ans));
        assert_vector("lbcn_query_padded_001.json", &query_padded_vector(&q));
        assert_vector("lbcn_answer_padded_001.json", &answer_padded_vector(&ans));
    }
}
