//! RAVEN_NEARBY_LINK_V1 (RNL1, Phase 5 nearby): the keys, the knock and the
//! pipe framing of the Bluetooth LE nearby carrier. Pure: no radio, no clock,
//! no file. raven-node's nearby engine owns the radio, the timers and the
//! Raven link (Noise XX with [`NEARBY_LINK_PROLOGUE`]) that runs on a pipe
//! channel.
//!
//! - **RNB1 pair keys** ([`pair_keys`]): from Phase 3's R2 pairwise root
//!   ([`lan_beacon::pair_root`], RAVEN_PRIVATE_RENDEZVOUS_V1 §5.3a) with the
//!   Bluetooth LE medium byte [`MEDIUM_BLE`]: `K_ble = K_medium(0x01)`, and
//!   from it `K_tok` and `K_knock`. Only for beacon tokens and knock tags:
//!   never a message, session, route, mailbox or ACK key. In memory only,
//!   wiped on drop, never stored or logged.
//! - **RNB1 tokens** ([`token`]): one 16-byte value per advertiser and
//!   15-minute epoch ([`EPOCH_MS`]), with the RFC 9562 version-4 bits set,
//!   advertised as the one 128-bit service UUID; [`char_uuid`] names the one
//!   characteristic. A scanner accepts the epochs next to its own
//!   ([`scan_epochs`], [`match_token`]).
//! - **RNK1 knock** ([`CentralKnock`], [`PeripheralKnock`]): HELLO,
//!   CHALLENGE and PROOF, before any Noise byte. Each side proves it holds
//!   the pair's `K_knock`; a stranger gets silence, and [`KnockReplay`] keeps
//!   a peripheral silent to a replayed HELLO.
//! - **RNP1 frames** ([`Frame`], [`decode`], [`encode`]) and [`PipeState`]:
//!   two ordered byte channels with sequence numbers and credits, one frame
//!   per ATT PDU. RNP1 is stream framing beneath Noise, not an endpoint-object
//!   fragment profile: endpoint objects are never fragmented at the endpoint
//!   layer, and Noise fails closed on any corruption.

use std::collections::{HashMap, VecDeque};
use std::ops::RangeInclusive;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::identity::Identity;
use crate::lan_beacon::{self, BeaconError, MEDIUM_BLE};

/// Noise prologue of the Raven link on a nearby pipe channel: same XX, RIH1
/// hello and frames as Internet direct, with a distinct prologue so no TCP,
/// libp2p or nearby transcript can complete against another.
pub const NEARBY_LINK_PROLOGUE: &[u8] = b"raven/nearby-link/v1";
/// Token epoch: `floor(unix_ms / EPOCH_MS)` (15 minutes).
pub const EPOCH_MS: u64 = 900_000;
/// The smallest `max_tx` that starts a knock (`min(ATT_MTU - 3, 512)`).
pub const MIN_FRAME: usize = 64;
/// The largest frame (one ATT attribute value).
pub const MAX_FRAME: usize = 512;
/// DATA credit each direction of a new channel instance starts with.
pub const W0: u16 = 8;
/// The most outstanding DATA credit, and the largest CREDIT `add`.
pub const W_MAX: u16 = 64;
/// More control frames received in a row than this, with no DATA sent or
/// received between them, is LIMIT.
pub const MAX_CONTROL_RUN: u16 = 64;
/// RNK1 version byte (HELLO and CHALLENGE).
pub const VERSION: u8 = 0x01;
/// RNK1 flags in V1: bit 0 ("L2CAP capable") is reserved and 0, as are the
/// others. Every flag bit is covered by the knock MACs.
pub const FLAGS_V1: u8 = 0x00;
/// HELLO: kind, version, flags_c, nonce_c[16], tag_h[16].
pub const HELLO_LEN: usize = 35;
/// CHALLENGE: kind, version, flags_p, nonce_p[16], tag_p[16].
pub const CHALLENGE_LEN: usize = 35;
/// PROOF: kind, tag_c[16].
pub const PROOF_LEN: usize = 17;
/// DATA header: kind, chan, seq[2].
pub const DATA_HEADER: usize = 4;
/// Nonces a peripheral remembers per token (at least 256, RNL1 §5).
pub const REPLAY_PER_TOKEN: usize = 256;
/// The last sequence number a DATA frame may carry: a sender whose next
/// sequence number is 65535 must FIN (sequence numbers never wrap).
pub const LAST_DATA_SEQ: u16 = u16::MAX - 1;

/// Frame kinds (the first byte of every RNK1 and RNP1 frame).
pub const KIND_HELLO: u8 = 0x01;
pub const KIND_CHALLENGE: u8 = 0x02;
pub const KIND_PROOF: u8 = 0x03;
pub const KIND_OPEN: u8 = 0x10;
pub const KIND_DATA: u8 = 0x11;
pub const KIND_CREDIT: u8 = 0x12;
pub const KIND_FIN: u8 = 0x13;
pub const KIND_RESET: u8 = 0x1F;

const _: () = assert!(
    HELLO_LEN == 3 + 16 + 16
        && CHALLENGE_LEN == HELLO_LEN
        && PROOF_LEN == 1 + 16
        && HELLO_LEN < MIN_FRAME
        && MEDIUM_BLE == 0x01
);

type HmacSha256 = Hmac<Sha256>;

/// One contact's RNB1 keys, seen from this node. Wiped on drop; `Debug`
/// shows no key, not even the contact's.
pub struct PairKeys {
    /// This node's Ed25519 identity key.
    pub me: [u8; 32],
    /// The contact's Ed25519 identity key.
    pub peer: [u8; 32],
    k_tok: Zeroizing<[u8; 32]>,
    k_knock: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for PairKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairKeys(..)")
    }
}

/// The RNB1 keys of `own` with the contact key `peer`: the R2 pairwise root
/// (the checks and errors of [`lan_beacon::pair_root`]: a key that is not a
/// canonical point, has small order or is `own`'s gives
/// [`BeaconError::BadKey`], an all-zero secret
/// [`BeaconError::NonContributory`]), its Bluetooth LE medium key
/// `K_ble = HKDF-Expand(K_root, "medium" || 0x01)`, then
/// `K_tok = HKDF-Expand(K_ble, "RNB1-token")` and
/// `K_knock = HKDF-Expand(K_ble, "RNB1-knock")`.
pub fn pair_keys(own: &Identity, peer: &[u8; 32]) -> Result<PairKeys, BeaconError> {
    let root = lan_beacon::pair_root(own, peer)?;
    Ok(keys_from_root(&root, own.public_key_bytes(), *peer))
}

/// [`pair_keys`] from the key `r` the medium keys come from: the R2
/// pairwise root, or `K_pair` of a pair seed (Phase 6b,
/// [`crate::pair_seed::pair_key`], which takes the root's place).
pub fn pair_keys_from(me: &[u8; 32], peer: &[u8; 32], r: &[u8; 32]) -> PairKeys {
    keys_from_root(r, *me, *peer)
}

/// [`pair_keys`] from the R2 pairwise root (or a `K_pair`).
fn keys_from_root(root: &[u8; 32], me: [u8; 32], peer: [u8; 32]) -> PairKeys {
    let ble = lan_beacon::medium_key(root, MEDIUM_BLE);
    PairKeys {
        me,
        peer,
        k_tok: expand(&ble, b"RNB1-token"),
        k_knock: expand(&ble, b"RNB1-knock"),
    }
}

/// HKDF-Expand-SHA256(PRK = `prk`, info = `label`, 32).
fn expand(prk: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::from_prk(prk)
        .expect("a 32-byte PRK is long enough")
        .expand(label, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn mac(key: &[u8; 32], parts: &[&[u8]]) -> HmacSha256 {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac takes any key");
    for part in parts {
        m.update(part);
    }
    m
}

fn tag16(m: HmacSha256) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&m.finalize().into_bytes()[..16]);
    out
}

/// RFC 9562 version-4 layout: version nibble 4, variant bits 10.
fn v4_bits(t: &mut [u8; 16]) {
    t[6] = (t[6] & 0x0f) | 0x40;
    t[8] = (t[8] & 0x3f) | 0x80;
}

/// The token epoch of a time: `unix_ms / EPOCH_MS`.
pub fn epoch_of(unix_ms: u64) -> u64 {
    unix_ms / EPOCH_MS
}

/// The epochs a scanner at `now_epoch` accepts: `now_epoch - 1 ..=
/// now_epoch + 1` (within u64).
pub fn scan_epochs(now_epoch: u64) -> RangeInclusive<u64> {
    now_epoch.saturating_sub(1)..=now_epoch.saturating_add(1)
}

/// RNB1 token `T(epoch, advertiser)`: `HMAC(K_tok, "RNB1" || 0x01 version
/// || 0x01 medium || u64be(epoch) || advertiser)[0..16]` with the
/// version-4 bits set. The advertiser is the side that advertises it and
/// hosts the GATT service (the peripheral).
pub fn token(k: &PairKeys, epoch: u64, advertiser: &[u8; 32]) -> [u8; 16] {
    let m = mac(
        &k.k_tok,
        &[
            b"RNB1",
            &[VERSION, MEDIUM_BLE],
            &epoch.to_be_bytes(),
            advertiser,
        ],
    );
    let mut t = tag16(m);
    v4_bits(&mut t);
    t
}

impl PairKeys {
    /// `T(epoch, me)`: the token this node advertises for the contact.
    pub fn token_out(&self, epoch: u64) -> [u8; 16] {
        token(self, epoch, &self.me)
    }

    /// `T(epoch, peer)`: the token the contact advertises for this node.
    pub fn token_in(&self, epoch: u64) -> [u8; 16] {
        token(self, epoch, &self.peer)
    }

    fn knock(&self, label: &[u8], t: &[u8; 16], fields: &[&[u8]]) -> HmacSha256 {
        let mut m = mac(&self.k_knock, &[label, t]);
        for field in fields {
            m.update(field);
        }
        m
    }
}

/// The characteristic UUID of the service `t`: `SHA-256("RNB1-char" ||
/// t)[0..16]` with the version-4 bits set.
pub fn char_uuid(t: &[u8; 16]) -> [u8; 16] {
    let digest = Sha256::new()
        .chain_update(b"RNB1-char")
        .chain_update(t)
        .finalize();
    let mut c = [0u8; 16];
    c.copy_from_slice(&digest[..16]);
    v4_bits(&mut c);
    c
}

/// A UUID as text: lowercase 8-4-4-4-12 over its 16 bytes in order.
pub fn uuid_string(u: &[u8; 16]) -> String {
    let h = hex::encode(u);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// A UUID as it goes on air in an advertisement (AD type 0x06/0x07): its
/// bytes reversed (little-endian).
pub fn uuid_ota_le(u: &[u8; 16]) -> [u8; 16] {
    let mut le = *u;
    le.reverse();
    le
}

/// The value a Windows GUID is made from (`GUID::from_u128`).
pub fn windows_guid_u128(u: &[u8; 16]) -> u128 {
    u128::from_be_bytes(*u)
}

/// The contact in `book` advertising `uuid` for this node, and the token's
/// epoch: the first contact whose `T(e, contact)` equals `uuid` for an `e`
/// in [`scan_epochs`]`(now_epoch)`. A match is a dial candidate, nothing
/// more: the knock, Noise and the contact gate decide.
pub fn match_token(uuid: &[u8; 16], now_epoch: u64, book: &[PairKeys]) -> Option<(usize, u64)> {
    scan_epochs(now_epoch).find_map(|e| {
        book.iter()
            .position(|k| k.token_in(e) == *uuid)
            .map(|i| (i, e))
    })
}

/// The central's side of one knock: the HELLO it sent on service `t`, kept
/// until the CHALLENGE.
#[derive(Debug, Clone)]
pub struct CentralKnock {
    t: [u8; 16],
    flags: u8,
    nonce: [u8; 16],
}

impl CentralKnock {
    /// A knock on service `t` with a fresh CSPRNG `nonce` and the V1 flags.
    pub fn new(t: [u8; 16], nonce: [u8; 16]) -> Self {
        Self {
            t,
            flags: FLAGS_V1,
            nonce,
        }
    }

    /// HELLO: `0x01 || 0x01 || flags_c || nonce_c || tag_h` with `tag_h =
    /// HMAC(K_knock, "RNK1/hello" || T || flags_c || nonce_c)[0..16]`.
    pub fn hello(&self, k: &PairKeys) -> [u8; HELLO_LEN] {
        let tag = tag16(k.knock(b"RNK1/hello", &self.t, &[&[self.flags], &self.nonce]));
        knock_frame(KIND_HELLO, self.flags, &self.nonce, &tag)
    }

    /// PROOF for a CHALLENGE of version 1 whose `tag_p` verifies:
    /// `0x03 || tag_c`, `tag_c = HMAC(K_knock, "RNK1/proof" || T || flags_c
    /// || nonce_c || flags_p || nonce_p)[0..16]`. `None` for anything else:
    /// the central aborts.
    pub fn proof(&self, k: &PairKeys, challenge: &Frame<'_>) -> Option<[u8; PROOF_LEN]> {
        let Frame::Challenge {
            version: VERSION,
            flags,
            nonce,
            tag,
        } = *challenge
        else {
            return None;
        };
        let fields: [&[u8]; 4] = [&[self.flags], &self.nonce, &[flags], &nonce];
        k.knock(b"RNK1/resp", &self.t, &fields)
            .verify_truncated_left(&tag)
            .ok()?;
        let tag_c = tag16(k.knock(b"RNK1/proof", &self.t, &fields));
        let mut out = [0u8; PROOF_LEN];
        out[0] = KIND_PROOF;
        out[1..].copy_from_slice(&tag_c);
        Some(out)
    }
}

/// The peripheral's side of one knock, after it answered a HELLO.
#[derive(Debug, Clone)]
pub struct PeripheralKnock {
    t: [u8; 16],
    flags_c: u8,
    nonce_c: [u8; 16],
    flags_p: u8,
    nonce_p: [u8; 16],
}

impl PeripheralKnock {
    /// The CHALLENGE for a HELLO that arrived on service `t`: only when its
    /// version is 1, its `tag_h` verifies under the pair's `K_knock` and its
    /// `nonce_c` is not in `replay` (then remembered). `nonce_p` is fresh
    /// CSPRNG output. `None` means the peripheral stays silent.
    pub fn answer(
        k: &PairKeys,
        t: [u8; 16],
        hello: &Frame<'_>,
        nonce_p: [u8; 16],
        replay: &mut KnockReplay,
    ) -> Option<(Self, [u8; CHALLENGE_LEN])> {
        let Frame::Hello {
            version: VERSION,
            flags,
            nonce,
            tag,
        } = *hello
        else {
            return None;
        };
        k.knock(b"RNK1/hello", &t, &[&[flags], &nonce])
            .verify_truncated_left(&tag)
            .ok()?;
        if !replay.insert(&t, &nonce) {
            return None;
        }
        let side = Self {
            t,
            flags_c: flags,
            nonce_c: nonce,
            flags_p: FLAGS_V1,
            nonce_p,
        };
        let tag_p = tag16(k.knock(b"RNK1/resp", &t, &side.fields()));
        let frame = knock_frame(KIND_CHALLENGE, side.flags_p, &nonce_p, &tag_p);
        Some((side, frame))
    }

    /// Whether `hello` is a V1 HELLO whose `tag_h` verifies under the pair's
    /// `K_knock` on service `t`, answered before or not: what tells a
    /// failed knock (Phase 6b `SEC_KNOCK_FAIL`) from a replayed HELLO when
    /// [`Self::answer`] stays silent. Remembers nothing.
    pub fn hello_verifies(k: &PairKeys, t: &[u8; 16], hello: &Frame<'_>) -> bool {
        let Frame::Hello {
            version: VERSION,
            flags,
            nonce,
            tag,
        } = *hello
        else {
            return false;
        };
        k.knock(b"RNK1/hello", t, &[&[flags], &nonce])
            .verify_truncated_left(&tag)
            .is_ok()
    }

    /// Whether `proof` is the PROOF of this knock: then the pipe is UP.
    pub fn accepts_proof(&self, k: &PairKeys, proof: &Frame<'_>) -> bool {
        let Frame::Proof { tag } = *proof else {
            return false;
        };
        k.knock(b"RNK1/proof", &self.t, &self.fields())
            .verify_truncated_left(&tag)
            .is_ok()
    }

    fn fields(&self) -> [&[u8]; 4] {
        [
            std::slice::from_ref(&self.flags_c),
            &self.nonce_c,
            std::slice::from_ref(&self.flags_p),
            &self.nonce_p,
        ]
    }
}

fn knock_frame(kind: u8, flags: u8, nonce: &[u8; 16], tag: &[u8; 16]) -> [u8; HELLO_LEN] {
    let mut out = [0u8; HELLO_LEN];
    out[0] = kind;
    out[1] = VERSION;
    out[2] = flags;
    out[3..19].copy_from_slice(nonce);
    out[19..].copy_from_slice(tag);
    out
}

/// The HELLO nonces a peripheral has answered, per token: a replayed HELLO
/// gets silence. At most [`REPLAY_PER_TOKEN`] per token (the oldest goes
/// first); the engine keeps the tokens of the current and previous epoch
/// ([`KnockReplay::retain`]). Only a HELLO whose tag verified is ever
/// remembered, so a stranger cannot fill it.
#[derive(Debug, Default)]
pub struct KnockReplay {
    seen: HashMap<[u8; 16], VecDeque<[u8; 16]>>,
}

impl KnockReplay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember `nonce` for `token`: true when it is new, false for a
    /// replay.
    pub fn insert(&mut self, token: &[u8; 16], nonce: &[u8; 16]) -> bool {
        let list = self.seen.entry(*token).or_default();
        if list.contains(nonce) {
            return false;
        }
        if list.len() == REPLAY_PER_TOKEN {
            list.pop_front();
        }
        list.push_back(*nonce);
        true
    }

    /// Forget the tokens `keep` refuses.
    pub fn retain(&mut self, mut keep: impl FnMut(&[u8; 16]) -> bool) {
        self.seen.retain(|t, _| keep(t));
    }

    /// How many tokens have remembered nonces.
    pub fn tokens(&self) -> usize {
        self.seen.len()
    }
}

/// Why a pipe ends: the RNP1 RESET codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[repr(u8)]
pub enum PipeError {
    /// An unknown kind, a wrong length, a bad channel, a channel owner,
    /// sequence or credit violation, or a knock frame after UP.
    #[error("RNP1 PROTOCOL")]
    Protocol = 1,
    /// No open channel for 30 s.
    #[error("RNP1 IDLE")]
    Idle = 2,
    /// More than [`MAX_CONTROL_RUN`] consecutive control frames.
    #[error("RNP1 LIMIT")]
    Limit = 3,
    /// The sender shuts down.
    #[error("RNP1 SHUTDOWN")]
    Shutdown = 4,
    /// A frame longer than the receiver's `max_rx`, or a link whose
    /// `max_tx` fell under [`MIN_FRAME`].
    #[error("RNP1 MTU")]
    Mtu = 5,
    /// Another pipe for the pair survives.
    #[error("RNP1 DUPLICATE")]
    Duplicate = 6,
}

impl PipeError {
    /// The RESET code.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// The code's name (as the vectors write it).
    pub fn name(self) -> &'static str {
        match self {
            Self::Protocol => "PROTOCOL",
            Self::Idle => "IDLE",
            Self::Limit => "LIMIT",
            Self::Shutdown => "SHUTDOWN",
            Self::Mtu => "MTU",
            Self::Duplicate => "DUPLICATE",
        }
    }

    /// The error a RESET code names, if any.
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Protocol,
            2 => Self::Idle,
            3 => Self::Limit,
            4 => Self::Shutdown,
            5 => Self::Mtu,
            6 => Self::Duplicate,
            _ => return None,
        })
    }

    /// The RESET frame carrying this code.
    pub fn reset(self) -> Frame<'static> {
        Frame::Reset { code: self.code() }
    }
}

/// One RNK1 or RNP1 frame (one ATT PDU value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    Hello {
        version: u8,
        flags: u8,
        nonce: [u8; 16],
        tag: [u8; 16],
    },
    Challenge {
        version: u8,
        flags: u8,
        nonce: [u8; 16],
        tag: [u8; 16],
    },
    Proof {
        tag: [u8; 16],
    },
    Open {
        chan: u8,
    },
    Data {
        chan: u8,
        seq: u16,
        payload: &'a [u8],
    },
    Credit {
        chan: u8,
        add: u16,
    },
    Fin {
        chan: u8,
        next_seq: u16,
    },
    Reset {
        code: u8,
    },
}

impl Frame<'_> {
    /// A knock frame (HELLO, CHALLENGE, PROOF).
    pub fn is_knock(&self) -> bool {
        matches!(
            self,
            Self::Hello { .. } | Self::Challenge { .. } | Self::Proof { .. }
        )
    }

    /// This frame's bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode(self, &mut out);
        out
    }
}

fn arr16(b: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(b);
    out
}

/// Decode one frame received on a link whose frames are at most `max_rx`
/// bytes (`min(ATT_MTU - 3, 512)`; values over [`MAX_FRAME`] count as
/// [`MAX_FRAME`]). A frame longer than that is [`PipeError::Mtu`]; an
/// empty frame, an unknown kind, a wrong length, a channel other than 0 or 1
/// or a CREDIT `add` outside 1..=64 is [`PipeError::Protocol`]. Knock frames
/// decode whatever their version: the knock checks it.
pub fn decode(buf: &[u8], max_rx: usize) -> Result<Frame<'_>, PipeError> {
    use PipeError::Protocol;
    if buf.len() > max_rx.min(MAX_FRAME) {
        return Err(PipeError::Mtu);
    }
    let (&kind, _) = buf.split_first().ok_or(Protocol)?;
    let fixed = |len: usize| {
        if buf.len() == len {
            Ok(())
        } else {
            Err(Protocol)
        }
    };
    let chan = |c: u8| if c <= 1 { Ok(c) } else { Err(Protocol) };
    let u16_at = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
    Ok(match kind {
        KIND_HELLO | KIND_CHALLENGE => {
            fixed(HELLO_LEN)?;
            let (version, flags) = (buf[1], buf[2]);
            let (nonce, tag) = (arr16(&buf[3..19]), arr16(&buf[19..35]));
            if kind == KIND_HELLO {
                Frame::Hello {
                    version,
                    flags,
                    nonce,
                    tag,
                }
            } else {
                Frame::Challenge {
                    version,
                    flags,
                    nonce,
                    tag,
                }
            }
        }
        KIND_PROOF => {
            fixed(PROOF_LEN)?;
            Frame::Proof {
                tag: arr16(&buf[1..]),
            }
        }
        KIND_OPEN => {
            fixed(2)?;
            Frame::Open {
                chan: chan(buf[1])?,
            }
        }
        KIND_DATA => {
            if buf.len() <= DATA_HEADER {
                return Err(Protocol);
            }
            Frame::Data {
                chan: chan(buf[1])?,
                seq: u16_at(2),
                payload: &buf[DATA_HEADER..],
            }
        }
        KIND_CREDIT => {
            fixed(4)?;
            let add = u16_at(2);
            if !(1..=W_MAX).contains(&add) {
                return Err(Protocol);
            }
            Frame::Credit {
                chan: chan(buf[1])?,
                add,
            }
        }
        KIND_FIN => {
            fixed(4)?;
            Frame::Fin {
                chan: chan(buf[1])?,
                next_seq: u16_at(2),
            }
        }
        KIND_RESET => {
            fixed(2)?;
            Frame::Reset { code: buf[1] }
        }
        _ => return Err(Protocol),
    })
}

/// Append `f`'s bytes to `out`. It does not check the frame: a sender keeps
/// a DATA payload within `1..=max_tx - 4` ([`PipeState::max_payload`]).
pub fn encode(f: &Frame<'_>, out: &mut Vec<u8>) {
    match *f {
        Frame::Hello {
            version,
            flags,
            nonce,
            tag,
        } => {
            out.extend_from_slice(&[KIND_HELLO, version, flags]);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&tag);
        }
        Frame::Challenge {
            version,
            flags,
            nonce,
            tag,
        } => {
            out.extend_from_slice(&[KIND_CHALLENGE, version, flags]);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&tag);
        }
        Frame::Proof { tag } => {
            out.push(KIND_PROOF);
            out.extend_from_slice(&tag);
        }
        Frame::Open { chan } => out.extend_from_slice(&[KIND_OPEN, chan]),
        Frame::Data { chan, seq, payload } => {
            out.extend_from_slice(&[KIND_DATA, chan]);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(payload);
        }
        Frame::Credit { chan, add } => {
            out.extend_from_slice(&[KIND_CREDIT, chan]);
            out.extend_from_slice(&add.to_be_bytes());
        }
        Frame::Fin { chan, next_seq } => {
            out.extend_from_slice(&[KIND_FIN, chan]);
            out.extend_from_slice(&next_seq.to_be_bytes());
        }
        Frame::Reset { code } => out.extend_from_slice(&[KIND_RESET, code]),
    }
}

/// This side's GATT role on the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Scanned, connected and knocked; opens channel 0.
    Central,
    /// Advertised and hosts the service; opens channel 1.
    Peripheral,
}

impl Role {
    /// The channel this role opens (and is the Noise initiator on).
    pub fn own_chan(self) -> u8 {
        match self {
            Self::Central => 0,
            Self::Peripheral => 1,
        }
    }
}

/// One channel's state. An instance starts at OPEN and ends when both
/// directions have FINed; then its owner may OPEN it again.
#[derive(Debug, Clone, Copy, Default)]
struct ChanState {
    /// An instance was ever opened.
    opened: bool,
    /// The sequence number of this side's next DATA.
    tx_seq: u16,
    /// The sequence number the next received DATA must carry.
    rx_seq: u16,
    /// DATA frames this side may still send.
    tx_credit: u16,
    /// DATA frames the other side may still send.
    rx_credit: u16,
    /// Received DATA frames delivered to the link but not yet granted back.
    rx_ungranted: u16,
    fin_tx: bool,
    fin_rx: bool,
}

impl ChanState {
    fn active(&self) -> bool {
        self.opened && !(self.fin_tx && self.fin_rx)
    }

    fn start(&mut self) {
        *self = Self {
            opened: true,
            tx_credit: W0,
            rx_credit: W0,
            ..Self::default()
        };
    }
}

/// What a received frame did to the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxAction<'a> {
    /// Bytes for the channel's link, in order.
    Deliver { chan: u8, bytes: &'a [u8] },
    /// The other side opened its channel: run the contact-gated responder.
    Opened { chan: u8 },
    /// The other side's direction of the channel ended.
    Fined { chan: u8 },
    /// More DATA credit on the channel.
    Credit { chan: u8 },
    /// The other side reset the pipe with this code: it is dead.
    Reset(u8),
}

/// The pure RNP1 state of one pipe after UP: channel ownership, sequence
/// numbers, credits and the control-frame run. The driver sends what it
/// returns; any error means send RESET with that code, and the pipe is dead.
#[derive(Debug, Clone)]
pub struct PipeState {
    role: Role,
    max_tx: usize,
    max_rx: usize,
    chans: [ChanState; 2],
    control_run: u16,
    dead: bool,
}

impl PipeState {
    /// A pipe that just came UP. `max_tx` and `max_rx` are this side's frame
    /// limits per direction (values over [`MAX_FRAME`] count as
    /// [`MAX_FRAME`]); under [`MIN_FRAME`] there is no pipe
    /// ([`PipeError::Mtu`]).
    pub fn new(role: Role, max_tx: usize, max_rx: usize) -> Result<Self, PipeError> {
        if max_tx < MIN_FRAME || max_rx < MIN_FRAME {
            return Err(PipeError::Mtu);
        }
        Ok(Self {
            role,
            max_tx: max_tx.min(MAX_FRAME),
            max_rx: max_rx.min(MAX_FRAME),
            chans: [ChanState::default(); 2],
            control_run: 0,
            dead: false,
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn max_tx(&self) -> usize {
        self.max_tx
    }

    pub fn max_rx(&self) -> usize {
        self.max_rx
    }

    /// The most payload bytes one DATA frame carries: `max_tx - 4`.
    pub fn max_payload(&self) -> usize {
        self.max_tx - DATA_HEADER
    }

    /// After a RESET was sent or received, or an error: nothing more flows.
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// A channel instance is open (not yet FINed both ways).
    pub fn is_open(&self, chan: u8) -> bool {
        self.chan(chan).is_some_and(ChanState::active)
    }

    /// Any channel instance is open (the idle timer runs while none is).
    pub fn any_open(&self) -> bool {
        self.chans.iter().any(ChanState::active)
    }

    /// DATA frames this side may still send on `chan`.
    pub fn tx_credit(&self, chan: u8) -> u16 {
        self.chan(chan).map_or(0, |c| c.tx_credit)
    }

    fn chan(&self, chan: u8) -> Option<&ChanState> {
        self.chans.get(usize::from(chan))
    }

    /// Decode and apply one received frame ([`decode`] at this pipe's
    /// `max_rx`, then [`PipeState::on_rx`]).
    pub fn on_rx_bytes<'a>(&mut self, buf: &'a [u8]) -> Result<RxAction<'a>, PipeError> {
        match decode(buf, self.max_rx) {
            Ok(f) => self.on_rx(&f),
            Err(e) => {
                self.dead = true;
                Err(e)
            }
        }
    }

    /// Apply one received frame. An error kills the pipe: send RESET with
    /// its code.
    pub fn on_rx<'a>(&mut self, f: &Frame<'a>) -> Result<RxAction<'a>, PipeError> {
        if self.dead {
            return Err(PipeError::Protocol);
        }
        let r = self.apply(f);
        if r.is_err() || matches!(r, Ok(RxAction::Reset(_))) {
            self.dead = true;
        }
        r
    }

    fn apply<'a>(&mut self, f: &Frame<'a>) -> Result<RxAction<'a>, PipeError> {
        use PipeError::Protocol;
        // What `decode` refuses, for a frame built by hand.
        match *f {
            Frame::Hello { .. } | Frame::Challenge { .. } | Frame::Proof { .. } => {
                return Err(Protocol)
            }
            Frame::Open { chan } | Frame::Fin { chan, .. } if chan > 1 => return Err(Protocol),
            Frame::Credit { chan, add } if chan > 1 || !(1..=W_MAX).contains(&add) => {
                return Err(Protocol)
            }
            Frame::Data { payload, .. } if DATA_HEADER + payload.len() > self.max_rx => {
                return Err(PipeError::Mtu)
            }
            Frame::Data { chan, .. } if chan > 1 => return Err(Protocol),
            _ => {}
        }
        match *f {
            Frame::Data { chan, seq, payload } => {
                let c = &mut self.chans[usize::from(chan)];
                if !c.active()
                    || c.fin_rx
                    || seq != c.rx_seq
                    || seq > LAST_DATA_SEQ
                    || c.rx_credit == 0
                    || payload.is_empty()
                {
                    return Err(Protocol);
                }
                c.rx_seq += 1;
                c.rx_credit -= 1;
                self.control_run = 0;
                return Ok(RxAction::Deliver {
                    chan,
                    bytes: payload,
                });
            }
            Frame::Reset { code } => return Ok(RxAction::Reset(code)),
            _ => {}
        }
        self.control_run += 1;
        if self.control_run > MAX_CONTROL_RUN {
            return Err(PipeError::Limit);
        }
        match *f {
            Frame::Open { chan } => {
                let c = &mut self.chans[usize::from(chan)];
                if chan == self.role.own_chan() || c.active() {
                    return Err(Protocol);
                }
                c.start();
                Ok(RxAction::Opened { chan })
            }
            Frame::Credit { chan, add } => {
                let c = &mut self.chans[usize::from(chan)];
                if !c.active() || c.tx_credit + add > W_MAX {
                    return Err(Protocol);
                }
                c.tx_credit += add;
                Ok(RxAction::Credit { chan })
            }
            Frame::Fin { chan, next_seq } => {
                let c = &mut self.chans[usize::from(chan)];
                if !c.active() || c.fin_rx || next_seq != c.rx_seq {
                    return Err(Protocol);
                }
                c.fin_rx = true;
                Ok(RxAction::Fined { chan })
            }
            _ => Err(Protocol),
        }
    }

    /// OPEN this side's channel ([`Role::own_chan`]): a new instance with
    /// sequence numbers at 0 and [`W0`] credit each way. `None` while the
    /// previous instance is still open (wait for both FINs) or the pipe is
    /// dead.
    pub fn open(&mut self) -> Option<Frame<'static>> {
        let chan = self.role.own_chan();
        let c = &mut self.chans[usize::from(chan)];
        if self.dead || c.active() {
            return None;
        }
        c.start();
        Some(Frame::Open { chan })
    }

    /// Whether this side may send DATA on `chan` now: the instance is open,
    /// this side has not FINed it, it holds credit and its next sequence
    /// number is at most [`LAST_DATA_SEQ`].
    pub fn can_send(&self, chan: u8) -> bool {
        !self.dead
            && self.chan(chan).is_some_and(|c| {
                c.active() && !c.fin_tx && c.tx_credit > 0 && c.tx_seq <= LAST_DATA_SEQ
            })
    }

    /// Take the sequence number of one DATA frame on `chan` (one credit).
    /// `None` when [`PipeState::can_send`] is false.
    pub fn on_tx_data(&mut self, chan: u8) -> Option<u16> {
        if !self.can_send(chan) {
            return None;
        }
        let c = &mut self.chans[usize::from(chan)];
        let seq = c.tx_seq;
        c.tx_seq += 1;
        c.tx_credit -= 1;
        // The other side's CREDITs answer this side's DATA: a one-way
        // transfer is a run of control frames on the sender's receive side.
        self.control_run = 0;
        Some(seq)
    }

    /// FIN this side's direction of `chan` (`next_seq` = its next sequence
    /// number). `None` when the instance is not open or already FINed.
    pub fn fin(&mut self, chan: u8) -> Option<Frame<'static>> {
        if self.dead {
            return None;
        }
        let c = self.chans.get_mut(usize::from(chan))?;
        if !c.active() || c.fin_tx {
            return None;
        }
        c.fin_tx = true;
        Some(Frame::Fin {
            chan,
            next_seq: c.tx_seq,
        })
    }

    /// `frames` received DATA frames of `chan` were delivered to its link:
    /// once at least `W0 / 2` are ungranted, the CREDIT that returns them
    /// (never past [`W_MAX`] outstanding). `None` otherwise, and after the
    /// other side FINed.
    pub fn consumed(&mut self, chan: u8, frames: u16) -> Option<Frame<'static>> {
        if self.dead {
            return None;
        }
        let c = self.chans.get_mut(usize::from(chan))?;
        if !c.active() || c.fin_rx {
            return None;
        }
        c.rx_ungranted = c.rx_ungranted.saturating_add(frames);
        if c.rx_ungranted < W0 / 2 {
            return None;
        }
        let add = c.rx_ungranted.min(W_MAX - c.rx_credit);
        c.rx_ungranted = 0;
        if add == 0 {
            return None;
        }
        c.rx_credit += add;
        Some(Frame::Credit { chan, add })
    }

    /// End the pipe with `e`: the RESET frame to send.
    pub fn reset(&mut self, e: PipeError) -> Frame<'static> {
        self.dead = true;
        e.reset()
    }
}

#[cfg(test)]
mod tests;
