//! RAVEN Link Padding V1 (PAD1, `protocol/RAVEN_LINK_PADDING_V1.md`;
//! `docs/roadmap/plans/phase6-design.json` step P6.33, design B §2 and W-B1,
//! owner decision OD6b-8): every frame on a Raven link padded to one of four
//! sizes, so someone on the path sees four size classes instead of exact
//! frame lengths (an ACK and a short text look alike, and so do a PairInit
//! and a medium text).
//!
//! ```text
//! frame = "RPD1" || 0x01 || 0x00 || inner_len u16 BE || inner || 0x00 padding
//! ```
//!
//! The frame's length is the smallest of [`PAD1_BUCKETS`] that holds the
//! 8-byte header and the inner frame (one link frame: a LAN bind, RVN1,
//! RLB1, RRH1, RFC1, RSR1, PairInit; 1..=[`PAD1_MAX_INNER`] bytes). The
//! largest bucket is [`MAX_TRANSPORT_PLAINTEXT`]: a padded frame is still one
//! Noise transport message.
//!
//! Negotiated per link with caps bit 9 ([`CAP_LINK_PAD1`](crate::CAP_LINK_PAD1)):
//! the signed RIH1 hello on Internet direct, p2p and nearby links, the
//! dialer's RLX1 `LINK_CAPS` on LAN. Old peers never set the bit, so they
//! never receive RPD1. [`PadState`] is one side of one link: what it sends
//! ([`PadState::on_send`]) and what it reads ([`PadState::on_recv`]: strict
//! after the peer's first RPD1 frame).
//!
//! Pure: no I/O, no clock, no randomness (the padding is zeros; the Noise
//! encryption around the frame hides it). The links use it (P6.34) only
//! while [`SecGate::LinkPadding`](crate::security_gate::SecGate::LinkPadding)
//! is live (`LINK_PADDING_PRODUCTION_ENABLED = false`); with the gate shut
//! every link is [`PadState::OFF`] and nothing on the wire changes.

use std::borrow::Cow;

use thiserror::Error;

use crate::lan_noise::MAX_TRANSPORT_PLAINTEXT;

/// The frame magic.
pub const PAD1_MAGIC: &[u8; 4] = b"RPD1";
/// The version byte this revision writes and reads.
pub const PAD1_VERSION: u8 = 0x01;
/// Magic, version, reserved byte and `inner_len`.
pub const PAD1_HEADER_LEN: usize = 8;
/// The frame lengths a padded frame may have (OD6b-8, option 1), smallest
/// first. The last is [`MAX_TRANSPORT_PLAINTEXT`].
pub const PAD1_BUCKETS: [usize; 4] = [512, 4_096, 16_384, 65_519];
/// The longest inner frame: the largest bucket less the header.
pub const PAD1_MAX_INNER: usize = 65_511;

const _: () = assert!(PAD1_BUCKETS[3] == MAX_TRANSPORT_PLAINTEXT);
const _: () = assert!(PAD1_MAX_INNER == PAD1_BUCKETS[3] - PAD1_HEADER_LEN);
const _: () = assert!(PAD1_MAX_INNER <= u16::MAX as usize);

/// Zeros to compare padding with: a slice compare is one `memcmp`.
static ZEROS: [u8; PAD1_MAX_INNER] = [0; PAD1_MAX_INNER];

/// Why a frame is refused (spec §6). Every refusal closes the link.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Pad1Error {
    /// [`unwrap`]: the frame does not start with `RPD1`.
    #[error("PAD1 BAD_MAGIC")]
    BadMagic,
    /// The frame's length is not one of [`PAD1_BUCKETS`].
    #[error("PAD1 BAD_BUCKET")]
    BadBucket,
    /// The version byte is not [`PAD1_VERSION`].
    #[error("PAD1 BAD_VERSION")]
    BadVersion,
    /// The reserved byte is not 0.
    #[error("PAD1 BAD_RESERVED")]
    BadReserved,
    /// `inner_len` is 0 or longer than the frame holds; for [`wrap`], an
    /// empty inner frame or one longer than [`PAD1_MAX_INNER`].
    #[error("PAD1 BAD_LENGTH")]
    BadLength,
    /// A padding byte is not 0.
    #[error("PAD1 NONZERO_PADDING")]
    NonZeroPadding,
    /// The inner frame starts with `RPD1`: padding is never nested.
    #[error("PAD1 NESTED")]
    Nested,
    /// [`PadState::on_recv`]: a frame that is not RPD1 after the peer's
    /// first RPD1 frame on this link.
    #[error("PAD1 UNPADDED")]
    Unpadded,
}

impl Pad1Error {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::BadMagic => "BAD_MAGIC",
            Self::BadBucket => "BAD_BUCKET",
            Self::BadVersion => "BAD_VERSION",
            Self::BadReserved => "BAD_RESERVED",
            Self::BadLength => "BAD_LENGTH",
            Self::NonZeroPadding => "NONZERO_PADDING",
            Self::Nested => "NESTED",
            Self::Unpadded => "UNPADDED",
        }
    }
}

/// The length of the padded frame of an `inner_len`-byte inner frame: the
/// smallest bucket that holds it and the header. `None` for 0 or more than
/// [`PAD1_MAX_INNER`].
pub fn bucket_for(inner_len: usize) -> Option<usize> {
    if inner_len == 0 {
        return None;
    }
    let need = inner_len.checked_add(PAD1_HEADER_LEN)?;
    PAD1_BUCKETS.into_iter().find(|&t| t >= need)
}

/// `inner` padded to its bucket (spec §2, §5).
pub fn wrap(inner: &[u8]) -> Result<Vec<u8>, Pad1Error> {
    if inner.starts_with(PAD1_MAGIC) {
        return Err(Pad1Error::Nested);
    }
    let total = bucket_for(inner.len()).ok_or(Pad1Error::BadLength)?;
    let inner_len = u16::try_from(inner.len()).map_err(|_| Pad1Error::BadLength)?;
    let mut frame = vec![0u8; total];
    frame[..4].copy_from_slice(PAD1_MAGIC);
    frame[4] = PAD1_VERSION;
    frame[6..PAD1_HEADER_LEN].copy_from_slice(&inner_len.to_be_bytes());
    frame[PAD1_HEADER_LEN..PAD1_HEADER_LEN + inner.len()].copy_from_slice(inner);
    Ok(frame)
}

/// The inner frame of a padded `frame`, checked in the order of spec §6:
/// magic, bucket, version, reserved byte, `inner_len`, padding, nesting. A
/// receiver does not check that the bucket is the smallest that fits.
pub fn unwrap(frame: &[u8]) -> Result<&[u8], Pad1Error> {
    if !frame.starts_with(PAD1_MAGIC) {
        return Err(Pad1Error::BadMagic);
    }
    let total = frame.len();
    if !PAD1_BUCKETS.contains(&total) {
        return Err(Pad1Error::BadBucket);
    }
    if frame[4] != PAD1_VERSION {
        return Err(Pad1Error::BadVersion);
    }
    if frame[5] != 0 {
        return Err(Pad1Error::BadReserved);
    }
    let inner_len = usize::from(u16::from_be_bytes([frame[6], frame[7]]));
    if inner_len == 0 || inner_len > total - PAD1_HEADER_LEN {
        return Err(Pad1Error::BadLength);
    }
    let (inner, padding) = frame[PAD1_HEADER_LEN..].split_at(inner_len);
    if padding != &ZEROS[..padding.len()] {
        return Err(Pad1Error::NonZeroPadding);
    }
    if inner.starts_with(PAD1_MAGIC) {
        return Err(Pad1Error::Nested);
    }
    Ok(inner)
}

/// PAD1 on one link, one side (spec §4, §6), from the end of the handshake
/// (and, on Internet direct, p2p and nearby links, both hellos) to the close.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PadState {
    /// This side reads RPD1 frames: it offered PAD1 on this link. A side
    /// that did not hands every frame on untouched, so an RPD1 frame from a
    /// peer that was never asked meets the link's usual handling of a frame
    /// it does not know.
    reads: bool,
    /// This side wraps every frame it sends.
    negotiated: bool,
    /// The peer's first RPD1 frame arrived: every later frame from it must
    /// be one.
    peer_started: bool,
}

impl PadState {
    /// No PAD1 on this link (the gate is shut, or a side did not offer it):
    /// every frame goes out and comes in exactly as without PAD1.
    pub const OFF: Self = Self {
        reads: false,
        negotiated: false,
        peer_started: false,
    };

    /// A side that knows whether both offered PAD1 on this link when the
    /// link starts: Internet direct, p2p and nearby links (both verified
    /// hellos carry bit 9), and the LAN listener (it offers PAD1 and the
    /// dialer's `LINK_CAPS` carries bit 9; it wraps from its bind on).
    /// `both` false is [`PadState::OFF`].
    pub fn agreed(both: bool) -> Self {
        Self {
            reads: both,
            negotiated: both,
            peer_started: false,
        }
    }

    /// The LAN dialer, which put bit 9 in its `LINK_CAPS` when `offered`:
    /// it reads RPD1 at once and wraps what it sends from the listener's
    /// first RPD1 frame on (a listener without PAD1 never sends one).
    /// `offered` false is [`PadState::OFF`].
    pub fn lan_dialer(offered: bool) -> Self {
        Self {
            reads: offered,
            negotiated: false,
            peer_started: false,
        }
    }

    /// Does this side wrap what it sends?
    pub fn negotiated(&self) -> bool {
        self.negotiated
    }

    /// Has the peer sent its first RPD1 frame on this link?
    pub fn peer_started(&self) -> bool {
        self.peer_started
    }

    /// The bytes to send for the link frame `frame`: padded once this side
    /// wraps, `frame` itself before. An error ([`wrap`]'s: an empty frame,
    /// one longer than [`PAD1_MAX_INNER`], one that starts with `RPD1`)
    /// means the frame cannot go on this link: sent bare it would close it.
    pub fn on_send<'a>(&self, frame: &'a [u8]) -> Result<Cow<'a, [u8]>, Pad1Error> {
        if self.negotiated {
            wrap(frame).map(Cow::Owned)
        } else {
            Ok(Cow::Borrowed(frame))
        }
    }

    /// The link frame in `frame`, as the peer sent it: unwrapped when it is
    /// an RPD1 frame and this side reads them, `frame` itself when it is
    /// not and the peer has not padded yet. After the peer's first RPD1
    /// frame, one that is not is [`Pad1Error::Unpadded`]. An error closes
    /// the link.
    pub fn on_recv<'a>(&mut self, frame: &'a [u8]) -> Result<&'a [u8], Pad1Error> {
        if !self.reads {
            return Ok(frame);
        }
        if frame.starts_with(PAD1_MAGIC) {
            let inner = unwrap(frame)?;
            self.peer_started = true;
            // A LAN dialer now knows the listener reads RPD1 too.
            self.negotiated = true;
            return Ok(inner);
        }
        if self.peer_started {
            return Err(Pad1Error::Unpadded);
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests;
