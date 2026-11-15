//! The attachment blob of `RVNATT/1`: one encryption for every path
//! (`docs/design/2026-11-attachments.md` §7).
//!
//! An attachment's bytes are padded with zeros to a size class (Padmé), cut
//! into segments of 61,424 bytes, and each segment is sealed on its own with
//! XChaCha20-Poly1305, under a key used for this attachment only, into a
//! chunk of 61,440 bytes (the last may be shorter). The RFC 6962 tree of the
//! release bundles ([`crate::release_bundle`]) is built over the sealed
//! chunks; its root travels in the offer, and every chunk is checked against
//! it with its audit path the moment it lands, whoever passed it on.
//!
//! ```text
//! padded     = bytes || zeros, Padmé(len) bytes in all
//! segment i  = padded[i * 61,424 ..][.. 61,424]            (the last: what is left)
//! chunk key  = HKDF-SHA256(key, info "rvnatt/1 chunk key")[32]
//! handle     = HKDF-SHA256(key, info "rvnatt/1 handle")[16]
//! custody id = HKDF-SHA256(key, info "rvnatt/1 custody id" || i u16 BE)[16]
//! nonce i    = i u64 BE || 16 zero bytes
//! aad i      = "rvnatt/1" || padded_len u64 BE || chunk_count u32 BE || i u32 BE
//! chunk i    = XChaCha20-Poly1305(chunk key, nonce i, aad i, segment i)
//! leaf i     = SHA-256(0x00 || chunk i);  root = RFC 6962 over the leaves
//! ```
//!
//! The key is random and new for every attachment, never derived from the
//! content: two copies of one photo are unrelated. A chunk cannot move to
//! another place (its index is in the nonce and the additional data) and
//! the attachment cannot be cut short (the count and the padded length are
//! in the additional data of every chunk).
//!
//! Nothing here reads a lab switch, a file or a clock: bytes in, bytes out.
//! Not a frozen wire format yet: `protocol/RAVEN_ATTACHMENT_V1.md` is still
//! to be written from this.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::release_bundle::{self, ChunkTree};
use crate::tlog;

/// The plaintext bytes one chunk holds.
pub const SEGMENT_LEN: usize = 61_424;
/// The Poly1305 tag at the end of every chunk.
pub const TAG_LEN: usize = 16;
/// A sealed chunk: the chunk size of the release bundles' tree.
pub const CHUNK_LEN: usize = SEGMENT_LEN + TAG_LEN;
/// The largest attachment (64 MB).
pub const MAX_LEN: u64 = 64_000_000;
/// What [`MAX_LEN`] pads to.
pub const MAX_PADDED_LEN: u64 = 65_011_712;
/// The chunks of [`MAX_PADDED_LEN`].
pub const MAX_CHUNKS: u32 = 1_059;
/// The key of one attachment.
pub const KEY_LEN: usize = 32;
/// The name of an attachment on links and on disk.
pub const HANDLE_LEN: usize = 16;
/// The name of one chunk at a mail friend.
pub const CUSTODY_ID_LEN: usize = 16;
/// The most bytes of an attachment that is always exactly one chunk (a
/// profile picture).
pub const ONE_CHUNK_MAX_LEN: u64 = 60_000;
/// The longest audit path a chunk travels with.
pub const MAX_PATH_LEN: usize = release_bundle::MAX_CHUNK_PATH_LEN;

const LABEL_CHUNK_KEY: &[u8] = b"rvnatt/1 chunk key";
const LABEL_HANDLE: &[u8] = b"rvnatt/1 handle";
const LABEL_CUSTODY_ID: &[u8] = b"rvnatt/1 custody id";
const AAD_DOMAIN: &[u8] = b"rvnatt/1";

const _: () = assert!(CHUNK_LEN == release_bundle::CHUNK_SIZE as usize);
const _: () =
    assert!(MAX_PADDED_LEN + MAX_CHUNKS as u64 * TAG_LEN as u64 <= release_bundle::MAX_PAYLOAD_LEN);

/// Why blob bytes are refused.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    /// An attachment has at least one byte.
    #[error("ATTACHMENT EMPTY")]
    Empty,
    /// More than [`MAX_LEN`] bytes.
    #[error("ATTACHMENT TOO_BIG")]
    TooBig,
    /// The padded length or the chunk count does not follow from the length.
    #[error("ATTACHMENT SHAPE")]
    Shape,
    /// A chunk index past the last chunk.
    #[error("ATTACHMENT INDEX")]
    Index,
    /// A segment or a chunk of the wrong length for its place.
    #[error("ATTACHMENT LENGTH")]
    Length,
    /// A chunk that does not open under this key at this place.
    #[error("ATTACHMENT SEAL")]
    Seal,
    /// Bytes after the true length that are not zero.
    #[error("ATTACHMENT PADDING")]
    Padding,
}

/// Padmé (the padding of the PURBs paper): `len` rounded up so that its
/// lowest `floor(log2 len) - floor(log2 floor(log2 len)) - 1` bits are zero.
/// A size keeps about log log n bits and grows by at most 12 %.
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = u64::from(63 - len.leading_zeros());
    let s = u64::from(63 - e.leading_zeros()) + 1;
    let mask = (1u64 << (e - s)) - 1;
    (len + mask) & !mask
}

/// The sizes of one attachment: its true length, its padded length and its
/// chunk count. The offer carries all three, and the two that follow from
/// the first must match it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    len: u64,
    padded: u64,
    chunks: u32,
}

impl Shape {
    /// The shape of an attachment of `len` bytes (1 to [`MAX_LEN`]).
    pub fn of(len: u64) -> Result<Shape, BlobError> {
        if len == 0 {
            return Err(BlobError::Empty);
        }
        if len > MAX_LEN {
            return Err(BlobError::TooBig);
        }
        let padded = padme(len);
        let chunks = padded.div_ceil(SEGMENT_LEN as u64);
        let chunks = u32::try_from(chunks).map_err(|_| BlobError::TooBig)?;
        Ok(Shape {
            len,
            padded,
            chunks,
        })
    }

    /// The shape of a profile picture: `len` bytes (1 to
    /// [`ONE_CHUNK_MAX_LEN`]) padded to exactly one whole segment, whatever
    /// Padmé would say, so that every picture is the same single chunk on
    /// the wire and at a mail friend
    /// (`docs/design/2026-11-profile-pictures.md` §8.3).
    pub fn one_chunk(len: u64) -> Result<Shape, BlobError> {
        if len == 0 {
            return Err(BlobError::Empty);
        }
        if len > ONE_CHUNK_MAX_LEN {
            return Err(BlobError::TooBig);
        }
        Ok(Shape {
            len,
            padded: SEGMENT_LEN as u64,
            chunks: 1,
        })
    }

    /// The shape an offer names: refused unless the padded length and the
    /// chunk count are the ones that follow from the length.
    pub fn from_offer(len: u64, padded: u64, chunks: u32) -> Result<Shape, BlobError> {
        let shape = Shape::of(len)?;
        if shape.padded != padded || shape.chunks != chunks {
            return Err(BlobError::Shape);
        }
        Ok(shape)
    }

    /// The true length.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Never: an attachment has at least one byte.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The padded length.
    pub fn padded(&self) -> u64 {
        self.padded
    }

    /// How many chunks.
    pub fn chunks(&self) -> u32 {
        self.chunks
    }

    /// The plaintext bytes of chunk `index`.
    pub fn segment_len(&self, index: u32) -> Option<usize> {
        if index >= self.chunks {
            return None;
        }
        let before = u64::from(index) * SEGMENT_LEN as u64;
        let left = self.padded - before;
        Some(usize::try_from(left.min(SEGMENT_LEN as u64)).expect("at most a segment"))
    }

    /// The sealed bytes of chunk `index`.
    pub fn chunk_len(&self, index: u32) -> Option<usize> {
        self.segment_len(index).map(|n| n + TAG_LEN)
    }

    /// Where chunk `index` starts in the sealed blob.
    pub fn chunk_offset(&self, index: u32) -> Option<u64> {
        (index < self.chunks).then(|| u64::from(index) * CHUNK_LEN as u64)
    }

    /// The sealed blob: every chunk back to back.
    pub fn sealed_len(&self) -> u64 {
        self.padded + u64::from(self.chunks) * TAG_LEN as u64
    }
}

/// The key of one attachment. Zeroed when dropped; never printed.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    /// A new random key.
    pub fn random() -> Key {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        rand::rngs::OsRng.fill_bytes(&mut key[..]);
        Key(key)
    }

    /// The key an offer or a store row carries.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Key {
        Key(Zeroizing::new(bytes))
    }

    /// The key's bytes, for the offer and the sealed store row only.
    pub fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn expand<const N: usize>(&self, info: &[&[u8]]) -> [u8; N] {
        let mut out = [0u8; N];
        Hkdf::<Sha256>::new(None, &self.0[..])
            .expand_multi_info(info, &mut out)
            .expect("32 bytes or fewer from HKDF-SHA256");
        out
    }

    /// The name of this attachment on links and on disk: the root never
    /// appears outside sealed messages.
    pub fn handle(&self) -> [u8; HANDLE_LEN] {
        self.expand(&[LABEL_HANDLE])
    }

    /// The name of chunk `index` at a mail friend: unrelated ids, so a
    /// keeper cannot tell from them which chunks belong together.
    pub fn custody_id(&self, index: u16) -> [u8; CUSTODY_ID_LEN] {
        self.expand(&[LABEL_CUSTODY_ID, &index.to_be_bytes()])
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(self.expand(&[LABEL_CHUNK_KEY]));
        XChaCha20Poly1305::new_from_slice(&key[..]).expect("a 32-byte key")
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

fn nonce(index: u32) -> XNonce {
    let mut n = [0u8; 24];
    n[..8].copy_from_slice(&u64::from(index).to_be_bytes());
    XNonce::from(n)
}

fn aad(shape: &Shape, index: u32) -> [u8; 24] {
    let mut a = [0u8; 24];
    a[..8].copy_from_slice(AAD_DOMAIN);
    a[8..16].copy_from_slice(&shape.padded.to_be_bytes());
    a[16..20].copy_from_slice(&shape.chunks.to_be_bytes());
    a[20..].copy_from_slice(&index.to_be_bytes());
    a
}

const _: () = assert!(AAD_DOMAIN.len() == 8);

/// Seals segment `index` (exactly [`Shape::segment_len`] plaintext bytes,
/// already padded) into its chunk.
pub fn seal_chunk(
    key: &Key,
    shape: &Shape,
    index: u32,
    segment: &[u8],
) -> Result<Vec<u8>, BlobError> {
    let want = shape.segment_len(index).ok_or(BlobError::Index)?;
    if segment.len() != want {
        return Err(BlobError::Length);
    }
    key.cipher()
        .encrypt(
            &nonce(index),
            Payload {
                msg: segment,
                aad: &aad(shape, index),
            },
        )
        .map_err(|_| BlobError::Seal)
}

/// Opens chunk `index`: its segment, still padded. Refused unless the
/// chunk has the length of its place and opens under this key there.
pub fn open_chunk(
    key: &Key,
    shape: &Shape,
    index: u32,
    chunk: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BlobError> {
    let want = shape.chunk_len(index).ok_or(BlobError::Index)?;
    if chunk.len() != want {
        return Err(BlobError::Length);
    }
    key.cipher()
        .decrypt(
            &nonce(index),
            Payload {
                msg: chunk,
                aad: &aad(shape, index),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| BlobError::Seal)
}

/// The tree leaf of a sealed chunk.
pub fn leaf(chunk: &[u8]) -> [u8; 32] {
    tlog::leaf_hash(chunk)
}

/// Is `chunk` chunk `index` of the attachment with this `root`? Its length
/// must be the length of its place, and its audit `path` must lead to the
/// root. Checked before a chunk is written, whoever sent it.
pub fn check_chunk(
    root: &[u8; 32],
    shape: &Shape,
    index: u32,
    chunk: &[u8],
    path: &[[u8; 32]],
) -> bool {
    if shape.chunk_len(index) != Some(chunk.len()) || path.len() > MAX_PATH_LEN {
        return false;
    }
    release_bundle::verify_chunk_path(
        root,
        u64::from(shape.chunks),
        u64::from(index),
        &leaf(chunk),
        path,
    )
}

/// An attachment sealed in memory: what a sender's node keeps and serves.
#[derive(Debug, Clone)]
pub struct Sealed {
    /// The sizes.
    pub shape: Shape,
    /// Every chunk back to back ([`Shape::sealed_len`] bytes).
    pub blob: Vec<u8>,
    /// The tree over the chunks: its root goes into the offer, its paths
    /// travel with the chunks.
    pub tree: ChunkTree,
}

impl Sealed {
    /// Chunk `index` as it travels.
    pub fn chunk(&self, index: u32) -> Option<&[u8]> {
        let start = usize::try_from(self.shape.chunk_offset(index)?).ok()?;
        let len = self.shape.chunk_len(index)?;
        self.blob.get(start..start + len)
    }

    /// The audit path of chunk `index`.
    pub fn path(&self, index: u32) -> Option<Vec<[u8; 32]>> {
        self.tree.chunk_path(usize::try_from(index).ok()?)
    }

    /// The root of the tree.
    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }
}

/// Pads and seals a whole attachment in memory, and builds its tree.
pub fn seal(key: &Key, bytes: &[u8]) -> Result<Sealed, BlobError> {
    seal_as(key, Shape::of(bytes.len() as u64)?, bytes)
}

/// Pads and seals a profile picture as its one chunk ([`Shape::one_chunk`]).
pub fn seal_one_chunk(key: &Key, bytes: &[u8]) -> Result<Sealed, BlobError> {
    seal_as(key, Shape::one_chunk(bytes.len() as u64)?, bytes)
}

fn seal_as(key: &Key, shape: Shape, bytes: &[u8]) -> Result<Sealed, BlobError> {
    debug_assert_eq!(shape.len, bytes.len() as u64);
    let sealed_len = usize::try_from(shape.sealed_len()).map_err(|_| BlobError::TooBig)?;
    let mut blob = Vec::with_capacity(sealed_len);
    let mut leaves = Vec::with_capacity(shape.chunks as usize);
    let mut segment = Zeroizing::new(vec![0u8; SEGMENT_LEN]);
    for index in 0..shape.chunks {
        let want = shape.segment_len(index).expect("an index below the count");
        // The bytes of this segment, then zeros; a last segment can be padding alone.
        let start = (index as usize * SEGMENT_LEN).min(bytes.len());
        let have = (bytes.len() - start).min(want);
        segment[..have].copy_from_slice(&bytes[start..start + have]);
        segment[have..want].fill(0);
        let chunk = seal_chunk(key, &shape, index, &segment[..want])?;
        leaves.push(leaf(&chunk));
        blob.extend_from_slice(&chunk);
    }
    debug_assert_eq!(blob.len(), sealed_len);
    Ok(Sealed {
        shape,
        blob,
        tree: ChunkTree::of_leaf_hashes(leaves),
    })
}

/// Opens a whole sealed blob in memory: the attachment's true bytes.
/// Refused unless every chunk opens at its place and the padding is zeros.
pub fn open(key: &Key, shape: &Shape, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, BlobError> {
    if blob.len() as u64 != shape.sealed_len() {
        return Err(BlobError::Length);
    }
    let len = usize::try_from(shape.len).map_err(|_| BlobError::TooBig)?;
    let padded = usize::try_from(shape.padded).map_err(|_| BlobError::TooBig)?;
    let mut out = Zeroizing::new(Vec::with_capacity(padded));
    let mut at = 0usize;
    for index in 0..shape.chunks {
        let n = shape.chunk_len(index).expect("an index below the count");
        let segment = open_chunk(key, shape, index, &blob[at..at + n])?;
        out.extend_from_slice(&segment);
        at += n;
    }
    if out[len..].iter().any(|b| *b != 0) {
        return Err(BlobError::Padding);
    }
    out.truncate(len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Key {
        Key::from_bytes([byte; KEY_LEN])
    }

    fn bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn padme_rounds_as_the_design_says() {
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(2), 2);
        assert_eq!(padme(3), 3);
        assert_eq!(padme(9), 10);
        assert_eq!(padme(409_600), 409_600);
        assert_eq!(padme(1_048_576), 1_048_576);
        assert_eq!(padme(1_048_577), 1_081_344);
        assert_eq!(padme(MAX_LEN), MAX_PADDED_LEN);
    }

    #[test]
    fn padme_never_shrinks_never_adds_more_than_an_eighth_and_is_stable() {
        let mut len = 1u64;
        while len <= MAX_LEN {
            for l in [len, len + 1, len + len / 3, len.saturating_mul(2) - 1] {
                let p = padme(l);
                assert!(p >= l, "{l}");
                assert!(p - l <= l / 8 + 1, "{l} -> {p}");
                assert_eq!(padme(p), p, "{l} -> {p}");
            }
            len = len * 3 / 2 + 1;
        }
    }

    #[test]
    fn the_shape_of_the_largest_attachment() {
        let s = Shape::of(MAX_LEN).unwrap();
        assert_eq!(s.padded(), MAX_PADDED_LEN);
        assert_eq!(s.chunks(), MAX_CHUNKS);
        assert_eq!(s.sealed_len(), 65_028_656);
        assert_eq!(Shape::of(MAX_LEN + 1), Err(BlobError::TooBig));
        assert_eq!(Shape::of(0), Err(BlobError::Empty));
        // One MiB: the 18 chunks of the design's phase 1.
        let mib = Shape::of(1_048_576).unwrap();
        assert_eq!(mib.chunks(), 18);
        assert_eq!(mib.chunk_len(0), Some(CHUNK_LEN));
        assert_eq!(mib.segment_len(17), Some(1_048_576 - 17 * SEGMENT_LEN));
        assert_eq!(mib.segment_len(18), None);
        assert_eq!(mib.chunk_offset(17), Some(17 * CHUNK_LEN as u64));
        assert_eq!(mib.chunk_offset(18), None);
    }

    #[test]
    fn an_offers_shape_must_follow_from_its_length() {
        let s = Shape::of(300_000).unwrap();
        assert_eq!(Shape::from_offer(300_000, s.padded(), s.chunks()), Ok(s));
        assert_eq!(
            Shape::from_offer(300_000, s.padded() + 1, s.chunks()),
            Err(BlobError::Shape)
        );
        assert_eq!(
            Shape::from_offer(300_000, s.padded(), s.chunks() + 1),
            Err(BlobError::Shape)
        );
        assert_eq!(
            Shape::from_offer(300_000, s.padded(), 0),
            Err(BlobError::Shape)
        );
        assert_eq!(Shape::from_offer(0, 0, 0), Err(BlobError::Empty));
    }

    #[test]
    fn a_blob_opens_to_its_bytes_at_every_edge() {
        // SEGMENT_LEN - 1 pads to 61,440: a second chunk that holds padding alone.
        assert_eq!(Shape::of(SEGMENT_LEN as u64 - 1).unwrap().chunks(), 2);
        for len in [
            1usize,
            2,
            100,
            SEGMENT_LEN - 1,
            SEGMENT_LEN,
            SEGMENT_LEN + 1,
            300_000,
            1_048_576,
        ] {
            let data = bytes(len);
            let k = key(7);
            let sealed = seal(&k, &data).unwrap();
            assert_eq!(sealed.blob.len() as u64, sealed.shape.sealed_len(), "{len}");
            assert_eq!(sealed.tree.len(), sealed.shape.chunks() as usize, "{len}");
            let back = open(&k, &sealed.shape, &sealed.blob).unwrap();
            assert_eq!(&back[..], &data[..], "{len}");
        }
    }

    #[test]
    fn every_chunk_proves_its_place_under_the_root() {
        let data = bytes(300_000);
        let sealed = seal(&key(1), &data).unwrap();
        let root = sealed.root();
        for index in 0..sealed.shape.chunks() {
            let chunk = sealed.chunk(index).unwrap();
            let path = sealed.path(index).unwrap();
            assert!(
                check_chunk(&root, &sealed.shape, index, chunk, &path),
                "{index}"
            );
            // Not at another place, not with another path, not when changed.
            let other = (index + 1) % sealed.shape.chunks();
            assert!(!check_chunk(&root, &sealed.shape, other, chunk, &path) || other == index);
            let mut bad = chunk.to_vec();
            bad[0] ^= 1;
            assert!(!check_chunk(&root, &sealed.shape, index, &bad, &path));
            let mut short = path.clone();
            short.pop();
            assert!(!check_chunk(&root, &sealed.shape, index, chunk, &short) || path.is_empty());
        }
        assert!(sealed.chunk(sealed.shape.chunks()).is_none());
        assert!(sealed.path(sealed.shape.chunks()).is_none());
    }

    #[test]
    fn a_chunk_opens_only_at_its_own_place_under_its_own_key_and_shape() {
        let data = bytes(SEGMENT_LEN * 3);
        let k = key(3);
        let sealed = seal(&k, &data).unwrap();
        let shape = sealed.shape;
        let c0 = sealed.chunk(0).unwrap();
        let c1 = sealed.chunk(1).unwrap();
        assert!(open_chunk(&k, &shape, 0, c0).is_ok());
        // Moved to another index.
        assert_eq!(open_chunk(&k, &shape, 1, c0).err(), Some(BlobError::Seal));
        // Another key.
        assert_eq!(
            open_chunk(&key(4), &shape, 0, c0).err(),
            Some(BlobError::Seal)
        );
        // A shape that says the attachment is shorter (cut short) or longer.
        let shorter = Shape::of((SEGMENT_LEN * 2) as u64).unwrap();
        assert_eq!(open_chunk(&k, &shorter, 0, c0).err(), Some(BlobError::Seal));
        let longer = Shape::of((SEGMENT_LEN * 4) as u64).unwrap();
        assert_eq!(open_chunk(&k, &longer, 1, c1).err(), Some(BlobError::Seal));
        // A wrong length is refused before the cipher runs.
        assert_eq!(
            open_chunk(&k, &shape, 0, &c0[..c0.len() - 1]).err(),
            Some(BlobError::Length)
        );
        assert_eq!(
            open_chunk(&k, &shape, shape.chunks(), c0).err(),
            Some(BlobError::Index)
        );
        assert_eq!(
            seal_chunk(&k, &shape, 0, &[0u8; 10]).err(),
            Some(BlobError::Length)
        );
    }

    #[test]
    fn a_blob_that_is_cut_or_whose_padding_is_not_zeros_is_refused() {
        let data = bytes(100_000);
        let k = key(9);
        let sealed = seal(&k, &data).unwrap();
        assert_eq!(
            open(&k, &sealed.shape, &sealed.blob[..sealed.blob.len() - 1]).err(),
            Some(BlobError::Length)
        );
        // A sender that pads with something else: sealed by hand.
        let shape = Shape::of(10).unwrap();
        let mut segment = vec![7u8; shape.segment_len(0).unwrap()];
        segment[..10].copy_from_slice(&data[..10]);
        let pads = shape.padded() > shape.len();
        let chunk = seal_chunk(&k, &shape, 0, &segment).unwrap();
        if pads {
            assert_eq!(open(&k, &shape, &chunk).err(), Some(BlobError::Padding));
        } else {
            assert!(open(&k, &shape, &chunk).is_ok());
        }
        let shape = Shape::of(1_000).unwrap();
        assert!(shape.padded() > shape.len(), "a size class above 1,000");
        let mut segment = vec![0u8; shape.segment_len(0).unwrap()];
        segment[..1_000].copy_from_slice(&data[..1_000]);
        *segment.last_mut().unwrap() = 1;
        let chunk = seal_chunk(&k, &shape, 0, &segment).unwrap();
        assert_eq!(open(&k, &shape, &chunk).err(), Some(BlobError::Padding));
    }

    #[test]
    fn names_come_from_the_key_and_are_unrelated() {
        let a = key(1);
        let b = key(2);
        assert_ne!(a.handle(), b.handle());
        assert_eq!(a.handle(), key(1).handle());
        assert_ne!(a.custody_id(0), a.custody_id(1));
        assert_ne!(a.custody_id(0)[..], a.handle()[..]);
        assert_eq!(a.custody_id(258), key(1).custody_id(258));
        assert_ne!(a.custody_id(1), a.custody_id(256));
        // Two seals of the same bytes under two keys share nothing.
        let data = bytes(1_000);
        let one = seal(&a, &data).unwrap();
        let two = seal(&b, &data).unwrap();
        assert_ne!(one.blob, two.blob);
        assert_ne!(one.root(), two.root());
        assert_eq!(format!("{a:?}"), "Key(..)");
    }

    #[test]
    fn a_profile_picture_is_always_one_whole_chunk() {
        let k = key(5);
        for len in [1usize, 16_000, 60_000] {
            let data = bytes(len);
            let sealed = seal_one_chunk(&k, &data).unwrap();
            assert_eq!(sealed.shape, Shape::one_chunk(len as u64).unwrap());
            assert_eq!(sealed.shape.chunks(), 1);
            assert_eq!(sealed.blob.len(), CHUNK_LEN, "{len}");
            assert!(check_chunk(
                &sealed.root(),
                &sealed.shape,
                0,
                &sealed.blob,
                &[]
            ));
            assert_eq!(
                &open(&k, &sealed.shape, &sealed.blob).unwrap()[..],
                &data[..]
            );
        }
        assert_eq!(
            seal_one_chunk(&k, &bytes(60_001)).err(),
            Some(BlobError::TooBig)
        );
        assert_eq!(seal_one_chunk(&k, &[]).err(), Some(BlobError::Empty));
        // Not the shape Padmé gives the same length: the two do not open as each other.
        let data = bytes(1_000);
        let one = seal_one_chunk(&k, &data).unwrap();
        let padme_shape = Shape::of(1_000).unwrap();
        assert_ne!(one.shape, padme_shape);
        assert_eq!(
            open(&k, &padme_shape, &one.blob).err(),
            Some(BlobError::Length)
        );
    }

    #[test]
    fn two_random_keys_differ() {
        assert_ne!(Key::random().bytes(), Key::random().bytes());
    }
}
