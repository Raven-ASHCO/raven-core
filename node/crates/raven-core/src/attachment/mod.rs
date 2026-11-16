//! Attachments (photos, voice notes, files): `RVNATT/1`
//! (`docs/design/2026-11-attachments.md`).
//!
//! An attachment is one sealed message, the offer, and a blob of sealed
//! chunks that never travel as messages. This module holds what both ends
//! share: the blob ([`blob`]), the offer ([`offer`]), what a build shows for
//! an offer it cannot open ([`shown`]), the store ([`store`]), making and
//! keeping offers ([`flow`]), the link frames that carry the chunks
//! ([`link`]), the exchange of them ([`exchange`]) and which friends take
//! them ([`peers`]). A profile picture is an attachment of a kind of its
//! own: the check of its JPEG ([`jpeg`]) and what is kept around it
//! ([`picture`]). Everything past phase 1a is
//! behind [`crate::attachment_gate`], off in release builds until the owner
//! flips it.

pub mod blob;
pub mod exchange;
pub mod flow;
pub mod jpeg;
pub mod link;
pub mod offer;
pub mod peers;
pub mod picture;
pub mod shown;
pub mod store;
pub mod sweep;

/// Offers for the tests of the code that takes, keeps and shows them.
#[cfg(test)]
pub(crate) mod testing {
    use super::blob::{Key, Shape, KEY_LEN};
    use super::offer::{BlobRef, Offer};

    /// A photo's offer, as it travels.
    pub(crate) fn photo_offer() -> String {
        let blob = BlobRef {
            shape: Shape::of(200_000).unwrap(),
            key: Key::from_bytes([1u8; KEY_LEN]),
            root: [2u8; 32],
        };
        Offer::photo(blob, "", 800, 600, &[1, 2, 3])
            .unwrap()
            .encode()
            .unwrap()
    }

    /// A profile picture's offer with this `seq`, as it travels.
    pub(crate) fn profile_offer(seq: u64) -> String {
        let blob = BlobRef {
            shape: Shape::one_chunk(20_000).unwrap(),
            key: Key::from_bytes([3u8; KEY_LEN]),
            root: [4u8; 32],
        };
        Offer::profile(blob, seq, 0, 384, &[9])
            .unwrap()
            .encode()
            .unwrap()
    }
}
