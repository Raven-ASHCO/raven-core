//! Attachments (photos, voice notes, files): `RVNATT/1`
//! (`docs/design/2026-11-attachments.md`).
//!
//! An attachment is one sealed message, the offer, and a blob of sealed
//! chunks that never travel as messages. This module holds what both ends
//! share and what needs no store and no link: the blob ([`blob`]) and, next,
//! the offer. The gates, the store and the link frames live elsewhere and
//! are off in release builds until the owner flips them.

pub mod blob;
pub mod offer;
