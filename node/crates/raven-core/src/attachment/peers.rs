//! Which friends' nodes take attachments
//! (`docs/design/2026-11-attachments.md` §10.1): the record of link caps
//! bit 12 ([`crate::CAP_LINK_ATT1`]).
//!
//! A node announces the bit in its signed hello and, on LAN, in its dial's
//! message 3. raven-node notes what an authenticated link with a verified
//! friend showed: the bit writes the friend's record, caps without the bit
//! clear it (the friend went back to an older build), and a link that
//! showed no caps at all (a LAN listener sends none) changes nothing. A
//! sender offers attachments, and sends `RAX1` frames, only to a friend
//! with a record.
//!
//! One small sealed file, `attachment_peers.json`: the friend's key and
//! when the bit was last seen. Written only when something changes, or
//! once a day.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::store::{StoreError, ATTACHMENTS_LOCK};
use crate::at_rest::{self, Kind};

/// The file of the record.
pub const PEERS_FILE: &str = "attachment_peers.json";
/// Friends kept at most; the one seen longest ago goes first.
pub const MAX_PEERS: usize = 1_024;
/// A record is written again when the bit is seen this much later.
const REFRESH_MS: u64 = 86_400_000;

const _: () = assert!(!ATTACHMENTS_LOCK.is_empty());

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Book {
    v: u8,
    /// The friend's key in hex, and when the bit was last seen (ms).
    #[serde(default)]
    peers: BTreeMap<String, u64>,
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(PEERS_FILE)
}

fn load(data_dir: &Path) -> Book {
    at_rest::load_json::<Book>(data_dir, &path(data_dir), Kind::Attachments)
        .ok()
        .flatten()
        .filter(|book| book.v == 1)
        .unwrap_or_default()
}

/// Does `peer`'s node take attachments, as far as this node saw?
pub fn speaks(data_dir: &Path, peer: &[u8; 32]) -> bool {
    load(data_dir).peers.contains_key(&hex::encode(peer))
}

/// An authenticated link with the verified friend `peer` showed link caps
/// with the bit (`speaks`) or without it. `Ok(true)`: the record changed.
pub fn note(
    data_dir: &Path,
    peer: &[u8; 32],
    speaks: bool,
    now_ms: u64,
) -> Result<bool, StoreError> {
    let key = hex::encode(peer);
    // Most links change nothing: looked at without the writer's lock.
    let seen = load(data_dir).peers.get(&key).copied();
    let stale = |at: u64| now_ms.saturating_sub(at) >= REFRESH_MS;
    match (speaks, seen) {
        (false, None) => return Ok(false),
        (true, Some(at)) if !stale(at) => return Ok(false),
        _ => {}
    }
    let io = |e: at_rest::AtRestError| StoreError::Io(e.to_string());
    let lock = at_rest::lock_file(data_dir, &path(data_dir), Kind::Attachments).map_err(io)?;
    let mut book = lock
        .load_json::<Book>()
        .map_err(io)?
        .filter(|book| book.v == 1)
        .unwrap_or_default();
    book.v = 1;
    let changed = if speaks {
        book.peers.insert(key, now_ms).is_none()
    } else {
        book.peers.remove(&key).is_some()
    };
    while book.peers.len() > MAX_PEERS {
        let Some(oldest) = book
            .peers
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        book.peers.remove(&oldest);
    }
    lock.store_json(&book).map_err(io)?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [1u8; 32];
    const B: [u8; 32] = [2u8; 32];

    #[test]
    fn the_bit_writes_a_record_and_caps_without_it_clear_it() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert!(!speaks(d, &A));
        // Caps without the bit for a friend with no record: nothing written.
        assert!(!note(d, &A, false, 10).unwrap());
        assert!(!path(d).exists());
        assert!(note(d, &A, true, 20).unwrap());
        assert!(speaks(d, &A) && !speaks(d, &B));
        // Seen again soon: nothing written.
        let before = std::fs::read(path(d)).unwrap();
        assert!(!note(d, &A, true, 30).unwrap());
        assert_eq!(std::fs::read(path(d)).unwrap(), before);
        // Seen a day later: the stamp moves, the record does not change.
        assert!(!note(d, &A, true, 20 + REFRESH_MS).unwrap());
        assert_ne!(std::fs::read(path(d)).unwrap(), before);
        assert!(note(d, &B, true, 40).unwrap());
        // The friend went back to an older build.
        assert!(note(d, &A, false, 50).unwrap());
        assert!(!speaks(d, &A) && speaks(d, &B));
    }

    #[test]
    fn the_record_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let mut book = Book {
            v: 1,
            peers: BTreeMap::new(),
        };
        for i in 0..MAX_PEERS as u64 {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&i.to_be_bytes());
            book.peers.insert(hex::encode(key), 1_000 + i);
        }
        at_rest::lock_file(d, &path(d), Kind::Attachments)
            .unwrap()
            .store_json(&book)
            .unwrap();
        assert!(note(d, &[0xEE; 32], true, 9_999).unwrap());
        let book = load(d);
        assert_eq!(book.peers.len(), MAX_PEERS);
        assert!(speaks(d, &[0xEE; 32]));
        // The one seen longest ago went.
        assert!(!speaks(d, &[0u8; 32]));
    }
}
