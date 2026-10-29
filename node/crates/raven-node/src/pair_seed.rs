//! Pair seeds on this node (Phase 6b step P6.38, design B §5 and W-B4,
//! [`raven_core::pair_seed`], `protocol/RAVEN_ROUTE_HINTS_V1.md` §14).
//!
//! - **Live** only while the pair-seed gate is ([`live`]:
//!   `PAIR_SEED_PRODUCTION_ENABLED`, or a debug build's
//!   `RAVEN_LAB_PAIR_SEED=1` with `RAVEN_LAB_TEST_A=1`, and route hints
//!   live). With it shut no RRH1 carries a seed, none received is kept, and
//!   every beacon, knock and Bluetooth key comes from the pair's root, byte
//!   for byte as before. Callers read it on their own thread and hand it to
//!   blocking work.
//! - **Exchange** (`crate::hints`): every RRH1 to a verified contact carries
//!   this node's PAIR_SEED entry ([`outgoing`]; a leader's proposal is
//!   stored before the frame goes), and a verified contact's RRH1 feeds its
//!   entry, or that it had none, to the state machine ([`incoming`]).
//! - **Keys** ([`key_sets`]): each contact's key sets in the order a
//!   receiver tries them (the current seed's, the leader's proposal's or the
//!   previous seed's, the root's last), each with what it is for
//!   ([`KeyUse`]): the LAN beacon (`crate::lan_beacon`), the RLK1 knock
//!   (`crate::link_knock`) and Bluetooth nearby (`crate::nearby`) send with
//!   one and accept them all. A match with the root while this node expects
//!   the contact's seed is `SEC_PAIR_SEED_ROOT`, a Notice ([`root_matched`]).
//! - **Cached books** are made again when [`PAIR_SEEDS_FILE`] changes and at
//!   least once an hour ([`stamp`]), so a retired seed leaves memory within
//!   the hour after it left the file.

use std::path::Path;

use raven_core::identity::Identity;
use raven_core::lan_beacon::BeaconError;
use raven_core::pair_seed::{self, SeedBook, SeedEntry, PAIR_SEEDS_FILE};
use raven_core::security_events::Via;

use crate::p2p::{file_stamp, FileStamp};

#[cfg(test)]
thread_local! {
    static LIVE_FOR_TEST: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Pair seeds are live in this process ([`pair_seed::live`]). A test sets
/// it for its own thread ([`SeedsForTest`]).
pub(crate) fn live() -> bool {
    #[cfg(test)]
    if let Some(live) = LIVE_FOR_TEST.with(std::cell::Cell::get) {
        return live;
    }
    pair_seed::live()
}

/// [`live`] for the current thread until dropped.
#[cfg(test)]
pub(crate) struct SeedsForTest;

#[cfg(test)]
impl SeedsForTest {
    pub(crate) fn set(live: bool) -> Self {
        LIVE_FOR_TEST.with(|c| c.set(Some(live)));
        Self
    }
}

#[cfg(test)]
impl Drop for SeedsForTest {
    fn drop(&mut self) {
        LIVE_FOR_TEST.with(|c| c.set(None));
    }
}

/// Blocking: every contact's seeds in `data_dir` (`live`: [`live`], read by
/// the caller), empty while the gate is shut.
pub(crate) fn book(data_dir: &Path, live: bool) -> SeedBook {
    SeedBook::load(data_dir, live, raven_core::clock::now_ms())
}

/// What one of a contact's key sets is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyUse {
    /// This node sends with it (beacon queries, knocks, advertised tokens).
    pub(crate) send: bool,
    /// A match with it is `SEC_PAIR_SEED_ROOT`: it is the root, and this
    /// node expects the contact to use their seed.
    pub(crate) notice: bool,
}

impl KeyUse {
    /// A key set this node sends with (the root's, for a pair without
    /// seeds): never the Notice.
    pub(crate) const SEND: KeyUse = KeyUse {
        send: true,
        notice: false,
    };
}

/// `identity`'s key sets with `peer` from `seeds`, made by `make(me, peer,
/// r)` from each key R (a seed's `K_pair` or the root), in the order a
/// receiver tries them, with what each is for (the checks and errors of
/// [`raven_core::lan_beacon::pair_root`]).
pub(crate) fn key_sets<T>(
    identity: &Identity,
    peer: &[u8; 32],
    seeds: &SeedBook,
    make: impl Fn(&[u8; 32], &[u8; 32], &[u8; 32]) -> T,
) -> Result<Vec<(T, KeyUse)>, BeaconError> {
    let roots = seeds.roots(identity, peer)?;
    let me = identity.public_key_bytes();
    Ok(roots
        .accept
        .iter()
        .enumerate()
        .map(|(i, r)| {
            (
                make(&me, peer, r),
                KeyUse {
                    send: i == roots.send,
                    notice: roots.notice_at(i),
                },
            )
        })
        .collect())
}

/// `peer` matched one of this node's key sets used as `key` (reached
/// `via`): `SEC_PAIR_SEED_ROOT` when that is the Notice.
pub(crate) fn root_matched(peer: &[u8; 32], key: KeyUse, via: Via) {
    if key.notice {
        crate::security::pair_seed_root(peer, via);
    }
}

/// What tells that the cached key sets must be made again: the seed file,
/// and the hour (a retired seed leaves the books within the hour).
pub(crate) fn stamp(data_dir: &Path) -> (Option<FileStamp>, u64) {
    (
        file_stamp(&data_dir.join(PAIR_SEEDS_FILE)),
        raven_core::clock::now_ms() / (60 * 60 * 1000),
    )
}

/// Blocking: the PAIR_SEED entry for this node's (`me`) RRH1 to the
/// verified contact `peer` (`None`: nothing to offer, or the gate is shut:
/// `live`). A leader's proposal is stored before it returns.
pub(crate) fn outgoing(
    data_dir: &Path,
    live: bool,
    me: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
) -> Option<SeedEntry> {
    if !live {
        return None;
    }
    pair_seed::outgoing(data_dir, me, peer, now_ms, || {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        seed
    })
}

/// Blocking: what [`outgoing`] would offer `peer` now, without storing
/// anything, and whether a leader would make its proposal first (route
/// hints ask a contact for its RRH1 when this changed since it was told,
/// `crate::hints::lan_asks`). `(None, false)` while the gate is shut; a
/// file that cannot be read reads as no seed.
pub(crate) fn peek(
    data_dir: &Path,
    live: bool,
    me: &[u8; 32],
    peer: &[u8; 32],
    now_ms: u64,
) -> (Option<SeedEntry>, bool) {
    if !live {
        return (None, false);
    }
    let leader = pair_seed::is_leader(me, peer);
    let mut state = pair_seed::state(data_dir, peer).unwrap_or_default();
    state.prune(now_ms);
    let propose = state.clone().propose(leader, now_ms, || [1; 32]);
    (state.entry(leader), propose)
}

/// Blocking: the verified contact `peer`'s RRH1 carried `entry` (`None`:
/// none; it has no seed now). Nothing while the gate is shut (`live`). A
/// file that cannot be read or written is left as it is, with a
/// counts-only log line.
pub(crate) fn incoming(
    data_dir: &Path,
    live: bool,
    me: &[u8; 32],
    peer: &[u8; 32],
    entry: Option<&SeedEntry>,
    now_ms: u64,
) {
    if !live {
        return;
    }
    if pair_seed::incoming(data_dir, me, peer, entry, now_ms).is_err() {
        crate::netutil::log_limited(&SEED_LOG, "raven-node hints", "could not keep a pair seed");
    }
}

static SEED_LOG: crate::netutil::LogLimiter =
    crate::netutil::LogLimiter::new(std::time::Duration::from_secs(30));

#[cfg(test)]
mod tests {
    use super::*;

    /// Shut, the book is empty and every contact has the root alone, sent
    /// with and never a Notice; nothing is offered or kept.
    #[test]
    fn shut_means_the_root_and_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let me = Identity::from_seed(&[0x61; 32]);
        let peer = Identity::from_seed(&[0x62; 32]).public_key_bytes();
        let sets = key_sets(&me, &peer, &book(dir.path(), false), |_, _, r| *r).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].1, KeyUse::SEND);
        let mine = me.public_key_bytes();
        assert!(outgoing(dir.path(), false, &mine, &peer, 1).is_none());
        incoming(dir.path(), false, &mine, &peer, None, 1);
        assert!(!dir.path().join(PAIR_SEEDS_FILE).exists());
    }

    /// `RAVEN_LAB_PAIR_SEED` (with `RAVEN_LAB_TEST_A` and route hints) is
    /// inert in a release build (the release test job sets every switch and
    /// runs this; a debug build returns early).
    #[test]
    fn pair_seed_lab_switch_is_inert_in_release() {
        if cfg!(debug_assertions) {
            return;
        }
        const { assert!(!raven_core::security_gate::PAIR_SEED_PRODUCTION_ENABLED) };
        assert!(!live());
        raven_core::security_gate::set_lab_for_this_thread(
            raven_core::security_gate::SecGate::PairSeed,
            Some(true),
        );
        assert!(!live());
        raven_core::security_gate::set_lab_for_this_thread(
            raven_core::security_gate::SecGate::PairSeed,
            None,
        );
    }
}
