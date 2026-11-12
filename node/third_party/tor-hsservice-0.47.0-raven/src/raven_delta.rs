//! Raven's change to this crate (RAVEN_DELTA.md): the descriptor publisher
//! keeps one reupload timer per time period.
//!
//! Upstream adds a timer on every upload result
//! (`Reactor::handle_upload_results`) and takes one away only when it fires.
//! A timer that fires marks the descriptor dirty for every HsDir of its time
//! period: a whole reupload, whose result adds a timer again. So every upload
//! that no timer asked for (a new consensus that moves an HsDir, a changed
//! introduction point, an HsDir tried again) leaves one more timer behind for
//! as long as its time period lasts, and each of them causes a whole reupload
//! every 60 to 120 minutes.

use std::collections::BinaryHeap;

/// Add `timer` to `waiting`, unless a timer `same` as it is already there
/// (in the publisher: one for the same time period).
///
/// Returns whether it was added.
///
/// The timer already there is the earlier one, and it is the one to keep.
/// When it fires, every HsDir of the time period gets the descriptor again,
/// also one that got it in between, so no HsDir waits longer for its reupload
/// than upstream's 120 minutes. A later timer in its place could be put off
/// again and again by uploads to single HsDirs.
pub fn push_unless_waiting<T: Ord>(
    waiting: &mut BinaryHeap<T>,
    timer: T,
    same: impl Fn(&T, &T) -> bool,
) -> bool {
    if waiting.iter().any(|other| same(other, &timer)) {
        return false;
    }
    waiting.push(timer);
    true
}
