//! Raven's changes to this crate (RAVEN_DELTA.md): the descriptor publisher
//! keeps one reupload timer per time period, and an upload round uploads to
//! every time period that needs the descriptor.
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

/// The time periods an upload round uploads to: every one with an HsDir that
/// needs the descriptor.
///
/// `dirty` is, for each time period in the publisher's order (the current one
/// first), how many of its HsDirs need the descriptor. Returns the places of
/// the time periods to upload to.
///
/// Upstream ends the round at the first time period that needs nothing
/// (`Reactor::upload_all` returns there), so a later time period waits until
/// the first one needs an upload as well. Upstream's many timers hid that:
/// one of the first time period's fired every few minutes. With one timer per
/// time period the wait is up to two hours more, and the HsDirs of the second
/// time period would hold a descriptor for up to four hours: longer than its
/// lifetime of three, so they drop it. The second time period is the one that
/// a client on the other side of the daily change looks in.
pub fn periods_to_upload(dirty: &[usize]) -> Vec<usize> {
    dirty
        .iter()
        .enumerate()
        .filter(|(_, needing)| **needing > 0)
        .map(|(place, _)| place)
        .collect()
}
