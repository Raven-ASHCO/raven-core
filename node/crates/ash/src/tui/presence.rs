//! A friend's mark in the list, and what it means in words (HELP's legend
//! and the open conversation's header).
//!
//! Raven has no online indicator, and nothing here asks the network: every
//! mark comes from the friend's saved addresses and the chat history.
//!
//! - No address: no saved address of any kind, so Raven doesn't know where
//!   to reach them.
//! - Waiting: some of your messages to them are still queued.
//! - In touch: since Raven was opened, a message from them arrived or one of
//!   yours was delivered, in the last 15 minutes. Rows that were already
//!   there at the first history load never count: they say nothing about
//!   now.
//! - Otherwise nothing recent, with the age of the newest message.
//!
//! The first that holds wins, in that order.

use std::time::{Duration, Instant};

use super::app::Row;
#[cfg(test)]
use super::app::Touch;
use super::bridge::{self, ContactView};
#[cfg(test)]
use super::controller::RowView;
#[cfg(test)]
use super::testkit;

/// How long a friend stays in touch after a message arrived or was
/// delivered.
pub(super) const RECENT_FOR: Duration = Duration::from_secs(15 * 60);

/// A friend's state for their mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Presence {
    /// No saved address (LAN, Internet or p2p).
    NoAddress,
    /// This many of your messages haven't reached them yet.
    Waiting(usize),
    /// In touch: the newest arrival or delivery this app saw, at `at_ms` on
    /// the wall clock.
    Recent { at_ms: u64 },
    /// Nothing recent. `last_ms`: the newest message's time (the sender's
    /// clock, never later than now; 0 when unknown), None with no messages.
    Quiet { last_ms: Option<u64> },
}

impl Presence {
    /// The mark in words, for the conversation's header: 'In touch 5 min
    /// ago', '2 messages waiting', 'Last message 3 d ago', 'No messages yet',
    /// 'No address to reach them'.
    pub(super) fn meaning(self, now_ms: u64) -> String {
        match self {
            Presence::NoAddress => "No address to reach them".to_owned(),
            Presence::Waiting(1) => "1 message waiting".to_owned(),
            Presence::Waiting(n) => format!("{n} messages waiting"),
            Presence::Recent { at_ms } => with_age("In touch", now_ms, at_ms),
            Presence::Quiet { last_ms: None } => "No messages yet".to_owned(),
            Presence::Quiet { last_ms: Some(0) } => "No recent contact".to_owned(),
            Presence::Quiet {
                last_ms: Some(last_ms),
            } => with_age("Last message", now_ms, last_ms),
        }
    }
}

/// `words` and how long ago `then_ms` was, as `ash messages` words it.
fn with_age(words: &str, now_ms: u64, then_ms: u64) -> String {
    match bridge::short_age(now_ms, then_ms) {
        age if age.is_empty() => words.to_owned(),
        age => format!("{words} {age}"),
    }
}

/// Whether Raven has any saved address for `friend` (LAN, Internet or p2p).
pub(super) fn has_address(friend: &ContactView) -> bool {
    [&friend.lan_dial, &friend.internet_dial, &friend.p2p]
        .iter()
        .any(|route| !route.trim().is_empty())
}

/// Where `friend` stands, from their saved addresses and `rows` (their
/// conversation, oldest first), at `now` (`now_ms` on the wall clock).
pub(super) fn presence(friend: &ContactView, rows: &[Row], now: Instant, now_ms: u64) -> Presence {
    if !has_address(friend) {
        return Presence::NoAddress;
    }
    let waiting = rows
        .iter()
        .filter(|row| row.view.outgoing && row.view.delivery == "queued")
        .count();
    if waiting > 0 {
        return Presence::Waiting(waiting);
    }
    let touched = rows
        .iter()
        .filter_map(|row| row.touched)
        .filter(|touch| now.saturating_duration_since(touch.at) < RECENT_FOR)
        .map(|touch| touch.at_ms)
        .max();
    if let Some(at_ms) = touched {
        return Presence::Recent { at_ms };
    }
    Presence::Quiet {
        // A sender's clock ahead of this one says nothing about now.
        last_ms: rows.last().map(|row| row.view.created_at_ms.min(now_ms)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW_MS: u64 = 1_760_000_000_000;
    const MINUTE: u64 = 60_000;

    fn with_address() -> ContactView {
        ContactView {
            lan_dial: "192.168.1.30:7420".into(),
            ..testkit::friend(1)
        }
    }

    fn row(outgoing: bool, delivery: &str, created_at_ms: u64) -> Row {
        Row {
            view: RowView {
                id: format!("{created_at_ms:032x}"),
                outgoing,
                created_at_ms,
                delivery: delivery.into(),
                body: "hi".into(),
                id_conflict: false,
            },
            seen_at_start: true,
            touched: None,
        }
    }

    /// `row` as one that appeared after the first load, at `at`.
    fn later(mut row: Row, at: Instant, at_ms: u64) -> Row {
        row.seen_at_start = false;
        row.touched = Some(Touch { at, at_ms });
        row
    }

    #[test]
    fn rows_from_the_first_load_never_make_a_friend_recent() {
        let now = Instant::now();
        let rows = [
            row(false, "", NOW_MS - MINUTE),
            row(true, "delivered", NOW_MS - 30_000),
        ];
        let p = presence(&with_address(), &rows, now, NOW_MS);
        assert_eq!(
            p,
            Presence::Quiet {
                last_ms: Some(NOW_MS - 30_000)
            }
        );
        assert_eq!(p.meaning(NOW_MS), "Last message just now");
    }

    #[test]
    fn rows_that_appear_later_do_for_15_minutes() {
        let t0 = Instant::now();
        let rows = [
            row(false, "", NOW_MS - 60 * MINUTE),
            later(row(false, "", NOW_MS), t0, NOW_MS),
        ];
        let at = |minutes: u64| {
            presence(
                &with_address(),
                &rows,
                t0 + Duration::from_secs(minutes * 60),
                NOW_MS + minutes * MINUTE,
            )
        };
        assert_eq!(at(0), Presence::Recent { at_ms: NOW_MS });
        assert_eq!(at(0).meaning(NOW_MS), "In touch just now");
        assert_eq!(at(5).meaning(NOW_MS + 5 * MINUTE), "In touch 5 min ago");
        assert_eq!(at(14), Presence::Recent { at_ms: NOW_MS });
        assert_eq!(
            at(15),
            Presence::Quiet {
                last_ms: Some(NOW_MS)
            }
        );
        assert_eq!(
            at(15).meaning(NOW_MS + 15 * MINUTE),
            "Last message 15 min ago"
        );
        // The newest touch counts.
        let both = [
            later(row(true, "delivered", NOW_MS), t0, NOW_MS),
            later(
                row(false, "", NOW_MS),
                t0 + Duration::from_secs(60),
                NOW_MS + MINUTE,
            ),
        ];
        assert_eq!(
            presence(
                &with_address(),
                &both,
                t0 + Duration::from_secs(120),
                NOW_MS
            ),
            Presence::Recent {
                at_ms: NOW_MS + MINUTE
            }
        );
    }

    #[test]
    fn a_future_sender_clock_is_clamped_to_now() {
        let now = Instant::now();
        let ahead = NOW_MS + 3 * 24 * 60 * MINUTE;
        let rows = [row(false, "", ahead)];
        let p = presence(&with_address(), &rows, now, NOW_MS);
        assert_eq!(
            p,
            Presence::Quiet {
                last_ms: Some(NOW_MS)
            }
        );
        assert_eq!(p.meaning(NOW_MS), "Last message just now");
        // Even seen later, it is in touch for 15 minutes of this clock only.
        let seen = [later(row(false, "", ahead), now, NOW_MS)];
        assert_eq!(
            presence(
                &with_address(),
                &seen,
                now + RECENT_FOR,
                NOW_MS + 15 * MINUTE
            ),
            Presence::Quiet {
                last_ms: Some(NOW_MS + 15 * MINUTE)
            }
        );
    }

    #[test]
    fn no_address_then_waiting_then_recent_then_nothing() {
        let now = Instant::now();
        let recent = later(row(false, "", NOW_MS), now, NOW_MS);
        let queued = row(true, "queued", NOW_MS);
        let all = [recent.clone(), queued.clone(), queued.clone()];
        // No address beats everything.
        let nowhere = testkit::friend(1);
        let p = presence(&nowhere, &all, now, NOW_MS);
        assert_eq!(p, Presence::NoAddress);
        assert_eq!(p.meaning(NOW_MS), "No address to reach them");
        // Any one address is one.
        for friend in [
            ContactView {
                internet_dial: "203.0.113.7:7421".into(),
                ..testkit::friend(1)
            },
            ContactView {
                p2p: "12D3KooWExample".into(),
                ..testkit::friend(1)
            },
            with_address(),
        ] {
            assert_ne!(presence(&friend, &all, now, NOW_MS), Presence::NoAddress);
        }
        let p = presence(&with_address(), &all, now, NOW_MS);
        assert_eq!(p, Presence::Waiting(2));
        assert_eq!(p.meaning(NOW_MS), "2 messages waiting");
        assert_eq!(
            presence(&with_address(), std::slice::from_ref(&queued), now, NOW_MS).meaning(NOW_MS),
            "1 message waiting"
        );
        // A queued message from the friend's side is not one of yours.
        let theirs = [recent.clone(), row(false, "queued", NOW_MS)];
        assert_eq!(
            presence(&with_address(), &theirs, now, NOW_MS),
            Presence::Recent { at_ms: NOW_MS }
        );
        let p = presence(&with_address(), &[], now, NOW_MS);
        assert_eq!(p, Presence::Quiet { last_ms: None });
        assert_eq!(p.meaning(NOW_MS), "No messages yet");
        let unknown = Presence::Quiet { last_ms: Some(0) };
        assert_eq!(unknown.meaning(NOW_MS), "No recent contact");
        // Delivered and failed rows of yours that were there at the start
        // are nothing recent either.
        let old = [row(true, "delivered", NOW_MS), row(true, "failed", NOW_MS)];
        assert!(matches!(
            presence(&with_address(), &old, now, NOW_MS),
            Presence::Quiet { .. }
        ));
    }
}
