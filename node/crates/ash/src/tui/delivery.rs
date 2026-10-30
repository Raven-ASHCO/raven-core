//! Delivery ticks: where each of your messages stands, from what its send
//! job answered, the chat history and raven-node's outbox, and what R, C and
//! S may do about it.
//!
//! - A message sent in this session is a [`PendingSend`] from Enter on. Once
//!   a history load shows a new row of yours with its text, that row is
//!   bound to it ([`bind`]); until then it is drawn on its own.
//! - Write evidence ([`evidence`]) says whether the message may have reached
//!   the friend's computer. Only one that never did may be sent again
//!   without a warning: the friend would otherwise see it twice.
//! - The tick ([`tick`]) is the strongest state any source gives, and
//!   Delivered is never taken back (as the history's own `delivery_after`).

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use raven_core::ipc::OutboxItem;

use super::app::Row;
use super::bridge::{self, Cause, DeadlineText};
use super::controller::SendResult;
#[cfg(test)]
use super::controller::{RowView, BLOCKED};
use super::errors::{self, OutcomeKind, Plain};
#[cfg(test)]
use super::live::Carrier;
use super::live::Route;
use super::theme::Glyphs;

/// What ext.rs's cancel adds when the message was already written once, so
/// the friend may have it (testkit checks ext.rs still says it).
pub(super) const MAY_HAVE_IT: &str = "may have it anyway";
/// With less time than this left, a waiting message's label says how much,
/// and MSG says to tell the friend another way.
pub(super) const SOON_MS: u64 = 2 * HOUR_MS;
const HOUR_MS: u64 = 3_600_000;
const MINUTE_MS: u64 = 60_000;

/// One message sent in this session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingSend {
    /// Its number in this session, oldest first.
    pub(super) local_id: u64,
    /// The friend's key in lower case, as their conversation goes by.
    pub(super) peer: String,
    /// The text as sent (raw).
    pub(super) body: String,
    /// The ids of the friend's rows of yours when it was sent: none of them
    /// is its row.
    pub(super) snapshot: HashSet<String>,
    /// Its history row (the message id, lower case), once one is bound.
    pub(super) bound_mid: Option<String>,
    /// How its job ended; None while the job waits or runs.
    pub(super) outcome: Option<Outcome>,
    /// What the job printed (raw, for Details).
    pub(super) captured: String,
    /// When Enter sent it, on both clocks.
    pub(super) sent_at: Instant,
    pub(super) sent_ms: u64,
    /// How it went, when its own send brought the receipt back (UXF.10's
    /// route line and ticker).
    pub(super) route: Option<Route>,
}

impl PendingSend {
    pub(super) fn new(
        local_id: u64,
        peer: &str,
        body: String,
        snapshot: HashSet<String>,
        sent_at: Instant,
        sent_ms: u64,
    ) -> PendingSend {
        PendingSend {
            local_id,
            peer: peer.to_ascii_lowercase(),
            body,
            snapshot,
            bound_mid: None,
            outcome: None,
            captured: String::new(),
            sent_at,
            sent_ms,
            route: None,
        }
    }

    /// Its job answered that nothing was queued or written: no history row
    /// is ever its own.
    fn wrote_nothing(&self) -> bool {
        matches!(self.outcome, Some(Outcome::NotSent { .. }))
    }
}

/// How a send job ended, in the words errors.rs gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Their Raven confirmed it.
    Delivered,
    /// Queued on this computer. `background`: raven-node keeps trying it,
    /// else only the next send to the friend does. `connect`: the dial never
    /// reached the friend's Raven (nothing answered there, no address, or no
    /// background program here).
    Waiting {
        background: bool,
        connect: bool,
        plain: Plain,
    },
    /// Written to the friend's computer, which hasn't confirmed it.
    Sent(Plain),
    /// Nothing was queued: not sent, refused, or no background program to
    /// send through. `unmet`: why it can go only later, whatever a retry
    /// does now.
    NotSent { unmet: Unmet, plain: Plain },
}

/// Why a message that was not sent can go only later: Raven has no secure
/// connection with the friend and couldn't reach their computer to set one
/// up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unmet {
    /// Nothing of the kind: a retry may send it.
    No,
    /// The last secure connection ended: only once you are on the same
    /// network at the same time.
    MeetFirst,
    /// Raven hasn't connected with the friend yet: a first message goes only
    /// while you are both online (E1, the CLI's words).
    FirstMessage,
}

impl Outcome {
    /// A send job's answer, `who` the friend's name as drawn: the start of an
    /// outcome text says where the message stands (errors.rs), and the raw
    /// failure it keeps says why.
    pub(super) fn of(result: &SendResult, who: &str) -> Outcome {
        match result {
            SendResult::Delivered(_) => Outcome::Delivered,
            SendResult::NodeUnavailable(text) => Outcome::NotSent {
                unmet: Unmet::No,
                plain: errors::explain_node_unavailable(text),
            },
            SendResult::Failed(text) => match errors::explain_send(text, who) {
                (OutcomeKind::Waiting { background }, plain) => Outcome::Waiting {
                    background,
                    connect: connect_cause(bridge::classify_cause(&plain.technical)),
                    plain,
                },
                (OutcomeKind::Sent, plain) => Outcome::Sent(plain),
                (OutcomeKind::NotSent, plain) => Outcome::NotSent {
                    unmet: if errors::needs_meeting(text) {
                        Unmet::MeetFirst
                    } else if errors::first_message_away(text) {
                        Unmet::FirstMessage
                    } else {
                        Unmet::No
                    },
                    plain,
                },
            },
        }
    }

    /// The plain words, but for Delivered.
    pub(super) fn plain(&self) -> Option<&Plain> {
        match self {
            Outcome::Delivered => None,
            Outcome::Waiting { plain, .. }
            | Outcome::Sent(plain)
            | Outcome::NotSent { plain, .. } => Some(plain),
        }
    }

    /// Not sent because the two of you have to meet first.
    pub(super) fn meet_first(&self) -> bool {
        self.unmet() == Unmet::MeetFirst
    }

    /// Not sent: a first message whose friend's computer couldn't be
    /// reached, which goes only while you are both online.
    pub(super) fn first_message(&self) -> bool {
        self.unmet() == Unmet::FirstMessage
    }

    fn unmet(&self) -> Unmet {
        match self {
            Outcome::NotSent { unmet, .. } => *unmet,
            _ => Unmet::No,
        }
    }
}

/// A failure where the dial never reached the friend's Raven: nothing of
/// the message can have been written there.
fn connect_cause(cause: Cause) -> bool {
    matches!(
        cause,
        Cause::NotListening
            | Cause::NotReachable
            | Cause::NameNotFound
            | Cause::NoAddress
            | Cause::BadAddress
            | Cause::ServiceDown
            | Cause::ServiceStart
            | Cause::LocalNetworkRefused
    )
}

/// Whether a message may have reached the friend's computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteEvidence {
    /// It never left this computer: sending it again is safe.
    NeverWritten,
    /// It may have arrived: a second copy could show twice.
    MaybeWritten,
    /// Not sent by this app (an earlier session, another program): taken as
    /// [`WriteEvidence::MaybeWritten`].
    Unknown,
}

/// The write evidence of a message whose send job answered `outcome` (None
/// for a message this app did not send, or whose job has not answered).
/// `written`: something showed it was written once: the outbox listed it as
/// `sent`, or a cancel said the friend may have it.
pub(super) fn evidence(outcome: Option<&Outcome>, written: bool) -> WriteEvidence {
    match outcome {
        None => WriteEvidence::Unknown,
        Some(Outcome::NotSent { .. }) => WriteEvidence::NeverWritten,
        Some(Outcome::Waiting { connect: true, .. }) if !written => WriteEvidence::NeverWritten,
        Some(_) => WriteEvidence::MaybeWritten,
    }
}

/// Whether an outbox item shows its message was written once: listed as
/// `sent` (written, no ACK yet). Attempts and a carrier alone say nothing:
/// raven-node counts a dial that failed as an attempt on its carrier
/// (raven-node/src/outbox.rs, `apply_outcome` for `Unreachable`), and the
/// message stays `queued`.
pub(super) fn outbox_wrote(item: &OutboxItem) -> bool {
    item.state == "sent"
}

/// Binds sends to the history rows that are theirs, after a history load:
/// the oldest unbound send takes the first row of yours to the same friend
/// that is not in its snapshot, holds the same text and is no other send's.
/// A send that wrote nothing takes none. Returns the pairs bound now, as
/// (send, row id).
pub(super) fn bind(
    pending: &mut [PendingSend],
    convo: &HashMap<String, Vec<Row>>,
) -> Vec<(u64, String)> {
    let mut taken: HashSet<String> = pending.iter().filter_map(|p| p.bound_mid.clone()).collect();
    let mut bound = Vec::new();
    for send in pending
        .iter_mut()
        .filter(|p| p.bound_mid.is_none() && !p.wrote_nothing())
    {
        let Some(rows) = convo.get(&send.peer) else {
            continue;
        };
        let found = rows.iter().map(|row| &row.view).find_map(|view| {
            let id = view.id.to_ascii_lowercase();
            (view.outgoing
                && !id.is_empty()
                && view.body == send.body
                && !send.snapshot.contains(&id)
                && !taken.contains(&id))
            .then_some(id)
        });
        if let Some(id) = found {
            taken.insert(id.clone());
            send.bound_mid = Some(id.clone());
            bound.push((send.local_id, id));
        }
    }
    bound
}

/// Where a message's own send job is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JobState {
    /// Behind another job of the send worker.
    Queued,
    Running,
    /// Answered, or none of this session's.
    Done,
}

/// What is known of one message of yours.
#[derive(Debug, Clone, Copy)]
pub(super) struct Sources<'a> {
    /// Its history row's delivery state; None without a row.
    pub(super) history: Option<&'a str>,
    /// raven-node's outbox item for it, as last listed.
    pub(super) outbox: Option<&'a OutboxItem>,
    pub(super) outcome: Option<&'a Outcome>,
    pub(super) job: JobState,
    /// A background program answers for this profile.
    pub(super) node_running: bool,
}

/// A message's delivery state, as its tick and label show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Tick {
    /// Their Raven confirmed it.
    Delivered,
    /// raven-node stopped trying it: failed, expired or cancelled.
    /// `expired`: its time ran out (the history says expired).
    Ended {
        expired: bool,
    },
    /// It left this computer, not confirmed yet.
    Sent,
    /// raven-node holds it for the reason `code` says (`last_error_code`).
    OnHold {
        code: String,
    },
    Waiting(Waiting),
    /// Its send runs and is still reaching the friend: no row yet.
    Connecting,
    /// Its row is written and its send is dialling: the message itself is
    /// on its way.
    Sending,
    /// Behind another send.
    WaitingToSend,
    /// Nothing was queued or written.
    NotSent,
}

/// Who sends a waiting message again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Waiting {
    /// raven-node, in the background, until it runs out of time at
    /// `expires_at_ms` on the wall clock (0: not known).
    Retried { expires_at_ms: u64 },
    /// The next send to the friend (this raven-node has no background
    /// outbox).
    NextSend,
    /// Nobody now: no background program answers.
    NotRetried,
}

/// The tick for what `s` says, strongest first:
///
/// 1. Delivered: the history says delivered (or read), or the send did;
/// 2. Ended: the history says failed, expired or cancelled;
/// 3. Sent: the outbox lists it as sent, or the send said so;
/// 4. On hold: the outbox holds it;
/// 5. while its own send runs, Connecting until its row is written, then
///    Sending (the row says queued then: the send is working on it); behind
///    another send, Waiting to send. Field test E3: the two came the other
///    way round ("Sending…" for half a second, then "Connecting…" while the
///    message itself went);
/// 6. Waiting: the outbox or the history says queued, or the send did;
/// 7. Not sent: the send said so and no row is its own.
///
/// None for a row with no state to show (an old row with none).
pub(super) fn tick(s: &Sources) -> Option<Tick> {
    let outbox = s.outbox.map_or("", |item| item.state.as_str());
    if matches!(s.history, Some("delivered" | "read")) || s.outcome == Some(&Outcome::Delivered) {
        return Some(Tick::Delivered);
    }
    if matches!(s.history, Some("failed" | "expired" | "cancelled")) {
        return Some(Tick::Ended {
            expired: s.history == Some("expired"),
        });
    }
    if outbox == "sent" || matches!(s.outcome, Some(Outcome::Sent(_))) {
        return Some(Tick::Sent);
    }
    if outbox == "held" {
        return Some(Tick::OnHold {
            code: s
                .outbox
                .map(|item| item.last_error_code.clone())
                .unwrap_or_default(),
        });
    }
    match s.job {
        JobState::Running if s.history.is_some() => return Some(Tick::Sending),
        JobState::Running => return Some(Tick::Connecting),
        JobState::Queued => return Some(Tick::WaitingToSend),
        JobState::Done => {}
    }
    if outbox == "queued"
        || s.history == Some("queued")
        || matches!(s.outcome, Some(Outcome::Waiting { .. }))
    {
        let waiting = if !s.node_running {
            Waiting::NotRetried
        } else if matches!(
            s.outcome,
            Some(Outcome::Waiting {
                background: false,
                ..
            })
        ) {
            Waiting::NextSend
        } else {
            Waiting::Retried {
                expires_at_ms: s.outbox.map_or(0, |item| item.expires_at_ms),
            }
        };
        return Some(Tick::Waiting(waiting));
    }
    (s.history.is_none() && matches!(s.outcome, Some(Outcome::NotSent { .. })))
        .then_some(Tick::NotSent)
}

impl Tick {
    /// Raven gave up on it, or never sent it: the failure mark.
    pub(super) fn failed(&self) -> bool {
        matches!(self, Tick::Ended { .. } | Tick::NotSent)
    }
}

/// What the keys may do to a message in `tick` with `evidence`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Actions {
    /// R: raven-node tries the waiting message now (`outbox retry`).
    pub(super) try_now: bool,
    /// R: the same text goes again, as a new message: nothing of it left
    /// this computer.
    pub(super) send_again: bool,
    /// C: raven-node stops trying it (`outbox cancel`), after confirming.
    pub(super) stop: bool,
    /// S in MSG: the same text again although the friend may have it,
    /// after a warning that they may see it twice.
    pub(super) send_again_anyway: bool,
}

/// The actions table: Waiting and On hold may be tried now or stopped; Not
/// sent, and Ended while it never left this computer, may be sent again;
/// Ended when it may have arrived only after a warning. Sent has none: the
/// CLI says not to type it again.
pub(super) fn actions(tick: &Tick, evidence: WriteEvidence) -> Actions {
    match tick {
        Tick::Waiting(_) | Tick::OnHold { .. } => Actions {
            try_now: true,
            stop: true,
            ..Actions::default()
        },
        Tick::NotSent => Actions {
            send_again: true,
            ..Actions::default()
        },
        Tick::Ended { .. } if evidence == WriteEvidence::NeverWritten => Actions {
            send_again: true,
            ..Actions::default()
        },
        Tick::Ended { .. } => Actions {
            send_again_anyway: true,
            ..Actions::default()
        },
        Tick::Delivered | Tick::Sent | Tick::Connecting | Tick::Sending | Tick::WaitingToSend => {
            Actions::default()
        }
    }
}

/// The label after a message's tick (HOME's copy). `who`: the friend's name
/// as drawn; `now_ms`: the wall clock, for how long a waiting message has.
pub(super) fn label(
    tick: &Tick,
    evidence: WriteEvidence,
    outcome: Option<&Outcome>,
    who: &str,
    glyphs: &Glyphs,
    now_ms: u64,
) -> String {
    let ellipsis = glyphs.ellipsis;
    match tick {
        Tick::WaitingToSend => "Waiting to send".to_owned(),
        Tick::Sending => format!("Sending{ellipsis}"),
        Tick::Connecting => format!("Connecting{ellipsis}"),
        Tick::Waiting(Waiting::Retried { expires_at_ms: 0 }) => {
            "Waiting: Raven keeps trying".to_owned()
        }
        Tick::Waiting(Waiting::Retried { expires_at_ms }) => format!(
            "Waiting for {who}{}{}",
            glyphs.inline_separator,
            time_left(&bridge::deadline_text(*expires_at_ms, now_ms))
        ),
        Tick::Waiting(Waiting::NextSend) => "Waiting: goes out with your next message".to_owned(),
        Tick::Waiting(Waiting::NotRetried) => {
            "Waiting: not being retried (Raven's background program isn't running)".to_owned()
        }
        Tick::OnHold { code } => format!(
            "On hold: {}",
            clause(&errors::explain_outbox_code(code, who).headline)
        ),
        Tick::Sent => "Sent, not confirmed yet".to_owned(),
        Tick::Delivered => "Delivered".to_owned(),
        Tick::Ended { expired: true } if evidence == WriteEvidence::NeverWritten => {
            "Time ran out: it never left this computer. Press R to send it again.".to_owned()
        }
        Tick::Ended { .. } if evidence == WriteEvidence::NeverWritten => {
            "Not delivered: it never left this computer. Press R to send it again.".to_owned()
        }
        Tick::Ended { .. } => {
            format!("Not confirmed: {who} may have it. Press Enter for options.")
        }
        Tick::NotSent if outcome.is_some_and(Outcome::meet_first) => {
            "Not sent: meet first. Press R when you're together.".to_owned()
        }
        Tick::NotSent if outcome.is_some_and(Outcome::first_message) => format!(
            "Not sent: a first message needs you both online. Press R when {who} is online."
        ),
        Tick::NotSent => {
            let reason = outcome
                .and_then(Outcome::plain)
                .map_or("Raven couldn't send it", |plain| clause(&plain.headline));
            format!("Not sent: {reason}. Press R to try again.")
        }
    }
}

/// A sentence without its closing full stop, to go on inside another.
fn clause(sentence: &str) -> &str {
    let sentence = sentence.trim();
    sentence.strip_suffix('.').unwrap_or(sentence)
}

/// What a waiting message's label says of its deadline: until when, or,
/// with less than [`SOON_MS`] left, how much is left.
fn time_left(deadline: &DeadlineText) -> String {
    match deadline.left_ms {
        left if left >= SOON_MS => format!("until {}", deadline.short),
        left if left >= HOUR_MS => format!("{} h left", left / HOUR_MS),
        left if left >= MINUTE_MS => format!("{} min left", left / MINUTE_MS),
        _ => "less than a minute left".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const WHO: &str = "Bob";

    fn plain(technical: &str) -> Plain {
        Plain {
            headline: "Something happened.".into(),
            next: String::new(),
            action: errors::Action::None,
            technical: technical.into(),
        }
    }

    fn item(state: &str) -> OutboxItem {
        OutboxItem {
            message_id_hex: "ab".repeat(16),
            peer_pub_hex: "b0".repeat(32),
            kind: "message".into(),
            state: state.into(),
            ..OutboxItem::default()
        }
    }

    fn sources<'a>(
        history: Option<&'a str>,
        outbox: Option<&'a OutboxItem>,
        outcome: Option<&'a Outcome>,
        job: JobState,
    ) -> Sources<'a> {
        Sources {
            history,
            outbox,
            outcome,
            job,
            node_running: true,
        }
    }

    fn not_sent(plain: Plain) -> Outcome {
        Outcome::NotSent {
            unmet: Unmet::No,
            plain,
        }
    }

    fn waiting(background: bool, connect: bool) -> Outcome {
        Outcome::Waiting {
            background,
            connect,
            plain: plain("connection refused"),
        }
    }

    #[test]
    fn the_strongest_source_wins_and_delivered_is_never_taken_back() {
        use JobState::{Done, Queued, Running};
        let delivered = Outcome::Delivered;
        let sent = Outcome::Sent(plain(""));
        let queued = waiting(true, true);
        let not_sent = not_sent(plain(""));
        let (outbox_sent, outbox_held, outbox_queued) =
            (item("sent"), item("held"), item("queued"));
        let cases: Vec<(Sources, Option<Tick>)> = vec![
            // Delivered beats everything, from either side.
            (
                sources(Some("delivered"), Some(&outbox_queued), Some(&queued), Done),
                Some(Tick::Delivered),
            ),
            (
                sources(Some("read"), None, None, Done),
                Some(Tick::Delivered),
            ),
            (
                sources(Some("queued"), Some(&outbox_held), Some(&delivered), Done),
                Some(Tick::Delivered),
            ),
            (
                sources(Some("failed"), Some(&outbox_sent), Some(&delivered), Done),
                Some(Tick::Delivered),
            ),
            // Then Ended, Sent, On hold.
            (
                sources(Some("cancelled"), Some(&outbox_sent), Some(&sent), Done),
                Some(Tick::Ended { expired: false }),
            ),
            (
                sources(Some("failed"), None, Some(&queued), Done),
                Some(Tick::Ended { expired: false }),
            ),
            // Its time ran out: the history says so, whatever else does.
            (
                sources(Some("expired"), Some(&outbox_queued), Some(&queued), Done),
                Some(Tick::Ended { expired: true }),
            ),
            (
                sources(Some("expired"), None, None, Done),
                Some(Tick::Ended { expired: true }),
            ),
            (
                sources(Some("queued"), Some(&outbox_sent), Some(&queued), Done),
                Some(Tick::Sent),
            ),
            (
                sources(Some("queued"), None, Some(&sent), Done),
                Some(Tick::Sent),
            ),
            (
                sources(Some("queued"), Some(&outbox_held), Some(&queued), Done),
                Some(Tick::OnHold {
                    code: String::new(),
                }),
            ),
            // Its own send at work: the row it wrote says queued meanwhile.
            (
                sources(Some("queued"), Some(&outbox_queued), None, Running),
                Some(Tick::Sending),
            ),
            (sources(None, None, None, Running), Some(Tick::Connecting)),
            (sources(None, None, None, Queued), Some(Tick::WaitingToSend)),
            // Waiting, from any of three sources.
            (
                sources(None, Some(&outbox_queued), None, Done),
                Some(Tick::Waiting(Waiting::Retried { expires_at_ms: 0 })),
            ),
            (
                sources(Some("queued"), None, None, Done),
                Some(Tick::Waiting(Waiting::Retried { expires_at_ms: 0 })),
            ),
            (
                sources(None, None, Some(&queued), Done),
                Some(Tick::Waiting(Waiting::Retried { expires_at_ms: 0 })),
            ),
            // Not sent only without a row of its own.
            (
                sources(None, None, Some(&not_sent), Done),
                Some(Tick::NotSent),
            ),
            (
                sources(Some("queued"), None, Some(&not_sent), Done),
                Some(Tick::Waiting(Waiting::Retried { expires_at_ms: 0 })),
            ),
            // An old row with no state shows none.
            (sources(Some(""), None, None, Done), None),
            (sources(None, None, None, Done), None),
        ];
        for (s, want) in cases {
            assert_eq!(tick(&s), want, "{s:?}");
        }
    }

    #[test]
    fn waiting_says_who_tries_again() {
        let mut timed = item("queued");
        timed.expires_at_ms = 1_760_086_400_000;
        let in_background = waiting(true, true);
        let next_send = waiting(false, true);
        let at = |outcome, outbox, node_running| {
            tick(&Sources {
                history: Some("queued"),
                outbox,
                outcome,
                job: JobState::Done,
                node_running,
            })
        };
        assert_eq!(
            at(Some(&in_background), Some(&timed), true),
            Some(Tick::Waiting(Waiting::Retried {
                expires_at_ms: 1_760_086_400_000
            }))
        );
        assert_eq!(
            at(Some(&next_send), None, true),
            Some(Tick::Waiting(Waiting::NextSend))
        );
        // No background program answers: nobody tries it now.
        for outcome in [Some(&in_background), Some(&next_send), None] {
            assert_eq!(
                at(outcome, None, false),
                Some(Tick::Waiting(Waiting::NotRetried))
            );
        }
    }

    /// The CLI's own outcome texts, as a send to Bob gets them.
    fn ctx(dir: &Path) -> bridge::SendCtx {
        bridge::send_ctx(dir, WHO, "", &"b0".repeat(32))
    }

    #[test]
    fn every_outcome_prefix_is_read() {
        let dir = tempfile::tempdir().expect("a profile");
        let ctx = ctx(dir.path());
        let note = |background| bridge::RetryNote {
            expires_at_ms: 1_760_086_400_000,
            copy_expires_at_ms: 0,
            background,
            custodians: Vec::new(),
            carry_first: None,
        };
        const REFUSED: &str = "lan connect: cannot connect to 127.0.0.1:9 (Connection refused)";
        const SILENT: &str = "early eof while reading the reply";
        let of = |text: String| Outcome::of(&SendResult::Failed(text), WHO);

        assert_eq!(
            Outcome::of(
                &SendResult::Delivered(Route {
                    carrier: Carrier::Lan,
                    dial: Some("127.0.0.1:9".into()),
                    path: String::new(),
                }),
                WHO
            ),
            Outcome::Delivered
        );
        match of(bridge::queued_text(&ctx, REFUSED, "hi", &note(true))) {
            Outcome::Waiting {
                background: true,
                connect: true,
                plain,
            } => assert!(plain.technical.contains("Connection refused"), "{plain:?}"),
            other => panic!("{other:?}"),
        }
        match of(bridge::queued_text(&ctx, SILENT, "hi", &note(false))) {
            Outcome::Waiting {
                background: false,
                connect: false,
                ..
            } => {}
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            of(bridge::unconfirmed_text(&ctx, SILENT, "hi", &note(true))),
            Outcome::Sent(_)
        ));
        match of(bridge::not_sent_text(&ctx, REFUSED, true)) {
            Outcome::NotSent {
                unmet: Unmet::No,
                plain,
            } => {
                assert_eq!(
                    plain.headline,
                    "Bob's computer is there, but Raven isn't receiving right now (it may be locked or closed)."
                );
                assert_eq!(plain.next, "Ask Bob to open Raven.");
            }
            other => panic!("{other:?}"),
        }
        // A first message to a friend whose computer couldn't be reached:
        // there is no secure connection to queue it on, so it goes only
        // while you are both online (E1), no meeting needed. One whose
        // computer answered needs Raven opened there; with a secure
        // connection it would have waited.
        const UNREACHABLE: &str = "lan connect: cannot connect to 192.168.1.20:7420 (timed out)";
        let first = of(bridge::not_sent_text(&ctx, UNREACHABLE, true));
        assert!(first.first_message() && !first.meet_first(), "{first:?}");
        for (raw, first_contact) in [(UNREACHABLE, false), (REFUSED, true), (SILENT, true)] {
            let outcome = of(bridge::not_sent_text(&ctx, raw, first_contact));
            assert!(
                matches!(outcome, Outcome::NotSent { .. })
                    && !outcome.meet_first()
                    && !outcome.first_message(),
                "{raw} {first_contact}: {outcome:?}"
            );
        }
        // A refusal before any dial, and anything else, is not sent too.
        for text in [
            BLOCKED.to_owned(),
            "send refused: the message is empty".to_owned(),
            "something no one wrote down".to_owned(),
        ] {
            assert!(
                matches!(
                    of(text.clone()),
                    Outcome::NotSent {
                        unmet: Unmet::No,
                        ..
                    }
                ),
                "{text}"
            );
        }
        match Outcome::of(
            &SendResult::NodeUnavailable(
                "local raven-node service is not running and could not be started: x".into(),
            ),
            WHO,
        ) {
            Outcome::NotSent {
                unmet: Unmet::No,
                plain,
            } => assert_eq!(
                plain.headline,
                "Raven's background program isn't running on this computer."
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn write_evidence_follows_the_outcome_and_what_was_seen_since() {
        use WriteEvidence::{MaybeWritten, NeverWritten, Unknown};
        let refused = waiting(true, true);
        let dropped = waiting(true, false);
        let sent = Outcome::Sent(plain(""));
        let not_sent = not_sent(plain(""));
        // A connect-type failure that queued it: it never left, until the
        // outbox (or a cancel) says it was written once.
        assert_eq!(evidence(Some(&refused), false), NeverWritten);
        assert_eq!(evidence(Some(&refused), true), MaybeWritten);
        // Anything that got as far as the friend's Raven may have arrived.
        assert_eq!(evidence(Some(&dropped), false), MaybeWritten);
        assert_eq!(evidence(Some(&sent), false), MaybeWritten);
        assert_eq!(evidence(Some(&Outcome::Delivered), false), MaybeWritten);
        assert_eq!(evidence(Some(&not_sent), false), NeverWritten);
        // A row this app did not send.
        assert_eq!(evidence(None, false), Unknown);

        // What the outbox shows: sent, written once on a carrier.
        let written = OutboxItem {
            attempts: 1,
            carrier: "lan_dial".into(),
            ..item("sent")
        };
        assert!(outbox_wrote(&written));
        assert!(outbox_wrote(&item("sent")));
        // Dials that failed count as attempts on their carrier, and the
        // message is still queued: nothing was written.
        let tried = OutboxItem {
            attempts: 2,
            carrier: "lan_dial".into(),
            last_error_code: "NOT_LISTENING".into(),
            ..item("queued")
        };
        assert!(!outbox_wrote(&tried));
        assert!(!outbox_wrote(&item("queued")));
        assert!(!outbox_wrote(&item("held")));
        // ext.rs's cancel, when the message was written once.
        assert!(
            "cancelled: raven-node stops trying to deliver your message \"hi\" to Bob. It was \
             already sent once, so Bob may have it anyway."
                .contains(MAY_HAVE_IT)
        );
    }

    fn out_row(id: u8, body: &str) -> Row {
        Row {
            view: RowView {
                id: format!("{id:02X}").repeat(16),
                outgoing: true,
                created_at_ms: 1,
                delivery: "queued".into(),
                body: body.into(),
                id_conflict: false,
            },
            seen_at_start: false,
            touched: None,
        }
    }

    fn sent(local_id: u64, body: &str, snapshot: &[u8]) -> PendingSend {
        let snapshot = snapshot
            .iter()
            .map(|id| format!("{id:02x}").repeat(16))
            .collect();
        PendingSend::new(
            local_id,
            &"B0".repeat(32),
            body.into(),
            snapshot,
            Instant::now(),
            0,
        )
    }

    #[test]
    fn sends_bind_to_their_own_rows_oldest_first() {
        let peer = "b0".repeat(32);
        let mid = |id: u8| format!("{id:02x}").repeat(16);
        // An older "hi" (row 1) was there when both were sent.
        let mut pending = vec![
            sent(1, "hi", &[1]),
            sent(2, "hi", &[1]),
            sent(3, "yo", &[1]),
        ];
        let mut convo = HashMap::new();
        convo.insert(peer.clone(), vec![out_row(1, "hi")]);
        assert!(bind(&mut pending, &convo).is_empty(), "no new row yet");
        // Two identical bodies in a row: each send its own row, in order.
        convo.insert(
            peer.clone(),
            vec![out_row(1, "hi"), out_row(2, "hi"), out_row(3, "hi")],
        );
        assert_eq!(
            bind(&mut pending, &convo),
            [(1, mid(2)), (2, mid(3))],
            "row 1 is in the snapshot"
        );
        assert_eq!(pending[2].bound_mid, None, "no row holds its text");
        // Bound once, never again; the next load binds the rest only.
        convo.get_mut(&peer).expect("Bob").push(out_row(4, "yo"));
        assert_eq!(bind(&mut pending, &convo), [(3, mid(4))]);
        assert!(bind(&mut pending, &convo).is_empty());
        assert_eq!(
            pending
                .iter()
                .map(|p| p.bound_mid.clone())
                .collect::<Vec<_>>(),
            [Some(mid(2)), Some(mid(3)), Some(mid(4))]
        );
        // A send that wrote nothing takes no row, so a later one with the
        // same text gets its own; another friend's rows are not looked at.
        let mut pending = vec![sent(5, "hi", &[]), sent(6, "hi", &[])];
        pending[0].outcome = Some(not_sent(plain("")));
        let mut convo = HashMap::new();
        convo.insert(peer, vec![out_row(7, "hi")]);
        convo.insert("c0".repeat(32), vec![out_row(8, "hi")]);
        assert_eq!(bind(&mut pending, &convo), [(6, mid(7))]);
        // The friend's own messages are never a send's.
        let mut theirs = out_row(9, "yo");
        theirs.view.outgoing = false;
        let mut pending = vec![sent(10, "yo", &[])];
        let mut convo = HashMap::new();
        convo.insert("b0".repeat(32), vec![theirs]);
        assert!(bind(&mut pending, &convo).is_empty());
    }

    #[test]
    fn each_state_allows_its_own_keys() {
        use WriteEvidence::{MaybeWritten, NeverWritten, Unknown};
        let waiting = Tick::Waiting(Waiting::NextSend);
        let held = Tick::OnHold {
            code: "NO_ROUTE".into(),
        };
        for tick in [&waiting, &held] {
            assert_eq!(
                actions(tick, MaybeWritten),
                Actions {
                    try_now: true,
                    stop: true,
                    ..Actions::default()
                }
            );
        }
        let again = Actions {
            send_again: true,
            ..Actions::default()
        };
        assert_eq!(actions(&Tick::NotSent, NeverWritten), again);
        for expired in [false, true] {
            assert_eq!(actions(&Tick::Ended { expired }, NeverWritten), again);
        }
        // It may have arrived: no R, only S after the warning.
        for (evidence, expired) in [
            (MaybeWritten, false),
            (Unknown, false),
            (MaybeWritten, true),
        ] {
            assert_eq!(
                actions(&Tick::Ended { expired }, evidence),
                Actions {
                    send_again_anyway: true,
                    ..Actions::default()
                }
            );
        }
        // Sent: never typed again; the rest have nothing to do.
        for tick in [
            Tick::Sent,
            Tick::Delivered,
            Tick::Connecting,
            Tick::Sending,
            Tick::WaitingToSend,
        ] {
            assert_eq!(actions(&tick, MaybeWritten), Actions::default(), "{tick:?}");
            assert_eq!(actions(&tick, NeverWritten), Actions::default(), "{tick:?}");
        }
    }

    #[test]
    fn labels_say_each_state_in_words() {
        use WriteEvidence::{MaybeWritten, NeverWritten, Unknown};
        const NOW: u64 = 1_760_000_000_000;
        let none = None;
        let label_of = |tick: &Tick, evidence, outcome: Option<&Outcome>| {
            label(tick, evidence, outcome, WHO, &Glyphs::fancy(), NOW)
        };
        let refused = not_sent(Plain {
            headline: "Bob's computer is there, but Raven isn't receiving right now (it may be locked or closed).".into(),
            ..plain("")
        });
        let unmet = Outcome::NotSent {
            unmet: Unmet::MeetFirst,
            plain: Plain {
                headline: "Bob's computer couldn't be reached.".into(),
                ..plain("")
            },
        };
        let first = Outcome::NotSent {
            unmet: Unmet::FirstMessage,
            plain: Plain {
                headline: "Bob's computer couldn't be reached.".into(),
                ..plain("")
            },
        };
        let cases = [
            (Tick::WaitingToSend, MaybeWritten, none, "Waiting to send"),
            (Tick::Sending, MaybeWritten, none, "Sending…"),
            (Tick::Connecting, MaybeWritten, none, "Connecting…"),
            (
                Tick::Waiting(Waiting::Retried {
                    expires_at_ms: NOW + 22 * HOUR_MS,
                }),
                MaybeWritten,
                none,
                "Waiting for Bob · until about 22 h from now",
            ),
            (
                Tick::Waiting(Waiting::Retried { expires_at_ms: 0 }),
                MaybeWritten,
                none,
                "Waiting: Raven keeps trying",
            ),
            (
                Tick::Waiting(Waiting::NextSend),
                MaybeWritten,
                none,
                "Waiting: goes out with your next message",
            ),
            (
                Tick::Waiting(Waiting::NotRetried),
                MaybeWritten,
                none,
                "Waiting: not being retried (Raven's background program isn't running)",
            ),
            (
                Tick::OnHold {
                    code: "NO_PEER_CERT".into(),
                },
                MaybeWritten,
                none,
                "On hold: Raven is still setting up a secure connection with Bob",
            ),
            (Tick::Sent, MaybeWritten, none, "Sent, not confirmed yet"),
            (Tick::Delivered, MaybeWritten, none, "Delivered"),
            // Ended: why it ended, and whether it may have arrived.
            (
                Tick::Ended { expired: true },
                NeverWritten,
                none,
                "Time ran out: it never left this computer. Press R to send it again.",
            ),
            (
                Tick::Ended { expired: false },
                NeverWritten,
                none,
                "Not delivered: it never left this computer. Press R to send it again.",
            ),
            (
                Tick::Ended { expired: true },
                MaybeWritten,
                none,
                "Not confirmed: Bob may have it. Press Enter for options.",
            ),
            (
                Tick::Ended { expired: true },
                Unknown,
                none,
                "Not confirmed: Bob may have it. Press Enter for options.",
            ),
            (
                Tick::Ended { expired: false },
                MaybeWritten,
                none,
                "Not confirmed: Bob may have it. Press Enter for options.",
            ),
            (
                Tick::NotSent,
                NeverWritten,
                Some(&refused),
                "Not sent: Bob's computer is there, but Raven isn't receiving right now (it may be locked or closed). Press R to \
                 try again.",
            ),
            (
                Tick::NotSent,
                NeverWritten,
                Some(&unmet),
                "Not sent: meet first. Press R when you're together.",
            ),
            (
                Tick::NotSent,
                NeverWritten,
                Some(&first),
                "Not sent: a first message needs you both online. Press R when Bob is online.",
            ),
        ];
        for (tick, evidence, outcome, want) in cases {
            assert_eq!(label_of(&tick, evidence, outcome), want, "{tick:?}");
        }
        // The separator is the glyph set's.
        let waiting = Tick::Waiting(Waiting::Retried {
            expires_at_ms: NOW + 22 * HOUR_MS,
        });
        for glyphs in [Glyphs::simple(), Glyphs::ascii()] {
            assert_eq!(
                label(&waiting, MaybeWritten, None, WHO, &glyphs, NOW),
                "Waiting for Bob - until about 22 h from now"
            );
        }
    }

    #[test]
    fn under_two_hours_the_label_counts_what_is_left() {
        const NOW: u64 = 1_760_000_000_000;
        let at = |left: u64| {
            let tick = Tick::Waiting(Waiting::Retried {
                expires_at_ms: NOW + left,
            });
            label(
                &tick,
                WriteEvidence::NeverWritten,
                None,
                WHO,
                &Glyphs::simple(),
                NOW,
            )
        };
        assert_eq!(at(SOON_MS), "Waiting for Bob - until about 2 h from now");
        assert_eq!(at(SOON_MS - 1), "Waiting for Bob - 1 h left");
        assert_eq!(at(HOUR_MS), "Waiting for Bob - 1 h left");
        assert_eq!(at(HOUR_MS - 1), "Waiting for Bob - 59 min left");
        assert_eq!(at(MINUTE_MS), "Waiting for Bob - 1 min left");
        assert_eq!(
            at(MINUTE_MS - 1),
            "Waiting for Bob - less than a minute left"
        );
        // raven-node hasn't marked it expired yet: none left, not a past time.
        let late = Tick::Waiting(Waiting::Retried {
            expires_at_ms: NOW - HOUR_MS,
        });
        assert_eq!(
            label(
                &late,
                WriteEvidence::NeverWritten,
                None,
                WHO,
                &Glyphs::simple(),
                NOW
            ),
            "Waiting for Bob - less than a minute left"
        );
    }
}
