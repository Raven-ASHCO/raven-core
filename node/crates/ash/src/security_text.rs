//! The plain texts of Raven's security notices (Phase 6b design A, step
//! P6.30): one English table that the CLI (`raven security`, the SECURITY
//! section of `raven status`, `raven doctor`, the note of `raven send` and
//! the older-method question of `raven contact verify`) and the terminal app
//! (through `tui/bridge.rs`) both read. English only (owner rule): there is
//! no translation layer.
//!
//! The rules (design A UX): say what happened, what Raven did and what the
//! person can do, in that order and in short sentences; the harmless
//! explanation first; never accuse a friend and never claim a certainty
//! Raven does not have; every notice ends with one concrete action
//! ([`Act`]); no address, message id or key in any text. A text that asks
//! to check a friend's key says "compare security words" ([`WORDS`], the
//! security words design), never a digits-only code.

use raven_core::local_time;
use raven_core::security_events::{SecKind, Severity};

/// What a person compares with a friend to check a key: the security words
/// (owner rule 8; the old code stays accepted when typed, never asked for).
pub(crate) const WORDS: &str = "security words";

/// `raven security` while the security events gate is shut (the release
/// builds of this version).
pub(crate) const NOT_IN_THIS_VERSION: &str = "Security notices are not part of this version.";

/// A profile that is not encrypted keeps no security ledger.
pub(crate) const NOT_KEPT_UNSEALED: &str = "This profile is not encrypted, so Raven keeps no \
     security notices for it (`raven privacy seal-now` encrypts it).";

/// `raven security` with nothing open.
pub(crate) const NOTHING_OPEN: &str = "No open security notices.";

/// The question of `raven security clear` (the typed word is `clear`).
pub(crate) const CLEAR_QUESTION: &str = "Delete every security notice and count Raven keeps on \
     this computer? Type clear to delete them (Enter keeps them):";

/// After `raven security clear`.
pub(crate) const CLEARED: &str = "Deleted every security notice and count Raven kept on this \
     computer.";

/// Where `raven status` and `raven doctor` send the person for more.
pub(crate) const DETAILS: &str = "Details: raven security";

/// The one thing a notice asks the person to do. The CLI prints its command
/// ([`cli_hint`]); the terminal app shows its own key for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Act {
    /// Compare security words with the contact (`raven contact verify`).
    CompareWords,
    /// Use a friend's mailbox again now, or let Raven try it after a day.
    MailboxRetry,
    /// Use another network.
    OtherNetwork,
    /// Stop listening while it is not needed (`raven lan off`).
    StopListening,
    /// Check the clock and time zone on both computers.
    CheckClock,
    /// Talk to the person; there is no command for it.
    AskThem,
    /// Nothing: Raven took care of it.
    Nothing,
}

impl Act {
    /// The stable name `--json` carries.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Act::CompareWords => "compare_words",
            Act::MailboxRetry => "mailbox_retry",
            Act::OtherNetwork => "other_network",
            Act::StopListening => "stop_listening",
            Act::CheckClock => "check_clock",
            Act::AskThem => "ask_them",
            Act::Nothing => "nothing",
        }
    }
}

/// Whom a notice is about, as its texts name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum About<'a> {
    /// A contact, by its name in this contact book.
    Contact(&'a str),
    /// A friend's computer as a mailbox or as a depositor, by its name.
    Carrier(&'a str),
    /// A p2p relay (only a digest of its PeerId is kept: no name).
    Relay,
    /// This computer's own state.
    ThisComputer,
    /// A security update, and the contact who passed it on, if any.
    Update(Option<&'a str>),
    /// A source on the network (never stored), or nobody known.
    Unknown,
}

impl<'a> About<'a> {
    /// The name the texts use.
    fn name(self) -> &'a str {
        match self {
            About::Contact(name) | About::Carrier(name) => name,
            About::Update(Some(name)) => name,
            About::Relay => "a relay",
            About::ThisComputer => "this computer",
            About::Update(None) | About::Unknown => "someone",
        }
    }
}

/// One notice in words: what happened (`headline`), what Raven did, what
/// the person can do, and that action ([`Act`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NoticeText {
    pub headline: String,
    pub did: String,
    pub todo: String,
    pub act: Act,
}

/// The texts of a notice of `kind` at `severity` about `about`; `action` is
/// the fixed code of what Raven did about it (the ledger's `action`), which
/// adds its sentence to what Raven did.
pub(crate) fn notice(
    kind: SecKind,
    severity: Severity,
    about: About<'_>,
    action: Option<&str>,
) -> NoticeText {
    let name = about.name();
    let words = WORDS;
    let ask_restore = format!(
        "Ask {name}, in person or by phone, whether they reinstalled Raven or restored their \
         computer. Then compare {words}."
    );
    let passed = match about {
        About::Update(Some(name)) => format!(" passed on by {name}"),
        _ => String::new(),
    };
    let (headline, did, todo, act): (String, &str, String, Act) = match kind {
        SecKind::LinkTagFail if severity >= Severity::Alert => (
            format!("Someone on this network keeps changing data between you and {name}"),
            "Raven noticed each time and threw it away. Nothing was read.",
            "Use another network or a hotspot you control.".into(),
            Act::OtherNetwork,
        ),
        SecKind::LinkTagFail => (
            format!("Data between you and {name} was changed on the way"),
            "Raven noticed it and threw it away. Nothing was read.",
            "If it keeps happening, use another network or a hotspot you control.".into(),
            Act::OtherNetwork,
        ),
        SecKind::HandshakeFail => (
            "Connections to this computer failed before they started".into(),
            "Raven closed them. They learned nothing about you.",
            "Nothing. If it keeps happening, stop listening when you don't need it.".into(),
            Act::StopListening,
        ),
        SecKind::PreauthMalformed => (
            "Unknown computers sent data Raven could not read".into(),
            "Raven closed those connections. They learned nothing about you.",
            "Nothing. If it keeps happening, stop listening when you don't need it.".into(),
            Act::StopListening,
        ),
        SecKind::StrangerRefused => (
            "Unknown computers tried to connect".into(),
            "Raven refused them. They learned nothing about you.",
            "Nothing. If you didn't expect this, stop listening when you don't need it.".into(),
            Act::StopListening,
        ),
        SecKind::BlockedRefused => (
            "Someone you blocked tried to connect".into(),
            "Raven refused it.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::UnverifiedRemote => (
            "A contact you haven't verified tried to connect from outside this network".into(),
            "Raven refused it: from outside this network, only friends you verified connect.",
            format!("Compare {words} with them, in person or by phone."),
            Act::CompareWords,
        ),
        SecKind::PreauthFlood => (
            "Unknown computers on this network tried to connect many times".into(),
            "Raven refused all of them. They learned nothing about you.",
            "If you didn't expect this, stop listening when you don't need it, or use meeting \
             mode."
                .into(),
            Act::StopListening,
        ),
        SecKind::P2pGateRefused => (
            "Unknown computers on the internet tried to connect".into(),
            "Raven refused them before they learned anything about you.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::BeaconReplay => (
            "Something on this network repeated an old Raven search".into(),
            "Raven ignored it.",
            "If you didn't expect this, use another network.".into(),
            Act::OtherNetwork,
        ),
        SecKind::BeaconFlood => (
            "Something on this network sent many Raven searches".into(),
            "Raven answered only within its limits.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::KnockReplay => (
            "Something on this network repeated an old Raven greeting".into(),
            "Raven refused it.",
            "If you didn't expect this, use another network.".into(),
            Act::OtherNetwork,
        ),
        SecKind::ObjectAuthFail => (
            format!("Messages from {name} failed Raven's security check"),
            "Raven didn't show them.",
            format!("{ask_restore} Raven never blocks {name} by itself."),
            Act::CompareWords,
        ),
        SecKind::ObjectSigFail => (
            format!("Messages from {name} carried a signature Raven doesn't accept"),
            "Raven didn't show them.",
            format!("{ask_restore} Raven never blocks {name} by itself."),
            Act::CompareWords,
        ),
        SecKind::ObjectReplay => (
            format!("Old messages from {name} arrived again"),
            "Raven didn't show them twice.",
            format!(
                "This can happen when {name} restored their computer from a backup. Ask {name}, \
                 then compare {words}."
            ),
            Act::CompareWords,
        ),
        SecKind::IndexJump => (
            format!("Some messages from {name} seem to be missing"),
            "Raven keeps the conversation going.",
            format!(
                "Nothing: a lost message or two is common. If {name} says messages are missing, \
                 compare {words}."
            ),
            Act::Nothing,
        ),
        SecKind::SessionUnknown => (
            format!("A message from {name} came over a secure connection Raven no longer has"),
            "Raven didn't show it. A new secure connection is set up the next time you connect.",
            "Nothing. This happens after a reinstall or a restore.".into(),
            Act::Nothing,
        ),
        SecKind::BindingMismatch | SecKind::RevokedDeviceUsed => (
            format!("Something claiming to be {name} used a key Raven doesn't accept"),
            "Raven refused it. Nothing was shown or sent.",
            format!(
                "Compare {words} with {name} before you continue. If {name} removed an old \
                 computer, this is expected."
            ),
            Act::CompareWords,
        ),
        SecKind::KeyChangeAttempt => (
            format!("An invite had a different key from the {name} you verified"),
            "Raven kept the old key.",
            format!(
                "If {name} really has a new key (a new computer or a reinstall), compare {words} \
                 with {name} before you add it. If not, ignore that invite."
            ),
            Act::CompareWords,
        ),
        SecKind::PrekeyRollback => (
            format!("{name}'s Raven offered an older key for new conversations"),
            "Raven kept using the newer one.",
            format!(
                "This can happen when {name} restored a backup. Ask {name}; if {name} didn't, \
                 compare {words}."
            ),
            Act::CompareWords,
        ),
        SecKind::AddressImpostor => (
            format!("Something else answered at {name}'s old address"),
            "Raven didn't introduce you.",
            format!("Nothing. Your message waits until {name} connects, or you meet."),
            Act::Nothing,
        ),
        SecKind::CapabilityDowngrade if severity >= Severity::Alert => (
            format!("{name}'s Raven now offers an older security method than before"),
            "Raven didn't use it. Your earlier messages are not affected.",
            format!(
                "If {name} didn't install an older version, someone may be pretending to be \
                 {name}. Compare {words} first."
            ),
            Act::CompareWords,
        ),
        SecKind::CapabilityDowngrade if severity >= Severity::Suspicious => (
            format!("{name}'s Raven turned off a privacy feature"),
            "Messages still go, but people on the network can see more about them again.",
            format!(
                "Ask {name} whether they changed their Raven. If not, compare {words} with {name}."
            ),
            Act::CompareWords,
        ),
        SecKind::CapabilityDowngrade => (
            format!("{name}'s Raven no longer offers a feature it offered before"),
            "Nothing changed for your messages.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::ContactMalformed => (
            format!("{name}'s Raven sent something Raven could not read"),
            "Raven ignored it.",
            "Nothing. This can happen when one of you runs a much older or newer Raven.".into(),
            Act::Nothing,
        ),
        SecKind::PairinitFlood => (
            format!("{name}'s Raven asked to start new secure connections many times"),
            "Raven answered only within its limits.",
            format!("If it keeps happening, ask {name} whether their Raven works normally."),
            Act::AskThem,
        ),
        SecKind::ResetLoop => (
            format!("Raven and {name}'s Raven keep starting over"),
            "Raven pauses starting over for a while.",
            format!("Ask {name} whether their Raven was reinstalled or restored more than once."),
            Act::AskThem,
        ),
        SecKind::ClockSkew => (
            format!("{name}'s clock and yours differ by more than 5 minutes"),
            "Raven couldn't set up a secure connection.",
            "Check the time and time zone on both computers.".into(),
            Act::CheckClock,
        ),
        SecKind::PairSeedRoot => (
            format!("{name}'s Raven found yours with your pair's fixed key, not the changing one"),
            "Raven let it through. Nothing changed for your messages.",
            "Nothing. This happens when one of you reinstalled Raven; the next connection agrees \
             on a new changing key."
                .into(),
            Act::Nothing,
        ),
        SecKind::CustodianBadObject => (
            format!("Mail that came through {name}'s computer failed Raven's checks"),
            "Raven didn't show it.",
            format!("Tell {name} in person: {name} may not know."),
            Act::AskThem,
        ),
        SecKind::CustodianUnrequested => (
            format!("{name}'s computer handed over mail Raven didn't ask for"),
            "Raven didn't show it.",
            format!("Tell {name} in person: {name} may not know."),
            Act::AskThem,
        ),
        SecKind::CustodianReplay => (
            format!("{name}'s computer handed over mail Raven already had"),
            "Raven didn't show it twice.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::DepositorFlood => (
            format!("{name} asked your computer to hold a lot of mail"),
            "Raven held only what fits its limits.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::DepositorBadObject => (
            format!("Mail {name} left with your computer failed Raven's checks"),
            "Raven didn't keep it.",
            format!("Tell {name} in person: {name}'s Raven may need an update."),
            Act::AskThem,
        ),
        SecKind::RelayNoReceipt => (
            "Messages through a relay often didn't arrive".into(),
            "Raven sent them another way.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::RelayLinkBroken => (
            "A relay broke a connection to a friend".into(),
            "Raven noticed it and tried again.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::LetterBad => {
            (
                match about {
                    About::Carrier(_) => {
                        format!("A sealed letter that came through {name}'s computer failed Raven's checks")
                    }
                    _ => format!("A sealed letter from {name} failed Raven's checks"),
                },
                "Raven didn't show it.",
                format!("Tell {name} in person: {name} may not know."),
                Act::AskThem,
            )
        }
        SecKind::HandoffRefused => (
            format!("{name}'s computer didn't pass mail on"),
            "Raven kept the mail and tries another way.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::KnockFail => (
            "A nearby device failed Raven's greeting".into(),
            "Raven ignored it.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::LocalRollback => (
            "Raven's data on this computer looks older than it should, or was changed outside \
             Raven"
                .into(),
            "Raven noted it.",
            format!(
                "If you restored a backup, this is expected. If not, someone may have had this \
                 computer. Compare {words} with your friends when you meet."
            ),
            Act::CompareWords,
        ),
        SecKind::UnlockFailed => (
            "Someone typed a wrong Raven passphrase on this computer".into(),
            "Raven stayed locked.",
            "If it wasn't you, keep this computer with you and lock it when you leave it.".into(),
            Act::Nothing,
        ),
        SecKind::AdvisoryForged => (
            format!("A security update{passed} failed Raven's checks"),
            "Raven didn't use it.",
            "Nothing. Get Raven's updates only from a source you trust.".into(),
            Act::Nothing,
        ),
        SecKind::AdvisoryRollback => (
            format!("An older security update{passed} arrived"),
            "Raven kept the newer one.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::AdvisoryEquivocation => (
            format!("Two different security updates with the same number{passed} arrived"),
            "Raven used neither.",
            "Get Raven's updates only from a source you trust, and tell your friends.".into(),
            Act::Nothing,
        ),
        SecKind::BundleForged => (
            format!("A Raven release{passed} failed Raven's checks"),
            "Raven didn't install it.",
            "Nothing. Get Raven only from a source you trust.".into(),
            Act::Nothing,
        ),
        SecKind::UpdateUnlogged => (
            format!("A security update{passed} was not in Raven's public update record"),
            "Raven didn't use it.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::BundleDowngrade => (
            format!("An older Raven release{passed} was offered"),
            "Raven kept this version.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::LogSplitView => (
            "Raven's public update record looks different from what your friends see".into(),
            "Raven stopped taking new updates until it matches again.",
            "Get Raven's updates only from a source you trust, and tell your friends.".into(),
            Act::Nothing,
        ),
        SecKind::AdvisoryApplied => (
            format!("Raven applied a security update{passed}"),
            "Raven changed what it allows, as the update said.",
            "Nothing.".into(),
            Act::Nothing,
        ),
        SecKind::UpdateFlood => (
            format!("{name}'s Raven offered many security updates"),
            "Raven took only what fits its limits.",
            "Nothing.".into(),
            Act::Nothing,
        ),
    };
    let mut did = did.to_owned();
    let mut act = act;
    if let Some(sentence) = action.and_then(|code| action_text(code, about)) {
        did.push(' ');
        did.push_str(&sentence);
        // A parked mailbox can be used again before its day is over.
        if code_is(action, ACTION_CUSTODIAN_PARKED) {
            act = Act::MailboxRetry;
        }
    }
    let todo = if act == Act::MailboxRetry {
        format!("{todo} Raven tries {name}'s mailbox again after a day; you can also do it now.")
    } else {
        todo
    };
    NoticeText {
        headline: sentence(headline),
        did,
        todo: sentence(todo),
        act,
    }
}

/// `text` with its first letter upper case (a name like "a relay" may start
/// it).
fn sentence(text: String) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) if first.is_lowercase() => first.to_uppercase().chain(chars).collect(),
        _ => text,
    }
}

/// raven-node's fixed action codes (`raven-node/src/security.rs`, design A
/// R2-R8), as the ledger stores them.
const ACTION_REKEY_REQUESTED: &str = "REKEY_REQUESTED";
const ACTION_PREKEY_ROTATED: &str = "PREKEY_ROTATED";
const ACTION_PATH_DEMOTED: &str = "PATH_DEMOTED";
const ACTION_ADDRESS_FORGOTTEN: &str = "ADDRESS_FORGOTTEN";
const ACTION_CUSTODIAN_PARKED: &str = "CUSTODIAN_PARKED";
const ACTION_DEPOSITS_THROTTLED: &str = "DEPOSITS_THROTTLED";
const ACTION_RELAY_DEMOTED: &str = "RELAY_DEMOTED";

fn code_is(action: Option<&str>, code: &str) -> bool {
    action == Some(code)
}

/// What Raven did, from the alert's fixed action code (one sentence that
/// follows the kind's own); `None` for a code this build does not know.
fn action_text(code: &str, about: About<'_>) -> Option<String> {
    let name = about.name();
    Some(match code {
        ACTION_REKEY_REQUESTED if about == About::ThisComputer => {
            "It set up new secure connections with your friends.".into()
        }
        ACTION_REKEY_REQUESTED => {
            format!("It set up a new secure connection with {name} by itself.")
        }
        ACTION_PREKEY_ROTATED => "It made new keys for new conversations.".into(),
        ACTION_PATH_DEMOTED => format!("It tries {name}'s other routes first for a while."),
        ACTION_ADDRESS_FORGOTTEN => "It forgot that address.".into(),
        ACTION_CUSTODIAN_PARKED => format!("It stopped using {name} as a mailbox for a day."),
        ACTION_DEPOSITS_THROTTLED => {
            format!("It takes no mail from {name} to hold for others for an hour.")
        }
        ACTION_RELAY_DEMOTED => "It uses that relay last for an hour.".into(),
        _ => return None,
    })
}

/// The CLI command for `act` (none for an act without one). `verify` is the
/// `raven contact verify` argument that names the contact
/// (`--petname Sara`, `@sara`); without one the command says `NAME`.
pub(crate) fn cli_hint(act: Act, verify: Option<&str>) -> Option<String> {
    match act {
        Act::CompareWords => Some(format!("raven contact verify {}", verify.unwrap_or("NAME"))),
        Act::MailboxRetry => {
            Some("raven outbox retry ID   (any waiting message; `raven outbox` lists them)".into())
        }
        Act::StopListening => {
            Some("raven lan off   (or meeting mode: raven lan on --for 1h)".into())
        }
        Act::OtherNetwork | Act::CheckClock | Act::AskThem | Act::Nothing => None,
    }
}

/// How serious a notice is, in one word (`raven security explain`, `--json`).
pub(crate) fn severity_word(severity: Severity) -> &'static str {
    match severity {
        Severity::Notice => "notice",
        Severity::Suspicious => "warning",
        Severity::Alert => "alert",
    }
}

/// When something happened, coarse and in this computer's local time:
/// "early this morning", "this morning", "this afternoon", "this evening",
/// "tonight", "yesterday", "on Tue", "on 14 Oct". Where the local offset of
/// either instant is unknown (`off_at`, `off_now`: seconds east of UTC), how
/// long ago ("about 3 h ago"), never a time on another clock.
pub(crate) fn when_text_with(
    at_ms: u64,
    now_ms: u64,
    off_at: Option<i32>,
    off_now: Option<i32>,
) -> String {
    let at = local_time::deadline_with_offsets(at_ms, now_ms, off_at, off_now);
    if !at.local {
        return local_time::ago_text(at_ms, now_ms);
    }
    let hour: u32 = at.hh_mm[..2].parse().unwrap_or(12);
    match at.days_ahead {
        0 => match hour {
            0..=4 => "early this morning",
            5..=11 => "this morning",
            12..=16 => "this afternoon",
            17..=21 => "this evening",
            _ => "tonight",
        }
        .into(),
        // A clock set back: never in the future.
        1.. => "just now".into(),
        -1 => "yesterday".into(),
        -6..=-2 => format!("on {}", at.weekday),
        _ => format!("on {} {}", at.day, at.month),
    }
}

/// [`when_text_with`] with this computer's offsets.
pub(crate) fn when_text(at_ms: u64, now_ms: u64) -> String {
    when_text_with(
        at_ms,
        now_ms,
        local_time::utc_offset_s(at_ms),
        local_time::utc_offset_s(now_ms),
    )
}

/// How often and when, after a headline: "this morning", or "4 times,
/// latest this morning".
pub(crate) fn count_when(n: u64, latest: &str) -> String {
    if n > 1 {
        format!("{n} times, latest {latest}")
    } else {
        latest.to_owned()
    }
}

/// "1 open alert", "3 open alerts".
pub(crate) fn open_alerts(n: usize) -> String {
    format!("{n} open alert{}", if n == 1 { "" } else { "s" })
}

/// `raven doctor`'s security row.
pub(crate) fn doctor_row(n: usize) -> String {
    format!("{} (raven security)", open_alerts(n))
}

/// The counts line of `raven status` (IPC `Status.security`).
pub(crate) fn strangers_line(n: u32) -> String {
    format!("Strangers refused in the last hour: {n} (they learned nothing about you)")
}

/// `raven security`'s line for the notices it only counts.
pub(crate) fn notices_line(n: usize) -> String {
    if n == 1 {
        "Also 1 smaller notice, only counted.".into()
    } else {
        format!("Also {n} smaller notices, only counted.")
    }
}

/// The last line of `raven security`'s list.
pub(crate) const LIST_FOOTER: &str = "More about one: raven security explain N. Done with one: \
     raven security resolve N. Delete them all: raven security clear.";

/// `raven security explain|resolve N` past the end of the list.
pub(crate) fn no_such_notice(n: usize) -> String {
    format!("There is no security notice {n}: `raven security` lists them.")
}

/// After `raven security resolve N`.
pub(crate) fn resolved(headline: &str) -> String {
    format!("Resolved: {headline}. What Raven did about it stays as it is.")
}

/// After a security words match in `raven contact verify` resolved `n`
/// notices about `name`.
pub(crate) fn resolved_by_verify(name: &str, n: usize) -> String {
    if n == 1 {
        format!("Resolved 1 security notice about {name}.")
    } else {
        format!("Resolved {n} security notices about {name}.")
    }
}

/// The one line `raven send` prints when the contact has an open alert: its
/// headline and when, and the send goes ahead.
pub(crate) fn send_note(headline: &str, when: &str, name: &str) -> String {
    format!(
        "Note: {headline} ({when}). Your message is still protected and is sent anyway. \
         Compare {WORDS} with {name} when you can (raven security)."
    )
}

// ── The older security method (design A R9, `raven contact verify`) ──────

/// Why `raven contact verify` asks about the older method.
pub(crate) fn floor_intro(name: &str) -> String {
    format!(
        "{name}'s Raven offered an older security method than before. That is expected when \
         {name} installed an older version of Raven; if not, ask {name} before you accept it."
    )
}

/// The old code matched, not the words: the words are needed to accept.
pub(crate) fn floor_words_needed(name: &str) -> String {
    format!(
        "To accept the older method for {name}, compare {WORDS} with {name} (the old code is \
         not enough for this)."
    )
}

/// No terminal to ask on.
pub(crate) fn floor_at_a_terminal(name: &str) -> String {
    format!("To accept the older method for {name}, run raven contact verify at a terminal.")
}

/// The question (the typed word is `accept`).
pub(crate) fn floor_question(name: &str) -> String {
    format!("Accept the older method for {name}? Type accept (Enter keeps the newer one): ")
}

/// Not accepted.
pub(crate) fn floor_kept(name: &str) -> String {
    format!("Kept: Raven still expects the newer method from {name}.")
}

/// Accepted (after the word "Accepted").
pub(crate) fn floor_accepted(name: &str) -> String {
    format!(
        "Raven takes the older method from {name} again, and expects the newer one once \
         {name}'s Raven offers it."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEVERITIES: [Severity; 3] = [Severity::Notice, Severity::Suspicious, Severity::Alert];
    const ACTIONS: [Option<&str>; 9] = [
        None,
        Some(ACTION_REKEY_REQUESTED),
        Some(ACTION_PREKEY_ROTATED),
        Some(ACTION_PATH_DEMOTED),
        Some(ACTION_ADDRESS_FORGOTTEN),
        Some(ACTION_CUSTODIAN_PARKED),
        Some(ACTION_DEPOSITS_THROTTLED),
        Some(ACTION_RELAY_DEMOTED),
        Some("SOMETHING_NEWER"),
    ];

    fn abouts() -> [About<'static>; 7] {
        [
            About::Contact("Sara"),
            About::Carrier("Rena"),
            About::Relay,
            About::ThisComputer,
            About::Update(Some("Sara")),
            About::Update(None),
            About::Unknown,
        ]
    }

    /// Every text this table can make.
    fn every_text() -> Vec<(SecKind, NoticeText)> {
        let mut all = Vec::new();
        for kind in SecKind::ALL {
            for severity in SEVERITIES {
                for about in abouts() {
                    for action in ACTIONS {
                        all.push((kind, notice(kind, severity, about, action)));
                    }
                }
            }
        }
        all
    }

    /// The rules of design A's UX: three parts, each a plain sentence; every
    /// one ends with what to do; a check of a key is "compare security
    /// words"; English, nothing but printable ASCII.
    #[test]
    fn every_notice_says_what_happened_what_raven_did_and_what_to_do() {
        for (kind, t) in every_text() {
            assert!(
                !t.headline.is_empty() && !t.headline.ends_with('.'),
                "{kind:?} {t:?}"
            );
            assert!(
                t.headline.starts_with(|c: char| c.is_ascii_uppercase()),
                "{t:?}"
            );
            for part in [&t.did, &t.todo] {
                assert!(part.ends_with('.'), "{kind:?}: {part:?}");
                assert!(
                    part.starts_with(|c: char| c.is_ascii_uppercase()),
                    "{part:?}"
                );
            }
            for part in [&t.headline, &t.did, &t.todo] {
                assert!(
                    part.bytes().all(|b| (0x20..0x7f).contains(&b)),
                    "{kind:?}: not plain ASCII: {part:?}"
                );
                assert!(!part.contains("  "), "{part:?}");
                let lower = part.to_lowercase();
                for never in [
                    "security code",
                    "attack",
                    "hacker",
                    "blocked sara",
                    "{",
                    "you are being",
                ] {
                    assert!(!lower.contains(never), "{kind:?}: {never:?} in {part:?}");
                }
            }
            let todo = t.todo.to_lowercase();
            if t.act == Act::CompareWords {
                assert!(todo.contains("compare security words"), "{kind:?}: {t:?}");
            }
            if todo.contains("compare") {
                assert!(todo.contains("compare security words"), "{t:?}");
            }
        }
    }

    /// No text carries a number that could be an address, a port, a key or
    /// a message id: the only digits are the clock's "5 minutes" and the
    /// counts the caller adds.
    #[test]
    fn no_text_holds_an_address_a_key_or_an_id() {
        for (kind, t) in every_text() {
            for part in [&t.headline, &t.did, &t.todo] {
                let digits: String = part.chars().filter(char::is_ascii_digit).collect();
                assert!(
                    digits.is_empty() || (kind == SecKind::ClockSkew && digits == "5"),
                    "{kind:?}: {part:?}"
                );
                assert!(!part.contains("::") && !part.contains("rvn1"), "{part:?}");
            }
        }
        for line in [
            strangers_line(37),
            doctor_row(2),
            send_note(
                "Messages from Sara failed Raven's security check",
                "today",
                "Sara",
            ),
        ] {
            assert!(!line.contains("192.") && !line.contains("rvn1"), "{line}");
        }
    }

    /// Who the text is about is named where the kind is about someone, and
    /// a friend is never called an attacker: "someone" stands only where
    /// nobody is known.
    #[test]
    fn the_contact_is_named_in_every_text_about_them() {
        let network_kinds = [
            SecKind::HandshakeFail,
            SecKind::PreauthMalformed,
            SecKind::StrangerRefused,
            SecKind::BlockedRefused,
            SecKind::UnverifiedRemote,
            SecKind::PreauthFlood,
            SecKind::P2pGateRefused,
            SecKind::BeaconReplay,
            SecKind::BeaconFlood,
            SecKind::KnockReplay,
            SecKind::RelayNoReceipt,
            SecKind::RelayLinkBroken,
            SecKind::KnockFail,
            SecKind::LocalRollback,
            SecKind::UnlockFailed,
            SecKind::AdvisoryForged,
            SecKind::AdvisoryRollback,
            SecKind::AdvisoryEquivocation,
            SecKind::BundleForged,
            SecKind::UpdateUnlogged,
            SecKind::BundleDowngrade,
            SecKind::LogSplitView,
            SecKind::AdvisoryApplied,
        ];
        for kind in SecKind::ALL {
            if network_kinds.contains(&kind) {
                continue;
            }
            for severity in SEVERITIES {
                let t = notice(kind, severity, About::Contact("Sara"), None);
                assert!(t.headline.contains("Sara"), "{kind:?}: {t:?}");
            }
        }
        // An update names who passed it on, and only then.
        let t = notice(
            SecKind::AdvisoryForged,
            Severity::Suspicious,
            About::Update(Some("Sara")),
            None,
        );
        assert_eq!(
            t.headline,
            "A security update passed on by Sara failed Raven's checks"
        );
        let t = notice(
            SecKind::AdvisoryForged,
            Severity::Suspicious,
            About::Update(None),
            None,
        );
        assert_eq!(t.headline, "A security update failed Raven's checks");
    }

    fn text(
        kind: SecKind,
        severity: Severity,
        about: About<'_>,
        action: Option<&str>,
    ) -> [String; 3] {
        let t = notice(kind, severity, about, action);
        [t.headline, t.did, t.todo]
    }

    /// The copy table of design A's UX, as the person reads it (the words
    /// in place of the old codes).
    #[test]
    fn snapshots_of_the_design_copy() {
        let sara = About::Contact("Sara");
        assert_eq!(
            text(
                SecKind::ObjectAuthFail,
                Severity::Alert,
                sara,
                Some(ACTION_REKEY_REQUESTED)
            ),
            [
                "Messages from Sara failed Raven's security check",
                "Raven didn't show them. It set up a new secure connection with Sara by itself.",
                "Ask Sara, in person or by phone, whether they reinstalled Raven or restored \
                 their computer. Then compare security words. Raven never blocks Sara by itself.",
            ]
        );
        assert_eq!(
            text(SecKind::ObjectAuthFail, Severity::Suspicious, sara, None)[1],
            "Raven didn't show them."
        );
        assert_eq!(
            text(SecKind::BindingMismatch, Severity::Alert, sara, None),
            [
                "Something claiming to be Sara used a key Raven doesn't accept",
                "Raven refused it. Nothing was shown or sent.",
                "Compare security words with Sara before you continue. If Sara removed an old \
                 computer, this is expected.",
            ]
        );
        assert_eq!(
            text(SecKind::RevokedDeviceUsed, Severity::Alert, sara, None),
            text(SecKind::BindingMismatch, Severity::Alert, sara, None)
        );
        assert_eq!(
            text(SecKind::KeyChangeAttempt, Severity::Alert, sara, None),
            [
                "An invite had a different key from the Sara you verified",
                "Raven kept the old key.",
                "If Sara really has a new key (a new computer or a reinstall), compare security \
                 words with Sara before you add it. If not, ignore that invite.",
            ]
        );
        assert_eq!(
            text(SecKind::CapabilityDowngrade, Severity::Alert, sara, None),
            [
                "Sara's Raven now offers an older security method than before",
                "Raven didn't use it. Your earlier messages are not affected.",
                "If Sara didn't install an older version, someone may be pretending to be Sara. \
                 Compare security words first.",
            ]
        );
        assert_eq!(
            text(
                SecKind::CapabilityDowngrade,
                Severity::Suspicious,
                sara,
                None
            ),
            [
                "Sara's Raven turned off a privacy feature",
                "Messages still go, but people on the network can see more about them again.",
                "Ask Sara whether they changed their Raven. If not, compare security words with \
                 Sara.",
            ]
        );
        assert_eq!(
            text(
                SecKind::LinkTagFail,
                Severity::Alert,
                sara,
                Some(ACTION_PATH_DEMOTED)
            ),
            [
                "Someone on this network keeps changing data between you and Sara",
                "Raven noticed each time and threw it away. Nothing was read. It tries Sara's \
                 other routes first for a while.",
                "Use another network or a hotspot you control.",
            ]
        );
        assert_eq!(
            text(
                SecKind::PreauthFlood,
                Severity::Suspicious,
                About::Unknown,
                None
            ),
            [
                "Unknown computers on this network tried to connect many times",
                "Raven refused all of them. They learned nothing about you.",
                "If you didn't expect this, stop listening when you don't need it, or use \
                 meeting mode.",
            ]
        );
        assert_eq!(
            text(
                SecKind::AddressImpostor,
                Severity::Suspicious,
                sara,
                Some(ACTION_ADDRESS_FORGOTTEN)
            ),
            [
                "Something else answered at Sara's old address",
                "Raven didn't introduce you. It forgot that address.",
                "Nothing. Your message waits until Sara connects, or you meet.",
            ]
        );
        let rena = About::Carrier("Rena");
        let parked = notice(
            SecKind::CustodianBadObject,
            Severity::Alert,
            rena,
            Some(ACTION_CUSTODIAN_PARKED),
        );
        assert_eq!(
            [&parked.headline, &parked.did, &parked.todo],
            [
                "Mail that came through Rena's computer failed Raven's checks",
                "Raven didn't show it. It stopped using Rena as a mailbox for a day.",
                "Tell Rena in person: Rena may not know. Raven tries Rena's mailbox again after \
                 a day; you can also do it now.",
            ]
        );
        assert_eq!(parked.act, Act::MailboxRetry);
        assert_eq!(
            text(
                SecKind::LocalRollback,
                Severity::Alert,
                About::ThisComputer,
                Some(ACTION_PREKEY_ROTATED)
            ),
            [
                "Raven's data on this computer looks older than it should, or was changed \
                 outside Raven",
                "Raven noted it. It made new keys for new conversations.",
                "If you restored a backup, this is expected. If not, someone may have had this \
                 computer. Compare security words with your friends when you meet.",
            ]
        );
        assert_eq!(
            text(SecKind::ClockSkew, Severity::Notice, sara, None),
            [
                "Sara's clock and yours differ by more than 5 minutes",
                "Raven couldn't set up a secure connection.",
                "Check the time and time zone on both computers.",
            ]
        );
        assert_eq!(
            send_note(
                "Messages from Sara failed Raven's security check",
                "this morning",
                "Sara"
            ),
            "Note: Messages from Sara failed Raven's security check (this morning). Your message \
             is still protected and is sent anyway. Compare security words with Sara when you \
             can (raven security)."
        );
    }

    #[test]
    fn the_cli_names_the_command_for_each_act() {
        assert_eq!(
            cli_hint(Act::CompareWords, Some("--petname Sara")).as_deref(),
            Some("raven contact verify --petname Sara")
        );
        assert_eq!(
            cli_hint(Act::CompareWords, None).as_deref(),
            Some("raven contact verify NAME")
        );
        assert!(cli_hint(Act::MailboxRetry, None)
            .unwrap()
            .starts_with("raven outbox retry"));
        assert!(cli_hint(Act::StopListening, None)
            .unwrap()
            .starts_with("raven lan off"));
        for act in [
            Act::OtherNetwork,
            Act::CheckClock,
            Act::AskThem,
            Act::Nothing,
        ] {
            assert_eq!(cli_hint(act, None), None, "{act:?}");
        }
    }

    /// Coarse local time: the part of today, yesterday, the weekday within
    /// a week, else the date; without the offsets, how long ago.
    #[test]
    fn when_is_coarse_and_local() {
        // 2026-10-20 (a Tuesday) 00:00 UTC.
        const DAY: u64 = 86_400_000;
        const HOUR: u64 = 3_600_000;
        let tue = 20_746 * DAY;
        let tehran = Some(3 * 3600 + 1800);
        let now = tue + 15 * HOUR; // 18:30 in Tehran
        let at = |ms: u64| when_text_with(ms, now, tehran, tehran);
        assert_eq!(at(tue), "early this morning"); // 03:30
        assert_eq!(at(tue + 5 * HOUR), "this morning"); // 08:30
        assert_eq!(at(tue + 9 * HOUR), "this afternoon"); // 12:30
        assert_eq!(at(tue + 14 * HOUR), "this evening"); // 17:30
        assert_eq!(at(tue - 4 * HOUR), "yesterday"); // Mon 23:30
        assert_eq!(at(tue - 3 * DAY), "on Sat");
        assert_eq!(at(tue - 9 * DAY), "on 11 Oct");
        assert_eq!(at(now + DAY), "just now");
        let late = tue + 20 * HOUR; // 23:30 in Tehran
        assert_eq!(when_text_with(late, late, tehran, tehran), "tonight");
        assert_eq!(when_text_with(tue, now, None, tehran), "about 15 h ago");
        assert_eq!(count_when(1, "this morning"), "this morning");
        assert_eq!(
            count_when(4, "this morning"),
            "4 times, latest this morning"
        );
    }

    /// Whom each kind is about in the snapshot: the subject the registry
    /// gives it.
    fn natural_about(kind: SecKind) -> About<'static> {
        match kind.code() {
            1 | 20..=39 | 78 => About::Contact("Sara"),
            40..=44 | 47 | 48 => About::Carrier("Rena"),
            45 | 46 => About::Relay,
            60..=69 => About::ThisComputer,
            70..=77 => About::Update(Some("Sara")),
            _ => About::Unknown,
        }
    }

    /// Every notice text, kind by kind (with the severities a text is for
    /// when they differ), as `security_text/notices.txt` keeps it.
    fn snapshot() -> String {
        let mut out = String::new();
        for kind in SecKind::ALL {
            let mut groups: Vec<(Vec<&str>, NoticeText)> = Vec::new();
            for severity in [Severity::Alert, Severity::Suspicious, Severity::Notice] {
                let t = notice(kind, severity, natural_about(kind), None);
                match groups.last_mut() {
                    Some((words, last)) if *last == t => words.push(severity_word(severity)),
                    _ => groups.push((vec![severity_word(severity)], t)),
                }
            }
            let several = groups.len() > 1;
            for (words, t) in groups {
                let at = if several {
                    format!(", {}", words.join(" and "))
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "{} ({}){at}\n  {}\n  {}\n  {}\n  [{}]\n",
                    kind.name(),
                    kind.code(),
                    t.headline,
                    t.did,
                    t.todo,
                    t.act.as_str()
                ));
            }
        }
        out
    }

    /// A snapshot of each notice's text: a change to any of them shows here
    /// and is reviewed (the file is the new output when it is right).
    #[test]
    fn snapshot_of_every_notice_text() {
        let now = snapshot();
        let kept = include_str!("security_text/notices.txt");
        assert!(
            now == kept,
            "the notice texts changed; if the new ones are right, they are \
             security_text/notices.txt:\n{now}"
        );
    }

    #[test]
    fn counts_read_as_words() {
        assert_eq!(doctor_row(1), "1 open alert (raven security)");
        assert_eq!(doctor_row(3), "3 open alerts (raven security)");
        assert_eq!(notices_line(1), "Also 1 smaller notice, only counted.");
        assert_eq!(notices_line(2), "Also 2 smaller notices, only counted.");
        assert_eq!(
            resolved_by_verify("Sara", 1),
            "Resolved 1 security notice about Sara."
        );
        assert_eq!(
            resolved_by_verify("Sara", 2),
            "Resolved 2 security notices about Sara."
        );
        assert!(NOT_IN_THIS_VERSION.starts_with("Security notices are not part of this version"));
    }
}
