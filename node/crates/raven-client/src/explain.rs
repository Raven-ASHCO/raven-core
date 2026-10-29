//! Plain words for what goes wrong: a send's outcome, a message raven-node
//! holds, the identity store and the background program's start.
//!
//! Adapted from the terminal app's `tui/errors.rs` (branch
//! feature/terminal-app): the same reading of the CLI's texts (its outcome
//! prefixes and ext.rs's `classify_cause`, through the engine bridge), with
//! the terminal's keys ("Press N") replaced by the desktop's places
//! ("Open Network"). The sentences never quote the technical text, so an OS
//! message or a friend's name can't change what one says.

use ash_engine::engine::{self as bridge, Cause};

/// One failure in plain words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plain {
    /// What happened.
    pub headline: String,
    /// What the user can do about it, or empty.
    pub next: String,
    /// The text it was read from (for Details).
    pub technical: String,
}

/// Where a send stands, from the start of its outcome text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeKind {
    /// Queued on this computer. `background`: raven-node keeps trying it.
    Waiting { background: bool },
    /// Written to the friend's computer, which hasn't confirmed it.
    Sent,
    /// Nothing is queued.
    NotSent,
}

/// Where an outcome line keeps the raw failure (ext.rs).
const TECHNICAL: &str = "(technical: ";
const HOLD_MARKS: &[&str] = &["internet_direct_hold", "p2p_hold"];
const UNVERIFIED_MARK: &str = "contact_not_verified";
const REMOTE_LAN_MARK: &str = "reached only at addresses on your local network";
const RESERVED_MARK: &str = "the reserved prefix";
const EARLIER_MARK: &str = "not sent: an earlier message";
const QUEUE_FULL_MARK: &str = "are already waiting until";
const STAGE_FULL_MARK: &str = "contacts who are offline";
const PEER_RESET_UNREACHABLE: &str = "PEER_RESET_UNREACHABLE";
const NO_LAN_DIAL_MARK: &str = "has no reachable lan_dial";
/// ext.rs's NOT SENT when Raven has no secure connection with the friend and
/// the dial couldn't set one up.
const MEET_FIRST_MARK: &str = "a first message needs";
/// ext.rs's NOT SENT when the secure connection with the friend has ended
/// and a new one needs a meeting (the terminal app's `SESSION_ENDED_MARK`).
const SESSION_ENDED_MARK: &str = "a new one needs you both on the same network";
/// raven-core's keystore_vault.rs, when a program without a terminal needs
/// the vault passphrase.
pub const PASSPHRASE_MARK: &str = "cannot ask for the passphrase";

/// Headline and next step, with `{who}` / `{whose}` for the friend's name.
type Words = (&'static str, &'static str);

const OPEN_DETAILS: &str = "Open Details.";
const OPEN_NETWORK: &str = "Open Network to see why.";

/// The words for each of ext.rs's causes.
fn cause_words(cause: Cause) -> Words {
    match cause {
        Cause::NotListening => (
            "{whose} computer is there, but Raven isn't receiving right now (it may be locked or closed).",
            "The message waits and goes by itself.",
        ),
        Cause::NotReachable => (
            "{whose} computer couldn't be reached (it may be off, asleep, or on another network).",
            "",
        ),
        Cause::LocalNetworkRefused => (
            "This Mac didn't let Raven connect to {who} on your network, so {who} was never asked.",
            "Turn on Raven in System Settings > Privacy & Security > Local Network, then quit and open Raven again.",
        ),
        Cause::NameNotFound => (
            "Raven couldn't find {whose} computer on this network.",
            "When you're both on the same network it goes by itself. If {whose} address changed, set it again.",
        ),
        Cause::ClosedEarly => ("The connection to {who} dropped.", "Try again."),
        Cause::PeerRefused => (
            "{whose} Raven didn't accept it. {who} may not have added you yet.",
            "Send {who} your invite.",
        ),
        Cause::WrongIdentity => (
            "The computer at that address isn't {whose} Raven.",
            "Ask {who} for a new invite.",
        ),
        Cause::NoAddress | Cause::BadAddress => (
            "Raven doesn't have a usable address for {who}.",
            "Set {whose} address, or add {whose} invite again.",
        ),
        Cause::ServiceDown | Cause::ServiceStart => (
            "Raven's background program isn't running on this computer.",
            OPEN_NETWORK,
        ),
        Cause::ServiceSlow => (
            "Raven's background program is still starting.",
            "On a Mac, look for a password window and choose Always Allow.",
        ),
        Cause::KeychainDenied => (
            "Raven wasn't allowed to read its keys from the system keychain.",
            "Allow access when asked, then try again.",
        ),
        Cause::HistoryLocked => (
            "Another Raven program is using your messages right now.",
            "Wait a moment, then try again.",
        ),
        Cause::HistoryUnreadable => ("Your message history can't be read.", OPEN_DETAILS),
        Cause::TooLarge => ("This message is too long.", "Shorten it."),
        Cause::BadCharacters => ("This message has characters Raven can't send.", ""),
        Cause::Blocked => ("You blocked {who}.", "Unblock {who} first."),
        Cause::SendInProgress => (
            "An earlier message to {who} is still being sent.",
            "Wait for it.",
        ),
        Cause::EmptyMessage => ("This message is empty.", "Type some text first."),
        Cause::PinStoreUnreadable => (
            "Raven can't read its file of your friends' keys (lan_noise_pins.json), so it can't connect to anyone.",
            "Fix that file's owner or permissions in Raven's data folder, or move it aside.",
        ),
        // `raven lan off`: nothing is dialled on the local network.
        Cause::LanOff => (
            "LAN is off on this computer, so Raven doesn't connect to {who} on your network.",
            "Turn it back on with: raven lan on.",
        ),
        Cause::Other => ("Raven couldn't send this message.", OPEN_DETAILS),
    }
}

const GATE_HOLD: Words = (
    "{who} can only be reached over the internet, which isn't in this version yet.",
    "Ask {who} for an invite with a local-network address.",
);
const UNVERIFIED_CARRIER: Words = (
    "{who} is only reachable over the internet, which needs {who} verified first.",
    "Check the security words with {who}.",
);
const UNVERIFIED_REMOTE_LAN: Words = (
    "{whose} address isn't on your local network, and {who} isn't verified yet.",
    "Check the security words with {who}.",
);
const UNCONFIRMED: Words = (
    "It left this computer, but {whose} Raven hasn't confirmed it.",
    "Wait. Don't send it again.",
);

/// raven-node's outbox codes (`last_error_code`), as the terminal app words
/// them (raven-node/src/outbox.rs `mod code`, then raven-core's
/// `CONTACT_NOT_VERIFIED`).
fn outbox_code_words(code: &str) -> Words {
    match code {
        "NOT_A_CONTACT" => (
            "{who} isn't in your friends list anymore.",
            "Add {who} again to send it.",
        ),
        "CONTACT_BLOCKED" => cause_words(Cause::Blocked),
        "CONTACTS_UNREADABLE" => ("Your friends list can't be read.", OPEN_DETAILS),
        "NO_ROUTE" => cause_words(Cause::NoAddress),
        "DEFERRED" => ("Other messages to {who} went first. This one goes next.", ""),
        "SEND_IN_PROGRESS" => cause_words(Cause::SendInProgress),
        "LOCK" => (
            "Raven couldn't get ready to send to {who}.",
            "It tries again by itself.",
        ),
        "LOCAL_DEVICE" => ("This computer isn't set up to send yet.", OPEN_DETAILS),
        "LOCAL_DEVICE_REVOKED" => (
            "This computer is no longer allowed to send as you.",
            OPEN_DETAILS,
        ),
        "PEER_REVOKED" => (
            "Raven stopped: {who} retired the device this message was for.",
            "Ask {who} for a new invite.",
        ),
        "NO_PEER_CERT" => (
            "Raven is still setting up a secure connection with {who}.",
            "It tries again by itself.",
        ),
        "NO_LOCAL_BODY" => (
            "The text of this message isn't on this computer anymore.",
            OPEN_DETAILS,
        ),
        "HISTORY" => (
            "Raven couldn't record this message in your history.",
            "It tries again by itself.",
        ),
        "CLOCK" => (
            "This computer's clock looks wrong.",
            "Check the date and time in your system settings.",
        ),
        "STORE" => (
            "Raven couldn't read its list of waiting messages.",
            "It tries again by itself.",
        ),
        "NO_ACK_YET" => UNCONFIRMED,
        "STAGE" => (
            "Raven couldn't keep this message ready to send, so it stopped trying.",
            "Send it again if {who} didn't get it.",
        ),
        "SUPERSEDED" => (
            "{whose} Raven can't accept this message anymore: it was sealed for an older connection.",
            "Send it again if {who} didn't get it.",
        ),
        "EXPIRED" => (
            "Raven stopped trying: this message waited too long.",
            "Send it again if {who} still needs it.",
        ),
        "INTERNET_HOLD" | "P2P_HOLD" => GATE_HOLD,
        "P2P_NOT_RUNNING" => (
            "Raven's peer-to-peer connection isn't running.",
            OPEN_NETWORK,
        ),
        "LINK_NOT_ACCEPTED" | "PEER_REFUSED" => cause_words(Cause::PeerRefused),
        "WRONG_IDENTITY" => cause_words(Cause::WrongIdentity),
        "NOT_LISTENING" => cause_words(Cause::NotListening),
        "NOT_REACHABLE" => cause_words(Cause::NotReachable),
        "CLOSED_EARLY" => cause_words(Cause::ClosedEarly),
        "PIN_STORE_UNREADABLE" => cause_words(Cause::PinStoreUnreadable),
        "DIAL_FAILED" => ("Raven couldn't connect to {who}.", "It tries again by itself."),
        "PEER_RESET" => (
            "{whose} Raven lost your secure connection. Raven is sending this again over a new one.",
            "",
        ),
        "PEER_RESET_NO_BODY" => (
            "{whose} Raven lost your secure connection, and this message can't be sent again from here.",
            "Send it again if {who} didn't get it.",
        ),
        "RESEAL_CAP" => (
            "Raven stopped trying: the connection with {who} was reset too many times.",
            "Send it again if {who} didn't get it.",
        ),
        "IN_CUSTODY" => (
            "A friend's computer is holding a sealed copy for {who}.",
            "Raven keeps trying {who} directly too.",
        ),
        // Friend custody status: why no friend holds a copy.
        "NO_SHARED_CUSTODIAN" => (
            "{who} collects mail only from friends you haven't verified, so no friend can hold this for {who}.",
            "Raven keeps trying {who} directly.",
        ),
        "CUSTODIAN_NOT_OFFERING" => (
            "The friend {who} collects mail from doesn't hold messages for you, or not over the internet.",
            "Raven keeps trying {who} directly.",
        ),
        "MAILBOX_OFF" => (
            "A friend could hold this for {who}, but friend mailboxes are off.",
            "To use them, run `raven custody use on`.",
        ),
        // Sealed letters (Phase 5): why no friend holds the letter yet (the
        // terminal app's words, tui/errors.rs).
        "WAITING_FOR_CARRIER" => (
            "Waiting for a friend to carry it to {who}.",
            "It tries again by itself; it can wait up to 7 days.",
        ),
        "CARRIER_FULL" => (
            "Waiting for a friend to carry it: your friend's Raven is full.",
            "It tries again by itself; it can wait up to 7 days.",
        ),
        "NO_SHARED_CARRIER" => (
            "No friend can carry it: you and {who} don't share a mail friend.",
            "It goes when you meet.",
        ),
        "CONTACT_NOT_VERIFIED" => UNVERIFIED_CARRIER,
        _ => ("Raven is holding this message for now.", OPEN_DETAILS),
    }
}

/// A send's outcome text (the `Err` of a send) in plain words, `who` the
/// friend's name. The start of the text says where the message stands; the
/// raw failure it keeps says why.
pub fn explain_send(outcome: &str, who: &str) -> (OutcomeKind, Plain) {
    let text = outcome.trim();
    let head = text.rfind(TECHNICAL).map_or(text, |at| &text[..at]);
    let kind = if text.starts_with(bridge::QUEUED_PREFIX) {
        OutcomeKind::Waiting {
            background: head.contains(bridge::BACKGROUND_RETRY),
        }
    } else if text.starts_with(bridge::UNCONFIRMED_PREFIX) {
        OutcomeKind::Sent
    } else {
        OutcomeKind::NotSent
    };
    let technical = technical_part(text);
    let words = match kind {
        // Whatever cut the confirmation short, the message is there: never
        // advice that ends in sending it again.
        OutcomeKind::Sent => UNCONFIRMED,
        _ => send_words(text, technical),
    };
    (kind, plain(words, who, technical))
}

/// Whether a NOT SENT outcome says it can go only once the two of you meet:
/// no secure connection with the friend, and their computer couldn't be
/// reached to set one up.
pub fn needs_meeting(outcome: &str) -> bool {
    let text = outcome.trim();
    let head = text.rfind(TECHNICAL).map_or(text, |at| &text[..at]);
    let head = head.to_ascii_lowercase();
    (head.contains(MEET_FIRST_MARK) || head.contains(SESSION_ENDED_MARK))
        && matches!(
            bridge::classify_cause(technical_part(text)),
            Cause::NotReachable | Cause::NameNotFound
        )
}

/// A failure where the dial never reached the friend's Raven: nothing of the
/// message can have been written there.
pub fn never_reached(outcome: &str) -> bool {
    matches!(
        bridge::classify_cause(technical_part(outcome.trim())),
        Cause::NotListening
            | Cause::NotReachable
            | Cause::NameNotFound
            | Cause::NoAddress
            | Cause::BadAddress
            | Cause::ServiceDown
            | Cause::ServiceStart
    )
}

/// Why raven-node holds a message, from its outbox `last_error_code`.
pub fn explain_outbox_code(code: &str, who: &str) -> Plain {
    plain(outbox_code_words(code.trim()), who, code)
}

/// A send that never dialled because the background program could not be
/// started or reached.
pub fn explain_node_unavailable(text: &str) -> Plain {
    let words = if let Some(words) = start_refusal(text) {
        words
    } else if text.contains(PASSPHRASE_MARK) {
        NEEDS_PASSPHRASE_FILE
    } else if bridge::classify_cause(text) == Cause::ServiceSlow {
        cause_words(Cause::ServiceSlow)
    } else {
        cause_words(Cause::ServiceDown)
    };
    plain(words, "", text)
}

/// A start ext.rs refused before trying: `raven lock` stopped this profile,
/// or an erase of it did not finish (the whole error is that text).
fn start_refusal(text: &str) -> Option<Words> {
    match text.trim() {
        bridge::LOCKED_TEXT => Some((
            "Raven is locked: `raven lock` stopped it.",
            "Run `raven unlock` to start it again.",
        )),
        bridge::ERASE_UNFINISHED_TEXT => Some((
            "An erase of this Raven profile didn't finish.",
            "Run `raven erase` to finish it.",
        )),
        _ => None,
    }
}

const NEEDS_PASSPHRASE_FILE: Words = (
    "Raven's background program can't start on this computer yet: it needs your passphrase in a private file.",
    "Set RAVEN_KEYSTORE_PASSPHRASE_FILE for it (see INSTALL_Linux.md).",
);

/// Why starting the background program failed (ext.rs's start), and whether
/// it is the missing passphrase file.
pub fn explain_node_start(text: &str) -> Plain {
    let l = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    let words: Words = if let Some(words) = start_refusal(text) {
        words
    } else if text.contains(PASSPHRASE_MARK) {
        NEEDS_PASSPHRASE_FILE
    } else if has(&["build or install raven-node", "is missing"]) {
        (
            "Raven's background program is missing.",
            "Install Raven again: its background program (raven-node) must be next to the app.",
        )
    } else if has(&["did not answer ipc within"]) {
        cause_words(Cause::ServiceSlow)
    } else if has(&["is running but is not answering ipc"]) {
        (
            "Raven's background program is running but not answering.",
            OPEN_NETWORK,
        )
    } else if has(&["disk is full"]) {
        (
            "This computer's disk is full.",
            "Free some space, then try again.",
        )
    } else if has(&[
        "holds the lan port",
        "failed to bind",
        "address already in use",
    ]) {
        (
            "Another program is using the network port Raven listens on.",
            OPEN_NETWORK,
        )
    } else if has(&["keychain"]) {
        cause_words(Cause::KeychainDenied)
    } else if has(&["exited during startup"]) {
        (
            "Raven's background program stopped while starting.",
            OPEN_NETWORK,
        )
    } else {
        ("Raven's background program couldn't start.", OPEN_NETWORK)
    };
    plain(words, "", text)
}

/// A sealed profile whose at-rest key this process does not hold (privacy
/// pack PP.4). `lost`: the key file is there, but the key that opens it is
/// gone from the keystore (raven-core's `at_rest::key_lost`).
pub fn explain_key_missing(lost: bool) -> Plain {
    let words: Words = if lost {
        (
            "Raven can't open your friends list: the key that encrypts it is no longer in your keychain (or your Raven passphrase vault).",
            "Put back the keychain or the backup this profile came from, then open Raven again.",
        )
    } else {
        (
            "Raven can't open your friends list: it needs your keychain (or your Raven passphrase).",
            "Allow access when asked, then try again.",
        )
    };
    plain(words, "", "")
}

/// What the identity store's refusal (raven-core's redacted reason) is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProblem {
    /// raven-core refuses to bind a new key over the files already there.
    Continuity,
    Keychain,
    /// The passphrase vault (Unix without a keychain).
    Vault,
    /// Another program holds the identity lock.
    Busy,
    Other,
}

pub fn explain_identity(text: &str) -> (IdentityProblem, Plain) {
    let l = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    let (problem, words): (IdentityProblem, Words) = if has(&["continuity"]) {
        (
            IdentityProblem::Continuity,
            (
                "This Raven folder has files but no identity. Raven will not make a new identity over them: to your friends it would look like someone else using your name.",
                "Move the folder aside and start fresh, or put back a backup of it.",
            ),
        )
    } else if has(&["passphrase vault", "keystore vault", "keystore passphrase"]) {
        (
            IdentityProblem::Vault,
            if has(&["passphrase is wrong"]) {
                (
                    "The passphrase didn't unlock Raven's key store.",
                    "Try again with the passphrase you chose.",
                )
            } else {
                (
                    "Raven's key store on this computer can't be opened.",
                    OPEN_DETAILS,
                )
            },
        )
    } else if has(&["database is locked", "database is busy"]) {
        (
            IdentityProblem::Busy,
            (
                "Another Raven program is using your identity right now.",
                "Wait a minute, then try again.",
            ),
        )
    } else if has(&[
        "keychain",
        "secret-service",
        "cryptunprotectdata",
        "cryptprotectdata",
    ]) {
        (
            IdentityProblem::Keychain,
            (
                "Raven wasn't allowed to read your identity from the system keychain.",
                "Allow access when asked, then try again.",
            ),
        )
    } else {
        (
            IdentityProblem::Other,
            (
                "Raven can't read its identity on this computer.",
                OPEN_DETAILS,
            ),
        )
    };
    (problem, plain(words, "", text))
}

/// The raw failure an outcome line keeps at its end as `(technical: …)`, else
/// the whole text.
pub fn technical_part(text: &str) -> &str {
    match text.rfind(TECHNICAL) {
        Some(at) => {
            let tail = &text[at + TECHNICAL.len()..];
            tail.strip_suffix(')').unwrap_or(tail).trim()
        }
        None => text,
    }
}

fn send_words(text: &str, technical: &str) -> Words {
    let l = text.to_ascii_lowercase();
    if HOLD_MARKS.iter().any(|mark| l.contains(mark)) {
        GATE_HOLD
    } else if l.contains(UNVERIFIED_MARK) {
        if l.contains(REMOTE_LAN_MARK) {
            UNVERIFIED_REMOTE_LAN
        } else {
            UNVERIFIED_CARRIER
        }
    } else if l.contains(RESERVED_MARK) {
        (
            "Messages can't start with RVNAPP/ or RVNGRP/.",
            "Change how it starts.",
        )
    } else if l.starts_with(EARLIER_MARK) {
        cause_words(Cause::SendInProgress)
    } else if l.contains(QUEUE_FULL_MARK) {
        (
            "Earlier messages to {who} are still waiting, so this one wasn't queued.",
            "Send it again once they arrive.",
        )
    } else if l.contains(STAGE_FULL_MARK) {
        (
            "Too many messages are waiting for friends who are offline, so this one wasn't queued.",
            "Send it again later.",
        )
    } else if technical == PEER_RESET_UNREACHABLE {
        (
            "{whose} Raven lost your secure connection, and {who} can't be reached right now.",
            "Send it again when {who} is online.",
        )
    } else if l.contains(NO_LAN_DIAL_MARK) {
        cause_words(Cause::NoAddress)
    } else {
        cause_words(bridge::classify_cause(technical))
    }
}

fn plain(words: Words, who: &str, technical: &str) -> Plain {
    Plain {
        headline: fill(words.0, who),
        next: fill(words.1, who),
        technical: technical.trim().to_owned(),
    }
}

/// `template` with `{who}` and `{whose}` replaced by the friend's name, in
/// one pass (a name that holds `{who}` stays as it is). With no name it is
/// "your friend", capitalised where it opens a sentence.
pub fn fill(template: &str, who: &str) -> String {
    let name = who.trim();
    let (who, whose) = if name.is_empty() {
        ("your friend".to_owned(), "your friend's".to_owned())
    } else {
        (name.to_owned(), format!("{name}'s"))
    };
    let mut out = String::with_capacity(template.len() + 2 * whose.len());
    let mut rest = template;
    while let Some(at) = rest.find('{') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let (word, tail) = if let Some(tail) = rest.strip_prefix("{whose}") {
            (whose.as_str(), tail)
        } else if let Some(tail) = rest.strip_prefix("{who}") {
            (who.as_str(), tail)
        } else {
            out.push('{');
            rest = &rest[1..];
            continue;
        };
        if name.is_empty() && (out.is_empty() || out.ends_with(". ")) {
            out.push('Y');
            out.push_str(&word[1..]);
        } else {
            out.push_str(word);
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_prefixes_say_where_a_message_stands() {
        let queued = format!(
            "{}: {} (technical: lan connect: cannot connect to 127.0.0.1:9 (Connection refused))",
            bridge::QUEUED_PREFIX,
            bridge::BACKGROUND_RETRY
        );
        let (kind, words) = explain_send(&queued, "Friend");
        assert_eq!(kind, OutcomeKind::Waiting { background: true });
        assert!(words.headline.contains("Friend"), "{words:?}");
        assert!(never_reached(&queued));
        let sent = format!(
            "{}: no ACK (technical: WAITING_FOR_ENDPOINT_ACK)",
            bridge::UNCONFIRMED_PREFIX
        );
        let (kind, words) = explain_send(&sent, "");
        assert_eq!(kind, OutcomeKind::Sent);
        assert!(words
            .headline
            .starts_with("It left this computer, but your friend's Raven"));
        let (kind, _) = explain_send(
            "NOT SENT, nothing queued: peer is on the local block list",
            "x",
        );
        assert_eq!(kind, OutcomeKind::NotSent);
    }

    #[test]
    fn names_fill_in_once_and_open_sentences_capitalised() {
        assert_eq!(
            fill("{whose} Raven. {who} may", ""),
            "Your friend's Raven. Your friend may"
        );
        assert_eq!(fill("Ask {who}.", "{who}"), "Ask {who}.");
        assert_eq!(fill("a {b} c", "x"), "a {b} c");
    }

    #[test]
    fn identity_problems_are_told_apart() {
        assert_eq!(
            explain_identity("identity continuity violation: profile contains state").0,
            IdentityProblem::Continuity
        );
        assert_eq!(
            explain_identity("macOS Keychain refused access").0,
            IdentityProblem::Keychain
        );
        assert_eq!(explain_identity("something else").0, IdentityProblem::Other);
    }

    /// The causes, codes and start refusals the CLI gained with the terminal
    /// app's phases (cutoff pack, Phase 3, privacy pack) get their own words.
    #[test]
    fn newer_causes_codes_and_refusals_get_words() {
        let not_sent =
            |technical: &str| format!("NOT SENT, nothing queued (technical: {technical})");
        let name =
            not_sent("lan connect: cannot resolve bob-mac.local: nodename nor servname provided");
        assert_eq!(
            bridge::classify_cause(technical_part(&name)),
            Cause::NameNotFound
        );
        let (_, words) = explain_send(&name, "Bob");
        assert_eq!(
            words.headline,
            "Raven couldn't find Bob's computer on this network."
        );
        assert!(never_reached(&name));
        let lan_off = not_sent("ipc LAN_OFF: LAN_OFF: raven lan off is in effect (raven lan on)");
        assert!(explain_send(&lan_off, "Bob")
            .1
            .headline
            .starts_with("LAN is off"));
        let pins = not_sent("lan noise pin unavailable: lan_noise_pins.json: permission denied");
        assert!(explain_send(&pins, "Bob")
            .1
            .headline
            .contains("lan_noise_pins.json"));
        assert_eq!(
            explain_outbox_code("PIN_STORE_UNREADABLE", "Bob").headline,
            explain_send(&pins, "Bob").1.headline
        );
        for code in [
            "NO_SHARED_CUSTODIAN",
            "CUSTODIAN_NOT_OFFERING",
            "MAILBOX_OFF",
        ] {
            let p = explain_outbox_code(code, "Bob");
            assert_ne!(
                p.headline, "Raven is holding this message for now.",
                "{code}"
            );
        }
        let locked = explain_node_start(bridge::LOCKED_TEXT);
        assert!(locked.next.contains("raven unlock"), "{locked:?}");
        assert_eq!(
            explain_node_unavailable(bridge::LOCKED_TEXT).headline,
            locked.headline
        );
        assert!(explain_node_start(bridge::ERASE_UNFINISHED_TEXT)
            .next
            .contains("raven erase"));
        let ended = format!(
            "NOT SENT: your secure connection with Bob has ended, and a new one needs you both \
             on the same network at the same time (technical: {})",
            "lan connect: cannot connect to 192.0.2.1:7420 (operation timed out)"
        );
        assert!(needs_meeting(&ended));
    }

    #[test]
    fn unknown_outbox_codes_still_get_words() {
        let p = explain_outbox_code("SOMETHING_NEW", "x");
        assert_eq!(p.headline, "Raven is holding this message for now.");
        assert_eq!(p.technical, "SOMETHING_NEW");
        assert!(explain_outbox_code("CONTACT_NOT_VERIFIED", "Friend")
            .next
            .contains("security words"));
    }
}
