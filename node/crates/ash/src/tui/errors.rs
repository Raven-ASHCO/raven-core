//! Plain words for everything that goes wrong: a send's outcome, a message
//! the background program holds, the identity, a friend's save and the
//! background program's start.
//!
//! Every error a screen shows comes from here as a [`Plain`]: what happened
//! and what to do, with the friend's name, and the technical text for
//! Details (shaped by display.rs when drawn, like every untrusted string).
//! The sentences never quote the technical text, so an OS message or a name
//! can't change what one says.
//!
//! A send failure is read with ext.rs's own classifier (`classify_cause`,
//! OD-8): a failure text the CLI learns to explain is explained here too.

use super::bridge::{self, Cause};
use super::controller;
#[cfg(test)]
use super::testkit;

/// One failure, in plain words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Plain {
    /// What happened, in a sentence or two.
    pub(super) headline: String,
    /// What the user can do about it, or empty.
    pub(super) next: String,
    /// What the screen can offer for it.
    pub(super) action: Action,
    /// The text the failure was read from, for Details. Security codes are
    /// already taken out of a friend's save (see [`explain_contact_add`]).
    pub(super) technical: String,
}

/// What a screen can offer for a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    /// Try the same thing again.
    Retry,
    /// Send the message again: Raven stopped trying it.
    SendAgain,
    /// Verify the friend (V).
    Verify,
    /// Type the friend's address (E).
    EditAddress,
    /// The friend has to add you first: send them your invite.
    AskFriendToAddYou,
    /// The network and status screen (N).
    OpenNetwork,
    /// Nothing to do but wait: Raven goes on by itself.
    Wait,
    /// Make the message shorter.
    Shorten,
    /// Unblock the friend on their page.
    Unblock,
    /// Nothing beyond Details.
    None,
}

/// Where a send stands, from the start of its outcome text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutcomeKind {
    /// Queued on this computer. `background`: raven-node keeps trying it;
    /// otherwise only the next send to the friend does.
    Waiting { background: bool },
    /// Written to the friend's computer, which hasn't confirmed it: it must
    /// not be typed again.
    Sent,
    /// Nothing is queued.
    NotSent,
}

/// What [`explain_identity`] found, for the screen to choose its copy:
/// ERR-ID never offers to create an identity over any of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IdentityProblem {
    /// raven-core refuses to bind a new key over the files already there.
    Continuity,
    Keychain,
    /// The passphrase vault (Unix without a keychain).
    Vault,
    /// Another program holds the identity lock.
    Busy,
    Other,
}

/// Why the background program did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NodeStartProblem {
    /// A vault profile with no passphrase file: raven-node runs without a
    /// terminal, so it can't ask (PASSFILE explains the steps).
    NeedsPassphraseFile,
    Failed(Plain),
}

/// Where an outcome line keeps the raw failure (ext.rs's `not_sent_for`,
/// `queued_text`, …).
const TECHNICAL: &str = "(technical: ";

/// The words of a failure text that the CLI's classifier does not read, each
/// matched in lower case and pinned by a test fed with the CLI's own text.
/// A carrier this release keeps off: pair_init_lab's `INTERNET_DIRECT_HOLD`
/// and raven-core's `P2P_HOLD`.
const HOLD_MARKS: &[&str] = &["internet_direct_hold", "p2p_hold"];
/// Internet or p2p delivery to a friend who isn't verified.
const UNVERIFIED_MARK: &str = "contact_not_verified";
/// pair_init_lab's `unverified_remote_lan_text`: a LAN address that isn't on
/// the local network, for a friend who isn't verified.
const REMOTE_LAN_MARK: &str = "reached only at addresses on your local network";
/// ext.rs's `verified_only_text` (Phase 3 P3.C2): `raven lan verified-only
/// on` holds and the friend isn't verified (raven-core's `LAN_VERIFIED_ONLY`,
/// lower case).
const VERIFIED_ONLY_MARK: &str = "lan_verified_only";
/// pair_init_lab's `RESERVED_PREFIX_REFUSAL`.
const RESERVED_MARK: &str = "the reserved prefix";
/// ext.rs's `earlier_undelivered_text` and `earlier_unconfirmed_text`.
const EARLIER_MARK: &str = "not sent: an earlier message";
/// ext.rs's `queue_full_text`.
const QUEUE_FULL_MARK: &str = "are already waiting until";
/// ext.rs's `offline_stage_full_text`.
const STAGE_FULL_MARK: &str = "contacts who are offline";
/// ext.rs's `peer_reset_unreachable_text` keeps this as its technical part.
const PEER_RESET_UNREACHABLE: &str = "PEER_RESET_UNREACHABLE";
/// cli.rs's `plan_contact_routes_with` for a friend with no address at all.
const NO_LAN_DIAL_MARK: &str = "has no reachable lan_dial";
/// ext.rs's NOT SENT of a first message (Raven hasn't connected with the
/// friend yet), in the words of its `first_message_rule` (E1).
pub(super) const FIRST_MESSAGE_MARK: &str = "a first message needs";
/// ext.rs's NOT SENT once the last secure connection ended (cutoff pack
/// CP.6: "RAVEN's secure connection with {who} ended {when} ...").
pub(super) const SESSION_ENDED_MARK: &str = "a new one needs you both on the same network";
/// raven-core's keystore_vault.rs, when a program without a terminal needs
/// the vault passphrase (testkit checks the file still says it).
pub(super) const PASSPHRASE_MARK: &str = "cannot ask for the passphrase";
/// What a denied Local Network permission looks like on macOS 15 and later.
const LOCAL_NETWORK_DENIED: &str = "no route to host";
const LOCAL_NETWORK_HINT: &str = "If this keeps happening, check System Settings > Privacy & \
                                  Security > Local Network for your terminal app.";
/// What to do when macOS refused raven-node's LAN connection outright.
const LOCAL_NETWORK_NEXT: &str = "Turn on your terminal app (or Raven) in System Settings > \
                                  Privacy & Security > Local Network, then restart Raven.";

/// What a failure is, for the words it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// A send failure as ext.rs classifies its raw text.
    Cause(Cause),
    /// Only a carrier this release keeps off can reach the friend.
    GateHold,
    /// Internet delivery needs the friend verified.
    UnverifiedCarrier,
    /// The friend's LAN address isn't on this network, and they aren't
    /// verified.
    UnverifiedRemoteLan,
    /// Written to the friend's computer, not confirmed.
    Unconfirmed,
    /// Sentences of their own: headline, next, action. `{who}` and `{whose}`
    /// are filled in with the friend's name.
    Says(&'static str, &'static str, Action),
}

const RESERVED: Why = Why::Says(
    "Messages can't start with RVNAPP/ or RVNGRP/.",
    "Change how it starts.",
    Action::None,
);
const QUEUE_FULL: Why = Why::Says(
    "Earlier messages to {who} are still waiting, so this one wasn't queued.",
    "Send it again once they arrive.",
    Action::Wait,
);
const STAGE_FULL: Why = Why::Says(
    "Too many messages are waiting for friends who are offline, so this one wasn't queued.",
    "Send it again later.",
    Action::Wait,
);
const PEER_RESET_GONE: Why = Why::Says(
    "{whose} Raven lost your secure connection, and {who} can't be reached right now.",
    "Send it again when {who} is online.",
    Action::Retry,
);
/// A start the lock refused (ext.rs's `LOCKED_TEXT`; review
/// E-harness-docs-ci-3): `raven lock` stopped Raven, and the user kept it
/// stopped when the app asked; NET's S asks again.
const RAVEN_LOCKED: Why = Why::Says(
    "Raven is locked: `raven lock` stopped it.",
    "Press N, then S to start Raven again.",
    Action::OpenNetwork,
);
const NEEDS_PASSPHRASE_FILE: Why = Why::Says(
    "Raven's background program can't start on this computer yet: it needs your passphrase \
     in a private file.",
    "Press N to see how.",
    Action::OpenNetwork,
);
/// A noise pin mismatch (M0, ext.rs's `is_noise_pin_mismatch`): another key
/// answered at the friend's address and Raven stopped before saying who you
/// are. Two causes, as the CLI says: another computer has the address now,
/// or the friend reinstalled Raven (a new key no wait reaches).
const NOISE_PIN_MISMATCH: Why = Why::Says(
    "Something else answered at {whose} address, so Raven didn't tell it who you are.",
    "{who} may be back at that address later. If {who} reinstalled Raven, ask for a new invite.",
    Action::None,
);
/// Only verified friends connect on the local network here (Phase 3 P3.C2,
/// the cutoff people report's words).
const VERIFIED_ONLY: Why = Why::Says(
    "Only verified friends can connect on this network: {who} isn't verified yet.",
    "Compare security codes with {who} in person (press V).",
    Action::Verify,
);
const UNKNOWN_HOLD: Why = Why::Says(
    "Raven is holding this message for now.",
    "Press D for details.",
    Action::None,
);

/// raven-node's outbox codes (`last_error_code`), as raven-node/src/outbox.rs
/// defines them in its `mod code` block, then raven-core's
/// `CONTACT_NOT_VERIFIED`. testkit's drift hash fails when that block
/// changes: then update this table.
const OUTBOX_CODES: &[(&str, Why)] = &[
    (
        "NOT_A_CONTACT",
        Why::Says(
            "{who} isn't in your friends list anymore.",
            "Add {who} again to send it.",
            Action::None,
        ),
    ),
    ("CONTACT_BLOCKED", Why::Cause(Cause::Blocked)),
    (
        "SENDING_PAUSED",
        Why::Says(
            "You paused sending to {who}.",
            "To send it, resume sending: press P on {who} in your friends list.",
            Action::None,
        ),
    ),
    (
        "CONTACTS_UNREADABLE",
        Why::Says(
            "Your friends list can't be read.",
            "Press D for details.",
            Action::None,
        ),
    ),
    ("NO_ROUTE", Why::Cause(Cause::NoAddress)),
    (
        "DEFERRED",
        Why::Says(
            "Other messages to {who} went first. This one goes next.",
            "",
            Action::Wait,
        ),
    ),
    ("SEND_IN_PROGRESS", Why::Cause(Cause::SendInProgress)),
    (
        "LOCK",
        Why::Says(
            "Raven couldn't get ready to send to {who}.",
            "It tries again by itself.",
            Action::Wait,
        ),
    ),
    (
        "LOCAL_DEVICE",
        Why::Says(
            "This computer isn't set up to send yet.",
            "Press D for details.",
            Action::None,
        ),
    ),
    (
        "LOCAL_DEVICE_REVOKED",
        Why::Says(
            "This computer is no longer allowed to send as you.",
            "Press D for details.",
            Action::None,
        ),
    ),
    (
        "PEER_REVOKED",
        Why::Says(
            "Raven stopped: {who} retired the device this message was for.",
            "Ask {who} for a new invite.",
            Action::None,
        ),
    ),
    (
        "NO_PEER_CERT",
        Why::Says(
            "Raven is still setting up a secure connection with {who}.",
            "It tries again by itself.",
            Action::Wait,
        ),
    ),
    (
        "NO_LOCAL_BODY",
        Why::Says(
            "The text of this message isn't on this computer anymore.",
            "Press D for details.",
            Action::None,
        ),
    ),
    (
        "HISTORY",
        Why::Says(
            "Raven couldn't record this message in your history.",
            "It tries again by itself.",
            Action::Wait,
        ),
    ),
    (
        "CLOCK",
        Why::Says(
            "This computer's clock looks wrong.",
            "Check the date and time in your system settings.",
            Action::None,
        ),
    ),
    (
        "STORE",
        Why::Says(
            "Raven couldn't read its list of waiting messages.",
            "It tries again by itself.",
            Action::Wait,
        ),
    ),
    ("NO_ACK_YET", Why::Unconfirmed),
    (
        "STAGE",
        Why::Says(
            "Raven couldn't keep this message ready to send, so it stopped trying.",
            "Send it again if {who} didn't get it.",
            Action::SendAgain,
        ),
    ),
    (
        "SUPERSEDED",
        Why::Says(
            "{whose} Raven can't accept this message anymore: it was sealed for an older \
             connection.",
            "Send it again if {who} didn't get it.",
            Action::SendAgain,
        ),
    ),
    (
        "EXPIRED",
        Why::Says(
            "Raven stopped trying: this message waited too long.",
            "Send it again if {who} still needs it.",
            Action::SendAgain,
        ),
    ),
    ("INTERNET_HOLD", Why::GateHold),
    ("P2P_HOLD", Why::GateHold),
    (
        "P2P_NOT_RUNNING",
        Why::Says(
            "Raven's peer-to-peer connection isn't running.",
            "Press N to see why.",
            Action::OpenNetwork,
        ),
    ),
    // The Bluetooth nearby carrier (Phase 5, lab-only).
    (
        "NEARBY_HOLD",
        Why::Says(
            "Bluetooth nearby isn't in this version yet.",
            "Send it again without choosing Bluetooth.",
            Action::SendAgain,
        ),
    ),
    (
        "NEARBY_NOT_RUNNING",
        Why::Says(
            "Raven's Bluetooth nearby isn't running.",
            "Press N to see why.",
            Action::OpenNetwork,
        ),
    ),
    (
        "NEARBY_NOT_IN_RANGE",
        Why::Says(
            "{who} isn't in Bluetooth range right now.",
            "Raven sends it when {who} is nearby or online.",
            Action::Wait,
        ),
    ),
    (
        "NEARBY_BUSY",
        Why::Says(
            "Every Bluetooth link is in use right now.",
            "Raven tries again shortly.",
            Action::Wait,
        ),
    ),
    // The Tor onion carrier (lab-only).
    ("ONION_HOLD", Why::GateHold),
    (
        "ONION_NOT_READY",
        Why::Says(
            "Tor isn't ready on this computer yet.",
            "Raven sends it once Tor is ready or another way works.",
            Action::Wait,
        ),
    ),
    (
        "ONION_UNREACHABLE",
        Why::Says(
            "{who} couldn't be reached over Tor right now.",
            "Raven sends it when {who} is online.",
            Action::Wait,
        ),
    ),
    ("LINK_NOT_ACCEPTED", Why::Cause(Cause::PeerRefused)),
    ("PEER_REFUSED", Why::Cause(Cause::PeerRefused)),
    ("WRONG_IDENTITY", Why::Cause(Cause::WrongIdentity)),
    ("NOT_LISTENING", Why::Cause(Cause::NotListening)),
    ("NOT_REACHABLE", Why::Cause(Cause::NotReachable)),
    ("CLOSED_EARLY", Why::Cause(Cause::ClosedEarly)),
    (
        "PIN_STORE_UNREADABLE",
        Why::Cause(Cause::PinStoreUnreadable),
    ),
    (
        "DIAL_FAILED",
        Why::Says(
            "Raven couldn't connect to {who}.",
            "It tries again by itself.",
            Action::Wait,
        ),
    ),
    (
        "PEER_RESET",
        Why::Says(
            "{whose} Raven lost your secure connection. Raven is sending this again over a new \
             one.",
            "",
            Action::Wait,
        ),
    ),
    (
        "PEER_RESET_NO_BODY",
        Why::Says(
            "{whose} Raven lost your secure connection, and this message can't be sent again \
             from here.",
            "Send it again if {who} didn't get it.",
            Action::SendAgain,
        ),
    ),
    (
        "RESEAL_CAP",
        Why::Says(
            "Raven stopped trying: the connection with {who} was reset too many times.",
            "Send it again if {who} didn't get it.",
            Action::SendAgain,
        ),
    ),
    (
        "IN_CUSTODY",
        Why::Says(
            "A friend's computer is holding a sealed copy for {who}.",
            "Raven keeps trying {who} directly too.",
            Action::Wait,
        ),
    ),
    // Friend custody status (Phase 3): why no friend holds a copy.
    (
        "NO_SHARED_CUSTODIAN",
        Why::Says(
            "{who} collects mail only from friends you haven't verified, so no friend can hold \
             this for {who}.",
            "Raven keeps trying {who} directly.",
            Action::Wait,
        ),
    ),
    (
        "CUSTODIAN_NOT_OFFERING",
        Why::Says(
            "The friend {who} collects mail from doesn't hold messages for you, or not over \
             the internet.",
            "Raven keeps trying {who} directly.",
            Action::Wait,
        ),
    ),
    (
        "MAILBOX_OFF",
        Why::Says(
            "A friend could hold this for {who}, but friend mailboxes are off.",
            "To use them, run `raven custody use on`.",
            Action::None,
        ),
    ),
    // Sealed letters (Phase 5b): why no friend holds the letter yet.
    (
        "WAITING_FOR_CARRIER",
        Why::Says(
            "Waiting for a friend to carry it to {who}.",
            "It tries again by itself; it can wait up to 7 days.",
            Action::Wait,
        ),
    ),
    (
        "CARRIER_FULL",
        Why::Says(
            "Waiting for a friend to carry it: your friend's Raven is full.",
            "It tries again by itself; it can wait up to 7 days.",
            Action::Wait,
        ),
    ),
    (
        "NO_SHARED_CARRIER",
        Why::Says(
            "No friend can carry it: you and {who} don't share a mail friend.",
            "It goes when you meet.",
            Action::Wait,
        ),
    ),
    // raven-core's outbox.rs: held until the friend is verified.
    ("CONTACT_NOT_VERIFIED", Why::UnverifiedCarrier),
];

/// A send's outcome text (the `Err` of a send) in plain words, with `who`
/// the friend's name. The start of the text says where the message stands;
/// the raw failure it keeps as `(technical: …)` says why.
pub(super) fn explain_send(outcome: &str, who: &str) -> (OutcomeKind, Plain) {
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
    let why = match kind {
        // Whatever cut the confirmation short, the message is there: never
        // advice that ends in sending it again.
        OutcomeKind::Sent => Why::Unconfirmed,
        _ => send_why(text, technical),
    };
    (kind, plain(why, who, technical))
}

/// Whether a send's NOT SENT outcome text says it can go only once the two of
/// you meet: Raven's last secure connection with the friend ended, and their
/// computer couldn't be reached to set up a new one. Not when it answered:
/// then Raven has to be opened there, and you may be together already.
pub(super) fn needs_meeting(outcome: &str) -> bool {
    away_with(outcome, SESSION_ENDED_MARK)
}

/// Whether a send's NOT SENT outcome text is a first message's (Raven hasn't
/// connected with the friend yet) whose friend's computer couldn't be
/// reached: it needs you both online (E1). Not when it
/// answered, as for [`needs_meeting`].
pub(super) fn first_message_away(outcome: &str) -> bool {
    away_with(outcome, FIRST_MESSAGE_MARK)
}

/// `outcome` says `mark` before its technical part, and its failure is that
/// the friend's computer couldn't be reached.
fn away_with(outcome: &str, mark: &str) -> bool {
    let text = outcome.trim();
    let head = text.rfind(TECHNICAL).map_or(text, |at| &text[..at]);
    head.to_ascii_lowercase().contains(mark)
        && matches!(
            bridge::classify_cause(technical_part(text)),
            Cause::NotReachable | Cause::NameNotFound
        )
}

/// The rule a first message goes by, in the app's words: ext.rs's
/// `first_message_rule` with Raven's name as the app writes it (E1: every
/// place says the same).
pub(super) fn first_message_rule(who: &str) -> String {
    bridge::first_message_rule(who).replace("RAVEN", "Raven")
}

/// A send that never dialled because the background program could not be
/// started or reached (the send job's ensure failed): `text` is that error.
pub(super) fn explain_node_unavailable(text: &str) -> Plain {
    let text = text.trim();
    let why = if text == raven_core::privacy::LOCKED_TEXT {
        RAVEN_LOCKED
    } else if text.contains(PASSPHRASE_MARK) {
        NEEDS_PASSPHRASE_FILE
    } else if bridge::classify_cause(text) == Cause::ServiceSlow {
        Why::Cause(Cause::ServiceSlow)
    } else {
        Why::Cause(Cause::ServiceDown)
    };
    plain(why, "", text)
}

/// Why the chat history could not be loaded for Home (raven-core's text):
/// another program holds it, the keychain refused its key, or it can't be
/// read, in the words a send that met the same gets.
pub(super) fn explain_history(text: &str) -> Plain {
    let text = text.trim();
    let cause = match bridge::classify_cause(text) {
        cause @ (Cause::HistoryLocked | Cause::KeychainDenied) => cause,
        _ => Cause::HistoryUnreadable,
    };
    plain(Why::Cause(cause), "", text)
}

/// Why a chat could not be deleted on this computer (PP.21): the delete
/// reads and writes the chat history (and the session store), so the
/// history's words say why; Details has raven-core's text.
pub(super) fn explain_delete_chat(text: &str) -> Plain {
    let why = explain_history(text);
    Plain {
        headline: format!("Raven couldn't delete the chat. {}", why.headline),
        ..why
    }
}

/// "Forget {name}'s address" cleared the saved address, but some of what
/// Raven learned about reaching the friend could not be forgotten (review
/// D-lock-tui-8): `notes`, one per part (`raven contact forget-address`'s
/// notes), for Details.
pub(super) fn explain_forget_partial(name: &str, notes: &[String]) -> Plain {
    Plain {
        headline: format!(
            "Raven forgot {name}'s saved address, but couldn't forget everything it learned \
             about reaching {name}."
        ),
        next: String::new(),
        action: Action::None,
        technical: notes.join("\n"),
    }
}

/// A change to the security notices or to a pause that could not be made
/// (P6.31): `headline`, with raven-core's text for Details.
pub(super) fn explain_security(headline: &str, text: &str) -> Plain {
    Plain {
        headline: headline.to_owned(),
        next: String::new(),
        action: Action::None,
        technical: text.trim().to_owned(),
    }
}

/// raven-node's outbox `last_error_code` in this table's words (its
/// headline, without the closing period), `None` for a code the table does
/// not know: `raven outbox list` says it so (E1: it showed the raw code).
pub(crate) fn outbox_code_headline(code: &str, who: &str) -> Option<String> {
    let code = code.trim();
    OUTBOX_CODES
        .iter()
        .any(|(known, _)| *known == code)
        .then(|| {
            let headline = explain_outbox_code(code, who).headline;
            headline.strip_suffix('.').unwrap_or(&headline).to_owned()
        })
}

/// Why raven-node holds a message, from its outbox `last_error_code`.
pub(super) fn explain_outbox_code(code: &str, who: &str) -> Plain {
    let code = code.trim();
    let why = OUTBOX_CODES
        .iter()
        .find(|(known, _)| *known == code)
        .map_or(UNKNOWN_HOLD, |(_, why)| *why);
    plain(why, who, code)
}

/// The identity store's refusal (raven-core's redacted reason), when loading
/// or creating the identity.
pub(super) fn explain_identity(text: &str) -> (IdentityProblem, Plain) {
    let text = text.trim();
    let l = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    // Continuity first: several of its texts name the Keychain too.
    let (problem, why) = if has(&["continuity"]) {
        (
            IdentityProblem::Continuity,
            Why::Says(
                "This folder has Raven files but no identity. Raven will not make a new \
                 identity over them: to your friends it would look like someone else using \
                 your name.",
                "What you can do: move this folder aside and start fresh, or put back a backup \
                 of it.",
                Action::None,
            ),
        )
    } else if has(&["passphrase vault", "keystore vault", "keystore passphrase"]) {
        let why = if has(&["passphrase is wrong"]) {
            Why::Says(
                "The passphrase didn't unlock Raven's key store.",
                "Open Raven again and type the passphrase you chose.",
                Action::Retry,
            )
        } else {
            Why::Says(
                "Raven's key store on this computer can't be opened.",
                "Press D for details.",
                Action::None,
            )
        };
        (IdentityProblem::Vault, why)
    } else if has(&["database is locked", "database is busy"]) {
        (
            IdentityProblem::Busy,
            Why::Says(
                "Another Raven program is using your identity right now.",
                "Wait a minute, then open Raven again.",
                Action::Wait,
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
            Why::Says(
                "Raven wasn't allowed to read your identity from the system keychain.",
                "Open Raven again and allow access when asked.",
                Action::Retry,
            ),
        )
    } else {
        (
            IdentityProblem::Other,
            Why::Says(
                "Raven can't read its identity on this computer.",
                "Press D for details.",
                Action::None,
            ),
        )
    };
    (problem, plain(why, "", text))
}

/// A refused change to a friend (save, verify, rename, address, remove,
/// unblock): cli.rs's error or the controller's own. Every security code in
/// it is taken out first: a refused pin says `got <code>`, and the code of a
/// friend not verified yet never shows (the design's security rules).
pub(super) fn explain_contact_add(text: &str) -> Plain {
    let text = hide_security_codes(text.trim());
    let l = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    let why = if has(&["fingerprint mismatch"]) {
        if text.contains(bridge::FINGERPRINT_CASE_HINT) {
            Why::Says(
                "Upper and lower case differ: codes are case-sensitive (W is not w).",
                "Nothing was saved.",
                Action::Verify,
            )
        } else {
            Why::Says(
                "That doesn't match. Do not verify: someone may have swapped {whose} key.",
                "Check you pasted the right invite, or save {who} as not verified.",
                Action::Verify,
            )
        }
    } else if has(&["security words do not match this key"]) {
        Why::Says(
            "These are real Raven words, but not {whose}. Do not verify: someone may have \
             swapped {whose} key.",
            "Check you pasted the right invite, or save {who} as not verified.",
            Action::Verify,
        )
    } else if has(&["security words not accepted"]) {
        Why::Says(
            "These aren't 10 Raven words that fit together, so nothing was saved.",
            "Ask {who} to read them again, slowly.",
            Action::Verify,
        )
    } else if text.contains("KEY_CHANGE_REFUSED_WITHOUT_REPIN") {
        Why::Says(
            "You verified this person with a different key, so nothing was saved.",
            "If they reinstalled Raven, check with them in person or by phone, remove the old \
             one on their page (X), then add them again.",
            Action::None,
        )
    } else if let Some(name) = taken_name(&text) {
        return Plain {
            headline: format!("You already have a friend called {name}."),
            next: "Pick another name.".into(),
            action: Action::None,
            technical: text,
        };
    } else if has(&["choose a distinct --petname"]) {
        Why::Says(
            "Another friend already uses this name.",
            "Pick another name.",
            Action::None,
        )
    } else if text.contains(controller::NO_NAME) {
        Why::Says("Give your friend a name.", "", Action::None)
    } else if text.contains(controller::OWN_KEY) {
        Why::Says(
            "That's your own invite.",
            "Paste your friend's instead.",
            Action::None,
        )
    } else if text.contains(controller::NOT_SAVED)
        || has(&["contact not found", "no contact matched"])
    {
        Why::Says(
            "That friend isn't saved on this computer anymore.",
            "",
            Action::None,
        )
    } else if text.contains(controller::NO_IDENTITY) {
        Why::Says(
            "Raven has no identity on this computer yet.",
            "",
            Action::None,
        )
    } else if l.starts_with("contacts.json:") || has(&["contacts.json corrupt"]) {
        // Before the words of a bad card: serde names the field it missed.
        Why::Says(
            "Your friends list can't be read.",
            "Press D for details.",
            Action::None,
        )
    } else if has(&["is not on the block list"]) {
        Why::Says("That friend isn't blocked.", "", Action::None)
    } else if l.starts_with("block list:") {
        Why::Says(
            "Your block list can't be read.",
            "Press D for details.",
            Action::None,
        )
    } else if controller::TAMPER_MARKS
        .iter()
        .any(|mark| text.contains(mark))
    {
        Why::Says(
            "This invite doesn't add up: its address and key don't match.",
            "Ask your friend to send it again.",
            Action::None,
        )
    } else if has(&[
        "address required",
        "address must be valid",
        "pub_hex",
        "looks like a terminal shell command",
    ]) {
        Why::Says(
            "That doesn't look like a Raven invite or card.",
            "",
            Action::None,
        )
    } else if has(&["lan_dial must look like host:port"]) {
        Why::Says(
            "That isn't an address Raven can use.",
            "It looks like 192.168.1.30:7420.",
            Action::EditAddress,
        )
    } else if has(&["internet address", "not a network address", "p2p:"]) {
        Why::Says(
            "The invite has an address Raven can't use.",
            "Ask your friend to send it again.",
            Action::None,
        )
    } else {
        Why::Says(
            "Raven couldn't save this change.",
            "Press D for details.",
            Action::None,
        )
    };
    plain(why, "", &text)
}

/// Why starting the background program failed (ext.rs's
/// `ensure_mac_lan_daemon`): its text, with the service's own last output.
pub(super) fn explain_node_start(text: &str) -> NodeStartProblem {
    let text = text.trim();
    if text.contains(PASSPHRASE_MARK) {
        return NodeStartProblem::NeedsPassphraseFile;
    }
    if text == raven_core::privacy::LOCKED_TEXT {
        return NodeStartProblem::Failed(plain(RAVEN_LOCKED, "", text));
    }
    let l = text.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    let why = if has(&["build or install raven-node"]) {
        Why::Says(
            "Raven's background program is missing.",
            "Install Raven again: its background program (raven-node) must be next to this one.",
            Action::None,
        )
    } else if has(&["did not answer ipc within"]) {
        Why::Cause(Cause::ServiceSlow)
    } else if has(&["is running but is not answering ipc"]) {
        Why::Says(
            "Raven's background program is running but not answering.",
            "Press N to see why.",
            Action::OpenNetwork,
        )
    } else if has(&["disk is full"]) {
        Why::Says(
            "This computer's disk is full.",
            "Free some space, then try again.",
            Action::Retry,
        )
    } else if has(&[
        "holds the lan port",
        "failed to bind",
        "address already in use",
    ]) {
        Why::Says(
            "Another program is using the network port Raven listens on.",
            "Press N to see why.",
            Action::OpenNetwork,
        )
    } else if has(&["keychain"]) {
        Why::Cause(Cause::KeychainDenied)
    } else if has(&["exited during startup"]) {
        Why::Says(
            "Raven's background program stopped while starting.",
            "Press N to see why.",
            Action::OpenNetwork,
        )
    } else {
        Why::Says(
            "Raven's background program couldn't start.",
            "Press N to see why.",
            Action::OpenNetwork,
        )
    };
    NodeStartProblem::Failed(plain(why, "", text))
}

/// A job that panicked: `message` is the panic's, `captured` what the job
/// printed before it.
pub(super) fn explain_panic(message: &str, captured: &str) -> Plain {
    let mut technical = format!("panic: {message}");
    if !captured.trim().is_empty() {
        technical.push('\n');
        technical.push_str(captured.trim_end());
    }
    Plain {
        headline: "Something went wrong inside Raven.".into(),
        next: "Press D for details.".into(),
        action: Action::None,
        technical,
    }
}

/// The raw failure an outcome line keeps at its end as `(technical: …)` (the
/// last one: a name in the sentence can't move it), else the whole text.
fn technical_part(text: &str) -> &str {
    match text.rfind(TECHNICAL) {
        Some(at) => {
            let tail = &text[at + TECHNICAL.len()..];
            tail.strip_suffix(')').unwrap_or(tail).trim()
        }
        None => text,
    }
}

/// What a send's failure is: the texts the CLI words without a cause first,
/// then ext.rs's classifier on the raw part.
fn send_why(text: &str, technical: &str) -> Why {
    let l = text.to_ascii_lowercase();
    if HOLD_MARKS.iter().any(|mark| l.contains(mark)) {
        Why::GateHold
    } else if l.contains(VERIFIED_ONLY_MARK) {
        VERIFIED_ONLY
    } else if l.contains(UNVERIFIED_MARK) {
        if l.contains(REMOTE_LAN_MARK) {
            Why::UnverifiedRemoteLan
        } else {
            Why::UnverifiedCarrier
        }
    } else if l.contains(RESERVED_MARK) {
        RESERVED
    } else if l.starts_with(EARLIER_MARK) {
        Why::Cause(Cause::SendInProgress)
    } else if l.contains(QUEUE_FULL_MARK) {
        QUEUE_FULL
    } else if l.contains(STAGE_FULL_MARK) {
        STAGE_FULL
    } else if technical == PEER_RESET_UNREACHABLE {
        PEER_RESET_GONE
    } else if l.contains(NO_LAN_DIAL_MARK) {
        Why::Cause(Cause::NoAddress)
    } else if bridge::classify_cause(technical) == Cause::WrongIdentity
        && bridge::is_noise_pin_mismatch(technical)
    {
        NOISE_PIN_MISMATCH
    } else {
        Why::Cause(bridge::classify_cause(technical))
    }
}

/// The sentences for `why`, with the friend's name filled in, and the
/// technical text as it came.
fn plain(why: Why, who: &str, technical: &str) -> Plain {
    let (headline, next, action) = words(why);
    let mut next = fill(next, who);
    if why == Why::Cause(Cause::NotReachable) && local_network_denied(technical) {
        if !next.is_empty() {
            next.push(' ');
        }
        next.push_str(LOCAL_NETWORK_HINT);
    }
    Plain {
        headline: fill(headline, who),
        next,
        action,
        technical: technical.trim().to_owned(),
    }
}

/// macOS refuses a terminal app's LAN dials while its Local Network
/// permission is off, and the OS says only `no route to host`.
fn local_network_denied(technical: &str) -> bool {
    cfg!(target_os = "macos")
        && technical
            .to_ascii_lowercase()
            .contains(LOCAL_NETWORK_DENIED)
}

/// Headline, next step and action for `why`.
fn words(why: Why) -> (&'static str, &'static str, Action) {
    match why {
        Why::Cause(cause) => cause_words(cause),
        Why::GateHold => (
            "{who} can only be reached over the internet, which isn't in this version yet.",
            "Ask {who} for an invite with a local-network address.",
            Action::None,
        ),
        Why::UnverifiedCarrier => (
            "{who} is only reachable over the internet, which needs {who} verified first.",
            "Press V to verify.",
            Action::Verify,
        ),
        Why::UnverifiedRemoteLan => (
            "{whose} address isn't on your local network, and {who} isn't verified yet.",
            "Press V to verify.",
            Action::Verify,
        ),
        Why::Unconfirmed => (
            "It left this computer, but {whose} Raven hasn't confirmed it.",
            "Wait. Don't send it again.",
            Action::Wait,
        ),
        Why::Says(headline, next, action) => (headline, next, action),
    }
}

/// The words for each of ext.rs's causes.
fn cause_words(cause: Cause) -> (&'static str, &'static str, Action) {
    match cause {
        Cause::NotListening => (
            "{whose} computer is there, but Raven isn't receiving right now (it may be locked or \
             closed).",
            "Ask {who} to open Raven.",
            Action::Retry,
        ),
        Cause::NameNotFound => NAME_NOT_FOUND,
        Cause::NotReachable => (
            "{whose} computer couldn't be reached (it may be off, asleep, or on another \
             network).",
            "",
            Action::Retry,
        ),
        Cause::ClosedEarly => (
            "The connection to {who} dropped.",
            "Try again.",
            Action::Retry,
        ),
        Cause::PeerRefused => (
            "{whose} Raven didn't accept it. {who} may not have added you yet.",
            "Send {who} your invite.",
            Action::AskFriendToAddYou,
        ),
        Cause::WrongIdentity => (
            "The computer at that address isn't {whose} Raven.",
            "Ask {who} for a new invite.",
            Action::None,
        ),
        Cause::NoAddress | Cause::BadAddress => (
            "Raven doesn't have a usable address for {who}.",
            "Press E to enter it, or paste {whose} invite again.",
            Action::EditAddress,
        ),
        Cause::ServiceDown | Cause::ServiceStart => (
            "Raven's background program isn't running on this computer.",
            "Press N to see why.",
            Action::OpenNetwork,
        ),
        Cause::ServiceSlow => (
            "Raven's background program is still starting.",
            "On a Mac, look for a password window and choose Always Allow.",
            Action::Wait,
        ),
        Cause::KeychainDenied => (
            "Raven wasn't allowed to read its keys from the system keychain.",
            "Allow access when asked, then try again.",
            Action::Retry,
        ),
        Cause::HistoryLocked => (
            "Another Raven program is using your messages right now.",
            "Wait a moment, then try again.",
            Action::Wait,
        ),
        Cause::HistoryUnreadable => (
            "Your message history can't be read.",
            "Press D for details.",
            Action::None,
        ),
        Cause::TooLarge => ("This message is too long.", "Shorten it.", Action::Shorten),
        Cause::BadCharacters => (
            "This message has characters Raven can't send.",
            "",
            Action::None,
        ),
        Cause::Blocked => (
            "You blocked {who}.",
            "Unblock {who} on {whose} page.",
            Action::Unblock,
        ),
        Cause::SendInProgress => (
            "An earlier message to {who} is still being sent.",
            "Wait for it.",
            Action::Wait,
        ),
        // The composer sends no empty message; the CLI's own check still has
        // words here.
        Cause::EmptyMessage => (
            "This message is empty.",
            "Type some text first.",
            Action::None,
        ),
        Cause::PinStoreUnreadable => (
            "Raven can't read its file of your friends' keys (lan_noise_pins.json), so it can't \
             connect to anyone.",
            "Fix that file's owner or permissions in Raven's data folder, or move it aside.",
            Action::None,
        ),
        // `raven lan off` (Phase 3): nothing is dialled on the local network.
        Cause::LanOff => (
            "LAN is off on this computer, so Raven doesn't connect to {who} on your network.",
            "Turn it back on with: raven lan on.",
            Action::None,
        ),
        // macOS refused the connection itself (the Local Network permission).
        Cause::LocalNetworkRefused => (
            "This Mac didn't let Raven connect to {who} on your local network.",
            LOCAL_NETWORK_NEXT,
            Action::Retry,
        ),
        Cause::Other => (
            "Raven couldn't send this message.",
            "Press D for details.",
            Action::None,
        ),
    }
}

/// The words for the cutoff pack's `Cause::NameNotFound` (CP.5): the
/// friend's saved computer name isn't found on this network.
const NAME_NOT_FOUND: (&str, &str, Action) = (
    "Raven couldn't find {whose} computer on this network.",
    "When you're both on the same network it goes by itself. If their address changed, press E \
     on their page.",
    Action::EditAddress,
);

/// `template` with `{who}` and `{whose}` replaced by the friend's name, in one
/// pass: a name that itself holds `{who}` stays as it is. With no name it is
/// "your friend", capitalised where it opens a sentence.
fn fill(template: &str, who: &str) -> String {
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

/// The name in cli.rs's `petname "<name>" is already used by another
/// contact` (sanitized there).
fn taken_name(text: &str) -> Option<&str> {
    let start = text.find("petname \"")? + "petname \"".len();
    let end = text.rfind("\" is already used by another contact")?;
    (start < end).then(|| &text[start..end])
}

/// `text` with everything shaped like a security code (`If4x-36FU-omFi`:
/// groups of 4, 4 and 1 to 4 letters and digits) replaced by the
/// controller's hidden-code words.
fn hide_security_codes(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while at < chars.len() {
        match code_len_at(&chars, at) {
            Some(len) => {
                out.push_str(controller::HIDDEN_CODE);
                at += len;
            }
            None => {
                out.push(chars[at]);
                at += 1;
            }
        }
    }
    out
}

/// The length of a security code starting at `at`, if one does: not inside a
/// longer word or a dashed run (a UUID, say), on either side.
fn code_len_at(chars: &[char], at: usize) -> Option<usize> {
    let joined = |c: &char| c.is_ascii_alphanumeric() || *c == '-';
    if at > 0 && joined(&chars[at - 1]) {
        return None;
    }
    let run = |from: usize| {
        chars[from..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric())
            .count()
    };
    if run(at) != 4 || chars.get(at + 4) != Some(&'-') {
        return None;
    }
    if run(at + 5) != 4 || chars.get(at + 9) != Some(&'-') {
        return None;
    }
    let last = run(at + 10);
    let end = at + 10 + last;
    if !(1..=4).contains(&last) || chars.get(end) == Some(&'-') {
        return None;
    }
    Some(end - at)
}

/// The codes [`explain_outbox_code`] has words for (testkit's drift check).
#[cfg(test)]
pub(super) fn outbox_codes() -> Vec<&'static str> {
    OUTBOX_CODES.iter().map(|(code, _)| *code).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use raven_core::identity::Identity;
    use raven_core::keystore_vault::VaultError;
    use raven_core::IdentityStoreError;

    /// A friend's key (any 32 bytes do for the outcome texts).
    const BOB_KEY: &str = "abababababababababababababababababababababababababababababababab";

    /// The send context the CLI builds for a friend saved as Bob.
    fn bob() -> bridge::SendCtx {
        bridge::send_ctx(Path::new("raven-test-profile"), "Bob", "", BOB_KEY)
    }

    fn retry(background: bool) -> bridge::RetryNote {
        bridge::RetryNote {
            expires_at_ms: bridge::now_ms() + 24 * 3_600_000,
            copy_expires_at_ms: 0,
            background,
            custodians: Vec::new(),
            carry_first: None,
        }
    }

    fn says(plain: &Plain) -> (&str, &str, Action) {
        (plain.headline.as_str(), plain.next.as_str(), plain.action)
    }

    #[test]
    fn a_history_that_cannot_be_read_is_said_plainly() {
        let unreadable =
            explain_history(" chat history authentication failed (wrong key or tampered file) ");
        assert_eq!(unreadable.headline, "Your message history can't be read.");
        assert_eq!(unreadable.next, "Press D for details.");
        assert_eq!(
            unreadable.technical,
            "chat history authentication failed (wrong key or tampered file)"
        );
        let locked = explain_history(
            "chat history I/O failed: history lock: still held by another raven process after \
             10s (database is locked)",
        );
        assert_eq!(
            locked.headline,
            "Another Raven program is using your messages right now."
        );
        // A key the keychain did not hand over, as a send that met it says.
        let keychain = explain_history("protected chat-history key is missing");
        assert_eq!(
            keychain.headline,
            "Raven wasn't allowed to read its keys from the system keychain."
        );
        // Anything else is the history, never a send's words.
        let other = explain_history("connection refused");
        assert_eq!(other.headline, "Your message history can't be read.");
    }

    /// One test per ext.rs cause: the raw text classifies as that cause, and
    /// the CLI's own NOT SENT line built from it reads in these words.
    macro_rules! cause_test {
        ($test:ident, $cause:ident, $raw:expr, $headline:expr, $next:expr, $action:ident) => {
            #[test]
            fn $test() {
                let raw: &str = $raw;
                assert_eq!(bridge::classify_cause(raw), Cause::$cause, "{raw}");
                let text = bridge::not_sent_text(&bob(), raw, false);
                let (kind, plain) = explain_send(&text, "Bob");
                assert_eq!(kind, OutcomeKind::NotSent, "{text}");
                assert_eq!(says(&plain), ($headline, $next, Action::$action), "{text}");
                assert_eq!(plain.technical, raven_core::ipc::without_addresses(raw));
            }
        };
    }

    /// Fails to compile when ext.rs gains a cause: give it words and a test.
    fn test_of(cause: Cause) -> fn() {
        match cause {
            Cause::NotListening => cause_not_listening,
            Cause::NotReachable => cause_not_reachable,
            Cause::NameNotFound => cause_name_not_found,
            Cause::ClosedEarly => cause_closed_early,
            Cause::PeerRefused => cause_peer_refused,
            Cause::WrongIdentity => cause_wrong_identity,
            Cause::BadAddress => cause_bad_address,
            Cause::NoAddress => cause_no_address,
            Cause::ServiceDown => cause_service_down,
            Cause::ServiceStart => cause_service_start,
            Cause::ServiceSlow => cause_service_slow,
            Cause::HistoryUnreadable => cause_history_unreadable,
            Cause::KeychainDenied => cause_keychain_denied,
            Cause::HistoryLocked => cause_history_locked,
            Cause::TooLarge => cause_too_large,
            Cause::BadCharacters => cause_bad_characters,
            Cause::Blocked => cause_blocked,
            Cause::SendInProgress => cause_send_in_progress,
            Cause::EmptyMessage => cause_empty_message,
            Cause::PinStoreUnreadable => cause_pin_store_unreadable,
            Cause::LanOff => cause_lan_off,
            Cause::LocalNetworkRefused => cause_local_network_refused,
            Cause::Other => cause_other,
        }
    }

    #[test]
    fn every_cause_has_its_test() {
        // The match above is the check; this only keeps it in use.
        let _ = test_of(Cause::Other);
    }

    cause_test!(
        cause_not_listening,
        NotListening,
        "cannot connect to 192.168.1.30:7420 (Connection refused (os error 61))",
        "Bob's computer is there, but Raven isn't receiving right now (it may be locked or closed).",
        "Ask Bob to open Raven.",
        Retry
    );
    cause_test!(
        cause_not_reachable,
        NotReachable,
        "cannot connect to 192.168.1.30:7420 (no answer within 5s)",
        "Bob's computer couldn't be reached (it may be off, asleep, or on another network).",
        "",
        Retry
    );
    cause_test!(
        cause_closed_early,
        ClosedEarly,
        "rlb1 read: early eof",
        "The connection to Bob dropped.",
        "Try again.",
        Retry
    );
    cause_test!(
        cause_peer_refused,
        PeerRefused,
        "LAN_DIAL_PEER_CLOSED: the peer closed the connection without an answer",
        "Bob's Raven didn't accept it. Bob may not have added you yet.",
        "Send Bob your invite.",
        AskFriendToAddYou
    );
    cause_test!(
        cause_wrong_identity,
        WrongIdentity,
        "rlb1 identity does not match the saved contact",
        "The computer at that address isn't Bob's Raven.",
        "Ask Bob for a new invite.",
        None
    );
    cause_test!(
        cause_bad_address,
        BadAddress,
        "invalid socket address syntax",
        "Raven doesn't have a usable address for Bob.",
        "Press E to enter it, or paste Bob's invite again.",
        EditAddress
    );
    cause_test!(
        cause_no_address,
        NoAddress,
        "valid lan_dial host:port required — refusing LocalListenQueue / 127.0.0.1:0 fallback",
        "Raven doesn't have a usable address for Bob.",
        "Press E to enter it, or paste Bob's invite again.",
        EditAddress
    );
    cause_test!(
        cause_service_down,
        ServiceDown,
        "raven-node is not running (ipc_transport_missing)",
        "Raven's background program isn't running on this computer.",
        "Press N to see why.",
        OpenNetwork
    );
    cause_test!(
        cause_service_start,
        ServiceStart,
        "local raven-node service is not running and could not be started: raven-node service \
         exited during startup (exit status: 1)",
        "Raven's background program isn't running on this computer.",
        "Press N to see why.",
        OpenNetwork
    );
    cause_test!(
        cause_service_slow,
        ServiceSlow,
        "local raven-node service is not running and could not be started: raven-node service \
         did not answer IPC within 20s (it is still running as process 4242; retry shortly, or \
         stop only this one with: kill 4242)",
        "Raven's background program is still starting.",
        "On a Mac, look for a password window and choose Always Allow.",
        Wait
    );
    cause_test!(
        cause_history_unreadable,
        HistoryUnreadable,
        "chat history is corrupt",
        "Your message history can't be read.",
        "Press D for details.",
        None
    );
    cause_test!(
        cause_keychain_denied,
        KeychainDenied,
        "protected chat-history key is missing (keychain read failed)",
        "Raven wasn't allowed to read its keys from the system keychain.",
        "Allow access when asked, then try again.",
        Retry
    );
    cause_test!(
        cause_history_locked,
        HistoryLocked,
        "chat history is still held by another RAVEN process",
        "Another Raven program is using your messages right now.",
        "Wait a moment, then try again.",
        Wait
    );
    cause_test!(
        cause_too_large,
        TooLarge,
        "message too large for one frame (max 4096 bytes)",
        "This message is too long.",
        "Shorten it.",
        Shorten
    );
    cause_test!(
        cause_bad_characters,
        BadCharacters,
        "text violates the bounded application policy",
        "This message has characters Raven can't send.",
        "",
        None
    );
    cause_test!(
        cause_blocked,
        Blocked,
        "peer is on the local block list",
        "You blocked Bob.",
        "Unblock Bob on Bob's page.",
        Unblock
    );
    cause_test!(
        cause_send_in_progress,
        SendInProgress,
        "an earlier outbound object must be retried first",
        "An earlier message to Bob is still being sent.",
        "Wait for it.",
        Wait
    );
    cause_test!(
        cause_empty_message,
        EmptyMessage,
        "message is empty",
        "This message is empty.",
        "Type some text first.",
        None
    );
    cause_test!(
        cause_pin_store_unreadable,
        PinStoreUnreadable,
        "ipc LAN_DIAL: lan noise pin unavailable: lan_noise_pins.json: permission denied",
        "Raven can't read its file of your friends' keys (lan_noise_pins.json), so it can't \
         connect to anyone.",
        "Fix that file's owner or permissions in Raven's data folder, or move it aside.",
        None
    );
    cause_test!(
        cause_local_network_refused,
        LocalNetworkRefused,
        "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.25:17420 (192.168.0.25:17420: No \
         route to host (os error 65)); mid=1fb52189…",
        "This Mac didn't let Raven connect to Bob on your local network.",
        "Turn on your terminal app (or Raven) in System Settings > Privacy & Security > Local \
         Network, then restart Raven.",
        Retry
    );
    cause_test!(
        cause_lan_off,
        LanOff,
        "ipc LAN_OFF: LAN_OFF: raven lan off is in effect (raven lan on)",
        "LAN is off on this computer, so Raven doesn't connect to Bob on your network.",
        "Turn it back on with: raven lan on.",
        None
    );
    cause_test!(
        cause_other,
        Other,
        "something nobody planned for",
        "Raven couldn't send this message.",
        "Press D for details.",
        None
    );

    cause_test!(
        cause_name_not_found,
        NameNotFound,
        "ipc LAN_DIAL: lan connect: cannot resolve bob-mac.local: failed to lookup address \
         information: nodename nor servname provided, or not known",
        "Raven couldn't find Bob's computer on this network.",
        "When you're both on the same network it goes by itself. If their address changed, \
         press E on their page.",
        EditAddress
    );

    /// The cutoff pack's NameNotFound (CP.5): every OS's words for a name
    /// not found read as it, and a friend with no name gets the words too.
    #[test]
    fn a_computer_name_not_found_has_its_words() {
        for raw in [
            "failed to lookup address information: nodename nor servname provided, or not known",
            "failed to lookup address information: Name or service not known",
            "No such host is known. (os error 11001)",
        ] {
            assert_eq!(bridge::classify_cause(raw), Cause::NameNotFound, "{raw}");
        }
        let raw = "failed to lookup address information: Name or service not known";
        let nameless = plain(Why::Cause(Cause::NameNotFound), "", raw);
        assert_eq!(
            nameless.headline,
            "Raven couldn't find your friend's computer on this network."
        );
        assert_eq!(nameless.technical, raw);
        // A first message to a friend whose name isn't found needs you both
        // online, as one whose computer couldn't be reached does; no meeting
        // is needed for it (E1).
        let first = bridge::not_sent_text(&bob(), raw, true);
        assert!(
            first_message_away(&first) && !needs_meeting(&first),
            "{first}"
        );
        let later = bridge::not_sent_text(&bob(), raw, false);
        assert!(
            !first_message_away(&later) && !needs_meeting(&later),
            "{later}"
        );
    }

    #[test]
    fn a_secure_connection_that_ended_needs_a_meeting_too() {
        // ext.rs's NOT SENT once the last secure connection ran out (CP.6).
        let raw = "cannot connect to 192.168.1.30:7420 (no answer within 5s)";
        let ended = format!(
            "NOT SENT: Bob did not answer at 192.168.1.30:7420. Nothing was queued: RAVEN's \
             secure connection with Bob ended yesterday at 14:05 (each one lasts a day from when \
             it is set up), and {SESSION_ENDED_MARK} at the same time. Send it when you meet. \
             (technical: {raw})"
        );
        assert!(needs_meeting(&ended) && !first_message_away(&ended));
        let refused = ended.replace(raw, "Connection refused (os error 61)");
        assert!(!needs_meeting(&refused), "it answered: no meeting needed");
    }

    /// E1: a first message the CLI could not send says the same rule as
    /// `raven contact list` and the app's Home; the app reads it as a first
    /// message whose friend was away only when nothing answered.
    #[test]
    fn a_first_message_reads_as_one_by_the_cli_rule() {
        let unreachable = "cannot connect to 192.168.1.30:7420 (no answer within 5s)";
        let refused = "cannot connect to 192.168.1.30:7420 (Connection refused (os error 61))";
        let away = bridge::not_sent_text(&bob(), unreachable, true);
        assert!(
            away.contains(&bridge::first_message_rule("Bob")[2..]),
            "{away}"
        );
        assert!(first_message_away(&away) && !needs_meeting(&away));
        let answered = bridge::not_sent_text(&bob(), refused, true);
        assert!(!first_message_away(&answered), "{answered}");
        assert_eq!(
            first_message_rule("Bob"),
            "A first message needs you and Bob both online (Raven hasn't connected with Bob \
             yet)."
        );
        assert!(first_message_rule("Bob")
            .to_ascii_lowercase()
            .contains(FIRST_MESSAGE_MARK));
    }

    #[test]
    fn each_outcome_text_of_the_cli_reads_as_its_kind() {
        let ctx = bob();
        let refused = "cannot connect to 192.168.1.30:7420 (Connection refused (os error 61))";
        let unreachable = "cannot connect to 192.168.1.30:7420 (no answer within 5s)";
        let listening = (
            "Bob's computer is there, but Raven isn't receiving right now (it may be locked or closed).",
            "Ask Bob to open Raven.",
            Action::Retry,
        );
        let lost = (
            "Bob's computer couldn't be reached (it may be off, asleep, or on another network).",
            "",
            Action::Retry,
        );
        let unconfirmed = (
            "It left this computer, but Bob's Raven hasn't confirmed it.",
            "Wait. Don't send it again.",
            Action::Wait,
        );
        let cases = [
            (
                bridge::not_sent_text(&ctx, refused, true),
                OutcomeKind::NotSent,
                listening,
                refused,
            ),
            (
                bridge::queued_text(&ctx, refused, "\"see you at 5\"", &retry(true)),
                OutcomeKind::Waiting { background: true },
                listening,
                refused,
            ),
            (
                bridge::queued_text(&ctx, unreachable, "", &retry(false)),
                OutcomeKind::Waiting { background: false },
                lost,
                unreachable,
            ),
            (
                bridge::unconfirmed_text(&ctx, "rlb1 read: early eof", "", &retry(true)),
                OutcomeKind::Sent,
                unconfirmed,
                "rlb1 read: early eof",
            ),
            (
                bridge::unconfirmed_text(&ctx, "NO_ACK", "\"hi\"", &retry(false)),
                OutcomeKind::Sent,
                unconfirmed,
                "NO_ACK",
            ),
        ];
        for (text, kind, words, technical) in cases {
            let (got_kind, plain) = explain_send(&text, "Bob");
            assert_eq!(got_kind, kind, "{text}");
            assert_eq!(says(&plain), words, "{text}");
            assert_eq!(
                plain.technical,
                raven_core::ipc::without_addresses(technical),
                "{text}"
            );
        }
        // The name the screen passes is the one used, whatever the text says.
        let (_, plain) = explain_send(&bridge::not_sent_text(&ctx, refused, false), "Ana");
        assert_eq!(plain.next, "Ask Ana to open Raven.");
    }

    #[test]
    fn the_cli_texts_that_carry_no_cause_get_their_own_words() {
        let ctx = bob();
        let pin = "raven contact add … --verify-fp <the fingerprint they read out>";
        let cases = [
            (
                format!(
                    "{} — Bob has only an Internet address saved; to reach them on your network \
                     save a LAN one: raven contact set-addr --petname Bob --lan HOST:PORT",
                    bridge::INTERNET_DIRECT_HOLD
                ),
                (
                    "Bob can only be reached over the internet, which isn't in this version yet.",
                    "Ask Bob for an invite with a local-network address.",
                    Action::None,
                ),
            ),
            (
                format!("{} — Bob has only a p2p route saved", raven_core::P2P_HOLD),
                (
                    "Bob can only be reached over the internet, which isn't in this version yet.",
                    "Ask Bob for an invite with a local-network address.",
                    Action::None,
                ),
            ),
            (
                bridge::unverified_carrier_text("Bob", "Internet", "raven contact verify", pin),
                (
                    "Bob is only reachable over the internet, which needs Bob verified first.",
                    "Press V to verify.",
                    Action::Verify,
                ),
            ),
            (
                bridge::unverified_remote_lan_text(
                    "Bob",
                    "203.0.113.7:7420 is not on your local network",
                    "raven contact verify",
                    pin,
                ),
                (
                    "Bob's address isn't on your local network, and Bob isn't verified yet.",
                    "Press V to verify.",
                    Action::Verify,
                ),
            ),
            (
                bridge::verified_only_text("Bob", &[0x5b; 32]),
                (
                    "Only verified friends can connect on this network: Bob isn't verified yet.",
                    "Compare security codes with Bob in person (press V).",
                    Action::Verify,
                ),
            ),
            (
                bridge::RESERVED_PREFIX_REFUSAL.to_owned(),
                (
                    "Messages can't start with RVNAPP/ or RVNGRP/.",
                    "Change how it starts.",
                    Action::None,
                ),
            ),
            (
                bridge::earlier_undelivered_text(&ctx, "_dial_peer_closed", "\"hi\"", &retry(true)),
                (
                    "An earlier message to Bob is still being sent.",
                    "Wait for it.",
                    Action::Wait,
                ),
            ),
            (
                bridge::earlier_unconfirmed_text(&ctx, ""),
                (
                    "An earlier message to Bob is still being sent.",
                    "Wait for it.",
                    Action::Wait,
                ),
            ),
            (
                bridge::queue_full_text(&ctx, 16),
                (
                    "Earlier messages to Bob are still waiting, so this one wasn't queued.",
                    "Send it again once they arrive.",
                    Action::Wait,
                ),
            ),
            (
                bridge::offline_stage_full_text(&ctx),
                (
                    "Too many messages are waiting for friends who are offline, so this one \
                     wasn't queued.",
                    "Send it again later.",
                    Action::Wait,
                ),
            ),
            (
                bridge::peer_reset_unreachable_text(&ctx),
                (
                    "Bob's Raven lost your secure connection, and Bob can't be reached right now.",
                    "Send it again when Bob is online.",
                    Action::Retry,
                ),
            ),
            (
                "contact Bob has no reachable lan_dial — set host:port (not LocalListenQueue)"
                    .to_owned(),
                (
                    "Raven doesn't have a usable address for Bob.",
                    "Press E to enter it, or paste Bob's invite again.",
                    Action::EditAddress,
                ),
            ),
        ];
        for (text, words) in cases {
            let (kind, plain) = explain_send(&text, "Bob");
            assert_eq!(kind, OutcomeKind::NotSent, "{text}");
            assert_eq!(says(&plain), words, "{text}");
            assert!(!plain.technical.is_empty(), "{text}");
        }
    }

    /// A-noise-pin-2: a noise pin mismatch (another key answered at the
    /// friend's address and Raven stopped before saying who you are) has
    /// its own words, as the CLI's: the friend may be back there later, or
    /// reinstalled Raven. A bind mismatch keeps "isn't {whose} Raven".
    #[test]
    fn a_noise_pin_mismatch_names_both_causes() {
        let ctx = bob();
        let raw = "ipc LAN_DIAL: lan noise pin mismatch: a different key answered at this \
                   address; RAVEN stopped before identifying this computer";
        let words = (
            "Something else answered at Bob's address, so Raven didn't tell it who you are.",
            "Bob may be back at that address later. If Bob reinstalled Raven, ask for a new \
             invite.",
            Action::None,
        );
        for (text, kind) in [
            (
                bridge::queued_text(&ctx, raw, "\"hi\"", &retry(true)),
                OutcomeKind::Waiting { background: true },
            ),
            (
                bridge::queued_text(&ctx, raw, "", &retry(false)),
                OutcomeKind::Waiting { background: false },
            ),
            (
                bridge::not_sent_text(&ctx, raw, false),
                OutcomeKind::NotSent,
            ),
            (bridge::not_sent_text(&ctx, raw, true), OutcomeKind::NotSent),
        ] {
            let (got_kind, plain) = explain_send(&text, "Bob");
            assert_eq!(got_kind, kind, "{text}");
            assert_eq!(says(&plain), words, "{text}");
            assert_eq!(plain.technical, raw, "{text}");
        }
        let bind = bridge::not_sent_text(&ctx, "identity bind does not match expected pub", false);
        assert_eq!(
            explain_send(&bind, "Bob").1.headline,
            "The computer at that address isn't Bob's Raven."
        );
    }

    #[test]
    fn a_technical_part_is_the_last_one_and_keeps_its_own_brackets() {
        let raw = "cannot connect to 10.0.0.5:7420 (Connection refused)";
        let text = bridge::not_sent_text(&bob(), raw, false);
        // No address in the technical part.
        assert_eq!(
            technical_part(&text),
            "cannot connect to <local address> (Connection refused)"
        );
        // A name that holds the marker can't move it.
        let named = bridge::not_sent_text(
            &bridge::send_ctx(Path::new("p"), "x (technical: y", "", BOB_KEY),
            raw,
            false,
        );
        assert_eq!(
            technical_part(&named),
            raven_core::ipc::without_addresses(raw)
        );
        assert_eq!(technical_part("send refused: odd"), "send refused: odd");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn no_route_to_host_points_at_the_local_network_permission_on_macos() {
        // A public address: macOS may mean a real "no route" there.
        let raw = "cannot connect to 203.0.113.7:7420 (No route to host (os error 65))";
        let (_, plain) = explain_send(&bridge::not_sent_text(&bob(), raw, false), "Bob");
        assert_eq!(plain.action, Action::Retry);
        assert_eq!(
            plain.next,
            "If this keeps happening, check System Settings > Privacy & Security > Local \
             Network for your terminal app."
        );
        // A local address: macOS refused it outright (cause_local_network_refused).
        let raw = "cannot connect to 192.168.1.30:7420 (No route to host (os error 65))";
        let (_, plain) = explain_send(&bridge::not_sent_text(&bob(), raw, false), "Bob");
        assert_eq!(plain.next, LOCAL_NETWORK_NEXT);
        // Only that error: a dial that timed out says nothing of it.
        let (_, plain) = explain_send(
            &bridge::not_sent_text(&bob(), "cannot connect to 1.2.3.4:7420 (timed out)", false),
            "Bob",
        );
        assert_eq!(plain.next, "");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn no_route_to_host_adds_no_macos_hint_elsewhere() {
        let raw = "cannot connect to 192.168.1.30:7420 (No route to host (os error 113))";
        let (_, plain) = explain_send(&bridge::not_sent_text(&bob(), raw, false), "Bob");
        assert_eq!(plain.next, "");
    }

    #[test]
    fn a_missing_name_is_your_friend() {
        let (_, plain) = explain_send(
            &bridge::not_sent_text(&bob(), "_dial_peer_closed", false),
            "  ",
        );
        assert_eq!(
            says(&plain),
            (
                "Your friend's Raven didn't accept it. Your friend may not have added you yet.",
                "Send your friend your invite.",
                Action::AskFriendToAddYou
            )
        );
        // Filled in one pass: a name with braces stays as typed.
        assert_eq!(fill("{who} and {whose}", "{who}"), "{who} and {who}'s");
        assert_eq!(fill("a {b} {who}", "Ana"), "a {b} Ana");
    }

    /// Review E-harness-docs-ci-3: a send or a start that `raven lock`'s
    /// lock refused (ext.rs's `LOCKED_TEXT`) says Raven is locked and how to
    /// start it again (NET's S asks UNLOCK).
    #[test]
    fn a_locked_profile_says_so() {
        let text = raven_core::privacy::LOCKED_TEXT;
        let expected = (
            "Raven is locked: `raven lock` stopped it.",
            "Press N, then S to start Raven again.",
            Action::OpenNetwork,
        );
        assert_eq!(says(&explain_node_unavailable(text)), expected);
        let NodeStartProblem::Failed(plain) = explain_node_start(text) else {
            panic!("a lock is no passphrase problem");
        };
        assert_eq!(says(&plain), expected);
        assert_eq!(plain.technical, text);
    }

    #[test]
    fn a_node_that_is_not_there_says_so() {
        for text in [
            "local raven-node service is not running and could not be started: could not start \
             /opt/raven/raven-node (No such file or directory (os error 2)); build or install \
             raven-node next to ash",
            "local raven-node service is running but is not answering IPC (profile /p; it holds \
             /p/raven-node.lock)",
        ] {
            assert_eq!(
                says(&explain_node_unavailable(text)),
                (
                    "Raven's background program isn't running on this computer.",
                    "Press N to see why.",
                    Action::OpenNetwork
                ),
                "{text}"
            );
            assert_eq!(explain_node_unavailable(text).technical, text);
        }
        let slow = "raven-node service did not answer IPC within 20s (it is still running as \
                    process 4242; retry shortly, or stop only this one with: kill 4242)";
        assert_eq!(
            explain_node_unavailable(slow).headline,
            "Raven's background program is still starting."
        );
    }

    /// One test per outbox code: the words the friend page and MSG show for
    /// a message raven-node holds with it.
    macro_rules! code_test {
        ($test:ident, $code:expr, $headline:expr, $next:expr, $action:ident) => {
            #[test]
            fn $test() {
                let plain = explain_outbox_code($code, "Bob");
                assert_eq!(says(&plain), ($headline, $next, Action::$action), $code);
                assert_eq!(plain.technical, $code);
            }
        };
    }

    code_test!(
        code_not_a_contact,
        "NOT_A_CONTACT",
        "Bob isn't in your friends list anymore.",
        "Add Bob again to send it.",
        None
    );
    code_test!(
        code_contact_blocked,
        "CONTACT_BLOCKED",
        "You blocked Bob.",
        "Unblock Bob on Bob's page.",
        Unblock
    );
    code_test!(
        code_sending_paused,
        "SENDING_PAUSED",
        "You paused sending to Bob.",
        "To send it, resume sending: press P on Bob in your friends list.",
        None
    );
    code_test!(
        code_contacts_unreadable,
        "CONTACTS_UNREADABLE",
        "Your friends list can't be read.",
        "Press D for details.",
        None
    );
    code_test!(
        code_no_route,
        "NO_ROUTE",
        "Raven doesn't have a usable address for Bob.",
        "Press E to enter it, or paste Bob's invite again.",
        EditAddress
    );
    code_test!(
        code_deferred,
        "DEFERRED",
        "Other messages to Bob went first. This one goes next.",
        "",
        Wait
    );
    code_test!(
        code_send_in_progress,
        "SEND_IN_PROGRESS",
        "An earlier message to Bob is still being sent.",
        "Wait for it.",
        Wait
    );
    code_test!(
        code_lock,
        "LOCK",
        "Raven couldn't get ready to send to Bob.",
        "It tries again by itself.",
        Wait
    );
    code_test!(
        code_local_device,
        "LOCAL_DEVICE",
        "This computer isn't set up to send yet.",
        "Press D for details.",
        None
    );
    code_test!(
        code_local_device_revoked,
        "LOCAL_DEVICE_REVOKED",
        "This computer is no longer allowed to send as you.",
        "Press D for details.",
        None
    );
    code_test!(
        code_peer_revoked,
        "PEER_REVOKED",
        "Raven stopped: Bob retired the device this message was for.",
        "Ask Bob for a new invite.",
        None
    );
    code_test!(
        code_no_peer_cert,
        "NO_PEER_CERT",
        "Raven is still setting up a secure connection with Bob.",
        "It tries again by itself.",
        Wait
    );
    code_test!(
        code_no_local_body,
        "NO_LOCAL_BODY",
        "The text of this message isn't on this computer anymore.",
        "Press D for details.",
        None
    );
    code_test!(
        code_history,
        "HISTORY",
        "Raven couldn't record this message in your history.",
        "It tries again by itself.",
        Wait
    );
    code_test!(
        code_clock,
        "CLOCK",
        "This computer's clock looks wrong.",
        "Check the date and time in your system settings.",
        None
    );
    code_test!(
        code_store,
        "STORE",
        "Raven couldn't read its list of waiting messages.",
        "It tries again by itself.",
        Wait
    );
    code_test!(
        code_no_ack_yet,
        "NO_ACK_YET",
        "It left this computer, but Bob's Raven hasn't confirmed it.",
        "Wait. Don't send it again.",
        Wait
    );
    code_test!(
        code_stage,
        "STAGE",
        "Raven couldn't keep this message ready to send, so it stopped trying.",
        "Send it again if Bob didn't get it.",
        SendAgain
    );
    code_test!(
        code_superseded,
        "SUPERSEDED",
        "Bob's Raven can't accept this message anymore: it was sealed for an older connection.",
        "Send it again if Bob didn't get it.",
        SendAgain
    );
    code_test!(
        code_expired,
        "EXPIRED",
        "Raven stopped trying: this message waited too long.",
        "Send it again if Bob still needs it.",
        SendAgain
    );
    code_test!(
        code_internet_hold,
        "INTERNET_HOLD",
        "Bob can only be reached over the internet, which isn't in this version yet.",
        "Ask Bob for an invite with a local-network address.",
        None
    );
    code_test!(
        code_p2p_hold,
        "P2P_HOLD",
        "Bob can only be reached over the internet, which isn't in this version yet.",
        "Ask Bob for an invite with a local-network address.",
        None
    );
    code_test!(
        code_p2p_not_running,
        "P2P_NOT_RUNNING",
        "Raven's peer-to-peer connection isn't running.",
        "Press N to see why.",
        OpenNetwork
    );
    code_test!(
        code_nearby_hold,
        "NEARBY_HOLD",
        "Bluetooth nearby isn't in this version yet.",
        "Send it again without choosing Bluetooth.",
        SendAgain
    );
    code_test!(
        code_nearby_not_running,
        "NEARBY_NOT_RUNNING",
        "Raven's Bluetooth nearby isn't running.",
        "Press N to see why.",
        OpenNetwork
    );
    code_test!(
        code_nearby_not_in_range,
        "NEARBY_NOT_IN_RANGE",
        "Bob isn't in Bluetooth range right now.",
        "Raven sends it when Bob is nearby or online.",
        Wait
    );
    code_test!(
        code_nearby_busy,
        "NEARBY_BUSY",
        "Every Bluetooth link is in use right now.",
        "Raven tries again shortly.",
        Wait
    );
    code_test!(
        code_onion_not_ready,
        "ONION_NOT_READY",
        "Tor isn't ready on this computer yet.",
        "Raven sends it once Tor is ready or another way works.",
        Wait
    );
    code_test!(
        code_onion_unreachable,
        "ONION_UNREACHABLE",
        "Bob couldn't be reached over Tor right now.",
        "Raven sends it when Bob is online.",
        Wait
    );
    code_test!(
        code_link_not_accepted,
        "LINK_NOT_ACCEPTED",
        "Bob's Raven didn't accept it. Bob may not have added you yet.",
        "Send Bob your invite.",
        AskFriendToAddYou
    );
    code_test!(
        code_peer_refused,
        "PEER_REFUSED",
        "Bob's Raven didn't accept it. Bob may not have added you yet.",
        "Send Bob your invite.",
        AskFriendToAddYou
    );
    code_test!(
        code_wrong_identity,
        "WRONG_IDENTITY",
        "The computer at that address isn't Bob's Raven.",
        "Ask Bob for a new invite.",
        None
    );
    code_test!(
        code_not_listening,
        "NOT_LISTENING",
        "Bob's computer is there, but Raven isn't receiving right now (it may be locked or closed).",
        "Ask Bob to open Raven.",
        Retry
    );
    code_test!(
        code_not_reachable,
        "NOT_REACHABLE",
        "Bob's computer couldn't be reached (it may be off, asleep, or on another network).",
        "",
        Retry
    );
    code_test!(
        code_closed_early,
        "CLOSED_EARLY",
        "The connection to Bob dropped.",
        "Try again.",
        Retry
    );
    code_test!(
        code_pin_store_unreadable,
        "PIN_STORE_UNREADABLE",
        "Raven can't read its file of your friends' keys (lan_noise_pins.json), so it can't \
         connect to anyone.",
        "Fix that file's owner or permissions in Raven's data folder, or move it aside.",
        None
    );
    code_test!(
        code_dial_failed,
        "DIAL_FAILED",
        "Raven couldn't connect to Bob.",
        "It tries again by itself.",
        Wait
    );
    code_test!(
        code_peer_reset,
        "PEER_RESET",
        "Bob's Raven lost your secure connection. Raven is sending this again over a new one.",
        "",
        Wait
    );
    code_test!(
        code_peer_reset_no_body,
        "PEER_RESET_NO_BODY",
        "Bob's Raven lost your secure connection, and this message can't be sent again from \
         here.",
        "Send it again if Bob didn't get it.",
        SendAgain
    );
    code_test!(
        code_reseal_cap,
        "RESEAL_CAP",
        "Raven stopped trying: the connection with Bob was reset too many times.",
        "Send it again if Bob didn't get it.",
        SendAgain
    );
    code_test!(
        code_in_custody,
        "IN_CUSTODY",
        "A friend's computer is holding a sealed copy for Bob.",
        "Raven keeps trying Bob directly too.",
        Wait
    );
    code_test!(
        code_no_shared_custodian,
        "NO_SHARED_CUSTODIAN",
        "Bob collects mail only from friends you haven't verified, so no friend can hold this \
         for Bob.",
        "Raven keeps trying Bob directly.",
        Wait
    );
    code_test!(
        code_custodian_not_offering,
        "CUSTODIAN_NOT_OFFERING",
        "The friend Bob collects mail from doesn't hold messages for you, or not over the \
         internet.",
        "Raven keeps trying Bob directly.",
        Wait
    );
    code_test!(
        code_mailbox_off,
        "MAILBOX_OFF",
        "A friend could hold this for Bob, but friend mailboxes are off.",
        "To use them, run `raven custody use on`.",
        None
    );
    code_test!(
        code_waiting_for_carrier,
        "WAITING_FOR_CARRIER",
        "Waiting for a friend to carry it to Bob.",
        "It tries again by itself; it can wait up to 7 days.",
        Wait
    );
    code_test!(
        code_carrier_full,
        "CARRIER_FULL",
        "Waiting for a friend to carry it: your friend's Raven is full.",
        "It tries again by itself; it can wait up to 7 days.",
        Wait
    );
    code_test!(
        code_no_shared_carrier,
        "NO_SHARED_CARRIER",
        "No friend can carry it: you and Bob don't share a mail friend.",
        "It goes when you meet.",
        Wait
    );
    code_test!(
        code_contact_not_verified,
        "CONTACT_NOT_VERIFIED",
        "Bob is only reachable over the internet, which needs Bob verified first.",
        "Press V to verify.",
        Verify
    );
    code_test!(
        code_unknown,
        "SOMETHING_NEW",
        "Raven is holding this message for now.",
        "Press D for details.",
        None
    );

    #[test]
    fn every_listed_code_has_words_of_its_own() {
        for code in outbox_codes() {
            assert_ne!(
                explain_outbox_code(code, "Bob").headline,
                explain_outbox_code("SOMETHING_NEW", "Bob").headline,
                "{code}"
            );
        }
        let mut codes = outbox_codes();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), OUTBOX_CODES.len(), "a code is listed twice");
        // raven-core's own constant, which the table spells out.
        assert!(outbox_codes().contains(&raven_core::CONTACT_NOT_VERIFIED));
    }

    /// The identity store's errors, worded as raven-core words them.
    fn store_error(e: IdentityStoreError) -> String {
        e.redacted_display()
    }

    #[test]
    fn identity_continuity() {
        let text = store_error(IdentityStoreError::Continuity(
            "profile contains state but has no identity continuity record; if this profile was \
             never initialised, move the stray files out of the data dir, otherwise restore the \
             missing identity",
        ));
        let (problem, plain) = explain_identity(&text);
        assert_eq!(problem, IdentityProblem::Continuity);
        assert_eq!(
            says(&plain),
            (
                "This folder has Raven files but no identity. Raven will not make a new identity \
                 over them: to your friends it would look like someone else using your name.",
                "What you can do: move this folder aside and start fresh, or put back a backup \
                 of it.",
                Action::None
            )
        );
        assert_eq!(plain.technical, text);
        // Its Keychain texts are continuity too.
        let keychain = store_error(IdentityStoreError::Continuity(
            "duplicate Keychain identity items",
        ));
        assert_eq!(explain_identity(&keychain).0, IdentityProblem::Continuity);
    }

    #[test]
    fn identity_keychain() {
        for text in [
            store_error(IdentityStoreError::SecureStore(
                "keychain get status -25293".into(),
            )),
            store_error(IdentityStoreError::SecureStore(
                "secret-service search: denied".into(),
            )),
            store_error(IdentityStoreError::SecureStore(
                "CryptUnprotectData failed".into(),
            )),
        ] {
            let (problem, plain) = explain_identity(&text);
            assert_eq!(problem, IdentityProblem::Keychain, "{text}");
            assert_eq!(
                says(&plain),
                (
                    "Raven wasn't allowed to read your identity from the system keychain.",
                    "Open Raven again and allow access when asked.",
                    Action::Retry
                )
            );
        }
    }

    #[test]
    fn identity_vault() {
        let wrong = store_error(IdentityStoreError::SecureStore(format!(
            "passphrase vault: {}",
            VaultError::WrongPassphraseOrTampered
        )));
        let (problem, plain) = explain_identity(&wrong);
        assert_eq!(problem, IdentityProblem::Vault);
        assert_eq!(
            says(&plain),
            (
                "The passphrase didn't unlock Raven's key store.",
                "Open Raven again and type the passphrase you chose.",
                Action::Retry
            )
        );
        let damaged = store_error(IdentityStoreError::SecureStore(format!(
            "passphrase vault: {}",
            VaultError::Corrupt("bad header")
        )));
        let (problem, plain) = explain_identity(&damaged);
        assert_eq!(problem, IdentityProblem::Vault);
        assert_eq!(
            plain.headline,
            "Raven's key store on this computer can't be opened."
        );
    }

    #[test]
    fn identity_busy() {
        let text = store_error(IdentityStoreError::Io(
            "data-dir lock identity_store.lock: database is locked".into(),
        ));
        let (problem, plain) = explain_identity(&text);
        assert_eq!(problem, IdentityProblem::Busy);
        assert_eq!(
            says(&plain),
            (
                "Another Raven program is using your identity right now.",
                "Wait a minute, then open Raven again.",
                Action::Wait
            )
        );
    }

    #[test]
    fn identity_other() {
        // A real one: the data folder is a file, so the lock can't be taken.
        testkit::lab_backends();
        let dir = tempfile::tempdir().expect("tempdir");
        let not_a_dir = dir.path().join("profile");
        std::fs::write(&not_a_dir, b"not a folder").expect("write");
        let bridge::IdentityLoad::Unavailable(text) = bridge::load_identity(&not_a_dir) else {
            panic!("a file is not a profile");
        };
        let (problem, plain) = explain_identity(&text);
        assert_eq!(problem, IdentityProblem::Other, "{text}");
        assert_eq!(
            says(&plain),
            (
                "Raven can't read its identity on this computer.",
                "Press D for details.",
                Action::None
            )
        );
        assert_eq!(plain.technical, text.trim());
    }

    /// A profile with no identity: cli.rs's contact functions need none.
    fn book() -> tempfile::TempDir {
        testkit::lab_backends();
        testkit::short_dir()
    }

    /// Someone with a fixed key: (address, pub_hex, security code).
    fn someone(seed: u8) -> (String, String, String) {
        let me = bridge::me_view(&Identity::from_seed(&[seed; 32]));
        (me.address, me.pub_hex, me.fingerprint)
    }

    fn add(dir: &Path, seed: u8, name: &str, typed: Option<&str>) -> Result<(), String> {
        let (address, pub_hex, _) = someone(seed);
        bridge::add_contact_with_routes(dir, &address, &pub_hex, name, "", typed, "", "", None)
    }

    /// Neither the code nor any of its groups.
    fn assert_no_code(text: &str, code: &str) {
        for part in std::iter::once(code).chain(code.split('-')) {
            assert!(!text.contains(part), "{part} of {code} is in: {text}");
        }
    }

    #[test]
    fn contact_add_code_mismatch_hides_the_real_code() {
        let dir = book();
        let (_, _, code) = someone(0x51);
        let err = add(dir.path(), 0x51, "Bob", Some("AAAA-BBBB-CCCC")).unwrap_err();
        assert!(
            !err.contains(&code),
            "cli.rs never names the key's code: {err}"
        );
        let plain = explain_contact_add(&err);
        assert_eq!(
            says(&plain),
            (
                "That doesn't match. Do not verify: someone may have swapped your friend's key.",
                "Check you pasted the right invite, or save your friend as not verified.",
                Action::Verify
            )
        );
        assert_no_code(&plain.technical, &code);
        assert!(plain.technical.contains(controller::HIDDEN_CODE));
        // What the user typed stays (as its shape): it's theirs.
        assert!(
            plain.technical.contains("is not this key's code"),
            "{}",
            plain.technical
        );
    }

    #[test]
    fn contact_add_code_case_only() {
        let dir = book();
        let (_, _, code) = someone(0x52);
        let err = add(dir.path(), 0x52, "Bob", Some(&code.to_lowercase())).unwrap_err();
        let plain = explain_contact_add(&err);
        assert_eq!(
            says(&plain),
            (
                "Upper and lower case differ: codes are case-sensitive (W is not w).",
                "Nothing was saved.",
                Action::Verify
            )
        );
        assert_no_code(&plain.technical, &code);
    }

    #[test]
    fn contact_add_words_refused_never_shows_the_expected_words() {
        let dir = book();
        let bob = bridge::me_view(&Identity::from_seed(&[0x53; 32]));
        let eve = bridge::me_view(&Identity::from_seed(&[0x54; 32]));
        let err = add(dir.path(), 0x53, "Bob", Some(&eve.words.join(" "))).unwrap_err();
        let plain = explain_contact_add(&err);
        assert_eq!(
            says(&plain),
            (
                "These are real Raven words, but not your friend's. Do not verify: someone may \
                 have swapped your friend's key.",
                "Check you pasted the right invite, or save your friend as not verified.",
                Action::Verify
            )
        );
        assert!(!plain.technical.contains(&bob.words.join(" ")));
        // Nine words: not accepted, and nothing of Bob's.
        let err = add(dir.path(), 0x53, "Bob", Some(&bob.words[..9].join(" "))).unwrap_err();
        let plain = explain_contact_add(&err);
        assert_eq!(
            plain.headline,
            "These aren't 10 Raven words that fit together, so nothing was saved."
        );
        assert!(
            !plain.technical.contains(&bob.words.join(" ")),
            "{}",
            plain.technical
        );
    }

    #[test]
    fn contact_add_key_change() {
        let plain = explain_contact_add("KEY_CHANGE_REFUSED_WITHOUT_REPIN");
        assert_eq!(
            plain.headline,
            "You verified this person with a different key, so nothing was saved."
        );
        assert_eq!(plain.action, Action::None);
    }

    #[test]
    fn contact_add_name_taken() {
        let dir = book();
        add(dir.path(), 0x53, "Bob", None).expect("the first Bob");
        let err = add(dir.path(), 0x54, "bob", None).unwrap_err();
        let plain = explain_contact_add(&err);
        assert_eq!(
            says(&plain),
            (
                "You already have a friend called bob.",
                "Pick another name.",
                Action::None
            )
        );
        // The other friend isn't verified: their code is out of Details too.
        assert_no_code(&plain.technical, &someone(0x53).2);
        let tag = explain_contact_add(
            "choose a distinct --petname (e.g. \"Bike club\") — never silent pick. Petnames \
             stay on this computer and in your shell history; a nickname is safer.",
        );
        assert_eq!(tag.headline, "Another friend already uses this name.");
    }

    #[test]
    fn contact_add_the_controllers_own_refusals() {
        for (text, headline) in [
            (controller::NO_NAME, "Give your friend a name."),
            (controller::OWN_KEY, "That's your own invite."),
            (
                controller::NOT_SAVED,
                "That friend isn't saved on this computer anymore.",
            ),
            (
                "contact not found for lan_dial update",
                "That friend isn't saved on this computer anymore.",
            ),
            (
                controller::NO_IDENTITY,
                "Raven has no identity on this computer yet.",
            ),
        ] {
            assert_eq!(explain_contact_add(text).headline, headline, "{text}");
        }
    }

    #[test]
    fn contact_add_tampered() {
        let dir = book();
        let (address, _, _) = someone(0x55);
        let (_, other_key, _) = someone(0x56);
        let err = bridge::add_contact_with_routes(
            dir.path(),
            &address,
            &other_key,
            "Bob",
            "",
            None,
            "",
            "",
            None,
        )
        .unwrap_err();
        assert_eq!(
            says(&explain_contact_add(&err)),
            (
                "This invite doesn't add up: its address and key don't match.",
                "Ask your friend to send it again.",
                Action::None
            ),
            "{err}"
        );
    }

    #[test]
    fn contact_add_not_a_card() {
        let dir = book();
        let (address, _, _) = someone(0x57);
        let err = bridge::add_contact_with_routes(
            dir.path(),
            &address,
            "zz",
            "Bob",
            "",
            None,
            "",
            "",
            None,
        )
        .unwrap_err();
        assert_eq!(
            explain_contact_add(&err).headline,
            "That doesn't look like a Raven invite or card.",
            "{err}"
        );
    }

    #[test]
    fn contact_add_bad_lan_address() {
        let err = bridge::parse_lan_dial("my laptop").unwrap_err();
        assert_eq!(
            says(&explain_contact_add(&err)),
            (
                "That isn't an address Raven can use.",
                "It looks like 192.168.1.30:7420.",
                Action::EditAddress
            ),
            "{err}"
        );
    }

    #[test]
    fn contact_add_bad_other_route() {
        let dir = book();
        let (address, pub_hex, _) = someone(0x58);
        let err = bridge::add_contact_with_routes(
            dir.path(),
            &address,
            &pub_hex,
            "Bob",
            "",
            None,
            "",
            "two words:7420",
            None,
        )
        .unwrap_err();
        assert_eq!(
            explain_contact_add(&err).headline,
            "The invite has an address Raven can't use.",
            "{err}"
        );
        let bad = bridge::P2pView {
            peer_id: "not-a-peer-id".into(),
            via: Vec::new(),
            next: None,
        };
        let err = bridge::add_contact_with_routes(
            dir.path(),
            &address,
            &pub_hex,
            "Bob",
            "",
            None,
            "",
            "",
            Some(&bad),
        )
        .unwrap_err();
        assert_eq!(
            explain_contact_add(&err).headline,
            "The invite has an address Raven can't use.",
            "{err}"
        );
    }

    #[test]
    fn contact_add_unreadable_friends_list() {
        let dir = book();
        std::fs::write(bridge::contacts_path(dir.path()), b"{ not json").expect("write");
        let err = bridge::contact_views(dir.path()).unwrap_err();
        assert_eq!(
            says(&explain_contact_add(&err)),
            (
                "Your friends list can't be read.",
                "Press D for details.",
                Action::None
            ),
            "{err}"
        );
    }

    #[test]
    fn contact_add_block_list() {
        let dir = book();
        let (_, pub_hex, code) = someone(0x59);
        let err = bridge::cmd_contact_unblock(dir.path(), &pub_hex).unwrap_err();
        let plain = explain_contact_add(&err);
        assert_eq!(plain.headline, "That friend isn't blocked.", "{err}");
        assert_no_code(&plain.technical, &code);
        let unreadable = explain_contact_add("block list: expected value at line 1 column 1");
        assert_eq!(unreadable.headline, "Your block list can't be read.");
    }

    #[test]
    fn contact_add_other() {
        let plain = explain_contact_add("atomic write: disk I/O error");
        assert_eq!(
            says(&plain),
            (
                "Raven couldn't save this change.",
                "Press D for details.",
                Action::None
            )
        );
    }

    #[test]
    fn only_code_shaped_words_are_hidden() {
        let hidden = controller::HIDDEN_CODE;
        assert_eq!(
            hide_security_codes("got If4x-36FU-omFi, expected x"),
            format!("got {hidden}, expected x")
        );
        // A last group of 1 to 4.
        assert_eq!(
            hide_security_codes("fp=Ab3d-Ef9h-K"),
            format!("fp={hidden}")
        );
        for kept in [
            "2026-10-16",
            "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
            "If4x-36FU-omFiX",
            "xIf4x-36FU-omFi",
            "If4x-36FU-omFi-",
            "192.168.1.20:7420",
        ] {
            assert_eq!(hide_security_codes(kept), kept);
        }
        // Hiding twice changes nothing more.
        let once = hide_security_codes("got If4x-36FU-omFi");
        assert_eq!(hide_security_codes(&once), once);
    }

    #[test]
    fn node_start_without_a_passphrase_file_needs_one() {
        let alone = "keystore passphrase unavailable: this profile's keys are in a \
                     passphrase-protected vault (/home/a/.raven/keystore.vault) and this \
                     program cannot ask for the passphrase. Set \
                     RAVEN_KEYSTORE_PASSPHRASE_FILE=<file>";
        let in_log = format!(
            "raven-node service exited during startup (exit status: 1)\n  service output:\n    \
             identity: secure store unavailable: passphrase vault: {alone}\n  full log: \
             /home/a/.raven/raven-node-service.log"
        );
        for text in [alone, in_log.as_str()] {
            assert_eq!(
                explain_node_start(text),
                NodeStartProblem::NeedsPassphraseFile,
                "{text}"
            );
            assert_eq!(
                says(&explain_node_unavailable(text)),
                (
                    "Raven's background program can't start on this computer yet: it needs your \
                     passphrase in a private file.",
                    "Press N to see how.",
                    Action::OpenNetwork
                )
            );
        }
    }

    #[test]
    fn node_start_failures() {
        let cases = [
            (
                "could not start /opt/raven/raven-node (No such file or directory (os error 2)); \
                 build or install raven-node next to ash",
                "Raven's background program is missing.",
                Action::None,
            ),
            (
                "raven-node service did not answer IPC within 20s (it is still running as \
                 process 4242; retry shortly, or stop only this one with: kill 4242)",
                "Raven's background program is still starting.",
                Action::Wait,
            ),
            (
                "local raven-node service is running but is not answering IPC (profile /p; it \
                 holds /p/raven-node.lock): it may be wedged",
                "Raven's background program is running but not answering.",
                Action::OpenNetwork,
            ),
            (
                "raven-node service exited during startup (exit status: 1)\n  service output:\n    \
                 failed to bind 0.0.0.0:7420: Address already in use\n  hint: another process \
                 holds the LAN port; set RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0",
                "Another program is using the network port Raven listens on.",
                Action::OpenNetwork,
            ),
            (
                "raven-node service exited during startup (exit status: 1)\n  hint: disk is full: \
                 RAVEN cannot save to /p until at least 50 MB of free space is available",
                "This computer's disk is full.",
                Action::Retry,
            ),
            (
                "raven-node service exited during startup (exit status: 1)\n  service output:\n    \
                 identity: secure store unavailable: keychain get status -25293",
                "Raven wasn't allowed to read its keys from the system keychain.",
                Action::Retry,
            ),
            (
                "raven-node service exited during startup (signal: 9)",
                "Raven's background program stopped while starting.",
                Action::OpenNetwork,
            ),
            (
                "could not poll the raven-node service: permission denied",
                "Raven's background program couldn't start.",
                Action::OpenNetwork,
            ),
        ];
        for (text, headline, action) in cases {
            let NodeStartProblem::Failed(plain) = explain_node_start(text) else {
                panic!("{text}");
            };
            assert_eq!(
                (plain.headline.as_str(), plain.action),
                (headline, action),
                "{text}"
            );
            assert_eq!(plain.technical, text);
        }
    }
}
