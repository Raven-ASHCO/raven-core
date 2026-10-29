//! Friend custody and friend mailboxes in the CLI (Phase 3 item 3, P3.21):
//! `raven node custody on` (holding mail for friends, with its consent),
//! `raven custody use|home|status` (leaving mail with friends and
//! collecting your own), and the ask-once mailbox question at the end of
//! `raven status` and after a queued send. Phase 5 P5.22: `raven node
//! custody handoff on|off` (multi-hop custody), the handoff counts of `raven
//! node custody status`, `raven contact show` and the offline delivery
//! coverage of `raven doctor`.
//!
//! Everything here edits local files only (node_policy.json and its sealed
//! sidecar, through `save_policy`) or reads what raven-node wrote
//! (learned_routes.json, custody_home.json, the custody and handoff stores,
//! its status over IPC). raven-node applies the choices on its next pass;
//! nothing here dials anybody.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use raven_core::clock::now_ms;
use raven_core::custody_client::handoff::announced_from;
use raven_core::custody_client::{
    announced_custodians, custodian_usable, custody_plan, deposit_custodians, listed_custodians,
    Announced, HandoffParked, PlanStep,
};
use raven_core::custody_gate::{
    custody_hints_live, handoff_live, CustodyGates, CUSTODY_HOLD, HANDOFF_HOLD, OFFER_REACHABLE,
    OFFER_WAN,
};
use raven_core::custody_handoff::{HandoffStore, HandoffUsage};
use raven_core::custody_home::{self, DRAIN_MS, MAX_HOME};
use raven_core::friend_custody::{CustodyStore, MAX_NODE_BYTES, MAX_PAIR_ROWS};
use raven_core::ipc::{IpcRequest, IpcResponse};
use raven_core::node_policy::{try_load_policy, update_policy, NodePolicy};
use raven_core::outbox::{contact_admission, pinned_unblocked_contacts, ContactAdmission};
use raven_core::sanitize::sanitize_terminal_line;

use super::{
    discard_pending_tty_input, load_contacts, no_contact_message, read_line_opt,
    resolve_contact_arg, stdin_is_tty, try_load_identity, Contact, C_DIM, C_GREEN, C_PURPLE,
    C_RESET,
};

/// What a custody command failed with, and the exit code: 2 when it needs
/// `--yes` (no terminal to ask on), 1 otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Refusal {
    pub code: i32,
    pub text: String,
}

impl From<String> for Refusal {
    fn from(text: String) -> Self {
        Self { code: 1, text }
    }
}

/// Print what a custody command says, or its refusal and exit with its code.
pub(super) fn exit_on_refusal(result: Result<Vec<String>, Refusal>) {
    match result {
        Ok(lines) => print_said(&lines),
        Err(r) => {
            eprintln!("{}", sanitize_terminal_line(&r.text));
            std::process::exit(r.code);
        }
    }
}

/// The first line plain (`ok` in green), `note:` lines in purple, the rest
/// dim (as the relay commands print).
fn print_said(lines: &[String]) {
    for (i, line) in lines.iter().enumerate() {
        if i == 0 {
            match line.strip_prefix("ok") {
                Some(rest) => println!("{C_GREEN}ok{C_RESET}{rest}"),
                None => println!("{line}"),
            }
        } else if let Some(rest) = line.strip_prefix("note:") {
            println!("{C_PURPLE}note{C_RESET}:{rest}");
        } else {
            println!("{C_DIM}{line}{C_RESET}");
        }
    }
}

fn policy_for_edit(data_dir: &Path) -> Result<NodePolicy, String> {
    try_load_policy(data_dir).map_err(|e| {
        format!(
            "node_policy.json is unreadable ({}); fix or move it aside first (nothing changed)",
            sanitize_terminal_line(&e.to_string())
        )
    })
}

/// Save one change to the policy as it is on disk now (review D-6): a
/// question that waited on the user never writes back an older copy of the
/// other settings (a `raven lan off` made meanwhile, say). What was saved.
pub(super) fn update(
    data_dir: &Path,
    change: impl FnOnce(&mut NodePolicy),
) -> Result<NodePolicy, String> {
    update_policy(data_dir, change).map_err(|e| format!("save policy failed: {e}"))
}

/// `y` / `yes` (any case) is yes; Enter, EOF or anything else is no.
pub(super) fn said_yes(answer: Option<String>) -> bool {
    answer.is_some_and(|a| {
        let a = a.trim();
        a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes")
    })
}

/// Both stdin and stdout are a terminal: someone sees the question.
fn terminal() -> bool {
    stdin_is_tty() && io::stdout().is_terminal() && !cfg!(test)
}

/// Ask `question` on the terminal (a trust decision: lines of an earlier
/// paste never answer it); the answer line, or `None` at EOF.
pub(super) fn ask_on_terminal(question: &str) -> Option<String> {
    discard_pending_tty_input();
    print!("{question}");
    let _ = io::stdout().flush();
    read_line_opt()
}

const TURN_ON: &str = "Turn on? [y/N] ";

// ── raven node custody on: holding mail for friends ─────────────────────────

/// What `raven node custody on` asks (Phase 3 item 3, custody consent (a)):
/// what this computer learns as a custodian (both Raven identities, timing,
/// size, collection time and, over the internet, IP addresses), and the
/// limits. P3.C4 (people study M12): it says what is kept and for how long.
/// Owner decision OD-C11 / OD-PP-6 (a) is taken, so its errata draft
/// (`docs/SECURITY_ERRATA_RULE9_CUSTODY_RELEASE_AMENDMENT_DRAFT.md`, PP.17)
/// applies: a message stays until the recipient's RELEASE (sent once its
/// Raven has it, not on the fetch itself) or until it expires; the signed
/// envelopes make what is held proof of who wrote to whom. Phase 5 P5.16:
/// sealed letters, held up to 7 days, signed by their writer.
pub(super) const CUSTODIAN_CONSENT: &str = "\
Hold sealed messages for your friends while they are offline?
- Only between two people who are both your verified contacts.
- What this computer keeps for them is sealed: you can't read it.
- It does learn, for every message it holds, who sent it and who it is for
  (both Raven identities), when, how big, and when it was collected. Over the
  internet it also sees the IP address each friend connects from (or their relay's).
- Each message stays until the recipient's Raven confirms it collected it, or
  until it expires (at most 24 hours). Deleting clears Raven's file; full-disk
  encryption protects what the disk itself may still hold.
- It also holds letters: sealed messages held up to 7 days, for a friend away
  longer than a day. A letter stays until its recipient's Raven confirms it
  collected it, its writer takes it back, or it expires; it is signed by its
  writer, so it is proof of who wrote to whom too.
- The envelopes are signed, so while this computer holds a message it holds
  proof of who wrote to whom, when, and how much.
- At most 128 messages per pair at a time, 64 MiB in all.";

/// Off a terminal without `--yes`: nothing is asked and nothing changes.
pub(super) const CUSTODY_NEEDS_YES: &str = "friend custody needs your consent and stdin is not a \
    terminal: add --yes to turn it on without the question (nothing changed)";

/// `raven node custody on [--yes]` with the terminal check and the question
/// passed in; returns what to print. On a terminal it shows
/// [`CUSTODIAN_CONSENT`] and asks: only `y` / `yes` turns it on; Enter, EOF
/// or anything else changes nothing. Off a terminal it needs `--yes`
/// (exit 2). `--yes` prints the consent as what was agreed to. AUTO and
/// the other policy flags are kept.
pub(super) fn custody_on_with(
    data_dir: &Path,
    yes: bool,
    tty: bool,
    ask: impl FnOnce(&str) -> Option<String>,
) -> Result<Vec<String>, Refusal> {
    if !yes && !tty {
        return Err(Refusal {
            code: 2,
            text: CUSTODY_NEEDS_YES.into(),
        });
    }
    let policy = policy_for_edit(data_dir)?;
    if !yes && !said_yes(ask(&format!("{CUSTODIAN_CONSENT}\n{TURN_ON}"))) {
        return Ok(vec![format!(
            "nothing changed: friend custody stays {}",
            if policy.custody { "on" } else { "off" }
        )]);
    }
    update(data_dir, |p| p.custody = true)?;
    let mut lines = vec!["ok friend custody on".to_string()];
    if yes {
        // Scripts: the log keeps what was agreed to.
        lines.extend(CUSTODIAN_CONSENT.lines().skip(1).map(str::to_string));
    }
    if !CustodyGates::current().live {
        lines.push(format!("note: {CUSTODY_HOLD}"));
    }
    Ok(lines)
}

/// `raven node custody on [--yes]`.
pub(super) fn cmd_node_custody_on(data_dir: &Path, yes: bool) {
    exit_on_refusal(custody_on_with(data_dir, yes, terminal(), ask_on_terminal));
}

/// The follow-up after a yes to the relay-offer question (Phase 2), asked
/// only while friend custody is off and its gate is live. It turns on the
/// same thing `raven node custody on` does, so it says everything
/// [`CUSTODIAN_CONSENT`] says (P3.C4; review D-4): what is kept, for how
/// long, the signed proof, the metadata and the limits.
pub(super) fn relay_custody_follow_up_question() -> String {
    let what: Vec<&str> = CUSTODIAN_CONSENT.lines().skip(1).collect();
    format!(
        "This computer can also hold sealed messages for your friends while they are offline.\n\
         {}\nTurn that on too? [y/N] ",
        what.join("\n")
    )
}

/// After a yes to the relay offer: ask
/// [`relay_custody_follow_up_question`] while custody is off and live, and
/// save a yes. `None` when nothing was asked.
pub(super) fn relay_custody_follow_up(
    data_dir: &Path,
    policy: &mut NodePolicy,
    ask: impl FnOnce(&str) -> Option<String>,
) -> Result<Option<Vec<String>>, String> {
    if policy.custody || !CustodyGates::current().live {
        return Ok(None);
    }
    if !said_yes(ask(&relay_custody_follow_up_question())) {
        return Ok(Some(vec![
            "not holding mail for your friends (`raven node custody on` to change it)".into(),
        ]));
    }
    *policy = update(data_dir, |p| p.custody = true)?;
    Ok(Some(vec![
        "friend custody on: this computer holds sealed messages for your verified friends \
         (`raven node custody status` shows how many; `raven node custody off` stops it)."
            .into(),
    ]))
}

// ── raven custody use: friends as mailboxes ─────────────────────────────────

/// The one mailbox question (custody consent (b)): leaving copies with
/// friends and collecting your own mail from them, with what a friend's
/// Raven learns and how long its signed copy stays (P3.C4), and what the
/// regular collecting shows a mail friend (review D-9: when this node is
/// online, and from the size of each request about how many contacts it
/// has a live session with). Phase 5 P5.16: a letter for a contact away
/// longer than a day, held up to 7 days, and what its holder learns.
pub(super) const MAILBOX_QUESTION: &str = "\
Use friends as mailboxes?
When a contact cannot be reached, raven-node can leave a sealed copy of your
message with a friend you have both verified, and collect mail left for you
with friends who offer to hold it. A friend's Raven can't read your messages,
but it learns that you wrote to someone, to whom, and when. It also sees both
Raven identities and how big each message is, and who wrote to you for mail
left for you. The envelopes are signed, so its copy is proof of who wrote to
whom until it is deleted: once collected, or when it expires (at most 24 hours).
For a contact away longer than a day it may leave a letter instead: sealed
messages held up to 7 days. Your friend can't read it, but knows you wrote to
that contact, and when; the letter is signed by you.
Your mail friends also see when your Raven checks in with them (every few
minutes while it runs) and about how many of your contacts you are in touch with.
Turn on? [y/N] ";

/// Off a terminal without `--yes`.
pub(super) const MAILBOX_NEEDS_YES: &str = "friend mailboxes need your consent and stdin is not \
    a terminal: add --yes to turn them on without the question (nothing changed)";

/// What to save for friend mailboxes, and whether it asked (a copy of
/// `raven node p2p on`'s UPnP decision). A flag (`--yes` for on, `off`)
/// decides without asking; an answer saved before is kept and never asked
/// again; a run that is not on a terminal asks nothing and leaves it unset
/// (no mailboxes); otherwise the question is asked exactly once: `y`/`yes`
/// is on, Enter, EOF or anything else is off.
pub(super) fn custody_use_decision(
    saved: Option<bool>,
    flag: Option<bool>,
    tty: bool,
    ask: impl FnOnce() -> Option<String>,
) -> (Option<bool>, bool) {
    if flag.is_some() {
        return (flag, false);
    }
    if saved.is_some() {
        return (saved, false);
    }
    if !tty {
        return (None, false);
    }
    (Some(said_yes(ask())), true)
}

/// Hours a dropped mail friend is still collected from ([`DRAIN_MS`]).
fn drain_hours() -> u64 {
    DRAIN_MS / 3_600_000
}

/// `raven custody use off`: `listed` contacts still have friends listed
/// for them by hand (`raven contact set-addr --custodian`), a consent of its
/// own that `off` does not cover (review D-5).
fn mailbox_off_text(listed: usize) -> Vec<String> {
    let mut lines = vec![format!(
        "ok friend mailboxes off: nothing new is left with your mail friends; mail already left \
         for you is still collected for up to {} h.",
        drain_hours()
    )];
    if listed > 0 {
        lines.push(listed_note(listed));
    }
    lines
}

/// What still uses friends listed by hand for `listed` contacts.
fn listed_note(listed: usize) -> String {
    format!(
        "note: {listed} contact{} still use{} the friends you listed for {} by hand: messages are \
         left with them and mail is collected from them (`raven contact set-addr --custodian` \
         changes that).",
        if listed == 1 { "" } else { "s" },
        if listed == 1 { "s" } else { "" },
        if listed == 1 { "it" } else { "them" }
    )
}

/// The contacts with friends listed by hand for them
/// (`raven contact set-addr --custodian`): how many. An unreadable book
/// counts nothing.
fn listed_contacts(data_dir: &Path, local: &[u8; 32]) -> usize {
    let Ok(contacts) = load_contacts(data_dir) else {
        return 0;
    };
    let mut seen = std::collections::HashSet::new();
    contacts
        .iter()
        .filter(|c| !c.custodians.is_empty())
        .filter_map(key_of)
        .filter(|k| seen.insert(*k))
        .filter(|k| {
            raven_core::custody_client::listed_custodians(data_dir, k, local)
                .is_ok_and(|l| !l.is_empty())
        })
        .count()
}

/// This profile's own key; zeros when it has none yet.
fn local_key(data_dir: &Path) -> [u8; 32] {
    try_load_identity(data_dir)
        .ok()
        .flatten()
        .map(|id| id.public_key_bytes())
        .unwrap_or([0; 32])
}

/// While learned custody is held in this build.
fn mailbox_held_note() -> String {
    format!(
        "note: friend mailboxes are lab-only in this build ({CUSTODY_HOLD}; they also need route \
         hints): raven-node keeps them off until they are enabled."
    )
}

/// What a saved mailbox answer says.
fn mailbox_answer_lines(choice: Option<bool>) -> Vec<String> {
    match choice {
        Some(true) => {
            let mut lines = vec![
                "ok friend mailboxes on: when a contact cannot be reached, raven-node leaves a \
                 sealed copy with a friend you both verified, and collects mail left for you."
                    .to_string(),
                "`raven custody status` shows your mail friends; `raven custody use off` stops it."
                    .to_string(),
            ];
            if !custody_hints_live() {
                lines.push(mailbox_held_note());
            }
            lines
        }
        Some(false) => vec![
            "ok: friend mailboxes stay off (change it any time with `raven custody use on`)".into(),
        ],
        None => Vec::new(),
    }
}

/// `raven custody use on|off|status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UseArg {
    On { yes: bool },
    Off,
    Status,
}

/// `raven custody use …` with the terminal check and the question passed
/// in; returns what to print.
pub(super) fn custody_use_with(
    data_dir: &Path,
    arg: UseArg,
    tty: bool,
    ask: impl FnOnce(&str) -> Option<String>,
) -> Result<Vec<String>, Refusal> {
    match arg {
        UseArg::Status => Ok(custody_status_rows(&gather_facts(data_dir))),
        UseArg::Off => {
            policy_for_edit(data_dir)?;
            update(data_dir, |p| p.custody_use = Some(false))?;
            Ok(mailbox_off_text(listed_contacts(
                data_dir,
                &local_key(data_dir),
            )))
        }
        UseArg::On { yes } => {
            let policy = policy_for_edit(data_dir)?;
            if policy.custody_use == Some(true) && !yes {
                return Ok(vec![
                    "friend mailboxes are on already (`raven custody use off` stops them)".into(),
                ]);
            }
            // An explicit `on` asks again whatever was saved before.
            let (choice, _) =
                custody_use_decision(None, yes.then_some(true), tty, || ask(MAILBOX_QUESTION));
            if choice.is_none() {
                return Err(Refusal {
                    code: 2,
                    text: MAILBOX_NEEDS_YES.into(),
                });
            }
            update(data_dir, |p| p.custody_use = choice)?;
            Ok(mailbox_answer_lines(choice))
        }
    }
}

/// `raven custody use on|off|status`.
pub(super) fn cmd_custody_use(data_dir: &Path, arg: UseArg) {
    exit_on_refusal(custody_use_with(data_dir, arg, terminal(), ask_on_terminal));
}

/// The pinned, unblocked contacts (keys) that offer to hold mail, with
/// their offer flags.
fn offering_friends(data_dir: &Path, now: u64) -> Vec<([u8; 32], u8)> {
    let Ok(book) = pinned_unblocked_contacts(data_dir) else {
        return Vec::new();
    };
    let learned = raven_core::learned_routes::learned_custody_all(data_dir, now);
    book.iter()
        .filter_map(|c| Some((*c, learned.get(c)?.offer?)))
        .collect()
}

/// The mailbox question is due: never answered, learned custody is live and
/// at least one verified friend offers to hold mail.
fn mailbox_due(data_dir: &Path, policy: &NodePolicy) -> bool {
    policy.custody_use.is_none()
        && custody_hints_live()
        && !offering_friends(data_dir, now_ms()).is_empty()
}

/// The end of `raven status` (after the relay offer, which comes first):
/// the mailbox question once, when [`mailbox_due`]. `None` when nothing
/// was asked.
pub(super) fn mailbox_prompt(
    data_dir: &Path,
    policy: &mut NodePolicy,
    tty: bool,
    ask: impl FnOnce(&str) -> Option<String>,
) -> Result<Option<Vec<String>>, String> {
    if !mailbox_due(data_dir, policy) {
        return Ok(None);
    }
    let (choice, asked) =
        custody_use_decision(policy.custody_use, None, tty, || ask(MAILBOX_QUESTION));
    if !asked {
        return Ok(None);
    }
    *policy = update(data_dir, |p| p.custody_use = choice)?;
    Ok(Some(mailbox_answer_lines(choice)))
}

/// `peer` announced a mail friend this node also has as a verified,
/// unblocked contact (its custodian tags, or Phase 2's plain keys).
pub(super) fn mailbox_match(data_dir: &Path, local: &[u8; 32], peer: &[u8; 32]) -> bool {
    let learned = raven_core::learned_routes::learned_custody_all(data_dir, now_ms());
    let Some(told) = learned.get(peer) else {
        return false;
    };
    if told.tags.is_empty() && told.plain.is_empty() {
        return false;
    }
    pinned_unblocked_contacts(data_dir)
        .unwrap_or_default()
        .iter()
        .filter(|c| *c != peer && *c != local)
        .any(|c| {
            told.tags
                .contains(&raven_core::route_hints::custodian_tag(peer, local, c))
                || told.plain.contains(c)
        })
}

/// After a send to `peer` was queued: the mailbox question once, on a
/// terminal, while it was never answered and `peer` announced a mail
/// friend this node knows ([`mailbox_match`]). Quiet otherwise.
pub(super) fn mailbox_after_queued(data_dir: &Path, local: &[u8; 32], peer_pub_hex: &str) {
    if !terminal() {
        return;
    }
    let Ok(policy) = try_load_policy(data_dir) else {
        return;
    };
    let Ok(peer) = <[u8; 32]>::try_from(hex::decode(peer_pub_hex.trim()).unwrap_or_default())
    else {
        return;
    };
    if policy.custody_use.is_some()
        || !custody_hints_live()
        || !mailbox_match(data_dir, local, &peer)
    {
        return;
    }
    let (choice, asked) = custody_use_decision(None, None, true, || {
        println!();
        ask_on_terminal(MAILBOX_QUESTION)
    });
    if !asked {
        return;
    }
    match update(data_dir, |p| p.custody_use = choice) {
        Ok(_) => print_said(&mailbox_answer_lines(choice)),
        Err(e) => eprintln!("{}", sanitize_terminal_line(&e)),
    }
}

// ── raven custody home ──────────────────────────────────────────────────────

/// `raven custody home @a [@b] | auto` with this node's key (`local`, hex;
/// empty: none) passed in; returns what to print. Each must be a verified,
/// unblocked contact other than you, at most [`MAX_HOME`]; `auto` lets
/// raven-node pick. Saved with `save_policy` (the list names friends: a
/// sealed profile keeps it in the sealed sidecar). Nothing changes on any
/// refusal.
pub(super) fn custody_home_with(
    data_dir: &Path,
    local: &str,
    who: &[String],
) -> Result<Vec<String>, String> {
    let auto = who.len() == 1 && who[0].trim().eq_ignore_ascii_case("auto");
    if !auto && who.iter().any(|w| w.trim().eq_ignore_ascii_case("auto")) {
        return Err("`auto` stands alone: `raven custody home auto` (nothing changed)".into());
    }
    policy_for_edit(data_dir)?;
    let mut lines = Vec::new();
    let policy = if auto {
        let policy = update(data_dir, |p| p.custody_home.clear())?;
        lines.push(format!(
            "ok mail friends: automatic (raven-node picks up to {MAX_HOME} verified friends who \
             offer to hold mail)"
        ));
        policy
    } else {
        let picked = home_picks(data_dir, local, who)?;
        let home: Vec<String> = picked
            .iter()
            .map(|c| c.pub_hex.to_ascii_lowercase())
            .collect();
        let policy = update(data_dir, |p| p.custody_home = home)?;
        let names: Vec<String> = picked.iter().map(Contact::primary_label).collect();
        lines.push(format!("ok mail friends: {}", names.join(", ")));
        let offering: Vec<[u8; 32]> = offering_friends(data_dir, now_ms())
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        for c in &picked {
            if !key_of(c).is_some_and(|k| offering.contains(&k)) {
                lines.push(format!(
                    "note: {} does not offer to hold mail right now: nothing is left with them \
                     until they run `raven node custody on`.",
                    c.primary_label()
                ));
            }
        }
        policy
    };
    if policy.custody_use != Some(true) {
        lines.push(
            "note: friend mailboxes are off: `raven custody use on` to use them.".to_string(),
        );
    }
    Ok(lines)
}

fn key_of(c: &Contact) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(c.pub_hex.trim()).ok()?).ok()
}

/// The contacts `who` names, checked: one match each, verified, unblocked,
/// not you; duplicates once; at most [`MAX_HOME`].
fn home_picks(data_dir: &Path, local: &str, who: &[String]) -> Result<Vec<Contact>, String> {
    let contacts = load_contacts(data_dir)?;
    let mut picked: Vec<Contact> = Vec::new();
    for sel in who {
        let hits = resolve_contact_arg(&contacts, sel);
        let one: Contact = match hits.as_slice() {
            [one] => (*one).clone(),
            [] => return Err(no_contact_message(&contacts, sel)),
            _ => {
                return Err(format!(
                    "{} is ambiguous: use the @tag (nothing changed)",
                    sanitize_terminal_line(sel)
                ))
            }
        };
        if !local.is_empty() && one.pub_hex.trim().eq_ignore_ascii_case(local) {
            return Err("you cannot be your own mail friend (nothing changed)".into());
        }
        let Some(key) = key_of(&one) else {
            return Err(format!(
                "{} has no valid key saved (nothing changed)",
                one.primary_label()
            ));
        };
        match contact_admission(data_dir, &key) {
            ContactAdmission::Allowed(c) if c.pinned => {}
            ContactAdmission::Allowed(_) => {
                return Err(format!(
                    "{} is not verified: only a contact whose fingerprint you checked can hold \
                     your mail (`raven contact verify`; nothing changed)",
                    one.primary_label()
                ))
            }
            ContactAdmission::Blocked => {
                return Err(format!(
                    "{} is blocked (nothing changed)",
                    one.primary_label()
                ))
            }
            ContactAdmission::NotContact | ContactAdmission::Unreadable => {
                return Err(format!(
                    "{} cannot be read from your contacts (nothing changed)",
                    one.primary_label()
                ))
            }
        }
        if !picked
            .iter()
            .any(|p| p.pub_hex.eq_ignore_ascii_case(&one.pub_hex))
        {
            picked.push(one);
        }
    }
    if picked.len() > MAX_HOME {
        return Err(format!(
            "at most {MAX_HOME} mail friends (got {}; nothing changed)",
            picked.len()
        ));
    }
    Ok(picked)
}

/// `raven custody home @a [@b] | auto`.
pub(super) fn cmd_custody_home(data_dir: &Path, who: &[String]) {
    let local = try_load_identity(data_dir)
        .ok()
        .flatten()
        .map(|id| hex::encode(id.public_key_bytes()))
        .unwrap_or_default();
    exit_on_refusal(custody_home_with(data_dir, &local, who).map_err(Refusal::from));
}

// ── raven custody status ────────────────────────────────────────────────────

/// What `raven custody status` shows: counts only, never a friend's name,
/// key or address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CustodyFacts {
    /// `raven custody use` (None: never answered).
    pub consent: Option<bool>,
    /// Mail friends this node collects from now.
    pub home: usize,
    /// Chosen by the user (`raven custody home @a`), not picked by raven-node.
    pub manual: bool,
    /// Dropped mail friends still collected from.
    pub draining: usize,
    /// Verified friends that offer to hold mail.
    pub offering: usize,
    /// ... over the internet too.
    pub offering_wan: usize,
    /// ... and reachable from the internet.
    pub offering_reachable: usize,
    /// `raven node custody on`: this computer holds mail for friends.
    pub holding_on: bool,
    /// What it holds now.
    pub held_rows: i64,
    pub held_bytes: i64,
    /// Learned custody runs in this build ([`custody_hints_live`]).
    pub hints_live: bool,
    /// Contacts with friends listed by hand for them (`raven contact
    /// set-addr --custodian`): used whatever `raven custody use` says.
    pub listed: usize,
}

/// `raven custody status` rows (counts only).
pub(super) fn custody_status_rows(f: &CustodyFacts) -> Vec<String> {
    let s = |n: usize| if n == 1 { "" } else { "s" };
    let mut rows = vec![format!(
        "friend mailboxes   {}",
        match f.consent {
            Some(true) => "on".to_string(),
            Some(false) => "off (`raven custody use on` to use them)".to_string(),
            None => "not decided yet (`raven custody use on` or `off`)".to_string(),
        }
    )];
    let mut friends = if f.consent == Some(true) {
        format!(
            "{} ({})",
            f.home,
            if f.manual {
                "chosen by you"
            } else {
                "picked automatically"
            }
        )
    } else {
        "none".to_string()
    };
    if f.draining > 0 {
        friends.push_str(&format!(
            ", {} more still collected from (up to {} h)",
            f.draining,
            drain_hours()
        ));
    }
    rows.push(format!("mail friends       {friends}"));
    rows.push(format!(
        "offering friends   {} verified friend{} offer{} to hold mail ({} over the internet, {} \
         reachable)",
        f.offering,
        s(f.offering),
        if f.offering == 1 { "s" } else { "" },
        f.offering_wan,
        f.offering_reachable
    ));
    rows.push(format!(
        "holding for others {}: {} sealed message{}, {} bytes",
        if f.holding_on { "on" } else { "off" },
        f.held_rows,
        if f.held_rows == 1 { "" } else { "s" },
        f.held_bytes
    ));
    if f.listed > 0 {
        rows.push(listed_note(f.listed));
    }
    if !f.hints_live {
        rows.push(mailbox_held_note());
    }
    rows
}

/// [`CustodyFacts`] from this profile's files. An unreadable file counts
/// as nothing.
pub(super) fn gather_facts(data_dir: &Path) -> CustodyFacts {
    let now = now_ms();
    let policy = try_load_policy(data_dir).unwrap_or_default();
    let local = local_key(data_dir);
    let home = custody_home::home(data_dir, &local, now);
    let draining = custody_home::fetch_from(data_dir, &local, now)
        .iter()
        .filter(|c| !home.contains(c))
        .count();
    let offers = offering_friends(data_dir, now);
    let (held_rows, held_bytes) = CustodyStore::open_existing(data_dir)
        .ok()
        .flatten()
        .and_then(|s| s.usage().ok())
        .unwrap_or((0, 0));
    CustodyFacts {
        consent: policy.custody_use,
        home: home.len(),
        manual: !policy.custody_home.is_empty(),
        draining,
        offering: offers.len(),
        offering_wan: offers.iter().filter(|(_, f)| f & OFFER_WAN != 0).count(),
        offering_reachable: offers
            .iter()
            .filter(|(_, f)| f & OFFER_REACHABLE != 0)
            .count(),
        holding_on: policy.custody,
        held_rows,
        held_bytes,
        hints_live: custody_hints_live(),
        listed: listed_contacts(data_dir, &local),
    }
}

/// `raven custody status`.
pub(super) fn cmd_custody_status(data_dir: &Path) {
    print_said(&custody_status_rows(&gather_facts(data_dir)));
}

// ── raven node custody handoff: passing mail on between friends ─────────────

/// What `raven node custody handoff on` says (Phase 5 multi-hop custody,
/// owner decision P5-MH-3: one consent flag for both custodian roles, with
/// this disclosure): what this computer does and what it sees in each role.
pub(super) const HANDOFF_DISCLOSURE: &str = "\
This node may pass sealed messages on from a verified contact to another
verified contact (your friend), and hold sealed messages a friend passes on
for someone who asked you to. You cannot read them. When passing on you see
who sent it and which friend it goes to, never the final recipient; when
holding you see the recipient and the friend who brought it, not the sender.";

/// `raven node custody handoff on` while friend custody itself is off.
pub(super) const HANDOFF_NEEDS_CUSTODY: &str = "note: friend custody is off, so nothing is \
    passed on or held yet: handoff works only together with it (`raven node custody on`).";

/// `raven node custody handoff off`: what happens to what is held already.
pub(super) const HANDOFF_OFF_TEXT: &str = "New handoffs are refused from now on; what this \
    computer already took on is still passed on or kept until it expires (`raven node custody \
    off --purge` deletes it now).";

/// `raven node custody handoff on|off` (Phase 5 P5.22): the one consent
/// flag of multi-hop custody (`NodePolicy::custody_handoff`), saved by a
/// setter of its own on top of the policy as it is on disk, so AUTO,
/// bridge, store, relay and custody stay as they are. `on` adds
/// [`HANDOFF_DISCLOSURE`], [`HANDOFF_NEEDS_CUSTODY`] while custody is off
/// and [`HANDOFF_HOLD`] while the handoff gate is closed; `off` adds
/// [`HANDOFF_OFF_TEXT`]. An unreadable node_policy.json changes nothing.
/// What to print.
pub(super) fn handoff_switch(data_dir: &Path, on: bool) -> Result<Vec<String>, String> {
    policy_for_edit(data_dir)?;
    let saved = update(data_dir, |p| p.custody_handoff = on)?;
    let mut lines = vec![format!(
        "ok custody handoff {}",
        if on { "on" } else { "off" }
    )];
    if !on {
        lines.push(HANDOFF_OFF_TEXT.into());
        return Ok(lines);
    }
    lines.extend(HANDOFF_DISCLOSURE.lines().map(str::to_string));
    if !saved.custody {
        lines.push(HANDOFF_NEEDS_CUSTODY.into());
    }
    if !handoff_live() {
        lines.push(format!("note: {HANDOFF_HOLD}"));
    }
    Ok(lines)
}

/// `raven node custody handoff on|off`.
pub(super) fn cmd_node_custody_handoff(data_dir: &Path, on: bool) -> Result<(), String> {
    print_said(&handoff_switch(data_dir, on)?);
    Ok(())
}

/// The handoff rows of `raven node custody status` (Phase 5 P5.22): counts
/// only, read from custody_handoff.sqlite (forward rows waiting, handed on
/// and refused, their bytes, registered tags), shown while handoff is on,
/// the store holds anything or the handoff gate is open, then
/// [`HANDOFF_HOLD`] while handoff is on and its gate closed. Nothing
/// otherwise, so the status reads as before Phase 5. No store is created.
pub(super) fn handoff_status_lines(data_dir: &Path) -> Vec<String> {
    let on = try_load_policy(data_dir).is_ok_and(|p| p.custody_handoff);
    let live = handoff_live();
    let word = if on { "on" } else { "off" };
    let mut lines = Vec::new();
    match HandoffStore::open_existing(data_dir).and_then(|s| s.map(|s| s.usage()).transpose()) {
        Ok(usage) => {
            let u = usage.unwrap_or_default();
            if !on && !live && u == HandoffUsage::default() {
                return lines;
            }
            lines.push(format!(
                "handoff {word}  passing on: {} waiting, {} handed on, {} refused, {} bytes; \
                 registered tags: {}",
                u.pending, u.handed, u.refused, u.bytes, u.tags
            ));
        }
        Err(e) => lines.push(format!(
            "handoff {word}  its store cannot be read ({})",
            sanitize_terminal_line(&e)
        )),
    }
    if on && !live {
        lines.push(HANDOFF_HOLD.to_string());
    }
    lines
}

/// Print [`handoff_status_lines`]: the counts plain, the gate dim.
pub(super) fn print_handoff_status(data_dir: &Path) {
    for (i, line) in handoff_status_lines(data_dir).iter().enumerate() {
        if i == 0 {
            println!("{line}");
        } else {
            println!("{C_DIM}{line}{C_RESET}");
        }
    }
}

/// `raven node custody off --purge` (Phase 5 P5.22): every handoff row and
/// registered tag goes too ([`HandoffStore::purge`]). Records deleted;
/// `None` when there is no handoff store (none is created).
pub(super) fn purge_handoff(data_dir: &Path) -> Result<Option<usize>, String> {
    HandoffStore::open_existing(data_dir)?
        .map(|mut store| store.purge())
        .transpose()
}

// ── offline delivery coverage: raven doctor, raven contact show ─────────────

/// How mail for a verified contact travels while one of you is away
/// (Phase 5 P5.22; owner decision O5-8: the data for the relay-mailbox
/// decision). Each class names its ceiling in plain words (the cutoff
/// addendum's text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Coverage {
    /// No friend can carry it, but a message reached the contact directly
    /// within the last 24 h.
    Direct,
    /// A mail friend both of you use holds it: one this node leaves the
    /// contact's mail with that the contact announced (listed ∩ announced).
    MutualFriend,
    /// Your mail friend passes it on to one the contact collects from and
    /// that takes handoffs for it (multi-hop custody: a FORWARD).
    TwoFriends,
    /// Nobody can carry it: it goes when you meet.
    Nobody,
}

impl Coverage {
    /// `raven doctor`'s order.
    pub(super) const ALL: [Self; 4] = [
        Self::Direct,
        Self::MutualFriend,
        Self::TwoFriends,
        Self::Nobody,
    ];

    /// The `raven doctor` key.
    pub(super) fn token(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::MutualFriend => "mutual_friend",
            Self::TwoFriends => "two_friends",
            Self::Nobody => "none",
        }
    }

    /// The class in plain words.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Direct => "Raven keeps it until you're both online",
            Self::MutualFriend => "a mail friend you share",
            Self::TwoFriends => "two friends in a row",
            Self::Nobody => "nobody can carry it",
        }
    }

    /// How long the contact may be away and still get it.
    pub(super) fn ceiling(self) -> &'static str {
        match self {
            // The long message horizon (Phase 5a) holds it 7 days; without
            // it, until the secure connection ends, a day after the last.
            Self::Direct if raven_core::horizon::horizon_live_enabled() => "for up to 7 days",
            Self::Direct => "for up to a day after you were last connected",
            // E2 r9 #7: the same hold as `raven send` and `raven outbox
            // list` name: the sealed copy's own expiry.
            Self::MutualFriend => {
                "the friend holds a sealed copy until it expires, up to a day (7 days as a letter)"
            }
            Self::TwoFriends => "up to a day",
            Self::Nobody => "it goes when you meet",
        }
    }
}

/// The next step for contacts nobody can carry mail for.
pub(super) const OFFLINE_NEXT_STEP: &str = "ask a friend you both trust to hold mail (raven node \
    custody on), or pin an always-on friend node as custodian";

/// The same while friend custody is held in this build.
pub(super) const OFFLINE_HELD_STEP: &str = "friends cannot hold mail in this build yet (friend \
    custody is lab-only)";

/// A last delivery at most this old (seconds) makes a contact `direct`.
pub(super) const DIRECT_WITHIN_S: u64 = 24 * 3600;

/// The best way mail for `peer` travels while one of you is away, pure:
/// the outbox worker's own plan ([`custody_plan`], without its RFC1 pair
/// parks) over the custodians it would leave `peer`'s mail with (`listed`,
/// [`deposit_custodians`]) and what `peer` announced (`announced`,
/// [`announced_custodians`]). A DEPOSIT at an announced custodian is a
/// mutual friend, a FORWARD two friends; otherwise `direct` (a delivery
/// within [`DIRECT_WITHIN_S`]) or nobody. `handoff_parked` is the worker's
/// handoff park (a custodian, or a custodian and next hop).
pub(super) fn coverage_of(
    peer: &[u8; 32],
    local: &[u8; 32],
    listed: &[[u8; 32]],
    announced: Option<&[Announced]>,
    handoff_live: bool,
    handoff_parked: &HandoffParked<'_>,
    direct: bool,
) -> Coverage {
    let plan = custody_plan(
        listed,
        announced,
        handoff_live,
        peer,
        local,
        &|_| false,
        handoff_parked,
    );
    let shared = |c: &[u8; 32]| announced.is_some_and(|a| a.iter().any(|a| a.key == *c));
    if plan
        .iter()
        .any(|s| matches!(s, PlanStep::Deposit(c) if shared(c)))
    {
        Coverage::MutualFriend
    } else if plan.iter().any(|s| matches!(s, PlanStep::Forward { .. })) {
        Coverage::TwoFriends
    } else if direct {
        Coverage::Direct
    } else {
        Coverage::Nobody
    }
}

/// [`coverage_of`] for `peer` from this profile's files: the custodians
/// the worker would use for it and what it announced (the learned-routes
/// cache), with the handoff gate as this process reads it.
fn coverage_from_files(
    data_dir: &Path,
    local: &[u8; 32],
    peer: &[u8; 32],
    now: u64,
    direct: bool,
    handoff_parked: &HandoffParked<'_>,
) -> Coverage {
    let listed: Vec<[u8; 32]> = deposit_custodians(data_dir, local, peer, now)
        .into_iter()
        .map(|(c, _)| c)
        .collect();
    let announced = announced_custodians(data_dir, local, peer, now);
    coverage_of(
        peer,
        local,
        &listed,
        announced.as_deref(),
        handoff_live(),
        handoff_parked,
        direct,
    )
}

/// The contacts a message reached directly within [`DIRECT_WITHIN_S`]:
/// the running raven-node's last paths (kept in its memory since it
/// started); none while it does not answer.
pub(super) fn direct_contacts(status: &Result<IpcResponse, String>) -> Vec<[u8; 32]> {
    let Ok(IpcResponse::Status { last_paths, .. }) = status else {
        return Vec::new();
    };
    last_paths
        .iter()
        .filter(|p| p.age_s <= DIRECT_WITHIN_S)
        .filter_map(|p| <[u8; 32]>::try_from(hex::decode(p.peer_pub_hex.trim()).ok()?).ok())
        .collect()
}

/// The offline delivery lines of `raven doctor` for the classes of every
/// verified contact (counts only, never a name or a key): one key=value
/// line, each class present with its ceiling, and for `none` the next step
/// (or, while friend custody is held in this build, that friends cannot
/// hold mail yet).
pub(super) fn offline_lines(classes: &[Coverage], custody_live: bool) -> Vec<String> {
    let count = |k: Coverage| classes.iter().filter(|c| **c == k).count();
    let mut keys = String::new();
    for k in Coverage::ALL {
        keys.push_str(&format!(" {}={}", k.token(), count(k)));
    }
    let mut lines = vec![format!(
        "offline_delivery: verified_contacts={}{keys} (raven contact show NAME says which way)",
        classes.len()
    )];
    for k in Coverage::ALL {
        let n = count(k);
        if n > 0 {
            lines.push(format!(
                "  {} ({n} contact{}): {}",
                k.name(),
                if n == 1 { "" } else { "s" },
                k.ceiling()
            ));
        }
    }
    if count(Coverage::Nobody) > 0 {
        lines.push(format!(
            "  next step: {}",
            if custody_live {
                OFFLINE_NEXT_STEP
            } else {
                OFFLINE_HELD_STEP
            }
        ));
    }
    lines
}

/// [`offline_lines`] from this profile's files and the running
/// raven-node's `status` (its last paths), for every verified, unblocked
/// contact but `local`. `handoff_parked`: raven-node keeps its handoff
/// parks in memory (an hour, or a day for a custodian without handoff), so
/// `raven doctor` passes none and shows what the files give.
pub(super) fn doctor_offline_lines_with(
    data_dir: &Path,
    local: &[u8; 32],
    status: &Result<IpcResponse, String>,
    handoff_parked: &HandoffParked<'_>,
) -> Vec<String> {
    let Ok(book) = pinned_unblocked_contacts(data_dir) else {
        return vec!["offline_delivery: unknown (contacts.json cannot be read)".into()];
    };
    let now = now_ms();
    let direct = direct_contacts(status);
    let peers: Vec<&[u8; 32]> = book.iter().filter(|peer| *peer != local).collect();
    let classes: Vec<Coverage> = peers
        .iter()
        .map(|peer| {
            coverage_from_files(
                data_dir,
                local,
                peer,
                now,
                direct.contains(peer),
                handoff_parked,
            )
        })
        .collect();
    let mut lines = offline_lines(&classes, CustodyGates::current().live);
    // Review handoff-3: contacts your receipts cannot reach through friends.
    if custody_hints_live() && handoff_live() {
        let learned = raven_core::learned_routes::learned_custody_all(data_dir, now);
        let stranded = peers
            .iter()
            .zip(&classes)
            .filter(|(peer, class)| {
                receipts_stranded(learned.get(**peer), &book, local, peer, **class)
            })
            .count();
        lines.extend(receipts_stranded_count_line(stranded));
    }
    lines
}

/// The offline delivery section of `raven doctor`.
pub(super) fn doctor_offline_lines(
    data_dir: &Path,
    status: &Result<IpcResponse, String>,
) -> Vec<String> {
    doctor_offline_lines_with(data_dir, &local_key(data_dir), status, &|_, _| false)
}

/// Who carries one contact's mail, as [`contact_show_lines`] says it, as
/// data for the desktop engine (`contacts.routes`). Keys in lower-case hex.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
// Only the engine (feature `engine`, the library) reads it, not the binaries.
#[cfg_attr(not(feature = "engine"), allow(dead_code))]
pub(super) struct ContactCarriers {
    /// Learned custody runs in this build ([`custody_hints_live`]): `told`
    /// is known only then.
    pub hints_live: bool,
    /// The mail friends the contact told this node about that are your own
    /// verified contacts, each with whether it takes mail another friend
    /// passes on (`HANDOFF_INBOX`).
    pub told: Vec<(String, bool)>,
    /// How many more it told about that are not your verified contacts.
    pub told_unknown: usize,
    /// The friends you listed for it by hand, each with whether it is
    /// usable now (a verified, unblocked contact).
    pub listed: Vec<(String, bool)>,
    /// Its offline delivery class; `None` for a contact not verified or
    /// blocked (friends carry mail for verified contacts only).
    pub coverage: Option<Coverage>,
    /// Your receipts for its messages cannot go back through friends
    /// ([`receipts_stranded`]).
    pub receipts_stranded: bool,
}

/// [`ContactCarriers`] of the contact with key `pub_hex`, from this
/// profile's files and the running raven-node's `status` (its last paths,
/// for the `direct` class), with the helpers [`contact_show_lines`] uses.
#[cfg_attr(not(feature = "engine"), allow(dead_code))]
pub(super) fn contact_carriers(
    data_dir: &Path,
    pub_hex: &str,
    status: &Result<IpcResponse, String>,
) -> Result<ContactCarriers, String> {
    let peer: [u8; 32] = hex::decode(pub_hex.trim())
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or("not a contact key")?;
    let local = local_key(data_dir);
    let now = now_ms();
    let book = pinned_unblocked_contacts(data_dir).unwrap_or_default();
    let hints_live = custody_hints_live();
    let learned = hints_live
        .then(|| raven_core::learned_routes::learned_custody(data_dir, &peer, now))
        .flatten();
    let (told, told_unknown) = match &learned {
        Some(t) => (
            announced_from(t, &book, &local, &peer)
                .iter()
                .map(|a| (hex::encode(a.key), a.handoff_inbox))
                .collect(),
            unknown_custodians(t, &book, &local, &peer),
        ),
        None => (Vec::new(), 0),
    };
    let listed = listed_custodians(data_dir, &peer, &local)
        .unwrap_or_default()
        .iter()
        .map(|c| (hex::encode(c), custodian_usable(data_dir, c, &peer, &local)))
        .collect();
    let pinned = load_contacts(data_dir)?
        .iter()
        .any(|c| c.pinned && key_of(c) == Some(peer));
    let coverage = (pinned && book.contains(&peer)).then(|| {
        coverage_from_files(
            data_dir,
            &local,
            &peer,
            now,
            direct_contacts(status).contains(&peer),
            &|_, _| false,
        )
    });
    let receipts_stranded = coverage
        .is_some_and(|class| receipts_stranded(learned.as_ref(), &book, &local, &peer, class));
    Ok(ContactCarriers {
        hints_live,
        told,
        told_unknown,
        listed,
        coverage,
        receipts_stranded,
    })
}

/// `raven contact show NAME` as lines (Phase 5 P5.22): the contact, the
/// mail friends it told this node about (its RRH1 custodian entries, named
/// only when they are your own verified contacts, each with whether it
/// takes mail another friend passes on: `HANDOFF_INBOX`; the others
/// counted), the friends you listed for it by hand (one not usable now
/// flagged), and its offline delivery class ([`coverage_from_files`];
/// `direct`: the contacts a message reached directly within 24 h). Names
/// come from your own contact book; nothing is dialled.
pub(super) fn contact_show_lines(
    data_dir: &Path,
    selector: &str,
    local: &[u8; 32],
    direct: &[[u8; 32]],
    now: u64,
) -> Result<Vec<String>, String> {
    let contacts = load_contacts(data_dir)?;
    let target = super::select_contact_for_edit(&contacts, Some(selector), None, None, None)?;
    let name = target.primary_label();
    let mut lines = vec![format!(
        "{name}{}  {}",
        target
            .tag_subtitle()
            .map_or_else(String::new, |t| format!("  {t}")),
        if target.pinned {
            "verified"
        } else {
            "not verified"
        }
    )];
    lines.push(format!("  fp {}", super::contact_fingerprint(&target)));
    let Some(peer) = key_of(&target) else {
        return Ok(lines);
    };
    let label = |k: &[u8; 32]| {
        contacts
            .iter()
            .find(|c| key_of(c).as_ref() == Some(k))
            .map_or_else(|| "a contact".to_string(), Contact::primary_label)
    };
    let book = pinned_unblocked_contacts(data_dir).unwrap_or_default();
    let learned = custody_hints_live()
        .then(|| raven_core::learned_routes::learned_custody(data_dir, &peer, now))
        .flatten();
    let told = if custody_hints_live() {
        let told = learned.as_ref();
        let friends = told.map_or_else(Vec::new, |t| {
            announced_from(t, &book, local, &peer)
                .iter()
                .map(|a| {
                    format!(
                        "{}{}",
                        label(&a.key),
                        if a.handoff_inbox {
                            " (also takes mail another friend passes on)"
                        } else {
                            ""
                        }
                    )
                })
                .collect()
        });
        let unknown = told.map_or(0, |t| unknown_custodians(t, &book, local, &peer));
        let mut text = if friends.is_empty() {
            "none".to_string()
        } else {
            friends.join(", ")
        };
        if unknown > 0 {
            text.push_str(&format!(
                "; {unknown} more that {} not your verified contact{}",
                if unknown == 1 { "is" } else { "are" },
                if unknown == 1 { "" } else { "s" }
            ));
        }
        text
    } else {
        "not in this build (friend mailboxes are lab-only)".to_string()
    };
    lines.push(format!("  mail friends {name} told you about: {told}"));
    let listed = listed_custodians(data_dir, &peer, local).unwrap_or_default();
    if !listed.is_empty() {
        let names: Vec<String> = listed
            .iter()
            .map(|c| {
                format!(
                    "{}{}",
                    label(c),
                    if custodian_usable(data_dir, c, &peer, local) {
                        ""
                    } else {
                        " (not used: not a verified, unblocked contact)"
                    }
                )
            })
            .collect();
        lines.push(format!(
            "  mail friends you listed for {name}: {}",
            names.join(", ")
        ));
    }
    if !target.pinned {
        lines.push(format!(
            "  offline delivery: friends carry mail for verified contacts only (raven contact \
             verify {})",
            sanitize_terminal_line(selector.trim())
        ));
        return Ok(lines);
    }
    if !book.contains(&peer) {
        lines.push(format!("  offline delivery: none ({name} is blocked)"));
        return Ok(lines);
    }
    let class = coverage_from_files(
        data_dir,
        local,
        &peer,
        now,
        direct.contains(&peer),
        &|_, _| false,
    );
    lines.push(format!(
        "  offline delivery ({}): {}",
        class.name(),
        class.ceiling()
    ));
    if receipts_stranded(learned.as_ref(), &book, local, &peer, class) {
        lines.push(receipts_stranded_line(&name));
    }
    if class == Coverage::Nobody {
        lines.push(format!(
            "  next step: {}",
            if CustodyGates::current().live {
                OFFLINE_NEXT_STEP
            } else {
                OFFLINE_HELD_STEP
            }
        ));
    }
    Ok(lines)
}

/// The custodians `peer` announced that are not your verified, unblocked
/// contacts (`book`): its tags no candidate matches and its plain keys
/// outside the book.
fn unknown_custodians(
    told: &raven_core::learned_routes::LearnedCustody,
    book: &[[u8; 32]],
    local: &[u8; 32],
    peer: &[u8; 32],
) -> usize {
    let candidates: Vec<&[u8; 32]> = book.iter().filter(|c| *c != peer && *c != local).collect();
    let tags = told
        .tags
        .iter()
        .filter(|t| {
            !candidates
                .iter()
                .any(|c| raven_core::route_hints::custodian_tag(peer, local, c) == **t)
        })
        .count();
    let plain = told
        .plain
        .iter()
        .filter(|k| !candidates.contains(k))
        .count();
    tags + plain
}

/// Review handoff-3: while custody handoff is live, `peer` announced the
/// friends at which it collects mail that friends pass on (`HANDOFF_INBOX`),
/// none of them is your verified, unblocked contact (`book`: an RRH1
/// custodian tag names only a friend you verified yourself), and no mail
/// friend you share carries mail from you to it (`class`). Its messages may
/// still reach you through two friends, but your receipts for them cannot
/// go back that way, so when their time runs out its outbox can only say
/// that delivery was not confirmed. `false` when one such friend is your
/// contact (what is missing then is a friend of your own: the next step
/// says so).
pub(super) fn receipts_stranded(
    told: Option<&raven_core::learned_routes::LearnedCustody>,
    book: &[[u8; 32]],
    local: &[u8; 32],
    peer: &[u8; 32],
    class: Coverage,
) -> bool {
    let Some(told) = told else {
        return false;
    };
    if !handoff_live() || matches!(class, Coverage::MutualFriend | Coverage::TwoFriends) {
        return false;
    }
    let inbox = raven_core::route_hints::CUSTODIAN_FLAG_HANDOFF_INBOX;
    let inboxes: Vec<&[u8; 32]> = told
        .tags
        .iter()
        .enumerate()
        .filter(|(i, _)| told.tag_flags.get(*i).copied().unwrap_or(0) & inbox != 0)
        .map(|(_, tag)| tag)
        .collect();
    let known = |tag: &[u8; 32]| {
        book.iter()
            .filter(|c| *c != peer && *c != local)
            .any(|c| raven_core::route_hints::custodian_tag(peer, local, c) == *tag)
    };
    !inboxes.is_empty() && !inboxes.iter().any(|tag| known(tag))
}

/// `raven contact show`'s line for [`receipts_stranded`].
pub(super) fn receipts_stranded_line(name: &str) -> String {
    format!(
        "  receipts: {name} collects mail that friends pass on only at a friend you have not \
         verified, so your receipts for {name}'s messages cannot go back through friends. Ask \
         {name} which friend that is and verify it by its key alone, with no address to dial \
         (raven contact add with --verify-fp and no --lan-dial)"
    )
}

/// `raven doctor`'s line for the verified contacts [`receipts_stranded`]
/// holds for: counts only. `None` when there are none.
pub(super) fn receipts_stranded_count_line(n: usize) -> Option<String> {
    (n > 0).then(|| {
        format!(
            "  receipts: {n} contact{} collect{} mail that friends pass on only at friends you \
             have not verified: your receipts cannot go back to {} through friends (raven \
             contact show NAME)",
            if n == 1 { "" } else { "s" },
            if n == 1 { "s" } else { "" },
            if n == 1 { "it" } else { "them" }
        )
    })
}

/// `raven contact show NAME`.
pub(super) fn cmd_contact_show(data_dir: &Path, selector: &str) -> Result<(), String> {
    let status = super::ipc_client::ipc_request_timeout(
        data_dir,
        &IpcRequest::status(),
        Duration::from_secs(2),
    );
    let lines = contact_show_lines(
        data_dir,
        selector,
        &local_key(data_dir),
        &direct_contacts(&status),
        now_ms(),
    )?;
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

// The limits [`CUSTODIAN_CONSENT`] names.
const _: () = assert!(MAX_PAIR_ROWS == 128 && MAX_NODE_BYTES == 64 * 1024 * 1024);

#[cfg(test)]
mod tests;
