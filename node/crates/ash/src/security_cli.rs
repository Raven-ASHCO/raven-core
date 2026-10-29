//! Security notices in the CLI (Phase 6b design A UX, step P6.30): `raven
//! security` (the open notices, `explain N`, `resolve N`, `clear`, `--json`
//! for each), the SECURITY section and strangers row of `raven status`, the
//! security row of `raven doctor`, the note `raven send` prints for a
//! contact with an open alert, and what a match in `raven contact verify`
//! resolves.
//!
//! Everything here reads the profile's security ledger
//! (`raven_core::security_ledger`, written by raven-node and by ash's own
//! sink) and, for the counts of strangers, the running raven-node's
//! `Status.security`. Nothing exists while the security events gate is
//! shut: `raven security` says so and the other commands show nothing. No
//! text names an address, a port, a message id or a whole key: a verified
//! friend's key shows as its first 8 hex characters in `explain` only.
//! Lowering a capability floor stays in cli.rs (the one caller the floor's
//! source scan allows).

use std::path::Path;

use raven_core::clock::now_ms;
use raven_core::ipc::IpcResponse;
use raven_core::sanitize::sanitize_terminal_line;
use raven_core::security_events::{CarrierRole, SecKind, Severity};
use raven_core::security_ledger::{
    ledger_path, Alert, AlertState, LedgerError, LedgerSubject, SecurityLedger,
};
use serde_json::{json, Value};

use super::security_text::{self as text, About, NoticeText};
use super::{load_contacts, normalize_tag, typed_confirmation, Contact, C_BOLD, C_DIM, C_RESET};

#[cfg(test)]
mod tests;

const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;

/// How many open notices `raven status` shows in full before it points at
/// `raven security`.
const STATUS_SHOWN: usize = 3;

/// The days of counts `raven security explain` adds.
const EXPLAIN_DAYS: u64 = 7;

/// The JSON version of every `raven security --json` answer.
const JSON_V: u32 = 1;

// ── The ledger as a command finds it ─────────────────────────────────────

/// What a command finds of the profile's security ledger.
enum Opened {
    /// The security events gate is shut: not part of this version.
    Off,
    /// The profile is not encrypted, so it keeps no ledger.
    NotKept,
    /// The gate is live and the profile encrypted, but nothing was noted
    /// yet (no file; reading never creates one).
    Nothing,
    Ledger(SecurityLedger),
}

/// Open the profile's ledger for a command: never creates the file.
fn open_ledger(data_dir: &Path) -> Result<Opened, String> {
    if !raven_core::security_sense::live() {
        return Ok(Opened::Off);
    }
    if !ledger_path(data_dir).exists() {
        let sealed = raven_core::privacy::mode(data_dir) == raven_core::at_rest::Mode::Sealed;
        return Ok(if sealed {
            Opened::Nothing
        } else {
            Opened::NotKept
        });
    }
    match SecurityLedger::open(data_dir) {
        Ok(ledger) => Ok(Opened::Ledger(ledger)),
        Err(LedgerError::GateClosed) => Ok(Opened::Off),
        Err(LedgerError::NotSealed) => Ok(Opened::NotKept),
        Err(e) => Err(sanitize_terminal_line(&e.to_string())),
    }
}

/// The contact book for naming, and whether it could be read.
pub(super) struct Book {
    contacts: Vec<Contact>,
    read: bool,
}

impl Book {
    pub(super) fn read(data_dir: &Path) -> Self {
        match load_contacts(data_dir) {
            Ok(contacts) => Self {
                contacts,
                read: true,
            },
            Err(_) => Self {
                contacts: Vec::new(),
                read: false,
            },
        }
    }

    /// A book already loaded by the caller.
    pub(super) fn of(contacts: &[Contact]) -> Self {
        Self {
            contacts: contacts.to_vec(),
            read: true,
        }
    }

    fn find(&self, key: &[u8; 32]) -> Option<&Contact> {
        let hex = hex::encode(key);
        self.contacts
            .iter()
            .find(|c| c.pub_hex.trim().eq_ignore_ascii_case(&hex))
    }
}

// ── Whom a notice is about ───────────────────────────────────────────────

/// The role a notice's subject plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Contact,
    /// A friend's computer holding mail (a custodian).
    Mailbox,
    /// A friend who left mail with this computer (a depositor).
    Depositor,
    Relay,
    ThisComputer,
    /// A security update; `key` is who passed it on, if anyone.
    Update,
    Nobody,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Contact => "contact",
            Role::Mailbox => "mailbox",
            Role::Depositor => "depositor",
            Role::Relay => "relay",
            Role::ThisComputer => "this_computer",
            Role::Update => "update",
            Role::Nobody => "unknown",
        }
    }
}

/// Whom a notice is about, named from the contact book.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Who {
    role: Role,
    /// The name the texts use (empty for a role without one).
    name: String,
    /// A contact in the book that is verified (pinned).
    verified: bool,
    /// The subject's key: shown (as a prefix) only for a verified contact.
    key: Option<[u8; 32]>,
    /// What `raven contact verify` takes to name the contact.
    verify: Option<String>,
}

/// The kinds about this computer's own state (registry codes 60-69).
fn about_this_computer(kind: SecKind) -> bool {
    (60..70).contains(&kind.code())
}

/// The kinds about security updates (registry codes 70-79).
fn about_an_update(kind: SecKind) -> bool {
    (70..80).contains(&kind.code())
}

fn who(alert: &Alert, book: &Book) -> Who {
    let named = |role: Role, key: [u8; 32]| match book.find(&key) {
        Some(c) => Who {
            role,
            name: display_name(c),
            verified: c.pinned,
            key: Some(key),
            verify: verify_arg(c),
        },
        None => Who {
            role,
            name: if book.read {
                "someone not in your contacts".into()
            } else {
                "a contact".into()
            },
            verified: false,
            key: Some(key),
            verify: None,
        },
    };
    let nameless = |role: Role| Who {
        role,
        name: String::new(),
        verified: false,
        key: None,
        verify: None,
    };
    match alert.subject {
        Some(LedgerSubject::Contact(key)) => named(Role::Contact, key),
        Some(LedgerSubject::Carrier {
            role: CarrierRole::Relay,
            ..
        }) => nameless(Role::Relay),
        Some(LedgerSubject::Carrier {
            key,
            role: CarrierRole::Custodian,
        }) => named(Role::Mailbox, key),
        Some(LedgerSubject::Carrier {
            key,
            role: CarrierRole::Depositor,
        }) => named(Role::Depositor, key),
        Some(LedgerSubject::PassedBy(key)) => named(Role::Update, key),
        None if about_an_update(alert.kind) => nameless(Role::Update),
        None if about_this_computer(alert.kind) => nameless(Role::ThisComputer),
        None => nameless(Role::Nobody),
    }
}

impl Who {
    fn about(&self) -> About<'_> {
        match self.role {
            Role::Contact => About::Contact(&self.name),
            Role::Mailbox | Role::Depositor => About::Carrier(&self.name),
            Role::Relay => About::Relay,
            Role::ThisComputer => About::ThisComputer,
            Role::Update if self.key.is_some() => About::Update(Some(&self.name)),
            Role::Update => About::Update(None),
            Role::Nobody => About::Unknown,
        }
    }

    /// `raven security explain`'s "About" value.
    fn details(&self) -> String {
        let prefix = self
            .key
            .filter(|_| self.verified)
            .map(|key| format!(", key {}", &hex::encode(key)[..8]))
            .unwrap_or_default();
        let verified = if self.verified {
            "verified friend"
        } else {
            "not verified"
        };
        match self.role {
            Role::Contact => format!("{} ({verified}{prefix})", self.name),
            Role::Mailbox => format!("{}, as a mailbox for you ({verified}{prefix})", self.name),
            Role::Depositor => format!(
                "{}, leaving mail with this computer ({verified}{prefix})",
                self.name
            ),
            Role::Update if self.key.is_some() => {
                format!("an update passed on by {} ({verified}{prefix})", self.name)
            }
            Role::Update => "a security update".into(),
            Role::Relay => "a relay (Raven keeps no name or address for it)".into(),
            Role::ThisComputer => "this computer".into(),
            Role::Nobody => "nobody Raven knows".into(),
        }
    }

    fn json(&self) -> Value {
        let mut about = json!({ "role": self.role.as_str() });
        if self.key.is_some() {
            about["name"] = json!(self.name);
            about["verified"] = json!(self.verified);
        }
        if let Some(key) = self.key.filter(|_| self.verified) {
            about["key_prefix"] = json!(&hex::encode(key)[..8]);
        }
        about
    }
}

/// A contact's name in the texts: its petname or @tag, never its address.
fn display_name(c: &Contact) -> String {
    let named = !sanitize_terminal_line(c.petname.trim()).is_empty()
        || !normalize_tag(&c.public_tag).is_empty();
    if named {
        c.primary_label()
    } else {
        "an unnamed contact".into()
    }
}

/// What `raven contact verify` takes to name `c`: `--petname NAME` (quoted
/// when it needs it) or `@tag`; none for a contact with neither.
fn verify_arg(c: &Contact) -> Option<String> {
    let petname = sanitize_terminal_line(c.petname.trim());
    let tag = normalize_tag(&c.public_tag);
    if !petname.is_empty() {
        Some(format!("--petname {}", shell_word(&petname)))
    } else if !tag.is_empty() {
        Some(format!("@{tag}"))
    } else {
        None
    }
}

/// `word` as one shell word: as it is when it is plain, else in double
/// quotes without the characters a shell expands inside them.
fn shell_word(word: &str) -> String {
    let plain = word
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    if plain {
        word.to_owned()
    } else {
        let kept: String = word
            .chars()
            .filter(|c| !matches!(c, '"' | '\\' | '$' | '`'))
            .collect();
        format!("\"{kept}\"")
    }
}

// ── What is open ─────────────────────────────────────────────────────────

/// One open notice, in words.
struct Shown {
    alert: Alert,
    who: Who,
    text: NoticeText,
}

impl Shown {
    fn of(alert: Alert, book: &Book) -> Self {
        let who = who(&alert, book);
        let text = text::notice(
            alert.kind,
            alert.severity,
            who.about(),
            alert.action.as_deref(),
        );
        Self { alert, who, text }
    }

    /// The CLI command for its action.
    fn hint(&self) -> Option<String> {
        text::cli_hint(self.text.act, self.who.verify.as_deref())
    }

    /// Its number in `raven security` and for `explain N` and `resolve N`:
    /// the notice's own (its ledger row's), so it names the same notice for
    /// as long as the notice is open, whatever was noted, refreshed or
    /// resolved meanwhile. A position in the list would shift (the ledger
    /// orders by severity and the latest hour, and raven-node writes all the
    /// time), and `resolve N` could close a notice the person never saw
    /// (Phase 6 review sensing-6).
    fn number(&self) -> i64 {
        self.alert.id.0
    }

    fn json(&self) -> Value {
        json!({
            "n": self.number(),
            "kind": self.alert.kind.name(),
            "code": self.alert.kind.code(),
            "severity": severity_key(self.alert.severity),
            "state": state_key(self.alert.state),
            "first_at_ms": self.alert.first_hour.saturating_mul(HOUR_MS),
            "last_at_ms": self.alert.last_hour.saturating_mul(HOUR_MS),
            "count": self.alert.n,
            "about": self.who.json(),
            "action": self.alert.action,
            "headline": self.text.headline,
            "did": self.text.did,
            "todo": self.text.todo,
            "act": self.text.act.as_str(),
        })
    }
}

fn severity_key(s: Severity) -> &'static str {
    match s {
        Severity::Notice => "notice",
        Severity::Suspicious => "suspicious",
        Severity::Alert => "alert",
    }
}

fn state_key(s: AlertState) -> &'static str {
    match s {
        AlertState::New => "new",
        AlertState::Seen => "seen",
        AlertState::Resolved => "resolved",
    }
}

/// The open notices a person is shown (alerts and warnings, the most
/// severe and the latest first, as the ledger orders them), and how many
/// notices are only counted (design A, OD6b-2).
struct View {
    shown: Vec<Shown>,
    counted: usize,
}

impl View {
    fn of(alerts: Vec<Alert>, book: &Book) -> Self {
        let counted = alerts
            .iter()
            .filter(|a| a.severity == Severity::Notice)
            .count();
        let shown = alerts
            .into_iter()
            .filter(|a| a.severity >= Severity::Suspicious)
            .map(|a| Shown::of(a, book))
            .collect();
        Self { shown, counted }
    }
}

/// The time of day an alert stands for (its last hour, half past).
fn last_at(alert: &Alert, now: u64) -> u64 {
    alert
        .last_hour
        .saturating_mul(HOUR_MS)
        .saturating_add(HOUR_MS / 2)
        .min(now)
}

fn first_at(alert: &Alert, now: u64) -> u64 {
    alert
        .first_hour
        .saturating_mul(HOUR_MS)
        .saturating_add(HOUR_MS / 2)
        .min(now)
}

/// The clock texts read: now, and this computer's local offset (or, for
/// tests, a fixed one).
#[derive(Clone, Copy, Debug)]
struct Clock {
    now_ms: u64,
    fixed: Option<Option<i32>>,
}

impl Clock {
    fn now() -> Self {
        Self {
            now_ms: now_ms(),
            fixed: None,
        }
    }

    fn when(&self, at_ms: u64) -> String {
        match self.fixed {
            Some(off) => text::when_text_with(at_ms, self.now_ms, off, off),
            None => text::when_text(at_ms, self.now_ms),
        }
    }

    /// "this morning" or "4 times, latest this morning".
    fn count_when(&self, alert: &Alert) -> String {
        text::count_when(alert.n, &self.when(last_at(alert, self.now_ms)))
    }
}

/// The marker of a shown notice: `!` an alert, `-` a warning.
fn marker(s: Severity) -> &'static str {
    if s >= Severity::Alert {
        "!"
    } else {
        "-"
    }
}

/// One notice as `raven security` and `raven status` print it: the
/// headline with how often and when, what Raven did, what to do and its
/// command. `indent` is the width of what precedes the headline.
fn notice_lines(s: &Shown, clock: &Clock, lead: &str, indent: usize) -> Vec<String> {
    let pad = " ".repeat(indent);
    let mut lines = vec![
        format!("{lead}{} ({})", s.text.headline, clock.count_when(&s.alert)),
        format!("{pad}{}", s.text.did),
        format!("{pad}{}", s.text.todo),
    ];
    if let Some(hint) = s.hint() {
        lines.push(format!("{pad}  {hint}"));
    }
    lines
}

/// The lines of `raven security` (under its header).
fn list_lines(view: &View, strangers: Option<u32>, clock: &Clock) -> Vec<String> {
    let mut lines = Vec::new();
    if view.shown.is_empty() {
        lines.push(text::NOTHING_OPEN.to_owned());
    }
    for s in &view.shown {
        let lead = format!("{}. {} ", s.number(), marker(s.alert.severity));
        let width = lead.chars().count();
        lines.extend(notice_lines(s, clock, &lead, width));
    }
    if view.counted > 0 {
        lines.push(text::notices_line(view.counted));
    }
    if let Some(n) = strangers.filter(|n| *n > 0) {
        lines.push(text::strangers_line(n));
    }
    if !view.shown.is_empty() {
        lines.push(text::LIST_FOOTER.to_owned());
    }
    lines
}

/// The lines of `raven security explain N`.
fn explain_lines(s: &Shown, days: &[(u64, u64)], clock: &Clock) -> Vec<String> {
    const W: usize = 16;
    let row = |label: &str, value: &str| format!("  {label:<W$}{value}");
    let mut lines = vec![format!("{} {}", marker(s.alert.severity), s.text.headline)];
    let first = clock.when(first_at(&s.alert, clock.now_ms));
    let latest = clock.when(last_at(&s.alert, clock.now_ms));
    let when = if s.alert.n > 1 && first != latest {
        format!("{} times, first {first}, latest {latest}", s.alert.n)
    } else {
        clock.count_when(&s.alert)
    };
    lines.push(row("When", &when));
    lines.push(row("What Raven did", &s.text.did));
    lines.push(row("What you can do", &s.text.todo));
    if let Some(hint) = s.hint() {
        lines.push(row("", &format!("  {hint}")));
    }
    lines.push("Details".to_owned());
    lines.push(row("About", &s.who.details()));
    if !days.is_empty() {
        let per_day: Vec<String> = days
            .iter()
            .map(|&(ago, n)| format!("{} {n}", days_ago_text(ago)))
            .collect();
        lines.push(row("Per day", &per_day.join(", ")));
    }
    lines.push(row("How serious", text::severity_word(s.alert.severity)));
    lines.push(row(
        "Code",
        &format!("{} ({})", s.alert.kind.name(), s.alert.kind.code()),
    ));
    if let Some(action) = &s.alert.action {
        lines.push(row("Raven's action", action));
    }
    lines
}

fn days_ago_text(ago: u64) -> String {
    match ago {
        0 => "today".into(),
        1 => "yesterday".into(),
        n => format!("{n} days ago"),
    }
}

/// The counts of `s`'s kind and subject per day for the last
/// [`EXPLAIN_DAYS`], newest first, as (days ago, count).
fn day_counts(ledger: &SecurityLedger, s: &Shown, now: u64) -> Vec<(u64, u64)> {
    let today = now / DAY_MS;
    let since = today.saturating_sub(EXPLAIN_DAYS - 1);
    let mut days: Vec<(u64, u64)> = ledger
        .counts(since)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.kind == s.alert.kind && c.subject == s.alert.subject)
        .map(|c| (today.saturating_sub(c.day), c.n))
        .collect();
    days.sort_unstable();
    days
}

// ── `raven security` ─────────────────────────────────────────────────────

/// What `--json` says while there is nothing to read: the gate is shut
/// (`not_in_this_version`) or the profile keeps no ledger (`not_encrypted`).
fn unavailable_json(why: &str) -> Value {
    json!({
        "v": JSON_V,
        "available": false,
        "why": why,
        "alerts": [],
        "counted": 0,
        "node": Value::Null,
    })
}

/// Say why there is nothing to read; `true` when there is.
fn say_unavailable(opened: &Opened, json: bool) -> bool {
    let (human, why) = match opened {
        Opened::Off => (text::NOT_IN_THIS_VERSION, "not_in_this_version"),
        Opened::NotKept => (text::NOT_KEPT_UNSEALED, "not_encrypted"),
        Opened::Nothing | Opened::Ledger(_) => return true,
    };
    if json {
        println!("{}", unavailable_json(why));
    } else {
        println!("{human}");
    }
    false
}

/// The running raven-node's security counts (`Status.security`), if it
/// answers and reports them.
fn node_security(data_dir: &Path) -> Option<raven_core::ipc::SecurityStatus> {
    let status = super::ipc_client::ipc_request_timeout(
        data_dir,
        &raven_core::ipc::IpcRequest::status(),
        std::time::Duration::from_secs(2),
    );
    status_security(&status)
}

fn status_security(
    status: &Result<IpcResponse, String>,
) -> Option<raven_core::ipc::SecurityStatus> {
    match status {
        Ok(IpcResponse::Status {
            security: Some(security),
            ..
        }) => Some((**security).clone()),
        _ => None,
    }
}

fn header() {
    println!();
    println!(
        "{C_BOLD}SECURITY \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{C_RESET}"
    );
}

/// The view of an opened ledger (none for [`Opened::Nothing`]).
fn view_of(opened: &Opened, book: &Book) -> Result<View, String> {
    match opened {
        Opened::Ledger(ledger) => {
            let alerts = ledger
                .open_alerts()
                .map_err(|e| sanitize_terminal_line(&e.to_string()))?;
            Ok(View::of(alerts, book))
        }
        _ => Ok(View {
            shown: Vec::new(),
            counted: 0,
        }),
    }
}

/// `raven security [--json]`: the open notices, each with its own number
/// for `explain` and `resolve` ([`Shown::number`]). The person saw them:
/// they are marked seen (not by `--json`).
pub(super) fn cmd_list(data_dir: &Path, json: bool) -> Result<(), String> {
    let mut opened = open_ledger(data_dir)?;
    if !say_unavailable(&opened, json) {
        return Ok(());
    }
    let book = Book::read(data_dir);
    let view = view_of(&opened, &book)?;
    let node = node_security(data_dir);
    if json {
        let alerts: Vec<Value> = view.shown.iter().map(Shown::json).collect();
        println!(
            "{}",
            json!({
                "v": JSON_V,
                "available": true,
                "why": Value::Null,
                "alerts": alerts,
                "counted": view.counted,
                "node": node.map(|n| json!({
                    "strangers_refused_1h": n.strangers_refused_1h,
                    "preauth_failures_1h": n.preauth_failures_1h,
                    "bans_active": n.bans_active,
                    "link_tag_failures_24h": n.link_tag_failures_24h,
                    "alerts_open": n.alerts_open,
                })),
            })
        );
        return Ok(());
    }
    header();
    for line in list_lines(&view, node.map(|n| n.strangers_refused_1h), &Clock::now()) {
        println!("  {line}");
    }
    if let Opened::Ledger(ledger) = &mut opened {
        for s in view
            .shown
            .iter()
            .filter(|s| s.alert.state == AlertState::New)
        {
            let _ = ledger.mark_seen(s.alert.id);
        }
    }
    Ok(())
}

/// The open notice numbered `n` ([`Shown::number`]).
fn numbered(view: View, n: usize) -> Result<Shown, String> {
    view.shown
        .into_iter()
        .find(|s| i64::try_from(n).is_ok_and(|n| s.number() == n))
        .ok_or_else(|| text::no_such_notice(n))
}

/// `raven security explain N [--json]`: one notice in full, with its counts
/// per day, whom it is about and its technical code.
pub(super) fn cmd_explain(data_dir: &Path, n: usize, json: bool) -> Result<(), String> {
    let mut opened = open_ledger(data_dir)?;
    if !say_unavailable(&opened, json) {
        return Ok(());
    }
    let book = Book::read(data_dir);
    let shown = numbered(view_of(&opened, &book)?, n)?;
    let clock = Clock::now();
    let days = match &opened {
        Opened::Ledger(ledger) => day_counts(ledger, &shown, clock.now_ms),
        _ => Vec::new(),
    };
    if json {
        let mut one = shown.json();
        one["days"] = days
            .iter()
            .map(|&(ago, count)| json!({ "days_ago": ago, "n": count }))
            .collect();
        println!(
            "{}",
            json!({ "v": JSON_V, "available": true, "alert": one })
        );
        return Ok(());
    }
    for line in explain_lines(&shown, &days, &clock) {
        println!("{line}");
    }
    if let Opened::Ledger(ledger) = &mut opened {
        if shown.alert.state == AlertState::New {
            let _ = ledger.mark_seen(shown.alert.id);
        }
    }
    Ok(())
}

/// `raven security resolve N [--json]`: the person is done with one notice.
/// What Raven did about it stays (a parked mailbox comes back by itself).
pub(super) fn cmd_resolve(data_dir: &Path, n: usize, json: bool) -> Result<(), String> {
    let mut opened = open_ledger(data_dir)?;
    if !say_unavailable(&opened, json) {
        return Ok(());
    }
    let book = Book::read(data_dir);
    let shown = numbered(view_of(&opened, &book)?, n)?;
    if let Opened::Ledger(ledger) = &mut opened {
        ledger
            .resolve(shown.alert.id, now_ms())
            .map_err(|e| sanitize_terminal_line(&e.to_string()))?;
    }
    if json {
        println!(
            "{}",
            json!({ "v": JSON_V, "available": true, "resolved": shown.json() })
        );
    } else {
        println!("{}", text::resolved(&shown.text.headline));
    }
    Ok(())
}

/// `raven security clear [--yes] [--json]`: every notice and count goes,
/// after the person typed `clear` (or `--yes` for scripts).
pub(super) fn cmd_clear(data_dir: &Path, yes: bool, json: bool) -> Result<(), String> {
    let mut opened = open_ledger(data_dir)?;
    if !say_unavailable(&opened, json) {
        return Ok(());
    }
    typed_confirmation(
        yes,
        text::CLEAR_QUESTION,
        "clear",
        "delete every security notice",
    )?;
    if let Opened::Ledger(ledger) = &mut opened {
        ledger
            .clear()
            .map_err(|e| sanitize_terminal_line(&e.to_string()))?;
    }
    if json {
        println!(
            "{}",
            json!({ "v": JSON_V, "available": true, "cleared": true })
        );
    } else {
        println!("{}", text::CLEARED);
    }
    Ok(())
}

// ── The rows of other commands ───────────────────────────────────────────

/// The open notices, for a row of another command: nothing while the gate
/// is shut, the profile keeps none or nothing was noted; an unreadable
/// ledger is `Err` (its reason).
fn read_view(data_dir: &Path, book: impl FnOnce() -> Book) -> Result<Option<View>, String> {
    match open_ledger(data_dir)? {
        opened @ Opened::Ledger(_) => view_of(&opened, &book()).map(Some),
        Opened::Off | Opened::NotKept | Opened::Nothing => Ok(None),
    }
}

/// `raven status`'s security part: the SECURITY section (only while an
/// alert or a warning is open: the most severe first, at most
/// [`STATUS_SHOWN`] in full, the strangers count and where the details
/// are), or, while nothing is open, the strangers row alone.
pub(super) struct StatusRows {
    /// The section's lines, under its header; empty: no section.
    pub section: Vec<String>,
    /// The `strangers` row while there is no section.
    pub strangers: Option<String>,
}

pub(super) fn status_rows(
    data_dir: &Path,
    contacts: &[Contact],
    daemon: &Result<IpcResponse, String>,
) -> StatusRows {
    let strangers = status_security(daemon).map(|s| s.strangers_refused_1h);
    let view = read_view(data_dir, || Book::of(contacts)).ok().flatten();
    status_rows_of(view.as_ref(), strangers, &Clock::now())
}

fn status_rows_of(view: Option<&View>, strangers: Option<u32>, clock: &Clock) -> StatusRows {
    let strangers = strangers.filter(|n| *n > 0);
    let Some(view) = view.filter(|v| !v.shown.is_empty()) else {
        return StatusRows {
            section: Vec::new(),
            strangers: strangers.map(text::strangers_line),
        };
    };
    let mut section = Vec::new();
    for s in view.shown.iter().take(STATUS_SHOWN) {
        let lead = format!("{} ", marker(s.alert.severity));
        section.extend(notice_lines(s, clock, &lead, 2));
    }
    let more = view.shown.len().saturating_sub(STATUS_SHOWN);
    if more > 0 {
        section.push(format!("{more} more: raven security"));
    }
    if let Some(n) = strangers {
        section.push(text::strangers_line(n));
    }
    section.push(text::DETAILS.to_owned());
    StatusRows {
        section,
        strangers: None,
    }
}

/// `raven doctor`'s security rows (label, value): how many alerts and
/// warnings are open and what to do about the first; nothing while none
/// is (or the gate is shut).
pub(super) fn doctor_rows(data_dir: &Path, contacts: &[Contact]) -> Vec<(&'static str, String)> {
    match read_view(data_dir, || Book::of(contacts)) {
        Ok(view) => doctor_rows_of(view.as_ref()),
        Err(why) => vec![(
            "security",
            format!("notices can't be read ({why}); `raven security` says more"),
        )],
    }
}

fn doctor_rows_of(view: Option<&View>) -> Vec<(&'static str, String)> {
    let Some(first) = view.and_then(|v| v.shown.first()) else {
        return Vec::new();
    };
    let n = view.map_or(0, |v| v.shown.len());
    let mut rows = vec![
        ("security", text::doctor_row(n)),
        ("", first.text.todo.clone()),
    ];
    if let Some(hint) = first.hint() {
        rows.push(("", format!("  {hint}")));
    }
    rows
}

/// The note `raven send` prints when the contact `pub_hex` has an open
/// alert (not a warning or a notice); the send goes ahead.
pub(super) fn send_note(data_dir: &Path, pub_hex: &str) -> Option<String> {
    let key = super::parse_pub_hex(pub_hex).ok()?;
    let view = read_view(data_dir, || Book::read(data_dir)).ok()??;
    send_note_of(&view, &key, &Clock::now())
}

fn send_note_of(view: &View, key: &[u8; 32], clock: &Clock) -> Option<String> {
    let s = view.shown.iter().find(|s| {
        s.alert.severity >= Severity::Alert
            && s.alert.subject.as_ref().is_some_and(|who| who.key() == key)
    })?;
    let when = clock.when(last_at(&s.alert, clock.now_ms));
    Some(text::send_note(&s.text.headline, &when, &s.who.name))
}

/// Whether an alert or a warning about the contact `pub_hex` is open:
/// `raven contact verify` at a terminal then checks a verified contact
/// again.
pub(super) fn open_about(data_dir: &Path, pub_hex: &str) -> bool {
    let Ok(key) = super::parse_pub_hex(pub_hex) else {
        return false;
    };
    let Ok(Some(view)) = read_view(data_dir, || Book::of(&[])) else {
        return false;
    };
    view.shown.iter().any(|s| {
        s.alert
            .subject
            .as_ref()
            .is_some_and(|who| who.key() == &key)
    })
}

/// What a match in `raven contact verify` (the security words, or the old
/// code) changed in the ledger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Verified {
    /// A capability downgrade about the contact (a warning or an alert)
    /// was open: the older method may be accepted now.
    pub floor_alert: bool,
    /// Notices about the contact resolved by the match.
    pub resolved: usize,
}

/// A match in `raven contact verify` for `peer`: whether a capability
/// downgrade about it was open, then every open notice about it is resolved
/// (`SecurityLedger::resolve_contact`). Nothing while there is no ledger.
pub(super) fn resolve_on_match(data_dir: &Path, peer: &[u8; 32]) -> Result<Verified, String> {
    let Opened::Ledger(mut ledger) = open_ledger(data_dir)? else {
        return Ok(Verified::default());
    };
    let floor_alert = ledger
        .open_alerts()
        .map_err(|e| sanitize_terminal_line(&e.to_string()))?
        .iter()
        .any(|a| {
            a.kind == SecKind::CapabilityDowngrade
                && a.severity >= Severity::Suspicious
                && a.subject.as_ref().is_some_and(|who| who.key() == peer)
        });
    let resolved = ledger
        .resolve_contact(peer, now_ms())
        .map_err(|e| sanitize_terminal_line(&e.to_string()))?;
    Ok(Verified {
        floor_alert,
        resolved,
    })
}

/// What `raven contact verify` prints after a match resolved notices.
pub(super) fn resolved_line(name: &str, v: &Verified) -> Option<String> {
    (v.resolved > 0).then(|| {
        format!(
            "{C_DIM}{}{C_RESET}",
            text::resolved_by_verify(name, v.resolved)
        )
    })
}

// ── The terminal app (P6.31) ─────────────────────────────────────────────

/// Whether this profile keeps security notices, as the terminal app says it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Kept {
    /// The security events gate is shut: not part of this version.
    #[default]
    Off,
    /// The profile is not encrypted, so it keeps none.
    Unsealed,
    /// Kept (nothing may be noted yet).
    Live,
}

/// One open notice (an alert or a warning) as the terminal app shows it:
/// its words, whom it is about and its details. No address, message id or
/// whole key: a verified friend's key is its first 8 hex characters, in
/// `details` only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AppNotice {
    /// The ledger's id: what resolving it names.
    pub id: i64,
    /// An alert; else a warning.
    pub alert: bool,
    /// The contact it is about (as a contact, a mailbox or a depositor), by
    /// its key in lower-case hex; None for anyone else.
    pub peer: Option<String>,
    /// The name its texts use.
    pub name: String,
    pub text: NoticeText,
    /// When, coarse: "this morning", "4 times, latest this morning".
    pub when: String,
    /// `raven security explain`'s details, as (label, value): about whom,
    /// how serious, the technical code and Raven's action.
    pub details: Vec<(&'static str, String)>,
}

/// What the terminal app reads of the security ledger (P6.31): the open
/// alerts and warnings in the ledger's order (the most severe and the
/// latest first), how many notices are only counted, and, per contact (by
/// key in lower-case hex), how many events the last 7 days counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct AppRead {
    pub kept: Kept,
    pub notices: Vec<AppNotice>,
    pub counted: usize,
    pub week: Vec<(String, u64)>,
}

/// The terminal app's read of the ledger: never creates it; nothing while
/// the gate is shut or the profile keeps none.
pub(super) fn app_read(data_dir: &Path) -> Result<AppRead, String> {
    let opened = open_ledger(data_dir)?;
    let kept = match opened {
        Opened::Off => Kept::Off,
        Opened::NotKept => Kept::Unsealed,
        Opened::Nothing | Opened::Ledger(_) => Kept::Live,
    };
    let Opened::Ledger(ledger) = &opened else {
        return Ok(AppRead {
            kept,
            ..AppRead::default()
        });
    };
    let clock = Clock::now();
    let view = view_of(&opened, &Book::read(data_dir))?;
    let week = week_counts(ledger, clock.now_ms);
    Ok(app_read_of(view, week, &clock))
}

fn app_read_of(view: View, week: Vec<(String, u64)>, clock: &Clock) -> AppRead {
    let notices = view
        .shown
        .into_iter()
        .map(|s| AppNotice {
            id: s.alert.id.0,
            alert: s.alert.severity >= Severity::Alert,
            peer: friend_key(&s.alert).map(hex::encode),
            name: s.who.name.clone(),
            when: clock.count_when(&s.alert),
            details: app_details(&s),
            text: s.text,
        })
        .collect();
    AppRead {
        kept: Kept::Live,
        notices,
        counted: view.counted,
        week,
    }
}

/// The contact a notice is about: as a contact, a mailbox or a depositor
/// (never a relay, nor who passed an update on).
fn friend_key(alert: &Alert) -> Option<&[u8; 32]> {
    match &alert.subject {
        Some(LedgerSubject::Contact(key)) => Some(key),
        Some(LedgerSubject::Carrier {
            key,
            role: CarrierRole::Custodian | CarrierRole::Depositor,
        }) => Some(key),
        _ => None,
    }
}

/// `explain`'s details, without the counts per day.
fn app_details(s: &Shown) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("About", s.who.details()),
        (
            "How serious",
            text::severity_word(s.alert.severity).to_owned(),
        ),
        (
            "Code",
            format!("{} ({})", s.alert.kind.name(), s.alert.kind.code()),
        ),
    ];
    if let Some(action) = &s.alert.action {
        rows.push(("Raven's action", action.clone()));
    }
    rows
}

/// The events about each contact (any kind and role but a relay) the last
/// [`EXPLAIN_DAYS`] counted, by key in lower-case hex, sorted.
fn week_counts(ledger: &SecurityLedger, now: u64) -> Vec<(String, u64)> {
    let since = (now / DAY_MS).saturating_sub(EXPLAIN_DAYS - 1);
    let mut week: Vec<(String, u64)> = Vec::new();
    for count in ledger.counts(since).unwrap_or_default() {
        let key = match count.subject {
            Some(LedgerSubject::Contact(key))
            | Some(LedgerSubject::Carrier {
                key,
                role: CarrierRole::Custodian | CarrierRole::Depositor,
            }) => hex::encode(key),
            _ => continue,
        };
        match week.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => *n = n.saturating_add(count.n),
            None => week.push((key, count.n)),
        }
    }
    week.sort();
    week
}

/// The terminal app's R on one notice: resolved by the ledger's `id`.
/// `Ok(false)`: it was not open any more (or nothing is kept).
pub(super) fn app_resolve(data_dir: &Path, id: i64) -> Result<bool, String> {
    let Opened::Ledger(mut ledger) = open_ledger(data_dir)? else {
        return Ok(false);
    };
    ledger
        .resolve(raven_core::security_ledger::AlertId(id), now_ms())
        .map_err(|e| sanitize_terminal_line(&e.to_string()))
}
