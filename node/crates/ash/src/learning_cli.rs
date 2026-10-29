//! Learning connectivity in the CLI (Phase 6a P6.17, design "Phase 6a"):
//! `raven learning status|reset|on|off`, the LEARNING rows of `raven
//! status` and the `learning:` lines of `raven doctor`.
//!
//! - **Held** by [`raven_core::learning::LEARNING_PRODUCTION_ENABLED`]
//!   (false; a debug build opens it with `RAVEN_LAB_LEARNING=1`). raven-node
//!   learns and reports (IPC `Status.learning`, `LearningReset`); ash only
//!   words what it says. A raven-node that reports no learning (the hold, or
//!   one from before Phase 6a) shows nothing new in `raven status` or
//!   `raven doctor`.
//! - **Names.** `raven learning status` and `raven status` name each row's
//!   contact as this contact book does; a key the book does not hold is
//!   skipped. `raven doctor`, which people paste for help, carries counts
//!   and reason tokens only (`learning_row_<n>`), never a name or key.
//! - **The switch** (`on`/`off`) is `node_policy.learning`, never saved
//!   over an unreadable policy. `off --forget` also deletes what was
//!   learned.
//! - **Reset** asks the running raven-node (IPC `LearningReset`); with none
//!   running (or one that holds learning or is older) it opens the sealed
//!   store itself with the same sealer: everyone's file is removed, or it is
//!   saved without one contact's rows. Route memory (G2) is forgotten with
//!   it (OD6a-10: learning supersedes it while on).

use std::path::Path;
use std::time::{Duration, Instant};

use raven_core::clock::now_ms;
use raven_core::ipc::{IpcRequest, IpcResponse, LearningRow, LearningStatus};
use raven_core::learning::explain::{carrier_token, Reason, State, Why};
use raven_core::learning::store::{self, PlatformSealer, Sealer, StoreState};
use raven_core::node_policy::{try_load_policy, update_policy};
use raven_core::outbox::OutboxCarrier;
use raven_core::sanitize::sanitize_terminal_line;

use super::{
    answer_is_yes, doctor_word, ipc_client, key_label, load_contacts, no_contact_message,
    read_decision_line, resolve_contact_arg, stdin_is_tty, Contact, C_GREEN, C_RESET,
};

/// What `raven learning` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LearningArg {
    Status { json: bool },
    Reset { contact: Option<String>, yes: bool },
    On,
    Off { forget: bool },
}

/// Rows of the LEARNING section of `raven status`, and `learning_row_<n>`
/// lines of `raven doctor`, shown at most.
pub(super) const SHOWN_ROWS: usize = 8;

/// How long `Status` may take here (the node answers at once).
const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
/// `off --forget` waits at most this long for the running raven-node to
/// read the switch (it reads it every 2 s) before it asks it to forget.
const OFF_APPLIED_WAIT: Duration = Duration::from_secs(5);

/// What there is to say about learning on this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LearningView<'a> {
    /// The running raven-node's report (its state may be `off`).
    Live(&'a LearningStatus),
    /// The gate is shut: this build, or the running raven-node (one from
    /// before Phase 6a reports no learning either).
    Held,
    /// No raven-node answers, and the user's switch is off.
    Off,
    /// No raven-node answers.
    NeedsNode,
}

/// The view from `daemon` (raven-node's answer to `Status`), this build's
/// gate (`live`) and the user's switch (`off`: `node_policy.learning` is
/// `Some(false)`).
pub(super) fn view(
    daemon: &Result<IpcResponse, String>,
    live: bool,
    off: bool,
) -> LearningView<'_> {
    match daemon {
        Ok(IpcResponse::Status {
            learning: Some(l), ..
        }) => LearningView::Live(l),
        Ok(IpcResponse::Status { learning: None, .. }) => LearningView::Held,
        _ if !live => LearningView::Held,
        _ if off => LearningView::Off,
        _ => LearningView::NeedsNode,
    }
}

/// The user's switch is off in this profile's policy (an unreadable policy
/// fails closed: off).
fn switch_off(data_dir: &Path) -> bool {
    raven_core::node_policy::load_policy(data_dir).learning == Some(false)
}

/// The carrier as the user reads it.
fn carrier_name(c: OutboxCarrier) -> &'static str {
    match c {
        OutboxCarrier::Lan => "LAN",
        OutboxCarrier::Internet => "Internet",
        OutboxCarrier::P2p => "p2p",
        OutboxCarrier::Nearby => "Bluetooth nearby",
        OutboxCarrier::Onion => "Tor",
    }
}

/// A carrier label (`lan_dial`, …) as [`OutboxCarrier::label`] writes it.
fn carrier_of_label(label: &str) -> Option<OutboxCarrier> {
    [
        OutboxCarrier::Lan,
        OutboxCarrier::Internet,
        OutboxCarrier::P2p,
        OutboxCarrier::Nearby,
        OutboxCarrier::Onion,
    ]
    .into_iter()
    .find(|c| c.label() == label)
}

/// `k of the last n tries`.
fn tries(k: u8, n: u8) -> String {
    format!("{k} of the last {n} tr{}", if n == 1 { "y" } else { "ies" })
}

/// One row's reason (`learn: state=… order=… why=…`) as a plain sentence:
/// "Internet first on this network: LAN did not answer 3 of the last 4
/// tries (2 h ago)". `None` when the block cannot be read (a newer
/// raven-node's reason: [`row_text`] then says the order alone).
pub(super) fn reason_text(raw: &str) -> Option<String> {
    let r = Reason::find(raw)?;
    let first = r
        .order
        .first()
        .map_or("the usual way", |c| carrier_name(*c));
    let mut text = match r.why {
        Why::Cold => "the usual order: too few tries to learn from yet".to_string(),
        Why::Kept => "the usual order: it works best here".to_string(),
        Why::Faster => match r.ok {
            Some(t) => format!(
                "{first} first on this network: it answered sooner ({} worked)",
                tries(t.k, t.n)
            ),
            None => format!("{first} first on this network: it answered sooner"),
        },
        Why::Failing => match r.fail {
            Some(t) => format!(
                "{first} first on this network: {} did not answer {}",
                carrier_name(t.carrier),
                tries(t.k, t.n)
            ),
            None => format!("{first} first on this network: the usual first did not answer"),
        },
        Why::Recovering => match r.ok {
            Some(t) => format!(
                "{} moves back up on this network: it worked {}",
                carrier_name(t.carrier),
                tries(t.k, t.n)
            ),
            None => "back toward the usual order on this network".to_string(),
        },
        Why::Contradiction => {
            "the usual order for a while: what was learned did not fit".to_string()
        }
        Why::Unreadable => {
            "the usual order: what was learned could not be read, so learning started over"
                .to_string()
        }
        Why::Off => "the usual order: learning is off".to_string(),
        Why::Held => "the usual order: learning is held in this build".to_string(),
        Why::Shadow => "the usual order: learning only watches for now".to_string(),
    };
    if let Some(age) = r.age_s {
        text.push_str(&format!(" ({} ago)", super::p2p_cli::age_text(age)));
    }
    Some(text)
}

/// [`reason_text`], or the order alone ("Internet, then LAN") when the
/// reason cannot be read.
fn row_text(row: &LearningRow) -> String {
    reason_text(&row.why).unwrap_or_else(|| {
        let names: Vec<String> = row
            .order
            .iter()
            .map(|l| {
                carrier_of_label(l)
                    .map_or_else(|| sanitize_terminal_line(l), |c| carrier_name(c).into())
            })
            .collect();
        if names.is_empty() {
            "a learned order".into()
        } else {
            names.join(", then ")
        }
    })
}

/// The rows of `status` this book names: (label, sentence), keys it does
/// not hold skipped, at most `max` and then `(+N more)`.
pub(super) fn rows(
    status: &LearningStatus,
    contacts: &[Contact],
    max: usize,
) -> Vec<(String, String)> {
    let known: Vec<(String, String)> = status
        .rows
        .iter()
        .filter_map(|row| {
            let contact = contacts.iter().find(|c| {
                c.pub_hex
                    .trim()
                    .eq_ignore_ascii_case(row.peer_pub_hex.trim())
            })?;
            Some((contact.primary_label(), row_text(row)))
        })
        .collect();
    let more = known.len().saturating_sub(max);
    let mut rows: Vec<(String, String)> = known.into_iter().take(max).collect();
    if more > 0 {
        rows.push((String::new(), format!("(+{more} more)")));
    }
    rows
}

/// The state as `raven learning status` and `raven status` word it.
fn state_text(state: &str) -> String {
    match State::parse(state) {
        Some(State::On) => "on".into(),
        Some(State::Shadow) => "watching only (it changes nothing yet)".into(),
        Some(State::Off) => "off (raven learning on)".into(),
        Some(State::MemoryOnly) => {
            "on, in memory only (this profile's key is not available here: nothing is saved)".into()
        }
        Some(State::ResetAfterUnreadable) => {
            "on, started over (what was learned could not be read)".into()
        }
        None => sanitize_terminal_line(state),
    }
}

/// `n thing` / `n things`.
fn count(n: u32, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `raven learning status`'s lines for `view` (names from `contacts`).
pub(super) fn status_lines(view: &LearningView<'_>, contacts: &[Contact]) -> Vec<String> {
    let l = match view {
        LearningView::Live(l) => *l,
        LearningView::Held => return vec!["learning: held in this build".into()],
        LearningView::Off => return vec!["learning: off (raven learning on)".into()],
        LearningView::NeedsNode => return vec!["learning: needs raven-node running".into()],
    };
    let mut lines = vec![format!("learning: {}", state_text(&l.state))];
    if State::parse(&l.state) == Some(State::Off) {
        return lines;
    }
    lines.push(format!(
        "  remembers {} on {}, {} and {}",
        count(l.contacts, "contact", "contacts"),
        count(l.networks, "network", "networks"),
        count(l.relays, "relay", "relays"),
        count(l.carriers, "mail-friend record", "mail-friend records")
    ));
    lines.push(format!(
        "  last 24 hours: {} watched, {}, {} dropped, {} set aside",
        count(l.observations_24h, "try", "tries"),
        count(l.probes_24h, "probe", "probes"),
        l.dropped_24h,
        count(l.contradictions, "learned order", "learned orders")
    ));
    lines.push(match l.saved_age_s {
        Some(age) => format!("  saved {} ago", super::p2p_cli::age_text(age)),
        None => "  not saved yet".into(),
    });
    let named = rows(l, contacts, usize::MAX);
    if named.is_empty() {
        lines.push("  (nothing learned about your contacts on this network yet)".into());
    }
    for (name, text) in named {
        lines.push(format!("  {name}: {text}"));
    }
    lines
}

/// `raven learning status --json`: raven-node's report as it is, or one
/// with only a `state` of `held`, `off` or `not_running`.
pub(super) fn status_json(view: &LearningView<'_>) -> String {
    let state = |s: &str| LearningStatus {
        state: s.into(),
        ..LearningStatus::default()
    };
    let shown = match view {
        LearningView::Live(l) => (*l).clone(),
        LearningView::Held => state("held"),
        LearningView::Off => state("off"),
        LearningView::NeedsNode => state("not_running"),
    };
    serde_json::to_string(&shown).unwrap_or_default()
}

/// The LEARNING section of `raven status`: its dim note and rows (label,
/// sentence; at most [`SHOWN_ROWS`], then `(+N more)`), only while the
/// running raven-node reports learning and it is not off.
pub(super) fn status_section(
    daemon: &Result<IpcResponse, String>,
    contacts: &[Contact],
) -> Option<(String, Vec<(String, String)>)> {
    let Ok(IpcResponse::Status {
        learning: Some(l), ..
    }) = daemon
    else {
        return None;
    };
    if State::parse(&l.state) == Some(State::Off) {
        return None;
    }
    let note = match State::parse(&l.state) {
        Some(State::On) => "(Raven tries first what worked on this network)".to_string(),
        _ => format!("learning is {}", state_text(&l.state)),
    };
    let rows: Vec<(String, String)> = rows(l, contacts, SHOWN_ROWS)
        .into_iter()
        .map(|(name, text)| (key_label(&name), text))
        .collect();
    Some((note, rows))
}

/// `raven doctor`'s learning lines while the running raven-node reports
/// learning: `learning: state=… contacts=… …` (counts), then at most
/// [`SHOWN_ROWS`] `learning_row_<n>: order=… why=…` (tokens), never a name
/// or key. Nothing for an older raven-node or the hold (the gate matrix
/// lists that).
pub(super) fn doctor_lines(status: &Result<IpcResponse, String>) -> Vec<String> {
    let Ok(IpcResponse::Status {
        learning: Some(l), ..
    }) = status
    else {
        return Vec::new();
    };
    let mut lines = vec![format!(
        "learning: state={} contacts={} networks={} observations_24h={} probes_24h={} \
         dropped_24h={} contradictions={} saved_age={}",
        doctor_word(&l.state),
        l.contacts,
        l.networks,
        l.observations_24h,
        l.probes_24h,
        l.dropped_24h,
        l.contradictions,
        l.saved_age_s
            .map_or_else(|| "-".into(), |s| format!("{s}s"))
    )];
    for (i, row) in l.rows.iter().take(SHOWN_ROWS).enumerate() {
        lines.push(format!("learning_row_{}: {}", i + 1, doctor_row(row)));
    }
    lines
}

/// One `learning_row_<n>` value: the reason's order and tokens, or the
/// order's labels with `why=-` when the reason cannot be read.
fn doctor_row(row: &LearningRow) -> String {
    let token = |c: OutboxCarrier| carrier_token(c).unwrap_or("nearby");
    match Reason::find(&row.why) {
        Some(r) => {
            let order: Vec<&str> = r.order.iter().map(|c| token(*c)).collect();
            let mut text = format!(
                "order={} why={}",
                doctor_word(&order.join(",")),
                doctor_word(r.why.token())
            );
            for (key, tally) in [("fail", r.fail), ("ok", r.ok)] {
                if let Some(t) = tally {
                    text.push_str(&format!(" {key}={}:{}/{}", token(t.carrier), t.k, t.n));
                }
            }
            text
        }
        None => {
            let order: Vec<String> = row
                .order
                .iter()
                .map(|l| carrier_of_label(l).map_or_else(|| l.clone(), |c| token(c).into()))
                .collect();
            format!("order={} why=-", doctor_word(&order.join(",")))
        }
    }
}

// ── Reset ────────────────────────────────────────────────────────────────

/// The question `raven learning reset` asks on a terminal (`name`: the
/// contact, or everyone).
pub(super) fn reset_question(name: Option<&str>) -> String {
    match name {
        Some(name) => format!("Forget what Raven learned about delivery for {name}? [y/N] "),
        None => "Forget what Raven learned about delivery for everyone? [y/N] ".into(),
    }
}

/// Go ahead: `--yes`, or `y`/`yes` typed on a terminal (`ask` prints the
/// question and reads the answer; EOF is no answer). Without a terminal it
/// needs `--yes`.
pub(super) fn confirmed(
    yes: bool,
    tty: bool,
    ask: impl FnOnce() -> Option<String>,
) -> Result<(), String> {
    if yes {
        return Ok(());
    }
    if !tty {
        return Err("stdin is not a terminal: pass --yes to forget without the question".into());
    }
    if ask().is_some_and(|a| answer_is_yes(&a)) {
        Ok(())
    } else {
        Err("cancelled \u{2014} nothing forgotten".into())
    }
}

/// The learning file is there (a symlink or a file that does not open
/// counts: it is removed or replaced too).
fn on_disk(data_dir: &Path) -> bool {
    std::fs::symlink_metadata(data_dir.join(store::LEARNING_FILE)).is_ok()
}

/// Forget what was learned about `peer` (or everyone): the contacts whose
/// rows went. `ask` is IPC `LearningReset` (`Ok(None)`: the running
/// raven-node holds learning or is older); when it answers, it did the work
/// in memory and on disk. With none running (or `Ok(None)`), the file is
/// changed here with `sealer` ([`forget_in_file`]). Any other answer (a
/// raven-node that does not answer, or could not change the file) is an
/// error and nothing is touched here: it would save its model over the
/// change.
pub(super) fn forget_learned(
    data_dir: &Path,
    peer: Option<&[u8; 32]>,
    ask: impl FnOnce(Option<&str>) -> Result<Option<u32>, String>,
    sealer: &dyn Sealer,
    now: u64,
) -> Result<u32, String> {
    let peer_hex = peer.map(hex::encode);
    match ask(peer_hex.as_deref()) {
        Ok(Some(cleared)) => Ok(cleared),
        Ok(None) => forget_in_file(data_dir, peer, sealer, now),
        Err(e) if ipc_client::error_means_not_running(&e) => {
            forget_in_file(data_dir, peer, sealer, now)
        }
        Err(e) => Err(format!(
            "raven-node could not forget what it learned ({}); nothing changed, try again",
            sanitize_terminal_line(&e)
        )),
    }
}

/// [`forget_learned`] with no raven-node doing it: everyone's file removed
/// (the contacts it held counted when it opens), or saved without `peer`'s
/// rows. No file: nothing (and no lock file made). A file that does not
/// open here (this profile's key is not loaded, or a newer Raven wrote it)
/// cannot lose one contact's rows: an error; one that could not be read at
/// all holds nothing to forget (the next save replaces it).
pub(super) fn forget_in_file(
    data_dir: &Path,
    peer: Option<&[u8; 32]>,
    sealer: &dyn Sealer,
    now: u64,
) -> Result<u32, String> {
    if !on_disk(data_dir) {
        return Ok(0);
    }
    let (mut model, state) = store::load(data_dir, sealer, now);
    match (peer, state) {
        (None, _) => {
            let cleared = if state == StoreState::On {
                model.sizes().contacts
            } else {
                0
            };
            store::delete(data_dir)?;
            Ok(cleared)
        }
        (Some(p), StoreState::On) => {
            let cleared = u32::from(model.forget_contact(p) > 0);
            if cleared > 0 {
                store::save(data_dir, sealer, &model, now)?;
            }
            Ok(cleared)
        }
        (Some(_), StoreState::ResetAfterUnreadable) => Ok(0),
        (Some(_), StoreState::MemoryOnly(_) | StoreState::Shadow) => Err(
            "what Raven learned could not be opened here, so one contact cannot be taken out \
             of it (`raven learning reset` for everyone deletes it)"
                .into(),
        ),
    }
}

/// `forget_outbox_routes` (a contact removed, its addresses changed):
/// forget what was learned about `peer`, and what a running raven-node's
/// sends found of its routes, best effort. With learning held and no file
/// that is only the node's part (one IPC request, no file read).
pub(super) fn forget_contact(data_dir: &Path, peer: &[u8; 32]) -> Result<(), String> {
    // Asked of a running raven-node whether learning is on or not: the same
    // request (IPC `LearningReset`) makes it forget what its sends found of
    // this contact's routes, and a changed route is news a send must try
    // (carrier matrix C26: with learning off, a relay set by hand was not
    // dialled while the old one's failure was fresh, two minutes). With
    // learning off the node answers LEARNING_HOLD after forgetting them,
    // and there is no file to clear.
    forget_learned(
        data_dir,
        Some(peer),
        |hex| ipc_client::learning_reset(data_dir, hex),
        &PlatformSealer,
        now_ms(),
    )
    .map(|_| ())
}

/// Route memory (G2) for `peer`, or for everyone (OD6a-10); a note when it
/// could not be forgotten.
fn forget_route_memory(data_dir: &Path, peer: Option<&[u8; 32]>) -> Option<String> {
    let result = match peer {
        Some(p) => raven_core::route_memory::forget(data_dir, p),
        None => raven_core::route_memory::forget_all(data_dir).map(|_| ()),
    };
    result.err().map(|e| {
        format!(
            "note: could not forget the remembered routes ({})",
            sanitize_terminal_line(&e)
        )
    })
}

/// What `reset` says once it forgot: how many contacts were cleared.
pub(super) fn reset_line(name: Option<&str>, cleared: u32) -> String {
    let who = name.map_or_else(|| "everyone".to_string(), |n| n.to_string());
    if cleared == 0 {
        format!("Nothing was learned about delivery for {who} yet: nothing to forget (cleared 0).")
    } else {
        format!(
            "Forgot what Raven learned about delivery for {who} ({} cleared).",
            count(cleared, "contact", "contacts")
        )
    }
}

/// The contact `arg` names, as (label, key).
fn contact_key(data_dir: &Path, arg: &str) -> Result<(String, [u8; 32]), String> {
    let contacts = load_contacts(data_dir)?;
    let hits = resolve_contact_arg(&contacts, arg);
    let c = match hits.as_slice() {
        [] => return Err(no_contact_message(&contacts, arg)),
        [c] => *c,
        _ => {
            return Err(format!(
                "contact {} is ambiguous ({} matches): use the @tag, or see `ash contact list`",
                sanitize_terminal_line(arg),
                hits.len()
            ))
        }
    };
    let key: [u8; 32] = hex::decode(c.pub_hex.trim())
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| {
            format!(
                "{} has no valid key in your contact book",
                c.primary_label()
            )
        })?;
    Ok((c.primary_label(), key))
}

// ── The switch ───────────────────────────────────────────────────────────

/// Save the switch (`node_policy.learning`): `Some(true)` on, `Some(false)`
/// off. Never over an unreadable policy (the user's other settings would go
/// with it).
fn save_switch(data_dir: &Path, on: bool) -> Result<(), String> {
    try_load_policy(data_dir).map_err(|e| {
        format!(
            "node_policy.json is unreadable ({}); fix or move it aside first (nothing changed)",
            sanitize_terminal_line(&e.to_string())
        )
    })?;
    update_policy(data_dir, |p| p.learning = Some(on))
        .map(|_| ())
        .map_err(|e| format!("save policy failed: {e}"))
}

/// Until the running raven-node reports learning off (or none), at most
/// `wait`: it reads the switch every 2 s and saves what changed as it lets
/// the model go, so a reset after that is not written over.
fn wait_until_off(status: impl Fn() -> Result<IpcResponse, String>, wait: Duration) {
    let deadline = Instant::now() + wait;
    loop {
        match status() {
            Ok(IpcResponse::Status {
                learning: Some(l), ..
            }) if State::parse(&l.state) != Some(State::Off) => {}
            _ => return,
        }
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// `raven learning on|off [--forget]`: the lines to print.
fn switch(data_dir: &Path, on: bool, forget: bool) -> Result<Vec<String>, String> {
    save_switch(data_dir, on)?;
    let mut lines = vec![if on {
        "ok learning: on. Raven tries first what worked on this network.".to_string()
    } else {
        "ok learning: off. Raven tries the ways it reaches a contact in the usual order."
            .to_string()
    }];
    if !raven_core::learning::learning_live() {
        lines.push(
            "  (learning is held in this build: the choice applies once it is released)".into(),
        );
    }
    if forget {
        let status =
            || ipc_client::ipc_request_timeout(data_dir, &IpcRequest::status(), STATUS_TIMEOUT);
        if status().is_ok() {
            wait_until_off(status, OFF_APPLIED_WAIT);
        }
        let cleared = forget_learned(
            data_dir,
            None,
            |hex| ipc_client::learning_reset(data_dir, hex),
            &PlatformSealer,
            now_ms(),
        )?;
        // The file goes whatever the node answered (none running, held).
        store::delete(data_dir)?;
        lines.push(format!(
            "  forgot what was learned ({} cleared)",
            count(cleared, "contact", "contacts")
        ));
    }
    Ok(lines)
}

/// `raven learning …`: the lines to print, or why not.
pub(super) fn cmd_learning(data_dir: &Path, arg: LearningArg) -> Result<Vec<String>, String> {
    match arg {
        LearningArg::Status { json } => {
            let daemon =
                ipc_client::ipc_request_timeout(data_dir, &IpcRequest::status(), STATUS_TIMEOUT);
            let v = view(
                &daemon,
                raven_core::learning::learning_live(),
                switch_off(data_dir),
            );
            if json {
                return Ok(vec![status_json(&v)]);
            }
            // An unreadable book names nobody; the counts still show.
            let contacts = load_contacts(data_dir).unwrap_or_default();
            Ok(status_lines(&v, &contacts))
        }
        LearningArg::Reset { contact, yes } => {
            let target = contact
                .as_deref()
                .map(|arg| contact_key(data_dir, arg))
                .transpose()?;
            let name = target.as_ref().map(|(name, _)| name.as_str());
            confirmed(yes, stdin_is_tty(), || {
                use std::io::Write as _;
                print!("{}", reset_question(name));
                let _ = std::io::stdout().flush();
                read_decision_line()
            })?;
            let peer = target.as_ref().map(|(_, key)| key);
            let cleared = forget_learned(
                data_dir,
                peer,
                |hex| ipc_client::learning_reset(data_dir, hex),
                &PlatformSealer,
                now_ms(),
            )?;
            let mut lines = vec![reset_line(name, cleared)];
            lines.extend(forget_route_memory(data_dir, peer));
            Ok(lines)
        }
        LearningArg::On => switch(data_dir, true, false),
        LearningArg::Off { forget } => switch(data_dir, false, forget),
    }
}

/// Print `raven learning`'s lines: a first `ok` in green, the rest as
/// they are.
pub(super) fn print_lines(lines: &[String]) {
    for (i, line) in lines.iter().enumerate() {
        match line.strip_prefix("ok ").filter(|_| i == 0) {
            Some(rest) => println!("{C_GREEN}ok{C_RESET} {rest}"),
            None => println!("{line}"),
        }
    }
}

#[cfg(test)]
mod tests;
