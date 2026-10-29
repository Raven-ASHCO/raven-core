//! Groups in the CLI (docs/design/2026-10-groups.md §8): `raven group
//! create|add|remove|leave|list|show|send`, and the group section of
//! `raven inbox`.
//!
//! - **Held** by [`raven_core::group::GROUPS_PRODUCTION_ENABLED`] (false; a
//!   debug build opens it with `RAVEN_LAB_TEST_A=1 RAVEN_LAB_HORIZON=1
//!   RAVEN_LAB_GROUPS=1`). Reading (`list`, `show`, the inbox section) works
//!   with the gate closed: what was stored stays readable.
//! - **Delivery.** Every copy is parked for raven-node's outbox
//!   (`raven_core::group::park`), which seals and sends it; a command kicks
//!   the outbox, starting raven-node as `raven send` does when none runs.
//! - **Names.** A member who is a friend is shown by this contact book's
//!   name, any other by the admin's label; keys only as their first 8 hex
//!   characters.

use std::io::{self, IsTerminal};
use std::path::Path;

use raven_core::clock::now_ms;
use raven_core::group::{
    self, GroupError, GroupId, GroupView, Key, MessageView, MAX_GROUP_BODY_BYTES,
};
use raven_core::sanitize::sanitize_terminal_line;

use super::{C_BOLD, C_DIM, C_GREEN, C_RESET};

/// What `raven group` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GroupArg {
    Create {
        name: String,
        members: Vec<String>,
    },
    Add {
        group: String,
        members: Vec<String>,
    },
    Remove {
        group: String,
        members: Vec<String>,
    },
    Leave {
        group: String,
        yes: bool,
    },
    List,
    Show {
        group: String,
        /// Every message the group keeps, not only the newest.
        all: bool,
    },
    /// The text comes from stdin.
    Send {
        group: String,
    },
}

/// Recent messages `raven group show` lists.
const SHOW_MESSAGES: usize = 20;
/// Group messages `raven inbox` lists, newest last.
const INBOX_GROUP_ROWS: usize = 20;

fn err_text(e: &GroupError) -> String {
    e.to_string()
}

fn short(key: &[u8]) -> String {
    hex::encode(&key[..4.min(key.len())])
}

fn identity(data_dir: &Path) -> Result<raven_core::identity::Identity, String> {
    match super::try_load_identity(data_dir)? {
        Some(id) => Ok(id),
        None => Err(err_text(&GroupError::NoIdentity)),
    }
}

/// `@tag` or a name of this contact book, each to exactly one friend: its
/// key and the name the other members will see.
fn resolve_members(data_dir: &Path, asked: &[String]) -> Result<Vec<(Key, String)>, String> {
    let contacts = super::load_contacts(data_dir)?;
    let mut out: Vec<(Key, String)> = Vec::new();
    for arg in asked {
        let found = super::resolve_contact_arg(&contacts, arg);
        let contact = match found.as_slice() {
            [one] => *one,
            [] => return Err(super::no_contact_message(&contacts, arg)),
            _ => {
                return Err(format!(
                    "more than one contact matches {}; use their @tag",
                    sanitize_terminal_line(arg)
                ))
            }
        };
        let key = hex::decode(contact.pub_hex.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| format!("{}: no valid key saved", sanitize_terminal_line(arg)))?;
        if !out.iter().any(|(k, _)| *k == key) {
            out.push((key, sanitize_terminal_line(&contact.petname)));
        }
    }
    Ok(out)
}

fn find(data_dir: &Path, query: &str) -> Result<GroupId, String> {
    group::find(data_dir, query).map_err(|e| err_text(&e))
}

/// Ask raven-node to send what was parked; start it when none answers, as
/// `raven send` does. The line to show when nothing runs.
fn kick(data_dir: &Path) -> Option<String> {
    if super::pair_init_lab::outbox_kick(data_dir, None) {
        return None;
    }
    // Unit tests never start a raven-node.
    if cfg!(test) {
        return Some("raven-node is not running (test)".into());
    }
    if super::ext::ensure_mac_lan_daemon(data_dir).is_ok()
        && super::pair_init_lab::outbox_kick(data_dir, None)
    {
        return None;
    }
    Some(
        "raven-node is not running: the messages wait on this computer and go once it runs \
         (`raven listen`, or Raven's login item)."
            .into(),
    )
}

/// Run `raven group …`; the lines to print.
pub(super) fn cmd_group(data_dir: &Path, arg: GroupArg) -> Result<Vec<String>, String> {
    match arg {
        GroupArg::List => list_lines(data_dir),
        GroupArg::Show { group, all } => {
            let id = find(data_dir, &group)?;
            if let Ok(Some(me)) = super::try_load_identity(data_dir) {
                let _ = group::run_pending(data_dir, &me, now_ms());
            }
            show_lines(data_dir, &id, all)
        }
        GroupArg::Create { name, members } => {
            let me = identity(data_dir)?;
            let name = group::clean_text(&name, group::MAX_GROUP_NAME_CHARS);
            if members.is_empty() {
                return Err("name at least one friend: --member NAME (or @tag)".into());
            }
            let list = resolve_members(data_dir, &members)?;
            let id =
                group::create(data_dir, &me, &name, &list, now_ms()).map_err(|e| err_text(&e))?;
            let mut lines = vec![format!(
                "ok group {} created ({} members, you are its admin; id {})",
                sanitize_terminal_line(&name),
                list.len() + 1,
                short(&id)
            )];
            lines.extend(kick(data_dir));
            Ok(lines)
        }
        GroupArg::Add { group: g, members } => {
            let me = identity(data_dir)?;
            let id = find(data_dir, &g)?;
            let list = resolve_members(data_dir, &members)?;
            let state = group::add_members(data_dir, &me, &id, &list, now_ms())
                .map_err(|e| err_text(&e))?;
            let mut lines = vec![format!(
                "ok added {} to {} ({} members now)",
                names(&list),
                sanitize_terminal_line(&state.name),
                state.members.len()
            )];
            lines.extend(kick(data_dir));
            Ok(lines)
        }
        GroupArg::Remove { group: g, members } => {
            let me = identity(data_dir)?;
            let id = find(data_dir, &g)?;
            let keys = remove_targets(data_dir, &id, &members)?;
            let state = group::remove_members(data_dir, &me, &id, &keys, now_ms())
                .map_err(|e| err_text(&e))?;
            let mut lines = vec![format!(
                "ok removed {} from {} ({} members now); they keep what they already received",
                keys.len(),
                sanitize_terminal_line(&state.name),
                state.members.len()
            )];
            lines.extend(kick(data_dir));
            Ok(lines)
        }
        GroupArg::Leave { group: g, yes } => {
            let me = identity(data_dir)?;
            let id = find(data_dir, &g)?;
            let view = group::view(data_dir, &id).map_err(|e| err_text(&e))?;
            let name = sanitize_terminal_line(&view.summary.name);
            if !yes {
                if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
                    return Err("leaving a group needs --yes when stdin is not a terminal".into());
                }
                let question = format!(
                    "Leave {name}? You get none of its new messages and send none; what you \
                     received stays here. [y/N] "
                );
                if !super::custody_cli::said_yes(super::custody_cli::ask_on_terminal(&question)) {
                    return Ok(vec!["nothing changed".into()]);
                }
            }
            group::leave(data_dir, &me, &id, now_ms()).map_err(|e| err_text(&e))?;
            let mut lines = vec![format!("ok you left {name}; its admin is told")];
            lines.extend(kick(data_dir));
            Ok(lines)
        }
        GroupArg::Send { group: g } => {
            let me = identity(data_dir)?;
            let id = find(data_dir, &g)?;
            if io::stdin().is_terminal() {
                eprintln!(
                    "{C_DIM}Type the message, then press {}.{C_RESET}",
                    super::END_OF_INPUT
                );
            }
            let text = super::read_message_text(io::stdin(), MAX_GROUP_BODY_BYTES)?;
            if text.trim().is_empty() {
                return Err("nothing to send (the message is empty)".into());
            }
            let report =
                group::send(data_dir, &me, &id, &text, now_ms()).map_err(|e| err_text(&e))?;
            let mut line = format!(
                "ok sent to {} member(s): {} sealed for your friends",
                report.direct + report.relayed,
                report.direct
            );
            if report.relayed > 0 {
                line.push_str(&format!(
                    ", {} passed on by another member (they are not your friends)",
                    report.relayed
                ));
            }
            line.push_str(&format!("; id {}", short(&report.id)));
            let mut lines = vec![line];
            if report.parked < report.direct {
                lines.push(format!(
                    "{} cop(ies) wait to be queued (another send is busy); Raven tries again",
                    report.direct - report.parked
                ));
            }
            lines.push(format!(
                "`raven group show {}` shows who has it",
                short(&id)
            ));
            lines.extend(kick(data_dir));
            Ok(lines)
        }
    }
}

fn names(list: &[(Key, String)]) -> String {
    list.iter()
        .map(|(k, n)| if n.is_empty() { short(k) } else { n.clone() })
        .collect::<Vec<_>>()
        .join(", ")
}

/// `--member` values for a remove: a friend's name or @tag, or a member's
/// name as the group shows it (a member who is not a friend), or the start
/// of its key.
fn remove_targets(data_dir: &Path, id: &GroupId, asked: &[String]) -> Result<Vec<Key>, String> {
    let view = group::view(data_dir, id).map_err(|e| err_text(&e))?;
    let mut out = Vec::new();
    for arg in asked {
        let want = sanitize_terminal_line(arg.trim().trim_start_matches('@')).to_lowercase();
        let by_view: Vec<Key> = view
            .members
            .iter()
            .filter(|m| {
                !m.me
                    && (m.display().to_lowercase() == want
                        || (want.len() >= 4 && hex::encode(m.key).starts_with(&want)))
            })
            .map(|m| m.key)
            .collect();
        let key = match by_view.as_slice() {
            [one] => *one,
            [] => match resolve_members(data_dir, std::slice::from_ref(arg)) {
                Ok(found) if found.len() == 1 => found[0].0,
                _ => {
                    return Err(format!(
                        "{} is not in this group (`raven group show` lists its members)",
                        sanitize_terminal_line(arg)
                    ))
                }
            },
            _ => {
                return Err(format!(
                    "more than one member matches {}; use the start of their key",
                    sanitize_terminal_line(arg)
                ))
            }
        };
        if !out.contains(&key) {
            out.push(key);
        }
    }
    Ok(out)
}

fn status_word(status: &str) -> &'static str {
    match status {
        group::store::STATUS_LEFT => "you left",
        group::store::STATUS_REMOVED => "you were removed",
        _ => "",
    }
}

fn list_lines(data_dir: &Path) -> Result<Vec<String>, String> {
    let groups = group::list(data_dir).map_err(|e| err_text(&e))?;
    let mut lines = Vec::new();
    if !group::group_live_enabled() {
        lines.push(format!("{C_DIM}{}{C_RESET}", GroupError::Hold.sentence()));
    }
    if groups.is_empty() {
        lines.push(
            "no groups yet. Create one: raven group create NAME --member FRIEND --member FRIEND"
                .into(),
        );
        return Ok(lines);
    }
    lines.push(format!("{C_BOLD}groups{C_RESET} ({})", groups.len()));
    for g in &groups {
        let mut extra = Vec::new();
        if g.i_am_admin {
            extra.push("you are the admin".to_owned());
        }
        if g.unread > 0 {
            extra.push(format!("{} unread", g.unread));
        }
        let word = status_word(&g.status);
        if !word.is_empty() {
            extra.push(word.into());
        }
        lines.push(format!(
            "  {}  {C_DIM}{}{C_RESET}  {} members{}",
            sanitize_terminal_line(&g.name),
            short(&g.id),
            g.members,
            if extra.is_empty() {
                String::new()
            } else {
                format!("  ({})", extra.join(", "))
            }
        ));
    }
    Ok(lines)
}

/// How a member reads in a delivery list.
fn line_word(state: &str) -> &'static str {
    match state {
        group::store::LINE_DELIVERED => "delivered",
        group::store::LINE_SENT => "sent",
        group::store::LINE_FAILED => "not delivered",
        _ => "waiting",
    }
}

/// One message as `show` and the inbox print it.
fn message_line(
    view: &GroupView,
    m: &MessageView,
    names: &std::collections::HashMap<Key, String>,
    now: u64,
) -> String {
    let who = if m.mine {
        "you".to_owned()
    } else {
        view.name_of(&m.from, names)
    };
    let mut line = format!(
        "  {C_DIM}{}{C_RESET} {}: {}",
        super::short_age(now, m.received_ms),
        sanitize_terminal_line(&who),
        sanitize_terminal_line(&m.body)
    );
    line.push_str(&format!(
        " {C_DIM}({}){C_RESET}",
        how_it_came(
            m,
            |k| view.name_of(k, names),
            |at| { super::ext::ended_text_zoned(at, now) }
        )
        .join(", ")
    ));
    if m.mine && m.total > 0 {
        let parts: Vec<String> = m
            .lines
            .iter()
            .map(|(k, state, _)| {
                format!(
                    "{} {}",
                    sanitize_terminal_line(&view.name_of(k, names)),
                    line_word(state)
                )
            })
            .collect();
        line.push_str(&format!(
            " {C_DIM}\u{2014} delivered to {} of {} ({}){C_RESET}",
            m.delivered,
            m.total,
            parts.join(", ")
        ));
    }
    line
}

/// How and when a message came, in order (E2 r9 #15: only "2 min ago" was
/// shown, with no path): for one of yours when you sent it; for a member's
/// how its copy came ("via Tor", "from a keeper"), who passed it on when it
/// was not its author ("passed on by Ana": the admin's forward), and when
/// it arrived. `name`: a member's name; `when`: a time in words with its
/// zone.
fn how_it_came(
    m: &MessageView,
    name: impl Fn(&Key) -> String,
    when: impl Fn(u64) -> String,
) -> Vec<String> {
    if m.mine {
        return vec![format!("sent {}", when(m.sent_ms))];
    }
    let mut how = Vec::new();
    if let Some(path) = m.path {
        how.push(path.phrase());
    }
    if let Some(via) = m.via {
        how.push(format!(
            "passed on by {}",
            sanitize_terminal_line(&name(&via))
        ));
    }
    how.push(format!("arrived {}", when(m.received_ms)));
    how
}

/// The header of `show`'s messages: how many are shown and, when the group
/// keeps older ones, how many and how to see them (E2 r9 #16: "messages
/// (newest 15)" gave no hint that older ones exist).
fn messages_header(shown: usize, total: usize, group_name: &str) -> String {
    if total <= shown {
        return format!("messages ({shown}):");
    }
    let name = sanitize_terminal_line(group_name);
    let arg = if name.contains(char::is_whitespace) {
        format!("\"{name}\"")
    } else {
        name
    };
    format!(
        "messages (newest {shown} of {total}; {} older: `raven group show {arg} --all`):",
        total - shown
    )
}

fn show_lines(data_dir: &Path, id: &GroupId, all: bool) -> Result<Vec<String>, String> {
    let view = group::view(data_dir, id).map_err(|e| err_text(&e))?;
    let s = &view.summary;
    let mut lines = vec![format!(
        "{C_BOLD}{}{C_RESET}  {C_DIM}id {} \u{00b7} epoch {}{C_RESET}{}",
        sanitize_terminal_line(&s.name),
        hex::encode(s.id),
        s.epoch,
        match status_word(&s.status) {
            "" => String::new(),
            w => format!("  ({w})"),
        }
    )];
    lines.push(format!("members ({}):", view.members.len()));
    for m in &view.members {
        let mut tags = Vec::new();
        if m.admin {
            tags.push("admin");
        }
        if !m.me {
            tags.push(if m.friend_name.is_some() {
                "your friend"
            } else {
                "not your friend; named by the admin"
            });
        }
        lines.push(format!(
            "  {}  {C_DIM}{}{}{C_RESET}",
            sanitize_terminal_line(&m.display()),
            short(&m.key),
            if tags.is_empty() {
                String::new()
            } else {
                format!(" \u{00b7} {}", tags.join(", "))
            }
        ));
    }
    let mut history = group::history(data_dir, id, None, usize::MAX).map_err(|e| err_text(&e))?;
    let total = history.len();
    if !all {
        history.drain(..total.saturating_sub(SHOW_MESSAGES));
    }
    if history.is_empty() {
        lines.push(format!("{C_DIM}no messages yet{C_RESET}"));
    } else {
        lines.push(messages_header(history.len(), total, &s.name));
        let now = now_ms();
        let names = group::friend_names(data_dir);
        lines.extend(history.iter().map(|m| message_line(&view, m, &names, now)));
    }
    let _ = group::mark_read(data_dir, id, now_ms());
    Ok(lines)
}

/// `raven inbox`'s group section: the newest received group messages,
/// `[group] name: text`. Empty without groups (or a store that cannot be
/// read: the chat inbox is shown as before).
pub(super) fn inbox_lines(data_dir: &Path) -> Vec<String> {
    let Ok(groups) = group::list(data_dir) else {
        return Vec::new();
    };
    let names = group::friend_names(data_dir);
    let now = now_ms();
    let mut rows: Vec<(u64, String)> = Vec::new();
    for g in &groups {
        let Ok(view) = group::view(data_dir, &g.id) else {
            continue;
        };
        let Ok(history) = group::history(data_dir, &g.id, None, INBOX_GROUP_ROWS) else {
            continue;
        };
        for m in history.iter().filter(|m| !m.mine) {
            rows.push((
                m.received_ms,
                format!(
                    "  {C_DIM}{}{C_RESET} [{}] {}: {}",
                    super::short_age(now, m.received_ms),
                    sanitize_terminal_line(&g.name),
                    sanitize_terminal_line(&view.name_of(&m.from, &names)),
                    sanitize_terminal_line(&m.body)
                ),
            ));
        }
    }
    if rows.is_empty() {
        return Vec::new();
    }
    rows.sort_by_key(|r| r.0);
    let start = rows.len().saturating_sub(INBOX_GROUP_ROWS);
    let mut lines = vec![format!(
        "{C_BOLD}group messages{C_RESET} ({}; `raven group show NAME` for one group)",
        rows.len()
    )];
    lines.extend(rows.drain(start..).map(|r| r.1));
    lines
}

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
