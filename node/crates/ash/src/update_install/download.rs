//! `raven update download` (Phase 6 P6.49; design D §6 and UX, OD6b-24):
//! the download approval for a release a friend offered this computer.
//!
//! - raven-node's update exchange notes every offer for this computer's
//!   target newer than this build in `updates/downloads` (who offered it,
//!   its build and size); nothing is fetched until the person approves it
//!   here or in the terminal app (UPDATES, Y). Then raven-node is woken
//!   (IPC `UpdateKick`) and fetches it, checking every part before it keeps
//!   it.
//! - A complete download is staged like an imported file (verified in full
//!   again, then `updates/staged/<serial>/`) by `raven update install` and
//!   by UPDATES before they show it; installing it is that separate,
//!   typed approval.
//! - The lab switch `RAVEN_LAB_UPDATE_AUTO_APPROVE=1` (debug builds with Lab
//!   Test A only) approves offers as they come (raven-node) and lets `raven
//!   update install` go on without the typed word: the update harness's
//!   C89 (P6.51). A release build never reads it.
//!
//! Every text names the friend who passed the update on (their name in this
//! profile's contacts, never a key), never blames them, and repeats that
//! Raven never installs anything without asking.

use raven_core::ipc::{IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::security_events::Via;
use raven_core::update_downloads::{
    self as downloads, ApproveError, Row, RowState, INCOMING_MANIFEST, INCOMING_PAYLOAD,
    INCOMING_SNAPSHOT, INCOMING_VERIFIED,
};

use super::*;

/// What `raven update download` says while updates from friends are off
/// (the mesh update gate, or the bundle gate below it, is shut).
pub(in super::super) const FRIENDS_OFF_TEXT: &str =
    "Raven updates from friends are not part of this version.";
/// With no offer waiting.
const NO_OFFER: &str = "No friend has offered a Raven update for this computer.";
/// How long the wake-up of raven-node may take.
const KICK_TIMEOUT: Duration = Duration::from_secs(5);
/// How many digits of an offer's code the CLI shows (and accepts at least).
const CODE_DIGITS: usize = 8;

/// Updates from friends: the mesh update gate (on the bundle and advisory
/// gates).
pub(in super::super) fn friends_live() -> bool {
    security_gate::live(SecGate::MeshUpdate)
}

/// The friend's name in this profile's contacts, else "a friend".
fn friend(data_dir: &Path, key: Option<&[u8; 32]>) -> String {
    let name = key
        .map(|k| super::super::ext::contact_label(data_dir, &hex::encode(k)))
        .unwrap_or_default();
    if name.is_empty() {
        "A friend".to_owned()
    } else {
        sanitize_terminal_line(&name)
    }
}

fn code(row: &Row) -> String {
    hex::encode(row.digest)[..CODE_DIGITS].to_owned()
}

/// The release a row is, as people read it: "Raven 1.5.0 (build 5)" once
/// its manifest checked, else "a Raven update (build 5)".
fn release_name(row: &Row) -> String {
    match &row.version {
        Some(version) => build_name(&sanitize_terminal_line(version), row.build_serial),
        None => format!("a Raven update (build {})", row.build_serial),
    }
}

/// The download prompt of an offer (design D UX), its question last.
pub(in super::super) fn offer_lines(data_dir: &Path, row: &Row) -> Vec<String> {
    let who = friend(data_dir, row.offered_by());
    vec![
        format!(
            "{who} has {} for this computer ({}).",
            release_name(row),
            size_text(row.payload_len)
        ),
        "Raven checks that it is signed by the Raven project keys and listed in the public \
         release log before it keeps any of it; installing it is a separate step."
            .to_owned(),
        format!("Download it from {who}?"),
    ]
}

/// `raven update status`'s lines about friends' offers and downloads.
pub(in super::super) fn download_lines(data_dir: &Path) -> Vec<String> {
    if !friends_live() {
        return Vec::new();
    }
    let rows = match downloads::load(data_dir) {
        Ok(rows) => rows.rows,
        Err(e) => {
            return vec![format!(
                "Raven can't read its list of updates from friends ({e})."
            )]
        }
    };
    let mut lines = Vec::new();
    for row in &rows {
        let who = friend(data_dir, row.offered_by());
        lines.push(match row.state {
            RowState::Offered => format!(
                "{who} has {} for this computer ({}): raven update download {}",
                release_name(row),
                size_text(row.payload_len),
                code(row)
            ),
            RowState::Approved => format!("Downloading {} from {who}.", release_name(row)),
            RowState::Downloading => format!(
                "Downloading {} from {who}: {} of {} parts, each checked.",
                release_name(row),
                row.chunks_have,
                row.chunks_total
            ),
            RowState::Complete => format!(
                "{} from {who} is downloaded and checked: raven update install",
                release_name(row)
            ),
            RowState::Staged => continue,
            RowState::Failed => failed_line(row, &who),
        });
    }
    lines
}

/// A failed row's status line. Only a failure of the friend's copy says the
/// friend passed on something that failed its checks; one caused on this
/// computer names no fault of theirs (Phase 6 review updates-protocol-7),
/// and one no log listed says just that (re-verify, updates-protocol-6).
fn failed_line(row: &Row, who: &str) -> String {
    match row
        .failed
        .as_deref()
        .unwrap_or(downloads::FAILED_NOT_STAGED)
    {
        downloads::FAILED_NO_ROOM => format!(
            "Raven had no room on this computer to download {} from {who}: install an update \
             it downloaded before (raven update install), then approve this one again: raven \
             update download {}",
            release_name(row),
            code(row)
        ),
        downloads::FAILED_NOT_LOGGED => format!(
            "{who} offered {}, but no Raven release log lists it: neither the one {who} sent \
             with it nor the one this computer has (NOT_LOGGED). Raven didn't use it. If the \
             Raven project published it, a newer log lists it: Raven tries again by itself once \
             a security notice brings one or a friend offers it.",
            release_name(row)
        ),
        code if downloads::failed_here(code) => format!(
            "{} from {who} was downloaded and checked, but this computer can no longer install \
             it (a newer Raven, a security notice or a freeze since). Raven removed it.",
            release_name(row)
        ),
        code => format!(
            "{who} passed on {} that failed its checks ({code}). Raven ignored it; {who} may not \
             know.",
            release_name(row)
        ),
    }
}

/// The first offer waiting for the person's approval (the terminal app's
/// UPDATES shows it with Y).
pub(in super::super) fn first_offer(data_dir: &Path) -> Option<(Row, Vec<String>)> {
    if !friends_live() {
        return None;
    }
    let rows = downloads::load(data_dir).ok()?;
    let row = rows
        .rows
        .into_iter()
        .find(|r| r.state == RowState::Offered)?;
    let lines = offer_lines(data_dir, &row);
    Some((row, lines))
}

/// Approve the offer whose code starts with `prefix` and wake raven-node.
/// The lines say what happens now.
pub(in super::super) fn approve(data_dir: &Path, prefix: &str) -> Result<Vec<String>, String> {
    if !friends_live() {
        return Err(FRIENDS_OFF_TEXT.to_owned());
    }
    let row = match downloads::approve(data_dir, prefix, raven_core::clock::now_ms())? {
        Ok(row) => row,
        Err(ApproveError::Unknown) => {
            return Err(format!(
                "No update offer starts with {}: raven update download lists them.",
                sanitize_terminal_line(prefix)
            ))
        }
        Err(ApproveError::Ambiguous) => {
            return Err("More than one offer starts with that: type more of its code.".to_owned())
        }
        Err(ApproveError::Already(state)) => {
            return Err(format!(
                "That update is {} already: raven update status says how far it is.",
                state.name()
            ))
        }
    };
    let who = friend(data_dir, row.offered_by());
    let kicked = matches!(
        super::super::ipc_client::ipc_request_timeout(
            data_dir,
            &IpcRequest::UpdateKick { v: IPC_VERSION },
            KICK_TIMEOUT,
        ),
        Ok(IpcResponse::Accepted { .. })
    );
    Ok(vec![
        if kicked {
            format!("Raven downloads it from {who} now, and checks every part before it keeps it.")
        } else {
            format!(
                "Raven downloads it from {who} once its background program runs (raven node \
                 start), and checks every part before it keeps it."
            )
        },
        "When it is complete, install it with: raven update install".to_owned(),
        NEVER_WITHOUT_ASKING.to_owned(),
    ])
}

/// Stage every complete download (verified in full again, like `raven
/// update import`): its row says `staged` and its folder in
/// `updates/incoming/` goes. A download that no longer checks (an install
/// in between, a freeze) fails with its reason (a cause on this computer,
/// [`downloads::FAILED_NOT_STAGED`]); one that cannot be read or written
/// now (the disk, the update state file) stays as it is for the next try.
/// The lines say what changed.
pub(in super::super) fn stage_downloads(data_dir: &Path, build: &Build) -> Vec<String> {
    if !friends_live() || !live() {
        return Vec::new();
    }
    let Ok(rows) = downloads::load(data_dir) else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    for row in rows.rows.iter().filter(|r| r.state == RowState::Complete) {
        let dir = downloads::incoming_dir(data_dir, &row.digest);
        if !dir.join(INCOMING_VERIFIED).exists() {
            continue;
        }
        let origin = Origin {
            passed_by: row.offered_by().copied(),
            via: Via::Local,
        };
        let outcome = parts_of(&dir, row)
            .and_then(|parts| stage_bundle(data_dir, build, &parts, false, origin));
        let (state, failed) = match outcome {
            Ok(_) => (RowState::Staged, None),
            Err(NotStaged::Later(why)) => {
                // Kept as it is: tried again next time.
                lines.push(why);
                continue;
            }
            Err(NotStaged::Refused(why)) => {
                lines.push(why);
                (
                    RowState::Failed,
                    Some(downloads::FAILED_NOT_STAGED.to_owned()),
                )
            }
        };
        let _ = downloads::change(data_dir, |rows| {
            if let Some(r) = rows.row_mut(&row.digest) {
                r.state = state;
                r.failed = failed;
            }
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
    lines
}

/// A complete download's pieces, read back (each capped): a file that
/// cannot be read now is [`NotStaged::Later`], one that does not decode is
/// refused.
fn parts_of(dir: &Path, row: &Row) -> Result<Parts, NotStaged> {
    let read = |name: &str, cap: usize| -> Result<Vec<u8>, NotStaged> {
        let path = dir.join(name);
        let file = std::fs::File::open(&path)
            .map_err(|e| NotStaged::Later(format!("{}: {e}", shown(&path))))?;
        if file
            .metadata()
            .is_ok_and(|m| m.is_file() && m.len() > cap as u64)
        {
            return Err(NotStaged::Refused(format!(
                "{} is larger than any Raven update file of its kind.",
                shown(&path)
            )));
        }
        read_capped(file, cap, &path).map_err(NotStaged::Later)
    };
    let refused = |why: String| NotStaged::Refused(why);
    let manifest = Manifest::decode(&read(INCOMING_MANIFEST, MAX_MANIFEST_LEN)?)
        .map_err(|e| refused(format!("a downloaded manifest: {}", e.code())))?;
    if manifest.digest() != row.digest {
        return Err(refused(
            "a downloaded release is in the wrong folder".to_owned(),
        ));
    }
    let snapshot = Snapshot::decode(&read(INCOMING_SNAPSHOT, MAX_SNAPSHOT_LEN)?)
        .map_err(|e| refused(format!("a downloaded log: {}", e.code())))?;
    let payload = read(INCOMING_PAYLOAD, manifest.payload_len as usize)?;
    Ok(Parts {
        manifest,
        snapshot,
        advisory: None,
        payload,
    })
}

/// `raven update download [OFFER]`: the offers, or the approval of one
/// (asked on a terminal; the lab switch answers yes).
pub(in super::super) fn cmd_download(data_dir: &Path, offer: Option<&str>) -> Result<(), String> {
    if !friends_live() || !live() {
        return Err(FRIENDS_OFF_TEXT.to_owned());
    }
    let rows = downloads::load(data_dir)?;
    let Some(prefix) = offer else {
        let waiting: Vec<&Row> = rows
            .rows
            .iter()
            .filter(|r| r.state == RowState::Offered)
            .collect();
        if waiting.is_empty() {
            println!("{NO_OFFER}");
        }
        for row in waiting {
            for line in offer_lines(data_dir, row) {
                println!("{line}");
            }
            println!("  raven update download {}", code(row));
        }
        for line in download_lines(data_dir)
            .into_iter()
            .filter(|l| !l.contains("raven update download"))
        {
            println!("{line}");
        }
        println!("{NEVER_WITHOUT_ASKING}");
        return Ok(());
    };
    let prefix = prefix.trim().to_ascii_lowercase();
    let row = rows
        .rows
        .iter()
        .find(|r| r.state == RowState::Offered && hex::encode(r.digest).starts_with(&prefix));
    if let Some(row) = row {
        let lines = offer_lines(data_dir, row);
        if !ask_yes(&lines) {
            println!("Nothing was downloaded.");
            return Ok(());
        }
    }
    // The approval itself says why when the code names no waiting offer.
    for line in approve(data_dir, &prefix)? {
        println!("{line}");
    }
    Ok(())
}

/// The download question on a terminal (`y` downloads), or the lab switch's
/// yes.
fn ask_yes(lines: &[String]) -> bool {
    for line in lines {
        println!("{line}");
    }
    if downloads::lab_auto_approve() {
        println!("(lab: approved by {})", downloads::LAB_UPDATE_AUTO_APPROVE);
        return true;
    }
    if !super::super::stdin_is_tty() {
        eprintln!("stdin is not a terminal: Raven downloads it only after you answer y at one.");
        return false;
    }
    print!("[y/N] ");
    let _ = io::stdout().flush();
    super::super::read_decision_line()
        .is_some_and(|a| a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"))
}

#[cfg(test)]
mod tests;
