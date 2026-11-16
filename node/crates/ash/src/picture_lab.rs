//! Profile pictures from a terminal, for the lab: `raven lab picture-set`,
//! `raven lab picture-clear`, `raven lab picture-send`, `raven lab pictures`
//! and `raven lab picture-save`.
//!
//! No desktop app has profile pictures yet, and tests across computers need
//! a way to set one and to look at what came. These commands do through the
//! core what an app's engine does (`raven_core::attachment::picture`): the
//! picture is checked and kept, one look finds the verified friends who are
//! due it, and each gets its offer as the text of a message over the send
//! every message takes. raven-node carries the picture's one chunk.
//!
//! They work only where profile pictures are live: a debug build started
//! with `RAVEN_LAB_TEST_A=1`, `RAVEN_LAB_ATTACHMENTS=1` and
//! `RAVEN_LAB_PROFILE_PICTURES=1`. In a release build the gate is shut and
//! each of them says so and does nothing.

use std::path::Path;

use raven_core::attachment::flow;
use raven_core::attachment::picture::{self, Reach};
use raven_core::clock::now_ms;
use raven_core::sanitize::sanitize_terminal_line;

use super::pair_init_lab;

/// The listen address a send passes (`raven send`'s default).
const SEND_LISTEN: &str = "127.0.0.1:0";

fn live() -> Result<(), String> {
    if raven_core::attachment_gate::pictures_live() {
        Ok(())
    } else {
        Err(raven_core::attachment_gate::PROFILE_PICTURES_HOLD.to_string())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(raven_core::release_sign::sha256(bytes))
}

fn read(file: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(file).map_err(|e| format!("could not read {}: {}", file.display(), e.kind()))
}

/// A contact's key, when it is one.
fn key_of(contact: &super::Contact) -> Option<[u8; 32]> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(contact.pub_hex.trim(), &mut key).ok()?;
    Some(key)
}

/// What names `contact` to a send: its petname (one on this computer), else
/// its tag.
fn send_name(contact: &super::Contact) -> String {
    if contact.petname.trim().is_empty() {
        contact.tag_subtitle().unwrap_or_default()
    } else {
        contact.petname.clone()
    }
}

/// `raven lab picture-set --file PICTURE [--preview SMALL]`: check both
/// JPEGs, keep the picture as it travels, and send it to every verified
/// friend who is due it. The terminal has no picture library: the picture
/// (square, 64 to 512 pixels, at most 60,000 bytes) and its preview
/// (square, 16 to 64 pixels, at most 1,536 bytes) are made beforehand, as an
/// app makes them. Without a preview a plain grey square goes in its place.
pub(super) fn cmd_set(data_dir: &Path, file: &Path, preview: Option<&Path>) -> Result<(), String> {
    live()?;
    let picture_bytes = read(file)?;
    let preview_bytes = match preview {
        Some(preview) => read(preview)?,
        None => raven_core::attachment::jpeg::flat(32, false),
    };
    picture::set_mine(data_dir, &picture_bytes, &preview_bytes, now_ms())
        .map_err(|e| e.to_string())?;
    let kept = picture::read_mine(data_dir, false).map_err(|e| e.to_string())?;
    println!(
        "your picture is set: {} bytes as it travels, sha256 {}",
        kept.len(),
        sha256_hex(&kept)
    );
    send_due(data_dir)
}

/// `raven lab picture-clear`: remove my picture, and tell every verified
/// friend who has it.
pub(super) fn cmd_clear(data_dir: &Path) -> Result<(), String> {
    live()?;
    picture::clear_mine(data_dir, now_ms()).map_err(|e| e.to_string())?;
    println!("your picture is removed");
    send_due(data_dir)
}

/// `raven lab picture-send`: one look, and an offer for every verified
/// friend who is due one (a friend verified since, a friend whose Raven
/// takes pictures now, an offer that never left).
pub(super) fn cmd_send(data_dir: &Path) -> Result<(), String> {
    live()?;
    send_due(data_dir)
}

fn send_due(data_dir: &Path) -> Result<(), String> {
    let due = picture::pass(data_dir, now_ms()).map_err(|e| e.to_string())?;
    if due.is_empty() {
        println!("nobody is due an offer now (raven lab pictures)");
        return Ok(());
    }
    let contacts = super::load_contacts(data_dir)?;
    let id = super::require_identity(data_dir);
    for to_send in due {
        let peer_hex = hex::encode(to_send.peer);
        let unsent = || {
            let _ = picture::offer_unsent(data_dir, &to_send.peer, to_send.seq);
        };
        let Some(contact) = contacts
            .iter()
            .find(|c| c.pub_hex.trim().eq_ignore_ascii_case(&peer_hex))
        else {
            unsent();
            continue;
        };
        let name = sanitize_terminal_line(&contact.primary_label());
        let target = match super::resolve_send_target(
            data_dir,
            &send_name(contact),
            "",
            "",
            SEND_LISTEN,
            super::CarrierChoice::Auto,
        ) {
            Ok(target) => target,
            Err(e) => {
                unsent();
                println!("{name}: not sent: {e}");
                continue;
            }
        };
        // The link that carries the offer takes the picture's chunk along
        // right behind its answer (raven-node, by the row).
        if let Some(handle) = &to_send.handle {
            flow::offer_going(data_dir, handle, now_ms());
        }
        let outcome = {
            let dir = data_dir.to_path_buf();
            let (peer, seq) = (to_send.peer, to_send.seq);
            let _offer = pair_init_lab::PictureOfferGuard::set();
            let _noting = pair_init_lab::OwnIdNoteGuard::set(Box::new(move |mid: &[u8; 16]| {
                let _ = picture::offer_sent(&dir, &peer, seq, mid, now_ms());
            }));
            super::run_send(
                data_dir,
                &id,
                &target,
                &to_send.offer,
                super::CarrierChoice::Auto,
            )
        };
        match outcome {
            Ok(used) if to_send.handle.is_some() => println!(
                "{name}: its message is delivered over {:?}; the picture follows (raven lab pictures)",
                used.carrier
            ),
            // The empty form: a removal, or no picture to tell a new friend of.
            Ok(used) => println!(
                "{name}: is told over {:?} that you have no picture",
                used.carrier
            ),
            Err(error) if error.starts_with(super::ext::QUEUED_PREFIX) => println!(
                "{name}: its message waits: {}",
                super::ext::shown_outcome(&pair_init_lab::send_failure_line(&error))
            ),
            Err(error) => {
                // No message was made for it: the friend is due again.
                if !picture::offer_has_message(data_dir, &to_send.peer, to_send.seq) {
                    unsent();
                }
                println!(
                    "{name}: not sent: {}",
                    super::ext::shown_outcome(&pair_init_lab::send_failure_line(&error))
                );
            }
        }
    }
    Ok(())
}

/// `raven lab pictures`: my picture and how far it is, then one line for
/// each verified friend: whether their Raven has mine, and whether theirs
/// is here.
pub(super) fn cmd_list(data_dir: &Path) -> Result<(), String> {
    live()?;
    let now = now_ms();
    let mine = picture::mine(data_dir, now).map_err(|e| e.to_string())?;
    let state = match (mine.set, mine.choice) {
        (true, _) => "set",
        (false, 0) => "never set",
        (false, _) => "removed",
    };
    println!(
        "yours  {state}  friends {}  have it {}  waiting {}  need a newer Raven {}  changes left today {}",
        mine.friends, mine.have_it, mine.waiting, mine.need_newer, mine.changes_left
    );
    for contact in super::load_contacts(data_dir)?.iter().filter(|c| c.pinned) {
        let Some(peer) = key_of(contact) else {
            continue;
        };
        // With no picture set, what a friend is told is that there is none.
        let yours = match (picture::reach(data_dir, &peer), mine.set) {
            (Some(Reach::Has), true) => "has yours",
            (Some(Reach::Has), false) => "knows you have none",
            (Some(Reach::Waiting), true) => "yours is on its way",
            (Some(Reach::Waiting), false) => "is not told yet that you have none",
            (Some(Reach::NeedsNewer), _) => "needs a newer Raven for pictures",
            (None, _) => "yours: nothing to tell",
        };
        let theirs = match picture::theirs(data_dir, &peer, now) {
            Some(view) if view.ready => "theirs is here",
            Some(_) => "theirs is coming (the preview is here)",
            None => "no picture of theirs",
        };
        println!(
            "{}  {yours}  {theirs}",
            sanitize_terminal_line(&contact.primary_label())
        );
    }
    Ok(())
}

/// `raven lab picture-save [--from FRIEND] [--preview] --out PATH`: write my
/// picture, or a verified friend's, to a new file, with its SHA-256 to
/// compare with the other side's. A friend's is checked first, as an app's
/// engine checks it before anything decodes it. An existing file is never
/// written over.
pub(super) fn cmd_save(
    data_dir: &Path,
    from: Option<&str>,
    preview: bool,
    out: &Path,
) -> Result<(), String> {
    use std::io::Write as _;
    live()?;
    let bytes = match from {
        None => picture::read_mine(data_dir, preview),
        Some(who) => {
            let contacts = super::load_contacts(data_dir)?;
            let hits = super::resolve_contact_arg(&contacts, who);
            let peer = match hits.as_slice() {
                [one] => key_of(one).ok_or("that contact's key does not read")?,
                [] => return Err(super::no_contact_message(&contacts, who)),
                _ => return Err("more than one contact matches: use the @tag".into()),
            };
            picture::read_theirs(data_dir, &peer, preview, now_ms())
        }
    }
    .map_err(|e| e.to_string())?;
    if super::attach_lab::inside_profile(data_dir, out) {
        return Err("choose a place outside the profile's folder".into());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|e| format!("could not make {}: {}", out.display(), e.kind()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("could not write {}: {}", out.display(), e.kind()))?;
    println!(
        "saved {} bytes to {}, sha256 {}",
        bytes.len(),
        out.display(),
        sha256_hex(&bytes)
    );
    Ok(())
}
