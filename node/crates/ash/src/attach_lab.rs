//! Attachments from a terminal, for the lab: `raven lab attach`, `raven lab
//! attachments`, `raven lab attachment-ask` and `raven lab attachment-save`.
//!
//! No desktop app has photos yet, and tests across computers need a way to
//! send one and to look at what came. These commands do through the core
//! what an app's engine does (`raven_core::attachment::flow`): the file is
//! sealed and written, its offer goes as the text of a message over the
//! send every message takes, and raven-node carries the bytes.
//!
//! They work only where attachments are live: a debug build started with
//! `RAVEN_LAB_TEST_A=1` and `RAVEN_LAB_ATTACHMENTS=1`. In a release build
//! the gate is shut and each of them says so and does nothing.

use std::path::Path;

use raven_core::attachment::flow::{self, Media};
use raven_core::attachment::offer::Kind;
use raven_core::attachment::store::{self, Row, State};
use raven_core::attachment::{blob::HANDLE_LEN, peers};
use raven_core::clock::now_ms;
use raven_core::sanitize::sanitize_terminal_line;
use zeroize::Zeroize;

use super::pair_init_lab;

/// The listen address a send passes (`raven send`'s default).
const SEND_LISTEN: &str = "127.0.0.1:0";

/// A photo's preview for the lab: the terminal has no picture library to
/// make the small blurred picture an app makes. A friend's app shows its
/// own plain ground for a preview it can not read, until the photo is here.
const LAB_PREVIEW: &[u8] = b"raven-lab-preview";

fn live() -> Result<(), String> {
    if raven_core::attachment_gate::attachments_live() {
        Ok(())
    } else {
        Err(raven_core::attachment_gate::ATTACHMENTS_HOLD.to_string())
    }
}

/// The first hex digits of a handle, as these commands print and take it.
fn short(handle_hex: &str) -> &str {
    handle_hex.get(..8).unwrap_or(handle_hex)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(raven_core::release_sign::sha256(bytes))
}

/// Width and height of a JPEG, from its frame header. `None`: not a JPEG
/// this reads, and the file then goes as a file.
fn jpeg_size(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return None;
    }
    let mut at = 2usize;
    while at + 4 <= bytes.len() {
        if bytes[at] != 0xFF {
            return None;
        }
        let marker = bytes[at + 1];
        // Fill bytes before a marker, and markers that stand alone.
        if marker == 0xFF {
            at += 1;
            continue;
        }
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            at += 2;
            continue;
        }
        let len = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
        if len < 2 {
            return None;
        }
        // A start of frame (every kind but the tables C4, C8 and CC).
        if (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
            let frame = bytes.get(at + 4..at + 4 + 5)?;
            let height = u32::from(u16::from_be_bytes([frame[1], frame[2]]));
            let width = u32::from(u16::from_be_bytes([frame[3], frame[4]]));
            return (width > 0 && height > 0).then_some((width, height));
        }
        // The picture's own bytes begin: no frame header came before them.
        if marker == 0xDA {
            return None;
        }
        at = at.checked_add(2 + len)?;
    }
    None
}

/// The type a file's name stands for, for the few kinds a test sends.
fn mime_of(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map_or("", |(_, e)| e);
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "pdf" => "application/pdf",
        "txt" | "log" | "md" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// `raven lab attach --to @friend --file PATH`: seal the file, send its
/// offer as a message, and leave the bytes to raven-node. A JPEG goes as a
/// photo, which the friend's Raven takes by itself; anything else, or a JPEG
/// with `--as-file`, goes as a file, which the friend's side fetches once it
/// is asked for (`raven lab attachment-ask`).
pub(super) fn cmd_attach(
    data_dir: &Path,
    to: &str,
    file: &Path,
    caption: &str,
    as_file: bool,
) -> Result<(), String> {
    live()?;
    let target = super::resolve_send_target(
        data_dir,
        to,
        "",
        "",
        SEND_LISTEN,
        super::CarrierChoice::Auto,
    )?;
    let mut peer = [0u8; 32];
    hex::decode_to_slice(target.pub_hex.trim(), &mut peer)
        .map_err(|_| "that contact's key does not read".to_string())?;
    if !flow::is_friend(data_dir, &peer) {
        return Err(
            "attachments go to verified friends only: verify this contact first (raven verify)"
                .into(),
        );
    }
    // As an app's engine: an offer goes only to a Raven that said it takes
    // attachments (an older one would show the offer as a message's text).
    if !peers::speaks(data_dir, &peer) {
        return Err(
            "this friend's Raven has not said yet that it takes attachments: nothing was sent \
             (a message each way first lets the two say so)"
                .into(),
        );
    }
    let bytes = std::fs::read(file)
        .map_err(|e| format!("could not read {}: {}", file.display(), e.kind()))?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let photo = if as_file { None } else { jpeg_size(&bytes) };
    let media = match photo {
        Some((width, height)) => Media::Photo {
            caption,
            width,
            height,
            preview: LAB_PREVIEW,
        },
        None => Media::File {
            mime: mime_of(&name),
            name: &name,
            caption,
        },
    };
    let made =
        flow::prepare(data_dir, &peer, &bytes, &media, now_ms()).map_err(|e| e.to_string())?;
    let handle = made.handle;
    let mut offer = made.offer;
    println!(
        "attachment {}: {} ({} bytes), sha256 {}",
        short(&hex::encode(handle)),
        if photo.is_some() { "photo" } else { "file" },
        bytes.len(),
        sha256_hex(&bytes)
    );
    let id = super::require_identity(data_dir);
    // The link that carries the offer takes the bytes along right behind
    // its answer (raven-node, by the row).
    flow::offer_going(data_dir, &handle, now_ms());
    let outcome = {
        let dir = data_dir.to_path_buf();
        let _offer = pair_init_lab::EngineOfferGuard::set();
        let _noting = pair_init_lab::OwnIdNoteGuard::set(Box::new(move |mid: &[u8; 16]| {
            let _ = flow::sent(&dir, &handle, mid, now_ms());
        }));
        super::run_send(data_dir, &id, &target, &offer, super::CarrierChoice::Auto)
    };
    // The offer holds the attachment's key.
    offer.zeroize();
    match outcome {
        Ok(used) => {
            println!(
                "its message is delivered over {:?}; the bytes follow (raven lab attachments)",
                used.carrier
            );
            Ok(())
        }
        Err(error) if error.starts_with(super::ext::QUEUED_PREFIX) => {
            println!(
                "its message waits: {}",
                super::ext::shown_outcome(&pair_init_lab::send_failure_line(&error))
            );
            println!("raven-node keeps trying, and the bytes go with it (raven lab attachments)");
            Ok(())
        }
        Err(error) => {
            // No message was made for it: the sealed copy goes again.
            let named = store::get(data_dir, &handle)
                .ok()
                .flatten()
                .and_then(|row| row.message_id_bytes())
                .is_some_and(|mid| mid != [0u8; 16]);
            if !named {
                flow::discard(data_dir, &handle);
            }
            Err(super::ext::shown_outcome(
                &pair_init_lab::send_failure_line(&error),
            ))
        }
    }
}

fn state_word(state: State) -> &'static str {
    match state {
        State::Staged => "staged",
        State::Offered => "offered",
        State::Delivered => "delivered",
        State::Incoming => "incoming",
        State::Complete => "complete",
        State::Gone => "gone",
        State::Failed => "failed",
    }
}

fn kind_word(row: &Row) -> &'static str {
    match row.stored().map(|r| r.kind()) {
        Some(Kind::Photo) => "photo",
        Some(Kind::Voice) => "voice",
        Some(Kind::File) => "file",
        Some(Kind::Profile) => "profile",
        None => "unknown",
    }
}

/// The friend of a row as the contact book names them, else the start of
/// their key.
fn friend_word(contacts: &[super::Contact], row: &Row) -> String {
    let Some(peer) = row.peer.as_deref() else {
        return "(group)".into();
    };
    contacts
        .iter()
        .find(|c| c.pub_hex.eq_ignore_ascii_case(peer))
        .map(|c| sanitize_terminal_line(&c.primary_label()))
        .unwrap_or_else(|| format!("#{}", peer.get(..8).unwrap_or(peer)))
}

/// `raven lab attachments`: one line for each attachment of this profile,
/// oldest first. `chunks` are the sealed chunks on this computer (a friend's
/// attachment) or the ones the friend's node said it has (mine).
pub(super) fn cmd_list(data_dir: &Path) -> Result<(), String> {
    live()?;
    let rows = store::list(data_dir).map_err(|e| e.to_string())?;
    if rows.is_empty() {
        println!("no attachments");
        return Ok(());
    }
    let contacts = super::load_contacts(data_dir).unwrap_or_default();
    for row in &rows {
        let bytes = row.shape().map_or(0, |s| s.len());
        let total = row.shape().map_or(0, |s| s.chunks());
        // Mine: what the friend's node said it has. A friend's: the chunks
        // that are here.
        let done = if row.outgoing {
            row.friend_has.min(total)
        } else {
            match (row.handle_bytes(), row.shape()) {
                (Some(handle), Some(shape)) => {
                    store::have(data_dir, &handle, &shape, false).map_or(0, |have| have.count())
                }
                _ => 0,
            }
        };
        println!(
            "{}  {}  {}  {}  {} bytes  {}  chunks {}/{}{}",
            short(&row.handle),
            if row.outgoing { "to  " } else { "from" },
            friend_word(&contacts, row),
            kind_word(row),
            bytes,
            state_word(row.state),
            done,
            total,
            if row.asked { "  asked" } else { "" },
        );
    }
    Ok(())
}

/// The one row whose handle begins with `prefix` (at least four hex digits).
fn row_by_prefix(data_dir: &Path, prefix: &str) -> Result<Row, String> {
    let prefix = prefix.trim().to_ascii_lowercase();
    if prefix.len() < 4
        || prefix.len() > 2 * HANDLE_LEN
        || !prefix.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(
            "give the start of the handle: four hex digits or more (raven lab attachments)".into(),
        );
    }
    let mut hits: Vec<Row> = store::list(data_dir)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|row| row.handle.to_ascii_lowercase().starts_with(&prefix))
        .collect();
    match hits.len() {
        0 => Err("no attachment begins with that".into()),
        1 => Ok(hits.remove(0)),
        n => Err(format!("{n} attachments begin with that: give more digits")),
    }
}

/// `raven lab attachment-ask HANDLE`: ask for a friend's attachment that
/// waits to be asked for (a file). raven-node fetches it at its next look.
pub(super) fn cmd_ask(data_dir: &Path, prefix: &str) -> Result<(), String> {
    live()?;
    let row = row_by_prefix(data_dir, prefix)?;
    if row.outgoing {
        return Err("that one is yours: nothing to ask for".into());
    }
    match row.state {
        State::Complete => {
            println!("it is here already (raven lab attachment-save)");
            return Ok(());
        }
        State::Incoming => {}
        other => {
            return Err(format!(
                "it can not be fetched: it is {}",
                state_word(other)
            ))
        }
    }
    let handle = row
        .handle_bytes()
        .ok_or_else(|| "that row's handle does not read".to_string())?;
    store::update(data_dir, &handle, now_ms(), |row| row.asked = true)
        .map_err(|e| e.to_string())?;
    println!(
        "asked for {}; raven-node fetches it (raven lab attachments)",
        short(&row.handle)
    );
    Ok(())
}

/// Is `out` a place inside the profile's folder? Its plain bytes do not
/// belong beside the sealed ones.
pub(super) fn inside_profile(data_dir: &Path, out: &Path) -> bool {
    let Ok(profile) = data_dir.canonicalize() else {
        return false;
    };
    let folder = match out.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    folder
        .canonicalize()
        .is_ok_and(|folder| folder.starts_with(&profile))
}

/// `raven lab attachment-save HANDLE --out PATH`: open an attachment that
/// is whole and write its bytes to a new file, with their SHA-256 to compare
/// with the sender's. An existing file is never written over.
pub(super) fn cmd_save(data_dir: &Path, prefix: &str, out: &Path) -> Result<(), String> {
    use std::io::Write as _;
    live()?;
    let row = row_by_prefix(data_dir, prefix)?;
    if !row.outgoing && row.state != State::Complete {
        return Err(format!(
            "it is not here yet: it is {} (raven lab attachments)",
            state_word(row.state)
        ));
    }
    let len = row
        .shape()
        .map(|s| s.len())
        .ok_or_else(|| "that row's sizes do not read".to_string())?;
    let len = usize::try_from(len).map_err(|_| "it is too large for this computer".to_string())?;
    if inside_profile(data_dir, out) {
        return Err("choose a place outside the profile's folder".into());
    }
    let plain = store::read_plain(data_dir, &row, 0, len).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|e| format!("could not make {}: {}", out.display(), e.kind()))?;
    file.write_all(&plain)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("could not write {}: {}", out.display(), e.kind()))?;
    println!(
        "saved {} bytes to {}, sha256 {}",
        plain.len(),
        out.display(),
        sha256_hex(&plain)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JPEG's size is read from its frame header, wherever it stands
    /// behind the first markers; what is no JPEG, or stops short, has none.
    #[test]
    fn a_jpegs_size_is_read_from_its_frame_header() {
        // SOI, APP0 (16 bytes), SOF0 with 8 bit, height 0x0102, width 0x0304.
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        jpeg.extend_from_slice(&[0u8; 14]);
        jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08, 0x01, 0x02, 0x03, 0x04, 0x03]);
        jpeg.extend_from_slice(&[0u8; 9]);
        assert_eq!(jpeg_size(&jpeg), Some((0x0304, 0x0102)));
        // A progressive frame (C2) reads the same; a table (C4) is passed over.
        let mut progressive = vec![0xFF, 0xD8, 0xFF, 0xC4, 0x00, 0x04, 0x00, 0x00];
        progressive
            .extend_from_slice(&[0xFF, 0xC2, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x20, 0x01]);
        progressive.extend_from_slice(&[0u8; 6]);
        assert_eq!(jpeg_size(&progressive), Some((0x20, 0x10)));
        // Not a JPEG, a JPEG cut before its frame, a frame of no size, and
        // one whose picture bytes begin with no frame before them.
        assert_eq!(jpeg_size(b"\x89PNG\r\n\x1a\n"), None);
        assert_eq!(jpeg_size(&[]), None);
        assert_eq!(jpeg_size(&jpeg[..22]), None);
        let mut empty = jpeg.clone();
        empty[25] = 0;
        empty[26] = 0;
        assert_eq!(jpeg_size(&empty), None);
        assert_eq!(
            jpeg_size(&[0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02, 0x00, 0x00]),
            None
        );
        // A length that would run past any file never loops or panics.
        assert_eq!(
            jpeg_size(&[0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF, 0x00, 0x00]),
            None
        );
        assert_eq!(
            jpeg_size(&[0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x00, 0x00, 0x00]),
            None
        );
    }

    #[test]
    fn a_names_type_and_a_handles_start() {
        assert_eq!(mime_of("Holiday.JPG"), "image/jpeg");
        assert_eq!(mime_of("notes.txt"), "text/plain");
        assert_eq!(mime_of("archive"), "application/octet-stream");
        assert_eq!(short("0123456789abcdef"), "01234567");
        assert_eq!(short("0123"), "0123");
    }
}
