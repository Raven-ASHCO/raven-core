//! The offer of `RVNATT/1`: the only message of an attachment
//! (`docs/design/2026-11-attachments.md` §8, and
//! `docs/design/2026-11-profile-pictures.md` §9 for the `profile` kind).
//!
//! Like `RVNGRP/1`, a frame is text: `RVNATT/1 <kind>`, a line feed, then
//! strict JSON (unknown fields refused, one byte form only).
//!
//! | Frame | Carries | Size |
//! |---|---|---|
//! | `offer` | the fields of its kind, then the key and the root, then a pad of zeros | exactly 8,192 B |
//! | `gone`  | a handle: the author deleted the attachment before the friend had all of it | small |
//! | `ref`   | stored only, never sent: the offer without key, root and pad | under 8,192 B |
//!
//! Members, in this order, each present or absent by the offer's kind:
//! `v`, `handle`, `kind`, `seq`, `held`, `chunks`, `padded_len`, `true_len`,
//! `mime`, `name`, `caption`, `width`, `height`, `duration_ms`, `levels`,
//! `preview`, `key`, `root`, `pad`.
//!
//! | Kind | Members between `kind` and `key` |
//! |---|---|
//! | `photo` | `chunks`, `padded_len`, `true_len`, `mime` (`image/jpeg`), `caption`, `width`, `height`, `preview` |
//! | `voice` | `chunks`, `padded_len`, `true_len`, `mime` (`audio/ogg`), `caption`, `duration_ms`, `levels` |
//! | `file` | `chunks`, `padded_len`, `true_len`, `mime`, `name`, `caption` |
//! | `profile` | `seq`, `held`, `chunks` (1), `padded_len` (61,424), `true_len`, `mime` (`image/jpeg`), `width`, `height` (equal), `preview` |
//! | `profile`, the empty form (No picture) | `seq`, `held`, `chunks` (0); no `key`, no `root` |
//!
//! Every offer has the same size, so its length says nothing about its
//! kind; the key and the root come after every other field and the pad
//! comes last, so no beginning of an offer holds the key. 8,192 bytes is the
//! group body limit, so the same offer is a group message body as it is.
//!
//! An offer is accepted only in its one byte form: what [`Offer::encode`]
//! writes for what was read. So white space, another member order, another
//! escape, a pad that is not zeros or a handle that is not the key's are all
//! refused, and a store can drop the pad and put it back byte for byte.
//!
//! Not a frozen wire format yet: `protocol/RAVEN_ATTACHMENT_V1.md` is still
//! to be written from this.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use super::blob::{Key, Shape, HANDLE_LEN, KEY_LEN};

/// Every text that starts with this is reserved for attachment frames: it
/// is never chat, and no composer sends it.
pub const ATT_RESERVED_PREFIX: &str = "RVNATT/";
/// The frame magic of version 1.
pub const ATT_FRAME_MAGIC: &str = "RVNATT/1";
/// An offer, to the byte.
pub const OFFER_LEN: usize = 8_192;
/// The most bytes of a caption (chat text rules).
pub const MAX_CAPTION_BYTES: usize = 2_000;
/// The most bytes of a file's name.
pub const MAX_NAME_BYTES: usize = 255;
/// The most bytes of a MIME type.
pub const MAX_MIME_BYTES: usize = 127;
/// The most bytes of a preview (a 32 px JPEG).
pub const MAX_PREVIEW_BYTES: usize = 1_536;
/// The loudness levels of a voice note, one byte each.
pub const LEVELS: usize = 64;
/// The longest side of a photo an offer may name.
pub const MAX_SIDE: u32 = 16_384;
/// The longest voice note (15 minutes).
pub const MAX_VOICE_MS: u32 = 900_000;
/// The sides of a profile picture.
pub const PROFILE_MIN_SIDE: u32 = 64;
/// The sides of a profile picture.
pub const PROFILE_MAX_SIDE: u32 = 512;
/// The largest `seq` and `held`: 2^53 − 1, exact as a JSON number.
pub const MAX_SEQ: u64 = 9_007_199_254_740_991;
/// The MIME type of a photo and of a profile picture.
pub const MIME_JPEG: &str = "image/jpeg";
/// The MIME type of a voice note.
pub const MIME_OGG: &str = "audio/ogg";

const HEAD_OFFER: &str = "RVNATT/1 offer\n";
const HEAD_GONE: &str = "RVNATT/1 gone\n";
const HEAD_REF: &str = "RVNATT/1 ref\n";
const VERSION: u8 = 1;
/// What an encoder puts between the last member and the pad's zeros, and
/// after them.
const PAD_OPEN: &str = ",\"pad\":\"";
const PAD_CLOSE: &str = "\"}";

/// Why an offer cannot be made.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OfferError {
    /// A caption that is too long or holds a control character.
    #[error("ATTACHMENT CAPTION")]
    Caption,
    /// A file name that is empty, too long or not clean.
    #[error("ATTACHMENT NAME")]
    Name,
    /// A MIME type that is empty, too long or not plain.
    #[error("ATTACHMENT MIME")]
    Mime,
    /// A preview that is empty or too big.
    #[error("ATTACHMENT PREVIEW")]
    Preview,
    /// A width, height or length out of range.
    #[error("ATTACHMENT SIZE")]
    Size,
    /// A `seq` or `held` past [`MAX_SEQ`].
    #[error("ATTACHMENT SEQ")]
    Seq,
    /// A blob whose shape does not fit the kind.
    #[error("ATTACHMENT SHAPE")]
    Shape,
    /// The fields leave no room for the pad.
    #[error("ATTACHMENT OFFER_TOO_BIG")]
    TooBig,
}

/// What kind of attachment an offer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A photo: shown inline.
    Photo,
    /// A voice note: played inline.
    Voice,
    /// Any file: downloaded and opened by the user's choice.
    File,
    /// A friend's profile picture: never a message.
    Profile,
}

impl Kind {
    /// The kind as the frame writes it.
    pub fn word(self) -> &'static str {
        match self {
            Kind::Photo => "photo",
            Kind::Voice => "voice",
            Kind::File => "file",
            Kind::Profile => "profile",
        }
    }

    fn parse(word: &str) -> Option<Kind> {
        match word {
            "photo" => Some(Kind::Photo),
            "voice" => Some(Kind::Voice),
            "file" => Some(Kind::File),
            "profile" => Some(Kind::Profile),
            _ => None,
        }
    }
}

/// Where an attachment's bytes are and how to open them: what only an offer
/// carries.
#[derive(Debug, Clone)]
pub struct BlobRef {
    /// The sizes.
    pub shape: Shape,
    /// The key of this attachment.
    pub key: Key,
    /// The root of the tree over its sealed chunks.
    pub root: [u8; 32],
}

impl PartialEq for BlobRef {
    fn eq(&self, other: &Self) -> bool {
        self.shape == other.shape
            && self.key.bytes() == other.key.bytes()
            && self.root == other.root
    }
}
impl Eq for BlobRef {}

/// What an offer says about its attachment, by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// A photo (JPEG).
    Photo {
        /// Words under the photo; may be empty.
        caption: String,
        /// Pixels.
        width: u32,
        /// Pixels.
        height: u32,
        /// The same photo at 32 px, shown blurred until the photo is here.
        preview: Vec<u8>,
    },
    /// A voice note (Opus in Ogg).
    Voice {
        /// Words under the player; may be empty.
        caption: String,
        /// Its length.
        duration_ms: u32,
        /// 64 loudness levels, drawn as the wave.
        levels: [u8; LEVELS],
    },
    /// A file.
    File {
        /// The type the sender's system gave.
        mime: String,
        /// Its name, cleaned.
        name: String,
        /// Words under the file; may be empty.
        caption: String,
    },
    /// A profile picture (a square JPEG in one chunk).
    Profile {
        /// The order of this sender's profile offers.
        seq: u64,
        /// The `seq` of the newest offer from the receiver that the sender
        /// holds; 0 for none.
        held: u64,
        /// Pixels, each side.
        side: u32,
        /// The same picture at 32 px.
        preview: Vec<u8>,
    },
    /// The empty form of a profile offer: No picture.
    NoProfile {
        /// The order of this sender's profile offers.
        seq: u64,
        /// As in [`Content::Profile`].
        held: u64,
    },
}

impl Content {
    /// The kind of this content.
    pub fn kind(&self) -> Kind {
        match self {
            Content::Photo { .. } => Kind::Photo,
            Content::Voice { .. } => Kind::Voice,
            Content::File { .. } => Kind::File,
            Content::Profile { .. } | Content::NoProfile { .. } => Kind::Profile,
        }
    }

    /// The caption, where the kind has one.
    pub fn caption(&self) -> &str {
        match self {
            Content::Photo { caption, .. }
            | Content::Voice { caption, .. }
            | Content::File { caption, .. } => caption,
            Content::Profile { .. } | Content::NoProfile { .. } => "",
        }
    }
}

/// An offer: the one message of an attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The name of the attachment on links and on disk: the key's handle,
    /// or 16 random bytes in the empty profile form.
    pub handle: [u8; HANDLE_LEN],
    /// What it is.
    pub content: Content,
    /// Where its bytes are; `None` only in the empty profile form.
    pub blob: Option<BlobRef>,
}

/// The stored form of an offer: everything but the key, the root and the
/// pad (and, for a profile picture, the preview). What a history row holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    /// The attachment's handle: the way to its row in the attachment store.
    pub handle: [u8; HANDLE_LEN],
    /// What it is.
    pub content: Content,
    /// Its sizes; `None` only for the empty profile form.
    pub shape: Option<Shape>,
}

/// A frame that travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// An offer.
    Offer(Box<Offer>),
    /// The author deleted the attachment before the friend had all of it.
    Gone([u8; HANDLE_LEN]),
}

/// Does `plaintext` start with the reserved `RVNATT/` prefix?
pub fn is_att_text(plaintext: &[u8]) -> bool {
    plaintext.starts_with(ATT_RESERVED_PREFIX.as_bytes())
}

/// Chat text rules for a caption: at most 2,000 bytes; tab, line feed and
/// carriage return, and no other control character. It may be empty.
pub fn caption_ok(caption: &str) -> bool {
    caption.len() <= MAX_CAPTION_BYTES
        && caption
            .chars()
            .all(|c| matches!(c, '\t' | '\n' | '\r') || plain(c))
}

/// A file name as an offer carries it: 1 to 255 bytes, no control
/// character, no path separator, no character that changes the direction or
/// hides text (so a name cannot pretend that an `.exe` is a `.png`), not
/// only dots or white space, and no white space at either end.
pub fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name.trim() == name
        && name.chars().any(|c| c != '.' && !c.is_whitespace())
        && name.chars().all(|c| {
            plain(c) && !c.is_control() && !matches!(c, '/' | '\\' | ':') && !hides_text(c)
        })
}

/// Makes a file name an offer can carry from what a system gave: what
/// [`name_ok`] refuses is dropped, the rest is cut at a character boundary;
/// a name with nothing left is `file`.
pub fn clean_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|c| {
            plain(*c) && !c.is_control() && !matches!(c, '/' | '\\' | ':') && !hides_text(*c)
        })
        .collect();
    let mut out = String::new();
    for c in kept.trim().chars() {
        if out.len() + c.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        out.push(c);
    }
    let out = out.trim().to_string();
    if name_ok(&out) {
        out
    } else {
        "file".to_string()
    }
}

/// A MIME type as an offer carries it: `type/subtype` in lower case ASCII
/// letters, digits and `.+-_`, at most 127 bytes.
pub fn mime_ok(mime: &str) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'+' | b'-' | b'_'))
    };
    mime.len() <= MAX_MIME_BYTES
        && mime
            .split_once('/')
            .is_some_and(|(a, b)| part(a) && part(b))
}

fn plain(c: char) -> bool {
    c >= '\u{20}' && c != '\u{7f}'
}

/// Direction marks, overrides and isolates, zero width characters, the
/// byte order mark and the tag characters.
fn hides_text(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}'
        | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E007F}')
}

fn seq_ok(seq: u64, held: u64) -> bool {
    (1..=MAX_SEQ).contains(&seq) && held <= MAX_SEQ
}

fn preview_ok(preview: &[u8]) -> bool {
    !preview.is_empty() && preview.len() <= MAX_PREVIEW_BYTES
}

impl Offer {
    /// A photo's offer.
    pub fn photo(
        blob: BlobRef,
        caption: &str,
        width: u32,
        height: u32,
        preview: &[u8],
    ) -> Result<Offer, OfferError> {
        Offer::checked(
            Content::Photo {
                caption: caption.to_string(),
                width,
                height,
                preview: preview.to_vec(),
            },
            Some(blob),
        )
    }

    /// A voice note's offer.
    pub fn voice(
        blob: BlobRef,
        caption: &str,
        duration_ms: u32,
        levels: [u8; LEVELS],
    ) -> Result<Offer, OfferError> {
        Offer::checked(
            Content::Voice {
                caption: caption.to_string(),
                duration_ms,
                levels,
            },
            Some(blob),
        )
    }

    /// A file's offer.
    pub fn file(blob: BlobRef, mime: &str, name: &str, caption: &str) -> Result<Offer, OfferError> {
        Offer::checked(
            Content::File {
                mime: mime.to_string(),
                name: name.to_string(),
                caption: caption.to_string(),
            },
            Some(blob),
        )
    }

    /// A profile picture's offer.
    pub fn profile(
        blob: BlobRef,
        seq: u64,
        held: u64,
        side: u32,
        preview: &[u8],
    ) -> Result<Offer, OfferError> {
        Offer::checked(
            Content::Profile {
                seq,
                held,
                side,
                preview: preview.to_vec(),
            },
            Some(blob),
        )
    }

    /// The empty profile form, No picture, under a random handle.
    pub fn no_profile(handle: [u8; HANDLE_LEN], seq: u64, held: u64) -> Result<Offer, OfferError> {
        let mut offer = Offer::checked(Content::NoProfile { seq, held }, None)?;
        offer.handle = handle;
        Ok(offer)
    }

    fn checked(content: Content, blob: Option<BlobRef>) -> Result<Offer, OfferError> {
        check(&content, blob.as_ref().map(|b| &b.shape))?;
        let handle = blob
            .as_ref()
            .map(|b| b.key.handle())
            .unwrap_or([0u8; HANDLE_LEN]);
        Ok(Offer {
            handle,
            content,
            blob,
        })
    }

    /// The kind of this offer.
    pub fn kind(&self) -> Kind {
        self.content.kind()
    }

    /// The frame as it travels: exactly [`OFFER_LEN`] bytes of text.
    pub fn encode(&self) -> Result<String, OfferError> {
        let wire = Wire::of(
            self.handle,
            &self.content,
            self.blob.as_ref().map(|b| &b.shape),
            self.blob.as_ref(),
        );
        // It holds the key: wiped when this returns.
        let json = Zeroizing::new(serde_json::to_string(&wire).expect("strings and numbers"));
        let fixed = HEAD_OFFER.len() + json.len() - 1 + PAD_OPEN.len() + PAD_CLOSE.len();
        let zeros = OFFER_LEN.checked_sub(fixed).ok_or(OfferError::TooBig)?;
        let mut text = String::with_capacity(OFFER_LEN);
        text.push_str(HEAD_OFFER);
        text.push_str(&json[..json.len() - 1]);
        text.push_str(PAD_OPEN);
        text.extend(std::iter::repeat_n('0', zeros));
        text.push_str(PAD_CLOSE);
        debug_assert_eq!(text.len(), OFFER_LEN);
        Ok(text)
    }

    /// The stored form of this offer.
    pub fn stored(&self) -> Ref {
        Ref {
            handle: self.handle,
            content: self.content.clone(),
            shape: self.blob.as_ref().map(|b| b.shape),
        }
    }
}

impl Ref {
    /// The kind of this attachment.
    pub fn kind(&self) -> Kind {
        self.content.kind()
    }

    /// The `ref` frame: what a history row holds instead of the offer. It
    /// never holds the key or the root; a profile picture's also drops the
    /// preview.
    pub fn encode(&self) -> String {
        let mut wire = Wire::of(self.handle, &self.content, self.shape.as_ref(), None);
        if self.kind() == Kind::Profile {
            wire.preview = None;
        }
        format!(
            "{HEAD_REF}{}",
            serde_json::to_string(&wire).expect("strings and numbers")
        )
    }

    /// The words of a chat list for this attachment: "Photo", "Voice
    /// message 0:42" or the file's name. A profile picture has none: it is
    /// never a message.
    pub fn list_words(&self) -> Option<String> {
        match &self.content {
            Content::Photo { .. } => Some("Photo".to_string()),
            Content::Voice { duration_ms, .. } => {
                let secs = duration_ms.div_ceil(1_000);
                Some(format!("Voice message {}:{:02}", secs / 60, secs % 60))
            }
            Content::File { name, .. } => Some(name.clone()),
            Content::Profile { .. } | Content::NoProfile { .. } => None,
        }
    }
}

/// Checks what a kind allows, for an offer that is made and for one that
/// is read.
fn check(content: &Content, shape: Option<&Shape>) -> Result<(), OfferError> {
    let side_ok = |n: u32| (1..=MAX_SIDE).contains(&n);
    match content {
        Content::Photo {
            caption,
            width,
            height,
            preview,
        } => {
            if !caption_ok(caption) {
                return Err(OfferError::Caption);
            }
            if !side_ok(*width) || !side_ok(*height) {
                return Err(OfferError::Size);
            }
            if !preview_ok(preview) {
                return Err(OfferError::Preview);
            }
            padme_shape(shape)
        }
        Content::Voice {
            caption,
            duration_ms,
            ..
        } => {
            if !caption_ok(caption) {
                return Err(OfferError::Caption);
            }
            if !(1..=MAX_VOICE_MS).contains(duration_ms) {
                return Err(OfferError::Size);
            }
            padme_shape(shape)
        }
        Content::File {
            mime,
            name,
            caption,
        } => {
            if !mime_ok(mime) {
                return Err(OfferError::Mime);
            }
            if !name_ok(name) {
                return Err(OfferError::Name);
            }
            if !caption_ok(caption) {
                return Err(OfferError::Caption);
            }
            padme_shape(shape)
        }
        Content::Profile {
            seq,
            held,
            side,
            preview,
        } => {
            if !seq_ok(*seq, *held) {
                return Err(OfferError::Seq);
            }
            if !(PROFILE_MIN_SIDE..=PROFILE_MAX_SIDE).contains(side) {
                return Err(OfferError::Size);
            }
            if !preview_ok(preview) {
                return Err(OfferError::Preview);
            }
            match shape {
                Some(s) if Shape::one_chunk(s.len()) == Ok(*s) => Ok(()),
                _ => Err(OfferError::Shape),
            }
        }
        Content::NoProfile { seq, held } => {
            if !seq_ok(*seq, *held) {
                return Err(OfferError::Seq);
            }
            match shape {
                None => Ok(()),
                Some(_) => Err(OfferError::Shape),
            }
        }
    }
}

fn padme_shape(shape: Option<&Shape>) -> Result<(), OfferError> {
    match shape {
        Some(s) if Shape::of(s.len()) == Ok(*s) => Ok(()),
        _ => Err(OfferError::Shape),
    }
}

/// The JSON form: members in the frame's order, absent ones left out.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Wire {
    v: u8,
    handle: String,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held: Option<u64>,
    chunks: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    padded_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    true_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caption: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    levels: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pad: Option<String>,
}

impl Drop for Wire {
    /// The key's hex goes from memory with the frame's fields.
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

impl Wire {
    fn of(
        handle: [u8; HANDLE_LEN],
        content: &Content,
        shape: Option<&Shape>,
        secrets: Option<&BlobRef>,
    ) -> Wire {
        let mut w = Wire {
            v: VERSION,
            handle: hex::encode(handle),
            kind: content.kind().word().to_string(),
            seq: None,
            held: None,
            chunks: shape.map_or(0, Shape::chunks),
            padded_len: shape.map(Shape::padded),
            true_len: shape.map(Shape::len),
            mime: None,
            name: None,
            caption: None,
            width: None,
            height: None,
            duration_ms: None,
            levels: None,
            preview: None,
            key: secrets.map(|b| hex::encode(b.key.bytes())),
            root: secrets.map(|b| hex::encode(b.root)),
            pad: None,
        };
        match content {
            Content::Photo {
                caption,
                width,
                height,
                preview,
            } => {
                w.mime = Some(MIME_JPEG.to_string());
                w.caption = Some(caption.clone());
                w.width = Some(*width);
                w.height = Some(*height);
                w.preview = Some(BASE64.encode(preview));
            }
            Content::Voice {
                caption,
                duration_ms,
                levels,
            } => {
                w.mime = Some(MIME_OGG.to_string());
                w.caption = Some(caption.clone());
                w.duration_ms = Some(*duration_ms);
                w.levels = Some(BASE64.encode(levels));
            }
            Content::File {
                mime,
                name,
                caption,
            } => {
                w.mime = Some(mime.clone());
                w.name = Some(name.clone());
                w.caption = Some(caption.clone());
            }
            Content::Profile {
                seq,
                held,
                side,
                preview,
            } => {
                w.seq = Some(*seq);
                w.held = Some(*held);
                w.mime = Some(MIME_JPEG.to_string());
                w.width = Some(*side);
                w.height = Some(*side);
                w.preview = Some(BASE64.encode(preview));
            }
            Content::NoProfile { seq, held } => {
                w.seq = Some(*seq);
                w.held = Some(*held);
            }
        }
        w
    }

    /// The content and the shape these members name, when they are the
    /// members of their kind and nothing else. `stored`: a `ref` frame,
    /// whose profile form has no preview.
    fn typed(&self, stored: bool) -> Option<(Content, Option<Shape>)> {
        if self.v != VERSION {
            return None;
        }
        let kind = Kind::parse(&self.kind)?;
        let padme = || Shape::from_offer(self.true_len?, self.padded_len?, self.chunks).ok();
        let none = |list: &[bool]| list.iter().all(|absent| *absent);
        let preview = || BASE64.decode(self.preview.as_deref()?).ok();
        let (content, shape) = match kind {
            Kind::Photo => {
                if !none(&[
                    self.seq.is_none(),
                    self.held.is_none(),
                    self.name.is_none(),
                    self.duration_ms.is_none(),
                    self.levels.is_none(),
                ]) || self.mime.as_deref() != Some(MIME_JPEG)
                {
                    return None;
                }
                let content = Content::Photo {
                    caption: self.caption.clone()?,
                    width: self.width?,
                    height: self.height?,
                    preview: preview()?,
                };
                (content, Some(padme()?))
            }
            Kind::Voice => {
                if !none(&[
                    self.seq.is_none(),
                    self.held.is_none(),
                    self.name.is_none(),
                    self.width.is_none(),
                    self.height.is_none(),
                    self.preview.is_none(),
                ]) || self.mime.as_deref() != Some(MIME_OGG)
                {
                    return None;
                }
                let levels: [u8; LEVELS] = BASE64
                    .decode(self.levels.as_deref()?)
                    .ok()?
                    .try_into()
                    .ok()?;
                let content = Content::Voice {
                    caption: self.caption.clone()?,
                    duration_ms: self.duration_ms?,
                    levels,
                };
                (content, Some(padme()?))
            }
            Kind::File => {
                if !none(&[
                    self.seq.is_none(),
                    self.held.is_none(),
                    self.width.is_none(),
                    self.height.is_none(),
                    self.duration_ms.is_none(),
                    self.levels.is_none(),
                    self.preview.is_none(),
                ]) {
                    return None;
                }
                let content = Content::File {
                    mime: self.mime.clone()?,
                    name: self.name.clone()?,
                    caption: self.caption.clone()?,
                };
                (content, Some(padme()?))
            }
            Kind::Profile if self.chunks == 0 => {
                if !none(&[
                    self.padded_len.is_none(),
                    self.true_len.is_none(),
                    self.mime.is_none(),
                    self.name.is_none(),
                    self.caption.is_none(),
                    self.width.is_none(),
                    self.height.is_none(),
                    self.duration_ms.is_none(),
                    self.levels.is_none(),
                    self.preview.is_none(),
                    self.key.is_none(),
                    self.root.is_none(),
                ]) {
                    return None;
                }
                (
                    Content::NoProfile {
                        seq: self.seq?,
                        held: self.held?,
                    },
                    None,
                )
            }
            Kind::Profile => {
                if !none(&[
                    self.name.is_none(),
                    self.caption.is_none(),
                    self.duration_ms.is_none(),
                    self.levels.is_none(),
                ]) || self.mime.as_deref() != Some(MIME_JPEG)
                    || self.width? != self.height?
                    || self.chunks != 1
                    || (stored && self.preview.is_some())
                {
                    return None;
                }
                let shape = Shape::one_chunk(self.true_len?).ok()?;
                if self.padded_len? != shape.padded() {
                    return None;
                }
                let content = Content::Profile {
                    seq: self.seq?,
                    held: self.held?,
                    side: self.width?,
                    // A stored profile form has no preview: one byte stands in
                    // for it, so that the same checks serve both forms.
                    preview: if stored { vec![0] } else { preview()? },
                };
                (content, Some(shape))
            }
        };
        check(&content, shape.as_ref()).ok()?;
        Some((content, shape))
    }
}

fn hex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

fn json_of<'a>(plaintext: &'a [u8], head: &str) -> Option<&'a str> {
    std::str::from_utf8(plaintext.strip_prefix(head.as_bytes())?).ok()
}

/// Strict parse of a frame that travels; `None` for anything else,
/// including every other `RVNATT/` text and every offer that is not in its
/// one byte form.
pub fn parse_frame(plaintext: &[u8]) -> Option<Frame> {
    if let Some(json) = json_of(plaintext, HEAD_GONE) {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Gone {
            v: u8,
            handle: String,
        }
        let gone: Gone = serde_json::from_str(json).ok()?;
        let handle = hex_n(&gone.handle)?;
        return (gone.v == VERSION && gone_text(&handle).as_bytes() == plaintext)
            .then_some(Frame::Gone(handle));
    }
    if plaintext.len() != OFFER_LEN {
        return None;
    }
    let wire: Wire = serde_json::from_str(json_of(plaintext, HEAD_OFFER)?).ok()?;
    let (content, shape) = wire.typed(false)?;
    let handle = hex_n(&wire.handle)?;
    let blob = match shape {
        Some(shape) => {
            let key = Key::from_bytes(hex_n::<KEY_LEN>(wire.key.as_deref()?)?);
            let root = hex_n(wire.root.as_deref()?)?;
            if key.handle() != handle {
                return None;
            }
            Some(BlobRef { shape, key, root })
        }
        None => None,
    };
    wire.pad.as_ref()?;
    let offer = Offer {
        handle,
        content,
        blob,
    };
    // One byte form: what the encoder writes for what was read.
    (offer.encode().ok()?.as_bytes() == plaintext).then(|| Frame::Offer(Box::new(offer)))
}

/// The `gone` frame for an attachment.
pub fn gone_text(handle: &[u8; HANDLE_LEN]) -> String {
    format!(
        "{HEAD_GONE}{{\"v\":{VERSION},\"handle\":\"{}\"}}",
        hex::encode(handle)
    )
}

/// Strict parse of a stored `ref` frame; `None` for anything else.
pub fn parse_ref(text: &[u8]) -> Option<Ref> {
    if text.len() >= OFFER_LEN {
        return None;
    }
    let wire: Wire = serde_json::from_str(json_of(text, HEAD_REF)?).ok()?;
    if wire.key.is_some() || wire.root.is_some() || wire.pad.is_some() {
        return None;
    }
    let (content, shape) = wire.typed(true)?;
    let stored = Ref {
        handle: hex_n(&wire.handle)?,
        content,
        shape,
    };
    (stored.encode().as_bytes() == text).then_some(stored)
}

/// What a build that cannot open attachments yet needs from an `RVNATT/`
/// text: its kind, when the text is an offer in its one byte form. Such a
/// build keeps the offer as it came and shows a line of its own words
/// instead ("{name} sent a photo. Update Raven to see it."); a `profile`
/// offer is kept silently and never shown.
pub fn offer_kind(plaintext: &[u8]) -> Option<Kind> {
    match parse_frame(plaintext)? {
        Frame::Offer(offer) => Some(offer.kind()),
        Frame::Gone(_) => None,
    }
}

/// The handle a blob store names the attachment by.
pub fn handle_hex(handle: &[u8; HANDLE_LEN]) -> String {
    hex::encode(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob_ref(len: u64) -> BlobRef {
        BlobRef {
            shape: Shape::of(len).unwrap(),
            key: Key::from_bytes([7u8; KEY_LEN]),
            root: [9u8; 32],
        }
    }

    fn profile_ref(len: u64) -> BlobRef {
        BlobRef {
            shape: Shape::one_chunk(len).unwrap(),
            key: Key::from_bytes([8u8; KEY_LEN]),
            root: [3u8; 32],
        }
    }

    fn photo() -> Offer {
        Offer::photo(blob_ref(300_000), "Look at this", 1600, 1200, &[1u8; 900]).unwrap()
    }

    fn voice() -> Offer {
        Offer::voice(blob_ref(120_000), "", 42_000, [5u8; LEVELS]).unwrap()
    }

    fn file() -> Offer {
        Offer::file(
            blob_ref(1_000_000),
            "application/pdf",
            "Plan 2026.pdf",
            "the plan",
        )
        .unwrap()
    }

    fn profile() -> Offer {
        Offer::profile(
            profile_ref(40_000),
            1_794_700_000_000,
            0,
            384,
            &[2u8; 1_000],
        )
        .unwrap()
    }

    fn no_profile() -> Offer {
        Offer::no_profile([4u8; HANDLE_LEN], 1_794_700_000_001, 17).unwrap()
    }

    fn all() -> Vec<Offer> {
        vec![photo(), voice(), file(), profile(), no_profile()]
    }

    #[test]
    fn every_offer_is_8192_bytes_and_reads_back_as_it_was() {
        for offer in all() {
            let text = offer.encode().unwrap();
            assert_eq!(text.len(), OFFER_LEN, "{:?}", offer.kind());
            assert!(is_att_text(text.as_bytes()));
            assert!(text.starts_with("RVNATT/1 offer\n{\"v\":1,\"handle\":\""));
            assert!(text.ends_with("0\"}"), "the pad is last");
            assert_eq!(
                parse_frame(text.as_bytes()),
                Some(Frame::Offer(Box::new(offer.clone())))
            );
            assert_eq!(offer_kind(text.as_bytes()), Some(offer.kind()));
            // Text a message and a group body can carry: one line feed, no other control character.
            assert_eq!(text.matches('\n').count(), 1);
            assert!(crate::group::body_ok(&text));
        }
    }

    #[test]
    fn the_key_and_the_root_come_after_every_other_field_and_the_pad_last() {
        let text = photo().encode().unwrap();
        let key = text.find("\"key\":\"").unwrap();
        let root = text.find("\"root\":\"").unwrap();
        let pad = text.find("\"pad\":\"").unwrap();
        for member in [
            "\"handle\"",
            "\"kind\"",
            "\"chunks\"",
            "\"padded_len\"",
            "\"true_len\"",
            "\"mime\"",
            "\"caption\"",
            "\"width\"",
            "\"height\"",
            "\"preview\"",
        ] {
            assert!(text.find(member).unwrap() < key, "{member}");
        }
        assert!(key < root && root < pad);
        assert!(text[pad + 7..text.len() - 2].bytes().all(|b| b == b'0'));
        // The empty profile form holds no key and no root at all.
        let empty = no_profile().encode().unwrap();
        assert!(
            !empty.contains("\"key\"")
                && !empty.contains("\"root\"")
                && !empty.contains("true_len")
        );
        assert!(empty.contains("\"chunks\":0,\"pad\":\""));
    }

    #[test]
    fn the_largest_fields_still_leave_room_for_the_pad() {
        // A caption of 2,000 bytes that escaping doubles, with the largest preview.
        let caption = "\"".repeat(MAX_CAPTION_BYTES);
        let offer = Offer::photo(
            blob_ref(64_000_000),
            &caption,
            MAX_SIDE,
            MAX_SIDE,
            &[0xFFu8; MAX_PREVIEW_BYTES],
        )
        .unwrap();
        let text = offer.encode().unwrap();
        assert_eq!(text.len(), OFFER_LEN);
        assert_eq!(
            parse_frame(text.as_bytes()),
            Some(Frame::Offer(Box::new(offer)))
        );
        // A file with the longest name and type, all of it escaped.
        let name = "\"".repeat(MAX_NAME_BYTES);
        let mime = format!("{}/{}", "a".repeat(63), "b".repeat(63));
        let offer = Offer::file(
            blob_ref(64_000_000),
            &mime,
            &name,
            &"\n".repeat(MAX_CAPTION_BYTES),
        )
        .unwrap();
        let text = offer.encode().unwrap();
        assert_eq!(text.len(), OFFER_LEN);
        assert_eq!(
            parse_frame(text.as_bytes()),
            Some(Frame::Offer(Box::new(offer)))
        );
    }

    #[test]
    fn only_the_one_byte_form_is_read() {
        let text = photo().encode().unwrap();
        let read = |t: &str| parse_frame(t.as_bytes());
        assert!(read(&text).is_some());
        // One byte more or less.
        assert!(read(&text[..text.len() - 1]).is_none());
        assert!(read(&format!("{text} ")).is_none());
        // A pad that is not zeros, with the length kept.
        let pad = text.find("\"pad\":\"").unwrap() + 7;
        let mut other = text.clone();
        other.replace_range(pad..pad + 1, "1");
        assert!(read(&other).is_none());
        // White space traded for a pad byte.
        let spaced = text
            .replacen("{\"v\":1,", "{\"v\":1, ", 1)
            .replacen("00\"}", "0\"}", 1);
        assert_eq!(spaced.len(), OFFER_LEN);
        assert!(read(&spaced).is_none());
        // Another member order.
        let swapped = text.replacen(
            "\"width\":1600,\"height\":1200",
            "\"height\":1200,\"width\":1600",
            1,
        );
        assert_eq!(swapped.len(), OFFER_LEN);
        assert!(read(&swapped).is_none());
        // An unknown member, a member twice, another version, another magic.
        let extra = text
            .replacen("\"kind\":\"photo\",", "\"kind\":\"photo\",\"x\":1,", 1)
            .replacen("000000\"}", "\"}", 1);
        assert_eq!(extra.len(), OFFER_LEN);
        assert!(read(&extra).is_none());
        let twice =
            text.replacen("\"v\":1,", "\"v\":1,\"v\":1,", 1)
                .replacen("000000\"}", "\"}", 1);
        assert_eq!(twice.len(), OFFER_LEN);
        assert!(read(&twice).is_none());
        assert!(read(&text.replacen("\"v\":1", "\"v\":2", 1)).is_none());
        assert!(read(&text.replacen("RVNATT/1 offer", "RVNATT/2 offer", 1)).is_none());
        assert!(read(&text.replacen("RVNATT/1 offer", "RVNATT/1 Offer", 1)).is_none());
        // A handle that is not the key's.
        let handle = hex::encode(photo().handle);
        let wrong = text.replacen(&handle, &"0".repeat(32), 1);
        assert!(read(&wrong).is_none());
        // Upper case hex.
        assert!(
            read(&text.replacen(&handle, &handle.to_uppercase(), 1)).is_none()
                || handle == handle.to_uppercase()
        );
    }

    #[test]
    fn a_kind_takes_its_own_members_and_no_others() {
        let read = |t: &str| parse_frame(t.as_bytes());
        // A photo with a file's name: six pad bytes pay for the member.
        let text = photo().encode().unwrap();
        let named = text.replacen("\"caption\":", "\"name\":\"a\",\"caption\":", 1);
        let named = named.replacen(&"0".repeat(11), "", 1);
        assert_eq!(named.len(), OFFER_LEN);
        assert!(read(&named).is_none());
        // A photo that says it is a voice note.
        assert!(read(&text.replacen("\"kind\":\"photo\"", "\"kind\":\"voice\"", 1)).is_none());
        // A photo of another type.
        assert!(read(&text.replacen("image/jpeg", "image/heic", 1)).is_none());
        // A shape that does not follow from the length.
        let s = Shape::of(300_000).unwrap();
        let chunks = format!("\"chunks\":{}", s.chunks());
        assert!(
            read(&text.replacen(&chunks, &format!("\"chunks\":{}", s.chunks() - 1), 1)).is_none()
        );
        // The empty profile form with a picture's member.
        let empty = no_profile().encode().unwrap();
        let with_mime = empty.replacen("\"chunks\":0,", "\"chunks\":0,\"mime\":\"image/jpeg\",", 1);
        let with_mime = with_mime.replacen(&"0".repeat(20), "", 1);
        assert_eq!(with_mime.len(), OFFER_LEN);
        assert!(read(&with_mime).is_none());
        // A profile picture that is not square.
        let p = profile().encode().unwrap();
        assert!(read(&p.replacen("\"height\":384", "\"height\":385", 1)).is_none());
        // Any other RVNATT/ text is no frame.
        assert!(read("RVNATT/1 hello\n{}").is_none());
        assert!(read("RVNATT/").is_none());
        assert!(is_att_text(b"RVNATT/anything"));
        assert!(!is_att_text(b"rvnatt/1 offer"));
    }

    #[test]
    fn what_an_offer_may_not_say() {
        let b = || blob_ref(300_000);
        assert_eq!(
            Offer::photo(b(), "a\u{7}", 1, 1, &[1]).err(),
            Some(OfferError::Caption)
        );
        assert_eq!(
            Offer::photo(b(), &"a".repeat(MAX_CAPTION_BYTES + 1), 1, 1, &[1]).err(),
            Some(OfferError::Caption)
        );
        assert_eq!(
            Offer::photo(b(), "", 0, 1, &[1]).err(),
            Some(OfferError::Size)
        );
        assert_eq!(
            Offer::photo(b(), "", 1, MAX_SIDE + 1, &[1]).err(),
            Some(OfferError::Size)
        );
        assert_eq!(
            Offer::photo(b(), "", 1, 1, &[]).err(),
            Some(OfferError::Preview)
        );
        assert_eq!(
            Offer::photo(b(), "", 1, 1, &[0u8; MAX_PREVIEW_BYTES + 1]).err(),
            Some(OfferError::Preview)
        );
        assert_eq!(
            Offer::photo(profile_ref(1_000), "", 1, 1, &[1]).err(),
            Some(OfferError::Shape)
        );
        assert_eq!(
            Offer::voice(b(), "", 0, [0; LEVELS]).err(),
            Some(OfferError::Size)
        );
        assert_eq!(
            Offer::voice(b(), "", MAX_VOICE_MS + 1, [0; LEVELS]).err(),
            Some(OfferError::Size)
        );
        assert_eq!(
            Offer::file(b(), "pdf", "a.pdf", "").err(),
            Some(OfferError::Mime)
        );
        assert_eq!(
            Offer::file(b(), "Application/PDF", "a.pdf", "").err(),
            Some(OfferError::Mime)
        );
        assert_eq!(
            Offer::file(b(), "application/pdf", "", "").err(),
            Some(OfferError::Name)
        );
        assert_eq!(
            Offer::file(b(), "application/pdf", "../a.pdf", "").err(),
            Some(OfferError::Name)
        );
        assert_eq!(
            Offer::file(b(), "application/pdf", "photo\u{202E}gnp.exe", "").err(),
            Some(OfferError::Name)
        );
        assert_eq!(
            Offer::profile(profile_ref(1_000), 0, 0, 384, &[1]).err(),
            Some(OfferError::Seq)
        );
        assert_eq!(
            Offer::profile(profile_ref(1_000), MAX_SEQ + 1, 0, 384, &[1]).err(),
            Some(OfferError::Seq)
        );
        assert_eq!(
            Offer::profile(profile_ref(1_000), 1, 0, 63, &[1]).err(),
            Some(OfferError::Size)
        );
        assert_eq!(
            Offer::profile(profile_ref(1_000), 1, 0, 513, &[1]).err(),
            Some(OfferError::Size)
        );
        assert_eq!(
            Offer::profile(b(), 1, 0, 384, &[1]).err(),
            Some(OfferError::Shape)
        );
        assert_eq!(
            Offer::no_profile([0; 16], 1, MAX_SEQ + 1).err(),
            Some(OfferError::Seq)
        );
    }

    #[test]
    fn names_are_cleaned_before_they_travel() {
        assert_eq!(clean_name("Plan 2026.pdf"), "Plan 2026.pdf");
        assert_eq!(clean_name("  a/b\\c:d.txt  "), "abcd.txt");
        assert_eq!(clean_name("photo\u{202E}gnp.exe"), "photognp.exe");
        assert_eq!(clean_name("a\u{0}b\nc.txt"), "abc.txt");
        assert_eq!(clean_name("..."), "file");
        assert_eq!(clean_name(""), "file");
        assert_eq!(clean_name("\u{200B}\u{FEFF}"), "file");
        let long = "é".repeat(300);
        let cut = clean_name(&long);
        assert!(cut.len() <= MAX_NAME_BYTES && cut.len() >= MAX_NAME_BYTES - 1);
        assert!(name_ok(&cut));
        for name in ["Plan 2026.pdf", "عکس.jpg", "a.b.c", "x"] {
            assert!(name_ok(name), "{name}");
            assert_eq!(clean_name(name), name);
        }
        for name in [
            "",
            " a",
            "a ",
            ".",
            "..",
            "a/b",
            "a\\b",
            "c:d",
            "a\tb",
            "a\u{202E}b",
            "a\u{85}b",
        ] {
            assert!(!name_ok(name), "{name:?}");
        }
        assert!(
            mime_ok("image/jpeg") && mime_ok("application/vnd.ms-excel") && mime_ok("audio/ogg")
        );
        assert!(
            !mime_ok("image")
                && !mime_ok("/jpeg")
                && !mime_ok("image/")
                && !mime_ok("image/jpeg; q=1")
        );
        assert!(!mime_ok(&format!("{}/{}", "a".repeat(64), "b".repeat(63))));
    }

    #[test]
    fn the_stored_form_never_holds_the_key_the_root_or_the_pad() {
        for offer in all() {
            let stored = offer.stored();
            let text = stored.encode();
            assert!(text.starts_with("RVNATT/1 ref\n{"));
            assert!(
                text.len() < OFFER_LEN / 2,
                "{:?}: {}",
                offer.kind(),
                text.len()
            );
            for secret in ["\"key\"", "\"root\"", "\"pad\""] {
                assert!(
                    !text.contains(secret),
                    "{secret} in the stored form of {:?}",
                    offer.kind()
                );
            }
            if let Some(blob) = &offer.blob {
                assert!(!text.contains(&hex::encode(blob.key.bytes())));
                assert!(!text.contains(&hex::encode(blob.root)));
            }
            let back = parse_ref(text.as_bytes()).unwrap();
            assert_eq!(back.handle, offer.handle);
            assert_eq!(back.shape, offer.blob.as_ref().map(|b| b.shape));
            assert_eq!(back.kind(), offer.kind());
            // A ref is not a frame that travels, and an offer is not a ref.
            assert!(parse_frame(text.as_bytes()).is_none());
            assert!(parse_ref(offer.encode().unwrap().as_bytes()).is_none());
            // A ref with a key is refused.
            let with_key = text.replacen("}", ",\"key\":\"00\"}", 1);
            assert!(parse_ref(with_key.as_bytes()).is_none());
        }
        // A profile picture's stored form also drops the preview; the others keep theirs.
        assert!(!profile().stored().encode().contains("preview"));
        assert!(photo().stored().encode().contains("preview"));
        assert_eq!(
            parse_ref(photo().stored().encode().as_bytes())
                .unwrap()
                .content,
            photo().content
        );
    }

    #[test]
    fn list_words_say_what_it_is() {
        assert_eq!(photo().stored().list_words().as_deref(), Some("Photo"));
        assert_eq!(
            voice().stored().list_words().as_deref(),
            Some("Voice message 0:42")
        );
        assert_eq!(
            file().stored().list_words().as_deref(),
            Some("Plan 2026.pdf")
        );
        assert_eq!(profile().stored().list_words(), None);
        assert_eq!(no_profile().stored().list_words(), None);
        let long = Offer::voice(blob_ref(900_000), "", 61_001, [0; LEVELS]).unwrap();
        assert_eq!(
            long.stored().list_words().as_deref(),
            Some("Voice message 1:02")
        );
    }

    #[test]
    fn a_gone_frame_reads_back() {
        let handle = [0xABu8; HANDLE_LEN];
        let text = gone_text(&handle);
        assert_eq!(parse_frame(text.as_bytes()), Some(Frame::Gone(handle)));
        assert_eq!(offer_kind(text.as_bytes()), None);
        assert!(parse_frame(text.replacen("\"v\":1", "\"v\": 1", 1).as_bytes()).is_none());
        assert!(parse_frame(format!("{text}\n").as_bytes()).is_none());
        assert_eq!(handle_hex(&handle), "ab".repeat(16));
    }
}
