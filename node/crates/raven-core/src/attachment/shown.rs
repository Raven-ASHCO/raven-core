//! What a build does with an `RVNATT/` text it cannot open, and what a
//! reader shows for one (`docs/design/2026-11-attachments.md` §8.4, phase
//! 1a; `docs/design/2026-11-profile-pictures.md` §9.5).
//!
//! Every build knows the prefix. An offer of a photo, a voice note or a
//! file is taken, ACKed and kept as it came, so a later build can open it,
//! and a reader shows a line of plain words in its place: never the offer
//! as text. A profile offer is taken and kept silently, one per friend,
//! and no reader shows it: not as a message, not in a chat list, not in an
//! unread count, not in a notice. Any other `RVNATT/` text (a `gone` frame,
//! a kind or a version of tomorrow, a broken offer) is taken and dropped.
//! None of them is ever deferred.

use super::offer::{self, Content, Frame, Kind};

/// What an `RVNATT/` text is to a build that cannot open attachments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttClass {
    /// An offer of a photo, a voice note or a file: kept as it came and
    /// shown as a line of words.
    Offer(Kind),
    /// A profile offer (a picture or No picture): kept silently, the newest
    /// `seq` of a friend only, never shown.
    Profile {
        /// The order of the sender's profile offers.
        seq: u64,
    },
    /// Anything else under the prefix: taken and dropped.
    Other,
}

/// Classifies a text that starts with `RVNATT/`.
pub fn class(plaintext: &[u8]) -> AttClass {
    match offer::parse_frame(plaintext) {
        Some(Frame::Offer(offer)) => match offer.content {
            Content::Profile { seq, .. } | Content::NoProfile { seq, .. } => {
                AttClass::Profile { seq }
            }
            Content::Photo { .. } | Content::Voice { .. } | Content::File { .. } => {
                AttClass::Offer(offer.kind())
            }
        },
        Some(Frame::Gone(_)) | None => AttClass::Other,
    }
}

/// Is this text one that no chat view, chat list, unread count or notice
/// may ever show or count: an `RVNATT/` text that is not an offer of a
/// photo, a voice note or a file?
pub fn is_silent(plaintext: &[u8]) -> bool {
    offer::is_att_text(plaintext) && !matches!(class(plaintext), AttClass::Offer(_))
}

/// Is this stored body one no chat view shows, lists or counts? Unlike
/// [`is_silent`], which judges a text as it comes from a link, this reads a
/// body as the history keeps it: the stored form of an attachment is shown.
pub fn is_hidden_body(body: &str) -> bool {
    offer::is_att_text(body.as_bytes()) && shown(body, "") == Shown::Hidden
}

/// The stored form of an attachment text: of an offer, or of a stored form
/// itself. `None` for anything else.
fn stored_form(body: &str) -> Option<String> {
    if !offer::is_att_text(body.as_bytes()) {
        return None;
    }
    if let Some(stored) = offer::parse_ref(body.as_bytes()) {
        return Some(stored.encode());
    }
    match offer::parse_frame(body.as_bytes())? {
        Frame::Offer(offer) => Some(offer.stored().encode()),
        Frame::Gone(_) => None,
    }
}

/// Do two stored bodies name the same attachment with the same words: an
/// offer and its stored form, say (a row written before attachments were
/// live holds the offer; a copy that comes later is stored in its stored
/// form)?
pub fn same_attachment(a: &str, b: &str) -> bool {
    matches!((stored_form(a), stored_form(b)), (Some(x), Some(y)) if x == y)
}

/// The line a build that cannot open attachments shows for one a friend
/// sent ("Max sent a photo. Update Raven to see it."). Plain words, no
/// hyphens, dashes or apostrophes. A profile offer has no line.
pub fn update_words(kind: Kind, name: &str) -> String {
    let name = name.trim();
    let name = if name.is_empty() { "A friend" } else { name };
    match kind {
        Kind::Photo => format!("{name} sent a photo. Update Raven to see it."),
        Kind::Voice => format!("{name} sent a voice message. Update Raven to hear it."),
        Kind::File => format!("{name} sent a file. Update Raven to open it."),
        Kind::Profile => String::new(),
    }
}

/// How a reader shows a stored message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// Ordinary text: shown as it is (the reader cleans it for its screen).
    Text,
    /// An attachment this build cannot open: these words instead.
    Words(String),
    /// Never shown and never counted.
    Hidden,
}

/// How a reader shows the stored `body` of a message from `name` (the
/// reader's own name for the friend or the group member). A body that
/// starts with `RVNATT/` is never [`Shown::Text`].
pub fn shown(body: &str, name: &str) -> Shown {
    if !offer::is_att_text(body.as_bytes()) {
        return Shown::Text;
    }
    // The stored form of an attachment this build keeps (a history row
    // never holds an offer of mine, nor a friend's once attachments are
    // live): its list words. A reader that can show the attachment itself
    // reads the row's stored form and the attachment store.
    if let Some(stored) = offer::parse_ref(body.as_bytes()) {
        return stored.list_words().map_or(Shown::Hidden, Shown::Words);
    }
    match class(body.as_bytes()) {
        AttClass::Offer(kind) => Shown::Words(update_words(kind, name)),
        AttClass::Profile { .. } | AttClass::Other => Shown::Hidden,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::blob::{Key, Shape, HANDLE_LEN, KEY_LEN};
    use crate::attachment::offer::{BlobRef, Offer, LEVELS};

    fn blob(len: u64) -> BlobRef {
        BlobRef {
            shape: Shape::of(len).unwrap(),
            key: Key::from_bytes([1u8; KEY_LEN]),
            root: [2u8; 32],
        }
    }

    fn photo_text() -> String {
        crate::attachment::testing::photo_offer()
    }

    fn profile_text(seq: u64) -> String {
        crate::attachment::testing::profile_offer(seq)
    }

    #[test]
    fn an_offer_is_words_and_never_text() {
        let photo = photo_text();
        assert_eq!(class(photo.as_bytes()), AttClass::Offer(Kind::Photo));
        assert!(!is_silent(photo.as_bytes()));
        assert_eq!(
            shown(&photo, "Max"),
            Shown::Words("Max sent a photo. Update Raven to see it.".to_string())
        );
        assert_eq!(
            shown(&photo, "  "),
            Shown::Words("A friend sent a photo. Update Raven to see it.".to_string())
        );
        let voice = Offer::voice(blob(90_000), "", 5_000, [0; LEVELS])
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(
            shown(&voice, "Lily"),
            Shown::Words("Lily sent a voice message. Update Raven to hear it.".to_string())
        );
        let file = Offer::file(blob(90_000), "application/pdf", "a.pdf", "")
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(
            shown(&file, "Lily"),
            Shown::Words("Lily sent a file. Update Raven to open it.".to_string())
        );
        for words in [
            update_words(Kind::Photo, "Max"),
            update_words(Kind::Voice, "Max"),
            update_words(Kind::File, "Max"),
        ] {
            assert!(
                !words.contains(['-', '\u{2013}', '\u{2014}', '\'', '\u{2019}']),
                "{words}"
            );
        }
    }

    #[test]
    fn a_profile_offer_and_every_other_text_under_the_prefix_are_never_shown() {
        let profile = profile_text(77);
        assert_eq!(class(profile.as_bytes()), AttClass::Profile { seq: 77 });
        assert!(is_silent(profile.as_bytes()));
        assert_eq!(shown(&profile, "Max"), Shown::Hidden);
        let none = Offer::no_profile([5u8; HANDLE_LEN], 78, 0)
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(class(none.as_bytes()), AttClass::Profile { seq: 78 });
        assert_eq!(shown(&none, "Max"), Shown::Hidden);
        let gone = offer::gone_text(&[6u8; HANDLE_LEN]);
        for text in [
            gone.as_str(),
            "RVNATT/2 offer\n{}",
            "RVNATT/1 offer\n{\"v\":1}",
            "RVNATT/",
            "RVNATT/x",
        ] {
            assert_eq!(class(text.as_bytes()), AttClass::Other, "{text}");
            assert!(is_silent(text.as_bytes()), "{text}");
            assert_eq!(shown(text, "Max"), Shown::Hidden, "{text}");
        }
        // A broken offer: one byte of a good one changed.
        let mut broken = photo_text();
        broken.replace_range(100..101, "!");
        assert_eq!(shown(&broken, "Max"), Shown::Hidden);
    }

    #[test]
    fn ordinary_text_is_text() {
        for text in [
            "hello",
            "",
            "rvnatt/1 offer",
            " RVNATT/1 offer",
            "RVNGRP/1 msg\n{}",
            "RVNAPP/1 x",
        ] {
            assert_eq!(shown(text, "Max"), Shown::Text, "{text}");
            assert!(!is_silent(text.as_bytes()), "{text}");
        }
    }
}
