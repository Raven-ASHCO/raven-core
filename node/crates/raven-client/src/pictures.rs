//! Your picture: `picture.mine`, `picture.set`, `picture.clear` and
//! `picture.read`, the `picture` and `my_picture` members of a friend's row,
//! and the `picture` and `picture_mine` events (API.md "Your picture";
//! raven-core's `attachment::picture`, behind its profile pictures gate).
//!
//! - **One picture.** A person sets one picture. Each verified friend gets
//!   it under a key of its own, and only a verified friend's picture is
//!   ever read here.
//! - **The engine sends while it runs.** raven-core finds who is due an
//!   offer (`picture::pass`); the engine takes that look after every change,
//!   and once a minute while an app listens, and sends each offer as a
//!   message of its own that no chat shows. raven-node carries the
//!   picture's one chunk as it carries a photo's.
//! - **Checked before it is handed over.** `picture.read` gives a friend's
//!   bytes only after raven-core checked them as a plain baseline JPEG; the
//!   app then decodes them with the system's decoder, pinned to JPEG.
//!
//! While the gate is shut every operation answers NOT_AVAILABLE_YET, no row
//! has a picture member, no event comes, and no file is read.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ash_engine::engine::{self as bridge, ContactView};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use raven_core::attachment::flow;
use raven_core::attachment::picture::{self, MineView, PictureError, Reach, TheirView, Views};
use raven_core::attachment::store::StoreError;
use raven_core::attachment_gate;
use serde_json::{json, Map, Value};

use crate::engine::{lock, now_ms, Inner};
use crate::envelope::{code, ApiError, Args, OpResult};

/// The look that finds who is due an offer is taken this often while an app
/// listens, and at once after a change.
const PASS_EVERY: Duration = Duration::from_secs(60);
/// What a row was last built from is used again for this long: a list of
/// friends reads the picture files once, not once a friend.
const VIEWS_FOR: Duration = Duration::from_millis(400);
/// The most bytes `picture.set` decodes for the picture and for its preview:
/// what an encoder may hand over (raven-core writes it again, smaller).
const MOST_PICTURE: usize = 60_000 + 8_192;
const MOST_PREVIEW: usize = 1_536 + 8_192;

/// What a friend's row says about pictures: theirs (its `seq`, and whether
/// its bytes are here) and how far mine is with them.
type Told = (Option<(u64, bool)>, Option<&'static str>);

/// What the apps were last told about pictures, and the look for offers.
#[derive(Default)]
pub(crate) struct PictureWatch {
    /// The first look only notes.
    seen: bool,
    /// By the friend's address.
    told: HashMap<String, Told>,
    mine: Option<MineView>,
    views: Option<(Instant, Arc<Views>)>,
    last_pass: Option<Instant>,
    passing: bool,
    kick: bool,
}

fn not_yet() -> ApiError {
    ApiError::new(
        code::NOT_AVAILABLE_YET,
        "Profile pictures are not in this version of Raven yet. Nothing was changed.",
        attachment_gate::PROFILE_PICTURES_HOLD,
    )
}

fn gate() -> Result<(), ApiError> {
    if attachment_gate::pictures_live() {
        Ok(())
    } else {
        Err(not_yet())
    }
}

fn picture_error(e: PictureError) -> ApiError {
    let why = e.to_string();
    match e {
        PictureError::Hold => not_yet(),
        PictureError::TooBig => ApiError::of(code::PICTURE_TOO_BIG, why),
        PictureError::Bad(_) => ApiError::of(code::PICTURE_BAD, why),
        PictureError::ChangeLimit => ApiError::of(code::CHANGE_LIMIT, why),
        PictureError::NotVerified => ApiError::of(code::NOT_VERIFIED, why),
        PictureError::NoPicture => ApiError::of(code::NO_PICTURE, why),
        PictureError::Store(StoreError::Full) => ApiError::of(code::STORAGE_FULL, why),
        PictureError::Store(_) => ApiError::internal(why),
    }
}

fn reach_word(reach: Reach) -> &'static str {
    match reach {
        Reach::Has => "has",
        Reach::Waiting => "waiting",
        Reach::NeedsNewer => "needs_newer",
    }
}

fn mine_json(mine: &MineView) -> Value {
    json!({
        "set": mine.set,
        "seq": mine.choice,
        "changed_ms": mine.changed_ms,
        "changes_left": mine.changes_left,
        "friends": mine.friends,
        "have_it": mine.have_it,
        "waiting": mine.waiting,
        "need_newer": mine.need_newer,
    })
}

fn their_json(seq: u64, ready: bool) -> Value {
    json!({"seq": seq, "state": if ready { "ready" } else { "preview" }})
}

fn key_of(pub_hex: &str) -> Option<[u8; 32]> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(pub_hex.trim(), &mut key).ok()?;
    Some(key)
}

fn told_of(views: &Views, c: &ContactView) -> Told {
    let Some(peer) = key_of(&c.pub_hex) else {
        return (None, None);
    };
    (
        views
            .theirs(&peer)
            .map(|TheirView { seq, ready }| (seq, ready)),
        views.reach(&peer).map(reach_word),
    )
}

impl Inner {
    /// The picture files as they are now, read once for a moment's rows.
    /// `None` while the gate is shut: no file is read then.
    fn picture_views(&self) -> Option<Arc<Views>> {
        if !attachment_gate::pictures_live() {
            return None;
        }
        let dir = self.data_dir().ok()?;
        let mut watch = lock(&self.pictures);
        if let Some((at, views)) = &watch.views {
            if at.elapsed() < VIEWS_FOR {
                return Some(Arc::clone(views));
            }
        }
        let views = Arc::new(Views::load(dir, now_ms()));
        watch.views = Some((Instant::now(), Arc::clone(&views)));
        Some(views)
    }

    /// The `picture` and `my_picture` members of a friend's row (API.md
    /// "Your picture"): there only for a friend who is verified and not
    /// blocked, as raven-core works it out at this moment.
    pub(crate) fn picture_members(&self, c: &ContactView, map: &mut Map<String, Value>) {
        let Some(views) = self.picture_views() else {
            return;
        };
        let (theirs, mine) = told_of(&views, c);
        if let Some((seq, ready)) = theirs {
            map.insert("picture".into(), their_json(seq, ready));
        }
        if let Some(word) = mine {
            map.insert("my_picture".into(), word.into());
        }
    }

    /// `picture.mine`: `{"mine": ...}`.
    pub(crate) fn picture_mine(&self) -> OpResult {
        gate()?;
        self.identity()?;
        let mine = picture::mine(self.data_dir()?, now_ms()).map_err(picture_error)?;
        Ok(json!({"mine": mine_json(&mine)}))
    }

    /// `picture.set {jpeg_b64, preview_b64}`: checks both, keeps the
    /// picture as it travels and starts sending it to the verified friends.
    pub(crate) fn picture_set(&self, args: &Args) -> OpResult {
        gate()?;
        self.identity()?;
        let decode = |key: &str, most: usize| -> Result<Vec<u8>, ApiError> {
            let text = args.str(key)?.trim();
            // More characters than that many bytes make is not a picture,
            // and is not decoded.
            if text.len() > most.div_ceil(3) * 4 {
                return Err(ApiError::of(
                    code::PICTURE_TOO_BIG,
                    format!("\"{key}\" holds more than a picture's bytes"),
                ));
            }
            BASE64
                .decode(text)
                .map_err(|e| ApiError::bad_request(format!("\"{key}\" is not base64: {e}")))
        };
        let jpeg = decode("jpeg_b64", MOST_PICTURE)?;
        let preview = decode("preview_b64", MOST_PREVIEW)?;
        picture::set_mine(self.data_dir()?, &jpeg, &preview, now_ms()).map_err(picture_error)?;
        self.kick_pictures();
        self.picture_mine()
    }

    /// `picture.clear`: my picture goes, and the verified friends who have
    /// it are told.
    pub(crate) fn picture_clear(&self) -> OpResult {
        gate()?;
        self.identity()?;
        picture::clear_mine(self.data_dir()?, now_ms()).map_err(picture_error)?;
        self.kick_pictures();
        self.picture_mine()
    }

    /// `picture.read {address?, preview?}`: `{"jpeg_b64": ...}`, my own
    /// picture or a verified friend's, opened in memory and checked.
    pub(crate) fn picture_read(&self, args: &Args) -> OpResult {
        gate()?;
        self.identity()?;
        let dir = self.data_dir()?;
        let preview = args.opt_bool("preview")?.unwrap_or(false);
        let bytes = match args.opt_str("address")? {
            None => picture::read_mine(dir, preview),
            Some(address) => {
                let c = self.contact(address)?;
                let peer = key_of(&c.pub_hex)
                    .ok_or_else(|| ApiError::internal("the friend's key is not 32 bytes"))?;
                let read = picture::read_theirs(dir, &peer, preview, now_ms());
                if read.is_err() {
                    // A picture that failed its check went: the rows say so.
                    lock(&self.pictures).views = None;
                }
                read
            }
        }
        .map_err(picture_error)?;
        Ok(json!({"jpeg_b64": BASE64.encode(bytes)}))
    }

    /// The look for offers is taken at the watcher's next beat: after a
    /// change of my picture, and after a friend was verified, unverified,
    /// blocked or removed.
    pub(crate) fn kick_pictures(&self) {
        let mut watch = lock(&self.pictures);
        watch.kick = true;
        watch.views = None;
    }

    /// One beat of the watcher: a `picture` event for each friend whose
    /// members changed since the apps were last told, a `picture_mine`
    /// event when my picture or its counts did (the first look only
    /// notes), and the look for offers when it is due.
    pub(crate) fn refresh_pictures(&self) {
        if !attachment_gate::pictures_live() {
            return;
        }
        let (Ok(dir), Ok(contacts)) = (self.data_dir(), self.contacts()) else {
            return;
        };
        let views = Views::load(dir, now_ms());
        let mut events: Vec<(&str, Value)> = Vec::new();
        {
            let mut watch = lock(&self.pictures);
            let first = !watch.seen;
            watch.seen = true;
            let mut told = HashMap::with_capacity(contacts.len());
            for c in contacts.iter() {
                let now = told_of(&views, c);
                if !first && watch.told.get(&c.address).copied().unwrap_or((None, None)) != now {
                    events.push((
                        "picture",
                        json!({
                            "address": c.address,
                            "picture": now.0.map(|(seq, ready)| their_json(seq, ready)),
                            "my_picture": now.1,
                        }),
                    ));
                }
                told.insert(c.address.clone(), now);
            }
            watch.told = told;
            let mine = views.mine();
            if !first && mine != watch.mine {
                if let Some(mine) = &mine {
                    events.push(("picture_mine", json!({"mine": mine_json(mine)})));
                }
            }
            watch.mine = mine;
            watch.views = Some((Instant::now(), Arc::new(views)));
        }
        for (kind, fields) in events {
            self.emit(kind, fields);
        }
        self.pictures_pass_if_due();
    }

    fn pictures_pass_if_due(&self) {
        {
            let mut watch = lock(&self.pictures);
            let due = watch.kick || watch.last_pass.is_none_or(|at| at.elapsed() >= PASS_EVERY);
            if watch.passing || !due {
                return;
            }
            watch.passing = true;
            watch.kick = false;
            watch.last_pass = Some(Instant::now());
        }
        let me = self.me.clone();
        let spawned = std::thread::Builder::new()
            .name("raven-client-pictures".into())
            .spawn(move || {
                let Some(inner) = me.upgrade() else {
                    return;
                };
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    inner.pictures_pass();
                }));
                let mut watch = lock(&inner.pictures);
                watch.passing = false;
                watch.views = None;
            });
        if spawned.is_err() {
            lock(&self.pictures).passing = false;
        }
    }

    /// The look, and each offer it made sent as a message of its own. A
    /// send that makes no message (the node is paused or locked, the friend
    /// is gone from the list) leaves the friend due at the next look.
    fn pictures_pass(&self) {
        if self.open().is_err() {
            return;
        }
        let (Ok(identity), Ok(dir)) = (self.identity(), self.data_dir().map(Path::to_path_buf))
        else {
            return;
        };
        let Ok(due) = picture::pass(&dir, now_ms()) else {
            return;
        };
        if due.is_empty() {
            return;
        }
        let node = self.ensure_node_for_send();
        for to_send in due {
            let unsent = || {
                let _ = picture::offer_unsent(&dir, &to_send.peer, to_send.seq);
            };
            if node.is_err() {
                unsent();
                continue;
            }
            // The link that carries the offer takes the picture's chunk
            // along right behind its answer (raven-node, by the row).
            if let Some(handle) = &to_send.handle {
                flow::offer_going(&dir, handle, now_ms());
            }
            let own_id: bridge::OwnIdNote = {
                let dir = dir.clone();
                let (peer, seq) = (to_send.peer, to_send.seq);
                Box::new(move |mid: &[u8; 16]| {
                    let _ = picture::offer_sent(&dir, &peer, seq, mid, now_ms());
                })
            };
            let sent = bridge::send_picture_offer_to_contact_noting(
                &dir,
                &identity,
                &hex::encode(to_send.peer),
                &to_send.offer,
                own_id,
            );
            // A message that waits is the outbox's to finish; no message
            // at all: the friend is due again.
            if sent.is_err() && !picture::offer_has_message(&dir, &to_send.peer, to_send.seq) {
                unsent();
            }
        }
        self.invalidate_history();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_words_of_the_refusals_are_plain() {
        let plain = |words: &str| !words.contains(['-', '\u{2013}', '\u{2014}', '\'', '\u{2019}']);
        for e in [
            not_yet(),
            picture_error(PictureError::TooBig),
            picture_error(PictureError::ChangeLimit),
            picture_error(PictureError::NotVerified),
            picture_error(PictureError::NoPicture),
        ] {
            assert!(plain(&e.message), "{}", e.message);
        }
        assert_eq!(
            picture_error(PictureError::Hold).code,
            code::NOT_AVAILABLE_YET
        );
        assert_eq!(
            picture_error(PictureError::TooBig).code,
            code::PICTURE_TOO_BIG
        );
        assert_eq!(
            picture_error(PictureError::Store(StoreError::Full)).code,
            code::STORAGE_FULL
        );
    }

    #[test]
    fn a_rows_members_say_what_the_app_shows() {
        assert_eq!(their_json(7, false), json!({"seq": 7, "state": "preview"}));
        assert_eq!(their_json(8, true), json!({"seq": 8, "state": "ready"}));
        assert_eq!(reach_word(Reach::Has), "has");
        assert_eq!(reach_word(Reach::Waiting), "waiting");
        assert_eq!(reach_word(Reach::NeedsNewer), "needs_newer");
        let mine = mine_json(&MineView {
            set: true,
            choice: 9,
            changed_ms: 9,
            changes_left: 2,
            friends: 3,
            have_it: 1,
            waiting: 1,
            need_newer: 1,
        });
        assert_eq!(mine["seq"], 9);
        assert_eq!(
            mine["have_it"].as_u64().unwrap()
                + mine["waiting"].as_u64().unwrap()
                + mine["need_newer"].as_u64().unwrap(),
            mine["friends"].as_u64().unwrap()
        );
    }

    #[test]
    fn with_the_gate_shut_nothing_is_read_and_every_operation_says_not_yet() {
        attachment_gate::set_lab_pictures_for_this_thread(Some(false));
        let dir = tempfile::tempdir().unwrap();
        let inner = Inner::new(Ok(dir.path().to_path_buf()));
        assert!(inner.picture_views().is_none());
        for e in [
            inner.picture_mine().unwrap_err(),
            inner.picture_clear().unwrap_err(),
        ] {
            assert_eq!(e.code, code::NOT_AVAILABLE_YET);
        }
        inner.refresh_pictures();
        assert!(!lock(&inner.pictures).seen);
        attachment_gate::set_lab_pictures_for_this_thread(None);
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }
}
